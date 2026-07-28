package api

import (
	"bytes"
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// rateLimiterMaxVaults hard-caps how many per-vault buckets the limiter holds,
// bounding its memory. At steady state only vaults with recent write activity
// have a bucket, and fully-refilled (idle) buckets are evicted before a new key
// is admitted, so this cap is only approached under abuse (that many distinct
// vaults all actively rate-limited at once). See Allow.
const rateLimiterMaxVaults = 10_000

// rateBucket is one vault's token bucket. tokens is the current allowance; last
// is when it was last refilled. A fresh bucket starts full (tokens == burst).
type rateBucket struct {
	tokens float64
	last   time.Time
}

// rateLimiter is a concurrency-safe, per-key token-bucket limiter, keyed by
// vaultID. It refills each bucket at `rate` tokens/second up to `burst` tokens;
// Allow consumes one token and reports whether the request may proceed.
//
// It is STDLIB-ONLY (sync.Mutex + a map + time), with a bounded number of keys
// (rateLimiterMaxVaults) and idle-bucket eviction, so memory cannot grow without
// bound. `now` is injectable so tests can drive refill/eviction deterministically;
// it defaults to time.Now.
type rateLimiter struct {
	rate  float64 // tokens per second
	burst float64 // bucket capacity
	// retryAfter is the Retry-After header value (seconds) advertised on a
	// rejection: the whole-second time to accrue one token, at least 1.
	retryAfter string
	// maxKeys hard-caps how many buckets this limiter holds. It is a per-limiter
	// value because the key spaces differ wildly: vault IDs and source-address
	// prefixes are effectively unbounded (and attacker-influenced), while the
	// invite limiter's keys come from the closed set of enrolled accounts.
	maxKeys int

	mu      sync.Mutex
	buckets map[string]*rateBucket
	now     func() time.Time
}

// newRateLimiter builds a limiter admitting `rate` requests/second per vault with
// a `burst` capacity. A burst < 1 is clamped to 1 so at least single requests
// pass. rate must be > 0 (callers only construct a limiter when it is).
func newRateLimiter(rate float64, burst int) *rateLimiter {
	return newRateLimiterWithMax(rate, burst, rateLimiterMaxVaults)
}

// newRateLimiterWithMax is newRateLimiter with an explicit key cap. Behaviour is
// otherwise identical, so the op-log limiter is unchanged.
func newRateLimiterWithMax(rate float64, burst, maxKeys int) *rateLimiter {
	b := float64(burst)
	if b < 1 {
		b = 1
	}
	if maxKeys < 1 {
		maxKeys = 1
	}
	// Time to accrue one token, rounded up, floored at 1 second.
	retry := int64(math.Ceil(1 / rate))
	if retry < 1 {
		retry = 1
	}
	return &rateLimiter{
		rate:       rate,
		burst:      b,
		retryAfter: strconv.FormatInt(retry, 10),
		maxKeys:    maxKeys,
		buckets:    make(map[string]*rateBucket),
		now:        time.Now,
	}
}

// Allow consumes one token from key's bucket and reports whether the request may
// proceed. A brand-new key starts with a full bucket. When the key is unknown and
// the bucket map is at its hard cap, fully-refilled idle buckets are evicted
// first.
//
// ⭐ AT THE CAP, WITH EVERY BUCKET STILL ACTIVE, THE REQUEST IS ADMITTED — THE
// LIMITER FAILS OPEN, NOT CLOSED. This was inverted after a live reproduction:
// the cap is reachable by an attacker (a single IPv6 /48 yields 65536 distinct
// /64 keys, and vault ids are caller-chosen), and the old fail-closed branch
// meant that filling the map REFUSED EVERY OTHER KEY — turning a memory bound
// into a global outage on an availability-critical, unauthenticated route. An
// abuse control that can be weaponised into a denial of service is worse than no
// abuse control: the thing it protects is availability.
//
// The map stays bounded either way — nothing new is inserted past the cap, so
// memory is capped; only the VERDICT changes. The correct place for a real
// per-source bound is the edge proxy (see clientRateKey).
func (rl *rateLimiter) Allow(key string) bool {
	now := rl.now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	b := rl.buckets[key]
	if b == nil {
		if len(rl.buckets) >= rl.maxKeys {
			rl.evictIdle(now)
		}
		if len(rl.buckets) >= rl.maxKeys {
			// FAIL OPEN: bounded memory, but never a self-inflicted outage.
			return true
		}
		b = &rateBucket{tokens: rl.burst, last: now}
		rl.buckets[key] = b
	}

	// Refill by the time elapsed since the last touch, capped at burst.
	if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * rl.rate
		if b.tokens > rl.burst {
			b.tokens = rl.burst
		}
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// evictIdle drops every bucket that has certainly refilled back to full since it
// was last touched (elapsed*rate >= burst). Such a bucket is indistinguishable
// from a freshly created (full) one, so removing it changes no future decision —
// it only reclaims memory. Caller must hold rl.mu.
func (rl *rateLimiter) evictIdle(now time.Time) {
	for k, b := range rl.buckets {
		if now.Sub(b.last).Seconds()*rl.rate >= rl.burst {
			delete(rl.buckets, k)
		}
	}
}

// ---- Abuse bounds (Phase 53, corrected in the 53-55 fix round) ----
//
// THE GAP THIS CLOSES: every existing cap in this server bounds stored STATE
// (how many devices an account may hold, how many open invites it may have, how
// big a body may be). None of them bounds REQUEST VOLUME, so two routes could be
// hammered for free:
//
//   - POST /v1/devices/enroll        UNAUTHENTICATED, and an attempt carrying a
//     valid proof costs a database round trip (the atomic token/invite
//     resolution at step 8).
//   - POST /v1/account/invites       authenticated, but a single valid member
//     could mint invites as fast as it could sign.
//
// ⛔ A THIRD LIMITER, ON POST /v1/billing/webhook/{provider}, WAS REMOVED. It
// let anonymous forged traffic spend the same tokens as authentic provider
// deliveries and demonstrably destroyed payment events. See billingWebhook for
// the full reasoning; do not reintroduce it.
//
// Both remaining limiters are the SAME hand-written stdlib token bucket the
// op-log limiter uses (sync.Mutex + map + time), with a bounded key count and
// idle eviction. NO dependency was added — sigild still has exactly one direct
// require.
//
// BOTH ARE OFF BY DEFAULT. An unset rate installs no limiter at all, so a server
// that does not opt in behaves byte-identically to Phase 52.
//
// ⚠️ READ THIS BEFORE TRUSTING EITHER OF THEM. These are a BACKSTOP, NOT A
// DEFENCE:
//
//   - The enrollment key is the SOCKET PEER ADDRESS, and the only documented
//     topology in this repo (deploy/caddy, deploy/local) puts a reverse proxy in
//     front of sigild — so in practice EVERY request arrives from one address
//     and the whole world shares ONE bucket. That is why enrollment charges the
//     bucket only on the DENIAL path (rateLimitEnroll): otherwise a junk flood
//     would refuse the next legitimate customer, which was reproduced live.
//   - Real per-source limiting belongs at the EDGE, which is the only component
//     that knows the actual peer and can be configured with trusted-proxy rules.
//     Nothing here is a substitute for that.

// abuseLimiterMaxKeys bounds the enroll and invite limiters. Their key spaces
// (source-address prefixes; account IDs) are large and partly attacker-
// influenced, so the same 10k cap + idle eviction the op-log limiter uses
// applies. At the cap the limiter FAILS OPEN (see Allow): the map stays bounded,
// but a full map can never be used to refuse everybody else.
const abuseLimiterMaxKeys = 10_000

// Abuse-limiter surfaces. This is a CLOSED set: it is the only label on the
// abuse rate-limit metric, and metrics.go materializes exactly these two.
const (
	abuseSurfaceEnroll = "enroll"
	abuseSurfaceInvite = "invite"
)

// abuseRateLimitSurfaces is that closed set in a stable order.
var abuseRateLimitSurfaces = []string{abuseSurfaceEnroll, abuseSurfaceInvite}

// unattributedRateKey is the SINGLE SHARED bucket used when a request's source
// address cannot be parsed (an exotic listener, a malformed RemoteAddr, a
// synthetic request).
//
// WHY A SHARED BUCKET AND NOT "ALLOW": falling open would mean the control
// silently evaporates for exactly the traffic we could not attribute, and a
// limiter that can be turned off by making yourself unidentifiable is not a
// limiter. WHY NOT "DENY": a hard denial would make the whole route unusable on
// a listener whose RemoteAddr this parser does not understand, which is a
// self-inflicted outage rather than a defence. One shared bucket is bounded,
// cannot be bypassed, and degrades to "all unattributable enrolments share one
// budget" — restrictive, but never open.
const unattributedRateKey = "-"

// clientRateKey derives the rate-limit key for an UNAUTHENTICATED request from
// its SOURCE ADDRESS. It is deliberately the socket peer address only.
//
// ⚠️ X-Forwarded-For AND FRIENDS ARE NOT CONSULTED, ON PURPOSE. sigild has no
// trusted-proxy configuration, so any forwarded-for header is attacker-supplied
// text. Keying on it would let one client mint an unlimited number of distinct
// buckets — turning the limiter into a no-op AND filling the bounded map, which
// is strictly worse than having no limiter at all.
// (TestEnrollRateLimitIgnoresForwardedFor pins this at the CALL SITE, not just
// on this function: a wrapper that read the header would otherwise satisfy every
// unit test of this pure function while defeating it completely.)
//
// ⚠️ THE COST OF THAT CHOICE IS NOT SMALL, AND IT IS NOT "FAIL SAFE". Behind a
// reverse proxy — the ONLY topology this repo documents (deploy/caddy/Caddyfile,
// deploy/local/Caddyfile.local) — every request appears to come from the proxy,
// so this returns ONE key for ALL traffic and the limiter degrades to a single
// global bucket. A junk flood would then refuse the next legitimate customer,
// which is why enrollment charges the bucket only on the DENIAL path
// (rateLimitEnroll) and why Allow fails open at its key cap. Even so: this
// limiter is a BACKSTOP, not a defence. Real per-source limiting belongs at the
// edge, which is the component that actually knows the peer.
//
// ⚠️ AND IT DOES NOT REDUCE LOAD. Charging only on the denial path means the
// handler ALWAYS runs — including its database work — and the limiter replaces
// only the RESPONSE. That is the deliberate trade that makes it impossible for
// the limiter to refuse a valid enrolment, but it means the name reads like a
// work bound and is not one: it bounds how useful flooding is, not what it costs
// us. A work bound for this route would have to reject before the handler, which
// is exactly what could deny a legitimate customer.
//
// IPv6 is bucketed by its /64 PREFIX, not its full address: a single host is
// routinely handed a /64 (and often far more), so keying the full address would
// let one allocation walk 2^64 buckets past the limit. IPv4 keys on the full
// address. An IPv4-mapped IPv6 address is unmapped first, so one client is one
// bucket regardless of how the listener presented it.
func clientRateKey(remoteAddr string) string {
	host := strings.TrimSpace(remoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// Drop any IPv6 zone ("fe80::1%eth0"), which netip parses but which would
	// otherwise split one link-local peer across zones.
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return unattributedRateKey
	}
	addr = addr.Unmap()
	if addr.Is4() {
		return addr.String()
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return unattributedRateKey
	}
	return prefix.String()
}

// writeRateLimited writes the shared 429 response: the same typed envelope and
// Retry-After header the op-log limiter uses, so a client sees ONE rate-limit
// contract across the whole server.
//
// The detail string names the SURFACE, never the key: it must not tell a caller
// which address bucket, which account, or which peer it collided with.
func writeRateLimited(w http.ResponseWriter, rl *rateLimiter, detail string) {
	w.Header().Set("Retry-After", rl.retryAfter)
	writeError(w, http.StatusTooManyRequests, "rate_limited", detail)
}

// allowAbuse is the shared choke point for the two abuse limiters: it consumes
// a token, and on rejection records the audit line and the metric. A nil limiter
// (the default — not configured) always allows, so the un-opted-in path does no
// work at all.
//
// subject is what the audit line may record about WHO was limited. It is the
// account ID for the invite surface and the provider name for the webhook
// surface; it is DELIBERATELY EMPTY for enrollment (see auditRateLimited).
func (h *handlers) allowAbuse(r *http.Request, rl *rateLimiter, surface, key, subject string) bool {
	if rl == nil {
		return true
	}
	if rl.Allow(key) {
		return true
	}
	h.auditRateLimited(r, surface, subject)
	h.metrics.incAbuseRateLimited(surface)
	return false
}

// bufferedResponse captures a handler's response so the wrapper can decide, from
// the OUTCOME, whether to emit it or replace it. Nothing is written through
// until Flush.
type bufferedResponse struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: make(http.Header), status: http.StatusOK}
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(code int) {
	if b.status == http.StatusOK {
		b.status = code
	}
}

func (b *bufferedResponse) Write(p []byte) (int, error) { return b.body.Write(p) }

// Flush copies the captured response onto the real ResponseWriter verbatim.
func (b *bufferedResponse) Flush(w http.ResponseWriter) {
	dst := w.Header()
	for k, v := range b.header {
		dst[k] = v
	}
	w.WriteHeader(b.status)
	_, _ = w.Write(b.body.Bytes())
}

// rateLimitEnroll wraps POST /v1/devices/enroll with a per-source-address token
// bucket that ⭐ CHARGES ONLY FOR FAILED ATTEMPTS.
//
// ---------------------------------------------------------------------------
// WHY THIS IS NOT THE OBVIOUS "REJECT BEFORE THE HANDLER" SHAPE
// ---------------------------------------------------------------------------
//
// It used to be. That version was reproduced live denying a real customer: an
// attacker sending junk from one address drew {401 x5, 429 x25}, and the next
// request — a LEGITIMATE new customer presenting a VALID, unspent operator token
// — was refused 429. Behind the reverse proxy this repo documents, "one address"
// is EVERY address (see clientRateKey), so that limiter was a global switch for
// turning off account creation AND invite redemption, i.e. the join path for
// somebody who has just lost a device.
//
// So the bucket is spent only when an attempt is REFUSED. Concretely:
//
//   - the handler always runs, and its response is BUFFERED;
//   - a 2xx (a valid, unspent credential plus a valid proof of possession)
//     is flushed through untouched and costs NOTHING — a successful enrolment
//     can never be rate limited, in any bucket state whatsoever;
//   - a non-2xx consumes one token; when the bucket is empty the buffered
//     denial is DISCARDED and replaced by the 429, so a source that is only ever
//     failing gets a cheap, retryable answer instead of an endless supply of
//     detailed ones.
//
// WHAT THIS BUYS AND WHAT IT DOES NOT. It bounds how fast a source can be TOLD
// it failed, and it cannot deny a legitimate user — which is the property that
// matters most on the one unauthenticated write path in a product whose users
// arrive here after losing a device. It does NOT bound the work a valid-proof,
// bad-credential attempt costs; the step-6 proof check already rejects junk
// before any store round trip, and real volume protection belongs at the edge.
// This is a backstop, and the comment on clientRateKey says why.
//
// It is installed ONLY on the live (dev-gated) route. The 501 stub is never rate
// limited: a gated route must answer 501 uniformly, or the limiter itself would
// become a probe for whether the feature is on.
func rateLimitEnroll(rl *rateLimiter, h *handlers, next http.Handler) http.Handler {
	if rl == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := newBufferedResponse()
		next.ServeHTTP(buf, r)

		if buf.status >= 200 && buf.status < 300 {
			// A successful enrolment. No token is consumed, and no bucket state
			// could have refused it.
			buf.Flush(w)
			return
		}
		if h.allowAbuse(r, rl, abuseSurfaceEnroll, clientRateKey(r.RemoteAddr), "") {
			buf.Flush(w)
			return
		}
		writeRateLimited(w, rl, "too many failed enrollment attempts from this source address")
	})
}

// rateLimitOps wraps a POST-ops handler with per-vault rate limiting. On a
// rejection it increments the rate-limit metric, sets Retry-After, and returns
// the typed 429 envelope; otherwise it calls next unchanged. The vaultID comes
// from the matched route pattern (ServeMux sets path values before the wrapped
// handler runs, so r.PathValue is populated here).
func rateLimitOps(rl *rateLimiter, m *Metrics, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.Allow(r.PathValue("vaultID")) {
			m.incRateLimited()
			w.Header().Set("Retry-After", rl.retryAfter)
			writeError(w, http.StatusTooManyRequests, "rate_limited",
				"per-vault operation rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}
