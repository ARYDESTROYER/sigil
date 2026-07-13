package api

import (
	"math"
	"net/http"
	"strconv"
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

	mu      sync.Mutex
	buckets map[string]*rateBucket
	now     func() time.Time
}

// newRateLimiter builds a limiter admitting `rate` requests/second per vault with
// a `burst` capacity. A burst < 1 is clamped to 1 so at least single requests
// pass. rate must be > 0 (callers only construct a limiter when it is).
func newRateLimiter(rate float64, burst int) *rateLimiter {
	b := float64(burst)
	if b < 1 {
		b = 1
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
		buckets:    make(map[string]*rateBucket),
		now:        time.Now,
	}
}

// Allow consumes one token from key's bucket and reports whether the request may
// proceed. A brand-new key starts with a full bucket. When the key is unknown and
// the bucket map is at its hard cap, fully-refilled idle buckets are evicted
// first; if the cap still holds (all buckets actively limited), the request is
// rejected rather than growing the map without bound.
func (rl *rateLimiter) Allow(key string) bool {
	now := rl.now()

	rl.mu.Lock()
	defer rl.mu.Unlock()

	b := rl.buckets[key]
	if b == nil {
		if len(rl.buckets) >= rateLimiterMaxVaults {
			rl.evictIdle(now)
		}
		if len(rl.buckets) >= rateLimiterMaxVaults {
			return false
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
