package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// opsAuthSkew bounds how far the client-supplied timestamp may drift from the
// server's clock, in seconds. It bounds replay AND, together with the seen-nonce
// cache (below), makes a captured request unreplayable within the window: the
// cache remembers a nonce for exactly as long as its request could still pass
// this window. It is still per-process/in-memory (see nonceCache).
const opsAuthSkew = 300 // seconds

// opsAuthDomain is the fixed first line of the signed message. It binds a
// signature to this scheme + version so a signature cannot be repurposed for a
// different protocol. It MUST stay byte-for-byte identical to the CLI signer.
//
// v2 (this) adds a per-request nonce to the signed message + a server-side
// replay cache. It is a CLEAN BREAK from v1: a v1 signature (no nonce segment)
// no longer verifies, and a request without X-Sigil-Nonce is rejected.
const opsAuthDomain = "sigil-oplog-auth-v2\n"

// errUnauthorized is the sentinel authorizeOps returns when a request fails the
// op-log auth contract (missing headers / bad timestamp / bad signature). The
// caller maps it to a 401 typed-error envelope.
var errUnauthorized = errors.New("oplog auth: unauthorized")

// errReplay is the sentinel authorizeOps returns when the signature is valid but
// the request's nonce was already seen inside the timestamp window (a replay).
// The caller maps it to a 401 with a distinct "replayed request" detail.
var errReplay = errors.New("oplog auth: replayed request")

// nonceCacheMaxEntries is a hard safety backstop on the seen-nonce cache size.
// At steady state the cache holds at most one window's worth of nonces (entries
// self-evict once their timestamp leaves the skew window), so this cap is only
// reached under abuse. When it is reached after eviction, further fresh nonces
// are refused (treated as replay) so the map cannot grow without bound. A single
// dev device signing at a sane rate never approaches it.
const nonceCacheMaxEntries = 50_000

// nonceCache is an in-memory, concurrency-safe, time-bounded replay cache for
// op-log request nonces.
//
// HONEST SCOPE (DEV-ONLY): this cache is PER-PROCESS and in-memory. It stops a
// replay against THIS sigild instance only; a multi-instance production deploy
// needs a shared store (e.g. Redis) so a request replayed against a different
// instance is also caught. It is sized to remember a nonce for exactly the skew
// window (the only interval in which a replay could still pass the timestamp
// check), plus a hard size cap as a backstop.
type nonceCache struct {
	mu   sync.Mutex
	seen map[string]int64 // nonce (raw header text) -> unix ts it was recorded with
}

// newNonceCache returns an empty, ready-to-use nonce cache.
func newNonceCache() *nonceCache {
	return &nonceCache{seen: make(map[string]int64)}
}

// checkAndRecord reports whether nonce is a REPLAY. It first evicts every entry
// whose timestamp has left the skew window (ts < now-opsAuthSkew) — such a nonce
// can no longer pass the timestamp check, so remembering it is pointless. Then:
//   - if nonce is still present, it is a replay within the window -> true;
//   - else, as a backstop, if the map is at/over the hard size cap, refuse the
//     fresh nonce (return true) so the map cannot grow without bound;
//   - else record (nonce -> ts) and return false (first sighting, allowed).
//
// It is safe for concurrent use. now is passed in (not read from the clock) so
// it matches the timestamp check authorizeOps already performed for this request.
func (c *nonceCache) checkAndRecord(nonce string, ts, now int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict entries whose request could no longer pass the timestamp window.
	cutoff := now - opsAuthSkew
	for n, t := range c.seen {
		if t < cutoff {
			delete(c.seen, n)
		}
	}

	// Seen within the window => replay.
	if _, ok := c.seen[nonce]; ok {
		return true
	}
	// Backstop: never grow past the hard cap (eviction above already ran).
	if len(c.seen) >= nonceCacheMaxEntries {
		return true
	}
	c.seen[nonce] = ts
	return false
}

// authorizeOps enforces the op-log request-authentication contract (v2) for a
// single vault-ops request.
//
// When h.cfg.OpLogPubKey is nil, auth is DISABLED and this returns nil
// immediately — the op-log keeps its existing UNAUTHENTICATED behaviour. When
// the key is set, the request must carry a valid Ed25519 signature over the
// canonical v2 message (below) AND a fresh, not-yet-seen nonce, else this returns
// errUnauthorized / errReplay (both -> 401).
//
// HONEST SCOPE (DEV-ONLY): this verifies against a SINGLE configured device
// public key, and the replay cache is PER-PROCESS/in-memory (see nonceCache) —
// a multi-instance deploy needs a shared store (e.g. Redis). Full device
// enrollment, a multi-device registry, and JWT bearer tokens (see internal/auth)
// remain FUTURE. Do NOT treat this as production authentication.
//
// The signed MESSAGE is built byte-for-byte as (lines joined by '\n' = 0x0A):
//
//	"sigil-oplog-auth-v2\n" + METHOD + "\n" + PATH + "\n" + QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + BODY
//
// where METHOD is the uppercase HTTP method (r.Method), PATH is r.URL.Path (no
// query), QUERY is r.URL.RawQuery ("" when absent), TIMESTAMP is the decimal
// ASCII value from X-Sigil-Timestamp, NONCE is the EXACT X-Sigil-Nonce header
// text (std-base64 of >=16 random bytes, used verbatim so both sides agree), and
// BODY is the raw request body bytes (empty for GET). The Go server and the Rust
// CLI MUST agree on this exactly.
//
// Verification order: (1) all three headers present; (2) timestamp parses and is
// inside the skew window; (3) signature verifies; (4) — ONLY after a valid
// signature, so unauthenticated probes never touch the cache — the nonce is not
// a replay. It is recorded on first valid sighting.
func (h *handlers) authorizeOps(r *http.Request, body []byte) error {
	// Auth disabled: nil key => unchanged, UNAUTHENTICATED behaviour.
	if h.cfg.OpLogPubKey == nil {
		return nil
	}

	// 1) All three headers must be present and non-blank.
	tsHeader := r.Header.Get("X-Sigil-Timestamp")
	nonceHeader := r.Header.Get("X-Sigil-Nonce")
	sigHeader := r.Header.Get("X-Sigil-Signature")
	if tsHeader == "" || nonceHeader == "" || sigHeader == "" {
		return errUnauthorized
	}

	// 2) Timestamp must parse as int64 and fall inside the skew window.
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return errUnauthorized
	}
	now := time.Now().Unix()
	if skew := now - ts; skew < -opsAuthSkew || skew > opsAuthSkew {
		return errUnauthorized
	}

	// 3) Reconstruct the canonical v2 signed MESSAGE from the request. The
	//    timestamp and nonce segments use the RAW header values, so they match
	//    whatever the client signed, not a re-formatted parse.
	msg := make([]byte, 0,
		len(opsAuthDomain)+len(r.Method)+len(r.URL.Path)+len(r.URL.RawQuery)+
			len(tsHeader)+len(nonceHeader)+5+len(body))
	msg = append(msg, opsAuthDomain...)
	msg = append(msg, r.Method...)
	msg = append(msg, '\n')
	msg = append(msg, r.URL.Path...)
	msg = append(msg, '\n')
	msg = append(msg, r.URL.RawQuery...)
	msg = append(msg, '\n')
	msg = append(msg, tsHeader...)
	msg = append(msg, '\n')
	msg = append(msg, nonceHeader...)
	msg = append(msg, '\n')
	msg = append(msg, body...)

	// Decode the signature and verify against the configured device key.
	sig, err := base64.StdEncoding.DecodeString(sigHeader)
	if err != nil {
		return errUnauthorized
	}
	if !ed25519.Verify(h.cfg.OpLogPubKey, msg, sig) {
		return errUnauthorized
	}

	// 4) Replay check — ONLY after a valid signature, so unauthenticated probes
	//    cannot populate/probe the cache. A repeated nonce within the window is a
	//    replay; a fresh nonce is recorded here. h.nonces is non-nil whenever
	//    OpLogPubKey is set (see NewRouter); guard defensively regardless.
	if h.nonces != nil && h.nonces.checkAndRecord(nonceHeader, ts, now) {
		return errReplay
	}
	return nil
}

// writeOpsAuthError maps an authorizeOps failure to the 401 typed-error
// envelope, distinguishing a replayed request from a generic signature failure.
// The error CODE stays "unauthorized" in both cases; only the detail differs.
func writeOpsAuthError(w http.ResponseWriter, err error) {
	detail := "missing or invalid op-log request signature"
	if errors.Is(err, errReplay) {
		detail = "replayed request"
	}
	writeError(w, http.StatusUnauthorized, "unauthorized", detail)
}
