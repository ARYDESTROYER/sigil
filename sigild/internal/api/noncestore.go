package api

import "sync"

// nonceStoreTTL is how long a seen nonce is retained, keyed on the server's
// receipt time. It is **2× the auth skew window, not 1×**: the timestamp check in
// authorizeOps is two-sided (a request may be signed up to opsAuthSkew in the
// FUTURE), so a captured request stays replayable until wall-clock reaches
// ts+opsAuthSkew — i.e. up to 2*opsAuthSkew after we first record it. A 1× TTL
// would evict the guard a full window before the request stops being replayable.
const nonceStoreTTL = 2 * opsAuthSkew // seconds (600)

// nonceStoreMaxEntries is the hard cap on live nonces the in-memory replay-guard
// retains at once. It caps memory against a flood of validly-signed unique
// nonces; at capacity checkAndRecord fails closed. ~64k entries at a few dozen
// bytes each is a few MB — ample for a dev op-log.
const nonceStoreMaxEntries = 65536

// nonceStore is a bounded, in-memory set of recently-seen op-log request nonces,
// used to reject replays of *signed* op-log requests within the auth timestamp
// window (Phase 15). It is consulted ONLY when op-log auth is enabled
// (SIGILD_OPLOG_PUBKEY set) and only AFTER a request's Ed25519 signature has
// verified — so an unauthenticated attacker cannot fill it.
//
// DEV-ONLY / IN-MEMORY: the store is LOST ON RESTART, so a captured signed
// request could be replayed after a restart within its (still-valid) timestamp
// window. A production op-log needs a shared/persistent nonce store (e.g. Redis).
// This closes the in-window replay gap for a single running dev process only.
type nonceStore struct {
	mu   sync.Mutex
	ttl  int64            // seconds a nonce is retained (set to nonceStoreTTL = 2× the skew window)
	max  int              // hard cap on retained nonces (flood bound)
	seen map[string]int64 // nonce -> unix-seconds expiry
}

// newNonceStore builds a store that retains each nonce for ttlSeconds and holds
// at most max entries.
func newNonceStore(ttlSeconds int64, max int) *nonceStore {
	return &nonceStore{
		ttl:  ttlSeconds,
		max:  max,
		seen: make(map[string]int64),
	}
}

// checkAndRecord atomically decides whether nonce is fresh and, if so, records
// it. It returns true when nonce is FRESH (not currently recorded) — recording it
// with expiry now+ttl — and false when nonce is a REPLAY (already recorded and
// unexpired) OR the store is full of live nonces after evicting expired ones
// (fail-closed under flood). now is unix seconds.
//
// Expired entries are swept lazily, and only when the map reaches capacity, so
// the amortised cost per call stays low while memory stays bounded by max without
// a background goroutine.
func (s *nonceStore) checkAndRecord(nonce string, now int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if exp, ok := s.seen[nonce]; ok && exp > now {
		return false // replay: recorded and not yet expired
	}

	if len(s.seen) >= s.max {
		// Reclaim expired entries before considering the cap breached.
		for n, exp := range s.seen {
			if exp <= now {
				delete(s.seen, n)
			}
		}
		if len(s.seen) >= s.max {
			return false // still full of live nonces: fail closed
		}
	}

	s.seen[nonce] = now + s.ttl
	return true
}
