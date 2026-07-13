package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRateLimiterBurstThenReject: with a tiny refill rate and burst 2, the first
// two calls pass and the third is rejected (tokens exhausted before any
// meaningful refill).
func TestRateLimiterBurstThenReject(t *testing.T) {
	rl := newRateLimiter(0.001, 2) // ~1000s to refill one token
	if !rl.Allow("v") {
		t.Fatal("call 1 rejected, want allowed")
	}
	if !rl.Allow("v") {
		t.Fatal("call 2 rejected, want allowed")
	}
	if rl.Allow("v") {
		t.Fatal("call 3 allowed, want rejected (burst exhausted)")
	}
}

// TestRateLimiterIndependentKeys: each vault has its own bucket, so exhausting
// one does not affect another.
func TestRateLimiterIndependentKeys(t *testing.T) {
	rl := newRateLimiter(0.001, 1)
	if !rl.Allow("a") {
		t.Fatal("a call 1 rejected, want allowed")
	}
	if rl.Allow("a") {
		t.Fatal("a call 2 allowed, want rejected")
	}
	// b is untouched: its own full bucket admits the first call.
	if !rl.Allow("b") {
		t.Fatal("b call 1 rejected, want allowed (independent bucket)")
	}
}

// TestRateLimiterBurstClampedToOne: a burst < 1 is clamped up to 1 so a single
// request always passes.
func TestRateLimiterBurstClampedToOne(t *testing.T) {
	rl := newRateLimiter(0.001, 0)
	if !rl.Allow("v") {
		t.Fatal("call 1 rejected with burst 0 clamped to 1, want allowed")
	}
	if rl.Allow("v") {
		t.Fatal("call 2 allowed, want rejected (burst clamped to 1)")
	}
}

// TestRateLimiterRefill drives the injectable clock: after exhausting the bucket,
// advancing time past the refill interval admits a request again.
func TestRateLimiterRefill(t *testing.T) {
	rl := newRateLimiter(1, 1) // 1 token/sec, burst 1
	now := time.Unix(1_000_000, 0)
	rl.now = func() time.Time { return now }

	if !rl.Allow("v") {
		t.Fatal("call 1 rejected, want allowed")
	}
	if rl.Allow("v") {
		t.Fatal("call 2 (no time passed) allowed, want rejected")
	}
	// Advance ~1.1s: one token refills.
	now = now.Add(1100 * time.Millisecond)
	if !rl.Allow("v") {
		t.Fatal("call 3 after refill rejected, want allowed")
	}
}

// TestRateLimiterEvictsIdle: at the key cap, an idle (fully-refilled) bucket is
// evicted so a brand-new key can be admitted, keeping the map bounded.
func TestRateLimiterEvictsIdle(t *testing.T) {
	rl := newRateLimiter(1, 1)
	now := time.Unix(1_000_000, 0)
	rl.now = func() time.Time { return now }

	// Fill the map to the cap with idle buckets (last far in the past => full).
	old := now.Add(-time.Hour)
	for i := 0; i < rateLimiterMaxVaults; i++ {
		rl.buckets["k"+itoa(i)] = &rateBucket{tokens: rl.burst, last: old}
	}
	if len(rl.buckets) != rateLimiterMaxVaults {
		t.Fatalf("pre-fill size = %d, want %d", len(rl.buckets), rateLimiterMaxVaults)
	}
	// A new key must be admitted (eviction reclaimed the idle buckets) and the map
	// stays within the cap.
	if !rl.Allow("fresh") {
		t.Fatal("fresh key rejected at cap, want allowed after idle eviction")
	}
	if len(rl.buckets) > rateLimiterMaxVaults {
		t.Fatalf("post-admit size = %d, want <= %d (bounded)", len(rl.buckets), rateLimiterMaxVaults)
	}
}

// TestRateLimiterConcurrent hammers one key from many goroutines under -race and
// asserts the number of ALLOWED calls never exceeds the burst (no over-admission
// under contention).
func TestRateLimiterConcurrent(t *testing.T) {
	const burst = 8
	rl := newRateLimiter(0.0001, burst) // negligible refill during the test
	var allowed int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if rl.Allow("shared") {
				atomic.AddInt64(&allowed, 1)
			}
		}()
	}
	wg.Wait()
	if allowed > burst {
		t.Fatalf("allowed = %d, want <= burst %d (no over-admission)", allowed, burst)
	}
	if allowed == 0 {
		t.Fatal("allowed = 0, want at least 1")
	}
}

// itoa is a tiny int->string without importing strconv into the test twice.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// --- HTTP-level rate-limit tests ---

// rateLimitedRouter returns a dev-ops router with per-vault rate limiting on.
func rateLimitedRouter(rate float64, burst int) http.Handler {
	return NewRouter(Config{
		Version:        "test",
		Logger:         discardLogger(),
		DevOpsEnabled:  true,
		OpLogRateLimit: rate,
		OpLogRateBurst: burst,
	})
}

// TestVaultOpsRateLimited: a burst of POSTs to one vault yields some 201s then
// 429s, and a 429 carries the typed rate_limited envelope + a Retry-After header.
func TestVaultOpsRateLimited(t *testing.T) {
	router := rateLimitedRouter(0.001, 2) // burst 2, negligible refill

	var created, limited int
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/rl/ops", bytes.NewReader([]byte("op")))
		router.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusCreated:
			created++
		case http.StatusTooManyRequests:
			limited++
			if got := rec.Header().Get("Retry-After"); got == "" {
				t.Fatal("429 missing Retry-After header")
			}
			var body apiError
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("429 body not JSON: %v", err)
			}
			if body.Error != "rate_limited" {
				t.Fatalf("429 error = %q, want rate_limited", body.Error)
			}
		default:
			t.Fatalf("unexpected status %d", rec.Code)
		}
	}
	if created != 2 {
		t.Fatalf("created = %d, want 2 (== burst)", created)
	}
	if limited != 3 {
		t.Fatalf("limited = %d, want 3", limited)
	}
}

// TestVaultOpsRateLimitIndependentVaults: exhausting one vault's bucket does not
// rate-limit a different vault.
func TestVaultOpsRateLimitIndependentVaults(t *testing.T) {
	router := rateLimitedRouter(0.001, 1)

	// Exhaust vault "a".
	postOp(t, router, "a", []byte("op")) // 201 (helper asserts)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/a/ops", bytes.NewReader([]byte("op")))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a second POST status = %d, want 429", rec.Code)
	}
	// Vault "b" still has a full bucket.
	if seq := postOp(t, router, "b", []byte("op")); seq != 1 {
		t.Fatalf("b first POST seq = %d, want 1 (independent bucket)", seq)
	}
}

// TestVaultOpsRateLimitDisabled: with rate 0 (disabled), no request is ever
// 429'd, no matter how many arrive.
func TestVaultOpsRateLimitDisabled(t *testing.T) {
	router := rateLimitedRouter(0, 0) // disabled
	for i := 0; i < 50; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/nolimit/ops", bytes.NewReader([]byte("op")))
		router.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d got 429 with rate limiting disabled", i)
		}
		if rec.Code != http.StatusCreated {
			t.Fatalf("request %d status = %d, want 201", i, rec.Code)
		}
	}
}

// TestVaultOpsRateLimitGetNotLimited: GET is never write-rate-limited even when
// the limiter is configured.
func TestVaultOpsRateLimitGetNotLimited(t *testing.T) {
	router := rateLimitedRouter(0.001, 1)
	postOp(t, router, "g", []byte("op")) // consume the single POST token
	for i := 0; i < 10; i++ {
		list := getOps(t, router, "g", "0") // helper asserts 200
		if len(list.Ops) != 1 {
			t.Fatalf("GET %d returned %d ops, want 1", i, len(list.Ops))
		}
	}
}
