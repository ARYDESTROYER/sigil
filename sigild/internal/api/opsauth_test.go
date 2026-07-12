package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// authedRouter returns a dev-ops router that REQUIRES op-log request signatures
// verified against pub.
func authedRouter(t *testing.T, pub ed25519.PublicKey) http.Handler {
	t.Helper()
	return NewRouter(Config{
		Version:       "test",
		Logger:        discardLogger(),
		DevOpsEnabled: true,
		OpLogPubKey:   pub,
	})
}

// randNonce returns a fresh std-base64 nonce over 16 random bytes (the client's
// job in the v2 contract).
func randNonce(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// signOpsRequest builds the canonical op-log MESSAGE (v2) and sets the three
// contract headers on req, signing with seed. It mirrors what the Rust CLI must
// produce:
//
//	"sigil-oplog-auth-v2\n" + METHOD + "\n" + PATH + "\n" + QUERY + "\n" + TS + "\n" + NONCE + "\n" + BODY
//
// ts is the unix-seconds value used both in the message and the
// X-Sigil-Timestamp header (they MUST match); nonce is used verbatim both in the
// message and the X-Sigil-Nonce header.
func signOpsRequest(t *testing.T, req *http.Request, seed []byte, ts int64, nonce string, body []byte) {
	t.Helper()
	tsStr := strconv.FormatInt(ts, 10)

	var msg []byte
	msg = append(msg, "sigil-oplog-auth-v2\n"...)
	msg = append(msg, req.Method...)
	msg = append(msg, '\n')
	msg = append(msg, req.URL.Path...)
	msg = append(msg, '\n')
	msg = append(msg, req.URL.RawQuery...)
	msg = append(msg, '\n')
	msg = append(msg, tsStr...)
	msg = append(msg, '\n')
	msg = append(msg, nonce...)
	msg = append(msg, '\n')
	msg = append(msg, body...)

	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, msg)

	req.Header.Set("X-Sigil-Timestamp", tsStr)
	req.Header.Set("X-Sigil-Nonce", nonce)
	req.Header.Set("X-Sigil-Signature", base64.StdEncoding.EncodeToString(sig))
}

// newKeypair returns (seed[32], publicKey) from a fresh Ed25519 key.
func newKeypair(t *testing.T) ([]byte, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv.Seed(), pub
}

// TestOpsAuthSignedPostAndGet: a correctly-signed POST -> 201, then a
// correctly-signed GET -> 200 and returns the op.
func TestOpsAuthSignedPostAndGet(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	now := time.Now().Unix()

	body := []byte("opaque-op-1")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
	signOpsRequest(t, req, seed, now, randNonce(t), body)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("signed POST status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/vaults/demo/ops?since=0", nil)
	signOpsRequest(t, req, seed, now, randNonce(t), nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("signed GET status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var list opsListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("GET body not JSON: %v", err)
	}
	if len(list.Ops) != 1 || !bytes.Equal(list.Ops[0].Blob, body) {
		t.Fatalf("GET ops = %+v, want one op with blob %x", list.Ops, body)
	}
}

// TestOpsAuthGetNoQuerySigned confirms the empty-query case (QUERY = "") signs
// and verifies correctly.
func TestOpsAuthGetNoQuerySigned(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	now := time.Now().Unix()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/vaults/demo/ops", nil)
	if req.URL.RawQuery != "" {
		t.Fatalf("expected empty RawQuery, got %q", req.URL.RawQuery)
	}
	signOpsRequest(t, req, seed, now, randNonce(t), nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("signed GET (no query) status = %d, want 200", rec.Code)
	}
}

// TestOpsAuthMissingHeaders: with auth enabled, a request missing ANY of the
// three contract headers is rejected with 401 (typed envelope). It builds a
// fully-valid signed request, then drops one header per case.
func TestOpsAuthMissingHeaders(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	now := time.Now().Unix()

	for _, drop := range []string{
		"", // drop none: sanity — the fully-signed request must pass
		"X-Sigil-Timestamp",
		"X-Sigil-Nonce",
		"X-Sigil-Signature",
	} {
		t.Run("drop_"+drop, func(t *testing.T) {
			body := []byte("op")
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
			signOpsRequest(t, req, seed, now, randNonce(t), body)
			if drop == "" {
				router.ServeHTTP(rec, req)
				if rec.Code != http.StatusCreated {
					t.Fatalf("fully-signed POST status = %d, want 201", rec.Code)
				}
				return
			}
			req.Header.Del(drop)
			router.ServeHTTP(rec, req)
			assertUnauthorized(t, rec)
		})
	}
}

// TestOpsAuthMissingHeadersNoneSet: a request with NO signature headers at all
// (both verbs) is rejected with 401.
func TestOpsAuthMissingHeadersNoneSet(t *testing.T) {
	_, pub := newKeypair(t)
	router := authedRouter(t, pub)

	cases := []struct {
		name   string
		method string
		body   []byte
	}{
		{"POST", http.MethodPost, []byte("op")},
		{"GET", http.MethodGet, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, "/v1/vaults/demo/ops", bytes.NewReader(tc.body))
			router.ServeHTTP(rec, req)
			assertUnauthorized(t, rec)
		})
	}
}

// TestOpsAuthGarbageSignature: a syntactically-valid header carrying nonsense
// (or non-base64) is rejected with 401, even with a present nonce+timestamp.
func TestOpsAuthGarbageSignature(t *testing.T) {
	_, pub := newKeypair(t)
	router := authedRouter(t, pub)
	now := strconv.FormatInt(time.Now().Unix(), 10)

	for _, sig := range []string{"not-base64-!!!", base64.StdEncoding.EncodeToString([]byte("too-short"))} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader([]byte("op")))
		req.Header.Set("X-Sigil-Timestamp", now)
		req.Header.Set("X-Sigil-Nonce", randNonce(t))
		req.Header.Set("X-Sigil-Signature", sig)
		router.ServeHTTP(rec, req)
		assertUnauthorized(t, rec)
	}
}

// TestOpsAuthStaleTimestamp: a timestamp 400s in the PAST (> 300s window) is
// rejected even with an otherwise-valid signature over that timestamp.
func TestOpsAuthStaleTimestamp(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	stale := time.Now().Unix() - 400

	body := []byte("op")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
	signOpsRequest(t, req, seed, stale, randNonce(t), body)
	router.ServeHTTP(rec, req)
	assertUnauthorized(t, rec)
}

// TestOpsAuthFutureSkewTimestamp: a timestamp 400s in the FUTURE (> 300s
// window) is likewise rejected.
func TestOpsAuthFutureSkewTimestamp(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	future := time.Now().Unix() + 400

	body := []byte("op")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
	signOpsRequest(t, req, seed, future, randNonce(t), body)
	router.ServeHTTP(rec, req)
	assertUnauthorized(t, rec)
}

// TestOpsAuthWrongKey: a signature from a DIFFERENT key than the server's
// configured pubkey is rejected with 401.
func TestOpsAuthWrongKey(t *testing.T) {
	_, pub := newKeypair(t)       // server trusts this key
	otherSeed, _ := newKeypair(t) // client signs with a different key
	router := authedRouter(t, pub)
	now := time.Now().Unix()

	body := []byte("op")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
	signOpsRequest(t, req, otherSeed, now, randNonce(t), body)
	router.ServeHTTP(rec, req)
	assertUnauthorized(t, rec)
}

// TestOpsAuthTamperedBody: signing one body but sending another fails (the body
// is part of the signed message).
func TestOpsAuthTamperedBody(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	now := time.Now().Unix()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader([]byte("actual-body")))
	// Sign a DIFFERENT body than the one the request actually carries.
	signOpsRequest(t, req, seed, now, randNonce(t), []byte("signed-a-different-body"))
	router.ServeHTTP(rec, req)
	assertUnauthorized(t, rec)
}

// TestOpsAuthReplayRejected is the core v2 property: submitting the SAME signed
// request (identical headers + body) TWICE gives 201 then 401 "replayed
// request" on POST, and 200 then 401 on GET.
func TestOpsAuthReplayRejected(t *testing.T) {
	t.Run("POST", func(t *testing.T) {
		seed, pub := newKeypair(t)
		router := authedRouter(t, pub)
		now := time.Now().Unix()
		body := []byte("replay-me")
		nonce := randNonce(t)

		// Build the exact same signed request twice.
		newReq := func() *http.Request {
			req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
			signOpsRequest(t, req, seed, now, nonce, body)
			return req
		}

		rec1 := httptest.NewRecorder()
		router.ServeHTTP(rec1, newReq())
		if rec1.Code != http.StatusCreated {
			t.Fatalf("first POST status = %d, want 201 (body: %s)", rec1.Code, rec1.Body.String())
		}

		rec2 := httptest.NewRecorder()
		router.ServeHTTP(rec2, newReq())
		assertReplay(t, rec2)
	})

	t.Run("GET", func(t *testing.T) {
		seed, pub := newKeypair(t)
		router := authedRouter(t, pub)
		now := time.Now().Unix()
		nonce := randNonce(t)

		newReq := func() *http.Request {
			req := httptest.NewRequest(http.MethodGet, "/v1/vaults/demo/ops?since=0", nil)
			signOpsRequest(t, req, seed, now, nonce, nil)
			return req
		}

		rec1 := httptest.NewRecorder()
		router.ServeHTTP(rec1, newReq())
		if rec1.Code != http.StatusOK {
			t.Fatalf("first GET status = %d, want 200 (body: %s)", rec1.Code, rec1.Body.String())
		}

		rec2 := httptest.NewRecorder()
		router.ServeHTTP(rec2, newReq())
		assertReplay(t, rec2)
	})
}

// TestOpsAuthFreshNonceSucceedsTwice: two requests that differ ONLY by nonce
// (same key, same ts, same body) both succeed — a fresh nonce is always fine.
func TestOpsAuthFreshNonceSucceedsTwice(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	now := time.Now().Unix()
	body := []byte("same-body")

	for i, nonce := range []string{randNonce(t), randNonce(t)} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
		signOpsRequest(t, req, seed, now, nonce, body)
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("POST #%d (fresh nonce) status = %d, want 201 (body: %s)", i+1, rec.Code, rec.Body.String())
		}
	}
}

// TestOpsAuthNonceOutsideWindowRejectedByTimestamp: a signed request whose ts is
// outside the skew window is rejected by the timestamp check BEFORE the nonce is
// ever recorded — so the same nonce can later be used in-window and succeed.
func TestOpsAuthNonceOutsideWindowRejectedByTimestamp(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	nonce := randNonce(t)
	body := []byte("op")

	// Out-of-window request with this nonce -> 401 (timestamp check first).
	stale := time.Now().Unix() - 400
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
	signOpsRequest(t, req, seed, stale, nonce, body)
	router.ServeHTTP(rec, req)
	assertUnauthorized(t, rec)

	// The SAME nonce, now in-window, must NOT have been recorded by the rejected
	// request, so it succeeds.
	now := time.Now().Unix()
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
	signOpsRequest(t, req, seed, now, nonce, body)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("in-window POST with previously-rejected nonce status = %d, want 201", rec.Code)
	}
}

// TestOpsAuthDisabledUnchangedNoHeaders is the regression guard: a router
// WITHOUT OpLogPubKey serves ops with NO signature headers exactly as before.
func TestOpsAuthDisabledUnchangedNoHeaders(t *testing.T) {
	router := devOpsRouter() // DevOpsEnabled:true, OpLogPubKey nil

	seq := postOp(t, router, "demo", []byte("op")) // helper asserts 201
	if seq != 1 {
		t.Fatalf("first POST seq = %d, want 1", seq)
	}
	list := getOps(t, router, "demo", "0") // helper asserts 200
	if len(list.Ops) != 1 {
		t.Fatalf("GET returned %d ops, want 1", len(list.Ops))
	}
}

// TestNonceCacheEvictsExpired verifies the cache is time-bounded: a nonce
// recorded with an old ts is evicted once `now` advances past its window, so the
// same nonce string is accepted again (it can no longer be a live replay).
func TestNonceCacheEvictsExpired(t *testing.T) {
	c := newNonceCache()
	base := int64(1_000_000)

	if c.checkAndRecord("n1", base, base) {
		t.Fatal("first sighting of n1 reported as replay")
	}
	if !c.checkAndRecord("n1", base, base) {
		t.Fatal("immediate repeat of n1 not reported as replay")
	}
	// Advance now past the window: the old n1 entry (ts=base) is now evicted, so
	// n1 is a fresh sighting again.
	later := base + opsAuthSkew + 1
	if c.checkAndRecord("n1", later, later) {
		t.Fatal("n1 after eviction window reported as replay, want fresh")
	}
	if len(c.seen) != 1 {
		t.Fatalf("cache size = %d after eviction, want 1", len(c.seen))
	}
}

// TestNonceCacheHardCap verifies the size backstop: once the cache is full of
// in-window entries, a fresh nonce is refused (treated as replay) rather than
// growing the map without bound.
func TestNonceCacheHardCap(t *testing.T) {
	c := newNonceCache()
	now := int64(1_000_000)
	// Pre-fill to the cap directly (white-box, same package) with in-window
	// entries. Filling through checkAndRecord would be O(n^2) — each call scans
	// the whole map for eviction — so we only exercise the cap DECISION here.
	for i := 0; i < nonceCacheMaxEntries; i++ {
		c.seen["n"+strconv.Itoa(i)] = now
	}
	// A fresh nonce, still in-window: refused by the backstop rather than growing
	// the map past the cap.
	if !c.checkAndRecord("overflow", now, now) {
		t.Fatal("fresh nonce over the hard cap not refused")
	}
	// An already-present nonce is still reported as a replay at/over the cap.
	if !c.checkAndRecord("n0", now, now) {
		t.Fatal("present nonce over the cap not reported as replay")
	}
	// Once entries age out of the window, the cache drains and accepts again.
	later := now + opsAuthSkew + 1
	if c.checkAndRecord("post-drain", later, later) {
		t.Fatal("fresh nonce after the window drained the cap reported as replay")
	}
}

// TestOpsAuthConcurrentRequests hammers the shared nonce cache from many
// goroutines at once so `go test -race` can surface any data race on it. Each
// goroutine sends TWO identical signed requests: the first must be accepted
// exactly once, the second must be a replay. Distinct nonces per goroutine keep
// the accept/replay accounting deterministic across the concurrency.
func TestOpsAuthConcurrentRequests(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	now := time.Now().Unix()

	const workers = 64
	var accepted, replayed int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := []byte("op")
			nonce := randNonce(t)
			for pass := 0; pass < 2; pass++ {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
				signOpsRequest(t, req, seed, now, nonce, body)
				router.ServeHTTP(rec, req)
				switch rec.Code {
				case http.StatusCreated:
					atomic.AddInt64(&accepted, 1)
				case http.StatusUnauthorized:
					atomic.AddInt64(&replayed, 1)
				default:
					t.Errorf("unexpected status %d", rec.Code)
				}
			}
		}()
	}
	wg.Wait()

	if accepted != workers {
		t.Fatalf("accepted = %d, want %d (each fresh nonce accepted exactly once)", accepted, workers)
	}
	if replayed != workers {
		t.Fatalf("replayed = %d, want %d (each nonce's second use is a replay)", replayed, workers)
	}
}

func assertUnauthorized(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (body: %s)", rec.Code, rec.Body.String())
	}
	var body apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("401 body not JSON: %v", err)
	}
	if body.Error != "unauthorized" {
		t.Fatalf("401 error = %q, want unauthorized", body.Error)
	}
}

// assertReplay asserts a 401 whose detail marks it as a replay (code stays
// "unauthorized").
func assertReplay(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("replay status = %d, want 401 (body: %s)", rec.Code, rec.Body.String())
	}
	var body apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("replay body not JSON: %v", err)
	}
	if body.Error != "unauthorized" {
		t.Fatalf("replay error = %q, want unauthorized", body.Error)
	}
	if body.Detail != "replayed request" {
		t.Fatalf("replay detail = %q, want %q", body.Detail, "replayed request")
	}
}
