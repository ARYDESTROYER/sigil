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
	"strings"
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

// signOpsRequest builds the canonical v2 op-log MESSAGE and sets the three
// contract headers on req, signing with seed. It mirrors what the Rust CLI must
// produce:
//
//	"sigil-oplog-auth-v2\n" + METHOD + "\n" + PATH + "\n" + QUERY + "\n" + TS + "\n" + NONCE + "\n" + BODY
//
// ts is the unix-seconds value used both in the message and the X-Sigil-Timestamp
// header; nonce is used both in the message and the X-Sigil-Nonce header (each
// MUST match). Reusing the same (ts, nonce, method, path, query, body) twice
// produces a byte-identical replay that the nonce store rejects.
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
	signOpsRequest(t, req, seed, now, "n-signed-post", body)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("signed POST status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/vaults/demo/ops?since=0", nil)
	signOpsRequest(t, req, seed, now, "n-signed-get", nil)
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
	signOpsRequest(t, req, seed, now, "n-noquery", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("signed GET (no query) status = %d, want 200", rec.Code)
	}
}

// TestOpsAuthMissingHeaders: with auth enabled, requests with no signature
// headers are rejected with 401 (typed envelope).
func TestOpsAuthMissingHeaders(t *testing.T) {
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
// (or non-base64) is rejected with 401.
func TestOpsAuthGarbageSignature(t *testing.T) {
	_, pub := newKeypair(t)
	router := authedRouter(t, pub)
	now := strconv.FormatInt(time.Now().Unix(), 10)

	for _, sig := range []string{"not-base64-!!!", base64.StdEncoding.EncodeToString([]byte("too-short"))} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader([]byte("op")))
		req.Header.Set("X-Sigil-Timestamp", now)
		req.Header.Set("X-Sigil-Nonce", "n-garbage-sig")
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
	signOpsRequest(t, req, seed, stale, "n-stale", body)
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
	signOpsRequest(t, req, seed, future, "n-future", body)
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
	signOpsRequest(t, req, otherSeed, now, "n-wrongkey", body)
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
	signOpsRequest(t, req, seed, now, "n-tamper", []byte("signed-a-different-body"))
	router.ServeHTTP(rec, req)
	assertUnauthorized(t, rec)
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

// TestOpsAuthReplayedNonceRejected: an identical signed request replayed within
// the window is rejected by the nonce store even though its signature is valid.
func TestOpsAuthReplayedNonceRejected(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	now := time.Now().Unix()
	body := []byte("replay-me")

	// First delivery: accepted (201).
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
	signOpsRequest(t, req, seed, now, "n-replay", body)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("first delivery status = %d, want 201", rec.Code)
	}

	// Exact replay (same ts, nonce, body -> byte-identical signature): 401.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
	signOpsRequest(t, req, seed, now, "n-replay", body)
	router.ServeHTTP(rec, req)
	assertUnauthorized(t, rec)
}

// TestOpsAuthMissingNonceHeaderRejected: valid timestamp+signature but no
// X-Sigil-Nonce is rejected.
func TestOpsAuthMissingNonceHeaderRejected(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	now := time.Now().Unix()
	body := []byte("op")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
	signOpsRequest(t, req, seed, now, "n-present", body)
	req.Header.Del("X-Sigil-Nonce")
	router.ServeHTTP(rec, req)
	assertUnauthorized(t, rec)
}

// TestOpsAuthMalformedNonceRejected: a nonce with a control byte, over the length
// cap, or empty is rejected before signature verification.
func TestOpsAuthMalformedNonceRejected(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	now := time.Now().Unix()
	body := []byte("op")

	for _, bad := range []string{"has\nnewline", strings.Repeat("x", opsAuthNonceMaxLen+1), ""} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
		signOpsRequest(t, req, seed, now, bad, body)
		router.ServeHTTP(rec, req)
		assertUnauthorized(t, rec)
	}
}

// TestOpsAuthV1MessageRejected: a request signed under the OLD v1 domain (no
// nonce line) no longer verifies against the v2 server — a deliberate hard cutover.
func TestOpsAuthV1MessageRejected(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	now := time.Now().Unix()
	tsStr := strconv.FormatInt(now, 10)
	body := []byte("op")

	var msg []byte
	msg = append(msg, "sigil-oplog-auth-v1\n"...)
	msg = append(msg, "POST\n"...)
	msg = append(msg, "/v1/vaults/demo/ops\n"...)
	msg = append(msg, '\n') // empty query
	msg = append(msg, tsStr...)
	msg = append(msg, '\n')
	msg = append(msg, body...)
	priv := ed25519.NewKeyFromSeed(seed)
	sig := ed25519.Sign(priv, msg)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
	req.Header.Set("X-Sigil-Timestamp", tsStr)
	req.Header.Set("X-Sigil-Nonce", "n-v1")
	req.Header.Set("X-Sigil-Signature", base64.StdEncoding.EncodeToString(sig))
	router.ServeHTTP(rec, req)
	assertUnauthorized(t, rec)
}

// TestOpsAuthDistinctNoncesBothAccepted: two requests with the SAME timestamp but
// DIFFERENT nonces both verify — distinct nonces are not replays of each other.
func TestOpsAuthDistinctNoncesBothAccepted(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	now := time.Now().Unix()
	body := []byte("op")

	for _, nonce := range []string{"n-distinct-1", "n-distinct-2"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
		signOpsRequest(t, req, seed, now, nonce, body)
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("nonce %q status = %d, want 201", nonce, rec.Code)
		}
	}
}

// TestOpsAuthGetReplayRejected: the read path (opsList -> authorizeOps(r, nil))
// must also reject a replayed nonce, not just the append path.
func TestOpsAuthGetReplayRejected(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	now := time.Now().Unix()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/vaults/demo/ops?since=0", nil)
	signOpsRequest(t, req, seed, now, "n-get-replay", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("first signed GET status = %d, want 200", rec.Code)
	}
	// Byte-identical replay (same ts, nonce, query, empty body): 401.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/vaults/demo/ops?since=0", nil)
	signOpsRequest(t, req, seed, now, "n-get-replay", nil)
	router.ServeHTTP(rec, req)
	assertUnauthorized(t, rec)
}

// TestOpsAuthBase64NonceAccepted: the real CLI sends std-base64 of 16 bytes,
// whose alphabet includes '+', '/', and '=' padding — all within validNonce's
// 0x21..0x7E range. A regression tightening validNonce to base64url/alphanumeric
// would break the shipped contract, so assert such a nonce is accepted.
func TestOpsAuthBase64NonceAccepted(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	now := time.Now().Unix()
	body := []byte("op")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
	signOpsRequest(t, req, seed, now, "AbC+/9de==", body)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("base64-alphabet nonce status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestOpsAuthMaxLenNonceAccepted: a nonce of exactly opsAuthNonceMaxLen bytes
// must be ACCEPTED (only > max is rejected). Guards a '>' vs '>=' off-by-one in
// validNonce (the reject side, max+1, is covered by TestOpsAuthMalformedNonceRejected).
func TestOpsAuthMaxLenNonceAccepted(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)
	now := time.Now().Unix()
	body := []byte("op")

	nonce := strings.Repeat("x", opsAuthNonceMaxLen)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/demo/ops", bytes.NewReader(body))
	signOpsRequest(t, req, seed, now, nonce, body)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("%d-byte nonce status = %d, want 201", opsAuthNonceMaxLen, rec.Code)
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
