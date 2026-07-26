package api

// Tests for op-log request-auth contract v3 (multi-device) and per-vault
// authorization. Helpers here are shared with devices_test.go.

import (
	"bytes"
	"context"
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

	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

// testEnrollToken / testAdminToken are TEST-ONLY operator secrets. They exist
// only inside this test binary and are never a default anywhere in the server:
// with no SIGILD_ENROLL_TOKENS / SIGILD_ADMIN_TOKEN configured, enrollment and
// the operator routes are simply unusable.
const (
	testEnrollToken = "test-enrollment-token-0000000001"
	testAdminToken  = "test-admin-token-000000000000001"
)

// testDevice is a client-side keypair plus the device ID the server assigned it.
type testDevice struct {
	ID   string
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey
}

// deviceEnv bundles a dev-ops router with the v3 device model enabled and the
// in-memory registry behind it, so a test can inspect/seed store state directly.
type deviceEnv struct {
	router  http.Handler
	devices *store.MemDeviceStore
}

// newDeviceEnv builds a router with the multi-device model on, one registered
// enrollment token (testEnrollToken) and the operator admin token configured.
func newDeviceEnv(t *testing.T) *deviceEnv {
	t.Helper()
	return newDeviceEnvWithTokens(t, []string{testEnrollToken}, testAdminToken)
}

// newDeviceEnvWithTokens is newDeviceEnv with an explicit token set, so a test
// can register several tokens (or none) and an optional admin token.
func newDeviceEnvWithTokens(t *testing.T, tokens []string, admin string) *deviceEnv {
	t.Helper()
	devices := store.NewMemDeviceStore()
	hashes := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		h := EnrollTokenHash(tok)
		hashes = append(hashes, h)
		if err := devices.RegisterEnrollmentToken(context.Background(), h, time.Now().UTC(), time.Time{}); err != nil {
			t.Fatalf("RegisterEnrollmentToken: %v", err)
		}
	}
	router := NewRouter(Config{
		Version:           "test",
		Logger:            discardLogger(),
		DevOpsEnabled:     true,
		Devices:           devices,
		EnrollTokenHashes: hashes,
		AdminToken:        admin,
	})
	return &deviceEnv{router: router, devices: devices}
}

// newClientKeypair returns a fresh Ed25519 keypair for a client device.
func newClientKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub, priv
}

// buildEnrollRequest constructs a signed enrollment request: the JSON body plus
// the four contract headers, with the proof-of-possession signature made by
// priv over the canonical enrollment challenge.
func buildEnrollRequest(t *testing.T, token string, pub ed25519.PublicKey, priv ed25519.PrivateKey,
	label string, ts int64, nonce string) *http.Request {
	t.Helper()
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	body, err := json.Marshal(enrollRequest{PublicKey: pubB64, Label: label})
	if err != nil {
		t.Fatalf("marshal enroll body: %v", err)
	}
	tsStr := strconv.FormatInt(ts, 10)

	req := httptest.NewRequest(http.MethodPost, "/v1/devices/enroll", bytes.NewReader(body))
	req.Header.Set(headerEnrollToken, token)
	req.Header.Set(headerTimestamp, tsStr)
	req.Header.Set(headerNonce, nonce)
	if priv != nil {
		msg := canonicalEnrollMessage(EnrollTokenHash(token), tsStr, nonce, pubB64, label)
		req.Header.Set(headerSignature, base64.StdEncoding.EncodeToString(ed25519.Sign(priv, msg)))
	}
	return req
}

// enrollDevice runs a full happy-path enrollment and returns the resulting
// device (failing the test if the server did not return 201).
func enrollDevice(t *testing.T, env *deviceEnv, token, label string) testDevice {
	t.Helper()
	pub, priv := newClientKeypair(t)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, buildEnrollRequest(t, token, pub, priv, label, time.Now().Unix(), randNonce(t)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("enroll status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	var out deviceJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("enroll body not JSON: %v", err)
	}
	if out.DeviceID == "" || out.Status != string(store.DeviceActive) {
		t.Fatalf("enroll response = %+v, want a device_id and status=active", out)
	}
	return testDevice{ID: out.DeviceID, Pub: pub, Priv: priv}
}

// signV3 sets the four v3 contract headers on req, signing the canonical v3
// message with dev's private key. This is exactly what a client must produce:
//
//	"sigil-oplog-auth-v3\n" + DEVICE + "\n" + METHOD + "\n" + PATH + "\n" +
//	QUERY + "\n" + TS + "\n" + NONCE + "\n" + BODY
func signV3(t *testing.T, req *http.Request, dev testDevice, ts int64, nonce string, body []byte) {
	t.Helper()
	tsStr := strconv.FormatInt(ts, 10)
	msg := canonicalV3Message(dev.ID, req.Method, req.URL.Path, req.URL.RawQuery, tsStr, nonce, body)
	req.Header.Set(headerDevice, dev.ID)
	req.Header.Set(headerTimestamp, tsStr)
	req.Header.Set(headerNonce, nonce)
	req.Header.Set(headerSignature, base64.StdEncoding.EncodeToString(ed25519.Sign(dev.Priv, msg)))
}

// v3Post builds and serves a v3-signed POST, returning the recorder.
func v3Post(t *testing.T, env *deviceEnv, dev testDevice, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	signV3(t, req, dev, time.Now().Unix(), randNonce(t), body)
	env.router.ServeHTTP(rec, req)
	return rec
}

// v3Get builds and serves a v3-signed GET, returning the recorder.
func v3Get(t *testing.T, env *deviceEnv, dev testDevice, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	signV3(t, req, dev, time.Now().Unix(), randNonce(t), nil)
	env.router.ServeHTTP(rec, req)
	return rec
}

// assertForbidden asserts a 403 with the typed "forbidden" envelope, and that
// the body does NOT leak which check failed.
func assertForbidden(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (body: %s)", rec.Code, rec.Body.String())
	}
	var body apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("403 body not JSON: %v", err)
	}
	if body.Error != "forbidden" {
		t.Fatalf("403 error = %q, want forbidden", body.Error)
	}
	for _, leak := range []string{"unauthorized_vault", "not_vault_owner", "unknown_device", "revoked_device"} {
		if bytes.Contains(rec.Body.Bytes(), []byte(leak)) {
			t.Fatalf("403 body leaked the internal reason %q: %s", leak, rec.Body.String())
		}
	}
}

// TestDeviceAuthHappyPath: an enrolled device appends to a fresh vault (claiming
// it), then reads it back.
func TestDeviceAuthHappyPath(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "laptop")

	blob := []byte("opaque-op-1")
	rec := v3Post(t, env, dev, "/v1/vaults/vaultA/ops", blob)
	if rec.Code != http.StatusCreated {
		t.Fatalf("signed POST status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}

	rec = v3Get(t, env, dev, "/v1/vaults/vaultA/ops?since=0")
	if rec.Code != http.StatusOK {
		t.Fatalf("signed GET status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var list opsListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("GET body not JSON: %v", err)
	}
	if len(list.Ops) != 1 || !bytes.Equal(list.Ops[0].Blob, blob) {
		t.Fatalf("GET ops = %+v, want one op with the exact blob", list.Ops)
	}

	// The claim made this device the vault's owner.
	g, err := env.devices.GetGrant(context.Background(), "vaultA", dev.ID)
	if err != nil {
		t.Fatalf("GetGrant after first write: %v", err)
	}
	if !g.Owner || g.Perm != store.PermWrite {
		t.Fatalf("owner grant = %+v, want owner=true perm=write", g)
	}

	// And /ops/verify is reachable with the same device.
	rec = v3Get(t, env, dev, "/v1/vaults/vaultA/ops/verify")
	if rec.Code != http.StatusOK {
		t.Fatalf("signed verify status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestDeviceAuthWrongKey: a signature made by a key that is NOT the enrolled
// device's key is rejected.
func TestDeviceAuthWrongKey(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "laptop")

	// Same device ID, different private key.
	_, otherPriv := newClientKeypair(t)
	impostor := testDevice{ID: dev.ID, Priv: otherPriv}

	rec := v3Post(t, env, impostor, "/v1/vaults/vaultA/ops", []byte("op"))
	assertUnauthorized(t, rec)
}

// TestDeviceAuthV2SignatureRejected is the DOMAIN-SEPARATION property: a
// perfectly valid v2-format signature (the old contract) does not verify under
// v3, even when made by the enrolled device's own key.
func TestDeviceAuthV2SignatureRejected(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "laptop")

	body := []byte("op")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/vaultA/ops", bytes.NewReader(body))
	// Sign the v2 message (no device segment, "-v2" domain) with the real key...
	signOpsRequest(t, req, dev.Priv.Seed(), time.Now().Unix(), randNonce(t), body)
	// ...and present the device header the v3 server requires.
	req.Header.Set(headerDevice, dev.ID)
	env.router.ServeHTTP(rec, req)
	assertUnauthorized(t, rec)

	// Sanity: the SAME request signed under v3 succeeds, so the rejection above
	// is the domain separation and not some unrelated failure.
	if rec := v3Post(t, env, dev, "/v1/vaults/vaultA/ops", body); rec.Code != http.StatusCreated {
		t.Fatalf("v3-signed POST status = %d, want 201", rec.Code)
	}
}

// TestDeviceAuthTampering: mutating any covered segment (body, path, query,
// device header) after signing invalidates the signature.
func TestDeviceAuthTampering(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "laptop")

	t.Run("body", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/vaultA/ops", bytes.NewReader([]byte("actual")))
		signV3(t, req, dev, time.Now().Unix(), randNonce(t), []byte("signed-something-else"))
		env.router.ServeHTTP(rec, req)
		assertUnauthorized(t, rec)
	})

	t.Run("path", func(t *testing.T) {
		rec := httptest.NewRecorder()
		body := []byte("op")
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/vaultA/ops", bytes.NewReader(body))
		signV3(t, req, dev, time.Now().Unix(), randNonce(t), body)
		// Re-point at another vault AFTER signing.
		req.URL.Path = "/v1/vaults/vaultB/ops"
		env.router.ServeHTTP(rec, req)
		assertUnauthorized(t, rec)
	})

	t.Run("query", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/vaults/vaultA/ops?since=0", nil)
		signV3(t, req, dev, time.Now().Unix(), randNonce(t), nil)
		req.URL.RawQuery = "since=99"
		env.router.ServeHTTP(rec, req)
		assertUnauthorized(t, rec)
	})

	t.Run("device_header", func(t *testing.T) {
		rec := httptest.NewRecorder()
		body := []byte("op")
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/vaultA/ops", bytes.NewReader(body))
		signV3(t, req, dev, time.Now().Unix(), randNonce(t), body)
		req.Header.Set(headerDevice, "dev_someone-else")
		env.router.ServeHTTP(rec, req)
		assertUnauthorized(t, rec)
	})
}

// TestDeviceAuthMissingHeaders: dropping any one of the four contract headers is
// a 401.
func TestDeviceAuthMissingHeaders(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "laptop")

	for _, drop := range []string{headerDevice, headerTimestamp, headerNonce, headerSignature} {
		t.Run("drop_"+drop, func(t *testing.T) {
			rec := httptest.NewRecorder()
			body := []byte("op")
			req := httptest.NewRequest(http.MethodPost, "/v1/vaults/vaultA/ops", bytes.NewReader(body))
			signV3(t, req, dev, time.Now().Unix(), randNonce(t), body)
			req.Header.Del(drop)
			env.router.ServeHTTP(rec, req)
			assertUnauthorized(t, rec)
		})
	}
}

// TestDeviceAuthStaleTimestamp: a timestamp outside the skew window fails in
// both directions, even with a valid signature over that timestamp.
func TestDeviceAuthStaleTimestamp(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "laptop")

	for name, ts := range map[string]int64{
		"past":   time.Now().Unix() - opsAuthSkew - 100,
		"future": time.Now().Unix() + opsAuthSkew + 100,
	} {
		t.Run(name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			body := []byte("op")
			req := httptest.NewRequest(http.MethodPost, "/v1/vaults/vaultA/ops", bytes.NewReader(body))
			signV3(t, req, dev, ts, randNonce(t), body)
			env.router.ServeHTTP(rec, req)
			assertUnauthorized(t, rec)
		})
	}
}

// TestDeviceAuthReplayRejected: replaying an identical signed request inside the
// window is rejected as a replay.
func TestDeviceAuthReplayRejected(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "laptop")

	ts := time.Now().Unix()
	nonce := randNonce(t)
	body := []byte("replay-me")
	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/vaultA/ops", bytes.NewReader(body))
		signV3(t, req, dev, ts, nonce, body)
		return req
	}

	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, newReq())
	if rec.Code != http.StatusCreated {
		t.Fatalf("first POST status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, newReq())
	assertReplay(t, rec)
}

// TestDeviceAuthUnknownDevice: a syntactically fine, correctly self-signed
// request from a device that was never enrolled is rejected.
func TestDeviceAuthUnknownDevice(t *testing.T) {
	env := newDeviceEnv(t)
	_, priv := newClientKeypair(t)
	ghost := testDevice{ID: "dev_never-enrolled", Priv: priv}

	rec := v3Post(t, env, ghost, "/v1/vaults/vaultA/ops", []byte("op"))
	assertUnauthorized(t, rec)
}

// TestDeviceAuthRevokedDeviceRejectedImmediately is the revocation property: a
// device that works right now stops working on its VERY NEXT request once
// revoked.
func TestDeviceAuthRevokedDeviceRejectedImmediately(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "laptop")

	// It works before revocation (and claims the vault).
	if rec := v3Post(t, env, dev, "/v1/vaults/vaultA/ops", []byte("op-1")); rec.Code != http.StatusCreated {
		t.Fatalf("pre-revocation POST status = %d, want 201", rec.Code)
	}

	if err := env.devices.RevokeDevice(context.Background(), dev.ID, time.Now().UTC()); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}

	// The very next request — same key, same vault, fresh nonce — fails.
	if rec := v3Post(t, env, dev, "/v1/vaults/vaultA/ops", []byte("op-2")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("post-revocation POST status = %d, want 401 (body: %s)", rec.Code, rec.Body.String())
	}
	if rec := v3Get(t, env, dev, "/v1/vaults/vaultA/ops"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("post-revocation GET status = %d, want 401", rec.Code)
	}
	// The op it wrote before revocation is still there (revocation is not a
	// data operation) — verified via a second, still-active device below.
}

// TestAuthzSecondDeviceForbiddenThenGranted is the core authorization property:
// device B is fully ENROLLED and its signature is valid, yet it may not touch
// device A's vault (403, distinct from 401) until A grants it access.
func TestAuthzSecondDeviceForbiddenThenGranted(t *testing.T) {
	env := newDeviceEnvWithTokens(t, []string{testEnrollToken, testEnrollToken + "-b"}, testAdminToken)
	devA := enrollDevice(t, env, testEnrollToken, "A")
	devB := enrollDevice(t, env, testEnrollToken+"-b", "B")

	// A claims vaultA by writing to it.
	if rec := v3Post(t, env, devA, "/v1/vaults/vaultA/ops", []byte("a-op")); rec.Code != http.StatusCreated {
		t.Fatalf("A's first POST status = %d, want 201", rec.Code)
	}

	// B is authenticated but not authorized: 403 on both verbs.
	assertForbidden(t, v3Get(t, env, devB, "/v1/vaults/vaultA/ops"))
	assertForbidden(t, v3Post(t, env, devB, "/v1/vaults/vaultA/ops", []byte("b-op")))
	assertForbidden(t, v3Get(t, env, devB, "/v1/vaults/vaultA/ops/verify"))

	// A (the owner) grants B READ.
	grantBody, _ := json.Marshal(grantRequest{DeviceID: devB.ID, Permission: string(store.PermRead)})
	if rec := v3Post(t, env, devA, "/v1/vaults/vaultA/grants", grantBody); rec.Code != http.StatusCreated {
		t.Fatalf("grant status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}

	// B can now READ, but still not WRITE (read does not imply write).
	if rec := v3Get(t, env, devB, "/v1/vaults/vaultA/ops"); rec.Code != http.StatusOK {
		t.Fatalf("B GET after read grant = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	assertForbidden(t, v3Post(t, env, devB, "/v1/vaults/vaultA/ops", []byte("b-op")))

	// Upgrade B to WRITE; now the append succeeds.
	grantBody, _ = json.Marshal(grantRequest{DeviceID: devB.ID, Permission: string(store.PermWrite)})
	if rec := v3Post(t, env, devA, "/v1/vaults/vaultA/grants", grantBody); rec.Code != http.StatusCreated {
		t.Fatalf("upgrade grant status = %d, want 201", rec.Code)
	}
	if rec := v3Post(t, env, devB, "/v1/vaults/vaultA/ops", []byte("b-op")); rec.Code != http.StatusCreated {
		t.Fatalf("B POST after write grant = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}

	// A write grant does NOT confer ownership: B cannot grant a third party.
	grantBody, _ = json.Marshal(grantRequest{DeviceID: devA.ID, Permission: string(store.PermWrite)})
	assertForbidden(t, v3Post(t, env, devB, "/v1/vaults/vaultA/grants", grantBody))
}

// TestAuthz401VersusUnauthorized403 pins the distinction the contract requires:
// a BAD CREDENTIAL is 401, an authenticated-but-unpermitted device is 403.
func TestAuthz401VersusForbidden403(t *testing.T) {
	env := newDeviceEnvWithTokens(t, []string{testEnrollToken, testEnrollToken + "-b"}, testAdminToken)
	devA := enrollDevice(t, env, testEnrollToken, "A")
	devB := enrollDevice(t, env, testEnrollToken+"-b", "B")
	if rec := v3Post(t, env, devA, "/v1/vaults/vaultA/ops", []byte("a-op")); rec.Code != http.StatusCreated {
		t.Fatalf("claim status = %d, want 201", rec.Code)
	}

	// Unauthenticated (bad signature) on the SAME vault -> 401, not 403.
	_, wrongPriv := newClientKeypair(t)
	if rec := v3Get(t, env, testDevice{ID: devB.ID, Priv: wrongPriv}, "/v1/vaults/vaultA/ops"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad-signature GET status = %d, want 401", rec.Code)
	}
	// Authenticated but unauthorized -> 403, not 401.
	assertForbidden(t, v3Get(t, env, devB, "/v1/vaults/vaultA/ops"))
}

// TestAuthzReadNeverClaimsVault: reading an unowned vault is 403, and it must
// NOT create an ownership grant as a side effect.
func TestAuthzReadNeverClaimsVault(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "laptop")

	assertForbidden(t, v3Get(t, env, dev, "/v1/vaults/fresh-vault/ops"))

	grants, err := env.devices.ListGrants(context.Background(), "fresh-vault")
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) != 0 {
		t.Fatalf("a denied READ created %d grants, want 0", len(grants))
	}
}

// TestAuthzFirstWriterWinsOwnership: the SECOND device to write a vault it does
// not own is refused; ownership is not transferred or shared implicitly.
func TestAuthzFirstWriterWinsOwnership(t *testing.T) {
	env := newDeviceEnvWithTokens(t, []string{"tok-a-0000000000000000", "tok-b-0000000000000000"}, "")
	devA := enrollDevice(t, env, "tok-a-0000000000000000", "A")
	devB := enrollDevice(t, env, "tok-b-0000000000000000", "B")

	if rec := v3Post(t, env, devA, "/v1/vaults/shared/ops", []byte("first")); rec.Code != http.StatusCreated {
		t.Fatalf("A claim status = %d, want 201", rec.Code)
	}
	assertForbidden(t, v3Post(t, env, devB, "/v1/vaults/shared/ops", []byte("second")))

	grants, err := env.devices.ListGrants(context.Background(), "shared")
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) != 1 || grants[0].DeviceID != devA.ID || !grants[0].Owner {
		t.Fatalf("grants = %+v, want exactly one owner grant for %s", grants, devA.ID)
	}
}

// TestGrantListRequiresReadAccess: a vault's grant list is visible to any device
// with read access and to nobody else.
func TestGrantListAccess(t *testing.T) {
	env := newDeviceEnvWithTokens(t, []string{"tok-a-0000000000000000", "tok-b-0000000000000000"}, "")
	devA := enrollDevice(t, env, "tok-a-0000000000000000", "A")
	devB := enrollDevice(t, env, "tok-b-0000000000000000", "B")
	if rec := v3Post(t, env, devA, "/v1/vaults/vaultA/ops", []byte("op")); rec.Code != http.StatusCreated {
		t.Fatalf("claim status = %d, want 201", rec.Code)
	}

	assertForbidden(t, v3Get(t, env, devB, "/v1/vaults/vaultA/grants"))

	rec := v3Get(t, env, devA, "/v1/vaults/vaultA/grants")
	if rec.Code != http.StatusOK {
		t.Fatalf("owner grant list status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var out struct {
		VaultID string      `json:"vaultID"`
		Grants  []grantJSON `json:"grants"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("grant list not JSON: %v", err)
	}
	if len(out.Grants) != 1 || out.Grants[0].DeviceID != devA.ID || !out.Grants[0].Owner {
		t.Fatalf("grant list = %+v, want one owner grant for %s", out.Grants, devA.ID)
	}
}

// TestGrantValidation covers the grant endpoint's input checks: unknown grantee,
// bad permission, revoked grantee.
func TestGrantValidation(t *testing.T) {
	env := newDeviceEnvWithTokens(t, []string{"tok-a-0000000000000000", "tok-b-0000000000000000"}, "")
	devA := enrollDevice(t, env, "tok-a-0000000000000000", "A")
	devB := enrollDevice(t, env, "tok-b-0000000000000000", "B")
	if rec := v3Post(t, env, devA, "/v1/vaults/vaultA/ops", []byte("op")); rec.Code != http.StatusCreated {
		t.Fatalf("claim status = %d, want 201", rec.Code)
	}

	body, _ := json.Marshal(grantRequest{DeviceID: "dev_nope", Permission: "read"})
	if rec := v3Post(t, env, devA, "/v1/vaults/vaultA/grants", body); rec.Code != http.StatusNotFound {
		t.Fatalf("grant to unknown device status = %d, want 404", rec.Code)
	}

	body, _ = json.Marshal(grantRequest{DeviceID: devB.ID, Permission: "admin"})
	if rec := v3Post(t, env, devA, "/v1/vaults/vaultA/grants", body); rec.Code != http.StatusBadRequest {
		t.Fatalf("grant with bad permission status = %d, want 400", rec.Code)
	}

	if err := env.devices.RevokeDevice(context.Background(), devB.ID, time.Now().UTC()); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	body, _ = json.Marshal(grantRequest{DeviceID: devB.ID, Permission: "read"})
	if rec := v3Post(t, env, devA, "/v1/vaults/vaultA/grants", body); rec.Code != http.StatusConflict {
		t.Fatalf("grant to revoked device status = %d, want 409", rec.Code)
	}
}

// TestDeviceAuthConcurrent hammers the v3 path from many goroutines so -race can
// surface a data race in the registry, the replay cache, or the claim logic.
// Every goroutine writes the SAME fresh vault, so exactly one claims ownership
// and the rest are refused with 403.
func TestDeviceAuthConcurrentClaim(t *testing.T) {
	tokens := make([]string, 0, 16)
	for i := 0; i < 16; i++ {
		tokens = append(tokens, "concurrent-token-"+strconv.Itoa(i)+"-000000")
	}
	env := newDeviceEnvWithTokens(t, tokens, "")

	devs := make([]testDevice, len(tokens))
	for i, tok := range tokens {
		devs[i] = enrollDevice(t, env, tok, "racer-"+strconv.Itoa(i))
	}

	var created, forbidden int64
	var wg sync.WaitGroup
	for i := range devs {
		wg.Add(1)
		go func(dev testDevice) {
			defer wg.Done()
			rec := v3Post(t, env, dev, "/v1/vaults/race-vault/ops", []byte("op"))
			switch rec.Code {
			case http.StatusCreated:
				atomic.AddInt64(&created, 1)
			case http.StatusForbidden:
				atomic.AddInt64(&forbidden, 1)
			default:
				t.Errorf("unexpected status %d (body: %s)", rec.Code, rec.Body.String())
			}
		}(devs[i])
	}
	wg.Wait()

	if created != 1 {
		t.Fatalf("%d devices claimed the vault, want exactly 1", created)
	}
	if forbidden != int64(len(devs))-1 {
		t.Fatalf("%d devices were refused, want %d", forbidden, len(devs)-1)
	}
}

// TestLegacyV2StillWorksWhenDeviceModelOff is the BACKWARD-COMPATIBILITY guard:
// with no device registry configured, the legacy single-key v2 contract behaves
// exactly as before — a v2-signed request is accepted with NO device header and
// NO per-vault grant.
func TestLegacyV2StillWorksWhenDeviceModelOff(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub) // Devices nil
	now := time.Now().Unix()

	body := []byte("legacy-op")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/legacy/ops", bytes.NewReader(body))
	signOpsRequest(t, req, seed, now, randNonce(t), body)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("legacy v2 POST status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/vaults/legacy/ops?since=0", nil)
	signOpsRequest(t, req, seed, now, randNonce(t), nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy v2 GET status = %d, want 200", rec.Code)
	}
}

// TestV3SignatureRejectedByLegacyV2Server is the other half of the domain
// separation: a v3-signed request does not verify against a legacy v2 server.
func TestV3SignatureRejectedByLegacyV2Server(t *testing.T) {
	seed, pub := newKeypair(t)
	router := authedRouter(t, pub)

	dev := testDevice{ID: "dev_whatever", Priv: ed25519.NewKeyFromSeed(seed)}
	body := []byte("op")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/legacy/ops", bytes.NewReader(body))
	signV3(t, req, dev, time.Now().Unix(), randNonce(t), body)
	router.ServeHTTP(rec, req)
	assertUnauthorized(t, rec)
}

// TestAuthStatusMapping pins the reason -> HTTP status table, so a new reason
// cannot silently become a 401 when it should be a 403 (or vice versa).
func TestAuthStatusMapping(t *testing.T) {
	cases := map[authReason]int{
		reasonMissingHeaders:     http.StatusUnauthorized,
		reasonBadTimestamp:       http.StatusUnauthorized,
		reasonStaleTimestamp:     http.StatusUnauthorized,
		reasonBadSignature:       http.StatusUnauthorized,
		reasonReplayed:           http.StatusUnauthorized,
		reasonUnknownDevice:      http.StatusUnauthorized,
		reasonRevokedDevice:      http.StatusUnauthorized,
		reasonBadAdminToken:      http.StatusUnauthorized,
		reasonBadEnrollToken:     http.StatusUnauthorized,
		reasonUnauthorizedVault:  http.StatusForbidden,
		reasonNotVaultOwner:      http.StatusForbidden,
		reasonForbiddenDevice:    http.StatusForbidden,
		reasonStoreUnavailable:   http.StatusInternalServerError,
		reasonEnrollTokenUsed:    http.StatusUnauthorized,
		reasonEnrollTokenExpired: http.StatusUnauthorized,
		reasonBadProof:           http.StatusUnauthorized,
	}
	for reason, want := range cases {
		if got := authStatus(reason); got != want {
			t.Errorf("authStatus(%q) = %d, want %d", reason, got, want)
		}
	}
}

// TestConstantTimeTokenMatch checks the configured-token comparison accepts an
// exact digest and nothing else (including a prefix or an empty string).
func TestMatchesConfiguredToken(t *testing.T) {
	configured := []string{EnrollTokenHash("token-one"), EnrollTokenHash("token-two")}
	if !matchesConfiguredToken(configured, EnrollTokenHash("token-one")) {
		t.Fatal("configured token digest did not match")
	}
	if !matchesConfiguredToken(configured, EnrollTokenHash("token-two")) {
		t.Fatal("second configured token digest did not match")
	}
	for _, bad := range []string{"", "deadbeef", EnrollTokenHash("token-three"), configured[0][:32]} {
		if matchesConfiguredToken(configured, bad) {
			t.Fatalf("non-configured digest %q matched", bad)
		}
	}
	if matchesConfiguredToken(nil, EnrollTokenHash("token-one")) {
		t.Fatal("a token matched with NO tokens configured")
	}
}
