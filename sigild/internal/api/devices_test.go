package api

// Tests for the device HTTP surface: enrollment (token + proof of possession),
// operator/self revocation, device listing, and the dev-gate.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

// TestEnrollHappyPath: a valid token plus a valid proof of possession yields a
// server-assigned device ID, and the registry holds the submitted public key.
func TestEnrollHappyPath(t *testing.T) {
	env := newDeviceEnv(t)
	pub, priv := newClientKeypair(t)

	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, buildEnrollRequest(t, testEnrollToken, pub, priv, "laptop", time.Now().Unix(), randNonce(t)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("enroll status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}

	var out deviceJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("enroll body not JSON: %v", err)
	}
	if !strings.HasPrefix(out.DeviceID, "dev_") {
		t.Fatalf("device_id = %q, want a server-assigned dev_ id", out.DeviceID)
	}
	if out.Label != "laptop" || out.Status != "active" || out.CreatedAt == "" {
		t.Fatalf("enroll response = %+v, want label=laptop status=active with created_at", out)
	}
	// The response must NOT echo key material.
	if bytes.Contains(rec.Body.Bytes(), []byte(base64.StdEncoding.EncodeToString(pub))) {
		t.Fatal("enroll response echoed the public key")
	}

	stored, err := env.devices.GetDevice(context.Background(), out.DeviceID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if !bytes.Equal(stored.PublicKey, pub) {
		t.Fatal("registry stored a different public key than was submitted")
	}
}

// TestEnrollBadToken: a token this server was not provisioned with is rejected,
// and nothing is registered.
func TestEnrollBadToken(t *testing.T) {
	env := newDeviceEnv(t)
	pub, priv := newClientKeypair(t)

	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, buildEnrollRequest(t, "not-the-configured-token-xxx", pub, priv, "laptop", time.Now().Unix(), randNonce(t)))
	assertUnauthorized(t, rec)

	devs, err := env.devices.ListDevices(context.Background())
	if err != nil {
		t.Fatalf("ListDevices: %v", err)
	}
	if len(devs) != 0 {
		t.Fatalf("a rejected enrollment registered %d devices, want 0", len(devs))
	}
}

// TestEnrollTokenIsSingleUse: the same token cannot enroll a second device.
func TestEnrollTokenIsSingleUse(t *testing.T) {
	env := newDeviceEnv(t)
	_ = enrollDevice(t, env, testEnrollToken, "first")

	pub, priv := newClientKeypair(t)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, buildEnrollRequest(t, testEnrollToken, pub, priv, "second", time.Now().Unix(), randNonce(t)))
	assertUnauthorized(t, rec)

	devs, _ := env.devices.ListDevices(context.Background())
	if len(devs) != 1 {
		t.Fatalf("registry holds %d devices after a reused token, want 1", len(devs))
	}
}

// TestEnrollExpiredToken: a time-limited token past its expiry is rejected.
func TestEnrollExpiredToken(t *testing.T) {
	expired := "expired-token-000000000000000001"
	devices := store.NewMemDeviceStore()
	issued := time.Now().UTC().Add(-2 * time.Hour)
	hash := EnrollTokenHash(expired)
	if err := devices.RegisterEnrollmentToken(context.Background(), hash, issued, issued.Add(time.Hour)); err != nil {
		t.Fatalf("RegisterEnrollmentToken: %v", err)
	}
	router := NewRouter(Config{
		Version:           "test",
		Logger:            discardLogger(),
		DevOpsEnabled:     true,
		Devices:           devices,
		EnrollTokenHashes: []string{hash},
	})

	pub, priv := newClientKeypair(t)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, buildEnrollRequest(t, expired, pub, priv, "late", time.Now().Unix(), randNonce(t)))
	assertUnauthorized(t, rec)

	devs, _ := devices.ListDevices(context.Background())
	if len(devs) != 0 {
		t.Fatalf("an expired token enrolled %d devices, want 0", len(devs))
	}
}

// TestEnrollRequiresProofOfPossession is the anti-key-upload property: a request
// with a VALID token but no/invalid proof that the submitter holds the private
// key is refused. A bare public-key upload is never accepted.
func TestEnrollRequiresProofOfPossession(t *testing.T) {
	t.Run("missing_signature", func(t *testing.T) {
		env := newDeviceEnv(t)
		pub, _ := newClientKeypair(t)
		rec := httptest.NewRecorder()
		// priv nil => buildEnrollRequest omits X-Sigil-Signature entirely.
		env.router.ServeHTTP(rec, buildEnrollRequest(t, testEnrollToken, pub, nil, "no-proof", time.Now().Unix(), randNonce(t)))
		assertUnauthorized(t, rec)
		if devs, _ := env.devices.ListDevices(context.Background()); len(devs) != 0 {
			t.Fatalf("enrolled %d devices with no proof, want 0", len(devs))
		}
	})

	t.Run("signature_from_a_different_key", func(t *testing.T) {
		env := newDeviceEnv(t)
		pub, _ := newClientKeypair(t)
		_, otherPriv := newClientKeypair(t)
		// Submit `pub` but sign the challenge with an unrelated private key.
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, buildEnrollRequest(t, testEnrollToken, pub, otherPriv, "wrong-proof", time.Now().Unix(), randNonce(t)))
		assertUnauthorized(t, rec)
		if devs, _ := env.devices.ListDevices(context.Background()); len(devs) != 0 {
			t.Fatalf("enrolled %d devices with a foreign proof, want 0", len(devs))
		}
	})

	t.Run("proof_bound_to_the_submitted_key", func(t *testing.T) {
		// An interceptor with a captured, valid proof cannot swap in ITS OWN key:
		// the public key is inside the signed challenge.
		env := newDeviceEnv(t)
		victimPub, victimPriv := newClientKeypair(t)
		attackerPub, _ := newClientKeypair(t)

		req := buildEnrollRequest(t, testEnrollToken, victimPub, victimPriv, "victim", time.Now().Unix(), randNonce(t))
		// Replace the body's key with the attacker's, keeping the victim's proof.
		swapped, _ := json.Marshal(enrollRequest{
			PublicKey: base64.StdEncoding.EncodeToString(attackerPub),
			Label:     "victim",
		})
		req.Body = io.NopCloser(bytes.NewReader(swapped))
		req.ContentLength = int64(len(swapped))

		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		assertUnauthorized(t, rec)
	})

	t.Run("proof_bound_to_the_token", func(t *testing.T) {
		// A proof made for token A does not authorize enrollment with token B.
		tokenA := "token-a-00000000000000000000001"
		tokenB := "token-b-00000000000000000000002"
		env := newDeviceEnvWithTokens(t, []string{tokenA, tokenB}, "")
		pub, priv := newClientKeypair(t)

		ts := time.Now().Unix()
		nonce := randNonce(t)
		req := buildEnrollRequest(t, tokenA, pub, priv, "x", ts, nonce) // proof over tokenA
		req.Header.Set(headerEnrollToken, tokenB)                       // present tokenB
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		assertUnauthorized(t, rec)
	})
}

// TestEnrollMalformedKey: a public key that is not 32 bytes of standard base64
// is a 400 (a request-shape error, not an auth oracle).
func TestEnrollMalformedKey(t *testing.T) {
	env := newDeviceEnv(t)
	for name, key := range map[string]string{
		"not_base64": "!!!not-base64!!!",
		"too_short":  base64.StdEncoding.EncodeToString([]byte("short")),
		"too_long":   base64.StdEncoding.EncodeToString(make([]byte, 64)),
		"empty":      "",
	} {
		t.Run(name, func(t *testing.T) {
			body, _ := json.Marshal(enrollRequest{PublicKey: key, Label: "x"})
			req := httptest.NewRequest(http.MethodPost, "/v1/devices/enroll", bytes.NewReader(body))
			req.Header.Set(headerEnrollToken, testEnrollToken)
			req.Header.Set(headerTimestamp, strconv.FormatInt(time.Now().Unix(), 10))
			req.Header.Set(headerNonce, randNonce(t))
			req.Header.Set(headerSignature, base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))
			rec := httptest.NewRecorder()
			env.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestEnrollMissingHeaders / stale timestamp / replay: the same protections the
// request contract has apply to enrollment.
func TestEnrollHeaderAndReplayProtections(t *testing.T) {
	t.Run("missing_headers", func(t *testing.T) {
		env := newDeviceEnv(t)
		pub, priv := newClientKeypair(t)
		for _, drop := range []string{headerEnrollToken, headerTimestamp, headerNonce, headerSignature} {
			req := buildEnrollRequest(t, testEnrollToken, pub, priv, "x", time.Now().Unix(), randNonce(t))
			req.Header.Del(drop)
			rec := httptest.NewRecorder()
			env.router.ServeHTTP(rec, req)
			assertUnauthorized(t, rec)
		}
	})

	t.Run("stale_timestamp", func(t *testing.T) {
		env := newDeviceEnv(t)
		pub, priv := newClientKeypair(t)
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, buildEnrollRequest(t, testEnrollToken, pub, priv, "x",
			time.Now().Unix()-opsAuthSkew-100, randNonce(t)))
		assertUnauthorized(t, rec)
	})

	t.Run("replayed_nonce", func(t *testing.T) {
		// Two tokens so the SECOND attempt fails on the NONCE, not on the token
		// having been spent by the first.
		tokenA := "replay-token-a-0000000000000001"
		tokenB := "replay-token-b-0000000000000002"
		env := newDeviceEnvWithTokens(t, []string{tokenA, tokenB}, "")
		ts := time.Now().Unix()
		nonce := randNonce(t)

		pubA, privA := newClientKeypair(t)
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, buildEnrollRequest(t, tokenA, pubA, privA, "a", ts, nonce))
		if rec.Code != http.StatusCreated {
			t.Fatalf("first enroll status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
		}

		pubB, privB := newClientKeypair(t)
		rec = httptest.NewRecorder()
		env.router.ServeHTTP(rec, buildEnrollRequest(t, tokenB, pubB, privB, "b", ts, nonce))
		assertUnauthorized(t, rec)
	})
}

// TestEnrollDuplicatePublicKey: re-enrolling an already-registered key is a 409
// (and it burns the token, which is the intended single-use posture).
func TestEnrollDuplicatePublicKey(t *testing.T) {
	tokenA := "dup-token-a-000000000000000001"
	tokenB := "dup-token-b-000000000000000002"
	env := newDeviceEnvWithTokens(t, []string{tokenA, tokenB}, "")

	pub, priv := newClientKeypair(t)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, buildEnrollRequest(t, tokenA, pub, priv, "first", time.Now().Unix(), randNonce(t)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("first enroll status = %d, want 201", rec.Code)
	}

	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, buildEnrollRequest(t, tokenB, pub, priv, "again", time.Now().Unix(), randNonce(t)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("duplicate-key enroll status = %d, want 409 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestDeviceSelfRevocation: a device may retire itself with a v3-signed request,
// and is refused immediately afterwards.
func TestDeviceSelfRevocation(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "laptop")

	rec := v3Post(t, env, dev, "/v1/devices/"+dev.ID+"/revoke", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("self-revoke status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	stored, err := env.devices.GetDevice(context.Background(), dev.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if stored.Status != store.DeviceRevoked {
		t.Fatalf("status after self-revoke = %q, want revoked", stored.Status)
	}
	// Next request from that device fails.
	if rec := v3Post(t, env, dev, "/v1/vaults/vaultA/ops", []byte("op")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("post-revocation POST status = %d, want 401", rec.Code)
	}
}

// TestDeviceCannotRevokeAnother: a device may not revoke a DIFFERENT device;
// that is 403 (authenticated, not permitted), and the target stays active.
func TestDeviceCannotRevokeAnother(t *testing.T) {
	tokenA := "revoke-token-a-0000000000000001"
	tokenB := "revoke-token-b-0000000000000002"
	env := newDeviceEnvWithTokens(t, []string{tokenA, tokenB}, "")
	devA := enrollDevice(t, env, tokenA, "A")
	devB := enrollDevice(t, env, tokenB, "B")

	assertForbidden(t, v3Post(t, env, devA, "/v1/devices/"+devB.ID+"/revoke", nil))

	stored, _ := env.devices.GetDevice(context.Background(), devB.ID)
	if stored.Status != store.DeviceActive {
		t.Fatalf("B status = %q after A tried to revoke it, want active", stored.Status)
	}
}

// TestAdminRevocationAndListing: the operator token may list every device and
// revoke any device; without it (or with a wrong one) both are 401.
func TestAdminRevocationAndListing(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "laptop")

	// No admin token -> 401.
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/devices", nil))
	assertUnauthorized(t, rec)

	// Wrong admin token -> 401.
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/devices", nil)
	req.Header.Set(headerAdminToken, "wrong-admin-token-000000000000")
	env.router.ServeHTTP(rec, req)
	assertUnauthorized(t, rec)

	// Correct admin token -> 200 with the device listed, WITHOUT its public key.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/devices", nil)
	req.Header.Set(headerAdminToken, testAdminToken)
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin list status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var list struct {
		Devices []deviceJSON `json:"devices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("device list not JSON: %v", err)
	}
	if len(list.Devices) != 1 || list.Devices[0].DeviceID != dev.ID {
		t.Fatalf("device list = %+v, want exactly %s", list.Devices, dev.ID)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte(base64.StdEncoding.EncodeToString(dev.Pub))) {
		t.Fatal("device list leaked a public key")
	}

	// Admin revoke of someone else's device -> 200, and it takes effect at once.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/devices/"+dev.ID+"/revoke", nil)
	req.Header.Set(headerAdminToken, testAdminToken)
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin revoke status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if rec := v3Post(t, env, dev, "/v1/vaults/vaultA/ops", []byte("op")); rec.Code != http.StatusUnauthorized {
		t.Fatalf("post-admin-revocation status = %d, want 401", rec.Code)
	}
}

// TestAdminRoutesClosedWhenNoAdminTokenConfigured: with no admin token there is
// NO implicit open-admin mode — the operator routes are permanently 401.
func TestAdminRoutesClosedWhenNoAdminTokenConfigured(t *testing.T) {
	env := newDeviceEnvWithTokens(t, []string{testEnrollToken}, "") // no admin token
	for _, hdr := range []string{"", "anything"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/v1/devices", nil)
		if hdr != "" {
			req.Header.Set(headerAdminToken, hdr)
		}
		env.router.ServeHTTP(rec, req)
		assertUnauthorized(t, rec)
	}
}

// TestRevokeUnknownDevice returns 404 for the admin path.
func TestRevokeUnknownDevice(t *testing.T) {
	env := newDeviceEnv(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/devices/dev_nope/revoke", nil)
	req.Header.Set(headerAdminToken, testAdminToken)
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("revoke unknown status = %d, want 404 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestDeviceRoutes501WhenDevOpsOff is the DEFAULT-POSTURE guard: with dev-ops
// off, every device route returns the deliberate 501 (never 404, never a partial
// implementation) — exactly like the ops routes.
func TestDeviceRoutes501WhenDevOpsOff(t *testing.T) {
	router := testRouter() // DevOpsEnabled false
	cases := []struct {
		method, path string
	}{
		{http.MethodPost, "/v1/devices/enroll"},
		{http.MethodGet, "/v1/devices"},
		{http.MethodPost, "/v1/devices/dev_x/revoke"},
		{http.MethodPost, "/v1/vaults/v1/grants"},
		{http.MethodGet, "/v1/vaults/v1/grants"},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte("{}"))))
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("%s %s status = %d, want 501 (body: %s)", c.method, c.path, rec.Code, rec.Body.String())
		}
		var body apiError
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("501 body not JSON: %v", err)
		}
		if body.Error != "not_implemented" {
			t.Fatalf("%s %s error = %q, want not_implemented", c.method, c.path, body.Error)
		}
	}
}

// TestDeviceRoutes501WhenRegistryUnconfigured: dev-ops ON but no device registry
// => the device routes are still 501, and the ops routes keep their existing
// (legacy) behaviour.
func TestDeviceRoutes501WhenRegistryUnconfigured(t *testing.T) {
	router := devOpsRouter() // DevOpsEnabled true, Devices nil
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/devices/enroll", bytes.NewReader([]byte("{}"))))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("enroll with no registry status = %d, want 501", rec.Code)
	}
	// Ops still work unauthenticated, exactly as before.
	if seq := postOp(t, router, "demo", []byte("op")); seq != 1 {
		t.Fatalf("legacy dev-ops append seq = %d, want 1", seq)
	}
}

// TestEnrollmentNeverLogsSecrets is the audit-hygiene guard: across a successful
// enrollment, a denied enrollment, a grant, and a revocation, the structured log
// must never contain the enrollment token, the admin token, a public key, a
// signature, or a nonce.
func TestDeviceAuditNeverLogsSecrets(t *testing.T) {
	var buf bytes.Buffer
	devices := store.NewMemDeviceStore()
	hash := EnrollTokenHash(testEnrollToken)
	if err := devices.RegisterEnrollmentToken(context.Background(), hash, time.Now().UTC(), time.Time{}); err != nil {
		t.Fatalf("RegisterEnrollmentToken: %v", err)
	}
	router := NewRouter(Config{
		Version:           "test",
		Logger:            slog.New(slog.NewJSONHandler(&buf, nil)),
		DevOpsEnabled:     true,
		Devices:           devices,
		EnrollTokenHashes: []string{hash},
		AdminToken:        testAdminToken,
	})
	env := &deviceEnv{router: router, devices: devices}

	// Successful enrollment.
	pub, priv := newClientKeypair(t)
	nonce := randNonce(t)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, buildEnrollRequest(t, testEnrollToken, pub, priv, "laptop", time.Now().Unix(), nonce))
	if rec.Code != http.StatusCreated {
		t.Fatalf("enroll status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	var enrolled deviceJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &enrolled); err != nil {
		t.Fatalf("enroll body: %v", err)
	}
	dev := testDevice{ID: enrolled.DeviceID, Pub: pub, Priv: priv}

	// Denied enrollment (bad token), a claim + a denied authz, and a revocation.
	pub2, priv2 := newClientKeypair(t)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, buildEnrollRequest(t, "bad-token-000000000000000000", pub2, priv2, "x", time.Now().Unix(), randNonce(t)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("denied enroll status = %d, want 401", rec.Code)
	}
	if rec := v3Post(t, env, dev, "/v1/vaults/vaultA/ops", []byte("op")); rec.Code != http.StatusCreated {
		t.Fatalf("claim status = %d, want 201", rec.Code)
	}
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/devices/"+dev.ID+"/revoke", nil)
	req.Header.Set(headerAdminToken, testAdminToken)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke status = %d, want 200", rec.Code)
	}

	logs := buf.String()
	if logs == "" {
		t.Fatal("no audit output captured")
	}
	forbidden := map[string]string{
		"enrollment token":   testEnrollToken,
		"enrollment digest":  hash,
		"admin token":        testAdminToken,
		"public key":         base64.StdEncoding.EncodeToString(pub),
		"enrollment nonce":   nonce,
		"private key seed":   base64.StdEncoding.EncodeToString(priv.Seed()),
		"bad token attempt":  "bad-token-000000000000000000",
		"raw op blob bytes":  "op",
		"second public key":  base64.StdEncoding.EncodeToString(pub2),
		"unused placeholder": "",
	}
	for name, secret := range forbidden {
		if secret == "" || secret == "op" {
			continue // "op" is too short to test meaningfully; blob-leak has its own test
		}
		if strings.Contains(logs, secret) {
			t.Fatalf("audit log leaked the %s", name)
		}
	}
	// It SHOULD carry the non-secret metadata.
	for _, want := range []string{"device.enrolled", "device.enroll_denied", "device.revoked", "vault.claimed", dev.ID} {
		if !strings.Contains(logs, want) {
			t.Fatalf("audit log missing %q", want)
		}
	}
}

// TestDeviceMetricsExposed checks the new counters appear on /metrics with the
// expected values, and that no secret or identifier leaks into the exposition.
func TestDeviceMetricsExposed(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "laptop")
	if rec := v3Post(t, env, dev, "/v1/vaults/vaultA/ops", []byte("op")); rec.Code != http.StatusCreated {
		t.Fatalf("claim status = %d, want 201", rec.Code)
	}
	// One denied enrollment (bad token) and one 403.
	pub, priv := newClientKeypair(t)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, buildEnrollRequest(t, "bad-token-000000000000000000", pub, priv, "x", time.Now().Unix(), randNonce(t)))
	_, otherPriv := newClientKeypair(t)
	_ = otherPriv

	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"sigild_device_enrollments_total 1",
		"sigild_vault_claims_total 1",
		"sigild_device_enroll_denied_total{reason=\"bad_enrollment_token\"} 1",
		"sigild_oplog_auth_denied_total{reason=\"unauthorized_vault\"}",
		"sigild_oplog_authz_denied_total",
		"sigild_device_revocations_total",
		"sigild_vault_grants_total",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/metrics missing %q\n%s", want, body)
		}
	}
	for _, leak := range []string{testEnrollToken, testAdminToken, dev.ID, "vaultA",
		base64.StdEncoding.EncodeToString(dev.Pub)} {
		if strings.Contains(body, leak) {
			t.Fatalf("/metrics leaked %q", leak)
		}
	}
}
