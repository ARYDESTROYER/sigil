package api

// Tests for the vault-sharing HTTP surface: publishing/fetching device hybrid
// PUBLIC keys and the opaque key-envelope relay.
//
// The assertions that matter most are the AUTHORIZATION ones (only me can
// publish my key; only the addressee can collect an envelope; a revoked device
// is refused) and the ZERO-KNOWLEDGE one (the relay returns byte-identical
// ciphertext and never logs it).

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

// randBytes returns n bytes of test randomness.
func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

// hybridKeyBody builds a shape-valid publish body. The bytes are random: the
// server validates length only, so this exercises exactly what it checks.
func hybridKeyBody(t *testing.T) []byte {
	t.Helper()
	body, err := json.Marshal(hybridKeyRequest{
		X25519PublicKey: base64.StdEncoding.EncodeToString(randBytes(t, store.X25519PublicKeyLen)),
		MLKEMEncapsKey:  base64.StdEncoding.EncodeToString(randBytes(t, store.MLKEM768EncapsKeyLen)),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return body
}

// v3Put builds and serves a v3-signed PUT, returning the recorder.
func v3Put(t *testing.T, env *deviceEnv, dev testDevice, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, path, bytes.NewReader(body))
	signV3(t, req, dev, time.Now().Unix(), randNonce(t), body)
	env.router.ServeHTTP(rec, req)
	return rec
}

// publishHybridKey runs a happy-path publish and returns the body it sent.
func publishHybridKey(t *testing.T, env *deviceEnv, dev testDevice) []byte {
	t.Helper()
	body := hybridKeyBody(t)
	rec := v3Put(t, env, dev, "/v1/devices/"+dev.ID+"/hybrid-key", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	return body
}

// TestHybridKeyPublishAndFetch: a device publishes its own key and another
// enrolled device can fetch it, byte-identical.
func TestHybridKeyPublishAndFetch(t *testing.T) {
	env := newDeviceEnvWithTokens(t, []string{testEnrollToken, testEnrollToken + "-b"}, testAdminToken)
	devA := enrollDevice(t, env, testEnrollToken, "A")
	devB := enrollDevice(t, env, testEnrollToken+"-b", "B")

	sent := publishHybridKey(t, env, devA)
	var want hybridKeyRequest
	if err := json.Unmarshal(sent, &want); err != nil {
		t.Fatalf("unmarshal sent: %v", err)
	}

	rec := v3Get(t, env, devB, "/v1/devices/"+devA.ID+"/hybrid-key")
	if rec.Code != http.StatusOK {
		t.Fatalf("fetch status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var got hybridKeyJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("fetch body not JSON: %v", err)
	}
	if got.DeviceID != devA.ID {
		t.Fatalf("device_id = %q, want %q", got.DeviceID, devA.ID)
	}
	// VERBATIM: the server served back exactly the key bytes it was given.
	if got.X25519PublicKey != want.X25519PublicKey || got.MLKEMEncapsKey != want.MLKEMEncapsKey {
		t.Fatal("served hybrid key is not byte-identical to the published one")
	}
}

// TestHybridKeyRepublishReplaces: publishing again is allowed (upsert) and the
// new key is what other devices then fetch.
func TestHybridKeyRepublishReplaces(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "A")
	publishHybridKey(t, env, dev)
	second := publishHybridKey(t, env, dev)

	var want hybridKeyRequest
	if err := json.Unmarshal(second, &want); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	rec := v3Get(t, env, dev, "/v1/devices/"+dev.ID+"/hybrid-key")
	var got hybridKeyJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("fetch body not JSON: %v", err)
	}
	if got.X25519PublicKey != want.X25519PublicKey {
		t.Fatal("republish did not replace the served key")
	}
}

// TestHybridKeyCannotPublishForAnotherDevice: authenticated, but publishing to
// someone else's slot is 403 — and nothing is stored for the victim.
func TestHybridKeyCannotPublishForAnotherDevice(t *testing.T) {
	env := newDeviceEnvWithTokens(t, []string{testEnrollToken, testEnrollToken + "-b"}, testAdminToken)
	devA := enrollDevice(t, env, testEnrollToken, "A")
	devB := enrollDevice(t, env, testEnrollToken+"-b", "B")

	rec := v3Put(t, env, devA, "/v1/devices/"+devB.ID+"/hybrid-key", hybridKeyBody(t))
	assertForbidden(t, rec)

	if _, err := env.devices.GetDeviceHybridKey(context.Background(), devB.ID); err == nil {
		t.Fatal("a device published a key into another device's slot")
	}
}

// TestHybridKeyRejectsMalformed: wrong-length key material is a 400, and nothing
// is stored. This is the ONLY validation the server does on key bytes.
func TestHybridKeyRejectsMalformed(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "A")

	body, err := json.Marshal(hybridKeyRequest{
		X25519PublicKey: base64.StdEncoding.EncodeToString(randBytes(t, 16)), // too short
		MLKEMEncapsKey:  base64.StdEncoding.EncodeToString(randBytes(t, store.MLKEM768EncapsKeyLen)),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rec := v3Put(t, env, dev, "/v1/devices/"+dev.ID+"/hybrid-key", body)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body: %s)", rec.Code, rec.Body.String())
	}
	if _, err := env.devices.GetDeviceHybridKey(context.Background(), dev.ID); err == nil {
		t.Fatal("a malformed key was stored")
	}
}

// TestHybridKeyUnauthenticated: an unsigned request is 401, never 200.
func TestHybridKeyUnauthenticated(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "A")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/v1/devices/"+dev.ID+"/hybrid-key",
		bytes.NewReader(hybridKeyBody(t)))
	env.router.ServeHTTP(rec, req)
	assertUnauthorized(t, rec)

	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/devices/"+dev.ID+"/hybrid-key", nil))
	assertUnauthorized(t, rec)
}

// TestHybridKeyRevokedDeviceRefused: a revoked device can neither publish nor
// fetch.
func TestHybridKeyRevokedDeviceRefused(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "A")
	publishHybridKey(t, env, dev)

	if err := env.devices.RevokeDevice(context.Background(), dev.ID, time.Now().UTC()); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	assertUnauthorized(t, v3Put(t, env, dev, "/v1/devices/"+dev.ID+"/hybrid-key", hybridKeyBody(t)))
	assertUnauthorized(t, v3Get(t, env, dev, "/v1/devices/"+dev.ID+"/hybrid-key"))
}

// TestHybridKeyNotPublished: fetching a device that has published nothing is a
// clean 404.
func TestHybridKeyNotPublished(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "A")
	rec := v3Get(t, env, dev, "/v1/devices/"+dev.ID+"/hybrid-key")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (body: %s)", rec.Code, rec.Body.String())
	}
}

// shareEnv builds a two-device environment where A owns a vault (claimed by
// depositing the first envelope) and B has published a hybrid key.
type shareEnv struct {
	*deviceEnv
	devA  testDevice
	devB  testDevice
	vault string
}

func newShareEnv(t *testing.T) *shareEnv {
	t.Helper()
	env := newDeviceEnvWithTokens(t,
		[]string{testEnrollToken, testEnrollToken + "-b", testEnrollToken + "-c"}, testAdminToken)
	devA := enrollDevice(t, env, testEnrollToken, "A")
	devB := enrollDevice(t, env, testEnrollToken+"-b", "B")
	publishHybridKey(t, env, devA)
	publishHybridKey(t, env, devB)
	return &shareEnv{deviceEnv: env, devA: devA, devB: devB, vault: "vaultShared"}
}

// keyPath is the envelope mailbox address for a (vault, device) pair.
func (e *shareEnv) keyPath(deviceID string) string {
	return "/v1/vaults/" + e.vault + "/keys/" + deviceID
}

// TestKeyEnvelopeRelayIsVerbatimAndAddressed: the owner deposits an envelope for
// B, only B can collect it, and the bytes come back byte-identical.
func TestKeyEnvelopeRelayIsVerbatimAndAddressed(t *testing.T) {
	env := newShareEnv(t)
	blob := randBytes(t, 1200)

	// A claims the vault by depositing the first envelope (trust-on-first-write,
	// the same rule as the first op append), then grants B read access.
	rec := v3Put(t, env.deviceEnv, env.devA, env.keyPath(env.devB.ID), blob)
	if rec.Code != http.StatusCreated {
		t.Fatalf("put envelope status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	grantBody, err := json.Marshal(grantRequest{DeviceID: env.devB.ID, Permission: "read"})
	if err != nil {
		t.Fatalf("marshal grant: %v", err)
	}
	if rec := v3Post(t, env.deviceEnv, env.devA, "/v1/vaults/"+env.vault+"/grants", grantBody); rec.Code != http.StatusCreated {
		t.Fatalf("grant status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}

	// B collects it: raw bytes, byte-for-byte what A uploaded.
	got := v3Get(t, env.deviceEnv, env.devB, env.keyPath(env.devB.ID))
	if got.Code != http.StatusOK {
		t.Fatalf("get envelope status = %d, want 200 (body: %s)", got.Code, got.Body.String())
	}
	if ct := got.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("content-type = %q, want application/octet-stream", ct)
	}
	if !bytes.Equal(got.Body.Bytes(), blob) {
		t.Fatal("relayed envelope is not byte-identical to the uploaded one")
	}
}

// TestKeyEnvelopeThirdDeviceForbidden: a third enrolled device — even one with a
// grant on the vault — cannot collect B's envelope. It is 403 (authenticated but
// not the addressee), NOT 401.
func TestKeyEnvelopeThirdDeviceForbidden(t *testing.T) {
	env := newShareEnv(t)
	devC := enrollDevice(t, env.deviceEnv, testEnrollToken+"-c", "C")

	blob := randBytes(t, 512)
	if rec := v3Put(t, env.deviceEnv, env.devA, env.keyPath(env.devB.ID), blob); rec.Code != http.StatusCreated {
		t.Fatalf("put envelope status = %d, want 201", rec.Code)
	}
	// Give C real READ access to the vault: authorization on the vault must NOT
	// be enough to read someone else's envelope.
	grantBody, _ := json.Marshal(grantRequest{DeviceID: devC.ID, Permission: "read"})
	if rec := v3Post(t, env.deviceEnv, env.devA, "/v1/vaults/"+env.vault+"/grants", grantBody); rec.Code != http.StatusCreated {
		t.Fatalf("grant C status = %d, want 201", rec.Code)
	}

	rec := v3Get(t, env.deviceEnv, devC, env.keyPath(env.devB.ID))
	assertForbidden(t, rec)
	if bytes.Contains(rec.Body.Bytes(), blob[:16]) {
		t.Fatal("the 403 response leaked envelope bytes")
	}
}

// TestKeyEnvelopeUnauthorizedVaultCannotDeposit: a device with no grant on the
// vault (owned by A) cannot deposit an envelope.
func TestKeyEnvelopeUnauthorizedVaultCannotDeposit(t *testing.T) {
	env := newShareEnv(t)
	devC := enrollDevice(t, env.deviceEnv, testEnrollToken+"-c", "C")

	if rec := v3Put(t, env.deviceEnv, env.devA, env.keyPath(env.devB.ID), randBytes(t, 256)); rec.Code != http.StatusCreated {
		t.Fatalf("A put envelope status = %d, want 201", rec.Code)
	}
	assertForbidden(t, v3Put(t, env.deviceEnv, devC, env.keyPath(devC.ID), randBytes(t, 256)))
}

// TestKeyEnvelopeReadOnlyGranteeCannotDeposit: read access is not enough to
// distribute keys — depositing requires WRITE.
func TestKeyEnvelopeReadOnlyGranteeCannotDeposit(t *testing.T) {
	env := newShareEnv(t)
	if rec := v3Put(t, env.deviceEnv, env.devA, env.keyPath(env.devB.ID), randBytes(t, 256)); rec.Code != http.StatusCreated {
		t.Fatalf("A put envelope status = %d, want 201", rec.Code)
	}
	grantBody, _ := json.Marshal(grantRequest{DeviceID: env.devB.ID, Permission: "read"})
	if rec := v3Post(t, env.deviceEnv, env.devA, "/v1/vaults/"+env.vault+"/grants", grantBody); rec.Code != http.StatusCreated {
		t.Fatalf("grant status = %d, want 201", rec.Code)
	}
	assertForbidden(t, v3Put(t, env.deviceEnv, env.devB, env.keyPath(env.devB.ID), randBytes(t, 256)))
}

// TestKeyEnvelopeRevokedDeviceRefused: a revoked recipient cannot collect, and a
// revoked sender cannot deposit.
func TestKeyEnvelopeRevokedDeviceRefused(t *testing.T) {
	env := newShareEnv(t)
	ctx := context.Background()
	if rec := v3Put(t, env.deviceEnv, env.devA, env.keyPath(env.devB.ID), randBytes(t, 256)); rec.Code != http.StatusCreated {
		t.Fatalf("put envelope status = %d, want 201", rec.Code)
	}
	grantBody, _ := json.Marshal(grantRequest{DeviceID: env.devB.ID, Permission: "read"})
	if rec := v3Post(t, env.deviceEnv, env.devA, "/v1/vaults/"+env.vault+"/grants", grantBody); rec.Code != http.StatusCreated {
		t.Fatalf("grant status = %d, want 201", rec.Code)
	}

	if err := env.devices.RevokeDevice(ctx, env.devB.ID, time.Now().UTC()); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	// The revoked recipient cannot collect...
	assertUnauthorized(t, v3Get(t, env.deviceEnv, env.devB, env.keyPath(env.devB.ID)))
	// ...and nobody can deposit a new envelope FOR a revoked device.
	rec := v3Put(t, env.deviceEnv, env.devA, env.keyPath(env.devB.ID), randBytes(t, 256))
	if rec.Code != http.StatusConflict {
		t.Fatalf("deposit for a revoked device = %d, want 409 (body: %s)", rec.Code, rec.Body.String())
	}

	// And a revoked SENDER cannot deposit either.
	if err := env.devices.RevokeDevice(ctx, env.devA.ID, time.Now().UTC()); err != nil {
		t.Fatalf("RevokeDevice A: %v", err)
	}
	assertUnauthorized(t, v3Put(t, env.deviceEnv, env.devA, env.keyPath(env.devA.ID), randBytes(t, 256)))
}

// TestKeyEnvelopeMissingAndUnknownRecipient: 404s are clean and distinct.
func TestKeyEnvelopeMissingAndUnknownRecipient(t *testing.T) {
	env := newShareEnv(t)
	// A owns the vault (claims it here), but nothing is addressed to A.
	if rec := v3Put(t, env.deviceEnv, env.devA, env.keyPath(env.devB.ID), randBytes(t, 256)); rec.Code != http.StatusCreated {
		t.Fatalf("put envelope status = %d, want 201", rec.Code)
	}
	rec := v3Get(t, env.deviceEnv, env.devA, env.keyPath(env.devA.ID))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing envelope = %d, want 404 (body: %s)", rec.Code, rec.Body.String())
	}
	rec = v3Put(t, env.deviceEnv, env.devA, env.keyPath("dev_nope"), randBytes(t, 256))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown recipient = %d, want 404 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestKeyEnvelopeOversizedRejected: the relay is not a blob store.
func TestKeyEnvelopeOversizedRejected(t *testing.T) {
	env := newShareEnv(t)
	rec := v3Put(t, env.deviceEnv, env.devA, env.keyPath(env.devB.ID), randBytes(t, store.MaxKeyEnvelopeBytes+1))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized envelope = %d, want 413 (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestSharingRoutesAreDevGated: with the device model off, every sharing route
// returns the deliberate 501 — never 404, never partial behaviour.
func TestSharingRoutesAreDevGated(t *testing.T) {
	for _, cfg := range []Config{
		{Version: "test", Logger: discardLogger()},                      // dev-ops off
		{Version: "test", Logger: discardLogger(), DevOpsEnabled: true}, // dev-ops on, no registry
	} {
		router := NewRouter(cfg)
		for _, tc := range []struct {
			method, path string
		}{
			{http.MethodPut, "/v1/devices/dev_x/hybrid-key"},
			{http.MethodGet, "/v1/devices/dev_x/hybrid-key"},
			{http.MethodPut, "/v1/vaults/v1/keys/dev_x"},
			{http.MethodGet, "/v1/vaults/v1/keys/dev_x"},
		} {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, bytes.NewReader([]byte("x"))))
			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("%s %s = %d, want 501 (body: %s)", tc.method, tc.path, rec.Code, rec.Body.String())
			}
		}
	}
}

// TestSharingNeverLogsEnvelopeBytes: the audit trail records a fingerprint and
// metadata, never the ciphertext or the published key material.
func TestSharingNeverLogsEnvelopeBytes(t *testing.T) {
	var logs bytes.Buffer
	devices := store.NewMemDeviceStore()
	hashes := []string{EnrollTokenHash(testEnrollToken), EnrollTokenHash(testEnrollToken + "-b")}
	for _, h := range hashes {
		if err := devices.RegisterEnrollmentToken(context.Background(), h, time.Now().UTC(), time.Time{}); err != nil {
			t.Fatalf("RegisterEnrollmentToken: %v", err)
		}
	}
	router := NewRouter(Config{
		Version:           "test",
		Logger:            slog.New(slog.NewJSONHandler(&logs, nil)),
		DevOpsEnabled:     true,
		Devices:           devices,
		EnrollTokenHashes: hashes,
		AdminToken:        testAdminToken,
	})
	env := &deviceEnv{router: router, devices: devices}
	devA := enrollDevice(t, env, testEnrollToken, "A")
	devB := enrollDevice(t, env, testEnrollToken+"-b", "B")
	keyBody := publishHybridKey(t, env, devB)

	// A recognisable "ciphertext" so a leak is unmistakable in the log text.
	blob := bytes.Repeat([]byte("SUPERSECRETWRAPPEDVAULTKEY"), 40)
	if rec := v3Put(t, env, devA, "/v1/vaults/vShare/keys/"+devB.ID, blob); rec.Code != http.StatusCreated {
		t.Fatalf("put envelope status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	grantBody, _ := json.Marshal(grantRequest{DeviceID: devB.ID, Permission: "read"})
	if rec := v3Post(t, env, devA, "/v1/vaults/vShare/grants", grantBody); rec.Code != http.StatusCreated {
		t.Fatalf("grant status = %d, want 201", rec.Code)
	}
	if rec := v3Get(t, env, devB, "/v1/vaults/vShare/keys/"+devB.ID); rec.Code != http.StatusOK {
		t.Fatalf("get envelope status = %d, want 200", rec.Code)
	}

	text := logs.String()
	if strings.Contains(text, "SUPERSECRETWRAPPEDVAULTKEY") {
		t.Fatal("the audit log contains envelope bytes")
	}
	if strings.Contains(text, base64.StdEncoding.EncodeToString(blob)) {
		t.Fatal("the audit log contains base64 envelope bytes")
	}
	var published hybridKeyRequest
	if err := json.Unmarshal(keyBody, &published); err != nil {
		t.Fatalf("unmarshal key body: %v", err)
	}
	if strings.Contains(text, published.MLKEMEncapsKey) || strings.Contains(text, published.X25519PublicKey) {
		t.Fatal("the audit log contains published key material")
	}
	// It SHOULD carry the metadata an operator needs.
	for _, want := range []string{"vault.key_envelope_put", "vault.key_envelope_get",
		"device.hybrid_key_published", "blob_sha256"} {
		if !strings.Contains(text, want) {
			t.Fatalf("audit log is missing %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// Rotation support (Phase 50): GET /v1/vaults/{id}/keys and
// DELETE /v1/vaults/{id}/keys/{deviceID}.
// ---------------------------------------------------------------------------

// v3Delete builds and serves a v3-signed DELETE.
func v3Delete(t *testing.T, env *deviceEnv, dev testDevice, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	signV3(t, req, dev, time.Now().Unix(), randNonce(t), nil)
	env.router.ServeHTTP(rec, req)
	return rec
}

// envelopeList is the JSON shape of the listing route.
type envelopeList struct {
	VaultID    string `json:"vaultID"`
	Recipients []struct {
		DeviceID       string `json:"device_id"`
		SenderDeviceID string `json:"sender_device_id"`
		SizeBytes      int    `json:"size_bytes"`
		CreatedAt      string `json:"created_at"`
	} `json:"recipients"`
}

// TestKeyEnvelopeListReturnsMetadataOnly: the owner sees WHICH devices hold a
// wrapped key, sorted, with sizes — and the response never contains a blob.
func TestKeyEnvelopeListReturnsMetadataOnly(t *testing.T) {
	env := newShareEnv(t)
	devC := enrollDevice(t, env.deviceEnv, testEnrollToken+"-c", "C")
	publishHybridKey(t, env.deviceEnv, devC)

	blobB := randBytes(t, 1226)
	blobC := randBytes(t, 900)
	if rec := v3Put(t, env.deviceEnv, env.devA, env.keyPath(env.devB.ID), blobB); rec.Code != http.StatusCreated {
		t.Fatalf("put B status = %d, want 201", rec.Code)
	}
	if rec := v3Put(t, env.deviceEnv, env.devA, env.keyPath(devC.ID), blobC); rec.Code != http.StatusCreated {
		t.Fatalf("put C status = %d, want 201", rec.Code)
	}

	rec := v3Get(t, env.deviceEnv, env.devA, "/v1/vaults/"+env.vault+"/keys")
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var got envelopeList
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Recipients) != 2 {
		t.Fatalf("recipients = %d, want 2", len(got.Recipients))
	}
	seen := map[string]int{}
	for _, r := range got.Recipients {
		seen[r.DeviceID] = r.SizeBytes
		if r.SenderDeviceID != env.devA.ID {
			t.Fatalf("sender = %q, want %q", r.SenderDeviceID, env.devA.ID)
		}
	}
	if seen[env.devB.ID] != len(blobB) || seen[devC.ID] != len(blobC) {
		t.Fatalf("sizes = %v, want B=%d C=%d", seen, len(blobB), len(blobC))
	}
	// ⭐ ZERO-KNOWLEDGE: the listing must not carry ciphertext.
	if bytes.Contains(rec.Body.Bytes(), blobB[:16]) || bytes.Contains(rec.Body.Bytes(), blobC[:16]) {
		t.Fatal("the envelope listing leaked blob bytes")
	}
}

// TestKeyEnvelopeDeleteRemovesTheMailbox: after a delete the recipient's GET is
// 404 — the whole point of a rotation deleting a stale envelope.
func TestKeyEnvelopeDeleteRemovesTheMailbox(t *testing.T) {
	env := newShareEnv(t)
	blob := randBytes(t, 512)
	if rec := v3Put(t, env.deviceEnv, env.devA, env.keyPath(env.devB.ID), blob); rec.Code != http.StatusCreated {
		t.Fatalf("put status = %d, want 201", rec.Code)
	}
	grantBody, _ := json.Marshal(grantRequest{DeviceID: env.devB.ID, Permission: "read"})
	if rec := v3Post(t, env.deviceEnv, env.devA, "/v1/vaults/"+env.vault+"/grants", grantBody); rec.Code != http.StatusCreated {
		t.Fatalf("grant status = %d, want 201", rec.Code)
	}
	if rec := v3Get(t, env.deviceEnv, env.devB, env.keyPath(env.devB.ID)); rec.Code != http.StatusOK {
		t.Fatalf("pre-delete collect = %d, want 200", rec.Code)
	}

	if rec := v3Delete(t, env.deviceEnv, env.devA, env.keyPath(env.devB.ID)); rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	if rec := v3Get(t, env.deviceEnv, env.devB, env.keyPath(env.devB.ID)); rec.Code != http.StatusNotFound {
		t.Fatalf("post-delete collect = %d, want 404", rec.Code)
	}
	// Deleting again is a clean 404, not a 500.
	if rec := v3Delete(t, env.deviceEnv, env.devA, env.keyPath(env.devB.ID)); rec.Code != http.StatusNotFound {
		t.Fatalf("second delete = %d, want 404", rec.Code)
	}
	// And the listing is now empty.
	rec := v3Get(t, env.deviceEnv, env.devA, "/v1/vaults/"+env.vault+"/keys")
	var got envelopeList
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Recipients) != 0 {
		t.Fatalf("recipients after delete = %d, want 0", len(got.Recipients))
	}
}

// TestKeyEnvelopeListAndDeleteRequireWrite: the documented rule — BOTH routes go
// through the same WRITE choke point as depositing an envelope. A read-only
// grantee and an unrelated device are 403; an unsigned request is 401.
func TestKeyEnvelopeListAndDeleteRequireWrite(t *testing.T) {
	env := newShareEnv(t)
	devC := enrollDevice(t, env.deviceEnv, testEnrollToken+"-c", "C")
	if rec := v3Put(t, env.deviceEnv, env.devA, env.keyPath(env.devB.ID), randBytes(t, 256)); rec.Code != http.StatusCreated {
		t.Fatalf("put status = %d, want 201", rec.Code)
	}
	// B gets READ only: enough to collect its own envelope, never enough to
	// enumerate or delete.
	grantBody, _ := json.Marshal(grantRequest{DeviceID: env.devB.ID, Permission: "read"})
	if rec := v3Post(t, env.deviceEnv, env.devA, "/v1/vaults/"+env.vault+"/grants", grantBody); rec.Code != http.StatusCreated {
		t.Fatalf("grant status = %d, want 201", rec.Code)
	}

	assertForbidden(t, v3Get(t, env.deviceEnv, env.devB, "/v1/vaults/"+env.vault+"/keys"))
	assertForbidden(t, v3Delete(t, env.deviceEnv, env.devB, env.keyPath(env.devB.ID)))
	// A device with no grant at all: also 403.
	assertForbidden(t, v3Get(t, env.deviceEnv, devC, "/v1/vaults/"+env.vault+"/keys"))
	assertForbidden(t, v3Delete(t, env.deviceEnv, devC, env.keyPath(env.devB.ID)))

	// Unsigned: 401, not 403.
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/vaults/"+env.vault+"/keys", nil))
	assertUnauthorized(t, rec)
	rec = httptest.NewRecorder()
	env.router.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, env.keyPath(env.devB.ID), nil))
	assertUnauthorized(t, rec)
}

// TestRotationRoutesAreDevGated: with the device model off both new routes
// return the deliberate 501 like every other sharing route.
func TestRotationRoutesAreDevGated(t *testing.T) {
	for _, cfg := range []Config{
		{Version: "test", Logger: discardLogger()},
		{Version: "test", Logger: discardLogger(), DevOpsEnabled: true},
	} {
		router := NewRouter(cfg)
		for _, tc := range []struct{ method, path string }{
			{http.MethodGet, "/v1/vaults/v1/keys"},
			{http.MethodDelete, "/v1/vaults/v1/keys/dev_x"},
		} {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("%s %s = %d, want 501", tc.method, tc.path, rec.Code)
			}
		}
	}
}
