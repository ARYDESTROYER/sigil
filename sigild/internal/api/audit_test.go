package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// jsonBufRouter builds a router whose Logger writes structured JSON to an
// in-memory buffer, so a test can read back the audit lines. The buffer is not
// safe for concurrent writes, so tests using it must drive requests
// sequentially (these do).
func jsonBufRouter(t *testing.T, cfg Config) (http.Handler, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	cfg.Logger = slog.New(slog.NewJSONHandler(&buf, nil))
	return NewRouter(cfg), &buf
}

// auditEvents parses every JSON log line in buf into a map.
func auditEvents(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range bytes.Split(buf.Bytes(), []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("log line not JSON: %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// findAuditEvent returns the first logged line whose "event" attr equals event,
// failing the test if none is present.
func findAuditEvent(t *testing.T, buf *bytes.Buffer, event string) map[string]any {
	t.Helper()
	for _, m := range auditEvents(t, buf) {
		if m["event"] == event {
			return m
		}
	}
	t.Fatalf("audit event %q not found in log:\n%s", event, buf.String())
	return nil
}

// TestAuditAppendAndListNoBlobInLogs (auth OFF) drives an append then a list and
// asserts both audit events carry the right metadata — and, critically, that the
// raw opaque blob bytes NEVER appear anywhere in the captured log output. The
// append records only a sha256 FINGERPRINT of the blob, not its content.
func TestAuditAppendAndListNoBlobInLogs(t *testing.T) {
	router, buf := jsonBufRouter(t, Config{Version: "test", DevOpsEnabled: true})

	// A distinctive, recognizable blob so grepping the log for it is meaningful.
	blob := []byte("TOPSECRET-opaque-blob-DO-NOT-LOG-9f3a2b7c")

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/auditvault/ops", bytes.NewReader(blob))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}

	appendEv := findAuditEvent(t, buf, "oplog.append")
	if appendEv["vault_id"] != "auditvault" {
		t.Fatalf("append vault_id = %v, want auditvault", appendEv["vault_id"])
	}
	if appendEv["seq"] != float64(1) {
		t.Fatalf("append seq = %v, want 1", appendEv["seq"])
	}
	if appendEv["size_bytes"] != float64(len(blob)) {
		t.Fatalf("append size_bytes = %v, want %d", appendEv["size_bytes"], len(blob))
	}
	sum := sha256.Sum256(blob)
	if appendEv["blob_sha256"] != hex.EncodeToString(sum[:]) {
		t.Fatalf("append blob_sha256 = %v, want %s", appendEv["blob_sha256"], hex.EncodeToString(sum[:]))
	}
	if appendEv["auth"] != "none" {
		t.Fatalf("append auth = %v, want none", appendEv["auth"])
	}
	if id, _ := appendEv["request_id"].(string); id == "" {
		t.Fatalf("append request_id missing/empty: %v", appendEv["request_id"])
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/v1/vaults/auditvault/ops?since=0", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}

	listEv := findAuditEvent(t, buf, "oplog.list")
	if listEv["vault_id"] != "auditvault" {
		t.Fatalf("list vault_id = %v, want auditvault", listEv["vault_id"])
	}
	if listEv["since"] != float64(0) {
		t.Fatalf("list since = %v, want 0", listEv["since"])
	}
	if listEv["returned_count"] != float64(1) {
		t.Fatalf("list returned_count = %v, want 1", listEv["returned_count"])
	}

	// The core invariant: the raw blob bytes are absent from the entire log.
	if bytes.Contains(buf.Bytes(), blob) {
		t.Fatalf("raw blob leaked into audit log:\n%s", buf.String())
	}
}

// TestAuditAuthDeniedReasonsNoBlobInLogs (auth ON) drives each auth-denial path
// and asserts the audit line names the precise reason, and that a POST body's
// raw blob is never logged even on denial.
func TestAuditAuthDeniedReasonsNoBlobInLogs(t *testing.T) {
	seed, pub := newKeypair(t)
	blob := []byte("SECRET-denied-op-blob-DO-NOT-LOG-77c1e9")

	newRouter := func() (http.Handler, *bytes.Buffer) {
		return jsonBufRouter(t, Config{Version: "test", DevOpsEnabled: true, OpLogPubKey: pub})
	}
	assertNoBlob := func(t *testing.T, buf *bytes.Buffer) {
		t.Helper()
		if bytes.Contains(buf.Bytes(), blob) {
			t.Fatalf("blob leaked into audit log:\n%s", buf.String())
		}
	}

	t.Run("missing_headers", func(t *testing.T) {
		router, buf := newRouter()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/denyvault/ops", bytes.NewReader(blob))
		router.ServeHTTP(rec, req)
		assertUnauthorized(t, rec)

		ev := findAuditEvent(t, buf, "oplog.auth_denied")
		if ev["reason"] != "missing_headers" {
			t.Fatalf("reason = %v, want missing_headers", ev["reason"])
		}
		if ev["vault_id"] != "denyvault" {
			t.Fatalf("vault_id = %v, want denyvault", ev["vault_id"])
		}
		if id, _ := ev["request_id"].(string); id == "" {
			t.Fatalf("auth_denied request_id missing/empty: %v", ev["request_id"])
		}
		assertNoBlob(t, buf)
	})

	t.Run("bad_signature", func(t *testing.T) {
		router, buf := newRouter()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/denyvault/ops", bytes.NewReader(blob))
		req.Header.Set("X-Sigil-Timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		req.Header.Set("X-Sigil-Nonce", randNonce(t))
		req.Header.Set("X-Sigil-Signature", base64.StdEncoding.EncodeToString([]byte("not-a-valid-signature")))
		router.ServeHTTP(rec, req)
		assertUnauthorized(t, rec)

		if ev := findAuditEvent(t, buf, "oplog.auth_denied"); ev["reason"] != "bad_signature" {
			t.Fatalf("reason = %v, want bad_signature", ev["reason"])
		}
		assertNoBlob(t, buf)
	})

	t.Run("stale_timestamp", func(t *testing.T) {
		router, buf := newRouter()
		stale := time.Now().Unix() - 400 // outside the 300s skew window
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/denyvault/ops", bytes.NewReader(blob))
		signOpsRequest(t, req, seed, stale, randNonce(t), blob)
		router.ServeHTTP(rec, req)
		assertUnauthorized(t, rec)

		if ev := findAuditEvent(t, buf, "oplog.auth_denied"); ev["reason"] != "stale_timestamp" {
			t.Fatalf("reason = %v, want stale_timestamp", ev["reason"])
		}
		assertNoBlob(t, buf)
	})

	t.Run("replayed", func(t *testing.T) {
		router, buf := newRouter()
		now := time.Now().Unix()
		nonce := randNonce(t)
		newReq := func() *http.Request {
			req := httptest.NewRequest(http.MethodPost, "/v1/vaults/denyvault/ops", bytes.NewReader(blob))
			signOpsRequest(t, req, seed, now, nonce, blob)
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

		if ev := findAuditEvent(t, buf, "oplog.auth_denied"); ev["reason"] != "replayed" {
			t.Fatalf("reason = %v, want replayed", ev["reason"])
		}
		// The accepted request's append line proves auth="ed25519" is recorded,
		// and the blob is still never logged across accept + replay.
		if app := findAuditEvent(t, buf, "oplog.append"); app["auth"] != "ed25519" {
			t.Fatalf("append auth = %v, want ed25519", app["auth"])
		}
		assertNoBlob(t, buf)
	})
}
