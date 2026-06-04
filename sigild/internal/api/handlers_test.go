package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testRouter() http.Handler {
	return NewRouter(Config{Version: "test", Logger: discardLogger()})
}

func TestHealthz(t *testing.T) {
	rec := httptest.NewRecorder()
	testRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("healthz status = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("healthz body not JSON: %v", err)
	}
	if body["status"] != "ok" || body["version"] != "test" {
		t.Fatalf("healthz body = %v, want status=ok version=test", body)
	}
}

func TestVersion(t *testing.T) {
	rec := httptest.NewRecorder()
	testRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/version", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("version status = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("version body not JSON: %v", err)
	}
	if body["name"] != "sigild" {
		t.Fatalf("version name = %q, want sigild", body["name"])
	}
	if body["version"] != "test" {
		t.Fatalf("version version = %q, want test (the configured version)", body["version"])
	}
}

func TestReadyzUnconfiguredIsOK(t *testing.T) {
	rec := httptest.NewRecorder()
	testRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("readyz (no deps configured) status = %d, want 200", rec.Code)
	}
}

func TestReadyzUnreachableIs503(t *testing.T) {
	// Port 1 on loopback should refuse immediately -> "unreachable".
	h := NewRouter(Config{Version: "test", PostgresAddr: "127.0.0.1:1"})
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz (dep unreachable) status = %d, want 503", rec.Code)
	}
}

func TestVaultOpsReturns501(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/v1/vaults/abc123/ops", nil)
		testRouter().ServeHTTP(rec, req)

		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("%s /v1/vaults/{id}/ops status = %d, want 501", method, rec.Code)
		}
		var body map[string]string
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("ops body not JSON: %v", err)
		}
		if body["error"] != "not_implemented" {
			t.Fatalf("ops error = %q, want not_implemented", body["error"])
		}
		if body["vaultID"] != "abc123" {
			t.Fatalf("ops vaultID = %q, want abc123", body["vaultID"])
		}
	}
}

func TestVaultOpsSmallBodyStill501(t *testing.T) {
	// A well-formed small POST body (under the 64 KiB cap) must fall through to
	// the 501 stub, not the size limiter.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/abc123/ops",
		strings.NewReader(`{"op":"noop"}`))
	testRouter().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("small POST status = %d, want 501", rec.Code)
	}
	var body apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("ops body not JSON: %v", err)
	}
	if body.Error != "not_implemented" {
		t.Fatalf("ops error = %q, want not_implemented", body.Error)
	}
	if body.VaultID != "abc123" {
		t.Fatalf("ops vaultID = %q, want abc123", body.VaultID)
	}
}

func TestVaultOpsOversizedBodyReturns413(t *testing.T) {
	// 64 KiB + 1 byte exceeds the per-operation cap.
	oversized := bytes.Repeat([]byte("a"), maxOpsBodyBytes+1)

	t.Run("with content-length", func(t *testing.T) {
		// httptest.NewRequest sets ContentLength from the reader's length, so
		// this exercises the short-circuit Content-Length check.
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/abc123/ops",
			bytes.NewReader(oversized))
		testRouter().ServeHTTP(rec, req)

		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized POST status = %d, want 413", rec.Code)
		}
		var body apiError
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("413 body not JSON: %v", err)
		}
		if body.Error != "payload_too_large" {
			t.Fatalf("413 error = %q, want payload_too_large", body.Error)
		}
	})

	t.Run("unknown content-length", func(t *testing.T) {
		// ContentLength = -1 forces the MaxBytesReader path inside the handler.
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/vaults/abc123/ops",
			bytes.NewReader(oversized))
		req.ContentLength = -1
		testRouter().ServeHTTP(rec, req)

		if rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized streamed POST status = %d, want 413", rec.Code)
		}
		var body apiError
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("413 body not JSON: %v", err)
		}
		if body.Error != "payload_too_large" {
			t.Fatalf("413 error = %q, want payload_too_large", body.Error)
		}
	})
}
