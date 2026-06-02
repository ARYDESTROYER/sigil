package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testRouter() http.Handler {
	return NewRouter(Config{Version: "test"})
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
