package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRequestIDGenerated(t *testing.T) {
	rec := httptest.NewRecorder()
	testRouter().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	if got := rec.Header().Get("X-Request-ID"); got == "" {
		t.Fatal("expected X-Request-ID header to be set")
	}
}

func TestRequestIDPropagated(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("X-Request-ID", "caller-supplied-id")
	testRouter().ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Request-ID"); got != "caller-supplied-id" {
		t.Fatalf("X-Request-ID = %q, want caller-supplied-id", got)
	}
}

func TestRecovererReturns500(t *testing.T) {
	panicky := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})
	h := recoverer(discardLogger())(panicky)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("recovered panic status = %d, want 500", rec.Code)
	}
}

func TestNewRequestIDIsHexAndUnique(t *testing.T) {
	a, b := newRequestID(), newRequestID()
	if a == b {
		t.Fatalf("expected unique request IDs, both were %q", a)
	}
	if len(a) != 16 { // 8 random bytes hex-encoded
		t.Fatalf("request ID %q length = %d, want 16", a, len(a))
	}
}
