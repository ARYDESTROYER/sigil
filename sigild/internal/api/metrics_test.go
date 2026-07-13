package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// scrapeMetrics GETs /metrics and returns (status, contentType, body). /metrics
// is never dev-gated, so any router exposes it.
func scrapeMetrics(t *testing.T, router http.Handler) (int, string, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	router.ServeHTTP(rec, req)
	return rec.Code, rec.Header().Get("Content-Type"), rec.Body.String()
}

// metricValue extracts the value of the exact sample line `name value` (name may
// include a full {labels} suffix). It fails if the sample is absent.
func metricValue(t *testing.T, body, name string) int64 {
	t.Helper()
	for _, line := range strings.Split(body, "\n") {
		if strings.HasPrefix(line, "#") {
			continue
		}
		// Split off the trailing value token.
		i := strings.LastIndexByte(line, ' ')
		if i < 0 {
			continue
		}
		if line[:i] == name {
			v, err := strconv.ParseInt(line[i+1:], 10, 64)
			if err != nil {
				t.Fatalf("metric %q value %q not an int: %v", name, line[i+1:], err)
			}
			return v
		}
	}
	t.Fatalf("metric %q not found in:\n%s", name, body)
	return 0
}

// TestMetricsEndpointShape: /metrics returns 200 text/plain with the expected
// HELP/TYPE lines and metric names, and build_info carries the version label.
func TestMetricsEndpointShape(t *testing.T) {
	router := NewRouter(Config{Version: "metrics-ver", Logger: discardLogger()})
	code, ctype, body := scrapeMetrics(t, router)
	if code != http.StatusOK {
		t.Fatalf("/metrics status = %d, want 200", code)
	}
	if !strings.HasPrefix(ctype, "text/plain") {
		t.Fatalf("/metrics content-type = %q, want text/plain...", ctype)
	}
	wantSubstrings := []string{
		"# TYPE sigild_build_info gauge",
		`sigild_build_info{version="metrics-ver"} 1`,
		"# TYPE sigild_schema_version gauge",
		"# TYPE sigild_http_requests_total counter",
		"# TYPE sigild_oplog_appends_total counter",
		"# TYPE sigild_oplog_verify_total counter",
		"# TYPE sigild_oplog_ratelimit_rejected_total counter",
		"# TYPE sigild_oplog_auth_denied_total counter",
		`sigild_oplog_auth_denied_total{reason="replayed"}`,
	}
	for _, s := range wantSubstrings {
		if !strings.Contains(body, s) {
			t.Fatalf("/metrics body missing %q in:\n%s", s, body)
		}
	}
}

// TestMetricsSchemaVersion: the sigild_schema_version gauge renders the value
// configured on the router (0 by default, the Postgres applied version when set).
func TestMetricsSchemaVersion(t *testing.T) {
	// Default (mem/file backend): 0.
	r0 := NewRouter(Config{Version: "test", Logger: discardLogger()})
	_, _, b0 := scrapeMetrics(t, r0)
	if v := metricValue(t, b0, "sigild_schema_version"); v != 0 {
		t.Fatalf("default sigild_schema_version = %d, want 0", v)
	}

	// Configured (as main would from the Postgres backend's applied version).
	r7 := NewRouter(Config{Version: "test", Logger: discardLogger(), SchemaVersion: 7})
	_, _, b7 := scrapeMetrics(t, r7)
	if v := metricValue(t, b7, "sigild_schema_version"); v != 7 {
		t.Fatalf("configured sigild_schema_version = %d, want 7", v)
	}
}

// TestMetricsAppendIncrements: counters are fresh per-router, so after exactly
// one append the appends_total is 1 (deterministic, no cross-test bleed).
func TestMetricsAppendIncrements(t *testing.T) {
	router := devOpsRouter()

	// Fresh router: no appends yet.
	_, _, before := scrapeMetrics(t, router)
	if v := metricValue(t, before, "sigild_oplog_appends_total"); v != 0 {
		t.Fatalf("fresh appends_total = %d, want 0 (counters must be non-global)", v)
	}

	postOp(t, router, "m", []byte("op"))

	_, _, after := scrapeMetrics(t, router)
	if v := metricValue(t, after, "sigild_oplog_appends_total"); v != 1 {
		t.Fatalf("appends_total after one append = %d, want 1", v)
	}
}

// TestMetricsVerifyIncrements: one /ops/verify call bumps verify_total to 1.
func TestMetricsVerifyIncrements(t *testing.T) {
	router := devOpsRouter()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/vaults/mv/ops/verify", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("verify status = %d, want 200", rec.Code)
	}
	_, _, body := scrapeMetrics(t, router)
	if v := metricValue(t, body, "sigild_oplog_verify_total"); v != 1 {
		t.Fatalf("verify_total = %d, want 1", v)
	}
}

// TestMetricsAuthDeniedReason: an auth-enabled router that rejects a request with
// no signature headers increments auth_denied_total{reason="missing_headers"}.
func TestMetricsAuthDeniedReason(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	router := NewRouter(Config{
		Version:       "test",
		Logger:        discardLogger(),
		DevOpsEnabled: true,
		OpLogPubKey:   pub,
	})

	// Unsigned POST -> 401 missing_headers.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/ad/ops", bytes.NewReader([]byte("op")))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned POST status = %d, want 401", rec.Code)
	}

	_, _, body := scrapeMetrics(t, router)
	if v := metricValue(t, body, `sigild_oplog_auth_denied_total{reason="missing_headers"}`); v != 1 {
		t.Fatalf("auth_denied missing_headers = %d, want 1", v)
	}
	// A DIFFERENT reason stayed at 0 — the label routing is correct.
	if v := metricValue(t, body, `sigild_oplog_auth_denied_total{reason="replayed"}`); v != 0 {
		t.Fatalf("auth_denied replayed = %d, want 0", v)
	}
}

// TestMetricsRateLimitRejectedIncrements: a rate-limited 429 bumps
// ratelimit_rejected_total.
func TestMetricsRateLimitRejectedIncrements(t *testing.T) {
	router := rateLimitedRouter(0.001, 1) // burst 1

	postOp(t, router, "rlm", []byte("op")) // consumes the token (201)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/rlm/ops", bytes.NewReader([]byte("op")))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("second POST status = %d, want 429", rec.Code)
	}

	_, _, body := scrapeMetrics(t, router)
	if v := metricValue(t, body, "sigild_oplog_ratelimit_rejected_total"); v != 1 {
		t.Fatalf("ratelimit_rejected_total = %d, want 1", v)
	}
}

// TestMetricsHTTPRequestsCounted: the http_requests_total{class="2xx"} counter
// advances as 2xx responses are served (delta-based, per fresh router).
func TestMetricsHTTPRequestsCounted(t *testing.T) {
	router := NewRouter(Config{Version: "test", Logger: discardLogger()})

	_, _, before := scrapeMetrics(t, router) // this scrape itself is a 2xx
	base := metricValue(t, before, `sigild_http_requests_total{class="2xx"}`)

	// Drive three more 2xx probes.
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("healthz status = %d, want 200", rec.Code)
		}
	}

	_, _, after := scrapeMetrics(t, router)
	got := metricValue(t, after, `sigild_http_requests_total{class="2xx"}`)
	// +3 healthz +1 the `before` scrape (counted after it was read) = at least 4.
	if got-base < 4 {
		t.Fatalf("2xx delta = %d, want >= 4", got-base)
	}
}

// TestMetricsNonGlobalIsolation: two independent routers keep independent
// counters — proving the counters are NOT package globals.
func TestMetricsNonGlobalIsolation(t *testing.T) {
	r1 := devOpsRouter()
	r2 := devOpsRouter()

	postOp(t, r1, "iso", []byte("op")) // only r1 gets an append

	_, _, b1 := scrapeMetrics(t, r1)
	_, _, b2 := scrapeMetrics(t, r2)
	if v := metricValue(t, b1, "sigild_oplog_appends_total"); v != 1 {
		t.Fatalf("r1 appends_total = %d, want 1", v)
	}
	if v := metricValue(t, b2, "sigild_oplog_appends_total"); v != 0 {
		t.Fatalf("r2 appends_total = %d, want 0 (counters must be per-router)", v)
	}
}
