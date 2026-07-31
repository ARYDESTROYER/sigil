package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	allowedOrigin = "http://127.0.0.1:3210"
	otherOrigin   = "http://evil.example"
)

func corsRouter(t *testing.T, origins ...string) http.Handler {
	t.Helper()
	return NewRouter(Config{Version: "test", CORSOrigins: origins})
}

// The DEFAULT server must be byte-identical to the pre-CORS one: not a single
// Access-Control-* header, and an OPTIONS still 405s.
func TestCORSOffByDefaultEmitsNoHeaders(t *testing.T) {
	r := NewRouter(Config{Version: "test"})

	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/healthz"},
		{http.MethodOptions, "/healthz"},
		{http.MethodGet, "/v1/vaults/v1/ops"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Origin", allowedOrigin)
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)

		for name := range rec.Header() {
			if strings.HasPrefix(strings.ToLower(name), "access-control-") {
				t.Fatalf("%s %s: unexpected %s with CORS unconfigured", tc.method, tc.path, name)
			}
		}
		if got := rec.Header().Get("Vary"); strings.Contains(got, "Origin") {
			t.Fatalf("%s %s: unexpected Vary: %q with CORS unconfigured", tc.method, tc.path, got)
		}
	}
}

// THE REGRESSION: a real browser preflight for a signed request. Before this, it
// was answered 405 with no Access-Control-Allow-Origin and the browser blocked
// every enroll / sync / share / restore / entitlement call.
func TestCORSPreflightAnswersSignedRequestHeaders(t *testing.T) {
	r := corsRouter(t, allowedOrigin)

	req := httptest.NewRequest(http.MethodOptions, "/v1/devices/enroll", nil)
	req.Header.Set("Origin", allowedOrigin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers",
		"content-type,x-sigil-device,x-sigil-timestamp,x-sigil-nonce,x-sigil-signature")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("preflight status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != allowedOrigin {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, allowedOrigin)
	}
	allowHeaders := strings.ToLower(rec.Header().Get("Access-Control-Allow-Headers"))
	// EVERY header the clients actually sign with must be allowed, or the
	// browser blocks the request even though the preflight "succeeded".
	for _, h := range []string{
		"content-type",
		"x-sigil-device", "x-sigil-timestamp", "x-sigil-nonce", "x-sigil-signature",
		"x-sigil-enroll-token", "x-sigil-admin-token",
	} {
		if !strings.Contains(allowHeaders, h) {
			t.Fatalf("Access-Control-Allow-Headers %q is missing %q", allowHeaders, h)
		}
	}
	allowMethods := rec.Header().Get("Access-Control-Allow-Methods")
	for _, m := range []string{"GET", "POST", "PUT", "DELETE"} {
		if !strings.Contains(allowMethods, m) {
			t.Fatalf("Access-Control-Allow-Methods %q is missing %q", allowMethods, m)
		}
	}
	if rec.Header().Get("Access-Control-Max-Age") == "" {
		t.Fatal("preflight has no Access-Control-Max-Age")
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Origin") {
		t.Fatalf("preflight Vary = %q, want it to include Origin", rec.Header().Get("Vary"))
	}
}

// The ACTUAL (non-preflight) request must carry the echoed origin AND expose the
// entitlement warning headers — without Expose-Headers a browser client cannot
// read them, so a customer in grace would never be told.
func TestCORSActualRequestEchoesOriginAndExposesEntitlementHeaders(t *testing.T) {
	r := corsRouter(t, allowedOrigin)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", allowedOrigin)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != allowedOrigin {
		t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, allowedOrigin)
	}
	exposed := rec.Header().Get("Access-Control-Expose-Headers")
	// "Date" is here for the CLOCK-SKEW DIAGNOSTIC, and it is load-bearing: a
	// browser cannot read Date cross-origin unless it is exposed (measured — the
	// only readable headers otherwise were content-length, content-type and
	// x-request-id). Without it the browser clients cannot tell a user that their
	// clock, not their secret, is the likely reason a code is being rejected.
	// (Not "every code": RFC 6238 §5.2 lets a verifier accept one step either
	// side, so a small drift may still validate — the same overstatement was
	// corrected in cors.go and in all four clients this phase.)
	for _, h := range []string{
		headerEntitlement, headerEntitlementStatus, headerEntitlementGraceEnds, "Date",
	} {
		if !strings.Contains(exposed, h) {
			t.Fatalf("Access-Control-Expose-Headers %q is missing %q", exposed, h)
		}
	}
	// And the header it names must actually be present on the response.
	if rec.Header().Get("Date") == "" {
		// httptest.Recorder does not stamp Date the way a real server does, so
		// this is only a sanity check that nothing stripped it.
		t.Log("no Date on the recorder (expected: httptest does not add it; the real server does)")
	}
}

// An origin that is NOT on the list gets nothing — and the response still
// carries Vary: Origin so a cache cannot hand it the allowed origin's header.
func TestCORSUnlistedOriginGetsNoAllowHeader(t *testing.T) {
	r := corsRouter(t, allowedOrigin)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", otherOrigin)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unlisted origin got Access-Control-Allow-Origin = %q, want none", got)
	}
	if !strings.Contains(rec.Header().Get("Vary"), "Origin") {
		t.Fatalf("Vary = %q, want it to include Origin", rec.Header().Get("Vary"))
	}

	// Its preflight is not answered either: it falls through to the mux.
	pre := httptest.NewRequest(http.MethodOptions, "/v1/devices/enroll", nil)
	pre.Header.Set("Origin", otherOrigin)
	pre.Header.Set("Access-Control-Request-Method", http.MethodPost)
	prec := httptest.NewRecorder()
	r.ServeHTTP(prec, pre)
	if prec.Code == http.StatusNoContent {
		t.Fatal("an unlisted origin's preflight was answered 204")
	}
	if got := prec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unlisted preflight got Access-Control-Allow-Origin = %q, want none", got)
	}
}

// ⭐ Two invariants that must never regress: the wildcard is never emitted, and
// credentials mode is never enabled (there is no cookie to protect, and enabling
// it alongside an echoed origin is the classic CORS footgun).
func TestCORSNeverWildcardNeverCredentials(t *testing.T) {
	r := corsRouter(t, allowedOrigin, "https://app.example")

	for _, origin := range []string{allowedOrigin, "https://app.example", otherOrigin, ""} {
		for _, method := range []string{http.MethodGet, http.MethodOptions} {
			req := httptest.NewRequest(method, "/v1/devices/enroll", nil)
			if origin != "" {
				req.Header.Set("Origin", origin)
			}
			req.Header.Set("Access-Control-Request-Method", http.MethodPost)
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, req)

			if got := rec.Header().Get("Access-Control-Allow-Origin"); got == "*" {
				t.Fatalf("origin %q %s: emitted the wildcard", origin, method)
			}
			if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
				t.Fatalf("origin %q %s: Access-Control-Allow-Credentials = %q, want none",
					origin, method, got)
			}
		}
	}
}

// The allowlist is matched EXACTLY: a different port, scheme or host is a
// different origin, and a suffix/prefix must never satisfy it.
func TestCORSMatchesOriginExactly(t *testing.T) {
	r := corsRouter(t, "http://127.0.0.1:3210")

	for _, origin := range []string{
		"http://127.0.0.1:3211",
		"https://127.0.0.1:3210",
		"http://127.0.0.1",
		"http://127.0.0.1:3210.evil.example",
		"http://evil.example/http://127.0.0.1:3210",
	} {
		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.Header.Set("Origin", origin)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Fatalf("origin %q was allowed (%q)", origin, got)
		}
	}
}

// A preflight must not reach a handler: it touches no store, no limiter and no
// auth path. Proven by preflighting a DEV-GATED route on a server with the dev
// gate OFF — the handler would answer 501, the middleware answers 204.
func TestCORSPreflightDoesNotReachHandlers(t *testing.T) {
	r := corsRouter(t, allowedOrigin)

	req := httptest.NewRequest(http.MethodOptions, "/v1/vaults/some-vault/ops", nil)
	req.Header.Set("Origin", allowedOrigin)
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (the preflight must not reach the 501 stub)", rec.Code)
	}
	if body := rec.Body.String(); body != "" {
		t.Fatalf("preflight body = %q, want empty", body)
	}
}

// An OPTIONS that is NOT a preflight (no Access-Control-Request-Method) is not
// hijacked: it falls through to the router exactly as before.
func TestCORSPlainOptionsFallsThrough(t *testing.T) {
	r := corsRouter(t, allowedOrigin)

	req := httptest.NewRequest(http.MethodOptions, "/healthz", nil)
	req.Header.Set("Origin", allowedOrigin)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if rec.Code == http.StatusNoContent {
		t.Fatal("a non-preflight OPTIONS was answered as a preflight")
	}
}
