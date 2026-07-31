package api

// CROSS-ORIGIN RESOURCE SHARING (Phase 56 fix).
//
// ---------------------------------------------------------------------------
// WHY THIS EXISTS AT ALL
// ---------------------------------------------------------------------------
//
// Every request a browser client makes to sigild carries X-Sigil-Device,
// X-Sigil-Timestamp, X-Sigil-Nonce and X-Sigil-Signature. Custom request headers
// are not "simple" headers, so the browser sends a CORS PREFLIGHT (OPTIONS)
// first. sigild routed no OPTIONS method, so a real preflight was answered
// `405 Method Not Allowed` with no Access-Control-* header at all, and the
// browser blocked the actual request. The result: from a page served on a
// different origin than the API — which is the entire localhost dev topology,
// webapp on :3000, sigild on :8080 — enrollment, sync, sharing, restore-from-kit
// and the entitlement read were ALL dead. The MV3 extension never hit this,
// because an extension page with a host permission is exempt from CORS.
//
// ---------------------------------------------------------------------------
// ⭐ THIS IS NOT AN AUTHENTICATION CONTROL, AND IT IS NOT A CSRF CONTROL
// ---------------------------------------------------------------------------
//
// Access-Control-Allow-Credentials is deliberately NEVER set, and there is
// nothing for it to enable: sigild issues no cookie, no session and no bearer
// token that a browser would attach ambiently. EVERY authenticated request is
// authenticated by a per-request Ed25519 signature over a canonical message
// (contract v3, deviceauth.go), computed from a private key the requesting page
// holds. A hostile cross-origin page has no such key, so it cannot forge a
// request whatever CORS says — which is also why CORS here provides no CSRF
// protection that the signature did not already provide.
//
// So the allowlist is not a security boundary. It exists so that (a) the browser
// half of the product works at all, (b) the set of origins that may talk to a
// given server is a deliberate, written-down operator decision rather than an
// accident, and (c) a browser-side failure is an honest configuration error
// instead of an unexplained network error.
//
// ---------------------------------------------------------------------------
// THE RULES
// ---------------------------------------------------------------------------
//
//   - UNSET (the default) installs NO middleware at all: not one byte of any
//     response changes, and `grep access-control` on a running server finds
//     nothing — exactly the behaviour that shipped before this file existed.
//   - The allowlist holds EXACT origins (scheme + host + port). `*` is rejected
//     at boot, not silently downgraded: a wildcard on an API that carries
//     per-request signed credentials is not something an operator should be able
//     to type by accident.
//   - Access-Control-Allow-Origin is ECHOED, and only for an origin that is on
//     the list. It is never `*`, and never a value the request did not present.
//   - `Vary: Origin` is set on EVERY response this middleware touches, allowed
//     or not, so no cache can serve one origin the header computed for another.
//   - A preflight is answered only for an allowed origin. An unknown origin's
//     OPTIONS falls through to the mux, which answers 405 exactly as it did
//     before — the browser blocks the request either way, and we have not built
//     a probe that distinguishes "route exists" from "origin allowed".
//
// ---------------------------------------------------------------------------
// PRODUCTION
// ---------------------------------------------------------------------------
//
// A production deployment should serve the app and the API from the SAME ORIGIN
// behind the reverse proxy (Caddy already fronts sigild — see
// docs/deployment.md), in which case NO origin needs to be listed and this file
// stays inert. SIGILD_CORS_ORIGINS exists for the localhost dev topology, where
// the two are necessarily on different ports.

import (
	"net/http"
	"strings"
)

// corsMaxAgeSeconds bounds how long a browser may cache a preflight result. Ten
// minutes: long enough that a burst of signed requests does not re-preflight
// every call, short enough that removing an origin from the allowlist takes
// effect promptly.
const corsMaxAgeSeconds = "600"

// corsAllowedRequestHeaders are the request headers a client is permitted to
// send cross-origin. It is EXACTLY the set the four clients actually send (see
// deviceauth.go for the auth headers and sync.mjs for the content type), not a
// wildcard: an operator reading this list can see the whole request surface.
var corsAllowedRequestHeaders = strings.Join([]string{
	"Content-Type",
	"X-Request-ID",
	"X-Sigil-Device",
	"X-Sigil-Timestamp",
	"X-Sigil-Nonce",
	"X-Sigil-Signature",
	"X-Sigil-Enroll-Token",
	"X-Sigil-Admin-Token",
}, ", ")

// corsAllowedMethods are the methods actually routed by NewRouter, plus the
// OPTIONS this middleware answers itself.
var corsAllowedMethods = strings.Join([]string{
	http.MethodGet,
	http.MethodHead,
	http.MethodPost,
	http.MethodPut,
	http.MethodDelete,
	http.MethodOptions,
}, ", ")

// corsExposedResponseHeaders are the response headers JavaScript is allowed to
// READ cross-origin. Without this the entitlement warning headers are invisible
// to a browser client (they are not on the CORS-safelisted set), and a customer
// inside their grace period would never be told — which is the exact defect the
// entitlement work exists to fix.
//
// ⭐ "Date" IS ON THIS LIST FOR THE SAME REASON, and it was measured rather than
// assumed. A TOTP code is a function of a secret and the current time, so a
// device whose clock has drifted past half a step starts having its codes
// rejected (RFC 6238 §5.2 lets a verifier accept one step either side, so it is
// LIKELY and increasingly certain, not immediate and total) — and to the user a
// rejected code is indistinguishable from a wrong secret. The client-side
// diagnostic that tells them apart (sigil-wasm/clock-skew.mjs) reads the server's
// clock off the `Date` header every Go response already carries. But `Date` is
// NOT one of the seven CORS-safelisted response headers, so a browser on a
// different origin gets null for it: probed against a real sigild from a real
// Chromium, the only readable headers were content-length, content-type and
// x-request-id. Naming it here is what makes the browser half of that diagnostic
// possible at all.
//
// It discloses nothing: the header is ALREADY sent on every response and already
// readable by curl, the CLI and the desktop. All that changes is whether
// same-machine JavaScript may read a value the browser already received. And
// this whole middleware is not installed unless SIGILD_CORS_ORIGINS is set.
var corsExposedResponseHeaders = strings.Join([]string{
	"X-Request-ID",
	"Date",
	headerEntitlement,
	headerEntitlementStatus,
	headerEntitlementGraceEnds,
}, ", ")

// corsMiddleware answers preflights and stamps CORS headers for origins on the
// allowlist. It is installed by NewRouter ONLY when the allowlist is non-empty.
//
// The origins are expected pre-normalized (lowercase scheme+host, no path) — the
// boot-time validator in cmd/server does that and refuses anything else.
func corsMiddleware(origins []string) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		allowed[strings.ToLower(strings.TrimSpace(o))] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Always, allowed or not: this response DEPENDS on Origin, so a
			// shared cache must not reuse it for a different one.
			w.Header().Add("Vary", "Origin")

			origin := r.Header.Get("Origin")
			_, ok := allowed[strings.ToLower(origin)]
			isPreflight := r.Method == http.MethodOptions &&
				r.Header.Get("Access-Control-Request-Method") != ""

			if origin == "" || !ok {
				// Not a CORS request, or an origin we do not serve. Emit NO
				// Access-Control-Allow-Origin — the browser will block it, which
				// is the correct outcome — and let the router answer normally.
				next.ServeHTTP(w, r)
				return
			}

			// ECHO the presented origin (never "*", never a stored value the
			// request did not send).
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Expose-Headers", corsExposedResponseHeaders)
			// ⛔ Access-Control-Allow-Credentials is NOT set, on purpose. See the
			// file header: there is no cookie and no ambient authority to grant.

			if isPreflight {
				w.Header().Add("Vary", "Access-Control-Request-Method")
				w.Header().Add("Vary", "Access-Control-Request-Headers")
				w.Header().Set("Access-Control-Allow-Methods", corsAllowedMethods)
				w.Header().Set("Access-Control-Allow-Headers", corsAllowedRequestHeaders)
				w.Header().Set("Access-Control-Max-Age", corsMaxAgeSeconds)
				// A preflight carries no body and reaches no handler: it must
				// never touch the op-log, the device registry or a rate limiter.
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
