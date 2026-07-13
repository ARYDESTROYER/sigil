// Package api wires sigild's HTTP surface.
//
// STATUS: pre-audit skeleton. The router exposes only liveness/readiness and a
// 501 stub for the vault operation log. Real authentication, the CRDT op log,
// device enrollment, recovery and admin endpoints are deferred (see the brief,
// section 14, and docs/sprint-72h.md).
package api

import (
	"crypto/ed25519"
	"log/slog"
	"net/http"

	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

// Config holds the server's runtime configuration.
type Config struct {
	Version string
	// PostgresAddr / RedisAddr are "host:port" reachability targets used by the
	// readiness probe. The production build will swap the plain TCP dial for a
	// real pgx / redis client ping.
	PostgresAddr string
	RedisAddr    string
	Logger       *slog.Logger
	// DevOpsEnabled gates the DEV-ONLY vault op-log. It defaults to false, which
	// keeps the vault-ops routes at their 501 stub. When true, the routes serve
	// an UNAUTHENTICATED, in-memory, non-durable op-log of opaque
	// client-encrypted blobs — for local development ONLY, never production.
	DevOpsEnabled bool
	// VaultLog is OPTIONAL. When DevOpsEnabled is true, NewRouter uses this
	// backend if it is non-nil; otherwise it falls back to an in-memory
	// MemVaultLog (the default). It lets local dev select a durable
	// FileVaultLog without changing handler behaviour. It is ignored when
	// DevOpsEnabled is false (the routes stay at their 501 stub).
	VaultLog store.VaultLog
	// OpLogPubKey, when non-nil AND DevOpsEnabled is true, turns on Ed25519
	// request-authentication for the dev op-log: every GET/POST
	// /v1/vaults/{vaultID}/ops must carry a valid X-Sigil-Timestamp +
	// X-Sigil-Nonce + X-Sigil-Signature per the op-log auth contract v2 (see
	// opsauth.go). nil (the default) means NO auth — unchanged, UNAUTHENTICATED
	// behaviour.
	//
	// HONEST SCOPE: this is a SINGLE configured DEV device key. Each request
	// carries a fresh nonce and the server keeps a PER-PROCESS/in-memory replay
	// cache, so a captured request cannot be replayed within the timestamp
	// window against this instance — but a multi-instance deploy needs a shared
	// store (e.g. Redis). Real device enrollment, a multi-device registry, and
	// JWT bearer tokens (see internal/auth) remain FUTURE. Dev-only; do NOT
	// expose publicly.
	OpLogPubKey ed25519.PublicKey
	// OpLogRateLimit is the per-vault write rate cap for the dev op-log, in
	// requests/second. 0 (the default) DISABLES rate limiting entirely (no
	// wrapper is installed; behaviour is unchanged). A positive value, together
	// with DevOpsEnabled, wraps POST /v1/vaults/{vaultID}/ops in a per-vault
	// token-bucket limiter that returns 429 when a vault exceeds its rate. GET
	// routes are never write-rate-limited. Dev-only.
	OpLogRateLimit float64
	// OpLogRateBurst is the token-bucket capacity (max burst) for OpLogRateLimit.
	// It is only consulted when OpLogRateLimit > 0; a value < 1 is clamped up to
	// 1 by the limiter so single requests always pass.
	OpLogRateBurst int
}

// NewRouter returns the sigild HTTP handler.
func NewRouter(cfg Config) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	h := &handlers{cfg: cfg, metrics: newMetrics(cfg.Version)}
	// Op-log request-auth enabled => attach the in-memory replay cache so a
	// captured, validly-signed request cannot be replayed within the timestamp
	// window. Per-process/in-memory only (a multi-instance deploy needs a shared
	// store, e.g. Redis); dev-only. nil when auth is off (authorizeOps returns
	// before touching it).
	if cfg.OpLogPubKey != nil {
		h.nonces = newNonceCache()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /readyz", h.readyz)
	mux.HandleFunc("GET /version", h.version)
	// Operational metrics: ALWAYS available (never dev-gated). It exposes only
	// process counters and the build version — no secrets, no vault material.
	mux.HandleFunc("GET /metrics", h.metricsHandler)

	if cfg.DevOpsEnabled {
		// DEV-ONLY op-log: UNAUTHENTICATED. Stores opaque client-encrypted
		// blobs; performs no crypto. Never expose publicly. POST is body-capped
		// (oversized -> 413); GET reads only. Backend selection: use the
		// caller-supplied cfg.VaultLog if set (e.g. a durable FileVaultLog),
		// else default to a non-durable in-memory MemVaultLog. Handler
		// behaviour is identical for either backend.
		if cfg.VaultLog != nil {
			h.log = cfg.VaultLog
		} else {
			h.log = store.NewMemVaultLog()
		}
		// POST append: body-capped, then (optionally) per-vault rate-limited.
		// The rate limiter wraps OUTSIDE limitBody so an over-rate request is
		// rejected with 429 before any body handling; it is installed only when a
		// positive rate is configured (0 => no wrapper, behaviour unchanged). GET
		// routes are never write-rate-limited.
		var appendHandler http.Handler = limitBody(maxOpsBodyBytes, http.HandlerFunc(h.opsAppend))
		if cfg.OpLogRateLimit > 0 {
			appendHandler = rateLimitOps(newRateLimiter(cfg.OpLogRateLimit, cfg.OpLogRateBurst), h.metrics, appendHandler)
		}
		mux.Handle("POST /v1/vaults/{vaultID}/ops", appendHandler)
		mux.Handle("GET /v1/vaults/{vaultID}/ops", http.HandlerFunc(h.opsList))
		// Tamper-evidence: walk the op-log hash chain. Same dev-gate + auth-guard
		// as the other ops routes.
		mux.Handle("GET /v1/vaults/{vaultID}/ops/verify", http.HandlerFunc(h.opsVerify))
	} else {
		// Default: vault operation log is intentionally unimplemented in the
		// skeleton. We return 501 rather than fake any crypto/vault/CRDT/auth
		// behaviour. The body is capped at 64 KiB per operation: oversized
		// requests get 413, well-formed small requests fall through to 501.
		ops := limitBody(maxOpsBodyBytes, http.HandlerFunc(h.opsNotImplemented))
		mux.Handle("GET /v1/vaults/{vaultID}/ops", ops)
		mux.Handle("POST /v1/vaults/{vaultID}/ops", ops)
		// The verify route is a distinct path, so register its own 501 stub
		// (it would otherwise 404 instead of the deliberate not-implemented 501).
		mux.Handle("GET /v1/vaults/{vaultID}/ops/verify", http.HandlerFunc(h.opsNotImplemented))
	}

	// Outermost first: count every response (even a recoverer-written 500),
	// recover panics, assign a request ID, then access-log.
	return chain(mux,
		countRequests(h.metrics),
		recoverer(cfg.Logger),
		requestID,
		accessLog(cfg.Logger),
	)
}
