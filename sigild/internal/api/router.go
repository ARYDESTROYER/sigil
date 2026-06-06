// Package api wires sigild's HTTP surface.
//
// STATUS: pre-audit skeleton. The router exposes only liveness/readiness and a
// 501 stub for the vault operation log. Real authentication, the CRDT op log,
// device enrollment, recovery and admin endpoints are deferred (see the brief,
// section 14, and docs/sprint-72h.md).
package api

import (
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
}

// NewRouter returns the sigild HTTP handler.
func NewRouter(cfg Config) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	h := &handlers{cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /readyz", h.readyz)
	mux.HandleFunc("GET /version", h.version)

	if cfg.DevOpsEnabled {
		// DEV-ONLY op-log: UNAUTHENTICATED, in-memory, non-durable. Stores
		// opaque client-encrypted blobs; performs no crypto. Never expose
		// publicly. POST is body-capped (oversized -> 413); GET reads only.
		h.log = store.NewMemVaultLog()
		mux.Handle("POST /v1/vaults/{vaultID}/ops",
			limitBody(maxOpsBodyBytes, http.HandlerFunc(h.opsAppend)))
		mux.Handle("GET /v1/vaults/{vaultID}/ops", http.HandlerFunc(h.opsList))
	} else {
		// Default: vault operation log is intentionally unimplemented in the
		// skeleton. We return 501 rather than fake any crypto/vault/CRDT/auth
		// behaviour. The body is capped at 64 KiB per operation: oversized
		// requests get 413, well-formed small requests fall through to 501.
		ops := limitBody(maxOpsBodyBytes, http.HandlerFunc(h.opsNotImplemented))
		mux.Handle("GET /v1/vaults/{vaultID}/ops", ops)
		mux.Handle("POST /v1/vaults/{vaultID}/ops", ops)
	}

	// Outermost first: recover panics, assign a request ID, then access-log.
	return chain(mux,
		recoverer(cfg.Logger),
		requestID,
		accessLog(cfg.Logger),
	)
}
