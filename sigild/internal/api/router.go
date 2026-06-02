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
	// Vault operation log — intentionally unimplemented in the skeleton.
	// We return 501 rather than fake any crypto/vault/CRDT/auth behaviour.
	mux.HandleFunc("GET /v1/vaults/{vaultID}/ops", h.opsNotImplemented)
	mux.HandleFunc("POST /v1/vaults/{vaultID}/ops", h.opsNotImplemented)
	return mux
}
