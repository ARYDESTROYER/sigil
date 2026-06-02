package api

import (
	"encoding/json"
	"net"
	"net/http"
	"time"
)

type handlers struct {
	cfg Config
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// healthz is a pure liveness probe: the process is up and serving.
func (h *handlers) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": h.cfg.Version,
	})
}

// readyz reports whether sigild's dependencies are reachable. The skeleton does
// a plain TCP dial (no auth handshake); the production build replaces this with
// real pgx/redis pings. If a *configured* dependency is unreachable we return
// 503 so a load balancer drains the instance.
func (h *handlers) readyz(w http.ResponseWriter, _ *http.Request) {
	checks := map[string]string{
		"postgres": dialState(h.cfg.PostgresAddr),
		"redis":    dialState(h.cfg.RedisAddr),
	}
	status := http.StatusOK
	for _, state := range checks {
		if state == "unreachable" {
			status = http.StatusServiceUnavailable
		}
	}
	writeJSON(w, status, map[string]any{
		"version": h.cfg.Version,
		"checks":  checks,
	})
}

func dialState(addr string) string {
	if addr == "" {
		return "unconfigured"
	}
	conn, err := net.DialTimeout("tcp", addr, 750*time.Millisecond)
	if err != nil {
		return "unreachable"
	}
	_ = conn.Close()
	return "ok"
}

// opsNotImplemented is the deliberate 501 for the vault operation log.
func (h *handlers) opsNotImplemented(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{
		"error":   "not_implemented",
		"detail":  "vault operation log is not implemented in the pre-audit skeleton",
		"vaultID": r.PathValue("vaultID"),
	})
}
