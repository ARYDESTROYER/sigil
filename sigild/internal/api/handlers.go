package api

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

type handlers struct {
	cfg Config
	// log backs the DEV-ONLY vault op-log. It is nil unless cfg.DevOpsEnabled,
	// in which case NewRouter wires an in-memory MemVaultLog and routes
	// opsAppend/opsList here instead of the 501 stub.
	log store.VaultLog
	// nonces is the op-log request-auth replay cache. NewRouter constructs it
	// only when cfg.OpLogPubKey is set (auth enabled); it is nil otherwise, and
	// authorizeOps returns before touching it when auth is off.
	nonces *nonceCache
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

// version reports the build's name and injected version string. It exposes no
// secrets and performs no cryptography — it simply echoes the value threaded in
// from buildinfo at build time (via api.Config.Version). Useful for confirming
// which build is deployed without parsing the liveness probe.
func (h *handlers) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"name":    "sigild",
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

// opsNotImplemented is the deliberate 501 for the vault operation log. On POST
// it first drains the (size-capped) request body so an oversized payload is
// rejected with 413 before we reach the not-implemented response.
func (h *handlers) opsNotImplemented(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			if maxErr := (*http.MaxBytesError)(nil); errors.As(err, &maxErr) {
				writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
					"request body exceeds the per-operation size limit")
				return
			}
			writeError(w, http.StatusBadRequest, "invalid_request",
				"could not read request body")
			return
		}
	}
	writeJSON(w, http.StatusNotImplemented, apiError{
		Error:   "not_implemented",
		Detail:  "vault operation log is not implemented in the pre-audit skeleton",
		VaultID: r.PathValue("vaultID"),
	})
}

// opsAppend appends one opaque, client-encrypted operation to a vault's log.
//
// DEV-ONLY: this handler is wired ONLY when cfg.DevOpsEnabled is set. It is
// UNAUTHENTICATED, backed by an IN-MEMORY, NON-DURABLE op-log, and performs NO
// cryptography — it treats the request body as opaque bytes and never decrypts,
// parses, or interprets them. Do NOT expose publicly; this is a dev skeleton,
// not production. The body is already capped upstream by limitBody (oversized
// -> 413).
func (h *handlers) opsAppend(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")
	if vaultID == "" {
		writeError(w, http.StatusBadRequest, "missing_vault_id", "vault ID is required")
		return
	}

	blob, err := io.ReadAll(r.Body)
	if err != nil {
		if maxErr := (*http.MaxBytesError)(nil); errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				"request body exceeds the per-operation size limit")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "could not read request body")
		return
	}
	// Verify the op-log request signature over (method, path, query, ts, nonce,
	// body) and reject replays. No-op (returns nil) unless cfg.OpLogPubKey is
	// set. Must run AFTER the body is read (it is part of the signed message) and
	// BEFORE we append.
	if err := h.authorizeOps(r, blob); err != nil {
		writeOpsAuthError(w, err)
		return
	}
	if len(blob) == 0 {
		writeError(w, http.StatusBadRequest, "empty_op", "operation body must not be empty")
		return
	}

	op, err := h.log.Append(vaultID, blob)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		VaultID string `json:"vaultID"`
		Seq     uint64 `json:"seq"`
	}{VaultID: vaultID, Seq: op.Seq})
}

// opsList returns a vault's operations with Seq greater than ?since= (default
// 0), in ascending order. Next is the max returned Seq, or the `since` value
// when nothing matched, so a caller can poll forward.
//
// DEV-ONLY: wired ONLY when cfg.DevOpsEnabled is set. UNAUTHENTICATED,
// IN-MEMORY, NON-DURABLE, performs NO cryptography. Each Op.Blob is the opaque
// client-encrypted payload exactly as stored; encoding/json marshals it ([]byte)
// as a base64 string automatically. Do NOT expose publicly.
func (h *handlers) opsList(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")
	if vaultID == "" {
		writeError(w, http.StatusBadRequest, "missing_vault_id", "vault ID is required")
		return
	}

	// Verify the op-log request signature over (method, path, query, ts, nonce,
	// "") and reject replays. GET carries no body, so the signed body is empty.
	// No-op (returns nil) unless cfg.OpLogPubKey is set. Must run BEFORE we list.
	if err := h.authorizeOps(r, nil); err != nil {
		writeOpsAuthError(w, err)
		return
	}

	var since uint64
	if raw := r.URL.Query().Get("since"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_since",
				"since must be a non-negative integer")
			return
		}
		since = parsed
	}

	ops, err := h.log.Since(vaultID, since)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}

	next := since
	for _, op := range ops {
		if op.Seq > next {
			next = op.Seq
		}
	}
	writeJSON(w, http.StatusOK, struct {
		VaultID string     `json:"vaultID"`
		Ops     []store.Op `json:"ops"`
		Next    uint64     `json:"next"`
	}{VaultID: vaultID, Ops: ops, Next: next})
}
