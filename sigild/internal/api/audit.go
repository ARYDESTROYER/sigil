package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
)

// Structured audit events for the DEV op-log. They are emitted through
// cfg.Logger (structured slog) so an operator has a stable, machine-readable
// trail of every op-log append, list, and auth denial.
//
// SECURITY INVARIANT: these lines record METADATA ONLY. They NEVER contain the
// opaque blob content, the request signature, the nonce, the timestamp value, or
// any other secret. For integrity, an append records blob_sha256 — a hex SHA-256
// FINGERPRINT of the blob, NOT the bytes themselves — so an operator can
// correlate a stored op with client-side records without the server ever
// retaining or logging the ciphertext. The fingerprint is computed once per
// append. The message string is set to the event name and the same name is also
// carried as the stable "event" attribute, so consumers can filter on it
// regardless of the slog handler.
const (
	auditEventAppend     = "oplog.append"
	auditEventList       = "oplog.list"
	auditEventVerify     = "oplog.verify"
	auditEventAuthDenied = "oplog.auth_denied"
)

// authMode reports the op-log's configured auth mode for the append audit line:
// "ed25519" when a device pubkey is configured, else "none".
func (h *handlers) authMode() string {
	if h.cfg.OpLogPubKey != nil {
		return "ed25519"
	}
	return "none"
}

// auditAppend logs a SUCCESSFUL op-log append. blob_sha256 is a hex fingerprint
// for integrity — never the content; the blob bytes themselves are not logged.
func (h *handlers) auditAppend(r *http.Request, vaultID string, seq uint64, blob []byte) {
	sum := sha256.Sum256(blob)
	h.cfg.Logger.Info(auditEventAppend,
		"event", auditEventAppend,
		"request_id", RequestIDFromContext(r.Context()),
		"vault_id", vaultID,
		"seq", seq,
		"size_bytes", len(blob),
		"blob_sha256", hex.EncodeToString(sum[:]),
		"auth", h.authMode(),
	)
}

// auditList logs an op-log list, recording only how many ops were returned (not
// their contents).
func (h *handlers) auditList(r *http.Request, vaultID string, since uint64, returnedCount int) {
	h.cfg.Logger.Info(auditEventList,
		"event", auditEventList,
		"request_id", RequestIDFromContext(r.Context()),
		"vault_id", vaultID,
		"since", since,
		"returned_count", returnedCount,
	)
}

// auditVerify logs an op-log chain-verification, recording the outcome (ok) and
// how many ops were walked — never any blob content or hash bytes.
func (h *handlers) auditVerify(r *http.Request, vaultID string, ok bool, count uint64) {
	h.cfg.Logger.Info(auditEventVerify,
		"event", auditEventVerify,
		"request_id", RequestIDFromContext(r.Context()),
		"vault_id", vaultID,
		"ok", ok,
		"count", count,
	)
}

// auditAuthDenied logs an op-log request rejected by authorizeOps. reason is the
// fixed enum naming the failed check (never any secret material).
func (h *handlers) auditAuthDenied(r *http.Request, vaultID string, reason authReason) {
	h.cfg.Logger.Warn(auditEventAuthDenied,
		"event", auditEventAuthDenied,
		"request_id", RequestIDFromContext(r.Context()),
		"vault_id", vaultID,
		"reason", string(reason),
	)
}
