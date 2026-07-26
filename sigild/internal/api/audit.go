package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"

	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
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
	// Device-model events (Phase 41). Like the op-log events they carry
	// METADATA ONLY: a device ID, a label, a permission, a fixed reason enum.
	// They NEVER carry a public key, a signature, a nonce, a timestamp value, an
	// enrollment token (or its digest), an admin token, or blob content.
	auditEventDeviceEnrolled     = "device.enrolled"
	auditEventDeviceEnrollDenied = "device.enroll_denied"
	auditEventDeviceRevoked      = "device.revoked"
	auditEventVaultClaimed       = "vault.claimed"
	auditEventVaultGranted       = "vault.granted"
)

// authMode reports the op-log's configured auth mode for the append audit line:
// "device" when the v3 multi-device registry is active, "ed25519" for the legacy
// single configured pubkey, else "none".
func (h *handlers) authMode() string {
	switch {
	case h.deviceAuthEnabled():
		return "device"
	case h.cfg.OpLogPubKey != nil:
		return "ed25519"
	default:
		return "none"
	}
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

// auditAuthDenied logs a request rejected by authentication or authorization.
// reason is the fixed enum naming the failed check; deviceID is the device ID
// the client PRESENTED (recorded even when it resolved to nothing, so an
// operator can see who was probing) and is empty in the legacy/no-auth modes.
// Never any secret material.
func (h *handlers) auditAuthDenied(r *http.Request, vaultID, deviceID string, reason authReason) {
	h.cfg.Logger.Warn(auditEventAuthDenied,
		"event", auditEventAuthDenied,
		"request_id", RequestIDFromContext(r.Context()),
		"vault_id", vaultID,
		"device_id", deviceID,
		"reason", string(reason),
		"status", authStatus(reason),
	)
}

// auditEnrolled logs a SUCCESSFUL device enrollment. It records the assigned
// device ID and label only — never the enrolled PUBLIC KEY, never the
// enrollment token or its digest, never the proof signature.
func (h *handlers) auditEnrolled(r *http.Request, d store.Device) {
	h.cfg.Logger.Info(auditEventDeviceEnrolled,
		"event", auditEventDeviceEnrolled,
		"request_id", RequestIDFromContext(r.Context()),
		"device_id", d.ID,
		"label", d.Label,
	)
}

// auditEnrollDenied logs a REJECTED enrollment attempt. reason is the fixed enum
// naming the failed check; no device ID exists yet, and no token/key/signature
// is ever logged.
func (h *handlers) auditEnrollDenied(r *http.Request, reason authReason) {
	h.cfg.Logger.Warn(auditEventDeviceEnrollDenied,
		"event", auditEventDeviceEnrollDenied,
		"request_id", RequestIDFromContext(r.Context()),
		"reason", string(reason),
	)
}

// auditDeviceRevoked logs a device revocation. revokedBy is either "admin" (the
// operator token path) or the revoking device's own ID (self-revocation) — never
// the token itself.
func (h *handlers) auditDeviceRevoked(r *http.Request, deviceID, revokedBy string) {
	h.cfg.Logger.Warn(auditEventDeviceRevoked,
		"event", auditEventDeviceRevoked,
		"request_id", RequestIDFromContext(r.Context()),
		"device_id", deviceID,
		"revoked_by", revokedBy,
	)
}

// auditVaultClaimed logs a trust-on-first-write ownership claim: this device is
// now the vault's owner. It is the security-relevant moment when a vault ID
// becomes bound to a device, so it is logged at Info with both IDs.
func (h *handlers) auditVaultClaimed(r *http.Request, vaultID, deviceID string) {
	h.cfg.Logger.Info(auditEventVaultClaimed,
		"event", auditEventVaultClaimed,
		"request_id", RequestIDFromContext(r.Context()),
		"vault_id", vaultID,
		"device_id", deviceID,
	)
}

// auditGrant logs an access grant on a vault: which device was granted what.
func (h *handlers) auditGrant(r *http.Request, vaultID, deviceID, permission string) {
	h.cfg.Logger.Info(auditEventVaultGranted,
		"event", auditEventVaultGranted,
		"request_id", RequestIDFromContext(r.Context()),
		"vault_id", vaultID,
		"device_id", deviceID,
		"permission", permission,
	)
}
