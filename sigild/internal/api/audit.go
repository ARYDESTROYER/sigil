package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/billing"
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
	// Account-model events (Phase 52). METADATA ONLY: account IDs, device IDs,
	// a PUBLIC invite handle, an expiry, and a fixed reason enum. They NEVER
	// carry an invite SECRET, an invite DIGEST, an enrollment token, a key, a
	// signature, a nonce or blob content.
	auditEventAccountCreated       = "account.created"
	auditEventAccountInviteCreated = "account.invite_created"
	auditEventAccountInviteRevoked = "account.invite_revoked"
	auditEventAccountDeviceJoined  = "account.device_joined"
	// Vault-sharing events (Phase 46). METADATA ONLY: device IDs, a vault ID, a
	// size, and a hex SHA-256 FINGERPRINT of the opaque envelope. They NEVER
	// carry the envelope bytes (which are ciphertext the server cannot read),
	// a vault key, a hybrid public key, a signature, or a nonce.
	auditEventHybridKeyPublished = "device.hybrid_key_published"
	auditEventKeyEnvelopePut     = "vault.key_envelope_put"
	auditEventKeyEnvelopeGet     = "vault.key_envelope_get"
	auditEventKeyEnvelopeList    = "vault.key_envelope_list"
	auditEventKeyEnvelopeDelete  = "vault.key_envelope_delete"
	// Billing events (Phase 45). METADATA ONLY: a provider name, a normalized
	// event type, an opaque provider event/session reference, our own subject
	// reference, and a fixed reason enum.
	//
	// They NEVER carry an API key, a webhook secret, a signature header, the RAW
	// WEBHOOK BODY (or any part of it), an email address, a name, a phone
	// number, an amount, or — by construction, since no such field exists
	// anywhere in this server — a card number, CVV or expiry date.
	auditEventBillingCheckout      = "billing.checkout_created"
	auditEventBillingCheckoutError = "billing.checkout_failed"
	auditEventBillingWebhook       = "billing.webhook"
	auditEventBillingWebhookDenied = "billing.webhook_rejected"
	auditEventBillingTransition    = "billing.subscription_transition"
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
// device ID, its account and the label only — never the enrolled PUBLIC KEY,
// never the enrollment token or invite (or either digest), never the proof
// signature.
func (h *handlers) auditEnrolled(r *http.Request, d store.Device) {
	h.cfg.Logger.Info(auditEventDeviceEnrolled,
		"event", auditEventDeviceEnrolled,
		"request_id", RequestIDFromContext(r.Context()),
		"device_id", d.ID,
		"account_id", d.AccountID,
		"label", d.Label,
	)
}

// auditEnrollDenied logs a REJECTED enrollment attempt. reason is the fixed enum
// naming the failed check; inviteReason carries the FINE-GRAINED account-invite
// cause (empty on the operator-token path).
//
// inviteReason is deliberately audit-log-ONLY: it must never become a /metrics
// label (that endpoint is always-on and unauthenticated, so a per-reason counter
// there is a correlatable oracle) and never reach a response body.
func (h *handlers) auditEnrollDenied(r *http.Request, reason authReason, inviteReason string) {
	h.cfg.Logger.Warn(auditEventDeviceEnrollDenied,
		"event", auditEventDeviceEnrollDenied,
		"request_id", RequestIDFromContext(r.Context()),
		"reason", string(reason),
		"invite_reason", inviteReason,
	)
}

// auditDeviceRevoked logs a device revocation. revokedBy is "admin" (the
// operator token path), the revoking device's own ID (self-revocation), or a
// SIBLING device's ID (same-account revocation) — never the token itself.
func (h *handlers) auditDeviceRevoked(r *http.Request, deviceID, revokedBy, accountID string) {
	h.cfg.Logger.Warn(auditEventDeviceRevoked,
		"event", auditEventDeviceRevoked,
		"request_id", RequestIDFromContext(r.Context()),
		"device_id", deviceID,
		"account_id", accountID,
		"revoked_by", revokedBy,
	)
}

// auditVaultClaimed logs a trust-on-first-write ownership claim: this ACCOUNT is
// now the vault's owner. It is the security-relevant moment when a vault ID
// becomes bound to a subject, so it is logged at Info with all three IDs (the
// device is recorded because it is who performed the claim, not because it
// confers anything).
func (h *handlers) auditVaultClaimed(r *http.Request, vaultID, deviceID, accountID string) {
	h.cfg.Logger.Info(auditEventVaultClaimed,
		"event", auditEventVaultClaimed,
		"request_id", RequestIDFromContext(r.Context()),
		"vault_id", vaultID,
		"device_id", deviceID,
		"account_id", accountID,
	)
}

// auditAccountCreated logs a new account founded by an operator-token
// enrollment. created_by_device_id is audit metadata: membership is flat, so the
// founder holds no extra power.
func (h *handlers) auditAccountCreated(r *http.Request, accountID, deviceID string) {
	h.cfg.Logger.Info(auditEventAccountCreated,
		"event", auditEventAccountCreated,
		"request_id", RequestIDFromContext(r.Context()),
		"account_id", accountID,
		"created_by_device_id", deviceID,
	)
}

// auditAccountInviteCreated logs a minted invite. It records the PUBLIC handle,
// the account, who minted it, when it expires and whether it is pinned —
// NEVER the invite secret and NEVER its digest. Those two are the credential;
// an audit line is not a credential-distribution channel.
func (h *handlers) auditAccountInviteCreated(r *http.Request, inviteID, accountID, deviceID string, expiresAt time.Time, pinned bool) {
	h.cfg.Logger.Info(auditEventAccountInviteCreated,
		"event", auditEventAccountInviteCreated,
		"request_id", RequestIDFromContext(r.Context()),
		"invite_id", inviteID,
		"account_id", accountID,
		"device_id", deviceID,
		"expires_at", expiresAt.UTC().Format(time.RFC3339),
		"pinned", pinned,
	)
}

// auditAccountInviteRevoked logs an invite revoked before use.
func (h *handlers) auditAccountInviteRevoked(r *http.Request, inviteID, accountID, deviceID string) {
	h.cfg.Logger.Warn(auditEventAccountInviteRevoked,
		"event", auditEventAccountInviteRevoked,
		"request_id", RequestIDFromContext(r.Context()),
		"invite_id", inviteID,
		"account_id", accountID,
		"device_id", deviceID,
	)
}

// auditAccountDeviceJoined logs a device joining an EXISTING account by invite.
// It names the inviter, which is what makes a planted device VISIBLE after the
// fact — flat membership means it is not PREVENTED.
func (h *handlers) auditAccountDeviceJoined(r *http.Request, accountID, deviceID, invitedBy, inviteID string) {
	h.cfg.Logger.Info(auditEventAccountDeviceJoined,
		"event", auditEventAccountDeviceJoined,
		"request_id", RequestIDFromContext(r.Context()),
		"account_id", accountID,
		"device_id", deviceID,
		"invited_by", invitedBy,
		"invite_id", inviteID,
	)
}

// auditCheckoutCreated logs a hosted checkout session created for a subject.
// sessionID is the PROVIDER's opaque session handle — useful for reconciling
// against the provider dashboard, and useless for charging anyone. No amount, no
// customer contact detail, and no payment-instrument field is recorded (none
// exists).
// The subject is the buying device's ACCOUNT (Phase 52); device_id records WHICH
// device ran the checkout, so an operator can still see that without the account
// ceasing to be the subject of entitlement.
func (h *handlers) auditCheckoutCreated(r *http.Request, provider, subject, deviceID, sessionID string) {
	h.cfg.Logger.Info(auditEventBillingCheckout,
		"event", auditEventBillingCheckout,
		"request_id", RequestIDFromContext(r.Context()),
		"provider", provider,
		"subject", subject,
		"device_id", deviceID,
		"session_id", sessionID,
	)
}

// auditCheckoutFailed logs a failed provider checkout call. The error is a
// billing.ProviderError (provider + operation + HTTP status) or a transport
// error — deliberately never the provider's response BODY, which can echo
// customer data, and never a credential (keys travel in headers, not URLs).
func (h *handlers) auditCheckoutFailed(r *http.Request, provider, subject, deviceID string, err error) {
	h.cfg.Logger.Error(auditEventBillingCheckoutError,
		"event", auditEventBillingCheckoutError,
		"request_id", RequestIDFromContext(r.Context()),
		"provider", provider,
		"subject", subject,
		"device_id", deviceID,
		"err", err.Error(),
	)
}

// auditWebhook logs an AUTHENTICATED webhook and what we did with it. It records
// the provider, the NORMALIZED event type, the provider's event ID (the
// idempotency key, so a duplicate is explainable) and the outcome — never the
// signature header and never one byte of the raw body.
func (h *handlers) auditWebhook(r *http.Request, ev billing.Event, outcome string) {
	h.cfg.Logger.Info(auditEventBillingWebhook,
		"event", auditEventBillingWebhook,
		"request_id", RequestIDFromContext(r.Context()),
		"provider", ev.Provider,
		"event_type", string(ev.Type),
		"event_id", ev.ID,
		"outcome", outcome,
	)
}

// auditWebhookRejected logs a webhook we would not act on. reason is a fixed
// enum naming which class of check failed; it is surfaced ONLY here and in the
// per-reason metric, never in the HTTP response (the caller gets a coarse 401 or
// 400). The signature header, the secret and the raw body are never logged.
func (h *handlers) auditWebhookRejected(r *http.Request, provider, reason string) {
	h.cfg.Logger.Warn(auditEventBillingWebhookDenied,
		"event", auditEventBillingWebhookDenied,
		"request_id", RequestIDFromContext(r.Context()),
		"provider", provider,
		"reason", reason,
	)
}

// auditSubscriptionTransition logs a REAL subscription status change. It fires
// once per applied transition — never for a duplicate, stale or illegal
// delivery — so the audit trail is a faithful history of entitlement.
func (h *handlers) auditSubscriptionTransition(r *http.Request, provider, subject, from, to string) {
	h.cfg.Logger.Info(auditEventBillingTransition,
		"event", auditEventBillingTransition,
		"request_id", RequestIDFromContext(r.Context()),
		"provider", provider,
		"subject", subject,
		"from", from,
		"to", to,
	)
}

// auditHybridKeyPublished logs a device publishing (or re-publishing) its
// hybrid PUBLIC key. It records the device ID only. The key bytes are public,
// but they are still not logged: an audit line is not a key-distribution
// channel, and keeping the rule "no key material in logs" absolute means there
// is no judgement call to get wrong later.
func (h *handlers) auditHybridKeyPublished(r *http.Request, deviceID string) {
	h.cfg.Logger.Info(auditEventHybridKeyPublished,
		"event", auditEventHybridKeyPublished,
		"request_id", RequestIDFromContext(r.Context()),
		"device_id", deviceID,
	)
}

// auditKeyEnvelopePut logs an opaque wrapped-vault-key deposit. Exactly like
// auditAppend it records a hex SHA-256 FINGERPRINT of the blob and its size —
// never the bytes. The blob is ciphertext the server cannot read, and the
// fingerprint lets an operator correlate "the sender uploaded X" with "the
// recipient collected X" without the server ever retaining the ciphertext.
func (h *handlers) auditKeyEnvelopePut(r *http.Request, vaultID, recipientID, senderID string, blob []byte) {
	sum := sha256.Sum256(blob)
	h.cfg.Logger.Info(auditEventKeyEnvelopePut,
		"event", auditEventKeyEnvelopePut,
		"request_id", RequestIDFromContext(r.Context()),
		"vault_id", vaultID,
		"recipient_device_id", recipientID,
		"sender_device_id", senderID,
		"size_bytes", len(blob),
		"blob_sha256", hex.EncodeToString(sum[:]),
	)
}

// auditKeyEnvelopeGet logs a recipient collecting its envelope, with the same
// fingerprint-not-content rule as auditKeyEnvelopePut.
func (h *handlers) auditKeyEnvelopeGet(r *http.Request, vaultID, recipientID string, blob []byte) {
	sum := sha256.Sum256(blob)
	h.cfg.Logger.Info(auditEventKeyEnvelopeGet,
		"event", auditEventKeyEnvelopeGet,
		"request_id", RequestIDFromContext(r.Context()),
		"vault_id", vaultID,
		"recipient_device_id", recipientID,
		"size_bytes", len(blob),
		"blob_sha256", hex.EncodeToString(sum[:]),
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

// auditKeyEnvelopeList logs a vault owner enumerating which devices hold a
// wrapped key (Phase 50 rotation support). Counts and device IDs only — the
// route never touches a blob, so there is nothing to fingerprint.
func (h *handlers) auditKeyEnvelopeList(r *http.Request, vaultID, callerID string, count int) {
	h.cfg.Logger.Info(auditEventKeyEnvelopeList,
		"event", auditEventKeyEnvelopeList,
		"request_id", RequestIDFromContext(r.Context()),
		"vault_id", vaultID,
		"device_id", callerID,
		"returned_count", count,
	)
}

// auditKeyEnvelopeDelete logs an owner removing a device's envelope during a
// rotation. It records WHO removed WHOSE envelope; there is no blob to
// fingerprint because the route deletes without reading one.
func (h *handlers) auditKeyEnvelopeDelete(r *http.Request, vaultID, recipientID, callerID string) {
	h.cfg.Logger.Info(auditEventKeyEnvelopeDelete,
		"event", auditEventKeyEnvelopeDelete,
		"request_id", RequestIDFromContext(r.Context()),
		"vault_id", vaultID,
		"recipient_device_id", recipientID,
		"device_id", callerID,
	)
}
