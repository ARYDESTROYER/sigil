package api

// HTTP surface for the multi-device auth model (Phase 41):
//
//	POST /v1/devices/enroll             enroll a device (token + proof of possession)
//	GET  /v1/devices                    list devices (operator admin token)
//	POST /v1/devices/{deviceID}/revoke  revoke a device (self, v3-signed, or admin)
//	POST /v1/vaults/{vaultID}/grants    grant another device access (vault owner)
//	GET  /v1/vaults/{vaultID}/grants    list a vault's grants (any authorized device)
//
// ALL of these are DEV-GATED exactly like the ops routes: with
// SIGILD_ENABLE_DEV_OPS unset (or the device model unconfigured) every one of
// them returns 501, never 404 and never a partial implementation.
//
// ZERO-KNOWLEDGE: these endpoints deal only in auth metadata. No handler here
// reads, writes, or touches a vault blob.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

// maxDeviceBodyBytes caps the JSON bodies of the device routes. They are tiny
// (a base64 key plus a label), so a small cap is generous and bounds the work an
// unauthenticated enrollment attempt can cause.
const maxDeviceBodyBytes = 8 << 10 // 8 KiB

// maxDeviceLabelLen bounds the human label stored with a device, so a caller
// cannot use the registry as a blob store.
const maxDeviceLabelLen = 128

// deviceNotImplemented is the deliberate 501 for every device route when the
// device model is not enabled (dev-ops off, or no registry configured). We
// return 501 rather than 404 so the surface is discoverable and unambiguous, and
// rather than any partial/faked auth behaviour.
func (h *handlers) deviceNotImplemented(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		_, _ = io.Copy(io.Discard, r.Body)
	}
	writeJSON(w, http.StatusNotImplemented, apiError{
		Error:  "not_implemented",
		Detail: "device enrollment, per-vault authorization and vault sharing are not enabled on this server",
	})
}

// enrollRequest is the JSON body of POST /v1/devices/enroll.
type enrollRequest struct {
	// PublicKey is the standard-base64 encoding of a raw 32-byte Ed25519 public
	// key — the key this device will sign its future requests with.
	PublicKey string `json:"public_key"`
	// Label is a human-readable device name (optional, bounded).
	Label string `json:"label"`
}

// deviceJSON is the wire shape of a device. It deliberately OMITS the public key
// (the client already has it) so the registry never echoes key material back out
// of an endpoint that is not strictly required to.
type deviceJSON struct {
	DeviceID  string `json:"device_id"`
	Label     string `json:"label"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	RevokedAt string `json:"revoked_at,omitempty"`
}

// toDeviceJSON renders a stored device for the wire.
func toDeviceJSON(d store.Device) deviceJSON {
	out := deviceJSON{
		DeviceID:  d.ID,
		Label:     d.Label,
		Status:    string(d.Status),
		CreatedAt: d.CreatedAt.UTC().Format(time.RFC3339),
	}
	if !d.RevokedAt.IsZero() {
		out.RevokedAt = d.RevokedAt.UTC().Format(time.RFC3339)
	}
	return out
}

// denyEnroll records an enrollment denial (audit + metric) and writes the coarse
// response. Every credential failure — bad token, spent token, expired token,
// bad proof — returns the SAME 401 body, so a prober cannot distinguish them.
func (h *handlers) denyEnroll(w http.ResponseWriter, r *http.Request, reason authReason) {
	h.auditEnrollDenied(r, reason)
	h.metrics.incEnrollDenied(reason)
	switch reason {
	case reasonMalformedKey:
		writeError(w, http.StatusBadRequest, "invalid_request",
			"public_key must be the standard-base64 encoding of a 32-byte Ed25519 public key")
	case reasonDeviceExists:
		writeError(w, http.StatusConflict, "device_exists",
			"that public key is already enrolled")
	case reasonStoreUnavailable:
		writeError(w, http.StatusInternalServerError, "internal", "")
	default:
		writeError(w, http.StatusUnauthorized, "unauthorized",
			"enrollment requires a valid, unused enrollment token and proof of key possession")
	}
}

// devicesEnroll registers a new device's Ed25519 public key and returns its
// server-assigned device ID.
//
// AUTHENTICATION IS TWO INDEPENDENT FACTORS, both mandatory:
//
//  1. an operator-provisioned ENROLLMENT TOKEN (X-Sigil-Enroll-Token), matched
//     in constant time against the configured digests and then SPENT atomically
//     in the registry — a token is SINGLE-USE and can never be silently reused;
//  2. PROOF OF POSSESSION: the request carries an Ed25519 signature over the
//     canonical enrollment challenge (see canonicalEnrollMessage), verified
//     against the public key being submitted. A bare public-key upload is NEVER
//     accepted.
//
// The v2/v3 replay protections apply here too: a 300 s timestamp window and a
// per-request nonce checked against the shared replay cache.
//
// The token is spent BEFORE the device row is created, so a token is consumed
// even if the subsequent insert conflicts. That is deliberate: single-use means
// single-ATTEMPT, and an operator issues a new token rather than the server
// silently allowing a retry.
func (h *handlers) devicesEnroll(w http.ResponseWriter, r *http.Request) {
	// 1) Contract headers must all be present.
	tokenHeader := r.Header.Get(headerEnrollToken)
	tsHeader := r.Header.Get(headerTimestamp)
	nonceHeader := r.Header.Get(headerNonce)
	sigHeader := r.Header.Get(headerSignature)
	if tokenHeader == "" || tsHeader == "" || nonceHeader == "" || sigHeader == "" {
		h.denyEnroll(w, r, reasonMissingHeaders)
		return
	}

	// 2) Body: small, well-formed JSON.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxDeviceBodyBytes+1))
	if err != nil || len(body) > maxDeviceBodyBytes {
		writeError(w, http.StatusBadRequest, "invalid_request", "could not read request body")
		return
	}
	var req enrollRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "body must be a JSON object")
		return
	}
	if len(req.Label) > maxDeviceLabelLen {
		writeError(w, http.StatusBadRequest, "invalid_request", "label is too long")
		return
	}

	// 3) The submitted key must be a well-formed 32-byte Ed25519 public key.
	pub, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil || len(pub) != 32 {
		h.denyEnroll(w, r, reasonMalformedKey)
		return
	}

	// 4) Timestamp window (same bound as the request-auth contract).
	ts, now, ok := parseTimestampWindow(tsHeader)
	if !ok {
		h.denyEnroll(w, r, reasonStaleTimestamp)
		return
	}

	// 5) The enrollment token must be one this server was provisioned with.
	//    Compared in constant time against the configured DIGESTS; the plaintext
	//    token is never stored or logged.
	tokenHash := hashEnrollToken(tokenHeader)
	if !matchesConfiguredToken(h.cfg.EnrollTokenHashes, tokenHash) {
		h.denyEnroll(w, r, reasonBadEnrollToken)
		return
	}

	// 6) PROOF OF POSSESSION — verify the signature with the SUBMITTED key.
	msg := canonicalEnrollMessage(tokenHash, tsHeader, nonceHeader, req.PublicKey, req.Label)
	sig, err := base64.StdEncoding.DecodeString(sigHeader)
	if err != nil || !ed25519Verify(pub, msg, sig) {
		h.denyEnroll(w, r, reasonBadProof)
		return
	}

	// 7) Replay: only after a valid proof, so probes cannot populate the cache.
	if h.nonces != nil && h.nonces.checkAndRecord(enrollNoncePrefix+nonceHeader, ts, now) {
		h.denyEnroll(w, r, reasonReplayed)
		return
	}

	// 8) Spend the token ATOMICALLY, then create the device.
	deviceID, err := store.NewDeviceID()
	if err != nil {
		h.denyEnroll(w, r, reasonStoreUnavailable)
		return
	}
	nowT := time.Now().UTC()
	switch err := h.devices.ConsumeEnrollmentToken(r.Context(), tokenHash, deviceID, nowT); {
	case err == nil:
	case errors.Is(err, store.ErrEnrollTokenUsed):
		h.denyEnroll(w, r, reasonEnrollTokenUsed)
		return
	case errors.Is(err, store.ErrEnrollTokenExpired):
		h.denyEnroll(w, r, reasonEnrollTokenExpired)
		return
	case errors.Is(err, store.ErrEnrollTokenUnknown):
		h.denyEnroll(w, r, reasonBadEnrollToken)
		return
	default:
		h.denyEnroll(w, r, reasonStoreUnavailable)
		return
	}

	dev := store.Device{
		ID:        deviceID,
		PublicKey: pub,
		Label:     req.Label,
		Status:    store.DeviceActive,
		CreatedAt: nowT,
	}
	if err := h.devices.CreateDevice(r.Context(), dev); err != nil {
		if errors.Is(err, store.ErrDeviceExists) {
			h.denyEnroll(w, r, reasonDeviceExists)
			return
		}
		h.denyEnroll(w, r, reasonStoreUnavailable)
		return
	}

	h.auditEnrolled(r, dev)
	h.metrics.incEnrollment()
	writeJSON(w, http.StatusCreated, toDeviceJSON(dev))
}

// devicesList returns every registered device. It requires the OPERATOR admin
// token (SIGILD_ADMIN_TOKEN); with no admin token configured the route is
// permanently unauthorized — there is no open-admin mode. Public keys are NOT
// included in the response.
func (h *handlers) devicesList(w http.ResponseWriter, r *http.Request) {
	if !h.checkAdminToken(r) {
		h.denyOps(w, r, "", authOutcome{Reason: reasonBadAdminToken})
		return
	}
	devs, err := h.devices.ListDevices(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	out := make([]deviceJSON, 0, len(devs))
	for _, d := range devs {
		out = append(out, toDeviceJSON(d))
	}
	writeJSON(w, http.StatusOK, struct {
		Devices []deviceJSON `json:"devices"`
	}{Devices: out})
}

// devicesRevoke revokes a device. A revoked device is rejected on its very next
// request (authenticateDevice checks status before verifying the signature).
//
// TWO authorized paths, both real, neither a bypass:
//
//   - the OPERATOR admin token (X-Sigil-Admin-Token), which may revoke ANY
//     device — this is the break-glass path for a lost/stolen device; or
//   - SELF-REVOCATION: a valid v3-signed request whose signing device IS the
//     device being revoked. A device may retire itself; it may NOT revoke
//     another device.
//
// Revocation is idempotent: revoking an already-revoked device succeeds without
// changing its original revoked_at.
func (h *handlers) devicesRevoke(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("deviceID")
	if targetID == "" {
		writeError(w, http.StatusBadRequest, "missing_device_id", "device ID is required")
		return
	}
	// Drain any body so it is part of nothing and cannot linger.
	body, err := io.ReadAll(io.LimitReader(r.Body, maxDeviceBodyBytes+1))
	if err != nil || len(body) > maxDeviceBodyBytes {
		writeError(w, http.StatusBadRequest, "invalid_request", "could not read request body")
		return
	}

	revokedBy := "admin"
	if !h.checkAdminToken(r) {
		// Not the operator: require a valid v3 signature from the target device.
		dev, out := h.authenticateDevice(r, body)
		if !out.allowed() {
			h.denyOps(w, r, "", out)
			return
		}
		if dev.ID != targetID {
			// Authenticated, but not permitted to revoke someone else -> 403.
			h.denyOps(w, r, "", authOutcome{Reason: reasonForbiddenDevice, DeviceID: dev.ID})
			return
		}
		revokedBy = dev.ID
	}

	if err := h.devices.RevokeDevice(r.Context(), targetID, time.Now().UTC()); err != nil {
		if errors.Is(err, store.ErrDeviceNotFound) {
			writeError(w, http.StatusNotFound, "device_not_found", "no such device")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	h.auditDeviceRevoked(r, targetID, revokedBy)
	h.metrics.incRevocation()
	writeJSON(w, http.StatusOK, struct {
		DeviceID string `json:"device_id"`
		Status   string `json:"status"`
	}{DeviceID: targetID, Status: string(store.DeviceRevoked)})
}

// grantRequest is the JSON body of POST /v1/vaults/{vaultID}/grants.
type grantRequest struct {
	DeviceID   string `json:"device_id"`
	Permission string `json:"permission"` // "read" | "write"
}

// grantJSON is the wire shape of one grant.
type grantJSON struct {
	DeviceID   string `json:"device_id"`
	Permission string `json:"permission"`
	Owner      bool   `json:"owner"`
	CreatedAt  string `json:"created_at"`
}

// vaultGrantCreate grants another enrolled device access to a vault. The
// requesting device must be the vault's OWNER (the device that claimed it on
// first write); any other authorized device gets 403. The grantee must be an
// enrolled, non-revoked device.
func (h *handlers) vaultGrantCreate(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")
	if vaultID == "" {
		writeError(w, http.StatusBadRequest, "missing_vault_id", "vault ID is required")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxDeviceBodyBytes+1))
	if err != nil || len(body) > maxDeviceBodyBytes {
		writeError(w, http.StatusBadRequest, "invalid_request", "could not read request body")
		return
	}
	// Signature covers the body, so authenticate/authorize AFTER reading it.
	if out := h.authorizeOpsRequest(r, body, vaultID, needOwner); !out.allowed() {
		h.denyOps(w, r, vaultID, out)
		return
	}

	var req grantRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "body must be a JSON object")
		return
	}
	if req.DeviceID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "device_id is required")
		return
	}
	perm := store.Permission(req.Permission)
	if !store.ValidPermission(perm) {
		writeError(w, http.StatusBadRequest, "invalid_request", `permission must be "read" or "write"`)
		return
	}
	// The grantee must exist and be active — a grant to an unknown or revoked
	// device is refused rather than silently recorded.
	grantee, err := h.devices.GetDevice(r.Context(), req.DeviceID)
	if err != nil {
		if errors.Is(err, store.ErrDeviceNotFound) {
			writeError(w, http.StatusNotFound, "device_not_found", "no such device")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	if !grantee.Active() {
		writeError(w, http.StatusConflict, "device_revoked", "cannot grant access to a revoked device")
		return
	}

	at := time.Now().UTC()
	if err := h.devices.PutGrant(r.Context(), vaultID, req.DeviceID, perm, at); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	h.auditGrant(r, vaultID, req.DeviceID, string(perm))
	h.metrics.incGrant()
	writeJSON(w, http.StatusCreated, grantJSON{
		DeviceID:   req.DeviceID,
		Permission: string(perm),
		Owner:      false,
		CreatedAt:  at.Format(time.RFC3339),
	})
}

// vaultGrantList lists a vault's grants. Any device with READ access to the
// vault may see who else can reach it.
func (h *handlers) vaultGrantList(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")
	if vaultID == "" {
		writeError(w, http.StatusBadRequest, "missing_vault_id", "vault ID is required")
		return
	}
	if out := h.authorizeOpsRequest(r, nil, vaultID, needRead); !out.allowed() {
		h.denyOps(w, r, vaultID, out)
		return
	}
	grants, err := h.devices.ListGrants(r.Context(), vaultID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	out := make([]grantJSON, 0, len(grants))
	for _, g := range grants {
		out = append(out, grantJSON{
			DeviceID:   g.DeviceID,
			Permission: string(g.Perm),
			Owner:      g.Owner,
			CreatedAt:  g.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, struct {
		VaultID string      `json:"vaultID"`
		Grants  []grantJSON `json:"grants"`
	}{VaultID: vaultID, Grants: out})
}
