package api

// HTTP surface for DEVICE-TO-DEVICE VAULT SHARING (Phase 46):
//
//	PUT  /v1/devices/{deviceID}/hybrid-key    publish MY hybrid public key
//	GET  /v1/devices/{deviceID}/hybrid-key    fetch a device's hybrid public key
//	PUT  /v1/vaults/{vaultID}/keys/{deviceID} deposit an opaque wrapped vault key
//	GET  /v1/vaults/{vaultID}/keys/{deviceID} collect the envelope addressed to me
//
// DEV-GATED exactly like the ops and device routes: with SIGILD_ENABLE_DEV_OPS
// unset (or no device registry configured) all four return the deliberate 501.
//
// AUTHORIZATION RULES (all enforced through the EXISTING v3 choke points —
// authenticateDevice / authorizeVault / authorizeOpsRequest; there is no new
// auth path here):
//
//	publish key : authenticated device, and deviceID MUST be its OWN id (403
//	              otherwise). Revoked devices are rejected by authenticateDevice
//	              before anything else. Re-publishing is ALLOWED and is an upsert
//	              (see the note on rotation below).
//	fetch key   : any authenticated, active device may fetch any device's PUBLIC
//	              hybrid key. They are public keys; requiring authentication just
//	              stops the registry being world-enumerable.
//	put envelope: authenticated device with WRITE access to the vault. Writing an
//	              envelope to an UNOWNED vault CLAIMS it, exactly like appending
//	              the first op (trust-on-first-write) — the same rule, the same
//	              code path. A read-only grantee cannot deposit envelopes; a
//	              write-granted device can, which mirrors the fact that it can
//	              already write the vault's contents.
//	get envelope: authenticated device that IS the addressee AND holds READ access
//	              to the vault. Another device asking for someone else's envelope
//	              is 403 (authenticated but not permitted), never 401.
//
// ZERO-KNOWLEDGE: the server stores and returns the envelope bytes VERBATIM. It
// holds no decapsulation key, decodes nothing, and never sees a vault key or a
// plaintext. The hybrid public keys are validated for LENGTH ONLY — the server
// performs no cryptography on them. The audit log records a SHA-256 fingerprint
// of an envelope, never its bytes.
//
// HONEST SCOPE: dev-only, UNAUDITED. Revoking a device stops FUTURE access; it
// cannot un-learn a vault key the device already accepted (rotating a shared
// vault means re-keying it client-side and re-sharing). Republishing a hybrid
// key does not re-wrap already-delivered envelopes.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

// maxHybridKeyBodyBytes caps the hybrid-key publish body. The JSON carries two
// base64 fields (~44 and ~1580 bytes), so 8 KiB is generous and bounds the work
// an authenticated device can cause.
const maxHybridKeyBodyBytes = 8 << 10 // 8 KiB

// hybridKeyRequest is the JSON body of PUT /v1/devices/{deviceID}/hybrid-key.
// Both fields are standard-base64 of RAW public key bytes. The server decodes
// the base64 (a transport encoding) and checks the LENGTHS — it never
// interprets the key material itself.
type hybridKeyRequest struct {
	// X25519PublicKey is std-base64 of the raw 32-byte X25519 public key.
	X25519PublicKey string `json:"x25519_public_key"`
	// MLKEMEncapsKey is std-base64 of the raw 1184-byte ML-KEM-768 encapsulation
	// key.
	MLKEMEncapsKey string `json:"mlkem_encaps_key"`
}

// hybridKeyJSON is the wire shape of a published hybrid public key. Unlike the
// device routes (which deliberately never echo an Ed25519 signing key), this one
// MUST return key material: publishing it for other devices to fetch is the
// entire purpose of the endpoint, and it is a PUBLIC key.
type hybridKeyJSON struct {
	DeviceID        string `json:"device_id"`
	X25519PublicKey string `json:"x25519_public_key"`
	MLKEMEncapsKey  string `json:"mlkem_encaps_key"`
	UpdatedAt       string `json:"updated_at"`
}

// deviceHybridKeyPublish stores THIS device's hybrid public key.
//
// A device may publish only its OWN key: the path device ID must equal the
// authenticated device's ID, else 403. Revoked devices never get here
// (authenticateDevice rejects them before the signature is even checked).
//
// Re-publishing is ALLOWED and is an upsert — a device that regenerates its
// local hybrid identity republishes and future shares use the new key. It does
// NOT re-wrap envelopes already deposited for that device: those were sealed to
// the old key and must be re-shared.
func (h *handlers) deviceHybridKeyPublish(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("deviceID")
	if targetID == "" {
		writeError(w, http.StatusBadRequest, "missing_device_id", "device ID is required")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxHybridKeyBodyBytes+1))
	if err != nil || len(body) > maxHybridKeyBodyBytes {
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
			"hybrid key body exceeds the size limit")
		return
	}

	// The signature covers the body, so authenticate AFTER reading it.
	dev, out := h.authenticateDevice(r, body)
	if !out.allowed() {
		h.denyOps(w, r, "", out)
		return
	}
	if dev.ID != targetID {
		// Authenticated, but a device may not publish someone else's key.
		h.denyOps(w, r, "", authOutcome{Reason: reasonForbiddenDevice, DeviceID: dev.ID})
		return
	}

	var req hybridKeyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "body must be a JSON object")
		return
	}
	x25519, err1 := base64.StdEncoding.DecodeString(req.X25519PublicKey)
	mlkem, err2 := base64.StdEncoding.DecodeString(req.MLKEMEncapsKey)
	if err1 != nil || err2 != nil {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"x25519_public_key and mlkem_encaps_key must be standard-base64")
		return
	}

	key := store.HybridPublicKey{
		DeviceID:        dev.ID,
		X25519PublicKey: x25519,
		MLKEMEncapsKey:  mlkem,
		UpdatedAt:       time.Now().UTC(),
	}
	// LENGTH-ONLY validation. The server never parses these as curve points or
	// KEM keys — doing so would be performing cryptography on user key material.
	if err := store.ValidateHybridPublicKey(key); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"x25519_public_key must decode to 32 bytes and mlkem_encaps_key to 1184 bytes")
		return
	}

	if err := h.devices.PutDeviceHybridKey(r.Context(), key); err != nil {
		if errors.Is(err, store.ErrDeviceNotFound) {
			writeError(w, http.StatusNotFound, "device_not_found", "no such device")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	h.auditHybridKeyPublished(r, dev.ID)
	h.metrics.incHybridKeyPublish()
	writeJSON(w, http.StatusOK, hybridKeyJSON{
		DeviceID:        key.DeviceID,
		X25519PublicKey: req.X25519PublicKey,
		MLKEMEncapsKey:  req.MLKEMEncapsKey,
		UpdatedAt:       key.UpdatedAt.Format(time.RFC3339),
	})
}

// deviceHybridKeyFetch returns a device's published hybrid PUBLIC key so another
// device can wrap a vault key to it. Any authenticated, active device may fetch
// any device's key; 404 when that device has not published one.
func (h *handlers) deviceHybridKeyFetch(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("deviceID")
	if targetID == "" {
		writeError(w, http.StatusBadRequest, "missing_device_id", "device ID is required")
		return
	}
	if _, out := h.authenticateDevice(r, nil); !out.allowed() {
		h.denyOps(w, r, "", out)
		return
	}

	key, err := h.devices.GetDeviceHybridKey(r.Context(), targetID)
	if err != nil {
		if errors.Is(err, store.ErrHybridKeyNotFound) {
			writeError(w, http.StatusNotFound, "hybrid_key_not_found",
				"that device has not published a hybrid public key")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	writeJSON(w, http.StatusOK, hybridKeyJSON{
		DeviceID:        key.DeviceID,
		X25519PublicKey: base64.StdEncoding.EncodeToString(key.X25519PublicKey),
		MLKEMEncapsKey:  base64.StdEncoding.EncodeToString(key.MLKEMEncapsKey),
		UpdatedAt:       key.UpdatedAt.UTC().Format(time.RFC3339),
	})
}

// checkKeyEnvelopePut is the cheap, VAULT-INDEPENDENT shape validation of a
// key-envelope PUT: a non-empty body, and a recipient that is an enrolled, ACTIVE
// device (depositing a key for an unknown or revoked device is refused rather
// than silently stored). It returns (0, "", "") when the request is well-formed,
// otherwise the status/code/detail to answer with.
//
// It is factored out so it can serve as a claimPrecondition — evaluated before
// the trust-on-first-write claim — and then be REUSED to write the response,
// rather than existing twice and drifting.
func (h *handlers) checkKeyEnvelopePut(ctx context.Context, blob []byte, recipientID string) (int, string, string) {
	if len(blob) == 0 {
		return http.StatusBadRequest, "empty_envelope", "envelope body must not be empty"
	}
	recipient, err := h.devices.GetDevice(ctx, recipientID)
	if err != nil {
		if errors.Is(err, store.ErrDeviceNotFound) {
			return http.StatusNotFound, "device_not_found", "no such device"
		}
		return http.StatusInternalServerError, "internal", ""
	}
	if !recipient.Active() {
		return http.StatusConflict, "device_revoked",
			"cannot deposit a key envelope for a revoked device"
	}
	return 0, "", ""
}

// keyEnvelopePut deposits an OPAQUE wrapped vault key addressed to one device.
//
// The request body is the RAW envelope bytes (application/octet-stream) — the
// same "opaque bytes in, opaque bytes out" shape as an op-log append. The server
// never decodes it. Size is capped upstream by limitBody (oversized -> 413) and
// again in the store.
//
// AUTHORIZATION: WRITE on the vault, via the SAME authorizeOpsRequest choke point
// the op-log uses, so depositing the first envelope for an unowned vault claims
// it (trust-on-first-write) exactly as the first op append would.
func (h *handlers) keyEnvelopePut(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")
	recipientID := r.PathValue("deviceID")
	if vaultID == "" || recipientID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"vault ID and recipient device ID are required")
		return
	}

	blob, err := io.ReadAll(r.Body)
	if err != nil {
		if maxErr := (*http.MaxBytesError)(nil); errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				"request body exceeds the key-envelope size limit")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "could not read request body")
		return
	}

	// ⭐ THE CLAIM PRECONDITION (Phase 57), the same fix as opsAppend. Every check
	// below that can REJECT this request — an empty body, an unknown recipient, a
	// revoked recipient — is cheap and VAULT-INDEPENDENT, so it is evaluated as a
	// claim precondition: a PUT that is going to be refused must not take
	// ownership of an unowned vault on its way out. The verdict is memoised and
	// reused after authorization, so each check runs at most once and the response
	// ordering (auth -> entitlement -> shape) is unchanged.
	var rejStatus int
	var rejCode, rejDetail string
	rejChecked := false
	wellFormed := func() bool {
		if !rejChecked {
			rejStatus, rejCode, rejDetail = h.checkKeyEnvelopePut(r.Context(), blob, recipientID)
			rejChecked = true
		}
		return rejStatus == 0
	}

	// Signature covers the body, so authenticate/authorize AFTER reading it.
	dev, out := h.authorizeOpsWrite(r, blob, vaultID, wellFormed)
	if !out.allowed() {
		h.denyOps(w, r, vaultID, out)
		return
	}
	// ENTITLEMENT (Phase 55): depositing a NEW wrapped key is a write, so a
	// fully-lapsed account is refused with 402 after grace. ⭐ THE COLLECTING
	// SIDE — keyEnvelopeGet, and the per-device index — IS NEVER GATED, so a
	// customer who stopped paying can still fetch every key they were given and
	// therefore still open every vault they already hold. Off by default.
	//
	// ⭐ AND A DEPOSIT TO A DEVICE OF THE CALLER'S OWN ACCOUNT IS EXEMPT. That is
	// how a replacement device — or a recovery kit, which is an ordinary member
	// device — is given the key to data the customer ALREADY has. Refusing it
	// left a lapsed customer downloading ciphertext they could never decrypt,
	// which is not "reads are never refused" in any meaningful sense. Sharing to
	// ANOTHER account is still gated: that extends the product to somebody else.
	if !h.sameAccountRecipient(r.Context(), dev, recipientID) {
		if !h.requireEntitlement(w, r, dev, entitlementSurfaceKeyEnvelopePut) {
			return
		}
	}
	// The memoised shape verdict from above: an empty body (400), an unknown
	// recipient (404) or a revoked recipient (409). Already computed as the claim
	// precondition on the device-auth path; computed here on the legacy path,
	// which never claims anything.
	if !wellFormed() {
		writeError(w, rejStatus, rejCode, rejDetail)
		return
	}

	env := store.KeyEnvelope{
		VaultID:           vaultID,
		RecipientDeviceID: recipientID,
		SenderDeviceID:    out.DeviceID,
		Blob:              blob,
		CreatedAt:         time.Now().UTC(),
	}
	if err := h.devices.PutKeyEnvelope(r.Context(), env); err != nil {
		if errors.Is(err, store.ErrKeyEnvelopeMalformed) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				"envelope exceeds the key-envelope size limit")
			return
		}
		if errors.Is(err, store.ErrDeviceNotFound) {
			writeError(w, http.StatusNotFound, "device_not_found", "no such device")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	h.auditKeyEnvelopePut(r, vaultID, recipientID, out.DeviceID, blob)
	h.metrics.incKeyEnvelopePut()
	writeJSON(w, http.StatusCreated, struct {
		VaultID   string `json:"vaultID"`
		DeviceID  string `json:"device_id"`
		SizeBytes int    `json:"size_bytes"`
		CreatedAt string `json:"created_at"`
	}{
		VaultID:   vaultID,
		DeviceID:  recipientID,
		SizeBytes: len(blob),
		CreatedAt: env.CreatedAt.Format(time.RFC3339),
	})
}

// keyEnvelopeGet returns the OPAQUE envelope addressed to the calling device,
// byte-for-byte as it was uploaded, as application/octet-stream.
//
// ONLY the addressee may collect it: an authenticated device asking for another
// device's envelope gets 403 (forbidden), never 401 — it authenticated fine, it
// is simply not the recipient. The caller must ALSO hold read access to the
// vault, so an envelope cannot outlive a revoked grant.
func (h *handlers) keyEnvelopeGet(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")
	recipientID := r.PathValue("deviceID")
	if vaultID == "" || recipientID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"vault ID and recipient device ID are required")
		return
	}

	dev, out := h.authenticateDevice(r, nil)
	if !out.allowed() {
		h.denyOps(w, r, vaultID, out)
		return
	}
	if dev.ID != recipientID {
		// Authenticated, but this envelope is addressed to someone else.
		h.denyOps(w, r, vaultID, authOutcome{Reason: reasonForbiddenDevice, DeviceID: dev.ID})
		return
	}
	if vout := h.authorizeVault(r, dev, vaultID, needRead); !vout.allowed() {
		h.denyOps(w, r, vaultID, vout)
		return
	}

	env, err := h.devices.GetKeyEnvelope(r.Context(), vaultID, recipientID)
	if err != nil {
		if errors.Is(err, store.ErrKeyEnvelopeNotFound) {
			writeError(w, http.StatusNotFound, "envelope_not_found",
				"no key envelope is addressed to this device for that vault")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	h.auditKeyEnvelopeGet(r, vaultID, recipientID, env.Blob)
	h.metrics.incKeyEnvelopeGet()

	// Return the EXACT stored bytes. No re-encoding, no framing, no JSON: what
	// the sender uploaded is what the recipient receives.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(env.Blob)
}

// ---------------------------------------------------------------------------
// Rotation support (Phase 50): list + delete key envelopes.
//
// WHY THE SERVER NEEDS THESE AT ALL. A client rotating a vault key re-wraps the
// NEW key to the devices that are still authorized, and must make sure the
// devices it is rotating AWAY from cannot collect anything. Re-wrapping alone is
// not enough: a removed device's OLD envelope would sit in its mailbox forever.
// The client therefore needs to (a) see which devices hold an envelope and
// (b) remove the ones it did not re-wrap to.
//
// THE AUTHORIZATION RULE, stated once: BOTH routes require WRITE access to the
// vault, enforced by the EXISTING authorizeOpsRequest choke point — the same one
// that authorizes depositing an envelope and appending an op. That is the right
// bar: a device that can deposit an envelope can already replace any envelope in
// the vault, so being able to enumerate and delete them grants no new power. A
// read-only grantee gets 403. An unauthenticated caller gets 401. Both are
// dev-gated with everything else (501 when the device model is off).
//
// ZERO-KNOWLEDGE UNCHANGED: the list route returns METADATA ONLY — recipient
// device id, sender device id, blob SIZE and timestamp. It never returns a blob,
// so it cannot be used to bulk-download ciphertext, and the server still decodes
// nothing.
//
// HONEST LIMIT: deleting an envelope stops a device collecting the key in
// FUTURE. It cannot make a device forget a key it already unwrapped.
// ---------------------------------------------------------------------------

// keyEnvelopeRecipientJSON is one row of the envelope listing. Metadata only.
type keyEnvelopeRecipientJSON struct {
	DeviceID       string `json:"device_id"`
	SenderDeviceID string `json:"sender_device_id"`
	SizeBytes      int    `json:"size_bytes"`
	CreatedAt      string `json:"created_at"`
}

// keyEnvelopeList reports which devices currently hold a wrapped vault key for
// this vault. Requires WRITE on the vault (an owner-side operation).
func (h *handlers) keyEnvelopeList(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")
	if vaultID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "vault ID is required")
		return
	}

	out := h.authorizeOpsRequest(r, nil, vaultID, needWriteNoClaim)
	if !out.allowed() {
		h.denyOps(w, r, vaultID, out)
		return
	}

	metas, err := h.devices.ListKeyEnvelopeRecipients(r.Context(), vaultID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	recipients := make([]keyEnvelopeRecipientJSON, 0, len(metas))
	for _, m := range metas {
		recipients = append(recipients, keyEnvelopeRecipientJSON{
			DeviceID:       m.RecipientDeviceID,
			SenderDeviceID: m.SenderDeviceID,
			SizeBytes:      m.SizeBytes,
			CreatedAt:      m.CreatedAt.Format(time.RFC3339),
		})
	}
	h.auditKeyEnvelopeList(r, vaultID, out.DeviceID, len(recipients))
	writeJSON(w, http.StatusOK, struct {
		VaultID    string                     `json:"vaultID"`
		Recipients []keyEnvelopeRecipientJSON `json:"recipients"`
	}{VaultID: vaultID, Recipients: recipients})
}

// ---------------------------------------------------------------------------
// Recovery support (Phase 54): the per-DEVICE envelope index.
//
//	GET /v1/devices/{deviceID}/keys
//
// WHY THE SERVER NEEDS THIS AT ALL. A client restored from a RECOVERY KIT — a
// printed 32-byte secret from which its Ed25519 and hybrid keys are re-derived —
// starts with NO local state whatsoever, so it knows no vault ids. Printing them
// on the sheet would go stale the instant a vault is created. The same hole
// exists (less dramatically) for any device that joined an account by invite.
//
// WHY IT GRANTS NOTHING NEW. The server already holds every one of these vault
// ids — they are in the path of every request the caller makes — and the caller
// could already collect each envelope one at a time by naming its vault. This
// route only removes the need to guess. Its net new capability is ~zero, which
// is exactly why it is acceptable.
//
// THE THREE RULES, all reusing existing choke points verbatim:
//
//	SELF-ONLY   deviceID != the AUTHENTICATED device => 403 forbidden_device,
//	            checked BEFORE any store read. Byte-identical to the addressee
//	            check in keyEnvelopeGet.
//	READ AUTHZ  every row is filtered through authorizeVault(needRead), so an
//	            envelope for a vault the caller no longer holds read on is not
//	            listed. needRead NEVER CLAIMS an unowned vault (the Phase 51
//	            rule), so listing can never take ownership of anything.
//	METADATA    the handler never calls GetKeyEnvelope. Postgres selects
//	            octet_length(blob), so no ciphertext leaves the database.
//
// NO MIGRATION was needed: the index sigil_vault_key_envelopes_by_recipient from
// 0004_key_sharing.sql was created for precisely this query, so
// sigild_schema_version stays 5.
// ---------------------------------------------------------------------------

// maxRecipientIndexRows caps one page of the per-device envelope index. A device
// with more covered vaults than this gets has_more=true; there is still no
// cursor.
//
// ⚠️ THE ORIGINAL JUSTIFICATION FOR HAVING NO CURSOR WAS "the realistic count is
// single digits and a cursor would be dead code". THAT PREMISE IS FALSE, and it
// was disproved by measurement in Phase 64 (ADR 0052): the count is not the
// user's, it is an ATTACKER'S. Any account may deposit an opaque envelope
// addressed to a device id it knows and then grant that device `read` on a vault
// it claimed itself — trust-on-first-write places no cap on how many vaults one
// account may own — so a third party fills this page at will. Reproduced against
// a real server: 520 vaults in 0.6 s with junk bytes, ~3 s when every envelope is genuine and authenticated pushed a genuine row off the listing.
//
// ⭐ THE FIX IS DELIBERATELY NOT HERE, and that is a decision rather than an
// omission. A cursor does not help: the flooder simply bloats what must be paged
// through, on a client that by construction has no local state and no way to
// know when to stop. Capping the SCAN is worse than the disease — an
// unauthorized row is `continue`d WITHOUT consuming the row budget, so a scan cap
// would let an attacker who deposits and grants NOTHING push genuine rows past
// the cap, turning a slow-but-CORRECT listing into an empty one: an ADR 0041
// mistake exactly, a protective bound that breaks the legitimate path. Ordering
// the caller's own account first only half-closes it (a cross-account-covered
// vault stays crowdable) and no client could rely on it without a version marker.
//
// So the duty moved to the CLIENT, where the information to settle it already
// exists: the PRINTED RECOVERY SHEET carries the covered vault ids, and a restore
// given those ids asks each VAULT directly — `GET /v1/vaults/{id}/keys` and
// `GET /v1/vaults/{id}/keys/{deviceID}`, both addressed BY VAULT ID, with nothing
// for a flood to crowd out. Given no ids and has_more=true a client REFUSES,
// rather than reporting a partial recovery as a complete one.
//
// ⚠️ WHAT REMAINS OPEN, so none of the above reads as a clean bill of health: an
// unauthorized row still costs a store round trip and neither consumes the row
// budget nor ends the loop, and ListKeyEnvelopesForRecipient has no LIMIT — so a
// stranger who deposits envelopes and grants NOTHING makes this handler scan
// without bound. That is a LATENCY denial on one route, not a crowd-out (the
// listing it returns stays correct and complete), it is PRE-EXISTING, and
// bounding it correctly means pushing the authorization filter into the query
// rather than bolting a cap on top. Recorded in ADR 0052 and the threat model;
// not fixed here.
const maxRecipientIndexRows = 500

// recipientVaultJSON is one row of the per-device envelope index. Metadata only.
type recipientVaultJSON struct {
	VaultID        string `json:"vaultID"`
	SenderDeviceID string `json:"sender_device_id"`
	SizeBytes      int    `json:"size_bytes"`
	CreatedAt      string `json:"created_at"`
}

// deviceKeyEnvelopeIndex reports which vaults have a wrapped key waiting for the
// CALLING device. Self-only, read-authorized, metadata-only.
func (h *handlers) deviceKeyEnvelopeIndex(w http.ResponseWriter, r *http.Request) {
	targetID := r.PathValue("deviceID")
	if targetID == "" {
		writeError(w, http.StatusBadRequest, "missing_device_id", "device ID is required")
		return
	}

	dev, out := h.authenticateDevice(r, nil)
	if !out.allowed() {
		h.denyOps(w, r, "", out)
		return
	}
	// SELF-ONLY, and decided before the store is touched: a device may ask what
	// is addressed to IT, never what is addressed to anyone else.
	if dev.ID != targetID {
		h.denyOps(w, r, "", authOutcome{Reason: reasonForbiddenDevice, DeviceID: dev.ID})
		return
	}

	metas, err := h.devices.ListKeyEnvelopesForRecipient(r.Context(), dev.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}

	vaults := make([]recipientVaultJSON, 0, len(metas))
	hasMore := false
	for _, m := range metas {
		// Per-vault READ authorization, one row at a time. needRead never
		// claims, so enumerating cannot take ownership of an unowned vault.
		if vout := h.authorizeVault(r, dev, m.VaultID, needRead); !vout.allowed() {
			continue
		}
		if len(vaults) >= maxRecipientIndexRows {
			hasMore = true
			break
		}
		vaults = append(vaults, recipientVaultJSON{
			VaultID:        m.VaultID,
			SenderDeviceID: m.SenderDeviceID,
			SizeBytes:      m.SizeBytes,
			CreatedAt:      m.CreatedAt.Format(time.RFC3339),
		})
	}

	h.auditKeyEnvelopeIndex(r, dev.ID, len(vaults))
	h.metrics.incKeyEnvelopeIndex()
	writeJSON(w, http.StatusOK, struct {
		DeviceID string               `json:"device_id"`
		Vaults   []recipientVaultJSON `json:"vaults"`
		HasMore  bool                 `json:"has_more"`
	}{DeviceID: dev.ID, Vaults: vaults, HasMore: hasMore})
}

// keyEnvelopeDelete removes the envelope addressed to one device, so a device
// rotated away from a vault cannot collect the NEW key. Requires WRITE on the
// vault. 404 when there was nothing there — a rotation treats that as "already
// in the desired state".
func (h *handlers) keyEnvelopeDelete(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")
	recipientID := r.PathValue("deviceID")
	if vaultID == "" || recipientID == "" {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"vault ID and recipient device ID are required")
		return
	}

	out := h.authorizeOpsRequest(r, nil, vaultID, needWriteNoClaim)
	if !out.allowed() {
		h.denyOps(w, r, vaultID, out)
		return
	}

	if err := h.devices.DeleteKeyEnvelope(r.Context(), vaultID, recipientID); err != nil {
		if errors.Is(err, store.ErrKeyEnvelopeNotFound) {
			writeError(w, http.StatusNotFound, "envelope_not_found",
				"no key envelope is addressed to that device for this vault")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	h.auditKeyEnvelopeDelete(r, vaultID, recipientID, out.DeviceID)
	h.metrics.incKeyEnvelopeDelete()
	writeJSON(w, http.StatusOK, struct {
		VaultID  string `json:"vaultID"`
		DeviceID string `json:"device_id"`
		Deleted  bool   `json:"deleted"`
	}{VaultID: vaultID, DeviceID: recipientID, Deleted: true})
}
