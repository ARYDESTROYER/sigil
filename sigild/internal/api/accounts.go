package api

// HTTP surface for the ACCOUNT model (Phase 52, ADR 0040):
//
//	GET  /v1/account                            who is in MY account
//	POST /v1/account/invites                    mint a single-use invite
//	GET  /v1/account/invites                    list MY account's open invites
//	POST /v1/account/invites/{inviteID}/revoke  revoke one before it is used
//
// DEV-GATED exactly like the ops, device and billing routes: with
// SIGILD_ENABLE_DEV_OPS unset — or no device registry configured — every one of
// them returns 501, never 404 and never a partial implementation.
//
// THE STRUCTURAL RULE THAT CLOSES EVERY CROSS-ACCOUNT IDOR: no path, no query
// parameter and no body field anywhere names an account. The account is ALWAYS
// dev.AccountID, taken from the device row of the signature the server just
// verified. There is therefore no request a client can construct that reads or
// writes another account's state — not by guessing an ID, because there is
// nowhere to put one.
//
// All four routes reuse the EXISTING device-auth v3 choke point
// (authenticateDevice) verbatim. There is no new signed-message domain, no new
// header, no second auth path.
//
// AUTH METADATA ONLY, ZERO-KNOWLEDGE UNCHANGED: no handler here reads, writes or
// touches a vault blob, and membership confers AUTHORIZATION, never DECRYPTION —
// a joined device can authenticate and see its entitlement, and can read nothing
// until an existing member wraps the vault key to its hybrid public key.

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

// Account-model defaults. These are the fallbacks a zero-valued Config uses, so
// a router built without them behaves sensibly.
//
// The RANGES an operator may configure (and the rejection of anything outside
// them) live in cmd/server, which validates fail-fast BEFORE the listener binds.
// Only the defaults are duplicated here, and cmd/server's copies carry the same
// values — keep the two in sync if either moves.
const (
	defaultAccountMaxDevices = 10
	defaultAccountMaxInvites = 5
	defaultAccountInviteTTL  = 15 * time.Minute
)

// maxAccountBodyBytes caps the JSON body of the invite-mint route. It carries at
// most an integer and a base64 public key, so a small cap is generous.
const maxAccountBodyBytes = 8 << 10 // 8 KiB

// inviteSecretBytes is the entropy behind an invite secret: 32 bytes (256 bits)
// of crypto/rand. An unpinned invite is a BEARER SECRET for its TTL, so it is
// sized as one.
const inviteSecretBytes = 32

// inviteSecretPrefix makes an invite obvious in a paste buffer (and obviously
// not an operator token).
const inviteSecretPrefix = "join_"

// inviteIDBytes / inviteIDPrefix produce the PUBLIC invite handle used for
// listing and revocation, so no endpoint ever echoes the redemption digest.
const (
	inviteIDBytes  = 12
	inviteIDPrefix = "inv_"
)

// accountNotImplemented is the deliberate 501 for every account route when the
// account model is not enabled (dev-ops off, or no registry configured). It is a
// SEPARATE handler from deviceNotImplemented — not a reuse — because its detail
// string names this surface, and existing tests assert the device stub's text.
func (h *handlers) accountNotImplemented(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		_, _ = io.Copy(io.Discard, r.Body)
	}
	writeJSON(w, http.StatusNotImplemented, apiError{
		Error:  "not_implemented",
		Detail: "the account model (membership and invites) is not enabled on this server",
	})
}

// accountMaxDevices is the effective per-account member cap.
func (h *handlers) accountMaxDevices() int {
	if h.cfg.AccountMaxDevices > 0 {
		return h.cfg.AccountMaxDevices
	}
	return defaultAccountMaxDevices
}

// accountMaxInvites is the effective per-account OPEN-invite cap.
func (h *handlers) accountMaxInvites() int {
	if h.cfg.AccountMaxInvites > 0 {
		return h.cfg.AccountMaxInvites
	}
	return defaultAccountMaxInvites
}

// accountInviteTTL is the effective invite lifetime.
func (h *handlers) accountInviteTTL() time.Duration {
	if h.cfg.AccountInviteTTL > 0 {
		return h.cfg.AccountInviteTTL
	}
	return defaultAccountInviteTTL
}

// newInviteSecret returns a fresh invite secret. It is SERVER-generated (never
// client-supplied), returned exactly ONCE in the 201 that mints it, and stored
// only as its SHA-256 digest.
func newInviteSecret() (string, error) {
	raw := make([]byte, inviteSecretBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return inviteSecretPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// newInviteID returns a fresh PUBLIC invite handle.
func newInviteID() (string, error) {
	raw := make([]byte, inviteIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return inviteIDPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// authenticateAccountRequest is the shared preamble for the account routes: read
// the (optional) body, verify the v3 signature over it, and resolve the caller's
// account — failing CLOSED with a 403 when the device carries none.
//
// A device with no account is a DATA state the server can plainly see (a device
// enrolled by a pre-0005 binary during a rollback), not a server fault, so it is
// refused as forbidden rather than reported as a 500. The coarse body is
// byte-identical to every other 403; the typed reason reaches only the audit log.
// `sigild migrate adopt` is the operator repair path.
//
// It returns ok=false having already written the response.
func (h *handlers) authenticateAccountRequest(w http.ResponseWriter, r *http.Request, body []byte) (store.Device, bool) {
	dev, out := h.authenticateDevice(r, body)
	if !out.allowed() {
		h.denyOps(w, r, "", out)
		return store.Device{}, false
	}
	if dev.AccountID == "" {
		h.denyOps(w, r, "", authOutcome{Reason: reasonMissingAccount, DeviceID: dev.ID})
		return store.Device{}, false
	}
	return dev, true
}

// accountResponse is the caller's own account. It lists MEMBERS ONLY — there is
// no route that lists another account, and none that enumerates accounts.
//
// DeviceCount COUNTS ACTIVE DEVICES ONLY, because that is what DeviceLimit
// bounds: the cap is on CONCURRENT devices, so a revoked device frees its seat.
// RevokedDeviceCount reports the rest separately rather than folding history
// into the limit — Devices still lists both, so nothing is hidden.
type accountResponse struct {
	AccountID          string       `json:"account_id"`
	CreatedAt          string       `json:"created_at,omitempty"`
	DeviceCount        int          `json:"device_count"`
	RevokedDeviceCount int          `json:"revoked_device_count"`
	DeviceLimit        int          `json:"device_limit"`
	Devices            []deviceJSON `json:"devices"`
}

// accountGet returns the AUTHENTICATED DEVICE's account and its members. The
// account is taken from the verified signature, never from a query parameter, so
// this endpoint cannot enumerate other accounts.
func (h *handlers) accountGet(w http.ResponseWriter, r *http.Request) {
	dev, ok := h.authenticateAccountRequest(w, r, nil)
	if !ok {
		return
	}

	devices, err := h.devices.ListAccountDevices(r.Context(), dev.AccountID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	out := make([]deviceJSON, 0, len(devices))
	active, revoked := 0, 0
	for _, d := range devices {
		out = append(out, toDeviceJSON(d))
		if d.Active() {
			active++
		} else {
			revoked++
		}
	}

	resp := accountResponse{
		AccountID:          dev.AccountID,
		DeviceCount:        active,
		RevokedDeviceCount: revoked,
		DeviceLimit:        h.accountMaxDevices(),
		Devices:            out,
	}
	if account, aerr := h.devices.GetAccount(r.Context(), dev.AccountID); aerr == nil {
		resp.CreatedAt = account.CreatedAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}

// inviteRequest is the JSON body of POST /v1/account/invites.
//
// NOTE WHAT IS NOT HERE: no account_id and no subject. The invite always lands in
// the CALLER's account. A body carrying such a field is simply ignored by
// encoding/json, which is the property test 15 pins.
type inviteRequest struct {
	// TTLSeconds optionally shortens the invite's life. It may never LENGTHEN it
	// past the server's configured ceiling.
	TTLSeconds int `json:"ttl_seconds"`
	// InviteePublicKey optionally PINS the invite to one Ed25519 public key
	// (standard base64 of 32 raw bytes), so an intercepted invite cannot be
	// redeemed by anyone else. Nothing forces pinning.
	InviteePublicKey string `json:"invitee_public_key"`
}

// inviteCreatedResponse is the ONE and ONLY time the invite secret is returned.
// It is never re-served, never logged, never recorded in a metric, and stored
// only as a SHA-256 digest.
type inviteCreatedResponse struct {
	InviteID  string `json:"invite_id"`
	Invite    string `json:"invite"`
	AccountID string `json:"account_id"`
	ExpiresAt string `json:"expires_at"`
	Pinned    bool   `json:"pinned"`
}

// inviteJSON is the wire shape of an OPEN invite in a listing: METADATA ONLY. It
// carries the PUBLIC handle and never the secret, never the digest.
type inviteJSON struct {
	InviteID          string `json:"invite_id"`
	CreatedByDeviceID string `json:"created_by_device_id"`
	CreatedAt         string `json:"created_at"`
	ExpiresAt         string `json:"expires_at"`
	Pinned            bool   `json:"pinned"`
}

// accountInviteCreate mints a single-use invite for the CALLER's account.
//
// RATE LIMITING (Phase 53) IS KEYED ON THE ACCOUNT, NOT THE DEVICE. The route is
// authenticated, so both keys are available — the account is the tighter and the
// more honest one:
//
//   - The state cap it complements (SIGILD_ACCOUNT_MAX_INVITES) is per-account,
//     so a per-device rate would let an account with N devices mint at N times
//     the rate its own quota was written around. Two bounds on the same resource
//     keyed to different subjects is how a limit becomes theatre.
//   - Membership is FLAT (ADR 0040 limitation 3): any member may invite. There
//     is no sense in which one device's invite budget is separable from its
//     siblings' — they are all spending the account's single open-invite quota.
//
// ⚠️ IT IS THE CHECK AFTER AUTHENTICATION, DELIBERATELY, AND THAT IS ITS LIMIT.
// The key does not exist until the signature has been verified and the device
// row read, so this bounds what a VALID MEMBER may mint; it does NOT make an
// unauthenticated flood of this route cheaper. That flood is bounded by the
// signature check itself, which is the same cost every other signed route pays.
func (h *handlers) accountInviteCreate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAccountBodyBytes+1))
	if err != nil || len(body) > maxAccountBodyBytes {
		writeError(w, http.StatusBadRequest, "invalid_request", "could not read request body")
		return
	}
	// The v3 signature covers the body, so authenticate AFTER reading it.
	dev, ok := h.authenticateAccountRequest(w, r, body)
	if !ok {
		return
	}
	// Bound minting volume before any store work. The subject recorded in the
	// audit line is the account — which this stream already carries everywhere,
	// so it is no new privacy surface.
	if !h.allowAbuse(r, h.inviteLimiter, abuseSurfaceInvite, dev.AccountID, dev.AccountID) {
		writeRateLimited(w, h.inviteLimiter, "too many invites minted by this account")
		return
	}

	var req inviteRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "body must be a JSON object")
			return
		}
	}

	ttl := h.accountInviteTTL()
	if req.TTLSeconds > 0 {
		if requested := time.Duration(req.TTLSeconds) * time.Second; requested < ttl {
			// A client may only SHORTEN the life of an invite, never extend it.
			ttl = requested
		}
	}

	var pinned []byte
	if req.InviteePublicKey != "" {
		decoded, derr := base64.StdEncoding.DecodeString(req.InviteePublicKey)
		if derr != nil || len(decoded) != 32 {
			writeError(w, http.StatusBadRequest, "invalid_request",
				"invitee_public_key must be the standard-base64 encoding of a 32-byte Ed25519 public key")
			return
		}
		pinned = decoded
	}

	// Refuse early when the account is already full: minting an invite that could
	// only ever fail is a worse experience than a clear 409, and it costs a
	// listing the operator would have to clean up.
	//
	// ACTIVE devices only — the same definition the store enforces at redemption,
	// so this pre-check can never refuse an invite the atomic redemption would
	// have accepted. Counting revoked rows here is what made the cap a LIFETIME
	// enrollment limit: an account that revoked its way to the limit could never
	// mint another invite, permanently, with no operation able to free a seat.
	members, err := h.devices.CountActiveAccountDevices(r.Context(), dev.AccountID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	if members >= h.accountMaxDevices() {
		writeError(w, http.StatusConflict, "account_full",
			"that account has reached its device limit")
		return
	}

	secret, err := newInviteSecret()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	inviteID, err := newInviteID()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	now := time.Now().UTC()
	inv := store.AccountInvite{
		// The SECRET is never stored: only this digest, which is also exactly
		// what the enrollment challenge already binds.
		InviteHash:        hashEnrollToken(secret),
		InviteID:          inviteID,
		AccountID:         dev.AccountID, // SERVER-DERIVED, never from the body
		CreatedByDeviceID: dev.ID,
		InviteePublicKey:  pinned,
		CreatedAt:         now,
		ExpiresAt:         now.Add(ttl),
	}
	switch err := h.devices.CreateAccountInvite(r.Context(), inv, h.accountMaxInvites()); {
	case err == nil:
	case errors.Is(err, store.ErrInviteLimit):
		writeError(w, http.StatusConflict, "invite_limit",
			"that account already has the maximum number of open invites")
		return
	case errors.Is(err, store.ErrAccountNotFound):
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	default:
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}

	h.auditAccountInviteCreated(r, inviteID, dev.AccountID, dev.ID, inv.ExpiresAt, inv.Pinned())
	h.metrics.incAccountInviteCreated()
	writeJSON(w, http.StatusCreated, inviteCreatedResponse{
		InviteID:  inviteID,
		Invite:    secret, // the ONLY time this value ever leaves the server
		AccountID: dev.AccountID,
		ExpiresAt: inv.ExpiresAt.Format(time.RFC3339),
		Pinned:    inv.Pinned(),
	})
}

// accountInviteList lists the CALLER's account's OPEN invites. METADATA ONLY:
// never the secret, never the digest — an invite that has been minted can never
// be recovered from the server.
func (h *handlers) accountInviteList(w http.ResponseWriter, r *http.Request) {
	dev, ok := h.authenticateAccountRequest(w, r, nil)
	if !ok {
		return
	}

	invites, err := h.devices.ListAccountInvites(r.Context(), dev.AccountID, time.Now().UTC())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	out := make([]inviteJSON, 0, len(invites))
	for _, inv := range invites {
		out = append(out, inviteJSON{
			InviteID:          inv.InviteID,
			CreatedByDeviceID: inv.CreatedByDeviceID,
			CreatedAt:         inv.CreatedAt.UTC().Format(time.RFC3339),
			ExpiresAt:         inv.ExpiresAt.UTC().Format(time.RFC3339),
			Pinned:            inv.Pinned(),
		})
	}
	writeJSON(w, http.StatusOK, struct {
		Invites []inviteJSON `json:"invites"`
	}{Invites: out})
}

// accountInviteRevoke revokes an unredeemed invite of the CALLER's account.
//
// The store scopes the update by (account_id, invite_id), so a FOREIGN invite ID
// and a MISSING one are indistinguishable — both answer 404 invite_not_found.
// There is no enumeration oracle.
func (h *handlers) accountInviteRevoke(w http.ResponseWriter, r *http.Request) {
	inviteID := r.PathValue("inviteID")
	if inviteID == "" {
		writeError(w, http.StatusBadRequest, "missing_invite_id", "invite ID is required")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAccountBodyBytes+1))
	if err != nil || len(body) > maxAccountBodyBytes {
		writeError(w, http.StatusBadRequest, "invalid_request", "could not read request body")
		return
	}
	dev, ok := h.authenticateAccountRequest(w, r, body)
	if !ok {
		return
	}

	switch err := h.devices.RevokeAccountInvite(r.Context(), dev.AccountID, inviteID, time.Now().UTC()); {
	case err == nil:
	case errors.Is(err, store.ErrInviteUnknown):
		writeError(w, http.StatusNotFound, "invite_not_found", "no such open invite")
		return
	default:
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}

	h.auditAccountInviteRevoked(r, inviteID, dev.AccountID, dev.ID)
	h.metrics.incAccountInviteRevoked()
	writeJSON(w, http.StatusOK, struct {
		InviteID string `json:"invite_id"`
		Revoked  bool   `json:"revoked"`
	}{InviteID: inviteID, Revoked: true})
}
