package api

// Multi-device request authentication + per-vault authorization (Phase 41).
//
// This is the op-log auth contract v3. It replaces the v2 model's ONE static
// public key (which authenticated every request to every vault) with a real
// device registry:
//
//	v2: X-Sigil-Signature verified against a SINGLE configured pubkey.
//	v3: X-Sigil-Device names WHICH enrolled device signed; the server resolves
//	    that ID to its registered Ed25519 public key, verifies the signature,
//	    rejects a revoked device, and then checks that THIS device is authorized
//	    for THIS vault.
//
// Everything is REAL: real crypto/ed25519 verification against a real registry,
// real per-vault grants, real revocation. There is no bypass path, no "trusted"
// fallback key, and no hardcoded credential. When the device registry is not
// configured the server keeps its EXISTING behaviour exactly (legacy v2 single
// key, or no auth) — the new model is strictly opt-in.
//
// Retained from v2: the 300 s timestamp window, the per-request nonce, the
// in-memory replay cache (still PER-PROCESS — a multi-instance deploy needs a
// shared store), and the typed authReason that goes ONLY to the audit log.
//
// HONEST SCOPE (DEV-ONLY): this is dev-gated behind SIGILD_ENABLE_DEV_OPS and
// remains UNAUDITED. There is no account model, no key rotation, no recovery, no
// hardware attestation, and the replay cache is not shared across instances.

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

// opsAuthDomainV3 is the fixed first line of the v3 signed message. Bumping the
// domain from "-v2" to "-v3" is deliberate DOMAIN SEPARATION: a v2 signature can
// never verify under v3 (different first line AND a new device-ID segment), so
// captured v2 traffic cannot be replayed into the device model.
const opsAuthDomainV3 = "sigil-oplog-auth-v3\n"

// enrollDomain is the fixed first line of the device-enrollment proof-of-
// possession message. It is a DIFFERENT domain from the request-auth contract,
// so an enrollment proof can never be repurposed as an op-log request signature
// (or vice versa).
const enrollDomain = "sigil-device-enroll-v1\n"

// enrollNoncePrefix namespaces enrollment nonces inside the shared replay cache
// so they cannot collide with, or be confused for, op-log request nonces.
const enrollNoncePrefix = "enroll:"

// Header names for the v3 contract. X-Sigil-Device is the ONLY addition over v2;
// the other three keep their v2 meanings.
const (
	headerDevice      = "X-Sigil-Device"
	headerTimestamp   = "X-Sigil-Timestamp"
	headerNonce       = "X-Sigil-Nonce"
	headerSignature   = "X-Sigil-Signature"
	headerEnrollToken = "X-Sigil-Enroll-Token"
	headerAdminToken  = "X-Sigil-Admin-Token"
)

// Additional authReason values introduced by v3. Like the v2 reasons these are a
// FIXED enum carrying no secret material — they name which check failed and are
// surfaced ONLY in the server-side audit log and the per-reason metric, never in
// a response body.
const (
	// reasonUnknownDevice: X-Sigil-Device names no registered device.
	reasonUnknownDevice authReason = "unknown_device"
	// reasonRevokedDevice: the device is registered but revoked.
	reasonRevokedDevice authReason = "revoked_device"
	// reasonUnauthorizedVault: the device authenticated, but holds no grant (or
	// too weak a grant) on the requested vault. This is the ONLY reason that maps
	// to 403 rather than 401.
	reasonUnauthorizedVault authReason = "unauthorized_vault"
	// reasonNotVaultOwner: the device is authorized on the vault but is not its
	// owner, and the operation requires ownership (granting access). Also 403.
	reasonNotVaultOwner authReason = "not_vault_owner"
	// reasonBadEnrollToken: the presented enrollment token is not one this server
	// provisioned.
	reasonBadEnrollToken authReason = "bad_enrollment_token"
	// reasonEnrollTokenUsed: the token is known but already spent (single-use).
	reasonEnrollTokenUsed authReason = "enrollment_token_used"
	// reasonEnrollTokenExpired: the token is known and unspent but past its TTL.
	reasonEnrollTokenExpired authReason = "enrollment_token_expired"
	// reasonBadProof: the enrolling key did not prove possession of its private
	// key over the canonical enrollment challenge.
	reasonBadProof authReason = "bad_proof"
	// reasonMalformedKey: the submitted public key is not 32 bytes of base64.
	reasonMalformedKey authReason = "malformed_key"
	// reasonDeviceExists: that public key is already enrolled.
	reasonDeviceExists authReason = "device_exists"
	// reasonBadAdminToken: a missing/incorrect operator admin token.
	reasonBadAdminToken authReason = "bad_admin_token"
	// reasonForbiddenDevice: the device authenticated but may not act on ANOTHER
	// device (e.g. revoking a device that is not itself). 403.
	reasonForbiddenDevice authReason = "forbidden_device"
	// reasonStoreUnavailable: the device registry could not be read/written. It
	// is NOT an authentication verdict — it maps to 500 so an infrastructure
	// fault is never mistaken for a credential failure.
	reasonStoreUnavailable authReason = "store_unavailable"
)

// accessNeed is the authorization level an ops route requires.
type accessNeed int

const (
	// needRead: list/verify a vault's op-log.
	needRead accessNeed = iota
	// needWrite: append to a vault's op-log. A write to an UNOWNED vault claims
	// ownership (trust-on-first-write, see authorizeVault).
	needWrite
	// needOwner: administer a vault (grant another device access).
	needOwner
)

// permission maps an accessNeed to the store permission it requires.
func (n accessNeed) permission() store.Permission {
	if n == needRead {
		return store.PermRead
	}
	return store.PermWrite
}

// authOutcome is the result of authenticating + authorizing one request.
// Reason == "" means ALLOWED. DeviceID is the ID the client PRESENTED (recorded
// for the audit trail even when the request was rejected, e.g. unknown_device);
// it is empty in the legacy/no-auth modes.
type authOutcome struct {
	Reason   authReason
	DeviceID string
}

// allowed reports whether the request may proceed.
func (o authOutcome) allowed() bool { return o.Reason == reasonOK }

// authStatus maps a denial reason to its HTTP status. Authorization failures are
// 403 (authenticated, but not permitted); everything else that is a credential
// verdict is 401; a registry fault is 500 so it is never read as a credential
// failure.
func authStatus(reason authReason) int {
	switch reason {
	case reasonUnauthorizedVault, reasonNotVaultOwner, reasonForbiddenDevice:
		return http.StatusForbidden
	case reasonStoreUnavailable:
		return http.StatusInternalServerError
	default:
		return http.StatusUnauthorized
	}
}

// deviceAuthEnabled reports whether the v3 device model is active for this
// router. It is on iff a device registry was wired (dev-gated by NewRouter).
func (h *handlers) deviceAuthEnabled() bool { return h.devices != nil }

// parseTimestampWindow parses an X-Sigil-Timestamp header and checks it against
// the shared skew window. It returns (ts, now, ok); ok is false when the header
// does not parse as an int64 or falls outside +/- opsAuthSkew seconds. Shared by
// the v3 request contract and enrollment so both use one window.
func parseTimestampWindow(tsHeader string) (ts, now int64, ok bool) {
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	now = time.Now().Unix()
	if skew := now - ts; skew < -opsAuthSkew || skew > opsAuthSkew {
		return ts, now, false
	}
	return ts, now, true
}

// ed25519Verify is a total wrapper around ed25519.Verify: it returns false for a
// wrong-length key or signature instead of panicking, so malformed client input
// is a clean rejection rather than a crash.
func ed25519Verify(pub, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// canonicalV3Message builds the byte-for-byte v3 signed message:
//
//	"sigil-oplog-auth-v3\n" + DEVICE + "\n" + METHOD + "\n" + PATH + "\n" +
//	QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + BODY
//
// DEVICE is the exact X-Sigil-Device header text, METHOD the uppercase HTTP
// method, PATH r.URL.Path, QUERY r.URL.RawQuery ("" when absent), TIMESTAMP and
// NONCE the exact header texts, and BODY the raw request body (empty for GET).
// Clients MUST reproduce this exactly.
func canonicalV3Message(deviceID, method, path, query, ts, nonce string, body []byte) []byte {
	msg := make([]byte, 0, len(opsAuthDomainV3)+len(deviceID)+len(method)+len(path)+
		len(query)+len(ts)+len(nonce)+6+len(body))
	msg = append(msg, opsAuthDomainV3...)
	msg = append(msg, deviceID...)
	msg = append(msg, '\n')
	msg = append(msg, method...)
	msg = append(msg, '\n')
	msg = append(msg, path...)
	msg = append(msg, '\n')
	msg = append(msg, query...)
	msg = append(msg, '\n')
	msg = append(msg, ts...)
	msg = append(msg, '\n')
	msg = append(msg, nonce...)
	msg = append(msg, '\n')
	msg = append(msg, body...)
	return msg
}

// authenticateDevice performs the AUTHENTICATION half of contract v3: it
// resolves X-Sigil-Device, verifies the Ed25519 signature over the canonical v3
// message with THAT device's registered public key, rejects a revoked device,
// and rejects a replayed nonce. It performs NO authorization — the caller
// decides what the authenticated device is allowed to do.
//
// Check order maps 1:1 to the returned reason:
//  1. all four headers present               -> missing_headers
//  2. timestamp parses / inside skew window  -> bad_timestamp / stale_timestamp
//  3. device resolves in the registry        -> unknown_device
//  4. device is not revoked                  -> revoked_device
//  5. signature verifies under its pubkey    -> bad_signature
//  6. nonce not seen in-window               -> replayed
//
// The nonce is recorded ONLY after a valid signature, so unauthenticated probes
// can neither populate nor probe the replay cache.
func (h *handlers) authenticateDevice(r *http.Request, body []byte) (store.Device, authOutcome) {
	deviceID := r.Header.Get(headerDevice)
	tsHeader := r.Header.Get(headerTimestamp)
	nonceHeader := r.Header.Get(headerNonce)
	sigHeader := r.Header.Get(headerSignature)
	if deviceID == "" || tsHeader == "" || nonceHeader == "" || sigHeader == "" {
		return store.Device{}, authOutcome{Reason: reasonMissingHeaders, DeviceID: deviceID}
	}

	if _, err := strconv.ParseInt(tsHeader, 10, 64); err != nil {
		return store.Device{}, authOutcome{Reason: reasonBadTimestamp, DeviceID: deviceID}
	}
	ts, now, inWindow := parseTimestampWindow(tsHeader)
	if !inWindow {
		return store.Device{}, authOutcome{Reason: reasonStaleTimestamp, DeviceID: deviceID}
	}

	dev, err := h.devices.GetDevice(r.Context(), deviceID)
	if err != nil {
		if errors.Is(err, store.ErrDeviceNotFound) {
			return store.Device{}, authOutcome{Reason: reasonUnknownDevice, DeviceID: deviceID}
		}
		return store.Device{}, authOutcome{Reason: reasonStoreUnavailable, DeviceID: deviceID}
	}
	if !dev.Active() {
		// A revoked device is rejected here, BEFORE its signature is even checked
		// — revocation takes effect on the device's very next request.
		return store.Device{}, authOutcome{Reason: reasonRevokedDevice, DeviceID: deviceID}
	}

	msg := canonicalV3Message(deviceID, r.Method, r.URL.Path, r.URL.RawQuery, tsHeader, nonceHeader, body)
	sig, err := base64.StdEncoding.DecodeString(sigHeader)
	if err != nil {
		return store.Device{}, authOutcome{Reason: reasonBadSignature, DeviceID: deviceID}
	}
	if !ed25519Verify(dev.PublicKey, msg, sig) {
		return store.Device{}, authOutcome{Reason: reasonBadSignature, DeviceID: deviceID}
	}

	if h.nonces != nil && h.nonces.checkAndRecord(nonceHeader, ts, now) {
		return store.Device{}, authOutcome{Reason: reasonReplayed, DeviceID: deviceID}
	}
	return dev, authOutcome{DeviceID: deviceID}
}

// authorizeVault performs the AUTHORIZATION half: it checks that an already-
// authenticated device holds a sufficient grant on vaultID.
//
// OWNERSHIP RULE — TRUST ON FIRST WRITE (TOFU): a vault with no owner is claimed
// by the FIRST device that successfully authenticates a WRITE (append) to it;
// that device becomes the owner with write permission. The claim is atomic in
// every backend (a mutex in memory, a partial UNIQUE index in Postgres), so
// exactly one of N concurrent first-writers wins and the losers get 403. Reads
// never claim: reading an unowned vault is 403.
//
// This rule is deliberately simple and is a DEV model. It is not an account
// model: it assumes the first writer of a vault ID is its legitimate owner, so
// an attacker who reaches an unclaimed vault ID before the real owner takes it.
// Vault IDs are client-chosen high-entropy identifiers, which is what makes that
// tolerable pre-audit — it is NOT sufficient for production.
func (h *handlers) authorizeVault(r *http.Request, dev store.Device, vaultID string, need accessNeed) authOutcome {
	out := authOutcome{DeviceID: dev.ID}

	grant, err := h.devices.GetGrant(r.Context(), vaultID, dev.ID)
	switch {
	case err == nil:
		// Have a grant: does it cover what this route needs?
		if need == needOwner && !grant.Owner {
			out.Reason = reasonNotVaultOwner
			return out
		}
		if !grant.Perm.Allows(need.permission()) {
			out.Reason = reasonUnauthorizedVault
			return out
		}
		return out
	case errors.Is(err, store.ErrGrantNotFound):
		// No grant. Only a WRITE may claim an unowned vault.
		if need != needWrite {
			out.Reason = reasonUnauthorizedVault
			return out
		}
		claimed, cerr := h.devices.ClaimVaultOwner(r.Context(), vaultID, dev.ID, time.Now().UTC())
		if cerr != nil {
			out.Reason = reasonStoreUnavailable
			return out
		}
		if !claimed {
			// The vault is already owned by another device.
			out.Reason = reasonUnauthorizedVault
			return out
		}
		h.auditVaultClaimed(r, vaultID, dev.ID)
		h.metrics.incVaultClaim()
		return out
	default:
		out.Reason = reasonStoreUnavailable
		return out
	}
}

// authorizeOpsRequest is the single entry point the ops handlers use. It selects
// the active mode:
//
//	device registry wired  -> contract v3 (authenticate device, then authorize
//	                          it for THIS vault at the required level)
//	OpLogPubKey set        -> legacy contract v2, UNCHANGED (single static key,
//	                          no per-vault authorization)
//	neither                -> no auth, UNCHANGED
//
// The legacy path is preserved byte-for-byte so existing clients (the sigil CLI,
// the wasm sync tests) keep working exactly as before.
func (h *handlers) authorizeOpsRequest(r *http.Request, body []byte, vaultID string, need accessNeed) authOutcome {
	if h.deviceAuthEnabled() {
		dev, out := h.authenticateDevice(r, body)
		if !out.allowed() {
			return out
		}
		return h.authorizeVault(r, dev, vaultID, need)
	}
	// Legacy v2 (or disabled) path, unchanged.
	return authOutcome{Reason: h.authorizeOps(r, body)}
}

// writeAuthError maps a denial reason to its response. The error CODE and DETAIL
// are deliberately coarse — "unauthorized" for every credential failure and
// "forbidden" for an authorization failure — so a prober learns only the status
// class, never which check tripped. The precise reason goes ONLY to the audit
// log and the per-reason metric.
func writeAuthError(w http.ResponseWriter, reason authReason) {
	switch authStatus(reason) {
	case http.StatusForbidden:
		writeError(w, http.StatusForbidden, "forbidden",
			"device is not authorized for this vault")
	case http.StatusInternalServerError:
		writeError(w, http.StatusInternalServerError, "internal", "")
	default:
		detail := "missing or invalid request signature"
		if reason == reasonReplayed {
			detail = "replayed request"
		}
		writeError(w, http.StatusUnauthorized, "unauthorized", detail)
	}
}

// EnrollTokenHash returns the lowercase hex SHA-256 digest of an enrollment
// token. It is exported so the process entrypoint can convert the operator's
// configured tokens into digests ONCE at boot — the plaintext token then never
// enters api.Config, the device registry, the audit log, or /metrics.
func EnrollTokenHash(token string) string { return hashEnrollToken(token) }

// hashEnrollToken returns the lowercase hex SHA-256 of a presented enrollment
// token. The PLAINTEXT token is never stored, logged, or compared directly
// against persisted state — only this digest is.
func hashEnrollToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// matchesConfiguredToken reports whether hash is one of the token digests this
// server was provisioned with. It compares against EVERY configured digest with
// subtle.ConstantTimeCompare and no early exit, so the comparison leaks neither
// which token matched nor how far a near-miss got.
func matchesConfiguredToken(configured []string, hash string) bool {
	var match int
	for _, want := range configured {
		match |= subtle.ConstantTimeCompare([]byte(want), []byte(hash))
	}
	return match == 1
}

// checkAdminToken verifies the operator admin token in constant time. When no
// admin token is configured the check ALWAYS fails: there is no implicit
// "admin access is open" mode.
func (h *handlers) checkAdminToken(r *http.Request) bool {
	if h.cfg.AdminToken == "" {
		return false
	}
	presented := r.Header.Get(headerAdminToken)
	return subtle.ConstantTimeCompare([]byte(h.cfg.AdminToken), []byte(presented)) == 1
}

// canonicalEnrollMessage builds the byte-for-byte enrollment proof-of-possession
// challenge:
//
//	"sigil-device-enroll-v1\n" + TOKEN_SHA256_HEX + "\n" + TIMESTAMP + "\n" +
//	NONCE + "\n" + PUBLIC_KEY_B64 + "\n" + LABEL
//
// The enrolling device signs this with the PRIVATE key matching the public key
// it is submitting, and the server verifies that signature against the submitted
// key — that is the proof of possession. Binding the token digest into the
// message means a captured proof cannot be re-presented alongside a different
// token, and binding the public key means an interceptor cannot swap in its own
// key while reusing the victim's token.
//
// PUBLIC_KEY_B64 and LABEL are the EXACT strings from the JSON request body, so
// both sides sign the same bytes with no re-encoding ambiguity.
func canonicalEnrollMessage(tokenHash, ts, nonce, pubKeyB64, label string) []byte {
	msg := make([]byte, 0, len(enrollDomain)+len(tokenHash)+len(ts)+len(nonce)+len(pubKeyB64)+len(label)+4)
	msg = append(msg, enrollDomain...)
	msg = append(msg, tokenHash...)
	msg = append(msg, '\n')
	msg = append(msg, ts...)
	msg = append(msg, '\n')
	msg = append(msg, nonce...)
	msg = append(msg, '\n')
	msg = append(msg, pubKeyB64...)
	msg = append(msg, '\n')
	msg = append(msg, label...)
	return msg
}
