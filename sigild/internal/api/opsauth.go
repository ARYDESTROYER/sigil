package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"time"
)

// opsAuthSkew bounds how far the client-supplied timestamp may drift from the
// server's clock, in seconds. It is two-sided (a request may be signed up to
// opsAuthSkew in the future). It is now paired with a per-request nonce store
// (see noncestore.go) so a captured request cannot be replayed WITHIN the
// window either. The single static device key and the in-memory nonce store
// remain DEV-ONLY (the store is lost on restart and is not shared across
// instances; production needs a shared/persistent store).
const opsAuthSkew = 300 // seconds

// opsAuthDomain is the fixed first line of the signed message. It binds a
// signature to this scheme + version so a signature cannot be repurposed for a
// different protocol OR an older contract version. It MUST stay byte-for-byte
// identical to the CLI signer. v2 (this version) adds a per-request NONCE line
// to the message; v1 signatures no longer verify (a deliberate hard cutover).
const opsAuthDomain = "sigil-oplog-auth-v2\n"

// opsAuthNonceMaxLen bounds the X-Sigil-Nonce header. A legitimate CLI nonce is
// standard-base64 of 16 random bytes (24 chars); 128 is generous headroom and is
// part of the cross-language contract (documented in api.md so any client
// conforms).
const opsAuthNonceMaxLen = 128

// errUnauthorized is the sentinel authorizeOps returns when a request fails the
// op-log auth contract. The caller maps it to a 401 typed-error envelope.
var errUnauthorized = errors.New("oplog auth: unauthorized")

// validNonce reports whether s is a well-formed X-Sigil-Nonce: non-empty, within
// the length cap, and every byte printable ASCII excluding space (0x21..0x7E).
// This admits the base64/hex alphabets and EXCLUDES '\n' (0x0A), '\r' (0x0D),
// space, and all other control/non-ASCII bytes — so a nonce can never shift the
// newline-delimited canonical message framing (it is folded into the signed
// message BEFORE verification) or bloat the store's keys.
func validNonce(s string) bool {
	if len(s) == 0 || len(s) > opsAuthNonceMaxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e {
			return false
		}
	}
	return true
}

// authorizeOps enforces the op-log request-authentication contract for a single
// vault-ops request.
//
// When h.cfg.OpLogPubKey is nil, auth is DISABLED and this returns nil
// immediately — the op-log keeps its existing UNAUTHENTICATED behaviour. When
// the key is set, the request must carry a valid Ed25519 signature over the
// canonical message (below), else this returns errUnauthorized (-> 401).
//
// HONEST SCOPE (DEV-ONLY): this verifies against a SINGLE configured device
// public key. A per-request nonce store (noncestore.go) now rejects replays
// within the timestamp window, but the store is IN-MEMORY — lost on restart and
// not shared across instances — so a captured request could still be replayed
// after a restart within its remaining window. Full device enrollment, a
// multi-device registry, JWT bearer tokens (see internal/auth), and a
// shared/persistent nonce store remain FUTURE. Do NOT treat this as production
// authentication.
//
// The signed MESSAGE is built byte-for-byte as (lines joined by '\n' = 0x0A,
// with a trailing '\n' after the nonce, then the raw body appended):
//
//	"sigil-oplog-auth-v2\n" + METHOD + "\n" + PATH + "\n" + QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + BODY
//
// where METHOD is the uppercase HTTP method (r.Method), PATH is r.URL.Path (no
// query), QUERY is r.URL.RawQuery ("" when absent), TIMESTAMP is the decimal
// ASCII value from X-Sigil-Timestamp, NONCE is the raw X-Sigil-Nonce header, and
// BODY is the raw request body bytes (empty for GET). The Go server and the Rust
// CLI MUST agree on this exactly.
func (h *handlers) authorizeOps(r *http.Request, body []byte) error {
	// Auth disabled: nil key => unchanged, UNAUTHENTICATED behaviour.
	if h.cfg.OpLogPubKey == nil {
		return nil
	}

	// 1) All three headers must be present; the nonce must be well-formed BEFORE
	//    it is folded into the signed message (a control byte in the nonce would
	//    otherwise shift the newline-delimited framing).
	tsHeader := r.Header.Get("X-Sigil-Timestamp")
	nonceHeader := r.Header.Get("X-Sigil-Nonce")
	sigHeader := r.Header.Get("X-Sigil-Signature")
	if tsHeader == "" || sigHeader == "" || !validNonce(nonceHeader) {
		return errUnauthorized
	}

	// 2) Timestamp must parse as int64 and fall inside the (two-sided) skew window.
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return errUnauthorized
	}
	now := time.Now().Unix()
	if skew := now - ts; skew < -opsAuthSkew || skew > opsAuthSkew {
		return errUnauthorized
	}

	// 3) Reconstruct the canonical signed MESSAGE from the request. The timestamp
	//    and nonce segments use the RAW header values, so they match whatever the
	//    client signed, not a re-formatted parse.
	msg := make([]byte, 0,
		len(opsAuthDomain)+len(r.Method)+len(r.URL.Path)+len(r.URL.RawQuery)+
			len(tsHeader)+len(nonceHeader)+5+len(body))
	msg = append(msg, opsAuthDomain...)
	msg = append(msg, r.Method...)
	msg = append(msg, '\n')
	msg = append(msg, r.URL.Path...)
	msg = append(msg, '\n')
	msg = append(msg, r.URL.RawQuery...)
	msg = append(msg, '\n')
	msg = append(msg, tsHeader...)
	msg = append(msg, '\n')
	msg = append(msg, nonceHeader...)
	msg = append(msg, '\n')
	msg = append(msg, body...)

	// 4) Decode the signature and verify against the configured device key.
	sig, err := base64.StdEncoding.DecodeString(sigHeader)
	if err != nil {
		return errUnauthorized
	}
	if !ed25519.Verify(h.cfg.OpLogPubKey, msg, sig) {
		return errUnauthorized
	}

	// 5) Replay guard: ONLY AFTER a valid signature do we consult the nonce store,
	//    so unauthenticated traffic can never populate or flood it. A nonce seen
	//    within its retention window is a replay.
	if h.nonces != nil && !h.nonces.checkAndRecord(nonceHeader, now) {
		return errUnauthorized
	}
	return nil
}
