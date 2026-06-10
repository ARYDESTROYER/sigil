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
// server's clock, in seconds. It bounds replay but does NOT prevent it: there
// is no nonce/jti tracking, so a captured request can be replayed within the
// window. Production needs per-request nonce tracking.
const opsAuthSkew = 300 // seconds

// opsAuthDomain is the fixed first line of the signed message. It binds a
// signature to this scheme + version so a signature cannot be repurposed for a
// different protocol. It MUST stay byte-for-byte identical to the CLI signer.
const opsAuthDomain = "sigil-oplog-auth-v1\n"

// errUnauthorized is the sentinel authorizeOps returns when a request fails the
// op-log auth contract. The caller maps it to a 401 typed-error envelope.
var errUnauthorized = errors.New("oplog auth: unauthorized")

// authorizeOps enforces the op-log request-authentication contract for a single
// vault-ops request.
//
// When h.cfg.OpLogPubKey is nil, auth is DISABLED and this returns nil
// immediately — the op-log keeps its existing UNAUTHENTICATED behaviour. When
// the key is set, the request must carry a valid Ed25519 signature over the
// canonical message (below), else this returns errUnauthorized (-> 401).
//
// HONEST SCOPE (DEV-ONLY): this verifies against a SINGLE configured device
// public key. The 300-second timestamp window bounds replay but does NOT fully
// prevent it — there is no nonce/jti store, so a captured signed request can be
// replayed inside the window. Full device enrollment, a multi-device registry,
// and JWT bearer tokens (see internal/auth) remain FUTURE. Do NOT treat this as
// production authentication.
//
// The signed MESSAGE is built byte-for-byte as (lines joined by '\n' = 0x0A,
// with a trailing '\n' after the timestamp, then the raw body appended):
//
//	"sigil-oplog-auth-v1\n" + METHOD + "\n" + PATH + "\n" + QUERY + "\n" + TIMESTAMP + "\n" + BODY
//
// where METHOD is the uppercase HTTP method (r.Method), PATH is r.URL.Path (no
// query), QUERY is r.URL.RawQuery ("" when absent), TIMESTAMP is the decimal
// ASCII value from X-Sigil-Timestamp, and BODY is the raw request body bytes
// (empty for GET). The Go server and the Rust CLI MUST agree on this exactly.
func (h *handlers) authorizeOps(r *http.Request, body []byte) error {
	// Auth disabled: nil key => unchanged, UNAUTHENTICATED behaviour.
	if h.cfg.OpLogPubKey == nil {
		return nil
	}

	// 1) Both headers must be present and non-blank.
	tsHeader := r.Header.Get("X-Sigil-Timestamp")
	sigHeader := r.Header.Get("X-Sigil-Signature")
	if tsHeader == "" || sigHeader == "" {
		return errUnauthorized
	}

	// 2) Timestamp must parse as int64 and fall inside the skew window.
	ts, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return errUnauthorized
	}
	now := time.Now().Unix()
	if skew := now - ts; skew < -opsAuthSkew || skew > opsAuthSkew {
		return errUnauthorized
	}

	// 3) Reconstruct the canonical signed MESSAGE from the request. The
	//    timestamp segment uses the RAW header value (tsHeader), so it matches
	//    whatever the client signed, not a re-formatted parse.
	msg := make([]byte, 0,
		len(opsAuthDomain)+len(r.Method)+len(r.URL.Path)+len(r.URL.RawQuery)+len(tsHeader)+4+len(body))
	msg = append(msg, opsAuthDomain...)
	msg = append(msg, r.Method...)
	msg = append(msg, '\n')
	msg = append(msg, r.URL.Path...)
	msg = append(msg, '\n')
	msg = append(msg, r.URL.RawQuery...)
	msg = append(msg, '\n')
	msg = append(msg, tsHeader...)
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
	return nil
}
