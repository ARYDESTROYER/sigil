# 0010 — Op-log request auth v2: signed per-request nonce + replay cache

- **Status:** Accepted — 2026-06.

## Context

[`0008`](0008-device-key-request-auth.md) added optional Ed25519 device-key
request auth to the dev op-log (`SIGILD_OPLOG_PUBKEY`): each request carries a
timestamp and a signature over a canonical
`MESSAGE = "sigil-oplog-auth-v1\n" + METHOD + "\n" + PATH + "\n" + QUERY + "\n" + TIMESTAMP + "\n" + BODY`.
That closed the wide-open dev route, but `0008` itself flagged one honest gap:
replay was only **window-bounded**, not prevented. The 300-second skew check
bounds how long a captured request stays valid, but with **no nonce/jti store**
a request replayed inside that window still verifies. For a signed op-log
append, an attacker who captures one authenticated request can resubmit it —
duplicating the op — for up to five minutes.

Everything needed to close this is already in place and stdlib-only. `sigild` is
Go stdlib-only ([`0005`](0005-stdlib-only-sigild.md)) and has `crypto/rand`,
`crypto/ed25519`, `encoding/base64`, `sync`, and `time`; the demo `cli` owns its
own entropy ([`0007`](0007-caller-supplied-entropy-in-core.md)) and can generate
a fresh nonce with `getrandom`. Crucially, **there are no external clients** of
the op-log auth — only the in-repo Go server and Rust CLI implement the
contract — so the wire format can be changed outright rather than versioned for
backward compatibility.

## Decision

Bump the op-log auth contract to **v2**: bind a **fresh per-request nonce** into
the signed message, send it as a header, and have the server enforce
single-use of each nonce with a **time-bounded, in-memory seen-nonce cache**. A
**clean break** — v2 supersedes v1; v1-signed requests (which lack the nonce
line) no longer verify, and there are no external clients to break.

- **Gate unchanged:** auth is still enabled only when `SIGILD_OPLOG_PUBKEY` is
  set (std-base64 of a 32-byte Ed25519 public key); unset → no auth, behaviour
  as before, existing no-auth tests unchanged.
- **Nonce:** the client generates a fresh **≥ 16-byte CSPRNG** nonce per request
  (`getrandom` in the CLI, `crypto/rand` in Go tests), std-base64-encoded to the
  `X-Sigil-Nonce` header string.
- **v2 canonical message** (the exact `X-Sigil-Nonce` string is signed
  **verbatim**, as its own line before the body):
  `MESSAGE = "sigil-oplog-auth-v2\n" + METHOD + "\n" + PATH + "\n" + QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + BODY`.
- **Headers:** `X-Sigil-Timestamp`, `X-Sigil-Nonce`, `X-Sigil-Signature` (all
  three now required).
- **Verification order (both GET and POST):** (1) all three headers
  present/non-blank else `401`; (2) parse timestamp, `abs(now - ts) > 300s` →
  `401`; (3) reconstruct the v2 `MESSAGE` (with the raw nonce header),
  `ed25519.Verify` false → `401`; (4) **only after a valid signature** — so
  unauthenticated probes cannot touch the cache — a **replay check**: nonce
  already cached (and unexpired) → `401` (replayed), else record it with its ts.
- **Seen-nonce cache:** in-memory, concurrency-safe, **time-bounded** — evict
  entries whose ts < `now - 300s` (a nonce is remembered exactly as long as a
  request bearing it could still pass the timestamp check), plus a hard size cap
  as a safety backstop. `401` responses keep the typed
  `{"error":"unauthorized","detail":"..."}` envelope; a distinct `detail`
  marks a replayed nonce.

The full byte-for-byte contract lives in [`../api.md`](../api.md).

## Consequences

- **Closes the replay caveat from `0008`.** A captured authenticated request can
  no longer be replayed inside the timestamp window: each nonce is accepted at
  most once, and the cache remembers it for exactly as long as the window would
  otherwise let it pass.
- **The cache is per-process / in-memory.** This is honest dev scope: a
  multi-instance production deploy would need a **shared** nonce store (e.g.
  Redis) for the guard to hold across instances, and would want the store to
  survive restarts. Not built.
- **Still a single static dev key.** v2 changes only replay protection; there is
  still no device enrollment, no multi-device registry, no rotation, no JWT, and
  no per-vault membership check — those remain **future** (see
  [`0008`](0008-device-key-request-auth.md) and
  [`../../sigild/internal/auth/`](../../sigild/internal/auth/)). It remains
  **dev-gated and plain-HTTP**; not a production posture, not for real secrets.
- **Clean break, no version negotiation.** Because there are no external
  clients, v2 simply replaces v1 rather than being negotiated alongside it; the
  domain-separation prefix moves from `sigil-oplog-auth-v1` to
  `sigil-oplog-auth-v2`, so a stale v1 signer fails closed.
- **Cross-language byte-for-byte agreement stays load-bearing** (as in `0008`):
  the Go verifier and Rust signer must reconstruct the identical v2 message —
  including the raw nonce header used verbatim — or every request fails.
