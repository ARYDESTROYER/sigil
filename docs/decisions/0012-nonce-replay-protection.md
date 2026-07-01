# 0012 — Per-request nonce replay protection for the dev op-log (contract v2)

- **Status:** Accepted — 2026-07.

## Context

[ADR 0008](0008-device-key-request-auth.md) added an optional Ed25519
request-signature check to the dev op-log (`SIGILD_OPLOG_PUBKEY`). It signs a
canonical `sigil-oplog-auth-v1` message over `(method, path, query, timestamp,
body)` with a 300-second timestamp skew window. That ADR was explicit that the
window **bounds but does not prevent** replay: with no nonce/jti tracking, a
captured signed request replays successfully within the window. The code and
`docs/api.md` both said "production needs per-request nonce tracking."

This ADR records closing that gap for a single running dev process.

## Decision

Add a per-request **nonce** to the request-auth contract (a hard cutover from v1
to **v2**) and a bounded, in-memory server-side nonce store.

- **Canonical message v2.** Bump the domain to `sigil-oplog-auth-v2\n` and insert
  a `NONCE` line **between `TIMESTAMP` and `BODY`**:
  `MESSAGE = "sigil-oplog-auth-v2\n" + METHOD + "\n" + PATH + "\n" + QUERY + "\n"
  + TIMESTAMP + "\n" + NONCE + "\n" + BODY`. v1 and v2 are mutually unverifiable
  by construction (the domain string and the framing both differ) — deliberate
  domain separation, no dual-verify path. The CLI and server ship together.
- **`X-Sigil-Nonce` header**, required when auth is on. The demo CLI sends
  standard-base64 of 16 CSPRNG bytes (24 chars). The server treats the nonce as an
  **opaque string** — it never decodes it; the raw header bytes are both the
  message segment and the store key.
- **Validate the nonce before folding it into the message.** Non-empty,
  `≤ 128` bytes, every byte printable ASCII `0x21`–`0x7E` (no space/control). This
  is critical: the nonce is folded in **before** signature verification, so a
  control byte (e.g. `\n`) could otherwise shift the newline-delimited framing.
- **Check order: nonce store AFTER `ed25519.Verify` succeeds.** Only
  validly-signed requests consume store space, so an unauthenticated attacker
  cannot populate or flood it.
- **Bounded, TTL-evicting in-memory store** (`nonceStore`, Go stdlib
  `sync.Mutex` + map). **TTL = 2× the skew window + 1 s (601 s), not 1×** — the
  skew check is two-sided *and inclusive* (a request may be signed up to
  `opsAuthSkew` in the future, and `skew == +opsAuthSkew` still passes), so a
  captured request is replayable on the **closed** interval `[ts−skew, ts+skew]`.
  Worst case the earliest first receipt is server-time `ts−skew`, so the guard must
  survive until `ts+skew` inclusive = `(ts−skew) + 2·skew`. Because the store's
  replay check is strict (`exp > now`), retaining for exactly `2·skew` would expire
  the guard one tick early at `now == ts+skew` and admit a single boundary replay;
  the **+1** closes that so retention covers the full replayable lifetime. Expiry is
  anchored to the **server's** receipt time, never the attacker-controlled client
  timestamp. A hard cap (`nonceStoreMaxEntries`, 65536) bounds memory; at capacity
  (after sweeping expired entries) `checkAndRecord` **fails closed**.
- **Gated with auth.** The store is created only when `SIGILD_OPLOG_PUBKEY` is
  set. With no pubkey there is no auth, no nonce requirement, and behaviour is
  byte-for-byte unchanged.

## Consequences

- A captured signed op-log request **can no longer be replayed** within the same
  running process: the second delivery of an identical `(ts, nonce, method, path,
  query, body)` — hence an identical signature — is rejected `401`. Verified with
  a **live cross-language round-trip**: a Rust-CLI-signed v2 request is accepted by
  the Go server, and an identical curl replay (same nonce, still-fresh timestamp)
  is rejected while a fresh nonce succeeds.
- **Still DEV-ONLY.** The store is **in-memory** — lost on restart and not shared
  across instances — so a captured request could be replayed after a restart
  within its remaining window, and horizontal replicas do not dedupe. Production
  needs a shared/persistent store (e.g. Redis `SET NX EX`). This is stated in the
  code, `api.md`, and the honest-scope notes; it is not represented as production
  auth.
- **Breaking contract change** (v1 → v2). Acceptable because both the client (the
  demo CLI) and the server live in this repo and are dev-only; old signed requests
  no longer verify by design.
- `sigild` stays **Go stdlib-only** ([ADR 0005](0005-stdlib-only-sigild.md)) — the
  store uses only `sync`/`time`; no `go.sum`. The core `getrandom`-0 / wasm
  invariants are untouched (the CLI's nonce uses its own already-present
  `getrandom`; `libsigil/Cargo.lock` is unchanged).
