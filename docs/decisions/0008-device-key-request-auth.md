# 0008 — Device-key request auth for the dev op-log (`SIGILD_OPLOG_PUBKEY`)

- **Status:** Accepted — 2026-06.

## Context

[`0003`](0003-dev-gated-opaque-op-log.md) added a **dev-gated, opaque,
in-memory** vault op-log to `sigild`, and that op-log is deliberately
**UNAUTHENTICATED**: anyone who can reach the port can append to and read from
any vault ID. That was acceptable as a pure storage demo, but the project
guardrail is to stub honestly rather than fake auth — and now there is enough
real machinery to authenticate the dev path *without* faking anything:

- `libsigil/core` gained a real (UNAUDITED) classical **Ed25519 sign/verify**
  primitive (Phase 11, [`../../libsigil/core/src/sig.rs`](../../libsigil/core/src/sig.rs)),
  which takes a **caller-supplied 32-byte secret seed** and is RNG-free in the
  core ([`0007`](0007-caller-supplied-entropy-in-core.md)).
- The demo `cli` ([`../../cli/`](../../cli/)) owns its own entropy and storage
  (its own lockfile, [`0007`](0007-caller-supplied-entropy-in-core.md)), so it
  can generate/hold a seed and **sign** requests via
  `sigil_core::{sign, public_key_from_seed}`.

`sigild` is **Go stdlib-only** ([`0005`](0005-stdlib-only-sigild.md)), and
`crypto/ed25519` / `encoding/base64` / `strconv` / `time` are all stdlib, so the
server can **verify** a signature without taking any third-party dependency.
What was missing was a contract that the Go server and the Rust CLI both
implement **byte-for-byte identically**.

## Decision

Authenticate op-log requests with a **client Ed25519 signature over a canonical
request message**, verified server-side against a **single configured device
public key**, **dev-gated** and **replay-window-bounded**:

- **Gate:** auth is enabled **only** when — with dev-ops on
  ([`0003`](0003-dev-gated-opaque-op-log.md)) — the env var
  **`SIGILD_OPLOG_PUBKEY`** is set to the **standard-base64 of a 32-byte Ed25519
  public key**. When `SIGILD_OPLOG_PUBKEY` is **unset (the default), there is no
  auth** and the op-log behaves exactly as in `0003` (the existing tests are
  unchanged).
- **Canonical message:** a fixed 5-line ASCII prefix (joined by `\n` = `0x0A`,
  **with** a trailing `\n` after the timestamp) immediately followed by the raw
  request body —
  `MESSAGE = "sigil-oplog-auth-v1\n" + METHOD + "\n" + PATH + "\n" + QUERY + "\n" + TIMESTAMP + "\n" + BODY`
  (uppercase method; path with no query; raw query or `""`; timestamp as unix
  seconds, decimal ASCII; body empty for GET).
- **Headers:** the client sends `X-Sigil-Timestamp` (the same decimal timestamp
  used in `MESSAGE`) and `X-Sigil-Signature` (standard-base64 of the 64-byte
  signature).
- **Verification (both GET and POST):** missing/blank headers → `401`;
  non-integer timestamp or skew `abs(now - ts) > 300s` → `401`; signature that
  does not `ed25519.Verify` against the configured public key → `401`; on
  success, fall through to the normal append/read handler. `401` uses the
  existing typed envelope: `{"error":"unauthorized","detail":"..."}`.
- **CLI key file:** JSON `{"version":1,"seed":"<std-base64 32B>","public_key":"<std-base64 32B>"}`,
  written with mode `0600`.

The full byte-for-byte contract and headers are documented in
[`../api.md`](../api.md).

## Consequences

- When enabled, op-log **writes and reads are authenticated**: only a holder of
  the configured device seed can append to or read a vault, closing the
  wide-open dev route for that deployment.
- It is a **single static device key** — there is **no enrollment**, no
  rotation, and no multi-device support; one key gates all vaults.
- Replay is only **window-bounded**: the 300-second skew check bounds but does
  **not** prevent replay, because there is **no nonce/jti store** — a captured
  request replayed inside the window still verifies. Production needs nonce
  tracking.
- It remains **dev-gated and plain-HTTP**: with `SIGILD_OPLOG_PUBKEY` unset the
  route is unauthenticated as before, and even when set it is a localhost-dev
  posture, not a production one. Real auth — full device enrollment, a
  multi-device registry, and JWT bearer tokens (see
  [`../../sigild/internal/auth/`](../../sigild/internal/auth/)) — is still
  **future**.
- The cross-language byte-for-byte message is the load-bearing part: the Go
  verifier and the Rust signer must agree exactly, or every request fails.
- Builds directly on the Phase 11 Ed25519 primitive and the caller-supplied
  entropy boundary ([`0007`](0007-caller-supplied-entropy-in-core.md)); the
  op-log it guards is the one from [`0003`](0003-dev-gated-opaque-op-log.md).
