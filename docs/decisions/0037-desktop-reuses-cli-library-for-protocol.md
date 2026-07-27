# 0037 — The desktop client drives the `sigil-cli` library instead of reimplementing the wire protocol

- **Status:** Accepted — 2026-07.
- **Date:** 2026-07-27
- **Relates to:** [0032](0032-native-desktop-client.md) (the desktop client, which
  already applied "reuse, not reimplementation" to the *container and vault* layer —
  this extends the same rule to the *network* layer),
  [0031](0031-multi-device-auth-model.md) (the contract-v3 message this decision
  refuses to copy a fourth time),
  [0035](0035-device-to-device-vault-sharing.md) (the sharing flow the desktop now
  implements), [0036](0036-browser-sharing-secret-storage.md) (the browsers' answer to
  the storage question the desktop answers differently), and
  [0002](0002-standalone-cli-crate-for-getrandom-isolation.md) (why `cli/` is a
  standalone crate at all).

## Context

Phase 49 had to put the native desktop client on the network: device enrollment,
contract-v3 signed op-log sync, and device-to-device vault sharing. The desktop was the
last client surface without any of it.

The obstacle is not the feature list, it is **the canonical signed message**. Contract
v3 signs a byte string built from the method, path, query, timestamp, nonce, device ID
and body, and enrollment signs a separate challenge. Those bytes already exist in
**three** independent implementations:

- [`../../sigild/internal/api/deviceauth.go`](../../sigild/internal/api/deviceauth.go) — Go, the source of truth;
- [`../../cli/src/lib.rs`](../../cli/src/lib.rs) — Rust, for the `sigil` CLI;
- [`../../sigil-wasm/device-auth.mjs`](../../sigil-wasm/device-auth.mjs) — JS, for the webapp and the extension.

They must stay **byte-identical**, and drift does not fail loudly: a single wrong byte
produces a `401` on every request, indistinguishable from a bad key or a skewed clock.
The only thing holding them together is a set of interop tests. The same is true of the
sharing layer, where a mismatch yields an envelope the other client cannot open.

A fourth copy — Rust again, in `desktop/core` — would have been the obvious way to
write this phase. It would also have been the third place to keep in sync with the Go
source of truth, for a client whose entire justification ([ADR 0032](0032-native-desktop-client.md))
is that it *reuses* `cli/`'s container, vault schema and migration codec rather than
mirroring them.

`cli/` is a standalone crate, but it already exposes a **library target** (`sigil_cli`)
that the desktop core depends on for exactly that reason. The question was whether that
library could carry the network half too.

## Decision

**`desktop/core/src/net.rs` contains no HTTP client, no signing path and no canonical
message. It drives the `sigil-cli` library — the same functions the `sigil` binary
calls — and confines itself to app-level glue.**

1. **Import the protocol, do not restate it.** One `use sigil_cli::{…}` brings in the
   30 symbols the desktop needs: `enroll_device`; `push_op_auth` / `pull_ops_auth`;
   `publish_hybrid_key` / `fetch_hybrid_key`; `put_key_envelope` / `get_key_envelope`;
   `wrap_vault_key` / `unwrap_vault_key`; `grant_vault_access`; `generate_key`,
   `generate_hybrid_identity`, `generate_vault_key`; `load_identity`, `load_key_file`,
   `load_hybrid_secret`, `load_hybrid_public`, `load_keyring`; `save_key`,
   `save_hybrid_secret`, `save_hybrid_public`; `keyring_get` / `keyring_put`;
   `vault_key_fingerprint`; and the types `RequestAuth`, `DeviceIdentity`,
   `VaultKeyring`, `CliError`, plus `VAULT_KEYRING_FILE` and `VAULT_KEY_LEN`.
   `sigil_cli::open_vault` is called by path in `pull_and_adopt`.
2. **Contract selection is the CLI's rule, unchanged**: contract v3 when the identity
   carries a server-assigned device id, legacy v2 when it does not, unsigned when there
   is no identity at all. It is expressed as a two-line match over `RequestAuth`, not as
   a policy of its own.
3. **Accept the CLI's file names and writers**, so the state files are the CLI's files:
   `device.key`, `device.hybrid`, `device.hybrid.pub` and `vault-keys.json`, mode
   `0600`, in a `0700` state directory defaulting to `$HOME/.sigil`.
4. **Write only what cannot be imported, and keep it free of protocol and crypto.** The
   CLI's path-resolution and error-explanation helpers live in
   [`../../cli/src/main.rs`](../../cli/src/main.rs) — the **binary**, not the library —
   so they are not importable. `DeviceConfig` therefore re-derives the same file names,
   and `net_error` maps `CliError` onto typed `DesktopError` variants a UI can act on
   (`Unreachable`, `Unauthenticated` 401, `Forbidden` 403, `MissingOnServer` 404,
   `NotEnabled` 501, `NotEnrolled`, `AlreadyEnrolled`, `NotShared`). That is app
   configuration and UI wording, nothing else.
5. **`cli/` is not edited to make this work.** The dependency runs one way.

## Consequences

### Good

- **The canonical message stays at three implementations.** The client surface count
  grew to four without growing the number of places a `401`-shaped bug can hide, and
  without adding a fourth interop test to keep two byte strings equal.
- **The desktop cannot drift from the CLI.** Not "is tested against" — *cannot*: it
  executes the same code. Composition rules that matter for security come along for
  free, notably [ADR 0035](0035-device-to-device-vault-sharing.md)'s wrap → deposit →
  **then** grant ordering, and the rejection of any recovered plaintext that is not
  exactly 32 bytes.
- **The state files are interchangeable.** Point `sigil --key` (or `HOME`) at a desktop
  state directory and the CLI *is* the same device: same identity, same hybrid identity,
  same keyring. Two client surfaces, one device record on the server.
- **The phase was small enough to verify.** What had to be reviewed was a seam and an
  error mapping, not a protocol — and the protocol half was already covered by the CLI's
  own tests.
- **It is proven end to end anyway.** `desktop/core/tests/server_interop.rs` boots a real
  `sigild`, builds the real `sigil` binary and shares a vault both ways, so the reuse
  claim is demonstrated rather than asserted.

### Bad / accepted costs

- **A GUI application now depends on a CLI crate.** `sigil-cli` was written as a
  pre-audit demo CLI; its library target is now a de-facto client SDK for the desktop,
  which constrains what can be changed there. A future refactor should extract a
  `sigil-client` crate that both consume — this decision deliberately does **not** do
  that, because extracting a shared crate mid-phase would have touched `cli/`.
- **The desktop inherits the CLI's storage model, weaknesses included.** The device
  seed, the hybrid secret and the vault keyring are `0600` **plaintext** files. That is
  **weaker at rest than the browser clients**, which seal the same secrets into a
  `SIGILcli` container ([ADR 0036](0036-browser-sharing-secret-storage.md)). Nothing is
  zeroized on either side.
- **Interchangeable state files are also a shared blast radius.** A corrupted or stolen
  `$HOME/.sigil` compromises both clients at once, and either can rewrite the other's
  identity.
- **`getrandom` comes along with it.** The desktop links native entropy through
  `sigil-cli`, which is fine because `desktop/` is its own cargo workspace with its own
  lockfile — but it is one more reason `libsigil/Cargo.lock` must keep asserting
  `getrandom == 0`.
- **Nothing here improves the protocol.** Every limit of contract v3 and of sharing
  applies unchanged, including the absence of out-of-band verification for a published
  hybrid public key. Still dev-gated, loopback, plain HTTP, **UNAUDITED**.

### Alternatives rejected

- **Reimplement the protocol in `desktop/core`.** The obvious path, and the reason this
  ADR exists. Rejected: a fourth copy of a byte string that fails silently, in the one
  client whose stated purpose is reuse.
- **Extract a shared `sigil-client` crate now.** The better long-term shape, and the
  likely successor to this decision. Rejected for this phase: it would have required
  editing `cli/` and re-verifying the CLI's own protocol tests, turning a client phase
  into a refactor phase.
- **Shell out to the `sigil` binary.** Zero drift, but it would make a GUI depend on a
  binary being installed and on parsing human-readable stdout, and would put secrets on
  a command line.
- **Speak the protocol from the webview in JS** (reusing `device-auth.mjs` /
  `sharing.mjs`). Rejected: it would move key material and signing into the webview,
  destroying the trust boundary [ADR 0032](0032-native-desktop-client.md) established —
  the webview holds no key material and does no cryptography.
