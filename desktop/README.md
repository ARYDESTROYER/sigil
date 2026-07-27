# `desktop/` — Sigil desktop authenticator (the NATIVE client column)

> # ⛔ PRE-AUDIT · UNAUDITED · DO NOT STORE REAL 2FA SECRETS
>
> This is a **private, pre-launch demonstration build**. The cryptography it uses
> is real but has **not been independently audited**, and nothing here is a
> security guarantee. It is **not signed, not notarized, and not distributed**.
> Use throwaway test secrets only. The brand name is provisional.

## What this is

A **Tauri v2** desktop authenticator: a small Rust backend plus a framework-free
HTML/CSS/JS frontend, wired together by `#[tauri::command]` functions.

It exists to open the client column the repo did not have. The webapp
(`web/apps/webapp`) and the browser extension (`extension/`) both run libsigil
compiled to **WebAssembly**. This app links **`sigil-core` as a plain native Rust
dependency** — there is no wasm anywhere in the loop. That is the whole point: it
exercises a path only `cli/` had exercised before.

`sigil-core` is `no_std` and deliberately reads **no clock and no RNG**, so a
native caller must supply both:

| The core needs | Where the desktop app gets it |
| --- | --- |
| Argon2id salt, AEAD nonce | native `getrandom`, inside `sigil-cli`'s `seal_to_container` |
| current Unix time | `std::time::SystemTime` via `sigil_desktop_core::now_unix`, passed *into* `totp` as a `u64` |

## Reuse, not reimplementation

**No crypto, container format, or vault schema is defined in this directory.**
Everything byte-level is re-used from the existing crates by path dependency:

- `sigil-core` — Argon2id + XChaCha20-Poly1305 record API, and the RFC 4226/6238
  `hotp`/`totp`/`format_code` primitive.
- `sigil-cli` (the **library** target, `sigil_cli`) — the `SIGILcli` container
  (`seal_vault`/`open_vault`), the `TotpVault`/`TotpEntry` JSON schema, base32,
  `otpauth://` parse/build, and the hand-rolled Google Authenticator migration
  codec.

That is precisely why a vault written here opens in the CLI, the webapp and the
extension, and vice versa.

## Layout

```
desktop/
  Cargo.toml          workspace root — OWN Cargo.lock, outside the libsigil workspace
  core/               sigil-desktop-core: ALL the logic, headless + unit-tested
    src/lib.rs        VaultSession: unlock / list+codes / add / import / export / remove
    src/net.rs        enrollment, contract-v3 sync, device-to-device vault sharing
    tests/cli_interop.rs      THE VAULT INTEROP PROOF (drives the real `sigil` binary)
    tests/server_interop.rs   THE NETWORK PROOF (real sigild + the real `sigil` binary)
  src-tauri/          the shell: window + one #[tauri::command] per action
  ui/                 framework-free HTML/CSS/JS (no npm, no bundler, no CDN)
```

The split is deliberate: the GUI cannot be clicked by CI, so **all** behaviour
lives in `core/` where tests can drive it, and `src-tauri/src/main.rs` is thin
glue that only marshals arguments.

## The vault

- **Path:** `$HOME/.sigil/totp-vault.sigil` (falls back to `./totp-vault.sigil`
  when `$HOME` is unset). This is byte-for-byte the `sigil` CLI's default, so the
  two share one vault with no configuration.
- **Format:** a `SIGILcli` container — Argon2id (`RECOMMENDED` work factor) →
  XChaCha20-Poly1305 over the `TotpVault` JSON. Only the **sealed** container is
  ever written.
- **Permissions:** the file is `0600`, the `.sigil` directory `0700`. Writes go to
  a temporary file and are renamed into place, so an interrupted save cannot
  truncate a good vault.
- **Password:** held only in memory for the session and best-effort zeroed on
  drop. It is never persisted, logged, or returned across the IPC. (Best-effort
  means exactly that — no `zeroize` crate, no volatile guarantee, and the OS may
  have paged the buffer.)

## Features

- Create or unlock the vault from a lock screen; **Lock** forgets the password.
- Live account list: issuer/label, the current code, and the seconds remaining in
  the period — computed by `sigil-core`, natively, once per second.
- Add an account from a **base32 secret** (algorithm / digits / period) or from an
  **`otpauth://totp/…` URI**.
- **Import** a Google Authenticator `otpauth-migration://offline?data=…` bulk
  export, a single `otpauth://` URI, or one URI per line. Duplicates are skipped,
  never overwritten; HOTP and invalid entries are skipped and counted.
- **Export** as `otpauth://` URIs or one combined migration URI, behind a loud
  secrets-in-the-clear warning that the Rust side returns *with* the payload so a
  UI cannot drop it.
- Remove an account.
- A loud pre-audit banner, sourced from the same Rust constants the terminal
  prints, so no surface can quietly soften it.
- **Sync & sharing** (optional, see below): enroll this device, publish its
  hybrid public key, push/pull the sealed vault, convert a password vault to a
  shared vault, share it to another device, and accept one shared here.

Not implemented: QR scanning, code verification, hardened zeroization, multi-vault
UI (the app operates on one vault file at a time).

## Sync & sharing

Entirely **optional**. With no server configured the app never touches the
network and everything above behaves exactly as it did before.

Like the vault format, none of this is reimplemented: `core/src/net.rs` drives the
**`sigil-cli` library** — `enroll_device`, `push_op_auth` / `pull_ops_auth`,
`publish_hybrid_key` / `fetch_hybrid_key`, `put_key_envelope` / `get_key_envelope`,
`wrap_vault_key` / `unwrap_vault_key` and `grant_vault_access` — so there is **no
second HTTP client, no second signing path, and no second copy of the canonical
contract-v3 message** in this directory.

### Device state on disk (the native model, identical to the CLI's)

| File | Holds | Mode |
| --- | --- | --- |
| `$HOME/.sigil/device.key` | Ed25519 seed (SECRET) + assigned device id | `0600` |
| `$HOME/.sigil/device.hybrid` | X25519 secret + ML-KEM-768 keygen seed (SECRET) | `0600` |
| `$HOME/.sigil/device.hybrid.pub` | public halves only | default |
| `$HOME/.sigil/vault-keys.json` | vault id → 32-byte vault key (SECRET) | `0600` |

…all inside a `0700` directory. These are the CLI's own types written by the CLI's
own writers, so the files are **interchangeable**: point `sigil --key` (or `HOME`)
at this directory and the CLI *is* the same device.

Nothing here ever prints, logs or returns a seed, a vault key or an enrollment
token — only SHA-256 **fingerprints** and opaque device ids. The enrollment token
crosses the IPC once, is used for that one call, and is never stored.

### The key model

- A **personal** vault stays sealed under your password.
- A **shared** vault is sealed under a **random 32-byte vault key** (the `SIGILcli`
  container takes arbitrary secret bytes, so no format change). *Convert to
  shared* is the explicit, one-way door.
- That key is wrapped **per recipient** with the PQ-hybrid seal (X25519 +
  ML-KEM-768) and relayed as opaque ciphertext. **Your password is never shared,
  wrapped or uploaded.**

The server stores sealed containers and wrapped keys it cannot read.

### Failure modes are shown, never swallowed

Every server error reaches the UI tagged: `unauthenticated` (401), `not
authorized` (403), `route disabled` (501), `nothing there` (404), `server
unreachable`, `not enrolled`, `not a shared vault`. Nothing panics, nothing
silently no-ops, and the offline flow keeps working with the server down.

**Dev only**: sigild's sync, device and sharing routes are dev-gated, plain HTTP
and localhost. Do not point this at a remote host.

## Trust boundary

The webview holds **no** key material and does **no** cryptography. The password
crosses the IPC once at unlock; codes arrive already computed. The Tauri
capability file grants `core:default` and nothing else — no `fs`, `shell`, `http`
or `dialog` plugin — so the frontend can only reach the disk through the explicit
commands in `src-tauri/src/main.rs`.

## Build & test

Put the toolchain on `PATH` first (this machine has no `~/.cargo/bin` proxies):

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/opt/homebrew/bin:$PATH"

cargo fmt   --manifest-path desktop/Cargo.toml --all -- --check
cargo clippy --manifest-path desktop/Cargo.toml --all-targets -- -D warnings
cargo test  --manifest-path desktop/Cargo.toml       # unit tests + THE INTEROP PROOF
cargo build --manifest-path desktop/Cargo.toml --release
./desktop/target/release/sigil-desktop                # opens the window (needs a GUI session)
```

`cargo test` builds the real `sigil` binary **and a real `sigild`** itself, so the
proofs need no setup. Allow ~40 s (two real builds + real Argon2id + a live
server). `sigild` is built with `/opt/homebrew/bin/go` (override with `GO=…`).

### The vault interop proof

`desktop/core/tests/cli_interop.rs` proves the headline claim without a human:

1. **Desktop → CLI.** The desktop code creates the vault and adds two accounts.
   The real `sigil totp list` sees them, `sigil totp code` prints the same code
   the desktop computed, and `sigil totp export` prints the same `otpauth://` URI.
2. **CLI → Desktop.** `sigil totp add` appends an account to that *same* file; the
   desktop code re-unlocks it and reproduces the CLI's code, issuer and algorithm.
3. A desktop-generated `otpauth-migration://` URI imports cleanly into `sigil totp
   import`.

**Pinning the clock.** `sigil totp code` reads the host clock and has no `--at`
flag, so the exact assertions use an account with `period = u32::MAX` (~136
years): its TOTP counter is `floor(now / period) = 0` for any date before 2106, so
the code is a constant two independently-clocked processes must agree on. The
ordinary 30 s account is cross-checked with a bounded retry that tolerates a step
boundary landing between the two processes.

### The network proof

`desktop/core/tests/server_interop.rs` boots a **real sigild** (dev-ops +
multi-device auth, contract v3) on a free loopback port, builds the **real `sigil`
binary**, and proves the desktop is a peer:

1. **(a) desktop → CLI.** The desktop enrolls, publishes its hybrid public key,
   creates a vault holding the RFC 6238 seed, converts it to a shared vault,
   pushes it, and shares it to an enrolled CLI device — and the real `sigil`
   binary accepts, pulls and prints `94287082`.
2. **(b) CLI → desktop.** The CLI re-keys and shares a vault to the desktop
   device; the desktop accepts, pulls and computes the same code. Both sides
   report the *same* key fingerprint.
3. **(c) negatives.** An unauthorized third device gets **403**; an unenrolled
   desktop gets a clear `NotEnrolled` error, not a panic; with the server
   unreachable the push reports `Unreachable` and the offline flow still
   generates codes.
4. **Opacity.** The bytes the CLI pulled are byte-identical to the bytes the
   desktop pushed and contain neither the seed nor the label.

The server is killed and every temp file removed in a `Drop` guard, so an
assertion failure still tears the world down.

**Pinning the clock, again.** RFC 6238 Appendix B's `T = 59` is TOTP counter
`floor(59/30) = 1`, so any period `P` with `floor(now/P) == 1` yields the same
published code. `P = 1_600_000_000` satisfies that from 2020 until 2071 — which is
why two independently-clocked processes must both print exactly `94287082`.

Correctness of the code path itself is pinned by an RFC 6238 Appendix B
known-answer test in `core/src/lib.rs`: seed ASCII `12345678901234567890`, `T=59`,
period 30 → `94287082` (8 digits) / `287082` (6 digits).

## Lockfile invariant

This workspace is **intentionally outside** the `libsigil/` cargo workspace and
carries its own `desktop/Cargo.lock`, exactly like `cli/` and `sigil-wasm/`. That
is what lets it depend on native-only crates (Tauri's platform stack, `getrandom`
via `sigil-cli`) without ever perturbing `libsigil/Cargo.lock`, which **must** stay
`getrandom`-free so `sigil-core` keeps compiling to `wasm32-unknown-unknown`:

```bash
grep -c 'name = "getrandom"' libsigil/Cargo.lock   # must STILL be 0
```

## Licence

Apache-2.0 OR MIT, matching the other client surfaces.
