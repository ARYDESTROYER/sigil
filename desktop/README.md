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
    tests/cli_interop.rs   THE INTEROP PROOF (drives the real `sigil` binary)
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

Not implemented: sync (`push`/`pull`), device enrollment, QR scanning, code
verification, hardened zeroization.

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

`cargo test` builds the real `sigil` binary itself, so the interop proof needs no
setup. It takes ~20 s (real Argon2id + a CLI build).

### The interop proof

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
