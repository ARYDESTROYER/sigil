# 0032 — Native desktop client: a Tauri v2 shell over a headless core crate

- **Status:** Accepted — 2026-07.

## Context

Three client surfaces existed before this decision, and **every one of them was
either a terminal or a browser**:

- `cli/` — the `sigil` binary: native, but a terminal tool
  ([ADR 0023](0023-totp-hotp-primitive-and-cli-vault.md),
  [ADR 0025](0025-totp-import-export.md));
- `web/apps/webapp` — a Next.js app running `sigil-core` compiled to **WebAssembly**
  ([ADR 0027](0027-webapp-and-wasm-bundling.md),
  [ADR 0028](0028-webapp-vault-persistence-and-unlock.md),
  [ADR 0029](0029-webapp-pwa-offline-a11y-and-ci.md));
- `extension/` — an MV3 popup, also **WebAssembly**
  ([ADR 0030](0030-browser-extension-client.md)).

The **native GUI column was empty**. That matters for a product whose stated shape
is "multi-platform authenticator": the repo could demonstrate that the core runs in
a browser, but nothing demonstrated that a *native application* could link the core
directly, hold a vault, and stay honest about the trust boundary. `README.md` said
native clients "live in separate repositories"; none existed.

It also matters *architecturally*. `sigil-core` is `no_std`, RNG-free and
clock-free by design ([ADR 0007](0007-caller-supplied-entropy-in-core.md)), and
every graphical consumer so far reached it through the same wasm binding. A second
consumer that reaches it a **different way** is the cheapest available test of
whether the caller-supplies-entropy-and-time contract is a real interface or an
accident of the wasm path. Routing a native desktop app through wasm would have
tested nothing new — it would have been a re-skin of the browser clients, carrying a
wasm toolchain (wasm-pack, the `target_features`/`externref` strip) for no benefit
on a platform that can link Rust directly.

Constraints going in: change **nothing** under `libsigil/`, `cli/`, `sigild/`, or
the repo-root `sigil-wasm/`; add no cryptography and no new at-rest format; and
preserve the mechanical lockfile invariant that keeps the audit-bound core
wasm-pure (`grep -c 'name = "getrandom"' libsigil/Cargo.lock` == `0`,
[ADR 0002](0002-standalone-cli-crate-for-getrandom-isolation.md)).

## Decision

**Build `desktop/` as a Tauri v2 application whose logic lives in a separate
headless crate, linking `sigil-core` natively and re-using `cli/` for every
byte-level format.** Five parts:

1. **Two crates, logic split from shell.**
   - **`sigil-desktop-core`** (`desktop/core`) holds **all** the authenticator
     logic, headless: `VaultSession` (`create` / `unlock` / `open_or_create` /
     `entries_at` / `entries_now` / `add_secret_base32` / `add_uri` / `import_text` /
     `import_file` / `remove` / `export_uris` / `export_migration_uri` / `save`),
     the `EntryView` and `ImportSummary` view models, `DesktopError`, `now_unix`,
     `default_vault_path`, and the `BANNER_TITLE` / `BANNER_BODY` / `EXPORT_WARNING`
     constants. It is `#![forbid(unsafe_code)]` and `#![deny(missing_docs)]`.
   - **`sigil-desktop`** (`desktop/src-tauri`) is a thin shell: a window, a
     `Mutex<Option<VaultSession>>` app state, and **ten `#[tauri::command]`s**
     (`status`, `unlock`, `lock`, `list`, `add_secret`, `add_uri`, `import`,
     `remove`, `export_uris`, `export_migration`) that only marshal arguments.
   - `desktop/ui` is framework-free HTML/CSS/JS — **no npm, no bundler, no CDN**.

   The split is the point: a GUI cannot be clicked by a test runner, so everything
   that could be wrong lives where a test *can* drive it.

2. **Link `sigil-core` natively — no wasm anywhere in this column.** `desktop/`
   contains no `wasm-bindgen`, no `wasm-pack`, and no `.wasm`. The core still reads
   no clock and no RNG, so the native app supplies both: **entropy** through
   `sigil-cli`'s native `getrandom` path inside `seal_to_container`, and the
   **clock** via `std::time::SystemTime` in `sigil_desktop_core::now_unix`, passed
   *into* the core's `totp` as a `u64`.

3. **Re-use `cli/`; reimplement nothing.** `sigil-desktop-core` path-depends on
   `sigil-core` **and on the `sigil-cli` library target**, and takes from it the
   `SIGILcli` container (`seal_vault` / `open_vault`), the `TotpVault` / `TotpEntry`
   JSON schema and `TotpEntry::code_at`, `base32_decode`, `new_totp_entry`,
   `totp_algorithm_from_str`, `parse_otpauth_uri` / `entry_to_otpauth_uri`, and the
   Google Authenticator migration codec (`decode_migration_uri` /
   `encode_migration_uri` / `entry_to_migration_otp` / `migration_otp_to_entry`).
   There is **no hand-rolled HMAC/SHA, no fourth container format, and no mirrored
   schema to keep in sync** — unlike the deliberate Rust↔JS mirrors of
   [ADR 0020](0020-shared-client-container-format.md) and
   [ADR 0026](0026-browser-totp-import-export.md), this column consumes the Rust
   definitions directly.

4. **Share the CLI's vault path.** The default vault is
   `$HOME/.sigil/totp-vault.sigil` (falling back to `./totp-vault.sigil` when
   `$HOME` is unset) — byte-for-byte the `sigil` CLI's default, so the desktop app
   and the CLI open the **same file** with no configuration. Only the **sealed**
   container is ever written; the directory is `0700` and the file `0600`, and
   `save()` writes a temporary file and renames it into place so an interrupted save
   cannot truncate a good vault. The password is held in memory for the life of a
   `VaultSession` and best-effort zeroed in `Drop`; it is never persisted, logged, or
   returned across the IPC.

5. **Keep `desktop/` outside the `libsigil` workspace, and the webview
   capability-minimal.** `desktop/` is its own cargo workspace with its own
   `desktop/Cargo.lock` (members `core` + `src-tauri`), exactly like `cli/` and
   `sigil-wasm/` — so Tauri's platform stack and the native `getrandom` reached
   through `sigil-cli` can never enter `libsigil/Cargo.lock`. On the trust boundary:
   the webview holds **no** key material and does **no** cryptography (the password
   crosses the IPC once at unlock; codes arrive already computed), and
   `desktop/src-tauri/capabilities/default.json` grants **`core:default` and nothing
   else** — no `fs`, `shell`, `http` or `dialog` plugin — so the frontend reaches
   disk only through the explicit commands. The export commands return
   `EXPORT_WARNING` **together with** the payload, so a UI cannot render the secrets
   without the warning.

Features shipped: create / unlock / lock an encrypted vault; a live account list
(issuer/label, current code, seconds remaining, recomputed roughly once a second);
add from a base32 secret with algorithm/digits/period; add from an `otpauth://` URI;
import a Google Authenticator `otpauth-migration://` bulk export; remove; and export
`otpauth://` URIs or one combined migration URI behind the loud warning. A pre-audit
banner is rendered in the window **and** printed to stderr at startup from the same
Rust constants.

## Consequences

**What this buys.**

- The **native client column is open**, and the caller-supplied-entropy/time
  contract is now exercised by a second, non-wasm consumer.
- **Vaults are genuinely interoperable across process boundaries**, proven rather
  than asserted: `desktop/core/tests/cli_interop.rs` builds the **real `sigil`
  binary** and drives it as a subprocess against **one shared vault file**, both
  directions — a desktop-created vault is read by `sigil totp list` / `totp code` /
  `totp export` with byte-identical agreement, `sigil totp add` appends to that same
  file and the desktop code reopens it and reproduces the CLI's code, issuer,
  algorithm and digits, and a desktop-generated migration URI imports via `sigil
  totp import`. The RFC 6238 Appendix B known-answer test in `desktop/core/src/lib.rs`
  pins the native code path itself (`T=59` → `94287082` at 8 digits, `287082` at 6).
- **No new at-rest format and no new mirror to maintain** — the desktop column is a
  consumer of `cli/`'s definitions, not a second copy of them.
- The wasm-pure core invariant is mechanically preserved: `libsigil/Cargo.lock`'s
  `getrandom` count is still `0`, and `desktop/` is not a `libsigil` workspace member.

**Costs and honest caveats — all of these hold today.**

- **The GUI is build-and-launch verified, not visually verified.** Screen capture is
  denied in this environment, so there is **no screenshot proof** of the rendered
  window. What was verified is that a release build succeeds, that launching the
  binary keeps the process alive with the event loop running, and that it prints the
  pre-audit banner. This is exactly why all behaviour lives in the headless crate
  where tests drive it — but the pixels themselves are unproven here.
- **No bundle, no signing, no notarization, no distribution.** `tauri build` (the
  `.app` bundler) was **not** run; the applicable build is
  `cargo build --release --manifest-path desktop/Cargo.toml`, which produces an
  ~8.6 MB native binary. The app is **not signed, not notarized, and not
  distributed**.
- **The interop test pins the clock with a deliberate artifice.** `sigil totp code`
  reads the host clock and has no `--at` flag, so for exact cross-process equality
  the test uses an account with `period = u32::MAX`: its TOTP counter is
  `floor(now / period) = 0` for any date before ~2106, making the code a constant
  that two independently-clocked processes must agree on. **That is a test artifice,
  not product behaviour.** An ordinary 30 s account is also checked, with a bounded
  retry that tolerates a step boundary landing between the two processes.
- **Password zeroing is best-effort.** `Drop` overwrites the buffer; there is no
  `zeroize` crate, no volatile guarantee, and the OS may already have paged it.
  Documented, not claimed.
- **Still pre-audit and UNAUDITED.** Real cryptography, no independent review, no
  security claim. **Do not store real 2FA secrets.**
- **This is one native surface, not the native story.** macOS is where it was built
  and launched; Windows and Linux are untried from here, and **mobile (iOS/Android)
  remains unbuilt**. There is also no sync (`push`/`pull`), no device enrollment, no
  QR scanning, no code verification, and no hardened zeroization in this column.
