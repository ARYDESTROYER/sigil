# 0030 — MV3 browser-extension client: a popup authenticator over the vendored wasm

- **Status:** Accepted — 2026-07.

## Context

`extension/` had been a **reserved directory** since the 72-hour sprint. Its README
said so explicitly, and it named the blocker: the extension "depends on
`libsigil-wasm`, not yet available". That blocker is gone. The repo-root
`sigil-wasm` crate now builds a browser wasm package
([ADR 0019](0019-wasm-client-bindings.md)), reads and writes the shared `SIGILcli`
container ([ADR 0020](0020-shared-client-container-format.md)), computes TOTP codes
([ADR 0024](0024-wasm-totp-vault-and-cross-client-totp.md)), and imports/exports
Google Authenticator migrations ([ADR 0026](0026-browser-totp-import-export.md)) —
all through framework-free ESM helpers (`totp-vault.mjs`, `totp-migration.mjs`) that
already have Node interop tests against the real CLI.

Two things made this the right moment to spend the directory:

1. **A second real client is the honest test of the shared-vault architecture.** The
   webapp ([ADR 0027](0027-webapp-and-wasm-bundling.md),
   [ADR 0028](0028-webapp-vault-persistence-and-unlock.md)) proved libsigil runs in a
   browser and that a sealed `SIGILcli` vault survives a lock/unlock cycle. But one
   browser client cannot demonstrate that the vault format, the helpers, and the
   persistence model *generalize*: any accidental coupling to Next.js, to
   `localStorage`, or to a bundler would be invisible with a sample size of one. A
   second surface with a **different runtime** (an MV3 extension page, a different
   storage API, a stricter CSP, no bundler at all) is the cheapest way to find that
   coupling — or to show there is none.
2. **An extension is where an authenticator actually gets used.** A popup one click
   from the login form is the shape of the product; a tab is not.

The constraints were: change **nothing** under `libsigil/`, `cli/`, `sigild/`, or the
repo-root `sigil-wasm/`; add no cryptography; stay dependency-light; and keep the
stealth / pre-audit posture (nothing published, nothing claimed).

## Decision

**Build `extension/` as a Manifest V3 extension whose popup is an encrypted TOTP
vault — vendoring the existing wasm + proven helpers rather than reimplementing them,
persisting ONLY the sealed `SIGILcli` container in `chrome.storage.local` with an
in-memory password, keeping the permission surface minimal, and publishing it to no
store.**

- **MV3, minimal surface.** `manifest.json` declares `"permissions": ["storage"]` and
  **nothing else** — no host permissions, no `tabs`, no `clipboardWrite` (copy uses
  the in-page clipboard API with a `document.execCommand` fallback, neither of which
  needs a permission). There is **no background service worker, no content script,
  and no options page**: the MVP does not need them, so they are not declared. The MV3
  CSP is widened by **exactly one keyword** —
  `script-src 'self' 'wasm-unsafe-eval'; object-src 'self'` — the minimum required to
  instantiate the core. A **public** RSA `key` is pinned in the manifest so the
  unpacked extension ID is deterministic and a headless test can address
  `chrome-extension://<id>/…` without a background worker to read the ID from; no
  private half exists in this repo and it is not a signing key.
- **Vendor the wasm and the proven helpers; do not reimplement.** `extension/build.sh`
  is the only build step (there is no bundler — the popup is plain ESM). It runs the
  repo-root `sigil-wasm/build-wasm.sh` (the single source of truth for how the wasm is
  built, pinning wasm-pack 0.13.1 against the `wasm-bindgen = "=0.2.100"` pin) and
  copies into a gitignored `extension/vendor/`: the wasm-bindgen browser bindings
  (`sigil_wasm.js`, `sigil_wasm_bg.wasm`) plus **verbatim copies** of
  `totp-vault.mjs` and `totp-migration.mjs`, with a `BUILD-INFO.txt` provenance stamp
  so a stale `vendor/` is obvious. `src/popup/popup.js` therefore contains **no
  cryptography and no vault/migration logic** — sealing, opening, and every TOTP code
  happen in the wasm; vault and migration transformations happen in the already-tested
  helpers; the popup is UI glue and storage. A third copy of that logic is exactly
  what we refused to write.
- **The same `SIGILcli` vault, so vaults stay cross-client.** The extension seals the
  same mirrored `TotpVault` JSON into the same Argon2id → XChaCha20-Poly1305 container
  the CLI and the webapp use ([ADR 0020](0020-shared-client-container-format.md),
  [ADR 0023](0023-totp-hotp-primitive-and-cli-vault.md)). No new at-rest format was
  invented for the extension. The container is self-describing, so a vault sealed here
  opens in the CLI and the webapp.
- **Persist only the sealed container; keep the password in memory.** Mirroring
  [ADR 0028](0028-webapp-vault-persistence-and-unlock.md), `chrome.storage.local`
  holds **only** the sealed container (base64) under `sigil.extension.vault.v1`. The
  plaintext vault and the password are **never** written; the password lives in a
  module-local variable that dies with the popup, so closing the popup re-locks the
  vault and a fresh open boots setup / locked / unlocked. Salt and nonce come from
  `crypto.getRandomValues` — the core still draws no entropy and reads no clock
  ([ADR 0007](0007-caller-supplied-entropy-in-core.md)).
- **Dependency-light and store-unpublished.** One devDependency (`@playwright/test`);
  no UI framework, no bundler, no PWA/crypto/protobuf library. The extension is loaded
  **unpacked, by hand**, and is **not signed and not submitted to any store** — the
  same human-gated posture as every other outward-facing step
  ([ADR 0009](0009-manual-gated-deploy-and-publish.md)).
- **Proven in the real extension runtime, not a stub.** `tests/extension.spec.mjs`
  launches a real Chromium with the unpacked extension loaded
  (`chromium.launchPersistentContext(…, { channel: "chromium", headless: true,
  args: ["--disable-extensions-except=…", "--load-extension=…"] })` — the headless
  *shell* cannot load extensions, the full browser in headless mode can) and drives
  `chrome-extension://<id>/src/popup/popup.html?t=59`. A `?t=<unix-seconds>` **test
  hook** pins the clock (and stops the 1 s tick) so an exact RFC 6238 vector can be
  asserted; it changes the displayed time only, never the vault. Nothing is stubbed:
  the real MV3 CSP, the real `chrome.storage.local`, and the real wasm are exercised.

## Consequences

- **The vault stays cross-client interoperable, and that is now demonstrated by a
  third surface.** A `SIGILcli` container written by the extension is the same
  artifact the `sigil` CLI and the webapp read; the mirrored `TotpVault`/`TotpEntry`
  JSON and the container constants gained **another** mirror site to keep in sync (the
  vendored copies are generated, so the sync obligation stays where it already was —
  `cli/src/lib.rs` ↔ `sigil-wasm/`), and the popup itself adds none.
- **A build step now stands between a clone and a loadable extension.** `vendor/` is a
  **generated, gitignored artifact**: `extension/build.sh` must run before the
  directory can be loaded unpacked or tested (`pretest` runs it). That means the
  extension needs the **Rust + wasm-pack toolchain**, exactly like the webapp — it is
  not a pure-JS surface, and a stale `vendor/` is a real failure mode (hence the
  provenance stamp).
- **MV3 constrains the design, permanently.** Running the core requires the
  `'wasm-unsafe-eval'` CSP keyword — a deliberate, minimal widening we accept and
  document. The popup's ephemeral lifetime is what gives us the in-memory-password
  property for free, but it also means there is **no background state**: no timers, no
  sync loop, no fill — those would need a service worker, which the MVP deliberately
  does not declare.
- **Still dev / UNAUDITED, and published nowhere.** The cryptography is the same
  unaudited building blocks; nothing here is reviewed, signed, or listed in any store,
  and no security claim is made (public copy still obeys
  [`../../web/apps/marketing/MARKETING-CLAIMS.md`](../../web/apps/marketing/MARKETING-CLAIMS.md)).
  **Do not store real 2FA secrets.** Codes are **generated**, not verified — there is
  no constant-time comparison and no zeroization; the extension does **not** talk to
  `sigild`, so the vault is local to one browser profile with no sync, enrollment, or
  recovery; a lost password is an unrecoverable local vault by design; and
  `chrome.storage.local` is **not** a hardened secret store. The originally reserved
  ambitions — phishing protection, passkey provider, content scripts — are **not**
  implemented by this phase.
- **No CI job yet.** The Playwright proof runs locally and needs a full Chromium plus
  the Rust/wasm toolchain; it has not been wired into `.github/workflows/`, so — unlike
  the marketing gate — the extension is not exercised by CI at all.
