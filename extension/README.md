# extension — the Sigil browser extension (MV3, **dev / UNAUDITED**)

> **PRE-AUDIT DEVELOPMENT BUILD.** The cryptography here has **not been audited
> by anyone**. This extension is **not published to any store** and is loaded
> unpacked, by hand, for development only. **Do NOT store real 2FA secrets in
> it.** No security claims are made — see
> [`web/apps/marketing/MARKETING-CLAIMS.md`](../web/apps/marketing/MARKETING-CLAIMS.md).

A Manifest V3 browser extension whose popup is a **multi-account encrypted TOTP
vault**, running the `libsigil` core as **WebAssembly, entirely inside the
extension page**. It is the third client surface over the same core, after the
CLI (`cli/`) and the webapp (`web/apps/webapp/`).

The vault is sealed into the **same `SIGILcli` container** the CLI and the webapp
use (Argon2id → XChaCha20-Poly1305 over a `TotpVault` JSON), so a vault created
here stays **cross-client interoperable**. This directory adds **no cryptography
and no vault/migration logic of its own**: it vendors the wasm bindings and the
proven, framework-free helpers from the repo-root `sigil-wasm/` and glues them to
a UI.

## Layout

```
extension/
  manifest.json              MV3 manifest (source)
  build.sh                   builds the wasm + vendors it into vendor/  (run this first)
  src/popup/
    popup.html               setup / locked / unlocked views
    popup.css                plain CSS, no framework
    popup.js                 UI glue: state machine, chrome.storage, rendering
  tests/extension.spec.mjs   headless Playwright proof (loads the REAL extension)
  playwright.config.mjs
  package.json               one devDependency: @playwright/test
  vendor/                    GENERATED, gitignored — never committed
```

There is **no background service worker**, no content script, and no options
page: the MVP does not need them, so they are not declared.

### Permissions

`"permissions": ["storage"]` — nothing else. **No host permissions, no `tabs`,
no `clipboardWrite`** (copy-to-clipboard uses the in-page clipboard API with a
`document.execCommand` fallback, neither of which needs a permission).

The MV3 CSP is widened by exactly one keyword so the core can be instantiated:

```json
"content_security_policy": {
  "extension_pages": "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'"
}
```

The manifest also pins a `key` — a **public** RSA key (no private half exists in
this repo, and none is needed for an unpacked load). It fixes the unpacked
extension ID to `pfjbkipclodhghopppjjgnlbhkmhlekp`, which is what lets the
headless test address `chrome-extension://<id>/…` without a background service
worker to read the ID from. It is not a secret and not a signing key.

## Build order

`build.sh` is the only build step (there is no bundler — the popup is plain ESM):

```bash
./extension/build.sh
```

It (1) runs the repo-root `sigil-wasm/build-wasm.sh` (wasm-pack 0.13.1,
`--target web`) and (2) copies into `extension/vendor/`:

| vendored file                          | from                              |
| -------------------------------------- | --------------------------------- |
| `sigil_wasm.js`, `sigil_wasm_bg.wasm`  | `sigil-wasm/pkg-web/` (generated) |
| `totp-vault.mjs`, `totp-migration.mjs` | `sigil-wasm/` (verbatim copies)   |

After that the directory is self-contained. Load it in Chrome/Edge/Brave via
`chrome://extensions` → **Developer mode** → **Load unpacked** → pick
`extension/`. `vendor/` is a build artifact and is **gitignored**; the extension
*source* is committed.

`popup.js` hands the loader an explicit
`chrome.runtime.getURL("vendor/sigil_wasm_bg.wasm")`, so the `.wasm` resolves
inside the extension package regardless of how the page was reached.

## What the popup does

- **State machine** — `setup` (create a vault password) → `unlocked`, or
  `locked` → `unlocked` when a sealed vault already exists. Mirrors the webapp.
- **Storage** — `chrome.storage.local` holds **only** the sealed container
  (base64) under `sigil.extension.vault.v1`. The **password lives only in
  memory** and is never persisted; closing the popup re-locks the vault. Salt and
  nonce come from `crypto.getRandomValues` (the core draws no entropy and reads
  no clock).
- **Unlocked view** — every account with its issuer/label, the **live
  wasm-computed code**, and a per-period countdown refreshed once a second.
  Clicking a code copies it.
- **Add** — from a base32 secret (with algorithm/digits/period), from an
  `otpauth://` URI, or by importing a Google Authenticator
  `otpauth-migration://offline?data=…` bulk export.
- **Remove**, **Lock**, and **Forget this vault** (deletes the sealed container).
- **Export** — `otpauth://` URIs or one combined `otpauth-migration://` URI,
  behind a loud warning: **export reveals the secrets in the clear** (that is the
  plaintext provisioning form, by design, so migrating away is always possible).

## TEST HOOK: pinning the clock

`popup.html?t=<unix-seconds>` **pins** the clock to that instant and stops the
1 s tick, so codes are deterministic and a headless test can assert an exact
RFC 6238 vector. Without `?t=` the popup uses the live wall clock. This is a
development affordance only — it changes the displayed time, never the vault.

## Headless proof

```bash
corepack pnpm -C extension install
corepack pnpm -C extension test        # `pretest` runs build.sh first
```

`tests/extension.spec.mjs` launches a **real Chromium with the unpacked
extension loaded** — `chromium.launchPersistentContext(…, { channel: "chromium",
headless: true, args: ["--disable-extensions-except=…", "--load-extension=…"] })`
— and drives `chrome-extension://<id>/src/popup/popup.html?t=59`. (`channel:
"chromium"` matters: the headless *shell* cannot load extensions; the full
browser in the new headless mode can.) Nothing is stubbed: the real MV3 CSP, the
real `chrome.storage.local`, and the real wasm are exercised.

It asserts:

1. the wasm instantiates inside the extension page, and the UNAUDITED banner is
   shown;
2. creating a vault, then adding the **public** RFC 6238 seed
   `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ` at the pinned `t=59`, displays exactly
   **`287082`** (the 6-digit form of the RFC's 8-digit `94287082`) with a `1s`
   countdown;
3. `chrome.storage.local` contains **only** the sealed container — no plaintext
   secret, label, or password;
4. a fresh popup boots **locked**, a wrong password is rejected, and the right
   one restores the persisted account and the same code;
5. the `otpauth://` and `otpauth-migration://` import paths and the export
   round-trip work, and removal re-seals the vault.

## Status / non-goals

- **Dev-only, unpublished, UNAUDITED.** Not signed, not in any store.
- The reserved-stub ambitions (phishing protection, passkey provider, content
  scripts) are **not** implemented here; this phase delivers the authenticator
  surface only.
- No sync: the extension does not talk to `sigild`. The vault is local to the
  browser profile.
- Codes are **generated**, not verified; there is no constant-time comparison or
  zeroization.
