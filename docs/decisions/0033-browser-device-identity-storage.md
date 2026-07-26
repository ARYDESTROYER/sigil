# 0033 — Browser device-identity storage (sealed in a second `SIGILcli` container)

- **Status:** Accepted — 2026-07.

## Context

[ADR 0031](0031-multi-device-auth-model.md) gave `sigild` a multi-device auth model
(contract v3), and Phase 42 taught the `sigil` CLI to speak it. Phase 44 extends that
to the browser clients: `web/apps/webapp` and the MV3 `extension/` now enroll and sign
through [`../../sigil-wasm/device-auth.mjs`](../../sigil-wasm/device-auth.mjs), over
three new wasm exports (`ed25519_public_key` / `ed25519_sign` / `ed25519_verify`) that
thinly wrap `sigil-core`'s Ed25519.

That raises a question the CLI never had to answer. A device identity is
`{device_id, seed}`, and the **32-byte Ed25519 seed is secret signing key material**:
anything holding it can sign requests as that device. The CLI writes it to a `0600`
file in `$HOME/.sigil/` and leans on filesystem permissions. **A browser has no
equivalent.** `localStorage` and `chrome.storage.local` are plaintext key-value stores
readable by anything with the origin (or the extension profile directory), and there
is no OS keychain binding available to a plain web page.

Three options were on the table:

1. **Plaintext in web storage** — write the raw seed next to the sealed vault. Simple,
   and how most demo code does it. It would mean a `localStorage` dump or a copied
   browser profile hands an attacker a working signing key, while the *vault* next to
   it is encrypted — an obviously inconsistent posture.
2. **A field inside the `TotpVault` JSON** — put `device_seed` in the vault, so it
   inherits the vault's encryption for free. But the `TotpVault` / `TotpEntry` schema
   is **mirrored, not shared**, between `cli/src/lib.rs`, `sigil-wasm/totp-vault.mjs`
   and (by path dependency) `desktop/`, and is pinned by cross-client interop tests
   ([ADR 0024](0024-wasm-totp-vault-and-cross-client-totp.md)). Adding a
   browser-only field would either break byte-compatibility or force the CLI, the
   desktop app and the migration codec to carry a field they have no use for.
3. **A second sealed container** — seal the identity separately, under the same
   password, using the machinery that already exists.

## Decision

**A browser client persists its device identity ONLY as a second `SIGILcli`
container, sealed under the same vault password. The raw seed is never written to web
storage, and the `TotpVault` JSON schema is left untouched.**

- **Second container, same format.** `sealDeviceIdentity` / `openDeviceIdentity` in
  `device-auth.mjs` seal and open a small JSON document —
  `{version, device_id, seed, base_url}` (`DEVICE_IDENTITY_VERSION = 1`, `seed` as
  standard base64) — through the same wasm `seal_to_container` / `open_container`
  path the vault uses (Argon2id → XChaCha20-Poly1305), with a fresh salt and nonce
  from `crypto.getRandomValues` per seal. All crypto happens inside the wasm; the
  module performs none.
- **Sealed-only persistence, one key per client.** The webapp writes the base64
  container to `localStorage` key **`sigil.webapp.device.v1`**; the extension writes
  it to `chrome.storage.local` key **`sigil.extension.device.v1`**. Nothing else about
  the identity is stored.
- **Same password, same lifecycle as the vault.** The identity is unsealed with the
  password the user already typed to unlock the vault, so it becomes available exactly
  when the vault does. A container that will not open (e.g. sealed under an older
  password) is treated as **"no device"** rather than blocking the unlock.
- **The seed is memory-only while unlocked.** It is held in component state /
  module state for the unlocked session; **Lock**, reload and tab close drop it, and
  **Forget** deletes the sealed identity container outright.
- **The enrollment token is never stored.** It is a single-use bearer secret: sent in
  `X-Sigil-Enroll-Token`, cleared from the input and from memory immediately after
  the attempt, and never logged.
- **`device-auth.mjs` itself persists nothing.** Storage is the caller's decision; the
  module only offers the seal/open helpers. That keeps the same source usable
  unchanged in Node (where the interop test drives it), in the webapp, and in the
  vendored extension copy.

## Consequences

### Good

- **No plaintext signing key at rest in a browser.** An attacker with offline access
  to a `localStorage` dump, a stolen backup, or a copied extension profile gets
  ciphertext; unsealing costs the same Argon2id work as the vault. The key and the
  secrets it guards now have a **consistent** at-rest posture.
- **The mirrored `TotpVault` schema stays byte-compatible.** The CLI, the desktop app
  and the migration codec are untouched, and the existing cross-client vault interop
  tests keep passing unchanged.
- **No new format and no new crypto.** This reuses the proven `SIGILcli` container
  ([ADR 0020](0020-shared-client-container-format.md)) and the same persistence model
  the vault already uses ([ADR 0028](0028-webapp-vault-persistence-and-unlock.md)), so
  there is nothing new for an audit to review beyond one more use of an existing seal.
- **Proven, not asserted.** `sigil-wasm/test/device-auth-interop.mjs` asserts against
  a live server that the identity round-trips through the sealed container, that the
  stored blob does **not** contain the seed, and that a wrong password cannot open it.

### Bad / honest limitations

- **The identity is only usable while the vault is unlocked.** Sync cannot run in the
  background, on a timer, or from a service worker: no password in memory means no
  seed, which means nothing can be signed. This is a real functional cost, accepted
  deliberately.
- **Forgetting the vault destroys the device identity.** Forget deletes both
  containers, and a lost password makes the sealed identity unrecoverable exactly as
  it makes the vault unrecoverable. Recovery means an operator revoke plus a fresh
  enrollment token — there is no key rotation or re-enrollment flow.
- **The seed is exposed in memory while unlocked.** Signing requires it. There is no
  zeroization, no `mlock`, no secure enclave: anything that can run script in the
  client's context while unlocked can read it, sign as that device, or capture the
  password as it is typed. Sealing defends the **stored** key, not a live process.
- **The MV3 extension needed a host permission.** Extension pages cannot `fetch`
  cross-origin without one, so `manifest.json` now declares
  `"host_permissions": ["http://127.0.0.1/*", "http://localhost/*"]` — an honest
  expansion of a previously host-permission-free extension. It is deliberately
  **loopback-only** (with an explanatory comment in the manifest) so this build cannot
  reach a remote server; `"permissions"` is still `["storage"]` alone.
- **Two containers, two seals.** The identity is re-sealed whenever it changes and
  opened on every unlock, so an unlock now performs two Argon2id derivations. At
  interactive parameters this is acceptable; it is still real work.
- **Not covered by a browser test.** The enrollment UI in both clients has **no**
  Playwright coverage. The protocol and the sealed-identity round-trip are proven live
  in Node; the existing UI suites still pass and assert no page errors.
- **Still dev / UNAUDITED / plain HTTP.** This is storage for a **dev** op-log
  identity, not the product's key-management model, and nothing here has been audited.

### Neutral

- `DEVICE_IDENTITY_VERSION` is a private, client-side schema — unlike `SIGILcli` or
  `TotpVault` it crosses no tool boundary, so it can change without a mirrored update
  anywhere else.
- `base_url` is stored purely as a convenience (which server this identity was
  enrolled with); it is not authenticated and carries no security weight.

## References

- Code: [`../../sigil-wasm/device-auth.mjs`](../../sigil-wasm/device-auth.mjs)
  (`sealDeviceIdentity` / `openDeviceIdentity`, `DEVICE_IDENTITY_VERSION`),
  [`../../sigil-wasm/src/lib.rs`](../../sigil-wasm/src/lib.rs) (`ed25519_public_key` /
  `ed25519_sign` / `ed25519_verify`),
  [`../../web/apps/webapp/app/authenticator.tsx`](../../web/apps/webapp/app/authenticator.tsx)
  (`DEVICE_KEY`, `persistDevice` / `loadDevice`),
  [`../../extension/src/popup/popup.js`](../../extension/src/popup/popup.js)
  (`DEVICE_KEY`, `persistDevice` / `loadDevice`),
  [`../../extension/manifest.json`](../../extension/manifest.json) (`host_permissions`).
- Test: [`../../sigil-wasm/test/device-auth-interop.mjs`](../../sigil-wasm/test/device-auth-interop.mjs).
- Protocol: [ADR 0031](0031-multi-device-auth-model.md) and
  [`../api.md`](../api.md) — the authoritative HTTP surface.
- At-rest model this extends: [ADR 0028](0028-webapp-vault-persistence-and-unlock.md),
  [ADR 0030](0030-browser-extension-client.md).
- Container format: [ADR 0020](0020-shared-client-container-format.md);
  caller-supplied entropy: [ADR 0007](0007-caller-supplied-entropy-in-core.md).
- Adversaries/defenses: [`../threat-model.md`](../threat-model.md).
