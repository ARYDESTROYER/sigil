# 0028 — Webapp vault persistence and password-unlock model

- **Status:** Accepted — 2026-07.

## Context

[ADR 0027](0027-webapp-and-wasm-bundling.md) turned `web/apps/webapp` into a real
Next.js app running the libsigil core via WebAssembly, but its page was only a
**live TOTP view** of one hard-coded RFC test seed — stateless, single-account,
nothing persisted. To be a real (dev) authenticator, the app needs to hold a
**user's multiple accounts** and keep them **across page reloads**, because a
2FA app that forgets every account on refresh is useless.

The webapp has **no backend** it can trust with secrets: there is no account,
device-enrollment, or sync-auth model yet (the dev op-log is opaque and, by
default, unauthenticated). So "persist the accounts" has to mean "persist them in
the browser" — and the only broadly-available browser persistence is
`localStorage` / `IndexedDB`, neither of which is a hardened secret store. We must
persist enough to survive a reload **without** writing TOTP secrets to disk in the
clear, and without inventing a new key-management scheme or a new on-disk format.

Everything needed to do this already exists and is proven: the `sigil-core` seal
(Argon2id → XChaCha20-Poly1305), the **`SIGILcli`** sealed-container format, and
the `TotpVault` JSON schema — all mirrored between the CLI and the browser JS
helpers and covered by cross-client interop tests
([ADR 0020](0020-shared-client-container-format.md),
[ADR 0023](0023-totp-hotp-primitive-and-cli-vault.md),
[ADR 0024](0024-wasm-totp-vault-and-cross-client-totp.md)).

## Decision

**Persist ONLY the `SIGILcli`-sealed vault container in `localStorage`; keep the
password in memory; and unlock by opening the container. Reuse the existing sealed
vault format so the persisted vault stays cross-client-interoperable, and draw all
entropy from `crypto.getRandomValues`.**

- **Store the sealed container, nothing else.** The plaintext `TotpVault` and the
  password are **never written to disk**. The single `localStorage` key
  `sigil.webapp.vault.v1` holds only the base64 of the sealed `SIGILcli`
  container. Every vault mutation (add / import / remove) applies to an in-memory
  clone, **re-seals** it with a fresh salt + nonce, and rewrites that one key — a
  rejected mutation (e.g. a duplicate label) throws **before** any persist, so the
  stored container is never corrupted by a failed change.
- **The password lives only in memory while unlocked.** It is held in a ref for
  the lifetime of the unlocked session and cleared on **Lock** (and lost on
  reload / tab close). Because the plaintext and password both vanish, the app
  boots into one of three phases decided purely by whether the `localStorage` key
  exists: **setup** (no container → create a vault + password), **locked**
  (container present → prompt for the password), **unlocked** (password entered,
  container opened in memory). **Unlock = open the container**: a wrong password
  fails the AEAD and is surfaced as "wrong password or tampered vault".
- **Reuse the shared sealed vault format — no new format.** The container is a
  plain `SIGILcli` seal of the same `TotpVault` JSON the CLI writes, so the same
  vault can round-trip through the CLI and the browser helpers. The container is
  self-describing (it stores its Argon2id parameters), so open needs none and the
  vault stays interoperable regardless of the sealing parameters the app chose.
- **Entropy from the platform CSPRNG.** The salt and nonce for each (re)seal come
  from `crypto.getRandomValues` in the app (the wasm core stays
  `getrandom`-free / caller-supplies-entropy, per
  [ADR 0007](0007-caller-supplied-entropy-in-core.md)).
- **A "Forget vault" escape hatch.** Because a forgotten password is
  unrecoverable, the locked screen offers a confirmed "Forget vault" that deletes
  the `localStorage` key and returns to setup — the only way out of a vault whose
  password is lost.

## Consequences

- **A lost password = an unrecoverable local vault, by design.** There is no
  backend, no recovery key, and no escrow: if the password is forgotten, the only
  option is to forget the vault and start over. This is the correct security
  posture (the whole point is that only the password opens the vault) but it is a
  real usability cliff, stated plainly in the setup copy.
- **`localStorage` is not a hardened secret store — dev only.** It is readable by
  any script that runs on the origin and is not encrypted at rest by the browser;
  we mitigate by persisting **only the sealed container** (never plaintext / never
  the password), but this is still a dev / UNAUDITED build and must not hold real
  2FA secrets. A production client would want a stronger store and per-device keys.
- **No account / device / sync-auth model yet.** Persistence is purely local and
  single-browser. The optional dev **Sync** panel can round-trip the *sealed*
  container through the opaque op-log, but that is dev / localhost / plain-HTTP /
  no-auth ([ADR 0022](0022-wasm-client-server-sync-loop.md)) and is **not** the
  product's multi-device or enrollment model.
- **Cross-client-interoperable for free.** Because the persisted artifact is the
  same `SIGILcli`-sealed `TotpVault`, a vault created in the browser and one
  created by the CLI are the same kind of object; no new format or migration was
  introduced, and no new cryptography was added — all crypto stays in
  `#![forbid(unsafe_code)]` `sigil-core`.
- **Proven by feature smokes.** Headless Playwright tests
  (`web/apps/webapp/tests/wasm.spec.ts`) exercise the real path end-to-end: adding
  an account reproduces the RFC 6238 vector `287082` through the vault code path,
  a Google Authenticator `otpauth-migration://` URI imports, and a
  **lock → reload → unlock** round-trip restores the persisted vault — proving the
  sealed-only persistence and in-memory unlock behave as designed.
- **Still dev / no-index / UNAUDITED, not deployed.** This is not the product's
  account / key-management model. Public copy still obeys
  [`../../web/apps/marketing/MARKETING-CLAIMS.md`](../../web/apps/marketing/MARKETING-CLAIMS.md).
