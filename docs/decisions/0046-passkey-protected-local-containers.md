# 0046 — Passkey-protected local containers: a second AT-REST factor whose break-glass is the recovery sheet already printed

- **Status:** Accepted (2026-07)
- **Date:** 2026-07-29
- **Builds on:** [0028](0028-webapp-vault-persistence-and-unlock.md) (persist only
  the sealed container; the password lives in memory),
  [0033](0033-browser-device-identity-storage.md) (the second sealed container
  holding the device identity),
  [0036](0036-browser-sharing-secret-storage.md) (the sealed-only invariant that
  constrains what may be written to web storage — it carries a dated addendum
  pointing here),
  [0042](0042-recovery-kit.md) (the printed 32-byte kit seed, which this decision
  gives a **second job** — its addendum records that),
  [0020](0020-shared-client-container-format.md) (the `SIGILcli` container, whose
  format is **unchanged**),
  [0007](0007-caller-supplied-entropy-in-core.md) (caller-supplied entropy, which
  is why an authenticator's PRF output can drive existing primitives with no core
  change).
- **Changes nothing in:** `sigild`. No route, no header, no canonical message, no
  migration, no table, no metric, no dependency. The wire protocol is byte-for-byte
  what it was.

## Context

Every browser client seals its two `SIGILcli` containers — the TOTP vault and the
device identity — with Argon2id under a **human password**, and nothing else. That
password is the only factor standing between an attacker who copied `localStorage`
and: every TOTP secret, the Ed25519 device seed, the hybrid secret identity, every
accepted vault key, and (since Phase 50) the hybrid-key pin store.

That is the weak link in an otherwise careful story. The wrap of a vault key is
PQ-hybrid ([0035](0035-device-to-device-vault-sharing.md)); the recipient gate is
enforced by a Rust type ([0042](0042-recovery-kit.md) §4); key substitution is
refused at a choke point ([0038](0038-key-pinning-safety-numbers-and-vault-rotation.md));
recovery is a paper key the server never sees ([0042](0042-recovery-kit.md)). All
of it is reachable by guessing one password offline, at whatever rate the
attacker's hardware allows against our Argon2id parameters.

A WebAuthn credential can produce a **32-byte PRF output** that never leaves the
authenticator and cannot be derived from anything on disk. Mixing it into the
at-rest sealing secret turns a copied profile from *"guess the password"* into
*"guess the password **and** hold the authenticator"*.

The reason this had not been done is that it is the single easiest way to build a
**lockout** into a product whose entire recovery story is "we cannot help you".

### Three blockers were settled by experiment BEFORE any code was written

This is why the feature is testable at all, and it is recorded because each answer
was assumed to be the opposite at some point in the design:

1. **The Chrome DevTools Protocol virtual authenticator DOES support the PRF
   extension**, via `hasPrf: true` on `WebAuthn.addVirtualAuthenticator`. Verified
   live: `prf.enabled === true` at creation, 32 bytes at assertion, and
   **byte-identical across two assertions**. WebAuthn is therefore drivable
   headlessly, so an untested branch of this feature has **no excuse**.
2. **Omitting `hasPrf` gives the "PRF unsupported" branch for free** — Chrome
   answers `prf.enabled === false` at creation and returns no `results` at
   assertion. The negative case is as real as the positive one.
3. ⛔ **`http://127.0.0.1` cannot do WebAuthn at all.** An RP ID must be a
   registrable domain, and Chrome rejects an IP literal with
   `SecurityError: This is an invalid domain.` — with or without an explicit
   `rp.id`. Both origins are secure contexts, so nothing else in the suite had ever
   noticed the difference, and `playwright.config.ts` was pinned to `127.0.0.1`.
   **Every passkey spec would have failed for a reason unrelated to the feature.**
   The config and the affected specs moved to `http://localhost`.

The same experiment **disproved** a design claim we had written down: that Chrome
hides WebAuthn from `chrome-extension://` pages. It does not. The MV3 extension is
still scoped out of this phase — deliberately, not because it is blocked (see
limitation 1).

## Decision

### 1. The two containers are sealed under a CONTAINER MASTER KEY, derived from the recovery seed

With protection on, both `SIGILcli` containers are sealed under a 32-byte
**container master key (CMK)** instead of the password. The CMK is an HKDF
derivation of the **existing [ADR 0042](0042-recovery-kit.md) recovery-sheet seed**:

```
CMK = HKDF-SHA256( salt = "sigil-recovery-kit-v1",
                   ikm  = kit_seed(32),                              ← the printed sheet
                   info = "sigil-recovery-kit-v1/container-master-key",
                   L    = 32 )
```

⭐ **This is the whole reason the break-glass needs NO new artifact and NO
server.** The 56 characters a user already printed to survive losing every device
also open a profile whose passkey is gone. There is no second sheet, no escrow, no
"recovery email", and nothing for `sigild` to hold — the sheet derives the CMK
offline, with no network, exactly as it derives the kit's device and hybrid
identities.

It reuses ADR 0042's HKDF-Extract salt with a **new, distinct `info` label**, which
is the same domain-separation pattern that already separates the three kit
derivations from each other.

The derivation is **one `crypto.subtle.deriveBits` call in JS**
([`../../sigil-wasm/passkey.mjs`](../../sigil-wasm/passkey.mjs)) and deliberately
**not** a fourth label in `libsigil/core/src/recovery.rs`: no Rust caller exists, so
a Rust copy would be a mirror that can only drift, and a new wasm export would mean
editing both `index.mjs` and `index.d.ts` — the two-hole trap Phase 56 fell into. If
the CLI or the desktop ever want offline local unlock, it moves into `recovery.rs`
then, single-sourced, and the JS becomes a shell.

### 2. The passkey slot: `PRF ‖ password`, fed straight to Argon2id

The CMK is also wrapped into a **THIRD `SIGILcli` container**, `localStorage` key
`sigil.webapp.hwslot.v1`, sealed under:

```
PRF_SALT = SHA-256("sigil-passkey-unlock-v1")          32-byte constant, NOT a secret
R        = prf.results.first from a WebAuthn assertion  32 bytes
hwslot   = seal_to_container( R ‖ utf8(password), … )   ⭐ PRF BYTES FIRST
```

Its sealed plaintext is `{version: 1, cmk, kit_device_id, credential_id, rp_id,
backup_eligible, backup_state, created_at}`.

Two choices in there are load-bearing:

- **`R ‖ utf8(password)` goes STRAIGHT to the container's own Argon2id.** There is
  deliberately no cheap HKDF over the password first. An attacker who can *drive
  the authenticator* — an unlocked device, a coerced user-verification prompt —
  recovers `R` and then still faces Argon2id over the password. Reducing the
  password through a fast KDF before Argon2id would hand that attacker an
  unstretched guess and throw away the only defence remaining in that scenario.
- **PRF bytes FIRST.** The fixed-length 32-byte prefix makes the parse
  unambiguous. Password-first would let `("abc", P)` and `("abcX", P′)` collide on
  the same concatenation.

The slot is a **container, not a JSON marker**, precisely so that the browser's
persisted key set stays *"sealed containers only"*
([ADR 0036](0036-browser-sharing-secret-storage.md)) — the leak specs check the
magic bytes of every stored value, and a plaintext `{credential_ids, rp_id}` marker
would be the first non-container persisted value in this repo's history. ⛔ Sealing
that public metadata under a hardcoded constant just to satisfy the magic check
would be fake crypto, which `CLAUDE.md` forbids by name.

The credential is **discoverable** (`residentKey: "required"`), which is what lets
the locked screen call `get()` with an empty `allowCredentials`: the client needs no
plaintext file naming credential ids, because the credential id lives *inside* the
sealed slot it is trying to open.

### 3. ⭐ AND, NEVER OR

**While protection is on there is no password-only slot.** The two doors are:

| door | what it needs |
|---|---|
| 1 | the **password AND the passkey** (the slot yields the CMK; the CMK opens both containers) |
| 2 | the **printed recovery sheet** (derives the CMK directly, offline) |

An **OR** design — either factor opens the container — is theatre. An offline
attacker holding a copied profile simply attacks the weaker branch, and the passkey
buys exactly zero. The second factor only means something if it is *required*.

⚠️ **Two places look like an OR and are not, and both are lockout fixes:**

- `unlock()` tries `[cmk, password]`. The password is a **second** candidate that
  is only reachable **after the slot has actually opened** — which already required
  the passkey. After a successful enable the ciphertext has changed, so the
  password path stops working *by construction*, not by policy. It exists because
  enabling is not atomic (§4).
- `unlockWithRecoverySheet()` tries `[cmk, currentPassword, newPassword]` for
  **both** containers. The whole branch is gated behind a valid
  `verifyRecoveryKit(code)`, so the door is **"sheet AND (CMK OR the old
  password)"** — nothing there opens anything without the printed sheet.

### 4. ⭐ THE WRITE ORDER IS THE SAFETY PROPERTY

Enabling protection touches three stored values and **cannot be made atomic** in
`localStorage`. The only real question is **which state a crash leaves behind**.

The first implementation wrote the **slot first**. A crash after that left a slot
sitting beside two still-**password-sealed** containers — and in that state **the
printed sheet alone is genuinely not a door**: a sheet-derived CMK cannot open a
password-sealed container. That is information-theoretically true, and it **cannot
be fixed at the unlock end** by any amount of candidate-trying.

The order is now **containers FIRST, slot LAST**:

```
1. re-seal the TOTP vault under the CMK          ← the only copy of the data
2. re-seal the device identity under the CMK     ← the only copy of the keys
3. write the passkey slot                        ← a recoverable marker
```

A crash now leaves **CMK-sealed containers with no slot** — the exact state the
sheet-alone recovery already handles and which a spec already proves. The dangerous
window collapses into the safe one.

> **The rule, stated so it generalises: make the last write the one whose loss
> costs least.**

### 5. No lockout is the acceptance criterion, and it is enforced, not remembered

Every way a passkey can become unavailable — a lost laptop, a cleared profile, a
revoked platform credential, a browser that drops PRF, a cancelled or timed-out
ceremony, an authenticator that returns different bytes — lands on the printed
sheet, which needs no passkey and no network. That is why:

- **Enabling REFUSES unless a recovery kit already exists** ("no sheet ⇒ no
  protection"), and the check **fails closed** when it cannot confirm one.
- **The code is typed back before anything is re-sealed**, decoded and checksummed
  **offline**, so a typo never reaches a server and never produces a half-enabled
  profile.
- **The break-glass form renders unconditionally on the locked screen.** It used to
  render only when a slot was present, which meant *deleting* a non-secret marker
  removed the only way out of the DOM while both containers stayed CMK-sealed
  (`localStorage` values vanish for a dozen mundane reasons). The sheet derives the
  CMK with no reference to the slot whatsoever; gating its form on the slot threw
  that property away.
- **`probePrf` asserts twice and requires byte-identical output.** A
  non-deterministic PRF is *indistinguishable* from a working one after a single
  call, and would seal a container nothing could ever open again. It is reported as
  **unsupported**, never as "try again".
- **`createVault()` clears any stale slot first.** A profile whose vault container
  is gone while the slot survives lands on SETUP; sealing a fresh vault beside the
  old slot closed **both** doors at once.
- **A surviving device identity is never deleted.** If the vault is gone but the
  identity remains, it is left **byte-for-byte in place and announced** — it is the
  only copy of the Ed25519 seed, the hybrid secret and every accepted vault key. A
  permanent loss a human is told about is recoverable by a human; a silent one is
  not.
- **Reprinting a kit re-seals the slot in the same operation.** A new sheet means a
  new CMK; leaving the old slot would keep the vault openable by the passkey while
  the **break-glass silently stopped working** — worse than a brick, because
  nothing tells you.
- **A protected personal vault refuses sync in BOTH directions.** Push is pointless
  (nothing else can read it) and **pull is destructive**: one click would replace
  the only copy with a stale pre-protection container or with bytes this browser
  cannot open at all.
- **A passkey error is never rendered as "wrong password".** The AEAD tag cannot
  distinguish a wrong password from a different passkey, so the wording does not
  pretend to, and every branch points at the sheet. `explainPasskeyStatus` takes an
  `atUnlock` flag because the same failure code means *"the control refused and
  nothing was written"* during enable and *"your containers are already sealed with
  a key this authenticator can no longer derive"* at unlock — the second must never
  reassure.

### 6. `sigild` gains NOTHING

⭐ No route, no header, no canonical message, no migration, no table, no metric, no
dependency, no schema-version bump. Request authentication is still the classical
Ed25519 contract-v3 signature. **A hostile server cannot disable, weaken, detect or
even observe this** — the only thing it could ever have contributed is the recovery
kit's *existence check*, which is advisory and fails closed.

## The sentence an auditor should be able to check

> With protection on, the two `SIGILcli` containers a browser persists are sealed
> under a CMK that is an HKDF derivation of the printed recovery seed; the CMK is
> additionally wrapped in a third container under `PRF(32) ‖ utf8(password)` fed
> straight to Argon2id; **there is no password-only slot**; enabling writes the
> containers before the slot, so any interruption leaves a state the printed sheet
> alone recovers; and `sigild` was not modified at all.

## Consequences

### Good

- **A copied `localStorage`, a stolen backup or a forensic image is no longer one
  password away from everything** — for containers re-sealed after protection was
  turned on.
- **The break-glass needed no new artifact.** One printed sheet now has two jobs:
  rebuild a lost account, and open a protected local profile. Users are not asked
  to keep a second piece of paper, and there is no second thing to lose.
- **The wire protocol is untouched**, so the CLI, the desktop and the extension are
  unaffected, and there is no new server-side attack surface.
- **The sealed-only storage invariant survived a feature that added a value.**
  Three `localStorage` keys, three sealed containers, nothing in the clear.
- **The honest status line is derived, not remembered.** The UI's claim about scope
  comes from the BE/BS flags of the **ceremony that just ran** — a backup-eligible
  credential syncs to a provider account and is described as such, never as "this
  device only".
- **Every branch is machine-checked.** PRF present, PRF absent, authenticator
  removed, a *different* authenticator, backup-eligible flags, both interruption
  states, a deleted slot and a corrupted slot are all driven through the real
  WebAuthn API by the CDP virtual authenticator.

### Bad / honest limitations — every one of them real

1. ⚠️ **Only the webapp has the passkey UI.** The MV3 extension and the native
   desktop app do not — even though the experiment **proved** WebAuthn works from an
   extension origin. This is **scope, not a blocker**, and it means a user with a
   protected webapp profile and an unprotected extension profile has both postures
   at once. Do not read this as done.
2. ⚠️ **Enabling requires a recovery kit to exist FIRST**, and a kit **cannot be
   created after the loss**. "No sheet ⇒ no protection" is a real refusal, and it
   inherits every limitation of [ADR 0042](0042-recovery-kit.md).
3. ⚠️⚠️ **Whoever holds the printed sheet has full control of the account** — that
   was already true, and this decision makes the sheet strictly more powerful by
   also making it a local unlock. The kit recovers **KEYS, not DATA**, and only for
   the vaults it was told to cover.
4. ⚠️ **It defends STORAGE, never EXECUTION.** Anything running in the origin while
   the vault is unlocked — XSS, a malicious extension, a hostile dependency — reads
   the plaintext vault, the seed, the hybrid secret, every vault key, the password,
   the PRF output **and the CMK**, exactly as before.
5. ⚠️ **It is NOT retroactive.** Only containers re-sealed after protection is
   enabled are protected. Earlier copies, backups and forensic images stay
   password-only **forever**.
6. ⚠️ **PRF availability varies** by browser, platform and authenticator. The UI
   must never claim protection it does not have, which is why capability is only
   ever reported from a probe that just ran.
7. ⚠️ **A protected personal vault cannot be synced in either direction**, so the
   local copy is the only copy. That is a deliberate refusal, but it means
   protection and multi-device sync are mutually exclusive for a personal vault
   today; converting it to a shared vault is the way out.
8. ⚠️ **User verification is a policy request, not a proof.** We ask for
   `userVerification: "required"` and read a flag. We cannot verify that a human was
   verified, and a lying authenticator is undetectable.
9. ⚠️ **A backup-eligible credential introduces a new third-party custodian** (a
   platform account or password manager). The factor is then only as strong as that
   account. This is described, not prevented.
10. ⚠️ **No attestation is requested**, deliberately: it costs privacy and CBOR
    parsing and buys nothing here. We therefore make **no claim whatsoever** about
    what kind of authenticator is in use.
11. **No zeroization**, as everywhere else in this repo. The CMK and the PRF output
    sit in JS `Uint8Array`s while unlocked.
12. **The PRF salt is a constant**, so all profiles on one credential derive the
    same `R`. Making it per-profile would need a **non-container** persisted
    artifact, which [ADR 0036](0036-browser-sharing-secret-storage.md) forbids.
13. **Dev / no-index / pre-audit / UNAUDITED**, over plain HTTP in dev, like
    everything around it. Do not store real 2FA secrets.

### Neutral

- The slot's plaintext holds `kit_device_id` **only when the account has exactly
  one active kit**. With several, picking one would be a guess, and a wrong guess
  makes the relink banner point at the wrong sheet — confidently wrong is worse than
  silent. Protection itself is unaffected; it is keyed by the typed code.
- `PASSKEY_TIMEOUT_MS` is not cosmetic. Verified live: in a profile whose passkeys
  are gone, `navigator.credentials.get()` **never settles on its own**. Without a
  timeout the unlock screen would sit on "Unlocking…" forever instead of naming the
  problem and pointing at the sheet — i.e. the no-lockout guarantee would be
  invisible to the person who needs it.

## Alternatives rejected

- **Use the passkey as the REQUEST credential** (sign requests with WebAuthn
  instead of the Ed25519 device key). Rejected on three counts: a WebAuthn assertion
  is **origin-bound**, so it cannot be produced by the CLI or the desktop app at
  all; verifying it would put a **WebAuthn verifier (CBOR, COSE, attestation
  formats, counters) inside `sigild`**, which today needs nothing but
  `crypto/ed25519` for the same job; and it would fork the canonical contract-v3
  message into a fourth shape. The wire protocol staying untouched is the single
  best property of this design.
- **An OR slot (passkey *or* password).** Rejected as theatre — see §3. An offline
  attacker attacks the weaker branch.
- **Ship Sigil as a passkey PROVIDER for other sites** (a WebAuthn/passkey
  authenticator that other relying parties use). Rejected as a different product:
  it needs a credential store, a CTAP or platform integration, an autofill surface
  and per-origin credential management, none of which this repo has. It is also not
  what this phase is for — the problem here is *our own containers at rest*.
- **A separate passkey-derived secret with its own paper backup.** Rejected: a
  second artifact users must print, keep and not lose, to solve a problem the first
  artifact already solves.
- **HKDF over `PRF ‖ password` before Argon2id.** Rejected — see §2. It hands an
  attacker who can drive the authenticator an unstretched password guess.
- **A plaintext marker file naming the credential ids and RP id.** Rejected: it
  would be the first non-container persisted value in this repo, breaking
  [ADR 0036](0036-browser-sharing-secret-storage.md)'s invariant for convenience.
  Discoverable credentials remove the need entirely.
- **Writing the slot first** (the original order). Rejected after reproducing the
  state it leaves — see §4.
- **A non-extractable WebCrypto key or the Credential Management API as the store.**
  Rejected for the same reason [ADR 0036](0036-browser-sharing-secret-storage.md)
  rejected it: our wasm needs raw bytes.
- **Gating the break-glass form on the presence of a slot.** Rejected after
  reproducing the lockout it caused — deleting a non-secret marker removed the only
  way out, while *corrupting* the same value stayed recoverable.

## References

- Code: [`../../sigil-wasm/passkey.mjs`](../../sigil-wasm/passkey.mjs) (the whole
  module: `passkeySupport`, `prfSalt`, `createPasskey`, `evaluatePrf`, `probePrf`,
  `hwSlotSecret`, `deriveContainerMasterKey`, `sealHwSlot`, `openHwSlot`,
  `backupFlags`, `describeProtectionScope`, `explainPasskeyStatus`,
  `PasskeyError` / `PrfUnavailableError`),
  [`../../web/packages/sigil-wasm/index.mjs`](../../web/packages/sigil-wasm/index.mjs)
  + [`index.d.ts`](../../web/packages/sigil-wasm/index.d.ts) (re-export **and**
  types — two separate holes, kept in step),
  [`../../web/apps/webapp/app/authenticator.tsx`](../../web/apps/webapp/app/authenticator.tsx)
  (`beginPasskeyProtection` / `completePasskeyProtection` /
  `disablePasskeyProtection` / `rekeyProtectionForNewKit` /
  `unlockWithRecoverySheet`, the `PasskeyPanel`, and the sync refusal).
- Proof: [`../../web/apps/webapp/tests/passkey.spec.ts`](../../web/apps/webapp/tests/passkey.spec.ts)
  — 24 specs driving the real WebAuthn API through the CDP virtual authenticator.
- Format + derivation spec: [`../crypto-spec.md`](../crypto-spec.md).
- Adversaries: [`../threat-model.md`](../threat-model.md) — the profile-copying
  attacker who does not hold the authenticator.
- The recovery sheet this borrows: [0042](0042-recovery-kit.md).
