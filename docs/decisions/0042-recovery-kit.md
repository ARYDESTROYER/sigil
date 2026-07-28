# 0042 — The recovery kit: a printable paper key that is an ordinary member device, and a wrap gate enforced by type

- **Status:** Accepted (2026-07)
- **Date:** 2026-07-28
- **Revises (does not supersede):** limitation 1 of
  [0040](0040-account-model.md) ("**THIS IS NOT AN IDENTITY SYSTEM, AND THERE IS
  NO RECOVERY** … *this must be written down before anyone charges real money*").
  It addresses the **DATA** half of that limitation and **not** the identity half:
  there is still no email, no password, no operator break-glass. 0040's body is
  unchanged; it carries a dated addendum pointing here.
- **Builds on:** [0007](0007-caller-supplied-entropy-in-core.md) (the
  caller-supplied-entropy contract, which is the *only* reason a deterministic
  paper key can drive the existing primitives at all),
  [0031](0031-multi-device-auth-model.md) (the enrollment challenge and the device
  registry a kit joins through), [0035](0035-device-to-device-vault-sharing.md)
  (the wrapped-vault-key envelope a kit receives),
  [0038](0038-key-pinning-safety-numbers-and-vault-rotation.md) (pinning, the
  safety number, and ⭐ **the lesson this phase initially violated**),
  [0040](0040-account-model.md) (a kit is a member of an account),
  [0023](0023-totp-hotp-primitive-and-cli-vault.md) (the RFC 4648 base32 codec
  this deliberately does **not** reuse).

## Context

[ADR 0040](0040-account-model.md) closed with the sentence this phase exists to
answer:

> **Lose or revoke every device and the account is permanently unreachable, its
> vaults permanently unreadable by the customer AND by us, and its subscription
> stranded.** … *This must be written down before anyone charges real money.*

Every ordinary answer to that is unavailable here, by design. There is no email
to send a reset to. There is no password to recover, because losing the password
is one of the ways you get here. There is no operator break-glass, because a
server that can restore a vault is a server that can read one — and the entire
premise is that it cannot. A key-escrow service would be the same failure wearing
a different name.

What is left is the oldest answer there is: **give the human the secret, on
paper, before they need it.**

## Decision

### 1. ⭐ A recovery kit is an ORDINARY MEMBER DEVICE whose keys come from paper

This is the whole design, and everything good about it follows from it.

A kit's Ed25519 device identity and its hybrid (X25519 + ML-KEM-768) identity are
**derived** from 32 bytes of client CSPRNG that are **printed and never
transmitted, never stored on a device, and never derivable from anything the
server holds**. It then enrolls, is granted, receives wrapped vault keys and
signs contract-v3 requests exactly like a phone does.

⭐ **`sigild` gained NO concept of "recovery".** No new table, **no migration**
(`sigild_schema_version` stays **5**), no new auth path, no new signed message.
The server sees only shapes it already relayed: one more device row, one more
hybrid public key, and one more opaque ~1226-byte `SIGILhyb` envelope per covered
vault. There is nothing in the database an operator could recognise as a recovery
mechanism, and nothing to attack that was not already there.

The one thing a kit does need that did not exist is a **self-only index**: on a
fresh machine the kit knows its own device id and nothing else, so it must be
able to ask *"which vaults hold a wrapped key for me?"* That is
**`GET /v1/devices/{deviceID}/keys`** — one new route, **metadata only, never a
blob** (Postgres selects `octet_length(blob)`), **self-only** (a mismatched path
id is `403` **before any store read**, and an unknown device is the same coarse
`403`, never a `404`), reusing `authenticateDevice` and `authorizeVault` with
`needRead` per row so unauthorized vaults are silently filtered rather than
erroring. It needed no migration: the index
`sigil_vault_key_envelopes_by_recipient` from `0004_key_sharing.sql` was created
for precisely this query.

### 2. The printed format: 56 Crockford characters

```
check = SHA-256( "sigil-recovery-kit-v1\n" ‖ [0x01] ‖ seed(32) )[0..2]
body  = [0x01] ‖ seed(32) ‖ check(2)            = 35 bytes = 280 bits
code  = crockford32(body)                       = 56 characters, NO padding
sheet = 7 groups of 8, hyphen-joined
```

280 bits divides by 5 exactly, so the encoding has **no padding character** and
no ambiguity about a partial final group.

**Crockford base32, not RFC 4648**, because this alphabet is read off paper by a
human under stress: it omits `I`, `L`, `O` and `U`, folds `O`→`0` and
`I`/`L`→`1`, and is case-insensitive. ⚠️ **`U` is REJECTED, never folded** —
Crockford excludes it, and folding it would let two distinct strings decode to
the same value.

⭐ **The decode order is part of the contract: length → alphabet → CHECKSUM →
version.** Putting the version check *last*, after a checksum that **covers the
version byte**, means a flipped version bit reports *"that is not a valid
recovery code — check for a mistyped character"* rather than *"unsupported
version 17"*. A person holding a paper sheet needs to be told to look at their
typing, not at their software. (`flipped_version_reports_checksum_not_version`
pins it.) Only a code whose checksum is *correct* for an unknown version yields
`UnsupportedVersion`.

This is a **new codec** in `libsigil/core/src/recovery.rs`. It deliberately does
**not** touch the RFC 4648 `base32_decode` used for TOTP secrets: that one must
stay interoperable with every `otpauth://` producer in the world, and quietly
teaching it to fold `O`→`0` would be a compatibility change to an
interoperability surface for the benefit of an unrelated feature.

### 3. Derivation: HKDF-SHA256 and nothing else

```
PRK = HKDF-Extract( salt = "sigil-recovery-kit-v1",  ikm = seed(32) )

ed25519_seed      = HKDF-Expand(PRK, "sigil-recovery-kit-v1/ed25519-device-seed", 32)
x25519_secret     = HKDF-Expand(PRK, "sigil-recovery-kit-v1/x25519-secret",       32)
mlkem_keygen_seed = HKDF-Expand(PRK, "sigil-recovery-kit-v1/mlkem-keygen-seed",   64)   // d ‖ z
```

(The HKDF salt has **no** trailing newline; the checksum domain **does**. They are
different strings on purpose.)

Those three outputs feed the **existing** deterministic primitives unchanged —
`public_key_from_seed`, `x25519_public_key`, `ml_kem768_keygen`. ⭐ **This is
[ADR 0007](0007-caller-supplied-entropy-in-core.md) paying off:** because
`sigil-core` reads no RNG and every keygen takes caller-supplied entropy, a paper
secret is just another entropy source. Nothing in the core changed to accommodate
recovery.

**No new dependency**: `hkdf` and `sha2` were already direct dependencies of
`sigil-core`, so the core stays wasm-pure and RNG-free, and both `Cargo.lock`s
stay `getrandom`-free.

**HKDF and not Argon2id, deliberately.** Argon2id exists to make a *low-entropy
human secret* expensive to guess. There is no password here — the input is 256
bits of CSPRNG, already uniform. All that is needed is domain separation, which
HKDF provides. Adding a memory-hard KDF would add cost and a parameter-drift
hazard while buying nothing.

`RecoveryKeys`'s `Debug` prints exactly `RecoveryKeys { <redacted> }`, so a stray
`{:?}` cannot leak the derived material.

### 4. ⭐ THE SECURITY-CRITICAL PART: the wrap gate is a CHOKE POINT enforced BY TYPE

This is the reason the phase needed two rounds, and it is the part an auditor
should read first.

**The first implementation put the safety-number requirement on the `recovery
cover` COMMAND.** A verifier proved live that
`sigil vault share --to <kitID>` and `sigil vault rotate --to <kitID>` reached the
**identical wrap** through ordinary first-sight TOFU — with the human shown the
safety number only **after** the wrap and the upload had completed. A hostile
server could substitute the kit's hybrid public key and receive the vault key.

⭐ **That is exactly the [ADR 0038](0038-key-pinning-safety-numbers-and-vault-rotation.md)
lesson — *"the choke point is the FETCH, and EVERY wrap path goes through it"* —
violated one phase after it was written down.** A rule that lives in a command
rather than on the path it protects is not a rule; it is a habit, and habits are
what new call sites forget.

The fix moved the requirement **into a single function**, and then made
forgetting it **impossible to compile**:

```rust
pub fn verify_recipient_for_wrap(
    server, device_id, auth, pins_path,
    expected_safety_number: Option<&str>,
    known_recovery_kit: bool,
) -> Result<VerifiedRecipient, CliError>

pub struct VerifiedRecipient { /* ALL FIELDS PRIVATE, no other constructor */ }

pub fn share_vault_to_known_key(…, recipient: &VerifiedRecipient, …)
```

`VerifiedRecipient` has **private fields and no public constructor**, and is
built in exactly three literals — all inside `verify_recipient_for_wrap`. The one
wrap→deposit→grant path takes `&VerifiedRecipient`. **A caller cannot reach the
wrap without having gone through the gate**, because it cannot produce the value
the wrap requires.

**Trust outcomes, exhaustively:**

| situation | outcome | pin store |
|---|---|---|
| key **derived locally** from the recovery secret (pin `origin = "recovery-kit"`) | `Derived` — **no fetch at all** | untouched |
| pinned, byte-identical | `Pinned` — proceeds | untouched |
| pinned, **different** | ⛔ `CliError::PinMismatch` | **untouched** |
| first sight + **matching** `--safety-number` | `VerifiedFirstSight` | pinned |
| first sight + **wrong** `--safety-number` | ⛔ `CliError::SafetyNumberMismatch` | **untouched** |
| first sight + recipient **is a recovery kit** + no number | ⛔ **`CliError::UnverifiedRecoveryKit`** | **untouched** |
| first sight + ordinary device + no number | `UnverifiedFirstSight` — TOFU, warned, as [ADR 0038](0038-key-pinning-safety-numbers-and-vault-rotation.md) allows | pinned |

⭐ **Every refusal happens BEFORE the key is pinned.** Pinning a key that was then
refused would mean a simple retry sees `Match` and proceeds — **the alarm would
silence its own alarm.** A supplied safety number is also checked *before* the pin
lookup, so it applies to pinned keys too.

The safety number of a kit is **printed on the sheet**, which is what makes the
requirement usable rather than merely strict: the out-of-band channel
[ADR 0038](0038-key-pinning-safety-numbers-and-vault-rotation.md) needed a human
for is, in this one case, a piece of paper the same human is already holding.

Rotation got a matching fail-closed guard: `vault rotate` **refuses** when a
device currently holding an envelope is named by neither `--to` nor `--drop`
(`CliError::RecipientsWouldBeDropped`), and flags a recovery kit specially —
*"⚠️ THIS IS YOUR RECOVERY KIT — dropping it means the printed sheet can no
longer recover this vault"*. Silently ending a kit's access during an unrelated
rotation was a way to lose recovery without ever being told.

**Verification of the fix.** Three independent mutations each turn share, rotate
and cover red **separately**, and the lead independently disabled the whole gate
and confirmed `cli/tests/e2e-recovery.sh` goes red with *"expected 'recovery cover
…' to FAIL, but it succeeded"*. The e2e script's step 9c exists specifically to
pin that **share and rotate obey the same rule as cover**.

### 5. ⚠️⚠️ THE RESIDUAL LIMIT, stated in these words and not softened

The **kit-DISCOVERY** arm — how a client decides that a pasted device id *is* a
recovery kit — resolves a kit by **device LABEL** (`"recovery-kit"`) from
**`GET /v1/account`**, a listing the **adversarial server serves**.

> **A server that renames or hides the label degrades `vault share` / `vault
> rotate` to a kit back to ordinary first-sight TOFU (warned and pinned) rather
> than a refusal.**

The caller-**ASSERTED** paths (`recovery cover`, `recovery generate`) pass
`known_recovery_kit: true` and **do not depend on the server**, so they are
unaffected. And **no path anywhere accepts a CHANGED key or a mismatched safety
number** — the pin check and the supplied-number check are independent of the
label and are never weakened by it.

So the honest claim is:

> **"refuses first-sight kit wraps against a server that does not lie about
> labels"** — **NOT** "refuses first-sight kit wraps".

A verifier judged this consistent with
[ADR 0038](0038-key-pinning-safety-numbers-and-vault-rotation.md)'s already-accepted
TOFU-on-first-contact limit, and asked specifically that this ADR say it in those
words. The lookup also **fails closed** on an error (a `501` — no account model,
hence no kits — is the only non-error "false"). The label is deliberately
*visible* rather than hidden: hiding it would buy only protection against targeted
denial, and would cost every client the ability to render *"Recovery: not set
up"*.

### 6. The commands, and how the secret is entered

`sigil recovery generate | cover | check | verify | restore | revoke`.

`generate` prints the sheet — the code in 7 groups of 8, the device id, the
account, the server, **the safety number**, the vaults covered *as of the print
date*, and four warnings. `cover` extends an existing kit to one more vault.
`verify` checks a typed code **offline**. `check` reports what a kit can reach.
`restore` runs on a **new install** and rebuilds the identity, the keyring and the
vaults. `revoke` retires the sheet.

⭐ **The secret is enterable by a non-argv path.** Precedence: `--code <value>`
(kept for scripts, and now printing a stderr warning that it puts the secret in
`argv` — readable via `/proc/<pid>/cmdline` and recorded in shell history) →
`--code-stdin`, or a non-TTY stdin → otherwise an **interactive prompt with echo
disabled** best-effort (and a loud warning when echo could not be turned off).
**There is deliberately no environment variable**: an env var is inherited by
every child process and appears in `/proc/<pid>/environ`.

`vault share` and `vault rotate` gained `--safety-number` (bare digits when there
is exactly one `--to`, or `<deviceID>=<digits>` repeatably), compared
presentation-insensitively so spacing and grouping never cause a false alarm.

## The sentence an auditor should be able to check

> A recovery kit is an **ordinary member device** whose private keys are HKDF
> derivations of 32 printed bytes the server never sees; **`sigild` gained no
> concept of recovery, no table and no migration**; and **no wrap can happen
> without a `VerifiedRecipient`, which only the single gate function can
> construct** — so a changed key, a wrong safety number, or an unverified
> first-sight kit (on a server that does not lie about labels) is refused with
> nothing wrapped, nothing uploaded, and the pin store unmutated.

## Consequences

### Good

- **The DATA half of [ADR 0040](0040-account-model.md) limitation 1 is closed.**
  A customer who loses every device can, if they printed a kit in advance, get
  their vaults back — without us being able to.
- **The server learned nothing.** No table, no migration, no new auth path, no
  new signed message; one metadata-only self-only route. There is no
  recovery-shaped thing in the database to attack or subpoena.
- ⭐ **The wrap gate is enforced by the type system**, so the class of bug that
  produced the fix round — a new call site reaching the wrap without the check —
  **cannot recur silently**. Three independent mutations prove all three paths.
- **No new dependency and no new entropy source.** HKDF + SHA-256 were already
  there; both `Cargo.lock`s stay `getrandom`-free and the core still reads no RNG
  and no clock.
- **The out-of-band channel finally has a carrier.** For a kit, the safety number
  is on the sheet, so the human verification
  [ADR 0038](0038-key-pinning-safety-numbers-and-vault-rotation.md) could only
  *ask* for is something the user already has in hand.
- **A rotation can no longer silently destroy recovery.** Dropping a kit is now
  an explicit act with a named warning.

### Bad / honest limitations — every one of them real

1. ⚠️⚠️ **WHOEVER HOLDS THE PAPER HAS FULL CONTROL OF THE ACCOUNT.** They can read
   every covered vault and **revoke every device**. It is **stronger than a stolen
   locked phone**, because there is no OS lock, no biometric and no vault password
   in front of it — the 56 characters are the whole credential. A kit left in a
   desk drawer is the account.
2. ⚠️ **It recovers KEYS, not DATA.** A vault that was never synced to the server
   is gone; the kit can unwrap a key for ciphertext that exists, and cannot
   conjure ciphertext that does not.
3. ⚠️ **It only opens the vaults it was told to COVER.** `generate` covers what
   the keyring holds *at that moment*; a vault created later needs
   `recovery cover`, and nothing reminds anyone. The sheet says *"as of the print
   date"* for exactly this reason.
4. ⚠️ **A kit cannot be created after the loss.** It is a
   print-it-before-you-need-it mechanism, which is the same failure mode as every
   backup: the people who most need it are the people who did not do it.
5. ⚠️ **Its nominal `read` grant is cosmetic.** Because the kit is an account
   **member** of the account that **owns** the vault, ownership authorizes it
   regardless ([ADR 0040](0040-account-model.md) §5) — it holds **owner-level
   power**. Do not read a `read` permission on a kit as a limit.
6. ⚠️ **The label-discovery residual of §5**, in the words given there.
7. ⚠️ **`--code` still exists and still puts the secret in `argv`** and shell
   history. It is warned about, not removed, because scripts need it.
8. ⚠️ **No zeroization anywhere.** The derived seeds, the decoded secret and the
   recovered vault keys sit in ordinary memory in every client, exactly as
   everything else in this repo does.
9. ⚠️ **CLIENT COVERAGE IS PARTIAL.** The **`sigil` CLI has the full flow**.
   There is **no `recovery.spec.ts` in the webapp and no `RecoveryPanel`**; the
   **extension has no recovery UI** although `extension/build.sh` **does** vendor
   `recovery.mjs`; the **desktop has no recovery commands**. The browser and
   desktop surfaces consume only the *wrap gate* (the safety-number field and the
   refusal), not the kit lifecycle. ⚠️ **And since `restore` runs on a NEW
   install, a user whose only client was the browser or the extension cannot
   restore there today.** Do not read this as done.
10. **A kit is one more enrolled device**, so it consumes a seat against
    `SIGILD_ACCOUNT_MAX_DEVICES`, appears in `GET /v1/account`, and can be
    revoked by any member — membership is still flat
    ([ADR 0040](0040-account-model.md) limitation 3).
11. **Revocation of a kit stops future access and cannot un-learn** anything a
    kit already unwrapped, exactly as for any other device; the remediation is
    still `vault rotate`, which protects **future content only**.
12. **The printed sheet has no revision, expiry or rotation story.** Reprinting
    means generating a new kit and revoking the old one by hand.
13. **UNAUDITED, dev-gated, plain HTTP in dev.** The codec, the derivation and the
    gate are all new code in the same pre-audit posture as everything around them.

### Neutral

- The `"recovery-kit"` string exists **twice, deliberately**:
  `RECOVERY_DEVICE_LABEL` (the server-visible device label) and
  `PIN_ORIGIN_RECOVERY_KIT` (the local pin-store origin marker that makes a
  derived key short-circuit to `Derived` with **no fetch at all**). They are
  different concerns that happen to share a spelling.
- The construction is **mirrored, not shared**, across the two implementations
  this repo already maintains — `cli/src/lib.rs` (CLI + desktop) and
  `sigil-wasm/recovery.mjs` (browser) — with the same known-answer vector on both
  sides, exactly like the safety number and the container formats. The wasm
  bindings add **no cryptography and no codec**: `recovery_encode` /
  `recovery_decode` / `recovery_derive_*` / `recovery_format` are thin shells over
  `sigil-core`.
- ⚠️ `interface SigilWasm` in `web/packages/sigil-wasm/index.d.ts` was **not**
  extended with the `recovery_*` methods, so those wasm calls are untyped at that
  boundary even though the `.mjs` helpers use them.

## Alternatives rejected

- **A 12- or 24-word BIP-39 mnemonic.** Rejected: it drags in a 2048-word list (a
  dependency or a large embedded table) and a checksum scheme designed for a
  different threat model, for a code that is typed once in a lifetime. 56
  Crockford characters need no word list, fold the characters humans actually
  confuse, and reject `U` rather than guessing.
- **Reuse the existing RFC 4648 base32 codec.** Rejected: it is the TOTP
  interoperability surface. Teaching it Crockford folding would change behaviour
  for `otpauth://` inputs to benefit an unrelated feature.
- **Argon2id over the printed secret.** Rejected: there is no low-entropy human
  secret to stretch; HKDF gives the domain separation that is the actual
  requirement. See §3.
- **A server-side recovery concept** — a `recovery` flag, an escrowed blob, an
  operator break-glass, or a "recovery" table. Rejected on the architecture's
  founding rule: a server that can restore a vault can read one. The kit works
  *because* the server cannot tell it apart from any other device.
- **Put the safety-number requirement on the `recovery cover` command.** This is
  what shipped first and it was **wrong** — `vault share` and `vault rotate`
  reached the identical wrap through plain TOFU. See §4. Recording it as a
  rejected alternative rather than quietly fixing it is the point.
- **Hide the `"recovery-kit"` label from `GET /v1/account`.** Rejected: it buys
  only protection against targeted denial (a hostile server that wants to strip
  the label can do so either way), and it costs every client the ability to show
  a user whether recovery is set up.
- **`SIGIL_RECOVERY_CODE` as an environment variable.** Rejected: inherited by
  every child process and readable in `/proc/<pid>/environ`. Prompt and stdin
  exist instead.
- **Refuse first-sight kit wraps unconditionally, using only the server's
  label.** Rejected as dishonest rather than as unhelpful: the label comes from
  the adversary, so an unconditional-sounding guarantee would be a guarantee the
  server can switch off. The gate is stated with its dependency instead (§5).
- **Auto-cover every new vault to the kit.** Rejected for now: it would make the
  kit's reach grow silently, and a user who printed a sheet in one trust context
  would find it covering vaults created in another. `recovery cover` is explicit.

## References

- Code: [`../../libsigil/core/src/recovery.rs`](../../libsigil/core/src/recovery.rs)
  (the codec + HKDF derivation),
  [`../../libsigil/core/src/lib.rs`](../../libsigil/core/src/lib.rs) (exports),
  [`../../cli/src/lib.rs`](../../cli/src/lib.rs)
  (`verify_recipient_for_wrap`, `VerifiedRecipient`, `RecipientTrust`,
  `share_vault_to_known_key`, `rotate_vault_key`, `derive_recovery_identity`,
  `recipient_is_recovery_kit`, `RECOVERY_DEVICE_LABEL`,
  `PIN_ORIGIN_RECOVERY_KIT`),
  [`../../cli/src/main.rs`](../../cli/src/main.rs) (`sigil recovery …`,
  `--safety-number`, `--drop`),
  [`../../sigild/internal/api/sharing.go`](../../sigild/internal/api/sharing.go)
  (`deviceKeyEnvelopeIndex`),
  [`../../sigild/internal/store/keysharing.go`](../../sigild/internal/store/keysharing.go)
  / [`postgreskeysharing.go`](../../sigild/internal/store/postgreskeysharing.go)
  (`ListKeyEnvelopesForRecipient`),
  [`../../sigil-wasm/recovery.mjs`](../../sigil-wasm/recovery.mjs),
  [`../../sigil-wasm/sharing.mjs`](../../sigil-wasm/sharing.mjs)
  (`verifyRecipientForWrap`, `UnverifiedRecoveryKitError`).
- Proofs: [`../../cli/tests/e2e-recovery.sh`](../../cli/tests/e2e-recovery.sh)
  (real `sigild` + real `sigil`, twelve steps including restore on a clean
  machine, an offline mistyped-code rejection, a foreign-account kit `401`, and
  step 9c pinning that **share and rotate obey the same rule as cover**),
  [`../../sigil-wasm/test/recovery-interop.mjs`](../../sigil-wasm/test/recovery-interop.mjs)
  (Rust ↔ JS agreement on the codec, the derivation and the shared known-answer
  vector).
- Format + derivation spec: [`../crypto-spec.md`](../crypto-spec.md).
- Contract: [`../api.md`](../api.md) — `GET /v1/devices/{deviceID}/keys`.
- Adversaries: [`../threat-model.md`](../threat-model.md) — the paper holder, and
  a server that lies about device labels.
- Operator runbook: [`../deployment.md`](../deployment.md) §17.

## Limitation 9 (partial client coverage) is retired (added Phase 56, 2026-07-28)

Per this repo's addendum rule the text above is left untouched; this section
records only what changed.

**Limitation 9 said:** *"CLIENT COVERAGE IS PARTIAL … There is **no
`recovery.spec.ts` in the webapp and no `RecoveryPanel`**; the **extension has no
recovery UI** …; the **desktop has no recovery commands** … **And since `restore`
runs on a NEW install, a user whose only client was the browser or the extension
cannot restore there today.**"*

**That is now false.** Phase 56 built the kit lifecycle on the three remaining
client surfaces:

- **Webapp** (`web/apps/webapp/app/authenticator.tsx`) — a `RecoveryPanel`
  (generate / cover / check / revoke) inside the unlocked vault, and a
  **`RestorePanel` on BOTH the setup and the locked screens**. Restore is
  deliberately **not** behind an unlocked vault: a fresh install with no local
  state is exactly the situation the sheet exists for. New specs
  `recovery.spec.ts`, `wrap-gate.spec.ts`, `leak.spec.ts`.
- **MV3 extension** (`extension/src/popup/popup.{html,js,css}`) — the same flow,
  with restore reachable from the locked/setup views, over the `recovery.mjs`
  `build.sh` was already vendoring. New specs `recovery.spec.mjs`,
  `wrap-gate.spec.mjs`, `leak.spec.mjs`.
- **Desktop** (`desktop/core/src/recovery.rs` + thin `#[tauri::command]`s +
  `desktop/ui`) — `recovery_generate` / `_cover` / `_check` / `_verify` /
  `_restore` / `_revoke` / `_kits`, following that directory's standing rule
  ([ADR 0037](0037-desktop-reuses-cli-library-for-protocol.md)): it calls the
  `sigil-cli` library and adds **no fourth copy** of the codec, the derivation or
  the safety-number digest.

**The wrap gate of §4 is unchanged and is exercised from the browsers.** A
`wrap-gate` spec in both browser clients drives a **second profile that never saw
the kit sheet**, and asserts the refusal, that **no envelope was stored**, and
that a wrong safety number is named as a mismatch — which also proves the first
refusal did not silently pin the key. It exists because deleting the gate
(`if (false && …)`) previously left every browser spec green.

**Two limitations related to the kit-as-credential are now enforced by a test
rather than by care.** A `leak` spec in both clients **enumerates** rather than
expects: every `localStorage` and `sessionStorage` key *and value*, cookies,
every IndexedDB record, every Cache Storage entry (the webapp is a PWA), the DOM
after the sheet is dismissed, every outgoing request URL and body, every console
message captured from before the first navigation, and the address bar — against
four spellings of the code. The earlier assertions checked only `localStorage`
and the URL, and a planted `sessionStorage.setItem` + `console.log` of the code
stayed green.

**Also fixed, and worth recording because it was latent:**
`web/packages/sigil-wasm/index.mjs` **never re-exported the `recovery_*` wasm
functions**, so every browser recovery call would have thrown at runtime. The
`.d.ts` gap recorded in the *Neutral* section above was a **separate** gap —
types and runtime were two distinct holes, and closing one would not have closed
the other. Both are closed.

**What is NOT retired.** Limitations 1–8 and 10–13 stand exactly as written: the
paper is still a full-account credential stronger than a stolen locked phone, it
still recovers **keys, not data**, it still opens only the vaults it was told to
**cover**, it still **cannot be created after the loss**, the label-discovery
residual of §5 is unchanged, and everything remains dev-gated, plain HTTP and
**UNAUDITED**. ⚠️ **Print output is not verified** — headless Chromium cannot
show a printed page, so the `@media print` rules are by-eye only. And the browser
suites still run against a **test double** (`sigil-wasm/test/fake-sigild.mjs`)
for everything except `cors.spec.ts`; real-server conformance for the kit still
lives in `cli/tests/e2e-recovery.sh` and
`sigil-wasm/test/recovery-interop.mjs`.

## The kit's device LABEL is now pinned to a golden literal (added Phase 57, 2026-07-28)

Per this repo's addendum rule the text above is left untouched. Two things in it
need correcting or completing.

### 1. The construction is SINGLE-SOURCED. The LABEL is the mirror — and it was untested.

The *Neutral* section says the construction is "mirrored, not shared, across the
two implementations". **That is not what the code does, and the sentence
immediately after it says so.** The Crockford codec, the checksum and the three
HKDF derivations live in **one place**, `libsigil/core/src/recovery.rs`; the CLI
imports `encode_recovery_kit` / `decode_recovery_kit` / `derive_recovery_keys`
directly, and the JS calls them through one-line `#[wasm_bindgen]` shells. There
is no second implementation to drift.

**What genuinely was a mirror — and had no test at all — is the device LABEL.**
`"recovery-kit"` existed as **three independent string literals**:
`cli/src/lib.rs::RECOVERY_DEVICE_LABEL`, `sigil-wasm/recovery.mjs`'s
`RECOVERY_DEVICE_LABEL`, and a **third** copy inside `sigil-wasm/sharing.mjs`. The
audit renamed it in **both** JS files and every suite stayed green.

That matters because the label is the **only** signal driving
`recipientIsRecoveryKit` — the arm that makes a wrap to a kit obey §5's mandatory
safety-number rule instead of ordinary TOFU. A rename in one place silently
downgrades a kit wrap to first-sight trust-on-first-use.

### 2. The fix, and why "consistent" is not good enough

- **The two JS literals are de-duplicated to one**: `sharing.mjs` now imports the
  label from `recovery.mjs` instead of redefining it. Two literals remain, one per
  language.
- **`sigil-wasm/test/recovery-interop.mjs` drives the REAL `sigil` binary in both
  directions** against a kit the other language enrolled, expecting the refusal.
- ⚠️ **A verifier then showed a *coordinated* rename still passed** — both
  languages agreeing on a new spelling satisfies a cross-language equality check.
  So the assertion now pins **both languages against a GOLDEN LITERAL**,
  `"recovery-kit"`. **The label is a WIRE value**: the server stores it on the
  device row and older clients compare against it, so it is **not free to change
  even consistently**. A cross-language agreement test is the wrong shape for a
  value whose compatibility extends to already-deployed clients.

### 3. A third hand-written copy remains, and drifts silently

`RECOVERY_DEVICE_LABEL` in `web/packages/sigil-wasm/index.d.ts` is a **literal
type**, hand-written a third time. A coordinated rename in the two runtime files
leaves that declaration contradicting the runtime value while `tsc` stays clean —
no test can see it. It is annotated in place pointing at the golden assertion as
the authority. (The `interface SigilWasm` gap recorded in *Neutral* was closed in
Phase 56; this is a different and still-open one.)

Nothing about the kit itself changed. Limitations 1–13 stand as written.

## The sheet now has a SECOND job: it derives the container master key (added Phase 58, 2026-07-29)

Per this repo's addendum rule the text above is left untouched; this section
records only what changed.

[ADR 0046](0046-passkey-protected-local-containers.md) adds a **second AT-REST
factor** to the webapp's sealed containers: with protection on they are sealed
under a 32-byte **container master key (CMK)** rather than the password, and the
CMK is derived from **this kit's printed seed**:

```
CMK = HKDF-SHA256( salt = "sigil-recovery-kit-v1",
                   ikm  = kit_seed(32),
                   info = "sigil-recovery-kit-v1/container-master-key",
                   L    = 32 )
```

It reuses this ADR's HKDF-Extract salt (§3) with a **new, distinct `info` label**,
which is the same domain separation that already keeps the Ed25519, X25519 and
ML-KEM derivations apart. **§3's three labels are unchanged**, the printed format
of §2 is unchanged, and the CMK is **not** derived by
`libsigil/core/src/recovery.rs` — it is one `crypto.subtle.deriveBits` call in
`sigil-wasm/passkey.mjs`, because no Rust caller exists and a Rust copy would be a
mirror that can only drift. If the CLI or the desktop ever want offline local
unlock, it moves into `recovery.rs` and the JS becomes a shell.

**What this means for the sheet, stated plainly:**

- ⭐ **One artifact, two jobs.** The same 56 characters that rebuild a lost
  account now also open a passkey-protected local profile — so the break-glass for
  a dead passkey needs **no second sheet, no escrow and no server**. That is the
  property that made ADR 0046 buildable.
- ⚠️ **Limitation 1 gets strictly heavier.** "Whoever holds the paper has full
  control of the account" now also means *whoever holds the paper can open the
  local containers of a protected browser profile, without its password*. Nothing
  about the paper changed; what it reaches did.
- ⚠️ **Limitation 4 ("a kit cannot be created after the loss") becomes a
  precondition rather than an afterthought.** ADR 0046 **refuses to enable
  protection** unless an active kit already exists, and the refusal fails closed
  when the account cannot be checked.
- **Reprinting a kit changes the CMK**, so the webapp **re-seals the passkey slot
  in the same operation** as a reprint. Otherwise the containers would stay
  openable by the passkey while the break-glass silently stopped working — worse
  than a brick, because nothing tells you. Limitation 12 ("the printed sheet has no
  revision, expiry or rotation story") is otherwise unchanged.
- **`sigild` still has no concept of recovery, and now no concept of passkeys
  either** — no route, no table, no migration, no metric, no dependency.

Limitations 1–13 stand as written, with 1 and 4 read in the light above.
