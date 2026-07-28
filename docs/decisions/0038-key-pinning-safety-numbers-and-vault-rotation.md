# 0038 — Key pinning, safety numbers, and vault key rotation

- **Status:** Accepted — 2026-07.
- **Date:** 2026-07-27
- **Relates to:** [0035](0035-device-to-device-vault-sharing.md) (the sharing flow
  whose two largest recorded limitations — no out-of-band verification of a published
  hybrid public key, and no rotation / re-wrap on revoke — this ADR retires; 0035
  carries a dated addendum pointing here),
  [0036](0036-browser-sharing-secret-storage.md) (the sealed device-identity container
  the browsers' pin store now rides inside, schema bumped v2 → v3),
  [0037](0037-desktop-reuses-cli-library-for-protocol.md) (why the desktop gets all of
  this by calling the Rust library rather than as a third implementation),
  [0013](0013-hybrid-public-key-seal.md) (the `hybrid_seal` composition a substituted
  key would have subverted), [0031](0031-multi-device-auth-model.md) (the contract-v3
  auth that protects the *request* but not the *response*), and
  [0007](0007-caller-supplied-entropy-in-core.md) (why the fresh vault key is drawn by
  the caller).

## Context

[ADR 0035](0035-device-to-device-vault-sharing.md) recorded its own worst problem
plainly, and [`../threat-model.md`](../threat-model.md) called it *"the single largest
gap in the design"*:

> **Trust in the published hybrid key is trust in the server's registry.** There is
> **no out-of-band verification** of a recipient's hybrid public key (no safety
> numbers, no key-transparency log, no cross-signature). A malicious server that
> substitutes its own hybrid public key for the recipient's would receive a vault key
> wrapped to itself.

That gap is structural, not incidental. Sharing works like this: device A asks the
server for device B's hybrid public key, wraps the vault key to whatever comes back,
and uploads the envelope. **The request is authenticated; the response is not.**
Contract v3 proves who *sent* a request — it binds nothing about what the server
*answers*. Every other defense in the sharing design is downstream of that answer being
honest: the envelope is unreadable to the server *only* because it was sealed to a key
the server does not hold. Substitute the key and the entire property collapses, and it
collapses **invisibly** — A sees a successful share, and B just sees an envelope it
cannot open, which is indistinguishable from a bug.

The second recorded limitation compounded the first:

> **No automatic re-wrap on revoke, no key rotation schedule, and no forward secrecy
> for the vault key.**

So even after detecting a compromise there was no remediation. Revoking a device stopped
its *future server access* but left it holding a vault key that still opened everything
the vault would ever contain, because nothing ever changed that key.

Three things were true when this phase started, and they shaped the answer:

1. **The fix cannot live on the server.** The adversary in question *is* the server. Any
   mechanism the server stores, serves or validates is a mechanism the server can lie
   about. Whatever we build has to live on the trusted side of the boundary.
2. **There is no identity binding to lean on.** A device's hybrid public key is not
   signed by its enrolled Ed25519 identity, so a client cannot verify a fetched key
   against something it already trusts. (Adding that cross-signature is the obvious
   better answer — see *Alternatives*.)
3. **There are four client surfaces but only two implementations.** The CLI and the
   desktop share the Rust `sigil-cli` library ([ADR 0037](0037-desktop-reuses-cli-library-for-protocol.md));
   the webapp and the MV3 extension share `sigil-wasm/sharing.mjs`. Anything added here
   has to be mirrored exactly twice — no more, and no fewer.

## Decision

Three mechanisms, decided together because none of them is sufficient alone.

### 1. PIN a device's hybrid public key, and BLOCK — never warn — when it changes

The first hybrid public key a client sees for a device is **pinned**; every later fetch
is compared against it, byte for byte over the decoded raw key material of **both**
halves. Three outcomes, and deliberately no fourth:

| Presented key | Outcome | State change |
|---------------|---------|--------------|
| device not seen before | **first sight** — proceeds, **with a warning** | the key is pinned |
| byte-identical to the pin | **match** — proceeds silently | none |
| **different** | ⛔ **hard refusal** | **none at all** |

A refusal means **nothing was wrapped, nothing was uploaded, and the pin store was not
mutated** — the vault key never touches the substituted key. It surfaces as a distinct,
catchable type, not a string: `CliError::PinMismatch` (Rust),
`KeyPinMismatchError` (JS), `DesktopError::KeyPinMismatch` (desktop, tagged `"key
changed"` across the IPC). Each carries the device id and **both** safety numbers — the
one trusted and the one presented — because that is exactly what a human needs to decide
what happened.

**Blocking rather than warning is the load-bearing part of this decision.** A warning on
a key change is a warning users click through, and the cost of clicking through is total
compromise of the vault being shared. So: **there is no flag, option, environment
variable or default anywhere that makes a wrap accept a changed key.**

⭐ **The enforcement rides on the fetch itself.** `fetch_hybrid_key_pinned` (Rust) /
`fetchHybridKeyPinned` (JS) fetch the key and check the pin in **one call**, and **every**
wrap path — share *and* rotate, in both implementations — goes through it. A trust store
that some code path forgets to consult is worthless, so the check is not a step a caller
can omit. The unchecked `fetch_hybrid_key` / `fetchHybridKey` survive only on paths that
wrap nothing: displaying a safety number, the deliberate re-pin, and the desktop's
`check_server`.

**Re-pinning is deliberate and never automatic.** `repin_hybrid_key` / `repinHybridKey`
is the only thing that ever replaces a pin. At the CLI it is
`sigil device repin <deviceID> --yes`, which refuses without `--yes` and refuses if the
`--safety-number "<digits>"` supplied does not match the key the server is presenting
right now (so a stale or mistyped value cannot bless the wrong key). Re-pins are
**counted** (`repins`) and shown by `sigil device pins`, so the evidence of a past
acceptance survives.

**Where the pin store lives follows each client's existing storage rule**, rather than
inventing a new one:

- **Native** (`sigil` CLI and the desktop app, which share it): `hybrid-pins.json`,
  mode `0600` in the `0700` state dir, written through the same `write_secret_file`
  helper as other sensitive state — created `0600` up front so it is never briefly
  world-readable, `fsync`'d, and re-`chmod`'d in case it pre-existed.
- **Browsers** (webapp, extension): a `pins` field **inside the existing sealed
  device-identity container**, schema bumped **v2 → v3**. v1 and v2 containers still
  open and yield an **empty** pin store.

The browser choice is the one worth defending: dropping a JSON blob into `localStorage`
would have been trivial and would have broken the invariant from
[ADR 0028](0028-webapp-vault-persistence-and-unlock.md) /
[ADR 0033](0033-browser-device-identity-storage.md) that a browser client persists
**only sealed containers**. Reusing the sealed container keeps the pin store on the same
password and the same lock/unlock lifecycle. The pins are *public* key material, but
they are **security-critical local state** — an attacker who can rewrite them can
silence the alarm — so they get secret-grade treatment on both sides.

### 2. A SAFETY NUMBER as the out-of-band check for first contact

Pinning is worthless on the **first** fetch: if the server lies then, the lie is what
gets pinned. The answer is a short, deterministic, human-comparable fingerprint that two
people read to each other over a channel the server does not control.

```
digest = SHA-256( "sigil-safety-number-v1\n"
                ‖ u32_be(len(device_id)) ‖ device_id
                ‖ u32_be(32)             ‖ x25519_public_key
                ‖ u32_be(1184)           ‖ mlkem_encaps_key )

rendered = 6 groups of 5 digits; group[g] = u40_be(digest[5g..5g+5]) mod 100000
           e.g. "83791 28129 67801 50284 55242 77845"
```

Every design choice in there is deliberate:

- **Domain-separated prefix**, so this digest can never collide with another use of
  SHA-256 in the system. Changing it changes every safety number in existence and is a
  version bump, not a bug fix.
- **Length-prefixed fields**, so no two different inputs produce the same byte stream
  (`"ab"+"c"` cannot collide with `"a"+"bc"`).
- ⭐ **Both halves of the hybrid key are covered.** A substitution that swapped only the
  ML-KEM half would still change the number.
- ⭐ **The device id is bound in.** A *genuine* key relayed under a **different**
  device's id does not verify — "is this the right key" is meaningless without "…for the
  right device".
- **Raw decoded bytes, not base64 text**, so a server re-encoding the same key cannot
  raise a false alarm.
- **30 decimal digits ≈ 99.6 bits** — short enough to read aloud, long enough that
  finding a second key with the same number is not an attack anyone mounts. It is a
  fingerprint **for human comparison**, not a programmatic identifier.

The **pairwise** form sorts the two per-device digests **bytewise ascending** and hashes
them under a separate prefix (`"sigil-safety-number-pair-v1\n"`). Sorting is the whole
trick: it makes the input, and therefore the output, identical whichever side computes
it, so both people see the **same** digits and cannot compare the wrong pair.

The construction is **MIRRORED — NOT SHARED** across the two implementations
(`cli/src/lib.rs` and `sigil-wasm/sharing.mjs`) and **must stay byte-identical**: if the
two ever diverge, two people comparing digits across clients would see different numbers
and wrongly conclude they were under attack. Both carry the **same known-answer test**,
and `sigil-wasm/test/pinning-interop.mjs` compares the **real `sigil` binary's** printed
digits against the JS module's.

### 3. ROTATION with re-wrap as the answer to revocation

Revocation stops future server access; it cannot make a device forget a key. So retire
the key. `rotate_vault_key` / `rotateVaultKey`:

1. load the current vault key from the local keyring (only an **already-shared** vault
   can be rotated — a password vault goes through `vault rekey` first);
2. ⭐ **pin-check EVERY recipient first**, so a mismatch aborts the whole rotation
   **before any local or remote state is mutated**;
3. draw a **fresh** 32-byte vault key from the CSPRNG — new, not derived from the old;
4. **re-seal** the container: open with the old key, seal with the new one, **never
   inspecting the plaintext** (so it re-keys a TOTP vault or any other `SIGILcli`
   container identically, with no format change);
5. write it `0600` via **temp file + rename**, so a crash cannot leave a half-written
   vault;
6. record the new key in the keyring **after** the file is in place — the other order
   would leave the keyring naming a key that opens nothing;
7. wrap and **upsert** an envelope per recipient;
8. **list**, then **delete**, every envelope not in the recipient set.

Steps 2 and 6 are the two orderings that matter, and both were chosen for the failure
case rather than the happy path: a half-rotated vault whose new key had already been
wrapped to an attacker would be worse than no rotation at all.

Two **new server routes** support step 8 — `GET /v1/vaults/{vaultID}/keys` (recipient
**metadata only**: device id, sender, size, timestamp — never a blob) and
`DELETE /v1/vaults/{vaultID}/keys/{deviceID}`. Both are **dev-gated** with everything
else and both reuse the **existing** `authorizeOpsRequest` with `needWrite` — the very
same check that authorizes depositing an envelope. That is the correct bar rather than a
stricter one: a device that can deposit an envelope can already **replace** any envelope
in the vault, so enumerating and deleting them grants it no new power. `sigild` gained
**no** knowledge of pins or safety numbers — it stores none, serves none, validates none
— and still has exactly **one** direct dependency.

## Consequences

### Good

- **The key-substitution attack is blocked after first contact**, and the block is
  proven rather than asserted: `sigil-wasm/test/pinning-interop.mjs` puts a **rewriting
  proxy** in front of a real `sigild` that swaps the victim's hybrid public key for an
  attacker's — exactly what a hostile registry would do — and shows the CLI refusing,
  the stored envelope staying **byte-identical to the honest one**, and that envelope
  **failing to open** with the attacker's hybrid secret. The JS client throws
  `KeyPinMismatchError` on the same attack.
- **First contact is now verifiable at all**, which it was not before. Two people can
  compare 30 digits over a phone call and know they are wrapping to the right key.
- **The two implementations agree**, checked by known-answer tests on both sides plus a
  cross-tool test driving the real binary. An independent reimplementation from the
  spec text alone — no project code — produced identical output for both the per-device
  and the pairwise number.
- **Revocation finally has a remediation.** A vault key can be retired and re-wrapped to
  exactly the devices that keep access, with the others' envelopes deleted.
- **No new server trust, and no new server dependency.** The whole trust mechanism is
  client-side; the two new routes are minimal, dev-gated, and reuse the existing
  authorization choke point.
- **The browsers still persist only sealed containers.** The invariant survived a
  feature that could easily have broken it.
- **Errors explain themselves.** The refusal names the device, shows both safety
  numbers, states the two possible causes, states that nothing was wrapped or uploaded,
  and says what to do next.

### Bad / accepted costs — every residual risk, stated

- ⚠️ **First contact is still trust-on-first-use.** Pinning cannot protect the first
  fetch; a server that lies the very first time gets its lie pinned. The safety number
  closes that window **only if a human actually compares it**. Nothing forces the
  comparison, nothing detects that it was skipped, and a first-sight share proceeds with
  a warning. This is the honest limit of TOFU, and it is why the cross-signature below
  remains the highest-value follow-up.
- ⚠️ **A user who blindly re-pins defeats the entire mechanism.** `--yes` and the
  optional safety-number check raise the cost of doing it thoughtlessly; they cannot
  prevent a user who re-pins to make an error message go away. The `repins` counter
  preserves the evidence, not the safety.
- ⚠️ **Rotation protects FUTURE content only.** A device that already unwrapped the
  previous key keeps that key and everything it had already copied. Cryptography cannot
  un-send a secret. Deleting an envelope stops a device collecting anything **new**; it
  does not reach into that device.
- ⚠️ **Rotation is manual and owner-driven.** Nothing re-keys on revoke, there is no
  rotation schedule, and there is no forward secrecy for a vault key already delivered.
- ⚠️ **The pin store is only as safe as its host.** Anything that can rewrite
  `hybrid-pins.json` (a native attacker running as that user) or the unlocked browser
  state can silence the alarm before it fires.
- ⚠️ **A legitimate re-enrolment is indistinguishable from an attack**, by construction,
  so it also trips the alarm and also needs an out-of-band check plus a deliberate
  re-pin. That friction is the price of the guarantee, and the test exercises it.
- ⚠️ **The digest is a third mirrored construction to keep in sync**, alongside the
  contract-v3 message and the container formats. Divergence would be *misdiagnosed as an
  attack* by users, which is a worse failure mode than a `401`. The known-answer tests
  and the cross-tool test exist for exactly that reason.
- ⚠️ **Two more routes on the server's attack surface**, however minimal, and one more
  metric (`sigild_key_envelope_deletes_total`).
- ⚠️ **None of this is audited**, and it is in the same dev-gated, plain-HTTP,
  do-not-store-real-secrets posture as everything around it. **Nothing here makes the
  system "secure"** — it closes one specific, documented hole and narrows another.

### Alternatives rejected

- **Warn on a changed key instead of blocking.** Rejected: the cost of clicking through
  is total compromise of the shared vault, and a warning that can be dismissed is a
  warning that will be. Blocking with a clear explanation and a deliberate escape hatch
  is strictly better, and it is why there is no accept-changed-key flag anywhere.
- **Cross-sign the hybrid public key with the device's enrolled Ed25519 identity**
  (sign at publish, verify at wrap). This is the **better** long-term answer — it would
  remove the human from the loop and protect first contact automatically. Deferred, not
  dismissed: it changes the publish route's payload and the registry schema, so it is a
  coordinated protocol change across four clients and the server, whereas pinning plus a
  safety number is purely client-side and could ship complete and proven now. It remains
  the highest-value follow-up, and it composes with pinning rather than replacing it
  (the enrolled key itself is still fetched from the same registry, so a first-contact
  trust anchor is still needed).
- **A key-transparency log** (Merkle-tree gossip, CONIKS/Key-Transparency style).
  Rejected for now as far too large for this phase and pointless without a second party
  to gossip with; it is the eventual answer at product scale.
- **Compare vault-key fingerprints after the fact** (what `vault list` already allows).
  Rejected as a *defense*: it detects the **result** of a substitution after the key has
  already been handed over. Detection after key disclosure is not prevention.
- **Auto-re-pin after a delay, or trust-on-first-use with a grace period.** Rejected:
  any rule that eventually accepts a changed key without a human is a rule an attacker
  waits out.
- **Hex or base32 fingerprints instead of digits.** Rejected: digits are markedly easier
  to read aloud accurately over a phone, which is the actual channel this defends, and
  grouping into fives is the well-established pattern for exactly this task.
- **Derive the new vault key from the old one** on rotation (e.g. `HKDF(old_key)`).
  Rejected outright: anyone holding the old key could then compute every future key,
  which is precisely the property rotation exists to break.
- **Server-side revocation of envelopes / server-enforced rotation.** Rejected on the
  same grounds as everything else in this architecture: it would make the server a
  participant in key management, and the server is the adversary this ADR is about.
- **Let `requirePinStore` default to an empty store when none is passed.** This is what
  the code originally did, and it was **fixed to fail closed** during this phase: a
  caller that forgot to pass its pins would silently get "every key is first-sight",
  i.e. the security control would degrade into a no-op with no error anywhere. It now
  throws. That change immediately surfaced one genuine stale caller (a pre-Phase-50 test
  relying on the fallback), which is the argument for fail-closed in miniature.

## The choke point is now enforced by TYPE (added Phase 54, 2026-07-28)

§1 above states the rule that matters: *"the enforcement rides on the fetch
itself … every wrap path goes through it."* Per the addendum rule the text above
is untouched; this records what changed and why it had to.

**Phase 54 violated that rule one phase after it was written down, and a verifier
caught it.** [ADR 0042](0042-recovery-kit.md)'s first implementation put its
extra safety-number requirement on the **`recovery cover` command** rather than
on the fetch — and `sigil vault share --to <kitID>` and
`sigil vault rotate --to <kitID>` reached the **identical wrap** through ordinary
first-sight TOFU, showing the human the safety number only **after** the wrap and
upload had completed.

The fix hardened this ADR's own mechanism for every caller:

- The pinned fetch is now reached through **one gate**,
  `verify_recipient_for_wrap` / `verifyRecipientForWrap`, which returns a
  **`VerifiedRecipient`** whose fields are **private** and which has **no other
  constructor**. The single wrap→deposit→grant path takes `&VerifiedRecipient`, so
  a caller cannot reach the wrap without passing the gate — the check is no longer
  something a new call site can forget.
- Two refusals join the hard-refusal set of §1's table, both leaving **nothing
  wrapped, nothing uploaded and the pin store unmutated**:
  `SafetyNumberMismatch` (a supplied `--safety-number` that does not match what
  the server is serving — checked **before** the pin lookup, so it applies to
  pinned keys too) and `UnverifiedRecoveryKit` (a first-sight wrap to a **recovery
  kit**, whose safety number is printed on its sheet).
- **Every refusal now happens BEFORE the key is pinned.** Pinning a refused key
  would let a retry see `Match` and proceed — the alarm would silence itself.
- A fourth trust outcome, **`Derived`**, exists for a key a client derived locally
  from a recovery secret: it is **never fetched**, so there is nothing for a server
  to substitute.

⚠️ **The first-contact limit of the "Bad / accepted costs" section is unchanged**,
and the kit rule inherits a dependency of its own: recognising that a recipient
*is* a kit uses a device **label** served by `GET /v1/account`, so a server that
renames or hides it degrades a kit wrap back to ordinary first-sight TOFU. See
[ADR 0042](0042-recovery-kit.md) §5 for the exact claim that can honestly be made.

## The superseded choke point has been DELETED (added Phase 57, 2026-07-28)

§1 above names `fetch_hybrid_key_pinned` (Rust) / `fetchHybridKeyPinned` (JS) as
the function every wrap path goes through. Per the addendum rule that text stays
as written; this records that **both functions no longer exist**.

The addendum above replaced them as the gate in Phase 54. What it did not do was
remove them. The Rust one was left as a public `pub fn` with **zero callers and
zero tests**; the JS one survived with exactly **one** caller, a test. Meanwhile
this ADR, `crypto-spec.md`, `architecture.md`, `threat-model.md`, `api.md` and
`CLAUDE.md` all still recommended them by name.

The fourth full-repo audit named that for what it was: a **ready-made bypass of
the type gate**. `fetch_hybrid_key_pinned` fetches and pins, but it does **not**
refuse an unverified recovery kit and does **not** honour a caller-supplied
safety number — so the next caller who reached for the familiar, still-documented
name would have gotten a wrap that skipped two of the three refusals, silently
and without touching the gate at all. **A superseded choke point is not harmless
dead code.**

Both are deleted, each leaving a tombstone comment at its old location naming the
replacement:

- **to WRAP** — `verify_recipient_for_wrap` / `verifyRecipientForWrap`, the only
  thing that can produce a `VerifiedRecipient`, which is the only thing the
  wrap→deposit→grant path accepts;
- **to DISPLAY** (a safety number, a reachability probe, a deliberate re-pin) —
  the bare `fetch_hybrid_key` / `fetchHybridKey`, which wraps nothing.

The JS test's single call was **moved onto the real gate** rather than deleted, so
what it proves is now what the product does. Nothing about the trust model in this
ADR changed: the same refusals, in the same order, on the same path.
