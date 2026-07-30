# 0048 — Authenticated, context-bound vault-key envelopes

- **Status:** Accepted (2026-07)
- **Date:** 2026-07-30
- **Builds on:** [0013](0013-hybrid-public-key-seal.md) (the anonymous
  `hybrid_seal` / `hybrid_open` KEM-then-AEAD, which **remains** and is still the
  right shape for the thing it was designed for),
  [0035](0035-device-to-device-vault-sharing.md) (the vault-sharing flow whose
  envelope this replaces), [0038](0038-key-pinning-safety-numbers-and-vault-rotation.md)
  (pinning + safety numbers + the typed wrap gate, whose choke-point rule this
  decision applies to the **unwrap** side), [0011](0011-hybrid-kem-combiner.md)
  (the anonymous hybrid combiner this one is domain-separated from),
  [0007](0007-caller-supplied-entropy-in-core.md) (caller-supplied entropy —
  three fresh values per wrap, none of them drawn in the core),
  [0042](0042-recovery-kit.md) (the recovery kit, which is a *recipient* of wraps
  and whose pre-print round trip is the one place a device unwraps its own wrap).
- **Changes nothing in:** `sigild`. **No route, no header, no canonical message,
  no migration, no table, no metric, no dependency, no schema-version bump.** The
  envelope is opaque to the server and stayed opaque; only its bytes changed, and
  the server never looked at them. `sigild` still has exactly one direct Go
  dependency (`pgx`), and request authentication is still classical Ed25519
  contract v3. `git diff --stat sigild/` for this phase is empty.

## Context

### The hole

Reproduced with the shipped binary and nothing else — no server, no privileged
position, no stolen secret:

```
$ sigil hybrid-keygen --out b.hybrid        # the victim; only b.hybrid.pub is ever published
$ head -c 32 /dev/urandom > attacker_key.bin
$ sigil hybrid-seal --recipient-pub b.hybrid.pub --in attacker_key.bin --out forged.env
    forged.env: 1226 bytes, magic SIGILhyb   <- byte-shaped IDENTICALLY to a genuine wrap
$ sigil hybrid-open --key b.hybrid --in forged.env --out recovered.bin
    exit=0   recovered = 32 bytes, IDENTICAL to the attacker's chosen key
```

Three defects lined up, and all three had to hold for the attack to work:

1. **`hybrid_seal` is anonymous.** It is an ephemeral-static KEM — HPKE
   `mode_base` — so the sender's only key is a per-message ephemeral. Holding the
   **recipient's public key** is the entire input needed to produce a container
   that recipient will open. And `sigild` serves every device's published hybrid
   public key to every authenticated device: that is the whole point of
   `GET /v1/devices/{deviceID}/hybrid-key`.
2. **The AAD was a fixed constant.** Every hybrid container in the system was
   sealed under `HYBRID_AAD = b"sigil-hybrid-cli/1"`, which bound it to **no
   vault, no recipient, no sender and no purpose**. That is precisely why the
   output of the general-purpose *file-encryption* command was a structurally
   valid *vault-key envelope*.
3. **`unwrap_vault_key`'s only check was `len == 32`.** A forged key is exactly
   32 bytes.

⛔ **And ADR 0038's pinning did not mitigate any of it, for a reason worth
stating precisely: `vault accept` fetched no hybrid key at all.** The pin store
was not bypassed — it was never *consulted*. Every control this repo had built
against a key-substituting server lived on the **wrap** side. The **unwrap** side
had nothing.

Two working attacks were then driven against a live `sigild`:

- A **rewriting proxy** minted an envelope from the victim's published key and
  `sigil vault accept` took it with **exit 0 and no warning**; a TOTP secret was
  read out of the victim's vault in plaintext afterwards.
- A **co-tenant with `write` but not ownership** deposited a key it invented,
  because `share_vault_to_known_key` **PUT the envelope before requesting the
  grant** — so the deposit landed and the `403` arrived afterwards, too late to
  matter.

The adversary here is not exotic. It is *any* party that can read a published
public key and write to a mailbox: a co-tenant on a shared vault, a
revoked-but-not-yet-rotated device, a breached relay. Everything the victim wrote
after accepting the forged key was readable by whoever chose it.

### ⚠️ Two load-bearing documents asserted the opposite

This is the part that must not be quietly rewritten, because both paragraphs sit
exactly where an external reviewer decides whether to look further.

**`docs/threat-model.md`, row V ("Envelope replayer / substituter") said:**

> *"A substituted envelope also **fails to open**: `hybrid_open` authenticates, so
> a wrong or tampered container yields an authentication failure, never plaintext,
> and `unwrap_vault_key` additionally rejects any recovered plaintext that is not
> exactly 32 bytes rather than using it as a key."*

**That was wrong.** It is true of a *tampered* envelope and false of a *freshly
minted valid* one — which is the actual attack. The second clause is true and
irrelevant: a forged key is exactly 32 bytes, so the length check passes. A
mitigation that is true but does not bear on the attack reads, to a reviewer, as
coverage.

**`docs/crypto-spec.md` said:**

> *"the server … **cannot mint** a valid envelope for a device without that
> device's public key producing ciphertext only that device can open."*

**That was wrong**, and self-evidently so: the table **immediately above that
sentence** lists device hybrid **public** keys among the things the server *has*.
The sentence assumed possession of the public key was the barrier. It was the
requirement.

The same section also called the construction **"hybrid public-key
authenticated encryption"** throughout. It was HPKE `mode_base` — no sender key
existed anywhere in it. The word "authenticated" was describing the AEAD
(ciphertext integrity), and it read as sender authentication. **It is
`mode_auth` now; it was not then.**

⚠️ **The lesson generalises:** these were not stale docs left behind by a change.
They were written at the same time as the code and were wrong on the day they
were written, because both described the *intent* of the flow rather than what
the primitive underneath it does. Neither would have been caught by any drift
check, because nothing drifted.

## Decision

### 1. An authenticated hybrid KEM in the core — `libsigil/core/src/hybrid_auth.rs`

A new module composing the primitives already present. **No new dependency, no
new low-level cryptography, no randomness, no clock.** The shape is HPKE's
`mode_auth`: the sender also holds a long-term ("static") X25519 key pair, and a
third Diffie–Hellman between the sender's static secret and the recipient's
static public key is mixed into the KDF.

```text
  ss_e = X25519(eph_secret,           recipient_x25519_pub)   -- ephemeral-static
  ss_s = X25519(sender_static_secret, recipient_x25519_pub)   -- static-static  <- THE AUTHENTICATION
 (mlkem_ct, ss_kem) = ML-KEM-768.Encaps(recipient_encaps_key, coin)

  transcript = SHA-256( "sigil-hybrid-auth-v1\n"
                      ‖ u32_be(32)   ‖ eph_x25519_pub
                      ‖ u32_be(1088) ‖ mlkem_ct
                      ‖ u32_be(32)   ‖ sender_static_x25519_pub
                      ‖ u32_be(32)   ‖ recipient_x25519_pub )

  ss = HKDF-SHA256( ikm  = ss_e ‖ ss_kem ‖ ss_s ‖ transcript,
                    salt = none,
                    info = "sigil-hybrid-auth-v1" )            [32 bytes]
```

Every transcript field is length-prefixed, so no two distinct field sets
serialise to the same bytes. The transcript binds the ephemeral key, the ML-KEM
ciphertext, **the sender's identity** and **the recipient's identity**, so a
capture cannot be re-attributed to a different sender or re-aimed at a different
recipient without changing the derived key.

⭐ **`sender_static_x25519_pub` is an INPUT to decapsulation, not something read
out of the ciphertext.** The container deliberately does **not** carry it.
Passing the wrong sender yields a different secret and therefore an AEAD failure
— the recipient learns *"this did not come from who I expected"* without any
string comparison being trusted. Carrying the sender's identity in the
attacker-controlled bytes and then "verifying" against it is the exact mistake
this fixes.

The `info` label (`"sigil-hybrid-auth-v1"`) domain-separates this combiner from
the anonymous one (`"sigil-hybrid-v1"`, ADR 0011), so the same material can never
yield the same key through both derivations.

### 2. A context-bound AAD — `vault_key_wrap_aad`

Authentication says *who made this ciphertext*. It does not say *what it was
meant for*. So the fixed tag is replaced, for vault-key wraps only, by:

```text
  "sigil-vault-key-wrap-v1\n"
  ‖ u32_be(len(vault_id))            ‖ vault_id
  ‖ u32_be(len(recipient_device_id)) ‖ recipient_device_id
  ‖ u32_be(len(sender_device_id))    ‖ sender_device_id
```

which makes four re-filing attacks impossible, none of which the AEAD could
otherwise see because the ciphertext itself is unchanged in each:

- a **file** envelope can never be presented as a **vault-key** envelope, or vice
  versa (different domain string) — closing defect 2 above;
- an envelope for vault A cannot be moved to vault B;
- an envelope addressed to device X cannot be re-filed under device Y;
- an envelope from sender S cannot be re-attributed to sender T.

The AAD travels in the clear inside the envelope and is authenticated by the AEAD
tag, so a mismatch is an authentication failure, never a silent success. It is
additionally compared **before** the AEAD is entered, so the caller never has to
trust an attacker-supplied context string.

**Golden vector**, pinned in `hybrid_auth.rs` and mirrored in JS —
`vault_key_wrap_aad("demo", "dev_bob", "dev_alice")`:

```
736967696c2d7661756c742d6b65792d777261702d76310a
0000000464656d6f
000000076465765f626f62
000000096465765f616c696365
```

56 bytes: a 24-byte prefix, then three length-prefixed fields. The combined-secret
KAT over fixed seeds is pinned alongside it
(`7d5cda4ae644faeb3fe30d492886bcd7961ed08c196b990c34bc9760be8c42b0`).

### 3. `SIGILhyb` container version 1 → 2, with **no compatibility flag**

The framing is unchanged; only the version byte at offset 8 moves.

```text
  offset  size    field
  ------  ------  -----------------------------------------------
  0       8       magic          = b"SIGILhyb"
  8       1       version        = 2   (1 = ANONYMOUS, 2 = AUTHENTICATED)
  9       32      eph_x25519_pub (the sender's EPHEMERAL X25519 public key)
  41      1088    mlkem_ct       (ML-KEM-768 ciphertext)
  1129    ..      envelope       (the hybrid_auth_seal envelope — carries the AAD)
```

⛔ **A version-1 container is refused wherever a vault key is expected, before any
cryptography runs.** There is no flag, option, environment variable or default
anywhere that accepts one.

**Why no compatibility mode, when this repo is otherwise careful about
backward compatibility** (ADR 0024's forward-compatible vault schema, ADR 0036's
`SUPPORTED_DEVICE_IDENTITY_VERSIONS = [1,2,3]`): those are cases where an old
reader misunderstanding new data is a *usability* problem. **Here, accepting v1
IS accepting the vulnerability.** A v1 container proves nothing about who made
it; a client that falls back to it can be *made* to fall back to it by the party
who benefits. A "warn and accept" mode would have been strictly worse than no fix
at all, because it would have carried the appearance of one. The cost is stated
plainly in the limits below: every existing envelope must be re-issued.

⭐ **The anonymous v1 form is KEPT** for `sigil hybrid-seal` / `hybrid-open`,
which are honestly anonymous file encryption to a public key and where
`mode_base` is the correct primitive. The two uses are now domain-separated
**three ways** — version byte, HKDF `info` label, and AAD prefix — so neither can
be substituted for the other in either direction. Defect 2 was, at bottom, one
`SIGILhyb` type serving two purposes with nothing distinguishing them.

### 4. A typed unwrap gate — `VerifiedSender`

ADR 0038 established the rule: *the choke point is the fetch, and every wrap path
goes through it*, enforced by a type (`VerifiedRecipient`) with no public
constructor. **That rule had never been applied to the receiving side.** It is
now, symmetrically:

`unwrap_vault_key` takes a `&VerifiedSender`. `VerifiedSender` has **private
fields and no public struct literal**, so its signature is a proof rather than a
convention. It exists in exactly two ways:

- **`verify_sender_for_unwrap`** — fetches the depositing device's published
  hybrid key and pin-checks it, with the **same trust table as the wrap side**:
  a locally derived key is `Derived` (no fetch at all); a byte-identical pinned
  key is `Pinned`; a **changed** pinned key is a hard `PinMismatch` with the pin
  store **not mutated**; a first sight with a matching `--safety-number` is
  `VerifiedFirstSight`; a **wrong** supplied safety number is a hard
  `SafetyNumberMismatch`; a first sight with no number is
  `UnverifiedFirstSight` (proceeds, **warns**). As on the wrap side, **every
  refusal happens before the key is pinned**, so a retry cannot silence its own
  alarm by pinning what was just refused.
- **`VerifiedSender::from_local`** — this process holds the sender's *secret*
  half, so nothing was fetched and there is nothing for a server to substitute.
  Not a bypass: anyone who can construct it already *is* the sender. Used where a
  device unwraps a wrap it made itself (`vault rekey --publish`, the recovery
  kit's mandatory pre-print round trip).

The JS mirror is `verifySenderForUnwrap` / `verifiedSenderFromLocal` /
`VerifiedSender` in `sigil-wasm/sharing.mjs`, with the same instance check.

### 5. Open before writing, and never silently replace

Two further controls on `accept_vault_key`, which are **each other's only
backstop**:

- ⭐ **OPEN BEFORE WRITING.** The recovered key must actually open the vault's
  newest op before it is written to the keyring — the shape `recovery_restore`
  already used. A key that opens nothing never reaches local state. (A vault with
  no ops yet is the one exception, reported as `verified_against_tip: false`
  rather than silently.)
- **NEVER SILENTLY REPLACE.** An existing, *different* keyring entry requires an
  explicit `--replace` (`replace: true` in JS). Overwriting is how a hostile
  deposit takes a vault away from a device that already had it; the refusal names
  both fingerprints and never a key byte. An identical key is a no-op re-accept.

⭐ **Both live where the key is PRODUCED, not at the call sites.** `acceptVault`
returns the key for the caller to persist, so a call-site check would have been
duplicated in every client and forgettable in each. Enforcing it at the point of
production means a client physically cannot obtain a key that opens nothing, or
one that displaces a held key without saying so.

### 6. Authorize, then deposit

`share_vault_to_known_key` **granted after depositing**. A device with `write` but
no ownership therefore got its envelope **stored** and only then met the grant
route's `403` — the co-tenant attack above. The order is now **grant first, then
deposit**: a failed grant means nothing was deposited. The reverse failure (grant
succeeds, deposit fails) is the safe one — the recipient can read ciphertext it
has no key for, which is the state every recipient is in before a share anyway.

⚠️ **Authorize-first exposed a cliff the old order had been hiding**, and it is a
deliberate behaviour change: only a vault's **owner** may grant, ownership is
trust-on-first-**write** (ADR 0040), so a vault never written to this server has
**no owner** — and the very first share of a never-pushed vault is now refused.
Under deposit-then-grant, the deposit silently claimed it. The `403` therefore
carries prose naming both causes and the remedy ("push it first"), because the
bare server message is true and useless.

## Why sender authentication uses the HYBRID key, not an Ed25519 signature

The obvious alternative — have the sender **sign** the envelope with the Ed25519
device key it already uses for every request — was considered and **rejected**.
The reason is structural, not aesthetic.

**No route serves a peer's Ed25519 public key.** `sigild`'s `deviceJSON`
(`internal/api/devices.go:61`) carries `device_id`, `account_id`, `label`,
`status`, `created_at`, `revoked_at` — and the comment above it says it
*deliberately omits the public key*. The registry holds each device's Ed25519 key
to **verify that device's own requests**; it never hands one device another
device's signing key. So a signature-based fix is not "add a signature". It is:

1. **A new `sigild` route** (or a new field on an existing one) publishing device
   Ed25519 public keys — new surface, new authorization question, on a server
   this phase otherwise leaves byte-for-byte untouched.
2. **A second pinned key type** in every client's trust store. Two keys per peer
   means two pin records, two mismatch paths, two first-sight decisions, and the
   possibility of them disagreeing — a state with no defined meaning.
3. **An impossible choice about the safety number.** The safety-number digest
   (ADR 0038) covers the device id and **both halves of the hybrid key**. Adding
   an Ed25519 key to the trust decision means either:
   - **adding it to the digest** — which changes every safety number, and
     therefore **invalidates the number printed on every recovery kit sheet
     already in a user's hands** (ADR 0042 prints it on the paper); or
   - **leaving it out of the digest** — in which case the digits two people read
     to each other **do not cover the key that authenticates the envelope**, and
     the out-of-band check silently stops covering the thing it exists to check.

Using the **hybrid** key avoids all three. It is **already published** (`PUT/GET
/v1/devices/{deviceID}/hybrid-key`), **already pinned**, and **already covered by
the safety number**. The trust machinery that had to exist for the wrap side to
work is exactly the machinery the unwrap side needed, and it needed **no new
server surface at all**. That the fix requires no `sigild` change is not a
coincidence — it is the consequence of authenticating with the key the trust
model already knows about.

A static-static DH also buys a property a signature does not, discussed next.

## ⚠️ Honest limits

**Stated at least as loudly as the feature, because two of these are the same
class of gap that produced the vulnerability.**

### 1. ⛔ The sender authentication is CLASSICAL ONLY. Confidentiality is hybrid; authentication is not.

`ss_s` is a plain X25519 Diffie–Hellman. **ML-KEM has no static-static analogue**
— a KEM encapsulates to a fresh public key and produces a ciphertext; there is no
"both parties' long-term keys" operation to mix in. The core says so at
`libsigil/core/src/hybrid_auth.rs:71-76`, quoted verbatim:

> ⚠️ **The post-quantum half is NOT authenticated.** `ss_s` is classical X25519
> only. A quantum adversary that can break X25519 could forge a ciphertext, even
> though it still could not *read* one (that needs ML-KEM too). Making
> authentication post-quantum needs an ML-KEM static-static encapsulation or an
> ML-DSA signature; neither is wired in here, and this module does not claim
> post-quantum authentication.

So the guarantees are **asymmetric**, and the asymmetry must not be rounded off:
breaking **confidentiality** requires breaking **both** X25519 and ML-KEM-768;
forging **authenticity** requires breaking **X25519 alone**. The SYSTEM is **not
"post-quantum secure"**, and this construction does not move it closer to being
so on the authentication axis. Making it post-quantum would need either an
ML-KEM-based static-static construction (which is not a standard operation) or
the ML-DSA-65 half of the hybrid signature — which exists in the core
(`hybrid_sig.rs`) but is wired into nothing and, per the section above, cannot be
bolted on here without new server surface and a broken safety number.

### 2. FIRST SIGHT of a sender is still trust-on-first-use

`verify_sender_for_unwrap` pins on first sight and **proceeds with a warning**.
Against a **key-substituting server**, first contact is undefended in *both*
directions — the server can serve its own key as "the sender's" **and** forge an
envelope under it. This is ADR 0038's accepted limitation, unchanged and now
symmetric; `--safety-number` (`expectedSafetyNumber` in JS) closes it, but **only
if a human actually compares the digits**.

⭐ What authentication buys **unconditionally** is the *other* adversary — a
co-tenant with write access, a revoked device, any party that is not the server.
That attacker can no longer mint an acceptable envelope **at all**, safety number
or not. Against the server itself, a pinned sender is a hard stop on change, and
first contact is the human's job. **Do not read this as "the forgery is fixed";
read it as "the forgery now requires being the server, and is detected the moment
a pin exists."**

### 3. The authentication is implicit, key-confirmed, and NON-TRANSFERABLE

This is **not a signature**. `ss_s` proves the ciphertext was produced by someone
holding the sender's static X25519 secret — and the recipient **cannot prove that
to anyone else**, because the recipient could have produced it too (it knows
`ss_s` as well). There is **no non-repudiation** and there is **nothing to show a
third party**.

For the question actually being asked — *"did MY peer choose this vault key, or
did somebody else?"* — that is exactly the property required, and the
deliberately weaker one is the better fit: a vault-key wrap should not be
evidence, held by whoever receives it, that a particular device shared a
particular vault. But it means **no audit, dispute or forensic process can rest
on an envelope**, and any future requirement for transferable proof needs a
signature and therefore the whole cost enumerated above.

### 4. ⛔ Every existing envelope must be re-issued

There is no migration and there cannot be one: a v1 envelope carries no sender,
so nothing can retroactively establish who made it. **Every wrapped vault key
deposited before this change is now refused**, and the remedy is manual —
`sigil vault share` / `vault rotate` / `recovery cover` again from a device that
holds the key, or the equivalent in the browser and desktop clients. ⚠️ **This
includes recovery kits**: a kit covered before this change cannot open those
vaults until re-covered, and **a printed sheet whose vaults are never re-covered
recovers nothing**. Since this repo is pre-launch and holds no real user data,
that cost is paid once, now, by us — which is the only reason a no-compatibility
break is defensible here and would not be later.

### 5. The rest, unchanged

- **UNAUDITED**, and a **custom composition**: this is HPKE `mode_auth`'s *shape*
  but it is **NOT RFC 9180 HPKE** and shares none of its test vectors.
- **No forward secrecy for the recipient.** `ss_e` protects against later
  compromise of the *sender's* static secret; compromise of the recipient's
  hybrid secret opens every envelope ever addressed to it.
- **Revocation still cannot un-learn a key** a device already unwrapped;
  remediation is `vault rotate`, which protects **future content only**.
- **Sender identification on accept is server-supplied** when `--from` is
  omitted — it comes from this device's own envelope index. That is *safe* (the
  wrong id makes the unwrap fail, since the sender's key is an input to the
  derivation, not a compared string) but it means a lying server can turn a
  successful accept into a *failed* one. Denial, not forgery.
- **No zeroization** of component secrets beyond what the dependencies do.
- **No rate limiting** on envelope deposit; one mailbox per (vault, recipient),
  so any authorized writer can still overwrite a *pending* envelope.

## The sentence an auditor should be able to check

A vault-key envelope is a **version-2 `SIGILhyb` container** whose AEAD key is
derived from **three** shared secrets — ephemeral-static X25519, ML-KEM-768, and
**static-static X25519 between the sender and the recipient** — bound to a
transcript naming both identities, and sealed under an AAD naming **the purpose,
the vault, the recipient device and the sender device**. Producing one requires
the **sender's** secret, not merely the recipient's published public key.
Consuming one requires a `VerifiedSender` — a type with no public constructor —
so the pin store is consulted on the **unwrap** path, which it never was before.
A **version-1** container is refused wherever a vault key is expected.
**Confidentiality is hybrid; authentication is classical X25519 only.**

## Consequences

**Good**

- The reproduced forgery no longer works. An attacker holding only the
  recipient's published hybrid public key cannot produce an acceptable envelope —
  pinned as a core test (`public_material_alone_cannot_forge_an_authenticated_record`)
  that hands a forger *everything* public and withholds only `ss_s`.
- The unwrap side has the same typed choke point the wrap side has had since
  Phase 54, so ADR 0038's rule now holds in both directions.
- A re-filing attack (wrong vault, wrong recipient, wrong sender, wrong purpose)
  is an authentication failure rather than a silent success.
- **`sigild` changed by zero lines**, and the zero-knowledge boundary is
  untouched: the envelope was opaque before and is opaque now.
- No dependency was added anywhere; the core still draws no randomness and reads
  no clock; both `libsigil/Cargo.lock` and `sigil-wasm/Cargo.lock` still contain
  `getrandom` exactly **0** times.

**Bad / accepted**

- **Every existing envelope is invalid** (limit 4). No migration exists or can.
- The envelope is **no longer a fixed size**. It is
  `1244 + len(vault_id) + len(recipient_device_id) + len(sender_device_id)`
  bytes, because it carries its context AAD. Measured live at **1310 bytes** for
  a 14-character vault id and two 26-character server-assigned device ids
  (`sharing-interop.mjs`); the anonymous v1 **file** container remains a flat
  1226. ⚠️ Anything that hard-codes 1226 for a *vault-key* envelope is wrong from
  this phase on — and conflating the two sizes is precisely how a forgery came to
  be byte-shaped like a genuine wrap.
- **A new refusal on a previously-succeeding path** in the browser clients: an
  accept now fails when the sender rotated the key and has not yet pushed the
  re-sealed vault (open-before-write sees a tip the new key cannot open). The CLI
  and desktop always behaved this way; the browsers now match, and the error text
  names the remedy.
- **A new refusal on first share of a never-pushed vault** (`403`), per section 6.
- One more mirrored construction to keep byte-identical: the AAD layout and the
  container version live in Rust (`sigil-core`, single-sourced) and are reached
  from JS through the wasm, but `sigil-wasm/sharing.mjs` mirrors the *lengths* and
  the version constants. `sharing-interop.mjs` and `pinning-interop.mjs` are the
  guards.

## Alternatives rejected

| Alternative | Why not |
|---|---|
| **Ed25519 signature over the envelope** | No route serves a peer's Ed25519 key (`deviceJSON` omits it deliberately); needs new `sigild` surface, a second pinned key type, and either breaks every printed recovery sheet's safety number or leaves the spoken digits not covering the authenticating key. See the dedicated section above. |
| **Keep v1, warn on accept** | Accepting v1 *is* accepting the vulnerability, and the party who benefits is the one who can force the fallback. A warning would have carried the appearance of a fix without being one. |
| **Adopt RFC 9180 HPKE `mode_auth` wholesale** | Would replace the hybrid combiner (ADR 0011) that the whole PQ story rests on, and HPKE has no standardised X25519+ML-KEM hybrid `mode_auth` to adopt. We would still be running a custom composition, but with a name that implies otherwise — strictly worse for an audit. |
| **Sender's static public key carried inside the container** | Reading the sender's identity out of attacker-controlled bytes and then "verifying" against it is the mistake this ADR exists to fix. It is an input from the pin store, out of band. |
| **Check `len == 32` harder / validate the key's shape** | The forged key was a well-formed 32-byte key. No property of the plaintext distinguishes it. The defect was the absence of a sender, and only a sender fixes it. |
| **Fix it only in the CLI** (the reference implementation) | The browsers are the clients most likely to meet a hostile relay. A control present in one client and absent in another is the asymmetry the second verification round found; see the journal entry. |

## References

- `libsigil/core/src/hybrid_auth.rs` — the construction, the AAD, the golden
  vectors, and 13 tests including the forgery-refusal proof.
- `cli/src/lib.rs` — `hybrid_auth_seal_to_container` / `hybrid_auth_open_container`
  (container v2), `VaultKeyWrapContext`, `SenderIdentity`, `VerifiedSender`,
  `verify_sender_for_unwrap`, `accept_vault_key`, `share_vault_to_known_key`, and
  the `unwrap_gate_tests` module (a bare `TcpListener` *is* the hostile server).
- `sigil-wasm/sharing.mjs` — the JS mirror: `vaultKeyWrapAad`,
  `verifySenderForUnwrap`, `VerifiedSender`, `UnauthenticatedEnvelopeError`,
  `UnknownSenderError`, `VaultKeyDoesNotOpenError`, `VaultKeyReplacementError`,
  `requireHeldVaultKeys`, `wrappedVaultKeyLen`.
- `sigil-wasm/test/sharing-interop.mjs`, `sigil-wasm/test/pinning-interop.mjs`
  (section 7), `cli/tests/e2e-sharing.sh`,
  `web/apps/webapp/tests/envelope-auth.spec.ts`,
  `extension/tests/envelope-auth.spec.mjs`.
- [ADR 0013](0013-hybrid-public-key-seal.md), [ADR 0035](0035-device-to-device-vault-sharing.md),
  [ADR 0038](0038-key-pinning-safety-numbers-and-vault-rotation.md),
  [ADR 0042](0042-recovery-kit.md), [`../threat-model.md`](../threat-model.md)
  rows V and X, [`../crypto-spec.md`](../crypto-spec.md).
