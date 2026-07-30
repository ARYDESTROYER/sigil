# Sigil cryptographic specification (condensed)

> **Internal / pre-audit. UNAUDITED.** This describes the intended design of
> `libsigil`. The code in this repo implements **real but UNAUDITED** building
> blocks — the algorithm-suite registry, the envelope codec, an Argon2id KDF, an
> XChaCha20-Poly1305 + HKDF AEAD, a composed `seal_record`/`open_record`, a
> standalone classical **Ed25519 sign/verify** primitive, a standalone
> **ML-DSA-65 (FIPS 204) post-quantum signature** primitive, a standalone
> classical **X25519 key-agreement** primitive, and a standalone
> **ML-KEM-768 (FIPS 203) post-quantum KEM** primitive — none wired into a
> finished product. The **combined hybrid KEM** (X25519 + ML-KEM-768, combined via
> HKDF-SHA-256) is now **assembled as a standalone primitive** in `sigil-core`
> (`hybrid.rs`), joining the two halves it composes. The **combined hybrid
> signature** (Ed25519 then ML-DSA-65; verification requires **both**) is now
> **assembled as a standalone primitive** too, in `sigil-core` (`hybrid_sig.rs`),
> composing the Ed25519 half (`sig.rs`) and the ML-DSA-65 half (`mldsa.rs`). So
> **both hybrid constructions (KEM and signature) now exist**. The hybrid **KEM** is
> further composed with the AEAD into public-key encryption in **two** forms:
> the **ANONYMOUS** `hybrid_seal` / `hybrid_open` (`hybrid_seal.rs`, HPKE
> `mode_base`) — ⚠️ **this document called that one "authenticated" until Phase
> 60, which was WRONG: it has no sender key at all** — now used only for file
> encryption; and the **AUTHENTICATED** `hybrid_auth_seal` / `hybrid_auth_open`
> (`hybrid_auth.rs`, HPKE `mode_auth`'s shape, mixing in a **static-static X25519
> DH** so a forger needs the *sender's* secret and not merely the recipient's
> published public key), which **carries device-to-device VAULT-KEY WRAPPING**
> (see
> [Key hierarchy and vault sharing](#key-hierarchy-and-vault-sharing-hybrid_auth_seal--hybrid_auth_open-in-use),
> [ADR 0035](decisions/0035-device-to-device-vault-sharing.md) and
> [ADR 0048](decisions/0048-authenticated-vault-key-envelopes.md)), which makes it
> **load-bearing and squarely in scope for the audit**. ⛔ **That sender
> authentication is CLASSICAL X25519 ONLY** — ML-KEM has no static-static
> analogue, so **confidentiality is hybrid while authenticity is not**. Both forms
> remain a **custom
> KEM-then-AEAD composition — NOT RFC 9180 HPKE** — both remain **UNAUDITED**, and
> they do **not** make the SYSTEM "post-quantum secure". The hybrid **signature**
> (`hybrid_sign` / `hybrid_verify`) is **still unused by every flow** — all request
> authentication is classical Ed25519 only. Condensed
> from the product brief §11/§20/§21. Subject to change. A Cure53 audit of the
> hybrid construction is to be commissioned before public beta.

## Design principle

The server cannot decrypt user data, ever. Every encrypted record crosses the
client→server boundary as opaque ciphertext over hybrid post-quantum TLS.

## Primitives (intended)

| Role | Primitive |
| --- | --- |
| Password KDF | Argon2id (m = 64 MiB, t = 4, p = 2) → 256-bit master key |
| Per-vault key | HKDF-SHA-256 from the master key, per-vault salt |
| AEAD | XChaCha20-Poly1305 (24-byte random nonce; suite byte + record ID as AAD) |
| Classical KEX | X25519 |
| PQ KEM | ML-KEM-768 (FIPS 203) |
| Classical signature | Ed25519 |
| PQ signature | ML-DSA-65 (FIPS 204) |
| Hashing | SHA-256, BLAKE3 |
| Transport | TLS 1.3, hybrid `X25519MLKEM768` named group |

## Algorithm-suite registry

A single suite byte in every record's header selects the `(KDF, KEM, AEAD,
signature)` tuple. New suites are *added* without breaking decryption of older
records — clients dispatch on the byte. This is the crypto-agility property that
lets post-quantum suites migrate without a flag-day re-encryption. Implemented
in [`libsigil/core/src/lib.rs`](../libsigil/core/src/lib.rs).

| Byte | Suite |
| --- | --- |
| `0x10` | Legacy: PBKDF2 + RSA + AES-GCM + ECDSA P-256 |
| `0x11` | Classical: Argon2id + X25519 + XChaCha20-Poly1305 + Ed25519 |
| `0x12` | **CURRENT** — hybrid PQ: Argon2id + X25519&ML-KEM-768 + XChaCha20-Poly1305 + Ed25519&ML-DSA-65 |
| `0x13` | Future: classical-only deprecated, hybrid required |
| `0x14` | Reserved backup: HQC-192 KEM + SLH-DSA-128f signatures (for an MLWE break) |
| `0x15` | Future: FN-DSA-512 signatures (smaller, for the watch) |

## Crypto-agility envelope (intended layout)

```
[0]   version    (u8)     envelope format version (currently 0x01)
[1]   suite_id   (u8)     algorithm suite (e.g. 0x12)
[2..] aad_length (varint) length of AAD
[..]  aad        (bytes)  additional authenticated data
[..]  nonce      (bytes)  AEAD nonce (length per suite)
[..]  ciphertext (bytes)  encrypted payload
[..]  tag        (bytes)  AEAD authentication tag
[..]  kem_ct     (bytes)  KEM ciphertext — present only on key-rotation records
```

**Implemented (format `0x01`):** [`libsigil/core/src/envelope.rs`](../libsigil/core/src/envelope.rs)
is a concrete, self-describing codec — each variable field carries an unsigned
LEB128 varint length prefix and a `flags` byte marks the optional `kem_ct`, so
the frame parses unambiguously (the brief's prose left nonce/ciphertext/tag
boundaries implicit-by-suite). It is **serialization only — no encryption** — and
is covered by round-trip + negative-case tests.

## Hybrid construction (intended)

**Key encapsulation** (per RFC 9794 / NIST SP 800-56C Rev. 2):

```
ss_x        = X25519(sk_x, pk_x_peer)
ss_kem      = ML-KEM-768.Decap(sk_kem, ct_kem)
ss_combined = HKDF-SHA-256(ss_x || ss_kem || transcript_hash, "sigil-hybrid-v1")
```

Secure if **either** component is secure: breaking the construction requires
breaking both X25519 and ML-KEM.

**Signatures**: `Ed25519.Sign(m) || ML-DSA-65.Sign(m)`; verification requires
**both** to validate.

**KEM implementation status (pre-audit, UNAUDITED).** **Both halves of the hybrid
KEM exist as separate primitives in `sigil-core`, and the combiner over them is now
in productive use** (it wraps vault keys — see the combiner note below and
[ADR 0035](decisions/0035-device-to-device-vault-sharing.md)). The **classical X25519
key-agreement half** (`ss_x` above) is **implemented** in
[`libsigil/core/src/kx.rs`](../libsigil/core/src/kx.rs): a raw-bytes
`x25519_public_key` / `x25519_shared_secret` Diffie–Hellman over a
**caller-supplied 32-byte secret scalar** (the core generates no key material —
see [ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md)), per RFC 7748,
that **rejects the all-zero / non-contributory shared secret**. Crucially, the
**raw X25519 output is not a key**: it must be run through HKDF — exactly as the
`ss_combined` line above specifies — before use.

The **ML-KEM-768 post-quantum half** (`ss_kem` above) is now **implemented** in
[`libsigil/core/src/mlkem.rs`](../libsigil/core/src/mlkem.rs): deterministic
FIPS 203 **keygen / encapsulate / decapsulate** built on the RustCrypto `ml-kem`
crate, over **caller-supplied entropy** — key generation from the 64-byte
`d || z` seed and encapsulation from the 32-byte `m` coin (the core generates no
key material and no coins — see
[ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md)). Decapsulation is
**total**: on a malformed or wrong ciphertext it returns the FIPS 203 **implicit
rejection** shared secret (a deterministic pseudo-random value derived from the
private key, never an error), so decaps never leaks a distinguishable failure.

Both primitives are **real but NOT YET AUDITED**.

⚠️ **What "tested" means for the two post-quantum primitives — state this
accurately, because it is easy to overstate.** **No official FIPS 203 / FIPS 204 /
NIST ACVP known-answer vector is embedded in this repository** (see the closing
notes in [`../libsigil/core/src/mlkem.rs`](../libsigil/core/src/mlkem.rs) and
[`../libsigil/core/src/mldsa.rs`](../libsigil/core/src/mldsa.rs)): reproducing one
requires the exact byte tuples, and fabricating them would be worse than not having
them. What exists here is **round-trip, determinism, implicit-rejection and
negative testing**; the **upstream RustCrypto `ml-kem` / `ml-dsa` crates** are the
ones validated against the ACVP KATs. So correctness rests on those local tests
**plus** that upstream vetting — **not** on our own FIPS/ACVP vector verification,
and this is not a claim of NIST validation or certification, which has been neither
sought nor granted. (Contrast the classical primitives and the OTP primitive, which
**do** carry official RFC known-answer vectors: RFC 7748 for X25519, RFC 8032 for
Ed25519, RFC 4226/6238 for HOTP/TOTP.)

The **combined hybrid KEM
`ss_combined` is now IMPLEMENTED** in
[`libsigil/core/src/hybrid.rs`](../libsigil/core/src/hybrid.rs) as
`hybrid_encapsulate` / `hybrid_decapsulate`, the combiner that composes the two
halves above. Encapsulation runs the ephemeral X25519 exchange (`kx.rs`) and an
ML-KEM-768 encapsulation (`mlkem.rs`) — the **caller supplies the ephemeral X25519
secret and the ML-KEM coin** ([ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md);
the core still generates no entropy) — computes the transcript binding
`transcript_hash = SHA-256(ephemeral_x25519_pub || mlkem_ct)` over the ciphertext
material, and mixes `ss_x || ss_kem || transcript_hash` through `HKDF-SHA-256`
under the `"sigil-hybrid-v1"` label into one 32-byte `ss_combined`; decapsulation
recomputes the same transcript from the received ciphertexts and reproduces the
identical secret. It is **secure if EITHER component remains secure** — the
standard hybrid-combiner property, so breaking it requires breaking **both** X25519
and ML-KEM-768 — and the transcript binding stops an attacker splicing a
ciphertext from one exchange onto material from another. It is **real but
UNAUDITED**.

**It is no longer standalone.** Through `hybrid_seal` (below) this combiner now
carries **device-to-device vault-key wrapping** — the vault key of a shared vault
is encapsulated to a recipient device's hybrid public key
([ADR 0035](decisions/0035-device-to-device-vault-sharing.md)) — so a flaw in the
combiner is a flaw in a real user-facing path. Two things this does **not** change:
the envelope's `kem_ct` field is still *reserved* but unused (the ML-KEM ciphertext
travels alongside the envelope in the `SIGILhyb` container, not inside the
envelope frame), and the **SYSTEM is still not "post-quantum secure"** — the
combiner's property is that `ss_combined` stays secret if **either** half holds,
which is a statement about the construction, not about the product (see
[ADR 0011](decisions/0011-hybrid-kem-combiner.md)). The **hybrid signature**
(Ed25519 & ML-DSA-65) is assembled too — see the signature-implementation-status
note below — but **unlike the KEM it is still wired into nothing**.

**Signature implementation status (pre-audit, UNAUDITED).** **The combined hybrid
signature — and both halves it composes — now exist as standalone primitives in
`sigil-core`.** The **classical Ed25519 half** is implemented in
[`libsigil/core/src/sig.rs`](../libsigil/core/src/sig.rs): a deterministic RFC 8032
Ed25519 `sign`/`verify` over a **caller-supplied 32-byte secret seed** (the core
generates no key material — see
[ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md)). It is also
reachable over the **C-ABI** as `sigil_public_key_from_seed` / `sigil_sign` /
`sigil_verify` ([`libsigil/ffi/`](../libsigil/ffi/), `sigil.h`), and the demo
`cli` uses it in-crate to sign op-log requests (see [`api.md`](api.md) and
[ADR 0008](decisions/0008-device-key-request-auth.md)).

The **ML-DSA-65 post-quantum half** is now **implemented** in
[`libsigil/core/src/mldsa.rs`](../libsigil/core/src/mldsa.rs): deterministic
FIPS 204 **keygen / sign / verify** built on the RustCrypto `ml-dsa` crate, over a
**caller-supplied 32-byte keygen seed** (the FIPS 204 `xi`; the core generates no
key material — see
[ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md)). Signing is
**deterministic**: FIPS 204 permits a zero (all-zeros) randomizer, so `sign` is a
pure function of `(sk, message)` and needs no per-signature entropy — matching the
core's no-RNG discipline. Both halves are **real but NOT YET AUDITED**.

The **combined hybrid signature is now IMPLEMENTED** in
[`libsigil/core/src/hybrid_sig.rs`](../libsigil/core/src/hybrid_sig.rs) as
`hybrid_sign` / `hybrid_verify`, the combiner that composes the two halves above.
`hybrid_sign` produces `Ed25519.Sign(m) || ML-DSA-65.Sign(m)` — the 64-byte
Ed25519 signature (`sig.rs`) followed by the 3309-byte ML-DSA-65 signature
(`mldsa.rs`), a fixed **3373-byte** hybrid signature — over the **two
caller-supplied 32-byte seeds** (the Ed25519 signing seed and the ML-DSA-65 keygen
seed `xi`; [ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md), the core
generates no key material). Because both halves are deterministic (RFC 8032
Ed25519 and zero-randomizer FIPS 204 ML-DSA-65), the **hybrid signature is
deterministic** — a pure function of `(seeds, message)`, matching the core's no-RNG
discipline. `hybrid_verify` splits the 3373-byte signature and requires **BOTH**
the Ed25519 and the ML-DSA-65 half to validate over the message; if either fails,
verification fails. The honest property, asserted as design intent of an
**UNAUDITED** primitive: **a forgery requires breaking BOTH Ed25519 AND
ML-DSA-65** — the concatenate-and-require-both hybrid pattern — which is **not** a
claim that the SYSTEM is "post-quantum secure". It is **real but UNAUDITED and
STILL STANDALONE**: it is **not wired into a record / vault / account / session /
sharing flow**. Every signature `sigild` verifies — the op-log request contract
(v2 and v3), device enrollment proofs, and **every device-to-device sharing
route** — is **classical Ed25519 only**. So the two hybrid constructions are now in
**different states**, and the distinction matters: the hybrid **KEM** is
load-bearing (it wraps vault keys, via `hybrid_seal` — see above and
[ADR 0035](decisions/0035-device-to-device-vault-sharing.md)), while the hybrid
**signature** is not used anywhere. The remaining hybrid-crypto work is therefore
**authentication**: wiring `hybrid_sign` / `hybrid_verify` into the request/identity
model, and wiring either construction into the suite frame. The **SYSTEM is still
not "post-quantum secure"**. See
[ADR 0012](decisions/0012-hybrid-signature-combiner.md).

## Hybrid public-key encryption — ANONYMOUS (`hybrid_seal` / `hybrid_open`)

> ⚠️ **NAMING CORRECTION (Phase 60).** This section was titled *"hybrid public-key
> **authenticated** encryption"*, and used that phrase throughout. **The word was
> wrong and it mattered.** `hybrid_seal` is HPKE `mode_base` — it has **no sender
> key at all** — so "authenticated" was describing only the AEAD's ciphertext
> integrity, while it *read* as sender authentication. A reviewer scoping this
> flow would have concluded a property existed that did not.
>
> The construction below is **ANONYMOUS**, and that is the correct shape for what
> it is now used for: encrypting a **file** to a public key (`sigil hybrid-seal` /
> `hybrid-open`), where "anyone may send to you" is the intended semantics.
>
> ⛔ It is **no longer used for vault-key wrapping**. Using an anonymous primitive
> to deliver a **key** was a vulnerability — the recipient could not tell a key
> its peer chose from a key an attacker chose. That path now uses the
> **authenticated** construction in the next section
> ([ADR 0048](decisions/0048-authenticated-vault-key-envelopes.md)).

**Status (pre-audit, UNAUDITED).** `sigil-core` composes the hybrid **KEM**
with the symmetric AEAD into anonymous hybrid public-key encryption —
`hybrid_seal` / `hybrid_open` in
[`libsigil/core/src/hybrid_seal.rs`](../libsigil/core/src/hybrid_seal.rs). This is
the **first time a hybrid primitive is wired into an encryption flow**: until now
the hybrid KEM (`hybrid.rs`) and the AEAD (`aead.rs`) were separate building
blocks, and the only end-to-end path was the *symmetric*, password-derived one
(Argon2id → AEAD → envelope; `seal_record` / `open_record`). `hybrid_seal` instead
encrypts a record **to a recipient's hybrid public key** (an X25519 public key +
an ML-KEM-768 encapsulation key).

It is a **KEM-then-AEAD** construction:

```text
hybrid_seal(recipient_x25519_pub, recipient_mlkem_encaps_key,
            ephemeral_x25519_secret, mlkem_coin, nonce, aad, plaintext):
  (eph_x25519_pub, mlkem_ct, ss_combined) = hybrid_encapsulate(   # hybrid.rs
      recipient_x25519_pub, recipient_mlkem_encaps_key,
      ephemeral_x25519_secret, mlkem_coin)
  envelope = seal(master_key = ss_combined, nonce, aad, plaintext)  # aead.rs
  return (eph_x25519_pub, mlkem_ct, envelope)

hybrid_open(recipient_x25519_secret, recipient_mlkem_decaps_key,
            eph_x25519_pub, mlkem_ct, envelope):
  ss_combined = hybrid_decapsulate(                               # hybrid.rs
      recipient_x25519_secret, recipient_mlkem_decaps_key,
      eph_x25519_pub, mlkem_ct)
  return open(master_key = ss_combined, envelope)                  # aead.rs
```

The 32-byte hybrid shared secret `ss_combined` is used as the AEAD **master key**
(the AEAD then binds the suite byte into its per-record HKDF `info` as usual — see
the AEAD design above); it is never used as an AEAD key directly. The recipient
decapsulates with its hybrid secret keys to reproduce the identical `ss_combined`
and then authenticates/decrypts the envelope; a tampered ML-KEM ciphertext,
ephemeral public key, or envelope yields a different key or an authentication
failure, never plaintext.

Honest framing:

- This is a **CUSTOM KEM-then-AEAD composition — NOT RFC 9180 HPKE.** It reuses the
  crate's existing hybrid combiner and HKDF-bound AEAD rather than the HPKE key
  schedule, so it carries no HPKE interoperability or standardized analysis.
- The **caller supplies** the ephemeral X25519 secret, the ML-KEM coin, and the
  AEAD nonce ([ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md)); the
  core generates no randomness and stays `wasm32-unknown-unknown`-pure.
- It inherits the hybrid property of the KEM
  ([ADR 0011](decisions/0011-hybrid-kem-combiner.md)): `ss_combined` stays secret if
  **either** X25519 or ML-KEM-768 remains secure, and the transcript binding stops
  mix-and-match — asserted as design intent of an **UNAUDITED** primitive, **not** a
  claim that the SYSTEM is "post-quantum secure".
- ⛔ **It is ANONYMOUS, and that is the property to understand before using it.**
  The sender's only key is a per-message ephemeral, so **anyone holding the
  recipient's public key can produce a container the recipient will open**. For
  file-to-a-public-key encryption that is the intended semantics. For delivering a
  **key** it is a vulnerability, and it was one here until Phase 60 — see
  [ADR 0048](decisions/0048-authenticated-vault-key-envelopes.md).
- It is **real but UNAUDITED**. ⚠️ It **no longer carries device-to-device
  vault-key wrapping** — that moved to the authenticated construction in the next
  section — so this primitive is once again used only by `sigil hybrid-seal` /
  `hybrid-open` (a file-encryption demo). The hybrid KEM as such **remains
  load-bearing and in scope for the audit**, because the authenticated
  construction is built from the same halves. It is still **not** the product's
  *account* model. The envelope's `kem_ct` field still stays
  *reserved* but unused — the ML-KEM ciphertext travels alongside the envelope here,
  not inside it. See [ADR 0013](decisions/0013-hybrid-public-key-seal.md).
- These hybrid primitives are also reachable over the **C-ABI** —
  `sigil_x25519_public_key`, `sigil_ml_kem768_keygen`, and `sigil_hybrid_*`
  (`encapsulate` / `decapsulate` / `seal` / `open`) in
  [`libsigil/ffi/`](../libsigil/ffi/) (`sigil.h`) — so native clients can generate a
  hybrid identity and encrypt to a recipient's hybrid public key. Still the same
  custom KEM-then-AEAD and still **UNAUDITED**; the **C-ABI itself** has no
  product consumer (the sharing flow reaches `hybrid_seal` through the Rust CLI
  crate, not through the FFI).

## Hybrid public-key AUTHENTICATED encryption (`hybrid_auth_seal` / `hybrid_auth_open`)

**Status (pre-audit, UNAUDITED). This is what wraps a vault key.**
[`libsigil/core/src/hybrid_auth.rs`](../libsigil/core/src/hybrid_auth.rs),
[ADR 0048](decisions/0048-authenticated-vault-key-envelopes.md).

It composes the **same** primitives as the anonymous form above — X25519,
ML-KEM-768, HKDF-SHA256, the AEAD and the envelope codec — and adds **no new
low-level cryptography, no dependency, no randomness and no clock**. The shape is
HPKE's `mode_auth`: the sender **also** holds a long-term ("static") X25519 key
pair, and a third Diffie–Hellman between the sender's static secret and the
recipient's static public key is mixed into the KDF.

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

  envelope = seal(master_key = ss, nonce, aad, plaintext)
```

An attacker who knows only **public** keys cannot compute `ss_s`, so it cannot
produce a ciphertext this construction will open. Every transcript field is
length-prefixed, so no two distinct field sets serialise to the same bytes, and
the transcript binds **both identities** — a capture cannot be re-attributed to a
different sender or re-aimed at a different recipient without changing the key.

⭐ **The sender's static public key is an INPUT to decapsulation, not something
read out of the ciphertext**, and is deliberately **not carried in the
container**. It comes from the pin store, out of band. Passing the wrong sender
yields a different key and therefore an AEAD failure — the recipient learns *"this
did not come from who I expected"* with **no string comparison being trusted**.
Reading the sender's identity from attacker-controlled bytes and then "verifying"
against it is exactly the mistake this design avoids.

The HKDF `info` (`"sigil-hybrid-auth-v1"`) domain-separates this from the
anonymous combiner (`"sigil-hybrid-v1"`), so the same material can never yield the
same key through both.

### The context-bound AAD

Authentication says *who* made a ciphertext. It does not say *what it was for*.
Every hybrid container used to be sealed under one fixed tag
(`"sigil-hybrid-cli/1"`), binding it to **no vault, no recipient, no sender and no
purpose** — which is why a *file* container was a structurally valid *vault-key*
envelope. A vault-key wrap now uses:

```text
  "sigil-vault-key-wrap-v1\n"
  ‖ u32_be(len(vault_id))            ‖ vault_id
  ‖ u32_be(len(recipient_device_id)) ‖ recipient_device_id
  ‖ u32_be(len(sender_device_id))    ‖ sender_device_id
```

so a **file** envelope can never be presented as a **vault-key** envelope, an
envelope for vault A cannot be moved to vault B, one addressed to device X cannot
be re-filed under device Y, and one from sender S cannot be re-attributed to
sender T. The AAD travels in the clear inside the envelope, authenticated by the
AEAD tag, and is additionally compared **before** the AEAD is entered.

⭐ **SINGLE-SOURCED, not mirrored.** The layout lives once, in
`sigil_core::vault_key_wrap_aad`; the CLI, the desktop and JavaScript all reach it
(JS through the wasm). **Golden vector** for
`vault_key_wrap_aad("demo", "dev_bob", "dev_alice")` — 56 bytes:

```
736967696c2d7661756c742d6b65792d777261702d76310a
0000000464656d6f 000000076465765f626f62 000000096465765f616c696365
```

The combined-secret KAT over fixed seeds is
`7d5cda4ae644faeb3fe30d492886bcd7961ed08c196b990c34bc9760be8c42b0`.

### ⚠️ What each half buys — the asymmetry, stated plainly

| component | buys |
|---|---|
| `ss_e` (ephemeral-static X25519) | forward secrecy against later compromise of the **sender's** static secret |
| `ss_kem` (ML-KEM-768) | the post-quantum half of **confidentiality** |
| `ss_s` (static-static X25519) | **the authentication — classical only** |

⛔ **The post-quantum half is NOT authenticated.** ML-KEM has no static-static
analogue. So: breaking **confidentiality** is designed to require breaking **both**
X25519 and ML-KEM-768; forging **authenticity** requires breaking **X25519 alone**.
A quantum adversary could forge an envelope it still could not read. **This does
not make the SYSTEM "post-quantum secure", and it does not claim post-quantum
authentication.**

⚠️ The authentication is **implicit and key-confirmed, not a signature, and NOT
TRANSFERABLE**: it proves the ciphertext was made by *someone holding the sender's
static X25519 secret*, and the recipient **cannot prove that to a third party**,
because the recipient could have made it too. For *"did MY peer choose this vault
key?"* that is exactly right, and deliberately weaker than non-repudiation — but
**no audit or dispute process can rest on an envelope**.

Also unchanged from the anonymous form: it is a **CUSTOM composition — NOT RFC
9180 HPKE**, sharing none of its test vectors; the caller supplies the ephemeral
secret, the ML-KEM coin and the nonce ([ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md));
a non-contributory recipient public key is rejected for **both** DH halves; and
there is **no zeroization** of component secrets beyond what the dependencies do.

## Key hierarchy and vault sharing (`hybrid_auth_seal` / `hybrid_auth_open` in use)

**Status (pre-audit, UNAUDITED, dev-gated).** This is where the hybrid public-key
seal above stops being a demo. Device-to-device **vault sharing**
([ADR 0035](decisions/0035-device-to-device-vault-sharing.md)) uses it to
distribute a vault's encryption key to another enrolled device, so a second device
can open the same vault **without ever learning the owner's password**.

### The three layers

```
human password ──Argon2id(m,t,p; per-vault salt)──▶ seals a PERSONAL vault
                  (the SIGILcli container)
                  NEVER shared. NEVER wrapped. NEVER sent anywhere.

vault key = 32 bytes from the OS CSPRNG
                 ──▶ seals a SHARED vault, through the SAME SIGILcli container
                     (the container takes arbitrary password BYTES, so a random
                      key drops in with NO format change)
     │
     └── per recipient device:
         hybrid_auth_seal( sender_static_x25519_secret,          <- THE SENDER'S IDENTITY
                           recipient_x25519_pub, recipient_mlkem_encaps_key,
                           eph_x25519_secret, mlkem_coin, nonce,
                           aad = vault_key_wrap_aad(vault_id,
                                                    recipient_device_id,
                                                    sender_device_id),
                           plaintext = the 32-byte vault key )
                 ──▶ (eph_x25519_pub, mlkem_ct, envelope)
                     packaged as a SIGILhyb container, VERSION 2  ("the envelope")
```

The recipient reverses it with `hybrid_auth_open` under its hybrid **secret**
identity (an X25519 secret scalar + an ML-KEM-768 keygen seed) **and the sender's
static X25519 public key**, recovering exactly 32 bytes; anything other than 32
bytes is rejected rather than used as a key.

⛔ **A version-1 (anonymous) container is REFUSED wherever a vault key is
expected**, before any cryptography runs. There is no flag, option or default
anywhere that accepts one — a v1 container proves nothing about who made it, so
accepting it would *be* the vulnerability
([ADR 0048](decisions/0048-authenticated-vault-key-envelopes.md)). ⚠️ Consequently
**every envelope deposited before Phase 60 must be re-issued**, including those
covering a recovery kit; there is no migration and there cannot be one.

⚠️ **The envelope is NOT a fixed size.** It carries its context AAD, so its length
depends on the identifiers:

```
  bytes = 1244 + len(vault_id) + len(recipient_device_id) + len(sender_device_id)
        = 1129 (magic + version + eph_x25519_pub + mlkem_ct)
        +   79 (nonce + framing + the sealed 32-byte key)
        +   36 + those three lengths   (the AAD)
```

Measured **1310 bytes** for a 14-character vault id and two 26-character
server-assigned device ids (`dev_` + 22 base64url chars). The **anonymous v1
file** container is still a flat **1226** bytes, and conflating the two is how a
forged file container came to be byte-shaped like a genuine wrap — do not
"correct" one to the other.

- **The human password is never shared and never wrapped.** Sharing it would hand a
  recipient every *other* vault sealed under it and would make revocation mean
  "change your password everywhere". A per-vault random key is rotatable in
  principle (re-key + re-share) and reveals nothing about the user.
- **Fresh ephemeral entropy per wrap.** The ephemeral X25519 secret, the ML-KEM coin
  and the AEAD nonce are drawn from a CSPRNG on **every** call, so two shares
  of the same key never reuse randomness. Consistent with
  [ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md), all of it is
  supplied by the caller — the OS CSPRNG in the CLI, `crypto.getRandomValues` in the
  browser clients; `sigil-core` still generates nothing.
- **Keys are never printed.** A vault key is shown only as
  `vault_key_fingerprint` — the first 16 hex characters of its SHA-256 — so two
  devices can confirm they hold the same key without revealing it.

### The same hierarchy, exercised from the browser

This hierarchy is **not CLI-specific**. The webapp and the MV3 extension run the
identical construction through [`../sigil-wasm/sharing.mjs`](../sigil-wasm/sharing.mjs)
(`generateVaultKey` → `wrapVaultKey` / `shareVault` → `acceptVault` /
`unwrapVaultKey`, with `vaultKeyFingerprint` computing the same 16-hex SHA-256 prefix
via `crypto.subtle`). **The wrap and unwrap still happen inside the wasm** —
`hybrid_auth_seal_to_container` / `hybrid_auth_open_container`, i.e. `sigil-core`'s
`hybrid_auth_seal` / `hybrid_auth_open` — so there is no second implementation of the
construction and no JS-side cryptography; the JS supplies entropy and moves bytes. The
recovered-plaintext length check (exactly 32 bytes, else reject) is mirrored in
`unwrapVaultKey`, which additionally requires a `VerifiedSender` instance and
rejects a version-1 container with `UnauthenticatedEnvelopeError`. A shared vault sealed by a browser is byte-compatible with one sealed
by the CLI, and vice versa: `sharing-interop.mjs` shares a vault **both ways** between
the JS client and the real `sigil` binary and both ends reach the same fingerprint and
the same RFC 6238 code. Where the CLI keeps the hybrid secret and the keyring in `0600`
files, the browser clients keep them inside their **sealed device-identity container**
([ADR 0036](decisions/0036-browser-sharing-secret-storage.md)) — sealed with the same
Argon2id → XChaCha20-Poly1305 `SIGILcli` construction as a vault.

The **native desktop app** runs the identical construction through a third route: it
calls the `sigil-cli` library's `wrap_vault_key` / `unwrap_vault_key` directly
([ADR 0037](decisions/0037-desktop-reuses-cli-library-for-protocol.md)), so there is no
third implementation of it either, and it stores the hybrid secret and the keyring in
**the same `0600` files as the CLI** — weaker at rest than the browsers' sealed
container.

### What the server sees, and what it cannot do

`sigild` **relays** the envelope: `PUT`/`GET /v1/vaults/{vaultID}/keys/{deviceID}`
store and return the bytes **verbatim** (see [`api.md`](api.md)). Concretely the
server holds:

| The server has | The server does **not** have |
|----------------|------------------------------|
| device hybrid **public** keys (32-byte X25519 + 1184-byte ML-KEM-768 encaps key) | any hybrid **secret** identity — decapsulation keys never leave a device |
| the opaque envelope (`SIGILhyb` ciphertext) | the vault key inside it, or any plaintext |
| device IDs, a vault ID, a size, a timestamp | the user's password, or anything derived from it |
| a SHA-256 **fingerprint** of the envelope in the audit log | the envelope's contents in any log or metric |

So the server **cannot decapsulate** (no secret key) and **cannot decrypt** the
vault that key protects.

> ### ⚠️ CORRECTION — this paragraph claimed a defense that did not exist (Phase 60)
>
> Until Phase 60 the sentence above continued: *"and **cannot mint** a valid
> envelope for a device without that device's public key producing ciphertext only
> that device can open."*
>
> **That was false, and self-evidently so: the table immediately above lists device
> hybrid PUBLIC keys among the things the server HAS.** The sentence treated
> possession of the recipient's public key as the barrier; it was the entire
> *requirement*. The wrap used the **anonymous** `hybrid_seal` (HPKE `mode_base`),
> so **anyone** holding a published hybrid public key — the server, or any
> authenticated device it serves that key to — could mint a container the
> recipient would open, and install a vault key of their own choosing. It was
> reproduced with the shipped binary alone.
>
> ⛔ **Nor did pinning help:** `vault accept` fetched no hybrid key, so the pin
> store was never consulted on the unwrap path.
>
> **What is true now** ([ADR 0048](decisions/0048-authenticated-vault-key-envelopes.md),
> and see the next section for the construction): minting a vault-key envelope
> requires the **sender's static X25519 secret**, not merely the recipient's
> published public key. So the server **cannot mint one that any client will
> accept as coming from a device the client has pinned** — but ⚠️ **on FIRST sight
> of a sender it still can**, by serving its own key as the sender's and forging
> under it. That is adversary **X**'s accepted trust-on-first-use limit, now
> symmetric across wrap and unwrap, and only a human comparing a safety number
> closes it.

Its **only** inspection of key material is a **length check** (32 / 1184 bytes) — it does not
decode a curve point, screen for low-order elements, or verify that the two halves
of a hybrid public key belong together. That is deliberate: validating key material
would be the server performing cryptography on it. Correctness of a published key
is the **client's** business.

### Safety numbers — the out-of-band verification of a hybrid public key

**Status (pre-audit, UNAUDITED).** A wrap is only as trustworthy as the public key
it wraps to. The **safety number** is the human-comparable fingerprint of one
device's hybrid public identity: two people read it to each other over a channel
the server does not control, and matching digits mean the key one is about to wrap
a vault key to really belongs to the other
([ADR 0038](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)).

⭐ **MIRRORED — NOT SHARED.** The construction exists in exactly **two**
implementations: `cli/src/lib.rs` (`hybrid_safety_digest` / `render_safety_number`
/ `hybrid_safety_number` / `pairwise_safety_number`), used by the `sigil` CLI *and*
the native desktop app, and `sigil-wasm/sharing.mjs` (`hybridSafetyDigest` /
`renderSafetyNumber` / `safetyNumber` / `pairwiseSafetyNumber`), used by the webapp
and the MV3 extension. **They MUST stay byte-identical.** If they ever diverge, two
people comparing digits across clients would see different numbers and wrongly
conclude they were under attack. Both sides carry the **same known-answer test**,
and `sigil-wasm/test/pinning-interop.mjs` drives the **real `sigil` binary** against
the JS module and compares the printed digits.

**The per-device digest.** SHA-256 over a length-prefixed transcript:

```
digest = SHA-256( "sigil-safety-number-v1\n"
                ‖ u32_be(len(device_id)) ‖ device_id
                ‖ u32_be(32)             ‖ x25519_public_key
                ‖ u32_be(1184)           ‖ mlkem_encaps_key )
```

- The prefix is **domain separation**; changing it changes every safety number in
  existence and would be a version bump, not a fix.
- Every field is **length-prefixed with a big-endian `u32`** before its bytes, so no
  two different inputs can produce the same byte stream (`"ab"+"c"` cannot collide
  with `"a"+"bc"`). The two key lengths are fixed by the algorithms — X25519 public
  key **32** bytes, ML-KEM-768 encapsulation key **1184** bytes — and are still
  length-prefixed rather than assumed.
- ⭐ **BOTH halves of the hybrid key are covered**, so a substitution that swapped
  only the ML-KEM half would still change the number.
- ⭐ **The device id is bound in**, so a *genuine* key relayed under a **different**
  device's id does not verify. Verifying "this key" is meaningless without "…for
  this device".
- Input is the **decoded raw key bytes**, never the base64 text, so a server that
  re-encodes the same key cannot change the number.

**Rendering.** The digest becomes **6 groups of 5 decimal digits** — 30 digits:

```
group[g] = ( u40_be( digest[5g .. 5g+5] ) ) mod 100000,  zero-padded to 5 digits
rendered = group[0] ‖ " " ‖ … ‖ " " ‖ group[5]      e.g. "83791 28129 67801 50284 55242 77845"
```

Each group consumes **5 digest bytes read big-endian** (max `2^40`, exactly
representable in a JS double, which is why the JS mirror can use plain arithmetic),
reduced `mod 100000`. Only the first **30** of the 32 digest bytes are consumed.
30 decimal digits is ≈ **99.6 bits** — short enough to read aloud, long enough that
searching for a second key with the same number is not a practical attack. It is
**not** the full 256-bit digest, and it is a **fingerprint for human comparison**,
not a cryptographic identifier to be used programmatically.

**The pairwise number, and why it is order-independent.** Reading two separate
numbers to each other invites the classic mistake of comparing the wrong pair, so
there is a single string both sides see:

```
d_a = digest(device_a, identity_a)
d_b = digest(device_b, identity_b)
(lo, hi) = (d_a, d_b) sorted BYTEWISE ASCENDING          ← this is the whole trick
pair = render( SHA-256( "sigil-safety-number-pair-v1\n" ‖ lo ‖ hi ) )
```

Sorting the two 32-byte digests into a **canonical order** before hashing makes the
input — and therefore the output — identical whichever side computes it:
`pair(a, b) == pair(b, a)` byte for byte. A **separate domain prefix** keeps a
pairwise number from ever colliding with a per-device one. Both sides run the same
comparison loop over the digest bytes, so the ordering rule is itself mirrored.

**No secret is involved.** A safety number is derived entirely from **public** key
material and a public device id. Computing or displaying one reveals nothing, sends
nothing, and needs no network for one's *own* number.

### Key pinning — where the number is enforced without a human

A safety number only helps if someone reads it. **Pinning** is the zero-effort half
that works from the **second** contact onward: the first hybrid public key a client
sees for a device is recorded, and every later fetch is compared against it.

The enforcement lives at **the fetch itself** — `verify_recipient_for_wrap` (Rust) /
`verifyRecipientForWrap` (JS) get the key and check the pin (and the safety number,
and the recovery-kit rule) in **one call**, and every wrap path (share, rotate *and*
recovery-kit cover, in both implementations) goes through it. In Rust it is the
**only** constructor of a `VerifiedRecipient`, and the wrap path accepts nothing
else, so the rule is enforced by type rather than by discipline. The bare
`fetch_hybrid_key` / `fetchHybridKey` survive only on paths that **do not wrap**:
displaying a safety number, the deliberate re-pin, and the desktop's `check_server`.

> ⚠️ **The names to *not* reach for: `fetch_hybrid_key_pinned` /
> `fetchHybridKeyPinned`.** They were this construction's original choke point,
> superseded in Phase 54 and **deleted in Phase 57** because they pin but do not
> refuse an unverified recovery kit and do not honour a supplied safety number —
> a fetch-and-pin left exported next to a stricter gate is a ready-made bypass for
> the next caller. Both are gone, with tombstone comments at their old locations.
> See [ADR 0038](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)'s
> addenda.

Three outcomes, and there is deliberately **no fourth**:

| Presented key | Outcome | State change |
|---------------|---------|--------------|
| device not seen before | **`FirstSight`** / `"first-sight"` — proceeds, **with a warning** | the key is pinned |
| byte-identical to the pin | **`Match`** / `"match"` — proceeds silently | none |
| **different** | ⛔ **hard refusal**: `CliError::PinMismatch` / `KeyPinMismatchError` / `DesktopError::KeyPinMismatch` | **none** — nothing wrapped, nothing uploaded, the pin store **not** mutated |

Comparison is over the **decoded raw key bytes** of both halves. There is **no flag,
option or default anywhere** that makes a wrap accept a changed key. The only way a
pin is ever replaced is the explicit `repin_hybrid_key` / `repinHybridKey`, which
nothing calls automatically, which requires `--yes` at the CLI, which refuses if the
safety number the user claims to have verified does not match what the server is
serving right now, and which **counts** re-pins so the evidence survives.

Where the pin store lives is a **client storage** decision, in
[`architecture.md`](architecture.md) — a `0600` `hybrid-pins.json` natively, a field
inside the sealed device-identity container in the browsers. Either way it holds only
**public** key material, and either way it is **security-critical local state**: an
attacker who can rewrite it can silence the alarm before it fires.

### The UNWRAP gate — the same rule, on the receiving side (Phase 60)

⚠️ **Everything above describes the WRAP side, and until Phase 60 that was the
only side that had it.** `vault accept` fetched an envelope and opened it: it
fetched **no hybrid key at all**, so the pin store was not merely bypassed on the
unwrap path — it was **never consulted**. That is why pinning did not mitigate the
envelope forgery ([ADR 0048](decisions/0048-authenticated-vault-key-envelopes.md)).

The rule is now symmetric, and enforced the same way — by type.
`unwrap_vault_key` takes a **`VerifiedSender`** (Rust: private fields, no public
struct literal; JS: an `instanceof` check), constructible in exactly two ways:

| constructor | what it establishes |
|---|---|
| `verify_sender_for_unwrap` / `verifySenderForUnwrap` | fetches the **depositing** device's hybrid public key and pin-checks it, honouring a supplied safety number — the **same trust table** as the wrap side |
| `VerifiedSender::from_local` / `verifiedSenderFromLocal` | this process holds the sender's **secret** half, so nothing was fetched and there is nothing to substitute. Not a bypass: whoever can build it already **is** the sender |

Trust outcomes match the wrap side: `Derived` (locally derived, no fetch) ·
`Pinned` (identical) · **different ⇒ `PinMismatch`, a hard stop with the pin store
unmutated** · first sight with a matching safety number ⇒ `VerifiedFirstSight` ·
first sight with a **wrong** one ⇒ `SafetyNumberMismatch` · first sight with none
⇒ `UnverifiedFirstSight` (proceeds, **warns**). As on the wrap side, **every
refusal happens before the key is pinned**, so a retry cannot silence its own
alarm by pinning what was just refused.

Two further controls sit behind the gate, and they are **each other's only
backstop**:

- ⭐ **OPEN BEFORE WRITING** — the recovered key must actually open the vault's
  newest op before it reaches the keyring. A key that opens nothing never becomes
  local state. (A vault with no ops is the one exception, reported explicitly
  rather than silently.)
- **NEVER SILENTLY REPLACE** — displacing a *different* held key requires an
  explicit `--replace` / `replace: true`, and the refusal names both fingerprints
  and never a key byte.

Both live where the key is **produced**, not at the call sites, so a client cannot
obtain a key that opens nothing or one that silently displaces a held key.

### Vault key rotation — the key lifecycle

Revocation stops future *server access*; it cannot make a device forget a key. The
remediation is to **retire the key itself**. `rotate_vault_key` (Rust) /
`rotateVaultKey` (JS) perform, in this order:

1. **Load the current vault key** from the local keyring. A vault with no key there
   is not rotatable — only a **shared** vault (one already sealed under a random vault
   key) can be rotated; a password vault must go through `vault rekey` first.
2. ⭐ **Pin-check EVERY recipient first.** All recipients' hybrid public keys are
   fetched through the pinned fetch **before anything is mutated**, so a single
   mismatch aborts the whole rotation with the vault file, the keyring and the server
   untouched — far better than a half-rotated vault whose new key has already been
   wrapped to an attacker.
3. **Draw a fresh 32-byte vault key** from the CSPRNG (`generate_vault_key` /
   `generateVaultKey`) — a new key, never a derivation of the old one.
4. **Re-seal the container**: `reseal_container` opens with the **old** key and seals
   with the **new** one. It is **container-agnostic and never inspects the
   plaintext**, so it re-keys a TOTP vault or any other `SIGILcli` container
   identically. The container format does **not** change; only the key does.
5. **Write the vault** `0600` via **temp file + rename**, so a crash cannot leave a
   half-written vault.
6. **Record the new key in the keyring — AFTER the file is in place.** Ordering is
   deliberate: a crash between the two would otherwise leave the keyring naming a key
   that opens nothing.
7. **Wrap and upsert an envelope per recipient**, with fresh ephemeral entropy per
   wrap exactly as for a first share.
8. **List, then delete every envelope not in the recipient set**, so a device left out
   cannot collect the new key. A `404` on delete counts as success — the desired end
   state already holds.

In the browser the same sequence runs, except that steps 5–6 do not exist as file
writes: `rotateVaultKey` **returns** the new key and the re-sealed container and the
caller persists them (into the sealed containers) and pushes.

⚠️ **What rotation guarantees, stated precisely.** Everything sealed **after** the
rotation is unreadable to a device left out of the recipient set. **Nothing else.** A
device that already unwrapped the previous key still holds that key and everything it
had already read or copied — cryptography cannot un-send a secret. Deleting its
envelope stops it collecting anything **new**; it does not reach into that device.

A rotation is reported as **fingerprints only** (`old_key_fingerprint` /
`new_key_fingerprint`, the same 16-hex SHA-256 prefix used everywhere else). No vault
key is ever printed, logged, or returned across a UI boundary.

### Honest limits (read these with the section above)

- **UNAUDITED**, dev-gated (`501` by default), plain HTTP on localhost. Do not
  store real 2FA secrets. The Phase 50 pinning, safety-number and rotation code is
  **new and unaudited** like everything around it.
- **Custom KEM-then-AEAD, NOT RFC 9180 HPKE** — no HPKE interoperability, no
  standardized analysis.
- **The system is NOT "post-quantum secure."** The wrap is designed to stay secret
  if **either** X25519 or ML-KEM-768 holds; that is a property of the construction.
- **The safety number does not verify itself.** Pinning blocks a key that *changes*;
  only a human comparing digits over a trusted channel can catch a key that was wrong
  the **first** time. Nothing forces that comparison, nothing detects that it was
  skipped, and a user who re-pins without checking hands over exactly what the
  refusal prevented. There is still **no key-transparency log and no
  cross-signature** binding a hybrid public key to the device's enrolled Ed25519
  identity — that would remove the human from the loop and remains the highest-value
  follow-up.
- **Rotation protects future content only, and is manual.** Revocation stops future
  server access; a device that already unwrapped a key keeps it. Nothing re-keys
  automatically on revoke, there is **no rotation schedule**, and there is **no
  forward secrecy** for a vault key already delivered. Republishing a hybrid key
  does not re-wrap already-deposited envelopes.
- **Authentication of the sharing routes is classical Ed25519 only** (contract v3).
  The wrap is hybrid; the request signature is not.
- **No zeroization of key material in the clients.** Rust `Vec`s and JS
  `Uint8Array`s holding a vault key or a hybrid secret are dropped, not wiped; in the
  browser they stay live in the JS heap for as long as the vault is unlocked.
- **The Argon2id pass over an already-uniform 32-byte vault key is redundant work**,
  kept deliberately so the shared vault is byte-identical in shape to a personal
  one and no client's container parser changes. Replacing it with a direct KDF is a
  future, format-breaking change.

## Container KDF parameters — a ceiling, and a no-downgrade ratchet

**Status (pre-audit, UNAUDITED).** A `SIGILcli` container
([ADR 0020](decisions/0020-shared-client-container-format.md)) is
**self-describing**: its header carries the Argon2id work factors it was sealed
with, as three raw `u32`s.

```
"SIGILcli" | version(u8) | m_cost(u32 LE) | t_cost(u32 LE) | p_cost(u32 LE) | salt_len(u8) | salt | envelope
                          └──────────────── UNAUTHENTICATED framing ────────────┘
```

⛔ **Those three fields cannot be authenticated.** They are *inputs* to the KDF,
so they must be readable before the AEAD key exists — which means they are
whatever the writer of the bytes chose.
[ADR 0047](decisions/0047-container-parameter-ceiling-and-no-downgrade-ratchet.md)
adds the two rules that make that safe to read.

### The ceiling: refuse before allocating

```
Argon2Params::MAX_M_COST = 262_144   KiB  = 256 MiB      (inclusive)
Argon2Params::MAX_T_COST = 16        passes              (inclusive)
Argon2Params::MAX_P_COST = 16        lanes               (inclusive)
```

Argon2id allocates `m_cost` KiB **in one block before it does any work**, so an
unbounded `m_cost` parsed out of a container header is a **remote denial of
service**. Measured on the dev machine (macOS arm64, 24 GB RAM, `argon2` 0.5.3 —
the crate [`../libsigil/core/src/kdf.rs`](../libsigil/core/src/kdf.rs) links):
`m_cost = 0xFFFF_FFF0` (≈ 4 TiB) ran **12.57 s**, peaked at a **≈ 90 GB memory
footprint** and was **killed**; `t_cost = 0xFFFF_FFF0` allocates nothing and
extrapolates to **≈ 282 days** for one open attempt. After the ceiling, the same
container is refused by the real `sigil` binary in **0.00 s** with a **1.18 MB**
peak footprint.

⭐ **The refusal has to be client-side, and that is a direct consequence of the
architecture.** Containers reach clients through `sigild`'s **zero-knowledge**
op-log, which stores opaque blobs and **cannot inspect or filter what it relays**.
The property that makes the server safe is the property that stops it helping
here.

`Argon2Params::validate()` returns `KdfError::ParamsTooLarge` — deliberately
**distinct from `InvalidParams`**, because the values may be perfectly legal
Argon2 parameters and are refused for what honouring them would cost. It is called
by `derive_master_key` first thing, and **earlier still** by both container parsers
(`sigil_cli::open_container`, the wasm binding's `open_container_inner`) so the
error can say *"this container is hostile"* rather than *"the KDF failed"* — a
distinction a user needs in order to tell it from a typo'd password.

⭐ **A ceiling only. There is no floor.** A low work factor is a *weak* container,
not a *dangerous* one, and refusing to open it would destroy data rather than
protect it.

### The ratchet: a re-seal may raise the work factor and may never lower it

```
no_downgrade(existing, requested) = componentwise max, then m_cost := max(m_cost, 8 * p_cost)
```

A re-seal is the operation that **chooses** new parameters, so it is the one place
a weak container could make its weakness permanent. Taking the maximum makes each
factor a ratchet — up, never down — and a client with stronger defaults silently
*repairs* a weak container the first time it re-seals it. The `m_cost` floor is
Argon2's own requirement (`m_cost >= 8 * p_cost`), which a componentwise max can
otherwise violate.

⭐ **One implementation, reached and never copied.** The rule is
`Argon2Params::no_downgrade` in `sigil-core`; `sigil_cli::no_downgrade` delegates
to it, `sigil_cli::reseal_container` applies it (so `params` there is a **floor**,
not an instruction), and JavaScript reaches the same function through two wasm
exports — `container_params` (read a header with no password, no KDF and no
allocation) and `reseal_params` — wrapped as `containerParams` / `ratchetParams` in
[`../sigil-wasm/totp-vault.mjs`](../sigil-wasm/totp-vault.mjs). ⚠️ **A mirrored
copy would be the wrong answer here specifically, because a drift downward is
invisible**: it yields a container that still opens everywhere, just weaker.

### What this does and does not give you

- ⛔ **The ceiling removes nothing.** A hostile container stays in the op-log; the
  server cannot know it is there. Every client that pulls parses and refuses it
  **again, every time**. What changed is the cost of that refusal.
- ⚠️ **The ratchet makes a bounded cost persistent.** A container accepted at
  exactly `256 MiB / 16 / 16` (legal; **1.64 s** per open, measured) keeps that
  cost **forever**, because the rule is a maximum and never a reset.
- ⛔ **The ratchet does not cover every write.** `sigil totp …` saves through
  `save_vault(…, Argon2Params::RECOMMENDED)` and the desktop through
  `seal_vault(…, self.params)`; **neither reads the existing container.** Today
  that cannot downgrade anything, because `RECOMMENDED` (64 MiB) *is* the strongest
  thing anything here writes — so **"strength only goes up" is true of the browsers
  and of re-keys, and not globally true of this system.**
- ⚠️ **`ratchetParams` fails open** on a container it cannot parse, so a corrupt
  stored value never blocks a save — at the cost of losing the ratchet for that one
  write. The dangerous direction still cannot happen: it falls back to the client's
  own defaults, never to something weaker.
- ⚠️ The numbers are **chosen by measurement on one machine**, and the whole of it
  is **UNAUDITED**. Adversary treatment in [`threat-model.md`](threat-model.md).

## Recovery kit — a printable paper key

**Status (pre-audit, UNAUDITED, dev-gated).** A **recovery kit** is the answer to
the failure the account model recorded and could not fix: lose every device and
the account is unreachable, by us as well as by the customer. Every ordinary
answer is unavailable here — there is no email to reset, no password to recover
(losing it is one of the ways you get here), and a server that could restore a
vault is a server that could read one. What is left is the oldest answer: **give
the human the secret, on paper, before they need it**
([ADR 0042](decisions/0042-recovery-kit.md)).

⭐ **Cryptographically, a kit is not a new mechanism.** It is a **deterministic
entropy source** feeding the *existing* key-generation primitives. Its device
identity and its hybrid identity are ordinary ones; the server cannot tell it
apart from a phone.

### The printed encoding

```
seed  = 32 bytes from the client CSPRNG              ← printed; never transmitted
check = SHA-256( "sigil-recovery-kit-v1\n" ‖ [version] ‖ seed )[0..2]
body  = [version=0x01] ‖ seed(32) ‖ check(2)         = 35 bytes = 280 bits
code  = crockford32(body)                            = 56 characters, NO PADDING
sheet = code rendered as 7 groups of 8, hyphen-joined
```

- **280 bits divides by 5 exactly**, so there is no padding character and no
  ambiguity about a partial final group.
- **Crockford base32, not RFC 4648**, because a human reads this off paper: the
  alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ` omits `I`, `L`, `O` and `U`, and
  decoding folds `O`→`0` and `I`/`L`→`1`, case-insensitively.
  ⚠️ **`U` is REJECTED, never folded** — Crockford excludes it, and folding it
  would let two distinct strings decode to the same value.
- Any non-alphanumeric character (hyphen, space, tab, newline) is stripped before
  decoding, so the printed grouping is presentation only.
- ⭐ **The decode order is part of the contract: length → alphabet → CHECKSUM →
  version.** The checksum **covers the version byte** and is checked *before* the
  version is interpreted, so a flipped version bit reports *"that is not a valid
  recovery code — check for a mistyped character"* rather than *"unsupported
  version"*. A person holding a paper sheet needs to be told to look at their
  typing. Only a code whose checksum is **correct** for an unknown version yields
  an unsupported-version error.
- The two check bytes are an **integrity** check against transcription error, not
  a security control: a 16-bit checksum catches the overwhelming majority of typos
  offline, before any network call. **It is not a MAC.**

⚠️ **This is a NEW codec** ([`../libsigil/core/src/recovery.rs`](../libsigil/core/src/recovery.rs)).
It deliberately does **not** touch the RFC 4648 `base32_decode` used for TOTP
secrets: that one must stay interoperable with every `otpauth://` producer in the
world, and teaching it Crockford folding would be a compatibility change to an
interoperability surface for the benefit of an unrelated feature.

### The derivation

```
PRK = HKDF-Extract( salt = "sigil-recovery-kit-v1",  ikm = seed(32) )

ed25519_seed      = HKDF-Expand( PRK, "sigil-recovery-kit-v1/ed25519-device-seed", 32 )
x25519_secret     = HKDF-Expand( PRK, "sigil-recovery-kit-v1/x25519-secret",       32 )
mlkem_keygen_seed = HKDF-Expand( PRK, "sigil-recovery-kit-v1/mlkem-keygen-seed",   64 )   // d ‖ z
```

(The HKDF **salt** has no trailing newline; the **checksum domain** above does.
They are different strings on purpose.)

Those three outputs feed the **existing, unchanged** deterministic primitives —
`public_key_from_seed` (Ed25519), `x25519_public_key`, and `ml_kem768_keygen`
(FIPS 203, over the 64-byte `d ‖ z` seed). So the kit ends up holding exactly the
same two identities every other device holds: an Ed25519 device key for contract-v3
request signing, and a hybrid (X25519 + ML-KEM-768) identity for receiving wrapped
vault keys.

- ⭐ **This is [ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md) paying
  off.** Because `sigil-core` reads **no RNG and no clock** and every keygen takes
  caller-supplied entropy, a paper secret is *just another entropy source*.
  **Nothing in the core changed to accommodate recovery.**
- **HKDF, deliberately NOT Argon2id.** Argon2id exists to make a *low-entropy
  human secret* expensive to guess. There is no password here — the input is 256
  bits of CSPRNG, already uniform. The only requirement is **domain separation**,
  which HKDF provides. A memory-hard KDF would add cost and a parameter-drift
  hazard while buying nothing.
- **No new dependency**: `hkdf` and `sha2` were already direct dependencies of
  `sigil-core`, so the core stays wasm-pure and RNG-free and both `Cargo.lock`s
  stay `getrandom`-free.
- The derived-key struct's `Debug` prints exactly `RecoveryKeys { <redacted> }`, so
  a stray `{:?}` cannot leak it.

⭐ **The construction is SINGLE-SOURCED, not mirrored** — this paragraph used to
claim the opposite and then contradict itself two sentences later. The Crockford
codec, the checksum and all three HKDF derivations live in **one file**,
[`../libsigil/core/src/recovery.rs`](../libsigil/core/src/recovery.rs). The CLI
(and, through it, the native desktop app) imports `encode_recovery_kit` /
`decode_recovery_kit` / `derive_recovery_keys` directly; the browser surfaces
reach the same code through one-line `#[wasm_bindgen]` shells, so the wasm
bindings add **no cryptography and no codec** and
[`../sigil-wasm/recovery.mjs`](../sigil-wasm/recovery.mjs) implements none of it.
There is no second implementation to drift, and the known-answer vector exists on
both sides only as a cheap end-to-end check.

⚠️ **The mirror that genuinely exists — and had no test at all until Phase 57 —
is the kit's device LABEL.** `"recovery-kit"` is the only signal that makes a wrap
to a kit obey the mandatory-safety-number rule instead of ordinary
trust-on-first-use, and it lived as **three** hand-written literals (`cli/src/lib.rs`,
`sigil-wasm/recovery.mjs`, `sigil-wasm/sharing.mjs`). Renaming it in both JS files
left every suite green. The two JS copies are now one, and
`sigil-wasm/test/recovery-interop.mjs` drives the **real `sigil` binary** in both
directions — pinning both languages against the **golden literal**, because a
label the server stores and older clients compare against is a **wire value** and
is not free to change even "consistently". A third literal type in
`web/packages/sigil-wasm/index.d.ts` still drifts silently and is annotated as
such. See [ADR 0042](decisions/0042-recovery-kit.md)'s addendum.

### What this does and does not give you

- **The server never sees the secret**, cannot derive it, and holds no record that
  a kit is anything other than a device. Adversary classes 4 and 5 in
  [`threat-model.md`](threat-model.md) are unchanged.
- **Wrapping a vault key TO a kit goes through the same pinned-fetch choke point
  as every other wrap** ([ADR 0038](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)),
  with one extra rule: a **first-sight** wrap to a device the client believes is a
  kit is **refused** unless the caller supplies the safety number — which is
  **printed on the sheet**, so for once the out-of-band channel is in the same
  hand as the code. A key **derived locally** from the recovery secret is never
  fetched at all, so there is nothing for a server to substitute.
- ⚠️ **Whoever holds the paper holds the account.** There is no OS lock, no
  biometric and **no vault password** in front of those 56 characters. It is
  **stronger than a stolen locked phone**.
- ⚠️ **It recovers KEYS, not DATA**, only for the vaults it was told to **cover**,
  and **it cannot be created after the loss**.
- ⚠️ **UNAUDITED**, like everything around it. The codec and the derivation are new
  code. Full adversary treatment in
  [`threat-model.md`](threat-model.md#recovery-kit-adversaries-dev-gated--see-adr-0042).

⚠️ **A FOURTH label now hangs off the same PRK, and it does NOT live in
`recovery.rs`.** [ADR 0046](decisions/0046-passkey-protected-local-containers.md)
derives a **container master key** from the same seed under
`"sigil-recovery-kit-v1/container-master-key"`. It is computed in JavaScript
(`crypto.subtle`), not in the core — see the next section for why, and for the
security consequence of the sheet acquiring a second job.

## Passkey-protected local containers — the container master key and the slot

**Status (pre-audit, UNAUDITED, dev-only; the webapp only).** Every browser client
seals its `SIGILcli` containers with Argon2id under a **human password**, and that
password is the only factor between an attacker who copied `localStorage` and
everything inside. [ADR 0046](decisions/0046-passkey-protected-local-containers.md)
adds a **second AT-REST factor**: a WebAuthn credential's **PRF output** is mixed
into the sealing secret, so a stolen copy of the storage is useless without the
authenticator too.

⛔ **This is not request authentication and not transport.** The wire protocol is
byte-for-byte unchanged — every signed request is still a classical Ed25519
contract-v3 signature, and `sigild` gained no route, header, canonical message,
migration, table, metric or dependency. A hostile server cannot disable, weaken,
detect or observe it.

### The container master key (CMK)

```
CMK = HKDF-SHA256( salt = "sigil-recovery-kit-v1",                 ← the SAME salt as above
                   ikm  = kit_seed(32),                            ← the printed ADR 0042 sheet
                   info = "sigil-recovery-kit-v1/container-master-key",
                   L    = 32 )
```

With protection on, **both** containers (the TOTP vault and the device identity)
are sealed under the CMK instead of the password.

⭐ **The break-glass therefore needs NO new artifact and NO server.** The 56
characters already printed to survive losing every device also open a protected
local profile, offline. There is no second sheet and nothing for the server to
hold.

⚠️ **It is computed in JS, deliberately** ([`../sigil-wasm/passkey.mjs`](../sigil-wasm/passkey.mjs)) —
one `crypto.subtle.deriveBits` call — and **not** added as a fourth label in
[`../libsigil/core/src/recovery.rs`](../libsigil/core/src/recovery.rs). No Rust
caller exists, so a Rust copy would be a mirror that can only drift, and a new wasm
export would mean editing both `index.mjs` and `index.d.ts` (two separate holes, as
Phase 56 proved). If the CLI or the desktop ever want offline local unlock, it moves
into `recovery.rs`, single-sourced, and the JS becomes a shell.

### The passkey slot

```
PRF_SALT = SHA-256("sigil-passkey-unlock-v1")        32-byte CONSTANT, not a secret
R        = prf.results.first of a WebAuthn assertion, evaluated at PRF_SALT   32 bytes

hwslot   = seal_to_container( R ‖ utf8(password), salt, nonce, Argon2 params,
                              {"version":1,"cmk":<b64 32>,"kit_device_id":…,
                               "credential_id":…,"rp_id":…,"backup_eligible":…,
                               "backup_state":…,"created_at":…} )
```

The slot is the third `SIGILcli` container in `localStorage`
(`sigil.webapp.hwslot.v1`). Two choices in the secret are load-bearing:

- ⭐ **`R ‖ utf8(password)` is fed STRAIGHT to the container's own Argon2id.**
  There is deliberately **no cheap HKDF over the password first**. An attacker who
  can *drive the authenticator* (an unlocked device, a coerced user-verification
  prompt) recovers `R` and then still faces Argon2id over the password; reducing
  the password through a fast KDF first would hand that attacker an **unstretched**
  guess.
- ⭐ **PRF bytes FIRST.** The fixed-length 32-byte prefix makes the concatenation
  unambiguous; password-first would let `("abc", P)` and `("abcX", P′)` collide.

The credential is **discoverable** (`residentKey: "required"`), so the locked
screen can run `get()` with an empty `allowCredentials` — the credential id lives
*inside* the sealed slot, and no plaintext marker naming it is ever written. The
slot is a container rather than a JSON marker precisely to keep the persisted set
*"sealed containers only"*
([ADR 0036](decisions/0036-browser-sharing-secret-storage.md)); sealing public
metadata under a hardcoded constant just to satisfy that check would be fake
crypto.

### The two doors, and the order of writes

⭐ **AND, never OR.** While protection is on there is **no password-only slot**.
The doors are **(password AND passkey)** and **(the printed sheet)**. An OR design
is theatre: an offline attacker attacks the weaker branch and the passkey buys
zero.

⭐ **Enabling is not atomic, so the write order IS the safety property.** The
containers are written **first** and the slot **last**, so a crash leaves
CMK-sealed containers with **no slot** — a state the printed sheet alone recovers.
The original order (slot first) left a slot beside still-password-sealed
containers, and in **that** state a sheet-derived CMK cannot open a password-sealed
container: information-theoretically true, and unfixable at the unlock end. *Make
the last write the one whose loss costs least.*

### What this does and does not give you

- **It defends STORAGE, never EXECUTION.** Anything running in the origin while
  the vault is unlocked reads the plaintext vault, the seed, the hybrid secret,
  every vault key, the password, the PRF output **and the CMK** — exactly as
  before.
- ⚠️ **It is NOT retroactive.** Only containers re-sealed after protection is
  enabled are protected; earlier copies, backups and forensic images stay
  password-only forever.
- ⚠️ **`R` is a keyed function's output, not an authenticator secret we hold.** We
  never see the credential's private key, request no attestation, and therefore
  make **no claim** about what kind of authenticator is in use. `userVerification:
  "required"` is a policy *request* and a flag we read, not a proof.
- ⚠️ **A backup-eligible credential syncs to a provider account**, so the factor is
  only as strong as that account. The UI derives its scope sentence from the BE/BS
  flags of the ceremony that just ran, never from what was true when protection was
  switched on.
- ⚠️ **PRF availability varies** by browser, platform and authenticator; a PRF that
  is missing, short, or non-deterministic is treated as **unsupported**, never as
  "retry", because a non-deterministic one would seal a container nothing could
  reopen.
- ⚠️ **Whoever holds the printed sheet now also holds local unlock.** The paper was
  already a full-account credential
  ([ADR 0042](decisions/0042-recovery-kit.md) limitation 1); its reach grew.
- ⚠️ **Only the webapp implements this.** The MV3 extension and the native desktop
  do not — scope, not a blocker.
- ⚠️ **UNAUDITED**, dev-only, like everything around it. Adversary treatment in
  [`threat-model.md`](threat-model.md).

## HOTP / TOTP one-time-password primitive (`hotp` / `totp`)

**Status (pre-audit, UNAUDITED).** `sigil-core` now implements the **authenticator
primitive** the product is named for: **RFC 4226 HOTP** and **RFC 6238 TOTP**, in
[`libsigil/core/src/totp.rs`](../libsigil/core/src/totp.rs). This is the **first
primitive that implements an actual product feature** rather than a general
cryptographic building block. The OTP math is **real** and checked against the
official RFC known-answer vectors; it is still **UNAUDITED** and pre-audit.

The primitive is three functions over an `OtpAlgorithm` selector
(`Sha1` (default) / `Sha256` / `Sha512`), returning `OtpError` for out-of-range
arguments:

```rust
pub fn hotp(key: &[u8], counter: u64, digits: u32,
            algorithm: OtpAlgorithm) -> Result<u32, OtpError>;

pub fn totp(key: &[u8], unix_time: u64, period: u32, t0: u64, digits: u32,
            algorithm: OtpAlgorithm) -> Result<u32, OtpError>;

pub fn format_code(code: u32, digits: u32) -> String;   // zero-padded
```

- **`hotp`** is RFC 4226 §5.3: `HMAC-H(key, counter_be64)` under the chosen hash,
  then **dynamic truncation** — the low nibble of the last MAC byte is an offset,
  a big-endian **31-bit** integer (top bit masked) is read from
  `MAC[offset..offset+4]`, and reduced modulo `10^digits`.
- **`totp`** is RFC 6238 §4: it forms the time counter
  `T = (unix_time - t0) / period` and defers to `hotp`. `t0` is the epoch offset
  (usually `0`) and `period` the time step in seconds (usually `30`).
- **`format_code`** renders the numeric code as a zero-padded fixed-width string
  (so `073921` keeps its leading zero).
- `digits` is bounded `MIN_DIGITS..=MAX_DIGITS` (**6..=10**); `OtpError` covers
  `InvalidDigits`, `InvalidPeriod` (zero period), and `TimeBeforeT0`.

**No clock, no RNG — the caller supplies the time.** Consistent with
[ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md), `totp` takes the
current Unix time as a **`u64` argument** and reads no system clock; the native
binary (or the browser) supplies it, exactly as callers supply salts, nonces, and
seeds. There is no in-core time source and no randomness here, so the
`wasm32-unknown-unknown` / `no_std` / `getrandom`-free build is preserved.

**Dependencies (both `getrandom`-free).** The HMAC uses RustCrypto
[`hmac`](https://docs.rs/hmac) (already in the tree transitively via `hkdf`, now a
direct dependency) with `sha1` for HMAC-SHA-1 and the existing `sha2` for
SHA-256/512. `sha1` is **new** and required for interop: real-world authenticator
apps and `otpauth://` provisioning are overwhelmingly HMAC-SHA-1, so SHA-1 is the
default and interoperability *demands* it (this is HMAC-SHA-1, a keyed MAC — not
SHA-1 as a collision-resistant hash). Both crates are `default-features = false`,
which keeps `getrandom`/`rand` out and the core lockfile guard
(`grep -c 'name = "getrandom"' libsigil/Cargo.lock` == 0) intact.

**Verified against the RFC vectors.** In-module tests check `hotp` against **RFC
4226 Appendix D** (the ten 6-digit HMAC-SHA-1 values for counters 0..=9) and
`totp` against the complete **RFC 6238 Appendix B** table (8-digit codes at six
reference times for SHA-1 / SHA-256 / SHA-512, with the RFC's per-hash key
lengths).

**Scope / caveats (honest, pre-audit).** The module **only generates** codes; it
does **not** verify a user-entered code — a constant-time compare and any validity
window are the caller's responsibility. It does **not** zeroize the key or
intermediate HMAC state beyond what the dependencies do. It is a **real but
UNAUDITED** building block; do **not** store real 2FA secrets in this pre-audit
build.

**First product-feature consumer: the CLI's encrypted TOTP vault.** The demo
`cli` wires this primitive into a `sigil totp` vault (`add` / `list` / `code` /
`remove`, with base32 and `otpauth://` import). Secrets are stored in a
`TotpVault` JSON that is **sealed at rest with the same `SIGILcli` password
container as `seal`/`open`** (Argon2id + XChaCha20-Poly1305), so a TOTP vault is
just another opaque sealed container — E2EE at rest, and syncable through the
op-log later with no new format. The CLI supplies the wall clock and the entropy;
the core supplies only the OTP math. See
[ADR 0023](decisions/0023-totp-hotp-primitive-and-cli-vault.md).

## Migration plan (intended)

1. **Today** — all new data at suite `0x12`.
2. **2026 Q4** — add `0x13`; deprecate classical-only `0x11`; warn on `0x11` records.
3. **2027 Q2** — register `0x14` (HQC + SLH-DSA) backup, not yet active.
4. **2028** — re-encrypt remaining `0x11` at `0x12`+; server rejects `0x11` writes.
5. **Q-Day / threshold** — classical-only verification disabled; hybrid required.
