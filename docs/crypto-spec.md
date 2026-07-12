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
> **both hybrid constructions (KEM and signature) now exist as standalone
> primitives**; neither is wired into a product flow. Condensed from
> the product brief §11/§20/§21. Subject to change. A Cure53 audit of the hybrid
> construction is to be commissioned before public beta.

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
KEM now exist as standalone primitives in `sigil-core`.** The **classical X25519
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

Both primitives are **real but NOT YET AUDITED**. The **combined hybrid KEM
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
ciphertext from one exchange onto material from another. This is **real but
UNAUDITED and standalone**: it is **not wired into the record / vault / account
flow**, the envelope's `kem_ct` field stays *reserved* but unused, and the
**SYSTEM is still not "post-quantum secure"** (see
[ADR 0011](decisions/0011-hybrid-kem-combiner.md)). The **hybrid signature**
(Ed25519 & ML-DSA-65) is now assembled as a standalone primitive too — see the
signature-implementation-status note below — so **both** hybrid constructions now
exist; the remaining hybrid-crypto work is **wiring** them into an actual flow.

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
standalone**: it is **not wired into a record / vault / account / session flow**
(e.g. the `sigild` op-log request auth still uses classical Ed25519 only). With
this and the hybrid **KEM** (`hybrid.rs`; see above and
[ADR 0011](decisions/0011-hybrid-kem-combiner.md)), **both hybrid constructions now
exist as standalone primitives**; the only remaining large crypto work is **wiring
the hybrid primitives into an actual account/session/record flow** (nothing uses
them yet), and the **SYSTEM is still not "post-quantum secure"**. See
[ADR 0012](decisions/0012-hybrid-signature-combiner.md).

## Migration plan (intended)

1. **Today** — all new data at suite `0x12`.
2. **2026 Q4** — add `0x13`; deprecate classical-only `0x11`; warn on `0x11` records.
3. **2027 Q2** — register `0x14` (HQC + SLH-DSA) backup, not yet active.
4. **2028** — re-encrypt remaining `0x11` at `0x12`+; server rejects `0x11` writes.
5. **Q-Day / threshold** — classical-only verification disabled; hybrid required.
