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
> (`hybrid.rs`), joining the two halves it composes. With ML-DSA-65 landed, **both
> halves of the hybrid signature now exist as standalone primitives** (Ed25519 in
> `sig.rs`, ML-DSA-65 in `mldsa.rs`), but the **combined hybrid signature is still
> not assembled** (no combiner yet), so it does not yet exist as a usable
> construction. Condensed from
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
[ADR 0011](decisions/0011-hybrid-kem-combiner.md)). The remaining hybrid-crypto
gap is the **hybrid signature** (Ed25519 & ML-DSA-65): per the
signature-implementation-status note below, **both** signature halves now exist as
standalone primitives, but the combining `Sign`/`Verify` that requires both has
not yet been assembled.

**Signature implementation status (pre-audit, UNAUDITED).** **Both halves of the
hybrid signature now exist as standalone primitives in `sigil-core`.** The
**classical Ed25519 half** is implemented in
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

The **combined hybrid signature has NOT yet been assembled.** There is **no
combiner** producing `Ed25519.Sign(m) || ML-DSA-65.Sign(m)` and no `Verify` that
requires **both** halves to validate, and neither half is wired into a
record / vault / account flow. So although both signature primitives now exist,
the hybrid `Ed25519 & ML-DSA-65` signature of suite `0x12` is **still not
available**. This lags the hybrid **KEM**, which **is** already assembled as a
standalone combiner (`hybrid.rs`; see above and
[ADR 0011](decisions/0011-hybrid-kem-combiner.md)). With ML-DSA-65 landed, the only
remaining large crypto gap is the **hybrid-signature combiner and wiring the
hybrid primitives into an actual flow**; the **SYSTEM is still not "post-quantum
secure"**.

## Migration plan (intended)

1. **Today** — all new data at suite `0x12`.
2. **2026 Q4** — add `0x13`; deprecate classical-only `0x11`; warn on `0x11` records.
3. **2027 Q2** — register `0x14` (HQC + SLH-DSA) backup, not yet active.
4. **2028** — re-encrypt remaining `0x11` at `0x12`+; server rejects `0x11` writes.
5. **Q-Day / threshold** — classical-only verification disabled; hybrid required.
