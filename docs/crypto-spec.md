# Sigil cryptographic specification (condensed)

> **Internal / pre-audit. UNAUDITED.** This describes the intended design of
> `libsigil`. The code in this repo implements **real but UNAUDITED** building
> blocks — the algorithm-suite registry, the envelope codec, an Argon2id KDF, an
> XChaCha20-Poly1305 + HKDF AEAD, a composed `seal_record`/`open_record`, and a
> standalone classical **Ed25519 sign/verify** primitive — none wired into a
> finished product. Both KEM halves (X25519 and ML-KEM-768) now exist as
> standalone UNAUDITED primitives, but the **hybrid *combine* and the ML-DSA-65
> post-quantum signature half remain specified-but-not-implemented.** Condensed from
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

**Implementation status (pre-audit, UNAUDITED).**

*Key encapsulation.* The **classical X25519 half** is now **implemented** in
`sigil-core` ([`libsigil/core/src/kex.rs`](../libsigil/core/src/kex.rs)): a raw
RFC 7748 X25519 key-agreement primitive — `x25519_public_key` and
`x25519_shared_secret` over a **caller-supplied 32-byte secret scalar** (the core
generates no key material — see
[ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md) and
[ADR 0010](decisions/0010-x25519-key-agreement-primitive.md)), plus a
constant-time `is_contributory` check for the low-order-point all-zero case
(RFC 7748 §6.1). Its output is exactly `ss_x` above. (Note: X25519 public keys
are **not canonically encoded** — bit 255 is masked and `u` reduced mod p — so any
`transcript_hash` that folds in raw peer-key bytes MUST normalize them first;
derive from the shared secret, not the raw encoding.) It is **real but NOT YET
AUDITED** and **not wired into a KEM/product flow**. The **ML-KEM-768 post-quantum
half** is now **also implemented** in `sigil-core`
([`libsigil/core/src/mlkem.rs`](../libsigil/core/src/mlkem.rs)): a raw FIPS 203
ML-KEM-768 primitive — `mlkem768_keygen` over **caller-supplied 32-byte `d` and
`z` seeds**, `mlkem768_encapsulate` over **caller-supplied 32-byte randomness
`m`** (the core still generates no key material —
[ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md)), and
`mlkem768_decapsulate` — backed by the RustCrypto `ml-kem` crate (`no_std`,
deterministic API, no `getrandom`); see
[ADR 0013](decisions/0013-ml-kem-768-pq-kem-primitive.md). Encoded sizes:
encapsulation key 1184 B, decapsulation key 2400 B, ciphertext 1088 B, shared
secret 32 B. Callers may persist the 64-byte `d ‖ z` seed instead of the
2400-byte decapsulation key and re-derive on demand (FIPS 203 permits this; the
seed is exactly as secret as the key). Per FIPS 203, decapsulation uses
**implicit rejection**: a tampered ciphertext yields a *different* shared secret,
**not an error** — callers MUST NOT treat successful decapsulation as
authentication. It too is **real but NOT YET AUDITED** and **not wired into any
KEM/product flow**. The two shared secrets are **still not combined** —
`ss_combined` above does not exist in code — so the hybrid `X25519 & ML-KEM-768`
encapsulation is **not** available, suite `0x12` remains **not fully
implemented**, and records still get **no post-quantum protection today**.

*Signatures.* The **classical Ed25519 half** is likewise **implemented** in
`sigil-core` ([`libsigil/core/src/sig.rs`](../libsigil/core/src/sig.rs)):
a deterministic RFC 8032 Ed25519 `sign`/`verify` primitive over a
**caller-supplied 32-byte secret seed**. It is **real but NOT YET AUDITED**, and
it is **not yet wired into the hybrid signature construction or any product
flow** — it stands as a standalone primitive. The **ML-DSA-65 post-quantum half
remains specified-but-not-implemented**, so the hybrid `Ed25519 & ML-DSA-65`
signature above is **not** available: there is no post-quantum signature in this
repo yet, and no combined hybrid `Sign`/`Verify`.

## Migration plan (intended)

1. **Today** — all new data at suite `0x12`.
2. **2026 Q4** — add `0x13`; deprecate classical-only `0x11`; warn on `0x11` records.
3. **2027 Q2** — register `0x14` (HQC + SLH-DSA) backup, not yet active.
4. **2028** — re-encrypt remaining `0x11` at `0x12`+; server rejects `0x11` writes.
5. **Q-Day / threshold** — classical-only verification disabled; hybrid required.
