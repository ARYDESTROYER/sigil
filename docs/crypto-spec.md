# Sigil cryptographic specification (condensed)

> **Internal / pre-audit. NOT YET IMPLEMENTED OR AUDITED.** This describes the
> intended design of `libsigil`. The code in this repo implements only the
> algorithm-suite registry and envelope metadata — no real cryptography runs
> yet. Condensed from the product brief §11/§20/§21. Subject to change. A
> Cure53 audit of the hybrid construction is to be commissioned before public
> beta.

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

## Migration plan (intended)

1. **Today** — all new data at suite `0x12`.
2. **2026 Q4** — add `0x13`; deprecate classical-only `0x11`; warn on `0x11` records.
3. **2027 Q2** — register `0x14` (HQC + SLH-DSA) backup, not yet active.
4. **2028** — re-encrypt remaining `0x11` at `0x12`+; server rejects `0x11` writes.
5. **Q-Day / threshold** — classical-only verification disabled; hybrid required.
