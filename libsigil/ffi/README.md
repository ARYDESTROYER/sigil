# sigil-ffi

C-ABI surface for libsigil.

**STATUS: pre-audit, UNAUDITED building block.** This crate exposes a thin,
hand-written C-ABI over `sigil-core`'s symmetric AEAD seal/open layer
(XChaCha20-Poly1305 + HKDF-SHA256), the classical **Ed25519** signature
primitive (derive public key / sign / verify), and the **hybrid encryption
path** (an X25519 + ML-KEM-768 KEM combined via HKDF, then the AEAD envelope).
The underlying cryptography is real (vetted RustCrypto crates) but has **not**
been audited, and it is **not** wired into a complete account / key-management /
key-rotation flow. The signatures are plain Ed25519 (RFC 8032); the hybrid path
is a **custom KEM-then-AEAD** construction — it is **NOT** RFC 9180 HPKE, and
"post-quantum" names only the ML-KEM-768 component algorithm, so neither the
construction nor the system is "post-quantum secure". The ML-DSA-65 signature
half of the future hybrid is **not** present here. Treat the exports as building
blocks, not a finished secure system. Do not store real secrets.

## Exports

| Symbol                       | Purpose                                                                 |
| ---------------------------- | ----------------------------------------------------------------------- |
| `sigil_current_suite`        | Link/smoke check; returns the current algorithm-suite byte (`0x12`).    |
| `sigil_seal`                 | Encrypt a plaintext; outputs the **encoded envelope bytes**.            |
| `sigil_open`                 | Authenticate + decrypt encoded envelope bytes; outputs the plaintext.   |
| `sigil_buffer_free`          | Release a buffer produced by `sigil_seal` / `sigil_open`.               |
| `sigil_public_key_from_seed` | Derive the 32-byte Ed25519 public key from a 32-byte secret seed.       |
| `sigil_sign`                 | Sign a message with a 32-byte seed; writes a 64-byte signature.         |
| `sigil_verify`               | Strictly verify a 64-byte signature against a 32-byte public key.       |
| `sigil_x25519_public_key`    | Derive the 32-byte X25519 public key from a 32-byte secret scalar.      |
| `sigil_ml_kem768_keygen`     | Generate an ML-KEM-768 `(encaps, decaps)` key pair from a 64-byte seed. |
| `sigil_hybrid_encapsulate`   | Hybrid-encapsulate a 32-byte secret to a recipient's hybrid public key. |
| `sigil_hybrid_decapsulate`   | Recover the 32-byte hybrid secret with the recipient's hybrid secret key. |
| `sigil_hybrid_seal`          | Encrypt **to** a hybrid public key; outputs eph pubkey, KEM ct, envelope. |
| `sigil_hybrid_open`          | Decrypt with the hybrid secret key; outputs the recovered plaintext.    |

The C declarations live in [`include/sigil.h`](include/sigil.h), which is
hand-written (not generated) and kept in sync with `src/lib.rs` by hand.

### Hybrid encryption path (X25519 + ML-KEM-768 KEM, then AEAD)

`sigil_x25519_public_key` / `sigil_ml_kem768_keygen` derive a **hybrid
identity**'s public halves; `sigil_hybrid_encapsulate` / `sigil_hybrid_decapsulate`
are the two sides of the hybrid KEM (X25519 + ML-KEM-768 combined via HKDF-SHA256
into one 32-byte secret); and `sigil_hybrid_seal` / `sigil_hybrid_open` encrypt
**to** a recipient's hybrid public key and decrypt with the matching hybrid
secret key. The seal/open pair is a **custom KEM-then-AEAD** construction — the
hybrid secret keys the XChaCha20-Poly1305 + HKDF envelope. **It is NOT RFC 9180
HPKE, and the system is NOT "post-quantum secure".**

Fixed-size buffers (from `#define`s in the header) go into caller-provided
buffers with nothing to free; the seal envelope and the open plaintext come back
in heap `SigilBuffer`s that the caller MUST release with `sigil_buffer_free`.

| Constant                          | Value  | Buffer                                    |
| --------------------------------- | ------ | ----------------------------------------- |
| `SIGIL_X25519_PUBLIC_KEY_LEN`     | `32`   | X25519 public key                         |
| `SIGIL_X25519_SECRET_KEY_LEN`     | `32`   | X25519 secret scalar                      |
| `SIGIL_MLKEM768_ENCAPS_KEY_LEN`   | `1184` | ML-KEM-768 encapsulation (public) key     |
| `SIGIL_MLKEM768_DECAPS_KEY_LEN`   | `2400` | ML-KEM-768 decapsulation (secret) key     |
| `SIGIL_MLKEM768_CIPHERTEXT_LEN`   | `1088` | ML-KEM-768 ciphertext                     |
| `SIGIL_MLKEM768_KEYGEN_SEED_LEN`  | `64`   | ML-KEM-768 keygen seed (`d ‖ z`)          |
| `SIGIL_MLKEM768_ENCAPS_COIN_LEN`  | `32`   | ML-KEM-768 encapsulation coin             |
| `SIGIL_HYBRID_SHARED_SECRET_LEN`  | `32`   | combined hybrid shared secret             |
| `SIGIL_AEAD_NONCE_LEN`            | `24`   | AEAD (XChaCha20-Poly1305) nonce           |

**Caller-supplied entropy (this layer draws NO randomness):** the ephemeral
X25519 secret, the ML-KEM-768 coin, the ML-KEM keygen seed, and the AEAD nonce
are ALL the caller's responsibility and MUST come fresh, per call, from a
CSPRNG. Reusing an ephemeral secret + coin repeats the hybrid secret, and a
repeated `(key, nonce)` pair is catastrophic for the AEAD.

### Ed25519 signature primitive (fixed-size, no heap)

`sigil_public_key_from_seed` / `sigil_sign` / `sigil_verify` are the classical
half of the future Ed25519 & ML-DSA-65 hybrid; **the ML-DSA-65 post-quantum half
is not implemented here.** Unlike seal/open, they write **fixed-size** outputs
into **caller-provided** buffers, so there is no heap `SigilBuffer` and nothing
to free. Buffer sizes are fixed by `#define`s in the header:

| Constant                   | Value | Buffer                          |
| -------------------------- | ----- | ------------------------------- |
| `SIGIL_SIG_SEED_LEN`       | `32`  | caller's secret seed            |
| `SIGIL_SIG_PUBLIC_KEY_LEN` | `32`  | public key                      |
| `SIGIL_SIGNATURE_LEN`      | `64`  | signature                       |

`message` may be `NULL` **iff** its length is `0` (an empty message is
signed/verified). This is a raw signature primitive, not an enrollment /
multi-device / key-rotation system.

## Status codes

`sigil_seal` / `sigil_open` / `sigil_sign` / `sigil_verify` /
`sigil_public_key_from_seed` return an `int32_t`:

| Constant              | Value | Meaning                                                              |
| --------------------- | ----- | -------------------------------------------------------------------- |
| `SIGIL_OK`            | `0`   | Success; the output buffer was written.                             |
| `SIGIL_ERR_NULL_ARG`  | `-1`  | A required pointer was null (or a non-zero length with a null ptr).  |
| `SIGIL_ERR_OPEN`      | `-2`  | Authentication or envelope-decode failure on `sigil_open`.           |
| `SIGIL_ERR_BAD_INPUT` | `-3`  | Malformed input shape (reserved; not an authentication failure).     |
| `SIGIL_ERR_VERIFY`    | `-4`  | `sigil_verify`: the Ed25519 signature did not verify.                |
| `SIGIL_ERR_HYBRID`    | `-5`  | Hybrid KEM failure on encapsulate/decapsulate/seal (e.g. a low-order key). |

`sigil_open` collapses every envelope-decode and authentication failure to
`SIGIL_ERR_OPEN` so the boundary never leaks plaintext or fine-grained
structure, and never writes `*out` on the error path. `sigil_verify` likewise
collapses every verification-path failure (invalid public-key point, malformed
signature, or a well-formed signature that does not verify) to
`SIGIL_ERR_VERIFY`. `sigil_hybrid_encapsulate` / `sigil_hybrid_decapsulate` /
`sigil_hybrid_seal` return `SIGIL_ERR_HYBRID` when the hybrid KEM rejects an
input (notably a non-contributory / low-order X25519 public key), writing no
output. `sigil_hybrid_open` mirrors `sigil_open`: **every** failure — hybrid-KEM
rejection, envelope decode, or authentication — collapses to `SIGIL_ERR_OPEN`,
and no plaintext is written.

## Buffer / ownership contract

```c
typedef struct {
    uint8_t *data; /* len heap bytes owned by libsigil, or NULL */
    size_t   len;
} SigilBuffer;
```

- `sigil_seal` / `sigil_open` write a freshly heap-allocated `SigilBuffer` into
  `*out`. The bytes are owned by **libsigil**, not the caller's allocator.
- The caller MUST release every buffer it receives with `sigil_buffer_free`,
  **exactly once**. Do not call C `free` on `data`.
- `sigil_buffer_free` is a no-op on the canonical empty buffer
  (`{data: NULL, len: 0}`); an empty plaintext / empty output normalises to
  that form. The caller still owns the `SigilBuffer` value itself (e.g. its
  stack slot); only the heap slice is reclaimed.

## Caller responsibilities (pre-audit caveats)

- **Nonce uniqueness is the caller's job.** This layer generates no randomness;
  the caller MUST ensure a `(master_key, nonce)` pair is never reused — nonce
  reuse is catastrophic for any Poly1305-based AEAD.
- `master_key` must point at 32 readable bytes and `nonce` at 24 readable
  bytes; both are copied into fixed-size arrays before use.
- `aad` / `plaintext` (and `envelope`) may be `NULL` **iff** their length is
  `0`; otherwise they must point at the stated number of readable bytes.
