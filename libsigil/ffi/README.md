# sigil-ffi

C-ABI surface for libsigil.

**STATUS: pre-audit, UNAUDITED building block.** This crate exposes a thin,
hand-written C-ABI over `sigil-core`'s symmetric AEAD seal/open layer
(XChaCha20-Poly1305 + HKDF-SHA256) plus the classical **Ed25519** signature
primitive (derive public key / sign / verify). The underlying cryptography is
real (vetted RustCrypto crates) but has **not** been audited, and it is **not**
wired into a complete account / key-management / key-rotation flow. The
signatures are plain Ed25519 (RFC 8032) — the post-quantum ML-DSA-65 half of the
future hybrid is **not** present here. Treat the exports as building blocks, not
a finished secure system. Do not store real secrets.

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

The C declarations live in [`include/sigil.h`](include/sigil.h), which is
hand-written (not generated) and kept in sync with `src/lib.rs` by hand.

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

`sigil_open` collapses every envelope-decode and authentication failure to
`SIGIL_ERR_OPEN` so the boundary never leaks plaintext or fine-grained
structure, and never writes `*out` on the error path. `sigil_verify` likewise
collapses every verification-path failure (invalid public-key point, malformed
signature, or a well-formed signature that does not verify) to
`SIGIL_ERR_VERIFY`.

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
