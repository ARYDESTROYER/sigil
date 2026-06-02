# sigil-ffi

C-ABI surface for libsigil.

**STATUS: pre-audit, UNAUDITED building block.** This crate exposes a thin,
hand-written C-ABI over `sigil-core`'s symmetric AEAD seal/open layer
(XChaCha20-Poly1305 + HKDF-SHA256). The underlying cryptography is real (vetted
RustCrypto crates) but has **not** been audited, and it is **not** wired into a
complete account / key-management / key-rotation flow. Treat the exports as
building blocks, not a finished secure system. Do not store real secrets.

## Exports

| Symbol                | Purpose                                                                 |
| --------------------- | ----------------------------------------------------------------------- |
| `sigil_current_suite` | Link/smoke check; returns the current algorithm-suite byte (`0x12`).    |
| `sigil_seal`          | Encrypt a plaintext; outputs the **encoded envelope bytes**.            |
| `sigil_open`          | Authenticate + decrypt encoded envelope bytes; outputs the plaintext.   |
| `sigil_buffer_free`   | Release a buffer produced by `sigil_seal` / `sigil_open`.               |

The C declarations live in [`include/sigil.h`](include/sigil.h), which is
hand-written (not generated) and kept in sync with `src/lib.rs` by hand.

## Status codes

`sigil_seal` / `sigil_open` return an `int32_t`:

| Constant              | Value | Meaning                                                              |
| --------------------- | ----- | -------------------------------------------------------------------- |
| `SIGIL_OK`            | `0`   | Success; `*out` was written.                                         |
| `SIGIL_ERR_NULL_ARG`  | `-1`  | A required pointer was null (or a non-zero length with a null ptr).  |
| `SIGIL_ERR_OPEN`      | `-2`  | Authentication or envelope-decode failure on `sigil_open`.           |
| `SIGIL_ERR_BAD_INPUT` | `-3`  | Malformed input shape (reserved; not an authentication failure).     |

`sigil_open` collapses every envelope-decode and authentication failure to
`SIGIL_ERR_OPEN` so the boundary never leaks plaintext or fine-grained
structure, and never writes `*out` on the error path.

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
