/*
 * sigil.h — C-ABI surface for libsigil.
 *
 * STATUS: pre-audit, UNAUDITED building block. This header declares a thin
 * C-ABI over sigil-core's symmetric AEAD seal/open layer (XChaCha20-Poly1305 +
 * HKDF-SHA256). The underlying cryptography is real (vetted RustCrypto crates)
 * but has NOT been audited, and it is NOT wired into a complete account /
 * key-management / key-rotation flow. Treat these functions as building blocks,
 * not a finished secure system. Do not store real secrets.
 *
 * This file is hand-written (not generated) and kept in sync with
 * libsigil/ffi/src/lib.rs by hand.
 */
#pragma once
#ifndef SIGIL_H
#define SIGIL_H

#include <stddef.h> /* size_t  */
#include <stdint.h> /* uint8_t, int32_t */

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Status codes (returned as int32_t by sigil_seal / sigil_open) ---- */

/* Success: the operation completed and *out was written. */
#define SIGIL_OK 0
/* A required pointer argument was null (or a non-zero length was paired with a
 * null pointer where that is not allowed). *out is left untouched. */
#define SIGIL_ERR_NULL_ARG (-1)
/* Authentication or envelope decode failed on sigil_open. No plaintext is
 * produced. Envelope-decode and authentication failures both map here so the
 * boundary never leaks plaintext or fine-grained structure. */
#define SIGIL_ERR_OPEN (-2)
/* Malformed input shape detected before the crypto step (reserved; not an
 * authentication failure). */
#define SIGIL_ERR_BAD_INPUT (-3)

/*
 * A heap buffer owned by libsigil until released with sigil_buffer_free().
 *
 * `data` points at `len` bytes allocated by libsigil. The value
 * {data: NULL, len: 0} is the canonical empty/freed buffer and is safe to pass
 * to sigil_buffer_free(). The caller owns the SigilBuffer value itself (e.g.
 * its stack slot); sigil_buffer_free reclaims only the heap slice it points at.
 * Do NOT free `data` with the C allocator (free()).
 */
typedef struct SigilBuffer {
    uint8_t *data; /* len heap bytes owned by libsigil, or NULL */
    size_t   len;  /* length, in bytes, of the region `data` points at */
} SigilBuffer;

/*
 * Returns the current algorithm-suite byte (0x12, hybrid post-quantum-ready).
 *
 * Link/smoke check: lets every client binding verify it links and calls into
 * libsigil correctly.
 */
uint8_t sigil_current_suite(void);

/*
 * Encrypt `plaintext` under `master_key` (32 bytes) with `nonce` (24 bytes) and
 * `aad`, writing the ENCODED ENVELOPE BYTES into a freshly heap-allocated
 * SigilBuffer via *out.
 *
 * Pre-audit, unaudited building block. The caller MUST ensure the
 * (master_key, nonce) pair is never reused (nonce reuse is catastrophic for any
 * Poly1305-based AEAD) and MUST release the produced buffer with
 * sigil_buffer_free.
 *
 * Pointer rules:
 *   - master_key, nonce, out: must be non-null.
 *   - master_key points at 32 readable bytes; nonce points at 24 readable bytes
 *     (both are copied internally before use).
 *   - aad / plaintext may be NULL iff aad_len / plaintext_len is 0 (an empty
 *     slice is used in that case); otherwise they must point at the stated
 *     number of readable bytes.
 *
 * Returns SIGIL_OK on success (*out is written), or SIGIL_ERR_NULL_ARG if a
 * required pointer is null (or a non-zero length is paired with a null
 * aad/plaintext pointer); *out is left untouched on error.
 */
int32_t sigil_seal(const uint8_t *master_key, /* 32 bytes */
                   const uint8_t *nonce,      /* 24 bytes */
                   const uint8_t *aad,
                   size_t         aad_len,
                   const uint8_t *plaintext,
                   size_t         plaintext_len,
                   SigilBuffer   *out);

/*
 * Decode the `envelope` bytes (as produced by sigil_seal) and authenticate +
 * decrypt them under `master_key` (32 bytes), writing the recovered plaintext
 * into a freshly heap-allocated SigilBuffer via *out.
 *
 * Pre-audit, unaudited building block. The caller MUST release the produced
 * buffer with sigil_buffer_free.
 *
 * Pointer rules:
 *   - master_key, out: must be non-null. master_key points at 32 readable bytes.
 *   - envelope may be NULL iff envelope_len is 0; otherwise it must point at
 *     envelope_len readable bytes.
 *
 * Returns:
 *   - SIGIL_OK on success (*out written; may be the empty buffer for an empty
 *     plaintext).
 *   - SIGIL_ERR_NULL_ARG if master_key/out is null (or envelope_len != 0 with a
 *     null envelope); *out is left untouched.
 *   - SIGIL_ERR_OPEN on any envelope-decode or authentication failure; no
 *     plaintext is ever written in this case.
 */
int32_t sigil_open(const uint8_t *master_key, /* 32 bytes */
                   const uint8_t *envelope,
                   size_t         envelope_len,
                   SigilBuffer   *out);

/*
 * Release a SigilBuffer previously produced by sigil_seal or sigil_open.
 *
 * No-op on the canonical empty buffer (data == NULL or len == 0). Each non-empty
 * buffer must be freed exactly once. Passing a buffer not produced by this
 * library, or freeing twice, is undefined behaviour. The caller still owns the
 * SigilBuffer value itself; this reclaims only the heap slice it points at.
 */
void sigil_buffer_free(SigilBuffer buf);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SIGIL_H */
