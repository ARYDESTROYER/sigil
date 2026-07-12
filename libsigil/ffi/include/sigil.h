/*
 * sigil.h — C-ABI surface for libsigil.
 *
 * STATUS: pre-audit, UNAUDITED building block. This header declares a thin
 * C-ABI over sigil-core's symmetric AEAD seal/open layer (XChaCha20-Poly1305 +
 * HKDF-SHA256) plus the classical Ed25519 signature primitive (derive public
 * key / sign / verify). The underlying cryptography is real (vetted RustCrypto
 * crates) but has NOT been audited, and it is NOT wired into a complete account
 * / key-management / key-rotation flow. The signatures are plain Ed25519 (RFC
 * 8032) — the post-quantum ML-DSA-65 half of the future hybrid is NOT present
 * here. Treat these functions as building blocks, not a finished secure system.
 * Do not store real secrets.
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
/* The Ed25519 signature did not verify (returned by sigil_verify). An invalid
 * public-key point, a malformed signature, and a well-formed signature that
 * does not verify all collapse to this single code. */
#define SIGIL_ERR_VERIFY (-4)

/* ---- Ed25519 signature primitive: fixed buffer sizes (bytes) ---- */

/* Length of the caller-supplied Ed25519 secret seed. */
#define SIGIL_SIG_SEED_LEN 32
/* Length of an Ed25519 public key. */
#define SIGIL_SIG_PUBLIC_KEY_LEN 32
/* Length of an Ed25519 signature. */
#define SIGIL_SIGNATURE_LEN 64

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

/* ---- Ed25519 signature primitive (classical half of the future hybrid) ----
 *
 * STATUS: pre-audit, UNAUDITED. Classical Ed25519 only (RFC 8032); the
 * post-quantum ML-DSA-65 half is future work and is NOT present here. This is a
 * raw signature primitive, not an enrollment / multi-device / key-rotation
 * system.
 *
 * Unlike sigil_seal / sigil_open, these produce FIXED-SIZE outputs into
 * caller-provided buffers, so there is NO heap SigilBuffer and nothing to free:
 * the caller owns the output buffers (public key / signature).
 */

/*
 * Derive the 32-byte Ed25519 public key from the caller-supplied 32-byte secret
 * `seed`, writing it into `out_public_key`. Deterministic and RNG-free.
 *
 * Pointer rules: `seed` and `out_public_key` must both be non-null. `seed`
 * points at SIGIL_SIG_SEED_LEN (32) readable bytes; `out_public_key` points at
 * SIGIL_SIG_PUBLIC_KEY_LEN (32) writable bytes. Both buffers are owned by the
 * caller.
 *
 * Returns SIGIL_OK on success (out_public_key written), or SIGIL_ERR_NULL_ARG
 * if `seed` or `out_public_key` is null (out_public_key left untouched).
 */
int32_t sigil_public_key_from_seed(const uint8_t *seed,           /* 32 bytes */
                                   uint8_t       *out_public_key); /* 32 bytes */

/*
 * Produce a 64-byte Ed25519 signature over `message` using the caller-supplied
 * 32-byte secret `seed`, writing it into `out_signature`. Signing is
 * deterministic (RFC 8032), so no randomness is drawn.
 *
 * Pointer rules: `seed` and `out_signature` must be non-null. `seed` points at
 * SIGIL_SIG_SEED_LEN (32) readable bytes; `out_signature` points at
 * SIGIL_SIGNATURE_LEN (64) writable bytes. `message` may be NULL iff
 * message_len is 0 (an empty message is signed); otherwise it points at
 * message_len readable bytes. All buffers are owned by the caller.
 *
 * Returns SIGIL_OK on success (out_signature written), or SIGIL_ERR_NULL_ARG if
 * `seed`/`out_signature` is null or message_len != 0 with a null `message`
 * (out_signature left untouched).
 */
int32_t sigil_sign(const uint8_t *seed, /* 32 bytes */
                   const uint8_t *message,
                   size_t         message_len,
                   uint8_t       *out_signature); /* 64 bytes */

/*
 * Strictly verify a 64-byte Ed25519 `signature` over `message` against the
 * 32-byte `public_key`. Strict verification rejects non-canonical encodings and
 * small-order keys.
 *
 * Pointer rules: `public_key` and `signature` must be non-null. `public_key`
 * points at SIGIL_SIG_PUBLIC_KEY_LEN (32) readable bytes; `signature` points at
 * SIGIL_SIGNATURE_LEN (64) readable bytes. `message` may be NULL iff message_len
 * is 0; otherwise it points at message_len readable bytes.
 *
 * Returns:
 *   - SIGIL_OK if the signature is valid for this exact public key and message.
 *   - SIGIL_ERR_VERIFY if it does not verify (invalid public-key point,
 *     malformed signature, or a well-formed signature that does not verify).
 *   - SIGIL_ERR_NULL_ARG if `public_key`/`signature` is null or message_len != 0
 *     with a null `message`.
 */
int32_t sigil_verify(const uint8_t *public_key, /* 32 bytes */
                     const uint8_t *message,
                     size_t         message_len,
                     const uint8_t *signature); /* 64 bytes */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SIGIL_H */
