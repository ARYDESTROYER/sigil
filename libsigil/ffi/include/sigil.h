/*
 * sigil.h — C-ABI surface for libsigil.
 *
 * STATUS: pre-audit, UNAUDITED building block. This header declares a thin
 * C-ABI over sigil-core: the symmetric AEAD seal/open layer (XChaCha20-Poly1305
 * + HKDF-SHA256), plus classical-only Ed25519 signatures and X25519 key
 * agreement. The underlying cryptography is real (vetted RustCrypto crates) but
 * has NOT been audited. ML-DSA-65 is NOT implemented; ML-KEM-768 now exists in
 * the core but is NOT exposed over this ABI and is not combined with X25519 —
 * so nothing reachable through this header is post-quantum — and none of it is
 * wired into a complete account / key-management / key-rotation flow. Treat these functions
 * as building blocks, not a finished secure system. All seeds/secrets are
 * caller-supplied — this library generates no randomness. Do not store real
 * secrets.
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

/* ---- Status codes (returned as int32_t by the functions below) ---- */

/* Success: the operation completed and the output (*out / out array) was written. */
#define SIGIL_OK 0
/* A required pointer argument was null (or a non-zero length was paired with a
 * null pointer where that is not allowed). No output is written. */
#define SIGIL_ERR_NULL_ARG (-1)
/* Authentication or envelope decode failed on sigil_open. No plaintext is
 * produced. Envelope-decode and authentication failures both map here so the
 * boundary never leaks plaintext or fine-grained structure. */
#define SIGIL_ERR_OPEN (-2)
/* Malformed input shape detected before the crypto step (reserved; not an
 * authentication failure). */
#define SIGIL_ERR_BAD_INPUT (-3)
/* Ed25519 verification failed on sigil_ed25519_verify: bad public key, bad
 * signature, or a non-matching signature — all collapse to this one code (no
 * structure leak), mirroring SIGIL_ERR_OPEN but kept distinct from it. */
#define SIGIL_ERR_VERIFY (-4)

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

/* ---- Asymmetric primitives (fixed-size, caller-provided out buffers) --------
 *
 * STATUS: pre-audit, UNAUDITED. Classical-only building blocks (Ed25519
 * signatures, X25519 key agreement); ML-DSA-65 is NOT implemented and
 * ML-KEM-768, while now a core primitive, is NOT exposed over this ABI and NOT
 * combined with X25519 — so these exports are NOT post-quantum and NOT wired
 * into any account or key-management flow.
 *
 * These take CALLER-ALLOCATED fixed-size output arrays (out_pk[32] / out_sig[64]
 * / out_ss[32]) and return an int32_t status; they NEVER heap-allocate, so there
 * is NO SigilBuffer and NOTHING to sigil_buffer_free. All seeds/secrets are
 * CALLER-SUPPLIED entropy — this layer generates no randomness. Fixed-size
 * pointer args must be non-null (msg may be NULL iff msg_len == 0); a null
 * pointer yields SIGIL_ERR_NULL_ARG and no out array is written. The out buffer
 * may safely overlap the inputs (inputs are copied internally first).
 * ------------------------------------------------------------------------- */

/*
 * Derive the Ed25519 public key from a 32-byte seed.
 * Returns SIGIL_OK, or SIGIL_ERR_NULL_ARG.
 */
int32_t sigil_ed25519_public_key(const uint8_t seed[32], uint8_t out_pk[32]);

/*
 * Ed25519-sign msg (msg_len bytes) under seed[32] -> out_sig[64]. Signing is
 * deterministic (RFC 8032). msg may be NULL iff msg_len == 0 (an empty message
 * is signed). Returns SIGIL_OK, or SIGIL_ERR_NULL_ARG.
 */
int32_t sigil_ed25519_sign(const uint8_t  seed[32],
                           const uint8_t *msg,
                           size_t         msg_len,
                           uint8_t        out_sig[64]);

/*
 * Verify sig[64] over msg (msg_len bytes) under pk[32]. msg may be NULL iff
 * msg_len == 0.
 *
 * WARNING: SIGIL_OK (0) == VALID, nonzero == INVALID — the OPPOSITE of a C bool.
 * Test `rc == SIGIL_OK`, never `if (rc)`.
 *
 * Returns SIGIL_OK (valid), SIGIL_ERR_VERIFY (bad key/signature or a
 * non-matching signature — all collapse to one code), or SIGIL_ERR_NULL_ARG.
 */
int32_t sigil_ed25519_verify(const uint8_t  pk[32],
                             const uint8_t *msg,
                             size_t         msg_len,
                             const uint8_t  sig[64]);

/*
 * Derive the X25519 public key from a 32-byte secret scalar (X25519 clamps the
 * scalar internally). Returns SIGIL_OK, or SIGIL_ERR_NULL_ARG.
 */
int32_t sigil_x25519_public_key(const uint8_t secret[32], uint8_t out_pk[32]);

/*
 * X25519 Diffie-Hellman: secret[32] x peer_pk[32] -> out_ss[32].
 *
 * The raw shared secret is NOT contributory-checked and NOT hashed here: a
 * low-order peer_pk yields an all-zero (non-contributory) secret and STILL
 * returns SIGIL_OK. Callers MUST run out_ss through a KDF and, if the protocol
 * requires contributory behaviour, reject a non-contributory result (see
 * sigil_x25519_is_contributory). Returns SIGIL_OK, or SIGIL_ERR_NULL_ARG.
 */
int32_t sigil_x25519_shared_secret(const uint8_t secret[32],
                                   const uint8_t peer_pk[32],
                                   uint8_t       out_ss[32]);

/*
 * Constant-time predicate: is a 32-byte X25519 shared secret contributory (i.e.
 * NOT all-zero)? This is a PREDICATE, not a status code.
 * Returns 1 if contributory, 0 if all-zero (non-contributory), or
 * SIGIL_ERR_NULL_ARG (-1) if shared_secret is NULL.
 */
int32_t sigil_x25519_is_contributory(const uint8_t shared_secret[32]);

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
