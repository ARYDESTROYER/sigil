/*
 * sigil.h — C-ABI surface for libsigil.
 *
 * STATUS: pre-audit, UNAUDITED building block. This header declares a thin
 * C-ABI over sigil-core's symmetric AEAD seal/open layer (XChaCha20-Poly1305 +
 * HKDF-SHA256), the classical Ed25519 signature primitive (derive public key /
 * sign / verify), and the hybrid encryption path (an X25519 + ML-KEM-768 KEM
 * combined via HKDF, then the AEAD envelope — a CUSTOM KEM-then-AEAD
 * construction, NOT RFC 9180 HPKE). The underlying cryptography is real (vetted
 * RustCrypto crates) but has NOT been audited, and it is NOT wired into a
 * complete account / key-management / key-rotation flow. The signatures are
 * plain Ed25519 (RFC 8032); "post-quantum" names only the ML-KEM-768 component
 * algorithm — the construction is unaudited and the system is NOT "post-quantum
 * secure". The ML-DSA-65 signature half of the future hybrid is NOT present
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
/* A hybrid KEM / key-agreement failure on the encapsulate / decapsulate / seal
 * path — e.g. a non-contributory (all-zero / low-order) X25519 public key
 * (RFC 7748 6.1). Returned by sigil_hybrid_encapsulate,
 * sigil_hybrid_decapsulate, and sigil_hybrid_seal; no output is written. The
 * decrypt path sigil_hybrid_open does NOT use this code — every failure there
 * collapses to SIGIL_ERR_OPEN so the boundary never leaks which stage failed. */
#define SIGIL_ERR_HYBRID (-5)

/* ---- Ed25519 signature primitive: fixed buffer sizes (bytes) ---- */

/* Length of the caller-supplied Ed25519 secret seed. */
#define SIGIL_SIG_SEED_LEN 32
/* Length of an Ed25519 public key. */
#define SIGIL_SIG_PUBLIC_KEY_LEN 32
/* Length of an Ed25519 signature. */
#define SIGIL_SIGNATURE_LEN 64

/* ---- Hybrid encryption path: fixed buffer sizes (bytes) ----
 *
 * X25519 + ML-KEM-768 KEM, then the XChaCha20-Poly1305 AEAD envelope. Custom
 * KEM-then-AEAD (NOT RFC 9180 HPKE). */

/* Length of an X25519 public key. */
#define SIGIL_X25519_PUBLIC_KEY_LEN 32
/* Length of an X25519 secret scalar. */
#define SIGIL_X25519_SECRET_KEY_LEN 32
/* Length of an ML-KEM-768 encapsulation (public) key. */
#define SIGIL_MLKEM768_ENCAPS_KEY_LEN 1184
/* Length of an ML-KEM-768 decapsulation (secret) key. */
#define SIGIL_MLKEM768_DECAPS_KEY_LEN 2400
/* Length of an ML-KEM-768 ciphertext. */
#define SIGIL_MLKEM768_CIPHERTEXT_LEN 1088
/* Length of the ML-KEM-768 keygen seed (d || z). */
#define SIGIL_MLKEM768_KEYGEN_SEED_LEN 64
/* Length of the ML-KEM-768 encapsulation coin. */
#define SIGIL_MLKEM768_ENCAPS_COIN_LEN 32
/* Length of the combined hybrid shared secret. */
#define SIGIL_HYBRID_SHARED_SECRET_LEN 32
/* Length of the AEAD (XChaCha20-Poly1305) nonce. */
#define SIGIL_AEAD_NONCE_LEN 24

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

/* ---- Hybrid encryption path (X25519 + ML-KEM-768 KEM, then AEAD) ----
 *
 * STATUS: pre-audit, UNAUDITED. Lets a native client build a hybrid identity
 * (an X25519 key pair + an ML-KEM-768 key pair) and encrypt a message TO a
 * recipient's hybrid PUBLIC key, recoverable only with the matching hybrid
 * SECRET key. This is a CUSTOM KEM-then-AEAD construction — the hybrid KEM
 * derives a fresh 32-byte secret (X25519 + ML-KEM-768 combined via HKDF-SHA256)
 * which keys the XChaCha20-Poly1305 + HKDF envelope. It is NOT RFC 9180 HPKE,
 * and the system is NOT "post-quantum secure".
 *
 * This layer draws NO randomness: the ephemeral X25519 secret, the ML-KEM
 * encapsulation coin, the ML-KEM keygen seed, and the AEAD nonce are ALL
 * caller-supplied and MUST come fresh, per call, from a CSPRNG. Reusing an
 * ephemeral secret + coin repeats the hybrid secret, and a repeated
 * (key, nonce) pair is catastrophic for the AEAD.
 *
 * Fixed-size outputs (public keys, KEM ciphertext, combined secret) go into
 * caller-provided buffers with NOTHING to free. Variable-length outputs (the
 * seal envelope, the open plaintext) come back in heap SigilBuffers that the
 * caller MUST release with sigil_buffer_free.
 */

/*
 * Derive the 32-byte X25519 public key from the caller-supplied 32-byte secret
 * scalar, writing it into out_public_key. Deterministic and RNG-free; one half
 * of a hybrid identity's public key.
 *
 * Pointer rules: `secret` and `out_public_key` must be non-null. `secret` points
 * at SIGIL_X25519_SECRET_KEY_LEN (32) readable bytes; `out_public_key` at
 * SIGIL_X25519_PUBLIC_KEY_LEN (32) writable bytes.
 *
 * Returns SIGIL_OK on success (out_public_key written), or SIGIL_ERR_NULL_ARG if
 * a pointer is null (out_public_key left untouched).
 */
int32_t sigil_x25519_public_key(const uint8_t *secret,          /* 32 bytes */
                                uint8_t       *out_public_key); /* 32 bytes */

/*
 * Generate an ML-KEM-768 key pair from the caller-supplied 64-byte seed (d || z),
 * writing the 1184-byte encapsulation (public) key into out_encaps_key and the
 * 2400-byte decapsulation (secret) key into out_decaps_key. Deterministic in the
 * seed, which the caller MUST draw fresh from a CSPRNG; the post-quantum half of
 * a hybrid identity.
 *
 * Pointer rules: all three pointers must be non-null. `seed` points at
 * SIGIL_MLKEM768_KEYGEN_SEED_LEN (64) readable bytes; out_encaps_key at
 * SIGIL_MLKEM768_ENCAPS_KEY_LEN (1184) writable bytes; out_decaps_key at
 * SIGIL_MLKEM768_DECAPS_KEY_LEN (2400) writable bytes.
 *
 * Returns SIGIL_OK on success (both key buffers written), or SIGIL_ERR_NULL_ARG
 * if any pointer is null (no buffer written).
 */
int32_t sigil_ml_kem768_keygen(const uint8_t *seed,           /* 64 bytes   */
                               uint8_t       *out_encaps_key, /* 1184 bytes */
                               uint8_t       *out_decaps_key); /* 2400 bytes */

/*
 * Hybrid-encapsulate a fresh 32-byte shared secret to a recipient holding the
 * hybrid public key (recipient_x25519_pub, recipient_mlkem_encaps_key), using a
 * caller-supplied ephemeral X25519 secret and ML-KEM-768 coin (both MUST be
 * fresh, per call, from a CSPRNG). Writes the sender's ephemeral X25519 public
 * key, the ML-KEM-768 ciphertext, and the combined 32-byte secret into the three
 * out buffers.
 *
 * Pointer rules: all pointers must be non-null. Input sizes: recipient_x25519_pub
 * 32, recipient_mlkem_encaps_key 1184, ephemeral_x25519_secret 32, mlkem_coin 32.
 * Output sizes: out_eph_x25519_pub 32, out_mlkem_ct 1088, out_combined 32.
 *
 * Returns:
 *   - SIGIL_OK on success (all three out buffers written).
 *   - SIGIL_ERR_NULL_ARG if any pointer is null (no output written).
 *   - SIGIL_ERR_HYBRID if the hybrid KEM rejects an input — notably a
 *     non-contributory (all-zero / low-order) recipient_x25519_pub (no output
 *     written).
 */
int32_t sigil_hybrid_encapsulate(const uint8_t *recipient_x25519_pub,       /* 32   */
                                 const uint8_t *recipient_mlkem_encaps_key, /* 1184 */
                                 const uint8_t *ephemeral_x25519_secret,    /* 32   */
                                 const uint8_t *mlkem_coin,                 /* 32   */
                                 uint8_t       *out_eph_x25519_pub,         /* 32   */
                                 uint8_t       *out_mlkem_ct,               /* 1088 */
                                 uint8_t       *out_combined);              /* 32   */

/*
 * Hybrid-decapsulate the combined 32-byte shared secret: the recipient uses its
 * hybrid secret key (recipient_x25519_secret, recipient_mlkem_decaps_key) with
 * the sender's ephemeral X25519 public key and the ML-KEM-768 ciphertext to
 * recover the same secret sigil_hybrid_encapsulate produced, into out_combined.
 *
 * ML-KEM-768 decapsulation is total (FIPS 203 implicit rejection): a tampered
 * ciphertext does not error here, it yields a different secret. The X25519 half
 * rejects a low-order sender_eph_x25519_pub.
 *
 * Pointer rules: all pointers must be non-null. Input sizes:
 * recipient_x25519_secret 32, recipient_mlkem_decaps_key 2400,
 * sender_eph_x25519_pub 32, mlkem_ct 1088. Output: out_combined 32.
 *
 * Returns:
 *   - SIGIL_OK on success (out_combined written).
 *   - SIGIL_ERR_NULL_ARG if any pointer is null (out_combined untouched).
 *   - SIGIL_ERR_HYBRID if the hybrid KEM rejects an input — notably a
 *     non-contributory (all-zero / low-order) sender_eph_x25519_pub.
 */
int32_t sigil_hybrid_decapsulate(const uint8_t *recipient_x25519_secret,    /* 32   */
                                 const uint8_t *recipient_mlkem_decaps_key, /* 2400 */
                                 const uint8_t *sender_eph_x25519_pub,      /* 32   */
                                 const uint8_t *mlkem_ct,                   /* 1088 */
                                 uint8_t       *out_combined);              /* 32   */

/*
 * Encrypt `plaintext` TO a recipient's hybrid public key
 * (recipient_x25519_pub, recipient_mlkem_encaps_key): establishes a fresh hybrid
 * shared secret (KEM) and seals the plaintext under it (AEAD). Writes the
 * sender's ephemeral X25519 public key and the ML-KEM-768 ciphertext into the
 * fixed-size out buffers, and the ENCODED ENVELOPE BYTES into a freshly
 * heap-allocated SigilBuffer via *out_envelope. All three outputs are required
 * to sigil_hybrid_open the record; the caller MUST release the envelope buffer
 * with sigil_buffer_free.
 *
 * Custom KEM-then-AEAD (NOT RFC 9180 HPKE). ephemeral_x25519_secret, mlkem_coin,
 * and aead_nonce are the caller's responsibility — draw the ephemeral secret and
 * coin fresh, per call, from a CSPRNG (a repeated ephemeral secret + coin
 * repeats the hybrid secret; a repeated (key, nonce) is catastrophic).
 *
 * Pointer rules: recipient_x25519_pub (32), recipient_mlkem_encaps_key (1184),
 * ephemeral_x25519_secret (32), mlkem_coin (32), aead_nonce (24),
 * out_eph_x25519_pub (32), out_mlkem_ct (1088), and out_envelope must be
 * non-null. aad / plaintext may be NULL iff aad_len / plaintext_len is 0.
 *
 * Returns:
 *   - SIGIL_OK on success (both fixed out buffers and *out_envelope written).
 *   - SIGIL_ERR_NULL_ARG if a required pointer is null (or a non-zero length is
 *     paired with a null aad/plaintext); no output written.
 *   - SIGIL_ERR_HYBRID if the hybrid KEM rejects an input — notably a
 *     non-contributory (all-zero / low-order) recipient_x25519_pub; no output
 *     written.
 */
int32_t sigil_hybrid_seal(const uint8_t *recipient_x25519_pub,       /* 32   */
                          const uint8_t *recipient_mlkem_encaps_key, /* 1184 */
                          const uint8_t *ephemeral_x25519_secret,    /* 32   */
                          const uint8_t *mlkem_coin,                 /* 32   */
                          const uint8_t *aead_nonce,                 /* 24   */
                          const uint8_t *aad,
                          size_t         aad_len,
                          const uint8_t *plaintext,
                          size_t         plaintext_len,
                          uint8_t       *out_eph_x25519_pub, /* 32   */
                          uint8_t       *out_mlkem_ct,       /* 1088 */
                          SigilBuffer   *out_envelope);

/*
 * Decrypt a record produced by sigil_hybrid_seal and addressed to this
 * recipient: recovers the hybrid shared secret from the recipient's hybrid
 * secret key (recipient_x25519_secret, recipient_mlkem_decaps_key), the sender's
 * ephemeral X25519 public key, and the ML-KEM-768 ciphertext, then opens the
 * envelope, writing the recovered plaintext into a freshly heap-allocated
 * SigilBuffer via *out_plaintext. The AAD is carried inside and authenticated by
 * the envelope, so it is not a parameter here. The caller MUST release the
 * produced buffer with sigil_buffer_free.
 *
 * Pointer rules: recipient_x25519_secret (32), recipient_mlkem_decaps_key (2400),
 * sender_eph_x25519_pub (32), mlkem_ct (1088), and out_plaintext must be
 * non-null. envelope may be NULL iff envelope_len is 0.
 *
 * Returns:
 *   - SIGIL_OK on success (*out_plaintext written; may be the empty buffer for
 *     an empty plaintext).
 *   - SIGIL_ERR_NULL_ARG if a required pointer is null (or envelope_len != 0 with
 *     a null envelope); *out_plaintext untouched.
 *   - SIGIL_ERR_OPEN on ANY failure — a non-contributory sender ephemeral key, a
 *     malformed/truncated envelope, or an authentication failure — collapse to
 *     this single code so the boundary never leaks which stage failed. No
 *     plaintext is ever written in this case.
 */
int32_t sigil_hybrid_open(const uint8_t *recipient_x25519_secret,    /* 32   */
                          const uint8_t *recipient_mlkem_decaps_key, /* 2400 */
                          const uint8_t *sender_eph_x25519_pub,      /* 32   */
                          const uint8_t *mlkem_ct,                   /* 1088 */
                          const uint8_t *envelope,
                          size_t         envelope_len,
                          SigilBuffer   *out_plaintext);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SIGIL_H */
