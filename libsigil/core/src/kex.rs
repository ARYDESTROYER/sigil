//! Classical X25519 key agreement (RFC 7748) — the classical half of the hybrid
//! X25519 & ML-KEM-768 key-encapsulation named by suite `0x12`.
//!
//! STATUS: pre-audit. This module performs **real** X25519 Diffie-Hellman with
//! the vetted dalek [`x25519_dalek`] crate, but it has **not** been audited and
//! is not yet wired into a complete key-encapsulation, key-rotation, or
//! account/key-management flow — treat it as a building block, not a finished
//! secure system.
//!
//! ## What this module does
//!
//! Given a caller-supplied 32-byte secret scalar, [`x25519_public_key`] derives
//! the 32-byte X25519 public key (the Montgomery-u coordinate of the secret times
//! the base point), and [`x25519_shared_secret`] performs the Diffie-Hellman
//! scalar multiplication of a secret with a peer's public key. Both use the raw
//! fixed-size byte API (arrays in, arrays out) so they are FFI-friendly and can be
//! exposed across the `sigil-ffi` C-ABI later, exactly like [`crate::sign`].
//!
//! ## Classical only — the PQ half is future
//!
//! [`crate::AlgorithmSuite::HybridPq`] (suite `0x12`, the current suite) names a
//! **hybrid** KEM: classical X25519 **and** post-quantum ML-KEM-768. Only the
//! **classical X25519** half is implemented here. The **ML-KEM-768** half is
//! reserved/future and **not** implemented, and the two shared secrets are **not**
//! yet combined — so the key agreement provided by this module is **not**
//! post-quantum and offers no protection against a cryptographically-relevant
//! quantum computer. A complete hybrid KEM will encapsulate under both and combine
//! the two shared secrets with an HKDF (see `docs/crypto-spec.md`).
//!
//! ## The secret is the caller's responsibility
//!
//! `sigil-core` is `no_std` and compiles to `wasm32-unknown-unknown`, where no
//! system RNG is available, so this module **never generates randomness** — in
//! particular it does **not** generate keys. The caller supplies the 32-byte
//! secret scalar, exactly as the caller supplies the Argon2id salt, the AEAD
//! nonce, and the Ed25519 seed elsewhere in the crate. The caller MUST generate
//! the secret from a cryptographically secure source, keep it secret, and safeguard
//! it. Do **not** reuse the same 32 bytes as both an X25519 secret and an Ed25519
//! signing seed ([`crate::sig`]): they are different key types and cross-using one
//! set of bytes for both is unsafe.
//!
//! ## Contributory behaviour (READ THIS)
//!
//! X25519 accepts every 32-byte string as a public key. For a small set of
//! low-order peer public keys the Diffie-Hellman output is the **all-zero** value
//! regardless of the secret. A protocol that requires *contributory* behaviour
//! (both parties genuinely influence the shared secret) MUST reject an all-zero
//! result; [`is_contributory`] provides a constant-time check for exactly this.
//! This module returns the raw shared secret and leaves the policy to the caller,
//! mirroring RFC 7748 §6.1 ("protocols ... MAY check ...; this check ... is a MUST
//! if the ... protocol requires contributory behaviour").
//!
//! ## Pre-audit caveats
//!
//! - There is no zeroization of the secret scalar or the shared secret beyond
//!   whatever the dependencies do internally.
//! - X25519 clamps the secret scalar internally (RFC 7748 §5): the three lowest
//!   bits and the top two bits of the caller's secret are forced, so distinct raw
//!   secrets can clamp to the same scalar; do not rely on the raw bit pattern.
//! - **Public keys are not canonically encoded.** X25519 masks bit 255 of the
//!   peer u-coordinate and reduces it mod p (RFC 7748 §5), so *distinct* 32-byte
//!   strings can denote the *same* public key and yield the *same* shared secret.
//!   The raw peer-key bytes therefore MUST NOT be used as a canonical identity
//!   (e.g. hashed into a key-agreement transcript) without first normalizing them;
//!   compare/derive from the shared secret, not the raw encoding.
//! - **Argument order matters and is not type-checked.** Both
//!   [`x25519_shared_secret`] parameters are `&[u8; 32]`; transposing `secret` and
//!   `peer_public` silently returns a plausible-but-wrong 32 bytes (the function is
//!   total and never panics). The raw-bytes API is a deliberate FFI-friendliness
//!   choice that forgoes the typed-key safety of dalek's higher-level DH API.
//! - This is unaudited and is not wired into any KEM/hybrid/product flow.

use subtle::ConstantTimeEq;
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

/// Length, in bytes, of the X25519 secret scalar the caller supplies.
pub const KEX_SECRET_LEN: usize = 32;
/// Length, in bytes, of an X25519 public key.
pub const KEX_PUBLIC_KEY_LEN: usize = 32;
/// Length, in bytes, of an X25519 shared secret.
pub const KEX_SHARED_SECRET_LEN: usize = 32;

/// Derive the 32-byte X25519 public key from the caller-supplied 32-byte secret
/// scalar.
///
/// This is RNG-free and deterministic: the same secret always yields the same
/// public key. The secret is the caller's (see the module-level docs); this
/// function never generates it. X25519 clamps the scalar internally, so the
/// public key corresponds to the clamped secret.
#[must_use]
pub fn x25519_public_key(secret: &[u8; KEX_SECRET_LEN]) -> [u8; KEX_PUBLIC_KEY_LEN] {
    // The public key is the shared secret with the standard base point (u = 9).
    x25519(*secret, X25519_BASEPOINT_BYTES)
}

/// Compute the 32-byte X25519 shared secret between the caller's 32-byte secret
/// scalar and a `peer_public` key.
///
/// This is the raw Diffie-Hellman scalar multiplication: deterministic, RNG-free,
/// and total (it never panics for any 32-byte inputs). If both sides run it with
/// each other's public keys they obtain the same shared secret.
///
/// **Contributory behaviour:** for a small set of low-order `peer_public` values
/// the result is all-zero regardless of `secret`. If your protocol requires
/// contributory key agreement, check the result with [`is_contributory`] and reject
/// it when that returns `false`. See the module-level docs.
#[must_use]
pub fn x25519_shared_secret(
    secret: &[u8; KEX_SECRET_LEN],
    peer_public: &[u8; KEX_PUBLIC_KEY_LEN],
) -> [u8; KEX_SHARED_SECRET_LEN] {
    x25519(*secret, *peer_public)
}

/// Constant-time check that a shared secret produced by [`x25519_shared_secret`]
/// is *contributory*, i.e. not the all-zero value that a low-order peer public key
/// forces.
///
/// Returns `true` when the shared secret has at least one non-zero byte, and
/// `false` when it is all-zero. The comparison is constant-time in the contents of
/// `shared_secret` (it does not short-circuit on the first non-zero byte), so it
/// does not leak which bytes are zero.
///
/// A protocol that requires contributory behaviour MUST reject a shared secret for
/// which this returns `false` (RFC 7748 §6.1).
#[must_use]
pub fn is_contributory(shared_secret: &[u8; KEX_SHARED_SECRET_LEN]) -> bool {
    // `ct_eq` against the all-zero array yields `Choice(1)` iff every byte is zero;
    // contributory means NOT all-zero. Negating the `Choice` (a constant-time op)
    // before converting to `bool` keeps the whole check free of data-dependent
    // branches.
    (!shared_secret.ct_eq(&[0u8; KEX_SHARED_SECRET_LEN])).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 7748 §6.1 — the Diffie-Hellman example (Alice and Bob).
    const ALICE_SECRET: [u8; KEX_SECRET_LEN] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    const ALICE_PUBLIC: [u8; KEX_PUBLIC_KEY_LEN] = [
        0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7,
        0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
        0x4e, 0x6a,
    ];
    const BOB_SECRET: [u8; KEX_SECRET_LEN] = [
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e,
        0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88,
        0xe0, 0xeb,
    ];
    const BOB_PUBLIC: [u8; KEX_PUBLIC_KEY_LEN] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];
    const SHARED: [u8; KEX_SHARED_SECRET_LEN] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f,
        0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16,
        0x17, 0x42,
    ];

    #[test]
    fn constants_have_expected_lengths() {
        assert_eq!(KEX_SECRET_LEN, 32);
        assert_eq!(KEX_PUBLIC_KEY_LEN, 32);
        assert_eq!(KEX_SHARED_SECRET_LEN, 32);
    }

    /// RFC 7748 §6.1 known-answer vector: derive both public keys from the given
    /// secrets and compute the shared secret both directions. Matching this proves
    /// interop-correct X25519, not just internal self-consistency.
    #[test]
    fn rfc7748_section6_1_diffie_hellman_kat() {
        assert_eq!(
            x25519_public_key(&ALICE_SECRET),
            ALICE_PUBLIC,
            "Alice pubkey"
        );
        assert_eq!(x25519_public_key(&BOB_SECRET), BOB_PUBLIC, "Bob pubkey");
        assert_eq!(
            x25519_shared_secret(&ALICE_SECRET, &BOB_PUBLIC),
            SHARED,
            "Alice·Bob.pub"
        );
        assert_eq!(
            x25519_shared_secret(&BOB_SECRET, &ALICE_PUBLIC),
            SHARED,
            "Bob·Alice.pub"
        );
    }

    /// RFC 7748 §5.2 single-iteration known-answer vector (scalar · u-coordinate).
    /// This is an independent KAT for the raw scalar-multiplication path.
    #[test]
    fn rfc7748_section5_2_scalar_mult_kat() {
        let scalar: [u8; 32] = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46,
            0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44,
            0xba, 0x44, 0x9a, 0xc4,
        ];
        let u_in: [u8; 32] = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1,
            0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6,
            0xd0, 0xab, 0x1c, 0x4c,
        ];
        let expected: [u8; 32] = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d,
            0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55,
            0x77, 0xa2, 0x85, 0x52,
        ];
        assert_eq!(x25519_shared_secret(&scalar, &u_in), expected);
    }

    #[test]
    fn agreement_is_symmetric_for_derived_keys() {
        // Derive both public keys ourselves, then confirm both parties reach the
        // same shared secret — the core Diffie-Hellman property.
        let a_sec = [0x11u8; KEX_SECRET_LEN];
        let b_sec = [0x22u8; KEX_SECRET_LEN];
        let a_pub = x25519_public_key(&a_sec);
        let b_pub = x25519_public_key(&b_sec);
        let ss_a = x25519_shared_secret(&a_sec, &b_pub);
        let ss_b = x25519_shared_secret(&b_sec, &a_pub);
        assert_eq!(ss_a, ss_b);
        assert!(is_contributory(&ss_a));
    }

    #[test]
    fn different_peers_produce_different_secrets() {
        let sec = [0x33u8; KEX_SECRET_LEN];
        let peer1 = x25519_public_key(&[0x44u8; KEX_SECRET_LEN]);
        let peer2 = x25519_public_key(&[0x55u8; KEX_SECRET_LEN]);
        assert_ne!(
            x25519_shared_secret(&sec, &peer1),
            x25519_shared_secret(&sec, &peer2)
        );
    }

    #[test]
    fn shared_secret_is_deterministic() {
        // X25519 scalar multiplication draws no randomness: identical inputs must
        // yield byte-identical output (the property the wasm/no-RNG invariant needs).
        let a = x25519_shared_secret(&ALICE_SECRET, &BOB_PUBLIC);
        let b = x25519_shared_secret(&ALICE_SECRET, &BOB_PUBLIC);
        assert_eq!(a, b);
    }

    #[test]
    fn low_order_zero_point_is_non_contributory() {
        // u = 0 is a low-order point: the shared secret is all-zero for any secret,
        // so `is_contributory` must report false.
        let ss = x25519_shared_secret(&ALICE_SECRET, &[0u8; KEX_PUBLIC_KEY_LEN]);
        assert_eq!(ss, [0u8; KEX_SHARED_SECRET_LEN]);
        assert!(!is_contributory(&ss));
    }

    #[test]
    fn low_order_one_point_is_non_contributory() {
        // u = 1 is also a low-order point that forces an all-zero shared secret.
        let mut u_one = [0u8; KEX_PUBLIC_KEY_LEN];
        u_one[0] = 1;
        let ss = x25519_shared_secret(&BOB_SECRET, &u_one);
        assert_eq!(ss, [0u8; KEX_SHARED_SECRET_LEN]);
        assert!(!is_contributory(&ss));
    }

    #[test]
    fn is_contributory_detects_all_zero_and_non_zero() {
        assert!(!is_contributory(&[0u8; KEX_SHARED_SECRET_LEN]));
        // A single non-zero byte anywhere makes it contributory.
        let mut one = [0u8; KEX_SHARED_SECRET_LEN];
        one[KEX_SHARED_SECRET_LEN - 1] = 0x01;
        assert!(is_contributory(&one));
        assert!(is_contributory(&SHARED));
    }

    #[test]
    fn non_canonical_public_key_encoding_agrees() {
        // X25519 masks bit 255 of the peer u-coordinate, so a peer key with the
        // high bit set denotes the same point and yields the same shared secret.
        // This documents that raw peer-key bytes are NOT a canonical identity.
        let mut noncanonical = BOB_PUBLIC;
        noncanonical[KEX_PUBLIC_KEY_LEN - 1] |= 0x80;
        assert_ne!(noncanonical, BOB_PUBLIC); // genuinely different bytes
        assert_eq!(
            x25519_shared_secret(&ALICE_SECRET, &noncanonical),
            x25519_shared_secret(&ALICE_SECRET, &BOB_PUBLIC),
        );
    }

    #[test]
    fn clamping_equivalence_is_locked() {
        // X25519 clamps the secret (clears the low 3 bits of byte 0 and bit 7 of
        // byte 31, sets bit 6 of byte 31). A secret differing only in those forced
        // bits must derive the SAME public key and SAME shared secret — locking the
        // documented clamping contract against a future refactor/dep change.
        let mut variant = ALICE_SECRET;
        variant[0] ^= 0x07; // the three clamped low bits of byte 0
        variant[KEX_SECRET_LEN - 1] ^= 0xC0; // bits 6 and 7 of byte 31
        assert_ne!(variant, ALICE_SECRET); // genuinely different raw bytes
        assert_eq!(
            x25519_public_key(&variant),
            x25519_public_key(&ALICE_SECRET)
        );
        assert_eq!(
            x25519_shared_secret(&variant, &BOB_PUBLIC),
            x25519_shared_secret(&ALICE_SECRET, &BOB_PUBLIC),
        );
    }

    #[test]
    fn non_trivial_low_order_point_is_non_contributory() {
        // A non-trivial low-order (order-8) peer point from the standard
        // Curve25519 low-order set also forces an all-zero shared secret — the
        // adversarial case is_contributory exists to catch.
        let order8: [u8; KEX_PUBLIC_KEY_LEN] = [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ];
        let ss = x25519_shared_secret(&ALICE_SECRET, &order8);
        assert_eq!(ss, [0u8; KEX_SHARED_SECRET_LEN]);
        assert!(!is_contributory(&ss));
    }
}
