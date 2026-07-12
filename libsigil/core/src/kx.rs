//! Classical X25519 Diffie-Hellman key agreement — the classical KEX half of
//! the hybrid X25519&ML-KEM-768 suite.
//!
//! STATUS: pre-audit. This module performs **real** X25519 (Curve25519
//! Montgomery-ladder) scalar multiplication with the vetted RustCrypto
//! [`x25519_dalek`] crate, but it has **not** been audited and is not yet wired
//! into a complete key-exchange, enrollment, or key-management flow — treat it
//! as a building block, not a finished secure system.
//!
//! ## What this module does
//!
//! Given a caller-supplied 32-byte secret scalar, [`x25519_public_key`] derives
//! the 32-byte X25519 public key (the scalar times the curve base point), and
//! [`x25519_shared_secret`] performs the Diffie-Hellman agreement (the caller's
//! scalar times a peer's public key) to produce the 32-byte raw shared secret.
//! The raw-bytes API (fixed-size arrays in, fixed-size arrays out) is
//! deliberately FFI-friendly so it can be exposed across the `sigil-ffi` C-ABI
//! later. The scalar is clamped internally by the [`x25519_dalek`] crate per
//! RFC 7748, so the caller passes raw 32 bytes.
//!
//! ## Classical only — the PQ half is future
//!
//! [`crate::AlgorithmSuite::HybridPq`] (suite `0x12`, the current suite) names a
//! **hybrid** key exchange: classical X25519 **and** post-quantum ML-KEM-768.
//! Only the **classical X25519** half is implemented here. The **ML-KEM-768**
//! KEM half is reserved/future and **not** implemented — so the shared secret
//! produced by this module is **not** post-quantum and provides no protection
//! against a cryptographically-relevant quantum computer. A complete hybrid
//! handshake will run both key exchanges and combine their outputs.
//!
//! ## The raw shared secret is NOT a key
//!
//! [`x25519_shared_secret`] returns the **raw** X25519 output. It is a group
//! element, not uniformly random, and MUST NOT be used directly as an
//! encryption key. Callers MUST run it through a KDF (e.g. HKDF-SHA256, see
//! [`crate::derive_master_key`]'s neighbour [`mod@aead`]) before use; and in the
//! hybrid suite they MUST combine it with the ML-KEM-768 shared secret (inside
//! the KDF) so that breaking either scheme alone does not compromise the session
//! key.
//!
//! ## The secret scalar is the caller's responsibility
//!
//! `sigil-core` is `no_std` and compiles to `wasm32-unknown-unknown`, where no
//! system RNG is available, so this module **never generates randomness** — in
//! particular it does **not** generate keys. The caller supplies the 32-byte
//! secret scalar, exactly as the caller supplies the Argon2id salt, the AEAD
//! nonce, and the Ed25519 seed elsewhere in the crate. The caller MUST generate
//! the scalar from a cryptographically secure source, keep it secret, and
//! safeguard it; whoever holds the scalar can recompute every shared secret it
//! agreed.
//!
//! ## Pre-audit caveats
//!
//! - There is no zeroization of the secret scalar or of the shared secret beyond
//!   what the dependencies do internally (the `zeroize` feature is intentionally
//!   off to keep `getrandom` and extra code out of the wasm build).
//! - A **non-contributory** exchange — a peer public key of small order, whose
//!   agreement yields the all-zero shared secret (RFC 7748 §6.1) — is rejected as
//!   [`KxError::NonContributory`] rather than returned. This is the conservative
//!   choice; it prevents a peer from forcing a known, attacker-chosen shared
//!   secret.
//! - This is unaudited and not wired into any product key-exchange flow.

use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};

/// Length, in bytes, of the X25519 secret scalar the caller supplies.
pub const X25519_SECRET_KEY_LEN: usize = 32;
/// Length, in bytes, of an X25519 public key.
pub const X25519_PUBLIC_KEY_LEN: usize = 32;
/// Length, in bytes, of an X25519 raw shared secret.
pub const X25519_SHARED_SECRET_LEN: usize = 32;

/// Errors returned by the key-agreement path of this module.
///
/// Public-key derivation cannot fail for a well-formed fixed-size scalar, so it
/// returns a plain array rather than a `Result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KxError {
    /// The Diffie-Hellman agreement produced the all-zero shared secret, which
    /// happens when the peer's public key is a low-order point. Such an exchange
    /// is **non-contributory** (RFC 7748 §6.1): the shared secret does not depend
    /// on our secret scalar and would be known to the peer, so it is rejected.
    NonContributory,
}

/// Derive the 32-byte X25519 public key from the caller-supplied 32-byte secret
/// `secret` scalar.
///
/// This is the scalar multiplied by the Curve25519 base point
/// ([`x25519_dalek::X25519_BASEPOINT_BYTES`]). It is RNG-free and deterministic:
/// the same scalar always yields the same public key. The scalar is clamped
/// internally per RFC 7748. The scalar is the caller's secret (see the
/// module-level docs); this function never generates it.
#[must_use]
pub fn x25519_public_key(secret: &[u8; X25519_SECRET_KEY_LEN]) -> [u8; X25519_PUBLIC_KEY_LEN] {
    x25519(*secret, X25519_BASEPOINT_BYTES)
}

/// Perform the X25519 Diffie-Hellman agreement: the caller-supplied 32-byte
/// secret `secret` scalar applied to the peer's 32-byte `their_public` key,
/// yielding the 32-byte **raw** shared secret.
///
/// The scalar is clamped internally per RFC 7748. The result is the raw group
/// element and is **not** an encryption key — run it through a KDF (and, in the
/// hybrid suite, combine it with the ML-KEM-768 secret) before use; see the
/// module-level docs.
///
/// # Errors
///
/// - [`KxError::NonContributory`] if the agreement yields the all-zero shared
///   secret, i.e. `their_public` is a low-order point (RFC 7748 §6.1). Rejecting
///   this prevents a peer from forcing a known shared secret.
pub fn x25519_shared_secret(
    secret: &[u8; X25519_SECRET_KEY_LEN],
    their_public: &[u8; X25519_PUBLIC_KEY_LEN],
) -> Result<[u8; X25519_SHARED_SECRET_LEN], KxError> {
    let shared = x25519(*secret, *their_public);
    // RFC 7748 §6.1 contributory-behaviour / low-order-point check: an all-zero
    // output means `their_public` had small order and the agreement did not
    // depend on our scalar. Reject it rather than hand back a known secret.
    if shared == [0u8; X25519_SHARED_SECRET_LEN] {
        return Err(KxError::NonContributory);
    }
    Ok(shared)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "expected 64 hex chars");
        let mut out = [0u8; 32];
        let bytes = s.as_bytes();
        for (i, chunk) in bytes.chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16).expect("hex digit") as u8;
            let lo = (chunk[1] as char).to_digit(16).expect("hex digit") as u8;
            out[i] = (hi << 4) | lo;
        }
        out
    }

    #[test]
    fn constants_have_expected_lengths() {
        assert_eq!(X25519_SECRET_KEY_LEN, 32);
        assert_eq!(X25519_PUBLIC_KEY_LEN, 32);
        assert_eq!(X25519_SHARED_SECRET_LEN, 32);
    }

    /// RFC 7748 §6.1 — the Diffie-Hellman known-answer vector (Alice & Bob).
    /// Matching it proves interop-correct X25519, not just internal
    /// self-consistency: both public keys derive correctly and both parties
    /// arrive at the same shared secret `K`.
    #[test]
    fn rfc7748_section_6_1_dh_known_answer_vector() {
        let alice_priv = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_pub = hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_priv = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_pub = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared_k = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        // Public keys derive from the private scalars.
        assert_eq!(x25519_public_key(&alice_priv), alice_pub, "alice pubkey");
        assert_eq!(x25519_public_key(&bob_priv), bob_pub, "bob pubkey");

        // Diffie-Hellman symmetry: both sides compute the same shared secret.
        assert_eq!(
            x25519_shared_secret(&alice_priv, &bob_pub),
            Ok(shared_k),
            "alice · bob_pub == K"
        );
        assert_eq!(
            x25519_shared_secret(&bob_priv, &alice_pub),
            Ok(shared_k),
            "bob · alice_pub == K"
        );
    }

    /// RFC 7748 §5.2 — scalar-multiplication known-answer vector 1. A raw
    /// (scalar, u-coordinate) → output check straight from the spec.
    #[test]
    fn rfc7748_section_5_2_scalarmult_vector_1() {
        let k = hex32("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        let u = hex32("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        let out = hex32("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        assert_eq!(x25519_shared_secret(&k, &u), Ok(out), "RFC 7748 §5.2 v1");
    }

    /// An all-zero peer public key is the canonical low-order point: the
    /// agreement yields the all-zero shared secret and must be rejected as
    /// non-contributory (RFC 7748 §6.1).
    #[test]
    fn all_zero_public_key_is_non_contributory() {
        // An arbitrary fixed secret scalar.
        let secret = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let zero_pub = [0u8; X25519_PUBLIC_KEY_LEN];
        assert_eq!(
            x25519_shared_secret(&secret, &zero_pub),
            Err(KxError::NonContributory)
        );
    }

    /// A second documented low-order point. This is one of the eight known
    /// Curve25519 small-order u-coordinates (order dividing 8); because the
    /// clamped scalar is a multiple of the cofactor 8, the agreement collapses to
    /// the identity (all-zero output) and must likewise be rejected.
    #[test]
    fn known_order_eight_point_is_non_contributory() {
        let secret = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let low_order = hex32("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800");
        assert_eq!(
            x25519_shared_secret(&secret, &low_order),
            Err(KxError::NonContributory)
        );
    }

    /// Determinism: the same (secret, public) pair always yields the same shared
    /// secret — this module draws no per-call randomness.
    #[test]
    fn agreement_is_deterministic() {
        let secret = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let peer = hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let a = x25519_shared_secret(&secret, &peer);
        let b = x25519_shared_secret(&secret, &peer);
        assert_eq!(a, b);
        assert!(a.is_ok());
    }
}
