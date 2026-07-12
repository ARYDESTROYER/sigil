//! Hybrid digital signatures — the classical Ed25519 and the post-quantum
//! ML-DSA-65 signatures composed into one signature that a verifier accepts
//! only if **both** halves validate.
//!
//! STATUS: pre-audit. This module performs **no new low-level cryptography of
//! its own**: it *composes* the two existing signature building blocks of
//! `sigil-core` — the classical Ed25519 signature ([`mod@crate::sig`]) and the
//! post-quantum ML-DSA-65 signature ([`mod@crate::mldsa`]) — into one hybrid
//! signature. It has **not** been audited and is a **standalone** primitive: it
//! is **not** wired into the record/account/vault flow, nor into any product
//! identity flow — in particular the sigild op-log request auth still uses the
//! **classical Ed25519 signature only**. Treat it as a building block, not a
//! finished secure system.
//!
//! ## What this module does
//!
//! [`hybrid_sign`] and [`hybrid_verify`] are the two sides of the hybrid
//! signature. The signer holds a **hybrid identity** = a caller-supplied Ed25519
//! seed **and** a caller-supplied ML-DSA-65 keygen seed. It signs a message under
//! both, and [`hybrid_sign`] returns the two signatures concatenated. A verifier,
//! holding the matching `(ed25519_public_key, mldsa_public_key)` pair, accepts the
//! message **only** when the Ed25519 half **and** the ML-DSA-65 half both verify.
//! The raw-bytes API (fixed-size arrays in, fixed-size arrays out) is deliberately
//! FFI-friendly so it can be exposed across the `sigil-ffi` C-ABI later.
//!
//! ## The layout — `ed25519_sig(64) ‖ ml_dsa65_sig(3309)` = 3373 bytes
//!
//! ```text
//! hybrid_sig = Ed25519.Sign(seed_ed, m)   [64 bytes]
//!            ‖ ML-DSA-65.Sign(sk, m)       [3309 bytes]      (sk from seed_mldsa)
//!                                          = 3373 bytes total
//! ```
//!
//! The Ed25519 half occupies bytes `0..64`, the ML-DSA-65 half bytes `64..3373`.
//! Both underlying signatures are over the **same** message bytes. This is a plain
//! concatenation combiner: unlike the hybrid KEM there is no KDF, because there is
//! no secret to combine — a signature is public, and the security property comes
//! from requiring both halves to verify.
//!
//! ## The hybrid property (design intent of an unaudited primitive)
//!
//! Because [`hybrid_verify`] returns `Ok(())` only when **both** halves verify, a
//! forgery — a `(message, hybrid_sig)` pair that verifies without the signer —
//! requires forging **both** an Ed25519 signature **and** an ML-DSA-65 signature
//! over that message. Breaking one scheme alone is not enough: the classical half
//! still stands if ML-DSA-65 is broken, and the post-quantum half still stands if
//! Ed25519 is broken (e.g. by a cryptographically-relevant quantum computer). This
//! is the honest *design intent* of an **UNAUDITED** primitive, not a proven or
//! audited guarantee. Nothing here makes the system — or even this primitive —
//! "post-quantum secure" or "secure"; the word "post-quantum" describes the
//! ML-DSA-65 component algorithm.
//!
//! ## The two seeds are the caller's responsibility; signing is deterministic
//!
//! `sigil-core` is `no_std` and compiles to `wasm32-unknown-unknown`, where no
//! system RNG is available, so this module **never generates randomness** — in
//! particular it does **not** generate keys. The caller supplies both the 32-byte
//! Ed25519 seed and the 32-byte ML-DSA-65 keygen seed (`xi`), exactly as the caller
//! supplies the Argon2id salt, the AEAD nonce, the X25519 scalar, and the ML-KEM
//! seed/coin elsewhere in the crate (see
//! [ADR 0007](../../../docs/decisions/0007-caller-supplied-entropy-in-core.md)).
//! Both component signatures are **deterministic** — Ed25519 per RFC 8032, and
//! ML-DSA-65 in its FIPS 204 deterministic variant (`rnd = 0`) — so the hybrid
//! signature is a pure function of `(seed_ed, seed_mldsa, message)`: no
//! per-signature entropy is drawn, and signing twice yields byte-identical output.
//! The caller MUST draw both seeds from a cryptographically secure source and
//! safeguard them; whoever holds a seed can forge that half.
//!
//! ## Pre-audit caveats
//!
//! - [`hybrid_sign`] recomputes the ML-DSA-65 key pair from `mldsa_keygen_seed` on
//!   every call ([`ml_dsa65_keygen`]) to obtain the secret key it signs with. This
//!   is deterministic and keeps the API a clean two-seeds *hybrid identity*, but it
//!   is not free — a caller that signs often can derive and cache the 4032-byte
//!   ML-DSA-65 secret key once and call [`ml_dsa65_sign`] directly, then assemble
//!   the two halves itself. The seed-in API is the model this module offers.
//! - There is no zeroization of the seeds, the derived ML-DSA-65 secret key, or any
//!   intermediate material beyond what the dependencies do internally.
//! - This is unaudited and not wired into any product identity flow.

use crate::{
    ml_dsa65_keygen, ml_dsa65_sign, ml_dsa65_verify, sign, verify, MlDsaError, SigError,
    ML_DSA65_KEYGEN_SEED_LEN, ML_DSA65_PUBLIC_KEY_LEN, ML_DSA65_SIGNATURE_LEN, SIGNATURE_LEN,
    SIG_PUBLIC_KEY_LEN, SIG_SEED_LEN,
};

/// Length, in bytes, of a hybrid signature: the 64-byte Ed25519 half followed by
/// the 3309-byte ML-DSA-65 half.
pub const HYBRID_SIGNATURE_LEN: usize = SIGNATURE_LEN + ML_DSA65_SIGNATURE_LEN;

/// Errors returned by [`hybrid_verify`]. Each variant wraps the failure of one
/// component half, so a caller can tell **which** signature scheme rejected the
/// inputs. [`hybrid_verify`] checks the Ed25519 half first, so an input that fails
/// both halves surfaces as [`HybridSigError::Ed25519`].
///
/// [`hybrid_sign`] returns a [`HybridSigError::MlDsa`] only on the (here-
/// unreachable) ML-DSA-65 secret-key length mismatch at the eventual FFI boundary;
/// the Ed25519 signing half is infallible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HybridSigError {
    /// The classical Ed25519 half failed — see [`SigError`].
    Ed25519(SigError),
    /// The post-quantum ML-DSA-65 half failed — see [`MlDsaError`].
    MlDsa(MlDsaError),
}

impl From<SigError> for HybridSigError {
    fn from(err: SigError) -> Self {
        HybridSigError::Ed25519(err)
    }
}

impl From<MlDsaError> for HybridSigError {
    fn from(err: MlDsaError) -> Self {
        HybridSigError::MlDsa(err)
    }
}

/// Sign `message` under a hybrid identity = the caller's Ed25519 `ed25519_seed`
/// and ML-DSA-65 `mldsa_keygen_seed`, returning the two signatures concatenated:
/// `ed25519_sig(64) ‖ ml_dsa65_sig(3309)` = 3373 bytes.
///
/// This is RNG-free and deterministic (both halves are deterministic — see the
/// module-level docs), so signing the same `(ed25519_seed, mldsa_keygen_seed,
/// message)` twice yields byte-identical output. Both seeds are the caller's
/// responsibility; this function generates no key material.
///
/// The ML-DSA-65 key pair is recomputed from `mldsa_keygen_seed` on every call to
/// recover the secret key to sign with; a caller that signs often can instead cache
/// the derived secret key (see the module-level caveats).
///
/// # Errors
///
/// - [`HybridSigError::MlDsa`] if [`ml_dsa65_sign`] rejects the derived secret key.
///   For the fixed-size seed used here the derived key is always well-formed, so
///   this is unreachable in practice; it guards the eventual FFI boundary. The
///   Ed25519 half cannot fail.
pub fn hybrid_sign(
    ed25519_seed: &[u8; SIG_SEED_LEN],
    mldsa_keygen_seed: &[u8; ML_DSA65_KEYGEN_SEED_LEN],
    message: &[u8],
) -> Result<[u8; HYBRID_SIGNATURE_LEN], HybridSigError> {
    // Classical Ed25519 half — infallible for a fixed-size seed.
    let ed_sig = sign(ed25519_seed, message);

    // Post-quantum ML-DSA-65 half. Recompute the key pair from the seed to obtain
    // the secret key; we only need the secret key, so discard the public key.
    let (_mldsa_pub, mldsa_sk) = ml_dsa65_keygen(mldsa_keygen_seed);
    let mldsa_sig = ml_dsa65_sign(&mldsa_sk, message)?;

    // Concatenate: ed25519_sig (0..64) ‖ ml_dsa65_sig (64..3373).
    let mut out = [0u8; HYBRID_SIGNATURE_LEN];
    out[..SIGNATURE_LEN].copy_from_slice(&ed_sig);
    out[SIGNATURE_LEN..].copy_from_slice(&mldsa_sig);
    Ok(out)
}

/// Verify a hybrid `hybrid_signature` over `message` against the
/// `(ed25519_public_key, mldsa_public_key)` pair.
///
/// Returns `Ok(())` **only** when the Ed25519 half **and** the ML-DSA-65 half both
/// verify against their respective public keys and the message — a forgery requires
/// breaking **both** schemes (see the module-level docs). If either half fails, the
/// corresponding error is returned; the Ed25519 half is checked first.
///
/// # Errors
///
/// - [`HybridSigError::Ed25519`] if the Ed25519 half (bytes `0..64`) does not
///   verify against `ed25519_public_key` and `message` — see [`SigError`].
/// - [`HybridSigError::MlDsa`] if the Ed25519 half verified but the ML-DSA-65 half
///   (bytes `64..3373`) does not verify against `mldsa_public_key` and `message` —
///   see [`MlDsaError`].
pub fn hybrid_verify(
    ed25519_public_key: &[u8; SIG_PUBLIC_KEY_LEN],
    mldsa_public_key: &[u8; ML_DSA65_PUBLIC_KEY_LEN],
    message: &[u8],
    hybrid_signature: &[u8; HYBRID_SIGNATURE_LEN],
) -> Result<(), HybridSigError> {
    // Split the concatenation back into its two fixed-size halves.
    let mut ed_sig = [0u8; SIGNATURE_LEN];
    ed_sig.copy_from_slice(&hybrid_signature[..SIGNATURE_LEN]);
    let mut mldsa_sig = [0u8; ML_DSA65_SIGNATURE_LEN];
    mldsa_sig.copy_from_slice(&hybrid_signature[SIGNATURE_LEN..]);

    // BOTH halves must pass. The `?` maps each component error into the matching
    // `HybridSigError` arm via the `From` impls above.
    verify(ed25519_public_key, message, &ed_sig)?;
    ml_dsa65_verify(mldsa_public_key, message, &mldsa_sig)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_key_from_seed;

    // Arbitrary fixed seeds for the Ed25519 and ML-DSA-65 halves of the hybrid
    // identity (NOT a way to generate real key material).
    const ED_SEED: [u8; SIG_SEED_LEN] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10,
    ];
    const MLDSA_SEED: [u8; ML_DSA65_KEYGEN_SEED_LEN] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
        0xbe, 0xbf,
    ];
    const MSG: &[u8] = b"sigil pre-audit hybrid signature test message";

    fn flipped32(seed: &[u8; 32]) -> [u8; 32] {
        let mut s = *seed;
        s[0] ^= 0xff;
        s
    }

    /// The two component public keys for the fixed hybrid identity under test.
    fn identity_pubs() -> ([u8; SIG_PUBLIC_KEY_LEN], [u8; ML_DSA65_PUBLIC_KEY_LEN]) {
        let ed_pub = public_key_from_seed(&ED_SEED);
        let (mldsa_pub, _sk) = ml_dsa65_keygen(&MLDSA_SEED);
        (ed_pub, mldsa_pub)
    }

    #[test]
    fn constant_has_expected_length() {
        // 64 (Ed25519) + 3309 (ML-DSA-65) = 3373.
        assert_eq!(HYBRID_SIGNATURE_LEN, 3373);
        assert_eq!(HYBRID_SIGNATURE_LEN, SIGNATURE_LEN + ML_DSA65_SIGNATURE_LEN);
    }

    /// THE CAPSTONE: a full hybrid-signature round-trip. Sign under the hybrid
    /// identity `(ed_seed, mldsa_seed)`; verify against the matching public-key
    /// pair — and it validates. This proves the two halves compose into one
    /// signature a joint verifier accepts. Also pins the 3373-byte length.
    #[test]
    fn round_trip_hybrid_signature_verifies() {
        let (ed_pub, mldsa_pub) = identity_pubs();
        let sig = hybrid_sign(&ED_SEED, &MLDSA_SEED, MSG).expect("sign");
        assert_eq!(sig.len(), HYBRID_SIGNATURE_LEN);
        assert_eq!(hybrid_verify(&ed_pub, &mldsa_pub, MSG, &sig), Ok(()));
    }

    /// THE HYBRID PROPERTY (a): tampering with ONLY the Ed25519 half (bytes
    /// `0..64`) makes verification fail with a `Ed25519` error, even though the
    /// ML-DSA-65 half is untouched and still valid. A valid signature needs BOTH.
    #[test]
    fn tampered_ed25519_half_fails_even_with_valid_mldsa() {
        let (ed_pub, mldsa_pub) = identity_pubs();
        let mut sig = hybrid_sign(&ED_SEED, &MLDSA_SEED, MSG).expect("sign");
        // Flip a byte in the Ed25519 half only; the ML-DSA-65 half (64..) is intact.
        sig[0] ^= 0x01;
        assert!(matches!(
            hybrid_verify(&ed_pub, &mldsa_pub, MSG, &sig),
            Err(HybridSigError::Ed25519(_))
        ));
    }

    /// THE HYBRID PROPERTY (b): tampering with ONLY the ML-DSA-65 half (bytes
    /// `64..`) makes verification fail with a `MlDsa` error, even though the
    /// Ed25519 half is untouched and still valid. A valid signature needs BOTH.
    #[test]
    fn tampered_mldsa_half_fails_even_with_valid_ed25519() {
        let (ed_pub, mldsa_pub) = identity_pubs();
        let mut sig = hybrid_sign(&ED_SEED, &MLDSA_SEED, MSG).expect("sign");
        // Flip a byte in the ML-DSA-65 half only; the Ed25519 half (0..64) is intact.
        sig[SIGNATURE_LEN] ^= 0x01;
        assert!(matches!(
            hybrid_verify(&ed_pub, &mldsa_pub, MSG, &sig),
            Err(HybridSigError::MlDsa(_))
        ));
    }

    /// A signature does not verify against a message it was not made over. (The
    /// Ed25519 half is checked first, so a wrong message surfaces there.)
    #[test]
    fn wrong_message_fails() {
        let (ed_pub, mldsa_pub) = identity_pubs();
        let sig = hybrid_sign(&ED_SEED, &MLDSA_SEED, MSG).expect("sign");
        assert!(hybrid_verify(&ed_pub, &mldsa_pub, b"a different message", &sig).is_err());
    }

    /// A wrong Ed25519 public key (from a different seed) fails at the Ed25519 half
    /// even though the ML-DSA-65 public key is correct.
    #[test]
    fn wrong_ed25519_public_key_fails() {
        let (_ed_pub, mldsa_pub) = identity_pubs();
        let other_ed_pub = public_key_from_seed(&flipped32(&ED_SEED));
        let sig = hybrid_sign(&ED_SEED, &MLDSA_SEED, MSG).expect("sign");
        assert!(matches!(
            hybrid_verify(&other_ed_pub, &mldsa_pub, MSG, &sig),
            Err(HybridSigError::Ed25519(_))
        ));
    }

    /// A wrong ML-DSA-65 public key (from a different keygen seed) fails at the
    /// ML-DSA-65 half even though the Ed25519 public key is correct (so the Ed25519
    /// half passes first).
    #[test]
    fn wrong_mldsa_public_key_fails() {
        let (ed_pub, _mldsa_pub) = identity_pubs();
        let (other_mldsa_pub, _sk) = ml_dsa65_keygen(&flipped32(&MLDSA_SEED));
        let sig = hybrid_sign(&ED_SEED, &MLDSA_SEED, MSG).expect("sign");
        assert!(matches!(
            hybrid_verify(&ed_pub, &other_mldsa_pub, MSG, &sig),
            Err(HybridSigError::MlDsa(_))
        ));
    }

    /// Determinism: both halves are deterministic, so signing the same hybrid
    /// identity and message twice yields byte-identical 3373-byte signatures.
    #[test]
    fn signing_is_deterministic() {
        let a = hybrid_sign(&ED_SEED, &MLDSA_SEED, MSG).expect("sign a");
        let b = hybrid_sign(&ED_SEED, &MLDSA_SEED, MSG).expect("sign b");
        assert_eq!(a, b);
    }

    /// The empty message signs and verifies like any other, and still requires the
    /// exact message on the verify side.
    #[test]
    fn empty_message_round_trips() {
        let (ed_pub, mldsa_pub) = identity_pubs();
        let sig = hybrid_sign(&ED_SEED, &MLDSA_SEED, b"").expect("sign empty");
        assert_eq!(hybrid_verify(&ed_pub, &mldsa_pub, b"", &sig), Ok(()));
        assert!(hybrid_verify(&ed_pub, &mldsa_pub, b"x", &sig).is_err());
    }
}
