//! Post-quantum ML-DSA-65 digital signatures (FIPS 204) — the post-quantum
//! signature half of the hybrid Ed25519&ML-DSA-65 signature suite.
//!
//! STATUS: pre-audit. This module performs **real** ML-DSA-65 (the NIST FIPS 204
//! Module-Lattice Digital Signature Algorithm, security category 3) key
//! generation, signing, and verification with the RustCrypto [`ml_dsa`] crate,
//! but it has **not** been audited and is not yet wired into a complete identity,
//! enrollment, or key-management flow — treat it as a building block, not a
//! finished secure system.
//!
//! ## What this module does
//!
//! Given a caller-supplied 32-byte keygen seed (`xi`, per FIPS 204),
//! [`ml_dsa65_keygen`] derives the `(public_key, secret_key)` pair, where the
//! secret key is the standard 4032-byte FIPS 204 `skEncode` form. Given that
//! secret key and a message, [`ml_dsa65_sign`] produces a deterministic 3309-byte
//! signature; given a public key, a message, and a signature, [`ml_dsa65_verify`]
//! checks it. The raw-bytes API (fixed-size arrays in, fixed-size arrays out) is
//! deliberately FFI-friendly so it can be exposed across the `sigil-ffi` C-ABI
//! later.
//!
//! ## Post-quantum only — standalone, NOT the hybrid
//!
//! [`crate::AlgorithmSuite::HybridPq`] (suite `0x12`, the current suite) names a
//! **hybrid** signature: classical Ed25519 **and** post-quantum ML-DSA-65. Only
//! the **post-quantum ML-DSA-65** half is implemented here; the classical Ed25519
//! half lives in [`mod@crate::sig`]. The two are **not** yet combined: a signature
//! from this module stands on its own and provides no classical protection if
//! ML-DSA were broken. A complete hybrid signer will produce both signatures and a
//! verifier will require **both** to pass. The word "post-quantum" describes the
//! ML-DSA-65 algorithm family; it does **not** mean this module — let alone the
//! system — is "post-quantum secure".
//!
//! ## The keygen seed is the caller's responsibility; signing is deterministic
//!
//! `sigil-core` is `no_std` and compiles to `wasm32-unknown-unknown`, where no
//! system RNG is available, so this module **never generates randomness** — in
//! particular it does **not** generate keys. It uses the FIPS 204 *deterministic*
//! entry points: the caller supplies the 32-byte keygen seed `xi`
//! ([`ml_dsa65_keygen`] is `ML-DSA.KeyGen_internal`), exactly as the caller
//! supplies the Argon2id salt, the AEAD nonce, the X25519 scalar, the ML-KEM
//! seed/coin, and the Ed25519 seed elsewhere in the crate. Signing uses the
//! FIPS 204 *deterministic* variant (the randomizer `rnd` is fixed to zero), so a
//! signature is a pure function of `(secret_key, message)` and no per-signature
//! entropy is drawn. The caller MUST draw the keygen seed from a
//! cryptographically secure source and safeguard it (and the secret key it
//! produces); whoever holds either can forge signatures.
//!
//! ## Pre-audit caveats
//!
//! - There is no zeroization of the seed, the secret key, or derived key material
//!   beyond what the [`ml_dsa`] dependency does internally.
//! - The secret key crosses this API as the 4032-byte FIPS 204 `skEncode`
//!   (`rho ‖ K ‖ tr ‖ s1 ‖ s2 ‖ t0`). The [`ml_dsa`] crate treats the 32-byte
//!   seed as the *preferred* custody form and marks the expanded encode/decode as
//!   deprecated; we use it because our raw-bytes contract fixes the 4032-byte
//!   standard form. Decoding it (`skDecode`) is **structural** and does **not**
//!   perform FIPS 204 validation, so a *maliciously malformed* 4032-byte secret
//!   key is not gracefully rejected — it can trip an internal assertion in the
//!   dependency. Every secret key produced by [`ml_dsa65_keygen`] is well-formed,
//!   so signing one back is total and panic-free; the `BadSecretKey` arm guards
//!   only the (here-unreachable) length mismatch at the eventual FFI boundary.
//! - Public-key decode (`pkDecode`) is likewise structural; for the fixed-size
//!   1952-byte input it cannot fail, so `BadPublicKey` is unreachable in practice.
//! - Signature decode (`sigDecode`) *does* run the FIPS 204 `z`-norm and hint
//!   checks, so a structurally invalid signature is rejected as `BadSignature`.
//! - This is unaudited and not wired into any product identity flow.

use ml_dsa::{
    EncodedVerifyingKey, ExpandedSigningKey, ExpandedSigningKeyBytes, MlDsa65, Signature,
    VerifyingKey, B32,
};

/// Length, in bytes, of an ML-DSA-65 public (verifying) key.
pub const ML_DSA65_PUBLIC_KEY_LEN: usize = 1952;
/// Length, in bytes, of an ML-DSA-65 secret key (the FIPS 204 4032-byte
/// `skEncode` form).
pub const ML_DSA65_SECRET_KEY_LEN: usize = 4032;
/// Length, in bytes, of an ML-DSA-65 signature.
pub const ML_DSA65_SIGNATURE_LEN: usize = 3309;
/// Length, in bytes, of the caller-supplied keygen seed `xi`.
pub const ML_DSA65_KEYGEN_SEED_LEN: usize = 32;

/// Errors returned by this module.
///
/// Key generation cannot fail for a well-formed fixed-size seed, so it returns a
/// plain tuple rather than a `Result`. For the fixed-size array inputs used here
/// the `BadPublicKey` / `BadSecretKey` variants are unreachable in practice (the
/// byte length is always correct); they exist so the raw-bytes contract stays
/// honest at the eventual FFI boundary, where a caller could pass a wrongly-sized
/// buffer. `BadSignature` and `Verification` are reachable at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MlDsaError {
    /// The public-key bytes could not be parsed as an ML-DSA-65 verifying key.
    BadPublicKey,
    /// The secret-key bytes could not be parsed as an ML-DSA-65 secret key.
    BadSecretKey,
    /// The signature bytes were not a structurally valid ML-DSA-65 signature
    /// (e.g. `sigDecode` rejected the `z`-norm or hint encoding).
    BadSignature,
    /// The (well-formed) signature did not verify against the given public key and
    /// message — e.g. a wrong message, the wrong key, or a tampered signature.
    Verification,
}

/// Generate an ML-DSA-65 key pair deterministically from the caller-supplied
/// 32-byte keygen seed `xi` (FIPS 204 `ML-DSA.KeyGen_internal`, Algorithm 6).
///
/// Returns `(public_key, secret_key)` as raw bytes, where `secret_key` is the
/// 4032-byte FIPS 204 `skEncode` form. This is RNG-free and deterministic: the
/// same seed always yields the same pair (see the module-level docs). Whoever
/// holds the seed — or the secret key it produces — can forge signatures.
#[must_use]
pub fn ml_dsa65_keygen(
    seed: &[u8; ML_DSA65_KEYGEN_SEED_LEN],
) -> ([u8; ML_DSA65_PUBLIC_KEY_LEN], [u8; ML_DSA65_SECRET_KEY_LEN]) {
    // `from_seed` is `ML-DSA.KeyGen_internal`: deterministic, no RNG.
    let signing_key = ExpandedSigningKey::<MlDsa65>::from_seed(&B32::from(*seed));

    let mut public_key = [0u8; ML_DSA65_PUBLIC_KEY_LEN];
    public_key.copy_from_slice(&signing_key.verifying_key().encode());

    // `to_expanded` (`skEncode`) is deprecated by the crate in favour of the
    // 32-byte seed, but it is the only accessor for the standard FIPS 204
    // 4032-byte secret-key form that our raw-bytes API fixes. Its output is always
    // well-formed (it came from keygen), so re-decoding it later cannot fail.
    #[allow(deprecated)]
    let expanded_sk = signing_key.to_expanded();
    let mut secret_key = [0u8; ML_DSA65_SECRET_KEY_LEN];
    secret_key.copy_from_slice(&expanded_sk);

    (public_key, secret_key)
}

/// Produce a deterministic 3309-byte ML-DSA-65 signature over `message` using the
/// 4032-byte `secret_key` (FIPS 204 deterministic variant, empty context).
///
/// This is RNG-free and deterministic: the randomizer is fixed to zero, so signing
/// the same `(secret_key, message)` twice yields byte-identical signatures.
///
/// # Errors
///
/// - [`MlDsaError::BadSecretKey`] if `secret_key` does not parse as an ML-DSA-65
///   secret key. For the fixed-size array input here this is unreachable; see the
///   module-level caveat about `skDecode` being structural (an adversarially
///   malformed key is not gracefully rejected).
pub fn ml_dsa65_sign(
    secret_key: &[u8; ML_DSA65_SECRET_KEY_LEN],
    message: &[u8],
) -> Result<[u8; ML_DSA65_SIGNATURE_LEN], MlDsaError> {
    // Length-checked borrow into the crate's encoded-key wrapper. For a fixed
    // 4032-byte input this always succeeds; the error path guards the FFI boundary.
    let encoded: &ExpandedSigningKeyBytes<MlDsa65> = secret_key[..]
        .try_into()
        .map_err(|_| MlDsaError::BadSecretKey)?;

    // `from_expanded` (`skDecode`) is deprecated and does not validate; it is total
    // for any key produced by `ml_dsa65_keygen` (see the module-level caveats).
    #[allow(deprecated)]
    let signing_key = ExpandedSigningKey::<MlDsa65>::from_expanded(encoded);

    // Deterministic FIPS 204 signing with an empty context string. The only error
    // path is a context longer than 255 bytes, which cannot happen for the empty
    // context, so this map is unreachable; surface it rather than panic.
    let signature = signing_key
        .sign_deterministic(message, &[])
        .map_err(|_| MlDsaError::BadSecretKey)?;

    let mut out = [0u8; ML_DSA65_SIGNATURE_LEN];
    out.copy_from_slice(&signature.encode());
    Ok(out)
}

/// Verify a 3309-byte ML-DSA-65 `signature` over `message` against the 1952-byte
/// `public_key` (FIPS 204 `ML-DSA.Verify`, empty context — matching [`ml_dsa65_sign`]).
///
/// Returns `Ok(())` **only** when the signature is valid for that exact public key
/// and message.
///
/// # Errors
///
/// - [`MlDsaError::BadPublicKey`] if `public_key` does not parse. (Unreachable for
///   the fixed-size array input here — `pkDecode` is structural.)
/// - [`MlDsaError::BadSignature`] if `signature` is not a structurally valid
///   ML-DSA-65 signature (`sigDecode` / `z`-norm / hint check failed).
/// - [`MlDsaError::Verification`] if the well-formed signature does not verify —
///   e.g. a wrong message, the wrong key, or a tampered signature.
pub fn ml_dsa65_verify(
    public_key: &[u8; ML_DSA65_PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; ML_DSA65_SIGNATURE_LEN],
) -> Result<(), MlDsaError> {
    let encoded_vk: &EncodedVerifyingKey<MlDsa65> = public_key[..]
        .try_into()
        .map_err(|_| MlDsaError::BadPublicKey)?;
    // `decode` (`pkDecode`) is infallible for a correctly-sized encoding; for the
    // fixed 1952-byte input it cannot fail.
    let verifying_key = VerifyingKey::<MlDsa65>::decode(encoded_vk);

    // `Signature::try_from` runs `sigDecode` plus the FIPS 204 `z`-norm and hint
    // checks, so a structurally invalid signature is rejected here.
    let signature =
        Signature::<MlDsa65>::try_from(&signature[..]).map_err(|_| MlDsaError::BadSignature)?;

    if verifying_key.verify_with_context(message, &[], &signature) {
        Ok(())
    } else {
        Err(MlDsaError::Verification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // An arbitrary fixed keygen seed for the internal round-trip/determinism tests.
    const SEED: [u8; ML_DSA65_KEYGEN_SEED_LEN] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10,
    ];
    const MSG: &[u8] = b"sigil pre-audit ML-DSA-65 signature test message";

    fn flipped(seed: &[u8; ML_DSA65_KEYGEN_SEED_LEN]) -> [u8; ML_DSA65_KEYGEN_SEED_LEN] {
        let mut s = *seed;
        s[0] ^= 0xff;
        s
    }

    #[test]
    fn constants_have_expected_lengths() {
        // FIPS 204 ML-DSA-65 sizes, cross-checked against the `ml_dsa` crate.
        assert_eq!(ML_DSA65_PUBLIC_KEY_LEN, 1952);
        assert_eq!(ML_DSA65_SECRET_KEY_LEN, 4032);
        assert_eq!(ML_DSA65_SIGNATURE_LEN, 3309);
        assert_eq!(ML_DSA65_KEYGEN_SEED_LEN, 32);
    }

    /// Signature correctness: a signature made under a key pair verifies against
    /// that pair's public key. Also pins the returned buffers to the FIPS 204 sizes.
    #[test]
    fn round_trip_verifies() {
        let (pk, sk) = ml_dsa65_keygen(&SEED);
        assert_eq!(pk.len(), ML_DSA65_PUBLIC_KEY_LEN);
        assert_eq!(sk.len(), ML_DSA65_SECRET_KEY_LEN);

        let sig = ml_dsa65_sign(&sk, MSG).expect("sign");
        assert_eq!(sig.len(), ML_DSA65_SIGNATURE_LEN);

        assert_eq!(ml_dsa65_verify(&pk, MSG, &sig), Ok(()));
    }

    /// Key generation is deterministic in the seed: identical seeds yield
    /// byte-identical key pairs; a different seed yields a different pair.
    #[test]
    fn keygen_is_deterministic() {
        let a = ml_dsa65_keygen(&SEED);
        let b = ml_dsa65_keygen(&SEED);
        assert_eq!(a.0, b.0, "public keys identical");
        assert_eq!(a.1, b.1, "secret keys identical");

        let c = ml_dsa65_keygen(&flipped(&SEED));
        assert_ne!(a.0, c.0, "different seed -> different public key");
        assert_ne!(a.1, c.1, "different seed -> different secret key");
    }

    /// Signing is deterministic (FIPS 204 deterministic variant, `rnd = 0`):
    /// identical `(secret_key, message)` inputs yield byte-identical signatures; a
    /// different message yields a different signature.
    #[test]
    fn signing_is_deterministic() {
        let (_pk, sk) = ml_dsa65_keygen(&SEED);

        let a = ml_dsa65_sign(&sk, MSG).expect("sign a");
        let b = ml_dsa65_sign(&sk, MSG).expect("sign b");
        assert_eq!(a, b, "signatures identical for same (sk, msg)");

        let c = ml_dsa65_sign(&sk, b"a different message").expect("sign c");
        assert_ne!(a, c, "different message -> different signature");
    }

    /// A signature does not verify against a message it was not made over.
    #[test]
    fn wrong_message_fails() {
        let (pk, sk) = ml_dsa65_keygen(&SEED);
        let sig = ml_dsa65_sign(&sk, MSG).expect("sign");
        assert_eq!(
            ml_dsa65_verify(&pk, b"a different message", &sig),
            Err(MlDsaError::Verification)
        );
    }

    /// Flipping a byte of a valid signature makes it fail: either it no longer
    /// decodes (`BadSignature`) or it decodes but does not verify (`Verification`).
    #[test]
    fn tampered_signature_fails() {
        let (pk, sk) = ml_dsa65_keygen(&SEED);
        let mut sig = ml_dsa65_sign(&sk, MSG).expect("sign");
        // Flip a bit in the leading `c_tilde` region: it stays structurally
        // parseable, so verification is what rejects it.
        sig[0] ^= 0x01;
        assert!(matches!(
            ml_dsa65_verify(&pk, MSG, &sig),
            Err(MlDsaError::Verification) | Err(MlDsaError::BadSignature)
        ));
    }

    /// A public key from a different seed must not verify a signature made under
    /// the original secret key.
    #[test]
    fn wrong_key_fails() {
        let (_pk, sk) = ml_dsa65_keygen(&SEED);
        let (other_pk, _other_sk) = ml_dsa65_keygen(&flipped(&SEED));
        let sig = ml_dsa65_sign(&sk, MSG).expect("sign");
        assert_eq!(
            ml_dsa65_verify(&other_pk, MSG, &sig),
            Err(MlDsaError::Verification)
        );
    }

    /// The empty message signs and verifies like any other.
    #[test]
    fn empty_message_round_trips() {
        let (pk, sk) = ml_dsa65_keygen(&SEED);
        let sig = ml_dsa65_sign(&sk, b"").expect("sign empty");
        assert_eq!(ml_dsa65_verify(&pk, b"", &sig), Ok(()));
        // ...and does not verify against a non-empty message.
        assert_eq!(
            ml_dsa65_verify(&pk, b"x", &sig),
            Err(MlDsaError::Verification)
        );
    }

    // NOTE: no official FIPS 204 / NIST ACVP known-answer vector is embedded here.
    // The upstream `ml-dsa` crate is validated against the ACVP KATs; reproducing
    // one requires the exact (xi -> pk, sk) and deterministic (sk, M -> sig) bytes,
    // which we will not fabricate. Correctness here rests on the round-trip and
    // determinism tests above plus that upstream vetting.
}
