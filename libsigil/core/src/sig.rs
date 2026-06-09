//! Classical Ed25519 digital signatures — the classical half of the hybrid
//! Ed25519&ML-DSA-65 signature suite.
//!
//! STATUS: pre-audit. This module performs **real** Ed25519 signing and
//! verification with the vetted RustCrypto [`ed25519_dalek`] crate, but it has
//! **not** been audited and is not yet wired into a complete identity,
//! enrollment, or key-management flow — treat it as a building block, not a
//! finished secure system.
//!
//! ## What this module does
//!
//! Given a caller-supplied 32-byte secret **seed**, [`public_key_from_seed`]
//! derives the 32-byte Ed25519 public key, [`sign`] produces a 64-byte
//! deterministic signature over a message, and [`verify`] strictly checks a
//! signature against a public key and message. The raw-bytes API (fixed-size
//! arrays in, fixed-size arrays out) is deliberately FFI-friendly so it can be
//! exposed across the `sigil-ffi` C-ABI later.
//!
//! ## Classical only — the PQ half is future
//!
//! [`crate::AlgorithmSuite::HybridPq`] (suite `0x12`, the current suite) names a
//! **hybrid** signature: classical Ed25519 **and** post-quantum ML-DSA-65. Only
//! the **classical Ed25519** half is implemented here. The **ML-DSA-65** half is
//! reserved/future and **not** implemented — so the signatures produced by this
//! module are **not** post-quantum and provide no protection against a
//! cryptographically-relevant quantum computer. A complete hybrid signer will
//! sign with both schemes and a verifier will require both to pass.
//!
//! ## The seed is the caller's responsibility
//!
//! `sigil-core` is `no_std` and compiles to `wasm32-unknown-unknown`, where no
//! system RNG is available, so this module **never generates randomness** — in
//! particular it does **not** generate keys. The caller supplies the 32-byte
//! secret seed (the Ed25519 private scalar source per RFC 8032), exactly as the
//! caller supplies the Argon2id salt and the AEAD nonce elsewhere in the crate.
//! The caller MUST generate the seed from a cryptographically secure source,
//! keep it secret, and safeguard it; whoever holds the seed can forge
//! signatures.
//!
//! ## Pre-audit caveats
//!
//! - There is no zeroization of the seed or of derived key material beyond what
//!   the dependencies do internally.
//! - Ed25519 is deterministic (RFC 8032): a given `(seed, message)` always
//!   yields the same signature. This module relies on that — it derives no
//!   per-signature randomness.
//! - [`verify`] uses dalek's *strict* verification, which rejects
//!   non-canonical `R`/`s` encodings and small-order/torsion public keys. This
//!   is the conservative choice; it can reject some signatures that a lax
//!   verifier would accept, but it gives stronger non-malleability guarantees.
//! - This is unaudited and not wired into any product identity flow.

use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
// `Signer` provides `SigningKey::sign`. Both traits come from the re-exported
// `signature` crate; pulling them into scope is what enables the method calls.
use ed25519_dalek::ed25519::signature::Signer;

/// Length, in bytes, of the Ed25519 secret seed the caller supplies.
pub const SIG_SEED_LEN: usize = 32;
/// Length, in bytes, of an Ed25519 public key.
pub const SIG_PUBLIC_KEY_LEN: usize = 32;
/// Length, in bytes, of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// Errors returned by the verification path of this module.
///
/// Signing and public-key derivation cannot fail for well-formed fixed-size
/// inputs, so they return plain arrays rather than a `Result`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigError {
    /// The 32-byte public key was not a valid Ed25519 point (e.g. it does not
    /// decompress to a curve point).
    BadPublicKey,
    /// The 64-byte signature was not a structurally valid Ed25519 signature.
    BadSignature,
    /// The signature did not verify against the given public key and message.
    Verification,
}

/// Derive the 32-byte Ed25519 public key from the caller-supplied 32-byte
/// secret `seed`.
///
/// This is RNG-free and deterministic: the same seed always yields the same
/// public key. The seed is the caller's secret (see the module-level docs);
/// this function never generates it.
#[must_use]
pub fn public_key_from_seed(seed: &[u8; SIG_SEED_LEN]) -> [u8; SIG_PUBLIC_KEY_LEN] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Produce a deterministic 64-byte Ed25519 signature over `message` using the
/// caller-supplied 32-byte secret `seed`.
///
/// Ed25519 signing is deterministic (RFC 8032): signing the same
/// `(seed, message)` twice yields byte-identical signatures, so no randomness is
/// drawn here.
#[must_use]
pub fn sign(seed: &[u8; SIG_SEED_LEN], message: &[u8]) -> [u8; SIGNATURE_LEN] {
    SigningKey::from_bytes(seed).sign(message).to_bytes()
}

/// Strictly verify a 64-byte Ed25519 `signature` over `message` against the
/// 32-byte `public_key`.
///
/// Returns `Ok(())` **only** when the signature is valid for that exact public
/// key and message under dalek's strict verification (which rejects
/// non-canonical encodings and small-order keys).
///
/// # Errors
///
/// - [`SigError::BadPublicKey`] if `public_key` is not a valid Ed25519 point.
/// - [`SigError::BadSignature`] if `signature` is not structurally valid.
/// - [`SigError::Verification`] if the (well-formed) signature does not verify
///   against this public key and message — e.g. a wrong message, the wrong key,
///   or a tampered signature.
pub fn verify(
    public_key: &[u8; SIG_PUBLIC_KEY_LEN],
    message: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), SigError> {
    let verifying_key = VerifyingKey::from_bytes(public_key).map_err(|_| SigError::BadPublicKey)?;
    // `Signature::from_bytes` is infallible in ed25519 v2 (it splits the 64
    // bytes into the `R`/`s` halves); strict verification below is what actually
    // rejects non-canonical `s`, weak keys, and tampered bytes.
    let signature = Signature::from_bytes(signature);
    verifying_key
        .verify_strict(message, &signature)
        .map_err(|_| SigError::Verification)
}

#[cfg(test)]
mod tests {
    use super::*;

    // An arbitrary fixed seed for the internal round-trip/determinism tests.
    const SEED: [u8; SIG_SEED_LEN] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10,
    ];
    const MSG: &[u8] = b"sigil pre-audit signature test message";

    #[test]
    fn constants_have_expected_lengths() {
        assert_eq!(SIG_SEED_LEN, 32);
        assert_eq!(SIG_PUBLIC_KEY_LEN, 32);
        assert_eq!(SIGNATURE_LEN, 64);
    }

    #[test]
    fn round_trip_verifies() {
        let pk = public_key_from_seed(&SEED);
        let sig = sign(&SEED, MSG);
        assert_eq!(verify(&pk, MSG, &sig), Ok(()));
    }

    #[test]
    fn wrong_message_fails() {
        let pk = public_key_from_seed(&SEED);
        let sig = sign(&SEED, MSG);
        assert_eq!(
            verify(&pk, b"a different message", &sig),
            Err(SigError::Verification)
        );
    }

    #[test]
    fn wrong_public_key_fails() {
        // A public key derived from a different seed must not verify a signature
        // made under SEED.
        let other_seed = {
            let mut s = SEED;
            s[0] ^= 0xff;
            s
        };
        let other_pk = public_key_from_seed(&other_seed);
        let sig = sign(&SEED, MSG);
        // Either it is a structurally-valid-but-wrong key (Verification) — that
        // is the case for a key derived from a real seed.
        assert_eq!(verify(&other_pk, MSG, &sig), Err(SigError::Verification));
    }

    #[test]
    fn malformed_public_key_is_rejected() {
        // An Ed25519 public key is a compressed point: the 255-bit y-coordinate
        // plus a sign bit for x. The y-coordinate 2 (little-endian 0x02, rest
        // zero) is a valid field element whose curve equation has no x solution,
        // so it does not decompress to a point and must be rejected up front.
        let mut bad_pk = [0u8; SIG_PUBLIC_KEY_LEN];
        bad_pk[0] = 0x02;
        let sig = sign(&SEED, MSG);
        assert_eq!(verify(&bad_pk, MSG, &sig), Err(SigError::BadPublicKey));
    }

    #[test]
    fn flipped_signature_byte_fails() {
        let pk = public_key_from_seed(&SEED);
        let mut sig = sign(&SEED, MSG);
        // Flip a bit in the `s` half (last byte) so the signature stays
        // structurally parseable but no longer verifies.
        sig[SIGNATURE_LEN - 1] ^= 0x01;
        assert!(matches!(
            verify(&pk, MSG, &sig),
            Err(SigError::Verification) | Err(SigError::BadSignature)
        ));
    }

    #[test]
    fn all_zero_signature_fails() {
        let pk = public_key_from_seed(&SEED);
        let zero_sig = [0u8; SIGNATURE_LEN];
        assert!(verify(&pk, MSG, &zero_sig).is_err());
    }

    #[test]
    fn signing_is_deterministic() {
        // Ed25519 (RFC 8032) is deterministic: identical (seed, message) inputs
        // must yield byte-identical signatures.
        let a = sign(&SEED, MSG);
        let b = sign(&SEED, MSG);
        assert_eq!(a, b);
    }

    /// RFC 8032 §7.1, Ed25519 TEST 1 (empty message). This is an official
    /// known-answer vector; matching it proves interop-correct Ed25519, not just
    /// internal self-consistency.
    #[test]
    fn rfc8032_test1_known_answer_vector() {
        // SECRET KEY (the 32-byte seed):
        let seed: [u8; SIG_SEED_LEN] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        // PUBLIC KEY:
        let expected_pk: [u8; SIG_PUBLIC_KEY_LEN] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        // MESSAGE: (empty)
        let message: &[u8] = &[];
        // SIGNATURE:
        let expected_sig: [u8; SIGNATURE_LEN] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        assert_eq!(public_key_from_seed(&seed), expected_pk, "RFC 8032 pubkey");
        assert_eq!(sign(&seed, message), expected_sig, "RFC 8032 signature");
        assert_eq!(
            verify(&expected_pk, message, &expected_sig),
            Ok(()),
            "RFC 8032 verify"
        );
    }
}
