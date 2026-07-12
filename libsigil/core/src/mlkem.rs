//! Post-quantum ML-KEM-768 key encapsulation (FIPS 203) — the post-quantum KEM
//! half of the hybrid X25519&ML-KEM-768 suite.
//!
//! STATUS: pre-audit. This module performs **real** ML-KEM-768 (the NIST FIPS
//! 203 Module-Lattice KEM) key generation, encapsulation, and decapsulation with
//! the vetted RustCrypto [`ml_kem`] crate, but it has **not** been audited and is
//! not yet wired into a complete key-exchange, enrollment, or key-management flow
//! — treat it as a building block, not a finished secure system.
//!
//! ## What this module does
//!
//! Given a caller-supplied 64-byte keygen seed (`d‖z`, the two 32-byte FIPS 203
//! seeds concatenated), [`ml_kem768_keygen`] derives the `(encapsulation key,
//! decapsulation key)` pair. Given an encapsulation key and a caller-supplied
//! 32-byte encapsulation coin (`m`), [`ml_kem768_encapsulate`] produces a
//! ciphertext and the sender's 32-byte shared secret. Given a decapsulation key
//! and a ciphertext, [`ml_kem768_decapsulate`] recovers the receiver's 32-byte
//! shared secret. The raw-bytes API (fixed-size arrays in, fixed-size arrays out)
//! is deliberately FFI-friendly so it can be exposed across the `sigil-ffi` C-ABI
//! later.
//!
//! ## Post-quantum only — standalone, NOT the hybrid
//!
//! [`crate::AlgorithmSuite::HybridPq`] (suite `0x12`, the current suite) names a
//! **hybrid** key exchange: classical X25519 **and** post-quantum ML-KEM-768.
//! Only the **post-quantum ML-KEM-768** half is implemented here; the classical
//! X25519 half lives in [`mod@crate::kx`]. The two are **not** yet combined: this
//! module's shared secret is the raw ML-KEM output on its own, providing no
//! classical protection if ML-KEM were broken. A complete hybrid handshake will
//! run both key exchanges and combine their shared secrets. The word
//! "post-quantum" describes the ML-KEM-768 algorithm family; it does **not** mean
//! this module — let alone the system — is "post-quantum secure".
//!
//! ## The shared secret is NOT a key
//!
//! The 32-byte shared secret is the raw ML-KEM output. It MUST NOT be used
//! directly as an encryption key: callers MUST run it through the hybrid HKDF
//! combiner (together with the X25519 shared secret, so that breaking either
//! scheme alone does not compromise the session key) before use, exactly as the
//! X25519 raw secret must be — see [`mod@crate::kx`].
//!
//! ## The seed and coin are the caller's responsibility
//!
//! `sigil-core` is `no_std` and compiles to `wasm32-unknown-unknown`, where no
//! system RNG is available, so this module **never generates randomness** — in
//! particular it does **not** generate keys. It uses the FIPS 203 *deterministic*
//! (known-answer-test) entry points: the caller supplies the 64-byte keygen seed
//! (`d‖z`) and the 32-byte encapsulation coin (`m`), exactly as the caller
//! supplies the Argon2id salt, the AEAD nonce, the X25519 scalar, and the Ed25519
//! seed elsewhere in the crate. The caller MUST draw the seed and coin from a
//! cryptographically secure source; a predictable coin breaks encapsulation
//! secrecy, and whoever holds the keygen seed (or the decapsulation key it
//! produces) can recover every shared secret encapsulated to it.
//!
//! ## Pre-audit caveats
//!
//! - There is no zeroization of the seed, coin, decapsulation key, or shared
//!   secret beyond what the [`ml_kem`] dependency does internally.
//! - ML-KEM decapsulation is **total** (FIPS 203 §6.3 *implicit rejection*): a
//!   ciphertext that does not decapsulate correctly yields a deterministic
//!   *pseudo-random* shared secret rather than an error. [`ml_kem768_decapsulate`]
//!   therefore returns `Ok` for any well-formed ciphertext; a tampered ciphertext
//!   simply produces a different secret from the sender's. Its `Err` arms cover
//!   only structurally unparseable inputs.
//! - This module version's `from_bytes` does not perform the FIPS 203 input
//!   validation (the encapsulation-key modulus check / decapsulation-key hash
//!   check); it decodes structurally. Our inputs are fixed-size arrays, so the
//!   only parse that can fail is a length mismatch, which cannot occur here.
//! - This is unaudited and not wired into any product key-exchange flow.

use ml_kem::kem::Decapsulate;
use ml_kem::{
    Ciphertext, EncapsulateDeterministic, Encoded, EncodedSizeUser, KemCore, MlKem768, B32,
};

/// Length, in bytes, of an ML-KEM-768 encapsulation (public) key.
pub const ML_KEM768_ENCAPS_KEY_LEN: usize = 1184;
/// Length, in bytes, of an ML-KEM-768 decapsulation (secret) key.
pub const ML_KEM768_DECAPS_KEY_LEN: usize = 2400;
/// Length, in bytes, of an ML-KEM-768 ciphertext.
pub const ML_KEM768_CIPHERTEXT_LEN: usize = 1088;
/// Length, in bytes, of an ML-KEM-768 shared secret.
pub const ML_KEM768_SHARED_SECRET_LEN: usize = 32;
/// Length, in bytes, of the caller-supplied keygen seed: `d` (32) ‖ `z` (32).
pub const ML_KEM768_KEYGEN_SEED_LEN: usize = 64;
/// Length, in bytes, of the caller-supplied encapsulation coin `m`.
pub const ML_KEM768_ENCAPS_COIN_LEN: usize = 32;

/// The concrete ML-KEM-768 encapsulation-key type.
type Ek = <MlKem768 as KemCore>::EncapsulationKey;
/// The concrete ML-KEM-768 decapsulation-key type.
type Dk = <MlKem768 as KemCore>::DecapsulationKey;

/// Errors returned by the encapsulation / decapsulation paths of this module.
///
/// Key generation cannot fail for a well-formed fixed-size seed, so it returns a
/// plain tuple rather than a `Result`. For the fixed-size array inputs used here
/// these variants are unreachable in practice (the byte length is always
/// correct); they exist so the raw-bytes contract stays honest at the eventual
/// FFI boundary, where a caller could pass a wrongly-sized buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MlKemError {
    /// The encapsulation-key bytes could not be parsed as an ML-KEM-768
    /// encapsulation key.
    BadEncapsKey,
    /// The decapsulation-key bytes could not be parsed as an ML-KEM-768
    /// decapsulation key.
    BadDecapsKey,
    /// The ciphertext bytes could not be parsed as an ML-KEM-768 ciphertext.
    BadCiphertext,
}

/// Generate an ML-KEM-768 key pair deterministically from the caller-supplied
/// 64-byte `seed` (`d = seed[..32]`, `z = seed[32..]`, per FIPS 203).
///
/// Returns `(encapsulation_key, decapsulation_key)` as raw bytes. This is
/// RNG-free and deterministic: the same seed always yields the same pair (see the
/// module-level docs). The `d` seed drives the K-PKE key generation and `z` is
/// the implicit-rejection secret folded into the decapsulation key.
#[must_use]
pub fn ml_kem768_keygen(
    seed: &[u8; ML_KEM768_KEYGEN_SEED_LEN],
) -> (
    [u8; ML_KEM768_ENCAPS_KEY_LEN],
    [u8; ML_KEM768_DECAPS_KEY_LEN],
) {
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    d.copy_from_slice(&seed[..32]);
    z.copy_from_slice(&seed[32..]);

    // `generate_deterministic` returns the pair in (decapsulation, encapsulation)
    // order; we expose it as (encapsulation, decapsulation).
    let (dk, ek) = MlKem768::generate_deterministic(&B32::from(d), &B32::from(z));

    let encaps_key: [u8; ML_KEM768_ENCAPS_KEY_LEN] = ek.as_bytes().into();
    let decaps_key: [u8; ML_KEM768_DECAPS_KEY_LEN] = dk.as_bytes().into();
    (encaps_key, decaps_key)
}

/// Encapsulate a shared secret to the holder of `encaps_key`, deterministically
/// from the caller-supplied 32-byte `coin` (`m`, per FIPS 203).
///
/// Returns `(ciphertext, shared_secret)`. This is RNG-free and deterministic: the
/// same `(encaps_key, coin)` always yields the same ciphertext and secret. The
/// shared secret is **not** an encryption key — run it through the hybrid HKDF
/// combiner before use (see the module-level docs).
///
/// # Errors
///
/// - [`MlKemError::BadEncapsKey`] if `encaps_key` does not parse as an ML-KEM-768
///   encapsulation key. (Unreachable for the fixed-size array input here.)
pub fn ml_kem768_encapsulate(
    encaps_key: &[u8; ML_KEM768_ENCAPS_KEY_LEN],
    coin: &[u8; ML_KEM768_ENCAPS_COIN_LEN],
) -> Result<
    (
        [u8; ML_KEM768_CIPHERTEXT_LEN],
        [u8; ML_KEM768_SHARED_SECRET_LEN],
    ),
    MlKemError,
> {
    // Length-checked parse into the crate's `Encoded` wrapper. For a fixed 1184-byte
    // input this always succeeds; the error path guards the FFI boundary.
    let encoded: &Encoded<Ek> = encaps_key[..]
        .try_into()
        .map_err(|_| MlKemError::BadEncapsKey)?;
    let ek = Ek::from_bytes(encoded);

    let m = B32::from(*coin);
    // `encapsulate_deterministic` is mathematically total; its associated `Error`
    // is `()` and is never produced. Surface the (unreachable) error as a parse
    // failure rather than panic, keeping the core panic-free.
    let (ciphertext, shared_secret) = ek
        .encapsulate_deterministic(&m)
        .map_err(|()| MlKemError::BadEncapsKey)?;

    Ok((ciphertext.into(), shared_secret.into()))
}

/// Decapsulate the 32-byte shared secret from `ciphertext` using `decaps_key`.
///
/// ML-KEM decapsulation is **total** (FIPS 203 §6.3 implicit rejection): a
/// ciphertext that does not correspond to a valid encapsulation under this key
/// yields a deterministic *pseudo-random* secret, **not** an error — so a
/// tampered ciphertext returns `Ok` with a secret that differs from the sender's,
/// rather than being rejected here. The result is **not** an encryption key — run
/// it through the hybrid HKDF combiner before use (see the module-level docs).
///
/// # Errors
///
/// - [`MlKemError::BadDecapsKey`] if `decaps_key` does not parse.
/// - [`MlKemError::BadCiphertext`] if `ciphertext` does not parse.
///
/// (Both are unreachable for the fixed-size array inputs here.)
pub fn ml_kem768_decapsulate(
    decaps_key: &[u8; ML_KEM768_DECAPS_KEY_LEN],
    ciphertext: &[u8; ML_KEM768_CIPHERTEXT_LEN],
) -> Result<[u8; ML_KEM768_SHARED_SECRET_LEN], MlKemError> {
    let encoded_dk: &Encoded<Dk> = decaps_key[..]
        .try_into()
        .map_err(|_| MlKemError::BadDecapsKey)?;
    let dk = Dk::from_bytes(encoded_dk);

    let encoded_ct: &Ciphertext<MlKem768> = ciphertext[..]
        .try_into()
        .map_err(|_| MlKemError::BadCiphertext)?;

    // Decapsulation's associated `Error` is `()` and is never produced (the
    // operation is total). Surface the (unreachable) error rather than panic.
    let shared_secret = dk
        .decapsulate(encoded_ct)
        .map_err(|()| MlKemError::BadCiphertext)?;

    Ok(shared_secret.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Arbitrary fixed inputs for the internal round-trip / determinism tests.
    const SEED: [u8; ML_KEM768_KEYGEN_SEED_LEN] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
        0x3c, 0x3d, 0x3e, 0x3f,
    ];
    const COIN: [u8; ML_KEM768_ENCAPS_COIN_LEN] = [
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd,
        0xbe, 0xbf,
    ];

    fn flipped(seed: &[u8; ML_KEM768_KEYGEN_SEED_LEN]) -> [u8; ML_KEM768_KEYGEN_SEED_LEN] {
        let mut s = *seed;
        s[0] ^= 0xff;
        s
    }

    #[test]
    fn constants_have_expected_lengths() {
        assert_eq!(ML_KEM768_ENCAPS_KEY_LEN, 1184);
        assert_eq!(ML_KEM768_DECAPS_KEY_LEN, 2400);
        assert_eq!(ML_KEM768_CIPHERTEXT_LEN, 1088);
        assert_eq!(ML_KEM768_SHARED_SECRET_LEN, 32);
        assert_eq!(ML_KEM768_KEYGEN_SEED_LEN, 64);
        assert_eq!(ML_KEM768_ENCAPS_COIN_LEN, 32);
    }

    /// KEM correctness: the secret the sender encapsulates equals the secret the
    /// receiver decapsulates. Also pins the returned buffers to the FIPS 203 sizes.
    #[test]
    fn round_trip_shared_secret_matches() {
        let (ek, dk) = ml_kem768_keygen(&SEED);
        assert_eq!(ek.len(), ML_KEM768_ENCAPS_KEY_LEN);
        assert_eq!(dk.len(), ML_KEM768_DECAPS_KEY_LEN);

        let (ct, ss_sender) = ml_kem768_encapsulate(&ek, &COIN).expect("encapsulate");
        assert_eq!(ct.len(), ML_KEM768_CIPHERTEXT_LEN);
        assert_eq!(ss_sender.len(), ML_KEM768_SHARED_SECRET_LEN);

        let ss_receiver = ml_kem768_decapsulate(&dk, &ct).expect("decapsulate");
        assert_eq!(ss_sender, ss_receiver, "sender and receiver agree on K");
    }

    /// Key generation is deterministic in the seed: identical seeds yield
    /// byte-identical key pairs; a different seed yields a different pair.
    #[test]
    fn keygen_is_deterministic() {
        let a = ml_kem768_keygen(&SEED);
        let b = ml_kem768_keygen(&SEED);
        assert_eq!(a.0, b.0, "encaps keys identical");
        assert_eq!(a.1, b.1, "decaps keys identical");

        let c = ml_kem768_keygen(&flipped(&SEED));
        assert_ne!(a.0, c.0, "different seed -> different encaps key");
        assert_ne!(a.1, c.1, "different seed -> different decaps key");
    }

    /// Encapsulation is deterministic in `(encaps_key, coin)`: identical inputs
    /// yield byte-identical ciphertext and secret; a different coin differs.
    #[test]
    fn encapsulate_is_deterministic() {
        let (ek, _dk) = ml_kem768_keygen(&SEED);

        let a = ml_kem768_encapsulate(&ek, &COIN).expect("encapsulate a");
        let b = ml_kem768_encapsulate(&ek, &COIN).expect("encapsulate b");
        assert_eq!(a.0, b.0, "ciphertexts identical");
        assert_eq!(a.1, b.1, "shared secrets identical");

        let mut other_coin = COIN;
        other_coin[0] ^= 0xff;
        let c = ml_kem768_encapsulate(&ek, &other_coin).expect("encapsulate c");
        assert_ne!(a.0, c.0, "different coin -> different ciphertext");
        assert_ne!(a.1, c.1, "different coin -> different shared secret");
    }

    /// FIPS 203 implicit rejection: a tampered ciphertext does NOT error — it
    /// decapsulates to a deterministic pseudo-random secret that differs from the
    /// sender's. Assert `Ok` and that it differs.
    #[test]
    fn tampered_ciphertext_is_implicitly_rejected() {
        let (ek, dk) = ml_kem768_keygen(&SEED);
        let (mut ct, ss_sender) = ml_kem768_encapsulate(&ek, &COIN).expect("encapsulate");

        ct[0] ^= 0x01; // flip one bit; the ciphertext stays structurally valid
        let ss_bad = ml_kem768_decapsulate(&dk, &ct).expect("decaps is total");
        assert_ne!(
            ss_sender, ss_bad,
            "implicit rejection yields a different pseudo-random secret"
        );
    }

    /// Decapsulating a valid ciphertext with the WRONG decapsulation key yields a
    /// secret unrelated to the sender's (again total — no error).
    #[test]
    fn wrong_decaps_key_yields_different_secret() {
        let (ek, _dk) = ml_kem768_keygen(&SEED);
        let (ct, ss_sender) = ml_kem768_encapsulate(&ek, &COIN).expect("encapsulate");

        let (_ek2, dk2) = ml_kem768_keygen(&flipped(&SEED));
        let ss_wrong = ml_kem768_decapsulate(&dk2, &ct).expect("decaps is total");
        assert_ne!(
            ss_sender, ss_wrong,
            "wrong decaps key -> different shared secret"
        );
    }

    // NOTE: no official FIPS 203 / NIST ACVP known-answer vector is embedded here.
    // The upstream `ml-kem` crate is validated against the ACVP KATs; reproducing
    // one requires the exact (d, z, m -> ek, dk, ct, K) bytes, which we will not
    // fabricate. Correctness here rests on the round-trip/determinism tests above
    // plus that upstream vetting.
}
