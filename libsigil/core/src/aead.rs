//! Real symmetric AEAD layer over the crypto-agility [`Envelope`] codec.
//!
//! STATUS: pre-audit. This is the first module in `sigil-core` that performs
//! **real** authenticated encryption, built on the vetted RustCrypto crates
//! [`chacha20poly1305`] (XChaCha20-Poly1305), [`hkdf`], and [`sha2`]. It has
//! **not** been audited and is not yet wired into a complete key-management or
//! key-rotation scheme — treat it as a building block, not a finished secure
//! system.
//!
//! ## What this layer does
//!
//! Given a 32-byte master key, a caller-supplied 24-byte nonce, some additional
//! authenticated data (AAD), and a plaintext, [`seal`] produces an [`Envelope`]
//! whose `ciphertext` and 16-byte Poly1305 `tag` fields are filled in by
//! XChaCha20-Poly1305. [`open`] reverses this, authenticating the AAD, nonce,
//! ciphertext, and tag before returning the plaintext.
//!
//! ## Key derivation
//!
//! The master key is **not** used directly as the AEAD key. A 32-byte
//! per-record key is derived with HKDF-SHA256:
//!
//! ```text
//! record_key = HKDF-SHA256(ikm = master_key, salt = none, info = INFO_PREFIX || suite_byte)
//! ```
//!
//! Binding the algorithm-suite byte into the HKDF `info` parameter ties every
//! derived key to the suite it was produced under: a record sealed under one
//! suite cannot be opened by deriving a key for a different suite, even with the
//! same master key. The suite byte itself also travels inside the envelope and
//! is authenticated transitively (it selects the key that authenticates the
//! tag), though note it is not currently part of the AEAD's AAD — see the
//! "Pre-audit caveats" below.
//!
//! ## Nonces
//!
//! Nonces are **passed in** by the caller; this module never generates
//! randomness. `sigil-core` is `no_std` and is compiled to
//! `wasm32-unknown-unknown`, where no system RNG is available, so nonce
//! generation is the caller's responsibility. XChaCha20-Poly1305's 192-bit
//! nonce is large enough to be generated randomly with a negligible collision
//! probability, but **callers MUST ensure a (key, nonce) pair is never reused**
//! — nonce reuse is catastrophic for any Poly1305-based AEAD.
//!
//! ## Pre-audit caveats
//!
//! - The suite byte binds the *key* (via HKDF `info`) but is not also fed to the
//!   AEAD as associated data. A future revision may additionally bind the full
//!   envelope header into the AAD.
//! - There is no key-rotation, no KEM integration, and no zeroization of derived
//!   key material beyond what the dependencies do internally.

use crate::{AlgorithmSuite, Envelope};
use alloc::vec::Vec;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;

/// Size of the master key, in bytes.
pub const KEY_LEN: usize = 32;
/// Size of the XChaCha20-Poly1305 nonce, in bytes (192-bit extended nonce).
pub const NONCE_LEN: usize = 24;
/// Size of the Poly1305 authentication tag, in bytes.
pub const TAG_LEN: usize = 16;

/// HKDF `info` prefix; the suite byte is appended to it so that derived keys are
/// bound to the algorithm suite that produced the record.
const INFO_PREFIX: &[u8] = b"sigil-record-v1";

/// Errors returned by [`open`] (and surfaced by [`seal`]'s envelope handling).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AeadError {
    /// The envelope's `nonce` field was not exactly [`NONCE_LEN`] bytes.
    BadNonceLength,
    /// The envelope's `tag` field was not exactly [`TAG_LEN`] bytes.
    BadTagLength,
    /// Authentication failed: the ciphertext, tag, nonce, or AAD was modified,
    /// or the wrong master key / suite was used. The plaintext is never
    /// returned in this case.
    Authentication,
    /// HKDF key derivation failed (only possible for absurd output lengths;
    /// included for completeness).
    KeyDerivation,
}

/// Derive the 32-byte per-record AEAD key from the master key, binding the
/// algorithm-suite byte into the HKDF `info` parameter.
fn derive_record_key(master_key: &[u8; KEY_LEN], suite: AlgorithmSuite) -> Result<Key, AeadError> {
    // salt = None: the master key is already a uniformly-random 32-byte secret,
    // so HKDF is used purely as a key-expansion/labelling step here.
    let hk = Hkdf::<Sha256>::new(None, master_key);

    let mut info = Vec::with_capacity(INFO_PREFIX.len() + 1);
    info.extend_from_slice(INFO_PREFIX);
    info.push(suite.as_byte());

    let mut okm = [0u8; KEY_LEN];
    hk.expand(&info, &mut okm)
        .map_err(|_| AeadError::KeyDerivation)?;

    Ok(Key::clone_from_slice(&okm))
}

/// Seal `plaintext` under `master_key` with the current algorithm suite,
/// producing an [`Envelope`].
///
/// The returned envelope carries `suite = AlgorithmSuite::CURRENT`, the
/// caller-supplied `aad` and `nonce`, the XChaCha20-Poly1305 `ciphertext`, and
/// the detached 16-byte Poly1305 `tag`. No KEM ciphertext is produced
/// (`kem_ct = None`).
///
/// The `nonce` is supplied by the caller; this function generates no
/// randomness. **The caller MUST never reuse a (key, nonce) pair** (see the
/// module-level docs).
///
/// # Panics
/// Panics only on the practically-impossible event that HKDF-SHA256 cannot
/// expand to 32 bytes; this never happens for the fixed lengths used here.
#[must_use]
pub fn seal(
    master_key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Envelope {
    let suite = AlgorithmSuite::CURRENT;
    let key = derive_record_key(master_key, suite).expect("HKDF-SHA256 expand to 32 bytes");
    let cipher = XChaCha20Poly1305::new(&key);
    let xnonce = XNonce::from_slice(nonce);

    // Encrypt in place into an owned buffer so the ciphertext and the detached
    // tag land in separate envelope fields.
    let mut buffer = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(xnonce, aad, &mut buffer)
        .expect("XChaCha20-Poly1305 in-place encryption is infallible for in-memory buffers");

    Envelope {
        suite,
        aad: aad.to_vec(),
        nonce: nonce.to_vec(),
        ciphertext: buffer,
        tag: tag.to_vec(),
        kem_ct: None,
    }
}

/// Open an [`Envelope`] produced by [`seal`], returning the authenticated
/// plaintext.
///
/// Authentication covers the ciphertext, the detached tag, the nonce, and the
/// AAD; the per-record key is additionally bound to the envelope's suite byte
/// via HKDF. Any mismatch — tampered ciphertext/tag/nonce/AAD, a wrong master
/// key, or a mismatched suite — yields [`AeadError::Authentication`] and never
/// leaks plaintext.
///
/// # Errors
/// Returns [`AeadError::BadNonceLength`] / [`AeadError::BadTagLength`] if those
/// envelope fields are the wrong size, and [`AeadError::Authentication`] if
/// verification fails.
pub fn open(master_key: &[u8; KEY_LEN], env: &Envelope) -> Result<Vec<u8>, AeadError> {
    let nonce: &[u8; NONCE_LEN] = env
        .nonce
        .as_slice()
        .try_into()
        .map_err(|_| AeadError::BadNonceLength)?;
    let tag_bytes: &[u8; TAG_LEN] = env
        .tag
        .as_slice()
        .try_into()
        .map_err(|_| AeadError::BadTagLength)?;

    let key = derive_record_key(master_key, env.suite)?;
    let cipher = XChaCha20Poly1305::new(&key);
    let xnonce = XNonce::from_slice(nonce);
    let tag = Tag::from_slice(tag_bytes);

    let mut buffer = env.ciphertext.clone();
    cipher
        .decrypt_in_place_detached(xnonce, &env.aad, &mut buffer, tag)
        .map_err(|_| AeadError::Authentication)?;

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: [u8; KEY_LEN] = [0x42; KEY_LEN];
    const NONCE: [u8; NONCE_LEN] = [0x07; NONCE_LEN];

    #[test]
    fn round_trip_recovers_plaintext() {
        let aad = b"record-id-42";
        let plaintext = b"top-secret recovery codes";
        let env = seal(&MASTER, &NONCE, aad, plaintext);

        assert_eq!(env.suite, AlgorithmSuite::CURRENT);
        assert_eq!(env.nonce, NONCE.to_vec());
        assert_eq!(env.aad, aad.to_vec());
        assert_eq!(env.tag.len(), TAG_LEN);
        // Ciphertext length matches plaintext length (detached tag).
        assert_eq!(env.ciphertext.len(), plaintext.len());
        // It is actually encrypted, not stored in the clear.
        assert_ne!(env.ciphertext.as_slice(), plaintext.as_slice());

        let recovered = open(&MASTER, &env).expect("open succeeds");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn round_trip_empty_plaintext() {
        let env = seal(&MASTER, &NONCE, b"", b"");
        assert!(env.ciphertext.is_empty());
        assert_eq!(env.tag.len(), TAG_LEN);
        assert_eq!(
            open(&MASTER, &env).expect("open succeeds"),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn round_trip_survives_envelope_codec() {
        // Seal, serialise to wire bytes, parse back, then open.
        let aad = b"aad-through-the-codec";
        let plaintext = b"plaintext that survives a full encode/decode cycle";
        let env = seal(&MASTER, &NONCE, aad, plaintext);
        let decoded = Envelope::decode(&env.encode()).expect("envelope decodes");
        assert_eq!(decoded, env);
        assert_eq!(open(&MASTER, &decoded).expect("open succeeds"), plaintext);
    }

    #[test]
    fn tamper_with_ciphertext_is_rejected() {
        let mut env = seal(&MASTER, &NONCE, b"aad", b"some plaintext here");
        env.ciphertext[0] ^= 0x01;
        assert_eq!(open(&MASTER, &env), Err(AeadError::Authentication));
    }

    #[test]
    fn tamper_with_tag_is_rejected() {
        let mut env = seal(&MASTER, &NONCE, b"aad", b"some plaintext here");
        env.tag[0] ^= 0x01;
        assert_eq!(open(&MASTER, &env), Err(AeadError::Authentication));
    }

    #[test]
    fn tamper_with_nonce_is_rejected() {
        let mut env = seal(&MASTER, &NONCE, b"aad", b"some plaintext here");
        env.nonce[0] ^= 0x01;
        assert_eq!(open(&MASTER, &env), Err(AeadError::Authentication));
    }

    #[test]
    fn aad_binding_is_enforced() {
        // Seal with one AAD, then decode the envelope and change the AAD: open
        // must fail because the AAD is authenticated by the AEAD.
        let env = seal(&MASTER, &NONCE, b"original-aad", b"plaintext");
        let mut decoded = Envelope::decode(&env.encode()).expect("decodes");
        decoded.aad = b"different-aad".to_vec();
        assert_eq!(open(&MASTER, &decoded), Err(AeadError::Authentication));
    }

    #[test]
    fn wrong_master_key_is_rejected() {
        let env = seal(&MASTER, &NONCE, b"aad", b"plaintext");
        let wrong = [0x99u8; KEY_LEN];
        assert_eq!(open(&wrong, &env), Err(AeadError::Authentication));
    }

    #[test]
    fn suite_byte_binds_the_key() {
        // The same ciphertext/tag opened against a different suite byte must
        // fail, because HKDF binds the suite into the derived key. We forge an
        // envelope that claims a different suite but carries the real ciphertext.
        let env = seal(&MASTER, &NONCE, b"aad", b"plaintext");
        assert_ne!(AlgorithmSuite::CURRENT, AlgorithmSuite::Classical);
        let forged = Envelope {
            suite: AlgorithmSuite::Classical,
            ..env
        };
        assert_eq!(open(&MASTER, &forged), Err(AeadError::Authentication));
    }

    #[test]
    fn bad_nonce_length_is_reported() {
        let mut env = seal(&MASTER, &NONCE, b"aad", b"plaintext");
        env.nonce.truncate(NONCE_LEN - 1);
        assert_eq!(open(&MASTER, &env), Err(AeadError::BadNonceLength));
    }

    #[test]
    fn bad_tag_length_is_reported() {
        let mut env = seal(&MASTER, &NONCE, b"aad", b"plaintext");
        env.tag.push(0x00);
        assert_eq!(open(&MASTER, &env), Err(AeadError::BadTagLength));
    }

    #[test]
    fn distinct_nonces_produce_distinct_ciphertexts() {
        let n1 = [0x01u8; NONCE_LEN];
        let n2 = [0x02u8; NONCE_LEN];
        let pt = b"same plaintext, different nonce";
        let c1 = seal(&MASTER, &n1, b"aad", pt).ciphertext;
        let c2 = seal(&MASTER, &n2, b"aad", pt).ciphertext;
        assert_ne!(c1, c2);
    }

    #[test]
    fn derived_keys_differ_per_suite() {
        let k_current = derive_record_key(&MASTER, AlgorithmSuite::CURRENT).unwrap();
        let k_classical = derive_record_key(&MASTER, AlgorithmSuite::Classical).unwrap();
        assert_ne!(k_current.as_slice(), k_classical.as_slice());
    }
}
