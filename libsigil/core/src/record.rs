//! The composed "record" API: the single call a client actually makes to seal
//! or open one encrypted record.
//!
//! STATUS: pre-audit. This module performs **no new cryptography of its own**;
//! it only *composes* the three existing building blocks of `sigil-core` —
//! Argon2id password stretching ([`crate::derive_master_key`]), the
//! XChaCha20-Poly1305 + HKDF AEAD layer ([`crate::seal`] / [`crate::open`]),
//! and the crypto-agility [`Envelope`] codec ([`Envelope::encode`] /
//! [`Envelope::decode`]) — into the end-to-end flow a caller would otherwise
//! have to wire up by hand:
//!
//! ```text
//!   password ─▶ Argon2id ─▶ master key ─▶ seal ─▶ Envelope ─▶ encode ─▶ bytes   (seal_record)
//!   bytes ─▶ decode ─▶ Envelope ─▶ open ─▶ master key ◀─ Argon2id ◀─ password    (open_record)
//! ```
//!
//! The whole stack is built on the vetted RustCrypto crates, but it has **not**
//! been audited and is **not** a complete account / key-management / key-rotation
//! system — treat it as a building block, not a finished secure system.
//!
//! ## What the caller MUST persist and provide
//!
//! - **`salt` and `params` are NOT stored in the envelope.** They are inputs to
//!   the Argon2id step, so the caller MUST store the exact same `(salt, params)`
//!   alongside the ciphertext and supply them again at open time. Re-deriving
//!   with a different salt or different parameters produces a different master
//!   key and the record will fail to open.
//! - The `nonce` is supplied by the caller and travels inside the envelope.
//!   `sigil-core` is `no_std` / `wasm32`-targetable and generates **no
//!   randomness**, so the caller MUST ensure a `(key, nonce)` pair is never
//!   reused — nonce reuse is catastrophic for any Poly1305-based AEAD.
//! - The `aad` passed to [`seal_record`] is carried inside the envelope and is
//!   authenticated (not encrypted); [`open_record`] therefore does not take it
//!   as a parameter — it is recovered from, and verified against, the envelope.
//!
//! ## Pre-audit caveats
//!
//! - No zeroization of the password, salt, derived master key, or plaintext
//!   beyond whatever the dependencies do internally.
//! - This composes building blocks only: there is no account model, no key
//!   rotation, no KEM integration, and no protection of the `(salt, params)`
//!   metadata. Those are out of scope for this layer.

use crate::{
    derive_master_key, open, seal, AeadError, Argon2Params, Envelope, EnvelopeError, KdfError,
    NONCE_LEN,
};
use alloc::vec::Vec;

/// Errors returned by [`seal_record`] and [`open_record`].
///
/// Each variant carries the underlying error from the building block that
/// failed, so callers can distinguish a bad password/parameters problem
/// ([`RecordError::Kdf`]), an authentication/decryption failure
/// ([`RecordError::Aead`]), and a malformed envelope ([`RecordError::Envelope`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordError {
    /// Argon2id key derivation failed (e.g. invalid parameters or salt).
    Kdf(KdfError),
    /// AEAD sealing/opening failed — most importantly authentication failure
    /// (wrong password, tampered ciphertext/tag/nonce/AAD, or mismatched suite).
    /// The plaintext is never returned in this case.
    Aead(AeadError),
    /// The supplied envelope bytes could not be decoded.
    Envelope(EnvelopeError),
}

impl From<KdfError> for RecordError {
    fn from(e: KdfError) -> Self {
        RecordError::Kdf(e)
    }
}

impl From<AeadError> for RecordError {
    fn from(e: AeadError) -> Self {
        RecordError::Aead(e)
    }
}

impl From<EnvelopeError> for RecordError {
    fn from(e: EnvelopeError) -> Self {
        RecordError::Envelope(e)
    }
}

/// Seal one record end to end: derive the master key from `password` and `salt`
/// via Argon2id, seal `plaintext` under the caller-supplied `nonce` and `aad`,
/// and return the **encoded** envelope bytes ready to store or transmit.
///
/// The returned bytes do **not** contain `salt` or `params`; the caller MUST
/// persist those alongside the ciphertext to be able to re-derive the master key
/// at open time (see the module-level docs).
///
/// The `nonce` is caller-supplied and this function generates no randomness.
/// **The caller MUST never reuse a `(key, nonce)` pair** (see the module-level
/// docs).
///
/// # Errors
/// Returns [`RecordError::Kdf`] if Argon2id rejects `salt` or `params`.
pub fn seal_record(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, RecordError> {
    let master_key = derive_master_key(password, salt, params)?;
    let envelope = seal(&master_key, nonce, aad, plaintext);
    Ok(envelope.encode())
}

/// Open one record end to end: decode `envelope_bytes`, re-derive the master key
/// from `password` and `salt` via Argon2id, then authenticate and decrypt,
/// returning the original plaintext.
///
/// The `salt` and `params` MUST match those used at seal time (they are not
/// stored in the envelope). The `aad` is carried inside the envelope and is
/// authenticated there, so it is **not** a parameter here.
///
/// # Errors
/// - [`RecordError::Envelope`] if `envelope_bytes` is malformed/truncated.
/// - [`RecordError::Kdf`] if Argon2id rejects `salt` or `params`.
/// - [`RecordError::Aead`] if authentication/decryption fails (wrong password,
///   tampered data, wrong salt/params, or mismatched suite). The plaintext is
///   never returned in this case.
pub fn open_record(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
    envelope_bytes: &[u8],
) -> Result<Vec<u8>, RecordError> {
    // Decode first so obviously-malformed input is rejected without paying the
    // (deliberately expensive) Argon2id cost.
    let envelope = Envelope::decode(envelope_bytes)?;
    let master_key = derive_master_key(password, salt, params)?;
    let plaintext = open(&master_key, &envelope)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fast Argon2 parameters so the tests are near-instant while still
    /// exercising the real Argon2id code path. (Argon2 requires
    /// `m_cost >= 8 * p_cost`.)
    const FAST: Argon2Params = Argon2Params {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    };

    // A salt long enough to satisfy Argon2's 8-byte minimum.
    const SALT: &[u8] = b"record-salt-0001";
    const NONCE: [u8; NONCE_LEN] = [0x5a; NONCE_LEN];
    const PASSWORD: &[u8] = b"correct horse battery staple";

    #[test]
    fn end_to_end_round_trip() {
        let aad = b"record-id-7";
        let plaintext = b"the launch codes are in the other vault";

        let sealed = seal_record(PASSWORD, SALT, FAST, &NONCE, aad, plaintext)
            .expect("seal_record succeeds");
        // The encoded bytes are not the plaintext in the clear.
        assert!(!sealed
            .windows(plaintext.len())
            .any(|w| w == plaintext.as_slice()));

        let opened = open_record(PASSWORD, SALT, FAST, &sealed).expect("open_record succeeds");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn wrong_password_returns_aead_error_without_leaking_plaintext() {
        let plaintext = b"super secret";
        let sealed =
            seal_record(PASSWORD, SALT, FAST, &NONCE, b"aad", plaintext).expect("seal succeeds");

        let result = open_record(b"wrong password", SALT, FAST, &sealed);
        assert_eq!(result, Err(RecordError::Aead(AeadError::Authentication)));
        // Belt and braces: nothing in an Err can be the plaintext.
        assert!(result.is_err());
    }

    #[test]
    fn tampered_envelope_is_rejected() {
        let plaintext = b"tamper-evident payload contents";
        let mut sealed =
            seal_record(PASSWORD, SALT, FAST, &NONCE, b"aad", plaintext).expect("seal succeeds");

        // Flip a late byte (inside the ciphertext/tag region, not the header).
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;

        let result = open_record(PASSWORD, SALT, FAST, &sealed);
        assert!(result.is_err());
        // A flipped tag/ciphertext byte still decodes structurally, so the
        // failure surfaces as an authentication error.
        assert_eq!(result, Err(RecordError::Aead(AeadError::Authentication)));
    }

    #[test]
    fn same_inputs_open_an_independently_sealed_record() {
        // Determinism of the key path: a record sealed in one call opens with a
        // fresh derivation from the same (password, salt, params) in another call.
        let plaintext = b"key-path determinism check";
        let sealed_a =
            seal_record(PASSWORD, SALT, FAST, &NONCE, b"aad", plaintext).expect("seal A succeeds");
        let sealed_b =
            seal_record(PASSWORD, SALT, FAST, &NONCE, b"aad", plaintext).expect("seal B succeeds");
        // Same inputs -> identical encoded output (deterministic key + nonce).
        assert_eq!(sealed_a, sealed_b);

        // And the bytes from one seal open under an independent re-derivation.
        let opened = open_record(PASSWORD, SALT, FAST, &sealed_a).expect("open succeeds");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let sealed = seal_record(PASSWORD, SALT, FAST, &NONCE, b"aad", b"").expect("seal succeeds");
        let opened = open_record(PASSWORD, SALT, FAST, &sealed).expect("open succeeds");
        assert!(opened.is_empty());
    }

    #[test]
    fn garbage_bytes_are_rejected_without_panic() {
        // Random garbage: should be an envelope decode error, never a panic and
        // never plaintext.
        let garbage = [0xFFu8; 12];
        let result = open_record(PASSWORD, SALT, FAST, &garbage);
        assert!(matches!(result, Err(RecordError::Envelope(_))));
    }

    #[test]
    fn truncated_envelope_is_rejected_without_panic() {
        let sealed =
            seal_record(PASSWORD, SALT, FAST, &NONCE, b"aad", b"payload").expect("seal succeeds");
        let truncated = &sealed[..sealed.len() - 4];
        let result = open_record(PASSWORD, SALT, FAST, truncated);
        // Truncation manifests as an envelope-level error (e.g. Truncated).
        assert!(matches!(result, Err(RecordError::Envelope(_))));
    }

    #[test]
    fn empty_input_is_rejected_without_panic() {
        let result = open_record(PASSWORD, SALT, FAST, &[]);
        assert!(matches!(result, Err(RecordError::Envelope(_))));
    }
}
