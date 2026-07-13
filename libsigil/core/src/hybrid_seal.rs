//! Hybrid public-key seal/open — encrypt a record TO a recipient's hybrid
//! public key by composing the hybrid KEM with the AEAD and the envelope codec.
//!
//! STATUS: pre-audit. This module performs **no new low-level cryptography of
//! its own**: it *composes* three existing building blocks of `sigil-core` into
//! the intended use of the hybrid KEM — public-key encryption to a device's
//! hybrid public key:
//!
//! ```text
//!   recipient hybrid pub ─▶ hybrid_encapsulate ─▶ (eph_pub, mlkem_ct, ss) ─▶ seal ─▶ Envelope ─▶ encode ─▶ bytes   (hybrid_seal)
//!   bytes ─▶ decode ─▶ Envelope ─▶ open ◀─ ss ◀─ hybrid_decapsulate ◀─ (eph_pub, mlkem_ct) + recipient hybrid secret   (hybrid_open)
//! ```
//!
//! The sender runs the hybrid KEM ([`mod@crate::hybrid`]) against the
//! recipient's `(x25519_pub, ml_kem768_encaps_key)` to establish a fresh 32-byte
//! hybrid shared secret, then seals the plaintext under it with the AEAD
//! ([`crate::seal`] / [`crate::open`], [`mod@crate::aead`]) inside the
//! crypto-agility [`Envelope`] ([`Envelope::encode`] / [`Envelope::decode`],
//! [`mod@crate::envelope`]). The recipient re-derives the same secret via
//! [`hybrid_decapsulate`] and opens the envelope.
//!
//! ## Caveats — read before relying on this
//!
//! - This is a **CUSTOM** hybrid public-key **authenticated** encryption scheme:
//!   a bespoke KEM-then-AEAD composition. It is **NOT** RFC 9180 HPKE and is not
//!   a standardised construction — it is our own wiring of the two building
//!   blocks.
//! - It has **not** been audited. Treat it as a crypto-level flow / primitive,
//!   not a finished secure system. It is **standalone**: this is not the
//!   product's account, key-management, or vault-storage model, and it is not yet
//!   wired into `sigild` or the CLI. Nothing here makes the system "secure",
//!   "post-quantum secure", or "audited".
//! - **Entropy is the caller's responsibility.** `sigil-core` is `no_std` and
//!   compiles to `wasm32-unknown-unknown` where no system RNG exists, so this
//!   module (like the rest of the crate — see
//!   [ADR 0007](../../../docs/decisions/0007-caller-supplied-entropy-in-core.md))
//!   generates **no randomness**: the sender supplies the ephemeral X25519
//!   secret, the ML-KEM-768 coin, and the AEAD nonce.
//! - **On nonce reuse.** In general, reusing a `(key, nonce)` pair is
//!   catastrophic for a Poly1305-based AEAD. Here the AEAD key is a **fresh
//!   per-message hybrid secret** (a fresh ephemeral X25519 secret and ML-KEM coin
//!   per call yield a fresh `combined` secret, hence a fresh derived record key),
//!   so a **fixed** `aead_nonce` is acceptable **provided the ephemeral secret and
//!   coin are genuinely fresh per message**. If the caller instead reuses the
//!   ephemeral secret **and** coin across two messages, the hybrid secret repeats
//!   and a fixed nonce then reuses `(key, nonce)` — which is catastrophic. The
//!   safe rule is: draw a fresh ephemeral secret and coin (and, ideally, a fresh
//!   nonce) per message from a CSPRNG.
//! - No zeroization of the hybrid secret or plaintext beyond what the
//!   dependencies do internally.

use crate::{
    hybrid_decapsulate, hybrid_encapsulate, open, seal, AeadError, Envelope, EnvelopeError,
    HybridError, ML_KEM768_CIPHERTEXT_LEN, ML_KEM768_DECAPS_KEY_LEN, ML_KEM768_ENCAPS_COIN_LEN,
    ML_KEM768_ENCAPS_KEY_LEN, NONCE_LEN, X25519_PUBLIC_KEY_LEN, X25519_SECRET_KEY_LEN,
};
use alloc::vec::Vec;

/// The output of [`hybrid_seal`]: the sender's ephemeral X25519 public key, the
/// ML-KEM-768 ciphertext, and the encoded envelope. All three are needed to
/// [`hybrid_open`] the record. (A named alias keeps the fn signature readable.)
pub type HybridSealed = (
    [u8; X25519_PUBLIC_KEY_LEN],
    [u8; ML_KEM768_CIPHERTEXT_LEN],
    Vec<u8>,
);

/// Errors returned by [`hybrid_seal`] and [`hybrid_open`].
///
/// Each variant carries the underlying error from the building block that
/// failed, so callers can distinguish a hybrid-KEM problem
/// ([`HybridSealError::Hybrid`] — e.g. a non-contributory recipient public key),
/// an authentication/decryption failure ([`HybridSealError::Aead`]), and a
/// malformed envelope ([`HybridSealError::Envelope`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HybridSealError {
    /// The hybrid KEM failed — encapsulation or decapsulation rejected an input
    /// (e.g. an all-zero / low-order X25519 public key, RFC 7748 §6.1).
    Hybrid(HybridError),
    /// AEAD sealing/opening failed — most importantly authentication failure
    /// (wrong recipient, tampered ciphertext/tag/nonce/AAD, or a KEM secret that
    /// did not match). The plaintext is never returned in this case.
    Aead(AeadError),
    /// The supplied envelope bytes could not be decoded.
    Envelope(EnvelopeError),
}

impl From<HybridError> for HybridSealError {
    fn from(err: HybridError) -> Self {
        HybridSealError::Hybrid(err)
    }
}

impl From<AeadError> for HybridSealError {
    fn from(err: AeadError) -> Self {
        HybridSealError::Aead(err)
    }
}

impl From<EnvelopeError> for HybridSealError {
    fn from(err: EnvelopeError) -> Self {
        HybridSealError::Envelope(err)
    }
}

/// Encrypt `plaintext` TO a recipient identified by their hybrid public key
/// (an X25519 public key + an ML-KEM-768 encapsulation key). Establishes a fresh
/// hybrid shared secret via the hybrid KEM ([`hybrid_encapsulate`]), then seals
/// the plaintext under it with the AEAD ([`seal`]).
///
/// Returns `(eph_x25519_pub, mlkem_ciphertext, envelope_bytes)`: the sender's
/// ephemeral X25519 public key, the ML-KEM-768 ciphertext, and the encoded
/// envelope — **all three** are needed by [`hybrid_open`] to recover the same
/// hybrid secret and decrypt.
///
/// The `combined` secret produced by the KEM is used directly as the 32-byte
/// AEAD master key; [`seal`] HKDF-derives the per-record key from it internally.
///
/// The `ephemeral_x25519_secret`, `mlkem_coin`, and `aead_nonce` are the
/// caller's responsibility (this function generates no randomness) — draw the
/// ephemeral secret and coin fresh per call from a CSPRNG (see the module-level
/// docs on nonce reuse).
///
/// # Errors
///
/// - [`HybridSealError::Hybrid`] if the hybrid KEM rejects an input — notably a
///   non-contributory (all-zero / low-order) `recipient_x25519_pub`
///   (RFC 7748 §6.1).
pub fn hybrid_seal(
    recipient_x25519_pub: &[u8; X25519_PUBLIC_KEY_LEN],
    recipient_mlkem_encaps_key: &[u8; ML_KEM768_ENCAPS_KEY_LEN],
    ephemeral_x25519_secret: &[u8; X25519_SECRET_KEY_LEN],
    mlkem_coin: &[u8; ML_KEM768_ENCAPS_COIN_LEN],
    aead_nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<HybridSealed, HybridSealError> {
    let (eph_pub, mlkem_ct, combined) = hybrid_encapsulate(
        recipient_x25519_pub,
        recipient_mlkem_encaps_key,
        ephemeral_x25519_secret,
        mlkem_coin,
    )?;
    // `combined` is the fresh 32-byte hybrid secret; `seal` HKDF-derives the
    // per-record key from it internally.
    let envelope = seal(&combined, aead_nonce, aad, plaintext);
    Ok((eph_pub, mlkem_ct, envelope.encode()))
}

/// Decrypt a record produced by [`hybrid_seal`] and addressed to this recipient.
/// Recovers the same hybrid shared secret via [`hybrid_decapsulate`] from the
/// sender's ephemeral X25519 public key and the ML-KEM-768 ciphertext, then
/// opens the envelope with the AEAD ([`open`]).
///
/// The `aad` is carried inside the envelope and is authenticated there, so it is
/// **not** a parameter here — it is recovered from, and verified against, the
/// envelope.
///
/// # Errors
///
/// - [`HybridSealError::Envelope`] if `envelope_bytes` is malformed/truncated.
/// - [`HybridSealError::Hybrid`] if the hybrid KEM rejects an input — notably a
///   non-contributory (all-zero / low-order) `sender_eph_x25519_pub`.
/// - [`HybridSealError::Aead`] if authentication/decryption fails (wrong
///   recipient, tampered ciphertext/tag/nonce/AAD, or a tampered ML-KEM
///   ciphertext / ephemeral public key that yields a different hybrid secret).
///   The plaintext is never returned in this case.
pub fn hybrid_open(
    recipient_x25519_secret: &[u8; X25519_SECRET_KEY_LEN],
    recipient_mlkem_decaps_key: &[u8; ML_KEM768_DECAPS_KEY_LEN],
    sender_eph_x25519_pub: &[u8; X25519_PUBLIC_KEY_LEN],
    mlkem_ct: &[u8; ML_KEM768_CIPHERTEXT_LEN],
    envelope_bytes: &[u8],
) -> Result<Vec<u8>, HybridSealError> {
    let combined = hybrid_decapsulate(
        recipient_x25519_secret,
        recipient_mlkem_decaps_key,
        sender_eph_x25519_pub,
        mlkem_ct,
    )?;
    let envelope = Envelope::decode(envelope_bytes)?;
    let plaintext = open(&combined, &envelope)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ml_kem768_keygen, x25519_public_key, KxError, ML_KEM768_DECAPS_KEY_LEN,
        ML_KEM768_ENCAPS_KEY_LEN, ML_KEM768_KEYGEN_SEED_LEN,
    };

    /// Deterministic 32-byte test array from a starting byte (an arbitrary but
    /// fixed pattern; NOT a way to generate real key material).
    fn arr32(seed: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        for (i, b) in a.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        a
    }

    /// Deterministic 64-byte test array (ML-KEM keygen seed `d ‖ z`).
    fn arr64(seed: u8) -> [u8; ML_KEM768_KEYGEN_SEED_LEN] {
        let mut a = [0u8; ML_KEM768_KEYGEN_SEED_LEN];
        for (i, b) in a.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        a
    }

    /// A recipient's hybrid key pair plus a sender's ephemeral secret, ML-KEM
    /// coin, and AEAD nonce — the fixed inputs the seal/open tests share.
    struct Setup {
        r_x_secret: [u8; X25519_SECRET_KEY_LEN],
        r_x_pub: [u8; X25519_PUBLIC_KEY_LEN],
        ek: [u8; ML_KEM768_ENCAPS_KEY_LEN],
        dk: [u8; ML_KEM768_DECAPS_KEY_LEN],
        eph_secret: [u8; X25519_SECRET_KEY_LEN],
        coin: [u8; ML_KEM768_ENCAPS_COIN_LEN],
        nonce: [u8; NONCE_LEN],
    }

    fn setup() -> Setup {
        let r_x_secret = arr32(0x11);
        let r_x_pub = x25519_public_key(&r_x_secret);
        let (ek, dk) = ml_kem768_keygen(&arr64(0x20));
        Setup {
            r_x_secret,
            r_x_pub,
            ek,
            dk,
            eph_secret: arr32(0x30),
            coin: arr32(0x40),
            nonce: [0x5a; NONCE_LEN],
        }
    }

    /// THE CAPSTONE: encrypt-to-pubkey round-trip. The sender seals a plaintext
    /// TO the recipient's hybrid public key `(x25519_pub, ml_kem_encaps_key)`; the
    /// recipient opens it with its hybrid secret `(x25519_secret, ml_kem_decaps
    /// _key)` and recovers the exact plaintext — proving the hybrid KEM + AEAD +
    /// envelope compose into public-key encryption to a device's hybrid key.
    #[test]
    fn encrypt_to_pubkey_round_trip() {
        let s = setup();
        let aad = b"ctx-capstone";
        let plaintext = b"top-secret recovery codes for the other vault";

        let (eph_pub, ct, env) = hybrid_seal(
            &s.r_x_pub,
            &s.ek,
            &s.eph_secret,
            &s.coin,
            &s.nonce,
            aad,
            plaintext,
        )
        .expect("hybrid_seal succeeds");

        // The envelope bytes do not carry the plaintext in the clear.
        assert!(!env
            .windows(plaintext.len())
            .any(|w| w == plaintext.as_slice()));

        let recovered =
            hybrid_open(&s.r_x_secret, &s.dk, &eph_pub, &ct, &env).expect("hybrid_open succeeds");
        assert_eq!(recovered, plaintext);
    }

    /// Wrong recipient: opening with a DIFFERENT recipient's hybrid secret
    /// `(x25519_secret, ml_kem_decaps_key)` recovers a *different* hybrid secret
    /// (the X25519 half disagrees; ML-KEM decapsulation is total), so the AEAD
    /// authentication fails — `Err(Aead(_))`, and no plaintext leaks.
    #[test]
    fn wrong_recipient_fails_with_aead_error() {
        let s = setup();
        let (eph_pub, ct, env) = hybrid_seal(
            &s.r_x_pub,
            &s.ek,
            &s.eph_secret,
            &s.coin,
            &s.nonce,
            b"aad",
            b"plaintext",
        )
        .expect("hybrid_seal succeeds");

        // A second, unrelated recipient.
        let other_x_secret = arr32(0x99);
        let (_other_ek, other_dk) = ml_kem768_keygen(&arr64(0xaa));

        let result = hybrid_open(&other_x_secret, &other_dk, &eph_pub, &ct, &env);
        assert!(matches!(result, Err(HybridSealError::Aead(_))));
    }

    /// Tamper (a): flipping a byte in the envelope's ciphertext/tag region (the
    /// last byte) still decodes structurally but fails AEAD authentication.
    #[test]
    fn tampered_envelope_is_rejected() {
        let s = setup();
        let (eph_pub, ct, mut env) = hybrid_seal(
            &s.r_x_pub,
            &s.ek,
            &s.eph_secret,
            &s.coin,
            &s.nonce,
            b"aad",
            b"some plaintext here",
        )
        .expect("hybrid_seal succeeds");

        let last = env.len() - 1; // inside the tag region
        env[last] ^= 0x01;
        assert_eq!(
            hybrid_open(&s.r_x_secret, &s.dk, &eph_pub, &ct, &env),
            Err(HybridSealError::Aead(AeadError::Authentication))
        );
    }

    /// Tamper (b): flipping a byte in the ML-KEM ciphertext yields a *different*
    /// combined secret (ML-KEM decapsulation is total, and the transcript hash
    /// changes), so the AEAD then fails authentication.
    #[test]
    fn tampered_mlkem_ct_is_rejected() {
        let s = setup();
        let (eph_pub, mut ct, env) = hybrid_seal(
            &s.r_x_pub,
            &s.ek,
            &s.eph_secret,
            &s.coin,
            &s.nonce,
            b"aad",
            b"some plaintext here",
        )
        .expect("hybrid_seal succeeds");

        ct[0] ^= 0x01;
        assert_eq!(
            hybrid_open(&s.r_x_secret, &s.dk, &eph_pub, &ct, &env),
            Err(HybridSealError::Aead(AeadError::Authentication))
        );
    }

    /// Tamper (c): flipping a byte in the ephemeral X25519 public key changes the
    /// X25519 shared secret (and the transcript hash), so the recovered hybrid
    /// secret differs and the AEAD fails.
    #[test]
    fn tampered_ephemeral_pubkey_is_rejected() {
        let s = setup();
        let (mut eph_pub, ct, env) = hybrid_seal(
            &s.r_x_pub,
            &s.ek,
            &s.eph_secret,
            &s.coin,
            &s.nonce,
            b"aad",
            b"some plaintext here",
        )
        .expect("hybrid_seal succeeds");

        eph_pub[0] ^= 0x01;
        assert!(hybrid_open(&s.r_x_secret, &s.dk, &eph_pub, &ct, &env).is_err());
    }

    /// AAD is authenticated: the sealed envelope carries the `aad` in the clear,
    /// and [`hybrid_open`] recovers and verifies it. Tampering with the AAD inside
    /// the envelope makes open fail.
    #[test]
    fn aad_is_authenticated() {
        let s = setup();
        let aad = b"ctx-A";
        let (eph_pub, ct, env) = hybrid_seal(
            &s.r_x_pub,
            &s.ek,
            &s.eph_secret,
            &s.coin,
            &s.nonce,
            aad,
            b"plaintext",
        )
        .expect("hybrid_seal succeeds");

        // The envelope carries the AAD verbatim, and open verifies it.
        let decoded = Envelope::decode(&env).expect("decodes");
        assert_eq!(decoded.aad, aad.to_vec());
        assert!(hybrid_open(&s.r_x_secret, &s.dk, &eph_pub, &ct, &env).is_ok());

        // Tamper the AAD inside the envelope, re-encode, and open must fail.
        let mut forged = decoded;
        forged.aad = b"ctx-B".to_vec();
        assert_eq!(
            hybrid_open(&s.r_x_secret, &s.dk, &eph_pub, &ct, &forged.encode()),
            Err(HybridSealError::Aead(AeadError::Authentication))
        );
    }

    /// Empty plaintext round-trips through the full seal/open flow.
    #[test]
    fn empty_plaintext_round_trips() {
        let s = setup();
        let (eph_pub, ct, env) = hybrid_seal(
            &s.r_x_pub,
            &s.ek,
            &s.eph_secret,
            &s.coin,
            &s.nonce,
            b"aad",
            b"",
        )
        .expect("hybrid_seal succeeds");
        let recovered =
            hybrid_open(&s.r_x_secret, &s.dk, &eph_pub, &ct, &env).expect("hybrid_open succeeds");
        assert!(recovered.is_empty());
    }

    /// Determinism: identical inputs yield byte-identical `(eph_pub, ct, env)` —
    /// this flow draws no per-call randomness (the KEM and the AEAD are both
    /// deterministic given the caller-supplied secret, coin, and nonce).
    #[test]
    fn hybrid_seal_is_deterministic() {
        let s = setup();
        let a = hybrid_seal(
            &s.r_x_pub,
            &s.ek,
            &s.eph_secret,
            &s.coin,
            &s.nonce,
            b"aad",
            b"plaintext",
        )
        .expect("hybrid_seal succeeds");
        let b = hybrid_seal(
            &s.r_x_pub,
            &s.ek,
            &s.eph_secret,
            &s.coin,
            &s.nonce,
            b"aad",
            b"plaintext",
        )
        .expect("hybrid_seal succeeds");
        assert_eq!(a.0, b.0, "ephemeral public keys identical");
        assert_eq!(a.1, b.1, "ML-KEM ciphertexts identical");
        assert_eq!(a.2, b.2, "encoded envelopes identical");
    }

    /// A non-contributory (all-zero / low-order) recipient X25519 public key is
    /// rejected by the hybrid KEM and surfaces as
    /// `Err(Hybrid(Kx(NonContributory)))` — no record is sealed under a known
    /// shared secret.
    #[test]
    fn non_contributory_recipient_pub_is_rejected() {
        let s = setup();
        let zero_pub = [0u8; X25519_PUBLIC_KEY_LEN];
        assert_eq!(
            hybrid_seal(
                &zero_pub,
                &s.ek,
                &s.eph_secret,
                &s.coin,
                &s.nonce,
                b"aad",
                b"plaintext"
            ),
            Err(HybridSealError::Hybrid(HybridError::Kx(
                KxError::NonContributory
            )))
        );
    }
}
