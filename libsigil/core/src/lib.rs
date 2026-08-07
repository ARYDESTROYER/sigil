//! `sigil-core` — the cryptographic heart of libsigil.
//!
//! STATUS: pre-audit. This crate defines the crypto-agility envelope metadata
//! (the algorithm-suite registry and the envelope header layout), a real
//! symmetric AEAD layer ([`mod@aead`]) that wraps that envelope with
//! XChaCha20-Poly1305 + HKDF-SHA256, and an Argon2id password-stretching KDF
//! ([`derive_master_key`]) — all via the vetted RustCrypto crates. The code
//! has **not** been audited and the pieces are not yet wired into a complete
//! account/key-management flow — treat them as building blocks, not a finished
//! secure system. See `docs/crypto-spec.md` for the intended design.
//!
//! [`seal_record`] / [`open_record`] ([`mod@record`]) compose those building
//! blocks into the single end-to-end call a client makes for one record
//! (Argon2id → AEAD → envelope codec); they add no new cryptography and are not
//! a complete account/key-management system.
//!
//! A classical Ed25519 signature primitive ([`sign`] / [`verify`], [`mod@sig`])
//! provides the classical half of the hybrid Ed25519&ML-DSA-65 signature suite.
//! Its post-quantum counterpart, an ML-DSA-65 (FIPS 204) signature primitive
//! ([`ml_dsa65_keygen`] / [`ml_dsa65_sign`] / [`ml_dsa65_verify`], [`mod@mldsa`],
//! deterministic/caller-supplied keygen seed, deterministic signing), is the PQ
//! signature half. The two are now assembled into the **hybrid signature**
//! ([`hybrid_sign`] / [`hybrid_verify`], [`mod@hybrid_sig`]): the signer produces
//! `Ed25519.Sign(m) ‖ ML-DSA-65.Sign(m)` (64 + 3309 = 3373 bytes) under a
//! two-seed hybrid identity, and the verifier accepts **only** if **both** halves
//! validate — so a forgery requires breaking **both** Ed25519 **and** ML-DSA-65.
//! Both halves are deterministic, so the hybrid signature is deterministic. It is
//! a **real but UNAUDITED, standalone** primitive — the caller supplies the two
//! signing seeds, and it is **not** wired into any identity/record/vault flow (the
//! sigild op-log request auth still uses the classical Ed25519 signature only).
//! This completes the hybrid suite alongside the hybrid KEM.
//!
//! A classical X25519 Diffie-Hellman key-agreement primitive
//! ([`x25519_public_key`] / [`x25519_shared_secret`], [`mod@kx`]) provides the
//! classical KEX half of the hybrid X25519&ML-KEM-768 suite. Its post-quantum
//! counterpart, an ML-KEM-768 (FIPS 203) KEM primitive ([`ml_kem768_keygen`] /
//! [`ml_kem768_encapsulate`] / [`ml_kem768_decapsulate`], [`mod@mlkem`],
//! deterministic/caller-supplied seed and coin), is the PQ half. The two are now
//! assembled into the **hybrid KEM** ([`hybrid_encapsulate`] /
//! [`hybrid_decapsulate`], [`mod@hybrid`]): they are combined via HKDF-SHA256
//! into one 32-byte shared secret designed to stay secret if **either** half
//! remains secure (the standard concatenation-KDF hybrid-combiner property). It
//! is a **real but UNAUDITED, standalone** primitive — the caller supplies the
//! ephemeral X25519 secret and the ML-KEM coin, and it is not yet wired into the
//! record/account/vault flow.
//!
//! [`hybrid_seal`] / [`hybrid_open`] ([`mod@hybrid_seal`]) then put that hybrid
//! KEM to its intended use: **public-key seal/open** — encrypt a record TO a
//! recipient's hybrid public key. They compose the hybrid KEM with the AEAD and
//! the envelope codec into a **CUSTOM** hybrid public-key authenticated
//! encryption (KEM-then-AEAD) flow — **NOT** RFC 9180 HPKE, and real but
//! **UNAUDITED**. Like the rest of the crate it is standalone (a crypto-level
//! flow, not the product's account/key-management/vault-storage model, and not
//! wired into `sigild`/CLI) and generates no randomness — the caller supplies the
//! ephemeral X25519 secret, the ML-KEM coin, and the AEAD nonce.
//!
//! Argon2id is the **first hop** in the key chain: a low-entropy human password
//! is stretched into a 32-byte master key, which is then expanded per record and
//! used for authenticated encryption:
//!
//! ```text
//!   password ─▶ Argon2id ─▶ master key ─▶ HKDF-SHA256 ─▶ per-record key ─▶ XChaCha20-Poly1305
//! ```
//!
//! The crate is `no_std` (it relies on `core` + `alloc`, not `std`) so it can be compiled to
//! `wasm32-unknown-unknown` for the web app and browser extension, and linked
//! into the native clients via the `sigil-ffi` C-ABI layer.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

extern crate alloc;

mod aead;
mod entry_id;
mod envelope;
mod hybrid;
mod hybrid_auth;
mod hybrid_seal;
mod hybrid_sig;
mod kdf;
mod kx;
mod mldsa;
mod mlkem;
mod record;
mod recovery;
mod sig;
mod totp;
pub use aead::{open, seal, AeadError, KEY_LEN, NONCE_LEN, TAG_LEN};
pub use entry_id::{entry_id, format_entry_uuid_v8};
pub use envelope::{Envelope, EnvelopeError};
pub use hybrid::{
    hybrid_decapsulate, hybrid_encapsulate, HybridEncapsulation, HybridError,
    HYBRID_SHARED_SECRET_LEN,
};
pub use hybrid_auth::{
    hybrid_auth_decapsulate, hybrid_auth_encapsulate, hybrid_auth_open, hybrid_auth_seal,
    vault_key_wrap_aad, HybridAuthEncapsulation, HYBRID_AUTH_INFO, HYBRID_AUTH_SHARED_SECRET_LEN,
    HYBRID_AUTH_TRANSCRIPT_PREFIX, VAULT_KEY_WRAP_AAD_PREFIX,
};
pub use hybrid_seal::{hybrid_open, hybrid_seal, HybridSealError, HybridSealed};
pub use hybrid_sig::{hybrid_sign, hybrid_verify, HybridSigError, HYBRID_SIGNATURE_LEN};
pub use kdf::{derive_master_key, Argon2Params, KdfError, MASTER_KEY_LEN};
pub use kx::{
    x25519_public_key, x25519_shared_secret, KxError, X25519_PUBLIC_KEY_LEN, X25519_SECRET_KEY_LEN,
    X25519_SHARED_SECRET_LEN,
};
pub use mldsa::{
    ml_dsa65_keygen, ml_dsa65_sign, ml_dsa65_verify, MlDsaError, ML_DSA65_KEYGEN_SEED_LEN,
    ML_DSA65_PUBLIC_KEY_LEN, ML_DSA65_SECRET_KEY_LEN, ML_DSA65_SIGNATURE_LEN,
};
pub use mlkem::{
    ml_kem768_decapsulate, ml_kem768_encapsulate, ml_kem768_keygen, MlKemError,
    ML_KEM768_CIPHERTEXT_LEN, ML_KEM768_DECAPS_KEY_LEN, ML_KEM768_ENCAPS_COIN_LEN,
    ML_KEM768_ENCAPS_KEY_LEN, ML_KEM768_KEYGEN_SEED_LEN, ML_KEM768_SHARED_SECRET_LEN,
};
pub use record::{open_record, seal_record, RecordError};
pub use recovery::{
    decode_recovery_kit, derive_recovery_keys, encode_recovery_kit, format_recovery_kit,
    RecoveryError, RecoveryKeys, RECOVERY_CHECK_LEN, RECOVERY_GROUP_LEN, RECOVERY_KIT_BODY_LEN,
    RECOVERY_KIT_CHARS, RECOVERY_KIT_VERSION, RECOVERY_SEED_LEN,
};
pub use sig::{
    public_key_from_seed, sign, verify, SigError, SIGNATURE_LEN, SIG_PUBLIC_KEY_LEN, SIG_SEED_LEN,
};
pub use totp::{
    format_code, hotp, is_unsafe_display_char, totp, validate_provisioning,
    validate_provisioning_count, OtpAlgorithm, OtpError, ProvisioningError, MAX_DIGITS,
    MAX_LABEL_CHARS, MAX_PERIOD, MAX_PROVISIONING_ENTRIES, MAX_SECRET_BYTES, MIN_DIGITS,
};

/// Envelope format version. Every encrypted record begins with this byte.
/// See `docs/crypto-spec.md` for the full layout.
pub const ENVELOPE_VERSION: u8 = 0x01;

/// The algorithm suites understood by libsigil.
///
/// A single suite byte in every encrypted record's header selects the
/// `(KDF, KEM, AEAD, signature)` tuple. New suites are *added* to this registry
/// without breaking decryption of records written under older suites — clients
/// dispatch on the header byte. This is the crypto-agility property that lets us
/// migrate post-quantum suites without a flag-day re-encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum AlgorithmSuite {
    /// Legacy: PBKDF2 + RSA + AES-GCM + ECDSA P-256.
    Legacy = 0x10,
    /// Classical: Argon2id + X25519 + XChaCha20-Poly1305 + Ed25519.
    Classical = 0x11,
    /// CURRENT — hybrid PQ: Argon2id + X25519&ML-KEM-768 + XChaCha20-Poly1305 + Ed25519&ML-DSA-65.
    HybridPq = 0x12,
    /// Future: classical-only deprecated, hybrid required.
    HybridRequired = 0x13,
    /// Reserved backup: HQC-192 KEM + SLH-DSA-128f signatures (for an MLWE break).
    Backup = 0x14,
    /// Future: FN-DSA-512 signatures (smaller, for the watch).
    FnDsa = 0x15,
}

impl AlgorithmSuite {
    /// The suite written into new records today.
    pub const CURRENT: AlgorithmSuite = AlgorithmSuite::HybridPq;

    /// Map a header byte to a known suite, if recognised.
    #[must_use]
    pub const fn from_byte(b: u8) -> Option<AlgorithmSuite> {
        match b {
            0x10 => Some(AlgorithmSuite::Legacy),
            0x11 => Some(AlgorithmSuite::Classical),
            0x12 => Some(AlgorithmSuite::HybridPq),
            0x13 => Some(AlgorithmSuite::HybridRequired),
            0x14 => Some(AlgorithmSuite::Backup),
            0x15 => Some(AlgorithmSuite::FnDsa),
            _ => None,
        }
    }

    /// The on-wire byte for this suite.
    #[must_use]
    pub const fn as_byte(self) -> u8 {
        self as u8
    }

    /// Whether this suite protects long-lived secrets against a future
    /// cryptographically-relevant quantum computer (i.e. it is hybrid-PQ or better).
    #[must_use]
    pub const fn is_post_quantum(self) -> bool {
        matches!(
            self,
            AlgorithmSuite::HybridPq
                | AlgorithmSuite::HybridRequired
                | AlgorithmSuite::Backup
                | AlgorithmSuite::FnDsa
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_suite_is_hybrid_pq_0x12() {
        assert_eq!(AlgorithmSuite::CURRENT, AlgorithmSuite::HybridPq);
        assert_eq!(AlgorithmSuite::CURRENT.as_byte(), 0x12);
        assert!(AlgorithmSuite::CURRENT.is_post_quantum());
    }

    #[test]
    fn known_bytes_round_trip() {
        for b in [0x10u8, 0x11, 0x12, 0x13, 0x14, 0x15] {
            let suite = AlgorithmSuite::from_byte(b).expect("known suite byte");
            assert_eq!(suite.as_byte(), b);
        }
    }

    #[test]
    fn unknown_bytes_are_rejected() {
        assert!(AlgorithmSuite::from_byte(0x00).is_none());
        assert!(AlgorithmSuite::from_byte(0x0f).is_none());
        assert!(AlgorithmSuite::from_byte(0xff).is_none());
    }

    #[test]
    fn classical_suites_are_not_post_quantum() {
        assert!(!AlgorithmSuite::Legacy.is_post_quantum());
        assert!(!AlgorithmSuite::Classical.is_post_quantum());
    }

    #[test]
    fn envelope_version_is_v1() {
        assert_eq!(ENVELOPE_VERSION, 0x01);
    }
}
