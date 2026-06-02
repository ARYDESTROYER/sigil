//! `sigil-core` — the pure, dependency-free heart of libsigil.
//!
//! STATUS: pre-audit skeleton. This crate currently defines only the
//! crypto-agility envelope metadata (the algorithm-suite registry and the
//! envelope header layout). **No real cryptography is implemented yet** — do
//! not use any of this for anything security-sensitive. See
//! `docs/crypto-spec.md` for the intended design.
//!
//! The crate is `no_std` (it pulls in only `core`) so it can be compiled to
//! `wasm32-unknown-unknown` for the web app and browser extension, and linked
//! into the native clients via the `sigil-ffi` C-ABI layer.
#![forbid(unsafe_code)]
#![cfg_attr(not(test), no_std)]

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
