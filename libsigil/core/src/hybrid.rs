//! Hybrid key encapsulation — the classical X25519 KEX and the post-quantum
//! ML-KEM-768 KEM combined into a single shared secret via HKDF-SHA256.
//!
//! STATUS: pre-audit. This module performs **no new low-level cryptography of
//! its own**: it *composes* the two existing KEM building blocks of
//! `sigil-core` — the classical X25519 Diffie-Hellman agreement
//! ([`mod@crate::kx`]) and the post-quantum ML-KEM-768 KEM ([`mod@crate::mlkem`])
//! — into one combined 32-byte shared secret, using the same vetted HKDF-SHA256
//! ([`hkdf`] + [`sha2`]) that the AEAD layer uses. It has **not** been audited
//! and is a **standalone** primitive: it is **not** yet wired into the
//! record/account/vault flow. Treat it as a building block, not a finished
//! secure system.
//!
//! ## What this module does
//!
//! [`hybrid_encapsulate`] and [`hybrid_decapsulate`] are the two sides of a
//! hybrid KEM. The sender encapsulates to a recipient holding an
//! `(x25519_pub, ml_kem768_encaps_key)` pair, producing an ephemeral X25519
//! public key, an ML-KEM-768 ciphertext, and a combined 32-byte shared secret.
//! The recipient, holding the matching `(x25519_secret, ml_kem768_decaps_key)`,
//! recovers the **same** combined secret from the ephemeral public key and the
//! ciphertext. The raw-bytes API (fixed-size arrays in, fixed-size arrays out)
//! is deliberately FFI-friendly so it can be exposed across the `sigil-ffi`
//! C-ABI later.
//!
//! ## The combiner — `ss_combined = HKDF-SHA256(ss_x ‖ ss_kem ‖ H, "sigil-hybrid-v1")`
//!
//! The load-bearing crypto is [`combine`]. Per `docs/crypto-spec.md` (RFC 9794 /
//! NIST SP 800-56C Rev. 2 style concatenation-KDF combiner):
//!
//! ```text
//! transcript_hash = SHA256( eph_x25519_pub ‖ ml_kem768_ciphertext )
//! ss_combined     = HKDF-SHA256( ikm  = ss_x ‖ ss_kem ‖ transcript_hash,
//!                                salt = none,
//!                                info = "sigil-hybrid-v1" )         [32 bytes]
//! ```
//!
//! Both raw shared secrets feed the HKDF input keying material, so the combined
//! key depends on **both** halves. The `transcript_hash` binds the exact
//! ciphertext material (the ephemeral public key and the ML-KEM ciphertext) into
//! the derivation, so the two halves cannot be mixed-and-matched or substituted
//! across sessions. `salt = None`: the concatenated raw secrets are already
//! high-entropy, so HKDF is used purely as a combiner/labelling step. The 32-byte
//! output is a proper uniformly-distributed key suitable to seed further KDFs
//! (it is **not** raw group/lattice material — unlike either input on its own).
//!
//! ## The hybrid property (design intent of an unaudited primitive)
//!
//! Because both `ss_x` and `ss_kem` are concatenated into the HKDF input, the
//! combined secret is designed to stay secret if **either** the X25519 **or** the
//! ML-KEM-768 component remains secure — the standard concatenation-KDF
//! hybrid-combiner property: recovering the combined key requires breaking
//! **both** X25519 **and** ML-KEM-768. This is the honest *design intent* of an
//! **UNAUDITED** primitive, not a proven or audited guarantee, and a full
//! "secure if either" proof is out of scope here. Nothing in this module makes
//! the system — or even this primitive — "post-quantum secure" or "secure"; the
//! word "post-quantum" describes the ML-KEM-768 component algorithm.
//!
//! ## The ephemeral secret and coin are the caller's responsibility
//!
//! `sigil-core` is `no_std` and compiles to `wasm32-unknown-unknown`, where no
//! system RNG is available, so this module **never generates randomness** — in
//! particular it does **not** generate the sender's ephemeral X25519 secret or
//! the ML-KEM encapsulation coin. The caller supplies both, exactly as the caller
//! supplies the Argon2id salt, the AEAD nonce, the X25519 scalar, and the Ed25519
//! seed elsewhere in the crate (see
//! [ADR 0007](../../../docs/decisions/0007-caller-supplied-entropy-in-core.md)).
//! The caller MUST draw them from a cryptographically secure source and use a
//! fresh ephemeral secret and coin per encapsulation; reuse breaks the ephemeral
//! secrecy of the exchange.
//!
//! ## Pre-audit caveats
//!
//! - There is no zeroization of the raw component secrets, the HKDF input keying
//!   material, or the combined secret beyond what the dependencies do internally.
//! - A **non-contributory** X25519 half — an all-zero / low-order recipient (or
//!   ephemeral) public key (RFC 7748 §6.1) — is rejected as
//!   [`HybridError::Kx`]`(`[`KxError::NonContributory`]`)` rather than silently
//!   folded into the combiner.
//! - ML-KEM-768 decapsulation is **total** (FIPS 203 §6.3 implicit rejection): a
//!   tampered ciphertext does not error, it yields a *different* pseudo-random
//!   `ss_kem` and hence a *different* combined secret. The transcript binding
//!   reinforces this — a flipped ciphertext or ephemeral public key changes the
//!   combined key regardless.
//! - This is unaudited and not wired into any product key-exchange flow.

use crate::{
    ml_kem768_decapsulate, ml_kem768_encapsulate, x25519_public_key, x25519_shared_secret, KxError,
    MlKemError, ML_KEM768_CIPHERTEXT_LEN, ML_KEM768_DECAPS_KEY_LEN, ML_KEM768_ENCAPS_COIN_LEN,
    ML_KEM768_ENCAPS_KEY_LEN, ML_KEM768_SHARED_SECRET_LEN, X25519_PUBLIC_KEY_LEN,
    X25519_SECRET_KEY_LEN, X25519_SHARED_SECRET_LEN,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// Length, in bytes, of the combined hybrid shared secret. It is a proper
/// 32-byte key (HKDF output), suitable to seed further KDFs.
pub const HYBRID_SHARED_SECRET_LEN: usize = 32;

/// HKDF `info` label domain-separating this combiner. Matches the
/// `"sigil-hybrid-v1"` label in `docs/crypto-spec.md`.
const HYBRID_INFO: &[u8] = b"sigil-hybrid-v1";

/// The output of [`hybrid_encapsulate`]: the sender's ephemeral X25519 public
/// key, the ML-KEM-768 ciphertext to hand to the recipient, and the combined
/// 32-byte shared secret. (A named alias keeps the fn signature readable.)
pub type HybridEncapsulation = (
    [u8; X25519_PUBLIC_KEY_LEN],
    [u8; ML_KEM768_CIPHERTEXT_LEN],
    [u8; HYBRID_SHARED_SECRET_LEN],
);

/// Errors returned by the hybrid KEM. Each variant wraps the failure of one
/// component half, so callers can tell which primitive rejected the inputs.
///
/// For the fixed-size array inputs used here the [`HybridError::MlKem`] arms are
/// unreachable in practice (a fixed-length buffer always parses); they exist so
/// the raw-bytes contract stays honest at the eventual FFI boundary. The
/// [`HybridError::Kx`] non-contributory arm **is** reachable — a low-order peer
/// public key triggers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HybridError {
    /// The classical X25519 half failed — currently only
    /// [`KxError::NonContributory`], an all-zero / low-order X25519 public key
    /// whose agreement does not depend on our scalar (RFC 7748 §6.1).
    Kx(KxError),
    /// The post-quantum ML-KEM-768 half failed to parse a fixed-size input.
    /// Unreachable for the fixed-size arrays used here (present for FFI honesty).
    MlKem(MlKemError),
}

impl From<KxError> for HybridError {
    fn from(err: KxError) -> Self {
        HybridError::Kx(err)
    }
}

impl From<MlKemError> for HybridError {
    fn from(err: MlKemError) -> Self {
        HybridError::MlKem(err)
    }
}

/// Combine the two raw component shared secrets into one 32-byte key, binding
/// the ciphertext material (the ephemeral X25519 public key and the ML-KEM-768
/// ciphertext) into the derivation.
///
/// This is the load-bearing crypto of the module:
///
/// ```text
/// transcript_hash = SHA256( eph_x25519_pub ‖ mlkem_ct )
/// out             = HKDF-SHA256( ikm  = ss_x ‖ ss_kem ‖ transcript_hash,
///                                salt = none,
///                                info = "sigil-hybrid-v1" )
/// ```
///
/// Both raw secrets feed the HKDF input keying material, so the output depends on
/// both halves; the transcript hash binds the exact ciphertext material so the
/// halves cannot be substituted. See the module-level docs.
fn combine(
    ss_x: &[u8; X25519_SHARED_SECRET_LEN],
    ss_kem: &[u8; ML_KEM768_SHARED_SECRET_LEN],
    eph_x25519_pub: &[u8; X25519_PUBLIC_KEY_LEN],
    mlkem_ct: &[u8; ML_KEM768_CIPHERTEXT_LEN],
) -> [u8; HYBRID_SHARED_SECRET_LEN] {
    // transcript_hash = SHA256(eph_x25519_pub ‖ mlkem_ct) — binds the ciphertext
    // material so a substituted/mixed half changes the derived key.
    let mut hasher = Sha256::new();
    hasher.update(eph_x25519_pub);
    hasher.update(mlkem_ct);
    let transcript_hash = hasher.finalize();

    // ikm = ss_x (32) ‖ ss_kem (32) ‖ transcript_hash (32) = 96 bytes. Both raw
    // component secrets are concatenated so the combined key needs both.
    let mut ikm = [0u8; X25519_SHARED_SECRET_LEN + ML_KEM768_SHARED_SECRET_LEN + 32];
    ikm[..32].copy_from_slice(ss_x);
    ikm[32..64].copy_from_slice(ss_kem);
    ikm[64..].copy_from_slice(&transcript_hash);

    // salt = None: the concatenated raw secrets are already high-entropy, so HKDF
    // acts purely as the combiner/labelling step. Output is a proper 32-byte key.
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; HYBRID_SHARED_SECRET_LEN];
    hk.expand(HYBRID_INFO, &mut okm)
        .expect("HKDF-SHA256 expand to 32 bytes is infallible");
    okm
}

/// Hybrid-encapsulate a shared secret to a recipient holding
/// `(recipient_x25519_pub, recipient_mlkem_encaps_key)`, using a caller-supplied
/// ephemeral X25519 secret and ML-KEM-768 coin.
///
/// Returns `(eph_x25519_pub, mlkem_ciphertext, combined_secret)`: the sender's
/// ephemeral X25519 public key and the ML-KEM ciphertext are the material the
/// recipient needs to recover the same 32-byte combined secret via
/// [`hybrid_decapsulate`]. The `ephemeral_x25519_secret` and `mlkem_coin` are
/// the caller's responsibility (see the module-level docs); this function
/// generates no randomness and MUST be given fresh values per call.
///
/// # Errors
///
/// - [`HybridError::Kx`]`(`[`KxError::NonContributory`]`)` if
///   `recipient_x25519_pub` is an all-zero / low-order point (RFC 7748 §6.1).
/// - [`HybridError::MlKem`] if `recipient_mlkem_encaps_key` does not parse
///   (unreachable for the fixed-size array here).
pub fn hybrid_encapsulate(
    recipient_x25519_pub: &[u8; X25519_PUBLIC_KEY_LEN],
    recipient_mlkem_encaps_key: &[u8; ML_KEM768_ENCAPS_KEY_LEN],
    ephemeral_x25519_secret: &[u8; X25519_SECRET_KEY_LEN],
    mlkem_coin: &[u8; ML_KEM768_ENCAPS_COIN_LEN],
) -> Result<HybridEncapsulation, HybridError> {
    let ss_x = x25519_shared_secret(ephemeral_x25519_secret, recipient_x25519_pub)?;
    let eph_x25519_pub = x25519_public_key(ephemeral_x25519_secret);
    let (mlkem_ct, ss_kem) = ml_kem768_encapsulate(recipient_mlkem_encaps_key, mlkem_coin)?;
    let combined = combine(&ss_x, &ss_kem, &eph_x25519_pub, &mlkem_ct);
    Ok((eph_x25519_pub, mlkem_ct, combined))
}

/// Hybrid-decapsulate the combined shared secret: the recipient uses
/// `(recipient_x25519_secret, recipient_mlkem_decaps_key)` with the sender's
/// ephemeral X25519 public key and the ML-KEM-768 ciphertext to recover the same
/// 32-byte combined secret that [`hybrid_encapsulate`] produced.
///
/// ML-KEM-768 decapsulation is **total** (FIPS 203 implicit rejection): a
/// tampered ciphertext does not error, it yields a *different* combined secret.
/// The X25519 half, by contrast, rejects a low-order `sender_eph_x25519_pub`.
///
/// # Errors
///
/// - [`HybridError::Kx`]`(`[`KxError::NonContributory`]`)` if
///   `sender_eph_x25519_pub` is an all-zero / low-order point (RFC 7748 §6.1).
/// - [`HybridError::MlKem`] if `recipient_mlkem_decaps_key` or `mlkem_ct` does
///   not parse (unreachable for the fixed-size arrays here).
pub fn hybrid_decapsulate(
    recipient_x25519_secret: &[u8; X25519_SECRET_KEY_LEN],
    recipient_mlkem_decaps_key: &[u8; ML_KEM768_DECAPS_KEY_LEN],
    sender_eph_x25519_pub: &[u8; X25519_PUBLIC_KEY_LEN],
    mlkem_ct: &[u8; ML_KEM768_CIPHERTEXT_LEN],
) -> Result<[u8; HYBRID_SHARED_SECRET_LEN], HybridError> {
    let ss_x = x25519_shared_secret(recipient_x25519_secret, sender_eph_x25519_pub)?;
    let ss_kem = ml_kem768_decapsulate(recipient_mlkem_decaps_key, mlkem_ct)?;
    let combined = combine(&ss_x, &ss_kem, sender_eph_x25519_pub, mlkem_ct);
    Ok(combined)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ml_kem768_keygen, ML_KEM768_KEYGEN_SEED_LEN};

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

    /// A recipient key pair plus a sender's ephemeral secret and ML-KEM coin —
    /// the fixed inputs the round-trip / tamper tests share.
    struct Setup {
        r_x_secret: [u8; X25519_SECRET_KEY_LEN],
        r_x_pub: [u8; X25519_PUBLIC_KEY_LEN],
        ek: [u8; ML_KEM768_ENCAPS_KEY_LEN],
        dk: [u8; ML_KEM768_DECAPS_KEY_LEN],
        eph_secret: [u8; X25519_SECRET_KEY_LEN],
        coin: [u8; ML_KEM768_ENCAPS_COIN_LEN],
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
        }
    }

    #[test]
    fn constant_has_expected_length() {
        assert_eq!(HYBRID_SHARED_SECRET_LEN, 32);
    }

    /// THE CAPSTONE: a full hybrid KEM round-trip. The sender encapsulates to the
    /// recipient's `(x25519_pub, ml_kem_encaps_key)`; the recipient decapsulates
    /// with its `(x25519_secret, ml_kem_decaps_key)` — and both arrive at the
    /// SAME combined 32-byte secret. This proves the two halves compose into one
    /// agreed key.
    #[test]
    fn round_trip_hybrid_kem_agrees() {
        let s = setup();
        let (eph_pub, ct, k_sender) =
            hybrid_encapsulate(&s.r_x_pub, &s.ek, &s.eph_secret, &s.coin).expect("encapsulate");
        let k_receiver =
            hybrid_decapsulate(&s.r_x_secret, &s.dk, &eph_pub, &ct).expect("decapsulate");
        assert_eq!(
            k_sender, k_receiver,
            "hybrid KEM agrees on the combined key"
        );
    }

    /// Determinism: identical inputs yield byte-identical ephemeral public key,
    /// ciphertext, and combined secret — this module draws no per-call randomness.
    #[test]
    fn encapsulate_is_deterministic() {
        let s = setup();
        let a = hybrid_encapsulate(&s.r_x_pub, &s.ek, &s.eph_secret, &s.coin).expect("encapsulate");
        let b = hybrid_encapsulate(&s.r_x_pub, &s.ek, &s.eph_secret, &s.coin).expect("encapsulate");
        assert_eq!(a.0, b.0, "ephemeral public keys identical");
        assert_eq!(a.1, b.1, "ciphertexts identical");
        assert_eq!(a.2, b.2, "combined secrets identical");
    }

    /// Transcript binding via a tampered ML-KEM ciphertext. ML-KEM decapsulation
    /// is total (implicit rejection), so decapsulate still returns `Ok` — but the
    /// combined secret differs from the sender's, because the flipped ciphertext
    /// changes both `ss_kem` and the transcript hash.
    #[test]
    fn tampered_ciphertext_yields_different_combined_secret() {
        let s = setup();
        let (eph_pub, mut ct, k_sender) =
            hybrid_encapsulate(&s.r_x_pub, &s.ek, &s.eph_secret, &s.coin).expect("encapsulate");

        ct[0] ^= 0x01; // structurally valid, semantically different
        let k_bad =
            hybrid_decapsulate(&s.r_x_secret, &s.dk, &eph_pub, &ct).expect("decaps is total");
        assert_ne!(
            k_sender, k_bad,
            "a tampered ciphertext must not recover the sender's combined secret"
        );
    }

    /// Transcript binding via a tampered ephemeral public key. Flipping a byte of
    /// `eph_pub` changes both the X25519 shared secret the recipient computes and
    /// the transcript hash, so the combined secret differs (decapsulate is still
    /// `Ok` — the flipped point is not low-order).
    #[test]
    fn tampered_ephemeral_pubkey_yields_different_combined_secret() {
        let s = setup();
        let (mut eph_pub, ct, k_sender) =
            hybrid_encapsulate(&s.r_x_pub, &s.ek, &s.eph_secret, &s.coin).expect("encapsulate");

        eph_pub[0] ^= 0x01;
        let k_bad = hybrid_decapsulate(&s.r_x_secret, &s.dk, &eph_pub, &ct).expect("decapsulate");
        assert_ne!(
            k_sender, k_bad,
            "a tampered ephemeral public key must change the combined secret"
        );
    }

    /// Component independence (the hybrid property, structurally): at the combiner
    /// level, changing ONLY the ML-KEM half of the input while holding the X25519
    /// half and the transcript fixed changes the combined key — and, symmetrically,
    /// changing ONLY the X25519 half changes it. Both halves feed the output, so
    /// breaking one alone cannot reproduce the key.
    #[test]
    fn both_halves_feed_the_combined_secret() {
        let ss_x = arr32(0x01);
        let ss_kem = arr32(0x02);
        let eph_pub = arr32(0x03);
        let ct = [0x04u8; ML_KEM768_CIPHERTEXT_LEN];

        let base = combine(&ss_x, &ss_kem, &eph_pub, &ct);

        // Flip only the ML-KEM shared secret; X25519 half and transcript unchanged.
        let mut ss_kem2 = ss_kem;
        ss_kem2[0] ^= 0xff;
        assert_ne!(
            base,
            combine(&ss_x, &ss_kem2, &eph_pub, &ct),
            "changing only the ML-KEM half changes the combined key"
        );

        // Flip only the X25519 shared secret; ML-KEM half and transcript unchanged.
        let mut ss_x2 = ss_x;
        ss_x2[0] ^= 0xff;
        assert_ne!(
            base,
            combine(&ss_x2, &ss_kem, &eph_pub, &ct),
            "changing only the X25519 half changes the combined key"
        );
    }

    /// The X25519 non-contributory rejection propagates through the hybrid: an
    /// all-zero (low-order) recipient public key makes `hybrid_encapsulate` return
    /// `Err(HybridError::Kx(KxError::NonContributory))` rather than folding a known
    /// shared secret into the combiner.
    #[test]
    fn low_order_recipient_pub_is_non_contributory() {
        let s = setup();
        let zero_pub = [0u8; X25519_PUBLIC_KEY_LEN];
        assert_eq!(
            hybrid_encapsulate(&zero_pub, &s.ek, &s.eph_secret, &s.coin),
            Err(HybridError::Kx(KxError::NonContributory))
        );
    }

    /// `combine` itself is deterministic: identical inputs yield the identical
    /// 32-byte key (self-consistency of the load-bearing combiner).
    #[test]
    fn combine_is_deterministic() {
        let ss_x = arr32(0x51);
        let ss_kem = arr32(0x62);
        let eph_pub = arr32(0x73);
        let ct = [0x84u8; ML_KEM768_CIPHERTEXT_LEN];
        assert_eq!(
            combine(&ss_x, &ss_kem, &eph_pub, &ct),
            combine(&ss_x, &ss_kem, &eph_pub, &ct)
        );
    }
}
