//! Post-quantum ML-KEM-768 key encapsulation (FIPS 203) — the post-quantum half
//! of the hybrid X25519 & ML-KEM-768 key-encapsulation named by suite `0x12`.
//!
//! STATUS: pre-audit. This module performs **real** ML-KEM-768 with the
//! RustCrypto [`ml_kem`] crate, but it has **not** been audited and is not yet
//! wired into a complete key-encapsulation, key-rotation, or
//! account/key-management flow — treat it as a building block, not a finished
//! secure system.
//!
//! ## The PQ half is real — use the hybrid, not this module alone
//!
//! [`crate::AlgorithmSuite::HybridPq`] (suite `0x12`) names a **hybrid** KEM:
//! classical X25519 ([`crate::kex`]) **and** post-quantum ML-KEM-768 (this
//! module). The **X-Wing hybrid** ([`crate::hybrid`]) combines the two at the
//! primitive level; using this module alone forfeits the hybrid's
//! belt-and-suspenders property (security would rest on ML-KEM-768 by itself).
//! No product flow is wired to either yet, so sealed records still gain **no**
//! post-quantum protection.
//!
//! ## Randomness is the caller's responsibility
//!
//! `sigil-core` is `no_std`/wasm and **never generates randomness**: the caller
//! supplies the two 32-byte key-generation seeds `d` and `z` and the 32-byte
//! encapsulation randomness `m`, exactly as it supplies the Argon2id salt, the
//! AEAD nonce, the Ed25519 seed, and the X25519 secret elsewhere in the crate.
//! All three MUST come from a cryptographically secure source, and `m` MUST be
//! fresh per encapsulation (see the caveats below).
//!
//! ## Implicit rejection (READ THIS)
//!
//! Per FIPS 203, decapsulating a tampered or mismatched ciphertext does **not**
//! error: it returns a **different, pseudorandom** shared secret (derived from
//! the rejection seed `z`). Never treat "decapsulation succeeded" as
//! authentication — a mismatch only surfaces when the shared secret is used
//! (e.g. a downstream AEAD open fails). There is deliberately no
//! "decapsulation failed" error; adding one would create a CCA oracle.
//!
//! ## Store the seed, not the decapsulation key
//!
//! Keygen is deterministic in the caller-supplied `(d, z)`: re-running it
//! reproduces the identical keypair, byte for byte. FIPS 203 explicitly permits
//! storing the seed in place of the decapsulation key and re-expanding on
//! demand. Callers SHOULD store `d ‖ z` (64 bytes, FIPS 203 order) rather than
//! the 2400-byte decapsulation key: it is far smaller, avoids
//! imported-expanded-key consistency pitfalls, and preserves the
//! implicit-rejection secret `z` by construction. `(d, z)` is exactly as secret
//! as the decapsulation key — protect it identically.
//!
//! ## Do not reuse or share these bytes
//!
//! - **`d`/`z` are key material, not salts.** `(d, z)` fully determines the
//!   keypair; reusing `d` with a different `z` yields the *same* encapsulation
//!   key with only the rejection secret changed. Use fresh, independent 32-byte
//!   values per keypair, and keep `z` as secret as the decapsulation key.
//! - **`m` is a one-time secret — never reuse it.** ML-KEM encapsulation is
//!   deterministic: the same `(encap_key, m)` yields a byte-identical
//!   `(ciphertext, shared secret)`, so an observer learns that two sessions
//!   share a key, and anyone who ever learns `m` recomputes the shared secret
//!   from public data. A guessable `m` makes the shared secret recomputable
//!   from `(encap_key, ciphertext)` alone.
//! - **No cross-primitive sharing.** Do not reuse `d`, `z`, or `m` bytes as an
//!   Ed25519 seed ([`crate::sig`]) or X25519 secret ([`crate::kex`]).
//!
//! ## Pre-audit caveats
//!
//! - The deterministic API is a **contract, not a convenience**: the caller
//!   MUST draw `d`, `z`, and `m` fresh from a CSPRNG (see above).
//! - **Tampering is NOT signaled at decapsulation** (implicit rejection, above).
//!   A garbage 2400-byte decapsulation key likewise decapsulates "successfully"
//!   to a deterministic garbage secret — dk integrity is the caller's
//!   responsibility (store the seed instead).
//! - There is no zeroization of `d`/`z`/`m`, the encoded keys, or the shared
//!   secret beyond what the dependencies do internally (ml-kem's `zeroize`
//!   feature scrubs its internal decapsulation key on drop; our stack copies of
//!   the encoded byte arrays are not scrubbed).
//! - Encoded sizes are large and fixed: ek = 1184, dk = 2400, ct = 1088, ss = 32.
//! - This is unaudited. It is consumed by the X-Wing hybrid ([`crate::hybrid`])
//!   but not wired into the envelope or any product flow; sealed records still
//!   gain no post-quantum protection.

use ml_kem::kem::Decapsulate;
use ml_kem::{EncapsulateDeterministic, Encoded, EncodedSizeUser, KemCore, MlKem768, B32};

type EncapKey = <MlKem768 as KemCore>::EncapsulationKey;
type DecapKey = <MlKem768 as KemCore>::DecapsulationKey;

/// Length, in bytes, of the FIPS 203 key-generation seed `d`.
pub const MLKEM768_SEED_D_LEN: usize = 32;
/// Length, in bytes, of the FIPS 203 implicit-rejection seed `z`.
pub const MLKEM768_SEED_Z_LEN: usize = 32;
/// Length, in bytes, of the FIPS 203 encapsulation randomness `m`.
pub const MLKEM768_ENCAP_SEED_LEN: usize = 32;
/// Length, in bytes, of an ML-KEM-768 encapsulation (public) key.
pub const MLKEM768_ENCAP_KEY_LEN: usize = 1184;
/// Length, in bytes, of an ML-KEM-768 decapsulation (secret) key.
pub const MLKEM768_DECAP_KEY_LEN: usize = 2400;
/// Length, in bytes, of an ML-KEM-768 ciphertext.
pub const MLKEM768_CIPHERTEXT_LEN: usize = 1088;
/// Length, in bytes, of an ML-KEM-768 shared secret.
pub const MLKEM768_SHARED_SECRET_LEN: usize = 32;

/// Errors returned by the ML-KEM-768 primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MlKemError {
    /// The 1184-byte encapsulation key failed FIPS 203 §7.2 input validation
    /// (the "modulus check"): its encoding is non-canonical (some 12-bit
    /// coefficient is ≥ q = 3329). The `ml_kem` crate accepts such keys
    /// silently (it reduces them mod q), which would diverge from a conformant
    /// peer — we reject them instead.
    BadEncapsulationKey,
    /// Defensive absorption of the `ml_kem` crate's vestigial `Error = ()`.
    /// Structurally unreachable in ml-kem 0.2.3 (every fallible upstream call
    /// is unconditionally `Ok`, verified against its source); kept so this
    /// module has no `unwrap`/`unreachable!` panic path.
    Internal,
}

/// FIPS 203 ML-KEM-768 key generation over the caller-supplied 32-byte seeds
/// `d` (key seed) and `z` (implicit-rejection seed). Deterministic and total:
/// the same `(d, z)` always yields the same keypair, and every seed pair is
/// valid. Returns `(encapsulation key, decapsulation key)` in FIPS 203 order.
///
/// The seeds are the caller's secret key material (see the module-level docs);
/// this function never generates them. Callers SHOULD persist `d ‖ z` instead
/// of the 2400-byte decapsulation key and re-derive on demand.
#[must_use]
pub fn mlkem768_keygen(
    seed_d: &[u8; MLKEM768_SEED_D_LEN],
    seed_z: &[u8; MLKEM768_SEED_Z_LEN],
) -> ([u8; MLKEM768_ENCAP_KEY_LEN], [u8; MLKEM768_DECAP_KEY_LEN]) {
    // B32::from(*seed) is a plain 32-byte copy. generate_deterministic is FIPS
    // 203 ML-KEM.KeyGen with the RNG hoisted to the caller (byte-identical
    // output). ml-kem returns (dk, ek); we return FIPS 203 order (ek, dk) —
    // transposition would be a compile error (1184 != 2400).
    let (dk, ek) = MlKem768::generate_deterministic(&B32::from(*seed_d), &B32::from(*seed_z));
    (ek.as_bytes().into(), dk.as_bytes().into())
}

/// FIPS 203 ML-KEM-768 encapsulation to `encap_key` using the caller-supplied
/// 32-byte randomness `m`. Deterministic: the same `(encap_key, m)` always
/// yields the same `(ciphertext, shared secret)` — `m` MUST be fresh per
/// encapsulation (see the module-level docs).
///
/// # Errors
/// - [`MlKemError::BadEncapsulationKey`] if `encap_key` fails the FIPS 203 §7.2
///   modulus check (a non-canonical encoding). This validation is performed
///   here because the underlying crate does not perform it.
/// - [`MlKemError::Internal`] is structurally unreachable (see its docs).
pub fn mlkem768_encapsulate(
    encap_key: &[u8; MLKEM768_ENCAP_KEY_LEN],
    seed_m: &[u8; MLKEM768_ENCAP_SEED_LEN],
) -> Result<
    (
        [u8; MLKEM768_CIPHERTEXT_LEN],
        [u8; MLKEM768_SHARED_SECRET_LEN],
    ),
    MlKemError,
> {
    // Length is statically 1184, so this TryFrom can never fail; the map_err is
    // defensive (no unwrap/panic path), not a reachable branch.
    let encoded =
        Encoded::<EncapKey>::try_from(&encap_key[..]).map_err(|_| MlKemError::Internal)?;
    let ek = EncapKey::from_bytes(&encoded);
    // FIPS 203 §7.2 input validation (the "modulus check"). ml-kem 0.2.3
    // performs NO validation: its decoder silently reduces every 12-bit
    // coefficient mod q, so a non-canonical encap key would be accepted here
    // but rejected by a conformant peer. Re-encoding and comparing detects
    // exactly the non-canonical case. The key is public, so this comparison
    // need not be constant-time.
    if ek.as_bytes().as_slice() != &encap_key[..] {
        return Err(MlKemError::BadEncapsulationKey);
    }
    // Upstream Error = () is vestigial: the body is unconditionally Ok.
    // Defensive map, never fires.
    let (ct, ss) = ek
        .encapsulate_deterministic(&B32::from(*seed_m))
        .map_err(|_| MlKemError::Internal)?;
    Ok((ct.into(), ss.into()))
}

/// FIPS 203 ML-KEM-768 decapsulation.
///
/// **IMPLICIT REJECTION:** per FIPS 203, decapsulating a tampered, forged, or
/// mismatched ciphertext does NOT return an error — it returns `Ok` with a
/// *different*, pseudorandom shared secret derived from the rejection seed `z`.
/// A garbage 2400-byte `decap_key` likewise decapsulates "successfully" to a
/// deterministic garbage secret; dk integrity is the caller's responsibility.
/// Never treat decapsulation success as authentication: agreement is confirmed
/// only when the shared secret is used (e.g. the downstream AEAD open fails).
///
/// # Errors
/// - [`MlKemError::Internal`] is structurally unreachable (see its docs); no
///   reachable error exists by design — a "decapsulation failed" signal would
///   create a CCA oracle.
pub fn mlkem768_decapsulate(
    decap_key: &[u8; MLKEM768_DECAP_KEY_LEN],
    ciphertext: &[u8; MLKEM768_CIPHERTEXT_LEN],
) -> Result<[u8; MLKEM768_SHARED_SECRET_LEN], MlKemError> {
    // Both TryFroms are statically sized (2400 / 1088) and cannot fail; the
    // upstream decapsulate Error = () is never constructed (single Ok return,
    // verified against the ml-kem 0.2.3 source). All map_errs are defensive.
    let encoded =
        Encoded::<DecapKey>::try_from(&decap_key[..]).map_err(|_| MlKemError::Internal)?;
    let dk = DecapKey::from_bytes(&encoded);
    let ct = ml_kem::Ciphertext::<MlKem768>::try_from(&ciphertext[..])
        .map_err(|_| MlKemError::Internal)?;
    let ss = dk.decapsulate(&ct).map_err(|_| MlKemError::Internal)?;
    Ok(ss.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    // ---- NIST ACVP known-answer vector ------------------------------------
    //
    // Provenance: usnistgov/ACVP-Server @ 65370b8 (the commit ml-kem 0.2.3's own
    // tests pin), gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json,
    // parameter set ML-KEM-768 (tgId 2), tcId 26 — d, z, and the expected ek/dk
    // (pinned below as SHA-256 digests of the official full-length bytes; the
    // digests were computed directly from the downloaded NIST file, and ml-kem's
    // keygen output was verified BYTE-FOR-BYTE identical to the official ek/dk
    // before pinning). This half is a TRUE interop KAT.
    const KAT_D: [u8; 32] = [
        0xe3, 0x4a, 0x70, 0x1c, 0x4c, 0x87, 0x58, 0x2f, 0x42, 0x26, 0x4e, 0xe4, 0x22, 0xd3, 0xc6,
        0x84, 0xd9, 0x76, 0x11, 0xf2, 0x52, 0x3e, 0xfe, 0x0c, 0x99, 0x8a, 0xf0, 0x50, 0x56, 0xd6,
        0x93, 0xdc,
    ];
    const KAT_Z: [u8; 32] = [
        0xa8, 0x57, 0x68, 0xf3, 0x48, 0x6b, 0xd3, 0x2a, 0x01, 0xbf, 0x9a, 0x8f, 0x21, 0xea, 0x93,
        0x8e, 0x64, 0x8e, 0xae, 0x4e, 0x54, 0x48, 0xc3, 0x4c, 0x3e, 0xb8, 0x88, 0x20, 0xb1, 0x59,
        0xee, 0xdd,
    ];
    const KAT_EK_SHA256: [u8; 32] = [
        0x77, 0x99, 0xc9, 0xd8, 0xee, 0xf1, 0x72, 0xaa, 0x78, 0xc0, 0x73, 0x51, 0x4f, 0x2f, 0x03,
        0x9c, 0x24, 0x0d, 0xe8, 0xc5, 0xcb, 0x61, 0xbc, 0xa8, 0x2b, 0xa0, 0xbc, 0x46, 0x04, 0x1c,
        0xe2, 0x79,
    ];
    const KAT_DK_SHA256: [u8; 32] = [
        0x10, 0x4b, 0x34, 0x44, 0xc3, 0xde, 0x2b, 0x81, 0x14, 0x37, 0x88, 0xd2, 0x7e, 0x17, 0x64,
        0x8f, 0x45, 0xc8, 0x0f, 0x61, 0x7f, 0x90, 0x61, 0x56, 0xdb, 0x22, 0x58, 0xda, 0x96, 0xde,
        0xad, 0x40,
    ];
    // Chained encaps half: m is official ACVP (ML-KEM-encapDecap-FIPS203,
    // ML-KEM-768 encapsulation group, tcId 26), but ct/ss are NOT raw ACVP
    // output (ACVP has no seed-chained keygen→encaps case) — they come from
    // encapsulating this m under the keyGen tcId 26 key, cross-checked
    // byte-identical by two independent implementations (kyber-py 1.2.0 and
    // ml-kem 0.2.3) with the decap round-trip asserted. A cross-checked chained
    // vector, not a raw NIST vector.
    const KAT_M: [u8; 32] = [
        0x2c, 0xe7, 0x4a, 0xd2, 0x91, 0x13, 0x35, 0x18, 0xfe, 0x60, 0xc7, 0xdf, 0x5d, 0x25, 0x1b,
        0x9d, 0x82, 0xad, 0xd4, 0x84, 0x62, 0xff, 0x50, 0x5c, 0x6e, 0x54, 0x7e, 0x94, 0x9e, 0x6b,
        0x6b, 0xf7,
    ];
    const KAT_CT_SHA256: [u8; 32] = [
        0xfd, 0x39, 0x47, 0xe3, 0x04, 0x31, 0x08, 0xce, 0x52, 0x3c, 0x9a, 0x8c, 0x8d, 0xe4, 0x91,
        0x8a, 0x23, 0x02, 0xd9, 0x7e, 0x7e, 0xdc, 0x9b, 0x9e, 0xe3, 0x16, 0x82, 0x73, 0x60, 0xf1,
        0xc7, 0x5d,
    ];
    const KAT_SS: [u8; 32] = [
        0x54, 0xa0, 0xa9, 0xad, 0x37, 0x25, 0x86, 0x43, 0x12, 0xe3, 0x21, 0xbf, 0x56, 0x59, 0x3d,
        0x30, 0xc3, 0xf1, 0xba, 0x5a, 0x82, 0xf8, 0x8d, 0xc2, 0x1e, 0xa2, 0x07, 0x13, 0x9c, 0x41,
        0x48, 0xea,
    ];

    const D: [u8; 32] = [0x11; 32];
    const Z: [u8; 32] = [0x22; 32];
    const M: [u8; 32] = [0x33; 32];

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bytes);
        h.finalize().into()
    }

    #[test]
    fn constants_have_expected_lengths() {
        assert_eq!(MLKEM768_SEED_D_LEN, 32);
        assert_eq!(MLKEM768_SEED_Z_LEN, 32);
        assert_eq!(MLKEM768_ENCAP_SEED_LEN, 32);
        assert_eq!(MLKEM768_ENCAP_KEY_LEN, 1184);
        assert_eq!(MLKEM768_DECAP_KEY_LEN, 2400);
        assert_eq!(MLKEM768_CIPHERTEXT_LEN, 1088);
        assert_eq!(MLKEM768_SHARED_SECRET_LEN, 32);
    }

    #[test]
    fn round_trip_encaps_decaps() {
        let (ek, dk) = mlkem768_keygen(&D, &Z);
        let (ct, ss_e) = mlkem768_encapsulate(&ek, &M).expect("encapsulate");
        let ss_d = mlkem768_decapsulate(&dk, &ct).expect("decapsulate");
        assert_eq!(ss_e, ss_d);
    }

    #[test]
    fn keygen_is_deterministic() {
        let (ek1, dk1) = mlkem768_keygen(&D, &Z);
        let (ek2, dk2) = mlkem768_keygen(&D, &Z);
        assert_eq!(ek1, ek2);
        assert_eq!(dk1[..], dk2[..]);
    }

    #[test]
    fn encapsulation_is_deterministic() {
        let (ek, _dk) = mlkem768_keygen(&D, &Z);
        let (ct1, ss1) = mlkem768_encapsulate(&ek, &M).expect("encapsulate");
        let (ct2, ss2) = mlkem768_encapsulate(&ek, &M).expect("encapsulate");
        assert_eq!(ct1[..], ct2[..]);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn distinct_d_seeds_produce_distinct_keys() {
        let mut d2 = D;
        d2[0] ^= 0x01;
        let (ek1, _) = mlkem768_keygen(&D, &Z);
        let (ek2, _) = mlkem768_keygen(&d2, &Z);
        assert_ne!(ek1, ek2);
    }

    #[test]
    fn distinct_z_same_d_yields_same_ek_different_rejection() {
        // z is the implicit-rejection secret only: same d -> identical ek, but a
        // tampered ciphertext decapsulates to DIFFERENT rejection secrets.
        let mut z2 = Z;
        z2[0] ^= 0x01;
        let (ek1, dk1) = mlkem768_keygen(&D, &Z);
        let (ek2, dk2) = mlkem768_keygen(&D, &z2);
        assert_eq!(ek1, ek2, "ek depends only on d");
        let (mut ct, _ss) = mlkem768_encapsulate(&ek1, &M).expect("encapsulate");
        ct[0] ^= 0x01; // force the implicit-rejection path
        let r1 = mlkem768_decapsulate(&dk1, &ct).expect("decapsulate");
        let r2 = mlkem768_decapsulate(&dk2, &ct).expect("decapsulate");
        assert_ne!(r1, r2, "rejection secret differs with z");
    }

    #[test]
    fn distinct_m_produces_distinct_ct_and_ss() {
        let (ek, _dk) = mlkem768_keygen(&D, &Z);
        let mut m2 = M;
        m2[0] ^= 0x01;
        let (ct1, ss1) = mlkem768_encapsulate(&ek, &M).expect("encapsulate");
        let (ct2, ss2) = mlkem768_encapsulate(&ek, &m2).expect("encapsulate");
        assert_ne!(ct1[..], ct2[..]);
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn tampered_ciphertext_implicit_rejection_differs() {
        let (ek, dk) = mlkem768_keygen(&D, &Z);
        let (mut ct, ss) = mlkem768_encapsulate(&ek, &M).expect("encapsulate");
        ct[0] ^= 0x01;
        // NO error: implicit rejection returns Ok with a DIFFERENT secret.
        let ss_bad = mlkem768_decapsulate(&dk, &ct).expect("decapsulate must NOT error");
        assert_ne!(ss_bad, ss);
    }

    #[test]
    fn wrong_dk_decapsulation_differs() {
        let (ek, _dk) = mlkem768_keygen(&D, &Z);
        let other_d = [0x44u8; 32];
        let (_ek2, dk2) = mlkem768_keygen(&other_d, &Z);
        let (ct, ss) = mlkem768_encapsulate(&ek, &M).expect("encapsulate");
        let ss_other = mlkem768_decapsulate(&dk2, &ct).expect("decapsulate must NOT error");
        assert_ne!(ss_other, ss);
    }

    #[test]
    fn all_zero_seeds_still_round_trip() {
        // Seeds are unconstrained: every (d, z, m) is valid; totality check.
        let zero = [0u8; 32];
        let (ek, dk) = mlkem768_keygen(&zero, &zero);
        let (ct, ss_e) = mlkem768_encapsulate(&ek, &zero).expect("encapsulate");
        let ss_d = mlkem768_decapsulate(&dk, &ct).expect("decapsulate");
        assert_eq!(ss_e, ss_d);
    }

    #[test]
    fn non_canonical_encapsulation_key_is_rejected() {
        let (mut ek, _dk) = mlkem768_keygen(&D, &Z);
        // A keygen-produced ek passes the FIPS 203 §7.2 modulus check.
        assert!(mlkem768_encapsulate(&ek, &M).is_ok());
        // Force the first 12-bit coefficient to 4095 (>= q = 3329): the encoding
        // becomes non-canonical and must be rejected.
        ek[0] = 0xff;
        ek[1] |= 0x0f;
        assert_eq!(
            mlkem768_encapsulate(&ek, &M),
            Err(MlKemError::BadEncapsulationKey)
        );
    }

    /// NIST ACVP keyGen tcId 26 (ML-KEM-768): (d, z) -> official ek/dk. A TRUE
    /// interop KAT — the expected digests are SHA-256 of the official
    /// full-length ek/dk bytes from the NIST file (see provenance above).
    #[test]
    fn acvp_keygen_known_answer() {
        let (ek, dk) = mlkem768_keygen(&KAT_D, &KAT_Z);
        assert_eq!(sha256(&ek), KAT_EK_SHA256, "ek digest vs NIST ACVP");
        assert_eq!(sha256(&dk), KAT_DK_SHA256, "dk digest vs NIST ACVP");
    }

    /// Chained encaps/decaps vector: official ACVP m under the ACVP keyGen key
    /// (cross-checked by two independent implementations; see provenance above).
    #[test]
    fn chained_encaps_decaps_known_answer() {
        let (ek, dk) = mlkem768_keygen(&KAT_D, &KAT_Z);
        let (ct, ss) = mlkem768_encapsulate(&ek, &KAT_M).expect("encapsulate");
        assert_eq!(sha256(&ct), KAT_CT_SHA256, "ct digest (chained vector)");
        assert_eq!(ss, KAT_SS, "shared secret (chained vector)");
        let ss_d = mlkem768_decapsulate(&dk, &ct).expect("decapsulate");
        assert_eq!(ss_d, KAT_SS);
    }
}
