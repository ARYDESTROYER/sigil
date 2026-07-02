//! Hybrid X25519 & ML-KEM-768 key encapsulation (X-Wing,
//! draft-connolly-cfrg-xwing-kem-10) — the combine of the two halves named by
//! suite `0x12`.
//!
//! STATUS: pre-audit. This module performs a **real** X-Wing combine of
//! [`crate::kex`] (X25519) and [`crate::mlkem`] (ML-KEM-768), but it has
//! **not** been audited and is **not** wired into the envelope,
//! `seal_record`/`open_record`, or any product flow — the envelope's reserved
//! `kem_ct` field stays `None`, and sealed records still gain no post-quantum
//! protection. Treat it as a building block, not a finished secure system.
//!
//! ## Why X-Wing, not a bespoke combiner
//!
//! X-Wing is the IETF CFRG draft specifying exactly this hybrid (pre-RFC, an
//! individual draft — not a NIST or IETF standard; its ML-KEM-768 component is
//! FIPS 203), with a formal IND-CCA proof and official test vectors: breaking
//! the combined KEM requires breaking **both** X25519 and ML-KEM-768. The
//! shared secret is
//! `SHA3-256(ss_ML-KEM ‖ ss_X25519 ‖ ct_X25519 ‖ pk_X25519 ‖ label)`, label =
//! the 6 ASCII bytes `\.//^\`. The ML-KEM key/ciphertext are deliberately NOT
//! hashed — the proof leans on ML-KEM's ciphertext binding, so this shortcut is
//! **not generic and must never be reused with a different PQ KEM**. The
//! combiner's byte order changed between draft revisions (the label moved to
//! the END in revision -05) — always match the vendored official vectors,
//! never "fix" the order by eye.
//!
//! ## Randomness is the caller's responsibility
//!
//! `sigil-core` is `no_std`/wasm and **never generates randomness**: keygen
//! takes one caller-supplied 32-byte seed, expanded via SHAKE-256 into the
//! ML-KEM `(d, z)` seeds and the X25519 secret; encapsulation takes 64 fresh
//! one-time bytes (`m ‖ ephemeral X25519 secret`). All MUST come from a
//! cryptographically secure source, and the 64-byte `eseed` MUST be fresh per
//! encapsulation. **The 32-byte seed IS the decapsulation key** — store it
//! (and protect it) as such; the expanded components are re-derived on demand
//! and never stored. Sizes: ek 1216, dk 32 (the seed), ct 1120, ss 32.
//!
//! ## Implicit rejection is inherited (READ THIS)
//!
//! Decapsulating a tampered ciphertext does **not** error: the ML-KEM half
//! implicitly rejects to a pseudorandom secret and X25519 never fails, so the
//! combined secret is silently wrong. The mismatch surfaces only downstream
//! (e.g. an AEAD open fails). Per the draft, **no contributory/low-order check
//! is applied** to the X25519 ciphertext — the proof covers this because the
//! combiner binds `ct_X ‖ pk_X`; adding a rejection would deviate from the
//! analyzed construction and create an explicit rejection oracle.
//!
//! ## Pre-audit caveats
//!
//! - The draft is not yet an RFC; this module pins draft-10 semantics (the
//!   combiner has been byte-exact since -05) and its official test vectors.
//! - There is no zeroization of the 32-byte seed, the SHAKE-256-expanded
//!   secrets (the ML-KEM `d`/`z` and the X25519 secret scalar), or the
//!   component/combined shared secrets beyond what the dependencies do
//!   internally — the same documented policy as every other module here.
//! - Unaudited; not wired into the envelope, record, or any product flow.

use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};

use crate::kex::{x25519_public_key, x25519_shared_secret, KEX_PUBLIC_KEY_LEN, KEX_SECRET_LEN};
use crate::mlkem::{
    mlkem768_decapsulate, mlkem768_encapsulate, mlkem768_keygen, MlKemError,
    MLKEM768_CIPHERTEXT_LEN, MLKEM768_ENCAP_KEY_LEN, MLKEM768_SHARED_SECRET_LEN,
};

/// Length, in bytes, of the X-Wing key-generation seed — which **is** the
/// decapsulation key (it is SHAKE-256-expanded to 96 bytes: ML-KEM `d` ‖ `z` ‖
/// the X25519 secret).
pub const XWING_SEED_LEN: usize = 32;
/// Length, in bytes, of the X-Wing decapsulation key (= the 32-byte seed).
pub const XWING_DECAP_KEY_LEN: usize = XWING_SEED_LEN;
/// Length, in bytes, of the one-time encapsulation randomness:
/// `eseed[0..32]` = the ML-KEM message `m`, `eseed[32..64]` = the ephemeral
/// X25519 secret.
pub const XWING_ENCAP_SEED_LEN: usize = 64;
/// Length, in bytes, of an X-Wing encapsulation key: ML-KEM-768 ek (1184) ‖
/// X25519 public key (32).
pub const XWING_ENCAP_KEY_LEN: usize = MLKEM768_ENCAP_KEY_LEN + KEX_PUBLIC_KEY_LEN;
/// Length, in bytes, of an X-Wing ciphertext: ML-KEM-768 ct (1088) ‖ the
/// ephemeral X25519 public key (32).
pub const XWING_CIPHERTEXT_LEN: usize = MLKEM768_CIPHERTEXT_LEN + KEX_PUBLIC_KEY_LEN;
/// Length, in bytes, of the combined X-Wing shared secret (SHA3-256 output).
pub const XWING_SHARED_SECRET_LEN: usize = 32;
/// The 6-byte X-Wing combiner label, the ASCII bytes `\.//^\`
/// (hex `5c 2e 2f 2f 5e 5c`). Hashed LAST (draft revision -05 onward).
pub const XWING_LABEL: [u8; 6] = *br"\.//^\";

/// Errors returned by the X-Wing hybrid primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum XWingError {
    /// The ML-KEM-768 half failed — in practice only the FIPS 203 §7.2
    /// encapsulation-key modulus check on [`xwing_encapsulate`]
    /// ([`MlKemError::BadEncapsulationKey`]); the other variant is the
    /// structurally-unreachable defensive [`MlKemError::Internal`].
    MlKem(MlKemError),
}

impl From<MlKemError> for XWingError {
    fn from(e: MlKemError) -> Self {
        XWingError::MlKem(e)
    }
}

/// SHAKE-256-expand the 32-byte seed into (ML-KEM `d`, ML-KEM `z`, X25519 sk),
/// exactly as X-Wing's `expandDecapsulationKey` prescribes.
fn expand_seed(seed: &[u8; XWING_SEED_LEN]) -> ([u8; 32], [u8; 32], [u8; KEX_SECRET_LEN]) {
    let mut xof = Shake256::default();
    xof.update(seed);
    let mut expanded = [0u8; 96];
    xof.finalize_xof().read(&mut expanded);
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    let mut sk_x = [0u8; KEX_SECRET_LEN];
    d.copy_from_slice(&expanded[0..32]);
    z.copy_from_slice(&expanded[32..64]);
    sk_x.copy_from_slice(&expanded[64..96]);
    (d, z, sk_x)
}

/// The X-Wing combiner:
/// `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWING_LABEL)` — label LAST.
fn combiner(
    ss_m: &[u8; MLKEM768_SHARED_SECRET_LEN],
    ss_x: &[u8; 32],
    ct_x: &[u8; KEX_PUBLIC_KEY_LEN],
    pk_x: &[u8; KEX_PUBLIC_KEY_LEN],
) -> [u8; XWING_SHARED_SECRET_LEN] {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, XWING_LABEL);
    h.finalize().into()
}

/// X-Wing key generation over the caller-supplied 32-byte `seed`, which **is**
/// the decapsulation key. Deterministic and total: the same seed always yields
/// the same 1216-byte encapsulation key (`ML-KEM ek ‖ X25519 pk`).
///
/// The seed is the caller's secret key material (see the module-level docs);
/// this function never generates it. Persist the seed itself — the expanded
/// components are re-derived on demand.
#[must_use]
pub fn xwing_keygen(seed: &[u8; XWING_SEED_LEN]) -> [u8; XWING_ENCAP_KEY_LEN] {
    let (d, z, sk_x) = expand_seed(seed);
    let (ek_m, _dk_m) = mlkem768_keygen(&d, &z);
    let pk_x = x25519_public_key(&sk_x);
    let mut ek = [0u8; XWING_ENCAP_KEY_LEN];
    ek[..MLKEM768_ENCAP_KEY_LEN].copy_from_slice(&ek_m);
    ek[MLKEM768_ENCAP_KEY_LEN..].copy_from_slice(&pk_x);
    ek
}

/// X-Wing encapsulation to `encap_key` using the caller-supplied 64-byte
/// one-time randomness `eseed` (`m ‖ ephemeral X25519 secret`). Deterministic:
/// the same `(encap_key, eseed)` always yields the same `(ciphertext, shared
/// secret)` — `eseed` MUST be fresh per encapsulation.
///
/// # Errors
/// - [`XWingError::MlKem`]`(`[`MlKemError::BadEncapsulationKey`]`)` if the
///   ML-KEM half of `encap_key` fails the FIPS 203 §7.2 modulus check (the
///   only reachable error).
pub fn xwing_encapsulate(
    encap_key: &[u8; XWING_ENCAP_KEY_LEN],
    eseed: &[u8; XWING_ENCAP_SEED_LEN],
) -> Result<([u8; XWING_CIPHERTEXT_LEN], [u8; XWING_SHARED_SECRET_LEN]), XWingError> {
    // Split the encapsulation key and the one-time randomness (fixed-size
    // array operations only; the slices are statically in range).
    let mut ek_m = [0u8; MLKEM768_ENCAP_KEY_LEN];
    let mut pk_x = [0u8; KEX_PUBLIC_KEY_LEN];
    ek_m.copy_from_slice(&encap_key[..MLKEM768_ENCAP_KEY_LEN]);
    pk_x.copy_from_slice(&encap_key[MLKEM768_ENCAP_KEY_LEN..]);
    let mut m = [0u8; 32];
    let mut ek_x = [0u8; KEX_SECRET_LEN];
    m.copy_from_slice(&eseed[0..32]);
    ek_x.copy_from_slice(&eseed[32..64]);

    // ML-KEM half (may reject a non-canonical ek per FIPS 203 §7.2).
    let (ct_m, ss_m) = mlkem768_encapsulate(&ek_m, &m)?;
    // X25519 half: the "ciphertext" is the ephemeral public key.
    let ct_x = x25519_public_key(&ek_x);
    let ss_x = x25519_shared_secret(&ek_x, &pk_x);

    let ss = combiner(&ss_m, &ss_x, &ct_x, &pk_x);
    let mut ct = [0u8; XWING_CIPHERTEXT_LEN];
    ct[..MLKEM768_CIPHERTEXT_LEN].copy_from_slice(&ct_m);
    ct[MLKEM768_CIPHERTEXT_LEN..].copy_from_slice(&ct_x);
    Ok((ct, ss))
}

/// X-Wing decapsulation. The 32-byte `seed` is the decapsulation key; the
/// expanded components (ML-KEM dk, X25519 sk and pk) are re-derived here.
///
/// **IMPLICIT REJECTION:** a tampered/mismatched ciphertext does NOT error —
/// the ML-KEM half rejects to a pseudorandom secret and the X25519 half is
/// total, so this returns `Ok` with a *different* shared secret. There is no
/// reachable error by design (an explicit failure would be a CCA oracle);
/// never treat decapsulation success as authentication.
///
/// # Errors
/// - [`XWingError::MlKem`]`(`[`MlKemError::Internal`]`)` is structurally
///   unreachable (defensive absorption only).
pub fn xwing_decapsulate(
    seed: &[u8; XWING_SEED_LEN],
    ciphertext: &[u8; XWING_CIPHERTEXT_LEN],
) -> Result<[u8; XWING_SHARED_SECRET_LEN], XWingError> {
    let (d, z, sk_x) = expand_seed(seed);
    let (_ek_m, dk_m) = mlkem768_keygen(&d, &z);
    // pk_X is part of the combiner input but never stored: re-derive it.
    let pk_x = x25519_public_key(&sk_x);

    let mut ct_m = [0u8; MLKEM768_CIPHERTEXT_LEN];
    let mut ct_x = [0u8; KEX_PUBLIC_KEY_LEN];
    ct_m.copy_from_slice(&ciphertext[..MLKEM768_CIPHERTEXT_LEN]);
    ct_x.copy_from_slice(&ciphertext[MLKEM768_CIPHERTEXT_LEN..]);

    let ss_m = mlkem768_decapsulate(&dk_m, &ct_m)?;
    // Total; deliberately NO low-order/contributory check (see module docs).
    let ss_x = x25519_shared_secret(&sk_x, &ct_x);

    Ok(combiner(&ss_m, &ss_x, &ct_x, &pk_x))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest as Sha2Digest, Sha256};

    // ---- Official X-Wing test vectors --------------------------------------
    //
    // Provenance: github.com/dconnolly/draft-connolly-cfrg-xwing-kem,
    // spec/test-vectors.json (the file the draft's Test Vectors appendix and the
    // RustCrypto x-wing crate KAT against; byte-identical for draft -05 through
    // -10). The file was re-downloaded first-hand and verified identical to the
    // research-vendored copy before these literals were generated MECHANICALLY
    // from it (seed/eseed/ss verbatim; the 1216-byte pk and 1120-byte ct pinned
    // as SHA-256 digests of the official full-length bytes). The SHAKE-256
    // seed-expansion intermediates below were verified against an independent
    // implementation (python hashlib.shake_256).
    const KAT1_SEED: [u8; 32] = [
        0x7f, 0x9c, 0x2b, 0xa4, 0xe8, 0x8f, 0x82, 0x7d, 0x61, 0x60, 0x45, 0x50, 0x76, 0x05, 0x85,
        0x3e, 0xd7, 0x3b, 0x80, 0x93, 0xf6, 0xef, 0xbc, 0x88, 0xeb, 0x1a, 0x6e, 0xac, 0xfa, 0x66,
        0xef, 0x26,
    ];
    const KAT1_ESEED: [u8; 64] = [
        0x3c, 0xb1, 0xee, 0xa9, 0x88, 0x00, 0x4b, 0x93, 0x10, 0x3c, 0xfb, 0x0a, 0xee, 0xfd, 0x2a,
        0x68, 0x6e, 0x01, 0xfa, 0x4a, 0x58, 0xe8, 0xa3, 0x63, 0x9c, 0xa8, 0xa1, 0xe3, 0xf9, 0xae,
        0x57, 0xe2, 0x35, 0xb8, 0xcc, 0x87, 0x3c, 0x23, 0xdc, 0x62, 0xb8, 0xd2, 0x60, 0x16, 0x9a,
        0xfa, 0x2f, 0x75, 0xab, 0x91, 0x6a, 0x58, 0xd9, 0x74, 0x91, 0x88, 0x35, 0xd2, 0x5e, 0x6a,
        0x43, 0x50, 0x85, 0xb2,
    ];
    const KAT1_SS: [u8; 32] = [
        0xd2, 0xdf, 0x05, 0x22, 0x12, 0x8f, 0x09, 0xdd, 0x8e, 0x2c, 0x92, 0xb1, 0xe9, 0x05, 0xc7,
        0x93, 0xd8, 0xf5, 0x7a, 0x54, 0xc3, 0xda, 0x25, 0x86, 0x1f, 0x10, 0xbf, 0x4c, 0xa6, 0x13,
        0xe3, 0x84,
    ];
    const KAT1_PK_SHA256: [u8; 32] = [
        0x2e, 0x81, 0x6d, 0xee, 0xbc, 0xd7, 0x6c, 0x5c, 0x80, 0xd0, 0xcd, 0x2d, 0x17, 0x44, 0x78,
        0x87, 0x16, 0x58, 0xe8, 0xe2, 0xff, 0x42, 0xbc, 0x9d, 0x4a, 0x6e, 0x48, 0x63, 0x72, 0xe8,
        0x56, 0xbb,
    ];
    const KAT1_CT_SHA256: [u8; 32] = [
        0x17, 0xcd, 0x53, 0x2d, 0x65, 0x7e, 0x44, 0xc8, 0x97, 0xca, 0x65, 0x83, 0xe5, 0x48, 0xa5,
        0x42, 0x4f, 0xc7, 0x0b, 0xf5, 0x4f, 0x99, 0x51, 0x5a, 0x4d, 0x2b, 0xcf, 0x99, 0xe3, 0x46,
        0x9f, 0x33,
    ];
    const KAT2_SEED: [u8; 32] = [
        0xba, 0xdf, 0xd6, 0xdf, 0xaa, 0xc3, 0x59, 0xa5, 0xef, 0xbb, 0x7b, 0xcc, 0x4b, 0x59, 0xd5,
        0x38, 0xdf, 0x9a, 0x04, 0x30, 0x2e, 0x10, 0xc8, 0xbc, 0x1c, 0xbf, 0x1a, 0x0b, 0x3a, 0x51,
        0x20, 0xea,
    ];
    const KAT2_ESEED: [u8; 64] = [
        0x17, 0xcd, 0xa7, 0xcf, 0xad, 0x76, 0x5f, 0x56, 0x23, 0x47, 0x4d, 0x36, 0x8c, 0xcc, 0xa8,
        0xaf, 0x00, 0x07, 0xcd, 0x9f, 0x5e, 0x4c, 0x84, 0x9f, 0x16, 0x7a, 0x58, 0x0b, 0x14, 0xaa,
        0xbd, 0xef, 0xae, 0xe7, 0xee, 0xf4, 0x7c, 0xb0, 0xfc, 0xa9, 0x76, 0x7b, 0xe1, 0xfd, 0xa6,
        0x94, 0x19, 0xdf, 0xb9, 0x27, 0xe9, 0xdf, 0x07, 0x34, 0x8b, 0x19, 0x66, 0x91, 0xab, 0xae,
        0xb5, 0x80, 0xb3, 0x2d,
    ];
    const KAT2_SS: [u8; 32] = [
        0xf2, 0xe8, 0x62, 0x41, 0xc6, 0x4d, 0x60, 0xf6, 0x64, 0x9f, 0xbc, 0x6c, 0x5b, 0x7d, 0x17,
        0x18, 0x0b, 0x78, 0x0a, 0x3f, 0x34, 0x35, 0x5e, 0x64, 0xa8, 0x57, 0x49, 0x94, 0x9c, 0x45,
        0xf1, 0x50,
    ];
    const KAT2_PK_SHA256: [u8; 32] = [
        0xc4, 0x2b, 0xa5, 0xf8, 0x43, 0x0d, 0x7d, 0x2c, 0x83, 0x73, 0x93, 0x38, 0x20, 0x38, 0x19,
        0xf0, 0x90, 0xe8, 0x30, 0x3c, 0xe9, 0xc8, 0xb0, 0x21, 0x07, 0xc2, 0x72, 0xbf, 0xa5, 0x37,
        0x69, 0x16,
    ];
    const KAT2_CT_SHA256: [u8; 32] = [
        0x16, 0x61, 0xea, 0x86, 0xd6, 0x08, 0xa1, 0x92, 0x4b, 0xa3, 0x08, 0x40, 0xcb, 0x0a, 0x65,
        0xf1, 0x3a, 0xe0, 0x51, 0xe3, 0xae, 0xc9, 0xcf, 0x0f, 0x06, 0x4e, 0xfc, 0x0b, 0xc9, 0x2f,
        0x21, 0x54,
    ];
    const KAT3_SEED: [u8; 32] = [
        0xef, 0x58, 0x53, 0x8b, 0x8d, 0x23, 0xf8, 0x77, 0x32, 0xea, 0x63, 0xb0, 0x2b, 0x4f, 0xa0,
        0xf4, 0x87, 0x33, 0x60, 0xe2, 0x84, 0x19, 0x28, 0xcd, 0x60, 0xdd, 0x4c, 0xee, 0x8c, 0xc0,
        0xd4, 0xc9,
    ];
    const KAT3_ESEED: [u8; 64] = [
        0x22, 0xa9, 0x61, 0x88, 0xd0, 0x32, 0x67, 0x5c, 0x8a, 0xc8, 0x50, 0x93, 0x3c, 0x7a, 0xff,
        0x15, 0x33, 0xb9, 0x4c, 0x83, 0x4a, 0xdb, 0xb6, 0x9c, 0x61, 0x15, 0xba, 0xd4, 0x69, 0x2d,
        0x86, 0x19, 0xf9, 0x0b, 0x0c, 0xdf, 0x8a, 0x7b, 0x9c, 0x26, 0x40, 0x29, 0xac, 0x18, 0x5b,
        0x70, 0xb8, 0x3f, 0x28, 0x01, 0xf2, 0xf4, 0xb3, 0xf7, 0x0c, 0x59, 0x3e, 0xa3, 0xae, 0xeb,
        0x61, 0x3a, 0x7f, 0x1b,
    ];
    const KAT3_SS: [u8; 32] = [
        0x95, 0x3f, 0x7f, 0x4e, 0x8c, 0x5b, 0x50, 0x49, 0xbd, 0xc7, 0x71, 0xd1, 0xdf, 0xfa, 0xda,
        0x0d, 0xd9, 0x61, 0x47, 0x7d, 0x1a, 0x2a, 0xe0, 0x98, 0x8b, 0xaa, 0x7e, 0xa6, 0x89, 0x8d,
        0x89, 0x3f,
    ];
    const KAT3_PK_SHA256: [u8; 32] = [
        0x6b, 0x08, 0x0d, 0x6b, 0x84, 0xf0, 0x95, 0x34, 0x20, 0x92, 0xfa, 0x7a, 0x22, 0x42, 0x3e,
        0x58, 0xbd, 0x68, 0x13, 0x97, 0xad, 0x0e, 0xf0, 0x0e, 0xac, 0x92, 0xbd, 0x25, 0x4d, 0xb4,
        0xfa, 0x95,
    ];
    const KAT3_CT_SHA256: [u8; 32] = [
        0xd3, 0xca, 0x55, 0x78, 0x50, 0x03, 0x44, 0xb5, 0x89, 0x6c, 0xff, 0xc4, 0xfd, 0x74, 0x0c,
        0x93, 0x11, 0x94, 0x6b, 0x82, 0x95, 0x1d, 0xf1, 0x55, 0xe6, 0xfd, 0x86, 0xa7, 0x96, 0x6b,
        0x43, 0xc6,
    ];
    const KAT1_EXP_D: [u8; 32] = [
        0xc4, 0x48, 0x29, 0xd2, 0xb2, 0x69, 0x88, 0x7f, 0x61, 0x50, 0xdf, 0xae, 0xe5, 0xa2, 0x5a,
        0x70, 0x4c, 0xbc, 0x60, 0x7e, 0x57, 0xd1, 0x8a, 0x2f, 0xfc, 0x87, 0x34, 0x63, 0x33, 0x33,
        0xcf, 0xf0,
    ];
    const KAT1_EXP_Z: [u8; 32] = [
        0xf0, 0xfc, 0x6f, 0xa4, 0xe4, 0x82, 0x75, 0x31, 0x16, 0x80, 0x87, 0xef, 0x22, 0x3e, 0x9b,
        0x07, 0x0c, 0x5a, 0x78, 0xa7, 0x89, 0xfd, 0x46, 0xd4, 0xc6, 0x04, 0xd6, 0x9b, 0x11, 0x39,
        0xd4, 0xda,
    ];
    const KAT1_EXP_SKX: [u8; 32] = [
        0xcd, 0x3f, 0x2c, 0xce, 0x66, 0xed, 0x13, 0x0e, 0x5e, 0x73, 0xa0, 0xeb, 0xd4, 0x54, 0xe1,
        0x54, 0x88, 0x88, 0x5a, 0x2a, 0x15, 0x44, 0x25, 0x2a, 0x20, 0xe0, 0xf5, 0x8b, 0x6e, 0x8f,
        0xc2, 0x7b,
    ];

    const SEED: [u8; XWING_SEED_LEN] = [0x11; XWING_SEED_LEN];
    const ESEED: [u8; XWING_ENCAP_SEED_LEN] = [0x22; XWING_ENCAP_SEED_LEN];

    fn sha256(bytes: &[u8]) -> [u8; 32] {
        let mut h = Sha256::new();
        Sha2Digest::update(&mut h, bytes);
        h.finalize().into()
    }

    #[test]
    fn constants_have_expected_lengths() {
        assert_eq!(XWING_SEED_LEN, 32);
        assert_eq!(XWING_DECAP_KEY_LEN, 32);
        assert_eq!(XWING_ENCAP_SEED_LEN, 64);
        assert_eq!(XWING_ENCAP_KEY_LEN, 1216);
        assert_eq!(XWING_CIPHERTEXT_LEN, 1120);
        assert_eq!(XWING_SHARED_SECRET_LEN, 32);
    }

    #[test]
    fn label_is_pinned() {
        // The 6 ASCII bytes `\.//^\`, hashed LAST. A raw-string typo here would
        // silently produce a different (wrong) combiner.
        assert_eq!(XWING_LABEL, [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
    }

    #[test]
    fn round_trip_encaps_decaps() {
        let ek = xwing_keygen(&SEED);
        let (ct, ss_e) = xwing_encapsulate(&ek, &ESEED).expect("encapsulate");
        let ss_d = xwing_decapsulate(&SEED, &ct).expect("decapsulate");
        assert_eq!(ss_e, ss_d);
    }

    #[test]
    fn keygen_is_deterministic() {
        assert_eq!(xwing_keygen(&SEED)[..], xwing_keygen(&SEED)[..]);
    }

    #[test]
    fn encapsulation_is_deterministic() {
        let ek = xwing_keygen(&SEED);
        let (ct1, ss1) = xwing_encapsulate(&ek, &ESEED).expect("encapsulate");
        let (ct2, ss2) = xwing_encapsulate(&ek, &ESEED).expect("encapsulate");
        assert_eq!(ct1[..], ct2[..]);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn seed_expansion_known_answer() {
        // Pins the SHAKE-256(seed, 96) -> d || z || sk_X split against values
        // verified with an independent implementation (python hashlib).
        let (d, z, sk_x) = expand_seed(&KAT1_SEED);
        assert_eq!(d, KAT1_EXP_D);
        assert_eq!(z, KAT1_EXP_Z);
        assert_eq!(sk_x, KAT1_EXP_SKX);
    }

    #[test]
    fn xwing_official_known_answer() {
        // All three official vectors, both directions.
        for (i, (seed, eseed, ss, pk_digest, ct_digest)) in [
            (
                KAT1_SEED,
                KAT1_ESEED,
                KAT1_SS,
                KAT1_PK_SHA256,
                KAT1_CT_SHA256,
            ),
            (
                KAT2_SEED,
                KAT2_ESEED,
                KAT2_SS,
                KAT2_PK_SHA256,
                KAT2_CT_SHA256,
            ),
            (
                KAT3_SEED,
                KAT3_ESEED,
                KAT3_SS,
                KAT3_PK_SHA256,
                KAT3_CT_SHA256,
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let ek = xwing_keygen(&seed);
            assert_eq!(sha256(&ek), pk_digest, "vector {} pk digest", i + 1);
            let (ct, ss_e) = xwing_encapsulate(&ek, &eseed).expect("encapsulate");
            assert_eq!(sha256(&ct), ct_digest, "vector {} ct digest", i + 1);
            assert_eq!(ss_e, ss, "vector {} encaps ss", i + 1);
            let ss_d = xwing_decapsulate(&seed, &ct).expect("decapsulate");
            assert_eq!(ss_d, ss, "vector {} decaps ss", i + 1);
        }
    }

    #[test]
    fn tampered_mlkem_ciphertext_implicit_rejection_differs() {
        let ek = xwing_keygen(&SEED);
        let (mut ct, ss) = xwing_encapsulate(&ek, &ESEED).expect("encapsulate");
        ct[0] ^= 0x01; // inside the ML-KEM half
        let ss_bad = xwing_decapsulate(&SEED, &ct).expect("decapsulate must NOT error");
        assert_ne!(ss_bad, ss);
    }

    #[test]
    fn tampered_x25519_ciphertext_changes_ss() {
        // Cross-half independence: the combiner binds ct_X, so flipping a byte
        // in the X25519 half changes the secret even though the ML-KEM half
        // still agrees.
        let ek = xwing_keygen(&SEED);
        let (mut ct, ss) = xwing_encapsulate(&ek, &ESEED).expect("encapsulate");
        ct[MLKEM768_CIPHERTEXT_LEN] ^= 0x01; // first byte of ct_X
        let ss_bad = xwing_decapsulate(&SEED, &ct).expect("decapsulate must NOT error");
        assert_ne!(ss_bad, ss);
    }

    #[test]
    fn wrong_seed_decapsulation_differs() {
        let ek = xwing_keygen(&SEED);
        let (ct, ss) = xwing_encapsulate(&ek, &ESEED).expect("encapsulate");
        let other = [0x99u8; XWING_SEED_LEN];
        let ss_other = xwing_decapsulate(&other, &ct).expect("decapsulate must NOT error");
        assert_ne!(ss_other, ss);
    }

    #[test]
    fn distinct_seeds_produce_distinct_keys() {
        let mut seed2 = SEED;
        seed2[0] ^= 0x01;
        assert_ne!(xwing_keygen(&SEED)[..], xwing_keygen(&seed2)[..]);
    }

    #[test]
    fn distinct_eseeds_produce_distinct_ct_and_ss() {
        let ek = xwing_keygen(&SEED);
        let mut eseed2 = ESEED;
        eseed2[0] ^= 0x01;
        let (ct1, ss1) = xwing_encapsulate(&ek, &ESEED).expect("encapsulate");
        let (ct2, ss2) = xwing_encapsulate(&ek, &eseed2).expect("encapsulate");
        assert_ne!(ct1[..], ct2[..]);
        assert_ne!(ss1, ss2);
    }

    #[test]
    fn all_zero_seed_still_round_trips() {
        // Totality: every seed/eseed is valid; no panic anywhere.
        let zero_seed = [0u8; XWING_SEED_LEN];
        let zero_eseed = [0u8; XWING_ENCAP_SEED_LEN];
        let ek = xwing_keygen(&zero_seed);
        let (ct, ss_e) = xwing_encapsulate(&ek, &zero_eseed).expect("encapsulate");
        let ss_d = xwing_decapsulate(&zero_seed, &ct).expect("decapsulate");
        assert_eq!(ss_e, ss_d);
    }

    #[test]
    fn bad_mlkem_half_rejected() {
        // A non-canonical ML-KEM coefficient in the hybrid ek must surface the
        // FIPS 203 s7.2 rejection through the hybrid error type.
        let mut ek = xwing_keygen(&SEED);
        ek[0] = 0xff;
        ek[1] |= 0x0f; // first 12-bit coefficient >= q
        assert_eq!(
            xwing_encapsulate(&ek, &ESEED),
            Err(XWingError::MlKem(MlKemError::BadEncapsulationKey))
        );
    }
}
