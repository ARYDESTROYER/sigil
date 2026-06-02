//! Password-based key derivation (Argon2id) that produces the 32-byte master
//! key consumed by [`crate::seal`] / [`crate::open`].
//!
//! STATUS: pre-audit. This module performs **real** key stretching with the
//! vetted RustCrypto [`argon2`] crate (Argon2id, version 0x13), but it has
//! **not** been audited and is not yet wired into a complete account-setup or
//! key-management flow — treat it as a building block, not a finished secure
//! system.
//!
//! ## Where this sits in the key chain
//!
//! Argon2id is the very first hop: it turns a low-entropy human password into a
//! high-entropy master key, which the rest of `sigil-core` then expands and uses
//! for authenticated encryption.
//!
//! ```text
//!   password ──┐
//!              ├─▶ Argon2id ─▶ master key ─▶ HKDF-SHA256 ─▶ per-record key ─▶ XChaCha20-Poly1305
//!   salt ──────┘  (this module)  (32 bytes)   (aead.rs)       (32 bytes)         (aead.rs)
//! ```
//!
//! 1. **Argon2id** (this module) stretches `password` with a caller-supplied
//!    `salt` into the 32-byte master key. The memory-hard work factor makes
//!    offline guessing of the password expensive.
//! 2. The master key is **not** used as an AEAD key directly. [`crate::seal`]
//!    derives a per-record key with `HKDF-SHA256(ikm = master_key, info =
//!    "sigil-record-v1" || suite_byte)`, binding the key to the algorithm suite.
//! 3. That per-record key drives **XChaCha20-Poly1305** to seal/open each
//!    record's envelope (see [`mod@crate::aead`]).
//!
//! ## The salt is the caller's responsibility
//!
//! `sigil-core` is `no_std` and compiles to `wasm32-unknown-unknown`, where no
//! system RNG is available, so this module **never generates randomness**. The
//! caller supplies the `salt`; it MUST be unique per password/account (a fresh
//! random salt of at least [`argon2::RECOMMENDED_SALT_LEN`] bytes is the norm)
//! and is stored alongside the encrypted data so the same master key can be
//! re-derived at unlock time. Argon2 enforces a minimum salt length and will
//! return an error for salts that are too short.
//!
//! ## Parameters
//!
//! [`Argon2Params::RECOMMENDED`] encodes the brief's work factor: 64 MiB of
//! memory (`m_cost = 65536` KiB), 4 iterations (`t_cost = 4`), and 2 lanes
//! (`p_cost = 2`). Deriving a key with these parameters intentionally takes a
//! noticeable fraction of a second; tests in this module therefore use much
//! smaller parameters and only assert the constant's *values* rather than
//! running a full 64 MiB hash.
//!
//! ## Pre-audit caveats
//!
//! - The Argon2 work factor has not been tuned against current hardware as part
//!   of an audit; [`Argon2Params::RECOMMENDED`] reflects the brief's numbers.
//! - There is no zeroization of the password, salt, or derived master key beyond
//!   what the dependencies do internally.

use argon2::{Algorithm, Argon2, Params, Version};

/// Size of the derived master key, in bytes. Matches [`crate::KEY_LEN`].
pub const MASTER_KEY_LEN: usize = 32;

/// Argon2id work-factor parameters.
///
/// All three fields map directly onto the corresponding Argon2 cost parameters:
///
/// - `m_cost`: memory size in **KiB** (kibibytes),
/// - `t_cost`: number of iterations (time cost),
/// - `p_cost`: degree of parallelism (number of lanes).
///
/// Use [`Argon2Params::RECOMMENDED`] unless you have a specific reason (such as a
/// fast unit test) to pick your own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB (kibibytes).
    pub m_cost: u32,
    /// Time cost: number of passes over memory.
    pub t_cost: u32,
    /// Parallelism: number of lanes.
    pub p_cost: u32,
}

impl Argon2Params {
    /// The recommended parameters for deriving a Sigil master key: 64 MiB of
    /// memory (`m_cost = 65536` KiB), 4 iterations, and 2 lanes.
    ///
    /// Pre-audit: these are the brief's numbers and have not been independently
    /// benchmarked or audited against current attacker hardware.
    pub const RECOMMENDED: Argon2Params = Argon2Params {
        m_cost: 65536,
        t_cost: 4,
        p_cost: 2,
    };
}

/// Errors returned by [`derive_master_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KdfError {
    /// The supplied [`Argon2Params`] were rejected by Argon2 (e.g. memory below
    /// the per-lane minimum, zero iterations, or zero lanes).
    InvalidParams,
    /// The caller-supplied salt was outside Argon2's accepted length range
    /// (too short or too long).
    InvalidSalt,
    /// Argon2id hashing failed for some other reason. Carried for completeness;
    /// the fixed 32-byte output length used here never triggers an
    /// output-length error.
    Hash,
}

/// Derive the 32-byte master key from `password` and a caller-supplied `salt`
/// using Argon2id (version 0x13) with the given work-factor `params`.
///
/// The salt is **never** generated here (see the module-level docs): the caller
/// must supply a unique salt and persist it so the master key can be re-derived
/// at unlock time.
///
/// # Errors
///
/// - [`KdfError::InvalidParams`] if `params` are out of range for Argon2.
/// - [`KdfError::InvalidSalt`] if `salt` is too short or too long.
/// - [`KdfError::Hash`] for any other Argon2 failure.
pub fn derive_master_key(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<[u8; MASTER_KEY_LEN], KdfError> {
    // `Some(MASTER_KEY_LEN)` pins the output length into the parameters so the
    // 32-byte length is bound into the Argon2 computation, not just the buffer.
    let argon_params = Params::new(
        params.m_cost,
        params.t_cost,
        params.p_cost,
        Some(MASTER_KEY_LEN),
    )
    .map_err(map_argon_err)?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut out = [0u8; MASTER_KEY_LEN];
    argon
        .hash_password_into(password, salt, &mut out)
        .map_err(map_argon_err)?;

    Ok(out)
}

/// Map an [`argon2::Error`] onto our coarser [`KdfError`].
fn map_argon_err(e: argon2::Error) -> KdfError {
    use argon2::Error as E;
    match e {
        E::MemoryTooLittle
        | E::MemoryTooMuch
        | E::TimeTooSmall
        | E::ThreadsTooFew
        | E::ThreadsTooMany
        | E::AlgorithmInvalid
        | E::VersionInvalid => KdfError::InvalidParams,
        E::SaltTooShort | E::SaltTooLong => KdfError::InvalidSalt,
        _ => KdfError::Hash,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fast parameters for the determinism/difference tests. 8 KiB of memory and
    /// a single pass/lane keep these tests near-instant while still exercising
    /// the real Argon2id code path. (Argon2 requires `m_cost >= 8 * p_cost`.)
    const FAST: Argon2Params = Argon2Params {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    };

    // A salt long enough to satisfy Argon2's minimum (>= 8 bytes).
    const SALT_A: &[u8] = b"salt-aaaa-0001";
    const SALT_B: &[u8] = b"salt-bbbb-0002";

    #[test]
    fn recommended_constant_matches_brief() {
        assert_eq!(Argon2Params::RECOMMENDED.m_cost, 65536);
        assert_eq!(Argon2Params::RECOMMENDED.t_cost, 4);
        assert_eq!(Argon2Params::RECOMMENDED.p_cost, 2);
    }

    #[test]
    fn master_key_len_is_32() {
        assert_eq!(MASTER_KEY_LEN, 32);
    }

    #[test]
    fn derivation_is_deterministic() {
        let k1 = derive_master_key(b"correct horse battery staple", SALT_A, FAST)
            .expect("derive succeeds");
        let k2 = derive_master_key(b"correct horse battery staple", SALT_A, FAST)
            .expect("derive succeeds");
        assert_eq!(k1, k2);
        assert_eq!(k1.len(), MASTER_KEY_LEN);
    }

    #[test]
    fn different_salt_yields_different_key() {
        let k1 = derive_master_key(b"same password", SALT_A, FAST).expect("derive succeeds");
        let k2 = derive_master_key(b"same password", SALT_B, FAST).expect("derive succeeds");
        assert_ne!(k1, k2);
    }

    #[test]
    fn different_password_yields_different_key() {
        let k1 = derive_master_key(b"password one", SALT_A, FAST).expect("derive succeeds");
        let k2 = derive_master_key(b"password two", SALT_A, FAST).expect("derive succeeds");
        assert_ne!(k1, k2);
    }

    #[test]
    fn too_short_salt_is_rejected() {
        // Argon2's minimum salt length is 8 bytes; a 1-byte salt must error.
        let err = derive_master_key(b"pw", b"x", FAST).expect_err("short salt rejected");
        assert_eq!(err, KdfError::InvalidSalt);
    }

    #[test]
    fn invalid_params_are_rejected() {
        // p_cost = 0 is below Argon2's minimum of 1 lane.
        let bad = Argon2Params {
            m_cost: 8,
            t_cost: 1,
            p_cost: 0,
        };
        let err = derive_master_key(b"pw", SALT_A, bad).expect_err("bad params rejected");
        assert_eq!(err, KdfError::InvalidParams);
    }
}
