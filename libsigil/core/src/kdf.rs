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

    /// ⛔ Upper bound on `m_cost`, in KiB: **262 144 KiB = 256 MiB**.
    ///
    /// Argon2id allocates `m_cost` KiB in ONE block before it does any work, so
    /// an unbounded `m_cost` read out of an attacker-supplied container header is
    /// a remote denial of service: `m_cost = 0xFFFF_FFF0` asks for ~4 TiB and the
    /// process dies on allocation, every time it retries. Sigil's containers
    /// arrive over a **zero-knowledge relay** (`sigild` stores opaque blobs and
    /// deliberately cannot inspect, let alone filter, them), so anyone who can put
    /// bytes in a user's op-log — a revoked-but-not-yet-rotated device, a co-tenant
    /// of a shared vault, a breached server — can otherwise stop that user reaching
    /// their own 2FA codes. The bound therefore has to be enforced **client-side,
    /// at parse time, before any allocation**.
    ///
    /// Why 256 MiB specifically:
    ///
    /// - It is **4× the largest value anything in this repo writes**
    ///   ([`Argon2Params::RECOMMENDED`], 64 MiB) and ~13× what the browser clients
    ///   write (19 MiB), so it leaves room to raise the work factor several times
    ///   over without a format break or a flag day. Nothing that opens today stops
    ///   opening.
    /// - It is comfortably above OWASP's highest current Argon2id recommendation
    ///   (46–64 MiB), so it does not cap us below the state of the practice.
    /// - It is a single allocation a **low-end phone** can still survive. The
    ///   ceiling is chosen for the weakest client that must open the vault, not for
    ///   a developer laptop: a mobile browser tab or an MV3 extension page that
    ///   asks for a gigabyte is killed by the platform, and a user whose phone
    ///   cannot open their vault is locked out just as surely as by a crash.
    ///
    /// This is a **ceiling only** — there is deliberately no floor here beyond
    /// Argon2's own minimums, because a low work factor is a weak container, not a
    /// dangerous one, and refusing to open it would lock out data rather than
    /// protect it. (The anti-downgrade rule belongs at the re-seal step, where new
    /// parameters are chosen: see `sigil_cli::reseal_container`.)
    pub const MAX_M_COST: u32 = 262_144;

    /// ⛔ Upper bound on `t_cost` (passes): **16**.
    ///
    /// Time cost is linear in CPU work and allocates nothing, so it cannot crash a
    /// client — but combined with [`Self::MAX_M_COST`] it bounds the worst case a
    /// hostile container can impose on one open attempt (256 MiB × 16 passes, a
    /// handful of seconds) instead of leaving it unbounded. 16 is 4× the 4 passes
    /// of [`Argon2Params::RECOMMENDED`].
    pub const MAX_T_COST: u32 = 16;

    /// ⛔ Upper bound on `p_cost` (lanes): **16**.
    ///
    /// 8× the 2 lanes of [`Argon2Params::RECOMMENDED`]. Argon2 itself caps lanes
    /// far higher (2^24 − 1); no Sigil client has a reason to go past a small
    /// multiple of the core count, and each lane is a thread's worth of work.
    pub const MAX_P_COST: u32 = 16;

    /// Range-check the three work factors against the ceilings above.
    ///
    /// ⭐ Call this **before** handing parameters to Argon2 — it is the check that
    /// makes a hostile container a rejected parse instead of a failed allocation.
    /// [`derive_master_key`] calls it first thing, so every `sigil-core` caller
    /// gets the bound for free; container parsers should ALSO call it at parse
    /// time so they can report a precise, typed error rather than a generic KDF
    /// failure.
    ///
    /// # Errors
    ///
    /// [`KdfError::ParamsTooLarge`] if any of `m_cost` / `t_cost` / `p_cost`
    /// exceeds its ceiling. Values that are merely *invalid* (zero lanes, memory
    /// below the per-lane minimum) are left to Argon2 itself, which reports them
    /// as [`KdfError::InvalidParams`].
    pub const fn validate(&self) -> Result<(), KdfError> {
        if self.m_cost > Self::MAX_M_COST
            || self.t_cost > Self::MAX_T_COST
            || self.p_cost > Self::MAX_P_COST
        {
            return Err(KdfError::ParamsTooLarge);
        }
        Ok(())
    }

    /// ⭐ **THE NO-DOWNGRADE RATCHET.** Returns the componentwise **maximum** of
    /// `self` (the work factors an existing container declares) and `requested`
    /// (what the client would write today).
    ///
    /// A re-seal is the operation that *chooses* new work factors, so it is the
    /// one place a weak container can make its weakness permanent. A container
    /// header is unauthenticated framing, so an attacker who gets ONE weak
    /// container accepted — say `m_cost = 8` — would otherwise see that weakness
    /// survive every subsequent re-seal. Taking the max makes each factor a
    /// ratchet: it can go up, never down, and a client with stronger defaults
    /// silently repairs a weak container the first time it re-seals it.
    ///
    /// Argon2 requires `m_cost >= 8 * p_cost`, and a componentwise max can pair a
    /// small `m_cost` with a larger `p_cost`, so `m_cost` is raised to that floor
    /// when needed. Both inputs are at or below the ceilings in practice (an
    /// out-of-range container cannot be opened at all) and `8 * MAX_P_COST` = 128
    /// KiB is far below [`Self::MAX_M_COST`], so the result stays in range.
    ///
    /// ⚠️ **This is the ONE implementation.** `sigil_cli::no_downgrade` delegates
    /// here, and the wasm binding exports it, so the browser clients cannot drift
    /// from the CLI the way a mirrored copy would.
    #[must_use]
    pub const fn no_downgrade(self, requested: Argon2Params) -> Argon2Params {
        let p_cost = if self.p_cost > requested.p_cost {
            self.p_cost
        } else {
            requested.p_cost
        };
        let mut m_cost = if self.m_cost > requested.m_cost {
            self.m_cost
        } else {
            requested.m_cost
        };
        let floor = p_cost.saturating_mul(8);
        if m_cost < floor {
            m_cost = floor;
        }
        Argon2Params {
            m_cost,
            t_cost: if self.t_cost > requested.t_cost {
                self.t_cost
            } else {
                requested.t_cost
            },
            p_cost,
        }
    }
}

/// Errors returned by [`derive_master_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KdfError {
    /// The supplied [`Argon2Params`] were rejected by Argon2 (e.g. memory below
    /// the per-lane minimum, zero iterations, or zero lanes).
    InvalidParams,
    /// ⛔ The supplied [`Argon2Params`] exceeded Sigil's own ceilings
    /// ([`Argon2Params::MAX_M_COST`] / [`Argon2Params::MAX_T_COST`] /
    /// [`Argon2Params::MAX_P_COST`]).
    ///
    /// Distinct from [`Self::InvalidParams`] on purpose: these values may be
    /// perfectly legal Argon2 parameters, and are refused because honouring them
    /// would let whoever wrote the container dictate an unbounded allocation on
    /// the machine opening it. **Nothing is allocated before this is returned.**
    ParamsTooLarge,
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
/// - [`KdfError::ParamsTooLarge`] if `params` exceed Sigil's ceilings — checked
///   FIRST, before anything is allocated (see [`Argon2Params::validate`]).
/// - [`KdfError::InvalidParams`] if `params` are out of range for Argon2.
/// - [`KdfError::InvalidSalt`] if `salt` is too short or too long.
/// - [`KdfError::Hash`] for any other Argon2 failure.
pub fn derive_master_key(
    password: &[u8],
    salt: &[u8],
    params: Argon2Params,
) -> Result<[u8; MASTER_KEY_LEN], KdfError> {
    // ⛔ RANGE CHECK FIRST. `hash_password_into` below allocates `m_cost` KiB in
    // one block; an unbounded `m_cost` parsed out of an attacker-supplied
    // container header is a remote DoS. This is the backstop for every
    // `sigil-core` caller — container parsers check earlier still, so they can
    // report a typed error of their own.
    params.validate()?;

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
    fn ceilings_sit_above_everything_this_repo_writes() {
        // Nothing that opens today may stop opening. The largest parameters any
        // Sigil client writes are RECOMMENDED (64 MiB / 4 / 2) and the browser
        // clients' 19456 / 2 / 1.
        assert!(Argon2Params::RECOMMENDED.validate().is_ok());
        assert!(Argon2Params {
            m_cost: 19456,
            t_cost: 2,
            p_cost: 1
        }
        .validate()
        .is_ok());
        assert!(FAST.validate().is_ok());
        // The ceiling must leave real headroom above the strongest parameters
        // anything here writes, so the work factor can be raised several times
        // over without a format break. (Not a const assert: clippy rightly
        // objects to comparing two constants, so compare the values as data.)
        let ceiling = Argon2Params::MAX_M_COST;
        let strongest = Argon2Params::RECOMMENDED.m_cost;
        assert!(
            ceiling >= strongest.saturating_mul(4),
            "ceiling {ceiling} leaves too little headroom over {strongest}"
        );
    }

    #[test]
    fn absurd_params_are_refused_without_allocating() {
        // ~4 TiB. Argon2 would happily try; validate() refuses first, and the
        // test completing at all is the evidence nothing was allocated.
        let absurd = Argon2Params {
            m_cost: 0xFFFF_FFF0,
            t_cost: 1,
            p_cost: 1,
        };
        assert_eq!(absurd.validate(), Err(KdfError::ParamsTooLarge));
        let err = derive_master_key(b"pw", SALT_A, absurd).expect_err("absurd params refused");
        assert_eq!(err, KdfError::ParamsTooLarge);
    }

    #[test]
    fn each_ceiling_is_enforced_independently() {
        for bad in [
            Argon2Params {
                m_cost: Argon2Params::MAX_M_COST + 1,
                t_cost: 1,
                p_cost: 1,
            },
            Argon2Params {
                m_cost: 8,
                t_cost: Argon2Params::MAX_T_COST + 1,
                p_cost: 1,
            },
            Argon2Params {
                m_cost: 8,
                t_cost: 1,
                p_cost: Argon2Params::MAX_P_COST + 1,
            },
        ] {
            assert_eq!(bad.validate(), Err(KdfError::ParamsTooLarge));
            assert_eq!(
                derive_master_key(b"pw", SALT_A, bad),
                Err(KdfError::ParamsTooLarge)
            );
        }
        // …and the ceiling value ITSELF is accepted (the bound is inclusive).
        assert!(Argon2Params {
            m_cost: Argon2Params::MAX_M_COST,
            t_cost: Argon2Params::MAX_T_COST,
            p_cost: Argon2Params::MAX_P_COST,
        }
        .validate()
        .is_ok());
    }

    #[test]
    fn too_large_is_distinct_from_invalid() {
        // A ceiling breach must not be reported as "Argon2 rejected these",
        // because a caller has to be able to tell "your container is hostile"
        // from "your container is malformed".
        assert_ne!(KdfError::ParamsTooLarge, KdfError::InvalidParams);
    }

    #[test]
    fn no_downgrade_is_a_componentwise_ratchet() {
        let weak = Argon2Params {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let strong = Argon2Params {
            m_cost: 65536,
            t_cost: 4,
            p_cost: 2,
        };
        // Strength only ever goes up, in either argument order.
        assert_eq!(weak.no_downgrade(strong), strong);
        assert_eq!(strong.no_downgrade(weak), strong);
        // Componentwise, not "pick a side".
        assert_eq!(
            Argon2Params {
                m_cost: 65536,
                t_cost: 1,
                p_cost: 1
            }
            .no_downgrade(Argon2Params {
                m_cost: 19456,
                t_cost: 8,
                p_cost: 4
            }),
            Argon2Params {
                m_cost: 65536,
                t_cost: 8,
                p_cost: 4
            }
        );
    }

    #[test]
    fn no_downgrade_honours_argon2s_m_cost_floor() {
        // A componentwise max can pair a tiny m_cost with a big p_cost, which
        // Argon2 itself rejects (m_cost >= 8 * p_cost). The ratchet must raise
        // m_cost rather than produce params that will not derive at all.
        let repaired = Argon2Params {
            m_cost: 8,
            t_cost: 1,
            p_cost: 16,
        }
        .no_downgrade(Argon2Params {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        });
        assert_eq!(repaired.p_cost, 16);
        assert_eq!(repaired.m_cost, 128, "raised to the 8 * p_cost floor");
        assert!(repaired.validate().is_ok());
        // And it really derives — the floor is not cosmetic.
        assert!(derive_master_key(b"pw", SALT_A, repaired).is_ok());
    }

    #[test]
    fn no_downgrade_never_exceeds_the_ceilings() {
        // Both inputs at the ceiling: the max is still exactly the ceiling, and
        // the 8 * p_cost floor (128 KiB) cannot push m_cost past MAX_M_COST.
        let at_max = Argon2Params {
            m_cost: Argon2Params::MAX_M_COST,
            t_cost: Argon2Params::MAX_T_COST,
            p_cost: Argon2Params::MAX_P_COST,
        };
        assert_eq!(at_max.no_downgrade(at_max), at_max);
        assert!(at_max.no_downgrade(at_max).validate().is_ok());
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
