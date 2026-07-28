//! Recovery-kit encoding and key derivation — the paper credential (Phase 54).
//!
//! STATUS: pre-audit, UNAUDITED. This module adds **no new low-level
//! cryptography**: it is a codec (Crockford Base32 + a SHA-256 checksum) plus a
//! **domain-separated HKDF-SHA256 expansion** of one caller-supplied 32-byte
//! secret into the three seeds the existing deterministic primitives already
//! take. It reads no clock and draws no randomness — the 32-byte recovery seed
//! is the CALLER's, exactly like the Argon2id salt, the AEAD nonce, the Ed25519
//! seed, the X25519 scalar and the ML-KEM seed/coin elsewhere in this crate
//! (ADR 0007). It is therefore `no_std` and wasm-pure like the rest.
//!
//! ## What a recovery kit IS
//!
//! An ORDINARY device identity whose private keys happen to live on paper. The
//! 32-byte seed is printed as 56 Crockford-Base32 characters; from it,
//! [`derive_recovery_keys`] deterministically re-derives:
//!
//! ```text
//!   PRK               = HKDF-Extract(salt = "sigil-recovery-kit-v1", ikm = seed)
//!   ed25519_seed      = HKDF-Expand(PRK, "sigil-recovery-kit-v1/ed25519-device-seed", 32)
//!   x25519_secret     = HKDF-Expand(PRK, "sigil-recovery-kit-v1/x25519-secret",       32)
//!   mlkem_keygen_seed = HKDF-Expand(PRK, "sigil-recovery-kit-v1/mlkem-keygen-seed",   64)
//! ```
//!
//! which feed [`crate::public_key_from_seed`], [`crate::x25519_public_key`] and
//! [`crate::ml_kem768_keygen`] **unchanged**. There is no new KEM composition,
//! no new signature scheme, and no new at-rest format: a kit is a recipient of
//! the SAME hybrid `SIGILhyb` envelope every other device receives.
//!
//! ## Why HKDF and NOT Argon2id
//!
//! There is no password here. The input is a uniform 256-bit CSPRNG secret, so
//! there is nothing to stretch; a memory-hard KDF over it would be decoration
//! that *signals* a low-entropy input, i.e. it would fake a property. HKDF
//! already provides the domain separation, which is the only thing actually
//! needed.
//!
//! ## The printed form
//!
//! ```text
//!   check = SHA-256("sigil-recovery-kit-v1\n" ‖ [version] ‖ seed)[0..2]
//!   body  = [version(1)] ‖ seed(32) ‖ check(2)                     = 35 bytes
//!   code  = crockford32(body)                                      = 56 chars
//!   sheet = code in 7 groups of 8, hyphen-joined
//! ```
//!
//! 35 bytes is 280 bits, which divides by 5 exactly — so the code is exactly 56
//! characters with **no padding**. The checksum covers the **version byte**, so
//! a corrupted version is reported as a mistyped code rather than as an
//! "unsupported version" (see [`decode_recovery_kit`] for the decode ORDER,
//! which is load-bearing).
//!
//! Crockford Base32 is used (not the RFC 4648 alphabet the TOTP secrets use)
//! because it folds the handwriting confusions `O→0`, `I→1`, `L→1` and excludes
//! `U` outright. It is a SEPARATE codec: nothing here touches
//! `sigil-cli`'s RFC 4648 `base32_decode`, which belongs to a different format.
//!
//! ## Honest scope
//!
//! Whoever holds the printed secret holds a full member device key. This module
//! performs no zeroization (this crate has no `zeroize` dependency) and makes no
//! claim beyond "the derivation is deterministic and domain-separated". The
//! surrounding system is dev-gated, pre-audit and **UNAUDITED**.

use alloc::string::String;
use alloc::vec::Vec;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};

/// The recovery-kit format version, written as the first byte of the encoded
/// body and covered by the checksum.
pub const RECOVERY_KIT_VERSION: u8 = 1;

/// Length of the raw recovery secret, in bytes. 32 bytes — the same width as
/// every other seed in this crate, deliberately.
pub const RECOVERY_SEED_LEN: usize = 32;

/// Length of the encoded body: `version(1) ‖ seed(32) ‖ check(2)`.
pub const RECOVERY_KIT_BODY_LEN: usize = 1 + RECOVERY_SEED_LEN + RECOVERY_CHECK_LEN;

/// Length of the truncated SHA-256 checksum, in bytes (16 bits).
pub const RECOVERY_CHECK_LEN: usize = 2;

/// Number of characters in a printed recovery code (ungrouped).
/// `RECOVERY_KIT_BODY_LEN * 8 / 5` = 280 / 5 = 56, exactly, with no padding.
pub const RECOVERY_KIT_CHARS: usize = RECOVERY_KIT_BODY_LEN * 8 / 5;

/// How many characters per printed group on the sheet.
pub const RECOVERY_GROUP_LEN: usize = 8;

/// Domain-separation prefix of the CHECKSUM. Distinct from the HKDF salt below
/// (it carries a trailing newline) so the two can never be confused.
const CHECK_DOMAIN: &[u8] = b"sigil-recovery-kit-v1\n";

/// HKDF-Extract salt for the derivation.
const HKDF_SALT: &[u8] = b"sigil-recovery-kit-v1";

/// HKDF-Expand info label for the Ed25519 device seed.
const INFO_ED25519: &[u8] = b"sigil-recovery-kit-v1/ed25519-device-seed";

/// HKDF-Expand info label for the X25519 secret scalar.
const INFO_X25519: &[u8] = b"sigil-recovery-kit-v1/x25519-secret";

/// HKDF-Expand info label for the ML-KEM-768 keygen seed (`d ‖ z`).
const INFO_MLKEM: &[u8] = b"sigil-recovery-kit-v1/mlkem-keygen-seed";

/// The Crockford Base32 alphabet: no `I`, `L`, `O` or `U`.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The three seeds a recovery kit re-derives. All are SECRET; this crate never
/// prints or logs them.
#[derive(Clone)]
pub struct RecoveryKeys {
    /// 32-byte Ed25519 signing seed — the kit's request-auth identity.
    pub ed25519_seed: [u8; 32],
    /// 32-byte X25519 secret scalar — the classical half of the kit's hybrid
    /// identity.
    pub x25519_secret: [u8; 32],
    /// 64-byte ML-KEM-768 keygen seed (`d ‖ z`) — the PQ half.
    pub mlkem_keygen_seed: [u8; 64],
}

/// REDACTED on purpose: derived key material must never reach a log line via a
/// stray `{:?}`.
impl core::fmt::Debug for RecoveryKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecoveryKeys { <redacted> }")
    }
}

/// Why a printed recovery code could not be decoded.
///
/// These are reported to a human who has just typed 56 characters, so they are
/// deliberately distinguishable — but note that they are all decided OFFLINE,
/// before any network request is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecoveryError {
    /// The code did not have [`RECOVERY_KIT_CHARS`] alphanumeric characters.
    BadLength {
        /// How many alphanumeric characters were actually supplied.
        got: usize,
    },
    /// The code contained a character that is not in the Crockford alphabet
    /// (including `U`, which Crockford excludes and this codec does NOT fold).
    BadChar,
    /// The 16-bit checksum did not match — a mistyped or corrupted code. This
    /// is also what a flipped VERSION byte reports, deliberately.
    BadChecksum,
    /// The code decoded and checksummed cleanly but names a format version this
    /// build does not understand.
    UnsupportedVersion(u8),
}

impl core::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RecoveryError::BadLength { got } => write!(
                f,
                "that is not a valid recovery code: expected {RECOVERY_KIT_CHARS} characters, got {got}"
            ),
            RecoveryError::BadChar => f.write_str(
                "that is not a valid recovery code: it contains a character that is not part of \
                 the recovery alphabet (note: U is never used)",
            ),
            RecoveryError::BadChecksum => f.write_str(
                "that is not a valid recovery code — check for a mistyped character",
            ),
            RecoveryError::UnsupportedVersion(v) => write!(
                f,
                "unsupported recovery kit version {v}: this build understands version \
                 {RECOVERY_KIT_VERSION}"
            ),
        }
    }
}

/// The 2-byte checksum over `version ‖ seed`, under its own domain prefix.
fn checksum(version: u8, seed: &[u8; RECOVERY_SEED_LEN]) -> [u8; RECOVERY_CHECK_LEN] {
    let mut h = Sha256::new();
    h.update(CHECK_DOMAIN);
    h.update([version]);
    h.update(seed);
    let digest = h.finalize();
    let mut out = [0u8; RECOVERY_CHECK_LEN];
    out.copy_from_slice(&digest[..RECOVERY_CHECK_LEN]);
    out
}

/// Deterministically derive the kit's three seeds from the 32-byte recovery
/// secret.
///
/// RNG-free and clock-free: the same secret always yields the same identity,
/// which is the entire point — the paper IS the key.
#[must_use]
pub fn derive_recovery_keys(seed: &[u8; RECOVERY_SEED_LEN]) -> RecoveryKeys {
    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), seed);
    let mut keys = RecoveryKeys {
        ed25519_seed: [0u8; 32],
        x25519_secret: [0u8; 32],
        mlkem_keygen_seed: [0u8; 64],
    };
    // HKDF-Expand cannot fail for these output lengths (all far below
    // 255 * HashLen), so the `expect`s are unreachable.
    hk.expand(INFO_ED25519, &mut keys.ed25519_seed)
        .expect("HKDF expand of 32 bytes never fails");
    hk.expand(INFO_X25519, &mut keys.x25519_secret)
        .expect("HKDF expand of 32 bytes never fails");
    hk.expand(INFO_MLKEM, &mut keys.mlkem_keygen_seed)
        .expect("HKDF expand of 64 bytes never fails");
    keys
}

/// Encode a 32-byte recovery secret as the printed [`RECOVERY_KIT_CHARS`]-character
/// code (UNGROUPED ASCII — see [`format_recovery_kit`] for the sheet rendering).
#[must_use]
pub fn encode_recovery_kit(seed: &[u8; RECOVERY_SEED_LEN]) -> [u8; RECOVERY_KIT_CHARS] {
    let check = checksum(RECOVERY_KIT_VERSION, seed);
    let mut body = [0u8; RECOVERY_KIT_BODY_LEN];
    body[0] = RECOVERY_KIT_VERSION;
    body[1..1 + RECOVERY_SEED_LEN].copy_from_slice(seed);
    body[1 + RECOVERY_SEED_LEN..].copy_from_slice(&check);

    // MSB-first 5-bit chunking (RFC 4648 §6 bit order, Crockford alphabet).
    // 35 bytes = 280 bits = 56 groups of 5 bits exactly, so there is no
    // remainder and no padding.
    let mut out = [0u8; RECOVERY_KIT_CHARS];
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut written = 0usize;
    for &b in body.iter() {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((acc >> bits) & 0x1f) as usize;
            out[written] = CROCKFORD[idx];
            written += 1;
        }
    }
    debug_assert_eq!(written, RECOVERY_KIT_CHARS);
    debug_assert_eq!(bits, 0);
    out
}

/// Map ONE character to its Crockford value, applying the confusion folding.
///
/// `O`/`o` → `0`, `I`/`i`/`L`/`l` → `1`. `U`/`u` is REJECTED rather than folded:
/// Crockford excludes it, and folding it would let two distinct strings decode
/// to the same value.
fn crockford_value(c: char) -> Option<u8> {
    let up = c.to_ascii_uppercase();
    match up {
        '0'..='9' => Some(up as u8 - b'0'),
        'O' => Some(0),
        'I' | 'L' => Some(1),
        'U' => None,
        'A'..='Z' => {
            // Look the (already upper-cased, non-folded) letter up in the
            // alphabet. Letters Crockford omits are simply absent.
            CROCKFORD
                .iter()
                .position(|&a| a == up as u8)
                .map(|p| p as u8)
        }
        _ => None,
    }
}

/// Decode a printed recovery code back to its 32-byte secret.
///
/// Input is forgiving about PRESENTATION and strict about CONTENT: every
/// non-alphanumeric character (hyphen, space, tab, newline) is stripped, case is
/// ignored, and `O`/`I`/`L` fold — but `U` and any other non-alphabet character
/// are rejected.
///
/// ⭐ **THE ORDER MATTERS, and it is part of the contract:**
/// `length → alphabet → CHECKSUM → version`. Because the checksum covers the
/// version byte, a corrupted version reports [`RecoveryError::BadChecksum`]
/// ("you mistyped it"), which is true, rather than
/// [`RecoveryError::UnsupportedVersion`] ("your kit is from the future"), which
/// would be a lie. Only a code whose checksum is *correct* for a version this
/// build does not know reports the latter.
///
/// This is a pure function: it makes **no** network request, so a mistyped code
/// is rejected before anything is sent anywhere.
///
/// # Errors
/// - [`RecoveryError::BadLength`] / [`RecoveryError::BadChar`] /
///   [`RecoveryError::BadChecksum`] / [`RecoveryError::UnsupportedVersion`].
pub fn decode_recovery_kit(s: &str) -> Result<[u8; RECOVERY_SEED_LEN], RecoveryError> {
    // 1) Strip presentation, then LENGTH.
    let cleaned: Vec<char> = s.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if cleaned.len() != RECOVERY_KIT_CHARS {
        return Err(RecoveryError::BadLength { got: cleaned.len() });
    }

    // 2) ALPHABET.
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut body = [0u8; RECOVERY_KIT_BODY_LEN];
    let mut written = 0usize;
    for c in cleaned {
        let v = crockford_value(c).ok_or(RecoveryError::BadChar)?;
        acc = (acc << 5) | u32::from(v);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            body[written] = ((acc >> bits) & 0xff) as u8;
            written += 1;
        }
    }
    debug_assert_eq!(written, RECOVERY_KIT_BODY_LEN);

    let version = body[0];
    let mut seed = [0u8; RECOVERY_SEED_LEN];
    seed.copy_from_slice(&body[1..1 + RECOVERY_SEED_LEN]);

    // 3) CHECKSUM (covers the version byte).
    if checksum(version, &seed) != body[1 + RECOVERY_SEED_LEN..] {
        return Err(RecoveryError::BadChecksum);
    }

    // 4) VERSION.
    if version != RECOVERY_KIT_VERSION {
        return Err(RecoveryError::UnsupportedVersion(version));
    }
    Ok(seed)
}

/// Render a code for the printed sheet: groups of [`RECOVERY_GROUP_LEN`]
/// characters joined by `-`.
///
/// ONE renderer, used everywhere a kit is displayed, so the grouping can never
/// drift between surfaces. Presentation characters in the input are stripped
/// first, so `format_recovery_kit(format_recovery_kit(c)) == format_recovery_kit(c)`.
#[must_use]
pub fn format_recovery_kit(code: &str) -> String {
    let cleaned: Vec<char> = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let mut out = String::with_capacity(cleaned.len() + cleaned.len() / RECOVERY_GROUP_LEN);
    for (i, c) in cleaned.iter().enumerate() {
        if i > 0 && i % RECOVERY_GROUP_LEN == 0 {
            out.push('-');
        }
        out.push(*c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ml_kem768_keygen, public_key_from_seed, x25519_public_key};

    /// Deterministic pseudo-random byte stream (an xorshift), so the tests need
    /// no RNG — this crate has none, by design.
    struct Rng(u64);
    impl Rng {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf.iter_mut() {
                *b = (self.next_u64() & 0xff) as u8;
            }
        }
    }

    fn hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(char::from_digit(u32::from(b >> 4), 16).unwrap());
            s.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap());
        }
        s
    }

    /// ⭐ THE ANTI-DRIFT ANCHOR (T1a). This exact vector is reproduced in
    /// `sigil-wasm`'s native tests, the CLI tests and the JS interop tests. If
    /// any of them disagree, a recovery kit printed by one client cannot be
    /// redeemed by another — and that failure is silent, so it is pinned here.
    #[test]
    fn derivation_known_answer_vector() {
        let seed = [0x42u8; RECOVERY_SEED_LEN];
        let keys = derive_recovery_keys(&seed);

        let ed_pub = public_key_from_seed(&keys.ed25519_seed);
        let x_pub = x25519_public_key(&keys.x25519_secret);
        let (encaps, _decaps) = ml_kem768_keygen(&keys.mlkem_keygen_seed);
        let encaps_digest: [u8; 32] = Sha256::digest(encaps).into();

        assert_eq!(
            hex(&ed_pub),
            "913af25b7f0ea458577b80124f137f7a8f0e5850a73a5cdeaf92e9169edeb717",
            "ed25519 public key KAT"
        );
        assert_eq!(
            hex(&x_pub),
            "a55ac63d4d1f84face17abb82cc3449cd43c3f25f7a08008075bd594acc98754",
            "x25519 public key KAT"
        );
        assert_eq!(
            hex(&encaps_digest),
            "14260b3e72b496ac3fde4a2434fd0f175f55324cca38ef8cd75a53675b643806",
            "ml-kem-768 encapsulation key SHA-256 KAT"
        );

        // The PRINTED form of the same seed, pinned so the codec cannot drift
        // either. (An all-0x42 seed encodes to a visibly repeating pattern —
        // that is the input, not a codec bug.)
        let encoded = encode_recovery_kit(&seed);
        let code = core::str::from_utf8(&encoded).unwrap();
        assert_eq!(
            format_recovery_kit(code),
            "05144GJ2-89144GJ2-89144GJ2-89144GJ2-89144GJ2-89144GJ2-89145G6W",
            "printed recovery code KAT"
        );
        assert_eq!(decode_recovery_kit(code).unwrap(), seed);
    }

    #[test]
    fn encode_decode_round_trips_over_many_seeds() {
        let mut rng = Rng(0x5161_1cd0_1234_5678);
        for _ in 0..1000 {
            let mut seed = [0u8; RECOVERY_SEED_LEN];
            rng.fill(&mut seed);
            let code = encode_recovery_kit(&seed);
            let text = core::str::from_utf8(&code).expect("ASCII");
            assert_eq!(text.len(), RECOVERY_KIT_CHARS);
            let back = decode_recovery_kit(text).expect("round trip");
            assert_eq!(back, seed);
            // The grouped rendering decodes to the same thing.
            let grouped = format_recovery_kit(text);
            assert_eq!(decode_recovery_kit(&grouped).expect("grouped"), seed);
        }
    }

    #[test]
    fn encoded_length_and_grouping_are_fixed() {
        let seed = [0x11u8; RECOVERY_SEED_LEN];
        let code = encode_recovery_kit(&seed);
        assert_eq!(code.len(), 56);
        let text = core::str::from_utf8(&code).unwrap();
        let grouped = format_recovery_kit(text);
        let parts: Vec<&str> = grouped.split('-').collect();
        assert_eq!(parts.len(), 7, "7 groups");
        for p in &parts {
            assert_eq!(p.len(), 8, "8 characters per group");
        }
        // Every character is in the alphabet (so no I/L/O/U was ever emitted).
        for c in text.chars() {
            assert!(
                CROCKFORD.contains(&(c as u8)),
                "emitted character {c:?} outside the Crockford alphabet"
            );
        }
    }

    #[test]
    fn presentation_and_confusable_characters_fold() {
        let seed = [0x7eu8; RECOVERY_SEED_LEN];
        let code = core::str::from_utf8(&encode_recovery_kit(&seed))
            .unwrap()
            .to_string();

        // Lowercase.
        assert_eq!(decode_recovery_kit(&code.to_lowercase()).unwrap(), seed);
        // Grouped with hyphens, spaces, tabs and a trailing newline.
        let spaced = format_recovery_kit(&code).replace('-', " ");
        assert_eq!(decode_recovery_kit(&spaced).unwrap(), seed);
        let messy = alloc::format!("  {}\t{}\n", &code[..10], &code[10..]);
        assert_eq!(decode_recovery_kit(&messy).unwrap(), seed);

        // O -> 0 and I/l -> 1, in both cases.
        let confused: String = code
            .chars()
            .map(|c| match c {
                '0' => 'O',
                '1' => 'I',
                other => other,
            })
            .collect();
        assert_eq!(decode_recovery_kit(&confused).unwrap(), seed);
        let confused_lower: String = code
            .chars()
            .map(|c| match c {
                '0' => 'o',
                '1' => 'l',
                other => other.to_ascii_lowercase(),
            })
            .collect();
        assert_eq!(decode_recovery_kit(&confused_lower).unwrap(), seed);
    }

    #[test]
    fn u_is_rejected_never_folded() {
        let seed = [0x03u8; RECOVERY_SEED_LEN];
        let code = core::str::from_utf8(&encode_recovery_kit(&seed))
            .unwrap()
            .to_string();
        let mut chars: Vec<char> = code.chars().collect();
        chars[5] = 'U';
        let with_u: String = chars.iter().collect();
        assert_eq!(decode_recovery_kit(&with_u), Err(RecoveryError::BadChar));
        chars[5] = 'u';
        let with_lower_u: String = chars.iter().collect();
        assert_eq!(
            decode_recovery_kit(&with_lower_u),
            Err(RecoveryError::BadChar)
        );
    }

    #[test]
    fn every_single_character_substitution_is_caught() {
        let seed = [0x5au8; RECOVERY_SEED_LEN];
        let code: Vec<char> = core::str::from_utf8(&encode_recovery_kit(&seed))
            .unwrap()
            .chars()
            .collect();

        let mut accepted_mutations = 0usize;
        let mut checked = 0usize;
        for pos in 0..RECOVERY_KIT_CHARS {
            for &sub in CROCKFORD.iter() {
                let sub = sub as char;
                if sub == code[pos] {
                    continue;
                }
                let mut m = code.clone();
                m[pos] = sub;
                let text: String = m.iter().collect();
                checked += 1;
                match decode_recovery_kit(&text) {
                    Ok(recovered) => {
                        // A mutation that somehow decodes MUST NOT yield a
                        // different seed silently.
                        assert_eq!(
                            recovered, seed,
                            "a mutated code decoded to a DIFFERENT seed"
                        );
                        accepted_mutations += 1;
                    }
                    Err(RecoveryError::BadChecksum) => {}
                    Err(RecoveryError::UnsupportedVersion(_)) => {
                        // Only reachable if the checksum still matched, which
                        // would mean a collision; counted as accepted.
                        accepted_mutations += 1;
                    }
                    Err(e) => panic!("unexpected error for a single substitution: {e:?}"),
                }
            }
        }
        assert!(checked > 1000, "the mutation sweep must be exhaustive");
        assert_eq!(
            accepted_mutations, 0,
            "no single-character substitution may be accepted"
        );
    }

    #[test]
    fn flipped_version_reports_checksum_not_version() {
        // Hand-build a body with the WRONG version but the ORIGINAL checksum:
        // the checksum covers the version, so this must read as a typo.
        let seed = [0x21u8; RECOVERY_SEED_LEN];
        let good_check = checksum(RECOVERY_KIT_VERSION, &seed);
        let mut body = [0u8; RECOVERY_KIT_BODY_LEN];
        body[0] = 0x02;
        body[1..1 + RECOVERY_SEED_LEN].copy_from_slice(&seed);
        body[1 + RECOVERY_SEED_LEN..].copy_from_slice(&good_check);
        assert_eq!(
            decode_recovery_kit(&encode_body_for_test(&body)),
            Err(RecoveryError::BadChecksum)
        );

        // Now RECOMPUTE the checksum for version 2: it decodes cleanly and is
        // reported as an unsupported version.
        let v2_check = checksum(0x02, &seed);
        body[1 + RECOVERY_SEED_LEN..].copy_from_slice(&v2_check);
        assert_eq!(
            decode_recovery_kit(&encode_body_for_test(&body)),
            Err(RecoveryError::UnsupportedVersion(2))
        );
    }

    /// Crockford-encode an arbitrary 35-byte body (test-only: the public
    /// encoder always writes the current version).
    fn encode_body_for_test(body: &[u8; RECOVERY_KIT_BODY_LEN]) -> String {
        let mut out = String::with_capacity(RECOVERY_KIT_CHARS);
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for &b in body.iter() {
            acc = (acc << 8) | u32::from(b);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                out.push(CROCKFORD[((acc >> bits) & 0x1f) as usize] as char);
            }
        }
        out
    }

    #[test]
    fn wrong_lengths_are_rejected() {
        let seed = [0x9fu8; RECOVERY_SEED_LEN];
        let code = core::str::from_utf8(&encode_recovery_kit(&seed))
            .unwrap()
            .to_string();
        assert_eq!(
            decode_recovery_kit(&code[..RECOVERY_KIT_CHARS - 1]),
            Err(RecoveryError::BadLength { got: 55 })
        );
        let mut longer = code.clone();
        longer.push('7');
        assert_eq!(
            decode_recovery_kit(&longer),
            Err(RecoveryError::BadLength { got: 57 })
        );
        assert_eq!(
            decode_recovery_kit(""),
            Err(RecoveryError::BadLength { got: 0 })
        );
    }

    #[test]
    fn the_three_derived_seeds_are_distinct_and_none_is_the_input() {
        let seed = [0xa7u8; RECOVERY_SEED_LEN];
        let k = derive_recovery_keys(&seed);
        assert_ne!(k.ed25519_seed, k.x25519_secret);
        assert_ne!(k.ed25519_seed, seed);
        assert_ne!(k.x25519_secret, seed);
        assert_ne!(&k.mlkem_keygen_seed[..32], &k.ed25519_seed[..]);
        assert_ne!(&k.mlkem_keygen_seed[..32], &k.x25519_secret[..]);
        assert_ne!(&k.mlkem_keygen_seed[..32], &seed[..]);
        assert_ne!(&k.mlkem_keygen_seed[..32], &k.mlkem_keygen_seed[32..]);

        // Deterministic: same input, same output.
        let again = derive_recovery_keys(&seed);
        assert_eq!(k.ed25519_seed, again.ed25519_seed);
        assert_eq!(k.x25519_secret, again.x25519_secret);
        assert_eq!(k.mlkem_keygen_seed, again.mlkem_keygen_seed);

        // A one-bit change in the secret changes every derived seed.
        let mut other = seed;
        other[0] ^= 0x01;
        let diff = derive_recovery_keys(&other);
        assert_ne!(k.ed25519_seed, diff.ed25519_seed);
        assert_ne!(k.x25519_secret, diff.x25519_secret);
        assert_ne!(k.mlkem_keygen_seed, diff.mlkem_keygen_seed);
    }

    #[test]
    fn debug_never_prints_key_material() {
        let k = derive_recovery_keys(&[0x01u8; RECOVERY_SEED_LEN]);
        let rendered = alloc::format!("{k:?}");
        assert_eq!(rendered, "RecoveryKeys { <redacted> }");
    }
}
