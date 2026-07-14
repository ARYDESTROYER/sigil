//! HOTP (RFC 4226) and TOTP (RFC 6238) one-time-password codes — the
//! authenticator primitive at the heart of the product.
//!
//! STATUS: pre-audit. This module computes **real** RFC 4226 HOTP and RFC 6238
//! TOTP codes using the vetted RustCrypto [`hmac`], [`sha1`], and [`sha2`]
//! crates, and is checked against the official RFC known-answer vectors (see the
//! tests). It performs the OTP math only — it is not a full account/enrollment
//! flow, and the secret key is the caller's responsibility.
//!
//! ## What this module does
//!
//! [`hotp`] implements RFC 4226 §5.3: `HMAC-H(key, counter_be64)` under a chosen
//! hash, then the RFC's *dynamic truncation* (take the low nibble of the last MAC
//! byte as an offset, read a big-endian 31-bit integer from `MAC[offset..offset+4]`,
//! and reduce it modulo `10^digits`). [`totp`] implements RFC 6238 §4: it turns a
//! Unix time into a counter `T = (unix_time - t0) / period` and defers to [`hotp`].
//!
//! ## No clock, no RNG — the caller supplies the time
//!
//! `sigil-core` is `no_std` and compiles to `wasm32-unknown-unknown`, where no
//! system clock and no system RNG are available. This module therefore **reads
//! neither**: [`totp`] takes the current Unix time as a `u64` argument, exactly
//! as the rest of the crate takes caller-supplied salts, nonces, and seeds. The
//! caller (a native client, the browser) reads its own clock and passes the value
//! in. There is no in-core time source and no randomness here.
//!
//! ## The secret key is the caller's responsibility
//!
//! The OTP secret (typically provisioned as a base32 string in an
//! `otpauth://` URI) is passed in as raw bytes. HMAC accepts a key of any length,
//! so no length validation is done on the key. The caller must keep it secret;
//! whoever holds it can generate valid codes.
//!
//! ## Pre-audit caveats
//!
//! - There is no zeroization of the key or of intermediate HMAC state beyond what
//!   the dependencies do internally.
//! - Code *verification* (comparing a user-entered code, with a validity window)
//!   is intentionally left to the caller — this module only *generates* codes.
//!   A constant-time compare is the caller's responsibility when checking codes.
//! - This is unaudited and, while the OTP math is standard, it is not yet wired
//!   into a complete product enrollment/storage flow in the core.

use alloc::string::String;
use alloc::vec::Vec;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// The smallest number of decimal digits an OTP code may have (RFC 4226 requires
/// at least 6 for adequate security).
pub const MIN_DIGITS: u32 = 6;
/// The largest number of decimal digits this module will produce. The dynamic
/// truncation yields a 31-bit integer (max 2_147_483_647, i.e. 10 digits), so 10
/// is the largest width that carries full entropy; beyond it the leading digits
/// would always be zero.
pub const MAX_DIGITS: u32 = 10;

/// The hash function underlying the HMAC in an HOTP/TOTP computation.
///
/// RFC 4226 defines HOTP over HMAC-SHA-1; RFC 6238 extends TOTP to HMAC-SHA-256
/// and HMAC-SHA-512. SHA-1 is the default because real-world authenticator apps
/// and `otpauth://` provisioning almost universally use it, so interoperability
/// requires it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum OtpAlgorithm {
    /// HMAC-SHA-1 (RFC 4226 default; the near-universal choice for 2FA apps).
    #[default]
    Sha1,
    /// HMAC-SHA-256 (RFC 6238).
    Sha256,
    /// HMAC-SHA-512 (RFC 6238).
    Sha512,
}

/// Errors returned when the OTP parameters are out of range.
///
/// The HMAC itself cannot fail (HMAC accepts a key of any length), so these
/// errors are purely about the `digits` / `period` / time arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OtpError {
    /// `digits` was outside the supported `MIN_DIGITS..=MAX_DIGITS` range.
    InvalidDigits(u32),
    /// The TOTP `period` was zero (division by the time step is undefined).
    InvalidPeriod,
    /// The supplied `unix_time` was earlier than the epoch offset `t0`, so the
    /// TOTP counter would be negative.
    TimeBeforeT0,
}

impl core::fmt::Display for OtpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OtpError::InvalidDigits(d) => write!(
                f,
                "invalid OTP digit count {d}: must be in {MIN_DIGITS}..={MAX_DIGITS}"
            ),
            OtpError::InvalidPeriod => f.write_str("invalid TOTP period: must be non-zero"),
            OtpError::TimeBeforeT0 => f.write_str("unix_time is before the TOTP epoch offset t0"),
        }
    }
}

/// Compute the full-length HMAC of `message` under `key` with the chosen hash,
/// returning the raw MAC bytes (20 for SHA-1, 32 for SHA-256, 64 for SHA-512).
///
/// HMAC (RFC 2104) accepts a key of any length — it hashes over-long keys and
/// zero-pads short ones — so `new_from_slice` never fails here, and the `expect`
/// is unreachable.
fn hmac_digest(algorithm: OtpAlgorithm, key: &[u8], message: &[u8]) -> Vec<u8> {
    // Each arm instantiates the concrete `Hmac<H>` for its hash. `new_from_slice`
    // is the `KeyInit`-via-`Mac` constructor; for HMAC it accepts any key length,
    // so the `expect` is unreachable.
    match algorithm {
        OtpAlgorithm::Sha1 => {
            let mut m =
                <Hmac<Sha1> as Mac>::new_from_slice(key).expect("HMAC accepts a key of any length");
            m.update(message);
            m.finalize().into_bytes().to_vec()
        }
        OtpAlgorithm::Sha256 => {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key)
                .expect("HMAC accepts a key of any length");
            m.update(message);
            m.finalize().into_bytes().to_vec()
        }
        OtpAlgorithm::Sha512 => {
            let mut m = <Hmac<Sha512> as Mac>::new_from_slice(key)
                .expect("HMAC accepts a key of any length");
            m.update(message);
            m.finalize().into_bytes().to_vec()
        }
    }
}

/// Compute an RFC 4226 HOTP value for `counter` under `key`, producing a
/// `digits`-digit decimal code with the chosen `algorithm`.
///
/// The `counter` is encoded as an 8-byte big-endian integer (RFC 4226 §5.1), the
/// HMAC is dynamically truncated (RFC 4226 §5.3), and the resulting 31-bit
/// integer is reduced modulo `10^digits`. The returned `u32` is the numeric code
/// **without** leading-zero padding — use [`format_code`] to render it as a
/// fixed-width string (a code like `073921` must keep its leading zero).
///
/// # Errors
/// - [`OtpError::InvalidDigits`] if `digits` is outside `MIN_DIGITS..=MAX_DIGITS`.
pub fn hotp(
    key: &[u8],
    counter: u64,
    digits: u32,
    algorithm: OtpAlgorithm,
) -> Result<u32, OtpError> {
    if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
        return Err(OtpError::InvalidDigits(digits));
    }

    let mac = hmac_digest(algorithm, key, &counter.to_be_bytes());

    // Dynamic truncation (RFC 4226 §5.3): the low nibble of the LAST MAC byte is
    // an offset into the MAC; read a big-endian 31-bit integer (top bit masked)
    // from the four bytes at that offset. The minimum MAC width here is 20 bytes
    // (SHA-1) and the offset is in 0..=15, so offset+3 <= 18 is always in bounds.
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(mac[offset] & 0x7f) << 24)
        | (u32::from(mac[offset + 1]) << 16)
        | (u32::from(mac[offset + 2]) << 8)
        | u32::from(mac[offset + 3]);

    // Reduce modulo 10^digits. `bin` is 31-bit (< 2^31), so the result always
    // fits in a u32; the modulus is computed in u64 because 10^10 overflows u32.
    let modulus = 10u64.pow(digits);
    let code = (u64::from(bin) % modulus) as u32;
    Ok(code)
}

/// Compute an RFC 6238 TOTP value for `unix_time` under `key`.
///
/// The time counter is `T = (unix_time - t0) / period` (RFC 6238 §4.2), which is
/// then fed to [`hotp`]. `t0` is the epoch offset (usually `0`) and `period` is
/// the time step in seconds (usually `30`). The caller supplies `unix_time` — this
/// module reads no clock (see the module-level docs).
///
/// # Errors
/// - [`OtpError::InvalidPeriod`] if `period` is `0`.
/// - [`OtpError::TimeBeforeT0`] if `unix_time < t0` (the counter would be negative).
/// - [`OtpError::InvalidDigits`] if `digits` is outside `MIN_DIGITS..=MAX_DIGITS`.
pub fn totp(
    key: &[u8],
    unix_time: u64,
    period: u32,
    t0: u64,
    digits: u32,
    algorithm: OtpAlgorithm,
) -> Result<u32, OtpError> {
    if period == 0 {
        return Err(OtpError::InvalidPeriod);
    }
    let elapsed = unix_time.checked_sub(t0).ok_or(OtpError::TimeBeforeT0)?;
    let counter = elapsed / u64::from(period);
    hotp(key, counter, digits, algorithm)
}

/// Render a numeric OTP `code` as a zero-padded decimal string of exactly
/// `digits` characters.
///
/// This preserves leading zeros — an HOTP/TOTP value such as `73921` at 6 digits
/// must display as `073921`, not `73921`. `digits` is clamped to the supported
/// range so this never panics; callers that need range validation should get it
/// from [`hotp`] / [`totp`], which reject out-of-range `digits` up front.
#[must_use]
pub fn format_code(code: u32, digits: u32) -> String {
    let width = (digits.clamp(MIN_DIGITS, MAX_DIGITS)) as usize;
    alloc::format!("{code:0width$}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4226 Appendix D — the standard 20-byte ASCII secret
    /// `"12345678901234567890"`.
    const RFC4226_KEY: &[u8] = b"12345678901234567890";

    /// RFC 4226 Appendix D, Table 1 (the "Truncated" / HOTP column): the first ten
    /// 6-digit HMAC-SHA-1 HOTP values for counters 0..=9. Matching these exactly is
    /// the correctness gate for the whole primitive.
    #[test]
    fn rfc4226_appendix_d_hotp_sha1() {
        const EXPECTED: [u32; 10] = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, want) in EXPECTED.iter().enumerate() {
            let got = hotp(RFC4226_KEY, counter as u64, 6, OtpAlgorithm::Sha1)
                .expect("valid digit count");
            assert_eq!(got, *want, "HOTP counter {counter}");
            // And the padded rendering must be exactly six characters.
            assert_eq!(format_code(got, 6).len(), 6);
        }
    }

    // RFC 6238 Appendix B secrets. The RFC uses a distinct key length per hash:
    // 20 ASCII bytes for SHA-1, 32 for SHA-256, 64 for SHA-512 (the ASCII digits
    // repeated to the required length).
    const RFC6238_KEY_SHA1: &[u8] = b"12345678901234567890";
    const RFC6238_KEY_SHA256: &[u8] = b"12345678901234567890123456789012";
    const RFC6238_KEY_SHA512: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    fn key_for(algorithm: OtpAlgorithm) -> &'static [u8] {
        match algorithm {
            OtpAlgorithm::Sha1 => RFC6238_KEY_SHA1,
            OtpAlgorithm::Sha256 => RFC6238_KEY_SHA256,
            OtpAlgorithm::Sha512 => RFC6238_KEY_SHA512,
        }
    }

    /// RFC 6238 Appendix B — the complete TOTP test-vector table: 8-digit codes,
    /// T0 = 0, period = 30 s, at six reference times, for all three hashes. Every
    /// one is an official known-answer vector.
    #[test]
    fn rfc6238_appendix_b_totp_all_hashes() {
        // (unix_time, sha1_code, sha256_code, sha512_code)
        const VECTORS: [(u64, u32, u32, u32); 6] = [
            (59, 94287082, 46119246, 90693936),
            (1111111109, 7081804, 68084774, 25091201),
            (1111111111, 14050471, 67062674, 99943326),
            (1234567890, 89005924, 91819424, 93441116),
            (2000000000, 69279037, 90698825, 38618901),
            (20000000000, 65353130, 77737706, 47863826),
        ];
        for (time, sha1, sha256, sha512) in VECTORS {
            for (algorithm, want) in [
                (OtpAlgorithm::Sha1, sha1),
                (OtpAlgorithm::Sha256, sha256),
                (OtpAlgorithm::Sha512, sha512),
            ] {
                let got =
                    totp(key_for(algorithm), time, 30, 0, 8, algorithm).expect("valid TOTP params");
                assert_eq!(got, want, "TOTP time={time} algorithm={algorithm:?}");
                assert_eq!(format_code(got, 8).len(), 8);
            }
        }
    }

    #[test]
    fn default_algorithm_is_sha1() {
        assert_eq!(OtpAlgorithm::default(), OtpAlgorithm::Sha1);
    }

    #[test]
    fn format_code_preserves_leading_zeros() {
        assert_eq!(format_code(73921, 6), "073921");
        assert_eq!(format_code(1, 6), "000001");
        assert_eq!(format_code(755224, 6), "755224");
        assert_eq!(format_code(7081804, 8), "07081804");
    }

    #[test]
    fn digits_out_of_range_rejected() {
        assert_eq!(
            hotp(RFC4226_KEY, 0, 5, OtpAlgorithm::Sha1),
            Err(OtpError::InvalidDigits(5))
        );
        assert_eq!(
            hotp(RFC4226_KEY, 0, 11, OtpAlgorithm::Sha1),
            Err(OtpError::InvalidDigits(11))
        );
        assert_eq!(
            hotp(RFC4226_KEY, 0, 0, OtpAlgorithm::Sha1),
            Err(OtpError::InvalidDigits(0))
        );
    }

    #[test]
    fn totp_period_and_time_validation() {
        assert_eq!(
            totp(RFC4226_KEY, 100, 0, 0, 6, OtpAlgorithm::Sha1),
            Err(OtpError::InvalidPeriod)
        );
        assert_eq!(
            totp(RFC4226_KEY, 10, 30, 100, 6, OtpAlgorithm::Sha1),
            Err(OtpError::TimeBeforeT0)
        );
    }

    #[test]
    fn totp_counter_matches_manual_hotp() {
        // TOTP at time=59, period=30, t0=0 uses counter = 59/30 = 1. Its 6-digit
        // SHA-1 value must equal HOTP(counter=1), which per RFC 4226 is 287082.
        let via_totp = totp(RFC6238_KEY_SHA1, 59, 30, 0, 6, OtpAlgorithm::Sha1).unwrap();
        let via_hotp = hotp(RFC6238_KEY_SHA1, 1, 6, OtpAlgorithm::Sha1).unwrap();
        assert_eq!(via_totp, via_hotp);
        assert_eq!(via_totp, 287082);
    }

    #[test]
    fn ten_digit_code_does_not_overflow() {
        // A 10-digit width must not panic on the 10^10 modulus (computed in u64).
        let code = hotp(RFC4226_KEY, 0, 10, OtpAlgorithm::Sha1).expect("10 digits ok");
        // The dynamic-truncation integer is 31-bit, so it always fits in a u32.
        assert!(code <= 0x7fff_ffff);
        assert_eq!(format_code(code, 10).len(), 10);
    }
}
