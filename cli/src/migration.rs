//! Google Authenticator migration (`otpauth-migration://offline?data=…`) codec.
//!
//! Google Authenticator's bulk export/import wraps a set of OTP accounts in a
//! protobuf ([proto3 wire format]) message, base64-encodes it, and hangs it off
//! an `otpauth-migration://offline?data=<BASE64>` URI (usually shown as a QR
//! code). This module is a HAND-ROLLED, DEPENDENCY-FREE codec for that message —
//! there is no protobuf library here, just the two proto3 wire types we need
//! (varint = 0 and length-delimited = 2), mirroring how the base32 codec was
//! hand-rolled elsewhere in this crate.
//!
//! The schema (proto3):
//!
//! ```text
//! message MigrationPayload {
//!   repeated OtpParameters otp_parameters = 1;
//!   int32 version = 2; int32 batch_size = 3;
//!   int32 batch_index = 4; int32 batch_id = 5;
//! }
//! message OtpParameters {
//!   bytes secret = 1; string name = 2; string issuer = 3;
//!   Algorithm algorithm = 4; DigitCount digits = 5;
//!   OtpType type = 6; int64 counter = 7;
//! }
//! enum Algorithm  { UNSPECIFIED=0; SHA1=1; SHA256=2; SHA512=3; MD5=4; }
//! enum DigitCount { UNSPECIFIED=0; SIX=1; EIGHT=2; }
//! enum OtpType    { UNSPECIFIED=0; HOTP=1; TOTP=2; }
//! ```
//!
//! This module is a pure protobuf codec: [`decode_migration_payload`] parses the
//! bytes into [`MigrationOtp`] records holding the RAW enum integers, and
//! [`encode_migration_payload`] renders them back. The mapping to/from the
//! crate's [`TotpEntry`] (SHA-1/256/512, 6/8 digits, TOTP only) lives in the
//! [`migration_otp_to_entry`] / [`entry_to_migration_otp`] converters so the
//! codec stays schema-agnostic and independently testable.
//!
//! STATUS: pre-audit, DEV-ONLY. Migration URIs carry OTP secrets IN THE CLEAR
//! (they are the plaintext provisioning form, not an encrypted container); the
//! export path warns loudly. Do NOT handle real 2FA secrets in this pre-audit
//! build.
//!
//! [proto3 wire format]: https://protobuf.dev/programming-guides/encoding/

use base64::engine::general_purpose::{STANDARD as BASE64, STANDARD_NO_PAD};
use base64::Engine as _;

use crate::{new_totp_entry, percent_decode, CliError, TotpEntry, TOTP_DEFAULT_PERIOD};
use sigil_core::OtpAlgorithm;

/// Proto3 wire type for base-128 varints (`int32`/`int64`/`enum`/`bool`).
const WIRE_VARINT: u8 = 0;
/// Proto3 wire type for length-delimited fields (`bytes`/`string`/embedded msg).
const WIRE_LEN: u8 = 2;

/// The `Algorithm` enum value for SHA-1 (the migration default).
const ALG_SHA1: i32 = 1;
/// The `Algorithm` enum value for SHA-256.
const ALG_SHA256: i32 = 2;
/// The `Algorithm` enum value for SHA-512.
const ALG_SHA512: i32 = 3;
/// The `Algorithm` enum value for MD5 (present in the schema; unsupported here).
const ALG_MD5: i32 = 4;

/// The `DigitCount` enum value for 6-digit codes.
const DIGITS_SIX: i32 = 1;
/// The `DigitCount` enum value for 8-digit codes.
const DIGITS_EIGHT: i32 = 2;

/// The `OtpType` enum value for HOTP (counter-based; skipped on import).
const OTP_HOTP: i32 = 1;
/// The `OtpType` enum value for TOTP (time-based; the only type we store).
const OTP_TOTP: i32 = 2;

/// The `version` field this build writes into an exported `MigrationPayload`.
/// (Decoding accepts any version; only the OTP parameters are consumed.)
const MIGRATION_PAYLOAD_VERSION: u64 = 1;

/// One decoded `OtpParameters` message, holding the RAW protobuf values.
///
/// The enum fields are kept as their raw wire integers (`algorithm`, `digits`,
/// `otp_type`) so this stays a faithful codec — the semantic mapping to the
/// crate's TOTP model happens in [`migration_otp_to_entry`]. `PartialEq` makes
/// the encode→decode round-trip test a direct equality assertion.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationOtp {
    /// Raw secret key bytes (NOT base32/base64 — the decoded key material).
    pub secret: Vec<u8>,
    /// Account name / label, e.g. `"Example:alice@google.com"`.
    pub name: String,
    /// Issuer / service name, e.g. `"Example"` (empty if absent).
    pub issuer: String,
    /// Raw `Algorithm` enum: 1=SHA1, 2=SHA256, 3=SHA512, 4=MD5, 0=unspecified.
    pub algorithm: i32,
    /// Raw `DigitCount` enum: 1=SIX, 2=EIGHT, 0=unspecified.
    pub digits: i32,
    /// Raw `OtpType` enum: 1=HOTP, 2=TOTP, 0=unspecified.
    pub otp_type: i32,
    /// HOTP counter (unused for TOTP).
    pub counter: i64,
}

/// The result of mapping one [`MigrationOtp`] to the crate's TOTP model.
pub enum ImportedOtp {
    /// A time-based entry ready to add to the vault.
    Totp(Box<TotpEntry>),
    /// A counter-based (HOTP) entry the caller should WARN about and SKIP — the
    /// vault stores period-based TOTP only and its JSON schema is not extended.
    SkippedHotp,
}

// ---------------------------------------------------------------------------
// Varint / length-delimited primitives (proto3 wire format).
// ---------------------------------------------------------------------------

/// Read one base-128 varint (LEB128, little-endian groups of 7 bits) from `buf`
/// at `*pos`, advancing `*pos` past it.
///
/// Caps at 10 bytes (the max for a 64-bit varint) so malformed, unterminated, or
/// hostile input can never spin or read unboundedly.
///
/// # Errors
/// - [`CliError::Totp`] if the varint runs off the end or exceeds 10 bytes.
fn read_varint(buf: &[u8], pos: &mut usize) -> Result<u64, CliError> {
    let mut result: u64 = 0;
    let mut shift: u32 = 0;
    for _ in 0..10 {
        let byte = *buf.get(*pos).ok_or_else(|| {
            CliError::Totp("migration payload: varint runs past end of buffer".to_string())
        })?;
        *pos += 1;
        result |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(result);
        }
        shift += 7;
    }
    Err(CliError::Totp(
        "migration payload: varint longer than 10 bytes".to_string(),
    ))
}

/// Read a length-delimited field body (a varint length followed by that many
/// bytes) from `buf` at `*pos`, returning the inner slice and advancing `*pos`.
///
/// # Errors
/// - [`CliError::Totp`] if the length overflows or runs past the buffer end.
fn read_len_delimited<'a>(buf: &'a [u8], pos: &mut usize) -> Result<&'a [u8], CliError> {
    let len = read_varint(buf, pos)? as usize;
    let end = pos
        .checked_add(len)
        .filter(|&e| e <= buf.len())
        .ok_or_else(|| {
            CliError::Totp("migration payload: length-delimited field runs past end".to_string())
        })?;
    let slice = &buf[*pos..end];
    *pos = end;
    Ok(slice)
}

/// Skip an unknown field of `wire` type at `*pos`, so forward-compatible or
/// unexpected fields (e.g. `batch_*`, a 64/32-bit field) never break decoding.
///
/// # Errors
/// - [`CliError::Totp`] on an unknown wire type or a field that runs past the end.
fn skip_field(buf: &[u8], pos: &mut usize, wire: u8) -> Result<(), CliError> {
    match wire {
        WIRE_VARINT => {
            read_varint(buf, pos)?;
        }
        WIRE_LEN => {
            read_len_delimited(buf, pos)?;
        }
        1 => {
            // 64-bit fixed
            *pos = pos
                .checked_add(8)
                .filter(|&e| e <= buf.len())
                .ok_or_else(|| {
                    CliError::Totp("migration payload: 64-bit field runs past end".to_string())
                })?;
        }
        5 => {
            // 32-bit fixed
            *pos = pos
                .checked_add(4)
                .filter(|&e| e <= buf.len())
                .ok_or_else(|| {
                    CliError::Totp("migration payload: 32-bit field runs past end".to_string())
                })?;
        }
        other => {
            return Err(CliError::Totp(format!(
                "migration payload: unknown wire type {other}"
            )))
        }
    }
    Ok(())
}

/// Append `value` to `out` as a base-128 varint.
fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Append a field tag `(field_number << 3) | wire_type`.
fn write_tag(out: &mut Vec<u8>, field: u64, wire: u8) {
    write_varint(out, (field << 3) | u64::from(wire));
}

/// Append a varint (wire type 0) field.
fn write_varint_field(out: &mut Vec<u8>, field: u64, value: u64) {
    write_tag(out, field, WIRE_VARINT);
    write_varint(out, value);
}

/// Append a length-delimited (wire type 2) field.
fn write_len_field(out: &mut Vec<u8>, field: u64, data: &[u8]) {
    write_tag(out, field, WIRE_LEN);
    write_varint(out, data.len() as u64);
    out.extend_from_slice(data);
}

// ---------------------------------------------------------------------------
// Message codec.
// ---------------------------------------------------------------------------

/// Decode one `OtpParameters` sub-message from `buf`.
///
/// Known fields (1..=7) are read into a [`MigrationOtp`]; any other field is
/// skipped by wire type. Strings are decoded lossily (names are UTF-8 in
/// practice; this never rejects an odd byte).
fn decode_otp_parameters(buf: &[u8]) -> Result<MigrationOtp, CliError> {
    let mut otp = MigrationOtp::default();
    let mut pos = 0usize;
    while pos < buf.len() {
        let tag = read_varint(buf, &mut pos)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, WIRE_LEN) => otp.secret = read_len_delimited(buf, &mut pos)?.to_vec(),
            (2, WIRE_LEN) => {
                otp.name = String::from_utf8_lossy(read_len_delimited(buf, &mut pos)?).into_owned()
            }
            (3, WIRE_LEN) => {
                otp.issuer =
                    String::from_utf8_lossy(read_len_delimited(buf, &mut pos)?).into_owned()
            }
            (4, WIRE_VARINT) => otp.algorithm = read_varint(buf, &mut pos)? as i32,
            (5, WIRE_VARINT) => otp.digits = read_varint(buf, &mut pos)? as i32,
            (6, WIRE_VARINT) => otp.otp_type = read_varint(buf, &mut pos)? as i32,
            (7, WIRE_VARINT) => otp.counter = read_varint(buf, &mut pos)? as i64,
            _ => skip_field(buf, &mut pos, wire)?,
        }
    }
    Ok(otp)
}

/// Decode a `MigrationPayload` into its list of [`MigrationOtp`] records.
///
/// Only `otp_parameters` (field 1) is retained; `version`/`batch_*` and any
/// unknown field are consumed and ignored. Truncated or malformed bytes yield a
/// clear [`CliError::Totp`], never a panic.
///
/// # Errors
/// - [`CliError::Totp`] on a malformed varint, an overrunning length, or an
///   unknown wire type.
pub fn decode_migration_payload(buf: &[u8]) -> Result<Vec<MigrationOtp>, CliError> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while pos < buf.len() {
        let tag = read_varint(buf, &mut pos)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, WIRE_LEN) => {
                let msg = read_len_delimited(buf, &mut pos)?;
                out.push(decode_otp_parameters(msg)?);
            }
            // version / batch_size / batch_index / batch_id — consumed, ignored.
            (2..=5, WIRE_VARINT) => {
                read_varint(buf, &mut pos)?;
            }
            _ => skip_field(buf, &mut pos, wire)?,
        }
    }
    Ok(out)
}

/// Encode one [`MigrationOtp`] into an `OtpParameters` sub-message.
///
/// Proto3 omits fields at their default (zero/empty) value; every non-default
/// field is written in ascending field-number order.
fn encode_otp_parameters(otp: &MigrationOtp) -> Vec<u8> {
    let mut out = Vec::new();
    if !otp.secret.is_empty() {
        write_len_field(&mut out, 1, &otp.secret);
    }
    if !otp.name.is_empty() {
        write_len_field(&mut out, 2, otp.name.as_bytes());
    }
    if !otp.issuer.is_empty() {
        write_len_field(&mut out, 3, otp.issuer.as_bytes());
    }
    if otp.algorithm != 0 {
        write_varint_field(&mut out, 4, otp.algorithm as u64);
    }
    if otp.digits != 0 {
        write_varint_field(&mut out, 5, otp.digits as u64);
    }
    if otp.otp_type != 0 {
        write_varint_field(&mut out, 6, otp.otp_type as u64);
    }
    if otp.counter != 0 {
        write_varint_field(&mut out, 7, otp.counter as u64);
    }
    out
}

/// Encode a slice of [`MigrationOtp`] into a full `MigrationPayload` blob.
///
/// Writes each account as an `otp_parameters` (field 1) sub-message, then
/// `version` (field 2) and `batch_size` (field 3) `= 1`. This is the exact
/// inverse of [`decode_migration_payload`] for the fields we model.
#[must_use]
pub fn encode_migration_payload(params: &[MigrationOtp]) -> Vec<u8> {
    let mut out = Vec::new();
    for otp in params {
        let msg = encode_otp_parameters(otp);
        write_len_field(&mut out, 1, &msg);
    }
    write_varint_field(&mut out, 2, MIGRATION_PAYLOAD_VERSION);
    // A single self-contained batch. batch_index/batch_id stay at their 0
    // defaults (omitted); real GA sets a random batch_id, but importers ignore it.
    write_varint_field(&mut out, 3, 1);
    out
}

// ---------------------------------------------------------------------------
// URI wrappers.
// ---------------------------------------------------------------------------

/// The `otpauth-migration://` scheme prefix (case-insensitive on decode).
const MIGRATION_SCHEME: &str = "otpauth-migration://";

/// Decode an `otpauth-migration://offline?data=<BASE64>` URI into its accounts.
///
/// Extracts the `data` query parameter, percent-decodes it, then base64-decodes
/// it tolerantly — accepting standard or URL-safe alphabets, with or without
/// padding — and parses the resulting `MigrationPayload`.
///
/// # Errors
/// - [`CliError::Totp`] on a wrong scheme, a missing `data` parameter, a bad
///   base64 body, or a malformed payload.
pub fn decode_migration_uri(uri: &str) -> Result<Vec<MigrationOtp>, CliError> {
    let trimmed = uri.trim();
    if !trimmed.to_ascii_lowercase().starts_with(MIGRATION_SCHEME) {
        return Err(CliError::Totp(
            "not an otpauth-migration:// URI".to_string(),
        ));
    }
    let query = trimmed.split_once('?').map(|(_, q)| q).unwrap_or("");
    let data = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("data="))
        .ok_or_else(|| {
            CliError::Totp("otpauth-migration URI has no data= parameter".to_string())
        })?;
    let bytes = decode_migration_data(data)?;
    decode_migration_payload(&bytes)
}

/// Base64-decode a migration `data` value, tolerating both alphabets/paddings.
///
/// The value may arrive percent-encoded (`%2B` etc.), standard or URL-safe, and
/// with or without `=` padding, depending on the producer. We percent-decode,
/// normalize `-_` → `+/`, strip whitespace and padding, and decode with a
/// no-pad standard engine.
fn decode_migration_data(data: &str) -> Result<Vec<u8>, CliError> {
    let decoded = percent_decode(data);
    let normalized: String = decoded
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    let trimmed = normalized.trim_end_matches('=');
    STANDARD_NO_PAD
        .decode(trimmed.as_bytes())
        .map_err(|e| CliError::Totp(format!("migration data is not valid base64: {e}")))
}

/// Build an `otpauth-migration://offline?data=<BASE64>` URI for `params`.
///
/// The payload is standard-base64 encoded (the form Google Authenticator emits);
/// [`decode_migration_uri`] reads it back. Note the output carries the OTP
/// SECRETS in the clear — callers must warn before printing it.
#[must_use]
pub fn encode_migration_uri(params: &[MigrationOtp]) -> String {
    let data = BASE64.encode(encode_migration_payload(params));
    format!("{MIGRATION_SCHEME}offline?data={data}")
}

// ---------------------------------------------------------------------------
// Conversion to/from the crate's TotpEntry model.
// ---------------------------------------------------------------------------

/// Map a decoded [`MigrationOtp`] to a [`TotpEntry`], applying this crate's
/// model constraints.
///
/// - `Algorithm`: SHA1/SHA256/SHA512 → the matching hash; MD5 or unspecified is
///   rejected with a clear error.
/// - `DigitCount`: SIX → 6, EIGHT → 8; unspecified (0) defaults to 6 (Google
///   omits the field for the common 6-digit case).
/// - `OtpType`: TOTP is imported; HOTP yields [`ImportedOtp::SkippedHotp`] (the
///   vault stores period-based TOTP only); any other type is rejected.
///
/// The migration format carries no period, so [`TOTP_DEFAULT_PERIOD`] (30 s) is
/// used — the standard for Google Authenticator TOTP accounts.
///
/// # Errors
/// - [`CliError::Totp`] on MD5/unspecified algorithm, an unknown digit count, a
///   non-TOTP/non-HOTP type, an empty name, or an empty secret.
pub fn migration_otp_to_entry(otp: &MigrationOtp) -> Result<ImportedOtp, CliError> {
    match otp.otp_type {
        OTP_TOTP => {}
        OTP_HOTP => return Ok(ImportedOtp::SkippedHotp),
        other => {
            return Err(CliError::Totp(format!(
                "unsupported OTP type {other} (expected TOTP)"
            )))
        }
    }

    let algorithm = match otp.algorithm {
        ALG_SHA1 => OtpAlgorithm::Sha1,
        ALG_SHA256 => OtpAlgorithm::Sha256,
        ALG_SHA512 => OtpAlgorithm::Sha512,
        ALG_MD5 => return Err(CliError::Totp("MD5 algorithm is not supported".to_string())),
        other => {
            return Err(CliError::Totp(format!(
                "unsupported/unspecified algorithm {other} (expected SHA1, SHA256, or SHA512)"
            )))
        }
    };

    let digits = match otp.digits {
        DIGITS_SIX => 6,
        DIGITS_EIGHT => 8,
        // Unspecified: Google omits the field for the default 6-digit case.
        0 => 6,
        other => {
            return Err(CliError::Totp(format!(
                "unsupported digit count {other} (expected SIX or EIGHT)"
            )))
        }
    };

    if otp.secret.is_empty() {
        return Err(CliError::Totp("entry has an empty secret".to_string()));
    }
    if otp.name.is_empty() {
        return Err(CliError::Totp("entry has an empty name".to_string()));
    }

    let issuer = if otp.issuer.is_empty() {
        None
    } else {
        Some(otp.issuer.clone())
    };

    let entry = new_totp_entry(
        &otp.name,
        issuer,
        &otp.secret,
        algorithm,
        digits,
        TOTP_DEFAULT_PERIOD,
    )?;
    Ok(ImportedOtp::Totp(Box::new(entry)))
}

/// Map a [`TotpEntry`] to a [`MigrationOtp`] for export.
///
/// The migration format only expresses SHA1/256/512, 6/8 digits, a fixed 30 s
/// period, and TOTP; an entry outside that (e.g. 7 digits) is rejected rather
/// than silently corrupted. The entry's `period` is NOT representable in the
/// format and is dropped (Google Authenticator TOTP is always 30 s); use the
/// plain `otpauth://` export to preserve a non-standard period.
///
/// # Errors
/// - [`CliError::Totp`] on a bad stored secret, an unknown algorithm, or a digit
///   count other than 6 or 8.
pub fn entry_to_migration_otp(entry: &TotpEntry) -> Result<MigrationOtp, CliError> {
    let secret = entry.secret_bytes()?;
    let algorithm = match entry.otp_algorithm()? {
        OtpAlgorithm::Sha1 => ALG_SHA1,
        OtpAlgorithm::Sha256 => ALG_SHA256,
        OtpAlgorithm::Sha512 => ALG_SHA512,
        _ => {
            return Err(CliError::Totp(
                "unsupported algorithm for migration".to_string(),
            ))
        }
    };
    let digits = match entry.digits {
        6 => DIGITS_SIX,
        8 => DIGITS_EIGHT,
        other => {
            return Err(CliError::Totp(format!(
                "cannot export {other}-digit entry {:?} to migration format (only 6 or 8)",
                entry.label
            )))
        }
    };
    Ok(MigrationOtp {
        secret,
        name: entry.label.clone(),
        issuer: entry.issuer.clone().unwrap_or_default(),
        algorithm,
        digits,
        otp_type: OTP_TOTP,
        counter: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base32_encode;

    /// The canonical Google Authenticator migration example (a single TOTP
    /// account) — a REAL, documented export decoding to known values:
    ///   secret base32 = JBSWY3DPEHPK3PXP  (raw = b"Hello!" ‖ DE AD BE EF),
    ///   name = "Example:alice@google.com", issuer = "Example",
    ///   algorithm SHA1, digits SIX, type TOTP.
    ///
    /// This is the properly-nested form: the `OtpParameters` length includes the
    /// digits+type fields (the widely-copied `CjEK…` string truncates the
    /// sub-message after `algorithm`, spilling digits/type/version to the top
    /// level; the correct sub-message length byte is 0x35, giving `CjUK…`).
    const GOLDEN_URI: &str = "otpauth-migration://offline?data=CjUKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZSABKAEwAhAB";

    #[test]
    fn golden_google_authenticator_example_decodes_to_documented_values() {
        let params = decode_migration_uri(GOLDEN_URI).expect("golden decodes");
        assert_eq!(params.len(), 1, "one account in the golden example");
        let p = &params[0];

        let mut expected_secret = b"Hello!".to_vec();
        expected_secret.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(p.secret, expected_secret, "raw secret bytes");
        // ...and the documented base32 form of that secret.
        assert_eq!(base32_encode(&p.secret), "JBSWY3DPEHPK3PXP");

        assert_eq!(p.name, "Example:alice@google.com");
        assert_eq!(p.issuer, "Example");
        assert_eq!(p.algorithm, ALG_SHA1);
        assert_eq!(p.digits, DIGITS_SIX);
        assert_eq!(p.otp_type, OTP_TOTP);

        // And it maps to a well-formed TOTP entry.
        match migration_otp_to_entry(p).expect("maps") {
            ImportedOtp::Totp(e) => {
                assert_eq!(e.label, "Example:alice@google.com");
                assert_eq!(e.issuer.as_deref(), Some("Example"));
                assert_eq!(e.algorithm, "sha1");
                assert_eq!(e.digits, 6);
                assert_eq!(e.period, TOTP_DEFAULT_PERIOD);
                assert_eq!(e.secret_bytes().unwrap(), expected_secret);
            }
            ImportedOtp::SkippedHotp => panic!("golden account is TOTP, not HOTP"),
        }
    }

    #[test]
    fn encode_decode_round_trip_preserves_all_accounts() {
        // A few accounts with varied algorithm/digits/type/issuer to exercise the
        // varint + length-delimited paths and multi-byte varints (a long secret).
        let long_secret: Vec<u8> = (0u8..200).collect(); // length 200 -> 2-byte varint len
        let originals = vec![
            MigrationOtp {
                secret: b"\x00\x01\x02\x03short".to_vec(),
                name: "acct-sha1".to_string(),
                issuer: "IssuerOne".to_string(),
                algorithm: ALG_SHA1,
                digits: DIGITS_SIX,
                otp_type: OTP_TOTP,
                counter: 0,
            },
            MigrationOtp {
                secret: b"another-secret-256".to_vec(),
                name: "acct-sha256".to_string(),
                issuer: String::new(), // no issuer -> field omitted, decodes to ""
                algorithm: ALG_SHA256,
                digits: DIGITS_EIGHT,
                otp_type: OTP_TOTP,
                counter: 0,
            },
            MigrationOtp {
                secret: long_secret,
                name: "acct-sha512-long".to_string(),
                issuer: "Issuer Three".to_string(),
                algorithm: ALG_SHA512,
                digits: DIGITS_SIX,
                otp_type: OTP_HOTP,
                counter: 42, // HOTP counter -> exercises field 7
            },
        ];

        let encoded = encode_migration_payload(&originals);
        let decoded = decode_migration_payload(&encoded).expect("decode round-trip");
        assert_eq!(decoded, originals, "encode->decode must be the identity");

        // And it survives the full URI wrapper (base64 + scheme) too.
        let uri = encode_migration_uri(&originals);
        let via_uri = decode_migration_uri(&uri).expect("uri round-trip");
        assert_eq!(via_uri, originals);
    }

    #[test]
    fn entry_migration_otp_round_trip() {
        // TotpEntry -> MigrationOtp -> encode -> decode -> back to TotpEntry.
        let entry = new_totp_entry(
            "alice@example.com",
            Some("GitHub".to_string()),
            b"1234567890",
            OtpAlgorithm::Sha256,
            8,
            TOTP_DEFAULT_PERIOD,
        )
        .expect("entry");
        let otp = entry_to_migration_otp(&entry).expect("to migration");
        let bytes = encode_migration_payload(std::slice::from_ref(&otp));
        let decoded = decode_migration_payload(&bytes).expect("decode");
        assert_eq!(decoded.len(), 1);
        match migration_otp_to_entry(&decoded[0]).expect("back to entry") {
            ImportedOtp::Totp(back) => assert_eq!(*back, entry),
            ImportedOtp::SkippedHotp => panic!("should be TOTP"),
        }
    }

    #[test]
    fn hotp_is_skipped_not_errored() {
        let otp = MigrationOtp {
            secret: b"seed".to_vec(),
            name: "counter-based".to_string(),
            issuer: String::new(),
            algorithm: ALG_SHA1,
            digits: DIGITS_SIX,
            otp_type: OTP_HOTP,
            counter: 5,
        };
        assert!(matches!(
            migration_otp_to_entry(&otp),
            Ok(ImportedOtp::SkippedHotp)
        ));
    }

    #[test]
    fn md5_and_unspecified_algorithm_are_rejected() {
        for bad_alg in [ALG_MD5, 0] {
            let otp = MigrationOtp {
                secret: b"seed".to_vec(),
                name: "n".to_string(),
                issuer: String::new(),
                algorithm: bad_alg,
                digits: DIGITS_SIX,
                otp_type: OTP_TOTP,
                counter: 0,
            };
            assert!(matches!(
                migration_otp_to_entry(&otp),
                Err(CliError::Totp(_))
            ));
        }
    }

    #[test]
    fn unspecified_digits_defaults_to_six() {
        let otp = MigrationOtp {
            secret: b"seed".to_vec(),
            name: "n".to_string(),
            issuer: String::new(),
            algorithm: ALG_SHA1,
            digits: 0, // DIGIT_COUNT_UNSPECIFIED
            otp_type: OTP_TOTP,
            counter: 0,
        };
        match migration_otp_to_entry(&otp).expect("maps") {
            ImportedOtp::Totp(e) => assert_eq!(e.digits, 6),
            ImportedOtp::SkippedHotp => panic!("TOTP"),
        }
    }

    #[test]
    fn truncated_payload_is_rejected_without_panic() {
        let full = encode_migration_uri(&[MigrationOtp {
            secret: b"abcdefgh".to_vec(),
            name: "n".to_string(),
            issuer: String::new(),
            algorithm: ALG_SHA1,
            digits: DIGITS_SIX,
            otp_type: OTP_TOTP,
            counter: 0,
        }]);
        // Corrupt the raw payload: a length that overruns the buffer.
        let bad = decode_migration_data(full.split_once("data=").unwrap().1).unwrap();
        // Chop the last few bytes so a length-delimited field overruns.
        let truncated = &bad[..bad.len().saturating_sub(3)];
        assert!(matches!(
            decode_migration_payload(truncated),
            Err(CliError::Totp(_))
        ));
    }

    #[test]
    fn unknown_fields_are_skipped() {
        // Hand-build a payload with an unknown field (field 9, varint) at the top
        // level and inside the OtpParameters, plus a fixed64 (wire type 1) — all
        // must be skipped, leaving the known account intact.
        let mut otp_msg = Vec::new();
        write_len_field(&mut otp_msg, 1, b"secretbytes"); // secret
        write_len_field(&mut otp_msg, 2, b"acct"); // name
        write_varint_field(&mut otp_msg, 4, ALG_SHA1 as u64);
        write_varint_field(&mut otp_msg, 5, DIGITS_SIX as u64);
        write_varint_field(&mut otp_msg, 6, OTP_TOTP as u64);
        write_varint_field(&mut otp_msg, 9, 12345); // unknown varint field
        write_tag(&mut otp_msg, 10, 1); // unknown fixed64 field
        otp_msg.extend_from_slice(&[0u8; 8]);

        let mut payload = Vec::new();
        write_len_field(&mut payload, 1, &otp_msg);
        write_varint_field(&mut payload, 2, 1); // version
        write_varint_field(&mut payload, 7, 999); // unknown top-level field

        let decoded = decode_migration_payload(&payload).expect("skips unknowns");
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].secret, b"secretbytes");
        assert_eq!(decoded[0].name, "acct");
        assert_eq!(decoded[0].algorithm, ALG_SHA1);
    }
}
