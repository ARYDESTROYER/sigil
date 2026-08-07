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

/// ⭐ A decoded `MigrationPayload`, INCLUDING the batch framing (Phase 59).
///
/// ⛔ **Why this type exists.** Google Authenticator splits a large export across
/// several QR codes. Each QR is a complete, independently-decodable
/// `MigrationPayload` carrying `batch_size` / `batch_index` / `batch_id`, and the
/// accounts are divided between them. This codec used to consume those three
/// fields and throw them away, so scanning the first QR of a three-QR export
/// imported a THIRD of the accounts and reported plain success — silent data loss
/// in the one feature whose entire purpose is not losing data, hitting exactly
/// the users with the most accounts.
///
/// Now the framing is decoded and carried, and [`Self::is_complete`] /
/// [`Self::batch_note`] make it impossible to describe a partial import as a
/// whole one without ignoring them on purpose.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MigrationBatch {
    /// The accounts carried by THIS payload — which may be a fraction of the
    /// export (see [`Self::batch_size`]).
    pub otps: Vec<MigrationOtp>,
    /// The payload's `version` field (informational; decoding accepts any).
    pub version: i32,
    /// How many QR codes / payloads the whole export was split into. `0` or `1`
    /// (the field is omitted at its proto3 default) means a single payload.
    pub batch_size: i32,
    /// Which payload this is, ZERO-BASED, as Google writes it. Omitted (`0`) for
    /// the first, which is also the value a single-payload export carries.
    pub batch_index: i32,
    /// An id shared by every payload of one export, so a caller collecting
    /// several can tell they belong together. `0` when absent.
    pub batch_id: i32,
}

impl MigrationBatch {
    /// Whether this payload is the WHOLE export.
    ///
    /// False as soon as `batch_size > 1` — i.e. there are other QR codes whose
    /// accounts are not in `otps`. A caller must not report success as
    /// "imported N accounts" when this is false; see [`Self::batch_note`].
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.batch_size <= 1
    }

    /// Whether this payload is the **LAST** QR of a multi-QR export.
    ///
    /// ⛔ Distinct from [`Self::is_complete`], and the distinction is the whole
    /// point: batch 2 of 2 is NOT the whole export (there was a batch 1), but
    /// nothing further needs scanning. Telling a user who has just finished that
    /// "0 more QR code(s) must be imported — this import is PARTIAL" is a warning
    /// that cries wolf, and a warning that cries wolf is one the next user
    /// ignores when it is real.
    ///
    /// False for a single-payload export, which is [`Self::is_complete`] instead.
    #[must_use]
    pub fn is_final_batch(&self) -> bool {
        !self.is_complete() && self.batch_index + 1 >= self.batch_size
    }

    /// A human-readable "batch i of N" note, or `None` for a single-payload
    /// export.
    ///
    /// `batch_index` is zero-based on the wire; this renders it one-based,
    /// because "batch 0 of 3" reads like nothing was imported.
    ///
    /// ⭐ TWO WORDINGS, because there are two situations. While QR codes remain
    /// the note says the import is **PARTIAL** and how many are outstanding. On
    /// the **final** batch nothing is outstanding, so it says so — while still
    /// naming the earlier batches, since this client has no cross-invocation
    /// state and genuinely cannot know whether they were imported. Callers pick
    /// their framing from [`Self::is_final_batch`], not from the string.
    #[must_use]
    pub fn batch_note(&self) -> Option<String> {
        if self.is_complete() {
            return None;
        }
        if self.is_final_batch() {
            let earlier = (self.batch_size - 1).max(0);
            return Some(format!(
                "this was batch {} of {} — the LAST QR code of a MULTI-QR Google \
                 Authenticator export (batch id {}), carrying {} of the accounts. \
                 Nothing further needs scanning from this export. Check that the \
                 earlier {earlier} QR code(s) were imported too before deleting \
                 anything from the old app",
                self.batch_index + 1,
                self.batch_size,
                self.batch_id,
                self.otps.len(),
            ));
        }
        let remaining = (self.batch_size - self.batch_index - 1).max(0);
        Some(format!(
            "this is batch {} of {} from a MULTI-QR Google Authenticator export \
             (batch id {}): it carries {} of the accounts, and {remaining} more QR \
             code(s) must be imported before the transfer is complete. This import \
             is PARTIAL",
            self.batch_index + 1,
            self.batch_size,
            self.batch_id,
            self.otps.len(),
        ))
    }
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

/// Decode a `MigrationPayload` into its accounts AND its batch framing.
///
/// ⭐ `version` / `batch_size` / `batch_index` / `batch_id` are DECODED, not
/// discarded — see [`MigrationBatch`] for why that matters. Unknown fields are
/// still skipped. Truncated or malformed bytes yield a clear [`CliError::Totp`],
/// never a panic.
///
/// # Errors
/// - [`CliError::Totp`] on a malformed varint, an overrunning length, or an
///   unknown wire type.
pub fn decode_migration_payload(buf: &[u8]) -> Result<MigrationBatch, CliError> {
    let mut out = MigrationBatch::default();
    let mut pos = 0usize;
    while pos < buf.len() {
        let tag = read_varint(buf, &mut pos)?;
        let field = tag >> 3;
        let wire = (tag & 0x07) as u8;
        match (field, wire) {
            (1, WIRE_LEN) => {
                // ⭐ THE COUNT CEILING, CHECKED BEFORE THE PUSH (Phase 63). A
                // migration URI is a stranger's bytes and nothing in the wire
                // format bounds how many accounts it declares, so this loop was
                // an unbounded allocation driven entirely by attacker input.
                // Refusing here means we never build the list we would then
                // throw away. See `sigil_core::MAX_PROVISIONING_ENTRIES` for why
                // the number is 512.
                sigil_core::validate_provisioning_count(out.otps.len() + 1)
                    .map_err(|e| CliError::Totp(e.to_string()))?;
                let msg = read_len_delimited(buf, &mut pos)?;
                out.otps.push(decode_otp_parameters(msg)?);
            }
            (2, WIRE_VARINT) => out.version = read_varint(buf, &mut pos)? as i32,
            (3, WIRE_VARINT) => out.batch_size = read_varint(buf, &mut pos)? as i32,
            (4, WIRE_VARINT) => out.batch_index = read_varint(buf, &mut pos)? as i32,
            (5, WIRE_VARINT) => out.batch_id = read_varint(buf, &mut pos)? as i32,
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

/// Decode an `otpauth-migration://offline?data=<BASE64>` URI into a
/// [`MigrationBatch`] — its accounts AND the batch framing.
///
/// Extracts the `data` query parameter, percent-decodes it, then base64-decodes
/// it tolerantly — accepting standard or URL-safe alphabets, with or without
/// padding — and parses the resulting `MigrationPayload`.
///
/// ⚠️ One URI is ONE QR code. A large Google Authenticator export spans several,
/// and this returns only what THIS one carried: check
/// [`MigrationBatch::is_complete`] before telling a user the transfer is done.
///
/// # Errors
/// - [`CliError::Totp`] on a wrong scheme, a missing `data` parameter, a bad
///   base64 body, or a malformed payload.
pub fn decode_migration_uri(uri: &str) -> Result<MigrationBatch, CliError> {
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

    // ⭐ THE SAME UNTRUSTED-TEXT GATE AS THE URI DOOR (Phase 63). A migration
    // payload is a stranger's bytes too — and it is the door that carries MANY
    // accounts at once, so a hostile name/issuer here is replicated across every
    // client through the op-log. `period` is not attacker-chosen on this path
    // (the wire format has no period field; it is always 30 s), but the label,
    // the issuer and the secret length all are.
    crate::check_provisioning(
        &otp.name,
        issuer.as_deref(),
        otp.secret.len(),
        digits,
        TOTP_DEFAULT_PERIOD,
    )?;

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
/// period, and TOTP; an entry outside that is REJECTED rather than silently
/// corrupted.
///
/// ⛔ **The period is part of that (Phase 59).** The wire format has no period
/// field — Google Authenticator TOTP is always 30 s — so an entry with, say, a
/// 60 s period used to be exported as if it were 30 s. The importing app would
/// then compute a DIFFERENT CODE from the same secret, i.e. the export was a
/// silent lie about an account that would simply stop working. It is now refused,
/// and the error points at the plain `otpauth://` export, which carries `period`
/// faithfully.
///
/// # Errors
/// - [`CliError::Totp`] on a bad stored secret, an unknown algorithm, a digit
///   count other than 6 or 8, or a period other than
///   [`TOTP_DEFAULT_PERIOD`] (30 s).
pub fn entry_to_migration_otp(entry: &TotpEntry) -> Result<MigrationOtp, CliError> {
    if entry.period != TOTP_DEFAULT_PERIOD {
        return Err(CliError::Totp(format!(
            "cannot export {:?} to the Google Authenticator migration format: its period is \
             {} s and that format can only express {TOTP_DEFAULT_PERIOD} s, so the exported \
             account would generate the WRONG codes. Use the plain `otpauth://` export \
             instead — it carries the period",
            entry.label, entry.period
        )));
    }
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
        let batch = decode_migration_uri(GOLDEN_URI).expect("golden decodes");
        assert_eq!(batch.otps.len(), 1, "one account in the golden example");
        // The real Google export is a SINGLE-batch one, so it is complete.
        assert!(batch.is_complete());
        assert!(batch.batch_note().is_none());
        let p = &batch.otps[0];

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
        assert_eq!(
            decoded.otps, originals,
            "encode->decode must be the identity"
        );
        assert_eq!(decoded.version, MIGRATION_PAYLOAD_VERSION as i32);
        assert_eq!(decoded.batch_size, 1);

        // And it survives the full URI wrapper (base64 + scheme) too.
        let uri = encode_migration_uri(&originals);
        let via_uri = decode_migration_uri(&uri).expect("uri round-trip");
        assert_eq!(via_uri.otps, originals);
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
        assert_eq!(decoded.otps.len(), 1);
        match migration_otp_to_entry(&decoded.otps[0]).expect("back to entry") {
            ImportedOtp::Totp(back) => {
                // The migration wire format has no field for a Sigil-local entry
                // id, so the imported entry gets a FRESH uuid — deliberately: it
                // is a different entry in a different vault. Everything the
                // format DOES carry must survive byte-identically.
                assert!(back.uuid.is_some(), "an imported entry gets an id");
                assert_ne!(back.uuid, entry.uuid);
                let mut normalized = *back;
                normalized.uuid = entry.uuid.clone();
                assert_eq!(normalized, entry);
            }
            ImportedOtp::SkippedHotp => panic!("should be TOTP"),
        }
    }

    /// Build a payload the way real Google Authenticator does for one QR of a
    /// MULTI-QR export: the accounts for this slice plus the batch framing.
    fn multi_qr_payload(otps: &[MigrationOtp], size: i32, index: i32, id: i32) -> Vec<u8> {
        let mut out = Vec::new();
        for otp in otps {
            let msg = encode_otp_parameters(otp);
            write_len_field(&mut out, 1, &msg);
        }
        write_varint_field(&mut out, 2, MIGRATION_PAYLOAD_VERSION);
        write_varint_field(&mut out, 3, size as u64);
        write_varint_field(&mut out, 4, index as u64);
        write_varint_field(&mut out, 5, id as u64);
        out
    }

    fn sample_otp(name: &str) -> MigrationOtp {
        MigrationOtp {
            secret: b"secretbytes".to_vec(),
            name: name.to_string(),
            issuer: "Svc".to_string(),
            algorithm: ALG_SHA1,
            digits: DIGITS_SIX,
            otp_type: OTP_TOTP,
            counter: 0,
        }
    }

    // --- ⛔ MULTI-QR EXPORTS ARE NO LONGER SILENTLY TRUNCATED (Phase 59) -----

    #[test]
    fn batch_framing_is_decoded_not_discarded() {
        let payload = multi_qr_payload(&[sample_otp("a"), sample_otp("b")], 3, 1, 77);
        let batch = decode_migration_payload(&payload).expect("decode");
        assert_eq!(batch.otps.len(), 2);
        assert_eq!(batch.batch_size, 3);
        assert_eq!(batch.batch_index, 1);
        assert_eq!(batch.batch_id, 77);
        assert_eq!(batch.version, MIGRATION_PAYLOAD_VERSION as i32);
    }

    #[test]
    fn a_partial_batch_can_never_read_as_a_whole_import() {
        // Batch 1 of 3 — what a user scanning the FIRST QR of a 30-account
        // export gets. Before Phase 59 this returned two entries and nothing
        // else, and the CLI printed "imported 2" with no warning at all.
        let batch = decode_migration_payload(&multi_qr_payload(
            &[sample_otp("a"), sample_otp("b")],
            3,
            0,
            77,
        ))
        .expect("decode");
        assert!(!batch.is_complete(), "batch_size 3 is not the whole export");
        let note = batch.batch_note().expect("a note is produced");
        // One-based, names the total, and says what is still missing.
        assert!(note.contains("batch 1 of 3"), "{note}");
        assert!(note.contains("2 more QR"), "{note}");
        assert!(note.contains("PARTIAL"), "{note}");

        // The LAST batch of a multi-QR export is still not, on its own, the
        // whole export — the other QRs' accounts are not here either.
        let last =
            decode_migration_payload(&multi_qr_payload(&[sample_otp("c")], 3, 2, 77)).expect("d");
        assert!(!last.is_complete());
        assert!(last.is_final_batch());
        let note = last.batch_note().expect("note");
        assert!(note.contains("batch 3 of 3"), "{note}");
    }

    #[test]
    fn the_final_batch_does_not_cry_wolf() {
        // ⛔ THE OBSERVED BUG: importing batch 2 of 2 printed "and 0 more QR
        // code(s) must be imported … This import is PARTIAL", i.e. it told a
        // user who had just finished that they had not. A warning that cries
        // wolf is one the next user ignores when it is real.
        let last =
            decode_migration_payload(&multi_qr_payload(&[sample_otp("b")], 2, 1, 9)).expect("d");
        assert!(last.is_final_batch(), "batch 2 of 2 is the final batch");
        let note = last
            .batch_note()
            .expect("the final batch still says what it was");
        assert!(note.contains("batch 2 of 2"), "{note}");
        assert!(note.contains("LAST QR code"), "{note}");
        // The three claims that were false must all be gone.
        assert!(!note.contains("0 more QR"), "{note}");
        assert!(!note.contains("must be imported"), "{note}");
        assert!(!note.contains("PARTIAL"), "{note}");

        // ...and a genuinely outstanding batch is STILL loud.
        let first =
            decode_migration_payload(&multi_qr_payload(&[sample_otp("a")], 2, 0, 9)).expect("d");
        assert!(!first.is_final_batch());
        let note = first.batch_note().expect("note");
        assert!(note.contains("PARTIAL"), "{note}");
        assert!(note.contains("1 more QR"), "{note}");

        // A single-QR export is neither: it is COMPLETE, and silent.
        let one =
            decode_migration_payload(&multi_qr_payload(&[sample_otp("a")], 1, 0, 9)).expect("d");
        assert!(one.is_complete());
        assert!(!one.is_final_batch());
        assert!(one.batch_note().is_none());
    }

    #[test]
    fn a_single_batch_export_is_complete_and_silent() {
        // The common case must not grow a scary warning.
        let one = decode_migration_payload(&multi_qr_payload(&[sample_otp("a")], 1, 0, 5))
            .expect("decode");
        assert!(one.is_complete());
        assert!(one.batch_note().is_none());

        // …and so must a payload that omits the field entirely (proto3 default).
        let mut bare = Vec::new();
        write_len_field(&mut bare, 1, &encode_otp_parameters(&sample_otp("a")));
        let d = decode_migration_payload(&bare).expect("decode");
        assert_eq!(d.batch_size, 0);
        assert!(d.is_complete());
        assert!(d.batch_note().is_none());
    }

    // --- ⛔ EXPORT MUST NOT EMIT A LIE ABOUT THE PERIOD (Phase 59) -----------

    #[test]
    fn migration_export_refuses_a_non_30_second_period() {
        // The migration wire format has no period field. Exporting a 60 s entry
        // as if it were 30 s produces an account whose codes are WRONG in the
        // receiving app — data loss dressed as success.
        let e = crate::new_totp_entry("acct", None, b"0123456789", OtpAlgorithm::Sha1, 6, 60)
            .expect("entry");
        let err = entry_to_migration_otp(&e).expect_err("refused");
        let msg = err.to_string();
        assert!(msg.contains("60 s"), "{msg}");
        assert!(msg.contains("WRONG codes"), "{msg}");
        // …and it names the export that DOES carry the period.
        assert!(msg.contains("otpauth://"), "{msg}");

        // The standard 30 s period still exports.
        let ok = crate::new_totp_entry(
            "acct",
            None,
            b"0123456789",
            OtpAlgorithm::Sha1,
            6,
            TOTP_DEFAULT_PERIOD,
        )
        .expect("entry");
        assert!(entry_to_migration_otp(&ok).is_ok());
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
        assert_eq!(decoded.otps.len(), 1);
        assert_eq!(decoded.otps[0].secret, b"secretbytes");
        assert_eq!(decoded.otps[0].name, "acct");
        assert_eq!(decoded.otps[0].algorithm, ALG_SHA1);
    }
}
