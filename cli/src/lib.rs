//! `sigil-cli` core — the testable seal/open logic, with no process exit and no
//! file I/O.
//!
//! STATUS: pre-audit. This crate composes the REAL but **UNAUDITED**
//! `sigil-core` record API ([`sigil_core::seal_record`] /
//! [`sigil_core::open_record`]) into a self-describing on-disk container. It is
//! a **demonstration of the libsigil building block only** and MUST NOT be used
//! to protect real secrets. It makes no security claims.
//!
//! ## Why a container?
//!
//! `seal_record` stores the AEAD nonce *inside* the envelope it returns, so
//! `open_record` does not need the nonce. But the Argon2id **salt** and
//! **params** are NOT in the envelope, and re-deriving the master key with a
//! different salt or params yields a different key (and the record won't open).
//! So this CLI MUST persist `(params, salt)` itself. The [container format]
//! below does exactly that, prepending a small self-describing header to the
//! envelope bytes.
//!
//! [container format]: #on-disk-container-format
//!
//! ## On-disk container format
//!
//! All integers are little-endian. The header is fixed except for the salt.
//!
//! ```text
//!   offset  size            field
//!   ------  --------------  -----------------------------------------------
//!   0       8               magic           = b"SIGILcli"
//!   8       1               format_version  = 1
//!   9       4   (u32 LE)    m_cost          (Argon2id memory cost, KiB)
//!   13      4   (u32 LE)    t_cost          (Argon2id time cost / passes)
//!   17      4   (u32 LE)    p_cost          (Argon2id parallelism / lanes)
//!   21      1               salt_len        (length of the salt, in bytes)
//!   22      salt_len        salt            (Argon2id salt)
//!   22+sl   ..              envelope        = the seal_record output (tail)
//! ```
//!
//! The header is authenticated only insofar as the params/salt feed the KDF: a
//! tampered salt or params simply derives the wrong key and `open` fails to
//! authenticate. The header is otherwise plaintext metadata (see `sigil-core`'s
//! note that `(salt, params)` are unprotected).

#![forbid(unsafe_code)]

use sigil_core::{open_record, seal_record, Argon2Params, RecordError, NONCE_LEN};

/// The 8-byte magic that prefixes every container.
pub const MAGIC: &[u8; 8] = b"SIGILcli";

/// The container format version this build writes and is the only one it reads.
pub const FORMAT_VERSION: u8 = 1;

/// Length of the random Argon2id salt this CLI generates, in bytes.
pub const SALT_LEN: usize = 16;

/// The fixed additional-authenticated-data tag bound into every sealed record.
/// It namespaces this tool's records and is authenticated by the AEAD.
pub const AAD: &[u8] = b"sigil-cli/1";

/// Byte length of the fixed part of the container header (everything up to and
/// including `salt_len`, i.e. before the variable-length salt and envelope).
const FIXED_HEADER_LEN: usize = 8 /* magic */ + 1 /* version */ + 4 /* m_cost */ + 4 /* t_cost */ + 4 /* p_cost */ + 1 /* salt_len */;

/// Errors from the CLI container layer.
///
/// These deliberately never carry plaintext. Authentication / decode failures
/// from the crypto core are folded into [`CliError::Record`] without exposing
/// any decrypted bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CliError {
    /// The OS random number generator failed while producing the salt or nonce.
    Rng,
    /// The container is too short to even hold the fixed header (truncated,
    /// empty, or garbage).
    ShortContainer,
    /// The leading magic bytes were not `b"SIGILcli"`.
    BadMagic,
    /// The container's `format_version` is one this build does not understand.
    UnsupportedVersion(u8),
    /// The header parsed but the declared `salt_len` runs past the buffer.
    MalformedHeader,
    /// The underlying `sigil-core` record API failed: a malformed/truncated
    /// envelope, or — most importantly — an authentication failure (wrong
    /// password or tampered data). The plaintext is never returned in this case.
    Record(RecordError),
}

impl From<RecordError> for CliError {
    fn from(e: RecordError) -> Self {
        CliError::Record(e)
    }
}

impl core::fmt::Display for CliError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CliError::Rng => f.write_str("failed to gather randomness from the OS RNG"),
            CliError::ShortContainer => {
                f.write_str("container is too short or empty to be a sigil-cli file")
            }
            CliError::BadMagic => {
                f.write_str("not a sigil-cli container (bad magic: expected \"SIGILcli\")")
            }
            CliError::UnsupportedVersion(v) => {
                write!(f, "unsupported sigil-cli container format version: {v}")
            }
            CliError::MalformedHeader => f.write_str(
                "malformed sigil-cli container header (declared salt overruns the file)",
            ),
            // `RecordError` derives Debug only; surface it via Debug so the user
            // sees Kdf / Aead / Envelope without us claiming more than we know.
            // Never includes plaintext.
            CliError::Record(e) => write!(f, "could not open record: {e:?}"),
        }
    }
}

impl std::error::Error for CliError {}

/// Fill `buf` with cryptographically-secure random bytes from the OS.
///
/// Native-only; this crate is never compiled to wasm, so `getrandom` is fine.
fn fill_random(buf: &mut [u8]) -> Result<(), CliError> {
    getrandom::getrandom(buf).map_err(|_| CliError::Rng)
}

/// Seal `plaintext` under `password` into a self-describing container.
///
/// Generates a fresh random [`SALT_LEN`]-byte Argon2id salt and a fresh random
/// [`NONCE_LEN`]-byte AEAD nonce, derives the master key with `params`, seals
/// with the fixed [`AAD`], and packs `(params, salt, envelope)` into the
/// [container format](crate#on-disk-container-format).
///
/// # Errors
/// - [`CliError::Rng`] if the OS RNG fails.
/// - [`CliError::Record`] if `sigil-core` rejects the salt/params.
pub fn seal_to_container(
    password: &[u8],
    plaintext: &[u8],
    params: Argon2Params,
) -> Result<Vec<u8>, CliError> {
    let mut salt = [0u8; SALT_LEN];
    fill_random(&mut salt)?;

    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;

    let envelope = seal_record(password, &salt, params, &nonce, AAD, plaintext)?;

    let mut out = Vec::with_capacity(FIXED_HEADER_LEN + salt.len() + envelope.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&params.m_cost.to_le_bytes());
    out.extend_from_slice(&params.t_cost.to_le_bytes());
    out.extend_from_slice(&params.p_cost.to_le_bytes());
    // SALT_LEN is 16, always fits in a u8.
    out.push(salt.len() as u8);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&envelope);
    Ok(out)
}

/// Parse a container produced by [`seal_to_container`] and open it.
///
/// Reads the header, rebuilds the [`Argon2Params`], and calls
/// [`sigil_core::open_record`] on the envelope tail. On any authentication or
/// decode failure it returns a [`CliError`] and **never leaks plaintext**.
///
/// # Errors
/// - [`CliError::ShortContainer`] if the buffer can't hold the fixed header.
/// - [`CliError::BadMagic`] / [`CliError::UnsupportedVersion`] on header
///   mismatch.
/// - [`CliError::MalformedHeader`] if the declared salt runs past the buffer.
/// - [`CliError::Record`] if the wrapped record fails to decode or authenticate.
pub fn open_container(password: &[u8], container: &[u8]) -> Result<Vec<u8>, CliError> {
    if container.len() < FIXED_HEADER_LEN {
        return Err(CliError::ShortContainer);
    }

    let (magic, rest) = container.split_at(8);
    if magic != MAGIC.as_slice() {
        return Err(CliError::BadMagic);
    }

    let version = rest[0];
    if version != FORMAT_VERSION {
        return Err(CliError::UnsupportedVersion(version));
    }

    // Fixed-width fields after the version byte: m_cost, t_cost, p_cost, salt_len.
    let m_cost = u32::from_le_bytes([rest[1], rest[2], rest[3], rest[4]]);
    let t_cost = u32::from_le_bytes([rest[5], rest[6], rest[7], rest[8]]);
    let p_cost = u32::from_le_bytes([rest[9], rest[10], rest[11], rest[12]]);
    let salt_len = rest[13] as usize;

    // `rest` starts at the version byte; the salt begins after the 14 fixed
    // bytes (version + 3 u32s + salt_len) consumed above.
    let after_fixed = &rest[14..];
    if after_fixed.len() < salt_len {
        return Err(CliError::MalformedHeader);
    }
    let (salt, envelope) = after_fixed.split_at(salt_len);

    let params = Argon2Params {
        m_cost,
        t_cost,
        p_cost,
    };

    let plaintext = open_record(password, salt, params, envelope)?;
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fast Argon2id params so tests are near-instant while still hitting the
    /// real KDF path. (Argon2 requires `m_cost >= 8 * p_cost`.)
    const FAST: Argon2Params = Argon2Params {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    };
    const PASSWORD: &[u8] = b"correct horse battery staple";

    #[test]
    fn container_has_expected_header_shape() {
        let c = seal_to_container(PASSWORD, b"hello", FAST).expect("seal");
        assert_eq!(&c[..8], MAGIC.as_slice());
        assert_eq!(c[8], FORMAT_VERSION);
        // params round-trip in the header
        assert_eq!(u32::from_le_bytes([c[9], c[10], c[11], c[12]]), FAST.m_cost);
        assert_eq!(
            u32::from_le_bytes([c[13], c[14], c[15], c[16]]),
            FAST.t_cost
        );
        assert_eq!(
            u32::from_le_bytes([c[17], c[18], c[19], c[20]]),
            FAST.p_cost
        );
        assert_eq!(c[21] as usize, SALT_LEN);
        // header + salt + at least an envelope follows
        assert!(c.len() > FIXED_HEADER_LEN + SALT_LEN);
    }

    #[test]
    fn seal_open_round_trip_equals_input() {
        let plaintext = b"the launch codes are in the other vault";
        let c = seal_to_container(PASSWORD, plaintext, FAST).expect("seal");
        let opened = open_container(PASSWORD, &c).expect("open");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn empty_plaintext_round_trips() {
        let c = seal_to_container(PASSWORD, b"", FAST).expect("seal");
        let opened = open_container(PASSWORD, &c).expect("open");
        assert!(opened.is_empty());
    }

    #[test]
    fn wrong_password_errors_without_leaking_plaintext() {
        let plaintext = b"super secret payload";
        let c = seal_to_container(PASSWORD, plaintext, FAST).expect("seal");
        let result = open_container(b"wrong password", &c);
        assert!(result.is_err());
        // The error path must not surface the plaintext anywhere.
        let msg = format!("{}", result.unwrap_err());
        assert!(!msg
            .as_bytes()
            .windows(plaintext.len())
            .any(|w| w == plaintext));
    }

    #[test]
    fn tampered_late_byte_is_rejected() {
        let plaintext = b"tamper-evident payload contents";
        let mut c = seal_to_container(PASSWORD, plaintext, FAST).expect("seal");
        // Flip a late byte (deep in the envelope's ciphertext/tag region).
        let last = c.len() - 1;
        c[last] ^= 0x01;
        let result = open_container(PASSWORD, &c);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(!msg
            .as_bytes()
            .windows(plaintext.len())
            .any(|w| w == plaintext));
    }

    #[test]
    fn empty_container_is_rejected() {
        assert_eq!(open_container(PASSWORD, &[]), Err(CliError::ShortContainer));
    }

    #[test]
    fn short_garbage_is_rejected_without_panic() {
        let garbage = [0xFFu8; 4];
        assert_eq!(
            open_container(PASSWORD, &garbage),
            Err(CliError::ShortContainer)
        );
    }

    #[test]
    fn bad_magic_is_rejected() {
        // A buffer long enough to pass the length gate but with wrong magic.
        let buf = [0x00u8; FIXED_HEADER_LEN + 8];
        assert_eq!(open_container(PASSWORD, &buf), Err(CliError::BadMagic));
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut c = seal_to_container(PASSWORD, b"x", FAST).expect("seal");
        c[8] = 99; // bump the format_version byte
        assert_eq!(
            open_container(PASSWORD, &c),
            Err(CliError::UnsupportedVersion(99))
        );
    }

    #[test]
    fn declared_salt_overrun_is_rejected() {
        let mut c = seal_to_container(PASSWORD, b"x", FAST).expect("seal");
        // Set salt_len (offset 21) absurdly large so it overruns the buffer.
        c[21] = 0xFF;
        assert_eq!(open_container(PASSWORD, &c), Err(CliError::MalformedHeader));
    }

    #[test]
    fn truncated_envelope_is_rejected_without_panic() {
        let c = seal_to_container(PASSWORD, b"payload", FAST).expect("seal");
        // Drop the tail so the envelope is truncated but the header is intact.
        let truncated = &c[..c.len() - 4];
        let result = open_container(PASSWORD, truncated);
        // Surfaces as a Record(Envelope(..)) or Record(Aead(..)) error, never a panic.
        assert!(matches!(result, Err(CliError::Record(_))));
    }
}
