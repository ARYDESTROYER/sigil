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

pub mod migration;

pub use migration::{
    decode_migration_payload, decode_migration_uri, encode_migration_payload, encode_migration_uri,
    entry_to_migration_otp, migration_otp_to_entry, ImportedOtp, MigrationOtp,
};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sigil_core::{
    hybrid_open, hybrid_seal, ml_kem768_keygen, open_record, public_key_from_seed, seal_record,
    sign, x25519_public_key, Argon2Params, HybridSealError, OtpAlgorithm, RecordError,
    ML_KEM768_CIPHERTEXT_LEN, ML_KEM768_DECAPS_KEY_LEN, ML_KEM768_ENCAPS_COIN_LEN,
    ML_KEM768_ENCAPS_KEY_LEN, ML_KEM768_KEYGEN_SEED_LEN, NONCE_LEN, SIG_PUBLIC_KEY_LEN,
    SIG_SEED_LEN, X25519_PUBLIC_KEY_LEN, X25519_SECRET_KEY_LEN,
};

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
    /// A transport/IO error while talking to the dev sigild op-log over plain
    /// HTTP (connection refused, broken pipe, etc.). Carries a short message.
    Http(String),
    /// The dev op-log returned a non-2xx HTTP status. `status` is the HTTP code
    /// (e.g. `501` when sigild's dev op-log flag is off) and `body` is the raw
    /// response body for context. Never contains plaintext (the op is opaque).
    Server { status: u16, body: String },
    /// A 2xx response that could not be parsed: bad JSON, missing field, or a
    /// `blob` that was not valid base64.
    BadResponse(String),
    /// The supplied vault identifier is empty or contains a path separator or
    /// whitespace, so it cannot be safely placed in the request URL.
    BadVault(String),
    /// A failure reading, parsing, or writing the LOCAL pull cursor state file
    /// (`.sigil-pull-state.json`). This is local, non-secret device state — an
    /// IO error or a corrupt/unparseable state file. Carries a short message.
    State(String),
    /// A failure generating, reading, parsing, or writing the LOCAL device key
    /// file: an IO error, malformed JSON, a `seed`/`public_key` that is not valid
    /// base64, or a decoded seed/public key of the wrong length. The key file is
    /// LOCAL device material — DEV-ONLY (see the signing module note). Carries a
    /// short message and never the raw seed bytes.
    Key(String),
    /// A failure generating, reading, parsing, writing, or DECODING a hybrid
    /// public-key identity file (secret or public): an IO error, malformed JSON,
    /// an unsupported version, a non-base64 field, or a decoded key of the wrong
    /// length. The SECRET identity holds private key material — DEV-ONLY,
    /// UNAUDITED. Carries a short message and never the raw secret bytes.
    Identity(String),
    /// The `sigil-core` hybrid public-key seal/open failed: a KEM-input rejection,
    /// a malformed/truncated envelope, or — most importantly — an authentication
    /// failure (wrong recipient identity or tampered container). The plaintext is
    /// never returned in this case.
    HybridSeal(HybridSealError),
    /// A TOTP-vault operation failed at the CLI layer: an unparseable
    /// `otpauth://` URI, an invalid base32 secret, an unknown algorithm/digit
    /// count, a duplicate/absent label, or a vault whose decrypted JSON does not
    /// parse. Never carries a secret key or a generated code. Carries a short
    /// message.
    Totp(String),
    /// A device-to-device VAULT SHARING operation failed at the CLI layer: a
    /// malformed local vault keyring, a missing vault key, a recipient that has
    /// not published a hybrid public key, or a recovered vault key of the wrong
    /// length. NEVER carries a vault key, a password, or any secret bytes.
    Sharing(String),
    /// ⚠️ A recipient device's hybrid PUBLIC key does NOT match the key this
    /// client PINNED the first time it saw that device (Phase 50).
    ///
    /// This is the key-substitution alarm and it is a HARD STOP: the caller must
    /// NOT wrap a vault key to the presented key. It means either (a) a hostile
    /// or compromised server substituted its OWN key so it could unwrap the
    /// vault key, or (b) that device legitimately re-enrolled / regenerated its
    /// hybrid identity. Only a human can tell those apart — by comparing the
    /// SAFETY NUMBER over a trusted out-of-band channel — so nothing here ever
    /// auto-re-pins.
    ///
    /// Carries only PUBLIC material: the device id and the two safety numbers.
    PinMismatch {
        /// The device whose published key changed.
        device_id: String,
        /// The safety number of the key this client pinned earlier.
        pinned_safety_number: String,
        /// The safety number of the key the server just presented.
        presented_safety_number: String,
    },
}

impl From<RecordError> for CliError {
    fn from(e: RecordError) -> Self {
        CliError::Record(e)
    }
}

impl From<HybridSealError> for CliError {
    fn from(e: HybridSealError) -> Self {
        CliError::HybridSeal(e)
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
            CliError::Http(e) => write!(f, "dev op-log transport error: {e}"),
            CliError::Server { status, body } => {
                write!(f, "dev op-log returned HTTP {status}: {body}")
            }
            CliError::BadResponse(e) => write!(f, "could not parse dev op-log response: {e}"),
            CliError::BadVault(v) => write!(
                f,
                "invalid vault id {v:?}: must be non-empty with no '/' or whitespace"
            ),
            CliError::State(e) => write!(f, "local pull-state error: {e}"),
            CliError::Key(e) => write!(f, "device key error: {e}"),
            CliError::Identity(e) => write!(f, "hybrid identity error: {e}"),
            // `HybridSealError` derives Debug only; surface it via Debug so the
            // user sees Hybrid / Aead / Envelope without claiming more than we
            // know. Never includes plaintext.
            CliError::HybridSeal(e) => write!(f, "could not hybrid-open record: {e:?}"),
            CliError::Totp(e) => write!(f, "totp vault error: {e}"),
            CliError::Sharing(e) => write!(f, "vault sharing error: {e}"),
            CliError::PinMismatch {
                device_id,
                pinned_safety_number,
                presented_safety_number,
            } => write!(
                f,
                "REFUSING TO SHARE: the hybrid public key published for device {device_id} has \
                 CHANGED since this client pinned it.\n  \
                 pinned    safety number: {pinned_safety_number}\n  \
                 presented safety number: {presented_safety_number}\n  \
                 This is either a KEY-SUBSTITUTION ATTACK (a hostile or compromised server \
                 swapped in a key it can decrypt with, so it would receive this vault's key) or a \
                 LEGITIMATE RE-ENROLMENT of that device.\n  \
                 No vault key was wrapped and nothing was uploaded. Confirm the presented safety \
                 number with the other device's owner over a TRUSTED out-of-band channel (a phone \
                 call, in person), then re-pin deliberately with \
                 `sigil device repin {device_id}`."
            ),
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

// ---------------------------------------------------------------------------
// Hybrid PUBLIC-KEY encryption: encrypt a file TO another device's hybrid
// public identity (X25519 + ML-KEM-768), with NO password. This is the
// public-key path, distinct from the password-based seal/open above.
//
// STATUS: pre-audit, UNAUDITED, DEV-ONLY. This composes sigil-core's REAL but
// UNAUDITED hybrid primitives ([`sigil_core::hybrid_seal`] /
// [`sigil_core::hybrid_open`]) into a self-describing on-disk container. The
// construction is a CUSTOM KEM-then-AEAD (X25519 + ML-KEM-768 -> shared secret
// -> XChaCha20-Poly1305); it is NOT RFC 9180 HPKE and NOT a standardised scheme.
// The SYSTEM is NOT "post-quantum secure" and makes NO security claims. Do NOT
// use it to protect real secrets.
//
// A device generates a HYBRID IDENTITY: a SECRET identity file (its X25519
// secret + ML-KEM-768 keygen seed, mode 0600) and a shareable PUBLIC identity
// file (its X25519 public key + ML-KEM-768 encapsulation key). Senders encrypt
// TO the public identity; only the holder of the secret identity can open.
// ---------------------------------------------------------------------------

/// The 8-byte magic that prefixes every hybrid public-key container.
pub const HYBRID_MAGIC: &[u8; 8] = b"SIGILhyb";

/// The hybrid container format version this build writes and is the only one it
/// reads.
pub const HYBRID_FORMAT_VERSION: u8 = 1;

/// The version byte written into every hybrid identity file (secret and public).
/// The only version this build writes or reads.
pub const HYBRID_IDENTITY_VERSION: u8 = 1;

/// The fixed additional-authenticated-data tag bound into every hybrid-sealed
/// container. It namespaces this tool's hybrid records and is authenticated by
/// the AEAD (carried inside the envelope).
pub const HYBRID_AAD: &[u8] = b"sigil-hybrid-cli/1";

/// Byte length of the fixed prefix of a hybrid container: `magic(8)` +
/// `version(1)` + `eph_x25519_pub(32)` + `mlkem_ct(1088)` = 1129. The seal
/// envelope bytes follow this prefix.
const HYBRID_FIXED_PREFIX_LEN: usize = 8 + 1 + X25519_PUBLIC_KEY_LEN + ML_KEM768_CIPHERTEXT_LEN;

/// A SECRET hybrid identity file: the private half a device keeps to itself.
///
/// On disk this is JSON
/// `{"version":1,"x25519_secret":"<b64 32>","mlkem_seed":"<b64 64>"}`, where
/// `x25519_secret` is standard-base64 of the 32-byte X25519 secret and
/// `mlkem_seed` is standard-base64 of the 64-byte ML-KEM-768 keygen seed (the
/// decapsulation key is DERIVED from the seed via [`ml_kem768_keygen`], not
/// stored). This file holds SECRET key material and is written with mode `0600`;
/// it is per-device, DEV-ONLY, and NOT synced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSecretIdentity {
    /// Identity file format version. Always [`HYBRID_IDENTITY_VERSION`].
    pub version: u8,
    /// Standard-base64 of the 32-byte X25519 secret key. SECRET material.
    pub x25519_secret: String,
    /// Standard-base64 of the 64-byte ML-KEM-768 keygen seed. SECRET material.
    pub mlkem_seed: String,
}

/// A shareable PUBLIC hybrid identity: the public half a device hands to
/// senders so they can encrypt TO it. Safe to share; carries no secret material.
///
/// On disk this is JSON
/// `{"version":1,"x25519_public_key":"<b64 32>","mlkem_encaps_key":"<b64 1184>"}`,
/// where `x25519_public_key` is standard-base64 of the 32-byte X25519 public key
/// and `mlkem_encaps_key` is standard-base64 of the 1184-byte ML-KEM-768
/// encapsulation key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridPublicIdentity {
    /// Identity file format version. Always [`HYBRID_IDENTITY_VERSION`].
    pub version: u8,
    /// Standard-base64 of the 32-byte X25519 public key.
    pub x25519_public_key: String,
    /// Standard-base64 of the 1184-byte ML-KEM-768 encapsulation key.
    pub mlkem_encaps_key: String,
}

/// A decoded recipient public identity: the raw key bytes ready to pass to
/// [`hybrid_seal_to_container`]. Produced by [`HybridPublicIdentity::decode`].
pub struct HybridPublicKeys {
    /// The recipient's 32-byte X25519 public key.
    pub x25519_public_key: [u8; X25519_PUBLIC_KEY_LEN],
    /// The recipient's 1184-byte ML-KEM-768 encapsulation key.
    pub mlkem_encaps_key: [u8; ML_KEM768_ENCAPS_KEY_LEN],
}

/// A decoded SECRET identity: the raw X25519 secret plus the ML-KEM-768
/// decapsulation key (derived from the stored seed), ready to pass to
/// [`hybrid_open_container`]. Produced by [`HybridSecretIdentity::decode`].
pub struct HybridSecretKeys {
    /// This device's 32-byte X25519 secret key. SECRET material.
    pub x25519_secret: [u8; X25519_SECRET_KEY_LEN],
    /// This device's 2400-byte ML-KEM-768 decapsulation key, derived from the
    /// stored keygen seed. SECRET material.
    pub mlkem_decaps_key: [u8; ML_KEM768_DECAPS_KEY_LEN],
}

/// Standard-base64-decode `field` into a fixed `[u8; N]`, mapping a bad alphabet
/// or a wrong decoded length to a clear [`CliError::Identity`] naming the field.
fn decode_identity_field<const N: usize>(field: &str, name: &str) -> Result<[u8; N], CliError> {
    let bytes = BASE64
        .decode(field.as_bytes())
        .map_err(|e| CliError::Identity(format!("{name} is not valid base64: {e}")))?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        CliError::Identity(format!("{name} must decode to {N} bytes, got {}", v.len()))
    })
}

impl HybridSecretIdentity {
    /// Decode this secret identity into raw key bytes: validate the version,
    /// base64-decode the X25519 secret and the ML-KEM keygen seed, and DERIVE the
    /// ML-KEM-768 decapsulation key from the seed with [`ml_kem768_keygen`].
    ///
    /// # Errors
    /// - [`CliError::Identity`] on an unsupported version, a non-base64 field, or
    ///   a decoded secret/seed of the wrong length.
    pub fn decode(&self) -> Result<HybridSecretKeys, CliError> {
        if self.version != HYBRID_IDENTITY_VERSION {
            return Err(CliError::Identity(format!(
                "unsupported hybrid identity version {}: expected {HYBRID_IDENTITY_VERSION}",
                self.version
            )));
        }
        let x25519_secret =
            decode_identity_field::<X25519_SECRET_KEY_LEN>(&self.x25519_secret, "x25519_secret")?;
        let mlkem_seed =
            decode_identity_field::<ML_KEM768_KEYGEN_SEED_LEN>(&self.mlkem_seed, "mlkem_seed")?;
        let (_ek, mlkem_decaps_key) = ml_kem768_keygen(&mlkem_seed);
        Ok(HybridSecretKeys {
            x25519_secret,
            mlkem_decaps_key,
        })
    }
}

impl HybridPublicIdentity {
    /// Decode this public identity into raw key bytes ready for
    /// [`hybrid_seal_to_container`]: validate the version and base64-decode the
    /// X25519 public key and the ML-KEM-768 encapsulation key.
    ///
    /// # Errors
    /// - [`CliError::Identity`] on an unsupported version, a non-base64 field, or
    ///   a decoded key of the wrong length.
    pub fn decode(&self) -> Result<HybridPublicKeys, CliError> {
        if self.version != HYBRID_IDENTITY_VERSION {
            return Err(CliError::Identity(format!(
                "unsupported hybrid identity version {}: expected {HYBRID_IDENTITY_VERSION}",
                self.version
            )));
        }
        let x25519_public_key = decode_identity_field::<X25519_PUBLIC_KEY_LEN>(
            &self.x25519_public_key,
            "x25519_public_key",
        )?;
        let mlkem_encaps_key = decode_identity_field::<ML_KEM768_ENCAPS_KEY_LEN>(
            &self.mlkem_encaps_key,
            "mlkem_encaps_key",
        )?;
        Ok(HybridPublicKeys {
            x25519_public_key,
            mlkem_encaps_key,
        })
    }
}

/// Generate a fresh DEV-ONLY hybrid identity: draw a 32-byte X25519 secret and a
/// 64-byte ML-KEM-768 keygen seed from the OS CSPRNG, derive the X25519 public
/// key and the ML-KEM-768 encapsulation key, and return the
/// `(secret_identity, public_identity)` pair.
///
/// The secret identity stores the X25519 secret and the ML-KEM keygen seed; the
/// public identity stores the X25519 public key and the ML-KEM encapsulation
/// key. Share the public identity with senders; keep the secret identity local.
///
/// # Errors
/// - [`CliError::Rng`] if the OS RNG fails while drawing the secret or seed.
pub fn generate_hybrid_identity() -> Result<(HybridSecretIdentity, HybridPublicIdentity), CliError>
{
    let mut x25519_secret = [0u8; X25519_SECRET_KEY_LEN];
    fill_random(&mut x25519_secret)?;
    let mut mlkem_seed = [0u8; ML_KEM768_KEYGEN_SEED_LEN];
    fill_random(&mut mlkem_seed)?;

    let x25519_pub = x25519_public_key(&x25519_secret);
    let (mlkem_encaps_key, _dk) = ml_kem768_keygen(&mlkem_seed);

    let secret = HybridSecretIdentity {
        version: HYBRID_IDENTITY_VERSION,
        x25519_secret: BASE64.encode(x25519_secret),
        mlkem_seed: BASE64.encode(mlkem_seed),
    };
    let public = HybridPublicIdentity {
        version: HYBRID_IDENTITY_VERSION,
        x25519_public_key: BASE64.encode(x25519_pub),
        mlkem_encaps_key: BASE64.encode(mlkem_encaps_key),
    };
    Ok((secret, public))
}

/// Write a SECRET hybrid identity to `path` as JSON, with file mode `0600`
/// (owner read/write only), since it holds private key material.
///
/// Mirrors [`save_key`]: created with `0600` up front so the secret is never
/// briefly world-readable, then re-asserts `0600` in case the file pre-existed
/// with looser permissions.
///
/// # Errors
/// - [`CliError::Identity`] on a serialize, write, or permission-set failure.
pub fn save_hybrid_secret(
    path: &std::path::Path,
    identity: &HybridSecretIdentity,
) -> Result<(), CliError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let json = serde_json::to_string_pretty(identity)
        .map_err(|e| CliError::Identity(format!("could not serialize secret identity: {e}")))?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| CliError::Identity(format!("could not create secret identity file: {e}")))?;
    use std::io::Write as _;
    f.write_all(json.as_bytes())
        .map_err(|e| CliError::Identity(format!("could not write secret identity file: {e}")))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| CliError::Identity(format!("could not set secret identity permissions: {e}")))
}

/// Write a shareable PUBLIC hybrid identity to `path` as JSON.
///
/// The public identity carries no secret material, so it is written with the
/// default permissions (unlike [`save_hybrid_secret`]).
///
/// # Errors
/// - [`CliError::Identity`] on a serialize or write failure.
pub fn save_hybrid_public(
    path: &std::path::Path,
    identity: &HybridPublicIdentity,
) -> Result<(), CliError> {
    let json = serde_json::to_string_pretty(identity)
        .map_err(|e| CliError::Identity(format!("could not serialize public identity: {e}")))?;
    std::fs::write(path, json)
        .map_err(|e| CliError::Identity(format!("could not write public identity file: {e}")))
}

/// Read a SECRET hybrid identity file from `path`.
///
/// Validates only the JSON shape here; the version and field lengths are checked
/// when the identity is [`decode`d](HybridSecretIdentity::decode).
///
/// # Errors
/// - [`CliError::Identity`] on an IO error or malformed JSON.
pub fn load_hybrid_secret(path: &std::path::Path) -> Result<HybridSecretIdentity, CliError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| CliError::Identity(format!("could not read secret identity file: {e}")))?;
    serde_json::from_str(&text)
        .map_err(|e| CliError::Identity(format!("secret identity file is not valid JSON: {e}")))
}

/// Read a shareable PUBLIC hybrid identity file from `path`.
///
/// Validates only the JSON shape here; the version and field lengths are checked
/// when the identity is [`decode`d](HybridPublicIdentity::decode).
///
/// # Errors
/// - [`CliError::Identity`] on an IO error or malformed JSON.
pub fn load_hybrid_public(path: &std::path::Path) -> Result<HybridPublicIdentity, CliError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| CliError::Identity(format!("could not read public identity file: {e}")))?;
    serde_json::from_str(&text)
        .map_err(|e| CliError::Identity(format!("public identity file is not valid JSON: {e}")))
}

/// Encrypt `plaintext` TO a recipient's decoded hybrid public identity, packing
/// the result into the [hybrid container format](#hybrid-container-format).
///
/// Draws a FRESH ephemeral X25519 secret (32 bytes), ML-KEM-768 coin (32 bytes),
/// and AEAD nonce ([`NONCE_LEN`] bytes) from the OS CSPRNG, calls
/// [`sigil_core::hybrid_seal`] with the fixed [`HYBRID_AAD`], and prepends the
/// magic, version, ephemeral X25519 public key, and ML-KEM-768 ciphertext to the
/// returned envelope bytes. No password is involved (this is the public-key
/// path). This CLI never sees the recipient's secret.
///
/// # Hybrid container format
///
/// ```text
///   offset  size    field
///   ------  ------  -----------------------------------------------
///   0       8       magic          = b"SIGILhyb"
///   8       1       version        = 1
///   9       32      eph_x25519_pub (sender's ephemeral X25519 public key)
///   41      1088    mlkem_ct       (ML-KEM-768 ciphertext)
///   1129    ..      envelope       = the hybrid_seal envelope (tail)
/// ```
///
/// # Errors
/// - [`CliError::Rng`] if the OS RNG fails while drawing the ephemeral secret,
///   coin, or nonce.
/// - [`CliError::HybridSeal`] if `sigil-core` rejects a KEM input (e.g. a
///   non-contributory recipient X25519 public key).
pub fn hybrid_seal_to_container(
    recipient: &HybridPublicKeys,
    plaintext: &[u8],
) -> Result<Vec<u8>, CliError> {
    let mut eph_secret = [0u8; X25519_SECRET_KEY_LEN];
    fill_random(&mut eph_secret)?;
    let mut coin = [0u8; ML_KEM768_ENCAPS_COIN_LEN];
    fill_random(&mut coin)?;
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;

    let (eph_pub, mlkem_ct, envelope) = hybrid_seal(
        &recipient.x25519_public_key,
        &recipient.mlkem_encaps_key,
        &eph_secret,
        &coin,
        &nonce,
        HYBRID_AAD,
        plaintext,
    )?;

    let mut out = Vec::with_capacity(HYBRID_FIXED_PREFIX_LEN + envelope.len());
    out.extend_from_slice(HYBRID_MAGIC);
    out.push(HYBRID_FORMAT_VERSION);
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&mlkem_ct);
    out.extend_from_slice(&envelope);
    Ok(out)
}

/// Parse a hybrid container produced by [`hybrid_seal_to_container`] and open it
/// with the recipient's decoded secret identity.
///
/// Bounds-checks the container (magic / version / fixed-prefix length) BEFORE
/// slicing — short or garbage input yields a clear [`CliError`], never a panic —
/// then calls [`sigil_core::hybrid_open`]. On any KEM/authentication/decode
/// failure it returns a [`CliError`] and **never leaks plaintext**.
///
/// # Errors
/// - [`CliError::ShortContainer`] if the buffer can't hold the fixed prefix.
/// - [`CliError::BadMagic`] / [`CliError::UnsupportedVersion`] on header
///   mismatch.
/// - [`CliError::HybridSeal`] if the wrapped record fails to decode or
///   authenticate (wrong identity or tampered container).
pub fn hybrid_open_container(
    identity: &HybridSecretKeys,
    container: &[u8],
) -> Result<Vec<u8>, CliError> {
    if container.len() < HYBRID_FIXED_PREFIX_LEN {
        return Err(CliError::ShortContainer);
    }

    let (magic, rest) = container.split_at(8);
    if magic != HYBRID_MAGIC.as_slice() {
        return Err(CliError::BadMagic);
    }

    let version = rest[0];
    if version != HYBRID_FORMAT_VERSION {
        return Err(CliError::UnsupportedVersion(version));
    }

    // After magic(8) + version(1): eph_x25519_pub[32] | mlkem_ct[1088] |
    // envelope[..]. The length gate above guarantees every split below is in
    // bounds, so the fixed-length `try_into`s cannot fail.
    let after_version = &rest[1..];
    let (eph_pub_bytes, rest2) = after_version.split_at(X25519_PUBLIC_KEY_LEN);
    let (mlkem_ct_bytes, envelope) = rest2.split_at(ML_KEM768_CIPHERTEXT_LEN);

    let eph_pub: [u8; X25519_PUBLIC_KEY_LEN] = eph_pub_bytes
        .try_into()
        .expect("eph_pub slice is exactly X25519_PUBLIC_KEY_LEN by construction");
    let mlkem_ct: [u8; ML_KEM768_CIPHERTEXT_LEN] = mlkem_ct_bytes
        .try_into()
        .expect("mlkem_ct slice is exactly ML_KEM768_CIPHERTEXT_LEN by construction");

    let plaintext = hybrid_open(
        &identity.x25519_secret,
        &identity.mlkem_decaps_key,
        &eph_pub,
        &mlkem_ct,
        envelope,
    )?;
    Ok(plaintext)
}

// ---------------------------------------------------------------------------
// Device-key signing: sign op-log requests so a hardened sigild will accept
// them (the op-log REQUEST-AUTH contract).
//
// STATUS: pre-audit, DEV-ONLY. This implements the CLIENT side of the
// `sigil-oplog-auth-v2` request-auth contract. sigild enables it ONLY when it is
// configured with SIGILD_OPLOG_PUBKEY = standard-base64 of this device's 32-byte
// Ed25519 PUBLIC key. When sigild has no pubkey configured, the dev op-log is
// UNAUTHENTICATED and these signatures are simply ignored.
//
// HONEST SCOPE: this is a SINGLE device key, DEV-ONLY. Each request now carries a
// FRESH random per-request NONCE (>=16 CSPRNG bytes, std-base64) that is BOTH
// signed into the message AND sent as the X-Sigil-Nonce header; a sigild that
// remembers seen nonces (for as long as the 300s timestamp window lets a request
// pass) will REJECT a replayed request, so within the window replay is prevented,
// not merely bounded. That replay cache is PER-PROCESS/in-memory on the server, so
// a multi-instance production deploy would need a shared store (e.g. Redis). Real
// device enrollment, a multi-device registry, and JWT bearer tokens all remain
// FUTURE work. The signing uses sigil_core's REAL but UNAUDITED Ed25519 primitive.
// ---------------------------------------------------------------------------

/// The version byte written into every device key file. The only version this
/// build writes or reads.
pub const KEY_FILE_VERSION: u8 = 1;

/// The fixed domain-separation prefix that opens the signed op-log auth message.
/// It MUST match sigild's verifier byte-for-byte (the `sigil-oplog-auth-v2`
/// contract).
const OPLOG_AUTH_PREFIX: &[u8] = b"sigil-oplog-auth-v2\n";

/// Number of random bytes drawn for each per-request auth nonce, before base64.
/// The v2 contract requires at least 16 bytes of CSPRNG output; the base64 text
/// of these bytes is what is signed and sent as `X-Sigil-Nonce`.
const OPLOG_NONCE_LEN: usize = 16;

/// A LOCAL, DEV-ONLY device key file — now also the DEVICE IDENTITY file.
///
/// One Ed25519 key pair, used to sign op-log requests under either the legacy
/// `sigil-oplog-auth-v2` contract (no `device_id`) or the multi-device
/// `sigil-oplog-auth-v3` contract (once `device_id` has been assigned by
/// `sigil device enroll`).
///
/// On disk this is JSON
/// `{"version":1,"seed":"<b64>","public_key":"<b64>"[,"device_id":"dev_..."]}`,
/// where `seed` is standard-base64 of the 32-byte Ed25519 secret seed and
/// `public_key` is standard-base64 of the 32-byte Ed25519 public key. The file
/// holds SECRET key material and is written with mode `0600`; it is per-device,
/// DEV-ONLY, and NOT synced.
///
/// BACKWARD COMPATIBILITY: `device_id` is OPTIONAL on read (serde `default`) and
/// OMITTED on write when absent, so a key file written by an older build parses
/// unchanged and keeps signing under contract v2. The file shape was EXTENDED,
/// not replaced — see [`DeviceIdentity`] for how the contract is selected.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    /// Key file format version. Always [`KEY_FILE_VERSION`].
    pub version: u8,
    /// Standard-base64 of the 32-byte Ed25519 secret seed. SECRET material.
    pub seed: String,
    /// Standard-base64 of the 32-byte Ed25519 public key. Set sigild's
    /// `SIGILD_OPLOG_PUBKEY` to exactly this string to enable LEGACY v2
    /// verification (v3 resolves the key through the device registry instead).
    pub public_key: String,
    /// The server-assigned device ID from `sigil device enroll`, when this key
    /// has been enrolled. `None` (the field absent on disk) means this is a
    /// pre-enrollment key file and requests are signed under LEGACY contract v2.
    /// This is NOT secret — it is an opaque public identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
}

/// Generate a fresh DEV-ONLY device key: draw a 32-byte Ed25519 seed from the OS
/// CSPRNG, derive its public key with [`sigil_core::public_key_from_seed`], and
/// return the [`KeyFile`] (seed + public key, both standard-base64).
///
/// # Errors
/// - [`CliError::Rng`] if the OS RNG fails while drawing the seed.
pub fn generate_key() -> Result<KeyFile, CliError> {
    let mut seed = [0u8; SIG_SEED_LEN];
    fill_random(&mut seed)?;
    let public = public_key_from_seed(&seed);
    Ok(KeyFile {
        version: KEY_FILE_VERSION,
        seed: BASE64.encode(seed),
        public_key: BASE64.encode(public),
        // Not enrolled yet: `sigil device enroll` fills this in.
        device_id: None,
    })
}

/// Write `key` to `path` as JSON, with file mode `0600` (owner read/write only),
/// since it contains the secret seed.
///
/// The file is created if absent and truncated if present; permissions are set
/// to `0600` regardless of the prior mode (or the process umask) so the secret
/// seed is never group/world-readable.
///
/// # Errors
/// - [`CliError::Key`] on a serialize, write, or permission-set failure.
pub fn save_key(path: &std::path::Path, key: &KeyFile) -> Result<(), CliError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let json = serde_json::to_string_pretty(key)
        .map_err(|e| CliError::Key(format!("could not serialize key file: {e}")))?;
    // Create with 0600 up front so the secret is never briefly world-readable,
    // then write. `truncate` handles an existing file at the same path.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| CliError::Key(format!("could not create key file: {e}")))?;
    use std::io::Write as _;
    f.write_all(json.as_bytes())
        .map_err(|e| CliError::Key(format!("could not write key file: {e}")))?;
    // Re-assert 0600 in case the file pre-existed with looser permissions
    // (OpenOptions::mode only applies to newly-created files).
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| CliError::Key(format!("could not set key file permissions: {e}")))
}

/// Read a device key file from `path` and return its decoded `(seed, public_key)`.
///
/// Validates the JSON shape, that `version == 1`, and that `seed` and
/// `public_key` are standard-base64 decoding to exactly 32 bytes each. The public
/// key is returned for convenience (e.g. echoing it); the seed is what callers
/// pass to [`push_op`] / [`pull_ops`] for signing.
///
/// # Errors
/// - [`CliError::Key`] on an IO error, malformed JSON, an unsupported version, a
///   non-base64 field, or a seed/public key of the wrong length.
pub fn load_key(
    path: &std::path::Path,
) -> Result<([u8; SIG_SEED_LEN], [u8; SIG_PUBLIC_KEY_LEN]), CliError> {
    let id = load_identity(path)?;
    Ok((id.seed, id.public_key))
}

/// Read a device key / identity file from `path` WITHOUT decoding its fields.
///
/// Validates only the JSON shape and the `version`; the base64 fields are decoded
/// by [`load_identity`]. Useful when a caller needs the raw file (e.g. to add a
/// `device_id` after enrollment and write it back).
///
/// # Errors
/// - [`CliError::Key`] on an IO error, malformed JSON, or an unsupported version.
pub fn load_key_file(path: &std::path::Path) -> Result<KeyFile, CliError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| CliError::Key(format!("could not read key file: {e}")))?;
    let kf: KeyFile = serde_json::from_str(&text)
        .map_err(|e| CliError::Key(format!("key file is not valid JSON: {e}")))?;
    if kf.version != KEY_FILE_VERSION {
        return Err(CliError::Key(format!(
            "unsupported key file version {}: expected {KEY_FILE_VERSION}",
            kf.version
        )));
    }
    Ok(kf)
}

/// Read and DECODE a device identity file from `path`.
///
/// This is the v3-aware loader: it returns the decoded seed and public key plus
/// the OPTIONAL `device_id`. A key file written before device enrollment existed
/// (no `device_id` field) loads fine and yields `device_id: None`, which selects
/// the LEGACY v2 contract — see [`DeviceIdentity::auth`].
///
/// # Errors
/// - [`CliError::Key`] on an IO error, malformed JSON, an unsupported version, a
///   non-base64 field, or a seed/public key of the wrong length.
pub fn load_identity(path: &std::path::Path) -> Result<DeviceIdentity, CliError> {
    load_key_file(path)?.decode()
}

impl KeyFile {
    /// Decode this key file's base64 fields into a [`DeviceIdentity`].
    ///
    /// # Errors
    /// - [`CliError::Key`] on a non-base64 field, a seed/public key of the wrong
    ///   length, or a `device_id` that could not sit in a URL path segment.
    pub fn decode(&self) -> Result<DeviceIdentity, CliError> {
        let seed_vec = BASE64
            .decode(self.seed.as_bytes())
            .map_err(|e| CliError::Key(format!("seed is not valid base64: {e}")))?;
        let seed: [u8; SIG_SEED_LEN] = seed_vec.try_into().map_err(|v: Vec<u8>| {
            CliError::Key(format!(
                "seed must decode to {SIG_SEED_LEN} bytes, got {}",
                v.len()
            ))
        })?;

        let pub_vec = BASE64
            .decode(self.public_key.as_bytes())
            .map_err(|e| CliError::Key(format!("public_key is not valid base64: {e}")))?;
        let public_key: [u8; SIG_PUBLIC_KEY_LEN] = pub_vec.try_into().map_err(|v: Vec<u8>| {
            CliError::Key(format!(
                "public_key must decode to {SIG_PUBLIC_KEY_LEN} bytes, got {}",
                v.len()
            ))
        })?;

        // An empty-string device_id is treated as absent rather than as a device
        // ID the server could never resolve.
        let device_id = self.device_id.clone().filter(|d| !d.is_empty());
        if let Some(d) = &device_id {
            check_device_id(d)?;
        }

        Ok(DeviceIdentity {
            seed,
            public_key,
            device_id,
        })
    }
}

/// The current wall-clock time as decimal-ASCII Unix SECONDS, e.g. `"1717900000"`.
///
/// Used as the `{TIMESTAMP}` line of the signed message AND sent verbatim in the
/// `X-Sigil-Timestamp` header, so the server reconstructs the exact same bytes.
fn unix_timestamp_secs() -> Result<String, CliError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| CliError::Key(format!("system clock is before the Unix epoch: {e}")))?;
    Ok(now.as_secs().to_string())
}

/// Build and sign the `sigil-oplog-auth-v2` message for one request, returning the
/// `(X-Sigil-Timestamp value, X-Sigil-Nonce value, X-Sigil-Signature value)`
/// header triple.
///
/// A FRESH random nonce is drawn per call: [`OPLOG_NONCE_LEN`] (>= 16) bytes from
/// the OS CSPRNG, standard-base64-encoded to the ASCII `X-Sigil-Nonce` value. That
/// exact base64 text is bound into the signed message AND returned as the header,
/// so a sigild that remembers seen nonces can REJECT a replayed request within the
/// timestamp window.
///
/// The signed MESSAGE is, byte-for-byte (lines joined by a single `\n`, with a
/// trailing `\n` after the nonce, then the raw body):
///
/// ```text
/// sigil-oplog-auth-v2\n
/// {METHOD}\n          (uppercase: "POST" or "GET")
/// {PATH}\n            (URL path, no query — e.g. /v1/vaults/demo/ops)
/// {QUERY}\n           (raw query string, or "" if none — e.g. since=0)
/// {TIMESTAMP}\n       (unix seconds, decimal ASCII)
/// {NONCE}\n           (the EXACT X-Sigil-Nonce base64 string, used verbatim)
/// {BODY}              (raw request body bytes; empty for GET)
/// ```
///
/// i.e. `MESSAGE = b"sigil-oplog-auth-v2\n" + METHOD + b"\n" + PATH + b"\n" +
/// QUERY + b"\n" + TIMESTAMP + b"\n" + NONCE + b"\n" + BODY`. The `(method, path,
/// query, body)` passed here MUST be exactly what the HTTP request will send (see
/// [`push_op`] / [`pull_ops`]), or the server's reconstruction will not match and
/// verification fails. The signature is standard-base64 of the 64-byte Ed25519
/// signature.
fn sign_oplog_request(
    seed: &[u8; SIG_SEED_LEN],
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
) -> Result<(String, String, String), CliError> {
    let timestamp = unix_timestamp_secs()?;

    // Fresh per-request nonce: OPLOG_NONCE_LEN random bytes, std-base64-encoded.
    // The base64 TEXT is both signed (verbatim, below) and sent as X-Sigil-Nonce,
    // so the server reconstructs the identical bytes.
    let mut nonce_bytes = [0u8; OPLOG_NONCE_LEN];
    fill_random(&mut nonce_bytes)?;
    let nonce = BASE64.encode(nonce_bytes);

    let mut message = Vec::with_capacity(
        OPLOG_AUTH_PREFIX.len()
            + method.len()
            + path.len()
            + query.len()
            + timestamp.len()
            + nonce.len()
            + body.len()
            + 5, // the five interior '\n' separators
    );
    message.extend_from_slice(OPLOG_AUTH_PREFIX);
    message.extend_from_slice(method.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(path.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(query.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(timestamp.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(nonce.as_bytes());
    message.push(b'\n');
    message.extend_from_slice(body);

    let signature = sign(seed, &message);
    Ok((timestamp, nonce, BASE64.encode(signature)))
}

// ---------------------------------------------------------------------------
// MULTI-DEVICE auth — the CLIENT side of sigild's contract v3 (Phase 42).
//
// STATUS: pre-audit, DEV-ONLY, UNAUDITED. This speaks sigild's REAL device model:
// a device ENROLLS (proving possession of its Ed25519 private key against an
// operator-provisioned, single-use enrollment token), the server assigns it a
// device ID, and every later op-log request is signed under the
// `sigil-oplog-auth-v3` message, which binds THAT device ID. The server resolves
// the ID to the registered public key, rejects a revoked device, and then checks
// a PER-VAULT grant (401 = not authenticated, 403 = authenticated but not
// authorized).
//
// CONTRACT SELECTION IS STRICTLY ADDITIVE:
//
//   no key file at all      -> unsigned            (unchanged legacy behaviour)
//   key file, no device_id  -> contract v2         (unchanged legacy behaviour)
//   key file with device_id -> contract v3         (new)
//
// so an existing key file, or no key at all, behaves EXACTLY as before.
//
// HONEST SCOPE: dev/localhost/plain-HTTP. The enrollment token is a bearer
// secret typed on the command line; the device seed lives in a 0600 file. There
// is no account model, no key rotation, no recovery, and no hardware backing.
// ---------------------------------------------------------------------------

/// The fixed domain-separation prefix of the contract v3 signed message. It MUST
/// match sigild's `opsAuthDomainV3` byte-for-byte.
pub const OPLOG_AUTH_V3_PREFIX: &[u8] = b"sigil-oplog-auth-v3\n";

/// The fixed domain-separation prefix of the device-enrollment proof-of-possession
/// challenge. It MUST match sigild's `enrollDomain` byte-for-byte. It is a
/// DIFFERENT domain from the request contract, so an enrollment proof can never be
/// replayed as a request signature.
pub const DEVICE_ENROLL_PREFIX: &[u8] = b"sigil-device-enroll-v1\n";

/// Header carrying the enrolled device ID on a contract v3 request.
const HEADER_DEVICE: &str = "X-Sigil-Device";
/// Header carrying the unix-seconds timestamp (both contracts + enrollment).
const HEADER_TIMESTAMP: &str = "X-Sigil-Timestamp";
/// Header carrying the fresh per-request nonce (both contracts + enrollment).
const HEADER_NONCE: &str = "X-Sigil-Nonce";
/// Header carrying the base64 Ed25519 signature (both contracts + enrollment).
const HEADER_SIGNATURE: &str = "X-Sigil-Signature";
/// Header carrying the single-use enrollment token. SECRET — never logged.
const HEADER_ENROLL_TOKEN: &str = "X-Sigil-Enroll-Token";
/// Header carrying the operator admin token. SECRET — never logged.
const HEADER_ADMIN_TOKEN: &str = "X-Sigil-Admin-Token";

/// A LOCAL device identity: the decoded Ed25519 key pair plus the OPTIONAL
/// server-assigned device ID. Produced by [`load_identity`].
///
/// The presence of `device_id` is what selects the request-auth contract (see
/// [`DeviceIdentity::auth`]). The `seed` is SECRET and is never printed by this
/// crate.
#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    /// The 32-byte Ed25519 secret seed. SECRET material.
    pub seed: [u8; SIG_SEED_LEN],
    /// The 32-byte Ed25519 public key.
    pub public_key: [u8; SIG_PUBLIC_KEY_LEN],
    /// The server-assigned device ID, when enrolled. `None` => legacy v2.
    pub device_id: Option<String>,
}

impl DeviceIdentity {
    /// Select the request-auth contract this identity signs under: contract v3
    /// when it carries a `device_id`, else the LEGACY contract v2.
    pub fn auth(&self) -> RequestAuth<'_> {
        match &self.device_id {
            Some(id) => RequestAuth::V3 {
                device_id: id,
                seed: &self.seed,
            },
            None => RequestAuth::V2 { seed: &self.seed },
        }
    }
}

/// How one HTTP request to sigild is authenticated.
///
/// [`RequestAuth::None`] sends no signature headers at all (the unauthenticated
/// dev path, unchanged); [`RequestAuth::V2`] is the legacy single-key contract;
/// [`RequestAuth::V3`] is the multi-device contract and additionally sends
/// `X-Sigil-Device`.
#[derive(Debug, Clone, Copy)]
pub enum RequestAuth<'a> {
    /// Send the request unsigned (sigild without request-auth configured).
    None,
    /// Sign under the legacy `sigil-oplog-auth-v2` contract.
    V2 {
        /// The 32-byte Ed25519 secret seed. SECRET material.
        seed: &'a [u8; SIG_SEED_LEN],
    },
    /// Sign under the multi-device `sigil-oplog-auth-v3` contract.
    V3 {
        /// The server-assigned device ID, sent as `X-Sigil-Device` AND bound
        /// into the signed message.
        device_id: &'a str,
        /// The 32-byte Ed25519 secret seed. SECRET material.
        seed: &'a [u8; SIG_SEED_LEN],
    },
}

impl RequestAuth<'_> {
    /// The short contract name, for user-facing messages. Never includes key
    /// material.
    pub fn contract(&self) -> &'static str {
        match self {
            RequestAuth::None => "unsigned",
            RequestAuth::V2 { .. } => "v2",
            RequestAuth::V3 { .. } => "v3",
        }
    }
}

/// Build the byte-for-byte contract v3 signed message:
///
/// ```text
/// sigil-oplog-auth-v3\n
/// {DEVICE_ID}\n
/// {METHOD}\n
/// {PATH}\n
/// {QUERY}\n
/// {TIMESTAMP}\n
/// {NONCE}\n
/// {BODY}
/// ```
///
/// i.e. `b"sigil-oplog-auth-v3\n" + DEVICE_ID + b"\n" + METHOD + b"\n" + PATH +
/// b"\n" + QUERY + b"\n" + TIMESTAMP + b"\n" + NONCE + b"\n" + BODY`. `METHOD` is
/// the uppercase HTTP method, `PATH` the URL path with NO query, `QUERY` the raw
/// query string (`""` when absent), `TIMESTAMP` decimal-ASCII unix seconds, and
/// `NONCE` the EXACT `X-Sigil-Nonce` text. This mirrors sigild's
/// `canonicalV3Message` and MUST stay byte-identical to it.
pub fn canonical_v3_message(
    device_id: &str,
    method: &str,
    path: &str,
    query: &str,
    timestamp: &str,
    nonce: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(
        OPLOG_AUTH_V3_PREFIX.len()
            + device_id.len()
            + method.len()
            + path.len()
            + query.len()
            + timestamp.len()
            + nonce.len()
            + body.len()
            + 6, // the six interior '\n' separators
    );
    m.extend_from_slice(OPLOG_AUTH_V3_PREFIX);
    for part in [device_id, method, path, query, timestamp, nonce] {
        m.extend_from_slice(part.as_bytes());
        m.push(b'\n');
    }
    m.extend_from_slice(body);
    m
}

/// Build the byte-for-byte device-enrollment proof-of-possession challenge:
///
/// ```text
/// sigil-device-enroll-v1\n
/// {TOKEN_SHA256_HEX}\n
/// {TIMESTAMP}\n
/// {NONCE}\n
/// {PUBLIC_KEY_B64}\n
/// {LABEL}
/// ```
///
/// i.e. `b"sigil-device-enroll-v1\n" + TOKEN_SHA256_HEX + b"\n" + TIMESTAMP +
/// b"\n" + NONCE + b"\n" + PUBLIC_KEY_B64 + b"\n" + LABEL` — note there is NO
/// trailing newline after the label. `TOKEN_SHA256_HEX` is [`enroll_token_hash`]
/// of the enrollment token; `PUBLIC_KEY_B64` and `LABEL` are the EXACT strings
/// placed in the JSON request body. The enrolling device signs this with the
/// private key matching the public key it submits — that is the proof of
/// possession. This mirrors sigild's `canonicalEnrollMessage`.
pub fn canonical_enroll_message(
    token_hash_hex: &str,
    timestamp: &str,
    nonce: &str,
    public_key_b64: &str,
    label: &str,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(
        DEVICE_ENROLL_PREFIX.len()
            + token_hash_hex.len()
            + timestamp.len()
            + nonce.len()
            + public_key_b64.len()
            + label.len()
            + 4, // the four interior '\n' separators
    );
    m.extend_from_slice(DEVICE_ENROLL_PREFIX);
    for part in [token_hash_hex, timestamp, nonce, public_key_b64] {
        m.extend_from_slice(part.as_bytes());
        m.push(b'\n');
    }
    m.extend_from_slice(label.as_bytes());
    m
}

/// Lowercase-hex SHA-256 of an enrollment token, exactly as sigild computes it.
///
/// The token itself is SECRET and is never logged; only this digest is bound into
/// the signed enrollment challenge (so a captured proof cannot be re-presented
/// with a different token).
pub fn enroll_token_hash(token: &str) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(token.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for b in digest {
        out.push(char::from_digit((b >> 4) as u32, 16).expect("nibble < 16"));
        out.push(char::from_digit((b & 0x0f) as u32, 16).expect("nibble < 16"));
    }
    out
}

/// Draw a fresh per-request nonce: [`OPLOG_NONCE_LEN`] CSPRNG bytes, standard
/// base64. The base64 TEXT is what is signed and sent, so both sides see the same
/// bytes.
fn fresh_nonce() -> Result<String, CliError> {
    let mut nonce_bytes = [0u8; OPLOG_NONCE_LEN];
    fill_random(&mut nonce_bytes)?;
    Ok(BASE64.encode(nonce_bytes))
}

/// Sign one request under contract v3, returning the
/// `(timestamp, nonce, signature)` header triple. A FRESH nonce is drawn per call
/// and the CURRENT unix time is used, so each request is unique and replay of a
/// captured one is rejected inside the server's window.
fn sign_oplog_request_v3(
    seed: &[u8; SIG_SEED_LEN],
    device_id: &str,
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
) -> Result<(String, String, String), CliError> {
    let timestamp = unix_timestamp_secs()?;
    let nonce = fresh_nonce()?;
    let message = canonical_v3_message(device_id, method, path, query, &timestamp, &nonce, body);
    let signature = sign(seed, &message);
    Ok((timestamp, nonce, BASE64.encode(signature)))
}

/// Attach the auth headers for `auth` to `req`, signing over EXACTLY the
/// `(method, path, query, body)` the request will send.
///
/// [`RequestAuth::None`] adds nothing at all — byte-for-byte the legacy
/// unauthenticated request.
fn apply_auth(
    req: ureq::Request,
    auth: &RequestAuth<'_>,
    method: &str,
    path: &str,
    query: &str,
    body: &[u8],
) -> Result<ureq::Request, CliError> {
    match auth {
        RequestAuth::None => Ok(req),
        RequestAuth::V2 { seed } => {
            let (ts, nonce, sig) = sign_oplog_request(seed, method, path, query, body)?;
            Ok(req
                .set(HEADER_TIMESTAMP, &ts)
                .set(HEADER_NONCE, &nonce)
                .set(HEADER_SIGNATURE, &sig))
        }
        RequestAuth::V3 { device_id, seed } => {
            let (ts, nonce, sig) =
                sign_oplog_request_v3(seed, device_id, method, path, query, body)?;
            Ok(req
                .set(HEADER_DEVICE, device_id)
                .set(HEADER_TIMESTAMP, &ts)
                .set(HEADER_NONCE, &nonce)
                .set(HEADER_SIGNATURE, &sig))
        }
    }
}

/// Reject device IDs that cannot be placed verbatim in a URL path segment.
///
/// Same rule as [`check_vault`]: non-empty, no `/`, no ASCII whitespace. Server
/// IDs are `dev_` + base64url, so a legitimate ID always passes.
fn check_device_id(device_id: &str) -> Result<(), CliError> {
    if device_id.is_empty()
        || device_id.contains('/')
        || device_id.chars().any(|c| c.is_whitespace())
    {
        return Err(CliError::Key(format!(
            "invalid device id {device_id:?}: must be non-empty with no '/' or whitespace"
        )));
    }
    Ok(())
}

/// Join a server base URL and an absolute path, tolerating a trailing `/` on the
/// base so we never build `http://host//v1/...`.
fn join_url(server: &str, path: &str) -> String {
    let base = server.strip_suffix('/').unwrap_or(server);
    format!("{base}{path}")
}

/// A device as reported by the server's device routes. The registry never echoes
/// public keys back, so this carries only metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct DeviceInfo {
    /// The server-assigned device ID.
    pub device_id: String,
    /// The human label supplied at enrollment.
    #[serde(default)]
    pub label: String,
    /// `"active"` or `"revoked"`.
    #[serde(default)]
    pub status: String,
    /// RFC 3339 creation time.
    #[serde(default)]
    pub created_at: String,
    /// RFC 3339 revocation time, absent while active.
    #[serde(default)]
    pub revoked_at: Option<String>,
}

/// ENROLL this device's Ed25519 public key with sigild and return the assigned
/// device record.
///
/// Two independent factors are sent, both mandatory server-side:
/// 1. the operator-provisioned, SINGLE-USE enrollment token (`X-Sigil-Enroll-Token`);
/// 2. PROOF OF POSSESSION — an Ed25519 signature by `seed` over
///    [`canonical_enroll_message`], which binds the token digest, the timestamp,
///    a fresh nonce, the submitted public key, and the label.
///
/// The token is a BEARER SECRET: it is sent in a header and is never printed or
/// logged by this crate. It is single-use — a failed attempt burns it.
///
/// # Errors
/// - [`CliError::Server`] on a non-2xx: `401` (bad/expired/spent token or bad
///   proof), `409` (that public key is already enrolled), `501` (the device model
///   is not enabled on that server).
/// - [`CliError::Http`] on a transport failure, [`CliError::BadResponse`] on an
///   unparseable `201` body.
pub fn enroll_device(
    server: &str,
    token: &str,
    label: &str,
    public_key: &[u8; SIG_PUBLIC_KEY_LEN],
    seed: &[u8; SIG_SEED_LEN],
) -> Result<DeviceInfo, CliError> {
    if token.is_empty() {
        return Err(CliError::Key(
            "enrollment token is empty; pass --token <token>".to_string(),
        ));
    }
    let public_key_b64 = BASE64.encode(public_key);

    // Serialize the body FIRST, then sign the exact strings it carries. The
    // server signs/verifies the DECODED JSON strings, so escaping cannot diverge.
    #[derive(Serialize)]
    struct EnrollBody<'a> {
        public_key: &'a str,
        label: &'a str,
    }
    let body = serde_json::to_vec(&EnrollBody {
        public_key: &public_key_b64,
        label,
    })
    .map_err(|e| CliError::Key(format!("could not serialize enrollment body: {e}")))?;

    let timestamp = unix_timestamp_secs()?;
    let nonce = fresh_nonce()?;
    let token_hash = enroll_token_hash(token);
    let message = canonical_enroll_message(&token_hash, &timestamp, &nonce, &public_key_b64, label);
    let signature = BASE64.encode(sign(seed, &message));

    let url = join_url(server, "/v1/devices/enroll");
    let result = ureq::post(&url)
        .set("Content-Type", "application/json")
        .set(HEADER_ENROLL_TOKEN, token)
        .set(HEADER_TIMESTAMP, &timestamp)
        .set(HEADER_NONCE, &nonce)
        .set(HEADER_SIGNATURE, &signature)
        .send_bytes(&body);
    let text = finish(result)?;
    serde_json::from_str(&text).map_err(|e| CliError::BadResponse(e.to_string()))
}

/// LIST every registered device. Operator-only: this requires the admin token
/// (sigild's `SIGILD_ADMIN_TOKEN`), which is a BEARER SECRET and is never logged.
///
/// # Errors
/// - [`CliError::Server`] on a non-2xx (`401` when the admin token is wrong or
///   the server has none configured, `501` when the device model is off).
pub fn list_devices(server: &str, admin_token: &str) -> Result<Vec<DeviceInfo>, CliError> {
    let url = join_url(server, "/v1/devices");
    let result = ureq::get(&url).set(HEADER_ADMIN_TOKEN, admin_token).call();
    let text = finish(result)?;

    #[derive(Deserialize)]
    struct ListResp {
        #[serde(default)]
        devices: Vec<DeviceInfo>,
    }
    let parsed: ListResp =
        serde_json::from_str(&text).map_err(|e| CliError::BadResponse(e.to_string()))?;
    Ok(parsed.devices)
}

/// REVOKE a device. A revoked device is rejected on its very next request.
///
/// Two authorized paths, matching the server: the operator `admin_token` (may
/// revoke ANY device), or SELF-REVOCATION — a valid contract v3 signature whose
/// signing device IS `device_id`. When `admin_token` is `Some`, it is sent and the
/// request is additionally signed if `auth` is a signing mode; a device may never
/// revoke a DIFFERENT device (the server answers 403).
///
/// # Errors
/// - [`CliError::Server`] on a non-2xx: `401` (no valid credential), `403`
///   (authenticated but revoking someone else), `404` (no such device).
pub fn revoke_device(
    server: &str,
    device_id: &str,
    auth: &RequestAuth<'_>,
    admin_token: Option<&str>,
) -> Result<DeviceInfo, CliError> {
    check_device_id(device_id)?;
    let path = format!("/v1/devices/{device_id}/revoke");
    let url = join_url(server, &path);

    // An empty body is sent and is what gets signed (the server authenticates
    // over the bytes it read).
    let body: &[u8] = b"";
    let mut req = ureq::post(&url).set("Content-Type", "application/json");
    if let Some(t) = admin_token {
        req = req.set(HEADER_ADMIN_TOKEN, t);
    }
    req = apply_auth(req, auth, "POST", &path, "", body)?;
    let text = finish(req.send_bytes(body))?;
    serde_json::from_str(&text).map_err(|e| CliError::BadResponse(e.to_string()))
}

/// GRANT another enrolled device access to a vault. OWNER-ONLY: the signing
/// device must be the vault's owner (the device that claimed it on first write),
/// so `auth` must be a contract v3 identity.
///
/// `permission` is `"read"` or `"write"`.
///
/// # Errors
/// - [`CliError::Key`] if `permission` is neither `read` nor `write`.
/// - [`CliError::Server`] on a non-2xx: `403` (the signer is not the vault
///   owner), `404` (no such grantee device), `409` (the grantee is revoked).
pub fn grant_vault_access(
    server: &str,
    vault: &str,
    device_id: &str,
    permission: &str,
    auth: &RequestAuth<'_>,
) -> Result<(), CliError> {
    check_vault(vault)?;
    check_device_id(device_id)?;
    if permission != "read" && permission != "write" {
        return Err(CliError::Key(format!(
            "invalid permission {permission:?}: must be \"read\" or \"write\""
        )));
    }

    #[derive(Serialize)]
    struct GrantBody<'a> {
        device_id: &'a str,
        permission: &'a str,
    }
    let body = serde_json::to_vec(&GrantBody {
        device_id,
        permission,
    })
    .map_err(|e| CliError::Key(format!("could not serialize grant body: {e}")))?;

    let path = format!("/v1/vaults/{vault}/grants");
    let url = join_url(server, &path);
    let req = ureq::post(&url).set("Content-Type", "application/json");
    let req = apply_auth(req, auth, "POST", &path, "", &body)?;
    finish(req.send_bytes(&body))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Sync layer: push/pull OPAQUE containers to/from sigild's DEV-ONLY op-log.
//
// STATUS: pre-audit, dev/localhost ONLY. These functions move already-sealed,
// OPAQUE container bytes over PLAIN HTTP to a sigild dev op-log that is itself
// dev-gated (SIGILD_ENABLE_DEV_OPS=1) and UNAUTHENTICATED. They perform NO
// cryptography and never see plaintext or the password — they just shuttle the
// envelope bytes. No TLS, no auth, no durability: not for production or real
// secrets.
// ---------------------------------------------------------------------------

/// One operation pulled back from the dev op-log: its server sequence number
/// and the OPAQUE container bytes (already base64-decoded from the wire).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulledOp {
    /// The op-log sequence number assigned by sigild (monotonic per vault).
    pub seq: u64,
    /// The opaque container bytes (a `seal_to_container` output, decoded).
    pub blob: Vec<u8>,
}

/// Reject vault ids that cannot be placed verbatim in a URL path segment.
///
/// We do not percent-encode; instead we require the id to be non-empty and free
/// of `/` and ASCII whitespace, which keeps the request line unambiguous.
fn check_vault(vault: &str) -> Result<(), CliError> {
    if vault.is_empty() || vault.contains('/') || vault.chars().any(|c| c.is_whitespace()) {
        return Err(CliError::BadVault(vault.to_string()));
    }
    Ok(())
}

/// Trim a single trailing `/` from the server base URL so we don't build
/// `http://host//v1/...` when the caller passes a trailing slash.
fn ops_url(server: &str, vault: &str) -> String {
    let base = server.strip_suffix('/').unwrap_or(server);
    format!("{base}{}", ops_path(vault))
}

/// The URL PATH (no scheme/host, no query) of the op-log endpoint for `vault`,
/// e.g. `/v1/vaults/demo/ops`. This is exactly the `{PATH}` the server parses
/// from `r.URL.Path`, so it is also what [`sign_oplog_request`] must sign.
fn ops_path(vault: &str) -> String {
    format!("/v1/vaults/{vault}/ops")
}

/// Map a `ureq` call result into a 2xx response string, or a [`CliError`].
///
/// `ureq` returns `Err(Status(code, resp))` for non-2xx; we fold that into
/// [`CliError::Server`]. Transport/IO errors become [`CliError::Http`]. On 2xx
/// we read the body to a string (a read failure is also `Http`).
fn finish(result: Result<ureq::Response, ureq::Error>) -> Result<String, CliError> {
    match result {
        Ok(resp) => resp
            .into_string()
            .map_err(|e| CliError::Http(e.to_string())),
        Err(ureq::Error::Status(status, resp)) => {
            // Best-effort read of the error body; ignore a body-read failure.
            let body = resp.into_string().unwrap_or_default();
            Err(CliError::Server { status, body })
        }
        Err(ureq::Error::Transport(t)) => Err(CliError::Http(t.to_string())),
    }
}

/// POST an OPAQUE `container` to the dev op-log and return its assigned `seq`.
///
/// Sends the raw container bytes (Content-Type `application/octet-stream`) to
/// `{server}/v1/vaults/{vault}/ops`. On `201` it parses `{"seq": <u64>}` and
/// returns the sequence number.
///
/// When `key` is `Some(seed)`, signs the request under the `sigil-oplog-auth-v2`
/// contract and attaches the `X-Sigil-Timestamp` / `X-Sigil-Nonce` /
/// `X-Sigil-Signature` headers (a fresh nonce per call), so a sigild configured
/// with `SIGILD_OPLOG_PUBKEY` will accept the append. The signed
/// `(method, path, query, body)` is exactly what this request sends: `POST`,
/// `/v1/vaults/{vault}/ops`, an EMPTY query, and `container` as the body. When
/// `key` is `None`, no signature headers are sent (the legacy unauthenticated dev
/// path).
///
/// DEV/LOCALHOST/PLAIN-HTTP ONLY — see the module note above. This never sees
/// plaintext; the container is opaque.
///
/// # Errors
/// - [`CliError::BadVault`] if `vault` is empty or has a `/`/whitespace.
/// - [`CliError::Server`] on any non-2xx (e.g. `501` if the dev flag is off,
///   `401` if the request is unsigned/invalid while sigild requires a signature,
///   `400` empty op, `413` oversized).
/// - [`CliError::Http`] on a transport/IO failure.
/// - [`CliError::BadResponse`] if the `201` body is not the expected JSON.
pub fn push_op(
    server: &str,
    vault: &str,
    container: &[u8],
    key: Option<&[u8; SIG_SEED_LEN]>,
) -> Result<u64, CliError> {
    let auth = match key {
        Some(seed) => RequestAuth::V2 { seed },
        None => RequestAuth::None,
    };
    push_op_auth(server, vault, container, &auth)
}

/// POST an OPAQUE `container` to the dev op-log under an explicit [`RequestAuth`]
/// and return its assigned `seq`.
///
/// This is [`push_op`] generalised over the auth contract: [`RequestAuth::None`]
/// sends the request unsigned (byte-identical to the legacy path),
/// [`RequestAuth::V2`] signs the legacy single-key message, and
/// [`RequestAuth::V3`] signs the multi-device message and sends `X-Sigil-Device`.
///
/// The signed `(method, path, query, body)` is exactly what this request sends:
/// `POST`, `/v1/vaults/{vault}/ops`, an EMPTY query, and `container` as the body.
///
/// Under v3 a WRITE to an unclaimed vault CLAIMS it for the signing device
/// (trust-on-first-write); a write to a vault owned by another device is `403`.
///
/// # Errors
/// As [`push_op`], plus `403` (authenticated but not authorized for this vault)
/// under contract v3.
pub fn push_op_auth(
    server: &str,
    vault: &str,
    container: &[u8],
    auth: &RequestAuth<'_>,
) -> Result<u64, CliError> {
    check_vault(vault)?;
    let url = ops_url(server, vault);

    let req = ureq::post(&url).set("Content-Type", "application/octet-stream");
    // Sign EXACTLY what this request sends: POST, the op path, NO query,
    // body = container. The query is "" to match the server's r.URL.RawQuery.
    let req = apply_auth(req, auth, "POST", &ops_path(vault), "", container)?;
    let result = req.send_bytes(container);
    let body = finish(result)?;

    #[derive(Deserialize)]
    struct AppendResp {
        seq: u64,
    }
    let parsed: AppendResp =
        serde_json::from_str(&body).map_err(|e| CliError::BadResponse(e.to_string()))?;
    Ok(parsed.seq)
}

/// GET operations with `seq > since` from the dev op-log, in ascending order.
///
/// Calls `{server}/v1/vaults/{vault}/ops?since={since}`, parses the JSON, and
/// base64-decodes each `blob` (standard alphabet) into the opaque container
/// bytes. Returns them in the order the server sent them (seq-ascending).
///
/// When `key` is `Some(seed)`, signs the request under the `sigil-oplog-auth-v2`
/// contract and attaches the `X-Sigil-Timestamp` / `X-Sigil-Nonce` /
/// `X-Sigil-Signature` headers (a fresh nonce per call), so a sigild configured
/// with `SIGILD_OPLOG_PUBKEY` will accept the list. The signed
/// `(method, path, query, body)` is exactly what this request sends: `GET`,
/// `/v1/vaults/{vault}/ops`, the query `since={since}`, and an EMPTY body. The
/// `since` value is rendered once and used both for the signed query and the
/// `?since=` parameter so the bytes match. When `key` is `None`, no signature
/// headers are sent (the legacy unauthenticated dev path).
///
/// DEV/LOCALHOST/PLAIN-HTTP ONLY — see the module note above.
///
/// # Errors
/// - [`CliError::BadVault`] if `vault` is empty or has a `/`/whitespace.
/// - [`CliError::Server`] on any non-2xx (e.g. `501` if the dev flag is off,
///   `401` if the request is unsigned/invalid while sigild requires a signature).
/// - [`CliError::Http`] on a transport/IO failure.
/// - [`CliError::BadResponse`] if the body is not the expected JSON or a `blob`
///   is not valid base64.
pub fn pull_ops(
    server: &str,
    vault: &str,
    since: u64,
    key: Option<&[u8; SIG_SEED_LEN]>,
) -> Result<Vec<PulledOp>, CliError> {
    let auth = match key {
        Some(seed) => RequestAuth::V2 { seed },
        None => RequestAuth::None,
    };
    pull_ops_auth(server, vault, since, &auth)
}

/// GET operations with `seq > since` from the dev op-log under an explicit
/// [`RequestAuth`].
///
/// This is [`pull_ops`] generalised over the auth contract (see
/// [`push_op_auth`]). The signed `(method, path, query, body)` is exactly what
/// this request sends: `GET`, `/v1/vaults/{vault}/ops`, the query
/// `since={since}`, and an EMPTY body.
///
/// Under contract v3 a READ never claims a vault: reading an unowned vault, or
/// one owned by another device with no grant, is `403`.
///
/// # Errors
/// As [`pull_ops`], plus `403` (authenticated but not authorized for this vault)
/// under contract v3.
pub fn pull_ops_auth(
    server: &str,
    vault: &str,
    since: u64,
    auth: &RequestAuth<'_>,
) -> Result<Vec<PulledOp>, CliError> {
    check_vault(vault)?;
    let url = ops_url(server, vault);

    // Render `since` ONCE so the signed query and the wire query are byte-identical.
    let since_str = since.to_string();
    let query = format!("since={since_str}");

    let req = ureq::get(&url).query("since", &since_str);
    // Sign EXACTLY what this request sends: GET, the op path, query
    // "since={since}", empty body — matching the server's r.URL.RawQuery.
    let req = apply_auth(req, auth, "GET", &ops_path(vault), &query, b"")?;
    let result = req.call();
    let body = finish(result)?;

    #[derive(Deserialize)]
    struct WireOp {
        seq: u64,
        blob: String,
    }
    #[derive(Deserialize)]
    struct ListResp {
        #[serde(default)]
        ops: Vec<WireOp>,
    }

    let parsed: ListResp =
        serde_json::from_str(&body).map_err(|e| CliError::BadResponse(e.to_string()))?;

    let mut out = Vec::with_capacity(parsed.ops.len());
    for op in parsed.ops {
        let blob = BASE64
            .decode(op.blob.as_bytes())
            .map_err(|e| CliError::BadResponse(format!("op {} blob not base64: {e}", op.seq)))?;
        out.push(PulledOp { seq: op.seq, blob });
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Pull cursor: per-(server, vault) "last pulled seq" so repeated pulls only
// fetch NEW ops.
//
// The cursor lives in a small JSON state file (`.sigil-pull-state.json`) inside
// the pull `--out-dir`. It is a flat object mapping a cursor key (a
// `"{server}|{vault}"` string) to the last seq that has been pulled for that
// (server, vault) pair, e.g. `{"http://127.0.0.1:8080|demo": 7}`.
//
// This is LOCAL DEVICE STATE: it is NOT secret, NOT synced, and contains no
// crypto material (only opaque server URLs, vault ids, and integers). The
// cursor is MONOTONIC — callers advance it forward and never move it backward,
// so a one-off `--since 0` re-fetch does not rewind future incremental pulls.
// ---------------------------------------------------------------------------

/// File name of the local pull-cursor state file, written into the pull
/// `--out-dir`. Local, non-secret device state — see the module note above.
pub const PULL_STATE_FILE: &str = ".sigil-pull-state.json";

/// Build the cursor key for a `(server, vault)` pair: `"{server}|{vault}"`.
///
/// `vault` ids are validated elsewhere to be free of whitespace and `/`; the
/// `|` separator keeps distinct pairs from colliding in the state map.
pub fn cursor_key(server: &str, vault: &str) -> String {
    format!("{server}|{vault}")
}

/// Read the last-pulled seq for `key` from the JSON state file at `state_path`.
///
/// Semantics:
/// - the file does not exist -> `Ok(0)` (nothing pulled yet);
/// - the file exists and parses as a `{string: u64}` object, but `key` is
///   absent -> `Ok(0)`;
/// - the file exists and `key` is present -> `Ok(its value)`;
/// - the file exists but cannot be read or parsed as such an object ->
///   `Err(CliError::State(..))`, so corruption is surfaced, not silently masked.
///
/// The state file is LOCAL, non-secret device state (see the module note).
///
/// # Errors
/// - [`CliError::State`] on a read failure (other than not-found) or if the
///   file is not a valid `{string: u64}` JSON object.
pub fn read_cursor(state_path: &std::path::Path, key: &str) -> Result<u64, CliError> {
    let text = match std::fs::read_to_string(state_path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(CliError::State(format!("could not read state file: {e}"))),
    };
    let map = parse_state(&text)?;
    Ok(map.get(key).copied().unwrap_or(0))
}

/// Set `key = seq` in the JSON state file at `state_path`, preserving any other
/// entries, and write the whole map back.
///
/// If the file does not exist it is created with a single entry; if it exists it
/// is read first (a corrupt file is an error, so we never clobber state we can't
/// understand) and the one key is updated.
///
/// The state file is LOCAL, non-secret device state (see the module note).
///
/// # Errors
/// - [`CliError::State`] on a read/parse failure of the existing file or on a
///   write failure.
pub fn write_cursor(state_path: &std::path::Path, key: &str, seq: u64) -> Result<(), CliError> {
    let mut map = match std::fs::read_to_string(state_path) {
        Ok(t) => parse_state(&t)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => std::collections::BTreeMap::new(),
        Err(e) => return Err(CliError::State(format!("could not read state file: {e}"))),
    };
    map.insert(key.to_string(), seq);

    let serialized = serde_json::to_string(&map)
        .map_err(|e| CliError::State(format!("could not serialize state: {e}")))?;
    std::fs::write(state_path, serialized)
        .map_err(|e| CliError::State(format!("could not write state file: {e}")))
}

/// Parse the state-file text into a `{string: u64}` map, mapping any JSON or
/// shape error to [`CliError::State`].
fn parse_state(text: &str) -> Result<std::collections::BTreeMap<String, u64>, CliError> {
    serde_json::from_str(text).map_err(|e| {
        CliError::State(format!(
            "state file is not a valid {{string: u64}} map: {e}"
        ))
    })
}

// ---------------------------------------------------------------------------
// TOTP vault: the FIRST real product feature. A list of TOTP secrets, sealed at
// rest with the SAME password container as `seal`/`open` (a `SIGILcli` file whose
// plaintext is the entries JSON), so a TOTP vault is just another opaque sealed
// container and can be synced through the op-log later.
//
// STATUS: pre-audit, UNAUDITED, DEV-ONLY. Code GENERATION uses `sigil-core`'s
// RFC 4226 / RFC 6238 primitive (checked against the official RFC vectors); the
// vault-at-rest uses the same Argon2id + XChaCha20-Poly1305 container as seal/open.
// Do NOT store real 2FA secrets in this pre-audit build.
// ---------------------------------------------------------------------------

/// The TOTP-vault JSON version this build writes and reads (the *inner* plaintext
/// version; the outer container is a normal `SIGILcli` file).
pub const TOTP_VAULT_VERSION: u8 = 1;

/// Default number of digits for a TOTP code when none is specified.
pub const TOTP_DEFAULT_DIGITS: u32 = 6;

/// Default TOTP period (time step) in seconds when none is specified.
pub const TOTP_DEFAULT_PERIOD: u32 = 30;

/// One TOTP secret in the vault.
///
/// The `secret` is the RAW key bytes stored as standard-base64 in the JSON (the
/// on-the-wire provisioning form is base32, but we store the decoded bytes). The
/// `algorithm` is one of `"sha1"`, `"sha256"`, `"sha512"` (lowercase).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpEntry {
    /// Human label for the account, e.g. `"alice@example.com"`. Unique within a
    /// vault (used to look an entry up).
    pub label: String,
    /// Optional issuer/service name, e.g. `"GitHub"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    /// Standard-base64 of the RAW secret key bytes (decoded from the base32
    /// provisioning form). SECRET material — never printed by `list`.
    pub secret: String,
    /// The HMAC hash: `"sha1"` (default), `"sha256"`, or `"sha512"`.
    pub algorithm: String,
    /// Number of digits in the generated code (typically 6).
    pub digits: u32,
    /// Time step in seconds (typically 30).
    pub period: u32,
}

/// The decrypted plaintext of a TOTP vault: a versioned list of [`TotpEntry`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TotpVault {
    /// Inner vault format version. Always [`TOTP_VAULT_VERSION`].
    pub version: u8,
    /// The stored TOTP entries.
    pub entries: Vec<TotpEntry>,
}

impl Default for TotpVault {
    fn default() -> Self {
        TotpVault {
            version: TOTP_VAULT_VERSION,
            entries: Vec::new(),
        }
    }
}

/// Map a lowercase algorithm string to a [`OtpAlgorithm`], defaulting `""` to
/// SHA-1. Accepts `sha1`/`sha256`/`sha512` case-insensitively.
///
/// # Errors
/// - [`CliError::Totp`] for any other value.
pub fn totp_algorithm_from_str(s: &str) -> Result<OtpAlgorithm, CliError> {
    match s.to_ascii_lowercase().as_str() {
        "" | "sha1" => Ok(OtpAlgorithm::Sha1),
        "sha256" => Ok(OtpAlgorithm::Sha256),
        "sha512" => Ok(OtpAlgorithm::Sha512),
        other => Err(CliError::Totp(format!(
            "unknown algorithm {other:?}: expected sha1, sha256, or sha512"
        ))),
    }
}

/// The canonical lowercase name for an [`OtpAlgorithm`] (what we store in JSON).
#[must_use]
pub fn totp_algorithm_name(a: OtpAlgorithm) -> &'static str {
    match a {
        OtpAlgorithm::Sha1 => "sha1",
        OtpAlgorithm::Sha256 => "sha256",
        OtpAlgorithm::Sha512 => "sha512",
        // OtpAlgorithm is #[non_exhaustive]; treat any future arm as sha1's name
        // is wrong, so name it explicitly-unknown to avoid silently mislabeling.
        _ => "sha1",
    }
}

/// Decode an RFC 4648 base32 string into raw bytes.
///
/// Case-insensitive; ASCII whitespace and `=` padding are ignored (so a secret
/// pasted with spaces, e.g. from a provisioning screen, still decodes). Rejects
/// any other non-alphabet character and an all-empty input.
///
/// # Errors
/// - [`CliError::Totp`] on an invalid character or an empty decode.
pub fn base32_decode(input: &str) -> Result<Vec<u8>, CliError> {
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    let mut out = Vec::new();
    for c in input.chars() {
        if c == '=' || c.is_whitespace() {
            continue;
        }
        let up = c.to_ascii_uppercase();
        let val: u32 = match up {
            'A'..='Z' => (up as u8 - b'A') as u32,
            '2'..='7' => (up as u8 - b'2') as u32 + 26,
            _ => {
                return Err(CliError::Totp(format!(
                    "invalid base32 character {c:?} in secret"
                )))
            }
        };
        acc = (acc << 5) | val;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            // Keep only the remaining low bits so `acc` cannot overflow across a
            // long secret. `(1 << 0) - 1 == 0` handles the nbits==0 case.
            acc &= (1u32 << nbits) - 1;
        }
    }
    if out.is_empty() {
        return Err(CliError::Totp(
            "base32 secret decoded to zero bytes".to_string(),
        ));
    }
    Ok(out)
}

/// Encode raw bytes into an RFC 4648 base32 string (uppercase, UNPADDED).
///
/// The inverse of [`base32_decode`] (which ignores case and `=` padding), so
/// `base32_decode(base32_encode(x)) == x`. Used to render a secret back into the
/// base32 provisioning form for an `otpauth://` export URI. Empty input yields an
/// empty string.
#[must_use]
pub fn base32_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut acc: u32 = 0;
    let mut nbits: u32 = 0;
    for &b in input {
        acc = (acc << 8) | u32::from(b);
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(ALPHABET[((acc >> nbits) & 0x1f) as usize] as char);
        }
    }
    if nbits > 0 {
        // Left-align the remaining low bits into a final 5-bit group.
        out.push(ALPHABET[((acc << (5 - nbits)) & 0x1f) as usize] as char);
    }
    out
}

/// Build a [`TotpEntry`] from raw parts, base64-encoding the raw `secret` bytes.
///
/// Validates `digits` against the core's supported range up front (a bad digit
/// count would otherwise only surface later at code-generation time).
///
/// # Errors
/// - [`CliError::Totp`] if `digits`/`period` are out of range.
pub fn new_totp_entry(
    label: &str,
    issuer: Option<String>,
    secret: &[u8],
    algorithm: OtpAlgorithm,
    digits: u32,
    period: u32,
) -> Result<TotpEntry, CliError> {
    if label.is_empty() {
        return Err(CliError::Totp("label must not be empty".to_string()));
    }
    if !(sigil_core::MIN_DIGITS..=sigil_core::MAX_DIGITS).contains(&digits) {
        return Err(CliError::Totp(format!(
            "digits {digits} out of range {}..={}",
            sigil_core::MIN_DIGITS,
            sigil_core::MAX_DIGITS
        )));
    }
    if period == 0 {
        return Err(CliError::Totp("period must be non-zero".to_string()));
    }
    Ok(TotpEntry {
        label: label.to_string(),
        issuer,
        secret: BASE64.encode(secret),
        algorithm: totp_algorithm_name(algorithm).to_string(),
        digits,
        period,
    })
}

/// Minimal percent-decoder for `otpauth://` label/issuer fields (`%XX` → byte).
/// Unknown/short escapes are passed through literally. UTF-8 is best-effort.
pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Map an ASCII hex digit byte to its 0..=15 value, or `None`.
fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Parse an `otpauth://totp/...` provisioning URI into a [`TotpEntry`].
///
/// Understands the standard shape
/// `otpauth://totp/LABEL?secret=BASE32&issuer=..&algorithm=..&digits=..&period=..`.
/// `LABEL` may be `Issuer:Account` — the account becomes the label and the prefix
/// seeds the issuer (a `?issuer=` query overrides it). `secret` is required.
///
/// Only the `totp` type is accepted (not `hotp`, which has no time step).
///
/// # Errors
/// - [`CliError::Totp`] on a missing/invalid scheme, a missing/invalid `secret`,
///   an unknown algorithm, or non-integer `digits`/`period`.
pub fn parse_otpauth_uri(uri: &str) -> Result<TotpEntry, CliError> {
    // Case-insensitive scheme+type prefix.
    let lower = uri.to_ascii_lowercase();
    let prefix = "otpauth://totp/";
    if !lower.starts_with(prefix) {
        if lower.starts_with("otpauth://hotp/") {
            return Err(CliError::Totp(
                "otpauth hotp:// URIs are not supported (no time step); use a totp:// URI"
                    .to_string(),
            ));
        }
        return Err(CliError::Totp("not an otpauth://totp/ URI".to_string()));
    }
    // Slice the ORIGINAL (case-preserving) string past the prefix.
    let rest = &uri[prefix.len()..];
    let (label_part, query) = match rest.split_once('?') {
        Some((l, q)) => (l, q),
        None => (rest, ""),
    };

    let label_decoded = percent_decode(label_part);
    // A "Issuer:Account" label seeds the issuer and reduces the label to Account.
    let (issuer_from_label, label) = match label_decoded.split_once(':') {
        Some((iss, acct)) => (Some(iss.trim().to_string()), acct.trim().to_string()),
        None => (None, label_decoded.trim().to_string()),
    };

    let mut secret_b32: Option<String> = None;
    let mut issuer_from_query: Option<String> = None;
    let mut algorithm = OtpAlgorithm::Sha1;
    let mut digits = TOTP_DEFAULT_DIGITS;
    let mut period = TOTP_DEFAULT_PERIOD;

    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k.to_ascii_lowercase().as_str() {
            "secret" => secret_b32 = Some(v.to_string()),
            "issuer" => issuer_from_query = Some(percent_decode(v)),
            "algorithm" => algorithm = totp_algorithm_from_str(v)?,
            "digits" => {
                digits = v
                    .parse::<u32>()
                    .map_err(|_| CliError::Totp(format!("digits {v:?} is not an integer")))?
            }
            "period" => {
                period = v
                    .parse::<u32>()
                    .map_err(|_| CliError::Totp(format!("period {v:?} is not an integer")))?
            }
            _ => { /* ignore unknown params (e.g. counter, image) */ }
        }
    }

    let secret_b32 =
        secret_b32.ok_or_else(|| CliError::Totp("otpauth URI has no secret".to_string()))?;
    let secret = base32_decode(&secret_b32)?;
    // A `?issuer=` query wins over the label prefix.
    let issuer = issuer_from_query
        .or(issuer_from_label)
        .filter(|s| !s.is_empty());
    if label.is_empty() {
        return Err(CliError::Totp(
            "otpauth URI has an empty account label".to_string(),
        ));
    }

    new_totp_entry(&label, issuer, &secret, algorithm, digits, period)
}

/// Percent-encode `s` for an `otpauth://` URI, escaping everything outside the
/// RFC 3986 unreserved set (`A-Z a-z 0-9 - . _ ~`). The inverse of
/// [`percent_decode`], so an exported label/issuer parses back to the original.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

/// Render a [`TotpEntry`] as an `otpauth://totp/...` provisioning URI.
///
/// The secret is base32-encoded (the provisioning form); the label/issuer are
/// percent-encoded. When an issuer is present the path is `Issuer:Account` AND an
/// `issuer=` query is added (both, per the Key URI convention). `algorithm` is
/// upper-cased (e.g. `SHA1`) as is conventional. The output round-trips through
/// [`parse_otpauth_uri`].
///
/// This is an EXPORT: the returned URI contains the secret IN THE CLEAR. Callers
/// must warn before printing it.
///
/// # Errors
/// - [`CliError::Totp`] if the entry's stored secret is not valid base64.
pub fn entry_to_otpauth_uri(entry: &TotpEntry) -> Result<String, CliError> {
    let secret_b32 = base32_encode(&entry.secret_bytes()?);
    let account = percent_encode(&entry.label);
    let issuer = entry.issuer.as_deref().filter(|s| !s.is_empty());

    let label_path = match issuer {
        Some(iss) => format!("{}:{}", percent_encode(iss), account),
        None => account,
    };

    let mut uri = format!("otpauth://totp/{label_path}?secret={secret_b32}");
    if let Some(iss) = issuer {
        uri.push_str(&format!("&issuer={}", percent_encode(iss)));
    }
    uri.push_str(&format!(
        "&algorithm={}",
        entry.algorithm.to_ascii_uppercase()
    ));
    uri.push_str(&format!("&digits={}", entry.digits));
    uri.push_str(&format!("&period={}", entry.period));
    Ok(uri)
}

impl TotpVault {
    /// Find an entry by exact label.
    #[must_use]
    pub fn find(&self, label: &str) -> Option<&TotpEntry> {
        self.entries.iter().find(|e| e.label == label)
    }

    /// Add `entry`, rejecting a duplicate label.
    ///
    /// # Errors
    /// - [`CliError::Totp`] if an entry with the same label already exists.
    pub fn add(&mut self, entry: TotpEntry) -> Result<(), CliError> {
        if self.find(&entry.label).is_some() {
            return Err(CliError::Totp(format!(
                "an entry labelled {:?} already exists",
                entry.label
            )));
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Remove the entry with `label`, returning it.
    ///
    /// # Errors
    /// - [`CliError::Totp`] if no entry has that label.
    pub fn remove(&mut self, label: &str) -> Result<TotpEntry, CliError> {
        match self.entries.iter().position(|e| e.label == label) {
            Some(i) => Ok(self.entries.remove(i)),
            None => Err(CliError::Totp(format!("no entry labelled {label:?}"))),
        }
    }
}

impl TotpEntry {
    /// Decode this entry's stored (base64) secret into raw key bytes.
    ///
    /// # Errors
    /// - [`CliError::Totp`] if the stored secret is not valid base64.
    pub fn secret_bytes(&self) -> Result<Vec<u8>, CliError> {
        BASE64
            .decode(self.secret.as_bytes())
            .map_err(|e| CliError::Totp(format!("stored secret is not valid base64: {e}")))
    }

    /// The [`OtpAlgorithm`] this entry names.
    ///
    /// # Errors
    /// - [`CliError::Totp`] if the stored algorithm string is unrecognized.
    pub fn otp_algorithm(&self) -> Result<OtpAlgorithm, CliError> {
        totp_algorithm_from_str(&self.algorithm)
    }

    /// Generate the current code for this entry at `unix_time`, returning the
    /// zero-padded code string and the whole seconds remaining in the current
    /// period.
    ///
    /// The caller (native binary) supplies `unix_time` from the system clock;
    /// `sigil-core` reads no clock. Uses `sigil_core::totp` + `format_code`.
    ///
    /// # Errors
    /// - [`CliError::Totp`] on a bad stored secret/algorithm, or if the core
    ///   rejects the parameters.
    pub fn code_at(&self, unix_time: u64) -> Result<(String, u64), CliError> {
        let secret = self.secret_bytes()?;
        let algorithm = self.otp_algorithm()?;
        let code = sigil_core::totp(&secret, unix_time, self.period, 0, self.digits, algorithm)
            .map_err(|e| CliError::Totp(format!("could not compute code: {e}")))?;
        let formatted = sigil_core::format_code(code, self.digits);
        let remaining = u64::from(self.period) - (unix_time % u64::from(self.period));
        Ok((formatted, remaining))
    }
}

/// Serialize a [`TotpVault`] to JSON and seal it under `password` into a
/// `SIGILcli` container (the same format as [`seal_to_container`]).
///
/// # Errors
/// - [`CliError::Totp`] if the vault cannot be serialized.
/// - [`CliError::Rng`] / [`CliError::Record`] from the underlying seal.
pub fn seal_vault(
    password: &[u8],
    vault: &TotpVault,
    params: Argon2Params,
) -> Result<Vec<u8>, CliError> {
    let json = serde_json::to_vec(vault)
        .map_err(|e| CliError::Totp(format!("could not serialize vault: {e}")))?;
    seal_to_container(password, &json, params)
}

/// Open a `SIGILcli` container produced by [`seal_vault`] under `password` and
/// parse the inner JSON into a [`TotpVault`].
///
/// # Errors
/// - [`CliError::Record`] on a wrong password or tampered container (no plaintext
///   is leaked).
/// - [`CliError::Totp`] if the decrypted bytes are not a valid vault, or the
///   inner version is unsupported.
pub fn open_vault(password: &[u8], container: &[u8]) -> Result<TotpVault, CliError> {
    let plaintext = open_container(password, container)?;
    let vault: TotpVault = serde_json::from_slice(&plaintext)
        .map_err(|e| CliError::Totp(format!("decrypted vault is not valid JSON: {e}")))?;
    if vault.version != TOTP_VAULT_VERSION {
        return Err(CliError::Totp(format!(
            "unsupported vault version {}: expected {TOTP_VAULT_VERSION}",
            vault.version
        )));
    }
    Ok(vault)
}

// ---------------------------------------------------------------------------
// DEVICE-TO-DEVICE VAULT SHARING (Phase 46) — the first LOAD-BEARING use of the
// post-quantum hybrid primitives.
//
// THE KEY HIERARCHY, and why it is shaped this way:
//
//   human password ──Argon2id──> (seals a PERSONAL vault; NEVER shared, never
//                                 wrapped, never leaves this machine)
//
//   vault key = 32 CSPRNG bytes ──> seals a SHARED vault (same `SIGILcli`
//                                    container; the container takes arbitrary
//                                    password BYTES, so a random key drops in
//                                    with NO format change)
//        │
//        └── wrapped per recipient device with `hybrid_seal_to_container`
//            (X25519 + ML-KEM-768 -> XChaCha20-Poly1305) -> an OPAQUE envelope
//            the server relays and cannot read.
//
// The human password is NEVER shared and NEVER wrapped. Sharing a password
// would hand every recipient the ability to open every OTHER vault sealed under
// it, and would make revocation mean "change your password everywhere". A
// per-vault random key is revocable in principle (re-key + re-share) and leaks
// nothing about the user.
//
// WHAT THE SERVER SEES: a device's PUBLIC hybrid key, device IDs, a vault ID,
// and ciphertext. It cannot derive the vault key — that needs the recipient's
// hybrid SECRET identity, which never leaves the device.
//
// HONEST SCOPE: pre-audit, UNAUDITED, DEV/localhost/plain-HTTP. The hybrid
// construction is a CUSTOM KEM-then-AEAD, NOT RFC 9180 HPKE; the system is NOT
// "post-quantum secure". Revoking a device stops FUTURE access — it cannot make
// a device forget a vault key it already accepted (that needs a re-key and a
// re-share). There is no key rotation schedule, no recovery, and no forward
// secrecy for an envelope already delivered.
// ---------------------------------------------------------------------------

/// Byte length of a vault key: 32 bytes of OS CSPRNG output. It is used as the
/// "password" bytes of a [`SIGILcli` container](seal_to_container) — the
/// container takes arbitrary bytes, so a random key needs NO format change.
pub const VAULT_KEY_LEN: usize = 32;

/// The version byte written into every local vault keyring file.
pub const VAULT_KEYRING_VERSION: u8 = 1;

/// Default file name of the LOCAL vault keyring (inside `$HOME/.sigil`).
pub const VAULT_KEYRING_FILE: &str = "vault-keys.json";

/// The LOCAL vault keyring: this device's map of `vault id -> vault key`.
///
/// On disk it is JSON `{"version":1,"keys":{"<vaultID>":"<b64 32 bytes>"}}`,
/// written with mode `0600`. It holds SECRET key material: every key in it can
/// open the corresponding shared vault. It is per-device, DEV-ONLY, and is NEVER
/// synced or uploaded — only individually WRAPPED keys ever leave the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultKeyring {
    /// Keyring format version. Always [`VAULT_KEYRING_VERSION`].
    pub version: u8,
    /// `vault id -> standard-base64 of the 32-byte vault key`. SECRET material.
    #[serde(default)]
    pub keys: std::collections::BTreeMap<String, String>,
}

impl Default for VaultKeyring {
    fn default() -> Self {
        VaultKeyring {
            version: VAULT_KEYRING_VERSION,
            keys: std::collections::BTreeMap::new(),
        }
    }
}

/// Draw a fresh 32-byte vault key from the OS CSPRNG.
///
/// # Errors
/// - [`CliError::Rng`] if the OS RNG fails.
pub fn generate_vault_key() -> Result<[u8; VAULT_KEY_LEN], CliError> {
    let mut key = [0u8; VAULT_KEY_LEN];
    fill_random(&mut key)?;
    Ok(key)
}

/// A short, NON-REVERSIBLE fingerprint of a vault key: the first 16 hex
/// characters of its SHA-256.
///
/// This exists so two devices can prove they hold the SAME key without either
/// of them ever printing it. Printing the key itself is never done anywhere in
/// this crate.
pub fn vault_key_fingerprint(key: &[u8; VAULT_KEY_LEN]) -> String {
    use sha2::Digest as _;
    let digest = sha2::Sha256::digest(key);
    let mut out = String::with_capacity(16);
    for b in digest.iter().take(8) {
        out.push(char::from_digit((b >> 4) as u32, 16).expect("nibble < 16"));
        out.push(char::from_digit((b & 0x0f) as u32, 16).expect("nibble < 16"));
    }
    out
}

/// Read the local vault keyring at `path`. A MISSING file is not an error — it
/// yields an empty keyring, so the first `vault rekey`/`vault accept` creates it.
///
/// # Errors
/// - [`CliError::Sharing`] on an IO error, malformed JSON, or an unsupported
///   version.
pub fn load_keyring(path: &std::path::Path) -> Result<VaultKeyring, CliError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(VaultKeyring::default()),
        Err(e) => return Err(CliError::Sharing(format!("could not read keyring: {e}"))),
    };
    let kr: VaultKeyring = serde_json::from_str(&text)
        .map_err(|e| CliError::Sharing(format!("keyring is not valid JSON: {e}")))?;
    if kr.version != VAULT_KEYRING_VERSION {
        return Err(CliError::Sharing(format!(
            "unsupported keyring version {}: expected {VAULT_KEYRING_VERSION}",
            kr.version
        )));
    }
    Ok(kr)
}

/// Write the vault keyring to `path` with mode `0600`, creating the parent
/// directory `0700` if needed. It holds secret key material, so it is created
/// `0600` up front (never briefly world-readable) and re-chmod'd afterwards in
/// case the file pre-existed with looser permissions.
///
/// # Errors
/// - [`CliError::Sharing`] on a serialize, directory, write, or chmod failure.
pub fn save_keyring(path: &std::path::Path, keyring: &VaultKeyring) -> Result<(), CliError> {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| CliError::Sharing(format!("could not create keyring dir: {e}")))?;
        }
    }
    let json = serde_json::to_string_pretty(keyring)
        .map_err(|e| CliError::Sharing(format!("could not serialize keyring: {e}")))?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| CliError::Sharing(format!("could not create keyring: {e}")))?;
    f.write_all(json.as_bytes())
        .map_err(|e| CliError::Sharing(format!("could not write keyring: {e}")))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| CliError::Sharing(format!("could not set keyring permissions: {e}")))
}

/// Look up one vault key in the keyring at `path`. `Ok(None)` means this device
/// holds no key for that vault (it is a password vault, or has not accepted a
/// share yet).
///
/// # Errors
/// - [`CliError::Sharing`] on a keyring read failure, or a stored key that is not
///   base64 of exactly [`VAULT_KEY_LEN`] bytes.
pub fn keyring_get(
    path: &std::path::Path,
    vault: &str,
) -> Result<Option<[u8; VAULT_KEY_LEN]>, CliError> {
    let kr = load_keyring(path)?;
    let Some(encoded) = kr.keys.get(vault) else {
        return Ok(None);
    };
    let raw = BASE64
        .decode(encoded.as_bytes())
        .map_err(|e| CliError::Sharing(format!("vault key for {vault:?} is not base64: {e}")))?;
    let key: [u8; VAULT_KEY_LEN] = raw.try_into().map_err(|v: Vec<u8>| {
        CliError::Sharing(format!(
            "vault key for {vault:?} must be {VAULT_KEY_LEN} bytes, got {}",
            v.len()
        ))
    })?;
    Ok(Some(key))
}

/// Record (or replace) one vault key in the keyring at `path`, rewriting the
/// file `0600`.
///
/// # Errors
/// - [`CliError::Sharing`] on a keyring read/write failure.
pub fn keyring_put(
    path: &std::path::Path,
    vault: &str,
    key: &[u8; VAULT_KEY_LEN],
) -> Result<(), CliError> {
    let mut kr = load_keyring(path)?;
    kr.version = VAULT_KEYRING_VERSION;
    kr.keys.insert(vault.to_string(), BASE64.encode(key));
    save_keyring(path, &kr)
}

// --- Sharing transport: hybrid public keys + the opaque key-envelope relay ---

/// Maximum response size this client will read from a sharing endpoint (1 MiB).
/// A wrapped vault key is ~1.2 KiB; the cap just stops a hostile/broken server
/// from making the client allocate without bound.
const MAX_SHARING_RESPONSE_BYTES: u64 = 1 << 20;

/// Map a `ureq` result into the raw 2xx response BYTES (used by the envelope
/// GET, which returns `application/octet-stream`, not JSON).
///
/// Non-2xx becomes [`CliError::Server`] exactly as [`finish`] does, so callers
/// can distinguish `401` / `403` / `404` / `501` identically.
fn finish_bytes(result: Result<ureq::Response, ureq::Error>) -> Result<Vec<u8>, CliError> {
    use std::io::Read as _;
    match result {
        Ok(resp) => {
            let mut buf = Vec::new();
            resp.into_reader()
                .take(MAX_SHARING_RESPONSE_BYTES)
                .read_to_end(&mut buf)
                .map_err(|e| CliError::Http(e.to_string()))?;
            Ok(buf)
        }
        Err(ureq::Error::Status(status, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            Err(CliError::Server { status, body })
        }
        Err(ureq::Error::Transport(t)) => Err(CliError::Http(t.to_string())),
    }
}

/// The wire shape of a device's hybrid public key on the sharing endpoints. It
/// carries no `version` field (that is a LOCAL identity-file concern), so
/// [`fetch_hybrid_key`] re-attaches [`HYBRID_IDENTITY_VERSION`].
#[derive(Debug, Clone, Deserialize)]
struct HybridKeyWire {
    #[serde(default)]
    x25519_public_key: String,
    #[serde(default)]
    mlkem_encaps_key: String,
}

/// The URL PATH of a device's hybrid-key endpoint. This is exactly the `{PATH}`
/// the server parses from `r.URL.Path`, so it is also what gets signed.
fn hybrid_key_path(device_id: &str) -> String {
    format!("/v1/devices/{device_id}/hybrid-key")
}

/// The URL PATH of a (vault, device) key-envelope mailbox.
fn key_envelope_path(vault: &str, device_id: &str) -> String {
    format!("/v1/vaults/{vault}/keys/{device_id}")
}

/// PUBLISH this device's hybrid PUBLIC identity so other devices can wrap a
/// vault key to it.
///
/// A device may publish only its OWN key: `auth` must be a contract v3 identity
/// whose device ID is `device_id`, or the server answers `403`. Publishing is an
/// UPSERT — re-publishing after regenerating the local hybrid identity is
/// allowed and simply replaces the stored key (it does NOT re-wrap envelopes
/// already deposited for this device).
///
/// Only the PUBLIC half is ever sent. The secret identity never leaves the
/// device.
///
/// # Errors
/// - [`CliError::Server`] on a non-2xx: `401` (unauthenticated / revoked), `403`
///   (publishing into another device's slot), `400` (malformed key), `501` (the
///   device model is off on that server).
pub fn publish_hybrid_key(
    server: &str,
    device_id: &str,
    identity: &HybridPublicIdentity,
    auth: &RequestAuth<'_>,
) -> Result<(), CliError> {
    check_device_id(device_id)?;

    #[derive(Serialize)]
    struct PublishBody<'a> {
        x25519_public_key: &'a str,
        mlkem_encaps_key: &'a str,
    }
    let body = serde_json::to_vec(&PublishBody {
        x25519_public_key: &identity.x25519_public_key,
        mlkem_encaps_key: &identity.mlkem_encaps_key,
    })
    .map_err(|e| CliError::Sharing(format!("could not serialize hybrid key body: {e}")))?;

    let path = hybrid_key_path(device_id);
    let req = ureq::put(&join_url(server, &path)).set("Content-Type", "application/json");
    let req = apply_auth(req, auth, "PUT", &path, "", &body)?;
    finish(req.send_bytes(&body))?;
    Ok(())
}

/// FETCH another device's published hybrid PUBLIC identity, so this device can
/// wrap a vault key to it. Requires an authenticated device (`auth` must sign);
/// the keys themselves are public.
///
/// # Errors
/// - [`CliError::Server`] on a non-2xx: `401` (unauthenticated / revoked), `404`
///   (that device has published no hybrid key), `501` (device model off).
/// - [`CliError::BadResponse`] if the `200` body is not the expected JSON.
pub fn fetch_hybrid_key(
    server: &str,
    device_id: &str,
    auth: &RequestAuth<'_>,
) -> Result<HybridPublicIdentity, CliError> {
    check_device_id(device_id)?;
    let path = hybrid_key_path(device_id);
    let req = ureq::get(&join_url(server, &path));
    let req = apply_auth(req, auth, "GET", &path, "", b"")?;
    let text = finish(req.call())?;

    let wire: HybridKeyWire =
        serde_json::from_str(&text).map_err(|e| CliError::BadResponse(e.to_string()))?;
    Ok(HybridPublicIdentity {
        version: HYBRID_IDENTITY_VERSION,
        x25519_public_key: wire.x25519_public_key,
        mlkem_encaps_key: wire.mlkem_encaps_key,
    })
}

/// DEPOSIT an OPAQUE wrapped vault key addressed to `device_id` for `vault`.
///
/// `envelope` is already-sealed ciphertext (a `SIGILhyb` container from
/// [`hybrid_seal_to_container`]); this function performs NO cryptography — it
/// only moves bytes, exactly like [`push_op_auth`]. The signing device must hold
/// WRITE access to the vault; depositing into an UNCLAIMED vault claims it
/// (trust-on-first-write, the same rule as the first op append).
///
/// # Errors
/// - [`CliError::Server`] on a non-2xx: `401`, `403` (no write access), `404`
///   (unknown recipient), `409` (revoked recipient), `413` (oversized).
pub fn put_key_envelope(
    server: &str,
    vault: &str,
    device_id: &str,
    envelope: &[u8],
    auth: &RequestAuth<'_>,
) -> Result<(), CliError> {
    check_vault(vault)?;
    check_device_id(device_id)?;
    let path = key_envelope_path(vault, device_id);
    let req = ureq::put(&join_url(server, &path)).set("Content-Type", "application/octet-stream");
    let req = apply_auth(req, auth, "PUT", &path, "", envelope)?;
    finish(req.send_bytes(envelope))?;
    Ok(())
}

/// COLLECT the opaque envelope addressed to `device_id` for `vault`, returning
/// the bytes EXACTLY as the sender uploaded them.
///
/// Only the addressee may collect: asking for another device's envelope is a
/// `403`, not a `401` (the request authenticated fine — it is simply not
/// permitted). This function performs no cryptography; the caller unwraps.
///
/// # Errors
/// - [`CliError::Server`] on a non-2xx: `401` (unauthenticated / revoked), `403`
///   (not the addressee, or no read access to the vault), `404` (nothing waiting).
pub fn get_key_envelope(
    server: &str,
    vault: &str,
    device_id: &str,
    auth: &RequestAuth<'_>,
) -> Result<Vec<u8>, CliError> {
    check_vault(vault)?;
    check_device_id(device_id)?;
    let path = key_envelope_path(vault, device_id);
    let req = ureq::get(&join_url(server, &path));
    let req = apply_auth(req, auth, "GET", &path, "", b"")?;
    finish_bytes(req.call())
}

/// WRAP a vault key to a recipient's hybrid public identity, producing the
/// OPAQUE envelope the server relays.
///
/// This is a thin, deliberately explicit wrapper over
/// [`hybrid_seal_to_container`]: fresh ephemeral entropy (an X25519 secret, an
/// ML-KEM-768 coin, and an AEAD nonce) is drawn from the OS CSPRNG on EVERY
/// call, so no two shares of the same key reuse randomness.
///
/// # Errors
/// - [`CliError::Identity`] if the recipient's public identity does not decode.
/// - [`CliError::Rng`] / [`CliError::HybridSeal`] from the underlying seal.
pub fn wrap_vault_key(
    recipient: &HybridPublicIdentity,
    key: &[u8; VAULT_KEY_LEN],
) -> Result<Vec<u8>, CliError> {
    let decoded = recipient.decode()?;
    hybrid_seal_to_container(&decoded, key)
}

/// UNWRAP an envelope with this device's hybrid SECRET identity, recovering the
/// 32-byte vault key.
///
/// The recovered plaintext must be exactly [`VAULT_KEY_LEN`] bytes — anything
/// else is rejected rather than silently used as a key.
///
/// # Errors
/// - [`CliError::Identity`] if the secret identity does not decode.
/// - [`CliError::HybridSeal`] on a wrong identity or tampered envelope (no
///   plaintext is leaked).
/// - [`CliError::Sharing`] if the envelope opened but did not hold a
///   [`VAULT_KEY_LEN`]-byte key.
pub fn unwrap_vault_key(
    identity: &HybridSecretIdentity,
    envelope: &[u8],
) -> Result<[u8; VAULT_KEY_LEN], CliError> {
    let decoded = identity.decode()?;
    let plaintext = hybrid_open_container(&decoded, envelope)?;
    plaintext.try_into().map_err(|v: Vec<u8>| {
        CliError::Sharing(format!(
            "envelope opened but held {} bytes, expected a {VAULT_KEY_LEN}-byte vault key",
            v.len()
        ))
    })
}

// ===========================================================================
// PHASE 50 — KEY VERIFICATION: SAFETY NUMBERS, KEY PINNING, VAULT ROTATION
// ===========================================================================
//
// THE HOLE THIS CLOSES. Until now a client fetched a recipient's hybrid PUBLIC
// key from the server and wrapped a vault key to whatever it got back. A hostile
// or compromised server could substitute its OWN hybrid public key for the
// recipient's, receive the vault key wrapped to itself, unwrap it, and read the
// vault — invisibly. There was also no way to rotate a vault key, so revoking a
// device did not protect content written after the revocation.
//
// THE THREE MITIGATIONS, and honestly what each one is worth:
//
//   1. PINNING (zero user effort, works after first contact). The first time this
//      client sees a device's hybrid public key it PINS it. Every later fetch
//      compares. Unchanged -> proceed. CHANGED -> [`CliError::PinMismatch`], a
//      HARD REFUSAL: no wrap, no upload, no auto-re-pin, ever. This converts a
//      silent substitution into a loud, specific stop. It CANNOT protect the
//      FIRST contact — if the server lies the very first time, the lie is what
//      gets pinned.
//
//   2. SAFETY NUMBER (closes the first-contact window, costs the user a phone
//      call). A short, deterministic, human-readable fingerprint over the FULL
//      hybrid public key material plus the device id. Two people read it to each
//      other over a channel the server does not control; if the digits match, the
//      key is the real one. A PAIRWISE number mixes both devices' digests in a
//      canonical (sorted) order so BOTH sides see the SAME string regardless of
//      who is "first".
//
//   3. ROTATION + RE-WRAP (the remediation revocation was missing). The owner
//      draws a FRESH vault key, re-seals the vault under it, re-wraps it to a
//      chosen set of still-authorized devices, and DELETES the envelopes of every
//      device not in that set. ⚠️ HONEST SCOPE: this protects FUTURE content
//      ONLY. A device that already unwrapped the previous key keeps everything it
//      had already copied — cryptography cannot un-send a secret.
//
// ⭐ MIRRORED — NOT SHARED. Every byte layout and every semantic below is
// duplicated in `sigil-wasm/sharing.mjs` (used by the webapp and the MV3
// extension). The safety-number digest MUST stay byte-identical between the two;
// `sigil-wasm/test/pinning-interop.mjs` is the cross-tool guard, and both sides
// carry the same known-answer test. The desktop app calls THIS code (ADR 0037),
// so there are exactly two implementations, not four.
//
// STILL UNAUDITED, still dev/localhost/plain-HTTP.

// --- safety numbers ---------------------------------------------------------

/// Domain-separation prefix for a SINGLE device's safety-number digest.
///
/// MIRRORED in `sigil-wasm/sharing.mjs` (`SAFETY_NUMBER_PREFIX`). Changing it
/// changes every safety number in existence and MUST be a version bump.
pub const SAFETY_NUMBER_PREFIX: &[u8] = b"sigil-safety-number-v1\n";

/// Domain-separation prefix for the ORDER-INDEPENDENT pairwise safety number.
///
/// MIRRORED in `sigil-wasm/sharing.mjs` (`SAFETY_NUMBER_PAIR_PREFIX`).
pub const SAFETY_NUMBER_PAIR_PREFIX: &[u8] = b"sigil-safety-number-pair-v1\n";

/// How many 5-digit groups a rendered safety number has.
///
/// 6 groups x 5 digits = 30 decimal digits ~= 99.6 bits of the SHA-256 digest —
/// short enough to read aloud, long enough that finding a second key with the
/// same number is not a thing an attacker does.
pub const SAFETY_NUMBER_GROUPS: usize = 6;

/// Bytes of digest consumed per rendered group (5 bytes -> one 5-digit group).
pub const SAFETY_NUMBER_BYTES_PER_GROUP: usize = 5;

/// Length-prefix a field into a hash transcript so no two different inputs can
/// produce the same byte stream (`"ab"+"c"` must not collide with `"a"+"bc"`).
fn absorb_field(h: &mut sha2::Sha256, field: &[u8]) {
    use sha2::Digest as _;
    h.update((field.len() as u32).to_be_bytes());
    h.update(field);
}

/// The raw 32-byte SAFETY DIGEST binding a device id to the FULL hybrid public
/// key material.
///
/// ```text
///   SHA-256( "sigil-safety-number-v1\n"
///          ‖ u32_be(len(device_id))  ‖ device_id
///          ‖ u32_be(32)              ‖ x25519_public_key
///          ‖ u32_be(1184)            ‖ mlkem_encaps_key )
/// ```
///
/// BOTH halves of the hybrid key are covered — a substitution that swapped only
/// the ML-KEM half would still change the number. The device id is bound in too,
/// so a real key relayed under a DIFFERENT device's id does not verify.
///
/// # Errors
/// - [`CliError::Identity`] if the public identity does not decode to the
///   expected lengths.
pub fn hybrid_safety_digest(
    device_id: &str,
    identity: &HybridPublicIdentity,
) -> Result<[u8; 32], CliError> {
    use sha2::Digest as _;
    let keys = identity.decode()?;
    let mut h = sha2::Sha256::new();
    h.update(SAFETY_NUMBER_PREFIX);
    absorb_field(&mut h, device_id.as_bytes());
    absorb_field(&mut h, &keys.x25519_public_key);
    absorb_field(&mut h, &keys.mlkem_encaps_key);
    Ok(h.finalize().into())
}

/// Render a 32-byte digest as human-comparable digit groups:
/// `"12345 67890 13579 24680 11223 44556"`.
///
/// Each group is 5 digest bytes read BIG-ENDIAN, reduced mod 100000 and
/// zero-padded to 5 digits. MIRRORED in `sigil-wasm/sharing.mjs`
/// (`renderSafetyNumber`).
pub fn render_safety_number(digest: &[u8; 32]) -> String {
    let mut groups = Vec::with_capacity(SAFETY_NUMBER_GROUPS);
    for g in 0..SAFETY_NUMBER_GROUPS {
        let mut acc: u64 = 0;
        for i in 0..SAFETY_NUMBER_BYTES_PER_GROUP {
            acc = (acc << 8) | u64::from(digest[g * SAFETY_NUMBER_BYTES_PER_GROUP + i]);
        }
        groups.push(format!("{:05}", acc % 100_000));
    }
    groups.join(" ")
}

/// The SAFETY NUMBER of ONE device's hybrid public key — what a user reads aloud
/// to verify a key BEFORE first use.
///
/// # Errors
/// - [`CliError::Identity`] if the public identity does not decode.
pub fn hybrid_safety_number(
    device_id: &str,
    identity: &HybridPublicIdentity,
) -> Result<String, CliError> {
    Ok(render_safety_number(&hybrid_safety_digest(
        device_id, identity,
    )?))
}

/// The PAIRWISE safety number for two devices — ORDER-INDEPENDENT, so both
/// people see the SAME digits no matter who calls whom.
///
/// ```text
///   (lo, hi) = the two per-device digests sorted BYTEWISE ascending
///   SHA-256( "sigil-safety-number-pair-v1\n" ‖ lo ‖ hi )  -> rendered
/// ```
///
/// Sorting is what makes it symmetric: `pair(a, b) == pair(b, a)` byte for byte.
///
/// # Errors
/// - [`CliError::Identity`] if either public identity does not decode.
pub fn pairwise_safety_number(
    device_a: &str,
    identity_a: &HybridPublicIdentity,
    device_b: &str,
    identity_b: &HybridPublicIdentity,
) -> Result<String, CliError> {
    use sha2::Digest as _;
    let da = hybrid_safety_digest(device_a, identity_a)?;
    let db = hybrid_safety_digest(device_b, identity_b)?;
    let (lo, hi) = if da <= db { (da, db) } else { (db, da) };
    let mut h = sha2::Sha256::new();
    h.update(SAFETY_NUMBER_PAIR_PREFIX);
    h.update(lo);
    h.update(hi);
    let digest: [u8; 32] = h.finalize().into();
    Ok(render_safety_number(&digest))
}

// --- the pin store ----------------------------------------------------------

/// The version byte written into every local hybrid-key pin store.
pub const HYBRID_PIN_STORE_VERSION: u8 = 1;

/// Default file name of the LOCAL pin store (inside `$HOME/.sigil`).
///
/// It holds only PUBLIC key material, but it is still security-critical LOCAL
/// state — an attacker who can rewrite it can silence the alarm — so it is
/// written `0600` in the `0700` state dir like everything else.
pub const HYBRID_PIN_FILE: &str = "hybrid-pins.json";

/// One pinned hybrid public key: what this client saw the FIRST time (or the
/// last time a human deliberately re-pinned).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridKeyPin {
    /// The device whose key this is.
    pub device_id: String,
    /// std-base64 of the pinned raw 32-byte X25519 public key.
    pub x25519_public_key: String,
    /// std-base64 of the pinned raw 1184-byte ML-KEM-768 encapsulation key.
    pub mlkem_encaps_key: String,
    /// The rendered safety number of the pinned key, cached so a mismatch can be
    /// reported without re-deriving.
    pub safety_number: String,
    /// Unix seconds at which this pin was recorded.
    pub pinned_at: u64,
    /// How many times a human has deliberately RE-pinned this device. `0` means
    /// "still the key we saw first". A non-zero value is worth showing a user.
    #[serde(default)]
    pub repins: u32,
}

/// The LOCAL pin store: `device id -> the hybrid public key we trust for it`.
///
/// On disk it is JSON `{"version":1,"pins":{...}}` with mode `0600`. It is
/// per-device LOCAL state and is NEVER uploaded — the whole point is that it is
/// the one copy of the truth the server cannot rewrite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridPinStore {
    /// Pin-store format version. Always [`HYBRID_PIN_STORE_VERSION`].
    pub version: u8,
    /// `device id -> pin`.
    #[serde(default)]
    pub pins: std::collections::BTreeMap<String, HybridKeyPin>,
}

impl Default for HybridPinStore {
    fn default() -> Self {
        HybridPinStore {
            version: HYBRID_PIN_STORE_VERSION,
            pins: std::collections::BTreeMap::new(),
        }
    }
}

/// What happened when a fetched key was checked against the pin store.
///
/// There is deliberately NO "changed but accepted" variant: a change is
/// [`CliError::PinMismatch`], never an outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinStatus {
    /// This device had never been seen; its key was just pinned (TOFU).
    FirstSight,
    /// The presented key is byte-identical to the pinned one.
    Match,
    /// A human deliberately replaced the pin via [`repin_hybrid_key`].
    Repinned,
}

impl PinStatus {
    /// A short word for logs and CLI output.
    pub fn label(&self) -> &'static str {
        match self {
            PinStatus::FirstSight => "first-sight (pinned now)",
            PinStatus::Match => "matches the pinned key",
            PinStatus::Repinned => "RE-PINNED by explicit request",
        }
    }
}

/// Read the local pin store at `path`. A MISSING file is not an error — it
/// yields an empty store, so the first fetch pins.
///
/// # Errors
/// - [`CliError::Sharing`] on an IO error, malformed JSON, or an unsupported
///   version.
pub fn load_pins(path: &std::path::Path) -> Result<HybridPinStore, CliError> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HybridPinStore::default()),
        Err(e) => return Err(CliError::Sharing(format!("could not read pin store: {e}"))),
    };
    let store: HybridPinStore = serde_json::from_str(&text)
        .map_err(|e| CliError::Sharing(format!("pin store is not valid JSON: {e}")))?;
    if store.version != HYBRID_PIN_STORE_VERSION {
        return Err(CliError::Sharing(format!(
            "unsupported pin store version {}: expected {HYBRID_PIN_STORE_VERSION}",
            store.version
        )));
    }
    Ok(store)
}

/// Write the pin store to `path` with mode `0600`, creating the parent directory
/// `0700` if needed.
///
/// # Errors
/// - [`CliError::Sharing`] on a serialize, directory, write, or chmod failure.
pub fn save_pins(path: &std::path::Path, store: &HybridPinStore) -> Result<(), CliError> {
    let json = serde_json::to_string_pretty(store)
        .map_err(|e| CliError::Sharing(format!("could not serialize pin store: {e}")))?;
    write_secret_file(path, json.as_bytes())
        .map_err(|e| CliError::Sharing(format!("could not write pin store: {e}")))
}

/// Write `bytes` to `path` with mode `0600`, creating the parent directory
/// `0700` if needed. Created `0600` UP FRONT so the file is never briefly
/// world-readable, and re-chmod'd in case it pre-existed with looser modes.
fn write_secret_file(path: &std::path::Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)?;
        }
    }
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

/// Build the pin record for a key as it stands right now.
fn make_pin(
    device_id: &str,
    identity: &HybridPublicIdentity,
    repins: u32,
) -> Result<HybridKeyPin, CliError> {
    Ok(HybridKeyPin {
        device_id: device_id.to_string(),
        x25519_public_key: identity.x25519_public_key.clone(),
        mlkem_encaps_key: identity.mlkem_encaps_key.clone(),
        safety_number: hybrid_safety_number(device_id, identity)?,
        pinned_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        repins,
    })
}

/// ⭐ THE CHOKE POINT. Compare a freshly-fetched hybrid public key against the
/// pin store and pin it on first sight.
///
///   * device not in the store -> PIN IT, return [`PinStatus::FirstSight`];
///   * pinned key is byte-identical -> return [`PinStatus::Match`], store
///     untouched;
///   * pinned key DIFFERS -> return [`CliError::PinMismatch`] and change
///     NOTHING. There is no flag on this function that makes it accept a changed
///     key: re-pinning is a separate, deliberate operation
///     ([`repin_hybrid_key`]).
///
/// Comparison is over the DECODED raw key bytes, not the base64 text, so a
/// server that re-encodes the same key cannot trip a false alarm.
///
/// # Errors
/// - [`CliError::PinMismatch`] when the key changed (the alarm).
/// - [`CliError::Identity`] if either identity does not decode.
/// - [`CliError::Sharing`] on a pin-store IO failure.
pub fn check_and_pin(
    pins_path: &std::path::Path,
    device_id: &str,
    identity: &HybridPublicIdentity,
) -> Result<PinStatus, CliError> {
    let presented = identity.decode()?;
    let mut store = load_pins(pins_path)?;

    if let Some(existing) = store.pins.get(device_id) {
        let pinned = HybridPublicIdentity {
            version: HYBRID_IDENTITY_VERSION,
            x25519_public_key: existing.x25519_public_key.clone(),
            mlkem_encaps_key: existing.mlkem_encaps_key.clone(),
        }
        .decode()?;
        if pinned.x25519_public_key == presented.x25519_public_key
            && pinned.mlkem_encaps_key == presented.mlkem_encaps_key
        {
            return Ok(PinStatus::Match);
        }
        return Err(CliError::PinMismatch {
            device_id: device_id.to_string(),
            pinned_safety_number: existing.safety_number.clone(),
            presented_safety_number: hybrid_safety_number(device_id, identity)?,
        });
    }

    store.version = HYBRID_PIN_STORE_VERSION;
    store
        .pins
        .insert(device_id.to_string(), make_pin(device_id, identity, 0)?);
    save_pins(pins_path, &store)?;
    Ok(PinStatus::FirstSight)
}

/// ⚠️ EXPLICIT, DELIBERATE re-pin — the ONLY way a changed key is ever accepted.
///
/// Overwrites the stored pin for `device_id` with `identity` and bumps its
/// `repins` counter. NOTHING calls this automatically; it exists so a human who
/// has just verified the NEW safety number out of band can tell the client "yes,
/// that device really did re-enrol".
///
/// Returns `(previous safety number or None, new safety number)`.
///
/// # Errors
/// - [`CliError::Identity`] / [`CliError::Sharing`] as above.
pub fn repin_hybrid_key(
    pins_path: &std::path::Path,
    device_id: &str,
    identity: &HybridPublicIdentity,
) -> Result<(Option<String>, String), CliError> {
    let mut store = load_pins(pins_path)?;
    let previous = store.pins.get(device_id).cloned();
    let repins = previous.as_ref().map(|p| p.repins + 1).unwrap_or(0);
    let pin = make_pin(device_id, identity, repins)?;
    let new_number = pin.safety_number.clone();
    store.version = HYBRID_PIN_STORE_VERSION;
    store.pins.insert(device_id.to_string(), pin);
    save_pins(pins_path, &store)?;
    Ok((previous.map(|p| p.safety_number), new_number))
}

/// ⭐ FETCH a device's hybrid public key AND enforce the pin in one call.
///
/// This is what every share/rotate path uses instead of the bare
/// [`fetch_hybrid_key`]: a pin store nothing consults is worthless, so the
/// enforcement lives on the same call that gets the key.
///
/// # Errors
/// - [`CliError::PinMismatch`] when the published key changed — the caller MUST
///   NOT proceed, and this function has already made sure nothing was wrapped.
/// - Everything [`fetch_hybrid_key`] can return.
pub fn fetch_hybrid_key_pinned(
    server: &str,
    device_id: &str,
    auth: &RequestAuth<'_>,
    pins_path: &std::path::Path,
) -> Result<(HybridPublicIdentity, PinStatus), CliError> {
    let identity = fetch_hybrid_key(server, device_id, auth)?;
    let status = check_and_pin(pins_path, device_id, &identity)?;
    Ok((identity, status))
}

// --- vault key rotation + re-wrap ------------------------------------------

/// The URL PATH of a vault's envelope COLLECTION (list / rotate support).
fn key_envelopes_path(vault: &str) -> String {
    format!("/v1/vaults/{vault}/keys")
}

/// One recipient currently holding an envelope for a vault, as reported by the
/// server. Metadata ONLY — the blob is never listed.
#[derive(Debug, Clone, Deserialize)]
pub struct EnvelopeRecipient {
    /// The device the envelope is addressed to.
    pub device_id: String,
    /// The device that deposited it.
    #[serde(default)]
    pub sender_device_id: String,
    /// Size of the opaque envelope in bytes.
    #[serde(default)]
    pub size_bytes: usize,
    /// RFC3339 timestamp of the deposit.
    #[serde(default)]
    pub created_at: String,
}

/// LIST which devices currently hold a key envelope for `vault`.
///
/// Requires WRITE on the vault (it is an owner-side operation — the same choke
/// point that authorizes depositing an envelope). Returns METADATA only; the
/// opaque blobs are never returned by this route.
///
/// # Errors
/// - [`CliError::Server`] on a non-2xx (`401`, `403` no write access, `501`).
/// - [`CliError::BadResponse`] if the `200` body is not the expected JSON.
pub fn list_key_envelopes(
    server: &str,
    vault: &str,
    auth: &RequestAuth<'_>,
) -> Result<Vec<EnvelopeRecipient>, CliError> {
    check_vault(vault)?;
    #[derive(Deserialize)]
    struct Wire {
        #[serde(default)]
        recipients: Vec<EnvelopeRecipient>,
    }
    let path = key_envelopes_path(vault);
    let req = ureq::get(&join_url(server, &path));
    let req = apply_auth(req, auth, "GET", &path, "", b"")?;
    let text = finish(req.call())?;
    let wire: Wire =
        serde_json::from_str(&text).map_err(|e| CliError::BadResponse(e.to_string()))?;
    Ok(wire.recipients)
}

/// DELETE the envelope addressed to `device_id` for `vault`, so a device removed
/// from a rotation cannot collect the NEW key.
///
/// Requires WRITE on the vault. Returns `true` if an envelope was removed and
/// `false` if there was nothing there (a `404` is not an error for a rotation —
/// the desired end state is "no envelope", which already holds).
///
/// ⚠️ Deleting an envelope does NOT un-learn a key the device already unwrapped.
/// It only stops it collecting anything NEW.
///
/// # Errors
/// - [`CliError::Server`] on a non-2xx other than `404` (`401`, `403`, `501`).
pub fn delete_key_envelope(
    server: &str,
    vault: &str,
    device_id: &str,
    auth: &RequestAuth<'_>,
) -> Result<bool, CliError> {
    check_vault(vault)?;
    check_device_id(device_id)?;
    let path = key_envelope_path(vault, device_id);
    let req = ureq::delete(&join_url(server, &path));
    let req = apply_auth(req, auth, "DELETE", &path, "", b"")?;
    match finish(req.call()) {
        Ok(_) => Ok(true),
        Err(CliError::Server { status: 404, .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Re-seal an existing `SIGILcli` container under a NEW secret: open it with
/// `old_secret`, seal the exact same plaintext under `new_secret`.
///
/// Container-agnostic on purpose — it re-keys a TOTP vault, a note, or anything
/// else that is a `SIGILcli` container, because it never looks at the plaintext.
///
/// # Errors
/// - Whatever [`open_container`] / [`seal_to_container`] return.
pub fn reseal_container(
    old_secret: &[u8],
    new_secret: &[u8],
    container: &[u8],
    params: Argon2Params,
) -> Result<Vec<u8>, CliError> {
    let plaintext = open_container(old_secret, container)?;
    seal_to_container(new_secret, &plaintext, params)
}

/// What a rotation actually did. Contains fingerprints only — never a key.
#[derive(Debug, Clone)]
pub struct RotationReport {
    /// The vault that was rotated.
    pub vault_id: String,
    /// SHA-256 fingerprint (16 hex) of the key that was RETIRED.
    pub old_key_fingerprint: String,
    /// SHA-256 fingerprint (16 hex) of the NEW key.
    pub new_key_fingerprint: String,
    /// Devices the new key was re-wrapped to, with their pin status.
    pub rewrapped: Vec<(String, PinStatus)>,
    /// Devices whose stale envelope was DELETED from the server.
    pub removed: Vec<String>,
}

/// ⭐ ROTATE a vault key and RE-WRAP it to a chosen set of devices.
///
/// The owner-side remediation that revocation was missing:
///
///   1. read the CURRENT vault key from the local keyring (required);
///   2. fetch + PIN-CHECK **every** recipient's hybrid public key FIRST, so a
///      [`CliError::PinMismatch`] aborts the whole rotation before a single byte
///      of local or server state is touched;
///   3. draw a FRESH 32-byte vault key;
///   4. re-seal the vault FILE under it (mode `0600`, written via a temp file and
///      renamed, so a crash cannot leave a half-written vault);
///   5. record the new key in the local keyring;
///   6. wrap it to each recipient and UPSERT the envelope (replacing the old one);
///   7. DELETE the envelope of every device that holds one but is NOT in
///      `recipients`.
///
/// `recipients` should normally INCLUDE this device, so the owner can still
/// recover its own key from the server. The caller decides — this function wraps
/// to exactly the list it is given.
///
/// ⚠️ WHAT THIS DOES NOT DO. It protects FUTURE content only. A device that
/// already unwrapped the PREVIOUS key still holds that key and whatever it had
/// already read or copied; nothing can retract that. What it does guarantee is
/// that everything sealed AFTER the rotation is unreadable to a device left out
/// of `recipients`.
///
/// # Errors
/// - [`CliError::PinMismatch`] if ANY recipient's key changed (nothing is
///   mutated).
/// - [`CliError::Sharing`] if this vault has no key in the keyring, or on an IO
///   failure.
/// - [`CliError::Server`] / [`CliError::Http`] from the transport.
#[allow(clippy::too_many_arguments)]
pub fn rotate_vault_key(
    server: &str,
    vault_id: &str,
    vault_file: &std::path::Path,
    keyring_path: &std::path::Path,
    pins_path: &std::path::Path,
    recipients: &[String],
    auth: &RequestAuth<'_>,
    params: Argon2Params,
) -> Result<RotationReport, CliError> {
    check_vault(vault_id)?;
    for r in recipients {
        check_device_id(r)?;
    }

    // 1) The key we are retiring. A vault that was never rekeyed has no key here,
    //    and rotating a PASSWORD vault is not a thing — `vault rekey` is.
    let old_key = keyring_get(keyring_path, vault_id)?.ok_or_else(|| {
        CliError::Sharing(format!(
            "no vault key for {vault_id:?} in {}; only a SHARED vault can be rotated — run \
             `sigil vault rekey --vault {vault_id}` first",
            keyring_path.display()
        ))
    })?;
    let container = std::fs::read(vault_file).map_err(|e| {
        CliError::Sharing(format!(
            "could not read vault {}: {e}",
            vault_file.display()
        ))
    })?;

    // 2) PIN-CHECK EVERY RECIPIENT BEFORE MUTATING ANYTHING. If one device's key
    //    was substituted, the whole rotation aborts with the vault untouched —
    //    far better than a half-rotated vault whose key leaked to an attacker.
    let mut resolved: Vec<(String, HybridPublicIdentity, PinStatus)> =
        Vec::with_capacity(recipients.len());
    for device in recipients {
        let (identity, status) = fetch_hybrid_key_pinned(server, device, auth, pins_path)?;
        resolved.push((device.clone(), identity, status));
    }

    // 3-4) Fresh key, re-seal the vault, write it atomically at 0600.
    let new_key = generate_vault_key()?;
    let resealed = reseal_container(&old_key, &new_key, &container, params)?;
    let tmp = vault_file.with_extension("rotate.tmp");
    write_secret_file(&tmp, &resealed)
        .map_err(|e| CliError::Sharing(format!("could not write rotated vault: {e}")))?;
    std::fs::rename(&tmp, vault_file).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        CliError::Sharing(format!(
            "could not replace vault {}: {e}",
            vault_file.display()
        ))
    })?;

    // 5) The local keyring now points at the new key. Do this AFTER the file is
    //    in place: if we crashed between, the keyring would name a key that opens
    //    nothing.
    keyring_put(keyring_path, vault_id, &new_key)?;

    // 6) Re-wrap to every chosen recipient (an UPSERT — the old envelope is
    //    replaced, not appended to).
    let mut rewrapped = Vec::with_capacity(resolved.len());
    for (device, identity, status) in &resolved {
        let envelope = wrap_vault_key(identity, &new_key)?;
        put_key_envelope(server, vault_id, device, &envelope, auth)?;
        rewrapped.push((device.clone(), *status));
    }

    // 7) Remove the stale envelopes of everyone left out.
    let keep: std::collections::BTreeSet<&str> = recipients.iter().map(String::as_str).collect();
    let mut removed = Vec::new();
    for existing in list_key_envelopes(server, vault_id, auth)? {
        if !keep.contains(existing.device_id.as_str())
            && delete_key_envelope(server, vault_id, &existing.device_id, auth)?
        {
            removed.push(existing.device_id);
        }
    }

    Ok(RotationReport {
        vault_id: vault_id.to_string(),
        old_key_fingerprint: vault_key_fingerprint(&old_key),
        new_key_fingerprint: vault_key_fingerprint(&new_key),
        rewrapped,
        removed,
    })
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

    // --- Sync-layer tests against a tiny in-process mock HTTP server ---------
    //
    // These do NOT need sigild. Each test spins a one-shot TCP listener on
    // 127.0.0.1:0, hands the client the captured request and the canned
    // response, and joins the thread to read what the client actually sent.

    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    /// What the mock server captured from the single request it served.
    struct CapturedRequest {
        /// The HTTP request line, e.g. `POST /v1/vaults/v/ops HTTP/1.1`.
        request_line: String,
        /// The request body bytes (read via Content-Length, if any).
        body: Vec<u8>,
        /// All request headers, captured as `(lowercased name, value)` pairs in
        /// the order received, so tests can assert on signature headers.
        headers: Vec<(String, String)>,
    }

    impl CapturedRequest {
        /// Look up a header value by case-insensitive name (the stored names are
        /// already lowercased).
        fn header(&self, name: &str) -> Option<&str> {
            let want = name.to_ascii_lowercase();
            self.headers
                .iter()
                .find(|(k, _)| *k == want)
                .map(|(_, v)| v.as_str())
        }
    }

    /// Spawn a one-shot mock server that accepts exactly one connection, reads
    /// the full request (request line + headers + Content-Length body), then
    /// writes `response` verbatim. Returns the bound `http://127.0.0.1:PORT`
    /// base URL and a join handle yielding the [`CapturedRequest`].
    fn spawn_mock(response: &'static str) -> (String, thread::JoinHandle<CapturedRequest>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local addr");
        let base = format!("http://{addr}");

        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept one connection");

            // Read until we have the full headers (terminated by CRLFCRLF),
            // then read exactly Content-Length more bytes for the body.
            let mut buf = Vec::new();
            let mut tmp = [0u8; 1024];
            let header_end = loop {
                if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4) {
                    break pos;
                }
                let n = stream.read(&mut tmp).expect("read request");
                if n == 0 {
                    break buf.len();
                }
                buf.extend_from_slice(&tmp[..n]);
            };

            let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
            let request_line = head.lines().next().unwrap_or_default().to_string();

            // Capture every header line (after the request line) as
            // (lowercased name, trimmed value) for the signature-header tests.
            let headers: Vec<(String, String)> = head
                .lines()
                .skip(1)
                .filter_map(|line| {
                    let (k, v) = line.split_once(':')?;
                    Some((k.trim().to_ascii_lowercase(), v.trim().to_string()))
                })
                .collect();

            // Parse Content-Length (case-insensitive) to know the body size.
            let content_len = head
                .lines()
                .find_map(|line| {
                    let (k, v) = line.split_once(':')?;
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        v.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);

            let mut body = buf[header_end..].to_vec();
            while body.len() < content_len {
                let n = stream.read(&mut tmp).expect("read body");
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&tmp[..n]);
            }
            body.truncate(content_len);

            stream
                .write_all(response.as_bytes())
                .expect("write response");
            stream.flush().ok();

            CapturedRequest {
                request_line,
                body,
                headers,
            }
        });

        (base, handle)
    }

    #[test]
    fn push_op_posts_body_to_right_path_and_returns_seq() {
        // Body `{"vaultID":"v","seq":7}` is 23 bytes; Content-Length matches.
        let response = "HTTP/1.1 201 Created\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 23\r\n\
             \r\n\
             {\"vaultID\":\"v\",\"seq\":7}";
        let (base, handle) = spawn_mock(response);

        let container = b"\x00\x01\x02opaque-container-bytes";
        let seq = push_op(&base, "v", container, None).expect("push_op ok");
        assert_eq!(seq, 7);

        let req = handle.join().expect("server thread");
        assert_eq!(req.request_line, "POST /v1/vaults/v/ops HTTP/1.1");
        // The exact container bytes must have been sent as the body.
        assert_eq!(req.body, container);
        // No key -> no signature headers.
        assert!(req.header("x-sigil-timestamp").is_none());
        assert!(req.header("x-sigil-nonce").is_none());
        assert!(req.header("x-sigil-signature").is_none());
    }

    #[test]
    fn pull_ops_sends_since_and_decodes_base64_blobs() {
        // Body below is 56 bytes; Content-Length matches.
        let response = "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 56\r\n\
             \r\n\
             {\"vaultID\":\"v\",\"ops\":[{\"seq\":1,\"blob\":\"aGk=\"}],\"next\":1}";
        let (base, handle) = spawn_mock(response);

        let ops = pull_ops(&base, "v", 5, None).expect("pull_ops ok");
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].seq, 1);
        assert_eq!(ops[0].blob, b"hi"); // "aGk=" base64-decodes to "hi"

        let req = handle.join().expect("server thread");
        assert_eq!(req.request_line, "GET /v1/vaults/v/ops?since=5 HTTP/1.1");
        // No key -> no signature headers.
        assert!(req.header("x-sigil-timestamp").is_none());
        assert!(req.header("x-sigil-nonce").is_none());
        assert!(req.header("x-sigil-signature").is_none());
    }

    #[test]
    fn server_500_becomes_cli_error_server() {
        let response = "HTTP/1.1 500 Internal Server Error\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 16\r\n\
             \r\n\
             {\"error\":\"boom\"}";
        let (base, handle) = spawn_mock(response);

        let err = push_op(&base, "v", b"x", None).expect_err("should be a server error");
        match err {
            CliError::Server { status, body } => {
                assert_eq!(status, 500);
                assert!(body.contains("boom"), "body should carry server detail");
            }
            other => panic!("expected CliError::Server, got {other:?}"),
        }
        let _ = handle.join();
    }

    #[test]
    fn bad_vault_is_rejected_before_any_request() {
        // No server is spawned; these must fail purely on validation.
        assert!(matches!(
            push_op("http://127.0.0.1:1", "", b"x", None),
            Err(CliError::BadVault(_))
        ));
        assert!(matches!(
            push_op("http://127.0.0.1:1", "a/b", b"x", None),
            Err(CliError::BadVault(_))
        ));
        assert!(matches!(
            pull_ops("http://127.0.0.1:1", "has space", 0, None),
            Err(CliError::BadVault(_))
        ));
    }

    // --- Pull-cursor tests ---------------------------------------------------
    //
    // Each test makes a unique temp dir under `std::env::temp_dir()` (no deps),
    // operates on a state file inside it, and removes the dir on the way out.

    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    // --- Device-key + op-log signing tests -----------------------------------
    //
    // These exercise the CLIENT side of the `sigil-oplog-auth-v2` contract and
    // close the loop IN-PROCESS: the push/pull tests reconstruct the EXACT
    // message bytes the server would build from the captured request (including
    // the captured X-Sigil-Nonce), then verify the captured `X-Sigil-Signature`
    // against the key's public key with `sigil_core::verify`. If the client signs
    // the wrong bytes, verify fails.

    use sigil_core::verify;

    /// Reconstruct the v2 contract MESSAGE the server builds, exactly as documented
    /// in [`sign_oplog_request`], so a test can verify the captured signature.
    fn rebuild_oplog_message(
        method: &str,
        path: &str,
        query: &str,
        timestamp: &str,
        nonce: &str,
        body: &[u8],
    ) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(b"sigil-oplog-auth-v2\n");
        m.extend_from_slice(method.as_bytes());
        m.push(b'\n');
        m.extend_from_slice(path.as_bytes());
        m.push(b'\n');
        m.extend_from_slice(query.as_bytes());
        m.push(b'\n');
        m.extend_from_slice(timestamp.as_bytes());
        m.push(b'\n');
        m.extend_from_slice(nonce.as_bytes());
        m.push(b'\n');
        m.extend_from_slice(body);
        m
    }

    #[test]
    fn generated_key_public_matches_derivation_and_round_trips() {
        let dir = TempDir::new("keygen");
        let path = dir.path.join("device.key");

        let kf = generate_key().expect("generate");
        assert_eq!(kf.version, KEY_FILE_VERSION);

        // The stored public_key must equal public_key_from_seed(seed).
        let seed_bytes: [u8; SIG_SEED_LEN] = BASE64
            .decode(kf.seed.as_bytes())
            .expect("seed b64")
            .try_into()
            .expect("seed 32");
        let derived = public_key_from_seed(&seed_bytes);
        assert_eq!(BASE64.encode(derived), kf.public_key);

        // Save with 0600, then load back; seed + public must match.
        save_key(&path, &kf).expect("save");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "key file must be 0600");

        let (seed, public) = load_key(&path).expect("load");
        assert_eq!(seed, seed_bytes);
        assert_eq!(public, derived);
    }

    #[test]
    fn load_key_rejects_wrong_length_seed() {
        let dir = TempDir::new("badkey");
        let path = dir.path.join("bad.key");
        // 16-byte seed (not 32) — must be rejected as a Key error.
        let bad = KeyFile {
            version: KEY_FILE_VERSION,
            seed: BASE64.encode([0u8; 16]),
            public_key: BASE64.encode([0u8; SIG_PUBLIC_KEY_LEN]),
            device_id: None,
        };
        let json = serde_json::to_string(&bad).unwrap();
        std::fs::write(&path, json).unwrap();
        assert!(matches!(load_key(&path), Err(CliError::Key(_))));
    }

    #[test]
    fn push_with_key_sets_headers_and_signature_verifies() {
        let kf = generate_key().expect("keygen");
        let seed: [u8; SIG_SEED_LEN] = BASE64
            .decode(kf.seed.as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let public: [u8; SIG_PUBLIC_KEY_LEN] = BASE64
            .decode(kf.public_key.as_bytes())
            .unwrap()
            .try_into()
            .unwrap();

        let container = b"\x00\x01\x02opaque-container-bytes";

        // One signed push against a fresh one-shot mock -> the captured
        // (timestamp, nonce, signature) header triple.
        let do_push = || {
            let response = "HTTP/1.1 201 Created\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: 23\r\n\
                 \r\n\
                 {\"vaultID\":\"v\",\"seq\":7}";
            let (base, handle) = spawn_mock(response);
            let seq = push_op(&base, "v", container, Some(&seed)).expect("push ok");
            assert_eq!(seq, 7);
            let req = handle.join().expect("server thread");
            assert_eq!(req.request_line, "POST /v1/vaults/v/ops HTTP/1.1");
            let ts = req
                .header("x-sigil-timestamp")
                .expect("timestamp header")
                .to_string();
            let nonce = req
                .header("x-sigil-nonce")
                .expect("nonce header")
                .to_string();
            let sig = req
                .header("x-sigil-signature")
                .expect("signature header")
                .to_string();
            (ts, nonce, sig)
        };

        let (ts, nonce, sig_b64) = do_push();

        // The nonce header must be present, non-empty, and decode to >= 16 bytes.
        assert!(!nonce.is_empty(), "nonce header must be non-empty");
        let nonce_bytes = BASE64.decode(nonce.as_bytes()).expect("nonce is base64");
        assert!(
            nonce_bytes.len() >= 16,
            "nonce must decode to >= 16 bytes, got {}",
            nonce_bytes.len()
        );

        // Reconstruct the v2 message: POST, path, EMPTY query, nonce, body=container.
        let msg = rebuild_oplog_message("POST", "/v1/vaults/v/ops", "", &ts, &nonce, container);
        let sig: [u8; sigil_core::SIGNATURE_LEN] = BASE64
            .decode(sig_b64.as_bytes())
            .expect("sig b64")
            .try_into()
            .expect("sig 64");
        verify(&public, &msg, &sig).expect("signature must verify over the contract message");

        // Two successive signed pushes must use DIFFERENT (freshly drawn) nonces.
        let (_, nonce2, _) = do_push();
        assert_ne!(nonce, nonce2, "each request must use a fresh nonce");
    }

    #[test]
    fn pull_with_key_sets_headers_and_signature_verifies() {
        let kf = generate_key().expect("keygen");
        let seed: [u8; SIG_SEED_LEN] = BASE64
            .decode(kf.seed.as_bytes())
            .unwrap()
            .try_into()
            .unwrap();
        let public: [u8; SIG_PUBLIC_KEY_LEN] = BASE64
            .decode(kf.public_key.as_bytes())
            .unwrap()
            .try_into()
            .unwrap();

        // One signed pull against a fresh one-shot mock -> the captured
        // (timestamp, nonce, signature) header triple.
        let do_pull = || {
            let response = "HTTP/1.1 200 OK\r\n\
                 Content-Type: application/json\r\n\
                 Content-Length: 56\r\n\
                 \r\n\
                 {\"vaultID\":\"v\",\"ops\":[{\"seq\":1,\"blob\":\"aGk=\"}],\"next\":1}";
            let (base, handle) = spawn_mock(response);
            let ops = pull_ops(&base, "v", 5, Some(&seed)).expect("pull ok");
            assert_eq!(ops.len(), 1);
            let req = handle.join().expect("server thread");
            assert_eq!(req.request_line, "GET /v1/vaults/v/ops?since=5 HTTP/1.1");
            let ts = req
                .header("x-sigil-timestamp")
                .expect("timestamp header")
                .to_string();
            let nonce = req
                .header("x-sigil-nonce")
                .expect("nonce header")
                .to_string();
            let sig = req
                .header("x-sigil-signature")
                .expect("signature header")
                .to_string();
            (ts, nonce, sig)
        };

        let (ts, nonce, sig_b64) = do_pull();

        // The nonce header must be present, non-empty, and decode to >= 16 bytes.
        assert!(!nonce.is_empty(), "nonce header must be non-empty");
        let nonce_bytes = BASE64.decode(nonce.as_bytes()).expect("nonce is base64");
        assert!(
            nonce_bytes.len() >= 16,
            "nonce must decode to >= 16 bytes, got {}",
            nonce_bytes.len()
        );

        // Reconstruct: GET, path, query "since=5", nonce, EMPTY body.
        let msg = rebuild_oplog_message("GET", "/v1/vaults/v/ops", "since=5", &ts, &nonce, b"");
        let sig: [u8; sigil_core::SIGNATURE_LEN] = BASE64
            .decode(sig_b64.as_bytes())
            .expect("sig b64")
            .try_into()
            .expect("sig 64");
        verify(&public, &msg, &sig).expect("signature must verify over the contract message");

        // Two successive signed pulls must use DIFFERENT (freshly drawn) nonces.
        let (_, nonce2, _) = do_pull();
        assert_ne!(nonce, nonce2, "each request must use a fresh nonce");
    }

    /// A self-cleaning unique temp dir under the OS temp dir (no tempfile dep).
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            // Unique-enough name: pid + a process-local monotonic counter.
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let n = COUNTER.fetch_add(1, Ordering::Relaxed);
            let pid = std::process::id();
            let path = std::env::temp_dir().join(format!("sigil-cli-cursor-{tag}-{pid}-{n}"));
            std::fs::create_dir_all(&path).expect("create temp dir");
            TempDir { path }
        }

        fn state_path(&self) -> PathBuf {
            self.path.join(PULL_STATE_FILE)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn cursor_write_then_read_round_trip() {
        let dir = TempDir::new("round-trip");
        let sp = dir.state_path();
        let key = cursor_key("http://127.0.0.1:8080", "demo");
        write_cursor(&sp, &key, 7).expect("write");
        assert_eq!(read_cursor(&sp, &key).expect("read"), 7);
    }

    #[test]
    fn cursor_missing_file_reads_zero() {
        let dir = TempDir::new("missing-file");
        let sp = dir.state_path();
        // No file written yet.
        assert!(!sp.exists());
        assert_eq!(read_cursor(&sp, "any|key").expect("read"), 0);
    }

    #[test]
    fn cursor_missing_key_reads_zero() {
        let dir = TempDir::new("missing-key");
        let sp = dir.state_path();
        write_cursor(&sp, "present|key", 42).expect("write");
        assert_eq!(read_cursor(&sp, "absent|key").expect("read"), 0);
    }

    #[test]
    fn cursor_two_keys_are_independent() {
        let dir = TempDir::new("two-keys");
        let sp = dir.state_path();
        let a = cursor_key("http://a", "v1");
        let b = cursor_key("http://b", "v2");
        write_cursor(&sp, &a, 3).expect("write a");
        write_cursor(&sp, &b, 9).expect("write b");
        assert_eq!(read_cursor(&sp, &a).expect("read a"), 3);
        assert_eq!(read_cursor(&sp, &b).expect("read b"), 9);
    }

    #[test]
    fn cursor_malformed_state_is_state_error() {
        let dir = TempDir::new("malformed");
        let sp = dir.state_path();
        std::fs::write(&sp, b"{ this is not valid json").expect("write garbage");
        assert!(matches!(read_cursor(&sp, "k"), Err(CliError::State(_))));
        // write_cursor must also refuse to clobber an unparseable file.
        assert!(matches!(write_cursor(&sp, "k", 1), Err(CliError::State(_))));
    }

    #[test]
    fn cursor_write_overwrites_same_key() {
        let dir = TempDir::new("overwrite");
        let sp = dir.state_path();
        let key = cursor_key("http://h", "v");
        write_cursor(&sp, &key, 1).expect("write 1");
        write_cursor(&sp, &key, 5).expect("write 5");
        assert_eq!(read_cursor(&sp, &key).expect("read"), 5);
        // Overwriting is idempotent for the same value.
        write_cursor(&sp, &key, 5).expect("write 5 again");
        assert_eq!(read_cursor(&sp, &key).expect("read"), 5);
    }

    #[test]
    fn cursor_key_combines_server_and_vault() {
        assert_eq!(cursor_key("http://h:8080", "demo"), "http://h:8080|demo");
    }

    // --- Hybrid public-key identity + container tests ------------------------
    //
    // These exercise the public-key path: generate a hybrid identity, encrypt a
    // file TO a recipient's PUBLIC identity, and open it with the matching SECRET
    // identity. No password is involved. They use the REAL but UNAUDITED
    // sigil-core hybrid primitives.

    /// Generate a fresh hybrid identity pair for a test.
    fn sample_hybrid() -> (HybridSecretIdentity, HybridPublicIdentity) {
        generate_hybrid_identity().expect("generate hybrid identity")
    }

    #[test]
    fn hybrid_identity_derivation_and_save_load_round_trip() {
        let (secret, public) = sample_hybrid();
        assert_eq!(secret.version, HYBRID_IDENTITY_VERSION);
        assert_eq!(public.version, HYBRID_IDENTITY_VERSION);

        // The public X25519 key must equal x25519_public_key(secret).
        let x_secret: [u8; X25519_SECRET_KEY_LEN] = BASE64
            .decode(secret.x25519_secret.as_bytes())
            .expect("x25519 secret b64")
            .try_into()
            .expect("x25519 secret 32");
        let derived_pub = x25519_public_key(&x_secret);
        assert_eq!(BASE64.encode(derived_pub), public.x25519_public_key);

        // The public ML-KEM encaps key must equal ek from ml_kem768_keygen(seed),
        // and the decoded secret's decaps key must be the matching dk.
        let seed: [u8; ML_KEM768_KEYGEN_SEED_LEN] = BASE64
            .decode(secret.mlkem_seed.as_bytes())
            .expect("mlkem seed b64")
            .try_into()
            .expect("mlkem seed 64");
        let (ek, dk) = ml_kem768_keygen(&seed);
        assert_eq!(BASE64.encode(ek), public.mlkem_encaps_key);

        // Decoding both identities yields the raw key bytes.
        let sk = secret.decode().expect("decode secret");
        assert_eq!(sk.x25519_secret, x_secret);
        assert_eq!(sk.mlkem_decaps_key, dk);
        let pk = public.decode().expect("decode public");
        assert_eq!(pk.x25519_public_key, derived_pub);
        assert_eq!(pk.mlkem_encaps_key, ek);

        // Save (secret 0600, public shareable), load back, and confirm they match.
        let dir = TempDir::new("hybrid-id");
        let sec_path = dir.path.join("id.key");
        let pub_path = dir.path.join("id.key.pub");
        save_hybrid_secret(&sec_path, &secret).expect("save secret");
        save_hybrid_public(&pub_path, &public).expect("save public");

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&sec_path)
            .expect("stat secret")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "secret identity must be 0600");

        let loaded_secret = load_hybrid_secret(&sec_path).expect("load secret");
        let loaded_public = load_hybrid_public(&pub_path).expect("load public");
        assert_eq!(
            loaded_secret
                .decode()
                .expect("re-decode secret")
                .x25519_secret,
            x_secret
        );
        assert_eq!(
            loaded_public
                .decode()
                .expect("re-decode public")
                .mlkem_encaps_key,
            ek
        );
    }

    #[test]
    fn hybrid_identity_decode_rejects_wrong_length_field() {
        // A 16-byte X25519 secret (not 32) must be rejected as an Identity error.
        let bad = HybridSecretIdentity {
            version: HYBRID_IDENTITY_VERSION,
            x25519_secret: BASE64.encode([0u8; 16]),
            mlkem_seed: BASE64.encode([0u8; ML_KEM768_KEYGEN_SEED_LEN]),
        };
        assert!(matches!(bad.decode(), Err(CliError::Identity(_))));
    }

    #[test]
    fn hybrid_container_seal_open_round_trip() {
        let (secret, public) = sample_hybrid();
        let pk = public.decode().expect("decode public");
        let sk = secret.decode().expect("decode secret");

        let plaintext = b"hybrid-encrypted to a device public identity";
        let container = hybrid_seal_to_container(&pk, plaintext).expect("hybrid seal");

        // Container shape: magic, version, and more than the fixed prefix.
        assert_eq!(&container[..8], HYBRID_MAGIC.as_slice());
        assert_eq!(container[8], HYBRID_FORMAT_VERSION);
        assert!(container.len() > HYBRID_FIXED_PREFIX_LEN);
        // The plaintext must not appear in the clear.
        assert!(!container
            .windows(plaintext.len())
            .any(|w| w == plaintext.as_slice()));

        let opened = hybrid_open_container(&sk, &container).expect("hybrid open");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn hybrid_empty_plaintext_round_trips() {
        let (secret, public) = sample_hybrid();
        let container =
            hybrid_seal_to_container(&public.decode().expect("decode public"), b"").expect("seal");
        let opened = hybrid_open_container(&secret.decode().expect("decode secret"), &container)
            .expect("open");
        assert!(opened.is_empty());
    }

    #[test]
    fn hybrid_wrong_identity_fails_without_leaking_plaintext() {
        let (_secret_a, public_a) = sample_hybrid();
        let (secret_b, _public_b) = sample_hybrid();

        let plaintext = b"addressed to identity A only";
        let container =
            hybrid_seal_to_container(&public_a.decode().expect("decode A pub"), plaintext)
                .expect("seal");

        // Opening with B's UNRELATED secret identity must fail (the X25519 half
        // disagrees, so the AEAD authentication fails).
        let result = hybrid_open_container(&secret_b.decode().expect("decode B sec"), &container);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(!msg
            .as_bytes()
            .windows(plaintext.len())
            .any(|w| w == plaintext));
    }

    #[test]
    fn hybrid_tampered_container_is_rejected() {
        let (secret, public) = sample_hybrid();
        let plaintext = b"tamper-evident hybrid payload contents";
        let mut container =
            hybrid_seal_to_container(&public.decode().expect("decode public"), plaintext)
                .expect("seal");
        // Flip a late byte (deep in the envelope's ciphertext/tag region).
        let last = container.len() - 1;
        container[last] ^= 0x01;
        let result = hybrid_open_container(&secret.decode().expect("decode secret"), &container);
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(!msg
            .as_bytes()
            .windows(plaintext.len())
            .any(|w| w == plaintext));
    }

    #[test]
    fn hybrid_short_and_garbage_containers_are_rejected_without_panic() {
        let (secret, public) = sample_hybrid();
        let sk = secret.decode().expect("decode secret");

        // Empty and too-short buffers hit the length gate, not a panic.
        assert_eq!(
            hybrid_open_container(&sk, &[]),
            Err(CliError::ShortContainer)
        );
        assert_eq!(
            hybrid_open_container(&sk, &[0xFFu8; 16]),
            Err(CliError::ShortContainer)
        );

        // Long enough to pass the length gate but with wrong magic.
        let buf = vec![0x00u8; HYBRID_FIXED_PREFIX_LEN + 8];
        assert_eq!(hybrid_open_container(&sk, &buf), Err(CliError::BadMagic));

        // A valid container with a bumped version byte.
        let mut c =
            hybrid_seal_to_container(&public.decode().expect("decode public"), b"x").expect("seal");
        c[8] = 99;
        assert_eq!(
            hybrid_open_container(&sk, &c),
            Err(CliError::UnsupportedVersion(99))
        );

        // Truncated envelope: header intact, envelope tail dropped. Surfaces as a
        // HybridSeal error (Envelope/Aead), never a panic.
        let c2 = hybrid_seal_to_container(&public.decode().expect("decode public"), b"payload")
            .expect("seal");
        let truncated = &c2[..c2.len() - 4];
        assert!(matches!(
            hybrid_open_container(&sk, truncated),
            Err(CliError::HybridSeal(_))
        ));
    }

    // --- TOTP vault ---------------------------------------------------------

    /// The RFC 6238 SHA-1 secret `"12345678901234567890"` is base32
    /// `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`. Decoding it must recover the ASCII.
    #[test]
    fn base32_decodes_rfc6238_seed() {
        let bytes = base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").expect("decode");
        assert_eq!(bytes, b"12345678901234567890");
        // Case-insensitive + spaces + padding are ignored.
        let spaced = base32_decode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq====").expect("decode");
        assert_eq!(spaced, b"12345678901234567890");
    }

    #[test]
    fn base32_rejects_bad_input() {
        assert!(matches!(base32_decode("!!!!"), Err(CliError::Totp(_))));
        assert!(matches!(base32_decode(""), Err(CliError::Totp(_))));
        // '1', '0', '8', '9' are not in the RFC 4648 base32 alphabet.
        assert!(matches!(base32_decode("01890189"), Err(CliError::Totp(_))));
    }

    /// FIXED-TIME KAT cross-check: an entry built from the RFC 6238 SHA-1 secret,
    /// 8 digits, period 30, generated at unix_time=59 must equal the published
    /// RFC 6238 Appendix B value 94287082. This pins the CLI's algorithm wiring to
    /// the core primitive at a fixed time (the live `sigil totp code` uses the real
    /// clock, so this test is what proves correctness).
    #[test]
    fn entry_code_matches_rfc6238_vector_at_fixed_time() {
        let secret = base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").expect("decode");
        let entry = new_totp_entry("rfc", None, &secret, OtpAlgorithm::Sha1, 8, 30).expect("entry");
        let (code, _remaining) = entry.code_at(59).expect("code");
        assert_eq!(code, "94287082");

        // SHA-256 / SHA-512 vectors at the same time, with their RFC key lengths.
        let s256 = b"12345678901234567890123456789012";
        let e256 = new_totp_entry("s256", None, s256, OtpAlgorithm::Sha256, 8, 30).expect("entry");
        assert_eq!(e256.code_at(59).expect("code").0, "46119246");

        let s512 = b"1234567890123456789012345678901234567890123456789012345678901234";
        let e512 = new_totp_entry("s512", None, s512, OtpAlgorithm::Sha512, 8, 30).expect("entry");
        assert_eq!(e512.code_at(59).expect("code").0, "90693936");
    }

    #[test]
    fn code_at_reports_remaining_seconds() {
        let secret = base32_decode("GEZDGNBVGY3TQOJQ").expect("decode");
        let entry = new_totp_entry("x", None, &secret, OtpAlgorithm::Sha1, 6, 30).expect("entry");
        // At t=59, 59 % 30 == 29, so 30 - 29 == 1 second remains.
        assert_eq!(entry.code_at(59).expect("code").1, 1);
        // At t=60 a fresh window: 30 - 0 == 30.
        assert_eq!(entry.code_at(60).expect("code").1, 30);
    }

    #[test]
    fn otpauth_uri_parses_full_form() {
        let uri = "otpauth://totp/GitHub:alice%40example.com?secret=GEZDGNBVGY3TQOJQ&issuer=GitHub&algorithm=SHA256&digits=8&period=60";
        let e = parse_otpauth_uri(uri).expect("parse");
        assert_eq!(e.label, "alice@example.com");
        assert_eq!(e.issuer.as_deref(), Some("GitHub"));
        assert_eq!(e.algorithm, "sha256");
        assert_eq!(e.digits, 8);
        assert_eq!(e.period, 60);
        // GEZDGNBVGY3TQOJQ (16 base32 chars) decodes to the 10 ASCII bytes "1234567890".
        assert_eq!(e.secret_bytes().unwrap(), b"1234567890");
    }

    #[test]
    fn otpauth_uri_defaults_and_errors() {
        // Minimal URI: default algorithm sha1, digits 6, period 30; issuer from
        // the label prefix.
        let e =
            parse_otpauth_uri("otpauth://totp/Acme:bob?secret=GEZDGNBVGY3TQOJQ").expect("parse");
        assert_eq!(e.label, "bob");
        assert_eq!(e.issuer.as_deref(), Some("Acme"));
        assert_eq!(e.algorithm, "sha1");
        assert_eq!(e.digits, TOTP_DEFAULT_DIGITS);
        assert_eq!(e.period, TOTP_DEFAULT_PERIOD);

        assert!(matches!(
            parse_otpauth_uri("otpauth://totp/x"),
            Err(CliError::Totp(_))
        ));
        assert!(matches!(
            parse_otpauth_uri("https://example.com"),
            Err(CliError::Totp(_))
        ));
        assert!(matches!(
            parse_otpauth_uri("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ"),
            Err(CliError::Totp(_))
        ));
    }

    #[test]
    fn base32_encode_is_inverse_of_decode() {
        for raw in [
            b"1234567890".as_slice(),
            b"Hello!\xde\xad\xbe\xef".as_slice(),
            b"a".as_slice(),
            &[0u8; 20],
        ] {
            let encoded = base32_encode(raw);
            assert_eq!(base32_decode(&encoded).expect("decode"), raw);
        }
        // Matches the documented base32 of the GA example secret.
        assert_eq!(base32_encode(b"Hello!\xde\xad\xbe\xef"), "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn otpauth_export_import_round_trip() {
        let secret = base32_decode("GEZDGNBVGY3TQOJQ").expect("decode");
        let entry = new_totp_entry(
            "alice@example.com",
            Some("GitHub".to_string()),
            &secret,
            OtpAlgorithm::Sha256,
            8,
            60,
        )
        .expect("entry");
        // Export to an otpauth:// URI, then parse it back: the entry must survive.
        let uri = entry_to_otpauth_uri(&entry).expect("export uri");
        assert!(uri.starts_with("otpauth://totp/GitHub:alice%40example.com?"));
        let parsed = parse_otpauth_uri(&uri).expect("re-parse");
        assert_eq!(parsed, entry);

        // An entry with no issuer round-trips too (no `Issuer:` path prefix).
        let no_issuer =
            new_totp_entry("solo", None, &secret, OtpAlgorithm::Sha1, 6, 30).expect("entry");
        let uri2 = entry_to_otpauth_uri(&no_issuer).expect("export uri");
        assert_eq!(parse_otpauth_uri(&uri2).expect("re-parse"), no_issuer);
    }

    #[test]
    fn vault_seal_open_round_trip_and_ops() {
        let mut vault = TotpVault::default();
        let secret = base32_decode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ").expect("decode");
        vault
            .add(
                new_totp_entry(
                    "acct",
                    Some("Svc".to_string()),
                    &secret,
                    OtpAlgorithm::Sha1,
                    6,
                    30,
                )
                .expect("entry"),
            )
            .expect("add");

        // Duplicate label rejected.
        assert!(matches!(
            vault.add(
                new_totp_entry("acct", None, &secret, OtpAlgorithm::Sha1, 6, 30).expect("entry")
            ),
            Err(CliError::Totp(_))
        ));

        let sealed = seal_vault(PASSWORD, &vault, FAST).expect("seal vault");
        // It really is a normal SIGILcli container.
        assert_eq!(&sealed[..8], MAGIC.as_slice());

        let opened = open_vault(PASSWORD, &sealed).expect("open vault");
        assert_eq!(opened, vault);
        assert_eq!(opened.find("acct").unwrap().issuer.as_deref(), Some("Svc"));

        // Wrong password cannot open the vault (and leaks no secret).
        assert!(open_vault(b"nope", &sealed).is_err());

        // Remove works.
        let mut v2 = opened;
        v2.remove("acct").expect("remove");
        assert!(v2.find("acct").is_none());
        assert!(matches!(v2.remove("acct"), Err(CliError::Totp(_))));
    }

    // --- Contract v3 + device enrollment tests --------------------------------
    //
    // These pin the INTEROP CONTRACT: the exact byte layout of both canonical
    // messages is asserted against hand-built expected values, so a drift from
    // sigild's canonicalV3Message / canonicalEnrollMessage fails here rather than
    // silently 401-ing in production. The HTTP tests then close the loop
    // in-process: the mock captures the real request, the test rebuilds the
    // message from what was captured, and verifies the signature with the public
    // key.

    /// Hand-build the v3 message with explicit byte concatenation (deliberately
    /// NOT reusing `canonical_v3_message`, so the test is an independent witness).
    fn handbuilt_v3(
        device_id: &str,
        method: &str,
        path: &str,
        query: &str,
        ts: &str,
        nonce: &str,
        body: &[u8],
    ) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(b"sigil-oplog-auth-v3\n");
        m.extend_from_slice(device_id.as_bytes());
        m.push(b'\n');
        m.extend_from_slice(method.as_bytes());
        m.push(b'\n');
        m.extend_from_slice(path.as_bytes());
        m.push(b'\n');
        m.extend_from_slice(query.as_bytes());
        m.push(b'\n');
        m.extend_from_slice(ts.as_bytes());
        m.push(b'\n');
        m.extend_from_slice(nonce.as_bytes());
        m.push(b'\n');
        m.extend_from_slice(body);
        m
    }

    #[test]
    fn canonical_v3_message_is_byte_exact() {
        let got = canonical_v3_message(
            "dev_abc",
            "POST",
            "/v1/vaults/demo/ops",
            "",
            "1717900000",
            "bm9uY2U=",
            b"BLOB",
        );
        // Literal expected bytes — this IS the wire contract.
        let want: &[u8] =
            b"sigil-oplog-auth-v3\ndev_abc\nPOST\n/v1/vaults/demo/ops\n\n1717900000\nbm9uY2U=\nBLOB";
        assert_eq!(got, want, "v3 canonical message must be byte-exact");

        // Same bytes as an independent hand-build, including a non-empty query
        // and an empty body (the GET shape).
        let get = canonical_v3_message(
            "dev_abc",
            "GET",
            "/v1/vaults/demo/ops",
            "since=5",
            "1717900000",
            "bm9uY2U=",
            b"",
        );
        assert_eq!(
            get,
            handbuilt_v3(
                "dev_abc",
                "GET",
                "/v1/vaults/demo/ops",
                "since=5",
                "1717900000",
                "bm9uY2U=",
                b""
            )
        );
        // The empty query must still contribute its own separator line.
        assert_eq!(
            get,
            b"sigil-oplog-auth-v3\ndev_abc\nGET\n/v1/vaults/demo/ops\nsince=5\n1717900000\nbm9uY2U=\n"
                .to_vec()
        );
    }

    #[test]
    fn v3_domain_differs_from_v2_so_signatures_do_not_cross() {
        let v2 = rebuild_oplog_message("POST", "/p", "", "1", "n", b"b");
        let v3 = canonical_v3_message("dev_x", "POST", "/p", "", "1", "n", b"b");
        assert_ne!(v2, v3);
        assert!(v3.starts_with(b"sigil-oplog-auth-v3\n"));
        assert!(v2.starts_with(b"sigil-oplog-auth-v2\n"));
    }

    #[test]
    fn canonical_enroll_message_is_byte_exact() {
        let got =
            canonical_enroll_message("deadbeef", "1717900000", "bm9uY2U=", "cHVia2V5", "laptop");
        // NOTE: no trailing newline after the label.
        let want: &[u8] =
            b"sigil-device-enroll-v1\ndeadbeef\n1717900000\nbm9uY2U=\ncHVia2V5\nlaptop";
        assert_eq!(got, want, "enrollment challenge must be byte-exact");

        // An EMPTY label still ends the message right after the key separator.
        let empty = canonical_enroll_message("deadbeef", "1", "n", "k", "");
        assert_eq!(
            empty,
            b"sigil-device-enroll-v1\ndeadbeef\n1\nn\nk\n".to_vec()
        );
    }

    #[test]
    fn enroll_token_hash_matches_sha256_known_vectors() {
        // NIST/FIPS 180-4 classic vectors; sigild computes the same lowercase hex.
        assert_eq!(
            enroll_token_hash("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            enroll_token_hash(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // Lowercase hex, fixed 64 chars.
        let h = enroll_token_hash("dev-enroll-token-0123456789");
        assert_eq!(h.len(), 64);
        assert!(h
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    #[test]
    fn identity_round_trips_with_device_id_and_is_0600() {
        let dir = TempDir::new("ident");
        let path = dir.path.join("device.key");

        let mut kf = generate_key().expect("generate");
        assert!(kf.device_id.is_none(), "a fresh key is not enrolled");
        kf.device_id = Some("dev_ABC123".to_string());
        save_key(&path, &kf).expect("save");

        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "identity file must be 0600");

        let id = load_identity(&path).expect("load identity");
        assert_eq!(id.device_id.as_deref(), Some("dev_ABC123"));
        assert_eq!(BASE64.encode(id.seed), kf.seed);
        assert_eq!(BASE64.encode(id.public_key), kf.public_key);

        // The on-disk JSON really carries the id, and the seed is still there.
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(text.contains("\"device_id\""));
    }

    #[test]
    fn old_key_file_without_device_id_still_loads_and_selects_v2() {
        let dir = TempDir::new("legacy");
        let path = dir.path.join("old.key");

        // EXACTLY the JSON an older build wrote: no device_id field at all.
        let kf = generate_key().expect("generate");
        let legacy = format!(
            "{{\n  \"version\": 1,\n  \"seed\": \"{}\",\n  \"public_key\": \"{}\"\n}}",
            kf.seed, kf.public_key
        );
        std::fs::write(&path, legacy).expect("write legacy key file");

        // The legacy loader still works, byte for byte.
        let (seed, public) = load_key(&path).expect("legacy load_key");
        assert_eq!(BASE64.encode(seed), kf.seed);
        assert_eq!(BASE64.encode(public), kf.public_key);

        // And the v3-aware loader reports "not enrolled" -> contract v2.
        let id = load_identity(&path).expect("load identity");
        assert!(id.device_id.is_none());
        assert!(matches!(id.auth(), RequestAuth::V2 { .. }));
        assert_eq!(id.auth().contract(), "v2");
    }

    #[test]
    fn contract_selection_is_driven_by_device_id() {
        let mut kf = generate_key().expect("generate");
        let v2 = kf.decode().expect("decode");
        assert!(matches!(v2.auth(), RequestAuth::V2 { .. }));

        kf.device_id = Some("dev_z".to_string());
        let v3 = kf.decode().expect("decode");
        match v3.auth() {
            RequestAuth::V3 { device_id, .. } => assert_eq!(device_id, "dev_z"),
            other => panic!("expected V3, got {other:?}"),
        }
        assert_eq!(v3.auth().contract(), "v3");

        // An empty device_id is treated as absent (never sent as a real ID).
        kf.device_id = Some(String::new());
        assert!(kf.decode().expect("decode").device_id.is_none());

        // A device_id that could not sit in a URL path segment is rejected.
        kf.device_id = Some("bad/id".to_string());
        assert!(matches!(kf.decode(), Err(CliError::Key(_))));

        // Explicitly: no identity at all -> unsigned.
        assert_eq!(RequestAuth::None.contract(), "unsigned");
    }

    #[test]
    fn push_v3_sets_device_header_and_signature_verifies() {
        let mut kf = generate_key().expect("keygen");
        kf.device_id = Some("dev_TESTDEVICE".to_string());
        let id = kf.decode().expect("decode");

        let container = b"\x00\x01\x02opaque-container-bytes";
        let response = "HTTP/1.1 201 Created\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 23\r\n\
             \r\n\
             {\"vaultID\":\"v\",\"seq\":7}";
        let (base, handle) = spawn_mock(response);
        let seq = push_op_auth(&base, "v", container, &id.auth()).expect("push ok");
        assert_eq!(seq, 7);

        let req = handle.join().expect("server thread");
        assert_eq!(req.request_line, "POST /v1/vaults/v/ops HTTP/1.1");
        assert_eq!(
            req.body, container,
            "the opaque bytes must be sent verbatim"
        );
        assert_eq!(req.header("x-sigil-device"), Some("dev_TESTDEVICE"));

        let ts = req.header("x-sigil-timestamp").expect("ts").to_string();
        let nonce = req.header("x-sigil-nonce").expect("nonce").to_string();
        let sig_b64 = req.header("x-sigil-signature").expect("sig").to_string();

        // Rebuild the v3 message the SERVER would build from this exact request.
        let msg = handbuilt_v3(
            "dev_TESTDEVICE",
            "POST",
            "/v1/vaults/v/ops",
            "",
            &ts,
            &nonce,
            container,
        );
        let sig: [u8; sigil_core::SIGNATURE_LEN] = BASE64
            .decode(sig_b64.as_bytes())
            .expect("sig b64")
            .try_into()
            .expect("sig 64");
        assert!(
            verify(&id.public_key, &msg, &sig).is_ok(),
            "the v3 signature must verify over the canonical message"
        );
        // A v2 reconstruction must NOT verify (domain separation holds).
        let v2msg = rebuild_oplog_message("POST", "/v1/vaults/v/ops", "", &ts, &nonce, container);
        assert!(verify(&id.public_key, &v2msg, &sig).is_err());
    }

    #[test]
    fn pull_v3_signs_query_and_sends_device_header() {
        let mut kf = generate_key().expect("keygen");
        kf.device_id = Some("dev_R".to_string());
        let id = kf.decode().expect("decode");

        let response = "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 56\r\n\
             \r\n\
             {\"vaultID\":\"v\",\"ops\":[{\"seq\":1,\"blob\":\"aGk=\"}],\"next\":1}";
        let (base, handle) = spawn_mock(response);
        let ops = pull_ops_auth(&base, "v", 5, &id.auth()).expect("pull ok");
        assert_eq!(ops.len(), 1);

        let req = handle.join().expect("server thread");
        assert_eq!(req.request_line, "GET /v1/vaults/v/ops?since=5 HTTP/1.1");
        assert_eq!(req.header("x-sigil-device"), Some("dev_R"));

        let ts = req.header("x-sigil-timestamp").expect("ts").to_string();
        let nonce = req.header("x-sigil-nonce").expect("nonce").to_string();
        let sig_b64 = req.header("x-sigil-signature").expect("sig").to_string();
        let msg = handbuilt_v3(
            "dev_R",
            "GET",
            "/v1/vaults/v/ops",
            "since=5",
            &ts,
            &nonce,
            b"",
        );
        let sig: [u8; sigil_core::SIGNATURE_LEN] = BASE64
            .decode(sig_b64.as_bytes())
            .expect("sig b64")
            .try_into()
            .expect("sig 64");
        assert!(verify(&id.public_key, &msg, &sig).is_ok());
    }

    #[test]
    fn unsigned_and_v2_paths_never_send_the_device_header() {
        // REGRESSION GUARD: RequestAuth::None must be byte-identical to the legacy
        // unauthenticated request, and V2 must not leak a v3 header.
        let response = "HTTP/1.1 201 Created\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 23\r\n\
             \r\n\
             {\"vaultID\":\"v\",\"seq\":1}";

        let (base, handle) = spawn_mock(response);
        push_op_auth(&base, "v", b"x", &RequestAuth::None).expect("push ok");
        let req = handle.join().expect("thread");
        assert!(req.header("x-sigil-device").is_none());
        assert!(req.header("x-sigil-signature").is_none());
        assert!(req.header("x-sigil-timestamp").is_none());
        assert!(req.header("x-sigil-nonce").is_none());

        let kf = generate_key().expect("keygen");
        let id = kf.decode().expect("decode");
        let (base, handle) = spawn_mock(response);
        push_op_auth(&base, "v", b"x", &id.auth()).expect("push ok");
        let req = handle.join().expect("thread");
        assert!(
            req.header("x-sigil-device").is_none(),
            "v2 must not send X-Sigil-Device"
        );
        assert!(req.header("x-sigil-signature").is_some());
    }

    #[test]
    fn enroll_posts_proof_of_possession_that_verifies() {
        let kf = generate_key().expect("keygen");
        let id = kf.decode().expect("decode");
        let token = "an-operator-enrollment-token";

        let response = "HTTP/1.1 201 Created\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 94\r\n\
             \r\n\
             {\"device_id\":\"dev_NEW\",\"label\":\"laptop\",\"status\":\"active\",\"created_at\":\"2026-01-01T00:00:00Z\"}";
        let (base, handle) = spawn_mock(response);
        let dev = enroll_device(&base, token, "laptop", &id.public_key, &id.seed).expect("enroll");
        assert_eq!(dev.device_id, "dev_NEW");
        assert_eq!(dev.status, "active");

        let req = handle.join().expect("thread");
        assert_eq!(req.request_line, "POST /v1/devices/enroll HTTP/1.1");
        // The token goes in its own header and is NEVER part of the body.
        assert_eq!(req.header("x-sigil-enroll-token"), Some(token));
        let body = String::from_utf8(req.body.clone()).expect("json body");
        assert!(!body.contains(token), "the token must not be in the body");
        assert!(body.contains(&BASE64.encode(id.public_key)));
        assert!(body.contains("\"label\":\"laptop\""));

        let ts = req.header("x-sigil-timestamp").expect("ts").to_string();
        let nonce = req.header("x-sigil-nonce").expect("nonce").to_string();
        let sig_b64 = req.header("x-sigil-signature").expect("sig").to_string();

        // Rebuild the challenge the SERVER builds: SHA-256(token) hex, the exact
        // header texts, the submitted public key b64, and the label.
        let mut msg = Vec::new();
        msg.extend_from_slice(b"sigil-device-enroll-v1\n");
        msg.extend_from_slice(enroll_token_hash(token).as_bytes());
        msg.push(b'\n');
        msg.extend_from_slice(ts.as_bytes());
        msg.push(b'\n');
        msg.extend_from_slice(nonce.as_bytes());
        msg.push(b'\n');
        msg.extend_from_slice(BASE64.encode(id.public_key).as_bytes());
        msg.push(b'\n');
        msg.extend_from_slice(b"laptop");
        let sig: [u8; sigil_core::SIGNATURE_LEN] = BASE64
            .decode(sig_b64.as_bytes())
            .expect("sig b64")
            .try_into()
            .expect("sig 64");
        assert!(
            verify(&id.public_key, &msg, &sig).is_ok(),
            "enrollment proof of possession must verify against the SUBMITTED key"
        );
    }

    #[test]
    fn grant_signs_its_json_body_under_v3() {
        let mut kf = generate_key().expect("keygen");
        kf.device_id = Some("dev_OWNER".to_string());
        let id = kf.decode().expect("decode");

        let response = "HTTP/1.1 201 Created\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 2\r\n\
             \r\n\
             {}";
        let (base, handle) = spawn_mock(response);
        grant_vault_access(&base, "demo", "dev_B", "read", &id.auth()).expect("grant ok");

        let req = handle.join().expect("thread");
        assert_eq!(req.request_line, "POST /v1/vaults/demo/grants HTTP/1.1");
        assert_eq!(req.header("x-sigil-device"), Some("dev_OWNER"));
        let body = req.body.clone();
        assert_eq!(
            String::from_utf8(body.clone()).unwrap(),
            "{\"device_id\":\"dev_B\",\"permission\":\"read\"}"
        );

        let ts = req.header("x-sigil-timestamp").expect("ts").to_string();
        let nonce = req.header("x-sigil-nonce").expect("nonce").to_string();
        let sig_b64 = req.header("x-sigil-signature").expect("sig").to_string();
        // The signature must cover the EXACT body bytes that were sent.
        let msg = handbuilt_v3(
            "dev_OWNER",
            "POST",
            "/v1/vaults/demo/grants",
            "",
            &ts,
            &nonce,
            &body,
        );
        let sig: [u8; sigil_core::SIGNATURE_LEN] = BASE64
            .decode(sig_b64.as_bytes())
            .expect("sig b64")
            .try_into()
            .expect("sig 64");
        assert!(verify(&id.public_key, &msg, &sig).is_ok());

        // A bad permission never reaches the network.
        assert!(matches!(
            grant_vault_access("http://127.0.0.1:1", "demo", "dev_B", "admin", &id.auth()),
            Err(CliError::Key(_))
        ));
    }

    #[test]
    fn revoke_self_signs_v3_and_admin_path_sends_the_admin_header() {
        let mut kf = generate_key().expect("keygen");
        kf.device_id = Some("dev_SELF".to_string());
        let id = kf.decode().expect("decode");

        let response = "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 43\r\n\
             \r\n\
             {\"device_id\":\"dev_SELF\",\"status\":\"revoked\"}";

        // Self-revocation: v3-signed, no admin header.
        let (base, handle) = spawn_mock(response);
        let dev = revoke_device(&base, "dev_SELF", &id.auth(), None).expect("revoke ok");
        assert_eq!(dev.status, "revoked");
        let req = handle.join().expect("thread");
        assert_eq!(
            req.request_line,
            "POST /v1/devices/dev_SELF/revoke HTTP/1.1"
        );
        assert_eq!(req.header("x-sigil-device"), Some("dev_SELF"));
        assert!(req.header("x-sigil-admin-token").is_none());
        let ts = req.header("x-sigil-timestamp").expect("ts").to_string();
        let nonce = req.header("x-sigil-nonce").expect("nonce").to_string();
        let sig_b64 = req.header("x-sigil-signature").expect("sig").to_string();
        let msg = handbuilt_v3(
            "dev_SELF",
            "POST",
            "/v1/devices/dev_SELF/revoke",
            "",
            &ts,
            &nonce,
            b"",
        );
        let sig: [u8; sigil_core::SIGNATURE_LEN] = BASE64
            .decode(sig_b64.as_bytes())
            .expect("sig b64")
            .try_into()
            .expect("sig 64");
        assert!(verify(&id.public_key, &msg, &sig).is_ok());

        // Operator path: the admin token header is sent, unsigned.
        let (base, handle) = spawn_mock(response);
        revoke_device(&base, "dev_OTHER", &RequestAuth::None, Some("admintok")).expect("revoke ok");
        let req = handle.join().expect("thread");
        assert_eq!(req.header("x-sigil-admin-token"), Some("admintok"));
        assert!(req.header("x-sigil-signature").is_none());

        // A device id that cannot be a path segment never reaches the network.
        assert!(matches!(
            revoke_device(
                "http://127.0.0.1:1",
                "bad id",
                &RequestAuth::None,
                Some("t")
            ),
            Err(CliError::Key(_))
        ));
    }

    #[test]
    fn list_devices_sends_admin_header_and_parses_the_registry() {
        let response = "HTTP/1.1 200 OK\r\n\
             Content-Type: application/json\r\n\
             Content-Length: 122\r\n\
             \r\n\
             {\"devices\":[{\"device_id\":\"dev_A\",\"label\":\"laptop\",\"status\":\"active\",\"created_at\":\"2026-01-01T00:00:00Z\",\"revoked_at\":\"\"}]}";
        let (base, handle) = spawn_mock(response);
        let devices = list_devices(&base, "admintok").expect("list ok");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device_id, "dev_A");
        assert_eq!(devices[0].status, "active");

        let req = handle.join().expect("thread");
        assert_eq!(req.request_line, "GET /v1/devices HTTP/1.1");
        assert_eq!(req.header("x-sigil-admin-token"), Some("admintok"));
    }

    // --- Vault sharing: keyring + wrap/unwrap (Phase 46) --------------------

    /// A unique temp path for one test, cleaned up by the caller.
    fn temp_path(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("sigil-share-{tag}-{}-{nanos}", std::process::id()))
    }

    #[test]
    fn vault_key_is_32_random_bytes_and_differs_per_call() {
        let a = generate_vault_key().expect("key a");
        let b = generate_vault_key().expect("key b");
        assert_eq!(a.len(), VAULT_KEY_LEN);
        assert_ne!(a, b, "two vault keys must not be identical");
    }

    #[test]
    fn keyring_round_trips_and_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_path("keyring");
        let path = dir.join("vault-keys.json");

        assert!(keyring_get(&path, "demo")
            .expect("missing keyring is empty")
            .is_none());

        let key = generate_vault_key().expect("key");
        keyring_put(&path, "demo", &key).expect("put");
        let got = keyring_get(&path, "demo").expect("get").expect("present");
        assert_eq!(got, key);

        // A second vault does not disturb the first.
        let key2 = generate_vault_key().expect("key2");
        keyring_put(&path, "other", &key2).expect("put 2");
        assert_eq!(
            keyring_get(&path, "demo").expect("get").expect("present"),
            key
        );
        assert_eq!(
            keyring_get(&path, "other").expect("get").expect("present"),
            key2
        );

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the keyring holds vault keys and must be 0600");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_vault_key_seals_a_vault_exactly_like_a_password() {
        // The point of the whole design: the SIGILcli container takes arbitrary
        // password BYTES, so a random 32-byte vault key works with NO format
        // change and produces a container the existing opener reads.
        let key = generate_vault_key().expect("key");
        let mut vault = TotpVault::default();
        vault
            .add(
                new_totp_entry("work", None, b"0123456789", OtpAlgorithm::Sha1, 6, 30)
                    .expect("entry"),
            )
            .expect("add");

        let sealed = seal_vault(&key, &vault, FAST).expect("seal under vault key");
        assert_eq!(&sealed[..8], MAGIC.as_slice(), "still a SIGILcli container");

        let opened = open_vault(&key, &sealed).expect("open under vault key");
        assert_eq!(opened.entries.len(), 1);
        assert_eq!(opened.entries[0].label, "work");

        // A different key does not open it, and leaks no plaintext.
        let other = generate_vault_key().expect("other");
        assert!(open_vault(&other, &sealed).is_err());
    }

    #[test]
    fn wrap_unwrap_vault_key_round_trips_and_rejects_the_wrong_device() {
        let (b_secret, b_public) = generate_hybrid_identity().expect("B identity");
        let (c_secret, _c_public) = generate_hybrid_identity().expect("C identity");
        let key = generate_vault_key().expect("key");

        let envelope = wrap_vault_key(&b_public, &key).expect("wrap to B");
        // The envelope is an opaque SIGILhyb container that does NOT contain the
        // key in the clear.
        assert_eq!(&envelope[..8], HYBRID_MAGIC.as_slice());
        assert!(
            !envelope.windows(VAULT_KEY_LEN).any(|w| w == key),
            "the wrapped envelope must not contain the vault key in the clear"
        );

        let recovered = unwrap_vault_key(&b_secret, &envelope).expect("B unwraps");
        assert_eq!(recovered, key);

        // A different device cannot open it.
        assert!(unwrap_vault_key(&c_secret, &envelope).is_err());

        // Two wraps of the SAME key differ (fresh ephemeral entropy per call).
        let envelope2 = wrap_vault_key(&b_public, &key).expect("wrap again");
        assert_ne!(
            envelope, envelope2,
            "each wrap must use fresh ephemeral entropy"
        );
        assert_eq!(
            unwrap_vault_key(&b_secret, &envelope2).expect("unwrap 2"),
            key
        );
    }

    #[test]
    fn unwrap_rejects_a_payload_that_is_not_a_vault_key() {
        let (secret, public) = generate_hybrid_identity().expect("identity");
        let decoded = public.decode().expect("decode");
        let not_a_key = hybrid_seal_to_container(&decoded, b"only nine").expect("seal");
        assert!(matches!(
            unwrap_vault_key(&secret, &not_a_key),
            Err(CliError::Sharing(_))
        ));
    }

    #[test]
    fn vault_key_fingerprint_is_stable_short_and_not_the_key() {
        let key = generate_vault_key().expect("key");
        let fp = vault_key_fingerprint(&key);
        assert_eq!(fp.len(), 16);
        assert_eq!(
            fp,
            vault_key_fingerprint(&key),
            "fingerprint must be stable"
        );
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(
            fp,
            BASE64.encode(key),
            "the fingerprint must not be the key"
        );
        assert_ne!(
            vault_key_fingerprint(&generate_vault_key().expect("k2")),
            fp
        );
    }

    // -----------------------------------------------------------------------
    // Phase 50 — safety numbers, key pinning, rotation.
    // -----------------------------------------------------------------------

    /// ⭐ KNOWN ANSWER — the safety number of `kat_identity()` under device id
    /// `"dev_KAT"`. This exact string is hardcoded in `sigil-wasm/sharing.mjs`
    /// too; `sigil-wasm/test/pinning-interop.mjs` proves Rust and JS agree.
    const SAFETY_NUMBER_KAT: &str = "83791 28129 67801 50284 55242 77845";

    /// ⭐ KNOWN ANSWER — the ORDER-INDEPENDENT pairwise number for
    /// (`dev_A`, kat_identity) and (`dev_B`, kat_identity_b).
    const PAIRWISE_SAFETY_NUMBER_KAT: &str = "05665 81205 97621 93440 13243 35164";

    /// The FIXED key material both the Rust and the JS known-answer tests use.
    /// Mirrored verbatim in sigil-wasm/sharing.mjs's `kat` helper and in
    /// sigil-wasm/test/pinning-interop.mjs. Not a real key — a deterministic
    /// fixture, chosen so both implementations can build it from a one-line loop.
    fn kat_identity() -> HybridPublicIdentity {
        let x: Vec<u8> = (0..X25519_PUBLIC_KEY_LEN).map(|i| i as u8).collect();
        let m: Vec<u8> = (0..ML_KEM768_ENCAPS_KEY_LEN)
            .map(|i| ((i * 7 + 11) % 256) as u8)
            .collect();
        HybridPublicIdentity {
            version: HYBRID_IDENTITY_VERSION,
            x25519_public_key: BASE64.encode(&x),
            mlkem_encaps_key: BASE64.encode(&m),
        }
    }

    /// A second fixture that differs from `kat_identity` in ONE byte of the
    /// X25519 half — the minimal substitution an attacker could attempt.
    fn kat_identity_b() -> HybridPublicIdentity {
        let mut x: Vec<u8> = (0..X25519_PUBLIC_KEY_LEN).map(|i| i as u8).collect();
        x[0] ^= 0x01;
        let m: Vec<u8> = (0..ML_KEM768_ENCAPS_KEY_LEN)
            .map(|i| ((i * 7 + 11) % 256) as u8)
            .collect();
        HybridPublicIdentity {
            version: HYBRID_IDENTITY_VERSION,
            x25519_public_key: BASE64.encode(&x),
            mlkem_encaps_key: BASE64.encode(&m),
        }
    }

    #[test]
    fn safety_number_known_answer() {
        // ⭐ KAT. This exact string is asserted in sigil-wasm/sharing.mjs's tests
        // and re-checked across the two implementations by
        // sigil-wasm/test/pinning-interop.mjs. If this changes, every safety
        // number every user ever wrote down changes — it is a version bump, not
        // a bug fix.
        let sn = hybrid_safety_number("dev_KAT", &kat_identity()).expect("safety number");
        assert_eq!(sn, SAFETY_NUMBER_KAT);
        // Shape: 6 groups of exactly 5 digits, space separated.
        let groups: Vec<&str> = sn.split(' ').collect();
        assert_eq!(groups.len(), SAFETY_NUMBER_GROUPS);
        assert!(groups
            .iter()
            .all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())));
    }

    #[test]
    fn safety_number_binds_device_id_and_both_key_halves() {
        let a = hybrid_safety_number("dev_A", &kat_identity()).expect("a");
        // Same key, DIFFERENT device id -> different number (the id is bound in,
        // so a real key replayed under another device's id does not verify).
        let b = hybrid_safety_number("dev_B", &kat_identity()).expect("b");
        assert_ne!(a, b);
        // One flipped bit in the X25519 half -> different number.
        let c = hybrid_safety_number("dev_A", &kat_identity_b()).expect("c");
        assert_ne!(a, c);
        // One flipped bit in the ML-KEM half -> different number.
        let mut m = BASE64
            .decode(kat_identity().mlkem_encaps_key.as_bytes())
            .expect("b64");
        m[1183] ^= 0x80;
        let d = hybrid_safety_number(
            "dev_A",
            &HybridPublicIdentity {
                version: HYBRID_IDENTITY_VERSION,
                x25519_public_key: kat_identity().x25519_public_key,
                mlkem_encaps_key: BASE64.encode(&m),
            },
        )
        .expect("d");
        assert_ne!(a, d);
    }

    #[test]
    fn pairwise_safety_number_is_order_independent() {
        let ab = pairwise_safety_number("dev_A", &kat_identity(), "dev_B", &kat_identity_b())
            .expect("ab");
        let ba = pairwise_safety_number("dev_B", &kat_identity_b(), "dev_A", &kat_identity())
            .expect("ba");
        assert_eq!(ab, ba, "a pairwise safety number MUST be order-independent");
        assert_eq!(ab, PAIRWISE_SAFETY_NUMBER_KAT);
        // And it is not just one of the two single numbers.
        assert_ne!(ab, hybrid_safety_number("dev_A", &kat_identity()).unwrap());
    }

    #[test]
    fn pin_first_sight_then_match_then_hard_refuse_on_change() {
        let dir = tempdir("pins");
        let pins = dir.join(HYBRID_PIN_FILE);

        // First sight -> pinned.
        assert_eq!(
            check_and_pin(&pins, "dev_B", &kat_identity()).expect("first"),
            PinStatus::FirstSight
        );
        // The pin store is 0600.
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&pins).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // Unchanged -> proceed.
        assert_eq!(
            check_and_pin(&pins, "dev_B", &kat_identity()).expect("match"),
            PinStatus::Match
        );
        // CHANGED -> hard refusal, with BOTH safety numbers for the human.
        let err = check_and_pin(&pins, "dev_B", &kat_identity_b()).expect_err("must refuse");
        match &err {
            CliError::PinMismatch {
                device_id,
                pinned_safety_number,
                presented_safety_number,
            } => {
                assert_eq!(device_id, "dev_B");
                assert_eq!(
                    pinned_safety_number,
                    &hybrid_safety_number("dev_B", &kat_identity()).unwrap()
                );
                assert_eq!(
                    presented_safety_number,
                    &hybrid_safety_number("dev_B", &kat_identity_b()).unwrap()
                );
            }
            other => panic!("expected PinMismatch, got {other:?}"),
        }
        // The message names the device and says what to do.
        let msg = err.to_string();
        assert!(msg.contains("dev_B"));
        assert!(msg.contains("KEY-SUBSTITUTION ATTACK"));
        assert!(msg.contains("repin"));

        // ⭐ And the store was NOT silently updated: the ORIGINAL key still
        // matches, so a second attempt with the attacker key still refuses.
        assert_eq!(
            check_and_pin(&pins, "dev_B", &kat_identity()).expect("still pinned to the real key"),
            PinStatus::Match
        );
        assert!(check_and_pin(&pins, "dev_B", &kat_identity_b()).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn repin_is_explicit_and_counted() {
        let dir = tempdir("repin");
        let pins = dir.join(HYBRID_PIN_FILE);
        check_and_pin(&pins, "dev_B", &kat_identity()).expect("first");

        let (old, new) = repin_hybrid_key(&pins, "dev_B", &kat_identity_b()).expect("repin");
        assert_eq!(
            old.as_deref(),
            Some(
                hybrid_safety_number("dev_B", &kat_identity())
                    .unwrap()
                    .as_str()
            )
        );
        assert_eq!(
            new,
            hybrid_safety_number("dev_B", &kat_identity_b()).unwrap()
        );
        // Now the NEW key is the accepted one and the OLD one alarms.
        assert_eq!(
            check_and_pin(&pins, "dev_B", &kat_identity_b()).expect("new matches"),
            PinStatus::Match
        );
        assert!(check_and_pin(&pins, "dev_B", &kat_identity()).is_err());
        assert_eq!(load_pins(&pins).unwrap().pins["dev_B"].repins, 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn pin_store_round_trips_and_rejects_a_bad_version() {
        let dir = tempdir("pinstore");
        let pins = dir.join(HYBRID_PIN_FILE);
        assert!(load_pins(&pins).expect("missing is empty").pins.is_empty());
        check_and_pin(&pins, "dev_A", &kat_identity()).expect("pin");
        let store = load_pins(&pins).expect("reload");
        assert_eq!(store.version, HYBRID_PIN_STORE_VERSION);
        assert_eq!(store.pins["dev_A"].device_id, "dev_A");
        assert_eq!(store.pins["dev_A"].repins, 0);

        std::fs::write(&pins, r#"{"version":9,"pins":{}}"#).unwrap();
        assert!(load_pins(&pins).is_err());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reseal_container_changes_the_secret_but_not_the_plaintext() {
        let old_key = [7u8; VAULT_KEY_LEN];
        let new_key = [9u8; VAULT_KEY_LEN];
        let plaintext = b"the secret that must survive a rotation";
        let c1 = seal_to_container(&old_key, plaintext, FAST).expect("seal");
        let c2 = reseal_container(&old_key, &new_key, &c1, FAST).expect("reseal");

        // The NEW key opens it and yields the SAME plaintext.
        assert_eq!(open_container(&new_key, &c2).expect("open new"), plaintext);
        // ⭐ The OLD key no longer opens the rotated container — that is the whole
        // point of a rotation.
        assert!(open_container(&old_key, &c2).is_err());
        // And the ciphertext genuinely changed.
        assert_ne!(c1, c2);
    }

    /// Create a unique temp directory under the OS temp dir.
    fn tempdir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "sigil-{tag}-{nanos}-{:?}",
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }
}
