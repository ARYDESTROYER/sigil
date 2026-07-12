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

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sigil_core::{
    open_record, public_key_from_seed, seal_record, sign, Argon2Params, RecordError, NONCE_LEN,
    SIG_PUBLIC_KEY_LEN, SIG_SEED_LEN,
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

/// A LOCAL, DEV-ONLY device key file: a single Ed25519 key pair used to sign
/// op-log requests under the `sigil-oplog-auth-v2` contract.
///
/// On disk this is JSON `{"version":1,"seed":"<b64>","public_key":"<b64>"}`,
/// where `seed` is standard-base64 of the 32-byte Ed25519 secret seed and
/// `public_key` is standard-base64 of the 32-byte Ed25519 public key. The file
/// holds SECRET key material and is written with mode `0600`; it is per-device,
/// DEV-ONLY, and NOT synced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyFile {
    /// Key file format version. Always [`KEY_FILE_VERSION`].
    pub version: u8,
    /// Standard-base64 of the 32-byte Ed25519 secret seed. SECRET material.
    pub seed: String,
    /// Standard-base64 of the 32-byte Ed25519 public key. Set sigild's
    /// `SIGILD_OPLOG_PUBKEY` to exactly this string to enable verification.
    pub public_key: String,
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

    let seed_vec = BASE64
        .decode(kf.seed.as_bytes())
        .map_err(|e| CliError::Key(format!("seed is not valid base64: {e}")))?;
    let seed: [u8; SIG_SEED_LEN] = seed_vec.try_into().map_err(|v: Vec<u8>| {
        CliError::Key(format!(
            "seed must decode to {SIG_SEED_LEN} bytes, got {}",
            v.len()
        ))
    })?;

    let pub_vec = BASE64
        .decode(kf.public_key.as_bytes())
        .map_err(|e| CliError::Key(format!("public_key is not valid base64: {e}")))?;
    let public: [u8; SIG_PUBLIC_KEY_LEN] = pub_vec.try_into().map_err(|v: Vec<u8>| {
        CliError::Key(format!(
            "public_key must decode to {SIG_PUBLIC_KEY_LEN} bytes, got {}",
            v.len()
        ))
    })?;

    Ok((seed, public))
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
    check_vault(vault)?;
    let url = ops_url(server, vault);

    let mut req = ureq::post(&url).set("Content-Type", "application/octet-stream");
    if let Some(seed) = key {
        // Sign EXACTLY what this request sends: POST, the op path, NO query,
        // body = container. The query is "" to match the server's r.URL.RawQuery.
        let (ts, nonce, sig) = sign_oplog_request(seed, "POST", &ops_path(vault), "", container)?;
        req = req
            .set("X-Sigil-Timestamp", &ts)
            .set("X-Sigil-Nonce", &nonce)
            .set("X-Sigil-Signature", &sig);
    }
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
    check_vault(vault)?;
    let url = ops_url(server, vault);

    // Render `since` ONCE so the signed query and the wire query are byte-identical.
    let since_str = since.to_string();
    let query = format!("since={since_str}");

    let mut req = ureq::get(&url).query("since", &since_str);
    if let Some(seed) = key {
        // Sign EXACTLY what this request sends: GET, the op path, query
        // "since={since}", empty body — matching the server's r.URL.RawQuery.
        let (ts, nonce, sig) = sign_oplog_request(seed, "GET", &ops_path(vault), &query, b"")?;
        req = req
            .set("X-Sigil-Timestamp", &ts)
            .set("X-Sigil-Nonce", &nonce)
            .set("X-Sigil-Signature", &sig);
    }
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
}
