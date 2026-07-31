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
    decode_recovery_kit, derive_recovery_keys, encode_recovery_kit, hybrid_auth_open,
    hybrid_auth_seal, hybrid_open, hybrid_seal, ml_kem768_keygen, open_record,
    public_key_from_seed, seal_record, sign, vault_key_wrap_aad, x25519_public_key, Argon2Params,
    HybridSealError, OtpAlgorithm, RecordError, RecoveryError, ML_KEM768_CIPHERTEXT_LEN,
    ML_KEM768_DECAPS_KEY_LEN, ML_KEM768_ENCAPS_COIN_LEN, ML_KEM768_ENCAPS_KEY_LEN,
    ML_KEM768_KEYGEN_SEED_LEN, NONCE_LEN, RECOVERY_SEED_LEN, SIG_PUBLIC_KEY_LEN, SIG_SEED_LEN,
    X25519_PUBLIC_KEY_LEN, X25519_SECRET_KEY_LEN,
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
    /// ⛔ The container header's Argon2id work factors exceed
    /// [`Argon2Params::MAX_M_COST`] / [`Argon2Params::MAX_T_COST`] /
    /// [`Argon2Params::MAX_P_COST`] (Phase 59).
    ///
    /// The header is UNAUTHENTICATED plaintext framing, so `m_cost` is whatever
    /// the writer of those bytes chose — and Argon2id allocates `m_cost` KiB in
    /// one block before doing any work. `m_cost = 0xFFFF_FFF0` asks for ~4 TiB.
    /// Containers reach a client through `sigild`'s **zero-knowledge** op-log,
    /// which by design cannot inspect or filter them, so anyone able to write to
    /// a vault's op-log (a revoked-but-not-yet-rotated device, a co-tenant of a
    /// shared vault, a breached server) could otherwise make every client that
    /// pulls die on allocation and keep the user away from their own 2FA codes.
    ///
    /// ⭐ Returned at PARSE time, before any allocation and before the KDF is
    /// entered. Carries the three offending values (public framing metadata, no
    /// secret) so an operator can see what was asked for.
    ParamsOutOfRange {
        /// The rejected memory cost, in KiB.
        m_cost: u32,
        /// The rejected time cost (passes).
        t_cost: u32,
        /// The rejected parallelism (lanes).
        p_cost: u32,
    },
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
    /// ⚠️ A rotation would have SILENTLY DESTROYED a recipient's access
    /// (Phase 54).
    ///
    /// `rotate_vault_key` deletes the envelope of every device not named by
    /// `--to`. That is the point — it is how a compromised device is excluded —
    /// but it means a rotation that simply forgot to name the RECOVERY KIT ends
    /// recoverability while everything else keeps working. Destruction is now an
    /// explicit act: the rotation aborts, having touched NOTHING, and the caller
    /// must either add each device to `--to` (keep it) or to `--drop` (remove
    /// it deliberately).
    ///
    /// Carries only device ids plus a flag for those this client's pin store
    /// marks as a recovery kit. No key material.
    RecipientsWouldBeDropped {
        /// The vault whose rotation was refused.
        vault_id: String,
        /// `(device id, is this client's recovery kit?)` for each device that
        /// holds an envelope but was named by neither `--to` nor `--drop`.
        unknown: Vec<(String, bool)>,
    },
    /// A RECOVERY KIT operation failed at the CLI layer: an undecodable printed
    /// code, a failed pre-print verification round-trip, a kit that covers
    /// nothing, or a refused first-sight cover. NEVER carries the recovery code,
    /// the recovery seed, a derived seed, a vault key or any secret bytes.
    Recovery(String),
    /// ⛔ A wrap was refused because the recipient is a RECOVERY KIT this client
    /// has never pinned, and no safety number was supplied to check the server's
    /// answer against (Phase 53-55 fix round).
    ///
    /// ADR 0038's lesson is that the choke point is the FETCH and EVERY wrap path
    /// must go through it. Phase 54 put this requirement on ONE COMMAND
    /// (`recovery cover`), so `vault share --to <kitID>` and `vault rotate --to
    /// <kitID>` reached the identical outcome — the live vault key wrapped to
    /// whatever key the server served — through ordinary first-sight TOFU. The
    /// requirement now lives in [`verify_recipient_for_wrap`], which every wrap
    /// path calls, so no command can reach a kit without it.
    ///
    /// It is STRICTER than ordinary first sight on purpose: for a recovery kit
    /// the out-of-band channel is guaranteed to exist — the safety number is
    /// printed on the sheet in the user's own hand — so there is no excuse for
    /// trusting the registry. Nothing was wrapped, nothing was uploaded, and the
    /// pin store was NOT mutated.
    UnverifiedRecoveryKit {
        /// The kit device the wrap was aimed at.
        device_id: String,
        /// The safety number the server is presenting for it right now, so a
        /// human can compare it to the sheet before re-running with
        /// `--safety-number`.
        presented_safety_number: String,
    },
    /// ⛔ A supplied `--safety-number` did NOT match the key the server is
    /// serving. A hard stop with nothing wrapped, nothing uploaded, and the pin
    /// store unchanged: either the sheet was mistyped, or the server substituted
    /// a key it can decrypt with.
    SafetyNumberMismatch {
        /// The device whose key was being verified.
        device_id: String,
        /// What the human supplied (from the sheet / the phone call).
        expected_safety_number: String,
        /// What the server is actually serving.
        presented_safety_number: String,
    },
    /// ⛔ A `SIGILhyb` container was presented in the WRONG SLOT (Phase 60).
    ///
    /// There are two kinds of hybrid container and they are NOT
    /// interchangeable:
    ///
    /// * **version 1** — the ANONYMOUS file container written by
    ///   `sigil hybrid-seal`. Anyone holding the recipient's PUBLIC key can mint
    ///   one; there is no sender in it at all.
    /// * **version 2** — the AUTHENTICATED container a vault-key wrap uses. It
    ///   can only be produced by a device holding a specific long-term X25519
    ///   secret, and it is sealed under a context AAD naming the vault, the
    ///   recipient and the sender.
    ///
    /// ⛔ **A version-1 container is REFUSED as a vault-key envelope, never
    /// accepted.** Accepting it would be accepting the forgery this version
    /// exists to stop: `sigil hybrid-seal --recipient-pub <victim>.pub --in
    /// <attacker-chosen-key>` produced bytes that were byte-shaped identically
    /// to a genuine wrap and opened cleanly. There is deliberately NO
    /// compatibility flag. This repo is pre-audit and dev-gated with no real
    /// users, so the break is clean: re-run `sigil vault share` / `sigil vault
    /// rotate` / `sigil recovery cover` to re-issue every envelope.
    WrongEnvelopeKind {
        /// The container version actually found.
        found_version: u8,
        /// The container version this slot requires.
        expected_version: u8,
    },
    /// ⛔ A vault-key envelope could not be attributed to an EXPECTED SENDER
    /// (Phase 60): the caller could not work out which device deposited it, so
    /// there was nothing to authenticate against and nothing was unwrapped.
    ///
    /// This is a REFUSAL, not a fallback: unwrapping "from whoever" is exactly
    /// the anonymous behaviour that made a forged envelope indistinguishable
    /// from a real one.
    UnknownSender(String),
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
            CliError::ParamsOutOfRange {
                m_cost,
                t_cost,
                p_cost,
            } => write!(
                f,
                "refusing this container: its header demands Argon2id work factors \
                 beyond what any Sigil client will honour (m_cost={m_cost} KiB, \
                 t_cost={t_cost}, p_cost={p_cost}; limits are {}/{}/{}). Nothing was \
                 allocated. A container that asks for more memory than a machine has \
                 is a denial-of-service attempt, not a strong vault",
                Argon2Params::MAX_M_COST,
                Argon2Params::MAX_T_COST,
                Argon2Params::MAX_P_COST
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
            CliError::RecipientsWouldBeDropped { vault_id, unknown } => {
                write!(
                    f,
                    "REFUSING TO ROTATE vault {vault_id}: {} device(s) currently hold a wrapped \
                     key for it but were named by neither --to nor --drop. Rotating would DELETE \
                     their envelopes and silently end their access.",
                    unknown.len()
                )?;
                for (device_id, is_kit) in unknown {
                    if *is_kit {
                        write!(
                            f,
                            "\n  {device_id}  ⚠️  THIS IS YOUR RECOVERY KIT — dropping it means \
                             the printed sheet can no longer recover this vault"
                        )?;
                    } else {
                        write!(f, "\n  {device_id}")?;
                    }
                }
                write!(
                    f,
                    "\n  Nothing was changed. Add each device to --to to KEEP its access, or to \
                     --drop to remove it deliberately (or use --drop-all-others)."
                )
            }
            CliError::Recovery(e) => write!(f, "recovery kit error: {e}"),
            CliError::UnverifiedRecoveryKit {
                device_id,
                presented_safety_number,
            } => write!(
                f,
                "REFUSING TO WRAP: device {device_id} is a RECOVERY KIT that this client has never \
                 pinned, so the only thing vouching for its key is the server — and a hostile \
                 server that substituted its own key would be handed this vault's key.\n  \
                 from server:  {presented_safety_number}\n  \
                 The safety number is PRINTED ON THE RECOVERY SHEET. Compare it, then re-run with \
                 --safety-number \"<the six 5-digit groups from the sheet>\".\n  \
                 Nothing was wrapped, nothing was uploaded, and no key was pinned."
            ),
            CliError::SafetyNumberMismatch {
                device_id,
                expected_safety_number,
                presented_safety_number,
            } => write!(
                f,
                "REFUSING TO WRAP: the safety number you supplied does not match the key this \
                 server is serving for {device_id}.\n  \
                 you supplied: {expected_safety_number}\n  \
                 from server:  {presented_safety_number}\n  \
                 Either it was mistyped, or the server substituted a key it can decrypt with. \
                 Nothing was wrapped, nothing was uploaded, and no key was pinned."
            ),
            CliError::WrongEnvelopeKind {
                found_version: 1,
                expected_version: 2,
            } => write!(
                f,
                "REFUSING TO UNWRAP: this is a version 1 (UNAUTHENTICATED) SIGILhyb container, \
                 and a vault-key envelope must be version 2 (AUTHENTICATED).\n  \
                 A version 1 container carries NO SENDER: anyone who can read the recipient's \
                 published hybrid PUBLIC key can mint one, so accepting it would let an \
                 attacker install a vault key of their own choosing and read everything \
                 written afterwards.\n  \
                 There is deliberately no compatibility flag. Ask the sender to re-issue it \
                 with `sigil vault share` (or `sigil vault rotate` / `sigil recovery cover`)."
            ),
            CliError::WrongEnvelopeKind {
                found_version,
                expected_version,
            } => write!(
                f,
                "SIGILhyb container version {found_version} presented where version \
                 {expected_version} is required (version 1 = anonymous file container, \
                 version 2 = authenticated vault-key envelope; they are not interchangeable)"
            ),
            CliError::UnknownSender(m) => write!(
                f,
                "REFUSING TO UNWRAP: {m}\n  \
                 A vault-key envelope is authenticated to the device that deposited it, so \
                 there is nothing to check it against until that device is known. Name it \
                 explicitly with --from <deviceID>."
            ),
        }
    }
}

impl From<RecoveryError> for CliError {
    fn from(e: RecoveryError) -> Self {
        CliError::Recovery(e.to_string())
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
/// - [`CliError::ParamsOutOfRange`] if the header's Argon2id work factors exceed
///   Sigil's ceilings — checked BEFORE any allocation (see the variant's docs).
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

    let params = Argon2Params {
        m_cost,
        t_cost,
        p_cost,
    };
    // ⛔ RANGE-CHECK BEFORE ANY ALLOCATION. These three u32s come straight out of
    // an UNAUTHENTICATED header written by whoever produced the bytes, and Argon2
    // allocates `m_cost` KiB up front. Refusing here — before the salt is even
    // sliced, and long before the KDF is entered — is what turns a 4 TiB request
    // from a crash into a typed error. `sigil-core` re-checks the same ceilings in
    // `derive_master_key`; this earlier copy exists so the failure is reportable
    // as "this container is hostile" rather than a generic KDF error.
    if params.validate().is_err() {
        return Err(CliError::ParamsOutOfRange {
            m_cost,
            t_cost,
            p_cost,
        });
    }

    // `rest` starts at the version byte; the salt begins after the 14 fixed
    // bytes (version + 3 u32s + salt_len) consumed above.
    let after_fixed = &rest[14..];
    if after_fixed.len() < salt_len {
        return Err(CliError::MalformedHeader);
    }
    let (salt, envelope) = after_fixed.split_at(salt_len);

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
/// - [`CliError::WrongEnvelopeKind`] if handed an AUTHENTICATED (version 2)
///   vault-key envelope — that one must go through
///   [`hybrid_auth_open_container`], which checks the sender and the context.
/// - [`CliError::HybridSeal`] if the wrapped record fails to decode or
///   authenticate (wrong identity or tampered container).
pub fn hybrid_open_container(
    identity: &HybridSecretKeys,
    container: &[u8],
) -> Result<Vec<u8>, CliError> {
    let (version, eph_pub, mlkem_ct, envelope) = split_hybrid_container(container)?;
    if version == HYBRID_AUTH_FORMAT_VERSION {
        // The OTHER direction of the same rule: an AUTHENTICATED vault-key
        // envelope is not an anonymous file, and opening it here would drop the
        // sender check and the context binding on the floor.
        return Err(CliError::WrongEnvelopeKind {
            found_version: version,
            expected_version: HYBRID_FORMAT_VERSION,
        });
    }
    if version != HYBRID_FORMAT_VERSION {
        return Err(CliError::UnsupportedVersion(version));
    }

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
// ⭐ PHASE 60 — THE **AUTHENTICATED** HYBRID CONTAINER (`SIGILhyb` version 2)
// ---------------------------------------------------------------------------
//
// THE HOLE THIS CLOSES, reproduced with the shipped binary and nothing else:
//
//     sigil hybrid-keygen --out b.hybrid          # victim; b.hybrid.pub is published
//     head -c 32 /dev/urandom > attacker_key.bin
//     sigil hybrid-seal --recipient-pub b.hybrid.pub --in attacker_key.bin --out forged.env
//     -> 1226 bytes, magic SIGILhyb, byte-shaped IDENTICALLY to a genuine vault-key wrap
//     sigil hybrid-open --key b.hybrid --in forged.env   # 32 bytes, the attacker's key
//
// Three separate defects lined up:
//
//   1. `hybrid_seal` is ANONYMOUS (ephemeral-static). Holding the recipient's
//      PUBLIC key is enough to produce a container it will open. sigild serves
//      every device's published hybrid public key to every authenticated device.
//   2. `HYBRID_AAD` was FIXED (`b"sigil-hybrid-cli/1"`), so a container was bound
//      to no vault, no recipient, no sender AND NO PURPOSE — which is exactly
//      why the general-purpose FILE command's output was a valid VAULT-KEY
//      envelope.
//   3. `unwrap_vault_key`'s only check was `len == 32`.
//
// Consequence: a hostile/breached server, or any co-tenant with WRITE on the
// vault, could install a vault key IT chose, and everything the victim wrote
// afterwards was readable by the attacker. ADR 0038 pinning did not help — the
// accept path fetched no hybrid key at all, so the pin store was never consulted.
//
// THE FIX, in three parts, all of which must hold:
//
//   * the KEM becomes AUTHENTICATED (`sigil_core::hybrid_auth_seal`): the sender
//     mixes in a static-static X25519 DH, so a forger needs the SENDER's secret,
//     not just the recipient's public key;
//   * the AAD becomes CONTEXT-BOUND (`sigil_core::vault_key_wrap_aad`): purpose
//     + vault id + recipient device id + sender device id;
//   * the container VERSION becomes 2, and a version-1 container is REFUSED
//     wherever a vault key is expected — accepting v1 would be accepting the
//     vulnerability.
//
// The ANONYMOUS v1 form is KEPT for `sigil hybrid-seal` / `hybrid-open`, which
// are honestly anonymous file encryption to a public key. The two are
// domain-separated three ways over (version byte, KDF info label, AAD prefix),
// so neither can be substituted for the other in either direction.

/// The AUTHENTICATED hybrid container format version — what every vault-key
/// envelope is written as and the only version an unwrap accepts.
///
/// MIRRORED in `sigil-wasm/src/lib.rs`; the two MUST stay byte-for-byte in sync.
pub const HYBRID_AUTH_FORMAT_VERSION: u8 = 2;

/// Encrypt `plaintext` TO a recipient's hybrid public identity **AS** the holder
/// of `sender_x25519_secret`, under the caller-supplied context `aad`.
///
/// The wire layout is the v1 layout with a bumped version byte, so the two are
/// distinguishable at offset 8 without parsing anything:
///
/// ```text
///   offset  size    field
///   ------  ------  -----------------------------------------------
///   0       8       magic          = b"SIGILhyb"
///   8       1       version        = 2   (1 = anonymous, 2 = AUTHENTICATED)
///   9       32      eph_x25519_pub (sender's EPHEMERAL X25519 public key)
///   41      1088    mlkem_ct       (ML-KEM-768 ciphertext)
///   1129    ..      envelope       = the hybrid_auth_seal envelope (tail)
/// ```
///
/// ⭐ The sender's STATIC public key is deliberately **NOT** carried in the
/// container. It is an INPUT to the recipient's derivation, supplied out of band
/// (from the pin store, through the [`VerifiedSender`] gate). Carrying it would
/// invite exactly the mistake this fixes: reading the sender's identity out of
/// the attacker-controlled bytes and then "verifying" against it.
///
/// # Errors
/// - [`CliError::Rng`] if the OS RNG fails.
/// - [`CliError::HybridSeal`] if the KEM rejects an input.
pub fn hybrid_auth_seal_to_container(
    sender_x25519_secret: &[u8; X25519_SECRET_KEY_LEN],
    recipient: &HybridPublicKeys,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, CliError> {
    let mut eph_secret = [0u8; X25519_SECRET_KEY_LEN];
    fill_random(&mut eph_secret)?;
    let mut coin = [0u8; ML_KEM768_ENCAPS_COIN_LEN];
    fill_random(&mut coin)?;
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;

    let (eph_pub, mlkem_ct, envelope) = hybrid_auth_seal(
        sender_x25519_secret,
        &recipient.x25519_public_key,
        &recipient.mlkem_encaps_key,
        &eph_secret,
        &coin,
        &nonce,
        aad,
        plaintext,
    )?;

    let mut out = Vec::with_capacity(HYBRID_FIXED_PREFIX_LEN + envelope.len());
    out.extend_from_slice(HYBRID_MAGIC);
    out.push(HYBRID_AUTH_FORMAT_VERSION);
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&mlkem_ct);
    out.extend_from_slice(&envelope);
    Ok(out)
}

/// The parsed parts of a `SIGILhyb` container: `(version, eph_x25519_pub,
/// mlkem_ct, envelope)`. Shared by the anonymous (v1) and authenticated (v2)
/// readers, which have identical framing and differ only in the version byte
/// and how the envelope was sealed.
type HybridContainerParts<'a> = (
    u8,
    [u8; X25519_PUBLIC_KEY_LEN],
    [u8; ML_KEM768_CIPHERTEXT_LEN],
    &'a [u8],
);

/// Split a `SIGILhyb` container into its parts, bounds-checking BEFORE slicing
/// so short or garbage input yields a clear error rather than a panic.
fn split_hybrid_container(container: &[u8]) -> Result<HybridContainerParts<'_>, CliError> {
    if container.len() < HYBRID_FIXED_PREFIX_LEN {
        return Err(CliError::ShortContainer);
    }
    let (magic, rest) = container.split_at(8);
    if magic != HYBRID_MAGIC.as_slice() {
        return Err(CliError::BadMagic);
    }
    let version = rest[0];
    let after_version = &rest[1..];
    let (eph_pub_bytes, rest2) = after_version.split_at(X25519_PUBLIC_KEY_LEN);
    let (mlkem_ct_bytes, envelope) = rest2.split_at(ML_KEM768_CIPHERTEXT_LEN);
    let eph_pub: [u8; X25519_PUBLIC_KEY_LEN] = eph_pub_bytes
        .try_into()
        .expect("slice is exactly X25519_PUBLIC_KEY_LEN by construction");
    let mlkem_ct: [u8; ML_KEM768_CIPHERTEXT_LEN] = mlkem_ct_bytes
        .try_into()
        .expect("slice is exactly ML_KEM768_CIPHERTEXT_LEN by construction");
    Ok((version, eph_pub, mlkem_ct, envelope))
}

/// Open an AUTHENTICATED container, asserting it came from
/// `sender_x25519_pub` and was sealed under exactly `aad`.
///
/// ⛔ A **version 1** (anonymous) container is refused with
/// [`CliError::WrongEnvelopeKind`] BEFORE any cryptography runs. That refusal is
/// the whole point: a v1 container proves nothing about who made it.
///
/// # Errors
/// - [`CliError::ShortContainer`] / [`CliError::BadMagic`].
/// - [`CliError::WrongEnvelopeKind`] for a v1 (or any non-v2) container.
/// - [`CliError::HybridSeal`] on ANY authentication failure — wrong recipient,
///   **wrong sender**, tampered bytes, or a mismatched context AAD. No plaintext
///   is ever returned in that case.
pub fn hybrid_auth_open_container(
    identity: &HybridSecretKeys,
    sender_x25519_pub: &[u8; X25519_PUBLIC_KEY_LEN],
    aad: &[u8],
    container: &[u8],
) -> Result<Vec<u8>, CliError> {
    let (version, eph_pub, mlkem_ct, envelope) = split_hybrid_container(container)?;
    if version != HYBRID_AUTH_FORMAT_VERSION {
        return Err(CliError::WrongEnvelopeKind {
            found_version: version,
            expected_version: HYBRID_AUTH_FORMAT_VERSION,
        });
    }
    Ok(hybrid_auth_open(
        &identity.x25519_secret,
        &identity.mlkem_decaps_key,
        sender_x25519_pub,
        &eph_pub,
        &mlkem_ct,
        aad,
        envelope,
    )?)
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
    /// The ACCOUNT this device belongs to (Phase 52). ADDITIVE and OPTIONAL: a
    /// server without the account model simply omits it, and this crate never
    /// sends it — the account is always derived server-side from the verified
    /// signature, never named by a request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
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
// The ACCOUNT model (Phase 52). Client half of sigild's four account routes.
//
// WHAT AN ACCOUNT IS: a server-assigned id sitting on a device row. Entitlement
// and vault ownership key off THAT id instead of the device id, so a second
// device of the same account inherits the subscription and can still administer
// a vault after its sibling is revoked.
//
// THE STRUCTURAL RULE, MIRRORED HERE: no request built below names an account.
// There is no account_id path segment, query parameter or body field anywhere —
// the server always takes the account from the device row of the signature it
// just verified. That is what closes every cross-account IDOR, and it is why
// these functions take only a [`RequestAuth`].
//
// NO NEW CRYPTO, NO NEW WIRE FORMAT: every call below rides the EXISTING
// contract v3 `apply_auth` path. There is no new signed-message domain and no
// new header, so the three canonical-message implementations (Go server, this
// crate, sigil-wasm) are untouched and stay byte-identical.
//
// JOINING NEEDS NO CODE AT ALL: an invite is presented in the EXISTING
// `X-Sigil-Enroll-Token` header, and the enrollment challenge already binds the
// token DIGEST — so `sigil device enroll --token <invite>` joins the inviter's
// account with the enrollment path completely unchanged.
//
// STATUS: dev-gated + pre-audit + UNAUDITED, plain HTTP. An account is AUTH
// METADATA ONLY: membership confers AUTHORIZATION, never DECRYPTION — a joined
// device can authenticate and see its entitlement, and can read nothing until an
// existing member wraps the vault key to its hybrid public key.
// ---------------------------------------------------------------------------

/// Reject invite IDs that cannot be placed verbatim in a URL path segment.
///
/// Same rule as [`check_device_id`]: non-empty, no `/`, no ASCII whitespace.
/// Server IDs are `inv_` + base64url, so a legitimate handle always passes.
fn check_invite_id(invite_id: &str) -> Result<(), CliError> {
    if invite_id.is_empty()
        || invite_id.contains('/')
        || invite_id.chars().any(|c| c.is_whitespace())
    {
        return Err(CliError::Key(format!(
            "invalid invite id {invite_id:?}: must be non-empty with no '/' or whitespace"
        )));
    }
    Ok(())
}

/// The CALLER's own account and its members, as reported by `GET /v1/account`.
///
/// There is no route that reads another account and none that enumerates
/// accounts, so this is always "mine".
#[derive(Debug, Clone, Deserialize)]
pub struct AccountInfo {
    /// The server-assigned account ID (`acct_…`, or `acct_mig_…` for a device
    /// adopted by the migration that introduced accounts).
    pub account_id: String,
    /// RFC 3339 creation time, when the server knows it.
    #[serde(default)]
    pub created_at: String,
    /// How many ACTIVE devices are in the account. This — not `devices.len()` —
    /// is what `device_limit` bounds: the cap is on CONCURRENT devices, so
    /// revoking one FREES its seat.
    #[serde(default)]
    pub device_count: usize,
    /// How many members are REVOKED. Reported separately rather than folded into
    /// the limit, so history stays visible without consuming capacity.
    #[serde(default)]
    pub revoked_device_count: usize,
    /// The server's configured per-account device cap.
    #[serde(default)]
    pub device_limit: usize,
    /// The member devices. Metadata only — the registry never echoes keys.
    #[serde(default)]
    pub devices: Vec<DeviceInfo>,
}

/// One OPEN invite in a listing. METADATA ONLY: it carries the PUBLIC handle and
/// never the secret, never the digest — a minted invite can never be recovered
/// from the server.
#[derive(Debug, Clone, Deserialize)]
pub struct AccountInviteInfo {
    /// The PUBLIC handle, used for revocation.
    pub invite_id: String,
    /// Which member device minted it.
    #[serde(default)]
    pub created_by_device_id: String,
    /// RFC 3339 creation time.
    #[serde(default)]
    pub created_at: String,
    /// RFC 3339 expiry.
    #[serde(default)]
    pub expires_at: String,
    /// Whether the invite is PINNED to one Ed25519 public key (so an intercepted
    /// invite cannot be redeemed by anyone else).
    #[serde(default)]
    pub pinned: bool,
}

/// A freshly minted invite. ⚠️ [`CreatedAccountInvite::invite`] is a BEARER
/// SECRET returned exactly ONCE by the server: anyone who reads it inside its TTL
/// can join the account (unless it was pinned to a public key). It is never
/// re-served, never logged, and never stored.
#[derive(Clone, Deserialize)]
pub struct CreatedAccountInvite {
    /// The PUBLIC handle for listing and revocation. Not a secret.
    pub invite_id: String,
    /// ⚠️ THE SECRET. Present only in the response that minted it.
    pub invite: String,
    /// The account it joins (the minting device's own).
    #[serde(default)]
    pub account_id: String,
    /// RFC 3339 expiry.
    #[serde(default)]
    pub expires_at: String,
    /// Whether it is pinned to one Ed25519 public key.
    #[serde(default)]
    pub pinned: bool,
}

/// REDACTED on purpose: the secret must not reach a log line via a stray
/// `{:?}`. Every other field is metadata and is shown.
impl std::fmt::Debug for CreatedAccountInvite {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreatedAccountInvite")
            .field("invite_id", &self.invite_id)
            .field("invite", &"<redacted>")
            .field("account_id", &self.account_id)
            .field("expires_at", &self.expires_at)
            .field("pinned", &self.pinned)
            .finish()
    }
}

/// READ the signing device's own account: its ID, its member devices, and the
/// server's device cap.
///
/// Requires a contract v3 identity ([`RequestAuth::V3`]) — the account is taken
/// from the verified signature, so an unsigned or v2 request cannot resolve one.
///
/// # Errors
/// - [`CliError::Server`] on a non-2xx: `401` (not authenticated / revoked),
///   `403` (not permitted — which INCLUDES the device carrying no account at
///   all, an invariant violation the server fails CLOSED on rather than falling
///   back to the device id; the body is the same coarse `forbidden` as any other
///   refusal, so the two cannot be told apart from here), `501` (the account
///   model is not enabled on that server).
pub fn get_account(server: &str, auth: &RequestAuth<'_>) -> Result<AccountInfo, CliError> {
    let path = "/v1/account";
    let req = ureq::get(&join_url(server, path));
    let req = apply_auth(req, auth, "GET", path, "", b"")?;
    let text = finish(req.call())?;
    serde_json::from_str(&text).map_err(|e| CliError::BadResponse(e.to_string()))
}

/// MINT a single-use invite that lets ANOTHER device join the signing device's
/// account.
///
/// `ttl_seconds` may only SHORTEN the invite's life — the server clamps it to its
/// own configured ceiling. `invitee_public_key`, when given, PINS the invite to
/// that one Ed25519 public key, so an intercepted invite cannot be redeemed by
/// anyone else; nothing forces pinning, and an UNPINNED invite is a bearer secret
/// for its whole TTL over a plain-HTTP dev transport.
///
/// The redeeming device presents the returned secret as its `--token` to
/// `sigil device enroll` — the enrollment path is unchanged.
///
/// ⚠️ The returned secret is shown ONCE. This crate never writes it to a file and
/// never logs it.
///
/// # Errors
/// - [`CliError::Server`] on a non-2xx: `401`, `409` (`invite_limit` — too many
///   open invites, or `account_full`), `501`.
pub fn create_account_invite(
    server: &str,
    auth: &RequestAuth<'_>,
    ttl_seconds: Option<u64>,
    invitee_public_key: Option<&[u8; SIG_PUBLIC_KEY_LEN]>,
) -> Result<CreatedAccountInvite, CliError> {
    // NOTE WHAT IS NOT HERE: no account_id and no subject. The invite always
    // lands in the CALLER's account, resolved from the signature server-side.
    #[derive(Serialize)]
    struct InviteBody {
        #[serde(skip_serializing_if = "Option::is_none")]
        ttl_seconds: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        invitee_public_key: Option<String>,
    }
    let body = serde_json::to_vec(&InviteBody {
        ttl_seconds,
        invitee_public_key: invitee_public_key.map(|k| BASE64.encode(k)),
    })
    .map_err(|e| CliError::Key(format!("could not serialize invite body: {e}")))?;

    let path = "/v1/account/invites";
    let req = ureq::post(&join_url(server, path)).set("Content-Type", "application/json");
    let req = apply_auth(req, auth, "POST", path, "", &body)?;
    let text = finish(req.send_bytes(&body))?;
    serde_json::from_str(&text).map_err(|e| CliError::BadResponse(e.to_string()))
}

/// LIST the signing device's account's OPEN invites. METADATA ONLY — the secret
/// and its digest are never served, by either the server or this function.
///
/// # Errors
/// - [`CliError::Server`] on a non-2xx (`401`, `403` — including a missing
///   account, `501`).
pub fn list_account_invites(
    server: &str,
    auth: &RequestAuth<'_>,
) -> Result<Vec<AccountInviteInfo>, CliError> {
    #[derive(Deserialize)]
    struct Wire {
        #[serde(default)]
        invites: Vec<AccountInviteInfo>,
    }
    let path = "/v1/account/invites";
    let req = ureq::get(&join_url(server, path));
    let req = apply_auth(req, auth, "GET", path, "", b"")?;
    let text = finish(req.call())?;
    let wire: Wire =
        serde_json::from_str(&text).map_err(|e| CliError::BadResponse(e.to_string()))?;
    Ok(wire.invites)
}

/// REVOKE an unredeemed invite of the signing device's account.
///
/// The server scopes the lookup by `(account, invite_id)`, so a FOREIGN invite
/// handle and a MISSING one are indistinguishable — both answer `404`. There is
/// no enumeration oracle, which is why this returns the same error either way.
///
/// # Errors
/// - [`CliError::Key`] if the handle is not a usable path segment.
/// - [`CliError::Server`] on a non-2xx: `401`, `404` (`invite_not_found` — unknown
///   OR belonging to another account), `501`.
pub fn revoke_account_invite(
    server: &str,
    auth: &RequestAuth<'_>,
    invite_id: &str,
) -> Result<(), CliError> {
    check_invite_id(invite_id)?;
    let path = format!("/v1/account/invites/{invite_id}/revoke");
    // An empty body is sent and is exactly what gets signed.
    let body: &[u8] = b"";
    let req = ureq::post(&join_url(server, &path)).set("Content-Type", "application/json");
    let req = apply_auth(req, auth, "POST", &path, "", body)?;
    finish(req.send_bytes(body))?;
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

/// The TOTP-vault JSON version this build WRITES into `version` (the *inner*
/// plaintext version; the outer container is a normal `SIGILcli` file).
pub const TOTP_VAULT_VERSION: u8 = 1;

/// ⭐ The highest [`TotpVault::min_reader_version`] this build can satisfy.
///
/// **This is the forward-compatibility contract, and it is deliberately not the
/// same knob as [`TOTP_VAULT_VERSION`].** `version` says *what wrote this vault*;
/// `min_reader_version` says *what a reader must understand to read it safely*.
/// A reader refuses if and only if `min_reader_version > TOTP_VAULT_READER_VERSION`.
///
/// Why this exists: the vault schema is MIRRORED across four clients (CLI,
/// webapp, MV3 extension, native desktop) plus a printed recovery kit, and the
/// old rule was a blanket `version != 1 ⇒ refuse`. That made *any* schema
/// addition a flag day — every client had to ship before any client could write
/// the new field — with the alternative being an older client silently STRIPPING
/// the field on its next write, on a sync path where the oldest writer wins.
///
/// With this field, a future purely-additive change writes `version: 2,
/// min_reader_version: 1` and old clients keep reading (and, thanks to
/// `TotpVault::extra` / `TotpEntry::extra`, keep the new data intact when they
/// write back). A genuinely incompatible change writes `min_reader_version: 2`
/// and is refused **precisely**, naming what is needed, instead of by a version
/// equality check that cannot tell the two cases apart.
///
/// ⚠️ It FAILS CLOSED: a vault with no `min_reader_version` is treated as
/// requiring a reader of its own `version`, so a version-2 writer that forgets to
/// state the field gets the old conservative behaviour rather than a silent
/// misread.
pub const TOTP_VAULT_READER_VERSION: u8 = 1;

/// Default number of digits for a TOTP code when none is specified.
pub const TOTP_DEFAULT_DIGITS: u32 = 6;

/// Default TOTP period (time step) in seconds when none is specified.
pub const TOTP_DEFAULT_PERIOD: u32 = 30;

/// One TOTP secret in the vault.
///
/// The `secret` is the RAW key bytes stored as standard-base64 in the JSON (the
/// on-the-wire provisioning form is base32, but we store the decoded bytes). The
/// `algorithm` is one of `"sha1"`, `"sha256"`, `"sha512"` (lowercase).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// ⭐ A STABLE, opaque per-entry identifier (Phase 59).
    ///
    /// Written as a lowercase RFC 4122 v4 UUID string, from 16 bytes of
    /// CALLER-supplied entropy (`getrandom` natively, `crypto.getRandomValues` in
    /// the browser — `sigil-core` draws none, ADR 0007). It carries **no
    /// meaning**: it is not derived from the label, the issuer or the secret, and
    /// it is not a secret itself.
    ///
    /// Why it exists: today an entry is identified by its `label`, which is user
    /// text that the user can edit and that collides across issuers. A stable id
    /// is what a future change would need to rename an entry without it looking
    /// like a delete-plus-add on a sync path, and to make de-duplication mean
    /// something. ⚠️ **Nothing keys off it yet** — every lookup is still by
    /// `label`, deliberately (changing entry identity is a semantics decision for
    /// the lead, not this phase). This only makes that change possible later.
    ///
    /// `None` on every entry written before this field existed; readers must not
    /// require it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    /// ⭐ Every OTHER JSON field on this entry, preserved verbatim.
    ///
    /// Without this, serde silently DROPS fields it does not know on the next
    /// re-serialize — so an older client that so much as opened and re-sealed a
    /// vault would delete a newer client's data, on a sync path where the oldest
    /// writer wins. See [`TotpVault::extra`].
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

/// The decrypted plaintext of a TOTP vault: a versioned list of [`TotpEntry`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TotpVault {
    /// Inner vault format version — what WROTE this vault. This build writes
    /// [`TOTP_VAULT_VERSION`]; readers tolerate other values and consult
    /// `min_reader_version` instead (see [`TOTP_VAULT_READER_VERSION`]).
    pub version: u8,
    /// ⭐ The minimum reader version required to open this vault SAFELY.
    ///
    /// Omitted (`None`) by this build, which writes nothing a version-1 reader
    /// cannot handle. A future writer that makes a genuinely incompatible change
    /// sets this, and older clients then refuse **precisely** — naming the version
    /// they would need — instead of refusing every future vault by a blanket
    /// version equality check. See [`TOTP_VAULT_READER_VERSION`] for the rule and
    /// why it fails closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_reader_version: Option<u8>,
    /// The stored TOTP entries.
    pub entries: Vec<TotpEntry>,
    /// ⭐ The REMOVE half of the vault's 2P-Set (Phase 61).
    ///
    /// A vault syncs as a sequence of whole SNAPSHOTS through an append-only
    /// op-log, and [`merge_vaults`] takes the UNION of every snapshot it can
    /// open. A union alone would resurrect every deleted entry the moment any
    /// device that still holds it pushes, so a delete has to be recorded
    /// positively. This is that record: an entry whose [`TotpEntry::uuid`]
    /// appears here is suppressed no matter how many snapshots still contain it.
    ///
    /// OMITTED entirely when empty, so a vault that has never had a delete is
    /// byte-identical to what earlier builds wrote.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tombstones: Vec<Tombstone>,
    /// ⭐ Every OTHER top-level JSON field, preserved verbatim (Phase 59).
    ///
    /// `#[serde(flatten)]` collects fields this build does not know about and
    /// writes them back unchanged, so an old client can open, edit and re-seal a
    /// vault written by a newer client **losslessly**.
    ///
    /// ⚠️ This is the whole point of the field, and it is easy to defeat by
    /// accident: any code that rebuilds a vault as `TotpVault { version, entries }`
    /// — or, in JavaScript, as `{ version: v.version, entries: [...] }` — throws
    /// the preserved data away again. The JS mirror
    /// (`sigil-wasm/totp-vault.mjs`) does the same job with an explicit
    /// rest-spread, and `test/schema-interop.mjs` proves both directions.
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

/// One removed entry, recorded so the removal survives a merge with a snapshot
/// that still contains it (Phase 61).
///
/// It carries the entry's `uuid` and nothing else that could identify the
/// account. ⚠️ For an entry created by this build the uuid is 128 random bits, so
/// a tombstone commits to **nothing** — not the label, not the issuer, not the
/// secret. For a LEGACY entry whose id was derived from its content
/// ([`sigil_core::entry_id`]) the tombstone is a commitment to that content, and
/// is therefore a confirmation oracle for anyone who can already open the vault
/// *and* guess the entry exactly. That is documented, bounded to entries written
/// before this build, and is the price of making a delete converge across the
/// migration boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tombstone {
    /// The [`TotpEntry::uuid`] of the entry that was removed.
    pub uuid: String,
    /// Unix seconds when the removal happened, from the CALLER's clock
    /// (`sigil-core` reads none, ADR 0007). ⭐ Informational: no merge decision
    /// branches on it — [`merge_vaults`] only keeps the smaller of two values, so
    /// a wrong or hostile clock cannot un-delete anything.
    ///
    /// ⭐ SO WHY WRITE IT AT ALL? It is the field a FUTURE compaction keys on.
    /// The remove-set never shrinks and nothing prunes it (see the tombstone
    /// growth limit above [`op_body_size_warning`]); the only safe prune rule is
    /// "drop tombstones older than a retention window every device has certainly
    /// synced within", and that needs a timestamp. Writing it today makes today's
    /// vaults compactable later. ⚠️ Nothing reads it yet — do not add a merge
    /// rule that does without revisiting the no-clock argument on [`merge_vaults`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<u64>,
    /// Every OTHER JSON field on this tombstone, preserved verbatim (same rule as
    /// [`TotpEntry::extra`]).
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

impl Default for TotpVault {
    fn default() -> Self {
        TotpVault {
            version: TOTP_VAULT_VERSION,
            min_reader_version: None,
            entries: Vec::new(),
            tombstones: Vec::new(),
            extra: std::collections::BTreeMap::new(),
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

/// Format 16 bytes of CALLER-SUPPLIED entropy as a lowercase RFC 4122 version-4
/// UUID string, for [`TotpEntry::uuid`].
///
/// Takes the randomness as an argument rather than drawing it, mirroring ADR
/// 0007's discipline: the browser mirror does exactly the same over
/// `crypto.getRandomValues`, and a pure function is testable with a fixed vector.
/// The version (4) and variant (RFC 4122) bits are set, so the output is a
/// well-formed UUID and not just hex.
///
/// ⚠️ The value is an identifier, NOT a secret and NOT a key.
#[must_use]
pub fn format_entry_uuid(random16: &[u8; 16]) -> String {
    let mut b = *random16;
    b[6] = (b[6] & 0x0f) | 0x40; // version 4
    b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
    let h = |r: &[u8]| -> String { r.iter().map(|x| format!("{x:02x}")).collect() };
    format!(
        "{}-{}-{}-{}-{}",
        h(&b[0..4]),
        h(&b[4..6]),
        h(&b[6..8]),
        h(&b[8..10]),
        h(&b[10..16])
    )
}

/// Draw a fresh [`TotpEntry::uuid`] from the OS RNG.
///
/// Native-only convenience over [`format_entry_uuid`]; this crate already links
/// `getrandom` (ADR 0002 keeps that out of the wasm-pure core). Browser clients
/// call `crypto.getRandomValues` and format it in JS instead.
///
/// # Errors
/// - [`CliError::Rng`] if the OS RNG fails.
pub fn random_entry_uuid() -> Result<String, CliError> {
    let mut b = [0u8; 16];
    fill_random(&mut b)?;
    Ok(format_entry_uuid(&b))
}

/// Build a [`TotpEntry`] from raw parts, base64-encoding the raw `secret` bytes,
/// and assign it a fresh random [`TotpEntry::uuid`].
///
/// Validates `digits` against the core's supported range up front (a bad digit
/// count would otherwise only surface later at code-generation time).
///
/// # Errors
/// - [`CliError::Totp`] if `digits`/`period` are out of range.
/// - [`CliError::Rng`] if the OS RNG fails while drawing the uuid.
pub fn new_totp_entry(
    label: &str,
    issuer: Option<String>,
    secret: &[u8],
    algorithm: OtpAlgorithm,
    digits: u32,
    period: u32,
) -> Result<TotpEntry, CliError> {
    let uuid = random_entry_uuid()?;
    new_totp_entry_with_uuid(label, issuer, secret, algorithm, digits, period, Some(uuid))
}

/// [`new_totp_entry`] with the entry id supplied by the caller.
///
/// Use this when the id must be deterministic (tests, a migration that carries
/// ids forward) or must be omitted entirely (`None`, matching an entry written
/// before the field existed).
///
/// # Errors
/// - [`CliError::Totp`] if `label` is empty or `digits`/`period` are out of range.
pub fn new_totp_entry_with_uuid(
    label: &str,
    issuer: Option<String>,
    secret: &[u8],
    algorithm: OtpAlgorithm,
    digits: u32,
    period: u32,
    uuid: Option<String>,
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
        uuid,
        extra: std::collections::BTreeMap::new(),
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

// ---------------------------------------------------------------------------
// ⭐⭐ ENTRY IDENTITY AND VAULT MERGE (Phase 61) — the fix for last-writer-wins.
//
// ⛔ THE DEFECT. A vault syncs as whole sealed SNAPSHOTS through an append-only
// op-log, and every client ADOPTED THE NEWEST ONE WHOLESALE. So: device A adds
// `github` and pushes; device B, which never pulled, adds `gitlab` and pushes.
// B's snapshot is now the tip, it has never seen `github`, and the moment any
// client adopts the tip that account is GONE. Both devices reported success.
// Reproduced end to end against a real sigild before this was written.
//
// ⭐ THE SHAPE OF THE FIX. A vault is a **2P-Set** (two-phase set) of entries
// keyed by `uuid`: `entries` is the add-set, `tombstones` is the remove-set, and
// `merge_vaults` is their union with the remove-set winning. That is the simplest
// CRDT that exists — commutative, associative and idempotent — so devices
// converge regardless of pull order, duplicate delivery or how many devices are
// involved. Boring on purpose.
//
// ⭐ NO CLOCK IS IN THE CORRECTNESS PATH. There is no Lamport counter, no vector
// clock, no per-entry revision and no timestamp tiebreak, because ENTRIES ARE
// IMMUTABLE: `add`, `import` and `remove` are the complete mutation surface
// across all four clients — there is no rename, no edit and no in-place field
// change anywhere. A uuid therefore names one fixed (label, issuer, secret,
// algorithm, digits, period) forever, so "which version of entry U wins" is a
// question that cannot be asked.
//
// ⛔⛔ THE ONE WAY THIS DESIGN GOES WRONG LATER: someone adds an EDIT. If a
// rename, a period change or an in-place secret update is ever added, this merge
// will silently keep whichever copy sorts higher. **An edit must be implemented
// as delete + add with a fresh uuid, or this merge is wrong.** The same warning
// is on the JS mirror, beside `uuid`.
// ---------------------------------------------------------------------------

/// The deterministic, content-derived id of `entry` — the id it gets when it has
/// no [`TotpEntry::uuid`] of its own.
///
/// ⭐ The derivation is [`sigil_core::entry_id`] and is **NOT mirrored**: the CLI
/// and the desktop call it directly and the browsers reach the same bytes through
/// a one-line wasm shell. A drift here would be invisible — it produces a vault
/// that opens fine everywhere and merely duplicates or mis-suppresses entries.
///
/// The stored `secret` is base64; the transcript commits to the DECODED key
/// bytes. ⚠️ A secret that is not valid base64 falls back to the raw stored
/// string's UTF-8 bytes, so this function is TOTAL — a corrupt entry must not be
/// able to abort a merge. The JS mirror does exactly the same.
#[must_use]
pub fn entry_content_id(entry: &TotpEntry, disambiguator: u32) -> String {
    let secret = entry
        .secret_bytes()
        .unwrap_or_else(|_| entry.secret.as_bytes().to_vec());
    sigil_core::entry_id(
        entry.issuer.as_deref().unwrap_or(""),
        &entry.label,
        &secret,
        &entry.algorithm,
        entry.digits,
        entry.period,
        disambiguator,
    )
}

/// The identity this entry is MERGED by: its own `uuid` when it has one,
/// otherwise its content-derived id ([`entry_content_id`]).
///
/// ⭐ This answers **"which entry is this?"** and nothing else. It is deliberately
/// NOT the question the import path asks — see [`entry_fingerprint`].
#[must_use]
pub fn entry_identity(entry: &TotpEntry) -> String {
    match &entry.uuid {
        Some(u) if !u.is_empty() => u.clone(),
        _ => entry_content_id(entry, 0),
    }
}

/// The content FINGERPRINT of an entry — [`entry_content_id`] with the
/// disambiguator fixed at `0`, **ignoring any `uuid` the entry carries**.
///
/// ⭐⭐ TWO DIFFERENT JOBS, TWO DIFFERENT MECHANISMS, and conflating them is a
/// real bug this code has already had. [`entry_identity`] answers *"which entry
/// is this?"* (a uuid); this answers *"have I already got this account?"* (its
/// content). Import and `add` must ask the SECOND question: a freshly imported
/// entry carries no id at all, while the copy already in the vault carries a
/// RANDOM one, so comparing identities would never match and re-importing the
/// same Google Authenticator export would duplicate every account in it.
///
/// It commits to `(issuer, label, secret, algorithm, digits, period)` — exactly
/// what makes two rows the same account.
#[must_use]
pub fn entry_fingerprint(entry: &TotpEntry) -> String {
    entry_content_id(entry, 0)
}

/// Canonical JSON for one entry — used ONLY as a deterministic tiebreak when two
/// snapshots claim the same id with different content, so that two devices
/// merging in different orders still agree byte for byte.
///
/// ⚠️ It goes through `serde_json::to_value` on purpose: `serde_json::Map` is a
/// `BTreeMap` by default, so the keys come out SORTED — which is what the JS
/// mirror's `sortKeysDeep` produces. If the two sides ordered keys differently
/// they could pick DIFFERENT winners for the same conflict and never converge.
fn canonical_entry(entry: &TotpEntry) -> String {
    serde_json::to_value(entry)
        .ok()
        .and_then(|v| serde_json::to_string(&v).ok())
        .unwrap_or_default()
}

/// Canonical JSON for one arbitrary (unknown, forward-compatibility) value — the
/// ordering key used to combine `extra` maps commutatively, at both the vault and
/// the tombstone level.
///
/// ⚠️ Keys come out SORTED because `serde_json::Value`'s map is a `BTreeMap`.
/// The JS mirror must sort too (`sortKeysDeep`), or the two clients could pick
/// different winners for the same unknown key and never converge.
fn canonical_json(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_default()
}

/// ⭐ Give every entry a stable id, deterministically and idempotently.
///
/// Runs on every read path, before anything else touches the vault. For each
/// entry with no `uuid`, the id is DERIVED from the entry's content, so two
/// devices holding copies of the same pre-Phase-61 vault arrive at the **same**
/// ids without either knowing the other exists — which is the whole reason the
/// migration id is derived rather than random. A random id here would duplicate
/// every account in every existing multi-device vault on first sync, and would
/// make a delete performed on one device unable to ever suppress the other's copy.
///
/// A within-vault collision (two byte-identical legacy entries, which nothing in
/// this repo writes but a hand-edited file can contain) is disambiguated with an
/// incrementing counter folded into the transcript — still deterministic, so the
/// two devices still agree.
///
/// It does **not** reorder, filter, rebuild or otherwise touch the entries; it
/// only fills in a missing field.
pub fn normalize_vault(vault: &mut TotpVault) {
    let mut seen: std::collections::BTreeSet<String> = vault
        .entries
        .iter()
        .filter_map(|e| e.uuid.clone())
        .filter(|u| !u.is_empty())
        .collect();
    for entry in &mut vault.entries {
        if entry.uuid.as_deref().is_some_and(|u| !u.is_empty()) {
            continue;
        }
        let mut n = 0u32;
        let mut id = entry_content_id(entry, n);
        while seen.contains(&id) {
            n += 1;
            id = entry_content_id(entry, n);
        }
        seen.insert(id.clone());
        entry.uuid = Some(id);
    }
}

/// Put a normalized vault into its canonical form: entries sorted by
/// `(issuer, label, uuid)` and tombstones by `uuid`.
///
/// ⭐ This is what makes convergence a TESTABLE EQUALITY rather than a claim: two
/// devices that have seen the same set of snapshots serialize to byte-identical
/// plaintext. The cost is that a first merge reorders a hand-arranged vault once.
fn canonicalize_vault(vault: &mut TotpVault) {
    // ⭐ Sort by `uuid` ALONE, and deliberately not by (issuer, label, uuid).
    // A uuid is ASCII hex, so Rust's byte-wise `Ord` and JavaScript's UTF-16
    // comparison agree EXACTLY. Sorting on user text would not: the two languages
    // order some non-ASCII strings differently, and the two clients would then
    // produce different canonical bytes for the same set and never agree that they
    // had converged. Display order is each client's own business.
    vault.entries.sort_by_key(entry_identity);
    vault.tombstones.sort_by(|a, b| a.uuid.cmp(&b.uuid));
    vault.tombstones.dedup_by(|a, b| a.uuid == b.uuid);
}

/// What a merge did, for the caller to report to a human.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Entries present in the merged vault that were not in `local`.
    pub added: usize,
    /// Entries dropped because a tombstone names them.
    pub removed: usize,
    /// Tombstones in the merged vault that were not in `local`.
    pub tombstones_added: usize,
    /// `true` when the merged vault differs from `local` (canonically).
    pub changed: bool,
    /// Ids claimed by two DIFFERENT entries. Nothing is dropped — the
    /// deterministic winner is kept and this names the id so a human can look.
    pub conflicts: Vec<String>,
}

/// ⭐ Join two vault snapshots. Commutative, associative and idempotent.
///
/// ```text
///   entries    = (local.entries ∪ remote.entries)  keyed by identity
///   tombstones = (local.tombstones ∪ remote.tombstones)  keyed by uuid
///   result     = entries MINUS every id named by a tombstone      // DELETE WINS
/// ```
///
/// **Delete wins unconditionally**, and that is safe here precisely because a
/// genuine re-add draws a FRESH random uuid — so a "re-add" of the same id is not
/// a user action at all, it is a stale snapshot or a hostile writer, and it should
/// lose. This dodges the textbook 2P-Set flaw ("a removed element can never come
/// back") by construction rather than papering over it.
///
/// A `deleted_at` is merged by taking the SMALLER value, so a later view of a
/// delete never postpones it; nothing else reads the field.
///
/// Two entries claiming the same id with different content keep the
/// lexicographically greater canonical JSON — **deterministic and
/// order-independent**, unlike "local wins", which would break convergence.
///
/// ⭐⭐ EVERY FIELD USES AN ORDER-INDEPENDENT RULE, INCLUDING THE UNKNOWN ONES.
/// The four combining rules are `max` (version, `min_reader_version`, unknown
/// `extra` at BOTH the vault and the TOMBSTONE level, and the entry tiebreak),
/// `min` (`deleted_at`) and set union (entries, tombstones) — all commutative and
/// associative, so `merge(a,b) == merge(b,a)` byte for byte with no exception.
///
/// ⭐ AND THE SAME BYTES AS THE JS MIRROR. Byte-equality here is nearly free —
/// `extra` is a [`std::collections::BTreeMap`], so serde writes it sorted no
/// matter what order the keys were inserted in. JavaScript has no such default:
/// its objects are INSERTION-ordered, and `sigil-wasm/totp-vault.mjs` had to
/// grow an explicit canonical writer (`vaultToJson`) to match this function
/// byte for byte. That writer hard-codes the field order of [`TotpVault`],
/// [`TotpEntry`] and [`Tombstone`] as declared **in this file**, so ⚠️ ADDING A
/// FIELD TO ONE OF THOSE STRUCTS — or reordering one — SILENTLY DESYNCHRONISES
/// THE TWO CLIENTS' BYTES unless the JS arrays are updated in the same change.
/// The BYTES section of `sigil-wasm/test/merge-interop.mjs` compares this
/// binary's actual output against the JS writer's and is the guard.
///
/// ⚠️ THAT WAS NOT ALWAYS TRUE, and the exception was real: tombstone-level
/// unknown fields used to merge FIRST-SEEN-WINS (`extra.entry(k).or_insert(…)`
/// here, `{ ...t, ...prev }` in the JS mirror), so two vaults whose tombstones
/// shared a uuid but carried different values for an unknown key did NOT
/// converge — while the doc comment claimed unqualified commutativity. It is
/// fixed rather than merely documented, because a forward-compatibility field
/// (ADR 0047) is exactly the kind of thing a future version writes and a current
/// one must carry through a merge unchanged, in either order.
/// The property test `merge_is_order_independent_over_generated_vaults` fails if
/// this regresses.
#[must_use]
pub fn merge_vaults(local: &TotpVault, remote: &TotpVault) -> (TotpVault, MergeReport) {
    let mut a = local.clone();
    let mut b = remote.clone();
    normalize_vault(&mut a);
    normalize_vault(&mut b);
    canonicalize_vault(&mut a);
    canonicalize_vault(&mut b);

    // 1) Remove-set: union by uuid, keeping the smaller deleted_at.
    let mut tombs: std::collections::BTreeMap<String, Tombstone> =
        std::collections::BTreeMap::new();
    for t in a.tombstones.iter().chain(b.tombstones.iter()) {
        match tombs.get_mut(&t.uuid) {
            None => {
                tombs.insert(t.uuid.clone(), t.clone());
            }
            Some(existing) => {
                existing.deleted_at = match (existing.deleted_at, t.deleted_at) {
                    (Some(x), Some(y)) => Some(x.min(y)),
                    (Some(x), None) => Some(x),
                    (None, y) => y,
                };
                // ⭐ The SAME commutative rule the vault level uses: keep the
                // lexicographically greater canonical JSON. ⚠️ This was
                // `extra.entry(k).or_insert_with(…)` — FIRST-SEEN-WINS — which
                // made `merge(a,b) != merge(b,a)` whenever two tombstones shared
                // a uuid and disagreed about an unknown key, contradicting this
                // function's own commutativity claim. `max` is the only rule
                // here that is both deterministic and order-independent.
                for (k, v) in &t.extra {
                    let replace = match existing.extra.get(k) {
                        None => true,
                        Some(cur) => canonical_json(v) > canonical_json(cur),
                    };
                    if replace {
                        existing.extra.insert(k.clone(), v.clone());
                    }
                }
            }
        }
    }

    // 2) Add-set: union by identity.
    let mut adds: std::collections::BTreeMap<String, TotpEntry> = std::collections::BTreeMap::new();
    let mut conflicts: Vec<String> = Vec::new();
    for e in a.entries.iter().chain(b.entries.iter()) {
        let id = entry_identity(e);
        match adds.get(&id) {
            None => {
                adds.insert(id, e.clone());
            }
            Some(existing) if existing == e => {}
            Some(existing) => {
                if !conflicts.contains(&id) {
                    conflicts.push(id.clone());
                }
                // Deterministic, order-independent tiebreak. NOT "the newest" —
                // there is no trustworthy newest on an untrusted op-log.
                if canonical_entry(e) > canonical_entry(existing) {
                    adds.insert(id, e.clone());
                }
            }
        }
    }

    // 3) Delete wins.
    let removed = adds.keys().filter(|id| tombs.contains_key(*id)).count();
    let entries: Vec<TotpEntry> = adds
        .into_iter()
        .filter(|(id, _)| !tombs.contains_key(id))
        .map(|(_, e)| e)
        .collect();

    // 4) Unknown top-level fields and min_reader_version: deterministic, and it
    //    FAILS CLOSED (the higher demand wins) so a merge can never make a vault
    //    look more readable than either input claimed.
    let mut extra = a.extra.clone();
    for (k, v) in &b.extra {
        match extra.get(k) {
            None => {
                extra.insert(k.clone(), v.clone());
            }
            Some(existing) => {
                if canonical_json(v) > canonical_json(existing) {
                    extra.insert(k.clone(), v.clone());
                }
            }
        }
    }
    let min_reader_version = match (a.min_reader_version, b.min_reader_version) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (Some(x), None) | (None, Some(x)) => Some(x),
        (None, None) => None,
    };

    let mut merged = TotpVault {
        version: a.version.max(b.version),
        min_reader_version,
        entries,
        tombstones: tombs.into_values().collect(),
        extra,
    };
    canonicalize_vault(&mut merged);

    let local_ids: std::collections::BTreeSet<String> =
        a.entries.iter().map(entry_identity).collect();
    let local_tombs: std::collections::BTreeSet<&String> =
        a.tombstones.iter().map(|t| &t.uuid).collect();
    let report = MergeReport {
        added: merged
            .entries
            .iter()
            .filter(|e| !local_ids.contains(&entry_identity(e)))
            .count(),
        removed,
        tombstones_added: merged
            .tombstones
            .iter()
            .filter(|t| !local_tombs.contains(&t.uuid))
            .count(),
        changed: merged != a,
        conflicts,
    };
    (merged, report)
}

/// What a fold over a run of op-log snapshots did.
#[derive(Debug, Clone, Default)]
pub struct SyncReport {
    /// Ops whose container this secret opened and which were merged in.
    pub applied: usize,
    /// Ops that could not be opened, with the reason. ⚠️ Never fatal and never
    /// silent: an op sealed under a superseded password or from before a
    /// `vault rekey` is skipped and NAMED. Nothing is destroyed — it stays in the
    /// log — but the merged snapshot is then not a superset of the log.
    pub skipped: Vec<(u64, String)>,
    /// The highest sequence number seen (a cursor for the next call).
    pub tip: u64,
    /// The accumulated effect of every merge.
    pub merge: MergeReport,
}

/// ⭐ Fold EVERY op in `ops` into `local`, instead of adopting the newest one.
///
/// This is the entire fix, and it costs nothing on the wire: the op-log already
/// stores every snapshot, append-only, and the clients were reading one row of a
/// table that had the answer in it the whole time. A free consequence is that it
/// **retroactively recovers data the old behaviour already shadowed** — an entry
/// that only ever reached op 1 comes back.
///
/// An op that will not open under `secret` is skipped and named, never fatal.
#[must_use]
pub fn merge_ops_into(
    local: &TotpVault,
    secret: &[u8],
    ops: &[PulledOp],
) -> (TotpVault, SyncReport) {
    let mut acc = local.clone();
    let mut report = SyncReport::default();
    for op in ops {
        report.tip = report.tip.max(op.seq);
        match open_vault(secret, &op.blob) {
            Ok(v) => {
                let (merged, m) = merge_vaults(&acc, &v);
                acc = merged;
                report.applied += 1;
                report.merge.added += m.added;
                report.merge.removed += m.removed;
                report.merge.tombstones_added += m.tombstones_added;
                report.merge.changed |= m.changed;
                for c in m.conflicts {
                    if !report.merge.conflicts.contains(&c) {
                        report.merge.conflicts.push(c);
                    }
                }
            }
            Err(e) => report.skipped.push((op.seq, e.to_string())),
        }
    }
    // Normalizing + canonicalizing `local` alone (no ops at all) can still change
    // it, so recompute `changed` against the input rather than trusting the last
    // per-op verdict.
    let mut base = local.clone();
    normalize_vault(&mut base);
    canonicalize_vault(&mut base);
    report.merge.changed = acc != base || acc != *local;
    (acc, report)
}

// ---------------------------------------------------------------------------
// ⛔⛔ THE TOMBSTONE GROWTH LIMIT — the honest record of an UNSOLVED problem.
//
// A vault is a 2P-Set, and the remove-set NEVER SHRINKS. Every `sigil totp
// remove` appends a tombstone (~55-95 bytes of JSON: a uuid, an optional
// `deleted_at`, punctuation) that must be carried forever, because dropping it
// resurrects the entry on the next merge with any device that still holds a
// snapshot from before the delete. There is NO COMPACTION PATH in this repo:
// `sigil totp compact` does not exist, and nothing anywhere prunes a tombstone.
//
// ⛔ THE HARD STOP. `sigild` caps a single op body at 64 KiB
// (`maxOpsBodyBytes`, sigild/internal/api/middleware.go) and answers **413**
// above it. The op body is the SEALED CONTAINER, so the ceiling is on
// ciphertext: roughly the JSON plaintext plus the ~100-byte `SIGILcli` header
// and the AEAD tag. Past the cap `push` fails and THERE IS NO SUPPORTED WAY TO
// SHRINK IT — a user who discovers this at the 413 has already lost the ability
// to sync, which is precisely the outcome this phase exists to prevent.
//
// ⭐ WHAT IS ACTUALLY BUILT HERE: a WARNING, not a fix. Every client that seals
// a vault for push calls [`op_body_size_warning`] first and tells the human
// while there is still room to act (export, or start a fresh vault id). That is
// strictly less than compaction and is not pretended to be more.
//
// ⭐ WHY `Tombstone::deleted_at` EXISTS AT ALL, given that no merge decision
// branches on it: it is the field a future compaction keys on. The only safe
// prune rule is "drop tombstones older than a retention window every device is
// guaranteed to have synced within", and that needs a timestamp. It is written
// today so that the vaults being written today are compactable later; it is
// merged by `min` so a wrong or hostile clock can only make a delete look
// EARLIER, never postpone it. Nothing reads it yet. Do not add a merge rule that
// does without revisiting the "no clock in the correctness path" argument above.
// ---------------------------------------------------------------------------

/// The largest op body `sigild` accepts: **64 KiB**.
///
/// ⚠️ MIRRORED — NOT SHARED — from `maxOpsBodyBytes` in
/// `sigild/internal/api/middleware.go`, and from `MAX_OP_BODY_BYTES` in
/// `sigil-wasm/totp-vault.mjs`. A drift does not fail loudly; it just makes the
/// warning fire at the wrong size. `sigil-wasm/test/merge-guard.mjs` asserts all
/// three agree.
pub const MAX_OP_BODY_BYTES: usize = 64 << 10;

/// The size at which a client must start warning: **75%** of
/// [`MAX_OP_BODY_BYTES`] (48 KiB).
///
/// Chosen so the warning arrives while a vault still has room for hundreds more
/// tombstones, not on the last one.
pub const OP_BODY_WARN_BYTES: usize = MAX_OP_BODY_BYTES / 4 * 3;

/// A human-readable warning when a sealed container is close to — or past — the
/// server's 64 KiB op-body cap, or `None` when it is comfortably below.
///
/// ⭐ Callers must print this BEFORE pushing, so the human hears about it while
/// the push still works. The `>= MAX` case is worded differently on purpose: at
/// that point the next `push` is a `413` and the advice changes from "plan" to
/// "this will now fail".
#[must_use]
pub fn op_body_size_warning(container_len: usize) -> Option<String> {
    if container_len >= MAX_OP_BODY_BYTES {
        return Some(format!(
            "this vault seals to {container_len} bytes, over the server's {MAX_OP_BODY_BYTES}-byte \
             op limit — `push`/`sync` will be REFUSED with HTTP 413. Tombstones (one per removed \
             entry) are never pruned and there is no compaction command; export with `sigil totp \
             export` and start a fresh vault id"
        ));
    }
    if container_len >= OP_BODY_WARN_BYTES {
        let pct = container_len * 100 / MAX_OP_BODY_BYTES;
        return Some(format!(
            "this vault seals to {container_len} bytes — {pct}% of the server's \
             {MAX_OP_BODY_BYTES}-byte op limit. Tombstones (one per removed entry) are never \
             pruned and there is no compaction command, so this only grows; past the limit \
             `push`/`sync` is refused with HTTP 413"
        ));
    }
    None
}

impl TotpVault {
    /// Find an entry by exact label.
    ///
    /// ⚠️ Labels are **no longer unique** (that is the fix for the Google
    /// Authenticator import defect: `work` at two different issuers is two
    /// accounts). This returns the FIRST match; use [`TotpVault::find_all`] when
    /// ambiguity matters, and [`TotpVault::find_by_uuid`] when it must not.
    #[must_use]
    pub fn find(&self, label: &str) -> Option<&TotpEntry> {
        self.entries.iter().find(|e| e.label == label)
    }

    /// Every entry with exactly this label.
    #[must_use]
    pub fn find_all(&self, label: &str) -> Vec<&TotpEntry> {
        self.entries.iter().filter(|e| e.label == label).collect()
    }

    /// Find an entry by its identity, or by a unique PREFIX of it (so a human can
    /// type the first few characters of a uuid).
    #[must_use]
    pub fn find_by_uuid(&self, id: &str) -> Option<&TotpEntry> {
        if id.is_empty() {
            return None;
        }
        let exact = self.entries.iter().find(|e| entry_identity(e) == id);
        if exact.is_some() {
            return exact;
        }
        let mut it = self
            .entries
            .iter()
            .filter(|e| entry_identity(e).starts_with(id));
        match (it.next(), it.next()) {
            (Some(e), None) => Some(e),
            _ => None,
        }
    }

    /// Add `entry`, rejecting an account already in the vault.
    ///
    /// ⚠️ It no longer rejects a duplicate LABEL. `work` at GitHub and `work` at
    /// GitLab are two accounts — refusing the second was exactly the Google
    /// Authenticator import defect this fixes.
    ///
    /// ⭐ The comparison is [`entry_fingerprint`] (the entry's CONTENT), not
    /// [`entry_identity`]. A candidate typically carries no `uuid` while the copy
    /// already in the vault carries a random one, so comparing identities would
    /// never match and adding the same account twice would silently succeed.
    /// A duplicate `uuid` is refused too, since two entries sharing an id is a
    /// merge conflict waiting to happen.
    ///
    /// # Errors
    /// - [`CliError::Totp`] if that account (or that id) is already present.
    pub fn add(&mut self, entry: TotpEntry) -> Result<(), CliError> {
        let fp = entry_fingerprint(&entry);
        let id = entry_identity(&entry);
        if self
            .entries
            .iter()
            .any(|e| entry_fingerprint(e) == fp || entry_identity(e) == id)
        {
            return Err(CliError::Totp(format!(
                "this account is already in the vault ({}{})",
                entry
                    .issuer
                    .as_deref()
                    .map(|i| format!("{i}: "))
                    .unwrap_or_default(),
                entry.label
            )));
        }
        self.entries.push(entry);
        Ok(())
    }

    /// Remove the entry with `label` **and record a tombstone**, returning it.
    ///
    /// [`TotpVault::remove_at`] with no timestamp. `sigil-core` reads no clock, so
    /// a caller that has one should pass it.
    ///
    /// # Errors
    /// - [`CliError::Totp`] if no entry has that label, or if more than one does.
    pub fn remove(&mut self, label: &str) -> Result<TotpEntry, CliError> {
        self.remove_at(label, None)
    }

    /// Remove the entry with `label`, recording a tombstone stamped `deleted_at`.
    ///
    /// ⚠️ An AMBIGUOUS label is refused, naming the candidates, rather than
    /// silently removing the first match — silently picking one is how a user
    /// deletes the wrong account.
    ///
    /// # Errors
    /// - [`CliError::Totp`] if no entry has that label, or if more than one does.
    pub fn remove_at(
        &mut self,
        label: &str,
        deleted_at: Option<u64>,
    ) -> Result<TotpEntry, CliError> {
        let matches: Vec<usize> = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.label == label)
            .map(|(i, _)| i)
            .collect();
        match matches.len() {
            0 => Err(CliError::Totp(format!("no entry labelled {label:?}"))),
            1 => self.remove_index(matches[0], deleted_at),
            _ => Err(CliError::Totp(format!(
                "{} entries are labelled {label:?} — name one with --id <prefix>:\n{}",
                matches.len(),
                self.candidate_lines(&matches)
            ))),
        }
    }

    /// Remove the entry whose identity is `id` (or a unique prefix of it),
    /// recording a tombstone.
    ///
    /// # Errors
    /// - [`CliError::Totp`] if nothing matches, or the prefix is ambiguous.
    pub fn remove_by_uuid(
        &mut self,
        id: &str,
        deleted_at: Option<u64>,
    ) -> Result<TotpEntry, CliError> {
        let want = self
            .find_by_uuid(id)
            .map(entry_identity)
            .ok_or_else(|| CliError::Totp(format!("no entry with id {id:?}")))?;
        let index = self
            .entries
            .iter()
            .position(|e| entry_identity(e) == want)
            .ok_or_else(|| CliError::Totp(format!("no entry with id {id:?}")))?;
        self.remove_index(index, deleted_at)
    }

    /// The shared tail of both removes: drop the entry AND record the tombstone.
    /// ⭐ These two must never come apart — a removal that writes no tombstone is
    /// exactly the pre-Phase-61 behaviour, and a merge will resurrect it.
    fn remove_index(
        &mut self,
        index: usize,
        deleted_at: Option<u64>,
    ) -> Result<TotpEntry, CliError> {
        let entry = self.entries.remove(index);
        let uuid = entry_identity(&entry);
        if !self.tombstones.iter().any(|t| t.uuid == uuid) {
            self.tombstones.push(Tombstone {
                uuid,
                deleted_at,
                extra: std::collections::BTreeMap::new(),
            });
        }
        Ok(entry)
    }

    /// `issuer: label  (id abcd1234)` lines for an ambiguity message.
    fn candidate_lines(&self, indices: &[usize]) -> String {
        indices
            .iter()
            .map(|i| {
                let e = &self.entries[*i];
                let id = entry_identity(e);
                format!(
                    "  {}{}  (id {})",
                    e.issuer
                        .as_deref()
                        .map(|s| format!("{s}: "))
                        .unwrap_or_default(),
                    e.label,
                    &id[..8.min(id.len())]
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
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
    let mut vault: TotpVault = serde_json::from_slice(&plaintext)
        .map_err(|e| CliError::Totp(format!("decrypted vault is not valid JSON: {e}")))?;
    check_vault_readable(&vault)?;
    // ⭐ Phase 61: every read path assigns a stable id to any entry that has none,
    // deterministically, so two devices holding the same legacy vault agree on
    // those ids without communicating. See `normalize_vault`.
    normalize_vault(&mut vault);
    Ok(vault)
}

/// ⭐ The forward-compatibility gate, replacing the old blanket
/// `version != TOTP_VAULT_VERSION` refusal.
///
/// A vault is readable when the reader version it DEMANDS is one this build can
/// satisfy. The demand is `min_reader_version` when stated, and otherwise the
/// vault's own `version` — which makes an un-annotated future vault fail closed,
/// exactly as it did before, while an explicitly-additive one (`version: 2,
/// min_reader_version: 1`) opens.
///
/// See [`TOTP_VAULT_READER_VERSION`] for why the two knobs are separate.
///
/// # Errors
/// - [`CliError::Totp`] naming the reader version required and the one we have.
pub fn check_vault_readable(vault: &TotpVault) -> Result<(), CliError> {
    let required = vault.min_reader_version.unwrap_or(vault.version);
    if required > TOTP_VAULT_READER_VERSION {
        return Err(CliError::Totp(format!(
            "this vault needs a reader that understands schema version {required}, \
             and this build understands {TOTP_VAULT_READER_VERSION} \
             (the vault was written by version {}). Upgrade the client that reads it — \
             opening it here could silently discard data it does not understand",
            vault.version
        )));
    }
    Ok(())
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

/// ⭐ The CONTEXT a vault-key envelope is bound to. Both sides MUST build the
/// identical value or the AEAD refuses to open — which is the point.
///
/// It answers the four questions a fixed AAD could not: *what is this for*
/// (purpose), *which vault*, *addressed to whom*, and *from whom*. Byte layout
/// is single-sourced in `sigil_core::vault_key_wrap_aad`.
///
/// ⚠️ The three ids are positional. `new` validates their shapes, but it cannot
/// tell a swapped recipient/sender pair from a legitimate one — the AEAD will,
/// on the other side, by refusing to open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultKeyWrapContext {
    vault_id: String,
    recipient_device_id: String,
    sender_device_id: String,
}

impl VaultKeyWrapContext {
    /// Build a context, validating that each identifier is a shape this CLI is
    /// willing to put in a URL (non-empty, no `/`, no whitespace).
    ///
    /// # Errors
    /// - [`CliError::BadVault`] / [`CliError::Key`] for a malformed identifier.
    pub fn new(
        vault_id: &str,
        recipient_device_id: &str,
        sender_device_id: &str,
    ) -> Result<Self, CliError> {
        check_vault(vault_id)?;
        check_device_id(recipient_device_id)?;
        check_device_id(sender_device_id)?;
        Ok(Self {
            vault_id: vault_id.to_string(),
            recipient_device_id: recipient_device_id.to_string(),
            sender_device_id: sender_device_id.to_string(),
        })
    }

    /// The vault this envelope belongs to.
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }
    /// The device the envelope is addressed to.
    pub fn recipient_device_id(&self) -> &str {
        &self.recipient_device_id
    }
    /// The device that deposited (or will deposit) it.
    pub fn sender_device_id(&self) -> &str {
        &self.sender_device_id
    }

    /// The exact additional-authenticated-data bytes.
    pub fn aad(&self) -> Vec<u8> {
        vault_key_wrap_aad(
            &self.vault_id,
            &self.recipient_device_id,
            &self.sender_device_id,
        )
    }
}

/// The SENDING half of a wrap: which device we are, and the hybrid SECRET
/// identity that proves it.
///
/// Bundled into one value so a call site cannot pass a device id belonging to
/// one identity and the secret of another — the two must travel together.
///
/// ⚠️ Deliberately NOT `Debug`: [`HybridSecretIdentity`]'s own `Debug` prints its
/// base64 secret, and nothing here should make that easier to reach.
#[derive(Clone)]
pub struct SenderIdentity {
    /// This device's server-assigned id.
    pub device_id: String,
    /// This device's hybrid SECRET identity (X25519 secret + ML-KEM seed).
    pub hybrid_secret: HybridSecretIdentity,
}

impl SenderIdentity {
    /// Build a sender identity from a device id and its secret hybrid identity.
    ///
    /// # Errors
    /// - [`CliError::Key`] if `device_id` is malformed.
    pub fn new(device_id: &str, hybrid_secret: HybridSecretIdentity) -> Result<Self, CliError> {
        check_device_id(device_id)?;
        Ok(Self {
            device_id: device_id.to_string(),
            hybrid_secret,
        })
    }

    /// This sender's X25519 SECRET scalar — the material that authenticates it.
    fn x25519_secret(&self) -> Result<[u8; X25519_SECRET_KEY_LEN], CliError> {
        Ok(self.hybrid_secret.decode()?.x25519_secret)
    }

    /// This sender's X25519 PUBLIC key, derived locally from the secret.
    pub fn x25519_public_key(&self) -> Result<[u8; X25519_PUBLIC_KEY_LEN], CliError> {
        Ok(x25519_public_key(&self.x25519_secret()?))
    }
}

/// ⭐ WRAP a vault key to a recipient's hybrid public identity, AUTHENTICATED as
/// `sender` and BOUND to `ctx`.
///
/// Fresh ephemeral entropy (an X25519 secret, an ML-KEM-768 coin, and an AEAD
/// nonce) is drawn from the OS CSPRNG on EVERY call, so no two wraps of the same
/// key reuse randomness.
///
/// ⚠️ `ctx.sender_device_id()` MUST be `sender.device_id` — the caller says who
/// it is twice, once for the AAD (which the recipient checks) and once for the
/// key material (which the AEAD checks). They are compared here so a mismatch is
/// a local error rather than an envelope that nobody can open.
///
/// # Errors
/// - [`CliError::Sharing`] if `ctx` names a different sender than `sender`.
/// - [`CliError::Identity`] if either identity does not decode.
/// - [`CliError::Rng`] / [`CliError::HybridSeal`] from the underlying seal.
pub fn wrap_vault_key(
    sender: &SenderIdentity,
    recipient: &HybridPublicIdentity,
    ctx: &VaultKeyWrapContext,
    key: &[u8; VAULT_KEY_LEN],
) -> Result<Vec<u8>, CliError> {
    if ctx.sender_device_id() != sender.device_id {
        return Err(CliError::Sharing(format!(
            "wrap context names sender {:?} but the signing identity is {:?}",
            ctx.sender_device_id(),
            sender.device_id
        )));
    }
    let decoded = recipient.decode()?;
    hybrid_auth_seal_to_container(&sender.x25519_secret()?, &decoded, &ctx.aad(), key)
}

/// ⭐ UNWRAP an envelope with this device's hybrid SECRET identity — but ONLY as
/// a record from `sender`, and ONLY under `ctx`.
///
/// Three checks, in this order, and every one of them is load-bearing:
///
///   1. the container must be AUTHENTICATED (version 2). A version-1 container
///      is [`CliError::WrongEnvelopeKind`] — it carries no sender at all;
///   2. the AEAD must authenticate under the shared secret derived with
///      `sender`'s **static X25519 public key**. A forger who has only public
///      material cannot produce one, so a wrong or forged sender fails HERE, at
///      the AEAD, not at a string comparison that could be bypassed;
///   3. the recovered plaintext must be exactly [`VAULT_KEY_LEN`] bytes.
///
/// ⭐ The sender arrives as a [`VerifiedSender`], which only
/// [`verify_sender_for_unwrap`] and [`VerifiedSender::from_local`] can build —
/// the same type-gate pattern as [`VerifiedRecipient`] on the wrap side. A
/// caller cannot reach this function with a key it pulled straight off the wire.
///
/// # Errors
/// - [`CliError::WrongEnvelopeKind`] for a legacy/anonymous envelope.
/// - [`CliError::Identity`] if an identity does not decode.
/// - [`CliError::HybridSeal`] on a wrong recipient, a WRONG SENDER, a tampered
///   envelope, or a mismatched context (no plaintext is leaked).
/// - [`CliError::Sharing`] if the envelope opened but did not hold a
///   [`VAULT_KEY_LEN`]-byte key.
pub fn unwrap_vault_key(
    identity: &HybridSecretIdentity,
    sender: &VerifiedSender,
    ctx: &VaultKeyWrapContext,
    envelope: &[u8],
) -> Result<[u8; VAULT_KEY_LEN], CliError> {
    if ctx.sender_device_id() != sender.device_id() {
        return Err(CliError::Sharing(format!(
            "unwrap context names sender {:?} but the verified sender is {:?}",
            ctx.sender_device_id(),
            sender.device_id()
        )));
    }
    let decoded = identity.decode()?;
    let plaintext =
        hybrid_auth_open_container(&decoded, &sender.x25519_public_key()?, &ctx.aad(), envelope)?;
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
    /// WHERE this pin came from, when it was not an ordinary server fetch.
    ///
    /// The only value written today is [`PIN_ORIGIN_RECOVERY_KIT`] (Phase 54),
    /// recording that the key was DERIVED locally from a recovery secret and
    /// pinned WITHOUT ever asking the server — the one pin in the system that
    /// cannot have been poisoned by a key substitution, and the marker that lets
    /// `vault rotate` say "this is your recovery kit" instead of "unknown
    /// recipient".
    ///
    /// ADDITIVE and OPTIONAL: it is omitted when absent, so a store written by
    /// an older client parses unchanged and this one writes the shape it always
    /// did unless a kit is involved. The pin-store VERSION is deliberately NOT
    /// bumped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
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
    origin: Option<String>,
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
        origin,
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
    store.pins.insert(
        device_id.to_string(),
        make_pin(device_id, identity, 0, None)?,
    );
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
    // A deliberate re-pin replaces a DERIVED pin with a fetched one, so the
    // `origin` marker is dropped: it would no longer be true.
    let pin = make_pin(device_id, identity, repins, None)?;
    let new_number = pin.safety_number.clone();
    store.version = HYBRID_PIN_STORE_VERSION;
    store.pins.insert(device_id.to_string(), pin);
    save_pins(pins_path, &store)?;
    Ok((previous.map(|p| p.safety_number), new_number))
}

// ⚠️ `fetch_hybrid_key_pinned` USED TO LIVE HERE and is DELETED ON PURPOSE
// (Phase 57). It was ADR 0038's choke point — fetch a hybrid public key and
// pin-check it in one call — and Phase 54 SUPERSEDED it with
// `verify_recipient_for_wrap`, which additionally refuses an unverified recovery
// kit and honours a caller-supplied safety number. It then sat here with ZERO
// callers and zero tests while the docs still recommended it by name: a public
// `pub fn` that fetches-and-pins WITHOUT the recovery-kit refusal is a
// ready-made bypass of the `VerifiedRecipient` type gate for whoever reaches for
// the familiar name next. A superseded choke point is not harmless dead code.
//
// Need a key for a wrap? Call `verify_recipient_for_wrap` — it is the only thing
// that can construct a `VerifiedRecipient`, and `share_vault_to_known_key`
// accepts nothing else. Need a key for DISPLAY only (a safety number, a
// reachability probe, a deliberate re-pin)? Call the bare `fetch_hybrid_key`,
// which wraps nothing.

// ===========================================================================
// ⭐⭐ THE WRAP GATE — the single choke point EVERY vault-key wrap passes
// ===========================================================================
//
// ADR 0038 states the rule this exists to enforce: "the enforcement rides on the
// fetch itself … EVERY wrap path goes through it. A trust store that some code
// path forgets to consult is worthless."
//
// Phase 54 broke that rule. It added a real requirement — a recovery kit's key
// must be checked against the safety number printed on the sheet — but it added
// it to ONE COMMAND (`recovery cover`) instead of to the choke point. A verifier
// reproduced the consequence live: `sigil vault share --to <kitID>` and
// `sigil vault rotate --to <kitID>` reach the IDENTICAL outcome (the live vault
// key wrapped to whatever key the server serves) through ordinary first-sight
// TOFU, from a sibling device with ZERO prior knowledge of the kit — with the
// human shown a safety number only AFTER the wrap, deposit and grant had all
// completed.
//
// So the requirement moved INTO the fetch, and the fetch produces a value that
// only this function can construct:
//
//   * [`VerifiedRecipient`] has PRIVATE fields and NO public constructor;
//   * [`share_vault_to_known_key`] — the one wrap → deposit → grant path — takes
//     a `&VerifiedRecipient`, so it cannot be called with an unchecked identity;
//   * `share`, `rotate`, `cover` and `recovery generate` all obtain theirs here.
//
// That makes "is every wrap gated?" answerable by grep rather than by reading
// every call site: `VerifiedRecipient` is constructed in exactly one place.

/// How this client came to trust a recipient's hybrid public key. Ordered
/// strongest → weakest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientTrust {
    /// DERIVED locally from a recovery secret this process holds. Nothing was
    /// fetched, so there was nothing for a server to substitute.
    Derived,
    /// Byte-identical to the key this client pinned earlier.
    Pinned,
    /// First sight, and a safety number supplied by the human MATCHED the key
    /// the server served.
    VerifiedFirstSight,
    /// ⚠️ First sight with no out-of-band check. This is ADR 0038's accepted
    /// trust-on-first-use limit, and it is NOT permitted for a recovery kit.
    UnverifiedFirstSight,
}

impl RecipientTrust {
    /// A short phrase for CLI output.
    pub fn label(&self) -> &'static str {
        match self {
            RecipientTrust::Derived => "derived locally from your recovery secret (never fetched)",
            RecipientTrust::Pinned => "matches the key this client pinned earlier",
            RecipientTrust::VerifiedFirstSight => {
                "FIRST SIGHT, verified against the safety number you supplied"
            }
            RecipientTrust::UnverifiedFirstSight => {
                "FIRST SIGHT — NOT verified out of band (pinned now)"
            }
        }
    }

    /// Whether a human still needs to compare the safety number out of band.
    pub fn needs_out_of_band_check(&self) -> bool {
        matches!(self, RecipientTrust::UnverifiedFirstSight)
    }
}

/// A recipient hybrid public key that has passed [`verify_recipient_for_wrap`].
///
/// ⭐ The fields are PRIVATE and there is NO public constructor, so the only way
/// to obtain one is through the gate. That is what makes
/// [`share_vault_to_known_key`]'s signature a proof rather than a convention.
#[derive(Debug, Clone)]
pub struct VerifiedRecipient {
    device_id: String,
    identity: HybridPublicIdentity,
    trust: RecipientTrust,
    safety_number: String,
}

impl VerifiedRecipient {
    /// The device this key belongs to.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
    /// The verified hybrid public identity.
    pub fn identity(&self) -> &HybridPublicIdentity {
        &self.identity
    }
    /// How trust was established.
    pub fn trust(&self) -> RecipientTrust {
        self.trust
    }
    /// The safety number of the key that is about to be wrapped to. Callers
    /// MUST show this BEFORE wrapping, not after.
    pub fn safety_number(&self) -> &str {
        &self.safety_number
    }
}

/// Is `device_id` a RECOVERY KIT, as far as this client can tell?
///
/// The signal is the kit's deliberately-visible device label
/// ([`RECOVERY_DEVICE_LABEL`]) on the CALLER'S OWN account listing — `GET
/// /v1/account`, which names no account and returns only "mine" (ADR 0040 §2).
/// A cross-account recipient is not this account's kit, so it is not one for
/// this purpose.
///
/// FAIL-CLOSED: any error other than "this server has no account model at all"
/// (`501`) propagates, so a wrap is refused rather than proceeding on a signal we
/// could not read. Under legacy v2 / unsigned auth there is no account model and
/// therefore no kit, which is answered without a request.
///
/// ⚠️ HONEST LIMIT: the label comes from the server, which is the adversary this
/// whole mechanism is about. A hostile server can HIDE the label and degrade a
/// kit wrap back to ordinary first-sight TOFU with a warning — no worse than any
/// other first contact, and exactly what the safety number exists to close. What
/// it cannot do is make a kit wrap succeed against a DIFFERENT key than the one
/// pinned, or against a supplied safety number that does not match.
fn recipient_is_recovery_kit(
    server: &str,
    device_id: &str,
    auth: &RequestAuth<'_>,
) -> Result<bool, CliError> {
    if !matches!(auth, RequestAuth::V3 { .. }) {
        return Ok(false);
    }
    match get_account(server, auth) {
        Ok(info) => Ok(info
            .devices
            .iter()
            .any(|d| d.device_id == device_id && d.label == RECOVERY_DEVICE_LABEL)),
        // No account model on this server => recovery kits cannot exist here.
        Err(CliError::Server { status: 501, .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

/// ⭐⭐ THE GATE. Resolve a recipient's hybrid public key and establish trust in
/// it, in ONE call, before anything can be wrapped to it.
///
/// | situation | outcome | pin store |
/// |---|---|---|
/// | key DERIVED locally (pin `origin = "recovery-kit"`) | [`RecipientTrust::Derived`], **no fetch at all** | untouched |
/// | pinned key, byte-identical | [`RecipientTrust::Pinned`] | untouched |
/// | pinned key, **different** | ⛔ [`CliError::PinMismatch`] | **untouched** |
/// | first sight + matching `expected_safety_number` | [`RecipientTrust::VerifiedFirstSight`] | pinned |
/// | first sight + **wrong** `expected_safety_number` | ⛔ [`CliError::SafetyNumberMismatch`] | **untouched** |
/// | first sight, **recipient is a RECOVERY KIT**, no safety number | ⛔ [`CliError::UnverifiedRecoveryKit`] | **untouched** |
///
/// `known_recovery_kit` is the caller ASSERTING that the recipient is a kit —
/// `sigil recovery cover --device-id <kitID>` says so by construction. When it
/// is false the gate works it out itself, from the caller's own account listing
/// (see [`recipient_is_recovery_kit`]), which is what makes `vault share --to
/// <kitID>` and `vault rotate --to <kitID>` obey the same rule without the user
/// having to declare anything.
/// | first sight, ordinary device, no safety number | [`RecipientTrust::UnverifiedFirstSight`] (ADR 0038 TOFU) | pinned |
///
/// Every refusal happens BEFORE the key is pinned, which matters more than it
/// looks: pinning a key we then refused would mean a simple retry sees "match"
/// and proceeds — the alarm would silence itself.
///
/// There is NO flag, option, environment variable or default anywhere that makes
/// this accept a changed key, and none that waives the safety number for a
/// recovery kit.
///
/// # Errors
/// - [`CliError::PinMismatch`] / [`CliError::SafetyNumberMismatch`] /
///   [`CliError::UnverifiedRecoveryKit`] — hard stops; nothing was wrapped,
///   uploaded or pinned.
/// - [`CliError::Server`] / [`CliError::Http`] from the fetch or the
///   recovery-kit lookup (fail-closed).
pub fn verify_recipient_for_wrap(
    server: &str,
    device_id: &str,
    auth: &RequestAuth<'_>,
    pins_path: &std::path::Path,
    expected_safety_number: Option<&str>,
    known_recovery_kit: bool,
) -> Result<VerifiedRecipient, CliError> {
    check_device_id(device_id)?;

    // 1) A LOCALLY DERIVED key (a recovery kit generated on this device). There
    //    is no fetch, so there is nothing to substitute and nothing to verify.
    if let Some(identity) = derived_pin(pins_path, device_id)? {
        let safety_number = hybrid_safety_number(device_id, &identity)?;
        return Ok(VerifiedRecipient {
            device_id: device_id.to_string(),
            identity,
            trust: RecipientTrust::Derived,
            safety_number,
        });
    }

    // 2) Ask the server, then decide. Note the ORDER: nothing below writes to the
    //    pin store until every check has passed.
    let identity = fetch_hybrid_key(server, device_id, auth)?;
    let presented = hybrid_safety_number(device_id, &identity)?;

    // A supplied safety number is ALWAYS checked, pinned or not. Checking it on a
    // pinned key costs nothing and catches a human who is comparing the wrong
    // device.
    if let Some(expected) = expected_safety_number {
        if normalize_safety_number(expected) != normalize_safety_number(&presented) {
            return Err(CliError::SafetyNumberMismatch {
                device_id: device_id.to_string(),
                expected_safety_number: expected.to_string(),
                presented_safety_number: presented,
            });
        }
    }

    let store = load_pins(pins_path)?;
    if store.pins.contains_key(device_id) {
        // check_and_pin returns Match or PinMismatch here and mutates nothing.
        match check_and_pin(pins_path, device_id, &identity)? {
            PinStatus::Match | PinStatus::Repinned | PinStatus::FirstSight => {}
        }
        return Ok(VerifiedRecipient {
            device_id: device_id.to_string(),
            identity,
            trust: RecipientTrust::Pinned,
            safety_number: presented,
        });
    }

    // 3) FIRST SIGHT. If this is a recovery kit, the printed sheet makes an
    //    out-of-band check available, so it is REQUIRED — no TOFU for the one
    //    credential that can reconstruct the whole account.
    let trust = if expected_safety_number.is_some() {
        RecipientTrust::VerifiedFirstSight
    } else {
        if known_recovery_kit || recipient_is_recovery_kit(server, device_id, auth)? {
            return Err(CliError::UnverifiedRecoveryKit {
                device_id: device_id.to_string(),
                presented_safety_number: presented,
            });
        }
        RecipientTrust::UnverifiedFirstSight
    };

    check_and_pin(pins_path, device_id, &identity)?;
    Ok(VerifiedRecipient {
        device_id: device_id.to_string(),
        identity,
        trust,
        safety_number: presented,
    })
}

// ===========================================================================
// ⭐⭐ THE UNWRAP GATE — the mirror image, on the receiving side
// ===========================================================================
//
// The wrap side has had a type-enforced choke point since Phase 54. The UNWRAP
// side had NOTHING: `vault accept` fetched an envelope and opened it, full stop.
// It never fetched a hybrid key, so ADR 0038's pin store was not merely
// bypassed — it was never CONSULTED. That is why key pinning did not mitigate
// the forgery at all.
//
// Now an unwrap needs a `VerifiedSender`, and a `VerifiedSender` exists only in
// two ways:
//
//   * `verify_sender_for_unwrap` — fetch the sender's published hybrid key and
//     pin-check it, exactly as the wrap side does;
//   * `VerifiedSender::from_local` — we HOLD the sender's secret half, so there
//     was no fetch and nothing to substitute.
//
// ⚠️ THE HONEST LIMIT, stated plainly because it is the same one ADR 0038
// accepted: on FIRST SIGHT of a sender, a hostile server can serve its own key
// as "the sender's" AND forge an envelope under it. Pinning cannot protect first
// contact in either direction. What authentication buys unconditionally is the
// OTHER attacker in the threat model — a co-tenant with write access, or any
// party that is not the server — who can no longer mint an acceptable envelope
// at all. Against the server itself, the defence is the same as for a wrap: a
// pinned sender is a hard stop on change, and `--safety-number` closes first
// contact if a human uses it.

/// A sender whose hybrid public key has passed [`verify_sender_for_unwrap`] (or
/// is held locally in full).
///
/// ⭐ Fields are PRIVATE and there is NO public struct literal, so
/// [`unwrap_vault_key`]'s signature is a proof rather than a convention.
#[derive(Debug, Clone)]
pub struct VerifiedSender {
    device_id: String,
    identity: HybridPublicIdentity,
    trust: RecipientTrust,
    safety_number: String,
}

impl VerifiedSender {
    /// The device this key belongs to.
    pub fn device_id(&self) -> &str {
        &self.device_id
    }
    /// The verified hybrid public identity.
    pub fn identity(&self) -> &HybridPublicIdentity {
        &self.identity
    }
    /// How trust was established.
    pub fn trust(&self) -> RecipientTrust {
        self.trust
    }
    /// The safety number of the key an envelope is about to be authenticated
    /// against. Callers SHOULD show it when trust is first-sight.
    pub fn safety_number(&self) -> &str {
        &self.safety_number
    }

    /// The sender's static X25519 public key — the authentication input.
    fn x25519_public_key(&self) -> Result<[u8; X25519_PUBLIC_KEY_LEN], CliError> {
        Ok(self.identity.decode()?.x25519_public_key)
    }

    /// ⭐ The sender is an identity THIS PROCESS HOLDS THE SECRET HALF OF.
    ///
    /// Nothing is fetched, so there is nothing for a server to substitute — this
    /// is the strongest of the trust outcomes, stronger than a pin. It is not a
    /// bypass: constructing it requires the sender's SECRET identity, and anyone
    /// holding that already *is* the sender. Used when a device unwraps an
    /// envelope it wrapped itself (`vault rekey --publish`, the recovery kit's
    /// mandatory pre-print round trip).
    ///
    /// # Errors
    /// - [`CliError::Identity`] if the secret identity does not decode.
    pub fn from_local(sender: &SenderIdentity) -> Result<Self, CliError> {
        let keys = sender.hybrid_secret.decode()?;
        let identity = HybridPublicIdentity {
            version: HYBRID_IDENTITY_VERSION,
            x25519_public_key: BASE64.encode(x25519_public_key(&keys.x25519_secret)),
            mlkem_encaps_key: BASE64.encode(
                ml_kem768_keygen(&decode_identity_field::<ML_KEM768_KEYGEN_SEED_LEN>(
                    &sender.hybrid_secret.mlkem_seed,
                    "mlkem_seed",
                )?)
                .0,
            ),
        };
        let safety_number = hybrid_safety_number(&sender.device_id, &identity)?;
        Ok(VerifiedSender {
            device_id: sender.device_id.clone(),
            identity,
            trust: RecipientTrust::Derived,
            safety_number,
        })
    }
}

/// ⭐⭐ THE UNWRAP GATE. Resolve the hybrid public key of the device that
/// DEPOSITED an envelope, and establish trust in it, before anything is opened.
///
/// | situation | outcome | pin store |
/// |---|---|---|
/// | key DERIVED locally (pin `origin = "recovery-kit"`) | [`RecipientTrust::Derived`], **no fetch** | untouched |
/// | pinned key, byte-identical | [`RecipientTrust::Pinned`] | untouched |
/// | pinned key, **different** | ⛔ [`CliError::PinMismatch`] | **untouched** |
/// | first sight + matching `expected_safety_number` | [`RecipientTrust::VerifiedFirstSight`] | pinned |
/// | first sight + **wrong** `expected_safety_number` | ⛔ [`CliError::SafetyNumberMismatch`] | **untouched** |
/// | first sight, no safety number | [`RecipientTrust::UnverifiedFirstSight`] (warn) | pinned |
///
/// Deliberately the SAME table as [`verify_recipient_for_wrap`] minus the
/// recovery-kit row: a kit is a *recipient* of wraps, and the one place a kit
/// acts as a sender (its own pre-print verification) holds the secret and uses
/// [`VerifiedSender::from_local`].
///
/// As on the wrap side, every refusal happens BEFORE the key is pinned, so a
/// retry cannot silence the alarm by pinning what was just refused.
///
/// # Errors
/// - [`CliError::PinMismatch`] / [`CliError::SafetyNumberMismatch`] — hard
///   stops; nothing was opened and the pin store is unchanged.
/// - [`CliError::Server`] / [`CliError::Http`] from the fetch (fail-closed: an
///   unreachable sender key means no unwrap, not an unauthenticated one).
pub fn verify_sender_for_unwrap(
    server: &str,
    device_id: &str,
    auth: &RequestAuth<'_>,
    pins_path: &std::path::Path,
    expected_safety_number: Option<&str>,
) -> Result<VerifiedSender, CliError> {
    check_device_id(device_id)?;

    if let Some(identity) = derived_pin(pins_path, device_id)? {
        let safety_number = hybrid_safety_number(device_id, &identity)?;
        return Ok(VerifiedSender {
            device_id: device_id.to_string(),
            identity,
            trust: RecipientTrust::Derived,
            safety_number,
        });
    }

    let identity = fetch_hybrid_key(server, device_id, auth)?;
    let presented = hybrid_safety_number(device_id, &identity)?;

    if let Some(expected) = expected_safety_number {
        if normalize_safety_number(expected) != normalize_safety_number(&presented) {
            return Err(CliError::SafetyNumberMismatch {
                device_id: device_id.to_string(),
                expected_safety_number: expected.to_string(),
                presented_safety_number: presented,
            });
        }
    }

    let store = load_pins(pins_path)?;
    let already_pinned = store.pins.contains_key(device_id);
    // Pins (or, when already pinned, compares and refuses on change).
    check_and_pin(pins_path, device_id, &identity)?;
    let trust = if already_pinned {
        RecipientTrust::Pinned
    } else if expected_safety_number.is_some() {
        RecipientTrust::VerifiedFirstSight
    } else {
        RecipientTrust::UnverifiedFirstSight
    };
    Ok(VerifiedSender {
        device_id: device_id.to_string(),
        identity,
        trust,
        safety_number: presented,
    })
}

// --- billing / entitlement (READ ONLY) --------------------------------------

/// The URL PATH of the subscription-status route.
const BILLING_SUBSCRIPTION_PATH: &str = "/v1/billing/subscription";

/// READ this device's ACCOUNT's subscription, and return the RAW JSON body.
///
/// ⭐ THE WARNING CHANNEL. It is the only signal that can say `"grace"` — that an
/// account has lapsed but writes still work, and when they will stop. A client
/// that never asks learns about a lapse only when a write is refused, which is
/// exactly the surprise ADR 0043 exists to avoid.
///
/// It is deliberately a RAW STRING, not a parsed struct: the additive
/// `entitlement` block is interpreted in exactly one place per client (the
/// desktop's `EntitlementView::from_subscription_block`), and a second
/// interpretation here would be a second thing to keep in sync.
///
/// NO REQUEST NAMES AN ACCOUNT (ADR 0040): the subject is the account behind the
/// verified signature, so there is nothing here to enumerate with. This route is
/// itself never gated by entitlement — refusing to tell a customer WHY they are
/// being refused, because they are being refused, would be absurd.
///
/// # Errors
/// - [`CliError::Server`] on a non-2xx (`401` unauthenticated, `403` no account,
///   `501` billing turned off on this server).
/// - [`CliError::Http`] if the server is unreachable.
pub fn fetch_subscription(server: &str, auth: &RequestAuth<'_>) -> Result<String, CliError> {
    let req = ureq::get(&join_url(server, BILLING_SUBSCRIPTION_PATH));
    let req = apply_auth(req, auth, "GET", BILLING_SUBSCRIPTION_PATH, "", b"")?;
    finish(req.call())
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

/// Read the Argon2id work factors out of a `SIGILcli` container header WITHOUT
/// opening it (no password, no KDF, no allocation).
///
/// The header is unauthenticated framing metadata, so this tells you what the
/// writer *claims* — which is exactly what [`reseal_container`]'s no-downgrade
/// rule needs, and exactly why the values are range-checked here too.
///
/// # Errors
/// - [`CliError::ShortContainer`] / [`CliError::BadMagic`] /
///   [`CliError::UnsupportedVersion`] on a header that is not ours.
/// - [`CliError::ParamsOutOfRange`] if the declared work factors exceed Sigil's
///   ceilings.
pub fn container_params(container: &[u8]) -> Result<Argon2Params, CliError> {
    if container.len() < FIXED_HEADER_LEN {
        return Err(CliError::ShortContainer);
    }
    let (magic, rest) = container.split_at(8);
    if magic != MAGIC.as_slice() {
        return Err(CliError::BadMagic);
    }
    if rest[0] != FORMAT_VERSION {
        return Err(CliError::UnsupportedVersion(rest[0]));
    }
    let params = Argon2Params {
        m_cost: u32::from_le_bytes([rest[1], rest[2], rest[3], rest[4]]),
        t_cost: u32::from_le_bytes([rest[5], rest[6], rest[7], rest[8]]),
        p_cost: u32::from_le_bytes([rest[9], rest[10], rest[11], rest[12]]),
    };
    if params.validate().is_err() {
        return Err(CliError::ParamsOutOfRange {
            m_cost: params.m_cost,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
        });
    }
    Ok(params)
}

/// ⭐ THE NO-DOWNGRADE RULE for re-sealing: never write a container weaker than
/// the one you read.
///
/// Returns the componentwise **maximum** of `existing` (what the input container
/// declared) and `requested` (what this build would write today).
///
/// The attack this closes: a container's header is unauthenticated, so an
/// attacker who can get ONE weak container accepted — say `m_cost = 8` — would
/// otherwise see that weakness *persist* through every subsequent re-seal, since
/// a re-seal is the operation that decides the new parameters. Taking the max
/// makes a work factor a ratchet: it can go up, never down, and a client with
/// stronger defaults silently repairs a weak container the first time it re-seals
/// it.
///
/// Argon2 requires `m_cost >= 8 * p_cost`; a componentwise max can in principle
/// pair a small `m_cost` with a larger `p_cost`, so `m_cost` is raised to that
/// floor if needed. Both inputs are already at or below the ceilings (an
/// out-of-range container cannot be opened at all, and `8 * MAX_P_COST` = 128 KiB
/// is far below [`Argon2Params::MAX_M_COST`]), so the result is always in range.
/// ⚠️ **Delegates to [`Argon2Params::no_downgrade`] — there is exactly ONE
/// implementation of this rule.** It lives in `sigil-core` so that the CLI, the
/// desktop app and the wasm binding (and therefore the webapp and the extension)
/// all ratchet identically; a mirrored copy would be free to drift, and a JS copy
/// that drifted downward would silently weaken every CLI-written vault the
/// browser touched.
pub fn no_downgrade(existing: Argon2Params, requested: Argon2Params) -> Argon2Params {
    existing.no_downgrade(requested)
}

/// Re-seal an existing `SIGILcli` container under a NEW secret: open it with
/// `old_secret`, seal the exact same plaintext under `new_secret`.
///
/// Container-agnostic on purpose — it re-keys a TOTP vault, a note, or anything
/// else that is a `SIGILcli` container, because it never looks at the plaintext.
///
/// ⭐ **The output is never weaker than the input.** `params` is a *floor*, not a
/// verbatim instruction: the parameters actually written are
/// [`no_downgrade(container's params, params)`](no_downgrade). See that
/// function for why — a re-seal is where new work factors are chosen, so it is
/// the one place a weak container could make its weakness permanent.
///
/// # Errors
/// - Whatever [`open_container`] / [`seal_to_container`] return (including
///   [`CliError::ParamsOutOfRange`] for a hostile header).
pub fn reseal_container(
    old_secret: &[u8],
    new_secret: &[u8],
    container: &[u8],
    params: Argon2Params,
) -> Result<Vec<u8>, CliError> {
    // Read the incoming work factors BEFORE opening, so the ratchet applies even
    // to a container this build would otherwise have re-sealed more weakly.
    let existing = container_params(container)?;
    let plaintext = open_container(old_secret, container)?;
    seal_to_container(new_secret, &plaintext, no_downgrade(existing, params))
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
    /// Devices the new key was re-wrapped to, with how trust in each was
    /// established by the wrap gate.
    pub rewrapped: Vec<(String, RecipientTrust)>,
    /// Devices whose stale envelope was DELETED from the server.
    ///
    /// Every entry here was named EXPLICITLY by the caller's `drop` list: a
    /// device that holds an envelope and is in neither `recipients` nor `drop`
    /// aborts the rotation ([`CliError::RecipientsWouldBeDropped`]) instead of
    /// being removed silently.
    pub removed: Vec<String>,
}

/// ⭐ ROTATE a vault key and RE-WRAP it to a chosen set of devices.
///
/// The owner-side remediation that revocation was missing:
///
///   1. read the CURRENT vault key from the local keyring (required);
///   2. run **every** recipient through [`verify_recipient_for_wrap`] FIRST — the
///      same gate `share` and `cover` use — so a [`CliError::PinMismatch`], a
///      [`CliError::SafetyNumberMismatch`] or an
///      [`CliError::UnverifiedRecoveryKit`] aborts the whole rotation before a
///      single byte of local or server state is touched. `safety_numbers` is
///      `(device id, printed digits)` for any recipient the caller can verify
///      out of band, and is REQUIRED for a first-sight recovery kit;
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
/// ⭐ **THE FAIL-CLOSED DROP GUARD (Phase 54).** Step 7 destroys access, so it
/// may not happen by omission. BEFORE anything is mutated, the current envelope
/// holders are listed and any device in neither `recipients` nor `drop` aborts
/// the rotation with [`CliError::RecipientsWouldBeDropped`], naming each one and
/// flagging any that this client's pin store marks as a RECOVERY KIT. `--to`
/// keeps its exact meaning (the complete new recipient set), so excluding a
/// compromised device is still one command — what changed is that the
/// destruction is now stated rather than implied.
///
/// # Errors
/// - [`CliError::RecipientsWouldBeDropped`] if a current holder was not named
///   (nothing is mutated).
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
    drop: &[String],
    safety_numbers: &[(String, String)],
    auth: &RequestAuth<'_>,
    params: Argon2Params,
    sender: &SenderIdentity,
) -> Result<RotationReport, CliError> {
    check_vault(vault_id)?;
    for r in recipients.iter().chain(drop.iter()) {
        check_device_id(r)?;
    }

    // 0) ⭐ THE DROP GUARD. Enumerate who holds an envelope RIGHT NOW and refuse
    //    if the caller did not account for every one of them. This runs FIRST,
    //    before the keyring, the vault file, the pin checks or a single request
    //    that changes state, so a refusal leaves everything exactly as it was.
    let existing = list_key_envelopes(server, vault_id, auth)?;
    let keep: std::collections::BTreeSet<&str> = recipients.iter().map(String::as_str).collect();
    let dropping: std::collections::BTreeSet<&str> = drop.iter().map(String::as_str).collect();
    let unnamed: Vec<&str> = existing
        .iter()
        .map(|e| e.device_id.as_str())
        .filter(|d| !keep.contains(d) && !dropping.contains(d))
        .collect();
    if !unnamed.is_empty() {
        // Consult the LOCAL pin store so a recovery kit is named as such. A
        // sibling device that never heard of the kit has no such pin and will
        // simply see "unknown recipient" — an honest limit, not a bug.
        let pins = load_pins(pins_path).unwrap_or_default();
        let unknown = unnamed
            .into_iter()
            .map(|d| {
                let is_kit = pins
                    .pins
                    .get(d)
                    .and_then(|p| p.origin.as_deref())
                    .is_some_and(|o| o == PIN_ORIGIN_RECOVERY_KIT);
                (d.to_string(), is_kit)
            })
            .collect();
        return Err(CliError::RecipientsWouldBeDropped {
            vault_id: vault_id.to_string(),
            unknown,
        });
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

    // 2) ⭐ GATE EVERY RECIPIENT BEFORE MUTATING ANYTHING, through the SAME
    //    verify_recipient_for_wrap that `share` and `cover` use. If one device's
    //    key was substituted — or one recipient is an unverified RECOVERY KIT —
    //    the whole rotation aborts with the vault untouched, which is far better
    //    than a half-rotated vault whose key leaked to an attacker.
    let mut resolved: Vec<VerifiedRecipient> = Vec::with_capacity(recipients.len());
    for device in recipients {
        let expected = safety_numbers
            .iter()
            .find(|(d, _)| d == device)
            .map(|(_, n)| n.as_str());
        resolved.push(verify_recipient_for_wrap(
            server, device, auth, pins_path, expected, false,
        )?);
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
    for recipient in &resolved {
        let ctx = VaultKeyWrapContext::new(vault_id, recipient.device_id(), &sender.device_id)?;
        let envelope = wrap_vault_key(sender, recipient.identity(), &ctx, &new_key)?;
        put_key_envelope(server, vault_id, recipient.device_id(), &envelope, auth)?;
        rewrapped.push((recipient.device_id().to_string(), recipient.trust()));
    }

    // 7) Remove the stale envelopes of everyone left out. Re-listed here rather
    //    than reusing step 0's snapshot, so a device that deposited an envelope
    //    mid-rotation is still caught — and every removal is one the caller
    //    named in `drop`, because step 0 refused otherwise.
    let mut removed = Vec::new();
    for holder in list_key_envelopes(server, vault_id, auth)? {
        if !keep.contains(holder.device_id.as_str())
            && delete_key_envelope(server, vault_id, &holder.device_id, auth)?
        {
            removed.push(holder.device_id);
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

// ===========================================================================
// PHASE 54 — THE RECOVERY KIT
// ===========================================================================
//
// THE MODEL, IN ONE SENTENCE. A recovery kit is an ORDINARY MEMBER DEVICE whose
// Ed25519 and hybrid private keys are derived from 32 bytes of client CSPRNG
// that are printed on paper, never transmitted, never stored on any device, and
// never derivable from anything the server holds. `sigild` gains NO concept of
// "recovery".
//
// WHAT THE SERVER SEES, AND IT IS ONLY WHAT IT ALREADY SAW: one more device row
// (a label, an Ed25519 PUBLIC key, an account id), one more hybrid PUBLIC key
// row (32 + 1184 bytes, length-checked only), and one more opaque ~1.3 KiB
// `SIGILhyb` envelope per covered vault (⚠️ NOT the flat 1226 bytes this comment
// used to claim: from Phase 60 a vault-key envelope carries its context AAD, so
// its length depends on the vault id and both device ids — 1304-1307 bytes
// observed with real server-assigned ids) — byte-for-byte the shapes it already
// relays for device-to-device sharing (ADR 0035). No table, column, route,
// metric or audit field added by this phase can hold a kit secret, a vault key,
// a password or a plaintext.
//
// THE CENTRAL COMPROMISE, recorded as a compromise and not a feature: the
// envelope is NOT on the paper, and retrieving it requires authentication. That
// is what forces the paper to ALSO be an identity, and that is where the entire
// blast radius comes from — a stolen kit is full account takeover (flat
// membership, ADR 0040 limitation 3), strictly more powerful than a stolen
// locked phone. `hybrid_seal` gives you a recipient who can decrypt; it does not
// give you a courier.
//
// WHAT IS RECOVERED: every vault key wrapped to the kit BEFORE the loss, and
// therefore the 2FA secrets in those vaults — but ONLY if the vault's sealed
// container was pushed to the op-log. ⚠️ THE KIT RECOVERS KEYS, NOT DATA.
//
// WHAT IS NOT: a vault key never wrapped to the kit; password-sealed PERSONAL
// vaults (they have no vault key to wrap — coverage requires `vault rekey`, a
// ONE-WAY DOOR); anything after a rotation that excluded the kit; and a LOST
// KIT, for which there is no recovery of the recovery and no escrow. The floor
// of "lose everything => lose everything" is NOT raised.
//
// ⚠️ THE PRINTED CODE AND EVERY DERIVED SEED ARE SECRETS. They are returned to
// the caller once, never written to a file by this crate, never logged, never
// placed in a request body, header, URL, metric or audit field. The only
// outbound bytes derived from a kit are PUBLIC keys and signatures.
//
// STATUS: dev-gated, plain HTTP, pre-audit, UNAUDITED. The wrap is a CUSTOM
// KEM-then-AEAD, NOT RFC 9180 HPKE, and the system is not "post-quantum secure".

/// The device label a recovery kit enrolls under.
///
/// DELIBERATELY VISIBLE. Hiding it would buy only protection against targeted
/// denial (a hostile server can deny everything anyway) and targeted
/// substitution (already covered by pinning), and it would cost every client the
/// ability to render "Recovery: not set up" — the single most valuable piece of
/// feedback in the design.
pub const RECOVERY_DEVICE_LABEL: &str = "recovery-kit";

/// The [`HybridKeyPin::origin`] marker for a key DERIVED from a recovery secret
/// rather than fetched from a server.
pub const PIN_ORIGIN_RECOVERY_KIT: &str = "recovery-kit";

/// Draw a fresh 32-byte recovery secret from the OS CSPRNG.
///
/// Caller-supplied entropy, exactly like every other seed this crate produces —
/// `sigil-core` still draws none (ADR 0007).
///
/// # Errors
/// - [`CliError::Rng`] if the OS RNG fails.
pub fn generate_recovery_seed() -> Result<[u8; RECOVERY_SEED_LEN], CliError> {
    let mut seed = [0u8; RECOVERY_SEED_LEN];
    fill_random(&mut seed)?;
    Ok(seed)
}

/// A recovery kit's full derived identity: the Ed25519 request-auth key pair and
/// the hybrid (X25519 + ML-KEM-768) encryption identity.
///
/// ⚠️ Holds SECRET key material. It is deliberately NOT `Serialize`, so there is
/// no accidental path from here to a file or a request body.
#[derive(Clone)]
pub struct RecoveryIdentity {
    /// The 32-byte Ed25519 signing seed. SECRET.
    pub ed25519_seed: [u8; SIG_SEED_LEN],
    /// The 32-byte Ed25519 public key. PUBLIC — this is what is enrolled.
    pub public_key: [u8; SIG_PUBLIC_KEY_LEN],
    /// The hybrid SECRET identity (X25519 secret + ML-KEM keygen seed). SECRET.
    pub hybrid_secret: HybridSecretIdentity,
    /// The hybrid PUBLIC identity. PUBLIC — this is what is published.
    pub hybrid_public: HybridPublicIdentity,
}

/// REDACTED on purpose: a kit's derived material must never reach a log line via
/// a stray `{:?}`.
impl std::fmt::Debug for RecoveryIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RecoveryIdentity { <redacted> }")
    }
}

/// Derive a kit's full identity from its 32-byte recovery secret.
///
/// Deterministic and RNG-free: it is `sigil-core`'s [`derive_recovery_keys`]
/// feeding the EXISTING [`public_key_from_seed`], [`x25519_public_key`] and
/// [`ml_kem768_keygen`] primitives unchanged. No new crypto lives here.
#[must_use]
pub fn derive_recovery_identity(seed: &[u8; RECOVERY_SEED_LEN]) -> RecoveryIdentity {
    let keys = derive_recovery_keys(seed);
    let public_key = public_key_from_seed(&keys.ed25519_seed);
    let x25519_pub = x25519_public_key(&keys.x25519_secret);
    let (mlkem_encaps_key, _dk) = ml_kem768_keygen(&keys.mlkem_keygen_seed);
    RecoveryIdentity {
        ed25519_seed: keys.ed25519_seed,
        public_key,
        hybrid_secret: HybridSecretIdentity {
            version: HYBRID_IDENTITY_VERSION,
            x25519_secret: BASE64.encode(keys.x25519_secret),
            mlkem_seed: BASE64.encode(keys.mlkem_keygen_seed),
        },
        hybrid_public: HybridPublicIdentity {
            version: HYBRID_IDENTITY_VERSION,
            x25519_public_key: BASE64.encode(x25519_pub),
            mlkem_encaps_key: BASE64.encode(mlkem_encaps_key),
        },
    }
}

/// Everything on a printed sheet EXCEPT the secret line. All of it is public;
/// none of it can be used to decrypt anything.
#[derive(Debug, Clone, Serialize)]
pub struct RecoveryKitPublic {
    /// The server-assigned device id of the enrolled kit. NOT secret — it is
    /// needed to address the kit's own envelope index at restore time, which is
    /// why it is printed on the sheet.
    pub device_id: String,
    /// The account the kit joined. NOT secret.
    pub account_id: String,
    /// The server the kit was enrolled against. NOT secret.
    pub server: String,
    /// std-base64 of the kit's 32-byte X25519 PUBLIC key.
    pub x25519_public_key: String,
    /// std-base64 of the kit's 1184-byte ML-KEM-768 encapsulation key.
    pub mlkem_encaps_key: String,
    /// The kit's rendered SAFETY NUMBER — the out-of-band verification string
    /// another device compares before wrapping a vault key to this kit.
    pub safety_number: String,
    /// Unix seconds at which the kit was printed.
    pub created_at: u64,
    /// The vaults covered AS OF THE PRINT DATE. Coverage drifts: a vault created
    /// later is not covered until `sigil recovery cover` runs.
    pub covered: Vec<String>,
}

/// PIN a hybrid public key this client DERIVED itself, without ever asking the
/// server.
///
/// ⭐ This is the one pin in the system established with no fetch, so there is
/// nothing to poison: from here on, covering a vault from THIS device calls
/// [`share_vault_to_known_key`] with the derived identity and never
/// [`fetch_hybrid_key`]. It does not weaken ADR 0038, whose invariant is "every
/// key OBTAINED FROM THE SERVER is pin-checked before a wrap" — here none is
/// obtained.
///
/// Re-pinning the SAME key is a no-op. A DIFFERENT existing pin is refused with
/// [`CliError::PinMismatch`]: this function never silently replaces a pin.
///
/// # Errors
/// - [`CliError::PinMismatch`] if a different key is already pinned for that id.
/// - [`CliError::Identity`] / [`CliError::Sharing`] on a decode or IO failure.
pub fn pin_derived_key(
    pins_path: &std::path::Path,
    device_id: &str,
    identity: &HybridPublicIdentity,
) -> Result<(), CliError> {
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
            return Ok(());
        }
        return Err(CliError::PinMismatch {
            device_id: device_id.to_string(),
            pinned_safety_number: existing.safety_number.clone(),
            presented_safety_number: hybrid_safety_number(device_id, identity)?,
        });
    }
    store.version = HYBRID_PIN_STORE_VERSION;
    store.pins.insert(
        device_id.to_string(),
        make_pin(
            device_id,
            identity,
            0,
            Some(PIN_ORIGIN_RECOVERY_KIT.to_string()),
        )?,
    );
    save_pins(pins_path, &store)
}

/// Look up the LOCALLY DERIVED hybrid identity this client pinned for
/// `device_id`, if any — i.e. a pin whose `origin` is
/// [`PIN_ORIGIN_RECOVERY_KIT`].
///
/// Returning `Some` is what lets a cover/share proceed with NO server fetch.
///
/// # Errors
/// - [`CliError::Sharing`] on a pin-store IO/parse failure.
pub fn derived_pin(
    pins_path: &std::path::Path,
    device_id: &str,
) -> Result<Option<HybridPublicIdentity>, CliError> {
    let store = load_pins(pins_path)?;
    Ok(store
        .pins
        .get(device_id)
        .filter(|p| p.origin.as_deref() == Some(PIN_ORIGIN_RECOVERY_KIT))
        .map(|p| HybridPublicIdentity {
            version: HYBRID_IDENTITY_VERSION,
            x25519_public_key: p.x25519_public_key.clone(),
            mlkem_encaps_key: p.mlkem_encaps_key.clone(),
        }))
}

/// ⭐ THE ONE wrap → deposit → grant path.
///
/// Wrap `vault_key` to a recipient, deposit the opaque envelope, and authorize
/// the recipient through the EXISTING grant route.
///
/// ⭐ IT TAKES A [`VerifiedRecipient`], WHICH ONLY [`verify_recipient_for_wrap`]
/// CAN CONSTRUCT. That is the enforcement, not a comment: `sigil vault share`,
/// `sigil vault rotate`, `sigil recovery cover` and `sigil recovery generate`
/// all funnel through here, and none of them can supply an identity that has not
/// been through the gate. Note what this function deliberately does NOT do: it
/// never fetches a key and never touches the pin store, so the trust decision
/// stays where the caller can display it BEFORE anything is wrapped.
///
/// Returns the envelope bytes so a caller can write them out for inspection.
///
/// ⭐ **THE ORDER IS AUTHORIZE-THEN-DEPOSIT, and it was the other way round.**
/// The deposit used to run first, so a device with WRITE but no ownership got
/// its envelope STORED and only then met the grant route's `403` — a caller who
/// could not legitimately share still landed a key envelope of its choosing in
/// the recipient's mailbox. A failed grant now means nothing was deposited. The
/// reverse failure (grant succeeds, deposit fails) is the safe one: the
/// recipient can read ciphertext it has no key for, which is exactly the state
/// every recipient is in before a share anyway.
///
/// # Errors
/// - [`CliError::Identity`] / [`CliError::Rng`] / [`CliError::HybridSeal`] from
///   the wrap.
/// - [`CliError::Server`] / [`CliError::Http`] from the grant or the deposit.
pub fn share_vault_to_known_key(
    server: &str,
    vault_id: &str,
    recipient: &VerifiedRecipient,
    permission: &str,
    vault_key: &[u8; VAULT_KEY_LEN],
    auth: &RequestAuth<'_>,
    sender: &SenderIdentity,
) -> Result<Vec<u8>, CliError> {
    check_vault(vault_id)?;
    let recipient_device_id = recipient.device_id();
    let ctx = VaultKeyWrapContext::new(vault_id, recipient_device_id, &sender.device_id)?;
    // WRAP: AUTHENTICATED as this sender, BOUND to (vault, recipient, sender);
    // fresh ephemeral X25519 secret + ML-KEM coin + AEAD nonce per call.
    let envelope = wrap_vault_key(sender, recipient.identity(), &ctx, vault_key)?;
    // AUTHORIZE FIRST through the EXISTING grant route, so a caller that may not
    // share cannot leave an envelope behind.
    //
    // ⚠️ AND THE 403 HERE NEEDS EXPLAINING, because authorize-first has a cliff
    // the old order hid: only a vault's OWNER may grant, ownership is
    // trust-on-first-WRITE, and a vault that has never been written to this
    // server therefore has NO owner — so the very first share of a never-pushed
    // vault is refused. Under the old deposit-then-grant order the deposit
    // silently claimed it. The bare server message ("only the vault owner ...")
    // is true and useless; say what to do.
    grant_vault_access(server, vault_id, recipient_device_id, permission, auth).map_err(
        |e| match e {
            CliError::Server { status: 403, .. } => CliError::Sharing(format!(
                "REFUSED (HTTP 403 forbidden): this device may not grant access to vault \
             {vault_id:?}, so nothing was wrapped and nothing was deposited.\n  \
             Two causes, and only you can tell them apart:\n  \
             (1) the vault has NEVER been written to this server, so NOBODY owns it yet \
             \u{2014} ownership is trust-on-first-write. Push it first (`sigil push \
             --vault {vault_id} --in <file>`, or Push in the app) and then share; a \
             recipient holding a key with no ciphertext could not open anything anyway.\n  \
             (2) the vault belongs to ANOTHER account. You may be able to write it, but \
             administering it \u{2014} granting another device access \u{2014} belongs \
             to its owner."
            )),
            other => other,
        },
    )?;
    // DEPOSIT the opaque envelope; the server cannot read it.
    put_key_envelope(server, vault_id, recipient_device_id, &envelope, auth)?;
    Ok(envelope)
}

/// What an accept actually did. Fingerprints only — never a key.
#[derive(Debug, Clone)]
pub struct AcceptReport {
    /// The vault accepted.
    pub vault_id: String,
    /// The device that deposited the envelope, as authenticated.
    pub sender_device_id: String,
    /// How trust in that sender was established.
    pub sender_trust: RecipientTrust,
    /// The sender's safety number, for a human to compare on first sight.
    pub sender_safety_number: String,
    /// SHA-256 fingerprint (16 hex) of the recovered key.
    pub key_fingerprint: String,
    /// Whether the recovered key was proved to OPEN this vault's newest op.
    /// `false` only when the vault has never been pushed, so there was nothing
    /// to open.
    pub verified_against_tip: bool,
    /// The fingerprint of the key this one REPLACED in the keyring, if any.
    pub replaced: Option<String>,
    /// The raw envelope, so a caller can write it out for inspection.
    pub envelope: Vec<u8>,
}

/// ⭐ ACCEPT a vault key that another device wrapped to this one.
///
/// This is the receiving half of [`share_vault_to_known_key`] and it is where
/// the forgery used to land. What it now does, in order, all of it load-bearing:
///
///   1. **work out WHO deposited the envelope.** Explicitly (`sender_device_id`)
///      or from this device's OWN envelope index (`GET /v1/devices/{id}/keys`,
///      self-only). No sender ⇒ [`CliError::UnknownSender`], a refusal. The id
///      is server-supplied and therefore untrusted — naming the wrong device
///      just makes step 3 fail, because the sender's static key is an input to
///      the derivation, not a string that gets compared;
///   2. **establish that sender's hybrid key** through
///      [`verify_sender_for_unwrap`] — the pin store, at last, on the accept
///      path;
///   3. **unwrap AUTHENTICATED and CONTEXT-BOUND.** A v1 (anonymous) envelope is
///      refused outright; a forged or re-filed one fails at the AEAD;
///   4. ⭐ **OPEN BEFORE WRITING.** The recovered key must actually open this
///      vault's newest op before it is written to the keyring — the same shape
///      `recovery_restore` already used. A key that opens nothing never reaches
///      local state;
///   5. **never silently REPLACE.** An existing, different keyring entry needs
///      `replace = true`. Overwriting is how a hostile deposit would take a
///      vault away from a device that already had it.
///
/// # Errors
/// - [`CliError::UnknownSender`] if the depositing device cannot be determined.
/// - [`CliError::PinMismatch`] / [`CliError::SafetyNumberMismatch`] from step 2.
/// - [`CliError::WrongEnvelopeKind`] / [`CliError::HybridSeal`] from step 3.
/// - [`CliError::Sharing`] if the key does not open the vault, or if it would
///   replace a different key without `replace`.
/// - [`CliError::Server`] / [`CliError::Http`] from the transport.
#[allow(clippy::too_many_arguments)]
pub fn accept_vault_key(
    server: &str,
    vault_id: &str,
    self_device_id: &str,
    hybrid_secret: &HybridSecretIdentity,
    keyring_path: &std::path::Path,
    pins_path: &std::path::Path,
    auth: &RequestAuth<'_>,
    sender_device_id: Option<&str>,
    expected_safety_number: Option<&str>,
    replace: bool,
) -> Result<AcceptReport, CliError> {
    check_vault(vault_id)?;
    check_device_id(self_device_id)?;

    // 0) ⭐ COLLECT THE ENVELOPE FIRST — before anything else is asked of the
    //    server. This ordering is deliberate and was the other way round: a
    //    device that may NOT read this vault would otherwise be told "I cannot
    //    work out who deposited the key" (its own index is empty) when the true
    //    and far more useful answer is the mailbox's own `403 forbidden`. The
    //    fetch grants nothing — the envelope is opaque ciphertext and is not
    //    unwrapped until step 3 — so surfacing the authorization failure first
    //    costs no security and stops a refusal being reported as a puzzle.
    let envelope = get_key_envelope(server, vault_id, self_device_id, auth)?;

    // 1) WHO SENT IT.
    let sender_id = match sender_device_id {
        Some(id) => {
            check_device_id(id)?;
            id.to_string()
        }
        None => {
            let index = list_recoverable_vaults(server, self_device_id, auth)?;
            let found = index
                .iter()
                .find(|v| v.vault_id == vault_id)
                .map(|v| v.sender_device_id.clone())
                .filter(|s| !s.is_empty());
            found.ok_or_else(|| {
                CliError::UnknownSender(format!(
                    "this device's envelope index does not say which device deposited the key for \
                     vault {vault_id:?}"
                ))
            })?
        }
    };

    // 2) ESTABLISH THE SENDER'S KEY (pin store consulted — it never was before).
    let sender =
        verify_sender_for_unwrap(server, &sender_id, auth, pins_path, expected_safety_number)?;

    // 3) UNWRAP, authenticated and context-bound.
    let ctx = VaultKeyWrapContext::new(vault_id, self_device_id, &sender_id)?;
    let key = unwrap_vault_key(hybrid_secret, &sender, &ctx, &envelope)?;

    // 4) ⭐ OPEN BEFORE WRITING.
    let ops = pull_ops_auth(server, vault_id, 0, auth)?;
    let verified_against_tip = match ops.last() {
        Some(last) => {
            open_container(&key, &last.blob).map_err(|e| {
                CliError::Sharing(format!(
                    "the recovered key does NOT open vault {vault_id:?}'s newest op ({e}); \
                     nothing was written to the keyring"
                ))
            })?;
            true
        }
        None => false,
    };

    // 5) NEVER SILENTLY REPLACE.
    let existing = keyring_get(keyring_path, vault_id)?;
    let replaced = match existing {
        Some(old) if old == key => None,
        Some(old) => {
            if !replace {
                return Err(CliError::Sharing(format!(
                    "this client already holds a DIFFERENT key for vault {vault_id:?} \
                     (sha256 {}); accepting would replace it and lose access to everything \
                     sealed under it. Re-run with --replace if that is what you mean.",
                    vault_key_fingerprint(&old)
                )));
            }
            Some(vault_key_fingerprint(&old))
        }
        None => None,
    };

    keyring_put(keyring_path, vault_id, &key)?;

    Ok(AcceptReport {
        vault_id: vault_id.to_string(),
        sender_device_id: sender_id,
        sender_trust: sender.trust(),
        sender_safety_number: sender.safety_number().to_string(),
        key_fingerprint: vault_key_fingerprint(&key),
        verified_against_tip,
        replaced,
        envelope,
    })
}

/// One vault a device holds a wrapped key for, as reported by
/// `GET /v1/devices/{deviceID}/keys`. METADATA ONLY — never a blob.
#[derive(Debug, Clone, Deserialize)]
pub struct RecoverableVault {
    /// The vault the envelope belongs to.
    #[serde(rename = "vaultID")]
    pub vault_id: String,
    /// The device that deposited it.
    #[serde(default)]
    pub sender_device_id: String,
    /// Size of the opaque envelope in bytes.
    #[serde(default)]
    pub size_bytes: usize,
    /// RFC 3339 timestamp of the deposit.
    #[serde(default)]
    pub created_at: String,
}

/// ASK THE SERVER which vaults hold a wrapped key for `device_id`.
///
/// SELF-ONLY server-side: asking for another device's index is a `403`. A
/// restored recovery kit has no local state at all and therefore knows no vault
/// ids — this is the only way it can find out what it is able to decrypt. It
/// grants nothing new: the server already holds every one of these ids, and the
/// caller could already fetch each envelope by naming its vault.
///
/// # Errors
/// - [`CliError::Server`] on a non-2xx: `401` (unknown/revoked kit — or the
///   wrong server), `403` (asking about another device), `501` (device model
///   off).
/// - [`CliError::BadResponse`] if the `200` body is not the expected JSON.
pub fn list_recoverable_vaults(
    server: &str,
    device_id: &str,
    auth: &RequestAuth<'_>,
) -> Result<Vec<RecoverableVault>, CliError> {
    check_device_id(device_id)?;
    #[derive(Deserialize)]
    struct Wire {
        #[serde(default)]
        vaults: Vec<RecoverableVault>,
    }
    let path = format!("/v1/devices/{device_id}/keys");
    let req = ureq::get(&join_url(server, &path));
    let req = apply_auth(req, auth, "GET", &path, "", b"")?;
    let text = finish(req.call())?;
    let wire: Wire =
        serde_json::from_str(&text).map_err(|e| CliError::BadResponse(e.to_string()))?;
    Ok(wire.vaults)
}

/// What the mandatory pre-print verification round-trip proved.
#[derive(Debug, Clone)]
pub struct RecoveryVerification {
    /// The account the kit resolved to when it authenticated AS ITSELF. It is
    /// compared against the generating device's own account: a mismatch means
    /// the server enrolled the kit somewhere else, and the kit is revoked
    /// instead of printed.
    pub account_id: String,
    /// How many vaults the kit's own envelope index reported.
    pub indexed_vaults: usize,
    /// The vault whose envelope was actually unwrapped end to end.
    pub unwrapped_vault: String,
    /// The 16-hex SHA-256 fingerprint of the unwrapped key — matched against the
    /// generating device's copy. Never the key.
    pub key_fingerprint: String,
}

/// A freshly generated recovery kit.
///
/// ⚠️ [`RecoveryKitOutcome::code`] is THE SECRET. It is returned exactly once,
/// is never written to a file or logged by this crate, and should be rendered
/// and then dropped.
#[derive(Clone)]
pub struct RecoveryKitOutcome {
    /// ⚠️ THE SECRET: the ungrouped 56-character recovery code. Render it with
    /// [`format_recovery_kit`].
    pub code: String,
    /// Everything else on the sheet. All public.
    pub public: RecoveryKitPublic,
    /// `(vault id, key fingerprint)` for each vault the kit now covers.
    pub covered: Vec<(String, String)>,
    /// What the pre-print verification round-trip proved.
    pub verification: RecoveryVerification,
    /// Active devices in the account after the kit joined, and the server's cap.
    /// The kit consumes one seat.
    pub seats_used: usize,
    /// The server's configured per-account device cap.
    pub seat_limit: usize,
}

/// REDACTED on purpose: the printed code must not reach a log line.
impl std::fmt::Debug for RecoveryKitOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoveryKitOutcome")
            .field("code", &"<redacted>")
            .field("public", &self.public)
            .field("covered", &self.covered)
            .field("verification", &self.verification)
            .finish()
    }
}

/// GENERATE a recovery kit and cover a set of vaults with it.
///
/// The whole flow, in order:
///
/// 1. draw 32 CSPRNG bytes and derive the kit's Ed25519 + hybrid identity;
/// 2. mint a PINNED, single-use invite for the kit's Ed25519 public key through
///    the EXISTING account-invite route (so an intercepted invite is useless to
///    anyone else);
/// 3. redeem it AS THE KIT through the EXISTING enrollment challenge, under the
///    visible label [`RECOVERY_DEVICE_LABEL`];
/// 4. publish the kit's hybrid PUBLIC key, signed as the kit (that route is
///    self-only, so it must happen here);
/// 5. ⭐ PIN the DERIVED key locally, `origin = "recovery-kit"` — from now on,
///    covering a vault from this device never fetches a key, so there is no
///    fetch to poison;
/// 6. wrap this device's copy of each vault key to the kit and grant it `read`;
/// 7. ⭐ VERIFY BEFORE PRINTING — re-parse the code about to be printed,
///    re-derive from the PARSED value, authenticate v3 as the kit, assert the
///    account it resolves to is the generating device's own, collect one
///    envelope, unwrap it, and compare fingerprints. Any failure REVOKES the
///    partial kit and returns an error: a kit that was generated but never
///    worked is structurally impossible.
///
/// The generating device persists ONLY public material (the pin). The seed and
/// every derived secret are dropped when this returns.
///
/// # Errors
/// - [`CliError::Recovery`] if the verification round-trip fails (the kit is
///   revoked first), or if a named vault has no key in the local keyring.
/// - [`CliError::Server`] / [`CliError::Http`] from any step.
#[allow(clippy::too_many_arguments)]
pub fn recovery_generate(
    server: &str,
    auth: &RequestAuth<'_>,
    vault_ids: &[String],
    keyring_path: &std::path::Path,
    pins_path: &std::path::Path,
    invite_ttl_seconds: Option<u64>,
    sender: &SenderIdentity,
) -> Result<RecoveryKitOutcome, CliError> {
    // The generating device's own account, so step 7 has something to compare
    // against. Fetched FIRST: if this device cannot even read its own account,
    // nothing below is going to work.
    let mine = get_account(server, auth)?;

    // 1) Entropy and derivation.
    let seed = generate_recovery_seed()?;
    let identity = derive_recovery_identity(&seed);
    let code_bytes = encode_recovery_kit(&seed);
    let code = std::str::from_utf8(&code_bytes)
        .map_err(|e| CliError::Recovery(format!("encoded code is not ASCII: {e}")))?
        .to_string();

    // Every vault we intend to cover must have a key HERE, before anything is
    // enrolled: failing later would leave a half-covered kit behind.
    let mut keys: Vec<(String, [u8; VAULT_KEY_LEN])> = Vec::with_capacity(vault_ids.len());
    for vault_id in vault_ids {
        let key = keyring_get(keyring_path, vault_id)?.ok_or_else(|| {
            CliError::Recovery(format!(
                "no vault key for {vault_id:?} in {}; a PASSWORD-sealed vault cannot be covered by \
                 a recovery kit — run `sigil vault rekey --vault {vault_id}` first (that is a \
                 ONE-WAY door)",
                keyring_path.display()
            ))
        })?;
        keys.push((vault_id.clone(), key));
    }

    // 2) A PINNED, single-use invite for exactly this public key.
    let invite =
        create_account_invite(server, auth, invite_ttl_seconds, Some(&identity.public_key))?;

    // 3) Redeem it AS THE KIT, over the unchanged enrollment challenge.
    let enrolled = enroll_device(
        server,
        &invite.invite,
        RECOVERY_DEVICE_LABEL,
        &identity.public_key,
        &identity.ed25519_seed,
    )?;
    let kit_id = enrolled.device_id.clone();
    let kit_auth = RequestAuth::V3 {
        device_id: &kit_id,
        seed: &identity.ed25519_seed,
    };

    // From here on a failure leaves a live kit on the server, so every early
    // return goes through this: revoke it and report the ORIGINAL error.
    let abort = |e: CliError| -> CliError {
        let _ = revoke_device(server, &kit_id, auth, None);
        e
    };

    // 4) Publish the kit's hybrid PUBLIC key (self-only route).
    publish_hybrid_key(server, &kit_id, &identity.hybrid_public, &kit_auth).map_err(abort)?;

    // 5) ⭐ PIN THE DERIVED KEY. Nothing was fetched, so nothing could be
    //    substituted. This is what makes step 6 fetch-free.
    pin_derived_key(pins_path, &kit_id, &identity.hybrid_public).map_err(abort)?;

    // 6) Cover each vault: wrap OUR copy of the key to the DERIVED identity.
    //    ⭐ It goes through the SAME gate as every other wrap. Because step 5
    //    just pinned the derived key with origin = "recovery-kit", the gate
    //    short-circuits on RecipientTrust::Derived and makes NO request — so
    //    there is still no fetch to poison, and there is still exactly ONE
    //    construction site for a VerifiedRecipient.
    let verified =
        verify_recipient_for_wrap(server, &kit_id, auth, pins_path, None, true).map_err(abort)?;
    debug_assert_eq!(verified.trust(), RecipientTrust::Derived);
    let mut covered = Vec::with_capacity(keys.len());
    for (vault_id, key) in &keys {
        share_vault_to_known_key(server, vault_id, &verified, "read", key, auth, sender)
            .map_err(abort)?;
        covered.push((vault_id.clone(), vault_key_fingerprint(key)));
    }

    // 7) ⭐ THE MANDATORY VERIFICATION ROUND-TRIP. Deliberately re-parses the
    //    printed form and re-derives from THAT, so a codec bug cannot ship a
    //    sheet that decodes to a different identity.
    let verification =
        verify_kit_round_trip(server, &code, &kit_id, &mine.account_id, &keys, sender)
            .map_err(abort)?;

    let safety_number = hybrid_safety_number(&kit_id, &identity.hybrid_public)?;
    let after = get_account(server, auth)?;

    Ok(RecoveryKitOutcome {
        code,
        public: RecoveryKitPublic {
            device_id: kit_id,
            account_id: enrolled
                .account_id
                .unwrap_or_else(|| mine.account_id.clone()),
            server: server.to_string(),
            x25519_public_key: identity.hybrid_public.x25519_public_key.clone(),
            mlkem_encaps_key: identity.hybrid_public.mlkem_encaps_key.clone(),
            safety_number,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            covered: vault_ids.to_vec(),
        },
        covered,
        verification,
        seats_used: after.device_count,
        seat_limit: after.device_limit,
    })
}

/// The pre-print proof: parse the code, re-derive, authenticate as the kit, and
/// unwrap one envelope end to end.
fn verify_kit_round_trip(
    server: &str,
    code: &str,
    kit_id: &str,
    expected_account: &str,
    keys: &[(String, [u8; VAULT_KEY_LEN])],
    sender: &SenderIdentity,
) -> Result<RecoveryVerification, CliError> {
    // Re-parse the EXACT text that will be printed.
    let parsed = decode_recovery_kit(code)?;
    let reborn = derive_recovery_identity(&parsed);
    let auth = RequestAuth::V3 {
        device_id: kit_id,
        seed: &reborn.ed25519_seed,
    };

    // ⭐ The account assertion. This is the only thing that catches a hostile
    // server that enrolled the kit into a DIFFERENT account — where it would
    // authenticate perfectly and recover nothing of ours.
    let account = get_account(server, &auth)?;
    if account.account_id != expected_account {
        return Err(CliError::Recovery(format!(
            "the kit enrolled into account {} but this device is in {expected_account}; the \
             server did not put the kit in your account, so it is being revoked and NOT printed",
            account.account_id
        )));
    }

    let indexed = list_recoverable_vaults(server, kit_id, &auth)?;
    if keys.is_empty() {
        // A kit covering nothing still proved it can authenticate and read its
        // own (empty) index, which is everything there is to prove.
        return Ok(RecoveryVerification {
            account_id: account.account_id,
            indexed_vaults: indexed.len(),
            unwrapped_vault: String::new(),
            key_fingerprint: String::new(),
        });
    }

    let (vault_id, expected_key) = &keys[0];
    if !indexed.iter().any(|v| &v.vault_id == vault_id) {
        return Err(CliError::Recovery(format!(
            "the kit's own envelope index does not list vault {vault_id:?}; it is being revoked \
             and NOT printed"
        )));
    }
    let envelope = get_key_envelope(server, vault_id, kit_id, &auth)?;
    // ⭐ The envelope was wrapped moments ago BY THIS DEVICE, whose hybrid secret
    // we hold — so the sender is established locally, with no fetch and nothing
    // for the server to substitute.
    let from_us = VerifiedSender::from_local(sender)?;
    let ctx = VaultKeyWrapContext::new(vault_id, kit_id, &sender.device_id)?;
    let recovered = unwrap_vault_key(&reborn.hybrid_secret, &from_us, &ctx, &envelope)?;
    let fingerprint = vault_key_fingerprint(&recovered);
    if fingerprint != vault_key_fingerprint(expected_key) {
        return Err(CliError::Recovery(format!(
            "the kit unwrapped a DIFFERENT key for vault {vault_id:?}; it is being revoked and \
             NOT printed"
        )));
    }
    Ok(RecoveryVerification {
        account_id: account.account_id,
        indexed_vaults: indexed.len(),
        unwrapped_vault: vault_id.clone(),
        key_fingerprint: fingerprint,
    })
}

/// VERIFY a printed recovery code OFFLINE — decode + checksum only.
///
/// Makes NO network request whatsoever, which is exactly the property that lets
/// a client tell "you mistyped it" apart from "this server does not know that
/// kit" without leaking a code to a wrong server first.
///
/// # Errors
/// - [`CliError::Recovery`] wrapping the [`RecoveryError`].
pub fn recovery_verify(code: &str) -> Result<[u8; RECOVERY_SEED_LEN], CliError> {
    Ok(decode_recovery_kit(code)?)
}

/// One vault's recovery coverage, as observed FROM THIS DEVICE.
#[derive(Debug, Clone)]
pub struct RecoveryCoverage {
    /// The vault.
    pub vault_id: String,
    /// Whether the kit currently holds an envelope for it.
    pub covered: bool,
    /// RFC 3339 timestamp of the kit's envelope, when covered.
    pub covered_at: String,
    /// Whether the vault's sealed container has EVER been pushed to the op-log.
    /// ⚠️ A kit recovers KEYS, not DATA: an unsynced vault is unrecoverable even
    /// when it is "covered".
    pub synced: bool,
}

/// CHECK, from this device, which of its vaults the kit still covers.
///
/// ⚠️ Report this as "checked from this device", never as "you are covered". A
/// vault created on a sibling device that never heard of the kit is invisible
/// here — that is honest coverage drift, not a bug.
///
/// # Errors
/// - [`CliError::Server`] / [`CliError::Http`] from the transport (listing a
///   vault's envelopes needs WRITE on it).
pub fn recovery_check(
    server: &str,
    auth: &RequestAuth<'_>,
    kit_device_id: &str,
    keyring_path: &std::path::Path,
) -> Result<Vec<RecoveryCoverage>, CliError> {
    check_device_id(kit_device_id)?;
    let keyring = load_keyring(keyring_path)?;
    let mut out = Vec::with_capacity(keyring.keys.len());
    for vault_id in keyring.keys.keys() {
        let holders = list_key_envelopes(server, vault_id, auth)?;
        let kit = holders.iter().find(|h| h.device_id == kit_device_id);
        // "Has this vault ever been synced?" — one op is enough to answer it,
        // and the blob is opaque to us as much as to the server.
        let synced = !pull_ops_auth(server, vault_id, 0, auth)?.is_empty();
        out.push(RecoveryCoverage {
            vault_id: vault_id.clone(),
            covered: kit.is_some(),
            covered_at: kit.map(|k| k.created_at.clone()).unwrap_or_default(),
            synced,
        });
    }
    Ok(out)
}

/// COVER one vault with an existing kit: wrap this vault's key to the kit and
/// grant it `read`.
///
/// TWO PATHS, and the difference is the whole point:
///
/// * **On the GENERATING device** the kit's key is in the pin store with
///   `origin = "recovery-kit"`, so the DERIVED identity is used directly and
///   nothing is fetched. There is no substitution window at all.
/// * **On any OTHER device** there is no derived pin, so the key comes from the
///   server through [`verify_recipient_for_wrap`] — which on a first sight would
///   otherwise be plain trust-on-first-use. This is STRICTER than ADR 0038 here,
///   because
///   the out-of-band channel is guaranteed present: the safety number is printed
///   on the sheet in the user's own hand. `expected_safety_number` is therefore
///   REQUIRED on that path, and a mismatch is refused. A warning would not be
///   good enough when the verification channel is in the user's pocket.
///
/// # Errors
/// - [`CliError::Recovery`] if a sibling device gave no (or a wrong) safety
///   number.
/// - [`CliError::PinMismatch`] if the kit's published key changed.
/// - [`CliError::Server`] / [`CliError::Http`] from the transport.
#[allow(clippy::too_many_arguments)]
pub fn recovery_cover(
    server: &str,
    auth: &RequestAuth<'_>,
    kit_device_id: &str,
    vault_id: &str,
    keyring_path: &std::path::Path,
    pins_path: &std::path::Path,
    expected_safety_number: Option<&str>,
    sender: &SenderIdentity,
) -> Result<(String, bool), CliError> {
    check_device_id(kit_device_id)?;
    check_vault(vault_id)?;

    // ⭐ THE TRUST DECISION COMES FIRST, before the keyring is even read: a
    // device that cannot establish which key belongs to the kit must be refused
    // for THAT reason, not for whatever it happens to be missing locally.
    //
    // This used to be bespoke logic living here, which is exactly the defect the
    // fix round closed — `vault share --to <kitID>` reached the same outcome
    // without it. It is now the SHARED gate, so the requirement holds from every
    // command rather than from this one.
    let verified = verify_recipient_for_wrap(
        server,
        kit_device_id,
        auth,
        pins_path,
        expected_safety_number,
        // The caller SAID this is a recovery kit, so the gate does not have to
        // discover it — and cannot be fooled by a server that hides the label.
        true,
    )?;
    let derived = verified.trust() == RecipientTrust::Derived;

    let key = keyring_get(keyring_path, vault_id)?.ok_or_else(|| {
        CliError::Recovery(format!(
            "no vault key for {vault_id:?} in {}; only a SHARED vault can be covered — run \
             `sigil vault rekey --vault {vault_id}` first",
            keyring_path.display()
        ))
    })?;

    share_vault_to_known_key(server, vault_id, &verified, "read", &key, auth, sender)?;
    Ok((vault_key_fingerprint(&key), derived))
}

/// Compare safety numbers ignoring presentation (spacing/case), so a user who
/// typed the digits without spaces is not told their sheet is wrong.
fn normalize_safety_number(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// What a restore actually recovered.
#[derive(Debug, Clone)]
pub struct RestoreReport {
    /// The kit's device id.
    pub device_id: String,
    /// The account it belongs to.
    pub account_id: String,
    /// `(vault id, vault file path, key fingerprint, entries recovered)`.
    pub vaults: Vec<(String, std::path::PathBuf, String, usize)>,
    /// Vaults the index listed but that could not be recovered, with a reason.
    /// A covered-but-never-synced vault lands here: the KEY was recovered, the
    /// DATA was never on the server.
    pub skipped: Vec<(String, String)>,
    /// Whether the kit's own secrets were persisted (`--adopt`).
    pub adopted: bool,
}

/// RESTORE from a printed recovery kit.
///
/// The code is decoded and checksummed **OFFLINE, before any network I/O**, so a
/// mistyped code never reaches a server. Then: derive → authenticate v3 as the
/// kit → read the kit's own envelope index → per vault, collect the envelope,
/// unwrap the vault key, pull the op-log, OPEN the container (proving it is
/// readable) and only then write the vault file `0600` in a `0700` directory via
/// a temp file and a rename, so an unreadable container can never clobber a good
/// vault.
///
/// ⭐ **DEFAULT IS EPHEMERAL.** With `adopt = false` the kit's own secrets are
/// NOT written to disk: this machine recovers the vaults and remains an ordinary
/// machine. With `adopt = true` the Ed25519 seed and hybrid identity are
/// persisted `0600` — and the caller MUST tell the user that this machine is now
/// a second copy of the paper.
///
/// # Errors
/// - [`CliError::Recovery`] for an undecodable code (offline) or a kit whose
///   index is empty.
/// - [`CliError::Server`]: `401` = valid code, but this server has no such
///   device (wrong server, wrong account, or revoked — the server deliberately
///   will not say which).
pub fn recovery_restore(
    code: &str,
    server: &str,
    device_id: &str,
    out_dir: &std::path::Path,
    adopt: bool,
) -> Result<RestoreReport, CliError> {
    // ⭐ OFFLINE FIRST. Zero network I/O happens before this succeeds.
    let seed = recovery_verify(code)?;
    check_device_id(device_id)?;
    let identity = derive_recovery_identity(&seed);
    let auth = RequestAuth::V3 {
        device_id,
        seed: &identity.ed25519_seed,
    };

    let account = get_account(server, &auth)?;
    let indexed = list_recoverable_vaults(server, device_id, &auth)?;
    if indexed.is_empty() {
        return Err(CliError::Recovery(
            "valid code and device, but there is nothing to recover: this kit holds no vault key \
             on this server. It was enrolled but never covered a vault (`sigil recovery cover`), \
             or a `sigil vault rotate` dropped it."
                .to_string(),
        ));
    }

    ensure_state_dir(out_dir)?;
    let keyring_path = out_dir.join(VAULT_KEYRING_FILE);
    // The kit pins the senders it authenticates envelopes against, in the state
    // dir it is already writing the keyring and the vault files into.
    let pins_path = out_dir.join(HYBRID_PIN_FILE);
    let mut report = RestoreReport {
        device_id: device_id.to_string(),
        account_id: account.account_id,
        vaults: Vec::new(),
        skipped: Vec::new(),
        adopted: adopt,
    };

    for entry in &indexed {
        let envelope = match get_key_envelope(server, &entry.vault_id, device_id, &auth) {
            Ok(e) => e,
            Err(e) => {
                report.skipped.push((entry.vault_id.clone(), e.to_string()));
                continue;
            }
        };
        // ⭐ WHO DEPOSITED THIS? A vault-key envelope is authenticated to its
        // sender, so a restore must establish one. The kit knows nothing locally
        // — it is a fresh machine — so the sender id comes from the kit's OWN
        // envelope index. That id is server-supplied and therefore untrusted:
        // naming the wrong device simply makes the AEAD refuse, because the
        // sender's static key is an input to the derivation. A server can
        // withhold recovery this way; it cannot forge one.
        if entry.sender_device_id.is_empty() {
            report.skipped.push((
                entry.vault_id.clone(),
                "the server did not say which device deposited this envelope, so there is no \
                 sender to authenticate it against and it was NOT unwrapped"
                    .to_string(),
            ));
            continue;
        }
        let sender = match verify_sender_for_unwrap(
            server,
            &entry.sender_device_id,
            &auth,
            &pins_path,
            None,
        ) {
            Ok(s) => s,
            Err(e) => {
                report.skipped.push((
                    entry.vault_id.clone(),
                    format!(
                        "could not establish the sending device {}: {e}",
                        entry.sender_device_id
                    ),
                ));
                continue;
            }
        };
        let ctx = VaultKeyWrapContext::new(&entry.vault_id, device_id, &entry.sender_device_id)?;
        // Rejects a legacy/anonymous envelope, a forged one, and any recovered
        // plaintext that is not exactly 32 bytes.
        let key = match unwrap_vault_key(&identity.hybrid_secret, &sender, &ctx, &envelope) {
            Ok(k) => k,
            Err(e) => {
                report
                    .skipped
                    .push((entry.vault_id.clone(), format!("envelope refused: {e}")));
                continue;
            }
        };

        let ops = pull_ops_auth(server, &entry.vault_id, 0, &auth)?;
        let Some(last) = ops.last() else {
            report.skipped.push((
                entry.vault_id.clone(),
                "the key was recovered but this vault has NEVER been pushed to the op-log — a kit \
                 recovers KEYS, not DATA, so there is nothing here to open"
                    .to_string(),
            ));
            // The key is still worth keeping: the data may be pushed later.
            keyring_put(&keyring_path, &entry.vault_id, &key)?;
            continue;
        };

        // ⭐ OPEN BEFORE WRITING. A container that does not open never touches
        // the filesystem, so it cannot clobber anything.
        let vault = match open_vault(&key, &last.blob) {
            Ok(v) => v,
            Err(e) => {
                report.skipped.push((
                    entry.vault_id.clone(),
                    format!(
                        "the newest op for this vault did not open with the recovered key: {e}"
                    ),
                ));
                keyring_put(&keyring_path, &entry.vault_id, &key)?;
                continue;
            }
        };

        let path = out_dir.join(format!("{}.sigil", sanitize_file_stem(&entry.vault_id)));
        let tmp = path.with_extension("restore.tmp");
        write_secret_file(&tmp, &last.blob)
            .map_err(|e| CliError::Recovery(format!("could not write restored vault: {e}")))?;
        std::fs::rename(&tmp, &path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            CliError::Recovery(format!(
                "could not place restored vault {}: {e}",
                path.display()
            ))
        })?;
        keyring_put(&keyring_path, &entry.vault_id, &key)?;
        report.vaults.push((
            entry.vault_id.clone(),
            path,
            vault_key_fingerprint(&key),
            vault.entries.len(),
        ));
    }

    if adopt {
        // ⚠️ THIS MACHINE IS NOW A SECOND COPY OF THE PAPER.
        let key_path = out_dir.join("device.key");
        save_key(
            &key_path,
            &KeyFile {
                version: KEY_FILE_VERSION,
                seed: BASE64.encode(identity.ed25519_seed),
                public_key: BASE64.encode(identity.public_key),
                device_id: Some(device_id.to_string()),
            },
        )?;
        let hybrid_path = out_dir.join("device.hybrid");
        save_hybrid_secret(&hybrid_path, &identity.hybrid_secret)?;
        let mut pub_path = hybrid_path.clone().into_os_string();
        pub_path.push(".pub");
        save_hybrid_public(std::path::Path::new(&pub_path), &identity.hybrid_public)?;
        // This machine DERIVED the kit's hybrid key from the paper, so it knows
        // that key without ever asking a server — pin it as such. Without this,
        // an adopted machine would have to be handed the safety number to cover
        // a new vault with a key it holds the secret half of.
        pin_derived_key(&pins_path, device_id, &identity.hybrid_public)?;
    }

    Ok(report)
}

/// Create `dir` mode `0700` if it does not exist, so everything written into it
/// starts out owner-only.
fn ensure_state_dir(dir: &std::path::Path) -> Result<(), CliError> {
    use std::os::unix::fs::DirBuilderExt;
    if dir.as_os_str().is_empty() || dir.exists() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| CliError::Recovery(format!("could not create {}: {e}", dir.display())))
}

/// Make a vault id safe to use as a FILE NAME. Vault ids are already free of
/// `/` and whitespace ([`check_vault`]), so this only guards the remaining
/// awkward cases (`.`/`..` and other path-ish characters).
fn sanitize_file_stem(vault_id: &str) -> String {
    let cleaned: String = vault_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() || cleaned.chars().all(|c| c == '_') {
        "vault".to_string()
    } else {
        cleaned
    }
}

/// What a revocation did, and what the user still has to do by hand.
#[derive(Debug, Clone)]
pub struct RecoveryRevokeReport {
    /// The kit that was revoked.
    pub device_id: String,
    /// Vaults whose envelope for the kit was deleted.
    pub envelopes_removed: Vec<String>,
    /// Vaults where there was no envelope to remove.
    pub already_clear: Vec<String>,
}

/// REVOKE a recovery kit: refuse it at the door and take back its envelopes.
///
/// It does NOT auto-rotate. Rotation re-seals user data and must stay an
/// explicit act — and revocation cannot un-learn a key the kit already
/// unwrapped, so the caller is told to run `sigil vault rotate` per vault.
///
/// Sibling revocation (ADR 0040 §5) means any member device can do this; the kit
/// can also revoke itself.
///
/// # Errors
/// - [`CliError::Server`] / [`CliError::Http`] from the transport.
pub fn recovery_revoke(
    server: &str,
    auth: &RequestAuth<'_>,
    kit_device_id: &str,
    vault_ids: &[String],
) -> Result<RecoveryRevokeReport, CliError> {
    check_device_id(kit_device_id)?;
    // Envelopes FIRST, while the caller's own access is certainly intact — and
    // because a revoked device that still has an envelope sitting in its mailbox
    // is a worse state than the reverse.
    let mut removed = Vec::new();
    let mut clear = Vec::new();
    for vault_id in vault_ids {
        if delete_key_envelope(server, vault_id, kit_device_id, auth)? {
            removed.push(vault_id.clone());
        } else {
            clear.push(vault_id.clone());
        }
    }
    revoke_device(server, kit_device_id, auth, None)?;
    Ok(RecoveryRevokeReport {
        device_id: kit_device_id.to_string(),
        envelopes_removed: removed,
        already_clear: clear,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::format_recovery_kit;

    // --- Phase 54: the recovery kit -----------------------------------------

    /// ⭐ THE ANTI-DRIFT ANCHOR, reproduced from `sigil-core`'s own KAT. The
    /// same fixed seed must yield the same Ed25519 public key, the same X25519
    /// public key and the same ML-KEM encapsulation key here, in the wasm
    /// bindings and in JS — otherwise a kit printed by one client cannot be
    /// redeemed by another, and that failure is SILENT.
    #[test]
    fn recovery_derivation_known_answer_vector() {
        use sha2::Digest as _;
        let seed = [0x42u8; RECOVERY_SEED_LEN];
        let id = derive_recovery_identity(&seed);

        let hex = |b: &[u8]| -> String {
            let mut s = String::new();
            for x in b {
                s.push_str(&format!("{x:02x}"));
            }
            s
        };
        assert_eq!(
            hex(&id.public_key),
            "913af25b7f0ea458577b80124f137f7a8f0e5850a73a5cdeaf92e9169edeb717"
        );
        let keys = id.hybrid_public.decode().expect("decode hybrid public");
        assert_eq!(
            hex(&keys.x25519_public_key),
            "a55ac63d4d1f84face17abb82cc3449cd43c3f25f7a08008075bd594acc98754"
        );
        let digest: [u8; 32] = sha2::Sha256::digest(keys.mlkem_encaps_key).into();
        assert_eq!(
            hex(&digest),
            "14260b3e72b496ac3fde4a2434fd0f175f55324cca38ef8cd75a53675b643806"
        );
        // The PRINTED form of the same seed.
        let encoded = encode_recovery_kit(&seed);
        assert_eq!(
            format_recovery_kit(std::str::from_utf8(&encoded).unwrap()),
            "05144GJ2-89144GJ2-89144GJ2-89144GJ2-89144GJ2-89144GJ2-89145G6W"
        );
    }

    /// The derived hybrid identity must actually be usable as a KEM recipient:
    /// wrap a vault key to the PUBLIC half, unwrap it with the SECRET half.
    #[test]
    fn recovery_identity_wraps_and_unwraps_a_vault_key() {
        let seed = [0x9du8; RECOVERY_SEED_LEN];
        let id = derive_recovery_identity(&seed);
        let key = [0x5au8; VAULT_KEY_LEN];
        let (sender, verified) = test_sender("dev_owner");
        let ctx = VaultKeyWrapContext::new("demo", "dev_kit", "dev_owner").expect("ctx");
        let envelope = wrap_vault_key(&sender, &id.hybrid_public, &ctx, &key).expect("wrap");
        // A recovery envelope is an ORDINARY SIGILhyb container — no new format,
        // just the AUTHENTICATED version byte.
        assert_eq!(&envelope[..8], HYBRID_MAGIC.as_slice());
        assert_eq!(envelope[8], HYBRID_AUTH_FORMAT_VERSION);
        let recovered =
            unwrap_vault_key(&id.hybrid_secret, &verified, &ctx, &envelope).expect("unwrap");
        assert_eq!(recovered, key);

        // A DIFFERENT recovery secret recovers nothing.
        let other = derive_recovery_identity(&[0x9eu8; RECOVERY_SEED_LEN]);
        assert!(unwrap_vault_key(&other.hybrid_secret, &verified, &ctx, &envelope).is_err());
    }

    /// A code that round-trips through the printed form re-derives the SAME
    /// identity — the property the pre-print verification relies on.
    #[test]
    fn printed_code_round_trips_to_the_same_identity() {
        let seed = generate_recovery_seed().expect("rng");
        let code = encode_recovery_kit(&seed);
        let text = std::str::from_utf8(&code).unwrap();
        let grouped = format_recovery_kit(text);
        let parsed = recovery_verify(&grouped).expect("decode the grouped form");
        assert_eq!(parsed, seed);
        let a = derive_recovery_identity(&seed);
        let b = derive_recovery_identity(&parsed);
        assert_eq!(a.public_key, b.public_key);
        assert_eq!(
            a.hybrid_public.mlkem_encaps_key,
            b.hybrid_public.mlkem_encaps_key
        );
    }

    /// A mistyped code is rejected OFFLINE, and the error never echoes the code.
    #[test]
    fn a_mistyped_code_is_rejected_offline_without_echoing_it() {
        let seed = [0x31u8; RECOVERY_SEED_LEN];
        let code = encode_recovery_kit(&seed);
        let mut text = std::str::from_utf8(&code).unwrap().to_string();
        // Flip one character to a different alphabet member.
        let first = text.remove(0);
        text.insert(0, if first == 'Z' { 'Y' } else { 'Z' });
        let err = recovery_verify(&text).expect_err("must reject");
        let msg = err.to_string();
        assert!(msg.contains("not a valid recovery code"), "{msg}");
        assert!(!msg.contains(&text), "the error echoed the code: {msg}");
    }

    /// `pin_derived_key` writes a pin marked `origin: "recovery-kit"`, is
    /// idempotent for the same key, and REFUSES to replace a different one.
    #[test]
    fn pin_derived_key_marks_origin_and_refuses_replacement() {
        let dir = std::env::temp_dir().join(format!("sigil-pin-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let pins = dir.join("hybrid-pins.json");
        let _ = std::fs::remove_file(&pins);

        let id = derive_recovery_identity(&[0x07u8; RECOVERY_SEED_LEN]);
        pin_derived_key(&pins, "dev_kit", &id.hybrid_public).expect("first pin");
        let store = load_pins(&pins).expect("load");
        let pin = store.pins.get("dev_kit").expect("pinned");
        assert_eq!(pin.origin.as_deref(), Some(PIN_ORIGIN_RECOVERY_KIT));
        assert_eq!(pin.repins, 0);

        // Idempotent for the same key.
        pin_derived_key(&pins, "dev_kit", &id.hybrid_public).expect("re-pin same key");

        // A DIFFERENT key is refused — this function never silently replaces.
        let other = derive_recovery_identity(&[0x08u8; RECOVERY_SEED_LEN]);
        let err = pin_derived_key(&pins, "dev_kit", &other.hybrid_public).expect_err("must refuse");
        assert!(matches!(err, CliError::PinMismatch { .. }));
        // And the store is untouched.
        let after = load_pins(&pins).expect("load");
        assert_eq!(
            after.pins.get("dev_kit").unwrap().x25519_public_key,
            id.hybrid_public.x25519_public_key
        );

        // `derived_pin` finds it; an ordinary (fetched) pin is not "derived".
        assert!(derived_pin(&pins, "dev_kit").expect("derived").is_some());
        check_and_pin(&pins, "dev_other", &other.hybrid_public).expect("ordinary pin");
        assert!(derived_pin(&pins, "dev_other").expect("derived").is_none());
        let _ = std::fs::remove_file(&pins);
    }

    /// An OLD pin store (no `origin` field) still parses, and a store written
    /// without a kit still has no `origin` key at all — the pin-store VERSION
    /// was deliberately not bumped.
    #[test]
    fn pin_store_origin_is_additive_and_omitted_when_absent() {
        let legacy = r#"{"version":1,"pins":{"dev_a":{"device_id":"dev_a",
            "x25519_public_key":"AA==","mlkem_encaps_key":"AA==",
            "safety_number":"00000 00000 00000 00000 00000 00000","pinned_at":1,"repins":0}}}"#;
        let store: HybridPinStore = serde_json::from_str(legacy).expect("legacy store parses");
        assert_eq!(store.version, HYBRID_PIN_STORE_VERSION);
        assert!(store.pins.get("dev_a").unwrap().origin.is_none());

        let rendered = serde_json::to_string(&store).expect("serialize");
        assert!(
            !rendered.contains("origin"),
            "an absent origin must not be written: {rendered}"
        );
    }

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

    // --- ⛔ Hostile Argon2 parameters in the container header (Phase 59) ------
    //
    // The header is unauthenticated framing, and Argon2id allocates `m_cost` KiB
    // in ONE block before doing any work. These bytes reach a client through
    // sigild's zero-knowledge op-log, which cannot filter them, so the refusal
    // has to be here. Each test below completing at all is the evidence that
    // nothing was allocated: an unbounded parse would have asked the allocator
    // for terabytes.

    /// Overwrite the three u32 LE work factors in a `SIGILcli` header in place.
    fn set_header_params(c: &mut [u8], m: u32, t: u32, p: u32) {
        c[9..13].copy_from_slice(&m.to_le_bytes());
        c[13..17].copy_from_slice(&t.to_le_bytes());
        c[17..21].copy_from_slice(&p.to_le_bytes());
    }

    #[test]
    fn absurd_m_cost_in_the_header_is_refused_before_allocating() {
        let mut c = seal_to_container(PASSWORD, b"payload", FAST).expect("seal");
        // ~4 TiB of memory. Unbounded, this is the process dying on allocation
        // every time the user pulls their vault.
        set_header_params(&mut c, 0xFFFF_FFF0, 1, 1);
        assert_eq!(
            open_container(PASSWORD, &c),
            Err(CliError::ParamsOutOfRange {
                m_cost: 0xFFFF_FFF0,
                t_cost: 1,
                p_cost: 1
            })
        );
    }

    #[test]
    fn each_work_factor_is_bounded_independently() {
        for (m, t, p) in [
            (Argon2Params::MAX_M_COST + 1, 1, 1),
            (8, Argon2Params::MAX_T_COST + 1, 1),
            (8, 1, Argon2Params::MAX_P_COST + 1),
        ] {
            let mut c = seal_to_container(PASSWORD, b"payload", FAST).expect("seal");
            set_header_params(&mut c, m, t, p);
            assert_eq!(
                open_container(PASSWORD, &c),
                Err(CliError::ParamsOutOfRange {
                    m_cost: m,
                    t_cost: t,
                    p_cost: p
                }),
                "({m},{t},{p}) must be refused"
            );
        }
    }

    #[test]
    fn a_normal_container_still_opens_and_the_ceiling_is_above_what_we_write() {
        // Nothing that opens today may stop opening. Prove it for the two
        // parameter sets this repo actually writes plus the test-fast one.
        for params in [
            FAST,
            Argon2Params {
                m_cost: 19456,
                t_cost: 2,
                p_cost: 1,
            },
        ] {
            let c = seal_to_container(PASSWORD, b"payload", params).expect("seal");
            assert_eq!(
                open_container(PASSWORD, &c).expect("open"),
                b"payload".to_vec()
            );
        }
        // RECOMMENDED is 64 MiB — assert the bound admits it without paying for
        // a 64 MiB derivation in a unit test.
        assert!(Argon2Params::RECOMMENDED.validate().is_ok());
        // And the ceiling itself is accepted (inclusive bound), so raising the
        // work factor later needs no format change.
        let ceiling = Argon2Params {
            m_cost: Argon2Params::MAX_M_COST,
            t_cost: Argon2Params::MAX_T_COST,
            p_cost: Argon2Params::MAX_P_COST,
        };
        assert!(ceiling.validate().is_ok());
    }

    #[test]
    fn the_refusal_is_typed_and_names_no_secret() {
        let mut c = seal_to_container(PASSWORD, b"payload", FAST).expect("seal");
        set_header_params(&mut c, 0xFFFF_FFF0, 1, 1);
        let msg = open_container(PASSWORD, &c).unwrap_err().to_string();
        // It must NOT be reported as a wrong password / generic KDF failure —
        // the user has to be able to tell "hostile container" from "typo".
        assert!(msg.contains("4294967280"), "names what was demanded: {msg}");
        assert!(msg.contains("Nothing was allocated"), "{msg}");
        assert!(!msg.contains(core::str::from_utf8(PASSWORD).unwrap()));
    }

    #[test]
    fn container_params_reads_the_header_without_a_password() {
        let c = seal_to_container(PASSWORD, b"payload", FAST).expect("seal");
        assert_eq!(container_params(&c).expect("params"), FAST);

        let mut hostile = c.clone();
        set_header_params(&mut hostile, 0xFFFF_FFF0, 1, 1);
        assert!(matches!(
            container_params(&hostile),
            Err(CliError::ParamsOutOfRange { .. })
        ));
    }

    // --- ⭐ The no-downgrade rule on re-seal ---------------------------------

    #[test]
    fn no_downgrade_is_a_componentwise_ratchet() {
        let weak = Argon2Params {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let strong = Argon2Params {
            m_cost: 19456,
            t_cost: 2,
            p_cost: 1,
        };
        // Up is allowed…
        assert_eq!(no_downgrade(weak, strong), strong);
        // …down is not: a weak input container cannot drag a strong re-seal down.
        assert_eq!(no_downgrade(strong, weak), strong);
        // Mixed: each factor rises independently.
        assert_eq!(
            no_downgrade(
                Argon2Params {
                    m_cost: 65536,
                    t_cost: 1,
                    p_cost: 1
                },
                Argon2Params {
                    m_cost: 8,
                    t_cost: 4,
                    p_cost: 2
                }
            ),
            Argon2Params {
                m_cost: 65536,
                t_cost: 4,
                p_cost: 2
            }
        );
        // Argon2 needs m_cost >= 8 * p_cost; a componentwise max could break
        // that, so m_cost is floored to it and the result stays in range.
        let repaired = no_downgrade(
            Argon2Params {
                m_cost: 8,
                t_cost: 1,
                p_cost: 1,
            },
            Argon2Params {
                m_cost: 8,
                t_cost: 1,
                p_cost: 4,
            },
        );
        assert_eq!(repaired.m_cost, 32);
        assert!(repaired.validate().is_ok());
    }

    #[test]
    fn reseal_cannot_lower_the_parameters_it_read() {
        let strong = Argon2Params {
            m_cost: 128,
            t_cost: 3,
            p_cost: 2,
        };
        let c = seal_to_container(b"old", b"payload", strong).expect("seal");

        // Ask for a WEAKER re-seal, as an attacker who got a weak container
        // accepted would want. The output header must still carry `strong`.
        let resealed = reseal_container(b"old", b"new", &c, FAST).expect("reseal");
        assert_eq!(container_params(&resealed).expect("params"), strong);
        assert_eq!(
            open_container(b"new", &resealed).expect("open"),
            b"payload".to_vec()
        );

        // And a re-seal that asks for MORE still gets more (the ratchet turns).
        let up = Argon2Params {
            m_cost: 19456,
            t_cost: 3,
            p_cost: 2,
        };
        let raised = reseal_container(b"new", b"newer", &resealed, up).expect("reseal up");
        assert_eq!(container_params(&raised).expect("params"), up);
    }

    #[test]
    fn reseal_refuses_a_hostile_input_header() {
        let mut c = seal_to_container(b"old", b"payload", FAST).expect("seal");
        set_header_params(&mut c, 0xFFFF_FFF0, 1, 1);
        assert!(matches!(
            reseal_container(b"old", b"new", &c, FAST),
            Err(CliError::ParamsOutOfRange { .. })
        ));
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
        let mut parsed = parse_otpauth_uri(&uri).expect("re-parse");
        // `otpauth://` is an INTEROP format with no field for a Sigil-local entry
        // id, so a re-parse yields a fresh one. Everything the URI carries must
        // survive exactly.
        assert!(parsed.uuid.is_some() && parsed.uuid != entry.uuid);
        parsed.uuid = entry.uuid.clone();
        assert_eq!(parsed, entry);

        // An entry with no issuer round-trips too (no `Issuer:` path prefix).
        let no_issuer =
            new_totp_entry("solo", None, &secret, OtpAlgorithm::Sha1, 6, 30).expect("entry");
        let uri2 = entry_to_otpauth_uri(&no_issuer).expect("export uri");
        let mut parsed2 = parse_otpauth_uri(&uri2).expect("re-parse");
        parsed2.uuid = no_issuer.uuid.clone();
        assert_eq!(parsed2, no_issuer);
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

        // ⭐ Phase 61: a duplicate LABEL is now ALLOWED (the same label at a
        // different issuer is a different account — that was the Google
        // Authenticator import defect). A duplicate IDENTITY is still rejected.
        vault
            .add(new_totp_entry("acct", None, &secret, OtpAlgorithm::Sha1, 6, 30).expect("entry"))
            .expect("same label, different issuer -> a different account");
        let dup = vault.entries[0].clone();
        assert!(matches!(vault.add(dup), Err(CliError::Totp(_))));
        vault.entries.truncate(1);

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

    // --- ⭐ Schema forward-compatibility (Phase 59) --------------------------
    //
    // The vault schema is MIRRORED across four clients and a printed recovery
    // kit. Before this, serde DROPPED any field it did not know, so an old client
    // that merely opened and re-sealed a vault deleted a newer client's data — on
    // a sync path where the oldest writer wins. `test/schema-interop.mjs` proves
    // the same property across the Rust/JS boundary; these pin the Rust half.

    #[test]
    fn unknown_top_level_fields_survive_an_open_and_reseal() {
        let future = br#"{
            "version": 1,
            "entries": [],
            "vault_name": "work",
            "future_object": {"nested": [1, 2, 3]}
        }"#;
        let vault: TotpVault = serde_json::from_slice(future).expect("parse");
        assert_eq!(vault.extra.len(), 2);
        assert_eq!(vault.extra["vault_name"], serde_json::json!("work"));

        // Re-serialize: the unknown fields must still be there, verbatim.
        let out: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&vault).unwrap()).unwrap();
        assert_eq!(out["vault_name"], serde_json::json!("work"));
        assert_eq!(out["future_object"]["nested"], serde_json::json!([1, 2, 3]));
    }

    #[test]
    fn unknown_per_entry_fields_survive_an_open_and_reseal() {
        let future = br#"{
            "version": 1,
            "entries": [{
                "label": "acct",
                "secret": "MTIzNDU2Nzg5MA==",
                "algorithm": "sha1",
                "digits": 6,
                "period": 30,
                "uuid": "11111111-2222-4333-8444-555555555555",
                "icon": "github",
                "tags": ["work", "critical"]
            }]
        }"#;
        let mut vault: TotpVault = serde_json::from_slice(future).expect("parse");
        let e = &vault.entries[0];
        assert_eq!(
            e.uuid.as_deref(),
            Some("11111111-2222-4333-8444-555555555555")
        );
        assert_eq!(e.extra["icon"], serde_json::json!("github"));

        // Edit the vault the way an old client would (append an entry) and
        // re-serialize: the OTHER entry's unknown fields must be untouched.
        vault
            .add(new_totp_entry("second", None, b"0123456789", OtpAlgorithm::Sha1, 6, 30).unwrap())
            .expect("add");
        let out: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&vault).unwrap()).unwrap();
        assert_eq!(out["entries"][0]["icon"], serde_json::json!("github"));
        assert_eq!(
            out["entries"][0]["tags"],
            serde_json::json!(["work", "critical"])
        );
        assert_eq!(
            out["entries"][0]["uuid"],
            serde_json::json!("11111111-2222-4333-8444-555555555555")
        );
        // …and the newly added entry got an id of its own.
        assert!(out["entries"][1]["uuid"].is_string());
    }

    #[test]
    fn a_vault_this_build_writes_is_byte_shape_compatible_with_the_old_one() {
        // Nothing that opens today may stop opening, and an untouched vault must
        // not grow fields: `min_reader_version` and `extra` are OMITTED when
        // empty, and `uuid` is omitted when absent.
        let vault = TotpVault::default();
        let json = String::from_utf8(serde_json::to_vec(&vault).unwrap()).unwrap();
        assert_eq!(json, r#"{"version":1,"entries":[]}"#);

        let bare = new_totp_entry_with_uuid("a", None, b"k", OtpAlgorithm::Sha1, 6, 30, None)
            .expect("entry");
        let json = String::from_utf8(serde_json::to_vec(&bare).unwrap()).unwrap();
        assert!(!json.contains("uuid"), "{json}");
    }

    // -- Phase 61: entry identity and the 2P-Set merge ----------------------

    fn e(label: &str, issuer: Option<&str>, secret: &[u8], uuid: Option<&str>) -> TotpEntry {
        new_totp_entry_with_uuid(
            label,
            issuer.map(str::to_string),
            secret,
            OtpAlgorithm::Sha1,
            6,
            30,
            uuid.map(str::to_string),
        )
        .expect("entry")
    }

    fn v(entries: Vec<TotpEntry>) -> TotpVault {
        TotpVault {
            entries,
            ..TotpVault::default()
        }
    }

    fn labels(vault: &TotpVault) -> Vec<String> {
        let mut l: Vec<String> = vault.entries.iter().map(|x| x.label.clone()).collect();
        l.sort();
        l
    }

    #[test]
    fn the_headline_two_devices_each_add_offline_and_nothing_is_lost() {
        // The exact CRITICAL-1 sequence: both devices start from `base`, each
        // adds a different account without pulling, and their snapshots meet.
        let base = e(
            "base",
            None,
            b"b",
            Some("00000000-0000-4000-8000-000000000000"),
        );
        let a = v(vec![
            base.clone(),
            e(
                "alpha",
                None,
                b"a",
                Some("11111111-1111-4111-8111-111111111111"),
            ),
        ]);
        let b = v(vec![
            base,
            e(
                "bravo",
                None,
                b"c",
                Some("22222222-2222-4222-8222-222222222222"),
            ),
        ]);
        let (merged, report) = merge_vaults(&a, &b);
        assert_eq!(labels(&merged), vec!["alpha", "base", "bravo"]);
        assert_eq!(report.added, 1);
        // …and it converges: the other device computes byte-identical plaintext.
        let (other, _) = merge_vaults(&b, &a);
        assert_eq!(
            serde_json::to_string(&merged).unwrap(),
            serde_json::to_string(&other).unwrap(),
            "merge must be commutative down to the bytes"
        );
    }

    #[test]
    fn merge_is_idempotent_and_associative() {
        let x = v(vec![e(
            "x",
            None,
            b"1",
            Some("aaaaaaaa-0000-4000-8000-000000000000"),
        )]);
        let y = v(vec![e(
            "y",
            None,
            b"2",
            Some("bbbbbbbb-0000-4000-8000-000000000000"),
        )]);
        let z = v(vec![e(
            "z",
            None,
            b"3",
            Some("cccccccc-0000-4000-8000-000000000000"),
        )]);
        let (xy, _) = merge_vaults(&x, &y);
        let (xy_z, _) = merge_vaults(&xy, &z);
        let (yz, _) = merge_vaults(&y, &z);
        let (x_yz, _) = merge_vaults(&x, &yz);
        assert_eq!(xy_z, x_yz, "associative");
        let (again, report) = merge_vaults(&xy_z, &xy_z);
        assert_eq!(again, xy_z, "idempotent");
        assert!(!report.changed);
    }

    // ═══════════════════════════════════════════════════════════════════════
    // ⭐⭐ THE ALGEBRA, AS A PROPERTY OVER GENERATED INPUTS.
    //
    // ⛔ WHY THIS EXISTS. `merge_vaults`'s doc comment claims "commutative,
    // associative and idempotent" WITHOUT QUALIFICATION, and the claim had a
    // real, reproduced exception: tombstone-level unknown (`extra`) fields
    // merged FIRST-SEEN-WINS (`extra.entry(k).or_insert_with(…)`), so two vaults
    // whose tombstones shared a uuid but disagreed about an unknown key gave
    // `merge(a,b) != merge(b,a)` and never converged. Every hand-written example
    // test stayed green, because none of them put an unknown field on a
    // tombstone — which is exactly what a FUTURE version of this client will do
    // (ADR 0047 forward compatibility) and what this one must carry through.
    //
    // ⭐ The fix was to make the claim TRUE (the same lexicographic-max rule the
    // vault level already used) rather than to qualify it, and this is the test
    // that keeps it true: it exercises the field kinds a hand-written example
    // forgets, in every order.
    // ═══════════════════════════════════════════════════════════════════════

    /// A tiny deterministic PRNG. ⚠️ Hand-rolled xorshift64* rather than a crate:
    /// no new dependency is allowed here, and this is a test fixture generator,
    /// not cryptography.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
        fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
            &xs[usize::try_from(self.below(xs.len() as u64)).unwrap()]
        }
    }

    /// A random vault drawn from a SMALL shared pool of ids, so two independently
    /// generated vaults genuinely overlap — the only way a conflict, a
    /// same-uuid tombstone pair or a same-key `extra` disagreement is ever hit.
    fn arbitrary_vault(rng: &mut Rng) -> TotpVault {
        // ⚠️ A tiny pool ON PURPOSE. With unique ids everywhere the union is
        // trivially commutative and this test would prove nothing.
        const IDS: [&str; 4] = [
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "44444444-4444-4444-8444-444444444444",
        ];
        const SECRETS: [&[u8]; 3] = [b"aaaaaaaaaaaaaaaaaaaa", b"bbbbbbbbbbbbbbbbbbbb", b"cc"];
        const LABELS: [&str; 3] = ["alpha", "bravo", "charlie"];
        const ISSUERS: [Option<&str>; 3] = [None, Some("GitHub"), Some("GitLab")];
        // The unknown-field VALUES that a future version might write. Two
        // different values under the SAME key is the whole point.
        let unknown_values = [
            serde_json::json!("left"),
            serde_json::json!("right"),
            serde_json::json!({ "z": 1, "a": 2 }),
            serde_json::json!([1, 2, 3]),
            serde_json::json!(7),
        ];

        let mut entries = Vec::new();
        for id in IDS {
            if rng.below(3) == 0 {
                continue;
            }
            let mut entry = e(
                rng.pick(&LABELS),
                *rng.pick(&ISSUERS),
                rng.pick(&SECRETS),
                Some(id),
            );
            // Some entries carry NO uuid at all (a pre-Phase-61 row), so the
            // derived-identity path is in the property too.
            if rng.below(5) == 0 {
                entry.uuid = None;
            }
            if rng.below(3) == 0 {
                entry.extra.insert(
                    "future_entry_field".to_string(),
                    rng.pick(&unknown_values).clone(),
                );
            }
            entries.push(entry);
        }

        let mut tombstones = Vec::new();
        for id in IDS {
            if rng.below(3) != 0 {
                continue;
            }
            let mut t = Tombstone {
                uuid: id.to_string(),
                deleted_at: if rng.below(4) == 0 {
                    None
                } else {
                    Some(1_700_000_000 + rng.below(1000))
                },
                extra: std::collections::BTreeMap::new(),
            };
            // ⭐ THE FIELD KIND THE REGRESSION LIVED IN. Two tombstones for the
            // same uuid carrying DIFFERENT values under the same unknown key is
            // precisely the input that made the merge order-dependent.
            if rng.below(2) == 0 {
                t.extra.insert(
                    "future_tombstone_field".to_string(),
                    rng.pick(&unknown_values).clone(),
                );
            }
            if rng.below(4) == 0 {
                t.extra
                    .insert("reason".to_string(), rng.pick(&unknown_values).clone());
            }
            tombstones.push(t);
        }

        let mut extra = std::collections::BTreeMap::new();
        if rng.below(2) == 0 {
            extra.insert(
                "future_vault_field".to_string(),
                rng.pick(&unknown_values).clone(),
            );
        }

        TotpVault {
            version: 1,
            min_reader_version: if rng.below(4) == 0 { Some(1) } else { None },
            entries,
            tombstones,
            extra,
        }
    }

    /// ⚠️ THIS SORTS EVERY KEY, SO IT IS **NOT** A BYTE-ORDER ORACLE.
    ///
    /// `serde_json::to_value` round-trips through a `BTreeMap`, so this returns
    /// key-sorted JSON no matter what order the fields were in. That makes it a
    /// fine oracle for "did the merge select the same VALUES", and useless for
    /// "did it produce the same BYTES".
    ///
    /// ⛔ That distinction is not academic: comparing through a canonicalizing
    /// helper is exactly how the JS mirror shipped a merge that was commutative
    /// in value and NOT in key order, with a property test that could not see
    /// it. Rust happens to be safe here because `serde_json::Value` sorts on the
    /// way out anyway — but a future change that hand-rolls serialization would
    /// reintroduce the same blind spot, and this test would still pass.
    ///
    /// The byte-level oracle is `vaultToJson` on the JS side, asserted
    /// cross-language against this binary in `sigil-wasm/test/merge-interop.mjs`
    /// (the `BYTES` section).
    fn canon_vault(v: &TotpVault) -> String {
        serde_json::to_string(&serde_json::to_value(v).expect("value")).expect("json")
    }

    #[test]
    fn merge_is_order_independent_over_generated_vaults() {
        let mut rng = Rng(0x5EED_1234_ABCD_0001);
        let mut saw_tombstone_extra_conflict = 0usize;
        for round in 0..600u32 {
            let a = arbitrary_vault(&mut rng);
            let b = arbitrary_vault(&mut rng);

            // Did this round actually contain the input the regression needs? A
            // property test that never generates the interesting case is a
            // no-op, so it is COUNTED and asserted at the end.
            for ta in &a.tombstones {
                for tb in &b.tombstones {
                    if ta.uuid == tb.uuid && ta.extra != tb.extra {
                        saw_tombstone_extra_conflict += 1;
                    }
                }
            }

            let (ab, _) = merge_vaults(&a, &b);
            let (ba, _) = merge_vaults(&b, &a);
            assert_eq!(
                canon_vault(&ab),
                canon_vault(&ba),
                "round {round}: merge is NOT commutative.\n  a={}\n  b={}",
                canon_vault(&a),
                canon_vault(&b)
            );

            // Idempotent: joining a value with itself changes nothing.
            let (again, _) = merge_vaults(&ab, &ab);
            assert_eq!(
                canon_vault(&again),
                canon_vault(&ab),
                "round {round}: merge is NOT idempotent"
            );

            // Associative, which is what makes a THIRD device joining late
            // converge no matter which pair merged first.
            let c = arbitrary_vault(&mut rng);
            let (bc, _) = merge_vaults(&b, &c);
            let (ab_c, _) = merge_vaults(&ab, &c);
            let (a_bc, _) = merge_vaults(&a, &bc);
            assert_eq!(
                canon_vault(&ab_c),
                canon_vault(&a_bc),
                "round {round}: merge is NOT associative"
            );
        }
        assert!(
            saw_tombstone_extra_conflict >= 20,
            "the generator never produced two tombstones sharing a uuid with DIFFERENT unknown \
             fields ({saw_tombstone_extra_conflict} times) — this property would then pass \
             without exercising the case it exists for"
        );
    }

    /// The minimal, hand-written witness of the regression, so a failure names it
    /// rather than dumping a generated pair.
    #[test]
    fn tombstone_unknown_fields_merge_commutatively() {
        let tomb = |value: serde_json::Value| {
            let mut extra = std::collections::BTreeMap::new();
            extra.insert("future_tombstone_field".to_string(), value);
            TotpVault {
                tombstones: vec![Tombstone {
                    uuid: "11111111-1111-4111-8111-111111111111".to_string(),
                    deleted_at: Some(1_700_000_000),
                    extra,
                }],
                ..TotpVault::default()
            }
        };
        let left = tomb(serde_json::json!("aaa"));
        let right = tomb(serde_json::json!("zzz"));
        let (ab, _) = merge_vaults(&left, &right);
        let (ba, _) = merge_vaults(&right, &left);
        assert_eq!(
            canon_vault(&ab),
            canon_vault(&ba),
            "⛔ tombstone `extra` merged FIRST-SEEN-WINS, so two devices that merged in \
             different orders hold different bytes forever"
        );
        // …and the surviving value is the deterministic MAX, not "whichever
        // arrived first" — the same rule the vault level uses.
        assert_eq!(
            ab.tombstones[0].extra["future_tombstone_field"],
            serde_json::json!("zzz")
        );
    }

    #[test]
    fn a_delete_survives_a_stale_snapshot_that_still_holds_the_entry() {
        let alpha = e(
            "alpha",
            None,
            b"a",
            Some("11111111-1111-4111-8111-111111111111"),
        );
        let stale = v(vec![alpha.clone()]);
        let mut deleted = stale.clone();
        deleted.remove_at("alpha", Some(1_700_000_000)).expect("rm");
        assert_eq!(deleted.tombstones.len(), 1);

        let (merged, report) = merge_vaults(&deleted, &stale);
        assert!(merged.entries.is_empty(), "the tombstone must win");
        assert_eq!(report.removed, 1);
        // …and in the other direction, which is the case that matters: a device
        // that still holds the entry merges the delete in.
        let (other, _) = merge_vaults(&stale, &deleted);
        assert!(other.entries.is_empty());
        assert_eq!(merged, other);
    }

    #[test]
    fn a_tombstone_does_not_poison_a_genuine_re_add() {
        // A re-add draws a FRESH uuid, so it is a different element and delete-wins
        // cannot eat it. This is what makes "tombstone always wins" safe.
        let mut vault = v(vec![e(
            "alpha",
            None,
            b"a",
            Some("11111111-1111-4111-8111-111111111111"),
        )]);
        vault.remove_at("alpha", Some(1)).expect("rm");
        vault
            .add(e(
                "alpha",
                None,
                b"a",
                Some("99999999-9999-4999-8999-999999999999"),
            ))
            .expect("re-add");
        let (merged, _) = merge_vaults(&vault, &vault);
        assert_eq!(labels(&merged), vec!["alpha"]);
        assert_eq!(merged.tombstones.len(), 1);
    }

    #[test]
    fn two_devices_normalizing_the_same_legacy_vault_do_not_duplicate() {
        // ⭐ The migration-safety property. A RANDOM id here would double every
        // account in every existing multi-device vault on first sync.
        let legacy = v(vec![
            e("alpha", Some("GitHub"), b"a", None),
            e("bravo", None, b"b", None),
        ]);
        let mut a = legacy.clone();
        let mut b = legacy.clone();
        normalize_vault(&mut a);
        normalize_vault(&mut b);
        assert_eq!(a, b, "the derived ids must agree across devices");
        let (merged, _) = merge_vaults(&a, &b);
        assert_eq!(merged.entries.len(), 2, "2 entries, not 4");
        // …and a delete on one device suppresses the other's still-legacy copy.
        a.remove_at("alpha", Some(5)).expect("rm");
        let (after, _) = merge_vaults(&legacy, &a);
        assert_eq!(labels(&after), vec!["bravo"]);
    }

    #[test]
    fn normalize_is_idempotent_and_disambiguates_an_identical_pair() {
        let mut vault = v(vec![
            e("dup", None, b"same", None),
            e("dup", None, b"same", None),
        ]);
        normalize_vault(&mut vault);
        let ids: Vec<String> = vault.entries.iter().map(entry_identity).collect();
        assert_ne!(ids[0], ids[1], "a hand-edited duplicate must not collapse");
        let before = vault.clone();
        normalize_vault(&mut vault);
        assert_eq!(before, vault, "idempotent");
    }

    #[test]
    fn work_at_two_issuers_is_two_entries() {
        // CRITICAL 2. Identity is content, not the label.
        let mut vault = TotpVault::default();
        vault
            .add(e("work", Some("GitHub"), b"gh", None))
            .expect("a");
        vault
            .add(e("work", Some("GitLab"), b"gl", None))
            .expect("b");
        assert_eq!(vault.entries.len(), 2);
        // …but the byte-identical account twice is still refused.
        assert!(vault.add(e("work", Some("GitHub"), b"gh", None)).is_err());
        // …and an ambiguous removal refuses instead of guessing.
        let err = vault.remove_at("work", None).unwrap_err().to_string();
        assert!(err.contains("--id"), "{err}");
        assert_eq!(vault.entries.len(), 2, "nothing was removed");
    }

    #[test]
    fn re_adding_an_account_that_already_has_a_random_id_is_still_refused() {
        // ⛔ THE BUG THIS PINS, which the first cut of Phase 61 actually had: the
        // de-dup compared `entry_identity` on both sides. A candidate coming from
        // an import carries NO uuid (so its identity is its content) while the
        // copy in the vault carries a RANDOM one — the two could never be equal,
        // so re-importing the same Google Authenticator export duplicated every
        // account in it. The comparison must be `entry_fingerprint` (content).
        let mut vault = TotpVault::default();
        let stored = new_totp_entry(
            "work",
            Some("GitHub".into()),
            b"gh",
            OtpAlgorithm::Sha1,
            6,
            30,
        )
        .expect("entry");
        assert!(stored.uuid.is_some(), "a new entry draws a random id");
        vault.add(stored).expect("first add");

        // The SAME account arriving from an import, with no id of its own.
        let imported = e("work", Some("GitHub"), b"gh", None);
        assert_ne!(
            entry_identity(&imported),
            entry_identity(&vault.entries[0]),
            "identities differ — which is exactly why they cannot be the comparison"
        );
        assert_eq!(
            entry_fingerprint(&imported),
            entry_fingerprint(&vault.entries[0]),
            "…while the fingerprints agree, because it is the same account"
        );
        assert!(vault.add(imported).is_err(), "a re-import must be a no-op");
        assert_eq!(vault.entries.len(), 1);

        // …and a genuinely different account with the same label still lands.
        vault
            .add(e("work", Some("GitLab"), b"gl", None))
            .expect("a different account");
        assert_eq!(vault.entries.len(), 2);
    }

    #[test]
    fn the_same_id_with_different_content_keeps_a_deterministic_winner() {
        let id = "11111111-1111-4111-8111-111111111111";
        let a = v(vec![e("alpha", None, b"one", Some(id))]);
        let b = v(vec![e("alpha", None, b"two", Some(id))]);
        let (ab, ra) = merge_vaults(&a, &b);
        let (ba, _) = merge_vaults(&b, &a);
        assert_eq!(ab, ba, "order must not decide the winner");
        assert_eq!(ra.conflicts, vec![id.to_string()]);
    }

    #[test]
    fn merge_preserves_unknown_fields_at_both_levels() {
        // ADR 0047 forward-compatibility must survive the NEW code path too.
        let a: TotpVault = serde_json::from_str(
            r#"{"version":1,"entries":[{"label":"a","secret":"aaaa","algorithm":"sha1",
                "digits":6,"period":30,"uuid":"11111111-1111-4111-8111-111111111111",
                "icon":"github"}],"future_top":{"k":1}}"#,
        )
        .expect("a");
        let b: TotpVault = serde_json::from_str(
            r#"{"version":1,"entries":[{"label":"b","secret":"bbbb","algorithm":"sha1",
                "digits":6,"period":30,"uuid":"22222222-2222-4222-8222-222222222222"}],
                "other_top":"x"}"#,
        )
        .expect("b");
        let (merged, _) = merge_vaults(&a, &b);
        let out: serde_json::Value =
            serde_json::from_slice(&serde_json::to_vec(&merged).unwrap()).unwrap();
        assert_eq!(out["future_top"], serde_json::json!({"k": 1}));
        assert_eq!(out["other_top"], serde_json::json!("x"));
        assert_eq!(out["entries"][0]["icon"], serde_json::json!("github"));
    }

    #[test]
    fn a_merged_vault_still_writes_the_old_byte_shape_when_nothing_was_deleted() {
        let (merged, _) = merge_vaults(&TotpVault::default(), &TotpVault::default());
        let json = String::from_utf8(serde_json::to_vec(&merged).unwrap()).unwrap();
        assert_eq!(json, r#"{"version":1,"entries":[]}"#);
        assert!(!json.contains("tombstones"));
    }

    #[test]
    fn merge_ops_folds_every_op_not_just_the_tip() {
        let secret = b"pw".as_slice();
        let params = Argon2Params {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let base = v(vec![e(
            "base",
            None,
            b"b",
            Some("00000000-0000-4000-8000-000000000000"),
        )]);
        let mut a = base.clone();
        a.add(e(
            "alpha",
            None,
            b"a",
            Some("11111111-1111-4111-8111-111111111111"),
        ))
        .expect("a");
        let mut b = base.clone();
        b.add(e(
            "bravo",
            None,
            b"c",
            Some("22222222-2222-4222-8222-222222222222"),
        ))
        .expect("b");
        let ops = vec![
            PulledOp {
                seq: 1,
                blob: seal_vault(secret, &a, params).expect("seal a"),
            },
            // The TIP, which has never seen `alpha`.
            PulledOp {
                seq: 2,
                blob: seal_vault(secret, &b, params).expect("seal b"),
            },
        ];
        let (merged, report) = merge_ops_into(&base, secret, &ops);
        assert_eq!(labels(&merged), vec!["alpha", "base", "bravo"]);
        assert_eq!(report.applied, 2);
        assert_eq!(report.tip, 2);
        assert!(report.skipped.is_empty());

        // An op sealed under a DIFFERENT key is skipped and NAMED, never fatal.
        let mut ops2 = ops.clone();
        ops2.push(PulledOp {
            seq: 3,
            blob: seal_vault(b"other", &a, params).expect("seal"),
        });
        let (merged2, report2) = merge_ops_into(&base, secret, &ops2);
        assert_eq!(labels(&merged2), vec!["alpha", "base", "bravo"]);
        assert_eq!(report2.skipped.len(), 1);
        assert_eq!(report2.skipped[0].0, 3);
    }

    #[test]
    fn min_reader_version_refuses_precisely_and_permits_additive_change() {
        // Additive future vault: written by v2, readable by a v1 reader.
        let additive: TotpVault =
            serde_json::from_slice(br#"{"version":2,"min_reader_version":1,"entries":[]}"#)
                .unwrap();
        assert!(check_vault_readable(&additive).is_ok());

        // Genuinely incompatible: refused, and the message NAMES the version.
        let breaking: TotpVault =
            serde_json::from_slice(br#"{"version":2,"min_reader_version":2,"entries":[]}"#)
                .unwrap();
        let err = check_vault_readable(&breaking).unwrap_err().to_string();
        assert!(err.contains("version 2"), "{err}");

        // FAILS CLOSED: a v2 vault that never states min_reader_version is
        // treated as needing a v2 reader — the old conservative behaviour.
        let silent: TotpVault = serde_json::from_slice(br#"{"version":2,"entries":[]}"#).unwrap();
        assert!(check_vault_readable(&silent).is_err());

        // And today's vaults still open.
        assert!(check_vault_readable(&TotpVault::default()).is_ok());
    }

    #[test]
    fn entry_uuid_is_a_well_formed_v4_from_caller_entropy() {
        // Pure function over CALLER-supplied bytes (ADR 0007 discipline), so it
        // has a fixed vector.
        let u = format_entry_uuid(&[0xff; 16]);
        assert_eq!(u, "ffffffff-ffff-4fff-bfff-ffffffffffff");
        assert_eq!(
            format_entry_uuid(&[0x00; 16]),
            "00000000-0000-4000-8000-000000000000"
        );
        // Two random draws differ.
        assert_ne!(random_entry_uuid().unwrap(), random_entry_uuid().unwrap());
        // A vault round-trip keeps the id stable.
        let mut v = TotpVault::default();
        v.add(new_totp_entry("a", None, b"k", OtpAlgorithm::Sha1, 6, 30).unwrap())
            .unwrap();
        let id = v.entries[0].uuid.clone();
        assert!(id.is_some());
        let sealed = seal_vault(PASSWORD, &v, FAST).unwrap();
        assert_eq!(open_vault(PASSWORD, &sealed).unwrap().entries[0].uuid, id);
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

    // --- The ACCOUNT model (Phase 52) --------------------------------------
    //
    // The invariant these pin: every account call is a plain contract v3 request
    // (no new header, no new signed-message domain) and NO request ever names an
    // account — the server derives it from the signature it verified.

    #[test]
    fn get_account_signs_v3_and_names_no_account() {
        let mut kf = generate_key().expect("keygen");
        kf.device_id = Some("dev_ME".to_string());
        let id = kf.decode().expect("decode");

        let json = "{\"account_id\":\"acct_AAA\",\"created_at\":\"2026-07-26T00:00:00Z\",\
             \"device_count\":2,\"device_limit\":10,\
             \"devices\":[{\"device_id\":\"dev_ME\",\"account_id\":\"acct_AAA\",\"status\":\"active\"},\
             {\"device_id\":\"dev_SIB\",\"account_id\":\"acct_AAA\",\"status\":\"active\"}]}";
        let response: &'static str = Box::leak(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{json}",
                json.len()
            )
            .into_boxed_str(),
        );

        let (base, handle) = spawn_mock(response);
        let acct = get_account(&base, &id.auth()).expect("get_account ok");
        assert_eq!(acct.account_id, "acct_AAA");
        assert_eq!(acct.device_count, 2);
        assert_eq!(acct.device_limit, 10);
        assert_eq!(acct.devices.len(), 2);
        // The ADDITIVE DeviceInfo field parses...
        assert_eq!(acct.devices[0].account_id.as_deref(), Some("acct_AAA"));

        let req = handle.join().expect("thread");
        assert_eq!(req.request_line, "GET /v1/account HTTP/1.1");
        assert_eq!(req.header("x-sigil-device"), Some("dev_ME"));
        assert!(req.body.is_empty(), "a GET must send no body");

        let ts = req.header("x-sigil-timestamp").expect("ts").to_string();
        let nonce = req.header("x-sigil-nonce").expect("nonce").to_string();
        let sig_b64 = req.header("x-sigil-signature").expect("sig").to_string();
        let msg = handbuilt_v3("dev_ME", "GET", "/v1/account", "", &ts, &nonce, b"");
        let sig: [u8; sigil_core::SIGNATURE_LEN] = BASE64
            .decode(sig_b64.as_bytes())
            .expect("sig b64")
            .try_into()
            .expect("sig 64");
        assert!(
            verify(&id.public_key, &msg, &sig).is_ok(),
            "the account route must verify under the EXISTING v3 message"
        );
        // ...and no new header was invented for it.
        assert!(req.header("x-sigil-account").is_none());
        assert!(req.header("x-sigil-enroll-token").is_none());
    }

    #[test]
    fn device_info_parses_without_an_account_id() {
        // BACKWARD COMPATIBILITY: a pre-account server omits the field entirely.
        let d: DeviceInfo = serde_json::from_str(
            "{\"device_id\":\"dev_OLD\",\"label\":\"laptop\",\"status\":\"active\"}",
        )
        .expect("parse");
        assert_eq!(d.device_id, "dev_OLD");
        assert!(d.account_id.is_none());
    }

    #[test]
    fn create_invite_signs_its_body_and_never_names_an_account() {
        let mut kf = generate_key().expect("keygen");
        kf.device_id = Some("dev_HOST".to_string());
        let id = kf.decode().expect("decode");

        let json = "{\"invite_id\":\"inv_XYZ\",\"invite\":\"join_SECRET\",\
             \"account_id\":\"acct_AAA\",\"expires_at\":\"2026-07-26T00:15:00Z\",\"pinned\":false}";
        let response: &'static str = Box::leak(
            format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{json}",
                json.len()
            )
            .into_boxed_str(),
        );

        let (base, handle) = spawn_mock(response);
        let inv = create_account_invite(&base, &id.auth(), None, None).expect("mint ok");
        assert_eq!(inv.invite_id, "inv_XYZ");
        assert_eq!(inv.invite, "join_SECRET");
        // The secret must never reach a log line through Debug.
        let debug = format!("{inv:?}");
        assert!(
            !debug.contains("join_SECRET"),
            "Debug must redact the invite secret, got {debug}"
        );
        assert!(debug.contains("inv_XYZ"), "the public handle stays visible");

        let req = handle.join().expect("thread");
        assert_eq!(req.request_line, "POST /v1/account/invites HTTP/1.1");
        assert_eq!(req.header("x-sigil-device"), Some("dev_HOST"));
        // With no options the body is an EMPTY JSON object: no account_id, no
        // subject, nothing that could steer which account the invite lands in.
        let body = req.body.clone();
        assert_eq!(String::from_utf8(body.clone()).unwrap(), "{}");

        let ts = req.header("x-sigil-timestamp").expect("ts").to_string();
        let nonce = req.header("x-sigil-nonce").expect("nonce").to_string();
        let sig_b64 = req.header("x-sigil-signature").expect("sig").to_string();
        let msg = handbuilt_v3(
            "dev_HOST",
            "POST",
            "/v1/account/invites",
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
    }

    #[test]
    fn create_invite_sends_ttl_and_pinned_key_when_asked() {
        let mut kf = generate_key().expect("keygen");
        kf.device_id = Some("dev_HOST".to_string());
        let id = kf.decode().expect("decode");
        let pin = [7u8; SIG_PUBLIC_KEY_LEN];

        let json = "{\"invite_id\":\"inv_P\",\"invite\":\"join_S\",\"pinned\":true}";
        let response: &'static str = Box::leak(
            format!(
                "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{json}",
                json.len()
            )
            .into_boxed_str(),
        );

        let (base, handle) = spawn_mock(response);
        let inv = create_account_invite(&base, &id.auth(), Some(120), Some(&pin)).expect("mint ok");
        assert!(inv.pinned);

        let req = handle.join().expect("thread");
        let body = String::from_utf8(req.body.clone()).unwrap();
        assert_eq!(
            body,
            format!(
                "{{\"ttl_seconds\":120,\"invitee_public_key\":\"{}\"}}",
                BASE64.encode(pin)
            )
        );
        assert!(
            !body.contains("account_id") && !body.contains("subject"),
            "the body must never name an account: {body}"
        );
    }

    #[test]
    fn list_invites_returns_metadata_only_and_revoke_scopes_by_handle() {
        let mut kf = generate_key().expect("keygen");
        kf.device_id = Some("dev_HOST".to_string());
        let id = kf.decode().expect("decode");

        let json = "{\"invites\":[{\"invite_id\":\"inv_1\",\"created_by_device_id\":\"dev_HOST\",\
             \"created_at\":\"2026-07-26T00:00:00Z\",\"expires_at\":\"2026-07-26T00:15:00Z\",\"pinned\":true}]}";
        let response: &'static str = Box::leak(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{json}",
                json.len()
            )
            .into_boxed_str(),
        );
        let (base, handle) = spawn_mock(response);
        let invites = list_account_invites(&base, &id.auth()).expect("list ok");
        assert_eq!(invites.len(), 1);
        assert_eq!(invites[0].invite_id, "inv_1");
        assert!(invites[0].pinned);
        let req = handle.join().expect("thread");
        assert_eq!(req.request_line, "GET /v1/account/invites HTTP/1.1");
        assert_eq!(req.header("x-sigil-device"), Some("dev_HOST"));

        // Revocation is by the PUBLIC handle in the path, signed under v3.
        let revoked = "{\"invite_id\":\"inv_1\",\"revoked\":true}";
        let ok: &'static str = Box::leak(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{revoked}",
                revoked.len()
            )
            .into_boxed_str(),
        );
        let (base, handle) = spawn_mock(ok);
        revoke_account_invite(&base, &id.auth(), "inv_1").expect("revoke ok");
        let req = handle.join().expect("thread");
        assert_eq!(
            req.request_line,
            "POST /v1/account/invites/inv_1/revoke HTTP/1.1"
        );
        let ts = req.header("x-sigil-timestamp").expect("ts").to_string();
        let nonce = req.header("x-sigil-nonce").expect("nonce").to_string();
        let sig_b64 = req.header("x-sigil-signature").expect("sig").to_string();
        let msg = handbuilt_v3(
            "dev_HOST",
            "POST",
            "/v1/account/invites/inv_1/revoke",
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

        // An invite handle that could not sit in a URL path segment never
        // reaches the network.
        assert!(matches!(
            revoke_account_invite("http://127.0.0.1:1", &id.auth(), "bad/handle"),
            Err(CliError::Key(_))
        ));
        assert!(matches!(
            revoke_account_invite("http://127.0.0.1:1", &id.auth(), ""),
            Err(CliError::Key(_))
        ));
    }

    #[test]
    fn account_calls_are_unsigned_when_the_identity_is_not_enrolled() {
        // No new auth path was invented: RequestAuth::None still sends nothing,
        // which is exactly how the server answers 401 rather than guessing.
        let json = "{\"error\":\"unauthorized\"}";
        let response: &'static str = Box::leak(
            format!(
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{json}",
                json.len()
            )
            .into_boxed_str(),
        );
        let (base, handle) = spawn_mock(response);
        let err = get_account(&base, &RequestAuth::None).expect_err("must fail");
        assert!(matches!(err, CliError::Server { status: 401, .. }));
        let req = handle.join().expect("thread");
        assert!(req.header("x-sigil-device").is_none());
        assert!(req.header("x-sigil-signature").is_none());
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

    /// A sender identity plus the locally-derived `VerifiedSender` for it —
    /// the shape every wrap/unwrap test needs.
    fn test_sender(device_id: &str) -> (SenderIdentity, VerifiedSender) {
        let (secret, _public) = generate_hybrid_identity().expect("sender identity");
        let sender = SenderIdentity::new(device_id, secret).expect("sender");
        let verified = VerifiedSender::from_local(&sender).expect("verified sender");
        (sender, verified)
    }

    #[test]
    fn wrap_unwrap_vault_key_round_trips_and_rejects_the_wrong_device() {
        let (b_secret, b_public) = generate_hybrid_identity().expect("B identity");
        let (c_secret, _c_public) = generate_hybrid_identity().expect("C identity");
        let key = generate_vault_key().expect("key");
        let (sender, verified) = test_sender("dev_a");
        let ctx = VaultKeyWrapContext::new("demo", "dev_b", "dev_a").expect("ctx");

        let envelope = wrap_vault_key(&sender, &b_public, &ctx, &key).expect("wrap to B");
        // The envelope is an opaque SIGILhyb container that does NOT contain the
        // key in the clear.
        assert_eq!(&envelope[..8], HYBRID_MAGIC.as_slice());
        assert!(
            !envelope.windows(VAULT_KEY_LEN).any(|w| w == key),
            "the wrapped envelope must not contain the vault key in the clear"
        );

        let recovered = unwrap_vault_key(&b_secret, &verified, &ctx, &envelope).expect("B unwraps");
        assert_eq!(recovered, key);

        // A different device cannot open it.
        assert!(unwrap_vault_key(&c_secret, &verified, &ctx, &envelope).is_err());

        // Two wraps of the SAME key differ (fresh ephemeral entropy per call).
        let envelope2 = wrap_vault_key(&sender, &b_public, &ctx, &key).expect("wrap again");
        assert_ne!(
            envelope, envelope2,
            "each wrap must use fresh ephemeral entropy"
        );
        assert_eq!(
            unwrap_vault_key(&b_secret, &verified, &ctx, &envelope2).expect("unwrap 2"),
            key
        );
    }

    #[test]
    fn unwrap_rejects_a_payload_that_is_not_a_vault_key() {
        let (secret, public) = generate_hybrid_identity().expect("identity");
        let (sender, verified) = test_sender("dev_a");
        let ctx = VaultKeyWrapContext::new("demo", "dev_b", "dev_a").expect("ctx");
        let not_a_key = hybrid_auth_seal_to_container(
            &sender.x25519_secret().expect("secret"),
            &public.decode().expect("decode"),
            &ctx.aad(),
            b"only nine",
        )
        .expect("seal");
        assert!(matches!(
            unwrap_vault_key(&secret, &verified, &ctx, &not_a_key),
            Err(CliError::Sharing(_))
        ));
    }

    // =======================================================================
    // ⭐ PHASE 60 — THE FORGERY, AND WHY IT NO LONGER WORKS
    // =======================================================================

    /// ⭐⭐ THE REPRODUCTION, AS A REGRESSION TEST.
    ///
    /// The shipped `sigil hybrid-seal --recipient-pub <victim>.pub` produced a
    /// 1226-byte `SIGILhyb` container, byte-shaped IDENTICALLY to a genuine
    /// vault-key wrap, from the victim's PUBLIC key alone — and
    /// `unwrap_vault_key` accepted it. It must now be refused, and refused for
    /// the RIGHT reason (it is unauthenticated), before any key material is
    /// derived.
    #[test]
    fn a_forged_envelope_minted_from_the_public_key_alone_is_refused() {
        let (victim_secret, victim_public) = generate_hybrid_identity().expect("victim identity");
        let attacker_chosen_key = [0xABu8; VAULT_KEY_LEN];
        let (_sender, verified) = test_sender("dev_peer");
        let ctx = VaultKeyWrapContext::new("demo", "dev_victim", "dev_peer").expect("ctx");

        // EXACTLY what `sigil hybrid-seal` does — no secret of anyone's needed.
        let forged = hybrid_seal_to_container(
            &victim_public.decode().expect("decode"),
            &attacker_chosen_key,
        )
        .expect("the anonymous file path still works, by design");
        assert_eq!(&forged[..8], HYBRID_MAGIC.as_slice());
        assert_eq!(forged[8], HYBRID_FORMAT_VERSION, "a v1 file container");

        assert_eq!(
            unwrap_vault_key(&victim_secret, &verified, &ctx, &forged),
            Err(CliError::WrongEnvelopeKind {
                found_version: 1,
                expected_version: 2,
            }),
            "a FILE envelope must NOT be accepted as a vault-key envelope"
        );

        // And the refusal says so in words a human can act on.
        let msg = CliError::WrongEnvelopeKind {
            found_version: 1,
            expected_version: 2,
        }
        .to_string();
        assert!(msg.contains("UNAUTHENTICATED"), "{msg}");
        assert!(msg.contains("NO SENDER"), "{msg}");
    }

    /// The reverse direction of the same rule: an AUTHENTICATED vault-key
    /// envelope is not an anonymous file, and `sigil hybrid-open` refuses it.
    #[test]
    fn a_vault_key_envelope_is_refused_as_a_file_envelope() {
        let (secret, public) = generate_hybrid_identity().expect("identity");
        let (sender, _verified) = test_sender("dev_a");
        let key = generate_vault_key().expect("key");
        let ctx = VaultKeyWrapContext::new("demo", "dev_b", "dev_a").expect("ctx");
        let envelope = wrap_vault_key(&sender, &public, &ctx, &key).expect("wrap");

        assert_eq!(
            hybrid_open_container(&secret.decode().expect("decode"), &envelope),
            Err(CliError::WrongEnvelopeKind {
                found_version: 2,
                expected_version: 1,
            })
        );
    }

    /// ⭐ A GENUINE envelope from the WRONG sender fails at the AEAD — never by
    /// returning plaintext, and never by comparing a string the server chose.
    #[test]
    fn an_envelope_from_an_unexpected_sender_fails_at_the_aead() {
        let (b_secret, b_public) = generate_hybrid_identity().expect("B identity");
        let key = generate_vault_key().expect("key");
        let (real_sender, real_verified) = test_sender("dev_a");
        let (_other, other_verified) = test_sender("dev_a"); // same id, DIFFERENT key
        let ctx = VaultKeyWrapContext::new("demo", "dev_b", "dev_a").expect("ctx");

        let envelope = wrap_vault_key(&real_sender, &b_public, &ctx, &key).expect("wrap");

        assert_eq!(
            unwrap_vault_key(&b_secret, &real_verified, &ctx, &envelope).expect("real sender"),
            key
        );
        assert!(
            matches!(
                unwrap_vault_key(&b_secret, &other_verified, &ctx, &envelope),
                Err(CliError::HybridSeal(_))
            ),
            "an envelope attributed to the wrong sender key must fail AUTHENTICATION"
        );
    }

    /// ⭐ CONTEXT BINDING at the CLI layer: the same envelope re-filed under a
    /// different vault, recipient or sender is refused.
    #[test]
    fn an_envelope_cannot_be_re_filed_under_another_context() {
        let (b_secret, b_public) = generate_hybrid_identity().expect("B identity");
        let key = generate_vault_key().expect("key");
        let (sender, verified) = test_sender("dev_a");
        let ctx = VaultKeyWrapContext::new("vault-a", "dev_b", "dev_a").expect("ctx");
        let envelope = wrap_vault_key(&sender, &b_public, &ctx, &key).expect("wrap");

        for wrong in [
            VaultKeyWrapContext::new("vault-b", "dev_b", "dev_a").expect("ctx"),
            VaultKeyWrapContext::new("vault-a", "dev_c", "dev_a").expect("ctx"),
        ] {
            assert!(
                matches!(
                    unwrap_vault_key(&b_secret, &verified, &wrong, &envelope),
                    Err(CliError::HybridSeal(_))
                ),
                "a re-filed envelope must be refused"
            );
        }
    }

    /// The two halves of a wrap must agree on who the sender is — a context
    /// naming one device and an identity holding another's secret is a LOCAL
    /// error, not an envelope nobody can open.
    #[test]
    fn wrap_refuses_a_context_that_names_a_different_sender() {
        let (_bs, b_public) = generate_hybrid_identity().expect("B identity");
        let key = generate_vault_key().expect("key");
        let (sender, verified) = test_sender("dev_a");
        let ctx = VaultKeyWrapContext::new("demo", "dev_b", "dev_z").expect("ctx");
        assert!(matches!(
            wrap_vault_key(&sender, &b_public, &ctx, &key),
            Err(CliError::Sharing(_))
        ));
        // Symmetrically on the unwrap side.
        let good = VaultKeyWrapContext::new("demo", "dev_b", "dev_a").expect("ctx");
        let envelope = wrap_vault_key(&sender, &b_public, &good, &key).expect("wrap");
        let (b_secret, _) = generate_hybrid_identity().expect("unused");
        assert!(matches!(
            unwrap_vault_key(&b_secret, &verified, &ctx, &envelope),
            Err(CliError::Sharing(_))
        ));
    }

    /// `VerifiedSender::from_local` must reconstruct EXACTLY the public identity
    /// that `generate_hybrid_identity` published, or a device would fail to
    /// authenticate envelopes it wrapped itself.
    #[test]
    fn from_local_reconstructs_the_published_public_identity() {
        let (secret, public) = generate_hybrid_identity().expect("identity");
        let sender = SenderIdentity::new("dev_a", secret).expect("sender");
        let verified = VerifiedSender::from_local(&sender).expect("verified");
        assert_eq!(
            verified.identity().x25519_public_key,
            public.x25519_public_key
        );
        assert_eq!(
            verified.identity().mlkem_encaps_key,
            public.mlkem_encaps_key
        );
        assert_eq!(verified.trust(), RecipientTrust::Derived);
    }

    /// ⭐ GOLDEN KAT for the wrap AAD, mirrored by `sigil-wasm/sharing.mjs`.
    /// Rust and JS must build byte-identical context or a browser-wrapped key
    /// will not open in the CLI.
    #[test]
    fn vault_key_wrap_aad_golden_vector() {
        let ctx = VaultKeyWrapContext::new("demo", "dev_bob", "dev_alice").expect("ctx");
        let hex: String = ctx.aad().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "736967696c2d7661756c742d6b65792d777261702d76310a0000000464656d6f\
             000000076465765f626f62000000096465765f616c696365"
        );
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

#[cfg(test)]
mod share_order_tests {
    //! ⭐ PHASE 60 — the AUTHORIZE-BEFORE-DEPOSIT ordering, pinned by a
    //! recording HTTP stub.
    //!
    //! `share_vault_to_known_key` used to PUT the envelope and only then ask for
    //! the grant, so a device with WRITE but no ownership left a key envelope of
    //! its choosing in the recipient's mailbox and met the `403` afterwards. The
    //! deposit is the part that cannot be taken back, so it must go LAST.
    //!
    //! This needs no `sigild`: a bare `TcpListener` speaks just enough HTTP to
    //! record which requests arrive, in order, and to answer the first one 403.

    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::sync::mpsc;

    /// A one-shot recording HTTP server. Returns `(base_url, receiver)`; the
    /// receiver yields `"METHOD PATH"` for each request it served.
    fn recording_server(status_for_first: u16) -> (String, mpsc::Receiver<String>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let mut served = 0usize;
            // Two connections at most: the grant, then (if allowed) the deposit.
            for stream in listener.incoming().take(2) {
                let Ok(mut stream) = stream else { break };
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    break;
                }
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or_default().to_string();
                let path = parts.next().unwrap_or_default().to_string();

                // Consume headers, noting Content-Length so the body is drained
                // (otherwise the client can block writing it).
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let trimmed = line.trim_end();
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some(v) = trimmed.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                if content_length > 0 {
                    let mut body = vec![0u8; content_length];
                    let _ = reader.read_exact(&mut body);
                }

                let _ = tx.send(format!("{method} {path}"));
                served += 1;
                let code = if served == 1 { status_for_first } else { 201 };
                let body = b"{}";
                let response = format!(
                    "HTTP/1.1 {code} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
                let _ = stream.flush();
            }
        });
        (format!("http://127.0.0.1:{port}"), rx)
    }

    /// Build a `VerifiedRecipient` without a network round trip, by pinning a
    /// locally generated identity as a "derived" key — the same short-circuit
    /// `recovery generate` uses.
    fn local_recipient(dir: &std::path::Path, device_id: &str) -> VerifiedRecipient {
        let (_secret, public) = generate_hybrid_identity().expect("recipient identity");
        let pins = dir.join("hybrid-pins.json");
        pin_derived_key(&pins, device_id, &public).expect("pin derived");
        verify_recipient_for_wrap(
            "http://127.0.0.1:1", // never reached: a derived pin short-circuits
            device_id,
            &RequestAuth::None,
            &pins,
            None,
            true,
        )
        .expect("derived recipient")
    }

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!("sigil-order-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&p).expect("mkdir");
        p
    }

    /// ⭐ A REFUSED GRANT MUST LEAVE NO ENVELOPE BEHIND.
    #[test]
    fn a_refused_grant_means_no_envelope_is_ever_deposited() {
        let dir = temp_dir("deny");
        let (server, rx) = recording_server(403);
        let recipient = local_recipient(&dir, "dev_b");
        let (sender_secret, _) = generate_hybrid_identity().expect("sender identity");
        let sender = SenderIdentity::new("dev_a", sender_secret).expect("sender");
        let key = generate_vault_key().expect("key");

        let result = share_vault_to_known_key(
            &server,
            "demo",
            &recipient,
            "read",
            &key,
            &RequestAuth::None,
            &sender,
        );
        // The 403 is REPHRASED, not swallowed: authorize-first has a cliff the old
        // order hid (a never-written vault has no owner, so its first share is
        // refused), and a bare "only the vault owner may do this" leaves the user
        // stuck. What must not change is that it ABORTS.
        let message = match &result {
            Err(CliError::Sharing(m)) => m.clone(),
            other => panic!("expected the grant's 403 to abort the share, got {other:?}"),
        };
        assert!(
            message.contains("nothing was deposited") && message.contains("Push it first"),
            "the refusal must say nothing was deposited AND how to fix it: {message}"
        );

        let requests: Vec<String> = rx.try_iter().collect();
        assert_eq!(
            requests,
            vec!["POST /v1/vaults/demo/grants".to_string()],
            "the GRANT must be the ONLY request a refused share makes — an envelope \
             deposited before the authorization check cannot be taken back"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// And on the happy path the order is still grant, then deposit.
    #[test]
    fn a_successful_share_grants_before_it_deposits() {
        let dir = temp_dir("allow");
        let (server, rx) = recording_server(201);
        let recipient = local_recipient(&dir, "dev_b");
        let (sender_secret, _) = generate_hybrid_identity().expect("sender identity");
        let sender = SenderIdentity::new("dev_a", sender_secret).expect("sender");
        let key = generate_vault_key().expect("key");

        share_vault_to_known_key(
            &server,
            "demo",
            &recipient,
            "read",
            &key,
            &RequestAuth::None,
            &sender,
        )
        .expect("share succeeds against the stub");

        let requests: Vec<String> = rx.try_iter().collect();
        assert_eq!(
            requests,
            vec![
                "POST /v1/vaults/demo/grants".to_string(),
                "PUT /v1/vaults/demo/keys/dev_b".to_string(),
            ]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod unwrap_gate_tests {
    //! ⭐⭐ PHASE 60 — THE RECEIVING SIDE'S TWO CONTROLS, PINNED BY TESTS.
    //!
    //! `accept_vault_key` is where a forged or substituted vault key would land,
    //! and it is defended by exactly two things:
    //!
    //!   * **the unwrap gate** — [`verify_sender_for_unwrap`] pin-checks the
    //!     DEPOSITING device's hybrid public key (and honours a supplied safety
    //!     number) before one byte is unwrapped;
    //!   * **open-before-write** — the recovered key must actually OPEN the
    //!     vault's newest op before it is written to the keyring.
    //!
    //! ⚠️ THEY ARE EACH OTHER'S ONLY BACKSTOP, and until this module existed
    //! NEITHER was pinned: deleting the safety-number comparison and the
    //! `check_and_pin` call from `verify_sender_for_unwrap`, or discarding the
    //! result of the `open_container` in step 4, left every suite in the
    //! repository green. A verifier then drove the neutered build against a
    //! rewriting proxy and the hostile key WAS installed in the victim's
    //! keyring. So each test below is written to go RED for exactly one deleted
    //! control, and the mutations were run.
    //!
    //! No `sigild` is needed: a bare `TcpListener` answering canned responses IS
    //! the hostile server, which is the honest shape — the whole point is that
    //! the client must not believe what the server says.

    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::path::{Path, PathBuf};

    /// Fast Argon2id params: the tip container is sealed and opened for real, but
    /// the KDF work factor is irrelevant to what is being proven.
    const FAST: Argon2Params = Argon2Params {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    };

    const VAULT: &str = "demo";
    const ME: &str = "dev_victim";
    const SENDER: &str = "dev_sender";
    const WRONG_NUMBER: &str = "00000 00000 00000 00000 00000 00000";

    /// One canned response: (path WITHOUT query, status, content-type, body).
    type Route = (String, u16, &'static str, Vec<u8>);

    /// A hostile server: it answers whatever it is told to answer.
    fn stub_server(routes: Vec<Route>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        std::thread::spawn(move || {
            // An accept makes at most four requests; take a few more so a
            // retry cannot wedge the test on a silent hang.
            for stream in listener.incoming().take(12) {
                let Ok(mut stream) = stream else { break };
                let mut reader = BufReader::new(stream.try_clone().expect("clone"));
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                    continue;
                }
                let target = request_line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_string();
                let path = target.split('?').next().unwrap_or_default().to_string();

                // Drain headers, noting Content-Length so a body is consumed and
                // the client is never left blocked writing it.
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let trimmed = line.trim_end();
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some(v) = trimmed.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                if content_length > 0 {
                    let mut body = vec![0u8; content_length];
                    let _ = reader.read_exact(&mut body);
                }

                let (code, ctype, body) = match routes.iter().find(|r| r.0 == path) {
                    Some((_, code, ctype, body)) => (*code, *ctype, body.clone()),
                    None => (404, "application/json", br#"{"error":"no route"}"#.to_vec()),
                };
                let head = format!(
                    "HTTP/1.1 {code} X\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });
        format!("http://127.0.0.1:{port}")
    }

    /// Every route an `accept_vault_key` can ask for, with the answers a hostile
    /// server would give. `tip` is the vault's newest op, or `None` for a vault
    /// that has never been pushed.
    fn accept_routes(
        envelope: &[u8],
        served_sender_key: &HybridPublicIdentity,
        tip: Option<&[u8]>,
    ) -> Vec<Route> {
        let key_json = serde_json::to_vec(&serde_json::json!({
            "device_id": SENDER,
            "x25519_public_key": served_sender_key.x25519_public_key,
            "mlkem_encaps_key": served_sender_key.mlkem_encaps_key,
        }))
        .expect("hybrid key json");
        let index_json = serde_json::to_vec(&serde_json::json!({
            "device_id": ME,
            "vaults": [{
                "vaultID": VAULT,
                "sender_device_id": SENDER,
                "size_bytes": envelope.len(),
                "created_at": "2026-01-01T00:00:00Z",
            }],
            "has_more": false,
        }))
        .expect("index json");
        let ops_json = serde_json::to_vec(&serde_json::json!({
            "vaultID": VAULT,
            "ops": match tip {
                Some(blob) => vec![serde_json::json!({ "seq": 1, "blob": BASE64.encode(blob) })],
                None => vec![],
            },
            "next": 1,
            "has_more": false,
        }))
        .expect("ops json");

        vec![
            (
                format!("/v1/vaults/{VAULT}/keys/{ME}"),
                200,
                "application/octet-stream",
                envelope.to_vec(),
            ),
            (
                format!("/v1/devices/{SENDER}/hybrid-key"),
                200,
                "application/json",
                key_json,
            ),
            (
                format!("/v1/devices/{ME}/keys"),
                200,
                "application/json",
                index_json,
            ),
            (
                format!("/v1/vaults/{VAULT}/ops"),
                200,
                "application/json",
                ops_json,
            ),
        ]
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        p.push(format!(
            "sigil-unwrap-{tag}-{}-{nanos}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&p).expect("mkdir");
        p
    }

    /// A plausible sealed vault, so "does this key open the tip?" is a real
    /// `open_container` over real ciphertext.
    fn sealed_tip(key: &[u8; VAULT_KEY_LEN]) -> Vec<u8> {
        seal_to_container(key, br#"{"version":1,"entries":[]}"#, FAST).expect("seal tip")
    }

    fn wrap_from(
        sender_device_id: &str,
        secret: HybridSecretIdentity,
        recipient: &HybridPublicIdentity,
        key: &[u8; VAULT_KEY_LEN],
    ) -> Vec<u8> {
        let sender = SenderIdentity::new(sender_device_id, secret).expect("sender identity");
        let ctx = VaultKeyWrapContext::new(VAULT, ME, sender_device_id).expect("ctx");
        wrap_vault_key(&sender, recipient, &ctx, key).expect("wrap")
    }

    /// A one-line rendering of an accept outcome. `AcceptReport`'s own `Debug`
    /// prints the whole envelope, which buries the assertion message that
    /// matters under 1300 bytes of ciphertext.
    fn outcome(result: &Result<AcceptReport, CliError>) -> String {
        match result {
            Ok(r) => format!(
                "Ok(accepted: sender={} trust={:?} key={} verified_against_tip={})",
                r.sender_device_id, r.sender_trust, r.key_fingerprint, r.verified_against_tip
            ),
            Err(e) => format!("Err({e:?})"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn accept(
        server: &str,
        secret: &HybridSecretIdentity,
        keyring: &Path,
        pins: &Path,
        sender_device_id: Option<&str>,
        expected_safety_number: Option<&str>,
    ) -> Result<AcceptReport, CliError> {
        accept_vault_key(
            server,
            VAULT,
            ME,
            secret,
            keyring,
            pins,
            &RequestAuth::None,
            sender_device_id,
            expected_safety_number,
            false,
        )
    }

    // =======================================================================
    // ⭐ THE UNWRAP GATE
    // =======================================================================

    /// ⭐⭐ A SUBSTITUTED SENDER KEY IS A HARD STOP, AND NOTHING IS WRITTEN.
    ///
    /// This is the attack a verifier reproduced end to end against the neutered
    /// build: a hostile server serves ITS OWN hybrid key as the sender's, mints
    /// an envelope under it (which then authenticates perfectly, because the
    /// authentication input is the key the server just handed over), and serves
    /// a tip op that the attacker's chosen vault key opens — so open-before-write
    /// cannot save us either. The ONLY thing standing between the victim and an
    /// attacker-chosen vault key is the pin check inside
    /// [`verify_sender_for_unwrap`].
    ///
    /// ⚠️ MUTATION: delete the `check_and_pin` call from
    /// `verify_sender_for_unwrap` and this test fails — the accept succeeds and
    /// the attacker's key lands in the keyring.
    #[test]
    fn a_substituted_sender_key_is_refused_and_no_key_is_written() {
        let dir = temp_dir("substituted");
        let pins = dir.join("hybrid-pins.json");
        let keyring = dir.join("vault-keys.json");

        let (victim_secret, victim_public) = generate_hybrid_identity().expect("victim");
        let (_honest_secret, honest_public) = generate_hybrid_identity().expect("honest sender");
        let (attacker_secret, attacker_public) = generate_hybrid_identity().expect("attacker");

        // The victim has met the sender before — its real key is PINNED.
        check_and_pin(&pins, SENDER, &honest_public).expect("pin the honest sender");
        let honest_number = hybrid_safety_number(SENDER, &honest_public).expect("number");

        // The attacker mints an envelope AS the sender, under its own keys, with
        // the correct context — so only the served key is a lie.
        let attacker_chosen = [0x5au8; VAULT_KEY_LEN];
        let forged = wrap_from(SENDER, attacker_secret, &victim_public, &attacker_chosen);
        // ...and a tip the attacker's key opens, so step 4 would wave it through.
        let tip = sealed_tip(&attacker_chosen);
        let server = stub_server(accept_routes(&forged, &attacker_public, Some(&tip)));

        let result = accept(&server, &victim_secret, &keyring, &pins, Some(SENDER), None);
        match &result {
            Err(CliError::PinMismatch {
                device_id,
                pinned_safety_number,
                presented_safety_number,
            }) => {
                assert_eq!(device_id, SENDER);
                assert_eq!(pinned_safety_number, &honest_number);
                assert_ne!(presented_safety_number, &honest_number);
            }
            _ => panic!(
                "⚠️ THE UNWRAP GATE DID NOT FIRE — expected CliError::PinMismatch, got {}",
                outcome(&result)
            ),
        }

        assert!(
            keyring_get(&keyring, VAULT).expect("keyring").is_none(),
            "⚠️ AN ATTACKER-CHOSEN VAULT KEY WAS WRITTEN TO THE KEYRING"
        );
        let store = load_pins(&pins).expect("pins");
        assert_eq!(
            store.pins[SENDER].safety_number, honest_number,
            "a refused check must NOT re-pin — a retry would then see a Match and \
             silence its own alarm"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ⭐ A SUPPLIED SAFETY NUMBER THAT DOES NOT MATCH IS A HARD STOP, and the
    /// key it refused is NOT pinned (so a retry cannot turn the refusal into a
    /// `Match`).
    ///
    /// ⚠️ MUTATION: delete the `expected_safety_number` comparison from
    /// `verify_sender_for_unwrap` and this test fails — the accept succeeds.
    #[test]
    fn a_wrong_supplied_safety_number_refuses_and_pins_nothing() {
        let dir = temp_dir("safety");
        let pins = dir.join("hybrid-pins.json");
        let keyring = dir.join("vault-keys.json");

        let (victim_secret, victim_public) = generate_hybrid_identity().expect("victim");
        let (sender_secret, sender_public) = generate_hybrid_identity().expect("sender");

        // Everything here is HONEST — the only thing wrong is the number the
        // human typed, which is exactly the case the check exists for.
        let key = generate_vault_key().expect("vault key");
        let envelope = wrap_from(SENDER, sender_secret, &victim_public, &key);
        let tip = sealed_tip(&key);
        let server = stub_server(accept_routes(&envelope, &sender_public, Some(&tip)));

        let result = accept(
            &server,
            &victim_secret,
            &keyring,
            &pins,
            Some(SENDER),
            Some(WRONG_NUMBER),
        );
        match &result {
            Err(CliError::SafetyNumberMismatch {
                device_id,
                expected_safety_number,
                presented_safety_number,
            }) => {
                assert_eq!(device_id, SENDER);
                assert_eq!(expected_safety_number, WRONG_NUMBER);
                assert_eq!(
                    presented_safety_number,
                    &hybrid_safety_number(SENDER, &sender_public).expect("number")
                );
            }
            _ => panic!(
                "⚠️ THE SAFETY-NUMBER CHECK DID NOT FIRE — expected \
                 CliError::SafetyNumberMismatch, got {}",
                outcome(&result)
            ),
        }
        assert!(
            keyring_get(&keyring, VAULT).expect("keyring").is_none(),
            "nothing may be written when the safety number did not match"
        );
        assert!(
            load_pins(&pins).expect("pins").pins.is_empty(),
            "a REFUSED key must not be pinned — pinning it would let the retry \
             report Match and the alarm would never fire again"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ⭐ THE RESIDUAL LIMIT, PINNED SO IT CANNOT SILENTLY INVERT (ADR 0038).
    ///
    /// FIRST SIGHT of a sender is trust-on-first-use: the client pins and
    /// PROCEEDS, reporting `UnverifiedFirstSight` so the caller can warn. A key
    /// that CHANGES afterwards is a hard refusal. Both halves are asserted here
    /// because the dangerous drift is the pair swapping over — a build that
    /// refused first contact and accepted changes would be worse than useless,
    /// and neither half alone would notice.
    ///
    /// It also exercises step 1 (the envelope INDEX) by passing no sender id.
    ///
    /// ⚠️ MUTATION: delete the `check_and_pin` call and this test fails — first
    /// sight no longer pins, so the changed key in part B is accepted.
    #[test]
    fn first_sight_pins_and_proceeds_but_a_changed_key_is_refused() {
        let dir = temp_dir("firstsight");
        let pins = dir.join("hybrid-pins.json");
        let keyring = dir.join("vault-keys.json");

        let (victim_secret, victim_public) = generate_hybrid_identity().expect("victim");
        let (sender_secret, sender_public) = generate_hybrid_identity().expect("sender");
        let sender_number = hybrid_safety_number(SENDER, &sender_public).expect("number");

        // --- A. FIRST SIGHT: pinned, warned about, and ACCEPTED. -------------
        let key = generate_vault_key().expect("vault key");
        let envelope = wrap_from(SENDER, sender_secret, &victim_public, &key);
        let tip = sealed_tip(&key);
        let server = stub_server(accept_routes(&envelope, &sender_public, Some(&tip)));

        // No sender id: the index says who deposited it (step 1).
        let report = accept(&server, &victim_secret, &keyring, &pins, None, None)
            .expect("a first-sight accept must PROCEED — this is ADR 0038's accepted TOFU");
        assert_eq!(report.sender_device_id, SENDER, "step 1 must use the index");
        assert_eq!(
            report.sender_trust,
            RecipientTrust::UnverifiedFirstSight,
            "first sight must be REPORTED as unverified so the caller can warn"
        );
        assert!(
            report.sender_trust.needs_out_of_band_check(),
            "this is the exact predicate `sigil vault accept` branches on to print its \
             first-contact warning — if it stops being true the human stops being told"
        );
        assert_eq!(report.sender_safety_number, sender_number);
        assert!(
            report.verified_against_tip,
            "the accept must have proved the key against the vault's newest op"
        );
        assert_eq!(keyring_get(&keyring, VAULT).expect("keyring"), Some(key));
        let pinned_after_first_sight = load_pins(&pins)
            .expect("pins")
            .pins
            .get(SENDER)
            .map(|p| p.safety_number.clone());
        assert_eq!(
            pinned_after_first_sight.as_deref(),
            Some(sender_number.as_str()),
            "⚠️ FIRST SIGHT DID NOT PIN THE SENDER — every later key change would be \
             a first sight too, and the gate would never fire"
        );

        // --- B. THE SAME SENDER, A DIFFERENT KEY: a hard refusal. ------------
        let (attacker_secret, attacker_public) = generate_hybrid_identity().expect("attacker");
        let attacker_chosen = [0x11u8; VAULT_KEY_LEN];
        let forged = wrap_from(SENDER, attacker_secret, &victim_public, &attacker_chosen);
        let forged_tip = sealed_tip(&attacker_chosen);
        let hostile = stub_server(accept_routes(&forged, &attacker_public, Some(&forged_tip)));

        let result = accept(
            &hostile,
            &victim_secret,
            &keyring,
            &pins,
            Some(SENDER),
            None,
        );
        assert!(
            matches!(result, Err(CliError::PinMismatch { .. })),
            "⚠️ A CHANGED SENDER KEY WAS ACCEPTED — got {}",
            outcome(&result)
        );
        assert_eq!(
            keyring_get(&keyring, VAULT).expect("keyring"),
            Some(key),
            "the vault key this device already held must be untouched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // =======================================================================
    // ⭐ OPEN BEFORE WRITE
    // =======================================================================

    /// ⭐⭐ A KEY THAT OPENS NOTHING NEVER REACHES LOCAL STATE.
    ///
    /// The sender here is honest and the envelope is genuinely authenticated —
    /// the gate above passes cleanly. What is wrong is the KEY: it does not open
    /// the vault it claims to be for. That is the shape of a hostile deposit
    /// that got past first-sight TOFU, and step 4 is the only thing that catches
    /// it. It is also the backstop the verifier watched stop the attack once the
    /// gate was neutered, which is precisely why it needs its own test.
    ///
    /// ⚠️ MUTATION: discard the result of step 4's `open_container` and this test
    /// fails — the useless key is written to the keyring and the accept reports
    /// success.
    #[test]
    fn a_key_that_does_not_open_the_vault_is_never_written_to_the_keyring() {
        let dir = temp_dir("openfirst");
        let pins = dir.join("hybrid-pins.json");
        let keyring = dir.join("vault-keys.json");

        let (victim_secret, victim_public) = generate_hybrid_identity().expect("victim");
        let (sender_secret, sender_public) = generate_hybrid_identity().expect("sender");

        let real_key = generate_vault_key().expect("real key");
        let wrong_key = generate_vault_key().expect("wrong key");
        assert_ne!(real_key, wrong_key);

        // A perfectly well-formed, authenticated, context-bound envelope — for
        // the WRONG key. Everything before step 4 will pass.
        let envelope = wrap_from(SENDER, sender_secret, &victim_public, &wrong_key);
        let tip = sealed_tip(&real_key);
        let server = stub_server(accept_routes(&envelope, &sender_public, Some(&tip)));

        let result = accept(&server, &victim_secret, &keyring, &pins, Some(SENDER), None);
        let message = match &result {
            Err(CliError::Sharing(m)) => m.clone(),
            _ => panic!(
                "⚠️ OPEN-BEFORE-WRITE DID NOT FIRE — a key that opens nothing was \
                 accepted: {}",
                outcome(&result)
            ),
        };
        assert!(
            message.contains("does NOT open") && message.contains("nothing was written"),
            "the refusal must say the key does not open the vault and that nothing \
             was written: {message}"
        );
        assert!(
            keyring_get(&keyring, VAULT).expect("keyring").is_none(),
            "⚠️ A KEY THAT OPENS NOTHING WAS WRITTEN TO THE KEYRING"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The POSITIVE CONTROL for the test above: with the SAME shape and the
    /// RIGHT key, the accept succeeds and records that it verified against the
    /// tip. Without this, "everything is refused" would look like a pass.
    #[test]
    fn the_right_key_opens_the_tip_and_is_written() {
        let dir = temp_dir("openctl");
        let pins = dir.join("hybrid-pins.json");
        let keyring = dir.join("vault-keys.json");

        let (victim_secret, victim_public) = generate_hybrid_identity().expect("victim");
        let (sender_secret, sender_public) = generate_hybrid_identity().expect("sender");

        let key = generate_vault_key().expect("key");
        let envelope = wrap_from(SENDER, sender_secret, &victim_public, &key);
        let tip = sealed_tip(&key);
        let server = stub_server(accept_routes(&envelope, &sender_public, Some(&tip)));

        let report = accept(&server, &victim_secret, &keyring, &pins, Some(SENDER), None)
            .expect("the correct key must be accepted");
        assert!(report.verified_against_tip);
        assert_eq!(report.key_fingerprint, vault_key_fingerprint(&key));
        assert_eq!(keyring_get(&keyring, VAULT).expect("keyring"), Some(key));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
