//! `sigil-desktop-core` — the headless authenticator logic behind the Sigil
//! desktop app.
//!
//! # STATUS: PRE-AUDIT — UNAUDITED — DO NOT STORE REAL 2FA SECRETS
//!
//! This crate composes the **real but UNAUDITED** libsigil building blocks
//! (`sigil-core`'s Argon2id + XChaCha20-Poly1305 record API and its RFC
//! 4226/6238 OTP primitive) with `sigil-cli`'s `SIGILcli` container and
//! `TotpVault` schema. It is a demonstration only and makes **no** security
//! claims. It is not audited, not signed, not notarized, and not distributed.
//!
//! # Why this crate exists
//!
//! The webapp and the browser extension run libsigil compiled to **WebAssembly**.
//! This is the **native** column: `sigil-core` is linked as a plain native Rust
//! dependency, with no wasm anywhere in the loop. `sigil-core` is `no_std` and
//! deliberately reads **no clock and no RNG** — a native caller must supply both.
//! Here:
//!
//! * entropy (Argon2id salt, AEAD nonce) comes from `sigil-cli`'s native
//!   `getrandom` path inside [`sigil_cli::seal_to_container`], and
//! * the clock comes from [`std::time::SystemTime`] via [`now_unix`], which is
//!   passed *into* the core's `totp` as a `u64`.
//!
//! # Reuse, not reimplementation
//!
//! No crypto, no container format, and no vault schema is defined here. Every
//! byte-level format decision lives in `sigil-cli` (`seal_vault`/`open_vault`,
//! `TotpVault`/`TotpEntry`, `parse_otpauth_uri`/`entry_to_otpauth_uri`,
//! `migration::*`). That is exactly what makes a desktop-written vault open in
//! the `sigil` CLI, the webapp and the extension, and vice versa.
//!
//! # On-disk state
//!
//! Only the **sealed** container is ever written. The password is held in memory
//! for the lifetime of a [`VaultSession`] and is best-effort zeroed on drop; it
//! is never persisted, logged, or included in any returned value.
//!
//! # Talking to a server
//!
//! Everything network-facing — device enrollment, contract-v3 signed op-log
//! sync, and device-to-device vault sharing — lives in [`net`] and is likewise
//! **driven by the `sigil-cli` library**, not reimplemented. See that module for
//! the reuse table and the on-disk secret model. A user with no server
//! configured never touches any of it: the offline flow above is unchanged.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod entitlement;
pub mod net;
pub mod recovery;

pub use entitlement::EntitlementView;
pub use net::{
    pull_and_adopt, AccountMember, AccountView, DeviceConfig, DeviceStatus, MintedInvite,
    OpenInvite, PulledVault, ServerCheck, VaultKeyInfo, DEVICE_IDENTITY_FILE, HYBRID_PUBLIC_FILE,
    HYBRID_SECRET_FILE,
};
pub use recovery::{
    format_code, verify_recovery_code, CoverageView, CoveredVault, KitView, RecoveryKitSheet,
    RecoveryProof, RestoreView, RestoredVault, RevokeView,
};

use std::path::{Path, PathBuf};

use sigil_cli::migration::{
    decode_migration_uri, encode_migration_uri, entry_to_migration_otp, migration_otp_to_entry,
    ImportedOtp,
};
use sigil_cli::{
    base32_decode, entry_to_otpauth_uri, new_totp_entry, open_vault, parse_otpauth_uri, seal_vault,
    totp_algorithm_from_str, CliError, TotpEntry, TotpVault, TOTP_DEFAULT_DIGITS,
    TOTP_DEFAULT_PERIOD,
};
use sigil_core::Argon2Params;

/// The loud pre-audit banner. Rendered verbatim in the GUI and printed by the
/// binary; keep it in one place so no surface can quietly drop it.
pub const BANNER_TITLE: &str = "PRE-AUDIT · UNAUDITED · DO NOT STORE REAL 2FA SECRETS";

/// The long-form banner body shown under [`BANNER_TITLE`].
pub const BANNER_BODY: &str =
    "This is a private, pre-launch demonstration build. The cryptography \
     is real but has NOT been independently audited, and no part of this app is a security \
     guarantee. Use throwaway test secrets only.";

/// The file name of the shared TOTP vault inside the Sigil state directory.
///
/// Deliberately identical to the `sigil` CLI's default so the desktop app and the
/// CLI open the *same* vault on the same machine.
pub const VAULT_FILE_NAME: &str = "totp-vault.sigil";

/// The Sigil per-user state directory name (under `$HOME`).
pub const STATE_DIR_NAME: &str = ".sigil";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Everything this crate can fail with.
#[derive(Debug)]
pub enum DesktopError {
    /// A filesystem operation failed.
    Io(String),
    /// The underlying `sigil-cli` / `sigil-core` layer failed (wrong password,
    /// tampered container, bad secret, invalid URI, ...).
    Vault(String),
    /// The caller asked to create a vault at a path that already exists.
    AlreadyExists(PathBuf),
    /// The caller asked to unlock a vault that is not on disk yet.
    NotFound(PathBuf),
    /// An empty password was supplied.
    EmptyPassword,

    // -- server-facing (see [`net`]) ------------------------------------
    /// A contract-v3 operation was attempted before this device enrolled. The
    /// path is where its identity file would live.
    NotEnrolled(PathBuf),
    /// Enrollment was attempted on a device that already has a device id. The
    /// existing identity is never silently overwritten — that would destroy this
    /// device's only credential.
    AlreadyEnrolled(String),
    /// A sharing operation was attempted on a vault this device holds no vault
    /// key for: it is still password-sealed, or no share has been accepted. The
    /// human password is never shared.
    NotShared(String),
    /// The server could not be reached at all (wrong URL, nothing listening,
    /// no network). The local vault is unaffected — the app stays usable offline.
    Unreachable(String),
    /// HTTP 401: the server did not accept this device's credentials.
    Unauthenticated(String),
    /// HTTP 403: authenticated, but not permitted (not the owner, not granted,
    /// or not the addressee of an envelope).
    Forbidden(String),
    /// HTTP 404: nothing is there — no published hybrid key, or nothing shared.
    MissingOnServer(String),
    /// HTTP 501: the server has that route switched off (sigild's sync and
    /// device routes are dev-gated).
    NotEnabled(String),
    /// ⚠️ HYBRID KEY CHANGED. The hybrid public key the server published for a
    /// device does NOT match the one this device pinned the first time it saw
    /// it (Phase 50).
    ///
    /// This BLOCKS the operation: nothing was wrapped and nothing was uploaded.
    /// It means either a KEY-SUBSTITUTION ATTACK (a hostile or compromised
    /// server offering a key it can decrypt with) or a LEGITIMATE re-enrolment
    /// of that device. Only a human can tell, by comparing the safety numbers
    /// out of band — so nothing ever re-pins automatically.
    KeyPinMismatch {
        /// The device whose published key changed.
        device_id: String,
        /// The safety number of the key this device trusted.
        pinned_safety_number: String,
        /// The safety number of the key the server just presented.
        presented_safety_number: String,
    },
    /// ⛔ The recipient's hybrid public key could NOT be verified, so nothing was
    /// wrapped (Phase 53-55 fix round).
    ///
    /// Two causes, both hard stops: the recipient is a RECOVERY KIT this device
    /// has never pinned and no safety number was supplied to check the server's
    /// answer against, or a supplied safety number did not match. A recovery kit
    /// is the one credential that reconstructs a whole account, and its safety
    /// number is printed on the sheet — so trusting the registry instead is not
    /// an option the UI offers.
    KeyUnverified {
        /// The device the wrap was aimed at.
        device_id: String,
        /// The safety number the server is presenting right now, to compare
        /// against the sheet.
        presented_safety_number: String,
        /// A human explanation. Never key material.
        detail: String,
    },
    /// ⚠️ A RECOVERY KIT operation failed at the client layer: an undecodable
    /// printed code (rejected OFFLINE, before anything was sent), a kit whose
    /// index holds nothing to recover, or a failed pre-print verification.
    ///
    /// NEVER carries the recovery code, a derived seed, a vault key or any other
    /// secret bytes.
    Recovery(String),
    /// HTTP 402: this account's subscription has lapsed past its grace period,
    /// so **new writes** are refused (ADR 0043).
    ///
    /// ⭐ It is deliberately its own variant and not a `Server { status: 402 }`:
    /// a client must be able to tell *"pay to continue"* from *"your key is
    /// wrong"* and from *"you may not touch this vault"*, and it must be able to
    /// say what is **still** available — reading every vault, generating every
    /// code, and giving another device of this same account a vault key
    /// (including a recovery kit) are never refused.
    PaymentRequired {
        /// What the server said, parsed into something renderable. Boxed so a
        /// billing state cannot bloat every `Result` in the crate.
        entitlement: Box<EntitlementView>,
        /// A display message. Never secret, never a card field.
        message: String,
    },
    /// Any other non-2xx status from the server.
    Server {
        /// The HTTP status code.
        status: u16,
        /// A display message. Never contains key material.
        message: String,
    },
}

impl std::fmt::Display for DesktopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DesktopError::Io(m) => write!(f, "{m}"),
            DesktopError::Vault(m) => write!(f, "{m}"),
            DesktopError::AlreadyExists(p) => {
                write!(f, "a vault already exists at {}", p.display())
            }
            DesktopError::NotFound(p) => write!(f, "no vault at {}", p.display()),
            DesktopError::EmptyPassword => write!(f, "password must not be empty"),
            DesktopError::NotEnrolled(p) => write!(
                f,
                "this device is not enrolled ({} has no device id): enroll it with a server URL \
                 and an enrollment token first",
                p.display()
            ),
            DesktopError::AlreadyEnrolled(id) => write!(
                f,
                "this device is already enrolled as {id}; it will not be re-enrolled because that \
                 would destroy its only credential"
            ),
            DesktopError::NotShared(v) => write!(
                f,
                "this device holds no vault key for {v:?}: convert the vault to a shared vault \
                 (owner) or accept a share (recipient) first — your password is never shared"
            ),
            DesktopError::Unreachable(m)
            | DesktopError::Unauthenticated(m)
            | DesktopError::Forbidden(m)
            | DesktopError::MissingOnServer(m)
            | DesktopError::NotEnabled(m) => write!(f, "{m}"),
            DesktopError::KeyPinMismatch {
                device_id,
                pinned_safety_number,
                presented_safety_number,
            } => write!(
                f,
                "REFUSED: the hybrid public key published for device {device_id} has CHANGED \
                 since this device pinned it.\n  pinned    safety number: {pinned_safety_number}\n  \
                 presented safety number: {presented_safety_number}\n  \
                 This is either a KEY-SUBSTITUTION ATTACK (a hostile or compromised server \
                 offering a key it can decrypt with, so it would receive this vault's key) or a \
                 LEGITIMATE RE-ENROLMENT of that device. Nothing was wrapped and nothing was \
                 uploaded. Confirm the presented safety number with that device's owner over a \
                 TRUSTED out-of-band channel, then re-pin deliberately."
            ),
            DesktopError::KeyUnverified { detail, .. } => write!(f, "{detail}"),
            DesktopError::Recovery(m) => write!(f, "recovery kit: {m}"),
            DesktopError::PaymentRequired { message, .. } => write!(f, "{message}"),
            DesktopError::Server { message, .. } => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for DesktopError {}

impl From<CliError> for DesktopError {
    fn from(e: CliError) -> Self {
        DesktopError::Vault(e.to_string())
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, DesktopError>;

// ---------------------------------------------------------------------------
// Clock + paths (the two things sigil-core refuses to do for us)
// ---------------------------------------------------------------------------

/// Current Unix time in whole seconds, read from the host clock.
///
/// `sigil-core` reads no clock, so a native caller must supply the time. Times
/// before the epoch (a badly misconfigured host) clamp to 0.
#[must_use]
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The default vault path: `$HOME/.sigil/totp-vault.sigil`, falling back to
/// `./totp-vault.sigil` when `$HOME` is unset.
///
/// This is byte-for-byte the `sigil` CLI's default location, so `sigil totp list`
/// and the desktop app see the same vault with no configuration.
#[must_use]
pub fn default_vault_path() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) if !home.is_empty() => PathBuf::from(home)
            .join(STATE_DIR_NAME)
            .join(VAULT_FILE_NAME),
        _ => PathBuf::from(VAULT_FILE_NAME),
    }
}

// ---------------------------------------------------------------------------
// View models (what a UI renders — never any secret material)
// ---------------------------------------------------------------------------

/// One account as a UI sees it: metadata plus the *current* code.
///
/// The raw secret is deliberately absent — a list view can never leak it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryView {
    /// Account label (unique within a vault).
    pub label: String,
    /// Optional issuer / service name.
    pub issuer: Option<String>,
    /// `"sha1"`, `"sha256"` or `"sha512"`.
    pub algorithm: String,
    /// Number of digits in the code.
    pub digits: u32,
    /// Time step, in seconds.
    pub period: u32,
    /// The zero-padded code for the supplied instant.
    pub code: String,
    /// Whole seconds left before `code` rolls over.
    pub seconds_remaining: u64,
}

/// The outcome of an import run.
// NOT `Copy`: `partial_batches` owns its notes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImportSummary {
    /// Entries added to the vault.
    pub imported: usize,
    /// Entries skipped because that label was already present.
    pub skipped_duplicate: usize,
    /// Entries skipped because they were counter-based (HOTP); the vault is
    /// TOTP-only and its schema is not extended.
    pub skipped_hotp: usize,
    /// Entries skipped because they were unparseable or invalid.
    pub skipped_invalid: usize,
    /// ⛔ One note per MULTI-QR Google Authenticator batch seen during this
    /// import (Phase 59).
    ///
    /// Google splits a large export across several QR codes; each one decodes
    /// independently and carries only ITS share of the accounts. A UI MUST show
    /// these rather than reporting a plain count. Empty for an ordinary
    /// single-QR export.
    ///
    /// ⚠️ Non-empty does NOT mean "something is missing" — see
    /// [`Self::batches_outstanding`]. The note for the LAST QR of an export says
    /// so in its own words; this vec carries both kinds.
    pub partial_batches: Vec<String>,
    /// ⭐ True only while QR codes remain UNSCANNED.
    ///
    /// This is the field a UI keys its alarm off, not `partial_batches` being
    /// non-empty. Importing batch 2 of 2 used to be reported as "THIS IMPORT IS
    /// INCOMPLETE … 0 more QR code(s) must be imported", i.e. a user who had just
    /// finished was told they had not — and a warning that cries wolf is one the
    /// next user ignores when it is real.
    pub batches_outstanding: bool,
}

impl ImportSummary {
    /// Whether everything the user was importing actually arrived.
    ///
    /// False only while a decoded payload announced QR codes still to come; the
    /// FINAL batch of a multi-QR export does not make an import incomplete (it
    /// still gets a note, because this client keeps no record of earlier runs).
    #[must_use]
    pub fn is_complete(&self) -> bool {
        !self.batches_outstanding
    }
}

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

/// An unlocked vault: a path, the in-memory password, and the decrypted entries.
///
/// Every mutation re-seals and rewrites the container immediately, so a UI can
/// never leave the disk out of sync with what it is showing. Only the sealed
/// container is ever written.
pub struct VaultSession {
    path: PathBuf,
    /// The password, kept ONLY in memory and best-effort zeroed in `Drop`.
    password: Vec<u8>,
    vault: TotpVault,
    params: Argon2Params,
}

impl std::fmt::Debug for VaultSession {
    /// Never renders the password or any secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultSession")
            .field("path", &self.path)
            .field("entries", &self.vault.entries.len())
            .finish_non_exhaustive()
    }
}

impl Drop for VaultSession {
    /// Best-effort scrub of the in-memory password. This is not a hardened
    /// zeroization (no `zeroize` crate, no volatile guarantee, and the OS may
    /// have paged the buffer); it is documented as such rather than claimed.
    fn drop(&mut self) {
        for b in self.password.iter_mut() {
            *b = 0;
        }
    }
}

impl VaultSession {
    /// Create a brand-new empty vault at `path` and seal it immediately.
    ///
    /// # Errors
    /// - [`DesktopError::AlreadyExists`] if `path` is already present.
    /// - [`DesktopError::EmptyPassword`] for an empty password.
    /// - [`DesktopError::Io`] / [`DesktopError::Vault`] on write or seal failure.
    pub fn create(path: impl Into<PathBuf>, password: &[u8]) -> Result<Self> {
        let path = path.into();
        if password.is_empty() {
            return Err(DesktopError::EmptyPassword);
        }
        if path.exists() {
            return Err(DesktopError::AlreadyExists(path));
        }
        let session = VaultSession {
            path,
            password: password.to_vec(),
            vault: TotpVault::default(),
            params: Argon2Params::RECOMMENDED,
        };
        session.save()?;
        Ok(session)
    }

    /// Unlock an existing vault at `path`.
    ///
    /// # Errors
    /// - [`DesktopError::NotFound`] if there is no vault there.
    /// - [`DesktopError::Vault`] on a wrong password or a tampered container (the
    ///   AEAD fails to authenticate; no plaintext is leaked).
    pub fn unlock(path: impl Into<PathBuf>, password: &[u8]) -> Result<Self> {
        let path = path.into();
        if password.is_empty() {
            return Err(DesktopError::EmptyPassword);
        }
        if !path.exists() {
            return Err(DesktopError::NotFound(path));
        }
        let container = std::fs::read(&path)
            .map_err(|e| DesktopError::Io(format!("could not read {}: {e}", path.display())))?;
        let vault = open_vault(password, &container)?;
        Ok(VaultSession {
            path,
            password: password.to_vec(),
            vault,
            params: Argon2Params::RECOMMENDED,
        })
    }

    /// Unlock the vault at `path` if it exists, else create it.
    ///
    /// # Errors
    /// Same as [`VaultSession::unlock`] / [`VaultSession::create`].
    pub fn open_or_create(path: impl Into<PathBuf>, password: &[u8]) -> Result<Self> {
        let path = path.into();
        if path.exists() {
            Self::unlock(path, password)
        } else {
            Self::create(path, password)
        }
    }

    /// Override the Argon2id work factor (tests use a deliberately cheap one).
    ///
    /// Production/UI callers should leave this at [`Argon2Params::RECOMMENDED`].
    /// The parameters are written into the container header, so the CLI (and any
    /// other client) still opens a vault sealed with custom params.
    #[must_use]
    pub fn with_params(mut self, params: Argon2Params) -> Self {
        self.params = params;
        self
    }

    /// Where this session's sealed container lives.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of accounts in the vault.
    #[must_use]
    pub fn len(&self) -> usize {
        self.vault.entries.len()
    }

    /// Whether the vault holds no accounts.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.vault.entries.is_empty()
    }

    /// Borrow the decrypted vault (used by the interop test and by exporters).
    #[must_use]
    pub fn vault(&self) -> &TotpVault {
        &self.vault
    }

    /// Render every account with its code at `unix_time`.
    ///
    /// The code is computed by `sigil-core` (`totp` + `format_code`) via
    /// `sigil-cli`'s [`TotpEntry::code_at`]; the time is supplied by the caller
    /// because the core reads no clock.
    ///
    /// # Errors
    /// - [`DesktopError::Vault`] if a stored entry is malformed.
    pub fn entries_at(&self, unix_time: u64) -> Result<Vec<EntryView>> {
        self.vault
            .entries
            .iter()
            .map(|e| {
                let (code, seconds_remaining) = e.code_at(unix_time)?;
                Ok(EntryView {
                    label: e.label.clone(),
                    issuer: e.issuer.clone(),
                    algorithm: e.algorithm.clone(),
                    digits: e.digits,
                    period: e.period,
                    code,
                    seconds_remaining,
                })
            })
            .collect()
    }

    /// [`VaultSession::entries_at`] against the host clock.
    ///
    /// # Errors
    /// Same as [`VaultSession::entries_at`].
    pub fn entries_now(&self) -> Result<Vec<EntryView>> {
        self.entries_at(now_unix())
    }

    /// Add an account from a base32 secret (the form printed next to a QR code).
    ///
    /// `algorithm` accepts `""`/`sha1`/`sha256`/`sha512` (case-insensitive);
    /// `digits`/`period` default to 6/30 when `None`.
    ///
    /// # Errors
    /// - [`DesktopError::Vault`] on a bad base32 secret, an unknown algorithm,
    ///   out-of-range digits/period, or a duplicate label.
    pub fn add_secret_base32(
        &mut self,
        label: &str,
        issuer: Option<String>,
        secret_base32: &str,
        algorithm: &str,
        digits: Option<u32>,
        period: Option<u32>,
    ) -> Result<()> {
        let raw = base32_decode(secret_base32)?;
        let algo = totp_algorithm_from_str(algorithm)?;
        let entry = new_totp_entry(
            label,
            issuer,
            &raw,
            algo,
            digits.unwrap_or(TOTP_DEFAULT_DIGITS),
            period.unwrap_or(TOTP_DEFAULT_PERIOD),
        )?;
        self.vault.add(entry)?;
        self.save()
    }

    /// Add one account from an `otpauth://totp/...` provisioning URI, returning
    /// the label it was stored under.
    ///
    /// # Errors
    /// - [`DesktopError::Vault`] on a bad URI or a duplicate label.
    pub fn add_uri(&mut self, uri: &str) -> Result<String> {
        let entry = parse_otpauth_uri(uri.trim())?;
        let label = entry.label.clone();
        self.vault.add(entry)?;
        self.save()?;
        Ok(label)
    }

    /// Import accounts from arbitrary text: a Google Authenticator
    /// `otpauth-migration://offline?data=...` bulk-export URI, a single
    /// `otpauth://totp/...` URI, or many URIs one per line (`#` comments and
    /// blank lines ignored).
    ///
    /// Duplicate labels are **skipped**, never overwritten. HOTP and invalid
    /// entries are skipped and counted. The vault is re-sealed only when at least
    /// one entry was actually imported.
    ///
    /// # Errors
    /// - [`DesktopError::Vault`] if re-sealing fails.
    pub fn import_text(&mut self, text: &str) -> Result<ImportSummary> {
        let mut summary = ImportSummary::default();
        let mut staged: Vec<TotpEntry> = Vec::new();

        for line in text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
        {
            collect_from_uri(line, &mut staged, &mut summary);
        }

        for entry in staged {
            if self.vault.find(&entry.label).is_some() {
                summary.skipped_duplicate += 1;
                continue;
            }
            match self.vault.add(entry) {
                Ok(()) => summary.imported += 1,
                Err(_) => summary.skipped_invalid += 1,
            }
        }

        if summary.imported > 0 {
            self.save()?;
        }
        Ok(summary)
    }

    /// [`VaultSession::import_text`] over the contents of a file.
    ///
    /// # Errors
    /// - [`DesktopError::Io`] if the file cannot be read.
    pub fn import_file(&mut self, path: &Path) -> Result<ImportSummary> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| DesktopError::Io(format!("could not read {}: {e}", path.display())))?;
        self.import_text(&text)
    }

    /// Remove the account labelled `label`.
    ///
    /// # Errors
    /// - [`DesktopError::Vault`] if no such account exists.
    pub fn remove(&mut self, label: &str) -> Result<()> {
        self.vault.remove(label)?;
        self.save()
    }

    /// Select entries: all of them, or just the one labelled `label`.
    fn select(&self, label: Option<&str>) -> Result<Vec<&TotpEntry>> {
        match label {
            Some(l) => Ok(vec![self.vault.find(l).ok_or_else(|| {
                DesktopError::Vault(format!("no entry labelled {l:?}"))
            })?]),
            None => {
                if self.vault.entries.is_empty() {
                    return Err(DesktopError::Vault(
                        "vault is empty; nothing to export".to_string(),
                    ));
                }
                Ok(self.vault.entries.iter().collect())
            }
        }
    }

    /// Export accounts as `otpauth://totp/...` URIs.
    ///
    /// # ⚠️ These strings contain the 2FA SECRETS IN THE CLEAR
    ///
    /// That is the point of an export (portability, no lock-in), but any caller
    /// MUST warn loudly before revealing the result. See [`EXPORT_WARNING`].
    ///
    /// # Errors
    /// - [`DesktopError::Vault`] on an unknown label, an empty vault, or an entry
    ///   that cannot be represented.
    pub fn export_uris(&self, label: Option<&str>) -> Result<Vec<String>> {
        self.select(label)?
            .into_iter()
            .map(|e| entry_to_otpauth_uri(e).map_err(DesktopError::from))
            .collect()
    }

    /// Export accounts as ONE combined Google Authenticator
    /// `otpauth-migration://offline?data=...` URI.
    ///
    /// # ⚠️ Contains the 2FA SECRETS IN THE CLEAR — see [`EXPORT_WARNING`].
    ///
    /// # Errors
    /// - [`DesktopError::Vault`] on an unknown label, an empty vault, or an entry
    ///   the migration format cannot express (e.g. 7 digits).
    pub fn export_migration_uri(&self, label: Option<&str>) -> Result<String> {
        let selected = self.select(label)?;
        let mut otps = Vec::with_capacity(selected.len());
        for e in selected {
            otps.push(entry_to_migration_otp(e)?);
        }
        Ok(encode_migration_uri(&otps))
    }

    /// Serialize, seal and write the container: `$path.tmp` (0600) then rename,
    /// so an interrupted write cannot truncate a good vault.
    ///
    /// # Errors
    /// - [`DesktopError::Vault`] on a seal failure.
    /// - [`DesktopError::Io`] on any filesystem failure.
    pub fn save(&self) -> Result<()> {
        let container = seal_vault(&self.password, &self.vault, self.params)?;

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    DesktopError::Io(format!("could not create {}: {e}", parent.display()))
                })?;
                // 0700: the state dir may hold the device key too.
                set_mode(parent, 0o700)?;
            }
        }

        let tmp = self.path.with_extension("sigil.tmp");
        write_private(&tmp, &container)?;
        std::fs::rename(&tmp, &self.path).map_err(|e| {
            DesktopError::Io(format!(
                "could not move {} into place at {}: {e}",
                tmp.display(),
                self.path.display()
            ))
        })?;
        set_mode(&self.path, 0o600)
    }
}

/// The mandatory warning any UI must show before revealing an export.
pub const EXPORT_WARNING: &str =
    "This export contains your TOTP SECRETS IN THE CLEAR. Anyone who reads it can generate your \
     codes. Treat it like a password: do not paste it into logs, chats, screenshots, or shared \
     terminals.";

/// Parse one line of import input into zero or more staged entries, counting
/// skips. Never fails the whole import for one bad line.
fn collect_from_uri(uri: &str, out: &mut Vec<TotpEntry>, summary: &mut ImportSummary) {
    let lower = uri.to_ascii_lowercase();
    if lower.starts_with("otpauth-migration://") {
        match decode_migration_uri(uri) {
            Ok(batch) => {
                // ⛔ Record a multi-QR batch BEFORE counting entries, so a
                // partial import can never be reported as a whole one.
                if let Some(note) = batch.batch_note() {
                    // ⭐ Only a NON-final batch means something is still missing.
                    summary.batches_outstanding |= !batch.is_final_batch();
                    summary.partial_batches.push(note);
                }
                for otp in &batch.otps {
                    match migration_otp_to_entry(otp) {
                        Ok(ImportedOtp::Totp(e)) => out.push(*e),
                        Ok(ImportedOtp::SkippedHotp) => summary.skipped_hotp += 1,
                        Err(_) => summary.skipped_invalid += 1,
                    }
                }
            }
            Err(_) => summary.skipped_invalid += 1,
        }
    } else if lower.starts_with("otpauth://hotp/") {
        summary.skipped_hotp += 1;
    } else {
        match parse_otpauth_uri(uri) {
            Ok(e) => out.push(e),
            Err(_) => summary.skipped_invalid += 1,
        }
    }
}

/// Create/truncate `path` with mode 0600 and write `bytes`.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| DesktopError::Io(format!("could not open {}: {e}", path.display())))?;
    f.write_all(bytes)
        .map_err(|e| DesktopError::Io(format!("could not write {}: {e}", path.display())))?;
    f.sync_all()
        .map_err(|e| DesktopError::Io(format!("could not flush {}: {e}", path.display())))
}

/// Force `path`'s permission bits (a pre-existing file keeps its old mode
/// through `OpenOptions::mode`, so set it explicitly).
fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| DesktopError::Io(format!("could not chmod {}: {e}", path.display())))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Cheap Argon2id params so tests stay fast while still hitting the REAL KDF
    /// path. (Argon2 requires `m_cost >= 8 * p_cost`.)
    pub(crate) const FAST: Argon2Params = Argon2Params {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    };
    const PASSWORD: &[u8] = b"correct horse battery staple";

    /// RFC 6238 test seed: ASCII "12345678901234567890" as base32.
    const RFC_SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sigil-desktop-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir.join("totp-vault.sigil")
    }

    fn new_session(name: &str) -> VaultSession {
        VaultSession::create(scratch(name), PASSWORD)
            .expect("create")
            .with_params(FAST)
    }

    #[test]
    fn create_then_unlock_round_trips_and_persists_only_the_sealed_container() {
        let path = scratch("roundtrip");
        {
            let mut s = VaultSession::create(&path, PASSWORD)
                .expect("create")
                .with_params(FAST);
            s.add_secret_base32(
                "alice",
                Some("Acme".into()),
                RFC_SEED_B32,
                "sha1",
                None,
                None,
            )
            .expect("add");
        }

        // On disk: a SIGILcli container, and NOT the plaintext secret.
        let bytes = std::fs::read(&path).expect("read");
        assert_eq!(&bytes[..8], b"SIGILcli", "must be the shared CLI container");
        assert!(
            !String::from_utf8_lossy(&bytes).contains("alice"),
            "label must not appear in the sealed bytes"
        );

        let reopened = VaultSession::unlock(&path, PASSWORD)
            .expect("unlock")
            .with_params(FAST);
        assert_eq!(reopened.len(), 1);
        assert_eq!(reopened.vault().entries[0].label, "alice");
        assert_eq!(reopened.vault().entries[0].issuer.as_deref(), Some("Acme"));
    }

    #[test]
    fn wrong_password_fails_to_unlock() {
        let path = scratch("wrongpw");
        let _ = VaultSession::create(&path, PASSWORD)
            .expect("create")
            .with_params(FAST);
        let err = VaultSession::unlock(&path, b"not the password").unwrap_err();
        assert!(matches!(err, DesktopError::Vault(_)), "got {err:?}");
    }

    #[test]
    fn create_refuses_to_clobber_and_unlock_refuses_a_missing_vault() {
        let path = scratch("guards");
        let _ = VaultSession::create(&path, PASSWORD)
            .expect("create")
            .with_params(FAST);
        assert!(matches!(
            VaultSession::create(&path, PASSWORD).unwrap_err(),
            DesktopError::AlreadyExists(_)
        ));
        let missing = path.with_file_name("nope.sigil");
        assert!(matches!(
            VaultSession::unlock(&missing, PASSWORD).unwrap_err(),
            DesktopError::NotFound(_)
        ));
        assert!(matches!(
            VaultSession::create(&missing, b"").unwrap_err(),
            DesktopError::EmptyPassword
        ));
    }

    #[test]
    fn add_remove_and_duplicate_rejection() {
        let mut s = new_session("addremove");
        s.add_secret_base32("a", None, RFC_SEED_B32, "sha1", None, None)
            .expect("add a");
        assert!(s
            .add_secret_base32("a", None, RFC_SEED_B32, "sha1", None, None)
            .is_err());
        s.add_secret_base32("b", None, RFC_SEED_B32, "sha256", Some(8), Some(60))
            .expect("add b");
        assert_eq!(s.len(), 2);

        let views = s.entries_at(0).expect("views");
        assert_eq!(views[1].algorithm, "sha256");
        assert_eq!(views[1].digits, 8);
        assert_eq!(views[1].period, 60);

        s.remove("a").expect("remove");
        assert_eq!(s.len(), 1);
        assert!(s.remove("a").is_err());
        assert!(!s.is_empty());
    }

    /// The headline correctness check: the NATIVE sigil-core path reproduces the
    /// RFC 6238 Appendix B vector at T=59 (SHA-1, period 30).
    #[test]
    fn totp_kat_rfc6238_t59() {
        let mut s = new_session("kat");
        s.add_secret_base32("eight", None, RFC_SEED_B32, "sha1", Some(8), Some(30))
            .expect("add 8");
        s.add_secret_base32("six", None, RFC_SEED_B32, "sha1", Some(6), Some(30))
            .expect("add 6");

        let views = s.entries_at(59).expect("views");
        assert_eq!(views[0].code, "94287082", "RFC 6238 App B, T=59, 8 digits");
        assert_eq!(views[1].code, "287082", "same vector truncated to 6 digits");
        // 59 s into a 30 s step => 1 s left in the current window.
        assert_eq!(views[0].seconds_remaining, 1);

        // And the next step boundary behaves.
        let at60 = s.entries_at(60).expect("views");
        assert_eq!(at60[0].seconds_remaining, 30);
        assert_ne!(at60[0].code, "94287082");
    }

    #[test]
    fn otpauth_uri_import_and_export_round_trip() {
        let mut s = new_session("uri");
        let label = s
            .add_uri(&format!(
                "otpauth://totp/Acme:bob%40example.com?secret={RFC_SEED_B32}&issuer=Acme&digits=8&period=30"
            ))
            .expect("add_uri");
        assert_eq!(label, "bob@example.com");
        assert_eq!(s.vault().entries[0].issuer.as_deref(), Some("Acme"));
        assert_eq!(s.entries_at(59).expect("views")[0].code, "94287082");

        let uris = s.export_uris(None).expect("export");
        assert_eq!(uris.len(), 1);
        assert!(uris[0].starts_with("otpauth://totp/"));
        assert!(uris[0].contains(RFC_SEED_B32));

        // Re-importing the exported URI into a fresh vault reproduces the entry.
        let mut fresh = new_session("uri2");
        let summary = fresh.import_text(&uris[0]).expect("import");
        assert_eq!(summary.imported, 1);
        assert_eq!(fresh.entries_at(59).expect("v")[0].code, "94287082");
    }

    #[test]
    fn migration_import_export_round_trip_and_skips() {
        let mut s = new_session("migration");
        s.add_secret_base32(
            "acct-1",
            Some("Acme".into()),
            RFC_SEED_B32,
            "sha1",
            None,
            None,
        )
        .expect("add");
        s.add_secret_base32("acct-2", None, RFC_SEED_B32, "sha256", Some(8), Some(30))
            .expect("add");

        let migration = s.export_migration_uri(None).expect("export migration");
        assert!(migration.starts_with("otpauth-migration://offline?data="));

        let mut fresh = new_session("migration2");
        let summary = fresh.import_text(&migration).expect("import");
        assert_eq!(summary.imported, 2, "{summary:?}");
        assert_eq!(fresh.vault().entries[0].label, "acct-1");
        assert_eq!(fresh.vault().entries[0].issuer.as_deref(), Some("Acme"));
        assert_eq!(fresh.vault().entries[1].algorithm, "sha256");

        // Re-importing the same URI: everything is a duplicate, nothing added.
        let again = fresh.import_text(&migration).expect("import again");
        assert_eq!(again.imported, 0);
        assert_eq!(again.skipped_duplicate, 2);

        // Mixed junk: comments/blanks ignored, HOTP and garbage counted, not fatal.
        let mut mixed = new_session("mixed");
        let summary = mixed
            .import_text(&format!(
                "# a comment\n\n\
                 otpauth://totp/good?secret={RFC_SEED_B32}\n\
                 otpauth://hotp/counter?secret={RFC_SEED_B32}&counter=1\n\
                 not-a-uri-at-all\n"
            ))
            .expect("import mixed");
        assert_eq!(summary.imported, 1);
        assert_eq!(summary.skipped_hotp, 1);
        assert_eq!(summary.skipped_invalid, 1);
    }

    /// ⛔ THE FINAL BATCH OF A MULTI-QR EXPORT IS NOT AN INCOMPLETE IMPORT.
    ///
    /// Importing batch 2 of 2 used to report "0 more QR code(s) must be imported
    /// … This import is PARTIAL", i.e. it told a user who had just finished that
    /// they had not — and a warning that cries wolf is one the next user ignores
    /// when it is real. The note must still NAME the batch (this app keeps no
    /// record of earlier runs), but `batches_outstanding` — what the UI keys its
    /// alarm off — must be false.
    /// Standard base64, hand-rolled: this crate deliberately has no base64
    /// dependency (it reuses the CLI's codecs), and one test fixture is not a
    /// reason to add one.
    fn b64(bytes: &[u8]) -> String {
        const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in bytes.chunks(3) {
            let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            out.push(A[(n >> 18) as usize & 63] as char);
            out.push(A[(n >> 12) as usize & 63] as char);
            out.push(if c.len() > 1 {
                A[(n >> 6) as usize & 63] as char
            } else {
                '='
            });
            out.push(if c.len() > 2 {
                A[n as usize & 63] as char
            } else {
                '='
            });
        }
        out
    }

    #[test]
    fn a_finished_multi_qr_import_is_not_reported_as_incomplete() {
        use sigil_cli::migration::{encode_migration_payload, MigrationOtp};

        // Build ONE QR of a two-QR export by hand: the encoder always writes a
        // single self-contained batch, so the framing is appended here.
        fn one_qr_of_two(index: u64) -> String {
            let otp = MigrationOtp {
                secret: b"12345678901234567890".to_vec(),
                name: format!("acct-{index}"),
                issuer: "Svc".to_string(),
                algorithm: 1,
                digits: 1,
                otp_type: 2,
                counter: 0,
            };
            // encode_migration_payload's tail is exactly
            //   0x10 <version> 0x18 <batch_size=1>
            // (batch_index / batch_id are omitted at their proto3 defaults), so
            // raise batch_size and append the batch_index field.
            let mut body = encode_migration_payload(std::slice::from_ref(&otp));
            let n = body.len();
            assert_eq!(&body[n - 2..], &[0x18, 0x01], "batch framing tail moved");
            body[n - 1] = 2; // batch_size = 2
            body.push(0x20); // field 4 (batch_index), varint
            body.push(index as u8);
            format!("otpauth-migration://offline?data={}", b64(&body))
        }

        // Batch 1 of 2: genuinely outstanding, and it must stay loud.
        let mut first = new_session("batch-first");
        let s1 = first.import_text(&one_qr_of_two(0)).expect("import");
        assert_eq!(s1.imported, 1);
        assert!(
            !s1.is_complete(),
            "batch 1 of 2 leaves QR codes outstanding"
        );
        assert!(s1.batches_outstanding);
        assert!(s1.partial_batches[0].contains("PARTIAL"), "{s1:?}");

        // Batch 2 of 2: still named, but NOT an incomplete import.
        let mut last = new_session("batch-last");
        let s2 = last.import_text(&one_qr_of_two(1)).expect("import");
        assert_eq!(s2.imported, 1);
        assert!(!s2.batches_outstanding, "nothing is outstanding: {s2:?}");
        assert!(s2.is_complete(), "the user has finished: {s2:?}");
        assert_eq!(s2.partial_batches.len(), 1, "it must still say which batch");
        assert!(s2.partial_batches[0].contains("batch 2 of 2"), "{s2:?}");
        assert!(!s2.partial_batches[0].contains("PARTIAL"), "{s2:?}");
    }

    #[test]
    fn export_selects_a_single_label_and_rejects_unknown_or_empty() {
        let mut s = new_session("select");
        assert!(s.export_uris(None).is_err(), "empty vault");
        s.add_secret_base32("a", None, RFC_SEED_B32, "sha1", None, None)
            .expect("add");
        s.add_secret_base32("b", None, RFC_SEED_B32, "sha1", None, None)
            .expect("add");
        assert_eq!(s.export_uris(Some("b")).expect("one").len(), 1);
        assert!(s.export_uris(Some("zzz")).is_err());
        assert!(!EXPORT_WARNING.is_empty());
    }

    #[test]
    fn saved_container_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let s = new_session("mode");
        let mode = std::fs::metadata(s.path())
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "sealed vault must be owner-only");
    }

    #[test]
    fn default_vault_path_matches_the_cli_location() {
        let p = default_vault_path();
        assert!(
            p.ends_with(format!("{STATE_DIR_NAME}/{VAULT_FILE_NAME}"))
                || p.ends_with(VAULT_FILE_NAME)
        );
    }

    #[test]
    fn now_unix_is_sane() {
        // Well after 2020 and before 2100 — proves we read the host clock.
        let t = now_unix();
        assert!(t > 1_577_836_800 && t < 4_102_444_800, "got {t}");
    }
}
