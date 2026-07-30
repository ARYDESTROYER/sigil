//! The server-facing half of the desktop column: enrollment, contract-v3
//! authenticated sync, and device-to-device vault sharing.
//!
//! # STATUS: PRE-AUDIT — UNAUDITED — DEV / LOCALHOST / PLAIN HTTP
//!
//! # Reuse, not reimplementation
//!
//! There is **no HTTP client, no signing path and no canonical message** in this
//! file. Every byte that goes on the wire is produced by the `sigil-cli`
//! library, which the `sigil` binary itself uses:
//!
//! | what | reused from `sigil_cli` |
//! |---|---|
//! | enrollment (token + proof-of-possession) | [`enroll_device`] |
//! | op-log push / pull, contract v3 signed | [`push_op_auth`] / [`pull_ops_auth`] |
//! | hybrid public key publish / fetch | [`publish_hybrid_key`] / [`fetch_hybrid_key`] |
//! | wrapped-key relay | [`put_key_envelope`] / [`get_key_envelope`] |
//! | wrap / unwrap a vault key (X25519 + ML-KEM-768) | [`wrap_vault_key`] / [`unwrap_vault_key`] |
//! | per-vault authorization | [`grant_vault_access`] |
//! | identity, hybrid identity, keyring file formats | [`KeyFile`](sigil_cli::KeyFile), [`HybridSecretIdentity`](sigil_cli::HybridSecretIdentity), [`VaultKeyring`] |
//!
//! Because the file formats are the CLI's own types written by the CLI's own
//! writers, the files this module creates are **byte-interchangeable with the
//! `sigil` CLI**: point `sigil --key <file>` (or `HOME`) at a desktop state
//! directory and the CLI is the same device.
//!
//! # Secrets on disk
//!
//! Native client, native model — the same one the CLI documents:
//!
//! | file | holds | mode |
//! |---|---|---|
//! | `<state>/device.key` | Ed25519 seed (SECRET) + assigned device id | `0600` |
//! | `<state>/device.hybrid` | X25519 secret + ML-KEM keygen seed (SECRET) | `0600` |
//! | `<state>/device.hybrid.pub` | public halves only | default |
//! | `<state>/vault-keys.json` | vault id → 32-byte vault key (SECRET) | `0600` |
//!
//! all inside a `0700` state directory. **Nothing here ever prints, logs or
//! returns a seed, a vault key or an enrollment token** — only SHA-256
//! fingerprints (via [`vault_key_fingerprint`]) and opaque device ids.
//!
//! # The key model (it must match the CLI exactly or nothing interoperates)
//!
//! * a PERSONAL vault stays sealed under the human password;
//! * a SHARED vault is sealed under a **random 32-byte vault key** — the
//!   `SIGILcli` container takes arbitrary password bytes, so no format changes;
//! * that key is wrapped **per recipient** with the PQ-hybrid seal and relayed
//!   as opaque ciphertext. The human password is **never** shared or wrapped.

use std::path::{Path, PathBuf};

use sigil_cli::{
    enroll_device, fetch_hybrid_key, fetch_subscription, generate_hybrid_identity, generate_key,
    generate_vault_key, keyring_get, keyring_put, load_hybrid_public, load_hybrid_secret,
    load_identity, load_key_file, load_keyring, publish_hybrid_key, pull_ops_auth, push_op_auth,
    save_hybrid_public, save_hybrid_secret, save_key, share_vault_to_known_key,
    vault_key_fingerprint, CliError, DeviceIdentity, RequestAuth, VaultKeyring, VAULT_KEYRING_FILE,
    VAULT_KEY_LEN,
};
// Phase 60 — the AUTHENTICATED vault-key envelope. Same rule as everywhere in
// this file: the desktop implements NOTHING of its own. `SenderIdentity` bundles
// this device's id with the hybrid secret that authenticates its wraps, and
// `accept_vault_key` is the CLI library's whole receiving path — resolve the
// depositing device, pin-check its key, unwrap AUTHENTICATED + context-bound,
// prove the key opens the vault, and refuse to silently replace a different one.
// Putting that logic in the library rather than in `cli/src/main.rs` is exactly
// what lets the desktop reuse it (ADR 0037).
use sigil_cli::{accept_vault_key, SenderIdentity};
// Phase 50 — key verification (safety numbers + pinning) and vault key rotation.
// The desktop adds NO implementation of its own: it calls the same sigil-cli
// library functions the CLI does, so the semantics and the safety-number digest
// cannot drift between the two (ADR 0037).
use sigil_cli::{
    hybrid_safety_number, load_pins, pairwise_safety_number, repin_hybrid_key, rotate_vault_key,
    verify_recipient_for_wrap, HybridKeyPin, RecipientTrust, HYBRID_PIN_FILE,
};

/// What a share actually did — fingerprints and PUBLIC digits only, never a key.
///
/// ⭐ `safety_number` and `trust` are returned so a UI can show the trust
/// decision. The CLI now prints them BEFORE wrapping (the previous ordering
/// showed the number only after the vault key was already on the server); a
/// desktop UI should surface `needs_out_of_band_check` just as loudly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareOutcome {
    /// 16-hex SHA-256 fingerprint of the vault key that was wrapped.
    pub fingerprint: String,
    /// The recipient's safety number — the digits to compare out of band.
    pub safety_number: String,
    /// How trust in the recipient's key was established.
    pub trust: String,
    /// True when this was an unverified FIRST SIGHT: pinned now, but nothing
    /// out of band has confirmed it.
    pub needs_out_of_band_check: bool,
}
// Phase 52 — the ACCOUNT model. Same rule again: the desktop implements no
// protocol of its own, it calls the sigil-cli library functions the CLI calls,
// so a desktop account request and a `sigil account …` request are the same
// bytes. JOINING needs nothing new — an invite is redeemed by the UNCHANGED
// `enroll_device` path (ADR 0037, ADR 0040).
use sigil_cli::{create_account_invite, get_account, list_account_invites, revoke_account_invite};
use sigil_core::Argon2Params;

use crate::{DesktopError, Result, VaultSession, STATE_DIR_NAME};

/// File name of this device's Ed25519 identity — the CLI's default name, so the
/// file is interchangeable with `sigil --key`.
pub const DEVICE_IDENTITY_FILE: &str = "device.key";

/// File name of this device's SECRET hybrid identity. Matches the CLI's rule
/// (`device.key` with the extension replaced by `hybrid`).
pub const HYBRID_SECRET_FILE: &str = "device.hybrid";

/// File name of the shareable PUBLIC hybrid identity (the CLI appends `.pub`).
pub const HYBRID_PUBLIC_FILE: &str = "device.hybrid.pub";

// ---------------------------------------------------------------------------
// View models — never any secret material
// ---------------------------------------------------------------------------

/// One shared vault this device holds a key for. The key itself is never in
/// here; only a non-reversible fingerprint so two devices can prove they hold
/// the same key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultKeyInfo {
    /// The op-log vault id.
    pub vault_id: String,
    /// First 16 hex chars of SHA-256 of the vault key.
    pub key_fingerprint: String,
}

/// Everything a UI can say about this device's server posture, read **purely
/// from local disk** — [`DeviceConfig::status`] never touches the network, so it
/// works offline and cannot fail because a server is down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceStatus {
    /// The configured sigild base URL.
    pub server: String,
    /// The 0700 state directory holding the files below.
    pub state_dir: PathBuf,
    /// Path of the Ed25519 identity file.
    pub identity_path: PathBuf,
    /// Whether an identity file exists AND carries a server-assigned device id.
    pub enrolled: bool,
    /// The server-assigned device id, when enrolled. Opaque, not secret.
    pub device_id: Option<String>,
    /// Fingerprint of the Ed25519 PUBLIC key, when an identity exists.
    pub device_fingerprint: Option<String>,
    /// Whether a local hybrid identity exists. Use [`DeviceConfig::check_server`]
    /// to confirm the *server* holds the published public half.
    pub hybrid_identity_present: bool,
    /// Fingerprint of the X25519 public half, when a hybrid identity exists.
    pub hybrid_fingerprint: Option<String>,
    /// Path of the local vault keyring.
    pub keyring_path: PathBuf,
    /// Which shared vaults this device holds keys for (fingerprints only).
    pub vaults: Vec<VaultKeyInfo>,
}

/// The result of a best-effort server probe. Never an error for "the server is
/// down" — that is reported as `reachable: false`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCheck {
    /// Whether sigild answered at all.
    pub reachable: bool,
    /// Whether the server holds this device's published hybrid public key.
    pub hybrid_published: bool,
    /// A short human-readable explanation, safe to display. Never secret.
    pub detail: String,
}

/// One member device of this device's account. METADATA ONLY — the registry
/// never echoes public keys, and nothing here is secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountMember {
    /// The server-assigned device id. Opaque, not secret.
    pub device_id: String,
    /// The human label given at enrollment.
    pub label: String,
    /// `"active"` or `"revoked"`.
    pub status: String,
    /// RFC 3339 enrollment time.
    pub created_at: String,
    /// RFC 3339 revocation time, empty while active.
    pub revoked_at: String,
    /// Whether this row is the device running this app.
    pub is_this_device: bool,
}

/// This device's ACCOUNT: the group of devices that share entitlement and vault
/// ownership. There is no way to ask about another account — the server derives
/// it from the verified signature, so this is always "mine".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountView {
    /// The server-assigned account id (`acct_…`). An identifier, never a credential.
    pub account_id: String,
    /// RFC 3339 creation time, when the server reports one.
    pub created_at: String,
    /// How many ACTIVE devices are in the account — the number the cap applies
    /// to. A revoked device does not consume a seat.
    pub device_count: usize,
    /// How many revoked devices the account still lists. They remain visible as
    /// history but do NOT count against [`Self::device_limit`].
    pub revoked_device_count: usize,
    /// The server's configured per-account device cap.
    pub device_limit: usize,
    /// The member devices.
    pub members: Vec<AccountMember>,
}

/// A freshly minted account invite.
///
/// ⚠️ [`MintedInvite::invite`] is a BEARER SECRET the server returns exactly ONCE.
/// Anyone who reads it inside its TTL can join this account and inherit its
/// subscription, and the dev transport is plain HTTP. Show it once, do not
/// persist it, and clear it from the UI after use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedInvite {
    /// The PUBLIC handle, for listing and revocation. Not a secret.
    pub invite_id: String,
    /// ⚠️ THE SECRET. Never logged, never stored, never re-served.
    pub invite: String,
    /// The account it joins (this device's own).
    pub account_id: String,
    /// RFC 3339 expiry.
    pub expires_at: String,
    /// Whether it is pinned to one device's public key.
    pub pinned: bool,
}

/// An OPEN invite in a listing: the PUBLIC handle and metadata, never the secret
/// and never its digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenInvite {
    /// The PUBLIC handle.
    pub invite_id: String,
    /// Which member device minted it.
    pub created_by_device_id: String,
    /// RFC 3339 creation time.
    pub created_at: String,
    /// RFC 3339 expiry.
    pub expires_at: String,
    /// Whether it is pinned to one device's public key.
    pub pinned: bool,
}

/// One sealed container pulled back from the op-log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PulledVault {
    /// The op-log sequence number of the container returned.
    pub seq: u64,
    /// The OPAQUE sealed bytes, exactly as the server returned them.
    pub container: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Error mapping — a UI must be able to tell 401 from 403 from 501 from "down"
// ---------------------------------------------------------------------------

/// Translate a `sigil-cli` failure into a [`DesktopError`] a UI can act on,
/// keeping the HTTP status distinctions the server actually makes.
///
/// `what` names the operation in progress; it never contains secret material.
pub(crate) fn net_error(e: CliError, server: &str, what: &str) -> DesktopError {
    match e {
        CliError::Http(msg) => DesktopError::Unreachable(format!(
            "could not reach the sync server at {server} while {what}: {msg}. \
             Check the server URL, or work offline — your vault is on this machine."
        )),
        CliError::Server { status: 401, .. } => DesktopError::Unauthenticated(format!(
            "the server rejected this device's credentials while {what} (HTTP 401). \
             Enroll this device, check it has not been revoked, and make sure this \
             machine's clock is within 300s of the server's."
        )),
        CliError::Server { status: 403, .. } => DesktopError::Forbidden(format!(
            "this device is authenticated but not permitted while {what} (HTTP 403). \
             Only the vault owner or a granted device may do this, and only the \
             addressee may collect a key envelope."
        )),
        CliError::Server { status: 404, .. } => DesktopError::MissingOnServer(format!(
            "nothing there while {what} (HTTP 404). The other device may not have \
             published a hybrid key, or nothing has been shared to this device yet."
        )),
        CliError::Server { status: 501, .. } => DesktopError::NotEnabled(format!(
            "the server has this route switched off while {what} (HTTP 501). \
             sigild's sync and device routes are dev-gated."
        )),
        // ⭐ NOT a generic server error. A 402 is a BILLING state, and rendering
        // it as "HTTP error 402" would turn a payment problem into something a
        // user reads as data loss. It is parsed so the UI can say what is still
        // available — and reads and same-account key recovery ALWAYS are.
        CliError::Server { status: 402, body } => {
            let entitlement = crate::entitlement::EntitlementView::from_payment_required(&body)
                .unwrap_or_else(|| {
                    let mut v = crate::entitlement::EntitlementView::unknown();
                    v.known = true;
                    v.writes = crate::entitlement::WRITES_REFUSED.to_string();
                    v.detail = "The server refused this write for payment reasons (HTTP 402) in a \
                                shape this client did not recognise. Your existing vaults and \
                                codes are unaffected: reads are never refused."
                        .to_string();
                    v
                });
            DesktopError::PaymentRequired {
                message: format!(
                    "payment required while {what} (HTTP 402): {}\n  -> Still available, always: \
                     reading every vault you hold, generating every code you already have, and \
                     giving another device of THIS account a vault key — including creating or \
                     extending a RECOVERY KIT.",
                    entitlement.detail
                ),
                entitlement: Box::new(entitlement),
            }
        }
        CliError::Server { status, body } => DesktopError::Server {
            status,
            message: format!("the server returned HTTP {status} while {what}: {body}"),
        },
        // ⭐ NOT a generic failure. A changed hybrid key is the key-substitution
        // alarm and must reach the UI as its own thing, with both safety numbers,
        // so a human can decide.
        CliError::PinMismatch {
            device_id,
            pinned_safety_number,
            presented_safety_number,
        } => DesktopError::KeyPinMismatch {
            device_id,
            pinned_safety_number,
            presented_safety_number,
        },
        // ⭐ Also not a generic failure: the WRAP GATE refused because trust in
        // the recipient's key could not be established. Both causes carry the
        // number the server is serving, which is what a human compares.
        e @ (CliError::UnverifiedRecoveryKit { .. } | CliError::SafetyNumberMismatch { .. }) => {
            let detail = e.to_string();
            match e {
                CliError::UnverifiedRecoveryKit {
                    device_id,
                    presented_safety_number,
                }
                | CliError::SafetyNumberMismatch {
                    device_id,
                    presented_safety_number,
                    ..
                } => DesktopError::KeyUnverified {
                    device_id,
                    presented_safety_number,
                    detail,
                },
                _ => unreachable!("matched above"),
            }
        }
        // ⭐ PHASE 60, and also not a generic failure. Neither of these is a 401
        // (the request authenticated), a 403 (nothing was forbidden) or a changed
        // key: the envelope's BYTES prove nothing about who produced them, or
        // nothing says who deposited them. Both are refusals; nothing was opened.
        e @ (CliError::WrongEnvelopeKind { .. } | CliError::UnknownSender(_)) => {
            let wrong_kind = matches!(e, CliError::WrongEnvelopeKind { .. });
            DesktopError::UnauthenticatedEnvelope {
                wrong_kind,
                detail: format!("{e} (while {what})"),
            }
        }
        other => DesktopError::Vault(format!("{other} (while {what})")),
    }
}

// ---------------------------------------------------------------------------
// DeviceConfig
// ---------------------------------------------------------------------------

/// Where this device's server-facing state lives, and which server it talks to.
///
/// The file names deliberately match the `sigil` CLI's defaults, so a state
/// directory written here is the CLI's `$HOME/.sigil` and vice versa.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceConfig {
    server: String,
    state_dir: PathBuf,
}

impl DeviceConfig {
    /// Point at `server`, keeping state in `state_dir` (created `0700` on first
    /// write).
    #[must_use]
    pub fn new(server: impl Into<String>, state_dir: impl Into<PathBuf>) -> Self {
        DeviceConfig {
            server: server.into().trim().to_string(),
            state_dir: state_dir.into(),
        }
    }

    /// Point at `server` with the standard state directory `$HOME/.sigil` — the
    /// SAME directory the `sigil` CLI uses.
    #[must_use]
    pub fn for_server(server: impl Into<String>) -> Self {
        let dir = match std::env::var_os("HOME") {
            Some(home) if !home.is_empty() => PathBuf::from(home).join(STATE_DIR_NAME),
            _ => PathBuf::from(STATE_DIR_NAME),
        };
        Self::new(server, dir)
    }

    /// The configured server base URL.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.server
    }

    /// The state directory.
    #[must_use]
    pub fn state_dir(&self) -> &Path {
        &self.state_dir
    }

    /// Path of the Ed25519 device identity file (`0600`).
    #[must_use]
    pub fn identity_path(&self) -> PathBuf {
        self.state_dir.join(DEVICE_IDENTITY_FILE)
    }

    /// Path of the SECRET hybrid identity file (`0600`).
    #[must_use]
    pub fn hybrid_secret_path(&self) -> PathBuf {
        self.state_dir.join(HYBRID_SECRET_FILE)
    }

    /// Path of the shareable PUBLIC hybrid identity file.
    #[must_use]
    pub fn hybrid_public_path(&self) -> PathBuf {
        self.state_dir.join(HYBRID_PUBLIC_FILE)
    }

    /// Path of the local vault keyring (`0600`).
    #[must_use]
    pub fn keyring_path(&self) -> PathBuf {
        self.state_dir.join(VAULT_KEYRING_FILE)
    }

    /// Path of the local HYBRID-KEY PIN STORE (`0600`) — the record of which
    /// public key this device trusts for each other device.
    ///
    /// It is the same file name the CLI uses in the same state directory, so a
    /// desktop state dir and a `sigil` state dir stay interchangeable: pin a key
    /// in one and the other honours it.
    #[must_use]
    pub fn pins_path(&self) -> PathBuf {
        self.state_dir.join(HYBRID_PIN_FILE)
    }

    // -- identity ---------------------------------------------------------

    /// Load the device identity, or `None` when this device has no identity file
    /// yet. The seed inside is SECRET and is never returned to a UI.
    ///
    /// # Errors
    /// - [`DesktopError::Vault`] if the file exists but is malformed.
    pub fn identity(&self) -> Result<Option<DeviceIdentity>> {
        let path = self.identity_path();
        if !path.exists() {
            return Ok(None);
        }
        Ok(Some(load_identity(&path)?))
    }

    /// Load the identity and require that it has been ENROLLED (has a
    /// server-assigned device id), which every contract-v3 route needs.
    ///
    /// # Errors
    /// - [`DesktopError::NotEnrolled`] when there is no identity file, or it has
    ///   no device id yet. This is the "clear error, not a panic" path.
    pub(crate) fn enrolled_identity(&self) -> Result<DeviceIdentity> {
        let path = self.identity_path();
        let Some(identity) = self.identity()? else {
            return Err(DesktopError::NotEnrolled(path));
        };
        if identity.device_id.is_none() {
            return Err(DesktopError::NotEnrolled(path));
        }
        Ok(identity)
    }

    /// ⭐ PHASE 60 — this device AS A SENDER: its enrolled device id bundled with
    /// the hybrid SECRET identity that authenticates every envelope it wraps.
    ///
    /// A vault-key envelope is now sealed under a KEM that mixes in the sender's
    /// long-term X25519 secret, so a wrap needs the secret, not just the
    /// recipient's public key. Bundling id + secret in one value is the CLI's own
    /// rule: a call site cannot pass one device's id with another's secret.
    ///
    /// # Errors
    /// - [`DesktopError::NotEnrolled`] when this device has no device id.
    /// - [`DesktopError::Vault`] when it has no hybrid identity yet (publish one
    ///   first — nothing can be wrapped without it).
    pub(crate) fn sender_identity(&self) -> Result<SenderIdentity> {
        let identity = self.enrolled_identity()?;
        let device_id = identity.device_id.clone().expect("enrolled");
        let secret_path = self.hybrid_secret_path();
        if !secret_path.exists() {
            return Err(DesktopError::Vault(format!(
                "this device has no hybrid identity at {}; publish one first — a vault-key \
                 envelope is AUTHENTICATED with this device's hybrid secret, so there is nothing \
                 to sign the wrap with",
                secret_path.display()
            )));
        }
        let secret = load_hybrid_secret(&secret_path)?;
        SenderIdentity::new(&device_id, secret)
            .map_err(|e| net_error(e, &self.server, "building this device's sender identity"))
    }

    /// The auth to sign op-log requests with: contract v3 when enrolled, the
    /// legacy v2 contract when an identity exists but is not enrolled, and
    /// unsigned when there is no identity at all (the offline / no-auth dev
    /// path, unchanged).
    fn sync_auth(identity: &Option<DeviceIdentity>) -> RequestAuth<'_> {
        match identity {
            Some(id) => id.auth(),
            None => RequestAuth::None,
        }
    }

    // -- enrollment -------------------------------------------------------

    /// ENROLL this device with sigild and persist the assigned device id into a
    /// `0600` identity file inside a `0700` state directory.
    ///
    /// The Ed25519 key pair is generated locally on first enrollment and reused
    /// if an un-enrolled identity file is already present; an ALREADY-enrolled
    /// file is never silently overwritten (that would destroy this device's only
    /// credential).
    ///
    /// `token` is a single-use BEARER SECRET: it is handed straight to
    /// [`enroll_device`], never stored, never logged, and never returned.
    ///
    /// Returns the assigned device id (opaque, not secret).
    ///
    /// # Errors
    /// - [`DesktopError::AlreadyEnrolled`] if this device already has a device id.
    /// - [`DesktopError::Unauthenticated`] on a bad/spent token or failed proof.
    /// - [`DesktopError::NotEnabled`] when the server's device model is off.
    /// - [`DesktopError::Unreachable`] when the server cannot be reached.
    pub fn enroll(&self, token: &str, label: &str) -> Result<String> {
        if token.trim().is_empty() {
            return Err(DesktopError::Vault(
                "an enrollment token is required; ask the operator for one".to_string(),
            ));
        }
        let path = self.identity_path();

        // Reuse an un-enrolled key file; refuse to clobber an enrolled one.
        let key_file = if path.exists() {
            let existing = load_key_file(&path)?;
            if let Some(id) = existing.device_id.as_ref().filter(|d| !d.is_empty()) {
                return Err(DesktopError::AlreadyEnrolled(id.clone()));
            }
            existing
        } else {
            generate_key()?
        };
        let identity = key_file.decode()?;

        let device = enroll_device(
            &self.server,
            token.trim(),
            label,
            &identity.public_key,
            &identity.seed,
        )
        .map_err(|e| net_error(e, &self.server, "enrolling this device"))?;

        ensure_state_dir(&self.state_dir)?;
        let mut stored = key_file;
        stored.device_id = Some(device.device_id.clone());
        save_key(&path, &stored)?;
        Ok(device.device_id)
    }

    /// PUBLISH this device's hybrid PUBLIC key so other devices can wrap a vault
    /// key to it, creating the hybrid identity on first use.
    ///
    /// Only the public half is ever sent; the secret identity is written `0600`
    /// and never leaves the machine. An existing secret is never regenerated —
    /// that would orphan every envelope already addressed to this device.
    ///
    /// Returns the X25519 public key's fingerprint (never the key).
    ///
    /// # Errors
    /// - [`DesktopError::NotEnrolled`] when this device has no device id.
    /// - [`DesktopError::Forbidden`] when publishing into another device's slot.
    /// - [`DesktopError::Unreachable`] / [`DesktopError::NotEnabled`] as above.
    pub fn publish_hybrid(&self) -> Result<String> {
        let identity = self.enrolled_identity()?;
        let device_id = identity.device_id.clone().expect("enrolled");
        let secret_path = self.hybrid_secret_path();
        let public_path = self.hybrid_public_path();

        let public = if secret_path.exists() {
            if !public_path.exists() {
                return Err(DesktopError::Vault(format!(
                    "the hybrid secret {} exists but its public half {} is missing; restore it \
                     rather than regenerating (a new hybrid identity would orphan every envelope \
                     already addressed to this device)",
                    secret_path.display(),
                    public_path.display()
                )));
            }
            load_hybrid_public(&public_path)?
        } else {
            ensure_state_dir(&self.state_dir)?;
            let (secret, public) = generate_hybrid_identity()?;
            save_hybrid_secret(&secret_path, &secret)?;
            save_hybrid_public(&public_path, &public)?;
            public
        };

        publish_hybrid_key(&self.server, &device_id, &public, &identity.auth()).map_err(|e| {
            net_error(
                e,
                &self.server,
                "publishing this device's hybrid public key",
            )
        })?;

        Ok(vault_key_fingerprint(&public.decode()?.x25519_public_key))
    }

    // -- sync -------------------------------------------------------------

    /// PUSH an OPAQUE sealed container to the op-log, contract-v3 signed when
    /// this device is enrolled. The server never sees anything but ciphertext.
    ///
    /// Returns the sequence number the server assigned.
    ///
    /// # Errors
    /// - [`DesktopError::Unreachable`] / [`DesktopError::Unauthenticated`] /
    ///   [`DesktopError::Forbidden`] / [`DesktopError::NotEnabled`].
    pub fn push_vault(&self, vault_id: &str, container: &[u8]) -> Result<u64> {
        let identity = self.identity()?;
        let auth = Self::sync_auth(&identity);
        push_op_auth(&self.server, vault_id, container, &auth)
            .map_err(|e| net_error(e, &self.server, "pushing the sealed vault"))
    }

    /// [`DeviceConfig::push_vault`] over a sealed container file's bytes.
    ///
    /// # Errors
    /// - [`DesktopError::Io`] if the file cannot be read, plus the push errors.
    pub fn push_vault_file(&self, vault_id: &str, path: &Path) -> Result<u64> {
        let bytes = std::fs::read(path)
            .map_err(|e| DesktopError::Io(format!("could not read {}: {e}", path.display())))?;
        self.push_vault(vault_id, &bytes)
    }

    /// PULL the LATEST sealed container for `vault_id` (ops with `seq > since`),
    /// or `Ok(None)` when there is nothing new.
    ///
    /// Each op is a whole vault snapshot, so only the highest sequence matters.
    ///
    /// # Errors
    /// Same as [`DeviceConfig::push_vault`].
    pub fn pull_vault(&self, vault_id: &str, since: u64) -> Result<Option<PulledVault>> {
        let identity = self.identity()?;
        let auth = Self::sync_auth(&identity);
        let ops = pull_ops_auth(&self.server, vault_id, since, &auth)
            .map_err(|e| net_error(e, &self.server, "pulling the sealed vault"))?;
        Ok(ops
            .into_iter()
            .max_by_key(|op| op.seq)
            .map(|op| PulledVault {
                seq: op.seq,
                container: op.blob,
            }))
    }

    // -- sharing ----------------------------------------------------------

    /// The vault key this device holds for `vault_id`, if any. SECRET — this is
    /// for opening a vault, never for display.
    ///
    /// # Errors
    /// - [`DesktopError::Vault`] if the keyring is malformed.
    pub fn vault_key(&self, vault_id: &str) -> Result<Option<[u8; VAULT_KEY_LEN]>> {
        Ok(keyring_get(&self.keyring_path(), vault_id)?)
    }

    /// SHARE a vault with another enrolled device: fetch that device's published
    /// hybrid public key, WRAP this vault's key to it with fresh ephemeral
    /// entropy, deposit the OPAQUE envelope, and GRANT access through the same
    /// authorization API the CLI uses — so keys and permissions never drift.
    ///
    /// `permission` is `"read"` or `"write"`. The vault key never leaves this
    /// machine unwrapped and is never printed; the returned fingerprint is what
    /// the two devices compare.
    ///
    /// # Errors
    /// - [`DesktopError::NotEnrolled`] when this device has no device id.
    /// - [`DesktopError::NotShared`] when this vault is still password-sealed
    ///   (convert it first — the human password is NEVER shared).
    /// - [`DesktopError::MissingOnServer`] when the recipient has published no
    ///   hybrid key, [`DesktopError::Forbidden`] when this device may not write.
    pub fn share_vault(
        &self,
        vault_id: &str,
        to_device: &str,
        permission: &str,
        expected_safety_number: Option<&str>,
    ) -> Result<ShareOutcome> {
        let identity = self.enrolled_identity()?;
        let auth = identity.auth();

        let key = self
            .vault_key(vault_id)?
            .ok_or_else(|| DesktopError::NotShared(vault_id.to_string()))?;

        // 1) ⭐ THE WRAP GATE (sigil_cli::verify_recipient_for_wrap). It resolves
        //    the recipient's PUBLIC hybrid key AND settles trust in it in one
        //    call. A changed key (KeyPinMismatch), a wrong safety number, or an
        //    unpinned RECOVERY KIT all stop HERE: nothing is wrapped, nothing is
        //    uploaded, and the pin store is not mutated. Same gate the CLI uses —
        //    there is no second implementation (ADR 0037).
        let recipient = verify_recipient_for_wrap(
            &self.server,
            to_device,
            &auth,
            &self.pins_path(),
            expected_safety_number,
            false,
        )
        .map_err(|e| {
            net_error(
                e,
                &self.server,
                "verifying the recipient's hybrid public key",
            )
        })?;
        let safety_number = recipient.safety_number().to_string();
        let needs_check = recipient.trust().needs_out_of_band_check();

        // 2-4) WRAP -> grant -> deposit, through the library's single path. It
        //      takes the VerifiedRecipient produced above and has no other way in.
        //      Phase 60: the wrap is AUTHENTICATED as this device (hence
        //      `sender`) and BOUND to (vault, recipient, sender), and the grant
        //      now runs BEFORE the deposit so a refused share leaves no envelope.
        let sender = self.sender_identity()?;
        share_vault_to_known_key(
            &self.server,
            vault_id,
            &recipient,
            permission,
            &key,
            &auth,
            &sender,
        )
        .map_err(|e| net_error(e, &self.server, "sharing the vault (wrap, grant, deposit)"))?;

        Ok(ShareOutcome {
            fingerprint: vault_key_fingerprint(&key),
            safety_number,
            trust: recipient.trust().label().to_string(),
            needs_out_of_band_check: needs_check,
        })
    }

    // -- Phase 50: key verification -------------------------------------

    /// This device's OWN safety number — the digits a user reads aloud so
    /// someone else can verify this device's hybrid public key BEFORE sharing to
    /// it for the first time.
    ///
    /// Purely LOCAL: it reads the published half of this device's hybrid identity
    /// off disk and opens no socket, so it works offline and cannot be influenced
    /// by a server.
    ///
    /// # Errors
    /// - [`DesktopError::NotEnrolled`] when this device has no device id.
    /// - [`DesktopError::Vault`] when it has no hybrid identity yet (publish one).
    pub fn my_safety_number(&self) -> Result<String> {
        let identity = self.enrolled_identity()?;
        let device_id = identity.device_id.clone().expect("enrolled");
        let public = load_hybrid_public(&self.hybrid_public_path()).map_err(|_| {
            DesktopError::Vault(
                "this device has no hybrid identity yet — publish one first".to_string(),
            )
        })?;
        Ok(hybrid_safety_number(&device_id, &public)?)
    }

    /// The safety number of ANOTHER device's published hybrid key, plus how it
    /// compares to what this device has PINNED.
    ///
    /// Deliberately READ-ONLY: it never pins and never re-pins, so a user can
    /// inspect a key (and spot a mismatch) without changing any trust state.
    /// Returns `(safety number, pin state)` where the pin state is
    /// `"not pinned yet"`, `"matches the pinned key"` or `"DIFFERS from the
    /// pinned key"`.
    ///
    /// # Errors
    /// - [`DesktopError::MissingOnServer`] when that device published no key.
    pub fn peer_safety_number(&self, device_id: &str) -> Result<(String, String)> {
        let identity = self.enrolled_identity()?;
        let auth = identity.auth();
        let public = fetch_hybrid_key(&self.server, device_id, &auth)
            .map_err(|e| net_error(e, &self.server, "fetching that device's hybrid public key"))?;
        let presented = hybrid_safety_number(device_id, &public)?;
        let store = load_pins(&self.pins_path())?;
        let state = match store.pins.get(device_id) {
            None => "not pinned yet".to_string(),
            Some(p) if p.safety_number == presented => "matches the pinned key".to_string(),
            Some(p) => format!("DIFFERS from the pinned key ({})", p.safety_number),
        };
        Ok((presented, state))
    }

    /// The ORDER-INDEPENDENT pairwise safety number for this device and
    /// `device_id`: both people see the SAME digits, whoever asks.
    ///
    /// # Errors
    /// - As [`Self::peer_safety_number`], plus [`DesktopError::Vault`] when this
    ///   device has no hybrid identity.
    pub fn pairwise_safety_number(&self, device_id: &str) -> Result<String> {
        let identity = self.enrolled_identity()?;
        let my_id = identity.device_id.clone().expect("enrolled");
        let auth = identity.auth();
        let mine = load_hybrid_public(&self.hybrid_public_path()).map_err(|_| {
            DesktopError::Vault(
                "this device has no hybrid identity yet — publish one first".to_string(),
            )
        })?;
        let theirs = fetch_hybrid_key(&self.server, device_id, &auth)
            .map_err(|e| net_error(e, &self.server, "fetching that device's hybrid public key"))?;
        Ok(pairwise_safety_number(&my_id, &mine, device_id, &theirs)?)
    }

    /// The hybrid public keys this device TRUSTS, newest pin state included.
    /// PUBLIC material only — safe to render.
    ///
    /// # Errors
    /// - [`DesktopError::Vault`] on a malformed pin store.
    pub fn pins(&self) -> Result<Vec<HybridKeyPin>> {
        Ok(load_pins(&self.pins_path())?.pins.into_values().collect())
    }

    /// ⚠️ DELIBERATELY accept a CHANGED hybrid key for a device.
    ///
    /// This is the ONLY thing that ever replaces a pin. It must be driven by an
    /// explicit user action AFTER they have compared the new safety number with
    /// the device's owner over a channel the server does not control — a changed
    /// key is either a legitimate re-enrolment or a key-substitution attack, and
    /// nothing on this machine can tell those apart.
    ///
    /// `expected` is the safety number the user says they verified; when
    /// supplied it MUST match the key the server is presenting right now, so a
    /// stale or mistyped value refuses instead of blessing the wrong key.
    ///
    /// Returns `(previous safety number, new safety number)`.
    ///
    /// # Errors
    /// - [`DesktopError::Vault`] when `expected` does not match what is served.
    pub fn repin_device(
        &self,
        device_id: &str,
        expected: Option<&str>,
    ) -> Result<(Option<String>, String)> {
        let identity = self.enrolled_identity()?;
        let auth = identity.auth();
        let public = fetch_hybrid_key(&self.server, device_id, &auth)
            .map_err(|e| net_error(e, &self.server, "fetching that device's hybrid public key"))?;
        let presented = hybrid_safety_number(device_id, &public)?;
        if let Some(claimed) = expected {
            let norm = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ");
            if norm(claimed) != norm(&presented) {
                return Err(DesktopError::Vault(format!(
                    "refusing to re-pin {device_id}: the safety number you verified ({claimed}) \
                     does not match the key this server is presenting ({presented}). Do NOT \
                     re-pin — either the value is stale, or the key changed again."
                )));
            }
        }
        Ok(repin_hybrid_key(&self.pins_path(), device_id, &public)?)
    }

    /// ROTATE a shared vault's key and RE-WRAP it to exactly `recipients`,
    /// deleting every other device's envelope.
    ///
    /// The remediation revocation was missing. Every recipient's key goes through
    /// the WRAP GATE first, so a substituted key — or an unverified RECOVERY KIT
    /// recipient — aborts the whole rotation before the vault file or the server
    /// is touched. `safety_numbers` is `(device id, printed digits)` for any
    /// recipient the user can verify out of band, and is REQUIRED for a
    /// first-sight recovery kit.
    ///
    /// ⚠️ It protects FUTURE content ONLY. A device that already unwrapped the
    /// previous key keeps that key and whatever it had already copied.
    ///
    /// ⭐ **The Phase 54 drop guard applies here too, by the same reuse rule.**
    /// A device that currently holds an envelope and is named by neither
    /// `recipients` nor `drop` ABORTS the rotation, having touched nothing —
    /// because rotating a vault while silently forgetting a RECOVERY KIT ends
    /// recoverability while everything else keeps working.
    ///
    /// Returns `(old fingerprint, new fingerprint, re-wrapped device ids,
    /// removed device ids)` — fingerprints, never keys.
    ///
    /// # Errors
    /// - [`DesktopError::KeyPinMismatch`] if ANY recipient's key changed.
    /// - [`DesktopError::Net`] naming each unaccounted-for holder.
    /// - [`DesktopError::NotShared`] when the vault has no key in the keyring.
    pub fn rotate_vault(
        &self,
        vault_id: &str,
        vault_path: &Path,
        recipients: &[String],
        drop: &[String],
        safety_numbers: &[(String, String)],
    ) -> Result<(String, String, Vec<String>, Vec<String>)> {
        let identity = self.enrolled_identity()?;
        let auth = identity.auth();
        // Phase 60: every re-wrap is AUTHENTICATED as this device.
        let sender = self.sender_identity()?;
        let report = rotate_vault_key(
            &self.server,
            vault_id,
            vault_path,
            &self.keyring_path(),
            &self.pins_path(),
            recipients,
            drop,
            safety_numbers,
            &auth,
            Argon2Params::RECOMMENDED,
            &sender,
        )
        .map_err(|e| net_error(e, &self.server, "rotating the vault key"))?;
        Ok((
            report.old_key_fingerprint,
            report.new_key_fingerprint,
            report
                .rewrapped
                .into_iter()
                .map(|(d, _): (String, RecipientTrust)| d)
                .collect(),
            report.removed,
        ))
    }

    /// ⭐ ACCEPT a vault shared TO this device, and **where the forgery used to
    /// land** (Phase 60).
    ///
    /// This used to collect the envelope and unwrap ANYTHING that decrypted to 32
    /// bytes, from anybody: it fetched no hybrid key, so ADR 0038's pin store was
    /// never consulted on the receiving side, and an envelope minted from this
    /// device's own PUBLISHED public key installed an attacker-chosen vault key.
    ///
    /// It now delegates the whole receiving path to the CLI library's
    /// `accept_vault_key`, which (1) works out WHICH device deposited the
    /// envelope — named here, else from this device's self-only envelope index,
    /// and a REFUSAL if neither says — (2) pin-checks that device's hybrid key,
    /// (3) unwraps AUTHENTICATED and bound to (vault, this device, that sender),
    /// (4) proves the key actually opens the vault before writing it, and (5)
    /// refuses to silently replace a DIFFERENT key already in the keyring.
    ///
    /// ⭐ There is no desktop implementation of any of that (ADR 0037) — the
    /// reason the logic lives in the library rather than in `cli/src/main.rs`.
    ///
    /// `sender_device_id` names the depositing device explicitly;
    /// `expected_safety_number` is the digits read out of band, which is what
    /// closes the first-contact window pinning cannot. `replace` must be set to
    /// overwrite a different existing key.
    ///
    /// Returns the key's fingerprint — never the key.
    ///
    /// # Errors
    /// - [`DesktopError::NotEnrolled`] when this device has no device id.
    /// - [`DesktopError::MissingOnServer`] when nothing has been shared here.
    /// - [`DesktopError::Forbidden`] when this device may not read the vault.
    /// - [`DesktopError::KeyPinMismatch`] when the sender's key CHANGED.
    /// - [`DesktopError::Vault`] when the envelope is not an AUTHENTICATED one,
    ///   does not open, or would replace a different key without `replace`; no
    ///   plaintext is leaked in any of those cases.
    pub fn accept_vault(
        &self,
        vault_id: &str,
        sender_device_id: Option<&str>,
        expected_safety_number: Option<&str>,
        replace: bool,
    ) -> Result<String> {
        let identity = self.enrolled_identity()?;
        let device_id = identity.device_id.clone().expect("enrolled");
        let auth = identity.auth();

        let secret_path = self.hybrid_secret_path();
        if !secret_path.exists() {
            return Err(DesktopError::Vault(format!(
                "this device has no hybrid identity at {}; publish one before accepting a share \
                 (only the hybrid secret can open an envelope addressed here)",
                secret_path.display()
            )));
        }
        let secret = load_hybrid_secret(&secret_path)?;

        let report = accept_vault_key(
            &self.server,
            vault_id,
            &device_id,
            &secret,
            &self.keyring_path(),
            &self.pins_path(),
            &auth,
            sender_device_id,
            expected_safety_number,
            replace,
        )
        .map_err(|e| net_error(e, &self.server, "accepting the shared vault key"))?;
        Ok(report.key_fingerprint)
    }

    // -- accounts (Phase 52) ----------------------------------------------
    //
    // An ACCOUNT groups one person's own devices. It is what a subscription and
    // a vault's OWNERSHIP belong to, so paying on one device entitles the rest
    // and revoking the device that first wrote a vault no longer orphans it.
    //
    // SAME RULE AS EVERYWHERE ELSE IN THIS FILE: no protocol is implemented
    // here. These four methods call the `sigil-cli` LIBRARY functions the CLI
    // itself calls, so a desktop request and a `sigil account …` request are the
    // same bytes, and there is no fourth copy of anything canonical.
    //
    // NO CALL NAMES AN ACCOUNT — the server reads it off the device row of the
    // signature it just verified. That is why none of these takes an account id.

    /// READ this device's account: which account it is in, and who else is in it.
    ///
    /// Requires an ENROLLED identity: the account is derived from the signature,
    /// so an un-enrolled key cannot name one.
    ///
    /// # Errors
    /// - [`DesktopError::NotEnrolled`] when this device has no device id.
    /// - [`DesktopError::Unauthenticated`] (401) when revoked or refused.
    /// - [`DesktopError::NotEnabled`] (501) when the server's account model is off.
    /// - [`DesktopError::Unreachable`] when the server cannot be reached.
    pub fn account(&self) -> Result<AccountView> {
        let identity = self.enrolled_identity()?;
        let me = identity.device_id.clone().unwrap_or_default();
        let info = get_account(&self.server, &identity.auth())
            .map_err(|e| net_error(e, &self.server, "reading this device's account"))?;
        Ok(AccountView {
            account_id: info.account_id,
            created_at: info.created_at,
            device_count: info.device_count,
            revoked_device_count: info.revoked_device_count,
            device_limit: info.device_limit,
            members: info
                .devices
                .into_iter()
                .map(|d| AccountMember {
                    is_this_device: d.device_id == me,
                    device_id: d.device_id,
                    label: d.label,
                    status: d.status,
                    created_at: d.created_at,
                    revoked_at: d.revoked_at.unwrap_or_default(),
                })
                .collect(),
        })
    }

    /// READ this account's SUBSCRIPTION and turn it into an
    /// [`EntitlementView`](crate::entitlement::EntitlementView).
    ///
    /// ⭐ THE WARNING CHANNEL, and the ONLY signal that can say **grace** — that
    /// this account has lapsed, that writes still work, and when they will stop.
    /// Without it a customer learns about a lapse the first time a write is
    /// refused, which is the surprise ADR 0043 exists to prevent. The refusal
    /// body (`402`) can only ever say "already too late".
    ///
    /// It reuses the `sigil-cli` library's signed transport like everything else
    /// here, so there is still NO second HTTP client and NO second request-signing
    /// path under `desktop/` (ADR 0037).
    ///
    /// A server with enforcement OFF — the default — sends no `entitlement`
    /// block, and that is reported as
    /// [`EntitlementView::not_enforced`](crate::entitlement::EntitlementView::not_enforced),
    /// which needs no attention and must render as nothing.
    ///
    /// This route is never gated by entitlement, and it names no account: the
    /// subject is the account behind the verified signature (ADR 0040).
    ///
    /// # Errors
    /// - [`DesktopError::NotEnrolled`] when this device has no device id.
    /// - [`DesktopError::Unauthenticated`] (401), [`DesktopError::Forbidden`] (403).
    /// - [`DesktopError::NotEnabled`] (501) when this server has billing off.
    /// - [`DesktopError::Unreachable`] when the server cannot be reached.
    pub fn subscription(&self) -> Result<crate::entitlement::EntitlementView> {
        let identity = self.enrolled_identity()?;
        let body = fetch_subscription(&self.server, &identity.auth())
            .map_err(|e| net_error(e, &self.server, "reading this account's subscription"))?;
        Ok(
            crate::entitlement::EntitlementView::from_subscription_block(&body).unwrap_or_else(
                || {
                    let status = serde_json::from_str::<serde_json::Value>(&body)
                        .ok()
                        .and_then(|v| {
                            v.get("status")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_string)
                        })
                        .unwrap_or_default();
                    crate::entitlement::EntitlementView::not_enforced(&status)
                },
            ),
        )
    }

    /// MINT a single-use invite letting ONE more device join this account.
    ///
    /// ⚠️ [`MintedInvite::invite`] is a BEARER SECRET returned exactly once. It is
    /// the ONE secret this module deliberately hands back to a UI, because the
    /// human has to carry it to the other device — the same way an enrollment
    /// token travels IN. Show it once, never write it to disk, never log it. The
    /// joining device redeems it as its ordinary enrollment token
    /// ([`DeviceConfig::enroll`], unchanged).
    ///
    /// `ttl_seconds` may only SHORTEN the invite's life; the server clamps it.
    ///
    /// # Errors
    /// - [`DesktopError::NotEnrolled`], [`DesktopError::Unauthenticated`],
    ///   [`DesktopError::NotEnabled`], [`DesktopError::Unreachable`]; and
    ///   [`DesktopError::Server`] with status 409 when the account is at its
    ///   device limit or already has the maximum number of open invites.
    pub fn create_invite(&self, ttl_seconds: Option<u64>) -> Result<MintedInvite> {
        let identity = self.enrolled_identity()?;
        // No pinning from the desktop yet: it needs the invitee's public key,
        // which this UI has no way to obtain. An UNPINNED invite is a bearer
        // secret for its whole TTL — that limit is real and is not papered over.
        let inv = create_account_invite(&self.server, &identity.auth(), ttl_seconds, None)
            .map_err(|e| net_error(e, &self.server, "minting an account invite"))?;
        Ok(MintedInvite {
            invite_id: inv.invite_id,
            invite: inv.invite,
            account_id: inv.account_id,
            expires_at: inv.expires_at,
            pinned: inv.pinned,
        })
    }

    /// LIST this account's OPEN invites. METADATA ONLY — a minted invite secret
    /// can never be recovered, from the server or from here.
    ///
    /// # Errors
    /// As [`DeviceConfig::account`].
    pub fn list_invites(&self) -> Result<Vec<OpenInvite>> {
        let identity = self.enrolled_identity()?;
        let invites = list_account_invites(&self.server, &identity.auth())
            .map_err(|e| net_error(e, &self.server, "listing account invites"))?;
        Ok(invites
            .into_iter()
            .map(|i| OpenInvite {
                invite_id: i.invite_id,
                created_by_device_id: i.created_by_device_id,
                created_at: i.created_at,
                expires_at: i.expires_at,
                pinned: i.pinned,
            })
            .collect())
    }

    /// REVOKE an unredeemed invite by its PUBLIC handle.
    ///
    /// A handle belonging to ANOTHER account and one that never existed are
    /// deliberately indistinguishable — both surface as
    /// [`DesktopError::MissingOnServer`] — so this cannot enumerate invites.
    ///
    /// # Errors
    /// As [`DeviceConfig::account`], plus [`DesktopError::MissingOnServer`] (404).
    pub fn revoke_invite(&self, invite_id: &str) -> Result<()> {
        let identity = self.enrolled_identity()?;
        revoke_account_invite(&self.server, &identity.auth(), invite_id.trim())
            .map_err(|e| net_error(e, &self.server, "revoking an account invite"))
    }

    // -- status -----------------------------------------------------------

    /// Everything a UI shows about this device, read from LOCAL DISK ONLY.
    /// Never touches the network, so it works with no server configured and
    /// cannot fail because one is down. Fingerprints only — never a key.
    ///
    /// # Errors
    /// - [`DesktopError::Vault`] if a local state file is malformed.
    pub fn status(&self) -> Result<DeviceStatus> {
        let identity = self.identity()?;
        let device_fingerprint = identity
            .as_ref()
            .map(|i| vault_key_fingerprint(&i.public_key));
        let device_id = identity.as_ref().and_then(|i| i.device_id.clone());

        let public_path = self.hybrid_public_path();
        let hybrid_identity_present = self.hybrid_secret_path().exists();
        let hybrid_fingerprint = if hybrid_identity_present && public_path.exists() {
            let public = load_hybrid_public(&public_path)?;
            Some(vault_key_fingerprint(&public.decode()?.x25519_public_key))
        } else {
            None
        };

        let keyring_path = self.keyring_path();
        let keyring: VaultKeyring = load_keyring(&keyring_path)?;
        let mut vaults = Vec::with_capacity(keyring.keys.len());
        for vault_id in keyring.keys.keys() {
            // Re-read through keyring_get so a malformed entry is reported
            // rather than silently rendered.
            let key_fingerprint = match keyring_get(&keyring_path, vault_id)? {
                Some(key) => vault_key_fingerprint(&key),
                None => "<unreadable>".to_string(),
            };
            vaults.push(VaultKeyInfo {
                vault_id: vault_id.clone(),
                key_fingerprint,
            });
        }

        Ok(DeviceStatus {
            server: self.server.clone(),
            state_dir: self.state_dir.clone(),
            identity_path: self.identity_path(),
            enrolled: device_id.is_some(),
            device_id,
            device_fingerprint,
            hybrid_identity_present,
            hybrid_fingerprint,
            keyring_path,
            vaults,
        })
    }

    /// Best-effort probe of the configured server: is it up, and does it hold
    /// this device's published hybrid public key?
    ///
    /// A server that is down or has the routes disabled is reported, never
    /// returned as an error — offline is a normal state for this app.
    ///
    /// # Errors
    /// - [`DesktopError::NotEnrolled`] when this device has no device id (there
    ///   is nothing to probe with).
    pub fn check_server(&self) -> Result<ServerCheck> {
        let identity = self.enrolled_identity()?;
        let device_id = identity.device_id.clone().expect("enrolled");
        match fetch_hybrid_key(&self.server, &device_id, &identity.auth()) {
            Ok(_) => Ok(ServerCheck {
                reachable: true,
                hybrid_published: true,
                detail: format!(
                    "{} is reachable and holds this device's hybrid public key",
                    self.server
                ),
            }),
            Err(CliError::Server { status: 404, .. }) => Ok(ServerCheck {
                reachable: true,
                hybrid_published: false,
                detail: format!(
                    "{} is reachable but has no hybrid public key for this device yet",
                    self.server
                ),
            }),
            Err(e) => {
                let mapped = net_error(e, &self.server, "checking the server");
                Ok(ServerCheck {
                    reachable: !matches!(mapped, DesktopError::Unreachable(_)),
                    hybrid_published: false,
                    detail: mapped.to_string(),
                })
            }
        }
    }
}

// ---------------------------------------------------------------------------
// VaultSession: the password -> vault-key transition, and opening a shared vault
// ---------------------------------------------------------------------------

impl VaultSession {
    /// Convert this PASSWORD-sealed vault into a SHARED vault: draw a fresh
    /// random 32-byte vault key, re-seal the SAME file under it, and record the
    /// key in this device's `0600` keyring.
    ///
    /// This is the one-way door between the two key models and it is explicit —
    /// an untouched password vault keeps working exactly as before. Afterwards
    /// the session holds the vault KEY in place of the password, so subsequent
    /// saves and pushes are already the shared ones. **The human password is
    /// never shared, wrapped or uploaded.**
    ///
    /// Returns the key's fingerprint — never the key.
    ///
    /// # Errors
    /// - [`DesktopError::Vault`] on an RNG, seal or keyring failure.
    /// - [`DesktopError::Io`] on a write failure.
    pub fn convert_to_shared(&mut self, config: &DeviceConfig, vault_id: &str) -> Result<String> {
        let key = generate_vault_key()?;
        // Swap the sealing secret first, then save: `save` re-seals under
        // `self.password`, so the file is rewritten under the new vault key.
        let mut old = std::mem::replace(&mut self.password, key.to_vec());
        // Best-effort scrub of the password we just stopped using.
        for b in old.iter_mut() {
            *b = 0;
        }
        self.save()?;
        keyring_put(&config.keyring_path(), vault_id, &key)?;
        Ok(vault_key_fingerprint(&key))
    }

    /// Unlock a SHARED vault file with the vault key this device holds for
    /// `vault_id` (the `SIGILcli` container takes arbitrary secret bytes, so a
    /// random key needs no format change).
    ///
    /// # Errors
    /// - [`DesktopError::NotShared`] when this device holds no key for that vault
    ///   (convert it, or accept a share, first).
    /// - [`DesktopError::NotFound`] / [`DesktopError::Vault`] as [`VaultSession::unlock`].
    pub fn unlock_shared(
        path: impl Into<PathBuf>,
        config: &DeviceConfig,
        vault_id: &str,
    ) -> Result<Self> {
        let key = config
            .vault_key(vault_id)?
            .ok_or_else(|| DesktopError::NotShared(vault_id.to_string()))?;
        VaultSession::unlock(path, &key)
    }
}

/// PULL the latest sealed container for `vault_id` and ADOPT it as the local
/// vault at `path`, returning the freshly opened session and the op-log sequence
/// it came from (or `Ok(None)` when the server had nothing newer).
///
/// The container is opened with this device's vault key BEFORE anything is
/// written, so a container this device cannot read — or one the server mangled —
/// can never clobber a good local vault.
///
/// # Errors
/// - [`DesktopError::NotShared`] when this device holds no key for that vault.
/// - The [`DeviceConfig::pull_vault`] errors, plus [`DesktopError::Vault`] when
///   the pulled container does not open under this device's key.
pub fn pull_and_adopt(
    config: &DeviceConfig,
    vault_id: &str,
    path: &Path,
    since: u64,
) -> Result<Option<(VaultSession, u64)>> {
    let key = config
        .vault_key(vault_id)?
        .ok_or_else(|| DesktopError::NotShared(vault_id.to_string()))?;

    let Some(pulled) = config.pull_vault(vault_id, since)? else {
        return Ok(None);
    };

    // Prove it opens under THIS device's key before it touches the disk.
    sigil_cli::open_vault(&key, &pulled.container)?;
    write_private_bytes(path, &pulled.container)?;

    let session = VaultSession::unlock(path, &key)?;
    Ok(Some((session, pulled.seq)))
}

/// Create the state directory `0700` if it is not there yet. It holds the device
/// seed, the hybrid secret and the vault keyring.
fn ensure_state_dir(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    if dir.as_os_str().is_empty() || dir.exists() {
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| DesktopError::Io(format!("could not create {}: {e}", dir.display())))
}

/// Write opaque sealed bytes to `path` with mode `0600` via a temp file +
/// rename, so an interrupted adopt cannot truncate a good vault.
fn write_private_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            ensure_state_dir(parent)?;
        }
    }
    let tmp = path.with_extension("sigil.pull.tmp");
    crate::write_private(&tmp, bytes)?;
    std::fs::rename(&tmp, path).map_err(|e| {
        DesktopError::Io(format!(
            "could not move {} into place at {}: {e}",
            tmp.display(),
            path.display()
        ))
    })?;
    crate::set_mode(path, 0o600)
}

// ---------------------------------------------------------------------------
// Tests — the OFFLINE half. Everything here runs with NO server in existence,
// which is the point: a user who never configures one must be unaffected.
// The full networked proof (a real sigild + the real `sigil` binary, both
// directions, plus the 401/403/501/unreachable negatives) is
// `tests/server_interop.rs`.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sigil_core::Argon2Params;

    const FAST: Argon2Params = Argon2Params {
        m_cost: 8,
        t_cost: 1,
        p_cost: 1,
    };
    const PASSWORD: &[u8] = b"correct horse battery staple";
    const RFC_SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sigil-desktop-net-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    /// The file names must be the CLI's, or a desktop state directory is not the
    /// same device as `sigil --key`.
    #[test]
    fn state_file_names_are_the_cli_defaults() {
        let c = DeviceConfig::new("http://127.0.0.1:1", "/tmp/nowhere");
        assert!(c.identity_path().ends_with("device.key"));
        assert!(c.hybrid_secret_path().ends_with("device.hybrid"));
        assert!(c.hybrid_public_path().ends_with("device.hybrid.pub"));
        assert!(c.keyring_path().ends_with(VAULT_KEYRING_FILE));
        assert_eq!(c.server(), "http://127.0.0.1:1");
    }

    /// `status` is a pure local read: it must succeed with nothing on disk and
    /// never touch the network.
    #[test]
    fn status_with_no_state_is_empty_and_never_fails() {
        let c = DeviceConfig::new("http://127.0.0.1:1", scratch("emptystatus"));
        let s = c.status().expect("status");
        assert!(!s.enrolled);
        assert!(s.device_id.is_none() && s.device_fingerprint.is_none());
        assert!(!s.hybrid_identity_present && s.hybrid_fingerprint.is_none());
        assert!(s.vaults.is_empty());
        assert!(!c.state_dir().exists(), "a read must not create state");
    }

    /// Every contract-v3 operation must refuse CLEARLY before it ever opens a
    /// socket, so an un-enrolled user gets a message and not a hang or a panic.
    #[test]
    fn v3_operations_without_an_identity_report_not_enrolled() {
        let c = DeviceConfig::new("http://127.0.0.1:1", scratch("notenrolled"));
        for e in [
            c.publish_hybrid().unwrap_err(),
            c.share_vault("v", "dev_x", "read", None).unwrap_err(),
            c.accept_vault("v", None, None, false).unwrap_err(),
            c.check_server().unwrap_err(),
        ] {
            assert!(matches!(e, DesktopError::NotEnrolled(_)), "got {e:?}");
            assert!(e.to_string().contains("not enrolled"), "{e}");
        }
    }

    /// The password -> vault-key transition, entirely offline: the vault is
    /// re-sealed under a random 32-byte key, the key lands in a 0600 keyring,
    /// and the password no longer opens the file. The password is never stored.
    #[test]
    fn convert_to_shared_swaps_the_secret_and_records_a_0600_keyring() {
        let dir = scratch("convert");
        std::fs::create_dir_all(&dir).expect("dir");
        let config = DeviceConfig::new("http://127.0.0.1:1", &dir);
        let path = dir.join("totp-vault.sigil");

        let mut s = VaultSession::create(&path, PASSWORD)
            .expect("create")
            .with_params(FAST);
        s.add_secret_base32("a", None, RFC_SEED_B32, "sha1", Some(8), Some(30))
            .expect("add");

        let fp = s.convert_to_shared(&config, "shared").expect("convert");
        assert_eq!(fp.len(), 16, "a fingerprint, never the key");
        assert_eq!(mode_of(&config.keyring_path()), 0o600);

        // The session kept working under the new secret.
        assert_eq!(s.entries_at(59).expect("codes")[0].code, "94287082");

        // The password is now the WRONG secret; the vault key is the right one.
        assert!(VaultSession::unlock(&path, PASSWORD).is_err());
        let reopened =
            VaultSession::unlock_shared(&path, &config, "shared").expect("unlock with the key");
        assert_eq!(reopened.entries_at(59).expect("codes")[0].code, "94287082");

        // ...and the status now lists it by fingerprint only.
        let status = config.status().expect("status");
        assert_eq!(status.vaults.len(), 1);
        assert_eq!(status.vaults[0].vault_id, "shared");
        assert_eq!(status.vaults[0].key_fingerprint, fp);

        // A vault this device holds no key for is a clear NotShared, not a panic.
        assert!(matches!(
            VaultSession::unlock_shared(&path, &config, "other"),
            Err(DesktopError::NotShared(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
