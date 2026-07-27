//! Sigil Desktop — the **native** client column.
//!
//! # STATUS: PRE-AUDIT — UNAUDITED — DO NOT STORE REAL 2FA SECRETS
//!
//! A Tauri v2 shell around [`sigil_desktop_core`]. Everything interesting — the
//! sealed `SIGILcli` vault, the RFC 4226/6238 code generation, import/export —
//! lives in that headless crate and is covered by its tests, including the
//! CLI-interop proof. This file is deliberately thin: a window, a
//! `Mutex<Option<VaultSession>>`, and one `#[tauri::command]` per user action.
//!
//! Unlike the webapp and the browser extension, which run libsigil compiled to
//! WebAssembly, this binary links `sigil-core` as a **native** Rust dependency.
//! There is no wasm in the loop.
//!
//! ## Trust boundary
//!
//! The frontend (`../ui`, framework-free HTML/CSS/JS) holds **no** key material
//! and does **no** crypto. The password crosses the IPC once at unlock and then
//! lives only in the Rust-side `VaultSession`; codes arrive already computed. The
//! capability file grants `core:default` and nothing else — no fs/shell/http
//! plugin — so the webview cannot touch the disk except through the commands
//! below.
//!
//! ## Sync and sharing
//!
//! The server-facing commands are the same shape: the webview names a server, a
//! vault id or a device id, and every byte on the wire is produced by
//! `sigil_desktop_core::net` (which in turn drives the `sigil-cli` library). No
//! seed, vault key or enrollment token ever crosses the IPC in either direction
//! — the enrollment token goes native-ward once and is never stored, and only
//! SHA-256 FINGERPRINTS come back. With no server configured none of it runs and
//! the offline app is untouched.

// Keep the console window off on Windows release builds (harmless elsewhere).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use std::sync::Mutex;

use serde::Serialize;
use sigil_desktop_core::{
    default_vault_path, now_unix, pull_and_adopt, DesktopError, DeviceConfig, VaultSession,
    BANNER_BODY, BANNER_TITLE, EXPORT_WARNING,
};
use tauri::{Manager, State};

/// The unlocked session (`None` when locked; `VaultSession` zeroes its password
/// on drop, so `lock()` is just `*guard = None`) plus the OPTIONAL server
/// configuration (`None` until the user names a server — the offline default).
#[derive(Default)]
struct AppState {
    session: Mutex<Option<VaultSession>>,
    sync: Mutex<Option<DeviceConfig>>,
}

/// What the UI shows in its header/lock screen.
#[derive(Serialize)]
struct Status {
    /// Absolute path of the sealed container.
    path: String,
    /// Whether that file exists yet.
    exists: bool,
    /// Whether a password is currently held in memory.
    unlocked: bool,
    /// Number of accounts (0 when locked).
    count: usize,
    /// The loud pre-audit banner headline.
    banner_title: &'static str,
    /// The loud pre-audit banner body.
    banner_body: &'static str,
}

/// One row in the account list. Mirrors `sigil_desktop_core::EntryView`; the raw
/// secret is deliberately never sent to the webview.
#[derive(Serialize)]
struct Row {
    label: String,
    issuer: Option<String>,
    algorithm: String,
    digits: u32,
    period: u32,
    code: String,
    seconds_remaining: u64,
}

/// The result of an import run, as the UI reports it.
#[derive(Serialize)]
struct Imported {
    imported: usize,
    skipped_duplicate: usize,
    skipped_hotp: usize,
    skipped_invalid: usize,
}

/// An export, always paired with the mandatory secrets-in-the-clear warning.
#[derive(Serialize)]
struct Export {
    warning: &'static str,
    lines: Vec<String>,
}

/// Errors cross the IPC as a small STRUCTURED value; they never contain secret
/// material (no password, no seed, no vault key — only ids, fingerprints and
/// safety numbers, all of which are public).
type CmdResult<T> = Result<T, IpcError>;

/// What the webview receives when a command fails.
///
/// `kind` is a coarse, machine-readable tag the UI branches on; `message` is the
/// human text. `key_change` is populated for EXACTLY ONE kind — `"key changed"`
/// — and carries the two safety numbers the user has to compare, because a
/// key-substitution alarm the UI cannot render properly is a control that does
/// not exist.
#[derive(Serialize)]
struct IpcError {
    kind: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_change: Option<KeyChange>,
}

/// The two safety numbers behind a `"key changed"` alarm. PUBLIC material only.
#[derive(Serialize)]
struct KeyChange {
    device_id: String,
    pinned_safety_number: String,
    presented_safety_number: String,
}

impl From<String> for IpcError {
    fn from(message: String) -> Self {
        IpcError {
            kind: "error",
            message,
            key_change: None,
        }
    }
}

/// A plain, untagged error message.
fn msg(m: impl Into<String>) -> IpcError {
    IpcError::from(m.into())
}

/// Render a core error for the UI, TAGGED with what the user can do about it.
///
/// The tag is what lets the webview tell "sign in again" (401) from "ask the
/// owner" (403) from "the server has this switched off" (501) from "you are
/// offline" — all four are genuinely different situations.
fn ipc(e: DesktopError) -> IpcError {
    let kind = match &e {
        DesktopError::Unreachable(_) => "server unreachable",
        DesktopError::Unauthenticated(_) => "unauthenticated",
        DesktopError::Forbidden(_) => "not authorized",
        DesktopError::MissingOnServer(_) => "nothing there",
        DesktopError::NotEnabled(_) => "route disabled",
        DesktopError::NotEnrolled(_) => "not enrolled",
        DesktopError::AlreadyEnrolled(_) => "already enrolled",
        DesktopError::NotShared(_) => "not a shared vault",
        // ⭐ Its own tag: a changed hybrid key is neither an auth failure nor a
        // server error. The UI must present it as the key-substitution alarm.
        DesktopError::KeyPinMismatch { .. } => "key changed",
        DesktopError::Server { .. } => "server error",
        _ => "error",
    };
    // ⭐ The alarm carries STRUCTURE, not just prose: the UI must be able to put
    // the pinned and presented safety numbers side by side and offer a
    // deliberate re-pin. Both numbers are public.
    let key_change = match &e {
        DesktopError::KeyPinMismatch {
            device_id,
            pinned_safety_number,
            presented_safety_number,
        } => Some(KeyChange {
            device_id: device_id.clone(),
            pinned_safety_number: pinned_safety_number.clone(),
            presented_safety_number: presented_safety_number.clone(),
        }),
        _ => None,
    };
    IpcError {
        kind,
        message: format!("{kind}: {e}"),
        key_change,
    }
}

/// Borrow the unlocked session or fail with a UI-friendly message.
fn with_session<T>(
    state: &State<'_, AppState>,
    f: impl FnOnce(&mut VaultSession) -> CmdResult<T>,
) -> CmdResult<T> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault state poisoned".to_string())?;
    let session = guard
        .as_mut()
        .ok_or_else(|| "vault is locked".to_string())?;
    f(session)
}

/// The configured server, or a clear "no server configured" error. Cloned out so
/// no lock is held across a network call.
fn sync_config(state: &State<'_, AppState>) -> CmdResult<DeviceConfig> {
    let guard = state
        .sync
        .lock()
        .map_err(|_| "sync state poisoned".to_string())?;
    guard
        .clone()
        .ok_or_else(|| msg("no sync server configured: set one in the Sync panel first"))
}

/// Build a [`Status`] from whatever the state currently holds.
fn status_of(guard: &Option<VaultSession>) -> Status {
    let path = guard
        .as_ref()
        .map(|s| s.path().to_path_buf())
        .unwrap_or_else(default_vault_path);
    Status {
        exists: path.exists(),
        path: path.display().to_string(),
        unlocked: guard.is_some(),
        count: guard.as_ref().map_or(0, VaultSession::len),
        banner_title: BANNER_TITLE,
        banner_body: BANNER_BODY,
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Current lock/vault status (also the first thing the UI asks for).
#[tauri::command]
fn status(state: State<'_, AppState>) -> CmdResult<Status> {
    let guard = state
        .session
        .lock()
        .map_err(|_| "vault state poisoned".to_string())?;
    Ok(status_of(&guard))
}

/// Unlock the vault at the default path, or create it if it does not exist.
#[tauri::command]
fn unlock(password: String, state: State<'_, AppState>) -> CmdResult<Status> {
    let session = VaultSession::open_or_create(default_vault_path(), password.as_bytes())
        .map_err(|e| e.to_string())?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault state poisoned".to_string())?;
    *guard = Some(session);
    Ok(status_of(&guard))
}

/// Unlock the vault at the default path as a SHARED vault — with the 32-byte
/// vault key this device holds for `vault_id`, not a password.
///
/// This is how a recipient opens a vault after `accept` + `pull`: a shared vault
/// is sealed under a random key and the owner's password is never involved.
#[tauri::command]
fn unlock_shared(vault_id: String, state: State<'_, AppState>) -> CmdResult<Status> {
    let config = sync_config(&state)?;
    let session =
        VaultSession::unlock_shared(default_vault_path(), &config, vault_id.trim()).map_err(ipc)?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault state poisoned".to_string())?;
    *guard = Some(session);
    Ok(status_of(&guard))
}

/// Forget the password and the decrypted entries (the sealed file stays).
#[tauri::command]
fn lock(state: State<'_, AppState>) -> CmdResult<Status> {
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault state poisoned".to_string())?;
    *guard = None; // Drop zeroes the password.
    Ok(status_of(&guard))
}

/// Every account with its code for *now*, read from the host clock and passed
/// into `sigil-core` (which reads no clock of its own).
#[tauri::command]
fn list(state: State<'_, AppState>) -> CmdResult<Vec<Row>> {
    with_session(&state, |s| {
        let views = s.entries_at(now_unix()).map_err(|e| e.to_string())?;
        Ok(views
            .into_iter()
            .map(|v| Row {
                label: v.label,
                issuer: v.issuer,
                algorithm: v.algorithm,
                digits: v.digits,
                period: v.period,
                code: v.code,
                seconds_remaining: v.seconds_remaining,
            })
            .collect())
    })
}

/// Add an account from a base32 secret.
#[tauri::command]
#[allow(clippy::too_many_arguments)]
fn add_secret(
    label: String,
    issuer: Option<String>,
    secret: String,
    algorithm: String,
    digits: Option<u32>,
    period: Option<u32>,
    state: State<'_, AppState>,
) -> CmdResult<()> {
    with_session(&state, |s| {
        let issuer = issuer.filter(|i| !i.trim().is_empty());
        s.add_secret_base32(
            label.trim(),
            issuer,
            secret.trim(),
            algorithm.trim(),
            digits,
            period,
        )
        .map_err(|e| msg(e.to_string()))
    })
}

/// Add an account from an `otpauth://totp/...` URI.
#[tauri::command]
fn add_uri(uri: String, state: State<'_, AppState>) -> CmdResult<String> {
    with_session(&state, |s| s.add_uri(&uri).map_err(|e| msg(e.to_string())))
}

/// Import a Google Authenticator `otpauth-migration://` URI, a single
/// `otpauth://` URI, or a newline-separated list of them.
#[tauri::command]
fn import(text: String, state: State<'_, AppState>) -> CmdResult<Imported> {
    with_session(&state, |s| {
        let r = s.import_text(&text).map_err(|e| e.to_string())?;
        Ok(Imported {
            imported: r.imported,
            skipped_duplicate: r.skipped_duplicate,
            skipped_hotp: r.skipped_hotp,
            skipped_invalid: r.skipped_invalid,
        })
    })
}

/// Remove one account by label.
#[tauri::command]
fn remove(label: String, state: State<'_, AppState>) -> CmdResult<()> {
    with_session(&state, |s| s.remove(&label).map_err(|e| msg(e.to_string())))
}

/// Export as `otpauth://` URIs. **Reveals the secrets in the clear** — the UI
/// must show [`EXPORT_WARNING`], which is returned alongside the payload so it
/// cannot be dropped by accident.
#[tauri::command]
fn export_uris(label: Option<String>, state: State<'_, AppState>) -> CmdResult<Export> {
    with_session(&state, |s| {
        let lines = s.export_uris(label.as_deref()).map_err(|e| e.to_string())?;
        Ok(Export {
            warning: EXPORT_WARNING,
            lines,
        })
    })
}

/// Export as ONE combined `otpauth-migration://` URI. **Reveals the secrets in
/// the clear** — same warning contract as [`export_uris`].
#[tauri::command]
fn export_migration(label: Option<String>, state: State<'_, AppState>) -> CmdResult<Export> {
    with_session(&state, |s| {
        let uri = s
            .export_migration_uri(label.as_deref())
            .map_err(|e| e.to_string())?;
        Ok(Export {
            warning: EXPORT_WARNING,
            lines: vec![uri],
        })
    })
}

// ---------------------------------------------------------------------------
// Sync + sharing commands
//
// Every one of these degrades gracefully: a missing server, a 401/403/501, or an
// unreachable host comes back as a TAGGED message (see `ipc`), never a panic and
// never a silent no-op. With no server configured none of them run at all.
// ---------------------------------------------------------------------------

/// One shared vault this device holds a key for — FINGERPRINT ONLY.
#[derive(Serialize)]
struct VaultRow {
    vault_id: String,
    key_fingerprint: String,
}

/// The Sync panel's whole view. Local read only: it never touches the network,
/// so it renders fine with the server down. No key material, ever.
#[derive(Serialize)]
struct SyncStatus {
    /// Whether a server URL has been set this session.
    configured: bool,
    /// The server URL, or `""`.
    server: String,
    /// The 0700 state directory (shared with the `sigil` CLI).
    state_dir: String,
    /// Whether this device has a server-assigned device id.
    enrolled: bool,
    /// The device id (opaque, not secret).
    device_id: Option<String>,
    /// SHA-256 fingerprint of the Ed25519 public key.
    device_fingerprint: Option<String>,
    /// Whether a hybrid identity exists locally.
    hybrid_identity_present: bool,
    /// SHA-256 fingerprint of the X25519 public half.
    hybrid_fingerprint: Option<String>,
    /// Which shared vaults this device holds keys for.
    vaults: Vec<VaultRow>,
}

impl SyncStatus {
    /// The "no server configured" view — the default, offline state.
    fn unconfigured() -> Self {
        SyncStatus {
            configured: false,
            server: String::new(),
            state_dir: String::new(),
            enrolled: false,
            device_id: None,
            device_fingerprint: None,
            hybrid_identity_present: false,
            hybrid_fingerprint: None,
            vaults: Vec::new(),
        }
    }
}

/// The outcome of a server probe. Never an error just because the server is down.
#[derive(Serialize)]
struct ServerProbe {
    reachable: bool,
    hybrid_published: bool,
    detail: String,
}

/// The outcome of a pull.
#[derive(Serialize)]
struct PullOutcome {
    /// Whether a newer sealed container was adopted.
    adopted: bool,
    /// The op-log sequence adopted, when one was.
    seq: Option<u64>,
    /// Accounts in the vault after the pull.
    count: usize,
}

/// Build the Sync panel view from whatever is configured and on disk.
fn sync_status_of(config: Option<&DeviceConfig>) -> CmdResult<SyncStatus> {
    let Some(config) = config else {
        return Ok(SyncStatus::unconfigured());
    };
    let s = config.status().map_err(ipc)?;
    Ok(SyncStatus {
        configured: true,
        server: s.server,
        state_dir: s.state_dir.display().to_string(),
        enrolled: s.enrolled,
        device_id: s.device_id,
        device_fingerprint: s.device_fingerprint,
        hybrid_identity_present: s.hybrid_identity_present,
        hybrid_fingerprint: s.hybrid_fingerprint,
        vaults: s
            .vaults
            .into_iter()
            .map(|v| VaultRow {
                vault_id: v.vault_id,
                key_fingerprint: v.key_fingerprint,
            })
            .collect(),
    })
}

/// Point this device at a sigild instance. State lives in `$HOME/.sigil` — the
/// SAME directory the `sigil` CLI uses, so the two are one device.
#[tauri::command]
fn set_server(server: String, state: State<'_, AppState>) -> CmdResult<SyncStatus> {
    let server = server.trim().to_string();
    let mut guard = state
        .sync
        .lock()
        .map_err(|_| "sync state poisoned".to_string())?;
    *guard = if server.is_empty() {
        None
    } else {
        Some(DeviceConfig::for_server(server))
    };
    sync_status_of(guard.as_ref())
}

/// The Sync panel's view (local read; safe with no server and safe offline).
#[tauri::command]
fn sync_status(state: State<'_, AppState>) -> CmdResult<SyncStatus> {
    let guard = state
        .sync
        .lock()
        .map_err(|_| "sync state poisoned".to_string())?;
    sync_status_of(guard.as_ref())
}

/// Enroll this device. The token is a single-use BEARER SECRET: it is used for
/// this one call and never stored, echoed or logged. Returns the device id.
#[tauri::command]
fn enroll(token: String, label: String, state: State<'_, AppState>) -> CmdResult<String> {
    sync_config(&state)?
        .enroll(&token, label.trim())
        .map_err(ipc)
}

/// Publish this device's hybrid PUBLIC key (creating the hybrid identity on
/// first use, `0600`). Returns its fingerprint — never the key.
#[tauri::command]
fn publish_hybrid(state: State<'_, AppState>) -> CmdResult<String> {
    sync_config(&state)?.publish_hybrid().map_err(ipc)
}

/// Ask the server whether it is up and whether it holds this device's hybrid key.
#[tauri::command]
fn check_server(state: State<'_, AppState>) -> CmdResult<ServerProbe> {
    let c = sync_config(&state)?.check_server().map_err(ipc)?;
    Ok(ServerProbe {
        reachable: c.reachable,
        hybrid_published: c.hybrid_published,
        detail: c.detail,
    })
}

/// Convert the OPEN vault into a SHARED vault under a fresh random 32-byte vault
/// key, recorded in the `0600` keyring. Your password is never shared.
#[tauri::command]
fn convert_to_shared(vault_id: String, state: State<'_, AppState>) -> CmdResult<String> {
    let config = sync_config(&state)?;
    with_session(&state, |s| {
        s.convert_to_shared(&config, vault_id.trim()).map_err(ipc)
    })
}

/// Push the OPEN vault's sealed container to the op-log. The server stores
/// opaque bytes; it never sees a password, a key or a code.
#[tauri::command]
fn push(vault_id: String, state: State<'_, AppState>) -> CmdResult<u64> {
    let config = sync_config(&state)?;
    let path = with_session(&state, |s| Ok(s.path().to_path_buf()))?;
    config.push_vault_file(vault_id.trim(), &path).map_err(ipc)
}

/// Pull the latest sealed container for `vault_id` and adopt it as the local
/// vault. It is opened with this device's vault key BEFORE anything is written,
/// so a container this device cannot read can never clobber a good vault.
#[tauri::command]
fn pull(vault_id: String, state: State<'_, AppState>) -> CmdResult<PullOutcome> {
    let config = sync_config(&state)?;
    let path = with_session(&state, |s| Ok(s.path().to_path_buf()))?;

    let adopted = pull_and_adopt(&config, vault_id.trim(), &path, 0).map_err(ipc)?;
    let mut guard = state
        .session
        .lock()
        .map_err(|_| "vault state poisoned".to_string())?;
    match adopted {
        Some((session, seq)) => {
            let count = session.len();
            *guard = Some(session);
            Ok(PullOutcome {
                adopted: true,
                seq: Some(seq),
                count,
            })
        }
        None => Ok(PullOutcome {
            adopted: false,
            seq: None,
            count: guard.as_ref().map_or(0, VaultSession::len),
        }),
    }
}

/// Share a vault with another enrolled device: wrap this vault's key to that
/// device's hybrid public key, deposit the opaque envelope, and grant access.
/// Returns the key's fingerprint so both sides can compare.
#[tauri::command]
fn share(
    vault_id: String,
    device_id: String,
    permission: String,
    state: State<'_, AppState>,
) -> CmdResult<String> {
    let permission = permission.trim();
    let permission = if permission.is_empty() {
        "read"
    } else {
        permission
    };
    sync_config(&state)?
        .share_vault(vault_id.trim(), device_id.trim(), permission)
        .map_err(ipc)
}

/// Accept a vault shared TO this device: collect the envelope, unwrap it with
/// this device's hybrid secret, and store the key in the `0600` keyring.
#[tauri::command]
fn accept(vault_id: String, state: State<'_, AppState>) -> CmdResult<String> {
    sync_config(&state)?
        .accept_vault(vault_id.trim())
        .map_err(ipc)
}

// ---------------------------------------------------------------------------
// Phase 52 — ACCOUNTS. An account groups this person's own devices; it is what a
// subscription and a vault's OWNERSHIP belong to, so revoking the device that
// first wrote a vault no longer orphans it. Every command delegates to
// DeviceConfig, which delegates to the sigil-cli library — no protocol here.
//
// NOTHING TAKES AN ACCOUNT ID: the server reads the account off the signature it
// verified, which is why there is no account parameter to get wrong.
// ---------------------------------------------------------------------------

/// One member device as the UI sees it. Metadata only.
#[derive(serde::Serialize)]
struct MemberView {
    device_id: String,
    label: String,
    status: String,
    created_at: String,
    revoked_at: String,
    is_this_device: bool,
}

/// This device's account and its members.
#[derive(serde::Serialize)]
struct AccountViewIpc {
    account_id: String,
    created_at: String,
    device_count: usize,
    device_limit: usize,
    members: Vec<MemberView>,
}

/// A minted invite. ⚠️ `invite` is a BEARER SECRET crossing the IPC exactly once,
/// by necessity — the human has to carry it to the other device, the same way an
/// enrollment token travels IN. The UI must show it once and never persist it.
#[derive(serde::Serialize)]
struct MintedInviteView {
    invite_id: String,
    invite: String,
    account_id: String,
    expires_at: String,
    pinned: bool,
}

/// An OPEN invite in a listing: the public handle and metadata, never a secret.
#[derive(serde::Serialize)]
struct OpenInviteView {
    invite_id: String,
    created_by_device_id: String,
    created_at: String,
    expires_at: String,
    pinned: bool,
}

/// Which account this device is in, and who else is in it.
#[tauri::command]
fn account_status(state: State<'_, AppState>) -> CmdResult<AccountViewIpc> {
    let a = sync_config(&state)?.account().map_err(ipc)?;
    Ok(AccountViewIpc {
        account_id: a.account_id,
        created_at: a.created_at,
        device_count: a.device_count,
        device_limit: a.device_limit,
        members: a
            .members
            .into_iter()
            .map(|m| MemberView {
                device_id: m.device_id,
                label: m.label,
                status: m.status,
                created_at: m.created_at,
                revoked_at: m.revoked_at,
                is_this_device: m.is_this_device,
            })
            .collect(),
    })
}

/// Mint a SINGLE-USE invite so one more device can join this account. The other
/// device redeems it as its ordinary enrollment token — there is no join command.
#[tauri::command]
fn account_invite(
    ttl_seconds: Option<u64>,
    state: State<'_, AppState>,
) -> CmdResult<MintedInviteView> {
    let ttl = ttl_seconds.filter(|t| *t > 0);
    let inv = sync_config(&state)?.create_invite(ttl).map_err(ipc)?;
    Ok(MintedInviteView {
        invite_id: inv.invite_id,
        invite: inv.invite,
        account_id: inv.account_id,
        expires_at: inv.expires_at,
        pinned: inv.pinned,
    })
}

/// This account's OPEN invites. Metadata only — a minted secret is unrecoverable.
#[tauri::command]
fn account_invites(state: State<'_, AppState>) -> CmdResult<Vec<OpenInviteView>> {
    Ok(sync_config(&state)?
        .list_invites()
        .map_err(ipc)?
        .into_iter()
        .map(|i| OpenInviteView {
            invite_id: i.invite_id,
            created_by_device_id: i.created_by_device_id,
            created_at: i.created_at,
            expires_at: i.expires_at,
            pinned: i.pinned,
        })
        .collect())
}

/// Revoke an unredeemed invite by its PUBLIC handle. A foreign handle and a
/// missing one are deliberately indistinguishable.
#[tauri::command]
fn account_revoke_invite(invite_id: String, state: State<'_, AppState>) -> CmdResult<()> {
    sync_config(&state)?
        .revoke_invite(invite_id.trim())
        .map_err(ipc)
}

// ---------------------------------------------------------------------------
// Phase 50 — key verification and rotation. Every one of these delegates to the
// sigil-cli library through DeviceConfig; the desktop implements no crypto and
// no pin logic of its own.
// ---------------------------------------------------------------------------

/// THIS device's safety number — the digits a user reads aloud so someone else
/// can verify this device's hybrid public key before sharing to it. Local only.
#[tauri::command]
fn my_safety_number(state: State<'_, AppState>) -> CmdResult<String> {
    sync_config(&state)?.my_safety_number().map_err(ipc)
}

/// Another device's safety number, plus whether it matches what we pinned.
/// READ-ONLY: it never pins and never re-pins.
#[tauri::command]
fn peer_safety_number(
    device_id: String,
    state: State<'_, AppState>,
) -> CmdResult<(String, String)> {
    sync_config(&state)?
        .peer_safety_number(device_id.trim())
        .map_err(ipc)
}

/// The ORDER-INDEPENDENT pairwise safety number: both people see the same digits.
#[tauri::command]
fn pairwise_safety_number(device_id: String, state: State<'_, AppState>) -> CmdResult<String> {
    sync_config(&state)?
        .pairwise_safety_number(device_id.trim())
        .map_err(ipc)
}

/// The hybrid public keys this device TRUSTS. Public material only.
#[tauri::command]
fn pins(state: State<'_, AppState>) -> CmdResult<Vec<PinView>> {
    Ok(sync_config(&state)?
        .pins()
        .map_err(ipc)?
        .into_iter()
        .map(|p| PinView {
            device_id: p.device_id,
            safety_number: p.safety_number,
            pinned_at: p.pinned_at,
            repins: p.repins,
        })
        .collect())
}

/// One pinned key as the UI sees it — no key bytes, only the safety number.
#[derive(serde::Serialize)]
struct PinView {
    device_id: String,
    safety_number: String,
    pinned_at: u64,
    repins: u32,
}

/// ⚠️ DELIBERATELY accept a CHANGED hybrid key for a device. The UI must only
/// reach this from an explicit confirmation that names the risk, and `expected`
/// carries the safety number the user says they verified out of band.
#[tauri::command]
fn repin(
    device_id: String,
    expected: Option<String>,
    state: State<'_, AppState>,
) -> CmdResult<(Option<String>, String)> {
    let expected = expected
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    sync_config(&state)?
        .repin_device(device_id.trim(), expected.as_deref())
        .map_err(ipc)
}

/// ROTATE this vault's key and re-wrap it to exactly `device_ids`, deleting every
/// other envelope. Protects FUTURE content only.
#[tauri::command]
fn rotate(
    vault_id: String,
    device_ids: Vec<String>,
    state: State<'_, AppState>,
) -> CmdResult<RotationView> {
    let recipients: Vec<String> = device_ids
        .into_iter()
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .collect();
    if recipients.is_empty() {
        return Err(msg(
            "list every device that KEEPS access (usually including this one)",
        ));
    }
    let config = sync_config(&state)?;
    let path = {
        let guard = state
            .session
            .lock()
            .map_err(|_| "vault state poisoned".to_string())?;
        guard
            .as_ref()
            .map(VaultSession::path)
            .map(std::path::Path::to_path_buf)
            .unwrap_or_else(default_vault_path)
    };
    let (old, new, rewrapped, removed) = config
        .rotate_vault(vault_id.trim(), &path, &recipients)
        .map_err(ipc)?;
    // The in-memory session still holds the OLD key, so drop it: the file on disk
    // is now sealed under the new one and must be unlocked afresh.
    if let Ok(mut guard) = state.session.lock() {
        *guard = None;
    }
    Ok(RotationView {
        old_fingerprint: old,
        new_fingerprint: new,
        rewrapped,
        removed,
    })
}

/// What a rotation did, for the UI. Fingerprints only — never a key.
#[derive(serde::Serialize)]
struct RotationView {
    old_fingerprint: String,
    new_fingerprint: String,
    rewrapped: Vec<String>,
    removed: Vec<String>,
}

fn main() {
    // The banner is not only a UI element: anyone launching from a terminal sees
    // it too, and it is the same constant the window renders.
    eprintln!("!! {BANNER_TITLE}");
    eprintln!("!! {BANNER_BODY}");

    tauri::Builder::default()
        .setup(|app| {
            app.manage(AppState::default());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status,
            unlock,
            unlock_shared,
            lock,
            list,
            add_secret,
            add_uri,
            import,
            remove,
            export_uris,
            export_migration,
            set_server,
            sync_status,
            enroll,
            publish_hybrid,
            check_server,
            convert_to_shared,
            push,
            pull,
            share,
            accept,
            my_safety_number,
            peer_safety_number,
            pairwise_safety_number,
            pins,
            repin,
            rotate,
            account_status,
            account_invite,
            account_invites,
            account_revoke_invite
        ])
        .run(tauri::generate_context!())
        .expect("could not start the Sigil desktop window");
}
