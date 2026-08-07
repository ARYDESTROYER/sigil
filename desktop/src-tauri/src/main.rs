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
    default_vault_path, now_unix, pull_and_adopt, verify_recovery_code, DesktopError, DeviceConfig,
    EntitlementView, VaultSession, BANNER_BODY, BANNER_TITLE, EXPORT_WARNING,
};
use tauri::{Manager, State};

/// The unlocked session (`None` when locked; `VaultSession` zeroes its password
/// on drop, so `lock()` is just `*guard = None`) plus the OPTIONAL server
/// configuration (`None` until the user names a server — the offline default)
/// and the last ENTITLEMENT the server told us about.
///
/// ⚠️ Note what is NOT in here: no recovery code, no seed, no vault key. The kit
/// code crosses the IPC once, outbound, and is never stored on either side.
#[derive(Default)]
struct AppState {
    session: Mutex<Option<VaultSession>>,
    sync: Mutex<Option<DeviceConfig>>,
    entitlement: Mutex<EntitlementView>,
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
    /// ⛔ Non-empty when this import came from a MULTI-QR Google Authenticator
    /// export: one "batch i of N" note per payload. The UI must NOT report a
    /// plain success while this has entries.
    partial_batches: Vec<String>,
    /// ⭐ True only while QR codes remain UNSCANNED. The UI keys its "INCOMPLETE"
    /// alarm off THIS, not off `partial_batches` — the final batch of an export
    /// still gets a note, and calling that incomplete is a false alarm.
    batches_outstanding: bool,
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
    /// Populated for EXACTLY ONE kind — `"payment required"` — so the UI can
    /// state what is STILL available instead of rendering a bare HTTP status.
    #[serde(skip_serializing_if = "Option::is_none")]
    entitlement: Option<Box<EntitlementDto>>,
}

/// The two safety numbers behind a `"key changed"` alarm. PUBLIC material only.
#[derive(Serialize)]
struct KeyChange {
    device_id: String,
    pinned_safety_number: String,
    presented_safety_number: String,
}

/// Entitlement as the webview sees it. PUBLIC facts only — there is no card
/// field, no customer identity and no key here, and the server sends none.
#[derive(Serialize, Clone)]
struct EntitlementDto {
    known: bool,
    writes: String,
    reads: String,
    key_recovery: String,
    subscription_status: String,
    grace_ends_at: String,
    checkout_path: String,
    detail: String,
    needs_attention: bool,
}

impl From<&EntitlementView> for EntitlementDto {
    fn from(v: &EntitlementView) -> Self {
        EntitlementDto {
            known: v.known,
            writes: v.writes.clone(),
            reads: v.reads.clone(),
            key_recovery: v.key_recovery.clone(),
            subscription_status: v.subscription_status.clone(),
            grace_ends_at: v.grace_ends_at.clone(),
            checkout_path: v.checkout_path.clone(),
            detail: v.detail.clone(),
            needs_attention: v.needs_attention(),
        }
    }
}

impl From<String> for IpcError {
    fn from(message: String) -> Self {
        IpcError {
            kind: "error",
            message,
            key_change: None,
            entitlement: None,
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
        DesktopError::KeyUnverified { .. } => "key unverified",
        // ⭐ Its own tag (Phase 60): an envelope that proves nothing about who
        // produced it is neither an auth failure, nor a permission failure, nor a
        // changed key. The UI must be able to say exactly that.
        DesktopError::UnauthenticatedEnvelope { .. } => "envelope not authenticated",
        // ⭐ Its own tag: a lapsed subscription is a BILLING state, not a
        // security failure and not data loss. The UI must be able to say so, and
        // to say what still works.
        DesktopError::PaymentRequired { .. } => "payment required",
        DesktopError::Recovery(_) => "recovery",
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
    let entitlement = match &e {
        DesktopError::PaymentRequired { entitlement, .. } => {
            Some(Box::new(EntitlementDto::from(&**entitlement)))
        }
        _ => None,
    };
    IpcError {
        kind,
        message: format!("{kind}: {e}"),
        key_change,
        entitlement,
    }
}

/// Run a SERVER-GATED WRITE, recording what its answer says about entitlement.
///
/// Writes are the only requests `sigild` gates (ADR 0043 §2), so they are the
/// only ones that carry a verdict: a `402` says the account lapsed past grace, a
/// success says it was served. Reads are never refused, so they never update
/// this — a read failure means something else went wrong.
fn track_write<T>(state: &State<'_, AppState>, r: sigil_desktop_core::Result<T>) -> CmdResult<T> {
    let observed = match &r {
        Ok(_) => Some(EntitlementView::write_accepted()),
        Err(DesktopError::PaymentRequired { entitlement, .. }) => Some((**entitlement).clone()),
        Err(_) => None,
    };
    if let Some(view) = observed {
        if let Ok(mut guard) = state.entitlement.lock() {
            *guard = view;
        }
    }
    r.map_err(ipc)
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
        // ⛔ THE GUI FORM'S DOOR, AND THE ONLY GATE ON IT (ADR 0051).
        //
        // ADR 0051 exempts `sigil totp add --period N` — a value a person typed
        // into a shell, where it lands in a history someone can review. A GUI
        // form is a different case: it is where a phishing page's "helpful setup
        // instructions" land. The webapp and the extension gate theirs; this one
        // did not, so the ADR asserted a policy it implemented in two of three
        // GUI clients. Found by an independent verifier, not by the build.
        //
        // It sits HERE rather than in `add_secret_base32` because that function
        // is the core's programmatic API and is used by `cli_interop.rs` /
        // `server_interop.rs` to pin a TOTP counter across processes with a
        // deliberately enormous period; those are integration tests and cannot
        // reach a private bypass. Gating the library would have broken the
        // repo's own documented artifice to close a door that is not the defect.
        //
        // Reached through the `sigil-cli` library (ADR 0037): no fourth copy of
        // the bounds, no second error vocabulary.
        VaultSession::check_form_provisioning(&label, issuer.as_deref(), &secret, digits, period)
            .map_err(|e| msg(e.to_string()))?;
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
            partial_batches: r.partial_batches,
            batches_outstanding: r.batches_outstanding,
        })
    })
}

/// Remove one account by label.
#[tauri::command]
fn remove(label: String, state: State<'_, AppState>) -> CmdResult<()> {
    with_session(&state, |s| s.remove(&label).map_err(|e| msg(e.to_string())))
}

/// Remove the account with this IDENTITY, recording a tombstone.
///
/// ⭐ Phase 61: this is what the UI calls. Labels are no longer unique (`work` at
/// two issuers is two accounts), so removing by label can be AMBIGUOUS — the
/// library refuses rather than guessing, and guessing is how a user deletes the
/// wrong account.
#[tauri::command]
fn remove_by_id(uuid: String, state: State<'_, AppState>) -> CmdResult<()> {
    with_session(&state, |s| {
        s.remove_by_id(uuid.trim()).map_err(|e| msg(e.to_string()))
    })
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

/// The outcome of a push.
///
/// ⛔ `size_warning` is the TOMBSTONE GROWTH LIMIT surfacing. A vault is a
/// 2P-Set whose remove-set never shrinks, nothing prunes a tombstone and there
/// is no compaction command, so a long-lived vault walks towards sigild's 64 KiB
/// op cap and then simply stops syncing (413). The warning has to reach the
/// human while the push still WORKS — meeting this first at the 413 means sync
/// is already gone — which is why the push result carries it rather than the
/// error path alone.
#[derive(Serialize)]
struct PushOutcome {
    /// The op-log sequence the server assigned.
    seq: u64,
    /// A size warning at ≥75% of the server's op cap, else `None`.
    size_warning: Option<String>,
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
fn push(vault_id: String, state: State<'_, AppState>) -> CmdResult<PushOutcome> {
    let config = sync_config(&state)?;
    let path = with_session(&state, |s| Ok(s.path().to_path_buf()))?;
    // ⛔ Computed BEFORE the push and returned whether or not the push succeeds
    // in the caller's eyes: the size problem belongs to the VAULT, not to this
    // one request, and the 413 that ends sync gives no second chance to say so.
    let size_warning = sigil_desktop_core::op_body_size_warning_for(&path);
    // An op-log append is THE gated write (ADR 0043 §2): this is where a lapsed
    // account learns it has lapsed, and where the UI learns to say so.
    match track_write(&state, config.push_vault_file(vault_id.trim(), &path)) {
        Ok(seq) => Ok(PushOutcome { seq, size_warning }),
        Err(mut e) => {
            // ⚠️ The warning must survive the FAILURE path too — a 413 IS the
            // failure it predicts, and "push failed" alone tells the user
            // nothing about why or what to do about it.
            if let Some(w) = size_warning {
                e.message = format!("{} ⚠️ {w}", e.message);
            }
            Err(e)
        }
    }
}

/// Pull EVERY sealed snapshot for `vault_id` and MERGE them into the local vault.
///
/// ⛔ It used to adopt the newest op wholesale, so an account added on another
/// device that had not pulled first was destroyed by one click, with both
/// devices reporting success. The merge is `sigil_cli::merge_ops_into`, reached
/// through `pull_and_adopt` — nothing under `desktop/` decides it (ADR 0037).
///
/// The merged vault is re-sealed BEFORE anything is written, so a container this
/// device cannot read can never clobber a good vault.
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
///
/// `safety_number` is the recipient's digits, read out of band (or printed on a
/// RECOVERY SHEET). It is OPTIONAL for an ordinary device — where a first sight
/// is still ADR 0038's accepted trust-on-first-use — and MANDATORY for a
/// recovery kit this device has never pinned, which the wrap gate enforces.
///
/// Returns the trust decision alongside the key fingerprint, so the UI can show
/// what was trusted rather than only that something happened.
#[tauri::command]
fn share(
    vault_id: String,
    device_id: String,
    permission: String,
    safety_number: Option<String>,
    state: State<'_, AppState>,
) -> CmdResult<ShareView> {
    let permission = permission.trim();
    let permission = if permission.is_empty() {
        "read"
    } else {
        permission
    };
    let expected = safety_number
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let config = sync_config(&state)?;
    let out = track_write(
        &state,
        config.share_vault(
            vault_id.trim(),
            device_id.trim(),
            permission,
            expected.as_deref(),
        ),
    )?;
    Ok(ShareView {
        fingerprint: out.fingerprint,
        safety_number: out.safety_number,
        trust: out.trust,
        needs_out_of_band_check: out.needs_out_of_band_check,
    })
}

/// What a share did, for the UI. PUBLIC material only — never a key.
#[derive(serde::Serialize)]
struct ShareView {
    fingerprint: String,
    safety_number: String,
    trust: String,
    needs_out_of_band_check: bool,
}

/// ⭐ Accept a vault shared TO this device (Phase 60).
///
/// It no longer unwraps whatever decrypts to 32 bytes from whoever: the
/// depositing device is resolved (named here, else from this device's self-only
/// envelope index), its hybrid key is PIN-CHECKED, and the envelope must be an
/// AUTHENTICATED (version 2) one bound to (this vault, this device, that
/// sender). `from` names the sender explicitly; `safety_number` is the digits
/// read out of band, which is what closes the first-contact window pinning
/// cannot; `replace` is required to overwrite a DIFFERENT key already held.
///
/// A blank string means "not supplied" — the UI sends empty inputs as `""`.
#[tauri::command]
fn accept(
    vault_id: String,
    from: Option<String>,
    safety_number: Option<String>,
    replace: Option<bool>,
    state: State<'_, AppState>,
) -> CmdResult<String> {
    let from = from.map(|s| s.trim().to_string()).filter(|s| !s.is_empty());
    let expected = safety_number
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    sync_config(&state)?
        .accept_vault(
            vault_id.trim(),
            from.as_deref(),
            expected.as_deref(),
            replace.unwrap_or(false),
        )
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

/// ROTATE this vault's key and re-wrap it to exactly `device_ids`, deleting the
/// envelope of every device named in `drop_device_ids`. A current holder named in
/// NEITHER list aborts the rotation (Phase 54). Protects FUTURE content only.
#[tauri::command]
fn rotate(
    vault_id: String,
    device_ids: Vec<String>,
    drop_device_ids: Option<Vec<String>>,
    // (device id, printed safety-number digits) for any recipient verified out
    // of band. REQUIRED for a first-sight recovery kit; the wrap gate refuses
    // otherwise, before a single byte of local or server state is touched.
    safety_numbers: Option<Vec<(String, String)>>,
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
    // Phase 54: a holder named by neither list aborts the rotation, so removing
    // a device's access — including a RECOVERY KIT's — has to be stated.
    let drop: Vec<String> = drop_device_ids
        .unwrap_or_default()
        .into_iter()
        .map(|d| d.trim().to_string())
        .filter(|d| !d.is_empty())
        .collect();
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
    let safety: Vec<(String, String)> = safety_numbers
        .unwrap_or_default()
        .into_iter()
        .map(|(d, n)| (d.trim().to_string(), n.trim().to_string()))
        .filter(|(d, n)| !d.is_empty() && !n.is_empty())
        .collect();
    let (old, new, rewrapped, removed) = track_write(
        &state,
        config.rotate_vault(vault_id.trim(), &path, &recipients, &drop, &safety),
    )?;
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

// ---------------------------------------------------------------------------
// Phase 54/56 — THE RECOVERY KIT.
//
// A kit is an ORDINARY MEMBER DEVICE whose keys are derived from 32 bytes
// printed on paper. Every command here delegates to `sigil_desktop_core::
// recovery`, which delegates to the `sigil-cli` library: no codec, no
// derivation, no safety-number digest and no HTTP lives under desktop/.
//
// ⚠️ THE ONE SECRET THAT CROSSES THIS IPC is `RecoveryKitView::code`, outbound,
// exactly once, because the human has to write it down — the same necessity as
// an account invite. It is never stored on either side, never logged, never put
// in a URL, and the webview clears it from the DOM as soon as it is confirmed.
// ---------------------------------------------------------------------------

/// One vault a kit covers. Fingerprint only.
#[derive(serde::Serialize)]
struct CoveredView {
    vault_id: String,
    key_fingerprint: String,
}

/// A freshly printed sheet. ⚠️ `code` IS THE CREDENTIAL.
#[derive(serde::Serialize)]
struct RecoveryKitView {
    code: String,
    device_id: String,
    account_id: String,
    server: String,
    safety_number: String,
    created_at: u64,
    covered: Vec<CoveredView>,
    seats_used: usize,
    seat_limit: usize,
    verified_account_id: String,
    verified_vault: String,
    verified_fingerprint: String,
    indexed_vaults: usize,
    /// ⚠️ The kit's envelope index was ALREADY truncated when it was printed, so
    /// this kit must be restored from the sheet's `covers` line and not from
    /// discovery. ⭐ Generation is the ONE moment the user can still act on that
    /// — re-print, reduce coverage, copy the ids carefully.
    index_truncated: bool,
}

/// One vault's coverage as seen FROM THIS DEVICE.
#[derive(serde::Serialize)]
struct CoverageRow {
    vault_id: String,
    covered: bool,
    covered_at: String,
    synced: bool,
}

/// What a restore rebuilt on a machine that had nothing.
#[derive(serde::Serialize)]
struct RestoreOutcome {
    device_id: String,
    account_id: String,
    vaults: Vec<RestoredRow>,
    skipped: Vec<(String, String)>,
    adopted: bool,
    /// ⚠️ The server truncated the kit's envelope index. What came back is what
    /// was NAMED plus one page — the UI must not call it "everything".
    index_truncated: bool,
    /// Vault ids the caller supplied that the index did not list.
    from_sheet: Vec<String>,
    /// ⚠️ The index route could not be read AT ALL; only the named vaults were
    /// tried. "Listed nothing" and "never answered" are different facts.
    index_error: Option<String>,
    /// How many listed rows were deposited by devices OUTSIDE this account and
    /// were ignored — a COUNT, never one row per line.
    ignored_untrusted: usize,
}

/// One vault a restore wrote back.
#[derive(serde::Serialize)]
struct RestoredRow {
    vault_id: String,
    path: String,
    key_fingerprint: String,
    entries: usize,
}

/// What a revocation did.
#[derive(serde::Serialize)]
struct RevokeOutcome {
    device_id: String,
    envelopes_removed: Vec<String>,
    already_clear: Vec<String>,
}

/// A kit this device can see in its own account listing.
#[derive(serde::Serialize)]
struct KitRow {
    device_id: String,
    status: String,
    created_at: String,
}

/// GENERATE a recovery kit and cover `vault_ids` (empty = every shared vault
/// this device holds a key for).
///
/// ⚠️ Returns THE CREDENTIAL once. The webview must render it for transcription
/// and then drop it: it is stronger than a stolen locked phone, because there is
/// no OS lock, no biometric and no vault password in front of it.
#[tauri::command]
fn recovery_generate(
    vault_ids: Option<Vec<String>>,
    state: State<'_, AppState>,
) -> CmdResult<RecoveryKitView> {
    let vaults: Vec<String> = vault_ids
        .unwrap_or_default()
        .into_iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect();
    let config = sync_config(&state)?;
    // Covering a vault is a key deposit, which ADR 0043 exempts from the
    // entitlement gate for a device of your OWN account — so a lapsed customer
    // can still print a kit. Tracked as a write anyway: if this ever DOES come
    // back 402, the UI must say so rather than swallow it.
    let kit = track_write(&state, config.recovery_generate(&vaults))?;
    Ok(RecoveryKitView {
        code: kit.code,
        device_id: kit.device_id,
        account_id: kit.account_id,
        server: kit.server,
        safety_number: kit.safety_number,
        created_at: kit.created_at,
        covered: kit
            .covered
            .into_iter()
            .map(|c| CoveredView {
                vault_id: c.vault_id,
                key_fingerprint: c.key_fingerprint,
            })
            .collect(),
        seats_used: kit.seats_used,
        seat_limit: kit.seat_limit,
        verified_account_id: kit.proof.account_id,
        verified_vault: kit.proof.unwrapped_vault,
        verified_fingerprint: kit.proof.key_fingerprint,
        indexed_vaults: kit.proof.indexed_vaults,
        index_truncated: kit.proof.index_truncated,
    })
}

/// COVER one more vault with an existing kit. `safety_number` is the digits
/// PRINTED ON THE SHEET; it is required on any device that did not generate the
/// kit, and the wrap gate refuses without it before anything is wrapped.
#[tauri::command]
fn recovery_cover(
    device_id: String,
    vault_id: String,
    safety_number: Option<String>,
    state: State<'_, AppState>,
) -> CmdResult<(String, bool)> {
    let expected = safety_number
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let config = sync_config(&state)?;
    track_write(
        &state,
        config.recovery_cover(device_id.trim(), vault_id.trim(), expected.as_deref()),
    )
}

/// What the kit still covers, CHECKED FROM THIS DEVICE (a vault created on a
/// sibling device that never heard of the kit is invisible here).
#[tauri::command]
fn recovery_check(device_id: String, state: State<'_, AppState>) -> CmdResult<Vec<CoverageRow>> {
    Ok(sync_config(&state)?
        .recovery_check(device_id.trim())
        .map_err(ipc)?
        .into_iter()
        .map(|c| CoverageRow {
            vault_id: c.vault_id,
            covered: c.covered,
            covered_at: c.covered_at,
            synced: c.synced,
        })
        .collect())
}

/// VERIFY a typed code OFFLINE — decode + checksum, no network at all.
///
/// The code is NOT echoed back and NOT stored: only the verdict crosses back.
#[tauri::command]
fn recovery_verify(code: String) -> CmdResult<bool> {
    verify_recovery_code(&code).map_err(ipc)?;
    Ok(true)
}

/// RESTORE from a printed kit. This is the command that runs on a NEW INSTALL —
/// the situation the sheet exists for.
///
/// `adopt = true` writes the kit's own secrets onto this machine, making it a
/// SECOND COPY OF THE PAPER; the UI must say that before offering it.
///
/// ⭐ `vault_ids` are the ids printed on the sheet's `covers` line. Supplying
/// them makes the restore ask each vault directly rather than depending on the
/// kit's per-device envelope index, which is one uncursored page that any other
/// account can crowd rows off. With none supplied and a truncated index the
/// library REFUSES rather than restoring a silent partial.
#[tauri::command]
fn recovery_restore(
    code: String,
    device_id: String,
    adopt: Option<bool>,
    vault_ids: Option<Vec<String>>,
    state: State<'_, AppState>,
) -> CmdResult<RestoreOutcome> {
    let vaults = vault_ids.unwrap_or_default();
    let r = sync_config(&state)?
        .recovery_restore(
            &code,
            device_id.trim(),
            None,
            adopt.unwrap_or(false),
            &vaults,
        )
        .map_err(ipc)?;
    Ok(RestoreOutcome {
        device_id: r.device_id,
        account_id: r.account_id,
        vaults: r
            .vaults
            .into_iter()
            .map(|v| RestoredRow {
                vault_id: v.vault_id,
                path: v.path.display().to_string(),
                key_fingerprint: v.key_fingerprint,
                entries: v.entries,
            })
            .collect(),
        skipped: r.skipped,
        adopted: r.adopted,
        index_truncated: r.index_truncated,
        from_sheet: r.from_sheet,
        index_error: r.index_error,
        ignored_untrusted: r.ignored_untrusted,
    })
}

/// REVOKE a kit and delete its envelopes. It does NOT rotate, and it cannot
/// un-learn a key the kit already unwrapped — rotation is the remediation, and
/// it protects future content only.
#[tauri::command]
fn recovery_revoke(
    device_id: String,
    vault_ids: Option<Vec<String>>,
    state: State<'_, AppState>,
) -> CmdResult<RevokeOutcome> {
    let vaults: Vec<String> = vault_ids
        .unwrap_or_default()
        .into_iter()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .collect();
    let r = sync_config(&state)?
        .recovery_revoke(device_id.trim(), &vaults)
        .map_err(ipc)?;
    Ok(RevokeOutcome {
        device_id: r.device_id,
        envelopes_removed: r.envelopes_removed,
        already_clear: r.already_clear,
    })
}

/// The kits in this device's account, as the SERVER lists them — the answer to
/// "is recovery set up?". ⚠️ Label-based, so a server that renames the label
/// hides a kit here (ADR 0042 §5); no trust decision rests on it.
#[tauri::command]
fn recovery_kits(state: State<'_, AppState>) -> CmdResult<Vec<KitRow>> {
    Ok(sync_config(&state)?
        .recovery_kits()
        .map_err(ipc)?
        .into_iter()
        .map(|k| KitRow {
            device_id: k.device_id,
            status: k.status,
            created_at: k.created_at,
        })
        .collect())
}

/// What the server has told THIS client about entitlement (ADR 0043).
///
/// Purely a cached read: it opens no socket and cannot fail because a server is
/// down. `known: false` means "not observed" and is deliberately NOT rendered as
/// "you are paid up" — an un-enforcing server looks identical from here.
#[tauri::command]
fn entitlement_status(state: State<'_, AppState>) -> CmdResult<EntitlementDto> {
    let guard = state
        .entitlement
        .lock()
        .map_err(|_| "entitlement state poisoned".to_string())?;
    Ok(EntitlementDto::from(&*guard))
}

/// ⭐ ASK THE SERVER about this account's subscription, and cache the answer.
///
/// This is the ONLY way this client can learn it is in its GRACE period —
/// lapsed, still served, with a deadline. A refusal (`402`) can only ever say
/// "already too late", and the grace warning `sigild` puts in response headers is
/// dropped by the library's transport. Without this command the desktop's
/// in-grace banner was unreachable code: `track_write` only ever produced
/// "allowed" or "refused".
///
/// It is a READ and is never gated by entitlement, so a lapsed account can always
/// find out why. A server with enforcement off answers "not enforced", which
/// renders as nothing.
#[tauri::command]
fn entitlement_refresh(state: State<'_, AppState>) -> CmdResult<EntitlementDto> {
    let view = sync_config(&state)?.subscription().map_err(ipc)?;
    let dto = EntitlementDto::from(&view);
    if let Ok(mut guard) = state.entitlement.lock() {
        *guard = view;
    }
    Ok(dto)
}

/// A clock reading as the webview sees it. PUBLIC facts only — two integers and
/// a sentence; no key, no identity, nothing secret.
#[derive(Serialize, Clone)]
struct ClockDto {
    available: bool,
    skewed: bool,
    skew_seconds: i64,
    detail: String,
}

/// Compare this machine's clock against the server's.
///
/// ⛔ THE FAILURE THIS EXISTS FOR: a TOTP code rejected because this machine's
/// clock drifted is indistinguishable, to the user, from a wrong secret — so
/// they re-scan the QR, re-import the export, delete and re-add the account, and
/// none of it helps.
///
/// ⛔⛔ IT REPORTS. IT NEVER CORRECTS. `list` still computes codes from
/// `now_unix()`, this machine's own system clock, exactly as before. Nothing in
/// this command's path touches it.
///
/// ⚠️ An unreachable server yields `available: false` — NO READING, which is a
/// different answer from "your clock is fine", and the UI renders it as such.
#[tauri::command]
fn clock_skew(state: State<'_, AppState>) -> CmdResult<ClockDto> {
    let r = sync_config(&state)?.clock();
    Ok(ClockDto {
        available: r.available,
        skewed: r.skewed,
        skew_seconds: r.skew_seconds,
        detail: r.detail,
    })
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
            remove_by_id,
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
            account_revoke_invite,
            recovery_generate,
            recovery_cover,
            recovery_check,
            recovery_verify,
            recovery_restore,
            recovery_revoke,
            recovery_kits,
            entitlement_status,
            entitlement_refresh,
            clock_skew
        ])
        .run(tauri::generate_context!())
        .expect("could not start the Sigil desktop window");
}
