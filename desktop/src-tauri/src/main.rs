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

// Keep the console window off on Windows release builds (harmless elsewhere).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use std::sync::Mutex;

use serde::Serialize;
use sigil_desktop_core::{
    default_vault_path, now_unix, VaultSession, BANNER_BODY, BANNER_TITLE, EXPORT_WARNING,
};
use tauri::{Manager, State};

/// The unlocked session, or `None` when locked. `VaultSession` zeroes its
/// password on drop, so `lock()` is just `*guard = None`.
#[derive(Default)]
struct AppState(Mutex<Option<VaultSession>>);

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

/// Errors cross the IPC as plain strings; they never contain secret material.
type CmdResult<T> = Result<T, String>;

/// Borrow the unlocked session or fail with a UI-friendly message.
fn with_session<T>(
    state: &State<'_, AppState>,
    f: impl FnOnce(&mut VaultSession) -> CmdResult<T>,
) -> CmdResult<T> {
    let mut guard = state
        .0
        .lock()
        .map_err(|_| "vault state poisoned".to_string())?;
    let session = guard
        .as_mut()
        .ok_or_else(|| "vault is locked".to_string())?;
    f(session)
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
        .0
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
        .0
        .lock()
        .map_err(|_| "vault state poisoned".to_string())?;
    *guard = Some(session);
    Ok(status_of(&guard))
}

/// Forget the password and the decrypted entries (the sealed file stays).
#[tauri::command]
fn lock(state: State<'_, AppState>) -> CmdResult<Status> {
    let mut guard = state
        .0
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
        .map_err(|e| e.to_string())
    })
}

/// Add an account from an `otpauth://totp/...` URI.
#[tauri::command]
fn add_uri(uri: String, state: State<'_, AppState>) -> CmdResult<String> {
    with_session(&state, |s| s.add_uri(&uri).map_err(|e| e.to_string()))
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
    with_session(&state, |s| s.remove(&label).map_err(|e| e.to_string()))
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
            lock,
            list,
            add_secret,
            add_uri,
            import,
            remove,
            export_uris,
            export_migration
        ])
        .run(tauri::generate_context!())
        .expect("could not start the Sigil desktop window");
}
