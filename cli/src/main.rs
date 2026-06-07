//! `sigil` — a pre-audit demonstration CLI that seals/opens one file with the
//! real-but-UNAUDITED libsigil `sigil-core` record API.
//!
//! STATUS: pre-audit. UNAUDITED cryptography. Demonstration of the libsigil
//! building block only. Do NOT use it to protect real secrets.
//!
//! Arg parsing is hand-rolled on `std::env` (no clap). See [`HELP`] for usage.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use sigil_cli::{
    cursor_key, open_container, pull_ops, push_op, read_cursor, seal_to_container, write_cursor,
    PULL_STATE_FILE,
};
use sigil_core::Argon2Params;

/// Environment variable the password is read from. Empty/unset is a hard error.
const PASSWORD_ENV: &str = "SIGIL_PASSWORD";

/// Environment variable for the dev sigild base URL (overridden by --server).
const SERVER_ENV: &str = "SIGIL_SERVER";

/// Default dev sigild base URL when neither --server nor SIGIL_SERVER is set.
const DEFAULT_SERVER: &str = "http://127.0.0.1:8080";

const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP: &str = "\
sigil — pre-audit demonstration CLI over the libsigil core

  !!  WARNING — PRE-AUDIT, UNAUDITED CRYPTOGRAPHY  !!
  This tool uses the REAL but UNAUDITED sigil-core building block
  (Argon2id + XChaCha20-Poly1305). It is a DEMONSTRATION of the libsigil
  core only. It has NOT been audited and makes NO security guarantees.
  Do NOT use it to protect real secrets.

USAGE:
  sigil seal --in <file> --out <file>    Seal <in> into an encrypted container at <out>
  sigil open --in <file> --out <file>    Open an encrypted container <in> into <out>
  sigil push --vault <id> --in <file> [--server <url>]
                                         Upload an opaque container to the dev op-log
  sigil pull --vault <id> --out-dir <dir> [--since <N>] [--server <url>]
                                         Download NEW opaque containers from the dev op-log
  sigil --help                           Show this help
  sigil --version                        Show the version

PASSWORD (seal/open only):
  The password is read from the SIGIL_PASSWORD environment variable. If it is
  unset or empty, the command fails immediately (it never prompts and never
  hangs). push/pull move OPAQUE sealed containers and do NOT need a password.
  Example:

    SIGIL_PASSWORD='correct horse battery staple' sigil seal --in secret.txt --out secret.sigil
    SIGIL_PASSWORD='correct horse battery staple' sigil open --in secret.sigil --out secret.txt

SYNC (push/pull) — !! DEV / LOCALHOST / PLAIN HTTP ONLY !!
  push/pull talk PLAIN, UNENCRYPTED HTTP to a sigild DEV op-log that is itself
  dev-gated (sigild must run with SIGILD_ENABLE_DEV_OPS=1) and UNAUTHENTICATED.
  There is NO TLS and NO auth on this path. They only shuttle already-sealed,
  OPAQUE container bytes — they never see your password or plaintext. This is a
  local development demo, NOT a production sync service. Do NOT point it at a
  remote host or use it for real secrets.

  The server base URL is chosen as: --server flag, else the SIGIL_SERVER
  environment variable, else the default http://127.0.0.1:8080. Example:

    sigil push --vault demo --in secret.sigil
    SIGIL_SERVER=http://127.0.0.1:8080 sigil pull --vault demo --out-dir ./inbox

INCREMENTAL PULL (pull only):
  Pulled ops are written to <out-dir>/<vault>/op-<seq>.sigil — a PER-VAULT subdir,
  so multiple vaults can safely share one --out-dir without their op-<seq>.sigil
  filenames colliding. The shared cursor state file is <out-dir>/.sigil-pull-state.json
  (at the out-dir root, NOT inside the per-vault subdir).

  pull is INCREMENTAL. It remembers the last pulled op sequence per (server,
  vault) in that LOCAL state file. The first pull for a (server, vault) gets
  every op; later pulls fetch only ops newer than the saved cursor. The cursor
  is MONOTONIC: it only ever advances.

    --since <N> overrides the start for ONE pull (fetch ops with seq > N), e.g.
    --since 0 re-fetches everything. It does NOT rewind the saved cursor: after
    an explicit --since, the cursor still only moves forward.

  The state file is LOCAL, per-device state — it is NOT secret and is NOT synced
  (it holds only server URLs, vault ids, and integers, never crypto material).
  Delete it to reset the cursor and re-pull from scratch.

ON-DISK CONTAINER FORMAT (all integers little-endian):
  magic[8]=\"SIGILcli\" | version:u8=1 | m_cost:u32 | t_cost:u32 | p_cost:u32 |
  salt_len:u8 | salt[salt_len] | envelope[..]
  The Argon2id salt and params are stored in the header (the AEAD nonce travels
  inside the envelope). The salt/params header is unprotected metadata; tampering
  with it makes the record fail to open.
";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("sigil: error: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// Parsed `--in` / `--out` pair for the seal/open subcommands.
struct IoArgs {
    input: String,
    output: String,
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let Some(command) = args.next() else {
        // No subcommand: print help to stderr and fail (so scripts notice).
        return Err(format!("no command given\n\n{HELP}"));
    };

    match command.as_str() {
        "--help" | "-h" | "help" => {
            print!("{HELP}");
            Ok(())
        }
        "--version" | "-V" => {
            println!("sigil {VERSION} (pre-audit, unaudited)");
            Ok(())
        }
        "seal" => {
            let io = parse_io(args)?;
            cmd_seal(&io)
        }
        "open" => {
            let io = parse_io(args)?;
            cmd_open(&io)
        }
        "push" => {
            let p = parse_push(args)?;
            cmd_push(&p)
        }
        "pull" => {
            let p = parse_pull(args)?;
            cmd_pull(&p)
        }
        other => Err(format!(
            "unknown command {other:?}; try `sigil --help`\n\n{HELP}"
        )),
    }
}

/// Resolve the dev sigild base URL: explicit `--server`, else `SIGIL_SERVER`,
/// else the localhost default.
fn resolve_server(flag: Option<String>) -> String {
    flag.or_else(|| std::env::var(SERVER_ENV).ok())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_SERVER.to_string())
}

/// Parsed args for `sigil push`.
struct PushArgs {
    vault: String,
    input: String,
    server: String,
}

/// Parsed args for `sigil pull`.
struct PullArgs {
    vault: String,
    /// The start seq override. `Some(n)` means `--since n` was given explicitly
    /// (a one-off re-fetch start); `None` means use the saved incremental cursor.
    since: Option<u64>,
    out_dir: String,
    server: String,
}

fn parse_push(mut args: impl Iterator<Item = String>) -> Result<PushArgs, String> {
    let mut vault: Option<String> = None;
    let mut input: Option<String> = None;
    let mut server: Option<String> = None;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--vault" => set_once(&mut vault, &mut args, "--vault")?,
            "--in" => set_once(&mut input, &mut args, "--in")?,
            "--server" => set_once(&mut server, &mut args, "--server")?,
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }

    Ok(PushArgs {
        vault: vault.ok_or_else(|| "missing required --vault <id>".to_string())?,
        input: input.ok_or_else(|| "missing required --in <file>".to_string())?,
        server: resolve_server(server),
    })
}

fn parse_pull(mut args: impl Iterator<Item = String>) -> Result<PullArgs, String> {
    let mut vault: Option<String> = None;
    let mut since_raw: Option<String> = None;
    let mut out_dir: Option<String> = None;
    let mut server: Option<String> = None;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--vault" => set_once(&mut vault, &mut args, "--vault")?,
            "--since" => set_once(&mut since_raw, &mut args, "--since")?,
            "--out-dir" => set_once(&mut out_dir, &mut args, "--out-dir")?,
            "--server" => set_once(&mut server, &mut args, "--server")?,
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }

    // Parse `--since` only when it was actually provided; `None` lets cmd_pull
    // fall back to the saved incremental cursor instead of forcing a start.
    let since = match since_raw {
        Some(raw) => Some(
            raw.parse::<u64>()
                .map_err(|_| format!("--since must be a non-negative integer, got {raw:?}"))?,
        ),
        None => None,
    };

    Ok(PullArgs {
        vault: vault.ok_or_else(|| "missing required --vault <id>".to_string())?,
        since,
        out_dir: out_dir.ok_or_else(|| "missing required --out-dir <dir>".to_string())?,
        server: resolve_server(server),
    })
}

/// Store a value into `slot` exactly once, erroring on a missing value or a
/// repeated flag.
fn set_once(
    slot: &mut Option<String>,
    args: &mut impl Iterator<Item = String>,
    flag: &str,
) -> Result<(), String> {
    let v = args
        .next()
        .ok_or_else(|| format!("{flag} requires a value"))?;
    if slot.replace(v).is_some() {
        return Err(format!("{flag} given more than once"));
    }
    Ok(())
}

/// Parse exactly `--in <file> --out <file>` (order-independent) from the
/// remaining args.
fn parse_io(mut args: impl Iterator<Item = String>) -> Result<IoArgs, String> {
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--in" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--in requires a file path".to_string())?;
                if input.replace(v).is_some() {
                    return Err("--in given more than once".to_string());
                }
            }
            "--out" => {
                let v = args
                    .next()
                    .ok_or_else(|| "--out requires a file path".to_string())?;
                if output.replace(v).is_some() {
                    return Err("--out given more than once".to_string());
                }
            }
            other => {
                return Err(format!("unexpected argument {other:?}; try `sigil --help`"));
            }
        }
    }

    let input = input.ok_or_else(|| "missing required --in <file>".to_string())?;
    let output = output.ok_or_else(|| "missing required --out <file>".to_string())?;
    Ok(IoArgs { input, output })
}

/// Read the password from the environment, erroring if unset or empty.
fn password_from_env() -> Result<Vec<u8>, String> {
    match std::env::var_os(PASSWORD_ENV) {
        Some(v) if !v.is_empty() => Ok(v.into_encoded_bytes()),
        _ => Err(format!(
            "{PASSWORD_ENV} is unset or empty; set it to the password, e.g. \
             `{PASSWORD_ENV}=... sigil seal --in f --out f.sigil`"
        )),
    }
}

fn cmd_seal(io: &IoArgs) -> Result<(), String> {
    let password = password_from_env()?;
    let plaintext = std::fs::read(&io.input)
        .map_err(|e| format!("could not read input {:?}: {e}", io.input))?;

    let container = seal_to_container(&password, &plaintext, Argon2Params::RECOMMENDED)
        .map_err(|e| e.to_string())?;

    std::fs::write(&io.output, &container)
        .map_err(|e| format!("could not write output {:?}: {e}", io.output))?;
    Ok(())
}

fn cmd_open(io: &IoArgs) -> Result<(), String> {
    let password = password_from_env()?;
    let container = std::fs::read(&io.input)
        .map_err(|e| format!("could not read input {:?}: {e}", io.input))?;

    // open_container never returns plaintext on error, so this message is safe.
    let plaintext = open_container(&password, &container).map_err(|e| e.to_string())?;

    std::fs::write(&io.output, &plaintext)
        .map_err(|e| format!("could not write output {:?}: {e}", io.output))?;
    Ok(())
}

fn cmd_push(p: &PushArgs) -> Result<(), String> {
    let container =
        std::fs::read(&p.input).map_err(|e| format!("could not read input {:?}: {e}", p.input))?;

    // push_op moves OPAQUE bytes to the dev op-log; no password is involved.
    let seq = push_op(&p.server, &p.vault, &container).map_err(|e| e.to_string())?;
    println!("pushed vault {} seq {}", p.vault, seq);
    Ok(())
}

fn cmd_pull(p: &PullArgs) -> Result<(), String> {
    // The state file lives at the out-dir ROOT (NOT inside the per-vault subdir),
    // shared across vaults and keyed by (server, vault).
    let state_path = std::path::Path::new(&p.out_dir).join(PULL_STATE_FILE);
    let key = cursor_key(&p.server, &p.vault);

    // Read the saved incremental cursor first; we need it both to choose the
    // default start AND to keep the new cursor monotonic on an explicit --since.
    let saved = read_cursor(&state_path, &key).map_err(|e| e.to_string())?;

    // Explicit `--since N` overrides the start for this one-off pull; otherwise
    // resume from the saved cursor.
    let start = p.since.unwrap_or(saved);

    let ops = pull_ops(&p.server, &p.vault, start).map_err(|e| e.to_string())?;

    if ops.is_empty() {
        println!("no new ops since {start}");
        return Ok(());
    }

    // Write each op into a PER-VAULT subdir so multiple vaults can safely share
    // one --out-dir without their flat `op-<seq>.sigil` filenames colliding. The
    // vault id was validated in pull_ops (check_vault rejects empty / '/' /
    // whitespace), so it is a safe single path segment. We create the subdir only
    // now that pull_ops returned a non-empty result, so "no new ops" leaves no
    // empty dirs behind.
    let vault_dir = std::path::Path::new(&p.out_dir).join(&p.vault);
    std::fs::create_dir_all(&vault_dir)
        .map_err(|e| format!("could not create out dir {:?}: {e}", vault_dir))?;

    let mut max_seq = 0u64;
    for op in &ops {
        let path = vault_dir.join(format!("op-{}.sigil", op.seq));
        std::fs::write(&path, &op.blob).map_err(|e| format!("could not write {:?}: {e}", path))?;
        println!("pulled seq {} -> {}", op.seq, path.display());
        max_seq = max_seq.max(op.seq);
    }

    // Advance the cursor MONOTONICALLY: never below the saved value, even when an
    // explicit `--since 0` re-fetched older ops.
    let new_cursor = saved.max(max_seq);
    write_cursor(&state_path, &key, new_cursor).map_err(|e| e.to_string())?;
    println!("cursor for {} now at {}", p.vault, new_cursor);
    Ok(())
}
