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
    base32_decode, cursor_key, generate_hybrid_identity, generate_key, hybrid_open_container,
    hybrid_seal_to_container, load_hybrid_public, load_hybrid_secret, load_key, new_totp_entry,
    open_container, open_vault, parse_otpauth_uri, pull_ops, push_op, read_cursor,
    save_hybrid_public, save_hybrid_secret, save_key, seal_to_container, seal_vault,
    totp_algorithm_from_str, write_cursor, TotpVault, PULL_STATE_FILE, TOTP_DEFAULT_DIGITS,
    TOTP_DEFAULT_PERIOD,
};
use sigil_core::Argon2Params;

/// Environment variable the password is read from. Empty/unset is a hard error.
const PASSWORD_ENV: &str = "SIGIL_PASSWORD";

/// Environment variable for the dev sigild base URL (overridden by --server).
const SERVER_ENV: &str = "SIGIL_SERVER";

/// Default dev sigild base URL when neither --server nor SIGIL_SERVER is set.
const DEFAULT_SERVER: &str = "http://127.0.0.1:8080";

/// Environment variable giving the path to the device key file used to SIGN
/// op-log requests (overridden by `--key`).
const DEVICE_KEY_ENV: &str = "SIGIL_DEVICE_KEY";

const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP: &str = "\
sigil — pre-audit demonstration CLI over the libsigil core

  !!  WARNING — PRE-AUDIT, UNAUDITED CRYPTOGRAPHY  !!
  This tool uses the REAL but UNAUDITED sigil-core building block
  (Argon2id + XChaCha20-Poly1305). It is a DEMONSTRATION of the libsigil
  core only. It has NOT been audited and makes NO security guarantees.
  Do NOT use it to protect real secrets.

USAGE:
  sigil seal --in <file> --out <file>    Seal <in> into a password-encrypted container at <out>
  sigil open --in <file> --out <file>    Open a password-encrypted container <in> into <out>
  sigil totp add <label> --secret <BASE32> [--issuer X] [--algorithm sha1|sha256|sha512]
                         [--digits 6] [--period 30] [--vault <file>]
                                         Add a TOTP secret to the encrypted vault
  sigil totp add --uri \"otpauth://totp/...\" [--vault <file>]
                                         Import a TOTP secret from an otpauth:// URI
  sigil totp list [--vault <file>]       List vault entries (label/issuer/algorithm/digits/period)
  sigil totp code <label> [--vault <file>]
                                         Print the CURRENT code for <label> (uses the system clock)
  sigil totp remove <label> [--vault <file>]
                                         Delete an entry from the vault
  sigil keygen --out <file>              Generate a DEV device key (0600) and print its public key
  sigil hybrid-keygen --out <file>       Generate a hybrid identity: secret <file> (0600) + shareable <file>.pub
  sigil hybrid-seal --recipient-pub <pubfile> --in <file> --out <file>
                                         Encrypt <in> TO a recipient's hybrid public identity (no password)
  sigil hybrid-open --key <file> --in <file> --out <file>
                                         Decrypt a hybrid container <in> with your secret identity <file>
  sigil push --vault <id> --in <file> [--server <url>] [--key <file>]
                                         Upload an opaque container to the dev op-log
  sigil pull --vault <id> --out-dir <dir> [--since <N>] [--server <url>] [--key <file>]
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

TOTP VAULT (totp add/list/code/remove) — the authenticator feature:
  A TOTP vault is an encrypted list of 2FA secrets, sealed AT REST with the SAME
  password container as seal/open (SIGIL_PASSWORD provides the password). Codes
  are generated with the real RFC 4226/6238 primitive in sigil-core.

  The vault path is --vault <file>, else the default $HOME/.sigil/totp-vault.sigil
  (the .sigil dir is created 0700; the vault file is written 0600). Example:

    export SIGIL_PASSWORD='correct horse battery staple'
    sigil totp add work --secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ --issuer Acme --digits 6
    sigil totp add --uri \"otpauth://totp/Acme:bob?secret=GEZDGNBVGY3TQOJQ&period=30\"
    sigil totp list
    sigil totp code work
    sigil totp remove work

  !! PRE-AUDIT / UNAUDITED / DEV-ONLY !! The OTP math is standard and RFC-vector
  checked, but the build is unaudited. Do NOT store real 2FA secrets yet.

HYBRID PUBLIC-KEY ENCRYPTION (hybrid-keygen / hybrid-seal / hybrid-open) — NO password:
  This is the PUBLIC-KEY path, distinct from the password-based seal/open above.
  You encrypt a file TO another device's HYBRID IDENTITY (an X25519 public key +
  an ML-KEM-768 encapsulation key); only the holder of the matching SECRET
  identity can decrypt it. There is NO shared password.

  !! PRE-AUDIT / UNAUDITED / DEV-ONLY !! The construction is a CUSTOM
  KEM-then-AEAD composition (X25519 + ML-KEM-768 -> shared secret ->
  XChaCha20-Poly1305). It is NOT RFC 9180 HPKE and NOT a standardised scheme; the
  SYSTEM is NOT post-quantum secure. It has NOT been audited and makes NO security
  guarantees. Do NOT use it to protect real secrets.

  Flow (device B receives; device A sends):

    # Device B: generate a hybrid identity. Writes the SECRET id to b.key (0600)
    # and the shareable PUBLIC id to b.key.pub. Share ONLY b.key.pub with senders.
    sigil hybrid-keygen --out b.key

    # Device A: encrypt a file TO B's public identity (no password).
    sigil hybrid-seal --recipient-pub b.key.pub --in secret.txt --out msg.hyb

    # Device B: decrypt with its secret identity.
    sigil hybrid-open --key b.key --in msg.hyb --out secret.txt

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

DEVICE-KEY SIGNING (push/pull) — DEV-ONLY, single device key:
  If the dev sigild is configured with SIGILD_OPLOG_PUBKEY (standard-base64 of a
  32-byte Ed25519 public key), it REQUIRES every op-log request to be SIGNED by
  the matching device key — unsigned or invalid requests get HTTP 401. Otherwise
  signing is OFF and the op-log stays unauthenticated (unchanged).

  Generate a device key once, then point sigild at its public key:

    sigil keygen --out device.key       # writes device.key (mode 0600), prints the public key
    # -> device public key (set sigild SIGILD_OPLOG_PUBKEY to this): <base64>

  Then pass the key on push/pull with --key <file>, or set SIGIL_DEVICE_KEY to
  the key-file path (--key takes precedence over SIGIL_DEVICE_KEY):

    sigil push --vault demo --in secret.sigil --key device.key
    SIGIL_DEVICE_KEY=device.key sigil pull --vault demo --out-dir ./inbox

  HONEST SCOPE: this is a SINGLE device key, DEV-ONLY, over plain HTTP. Requests
  are signed under the CONTRACT v2 message, which binds the method, path, query, a
  unix-seconds timestamp, a FRESH per-request nonce, and the body; sigild rejects
  timestamps skewed more than 300s AND, when it tracks seen nonces, rejects a
  replayed nonce within that window — so a captured request is replay-resistant.
  That replay cache is per-process/in-memory on the server (a multi-instance deploy
  would need a shared store). Device enrollment, a multi-device registry, and JWT
  bearer tokens are all FUTURE work. The signing primitive (Ed25519) is REAL but
  UNAUDITED.

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
  Password container (seal/open):
    magic[8]=\"SIGILcli\" | version:u8=1 | m_cost:u32 | t_cost:u32 | p_cost:u32 |
    salt_len:u8 | salt[salt_len] | envelope[..]
    The Argon2id salt and params are stored in the header (the AEAD nonce travels
    inside the envelope). The salt/params header is unprotected metadata; tampering
    with it makes the record fail to open.

  Hybrid container (hybrid-seal/hybrid-open):
    magic[8]=\"SIGILhyb\" | version:u8=1 | eph_x25519_pub[32] | mlkem_ct[1088] |
    envelope[..]
    The sender's ephemeral X25519 public key and the ML-KEM-768 ciphertext precede
    the seal envelope; the recipient re-derives the shared secret from them plus its
    secret identity. Tampering with any of it makes the record fail to open.
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
        "keygen" => {
            let out = parse_keygen(args)?;
            cmd_keygen(&out)
        }
        "hybrid-keygen" => {
            let out = parse_keygen(args)?;
            cmd_hybrid_keygen(&out)
        }
        "hybrid-seal" => {
            let a = parse_hybrid_seal(args)?;
            cmd_hybrid_seal(&a)
        }
        "hybrid-open" => {
            let a = parse_hybrid_open(args)?;
            cmd_hybrid_open(&a)
        }
        "totp" => cmd_totp(args),
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
    /// Path to the device key file to SIGN the request with: `--key`, else the
    /// `SIGIL_DEVICE_KEY` env var, else `None` (send unsigned).
    key: Option<String>,
}

/// Parsed args for `sigil pull`.
struct PullArgs {
    vault: String,
    /// The start seq override. `Some(n)` means `--since n` was given explicitly
    /// (a one-off re-fetch start); `None` means use the saved incremental cursor.
    since: Option<u64>,
    out_dir: String,
    server: String,
    /// Path to the device key file to SIGN the request with: `--key`, else the
    /// `SIGIL_DEVICE_KEY` env var, else `None` (send unsigned).
    key: Option<String>,
}

/// Resolve the device key-file path: explicit `--key` wins, else the
/// `SIGIL_DEVICE_KEY` env var (empty treated as unset), else `None` (unsigned).
fn resolve_key(flag: Option<String>) -> Option<String> {
    flag.or_else(|| std::env::var(DEVICE_KEY_ENV).ok())
        .filter(|s| !s.is_empty())
}

fn parse_push(mut args: impl Iterator<Item = String>) -> Result<PushArgs, String> {
    let mut vault: Option<String> = None;
    let mut input: Option<String> = None;
    let mut server: Option<String> = None;
    let mut key: Option<String> = None;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--vault" => set_once(&mut vault, &mut args, "--vault")?,
            "--in" => set_once(&mut input, &mut args, "--in")?,
            "--server" => set_once(&mut server, &mut args, "--server")?,
            "--key" => set_once(&mut key, &mut args, "--key")?,
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }

    Ok(PushArgs {
        vault: vault.ok_or_else(|| "missing required --vault <id>".to_string())?,
        input: input.ok_or_else(|| "missing required --in <file>".to_string())?,
        server: resolve_server(server),
        key: resolve_key(key),
    })
}

fn parse_pull(mut args: impl Iterator<Item = String>) -> Result<PullArgs, String> {
    let mut vault: Option<String> = None;
    let mut since_raw: Option<String> = None;
    let mut out_dir: Option<String> = None;
    let mut server: Option<String> = None;
    let mut key: Option<String> = None;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--vault" => set_once(&mut vault, &mut args, "--vault")?,
            "--since" => set_once(&mut since_raw, &mut args, "--since")?,
            "--out-dir" => set_once(&mut out_dir, &mut args, "--out-dir")?,
            "--server" => set_once(&mut server, &mut args, "--server")?,
            "--key" => set_once(&mut key, &mut args, "--key")?,
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
        key: resolve_key(key),
    })
}

/// Parse `sigil keygen --out <file>` from the remaining args. Also used by
/// `hybrid-keygen`, which takes the same single `--out <file>` argument.
fn parse_keygen(mut args: impl Iterator<Item = String>) -> Result<String, String> {
    let mut out: Option<String> = None;
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--out" => set_once(&mut out, &mut args, "--out")?,
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }
    out.ok_or_else(|| "missing required --out <file>".to_string())
}

/// Parsed args for `sigil hybrid-seal`: encrypt `--in` TO the recipient public
/// identity at `--recipient-pub`, writing the hybrid container to `--out`.
struct HybridSealArgs {
    recipient_pub: String,
    input: String,
    output: String,
}

/// Parsed args for `sigil hybrid-open`: decrypt the hybrid container at `--in`
/// with the secret identity at `--key`, writing the plaintext to `--out`.
struct HybridOpenArgs {
    key: String,
    input: String,
    output: String,
}

fn parse_hybrid_seal(mut args: impl Iterator<Item = String>) -> Result<HybridSealArgs, String> {
    let mut recipient_pub: Option<String> = None;
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--recipient-pub" => set_once(&mut recipient_pub, &mut args, "--recipient-pub")?,
            "--in" => set_once(&mut input, &mut args, "--in")?,
            "--out" => set_once(&mut output, &mut args, "--out")?,
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }

    Ok(HybridSealArgs {
        recipient_pub: recipient_pub
            .ok_or_else(|| "missing required --recipient-pub <file>".to_string())?,
        input: input.ok_or_else(|| "missing required --in <file>".to_string())?,
        output: output.ok_or_else(|| "missing required --out <file>".to_string())?,
    })
}

fn parse_hybrid_open(mut args: impl Iterator<Item = String>) -> Result<HybridOpenArgs, String> {
    let mut key: Option<String> = None;
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;

    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--key" => set_once(&mut key, &mut args, "--key")?,
            "--in" => set_once(&mut input, &mut args, "--in")?,
            "--out" => set_once(&mut output, &mut args, "--out")?,
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }

    Ok(HybridOpenArgs {
        key: key.ok_or_else(|| "missing required --key <file>".to_string())?,
        input: input.ok_or_else(|| "missing required --in <file>".to_string())?,
        output: output.ok_or_else(|| "missing required --out <file>".to_string())?,
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

/// Generate a fresh DEV device key, write it to `out` (mode `0600`), and print
/// its public key so the user can set `SIGILD_OPLOG_PUBKEY` to it.
fn cmd_keygen(out: &str) -> Result<(), String> {
    let kf = generate_key().map_err(|e| e.to_string())?;
    let path = std::path::Path::new(out);
    save_key(path, &kf).map_err(|e| e.to_string())?;
    // Echo the public key (base64) for the user to paste into sigild's config.
    println!(
        "wrote device key to {out} (mode 0600)\n\
         device public key (set sigild SIGILD_OPLOG_PUBKEY to this): {}",
        kf.public_key
    );
    Ok(())
}

/// Generate a fresh hybrid identity, writing the SECRET identity to `out` (mode
/// `0600`) and the shareable PUBLIC identity to `<out>.pub`. Prints the `.pub`
/// path and a note to SHARE it with senders.
fn cmd_hybrid_keygen(out: &str) -> Result<(), String> {
    let (secret, public) = generate_hybrid_identity().map_err(|e| e.to_string())?;
    let pub_out = format!("{out}.pub");

    save_hybrid_secret(std::path::Path::new(out), &secret).map_err(|e| e.to_string())?;
    save_hybrid_public(std::path::Path::new(&pub_out), &public).map_err(|e| e.to_string())?;

    println!(
        "wrote hybrid SECRET identity to {out} (mode 0600) — keep it local, it decrypts your messages\n\
         wrote shareable PUBLIC identity to {pub_out}\n\
         SHARE {pub_out} with senders so they can `hybrid-seal --recipient-pub {pub_out}` TO this device"
    );
    Ok(())
}

/// Encrypt `--in` TO the recipient's PUBLIC hybrid identity and write the hybrid
/// container to `--out`. No password (this is the public-key path).
fn cmd_hybrid_seal(a: &HybridSealArgs) -> Result<(), String> {
    let public =
        load_hybrid_public(std::path::Path::new(&a.recipient_pub)).map_err(|e| e.to_string())?;
    let recipient = public.decode().map_err(|e| e.to_string())?;

    let plaintext =
        std::fs::read(&a.input).map_err(|e| format!("could not read input {:?}: {e}", a.input))?;

    let container = hybrid_seal_to_container(&recipient, &plaintext).map_err(|e| e.to_string())?;

    std::fs::write(&a.output, &container)
        .map_err(|e| format!("could not write output {:?}: {e}", a.output))?;
    Ok(())
}

/// Decrypt the hybrid container at `--in` with the SECRET identity at `--key` and
/// write the plaintext to `--out`. No password (this is the public-key path).
fn cmd_hybrid_open(a: &HybridOpenArgs) -> Result<(), String> {
    let secret = load_hybrid_secret(std::path::Path::new(&a.key)).map_err(|e| e.to_string())?;
    let identity = secret.decode().map_err(|e| e.to_string())?;

    let container =
        std::fs::read(&a.input).map_err(|e| format!("could not read input {:?}: {e}", a.input))?;

    // hybrid_open_container never returns plaintext on error, so this is safe.
    let plaintext = hybrid_open_container(&identity, &container).map_err(|e| e.to_string())?;

    std::fs::write(&a.output, &plaintext)
        .map_err(|e| format!("could not write output {:?}: {e}", a.output))?;
    Ok(())
}

/// Load the device-key seed from an optional key-file path. `None` -> `None`
/// (send unsigned); `Some(path)` -> decode the seed, mapping errors to a string.
fn load_seed(key: &Option<String>) -> Result<Option<[u8; sigil_core::SIG_SEED_LEN]>, String> {
    match key {
        None => Ok(None),
        Some(path) => {
            let (seed, _public) =
                load_key(std::path::Path::new(path)).map_err(|e| e.to_string())?;
            Ok(Some(seed))
        }
    }
}

fn cmd_push(p: &PushArgs) -> Result<(), String> {
    let container =
        std::fs::read(&p.input).map_err(|e| format!("could not read input {:?}: {e}", p.input))?;

    // When a device key is configured, SIGN the request (required if sigild has
    // SIGILD_OPLOG_PUBKEY set). push_op still moves OPAQUE bytes; no password.
    let seed = load_seed(&p.key)?;
    let seq = push_op(&p.server, &p.vault, &container, seed.as_ref()).map_err(|e| e.to_string())?;
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

    // When a device key is configured, SIGN the request (required if sigild has
    // SIGILD_OPLOG_PUBKEY set).
    let seed = load_seed(&p.key)?;
    let ops = pull_ops(&p.server, &p.vault, start, seed.as_ref()).map_err(|e| e.to_string())?;

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

// ---------------------------------------------------------------------------
// `sigil totp` — the encrypted TOTP-secret vault (the first product feature).
// ---------------------------------------------------------------------------

/// Resolve the vault path: `--vault <file>` if given, else the default
/// `$HOME/.sigil/totp-vault.sigil` (falling back to the CWD if `$HOME` is unset).
fn resolve_vault_path(flag: Option<String>) -> std::path::PathBuf {
    if let Some(f) = flag {
        return std::path::PathBuf::from(f);
    }
    match std::env::var_os("HOME") {
        Some(home) if !home.is_empty() => std::path::Path::new(&home)
            .join(".sigil")
            .join("totp-vault.sigil"),
        _ => std::path::PathBuf::from("totp-vault.sigil"),
    }
}

/// Read+decrypt the vault at `path`. If the file does not exist, returns an empty
/// vault (used by `add`, so the first add creates the vault).
fn load_vault_or_empty(path: &std::path::Path, password: &[u8]) -> Result<TotpVault, String> {
    match std::fs::read(path) {
        Ok(bytes) => open_vault(password, &bytes).map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TotpVault::default()),
        Err(e) => Err(format!("could not read vault {:?}: {e}", path)),
    }
}

/// Read+decrypt the vault at `path`, erroring if it does not exist (used by
/// `list`/`code`/`remove`, which need an existing vault).
fn load_vault_required(path: &std::path::Path, password: &[u8]) -> Result<TotpVault, String> {
    let bytes = std::fs::read(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!(
                "no vault at {:?}; add an entry first with `sigil totp add`",
                path
            )
        } else {
            format!("could not read vault {:?}: {e}", path)
        }
    })?;
    open_vault(password, &bytes).map_err(|e| e.to_string())
}

/// Seal `vault` under `password` and write it to `path` with mode 0600, creating
/// the parent directory (mode 0700) if needed.
fn save_vault(path: &std::path::Path, password: &[u8], vault: &TotpVault) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| format!("could not create vault dir {:?}: {e}", parent))?;
        }
    }

    let sealed =
        seal_vault(password, vault, Argon2Params::RECOMMENDED).map_err(|e| e.to_string())?;

    // Create with 0600 up front so the sealed vault is never briefly world-readable.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("could not create vault {:?}: {e}", path))?;
    use std::io::Write as _;
    f.write_all(&sealed)
        .map_err(|e| format!("could not write vault {:?}: {e}", path))?;
    // Re-assert 0600 in case the file pre-existed with looser permissions.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("could not set vault permissions {:?}: {e}", path))
}

/// The current wall-clock time as Unix seconds. Native-only; the core reads no
/// clock, so the binary supplies the time.
fn now_unix_secs() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| format!("system clock is before the Unix epoch: {e}"))
}

/// Dispatch `sigil totp <sub> ...`.
fn cmd_totp(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let Some(sub) = args.next() else {
        return Err("missing totp subcommand: add | list | code | remove".to_string());
    };
    let rest: Vec<String> = args.collect();
    match sub.as_str() {
        "add" => cmd_totp_add(rest),
        "list" => cmd_totp_list(rest),
        "code" => cmd_totp_code(rest),
        "remove" => cmd_totp_remove(rest),
        other => Err(format!(
            "unknown totp subcommand {other:?}; try add | list | code | remove"
        )),
    }
}

/// Split the args into an optional leading positional (the `<label>`) plus the
/// flag map. A positional is any leading token that does not start with `--`.
fn take_positional(args: &[String]) -> (Option<String>, &[String]) {
    match args.first() {
        Some(first) if !first.starts_with("--") => (Some(first.clone()), &args[1..]),
        _ => (None, args),
    }
}

/// Pull `--vault <file>` (if present) from a flag list, returning the resolved
/// vault path and the remaining flags.
fn extract_vault_flag(mut flags: Vec<String>) -> Result<(std::path::PathBuf, Vec<String>), String> {
    let mut vault: Option<String> = None;
    let mut rest = Vec::new();
    let mut it = flags.drain(..);
    while let Some(f) = it.next() {
        if f == "--vault" {
            let v = it
                .next()
                .ok_or_else(|| "--vault requires a value".to_string())?;
            if vault.replace(v).is_some() {
                return Err("--vault given more than once".to_string());
            }
        } else {
            rest.push(f);
        }
    }
    Ok((resolve_vault_path(vault), rest))
}

fn cmd_totp_add(args: Vec<String>) -> Result<(), String> {
    let (label, flags) = take_positional(&args);
    let (vault_path, flags) = extract_vault_flag(flags.to_vec())?;

    // Parse the add flags.
    let mut uri: Option<String> = None;
    let mut secret: Option<String> = None;
    let mut issuer: Option<String> = None;
    let mut algorithm: Option<String> = None;
    let mut digits: Option<u32> = None;
    let mut period: Option<u32> = None;

    let mut it = flags.into_iter();
    while let Some(f) = it.next() {
        let mut next = || it.next().ok_or_else(|| format!("{f} requires a value"));
        match f.as_str() {
            "--uri" => uri = Some(next()?),
            "--secret" => secret = Some(next()?),
            "--issuer" => issuer = Some(next()?),
            "--algorithm" => algorithm = Some(next()?),
            "--digits" => {
                digits = Some(
                    next()?
                        .parse()
                        .map_err(|_| "--digits must be an integer".to_string())?,
                )
            }
            "--period" => {
                period = Some(
                    next()?
                        .parse()
                        .map_err(|_| "--period must be an integer".to_string())?,
                )
            }
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }

    let password = password_from_env()?;
    let mut vault = load_vault_or_empty(&vault_path, &password)?;

    let entry = if let Some(uri) = uri {
        // --uri import path: a leading positional label / other flags are ignored
        // in favor of the URI's own fields.
        if secret.is_some() {
            return Err("--uri and --secret are mutually exclusive".to_string());
        }
        parse_otpauth_uri(&uri).map_err(|e| e.to_string())?
    } else {
        let label =
            label.ok_or_else(|| "missing <label> (or use --uri \"otpauth://...\")".to_string())?;
        let secret_b32 = secret.ok_or_else(|| {
            "missing --secret <BASE32> (or use --uri \"otpauth://...\")".to_string()
        })?;
        let secret_bytes = base32_decode(&secret_b32).map_err(|e| e.to_string())?;
        let algo = totp_algorithm_from_str(algorithm.as_deref().unwrap_or("sha1"))
            .map_err(|e| e.to_string())?;
        new_totp_entry(
            &label,
            issuer,
            &secret_bytes,
            algo,
            digits.unwrap_or(TOTP_DEFAULT_DIGITS),
            period.unwrap_or(TOTP_DEFAULT_PERIOD),
        )
        .map_err(|e| e.to_string())?
    };

    let label = entry.label.clone();
    vault.add(entry).map_err(|e| e.to_string())?;
    save_vault(&vault_path, &password, &vault)?;
    println!("added {label:?} to vault {}", vault_path.display());
    Ok(())
}

fn cmd_totp_list(args: Vec<String>) -> Result<(), String> {
    let (vault_path, rest) = extract_vault_flag(args)?;
    if let Some(x) = rest.first() {
        return Err(format!("unexpected argument {x:?}; try `sigil --help`"));
    }
    let password = password_from_env()?;
    let vault = load_vault_required(&vault_path, &password)?;

    if vault.entries.is_empty() {
        println!("vault {} is empty", vault_path.display());
        return Ok(());
    }
    println!(
        "vault {} ({} entries):",
        vault_path.display(),
        vault.entries.len()
    );
    for e in &vault.entries {
        let issuer = e.issuer.as_deref().unwrap_or("-");
        // Never print the secret.
        println!(
            "  {label}  issuer={issuer}  algorithm={algo}  digits={digits}  period={period}s",
            label = e.label,
            algo = e.algorithm,
            digits = e.digits,
            period = e.period,
        );
    }
    Ok(())
}

fn cmd_totp_code(args: Vec<String>) -> Result<(), String> {
    let (label, flags) = take_positional(&args);
    let (vault_path, rest) = extract_vault_flag(flags.to_vec())?;
    if let Some(x) = rest.first() {
        return Err(format!("unexpected argument {x:?}; try `sigil --help`"));
    }
    let label = label.ok_or_else(|| "missing <label>".to_string())?;

    let password = password_from_env()?;
    let vault = load_vault_required(&vault_path, &password)?;
    let entry = vault
        .find(&label)
        .ok_or_else(|| format!("no entry labelled {label:?} in the vault"))?;

    let now = now_unix_secs()?;
    let (code, remaining) = entry.code_at(now).map_err(|e| e.to_string())?;
    println!("{code}  (valid for {remaining}s)");
    Ok(())
}

fn cmd_totp_remove(args: Vec<String>) -> Result<(), String> {
    let (label, flags) = take_positional(&args);
    let (vault_path, rest) = extract_vault_flag(flags.to_vec())?;
    if let Some(x) = rest.first() {
        return Err(format!("unexpected argument {x:?}; try `sigil --help`"));
    }
    let label = label.ok_or_else(|| "missing <label>".to_string())?;

    let password = password_from_env()?;
    let mut vault = load_vault_required(&vault_path, &password)?;
    vault.remove(&label).map_err(|e| e.to_string())?;
    save_vault(&vault_path, &password, &vault)?;
    println!("removed {label:?} from vault {}", vault_path.display());
    Ok(())
}
