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
    base32_decode, cursor_key, decode_migration_uri, encode_migration_uri, enroll_device,
    entry_to_migration_otp, entry_to_otpauth_uri, generate_hybrid_identity, generate_key,
    grant_vault_access, hybrid_open_container, hybrid_seal_to_container, list_devices,
    load_hybrid_public, load_hybrid_secret, load_identity, load_key_file, migration_otp_to_entry,
    new_totp_entry, open_container, open_vault, parse_otpauth_uri, pull_ops_auth, push_op_auth,
    read_cursor, revoke_device, save_hybrid_public, save_hybrid_secret, save_key,
    seal_to_container, seal_vault, totp_algorithm_from_str, write_cursor, CliError, DeviceIdentity,
    ImportedOtp, RequestAuth, TotpEntry, TotpVault, PULL_STATE_FILE, TOTP_DEFAULT_DIGITS,
    TOTP_DEFAULT_PERIOD,
};
use sigil_core::Argon2Params;

/// Environment variable the password is read from. Empty/unset is a hard error.
const PASSWORD_ENV: &str = "SIGIL_PASSWORD";

/// Environment variable for the dev sigild base URL (overridden by --server).
const SERVER_ENV: &str = "SIGIL_SERVER";

/// Default dev sigild base URL when neither --server nor SIGIL_SERVER is set.
const DEFAULT_SERVER: &str = "http://127.0.0.1:8080";

/// Environment variable giving the path to the device key / identity file used to
/// SIGN op-log requests (overridden by `--key`).
const DEVICE_KEY_ENV: &str = "SIGIL_DEVICE_KEY";

/// Environment variable that supplies (or overrides) the enrolled DEVICE ID.
/// Setting it forces contract v3 signing even for an identity file that has no
/// `device_id` yet. Unset/empty means "use whatever the identity file says".
const DEVICE_ID_ENV: &str = "SIGIL_DEVICE_ID";

/// Environment variable for the operator ADMIN token used by
/// `sigil device list` / `sigil device revoke` (overridden by `--admin-token`).
/// It is a BEARER SECRET and is never printed.
const ADMIN_TOKEN_ENV: &str = "SIGIL_ADMIN_TOKEN";

/// Environment variable for the single-use device ENROLLMENT token (overridden by
/// `--token`). It is a BEARER SECRET and is never printed.
const ENROLL_TOKEN_ENV: &str = "SIGIL_ENROLL_TOKEN";

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
  sigil totp import <ARG> [--vault <file>]
                                         Import 2FA secrets: <ARG> is an
                                         otpauth-migration:// URI (Google Authenticator bulk
                                         export), an otpauth:// URI, or a file with one URI per line
  sigil totp export [<label>] [--vault <file>] [--migration] [--out <file>]
                                         Export entries as otpauth:// URIs (or ONE
                                         otpauth-migration:// URI with --migration). PRINTS SECRETS.
  sigil keygen --out <file>              Generate a DEV device key (0600) and print its public key
  sigil device enroll --token <t> [--label <name>] [--key <file>] [--server <url>] [--reuse-key]
                                         Enroll this device with sigild; writes the identity (0600)
  sigil device list --admin-token <t> [--server <url>]
                                         List enrolled devices (operator admin token)
  sigil device revoke <deviceID> [--admin-token <t>] [--key <file>] [--server <url>]
                                         Revoke a device (self, v3-signed, or operator admin token)
  sigil device grant <deviceID> --vault <id> --permission read|write [--key <file>] [--server <url>]
                                         Grant another device access to YOUR vault (owner only)
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

TOTP IMPORT / EXPORT (totp import/export) — migrate 2FA in and out:
  import ingests either a Google Authenticator bulk-export migration URI
  (otpauth-migration://offline?data=<BASE64>, hand-rolled protobuf decode), a
  single otpauth:// URI, or a text file with one such URI per line. HOTP entries
  and duplicate labels are SKIPPED; the vault is re-sealed with any new TOTP
  entries. export is the inverse: it prints each entry as an otpauth:// URI, or —
  with --migration — one otpauth-migration:// URI holding them all.

    sigil totp import \"otpauth-migration://offline?data=CjUK...AB\"
    sigil totp import ./exported-uris.txt
    sigil totp export                     # every entry as otpauth:// URIs
    sigil totp export work                # just the 'work' entry
    sigil totp export --migration         # ONE migration URI for all entries
    sigil totp export --migration --out backup.txt   # write to a 0600 file

  !! export prints your SECRETS IN THE CLEAR (that is what a 2FA export is). It
  warns on stderr; treat the output like a password. !!

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
  would need a shared store). The signing primitive (Ed25519) is REAL but UNAUDITED.

MULTI-DEVICE AUTH (sigil device ...) — CONTRACT v3, DEV-ONLY:
  A sigild started with SIGILD_DEVICE_AUTH=1 (plus SIGILD_ENABLE_DEV_OPS=1 and
  SIGILD_ENROLL_TOKENS=<...>) runs a real device registry instead of the single
  v2 key: each device ENROLLS, gets a device ID, signs every request under the
  CONTRACT v3 message (which additionally binds that device ID and is sent with
  X-Sigil-Device), and is authorized PER VAULT. The first device to WRITE an
  unclaimed vault becomes its owner; any other device gets 403 until granted.

  CONTRACT SELECTION is automatic and additive:
    no --key/SIGIL_DEVICE_KEY        -> unsigned      (unchanged legacy behaviour)
    identity file WITHOUT device_id  -> contract v2   (unchanged legacy behaviour)
    identity file WITH device_id     -> contract v3   (after `device enroll`)
  Setting SIGIL_DEVICE_ID=<id> forces v3 with that ID even for an older key file.

  The identity file is the SAME 0600 JSON as `sigil keygen` writes, EXTENDED with
  an optional \"device_id\" that `device enroll` fills in — an old key file still
  works untouched. The default identity path is $HOME/.sigil/device.key. The seed
  is never printed; enrollment/admin tokens are never printed or logged.

    # operator: sigild with SIGILD_DEVICE_AUTH=1 SIGILD_ENROLL_TOKENS=tokA,tokB
    sigil device enroll --token tokA --label laptop --key ./a.key
    # -> enrolled device dev_XXXX (identity written to ./a.key, mode 0600)

    sigil push --vault demo --in secret.sigil --key ./a.key   # A claims 'demo'
    sigil pull --vault demo --out-dir ./inbox --key ./a.key

    # a second device is 403 on A's vault until A grants it:
    sigil device enroll --token tokB --label phone --key ./b.key
    sigil device grant <B_ID> --vault demo --permission read --key ./a.key
    sigil pull --vault demo --out-dir ./inbox-b --key ./b.key

    # revoke: the device itself (v3-signed) or the operator admin token
    sigil device revoke <B_ID> --key ./b.key
    sigil device revoke <B_ID> --admin-token \"$SIGIL_ADMIN_TOKEN\"
    sigil device list --admin-token \"$SIGIL_ADMIN_TOKEN\"

  Enrollment tokens are SINGLE-USE (a failed attempt burns one) and are bound into
  the signed enrollment challenge only as their SHA-256 digest. Enrollment proves
  possession of the device private key. HONEST SCOPE: dev/localhost/plain HTTP,
  UNAUDITED; no account model, no key rotation, no recovery.

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
        "device" => cmd_device(args),
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

/// Load the device IDENTITY from an optional key-file path.
///
/// `None` -> `Ok(None)` (send unsigned — the EXACT legacy behaviour when neither
/// `--key` nor `SIGIL_DEVICE_KEY` is set). `Some(path)` -> decode the identity;
/// its `device_id` (or `SIGIL_DEVICE_ID`, which overrides it) is what later
/// selects contract v3 over the legacy v2.
fn load_identity_opt(key: &Option<String>) -> Result<Option<DeviceIdentity>, String> {
    let Some(path) = key else { return Ok(None) };
    let mut id = load_identity(std::path::Path::new(path)).map_err(|e| e.to_string())?;
    if let Some(env_id) = std::env::var(DEVICE_ID_ENV).ok().filter(|s| !s.is_empty()) {
        id.device_id = Some(env_id);
    }
    Ok(Some(id))
}

/// The [`RequestAuth`] for an optional identity: no identity -> unsigned;
/// identity without a device ID -> legacy v2; with one -> contract v3.
fn auth_for(identity: &Option<DeviceIdentity>) -> RequestAuth<'_> {
    match identity {
        Some(id) => id.auth(),
        None => RequestAuth::None,
    }
}

/// Turn a sync error into an actionable message, distinguishing the two auth
/// verdicts sigild can return: `401` = the request was not authenticated at all
/// (missing/invalid/replayed signature, unknown or revoked device), `403` = it WAS
/// authenticated but this device holds no sufficient grant on that vault.
fn explain_sync_error(e: CliError, vault: &str, contract: &str) -> String {
    match &e {
        CliError::Server { status: 401, .. } => format!(
            "{e}\n  -> HTTP 401: sigild did not accept this request's credentials (contract {contract}).\n     \
             Check that the device is enrolled and not revoked, that --key/SIGIL_DEVICE_KEY points at the\n     \
             enrolled identity, and that the clock is within 300s of the server."
        ),
        CliError::Server { status: 403, .. } => format!(
            "{e}\n  -> HTTP 403: this device IS authenticated but is NOT authorized for vault {vault:?}.\n     \
             The vault is owned by another device. Ask its owner to run:\n       \
             sigil device grant <THIS_DEVICE_ID> --vault {vault} --permission read|write"
        ),
        _ => e.to_string(),
    }
}

fn cmd_push(p: &PushArgs) -> Result<(), String> {
    let container =
        std::fs::read(&p.input).map_err(|e| format!("could not read input {:?}: {e}", p.input))?;

    // When a device identity is configured, SIGN the request: contract v3 if the
    // identity is enrolled (has a device ID), else the LEGACY v2 contract. With no
    // identity the request is unsigned, exactly as before. Either way push moves
    // OPAQUE bytes; no password, no plaintext.
    let identity = load_identity_opt(&p.key)?;
    let auth = auth_for(&identity);
    let seq = push_op_auth(&p.server, &p.vault, &container, &auth)
        .map_err(|e| explain_sync_error(e, &p.vault, auth.contract()))?;
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

    // When a device identity is configured, SIGN the request: contract v3 if the
    // identity is enrolled, else the LEGACY v2 contract; unsigned with no identity.
    let identity = load_identity_opt(&p.key)?;
    let auth = auth_for(&identity);
    let ops = pull_ops_auth(&p.server, &p.vault, start, &auth)
        .map_err(|e| explain_sync_error(e, &p.vault, auth.contract()))?;

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
// `sigil device` — the CLIENT side of sigild's MULTI-DEVICE auth model
// (contract v3): enroll / list / revoke / grant.
//
// DEV-ONLY, UNAUDITED, plain HTTP. Every secret here (the device seed, the
// enrollment token, the admin token) is kept out of stdout/stderr: we print
// device IDs, labels and statuses only.
// ---------------------------------------------------------------------------

/// Resolve the device identity path: `--key <file>`, else `SIGIL_DEVICE_KEY`,
/// else the default `$HOME/.sigil/device.key` (falling back to the CWD if `$HOME`
/// is unset).
///
/// NOTE: this default applies ONLY to the `device` subcommands. push/pull keep
/// their existing rule (no `--key` and no `SIGIL_DEVICE_KEY` => send UNSIGNED),
/// so their legacy behaviour is untouched.
fn resolve_identity_path(flag: Option<String>) -> std::path::PathBuf {
    if let Some(p) = resolve_key(flag) {
        return std::path::PathBuf::from(p);
    }
    match std::env::var_os("HOME") {
        Some(home) if !home.is_empty() => std::path::Path::new(&home)
            .join(".sigil")
            .join("device.key"),
        _ => std::path::PathBuf::from("device.key"),
    }
}

/// Read a token from an explicit flag, else the given environment variable.
/// Tokens are BEARER SECRETS: this never echoes the value.
fn resolve_token(flag: Option<String>, env: &str) -> Option<String> {
    flag.or_else(|| std::env::var(env).ok())
        .filter(|s| !s.is_empty())
}

/// Parsed flags shared by the `device` subcommands. Unknown flags are rejected by
/// the caller, so each subcommand validates the combination it needs.
#[derive(Default)]
struct DeviceFlags {
    server: Option<String>,
    key: Option<String>,
    token: Option<String>,
    admin_token: Option<String>,
    label: Option<String>,
    vault: Option<String>,
    permission: Option<String>,
    reuse_key: bool,
}

/// Parse the `device` subcommand flags (order-independent), rejecting anything
/// unknown or repeated.
fn parse_device_flags(args: Vec<String>) -> Result<DeviceFlags, String> {
    let mut f = DeviceFlags::default();
    let mut it = args.into_iter();
    while let Some(flag) = it.next() {
        match flag.as_str() {
            "--server" => set_once(&mut f.server, &mut it, "--server")?,
            "--key" => set_once(&mut f.key, &mut it, "--key")?,
            "--token" => set_once(&mut f.token, &mut it, "--token")?,
            "--admin-token" => set_once(&mut f.admin_token, &mut it, "--admin-token")?,
            "--label" => set_once(&mut f.label, &mut it, "--label")?,
            "--vault" => set_once(&mut f.vault, &mut it, "--vault")?,
            "--permission" => set_once(&mut f.permission, &mut it, "--permission")?,
            "--reuse-key" => f.reuse_key = true,
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }
    Ok(f)
}

/// Dispatch `sigil device <sub> ...`.
fn cmd_device(mut args: impl Iterator<Item = String>) -> Result<(), String> {
    let Some(sub) = args.next() else {
        return Err("missing device subcommand: enroll | list | revoke | grant".to_string());
    };
    let rest: Vec<String> = args.collect();
    let (positional, flags) = take_positional(&rest);
    let f = parse_device_flags(flags.to_vec())?;

    match sub.as_str() {
        "enroll" => cmd_device_enroll(&f),
        "list" => cmd_device_list(&f),
        "revoke" => cmd_device_revoke(positional, &f),
        "grant" => cmd_device_grant(positional, &f),
        other => Err(format!(
            "unknown device subcommand {other:?}; try enroll | list | revoke | grant"
        )),
    }
}

/// Explain a device-route HTTP failure in terms of what the operator can do.
/// Never echoes a token.
fn explain_device_error(e: CliError, what: &str) -> String {
    match &e {
        CliError::Server { status: 401, .. } => format!(
            "{e}\n  -> HTTP 401: sigild rejected the credentials for {what}. Enrollment tokens are\n     \
             SINGLE-USE and time-limited, the admin token must match SIGILD_ADMIN_TOKEN exactly, and the\n     \
             clock must be within 300s of the server."
        ),
        CliError::Server { status: 403, .. } => format!(
            "{e}\n  -> HTTP 403: authenticated, but not permitted to {what}. A device may only revoke\n     \
             ITSELF, and only a vault's OWNER may grant access to it."
        ),
        CliError::Server { status: 409, .. } => format!(
            "{e}\n  -> HTTP 409: that public key is already enrolled. Use the existing identity file, or\n     \
             enroll a FRESH key (drop --reuse-key / choose a new --key path)."
        ),
        CliError::Server { status: 501, .. } => format!(
            "{e}\n  -> HTTP 501: this sigild does not have the device model enabled. Start it with\n     \
             SIGILD_ENABLE_DEV_OPS=1 SIGILD_DEVICE_AUTH=1 SIGILD_ENROLL_TOKENS=<token,...>."
        ),
        _ => e.to_string(),
    }
}

/// `sigil device enroll --token <t> [--label <name>] [--key <file>] [--reuse-key]`
///
/// Generates a FRESH Ed25519 key pair (or reuses the existing identity file with
/// `--reuse-key`), proves possession of it against the enrollment challenge, and
/// on success writes the identity file (mode 0600) INCLUDING the server-assigned
/// device ID. Prints the device ID; never the seed and never the token.
fn cmd_device_enroll(f: &DeviceFlags) -> Result<(), String> {
    if f.vault.is_some() || f.permission.is_some() || f.admin_token.is_some() {
        return Err("device enroll takes --token/--label/--key/--server/--reuse-key only".into());
    }
    let token = resolve_token(f.token.clone(), ENROLL_TOKEN_ENV).ok_or_else(|| {
        format!("missing required --token <enrollment-token> (or set {ENROLL_TOKEN_ENV})")
    })?;
    let server = resolve_server(f.server.clone());
    let path = resolve_identity_path(f.key.clone());
    let label = f.label.clone().unwrap_or_default();

    // Choose the key: reuse the existing identity file on request, else generate a
    // fresh pair. We NEVER silently overwrite an existing identity — that would
    // destroy a device's only credential.
    let key_file = if f.reuse_key {
        load_key_file(&path).map_err(|e| e.to_string())?
    } else {
        if path.exists() {
            return Err(format!(
                "identity file {} already exists; pass --reuse-key to enroll that key, \
                 or --key <other-file> to enroll a fresh one",
                path.display()
            ));
        }
        generate_key().map_err(|e| e.to_string())?
    };

    let identity = key_file.decode().map_err(|e| e.to_string())?;

    let dev = enroll_device(
        &server,
        &token,
        &label,
        &identity.public_key,
        &identity.seed,
    )
    .map_err(|e| explain_device_error(e, "device enrollment"))?;

    // Persist the assigned device ID alongside the key (mode 0600). Creating the
    // parent dir 0700 mirrors the TOTP vault's handling of $HOME/.sigil.
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(parent)
                .map_err(|e| format!("could not create identity dir {:?}: {e}", parent))?;
        }
    }
    let mut stored = key_file;
    stored.device_id = Some(dev.device_id.clone());
    save_key(&path, &stored).map_err(|e| e.to_string())?;

    println!(
        "enrolled device {id} (label {label:?}, status {status})\n\
         identity written to {path} (mode 0600) — push/pull with this --key now sign under contract v3",
        id = dev.device_id,
        status = dev.status,
        path = path.display(),
    );
    Ok(())
}

/// `sigil device list --admin-token <t>` — operator-only listing.
fn cmd_device_list(f: &DeviceFlags) -> Result<(), String> {
    if f.token.is_some() || f.vault.is_some() || f.permission.is_some() {
        return Err("device list takes --admin-token/--server only".into());
    }
    let admin = resolve_token(f.admin_token.clone(), ADMIN_TOKEN_ENV).ok_or_else(|| {
        format!("missing required --admin-token <token> (or set {ADMIN_TOKEN_ENV}); listing devices is operator-only")
    })?;
    let server = resolve_server(f.server.clone());

    let devices =
        list_devices(&server, &admin).map_err(|e| explain_device_error(e, "listing devices"))?;
    if devices.is_empty() {
        println!("no devices enrolled");
        return Ok(());
    }
    println!("{} device(s):", devices.len());
    for d in &devices {
        let revoked = d.revoked_at.as_deref().unwrap_or("-");
        println!(
            "  {id}  status={status}  label={label:?}  created={created}  revoked={revoked}",
            id = d.device_id,
            status = d.status,
            label = d.label,
            created = d.created_at,
        );
    }
    Ok(())
}

/// `sigil device revoke <deviceID> [--admin-token <t>] [--key <file>]`
///
/// Authorized EITHER by the operator admin token (may revoke any device) OR by the
/// device itself (a contract v3 signature whose device ID IS `<deviceID>`).
fn cmd_device_revoke(target: Option<String>, f: &DeviceFlags) -> Result<(), String> {
    if f.token.is_some() || f.vault.is_some() || f.permission.is_some() {
        return Err("device revoke takes <deviceID> plus --admin-token/--key/--server only".into());
    }
    let target = target.ok_or_else(|| "missing <deviceID> to revoke".to_string())?;
    let server = resolve_server(f.server.clone());
    let admin = resolve_token(f.admin_token.clone(), ADMIN_TOKEN_ENV);

    // Self-revocation needs the device's own identity; with an admin token the
    // identity is optional.
    let identity = match (&admin, resolve_key(f.key.clone())) {
        (_, Some(path)) => {
            Some(load_identity(std::path::Path::new(&path)).map_err(|e| e.to_string())?)
        }
        (Some(_), None) => None,
        (None, None) => {
            return Err(format!(
                "revoking needs a credential: either --admin-token <t> (or {ADMIN_TOKEN_ENV}) \
                 or --key <identity-file> for SELF-revocation"
            ))
        }
    };
    if let (None, Some(id)) = (&admin, &identity) {
        if id.device_id.as_deref() != Some(target.as_str()) {
            return Err(format!(
                "that identity is device {:?}, not {target:?}; a device may only revoke ITSELF \
                 (use --admin-token to revoke another device)",
                id.device_id.as_deref().unwrap_or("<not enrolled>")
            ));
        }
    }
    let auth = auth_for(&identity);

    let dev = revoke_device(&server, &target, &auth, admin.as_deref())
        .map_err(|e| explain_device_error(e, "revoking a device"))?;
    println!("revoked device {} (status {})", dev.device_id, dev.status);
    Ok(())
}

/// `sigil device grant <deviceID> --vault <id> --permission read|write`
///
/// OWNER-ONLY: signed under contract v3 by the identity that owns `--vault`.
fn cmd_device_grant(target: Option<String>, f: &DeviceFlags) -> Result<(), String> {
    if f.token.is_some() || f.admin_token.is_some() {
        return Err(
            "device grant takes <deviceID> plus --vault/--permission/--key/--server only".into(),
        );
    }
    let target = target.ok_or_else(|| "missing <deviceID> to grant access to".to_string())?;
    let vault = f
        .vault
        .clone()
        .ok_or_else(|| "missing required --vault <id>".to_string())?;
    let permission = f
        .permission
        .clone()
        .ok_or_else(|| "missing required --permission read|write".to_string())?;
    let server = resolve_server(f.server.clone());

    let path = resolve_identity_path(f.key.clone());
    let identity = load_identity(&path).map_err(|e| e.to_string())?;
    if identity.device_id.is_none() {
        return Err(format!(
            "identity {} has no device_id: run `sigil device enroll` first (granting is a \
             contract v3, owner-only operation)",
            path.display()
        ));
    }
    let identity = Some(identity);
    let auth = auth_for(&identity);

    grant_vault_access(&server, &vault, &target, &permission, &auth)
        .map_err(|e| explain_device_error(e, "granting vault access"))?;
    println!("granted {target} {permission} access to vault {vault}");
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
        "import" => cmd_totp_import(rest),
        "export" => cmd_totp_export(rest),
        other => Err(format!(
            "unknown totp subcommand {other:?}; try add | list | code | remove | import | export"
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

/// Collect the TOTP entries carried by a single `otpauth-migration://` or
/// `otpauth://` URI, appending to `entries` and bumping the skip counters.
/// A malformed migration/otpauth URI is counted as invalid (not fatal), so a
/// bulk import of many URIs keeps going.
fn collect_from_uri(
    uri: &str,
    entries: &mut Vec<TotpEntry>,
    skipped_hotp: &mut usize,
    skipped_invalid: &mut usize,
) -> Result<(), String> {
    let lower = uri.to_ascii_lowercase();
    if lower.starts_with("otpauth-migration://") {
        // Bulk export: one URI, many accounts. A bad payload is fatal for THIS
        // URI (we cannot parse further), but per-account mapping errors are not.
        let params = decode_migration_uri(uri).map_err(|e| e.to_string())?;
        for p in &params {
            match migration_otp_to_entry(p) {
                Ok(ImportedOtp::Totp(e)) => entries.push(*e),
                Ok(ImportedOtp::SkippedHotp) => {
                    eprintln!(
                        "sigil: skipping HOTP entry {:?} (the vault stores TOTP only)",
                        p.name
                    );
                    *skipped_hotp += 1;
                }
                Err(e) => {
                    eprintln!("sigil: skipping invalid entry {:?}: {e}", p.name);
                    *skipped_invalid += 1;
                }
            }
        }
        Ok(())
    } else if lower.starts_with("otpauth://") {
        match parse_otpauth_uri(uri) {
            Ok(e) => {
                entries.push(e);
                Ok(())
            }
            Err(e) => {
                eprintln!("sigil: skipping invalid otpauth URI: {e}");
                *skipped_invalid += 1;
                Ok(())
            }
        }
    } else {
        Err(format!(
            "unrecognized entry (not otpauth:// or otpauth-migration://): {uri:?}"
        ))
    }
}

/// `sigil totp import <ARG> [--vault <file>]` — import 2FA secrets.
///
/// `<ARG>` is an `otpauth-migration://offline?data=…` URI (Google Authenticator
/// bulk export), a single `otpauth://totp/…` URI, or a PATH to a file with one
/// such URI per line (`#` comments and blank lines ignored). Duplicate labels
/// (already present in the vault) are SKIPPED, not overwritten. HOTP entries and
/// unparseable/invalid entries are skipped. The vault is re-sealed only if at
/// least one entry was imported.
fn cmd_totp_import(args: Vec<String>) -> Result<(), String> {
    let (arg, flags) = take_positional(&args);
    let arg = arg.ok_or_else(|| {
        "missing <ARG>: an otpauth-migration:// URI, an otpauth:// URI, or a file path".to_string()
    })?;
    let (vault_path, rest) = extract_vault_flag(flags.to_vec())?;
    if let Some(x) = rest.first() {
        return Err(format!("unexpected argument {x:?}; try `sigil --help`"));
    }

    let password = password_from_env()?;
    let mut vault = load_vault_or_empty(&vault_path, &password)?;

    // Resolve the arg to a list of URI strings: a URI is used directly; anything
    // else is treated as a file with one URI per line.
    let lower = arg.to_ascii_lowercase();
    let uris: Vec<String> =
        if lower.starts_with("otpauth-migration://") || lower.starts_with("otpauth://") {
            vec![arg.clone()]
        } else {
            let text = std::fs::read_to_string(&arg)
                .map_err(|e| format!("could not read import file {arg:?}: {e}"))?;
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_string)
                .collect()
        };

    let mut entries: Vec<TotpEntry> = Vec::new();
    let mut skipped_hotp = 0usize;
    let mut skipped_invalid = 0usize;
    for uri in &uris {
        collect_from_uri(uri, &mut entries, &mut skipped_hotp, &mut skipped_invalid)?;
    }

    // De-dup by label against the existing vault (and within this batch): SKIP a
    // label that already exists rather than overwrite it.
    let mut imported = 0usize;
    let mut skipped_dup = 0usize;
    for e in entries {
        if vault.find(&e.label).is_some() {
            eprintln!("sigil: skipping {:?}: already in the vault", e.label);
            skipped_dup += 1;
            continue;
        }
        vault.add(e).map_err(|e| e.to_string())?;
        imported += 1;
    }

    if imported > 0 {
        save_vault(&vault_path, &password, &vault)?;
    }
    println!(
        "imported {imported} into {} ({} duplicate, {} HOTP, {} invalid skipped)",
        vault_path.display(),
        skipped_dup,
        skipped_hotp,
        skipped_invalid
    );
    Ok(())
}

/// `sigil totp export [<label>] [--vault <file>] [--migration] [--out <file>]`.
///
/// Default: print each entry (or just `<label>`) as an `otpauth://totp/…` URI.
/// With `--migration`: emit ALL selected entries as ONE
/// `otpauth-migration://offline?data=…` URI. The output carries SECRETS in the
/// clear, so a LOUD warning is printed to stderr first. Output goes to stdout
/// unless `--out <file>` is given (written mode 0600).
fn cmd_totp_export(args: Vec<String>) -> Result<(), String> {
    let (label, flags) = take_positional(&args);
    let (vault_path, rest) = extract_vault_flag(flags.to_vec())?;

    let mut migration = false;
    let mut out: Option<String> = None;
    let mut it = rest.into_iter();
    while let Some(f) = it.next() {
        match f.as_str() {
            "--migration" => migration = true,
            "--out" => {
                out = Some(
                    it.next()
                        .ok_or_else(|| "--out requires a value".to_string())?,
                )
            }
            other => return Err(format!("unexpected argument {other:?}; try `sigil --help`")),
        }
    }

    let password = password_from_env()?;
    let vault = load_vault_required(&vault_path, &password)?;

    let selected: Vec<&TotpEntry> = match &label {
        Some(l) => vec![vault
            .find(l)
            .ok_or_else(|| format!("no entry labelled {l:?} in the vault"))?],
        None => vault.entries.iter().collect(),
    };
    if selected.is_empty() {
        return Err("vault is empty; nothing to export".to_string());
    }

    // LOUD warning: an export is plaintext secret material.
    eprintln!(
        "!! WARNING: this export contains your TOTP SECRETS IN THE CLEAR. Anyone who reads it can\n\
         !! generate your codes. Treat the output like a password — do not paste it into logs,\n\
         !! chats, or shared terminals. !!"
    );

    let output = if migration {
        let mut otps = Vec::with_capacity(selected.len());
        for e in &selected {
            otps.push(entry_to_migration_otp(e).map_err(|err| err.to_string())?);
        }
        encode_migration_uri(&otps)
    } else {
        let mut lines = Vec::with_capacity(selected.len());
        for e in &selected {
            lines.push(entry_to_otpauth_uri(e).map_err(|err| err.to_string())?);
        }
        lines.join("\n")
    };

    match out {
        Some(path) => {
            use std::io::Write as _;
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            let p = std::path::Path::new(&path);
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(p)
                .map_err(|e| format!("could not create export file {path:?}: {e}"))?;
            f.write_all(output.as_bytes())
                .map_err(|e| format!("could not write export file {path:?}: {e}"))?;
            f.write_all(b"\n")
                .map_err(|e| format!("could not write export file {path:?}: {e}"))?;
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("could not set export permissions {path:?}: {e}"))?;
            println!(
                "wrote {} entr{} to {path} (mode 0600)",
                selected.len(),
                if selected.len() == 1 { "y" } else { "ies" }
            );
        }
        None => println!("{output}"),
    }
    Ok(())
}
