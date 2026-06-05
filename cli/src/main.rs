//! `sigil` — a pre-audit demonstration CLI that seals/opens one file with the
//! real-but-UNAUDITED libsigil `sigil-core` record API.
//!
//! STATUS: pre-audit. UNAUDITED cryptography. Demonstration of the libsigil
//! building block only. Do NOT use it to protect real secrets.
//!
//! Arg parsing is hand-rolled on `std::env` (no clap). See [`HELP`] for usage.

#![forbid(unsafe_code)]

use std::process::ExitCode;

use sigil_cli::{open_container, seal_to_container};
use sigil_core::Argon2Params;

/// Environment variable the password is read from. Empty/unset is a hard error.
const PASSWORD_ENV: &str = "SIGIL_PASSWORD";

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
  sigil --help                           Show this help
  sigil --version                        Show the version

PASSWORD:
  The password is read from the SIGIL_PASSWORD environment variable. If it is
  unset or empty, the command fails immediately (it never prompts and never
  hangs). Example:

    SIGIL_PASSWORD='correct horse battery staple' sigil seal --in secret.txt --out secret.sigil
    SIGIL_PASSWORD='correct horse battery staple' sigil open --in secret.sigil --out secret.txt

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
        other => Err(format!(
            "unknown command {other:?}; try `sigil --help`\n\n{HELP}"
        )),
    }
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
