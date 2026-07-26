//! THE INTEROP PROOF — the desktop (native) column and the `sigil` CLI share one
//! vault.
//!
//! This is the headline claim of the native column: a vault written by the
//! desktop app opens in the REAL `sigil` binary, and a vault written by `sigil
//! totp add` opens in the desktop code — same sealed `SIGILcli` container, same
//! `TotpVault` JSON schema, same codes.
//!
//! The test does the whole thing without a human:
//!
//! 1. builds the real CLI (`cargo build --manifest-path ../cli/Cargo.toml --bin sigil`),
//! 2. **A: DESKTOP → CLI** — the desktop code creates the vault and adds an
//!    account; `sigil totp list` sees it and `sigil totp code` prints the code the
//!    desktop computed,
//! 3. **B: CLI → DESKTOP** — `sigil totp add` appends a second account to that
//!    SAME file; the desktop code re-unlocks it and reproduces the CLI's code,
//! 4. and both directions are checked against `sigil totp export`, so the
//!    `otpauth://` layer agrees too.
//!
//! ## Pinning the clock
//!
//! `sigil totp code` reads the host clock and has no `--at` flag, so an exact
//! assertion needs a code that does not move. The trick is the **time step**: an
//! account with `period = u32::MAX` (≈136 years) has TOTP counter
//! `T = floor(now / period) = 0` for every `now` before the year 2106, so its code
//! is a fixed value that both sides must agree on exactly. A second account with
//! the ordinary 30 s period is cross-checked with a bounded re-read that tolerates
//! a step boundary landing between the two processes.

use std::path::{Path, PathBuf};
use std::process::Command;

use sigil_desktop_core::{now_unix, VaultSession};

/// ASCII "12345678901234567890" (the RFC 4226 / RFC 6238 test seed) in base32.
const RFC_SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PASSWORD: &str = "interop test password, not a real one";

/// A period so long the TOTP counter stays 0 for the next century, which makes
/// the code a constant that two independently-clocked processes must agree on.
const PINNED_PERIOD: u32 = u32::MAX;

/// `<repo>/desktop/core` -> `<repo>`.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root is two levels above desktop/core")
        .to_path_buf()
}

/// Build the REAL `sigil` binary and return its path.
fn build_sigil() -> PathBuf {
    let root = repo_root();
    let manifest = root.join("cli/Cargo.toml");
    let out = Command::new(env!("CARGO"))
        .args(["build", "--manifest-path"])
        .arg(&manifest)
        .args(["--bin", "sigil"])
        // Do NOT inherit this test run's CARGO_TARGET_DIR / RUSTFLAGS-driven env:
        // the CLI is a separate workspace with its own lockfile.
        .env_remove("CARGO_TARGET_DIR")
        .output()
        .expect("could not run cargo to build the sigil CLI");
    assert!(
        out.status.success(),
        "building the sigil CLI failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let bin = root.join("cli/target/debug/sigil");
    assert!(
        bin.exists(),
        "expected the sigil binary at {}",
        bin.display()
    );
    bin
}

/// Run `sigil <args...>` with the vault password in the environment, asserting
/// success and returning stdout.
fn sigil(bin: &Path, args: &[&str]) -> String {
    let out = Command::new(bin)
        .args(args)
        .env("SIGIL_PASSWORD", PASSWORD)
        .output()
        .expect("could not run the sigil binary");
    assert!(
        out.status.success(),
        "`sigil {}` failed:\nstdout: {}\nstderr: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Pull the leading code out of `sigil totp code`'s `"<code>  (valid for Ns)"`.
fn parse_code_line(stdout: &str) -> String {
    stdout
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string()
}

fn scratch_vault() -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sigil-desktop-interop-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir.join("totp-vault.sigil")
}

#[test]
fn desktop_and_cli_share_one_vault_in_both_directions() {
    let bin = build_sigil();
    let vault_path = scratch_vault();
    let vault_arg = vault_path.to_str().expect("utf-8 path").to_string();

    // -----------------------------------------------------------------------
    // A. DESKTOP WRITES -> THE REAL `sigil` BINARY READS
    // -----------------------------------------------------------------------
    let (desktop_pinned_code, desktop_rfc_uri) = {
        let mut s = VaultSession::create(&vault_path, PASSWORD.as_bytes()).expect("desktop create");
        s.add_secret_base32(
            "desktop-pinned",
            Some("DesktopColumn".into()),
            RFC_SEED_B32,
            "sha1",
            Some(8),
            Some(PINNED_PERIOD),
        )
        .expect("desktop add pinned");
        s.add_secret_base32("desktop-rfc", None, RFC_SEED_B32, "sha1", Some(8), Some(30))
            .expect("desktop add rfc");

        // Sanity: the native core reproduces RFC 6238 App B at T=59.
        let at59 = s.entries_at(59).expect("views at 59");
        assert_eq!(at59[1].code, "94287082", "RFC 6238 App B, T=59, 8 digits");

        let views = s.entries_at(now_unix()).expect("views now");
        (
            views[0].code.clone(),
            s.export_uris(Some("desktop-rfc")).expect("export")[0].clone(),
        )
    };

    // The bytes on disk are the shared container, not plaintext.
    let raw = std::fs::read(&vault_path).expect("read container");
    assert_eq!(
        &raw[..8],
        b"SIGILcli",
        "desktop must write the CLI container"
    );

    let listed = sigil(&bin, &["totp", "list", "--vault", &vault_arg]);
    assert!(
        listed.contains("desktop-pinned") && listed.contains("issuer=DesktopColumn"),
        "the CLI did not see the desktop's account:\n{listed}"
    );
    assert!(
        listed.contains("desktop-rfc"),
        "missing second account:\n{listed}"
    );

    let cli_pinned = parse_code_line(&sigil(
        &bin,
        &["totp", "code", "desktop-pinned", "--vault", &vault_arg],
    ));
    assert_eq!(
        cli_pinned, desktop_pinned_code,
        "the CLI and the desktop disagree on a pinned-period code"
    );
    assert_eq!(
        cli_pinned.len(),
        8,
        "8-digit code expected, got {cli_pinned:?}"
    );

    // The otpauth:// layer agrees too.
    let exported = sigil(
        &bin,
        &["totp", "export", "desktop-rfc", "--vault", &vault_arg],
    );
    assert_eq!(
        exported.trim(),
        desktop_rfc_uri.trim(),
        "CLI and desktop produced different otpauth:// URIs"
    );

    // -----------------------------------------------------------------------
    // B. THE REAL `sigil` BINARY WRITES -> DESKTOP READS
    // -----------------------------------------------------------------------
    sigil(
        &bin,
        &[
            "totp",
            "add",
            "cli-pinned",
            "--secret",
            RFC_SEED_B32,
            "--issuer",
            "CliColumn",
            "--algorithm",
            "sha256",
            "--digits",
            "8",
            "--period",
            "4294967295",
            "--vault",
            &vault_arg,
        ],
    );
    let cli_added_code = parse_code_line(&sigil(
        &bin,
        &["totp", "code", "cli-pinned", "--vault", &vault_arg],
    ));

    let reopened = VaultSession::unlock(&vault_path, PASSWORD.as_bytes())
        .expect("desktop re-unlock of a CLI-written vault");
    assert_eq!(reopened.len(), 3, "desktop should see all three accounts");
    let views = reopened.entries_at(now_unix()).expect("views");
    let cli_view = views
        .iter()
        .find(|v| v.label == "cli-pinned")
        .expect("desktop did not see the CLI's account");
    assert_eq!(cli_view.issuer.as_deref(), Some("CliColumn"));
    assert_eq!(cli_view.algorithm, "sha256");
    assert_eq!(cli_view.digits, 8);
    assert_eq!(
        cli_view.code, cli_added_code,
        "the desktop and the CLI disagree on the CLI-added account's code"
    );

    // -----------------------------------------------------------------------
    // C. The ordinary 30 s account agrees across processes too. The two reads
    //    can straddle a step boundary, so retry a bounded number of times.
    // -----------------------------------------------------------------------
    let mut agreed = false;
    let mut last = (String::new(), String::new());
    for _ in 0..5 {
        let cli_code = parse_code_line(&sigil(
            &bin,
            &["totp", "code", "desktop-rfc", "--vault", &vault_arg],
        ));
        let mine = reopened
            .entries_at(now_unix())
            .expect("views")
            .into_iter()
            .find(|v| v.label == "desktop-rfc")
            .expect("entry")
            .code;
        if cli_code == mine {
            agreed = true;
            break;
        }
        last = (cli_code, mine);
        std::thread::sleep(std::time::Duration::from_millis(1200));
    }
    assert!(
        agreed,
        "30s-period codes never agreed across processes (last: cli={:?} desktop={:?})",
        last.0, last.1
    );

    // -----------------------------------------------------------------------
    // D. A migration URI written by the desktop imports into the CLI.
    // -----------------------------------------------------------------------
    let migration = reopened
        .export_migration_uri(Some("desktop-rfc"))
        .expect("desktop migration export");
    let second_vault = vault_path.with_file_name("from-desktop-migration.sigil");
    let second_arg = second_vault.to_str().expect("utf-8").to_string();
    let imported = sigil(
        &bin,
        &["totp", "import", &migration, "--vault", &second_arg],
    );
    assert!(
        imported.contains("imported 1"),
        "the CLI did not import the desktop's migration URI:\n{imported}"
    );
    let listed2 = sigil(&bin, &["totp", "list", "--vault", &second_arg]);
    assert!(listed2.contains("desktop-rfc"), "{listed2}");

    let _ = std::fs::remove_dir_all(vault_path.parent().expect("parent"));
}
