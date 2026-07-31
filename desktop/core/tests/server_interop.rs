//! THE PHASE 49 PROOF — the desktop column is a PEER on the network.
//!
//! Until now the desktop was the only client that never talked to the server.
//! This test boots a **REAL sigild** (dev-ops + multi-device auth, contract v3)
//! and builds the **REAL `sigil` binary**, then proves the desktop core is a
//! first-class device alongside it. No mocks, no stubs, no fake HTTP.
//!
//! * **(a) desktop → CLI.** The desktop enrolls, publishes its hybrid public
//!   key, creates a vault holding the RFC 6238 test seed, converts it to a
//!   SHARED vault under a random 32-byte vault key, pushes the opaque container,
//!   and shares it to an enrolled CLI device. The real `sigil` binary accepts the
//!   share, pulls the vault, and prints the RFC 6238 vector `94287082`.
//! * **(b) CLI → desktop.** The CLI re-keys and shares a vault of its own to the
//!   DESKTOP device; the desktop core accepts, pulls, and computes the SAME code.
//! * **(c) negatives.** An unauthorized third device gets **403**; an unenrolled
//!   desktop gets a clear `NotEnrolled` error rather than a panic; with the
//!   server unreachable the push reports `Unreachable` and the OFFLINE flow —
//!   unlock the local vault, generate codes — still works.
//! * **opacity.** The bytes the CLI pulled are byte-identical to the bytes the
//!   desktop pushed, and contain neither the 2FA seed nor the label: the server
//!   relayed ciphertext it cannot read.
//!
//! # Pinning the clock
//!
//! `sigil totp code` reads the host clock and has no `--at` flag, so an exact
//! assertion needs a code that does not move. RFC 6238 Appendix B's `T = 59`
//! entry is TOTP counter `floor(59 / 30) = 1`. Any period `P` with
//! `floor(now / P) == 1` therefore yields the SAME published code — and
//! `P = 1_600_000_000` (Sept 2020) satisfies that for every instant from 2020
//! until 2071. So both the desktop and the CLI, each reading their own clock,
//! must print exactly `94287082`.
//!
//! STATUS: pre-audit, DEV-ONLY, UNAUDITED, loopback + plain HTTP. The server is
//! bound to a free 127.0.0.1 port and torn down in a `Drop` guard.

use std::io::Write as _;
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sigil_core::Argon2Params;
use sigil_desktop_core::{now_unix, pull_and_adopt, DesktopError, DeviceConfig, VaultSession};

/// ASCII "12345678901234567890" — the PUBLIC RFC 4226 / RFC 6238 test seed, in
/// base32. Not a real secret: that is the entire point of a published vector.
const RFC_SEED_B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
/// RFC 6238 Appendix B, T = 59, SHA-1, 8 digits.
const RFC_CODE: &str = "94287082";
/// A period that pins the TOTP counter to 1 for the next few decades (see the
/// module note), so `sigil totp code` must print [`RFC_CODE`] exactly.
const PINNED_PERIOD: u32 = 1_600_000_000;

const DESKTOP_PASSWORD: &str = "desktop phase-49 test password, not a real one";
const CLI_PASSWORD: &str = "cli phase-49 test password, not a real one";

const VAULT_FROM_DESKTOP: &str = "desktop-shared-vault";
const VAULT_FROM_CLI: &str = "cli-shared-vault";

// Operator-provisioned, single-use enrollment tokens (sigild requires >= 16
// chars). Throwaway values for a throwaway loopback server.
const TOKEN_DESKTOP: &str = "tok-desktop-0000000000000001";
const TOKEN_CLI: &str = "tok-cli-00000000000000000002";
const TOKEN_THIRD: &str = "tok-third-000000000000000003";
const ADMIN_TOKEN: &str = "admin-token-0000000000000001";

/// Cheap Argon2id params so the test stays fast while still exercising the REAL
/// KDF. The parameters ride in the container header, so the CLI opens a vault
/// sealed with them without being told. (Argon2 needs `m_cost >= 8 * p_cost`.)
const FAST: Argon2Params = Argon2Params {
    m_cost: 8,
    t_cost: 1,
    p_cost: 1,
};

// ---------------------------------------------------------------------------
// Harness: build the real binaries, boot a real sigild, tear it all down.
// ---------------------------------------------------------------------------

/// `<repo>/desktop/core` -> `<repo>`.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repo root is two levels above desktop/core")
        .to_path_buf()
}

/// A booted sigild plus the scratch state. `Drop` is the finally/defer path: it
/// kills the server and removes every temp file even when an assertion panics.
struct Harness {
    tmp: PathBuf,
    server: String,
    sigil: PathBuf,
    child: Option<Child>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.tmp);
    }
}

/// Locate a usable `go` binary.
///
/// Deliberately NOT a graceful skip: this test is the only thing proving the
/// desktop client actually interoperates with a live server and the real CLI, and
/// a test that silently skips when a toolchain is missing reads as green while
/// proving nothing. (That exact failure mode — a Postgres suite skipping because
/// its DSN was unset — hid a CI-red bug in this repo for two phases.) So if Go is
/// genuinely absent we PANIC with an actionable message rather than pass.
fn resolve_go() -> String {
    if let Ok(go) = std::env::var("GO") {
        return go;
    }
    // `go` on PATH covers CI (actions/setup-go) and any normal dev shell.
    if Command::new("go")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return "go".to_string();
    }
    // Last resort: the Homebrew location on a bare macOS shell where PATH was
    // not inherited (e.g. some GUI-launched test runners).
    let brew = "/opt/homebrew/bin/go";
    if std::path::Path::new(brew).exists() {
        return brew.to_string();
    }
    panic!(
        "no Go toolchain found: this test builds the real sigild. \
         Install Go, put it on PATH, or set GO=/path/to/go"
    );
}

impl Harness {
    fn start() -> Harness {
        Harness::start_with(&[])
    }

    /// Boot with EXTRA server environment on top of the standard dev-ops +
    /// device-auth set — used by the entitlement proof, which needs a sigild
    /// that actually enforces payment.
    fn start_with(extra_env: &[(&str, &str)]) -> Harness {
        let root = repo_root();
        // The per-harness suffix MUST include a counter, not just pid+seconds.
        // `cargo test` runs the tests in this file in PARALLEL threads of ONE
        // process, so two harnesses starting in the same second produced the
        // SAME path — and the second one's `remove_dir_all` deleted the first
        // one's state from under it. That surfaced the moment a second test was
        // added, as a baffling "No such file or directory" in the OTHER test.
        static NTH: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let nth = NTH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let tmp = std::env::temp_dir().join(format!(
            "sigil-desktop-net-{}-{}-{nth}",
            std::process::id(),
            now_unix()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("scratch dir");

        // --- build the REAL sigild -------------------------------------
        // Resolve the Go toolchain PORTABLY. An earlier version fell back to a
        // hardcoded /opt/homebrew/bin/go, which works on this macOS dev machine
        // but does not exist on a Linux CI runner — so the test would have failed
        // there. Order: $GO, then whatever is on PATH, then the Homebrew path as
        // a last resort for a bare macOS shell.
        let go = resolve_go();
        let sigild = tmp.join("sigild");
        let out = Command::new(&go)
            .arg("-C")
            .arg(root.join("sigild"))
            .args(["build", "-o"])
            .arg(&sigild)
            .arg("./cmd/server")
            .output()
            .unwrap_or_else(|e| panic!("could not run {go} to build sigild: {e}"));
        assert!(
            out.status.success(),
            "building sigild failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );

        // --- build the REAL sigil CLI ----------------------------------
        let out = Command::new(env!("CARGO"))
            .args(["build", "--manifest-path"])
            .arg(root.join("cli/Cargo.toml"))
            .args(["--bin", "sigil"])
            // The CLI is a separate workspace with its own lockfile; do not
            // inherit this test run's target dir.
            .env_remove("CARGO_TARGET_DIR")
            .output()
            .expect("could not run cargo to build the sigil CLI");
        assert!(
            out.status.success(),
            "building the sigil CLI failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let sigil = root.join("cli/target/debug/sigil");
        assert!(sigil.exists(), "expected {}", sigil.display());

        // --- boot sigild on a free loopback port ------------------------
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
            l.local_addr().expect("addr").port()
        };
        let addr = format!("127.0.0.1:{port}");
        let server = format!("http://{addr}");
        let log = std::fs::File::create(tmp.join("sigild.log")).expect("log file");
        let child = Command::new(&sigild)
            .envs(extra_env.iter().copied())
            .env("SIGILD_ADDR", &addr)
            .env("SIGILD_ENABLE_DEV_OPS", "1")
            .env("SIGILD_DEVICE_AUTH", "1")
            .env(
                "SIGILD_ENROLL_TOKENS",
                format!("{TOKEN_DESKTOP},{TOKEN_CLI},{TOKEN_THIRD}"),
            )
            .env("SIGILD_ADMIN_TOKEN", ADMIN_TOKEN)
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("could not spawn sigild");

        let harness = Harness {
            tmp,
            server,
            sigil,
            child: Some(child),
        };

        // Wait for the listener. A successful connect means it is bound.
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if TcpStream::connect(&addr).is_ok() {
                return harness;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "sigild never bound {addr}; log:\n{}",
            std::fs::read_to_string(harness.tmp.join("sigild.log")).unwrap_or_default()
        );
    }

    /// Run the real `sigil` binary as the device whose HOME is `home`, asserting
    /// success and returning stdout. `SIGIL_DEVICE_KEY` is what makes push/pull
    /// sign under contract v3 (their legacy rule — no key means unsigned — is
    /// untouched).
    fn cli(&self, home: &Path, password: &str, args: &[&str]) -> String {
        let out = self
            .cli_raw(home, password, args)
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

    fn cli_raw(
        &self,
        home: &Path,
        password: &str,
        args: &[&str],
    ) -> std::io::Result<std::process::Output> {
        Command::new(&self.sigil)
            .args(args)
            .env("HOME", home)
            .env("SIGIL_SERVER", &self.server)
            .env("SIGIL_DEVICE_KEY", home.join(".sigil/device.key"))
            .env("SIGIL_PASSWORD", password)
            .output()
    }
}

/// Pull the leading `dev_...` identifier out of a CLI message.
fn device_id_in(text: &str) -> String {
    let start = text
        .find("dev_")
        .unwrap_or_else(|| panic!("no dev_ id in:\n{text}"));
    text[start..]
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect()
}

/// The leading code from `sigil totp code`'s `"<code>  (valid for Ns)"`.
fn code_in(stdout: &str) -> String {
    stdout
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string()
}

/// The first whitespace-delimited token after `marker` in CLI output — used to
/// read back the `key sha256:` FINGERPRINT the CLI prints (never a key).
fn field_after(text: &str, marker: &str) -> String {
    let start = text
        .find(marker)
        .unwrap_or_else(|| panic!("no {marker:?} in:\n{text}"));
    text[start + marker.len()..]
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string()
}

/// `<path>`'s permission bits.
fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::metadata(path)
        .unwrap_or_else(|e| panic!("stat {}: {e}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

fn assert_0600(path: &Path) {
    assert_eq!(
        mode_of(path),
        0o600,
        "{} must be owner-only",
        path.display()
    );
}

fn say(line: &str) {
    println!("  OK   {line}");
    let _ = std::io::stdout().flush();
}

// ---------------------------------------------------------------------------
// THE PROOF
// ---------------------------------------------------------------------------

#[test]
fn the_desktop_is_a_network_peer_with_the_cli_and_a_real_sigild() {
    let h = Harness::start();
    println!("\n=== sigild up at {} (dev ops + device auth v3)", h.server);

    // Each device gets its OWN state directory: separate identity, separate
    // hybrid identity, separate keyring — exactly like separate machines.
    let desktop_dir = h.tmp.join("desktop/.sigil");
    let third_dir = h.tmp.join("third/.sigil");
    let unenrolled_dir = h.tmp.join("unenrolled/.sigil");
    let cli_home = h.tmp.join("cli-device");
    std::fs::create_dir_all(&cli_home).expect("cli home");

    let desktop = DeviceConfig::new(&h.server, &desktop_dir);

    // -----------------------------------------------------------------
    // 0. Before enrollment: local status works, network ops fail CLEARLY.
    // -----------------------------------------------------------------
    let status = desktop.status().expect("status offline");
    assert!(!status.enrolled && status.device_id.is_none());
    assert!(status.vaults.is_empty() && !status.hybrid_identity_present);
    assert!(matches!(
        desktop.publish_hybrid(),
        Err(DesktopError::NotEnrolled(_))
    ));
    assert!(matches!(
        desktop.share_vault(VAULT_FROM_DESKTOP, "dev_whoever", "read", None),
        Err(DesktopError::NotEnrolled(_))
    ));
    say("status reads with no state at all; contract-v3 ops say NotEnrolled");

    // -----------------------------------------------------------------
    // 1. THE DESKTOP ENROLLS and publishes its hybrid public key.
    // -----------------------------------------------------------------
    let desktop_id = desktop
        .enroll(TOKEN_DESKTOP, "phase-49 desktop")
        .expect("desktop enrollment");
    assert!(desktop_id.starts_with("dev_"), "got {desktop_id:?}");
    assert_0600(&desktop.identity_path());
    assert_eq!(
        mode_of(&desktop_dir),
        0o700,
        "the state dir must be owner-only"
    );
    assert!(matches!(
        desktop.enroll(TOKEN_DESKTOP, "again"),
        Err(DesktopError::AlreadyEnrolled(_))
    ));
    say(&format!(
        "desktop enrolled as {desktop_id} (identity 0600 in a 0700 dir)"
    ));

    let desktop_hybrid_fp = desktop.publish_hybrid().expect("publish hybrid");
    assert_eq!(desktop_hybrid_fp.len(), 16);
    assert_0600(&desktop.hybrid_secret_path());
    let probe = desktop.check_server().expect("check server");
    assert!(probe.reachable && probe.hybrid_published, "{probe:?}");
    say("desktop hybrid public key published (secret 0600, never uploaded)");

    // -----------------------------------------------------------------
    // 2. A vault with the RFC seed, converted to a SHARED vault.
    // -----------------------------------------------------------------
    let desktop_vault = desktop_dir.join("totp-vault.sigil");
    let mut session = VaultSession::create(&desktop_vault, DESKTOP_PASSWORD.as_bytes())
        .expect("create vault")
        .with_params(FAST);
    session
        .add_secret_base32(
            "shared-rfc",
            Some("Phase49".into()),
            RFC_SEED_B32,
            "sha1",
            Some(8),
            Some(PINNED_PERIOD),
        )
        .expect("add pinned");
    session
        .add_secret_base32("rfc-30", None, RFC_SEED_B32, "sha1", Some(8), Some(30))
        .expect("add rfc-30");
    assert_eq!(
        session.entries_at(59).expect("t59")[1].code,
        RFC_CODE,
        "RFC 6238 App B, T=59"
    );
    assert_eq!(
        session.entries_at(now_unix()).expect("now")[0].code,
        RFC_CODE,
        "the pinned-period entry must reproduce the same vector at any instant"
    );

    let shared_fp = session
        .convert_to_shared(&desktop, VAULT_FROM_DESKTOP)
        .expect("convert to shared");
    assert_eq!(shared_fp.len(), 16);
    assert_0600(&desktop.keyring_path());
    // The password no longer opens it; the vault key does. The human password
    // was never shared and never left this machine.
    assert!(VaultSession::unlock(&desktop_vault, DESKTOP_PASSWORD.as_bytes()).is_err());
    let reopened = VaultSession::unlock_shared(&desktop_vault, &desktop, VAULT_FROM_DESKTOP)
        .expect("unlock with the vault key");
    assert_eq!(reopened.len(), 2);
    say(&format!(
        "vault re-sealed under a random 32-byte vault key (sha256 {shared_fp}); the password no longer opens it"
    ));

    // -----------------------------------------------------------------
    // 3. PUSH the opaque container. The server never sees plaintext.
    // -----------------------------------------------------------------
    let pushed_bytes = std::fs::read(&desktop_vault).expect("read container");
    let seq = desktop
        .push_vault_file(VAULT_FROM_DESKTOP, &desktop_vault)
        .expect("push");
    assert!(seq >= 1);
    say(&format!(
        "pushed the sealed vault as seq {seq} (contract v3 signed)"
    ));

    // -----------------------------------------------------------------
    // 4. A REAL CLI device enrolls and publishes its hybrid key.
    // -----------------------------------------------------------------
    let cli_id = device_id_in(&h.cli(
        &cli_home,
        CLI_PASSWORD,
        &["device", "enroll", "--token", TOKEN_CLI, "--label", "cli"],
    ));
    h.cli(&cli_home, CLI_PASSWORD, &["device", "hybrid-publish"]);
    say(&format!("the real sigil CLI enrolled as {cli_id}"));

    // -----------------------------------------------------------------
    // 4b. ACCOUNTS (Phase 52). The desktop can read its own account and mint an
    //     invite, and a device that redeems that invite with the ORDINARY
    //     `sigil device enroll` lands in the desktop's account. Two devices that
    //     each used an OPERATOR token are in two DIFFERENT accounts.
    // -----------------------------------------------------------------
    {
        let mine = desktop.account().expect("desktop account");
        assert!(
            mine.account_id.starts_with("acct_"),
            "expected an acct_ id, got {}",
            mine.account_id
        );
        assert_eq!(mine.device_count, 1, "the desktop should be alone so far");
        assert!(
            mine.members.iter().any(|m| m.is_this_device),
            "the desktop must recognise its own row"
        );
        assert!(
            !mine.members.iter().any(|m| m.device_id == cli_id),
            "an OPERATOR token must found a NEW account, never join one"
        );

        // Mint an invite and redeem it with the REAL CLI binary — no new command
        // and no new wire format: an invite IS an enrollment token.
        let invite = desktop.create_invite(Some(300)).expect("mint invite");
        assert!(
            invite.invite.starts_with("join_"),
            "expected a join_ secret"
        );
        assert_eq!(invite.account_id, mine.account_id);
        let open = desktop.list_invites().expect("list invites");
        assert_eq!(open.len(), 1, "the open invite should be listed");
        assert_eq!(open[0].invite_id, invite.invite_id);
        // The listing is METADATA ONLY: a minted secret is unrecoverable.
        assert!(
            !format!("{open:?}").contains(&invite.invite),
            "the invite listing echoed the secret"
        );

        let joiner_home = h.tmp.join("account-joiner");
        std::fs::create_dir_all(&joiner_home).expect("joiner home");
        let joiner_id = device_id_in(&h.cli(
            &joiner_home,
            CLI_PASSWORD,
            &[
                "device",
                "enroll",
                "--token",
                &invite.invite,
                "--label",
                "joined-by-invite",
            ],
        ));
        let after = desktop.account().expect("account after join");
        assert_eq!(after.account_id, mine.account_id);
        assert_eq!(after.device_count, 2, "the joiner should be a member");
        assert!(
            after.members.iter().any(|m| m.device_id == joiner_id),
            "the joiner is missing from the member list"
        );
        assert!(
            desktop.list_invites().expect("invites").is_empty(),
            "a redeemed invite must not stay open"
        );

        // A handle that does not exist (or belongs to someone else) is the SAME
        // answer — there is no enumeration oracle.
        match desktop.revoke_invite("inv_doesNotExist") {
            Err(DesktopError::MissingOnServer(_)) => {}
            other => panic!("expected MissingOnServer for an unknown invite, got {other:?}"),
        }
        say(&format!(
            "accounts: the desktop owns {} and a CLI device joined it by invite ({joiner_id}); \
             the operator-token CLI device is in a different account",
            mine.account_id
        ));
    }

    // -----------------------------------------------------------------
    // 5. (a) DESKTOP SHARES TO THE CLI -> the CLI prints 94287082.
    // -----------------------------------------------------------------
    let share_fp = desktop
        .share_vault(VAULT_FROM_DESKTOP, &cli_id, "read", None)
        .expect("share to the CLI device");
    assert_eq!(
        share_fp.fingerprint, shared_fp,
        "shared the same key it holds"
    );

    let accepted = h.cli(
        &cli_home,
        CLI_PASSWORD,
        &["vault", "accept", "--vault", VAULT_FROM_DESKTOP],
    );
    assert!(
        accepted.contains(&shared_fp),
        "the CLI recovered a DIFFERENT vault key:\n{accepted}"
    );

    let inbox = cli_home.join("inbox");
    h.cli(
        &cli_home,
        CLI_PASSWORD,
        &[
            "pull",
            "--vault",
            VAULT_FROM_DESKTOP,
            "--out-dir",
            inbox.to_str().expect("utf-8"),
        ],
    );
    let pulled_file = inbox
        .join(VAULT_FROM_DESKTOP)
        .join(format!("op-{seq}.sigil"));
    let pulled_bytes = std::fs::read(&pulled_file).expect("read pulled container");
    assert_eq!(
        pulled_bytes, pushed_bytes,
        "the server did not return the pushed bytes verbatim"
    );
    assert_eq!(&pulled_bytes[..8], b"SIGILcli");
    let as_text = String::from_utf8_lossy(&pulled_bytes);
    assert!(
        !as_text.contains("shared-rfc") && !as_text.contains(RFC_SEED_B32),
        "the container leaked plaintext"
    );

    let cli_code = code_in(&h.cli(
        &cli_home,
        CLI_PASSWORD,
        &[
            "totp",
            "code",
            "shared-rfc",
            "--vault",
            pulled_file.to_str().expect("utf-8"),
            "--vault-id",
            VAULT_FROM_DESKTOP,
        ],
    ));
    assert_eq!(
        cli_code, RFC_CODE,
        "the real sigil binary did not reproduce the RFC 6238 vector from the desktop's vault"
    );
    say(&format!(
        "(a) DESKTOP -> op-log -> CLI: `sigil totp code` printed {cli_code} (RFC 6238 App B) \
         from a vault the desktop sealed, pushed and shared"
    ));

    // -----------------------------------------------------------------
    // 6. (b) THE CLI SHARES TO THE DESKTOP -> the desktop computes the same.
    // -----------------------------------------------------------------
    let cli_vault_file = cli_home.join("cli-vault.sigil");
    let cli_vault_arg = cli_vault_file.to_str().expect("utf-8").to_string();
    h.cli(
        &cli_home,
        CLI_PASSWORD,
        &[
            "totp",
            "add",
            "cli-rfc",
            "--secret",
            RFC_SEED_B32,
            "--issuer",
            "CliColumn",
            "--digits",
            "8",
            "--period",
            &PINNED_PERIOD.to_string(),
            "--vault",
            &cli_vault_arg,
        ],
    );
    let rekeyed = h.cli(
        &cli_home,
        CLI_PASSWORD,
        &[
            "vault",
            "rekey",
            "--vault",
            VAULT_FROM_CLI,
            "--file",
            &cli_vault_arg,
        ],
    );
    let cli_key_fp = field_after(&rekeyed, "key sha256:");
    assert_eq!(cli_key_fp.len(), 16, "in:\n{rekeyed}");
    h.cli(
        &cli_home,
        CLI_PASSWORD,
        &["push", "--vault", VAULT_FROM_CLI, "--in", &cli_vault_arg],
    );
    h.cli(
        &cli_home,
        CLI_PASSWORD,
        &[
            "vault",
            "share",
            "--vault",
            VAULT_FROM_CLI,
            "--to",
            &desktop_id,
            "--permission",
            "read",
        ],
    );

    let desktop_fp = desktop
        .accept_vault(VAULT_FROM_CLI, None, None, false)
        .expect("desktop accept");
    assert_eq!(
        desktop_fp, cli_key_fp,
        "the desktop unwrapped a DIFFERENT vault key than the CLI holds"
    );
    assert_0600(&desktop.keyring_path());

    let adopted = desktop_dir.join("from-cli.sigil");
    let (from_cli, from_seq) = pull_and_adopt(&desktop, VAULT_FROM_CLI, &adopted, 0)
        .expect("pull the CLI's vault")
        .expect("the CLI pushed something");
    assert!(from_seq >= 1);
    assert_0600(&adopted);
    let view = from_cli
        .entries_at(now_unix())
        .expect("codes")
        .into_iter()
        .find(|v| v.label == "cli-rfc")
        .expect("the CLI's account");
    assert_eq!(view.issuer.as_deref(), Some("CliColumn"));
    assert_eq!(
        view.code, RFC_CODE,
        "the desktop did not reproduce the RFC vector from the CLI's shared vault"
    );
    say(&format!(
        "(b) CLI -> op-log -> DESKTOP: the desktop unwrapped the same key (sha256 {desktop_fp}) \
         and computed {} from the CLI's vault",
        view.code
    ));

    // -----------------------------------------------------------------
    // 7. (c) NEGATIVES.
    // -----------------------------------------------------------------
    // An enrolled but UNAUTHORIZED third device: 403, not data.
    let third = DeviceConfig::new(&h.server, &third_dir);
    third.enroll(TOKEN_THIRD, "third").expect("third enroll");
    third.publish_hybrid().expect("third hybrid");
    match third.pull_vault(VAULT_FROM_DESKTOP, 0) {
        Err(DesktopError::Forbidden(msg)) => assert!(msg.contains("403"), "{msg}"),
        other => panic!("an unauthorized device must be refused, got {other:?}"),
    }
    match third.accept_vault(VAULT_FROM_DESKTOP, None, None, false) {
        Err(DesktopError::Forbidden(_)) | Err(DesktopError::MissingOnServer(_)) => {}
        other => panic!("a third device must not collect an envelope, got {other:?}"),
    }
    say("an enrolled but unauthorized third device is refused (403) on read and on accept");

    // An UNENROLLED desktop: a clear error, never a panic.
    let unenrolled = DeviceConfig::new(&h.server, &unenrolled_dir);
    for err in [
        unenrolled.publish_hybrid().unwrap_err(),
        unenrolled
            .accept_vault(VAULT_FROM_DESKTOP, None, None, false)
            .unwrap_err(),
        unenrolled
            .share_vault(VAULT_FROM_DESKTOP, &cli_id, "read", None)
            .unwrap_err(),
        unenrolled.check_server().unwrap_err(),
    ] {
        assert!(matches!(err, DesktopError::NotEnrolled(_)), "got {err:?}");
        assert!(err.to_string().contains("not enrolled"), "{err}");
    }
    assert!(
        !unenrolled_dir.exists(),
        "a failed op must not create device state"
    );
    say("an unenrolled desktop gets a clear NotEnrolled error, not a panic");

    // SERVER UNREACHABLE: reported as such, and the offline flow is untouched.
    let dead_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.local_addr().expect("addr").port()
    };
    let offline = DeviceConfig::new(format!("http://127.0.0.1:{dead_port}"), &desktop_dir);
    match offline.push_vault(VAULT_FROM_DESKTOP, &pushed_bytes) {
        Err(DesktopError::Unreachable(msg)) => {
            assert!(msg.contains("could not reach"), "{msg}")
        }
        other => panic!("expected Unreachable, got {other:?}"),
    }
    let probe = offline.check_server().expect("probe must not error");
    assert!(!probe.reachable, "{probe:?}");
    // ...and everything local still works with no server at all.
    let still = VaultSession::unlock_shared(&desktop_vault, &offline, VAULT_FROM_DESKTOP)
        .expect("offline unlock");
    assert_eq!(
        still.entries_at(now_unix()).expect("codes")[0].code,
        RFC_CODE
    );
    let offline_status = offline.status().expect("offline status");
    assert!(offline_status.enrolled);
    assert_eq!(offline_status.vaults.len(), 2, "{offline_status:?}");
    assert!(offline_status
        .vaults
        .iter()
        .all(|v| v.key_fingerprint.len() == 16));
    say("with the server unreachable: a clear Unreachable error, and the offline flow still generates codes");

    println!("\nPASS — the desktop enrolls, publishes, pushes, pulls, shares and accepts against a real sigild, and interoperates with the real sigil CLI in BOTH directions.\n");
}

// ---------------------------------------------------------------------------
// The key-substitution alarm
// ---------------------------------------------------------------------------

/// Phase 51 gave the desktop UI a blocking alarm for a changed hybrid key.
/// Nothing tested the path that RAISES it, which made the desktop the only
/// client whose key-substitution defence had no regression test — the browser
/// side is covered by `sigil-wasm/test/pinning-interop.mjs`.
///
/// The trigger here is faithful rather than simulated: a device that already
/// published key K1 publishes a BRAND-NEW K2 under the SAME device id. That is
/// byte-for-byte what a hostile server does when it substitutes a key it can
/// decrypt with — and it is deliberately indistinguishable from a legitimate
/// re-enrolment, which is exactly why the decision has to reach a human.
///
/// Asserted: the refusal is [`DesktopError::KeyPinMismatch`] (not a generic
/// failure), it carries BOTH safety numbers in the shape the UI prints, the
/// rotation path is guarded too, a re-pin with the WRONG number is refused, and
/// only a re-pin with the presented number lets sharing resume.
#[test]
fn a_substituted_hybrid_key_raises_the_alarm_the_desktop_ui_renders() {
    let h = Harness::start();
    println!("\n=== sigild up at {} (key-substitution alarm)", h.server);

    let desktop_dir = h.tmp.join("alarm-desktop/.sigil");
    let cli_home = h.tmp.join("alarm-cli");
    std::fs::create_dir_all(&cli_home).expect("cli home");
    let desktop = DeviceConfig::new(&h.server, &desktop_dir);

    desktop
        .enroll(TOKEN_DESKTOP, "alarm desktop")
        .expect("desktop enrollment");
    desktop.publish_hybrid().expect("publish hybrid");

    let vault_path = desktop_dir.join("totp-vault.sigil");
    let mut session = VaultSession::create(&vault_path, DESKTOP_PASSWORD.as_bytes())
        .expect("create vault")
        .with_params(FAST);
    session
        .add_secret_base32("rfc-30", None, RFC_SEED_B32, "sha1", Some(8), Some(30))
        .expect("add entry");
    session
        .convert_to_shared(&desktop, VAULT_FROM_DESKTOP)
        .expect("convert to shared");

    // ⭐ PUSH BEFORE SHARING, and it is not incidental setup. Phase 60 made
    // `share_vault` GRANT before it deposits, and only the vault's OWNER may
    // grant — while ownership is trust-on-first-WRITE. A vault that has never
    // been written to this server therefore has no owner, and the grant is a
    // 403. Pushing is the write that claims it, which is also the only order
    // that makes sense for the recipient: a key with no ciphertext opens nothing.
    desktop
        .push_vault_file(VAULT_FROM_DESKTOP, &vault_path)
        .expect("push claims the vault for this account");

    // A real peer publishes its first hybrid key, K1.
    let cli_id = device_id_in(&h.cli(
        &cli_home,
        CLI_PASSWORD,
        &["device", "enroll", "--token", TOKEN_CLI, "--label", "cli"],
    ));
    h.cli(&cli_home, CLI_PASSWORD, &["device", "hybrid-publish"]);

    // The first share is what PINS K1. It must succeed.
    desktop
        .share_vault(VAULT_FROM_DESKTOP, &cli_id, "read", None)
        .expect("the first share pins the key and succeeds");
    let (k1, state) = desktop.peer_safety_number(&cli_id).expect("safety number");
    assert_eq!(state, "matches the pinned key", "K1 should be pinned now");
    say(&format!("{cli_id} pinned at {k1}"));

    // ⚡ THE SUBSTITUTION. Same device id, a completely different hybrid key.
    h.cli(
        &cli_home,
        CLI_PASSWORD,
        &["device", "hybrid-publish", "--regenerate"],
    );
    say("that device now presents a DIFFERENT hybrid public key under the same id");

    // The share must REFUSE, and refuse as the alarm — not as a generic error.
    let presented = match desktop.share_vault(VAULT_FROM_DESKTOP, &cli_id, "read", None) {
        Err(DesktopError::KeyPinMismatch {
            device_id,
            pinned_safety_number,
            presented_safety_number,
        }) => {
            assert_eq!(device_id, cli_id);
            assert_eq!(
                pinned_safety_number, k1,
                "the alarm must show the key we actually pinned"
            );
            assert_ne!(
                pinned_safety_number, presented_safety_number,
                "a mismatch with equal numbers would be a bug in the comparison"
            );
            // The shape the UI prints: 6 groups of 5 digits.
            for n in [&pinned_safety_number, &presented_safety_number] {
                let groups: Vec<&str> = n.split_whitespace().collect();
                assert_eq!(groups.len(), 6, "safety number shape: {n}");
                assert!(
                    groups
                        .iter()
                        .all(|g| g.len() == 5 && g.chars().all(|c| c.is_ascii_digit())),
                    "safety number shape: {n}"
                );
            }
            presented_safety_number
        }
        Err(other) => panic!("expected the key-substitution alarm, got: {other}"),
        Ok(_) => panic!("SHARED TO A SUBSTITUTED KEY — the pin check did not fire"),
    };
    say("the share was REFUSED with both safety numbers (nothing was wrapped)");

    // Rotation runs the same check before it touches anything.
    assert!(
        matches!(
            desktop.rotate_vault(
                VAULT_FROM_DESKTOP,
                &vault_path,
                std::slice::from_ref(&cli_id),
                &[],
                &[],
            ),
            Err(DesktopError::KeyPinMismatch { .. })
        ),
        "rotation must refuse a substituted recipient key too"
    );

    // The escape hatch is guarded: a stale or mistyped number does NOT re-pin.
    assert!(
        desktop
            .repin_device(&cli_id, Some("11111 22222 33333 44444 55555 66666"))
            .is_err(),
        "re-pinning to a number the server is not presenting must be refused"
    );
    assert!(
        matches!(
            desktop.share_vault(VAULT_FROM_DESKTOP, &cli_id, "read", None),
            Err(DesktopError::KeyPinMismatch { .. })
        ),
        "a refused re-pin must leave the old pin in place"
    );
    say("a re-pin to the wrong number is refused, and the alarm still stands");

    // Only a DELIBERATE re-pin to the presented number clears it.
    let (previous, current) = desktop
        .repin_device(&cli_id, Some(&presented))
        .expect("deliberate re-pin");
    assert_eq!(previous.as_deref(), Some(k1.as_str()));
    assert_eq!(current, presented);
    desktop
        .share_vault(VAULT_FROM_DESKTOP, &cli_id, "read", None)
        .expect("sharing resumes once the new key is deliberately pinned");
    say("after a deliberate re-pin to the presented number, sharing resumes");

    println!("\nPASS — a substituted hybrid key is detected, refused with both safety numbers, blocks rotation, survives a wrong-number re-pin, and clears only on a deliberate one.\n");
}

// ---------------------------------------------------------------------------
// THE RECOVERY KIT — the proof that a printed sheet is enough
// ---------------------------------------------------------------------------

/// ⭐ **THE PHASE 56 PROOF.** A recovery kit ([ADR 0042]) shipped in the `sigil`
/// CLI only, and its own limitation 9 said the quiet part: *"the desktop has no
/// recovery commands"* — while `restore` is precisely the flow a person runs on
/// a NEW INSTALL after losing everything.
///
/// So this drives the real thing end to end, with **nothing simulated**: a real
/// `sigild`, a real desktop device that seals a vault and pushes it, a kit
/// printed from that device — and then the device's entire state directory is
/// **deleted**. Identity, hybrid secret, keyring and vault file: gone, exactly
/// as if the laptop had been stolen. What is left is the 56 characters.
///
/// Asserted:
/// * the sheet verifies OFFLINE, and one flipped character does not;
/// * a well-formed code for a DIFFERENT secret recovers **nothing**, and writes
///   nothing to disk;
/// * a **revoked** kit recovers nothing either;
/// * the real code rebuilds both covered vaults on a machine that had no state
///   at all, and one of them produces the RFC 6238 vector `94287082`;
/// * `adopt = false` leaves no kit identity behind, and `adopt = true` makes the
///   machine a second copy of the paper — visibly, in `0600` files.
#[test]
fn a_printed_sheet_recovers_the_vaults_after_every_device_is_gone() {
    const VAULT_TWO: &str = "desktop-second-vault";
    let h = Harness::start();
    println!("\n=== sigild up at {} (recovery kit)", h.server);

    let desktop_dir = h.tmp.join("recovery-desktop/.sigil");
    let desktop = DeviceConfig::new(&h.server, &desktop_dir);
    desktop
        .enroll(TOKEN_DESKTOP, "recovery desktop")
        .expect("enroll");
    desktop.publish_hybrid().expect("publish hybrid");

    // A vault holding the RFC seed, converted to a SHARED vault (a
    // PASSWORD-sealed vault has no vault key, so a kit cannot cover it) and
    // pushed — a kit recovers KEYS, and only ciphertext that exists.
    let vault_one = desktop_dir.join("totp-vault.sigil");
    let mut session = VaultSession::create(&vault_one, DESKTOP_PASSWORD.as_bytes())
        .expect("create")
        .with_params(FAST);
    session
        .add_secret_base32(
            "shared-rfc",
            Some("Phase56".into()),
            RFC_SEED_B32,
            "sha1",
            Some(8),
            Some(PINNED_PERIOD),
        )
        .expect("add");
    let fp_one = session
        .convert_to_shared(&desktop, VAULT_FROM_DESKTOP)
        .expect("convert");
    desktop
        .push_vault_file(VAULT_FROM_DESKTOP, &vault_one)
        .expect("push");
    drop(session);

    // Before anything: "Recovery: not set up".
    assert!(
        desktop.recovery_kits().expect("kits").is_empty(),
        "no kit should exist yet"
    );

    // -----------------------------------------------------------------
    // 1. GENERATE. The sheet is printed once and verified BEFORE printing.
    // -----------------------------------------------------------------
    let sheet = desktop
        .recovery_generate(&[VAULT_FROM_DESKTOP.to_string()])
        .expect("generate a kit");
    let kit_id = sheet.device_id.clone();
    assert!(kit_id.starts_with("dev_"), "{kit_id}");

    // 7 groups of 8 Crockford characters, hyphen-joined.
    let groups: Vec<&str> = sheet.code.split('-').collect();
    assert_eq!(groups.len(), 7, "printed grouping: {}", sheet.code);
    assert!(
        groups.iter().all(|g| g.len() == 8),
        "printed grouping: {}",
        sheet.code
    );
    // The safety number is on the sheet, which is what makes the out-of-band
    // check usable: the channel is a piece of paper the user already holds.
    assert_eq!(sheet.safety_number.split_whitespace().count(), 6);
    assert_eq!(sheet.covered.len(), 1);
    assert_eq!(sheet.covered[0].vault_id, VAULT_FROM_DESKTOP);
    assert_eq!(sheet.covered[0].key_fingerprint, fp_one);
    // The pre-print round trip: re-parsed, re-derived, authenticated as the kit,
    // landed in THIS account, and unwrapped a real envelope.
    assert_eq!(sheet.proof.unwrapped_vault, VAULT_FROM_DESKTOP);
    assert_eq!(sheet.proof.key_fingerprint, fp_one);
    assert_eq!(sheet.proof.account_id, sheet.account_id);
    assert!(sheet.seats_used >= 2, "a kit consumes a seat");
    // ⚠️ And the credential is NOT in the Debug rendering.
    assert!(!format!("{sheet:?}").contains(&groups[0].to_string()));

    // Offline: the sheet verifies, a typo does not, and neither touches a socket.
    sigil_desktop_core::verify_recovery_code(&sheet.code).expect("the printed code verifies");
    let mut typo: Vec<char> = sheet.code.chars().collect();
    let i = typo
        .iter()
        .position(|c| c.is_ascii_alphanumeric())
        .expect("a character");
    typo[i] = if typo[i] == '2' { '3' } else { '2' };
    let typo: String = typo.into_iter().collect();
    assert!(
        matches!(
            sigil_desktop_core::verify_recovery_code(&typo),
            Err(DesktopError::Recovery(_))
        ),
        "a mistyped sheet must be caught offline"
    );

    let kits = desktop.recovery_kits().expect("kits");
    assert_eq!(kits.len(), 1);
    assert_eq!(kits[0].device_id, kit_id);
    assert_eq!(kits[0].status, "active");
    say(&format!(
        "kit {kit_id} printed and verified before printing (safety number {})",
        sheet.safety_number
    ));

    // -----------------------------------------------------------------
    // 2. COVER a vault created LATER. On the generating device the kit's key
    //    is pinned as DERIVED, so this wraps with no fetch at all.
    // -----------------------------------------------------------------
    let vault_two = desktop_dir.join("second.sigil");
    let mut second = VaultSession::create(&vault_two, DESKTOP_PASSWORD.as_bytes())
        .expect("create second")
        .with_params(FAST);
    second
        .add_secret_base32("second-rfc", None, RFC_SEED_B32, "sha1", Some(6), Some(30))
        .expect("add");
    let fp_two = second
        .convert_to_shared(&desktop, VAULT_TWO)
        .expect("convert second");
    desktop
        .push_vault_file(VAULT_TWO, &vault_two)
        .expect("push second");
    drop(second);

    let (covered_fp, derived) = desktop
        .recovery_cover(&kit_id, VAULT_TWO, None)
        .expect("cover the second vault");
    assert_eq!(covered_fp, fp_two);
    assert!(
        derived,
        "the generating device must use its DERIVED pin and fetch nothing"
    );

    let coverage = desktop.recovery_check(&kit_id).expect("check");
    assert_eq!(coverage.len(), 2, "{coverage:?}");
    assert!(
        coverage.iter().all(|c| c.covered && c.synced),
        "both vaults should be covered AND synced: {coverage:?}"
    );
    say("a vault created later was covered with no fetch, and both are covered + synced");

    // -----------------------------------------------------------------
    // 3. A REVOKED sheet recovers nothing. (Proved with a second kit, so the
    //    first one survives for the restore below.)
    // -----------------------------------------------------------------
    let doomed = desktop.recovery_generate(&[]).expect("second kit");
    let report = desktop
        .recovery_revoke(&doomed.device_id, &[])
        .expect("revoke");
    assert_eq!(report.device_id, doomed.device_id);
    assert_eq!(
        report.envelopes_removed.len(),
        2,
        "both envelopes should have been taken back: {report:?}"
    );
    let dead_dir = h.tmp.join("revoked-restore/.sigil");
    match DeviceConfig::new(&h.server, &dead_dir).recovery_restore(
        &doomed.code,
        &doomed.device_id,
        None,
        false,
    ) {
        Err(DesktopError::Unauthenticated(_)) => {}
        other => panic!("a REVOKED kit must recover nothing, got {other:?}"),
    }
    assert!(
        !dead_dir.join("vault-keys.json").exists(),
        "a refused restore must not write a keyring"
    );
    say("a revoked sheet is refused at the door and writes nothing");

    // -----------------------------------------------------------------
    // 4. ⚡ THE DEVICE IS GONE. Everything local is deleted.
    // -----------------------------------------------------------------
    std::fs::remove_dir_all(&desktop_dir).expect("destroy the device's state");
    assert!(!desktop_dir.exists());
    say("the device's identity, hybrid secret, keyring and vault files were DELETED");

    // A brand-new machine, holding nothing.
    let fresh_dir = h.tmp.join("new-install/.sigil");
    let fresh = DeviceConfig::new(&h.server, &fresh_dir);
    let before = fresh.status().expect("status");
    assert!(!before.enrolled && before.vaults.is_empty());

    // A well-formed code for a DIFFERENT secret authenticates as nobody.
    let stranger = sigil_core::encode_recovery_kit(&[0x11u8; sigil_core::RECOVERY_SEED_LEN]);
    let stranger = std::str::from_utf8(&stranger).expect("ascii");
    sigil_desktop_core::verify_recovery_code(stranger).expect("it IS well-formed");
    match fresh.recovery_restore(stranger, &kit_id, None, false) {
        Err(DesktopError::Unauthenticated(_)) => {}
        other => panic!("a valid-but-wrong code must recover nothing, got {other:?}"),
    }
    // ...and a mistyped one never even reaches the network.
    assert!(matches!(
        fresh.recovery_restore(&typo, &kit_id, None, false),
        Err(DesktopError::Recovery(_))
    ));
    assert!(
        !fresh_dir.join("vault-keys.json").exists(),
        "a failed restore must not write a keyring"
    );
    say("a wrong sheet recovers nothing, and a mistyped one is refused before any network I/O");

    // -----------------------------------------------------------------
    // 5. ⭐ THE RESTORE. The paper alone rebuilds both vaults.
    // -----------------------------------------------------------------
    let restored = fresh
        .recovery_restore(&sheet.code, &kit_id, None, false)
        .expect("restore from the printed sheet");
    assert_eq!(restored.device_id, kit_id);
    assert_eq!(restored.account_id, sheet.account_id);
    assert_eq!(restored.vaults.len(), 2, "{restored:?}");
    assert!(restored.skipped.is_empty(), "{restored:?}");
    assert!(!restored.adopted);

    let one = restored
        .vaults
        .iter()
        .find(|v| v.vault_id == VAULT_FROM_DESKTOP)
        .expect("the first vault");
    assert_eq!(one.key_fingerprint, fp_one, "a DIFFERENT key came back");
    assert_eq!(one.entries, 1);
    assert_0600(&one.path);
    assert!(restored
        .vaults
        .iter()
        .any(|v| v.vault_id == VAULT_TWO && v.key_fingerprint == fp_two));

    // ⭐ THE ASSERTION THE WHOLE FEATURE EXISTS FOR: the codes are back.
    let reopened = VaultSession::unlock_shared(&one.path, &fresh, VAULT_FROM_DESKTOP)
        .expect("open the restored vault with the recovered key");
    let view = reopened.entries_at(now_unix()).expect("codes");
    assert_eq!(view[0].label, "shared-rfc");
    assert_eq!(
        view[0].code, RFC_CODE,
        "the recovered vault did not reproduce the RFC 6238 vector"
    );
    assert_0600(&fresh.keyring_path());
    assert_eq!(fresh.status().expect("status").vaults.len(), 2);

    // DEFAULT IS EPHEMERAL: this machine recovered the vaults and is NOT the kit.
    assert!(
        !fresh.identity_path().exists() && !fresh.hybrid_secret_path().exists(),
        "adopt=false must leave no kit identity behind"
    );
    say(&format!(
        "⭐ restored from the sheet ALONE on a machine with no state: 2 vaults, and {} for the \
         RFC 6238 account",
        view[0].code
    ));

    // -----------------------------------------------------------------
    // 6. ADOPT — the same restore, told to keep the kit's identity. This
    //    machine becomes a SECOND COPY OF THE PAPER, and says so on disk.
    // -----------------------------------------------------------------
    let adopt_dir = h.tmp.join("adopted/.sigil");
    let adopted = DeviceConfig::new(&h.server, &adopt_dir);
    let report = adopted
        .recovery_restore(&sheet.code, &kit_id, None, true)
        .expect("restore with adopt");
    assert!(report.adopted);
    assert_0600(&adopted.identity_path());
    assert_0600(&adopted.hybrid_secret_path());
    let status = adopted.status().expect("status");
    assert!(status.enrolled);
    assert_eq!(status.device_id.as_deref(), Some(kit_id.as_str()));
    // The kit's own key is pinned as DERIVED — established with no fetch, so
    // there was never anything for a server to substitute.
    assert!(
        adopted
            .pins()
            .expect("pins")
            .iter()
            .any(|p| p.device_id == kit_id),
        "an adopted machine must hold the kit's derived pin"
    );
    say("adopt=true persisted the kit identity 0600 — that machine IS the paper now");

    println!(
        "\nPASS — a printed recovery kit rebuilt both vaults on a machine that had nothing, a \
         wrong or revoked sheet recovered nothing, and the RFC 6238 vector came back.\n"
    );
}

// ---------------------------------------------------------------------------
// THE WRAP GATE, for a recovery kit
// ---------------------------------------------------------------------------

/// ⭐ [ADR 0042 §4] is the lesson this repo learned twice: **the requirement
/// belongs on the wrap path, not on a command.** A recovery kit is the one
/// credential that reconstructs a whole account, so wrapping a vault key to a
/// kit whose public key this device has never seen — on the word of the server
/// that serves that key — must be REFUSED, from every path, and the sheet
/// carries the safety number that resolves it.
///
/// The desktop reaches that gate through the same `sigil-cli`
/// `verify_recipient_for_wrap`, whose `VerifiedRecipient` cannot be constructed
/// anywhere else. This proves it *fires here*, on a **sibling device** — the
/// realistic case, since the generating device holds a derived pin and never
/// fetches at all.
#[test]
fn a_sibling_device_cannot_cover_a_kit_without_the_printed_safety_number() {
    let h = Harness::start();
    println!("\n=== sigild up at {} (the wrap gate)", h.server);

    let owner_dir = h.tmp.join("gate-owner/.sigil");
    let sibling_dir = h.tmp.join("gate-sibling/.sigil");
    let owner = DeviceConfig::new(&h.server, &owner_dir);
    owner.enroll(TOKEN_DESKTOP, "owner").expect("enroll owner");
    owner.publish_hybrid().expect("owner hybrid");

    let vault_path = owner_dir.join("totp-vault.sigil");
    let mut session = VaultSession::create(&vault_path, DESKTOP_PASSWORD.as_bytes())
        .expect("create")
        .with_params(FAST);
    session
        .add_secret_base32(
            "rfc",
            None,
            RFC_SEED_B32,
            "sha1",
            Some(8),
            Some(PINNED_PERIOD),
        )
        .expect("add");
    let fp = session
        .convert_to_shared(&owner, VAULT_FROM_DESKTOP)
        .expect("convert");
    owner
        .push_vault_file(VAULT_FROM_DESKTOP, &vault_path)
        .expect("push");
    drop(session);

    let sheet = owner
        .recovery_generate(&[VAULT_FROM_DESKTOP.to_string()])
        .expect("kit");
    let kit_id = sheet.device_id.clone();

    // A second device of the SAME account, with write access to the vault.
    let invite = owner.create_invite(Some(300)).expect("invite");
    let sibling = DeviceConfig::new(&h.server, &sibling_dir);
    sibling
        .enroll(&invite.invite, "sibling")
        .expect("sibling enroll");
    sibling.publish_hybrid().expect("sibling hybrid");
    owner
        .share_vault(
            VAULT_FROM_DESKTOP,
            &sibling.status().unwrap().device_id.unwrap(),
            "write",
            None,
        )
        .expect("share to the sibling");
    assert_eq!(
        sibling
            .accept_vault(VAULT_FROM_DESKTOP, None, None, false)
            .expect("accept"),
        fp,
        "the sibling holds the same vault key"
    );

    // ⛔ FIRST SIGHT OF A KIT, NO NUMBER. Refused — nothing wrapped, nothing
    // uploaded, and (critically) the pin store NOT mutated: pinning a key that
    // was then refused would let a plain retry succeed.
    let presented = match sibling.recovery_cover(&kit_id, VAULT_FROM_DESKTOP, None) {
        Err(DesktopError::KeyUnverified {
            device_id,
            presented_safety_number,
            ..
        }) => {
            assert_eq!(device_id, kit_id);
            assert_eq!(presented_safety_number, sheet.safety_number);
            presented_safety_number
        }
        other => panic!("an unverified first-sight KIT wrap must be refused, got {other:?}"),
    };
    assert!(
        !sibling
            .pins()
            .expect("pins")
            .iter()
            .any(|p| p.device_id == kit_id),
        "a REFUSED wrap must not pin the key it refused"
    );

    // ⛔ A WRONG number is refused too, and still does not pin.
    assert!(
        matches!(
            sibling.recovery_cover(
                &kit_id,
                VAULT_FROM_DESKTOP,
                Some("11111 22222 33333 44444 55555 66666")
            ),
            Err(DesktopError::KeyUnverified { .. })
        ),
        "a wrong safety number must be refused"
    );
    assert!(!sibling
        .pins()
        .expect("pins")
        .iter()
        .any(|p| p.device_id == kit_id));
    say("a sibling device is REFUSED both without a safety number and with a wrong one");

    // ✅ The number PRINTED ON THE SHEET is what unlocks it.
    let (covered_fp, derived) = sibling
        .recovery_cover(&kit_id, VAULT_FROM_DESKTOP, Some(&presented))
        .expect("the printed safety number must be accepted");
    assert_eq!(covered_fp, fp);
    assert!(
        !derived,
        "the sibling fetched the key, it did not derive it"
    );
    assert!(
        sibling
            .pins()
            .expect("pins")
            .iter()
            .any(|p| p.device_id == kit_id),
        "an ACCEPTED wrap pins the verified key"
    );
    say("with the digits from the sheet, the same cover succeeds and pins the key");

    println!(
        "\nPASS — the wrap gate refuses a first-sight recovery kit from the desktop, leaves the \
         pin store untouched, and accepts only the safety number printed on the sheet.\n"
    );
}

// ---------------------------------------------------------------------------
// ENTITLEMENT — writes may be refused; reads and key recovery never are
// ---------------------------------------------------------------------------

/// ⭐ [ADR 0043] made `sigild` able to refuse a lapsed account, and the whole
/// point is the **asymmetry**: this product holds a customer's second factor, so
/// a declined card must never cost them a code they already have.
///
/// Until now nothing in this repo *read* those signals — a refused write reached
/// the user as a raw HTTP status. This drives a sigild with enforcement ON and a
/// grace window of `1ms` (so a brand-new account is already past it) and asserts
/// the desktop renders the truth:
///
/// * a push is refused as [`DesktopError::PaymentRequired`] — its own kind, not
///   a generic server error — carrying the status, the checkout route and, in
///   the same breath, what is still available;
/// * **reads are not refused**;
/// * ⭐ **key recovery is not refused**: a lapsed customer can still PRINT A
///   RECOVERY KIT, which is the difference between "inconvenienced" and "one
///   device failure from permanent loss";
/// * the offline flow still generates codes, because none of this touches the
///   local vault.
#[test]
fn a_lapsed_account_is_refused_writes_but_never_reads_or_key_recovery() {
    let h = Harness::start_with(&[
        ("SIGILD_ENTITLEMENT_ENFORCE", "1"),
        // A brand-new account's grace runs from its creation, so 1ms means
        // "already lapsed" by the time the first write happens.
        ("SIGILD_ENTITLEMENT_GRACE", "1ms"),
        // Enforcement REQUIRES a subscription store to read; these are throwaway
        // values for a loopback server that never contacts a provider.
        ("SIGILD_BILLING_PROVIDERS", "stripe"),
        ("SIGILD_BILLING_SUCCESS_URL", "http://127.0.0.1/paid"),
        ("SIGILD_BILLING_CANCEL_URL", "http://127.0.0.1/cancelled"),
        ("SIGILD_STRIPE_SECRET_KEY", "sk_test_not_a_real_key_000000"),
        (
            "SIGILD_STRIPE_WEBHOOK_SECRET",
            "whsec_not_a_real_secret_0000",
        ),
    ]);
    println!("\n=== sigild up at {} (entitlement enforced)", h.server);

    let dir = h.tmp.join("lapsed/.sigil");
    let device = DeviceConfig::new(&h.server, &dir);
    device
        .enroll(TOKEN_DESKTOP, "lapsed device")
        .expect("enroll");
    device.publish_hybrid().expect("publish hybrid");

    let vault_path = dir.join("totp-vault.sigil");
    let mut session = VaultSession::create(&vault_path, DESKTOP_PASSWORD.as_bytes())
        .expect("create")
        .with_params(FAST);
    session
        .add_secret_base32(
            "rfc",
            None,
            RFC_SEED_B32,
            "sha1",
            Some(8),
            Some(PINNED_PERIOD),
        )
        .expect("add");
    let fp = session
        .convert_to_shared(&device, VAULT_FROM_DESKTOP)
        .expect("convert");
    drop(session);

    // ⛔ THE WRITE. Refused as a BILLING state, with everything a UI needs.
    let entitlement = match device.push_vault_file(VAULT_FROM_DESKTOP, &vault_path) {
        Err(DesktopError::PaymentRequired {
            entitlement,
            message,
        }) => {
            assert!(message.contains("402"), "{message}");
            assert!(
                message.contains("RECOVERY KIT"),
                "the refusal must say what still works: {message}"
            );
            *entitlement
        }
        other => panic!("expected a payment refusal, got {other:?}"),
    };
    assert!(entitlement.known && entitlement.needs_attention());
    assert_eq!(entitlement.writes, "refused");
    // ⭐ The two guarantees, as the server states them.
    assert_eq!(entitlement.reads, "allowed");
    assert_eq!(entitlement.key_recovery, "allowed");
    assert_eq!(entitlement.checkout_path, "/v1/billing/checkout");
    assert!(
        !entitlement.subscription_status.is_empty(),
        "the account's own status should be named: {entitlement:?}"
    );
    say(&format!(
        "a push is refused as PaymentRequired (status {}), not as a generic HTTP error",
        entitlement.subscription_status
    ));

    // ✅ READS ARE NEVER REFUSED. Nothing was ever pushed, so there is nothing
    // to return — but the answer is "nothing there", never a 402.
    assert!(
        device
            .pull_vault(VAULT_FROM_DESKTOP, 0)
            .expect("read")
            .is_none(),
        "a read must not be refused"
    );
    device
        .account()
        .expect("reading the account is not a write");
    assert!(device.check_server().expect("probe").reachable);

    // ⭐ AND KEY RECOVERY IS NEVER REFUSED. A lapsed customer can still print a
    // kit — the case ADR 0043 §3 exists for.
    let sheet = device
        .recovery_generate(&[VAULT_FROM_DESKTOP.to_string()])
        .expect("a lapsed account MUST still be able to print a recovery kit");
    assert_eq!(sheet.covered.len(), 1);
    assert_eq!(sheet.covered[0].key_fingerprint, fp);

    // ...and the honest half of that: the KEY is covered, the DATA never got
    // pushed, so `check` says so rather than claiming the vault is recoverable.
    let coverage = device.recovery_check(&sheet.device_id).expect("check");
    assert_eq!(coverage.len(), 1);
    assert!(coverage[0].covered, "{coverage:?}");
    assert!(
        !coverage[0].synced,
        "a vault that could not be pushed is NOT recoverable, and must not be reported as if it were: {coverage:?}"
    );
    say(
        "a lapsed account still printed a recovery kit, and `check` says the data was never synced",
    );

    // The local vault never depended on any of this.
    let still = VaultSession::unlock_shared(&vault_path, &device, VAULT_FROM_DESKTOP)
        .expect("offline unlock");
    assert_eq!(
        still.entries_at(now_unix()).expect("codes")[0].code,
        RFC_CODE
    );
    say("codes still generate locally — a payment state never costs a second factor");

    println!(
        "\nPASS — a lapsed account is refused WRITES with an actionable 402, and is refused \
         neither reads, nor key recovery, nor its own codes.\n"
    );
}

/// ⭐ THE GRACE PERIOD — the state a customer must be TOLD about, because it is
/// the only one they can still act on.
///
/// A grace period nobody is warned about is not a grace period; it is a delayed
/// outage. `sigild` publishes the warning two ways — a response header on a
/// served write, and the additive `entitlement` block on
/// `GET /v1/billing/subscription` — and the desktop can only see the second: the
/// `sigil-cli` transport returns a body and drops response headers.
///
/// Until this was wired, `EntitlementView::from_subscription_block` had ZERO
/// production call sites. The only writer of desktop entitlement state was
/// `track_write`, which yields "allowed" or "refused" and never "grace", so the
/// UI branch that says "Writes still work, for now." was unreachable code and a
/// desktop customer inside grace was never told.
#[test]
fn a_desktop_inside_its_grace_period_is_warned_before_any_write_is_refused() {
    let h = Harness::start_with(&[
        ("SIGILD_ENTITLEMENT_ENFORCE", "1"),
        // A brand-new account has never subscribed, so its grace runs from its
        // CREATION. A long window means it is inside grace for this whole test.
        ("SIGILD_ENTITLEMENT_GRACE", "24h"),
        ("SIGILD_BILLING_PROVIDERS", "stripe"),
        ("SIGILD_BILLING_SUCCESS_URL", "http://127.0.0.1/paid"),
        ("SIGILD_BILLING_CANCEL_URL", "http://127.0.0.1/cancelled"),
        ("SIGILD_STRIPE_SECRET_KEY", "sk_test_not_a_real_key_000000"),
        (
            "SIGILD_STRIPE_WEBHOOK_SECRET",
            "whsec_not_a_real_secret_0000",
        ),
    ]);
    println!(
        "\n=== sigild up at {} (entitlement enforced, 24h grace)",
        h.server
    );

    let dir = h.tmp.join("grace/.sigil");
    let device = DeviceConfig::new(&h.server, &dir);
    device
        .enroll(TOKEN_DESKTOP, "grace device")
        .expect("enroll");
    device.publish_hybrid().expect("publish hybrid");

    // ⭐ ASK. This is the whole fix: the client learns it has lapsed BEFORE a
    // write is ever refused.
    let view = device
        .subscription()
        .expect("the subscription route is never itself gated by entitlement");
    assert!(view.known, "{view:?}");
    assert_eq!(view.writes, "grace", "{view:?}");
    assert!(
        view.needs_attention(),
        "grace must raise the banner, not stay silent: {view:?}"
    );
    assert!(
        !view.grace_ends_at.is_empty(),
        "the customer needs the DEADLINE, not just the fact: {view:?}"
    );
    assert!(
        view.detail.contains(&view.grace_ends_at),
        "the rendered sentence must name the deadline: {view:?}"
    );
    // The two guarantees hold in this state as well.
    assert_eq!(view.reads, "allowed");
    assert_eq!(view.key_recovery, "allowed");
    say("inside grace, the desktop is WARNED and told exactly when writes stop");

    // ...and the write really is still served, which is what makes the warning a
    // warning rather than a refusal.
    let vault_path = dir.join("totp-vault.sigil");
    let mut session = VaultSession::create(&vault_path, DESKTOP_PASSWORD.as_bytes())
        .expect("create")
        .with_params(FAST);
    session
        .add_secret_base32(
            "rfc",
            None,
            RFC_SEED_B32,
            "sha1",
            Some(8),
            Some(PINNED_PERIOD),
        )
        .expect("add");
    session
        .convert_to_shared(&device, VAULT_FROM_DESKTOP)
        .expect("convert");
    drop(session);
    device
        .push_vault_file(VAULT_FROM_DESKTOP, &vault_path)
        .expect("a write INSIDE grace must still be served");
    say("the write inside grace is served — the warning is a warning, not a refusal");

    println!(
        "\nPASS — a desktop inside its grace period is warned, with a deadline, while its \
         writes are still being served.\n"
    );
}

// ---------------------------------------------------------------------------
// ⭐⭐ PHASE 61 — THE MULTI-DEVICE MERGE, against a real sigild and the real
// `sigil` binary.
//
// ⛔ THE DEFECT. `pull_and_adopt` used to take the NEWEST op and
// `write_private_bytes(path, &pulled.container)` — writing it straight over the
// local vault. So: this desktop adds an account and pushes; the CLI, which never
// pulled, adds a different one and pushes; the CLI's snapshot is now the tip, it
// has never seen the desktop's account, and one adopt destroys it. Both devices
// report success.
//
// ⭐ WHY THIS TEST IS HERE AND NOT ONLY IN THE LIBRARY. The desktop was once the
// ONLY client whose key-substitution defence had no test (Phase 51 fixed that).
// `docs/engineering-lessons.md` entry 10 is the general form: a fix guarded in
// the shared library and unguarded at the call site is deletable with the whole
// gate green. Reverting `pull_and_adopt` to write the pulled container must turn
// THIS test red.
// ---------------------------------------------------------------------------
#[test]
fn two_devices_that_each_added_offline_keep_both_accounts_after_a_merge() {
    const MERGE_VAULT: &str = "merge-two-devices";
    let h = Harness::start();
    println!("\n=== sigild up at {} (the multi-device merge)", h.server);

    let desktop_dir = h.tmp.join("m-desktop/.sigil");
    let cli_home = h.tmp.join("m-cli");
    std::fs::create_dir_all(&cli_home).expect("cli home");

    // --- both devices enroll and publish hybrid keys ----------------------
    let desktop = DeviceConfig::new(&h.server, &desktop_dir);
    let desktop_id = desktop
        .enroll(TOKEN_DESKTOP, "merge desktop")
        .expect("desktop enroll");
    desktop.publish_hybrid().expect("desktop hybrid");

    let cli_id = device_id_in(&h.cli(
        &cli_home,
        CLI_PASSWORD,
        &["device", "enroll", "--token", TOKEN_CLI, "--label", "cli"],
    ));
    h.cli(&cli_home, CLI_PASSWORD, &["device", "hybrid-publish"]);

    // --- the desktop creates a SHARED vault holding the RFC seed ----------
    let desktop_vault = desktop_dir.join("totp-vault.sigil");
    let mut session = VaultSession::create(&desktop_vault, DESKTOP_PASSWORD.as_bytes())
        .expect("create")
        .with_params(FAST);
    session
        .add_secret_base32(
            "shared-base",
            Some("Phase61".into()),
            RFC_SEED_B32,
            "sha1",
            Some(8),
            Some(PINNED_PERIOD),
        )
        .expect("add base");
    session
        .convert_to_shared(&desktop, MERGE_VAULT)
        .expect("convert to shared");
    drop(session);
    desktop
        .push_vault_file(MERGE_VAULT, &desktop_vault)
        .expect("push the base");

    // --- share it with the CLI so both devices hold the SAME vault key ----
    let (safety, _state) = desktop
        .peer_safety_number(&cli_id)
        .expect("read the CLI's safety number");
    desktop
        .share_vault(MERGE_VAULT, &cli_id, "write", Some(&safety))
        .expect("share");
    h.cli(
        &cli_home,
        CLI_PASSWORD,
        &["vault", "accept", "--vault", MERGE_VAULT],
    );
    let cli_vault = cli_home.join("cli-vault.sigil");
    h.cli(
        &cli_home,
        CLI_PASSWORD,
        &[
            "totp",
            "sync",
            MERGE_VAULT,
            "--vault-id",
            MERGE_VAULT,
            "--vault",
            cli_vault.to_str().expect("path"),
        ],
    );
    say(&format!(
        "desktop {desktop_id} and CLI {cli_id} both hold the vault key for {MERGE_VAULT}"
    ));

    // =====================================================================
    // ⛔ THE PARTITION. Each device adds a DIFFERENT account, neither pulls.
    // =====================================================================
    let mut local = VaultSession::unlock_shared(&desktop_vault, &desktop, MERGE_VAULT)
        .expect("unlock shared")
        .with_params(FAST);
    local
        .add_secret_base32(
            "only-on-desktop",
            None,
            RFC_SEED_B32,
            "sha1",
            Some(8),
            Some(PINNED_PERIOD),
        )
        .expect("desktop-only account");
    drop(local);
    desktop
        .push_vault_file(MERGE_VAULT, &desktop_vault)
        .expect("desktop push");

    // The CLI, which never pulled the line above, adds its own and pushes.
    // Its snapshot becomes THE TIP and has never seen `only-on-desktop`.
    h.cli(
        &cli_home,
        CLI_PASSWORD,
        &[
            "totp",
            "add",
            "only-on-cli",
            "--secret",
            RFC_SEED_B32,
            "--digits",
            "8",
            "--period",
            "30",
            "--vault-id",
            MERGE_VAULT,
            "--vault",
            cli_vault.to_str().expect("path"),
        ],
    );
    // ⚠️ `sigil push`, NOT `sigil totp sync`. This is the whole point of the
    // partition and a MUTATION EXPOSED THAT IT WAS WRONG HERE: `totp sync` MERGES
    // before it pushes, so its snapshot already contained the desktop's account
    // and the tip was the union — which meant reverting `pull_and_adopt` to adopt
    // the tip left this test GREEN. `push` uploads the CLI's own container
    // verbatim, so the tip genuinely has never seen `only-on-desktop`.
    h.cli(
        &cli_home,
        CLI_PASSWORD,
        &[
            "push",
            "--vault",
            MERGE_VAULT,
            "--in",
            cli_vault.to_str().expect("path"),
        ],
    );
    say("both devices pushed WITHOUT pulling first — the tip has never seen the desktop's account");

    // ⭐ ASSERT THE SETUP, so a future change cannot silently un-partition it and
    // leave this test proving nothing. The tip must NOT contain the desktop's
    // account; if it does, adopting the tip would pass and the test is a lie.
    {
        let ops = desktop
            .pull_vault_ops(MERGE_VAULT, 0)
            .expect("read the raw op-log");
        let tip = ops.iter().max_by_key(|o| o.seq).expect("at least one op");
        let key = desktop
            .vault_key(MERGE_VAULT)
            .expect("keyring")
            .expect("key");
        let tip_vault = sigil_cli::open_vault(&key, &tip.blob).expect("open the tip");
        assert!(
            !tip_vault
                .entries
                .iter()
                .any(|e| e.label == "only-on-desktop"),
            "THE SETUP IS BROKEN: the tip already holds the desktop's account, so adopting \
             it wholesale would pass and this test would prove nothing"
        );
        say(&format!(
            "the tip (op #{}) holds {:?} — adopting it wholesale is the defect",
            tip.seq,
            tip_vault
                .entries
                .iter()
                .map(|e| &e.label)
                .collect::<Vec<_>>()
        ));
    }

    // =====================================================================
    // ⭐ THE ASSERTION. The desktop merges and must hold ALL THREE.
    // =====================================================================
    let adopted = desktop_dir.join("merged.sigil");
    let (merged, seq) = pull_and_adopt(&desktop, MERGE_VAULT, &adopted, 0)
        .expect("pull and merge")
        .expect("the server has ops");
    assert!(seq >= 3, "expected at least 3 ops, saw tip {seq}");
    assert_0600(&adopted);

    let views = merged.entries_at(59).expect("codes at T=59");
    let mut labels: Vec<&str> = views.iter().map(|v| v.label.as_str()).collect();
    labels.sort_unstable();
    assert_eq!(
        labels,
        vec!["only-on-cli", "only-on-desktop", "shared-base"],
        "⛔ THE MERGE LOST AN ACCOUNT — adopting the tip wholesale is the defect this fixes"
    );

    // ⭐ The SECRETS survived, not merely the labels: every one of these carries
    // the RFC 6238 App B seed, so at T=59 the 30s entry reads the vector and the
    // pinned-period ones read it at ANY instant.
    let cli_view = views
        .iter()
        .find(|v| v.label == "only-on-cli")
        .expect("the CLI's account");
    assert_eq!(
        cli_view.code, RFC_CODE,
        "the CLI's account crossed the merge without its secret"
    );
    let now_views = merged.entries_at(now_unix()).expect("codes now");
    let own = now_views
        .iter()
        .find(|v| v.label == "only-on-desktop")
        .expect("the desktop's own account");
    assert_eq!(
        own.code, RFC_CODE,
        "the desktop's OWN account crossed the merge without its secret"
    );
    // Every view carries a stable identity a UI can remove by.
    assert!(
        views.iter().all(|v| v.uuid.len() == 36),
        "every EntryView must carry a stable id: {:?}",
        views.iter().map(|v| v.uuid.clone()).collect::<Vec<_>>()
    );
    say("(a) the desktop merged 3 ops and holds ALL THREE accounts, with correct codes");

    // =====================================================================
    // DELETE — a removal must survive meeting a snapshot that still holds it.
    // =====================================================================
    let mut after = VaultSession::unlock_shared(&adopted, &desktop, MERGE_VAULT)
        .expect("reopen merged")
        .with_params(FAST);
    after.remove("only-on-cli").expect("remove");
    assert_eq!(after.len(), 2);
    drop(after);
    desktop
        .push_vault_file(MERGE_VAULT, &adopted)
        .expect("push the delete");

    // The CLI still HOLDS `only-on-cli` and has not pulled. It syncs, which both
    // merges the delete in AND pushes its post-merge snapshot back.
    let cli_after = h.cli(
        &cli_home,
        CLI_PASSWORD,
        &[
            "totp",
            "sync",
            MERGE_VAULT,
            "--vault-id",
            MERGE_VAULT,
            "--vault",
            cli_vault.to_str().expect("path"),
        ],
    );
    let cli_list = h.cli(
        &cli_home,
        CLI_PASSWORD,
        &[
            "totp",
            "list",
            "--vault-id",
            MERGE_VAULT,
            "--vault",
            cli_vault.to_str().expect("path"),
        ],
    );
    assert!(
        !cli_list.contains("only-on-cli"),
        "the delete did not reach the CLI — a tombstone must beat a stale snapshot.\n\
         sync said: {cli_after}\nlist said: {cli_list}"
    );

    // ⭐ And it must STAY deleted after the CLI's own snapshot comes back round.
    let re = desktop_dir.join("merged2.sigil");
    let (final_vault, _) = pull_and_adopt(&desktop, MERGE_VAULT, &re, 0)
        .expect("second merge")
        .expect("ops");
    let final_labels: Vec<String> = final_vault
        .entries_at(59)
        .expect("codes")
        .into_iter()
        .map(|v| v.label)
        .collect();
    assert!(
        !final_labels.contains(&"only-on-cli".to_string()),
        "⛔ RESURRECTION: the deleted account came back through an older snapshot: {final_labels:?}"
    );
    assert_eq!(final_labels.len(), 2, "{final_labels:?}");
    say("(b) a delete converges and does NOT resurrect through an older snapshot");

    println!(
        "\nPASS — two devices each added an account offline; after syncing BOTH hold BOTH, \
         the secrets survived (RFC 6238 {RFC_CODE}), and a delete converges without \
         resurrecting.\n"
    );
}
