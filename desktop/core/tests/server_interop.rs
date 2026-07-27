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
        desktop.share_vault(VAULT_FROM_DESKTOP, "dev_whoever", "read"),
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
        .share_vault(VAULT_FROM_DESKTOP, &cli_id, "read")
        .expect("share to the CLI device");
    assert_eq!(share_fp, shared_fp, "shared the same key it holds");

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
        .accept_vault(VAULT_FROM_CLI)
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
    match third.accept_vault(VAULT_FROM_DESKTOP) {
        Err(DesktopError::Forbidden(_)) | Err(DesktopError::MissingOnServer(_)) => {}
        other => panic!("a third device must not collect an envelope, got {other:?}"),
    }
    say("an enrolled but unauthorized third device is refused (403) on read and on accept");

    // An UNENROLLED desktop: a clear error, never a panic.
    let unenrolled = DeviceConfig::new(&h.server, &unenrolled_dir);
    for err in [
        unenrolled.publish_hybrid().unwrap_err(),
        unenrolled.accept_vault(VAULT_FROM_DESKTOP).unwrap_err(),
        unenrolled
            .share_vault(VAULT_FROM_DESKTOP, &cli_id, "read")
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

    // A real peer publishes its first hybrid key, K1.
    let cli_id = device_id_in(&h.cli(
        &cli_home,
        CLI_PASSWORD,
        &["device", "enroll", "--token", TOKEN_CLI, "--label", "cli"],
    ));
    h.cli(&cli_home, CLI_PASSWORD, &["device", "hybrid-publish"]);

    // The first share is what PINS K1. It must succeed.
    desktop
        .share_vault(VAULT_FROM_DESKTOP, &cli_id, "read")
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
    let presented = match desktop.share_vault(VAULT_FROM_DESKTOP, &cli_id, "read") {
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
                std::slice::from_ref(&cli_id)
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
            desktop.share_vault(VAULT_FROM_DESKTOP, &cli_id, "read"),
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
        .share_vault(VAULT_FROM_DESKTOP, &cli_id, "read")
        .expect("sharing resumes once the new key is deliberately pinned");
    say("after a deliberate re-pin to the presented number, sharing resumes");

    println!("\nPASS — a substituted hybrid key is detected, refused with both safety numbers, blocks rotation, survives a wrong-number re-pin, and clears only on a deliberate one.\n");
}
