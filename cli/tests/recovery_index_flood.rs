//! THE RECOVERY-DISCOVERY PROOF — a third party must not be able to turn a
//! recovery into a SILENT PARTIAL, and must not be able to deny it outright.
//!
//! # What this reproduces, against a REAL `sigild`, with no mocks
//!
//! `GET /v1/devices/{deviceID}/keys` is how a restored recovery kit — a machine
//! with **no local state at all** — finds out which vaults it can decrypt. It is
//! **one page, capped at 500 rows, with NO CURSOR**.
//!
//! Any account can put rows in that page: deposit an opaque envelope addressed to
//! a device id it knows, then grant that device `read` on a vault it claimed
//! itself (trust-on-first-write places no cap on how many vaults one account may
//! own). Nothing is decrypted, nothing is forged — but genuine rows get pushed
//! off the single page, and `has_more` goes true.
//!
//! ⚠️ **The kit's device id is not guessable (128 bits of CSPRNG) — but it is not
//! secret either.** `GET /v1/vaults/{id}/grants` discloses it with `read` alone,
//! so any current *or former* collaborator on a vault the kit covers keeps it
//! permanently, and revocation cannot un-learn it (ADR 0038).
//!
//! # The failures this pins, in order of sharpness
//!
//! 0. ⛔⛔ **THE STRANGER'S VAULT, PRESENTED AS YOURS.** Every input to a
//!    vault-key wrap is PUBLIC — sigild serves any device's published hybrid key
//!    to any authenticated device, and the AAD is (purpose, vault id, recipient
//!    id, sender id). So a stranger can mint an envelope that authenticates
//!    PERFECTLY: `hybrid_auth_seal` (ADR 0048) proves WHO deposited it and says
//!    **nothing** about whether they are trusted. A restore runs on a machine
//!    with an EMPTY pin store, so first-sight TOFU pinned the stranger's key,
//!    unwrapped, opened their container and reported it as a RECOVERED VAULT —
//!    to the one person who by definition has nothing left to check it against.
//!    The rule: a vault **named on the sheet** is vouched for by the user; a
//!    vault the **index alone** introduced is processed only if its sender is a
//!    device in the kit's **own account**, decided before any network call for
//!    that row.
//! 1. ⛔ **THE SILENT PARTIAL.** The Rust CLI's index deserializer had no
//!    `has_more` field at all and `recovery_restore` never looked, so a truncated
//!    page meant restoring the visible prefix and **reporting success**. That is
//!    the worst possible outcome for the one mechanism whose entire job is
//!    answering *"did I get everything back?"* — and it lands on the one person
//!    who has nothing left to check it against. The JS half has refused since
//!    Phase 58; Rust did not.
//! 2. **DENIAL.** Refusing is correct but is not, on its own, a recovery. So the
//!    real fix is that a restore does not have to use that route: ⭐ **the printed
//!    sheet already carries the covered vault ids**, and `--vault` makes the
//!    restore ask each VAULT directly (`GET /v1/vaults/{id}/keys` +
//!    `GET /v1/vaults/{id}/keys/{deviceID}`). Both are addressed BY VAULT ID, so
//!    there is nothing for a flood to crowd out.
//!
//! # What is asserted
//!
//! * BEFORE: the index lists the real vault, `has_more` is false, restore works.
//! * The flood: a SECOND account, contract-v3 signed throughout, fills the page.
//! * AFTER: `has_more` is true and the real vault is **gone from the listing**.
//! * ⛔ A restore with no vault ids **REFUSES**, names `--vault`, and writes
//!   NOTHING — never a success-shaped partial.
//! * ⭐ A restore given the sheet's vault id **SUCCEEDS**: the real vault comes
//!   back with its entries, `index_truncated` is true and `from_sheet` names it,
//!   so the report cannot be mistaken for "everything".
//! * The same two outcomes through the **REAL `sigil` binary**, which is what a
//!   human actually runs.
//! * ⛔⛔ EXACTLY the sheet's vault comes back. The 520 planted envelopes are
//!   **genuine and authenticated**; none is unwrapped, none is written to disk,
//!   and the stranger's key is **never pinned**. They are reported as ONE
//!   COUNT, because rendering a flood row by row buries the real result —
//!   which is exactly what the flood is for.
//! * ⭐ In a second test, with ONE route broken by a proxy in front of the real
//!   server: the sheet path still recovers when the per-device index is DEAD
//!   (it is not gated behind the route it exists to bypass), and one unreadable
//!   vault is a **per-vault** failure that does not erase the report of the
//!   vaults already restored.
//!
//! STATUS: pre-audit, DEV-ONLY, UNAUDITED, loopback + plain HTTP. sigild is bound
//! to a free 127.0.0.1 port and killed in a `Drop` guard.

use std::io::{Read as _, Write as _};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use sigil_cli::{
    enroll_device, fetch_hybrid_key, generate_key, generate_vault_key, grant_vault_access,
    keyring_put, list_recoverable_vaults, new_totp_entry, publish_hybrid_key, push_op_auth,
    put_key_envelope, recovery_generate, recovery_restore, seal_vault, wrap_vault_key, CliError,
    RequestAuth, SenderIdentity, TotpVault, VaultKeyWrapContext,
};
use sigil_core::{Argon2Params, OtpAlgorithm};

/// ASCII "12345678901234567890" — the PUBLIC RFC 4226 / RFC 6238 test seed. Not a
/// real secret: that is the entire point of a published vector.
const RFC_SEED: &[u8] = b"12345678901234567890";

/// The victim's one real vault. Named to sort AFTER the spam ids below, because
/// `ListKeyEnvelopesForRecipient` sorts by vault id — which is exactly how a
/// flood pushes a genuine row off the page.
const REAL_VAULT: &str = "zz-real-vault";
/// Enough spam vaults to overflow sigild's `maxRecipientIndexRows` (500).
const SPAM_VAULTS: usize = 520;
/// How many of the planted vaults also get a pushed container the planted key
/// opens. Without the trust rule these come back as fully-formed "recovered"
/// vaults — the sharpest form of the defect, and cheap to arrange for a few.
const PLANTED_WITH_CONTENT: usize = 5;

const TOKEN_VICTIM: &str = "tok-victim-00000000000000001";
const TOKEN_ATTACKER: &str = "tok-attacker-000000000000002";
/// A third account, so the file-name-collision proof does not share state with
/// the flood tests (`cargo test` runs these in PARALLEL threads of one process).
const TOKEN_COLLIDE: &str = "tok-collide-0000000000000003";
const ADMIN_TOKEN: &str = "admin-token-0000000000000001";

/// Cheap Argon2id so the test stays fast while still exercising the REAL KDF.
/// The parameters ride in the container header. (Argon2: `m_cost >= 8 * p_cost`.)
const FAST: Argon2Params = Argon2Params {
    m_cost: 8,
    t_cost: 1,
    p_cost: 1,
};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// `<repo>/cli` -> `<repo>`.
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("repo root is one level above cli/")
        .to_path_buf()
}

/// Locate a usable `go`.
///
/// Deliberately NOT a graceful skip. This is the only thing proving the recovery
/// path survives a real server being flooded, and a suite that silently skips
/// when a toolchain is missing reads exactly like one that passes — a failure
/// mode this repo has been bitten by more than once. Absent Go ⇒ PANIC.
fn resolve_go() -> String {
    if let Ok(go) = std::env::var("GO") {
        return go;
    }
    if Command::new("go")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return "go".to_string();
    }
    let brew = "/opt/homebrew/bin/go";
    if Path::new(brew).exists() {
        return brew.to_string();
    }
    panic!(
        "no Go toolchain found: this test builds the real sigild. \
         Install Go, put it on PATH, or set GO=/path/to/go"
    );
}

struct Harness {
    tmp: PathBuf,
    server: String,
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

impl Harness {
    fn start() -> Harness {
        let root = repo_root();
        // pid + nanos + a counter: `cargo test` runs integration tests in
        // parallel threads of ONE process, and two harnesses sharing a temp dir
        // delete each other's state (a real bug already hit in this repo).
        static NTH: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let nth = NTH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp = std::env::temp_dir().join(format!(
            "sigil-recovery-flood-{}-{nanos}-{nth}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("scratch dir");

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
                format!("{TOKEN_VICTIM},{TOKEN_ATTACKER},{TOKEN_COLLIDE}"),
            )
            .env("SIGILD_ADMIN_TOKEN", ADMIN_TOKEN)
            .stdout(Stdio::from(log.try_clone().expect("clone log")))
            .stderr(Stdio::from(log))
            .spawn()
            .expect("could not spawn sigild");

        let harness = Harness {
            tmp,
            server,
            child: Some(child),
        };
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
}

// ---------------------------------------------------------------------------
// A fail-injecting proxy
// ---------------------------------------------------------------------------

/// A loopback HTTP proxy in front of the REAL sigild that answers `500` for
/// selected `(method, path-prefix)` pairs and forwards everything else verbatim.
///
/// ⭐ WHY THIS AND NOT A MOCK SERVER: the point of these two arms is that a
/// restore survives ONE route being broken while the rest of a genuine server
/// keeps working. A mock would have to reimplement enrollment, signing,
/// ownership and the op-log — and a double that is more permissive than the real
/// thing is this repo's most repeated failure. So every byte still goes to the
/// real sigild; the proxy only refuses the exact route under test.
///
/// ⚠️ Signatures survive proxying because sigild's canonical v3 message covers
/// `(device, method, path, query, timestamp, nonce, body)` and NOT the `Host`
/// header. Each request is forwarded on its own upstream connection with
/// `Connection: close`, so the response has a definite end without parsing
/// chunked encoding.
struct FailProxy {
    url: String,
    stop: Arc<AtomicBool>,
}

impl Drop for FailProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl FailProxy {
    /// `rules` are `(METHOD, path-prefix)`; a match is answered `500` and the
    /// upstream never sees the request.
    fn start(upstream: &str, rules: Vec<(String, String)>) -> FailProxy {
        let upstream_addr = upstream
            .trim_start_matches("http://")
            .trim_end_matches('/')
            .to_string();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind proxy");
        let port = listener.local_addr().expect("proxy addr").port();
        listener
            .set_nonblocking(true)
            .expect("proxy non-blocking accept");
        let stop = Arc::new(AtomicBool::new(false));
        let stop_thread = Arc::clone(&stop);
        std::thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((sock, _)) => {
                        let rules = rules.clone();
                        let up = upstream_addr.clone();
                        std::thread::spawn(move || {
                            let _ = sock.set_nonblocking(false);
                            let _ = proxy_one(sock, &up, &rules);
                        });
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        FailProxy {
            url: format!("http://127.0.0.1:{port}"),
            stop,
        }
    }
}

/// Serve exactly one request: read the head (+ body), decide, forward or refuse.
fn proxy_one(
    mut client: TcpStream,
    upstream: &str,
    rules: &[(String, String)],
) -> std::io::Result<()> {
    // Read until the end of the header block. Requests here are small.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if client.read(&mut byte)? == 0 {
            return Ok(());
        }
        head.push(byte[0]);
        if head.len() > 64 * 1024 {
            return Ok(());
        }
    }
    let head_str = String::from_utf8_lossy(&head).to_string();
    let mut lines = head_str.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or_default().to_string();
    let target = parts.next().unwrap_or_default().to_string();
    let path = target.split('?').next().unwrap_or_default().to_string();

    let mut content_length = 0usize;
    for line in lines {
        if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        client.read_exact(&mut body)?;
    }

    if rules
        .iter()
        .any(|(m, prefix)| m == &method && path.starts_with(prefix.as_str()))
    {
        let payload = b"{\"error\":\"internal\"}";
        let resp = format!(
            "HTTP/1.1 500 Internal Server Error\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            payload.len()
        );
        client.write_all(resp.as_bytes())?;
        client.write_all(payload)?;
        return client.flush();
    }

    // Forward on a fresh upstream connection, forcing a close-delimited response.
    let mut up = TcpStream::connect(upstream)?;
    let mut out = format!("{request_line}\r\n");
    for line in head_str.split("\r\n").skip(1) {
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("connection:") || lower.starts_with("keep-alive:") {
            continue;
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out.push_str("Connection: close\r\n\r\n");
    up.write_all(out.as_bytes())?;
    up.write_all(&body)?;
    up.flush()?;
    let mut response = Vec::new();
    up.read_to_end(&mut response)?;
    client.write_all(&response)?;
    client.flush()
}

/// One enrolled device, holding everything needed to sign as itself.
struct Device {
    id: String,
    seed: [u8; 32],
    hybrid: sigil_cli::HybridSecretIdentity,
    home: PathBuf,
}

impl Device {
    fn auth(&self) -> RequestAuth<'_> {
        RequestAuth::V3 {
            device_id: &self.id,
            seed: &self.seed,
        }
    }
    fn keyring(&self) -> PathBuf {
        self.home.join("vault-keys.json")
    }
    fn pins(&self) -> PathBuf {
        self.home.join("hybrid-pins.json")
    }
    fn sender(&self) -> SenderIdentity {
        SenderIdentity::new(&self.id, self.hybrid.clone()).expect("sender identity")
    }
}

/// Enroll a device with an operator token — which always founds a NEW account
/// (ADR 0040), so the attacker below is genuinely a separate party.
fn enroll(h: &Harness, token: &str, label: &str, home_name: &str) -> Device {
    let home = h.tmp.join(home_name);
    std::fs::create_dir_all(&home).expect("home");
    let key = generate_key().expect("device key");
    let seed: [u8; 32] = base64_decode(&key.seed);
    let public: [u8; 32] = base64_decode(&key.public_key);
    let info = enroll_device(&h.server, token, label, &public, &seed).expect("enroll");
    let (secret, public_hybrid) = sigil_cli::generate_hybrid_identity().expect("hybrid identity");
    let dev = Device {
        id: info.device_id,
        seed,
        hybrid: secret,
        home,
    };
    publish_hybrid_key(&h.server, &dev.id, &public_hybrid, &dev.auth()).expect("publish hybrid");
    dev
}

fn base64_decode<const N: usize>(s: &str) -> [u8; N] {
    use base64::Engine as _;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(s)
        .expect("base64");
    let mut out = [0u8; N];
    assert_eq!(raw.len(), N, "unexpected key length");
    out.copy_from_slice(&raw);
    out
}

/// Create a SHARED vault holding the RFC 6238 seed, push it, and record its key.
fn create_and_push_vault(h: &Harness, dev: &Device, vault_id: &str) -> [u8; 32] {
    let mut vault = TotpVault::default();
    vault.entries.push(
        new_totp_entry(
            "rfc-vector",
            Some("sigil-test".to_string()),
            RFC_SEED,
            OtpAlgorithm::Sha1,
            8,
            30,
        )
        .expect("entry"),
    );
    let key = generate_vault_key().expect("vault key");
    let container = seal_vault(&key, &vault, FAST).expect("seal");
    push_op_auth(&h.server, vault_id, &container, &dev.auth()).expect("push");
    keyring_put(&dev.keyring(), vault_id, &key).expect("keyring");
    key
}

/// Run the real `sigil` binary with the kit's code on stdin (never in argv).
fn sigil_restore(h: &Harness, home: &Path, code: &str, args: &[&str]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sigil"))
        .arg("recovery")
        .arg("restore")
        .args(["--server", &h.server])
        .args(["--code-stdin"])
        .args(args)
        .env("HOME", home)
        .env_remove("SIGIL_SERVER")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sigil");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(format!("{code}\n").as_bytes())
        .expect("write code");
    child.wait_with_output().expect("wait sigil")
}

fn say(msg: &str) {
    println!("  * {msg}");
}

// ---------------------------------------------------------------------------
// THE PROOF
// ---------------------------------------------------------------------------

#[test]
fn a_flooded_envelope_index_cannot_produce_a_silent_partial_recovery() {
    let h = Harness::start();

    // -------------------------------------------------------------------
    // 1. The victim: one shared vault, pushed, covered by a printed kit.
    // -------------------------------------------------------------------
    let victim = enroll(&h, TOKEN_VICTIM, "victim-laptop", "victim");
    create_and_push_vault(&h, &victim, REAL_VAULT);
    let kit = recovery_generate(
        &h.server,
        &victim.auth(),
        &[REAL_VAULT.to_string()],
        &victim.keyring(),
        &victim.pins(),
        None,
        &victim.sender(),
    )
    .expect("generate the recovery kit");
    let kit_id = kit.public.device_id.clone();
    let code = kit.code.clone();
    assert_eq!(
        kit.public.covered,
        vec![REAL_VAULT.to_string()],
        "the SHEET must carry the covered vault ids — that is the whole fallback"
    );
    say(&format!(
        "kit {kit_id} printed; sheet covers {:?}",
        kit.public.covered
    ));

    let kit_seed = sigil_cli::recovery_verify(&code).expect("decode the printed code");
    let kit_identity = sigil_cli::derive_recovery_identity(&kit_seed);
    let kit_auth = RequestAuth::V3 {
        device_id: &kit_id,
        seed: &kit_identity.ed25519_seed,
    };

    // -------------------------------------------------------------------
    // 2. BEFORE — discovery works and the index is complete.
    // -------------------------------------------------------------------
    let before = list_recoverable_vaults(&h.server, &kit_id, &kit_auth).expect("index before");
    assert!(!before.truncated, "index must start complete: {before:?}");
    assert!(
        before.vaults.iter().any(|v| v.vault_id == REAL_VAULT),
        "the real vault must be visible before the flood: {before:?}"
    );
    say(&format!(
        "BEFORE: count={} truncated={} real vault visible=true",
        before.vaults.len(),
        before.truncated
    ));

    // -------------------------------------------------------------------
    // 3. THE FLOOD. A SEPARATE account (its own operator token founds one),
    //    signing every request under contract v3. It decrypts nothing and
    //    forges nothing: it deposits opaque bytes addressed to a device id it
    //    knows, and grants that device read on vaults it claimed itself.
    // -------------------------------------------------------------------
    let attacker = enroll(&h, TOKEN_ATTACKER, "attacker", "attacker");
    assert_ne!(attacker.id, victim.id);

    // ⭐⭐ THE ENVELOPES ARE GENUINE, AND THAT IS THE WHOLE POINT OF THIS ARM.
    //
    // An earlier version of this flood deposited 64 bytes of `0x5a`, which the
    // AEAD refuses — so it proved the index could be crowded and NOTHING about
    // what a restore does with a row it can actually open. Every input to a
    // vault-key wrap is PUBLIC: sigild serves any device's published hybrid key
    // to any authenticated device (`deviceHybridKeyFetch`), and the AAD is
    // (purpose, vault id, recipient id, sender id). So a stranger can mint an
    // envelope that authenticates PERFECTLY under ADR 0048 — `hybrid_auth_seal`
    // proves WHO deposited it and says nothing about whether they are trusted.
    // On a fresh machine the pin store is empty, so first-sight TOFU pins the
    // stranger's key, unwraps, opens their container, and hands it back as a
    // RECOVERED VAULT to the one person with nothing left to check it against.
    let kit_hybrid_public = fetch_hybrid_key(&h.server, &kit_id, &attacker.auth())
        .expect("the kit's PUBLIC hybrid key");
    let attacker_key = generate_vault_key().expect("the attacker's chosen vault key");
    let mut attacker_vault = TotpVault::default();
    attacker_vault.entries.push(
        new_totp_entry(
            "PLANTED-BY-A-STRANGER",
            Some("not-yours".to_string()),
            RFC_SEED,
            OtpAlgorithm::Sha1,
            8,
            30,
        )
        .expect("entry"),
    );
    let attacker_container =
        seal_vault(&attacker_key, &attacker_vault, FAST).expect("seal the attacker's vault");

    let started = Instant::now();
    for i in 0..SPAM_VAULTS {
        // Sorts BEFORE REAL_VAULT, so these are the rows that survive the cap.
        let vault_id = format!("aaa-spam-{i:05}");
        // A GENUINE, correctly-authenticated envelope for a key of the
        // attacker's choosing, bound to (this vault, this kit, this sender).
        let ctx = VaultKeyWrapContext::new(&vault_id, &kit_id, &attacker.id).expect("wrap context");
        let envelope = wrap_vault_key(&attacker.sender(), &kit_hybrid_public, &ctx, &attacker_key)
            .expect("the attacker mints a GENUINE authenticated envelope");
        // A non-empty deposit is a WRITE, and a write to an unclaimed vault
        // claims it for the writer's account (trust-on-first-write).
        put_key_envelope(&h.server, &vault_id, &kit_id, &envelope, &attacker.auth())
            .expect("attacker deposit");
        // Read authorization is what makes the row survive the index's
        // per-row authorizeVault(needRead) filter.
        grant_vault_access(&h.server, &vault_id, &kit_id, "read", &attacker.auth())
            .expect("attacker grant");
        // A handful also get real op-log content, so that WITHOUT the fix they
        // come back as fully-formed "recovered" vaults rather than merely
        // poisoning the keyring and the pin store.
        if i < PLANTED_WITH_CONTENT {
            push_op_auth(&h.server, &vault_id, &attacker_container, &attacker.auth())
                .expect("attacker pushes a container the planted key opens");
        }
    }
    say(&format!(
        "flooded {SPAM_VAULTS} vaults from a second account in {:.1}s — every envelope GENUINE \
         and authenticated, {PLANTED_WITH_CONTENT} of them backed by a real container",
        started.elapsed().as_secs_f64()
    ));

    // -------------------------------------------------------------------
    // 4. AFTER — the page is full of someone else's rows.
    // -------------------------------------------------------------------
    let after = list_recoverable_vaults(&h.server, &kit_id, &kit_auth).expect("index after");
    assert!(
        after.truncated,
        "the flood must truncate the index; got {} rows, truncated={}",
        after.vaults.len(),
        after.truncated
    );
    assert!(
        !after.vaults.iter().any(|v| v.vault_id == REAL_VAULT),
        "the genuine vault must have been pushed off the single page — if it is still \
         listed the flood was too small and this test proves nothing"
    );
    say(&format!(
        "AFTER: count={} truncated={} real vault PUSHED OUT",
        after.vaults.len(),
        after.truncated
    ));

    // -------------------------------------------------------------------
    // 5. ⛔ THE SHARP ONE. A restore that relies on discovery must REFUSE —
    //    never restore the visible prefix and report success.
    // -------------------------------------------------------------------
    let blind_dir = h.tmp.join("restore-blind");
    let err = recovery_restore(&code, &h.server, &kit_id, &blind_dir, false, &[])
        .expect_err("a truncated index MUST NOT produce a success-shaped partial restore");
    let msg = err.to_string();
    assert!(
        matches!(err, CliError::Recovery(_)),
        "expected a recovery refusal, got {err:?}"
    );
    assert!(
        msg.contains("REFUSES") && msg.contains("NOTHING WAS RESTORED"),
        "the refusal must say plainly that nothing was restored: {msg}"
    );
    assert!(
        msg.contains("--vault"),
        "the refusal must name the way out (the sheet's vault ids): {msg}"
    );
    assert!(
        !blind_dir.join("vault-keys.json").exists(),
        "a refused restore must write NOTHING"
    );
    say("a restore with no sheet ids REFUSES, names --vault, and writes nothing");

    // -------------------------------------------------------------------
    // 6. ⭐ THE WAY OUT. The sheet names the vault; asking that vault directly
    //    cannot be crowded out by anything.
    // -------------------------------------------------------------------
    let sheet_dir = h.tmp.join("restore-sheet");
    let report = recovery_restore(
        &code,
        &h.server,
        &kit_id,
        &sheet_dir,
        false,
        &[REAL_VAULT.to_string()],
    )
    .expect("restoring by the sheet's vault ids must SUCCEED");
    let recovered: Vec<&str> = report
        .vaults
        .iter()
        .map(|(v, _, _, _)| v.as_str())
        .collect();
    assert!(
        recovered.contains(&REAL_VAULT),
        "the sheet's vault must come back: recovered={recovered:?} skipped={:?}",
        report.skipped
    );
    let entries = report
        .vaults
        .iter()
        .find(|(v, _, _, _)| v == REAL_VAULT)
        .map(|(_, _, _, n)| *n)
        .expect("the real vault");
    assert_eq!(entries, 1, "the recovered vault must hold its account");
    assert!(
        report.index_truncated,
        "a truncated index must be REPORTED even on the successful path — otherwise \
         this is still a partial dressed up as a complete recovery"
    );
    assert!(
        report.from_sheet.contains(&REAL_VAULT.to_string()),
        "the report must say the vault came from the SHEET, not the index: {:?}",
        report.from_sheet
    );
    say(&format!(
        "restoring by the sheet recovered {REAL_VAULT} ({entries} entry) with \
         index_truncated=true and from_sheet={:?}",
        report.from_sheet
    ));

    // -------------------------------------------------------------------
    // 6b. ⛔⛔ THE SHARPEST ARM. Every planted envelope AUTHENTICATES —
    //     ADR 0048 proves WHO sent it and nothing about whether they are
    //     trusted. A restore must therefore refuse to be INTRODUCED to a vault
    //     by a stranger, and must not pin a stranger's key while doing it.
    // -------------------------------------------------------------------
    assert_eq!(
        recovered,
        vec![REAL_VAULT],
        "a restore must recover EXACTLY the vault the sheet named. Anything else here is a \
         vault a STRANGER introduced through the index, unwrapped from a genuine envelope and \
         presented to the user as recovered: {recovered:?}"
    );
    // Every row the index actually returned was a stranger's (the flood pushed
    // the genuine one off the page), and every one of them must have been
    // ignored — reported as ONE COUNT, never one line each.
    assert_eq!(
        report.ignored_untrusted,
        after.vaults.len(),
        "every listed row here was deposited by another account and must have been ignored; \
         got ignored_untrusted={} for {} listed rows",
        report.ignored_untrusted,
        after.vaults.len()
    );
    assert!(
        report.ignored_untrusted > 100,
        "the flood must actually have filled the page, else this arm proves nothing: {}",
        report.ignored_untrusted
    );
    assert!(
        report.skipped.len() < 20,
        "a flood must not be rendered one line per row — that buries the real result, which is \
         exactly what the flood is for; got {} skipped lines",
        report.skipped.len()
    );
    // ⭐ NOT FETCHED, NOT UNWRAPPED, NOT PINNED. The pin store is the durable
    // consequence: a pinned stranger reads as "trusted" to every later check.
    let pins_after =
        std::fs::read_to_string(sheet_dir.join("hybrid-pins.json")).unwrap_or_default();
    assert!(
        !pins_after.contains(&attacker.id),
        "the attacker's hybrid key was PINNED by the restore — a stranger who floods a listing \
         must not end up in the kit's pin store: {pins_after}"
    );
    for i in 0..PLANTED_WITH_CONTENT {
        let planted = sheet_dir.join(format!("aaa-spam-{i:05}.sigil"));
        assert!(
            !planted.exists(),
            "a stranger's vault was WRITTEN TO DISK as a recovered vault: {}",
            planted.display()
        );
    }
    say(&format!(
        "{SPAM_VAULTS} GENUINE authenticated envelopes from another account were ignored \
         (ignored_untrusted={}, {} skipped lines, no stranger pinned, nothing written)",
        report.ignored_untrusted,
        report.skipped.len()
    ));

    // -------------------------------------------------------------------
    // 7. THE SAME TWO OUTCOMES THROUGH THE REAL BINARY — what a human runs.
    // -------------------------------------------------------------------
    let cli_blind_home = h.tmp.join("cli-blind");
    std::fs::create_dir_all(&cli_blind_home).expect("home");
    let out = sigil_restore(&h, &cli_blind_home, &code, &["--device-id", &kit_id]);
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !out.status.success(),
        "the real binary must FAIL rather than report a partial: {combined}"
    );
    assert!(
        combined.contains("NOTHING WAS RESTORED") && combined.contains("--vault"),
        "the binary's refusal must be actionable: {combined}"
    );

    let cli_sheet_home = h.tmp.join("cli-sheet");
    std::fs::create_dir_all(&cli_sheet_home).expect("home");
    let out = sigil_restore(
        &h,
        &cli_sheet_home,
        &code,
        &["--device-id", &kit_id, "--vault", REAL_VAULT],
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        out.status.success(),
        "the real binary must RECOVER when given the sheet's vault ids: {combined}"
    );
    assert!(
        combined.contains(REAL_VAULT),
        "the binary must name what it recovered: {combined}"
    );
    assert!(
        combined.contains("NOT PROVABLY EVERYTHING"),
        "the binary must NOT present a truncated restore as complete: {combined}"
    );
    let restored_file = cli_sheet_home.join(".sigil").join("zz-real-vault.sigil");
    assert!(
        restored_file.exists(),
        "the real binary must have written the vault to {}",
        restored_file.display()
    );
    say("the REAL sigil binary: refuses blind, recovers by sheet, and says so honestly");
}

/// ⛔ THE SHEET PATH MUST NOT BE GATED BEHIND THE ROUTE IT EXISTS TO BYPASS —
/// and one hostile row must not erase the report of the work already done.
///
/// Two independent failures, both against a REAL sigild with exactly one route
/// broken by a proxy in front of it:
///
/// 1. **C1 — the sheet path was gated behind the index.** `recovery_restore`
///    called `list_recoverable_vaults` unconditionally and propagated its error,
///    so a server that merely FAILS that one endpoint killed the sheet path too
///    — the path whose entire purpose is not needing that endpoint. The phase
///    called it "the discovery path that cannot be denied" in three places while
///    a single `500` denied it.
/// 2. **C3 — one bad row aborted everything.** Sheet vaults are processed first,
///    so a later row's `pull_ops_auth` failure returned `Err` after real vaults
///    were already on disk. The user was told the recovery FAILED while their
///    vaults sat in the state dir, and the recovered list, `from_sheet` and
///    `index_truncated` were never printed at all.
#[test]
fn a_restore_survives_a_broken_index_and_a_hostile_row() {
    let h = Harness::start();
    let victim = enroll(&h, TOKEN_VICTIM, "victim-laptop", "victim");

    // Two vaults, BOTH legitimately covered by the kit and both on the sheet.
    const VAULT_A: &str = "aa-first-vault";
    const VAULT_B: &str = "bb-second-vault";
    create_and_push_vault(&h, &victim, VAULT_A);
    create_and_push_vault(&h, &victim, VAULT_B);
    let kit = recovery_generate(
        &h.server,
        &victim.auth(),
        &[VAULT_A.to_string(), VAULT_B.to_string()],
        &victim.keyring(),
        &victim.pins(),
        None,
        &victim.sender(),
    )
    .expect("generate the recovery kit");
    let kit_id = kit.public.device_id.clone();
    let code = kit.code.clone();
    say(&format!("kit {kit_id} covers {:?}", kit.public.covered));

    // -------------------------------------------------------------------
    // 1. ⛔ C1 — the ONE route the sheet path exists to bypass is dead.
    // -------------------------------------------------------------------
    let index_down = FailProxy::start(
        &h.server,
        vec![("GET".to_string(), format!("/v1/devices/{kit_id}/keys"))],
    );
    // The route really is dead through this proxy — assert that, so a proxy that
    // silently forwarded would make the rest of this arm meaningless.
    let kit_seed = sigil_cli::recovery_verify(&code).expect("decode the printed code");
    let kit_identity = sigil_cli::derive_recovery_identity(&kit_seed);
    let kit_auth = RequestAuth::V3 {
        device_id: &kit_id,
        seed: &kit_identity.ed25519_seed,
    };
    let probe = list_recoverable_vaults(&index_down.url, &kit_id, &kit_auth);
    assert!(
        probe.is_err(),
        "the proxy must actually break the index route, else this arm proves nothing: {probe:?}"
    );

    let dir_a = h.tmp.join("restore-index-down");
    let report = recovery_restore(
        &code,
        &index_down.url,
        &kit_id,
        &dir_a,
        false,
        &[VAULT_A.to_string(), VAULT_B.to_string()],
    )
    .expect(
        "naming the sheet's vaults MUST still recover them when the per-device index is dead — \
         that path exists precisely so it does not depend on that route",
    );
    let got: Vec<&str> = report
        .vaults
        .iter()
        .map(|(v, _, _, _)| v.as_str())
        .collect();
    assert!(
        got.contains(&VAULT_A) && got.contains(&VAULT_B),
        "both sheet vaults must come back with the index down: got={got:?} skipped={:?}",
        report.skipped
    );
    assert!(
        report.index_error.is_some(),
        "a degraded index must be REPORTED, never swallowed — the user has to be able to tell \
         'the index listed nothing' from 'the index never answered'"
    );
    assert!(
        report.index_truncated,
        "an index that never answered is the strongest possible statement that this client \
         cannot enumerate its coverage; it must not read as complete"
    );
    say("C1: the index route is dead and the SHEET path still recovers both vaults, loudly");

    // With NO sheet ids there is nothing to fall back to, so the error must
    // still propagate rather than silently producing an empty "success".
    let dir_blind = h.tmp.join("restore-index-down-blind");
    let err = recovery_restore(&code, &index_down.url, &kit_id, &dir_blind, false, &[])
        .expect_err("with no sheet ids a dead index has no fallback and MUST propagate");
    say(&format!(
        "C1: with no sheet ids the same failure still propagates ({err})"
    ));
    drop(index_down);

    // -------------------------------------------------------------------
    // 2. ⛔ C3 — a later row explodes; the earlier work must still be reported.
    // -------------------------------------------------------------------
    let ops_down = FailProxy::start(
        &h.server,
        vec![("GET".to_string(), format!("/v1/vaults/{VAULT_B}/ops"))],
    );
    let dir_b = h.tmp.join("restore-hostile-row");
    let report = recovery_restore(
        &code,
        &ops_down.url,
        &kit_id,
        &dir_b,
        false,
        &[VAULT_A.to_string(), VAULT_B.to_string()],
    )
    .expect(
        "one unreadable vault must be a PER-VAULT failure — returning Err here throws away the \
         report of every vault already written to disk",
    );
    let got: Vec<&str> = report
        .vaults
        .iter()
        .map(|(v, _, _, _)| v.as_str())
        .collect();
    assert_eq!(
        got,
        vec![VAULT_A],
        "the healthy vault must still be reported as recovered: got={got:?}"
    );
    assert!(
        report.skipped.iter().any(|(v, _)| v == VAULT_B),
        "the broken vault must be named in `skipped` with its reason: {:?}",
        report.skipped
    );
    assert!(
        dir_b.join("aa-first-vault.sigil").exists(),
        "the healthy vault must be on disk — it was written before the failure, and the whole \
         point is that the report now says so"
    );
    say("C3: one unreadable vault is skipped by name; the healthy vault is recovered and reported");
}

/// ⛔ TWO VAULT IDS THAT SANITIZE TO ONE FILE NAME MUST NOT OVERWRITE EACH OTHER.
///
/// Found by an adversarial verifier AFTER the rest of this phase was written, and
/// reachable with **NO ATTACKER AT ALL** — two of a user's own vault ids are
/// enough. `check_vault` permits every character except `/` and whitespace, while
/// `sanitize_file_stem` folds everything outside `[A-Za-z0-9_-]` to `_`, so
/// `team.vault` and `team_vault` both resolved to `team_vault.sigil`. The second
/// write silently replaced the first, **both** appeared in `report.vaults`, and —
/// because the keyring is keyed by the exact vault id — the losing vault became a
/// container on disk that does **not open** with the key filed beside it.
///
/// ⭐ That is the SAME invariant `recovery_restore` already enforces for a failed
/// keyring write ("a container on disk that cannot be opened, reported as
/// recovered"), closed for one instance and missed for the other. This drives the
/// REAL `recovery_restore` against a REAL sigild rather than re-checking the
/// naming rule in isolation, because a rule verified only in a unit test is the
/// "guarded in the library, unguarded in the product" trap this repo keeps
/// shipping (docs/engineering-lessons.md #10).
#[test]
fn colliding_vault_ids_do_not_overwrite_each_others_restored_files() {
    let h = Harness::start();
    let me = enroll(&h, TOKEN_COLLIDE, "collide-laptop", "collide");

    // Both are legal vault ids and both sanitize to `team_vault`.
    const DOTTED: &str = "team.vault";
    const UNDERSCORED: &str = "team_vault";
    let key_dotted = create_and_push_vault(&h, &me, DOTTED);
    let key_underscored = create_and_push_vault(&h, &me, UNDERSCORED);
    assert_ne!(key_dotted, key_underscored, "two vaults, two keys");

    let kit = recovery_generate(
        &h.server,
        &me.auth(),
        &[DOTTED.to_string(), UNDERSCORED.to_string()],
        &me.keyring(),
        &me.pins(),
        None,
        &me.sender(),
    )
    .expect("generate a kit covering both");
    let kit_id = kit.public.device_id.clone();

    let out = h.tmp.join("collide-restore");
    let report = recovery_restore(
        &kit.code,
        &h.server,
        &kit_id,
        &out,
        false,
        &[DOTTED.to_string(), UNDERSCORED.to_string()],
    )
    .expect("restore both");

    assert_eq!(
        report.vaults.len(),
        2,
        "both vaults must be recovered: {report:?}"
    );
    let path_of = |vault_id: &str| -> std::path::PathBuf {
        report
            .vaults
            .iter()
            .find(|(v, _, _, _)| v == vault_id)
            .map(|(_, p, _, _)| p.clone())
            .unwrap_or_else(|| panic!("{vault_id} missing from {report:?}"))
    };
    let p_dotted = path_of(DOTTED);
    let p_underscored = path_of(UNDERSCORED);
    assert_ne!(
        p_dotted,
        p_underscored,
        "⛔ both vaults were reported recovered at ONE path — the second overwrote \
         the first and the report is a lie: {} vs {}",
        p_dotted.display(),
        p_underscored.display()
    );
    assert!(p_dotted.exists() && p_underscored.exists(), "{report:?}");

    // ⭐ THE REAL ASSERTION: each reported file must open with the key filed for
    // ITS OWN vault. This is what the overwrite broke — the report said
    // "recovered" about a container that would not decrypt.
    for (vault_id, path, key) in [
        (DOTTED, &p_dotted, &key_dotted),
        (UNDERSCORED, &p_underscored, &key_underscored),
    ] {
        let blob = std::fs::read(path).expect("restored container");
        let vault = sigil_cli::open_vault(key, &blob).unwrap_or_else(|e| {
            panic!(
                "the file reported as {vault_id} ({}) does NOT open with {vault_id}'s own key: {e}",
                path.display()
            )
        });
        assert_eq!(vault.entries.len(), 1, "{vault_id} lost its entry");
    }

    // The unambiguous name is still the unsurprising one — nothing that restores
    // today changes file name because of this fix.
    assert!(
        p_dotted.ends_with("team_vault.sigil") || p_underscored.ends_with("team_vault.sigil"),
        "one of the two should keep the plain name: {} / {}",
        p_dotted.display(),
        p_underscored.display()
    );
    say("two colliding vault ids restored to two distinct files, each opening with its own key");
}
