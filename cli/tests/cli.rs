//! Integration test: drive the ACTUAL `sigil` binary end to end.
//!
//! STATUS: pre-audit. Exercises the real (unaudited) seal/open round-trip via
//! the compiled binary. Uses RECOMMENDED Argon2id params (real work factor), so
//! it is kept to a single round-trip plus one negative case to stay fast.

use std::path::PathBuf;
use std::process::Command;

/// A unique temp directory for one test run, removed on drop.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let mut path = std::env::temp_dir();
        // Uniqueness: tag + pid + a nanosecond timestamp.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        path.push(format!("sigil-cli-it-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
}

#[test]
fn seal_then_open_round_trips_via_binary() {
    let dir = TempDir::new("rt");
    let plain = dir.join("secret.txt");
    let sealed = dir.join("secret.sigil");
    let recovered = dir.join("recovered.txt");

    let original = b"end-to-end through the real binary";
    std::fs::write(&plain, original).expect("write plaintext");

    let password = "correct horse battery staple";

    // seal
    let status = bin()
        .args(["seal", "--in"])
        .arg(&plain)
        .arg("--out")
        .arg(&sealed)
        .env("SIGIL_PASSWORD", password)
        .status()
        .expect("run seal");
    assert!(status.success(), "seal should exit 0");

    // the container must not be the plaintext in the clear
    let container = std::fs::read(&sealed).expect("read container");
    assert!(!container
        .windows(original.len())
        .any(|w| w == original.as_slice()));

    // open
    let status = bin()
        .args(["open", "--in"])
        .arg(&sealed)
        .arg("--out")
        .arg(&recovered)
        .env("SIGIL_PASSWORD", password)
        .status()
        .expect("run open");
    assert!(status.success(), "open should exit 0");

    let round_tripped = std::fs::read(&recovered).expect("read recovered");
    assert_eq!(round_tripped, original);
}

#[test]
fn wrong_password_open_exits_nonzero() {
    let dir = TempDir::new("wp");
    let plain = dir.join("secret.txt");
    let sealed = dir.join("secret.sigil");
    let recovered = dir.join("recovered.txt");

    std::fs::write(&plain, b"top secret").expect("write plaintext");

    // seal with the right password
    let status = bin()
        .args(["seal", "--in"])
        .arg(&plain)
        .arg("--out")
        .arg(&sealed)
        .env("SIGIL_PASSWORD", "the right password")
        .status()
        .expect("run seal");
    assert!(status.success(), "seal should exit 0");

    // open with the WRONG password must fail (non-zero exit)
    let status = bin()
        .args(["open", "--in"])
        .arg(&sealed)
        .arg("--out")
        .arg(&recovered)
        .env("SIGIL_PASSWORD", "the WRONG password")
        .status()
        .expect("run open");
    assert!(
        !status.success(),
        "open with wrong password must exit non-zero"
    );
    // And it must not have written a recovered plaintext file.
    assert!(
        !recovered.exists(),
        "no plaintext should be written on failure"
    );
}

#[test]
fn hybrid_keygen_seal_open_round_trips_via_binary() {
    let dir = TempDir::new("hyb");
    let key = dir.join("b.key");
    let pubkey = dir.join("b.key.pub"); // hybrid-keygen derives this from --out
    let plain = dir.join("secret.txt");
    let sealed = dir.join("msg.hyb");
    let recovered = dir.join("recovered.txt");

    let original = b"public-key hybrid encryption through the real binary";
    std::fs::write(&plain, original).expect("write plaintext");

    // Device B: generate a hybrid identity; b.key.pub is shareable.
    let status = bin()
        .args(["hybrid-keygen", "--out"])
        .arg(&key)
        .status()
        .expect("run hybrid-keygen");
    assert!(status.success(), "hybrid-keygen should exit 0");
    assert!(
        pubkey.exists(),
        "hybrid-keygen must write the shareable .pub identity"
    );

    // Device A: encrypt TO B's public identity (no password).
    let status = bin()
        .args(["hybrid-seal", "--recipient-pub"])
        .arg(&pubkey)
        .arg("--in")
        .arg(&plain)
        .arg("--out")
        .arg(&sealed)
        .status()
        .expect("run hybrid-seal");
    assert!(status.success(), "hybrid-seal should exit 0");

    // The container must not carry the plaintext in the clear.
    let container = std::fs::read(&sealed).expect("read container");
    assert!(!container
        .windows(original.len())
        .any(|w| w == original.as_slice()));

    // Device B: decrypt with its secret identity.
    let status = bin()
        .args(["hybrid-open", "--key"])
        .arg(&key)
        .arg("--in")
        .arg(&sealed)
        .arg("--out")
        .arg(&recovered)
        .status()
        .expect("run hybrid-open");
    assert!(status.success(), "hybrid-open should exit 0");

    let round_tripped = std::fs::read(&recovered).expect("read recovered");
    assert_eq!(round_tripped, original);
}

/// ⭐⭐ THE ORIGINAL REPRODUCTION, DRIVEN THROUGH THE REAL BINARY, asserting it
/// no longer produces a usable vault-key envelope.
///
/// The forgery was, verbatim:
///
/// ```text
///   sigil hybrid-keygen --out b.hybrid            # victim; only b.hybrid.pub is published
///   head -c 32 /dev/urandom > attacker_key.bin
///   sigil hybrid-seal --recipient-pub b.hybrid.pub --in attacker_key.bin --out forged.env
///   sigil hybrid-open --key b.hybrid --in forged.env      # 32 bytes, the attacker's key
/// ```
///
/// Every step still RUNS — `hybrid-seal`/`hybrid-open` are honest anonymous file
/// encryption to a public key and were never the bug. What has changed is that
/// the bytes they produce are no longer a vault-key envelope: they carry
/// container version 1 (anonymous), a vault-key envelope is version 2
/// (AUTHENTICATED), and `unwrap_vault_key` — the one function every client's
/// accept path goes through — refuses version 1 outright.
#[test]
fn the_forged_vault_key_envelope_is_no_longer_accepted() {
    use sigil_cli::{
        load_hybrid_secret, unwrap_vault_key, CliError, SenderIdentity, VaultKeyWrapContext,
        VerifiedSender, HYBRID_AUTH_FORMAT_VERSION,
    };

    let dir = TempDir::new("forge");
    let victim = dir.join("b.hybrid");
    let victim_pub = dir.join("b.hybrid.pub");
    let attacker_key = dir.join("attacker_key.bin");
    let forged = dir.join("forged.env");

    // The victim's identity. ONLY b.hybrid.pub is ever published.
    assert!(bin()
        .args(["hybrid-keygen", "--out"])
        .arg(&victim)
        .status()
        .expect("run hybrid-keygen")
        .success());

    // 32 attacker-chosen bytes, exactly the shape of a vault key.
    let attacker_chosen = [0x5au8; 32];
    std::fs::write(&attacker_key, attacker_chosen).expect("write attacker key");

    // The forgery, minted from the victim's PUBLIC key and nothing else.
    assert!(bin()
        .args(["hybrid-seal", "--recipient-pub"])
        .arg(&victim_pub)
        .arg("--in")
        .arg(&attacker_key)
        .arg("--out")
        .arg(&forged)
        .status()
        .expect("run hybrid-seal")
        .success());

    let bytes = std::fs::read(&forged).expect("read forged envelope");
    assert_eq!(&bytes[..8], b"SIGILhyb", "still the same magic");
    assert_eq!(
        bytes[8], 1,
        "the anonymous FILE path writes container version 1"
    );
    assert_ne!(
        bytes[8], HYBRID_AUTH_FORMAT_VERSION,
        "and version 1 is NOT the authenticated vault-key version"
    );

    // ⛔ THE ASSERTION THAT MATTERS: presented as a vault-key envelope, it is
    // refused. Before Phase 60 this returned Ok(attacker_chosen).
    let secret = load_hybrid_secret(&victim).expect("load victim secret");
    let (sender_secret, _) = sigil_cli::generate_hybrid_identity().expect("peer identity");
    let peer = SenderIdentity::new("dev_peer", sender_secret).expect("sender");
    let verified = VerifiedSender::from_local(&peer).expect("verified");
    let ctx = VaultKeyWrapContext::new("demo", "dev_victim", "dev_peer").expect("ctx");

    let result = unwrap_vault_key(&secret, &verified, &ctx, &bytes);
    assert_eq!(
        result,
        Err(CliError::WrongEnvelopeKind {
            found_version: 1,
            expected_version: 2,
        }),
        "the forged envelope must be REFUSED, not opened"
    );
    assert!(
        !format!("{:?}", result).contains("5a5a5a"),
        "no plaintext may leak into the error"
    );
}
