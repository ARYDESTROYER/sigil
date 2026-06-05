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
