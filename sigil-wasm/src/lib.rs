//! `sigil-wasm` — a thin `wasm-bindgen` binding over the libsigil `sigil-core`
//! record API, exposing `seal_record` / `open_record` to JavaScript.
//!
//! STATUS: **pre-audit / UNAUDITED**. This crate is a *thin binding* — it adds
//! **no** cryptography of its own. All crypto lives in the `#![forbid(unsafe_code)]`
//! `sigil-core` crate (Argon2id -> XChaCha20-Poly1305 + HKDF envelope). This is a
//! DEMONSTRATION of that wasm-pure building block in a JavaScript runtime and MUST
//! NOT be used to protect real secrets. It is NOT the product's
//! account/key-management model.
//!
//! ## The invariant this crate proves
//!
//! `sigil-core` is `no_std`, wasm-pure, and has **no in-core RNG** — every piece
//! of entropy is *caller-supplied*. This binding carries that contract all the
//! way out to the browser: the Argon2id **salt** and the AEAD **nonce** are
//! generated in JavaScript (`crypto.getRandomValues`) and passed IN as byte
//! arrays. This crate therefore stays `getrandom`-free too (no `getrandom`
//! dependency; the lockfile check must report 0).
//!
//! ## Why no `#![forbid(unsafe_code)]`
//!
//! The `#[wasm_bindgen]` proc-macro generates `extern "C"` shims and raw-pointer
//! glue containing `unsafe`, so this crate cannot `forbid(unsafe_code)`. That is
//! expected for a wasm binding; the security-relevant code (all of `sigil-core`)
//! remains `#![forbid(unsafe_code)]`. This crate only marshals bytes.
//!
//! ## Structure
//!
//! The crypto-marshalling logic lives in the `*_inner` helpers, which return
//! `Result<Vec<u8>, String>` and are exercised by the native `#[cfg(test)]`
//! unit tests. The `#[wasm_bindgen]` entry points are a paper-thin shell that
//! only converts the `String` error into a JS `Error` (`JsError`) — and
//! `JsError` intentionally cannot be constructed on non-wasm targets, which is
//! exactly why the testable logic is kept out of it.

use sigil_core::{
    open_record as core_open_record, seal_record as core_seal_record, Argon2Params, NONCE_LEN,
};
use wasm_bindgen::prelude::*;

/// The recommended Argon2id salt length, in bytes. The core accepts any salt
/// within Argon2's length bounds; 16 matches the reference CLI.
const RECOMMENDED_SALT_LEN: usize = 16;

// --- CLI-compatible `SIGILcli` container format ----------------------------
//
// These constants MUST match `cli/src/lib.rs` byte-for-byte, or a container
// sealed here will not open with `sigil open` (and vice versa). From that file:
//   pub const MAGIC: &[u8; 8]     = b"SIGILcli";
//   pub const FORMAT_VERSION: u8  = 1;
//   pub const AAD: &[u8]          = b"sigil-cli/1";
// The on-disk layout (all integers LITTLE-ENDIAN) is:
//   magic[8] | version:u8 | m_cost:u32 | t_cost:u32 | p_cost:u32 |
//   salt_len:u8 | salt[salt_len] | envelope[..]

/// The 8-byte magic that prefixes every `SIGILcli` container. MUST equal
/// `cli/src/lib.rs::MAGIC` (`b"SIGILcli"`).
const CLI_MAGIC: &[u8; 8] = b"SIGILcli";

/// The `SIGILcli` container format version this binding writes and reads. MUST
/// equal `cli/src/lib.rs::FORMAT_VERSION` (`1`).
const CLI_FORMAT_VERSION: u8 = 1;

/// The fixed AEAD additional-authenticated-data tag the CLI binds into every
/// sealed record. The wasm MUST seal with this SAME AAD or `sigil open` fails to
/// authenticate. MUST equal `cli/src/lib.rs::AAD` (`b"sigil-cli/1"`).
const CLI_AAD: &[u8] = b"sigil-cli/1";

/// Byte length of the fixed part of the `SIGILcli` header (everything up to and
/// including `salt_len`): magic(8)+version(1)+m_cost(4)+t_cost(4)+p_cost(4)+
/// salt_len(1) = 22. Mirrors `cli/src/lib.rs::FIXED_HEADER_LEN`.
const CLI_FIXED_HEADER_LEN: usize = 22;

/// The XChaCha20-Poly1305 nonce length, in bytes (24). JavaScript should
/// generate exactly this many random bytes for the `nonce` argument to
/// [`seal_record`].
#[wasm_bindgen]
pub fn nonce_len() -> usize {
    NONCE_LEN
}

/// The recommended Argon2id salt length, in bytes (16). JavaScript should
/// generate exactly this many random bytes for the `salt` argument.
#[wasm_bindgen]
pub fn recommended_salt_len() -> usize {
    RECOMMENDED_SALT_LEN
}

/// A human-readable build/version string for this binding.
#[wasm_bindgen]
pub fn version() -> String {
    format!(
        "sigil-wasm {} (sigil-core record API; pre-audit / UNAUDITED)",
        env!("CARGO_PKG_VERSION")
    )
}

/// Seal one record: stretch `password` with Argon2id over the caller-supplied
/// `salt`, then seal `plaintext` under the caller-supplied `nonce` and `aad`
/// with XChaCha20-Poly1305, returning the encoded envelope bytes (JS sees a
/// `Uint8Array`).
///
/// The AEAD nonce is stored *inside* the returned envelope; the caller MUST
/// persist `salt` and the three Argon2 cost parameters separately to be able to
/// [`open_record`] later — they are NOT in the returned bytes.
///
/// `nonce` MUST be exactly [`nonce_len`] (24) bytes and `salt` SHOULD be
/// [`recommended_salt_len`] (16) bytes of fresh CSPRNG output from
/// `crypto.getRandomValues`. **Never reuse a `(password+salt, nonce)` pair.**
///
/// Errors surface to JS as a thrown `Error` with a descriptive message (a bad
/// nonce length, or an Argon2id/AEAD/envelope failure from the core).
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn seal_record(
    password: &[u8],
    salt: &[u8],
    nonce: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    seal_record_inner(
        password, salt, nonce, m_cost, t_cost, p_cost, aad, plaintext,
    )
    .map_err(|e| JsError::new(&e))
}

/// Open one record: decode `envelope`, re-derive the master key from `password`
/// and `salt` with the same Argon2 parameters used at seal time, then
/// authenticate and decrypt, returning the recovered plaintext (JS sees a
/// `Uint8Array`).
///
/// `salt`, `m_cost`, `t_cost`, and `p_cost` MUST match the values used at seal
/// time (they are not carried in the envelope). The `aad` is authenticated from
/// inside the envelope and is therefore not a parameter here.
///
/// A wrong password, wrong salt/params, or tampered ciphertext surfaces to JS as
/// a thrown `Error`; the plaintext is never returned in that case.
#[wasm_bindgen]
pub fn open_record(
    password: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    envelope: &[u8],
) -> Result<Vec<u8>, JsError> {
    open_record_inner(password, salt, m_cost, t_cost, p_cost, envelope)
        .map_err(|e| JsError::new(&e))
}

/// Seal `plaintext` into a **CLI-compatible `SIGILcli` container** that
/// `sigil open` can decrypt (and, conversely, that this binding's
/// [`open_container`] can decrypt when produced by `sigil seal`).
///
/// This is the interop path. It stretches `password` with Argon2id over the
/// caller-supplied `salt`, seals under the caller-supplied `nonce` with the
/// fixed CLI AAD (`b"sigil-cli/1"`), and packs the self-describing header —
/// `magic ‖ version=1 ‖ m_cost/t_cost/p_cost (u32 LE) ‖ salt_len(u8) ‖ salt` —
/// in front of the envelope, exactly mirroring `cli/src/lib.rs`.
///
/// Unlike the CLI (which draws its own OS entropy), the salt and nonce are
/// caller-supplied here — generate them in JS with `crypto.getRandomValues`.
/// `nonce` MUST be exactly [`nonce_len`] (24) bytes and `salt` MUST be at most
/// 255 bytes (it is length-prefixed with a single `u8`); use
/// [`recommended_salt_len`] (16) bytes to match the CLI.
///
/// Errors (a bad nonce length, an oversized salt, or an Argon2id/AEAD/envelope
/// failure) surface to JS as a thrown `Error`.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn seal_to_container(
    password: &[u8],
    salt: &[u8],
    nonce: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    seal_to_container_inner(password, salt, nonce, m_cost, t_cost, p_cost, plaintext)
        .map_err(|e| JsError::new(&e))
}

/// Open a **CLI-compatible `SIGILcli` container** (one produced by `sigil seal`
/// or by [`seal_to_container`]), returning the recovered plaintext.
///
/// The Argon2 params and salt are read from the self-describing header (so,
/// unlike [`open_record`], they are NOT parameters), the envelope tail is sliced
/// out, and the master key is re-derived from `password` to authenticate and
/// decrypt. A bad magic, an unsupported version, a header whose declared salt
/// overruns the buffer, a wrong password, or tampered ciphertext all surface to
/// JS as a thrown `Error`; the plaintext is never returned in that case.
#[wasm_bindgen]
pub fn open_container(password: &[u8], container: &[u8]) -> Result<Vec<u8>, JsError> {
    open_container_inner(password, container).map_err(|e| JsError::new(&e))
}

// --- Testable core-marshalling logic (no `JsError`, so it runs natively) ----

#[allow(clippy::too_many_arguments)]
fn seal_record_inner(
    password: &[u8],
    salt: &[u8],
    nonce: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().map_err(|_| {
        format!(
            "nonce must be exactly {} bytes, got {}",
            NONCE_LEN,
            nonce.len()
        )
    })?;
    let params = Argon2Params {
        m_cost,
        t_cost,
        p_cost,
    };
    core_seal_record(password, salt, params, nonce, aad, plaintext)
        .map_err(|e| format!("seal_record failed: {e:?}"))
}

fn open_record_inner(
    password: &[u8],
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    envelope: &[u8],
) -> Result<Vec<u8>, String> {
    let params = Argon2Params {
        m_cost,
        t_cost,
        p_cost,
    };
    core_open_record(password, salt, params, envelope)
        .map_err(|e| format!("open_record failed: {e:?}"))
}

#[allow(clippy::too_many_arguments)]
fn seal_to_container_inner(
    password: &[u8],
    salt: &[u8],
    nonce: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    // `salt_len` is written as a single u8, so the salt must fit in 0..=255.
    if salt.len() > u8::MAX as usize {
        return Err(format!(
            "salt must be at most {} bytes for the SIGILcli header, got {}",
            u8::MAX,
            salt.len()
        ));
    }

    // Seal under the CLI's fixed AAD so `sigil open` authenticates it. This also
    // validates the nonce length (must be NONCE_LEN).
    let envelope = seal_record_inner(
        password, salt, nonce, m_cost, t_cost, p_cost, CLI_AAD, plaintext,
    )?;

    let mut out = Vec::with_capacity(CLI_FIXED_HEADER_LEN + salt.len() + envelope.len());
    out.extend_from_slice(CLI_MAGIC);
    out.push(CLI_FORMAT_VERSION);
    out.extend_from_slice(&m_cost.to_le_bytes());
    out.extend_from_slice(&t_cost.to_le_bytes());
    out.extend_from_slice(&p_cost.to_le_bytes());
    out.push(salt.len() as u8);
    out.extend_from_slice(salt);
    out.extend_from_slice(&envelope);
    Ok(out)
}

fn open_container_inner(password: &[u8], container: &[u8]) -> Result<Vec<u8>, String> {
    if container.len() < CLI_FIXED_HEADER_LEN {
        return Err("container is too short to hold the SIGILcli header".to_string());
    }

    let (magic, rest) = container.split_at(8);
    if magic != CLI_MAGIC.as_slice() {
        return Err("not a SIGILcli container (bad magic: expected \"SIGILcli\")".to_string());
    }

    let version = rest[0];
    if version != CLI_FORMAT_VERSION {
        return Err(format!(
            "unsupported SIGILcli container version {version}: expected {CLI_FORMAT_VERSION}"
        ));
    }

    // Fixed-width fields after the version byte: m_cost, t_cost, p_cost, salt_len.
    let m_cost = u32::from_le_bytes([rest[1], rest[2], rest[3], rest[4]]);
    let t_cost = u32::from_le_bytes([rest[5], rest[6], rest[7], rest[8]]);
    let p_cost = u32::from_le_bytes([rest[9], rest[10], rest[11], rest[12]]);
    let salt_len = rest[13] as usize;

    // `rest` starts at the version byte; the salt begins after the 14 fixed
    // bytes (version + 3 u32s + salt_len) consumed above.
    let after_fixed = &rest[14..];
    if after_fixed.len() < salt_len {
        return Err("malformed SIGILcli header (declared salt overruns the container)".to_string());
    }
    let (salt, envelope) = after_fixed.split_at(salt_len);

    open_record_inner(password, salt, m_cost, t_cost, p_cost, envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fast Argon2 params so the native tests are near-instant while still
    // exercising the real Argon2id path. (Argon2 requires m_cost >= 8 * p_cost.)
    const M: u32 = 8;
    const T: u32 = 1;
    const P: u32 = 1;
    const SALT: &[u8] = b"wasm-salt-000001"; // 16 bytes
    const PASSWORD: &[u8] = b"correct horse battery staple";
    const AAD: &[u8] = b"sigil-wasm-test";
    const PLAINTEXT: &[u8] = b"a very secret note (not really)";

    fn nonce() -> Vec<u8> {
        vec![0x5a; NONCE_LEN]
    }

    #[test]
    fn round_trip_seal_open() {
        let env = seal_record_inner(PASSWORD, SALT, &nonce(), M, T, P, AAD, PLAINTEXT).unwrap();
        // Sealed bytes must not leak the plaintext.
        assert!(!contains(&env, PLAINTEXT));
        let out = open_record_inner(PASSWORD, SALT, M, T, P, &env).unwrap();
        assert_eq!(out, PLAINTEXT);
    }

    #[test]
    fn wrong_password_fails() {
        let env = seal_record_inner(PASSWORD, SALT, &nonce(), M, T, P, AAD, PLAINTEXT).unwrap();
        assert!(open_record_inner(b"wrong password", SALT, M, T, P, &env).is_err());
    }

    #[test]
    fn wrong_nonce_len_rejected() {
        let short = vec![0u8; NONCE_LEN - 1];
        assert!(seal_record_inner(PASSWORD, SALT, &short, M, T, P, AAD, PLAINTEXT).is_err());
    }

    #[test]
    fn constants_are_faithful() {
        assert_eq!(nonce_len(), NONCE_LEN);
        assert_eq!(recommended_salt_len(), 16);
    }

    // --- CLI-compatible SIGILcli container interop ------------------------

    #[test]
    fn container_round_trip() {
        let c = seal_to_container_inner(PASSWORD, SALT, &nonce(), M, T, P, PLAINTEXT).unwrap();
        // The container must not leak the plaintext.
        assert!(!contains(&c, PLAINTEXT));
        let out = open_container_inner(PASSWORD, &c).unwrap();
        assert_eq!(out, PLAINTEXT);
    }

    #[test]
    fn container_wrong_password_fails() {
        let c = seal_to_container_inner(PASSWORD, SALT, &nonce(), M, T, P, PLAINTEXT).unwrap();
        assert!(open_container_inner(b"wrong password", &c).is_err());
    }

    #[test]
    fn container_bad_magic_rejected() {
        let mut c = seal_to_container_inner(PASSWORD, SALT, &nonce(), M, T, P, PLAINTEXT).unwrap();
        c[0] ^= 0xff; // corrupt the first magic byte
        assert!(open_container_inner(PASSWORD, &c).is_err());
    }

    #[test]
    fn container_truncated_header_rejected() {
        // Anything shorter than the fixed header must be rejected, not panic.
        let short = vec![0u8; CLI_FIXED_HEADER_LEN - 1];
        assert!(open_container_inner(PASSWORD, &short).is_err());
    }

    #[test]
    fn container_declared_salt_overrun_rejected() {
        let mut c = seal_to_container_inner(PASSWORD, SALT, &nonce(), M, T, P, PLAINTEXT).unwrap();
        // Force salt_len (byte index 21) far past the buffer.
        c[21] = 0xff;
        assert!(open_container_inner(PASSWORD, &c).is_err());
    }

    #[test]
    fn container_header_is_golden() {
        // A byte-exact cross-check of the header against a hand-built expected
        // header. Any drift from the CLI's layout (cli/src/lib.rs) fails here.
        let c = seal_to_container_inner(PASSWORD, SALT, &nonce(), M, T, P, PLAINTEXT).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(b"SIGILcli"); // magic
        expected.push(1); // version
        expected.extend_from_slice(&8u32.to_le_bytes()); // m_cost = M
        expected.extend_from_slice(&1u32.to_le_bytes()); // t_cost = T
        expected.extend_from_slice(&1u32.to_le_bytes()); // p_cost = P
        expected.push(16); // salt_len = SALT.len()
        expected.extend_from_slice(SALT); // salt

        let header_len = CLI_FIXED_HEADER_LEN + SALT.len(); // 22 + 16 = 38
        assert_eq!(expected.len(), header_len);
        assert_eq!(&c[..header_len], expected.as_slice());
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
