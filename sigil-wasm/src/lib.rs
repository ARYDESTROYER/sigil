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

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }
}
