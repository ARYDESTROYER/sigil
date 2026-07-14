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
    format_code as core_format_code, hotp as core_hotp, hybrid_open as core_hybrid_open,
    hybrid_seal as core_hybrid_seal, ml_kem768_keygen as core_ml_kem768_keygen,
    open_record as core_open_record, seal_record as core_seal_record, totp as core_totp,
    x25519_public_key as core_x25519_public_key, Argon2Params, OtpAlgorithm,
    ML_KEM768_CIPHERTEXT_LEN, ML_KEM768_ENCAPS_COIN_LEN, ML_KEM768_ENCAPS_KEY_LEN,
    ML_KEM768_KEYGEN_SEED_LEN, NONCE_LEN, X25519_PUBLIC_KEY_LEN, X25519_SECRET_KEY_LEN,
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

// --- CLI-compatible `SIGILhyb` hybrid public-key container -------------------
//
// The PUBLIC-KEY (no-password) path. These constants MUST match
// `cli/src/lib.rs` byte-for-byte, or a container sealed here will not open with
// `sigil hybrid-open` (and vice versa). From that file:
//   pub const HYBRID_MAGIC: &[u8; 8]      = b"SIGILhyb";
//   pub const HYBRID_FORMAT_VERSION: u8   = 1;
//   pub const HYBRID_AAD: &[u8]           = b"sigil-hybrid-cli/1";
// The on-disk layout is:
//   magic[8] | version:u8 | eph_x25519_pub[32] | mlkem_ct[1088] | envelope[..]
//
// The hybrid IDENTITY (a device's X25519 secret + ML-KEM keygen seed for the
// secret half, X25519 public key + ML-KEM encaps key for the public half) is a
// JSON file the CLI parses; this wasm crate never parses identity files — JS
// bridges the JSON and hands the raw key bytes to the functions below.

/// The 8-byte magic that prefixes every `SIGILhyb` container. MUST equal
/// `cli/src/lib.rs::HYBRID_MAGIC` (`b"SIGILhyb"`).
const HYBRID_MAGIC: &[u8; 8] = b"SIGILhyb";

/// The `SIGILhyb` container format version this binding writes and reads. MUST
/// equal `cli/src/lib.rs::HYBRID_FORMAT_VERSION` (`1`).
const HYBRID_FORMAT_VERSION: u8 = 1;

/// The fixed AEAD additional-authenticated-data tag the CLI binds into every
/// hybrid-sealed record. The wasm MUST seal with this SAME AAD or
/// `sigil hybrid-open` fails to authenticate. MUST equal
/// `cli/src/lib.rs::HYBRID_AAD` (`b"sigil-hybrid-cli/1"`).
const HYBRID_AAD: &[u8] = b"sigil-hybrid-cli/1";

/// Byte length of the fixed prefix of a `SIGILhyb` container: magic(8) +
/// version(1) + eph_x25519_pub(32) + mlkem_ct(1088) = 1129. The seal envelope
/// bytes follow this prefix. Mirrors `cli/src/lib.rs::HYBRID_FIXED_PREFIX_LEN`.
const HYBRID_FIXED_PREFIX_LEN: usize = 8 + 1 + X25519_PUBLIC_KEY_LEN + ML_KEM768_CIPHERTEXT_LEN;

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

// --- Hybrid PUBLIC-KEY (no-password) encryption: `SIGILhyb` interop ----------
//
// The public-key path, distinct from the password-based seal/open above. It
// composes `sigil-core`'s REAL but UNAUDITED hybrid primitives (X25519 +
// ML-KEM-768 -> shared secret -> XChaCha20-Poly1305). It is a CUSTOM
// KEM-then-AEAD composition, NOT RFC 9180 HPKE, and the SYSTEM is NOT
// "post-quantum secure". Do NOT protect real secrets. As everywhere in this
// crate, ALL entropy (the ephemeral X25519 secret, the ML-KEM coin, and the
// AEAD nonce) is CALLER-SUPPLIED from JavaScript — the module has no RNG.

/// Derive a 32-byte X25519 **public** key from a 32-byte X25519 **secret**.
///
/// JS holds the secret (generated with `crypto.getRandomValues`); this returns
/// the public key to publish in a recipient `.pub` identity (the CLI's
/// `x25519_public_key` field). `secret` MUST be exactly 32 bytes.
#[wasm_bindgen]
pub fn hybrid_x25519_public(secret: &[u8]) -> Result<Vec<u8>, JsError> {
    hybrid_x25519_public_inner(secret).map_err(|e| JsError::new(&e))
}

/// Derive the 1184-byte ML-KEM-768 **encapsulation key** from a 64-byte
/// ML-KEM-768 keygen **seed**.
///
/// JS holds the seed; this returns the encapsulation key to publish in a
/// recipient `.pub` identity (the CLI's `mlkem_encaps_key` field). The
/// decapsulation key is NOT returned — the recipient re-derives it from the
/// seed at open time (see [`hybrid_open_container`]). `seed` MUST be exactly 64
/// bytes.
#[wasm_bindgen]
pub fn hybrid_mlkem_encaps_key(seed: &[u8]) -> Result<Vec<u8>, JsError> {
    hybrid_mlkem_encaps_key_inner(seed).map_err(|e| JsError::new(&e))
}

/// Seal `plaintext` TO a recipient's hybrid public identity, producing a
/// **CLI-compatible `SIGILhyb` container** that `sigil hybrid-open` can decrypt
/// (and, conversely, that this binding's [`hybrid_open_container`] can decrypt
/// when produced by `sigil hybrid-seal`).
///
/// Encapsulates a fresh hybrid shared secret to `(recipient_x25519_pub,
/// recipient_mlkem_encaps_key)`, seals under the fixed hybrid AAD
/// (`b"sigil-hybrid-cli/1"`), and packs the self-describing prefix — `magic ‖
/// version=1 ‖ eph_x25519_pub(32) ‖ mlkem_ct(1088)` — in front of the envelope,
/// exactly mirroring `cli/src/lib.rs`.
///
/// All entropy is caller-supplied (generate in JS with
/// `crypto.getRandomValues`): `ephemeral_x25519_secret` (32) and `mlkem_coin`
/// (32) MUST be fresh per call, and `aead_nonce` MUST be exactly [`nonce_len`]
/// (24) bytes. Lengths are validated (32 / 1184 / 32 / 32 / 24); a bad length or
/// a KEM-input rejection surfaces to JS as a thrown `Error`.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn hybrid_seal_to_container(
    recipient_x25519_pub: &[u8],
    recipient_mlkem_encaps_key: &[u8],
    ephemeral_x25519_secret: &[u8],
    mlkem_coin: &[u8],
    aead_nonce: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    hybrid_seal_to_container_inner(
        recipient_x25519_pub,
        recipient_mlkem_encaps_key,
        ephemeral_x25519_secret,
        mlkem_coin,
        aead_nonce,
        plaintext,
    )
    .map_err(|e| JsError::new(&e))
}

/// Open a **CLI-compatible `SIGILhyb` container** (one produced by
/// `sigil hybrid-seal` or by [`hybrid_seal_to_container`]) with the recipient's
/// secret identity, returning the recovered plaintext.
///
/// The recipient's secret identity is the raw `(x25519_secret, mlkem_seed)` pair
/// — exactly what the CLI stores in its secret identity JSON. This re-derives
/// the 2400-byte ML-KEM decapsulation key from the 64-byte seed (like the CLI),
/// bounds-checks and parses the `SIGILhyb` header (bad magic, unsupported
/// version, or a short container all surface as a thrown `Error`), slices out
/// `eph_pub` / `mlkem_ct` / envelope, and decapsulates + decrypts. A wrong
/// recipient identity or tampered container surfaces as a thrown `Error`; the
/// plaintext is never returned in that case. `recipient_x25519_secret` MUST be
/// 32 bytes and `recipient_mlkem_seed` MUST be 64 bytes.
#[wasm_bindgen]
pub fn hybrid_open_container(
    recipient_x25519_secret: &[u8],
    recipient_mlkem_seed: &[u8],
    container: &[u8],
) -> Result<Vec<u8>, JsError> {
    hybrid_open_container_inner(recipient_x25519_secret, recipient_mlkem_seed, container)
        .map_err(|e| JsError::new(&e))
}

// --- TOTP / HOTP one-time-password codes (RFC 4226 / RFC 6238) --------------
//
// A thin binding over `sigil-core`'s OTP primitive — the authenticator math at
// the heart of the product. It adds NO cryptography of its own; it only marshals
// arguments. Two contracts carry through to JS:
//
//   * NO CLOCK. `sigil-core` reads no time; the Unix time is a *caller-supplied*
//     argument. JS passes it as a Number (`f64`), which this validates to a
//     non-negative integer before the `u64` cast (JS has no native u64).
//   * The `algorithm` arrives as a lowercase string ("sha1"/"sha256"/"sha512",
//     "" → sha1), matching the CLI's `TotpEntry.algorithm` JSON field, so the
//     browser and the `sigil totp` CLI agree on the same vault entries.
//
// TOTP/HOTP draw NO entropy, so these keep the crate `getrandom`-free.

/// Compute an RFC 6238 TOTP code for `unix_time` under `key`.
///
/// `unix_time` and `t0` are JS Numbers (`f64`): each MUST be a non-negative
/// integer (finite, no fractional part, within `u64` range) or a JS `Error` is
/// thrown. `period` is the time step in seconds (usually 30), `t0` the epoch
/// offset (usually 0), `digits` the code width (6..=10), and `algorithm` one of
/// `"sha1"` (default, also for `""`), `"sha256"`, `"sha512"` — any other value is
/// rejected. Returns the numeric code WITHOUT leading-zero padding; render it with
/// [`format_code`]. A bad period / time-before-`t0` / digit count surfaces as a
/// thrown `Error`.
#[wasm_bindgen]
pub fn totp(
    key: &[u8],
    unix_time: f64,
    period: u32,
    t0: f64,
    digits: u32,
    algorithm: &str,
) -> Result<u32, JsError> {
    totp_inner(key, unix_time, period, t0, digits, algorithm).map_err(|e| JsError::new(&e))
}

/// Compute an RFC 4226 HOTP code for `counter` under `key`.
///
/// `counter` is a JS Number (`f64`) that MUST be a non-negative integer, as for
/// [`totp`]. `digits` is the code width (6..=10) and `algorithm` one of
/// `"sha1"` (default, also for `""`), `"sha256"`, `"sha512"`. Returns the numeric
/// code WITHOUT leading-zero padding; render it with [`format_code`]. Bad inputs
/// surface as a thrown `Error`.
#[wasm_bindgen]
pub fn hotp(key: &[u8], counter: f64, digits: u32, algorithm: &str) -> Result<u32, JsError> {
    hotp_inner(key, counter, digits, algorithm).map_err(|e| JsError::new(&e))
}

/// Render a numeric OTP `code` as a zero-padded decimal string of exactly
/// `digits` characters (e.g. `1` at 6 digits → `"000001"`), preserving leading
/// zeros. `digits` is clamped to the supported range, so this never throws. Thin
/// wrapper over `sigil_core::format_code`.
#[wasm_bindgen]
pub fn format_code(code: u32, digits: u32) -> String {
    core_format_code(code, digits)
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

// --- Hybrid public-key inner helpers (native-testable) ----------------------

/// Coerce a byte slice to a fixed `[u8; N]`, or a clear length-error naming the
/// argument. Used to validate the exact key/entropy sizes before calling core.
fn fixed<const N: usize>(name: &str, bytes: &[u8]) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{name} must be exactly {N} bytes, got {}", bytes.len()))
}

fn hybrid_x25519_public_inner(secret: &[u8]) -> Result<Vec<u8>, String> {
    let secret: [u8; X25519_SECRET_KEY_LEN] = fixed("x25519 secret", secret)?;
    Ok(core_x25519_public_key(&secret).to_vec())
}

fn hybrid_mlkem_encaps_key_inner(seed: &[u8]) -> Result<Vec<u8>, String> {
    let seed: [u8; ML_KEM768_KEYGEN_SEED_LEN] = fixed("mlkem keygen seed", seed)?;
    let (encaps_key, _decaps_key) = core_ml_kem768_keygen(&seed);
    Ok(encaps_key.to_vec())
}

fn hybrid_seal_to_container_inner(
    recipient_x25519_pub: &[u8],
    recipient_mlkem_encaps_key: &[u8],
    ephemeral_x25519_secret: &[u8],
    mlkem_coin: &[u8],
    aead_nonce: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let recipient_x25519_pub: [u8; X25519_PUBLIC_KEY_LEN] =
        fixed("recipient x25519 public key", recipient_x25519_pub)?;
    let recipient_mlkem_encaps_key: [u8; ML_KEM768_ENCAPS_KEY_LEN] =
        fixed("recipient mlkem encaps key", recipient_mlkem_encaps_key)?;
    let ephemeral_x25519_secret: [u8; X25519_SECRET_KEY_LEN] =
        fixed("ephemeral x25519 secret", ephemeral_x25519_secret)?;
    let mlkem_coin: [u8; ML_KEM768_ENCAPS_COIN_LEN] = fixed("mlkem coin", mlkem_coin)?;
    let aead_nonce: [u8; NONCE_LEN] = fixed("aead nonce", aead_nonce)?;

    let (eph_pub, mlkem_ct, envelope) = core_hybrid_seal(
        &recipient_x25519_pub,
        &recipient_mlkem_encaps_key,
        &ephemeral_x25519_secret,
        &mlkem_coin,
        &aead_nonce,
        HYBRID_AAD,
        plaintext,
    )
    .map_err(|e| format!("hybrid_seal failed: {e:?}"))?;

    let mut out = Vec::with_capacity(HYBRID_FIXED_PREFIX_LEN + envelope.len());
    out.extend_from_slice(HYBRID_MAGIC);
    out.push(HYBRID_FORMAT_VERSION);
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&mlkem_ct);
    out.extend_from_slice(&envelope);
    Ok(out)
}

fn hybrid_open_container_inner(
    recipient_x25519_secret: &[u8],
    recipient_mlkem_seed: &[u8],
    container: &[u8],
) -> Result<Vec<u8>, String> {
    let recipient_x25519_secret: [u8; X25519_SECRET_KEY_LEN] =
        fixed("recipient x25519 secret", recipient_x25519_secret)?;
    let recipient_mlkem_seed: [u8; ML_KEM768_KEYGEN_SEED_LEN] =
        fixed("recipient mlkem seed", recipient_mlkem_seed)?;

    // Re-derive the decapsulation key from the stored seed (like the CLI, which
    // stores only the 64-byte seed, not the expanded 2400-byte decaps key).
    let (_encaps_key, mlkem_decaps_key) = core_ml_kem768_keygen(&recipient_mlkem_seed);

    if container.len() < HYBRID_FIXED_PREFIX_LEN {
        return Err("container is too short to hold the SIGILhyb prefix".to_string());
    }

    let (magic, rest) = container.split_at(8);
    if magic != HYBRID_MAGIC.as_slice() {
        return Err("not a SIGILhyb container (bad magic: expected \"SIGILhyb\")".to_string());
    }

    let version = rest[0];
    if version != HYBRID_FORMAT_VERSION {
        return Err(format!(
            "unsupported SIGILhyb container version {version}: expected {HYBRID_FORMAT_VERSION}"
        ));
    }

    // After magic(8) + version(1): eph_x25519_pub[32] | mlkem_ct[1088] |
    // envelope[..]. The length gate above guarantees these splits are in bounds.
    let after_version = &rest[1..];
    let (eph_pub_bytes, rest2) = after_version.split_at(X25519_PUBLIC_KEY_LEN);
    let (mlkem_ct_bytes, envelope) = rest2.split_at(ML_KEM768_CIPHERTEXT_LEN);

    let eph_pub: [u8; X25519_PUBLIC_KEY_LEN] = eph_pub_bytes
        .try_into()
        .expect("eph_pub slice is exactly X25519_PUBLIC_KEY_LEN by construction");
    let mlkem_ct: [u8; ML_KEM768_CIPHERTEXT_LEN] = mlkem_ct_bytes
        .try_into()
        .expect("mlkem_ct slice is exactly ML_KEM768_CIPHERTEXT_LEN by construction");

    core_hybrid_open(
        &recipient_x25519_secret,
        &mlkem_decaps_key,
        &eph_pub,
        &mlkem_ct,
        envelope,
    )
    .map_err(|e| format!("hybrid_open failed: {e:?}"))
}

// --- TOTP / HOTP inner helpers (native-testable, no `JsError`) --------------

/// Map a case-insensitive algorithm string to an [`OtpAlgorithm`], defaulting
/// `""` to SHA-1 and rejecting anything unknown. Mirrors the CLI's
/// `totp_algorithm_from_str` so the two clients accept the same JSON.
fn otp_algorithm_from_str(s: &str) -> Result<OtpAlgorithm, String> {
    match s.to_ascii_lowercase().as_str() {
        "" | "sha1" => Ok(OtpAlgorithm::Sha1),
        "sha256" => Ok(OtpAlgorithm::Sha256),
        "sha512" => Ok(OtpAlgorithm::Sha512),
        other => Err(format!(
            "unknown OTP algorithm {other:?}: expected sha1, sha256, or sha512"
        )),
    }
}

/// Validate a JS Number (`f64`) as a non-negative integer and cast it to `u64`.
/// JS has no native u64, so time/counter values arrive as `f64`; reject anything
/// non-finite, negative, fractional, or beyond `u64` range rather than silently
/// truncating.
fn u64_from_f64(name: &str, v: f64) -> Result<u64, String> {
    if !v.is_finite() || v < 0.0 || v.fract() != 0.0 {
        return Err(format!("{name} must be a non-negative integer, got {v}"));
    }
    // f64 represents integers exactly only up to 2^53, but the round-trip is
    // still monotone up to u64::MAX; reject anything that would overflow the cast.
    if v > u64::MAX as f64 {
        return Err(format!("{name} is too large to be a u64: {v}"));
    }
    Ok(v as u64)
}

fn totp_inner(
    key: &[u8],
    unix_time: f64,
    period: u32,
    t0: f64,
    digits: u32,
    algorithm: &str,
) -> Result<u32, String> {
    let unix_time = u64_from_f64("unix_time", unix_time)?;
    let t0 = u64_from_f64("t0", t0)?;
    let algorithm = otp_algorithm_from_str(algorithm)?;
    core_totp(key, unix_time, period, t0, digits, algorithm)
        .map_err(|e| format!("totp failed: {e}"))
}

fn hotp_inner(key: &[u8], counter: f64, digits: u32, algorithm: &str) -> Result<u32, String> {
    let counter = u64_from_f64("counter", counter)?;
    let algorithm = otp_algorithm_from_str(algorithm)?;
    core_hotp(key, counter, digits, algorithm).map_err(|e| format!("hotp failed: {e}"))
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

    // --- Hybrid public-key `SIGILhyb` container interop -------------------

    // Deterministic test material so the native tests are reproducible. The
    // wasm module has no RNG; these mirror what JS would supply via
    // crypto.getRandomValues.
    const HYB_X25519_SECRET: [u8; X25519_SECRET_KEY_LEN] = [0x11; X25519_SECRET_KEY_LEN];
    const HYB_MLKEM_SEED: [u8; ML_KEM768_KEYGEN_SEED_LEN] = [0x22; ML_KEM768_KEYGEN_SEED_LEN];
    const HYB_EPH_SECRET: [u8; X25519_SECRET_KEY_LEN] = [0x33; X25519_SECRET_KEY_LEN];
    const HYB_COIN: [u8; ML_KEM768_ENCAPS_COIN_LEN] = [0x44; ML_KEM768_ENCAPS_COIN_LEN];
    const HYB_PLAINTEXT: &[u8] = b"a hybrid public-key secret (not really)";

    fn hyb_nonce() -> Vec<u8> {
        vec![0x55; NONCE_LEN]
    }

    /// Derive the recipient's public parts (as JS would) then seal to them.
    fn hyb_seal() -> Vec<u8> {
        let recipient_pub = hybrid_x25519_public_inner(&HYB_X25519_SECRET).unwrap();
        let recipient_ek = hybrid_mlkem_encaps_key_inner(&HYB_MLKEM_SEED).unwrap();
        hybrid_seal_to_container_inner(
            &recipient_pub,
            &recipient_ek,
            &HYB_EPH_SECRET,
            &HYB_COIN,
            &hyb_nonce(),
            HYB_PLAINTEXT,
        )
        .unwrap()
    }

    #[test]
    fn hybrid_public_derivation_lengths() {
        // The derived public parts must have the CLI/core-fixed sizes.
        assert_eq!(
            hybrid_x25519_public_inner(&HYB_X25519_SECRET)
                .unwrap()
                .len(),
            X25519_PUBLIC_KEY_LEN
        );
        assert_eq!(
            hybrid_mlkem_encaps_key_inner(&HYB_MLKEM_SEED)
                .unwrap()
                .len(),
            ML_KEM768_ENCAPS_KEY_LEN
        );
        // Bad input lengths are rejected, not truncated.
        assert!(hybrid_x25519_public_inner(&[0u8; 31]).is_err());
        assert!(hybrid_mlkem_encaps_key_inner(&[0u8; 63]).is_err());
    }

    #[test]
    fn hybrid_container_round_trip() {
        let c = hyb_seal();
        // The container must not leak the plaintext.
        assert!(!contains(&c, HYB_PLAINTEXT));
        let out = hybrid_open_container_inner(&HYB_X25519_SECRET, &HYB_MLKEM_SEED, &c).unwrap();
        assert_eq!(out, HYB_PLAINTEXT);
    }

    #[test]
    fn hybrid_wrong_recipient_fails() {
        let c = hyb_seal();
        // A different X25519 secret must not open it.
        let other_x = [0x99; X25519_SECRET_KEY_LEN];
        assert!(hybrid_open_container_inner(&other_x, &HYB_MLKEM_SEED, &c).is_err());
        // A different ML-KEM seed must not open it either.
        let other_seed = [0xAA; ML_KEM768_KEYGEN_SEED_LEN];
        assert!(hybrid_open_container_inner(&HYB_X25519_SECRET, &other_seed, &c).is_err());
    }

    #[test]
    fn hybrid_bad_magic_rejected() {
        let mut c = hyb_seal();
        c[0] ^= 0xff; // corrupt the first magic byte
        assert!(hybrid_open_container_inner(&HYB_X25519_SECRET, &HYB_MLKEM_SEED, &c).is_err());
    }

    #[test]
    fn hybrid_truncated_container_rejected() {
        // Anything shorter than the fixed prefix must be rejected, not panic.
        let short = vec![0u8; HYBRID_FIXED_PREFIX_LEN - 1];
        assert!(hybrid_open_container_inner(&HYB_X25519_SECRET, &HYB_MLKEM_SEED, &short).is_err());
    }

    #[test]
    fn hybrid_bad_secret_lengths_rejected() {
        let c = hyb_seal();
        // A wrong-length secret or seed is a clear error, never a panic.
        assert!(hybrid_open_container_inner(&[0u8; 31], &HYB_MLKEM_SEED, &c).is_err());
        assert!(hybrid_open_container_inner(&HYB_X25519_SECRET, &[0u8; 63], &c).is_err());
    }

    #[test]
    fn hybrid_container_prefix_is_golden() {
        // A byte-exact cross-check of the fixed prefix against the CLI layout
        // (cli/src/lib.rs): magic ‖ version ‖ eph_pub[32] ‖ mlkem_ct[1088].
        let c = hyb_seal();
        assert!(c.len() > HYBRID_FIXED_PREFIX_LEN);
        assert_eq!(&c[..8], b"SIGILhyb"); // magic
        assert_eq!(c[8], 1); // version
                             // eph_pub occupies bytes 9..41, mlkem_ct 41..1129.
        assert_eq!(
            HYBRID_FIXED_PREFIX_LEN,
            9 + X25519_PUBLIC_KEY_LEN + ML_KEM768_CIPHERTEXT_LEN
        );
        assert_eq!(HYBRID_FIXED_PREFIX_LEN, 1129);
        // The eph_pub in the container must equal the public key of the
        // ephemeral secret we sealed with (offsets are correct).
        let eph_pub = core_x25519_public_key(&HYB_EPH_SECRET);
        assert_eq!(&c[9..9 + X25519_PUBLIC_KEY_LEN], eph_pub.as_slice());
    }

    // --- TOTP / HOTP: RFC vectors through the wasm wrappers ---------------
    //
    // These assert the SAME official known-answer vectors sigil-core is checked
    // against (RFC 4226 App D / RFC 6238 App B), but *through* the f64/string
    // wrapper shells, so the JS-facing contract is proven correct independent of
    // any clock.

    /// RFC 6238 Appendix B keys — a distinct ASCII length per hash.
    const RFC_KEY_SHA1: &[u8] = b"12345678901234567890";
    const RFC_KEY_SHA256: &[u8] = b"12345678901234567890123456789012";
    const RFC_KEY_SHA512: &[u8] =
        b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn totp_rfc6238_vectors_through_wrapper() {
        // T=59, 8 digits, period 30, t0 0 — one vector per hash.
        assert_eq!(
            totp_inner(RFC_KEY_SHA1, 59.0, 30, 0.0, 8, "sha1").unwrap(),
            94287082
        );
        assert_eq!(
            totp_inner(RFC_KEY_SHA256, 59.0, 30, 0.0, 8, "sha256").unwrap(),
            46119246
        );
        assert_eq!(
            totp_inner(RFC_KEY_SHA512, 59.0, 30, 0.0, 8, "sha512").unwrap(),
            90693936
        );
        // A large time (2e10) is still an exact f64 integer and must verify.
        assert_eq!(
            totp_inner(RFC_KEY_SHA1, 20000000000.0, 30, 0.0, 8, "sha1").unwrap(),
            65353130
        );
        // "" defaults to SHA-1.
        assert_eq!(
            totp_inner(RFC_KEY_SHA1, 59.0, 30, 0.0, 8, "").unwrap(),
            94287082
        );
    }

    #[test]
    fn hotp_rfc4226_vectors_through_wrapper() {
        // RFC 4226 Appendix D, counters 0 and 1, 6 digits, SHA-1.
        assert_eq!(hotp_inner(RFC_KEY_SHA1, 0.0, 6, "sha1").unwrap(), 755224);
        assert_eq!(hotp_inner(RFC_KEY_SHA1, 1.0, 6, "SHA1").unwrap(), 287082);
    }

    #[test]
    fn format_code_wrapper_pads() {
        // The wasm shell must preserve leading zeros exactly like the core.
        assert_eq!(format_code(1, 6), "000001");
        assert_eq!(format_code(73921, 6), "073921");
        assert_eq!(format_code(94287082, 8), "94287082");
    }

    #[test]
    fn otp_unknown_algorithm_rejected() {
        assert!(totp_inner(RFC_KEY_SHA1, 59.0, 30, 0.0, 8, "md5").is_err());
        assert!(hotp_inner(RFC_KEY_SHA1, 0.0, 6, "sha3-256").is_err());
    }

    #[test]
    fn otp_rejects_non_integer_negative_and_nan_time() {
        assert!(totp_inner(RFC_KEY_SHA1, 59.5, 30, 0.0, 8, "sha1").is_err());
        assert!(totp_inner(RFC_KEY_SHA1, -1.0, 30, 0.0, 8, "sha1").is_err());
        assert!(totp_inner(RFC_KEY_SHA1, f64::NAN, 30, 0.0, 8, "sha1").is_err());
        assert!(totp_inner(RFC_KEY_SHA1, f64::INFINITY, 30, 0.0, 8, "sha1").is_err());
        assert!(hotp_inner(RFC_KEY_SHA1, 1.5, 6, "sha1").is_err());
    }

    #[test]
    fn otp_out_of_range_params_rejected() {
        // digits below MIN, and a zero period, must surface as errors (not panic).
        assert!(totp_inner(RFC_KEY_SHA1, 59.0, 30, 0.0, 5, "sha1").is_err());
        assert!(totp_inner(RFC_KEY_SHA1, 59.0, 0, 0.0, 8, "sha1").is_err());
    }
}
