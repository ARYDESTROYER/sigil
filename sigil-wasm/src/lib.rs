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
    decode_recovery_kit as core_decode_recovery_kit,
    derive_recovery_keys as core_derive_recovery_keys,
    encode_recovery_kit as core_encode_recovery_kit, format_code as core_format_code,
    format_recovery_kit as core_format_recovery_kit, hotp as core_hotp,
    hybrid_auth_open as core_hybrid_auth_open, hybrid_auth_seal as core_hybrid_auth_seal,
    hybrid_open as core_hybrid_open, hybrid_seal as core_hybrid_seal,
    ml_kem768_keygen as core_ml_kem768_keygen, open_record as core_open_record,
    public_key_from_seed as core_public_key_from_seed, seal_record as core_seal_record,
    sign as core_sign, totp as core_totp, vault_key_wrap_aad as core_vault_key_wrap_aad,
    verify as core_verify, x25519_public_key as core_x25519_public_key, Argon2Params, OtpAlgorithm,
    ML_KEM768_CIPHERTEXT_LEN, ML_KEM768_ENCAPS_COIN_LEN, ML_KEM768_ENCAPS_KEY_LEN,
    ML_KEM768_KEYGEN_SEED_LEN, NONCE_LEN, RECOVERY_SEED_LEN, SIGNATURE_LEN, SIG_PUBLIC_KEY_LEN,
    SIG_SEED_LEN, X25519_PUBLIC_KEY_LEN, X25519_SECRET_KEY_LEN,
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

// --- The AUTHENTICATED `SIGILhyb` container (version 2) ---------------------
//
// PHASE 60. The version-1 container above is ANONYMOUS: its only sender-side key
// is a per-message EPHEMERAL X25519 secret, so anybody holding the recipient's
// PUBLISHED hybrid public key can mint a container the recipient opens happily.
// That is honest for file-to-a-pubkey encryption and CATASTROPHIC for delivering
// a vault KEY — reproduced with the shipped binary:
//
//     sigil hybrid-seal --recipient-pub victim.pub --in attacker_key.bin --out forged.env
//     -> 1226 bytes, magic SIGILhyb, byte-shaped IDENTICALLY to a genuine wrap
//
// Version 2 fixes it with `sigil_core::hybrid_auth_seal` (HPKE `mode_auth`'s
// shape: a static-static X25519 DH from the SENDER's long-term secret is mixed
// into the KDF) plus a CONTEXT-BOUND AAD. The FRAMING is byte-identical to v1 —
// only the version byte and the sealing differ.
//
// ⚠️ BUT THE LENGTH IS NOT. This comment used to end "so a wrapped 32-byte vault
// key is still exactly 1226 bytes", which is FALSE and was contradicted by this
// file's own `authenticated_container_round_trips` test. The envelope carries
// its AAD (in the clear, authenticated by the tag), and the AAD now names the
// vault and BOTH device ids — so the size depends on those identifiers. Measured
// against a live sigild with real server-assigned ids: 1304-1307 bytes. The
// fixed part is `HYBRID_FIXED_PREFIX_LEN + 79`; add `aad.len()`. Nothing may
// hard-code 1226 for a VAULT-KEY envelope from Phase 60 on — the ANONYMOUS v1
// FILE container is the fixed-size one, and conflating the two is how a
// forgery ended up byte-shaped like a genuine wrap in the first place.
//
// ⭐ The SENDER's static public key is deliberately NOT carried in the container.
// It is an INPUT the caller supplies out of band (from the pin store, through
// `verifySenderForUnwrap` in sharing.mjs). Carrying it would invite exactly the
// mistake this fixes: reading the sender's identity out of attacker-controlled
// bytes and then "verifying" against it.

/// The AUTHENTICATED `SIGILhyb` container version — what every vault-key
/// envelope is written as, and the only version an authenticated open accepts.
/// MUST equal `cli/src/lib.rs::HYBRID_AUTH_FORMAT_VERSION` (`2`).
const HYBRID_AUTH_FORMAT_VERSION: u8 = 2;

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

/// Read the Argon2id work factors declared by a `SIGILcli` container header,
/// WITHOUT opening it — no password, no KDF, no allocation.
///
/// Returns `[m_cost, t_cost, p_cost]` as a `Uint32Array`. The JS wrapper
/// `containerParams()` in `totp-vault.mjs` turns that into
/// `{ m_cost, t_cost, p_cost }`.
///
/// Mirrors `sigil_cli::container_params`, and like it, range-checks the declared
/// values against `sigil-core`'s ceilings so a hostile header is a thrown error
/// rather than something a caller might feed back into a seal.
#[wasm_bindgen]
pub fn container_params(container: &[u8]) -> Result<Vec<u32>, JsError> {
    let p = container_params_inner(container).map_err(|e| JsError::new(&e))?;
    Ok(vec![p.m_cost, p.t_cost, p.p_cost])
}

/// ⭐ **THE NO-DOWNGRADE RATCHET FOR JAVASCRIPT — the choke point for every JS
/// re-seal.** Given the container about to be REPLACED and the work factors this
/// client would write today, return the factors it must actually write:
/// `Argon2Params::no_downgrade(existing, requested)`, the componentwise maximum
/// (with Argon2's `m_cost >= 8 * p_cost` floor honoured).
///
/// Returns `[m_cost, t_cost, p_cost]` as a `Uint32Array`.
///
/// ⛔ **Why this exists.** The Rust clients have had this ratchet since Phase 58
/// (`sigil_cli::reseal_container`); the JS clients had NO equivalent, so every
/// browser edit re-sealed at a hardcoded `19456 / 2 / 1`. A vault written by the
/// CLI at `65536 / 4 / 2` came back from a single browser edit at a **3.4×
/// weaker memory cost and half the passes**, silently, with no user action and
/// no error — and because a re-seal is where new parameters are chosen, the
/// weakening was permanent until something else raised it.
///
/// ⭐ The rule itself is NOT reimplemented here: it is `sigil-core`'s
/// `Argon2Params::no_downgrade`, the same function `sigil_cli::no_downgrade`
/// delegates to. There is one implementation, so the browser and the CLI cannot
/// drift — which matters because a drift downward would be invisible.
///
/// Errors on a header that is not a valid `SIGILcli` header (see
/// [`container_params`]); a caller with no existing container must not call this
/// at all — it should seal at its own defaults, since there is nothing to ratchet
/// from.
#[wasm_bindgen]
pub fn reseal_params(
    container: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Vec<u32>, JsError> {
    let existing = container_params_inner(container).map_err(|e| JsError::new(&e))?;
    let out = existing.no_downgrade(Argon2Params {
        m_cost,
        t_cost,
        p_cost,
    });
    Ok(vec![out.m_cost, out.t_cost, out.p_cost])
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

// --- AUTHENTICATED hybrid encryption: the `SIGILhyb` v2 vault-key envelope ---
//
// Three thin shells over `sigil_core::hybrid_auth` + `vault_key_wrap_aad`. As
// everywhere in this crate they add NO cryptography and NO codec of their own,
// and ALL entropy stays caller-supplied from JS `crypto.getRandomValues`, so
// `sigil-wasm/Cargo.lock` stays `getrandom`-free.

/// Build the CONTEXT-BOUND additional-authenticated-data bytes for a vault-key
/// wrap: `"sigil-vault-key-wrap-v1\n"` followed by the three identifiers, each
/// `u32` big-endian length-prefixed.
///
/// ⭐ SINGLE-SOURCED, NOT MIRRORED. This is a one-line shell over
/// `sigil_core::vault_key_wrap_aad`, which the `sigil` CLI calls too — so the JS
/// clients and the Rust clients compute the same bytes by construction rather
/// than by two hand-written implementations agreeing. Both sides still carry the
/// same golden vector as a drift alarm.
///
/// Both parties MUST pass the identical `(vault_id, recipient_device_id,
/// sender_device_id)` triple or the AEAD refuses to open — which is the point:
/// it is what stops an envelope being re-filed under another vault, another
/// recipient, another sender, or as an anonymous file container.
#[wasm_bindgen]
pub fn vault_key_wrap_aad(
    vault_id: &str,
    recipient_device_id: &str,
    sender_device_id: &str,
) -> Vec<u8> {
    core_vault_key_wrap_aad(vault_id, recipient_device_id, sender_device_id)
}

/// AUTHENTICATED seal: encrypt `plaintext` TO a recipient's hybrid public
/// identity **AS** the holder of `sender_x25519_secret`, under `aad`, producing
/// a **CLI-compatible `SIGILhyb` VERSION 2 container**.
///
/// This is the wrap half of device-to-device vault sharing. Unlike
/// [`hybrid_seal_to_container`], a party holding only the recipient's PUBLIC key
/// cannot produce a container this authenticates: the sender's long-term X25519
/// secret feeds a third Diffie–Hellman that goes into the KDF.
///
/// `sender_x25519_secret` (32) is the device's LONG-TERM hybrid secret scalar —
/// the same one [`hybrid_x25519_public`] publishes the public half of. The
/// remaining entropy is caller-supplied and MUST be fresh per call:
/// `ephemeral_x25519_secret` (32), `mlkem_coin` (32), `aead_nonce` (24).
///
/// ⭐ Pass [`vault_key_wrap_aad`]'s output as `aad` for a vault-key wrap. A bad
/// length or a KEM-input rejection surfaces to JS as a thrown `Error`.
#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
pub fn hybrid_auth_seal_to_container(
    sender_x25519_secret: &[u8],
    recipient_x25519_pub: &[u8],
    recipient_mlkem_encaps_key: &[u8],
    ephemeral_x25519_secret: &[u8],
    mlkem_coin: &[u8],
    aead_nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    hybrid_auth_seal_to_container_inner(
        sender_x25519_secret,
        recipient_x25519_pub,
        recipient_mlkem_encaps_key,
        ephemeral_x25519_secret,
        mlkem_coin,
        aead_nonce,
        aad,
        plaintext,
    )
    .map_err(|e| JsError::new(&e))
}

/// AUTHENTICATED open: decrypt a `SIGILhyb` **version 2** container with this
/// device's hybrid secret identity, **asserting it came from
/// `sender_x25519_pub`** and was sealed under exactly `aad`.
///
/// ⛔ A **version 1** (anonymous) container is REFUSED before any cryptography
/// runs, with an error naming the version found. That refusal is the whole
/// point: a v1 container carries no sender at all, so accepting one would accept
/// a key an attacker chose.
///
/// `sender_x25519_pub` is an INPUT, never read out of the container. Passing the
/// wrong sender yields a different shared secret and therefore an AEAD
/// authentication failure — no string comparison is trusted anywhere.
///
/// A wrong recipient, a WRONG SENDER, a tampered container or a mismatched `aad`
/// all surface as a thrown `Error`, and no plaintext is returned in any of those
/// cases.
#[wasm_bindgen]
pub fn hybrid_auth_open_container(
    recipient_x25519_secret: &[u8],
    recipient_mlkem_seed: &[u8],
    sender_x25519_pub: &[u8],
    aad: &[u8],
    container: &[u8],
) -> Result<Vec<u8>, JsError> {
    hybrid_auth_open_container_inner(
        recipient_x25519_secret,
        recipient_mlkem_seed,
        sender_x25519_pub,
        aad,
        container,
    )
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

/// ⭐ The CONTENT-DERIVED id of a TOTP entry (Phase 61) — a one-line shell over
/// `sigil_core::entry_id`, adding NO cryptography and NO codec.
///
/// It exists so the browser clients reach the SAME bytes the CLI and the desktop
/// do, rather than a JavaScript reimplementation. A drift in this function would
/// be **invisible**: it produces a vault that opens correctly everywhere and
/// merely duplicates or mis-suppresses entries when two devices merge. So unlike
/// the vault SCHEMA (which is mirrored, ADR 0024), the identity derivation is
/// single-sourced in `sigil-core`.
///
/// `issuer` is `""` when the entry has none; `secret` is the DECODED key bytes
/// (not the base64 the vault stores); `algorithm` is the lowercase name.
/// `disambiguator` is `0` for every ordinary call. Draws no entropy and reads no
/// clock, so the crate stays `getrandom`-free.
#[wasm_bindgen]
pub fn entry_id(
    issuer: &str,
    label: &str,
    secret: &[u8],
    algorithm: &str,
    digits: u32,
    period: u32,
    disambiguator: u32,
) -> String {
    sigil_core::entry_id(
        issuer,
        label,
        secret,
        algorithm,
        digits,
        period,
        disambiguator,
    )
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

// --- Ed25519 signatures (device identity / op-log request auth) -------------
//
// A thin binding over `sigil-core`'s CLASSICAL Ed25519 primitive. It exists so a
// BROWSER client can hold a device identity and sign sigild's op-log request-auth
// contract v3 (and the device-enrollment proof of possession) with the SAME real
// crypto the `sigil` CLI uses — see `sigil-wasm/device-auth.mjs`, which mirrors
// `cli/src/lib.rs` byte for byte.
//
// The caller-supplied-entropy invariant carries through unchanged: the 32-byte
// seed is a caller ARGUMENT (JS draws it from `crypto.getRandomValues`), and
// Ed25519 signing is deterministic (RFC 8032), so nothing here draws entropy and
// the crate stays `getrandom`-free.
//
// UNAUDITED, like everything else here. The seed is SECRET key material: JS must
// not log it or persist it in plaintext.

/// Derive the 32-byte Ed25519 public key from a caller-supplied 32-byte `seed`.
///
/// Deterministic and RNG-free: the same seed always yields the same public key.
/// Throws a JS `Error` unless `seed` is exactly 32 bytes.
#[wasm_bindgen]
pub fn ed25519_public_key(seed: &[u8]) -> Result<Vec<u8>, JsError> {
    ed25519_public_key_inner(seed).map_err(|e| JsError::new(&e))
}

/// Sign `message` with the caller-supplied 32-byte Ed25519 `seed`, returning the
/// 64-byte signature.
///
/// Ed25519 signing is deterministic, so this draws no randomness. Throws a JS
/// `Error` unless `seed` is exactly 32 bytes.
#[wasm_bindgen]
pub fn ed25519_sign(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, JsError> {
    ed25519_sign_inner(seed, message).map_err(|e| JsError::new(&e))
}

/// Strictly verify a 64-byte Ed25519 `signature` over `message` under
/// `public_key` (32 bytes). Returns `true`/`false`; a wrong-length key or
/// signature throws a JS `Error` (that is a caller bug, not a verdict).
#[wasm_bindgen]
pub fn ed25519_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, JsError> {
    ed25519_verify_inner(public_key, message, signature).map_err(|e| JsError::new(&e))
}

// --- RECOVERY KIT (Phase 54) -----------------------------------------------
//
// Thin shells over `sigil-core`'s recovery module. NO cryptography and NO codec
// lives here: the Crockford codec, the checksum and the HKDF derivation are all
// in the core, so the browser, the CLI and the native desktop client cannot
// drift — a kit printed by one MUST be redeemable by the others, and that
// failure would be silent.
//
// ⚠️ The 32-byte recovery secret and every derived seed are SECRET. JS must not
// log them, persist them in the clear, or place them in a request. The only
// outbound bytes derived from a kit are PUBLIC keys and signatures.
//
// The entropy is still the CALLER's (`crypto.getRandomValues` in JS), so this
// crate stays `getrandom`-free.

/// Encode a caller-supplied 32-byte recovery secret as the printed
/// 56-character (ungrouped) recovery code.
///
/// Throws a JS `Error` unless `seed` is exactly 32 bytes.
#[wasm_bindgen]
pub fn recovery_encode(seed: &[u8]) -> Result<String, JsError> {
    recovery_encode_inner(seed).map_err(|e| JsError::new(&e))
}

/// Decode a printed recovery code back to its 32-byte secret.
///
/// Forgiving about presentation (hyphens, spaces, case, and the Crockford
/// `O`/`I`/`L` folding) and strict about content. Throws a JS `Error` naming the
/// failure — a wrong length, a character outside the alphabet, a failed
/// checksum, or an unsupported version. It makes NO network request, which is
/// what lets a client tell "you mistyped it" apart from "that server does not
/// know this kit".
#[wasm_bindgen]
pub fn recovery_decode(code: &str) -> Result<Vec<u8>, JsError> {
    recovery_decode_inner(code).map_err(|e| JsError::new(&e))
}

/// Derive the kit's 32-byte Ed25519 device seed from its recovery secret.
#[wasm_bindgen]
pub fn recovery_derive_ed25519_seed(seed: &[u8]) -> Result<Vec<u8>, JsError> {
    recovery_derive_ed25519_seed_inner(seed).map_err(|e| JsError::new(&e))
}

/// Derive the kit's 32-byte X25519 secret scalar from its recovery secret.
#[wasm_bindgen]
pub fn recovery_derive_x25519_secret(seed: &[u8]) -> Result<Vec<u8>, JsError> {
    recovery_derive_x25519_secret_inner(seed).map_err(|e| JsError::new(&e))
}

/// Derive the kit's 64-byte ML-KEM-768 keygen seed (`d ‖ z`) from its recovery
/// secret.
#[wasm_bindgen]
pub fn recovery_derive_mlkem_seed(seed: &[u8]) -> Result<Vec<u8>, JsError> {
    recovery_derive_mlkem_seed_inner(seed).map_err(|e| JsError::new(&e))
}

/// Render a recovery code for the printed sheet: 7 groups of 8 characters
/// joined by `-`. ONE renderer everywhere, so the grouping cannot drift between
/// surfaces.
#[wasm_bindgen]
pub fn recovery_format(code: &str) -> String {
    core_format_recovery_kit(code)
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

/// Read the Argon2id work factors out of a `SIGILcli` header WITHOUT opening the
/// container — no password, no KDF, no allocation.
///
/// ⭐ This is the JS clients' equivalent of `sigil_cli::container_params`, and it
/// exists so the browser can apply the SAME no-downgrade ratchet the CLI applies
/// (`Argon2Params::no_downgrade`) instead of re-sealing at whatever its own
/// defaults happen to be. Without it, one browser edit of a CLI-written vault
/// silently rewrote a 64 MiB / 4-pass header as 19 MiB / 2-pass.
///
/// The header is unauthenticated framing, so this reports what the writer
/// *claims* — which is exactly what the ratchet needs, and exactly why the values
/// are range-checked here as well.
fn container_params_inner(container: &[u8]) -> Result<Argon2Params, String> {
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

    // Fixed-width fields after the version byte: m_cost, t_cost, p_cost.
    let m_cost = u32::from_le_bytes([rest[1], rest[2], rest[3], rest[4]]);
    let t_cost = u32::from_le_bytes([rest[5], rest[6], rest[7], rest[8]]);
    let p_cost = u32::from_le_bytes([rest[9], rest[10], rest[11], rest[12]]);

    // ⛔ RANGE-CHECK BEFORE ANY ALLOCATION — the mirror of the same check in
    // `cli/src/lib.rs::open_container`. These three u32s are UNAUTHENTICATED
    // header bytes written by whoever produced the container, and Argon2id
    // allocates `m_cost` KiB in one block before doing any work; `m_cost =
    // 0xFFFF_FFF0` asks for ~4 TiB and takes the tab (or the whole extension
    // page) down. Browser clients pull containers from `sigild`'s ZERO-KNOWLEDGE
    // op-log, which by design cannot inspect or filter what it relays, so the
    // refusal has to happen here.
    //
    // ⭐ The ceilings themselves are NOT mirrored: they are `sigil-core`'s
    // `Argon2Params::MAX_*` constants, read from the one crate both this binding
    // and the CLI already depend on, so this bound cannot drift from the CLI's
    // the way the format constants above could.
    let params = Argon2Params {
        m_cost,
        t_cost,
        p_cost,
    };
    if params.validate().is_err() {
        return Err(format!(
            "refusing this SIGILcli container: its header demands Argon2id work \
             factors beyond what any Sigil client will honour (m_cost={m_cost} KiB, \
             t_cost={t_cost}, p_cost={p_cost}; limits are {}/{}/{}). Nothing was \
             allocated",
            Argon2Params::MAX_M_COST,
            Argon2Params::MAX_T_COST,
            Argon2Params::MAX_P_COST
        ));
    }
    Ok(params)
}

fn open_container_inner(password: &[u8], container: &[u8]) -> Result<Vec<u8>, String> {
    // Parses + range-checks magic, version and the three work factors. Every
    // failure here happens BEFORE a byte is allocated for the KDF.
    let params = container_params_inner(container)?;
    let (m_cost, t_cost, p_cost) = (params.m_cost, params.t_cost, params.p_cost);
    let rest = &container[8..];
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

    let (version, eph_pub, mlkem_ct, envelope) = split_hybrid_container(container)?;
    if version == HYBRID_AUTH_FORMAT_VERSION {
        // The OTHER direction of the same rule (mirrors the CLI): opening an
        // AUTHENTICATED vault-key envelope here would drop the sender check and
        // the context binding on the floor.
        return Err(format!(
            "SIGILhyb container version {version} presented where version \
             {HYBRID_FORMAT_VERSION} is required (version 2 is an AUTHENTICATED vault-key \
             envelope — open it with hybrid_auth_open_container)"
        ));
    }
    if version != HYBRID_FORMAT_VERSION {
        return Err(format!(
            "unsupported SIGILhyb container version {version}: expected {HYBRID_FORMAT_VERSION}"
        ));
    }

    core_hybrid_open(
        &recipient_x25519_secret,
        &mlkem_decaps_key,
        &eph_pub,
        &mlkem_ct,
        envelope,
    )
    .map_err(|e| format!("hybrid_open failed: {e:?}"))
}

/// Split a `SIGILhyb` container into `(version, eph_x25519_pub, mlkem_ct,
/// envelope)`, bounds-checking BEFORE slicing. Shared by the anonymous (v1) and
/// authenticated (v2) readers, whose framing is identical. Mirrors
/// `cli/src/lib.rs::split_hybrid_container`.
#[allow(clippy::type_complexity)]
fn split_hybrid_container(
    container: &[u8],
) -> Result<
    (
        u8,
        [u8; X25519_PUBLIC_KEY_LEN],
        [u8; ML_KEM768_CIPHERTEXT_LEN],
        &[u8],
    ),
    String,
> {
    if container.len() < HYBRID_FIXED_PREFIX_LEN {
        return Err("container is too short to hold the SIGILhyb prefix".to_string());
    }
    let (magic, rest) = container.split_at(8);
    if magic != HYBRID_MAGIC.as_slice() {
        return Err("not a SIGILhyb container (bad magic: expected \"SIGILhyb\")".to_string());
    }
    let version = rest[0];
    let after_version = &rest[1..];
    let (eph_pub_bytes, rest2) = after_version.split_at(X25519_PUBLIC_KEY_LEN);
    let (mlkem_ct_bytes, envelope) = rest2.split_at(ML_KEM768_CIPHERTEXT_LEN);
    let eph_pub: [u8; X25519_PUBLIC_KEY_LEN] = eph_pub_bytes
        .try_into()
        .expect("eph_pub slice is exactly X25519_PUBLIC_KEY_LEN by construction");
    let mlkem_ct: [u8; ML_KEM768_CIPHERTEXT_LEN] = mlkem_ct_bytes
        .try_into()
        .expect("mlkem_ct slice is exactly ML_KEM768_CIPHERTEXT_LEN by construction");
    Ok((version, eph_pub, mlkem_ct, envelope))
}

#[allow(clippy::too_many_arguments)]
fn hybrid_auth_seal_to_container_inner(
    sender_x25519_secret: &[u8],
    recipient_x25519_pub: &[u8],
    recipient_mlkem_encaps_key: &[u8],
    ephemeral_x25519_secret: &[u8],
    mlkem_coin: &[u8],
    aead_nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let sender_x25519_secret: [u8; X25519_SECRET_KEY_LEN] =
        fixed("sender x25519 secret", sender_x25519_secret)?;
    let recipient_x25519_pub: [u8; X25519_PUBLIC_KEY_LEN] =
        fixed("recipient x25519 public key", recipient_x25519_pub)?;
    let recipient_mlkem_encaps_key: [u8; ML_KEM768_ENCAPS_KEY_LEN] =
        fixed("recipient mlkem encaps key", recipient_mlkem_encaps_key)?;
    let ephemeral_x25519_secret: [u8; X25519_SECRET_KEY_LEN] =
        fixed("ephemeral x25519 secret", ephemeral_x25519_secret)?;
    let mlkem_coin: [u8; ML_KEM768_ENCAPS_COIN_LEN] = fixed("mlkem coin", mlkem_coin)?;
    let aead_nonce: [u8; NONCE_LEN] = fixed("aead nonce", aead_nonce)?;

    let (eph_pub, mlkem_ct, envelope) = core_hybrid_auth_seal(
        &sender_x25519_secret,
        &recipient_x25519_pub,
        &recipient_mlkem_encaps_key,
        &ephemeral_x25519_secret,
        &mlkem_coin,
        &aead_nonce,
        aad,
        plaintext,
    )
    .map_err(|e| format!("hybrid_auth_seal failed: {e:?}"))?;

    let mut out = Vec::with_capacity(HYBRID_FIXED_PREFIX_LEN + envelope.len());
    out.extend_from_slice(HYBRID_MAGIC);
    out.push(HYBRID_AUTH_FORMAT_VERSION);
    out.extend_from_slice(&eph_pub);
    out.extend_from_slice(&mlkem_ct);
    out.extend_from_slice(&envelope);
    Ok(out)
}

fn hybrid_auth_open_container_inner(
    recipient_x25519_secret: &[u8],
    recipient_mlkem_seed: &[u8],
    sender_x25519_pub: &[u8],
    aad: &[u8],
    container: &[u8],
) -> Result<Vec<u8>, String> {
    let recipient_x25519_secret: [u8; X25519_SECRET_KEY_LEN] =
        fixed("recipient x25519 secret", recipient_x25519_secret)?;
    let recipient_mlkem_seed: [u8; ML_KEM768_KEYGEN_SEED_LEN] =
        fixed("recipient mlkem seed", recipient_mlkem_seed)?;
    let sender_x25519_pub: [u8; X25519_PUBLIC_KEY_LEN] =
        fixed("sender x25519 public key", sender_x25519_pub)?;

    let (version, eph_pub, mlkem_ct, envelope) = split_hybrid_container(container)?;
    if version != HYBRID_AUTH_FORMAT_VERSION {
        // ⛔ THE REFUSAL. A version-1 container proves nothing about who made it.
        return Err(format!(
            "SIGILhyb container version {version} presented where version \
             {HYBRID_AUTH_FORMAT_VERSION} is required (version 1 = ANONYMOUS file container, \
             version 2 = AUTHENTICATED vault-key envelope; they are not interchangeable)"
        ));
    }

    // The CLI stores only the 64-byte seed; re-derive the decapsulation key.
    let (_encaps_key, mlkem_decaps_key) = core_ml_kem768_keygen(&recipient_mlkem_seed);

    core_hybrid_auth_open(
        &recipient_x25519_secret,
        &mlkem_decaps_key,
        &sender_x25519_pub,
        &eph_pub,
        &mlkem_ct,
        aad,
        envelope,
    )
    .map_err(|e| format!("hybrid_auth_open failed: {e:?}"))
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

// --- Ed25519 inner helpers (native-testable, no `JsError`) ------------------

fn ed25519_public_key_inner(seed: &[u8]) -> Result<Vec<u8>, String> {
    let seed: [u8; SIG_SEED_LEN] = fixed("ed25519 seed", seed)?;
    Ok(core_public_key_from_seed(&seed).to_vec())
}

fn ed25519_sign_inner(seed: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let seed: [u8; SIG_SEED_LEN] = fixed("ed25519 seed", seed)?;
    Ok(core_sign(&seed, message).to_vec())
}

fn ed25519_verify_inner(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    let public_key: [u8; SIG_PUBLIC_KEY_LEN] = fixed("ed25519 public key", public_key)?;
    let signature: [u8; SIGNATURE_LEN] = fixed("ed25519 signature", signature)?;
    Ok(core_verify(&public_key, message, &signature).is_ok())
}

// --- Recovery-kit inner helpers (native-testable, no `JsError`) -------------

fn recovery_seed_arg(seed: &[u8]) -> Result<[u8; RECOVERY_SEED_LEN], String> {
    fixed("recovery secret", seed)
}

fn recovery_encode_inner(seed: &[u8]) -> Result<String, String> {
    let seed = recovery_seed_arg(seed)?;
    let code = core_encode_recovery_kit(&seed);
    String::from_utf8(code.to_vec()).map_err(|e| format!("encoded recovery code is not ASCII: {e}"))
}

fn recovery_decode_inner(code: &str) -> Result<Vec<u8>, String> {
    core_decode_recovery_kit(code)
        .map(|s| s.to_vec())
        .map_err(|e| e.to_string())
}

fn recovery_derive_ed25519_seed_inner(seed: &[u8]) -> Result<Vec<u8>, String> {
    let seed = recovery_seed_arg(seed)?;
    Ok(core_derive_recovery_keys(&seed).ed25519_seed.to_vec())
}

fn recovery_derive_x25519_secret_inner(seed: &[u8]) -> Result<Vec<u8>, String> {
    let seed = recovery_seed_arg(seed)?;
    Ok(core_derive_recovery_keys(&seed).x25519_secret.to_vec())
}

fn recovery_derive_mlkem_seed_inner(seed: &[u8]) -> Result<Vec<u8>, String> {
    let seed = recovery_seed_arg(seed)?;
    Ok(core_derive_recovery_keys(&seed).mlkem_keygen_seed.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Phase 54: the recovery kit ----------------------------------------

    /// Lowercase hex, so the KATs below read the same as the core's.
    fn hex(bytes: &[u8]) -> String {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            out.push(char::from_digit(u32::from(b >> 4), 16).expect("nibble"));
            out.push(char::from_digit(u32::from(b & 0x0f), 16).expect("nibble"));
        }
        out
    }

    /// ⭐ THE ANTI-DRIFT ANCHOR, identical to `sigil-core`'s and the CLI's. A
    /// kit printed by one client must be redeemable by every other, and a
    /// divergence here would fail SILENTLY.
    #[test]
    fn recovery_derivation_known_answer_vector() {
        let seed = [0x42u8; RECOVERY_SEED_LEN];

        let ed_seed = recovery_derive_ed25519_seed_inner(&seed).expect("ed25519 seed");
        let ed_pub = ed25519_public_key_inner(&ed_seed).expect("ed25519 public key");
        assert_eq!(
            hex(&ed_pub),
            "913af25b7f0ea458577b80124f137f7a8f0e5850a73a5cdeaf92e9169edeb717"
        );

        let x_secret = recovery_derive_x25519_secret_inner(&seed).expect("x25519 secret");
        let x_pub = hybrid_x25519_public_inner(&x_secret).expect("x25519 public");
        assert_eq!(
            hex(&x_pub),
            "a55ac63d4d1f84face17abb82cc3449cd43c3f25f7a08008075bd594acc98754"
        );

        // The ML-KEM encapsulation key is 1184 bytes, so its FIRST and LAST 16
        // bytes are pinned rather than a SHA-256 of the whole thing (this crate
        // has no hash dependency and must not gain one). `sigil-core`'s own KAT
        // pins the full digest; these two windows pin the same key here.
        let mlkem_seed = recovery_derive_mlkem_seed_inner(&seed).expect("mlkem seed");
        let encaps = hybrid_mlkem_encaps_key_inner(&mlkem_seed).expect("mlkem encaps");
        assert_eq!(encaps.len(), ML_KEM768_ENCAPS_KEY_LEN);
        assert_eq!(hex(&encaps[..16]), "ea867c0b6760c45a626095121b213812");
        assert_eq!(
            hex(&encaps[encaps.len() - 16..]),
            "9d833ea2523b6b6d6f5add44e4529afc"
        );

        // And the PRINTED form.
        let code = recovery_encode_inner(&seed).expect("encode");
        assert_eq!(code.len(), 56);
        assert_eq!(
            recovery_format(&code),
            "05144GJ2-89144GJ2-89144GJ2-89144GJ2-89144GJ2-89144GJ2-89145G6W"
        );
        assert_eq!(recovery_decode_inner(&code).expect("decode"), seed.to_vec());
    }

    /// Presentation folds; `U` and a bad checksum do not.
    #[test]
    fn recovery_decode_is_forgiving_about_presentation_and_strict_about_content() {
        let seed = [0x1du8; RECOVERY_SEED_LEN];
        let code = recovery_encode_inner(&seed).expect("encode");
        let grouped = recovery_format(&code);
        assert_eq!(
            recovery_decode_inner(&grouped).expect("grouped"),
            seed.to_vec()
        );
        assert_eq!(
            recovery_decode_inner(&grouped.to_lowercase()).expect("lowercase"),
            seed.to_vec()
        );

        let mut with_u: Vec<char> = code.chars().collect();
        with_u[3] = 'U';
        let with_u: String = with_u.into_iter().collect();
        assert!(
            recovery_decode_inner(&with_u).is_err(),
            "U must be rejected"
        );

        let mut typo: Vec<char> = code.chars().collect();
        typo[0] = if typo[0] == 'Z' { 'Y' } else { 'Z' };
        let typo: String = typo.into_iter().collect();
        let err = recovery_decode_inner(&typo).expect_err("a typo must be rejected");
        assert!(err.contains("not a valid recovery code"), "{err}");
    }

    /// A wrong-length secret is a caller bug and is reported as such.
    #[test]
    fn recovery_derive_rejects_a_wrong_length_secret() {
        for bad in [vec![0u8; 31], vec![0u8; 33], vec![]] {
            assert!(recovery_encode_inner(&bad).is_err());
            assert!(recovery_derive_ed25519_seed_inner(&bad).is_err());
            assert!(recovery_derive_x25519_secret_inner(&bad).is_err());
            assert!(recovery_derive_mlkem_seed_inner(&bad).is_err());
        }
    }

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

    // --- ⛔ Hostile Argon2 parameters in the container header (Phase 59) ------
    //
    // MIRRORS `cli/src/lib.rs`'s tests of the same name. A browser pulls
    // containers from sigild's zero-knowledge op-log, which cannot filter what it
    // relays, so an unbounded `m_cost` here is a remote way to kill the tab. The
    // ceilings are read from `sigil-core` (`Argon2Params::MAX_*`), NOT mirrored,
    // so this bound cannot drift from the CLI's.

    fn set_header_params(c: &mut [u8], m: u32, t: u32, p: u32) {
        c[9..13].copy_from_slice(&m.to_le_bytes());
        c[13..17].copy_from_slice(&t.to_le_bytes());
        c[17..21].copy_from_slice(&p.to_le_bytes());
    }

    #[test]
    fn container_absurd_m_cost_refused_before_allocating() {
        let mut c = seal_to_container_inner(PASSWORD, SALT, &nonce(), M, T, P, PLAINTEXT).unwrap();
        set_header_params(&mut c, 0xFFFF_FFF0, 1, 1); // ~4 TiB
        let err = open_container_inner(PASSWORD, &c).expect_err("refused");
        assert!(err.contains("4294967280"), "{err}");
        assert!(err.contains("Nothing was allocated"), "{err}");
        // Must NOT read as an authentication failure — "hostile container" and
        // "wrong password" are different things a user has to be able to tell
        // apart.
        assert!(!err.contains("open_record failed"), "{err}");
    }

    #[test]
    fn container_each_work_factor_bounded_independently() {
        for (m, t, p) in [
            (Argon2Params::MAX_M_COST + 1, 1, 1),
            (8, Argon2Params::MAX_T_COST + 1, 1),
            (8, 1, Argon2Params::MAX_P_COST + 1),
        ] {
            let mut c =
                seal_to_container_inner(PASSWORD, SALT, &nonce(), M, T, P, PLAINTEXT).unwrap();
            set_header_params(&mut c, m, t, p);
            assert!(
                open_container_inner(PASSWORD, &c).is_err(),
                "({m},{t},{p}) must be refused"
            );
        }
    }

    #[test]
    fn container_normal_params_still_open() {
        // Nothing that opens today may stop opening: the browser clients write
        // 19456/2/1, the CLI writes 65536/4/2, tests write 8/1/1.
        let c = seal_to_container_inner(PASSWORD, SALT, &nonce(), 19456, 2, 1, PLAINTEXT).unwrap();
        assert_eq!(open_container_inner(PASSWORD, &c).unwrap(), PLAINTEXT);
        assert!(Argon2Params::RECOMMENDED.validate().is_ok());
    }

    // --- ⭐ The JS no-downgrade ratchet (Phase 59 fix round) -----------------
    //
    // These back the `container_params` / `reseal_params` exports the browser
    // clients now call on EVERY re-seal. Before them, JS had no equivalent of
    // `sigil_cli::reseal_container`'s ratchet and one browser edit rewrote a
    // CLI-written 65536/4/2 header as 19456/2/1.

    #[test]
    fn container_params_reads_the_header_without_a_password() {
        let c = seal_to_container_inner(PASSWORD, SALT, &nonce(), 65536, 4, 2, PLAINTEXT).unwrap();
        let p = container_params_inner(&c).expect("params");
        assert_eq!((p.m_cost, p.t_cost, p.p_cost), (65536, 4, 2));
        // Not a container at all -> an error, never a silent default.
        assert!(container_params_inner(b"nope").is_err());
        // A hostile header is refused here too, so a caller can never feed
        // absurd factors BACK INTO a seal by way of the ratchet.
        let mut hostile =
            seal_to_container_inner(PASSWORD, SALT, &nonce(), M, T, P, PLAINTEXT).unwrap();
        set_header_params(&mut hostile, 0xFFFF_FFF0, 1, 1);
        assert!(container_params_inner(&hostile).is_err());
    }

    #[test]
    fn reseal_params_never_writes_a_weaker_header() {
        // ⛔ THE OBSERVED BUG: a CLI-written 65536/4/2 vault, re-sealed by a
        // browser whose defaults are 19456/2/1, must come back at 65536/4/2.
        let strong = seal_to_container_inner(PASSWORD, SALT, &nonce(), 65536, 4, 2, PLAINTEXT)
            .expect("seal strong");
        let existing = container_params_inner(&strong).unwrap();
        let out = existing.no_downgrade(Argon2Params {
            m_cost: 19456,
            t_cost: 2,
            p_cost: 1,
        });
        assert_eq!((out.m_cost, out.t_cost, out.p_cost), (65536, 4, 2));

        // ...and the reverse: a deliberately WEAK container is RAISED to the
        // client's defaults, not merely preserved.
        let weak =
            seal_to_container_inner(PASSWORD, SALT, &nonce(), 8, 1, 1, PLAINTEXT).expect("seal");
        let raised = container_params_inner(&weak)
            .unwrap()
            .no_downgrade(Argon2Params {
                m_cost: 19456,
                t_cost: 2,
                p_cost: 1,
            });
        assert_eq!((raised.m_cost, raised.t_cost, raised.p_cost), (19456, 2, 1));

        // A ratcheted re-seal really opens, at the ratcheted strength.
        let resealed = seal_to_container_inner(
            PASSWORD,
            SALT,
            &nonce(),
            raised.m_cost,
            raised.t_cost,
            raised.p_cost,
            PLAINTEXT,
        )
        .unwrap();
        assert_eq!(
            open_container_inner(PASSWORD, &resealed).unwrap(),
            PLAINTEXT
        );
        assert_eq!(container_params_inner(&resealed).unwrap(), raised);
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

    // --- AUTHENTICATED `SIGILhyb` v2: the vault-key envelope ---------------
    //
    // These pin the Phase 60 fix at the wasm boundary. The construction itself
    // lives in sigil-core (and is tested there); what is proven HERE is the
    // container framing, the version refusals in BOTH directions, and that the
    // shell passes the sender/AAD through unmangled.

    /// The SENDER's long-term X25519 secret (distinct from every other constant).
    const HYB_SENDER_SECRET: [u8; X25519_SECRET_KEY_LEN] = [0x66; X25519_SECRET_KEY_LEN];

    fn auth_aad() -> Vec<u8> {
        vault_key_wrap_aad("demo", "dev_bob", "dev_alice")
    }

    /// Wrap a plausible 32-byte vault key, exactly as sharing.mjs does.
    fn hyb_auth_seal(aad: &[u8]) -> Vec<u8> {
        let recipient_pub = hybrid_x25519_public_inner(&HYB_X25519_SECRET).unwrap();
        let recipient_ek = hybrid_mlkem_encaps_key_inner(&HYB_MLKEM_SEED).unwrap();
        hybrid_auth_seal_to_container_inner(
            &HYB_SENDER_SECRET,
            &recipient_pub,
            &recipient_ek,
            &HYB_EPH_SECRET,
            &HYB_COIN,
            &hyb_nonce(),
            aad,
            &[0x9Au8; 32],
        )
        .unwrap()
    }

    fn sender_pub() -> Vec<u8> {
        hybrid_x25519_public_inner(&HYB_SENDER_SECRET).unwrap()
    }

    #[test]
    fn authenticated_container_round_trips() {
        let aad = auth_aad();
        let c = hyb_auth_seal(&aad);
        // ⚠️ THE SIZE IS NO LONGER FIXED. The envelope carries its AAD in the
        // clear (authenticated by the tag), and the AAD now names the vault and
        // both devices — so a wrapped 32-byte vault key is 1129 (prefix) + 79
        // (nonce + framing + 48-byte ciphertext) + len(aad), not the flat 1226
        // that the anonymous v1 form produced with its 18-byte fixed tag.
        // Anything that hard-codes 1226 is wrong from Phase 60 on.
        assert_eq!(c.len(), HYBRID_FIXED_PREFIX_LEN + 79 + aad.len());
        assert_eq!(c.len(), 1226 - 18 + aad.len());
        assert_eq!(&c[..8], b"SIGILhyb");
        assert_eq!(c[8], HYBRID_AUTH_FORMAT_VERSION);
        assert_eq!(c[8], 2);
        let out = hybrid_auth_open_container_inner(
            &HYB_X25519_SECRET,
            &HYB_MLKEM_SEED,
            &sender_pub(),
            &aad,
            &c,
        )
        .unwrap();
        assert_eq!(out, vec![0x9Au8; 32]);
    }

    /// ⭐ THE VULNERABILITY, AT THE WASM BOUNDARY. A forger holding ONLY the
    /// recipient's published public key mints the ANONYMOUS container — the
    /// exact bytes `sigil hybrid-seal` produced — and the authenticated open
    /// refuses it as the wrong KIND, before any cryptography runs.
    #[test]
    fn a_v1_container_is_refused_where_a_vault_key_is_expected() {
        let forged = hyb_seal(); // anonymous: needs no secret of anyone's
        assert_eq!(forged[8], 1);
        let err = hybrid_auth_open_container_inner(
            &HYB_X25519_SECRET,
            &HYB_MLKEM_SEED,
            &sender_pub(),
            &auth_aad(),
            &forged,
        )
        .unwrap_err();
        assert!(err.contains("version 1"), "{err}");
        assert!(err.contains("ANONYMOUS"), "{err}");
    }

    /// And the reverse: an authenticated envelope is not an anonymous file.
    #[test]
    fn a_v2_container_is_refused_as_an_anonymous_file() {
        let c = hyb_auth_seal(&auth_aad());
        let err = hybrid_open_container_inner(&HYB_X25519_SECRET, &HYB_MLKEM_SEED, &c).unwrap_err();
        assert!(err.contains("version 2"), "{err}");
    }

    #[test]
    fn the_wrong_sender_or_the_wrong_context_is_refused() {
        let aad = auth_aad();
        let c = hyb_auth_seal(&aad);
        // Wrong sender.
        let other = hybrid_x25519_public_inner(&[0x77; X25519_SECRET_KEY_LEN]).unwrap();
        assert!(hybrid_auth_open_container_inner(
            &HYB_X25519_SECRET,
            &HYB_MLKEM_SEED,
            &other,
            &aad,
            &c
        )
        .is_err());
        // Re-filed under another vault / recipient / sender / purpose.
        for wrong in [
            vault_key_wrap_aad("other", "dev_bob", "dev_alice"),
            vault_key_wrap_aad("demo", "dev_eve", "dev_alice"),
            vault_key_wrap_aad("demo", "dev_bob", "dev_eve"),
            b"sigil-hybrid-cli/1".to_vec(),
        ] {
            assert!(
                hybrid_auth_open_container_inner(
                    &HYB_X25519_SECRET,
                    &HYB_MLKEM_SEED,
                    &sender_pub(),
                    &wrong,
                    &c
                )
                .is_err(),
                "a re-filed envelope must be refused"
            );
        }
    }

    #[test]
    fn authenticated_bad_lengths_are_rejected() {
        let aad = auth_aad();
        let recipient_pub = hybrid_x25519_public_inner(&HYB_X25519_SECRET).unwrap();
        let recipient_ek = hybrid_mlkem_encaps_key_inner(&HYB_MLKEM_SEED).unwrap();
        assert!(hybrid_auth_seal_to_container_inner(
            &[0u8; 31],
            &recipient_pub,
            &recipient_ek,
            &HYB_EPH_SECRET,
            &HYB_COIN,
            &hyb_nonce(),
            &aad,
            b"x"
        )
        .is_err());
        let c = hyb_auth_seal(&aad);
        assert!(hybrid_auth_open_container_inner(
            &HYB_X25519_SECRET,
            &HYB_MLKEM_SEED,
            &[0u8; 31],
            &aad,
            &c
        )
        .is_err());
    }

    /// ⭐ THE GOLDEN AAD VECTOR, byte for byte, so the JS mirror has exactly one
    /// number to match. Duplicated in `libsigil/core/src/hybrid_auth.rs` and in
    /// `sigil-wasm/test/sharing-interop.mjs`.
    #[test]
    fn vault_key_wrap_aad_is_golden() {
        let aad = vault_key_wrap_aad("demo", "dev_bob", "dev_alice");
        let hex: String = aad.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "736967696c2d7661756c742d6b65792d777261702d76310a0000000464656d6f\
             000000076465765f626f62000000096465765f616c696365"
        );
        // Length-prefixing means no two distinct triples collide.
        assert_ne!(
            vault_key_wrap_aad("ab", "c", "d"),
            vault_key_wrap_aad("a", "bc", "d")
        );
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

    // --- Ed25519 (device identity) ------------------------------------------

    /// RFC 8032 §7.1 Ed25519 TEST 1 (empty message) — an OFFICIAL known-answer
    /// vector. Matching it proves the binding marshals bytes to the core without
    /// mangling them, so a browser-signed request is interop-correct with sigild's
    /// Go `crypto/ed25519` verifier.
    #[test]
    fn ed25519_rfc8032_test1_known_answer_vector() {
        let seed: [u8; SIG_SEED_LEN] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        let expected_pk: [u8; SIG_PUBLIC_KEY_LEN] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        let expected_sig: [u8; SIGNATURE_LEN] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];
        let message: &[u8] = &[];

        assert_eq!(
            ed25519_public_key_inner(&seed).unwrap(),
            expected_pk.to_vec()
        );
        assert_eq!(
            ed25519_sign_inner(&seed, message).unwrap(),
            expected_sig.to_vec()
        );
        assert!(ed25519_verify_inner(&expected_pk, message, &expected_sig).unwrap());
    }

    #[test]
    fn ed25519_sign_verify_round_trip_and_rejections() {
        let seed = [0x42u8; SIG_SEED_LEN];
        let pk = ed25519_public_key_inner(&seed).unwrap();
        // A realistic contract-v3 message shape (see device-auth.mjs).
        let msg =
            b"sigil-oplog-auth-v3\ndev_abc\nPOST\n/v1/vaults/v/ops\n\n1717900000\nbm9uY2U=\nBODY";
        let sig = ed25519_sign_inner(&seed, msg).unwrap();
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert!(ed25519_verify_inner(&pk, msg, &sig).unwrap());

        // Deterministic: same (seed, message) -> identical signature.
        assert_eq!(ed25519_sign_inner(&seed, msg).unwrap(), sig);

        // A tampered message, a tampered signature, and a different key all fail
        // as a VERDICT (false), not an error.
        let mut tampered_msg = msg.to_vec();
        tampered_msg[0] ^= 0x01;
        assert!(!ed25519_verify_inner(&pk, &tampered_msg, &sig).unwrap());
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0x01;
        assert!(!ed25519_verify_inner(&pk, msg, &bad_sig).unwrap());
        let other_pk = ed25519_public_key_inner(&[0x43u8; SIG_SEED_LEN]).unwrap();
        assert!(!ed25519_verify_inner(&other_pk, msg, &sig).unwrap());
    }

    // ⭐ The SAME known-answer vector asserted in `libsigil/core/src/entry_id.rs`,
    // `cli/src/lib.rs` and `sigil-wasm/test/merge-interop.mjs`. If this export
    // ever stopped reaching `sigil_core::entry_id`, two clients would disagree
    // about which entries are the same account — silently.
    #[test]
    fn entry_id_matches_the_shared_known_answer_vector() {
        assert_eq!(
            entry_id(
                "GitHub",
                "alice@example.com",
                b"12345678901234567890",
                "sha1",
                6,
                30,
                0
            ),
            "41828256-7397-80c1-bf67-e6b85ff84173"
        );
    }

    #[test]
    fn ed25519_rejects_wrong_lengths() {
        assert!(ed25519_public_key_inner(&[0u8; 31]).is_err());
        assert!(ed25519_public_key_inner(&[0u8; 33]).is_err());
        assert!(ed25519_sign_inner(&[0u8; 31], b"m").is_err());
        let seed = [0x42u8; SIG_SEED_LEN];
        let pk = ed25519_public_key_inner(&seed).unwrap();
        let sig = ed25519_sign_inner(&seed, b"m").unwrap();
        assert!(ed25519_verify_inner(&pk[..31], b"m", &sig).is_err());
        assert!(ed25519_verify_inner(&pk, b"m", &sig[..63]).is_err());
    }
}
