//! C-ABI surface for libsigil.
//!
//! STATUS: pre-audit, UNAUDITED building block. This crate exposes a thin,
//! hand-written C-ABI over `sigil-core`'s symmetric AEAD seal/open layer
//! (XChaCha20-Poly1305 + HKDF-SHA256) so the native clients can link and call
//! into it via FFI. The underlying crypto is real (vetted RustCrypto crates)
//! but has **not** been audited, and it is **not** wired into a complete
//! account / key-management / key-rotation flow — treat the exports as
//! building blocks, not a finished secure system.
//!
//! ## Exports
//!
//! *Symmetric AEAD (variable-size output → heap [`SigilBuffer`]):*
//!
//! - [`sigil_current_suite`] — link/smoke check: returns the current
//!   algorithm-suite byte.
//! - [`sigil_seal`] — encrypt a plaintext under a caller-supplied master key
//!   and nonce, returning the **encoded envelope bytes**
//!   ([`sigil_core::Envelope::encode`]) in a heap-allocated [`SigilBuffer`].
//! - [`sigil_open`] — authenticate and decrypt encoded envelope bytes,
//!   returning the recovered plaintext in a heap-allocated [`SigilBuffer`].
//! - [`sigil_buffer_free`] — release a [`SigilBuffer`] produced by this library.
//!
//! *Asymmetric primitives (fixed-size output → caller-provided buffer,
//! classical-only, UNAUDITED):*
//!
//! - [`sigil_ed25519_public_key`] — derive the 32-byte Ed25519 public key from a
//!   caller-supplied 32-byte seed.
//! - [`sigil_ed25519_sign`] — 64-byte Ed25519 signature over a message.
//! - [`sigil_ed25519_verify`] — verify an Ed25519 signature (`SIGIL_OK` == valid).
//! - [`sigil_x25519_public_key`] — derive the 32-byte X25519 public key from a
//!   caller-supplied 32-byte secret scalar.
//! - [`sigil_x25519_shared_secret`] — 32-byte X25519 Diffie-Hellman shared secret.
//! - [`sigil_x25519_is_contributory`] — constant-time all-zero (low-order) check
//!   on a shared secret (a predicate: `1`/`0`, not a status code).
//!
//! ## Ownership / memory contract
//!
//! Buffers returned via the `out` parameter of [`sigil_seal`] / [`sigil_open`]
//! are heap-allocated **by this library** and remain owned by it until the
//! caller hands them back to [`sigil_buffer_free`]. The caller MUST free every
//! buffer it receives with [`sigil_buffer_free`], exactly once, and MUST NOT
//! free the `data` pointer with any other allocator (e.g. C `free`). The
//! `SigilBuffer` struct itself is a plain value owned by the caller; only the
//! heap slice it points at is reclaimed by [`sigil_buffer_free`].
//!
//! The **asymmetric primitives** ([`sigil_ed25519_public_key`] /
//! [`sigil_ed25519_sign`] / [`sigil_ed25519_verify`] / [`sigil_x25519_public_key`]
//! / [`sigil_x25519_shared_secret`] / [`sigil_x25519_is_contributory`]) use a
//! **different, simpler contract**: their outputs are a fixed size (32 or 64
//! bytes), so they write into a **caller-allocated** output array and return a
//! status code. They **never heap-allocate**, so there is no [`SigilBuffer`] and
//! nothing to free. Because each input is copied into a local array before any
//! output is written, an output buffer may safely overlap an input buffer, and on
//! any error path the output array is left untouched.
//!
//! ## Caller responsibilities (pre-audit caveats)
//!
//! - **Nonce uniqueness is the caller's job.** This layer never generates
//!   randomness; the caller MUST ensure a `(master_key, nonce)` pair is never
//!   reused. Nonce reuse is catastrophic for any Poly1305-based AEAD.
//! - The master key and nonce are read from raw pointers and copied into
//!   fixed-size arrays before use; the caller must guarantee they point at at
//!   least 32 and 24 readable bytes respectively.
//! - On any authentication or decode failure, [`sigil_open`] returns
//!   [`SIGIL_ERR_OPEN`] and never writes plaintext.
#![deny(unsafe_op_in_unsafe_fn)]

use core::slice;
use sigil_core::{
    is_contributory, open, public_key_from_seed, seal, sign, verify, x25519_public_key,
    x25519_shared_secret, AlgorithmSuite, Envelope, KEX_PUBLIC_KEY_LEN, KEX_SECRET_LEN,
    KEX_SHARED_SECRET_LEN, KEY_LEN, NONCE_LEN, SIGNATURE_LEN, SIG_PUBLIC_KEY_LEN, SIG_SEED_LEN,
};

/// Success: the operation completed and (for seal/open) `*out` was written.
pub const SIGIL_OK: i32 = 0;
/// A required pointer argument was null (or a non-null length paired with a
/// null pointer where that is not allowed).
pub const SIGIL_ERR_NULL_ARG: i32 = -1;
/// Authentication or envelope decode failed on [`sigil_open`]. No plaintext is
/// produced. This is deliberately a single code so callers cannot distinguish
/// "wrong key/tampered" from "malformed envelope" beyond what is necessary.
pub const SIGIL_ERR_OPEN: i32 = -2;
/// Malformed input that is not an authentication failure (reserved for input
/// shape problems detected before the crypto step, e.g. a length that cannot be
/// represented). [`sigil_open`] maps envelope-codec failures to
/// [`SIGIL_ERR_OPEN`] so as not to leak structure; this code is currently
/// returned only for input-shape problems.
pub const SIGIL_ERR_BAD_INPUT: i32 = -3;
/// Ed25519 verification failed on [`sigil_ed25519_verify`]: a malformed public
/// key, a malformed signature, or a well-formed-but-non-matching signature.
/// Deliberately a **single** code — [`sigil_core::SigError`]'s `BadPublicKey`,
/// `BadSignature`, and `Verification` variants all collapse here so the boundary
/// never leaks which check failed (mirroring how [`sigil_open`] collapses to
/// [`SIGIL_ERR_OPEN`]). Kept distinct from [`SIGIL_ERR_OPEN`] so callers never
/// conflate the signature boundary with the AEAD open boundary.
pub const SIGIL_ERR_VERIFY: i32 = -4;

/// A heap buffer owned by libsigil until released with [`sigil_buffer_free`].
///
/// `data` points at `len` bytes allocated by this library. A `{data: null,
/// len: 0}` value is the canonical empty/freed buffer and is safe to pass to
/// [`sigil_buffer_free`].
#[repr(C)]
pub struct SigilBuffer {
    /// Pointer to `len` heap bytes owned by libsigil, or null for the empty
    /// buffer.
    pub data: *mut u8,
    /// Length, in bytes, of the region `data` points at.
    pub len: usize,
}

impl SigilBuffer {
    /// The canonical empty buffer.
    const EMPTY: SigilBuffer = SigilBuffer {
        data: core::ptr::null_mut(),
        len: 0,
    };

    /// Take ownership of `bytes` and expose it as a `SigilBuffer`. The returned
    /// buffer must eventually be released by [`sigil_buffer_free`].
    fn from_vec(bytes: Vec<u8>) -> SigilBuffer {
        if bytes.is_empty() {
            // An empty Vec has a dangling, non-allocating pointer; normalise it
            // to the canonical empty buffer so free is a clean no-op.
            return SigilBuffer::EMPTY;
        }
        let boxed: Box<[u8]> = bytes.into_boxed_slice();
        let len = boxed.len();
        let ptr = Box::into_raw(boxed) as *mut u8;
        SigilBuffer { data: ptr, len }
    }
}

/// Returns the current algorithm-suite byte (`0x12`, hybrid post-quantum-ready).
///
/// Stable C symbol: `sigil_current_suite`. This exists so every client binding
/// can verify it links and calls into `libsigil` correctly.
#[no_mangle]
pub extern "C" fn sigil_current_suite() -> u8 {
    AlgorithmSuite::CURRENT.as_byte()
}

/// Build a read-only slice from a `(ptr, len)` pair, allowing a null pointer
/// only when `len == 0` (in which case an empty slice is returned).
///
/// Returns `None` when `ptr` is null but `len != 0`, which the caller maps to
/// [`SIGIL_ERR_NULL_ARG`].
///
/// # Safety
/// If `len != 0`, `ptr` must be non-null and point at at least `len` readable,
/// initialised bytes that stay valid for the duration of the call.
unsafe fn optional_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        Some(&[])
    } else if ptr.is_null() {
        None
    } else {
        // SAFETY: `len != 0` and `ptr` is non-null; the caller guarantees it
        // points at `len` readable, initialised bytes valid for the call.
        Some(unsafe { slice::from_raw_parts(ptr, len) })
    }
}

/// Encrypt `plaintext` under `master_key` (32 bytes) with `nonce` (24 bytes)
/// and `aad`, writing the **encoded envelope bytes** into a freshly
/// heap-allocated [`SigilBuffer`] via `*out`.
///
/// STATUS: pre-audit, unaudited building block. The caller MUST ensure the
/// `(master_key, nonce)` pair is never reused (see the crate docs) and MUST
/// release the produced buffer with [`sigil_buffer_free`].
///
/// `aad` / `plaintext` may be null **iff** their corresponding length is `0`
/// (an empty slice is used in that case). `master_key`, `nonce`, and `out`
/// must be non-null.
///
/// # Returns
/// - [`SIGIL_OK`] on success (`*out` is written).
/// - [`SIGIL_ERR_NULL_ARG`] if a required pointer is null or a non-zero length
///   is paired with a null `aad`/`plaintext` pointer. `*out` is left untouched.
///
/// # Safety
/// `master_key` must point at 32 readable bytes and `nonce` at 24 readable
/// bytes. `aad`/`plaintext` must point at `aad_len`/`plaintext_len` readable
/// bytes when those lengths are non-zero. `out` must point at a writable,
/// properly aligned [`SigilBuffer`].
#[no_mangle]
pub unsafe extern "C" fn sigil_seal(
    master_key: *const u8,
    nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    out: *mut SigilBuffer,
) -> i32 {
    if master_key.is_null() || nonce.is_null() || out.is_null() {
        return SIGIL_ERR_NULL_ARG;
    }

    // SAFETY: `aad`/`plaintext` are allowed to be null iff their len is 0; this
    // helper enforces that and only dereferences for non-zero lengths.
    let aad_slice = match unsafe { optional_slice(aad, aad_len) } {
        Some(s) => s,
        None => return SIGIL_ERR_NULL_ARG,
    };
    let plaintext_slice = match unsafe { optional_slice(plaintext, plaintext_len) } {
        Some(s) => s,
        None => return SIGIL_ERR_NULL_ARG,
    };

    // Copy the fixed-size key/nonce out of the raw pointers before calling core.
    let mut key = [0u8; KEY_LEN];
    let mut n = [0u8; NONCE_LEN];
    // SAFETY: both pointers are non-null (checked above) and the caller
    // guarantees they point at KEY_LEN / NONCE_LEN readable bytes.
    unsafe {
        key.copy_from_slice(slice::from_raw_parts(master_key, KEY_LEN));
        n.copy_from_slice(slice::from_raw_parts(nonce, NONCE_LEN));
    }

    let envelope = seal(&key, &n, aad_slice, plaintext_slice);
    let encoded = envelope.encode();
    let buffer = SigilBuffer::from_vec(encoded);

    // SAFETY: `out` is non-null (checked above) and the caller guarantees it
    // points at a writable, aligned SigilBuffer.
    unsafe {
        out.write(buffer);
    }
    SIGIL_OK
}

/// Decode the `envelope` bytes (as produced by [`sigil_seal`]) and
/// authenticate + decrypt them under `master_key` (32 bytes), writing the
/// recovered plaintext into a freshly heap-allocated [`SigilBuffer`] via `*out`.
///
/// STATUS: pre-audit, unaudited building block. The caller MUST release the
/// produced buffer with [`sigil_buffer_free`].
///
/// # Returns
/// - [`SIGIL_OK`] on success (`*out` is written with the plaintext, which may
///   be the empty buffer for an empty plaintext).
/// - [`SIGIL_ERR_NULL_ARG`] if `master_key`, `envelope`, or `out` is null (or
///   `envelope_len != 0` with a null `envelope`). `*out` is left untouched.
/// - [`SIGIL_ERR_OPEN`] on any envelope-decode or authentication failure. No
///   plaintext is ever written in this case.
///
/// # Safety
/// `master_key` must point at 32 readable bytes; `envelope` must point at
/// `envelope_len` readable bytes when `envelope_len != 0`. `out` must point at
/// a writable, properly aligned [`SigilBuffer`].
#[no_mangle]
pub unsafe extern "C" fn sigil_open(
    master_key: *const u8,
    envelope: *const u8,
    envelope_len: usize,
    out: *mut SigilBuffer,
) -> i32 {
    if master_key.is_null() || out.is_null() {
        return SIGIL_ERR_NULL_ARG;
    }

    // SAFETY: null `envelope` is permitted only when `envelope_len == 0`; the
    // helper enforces that. An empty input decodes to an error below, never a
    // panic.
    let envelope_slice = match unsafe { optional_slice(envelope, envelope_len) } {
        Some(s) => s,
        None => return SIGIL_ERR_NULL_ARG,
    };

    let mut key = [0u8; KEY_LEN];
    // SAFETY: `master_key` is non-null (checked above) and the caller
    // guarantees it points at KEY_LEN readable bytes.
    unsafe {
        key.copy_from_slice(slice::from_raw_parts(master_key, KEY_LEN));
    }

    // Decode then open. Both envelope-codec and authentication failures collapse
    // to SIGIL_ERR_OPEN so the boundary never leaks plaintext or fine-grained
    // structure.
    let env = match Envelope::decode(envelope_slice) {
        Ok(env) => env,
        Err(_) => return SIGIL_ERR_OPEN,
    };
    let plaintext = match open(&key, &env) {
        Ok(pt) => pt,
        Err(_) => return SIGIL_ERR_OPEN,
    };

    let buffer = SigilBuffer::from_vec(plaintext);
    // SAFETY: `out` is non-null (checked above) and the caller guarantees it
    // points at a writable, aligned SigilBuffer.
    unsafe {
        out.write(buffer);
    }
    SIGIL_OK
}

// ---- Asymmetric primitives (fixed-size, caller-provided out buffers) --------
//
// STATUS: pre-audit, UNAUDITED. These wrap `sigil-core`'s classical-only
// building blocks — Ed25519 signatures ([`sigil_core::sign`] / [`verify`]) and
// X25519 key agreement ([`sigil_core::x25519_shared_secret`]). The ML-DSA-65 /
// ML-KEM-768 post-quantum halves are NOT implemented, so these are **not**
// post-quantum and are **not** wired into any account / key-management flow.
//
// Unlike [`sigil_seal`] / [`sigil_open`], every output here is a **fixed size**
// (32 or 64 bytes), so these write into a **caller-allocated** output array and
// return a status code. They never heap-allocate: there is **no** [`SigilBuffer`]
// and **nothing** to [`sigil_buffer_free`]. All seeds/secrets are
// **caller-supplied** entropy — this layer generates no randomness (see
// [`sigil_core`]'s caller-supplied-entropy stance). Every fixed-size pointer
// argument must be non-null; `msg` may be null iff `msg_len == 0`. A null
// required pointer yields [`SIGIL_ERR_NULL_ARG`] and no output array is written.
// Because each input is copied into a local array before any output is written,
// the output buffer MAY safely overlap an input buffer.

/// Derive the 32-byte Ed25519 public key from a caller-supplied 32-byte `seed`,
/// writing it into `out_pk` (32 bytes).
///
/// STATUS: pre-audit, UNAUDITED classical building block. The seed is the
/// caller's secret; this layer generates no randomness.
///
/// # Returns
/// - [`SIGIL_OK`] on success (`out_pk` is written with 32 bytes).
/// - [`SIGIL_ERR_NULL_ARG`] if `seed` or `out_pk` is null; nothing is written.
///
/// # Safety
/// `seed` must point at 32 readable bytes and `out_pk` at 32 writable bytes.
/// `out_pk` may overlap `seed` (the seed is copied out before `out_pk` is
/// written).
#[no_mangle]
pub unsafe extern "C" fn sigil_ed25519_public_key(seed: *const u8, out_pk: *mut u8) -> i32 {
    if seed.is_null() || out_pk.is_null() {
        return SIGIL_ERR_NULL_ARG;
    }
    let mut seed_bytes = [0u8; SIG_SEED_LEN];
    // SAFETY: `seed` is non-null (checked above) and the caller guarantees it
    // points at SIG_SEED_LEN readable bytes.
    unsafe {
        seed_bytes.copy_from_slice(slice::from_raw_parts(seed, SIG_SEED_LEN));
    }
    let pk = public_key_from_seed(&seed_bytes);
    // SAFETY: `out_pk` is non-null (checked above) and the caller guarantees 32
    // writable bytes. `pk` is a fresh local, so any overlap with `seed` is
    // harmless.
    unsafe {
        core::ptr::copy_nonoverlapping(pk.as_ptr(), out_pk, SIG_PUBLIC_KEY_LEN);
    }
    SIGIL_OK
}

/// Produce a 64-byte Ed25519 signature over `msg` (`msg_len` bytes) using the
/// caller-supplied 32-byte `seed`, writing it into `out_sig` (64 bytes).
///
/// Signing is deterministic (RFC 8032). `msg` may be null iff `msg_len == 0` (an
/// empty message is signed). STATUS: pre-audit, UNAUDITED classical building
/// block.
///
/// # Returns
/// - [`SIGIL_OK`] on success (`out_sig` is written with 64 bytes).
/// - [`SIGIL_ERR_NULL_ARG`] if `seed` or `out_sig` is null, or `msg` is null with
///   `msg_len != 0`; nothing is written.
///
/// # Safety
/// `seed` must point at 32 readable bytes, `out_sig` at 64 writable bytes, and
/// `msg` at `msg_len` readable bytes when `msg_len != 0`. `out_sig` may overlap
/// the inputs (they are copied/borrowed before `out_sig` is written).
#[no_mangle]
pub unsafe extern "C" fn sigil_ed25519_sign(
    seed: *const u8,
    msg: *const u8,
    msg_len: usize,
    out_sig: *mut u8,
) -> i32 {
    if seed.is_null() || out_sig.is_null() {
        return SIGIL_ERR_NULL_ARG;
    }
    // SAFETY: `msg` may be null iff `msg_len == 0`; the helper enforces that.
    let msg_slice = match unsafe { optional_slice(msg, msg_len) } {
        Some(s) => s,
        None => return SIGIL_ERR_NULL_ARG,
    };
    let mut seed_bytes = [0u8; SIG_SEED_LEN];
    // SAFETY: `seed` is non-null (checked above); caller guarantees 32 readable
    // bytes.
    unsafe {
        seed_bytes.copy_from_slice(slice::from_raw_parts(seed, SIG_SEED_LEN));
    }
    let sig = sign(&seed_bytes, msg_slice);
    // SAFETY: `out_sig` is non-null (checked above); caller guarantees 64 writable
    // bytes. `sig` is a fresh local, so overlap with `seed`/`msg` is harmless.
    unsafe {
        core::ptr::copy_nonoverlapping(sig.as_ptr(), out_sig, SIGNATURE_LEN);
    }
    SIGIL_OK
}

/// Verify a 64-byte Ed25519 `sig` over `msg` (`msg_len` bytes) against the
/// 32-byte public key `pk`.
///
/// **`SIGIL_OK` (0) means the signature is VALID; a non-zero return means it is
/// INVALID** — the opposite of a typical C boolean. Callers MUST test
/// `rc == SIGIL_OK`, never `if (rc)`. `msg` may be null iff `msg_len == 0`.
/// STATUS: pre-audit, UNAUDITED classical building block.
///
/// # Returns
/// - [`SIGIL_OK`] if the signature is valid for this exact `pk` and `msg`.
/// - [`SIGIL_ERR_VERIFY`] if it is not valid — a malformed public key, a
///   malformed signature, or a well-formed-but-non-matching signature all
///   collapse to this one code (no structure leak).
/// - [`SIGIL_ERR_NULL_ARG`] if `pk` or `sig` is null, or `msg` is null with
///   `msg_len != 0`.
///
/// # Safety
/// `pk` must point at 32 readable bytes, `sig` at 64 readable bytes, and `msg` at
/// `msg_len` readable bytes when `msg_len != 0`.
#[no_mangle]
pub unsafe extern "C" fn sigil_ed25519_verify(
    pk: *const u8,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
) -> i32 {
    if pk.is_null() || sig.is_null() {
        return SIGIL_ERR_NULL_ARG;
    }
    // SAFETY: `msg` may be null iff `msg_len == 0`; the helper enforces that.
    let msg_slice = match unsafe { optional_slice(msg, msg_len) } {
        Some(s) => s,
        None => return SIGIL_ERR_NULL_ARG,
    };
    let mut pk_bytes = [0u8; SIG_PUBLIC_KEY_LEN];
    let mut sig_bytes = [0u8; SIGNATURE_LEN];
    // SAFETY: `pk`/`sig` are non-null (checked above); caller guarantees 32 / 64
    // readable bytes respectively.
    unsafe {
        pk_bytes.copy_from_slice(slice::from_raw_parts(pk, SIG_PUBLIC_KEY_LEN));
        sig_bytes.copy_from_slice(slice::from_raw_parts(sig, SIGNATURE_LEN));
    }
    match verify(&pk_bytes, msg_slice, &sig_bytes) {
        Ok(()) => SIGIL_OK,
        // Every SigError variant collapses to one code so the boundary never
        // reveals which check failed.
        Err(_) => SIGIL_ERR_VERIFY,
    }
}

/// Derive the 32-byte X25519 public key from a caller-supplied 32-byte secret
/// scalar `secret`, writing it into `out_pk` (32 bytes).
///
/// STATUS: pre-audit, UNAUDITED classical building block. The secret is the
/// caller's; this layer generates no randomness. X25519 clamps the scalar
/// internally.
///
/// # Returns
/// - [`SIGIL_OK`] on success (`out_pk` is written with 32 bytes).
/// - [`SIGIL_ERR_NULL_ARG`] if `secret` or `out_pk` is null; nothing is written.
///
/// # Safety
/// `secret` must point at 32 readable bytes and `out_pk` at 32 writable bytes.
/// `out_pk` may overlap `secret` (the secret is copied out first).
#[no_mangle]
pub unsafe extern "C" fn sigil_x25519_public_key(secret: *const u8, out_pk: *mut u8) -> i32 {
    if secret.is_null() || out_pk.is_null() {
        return SIGIL_ERR_NULL_ARG;
    }
    let mut secret_bytes = [0u8; KEX_SECRET_LEN];
    // SAFETY: `secret` is non-null (checked above); caller guarantees 32 readable
    // bytes.
    unsafe {
        secret_bytes.copy_from_slice(slice::from_raw_parts(secret, KEX_SECRET_LEN));
    }
    let pk = x25519_public_key(&secret_bytes);
    // SAFETY: `out_pk` is non-null (checked above); caller guarantees 32 writable
    // bytes. `pk` is a fresh local, so overlap with `secret` is harmless.
    unsafe {
        core::ptr::copy_nonoverlapping(pk.as_ptr(), out_pk, KEX_PUBLIC_KEY_LEN);
    }
    SIGIL_OK
}

/// Compute the 32-byte X25519 shared secret between the caller's 32-byte
/// `secret` scalar and a `peer_pk`, writing it into `out_ss` (32 bytes).
///
/// The raw shared secret is **not** contributory-checked and **not** hashed
/// here: a low-order `peer_pk` yields an all-zero (non-contributory) shared
/// secret and STILL returns [`SIGIL_OK`]. Callers MUST run `out_ss` through a KDF
/// and, if the protocol requires contributory behaviour, reject a
/// non-contributory result (see [`sigil_x25519_is_contributory`]). STATUS:
/// pre-audit, UNAUDITED classical building block.
///
/// # Returns
/// - [`SIGIL_OK`] on success (`out_ss` is written with 32 bytes; possibly
///   all-zero for a low-order `peer_pk`).
/// - [`SIGIL_ERR_NULL_ARG`] if any pointer is null; nothing is written.
///
/// # Safety
/// `secret` and `peer_pk` must point at 32 readable bytes each and `out_ss` at 32
/// writable bytes. `out_ss` may overlap the inputs (they are copied out first).
#[no_mangle]
pub unsafe extern "C" fn sigil_x25519_shared_secret(
    secret: *const u8,
    peer_pk: *const u8,
    out_ss: *mut u8,
) -> i32 {
    if secret.is_null() || peer_pk.is_null() || out_ss.is_null() {
        return SIGIL_ERR_NULL_ARG;
    }
    let mut secret_bytes = [0u8; KEX_SECRET_LEN];
    let mut peer_bytes = [0u8; KEX_PUBLIC_KEY_LEN];
    // SAFETY: `secret`/`peer_pk` are non-null (checked above); caller guarantees
    // 32 readable bytes each.
    unsafe {
        secret_bytes.copy_from_slice(slice::from_raw_parts(secret, KEX_SECRET_LEN));
        peer_bytes.copy_from_slice(slice::from_raw_parts(peer_pk, KEX_PUBLIC_KEY_LEN));
    }
    let ss = x25519_shared_secret(&secret_bytes, &peer_bytes);
    // SAFETY: `out_ss` is non-null (checked above); caller guarantees 32 writable
    // bytes. `ss` is a fresh local, so overlap with the inputs is harmless.
    unsafe {
        core::ptr::copy_nonoverlapping(ss.as_ptr(), out_ss, KEX_SHARED_SECRET_LEN);
    }
    SIGIL_OK
}

/// Constant-time predicate: is a 32-byte X25519 `shared_secret` *contributory*
/// (i.e. not the all-zero value a low-order peer key forces)?
///
/// This is a **predicate**, not a status code: `1` means contributory, `0` means
/// non-contributory (all-zero). Note `0` coincides numerically with [`SIGIL_OK`]
/// but here it means "non-contributory", so callers must NOT test it as
/// `rc == SIGIL_OK`. STATUS: pre-audit, UNAUDITED classical building block.
///
/// # Returns
/// - `1` if `shared_secret` has at least one non-zero byte (contributory).
/// - `0` if `shared_secret` is all-zero (non-contributory).
/// - [`SIGIL_ERR_NULL_ARG`] (`-1`) if `shared_secret` is null.
///
/// # Safety
/// `shared_secret` must point at 32 readable bytes.
#[no_mangle]
pub unsafe extern "C" fn sigil_x25519_is_contributory(shared_secret: *const u8) -> i32 {
    if shared_secret.is_null() {
        return SIGIL_ERR_NULL_ARG;
    }
    let mut ss = [0u8; KEX_SHARED_SECRET_LEN];
    // SAFETY: `shared_secret` is non-null (checked above); caller guarantees 32
    // readable bytes.
    unsafe {
        ss.copy_from_slice(slice::from_raw_parts(shared_secret, KEX_SHARED_SECRET_LEN));
    }
    i32::from(is_contributory(&ss))
}

/// Release a [`SigilBuffer`] previously produced by [`sigil_seal`] or
/// [`sigil_open`].
///
/// This is a no-op on the canonical empty buffer (`data == null` or `len ==
/// 0`). The caller still owns the `SigilBuffer` value itself (e.g. its stack
/// slot); this function reclaims only the heap slice it points at. Each
/// non-empty buffer must be freed exactly once.
///
/// # Safety
/// `buf` must be a buffer obtained from this library (or the canonical empty
/// buffer) that has not already been freed. Passing a buffer not produced by
/// this library, or freeing twice, is undefined behaviour.
#[no_mangle]
pub unsafe extern "C" fn sigil_buffer_free(buf: SigilBuffer) {
    if buf.data.is_null() || buf.len == 0 {
        return;
    }
    // SAFETY: `data`/`len` came from `SigilBuffer::from_vec`, which produced
    // them via `Box::<[u8]>::into_raw`; reconstructing the same fat pointer and
    // boxing it reclaims exactly that allocation. The null/zero cases were
    // handled above, and the caller contract forbids double-free / foreign
    // buffers.
    unsafe {
        let slice_ptr = slice::from_raw_parts_mut(buf.data, buf.len);
        drop(Box::from_raw(slice_ptr));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: [u8; KEY_LEN] = [0x42; KEY_LEN];
    const NONCE: [u8; NONCE_LEN] = [0x07; NONCE_LEN];

    #[test]
    fn current_suite_is_0x12() {
        assert_eq!(sigil_current_suite(), 0x12);
    }

    /// Seal a known plaintext+aad, then open the produced bytes back to the
    /// original plaintext. Frees both buffers.
    #[test]
    fn seal_then_open_round_trip() {
        let aad = b"record-id-42";
        let plaintext = b"top-secret recovery codes";

        let mut sealed = SigilBuffer::EMPTY;
        let rc = unsafe {
            sigil_seal(
                MASTER.as_ptr(),
                NONCE.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                &mut sealed,
            )
        };
        assert_eq!(rc, SIGIL_OK);
        assert!(!sealed.data.is_null());
        assert!(sealed.len > 0);

        let mut opened = SigilBuffer::EMPTY;
        let rc = unsafe { sigil_open(MASTER.as_ptr(), sealed.data, sealed.len, &mut opened) };
        assert_eq!(rc, SIGIL_OK);

        let recovered = unsafe { slice::from_raw_parts(opened.data, opened.len) };
        assert_eq!(recovered, plaintext);

        unsafe {
            sigil_buffer_free(sealed);
            sigil_buffer_free(opened);
        }
    }

    /// Flipping one ciphertext byte in the sealed buffer makes open fail with
    /// SIGIL_ERR_OPEN.
    #[test]
    fn tampered_ciphertext_fails_open() {
        let plaintext = b"some plaintext here";
        let mut sealed = SigilBuffer::EMPTY;
        let rc = unsafe {
            sigil_seal(
                MASTER.as_ptr(),
                NONCE.as_ptr(),
                core::ptr::null(),
                0,
                plaintext.as_ptr(),
                plaintext.len(),
                &mut sealed,
            )
        };
        assert_eq!(rc, SIGIL_OK);

        // Flip a byte near the end of the encoded envelope, which lands inside
        // the ciphertext/tag region (the header is the first few bytes).
        let bytes = unsafe { slice::from_raw_parts_mut(sealed.data, sealed.len) };
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;

        let mut opened = SigilBuffer::EMPTY;
        let rc = unsafe { sigil_open(MASTER.as_ptr(), sealed.data, sealed.len, &mut opened) };
        assert_eq!(rc, SIGIL_ERR_OPEN);

        unsafe { sigil_buffer_free(sealed) };
    }

    /// Opening truncated / garbage bytes returns an error, not a crash.
    #[test]
    fn open_garbage_returns_error_not_crash() {
        let garbage = [0xAAu8; 8];
        let mut opened = SigilBuffer::EMPTY;
        let rc = unsafe {
            sigil_open(
                MASTER.as_ptr(),
                garbage.as_ptr(),
                garbage.len(),
                &mut opened,
            )
        };
        assert!(rc == SIGIL_ERR_OPEN || rc == SIGIL_ERR_BAD_INPUT);
        // No output buffer should have been produced on the error path.
        assert!(opened.data.is_null());

        // Also exercise a truncated-but-otherwise-valid envelope.
        let mut sealed = SigilBuffer::EMPTY;
        let rc = unsafe {
            sigil_seal(
                MASTER.as_ptr(),
                NONCE.as_ptr(),
                core::ptr::null(),
                0,
                b"x".as_ptr(),
                1,
                &mut sealed,
            )
        };
        assert_eq!(rc, SIGIL_OK);
        let truncated_len = sealed.len - 2;
        let mut opened2 = SigilBuffer::EMPTY;
        let rc = unsafe { sigil_open(MASTER.as_ptr(), sealed.data, truncated_len, &mut opened2) };
        assert!(rc == SIGIL_ERR_OPEN || rc == SIGIL_ERR_BAD_INPUT);
        unsafe { sigil_buffer_free(sealed) };
    }

    /// A null required pointer yields SIGIL_ERR_NULL_ARG without touching out.
    #[test]
    fn null_args_return_null_arg() {
        // Null out.
        let rc = unsafe {
            sigil_seal(
                MASTER.as_ptr(),
                NONCE.as_ptr(),
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);

        // Null master_key.
        let mut out = SigilBuffer::EMPTY;
        let rc = unsafe {
            sigil_seal(
                core::ptr::null(),
                NONCE.as_ptr(),
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                &mut out,
            )
        };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);
        assert!(out.data.is_null());

        // Non-zero length paired with a null plaintext pointer.
        let rc = unsafe {
            sigil_seal(
                MASTER.as_ptr(),
                NONCE.as_ptr(),
                core::ptr::null(),
                0,
                core::ptr::null(),
                4,
                &mut out,
            )
        };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);
    }

    /// An empty plaintext round-trips to an empty plaintext.
    #[test]
    fn empty_plaintext_round_trips() {
        let mut sealed = SigilBuffer::EMPTY;
        let rc = unsafe {
            sigil_seal(
                MASTER.as_ptr(),
                NONCE.as_ptr(),
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                &mut sealed,
            )
        };
        assert_eq!(rc, SIGIL_OK);
        assert!(!sealed.data.is_null());

        let mut opened = SigilBuffer::EMPTY;
        let rc = unsafe { sigil_open(MASTER.as_ptr(), sealed.data, sealed.len, &mut opened) };
        assert_eq!(rc, SIGIL_OK);
        assert_eq!(opened.len, 0);
        // Empty plaintext normalises to the canonical empty buffer.
        assert!(opened.data.is_null());

        unsafe {
            sigil_buffer_free(sealed);
            sigil_buffer_free(opened);
        }
    }

    /// Freeing the canonical empty buffer does not crash.
    #[test]
    fn free_empty_buffer_is_noop() {
        unsafe {
            sigil_buffer_free(SigilBuffer::EMPTY);
            sigil_buffer_free(SigilBuffer {
                data: core::ptr::null_mut(),
                len: 0,
            });
        }
    }

    // ---- Asymmetric primitive tests (Phase 14) ----------------------------

    // RFC 8032 §7.1 Ed25519 TEST 1 (empty message) — the same vector core's
    // sig.rs asserts, driven here through the C-ABI to prove the boundary is
    // transparent.
    const RFC8032_SEED: [u8; SIG_SEED_LEN] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const RFC8032_PK: [u8; SIG_PUBLIC_KEY_LEN] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    const RFC8032_SIG: [u8; SIGNATURE_LEN] = [
        0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e, 0x82,
        0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65, 0x22, 0x49,
        0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e, 0x39, 0x70, 0x1c,
        0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24, 0x65, 0x51, 0x41, 0x43,
        0x8e, 0x7a, 0x10, 0x0b,
    ];

    // RFC 7748 §6.1 X25519 — the same vector core's kex.rs asserts.
    const X_ALICE_SECRET: [u8; KEX_SECRET_LEN] = [
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66,
        0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
        0x2c, 0x2a,
    ];
    const X_BOB_PUBLIC: [u8; KEX_PUBLIC_KEY_LEN] = [
        0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35,
        0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88,
        0x2b, 0x4f,
    ];
    const X_SHARED: [u8; KEX_SHARED_SECRET_LEN] = [
        0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f,
        0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16,
        0x17, 0x42,
    ];

    #[test]
    fn ed25519_sign_verify_round_trip() {
        let seed = [0x11u8; SIG_SEED_LEN];
        let msg = b"sigil ffi ed25519 round trip";
        let mut pk = [0u8; SIG_PUBLIC_KEY_LEN];
        let mut sig = [0u8; SIGNATURE_LEN];
        unsafe {
            assert_eq!(
                sigil_ed25519_public_key(seed.as_ptr(), pk.as_mut_ptr()),
                SIGIL_OK
            );
            assert_eq!(
                sigil_ed25519_sign(seed.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr()),
                SIGIL_OK
            );
            assert_eq!(
                sigil_ed25519_verify(pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()),
                SIGIL_OK
            );
        }
    }

    #[test]
    fn ed25519_tamper_sig_fails() {
        let seed = [0x22u8; SIG_SEED_LEN];
        let msg = b"message";
        let mut pk = [0u8; SIG_PUBLIC_KEY_LEN];
        let mut sig = [0u8; SIGNATURE_LEN];
        unsafe {
            sigil_ed25519_public_key(seed.as_ptr(), pk.as_mut_ptr());
            sigil_ed25519_sign(seed.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr());
        }
        sig[0] ^= 0x01;
        assert_eq!(
            unsafe { sigil_ed25519_verify(pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()) },
            SIGIL_ERR_VERIFY
        );
    }

    #[test]
    fn ed25519_tamper_msg_fails() {
        let seed = [0x22u8; SIG_SEED_LEN];
        let msg = b"message";
        let mut pk = [0u8; SIG_PUBLIC_KEY_LEN];
        let mut sig = [0u8; SIGNATURE_LEN];
        unsafe {
            sigil_ed25519_public_key(seed.as_ptr(), pk.as_mut_ptr());
            sigil_ed25519_sign(seed.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr());
        }
        let other = b"messagE";
        assert_eq!(
            unsafe { sigil_ed25519_verify(pk.as_ptr(), other.as_ptr(), other.len(), sig.as_ptr()) },
            SIGIL_ERR_VERIFY
        );
    }

    #[test]
    fn ed25519_wrong_key_fails() {
        let seed = [0x22u8; SIG_SEED_LEN];
        let msg = b"message";
        let mut sig = [0u8; SIGNATURE_LEN];
        let mut other_pk = [0u8; SIG_PUBLIC_KEY_LEN];
        let other_seed = [0x33u8; SIG_SEED_LEN];
        unsafe {
            sigil_ed25519_sign(seed.as_ptr(), msg.as_ptr(), msg.len(), sig.as_mut_ptr());
            sigil_ed25519_public_key(other_seed.as_ptr(), other_pk.as_mut_ptr());
            assert_eq!(
                sigil_ed25519_verify(other_pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()),
                SIGIL_ERR_VERIFY
            );
        }
    }

    #[test]
    fn ed25519_malformed_pubkey_collapses_to_verify() {
        // y-coordinate 2 does not decompress to a curve point (BadPublicKey); it
        // must collapse to SIGIL_ERR_VERIFY, not crash.
        let mut bad_pk = [0u8; SIG_PUBLIC_KEY_LEN];
        bad_pk[0] = 0x02;
        let sig = [0u8; SIGNATURE_LEN];
        let msg = b"m";
        assert_eq!(
            unsafe { sigil_ed25519_verify(bad_pk.as_ptr(), msg.as_ptr(), msg.len(), sig.as_ptr()) },
            SIGIL_ERR_VERIFY
        );
    }

    #[test]
    fn ed25519_empty_message_signs_and_verifies() {
        let mut sig = [0u8; SIGNATURE_LEN];
        unsafe {
            // msg null with len 0 is a valid empty message.
            assert_eq!(
                sigil_ed25519_sign(
                    RFC8032_SEED.as_ptr(),
                    core::ptr::null(),
                    0,
                    sig.as_mut_ptr()
                ),
                SIGIL_OK
            );
            assert_eq!(
                sigil_ed25519_verify(RFC8032_PK.as_ptr(), core::ptr::null(), 0, sig.as_ptr()),
                SIGIL_OK
            );
        }
    }

    #[test]
    fn ed25519_null_args_return_null_arg() {
        let seed = [0x01u8; SIG_SEED_LEN];
        let mut out = [0u8; SIGNATURE_LEN];
        let mut pk = [0u8; SIG_PUBLIC_KEY_LEN];
        let sig = [0u8; SIGNATURE_LEN];
        unsafe {
            assert_eq!(
                sigil_ed25519_public_key(core::ptr::null(), pk.as_mut_ptr()),
                SIGIL_ERR_NULL_ARG
            );
            assert_eq!(
                sigil_ed25519_public_key(seed.as_ptr(), core::ptr::null_mut()),
                SIGIL_ERR_NULL_ARG
            );
            assert_eq!(
                sigil_ed25519_sign(core::ptr::null(), core::ptr::null(), 0, out.as_mut_ptr()),
                SIGIL_ERR_NULL_ARG
            );
            assert_eq!(
                sigil_ed25519_sign(seed.as_ptr(), core::ptr::null(), 0, core::ptr::null_mut()),
                SIGIL_ERR_NULL_ARG
            );
            // Non-zero msg_len paired with a null msg pointer.
            assert_eq!(
                sigil_ed25519_sign(seed.as_ptr(), core::ptr::null(), 4, out.as_mut_ptr()),
                SIGIL_ERR_NULL_ARG
            );
            assert_eq!(
                sigil_ed25519_verify(core::ptr::null(), core::ptr::null(), 0, sig.as_ptr()),
                SIGIL_ERR_NULL_ARG
            );
            assert_eq!(
                sigil_ed25519_verify(pk.as_ptr(), core::ptr::null(), 0, core::ptr::null()),
                SIGIL_ERR_NULL_ARG
            );
        }
    }

    #[test]
    fn ed25519_rfc8032_test1_over_ffi() {
        // The RFC 8032 §7.1 TEST 1 vector, driven THROUGH the C-ABI.
        let mut pk = [0u8; SIG_PUBLIC_KEY_LEN];
        let mut sig = [0u8; SIGNATURE_LEN];
        unsafe {
            assert_eq!(
                sigil_ed25519_public_key(RFC8032_SEED.as_ptr(), pk.as_mut_ptr()),
                SIGIL_OK
            );
            assert_eq!(
                sigil_ed25519_sign(
                    RFC8032_SEED.as_ptr(),
                    core::ptr::null(),
                    0,
                    sig.as_mut_ptr()
                ),
                SIGIL_OK
            );
        }
        assert_eq!(pk, RFC8032_PK);
        assert_eq!(sig, RFC8032_SIG);
    }

    #[test]
    fn x25519_agreement_over_ffi() {
        let a_sec = [0x11u8; KEX_SECRET_LEN];
        let b_sec = [0x22u8; KEX_SECRET_LEN];
        let mut a_pub = [0u8; KEX_PUBLIC_KEY_LEN];
        let mut b_pub = [0u8; KEX_PUBLIC_KEY_LEN];
        let mut ss_a = [0u8; KEX_SHARED_SECRET_LEN];
        let mut ss_b = [0u8; KEX_SHARED_SECRET_LEN];
        unsafe {
            sigil_x25519_public_key(a_sec.as_ptr(), a_pub.as_mut_ptr());
            sigil_x25519_public_key(b_sec.as_ptr(), b_pub.as_mut_ptr());
            assert_eq!(
                sigil_x25519_shared_secret(a_sec.as_ptr(), b_pub.as_ptr(), ss_a.as_mut_ptr()),
                SIGIL_OK
            );
            assert_eq!(
                sigil_x25519_shared_secret(b_sec.as_ptr(), a_pub.as_ptr(), ss_b.as_mut_ptr()),
                SIGIL_OK
            );
            assert_eq!(sigil_x25519_is_contributory(ss_a.as_ptr()), 1);
        }
        assert_eq!(ss_a, ss_b);
    }

    #[test]
    fn x25519_public_key_matches_core() {
        let sec = [0x44u8; KEX_SECRET_LEN];
        let mut pk = [0u8; KEX_PUBLIC_KEY_LEN];
        unsafe {
            sigil_x25519_public_key(sec.as_ptr(), pk.as_mut_ptr());
        }
        assert_eq!(pk, x25519_public_key(&sec));
    }

    #[test]
    fn x25519_rfc7748_61_over_ffi() {
        // RFC 7748 §6.1 Alice·Bob.pub == shared, driven THROUGH the C-ABI.
        let mut ss = [0u8; KEX_SHARED_SECRET_LEN];
        assert_eq!(
            unsafe {
                sigil_x25519_shared_secret(
                    X_ALICE_SECRET.as_ptr(),
                    X_BOB_PUBLIC.as_ptr(),
                    ss.as_mut_ptr(),
                )
            },
            SIGIL_OK
        );
        assert_eq!(ss, X_SHARED);
    }

    #[test]
    fn x25519_null_args_return_null_arg() {
        let sec = [0x01u8; KEX_SECRET_LEN];
        let mut out = [0u8; KEX_SHARED_SECRET_LEN];
        unsafe {
            assert_eq!(
                sigil_x25519_public_key(core::ptr::null(), out.as_mut_ptr()),
                SIGIL_ERR_NULL_ARG
            );
            assert_eq!(
                sigil_x25519_public_key(sec.as_ptr(), core::ptr::null_mut()),
                SIGIL_ERR_NULL_ARG
            );
            assert_eq!(
                sigil_x25519_shared_secret(core::ptr::null(), sec.as_ptr(), out.as_mut_ptr()),
                SIGIL_ERR_NULL_ARG
            );
            assert_eq!(
                sigil_x25519_shared_secret(sec.as_ptr(), core::ptr::null(), out.as_mut_ptr()),
                SIGIL_ERR_NULL_ARG
            );
            assert_eq!(
                sigil_x25519_shared_secret(sec.as_ptr(), sec.as_ptr(), core::ptr::null_mut()),
                SIGIL_ERR_NULL_ARG
            );
            assert_eq!(
                sigil_x25519_is_contributory(core::ptr::null()),
                SIGIL_ERR_NULL_ARG
            );
        }
    }

    #[test]
    fn x25519_low_order_peer_is_all_zero_and_ok() {
        // A low-order peer key (u = 0) forces an all-zero shared secret; the call
        // still returns SIGIL_OK (raw primitive, no policy), and the predicate
        // reports non-contributory.
        let sec = [0x09u8; KEX_SECRET_LEN];
        let low_order = [0u8; KEX_PUBLIC_KEY_LEN];
        let mut ss = [0xffu8; KEX_SHARED_SECRET_LEN];
        assert_eq!(
            unsafe {
                sigil_x25519_shared_secret(sec.as_ptr(), low_order.as_ptr(), ss.as_mut_ptr())
            },
            SIGIL_OK
        );
        assert_eq!(ss, [0u8; KEX_SHARED_SECRET_LEN]);
        assert_eq!(unsafe { sigil_x25519_is_contributory(ss.as_ptr()) }, 0);
    }

    #[test]
    fn x25519_is_contributory_predicate() {
        let all_zero = [0u8; KEX_SHARED_SECRET_LEN];
        let mut one = [0u8; KEX_SHARED_SECRET_LEN];
        one[KEX_SHARED_SECRET_LEN - 1] = 1;
        unsafe {
            assert_eq!(sigil_x25519_is_contributory(all_zero.as_ptr()), 0);
            assert_eq!(sigil_x25519_is_contributory(one.as_ptr()), 1);
        }
    }

    #[test]
    fn status_code_values_are_stable() {
        // Regression pin: renumbering any of these silently breaks every C caller.
        assert_eq!(
            (
                SIGIL_OK,
                SIGIL_ERR_NULL_ARG,
                SIGIL_ERR_OPEN,
                SIGIL_ERR_BAD_INPUT,
                SIGIL_ERR_VERIFY
            ),
            (0, -1, -2, -3, -4)
        );
    }
}
