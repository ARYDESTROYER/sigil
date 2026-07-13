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
//! - [`sigil_current_suite`] — link/smoke check: returns the current
//!   algorithm-suite byte.
//! - [`sigil_seal`] — encrypt a plaintext under a caller-supplied master key
//!   and nonce, returning the **encoded envelope bytes**
//!   ([`sigil_core::Envelope::encode`]) in a heap-allocated [`SigilBuffer`].
//! - [`sigil_open`] — authenticate and decrypt encoded envelope bytes,
//!   returning the recovered plaintext in a heap-allocated [`SigilBuffer`].
//! - [`sigil_buffer_free`] — release a [`SigilBuffer`] produced by this library.
//! - [`sigil_public_key_from_seed`] / [`sigil_sign`] / [`sigil_verify`] — the
//!   classical **Ed25519** signature primitive (derive public key, sign,
//!   verify) over the C-ABI. These produce **fixed-size** outputs into
//!   caller-provided buffers, so — unlike seal/open — there is no heap
//!   [`SigilBuffer`] and nothing to free. This is the classical half of the
//!   future Ed25519 & ML-DSA-65 hybrid; the post-quantum ML-DSA-65 half is
//!   **not** implemented here. Raw signature primitive, UNAUDITED, and not an
//!   enrollment / multi-device / key-rotation system.
//! - [`sigil_x25519_public_key`] / [`sigil_ml_kem768_keygen`] — derive a hybrid
//!   identity's public halves (an X25519 public key from a secret scalar; an
//!   ML-KEM-768 `(encaps, decaps)` key pair from a 64-byte seed). Fixed-size
//!   caller buffers, no heap.
//! - [`sigil_hybrid_encapsulate`] / [`sigil_hybrid_decapsulate`] — the two sides
//!   of the hybrid KEM (X25519 + ML-KEM-768 combined via HKDF-SHA256 into one
//!   32-byte secret). Fixed-size caller buffers, no heap.
//! - [`sigil_hybrid_seal`] / [`sigil_hybrid_open`] — encrypt **to** a
//!   recipient's hybrid public key and decrypt with the matching hybrid secret
//!   key. This is a **custom KEM-then-AEAD** construction (hybrid KEM →
//!   XChaCha20-Poly1305 envelope) — it is **NOT** RFC 9180 HPKE. `seal` writes
//!   the fixed-size ephemeral X25519 public key and ML-KEM-768 ciphertext into
//!   caller buffers and the variable-length envelope into a heap
//!   [`SigilBuffer`]; `open` writes the recovered plaintext into a heap
//!   [`SigilBuffer`]. UNAUDITED building blocks, not a finished secure system.
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
    hybrid_decapsulate, hybrid_encapsulate, hybrid_open, hybrid_seal, ml_kem768_keygen, open, seal,
    x25519_public_key, AlgorithmSuite, Envelope, KEY_LEN, ML_KEM768_CIPHERTEXT_LEN,
    ML_KEM768_DECAPS_KEY_LEN, ML_KEM768_ENCAPS_COIN_LEN, ML_KEM768_ENCAPS_KEY_LEN,
    ML_KEM768_KEYGEN_SEED_LEN, NONCE_LEN, SIGNATURE_LEN, SIG_PUBLIC_KEY_LEN, SIG_SEED_LEN,
    X25519_PUBLIC_KEY_LEN, X25519_SECRET_KEY_LEN,
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
/// The Ed25519 signature did not verify (returned by [`sigil_verify`]). Every
/// verification-path failure from `sigil-core` — an invalid public-key point, a
/// structurally malformed signature, or a well-formed signature that simply
/// does not verify — collapses to this single code so the boundary does not
/// distinguish those cases.
pub const SIGIL_ERR_VERIFY: i32 = -4;
/// A hybrid KEM / key-agreement failure on the encapsulate / decapsulate / seal
/// path — for example a **non-contributory** (all-zero / low-order) X25519
/// public key (RFC 7748 §6.1) that the classical half rejects. Returned by
/// [`sigil_hybrid_encapsulate`], [`sigil_hybrid_decapsulate`], and
/// [`sigil_hybrid_seal`]. The decrypt path [`sigil_hybrid_open`] does **not**
/// use this code: every failure there collapses to [`SIGIL_ERR_OPEN`] so the
/// boundary never leaks which stage failed.
pub const SIGIL_ERR_HYBRID: i32 = -5;

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

/// Copy `N` bytes from a non-null raw pointer into a fresh fixed-size array.
///
/// The many hybrid entry points each read several fixed-size key/ciphertext
/// buffers out of raw pointers before handing them to `sigil-core`; this
/// centralises that "copy exactly `N` bytes into a `[u8; N]`" step (the same
/// pattern [`sigil_seal`] uses inline for its key/nonce).
///
/// # Safety
/// `ptr` must be non-null and point at at least `N` readable, initialised bytes
/// that stay valid for the duration of the call.
unsafe fn copy_fixed<const N: usize>(ptr: *const u8) -> [u8; N] {
    let mut buf = [0u8; N];
    // SAFETY: the caller guarantees `ptr` is non-null and points at `N`
    // readable, initialised bytes valid for the call.
    unsafe {
        buf.copy_from_slice(slice::from_raw_parts(ptr, N));
    }
    buf
}

/// Write a fixed-size array into a non-null raw output pointer.
///
/// The counterpart to [`copy_fixed`] for the fixed-size `out_*` parameters of
/// the hybrid entry points.
///
/// # Safety
/// `ptr` must be non-null and point at at least `N` writable, properly aligned
/// bytes that stay valid for the duration of the call.
unsafe fn write_fixed<const N: usize>(ptr: *mut u8, src: &[u8; N]) {
    // SAFETY: the caller guarantees `ptr` is non-null and points at `N`
    // writable, aligned bytes valid for the call.
    unsafe {
        slice::from_raw_parts_mut(ptr, N).copy_from_slice(src);
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

// ---------------------------------------------------------------------------
// Ed25519 signature primitive (classical half of the future Ed25519 & ML-DSA-65
// hybrid).
//
// STATUS: pre-audit, UNAUDITED. These wrap `sigil-core`'s classical Ed25519
// sign/verify across the C-ABI so a native client can derive a device public
// key, sign a message, and verify a signature. The signatures are plain
// Ed25519 (RFC 8032); the post-quantum ML-DSA-65 half is future work and is NOT
// present here. This is a raw signature primitive, not an enrollment /
// multi-device / key-rotation system.
//
// Unlike seal/open these produce FIXED-SIZE outputs, so there is no heap
// `SigilBuffer` and nothing to free: the caller provides the output buffers
// (32-byte public key, 64-byte signature) and owns them.
// ---------------------------------------------------------------------------

/// Derive the 32-byte Ed25519 public key from the caller-supplied 32-byte
/// secret `seed`, writing it into `out_public_key`.
///
/// STATUS: pre-audit, unaudited building block. Classical Ed25519 only (the
/// ML-DSA-65 post-quantum half is future work). Deterministic and RNG-free: the
/// `seed` is the caller's secret and is never generated here.
///
/// # Returns
/// - [`SIGIL_OK`] on success (`out_public_key` written with
///   [`SIG_PUBLIC_KEY_LEN`] bytes).
/// - [`SIGIL_ERR_NULL_ARG`] if `seed` or `out_public_key` is null;
///   `out_public_key` is left untouched.
///
/// # Safety
/// `seed` must point at [`SIG_SEED_LEN`] (32) readable bytes and
/// `out_public_key` at [`SIG_PUBLIC_KEY_LEN`] (32) writable bytes. Both buffers
/// are owned by the caller and must stay valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn sigil_public_key_from_seed(
    seed: *const u8,
    out_public_key: *mut u8,
) -> i32 {
    if seed.is_null() || out_public_key.is_null() {
        return SIGIL_ERR_NULL_ARG;
    }

    let mut seed_bytes = [0u8; SIG_SEED_LEN];
    // SAFETY: `seed` is non-null (checked above) and the caller guarantees it
    // points at SIG_SEED_LEN readable bytes.
    unsafe {
        seed_bytes.copy_from_slice(slice::from_raw_parts(seed, SIG_SEED_LEN));
    }

    let public_key = sigil_core::public_key_from_seed(&seed_bytes);

    // SAFETY: `out_public_key` is non-null (checked above) and the caller
    // guarantees it points at SIG_PUBLIC_KEY_LEN writable bytes.
    unsafe {
        slice::from_raw_parts_mut(out_public_key, SIG_PUBLIC_KEY_LEN).copy_from_slice(&public_key);
    }
    SIGIL_OK
}

/// Produce a 64-byte Ed25519 signature over `message` using the caller-supplied
/// 32-byte secret `seed`, writing it into `out_signature`.
///
/// STATUS: pre-audit, unaudited building block. Classical Ed25519 only (RFC
/// 8032; signing is deterministic, so no randomness is drawn). The ML-DSA-65
/// post-quantum half is future work.
///
/// `message` may be null **iff** `message_len == 0` (an empty message is signed
/// in that case). `seed` and `out_signature` must be non-null.
///
/// # Returns
/// - [`SIGIL_OK`] on success (`out_signature` written with [`SIGNATURE_LEN`]
///   bytes).
/// - [`SIGIL_ERR_NULL_ARG`] if `seed` or `out_signature` is null, or
///   `message_len != 0` is paired with a null `message`; `out_signature` is
///   left untouched.
///
/// # Safety
/// `seed` must point at [`SIG_SEED_LEN`] (32) readable bytes and
/// `out_signature` at [`SIGNATURE_LEN`] (64) writable bytes. `message` must
/// point at `message_len` readable bytes when `message_len != 0`. All buffers
/// are owned by the caller and must stay valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn sigil_sign(
    seed: *const u8,
    message: *const u8,
    message_len: usize,
    out_signature: *mut u8,
) -> i32 {
    if seed.is_null() || out_signature.is_null() {
        return SIGIL_ERR_NULL_ARG;
    }

    // SAFETY: `message` is allowed to be null iff `message_len == 0`; this
    // helper enforces that and only dereferences for non-zero lengths.
    let message_slice = match unsafe { optional_slice(message, message_len) } {
        Some(s) => s,
        None => return SIGIL_ERR_NULL_ARG,
    };

    let mut seed_bytes = [0u8; SIG_SEED_LEN];
    // SAFETY: `seed` is non-null (checked above) and the caller guarantees it
    // points at SIG_SEED_LEN readable bytes.
    unsafe {
        seed_bytes.copy_from_slice(slice::from_raw_parts(seed, SIG_SEED_LEN));
    }

    let signature = sigil_core::sign(&seed_bytes, message_slice);

    // SAFETY: `out_signature` is non-null (checked above) and the caller
    // guarantees it points at SIGNATURE_LEN writable bytes.
    unsafe {
        slice::from_raw_parts_mut(out_signature, SIGNATURE_LEN).copy_from_slice(&signature);
    }
    SIGIL_OK
}

/// Strictly verify a 64-byte Ed25519 `signature` over `message` against the
/// 32-byte `public_key`.
///
/// STATUS: pre-audit, unaudited building block. Classical Ed25519 only; strict
/// verification rejects non-canonical encodings and small-order keys. The
/// ML-DSA-65 post-quantum half is future work.
///
/// `message` may be null **iff** `message_len == 0`. `public_key` and
/// `signature` must be non-null.
///
/// # Returns
/// - [`SIGIL_OK`] if the signature is valid for this exact public key and
///   message.
/// - [`SIGIL_ERR_VERIFY`] if it does not verify. An invalid public-key point, a
///   malformed signature, and a well-formed signature that does not verify all
///   collapse to this single code.
/// - [`SIGIL_ERR_NULL_ARG`] if `public_key` or `signature` is null, or
///   `message_len != 0` is paired with a null `message`.
///
/// # Safety
/// `public_key` must point at [`SIG_PUBLIC_KEY_LEN`] (32) readable bytes and
/// `signature` at [`SIGNATURE_LEN`] (64) readable bytes. `message` must point
/// at `message_len` readable bytes when `message_len != 0`. All buffers are
/// owned by the caller and must stay valid for the duration of the call.
#[no_mangle]
pub unsafe extern "C" fn sigil_verify(
    public_key: *const u8,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
) -> i32 {
    if public_key.is_null() || signature.is_null() {
        return SIGIL_ERR_NULL_ARG;
    }

    // SAFETY: `message` is allowed to be null iff `message_len == 0`; this
    // helper enforces that and only dereferences for non-zero lengths.
    let message_slice = match unsafe { optional_slice(message, message_len) } {
        Some(s) => s,
        None => return SIGIL_ERR_NULL_ARG,
    };

    let mut public_key_bytes = [0u8; SIG_PUBLIC_KEY_LEN];
    let mut signature_bytes = [0u8; SIGNATURE_LEN];
    // SAFETY: both pointers are non-null (checked above) and the caller
    // guarantees they point at SIG_PUBLIC_KEY_LEN / SIGNATURE_LEN readable
    // bytes.
    unsafe {
        public_key_bytes.copy_from_slice(slice::from_raw_parts(public_key, SIG_PUBLIC_KEY_LEN));
        signature_bytes.copy_from_slice(slice::from_raw_parts(signature, SIGNATURE_LEN));
    }

    match sigil_core::verify(&public_key_bytes, message_slice, &signature_bytes) {
        Ok(()) => SIGIL_OK,
        Err(_) => SIGIL_ERR_VERIFY,
    }
}

// ---------------------------------------------------------------------------
// Hybrid encryption path (X25519 + ML-KEM-768 KEM, then XChaCha20-Poly1305).
//
// STATUS: pre-audit, UNAUDITED. These wrap `sigil-core`'s hybrid key-agreement
// and encrypt-to-recipient layer across the C-ABI so a native client can build
// a hybrid identity (an X25519 key pair + an ML-KEM-768 key pair) and encrypt a
// message to a recipient's hybrid PUBLIC key, recoverable only with the
// matching hybrid SECRET key.
//
// This is a **custom KEM-then-AEAD** construction — the hybrid KEM derives a
// fresh 32-byte secret (combining X25519 and ML-KEM-768 via HKDF-SHA256), which
// keys the existing XChaCha20-Poly1305 + HKDF envelope. It is **NOT** RFC 9180
// HPKE, and "post-quantum" names only the ML-KEM-768 component algorithm; the
// construction is unaudited and the system is not "post-quantum secure".
//
// Caller responsibilities (this layer draws NO randomness): the ephemeral
// X25519 secret, the ML-KEM-768 encapsulation coin, the ML-KEM keygen seed, and
// the AEAD nonce are ALL supplied by the caller and MUST come fresh, per call,
// from a CSPRNG. Reusing an ephemeral secret + coin repeats the hybrid secret,
// and a repeated (key, nonce) pair is catastrophic for the AEAD. Secret inputs
// (X25519 secret scalars, ML-KEM decaps keys) are the caller's to protect and
// are copied out of raw pointers before use.
//
// Fixed-size outputs (public keys, KEM ciphertext, combined secret) go into
// caller-provided buffers with NOTHING to free; the variable-length envelope
// (seal) and recovered plaintext (open) come back in heap `SigilBuffer`s that
// the caller MUST release with `sigil_buffer_free`.
// ---------------------------------------------------------------------------

/// Derive the 32-byte X25519 public key from the caller-supplied 32-byte secret
/// scalar `secret`, writing it into `out_public_key`.
///
/// STATUS: pre-audit, unaudited building block. Deterministic and RNG-free (the
/// scalar is the caller's secret and is never generated here). This is one half
/// of a hybrid identity's public key; the ML-KEM-768 half comes from
/// [`sigil_ml_kem768_keygen`].
///
/// # Returns
/// - [`SIGIL_OK`] on success (`out_public_key` written with 32 bytes).
/// - [`SIGIL_ERR_NULL_ARG`] if `secret` or `out_public_key` is null;
///   `out_public_key` is left untouched.
///
/// # Safety
/// `secret` must point at 32 readable bytes and `out_public_key` at 32 writable
/// bytes. Both buffers are owned by the caller and must stay valid for the call.
#[no_mangle]
pub unsafe extern "C" fn sigil_x25519_public_key(
    secret: *const u8,
    out_public_key: *mut u8,
) -> i32 {
    if secret.is_null() || out_public_key.is_null() {
        return SIGIL_ERR_NULL_ARG;
    }

    // SAFETY: `secret` is non-null (checked above) and the caller guarantees it
    // points at X25519_SECRET_KEY_LEN readable bytes.
    let secret_bytes = unsafe { copy_fixed::<X25519_SECRET_KEY_LEN>(secret) };
    let public_key = x25519_public_key(&secret_bytes);

    // SAFETY: `out_public_key` is non-null (checked above) and the caller
    // guarantees it points at X25519_PUBLIC_KEY_LEN writable bytes.
    unsafe { write_fixed(out_public_key, &public_key) };
    SIGIL_OK
}

/// Generate an ML-KEM-768 key pair from the caller-supplied 64-byte `seed`
/// (`d ‖ z`), writing the 1184-byte encapsulation (public) key into
/// `out_encaps_key` and the 2400-byte decapsulation (secret) key into
/// `out_decaps_key`.
///
/// STATUS: pre-audit, unaudited building block. Deterministic in `seed`, which
/// the caller MUST draw fresh from a CSPRNG. This is the post-quantum half of a
/// hybrid identity; the X25519 half comes from [`sigil_x25519_public_key`].
///
/// # Returns
/// - [`SIGIL_OK`] on success (both key buffers written).
/// - [`SIGIL_ERR_NULL_ARG`] if any pointer is null; no buffer is written.
///
/// # Safety
/// `seed` must point at 64 readable bytes; `out_encaps_key` at 1184 writable
/// bytes and `out_decaps_key` at 2400 writable bytes. All buffers are owned by
/// the caller and must stay valid for the call.
#[no_mangle]
pub unsafe extern "C" fn sigil_ml_kem768_keygen(
    seed: *const u8,
    out_encaps_key: *mut u8,
    out_decaps_key: *mut u8,
) -> i32 {
    if seed.is_null() || out_encaps_key.is_null() || out_decaps_key.is_null() {
        return SIGIL_ERR_NULL_ARG;
    }

    // SAFETY: `seed` is non-null (checked above) and the caller guarantees it
    // points at ML_KEM768_KEYGEN_SEED_LEN readable bytes.
    let seed_bytes = unsafe { copy_fixed::<ML_KEM768_KEYGEN_SEED_LEN>(seed) };
    let (encaps_key, decaps_key) = ml_kem768_keygen(&seed_bytes);

    // SAFETY: both out pointers are non-null (checked above) and the caller
    // guarantees they point at the stated writable byte counts.
    unsafe {
        write_fixed(out_encaps_key, &encaps_key);
        write_fixed(out_decaps_key, &decaps_key);
    }
    SIGIL_OK
}

/// Hybrid-encapsulate a fresh 32-byte shared secret to a recipient holding the
/// hybrid public key `(recipient_x25519_pub, recipient_mlkem_encaps_key)`, using
/// a caller-supplied ephemeral X25519 secret and ML-KEM-768 coin. Writes the
/// sender's ephemeral X25519 public key, the ML-KEM-768 ciphertext, and the
/// combined 32-byte secret into the three `out_*` buffers.
///
/// STATUS: pre-audit, unaudited building block. Custom KEM combiner (not RFC
/// 9180 HPKE). The `ephemeral_x25519_secret` and `mlkem_coin` MUST be fresh,
/// per call, from a CSPRNG; this function generates no randomness.
///
/// # Returns
/// - [`SIGIL_OK`] on success (all three `out_*` buffers written).
/// - [`SIGIL_ERR_NULL_ARG`] if any pointer is null; no `out_*` buffer is written.
/// - [`SIGIL_ERR_HYBRID`] if the hybrid KEM rejects an input — notably a
///   non-contributory (all-zero / low-order) `recipient_x25519_pub`
///   (RFC 7748 §6.1). No `out_*` buffer is written.
///
/// # Safety
/// `recipient_x25519_pub` (32), `recipient_mlkem_encaps_key` (1184),
/// `ephemeral_x25519_secret` (32), and `mlkem_coin` (32) must point at that many
/// readable bytes; `out_eph_x25519_pub` (32), `out_mlkem_ct` (1088), and
/// `out_combined` (32) at that many writable bytes. All buffers are owned by the
/// caller and must stay valid for the call.
#[no_mangle]
pub unsafe extern "C" fn sigil_hybrid_encapsulate(
    recipient_x25519_pub: *const u8,
    recipient_mlkem_encaps_key: *const u8,
    ephemeral_x25519_secret: *const u8,
    mlkem_coin: *const u8,
    out_eph_x25519_pub: *mut u8,
    out_mlkem_ct: *mut u8,
    out_combined: *mut u8,
) -> i32 {
    if recipient_x25519_pub.is_null()
        || recipient_mlkem_encaps_key.is_null()
        || ephemeral_x25519_secret.is_null()
        || mlkem_coin.is_null()
        || out_eph_x25519_pub.is_null()
        || out_mlkem_ct.is_null()
        || out_combined.is_null()
    {
        return SIGIL_ERR_NULL_ARG;
    }

    // SAFETY: each pointer is non-null (checked above) and the caller guarantees
    // it points at the stated number of readable bytes.
    let recip_pub = unsafe { copy_fixed::<X25519_PUBLIC_KEY_LEN>(recipient_x25519_pub) };
    let recip_ek = unsafe { copy_fixed::<ML_KEM768_ENCAPS_KEY_LEN>(recipient_mlkem_encaps_key) };
    let eph_secret = unsafe { copy_fixed::<X25519_SECRET_KEY_LEN>(ephemeral_x25519_secret) };
    let coin = unsafe { copy_fixed::<ML_KEM768_ENCAPS_COIN_LEN>(mlkem_coin) };

    let (eph_pub, mlkem_ct, combined) =
        match hybrid_encapsulate(&recip_pub, &recip_ek, &eph_secret, &coin) {
            Ok(v) => v,
            Err(_) => return SIGIL_ERR_HYBRID,
        };

    // SAFETY: each out pointer is non-null (checked above) and the caller
    // guarantees it points at the stated number of writable bytes.
    unsafe {
        write_fixed(out_eph_x25519_pub, &eph_pub);
        write_fixed(out_mlkem_ct, &mlkem_ct);
        write_fixed(out_combined, &combined);
    }
    SIGIL_OK
}

/// Hybrid-decapsulate the combined 32-byte shared secret: the recipient uses its
/// hybrid secret key `(recipient_x25519_secret, recipient_mlkem_decaps_key)`
/// with the sender's ephemeral X25519 public key and the ML-KEM-768 ciphertext
/// to recover the same secret that [`sigil_hybrid_encapsulate`] produced, writing
/// it into `out_combined`.
///
/// STATUS: pre-audit, unaudited building block. ML-KEM-768 decapsulation is
/// **total** (FIPS 203 implicit rejection): a tampered ciphertext does not error
/// here, it yields a *different* combined secret. The X25519 half, by contrast,
/// rejects a low-order `sender_eph_x25519_pub`.
///
/// # Returns
/// - [`SIGIL_OK`] on success (`out_combined` written with 32 bytes).
/// - [`SIGIL_ERR_NULL_ARG`] if any pointer is null; `out_combined` untouched.
/// - [`SIGIL_ERR_HYBRID`] if the hybrid KEM rejects an input — notably a
///   non-contributory (all-zero / low-order) `sender_eph_x25519_pub`.
///
/// # Safety
/// `recipient_x25519_secret` (32), `recipient_mlkem_decaps_key` (2400),
/// `sender_eph_x25519_pub` (32), and `mlkem_ct` (1088) must point at that many
/// readable bytes; `out_combined` at 32 writable bytes. All buffers are owned by
/// the caller and must stay valid for the call.
#[no_mangle]
pub unsafe extern "C" fn sigil_hybrid_decapsulate(
    recipient_x25519_secret: *const u8,
    recipient_mlkem_decaps_key: *const u8,
    sender_eph_x25519_pub: *const u8,
    mlkem_ct: *const u8,
    out_combined: *mut u8,
) -> i32 {
    if recipient_x25519_secret.is_null()
        || recipient_mlkem_decaps_key.is_null()
        || sender_eph_x25519_pub.is_null()
        || mlkem_ct.is_null()
        || out_combined.is_null()
    {
        return SIGIL_ERR_NULL_ARG;
    }

    // SAFETY: each pointer is non-null (checked above) and the caller guarantees
    // it points at the stated number of readable bytes.
    let recip_secret = unsafe { copy_fixed::<X25519_SECRET_KEY_LEN>(recipient_x25519_secret) };
    let recip_dk = unsafe { copy_fixed::<ML_KEM768_DECAPS_KEY_LEN>(recipient_mlkem_decaps_key) };
    let sender_eph = unsafe { copy_fixed::<X25519_PUBLIC_KEY_LEN>(sender_eph_x25519_pub) };
    let ct = unsafe { copy_fixed::<ML_KEM768_CIPHERTEXT_LEN>(mlkem_ct) };

    let combined = match hybrid_decapsulate(&recip_secret, &recip_dk, &sender_eph, &ct) {
        Ok(v) => v,
        Err(_) => return SIGIL_ERR_HYBRID,
    };

    // SAFETY: `out_combined` is non-null (checked above) and the caller
    // guarantees it points at HYBRID_SHARED_SECRET_LEN writable bytes.
    unsafe { write_fixed(out_combined, &combined) };
    SIGIL_OK
}

/// Encrypt `plaintext` **to** a recipient's hybrid public key
/// `(recipient_x25519_pub, recipient_mlkem_encaps_key)`: establishes a fresh
/// hybrid shared secret (KEM) and seals the plaintext under it (AEAD). Writes the
/// sender's ephemeral X25519 public key and the ML-KEM-768 ciphertext into the
/// fixed-size `out_*` buffers, and the encoded envelope bytes into a freshly
/// heap-allocated [`SigilBuffer`] via `out_envelope`. All three outputs are
/// required to [`sigil_hybrid_open`] the record.
///
/// STATUS: pre-audit, unaudited building block. Custom KEM-then-AEAD (NOT RFC
/// 9180 HPKE). The `ephemeral_x25519_secret`, `mlkem_coin`, and `aead_nonce` are
/// the caller's responsibility — draw the ephemeral secret and coin fresh, per
/// call, from a CSPRNG (a repeated ephemeral secret + coin repeats the hybrid
/// secret; a repeated `(key, nonce)` is catastrophic for the AEAD). The caller
/// MUST release the produced envelope buffer with [`sigil_buffer_free`].
///
/// `aad` / `plaintext` may be null **iff** their corresponding length is `0`.
///
/// # Returns
/// - [`SIGIL_OK`] on success (both fixed `out_*` buffers and `*out_envelope`
///   written).
/// - [`SIGIL_ERR_NULL_ARG`] if a required pointer is null (or a non-zero length
///   is paired with a null `aad`/`plaintext`); no output is written.
/// - [`SIGIL_ERR_HYBRID`] if the hybrid KEM rejects an input — notably a
///   non-contributory (all-zero / low-order) `recipient_x25519_pub`. No output
///   is written.
///
/// # Safety
/// `recipient_x25519_pub` (32), `recipient_mlkem_encaps_key` (1184),
/// `ephemeral_x25519_secret` (32), `mlkem_coin` (32), and `aead_nonce` (24) must
/// point at that many readable bytes; `aad`/`plaintext` at `aad_len`/
/// `plaintext_len` readable bytes when non-zero. `out_eph_x25519_pub` (32) and
/// `out_mlkem_ct` (1088) must point at that many writable bytes; `out_envelope`
/// at a writable, properly aligned [`SigilBuffer`]. All buffers are owned by the
/// caller and must stay valid for the call.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn sigil_hybrid_seal(
    recipient_x25519_pub: *const u8,
    recipient_mlkem_encaps_key: *const u8,
    ephemeral_x25519_secret: *const u8,
    mlkem_coin: *const u8,
    aead_nonce: *const u8,
    aad: *const u8,
    aad_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    out_eph_x25519_pub: *mut u8,
    out_mlkem_ct: *mut u8,
    out_envelope: *mut SigilBuffer,
) -> i32 {
    if recipient_x25519_pub.is_null()
        || recipient_mlkem_encaps_key.is_null()
        || ephemeral_x25519_secret.is_null()
        || mlkem_coin.is_null()
        || aead_nonce.is_null()
        || out_eph_x25519_pub.is_null()
        || out_mlkem_ct.is_null()
        || out_envelope.is_null()
    {
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

    // SAFETY: each pointer is non-null (checked above) and the caller guarantees
    // it points at the stated number of readable bytes.
    let recip_pub = unsafe { copy_fixed::<X25519_PUBLIC_KEY_LEN>(recipient_x25519_pub) };
    let recip_ek = unsafe { copy_fixed::<ML_KEM768_ENCAPS_KEY_LEN>(recipient_mlkem_encaps_key) };
    let eph_secret = unsafe { copy_fixed::<X25519_SECRET_KEY_LEN>(ephemeral_x25519_secret) };
    let coin = unsafe { copy_fixed::<ML_KEM768_ENCAPS_COIN_LEN>(mlkem_coin) };
    let nonce = unsafe { copy_fixed::<NONCE_LEN>(aead_nonce) };

    let (eph_pub, mlkem_ct, envelope) = match hybrid_seal(
        &recip_pub,
        &recip_ek,
        &eph_secret,
        &coin,
        &nonce,
        aad_slice,
        plaintext_slice,
    ) {
        Ok(v) => v,
        Err(_) => return SIGIL_ERR_HYBRID,
    };

    let buffer = SigilBuffer::from_vec(envelope);
    // SAFETY: the fixed out pointers and `out_envelope` are non-null (checked
    // above) and the caller guarantees they point at the stated writable
    // bytes / a writable, aligned SigilBuffer.
    unsafe {
        write_fixed(out_eph_x25519_pub, &eph_pub);
        write_fixed(out_mlkem_ct, &mlkem_ct);
        out_envelope.write(buffer);
    }
    SIGIL_OK
}

/// Decrypt a record produced by [`sigil_hybrid_seal`] and addressed to this
/// recipient: recovers the hybrid shared secret from the recipient's hybrid
/// secret key `(recipient_x25519_secret, recipient_mlkem_decaps_key)`, the
/// sender's ephemeral X25519 public key, and the ML-KEM-768 ciphertext, then
/// opens the envelope, writing the recovered plaintext into a freshly
/// heap-allocated [`SigilBuffer`] via `out_plaintext`.
///
/// STATUS: pre-audit, unaudited building block. Custom KEM-then-AEAD (NOT RFC
/// 9180 HPKE). The AAD is carried inside and authenticated by the envelope, so
/// it is not a parameter here. The caller MUST release the produced buffer with
/// [`sigil_buffer_free`].
///
/// `envelope` may be null **iff** `envelope_len == 0`.
///
/// # Returns
/// - [`SIGIL_OK`] on success (`*out_plaintext` written; may be the empty buffer
///   for an empty plaintext).
/// - [`SIGIL_ERR_NULL_ARG`] if a required pointer is null (or `envelope_len != 0`
///   with a null `envelope`); `*out_plaintext` untouched.
/// - [`SIGIL_ERR_OPEN`] on **any** failure — a non-contributory sender ephemeral
///   key, a malformed/truncated envelope, or an authentication failure (wrong
///   recipient, tampered ciphertext / ephemeral key / KEM ciphertext) — collapse
///   to this single code so the boundary never leaks which stage failed. No
///   plaintext is ever written in this case.
///
/// # Safety
/// `recipient_x25519_secret` (32), `recipient_mlkem_decaps_key` (2400),
/// `sender_eph_x25519_pub` (32), and `mlkem_ct` (1088) must point at that many
/// readable bytes; `envelope` at `envelope_len` readable bytes when non-zero.
/// `out_plaintext` must point at a writable, properly aligned [`SigilBuffer`].
/// All buffers are owned by the caller and must stay valid for the call.
#[no_mangle]
pub unsafe extern "C" fn sigil_hybrid_open(
    recipient_x25519_secret: *const u8,
    recipient_mlkem_decaps_key: *const u8,
    sender_eph_x25519_pub: *const u8,
    mlkem_ct: *const u8,
    envelope: *const u8,
    envelope_len: usize,
    out_plaintext: *mut SigilBuffer,
) -> i32 {
    if recipient_x25519_secret.is_null()
        || recipient_mlkem_decaps_key.is_null()
        || sender_eph_x25519_pub.is_null()
        || mlkem_ct.is_null()
        || out_plaintext.is_null()
    {
        return SIGIL_ERR_NULL_ARG;
    }

    // SAFETY: null `envelope` is permitted only when `envelope_len == 0`; the
    // helper enforces that and only dereferences for non-zero lengths.
    let envelope_slice = match unsafe { optional_slice(envelope, envelope_len) } {
        Some(s) => s,
        None => return SIGIL_ERR_NULL_ARG,
    };

    // SAFETY: each pointer is non-null (checked above) and the caller guarantees
    // it points at the stated number of readable bytes.
    let recip_secret = unsafe { copy_fixed::<X25519_SECRET_KEY_LEN>(recipient_x25519_secret) };
    let recip_dk = unsafe { copy_fixed::<ML_KEM768_DECAPS_KEY_LEN>(recipient_mlkem_decaps_key) };
    let sender_eph = unsafe { copy_fixed::<X25519_PUBLIC_KEY_LEN>(sender_eph_x25519_pub) };
    let ct = unsafe { copy_fixed::<ML_KEM768_CIPHERTEXT_LEN>(mlkem_ct) };

    // Every failure — hybrid-KEM rejection, envelope decode, or authentication —
    // collapses to SIGIL_ERR_OPEN so the boundary never leaks structure or
    // plaintext.
    let plaintext = match hybrid_open(&recip_secret, &recip_dk, &sender_eph, &ct, envelope_slice) {
        Ok(pt) => pt,
        Err(_) => return SIGIL_ERR_OPEN,
    };

    let buffer = SigilBuffer::from_vec(plaintext);
    // SAFETY: `out_plaintext` is non-null (checked above) and the caller
    // guarantees it points at a writable, aligned SigilBuffer.
    unsafe { out_plaintext.write(buffer) };
    SIGIL_OK
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

    // ---- Ed25519 signature primitive (classical, unaudited) ----

    /// Derive a public key, sign a message, and verify the signature — the full
    /// FFI round-trip returns SIGIL_OK.
    #[test]
    fn sign_then_verify_round_trip() {
        let seed = [0x11u8; SIG_SEED_LEN];
        let message = b"authenticate this op-log request";

        let mut public_key = [0u8; SIG_PUBLIC_KEY_LEN];
        let rc = unsafe { sigil_public_key_from_seed(seed.as_ptr(), public_key.as_mut_ptr()) };
        assert_eq!(rc, SIGIL_OK);

        let mut signature = [0u8; SIGNATURE_LEN];
        let rc = unsafe {
            sigil_sign(
                seed.as_ptr(),
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr(),
            )
        };
        assert_eq!(rc, SIGIL_OK);

        let rc = unsafe {
            sigil_verify(
                public_key.as_ptr(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
            )
        };
        assert_eq!(rc, SIGIL_OK);
    }

    /// A signature with one flipped byte fails verification with
    /// SIGIL_ERR_VERIFY.
    #[test]
    fn tampered_signature_fails_verify() {
        let seed = [0x22u8; SIG_SEED_LEN];
        let message = b"do not tamper";

        let mut public_key = [0u8; SIG_PUBLIC_KEY_LEN];
        let rc = unsafe { sigil_public_key_from_seed(seed.as_ptr(), public_key.as_mut_ptr()) };
        assert_eq!(rc, SIGIL_OK);

        let mut signature = [0u8; SIGNATURE_LEN];
        let rc = unsafe {
            sigil_sign(
                seed.as_ptr(),
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr(),
            )
        };
        assert_eq!(rc, SIGIL_OK);
        signature[SIGNATURE_LEN - 1] ^= 0x01;

        let rc = unsafe {
            sigil_verify(
                public_key.as_ptr(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
            )
        };
        assert_eq!(rc, SIGIL_ERR_VERIFY);
    }

    /// A valid signature verified against a different public key fails with
    /// SIGIL_ERR_VERIFY.
    #[test]
    fn wrong_public_key_fails_verify() {
        let seed = [0x33u8; SIG_SEED_LEN];
        let other_seed = [0x44u8; SIG_SEED_LEN];
        let message = b"bound to one key";

        let mut signature = [0u8; SIGNATURE_LEN];
        let rc = unsafe {
            sigil_sign(
                seed.as_ptr(),
                message.as_ptr(),
                message.len(),
                signature.as_mut_ptr(),
            )
        };
        assert_eq!(rc, SIGIL_OK);

        let mut other_public_key = [0u8; SIG_PUBLIC_KEY_LEN];
        let rc = unsafe {
            sigil_public_key_from_seed(other_seed.as_ptr(), other_public_key.as_mut_ptr())
        };
        assert_eq!(rc, SIGIL_OK);

        let rc = unsafe {
            sigil_verify(
                other_public_key.as_ptr(),
                message.as_ptr(),
                message.len(),
                signature.as_ptr(),
            )
        };
        assert_eq!(rc, SIGIL_ERR_VERIFY);
    }

    /// Null required pointers on the signature functions yield
    /// SIGIL_ERR_NULL_ARG (including a non-zero length paired with a null
    /// message).
    #[test]
    fn sig_null_args_return_null_arg() {
        let seed = [0x55u8; SIG_SEED_LEN];
        let mut public_key = [0u8; SIG_PUBLIC_KEY_LEN];
        let mut signature = [0u8; SIGNATURE_LEN];

        // public_key_from_seed: null seed, then null out.
        let rc = unsafe { sigil_public_key_from_seed(core::ptr::null(), public_key.as_mut_ptr()) };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);
        let rc = unsafe { sigil_public_key_from_seed(seed.as_ptr(), core::ptr::null_mut()) };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);

        // sign: null seed, null out, and a non-zero len with a null message.
        let rc = unsafe {
            sigil_sign(
                core::ptr::null(),
                core::ptr::null(),
                0,
                signature.as_mut_ptr(),
            )
        };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);
        let rc = unsafe { sigil_sign(seed.as_ptr(), core::ptr::null(), 0, core::ptr::null_mut()) };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);
        let rc = unsafe { sigil_sign(seed.as_ptr(), core::ptr::null(), 4, signature.as_mut_ptr()) };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);

        // verify: null public_key, null signature, and a non-zero len with a
        // null message.
        let rc = unsafe { sigil_public_key_from_seed(seed.as_ptr(), public_key.as_mut_ptr()) };
        assert_eq!(rc, SIGIL_OK);
        let rc =
            unsafe { sigil_verify(core::ptr::null(), core::ptr::null(), 0, signature.as_ptr()) };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);
        let rc =
            unsafe { sigil_verify(public_key.as_ptr(), core::ptr::null(), 0, core::ptr::null()) };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);
        let rc = unsafe {
            sigil_verify(
                public_key.as_ptr(),
                core::ptr::null(),
                4,
                signature.as_ptr(),
            )
        };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);
    }

    /// An empty message (null pointer, len 0) signs and verifies through the
    /// FFI.
    #[test]
    fn empty_message_signs_and_verifies() {
        let seed = [0x66u8; SIG_SEED_LEN];

        let mut public_key = [0u8; SIG_PUBLIC_KEY_LEN];
        let rc = unsafe { sigil_public_key_from_seed(seed.as_ptr(), public_key.as_mut_ptr()) };
        assert_eq!(rc, SIGIL_OK);

        let mut signature = [0u8; SIGNATURE_LEN];
        let rc = unsafe { sigil_sign(seed.as_ptr(), core::ptr::null(), 0, signature.as_mut_ptr()) };
        assert_eq!(rc, SIGIL_OK);

        let rc = unsafe {
            sigil_verify(
                public_key.as_ptr(),
                core::ptr::null(),
                0,
                signature.as_ptr(),
            )
        };
        assert_eq!(rc, SIGIL_OK);
    }

    /// RFC 8032 §7.1, Ed25519 TEST 1 (empty message) driven THROUGH the FFI: the
    /// derived public key, the produced signature, and the verify result all
    /// match the official known-answer vector. Proves the C-ABI wraps
    /// interop-correct Ed25519, not just internal self-consistency.
    #[test]
    fn rfc8032_test1_through_ffi() {
        // SECRET KEY (32-byte seed):
        let seed: [u8; SIG_SEED_LEN] = [
            0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
            0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
            0x1c, 0xae, 0x7f, 0x60,
        ];
        // PUBLIC KEY:
        let expected_pk: [u8; SIG_PUBLIC_KEY_LEN] = [
            0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
            0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
            0xf7, 0x07, 0x51, 0x1a,
        ];
        // SIGNATURE (over the empty message):
        let expected_sig: [u8; SIGNATURE_LEN] = [
            0xe5, 0x56, 0x43, 0x00, 0xc3, 0x60, 0xac, 0x72, 0x90, 0x86, 0xe2, 0xcc, 0x80, 0x6e,
            0x82, 0x8a, 0x84, 0x87, 0x7f, 0x1e, 0xb8, 0xe5, 0xd9, 0x74, 0xd8, 0x73, 0xe0, 0x65,
            0x22, 0x49, 0x01, 0x55, 0x5f, 0xb8, 0x82, 0x15, 0x90, 0xa3, 0x3b, 0xac, 0xc6, 0x1e,
            0x39, 0x70, 0x1c, 0xf9, 0xb4, 0x6b, 0xd2, 0x5b, 0xf5, 0xf0, 0x59, 0x5b, 0xbe, 0x24,
            0x65, 0x51, 0x41, 0x43, 0x8e, 0x7a, 0x10, 0x0b,
        ];

        // Derived public key matches the vector.
        let mut public_key = [0u8; SIG_PUBLIC_KEY_LEN];
        let rc = unsafe { sigil_public_key_from_seed(seed.as_ptr(), public_key.as_mut_ptr()) };
        assert_eq!(rc, SIGIL_OK);
        assert_eq!(public_key, expected_pk, "RFC 8032 pubkey through FFI");

        // Signature over the empty message matches the vector.
        let mut signature = [0u8; SIGNATURE_LEN];
        let rc = unsafe { sigil_sign(seed.as_ptr(), core::ptr::null(), 0, signature.as_mut_ptr()) };
        assert_eq!(rc, SIGIL_OK);
        assert_eq!(signature, expected_sig, "RFC 8032 signature through FFI");

        // Verifying the known-answer vector through the FFI succeeds.
        let rc = unsafe {
            sigil_verify(
                expected_pk.as_ptr(),
                core::ptr::null(),
                0,
                expected_sig.as_ptr(),
            )
        };
        assert_eq!(rc, SIGIL_OK, "RFC 8032 verify through FFI");
    }

    // ---- Hybrid encryption path (X25519 + ML-KEM-768, custom KEM-then-AEAD) ----

    /// Deterministic `N`-byte test array from a starting byte (an arbitrary but
    /// fixed pattern; NOT a way to generate real key material).
    fn filled<const N: usize>(seed: u8) -> [u8; N] {
        let mut a = [0u8; N];
        for (i, b) in a.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        a
    }

    /// A recipient's hybrid key pair (X25519 + ML-KEM-768) built THROUGH the FFI,
    /// plus a sender's ephemeral X25519 secret, ML-KEM coin, and AEAD nonce — the
    /// fixed inputs the hybrid round-trip tests share.
    struct HybridSetup {
        r_x_secret: [u8; X25519_SECRET_KEY_LEN],
        r_x_pub: [u8; X25519_PUBLIC_KEY_LEN],
        ek: [u8; ML_KEM768_ENCAPS_KEY_LEN],
        dk: [u8; ML_KEM768_DECAPS_KEY_LEN],
        eph_secret: [u8; X25519_SECRET_KEY_LEN],
        coin: [u8; ML_KEM768_ENCAPS_COIN_LEN],
        nonce: [u8; NONCE_LEN],
    }

    fn hybrid_setup() -> HybridSetup {
        let r_x_secret = filled::<X25519_SECRET_KEY_LEN>(0x11);
        let mut r_x_pub = [0u8; X25519_PUBLIC_KEY_LEN];
        let rc = unsafe { sigil_x25519_public_key(r_x_secret.as_ptr(), r_x_pub.as_mut_ptr()) };
        assert_eq!(rc, SIGIL_OK);

        let kem_seed = filled::<ML_KEM768_KEYGEN_SEED_LEN>(0x20);
        let mut ek = [0u8; ML_KEM768_ENCAPS_KEY_LEN];
        let mut dk = [0u8; ML_KEM768_DECAPS_KEY_LEN];
        let rc =
            unsafe { sigil_ml_kem768_keygen(kem_seed.as_ptr(), ek.as_mut_ptr(), dk.as_mut_ptr()) };
        assert_eq!(rc, SIGIL_OK);

        HybridSetup {
            r_x_secret,
            r_x_pub,
            ek,
            dk,
            eph_secret: filled::<X25519_SECRET_KEY_LEN>(0x30),
            coin: filled::<ML_KEM768_ENCAPS_COIN_LEN>(0x40),
            nonce: filled::<NONCE_LEN>(0x5a),
        }
    }

    /// THE KEM CAPSTONE via the C-ABI: build the recipient's hybrid identity,
    /// encapsulate to it, decapsulate with the matching secret keys, and assert
    /// the sender and receiver arrive at the SAME 32-byte combined secret.
    #[test]
    fn hybrid_kem_round_trip_through_ffi() {
        let s = hybrid_setup();

        let mut eph_pub = [0u8; X25519_PUBLIC_KEY_LEN];
        let mut ct = [0u8; ML_KEM768_CIPHERTEXT_LEN];
        let mut combined_sender = [0u8; 32];
        let rc = unsafe {
            sigil_hybrid_encapsulate(
                s.r_x_pub.as_ptr(),
                s.ek.as_ptr(),
                s.eph_secret.as_ptr(),
                s.coin.as_ptr(),
                eph_pub.as_mut_ptr(),
                ct.as_mut_ptr(),
                combined_sender.as_mut_ptr(),
            )
        };
        assert_eq!(rc, SIGIL_OK);

        let mut combined_receiver = [0u8; 32];
        let rc = unsafe {
            sigil_hybrid_decapsulate(
                s.r_x_secret.as_ptr(),
                s.dk.as_ptr(),
                eph_pub.as_ptr(),
                ct.as_ptr(),
                combined_receiver.as_mut_ptr(),
            )
        };
        assert_eq!(rc, SIGIL_OK);
        assert_eq!(
            combined_sender, combined_receiver,
            "hybrid KEM agrees on the combined secret through the FFI"
        );
    }

    /// SEAL/OPEN round-trip via the C-ABI: encrypt to the recipient's hybrid
    /// public key, then decrypt with the matching secret keys and recover the
    /// exact plaintext. Frees both heap buffers.
    #[test]
    fn hybrid_seal_then_open_round_trip() {
        let s = hybrid_setup();
        let aad = b"vault-record-7";
        let plaintext = b"top-secret recovery codes";

        let mut eph_pub = [0u8; X25519_PUBLIC_KEY_LEN];
        let mut ct = [0u8; ML_KEM768_CIPHERTEXT_LEN];
        let mut envelope = SigilBuffer::EMPTY;
        let rc = unsafe {
            sigil_hybrid_seal(
                s.r_x_pub.as_ptr(),
                s.ek.as_ptr(),
                s.eph_secret.as_ptr(),
                s.coin.as_ptr(),
                s.nonce.as_ptr(),
                aad.as_ptr(),
                aad.len(),
                plaintext.as_ptr(),
                plaintext.len(),
                eph_pub.as_mut_ptr(),
                ct.as_mut_ptr(),
                &mut envelope,
            )
        };
        assert_eq!(rc, SIGIL_OK);
        assert!(!envelope.data.is_null());
        assert!(envelope.len > 0);

        let mut opened = SigilBuffer::EMPTY;
        let rc = unsafe {
            sigil_hybrid_open(
                s.r_x_secret.as_ptr(),
                s.dk.as_ptr(),
                eph_pub.as_ptr(),
                ct.as_ptr(),
                envelope.data,
                envelope.len,
                &mut opened,
            )
        };
        assert_eq!(rc, SIGIL_OK);
        let recovered = unsafe { slice::from_raw_parts(opened.data, opened.len) };
        assert_eq!(recovered, plaintext);

        unsafe {
            sigil_buffer_free(envelope);
            sigil_buffer_free(opened);
        }
    }

    /// Opening a record with the WRONG recipient's secret keys fails with
    /// SIGIL_ERR_OPEN and writes no plaintext buffer.
    #[test]
    fn hybrid_wrong_recipient_open_fails() {
        let s = hybrid_setup();
        let plaintext = b"only for the right recipient";

        let mut eph_pub = [0u8; X25519_PUBLIC_KEY_LEN];
        let mut ct = [0u8; ML_KEM768_CIPHERTEXT_LEN];
        let mut envelope = SigilBuffer::EMPTY;
        let rc = unsafe {
            sigil_hybrid_seal(
                s.r_x_pub.as_ptr(),
                s.ek.as_ptr(),
                s.eph_secret.as_ptr(),
                s.coin.as_ptr(),
                s.nonce.as_ptr(),
                core::ptr::null(),
                0,
                plaintext.as_ptr(),
                plaintext.len(),
                eph_pub.as_mut_ptr(),
                ct.as_mut_ptr(),
                &mut envelope,
            )
        };
        assert_eq!(rc, SIGIL_OK);

        // A DIFFERENT recipient: fresh X25519 secret and a fresh ML-KEM key pair.
        let wrong_x_secret = filled::<X25519_SECRET_KEY_LEN>(0x99);
        let wrong_seed = filled::<ML_KEM768_KEYGEN_SEED_LEN>(0x88);
        let mut wrong_ek = [0u8; ML_KEM768_ENCAPS_KEY_LEN];
        let mut wrong_dk = [0u8; ML_KEM768_DECAPS_KEY_LEN];
        let rc = unsafe {
            sigil_ml_kem768_keygen(
                wrong_seed.as_ptr(),
                wrong_ek.as_mut_ptr(),
                wrong_dk.as_mut_ptr(),
            )
        };
        assert_eq!(rc, SIGIL_OK);

        let mut opened = SigilBuffer::EMPTY;
        let rc = unsafe {
            sigil_hybrid_open(
                wrong_x_secret.as_ptr(),
                wrong_dk.as_ptr(),
                eph_pub.as_ptr(),
                ct.as_ptr(),
                envelope.data,
                envelope.len,
                &mut opened,
            )
        };
        assert_eq!(rc, SIGIL_ERR_OPEN);
        assert!(
            opened.data.is_null(),
            "no plaintext is written on the open error path"
        );

        unsafe { sigil_buffer_free(envelope) };
    }

    /// A non-contributory (all-zero / low-order) recipient X25519 public key is
    /// rejected with SIGIL_ERR_HYBRID by both encapsulate and seal, and no output
    /// is written.
    #[test]
    fn hybrid_non_contributory_recipient_pub_errors() {
        let s = hybrid_setup();
        let zero_pub = [0u8; X25519_PUBLIC_KEY_LEN];

        let mut eph_pub = [0u8; X25519_PUBLIC_KEY_LEN];
        let mut ct = [0u8; ML_KEM768_CIPHERTEXT_LEN];
        let mut combined = [0u8; 32];
        let rc = unsafe {
            sigil_hybrid_encapsulate(
                zero_pub.as_ptr(),
                s.ek.as_ptr(),
                s.eph_secret.as_ptr(),
                s.coin.as_ptr(),
                eph_pub.as_mut_ptr(),
                ct.as_mut_ptr(),
                combined.as_mut_ptr(),
            )
        };
        assert_eq!(rc, SIGIL_ERR_HYBRID);

        // The same non-contributory key is rejected by seal too.
        let mut envelope = SigilBuffer::EMPTY;
        let rc = unsafe {
            sigil_hybrid_seal(
                zero_pub.as_ptr(),
                s.ek.as_ptr(),
                s.eph_secret.as_ptr(),
                s.coin.as_ptr(),
                s.nonce.as_ptr(),
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                eph_pub.as_mut_ptr(),
                ct.as_mut_ptr(),
                &mut envelope,
            )
        };
        assert_eq!(rc, SIGIL_ERR_HYBRID);
        assert!(
            envelope.data.is_null(),
            "no envelope is written on the hybrid-error path"
        );
    }

    /// Null required pointers on each hybrid entry point yield
    /// SIGIL_ERR_NULL_ARG (including non-zero lengths paired with null
    /// aad/plaintext/envelope).
    #[test]
    fn hybrid_null_args_return_null_arg() {
        let secret = filled::<X25519_SECRET_KEY_LEN>(0x11);
        let seed = filled::<ML_KEM768_KEYGEN_SEED_LEN>(0x20);
        let mut ek = [0u8; ML_KEM768_ENCAPS_KEY_LEN];
        let dk = [0u8; ML_KEM768_DECAPS_KEY_LEN];
        let mut ct = [0u8; ML_KEM768_CIPHERTEXT_LEN];
        let mut out_eph = [0u8; X25519_PUBLIC_KEY_LEN];
        let mut out_combined = [0u8; 32];
        let mut envelope = SigilBuffer::EMPTY;
        let mut opened = SigilBuffer::EMPTY;

        // x25519_public_key: null secret, then null out.
        let rc = unsafe { sigil_x25519_public_key(core::ptr::null(), out_eph.as_mut_ptr()) };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);
        let rc = unsafe { sigil_x25519_public_key(secret.as_ptr(), core::ptr::null_mut()) };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);

        // ml_kem768_keygen: null decaps out.
        let rc = unsafe {
            sigil_ml_kem768_keygen(seed.as_ptr(), ek.as_mut_ptr(), core::ptr::null_mut())
        };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);

        // encapsulate: null recipient public key.
        let rc = unsafe {
            sigil_hybrid_encapsulate(
                core::ptr::null(),
                ek.as_ptr(),
                secret.as_ptr(),
                secret.as_ptr(),
                out_eph.as_mut_ptr(),
                ct.as_mut_ptr(),
                out_combined.as_mut_ptr(),
            )
        };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);

        // decapsulate: null out_combined.
        let rc = unsafe {
            sigil_hybrid_decapsulate(
                secret.as_ptr(),
                dk.as_ptr(),
                out_eph.as_ptr(),
                ct.as_ptr(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);

        // seal: null out_envelope, and a non-zero plaintext len with a null
        // plaintext pointer.
        let rc = unsafe {
            sigil_hybrid_seal(
                secret.as_ptr(),
                ek.as_ptr(),
                secret.as_ptr(),
                secret.as_ptr(),
                secret.as_ptr(),
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                out_eph.as_mut_ptr(),
                ct.as_mut_ptr(),
                core::ptr::null_mut(),
            )
        };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);
        let rc = unsafe {
            sigil_hybrid_seal(
                secret.as_ptr(),
                ek.as_ptr(),
                secret.as_ptr(),
                secret.as_ptr(),
                secret.as_ptr(),
                core::ptr::null(),
                0,
                core::ptr::null(),
                4,
                out_eph.as_mut_ptr(),
                ct.as_mut_ptr(),
                &mut envelope,
            )
        };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);
        assert!(envelope.data.is_null());

        // open: null out_plaintext, and a non-zero envelope len with a null
        // envelope pointer.
        let rc = unsafe {
            sigil_hybrid_open(
                secret.as_ptr(),
                dk.as_ptr(),
                out_eph.as_ptr(),
                ct.as_ptr(),
                core::ptr::null(),
                0,
                core::ptr::null_mut(),
            )
        };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);
        let rc = unsafe {
            sigil_hybrid_open(
                secret.as_ptr(),
                dk.as_ptr(),
                out_eph.as_ptr(),
                ct.as_ptr(),
                core::ptr::null(),
                8,
                &mut opened,
            )
        };
        assert_eq!(rc, SIGIL_ERR_NULL_ARG);
        assert!(opened.data.is_null());
    }

    /// An empty plaintext round-trips through hybrid seal/open to the canonical
    /// empty buffer.
    #[test]
    fn hybrid_empty_plaintext_round_trips() {
        let s = hybrid_setup();

        let mut eph_pub = [0u8; X25519_PUBLIC_KEY_LEN];
        let mut ct = [0u8; ML_KEM768_CIPHERTEXT_LEN];
        let mut envelope = SigilBuffer::EMPTY;
        let rc = unsafe {
            sigil_hybrid_seal(
                s.r_x_pub.as_ptr(),
                s.ek.as_ptr(),
                s.eph_secret.as_ptr(),
                s.coin.as_ptr(),
                s.nonce.as_ptr(),
                core::ptr::null(),
                0,
                core::ptr::null(),
                0,
                eph_pub.as_mut_ptr(),
                ct.as_mut_ptr(),
                &mut envelope,
            )
        };
        assert_eq!(rc, SIGIL_OK);
        assert!(!envelope.data.is_null());

        let mut opened = SigilBuffer::EMPTY;
        let rc = unsafe {
            sigil_hybrid_open(
                s.r_x_secret.as_ptr(),
                s.dk.as_ptr(),
                eph_pub.as_ptr(),
                ct.as_ptr(),
                envelope.data,
                envelope.len,
                &mut opened,
            )
        };
        assert_eq!(rc, SIGIL_OK);
        assert_eq!(opened.len, 0);
        assert!(
            opened.data.is_null(),
            "empty plaintext normalises to the canonical empty buffer"
        );

        unsafe {
            sigil_buffer_free(envelope);
            sigil_buffer_free(opened);
        }
    }
}
