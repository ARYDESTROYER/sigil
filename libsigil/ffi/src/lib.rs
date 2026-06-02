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
use sigil_core::{open, seal, AlgorithmSuite, Envelope, KEY_LEN, NONCE_LEN};

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
}
