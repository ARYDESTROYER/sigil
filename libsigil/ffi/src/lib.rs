//! C-ABI surface for libsigil.
//!
//! STATUS: pre-audit skeleton. The only export today is a smoke-test that
//! returns the current algorithm-suite byte, proving the FFI boundary and the
//! `cbindgen`-generated header pipeline work end-to-end before any real
//! cryptographic functions are added.
#![deny(unsafe_op_in_unsafe_fn)]

use sigil_core::AlgorithmSuite;

/// Returns the current algorithm-suite byte (`0x12`, hybrid post-quantum).
///
/// Stable C symbol: `sigil_current_suite`. This exists so every client binding
/// can verify it links and calls into `libsigil` correctly.
#[no_mangle]
pub extern "C" fn sigil_current_suite() -> u8 {
    AlgorithmSuite::CURRENT.as_byte()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_suite_is_0x12() {
        assert_eq!(sigil_current_suite(), 0x12);
    }
}
