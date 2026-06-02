# sigil-ffi

C-ABI surface for libsigil. Pre-audit skeleton: the only export is
`sigil_current_suite()`, proving the FFI boundary and the `cbindgen` header
pipeline work before real cryptographic functions are added.
