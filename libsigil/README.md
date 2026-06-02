# libsigil

Sigil's cryptographic core (Rust workspace). Built once, shared by every client.

- `core/` — pure, `no_std`, dependency-free logic. Today: the algorithm-suite
  registry + envelope metadata. **No real cryptography yet.**
- `ffi/` — C-ABI surface (`cdylib`/`staticlib`) the native clients link against.
- `bindings/` — generated per-platform bindings (`swift`, `kotlin`, `wasm`, `node`).

Build/test commands are in the root [`CLAUDE.md`](../CLAUDE.md). The wasm target
(`wasm32-unknown-unknown`) is required and built in CI.
