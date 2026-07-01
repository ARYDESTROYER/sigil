# 0011 — Fixed-size out-buffer convention for the asymmetric C-ABI

- **Status:** Accepted — 2026-07.

## Context

The `sigil-ffi` C-ABI ([`../../libsigil/ffi/`](../../libsigil/ffi/)) originally
exposed only the symmetric AEAD (`sigil_seal` / `sigil_open`) plus
`sigil_buffer_free` and `sigil_current_suite`. `seal`/`open` return outputs whose
length the caller cannot predict (an encoded envelope; a recovered plaintext), so
they hand back a **heap-allocated `SigilBuffer {data, len}`** that the caller must
release with `sigil_buffer_free`. That heap+free ownership dance exists **because**
the output size is variable.

Phase 14 exposes the classical asymmetric primitives from `sigil-core` over the
same C-ABI so the native clients (separate repos) can use them: Ed25519
`public_key_from_seed` / `sign` / `verify` and X25519 `x25519_public_key` /
`x25519_shared_secret` / `is_contributory`. Every one of these has a **fixed-size
output** — 32 or 64 bytes — known at compile time. Reusing `SigilBuffer` for them
would force a heap allocation and a mandatory `sigil_buffer_free` on what is a
signing/keygen hot path, and would imply an ownership transfer that isn't there.

## Decision

Adopt a **second FFI calling convention** for fixed-size outputs, coexisting with
(not replacing) the `SigilBuffer` convention, selected purely by output shape:

- **Caller-allocated fixed-size out buffers.** Each function writes its result
  into a caller-provided array (`out_pk[32]`, `out_sig[64]`, `out_ss[32]`) and
  returns an `int32_t` status. These functions **never heap-allocate**: there is
  no `SigilBuffer` and nothing to `sigil_buffer_free`. `SigilBuffer` and
  `sigil_buffer_free` stay untouched, exclusively for `seal`/`open`.
- **Guard-first, copy-first, alias-safe.** All required non-null pointers are
  checked before any output is written (on error the out array is untouched); each
  fixed input is copied into a local array before the output is written, so an out
  buffer may safely overlap an input. Variable-length `msg` reuses the existing
  `optional_slice` helper (null iff `len == 0`).
- **One new status code, `SIGIL_ERR_VERIFY = -4`.** `sigil_ed25519_verify`
  returns `SIGIL_OK` (0) for a valid signature and collapses **all**
  `SigError` variants (`BadPublicKey`, `BadSignature`, `Verification`) into the
  single `SIGIL_ERR_VERIFY`, so the boundary never leaks *which* check failed —
  the same no-structure-leak stance `sigil_open` takes with `SIGIL_ERR_OPEN`, but
  a distinct code so the two crypto boundaries are never conflated. `0 == valid`
  is documented loudly (it is the opposite of a C bool).
- **Algorithm-qualified names** (`sigil_ed25519_*`, `sigil_x25519_*`) so the
  future ML-DSA-65 / ML-KEM-768 siblings slot in without collision, and bare
  `sigil_sign` / `sigil_verify` stay reserved for a possible future
  suite-dispatched hybrid wrapper.
- **`sigil_x25519_is_contributory` is a predicate, not a status code** (`1` =
  contributory, `0` = all-zero, `-1` = null): the raw shared secret is returned
  as-is (an all-zero low-order result still returns `SIGIL_OK`), leaving the
  contributory policy to the caller, consistent with the core primitive
  ([ADR 0010](0010-x25519-key-agreement-primitive.md)).
- **No RNG in the FFI.** The seed/secret *is* the private key and the host CSPRNG
  supplies it ([ADR 0007](0007-caller-supplied-entropy-in-core.md)); no keygen
  helper is added, so `getrandom` stays out of the core/ffi lockfile.

## Consequences

- The signing/keygen/DH path is **allocation-free and free-free**: no
  `sigil_buffer_free`, no leak/double-free footgun, one status code to check.
- **Two conventions in one header** — reviewers/callers must know which applies:
  variable-size AEAD → `SigilBuffer` + `sigil_buffer_free`; fixed-size asymmetric
  → caller out-buffer, nothing to free. Both `sigil.h` and the crate docs state
  the split explicitly.
- The header stays **hand-synced** (no cbindgen): a symbol-parity check
  (`extern "C" fn` names in `lib.rs` == prototype names in `sigil.h`; `SIGIL_*`
  codes match) is the mechanical guard.
- **Honest labeling preserved.** These are classical-only, UNAUDITED building
  blocks; the PQ halves are unimplemented and nothing is wired into a product
  flow. `#![deny(unsafe_op_in_unsafe_fn)]`, per-block `// SAFETY:` notes, and
  `# Safety` doc sections carry over to every new export; `core`'s
  `#![forbid(unsafe_code)]` and the `getrandom`-count-0 / wasm invariants are
  unaffected (the FFI added no dependency).
