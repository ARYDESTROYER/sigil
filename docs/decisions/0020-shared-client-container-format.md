# 0020 — Shared `SIGILcli` client container format (wasm ↔ CLI interop)

- **Status:** Accepted — 2026-07.

## Context

Two clients now sit over the same `sigil-core` record API: the native demo CLI
([`../../cli/`](../../cli/), [ADR 0002](0002-standalone-cli-crate-for-getrandom-isolation.md))
and the `wasm-bindgen` browser/Node binding
([`../../sigil-wasm/`](../../sigil-wasm/), [ADR 0019](0019-wasm-client-bindings.md)).
The CLI already defines a small self-describing on-disk **`SIGILcli` container** —
the raw `seal_record` envelope prefixed with the salt and the three Argon2 cost
parameters, which the envelope itself does **not** carry (`cli/src/lib.rs`):

```text
  magic[8] = "SIGILcli" | version:u8 = 1 |
  m_cost:u32 | t_cost:u32 | p_cost:u32 |   (all little-endian)
  salt_len:u8 | salt[salt_len] | envelope[..]
```

with the AEAD additional-authenticated-data fixed to the ASCII tag
`sigil-cli/1`. `sigil-core` is `no_std`, wasm-pure, and RNG-free, so both clients
already share the *cryptography*; what they did not share was the *packaging*. A
file sealed in the browser could not be opened with `sigil open`, and vice-versa,
purely because the wasm binding only exposed the bare `seal_record` /
`open_record` envelope (salt + params carried out-of-band) and had no container
codec.

We want the two clients to **interoperate** — seal in one, open in the other —
without weakening the isolation both crates depend on. The design question is
where the byte format should live so that both crates agree on it.

Two options:

1. **Extract a shared crate** that both `cli` and `sigil-wasm` depend on for the
   container codec, so there is a single definition of the bytes.
2. **Mirror the format** in each crate (a second, faithful copy of the constants
   and the pack/unpack logic in `sigil-wasm/src/lib.rs`) and pin the two copies
   together with a cross-check test.

## Decision

**Mirror the `SIGILcli` byte format and its AAD in `sigil-wasm` rather than
introduce a shared crate**, and prove parity with a test that shells to the real
CLI in both directions.

`sigil-wasm` gains two `#[wasm_bindgen]` exports —
[`seal_to_container`](../../sigil-wasm/src/lib.rs) and `open_container` — that
read and write the exact same container as the CLI. The format constants are
duplicated with an explicit sync comment: `cli/src/lib.rs` defines `MAGIC`
(`b"SIGILcli"`), `FORMAT_VERSION` (`1`), `AAD` (`b"sigil-cli/1"`), and
`FIXED_HEADER_LEN` (`22`); `sigil-wasm/src/lib.rs` mirrors them as `CLI_MAGIC`,
`CLI_FORMAT_VERSION`, `CLI_AAD`, and `CLI_FIXED_HEADER_LEN`, each carrying a
comment naming the CLI value it must equal byte-for-byte. As in the CLI, the
container is unprotected framing metadata: tampering with the header just derives
the wrong key and `open` fails to authenticate.

Why mirror instead of share:

- **This is a pre-audit demo format, not a product wire format.** Standing up a
  shared crate — a fourth Cargo unit, its own lockfile question, a versioning and
  publishing story — is real structural weight for a format we fully expect to
  replace. It would also have to be wasm-pure and RNG-free to remain linkable by
  both crates, re-litigating the isolation both ADR 0002 and ADR 0019 already
  settled per-crate.
- **The crates are already deliberately isolated.** `cli` and `sigil-wasm` each
  keep their **own** `Cargo.lock` and are **not** libsigil workspace members so
  their native/`wasm-bindgen` dependency trees never touch the audit-bound
  `libsigil/Cargo.lock`. A shared crate would create a new coupling point between
  them; mirroring keeps them independent.
- **The duplication is small and mechanically guarded.** The format is a handful
  of constants and a linear pack/unpack. Parity is enforced by two tests: a native
  golden-header test in `sigil-wasm` that asserts the emitted header byte-for-byte
  against a hand-built expected header, and a Node interop test
  ([`../../sigil-wasm/test/interop.mjs`](../../sigil-wasm/test/interop.mjs)) that
  **builds and shells to the real `sigil` binary** and drives **both** directions —
  Direction A (`sigil seal` → `wasm.open_container`) and Direction B
  (`wasm.seal_to_container` → `sigil open`). If either copy drifts, one direction
  fails.

## Consequences

- **Seal-in-browser ↔ open-with-CLI works both ways.** A `.sigil` container
  written by the browser/Node opens with `sigil open`, and one written by `sigil
  seal` opens with `open_container` — proven end-to-end against the actual CLI
  binary, not a re-implementation.
- **The format is duplicated in two crates.** `cli/src/lib.rs` and
  `sigil-wasm/src/lib.rs` each carry the constants and codec, tied together by a
  sync comment and the golden + interop tests. Anyone changing the container in one
  place **must** change the other; the tests are the tripwire. This is an accepted,
  bounded cost for avoiding a shared-crate for a throwaway format.
- **No new crate, no new lockfile coupling.** Both clients stay standalone with
  their own lockfiles; `libsigil/Cargo.lock` is untouched and both remain
  `getrandom`-count `0`.
- **It is still a pre-audit demo, not the product.** The `SIGILcli` container is a
  **CLI/demo container, not a frozen product wire format**, over the **UNAUDITED**
  symmetric `seal_record` / `open_record` building block; it is **not** the
  product's account / key-management model and must not protect real secrets. A
  future real, versioned container/wire format is a different decision and belongs
  in `sigil-core` or a purpose-built shared crate — at which point this ADR would
  be superseded.
