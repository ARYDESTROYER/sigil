# 0021 — Hybrid public-key encryption in the wasm client (`SIGILhyb` interop)

- **Status:** Accepted — 2026-07.

## Context

The `wasm-bindgen` client binding
([`../../sigil-wasm/`](../../sigil-wasm/), [ADR 0019](0019-wasm-client-bindings.md))
already interoperates with the native demo CLI
([`../../cli/`](../../cli/), [ADR 0002](0002-standalone-cli-crate-for-getrandom-isolation.md))
on the **password** path: the `SIGILcli` container format is mirrored in both
crates so a file sealed in the browser opens with `sigil open` and vice-versa
([ADR 0020](0020-shared-client-container-format.md)).

Separately, `sigil-core` now carries a full **hybrid public-key** encryption path
— `hybrid_seal` / `hybrid_open` ([ADR 0013](0013-hybrid-public-key-seal.md)):
encrypt a record **to** a recipient's hybrid identity (**X25519 + ML-KEM-768**)
via a custom KEM-then-AEAD composition, so it survives if **either** the classical
or the post-quantum half holds. The CLI already exposes it
(`sigil hybrid-keygen` / `hybrid-seal` / `hybrid-open`, [ADR 0013] follow-on) over
a self-describing on-disk **`SIGILhyb` container** (`cli/src/lib.rs`):

```text
  magic[8] = "SIGILhyb" | version:u8 = 1 |
  eph_x25519_pub[32] | mlkem_ct[1088] | envelope[..]
```

with the AEAD additional-authenticated-data fixed to the ASCII tag
`sigil-hybrid-cli/1`. Until now that path had **only ever run natively** (CLI +
FFI). The client column — the browser — had not exercised the PQ-hybrid path at
all; the wasm binding stopped at the symmetric `SIGILcli` container.

We want the wasm client to reach the **same hybrid public-key path**, and to be
**interoperable with the CLI** on it — seal in the browser to a device's hybrid
identity and open with `sigil hybrid-open`, and vice-versa — without weakening the
isolation both crates depend on and **without** giving the wasm crate an RNG or a
dependency on identity-file parsing.

## Decision

**Mirror the `SIGILhyb` byte format and its AAD into `sigil-wasm` exactly as
`SIGILcli` was mirrored in [ADR 0020](0020-shared-client-container-format.md) — no
shared crate — and prove parity with a test that shells to the real CLI in both
directions.** Two subordinate choices make this fit the crate's invariants:

- **All entropy stays JS-supplied.** `sigil-core` is RNG-free and
  caller-supplied-entropy ([ADR 0007](0007-caller-supplied-entropy-in-core.md)); the
  wasm binding carries that contract to JavaScript ([ADR 0019]). The new hybrid
  exports keep it: the recipient's X25519 secret and ML-KEM keygen seed, and the
  per-message ephemeral X25519 secret, ML-KEM encapsulation coin, and AEAD nonce,
  are **all** generated in JS with `crypto.getRandomValues` and passed **in** as
  byte arrays. So `sigil-wasm` stays **`getrandom`-free** — the wasm lockfile keeps
  its `getrandom`-count `0`, exactly like `libsigil/Cargo.lock`.
- **Node bridges the identity JSON; the wasm crate does not parse identity files.**
  Identity files are a CLI convenience, not core surface. Rather than teach the
  wasm crate to read the CLI's `.pub` / secret JSON, the crate exposes just the two
  raw derivations it needs — `hybrid_x25519_public(secret) -> 32` and
  `hybrid_mlkem_encaps_key(seed) -> 1184` — and the interop harness (Node) does the
  base64 marshalling of the CLI identity JSON (fields `x25519_public_key` /
  `mlkem_encaps_key` / `x25519_secret` / `mlkem_seed`) into raw key bytes and back.

`sigil-wasm` gains four `#[wasm_bindgen]` exports — `hybrid_x25519_public`,
`hybrid_mlkem_encaps_key`, `hybrid_seal_to_container`, and `hybrid_open_container`
(`sigil-wasm/src/lib.rs`). The format constants are duplicated with an explicit
sync comment: `cli/src/lib.rs` defines `HYBRID_MAGIC` (`b"SIGILhyb"`) and
`HYBRID_AAD` (`b"sigil-hybrid-cli/1"`); `sigil-wasm/src/lib.rs` mirrors
`HYBRID_MAGIC`, `HYBRID_FORMAT_VERSION`, and `HYBRID_AAD`, each carrying a comment
naming the CLI value it must equal byte-for-byte. As with `SIGILcli`, the container
prefix is unprotected framing metadata: tampering just yields the wrong key /
ciphertext and `open` fails to authenticate.

Why mirror instead of extract a shared crate — the reasoning from
[ADR 0020](0020-shared-client-container-format.md) applies unchanged: this is a
**pre-audit demo format, not a product wire format**; a shared crate is real
structural weight (a fourth Cargo unit, its own lockfile / wasm-purity question)
for a format we expect to replace; and the crates are deliberately isolated (each
keeps its own `Cargo.lock`, neither a `libsigil` workspace member) so a shared
crate would create a new coupling the mirror avoids. The duplication is small and
mechanically guarded (below).

## Consequences

- **Browser hybrid public-key encryption, interoperable with the CLI both ways.**
  A `.hyb` `SIGILhyb` container written by the browser/Node opens with `sigil
  hybrid-open`, and one written by `sigil hybrid-seal` opens with
  `hybrid_open_container` — proven end-to-end against the **actual** CLI binary,
  not a re-implementation. This is the **first time the PQ-hybrid encryption path
  is exercised in a browser client**.
- **The format is duplicated in two crates.** `cli/src/lib.rs` and
  `sigil-wasm/src/lib.rs` each carry the `SIGILhyb` constants and codec, tied
  together by a sync comment and two tripwire tests: a native golden fixed-prefix
  test in `sigil-wasm` and a Node interop test
  ([`../../sigil-wasm/test/hybrid-interop.mjs`](../../sigil-wasm/test/hybrid-interop.mjs))
  that **builds and shells to the real `sigil` binary** and drives **both**
  directions — Direction A (`hybrid_seal_to_container` → `sigil hybrid-open`) and
  Direction B (`sigil hybrid-seal` → `hybrid_open_container`). If either copy
  drifts, one direction fails. This mirrors — and doubles — the accepted, bounded
  maintenance cost from ADR 0020.
- **No RNG, no new lockfile coupling.** Entropy stays JS-supplied and identity JSON
  stays in Node, so `sigil-wasm` remains `getrandom`-free and standalone; both
  `libsigil/Cargo.lock` and `sigil-wasm/Cargo.lock` keep `getrandom`-count `0`.
- **It is still a pre-audit demo, not the product, and not "post-quantum secure".**
  `hybrid_seal` / `hybrid_open` are a **CUSTOM KEM-then-AEAD composition, NOT RFC
  9180 HPKE**, over the **UNAUDITED** hybrid building blocks; `SIGILhyb` is a
  **CLI/demo container, not a frozen product wire format**. This is **not** the
  product's account / key-management model and must not protect real secrets. That
  the wasm client can now run the hybrid path does **not** make the **system**
  post-quantum secure. A future real, versioned container/wire format is a
  different decision (it would belong in `sigil-core` or a purpose-built shared
  crate), at which point this ADR and ADR 0020 would be superseded.
