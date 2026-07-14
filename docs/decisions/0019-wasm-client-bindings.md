# 0019 — WebAssembly client binding (`sigil-wasm`)

- **Status:** Accepted — 2026-07.

## Context

`libsigil/core` ([`../../libsigil/core/`](../../libsigil/core/)) is the
audit-bound cryptographic core. It is `#![forbid(unsafe_code)]`, `no_std`, and —
by design — compiles to `wasm32-unknown-unknown` so the future web app and
browser extension can link it. Two invariants make that possible and are recorded
elsewhere: the core generates **no randomness** (every salt/nonce/seed is
**caller-supplied**; [ADR 0007](0007-caller-supplied-entropy-in-core.md)), and
native-only dependencies are kept out of `libsigil/Cargo.lock` by living in
separate crates ([ADR 0002](0002-standalone-cli-crate-for-getrandom-isolation.md)).

Until now nothing actually *consumed* the wasm-pure core in a JavaScript runtime —
the wasm build only proved the core stays browser-linkable, and the client column
of the architecture was reserved/empty. We want the smallest honest artifact that
(a) exercises the real `seal_record` / `open_record` record API from JavaScript in
both the browser and Node, and (b) demonstrates that the caller-supplied-entropy
design holds all the way out to a JS host, not just in Rust tests.

Two design questions had to be settled to do that without weakening the core:

1. **Where does the binding crate live?** A `wasm-bindgen` binding needs
   `wasm-bindgen` as a dependency and links a `cdylib`. If it were a member of the
   `libsigil` workspace it would share `libsigil/Cargo.lock`, dragging
   `wasm-bindgen` (and its transitive tree) into the lockfile an auditor reviews
   for the core.
2. **Where does entropy come from in the browser?** The record API needs a random
   Argon2id salt and a random AEAD nonce. The obvious path is to add `getrandom`
   (its `js` feature bridges to `crypto.getRandomValues`). But adding `getrandom`
   here would blur the very invariant we want to demonstrate — that the core, and
   anything built directly on its wasm surface, needs no in-crate RNG.

## Decision

Add **`sigil-wasm`** ([`../../sigil-wasm/`](../../sigil-wasm/)) as a thin
`wasm-bindgen` binding over the `sigil-core` record API, exposing `seal_record` /
`open_record` (plus `nonce_len` / `recommended_salt_len` / `version`) to
JavaScript. It adds **no cryptography of its own** — the `#[wasm_bindgen]` entry
points are a paper-thin shell over `*_inner` helpers that only marshal bytes and
call into `sigil-core`. (The crate cannot itself `#![forbid(unsafe_code)]` because
the `#[wasm_bindgen]` proc-macro emits `unsafe` glue; the security-relevant code
stays in the `forbid(unsafe_code)` core. Its lib is `crate-type =
["cdylib", "rlib"]` so the native `#[cfg(test)]` unit tests can run.)

Two isolation decisions, matching the questions above:

1. **Separate crate with its own lockfile.** `sigil-wasm` is **not** a member of
   the `libsigil` workspace; it path-depends on `../libsigil/core` and resolves its
   own dependencies into its **own
   [`../../sigil-wasm/Cargo.lock`](../../sigil-wasm/Cargo.lock)**. `wasm-bindgen`
   is pinned exactly (`= "0.2.100"`) so the generated bindings match the CLI that
   `wasm-pack` bundles. This mirrors `cli/` ([ADR 0002](0002-standalone-cli-crate-for-getrandom-isolation.md))
   and leaves `libsigil/Cargo.lock` untouched.
2. **Entropy from JavaScript, not `getrandom`.** The crate deliberately does
   **not** depend on `getrandom`. The Argon2id salt and the AEAD nonce are
   generated on the JS side with `crypto.getRandomValues` (`webcrypto` in Node) and
   passed **in** as byte arrays. So the no-in-core-RNG / caller-supplied-entropy
   invariant is proven all the way into the browser, and the mechanical guard now
   covers a second lockfile:

   ```
   grep -c 'name = "getrandom"' libsigil/Cargo.lock   # must be 0
   grep -c 'name = "getrandom"' sigil-wasm/Cargo.lock # must ALSO be 0
   ```

The crate builds via [`../../sigil-wasm/build-wasm.sh`](../../sigil-wasm/build-wasm.sh)
(`wasm-pack`, pinned 0.13.1), which emits two packages from the one crate:
`pkg-web/` (browser ESM, `--target web`) and `pkg-node/` (Node CJS,
`--target nodejs`). It is exercised by native `*_inner` unit tests, an automated
Node round-trip test ([`test/roundtrip.mjs`](../../sigil-wasm/test/roundtrip.mjs):
JS-generated salt+nonce → seal → assert no-plaintext-leak → open → assert equality
→ assert wrong-password and bad-nonce both throw), and a browser `demo/`.

## Consequences

- **The audit-bound core lockfile is untouched.** `wasm-bindgen` and its tree land
  **only** in `sigil-wasm/Cargo.lock`; the auditor's dependency surface for
  `sigil-core` stays minimal and wasm-pure, exactly as for the CLI.
- **The caller-supplied-entropy invariant is now proven end to end into a JS
  host**, not merely in Rust — and it is enforced mechanically by a second
  `getrandom`-count guard (0 in both lockfiles).
- **A build step is required.** The JS packages are produced by `wasm-pack`, and
  `pkg-web/` / `pkg-node/` are **build artifacts** — **gitignored, never
  committed** (nor is `target/`); only the crate source, `Cargo.lock`,
  `build-wasm.sh`, the test, and the `demo/` are in the repo. Consumers must run
  `build-wasm.sh` before the Node test or the browser demo will resolve.
- **This is a demo, not the product.** `sigil-wasm` wraps only the symmetric,
  password-derived `seal_record` / `open_record` path over the **UNAUDITED**
  building block. It is **not** the product's account / key-management / session
  model, carries a loud pre-audit banner, and must not protect real secrets.
- Two more crates now share the `getrandom`-free guarantee, and the client column
  of the architecture ([`../architecture.md`](../architecture.md) §1, §4, §6) is no
  longer empty — but it is a single building-block demo, so no client / product
  claim follows from it.
