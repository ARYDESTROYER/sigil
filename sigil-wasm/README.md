# sigil-wasm

> **PRE-AUDIT / UNAUDITED.** A demonstration of the wasm-pure `sigil-core`
> crypto core running in a JavaScript runtime (browser + Node). It is a
> building-block demo only and **MUST NOT be used to protect real secrets.** It
> is **not** the product's account / key-management model.

`sigil-wasm` is a thin [`wasm-bindgen`](https://rustwasm.github.io/wasm-bindgen/)
binding over the libsigil [`sigil-core`](../libsigil/core) **record API**
(Argon2id → XChaCha20-Poly1305 + HKDF envelope). It exposes `seal_record` /
`open_record` to JavaScript so a browser or Node process can seal and open a
record entirely client-side.

## The invariant it proves

`sigil-core` is `no_std`, wasm-pure, and has **no in-core RNG** — every piece of
entropy is **caller-supplied**. This crate carries that contract all the way out
to JavaScript: the Argon2id **salt** and the AEAD **nonce** are generated in JS
with `crypto.getRandomValues` and passed **into** the wasm as byte arrays. The
wasm module never reaches for randomness.

Concretely, this crate is **`getrandom`-free**, exactly like `sigil-core`:

```bash
grep -c 'name = "getrandom"' ../libsigil/Cargo.lock   # 0 (unchanged by this crate)
grep -c 'name = "getrandom"' Cargo.lock               # 0
```

Like `cli/`, this is a **standalone crate with its own `Cargo.lock`**, path-
depending on `../libsigil/core`. It is **not** a member of the `libsigil`
workspace, so it can never perturb `libsigil/Cargo.lock`. Unlike `cli/`, it
deliberately does **not** add `getrandom` — proving the caller-supplied-entropy
design end to end.

> Note: because the `#[wasm_bindgen]` macro generates `unsafe` glue, this crate
> cannot `#![forbid(unsafe_code)]`. All the security-relevant code — every line
> of cryptography — lives in `sigil-core`, which **is** `#![forbid(unsafe_code)]`.
> This crate only marshals bytes.

## API (as seen from JavaScript)

```ts
seal_record(password, salt, nonce, m_cost, t_cost, p_cost, aad, plaintext): Uint8Array
open_record(password, salt, m_cost, t_cost, p_cost, envelope): Uint8Array
nonce_len(): number            // 24 (XChaCha20-Poly1305 nonce length)
recommended_salt_len(): number // 16
version(): string
```

All byte arguments are `Uint8Array`. `seal_record` returns the encoded envelope
(the AEAD nonce is stored **inside** it); the caller MUST persist `salt` and the
three Argon2 cost params separately to `open` later. A wrong password / bad nonce
length / tampered ciphertext throws a JS `Error`.

## Build

```bash
./build-wasm.sh
```

This uses [`wasm-pack`](https://rustwasm.github.io/wasm-pack/) (installing it if
absent) to produce **two** packages from the one crate:

- `pkg-web/`  — ESM package for the browser demo (`--target web`)
- `pkg-node/` — CommonJS package for the Node test (`--target nodejs`)

Both are **build artifacts** (git-ignored) — do not commit them.

Pinned tooling (for reproducibility): **wasm-pack 0.13.1**, which bundles
**wasm-bindgen-cli 0.2.100**, matching the `wasm-bindgen = "=0.2.100"` pin in
`Cargo.toml`.

## Run the automated Node round-trip test

```bash
./build-wasm.sh                     # produces pkg-node/
node test/roundtrip.mjs
```

The test generates a random 16-byte salt + 24-byte nonce with
`webcrypto.getRandomValues`, seals a known plaintext under fast Argon2 params,
asserts the sealed bytes do **not** contain the plaintext, opens it back and
asserts equality, and asserts that opening with the **wrong password** throws. It
prints a `PASS` line and exits 0 on success (non-zero on any failure). This is
the proof the wasm-pure core works in a JS runtime with caller-supplied entropy.

## Serve the browser demo

```bash
./build-wasm.sh                     # produces pkg-web/
python3 -m http.server 8000         # from this directory
# open http://localhost:8000/demo/
```

The demo (`demo/index.html` + `demo/main.js`) has a password field, a plaintext
textarea, and Seal / Open buttons; Seal generates the salt+nonce via
`window.crypto.getRandomValues`, shows the envelope as base64, and keeps
`(salt, params)` in memory for Open. It carries a loud pre-audit banner.

## Native unit tests

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/opt/homebrew/bin:$PATH"
cargo test --manifest-path Cargo.toml
```

These exercise the `*_inner` marshalling helpers (seal→open round-trip,
wrong-password failure, bad-nonce rejection) natively as an `rlib`.
