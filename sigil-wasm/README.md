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
// Password path
seal_record(password, salt, nonce, m_cost, t_cost, p_cost, aad, plaintext): Uint8Array
open_record(password, salt, m_cost, t_cost, p_cost, envelope): Uint8Array
seal_to_container(password, salt, nonce, m_cost, t_cost, p_cost, plaintext): Uint8Array
open_container(password, container): Uint8Array
// Hybrid PUBLIC-KEY path (no password) — see below
hybrid_x25519_public(secret): Uint8Array          // 32-byte secret  -> 32-byte X25519 public key
hybrid_mlkem_encaps_key(seed): Uint8Array         // 64-byte seed    -> 1184-byte ML-KEM encaps key
hybrid_seal_to_container(recipient_x25519_pub, recipient_mlkem_encaps_key,
                         ephemeral_x25519_secret, mlkem_coin, aead_nonce, plaintext): Uint8Array
hybrid_open_container(recipient_x25519_secret, recipient_mlkem_seed, container): Uint8Array
nonce_len(): number            // 24 (XChaCha20-Poly1305 nonce length)
recommended_salt_len(): number // 16
version(): string
```

All byte arguments are `Uint8Array`. `seal_record` returns the encoded envelope
(the AEAD nonce is stored **inside** it); the caller MUST persist `salt` and the
three Argon2 cost params separately to `open` later. A wrong password / bad nonce
length / tampered ciphertext throws a JS `Error`.

## CLI-compatible `SIGILcli` container interop

`seal_to_container` / `open_container` are the **interop** path: they read and
write the exact same self-describing container the [`sigil` CLI](../cli) does, so
you can **seal in the browser and open with `sigil open`**, and vice-versa.

The format is **byte-identical** to `cli/src/lib.rs` (all integers
little-endian):

```text
  magic[8] = "SIGILcli" | version:u8 = 1 | m_cost:u32 | t_cost:u32 | p_cost:u32 |
  salt_len:u8 | salt[salt_len] | envelope[..]
```

and the AEAD **AAD** bound at seal time is the fixed ASCII tag `sigil-cli/1` —
the wasm seals with the same AAD, or the CLI's `open` would fail authentication.
`open_container` reads the params + salt back out of the header (self-describing),
so you do **not** carry them separately. The container header constants are
mirrored in `sigil-wasm/src/lib.rs` with a comment tying each value back to the
CLI; a native golden test asserts the header bytes byte-for-byte, and the Node
interop test below drives both directions against the **real** CLI binary.

Unlike the CLI (which draws its own OS entropy), `seal_to_container` takes the
salt and nonce as arguments — keep the caller-supplied-entropy contract by
generating them in JS with `crypto.getRandomValues`. Example:

```js
// Seal in the browser -> a file you can `sigil open`.
const salt = new Uint8Array(recommended_salt_len());  crypto.getRandomValues(salt);
const nonce = new Uint8Array(nonce_len());            crypto.getRandomValues(nonce);
const container = seal_to_container(password, salt, nonce, 8, 1, 1, plaintext);
// ... download `container` as note.sigil, then on a shell:
//   SIGIL_PASSWORD='…' sigil open --in note.sigil --out note.txt

// Open a container written by `sigil seal` (its params ride in the header).
const plaintext = open_container(password, uploadedBytes);
```

## Hybrid PUBLIC-KEY (`SIGILhyb`) interop

> **CUSTOM KEM-then-AEAD, NOT RFC 9180 HPKE. The system is NOT post-quantum
> secure. UNAUDITED — do not protect real secrets.**

The **no-password**, public-key path. A device has a **hybrid identity**: a
**secret** half (a 32-byte X25519 secret + a 64-byte ML-KEM-768 keygen seed) and
a shareable **public** half (a 32-byte X25519 public key + a 1184-byte ML-KEM-768
encapsulation key). A sender encrypts **to** the public half; only the holder of
the secret half can open. It composes `sigil-core`'s hybrid primitives (X25519 +
ML-KEM-768 → shared secret → XChaCha20-Poly1305) and is byte-compatible with the
CLI's `sigil hybrid-seal` / `sigil hybrid-open`.

As everywhere in this crate, **all entropy is caller-supplied in JS**: the X25519
secret, the ML-KEM keygen seed, the per-message ephemeral X25519 secret, the
ML-KEM coin, and the AEAD nonce are all generated with `crypto.getRandomValues`.

The wasm crate deliberately does **not** parse identity files — JS bridges the
CLI's identity JSON. The public identity `.pub` JSON is (standard-base64 fields):

```json
{ "version": 1, "x25519_public_key": "<b64 32>", "mlkem_encaps_key": "<b64 1184>" }
```

and the container is **byte-identical** to `cli/src/lib.rs`:

```text
  magic[8] = "SIGILhyb" | version:u8 = 1 | eph_x25519_pub[32] | mlkem_ct[1088] | envelope[..]
```

with the fixed AEAD **AAD** `sigil-hybrid-cli/1`. These constants are mirrored in
`sigil-wasm/src/lib.rs` with comments tying each value to the CLI; a native golden
test asserts the fixed-prefix bytes and field offsets. Example:

```js
// --- Derive a recipient identity in JS (secrets stay in JS) ---
const x25519_secret = crypto.getRandomValues(new Uint8Array(32));
const mlkem_seed    = crypto.getRandomValues(new Uint8Array(64));
const x25519_public_key = hybrid_x25519_public(x25519_secret);   // 32 bytes
const mlkem_encaps_key  = hybrid_mlkem_encaps_key(mlkem_seed);   // 1184 bytes
// publish { version:1, x25519_public_key, mlkem_encaps_key } (base64) as the .pub

// --- Seal TO a recipient .pub, download the SIGILhyb container ---
const ephSecret = crypto.getRandomValues(new Uint8Array(32));
const coin      = crypto.getRandomValues(new Uint8Array(32));
const nonce     = crypto.getRandomValues(new Uint8Array(nonce_len()));
const container = hybrid_seal_to_container(
  recipient_x25519_pub, recipient_mlkem_encaps_key, ephSecret, coin, nonce, plaintext);
// ... download as note.hyb, then:  sigil hybrid-open --key you.key --in note.hyb --out note.txt

// --- Open a SIGILhyb container with your secret identity ---
const plaintext = hybrid_open_container(x25519_secret, mlkem_seed, uploadedBytes);
```

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

## Run the CLI interop test

```bash
./build-wasm.sh                     # produces pkg-node/ (must run first)
node test/interop.mjs
```

This proves the `SIGILcli` container is byte-compatible in **both** directions by
shelling out to the **real** `sigil` binary (it runs `cargo build --bin sigil`
first, so no stale binary):

- **Direction A** — `sigil seal` writes a container, Node reads the bytes and
  `open_container` recovers the plaintext (asserts equality);
- **Direction B** — `seal_to_container` (with a JS-generated salt + nonce) writes
  a container, `sigil open` decrypts it (asserts equality).

It prints a `PASS` line naming both directions and exits non-zero on any
mismatch. It builds the CLI itself but needs `pkg-node/` from `./build-wasm.sh`.

## Run the hybrid public-key interop test

```bash
./build-wasm.sh                     # produces pkg-node/ (must run first)
node test/hybrid-interop.mjs
```

This proves the `SIGILhyb` container is byte-compatible in **both** directions
against the **real** `sigil` binary (it runs `cargo build --bin sigil` first).
Node bridges the CLI identity JSON — the wasm crate never parses identity files:

- **Direction A** — `sigil hybrid-keygen` writes a recipient identity; Node reads
  the `.pub`, decodes the public parts, `hybrid_seal_to_container` (with a
  JS-generated ephemeral secret + coin + nonce) writes the container, and
  `sigil hybrid-open` recovers the plaintext (asserts equality);
- **Direction B** — Node generates the recipient secret material, derives the
  public parts via `hybrid_x25519_public` / `hybrid_mlkem_encaps_key`, writes a
  CLI-format `.pub`, `sigil hybrid-seal` writes the container, and
  `hybrid_open_container` recovers the plaintext (asserts equality).

It prints a `PASS` line naming both directions and exits non-zero on any
mismatch. It builds the CLI itself but needs `pkg-node/` from `./build-wasm.sh`.

## Sync over the dev `sigild` op-log (`sync.mjs`)

`sync.mjs` is a small, framework-free, dependency-free ESM transport that moves
**opaque** sealed containers to/from a dev `sigild` op-log over plain HTTP. It is
the JS twin of the `sigil push` / `sigil pull` CLI: it performs **no cryptography**
and never inspects a container — it just shuttles already-sealed bytes. It works
in **both** Node (global `fetch`) and the browser (`fetch` + `atob`); base64
decoding is feature-detected (`Buffer` in Node, `atob` in the browser).

```js
import { pushContainer, pullContainers } from "./sync.mjs";

// POST the raw sealed bytes; returns the server-assigned seq.
const { seq } = await pushContainer("http://127.0.0.1:8080", "demo", containerBytes);

// Drain the vault (loops since=next until has_more=false); base64-decodes each
// op.blob back to the exact container bytes, in ascending seq order.
const ops = await pullContainers("http://127.0.0.1:8080", "demo", 0);
// -> [{ seq, container: Uint8Array, hash }, ...]
```

The `sigild` op-log is **zero-knowledge**: it stores and returns the exact opaque
bytes and does no crypto — confidentiality is the caller sealing *before* push.
This is **dev / localhost / plain-HTTP / no-auth**: enable it with a local sigild
started as `SIGILD_ADDR=127.0.0.1:8080 SIGILD_ENABLE_DEV_OPS=1 ./sigild` (the
in-memory backend; no `SIGILD_OPLOG_PUBKEY` ⇒ unauthenticated). Do **not** point
it at a remote host or use it for real secrets.

## Run the sync-loop interop test

```bash
./build-wasm.sh                     # produces pkg-node/ (must run first)
node test/sync-interop.mjs
```

This closes the E2EE sync loop against a **live** sigild AND the real `sigil`
CLI, all through the opaque op-log. It builds `sigild` (`go build ./cmd/server`)
and the CLI (`cargo build --bin sigil`), boots sigild on a free localhost port
with `SIGILD_ENABLE_DEV_OPS=1` (in-memory, no auth), polls `/readyz`, and always
kills the server in a `finally`. It proves:

- **PROOF 1** — client self-loop: `wasm.seal_to_container` → `pushContainer` →
  `pullContainers` → `wasm.open_container` equals the original;
- **PROOF 2** — CLI writes / browser reads: `sigil seal` + `sigil push` a
  `SIGILcli` container, then `pullContainers` (JS) + `wasm.open_container` equals
  the original;
- **PROOF 3** — browser writes / CLI reads: `wasm.seal_to_container` +
  `pushContainer`, then `sigil pull` + `sigil open` equals the original;
- **OPAQUE** — after a push, a raw `GET …/ops` is fetched and the stored blob is
  asserted to base64-decode to **exactly** the pushed bytes (the server returned
  them verbatim; it did no crypto).

It prints a `PASS` line naming all proofs and exits non-zero on any failure.

## Serve the browser demo

```bash
./build-wasm.sh                     # produces pkg-web/
python3 -m http.server 8000         # from this directory
# open http://localhost:8000/demo/
```

The demo (`demo/index.html` + `demo/main.js`) has a password field, a plaintext
textarea, and Seal / Open buttons; Seal generates the salt+nonce via
`window.crypto.getRandomValues`, shows the envelope as base64, and keeps
`(salt, params)` in memory for Open. It also has an **interop** section that uses
`seal_to_container` / `open_container`: **Seal → download .sigil** saves a
CLI-compatible container you can open with `sigil open`, and the file picker
**opens** a `.sigil` container (from the demo *or* from `sigil seal`) right in the
browser. Finally it has a **hybrid PUBLIC-KEY** section: generate a hybrid
identity (secret held in memory, `.pub` downloadable), **hybrid-seal → download
.hyb** to a loaded recipient `.pub` (or, by default, your own identity for a
self-round-trip), and **open** an uploaded `.hyb` with your secret identity —
byte-compatible with `sigil hybrid-seal` / `sigil hybrid-open`. Finally it has a
**Sync** section (via `sync.mjs`) with a server-URL field, a vault-ID field, a
**Seal → Push** button (seals the plaintext and POSTs the opaque container to a
dev sigild, showing the assigned seq) and a **Pull → Open** button (drains the
vault, opens the latest container with the password, and shows the recovered
plaintext) — interoperating with `sigil push` / `sigil pull` through the same
vault. That section needs a local dev sigild started with
`SIGILD_ENABLE_DEV_OPS=1` on loopback and is dev / plain-HTTP / no-auth. It
carries a loud pre-audit banner.

## Native unit tests

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/opt/homebrew/bin:$PATH"
cargo test --manifest-path Cargo.toml
```

These exercise the `*_inner` marshalling helpers natively as an `rlib`: the
password path (seal→open round-trip, wrong-password failure, bad-nonce
rejection, `SIGILcli` golden header) and the hybrid public-key path (derive
publics → `hybrid_seal_to_container` → `hybrid_open_container` round-trip,
wrong-recipient failure, bad-magic / truncated / bad-length rejection, and a
`SIGILhyb` golden fixed-prefix check).
