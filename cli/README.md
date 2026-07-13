# sigil-cli

> **STATUS: pre-audit.** A tiny, standalone demonstration binary that seals and
> opens a single file using the **real but UNAUDITED** libsigil core
> (`sigil-core`). It is a demonstration of the libsigil building block only.

## ⚠️ Do not use this for real secrets

This tool uses **UNAUDITED** cryptography. It wires the real `sigil-core` record
API (Argon2id password stretching → XChaCha20-Poly1305 + HKDF envelope) to a
file on disk, but that code **has not been audited** and this CLI is **not** a
finished, reviewed secret-management product. It makes **no** security
guarantees.

**Do NOT use `sigil-cli` to protect real secrets pre-audit.** It exists to
exercise and demonstrate the libsigil core, nothing more.

## What it is

- A **separate, standalone** cargo crate with its own `Cargo.lock`. It is
  **intentionally outside** the `libsigil/` cargo workspace so that it can use
  `getrandom` for native randomness without touching the libsigil workspace
  lockfile (which must stay `getrandom`-free because `sigil-core` compiles to
  `wasm32`). This binary is native-only and is never compiled to wasm.
- A `--help`/`--version`-aware binary named `sigil` with the password-based
  `seal` and `open` subcommands, the public-key `hybrid-keygen` /
  `hybrid-seal` / `hybrid-open` subcommands (see below), and `push`/`pull` (see
  below), plus a testable library (`src/lib.rs`) with the container, hybrid, and
  sync logic.

## Usage

The password is read from the `SIGIL_PASSWORD` environment variable. If it is
unset or empty, the command fails immediately — it never prompts and never
hangs.

```bash
# Seal a file into an encrypted container.
SIGIL_PASSWORD='correct horse battery staple' \
  sigil seal --in secret.txt --out secret.sigil

# Open the container back to plaintext.
SIGIL_PASSWORD='correct horse battery staple' \
  sigil open --in secret.sigil --out secret.txt

sigil --help
sigil --version
```

On success the command exits `0` and writes the output file. On any error it
prints a clear message to stderr and exits non-zero. It never prints secrets,
and a failed `open` (wrong password or tampered file) writes no plaintext.

## Hybrid public-key encryption (`hybrid-keygen` / `hybrid-seal` / `hybrid-open`) — ⚠️ no password, UNAUDITED

This is the **public-key path**, distinct from the password-based `seal`/`open`
above. Instead of a shared password, you encrypt a file **to another device's
hybrid identity** — an X25519 public key **plus** an ML-KEM-768 encapsulation
key — and only the holder of the matching **secret** identity can open it.

> **⚠️ PRE-AUDIT / UNAUDITED / DEV-ONLY.** The construction is a **custom
> KEM-then-AEAD** composition (X25519 + ML-KEM-768 → shared secret →
> XChaCha20-Poly1305). It is **NOT** RFC 9180 HPKE and **NOT** a standardised
> scheme; the **system is not post-quantum secure**. It wires the **real but
> UNAUDITED** `sigil-core` hybrid primitives and has **not** been audited. It
> makes **no** security guarantees. **Do not use it for real secrets.**

A device generates a hybrid **identity**: a **secret** identity file (its X25519
secret + ML-KEM-768 keygen seed, written mode `0600`) and a **shareable public**
identity file (its X25519 public key + ML-KEM-768 encapsulation key). The public
file is safe to hand out; senders encrypt to it.

```bash
# Device B: generate a hybrid identity. Writes the SECRET id to b.key (mode 0600)
# and the shareable PUBLIC id to b.key.pub. Share ONLY b.key.pub with senders.
sigil hybrid-keygen --out b.key
# -> wrote hybrid SECRET identity to b.key (mode 0600) ...
# -> wrote shareable PUBLIC identity to b.key.pub
# -> SHARE b.key.pub with senders ...

# Device A: encrypt a file TO B's public identity (no password).
sigil hybrid-seal --recipient-pub b.key.pub --in secret.txt --out msg.hyb

# Device B: decrypt with its secret identity.
sigil hybrid-open --key b.key --in msg.hyb --out secret.txt
```

There is **no password** on this path. `hybrid-open` never writes plaintext on
failure (a wrong identity or a tampered container fails to authenticate and
exits non-zero). See the [hybrid container format](#hybrid-container-format)
below.

**Identity file formats** (JSON). The **secret** identity is written mode `0600`
and holds private key material — keep it local and do **not** commit it; the
**public** identity is shareable:

```json
// secret identity (mode 0600) — keep local:
{ "version": 1, "x25519_secret": "<std-base64 of 32 bytes>", "mlkem_seed": "<std-base64 of 64 bytes>" }

// public identity (.pub) — shareable:
{ "version": 1, "x25519_public_key": "<std-base64 of 32 bytes>", "mlkem_encaps_key": "<std-base64 of 1184 bytes>" }
```

(The ML-KEM-768 decapsulation key is **derived** from the stored keygen seed, not
stored, so the secret identity stays small.)

## Two-"device" sync (`push` / `pull`) — ⚠️ dev / localhost / plain HTTP only

`push` and `pull` move **opaque, already-sealed** containers between two
"devices" through `sigild`'s **dev op-log**. The demo flow is:

```text
  device A:  seal  --->  push   ─┐
                                 ├──►  sigild dev op-log  (opaque blobs only)
  device B:  pull  <───  open   ─┘
```

> **This path is DEV / LOCALHOST / PLAIN-HTTP / UNAUDITED.** `push`/`pull` talk
> **plain, unencrypted HTTP** to a `sigild` op-log that is itself **dev-gated**
> (it only exists when `sigild` runs with `SIGILD_ENABLE_DEV_OPS=1`) and
> **unauthenticated**. There is **no TLS and no auth** on this path. The op-log
> is **in-memory and non-durable** and stores **opaque blobs only** — it never
> decrypts anything. `push`/`pull` never see your password or plaintext; they
> only shuttle the sealed container bytes. **Do not** point this at a remote
> host and **do not** use it for real secrets.

The server base URL is chosen as: `--server` flag, else the `SIGIL_SERVER`
environment variable, else the default `http://127.0.0.1:8080`.

```bash
# Device A: seal a file, then push the opaque container to the dev op-log.
SIGIL_PASSWORD='correct horse battery staple' \
  sigil seal --in secret.txt --out secret.sigil
sigil push --vault demo --in secret.sigil
# -> pushed vault demo seq 1

# Device B: pull new ops into an inbox dir, then open each one locally.
sigil pull --vault demo --out-dir ./inbox
# -> pulled seq 1 -> ./inbox/demo/op-1.sigil
# -> cursor for demo now at 1
SIGIL_PASSWORD='correct horse battery staple' \
  sigil open --in ./inbox/demo/op-1.sigil --out recovered.txt
```

Each pulled op is written to `<out-dir>/<vault>/op-<seq>.sigil` — a **per-vault
subdir**, so multiple vaults can safely share one `--out-dir` without their
`op-<seq>.sigil` filenames colliding on disk. If the dev op-log flag is off,
`sigild` returns `501` and `sigil` surfaces that as a clear error and exits
non-zero.

### Device-key signing (`keygen` + `--key`) — ⚠️ dev-only, single device key

By default the dev op-log is **unauthenticated**. A hardened `sigild` can instead
**require** every op-log request to be **signed** by one configured device key: set
`sigild`'s `SIGILD_OPLOG_PUBKEY` to the standard-base64 of a 32-byte Ed25519
**public** key, and `sigild` will reject any unsigned or invalid request with
HTTP `401`. When `SIGILD_OPLOG_PUBKEY` is **unset**, signing is off and the op-log
stays unauthenticated (unchanged).

> **HONEST SCOPE.** This is a **single** device key, **dev-only**, still over
> **plain HTTP**. Each request is signed under the **contract v2** message, which
> binds the request's method, path, query, a unix-seconds timestamp, a **fresh
> per-request nonce**, and the body; `sigild` rejects timestamps skewed more than
> **300 s** and, when it tracks seen nonces, rejects a **replayed** request whose
> nonce it has already seen inside that window — so a captured request is
> **replay-resistant**. That replay cache is **per-process / in-memory** on the
> server, so a multi-instance production deploy would need a shared store (e.g.
> Redis). Real **device enrollment**, a **multi-device registry**, and **JWT bearer
> tokens** all remain **future** work. The signing primitive (Ed25519, from
> `sigil-core`) is **real but UNAUDITED**.

Generate a device key once (written with mode `0600`; its public key is printed),
then point `sigild` at the public key:

```bash
# 1. Generate a device key. Prints the public key to paste into sigild's config.
sigil keygen --out device.key
# -> wrote device key to device.key (mode 0600)
# -> device public key (set sigild SIGILD_OPLOG_PUBKEY to this): <base64>

# 2. Run the dev sigild REQUIRING that key (dev op-log + configured pubkey).
SIGILD_ENABLE_DEV_OPS=1 \
SIGILD_OPLOG_PUBKEY='<base64 from step 1>' \
  go -C ../sigild run ./cmd/server
```

Then **sign** every `push`/`pull` by passing the key with `--key <file>`, or by
setting the `SIGIL_DEVICE_KEY` environment variable to the key-file path (`--key`
takes precedence over `SIGIL_DEVICE_KEY`):

```bash
# Sign the push with the device key.
sigil push --vault demo --in secret.sigil --key device.key

# Or point at the key via the environment.
SIGIL_DEVICE_KEY=device.key sigil pull --vault demo --out-dir ./inbox
```

Without a key against a `sigild` that has `SIGILD_OPLOG_PUBKEY` set, `push`/`pull`
get a `401` (surfaced as a clear error, non-zero exit). Against a `sigild` with no
pubkey configured, the key is simply ignored and the request is accepted.

**Key file format** (JSON, mode `0600`; it holds the secret seed — keep it local
and do not commit it):

```json
{ "version": 1, "seed": "<std-base64 of 32 bytes>", "public_key": "<std-base64 of 32 bytes>" }
```

### Incremental pull

Pulled ops are written to `<out-dir>/<vault>/op-<seq>.sigil` (a per-vault subdir,
so multiple vaults can safely share one `--out-dir` without their `op-<seq>.sigil`
filenames colliding). The cursor state file stays at the `--out-dir` **root** —
`<out-dir>/.sigil-pull-state.json`, **not** inside the per-vault subdir — shared
across vaults and keyed by `(server, vault)`.

`pull` is **incremental**. It remembers the last pulled op sequence for each
`(server, vault)` pair in that small **local** state file,
`.sigil-pull-state.json`:

- The **first** pull for a `(server, vault)` gets every op.
- **Subsequent** pulls fetch only ops newer than the saved cursor, so you never
  re-download what you already have. When there is nothing new it prints
  `no new ops since <start>` and writes nothing.
- After a successful pull it prints `cursor for <vault> now at <seq>`.

The cursor is **monotonic** — it only ever advances. `--since N` overrides the
start for a **one-off** pull (returns ops with sequence `> N`; `--since 0`
re-fetches everything), but it does **not** rewind the saved cursor: after an
explicit `--since`, future incremental pulls still resume from the highest seq
seen.

```bash
sigil pull --vault demo --out-dir ./inbox     # first time: gets everything
sigil pull --vault demo --out-dir ./inbox     # later: only new ops
sigil pull --vault demo --since 0 --out-dir ./inbox   # one-off full re-fetch
```

The state file is **local, per-device state**: it is **not secret** and is
**not synced** (it holds only server URLs, vault ids, and integers — never any
crypto material). Delete `<out-dir>/.sigil-pull-state.json` to reset the cursor
and pull from scratch.

To run the dev op-log locally (see `sigild/README.md` for details):

```bash
SIGILD_ENABLE_DEV_OPS=1 go -C sigild run ./cmd/server
```

## On-disk container format

`seal_record` stores the AEAD nonce *inside* the envelope it returns, so `open`
does not need the nonce. But the Argon2id **salt** and **params** are not in the
envelope, so this CLI persists them itself in a small self-describing header.

All integers are little-endian:

```text
  offset  size            field
  ------  --------------  -----------------------------------------------
  0       8               magic           = "SIGILcli"
  8       1               format_version  = 1
  9       4   (u32 LE)    m_cost          (Argon2id memory cost, KiB)
  13      4   (u32 LE)    t_cost          (Argon2id time cost / passes)
  17      4   (u32 LE)    p_cost          (Argon2id parallelism / lanes)
  21      1               salt_len        (length of the salt, in bytes)
  22      salt_len        salt            (random Argon2id salt)
  22+sl   ..              envelope        = the sigil-core seal_record output
```

The salt/params header is **unprotected metadata** (the AEAD authenticates the
ciphertext, tag, nonce, and a fixed `aad = "sigil-cli/1"`, not this header).
Tampering with the salt or params simply derives the wrong key, so the record
fails to authenticate and `open` returns an error.

## Hybrid container format

The `hybrid-seal` / `hybrid-open` public-key path uses its own container. It
prepends the sender's ephemeral X25519 public key and the ML-KEM-768 ciphertext
(both needed to re-derive the shared secret) to the seal envelope:

```text
  offset  size    field
  ------  ------  -----------------------------------------------
  0       8       magic          = "SIGILhyb"
  8       1       format_version = 1
  9       32      eph_x25519_pub (sender's ephemeral X25519 public key)
  41      1088    mlkem_ct       (ML-KEM-768 ciphertext)
  1129    ..      envelope       = the sigil-core hybrid_seal output
```

The recipient re-derives the hybrid shared secret from `eph_x25519_pub` +
`mlkem_ct` + its **secret** identity, then opens the envelope. The AEAD
authenticates the ciphertext, tag, nonce, and a fixed `aad = "sigil-hybrid-cli/1"`;
tampering with any part of the container makes `hybrid-open` fail. `hybrid-open`
bounds-checks the fixed prefix before slicing, so short or garbage input is a
clear error, never a panic.

## Build & test

This crate is built against its **own** manifest (not the libsigil workspace):

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/opt/homebrew/bin:$PATH"
cargo fmt   --manifest-path cli/Cargo.toml --all -- --check
cargo clippy --manifest-path cli/Cargo.toml --all-targets -- -D warnings
cargo test  --manifest-path cli/Cargo.toml
cargo build --manifest-path cli/Cargo.toml
```
