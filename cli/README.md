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
- A `--help`/`--version`-aware binary named `sigil` with two subcommands,
  `seal` and `open`, plus a testable library (`src/lib.rs`) with the container
  logic.

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

## Build & test

This crate is built against its **own** manifest (not the libsigil workspace):

```bash
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/opt/homebrew/bin:$PATH"
cargo fmt   --manifest-path cli/Cargo.toml --all -- --check
cargo clippy --manifest-path cli/Cargo.toml --all-targets -- -D warnings
cargo test  --manifest-path cli/Cargo.toml
cargo build --manifest-path cli/Cargo.toml
```
