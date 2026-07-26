# 0023 — TOTP/HOTP primitive in `sigil-core` and an encrypted CLI TOTP vault

- **Status:** Accepted — 2026-07.

## Context

Sigil's product is an **authenticator**, yet until now the repository contained
**no authenticator function at all**. Every crypto primitive built so far — the
Argon2id KDF, the XChaCha20-Poly1305 AEAD, `seal_record` / `open_record`, the
Ed25519 / ML-DSA-65 / X25519 / ML-KEM-768 primitives, the hybrid KEM and hybrid
signature combiners, and the hybrid public-key seal — is a general-purpose
**building block**. None of them *is* the product feature a user actually wants:
generate a valid 2FA code for an account.

The one-time-password math is a small, fully specified standard: **RFC 4226**
(HOTP — HMAC-SHA-1 with dynamic truncation) and **RFC 6238** (TOTP — HOTP over a
time counter, extended to SHA-256 / SHA-512). Both come with official
known-answer test vectors (RFC 4226 Appendix D, RFC 6238 Appendix B), so the
primitive is verifiable to the standard rather than to our own judgement.

Two constraints shaped where and how it lands:

1. **The core reads no clock and no RNG** ([ADR 0007](0007-caller-supplied-entropy-in-core.md)).
   `sigil-core` is `no_std` and must keep compiling to
   `wasm32-unknown-unknown`, where there is no system clock and no `getrandom`
   backend. TOTP is defined over "current Unix time", but the core cannot read
   it. And the HMAC needs SHA-1 (`sha1`) and the keyed-MAC wrapper (`hmac`),
   which must not drag `getrandom` into the audit-bound core lockfile.
2. **A 2FA secret is exactly the kind of thing this product is supposed to
   protect.** Storing OTP secrets in plaintext on disk would contradict the
   entire premise, so the vault must be encrypted at rest with a real primitive
   we already have — not a new bespoke store.

## Decision

**Put the OTP math in the wasm-pure core; keep the clock, the RNG, and the vault
storage in the native CLI.**

- **Primitive — [`libsigil/core/src/totp.rs`](../../libsigil/core/src/totp.rs).**
  Add `hotp(key, counter, digits, algorithm)` (RFC 4226 §5.3 dynamic
  truncation), `totp(key, unix_time, period, t0, digits, algorithm)` (RFC 6238
  §4, counter `T = (unix_time - t0) / period`), and `format_code(code, digits)`
  (zero-padded rendering), over an `OtpAlgorithm` enum (`Sha1` default /
  `Sha256` / `Sha512`) with an `OtpError` for out-of-range `digits` / zero
  `period` / time-before-`t0`. Digits are bounded `MIN_DIGITS..=MAX_DIGITS`
  (6..=10). **The caller supplies `unix_time`** — the core reads no clock, so
  the no-RNG/no-clock invariant of [ADR 0007](0007-caller-supplied-entropy-in-core.md)
  holds unchanged. Correctness is gated by the **RFC 4226 Appendix D** and
  **RFC 6238 Appendix B** known-answer vectors as in-module tests.
- **New dependencies, both `getrandom`-free.** `hmac` (already in the tree
  transitively via `hkdf`, now a direct dep) provides the keyed MAC; `sha1` is
  new and required because real-world authenticator apps and `otpauth://`
  provisioning are overwhelmingly HMAC-SHA-1 — interop *demands* SHA-1. Both are
  `default-features = false`, so neither pulls `getrandom`/`rand`, and the
  `wasm32-unknown-unknown` / `no_std` build and the `getrandom`-count guard
  (`grep -c 'name = "getrandom"' libsigil/Cargo.lock` == 0) are preserved.
- **Encrypted vault — the CLI's `sigil totp` subcommands**
  ([`cli/src/lib.rs`](../../cli/src/lib.rs), [`cli/src/main.rs`](../../cli/src/main.rs)).
  A `TotpVault` (a versioned list of `TotpEntry`) is serialized to JSON and
  **sealed with the exact same `SIGILcli` password container as `seal`/`open`**
  (`seal_vault` / `open_vault` wrap `seal_to_container` / `open_container`), so a
  TOTP vault is just another opaque sealed container — E2EE at rest and syncable
  through the op-log later, with no new storage format. The CLI supplies the
  clock (`SystemTime::now`) and the entropy (the Argon2 salt / AEAD nonce, as it
  already does), and adds `add` / `list` / `code` / `remove`, plus base32
  (`base32_decode`) and `otpauth://` (`parse_otpauth_uri`) import. `list` never
  prints the secret; the vault file is `0600` under a `0700` `~/.sigil` dir.

## Consequences

- **The authenticator function now exists** — the first primitive that
  implements an actual product *feature* rather than a general building block.
  It is verified to the RFC vectors and exercised end-to-end by the CLI vault.
- **SHA-1 is a deliberate interop requirement, not a security regression.**
  HMAC-SHA-1 is the near-universal `otpauth://` default; an authenticator that
  cannot do it is not interoperable. SHA-256 / SHA-512 are offered too. This is
  HMAC-SHA-1 (a MAC), not SHA-1 as a collision-resistant hash.
- **The no-clock / no-RNG core invariant is intact.** `totp` takes time as an
  argument; `hmac` + `sha1` are `getrandom`-free. The core stays `no_std`,
  wasm-pure, and RNG-free ([ADR 0007](0007-caller-supplied-entropy-in-core.md)).
- **The vault reuses the audit-surface-minimal `SIGILcli` sealing.** (Minimal
  *surface to audit* — nothing here is audited.) No new
  at-rest format, no new crypto — the vault inherits the Argon2id +
  XChaCha20-Poly1305 container and its properties (wrong password / tamper →
  authentication failure, never plaintext). Because it is an opaque sealed
  container, the dev op-log could sync it unchanged with no server change.
- **Still pre-audit / UNAUDITED / dev-only.** The OTP math is standard and
  RFC-vector-checked, but the build is unaudited; the vault does not zeroize key
  material, and code *verification* (constant-time compare, validity window) is
  left to callers — `sigil-core` only *generates* codes. **Do not store real 2FA
  secrets in this build.** Public copy still obeys
  [`../../web/apps/marketing/MARKETING-CLAIMS.md`](../../web/apps/marketing/MARKETING-CLAIMS.md).
