# 0010 — X25519 key-agreement primitive (classical KEM half)

- **Status:** Accepted — 2026-07.

## Context

Suite `0x12` (the current suite — see
[ADR 0004](0004-crypto-agility-suite-registry.md) and
[`../crypto-spec.md`](../crypto-spec.md)) names a **hybrid** key encapsulation:
classical **X25519** *and* post-quantum **ML-KEM-768**, with the two shared
secrets combined by an HKDF so the construction is secure if *either* component
holds. Until now `sigil-core` implemented neither half of the KEM: the AEAD took
a master key directly, and there was no key-agreement primitive at all.

The Ed25519 signature primitive
([`../../libsigil/core/src/sig.rs`](../../libsigil/core/src/sig.rs)) set the
pattern: a real, deterministic, caller-seeded classical primitive that stands
alone, unaudited, ahead of its post-quantum sibling. That pattern applies just as
well to the KEM — we can land the **classical X25519 half now** and leave the
**ML-KEM-768 half** (and the hybrid *combine*) for later, without faking
anything.

The constraints are the same ones that shape the rest of the core
([ADR 0007](0007-caller-supplied-entropy-in-core.md),
[ADR 0002](0002-standalone-cli-crate-for-getrandom-isolation.md)): the core is
`#![forbid(unsafe_code)]`, `no_std`, must keep compiling to
`wasm32-unknown-unknown`, and **`getrandom` must never enter
`libsigil/Cargo.lock`** (`grep -c 'name = "getrandom"'` stays `0`).

## Decision

Add [`../../libsigil/core/src/kex.rs`](../../libsigil/core/src/kex.rs): a real
(but **UNAUDITED**) X25519 (RFC 7748) key-agreement primitive that is the
**classical half** of the hybrid X25519 & ML-KEM-768 KEM.

- **Raw fixed-size byte API**, mirroring `sig.rs`: `x25519_public_key(&[u8;32]) ->
  [u8;32]` and `x25519_shared_secret(&[u8;32], &[u8;32]) -> [u8;32]`, plus a
  constant-time `is_contributory(&[u8;32]) -> bool` helper and the length
  constants `KEX_SECRET_LEN` / `KEX_PUBLIC_KEY_LEN` / `KEX_SHARED_SECRET_LEN`
  (all 32).
- **Dependency:** `x25519-dalek = { version = "2", default-features = false }`.
  `default-features = false` drops the default `alloc`, `precomputed-tables`, and
  `zeroize` features; the `getrandom`/`static_secrets` features are opt-in and are
  never enabled, so no system RNG is pulled. (`rand_core` remains a *non-optional*
  transitive dependency in the lockfile, but without its `getrandom` feature — that
  is the actual reason the `getrandom` count stays `0`, not the removal of a
  feature.) We call only the always-available, RNG-free free function `x25519()`
  and the `X25519_BASEPOINT_BYTES` constant. It reuses the same `curve25519-dalek`
  that `ed25519-dalek` already pulls in (a single copy in the lockfile). The
  constant-time check uses `subtle` (also already transitive via
  `curve25519-dalek`), declared directly, `default-features = false`.
- **Caller-supplied secret, no in-core RNG** — exactly as for the Argon2id salt,
  the AEAD nonce, and the Ed25519 seed
  ([ADR 0007](0007-caller-supplied-entropy-in-core.md)). The core never generates
  a key; the caller supplies the 32-byte secret scalar. X25519 clamps it
  internally.
- **Contributory behaviour is surfaced, not decided for the caller.**
  `x25519_shared_secret` returns the raw result (a low-order peer key forces an
  all-zero shared secret); `is_contributory` gives a constant-time all-zero check
  a protocol can use to enforce contributory key agreement (RFC 7748 §6.1). This
  matches the "raw primitive, caller owns policy" stance of `sig.rs`.
- **Classical only.** The **ML-KEM-768** half stays specified-but-unimplemented,
  and the two shared secrets are **not** combined, so this provides **no**
  post-quantum protection. The primitive is **not** wired into a KEM/hybrid or any
  product flow — it stands alone, like `sig.rs`.

## Consequences

- The core gains a real, interop-correct (RFC 7748 §5.2 and §6.1 known-answer
  vectors) classical KEX building block while staying
  **`wasm32-unknown-unknown`-pure and `getrandom`-free** (count stays `0`; wasm
  build stays green; `#![forbid(unsafe_code)]` intact).
- **No over-claim.** The KEM remains only half-built: the module, the crate docs,
  [`../crypto-spec.md`](../crypto-spec.md), and
  [`../architecture.md`](../architecture.md) all state that the PQ half and the
  hybrid combine are unimplemented and that the primitive is unaudited and unwired.
- **Callers own entropy, storage, and contributory policy.** A caller that reuses
  the same 32 bytes as both an Ed25519 seed and an X25519 secret, supplies a weak
  secret, or ignores a non-contributory result undermines the construction — this
  is explicit at the API boundary, not hidden.
- A future ADR will record the ML-KEM-768 half and the hybrid combine (`ss_x ||
  ss_kem` → HKDF) when they are actually built; this ADR is not rewritten then.
