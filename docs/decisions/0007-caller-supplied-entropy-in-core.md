# 0007 — Caller-supplied entropy in `sigil-core`

- **Status:** Accepted — 2026-06.

## Context

`libsigil/core` ([`../../libsigil/core/`](../../libsigil/core/)) is the
audit-bound cryptographic core. It is `#![forbid(unsafe_code)]`, `no_std` (uses
`core` + `alloc`), and **must keep compiling to `wasm32-unknown-unknown`** so the
future web app and browser extension can link it. On
`wasm32-unknown-unknown` there is **no system entropy backend**: pulling an RNG
into the core would mean pulling [`getrandom`](https://docs.rs/getrandom), which
has no `wasm32-unknown-unknown` backend without extra opt-in shims. That would
**break the wasm build** and **violate the `getrandom`-count invariant** that
keeps the audit-bound core minimal and wasm-pure
(`grep -c 'name = "getrandom"' libsigil/Cargo.lock` must stay `0` — see
[ADR 0002](0002-standalone-cli-crate-for-getrandom-isolation.md)).

Several of the core's primitives nonetheless require fresh entropy *somewhere*:
Argon2id needs a per-record **salt**, the XChaCha20-Poly1305 AEAD needs a
**nonce**, the classical Ed25519 sign/verify primitive
([`../../libsigil/core/src/sig.rs`](../../libsigil/core/src/sig.rs)) needs a
32-byte secret **signing seed**, the classical X25519 key-agreement primitive
([`../../libsigil/core/src/kx.rs`](../../libsigil/core/src/kx.rs)) needs a 32-byte
secret **scalar**, and the ML-KEM-768 post-quantum KEM primitive
([`../../libsigil/core/src/mlkem.rs`](../../libsigil/core/src/mlkem.rs)) needs a
64-byte **keygen seed** (`d || z`) and a 32-byte **encapsulation coin** (`m`). The
question is *who* generates that entropy.

## Decision

**`sigil-core` NEVER generates randomness.** Every secret input that needs
entropy is **supplied by the caller**:

- the **Argon2id salt** (KDF),
- the **AEAD nonce** (XChaCha20-Poly1305),
- the **Ed25519 signing seed** (the 32-byte secret key seed; signing itself is
  deterministic per RFC 8032, so no per-signature RNG is needed either),
- the **X25519 secret scalar** (the 32-byte key-agreement secret; the
  Diffie–Hellman is deterministic per RFC 7748, so no per-exchange RNG is needed
  either),
- the **ML-KEM-768 keygen seed** (`d || z`, 64 bytes) **and encapsulation coin**
  (`m`, 32 bytes) — the deterministic FIPS 203 variants consume this caller
  entropy, so neither key generation nor encapsulation calls an RNG inside the
  core (decapsulation is deterministic and needs no entropy).

The core contains **no key-generation, no salt-generation, and no
nonce-generation RNG** — not behind a feature flag, not on native targets. It
exposes primitives that *consume* caller-provided entropy and leaves the
*production* of that entropy to the host. Entropy generation (and seed/key
storage) lives in the callers: the demo `cli/` crate uses `getrandom` in its
**own** lockfile (ADR 0002), and the native clients / FFI hosts own it on their
platforms.

## Consequences

- The core stays **`wasm32-unknown-unknown`-pure and `getrandom`-free**; the
  `getrandom`-count guard stays `0` in `libsigil/Cargo.lock`, and the web app /
  extension can link the core unchanged.
- **Callers own entropy and storage.** The CLI, the native clients, and any FFI
  host are responsible for generating a strong salt/nonce/seed/scalar and for storing
  secret seeds and keys safely. A caller that supplies a weak or reused
  salt/nonce/seed/scalar undermines the construction — this responsibility is **explicit
  and by design**, surfaced at the API boundary, not hidden inside the core.
- This is a **deliberate architectural boundary, not an oversight**: the core is a
  pure transform over caller-supplied inputs. It keeps the audit surface small and
  the wasm invariant mechanical.
- **Pre-audit reality:** the primitives that consume this entropy (Argon2id, the
  AEAD, the standalone Ed25519 sign/verify, the standalone X25519 key-agreement,
  and the standalone ML-KEM-768 KEM) are **real but UNAUDITED** and not wired into
  a finished product; the two hybrid-KEM halves are now combined by the standalone
  hybrid KEM combiner ([`../../libsigil/core/src/hybrid.rs`](../../libsigil/core/src/hybrid.rs);
  [ADR 0011](0011-hybrid-kem-combiner.md)), which likewise consumes only
  caller-supplied ephemeral entropy (the ephemeral X25519 secret and the ML-KEM
  coin), and the ML-DSA-65 post-quantum signature half stays unimplemented. See
  [`../architecture.md`](../architecture.md) §1 and §6 and
  [`../crypto-spec.md`](../crypto-spec.md).
