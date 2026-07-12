# 0012 — Hybrid signature combiner (Ed25519 then ML-DSA-65)

- **Status:** Accepted — 2026-07.

## Context

Suite `0x12` — the current suite ([ADR 0004](0004-crypto-agility-suite-registry.md))
— specifies a **hybrid** signature, `Ed25519 & ML-DSA-65`, so that a signed
artifact stays unforgeable as long as *either* the classical (elliptic-curve) or
the post-quantum (lattice) assumption holds. Both halves already existed in
`sigil-core` as **standalone** primitives — the classical RFC 8032 Ed25519
sign/verify in [`../../libsigil/core/src/sig.rs`](../../libsigil/core/src/sig.rs)
and the ML-DSA-65 (FIPS 204) sign/verify in
[`../../libsigil/core/src/mldsa.rs`](../../libsigil/core/src/mldsa.rs) — but
nothing combined them: there was **no combiner**, so no single hybrid signature
existed. This mirrored the situation the **KEM** was already past, once its
combiner landed in `hybrid.rs` ([ADR 0011](0011-hybrid-kem-combiner.md)).

The crypto-spec already fixed the shape of the combiner:
`Ed25519.Sign(m) || ML-DSA-65.Sign(m)`, with verification requiring **both** halves
to validate. Unlike a KEM, a signature combiner needs no KDF and no transcript
binding — a signature already commits to the message `m`, and the two component
signatures cover the *same* `m` — so the construction is a plain concatenation of
the two fixed-length signatures plus an AND over the two verifications.

The core also **generates no randomness** ([ADR 0007](0007-caller-supplied-entropy-in-core.md))
— it must stay `wasm32-unknown-unknown`-pure and `getrandom`-free — so the
combiner cannot mint the signing keys itself; the two seeds come from the caller,
as they do for both underlying primitives. This is compatible with a hybrid
signature because **both halves are deterministic**: RFC 8032 Ed25519 signing is
deterministic, and FIPS 204 permits a zero (all-zeros) ML-DSA-65 randomizer, so
neither half draws per-signature entropy and the combined signature is a pure
function of `(seeds, message)`.

## Decision

Implement the combiner in
[`../../libsigil/core/src/hybrid_sig.rs`](../../libsigil/core/src/hybrid_sig.rs) as
`hybrid_sign` / `hybrid_verify`, composing the two existing halves into a single
hybrid signature exactly as the crypto-spec specifies:

- **`hybrid_sign`** takes the **two caller-supplied 32-byte seeds** — the Ed25519
  signing seed and the ML-DSA-65 keygen seed `xi` (per
  [ADR 0007](0007-caller-supplied-entropy-in-core.md), the core generates neither)
  — and a message, and returns the concatenation
  `Ed25519.Sign(m) || ML-DSA-65.Sign(m)`: the **64-byte** Ed25519 signature
  (`sig.rs`) followed by the **3309-byte** ML-DSA-65 signature (`mldsa.rs`), a fixed
  **3373-byte** hybrid signature. Because both halves are deterministic, the hybrid
  signature is **deterministic**.
- **`hybrid_verify`** takes the two public keys, the message, and the 3373-byte
  signature, splits it at the fixed 64-byte boundary, and requires **BOTH** the
  Ed25519 half and the ML-DSA-65 half to validate over the message. If either half
  fails, verification fails.

The two halves are ordered classical-then-PQ (`64 || 3309`) at a fixed offset, so
the split needs no length prefix; the lengths are compile-time constants
(`SIGNATURE_LEN`, `ML_DSA65_SIGNATURE_LEN`).

## Consequences

- **One signature with the hybrid property.** A valid `hybrid_sign` output is
  unforgeable unless **BOTH** Ed25519 **and** ML-DSA-65 are broken — the
  concatenate-and-require-both property. This is a property of the *construction*,
  asserted as design intent of an **UNAUDITED** primitive; it is honest to describe
  the property (a forgery requires breaking both schemes) but it does **not** make
  the SYSTEM "post-quantum secure".
- **Caller still owns the seeds.** The combiner consumes two caller-supplied 32-byte
  seeds; the core stays RNG-free, wasm-pure, and `getrandom`-free
  ([ADR 0007](0007-caller-supplied-entropy-in-core.md)). A caller that supplies weak
  or reused seeds undermines the construction — an explicit, by-design responsibility
  at the API boundary.
- **Completes the hybrid crypto suite as standalone primitives.** With the hybrid
  **KEM** (`hybrid.rs`; [ADR 0011](0011-hybrid-kem-combiner.md)) and now the hybrid
  **signature** (`hybrid_sig.rs`), **both** hybrid constructions of suite `0x12`
  exist as real, UNAUDITED, standalone primitives.
- **Still UNAUDITED and standalone.** The combined hybrid signature is **not wired
  into any record / vault / account / session flow** — e.g. the `sigild` op-log
  request auth still uses **classical Ed25519 only** — suite `0x12`'s "hybrid PQ"
  name still describes the intended wiring, not a running product path, and the
  **SYSTEM is still not "post-quantum secure"**. It awaits the Cure53 audit. The
  remaining crypto work is now **wiring** the hybrid primitives into an actual flow;
  see [`../crypto-spec.md`](../crypto-spec.md) and
  [`../architecture.md`](../architecture.md) §6.
