# 0011 — Hybrid KEM combiner (X25519 & ML-KEM-768 via HKDF)

- **Status:** Accepted — 2026-07.

## Context

Suite `0x12` — the current suite ([ADR 0004](0004-crypto-agility-suite-registry.md))
— specifies a **hybrid** key encapsulation, `X25519 & ML-KEM-768`, so that a
vault's key agreement stays secure as long as *either* the classical
(elliptic-curve) or the post-quantum (lattice) assumption holds. Both halves
already existed in `sigil-core` as **standalone** primitives — the classical
X25519 Diffie–Hellman in [`../../libsigil/core/src/kx.rs`](../../libsigil/core/src/kx.rs)
and the ML-KEM-768 (FIPS 203) KEM in
[`../../libsigil/core/src/mlkem.rs`](../../libsigil/core/src/mlkem.rs) — but
nothing combined them: there was **no combiner**, so no single hybrid shared
secret existed.

A hybrid KEM is not just the concatenation of two shared secrets. Getting one
32-byte key that inherits the OR-security property requires a **combiner** with
two properties: (1) it must mix both component secrets so that either one being
secure keeps the output secure; and (2) it must **bind the ciphertext material**
so an attacker cannot splice a component ciphertext from one exchange onto
material from another (a mix-and-match / non-committing attack). The crypto-spec
already fixed the shape of this combiner (RFC 9794 / NIST SP 800-56C Rev. 2
concatenation-KDF style):
`ss_combined = HKDF-SHA-256(ss_x || ss_kem || transcript_hash, "sigil-hybrid-v1")`.

The core also **generates no randomness** ([ADR 0007](0007-caller-supplied-entropy-in-core.md))
— it must stay `wasm32-unknown-unknown`-pure and `getrandom`-free — so the
combiner cannot mint the ephemeral X25519 secret or the ML-KEM encapsulation coin
itself; that entropy has to come from the caller, as it does for every other
core primitive.

## Decision

Implement the combiner in
[`../../libsigil/core/src/hybrid.rs`](../../libsigil/core/src/hybrid.rs) as
`hybrid_encapsulate` / `hybrid_decapsulate`, composing the two existing halves
into a single 32-byte hybrid shared secret exactly as the crypto-spec specifies:

- **Encapsulation** takes the recipient's X25519 public key and ML-KEM-768
  encapsulation key plus **caller-supplied ephemeral entropy** — the ephemeral
  X25519 secret and the ML-KEM coin `m` (per [ADR 0007](0007-caller-supplied-entropy-in-core.md),
  the core generates neither). It runs the ephemeral X25519 exchange (`kx.rs`) for
  `ss_x`, an ML-KEM-768 encapsulation (`mlkem.rs`) for `(mlkem_ct, ss_kem)`,
  computes the **transcript binding** `transcript_hash = SHA-256(ephemeral_x25519_pub
  || mlkem_ct)` over the ciphertext material, and derives
  `ss_combined = HKDF-SHA-256(ss_x || ss_kem || transcript_hash, "sigil-hybrid-v1")`.
  It returns the two ciphertexts (`ephemeral_x25519_pub`, `mlkem_ct`) and
  `ss_combined`.
- **Decapsulation** takes the recipient's X25519 secret and ML-KEM decapsulation
  key and the received ciphertexts, recovers `ss_x` and `ss_kem`, **recomputes the
  same `transcript_hash` from the received ciphertexts**, and reproduces the
  identical `ss_combined`.

The label `"sigil-hybrid-v1"` domain-separates this combiner from every other
HKDF use in the core. The output is one 32-byte secret; the raw component secrets
are never used directly as keys.

## Consequences

- **One key with the hybrid-combiner property.** `ss_combined` is **secure if
  EITHER** X25519 or ML-KEM-768 remains secure — breaking it requires breaking
  **both**. This is the standard concatenation-KDF hybrid property; it is a
  property of the *construction*, asserted as design intent of an **UNAUDITED**
  primitive, and it does **not** make the SYSTEM "post-quantum secure".
- **Transcript binding prevents mix-and-match.** Folding
  `SHA-256(ephemeral_x25519_pub || mlkem_ct)` into the KDF ties the derived key to
  the exact pair of ciphertexts, so a spliced or substituted component ciphertext
  yields a different key rather than a usable one.
- **Caller still owns all entropy.** The combiner consumes a caller-supplied
  ephemeral X25519 secret and ML-KEM coin; the core stays RNG-free, wasm-pure, and
  `getrandom`-free ([ADR 0007](0007-caller-supplied-entropy-in-core.md)). A caller
  that supplies weak or reused ephemeral entropy undermines the construction — an
  explicit, by-design responsibility at the API boundary.
- **Still UNAUDITED and standalone.** The combined hybrid KEM is **not wired into
  any record / vault / account / session flow**; the envelope's `kem_ct` field
  stays *reserved* but unused, and suite `0x12`'s "hybrid PQ" name still describes
  the intended wiring, not a running product path. It awaits the Cure53 audit.
- **The hybrid signature remains future.** This ADR covers only the KEM. The
  hybrid `Ed25519 & ML-DSA-65` signature still lacks its **ML-DSA-65 post-quantum
  half**, so the combined hybrid signature does not yet exist. See
  [`../crypto-spec.md`](../crypto-spec.md) and [`../architecture.md`](../architecture.md) §6.
