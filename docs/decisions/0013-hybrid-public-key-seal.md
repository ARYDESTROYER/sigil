# 0013 — Hybrid public-key seal (KEM-then-AEAD over the hybrid KEM)

- **Status:** Accepted — 2026-07.

## Context

The hybrid **KEM** already existed in `sigil-core` as a standalone primitive
([ADR 0011](0011-hybrid-kem-combiner.md)): `hybrid_encapsulate` /
`hybrid_decapsulate` in
[`../../libsigil/core/src/hybrid.rs`](../../libsigil/core/src/hybrid.rs) produce a
32-byte combined shared secret `ss_combined` to a recipient's hybrid public key
(an X25519 public key + an ML-KEM-768 encapsulation key). The symmetric AEAD layer
([`../../libsigil/core/src/aead.rs`](../../libsigil/core/src/aead.rs)) already
sealed a record under a 32-byte master key. But **nothing composed them**: the KEM
produced a key and the AEAD consumed a key, yet no function encrypted a record *to
a recipient's public key*. Every end-to-end path to date was the **symmetric**,
password-derived one (Argon2id → AEAD → envelope; `seal_record` / `open_record`),
and — as [ADR 0011](0011-hybrid-kem-combiner.md) and
[ADR 0012](0012-hybrid-signature-combiner.md) record — **neither** hybrid
construction was wired into any encryption flow at all.

The core also **generates no randomness** ([ADR 0007](0007-caller-supplied-entropy-in-core.md))
— it must stay `wasm32-unknown-unknown`-pure and `getrandom`-free — so a
public-key seal cannot mint the sender's ephemeral X25519 secret, the ML-KEM
encapsulation coin, or the AEAD nonce; those come from the caller, exactly as they
do for every other core primitive.

## Decision

Implement **hybrid public-key authenticated encryption** in
[`../../libsigil/core/src/hybrid_seal.rs`](../../libsigil/core/src/hybrid_seal.rs)
as `hybrid_seal` / `hybrid_open`, a **KEM-then-AEAD** composition over the two
existing building blocks:

- **`hybrid_seal`** takes the recipient's hybrid public key (X25519 public key +
  ML-KEM-768 encapsulation key), the **caller-supplied** ephemeral X25519 secret +
  ML-KEM coin + AEAD nonce (per [ADR 0007](0007-caller-supplied-entropy-in-core.md),
  the core generates none), AAD, and plaintext. It runs `hybrid_encapsulate`
  (`hybrid.rs`) to derive `ss_combined` and the two ciphertexts, then calls the
  XChaCha20-Poly1305 AEAD `seal` (`aead.rs`) with **`ss_combined` as the master
  key**, and returns `(ephemeral X25519 public key, ML-KEM-768 ciphertext,
  envelope)`.
- **`hybrid_open`** takes the recipient's hybrid secret keys (X25519 secret +
  ML-KEM-768 decapsulation key), the two ciphertexts, and the envelope. It runs
  `hybrid_decapsulate` to recover the same `ss_combined`, then `open`s the envelope,
  authenticating AAD / nonce / ciphertext / tag and returning the plaintext.

`ss_combined` is used as the AEAD **master key** (the AEAD then binds the suite
byte into its per-record HKDF `info`, as it always does); it is never used as an
AEAD key directly. This is a **custom KEM-then-AEAD composition**, explicitly **not
RFC 9180 HPKE** — there is no HPKE key schedule, exporter secret, or per-message
sequence number; it reuses the crate's existing hybrid combiner and HKDF-bound AEAD
as the symmetric stage.

## Consequences

- **First integration of a hybrid primitive into an encryption flow.** Before this,
  both hybrid constructions were bare primitives; the hybrid KEM is now composed
  with the AEAD into an actual encrypt-to-a-recipient's-public-key flow. This
  complements — it does not replace — the password-derived symmetric path
  (`seal_record`).
- **Caller still owns all entropy** ([ADR 0007](0007-caller-supplied-entropy-in-core.md)):
  the ephemeral X25519 secret, the ML-KEM coin, and the AEAD nonce. A caller that
  supplies weak or reused ephemeral entropy, or reuses a (key, nonce) pair,
  undermines the construction — an explicit, by-design responsibility at the API
  boundary. The core stays RNG-free, wasm-pure, and `getrandom`-free.
- **Inherits the hybrid property and its caveats** ([ADR 0011](0011-hybrid-kem-combiner.md)):
  `ss_combined` stays secret if **either** X25519 or ML-KEM-768 remains secure, and
  the transcript binding stops mix-and-match. This is design intent of an
  **UNAUDITED** primitive; it does **not** make the SYSTEM "post-quantum secure".
- **Bespoke, not HPKE — a deliberate tradeoff.** Reusing the crate's own combiner
  and AEAD keeps the audit surface minimal and avoids a new dependency, at the cost
  of the standardization and third-party analysis RFC 9180 HPKE would bring. The
  future Cure53 audit must weigh this composition on its own.
- **Still not the product model.** `hybrid_seal` / `hybrid_open` is a **crypto-level**
  primitive/flow, **not** the product's account / key-management / vault-storage
  model, and is **not** used by `sigild` or the CLI. Suite `0x12`'s `kem_ct`
  envelope field stays *reserved* but unused (the ML-KEM ciphertext travels
  alongside the envelope, not inside it); the op-log still stores opaque
  symmetric-sealed blobs. The remaining crypto work is wiring the hybrid primitives
  into an actual account/session/record model; see
  [`../crypto-spec.md`](../crypto-spec.md) and
  [`../architecture.md`](../architecture.md) §6.
