# 0004 — Crypto-agility via an algorithm-suite registry

- **Status:** Accepted — 2026-06.

## Context

Sigil is positioned as a post-quantum-*ready* authenticator. The primitives it
will use are expected to change over the product's life: hybrid PQ suites will be
introduced, classical-only suites deprecated, and backup suites registered in
case a lattice assumption breaks. A design that hard-codes one
`(KDF, KEM, AEAD, signature)` tuple would force a **flag-day re-encryption** of
every stored record each time the primitives change — operationally painful and
risky.

Records also need to be self-describing: a reader must know which suite a record
was sealed under, years after it was written, without out-of-band context.

## Decision

Carry a single one-byte **algorithm-suite id** *inside* every record's envelope
frame, and dispatch on it. The registry is `AlgorithmSuite` in
[`../../libsigil/core/src/lib.rs`](../../libsigil/core/src/lib.rs):

| Byte | Role |
| --- | --- |
| `0x10` | legacy |
| `0x11` | classical |
| `0x12` | **CURRENT** — hybrid post-quantum-*ready* |
| `0x13`–`0x15` | reserved / future |

`AlgorithmSuite::CURRENT` is `0x12`. Adding a suite means appending a variant
(the enum is `#[non_exhaustive]`), teaching the affected layer to handle it, and
starting to write the new byte for new records — **older bytes remain
decodable**, so there is no flag-day re-encryption. The suite byte is
additionally **bound into the per-record HKDF `info`**
(`"sigil-record-v1" || suite_byte`), so a record sealed under one suite cannot be
opened by deriving a key for another.

The **full suite table, the intended hybrid construction** (X25519 & ML-KEM-768
key encapsulation, Ed25519 & ML-DSA-65 signatures), **and the migration
timeline** live in [`../crypto-spec.md`](../crypto-spec.md) — this ADR records
the *decision* to be suite-agile and does not duplicate that spec.

## Consequences

- New suites are **added, not swapped**: post-quantum and future suites can be
  introduced without re-encrypting existing records, and old records keep
  opening.
- Records are self-describing — the suite byte travels with the data — and the
  HKDF binding makes cross-suite key confusion fail closed.
- **Pre-audit reality:** today only the **symmetric path runs** (Argon2id → HKDF
  → XChaCha20-Poly1305 → envelope codec). The **KEM and signature halves of the
  suites are specified and reserved** (the `kem_ct` envelope field exists) **but
  not implemented**; suite `0x12`'s "hybrid PQ" name describes the intended
  construction, not running code. This is **unaudited** and not wired into a
  finished product. See [`../architecture.md`](../architecture.md) §3 and §6 and
  [`../crypto-spec.md`](../crypto-spec.md).
