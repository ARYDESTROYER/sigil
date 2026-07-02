# 0014 — X-Wing as the suite-0x12 hybrid KEM (drop the bespoke combiner)

- **Status:** Accepted — 2026-07.

## Context

Suite `0x12` names a hybrid X25519 & ML-KEM-768 KEM. Both halves now exist as
standalone primitives ([ADR 0010](0010-x25519-key-agreement-primitive.md),
[ADR 0013](0013-ml-kem-768-pq-kem-primitive.md)). The product brief — and until
now [`../crypto-spec.md`](../crypto-spec.md) — *sketched* a bespoke combiner:
`HKDF-SHA-256(ss_x ‖ ss_kem ‖ transcript_hash, "sigil-hybrid-v1")`, with the
transcript undefined, no security analysis, and no test vectors.

Since that sketch was written, the IETF CFRG draft **X-Wing**
(draft-connolly-cfrg-xwing-kem) standardized exactly this hybrid — ML-KEM-768 +
X25519 — with a formal IND-CCA proof (Barbosa, Connolly, Duarte, Kaiser,
Schwabe, Varner, Westerbaan; IACR CiC 1(1):21) and official test vectors. Its
combiner has been byte-exact stable since revision -05 (2024); we pin **-10**
(2026-03-02).

## Decision

Implement the suite-`0x12` hybrid KEM as **X-Wing, faithfully**, in
[`../../libsigil/core/src/hybrid.rs`](../../libsigil/core/src/hybrid.rs),
composed from our existing `kex`/`mlkem` modules plus the already-in-tree `sha3`
crate. **Drop the bespoke `sigil-hybrid-v1` combiner** — spec follows analysis,
not vice versa; an auditor reviews a named, proven construction against
published KATs instead of a one-off.

- **Construction** (byte-exact per draft-10):
  `ss = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label)`, label = the 6 ASCII bytes
  `\.//^\` hashed **last**; `pk = pk_M ‖ pk_X` (1216 B); `ct = ct_M ‖ ct_X`
  (1120 B); `sk` = a 32-byte seed, SHAKE-256-expanded to ML-KEM `(d, z)` ‖
  `sk_X` — the **seed is the decapsulation key** (components re-derived, never
  stored).
- **Deterministic caller-seeded APIs** (`xwing_keygen(seed[32])`,
  `xwing_encapsulate(ek, eseed[64])`, `xwing_decapsulate(seed, ct)`) — these are
  the draft's own derandomized functions, so KAT-verifiability and
  [ADR 0007](0007-caller-supplied-entropy-in-core.md) coexist; the core still
  generates no randomness.
- **Proof shape** (recorded for the audit): classically, IND-CCA in the ROM
  under gap-DH on Curve25519 — hashing `ct_X ‖ pk_X` into the combiner is what
  makes the DH side CCA-secure; post-quantum, a standard-model reduction to
  ML-KEM-768's IND-CCA with SHA3-256 as a PRF keyed by `ss_M`. Omitting the
  ML-KEM `pk`/`ct` from the hash is proven safe via ML-KEM's
  ciphertext-collision resistance (an FO-transform property) — **this shortcut
  is FO-specific; reusing the combiner with a different PQ KEM is unsound.**
- **No contributory/low-order check inside the hybrid** — per the draft,
  decapsulation is total (the proof covers small-order `ct_X` because the
  combiner binds `ct_X ‖ pk_X`); adding a rejection would deviate from the
  analyzed construction and create an explicit rejection oracle.
  `kex::is_contributory` remains the documented escape hatch for raw-DH users
  only.
- **The RustCrypto `x-wing` crate is rejected** on hard facts: its only current
  release requires MSRV 1.85 + edition 2024 (ours: 1.81, ADR 0013) and pins a
  duplicate pre-release copy of half our crypto tree (`ml-kem` 0.3-rc,
  `x25519-dalek` 3-pre, `sha3` 0.11-rc, a second `curve25519-dalek`) — ~19
  duplicate lock entries. The composition we need is ~60 lines over existing,
  already-locked modules, and it reproduces **all three official test vectors
  byte-for-byte** (verified first-hand: the vectors were re-downloaded from the
  draft's reference repo and the literals generated mechanically; the SHAKE-256
  seed-expansion split was verified against an independent implementation).

## Consequences

- The suite-`0x12` KEM now exists **as a primitive**: breaking it requires
  breaking both X25519 and ML-KEM-768. It is **not wired into the envelope,
  record API, or any product flow** — `kem_ct` stays reserved/`None` (populating
  it without a real recipient-key/rotation flow would be a dead path that *looks*
  like PQ protection — the fake-crypto failure mode). **Records still get no
  post-quantum protection today**, and there is still no post-quantum signature.
  Everything is UNAUDITED.
- [`../crypto-spec.md`](../crypto-spec.md) is updated: the bespoke
  `sigil-hybrid-v1` sketch is superseded by the X-Wing construction. Honest
  labeling: X-Wing is a **pre-RFC individual CFRG draft**, never to be called a
  "standard" (only its FIPS 203 component is a NIST standard) — public copy must
  not say "standards-based hybrid".
- **Dependency/lock delta: one manifest line, zero new packages** (`sha3` was
  already in the tree via ml-kem; declared directly with
  `default-features = false` — mandatory, or feature unification would re-enable
  `std` crate-wide). `getrandom` stays 0; wasm32 stays green; MSRV stays 1.81.
- Draft-revision watch: recheck the combiner + vectors when X-Wing becomes an
  RFC (bytes frozen since -05, so editorial-only is expected) and bump the
  citation.
- Future ADRs will cover: wiring the 1120-byte X-Wing ciphertext into the
  envelope's `kem_ct` (needs a recipient static-key model, an ss→record-key
  wrap, and rotation semantics), and suite-aware `kem_ct` length validation in
  the envelope decoder.
