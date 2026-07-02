# 0013 — ML-KEM-768 primitive (post-quantum KEM half, caller-supplied seeds)

- **Status:** Accepted — 2026-07.

## Context

Suite `0x12` ([ADR 0004](0004-crypto-agility-suite-registry.md),
[`../crypto-spec.md`](../crypto-spec.md)) names a **hybrid** key encapsulation:
classical **X25519** *and* post-quantum **ML-KEM-768** (FIPS 203), combined by an
HKDF so the construction holds if *either* component holds. The classical X25519
half landed as a standalone primitive in
[ADR 0010](0010-x25519-key-agreement-primitive.md); the post-quantum half — the
reason the product says "post-quantum-*ready*" at all — remained
specified-but-not-implemented.

The constraints are the crate-wide ones
([ADR 0007](0007-caller-supplied-entropy-in-core.md),
[ADR 0002](0002-standalone-cli-crate-for-getrandom-isolation.md)):
`#![forbid(unsafe_code)]`, `no_std`, `wasm32-unknown-unknown` must keep building,
**`getrandom` must never enter `libsigil/Cargo.lock`**, and no primitive may
generate its own randomness.

## Decision

Add [`../../libsigil/core/src/mlkem.rs`](../../libsigil/core/src/mlkem.rs): a
real (but **UNAUDITED**) FIPS 203 **ML-KEM-768** primitive, backed by the
RustCrypto **`ml-kem`** crate
(`version = "0.2", default-features = false, features = ["deterministic", "zeroize"]`).

- **Deterministic, caller-seeded API — no RNG.** `mlkem768_keygen(d, z)` takes
  the two 32-byte FIPS 203 seeds; `mlkem768_encapsulate(ek, m)` takes the 32-byte
  encapsulation randomness `m`; `mlkem768_decapsulate(dk, ct)` is deterministic.
  The `deterministic` feature exposes the same FIPS 203 internal algorithms with
  the RNG hoisted to the caller (byte-identical output to the RNG-driven path) —
  exactly the ADR 0007 stance: the core consumes caller entropy, never produces
  it. The caller MUST draw `d`, `z`, and `m` fresh from a CSPRNG.
- **Raw fixed-size byte API**, mirroring `kex.rs`/`sig.rs`: `[u8; N]` arrays plus
  `MLKEM768_*_LEN` constants (ek 1184, dk 2400, ct 1088, ss 32, seeds 32).
  Keygen returns FIPS 203 order `(ek, dk)`.
- **We implement the FIPS 203 §7.2 encapsulation-key "modulus check" ourselves**,
  because ml-kem 0.2.3 does **not**: its decoder silently reduces non-canonical
  coefficients mod q, which would accept keys a conformant peer rejects.
  `mlkem768_encapsulate` re-encodes the parsed key and compares; a mismatch is
  `MlKemError::BadEncapsulationKey` — the module's only reachable error. (The
  key is public; the comparison need not be constant-time.)
- **Implicit rejection is preserved, not wrapped.** Per FIPS 203, decapsulating
  a tampered/mismatched ciphertext returns a *different pseudorandom* shared
  secret, never an error — deliberately, since a "decapsulation failed" signal
  would create a CCA oracle. This is documented loudly; callers must confirm
  agreement via use of the secret (e.g. AEAD open), never via error absence.
- **Raw primitive, no sigil domain label.** FIPS 203 has no domain-separation
  hook and a label would break KAT verifiability; domain separation binds once,
  in the future hybrid combine (`HKDF(ss_x ‖ ss_kem ‖ transcript,
  "sigil-hybrid-v1")`), exactly as record keys bind `sigil-record-v1` in
  `aead.rs` rather than inside XChaCha20.
- **KATs with verified provenance.** The keygen test is a **true interop KAT**
  against NIST ACVP (usnistgov/ACVP-Server @ `65370b8`, ML-KEM-768 keyGen tgId 2
  tcId 26): the official `(d, z)` reproduce ek/dk whose SHA-256 digests match
  digests computed directly from the downloaded NIST file, and ml-kem's output
  was verified **byte-for-byte identical** to the official ek/dk before pinning.
  The encaps test is a **cross-checked chained vector** (official ACVP `m` under
  that key; ct/ss cross-checked by two independent implementations), labeled as
  such — ACVP has no seed-chained keygen→encaps case.

## Consequences

- The core now holds **both halves** of the suite-`0x12` KEM as real, standalone,
  UNAUDITED primitives — but the **hybrid combine still does not exist**, the two
  shared secrets are never mixed, `kem_ct` in the envelope stays reserved/unused,
  and **records sealed today still gain no post-quantum protection**. No
  over-claim: only the *primitive* is real.
- **MSRV bump 1.74 → 1.81** across `core`/`ffi`/`cli` manifests, forced by
  `hybrid-array` (a required `ml-kem` dep). Local/CI toolchains (1.96/stable) are
  unaffected. Note: `zeroize` must stay on the locked 1.8.x line (1.9.0 is
  MSRV 1.85).
- Lockfile gains `ml-kem`, `hybrid-array`, `kem`, `sha3`, `keccak` — all RNG-free
  and `build.rs`-free; **`getrandom` count stays 0** and the wasm32 build stays
  green (`rand_core` remains trait-definitions-only without its `getrandom`
  feature). The `zeroize` feature enables ml-kem's internal Drop scrub of its
  decapsulation key; our stack copies of encoded bytes remain unscrubbed (a
  documented crate-wide pre-audit gap).
- **dk integrity is the caller's responsibility** (a garbage dk "decapsulates"
  deterministically; the FIPS 203 §7.3 dk hash check is not performed here) —
  mitigated by the documented recommendation to **store the 64-byte `d ‖ z` seed
  instead of the 2400-byte dk** and re-derive on demand (FIPS 203 permits this;
  the seed is exactly as secret as the dk).
- A future ADR will record the hybrid combine (transcript definition, HKDF
  labeling, and how `kem_ct` is bound under the AEAD) when it is actually built.
