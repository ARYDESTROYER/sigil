# Sigil cryptographic specification (condensed)

> **Internal / pre-audit. UNAUDITED.** This describes the intended design of
> `libsigil`. The code in this repo implements **real but UNAUDITED** building
> blocks — the algorithm-suite registry, the envelope codec, an Argon2id KDF, an
> XChaCha20-Poly1305 + HKDF AEAD, a composed `seal_record`/`open_record`, a
> standalone classical **Ed25519 sign/verify** primitive, a standalone
> **ML-DSA-65 (FIPS 204) post-quantum signature** primitive, a standalone
> classical **X25519 key-agreement** primitive, and a standalone
> **ML-KEM-768 (FIPS 203) post-quantum KEM** primitive — none wired into a
> finished product. The **combined hybrid KEM** (X25519 + ML-KEM-768, combined via
> HKDF-SHA-256) is now **assembled as a standalone primitive** in `sigil-core`
> (`hybrid.rs`), joining the two halves it composes. The **combined hybrid
> signature** (Ed25519 then ML-DSA-65; verification requires **both**) is now
> **assembled as a standalone primitive** too, in `sigil-core` (`hybrid_sig.rs`),
> composing the Ed25519 half (`sig.rs`) and the ML-DSA-65 half (`mldsa.rs`). So
> **both hybrid constructions (KEM and signature) now exist**. The hybrid **KEM** is
> further composed with the AEAD into **hybrid public-key authenticated encryption**
> — `hybrid_seal` / `hybrid_open` (`hybrid_seal.rs`) — and **that flow is no longer
> standalone: it now carries device-to-device VAULT-KEY WRAPPING** (see
> [Key hierarchy and vault sharing](#key-hierarchy-and-vault-sharing-hybrid_seal--hybrid_open-in-use)
> and [ADR 0035](decisions/0035-device-to-device-vault-sharing.md)), which makes it
> **load-bearing and squarely in scope for the audit**. It remains a **custom
> KEM-then-AEAD composition — NOT RFC 9180 HPKE** — it remains **UNAUDITED**, and it
> does **not** make the SYSTEM "post-quantum secure". The hybrid **signature**
> (`hybrid_sign` / `hybrid_verify`) is **still unused by every flow** — all request
> authentication is classical Ed25519 only. Condensed
> from the product brief §11/§20/§21. Subject to change. A Cure53 audit of the
> hybrid construction is to be commissioned before public beta.

## Design principle

The server cannot decrypt user data, ever. Every encrypted record crosses the
client→server boundary as opaque ciphertext over hybrid post-quantum TLS.

## Primitives (intended)

| Role | Primitive |
| --- | --- |
| Password KDF | Argon2id (m = 64 MiB, t = 4, p = 2) → 256-bit master key |
| Per-vault key | HKDF-SHA-256 from the master key, per-vault salt |
| AEAD | XChaCha20-Poly1305 (24-byte random nonce; suite byte + record ID as AAD) |
| Classical KEX | X25519 |
| PQ KEM | ML-KEM-768 (FIPS 203) |
| Classical signature | Ed25519 |
| PQ signature | ML-DSA-65 (FIPS 204) |
| Hashing | SHA-256, BLAKE3 |
| Transport | TLS 1.3, hybrid `X25519MLKEM768` named group |

## Algorithm-suite registry

A single suite byte in every record's header selects the `(KDF, KEM, AEAD,
signature)` tuple. New suites are *added* without breaking decryption of older
records — clients dispatch on the byte. This is the crypto-agility property that
lets post-quantum suites migrate without a flag-day re-encryption. Implemented
in [`libsigil/core/src/lib.rs`](../libsigil/core/src/lib.rs).

| Byte | Suite |
| --- | --- |
| `0x10` | Legacy: PBKDF2 + RSA + AES-GCM + ECDSA P-256 |
| `0x11` | Classical: Argon2id + X25519 + XChaCha20-Poly1305 + Ed25519 |
| `0x12` | **CURRENT** — hybrid PQ: Argon2id + X25519&ML-KEM-768 + XChaCha20-Poly1305 + Ed25519&ML-DSA-65 |
| `0x13` | Future: classical-only deprecated, hybrid required |
| `0x14` | Reserved backup: HQC-192 KEM + SLH-DSA-128f signatures (for an MLWE break) |
| `0x15` | Future: FN-DSA-512 signatures (smaller, for the watch) |

## Crypto-agility envelope (intended layout)

```
[0]   version    (u8)     envelope format version (currently 0x01)
[1]   suite_id   (u8)     algorithm suite (e.g. 0x12)
[2..] aad_length (varint) length of AAD
[..]  aad        (bytes)  additional authenticated data
[..]  nonce      (bytes)  AEAD nonce (length per suite)
[..]  ciphertext (bytes)  encrypted payload
[..]  tag        (bytes)  AEAD authentication tag
[..]  kem_ct     (bytes)  KEM ciphertext — present only on key-rotation records
```

**Implemented (format `0x01`):** [`libsigil/core/src/envelope.rs`](../libsigil/core/src/envelope.rs)
is a concrete, self-describing codec — each variable field carries an unsigned
LEB128 varint length prefix and a `flags` byte marks the optional `kem_ct`, so
the frame parses unambiguously (the brief's prose left nonce/ciphertext/tag
boundaries implicit-by-suite). It is **serialization only — no encryption** — and
is covered by round-trip + negative-case tests.

## Hybrid construction (intended)

**Key encapsulation** (per RFC 9794 / NIST SP 800-56C Rev. 2):

```
ss_x        = X25519(sk_x, pk_x_peer)
ss_kem      = ML-KEM-768.Decap(sk_kem, ct_kem)
ss_combined = HKDF-SHA-256(ss_x || ss_kem || transcript_hash, "sigil-hybrid-v1")
```

Secure if **either** component is secure: breaking the construction requires
breaking both X25519 and ML-KEM.

**Signatures**: `Ed25519.Sign(m) || ML-DSA-65.Sign(m)`; verification requires
**both** to validate.

**KEM implementation status (pre-audit, UNAUDITED).** **Both halves of the hybrid
KEM exist as separate primitives in `sigil-core`, and the combiner over them is now
in productive use** (it wraps vault keys — see the combiner note below and
[ADR 0035](decisions/0035-device-to-device-vault-sharing.md)). The **classical X25519
key-agreement half** (`ss_x` above) is **implemented** in
[`libsigil/core/src/kx.rs`](../libsigil/core/src/kx.rs): a raw-bytes
`x25519_public_key` / `x25519_shared_secret` Diffie–Hellman over a
**caller-supplied 32-byte secret scalar** (the core generates no key material —
see [ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md)), per RFC 7748,
that **rejects the all-zero / non-contributory shared secret**. Crucially, the
**raw X25519 output is not a key**: it must be run through HKDF — exactly as the
`ss_combined` line above specifies — before use.

The **ML-KEM-768 post-quantum half** (`ss_kem` above) is now **implemented** in
[`libsigil/core/src/mlkem.rs`](../libsigil/core/src/mlkem.rs): deterministic
FIPS 203 **keygen / encapsulate / decapsulate** built on the RustCrypto `ml-kem`
crate, over **caller-supplied entropy** — key generation from the 64-byte
`d || z` seed and encapsulation from the 32-byte `m` coin (the core generates no
key material and no coins — see
[ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md)). Decapsulation is
**total**: on a malformed or wrong ciphertext it returns the FIPS 203 **implicit
rejection** shared secret (a deterministic pseudo-random value derived from the
private key, never an error), so decaps never leaks a distinguishable failure.

Both primitives are **real but NOT YET AUDITED**. The **combined hybrid KEM
`ss_combined` is now IMPLEMENTED** in
[`libsigil/core/src/hybrid.rs`](../libsigil/core/src/hybrid.rs) as
`hybrid_encapsulate` / `hybrid_decapsulate`, the combiner that composes the two
halves above. Encapsulation runs the ephemeral X25519 exchange (`kx.rs`) and an
ML-KEM-768 encapsulation (`mlkem.rs`) — the **caller supplies the ephemeral X25519
secret and the ML-KEM coin** ([ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md);
the core still generates no entropy) — computes the transcript binding
`transcript_hash = SHA-256(ephemeral_x25519_pub || mlkem_ct)` over the ciphertext
material, and mixes `ss_x || ss_kem || transcript_hash` through `HKDF-SHA-256`
under the `"sigil-hybrid-v1"` label into one 32-byte `ss_combined`; decapsulation
recomputes the same transcript from the received ciphertexts and reproduces the
identical secret. It is **secure if EITHER component remains secure** — the
standard hybrid-combiner property, so breaking it requires breaking **both** X25519
and ML-KEM-768 — and the transcript binding stops an attacker splicing a
ciphertext from one exchange onto material from another. It is **real but
UNAUDITED**.

**It is no longer standalone.** Through `hybrid_seal` (below) this combiner now
carries **device-to-device vault-key wrapping** — the vault key of a shared vault
is encapsulated to a recipient device's hybrid public key
([ADR 0035](decisions/0035-device-to-device-vault-sharing.md)) — so a flaw in the
combiner is a flaw in a real user-facing path. Two things this does **not** change:
the envelope's `kem_ct` field is still *reserved* but unused (the ML-KEM ciphertext
travels alongside the envelope in the `SIGILhyb` container, not inside the
envelope frame), and the **SYSTEM is still not "post-quantum secure"** — the
combiner's property is that `ss_combined` stays secret if **either** half holds,
which is a statement about the construction, not about the product (see
[ADR 0011](decisions/0011-hybrid-kem-combiner.md)). The **hybrid signature**
(Ed25519 & ML-DSA-65) is assembled too — see the signature-implementation-status
note below — but **unlike the KEM it is still wired into nothing**.

**Signature implementation status (pre-audit, UNAUDITED).** **The combined hybrid
signature — and both halves it composes — now exist as standalone primitives in
`sigil-core`.** The **classical Ed25519 half** is implemented in
[`libsigil/core/src/sig.rs`](../libsigil/core/src/sig.rs): a deterministic RFC 8032
Ed25519 `sign`/`verify` over a **caller-supplied 32-byte secret seed** (the core
generates no key material — see
[ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md)). It is also
reachable over the **C-ABI** as `sigil_public_key_from_seed` / `sigil_sign` /
`sigil_verify` ([`libsigil/ffi/`](../libsigil/ffi/), `sigil.h`), and the demo
`cli` uses it in-crate to sign op-log requests (see [`api.md`](api.md) and
[ADR 0008](decisions/0008-device-key-request-auth.md)).

The **ML-DSA-65 post-quantum half** is now **implemented** in
[`libsigil/core/src/mldsa.rs`](../libsigil/core/src/mldsa.rs): deterministic
FIPS 204 **keygen / sign / verify** built on the RustCrypto `ml-dsa` crate, over a
**caller-supplied 32-byte keygen seed** (the FIPS 204 `xi`; the core generates no
key material — see
[ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md)). Signing is
**deterministic**: FIPS 204 permits a zero (all-zeros) randomizer, so `sign` is a
pure function of `(sk, message)` and needs no per-signature entropy — matching the
core's no-RNG discipline. Both halves are **real but NOT YET AUDITED**.

The **combined hybrid signature is now IMPLEMENTED** in
[`libsigil/core/src/hybrid_sig.rs`](../libsigil/core/src/hybrid_sig.rs) as
`hybrid_sign` / `hybrid_verify`, the combiner that composes the two halves above.
`hybrid_sign` produces `Ed25519.Sign(m) || ML-DSA-65.Sign(m)` — the 64-byte
Ed25519 signature (`sig.rs`) followed by the 3309-byte ML-DSA-65 signature
(`mldsa.rs`), a fixed **3373-byte** hybrid signature — over the **two
caller-supplied 32-byte seeds** (the Ed25519 signing seed and the ML-DSA-65 keygen
seed `xi`; [ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md), the core
generates no key material). Because both halves are deterministic (RFC 8032
Ed25519 and zero-randomizer FIPS 204 ML-DSA-65), the **hybrid signature is
deterministic** — a pure function of `(seeds, message)`, matching the core's no-RNG
discipline. `hybrid_verify` splits the 3373-byte signature and requires **BOTH**
the Ed25519 and the ML-DSA-65 half to validate over the message; if either fails,
verification fails. The honest property, asserted as design intent of an
**UNAUDITED** primitive: **a forgery requires breaking BOTH Ed25519 AND
ML-DSA-65** — the concatenate-and-require-both hybrid pattern — which is **not** a
claim that the SYSTEM is "post-quantum secure". It is **real but UNAUDITED and
STILL STANDALONE**: it is **not wired into a record / vault / account / session /
sharing flow**. Every signature `sigild` verifies — the op-log request contract
(v2 and v3), device enrollment proofs, and **every device-to-device sharing
route** — is **classical Ed25519 only**. So the two hybrid constructions are now in
**different states**, and the distinction matters: the hybrid **KEM** is
load-bearing (it wraps vault keys, via `hybrid_seal` — see above and
[ADR 0035](decisions/0035-device-to-device-vault-sharing.md)), while the hybrid
**signature** is not used anywhere. The remaining hybrid-crypto work is therefore
**authentication**: wiring `hybrid_sign` / `hybrid_verify` into the request/identity
model, and wiring either construction into the suite frame. The **SYSTEM is still
not "post-quantum secure"**. See
[ADR 0012](decisions/0012-hybrid-signature-combiner.md).

## Hybrid public-key authenticated encryption (`hybrid_seal` / `hybrid_open`)

**Status (pre-audit, UNAUDITED).** `sigil-core` now composes the hybrid **KEM**
with the symmetric AEAD into **hybrid public-key authenticated encryption** —
`hybrid_seal` / `hybrid_open` in
[`libsigil/core/src/hybrid_seal.rs`](../libsigil/core/src/hybrid_seal.rs). This is
the **first time a hybrid primitive is wired into an encryption flow**: until now
the hybrid KEM (`hybrid.rs`) and the AEAD (`aead.rs`) were separate building
blocks, and the only end-to-end path was the *symmetric*, password-derived one
(Argon2id → AEAD → envelope; `seal_record` / `open_record`). `hybrid_seal` instead
encrypts a record **to a recipient's hybrid public key** (an X25519 public key +
an ML-KEM-768 encapsulation key).

It is a **KEM-then-AEAD** construction:

```text
hybrid_seal(recipient_x25519_pub, recipient_mlkem_encaps_key,
            ephemeral_x25519_secret, mlkem_coin, nonce, aad, plaintext):
  (eph_x25519_pub, mlkem_ct, ss_combined) = hybrid_encapsulate(   # hybrid.rs
      recipient_x25519_pub, recipient_mlkem_encaps_key,
      ephemeral_x25519_secret, mlkem_coin)
  envelope = seal(master_key = ss_combined, nonce, aad, plaintext)  # aead.rs
  return (eph_x25519_pub, mlkem_ct, envelope)

hybrid_open(recipient_x25519_secret, recipient_mlkem_decaps_key,
            eph_x25519_pub, mlkem_ct, envelope):
  ss_combined = hybrid_decapsulate(                               # hybrid.rs
      recipient_x25519_secret, recipient_mlkem_decaps_key,
      eph_x25519_pub, mlkem_ct)
  return open(master_key = ss_combined, envelope)                  # aead.rs
```

The 32-byte hybrid shared secret `ss_combined` is used as the AEAD **master key**
(the AEAD then binds the suite byte into its per-record HKDF `info` as usual — see
the AEAD design above); it is never used as an AEAD key directly. The recipient
decapsulates with its hybrid secret keys to reproduce the identical `ss_combined`
and then authenticates/decrypts the envelope; a tampered ML-KEM ciphertext,
ephemeral public key, or envelope yields a different key or an authentication
failure, never plaintext.

Honest framing:

- This is a **CUSTOM KEM-then-AEAD composition — NOT RFC 9180 HPKE.** It reuses the
  crate's existing hybrid combiner and HKDF-bound AEAD rather than the HPKE key
  schedule, so it carries no HPKE interoperability or standardized analysis.
- The **caller supplies** the ephemeral X25519 secret, the ML-KEM coin, and the
  AEAD nonce ([ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md)); the
  core generates no randomness and stays `wasm32-unknown-unknown`-pure.
- It inherits the hybrid property of the KEM
  ([ADR 0011](decisions/0011-hybrid-kem-combiner.md)): `ss_combined` stays secret if
  **either** X25519 or ML-KEM-768 remains secure, and the transcript binding stops
  mix-and-match — asserted as design intent of an **UNAUDITED** primitive, **not** a
  claim that the SYSTEM is "post-quantum secure".
- It is **real but UNAUDITED**, and it is **no longer standalone**: `hybrid_seal` /
  `hybrid_open` now carry **device-to-device vault-key wrapping** (next section;
  [ADR 0035](decisions/0035-device-to-device-vault-sharing.md)). That is the first
  time a hybrid primitive does load-bearing work in a user-facing feature, and it
  is why this composition must be treated as **in-scope product code** by the
  audit rather than as a lab primitive. It is still **not** the product's *account*
  model, and there is still **no key-transparency / out-of-band verification** of a
  recipient's hybrid public key. The envelope's `kem_ct` field still stays
  *reserved* but unused — the ML-KEM ciphertext travels alongside the envelope here,
  not inside it. See [ADR 0013](decisions/0013-hybrid-public-key-seal.md).
- These hybrid primitives are also reachable over the **C-ABI** —
  `sigil_x25519_public_key`, `sigil_ml_kem768_keygen`, and `sigil_hybrid_*`
  (`encapsulate` / `decapsulate` / `seal` / `open`) in
  [`libsigil/ffi/`](../libsigil/ffi/) (`sigil.h`) — so native clients can generate a
  hybrid identity and encrypt to a recipient's hybrid public key. Still the same
  custom KEM-then-AEAD and still **UNAUDITED**; the **C-ABI itself** has no
  product consumer (the sharing flow reaches `hybrid_seal` through the Rust CLI
  crate, not through the FFI).

## Key hierarchy and vault sharing (`hybrid_seal` / `hybrid_open` in use)

**Status (pre-audit, UNAUDITED, dev-gated).** This is where the hybrid public-key
seal above stops being a demo. Device-to-device **vault sharing**
([ADR 0035](decisions/0035-device-to-device-vault-sharing.md)) uses it to
distribute a vault's encryption key to another enrolled device, so a second device
can open the same vault **without ever learning the owner's password**.

### The three layers

```
human password ──Argon2id(m,t,p; per-vault salt)──▶ seals a PERSONAL vault
                  (the SIGILcli container)
                  NEVER shared. NEVER wrapped. NEVER sent anywhere.

vault key = 32 bytes from the OS CSPRNG
                 ──▶ seals a SHARED vault, through the SAME SIGILcli container
                     (the container takes arbitrary password BYTES, so a random
                      key drops in with NO format change)
     │
     └── per recipient device:
         hybrid_seal( recipient_x25519_pub, recipient_mlkem_encaps_key,
                      eph_x25519_secret, mlkem_coin, nonce,
                      plaintext = the 32-byte vault key )
                 ──▶ (eph_x25519_pub, mlkem_ct, envelope)
                     packaged as a SIGILhyb container ≈ 1.2 KiB  ("the envelope")
```

The recipient reverses it with `hybrid_open` under its hybrid **secret** identity
(an X25519 secret scalar + an ML-KEM-768 keygen seed), recovering exactly 32 bytes;
anything other than 32 bytes is rejected rather than used as a key.

- **The human password is never shared and never wrapped.** Sharing it would hand a
  recipient every *other* vault sealed under it and would make revocation mean
  "change your password everywhere". A per-vault random key is rotatable in
  principle (re-key + re-share) and reveals nothing about the user.
- **Fresh ephemeral entropy per wrap.** The ephemeral X25519 secret, the ML-KEM coin
  and the AEAD nonce are drawn from a CSPRNG on **every** call, so two shares
  of the same key never reuse randomness. Consistent with
  [ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md), all of it is
  supplied by the caller — the OS CSPRNG in the CLI, `crypto.getRandomValues` in the
  browser clients; `sigil-core` still generates nothing.
- **Keys are never printed.** A vault key is shown only as
  `vault_key_fingerprint` — the first 16 hex characters of its SHA-256 — so two
  devices can confirm they hold the same key without revealing it.

### The same hierarchy, exercised from the browser

This hierarchy is **not CLI-specific**. The webapp and the MV3 extension run the
identical construction through [`../sigil-wasm/sharing.mjs`](../sigil-wasm/sharing.mjs)
(`generateVaultKey` → `wrapVaultKey` / `shareVault` → `acceptVault` /
`unwrapVaultKey`, with `vaultKeyFingerprint` computing the same 16-hex SHA-256 prefix
via `crypto.subtle`). **The wrap and unwrap still happen inside the wasm** —
`hybrid_seal_to_container` / `hybrid_open_container`, i.e. `sigil-core`'s
`hybrid_seal` / `hybrid_open` — so there is no second implementation of the
construction and no JS-side cryptography; the JS supplies entropy and moves bytes. The
recovered-plaintext length check (exactly 32 bytes, else reject) is mirrored in
`unwrapVaultKey`. A shared vault sealed by a browser is byte-compatible with one sealed
by the CLI, and vice versa: `sharing-interop.mjs` shares a vault **both ways** between
the JS client and the real `sigil` binary and both ends reach the same fingerprint and
the same RFC 6238 code. Where the CLI keeps the hybrid secret and the keyring in `0600`
files, the browser clients keep them inside their **sealed device-identity container**
([ADR 0036](decisions/0036-browser-sharing-secret-storage.md)) — sealed with the same
Argon2id → XChaCha20-Poly1305 `SIGILcli` construction as a vault.

### What the server sees, and what it cannot do

`sigild` **relays** the envelope: `PUT`/`GET /v1/vaults/{vaultID}/keys/{deviceID}`
store and return the bytes **verbatim** (see [`api.md`](api.md)). Concretely the
server holds:

| The server has | The server does **not** have |
|----------------|------------------------------|
| device hybrid **public** keys (32-byte X25519 + 1184-byte ML-KEM-768 encaps key) | any hybrid **secret** identity — decapsulation keys never leave a device |
| the opaque envelope (`SIGILhyb` ciphertext) | the vault key inside it, or any plaintext |
| device IDs, a vault ID, a size, a timestamp | the user's password, or anything derived from it |
| a SHA-256 **fingerprint** of the envelope in the audit log | the envelope's contents in any log or metric |

So the server **cannot decapsulate** (no secret key), **cannot decrypt** the vault
that key protects, and **cannot mint** a valid envelope for a device without that
device's public key producing ciphertext only that device can open. Its **only**
inspection of key material is a **length check** (32 / 1184 bytes) — it does not
decode a curve point, screen for low-order elements, or verify that the two halves
of a hybrid public key belong together. That is deliberate: validating key material
would be the server performing cryptography on it. Correctness of a published key
is the **client's** business.

### Honest limits (read these with the section above)

- **UNAUDITED**, dev-gated (`501` by default), plain HTTP on localhost. Do not
  store real 2FA secrets.
- **Custom KEM-then-AEAD, NOT RFC 9180 HPKE** — no HPKE interoperability, no
  standardized analysis.
- **The system is NOT "post-quantum secure."** The wrap is designed to stay secret
  if **either** X25519 or ML-KEM-768 holds; that is a property of the construction.
- **No out-of-band verification of a recipient's hybrid public key.** A device
  trusts what the registry serves. A malicious server that substitutes its own
  hybrid public key would receive a vault key wrapped to itself. There is no
  safety-number, key-transparency, or cross-signature mechanism.
- **No forward secrecy for a delivered vault key, no rotation schedule, and no
  re-wrap on revoke.** Revocation stops **future** server access; it cannot make a
  device forget a key it already unwrapped. Remediation is a manual `vault rekey`
  + re-share. Republishing a hybrid key does not re-wrap already-deposited
  envelopes.
- **Authentication of the sharing routes is classical Ed25519 only** (contract v3).
  The wrap is hybrid; the request signature is not.
- **No zeroization of key material in the clients.** Rust `Vec`s and JS
  `Uint8Array`s holding a vault key or a hybrid secret are dropped, not wiped; in the
  browser they stay live in the JS heap for as long as the vault is unlocked.
- **The Argon2id pass over an already-uniform 32-byte vault key is redundant work**,
  kept deliberately so the shared vault is byte-identical in shape to a personal
  one and no client's container parser changes. Replacing it with a direct KDF is a
  future, format-breaking change.

## HOTP / TOTP one-time-password primitive (`hotp` / `totp`)

**Status (pre-audit, UNAUDITED).** `sigil-core` now implements the **authenticator
primitive** the product is named for: **RFC 4226 HOTP** and **RFC 6238 TOTP**, in
[`libsigil/core/src/totp.rs`](../libsigil/core/src/totp.rs). This is the **first
primitive that implements an actual product feature** rather than a general
cryptographic building block. The OTP math is **real** and checked against the
official RFC known-answer vectors; it is still **UNAUDITED** and pre-audit.

The primitive is three functions over an `OtpAlgorithm` selector
(`Sha1` (default) / `Sha256` / `Sha512`), returning `OtpError` for out-of-range
arguments:

```rust
pub fn hotp(key: &[u8], counter: u64, digits: u32,
            algorithm: OtpAlgorithm) -> Result<u32, OtpError>;

pub fn totp(key: &[u8], unix_time: u64, period: u32, t0: u64, digits: u32,
            algorithm: OtpAlgorithm) -> Result<u32, OtpError>;

pub fn format_code(code: u32, digits: u32) -> String;   // zero-padded
```

- **`hotp`** is RFC 4226 §5.3: `HMAC-H(key, counter_be64)` under the chosen hash,
  then **dynamic truncation** — the low nibble of the last MAC byte is an offset,
  a big-endian **31-bit** integer (top bit masked) is read from
  `MAC[offset..offset+4]`, and reduced modulo `10^digits`.
- **`totp`** is RFC 6238 §4: it forms the time counter
  `T = (unix_time - t0) / period` and defers to `hotp`. `t0` is the epoch offset
  (usually `0`) and `period` the time step in seconds (usually `30`).
- **`format_code`** renders the numeric code as a zero-padded fixed-width string
  (so `073921` keeps its leading zero).
- `digits` is bounded `MIN_DIGITS..=MAX_DIGITS` (**6..=10**); `OtpError` covers
  `InvalidDigits`, `InvalidPeriod` (zero period), and `TimeBeforeT0`.

**No clock, no RNG — the caller supplies the time.** Consistent with
[ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md), `totp` takes the
current Unix time as a **`u64` argument** and reads no system clock; the native
binary (or the browser) supplies it, exactly as callers supply salts, nonces, and
seeds. There is no in-core time source and no randomness here, so the
`wasm32-unknown-unknown` / `no_std` / `getrandom`-free build is preserved.

**Dependencies (both `getrandom`-free).** The HMAC uses RustCrypto
[`hmac`](https://docs.rs/hmac) (already in the tree transitively via `hkdf`, now a
direct dependency) with `sha1` for HMAC-SHA-1 and the existing `sha2` for
SHA-256/512. `sha1` is **new** and required for interop: real-world authenticator
apps and `otpauth://` provisioning are overwhelmingly HMAC-SHA-1, so SHA-1 is the
default and interoperability *demands* it (this is HMAC-SHA-1, a keyed MAC — not
SHA-1 as a collision-resistant hash). Both crates are `default-features = false`,
which keeps `getrandom`/`rand` out and the core lockfile guard
(`grep -c 'name = "getrandom"' libsigil/Cargo.lock` == 0) intact.

**Verified against the RFC vectors.** In-module tests check `hotp` against **RFC
4226 Appendix D** (the ten 6-digit HMAC-SHA-1 values for counters 0..=9) and
`totp` against the complete **RFC 6238 Appendix B** table (8-digit codes at six
reference times for SHA-1 / SHA-256 / SHA-512, with the RFC's per-hash key
lengths).

**Scope / caveats (honest, pre-audit).** The module **only generates** codes; it
does **not** verify a user-entered code — a constant-time compare and any validity
window are the caller's responsibility. It does **not** zeroize the key or
intermediate HMAC state beyond what the dependencies do. It is a **real but
UNAUDITED** building block; do **not** store real 2FA secrets in this pre-audit
build.

**First product-feature consumer: the CLI's encrypted TOTP vault.** The demo
`cli` wires this primitive into a `sigil totp` vault (`add` / `list` / `code` /
`remove`, with base32 and `otpauth://` import). Secrets are stored in a
`TotpVault` JSON that is **sealed at rest with the same `SIGILcli` password
container as `seal`/`open`** (Argon2id + XChaCha20-Poly1305), so a TOTP vault is
just another opaque sealed container — E2EE at rest, and syncable through the
op-log later with no new format. The CLI supplies the wall clock and the entropy;
the core supplies only the OTP math. See
[ADR 0023](decisions/0023-totp-hotp-primitive-and-cli-vault.md).

## Migration plan (intended)

1. **Today** — all new data at suite `0x12`.
2. **2026 Q4** — add `0x13`; deprecate classical-only `0x11`; warn on `0x11` records.
3. **2027 Q2** — register `0x14` (HQC + SLH-DSA) backup, not yet active.
4. **2028** — re-encrypt remaining `0x11` at `0x12`+; server rejects `0x11` writes.
5. **Q-Day / threshold** — classical-only verification disabled; hybrid required.
