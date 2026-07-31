# Sigil system architecture (condensed)

> **STATUS: pre-audit skeleton.** This is the *system shape* of the repository
> as it stands today (the 72-hour foundation sprint, through the dev-gated
> op-log and its optional Ed25519 device-key request auth). It is **not** a
> shipping product. `libsigil` contains **real but
> UNAUDITED** cryptographic building blocks — an Argon2id KDF, an
> XChaCha20-Poly1305 + HKDF-SHA256 AEAD, a composed `seal_record`/`open_record`,
> and a C-ABI over them — that are **not wired into a finished
> account/key-management product**. `sigild` performs **no cryptography on vault
> content** and stores only opaque blobs — ⚠️ **which is not the same as "no
> cryptography", and this line used to say the wrong one.** `sigild` really does
> verify Ed25519 request signatures, hash the op-log chain with SHA-256, digest
> enrollment tokens and verify provider webhook HMACs in constant time, and it
> really does hold **public** device keys, published **public** hybrid keys and
> webhook **secrets**. What it holds none of is a key that can **decrypt a
> vault**. No security claims hold yet: nothing here is
> "audited", "secure", "post-quantum secure", "SOC 2", or unqualified
> "end-to-end encrypted". **Do not store real secrets.**
>
> This document complements its siblings rather than repeating them:
> [`crypto-spec.md`](crypto-spec.md) is the algorithm/primitive authority,
> [`api.md`](api.md) is the `sigild` HTTP contract, [`threat-model.md`](threat-model.md)
> is the adversary/defense table, [`deployment.md`](deployment.md) is the (not
> applied) deploy story, and [`sprint-72h.md`](sprint-72h.md) holds the
> definition of done and the **defer ledger**. The repo root
> [`../CLAUDE.md`](../CLAUDE.md) is the working guide (and the source of the
> known-green build commands cross-linked below); [`../README.md`](../README.md)
> is the public-facing overview.

---

## 1. Component map

Sigil splits cleanly into a **client-side cryptographic core** (which does all
the crypto **on user data**) and a **server skeleton** (which does none of
*that* — but which does authenticate, hash-chain and verify webhooks with real
cryptography of its own; see the status note above). The pieces in this repo:

- **`libsigil/core`** ([`../libsigil/core/`](../libsigil/core/)) — the Rust
  crypto core. `#![forbid(unsafe_code)]`, `no_std` (uses `core` + `alloc`), and
  compiles to `wasm32-unknown-unknown` so the future web app / extension can link
  it. It contains:
  - the **algorithm-suite registry** (`AlgorithmSuite`, bytes `0x10`–`0x15`,
    current `0x12`) and the `ENVELOPE_VERSION` constant;
  - the **crypto-agility envelope codec** (`Envelope::encode`/`decode`) — a
    self-describing wire frame, serialization only;
  - the **Argon2id KDF** (`derive_master_key`, `Argon2Params`) — password → 32-byte
    master key. ⭐ Since Phase 59 it also owns the two rules that make a container's
    **unauthenticated** work factors safe to act on
    ([ADR 0047](decisions/0047-container-parameter-ceiling-and-no-downgrade-ratchet.md)):
    a **ceiling** (`MAX_M_COST` 256 MiB / `MAX_T_COST` 16 / `MAX_P_COST` 16, validated
    **before any allocation**, `KdfError::ParamsTooLarge`) and the **no-downgrade
    ratchet** (`Argon2Params::no_downgrade`). Both live here so the CLI, the desktop and
    the wasm binding **reach** them rather than copy them — a drift downward would be
    invisible;
  - the **XChaCha20-Poly1305 + HKDF-SHA256 AEAD** (`seal`/`open`) — per-record key
    derivation plus authenticated encryption;
  - the **composed record API** (`seal_record`/`open_record`) — the single
    end-to-end call (Argon2id → AEAD → envelope codec) that adds no new crypto;
  - the **classical Ed25519 signature primitive** (`sign`/`verify`) — a
    deterministic RFC 8032 sign/verify over a **caller-supplied 32-byte secret
    seed** (real but UNAUDITED; a standalone primitive). It is the classical half
    of suite `0x12`'s hybrid `Ed25519 & ML-DSA-65` signature — now composed with
    its ML-DSA-65 sibling (below) by the hybrid-signature combiner
    (`hybrid_sig.rs`, further below);
  - the **ML-DSA-65 post-quantum signature primitive**
    ([`../libsigil/core/src/mldsa.rs`](../libsigil/core/src/mldsa.rs):
    `keygen`/`sign`/`verify`) — deterministic FIPS 204, on the RustCrypto `ml-dsa`
    crate, over a **caller-supplied 32-byte keygen seed** (the FIPS 204 `xi`; the
    core generates no key material). Signing is deterministic (FIPS 204 permits a
    zero randomizer, so `sign` is a pure function of `(sk, message)`), so it draws
    no per-signature entropy. Real but UNAUDITED. It is the post-quantum half of
    the hybrid `Ed25519 & ML-DSA-65` signature — now composed with the Ed25519
    half above by the hybrid-signature combiner (`hybrid_sig.rs`, below);
  - the **classical X25519 key-agreement primitive**
    (`x25519_public_key`/`x25519_shared_secret`) — a raw-bytes RFC 7748
    Diffie–Hellman over a **caller-supplied 32-byte secret scalar** that rejects
    the all-zero / non-contributory shared secret (real but UNAUDITED; the raw DH
    output is not a key — it must be run through HKDF). It is a standalone
    primitive, **not yet** combined with its ML-KEM-768 sibling (below) into the
    hybrid `X25519 & ML-KEM-768` key encapsulation of suite `0x12`;
  - the **ML-KEM-768 post-quantum KEM primitive**
    ([`../libsigil/core/src/mlkem.rs`](../libsigil/core/src/mlkem.rs):
    `keygen`/`encapsulate`/`decapsulate`) — deterministic FIPS 203, on the
    RustCrypto `ml-kem` crate, over **caller-supplied entropy** (key generation
    from the 64-byte `d || z` seed, encapsulation from the 32-byte `m` coin; the
    core generates no key material and no coins), with **total, implicit-rejection**
    decapsulation (a wrong/malformed ciphertext yields the FIPS 203 deterministic
    reject secret, never an error). Real but UNAUDITED. It is one of the two KEM
    halves the combined hybrid KEM (next) composes;
  - the **combined hybrid KEM**
    ([`../libsigil/core/src/hybrid.rs`](../libsigil/core/src/hybrid.rs):
    `hybrid_encapsulate` / `hybrid_decapsulate`) — the **combiner** that assembles
    the X25519 and ML-KEM-768 halves above into one 32-byte shared secret
    `ss_combined`. Encapsulation runs the ephemeral X25519 exchange (`kx.rs`) and an
    ML-KEM-768 encapsulation (`mlkem.rs`) over **caller-supplied** ephemeral entropy
    (the ephemeral X25519 secret and the ML-KEM coin), binds both ciphertexts with
    `transcript_hash = SHA-256(ephemeral_x25519_pub || mlkem_ct)`, and mixes
    `ss_x || ss_kem || transcript_hash` through `HKDF-SHA-256` under the
    `"sigil-hybrid-v1"` label. Secure if **either** component stays secure (the
    standard hybrid-combiner property); the transcript binding prevents
    mix-and-match. Real but UNAUDITED. It is **no longer standalone**: through
    `hybrid_seal` (below) this combiner now carries **device-to-device vault-key
    wrapping** ([`decisions/0035-device-to-device-vault-sharing.md`](decisions/0035-device-to-device-vault-sharing.md)),
    so it is load-bearing product code. It is still **not wired into suite `0x12`**
    (the envelope's `kem_ct` field stays reserved — the ML-KEM ciphertext travels
    alongside the envelope), and the system is still not "post-quantum secure". See
    [`decisions/0011-hybrid-kem-combiner.md`](decisions/0011-hybrid-kem-combiner.md).
  - the **combined hybrid signature**
    ([`../libsigil/core/src/hybrid_sig.rs`](../libsigil/core/src/hybrid_sig.rs):
    `hybrid_sign` / `hybrid_verify`) — the **combiner** that assembles the Ed25519
    and ML-DSA-65 halves above into one signature. `hybrid_sign` concatenates
    `Ed25519.Sign(m)` (64 bytes) then `ML-DSA-65.Sign(m)` (3309 bytes) into a fixed
    **3373-byte** signature over the **two caller-supplied 32-byte seeds** (the
    Ed25519 signing seed and the ML-DSA-65 keygen seed `xi`); it is
    **deterministic** (both halves are, so the core draws no per-signature entropy).
    `hybrid_verify` splits the signature and requires **BOTH** halves to validate —
    so a forgery requires breaking **both** Ed25519 and ML-DSA-65 (the
    concatenate-and-require-both property; not a claim the system is "post-quantum
    secure"). Real but UNAUDITED and — **unlike its KEM sibling above — STILL
    STANDALONE**: it is not wired into suite `0x12` or into any
    record/vault/account/session/sharing flow. Every signature `sigild` verifies
    (op-log contracts v2 and v3, enrollment proofs, and **every vault-sharing
    route**) is **classical Ed25519 only**, and the system is still not
    "post-quantum secure".
    See [`decisions/0012-hybrid-signature-combiner.md`](decisions/0012-hybrid-signature-combiner.md).
  - the **hybrid public-key authenticated encryption** flow
    ([`../libsigil/core/src/hybrid_seal.rs`](../libsigil/core/src/hybrid_seal.rs):
    `hybrid_seal` / `hybrid_open`) — a **KEM-then-AEAD** composition that encrypts a
    record **to a recipient's hybrid public key** (an X25519 public key + an
    ML-KEM-768 encapsulation key). `hybrid_seal` runs the hybrid KEM (`hybrid.rs`)
    to encapsulate a fresh 32-byte shared secret to the recipient, uses that secret
    as the master key for the XChaCha20-Poly1305 AEAD (`aead.rs`), and returns
    `(ephemeral X25519 public key, ML-KEM-768 ciphertext, envelope)`; `hybrid_open`
    decapsulates with the recipient's hybrid secret keys to recover the same secret,
    then authenticates and decrypts the envelope. Caller-supplied ephemeral X25519
    secret + ML-KEM coin + AEAD nonce (the core generates no randomness). This is a
    **bespoke composition — NOT RFC 9180 HPKE**. Real but UNAUDITED, and **no longer
    standalone: it is now the mechanism that distributes vault keys between
    devices.** `sigil vault share` wraps a shared vault's random 32-byte vault key to
    a recipient device's hybrid public key with exactly this call, and `sigild`
    relays the result as an opaque envelope it cannot read
    ([`decisions/0035-device-to-device-vault-sharing.md`](decisions/0035-device-to-device-vault-sharing.md)).
    That makes it **load-bearing product code and squarely in scope for the audit**.
    It is still **not** the product's *account* model; out-of-band verification of a
    recipient's hybrid public key now **exists** as a client-side safety number
    plus key pinning (§2c), but it protects first contact only if a human actually
    compares the digits; and the
    envelope's `kem_ct` field stays reserved — the ML-KEM ciphertext travels
    alongside the envelope. See
    [`decisions/0013-hybrid-public-key-seal.md`](decisions/0013-hybrid-public-key-seal.md).
  - the **HOTP / TOTP one-time-password primitive**
    ([`../libsigil/core/src/totp.rs`](../libsigil/core/src/totp.rs): `hotp` /
    `totp` / `format_code`, over an `OtpAlgorithm` enum — SHA-1 (default) /
    SHA-256 / SHA-512) — **RFC 4226 HOTP** (dynamic truncation) and **RFC 6238
    TOTP**, checked against the RFC 4226 Appendix D / RFC 6238 Appendix B
    known-answer vectors. This is the **first primitive that implements an actual
    product *feature*** (generating a 2FA code) rather than a general building
    block. Consistent with the no-clock / no-RNG invariant, **`totp` takes the
    current Unix time as a caller-supplied `u64` argument** — the core reads no
    clock and no randomness, so the wasm-pure build is preserved. It adds two
    `getrandom`-free deps: `hmac` (the keyed MAC, already transitively present via
    `hkdf`, now direct) and the **new** `sha1` (HMAC-SHA-1 is the near-universal
    `otpauth://` default, so interop requires it; `sha2` is already a dep). Real
    but UNAUDITED; it only *generates* codes (verification is left to callers). See
    [`decisions/0023-totp-hotp-primitive-and-cli-vault.md`](decisions/0023-totp-hotp-primitive-and-cli-vault.md).

  Consistent with the above, **`core` generates NO randomness** — the Argon2 salt,
  the AEAD nonce, the Ed25519 signing seed, the ML-DSA-65 keygen seed (`xi`), the
  X25519 secret scalar, and the ML-KEM-768 keygen seed (`d || z`) and encapsulation
  coin (`m`) — including the ephemeral X25519 secret and ML-KEM coin the hybrid KEM
  combiner consumes and the two 32-byte seeds the hybrid signature combiner
  consumes — are
  **all caller-supplied**, so the core stays `wasm32-unknown-unknown`-pure and
  `getrandom`-free (see
  [`decisions/0007-caller-supplied-entropy-in-core.md`](decisions/0007-caller-supplied-entropy-in-core.md)).
- **`libsigil/ffi`** ([`../libsigil/ffi/`](../libsigil/ffi/)) — a thin, hand-written
  **C-ABI** over the core: the AEAD layer `sigil_seal` / `sigil_open` /
  `sigil_buffer_free`, and — alongside it — the classical **Ed25519** primitive
  `sigil_public_key_from_seed` / `sigil_sign` / `sigil_verify`, so the same
  standalone, UNAUDITED sign/verify the CLI uses is reachable over the C-ABI too.
  The C-ABI now **also exposes the hybrid encryption path** —
  `sigil_x25519_public_key`, `sigil_ml_kem768_keygen`, and
  `sigil_hybrid_encapsulate` / `sigil_hybrid_decapsulate` / `sigil_hybrid_seal` /
  `sigil_hybrid_open` — so a native client can generate a hybrid identity and
  encrypt a record **to a recipient's hybrid public key** through the FFI. That is
  the same **custom KEM-then-AEAD** composition as the core's `hybrid_seal`
  (**NOT** RFC 9180 HPKE) and still **real but UNAUDITED**; note that the **C-ABI
  itself has no product consumer** — the vault-sharing flow reaches `hybrid_seal`
  through the Rust `cli` crate, not through the FFI. (Plus `sigil_current_suite` as
  a link/smoke check.) All with a
  hand-maintained [`sigil.h`](../libsigil/ffi/include/sigil.h). This is the seam the
  native clients (in separate repos) will link against. It is the only crate with
  `unsafe` (the FFI boundary); `core` forbids it.
- **`cli`** ([`../cli/`](../cli/)) — `sigil`, a **pre-audit demonstration** binary.
  `seal`/`open` wrap one file in a self-describing container via the real
  `sigil-core` record API; `push`/`pull` move that **opaque** container to/from a
  **dev/localhost** `sigild` op-log over **plain HTTP** (no TLS). It now **also**
  has hybrid public-key encryption commands — `hybrid-keygen` / `hybrid-seal` /
  `hybrid-open` — that exercise the core's `hybrid_seal` / `hybrid_open` to encrypt
  a file **to a device's hybrid public identity** (an X25519 public key + an
  ML-KEM-768 encapsulation key). This is the **first user-facing use of the hybrid
  encryption path**, but it is still a **demo over UNAUDITED primitives**: a
  **custom KEM-then-AEAD** composition (**NOT** RFC 9180 HPKE), and **not** the
  product's account / key-management model. It now **also** has an **encrypted
  TOTP vault** — `sigil totp add` / `list` / `code` / `remove` (with base32 and
  `otpauth://` import) — the **first user-facing product feature**: it generates
  RFC 4226/6238 codes with the core's `totp` primitive and stores the 2FA secrets
  in a `TotpVault` **sealed at rest with the same `SIGILcli` password container as
  `seal`/`open`** (so a vault is just another opaque sealed container — E2EE at
  rest, and syncable through the op-log later with no new format). The CLI supplies
  the wall clock and the entropy; the core supplies only the OTP math (see
  [`decisions/0023-totp-hotp-primitive-and-cli-vault.md`](decisions/0023-totp-hotp-primitive-and-cli-vault.md)).
  The vault also **imports and exports** existing 2FA — `sigil totp import` ingests a
  **Google Authenticator** bulk-export migration URI
  (`otpauth-migration://offline?data=…`, parsed by a hand-rolled, dependency-free
  protobuf decoder in [`../cli/src/migration.rs`](../cli/src/migration.rs)), a single
  `otpauth://` URI, or a file of URIs, and `sigil totp export` prints entries back as
  `otpauth://` URIs or one combined `otpauth-migration://` URI — so users can migrate
  their 2FA **in** (adoption) and back **out** (no lock-in). The vault's on-disk
  `TotpVault` JSON schema is **unchanged** (the browser mirror stays intact); HOTP
  entries in a migration payload are warned-and-skipped because the vault is TOTP-only.
  Honest framing: still **dev / UNAUDITED**, and `export` reveals the secrets in the
  clear **by design** (an export is plaintext provisioning material) behind a loud
  warning (see
  [`decisions/0025-totp-import-export.md`](decisions/0025-totp-import-export.md)).
  The CLI is also **the first (and so far only) client that can SHARE a vault
  between devices** — `sigil device hybrid-publish` plus `sigil vault rekey` /
  `share` / `accept` / `list`. `rekey` re-seals a password vault under a fresh
  random 32-byte **vault key** (same `SIGILcli` container, no format change);
  `share` fetches the recipient's hybrid **public** key, wraps that vault key to it
  with the core's `hybrid_seal` path, uploads the **opaque** envelope, and grants
  access through the existing grant route; `accept` collects the envelope and
  unwraps it with the local hybrid **secret** identity. Vault keys live in a `0600`
  keyring (`$HOME/.sigil/vault-keys.json`) that is **never synced**, are **never
  printed** (only a 16-hex-character SHA-256 fingerprint), and the human password
  is **never shared or wrapped**. `sigil totp …` gained `--vault-id <id>` to open a
  key-sealed vault instead of a password-sealed one — purely additive, so existing
  invocations are unchanged. This is the **first load-bearing use of the hybrid
  primitives**; it is still **dev / localhost / plain-HTTP / UNAUDITED**, a
  **custom KEM-then-AEAD (NOT RFC 9180 HPKE)**, and revocation cannot make a device
  forget a key it already accepted (see
  [`decisions/0035-device-to-device-vault-sharing.md`](decisions/0035-device-to-device-vault-sharing.md)).
  A **standalone crate** with its own lockfile (see
  [§4](#4-build--dependency-isolation)). Keeps a loud UNAUDITED /
  not-for-real-secrets banner.
- **`sigil-wasm`** ([`../sigil-wasm/`](../sigil-wasm/)) — a thin
  [`wasm-bindgen`](https://rustwasm.github.io/wasm-bindgen/) binding over the
  `sigil-core` **record API**, exposing `seal_record` / `open_record` (plus
  `nonce_len` / `recommended_salt_len` / `version`) to JavaScript. It is the
  **first thing to actually consume the wasm-pure core** — the client column,
  reserved until now, has started. It adds **no cryptography of its own** (all
  crypto stays in `#![forbid(unsafe_code)]` `sigil-core`; this crate only marshals
  bytes and cannot itself `forbid(unsafe_code)` because `#[wasm_bindgen]` generates
  `unsafe` glue). Its point is to carry the **caller-supplied-entropy invariant all
  the way out to a JS runtime**: the Argon2id **salt** and the AEAD **nonce** are
  generated in JavaScript with `crypto.getRandomValues` and passed **into** the
  wasm as byte arrays, so both the core **and** this binding stay `getrandom`-free
  (proven mechanically — `getrandom` appears in neither `libsigil/Cargo.lock` nor
  `sigil-wasm/Cargo.lock`). Like `cli`, it is a **standalone crate** with its own
  lockfile, path-depending on `../libsigil/core` and **not** a member of the
  `libsigil` workspace (see [§4](#4-build--dependency-isolation)), so it can never
  perturb the audit-bound core lockfile. It builds via
  [`../sigil-wasm/build-wasm.sh`](../sigil-wasm/build-wasm.sh) (wasm-pack) into
  gitignored `pkg-web/` (browser ESM) + `pkg-node/` (Node CJS) artifacts, and is
  exercised by a Node round-trip test, native `#[cfg(test)]` unit tests, and a
  browser `demo/`. **It is now INTEROPERABLE with the `sigil` CLI:** the
  `seal_to_container` / `open_container` exports read and write the exact same
  self-describing **`SIGILcli` container** the CLI does (magic `SIGILcli`,
  version `1`, the three Argon2 cost params as `u32` little-endian, a `u8`-prefixed
  salt, then the envelope; AEAD `AAD = sigil-cli/1`), so **seal-in-browser →
  `sigil open`** and **`sigil seal` → open-in-browser** both round-trip. The
  container constants are **mirrored** in `sigil-wasm/src/lib.rs` and
  `cli/src/lib.rs` (each value carries a comment tying it to the other file — there
  is **no shared crate**), guarded by a native golden-header test plus a Node
  interop test (`test/interop.mjs`) that shells to the **real** built CLI binary in
  both directions. ⚠️ **Those three `u32` cost params are the one part of the frame
  a reader must act on before it can authenticate anything**, which since Phase 59
  means both sides range-check them **before any allocation** and both re-seal
  through the **no-downgrade ratchet** — reaching `sigil-core`'s `Argon2Params`
  rather than mirroring it, unlike the format constants above
  ([ADR 0047](decisions/0047-container-parameter-ceiling-and-no-downgrade-ratchet.md)). It wraps **only** the symmetric `seal_record` / `open_record` /
  container path — a **DEMONSTRATION** of the UNAUDITED building block, **NOT** the
  product's account / key-management model, and not for real secrets; the
  `SIGILcli` container is a **pre-audit CLI/demo container, not a frozen product
  wire format** (see [ADR 0020](decisions/0020-shared-client-container-format.md)).
  **It now also does HYBRID public-key (no-password) encryption** — the
  `hybrid_x25519_public` / `hybrid_mlkem_encaps_key` / `hybrid_seal_to_container` /
  `hybrid_open_container` exports encrypt a file **to** a device's hybrid identity
  (**X25519 + ML-KEM-768**) and decrypt it, reading and writing the same
  self-describing **`SIGILhyb` container** the CLI does (magic `SIGILhyb`,
  version `1`, `eph_x25519_pub[32]`, `mlkem_ct[1088]`, then the envelope; AEAD
  `AAD = sigil-hybrid-cli/1`). This is the **FIRST time the PQ-hybrid encryption
  path is exercised in a browser client** — the wasm client column now reaches all
  the way to the hybrid KEM-then-AEAD flow. All entropy stays JS-supplied (the
  X25519 secret, ML-KEM keygen seed, per-message ephemeral X25519 secret, ML-KEM
  coin, and AEAD nonce all come from `crypto.getRandomValues`, so both lockfiles
  stay `getrandom`-free); the wasm crate does **not** parse identity files, so Node
  bridges the CLI's identity JSON (fields `x25519_public_key` / `mlkem_encaps_key`
  / `x25519_secret` / `mlkem_seed`, standard-base64) into raw key bytes. Like
  `SIGILcli`, the `SIGILhyb` format constants are **mirrored** in
  `sigil-wasm/src/lib.rs` and `cli/src/lib.rs` (`HYBRID_MAGIC` / `HYBRID_AAD`; **no
  shared crate**) and pinned by a native golden fixed-prefix test plus a Node
  interop test (`test/hybrid-interop.mjs`) that shells to the **real** built CLI
  binary in **both** directions (wasm seals → `sigil hybrid-open`; `sigil
  hybrid-seal` → wasm opens). Honest framing: these are the same **UNAUDITED**
  building blocks, the composition is a **CUSTOM KEM-then-AEAD, NOT RFC 9180
  HPKE**, it is a **DEMO — not the product key-management model**, and the **system
  is still NOT "post-quantum secure"** (see
  [ADR 0021](decisions/0021-wasm-hybrid-public-key-encryption.md)).
  **The wasm client now also CLOSES THE CLIENT↔SERVER SYNC LOOP** — it reaches all
  the way to the `sigild` op-log. `sigil-wasm/sync.mjs` is a tiny, framework-free,
  dependency-free ESM transport (`pushContainer` / `pullContainers`) — the JS twin
  of the CLI's `sigil push` / `sigil pull` — that shuttles an **opaque** sealed
  container to/from a dev op-log over `fetch`. `pushContainer` POSTs the **raw
  container bytes** to `POST /v1/vaults/{id}/ops` (→ `201 {vaultID, seq}`);
  `pullContainers` drains `GET /v1/vaults/{id}/ops?since=&limit=` (→
  `{vaultID, ops:[{seq, blob, hash}], next, has_more}`, `blob`/`hash` standard-base64),
  looping `since=next` until `has_more` is false and base64-decoding each `blob`
  back to the exact pushed bytes. It runs in **both Node** (global `fetch` +
  `Buffer`) **and the browser** (`fetch` + `atob`); the demo `demo/` gains a **Sync**
  section over it. Because the container is **opaque**, `sigil-wasm` performs **no
  crypto in the transport** (the wasm seals *before* push) and the **server stays
  zero-knowledge** — it stores and re-emits the exact bytes. Crucially this
  **interoperates cross-client with the CLI** through the same server: the browser
  and `sigil` share the `SIGILcli` container **and** the op-log contract, so `sigil
  seal`+`push` → wasm `open_container` and wasm `seal_to_container`+push → `sigil
  pull`+`open` both round-trip. A live-server integration test
  ([`../sigil-wasm/test/sync-interop.mjs`](../sigil-wasm/test/sync-interop.mjs))
  proves it end-to-end: it builds `sigild` + the **real** CLI, boots a live sigild
  on a free localhost port (`SIGILD_ENABLE_DEV_OPS=1`, in-memory, no auth), and
  asserts a client self-loop, both cross-client directions, and an **OPAQUE** check
  that a raw `GET …/ops` blob base64-decodes to **exactly** the pushed bytes (the
  server did no crypto). Honest framing: this is **dev / localhost / plain-HTTP /
  no-auth** and **UNAUDITED** — it is **not** the product's sync model (no real
  auth / enrollment / CRDT / merge); it only demonstrates that the client column
  can reach the opaque op-log and interoperate with the CLI through it (see
  [ADR 0022](decisions/0022-wasm-client-server-sync-loop.md)).
  **The wasm client now GENERATES TOTP codes in the browser, cross-client with
  the CLI** — the **first end-to-end product feature working across two clients
  and the server**. Three `#[wasm_bindgen]` exports wrap the core OTP primitive
  ([ADR 0023](decisions/0023-totp-hotp-primitive-and-cli-vault.md)):
  `totp(key, unix_time, period, t0, digits, algorithm)`,
  `hotp(key, counter, digits, algorithm)`, and `format_code(code, digits)`. Per
  the no-clock invariant, **the JS caller supplies the Unix time** (`unix_time` /
  `t0` / `counter` arrive as `f64` and are validated to non-negative integers
  before the `u64` cast); the `algorithm` string map mirrors the CLI's, and
  TOTP/HOTP draw no entropy, so the crate stays `getrandom`-free. A small,
  framework-free ESM module
  ([`../sigil-wasm/totp-vault.mjs`](../sigil-wasm/totp-vault.mjs)) reads and
  writes the **same sealed `SIGILcli` TOTP vault the `sigil totp` CLI uses**
  (`openVault` / `sealVault` / `addEntry` / `codeForEntry` / `newVault` over
  `open_container` / `seal_to_container` / `totp` / `format_code`), performing no
  crypto of its own. The inner **`TotpVault` / `TotpEntry` JSON schema is
  MIRRORED — not shared — between `cli/src/lib.rs` and `totp-vault.mjs`**
  (version `1`; `label` / optional `issuer` / `secret` as standard base64 of the
  raw key bytes / lowercase `algorithm` / `digits` / `period`) and must stay in
  sync. Because the vault is just another opaque `SIGILcli` container, it rides
  the existing `sync.mjs` op-log transport unchanged, so **a secret added on one
  client and synced through the opaque, zero-knowledge op-log yields the same
  code on the other** — E2EE, with no server change. Proven end-to-end by
  ([`../sigil-wasm/test/totp-interop.mjs`](../sigil-wasm/test/totp-interop.mjs)):
  it asserts the wasm TOTP known-answer vectors (RFC 6238 App B, T=59,
  sha1/256/512), then has the **CLI add a secret → push → the browser pull →
  `openVault` → `codeForEntry(T=59)`** equal both the RFC vector `94287082` and
  an independent from-scratch Node HMAC-SHA-1 TOTP, and checks the server
  returned the bytes verbatim (opaque). The browser `demo/` gains a **TOTP
  authenticator vault** section (add a base32 secret, live codes, Seal→Push /
  Pull→Open). Honest framing: **UNAUDITED**, dev / localhost / plain-HTTP /
  no-auth, generation only (no verification / constant-time compare /
  zeroization); do not store real 2FA secrets
  (see [ADR 0024](decisions/0024-wasm-totp-vault-and-cross-client-totp.md)).
  **The browser client now also IMPORTS and EXPORTS TOTP, at parity with the CLI** —
  so **both** clients have full import/export. A framework-free, dependency-free ESM
  module ([`../sigil-wasm/totp-migration.mjs`](../sigil-wasm/totp-migration.mjs))
  gives the browser the same Google Authenticator bulk-import
  (`otpauth-migration://offline?data=…`) and single-account `otpauth://` import/export
  the `sigil totp import` / `sigil totp export` CLI has (`decodeMigrationUri` /
  `encodeMigrationUri` / `parseOtpauthUri` / `buildOtpauthUri`), and the demo `demo/`
  wires import + export over it. Like the container and vault formats, the migration
  **protobuf codec is MIRRORED — not shared — between the Rust CLI
  ([`../cli/src/migration.rs`](../cli/src/migration.rs)) and this JS module** (a
  hand-rolled, dependency-free proto3 codec on both sides — no protobuf library, no
  wasm bridge) and must stay in sync. Agreement is pinned by a Node CLI↔JS cross-tool
  test ([`../sigil-wasm/test/migration-interop.mjs`](../sigil-wasm/test/migration-interop.mjs))
  that builds the **real** CLI and proves both codecs are wire-compatible **both ways**
  — a GOLDEN Google Authenticator vector decoded via JS, `sigil totp export
  --migration` decoded in JS (RUST→JS), and a JS-encoded migration URI imported by the
  CLI (JS→RUST). Honest framing: still **dev / UNAUDITED**, and `export` reveals the
  2FA secrets **in the clear by design** (an export is plaintext provisioning
  material); do not import/export real 2FA secrets in this build (see
  [ADR 0026](decisions/0026-browser-totp-import-export.md)).
  **The wasm client can now also AUTHENTICATE as an enrolled device** — the client half
  of `sigild`'s multi-device auth model (contract v3,
  [ADR 0031](decisions/0031-multi-device-auth-model.md)). Three new `#[wasm_bindgen]`
  exports thinly wrap `sigil-core`'s classical Ed25519 primitive —
  `ed25519_public_key(seed)`, `ed25519_sign(seed, message)` and
  `ed25519_verify(public_key, message, signature)` — so a browser client can hold a
  **device identity** and sign with the **same real crypto the CLI uses**. The 32-byte
  seed is a **caller argument** (JS draws it with `crypto.getRandomValues`) and Ed25519
  signing is deterministic, so nothing here draws entropy and **both lockfiles stay
  `getrandom`-free**; an RFC 8032 known-answer vector pins the implementation. On top of
  them, [`../sigil-wasm/device-auth.mjs`](../sigil-wasm/device-auth.mjs) is a
  framework-free, dependency-free ESM module (Node **and** browser) implementing the
  client half of the contract: `generateDeviceSeed` / `devicePublicKey`, `enrollDevice`,
  `signedFetch` / `makeSignedFetch`, `pushContainerAuthed` / `pullContainersAuthed`,
  `grantVaultAccess` / `listVaultGrants`, `revokeSelf` / `revokeDeviceAdmin` /
  `listDevices`, the sealed-identity helpers `sealDeviceIdentity` / `openDeviceIdentity`,
  and `DeviceAuthError` / `explainAuthStatus`. **All signing happens in the wasm**
  (`ed25519_sign`) — there is no JS-side signing — and the enrollment token's SHA-256
  digest comes from `crypto.subtle`. The canonical byte layouts (`canonicalV3Message` /
  `canonicalEnrollMessage` / `enrollTokenHash`) are **MIRRORED — not shared — from
  `sigild/internal/api/deviceauth.go` and `cli/src/lib.rs`**, so the layout now lives in
  **three** implementations that must stay byte-identical (drift does not fail loudly; it
  just yields `401` on every request). `sync.mjs` was extended **additively** with one
  optional `opts.fetch` (default: the global `fetch`) plus an additive `err.status`, so
  the **unauthenticated path is behaviourally identical** and the authenticated path just
  injects the signer — which is why the earlier interop tests still pass unchanged.
  Proven against a **live** server by
  [`../sigil-wasm/test/device-auth-interop.mjs`](../sigil-wasm/test/device-auth-interop.mjs),
  which boots a real `sigild` with `SIGILD_DEVICE_AUTH=1` and asserts: an **unsigned**
  request is `401`; device A enrolls; the identity **round-trips through a
  password-sealed container with no plaintext seed at rest**; A pushes, claims the vault
  (trust-on-first-write), pulls and opens it byte-verbatim; device B enrolls but is
  **`403`** on A's vault; after a **read grant** B can pull yet is still `403` on write;
  an admin **revoke** makes B `401` while A is unaffected; a **tampered body** and a
  **stale timestamp** are both `401`; and a **spent enrollment token** is refused.
  Honest framing: **dev / localhost / plain-HTTP / no TLS** and **UNAUDITED** — this is
  request auth for a dev op-log, **not** the product's account, session or
  key-management model (see
  [ADR 0033](decisions/0033-browser-device-identity-storage.md) for how a browser client
  stores that identity).
  **The wasm client can now also SHARE a vault with another device** — the client half
  of the sharing flow ([ADR 0035](decisions/0035-device-to-device-vault-sharing.md)),
  in [`../sigil-wasm/sharing.mjs`](../sigil-wasm/sharing.mjs): another framework-free,
  dependency-free ESM module (Node **and** browser) exporting `generateHybridIdentity` /
  `hybridPublicIdentity`, `publishHybridKey` / `fetchHybridKey`, `generateVaultKey` /
  `vaultKeyFingerprint`, `wrapVaultKey` / `unwrapVaultKey`, `putKeyEnvelope` /
  `getKeyEnvelope`, the two composed operations `shareVault` / `acceptVault`, and
  `explainSharingStatus` (which separates `401` "not authenticated" from `403` "not the
  addressee / not permitted" from `404` "nothing shared yet"). **No Rust changed:** every
  wasm export it needs — `hybrid_x25519_public`, `hybrid_mlkem_encaps_key`,
  `hybrid_seal_to_container`, `hybrid_open_container` — already existed from
  [ADR 0021](decisions/0021-wasm-hybrid-public-key-encryption.md). Like `device-auth.mjs`
  it does **no cryptography of its own**: the KEM/AEAD happens in the wasm and every
  request signature goes through `device-auth.mjs`. All entropy is JS-supplied
  (`crypto.getRandomValues`): the hybrid identity, each 32-byte vault key, and the
  per-wrap ephemeral X25519 secret / ML-KEM coin / AEAD nonce — so both lockfiles stay
  `getrandom`-free. `shareVault` deliberately does wrap + deposit **and then** the grant
  through the **existing** `grantVaultAccess`, so authorization and key distribution
  cannot drift apart; `unwrapVaultKey` rejects any recovered plaintext that is not
  exactly 32 bytes rather than using it as a key. The semantics and byte layouts are
  **MIRRORED — not shared — from `cli/src/lib.rs` and
  `sigild/internal/api/sharing.go`**, and the guard is
  [`../sigil-wasm/test/sharing-interop.mjs`](../sigil-wasm/test/sharing-interop.mjs),
  which boots a real `sigild`, builds the **real `sigil` binary**, and shares **both
  ways** between the JS client and the CLI.
- **`sigild`** ([`../sigild/`](../sigild/)) — the Go sync-server **skeleton**. Serves
  `/healthz`, `/readyz`, `/version`, request-ID / access-log / panic-recovery
  middleware (plus, **only when `SIGILD_CORS_ORIGINS` is set**, an innermost
  browser-origin **CORS** middleware — unset, it is not installed and no response
  carries an `Access-Control-*` header;
  [ADR 0044](decisions/0044-opt-in-cors-allowlist.md)),
  and a **dev-gated** (`SIGILD_ENABLE_DEV_OPS`, default off → `501`),
  vault op-log that stores **opaque client-encrypted blobs** and hands them back
  unchanged. The op-log is **unauthenticated by default**; when started with
  **`SIGILD_OPLOG_PUBKEY`** (std-base64 Ed25519 public key) it additionally
  requires each request to carry an Ed25519 signature over a canonical
  `(method, path, query, timestamp, nonce, body)` message — **op-log auth
  contract v2** — a **single static dev device key** whose **per-request nonce**
  is checked against a time-bounded, **in-memory / per-process seen-nonce cache**
  so a captured request cannot be replayed inside the 300 s window; real
  multi-device enrollment / JWT auth remains **future** (see
  [`decisions/0008-device-key-request-auth.md`](decisions/0008-device-key-request-auth.md)
  and [`decisions/0010-op-log-auth-v2-nonce-replay.md`](decisions/0010-op-log-auth-v2-nonce-replay.md)).
  The op-log sits behind a `VaultLog` seam with
  **three dev backends**, chosen at startup by precedence
  `SIGILD_OPLOG_POSTGRES` > `SIGILD_OPLOG_DIR` > in-memory: an **in-memory,
  non-durable** map (the default); an optional **file-backed** one
  (`SIGILD_OPLOG_DIR`) for local-dev durability (the `vaultID` is
  base64url-encoded to a safe flat filename to prevent path traversal); and a
  **durable Postgres** backend (`SIGILD_OPLOG_POSTGRES`) on the `pgx` driver —
  **`sigild`'s first third-party dependency** and its first real
  production-store *adapter*, with concurrency-safe per-vault sequencing over
  opaque `bytea` blobs. All three are dev-only and opaque; the Postgres backend
  adds durability + concurrency but is **still not a finished production store**
  (no auth model, enrollment, CRDT/merge, or production backup/replication) — see
  [`decisions/0006-file-backed-dev-op-log-backend.md`](decisions/0006-file-backed-dev-op-log-backend.md)
  and [`decisions/0014-postgres-durable-oplog-backend.md`](decisions/0014-postgres-durable-oplog-backend.md).
  **Reliability & auditability hardening** (dev backend): the `VaultLog` seam now
  takes a **request `context.Context`**, so a cancelled or slow request (client
  disconnect, `http.Server` read/write/idle timeouts, or — for Postgres —
  `pgxpool` acquire limits) cancels the in-flight append/read instead of leaking a
  goroutine; `/readyz` performs a **real** health check of the active backend
  (pinging the `pgxpool` when Postgres is configured, `503` if the DB is down);
  and every append, list, and auth denial emits a **structured audit event**
  (`event`, `request_id`, `vault_id`, `seq`, `size`, a **SHA-256 fingerprint** of
  the opaque blob, and the denial reason). The audit log records **metadata and a
  fingerprint of the already-encrypted blob — never its content, and never a
  signature, nonce, or key** — so it proves *who appended what, when* while the
  **trust boundary is preserved**: the server still never sees plaintext (see
  [`decisions/0015-oplog-auditability-and-request-context.md`](decisions/0015-oplog-auditability-and-request-context.md)).
  **Tamper-evidence (hash chain):** across **all three backends**, every op now
  carries a per-op **SHA-256 hash-chain link** — `hash(seq) =
  SHA-256("sigil-oplog-chain-v1" || len-prefixed vaultID || seq || prev_hash ||
  blob)`, genesis `prev_hash` = zeros — so each op commits to the previous one and
  any insertion / deletion / reorder / modification of stored ops is **detectable**.
  The hash is returned per-op by `GET …/ops`, and a `GET …/ops/verify` route
  recomputes the whole chain server-side (`{ok, count, tip_hash, broken_at_seq}`).
  Because the hash fingerprints the **already client-encrypted** blob, it adds
  tamper-evidence with **no plaintext and no key** — zero-knowledge intact. This is
  **tamper-EVIDENT, not tamper-PROOF**: a hostile server can still lie about
  `/ops/verify`, so the real check is **client-side** re-derivation from the
  returned per-op hashes; it is not a signed / Merkle / Byzantine-proof log (see
  [`decisions/0016-tamper-evident-oplog-hash-chain.md`](decisions/0016-tamper-evident-oplog-hash-chain.md)).
  **Scale & observability (all Go stdlib):** op-log reads are now **bounded and
  paginated** — `GET …/ops` takes a `?limit` (default 500, max 1000; invalid →
  `400 bad_limit`) and returns `has_more`, so a client drains a vault by paging
  with `since=next` instead of pulling an unbounded slice; `POST …/ops` can be
  **rate-limited per vault** by a **stdlib token-bucket** (`SIGILD_OPLOG_RATE_LIMIT`
  / `SIGILD_OPLOG_RATE_BURST` → `429 rate_limited` + `Retry-After`, off by default,
  one bucket per vault ID so a busy vault can't starve others); an **always-on**
  `GET /metrics` renders **Prometheus-text counters** (HTTP requests, op-log
  appends, verifies, auth denials by reason, rate-limit rejections, and
  `build_info`) exposing **only aggregate counts and the build version — no
  secrets, no blob, no vault ID**; and `sigild` now **validates its configuration
  fail-fast at startup**, refusing to boot on a malformed env var rather than
  starting misconfigured. These four are **pure stdlib** (`pgx` is still the only
  third-party dependency) and change **none** of the posture above — still
  dev-gated / opaque / unauthenticated-by-default (see
  [`decisions/0017-oplog-scale-and-observability.md`](decisions/0017-oplog-scale-and-observability.md)).
  **Managed schema migrations (Postgres backend):** the Postgres backend now
  manages its schema with **versioned, embedded migrations** tracked in a
  `schema_migrations` table (`go:embed`'d `NNNN_*.sql`, applied in ascending
  order under a session-level `pg_advisory_lock` so concurrent boots are safe),
  replacing the old ad-hoc boot-time `IF NOT EXISTS` DDL. Migrations are
  **auto-applied at boot by default** and can be run/inspected explicitly with the
  `sigild migrate` / `sigild migrate status` operator CLI;
  **`SIGILD_OPLOG_AUTO_MIGRATE=0`** disables auto-apply (boot then fails fast until
  `sigild migrate` runs). They are **pure DDL** over the opaque `bytea` `blob` +
  `hash` columns — no crypto, zero-knowledge intact — and `GET /metrics` exposes
  the applied version as the **`sigild_schema_version`** gauge (0 for mem/file). A
  logical `pg_dump` / `pg_restore` backup preserves the per-op hash chain
  byte-for-byte, so **`GET …/ops/verify` re-proves the same `tip_hash` after a
  restore** (see
  [`decisions/0018-managed-oplog-migrations-and-backup-integrity.md`](decisions/0018-managed-oplog-migrations-and-backup-integrity.md)).
  **Multi-device auth model (contract v3, opt-in):** alongside the legacy
  single-static-key v2 above, `sigild` now has a **real device-identity and
  authorization model** — opt-in via **`SIGILD_DEVICE_AUTH`**, dev-gated behind
  `SIGILD_ENABLE_DEV_OPS`, and **mutually exclusive** with `SIGILD_OPLOG_PUBKEY`
  (setting both makes the server **refuse to boot**, fail-fast before the
  listener binds). It has four parts:
  (1) a **device registry** — one Ed25519 public key per device with a
  **server-assigned** ID (`dev_` + raw-URL-base64 of 16 CSPRNG bytes), a label
  and an `active`/`revoked` status;
  (2) **enrollment** (`POST /v1/devices/enroll`) requiring **two independent
  factors** — an operator-provisioned single-use **enrollment token**
  (`SIGILD_ENROLL_TOKENS`, held **only** as a SHA-256 digest, optional
  `SIGILD_ENROLL_TOKEN_TTL`) **plus proof of possession**: a signature over a
  challenge on a *different* domain (`"sigil-device-enroll-v1\n" + token_sha256 +
  timestamp + nonce + public_key + label`) verified against the **submitted**
  key, so neither a stolen token nor a captured proof suffices alone;
  (3) **per-vault grants** — `(vaultID, deviceID) -> read|write` (write implies
  read) with **trust-on-first-write ownership**: the first device to
  authenticate a *write* to an unclaimed vault becomes its owner (atomically — a
  mutex in memory, a partial `UNIQUE` index in Postgres), reads never claim, and
  only the owner may grant; and
  (4) **revocation** (`POST /v1/devices/{deviceID}/revoke`, by the operator
  `SIGILD_ADMIN_TOKEN` or by the device on itself), checked **before** signature
  verification so a revoked device is refused on its very next request.
  Requests name their device in a new **`X-Sigil-Device`** header and sign
  `"sigil-oplog-auth-v3\n" + device_id + method + path + query + timestamp +
  nonce + body`; the domain bump *and* the device segment mean **v2 signatures do
  not verify under v3**. `401` (unauthenticated) and `403` (authenticated but not
  authorized) are now **distinct**, while the response body stays coarse
  (`unauthorized` / `forbidden`) — the typed reason goes **only** to the audit log
  (`device.enrolled`, `device.revoked`, `vault.claimed`, `vault.granted`,
  `oplog.auth_denied` with `device_id` + `reason`) and the per-reason metric, so
  there is **no auth oracle**.
  It rides the **same store seams**: a `store.DeviceStore` interface with an
  in-memory backend (non-durable) and a Postgres backend that **shares the op-log's
  existing `pgxpool`** (no second pool, no new dependency) over migration
  **`0002_devices.sql`** (`sigil_devices`, `sigil_enrollment_tokens`,
  `sigil_device_grants`) — so `sigild_schema_version` reports **2** at that point
  (**3** once the billing migration below is applied, **4** once the vault-sharing
  migration is, **5** once the account migration is). That
  migration adds **AUTH METADATA ONLY** (public keys, IDs, labels, permissions,
  timestamps, a token digest) and touches **nothing** in `sigil_vault_ops`: the
  **opaque blob, its tamper-evidence hash chain, and the zero-knowledge boundary
  are completely unchanged**, and the server still does no cryptography on vault
  contents. All five device routes are dev-gated exactly like the ops routes
  (`501` when off, never `404`). Honest scope: **dev-gated, opt-in, UNAUDITED** —
  trust-on-first-write is a dev ownership heuristic (Phase 52 moved it from the
  device to the **account**, it did not remove it), revoking a vault's owner
  **no longer orphans it** now that siblings inherit ownership from the account
  (⚠️ losing *every* device in an account still does, permanently), an enrollment
  token is single-*attempt* (spent before the device row is created), the replay
  cache is still **per-process**, the in-memory registry is non-durable (a spent
  token becomes reusable after a restart) and the **file backend was not
  extended**, and there is still no session model and no device-key rotation.
  Enrollment **can** now be rate limited (opt-in, Phase 53) — but behind the only
  topology this repo documents it is one global bucket, it charges only failed
  attempts and it does not reduce load, so it is a **backstop, not a defence**
  ([ADR 0041](decisions/0041-abuse-bounds-and-the-removed-webhook-limiter.md); see
  [`decisions/0031-multi-device-auth-model.md`](decisions/0031-multi-device-auth-model.md)).
  ⚠️ Two of those limits were **revised by the account model below**: ownership is
  no longer per-device, and revoking a vault's claimant no longer orphans it.
  **Account model (same dev gate, no separate switch):** the subject of
  **entitlement** and the **owner of vaults** is an **account**, not a device
  ([ADR 0040](decisions/0040-account-model.md)). An account is a
  **server-assigned id on the device row** (`sigil_accounts` +
  `sigil_devices.account_id`) and nothing else that could identify a human —
  **auth metadata only**: no email, no password, no session, no PII and no key
  material — **not an identity system**, and the only recovery is a **paper kit
  printed in advance** ([ADR 0042](decisions/0042-recovery-kit.md)).
  It exists because a device was too small a subject
  twice over: a subscription bought on a phone did not entitle a laptop, and a
  vault owned by a device was **orphaned** when that device was revoked.
  Four parts:
  (1) **membership** — an operator enrollment token always founds a **new**
  account; every later device joins with a **single-use invite** minted by a
  member, presented in the **existing `X-Sigil-Enroll-Token` header under the
  existing enrollment challenge** (which already binds the credential's SHA-256
  digest), so there is **no new header, no new signed-message domain and no
  fourth canonical message** — the three-implementation count of ADR 0031 is
  unchanged and today's shipped clients can already join;
  (2) **ownership** — `sigil_vault_owners` (`vault_id` PRIMARY KEY → `account_id`)
  is the authority; trust-on-first-write **moved up one level** (the first
  *account* to write an unclaimed vault owns it), every device of the owning
  account has full access **without a grant row**, and `needOwner` is satisfied
  **only** by account ownership — a legacy `is_owner` grant never satisfies it,
  though the flag is retained as the per-device *view* so `GET …/grants` is
  byte-identical for existing clients;
  (3) **entitlement** — the billing subject is `dev.AccountID`, still
  server-derived and never a body field; and
  (4) **four dev-gated routes** (`GET /v1/account`, `POST`/`GET
  /v1/account/invites`, `POST /v1/account/invites/{inviteID}/revoke`) reusing the
  **same `authenticateDevice` choke point** — no new auth path.
  ⭐ **The structural rule: NO REQUEST ANYWHERE NAMES AN ACCOUNT.** Every handler
  takes it from the device row of the signature it just verified, so a
  cross-account request is **unconstructible**, not merely rejected. Storage is
  migration **`0005_accounts.sql`** (`sigil_accounts`, `sigil_account_invites`
  storing an invite only as a SHA-256 **digest**, `sigil_vault_owners`, plus an
  **adoption backfill** giving every pre-existing device its own singleton
  account) ⇒ **`sigild_schema_version` reports 5**; it names `sigil_vault_ops`
  nowhere, so the opaque blob and its hash chain are byte-for-byte unchanged.
  Honest scope: **dev-gated, `501` by default, UNAUDITED, and NOT an identity
  system** — ⚠️ **the only recovery is a kit printed BEFORE the loss** (lose or
  revoke every device having printed nothing and the account is permanently
  unreachable; the orphan failure was *narrowed* twice, not eliminated, and
  ⚠️ **whoever holds the printed sheet holds the account**), membership is **FLAT** (any member may invite, revoke every
  sibling, run checkout and administer every account-owned vault) and
  **immutable** (no transfer, merge, split or deletion), **there is no account
  merge across the cutover** (a pre-0005 two-device customer ends up with two
  accounts and two billing subjects), entitlement is **reported unless
  `SIGILD_ENTITLEMENT_ENFORCE` is set**, in which case a lapsed account's
  **writes** answer `402` past a grace period while ⭐ **reads and same-account key
  recovery are never refused** ([ADR 0043](decisions/0043-entitlement-enforcement.md)),
  and a **rolled-back pre-0005 binary** writes `account_id NULL` rows that are
  refused with a coarse `403` until an operator runs the explicit, idempotent
  **`sigild migrate adopt`** (warned at boot; adoption **never** happens
  implicitly on the authentication path).
  **Vault-sharing relay (same dev gate, same auth choke points):** on top of that
  model `sigild` acts as a **mailbox** for device-to-device key distribution —
  `PUT`/`GET /v1/devices/{deviceID}/hybrid-key` (a device's **public** X25519 +
  ML-KEM-768 key), `PUT`/`GET /v1/vaults/{vaultID}/keys/{deviceID}` (an
  **opaque wrapped vault key**) and — for rotation —
  `GET /v1/vaults/{vaultID}/keys` (recipient **metadata only**, never a blob) plus
  `DELETE /v1/vaults/{vaultID}/keys/{deviceID}`, both requiring **write** through the
  *same* `authorizeOpsRequest` choke point as a deposit — and, since Phase 54,
  `GET /v1/devices/{deviceID}/keys`, a **self-only, metadata-only** index of which
  vaults hold a wrapped key for one device (the route a **recovery kit** uses to
  find itself on a fresh machine; it needed **no migration**, reusing the index
  `0004` already created). It is deliberately the dullest possible component:
  it stores and returns the envelope **byte-for-byte**, holds **no decapsulation
  key**, decodes nothing, and its **only** inspection of key material is a length
  check (32 / 1184 bytes) — validating a curve point would be the server performing
  cryptography on user key material. Authorization is **not a new path**: publishing
  is self-only (`403` otherwise), a deposit needs **write** on the vault (and a
  first deposit *claims* an unowned vault exactly like a first append), and
  collection requires the caller to **be the addressee** *and* hold **read** — so
  `403` means "authenticated but not permitted", never `401`. Migration
  **`0004_key_sharing.sql`** (`sigil_device_hybrid_keys`,
  `sigil_vault_key_envelopes`; `sigild_schema_version` → **4**) is purely additive
  and again touches **nothing** in `sigil_vault_ops`. Audit lines
  (`device.hybrid_key_published`, `vault.key_envelope_put`,
  `vault.key_envelope_get`, plus `vault.key_envelope_list` / `_delete`, which read no
  blob and so carry no fingerprint) carry metadata plus a **SHA-256 fingerprint** of the
  envelope — never its bytes, never a key. Honest scope: **dev-gated (`501` by
  default), plain HTTP, UNAUDITED**; verification of a published hybrid key is
  **client-side only** — `sigild` stores and validates no pin and no safety number
  (§2c) — revocation stops future access but cannot un-share a key a device already
  unwrapped, and re-keying is the **manual** `vault rotate` with no schedule and no
  automatic re-wrap on revoke
  (see [`decisions/0035-device-to-device-vault-sharing.md`](decisions/0035-device-to-device-vault-sharing.md)
  and [`decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md`](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)).
  **Billing / subscriptions (opt-in, dev-gated):** because Sigil is a **paid**
  product, `sigild` also carries a **provider-agnostic billing seam** —
  one `billing.Provider` interface with three **stdlib-only** adapters
  (**Stripe** international; **Razorpay** and **Juspay** for India), a
  **normalized event vocabulary** (`checkout_completed`,
  `subscription_activated`, `subscription_renewed`, `subscription_canceled`,
  `payment_failed`, `ignored`), a **subscription state machine**
  (`none`/`trialing`/`active`/`past_due`/`canceled`, written as an explicit
  transition table), and three routes: `POST /v1/billing/checkout` +
  `GET /v1/billing/subscription` (**device auth v3**, the same choke point as the
  ops routes — the subject is the authenticated device's **ACCOUNT ID** since
  Phase 52, still server-derived and never a body field, so paying on one device
  entitles the others and a cancellation demotes the account at once; a device
  carrying no account is refused with a coarse `403` **before** the provider or
  the store is touched, never falling back to the device id, and a
  provider-echoed **pre-0005 device subject** is *resolved* onto an account
  rather than trusted, or blanked so it can never invent a subscription row)
  and `POST /v1/billing/webhook/{provider}` (authenticated **only** by the
  provider's own signature over the **raw** body, because a payment provider has
  no device key). Webhook handling is **idempotent on `(provider, dedup key)`**,
  where ⭐ **the dedup key is derived only from bytes the provider's signature
  covers** — Stripe's event id is inside the signed payload, Razorpay's is
  `SHA-256(raw body)` rather than the unsigned `X-Razorpay-Event-Id` header, and
  Juspay's comes out of the body
  ([ADR 0039](decisions/0039-webhook-idempotency-from-signed-bytes.md), which
  revises §4 of [ADR 0034](decisions/0034-billing-provider-seam.md); Juspay's
  default webhook scheme is `hmac` for the same reason, since `basic` binds no
  bytes). It is
  fused with the state change into **one atomic operation** (a mutex in memory, a
  transaction in Postgres over migration **`0003_billing.sql`** —
  `sigil_subscriptions`, `sigil_billing_processed_events`; `sigild_schema_version`
  → **3**), so a redelivered webhook is a guaranteed no-op that still answers
  `200`. Two architectural properties: **hosted checkout only** — every adapter
  asks the provider for a URL and hands it to the client, so **no card data ever
  enters this process** and there is no field or column anywhere that could hold
  a PAN/CVV/expiry (PCI scope stays SAQ-A); and **no vendor SDKs** — every
  adapter is `net/http` + `crypto/hmac` + `encoding/json` + `net/url`, so
  `sigild`'s go.mod still has exactly **one** direct require (`pgx`) and the
  verification code stays small enough to audit by reading it.
  **Honest architectural caveat:** putting a billing layer *inside the sync
  server* is a **scaffold decision, not a final topology**. It is where it is
  because that is where the device identity, the config/fail-fast plumbing, the
  store seams, the audit log and `/metrics` already live — not because a
  zero-knowledge sync server is the right long-term home for money-adjacent
  state. A production shape would more likely separate billing (its own service
  and database, its own blast radius, its own compliance surface) and have
  `sigild` consume an entitlement, not compute one. Nothing here has been run
  against a live provider account, the Juspay scheme is explicitly
  **UNVERIFIED-AGAINST-LIVE-DASHBOARD**, the account that is now the subject is
  **not an identity** (no email, no password, no operator break-glass — recovery
  is a paper kit printed in advance — and every pre-0005 device was adopted into
  its own singleton account, so an existing two-device customer has two billing
  subjects), and there is no fraud/chargeback/refund/proration/tax handling and no
  PCI attestation (see
  [`decisions/0034-billing-provider-seam.md`](decisions/0034-billing-provider-seam.md)).
  **Entitlement enforcement (opt-in, Phase 55):** with
  `SIGILD_ENTITLEMENT_ENFORCE` set, a lapsed account's **writes** answer **`402`**
  past a grace period (default 14 days). ⭐ **Reads and same-account key recovery
  are never refused** — the enforcement call set is *three write handlers*, pinned
  by a test that parses the package's AST — so a lapsed customer keeps every 2FA
  code they hold, can key a replacement device, can print a recovery kit and can
  always pay. Every uncertainty **fails open**. Off by default and byte-identical
  when unset ([`decisions/0043-entitlement-enforcement.md`](decisions/0043-entitlement-enforcement.md)).
  ⛔ There is deliberately **no rate limiting on the webhook route**: the limiter
  built for it in Phase 53 was **removed** after a live reproduction showed it
  shedding genuine, correctly-signed provider deliveries — you cannot safely shed
  traffic on a route where shedding costs money and the legitimate sender has a
  finite retry budget
  ([`decisions/0041-abuse-bounds-and-the-removed-webhook-limiter.md`](decisions/0041-abuse-bounds-and-the-removed-webhook-limiter.md)).
  Billing touches **nothing** in `sigil_vault_ops` and performs no cryptography
  on vault contents, so the trust boundary is unchanged.
  `sigild` performs **no cryptography on vault contents** and never sees plaintext
  or vault keys — but it is **not** crypto-free: it verifies Ed25519 request
  signatures, chains ops with SHA-256, digests enrollment and admin tokens, and
  verifies provider webhook HMACs in constant time. The distinction that matters
  is that **none of those keys can decrypt a vault**. Full contract in
  [`api.md`](api.md).
  **A rejected write never claims a vault** ([ADR 0045](decisions/0045-claim-precondition-rejected-writes-never-claim.md)):
  trust-on-first-write used to fire inside authorization, ahead of a handler's
  request-shape checks, so a request answered `400` still took permanent ownership
  of the vault id it named. A cheap, vault-independent precondition now downgrades
  the access level of a request that is going to be refused, so it cannot claim —
  at the cost of one documented status change (an empty write to an **unowned**
  vault answers `403`, not `400`).
- **`web/apps/marketing`** ([`../web/apps/marketing/`](../web/apps/marketing/)) —
  Next.js 15 stealth splash + early-access waitlist. No-index, wallable, no
  product surface.
- **`web/apps/webapp` + `web/packages/sigil-wasm`**
  ([`../web/apps/webapp/`](../web/apps/webapp/),
  [`../web/packages/sigil-wasm/`](../web/packages/sigil-wasm/)) — **the first real
  product client surface**: a Next.js 15 app-router app that runs the **libsigil core
  compiled to WebAssembly, entirely client-side**. It consumes a workspace loader
  package, **`@sigil/wasm`** ([`../web/packages/sigil-wasm/`](../web/packages/sigil-wasm/)),
  whose `build.sh` compiles the **repo-root `sigil-wasm` Rust crate** (the same crate
  the standalone `pkg-web`/`pkg-node` build uses) to wasm and re-exports the wasm
  surface (`seal_record` / `open_record`, `seal_to_container` / `open_container`,
  `hybrid_*`, `totp` / `hotp` / `format_code`) behind an `initWasm()` awaitable and a
  typed `index.d.ts`, **plus re-uses the proven, wasm-agnostic JS helpers** from the
  repo-root `sigil-wasm/{totp-vault,sync,totp-migration,device-auth,sharing}.mjs` by
  relative import — the
  same tested source those interop tests exercise ([ADR 0024](decisions/0024-wasm-totp-vault-and-cross-client-totp.md),
  [ADR 0026](decisions/0026-browser-totp-import-export.md)), **not a rewrite** and
  **no new crypto** (all crypto stays in `sigil-core`). It adds a wasm-bundling wrinkle:
  because rustc 1.85+ force-enables the wasm `reference-types` + `multivalue` target
  features, wasm-bindgen emits `externref`, which Next.js 15's bundled (old
  `@webassemblyjs`) webpack parser cannot decode. `build.sh` therefore does a **3-step
  strip** — (1) cargo build the crate to raw wasm, (2) delete the `target_features`
  custom section so wasm-bindgen stays in the MVP subset (no `externref`), (3) run
  `wasm-bindgen --target bundler` — and the app enables webpack
  `experiments.asyncWebAssembly`. The app itself (`app/page.tsx` +
  a `"use client"` `app/authenticator.tsx`, plus a collapsed `app/totp-demo.tsx`
  wasm self-check, that dynamic-import `@sigil/wasm` so wasm loads in the browser only)
  is now a **real (dev) authenticator UI — a multi-account encrypted TOTP vault**, not
  just a single-code demo. It **seals its accounts into a `SIGILcli` container**
  (Argon2id → XChaCha20-Poly1305, the same sealed vault format the CLI and browser
  helpers use, so the vault stays **cross-client-interoperable**) and **persists ONLY
  the sealed container** to `localStorage` (key `sigil.webapp.vault.v1`) — the plaintext
  vault and the password are **never persisted**; the password lives only in memory
  while unlocked and vanishes on Lock / reload, so the app boots into a **password
  unlock** flow whenever a sealed vault already exists (setup / locked / unlocked
  phases). You **add accounts** by form (label / issuer / base32 secret / algorithm /
  digits / period), by pasting an `otpauth://` URI, or by **importing a Google
  Authenticator `otpauth-migration://` export** (duplicates skipped), and **export**
  back out as `otpauth://` URIs or one combined migration URI (behind a loud
  secrets-in-the-clear warning). Live **codes + countdown rings are computed in the
  wasm** (`codeForEntry` / `base32Decode`; the wasm computes every code, never JS); each
  vault mutation re-seals and re-persists the container. Fresh salt/nonce entropy comes
  from `crypto.getRandomValues`. An optional **Sync (dev)** panel round-trips the
  **sealed** container to/from a localhost sigild op-log over plain HTTP (opaque bytes
  only; no TLS).
  That panel can now also **enroll this browser as a device** and sign every sync
  request under `sigild`'s multi-device **contract v3** (ADR 0031), over
  `device-auth.mjs` re-exported by `@sigil/wasm`: paste a single-use enrollment token,
  `enrollDevice` derives + proves possession of a fresh Ed25519 key in the wasm, and
  `push`/`pull` then go through `pushContainerAuthed` / `pullContainersAuthed`
  (`explainAuthStatus` renders `401` vs `403` in plain language). With **no** identity
  enrolled the panel behaves exactly as before (unauthenticated). The **device identity
  is never stored in plaintext**: the 32-byte seed is sealed into a **SECOND `SIGILcli`
  container under the same vault password** and only that container is written to
  `localStorage` (key `sigil.webapp.device.v1`, sealed plaintext
  `{version, device_id, seed, base_url}` — schema **v1**; sharing extended it to v2,
  below); the decrypted seed lives **only in memory
  while the vault is unlocked**, Lock / reload / Forget all drop it, and Forget deletes
  the sealed identity too. The enrollment token is an in-memory bearer secret, cleared
  after use and never stored or logged
  ([ADR 0033](decisions/0033-browser-device-identity-storage.md)).
  A **Sharing (dev) panel** (`SharingPanel` in `app/authenticator.tsx`, over
  `sharing.mjs` re-exported by `@sigil/wasm`) now gives the webapp the **whole**
  device-to-device sharing flow, not a reduced one: show/copy this device's ID,
  **publish** this device's hybrid public key (`generateHybridIdentity` on first use,
  then `publishHybridKey`), **convert** this password-sealed vault into a shared vault
  sealed under a fresh random 32-byte key (`generateVaultKey`, the webapp's equivalent of
  `sigil vault rekey` — a **one-way door** in the UI), **share** it to a pasted recipient
  device ID with `read`/`write` (`shareVault`), and **accept** a vault shared to this
  device (`acceptVault`, then pull and open it). `explainSharingStatus` renders `401` /
  `403` / `404` distinctly. **Storage adds nothing new in the clear:** the **sealed
  device-identity container was extended from schema v1 to v2** rather than adding a
  second store, so its sealed plaintext is now
  `{version: 2, device_id, seed, base_url, hybrid: {x25519_secret, mlkem_seed},
  vault_keys: {<vaultID>: <b64 32 bytes>}}` — the Ed25519 seed, the **hybrid secret
  identity** and **every accepted vault key** all live inside that one container under
  the vault password. The browser therefore still persists exactly **two** values, both
  sealed: `sigil.webapp.vault.v1` (the TOTP vault) and `sigil.webapp.device.v1` (the
  identity). v1 containers still open (yielding `hybrid: null` and an empty keyring), so
  the change is backward compatible. Because a shared vault is no longer sealed under the
  password, **unlock now opens the device identity first, tries the password, then falls
  back to each held vault key**, so a shared vault re-opens after a reload; the password
  and every decrypted secret remain memory-only and are dropped on Lock / Forget /
  reload ([ADR 0036](decisions/0036-browser-sharing-secret-storage.md)).
  ⭐ **Since Phase 58 the webapp can also protect both containers with a PASSKEY**
  ([ADR 0046](decisions/0046-passkey-protected-local-containers.md), over the new
  `sigil-wasm/passkey.mjs` re-exported by `@sigil/wasm`) — the **only** client with
  this UI. With protection on, the TOTP vault and the device identity are sealed
  under a 32-byte **container master key** instead of the password, and the CMK is
  wrapped into a **third `SIGILcli` container** (`localStorage` key
  `sigil.webapp.hwslot.v1`) sealed under `PRF(32) ‖ utf8(password)` — a WebAuthn
  credential's PRF output first, then the password, fed **straight to the
  container's own Argon2id**. The CMK is an HKDF derivation of the **existing
  [ADR 0042](decisions/0042-recovery-kit.md) recovery-sheet seed**, so the
  break-glass for a dead passkey is the sheet the user already printed — no new
  artifact and **no server**. ⭐ **AND, never OR:** while protection is on there is
  no password-only slot; the two doors are (password AND passkey) and (the sheet).
  Enabling **refuses without an active recovery kit**, and because it cannot be
  atomic the **containers are written first and the slot last**, so an interruption
  leaves CMK-sealed containers with no slot — the state the sheet alone recovers.
  A protected **personal** vault refuses sync in **both** directions (push is
  pointless, pull would overwrite the only copy). ⭐ **`sigild` gained nothing**:
  no route, header, canonical message, migration, table, metric or dependency, and
  request auth is still classical Ed25519 contract v3. The persisted set is still
  **sealed containers only** — now three of them. It defends **storage, never
  execution**, and is **not retroactive**.
  It is now an **installable PWA that works fully OFFLINE** — a web
  **manifest** (`app/manifest.ts`) makes it installable, and a hand-rolled
  **service worker** (`public/sw.js`, registered by `app/register-sw.tsx`)
  precaches the app shell and **runtime-caches the JS/CSS/`.wasm`** cache-first, so
  after the first online load the app still renders **and still computes codes in the
  wasm with no network** (a real authenticator must). The SW caches **only public
  static assets** — never a secret: the **sealed vault stays in `localStorage`** and
  the SW leaves cross-origin (e.g. the dev sync) requests untouched. It is also
  **accessible** — labelled landmarks/controls, keyboard-operable, visible focus, and
  a live-region for code updates — and **axe-clean** (no serious/critical violations).
  Proven GREEN by headless Playwright smokes: `tests/wasm.spec.ts` (add-account
  reproduces the RFC 6238 vector `287082`, a Google Authenticator migration URI
  imports, and a lock/reload/unlock round-trip restores the persisted vault —
  [ADR 0028](decisions/0028-webapp-vault-persistence-and-unlock.md)),
  `tests/offline.spec.ts` (after first load, going **offline** still renders the shell
  and computes the TOTP in the cached wasm), and `tests/a11y.spec.ts`
  (`@axe-core/playwright` on setup + unlocked views). Phase 56 added
  `tests/recovery.spec.ts` (the kit lifecycle, incl. restore into a **clean profile**),
  `tests/wrap-gate.spec.ts` (a **second profile that never saw the sheet** is refused,
  stores no envelope, and is told a wrong safety number is a mismatch),
  `tests/leak.spec.ts` (an **enumerating** sweep of every storage key *and value*,
  cookies, IndexedDB, Cache Storage, the DOM, every request URL/body, every console
  message and the address bar, against four spellings of the recovery code — and,
  since Phase 57, ⭐ **the POSITIVE assertion of [ADR 0036](decisions/0036-browser-sharing-secret-storage.md)**:
  every persisted value must decode to bytes beginning with the `SIGILcli` magic
  and every other surface must be **empty**, with Cache Storage constrained by an
  **allowlist** of what the service worker legitimately holds — the shell `/`,
  `/_next/` output and static asset extensions — because filtering only
  *cross-origin* entries was vacuous against a same-origin plant),
  `tests/entitlement.spec.ts` and ⭐ **`tests/cors.spec.ts` — the only spec here that
  drives the UI against a REAL `sigild`** (it builds and boots one, enrols this browser
  through the enrollment UI over the real contract-v3 signed path, and asserts the
  **pre-fix** behaviour is reproduced when `SIGILD_CORS_ORIGINS` is absent). That
  closes the earlier honest gap that no Playwright test had ever driven the enroll
  button. Phase 58 added **`tests/passkey.spec.ts`** — now **26 specs** — driving the **real
  WebAuthn API** through the Chrome DevTools Protocol **virtual authenticator**
  ([ADR 0046](decisions/0046-passkey-protected-local-containers.md)): PRF present
  (`hasPrf: true`), PRF absent (omit it), the authenticator **removed**, a
  **different** authenticator, backup-eligible flags, both interruption states of
  the non-atomic enable, a **deleted** slot and a **corrupted** slot. ⛔ **The origin
  had to move to `http://localhost`** — Chrome rejects WebAuthn on an IP literal
  (`SecurityError: This is an invalid domain.`), so `playwright.config.ts`'s
  `127.0.0.1` would have failed every passkey spec for a reason unrelated to the
  feature. **Honest gaps that remain:** every other spec here runs against a **test
  double** (`sigil-wasm/test/fake-sigild.mjs`), and **print output is not verified** —
  headless Chromium cannot render a printed page, so the recovery sheet's
  `@media print` rules are by-eye.
  ⚠️ **The double used to be MORE PERMISSIVE than real `sigild` on axes its header
  did not disclaim** (found by the fourth audit). Four of them are now **enforced in
  the double itself**: the catch-all answers **`501`** for unimplemented `/v1/`
  routes (restoring the *"`501` by default, never `404`"* invariant inside the
  double), the key-envelope `PUT` enforces the **16 KiB** cap, the hybrid-key `PUT`
  validates **both halves' lengths** (32 / 1184), and the key-envelope `PUT` checks
  the recipient **exists and is not revoked**. ⚠️ **What is still laxer is now stated
  in its header rather than left to be discovered:** it verifies **no signature**,
  enforces **no ownership/grant/authorization**, applies **no entitlement gate**
  beyond a switch, and has **no rate limiting, no nonce/replay window, no account
  seat cap, no hash chain and no self-only check** on the per-device envelope index.
  A spec here proves what the **browser** does and **nothing** about what `sigild`
  would allow.
  It carries the **same no-index stealth posture as
  marketing** (`X-Robots-Tag noindex/nofollow/noarchive`, `X-Content-Type-Options
  nosniff`, `Referrer-Policy no-referrer`, `X-Frame-Options DENY`, plus an
  `app/robots.ts` `Disallow: /`; a manifest never makes a site crawlable) and a loud
  **UNAUDITED / no-real-secrets** banner.
  It is **dev / no-index / UNAUDITED**, **not deployed**, and — because it needs the
  **Rust + wasm-pack toolchain** — it is **built via its own filter and kept OUT of the
  default `web` CI job**, so marketing typecheck/lint/build stay Rust-free; a **separate
  `webapp` CI job** (`.github/workflows/web.yml`) builds `@sigil/wasm` with a Rust +
  wasm-pack toolchain and runs the Playwright suite (incl. the offline + axe proofs) —
  like the repo's other CI mirrors it is validated by-eye / YAML-parse locally and has
  not been run on real GitHub Actions from here (see
  [ADR 0027](decisions/0027-webapp-and-wasm-bundling.md),
  [ADR 0029](decisions/0029-webapp-pwa-offline-a11y-and-ci.md)).
- **`extension`** ([`../extension/`](../extension/)) — **the second real product
  client surface** (after `web/apps/webapp`; the third client over the core if you
  count the demo `cli/`): a **Manifest V3 browser extension** whose **popup is a
  multi-account encrypted TOTP vault**, running the **libsigil core as WebAssembly
  inside the extension page**. It **adds no cryptography and no vault/migration
  logic of its own**: `extension/build.sh` runs the repo-root
  `sigil-wasm/build-wasm.sh` (wasm-pack `--target web`) and **vendors** the wasm
  bindings (`sigil_wasm.js` + `sigil_wasm_bg.wasm`) together with the **proven,
  framework-free helpers** `totp-vault.mjs`, `totp-migration.mjs`, `sync.mjs`,
  `device-auth.mjs` and `sharing.mjs` — copied **verbatim** from the repo-root `sigil-wasm/`, the same
  source the Node interop tests exercise
  ([ADR 0024](decisions/0024-wasm-totp-vault-and-cross-client-totp.md),
  [ADR 0026](decisions/0026-browser-totp-import-export.md)) — into a gitignored
  `extension/vendor/`; `src/popup/popup.{html,css,js}` is UI glue only (there is no
  bundler — the popup is plain ESM). The vault seals into the **same `SIGILcli`
  container** the CLI and the webapp use (Argon2id → XChaCha20-Poly1305 over the
  mirrored `TotpVault` JSON), so **a vault stays cross-client interoperable** rather
  than becoming a third at-rest format. Persistence mirrors the webapp model
  ([ADR 0028](decisions/0028-webapp-vault-persistence-and-unlock.md)):
  `chrome.storage.local` holds **ONLY the sealed container** (base64, key
  `sigil.extension.vault.v1`) — the plaintext vault and the password are **never
  persisted**, the **password lives only in memory** while unlocked, and closing the
  popup re-locks, so the popup boots setup / locked / unlocked. You **add accounts**
  by form (label / issuer / base32 secret / algorithm / digits / period), by pasting
  an `otpauth://` URI, or by **importing a Google Authenticator
  `otpauth-migration://` export**, and **export** back out as `otpauth://` URIs or one
  combined migration URI (behind a loud secrets-in-the-clear warning); **codes and
  countdowns are computed in the wasm**, never in JS, and salt/nonce entropy comes
  from `crypto.getRandomValues`. The popup now also has a **Sync (dev)** panel and can
  **enroll as a device**: it vendors the same `sync.mjs` + `device-auth.mjs`, so push /
  pull go through `pushContainerAuthed` / `pullContainersAuthed` once enrolled (and stay
  unauthenticated when not), and the device identity is persisted **only** as a **second
  `SIGILcli` container sealed under the vault password** — `chrome.storage.local` key
  `sigil.extension.device.v1`, with the seed in memory only while unlocked
  ([ADR 0033](decisions/0033-browser-device-identity-storage.md)). It also has
  a **Sharing (dev)** panel with the **same full flow as the webapp** — show/copy this
  device ID, publish the hybrid key, convert to a shared vault, share to a pasted
  recipient device ID with `read`/`write`, and accept a vault shared to this device —
  over a **vendored copy of `sharing.mjs`** (`extension/build.sh` copies it alongside
  `totp-vault.mjs` / `totp-migration.mjs` / `sync.mjs` / `device-auth.mjs`, since it
  imports two of them and all five must stay siblings). Storage follows the webapp
  exactly: the sealed device-identity container is the **v2 schema** carrying the hybrid
  secret identity and the vault keyring beside the seed, so `chrome.storage.local` still
  holds only the two sealed containers (`sigil.extension.vault.v1`,
  `sigil.extension.device.v1`), and unlock opens the identity, tries the password, then
  falls back to each held vault key
  ([ADR 0036](decisions/0036-browser-sharing-secret-storage.md)). That required an
  **honest expansion of the manifest**: MV3 extension pages cannot `fetch` cross-origin
  without an explicit host permission, so the manifest now declares
  `"host_permissions": ["http://127.0.0.1/*", "http://localhost/*"]` — deliberately
  **loopback-only**, carrying an explanatory comment, so this build **cannot reach a
  remote server**. The rest of the surface is still deliberately small:
  `"permissions": ["storage"]` and **nothing else** (no `tabs`, no `clipboardWrite`),
  **no background service worker, no content script, no options
  page**, and the MV3 CSP is widened by exactly one keyword —
  `script-src 'self' 'wasm-unsafe-eval'` — so the wasm can be instantiated. A pinned
  **public** `key` in the manifest fixes the unpacked extension ID (no private half
  exists in this repo; it is not a signing key) so a headless test can address
  `chrome-extension://<id>/…`. Proven GREEN by `tests/extension.spec.mjs`, which
  loads the **real unpacked extension** in Chromium (`launchPersistentContext`,
  `channel: "chromium"`) and drives the real popup under the real MV3 CSP and real
  `chrome.storage.local`: the wasm instantiates in-page and renders the RFC 6238
  vector `287082` at the pinned test clock `?t=59`, storage contains **only** the
  sealed container (no plaintext secret / label / password), a reload boots
  **locked** and the right password restores the vault, and the `otpauth://` +
  migration import/export paths round-trip. Phase 56 added four more specs matching the
  webapp's — `recovery.spec.mjs`, `wrap-gate.spec.mjs`, `leak.spec.mjs` and
  `entitlement.spec.mjs` — which do drive the enrollment UI (against the test double),
  closing the earlier gap that no Playwright test had clicked the enroll button.
  Since Phase 57 `leak.spec.mjs` also asserts [ADR 0036](decisions/0036-browser-sharing-secret-storage.md)
  **positively**: every value in `chrome.storage.local` must be a sealed `SIGILcli`
  container and `chrome.storage.session` / `sync` / `managed`, `sessionStorage`,
  cookies and IndexedDB must all be **empty**. That is the assertion the extension
  suite had never made either — a planted plaintext dump of the device seed, the
  hybrid secret and every vault key had passed 12/12.
  ⭐ **The extension never needed the CORS fix**: an MV3 page with a host permission is
  **exempt from CORS**, so while the webapp could not reach a real `sigild` at all, the
  extension always could — the asymmetry that kept its suite honest and hid the webapp's
  failure ([ADR 0044](decisions/0044-opt-in-cors-allowlist.md)). It is **dev / UNAUDITED
  / not published to any store** (loaded unpacked, by
  hand), talks to `sigild` over **loopback plain HTTP only**, and generates codes
  without verifying them (no constant-time compare, no zeroization). The reserved-stub
  ambitions
  (phishing protection, passkey provider, content scripts) are **not** implemented
  ([ADR 0030](decisions/0030-browser-extension-client.md)).
- **`desktop`** ([`../desktop/`](../desktop/)) — **the fourth client surface and the
  first NATIVE one**: a **Tauri v2** desktop authenticator. Unlike `web/apps/webapp`
  and `extension`, which run the core compiled to **WebAssembly**, this column links
  **`sigil-core` as a plain native Rust dependency** — there is **no wasm,
  `wasm-bindgen` or `wasm-pack` anywhere under `desktop/`**. That is what makes it a
  new column rather than a re-skin: the core still reads **no clock and no RNG**
  ([ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md)), so the native app
  supplies both — **entropy** through `sigil-cli`'s native `getrandom` path inside
  `seal_to_container`, and the **clock** via `std::time::SystemTime`
  (`sigil_desktop_core::now_unix`) passed *into* the core's `totp` as a `u64`.
  It is **two crates**: **`sigil-desktop-core`** (`desktop/core`) holds **all** the
  authenticator logic headless — `VaultSession` (`create`/`unlock`/`open_or_create`,
  `entries_at`/`entries_now`, `add_secret_base32`, `add_uri`, `import_text`,
  `remove`, `export_uris`, `export_migration_uri`, `save`), the `EntryView` /
  `ImportSummary` view models, `DesktopError`, `default_vault_path` and the
  `BANNER_TITLE` / `BANNER_BODY` / `EXPORT_WARNING` constants, plus the whole
  server-facing half in `desktop/core/src/net.rs` (below) — and is
  `#![forbid(unsafe_code)]`; **`sigil-desktop`** (`desktop/src-tauri`) is a thin
  shell holding an `AppState { session: Mutex<Option<VaultSession>>, sync:
  Mutex<Option<DeviceConfig>> }` and **41 `#[tauri::command]`s** — the ten
  offline ones (`status`, `unlock`, `lock`, `list`, `add_secret`, `add_uri`,
  `import`, `remove`, `export_uris`, `export_migration`), **eleven added in
  Phase 49** (`unlock_shared`, `set_server`, `sync_status`, `enroll`,
  `publish_hybrid`, `check_server`, `convert_to_shared`, `push`, `pull`, `share`,
  `accept`), the Phase 50 key-trust ones, the four Phase 52 account ones and
  **nine added in Phase 56** (`recovery_generate`/`_cover`/`_check`/`_verify`/
  `_restore`/`_revoke`/`_kits`, `entitlement_status`, `entitlement_refresh` — the
  kit lifecycle and the payment warning, both over the `sigil-cli` library, with no
  second copy of the codec, the derivation or the safety-number digest), each of
  which clones the `DeviceConfig` out of the mutex *before* any
  network call so no lock is held across I/O. `desktop/ui` is framework-free HTML/CSS/JS —
  **no npm, no bundler, no CDN**. The split is deliberate: a GUI cannot be clicked by
  a test runner, so everything that could be wrong lives where a test can drive it.
  ⭐ **Errors cross the IPC as a structured value, not a string (Phase 51):**
  `CmdResult<T> = Result<T, IpcError>` where `IpcError { kind, message,
  key_change? }`. `kind` is the coarse tag the webview branches on
  (`unauthenticated` / `not authorized` / `route disabled` / `nothing there` /
  `server unreachable` / `not enrolled` / `already enrolled` / `not a shared vault`
  / `key changed`), and `key_change` is populated for **exactly one** kind —
  `"key changed"` — carrying the device id and **both safety numbers** so the UI
  can render the key-substitution alarm properly. It is **public material only**:
  no key bytes, no seed, nothing secret gained a route across the boundary.
  `From<String> for IpcError` keeps every existing `?` site unchanged. The
  corresponding UI half is a blocking `role="alert"` panel in `desktop/ui` that
  **disables share and rotate** and puts a confirm-guarded re-pin behind both
  numbers — matching what the webapp and the extension already did, and reached
  from the single central `call()` error path so no command can bypass it.
  It **reimplements nothing**: `sigil-desktop-core` path-depends on `sigil-core` **and
  on the `sigil-cli` library target**, taking the `SIGILcli` container
  (`seal_vault`/`open_vault`), the `TotpVault`/`TotpEntry` schema and
  `TotpEntry::code_at`, `base32_decode`, `new_totp_entry`, `totp_algorithm_from_str`,
  `parse_otpauth_uri`/`entry_to_otpauth_uri` and the Google Authenticator migration
  codec straight from `cli/` — so there is **no fourth at-rest format and no mirrored
  schema to keep in sync** (unlike the deliberate Rust↔JS mirrors of
  [ADR 0020](decisions/0020-shared-client-container-format.md) and
  [ADR 0026](decisions/0026-browser-totp-import-export.md)). Consequently the desktop
  app and the `sigil` CLI **literally share one vault file**:
  `$HOME/.sigil/totp-vault.sigil`, byte-for-byte the CLI's default (falling back to
  `./totp-vault.sigil` when `$HOME` is unset), directory `0700` and file `0600`, with
  `save()` writing a temp file and renaming it into place so an interrupted save
  cannot truncate a good vault. **Only the sealed container is ever persisted**; the
  password lives in memory for the life of a `VaultSession` and is **best-effort**
  zeroed on `Drop` (no `zeroize`, no volatile guarantee — documented, not claimed).
  **Trust boundary:** the webview holds **no** key material and does **no**
  cryptography (the password crosses the IPC once at unlock; codes arrive already
  computed), and `desktop/src-tauri/capabilities/default.json` grants **`core:default`
  and nothing else** — no `fs`, `shell`, `http` or `dialog` plugin — so the frontend
  reaches disk only through the explicit commands; the export commands return
  `EXPORT_WARNING` *with* the payload so a UI cannot drop it. Features: create /
  unlock / lock, a live list (issuer/label + code + seconds remaining, recomputed
  ~1/s), add by base32 secret (algorithm/digits/period) or `otpauth://` URI, Google
  Authenticator `otpauth-migration://` import, remove, and `otpauth://` / combined
  migration export behind the loud warning; a pre-audit banner is rendered in the
  window and printed to stderr at startup from the same Rust constants. `desktop/` is
  its **own cargo workspace with its own `desktop/Cargo.lock`**, deliberately outside
  the `libsigil` workspace (exactly like `cli/` and `sigil-wasm/`; see §4) so Tauri's
  platform stack and the native `getrandom` can never enter `libsigil/Cargo.lock`.
  Proven by `desktop/core/tests/cli_interop.rs`, which builds the **real `sigil`
  binary** and drives it as a subprocess against **one shared vault file** in both
  directions, plus an RFC 6238 Appendix B KAT in `desktop/core/src/lib.rs` (`T=59` →
  `94287082` at 8 digits, `287082` at 6).

  **The desktop is no longer offline-only (Phase 49).** `desktop/core/src/net.rs`
  adds device **enrollment**, **contract-v3 signed op-log sync**, and
  **device-to-device vault sharing**, so all four client surfaces (CLI, webapp, MV3
  extension, native desktop) are peers on the network. The operations are
  `DeviceConfig` (`new` / `for_server`, which defaults the state directory to
  `$HOME/.sigil` — the CLI's) with `enroll`, `publish_hybrid`, `push_vault` /
  `push_vault_file`, `pull_vault`, `share_vault`, `accept_vault`, `status` and
  `check_server`, plus `VaultSession::convert_to_shared` / `unlock_shared` and the
  free function `pull_and_adopt`. Contract selection follows the CLI's rule
  exactly: **v3 when enrolled**, legacy **v2** when an identity file has no device
  id, **unsigned** when there is no identity at all.
  ⭐ **The engineering point is reuse, not reimplementation, at the protocol layer
  too** ([ADR 0037](decisions/0037-desktop-reuses-cli-library-for-protocol.md)):
  `net.rs` imports **30 symbols from the `sigil-cli` library** in one `use` —
  `enroll_device`, `push_op_auth` / `pull_ops_auth`, `publish_hybrid_key` /
  `fetch_hybrid_key`, `put_key_envelope` / `get_key_envelope`, `wrap_vault_key` /
  `unwrap_vault_key`, `grant_vault_access`, the key/identity/keyring readers and
  writers, `RequestAuth`, `DeviceIdentity`, `CliError` — so **there is no HTTP
  client, no signing path and no canonical-message construction anywhere under
  `desktop/`** (grep-verified: zero copies of the v3 message domain, zero copies of
  the enrollment-challenge domain, zero direct `ureq`/`reqwest`, zero direct
  Ed25519 signing). The canonical signed bytes already exist in **three**
  implementations — `sigild/internal/api/deviceauth.go` (Go, the source of truth),
  `cli/src/lib.rs` (Rust) and `sigil-wasm/device-auth.mjs` (JS) — kept in sync only
  by interop tests, so a **fourth copy was explicitly avoided**. What could *not*
  be reused is app-level only, with no protocol or crypto in it: the CLI's
  path-resolution and error-explanation helpers live in `cli/src/main.rs`, i.e. the
  **binary**, so they are not importable; `DeviceConfig` therefore re-derives the
  same file names and `net_error` maps `CliError` onto typed `DesktopError`
  variants. **`cli/` was not edited.**
  Because the CLI's own writers and file names are used, the desktop's state files
  are **interchangeable with the CLI's**: `device.key` (Ed25519 seed + assigned
  device id, `0600`), `device.hybrid` (X25519 secret + ML-KEM keygen seed, `0600`),
  `device.hybrid.pub` (public halves), and `vault-keys.json` (vault id → 32-byte
  vault key, `0600`), all inside a `0700` state directory — point `sigil --key` (or
  `HOME`) at a desktop state directory and it is literally the same device.
  Two deliberate shapes in the seam: **`status()` is purely local** (it reads disk
  only, never opens a socket, so it renders with no server configured and cannot
  fail because one is down), while **`check_server` reports reachability as data**
  (`ServerCheck { reachable, hybrid_published, detail }`) rather than as an error;
  and **`pull_and_adopt` opens the pulled container *before* writing it** (then
  temp-file + rename, `0600`), so a container this device cannot read can never
  clobber a good vault. Failures reach the UI tagged distinctly — `unauthenticated`
  (401), `not authorized` (403), `route disabled` (501), `nothing there` (404),
  `server unreachable`, `not enrolled`, `already enrolled`, `not a shared vault`.
  **No seed, hybrid secret, vault key, password or enrollment token ever crosses
  the IPC, is printed, or is logged** — only opaque device ids and 16-hex SHA-256
  fingerprints; the enrollment token is a password-type field used for one call and
  cleared in a `finally`, never stored.
  ⚠️ **At-rest asymmetry worth stating plainly:** the desktop keeps those secrets as
  **`0600` plaintext files** (the documented native model, identical to the CLI's),
  whereas the **browser clients seal everything** into a `SIGILcli` container under
  the vault password ([ADR 0036](decisions/0036-browser-sharing-secret-storage.md)).
  The browser clients are therefore **stronger at rest**; the native clients trade
  that for OS file permissions. Nothing is zeroized on either side.
  **The network proof** is `desktop/core/tests/server_interop.rs`, which boots a
  **real `sigild`** (dev-ops + device auth) on a free loopback port and builds the
  **real `sigil` binary**: the desktop enrolls (identity `0600` in a `0700` dir),
  publishes its hybrid public key (secret `0600`, never uploaded), re-seals its
  vault under a random 32-byte vault key so the password no longer opens it, pushes
  it as seq 1 contract-v3 signed, and then **(a)** the real `sigil totp code`
  prints `94287082` from that vault and **(b)** the desktop unwraps the CLI's key
  and computes `94287082` from the CLI's vault — the RFC 6238 Appendix B vector,
  with the clock pinned by `period = 1_600_000_000` so the TOTP counter equals
  App B's `T = 59` counter from 2020 to 2071. The negatives are asserted too: an
  enrolled but unauthorized third device is **403** on read and on accept, an
  unenrolled desktop gets a clear `NotEnrolled` error rather than a panic, and with
  the server unreachable there is a clear `Unreachable` error **and the offline flow
  still generates codes**.

  It is **dev / UNAUDITED**, **not signed, not
  notarized and not distributed** (`tauri build` was not run; the applicable build is
  `cargo build --release`), the **GUI is build-and-launch verified but not visually
  verified** here (all behaviour lives in the headless core the tests drive), the
  server side it talks to is **dev-gated, loopback, plain HTTP**, and there is still
  **no QR scanning, no code verification and no hardened zeroization** in this column
  ([ADR 0032](decisions/0032-native-desktop-client.md),
  [ADR 0037](decisions/0037-desktop-reuses-cli-library-for-protocol.md)).

```
                         CLIENT SIDE  (all cryptography lives here)
   ┌───────────────────────────────────────────────────────────────────────┐
   │                                                                         │
   │   ┌──────────────────────── libsigil/core (Rust) ──────────────────┐    │
   │   │  no_std · wasm-pure · #![forbid(unsafe_code)]                   │    │
   │   │   suite registry (0x10–0x15, current 0x12)                      │    │
   │   │   envelope codec (encode/decode)                                │    │
   │   │   Argon2id KDF  →  XChaCha20-Poly1305 + HKDF AEAD               │    │
   │   │   record API: seal_record / open_record                        │    │
   │   │   Ed25519 sign / verify  (seed caller-supplied; no RNG)         │    │
   │   │   ML-DSA-65 sign / verify  (keygen seed xi; caller-supplied)    │    │
   │   │   X25519 key-agreement   (secret caller-supplied; no RNG)       │    │
   │   │   ML-KEM-768 KEM  (keygen d||z / m coin; caller-supplied)       │    │
   │   │   hybrid KEM: X25519 & ML-KEM-768 → HKDF combiner               │    │
   │   │   hybrid signature: Ed25519 || ML-DSA-65 (verify needs both)    │    │
   │   │   hybrid public-key seal / open  (KEM-then-AEAD to a pubkey)    │    │
   │   │   HOTP / TOTP codes  (RFC 4226/6238; caller-supplied time)      │    │
   │   └───────────────┬───────────────────────────────┬────────────────┘    │
   │                   │ Rust path-dep                  │ C-ABI               │
   │      ┌────────────┴───────────┐        ┌───────────┴───────────────┐     │
   │      │ cli  (sigil)           │        │ libsigil/ffi  + sigil.h    │     │
   │      │ seal/open file         │        │ sigil_seal / sigil_open /  │     │
   │      │ totp vault (2FA codes) │        │ sigil_buffer_free          │     │
   │      │ push/pull (dev HTTP)   │        │                            │     │
   │      └────────────┬───────────┘        └───────────┬───────────────┘     │
   │                   │                                 │                     │
   └───────────────────┼─────────────────────────────────┼────────────────────┘
                       │ opaque sealed bytes             │ (native clients —
                       │ (plain HTTP, localhost dev)     │  separate repos,
   ════════════════════╪═════════════════════════════════╪══ TRUST BOUNDARY ══
                       ▼                                  ▼  not in this repo)
   ┌───────────────────────────────────────────────────────────────────────┐
   │  SERVER SIDE — sigild (Go)    NO CRYPTO ON VAULT CONTENT · OPAQUE BLOBS │
   │   /healthz · /readyz · /version   (probes; no secrets)                 │
   │   /metrics  → Prometheus-text counters (always on; counts only)        │
   │   /v1/vaults/{id}/ops  →  501 by default                               │
   │     └─ SIGILD_ENABLE_DEV_OPS: op-log (mem/file/pg) of opaque ciphertext│
   │        (append seq / read since, paginated ?limit+has_more;            │
   │         SHA-256 hash chain, tamper-evident; opt per-vault rate limit)  │
   │        unless SIGILD_OPLOG_PUBKEY sets a single Ed25519 dev device key  │
   └───────────────────────────────────────────────────────────────────────┘

   web/apps/marketing (Next.js): stealth splash + waitlist. Separate; no product surface.
   web/apps/webapp (Next.js) + @sigil/wasm: in-browser libsigil-via-WebAssembly
     authenticator — multi-account encrypted TOTP vault (add/import/export), password
     unlock + localStorage persistence of the SIGILcli-sealed container, codes in wasm;
     installable, OFFLINE-capable (manifest + service worker: static assets cached, the
     sealed vault stays in localStorage), accessible/axe-clean;
     optional PASSKEY protection of the at-rest seal (WebAuthn PRF + password -> a
     container master key derived from the printed recovery sheet; ADR 0046) — the
     only client with it, and the server learns nothing about it;
     client-side only; dev / no-index / UNAUDITED; not deployed.
   extension (MV3, popup): the same in-browser wasm authenticator as an extension —
     encrypted TOTP vault (add/import/export), codes in wasm, ONLY the SIGILcli-sealed
     container in chrome.storage.local, in-memory password; permissions: ["storage"];
     no sync, no background worker; dev / UNAUDITED; not published to any store.
   desktop (Tauri v2): the FIRST NATIVE client — sigil-core linked as a plain Rust
     dependency, NO wasm. sigil-desktop-core (headless logic, all the tests) +
     sigil-desktop (shell: 41 #[tauri::command]s) + framework-free ui/. Re-uses cli/'s
     SIGILcli container + TotpVault schema + migration codec, and shares the CLI's
     $HOME/.sigil/totp-vault.sigil, so desktop and `sigil totp` drive ONE vault file.
     Sealed-only vault persistence, in-memory password; webview does no crypto
     (capability = core:default only); own workspace + Cargo.lock. Also enrolls,
     syncs (contract v3) and shares vaults by DRIVING THE sigil-cli LIBRARY — no
     second HTTP client, signer or canonical message — so its device.key /
     device.hybrid / vault-keys.json (0600, in a 0700 dir) ARE the CLI's files.
     Dev / UNAUDITED; unsigned, unnotarized, not distributed.
```

---

## 2. Data flow — the life of one record

The end-to-end path for a single record, as actually implemented by
`seal_record`/`open_record` and packaged by the demo CLI. Every step left of the
trust boundary runs on the client.

```
  password ─┐
            ├─▶ Argon2id (m=64MiB,t=4,p=2)* ─▶ master key (32 B)
  salt ─────┘           (kdf.rs)
                                   │
                                   ▼
            HKDF-SHA256(info = "sigil-record-v1" || suite_byte) ─▶ per-record key (32 B)
                                   │                                   (aead.rs)
       nonce (24 B, caller-supplied) │   aad
                                   ▼   ▼
                        XChaCha20-Poly1305.seal  ─▶  ciphertext + 16-B tag
                                   │
                                   ▼
            Envelope{ version, suite=0x12, flags, aad, nonce, ciphertext, tag, [kem_ct] }
                                   │  Envelope::encode()  (envelope.rs)
                                   ▼
                          encoded envelope bytes
                                   │
   ┌────────────────────────── SIGILcli container (cli + sigil-wasm) ──────────┐
   │  magic "SIGILcli" | ver | m_cost | t_cost | p_cost | salt_len | salt |    │
   │  envelope-bytes                                                          │
   │  (salt + Argon2 params live HERE, not in the envelope; the nonce lives   │
   │   inside the envelope. The header is unprotected metadata — tampering    │
   │   with it just derives the wrong key and open fails to authenticate.)    │
   └───────────────────────────────┬──────────────────────────────────────────┘
                                   │  sigil push   (plain HTTP, localhost dev)
   ════════════════════════════════╪═══════════════ TRUST BOUNDARY ═══════════
                                   ▼
            sigild op-log:  POST /v1/vaults/{id}/ops  ─▶ stores OPAQUE bytes, assigns seq
                            (no crypto, no plaintext, no keys ever)
                                   │  sigil pull   GET …/ops?since=N → base64 blobs
   ════════════════════════════════╪═══════════════ TRUST BOUNDARY ═══════════
                                   ▼
   open is the mirror image:  bytes ─▶ decode envelope ─▶ re-derive master key from
   (password, salt, params) ─▶ XChaCha20-Poly1305.open authenticates aad/nonce/ct/tag
   ─▶ plaintext.  Wrong password / tampered bytes ⇒ authentication failure, never plaintext.

   * RECOMMENDED params; the CLI's fast test params differ. Exact numbers: crypto-spec.md.
```

**The trust boundary is the whole point.** All key derivation and all
authenticated encryption happen **client-side**. What crosses the boundary is an
**opaque, already-sealed** byte string. `sigild` assigns it a sequence number,
stores it, and re-emits it unchanged; it never decodes the envelope, never holds
plaintext, and never holds a key. Vault confidentiality therefore does **not**
depend on the server (this is the property the threat model leans on for the
rogue-employee and compromised-server adversaries — see
[`threat-model.md`](threat-model.md)). The dev op-log's structured **audit log**
does not change this: it records metadata and a **SHA-256 fingerprint of the
already-encrypted blob**, never the blob content or any key, so an audit trail of
*who appended what, when* coexists with the server never seeing plaintext. Note the current dev op-log is *also*
non-durable and unauthenticated by default — optionally guarded either by a
single static Ed25519 dev device key (`SIGILD_OPLOG_PUBKEY`, contract v2: a
per-request nonce checked against a time-bounded in-memory replay cache) or by
the opt-in **multi-device model** (`SIGILD_DEVICE_AUTH`, contract v3: a device
registry, enrollment with proof of possession, per-vault grants and revocation;
[ADR 0031](decisions/0031-multi-device-auth-model.md)) — which is still
dev-gated-off, still **UNAUDITED**, and must never be exposed or hold real
secrets. Neither contract changes the blob: device auth adds **auth metadata
only**, so the server remains zero-knowledge either way.

**A second, public-key data path — and it now does real work.** The flow above is
the *symmetric*, password-derived path (`seal_record` / `open_record`).
`sigil-core` also provides an *encrypt-to-a-recipient's-hybrid-public-key* path —
`hybrid_seal` / `hybrid_open`
([`../libsigil/core/src/hybrid_seal.rs`](../libsigil/core/src/hybrid_seal.rs)) — a
**KEM-then-AEAD** composition: `hybrid_seal` hybrid-encapsulates a fresh 32-byte
shared secret to the recipient's `(X25519 public key, ML-KEM-768 encapsulation
key)`, seals the plaintext under that secret with the same XChaCha20-Poly1305 AEAD,
and emits `(ephemeral X25519 public key, ML-KEM-768 ciphertext, envelope)`; the
recipient's `hybrid_open` decapsulates with its hybrid secret keys and opens the
envelope. **As of Phase 46 this is no longer a demo:** it is the mechanism that
carries **vault keys between devices** (next subsection;
[`decisions/0035-device-to-device-vault-sharing.md`](decisions/0035-device-to-device-vault-sharing.md)).
It remains bespoke (**NOT** RFC 9180 HPKE) and **UNAUDITED**, and it is still not
the product's *account* model — but it is now load-bearing, so a flaw in it is a
flaw in a user-facing path. See [`crypto-spec.md`](crypto-spec.md) and
[`decisions/0013-hybrid-public-key-seal.md`](decisions/0013-hybrid-public-key-seal.md).

### 2b. Data flow — sharing one vault with a second device

Adding a device to a vault is a **key-distribution** problem, not an authorization
problem: a grant decides who the server will talk to, but the server holds no key,
so a merely-authorized device could pull every container and open none of them. The
answer is a third layer in the key hierarchy — a random **vault key** — wrapped per
recipient with the public-key path above.

```
  DEVICE A (owner)                    sigild                    DEVICE B (recipient)
  ────────────────                    ──────                    ────────────────────
  password ─Argon2id─▶ personal vault
        │  (NEVER shared, never wrapped, never sent)
        │
        │  sigil vault rekey
        ▼
  vault key = 32 CSPRNG bytes ──▶ re-seals the SAME SIGILcli container
        │                          (the container takes arbitrary password BYTES,
        │                           so a random key needs NO format change)
        │
        │  sigil vault share --to B
        │     1. GET /v1/devices/{B}/hybrid-key   ◀── B's PUBLIC X25519 + ML-KEM-768 key
        │     2. hybrid_seal(vault key → B's hybrid public key)   [client-side]
        ▼
  SIGILhyb envelope (~1.2 KiB)
        │  3. PUT /v1/vaults/{V}/keys/{B}
  ══════╪═════════════════════════ TRUST BOUNDARY ═══════════════════════════════
        ▼
             sigild stores the envelope bytes VERBATIM
             (no decapsulation key · decodes nothing · length-checks public keys only)
        │  4. POST /v1/vaults/{V}/grants   → B authorized (EXISTING route)
        │
        │                                   GET /v1/vaults/{V}/keys/{B}
  ══════╪═════════════════════════ TRUST BOUNDARY ═══════════════════════════════
        │                                            ▼
        │                              exact same bytes back ─▶ hybrid_open with B's
        │                              hybrid SECRET identity ─▶ the 32-byte vault key
        │                                            │
        │                              sigil pull ─▶ the sealed vault container
        │                                            ▼
        └──────────▶  A and B now generate the SAME code from the SAME vault.
```

**This is not a CLI-only flow — all four clients perform it.** The diagram labels the
CLI commands because the CLI is the reference client, but the **webapp and the MV3
extension perform the identical sequence** through
[`../sigil-wasm/sharing.mjs`](../sigil-wasm/sharing.mjs)
(`publishHybridKey` → `generateVaultKey` → `shareVault` → `acceptVault`), and the
**native desktop app** performs it through `desktop/core/src/net.rs`
(`publish_hybrid` → `convert_to_shared` → `share_vault` → `accept_vault`), which
**calls the `sigil-cli` library functions the CLI itself uses** rather than
reimplementing them ([ADR 0037](decisions/0037-desktop-reuses-cli-library-for-protocol.md)).
All of them hit the same routes with the same v3 signatures, so either end of the
diagram can be a browser, the CLI or the desktop — proven with no mocks by
[`../sigil-wasm/test/sharing-interop.mjs`](../sigil-wasm/test/sharing-interop.mjs)
(JS ↔ the **real `sigil` binary**) and
[`../desktop/core/tests/server_interop.rs`](../desktop/core/tests/server_interop.rs)
(desktop ↔ the real `sigil` binary against a real `sigild`), each direction reaching
the same vault-key fingerprint and the same RFC 6238 code. The browser
clients keep the recovered key inside their **sealed v3 device-identity container**
([ADR 0036](decisions/0036-browser-sharing-secret-storage.md)) where the CLI and the
desktop app use the same `0600` keyring file.

**The zero-knowledge boundary is unchanged — and this is the sharpest test of it.**
The server relays *key* material and still cannot use it: it has no decapsulation
key, so the envelope is ciphertext to it exactly as an op-log blob is; it never sees
the vault key, the password, or a plaintext; and its only look at key material is a
**length check** (32 / 1184 bytes) on a *published public* key, because parsing it
would be the server doing cryptography on user key material. Migration
`0004_key_sharing.sql` is additive and leaves `sigil_vault_ops` and its hash chain
byte-for-byte unchanged, and the audit log records a **SHA-256 fingerprint** of an
envelope, never its bytes. Verified end-to-end with no mocks by
[`../cli/tests/e2e-sharing.sh`](../cli/tests/e2e-sharing.sh): two devices produce
the same RFC 6238 code from the same shared vault, the bytes the server returned
are byte-identical to the bytes uploaded, and the envelope contains neither the
vault key nor the 2FA seed.

**Honest limits.** Dev-gated (`501` by default), plain HTTP, **UNAUDITED**; a
**custom KEM-then-AEAD, NOT RFC 9180 HPKE**; the **system is not "post-quantum
secure"**. Trust in a fetched public key is addressed — but only partly — by the
pinning and safety-number layer in §2c below: substitution **after** first contact
is blocked, **first** contact is trust-on-first-use unless a human compares the
safety number. Revocation stops **future** access but cannot make a device forget a
key it already unwrapped; `vault rotate` (§2c) is the remediation and protects
**future content only**, and it is **manual** — nothing re-keys on revoke and there
is **no rotation schedule and no forward secrecy** for a delivered vault key.
Request signatures on
these routes are **classical Ed25519** — the wrap is hybrid, the authentication is
not. On the browser clients, converting a personal vault into a shared one is a
**one-way door** in the UI, and the `Uint8Array`s holding a vault key or a hybrid
secret are **not zeroized** while the vault is unlocked (JS gives no reliable way to
do so).

### 2b′. Who owns the vault, and who is entitled — the account boundary

§2b's step 4 ("B authorized") hides a question the device model got wrong twice:
**what is the subject that owns a vault, and what is the subject that pays?**
Until Phase 52 both were a **device**, which meant paying on a phone did not
entitle a laptop, and revoking the device that first wrote a vault **orphaned**
that vault forever. The subject is now an **account**
([ADR 0040](decisions/0040-account-model.md)).

```
  OPERATOR TOKEN                    ACCOUNT  (server-assigned id, auth metadata only)
  ──────────────                    ───────────────────────────────────────────────
  sigil device enroll --token <op>  ──▶  founds a NEW account, device A is member #1
                                          │
  sigil account invite  (on A)            │  single-use invite  join_…  (bearer secret,
        └── POST /v1/account/invites      │   256-bit, TTL-bounded, optionally PINNED
            201 { "invite": "join_…" }    │   to one Ed25519 key; shown exactly ONCE)
                                          ▼
  sigil device enroll --token join_…  ──▶  device B JOINS THE SAME account
        (the ORDINARY enroll route: the invite rides the EXISTING
         X-Sigil-Enroll-Token header under the EXISTING challenge, so
         there is NO fourth canonical message and no client change)
                                          │
                    ┌─────────────────────┴─────────────────────┐
                    ▼                                           ▼
   VAULT OWNERSHIP keys off the account            ENTITLEMENT keys off the account
   sigil_vault_owners: vault_id → account_id       billing subject = dev.AccountID
   · first ACCOUNT to write an unclaimed           · pay on the phone, entitled on
     vault owns it (TOFW, one level up)              the laptop
   · every sibling device has full access          · a cancel/refund demotes the
     with NO grant row of its own                    WHOLE account at once
   · revoking A no longer orphans A's vaults
```

⭐ **No request anywhere names an account.** Every handler derives it from
`dev.AccountID` on the device row of the signature it just verified, so a
cross-account request is **unconstructible**, not merely rejected.

⚠️ **Membership is AUTHORIZATION, never DECRYPTION — and that is the seam back to
§2b.** Joining tells the server B may act on the account's vaults; it hands B
**no key**. B still reads nothing until an existing member performs §2b's wrap to
B's hybrid public key. The consequence cuts both ways: a **hostile server can
insert a device into any account** (it writes the registry) and **still cannot
decrypt anything** — its only remaining move is to substitute a hybrid public key
at §2b step 1, which is what §2c defends.

⚠️ **And the failure that only narrowed: recovery exists ONLY if it was printed in
advance.** An account is reachable only through a member device's private key —
or through a **recovery kit**, which is exactly such a key, HKDF-derived from 32
bytes printed on paper before the loss ([ADR 0042](decisions/0042-recovery-kit.md)).
The orphan failure went from "revoke one device" to "lose every device" to "lose
every device **having printed nothing**"; in that last case the account, its
vaults and its subscription are permanently unreachable — by the customer and by
us — and **a kit cannot be created afterwards**. ⚠️ In exchange, **whoever holds
the printed sheet holds the account**, immediately and without notification.
Membership is also **flat** (any member may invite, revoke every sibling and run
checkout) and **immutable** (no transfer, merge, split or deletion). Full lists:
[ADR 0040](decisions/0040-account-model.md), [ADR 0042](decisions/0042-recovery-kit.md).

### 2c. Trust in a fetched public key — the client-side pin store

§2b has one structural weakness: step 1 fetches the recipient's hybrid public key
**from the server**, and the server is explicitly outside the trust boundary. A
hostile or compromised registry could answer with **its own** key, receive the vault
key wrapped to itself, and read the vault — invisibly. Phase 50 answers that
**entirely on the client side**
([ADR 0038](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)).

⭐ **The architectural point: the pin store is a client-side trust store that the
server can neither read nor write.** It is not a protocol feature. `sigild` gained
no knowledge of pins or safety numbers, stores none, serves none, and validates
none — it still relays opaque bytes. The one copy of "which key do I trust for that
device" lives on each client, on the trusted side of the boundary, which is the only
place an answer to a lying server can live.

```
      CLIENT (trusted)                        ║          SERVER (untrusted)
  ┌───────────────────────────────┐           ║
  │ pin store                     │           ║   registry of hybrid PUBLIC keys
  │  deviceID → {x25519, mlkem,   │           ║        │
  │             safety_number,    │           ║        │  GET /v1/devices/{B}/hybrid-key
  │             pinned_at, repins}│           ║        ▼
  └───────────────┬───────────────┘           ║   whatever the server chooses to say
                  │                           ║        │
                  ▼  verify_recipient_for_wrap / verifyRecipientForWrap ◀───┘
        ┌─────────────────────┐               ║
        │ compare RAW bytes   │               ║   ⚠️ the request is authenticated;
        │  first sight → PIN  │  ⚠️ + warn    ║      the RESPONSE is not. Nothing
        │  identical   → OK   │               ║      in the protocol binds this key
        │  DIFFERENT   → STOP │  ⛔ no wrap,  ║      to device B.
        └─────────────────────┘     no upload ║
```

**Where the choke point is.** Enforcement rides on **the fetch itself** —
`verify_recipient_for_wrap` (Rust) / `verifyRecipientForWrap` (JS) return a
recipient only after checking it — and **every** wrap path (share, rotate and
recovery-kit cover), in both implementations, goes through it. That is deliberate:
a trust store that some code path forgets to consult is worthless. In Rust the
rule is enforced **by type**: the gate is the only constructor of a
`VerifiedRecipient`, and the wrap→deposit→grant path accepts nothing else
([ADR 0038](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)
addenda, [ADR 0042](decisions/0042-recovery-kit.md)). The unchecked
`fetch_hybrid_key` / `fetchHybridKey` survive only where nothing is wrapped —
displaying a safety number, the deliberate re-pin, and the desktop's
`check_server`.

⚠️ **The earlier gate was DELETED, not merely bypassed.** `fetch_hybrid_key_pinned`
(Rust) / `fetchHybridKeyPinned` (JS) were this ADR's original choke point.
Phase 54 superseded them and Phase 57 removed them: the Rust one had **zero
callers** and the JS one had exactly **one** (a test), while every document —
including this one — still recommended them by name. They pin, but they do **not**
refuse an unverified recovery kit and do **not** honour a supplied safety number,
so the next caller reaching for the familiar name would have gotten a wrap that
skipped two of the three refusals. A superseded choke point is a ready-made bypass,
not harmless dead code.

**Two implementations, not four.** The Rust `sigil-cli` library serves the CLI **and**
the desktop app ([ADR 0037](decisions/0037-desktop-reuses-cli-library-for-protocol.md));
`sigil-wasm/sharing.mjs` serves the webapp and the extension. The digest must be
byte-identical across both or cross-client verification breaks, so both carry the same
known-answer test and `sigil-wasm/test/pinning-interop.mjs` compares the real `sigil`
binary's output against the JS module's.

**Where the store lives is per-client, and follows each client's existing rule:**

| Client | Pin store | Mode / protection |
|--------|-----------|-------------------|
| `sigil` CLI, native desktop | `hybrid-pins.json` in the state dir (`$HOME/.sigil` by default) — **the same file**, so a CLI pin and a desktop pin are one record | `0600` file in a `0700` dir, written via the same `write_secret_file` helper as other sensitive state (created `0600` up front, `fsync`'d, re-`chmod`'d) |
| webapp, MV3 extension | a `pins` field **inside the existing sealed device-identity container**, schema **v3** | sealed with the same Argon2id → XChaCha20-Poly1305 `SIGILcli` construction as everything else — under the vault password, or (webapp, passkey protection on) under the **container master key** of [ADR 0046](decisions/0046-passkey-protected-local-containers.md). **The browsers still persist only sealed containers** |

The browser choice matters architecturally: it would have been easy to drop a JSON
blob in `localStorage`, and that would have broken the invariant from
[ADR 0028](decisions/0028-webapp-vault-persistence-and-unlock.md) /
[ADR 0033](decisions/0033-browser-device-identity-storage.md) that a browser persists
**nothing in the clear**. Reusing the sealed container keeps the pin store on the same
password, the same lock/unlock lifecycle, and the same one-key-per-client storage
footprint. **v1 and v2 containers still open** and yield an **empty** pin store, so an
existing client keeps working and simply pins on next use.

The pins are **public** key material — but they are security-critical **local** state:
anything that can rewrite the store can silence the alarm before it fires. That is why
they get secret-grade treatment on both sides, and it is a real residual risk on a
compromised host.

**Rotation is the other half.** Pinning and safety numbers protect key
*distribution*; they do nothing about a key already distributed. `sigil vault rotate`
(and the desktop command, and the browser UIs) draws a fresh vault key, re-seals the
container under it, re-wraps to exactly the named devices, and **deletes** every other
device's envelope through the two Phase 50 routes (`GET /v1/vaults/{V}/keys`,
`DELETE /v1/vaults/{V}/keys/{deviceID}`). Every recipient is **pin-checked first**, so
a mismatch aborts before any local or remote state is touched. The full step order and
its crash-safety reasoning are in
[`crypto-spec.md`](crypto-spec.md#vault-key-rotation--the-key-lifecycle).

**All four client surfaces now SHOW the alarm, not just raise it (Phase 51).** The
refusal always happened in the shared library; what differed was whether a user could
see it. The webapp and the extension already blocked and explained; the desktop
tagged the error and then let it expire as a seven-second toast, which is a control
the user effectively does not have. It now renders a blocking `role="alert"` panel
with both safety numbers and a confirm-guarded re-pin, fed by the structured
`IpcError.key_change` described in the `desktop` component above. The refusal itself
did not change — only its visibility — and the path that raises it gained its first
regression test
([`../desktop/core/tests/server_interop.rs`](../desktop/core/tests/server_interop.rs),
which republishes a different hybrid key under the same device id against a real
`sigild`).

⚠️ **Honest scope, because this is the security story people will read fastest:**
pinning **cannot** protect first contact — if the server lies the very first time, the
lie is what gets pinned, and only a human comparing the safety number out of band
catches it. A user who re-pins without checking defeats it. Rotation protects **future
content only**; a device that already unwrapped a key keeps what it copied. And all of
it is **new, unaudited code** in a dev-gated, plain-HTTP posture.

---

## 3. Crypto-agility

Every encrypted record carries a one-byte **algorithm-suite id** *inside* its
envelope frame. A reader dispatches on that byte to select the
`(KDF, KEM, AEAD, signature)` tuple, so records written under an older suite keep
opening after a newer suite is introduced — there is **no flag-day
re-encryption**. The registry today (`AlgorithmSuite`,
[`../libsigil/core/src/lib.rs`](../libsigil/core/src/lib.rs)):

| Byte | Role |
| --- | --- |
| `0x10` | legacy |
| `0x11` | classical |
| `0x12` | **CURRENT** — hybrid post-quantum-*ready* |
| `0x13`–`0x15` | reserved / future |

Adding a suite means: append a variant to the registry, teach the affected layer
to handle it, and start writing the new byte for new records — old bytes remain
decodable. The suite byte is additionally bound into the per-record HKDF `info`
(`"sigil-record-v1" || suite_byte`), so a record sealed under one suite cannot be
opened by deriving a key for another. **The full suite table, the intended
hybrid X25519 & ML-KEM-768 / Ed25519 & ML-DSA-65 construction, and the migration
timeline live in [`crypto-spec.md`](crypto-spec.md)** — not duplicated here. (The
combined hybrid KEM (`hybrid.rs`) and combined hybrid signature (`hybrid_sig.rs`)
both exist. The **KEM is in use** — it wraps vault keys for device-to-device
sharing via `hybrid_seal` — while the **signature is still used by nothing**.
Neither, however, is wired into the **suite frame** itself: the `kem_ct` envelope
field stays *reserved* but unused, and the ML-KEM ciphertext travels alongside the
envelope inside the `SIGILhyb` container; see
[§6](#6-what-is-deliberately-not-here-yet).)

---

## 4. Build & dependency isolation

There are **five Rust build surfaces** plus the Go server, and the boundaries
between them are load-bearing:

1. **The `libsigil` workspace** (`core` + `ffi`) — native build/clippy/test. This
   is the audit target. `core` is `#![forbid(unsafe_code)]`; `ffi` localises all
   `unsafe` to the C-ABI seam.
2. **The `wasm32-unknown-unknown` target** of `sigil-core` — proves the core stays
   browser-linkable. This is **why the core must be RNG-free**: on `wasm32`
   there is no system entropy backend, so `core` never generates randomness — the
   caller supplies the salt and nonce. Consequently **`getrandom` must never enter
   `libsigil/Cargo.lock`** (it would break the wasm build and pull a non-pure
   dependency into the audit-bound core).
3. **The standalone `cli` crate** — deliberately **outside** the `libsigil`
   workspace, with its **own [`../cli/Cargo.lock`](../cli/Cargo.lock)**. Because it
   is native-only (never wasm), it *may* depend on `getrandom` (for the salt/nonce)
   and on `ureq` / `serde` / `serde_json` / `base64` (for the dev push/pull HTTP),
   and those land **only** in the CLI's lockfile. Keeping the CLI a separate crate
   is exactly what prevents those native deps from polluting the wasm-pure,
   audit-bound core. The invariant is mechanical and CI-checkable:
   `grep -c 'name = "getrandom"' libsigil/Cargo.lock` **must stay `0`**, and
   `libsigil/Cargo.lock` must be unchanged by any CLI work. The CLI's `ureq` is
   built with `default-features = false` to strip its TLS stack on purpose — push/pull
   speak plain HTTP to a localhost dev `sigild` only.
4. **The standalone `sigil-wasm` crate** — the `wasm-bindgen` binding, also
   **outside** the `libsigil` workspace with its **own
   [`../sigil-wasm/Cargo.lock`](../sigil-wasm/Cargo.lock)**, path-depending on
   `../libsigil/core`. It compiles to a real `.wasm` via `wasm-pack` (which bundles
   a `wasm-bindgen` matching the pinned `=0.2.100`). Unlike `cli`, it deliberately
   does **not** add `getrandom`: entropy is supplied by JavaScript
   (`crypto.getRandomValues`), so the same mechanical guard applies to a second
   lockfile — `grep -c 'name = "getrandom"' sigil-wasm/Cargo.lock` **must also stay
   `0`**, and `libsigil/Cargo.lock` must be unchanged by any wasm-binding work. This
   is what proves the caller-supplied-entropy invariant end to end into a JS runtime
   (see [`decisions/0019-wasm-client-bindings.md`](decisions/0019-wasm-client-bindings.md)).
5. **The standalone `desktop` workspace** (`sigil-desktop-core` + `sigil-desktop`) —
   the native GUI column, also **outside** the `libsigil` workspace with its **own
   [`../desktop/Cargo.lock`](../desktop/Cargo.lock)**, path-depending on
   `../libsigil/core` **and** `../cli` (the `sigil-cli` **library** target). Because it
   is native-only it may pull Tauri's whole platform stack and, transitively through
   `sigil-cli`, `getrandom` — and all of that lands **only** in `desktop/Cargo.lock`.
   The same mechanical guard applies: `grep -c 'name = "getrandom"' libsigil/Cargo.lock`
   **must stay `0`** and `libsigil/Cargo.lock` must be unchanged by any desktop work.
   This is the surface that links `sigil-core` **natively** — no `wasm-bindgen`, no
   `wasm-pack`, no `.wasm` (see
   [`decisions/0032-native-desktop-client.md`](decisions/0032-native-desktop-client.md)).

`sigild`'s **core server and its in-memory / file-backed dev backends are Go
stdlib-only**, which keeps that surface reproducible and near-zero-dependency.
The **scale & observability** features — bounded/paginated reads, the per-vault
token-bucket rate limiter, the Prometheus-text `/metrics` renderer, and fail-fast
config validation — are **also pure stdlib** ([ADR 0017](decisions/0017-oplog-scale-and-observability.md)),
so they add **no new dependency**. The optional **Postgres** op-log backend
(`SIGILD_OPLOG_POSTGRES`) is the one exception: it links the `pgx` driver — `sigild`'s **first third-party
dependency**, so the module now carries a `go.sum` — and is compiled in but
dormant unless a DSN is configured. This is a deliberate, documented relaxation
of the stdlib-only rule (partially superseding
[`decisions/0005-stdlib-only-sigild.md`](decisions/0005-stdlib-only-sigild.md))
recorded in
[`decisions/0014-postgres-durable-oplog-backend.md`](decisions/0014-postgres-durable-oplog-backend.md);
so the honest framing is "stdlib-only **except** the opt-in Postgres backend,"
not "stdlib-only."

The exact, known-green `fmt`/`clippy`/`test`/`wasm`/`vet`/`build` invocations (and
the `getrandom`-count guard) are maintained in [`../CLAUDE.md`](../CLAUDE.md) and
mirrored by the CI workflows under `../.github/workflows/`; they are **not**
repeated here so there is a single source of truth.

---

## 5. Licensing & posture (architectural facts)

- **License split:** `libsigil` (core + ffi), the CLI, the clients, and `web` are
  Apache-2.0; **`sigild` is BSL-1.1** (source-available server, open-source
  clients). This split is a deliberate architectural choice, not an accident.
- **Posture is stealth / pre-launch:** no public index, request-beta-access,
  **no security claims** until the audit completes and trademark clears. Public
  copy obeys [`../web/apps/marketing/MARKETING-CLAIMS.md`](../web/apps/marketing/MARKETING-CLAIMS.md).
- **No secrets in the repo:** configuration reaches `sigild` only at runtime; see
  the secrets posture in [`deployment.md`](deployment.md).

---

## 6. What is deliberately NOT here yet

To avoid any over-claim, the honest gaps in the current architecture (the
authoritative list, with rationale, is the **defer ledger** in
[`sprint-72h.md`](sprint-72h.md)):

- **One native GUI client now exists; the rest of the native platforms do not.**
  `desktop/` is a real **Tauri v2** desktop authenticator that links `sigil-core`
  **natively** (no wasm) and shares the CLI's sealed `SIGILcli` vault file
  ([ADR 0032](decisions/0032-native-desktop-client.md)) — but it is **dev /
  UNAUDITED**, **unsigned, unnotarized and undistributed** (no `.app` bundle was
  built), its **GUI has not been visually verified** here (all behaviour is proven
  through the headless `sigil-desktop-core` crate and its interop tests), and while it
  now enrolls, syncs and shares like the other clients, it does so only against a
  **dev-gated, loopback, plain-HTTP** server and still has **no QR scanning and no code
  verification**. The
  **mobile** clients (iOS/Android/watch) and the other desktop platforms
  (Windows/Linux) remain **unbuilt**; native apps outside this repo consume `libsigil`
  as a versioned artifact, and the admin console is still a reserved directory. The
  **browser-side** consumer is **`sigil-wasm`** — the first thing to
  actually link the wasm-pure core into a JS runtime — but it is a **demo of the
  UNAUDITED `seal_record` / `open_record` building block**, not a product client
  and not the account / key-management model
  ([ADR 0019](decisions/0019-wasm-client-bindings.md)). It now **closes the
  client↔server sync loop** by push/pulling opaque containers to a dev `sigild`
  op-log (`sync.mjs`; [ADR 0022](decisions/0022-wasm-client-server-sync-loop.md)) and
  can **enroll + sign as a device** under contract v3 (`device-auth.mjs`;
  [ADR 0031](decisions/0031-multi-device-auth-model.md),
  [ADR 0033](decisions/0033-browser-device-identity-storage.md)) — but still only over
  **dev / localhost / plain-HTTP with no TLS** — this demonstrates the E2EE sync
  architecture and a dev request-auth model, it is **not** the product's sync / account
  / CRDT model. The
  **`web/apps/webapp`** Next.js app (over the **`@sigil/wasm`** loader) is now a
  real *browser authenticator UI* running libsigil-via-WebAssembly client-side — a
  multi-account encrypted TOTP vault with add/import (`otpauth://` + Google
  Authenticator)/export, live wasm-computed codes, and a password unlock over a
  `SIGILcli`-sealed container persisted (sealed-only) in `localStorage`
  ([ADR 0027](decisions/0027-webapp-and-wasm-bundling.md),
  [ADR 0028](decisions/0028-webapp-vault-persistence-and-unlock.md)) — but it too is
  **dev / no-index / UNAUDITED**, **not deployed**, and **not** the product's
  account / device / sync-auth or key-management model. The **`extension`**
  directory is likewise no longer reserved: it is a real **MV3 browser extension**
  whose popup is the same wasm authenticator over the same `SIGILcli`-sealed vault
  (sealed-only persistence in `chrome.storage.local`, in-memory password;
  [ADR 0030](decisions/0030-browser-extension-client.md)) — but it is **dev /
  UNAUDITED**, **loaded unpacked and published to no store**, its dev sync is
  **loopback-only by manifest** (`host_permissions` scoped to `127.0.0.1` /
  `localhost`), and it implements **none** of the originally reserved
  extension ambitions (phishing protection, passkey provider, content scripts).
  **Both browser clients can now authenticate as enrolled devices** against a dev
  `SIGILD_DEVICE_AUTH` server ([ADR 0033](decisions/0033-browser-device-identity-storage.md)),
  and since Phase 49 the **native `desktop/` client enrolls, syncs under contract v3 and
  shares vaults too** — by driving the `sigil-cli` library rather than duplicating the
  protocol ([ADR 0037](decisions/0037-desktop-reuses-cli-library-for-protocol.md)) — so
  the auth story is closed across **all four** client surfaces. ⚠️ **But until Phase 56
  the webapp could not reach a real `sigild` at all**: every signed request carries
  `X-Sigil-*` headers, so a browser preflights it, and `sigild` answered every preflight
  `405` with no `Access-Control-*` header. Enrollment, sync, sharing, restore and the
  entitlement read were all blocked **in the browser, before a byte was sent** — for
  twelve phases, while the **MV3 extension worked fine**, because a `host_permissions`
  page is exempt from CORS. The fix is an opt-in, allowlisted
  `SIGILD_CORS_ORIGINS` that is explicitly **not** an authentication or CSRF control
  ([ADR 0044](decisions/0044-opt-in-cors-allowlist.md)). The enrollment UI in both
  browser clients is now Playwright-driven (the webapp's against a real server), the
  desktop's GUI is still build-and-launch verified rather than visually verified (its
  behaviour is proven in the headless core), and none of this is TLS or audited. The
  **account** commands are still uneven: the CLI and the desktop app can mint, list and
  revoke invites; the webapp and the MV3 extension can only **join** and **read** the
  account.
- **Auth, authorization and a minimal account model now exist for the dev op-log
  — an IDENTITY system does not.** The op-log is still **wide open by default**. Two opt-in contracts
  change that: legacy `SIGILD_OPLOG_PUBKEY` (a **single static** Ed25519 dev key,
  contract v2, no authorization at all —
  [ADR 0008](decisions/0008-device-key-request-auth.md),
  [ADR 0010](decisions/0010-op-log-auth-v2-nonce-replay.md)), and the **v3
  multi-device model** (`SIGILD_DEVICE_AUTH`) — a real device registry, enrollment
  with proof of possession, per-vault grants and revocation
  ([ADR 0031](decisions/0031-multi-device-auth-model.md)), now extended with a
  **vault-sharing relay** that distributes wrapped vault keys between authorized
  devices without the server being able to read them
  ([ADR 0035](decisions/0035-device-to-device-vault-sharing.md)) and an **account
  model** that makes entitlement and vault ownership survive a device change
  ([ADR 0040](decisions/0040-account-model.md)). What is still missing
  is the **product** layer: ⚠️ **no identity system** (no email, no password, no
  operator break-glass; the only recovery is a **paper kit printed in advance**,
  [ADR 0042](decisions/0042-recovery-kit.md), and a kit cannot be created after
  the loss), no roles inside an account (membership is **flat**: any member
  may invite, revoke every sibling and run checkout), no account transfer, merge,
  split or deletion, no session or JWT token
  issuance ([`../sigild/internal/auth/`](../sigild/internal/auth/) is still a
  placeholder), no **device-key** rotation or re-enrollment, only a
  **proxy-blind backstop** for rate limiting enrollment and invite minting
  ([ADR 0041](decisions/0041-abuse-bounds-and-the-removed-webhook-limiter.md);
  real per-source limiting belongs at the edge and is configured nowhere in
  `deploy/`), a replay cache that is still
  **per-process** (a multi-instance deploy needs a shared store), and an ownership
  rule (trust-on-first-write, now by account) that is a dev heuristic rather than
  an identity. All of it is **dev-gated and UNAUDITED**.
- **Billing exists in code but has never taken a payment, and lives in the wrong
  place on purpose.** `sigild` has a real **provider-agnostic billing seam**
  (Stripe / Razorpay / Juspay adapters, hosted checkout only, raw-body HMAC
  webhook verification, an idempotent ledger keyed on signature-covered bytes
  ([ADR 0039](decisions/0039-webhook-idempotency-from-signed-bytes.md)), a
  subscription state machine, migration `0003_billing.sql`;
  [ADR 0034](decisions/0034-billing-provider-seam.md)) — **opt-in, dev-gated,
  `501` by default, and UNAUDITED**. What it is **not**: it has **never been run
  against a live provider account** (every test drives a local `httptest` server
  with fake credentials), the **Juspay** scheme is explicitly
  **UNVERIFIED-AGAINST-LIVE-DASHBOARD**, recurring *subscription creation* is
  unimplemented for the two India adapters (their webhook sides map the events,
  but checkout creates a one-time hosted page), the subject is now an **account**
  but that account is **not an identity** (no email, no password, no operator
  break-glass — and every pre-`0005` device was adopted into its own singleton
  account, so an existing two-device customer has two billing subjects),
  entitlement enforcement exists but is **opt-in, write-only and never refuses
  reads** ([ADR 0043](decisions/0043-entitlement-enforcement.md)), and there is
  no fraud, chargeback, refund, proration, tax, dunning or
  reconciliation handling, and **no PCI attestation** (hosted checkout keeps
  scope minimal; it certifies nothing). **Billing living inside the sync server
  is provisional**: it is a scaffold placed where the identity, config, storage
  and observability plumbing already existed, not a claim that money-adjacent
  state belongs in a zero-knowledge sync server.
- **No production storage.** The dev op-log now has an opt-in **durable Postgres
  backend** (`SIGILD_OPLOG_POSTGRES`, on `pgx`;
  [ADR 0014](decisions/0014-postgres-durable-oplog-backend.md)) alongside the
  in-memory (default) and file-backed backends — so it *can* be durable and
  concurrent in dev, now with **managed embedded migrations** (`schema_migrations`,
  `sigild migrate`, `SIGILD_OPLOG_AUTO_MIGRATE`) and a **`pg_dump`/`pg_restore`
  backup runbook whose restore integrity is proved by the op-log hash chain**
  ([ADR 0018](decisions/0018-managed-oplog-migrations-and-backup-integrity.md)) —
  but that is **still not a production store**: no PITR / replication, no
  Redis / object store, and no CRDT around it. (Device enrollment, per-vault
  authorization and account membership *do* now exist as an opt-in dev model,
  [ADR 0031](decisions/0031-multi-device-auth-model.md) +
  [ADR 0040](decisions/0040-account-model.md) — but they are dev-gated,
  unaudited, and an account is auth metadata, not an identity.)
- **Both hybrid constructions are assembled; the KEM is now load-bearing, the
  signature is still used by nothing, and neither is in the suite frame.** For key
  agreement, the **combined hybrid KEM exists**
  (`hybrid.rs`: `hybrid_encapsulate` / `hybrid_decapsulate`;
  [ADR 0011](decisions/0011-hybrid-kem-combiner.md)): the combiner assembles the
  classical X25519 half (`x25519_public_key` / `x25519_shared_secret`;
  caller-supplied 32-byte secret; RFC 7748; rejects the all-zero / non-contributory
  shared secret) and the ML-KEM-768 post-quantum half (`mlkem.rs`: deterministic
  FIPS 203 `keygen`/`encapsulate`/`decapsulate`; caller-supplied `d || z` seed and
  `m` coin; total implicit-rejection decaps) into
  `ss_combined = HKDF-SHA-256(ss_x || ss_kem || transcript_hash, "sigil-hybrid-v1")`
  with `transcript_hash = SHA-256(ephemeral_x25519_pub || mlkem_ct)`. For
  signatures, the **combined hybrid signature exists**
  too (`hybrid_sig.rs`: `hybrid_sign` / `hybrid_verify`;
  [ADR 0012](decisions/0012-hybrid-signature-combiner.md)): the combiner assembles
  the classical Ed25519 half (`sig.rs`; caller-supplied 32-byte seed; UNAUDITED) and
  the ML-DSA-65 post-quantum half (`mldsa.rs`: deterministic FIPS 204 on the
  RustCrypto `ml-dsa` crate; caller-supplied 32-byte keygen seed `xi`; deterministic
  signing; UNAUDITED) into the fixed **3373-byte** `Ed25519.Sign(m) ||
  ML-DSA-65.Sign(m)` (64 + 3309 bytes), where `hybrid_verify` requires **BOTH**
  halves to validate — a forgery requires breaking **both** Ed25519 and ML-DSA-65.
  Both combiners are real but **UNAUDITED**. The hybrid **KEM** is further
  composed with the AEAD into a **hybrid public-key seal/open flow**
  (`hybrid_seal.rs`: `hybrid_seal` / `hybrid_open` — a KEM-then-AEAD encryption to a
  recipient's hybrid public key; bespoke, **NOT** RFC 9180 HPKE;
  [ADR 0013](decisions/0013-hybrid-public-key-seal.md)), and **that flow is now
  load-bearing**: it wraps the vault key for **device-to-device vault sharing**
  ([ADR 0035](decisions/0035-device-to-device-vault-sharing.md)), so the hybrid KEM
  is real product code and in scope for the audit. What is still missing is
  everything else: the **hybrid signature is used by nothing** (all request auth,
  including every sharing route, is classical Ed25519 only); neither construction is
  wired into the **suite frame** (the envelope's `kem_ct` field stays *reserved* but
  unused); sharing is **not** an account/session model; and the **system is still
  not "post-quantum secure"**. The sharing flow's named gaps are **narrower than they
  were** — key substitution after first contact is now blocked by client-side pinning,
  and a safety number makes first contact verifiable (§2c) — but the residue is real:
  **first contact is trust-on-first-use unless a human compares the digits**, there is
  **no key transparency and no cross-signature**, rotation is **manual** with no
  schedule and no automatic re-wrap on revoke, and there is **no forward secrecy** for
  a delivered vault key — and it is **dev-gated and UNAUDITED**.
- **No real operation / CRDT semantics.** The op-log is a plain append-and-read
  byte journal with a monotonic sequence number and a per-op SHA-256 **hash
  chain** for **tamper-evidence** (detects modify/insert/delete/reorder of stored
  ops via a client-side verifier; [ADR 0016](decisions/0016-tamper-evident-oplog-hash-chain.md)) —
  but still **no signed ops**, no Lamport/Merkle ordering, no conflict-free
  merge, and the chain is **tamper-evident, not tamper-proof** (a hostile server
  can lie about `/ops/verify`; the real check is client-side).
- **No real sync protocol, and recovery only as a printed kit.** Device-to-device
  **vault sharing** now exists ([ADR 0035](decisions/0035-device-to-device-vault-sharing.md)),
  a **vault key can now be rotated and re-wrapped**
  ([ADR 0038](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)),
  a **recovery kit** can be printed in advance
  ([ADR 0042](decisions/0042-recovery-kit.md)), and
  billing exists in code (above), but the rest of the product workflows do
  not — and sharing still has **no rotation schedule, no automatic re-wrap on
  revoke, and no key-transparency log or cross-signature** binding a
  recipient's hybrid public key to its enrolled identity (the safety number puts a
  **human** in that loop rather than removing the loop). Recovery now exists on
  **all four** client surfaces (Phase 56), so a customer whose only client was a
  browser can restore into a fresh profile — but a kit still **cannot be created
  after the loss**, still recovers **keys and not data**, and still opens only the
  vaults it was told to **cover**.
- **No live PQ-TLS proof.** `sigild` serves plain HTTP in the skeleton; the hybrid
  `X25519MLKEM768` handshake is unproven on this machine (see
  [`deployment.md`](deployment.md) §3).

Everything above is intentional: the guardrail is to **stub honestly** (`501` /
clear "not implemented") rather than fake crypto or auth and poison the future
audit.
