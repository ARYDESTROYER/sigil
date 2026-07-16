# Sigil system architecture (condensed)

> **STATUS: pre-audit skeleton.** This is the *system shape* of the repository
> as it stands today (the 72-hour foundation sprint, through the dev-gated
> op-log and its optional Ed25519 device-key request auth). It is **not** a
> shipping product. `libsigil` contains **real but
> UNAUDITED** cryptographic building blocks — an Argon2id KDF, an
> XChaCha20-Poly1305 + HKDF-SHA256 AEAD, a composed `seal_record`/`open_record`,
> and a C-ABI over them — that are **not wired into a finished
> account/key-management product**. `sigild` performs **no cryptography** and
> stores only opaque blobs. No security claims hold yet: nothing here is
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
the crypto) and a **server skeleton** (which does none). The pieces in this repo:

- **`libsigil/core`** ([`../libsigil/core/`](../libsigil/core/)) — the Rust
  crypto core. `#![forbid(unsafe_code)]`, `no_std` (uses `core` + `alloc`), and
  compiles to `wasm32-unknown-unknown` so the future web app / extension can link
  it. It contains:
  - the **algorithm-suite registry** (`AlgorithmSuite`, bytes `0x10`–`0x15`,
    current `0x12`) and the `ENVELOPE_VERSION` constant;
  - the **crypto-agility envelope codec** (`Envelope::encode`/`decode`) — a
    self-describing wire frame, serialization only;
  - the **Argon2id KDF** (`derive_master_key`, `Argon2Params`) — password → 32-byte
    master key;
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
    mix-and-match. Real but UNAUDITED and **standalone** — not wired into suite
    `0x12` or any record/vault/account flow (the envelope's `kem_ct` field stays
    reserved), and the system is still not "post-quantum secure". See
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
    secure"). Real but UNAUDITED and **standalone** — not wired into suite `0x12` or
    any record/vault/account/session flow (the `sigild` op-log request auth still
    uses classical Ed25519 only), and the system is still not "post-quantum secure".
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
    **bespoke composition — NOT RFC 9180 HPKE** — and the **first wiring of a hybrid
    primitive into an encryption flow**. Real but UNAUDITED and **standalone**: a
    crypto-level flow, **not** the product's account / key-management /
    vault-storage model; `sigild` never uses it and the CLI exercises it only as a
    demo (its `hybrid-keygen` / `hybrid-seal` / `hybrid-open` commands, above). The
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
  (**NOT** RFC 9180 HPKE), still **real but UNAUDITED** and not wired into a product
  flow. (Plus `sigil_current_suite` as a link/smoke check.) All with a
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
  A **standalone crate** with its own lockfile (see
  [§5](#5-build--dependency-isolation)). Keeps a loud UNAUDITED /
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
  both directions. It wraps **only** the symmetric `seal_record` / `open_record` /
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
- **`sigild`** ([`../sigild/`](../sigild/)) — the Go sync-server **skeleton**. Serves
  `/healthz`, `/readyz`, `/version`, request-ID / access-log / panic-recovery
  middleware, and a **dev-gated** (`SIGILD_ENABLE_DEV_OPS`, default off → `501`),
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
  `sigild` performs **no cryptography** and never sees plaintext or keys. Full
  contract in [`api.md`](api.md).
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
  repo-root `sigil-wasm/{totp-vault,sync,totp-migration}.mjs` by relative import — the
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
  only; no TLS, no auth). Proven GREEN by headless Playwright feature smokes
  (`tests/wasm.spec.ts`): add-account reproduces the RFC 6238 vector `287082`, a Google
  Authenticator migration URI imports, and a lock/reload/unlock round-trip restores the
  persisted vault ([ADR 0028](decisions/0028-webapp-vault-persistence-and-unlock.md)).
  It carries the **same no-index stealth posture as
  marketing** (`X-Robots-Tag noindex/nofollow/noarchive`, `X-Content-Type-Options
  nosniff`, `Referrer-Policy no-referrer`, `X-Frame-Options DENY`, plus an
  `app/robots.ts` `Disallow: /`) and a loud **UNAUDITED / no-real-secrets** banner.
  It is **dev / no-index / UNAUDITED**, **not deployed**, and — because it needs the
  **Rust + wasm-pack toolchain** — it is **built via its own filter and kept OUT of the
  default `web` CI build**, so marketing typecheck/lint/build and CI are unchanged and
  stay Rust-free (see [ADR 0027](decisions/0027-webapp-and-wasm-bundling.md)).

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
   │  SERVER SIDE — sigild (Go)        NO CRYPTO · OPAQUE BLOBS ONLY         │
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
     client-side only; dev / no-index / UNAUDITED; not deployed.
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
non-durable and unauthenticated by default — optionally guarded by a single
static Ed25519 dev device key (`SIGILD_OPLOG_PUBKEY`, contract v2: a per-request
nonce checked against a time-bounded in-memory replay cache; real multi-device
auth is still future) — which is why it is dev-gated-off and must never be
exposed or hold real secrets.

**A second, public-key data path exists at the crypto level (not yet wired into
the product).** The flow above is the *symmetric*, password-derived path
(`seal_record` / `open_record`), and it is the only one the CLI packages.
`sigil-core` now also provides an *encrypt-to-a-recipient's-hybrid-public-key*
path — `hybrid_seal` / `hybrid_open`
([`../libsigil/core/src/hybrid_seal.rs`](../libsigil/core/src/hybrid_seal.rs)) — a
**KEM-then-AEAD** composition: `hybrid_seal` hybrid-encapsulates a fresh 32-byte
shared secret to the recipient's `(X25519 public key, ML-KEM-768 encapsulation
key)`, seals the plaintext under that secret with the same XChaCha20-Poly1305 AEAD,
and emits `(ephemeral X25519 public key, ML-KEM-768 ciphertext, envelope)`; the
recipient's `hybrid_open` decapsulates with its hybrid secret keys and opens the
envelope. This is the **first wiring of a hybrid primitive into an encryption
flow**, but it is a **crypto-level building block only** — bespoke (**NOT** RFC
9180 HPKE), UNAUDITED, and **not** the product's account / key-management /
vault-storage model; `sigild` never uses it, and the CLI exercises it only as a
demo (its `hybrid-keygen` / `hybrid-seal` / `hybrid-open` commands). See
[`crypto-spec.md`](crypto-spec.md) and
[`decisions/0013-hybrid-public-key-seal.md`](decisions/0013-hybrid-public-key-seal.md).

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
now exist as **standalone** primitives, but they and the individual
KEM/signature primitives are **not yet wired into the suite frame** — the
`kem_ct` envelope field stays *reserved* but unused; see
[§6](#6-what-is-deliberately-not-here-yet).)

---

## 4. Build & dependency isolation

There are **four Rust build surfaces** plus the Go server, and the boundaries
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

- **No clients / extension (but the client column has started, and now reaches a
  real browser app).** The native apps
  (iOS/Android/macOS/Windows/Linux/watch) live in separate repos and consume
  `libsigil` as a versioned artifact; none exist yet, and the admin console and
  browser extension are still reserved directories. The **one**
  client-side consumer that now exists is **`sigil-wasm`** — the first thing to
  actually link the wasm-pure core into a JS runtime — but it is a **demo of the
  UNAUDITED `seal_record` / `open_record` building block**, not a product client
  and not the account / key-management model
  ([ADR 0019](decisions/0019-wasm-client-bindings.md)). It now **closes the
  client↔server sync loop** by push/pulling opaque containers to a dev `sigild`
  op-log (`sync.mjs`; [ADR 0022](decisions/0022-wasm-client-server-sync-loop.md)),
  but only over **dev / localhost / plain-HTTP / no-auth** — this demonstrates the
  E2EE sync architecture, it is **not** the product's sync / auth / CRDT model. The
  **`web/apps/webapp`** Next.js app (over the **`@sigil/wasm`** loader) is now a
  real *browser authenticator UI* running libsigil-via-WebAssembly client-side — a
  multi-account encrypted TOTP vault with add/import (`otpauth://` + Google
  Authenticator)/export, live wasm-computed codes, and a password unlock over a
  `SIGILcli`-sealed container persisted (sealed-only) in `localStorage`
  ([ADR 0027](decisions/0027-webapp-and-wasm-bundling.md),
  [ADR 0028](decisions/0028-webapp-vault-persistence-and-unlock.md)) — but it too is
  **dev / no-index / UNAUDITED**, **not deployed**, and **not** the product's
  account / device / sync-auth or key-management model.
- **No real auth or authorization.** The dev op-log is wide open by default; an
  optional `SIGILD_OPLOG_PUBKEY` enables a **single static** Ed25519 dev
  device-key signature check (contract v2: a per-request nonce plus a
  time-bounded, **per-process** in-memory replay cache — a multi-instance deploy
  would need a shared store), but there is no device enrollment, no multi-device
  registry, no JWT auth, and no per-vault membership check
  ([`decisions/0008-device-key-request-auth.md`](decisions/0008-device-key-request-auth.md),
  [`decisions/0010-op-log-auth-v2-nonce-replay.md`](decisions/0010-op-log-auth-v2-nonce-replay.md)).
- **No production storage.** The dev op-log now has an opt-in **durable Postgres
  backend** (`SIGILD_OPLOG_POSTGRES`, on `pgx`;
  [ADR 0014](decisions/0014-postgres-durable-oplog-backend.md)) alongside the
  in-memory (default) and file-backed backends — so it *can* be durable and
  concurrent in dev, now with **managed embedded migrations** (`schema_migrations`,
  `sigild migrate`, `SIGILD_OPLOG_AUTO_MIGRATE`) and a **`pg_dump`/`pg_restore`
  backup runbook whose restore integrity is proved by the op-log hash chain**
  ([ADR 0018](decisions/0018-managed-oplog-migrations-and-backup-integrity.md)) —
  but that is **still not a production store**: no PITR / replication, no
  Redis / object store, and no auth / enrollment / CRDT around it.
- **Both hybrid constructions are assembled; the hybrid KEM now drives a
  crypto-level seal/open flow, but neither is in the product flow.** For key
  agreement, the **combined hybrid KEM exists as a standalone primitive**
  (`hybrid.rs`: `hybrid_encapsulate` / `hybrid_decapsulate`;
  [ADR 0011](decisions/0011-hybrid-kem-combiner.md)): the combiner assembles the
  classical X25519 half (`x25519_public_key` / `x25519_shared_secret`;
  caller-supplied 32-byte secret; RFC 7748; rejects the all-zero / non-contributory
  shared secret) and the ML-KEM-768 post-quantum half (`mlkem.rs`: deterministic
  FIPS 203 `keygen`/`encapsulate`/`decapsulate`; caller-supplied `d || z` seed and
  `m` coin; total implicit-rejection decaps) into
  `ss_combined = HKDF-SHA-256(ss_x || ss_kem || transcript_hash, "sigil-hybrid-v1")`
  with `transcript_hash = SHA-256(ephemeral_x25519_pub || mlkem_ct)`. For
  signatures, the **combined hybrid signature now exists as a standalone primitive**
  too (`hybrid_sig.rs`: `hybrid_sign` / `hybrid_verify`;
  [ADR 0012](decisions/0012-hybrid-signature-combiner.md)): the combiner assembles
  the classical Ed25519 half (`sig.rs`; caller-supplied 32-byte seed; UNAUDITED) and
  the ML-DSA-65 post-quantum half (`mldsa.rs`: deterministic FIPS 204 on the
  RustCrypto `ml-dsa` crate; caller-supplied 32-byte keygen seed `xi`; deterministic
  signing; UNAUDITED) into the fixed **3373-byte** `Ed25519.Sign(m) ||
  ML-DSA-65.Sign(m)` (64 + 3309 bytes), where `hybrid_verify` requires **BOTH**
  halves to validate — a forgery requires breaking **both** Ed25519 and ML-DSA-65.
  Both combiners are real but **UNAUDITED**. The hybrid **KEM** is now further
  composed with the AEAD into a standalone **hybrid public-key seal/open flow**
  (`hybrid_seal.rs`: `hybrid_seal` / `hybrid_open` — a KEM-then-AEAD encryption to a
  recipient's hybrid public key, the **first wiring of a hybrid primitive into an
  encryption flow**; bespoke, **NOT** RFC 9180 HPKE;
  [ADR 0013](decisions/0013-hybrid-public-key-seal.md)). But that remains a
  **crypto-level** flow only: neither hybrid construction is wired into the
  **product's account / session / vault-storage flow** (the envelope's `kem_ct`
  field stays *reserved* but unused, and the `sigild` op-log request auth still uses
  classical Ed25519 only), and the **system is still not "post-quantum secure"**.
  The remaining crypto gap is therefore **wiring the hybrid primitives into the
  product account/session/record model** — `sigild` is unchanged and the CLI only
  **demos** the hybrid seal/open flow (its `hybrid-keygen` / `hybrid-seal` /
  `hybrid-open` commands), not the product model, and the hybrid signature is not
  yet composed into any flow.
- **No real operation / CRDT semantics.** The op-log is a plain append-and-read
  byte journal with a monotonic sequence number and a per-op SHA-256 **hash
  chain** for **tamper-evidence** (detects modify/insert/delete/reorder of stored
  ops via a client-side verifier; [ADR 0016](decisions/0016-tamper-evident-oplog-hash-chain.md)) —
  but still **no signed ops**, no Lamport/Merkle ordering, no conflict-free
  merge, and the chain is **tamper-evident, not tamper-proof** (a hostile server
  can lie about `/ops/verify`; the real check is client-side).
- **No payments / accounts / sync protocol / key rotation / recovery.** None of
  the product workflows exist.
- **No live PQ-TLS proof.** `sigild` serves plain HTTP in the skeleton; the hybrid
  `X25519MLKEM768` handshake is unproven on this machine (see
  [`deployment.md`](deployment.md) §3).

Everything above is intentional: the guardrail is to **stub honestly** (`501` /
clear "not implemented") rather than fake crypto or auth and poison the future
audit.
