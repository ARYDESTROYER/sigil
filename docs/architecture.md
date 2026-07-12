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
    seed** (real but UNAUDITED; a standalone primitive, **not yet** wired into the
    hybrid `Ed25519 & ML-DSA-65` signature of suite `0x12` — the ML-DSA-65
    post-quantum half stays unimplemented);
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

  Consistent with the above, **`core` generates NO randomness** — the Argon2 salt,
  the AEAD nonce, the Ed25519 signing seed, the X25519 secret scalar, and the
  ML-KEM-768 keygen seed (`d || z`) and encapsulation coin (`m`) — including the
  ephemeral X25519 secret and ML-KEM coin the hybrid KEM combiner consumes — are
  **all caller-supplied**, so the core stays `wasm32-unknown-unknown`-pure and
  `getrandom`-free (see
  [`decisions/0007-caller-supplied-entropy-in-core.md`](decisions/0007-caller-supplied-entropy-in-core.md)).
- **`libsigil/ffi`** ([`../libsigil/ffi/`](../libsigil/ffi/)) — a thin, hand-written
  **C-ABI** over the core: the AEAD layer `sigil_seal` / `sigil_open` /
  `sigil_buffer_free`, and — alongside it — the classical **Ed25519** primitive
  `sigil_public_key_from_seed` / `sigil_sign` / `sigil_verify`, so the same
  standalone, UNAUDITED sign/verify the CLI uses is reachable over the C-ABI too
  (plus `sigil_current_suite` as a link/smoke check), with a hand-maintained
  [`sigil.h`](../libsigil/ffi/include/sigil.h). This is the seam the native
  clients (in separate repos) will link against. It is the only crate with
  `unsafe` (the FFI boundary); `core` forbids it.
- **`cli`** ([`../cli/`](../cli/)) — `sigil`, a **pre-audit demonstration** binary.
  `seal`/`open` wrap one file in a self-describing container via the real
  `sigil-core` record API; `push`/`pull` move that **opaque** container to/from a
  **dev/localhost** `sigild` op-log over **plain HTTP** (no TLS). A **standalone
  crate** with its own lockfile (see [§5](#5-build--dependency-isolation)). Keeps a
  loud UNAUDITED / not-for-real-secrets banner.
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
  **two dev backends**: an **in-memory, non-durable** map (the default) and an
  optional **file-backed** one selected via `SIGILD_OPLOG_DIR` for local-dev
  durability (the `vaultID` is base64url-encoded to a safe flat filename to
  prevent path traversal). Both are dev-only and opaque; **production storage
  (Postgres/S3, with auth/backups/restore) is still unbuilt** — see
  [`decisions/0006-file-backed-dev-op-log-backend.md`](decisions/0006-file-backed-dev-op-log-backend.md).
  `sigild` performs **no cryptography** and never sees plaintext or keys. Full
  contract in [`api.md`](api.md).
- **`web/apps/marketing`** ([`../web/apps/marketing/`](../web/apps/marketing/)) —
  Next.js 15 stealth splash + early-access waitlist. No-index, wallable, no
  product surface.

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
   │   │   X25519 key-agreement   (secret caller-supplied; no RNG)       │    │
   │   │   ML-KEM-768 KEM  (keygen d||z / m coin; caller-supplied)       │    │
   │   │   hybrid KEM: X25519 & ML-KEM-768 → HKDF combiner               │    │
   │   └───────────────┬───────────────────────────────┬────────────────┘    │
   │                   │ Rust path-dep                  │ C-ABI               │
   │      ┌────────────┴───────────┐        ┌───────────┴───────────────┐     │
   │      │ cli  (sigil)           │        │ libsigil/ffi  + sigil.h    │     │
   │      │ seal/open file         │        │ sigil_seal / sigil_open /  │     │
   │      │ push/pull (dev HTTP)   │        │ sigil_buffer_free          │     │
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
   │   /v1/vaults/{id}/ops  →  501 by default                               │
   │     └─ SIGILD_ENABLE_DEV_OPS: in-memory op-log of opaque ciphertext    │
   │        (append seq / read since) — dev wiring only; unauthenticated    │
   │        unless SIGILD_OPLOG_PUBKEY sets a single Ed25519 dev device key  │
   └───────────────────────────────────────────────────────────────────────┘

   web/apps/marketing (Next.js): stealth splash + waitlist. Separate; no product surface.
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
   ┌───────────────────────────────┴──────────────── CLI container (cli) ─────┐
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
[`threat-model.md`](threat-model.md)). Note the current dev op-log is *also*
non-durable and unauthenticated by default — optionally guarded by a single
static Ed25519 dev device key (`SIGILD_OPLOG_PUBKEY`, contract v2: a per-request
nonce checked against a time-bounded in-memory replay cache; real multi-device
auth is still future) — which is why it is dev-gated-off and must never be
exposed or hold real secrets.

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
combined hybrid KEM now exists as a **standalone** primitive (`hybrid.rs`), but it
and the individual KEM/signature primitives are **not yet wired into the suite
frame** — the `kem_ct` envelope field stays *reserved* but unused — and the
ML-DSA-65 signature half is still unimplemented; see
[§6](#6-what-is-deliberately-not-here-yet).)

---

## 4. Build & dependency isolation

There are **three Rust build surfaces** plus the Go server, and the boundaries
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

`sigild` is **Go stdlib-only / hermetic** — no third-party modules — which keeps
the server build reproducible and its dependency surface near-zero.

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

- **No clients / extension.** The native apps (iOS/Android/macOS/Windows/Linux/
  watch) live in separate repos and consume `libsigil` as a versioned artifact;
  none exist yet. The web app, admin console, and browser extension are reserved
  directories.
- **No real auth or authorization.** The dev op-log is wide open by default; an
  optional `SIGILD_OPLOG_PUBKEY` enables a **single static** Ed25519 dev
  device-key signature check (contract v2: a per-request nonce plus a
  time-bounded, **per-process** in-memory replay cache — a multi-instance deploy
  would need a shared store), but there is no device enrollment, no multi-device
  registry, no JWT auth, and no per-vault membership check
  ([`decisions/0008-device-key-request-auth.md`](decisions/0008-device-key-request-auth.md),
  [`decisions/0010-op-log-auth-v2-nonce-replay.md`](decisions/0010-op-log-auth-v2-nonce-replay.md)).
- **No durable storage.** No Postgres / Redis / object store is wired — the op-log
  is an in-memory map, lost on restart. No schema, migration, backup, or restore.
- **The combined hybrid KEM is assembled but wired into no flow, and there is no
  hybrid signature yet.** For key agreement, the **combined hybrid KEM now exists
  as a standalone primitive** (`hybrid.rs`: `hybrid_encapsulate` /
  `hybrid_decapsulate`; [ADR 0011](decisions/0011-hybrid-kem-combiner.md)): the
  combiner assembles the classical X25519 half (`x25519_public_key` /
  `x25519_shared_secret`; caller-supplied 32-byte secret; RFC 7748; rejects the
  all-zero / non-contributory shared secret) and the ML-KEM-768 post-quantum half
  (`mlkem.rs`: deterministic FIPS 203 `keygen`/`encapsulate`/`decapsulate`;
  caller-supplied `d || z` seed and `m` coin; total implicit-rejection decaps) into
  `ss_combined = HKDF-SHA-256(ss_x || ss_kem || transcript_hash, "sigil-hybrid-v1")`
  with `transcript_hash = SHA-256(ephemeral_x25519_pub || mlkem_ct)`. It is real but
  **UNAUDITED and standalone** — not wired into a record / vault / account / session
  flow, and the envelope's `kem_ct` field stays *reserved* but unused. For
  signatures, the **classical Ed25519 half is implemented** as a standalone
  `sign`/`verify` primitive (caller-supplied seed; UNAUDITED), but the **ML-DSA-65
  post-quantum half is not**, so the combined hybrid signature does not yet exist.
  The remaining crypto gaps are therefore the **ML-DSA-65 PQ signature half** and
  **wiring the hybrid KEM into an actual account/session flow**; today only the
  symmetric path (Argon2id → AEAD → envelope) runs end-to-end.
- **No real operation / CRDT semantics.** The op-log is a plain append-and-read
  byte journal with a monotonic sequence number — no signed ops, no Lamport/Merkle
  ordering, no conflict-free merge.
- **No payments / accounts / sync protocol / key rotation / recovery.** None of
  the product workflows exist.
- **No live PQ-TLS proof.** `sigild` serves plain HTTP in the skeleton; the hybrid
  `X25519MLKEM768` handshake is unproven on this machine (see
  [`deployment.md`](deployment.md) §3).

Everything above is intentional: the guardrail is to **stub honestly** (`501` /
clear "not implemented") rather than fake crypto or auth and poison the future
audit.
