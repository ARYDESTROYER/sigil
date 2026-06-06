# Sigil system architecture (condensed)

> **STATUS: pre-audit skeleton.** This is the *system shape* of the repository
> as it stands today (the 72-hour foundation sprint, through the dev-gated
> op-log). It is **not** a shipping product. `libsigil` contains **real but
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
    end-to-end call (Argon2id → AEAD → envelope codec) that adds no new crypto.
- **`libsigil/ffi`** ([`../libsigil/ffi/`](../libsigil/ffi/)) — a thin, hand-written
  **C-ABI** over the AEAD layer: `sigil_seal` / `sigil_open` / `sigil_buffer_free`
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
  **unauthenticated**, **in-memory**, **non-durable** vault op-log that stores
  **opaque client-encrypted blobs** and hands them back unchanged. It performs
  **no cryptography** and never sees plaintext or keys. Full contract in
  [`api.md`](api.md).
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
   │     └─ SIGILD_ENABLE_DEV_OPS: in-memory, unauthenticated op-log of     │
   │        opaque ciphertext (append seq / read since) — dev wiring only   │
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
unauthenticated and non-durable, which is why it is dev-gated-off and must never
be exposed or hold real secrets.

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
`kem_ct` envelope field and the KEM/signature halves of the suites are reserved
in the frame but **not yet implemented**; see [§6](#6-what-is-deliberately-not-here-yet).)

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
   dependency into the audited core).
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
- **No real auth or authorization.** The dev op-log is wide open; there is no
  device-key authentication and no per-vault membership check.
- **No durable storage.** No Postgres / Redis / object store is wired — the op-log
  is an in-memory map, lost on restart. No schema, migration, backup, or restore.
- **No KEM / signatures in a flow.** The hybrid X25519 & ML-KEM-768 key
  encapsulation and Ed25519 & ML-DSA-65 signatures of suite `0x12` are *specified*
  and *reserved* in the envelope (`kem_ct`), but **not implemented**. Only the
  symmetric path (Argon2id → AEAD → envelope) actually runs.
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
