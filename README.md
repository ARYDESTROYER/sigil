# Sigil (working name)

A paid, multi-platform, end-to-end-encrypted, post-quantum-ready authenticator.

> **STATUS: pre-launch / pre-audit skeleton.** This repository is the
> foundation scaffold from the 72-hour deployment sprint — _not_ a shipping
> product. The sync server and every client are intentionally stubbed.
> `libsigil` now has **real but UNAUDITED** crypto building blocks — an
> Argon2id KDF, an XChaCha20-Poly1305 + HKDF AEAD, and a C-ABI `seal`/`open`
> over them — that are **not wired into any product flow**.
> Everything is pre-audit; **do not store real secrets.** See
> [`docs/sprint-72h.md`](docs/sprint-72h.md) for the
> exact definition of done and the defer ledger.
>
> The name **Sigil** and any domain are **provisional**, pending trademark
> clearance in the US/EU/UK/India.

## What this repo is (today)

- `libsigil/` — Rust crypto core. **Builds, lints, tests, and compiles to
  `wasm32`** — algorithm-suite registry, the crypto-agility envelope codec, a
  real (unaudited) Argon2id KDF and XChaCha20-Poly1305 + HKDF AEAD seal/open
  layer, a real (unaudited) **classical Ed25519** sign/verify primitive
  (`public_key_from_seed`/`sign`/`verify` over a caller-supplied 32-byte seed —
  the core generates no randomness; this is the signature half of the planned
  Ed25519&ML-DSA-65 hybrid, the ML-DSA-65 post-quantum half is **not yet
  implemented**, and the primitive is not yet wired into any auth flow), and a
  real (unaudited) **classical X25519** key-agreement primitive
  (`x25519_public_key`/`x25519_shared_secret` over a caller-supplied 32-byte
  secret scalar — again no in-core randomness; rejects non-contributory shared
  secrets and the raw DH output must be run through a KDF before use; this is the
  classical KEX half of the planned X25519&ML-KEM-768 hybrid), a real (unaudited)
  **post-quantum ML-KEM-768** (FIPS 203) KEM primitive
  (`ml_kem768_keygen`/`ml_kem768_encapsulate`/`ml_kem768_decapsulate`, deterministic
  over a caller-supplied 64-byte `d‖z` keygen seed and 32-byte `m` encapsulation
  coin — still no in-core randomness; decapsulation is total per FIPS 203 implicit
  rejection; the raw shared secret must be run through a KDF before use; this is the
  post-quantum KEM half of the X25519&ML-KEM-768 hybrid), and — **now assembled** —
  a real (unaudited) **hybrid KEM** that combines the two
  (`hybrid_encapsulate`/`hybrid_decapsulate`) into a single 32-byte shared secret
  via HKDF-SHA256 over `ss_x25519 ‖ ss_ml-kem ‖ SHA256(eph_pub ‖ ct)` under a
  `"sigil-hybrid-v1"` domain label — caller-supplied ephemeral X25519 secret +
  ML-KEM coin, no in-core randomness, no new deps; the transcript hash binds the
  ciphertext material, and both halves feed the output so the combined key is
  designed to stay secret if **either** the X25519 **or** the ML-KEM-768 component
  holds (the standard hybrid-combiner property). **The hybrid KEM primitive now
  exists but is UNAUDITED and standalone — NOT wired into any key-exchange /
  session / account / vault flow; the ML-DSA-65 post-quantum *signature* half of
  the other planned hybrid is still not implemented, and the system is NOT
  "post-quantum secure"**), plus a
  `sigil-ffi` C-ABI (`seal`/`open`/`buffer_free`, and the classical Ed25519 sig
  exports `sigil_public_key_from_seed`/`sigil_sign`/`sigil_verify` with a
  `SIGIL_ERR_VERIFY` code) for the clients.
- `sigild/` — Go sync server. **Builds, vets, tests** (incl. real-socket
  `httptest` HTTP integration tests, race-clean). Serves `/healthz`, `/readyz`,
  `/version`, and a deliberate `501` on `/v1/vaults/{id}/ops` by default. Behind a
  dev flag (`SIGILD_ENABLE_DEV_OPS`, default off) the ops route becomes an op-log
  that stores **opaque client-encrypted blobs** and hands them back unchanged — by
  default **in-memory** (non-durable), or, when `SIGILD_OPLOG_DIR` is set, a
  **file-backed durable** backend (path-traversal-safe filenames; **dev-only, NOT
  the production store**). Op-log requests are **unauthenticated by default**, but
  when `SIGILD_OPLOG_PUBKEY` (std-base64 of a 32-byte Ed25519 public key) is set
  the server **verifies an Ed25519 signature (contract v2)** (Go stdlib
  `crypto/ed25519`) over a canonical `(method,path,query,timestamp,nonce,body)`
  message — with a fresh per-request `X-Sigil-Nonce` and a **time-bounded, in-memory
  replay cache** that rejects a replayed request within the 300 s window (`401`
  "replayed request") — on every op-log request (else `401`). A **single static dev
  key**; the replay cache is **per-process/in-memory** (multi-instance needs a shared
  store); **dev-only** (enrollment / multi-device / JWT are future). Performs no
  crypto on the blob —
  never decodes it. Ships a distroless `Dockerfile`.
- `cli/` — `sigil`, a **pre-audit demo CLI** that seals/opens one file via the
  libsigil core (`sigil seal`/`sigil open`), plus `sigil push`/`sigil pull` — a
  two-device **opaque sync demo** that ships the sealed container to/from
  sigild's op-log over plain HTTP (**dev / localhost only**; the server never
  decrypts). `sigil keygen` writes a 0600 device-key file and prints the pubkey for
  `SIGILD_OPLOG_PUBKEY`; `push`/`pull` then **Ed25519-sign** the request with
  `--key` (or `SIGIL_DEVICE_KEY`) so a pubkey-configured server accepts them
  (no key → unsigned, as before) — **dev-only**. `pull` is **incremental** — a
  per-vault cursor is kept in the out-dir, so repeat pulls fetch only new ops.
  Standalone crate; unaudited; not for real secrets.
- `web/apps/marketing/` — Next.js 15 stealth splash + early-access waitlist +
  privacy/terms/imprint stubs. **No-index, password-wallable.**
- `docs/` — architecture map, threat model, crypto spec, op-log API reference,
  and the sprint plan (kept internal/pre-audit), plus `docs/decisions/` —
  Architecture Decision Records (ADRs) for load-bearing choices.
- `deploy/` — Terraform / Nomad / Caddy / systemd skeletons, plus `local/` (a
  loopback-only Caddy→sigild `docker compose` topology smoke — no real TLS, torn
  down after) and `preflight.sh` (a read-only GO/NO-GO deploy gate). The offline
  IaC validators (`caddy validate`, `terraform validate`, `nomad job validate`)
  pass and the loopback topology was probed, but **nothing is published / applied /
  exposed** and there is **no domain**. A manual, `workflow_dispatch`-only workflow
  (`.github/workflows/publish-sigild.yml`) publishes the `sigild` image to a
  **private** GHCR package only when a human triggers it — see
  [ADR 0009](docs/decisions/0009-manual-gated-deploy-and-publish.md).

## Repository layout

```
libsigil/        Rust crypto core (workspace: core + ffi)
sigild/          Go sync server (cmd/server, cmd/worker-*, internal/*)
web/             Next.js marketing (+ webapp/admin reserved), pnpm workspace
extension/       Browser extension (reserved)
cli/             Rust demo CLI — `sigil` seals/opens a file via libsigil (pre-audit)
deploy/          terraform / nomad / caddy / systemd + local/ (loopback smoke) + preflight.sh
docs/            architecture, threat model, crypto spec, op-log API, sprint plan
docs/decisions/  Architecture Decision Records (ADRs)
```

Native platform clients (iOS/Android/macOS/Windows/Linux/watchOS/wearOS) live in
**separate repositories** and consume `libsigil` as a versioned binary artifact.

## Toolchains

- Rust stable (rustfmt, clippy, `wasm32-unknown-unknown` target) — pinned in
  [`rust-toolchain.toml`](rust-toolchain.toml).
- Go 1.24+ (the brief targets 1.24.x for the native `X25519MLKEM768` TLS group).
- Node 22 (`.nvmrc`) + pnpm 9 (via Corepack).

## Build & test

```bash
# Rust crypto core
cargo fmt   --manifest-path libsigil/Cargo.toml --all -- --check
cargo clippy --manifest-path libsigil/Cargo.toml --all-targets -- -D warnings
cargo test  --manifest-path libsigil/Cargo.toml
cargo build --manifest-path libsigil/Cargo.toml -p sigil-core --target wasm32-unknown-unknown

# Rust demo CLI (separate crate; native-only)
cargo test  --manifest-path cli/Cargo.toml

# Go sync server
( cd sigild && gofmt -l . && go vet ./... && go test ./... && go build ./... )

# Web (marketing)
( cd web && pnpm install && pnpm lint && pnpm typecheck && pnpm build )
```

## Licensing

Dual model (see [`LICENSE`](LICENSE)):

- **`libsigil/`, clients, CLI, web** → Apache-2.0 ([`LICENSE-APACHE`](LICENSE-APACHE)).
- **`sigild/` (the server)** → intended Business Source License 1.1 (converting
  to Apache-2.0), matching the "open-source clients, source-available server"
  posture in the brief. **Server license text deferred** — not finalized yet.

## Security

Pre-audit. Report issues per [`SECURITY.md`](SECURITY.md). Public marketing copy
must obey [`web/apps/marketing/MARKETING-CLAIMS.md`](web/apps/marketing/MARKETING-CLAIMS.md)
— no "audited" / "SOC 2" / "post-quantum secure" claims until they are true.
