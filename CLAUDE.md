# CLAUDE.md — working guide for this repo

> **Onboarding — the required first step for any new session.** Before changing
> anything, orient by reading, in order: (i) [`journal.md`](journal.md) — the
> running log of everything done, why, and what's next (the source of truth for
> context that isn't obvious from the code); then (ii) the [`docs/`](docs/)
> folder **in full** — start with [`docs/README.md`](docs/README.md) (the index),
> then [`docs/architecture.md`](docs/architecture.md) (the system shape, data
> flow, and trust boundary), then the rest:
> [`api.md`](docs/api.md), [`crypto-spec.md`](docs/crypto-spec.md),
> [`threat-model.md`](docs/threat-model.md), [`deployment.md`](docs/deployment.md),
> and [`sprint-72h.md`](docs/sprint-72h.md). **And keep `journal.md` updated** —
> **frequently and in depth**, at the start and end of every work session and
> after every meaningful decision, build, test, or scope change. **And keep the
> `docs/` files in sync with the code in the SAME change, not later**: when you
> change the HTTP surface update [`api.md`](docs/api.md); a component or data flow,
> [`architecture.md`](docs/architecture.md); crypto, [`crypto-spec.md`](docs/crypto-spec.md);
> the deploy story, [`deployment.md`](docs/deployment.md); and record any
> load-bearing decision as an ADR under [`docs/decisions/`](docs/decisions/).

## What this is

**Sigil (working name)** — a paid, multi-platform, end-to-end-encrypted,
post-quantum-*ready* authenticator. This repo is the **pre-launch / pre-audit
foundation scaffold** from the 72-hour deployment sprint. It is **not** a
shipping product: the sync server and clients are stubbed, and `libsigil` has
**real but UNAUDITED** crypto building blocks — an Argon2id KDF, an
XChaCha20-Poly1305 + HKDF AEAD, and a C-ABI `seal`/`open` over them — that are
**not wired into any product flow**. Pre-audit — **do not store real
secrets.** See [`docs/sprint-72h.md`](docs/sprint-72h.md).

Posture is **stealth**: defensive, no-index, request-beta-access. Ship nothing
public, make no security claims, until the audit completes and trademark clears.

## Repository map

- `libsigil/` — Rust crypto core (`core` = suite registry + envelope codec +
  real-but-unaudited Argon2id KDF, XChaCha20-Poly1305+HKDF AEAD, composed
  `seal_record`/`open_record`, and a classical **Ed25519** sign/verify primitive
  (`public_key_from_seed`/`sign`/`verify`, caller-supplied 32-byte seed, no
  in-core RNG; the signature half of the future Ed25519&ML-DSA-65 hybrid — the
  PQ ML-DSA-65 half now also exists (below); primitive not yet wired into auth), and
  a classical **X25519** key-agreement primitive (`x25519_public_key`/
  `x25519_shared_secret`, caller-supplied 32-byte secret scalar, no in-core RNG;
  rejects non-contributory/all-zero shared secrets; raw DH output must go through
  a KDF; RFC 7748 §6.1/§5.2 KATs; the classical KEX half of the future
  X25519&ML-KEM-768 hybrid), and a post-quantum **ML-KEM-768** (FIPS 203) KEM
  primitive (`ml_kem768_keygen`/`ml_kem768_encapsulate`/`ml_kem768_decapsulate`,
  deterministic over a caller-supplied 64-byte `d‖z` keygen seed + 32-byte `m`
  encaps coin, no in-core RNG; decapsulation is total/implicit-rejection; raw
  32-byte shared secret must go through a KDF; RustCrypto `ml-kem`,
  `default-features = false`, wasm-pure/getrandom-free; the PQ KEM half of the
  X25519&ML-KEM-768 hybrid). **Both KEM halves are now COMBINED into a hybrid KEM
  (`hybrid_encapsulate`/`hybrid_decapsulate`, `hybrid.rs`): `ss_combined =
  HKDF-SHA256(ss_x ‖ ss_kem ‖ SHA256(eph_pub ‖ ct), "sigil-hybrid-v1")` —
  caller-supplied ephemeral entropy, transcript-bound, reusing kx/mlkem/hkdf (no
  new deps); designed secure if EITHER half holds. Still STANDALONE + UNAUDITED
  (not wired into any key exchange / session / vault flow); the SYSTEM is not
  "post-quantum secure".** A post-quantum **ML-DSA-65** (FIPS 204) signature
  primitive (`ml_dsa65_keygen`/`ml_dsa65_sign`/`ml_dsa65_verify`, `mldsa.rs`,
  deterministic over a caller-supplied 32-byte keygen seed `xi`; signing fixes the
  FIPS 204 randomizer to zero, so it draws no in-core entropy either; FIPS 204 sizes
  pk=1952/sk=4032/sig=3309; RustCrypto `ml-dsa` 0.1.1, `default-features = false`,
  wasm-pure/getrandom-free — this crate is edition-2024 and raised the core crate's
  MSRV `rust-version` 1.74→1.85, still below the machine's rustc 1.96; the PQ
  signature half of the Ed25519&ML-DSA-65 hybrid). **Both signature halves are now
  ASSEMBLED into a hybrid signature (`hybrid_sign`/`hybrid_verify`, `hybrid_sig.rs`):
  `ed25519_sig(64) ‖ ml_dsa65_sig(3309)` = 3373 bytes — a plain concatenation (no KDF,
  a signature already commits to the message) whose verify requires BOTH halves to
  validate, so a forgery needs breaking BOTH schemes; two caller-supplied seeds,
  deterministic, reuses sig/mldsa (no new deps). This COMPLETES the hybrid crypto
  suite alongside the hybrid KEM. Still STANDALONE + UNAUDITED — NOT wired into any
  flow (the sigild op-log auth still uses the classical Ed25519 signature only); the
  SYSTEM is not "post-quantum secure".** **The hybrid KEM is now WIRED into an
  encryption flow — hybrid public-key authenticated encryption
  (`hybrid_seal`/`hybrid_open`, `hybrid_seal.rs`): `hybrid_seal` encapsulates to a
  recipient's hybrid public key (`hybrid_encapsulate` → 32-byte combined key) then
  `seal`s the record under it (KEM-then-AEAD), returning `(eph_pub, mlkem_ct,
  envelope)`; `hybrid_open` decapsulates with the recipient's hybrid secret and
  `open`s. Caller-supplied ephemeral X25519 secret + ML-KEM coin + AEAD nonce
  (ADR 0007), composes hybrid.rs + aead.rs + envelope.rs (no new deps). A CUSTOM
  composition — NOT RFC 9180 HPKE — and the FIRST wiring of a hybrid primitive into
  an encryption flow; still real but UNAUDITED and STANDALONE (not the product's
  account / key-management / vault-storage model, not used by sigild/CLI). ADR 0013.**
  `ffi` = C-ABI `seal`/`open`/`buffer_free` + suite smoke export **plus the classical
  Ed25519 sig exports `sigil_public_key_from_seed`/`sigil_sign`/`sigil_verify`**
  (`SIGIL_ERR_VERIFY` = -4), hand-written `sigil.h`).
- `sigild/` — Go sync server skeleton (`/healthz`, `/readyz`, `/version`,
  request-ID/access-log/recover middleware, in-memory `store`; distroless
  `Dockerfile`). `POST|GET /v1/vaults/{id}/ops` defaults to **`501`**; an
  opaque, **dev-gated** op-log (the `VaultLog` interface) is wired in only when
  `SIGILD_ENABLE_DEV_OPS` is truthy (**dev only, unauthenticated**; default OFF →
  ops stay `501`). Two dev backends, same `VaultLog` interface: the default
  **in-memory** `MemVaultLog` (non-durable, lost on restart), or — when
  **`SIGILD_OPLOG_DIR`** is set — a **file-backed** `FileVaultLog`
  (length-prefixed + `fsync`'d per-vault append-only files, durable across
  restart; the untrusted `vaultID` is `base64.RawURLEncoding`-encoded to a flat,
  path-traversal-safe filename). The file backend is a **local-dev convenience,
  NOT the production store** (production = Postgres/S3). When
  **`SIGILD_OPLOG_PUBKEY`** (std-base64 of a 32-byte Ed25519 public key) is set,
  op-log requests are **Ed25519-authenticated — contract v2** (`authorizeOps`, Go
  stdlib `crypto/ed25519`): both GET and POST verify an `X-Sigil-Signature` over a
  canonical `(method,path,query,timestamp,nonce,body)` message that now includes a
  fresh per-request **`X-Sigil-Nonce`** (300 s window), else **401**
  `{"error":"unauthorized",…}`. A **time-bounded, in-memory seen-nonce cache**
  (`nonceCache`; concurrency-safe, evicts entries past the window + a hard size cap)
  rejects a **replayed** request inside the window with a distinct **401**
  `"replayed request"`. **v2 supersedes v1** (nonce added to the signed message +
  domain prefix `…-v1`→`…-v2`; v1-signed requests no longer verify). **Default off**
  (no pubkey → unauthenticated, behavior unchanged); a **SINGLE static dev key** and
  the replay cache is **per-process/in-memory** (multi-instance needs a shared store,
  e.g. Redis), dev-only — enrollment / multi-device / JWT remain future. **No crypto
  on the blob**: the server never decodes it; it
  stores/returns the exact client bytes. Endpoint reference in
  [`docs/api.md`](docs/api.md).
- `web/apps/marketing/` — Next.js 15 stealth splash + waitlist. No-index, wallable.
- `docs/` — architecture map, threat model, crypto spec, op-log API reference,
  sprint plan, deployment runbook (internal/pre-audit), plus `docs/decisions/` —
  Architecture Decision Records (Nygard-style ADRs for load-bearing choices).
- `deploy/` — Terraform / Nomad / Caddy / systemd skeletons, **plus `local/`** (a
  loopback-only `docker compose` Caddy→sigild topology smoke — no real TLS; brought
  up + torn down, **not a deployment**) **and `preflight.sh`** (a read-only GO/NO-GO
  deploy gate: DNS resolves / `EnvironmentFile` present / image ≠ PLACEHOLDER /
  Docker present). **Nothing applied or exposed**: the offline IaC validators
  (`caddy validate`, `terraform fmt -check`+`validate`, `nomad job validate`) pass;
  `systemd-analyze` is macOS-N/A so the systemd unit stays by-eye. The manual,
  human-gated container publish lives in `.github/workflows/publish-sigild.yml`
  (`workflow_dispatch`-**only**; **private** GHCR `ghcr.io/<owner>/sigild`,
  SHA-tagged) — see [ADR 0009](docs/decisions/0009-manual-gated-deploy-and-publish.md).
- `cli/` — `sigil`, a pre-audit demo CLI that seals/opens a file via the libsigil
  core, plus `push`/`pull` that sync the opaque container to/from sigild's
  **dev/localhost** op-log over **plain HTTP** (`SIGIL_SERVER`/`--server`;
  dev-only). `sigil keygen --out <file>` writes a 0600 device-key JSON
  (`{version,seed,public_key}`, std-base64) and prints the pubkey for
  `SIGILD_OPLOG_PUBKEY`; `push`/`pull` then **sign** the request with `--key
  <file>` (or **`SIGIL_DEVICE_KEY`**) via `sigil_core::sign` (no key → unsigned,
  as before). `pull` is **incremental**: a per-`(server,vault)` monotonic cursor is
  persisted in `<out-dir>/.sigil-pull-state.json`, so repeat pulls fetch only new
  ops (multi-vault independent); `--since` overrides the cursor for a one-off.
  **Standalone crate** (own `cli/Cargo.lock`, NOT a libsigil workspace member) so
  it can use `getrandom` (+ `ureq`/`serde`/`base64`) without polluting the
  wasm-pure core.
- `extension/`, `web/apps/{webapp,admin}`, `web/packages/*` — reserved.

## Toolchains (this machine — macOS arm64)

- **Go** 1.26.3 at `/opt/homebrew/bin/go` (go.mod directive: 1.24).
- **Rust** stable (rustc 1.96) via Homebrew `rustup`. ⚠️ The `~/.cargo/bin`
  proxies were **not** created, and `rustup run stable cargo` did not resolve
  subcommands. The reliable invocation is to put the toolchain bin on PATH:
  `export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/opt/homebrew/bin:$PATH"`
- **Node** 20.12 + **pnpm** 9.15 via Corepack (`corepack pnpm …`). CI uses Node 22.
- System `openssl` is **LibreSSL** — it CANNOT negotiate `X25519MLKEM768`. Any
  PQ-TLS verification needs OpenSSL 3.5+ / Go 1.24.x installed explicitly first.

## Build & test (these commands are known-green)

```bash
# Rust core — fmt / clippy / test / wasm
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/opt/homebrew/bin:$PATH"
M=libsigil/Cargo.toml
cargo fmt --manifest-path $M --all -- --check
cargo clippy --manifest-path $M --all-targets -- -D warnings
cargo test --manifest-path $M
cargo build --manifest-path $M -p sigil-core --target wasm32-unknown-unknown

# Rust demo CLI — separate crate; native-only, so getrandom is fine here. After
# building it, confirm it did NOT leak into the wasm-pure core:
cargo fmt   --manifest-path cli/Cargo.toml --all -- --check
cargo clippy --manifest-path cli/Cargo.toml --all-targets -- -D warnings
cargo test  --manifest-path cli/Cargo.toml
grep -c 'name = "getrandom"' libsigil/Cargo.lock   # must STILL be 0

# Go server — fmt / vet / test / build
go=/opt/homebrew/bin/go
gofmt -l sigild            # must print nothing
$go -C sigild vet ./...
$go -C sigild test ./...
$go -C sigild build ./...

# sigild container (multi-stage → distroless, ~14 MB) — needs the Docker daemon
docker build --build-arg VERSION=$(git rev-parse --short HEAD) -t sigild:dev sigild

# Web — typecheck / lint / build (NEXT_TELEMETRY_DISABLED=1)
corepack pnpm -C web typecheck
corepack pnpm -C web lint
corepack pnpm -C web build
```

**Always run the relevant suite after changes and record the result in
`journal.md`.** CI mirrors these in `.github/workflows/` — **except**
`publish-sigild.yml`, which is deliberately **not** a mirror: it is
`workflow_dispatch`-only (no `push`/`pull_request` trigger) so nothing builds or
publishes automatically while in stealth.

## Conventions & guardrails

- **License split:** clients/core/web/CLI = Apache-2.0; `sigild/` = BSL-1.1.
- **No over-claims:** public copy must obey
  [`web/apps/marketing/MARKETING-CLAIMS.md`](web/apps/marketing/MARKETING-CLAIMS.md)
  — never "audited", "SOC 2", "post-quantum secure", or unqualified "E2E
  encrypted" until true.
- **No secrets in the repo.** Secrets live in the team password manager;
  `.gitleaks.toml` scans, and `docs/sprint-72h.md` has the rotation runbook.
- **Don't fake crypto/auth.** Stub with `501` / clear "not implemented" rather
  than implement something that would poison the future audit.
- Rust: `#![forbid(unsafe_code)]` in `core`; clippy `-D warnings` is the bar.
- **Record load-bearing decisions as ADRs** under
  [`docs/decisions/`](docs/decisions/) (Nygard-style; keep them accurate to the
  current code — don't invent decisions that weren't made).
- The brand name and `sigilapp.io` are **provisional** (trademark pending).

## Git / deploy

`main` is committed and pushed to `origin` (genesis → Phase 13); the human has
authorized commits + pushes to `main`. **Still do not register domains, publish the
container image, `terraform apply` / `nomad job run`, or deploy publicly without
explicit human approval** — those are outward-facing/irreversible. Deploy readiness
is verified **locally only** (offline IaC validators + a loopback compose smoke,
then torn down); **nothing is published / applied / exposed** and there is **no
domain**. Publish is a manual `workflow_dispatch` and all infra is human-gated (see
[ADR 0009](docs/decisions/0009-manual-gated-deploy-and-publish.md)); the
(not-yet-applied) deploy story is in [`docs/deployment.md`](docs/deployment.md).
