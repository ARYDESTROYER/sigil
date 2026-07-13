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
>
> **Personal working memory:** also keep a **local, uncommitted** `memory.md` at
> the repo root — a granular scratchpad of current state, hard invariants,
> gotchas, the phase ledger (commit hashes), and what's next. It is excluded via
> `.git/info/exclude` and **must never be committed** (it is not part of the
> repo). Read it at session start — it survives context compaction — and keep it
> current as you work; create it if absent. `journal.md` stays the committed
> source of truth; `memory.md` is just the fast personal cache.

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
  `ffi` = C-ABI `seal`/`open`/`buffer_free` + suite smoke export, **plus the classical
  Ed25519 sig exports `sigil_public_key_from_seed`/`sigil_sign`/`sigil_verify`**
  (`SIGIL_ERR_VERIFY` = -4), **plus the hybrid encryption path
  (`sigil_x25519_public_key`, `sigil_ml_kem768_keygen`,
  `sigil_hybrid_encapsulate`/`sigil_hybrid_decapsulate`/`sigil_hybrid_seal`/`sigil_hybrid_open`)**
  — derive a hybrid identity + encapsulate/decapsulate + encrypt a record TO a
  recipient's hybrid pubkey (the custom KEM-then-AEAD `hybrid_seal`/`hybrid_open`
  flow over the C-ABI, NOT RFC 9180 HPKE), with `SIGIL_ERR_HYBRID` = -5 and
  fixed-size length `#define`s; C-ABI round-trips proven, UNAUDITED, not wired into
  any product flow — hand-written `sigil.h`).
- `sigild/` — Go sync server skeleton (`/healthz`, `/readyz`, `/version`,
  request-ID/access-log/recover middleware, in-memory `store`; distroless
  `Dockerfile`). `POST|GET /v1/vaults/{id}/ops` defaults to **`501`**; an
  opaque, **dev-gated** op-log (the `VaultLog` interface) is wired in only when
  `SIGILD_ENABLE_DEV_OPS` is truthy (**dev only, unauthenticated**; default OFF →
  ops stay `501`). **Three backends**, same `VaultLog` interface, selected by
  precedence **`SIGILD_OPLOG_POSTGRES` > `SIGILD_OPLOG_DIR` > in-memory**: the
  default **in-memory** `MemVaultLog` (non-durable, lost on restart); when
  **`SIGILD_OPLOG_DIR`** is set, a **file-backed** `FileVaultLog`
  (length-prefixed + `fsync`'d per-vault append-only files, durable across
  restart; the untrusted `vaultID` is `base64.RawURLEncoding`-encoded to a flat,
  path-traversal-safe filename); or, when **`SIGILD_OPLOG_POSTGRES`** (a pgx DSN)
  is set, a **durable, concurrent Postgres** `PostgresVaultLog` (pgx/v5 `pgxpool`,
  schema `sigil_vault_ops`, opaque `bytea` blobs, per-vault `seq` assigned inside a
  tx under `pg_advisory_xact_lock` so concurrent same-vault appends stay gap-free;
  integration tests gated on `SIGILD_TEST_POSTGRES`, else skipped). The file backend
  is a **local-dev convenience** and the Postgres backend is the **first durable
  store adapter but still NOT a finished production store** (no auth / enrollment,
  per-vault authorization, CRDT / merge, or production backup/replication/PITR — though
  schema migrations are now managed and a `pg_dump`/restore runbook exists, see below). When
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
  stores/returns the exact client bytes. **Hardened for reliability + auditability
  (Phase 25, ADR 0015):** the `VaultLog` seam is **request-context-aware** — `Append`/
  `Since` take a `context.Context` threaded from `r.Context()` (bodies read under it),
  so a client disconnect / timeout cancels in-flight storage work instead of pinning a
  pooled Postgres connection (Mem/File honor cancellation cheaply; Postgres passes ctx to
  `pgx`). `/readyz` now performs a **real health check of the live backend** — when
  Postgres is configured it pings the `pgxpool` (`store.Pinger`, bounded by a 2 s
  `readyzPingTimeout`) and returns **503** if the DB is down (Mem/File report healthy).
  `http.Server` read/write/idle timeouts + `pgxpool` limits bound the work. A
  **structured audit log** (`internal/api/audit.go`, `slog`) emits `oplog.append`
  (`event/request_id/vault_id/seq/size_bytes/blob_sha256/auth`), `oplog.list`
  (…`/since/returned_count`), and `oplog.auth_denied` (…`/reason`, a fixed enum) — where
  `blob_sha256` is a hex **SHA-256 fingerprint** of the opaque stored bytes; the server
  **NEVER logs the blob content or any signature/nonce/timestamp/key** (zero-knowledge
  boundary intact, proven by a no-blob-in-logs test). **Tamper-evident via a per-op
  SHA-256 hash chain (Phase 26, ADR 0016):** one canonical `chainHash`
  (`store/oplogchain.go`) shared by all three backends commits each op to the previous —
  `hash(seq) = SHA-256("sigil-oplog-chain-v1" ‖ uint32_be(len(vaultID)) ‖ vaultID ‖
  uint64_be(seq) ‖ prev_hash[32] ‖ blob)`, genesis `prev_hash` = 32 zero bytes — so
  altering / inserting / deleting / reordering any op changes that op's hash and every
  hash after it. `Op` carries `Hash`; **File's on-disk format is bumped v1→v2** to persist
  the hash, **Postgres gains a hash column** (assigned inside the same advisory-lock tx as
  `seq`), Mem holds it in-process. `GET …/ops` returns each op's hex `hash`; a new
  **`GET /v1/vaults/{vaultID}/ops/verify`** recomputes the chain server-side and returns
  `{vaultID, ok, count, tip_hash, broken_at_seq}` (`VerifyChain`) — both **dev-gated**
  (`501` when dev-ops off) and **auth-guarded** exactly like the other ops routes. The
  chain fingerprints the OPAQUE ciphertext (no key, no plaintext → **zero-knowledge
  intact**) and is tamper-**EVIDENT, NOT tamper-proof**: a hostile server can still lie
  about `/ops/verify`, so the real guarantee is **client-side** (re-derive the chain from
  the returned per-op hashes); this stays a **dev op-log**, not a Byzantine /
  append-only-enforced / notarized log. **Scaled + observable (Phase 27, ADR 0017 — four
  pure-stdlib features, NO new dep):** (1) **paginated reads** — `GET …/ops` takes `?limit`
  (default **500**, clamped `[1,1000]`; non-integer → **`400 bad_limit`**) and returns
  **`has_more`** beside `next`; the cap is a `VaultLog.Since(ctx,vaultID,since,limit)`
  signature change pushed into every backend (Postgres applies it as a SQL `LIMIT`), so a
  client drains a vault by looping `since=next` until `has_more=false`; (2) **per-vault
  rate limiting** — when **`SIGILD_OPLOG_RATE_LIMIT`** (sustained appends/sec/vault; +
  optional **`SIGILD_OPLOG_RATE_BURST`** bucket depth) is set, each vault ID gets an
  independent stdlib token-bucket (`internal/api/ratelimit.go`, `sync.Mutex`+map+`time`,
  bounded via `rateLimiterMaxVaults`+idle eviction) and an over-rate append → **`429
  rate_limited`** + `Retry-After`; **off by default** (unset ⇒ no throttle), GET is never
  limited, and it **never inspects the blob**; (3) **`GET /metrics`** — an **always-on**
  (NOT dev-gated), unauthenticated Prometheus-text endpoint (`internal/api/metrics.go`,
  hand-written, no client lib) exposing **per-router** (atomic, test-isolatable) counters
  only — `sigild_oplog_appends_total`/`_verify_total`/`_ratelimit_rejected_total`/
  `_auth_denied_total{reason}`, `sigild_http_requests_total{class}`,
  `sigild_build_info{version}` — **never** a blob / key / signature / nonce / vault ID;
  (4) **fail-fast config validation** — `cmd/server` parses+validates `SIGILD_ADDR` /
  `SIGILD_OPLOG_RATE_LIMIT` / `SIGILD_OPLOG_RATE_BURST` / `SIGILD_OPLOG_PUBKEY` **before
  binding** and exits non-zero on any malformed value. These are **dev-scale operability
  primitives** (in-process limiter, process-local counters, boot-time validation), NOT
  production SLOs; posture unchanged (still dev-gated/`501` by default, opaque, no crypto
  on the blob). Endpoint reference in [`docs/api.md`](docs/api.md). **Managed op-log schema
  migrations (Phase 28, ADR 0018) — Postgres backend only:** the Postgres backend now
  manages its schema with **versioned, embedded migrations** (`go:embed`'d
  `internal/store/migrations/NNNN_*.sql`, baseline `0001_init.sql` = version 1) tracked in a
  **`schema_migrations`** table, replacing the old inline `CREATE TABLE IF NOT EXISTS` DDL.
  The run is serialized across instances by a **session-level `pg_advisory_lock`** (key
  `0x5347494C5F4D4752`) with each migration in its own tx, so concurrent boots can't
  double-apply. Migrations are **auto-applied at boot by default**; **`SIGILD_OPLOG_AUTO_MIGRATE=0`**
  (`0`/`false`/`no`/`off`) disables that (boot then fails fast until migrations are applied).
  Operator CLI (**not** an HTTP endpoint): **`sigild migrate`** applies pending, **`sigild
  migrate status`** reports applied/pending. The applied version is exported as the
  **`sigild_schema_version`** gauge on `GET /metrics` (0 for mem/file). Migrations are **pure
  DDL** over the opaque `bytea` `blob`+`hash` columns — no crypto, zero-knowledge intact.
  **Backup/restore:** a logical **`pg_dump`/`pg_restore`** (or `psql`) dumps `blob` AND
  `hash` byte-for-byte, so the tamper-evidence hash chain survives a restore; the post-restore
  integrity gate is **`GET /v1/vaults/{id}/ops/verify`** per vault (expect `ok:true` + the
  same `tip_hash`) — the verifier proved a dump→drop→restore preserved the `tip_hash`. Still a
  **dev** backend (no PITR/replication/object-store, no production change-management). Runbook
  in [`docs/deployment.md`](docs/deployment.md) §11–§12.
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
  Also **`hybrid-keygen`/`hybrid-seal`/`hybrid-open`** — **public-key** (no-password)
  encryption: `hybrid-keygen --out <file>` writes a 0600 secret hybrid identity
  (`{x25519_secret, mlkem_seed}`) + shareable `<file>.pub` (`{x25519_public_key,
  mlkem_encaps_key}`); `hybrid-seal --recipient-pub <pub>` encrypts a file TO that
  device's hybrid identity (X25519 + ML-KEM-768) into a `SIGILhyb` container, and
  `hybrid-open --key <secret>` decrypts it — via the core's `hybrid_seal`/`hybrid_open`
  (dev/UNAUDITED; custom KEM-then-AEAD, NOT RFC 9180 HPKE; the FIRST user-facing use
  of the hybrid encryption path — a demo, NOT the product key-management model).
  **Standalone crate** (own `cli/Cargo.lock`, NOT a libsigil workspace member) so
  it can use `getrandom` (+ `ureq`/`serde`/`base64`) without polluting the
  wasm-pure core.
- `extension/`, `web/apps/{webapp,admin}`, `web/packages/*` — reserved.

## Toolchains (this machine — macOS arm64)

- **Go** 1.26.3 at `/opt/homebrew/bin/go` (go.mod directive: **1.25.0** — raised for
  the opt-in Postgres backend's `pgx`, which requires Go ≥ 1.25).
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
- **`sigild` dependencies:** stdlib-only **except** the opt-in Postgres op-log
  backend, which links `pgx` (the module has a `go.sum`; ADR 0014 relaxes ADR 0005).
  The core server + the in-memory / file-backed backends stay stdlib; `pgx` is
  dormant unless `SIGILD_OPLOG_POSTGRES` is set. Keep new deps out of everything else.
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
