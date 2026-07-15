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
  Ed25519&ML-DSA-65 hybrid, whose post-quantum ML-DSA-65 half now **also exists**
  (below), and the primitive is not yet wired into any auth flow), and a
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
  session / account / vault flow**), and a real (unaudited) **post-quantum
  ML-DSA-65** (FIPS 204) signature primitive
  (`ml_dsa65_keygen`/`ml_dsa65_sign`/`ml_dsa65_verify`, deterministic over a
  caller-supplied 32-byte keygen seed `xi` — signing fixes the FIPS 204 randomizer
  to zero, so it too draws no in-core randomness; FIPS 204 sizes
  pk=1952/sk=4032/sig=3309; RustCrypto `ml-dsa`, `default-features = false`,
  wasm-pure/getrandom-free — the **post-quantum signature half** of the planned
  Ed25519&ML-DSA-65 hybrid), and — **now assembled** — a real (unaudited)
  **hybrid signature** that composes the two
  (`hybrid_sign`/`hybrid_verify`) into `ed25519_sig(64) ‖ ml_dsa65_sig(3309)` =
  3373 bytes — a plain concatenation (no KDF: a signature already commits to the
  message) whose verify requires **both** halves to validate, so forging a
  signature is designed to require breaking **both** Ed25519 and ML-DSA-65;
  two caller-supplied seeds, deterministic (RNG-free), reuses the sig/mldsa
  primitives with no new deps. **With this, both planned hybrid constructions —
  the hybrid KEM (X25519&ML-KEM-768) and the hybrid signature (Ed25519&ML-DSA-65)
  — now exist as primitives, but both are UNAUDITED and standalone, NOT wired into
  any key-exchange / session / account / vault / auth flow; the system is NOT
  "post-quantum secure"**, and — **now composed into an encryption flow** — a real
  (unaudited) **hybrid public-key authenticated encryption** layer
  (`hybrid_seal`/`hybrid_open`) that encapsulates to a recipient's **hybrid public
  key** with the hybrid KEM and then AEAD-`seal`s the record under the derived key
  (**KEM-then-AEAD**), returning `(eph_pub, mlkem_ct, envelope)` — caller-supplied
  ephemeral X25519 secret + ML-KEM coin + AEAD nonce (no in-core randomness),
  composing the hybrid KEM + AEAD + envelope codec with no new deps. **This is a
  CUSTOM composition — NOT RFC 9180 HPKE — and the FIRST wiring of a hybrid primitive
  into an encryption flow, but it is UNAUDITED and STANDALONE: a crypto-level flow
  only, NOT the product's account / key-management / vault-storage model, and not
  used by sigild or the CLI**, plus a
  `sigil-ffi` C-ABI for the clients — `seal`/`open`/`buffer_free`, the classical
  Ed25519 sig exports `sigil_public_key_from_seed`/`sigil_sign`/`sigil_verify`
  (with a `SIGIL_ERR_VERIFY` code), and — **now assembled** — the **hybrid
  encryption path**: `sigil_x25519_public_key` + `sigil_ml_kem768_keygen` derive a
  hybrid identity's public halves, `sigil_hybrid_encapsulate`/`sigil_hybrid_decapsulate`
  are the two sides of the hybrid KEM, and `sigil_hybrid_seal`/`sigil_hybrid_open`
  encrypt a record **to** a recipient's hybrid public key and decrypt it — the
  custom KEM-then-AEAD `hybrid_seal`/`hybrid_open` flow above exposed over the C-ABI
  (a `SIGIL_ERR_HYBRID` status code plus fixed-size length `#define`s, both C-ABI
  round-trips proven). **These FFI exports are real but UNAUDITED building blocks —
  a CUSTOM KEM-then-AEAD construction, NOT RFC 9180 HPKE, and NOT wired into any
  product flow; the system is NOT "post-quantum secure".** libsigil-core now also
  has the **first primitive that implements an actual product feature** rather than
  a building block: a real (unaudited) **HOTP/TOTP** one-time-password primitive
  (`hotp`/`totp`/`format_code`, SHA-1/256/512) — **RFC 4226 / RFC 6238**, verified
  against the official RFC known-answer vectors. `totp` takes the current Unix time
  as a caller-supplied argument, so the core still reads no clock and no randomness
  (staying wasm-pure/`getrandom`-free); the two new deps (`hmac`, `sha1`) are both
  `default-features = false`. It only generates codes (verification is left to
  callers) and is UNAUDITED. This is what the `sigil totp` vault (below) is built on.
- `sigild/` — Go sync server. **Builds, vets, tests** (incl. real-socket
  `httptest` HTTP integration tests, race-clean). Serves `/healthz`, `/readyz`,
  `/version`, and a deliberate `501` on `/v1/vaults/{id}/ops` by default. Behind a
  dev flag (`SIGILD_ENABLE_DEV_OPS`, default off) the ops route becomes an op-log
  that stores **opaque client-encrypted blobs** and hands them back unchanged, via
  one of **three `VaultLog` backends** (precedence `SIGILD_OPLOG_POSTGRES` >
  `SIGILD_OPLOG_DIR` > in-memory): by default **in-memory** (non-durable); when
  `SIGILD_OPLOG_DIR` is set, a **file-backed durable** backend
  (path-traversal-safe filenames); or, when `SIGILD_OPLOG_POSTGRES` (a `pgx` DSN)
  is set, a **durable, concurrent PostgreSQL** backend (opaque `bytea` blobs,
  concurrency-safe per-vault sequencing) — the first real store adapter, and the
  reason `sigild` now has **its first third-party dependency (`pgx`)** and a
  `go.sum`; the core server + the in-memory / file backends stay stdlib-only. All
  three are **dev-only, NOT a finished production store** (no auth / enrollment,
  per-vault authorization, or CRDT / merge; the Postgres backend now has managed
  migrations and a chain-verified backup runbook (below), but no PITR / replication).
  Op-log requests
  are **unauthenticated by default**, but
  when `SIGILD_OPLOG_PUBKEY` (std-base64 of a 32-byte Ed25519 public key) is set
  the server **verifies an Ed25519 signature (contract v2)** (Go stdlib
  `crypto/ed25519`) over a canonical `(method,path,query,timestamp,nonce,body)`
  message — with a fresh per-request `X-Sigil-Nonce` and a **time-bounded, in-memory
  replay cache** that rejects a replayed request within the 300 s window (`401`
  "replayed request") — on every op-log request (else `401`). A **single static dev
  key**; the replay cache is **per-process/in-memory** (multi-instance needs a shared
  store); **dev-only** (enrollment / multi-device / JWT are future). Performs no
  crypto on the blob —
  never decodes it. The dev op-log is **hardened for reliability and auditability**:
  the `VaultLog` seam is **request-context-aware**, so a client disconnect or timeout
  cancels in-flight storage work (instead of pinning a pooled Postgres connection);
  `/readyz` performs a **real health check of the live backend** (it pings the Postgres
  pool and returns `503` if the database is down, so a load balancer drains the node);
  `http.Server` timeouts and `pgxpool` limits bound the work; and a **structured audit
  log** records each append / list / auth-denial as metadata plus a **SHA-256
  fingerprint** of the opaque blob — **never the blob content, and never any key,
  signature, nonce, or timestamp** (the zero-knowledge boundary is preserved, proven by
  a no-blob-in-logs test). The op-log is also **tamper-evident**: every backend maintains
  a **per-op SHA-256 hash chain** (each op's hash commits to the previous op's hash, over
  the opaque ciphertext), so modifying, inserting, deleting, or reordering any stored op
  changes that op's hash and every hash after it. `GET …/ops` returns each op's hash and a
  new `GET …/ops/verify` recomputes the chain and reports
  `{ok, count, tip_hash, broken_at_seq}` for **integrity auditing** — both dev-gated and
  auth-guarded exactly like the other ops routes. Hashing the **already-encrypted** blob
  fingerprints ciphertext only (no key, no plaintext), so zero-knowledge is preserved.
  This is **tamper-evident, not tamper-proof**: a hostile server can still lie about
  `/ops/verify`, so the real guarantee is **client-side** — a client re-derives the chain
  from the returned per-op hashes. The dev op-log is also **bounded, rate-limited, and
  observable** (all Go-stdlib, no new dependency): `GET …/ops` is **paginated** — an
  optional **`?limit`** (default 500, max 1000; a non-integer value → `400 bad_limit`)
  returns a **`has_more`** flag beside `next`, and the limit is applied in every backend
  (the Postgres backend as a SQL `LIMIT`), so a client drains a vault by looping
  `since = next` until `has_more` is false; when **`SIGILD_OPLOG_RATE_LIMIT`** (with an
  optional **`SIGILD_OPLOG_RATE_BURST`**) is set, each **vault** gets an independent
  **token-bucket rate limit** and an append over its rate gets **`429 rate_limited`** +
  `Retry-After` (**off by default**, GET is never limited, and the limiter never inspects
  the blob); an **always-available**, unauthenticated **`GET /metrics`** renders a
  **Prometheus-text** exposition of process counters (HTTP requests, appends, verifies,
  auth denials by reason, rate-limit rejections, and the build version) — **counters and
  the build version only, never a blob, key, signature, nonce, vault content, or vault
  ID**, so it cannot leak plaintext or weaken zero-knowledge; and on startup `sigild`
  **validates its configuration and refuses to boot** on a malformed value (bad
  `SIGILD_ADDR`, a non-numeric rate/burst, or an invalid `SIGILD_OPLOG_PUBKEY`) rather
  than starting misconfigured. These are **dev-scale operability primitives** (an
  in-process limiter, process-local counters, boot-time validation) — **not** production
  SLOs, a distributed quota, or a durable metrics pipeline; the security posture is
  unchanged (still dev-gated and `501` by default, still opaque blobs only). The
  **Postgres backend** now manages its schema with **versioned, embedded migrations**
  (a `schema_migrations` table; applied under a session-level `pg_advisory_lock` so
  concurrent boots are safe) — auto-applied at boot by default, or run/inspected with the
  **`sigild migrate` / `sigild migrate status`** operator CLI, and disabled with
  `SIGILD_OPLOG_AUTO_MIGRATE=0`; the applied version is exported as the
  `sigild_schema_version` gauge. **Backup/restore** is a plain `pg_dump`/`pg_restore`
  whose integrity is provable via the existing hash chain — because the `blob` and `hash`
  columns dump byte-for-byte, `GET …/ops/verify` re-proves the same `tip_hash` after a
  restore (dev backend only; no PITR/replication yet). Ships a distroless `Dockerfile`.
- `cli/` — `sigil`, a **pre-audit demo CLI** that seals/opens one file via the
  libsigil core (`sigil seal`/`sigil open`), plus `sigil push`/`sigil pull` — a
  two-device **opaque sync demo** that ships the sealed container to/from
  sigild's op-log over plain HTTP (**dev / localhost only**; the server never
  decrypts). `sigil keygen` writes a 0600 device-key file and prints the pubkey for
  `SIGILD_OPLOG_PUBKEY`; `push`/`pull` then **Ed25519-sign** the request with
  `--key` (or `SIGIL_DEVICE_KEY`) so a pubkey-configured server accepts them
  (no key → unsigned, as before) — **dev-only**. `pull` is **incremental** — a
  per-vault cursor is kept in the out-dir, so repeat pulls fetch only new ops.
  Also `sigil hybrid-keygen`/`hybrid-seal`/`hybrid-open` — **public-key** (no
  shared password) encryption: `hybrid-keygen` writes a 0600 secret hybrid identity
  + a shareable `.pub`, then `hybrid-seal --recipient-pub <pub>` encrypts a file
  **to** another device's hybrid identity (X25519 + ML-KEM-768) and `hybrid-open`
  decrypts it, via the core's `hybrid_seal`/`hybrid_open` — the **first user-facing
  use of the hybrid encryption path** (a demo; a **custom KEM-then-AEAD**
  construction, **NOT RFC 9180 HPKE**; not the product's key-management model).
  Also `sigil totp add`/`list`/`code`/`remove` — the **first authenticator
  feature**: generate **2FA (TOTP) codes** from secrets stored in an **encrypted
  vault**. Add a secret by base32 (`--secret`) or by pasting an `otpauth://` URI
  (`--uri`), then `sigil totp code <label>` prints the current code. The codes come
  from the core's RFC 4226/6238 primitive, and the secrets are sealed at rest in the
  **same `SIGILcli` password container** as `seal`/`open` (Argon2id +
  XChaCha20-Poly1305), so a vault is just another opaque, syncable sealed container.
  `sigil totp import`/`export` **migrate 2FA in and out** so you are not locked in:
  `import` ingests a **Google Authenticator** bulk-export migration URI
  (`otpauth-migration://offline?data=…`, decoded by a hand-rolled dependency-free
  protobuf codec), a single `otpauth://` URI, or a file of URIs; `export` is the
  inverse — it prints each entry as an `otpauth://` URI, or (with `--migration`) one
  combined `otpauth-migration://` URI. **`export` prints your secrets IN THE CLEAR**
  (that is what a 2FA export is) — by design, guarded by a loud warning. Standalone
  crate; **UNAUDITED** — the OTP math is RFC-vector-checked but the build is not
  audited; **do not store real 2FA secrets yet**. Public copy obeys
  `web/apps/marketing/MARKETING-CLAIMS.md`.
- `sigil-wasm/` — a thin **`wasm-bindgen`** binding over the libsigil core's
  record API that runs **`seal_record` / `open_record` in the browser (and Node)**
  — the first thing to actually consume the wasm-pure core in a JS runtime. It
  adds **no crypto of its own** (all crypto stays in `sigil-core`) and carries the
  core's caller-supplied-entropy design all the way into JavaScript: the Argon2id
  salt and the AEAD nonce are generated in JS with `crypto.getRandomValues` and
  passed in, so it stays **`getrandom`-free**, exactly like the core. Build with
  `./sigil-wasm/build-wasm.sh` (uses `wasm-pack` to emit gitignored `pkg-web/` +
  `pkg-node/`); prove it with `node sigil-wasm/test/roundtrip.mjs` or serve
  `sigil-wasm/demo/` for an in-browser seal/open page. It also **shares a container
  format with the `sigil` CLI** (`seal_to_container` / `open_container` read and
  write the same `SIGILcli` container), so you can **seal in the browser and open
  with `sigil open`** — and vice-versa; a `node sigil-wasm/test/interop.mjs` proof
  shells to the real CLI binary in both directions. It can also do **password-less
  HYBRID public-key encryption in the browser** — `hybrid_seal_to_container` /
  `hybrid_open_container` encrypt a file **to** a device's hybrid identity (X25519
  + ML-KEM-768) into the same `SIGILhyb` container the CLI uses, interoperable with
  `sigil hybrid-seal` / `sigil hybrid-open` both ways (proven by `node
  sigil-wasm/test/hybrid-interop.mjs`). It can now also **sync opaque sealed
  containers to a dev `sigild` op-log** — `sigil-wasm/sync.mjs` (`pushContainer` /
  `pullContainers`) POSTs the raw sealed bytes and pulls them back (paginated) over
  `fetch`, doing **no crypto itself** (the wasm seals before push), so the browser
  interoperates with `sigil push` / `sigil pull` through the same vault and the
  server stays **zero-knowledge**; proven end-to-end against a **live** sigild and
  the real CLI by `node sigil-wasm/test/sync-interop.mjs` (**dev / localhost /
  plain-HTTP / no-auth**). The browser can now also **hold an encrypted TOTP vault
  and generate 2FA codes** — wasm `totp` / `hotp` / `format_code` (the JS caller
  supplies the time; the crate stays `getrandom`-free) plus a framework-free
  `sigil-wasm/totp-vault.mjs` that reads/writes the **same sealed `SIGILcli` TOTP
  vault the `sigil totp` CLI uses**, so a secret added on one client and synced
  through the opaque op-log yields the **same code on the other, cross-client**
  (proven by `node sigil-wasm/test/totp-interop.mjs`: CLI adds → op-log → browser
  code == the RFC vector). UNAUDITED, generation only — **do not store real 2FA
  secrets yet**. A **standalone crate** (own lockfile),
  **UNAUDITED**, a **demo of a building block** — a custom KEM-then-AEAD (not RFC
  9180 HPKE), not the product's account/key-management/sync model, and not for real
  secrets; the system is **not** "post-quantum secure". (Public copy still obeys
  [`web/apps/marketing/MARKETING-CLAIMS.md`](web/apps/marketing/MARKETING-CLAIMS.md).)
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
sigil-wasm/      Rust wasm-bindgen binding — in-browser seal/open demo over the core (pre-audit)
deploy/          terraform / nomad / caddy / systemd + local/ (loopback smoke) + preflight.sh
docs/            architecture, threat model, crypto spec, op-log API, sprint plan
docs/decisions/  Architecture Decision Records (ADRs)
```

Native platform clients (iOS/Android/macOS/Windows/Linux/watchOS/wearOS) live in
**separate repositories** and consume `libsigil` as a versioned binary artifact.

## Toolchains

- Rust stable (rustfmt, clippy, `wasm32-unknown-unknown` target) — pinned in
  [`rust-toolchain.toml`](rust-toolchain.toml).
- Go 1.25+ (`sigild`'s `go.mod` is `go 1.25.0`, required by the Postgres backend's
  `pgx`; the brief targets 1.24.x for the native `X25519MLKEM768` TLS group).
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

# sigil-wasm (separate crate; wasm-bindgen binding — getrandom-free, JS supplies entropy)
cargo test  --manifest-path sigil-wasm/Cargo.toml   # native *_inner unit tests
./sigil-wasm/build-wasm.sh && node sigil-wasm/test/roundtrip.mjs   # browser/Node round-trip

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
