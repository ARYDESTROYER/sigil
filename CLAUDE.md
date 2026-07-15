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
  **The core now also has the FIRST primitive that implements an actual product
  FEATURE (not a building block): an **HOTP/TOTP** one-time-password primitive
  (`hotp`/`totp`/`format_code` over an `OtpAlgorithm` enum — SHA-1 (default)/
  SHA-256/SHA-512; `OtpError` for out-of-range digits/period/time; `totp.rs`) — RFC
  4226 HOTP (dynamic truncation) + RFC 6238 TOTP, verified against the RFC 4226
  App D / RFC 6238 App B known-answer vectors. `totp` takes the current Unix time as
  a CALLER-SUPPLIED `u64` arg (the core reads NO clock and NO RNG, preserving the
  wasm-pure/no-RNG contract, ADR 0007); it only GENERATES codes (verification left
  to callers). Adds two getrandom-free deps: `hmac` (keyed MAC, already transitive
  via `hkdf`, now DIRECT) + the NEW `sha1` (HMAC-SHA-1 is the near-universal
  `otpauth://` default, so interop requires it; `sha2` already present) — both
  `default-features = false` so the `getrandom`==0 core-lockfile guard holds. Real
  but UNAUDITED. ADR 0023.**
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
  Also **`sigil totp add|list|code|remove`** — the FIRST user-facing product
  FEATURE: an **encrypted TOTP (2FA) vault**. `totp add <label> --secret <BASE32>
  [--issuer X] [--algorithm sha1|sha256|sha512] [--digits 6] [--period 30]`, or
  `totp add --uri "otpauth://totp/..."` (base32 + otpauth import); `list` (never
  prints the secret), `code <label>` (current code via the system clock), `remove
  <label>`. Codes are generated with the core's RFC 4226/6238 `totp` primitive; the
  secrets are stored in a `TotpVault` JSON **sealed at rest with the SAME `SIGILcli`
  password container as `seal`/`open`** (`SIGIL_PASSWORD`), so a vault is just
  another opaque sealed container (E2EE at rest, op-log-syncable later). Vault path
  is `--vault <file>` else `$HOME/.sigil/totp-vault.sigil` (dir 0700, file 0600).
  Dev/UNAUDITED — do NOT store real 2FA secrets yet. ADR 0023.
  Also **`sigil totp import <ARG>`/`export [<label>]`** — migrate 2FA in/out (no
  lock-in). `import` ingests a **Google Authenticator** bulk-export
  `otpauth-migration://offline?data=…` URI, a single `otpauth://` URI, or a file of
  URIs (one per line, `#` comments skipped); duplicate-label, HOTP, and invalid
  entries are skipped. `export` prints each entry as an `otpauth://` URI, or (with
  `--migration`) ONE combined `otpauth-migration://` URI, to stdout or `--out <file>`
  (0600) — **export prints SECRETS IN THE CLEAR** (by design; loud stderr warning
  first). The migration format is decoded/encoded by a **hand-rolled, dependency-free
  protobuf codec** (`cli/src/migration.rs`: `decode_migration_uri`/`encode_migration_uri`
  + the `MigrationOtp`↔`TotpEntry` converters), golden-vector (a real Google
  Authenticator export) + round-trip verified. The vault's `TotpVault` JSON schema is
  **UNCHANGED** (browser mirror intact); HOTP entries are warned-and-skipped since the
  vault is TOTP-only. Dev/UNAUDITED. ADR 0025.
  **Standalone crate** (own `cli/Cargo.lock`, NOT a libsigil workspace member) so
  it can use `getrandom` (+ `ureq`/`serde`/`base64`) without polluting the
  wasm-pure core.
- `sigil-wasm/` — a thin **`wasm-bindgen`** binding (`sigil-wasm`, Apache-2.0)
  over the libsigil-core **record API**, exposing `seal_record`/`open_record`
  (plus `nonce_len`/`recommended_salt_len`/`version`) to JavaScript. The **FIRST
  thing to actually consume the wasm-pure core** in a JS runtime (browser + Node).
  Like `cli/` it is a **standalone crate with its own `sigil-wasm/Cargo.lock`**
  (path-deps `../libsigil/core`, NOT a libsigil workspace member, so it can never
  perturb `libsigil/Cargo.lock`). **Unlike `cli/` it is deliberately
  `getrandom`-free:** the Argon2id salt + the AEAD nonce are generated in JS
  (`crypto.getRandomValues`) and passed IN as byte arrays, proving the
  caller-supplied-entropy invariant end to end — so **both** `libsigil/Cargo.lock`
  **and** `sigil-wasm/Cargo.lock` must stay `getrandom`-free. It adds **no crypto
  of its own** (all crypto stays in `#![forbid(unsafe_code)]` `sigil-core`; the
  binding cannot `forbid(unsafe_code)` because `#[wasm_bindgen]` generates
  `unsafe` glue, so the crate-type is `["cdylib","rlib"]` and the testable logic
  lives in `*_inner` helpers). Build with **`sigil-wasm/build-wasm.sh`** (wasm-pack
  0.13.1, which bundles wasm-bindgen 0.2.100 matching the `=0.2.100` pin),
  producing `pkg-web/` (browser ESM) + `pkg-node/` (Node CJS) — both **gitignored
  build artifacts, never committed**. Verified by a Node round-trip test
  (`test/roundtrip.mjs`) + native unit tests + a browser `demo/`. **INTEROPERABLE
  with the `sigil` CLI (Phase 30):** the `seal_to_container`/`open_container`
  exports read+write the exact same **`SIGILcli` container** the CLI does (magic
  `SIGILcli`, `FORMAT_VERSION` 1, the three Argon2 params as `u32` LE, a `u8`-length
  salt, then the envelope; fixed AEAD `AAD = "sigil-cli/1"`), so **seal-in-browser →
  `sigil open`** and **`sigil seal` → open-in-browser** both round-trip. The format
  constants are **MIRRORED — not shared** — in `cli/src/lib.rs` (`MAGIC`,
  `FORMAT_VERSION`, `AAD`, `FIXED_HEADER_LEN`) and `sigil-wasm/src/lib.rs`
  (`CLI_MAGIC`, `CLI_FORMAT_VERSION`, `CLI_AAD`, `CLI_FIXED_HEADER_LEN`), each with a
  comment tying it to the other file; **they MUST stay byte-for-byte in sync** (no
  shared crate for this pre-audit demo format). Guarded by a native golden-header
  test plus a Node interop test (`sigil-wasm/test/interop.mjs`) that **shells to the
  real built `sigil` binary in BOTH directions** (A: CLI seals → wasm opens; B: wasm
  seals → CLI opens). A DEMO of the UNAUDITED building block, **NOT** the product
  account/key-management model; the `SIGILcli` container is a pre-audit CLI/demo
  container, not a frozen product wire format; not for real secrets (ADR 0020).
  **Now ALSO does HYBRID public-key (no-password) encryption (Phase 31):** the
  `hybrid_x25519_public` / `hybrid_mlkem_encaps_key` / `hybrid_seal_to_container` /
  `hybrid_open_container` exports encrypt a file **to** a device's hybrid identity
  (**X25519 + ML-KEM-768**) and decrypt it, reading+writing the same **`SIGILhyb`
  container** the CLI does (`HYBRID_MAGIC` `SIGILhyb`, `HYBRID_FORMAT_VERSION` 1,
  `eph_x25519_pub[32]`, `mlkem_ct[1088]`, then the envelope; fixed AEAD `HYBRID_AAD =
  "sigil-hybrid-cli/1"`) — the **FIRST browser exercise of the PQ-hybrid encryption
  path**. All entropy stays JS-supplied (X25519 secret, ML-KEM keygen seed,
  ephemeral X25519 secret, ML-KEM coin, AEAD nonce all via `crypto.getRandomValues`
  → both `Cargo.lock`s stay `getrandom`==0); the wasm crate does **not** parse
  identity files, so Node bridges the CLI identity JSON (fields `x25519_public_key`
  / `mlkem_encaps_key` / `x25519_secret` / `mlkem_seed`, std-base64). The `HYBRID_*`
  format consts are **MIRRORED — not shared** — both `cli/src/lib.rs` and
  `sigil-wasm/src/lib.rs` define `HYBRID_MAGIC` / `HYBRID_FORMAT_VERSION` /
  `HYBRID_AAD`, each with a sync comment; **they MUST stay byte-for-byte in sync**.
  Guarded by a native golden fixed-prefix test plus a Node interop test
  (`sigil-wasm/test/hybrid-interop.mjs`) that **shells to the real built `sigil`
  binary in BOTH directions** (A: wasm seals → `sigil hybrid-open`; B: `sigil
  hybrid-seal` → wasm opens). A DEMO of the UNAUDITED building blocks — a **custom
  KEM-then-AEAD, NOT RFC 9180 HPKE**, not the product key-management model, not for
  real secrets; the **system is NOT "post-quantum secure"** (ADR 0021).
  **Now CLOSES THE CLIENT↔SERVER E2EE SYNC LOOP (Phase 32, ADR 0022):**
  **`sigil-wasm/sync.mjs`** is a tiny, framework-free, dependency-free ESM transport
  (`pushContainer` / `pullContainers`) that shuttles **OPAQUE** sealed containers
  to/from a **dev `sigild` op-log** over `fetch` — the JS twin of `sigil push` /
  `sigil pull`. It does **no cryptography** and never inspects a container: crypto
  stays in the wasm (`seal_to_container` / `hybrid_seal_to_container` seal BEFORE
  push), the JS only moves bytes. It speaks the existing dev op-log contract:
  `pushContainer` POSTs the **raw container bytes** to `POST /v1/vaults/{id}/ops`
  (→ 201 `{vaultID, seq}`); `pullContainers` drains `GET /v1/vaults/{id}/ops?since=&limit=`
  (→ `{vaultID, ops:[{seq, blob, hash}], next, has_more}`, `blob`/`hash` std-base64),
  looping `since=next` until `has_more` is false and base64-decoding each `blob` back
  to the exact bytes. Works in **both Node (global `fetch` + `Buffer`) and the browser
  (`fetch` + `atob`)** — the only env-specific bit (base64 decode) is feature-detected.
  Proven by **`sigil-wasm/test/sync-interop.mjs`**, which builds `sigild` (`go build
  ./cmd/server`) + the real `sigil` CLI (`cargo build --bin sigil`), boots a **LIVE
  sigild** on a free localhost port (`SIGILD_ENABLE_DEV_OPS=1`, in-memory, no auth),
  and asserts: PROOF 1 client self-loop (wasm seal → push → pull → wasm open); PROOF 2
  **CLI writes / browser reads** (`sigil seal`+`sigil push` → JS pull → `wasm.open_container`);
  PROOF 3 **browser writes / CLI reads** (wasm seal + JS push → `sigil pull` + `sigil open`);
  and OPAQUE — a raw `GET …/ops` blob base64-decodes to **EXACTLY** the pushed bytes
  (the server returned them verbatim, did no crypto → **zero-knowledge** intact). The
  browser `demo/` also gains a **Sync** section (server-URL + vault-ID fields, Seal→Push /
  Pull→Open buttons) over `sync.mjs`. **Dev / localhost / plain-HTTP / no-auth** (no
  `SIGILD_OPLOG_PUBKEY`), UNAUDITED, **not** the product sync model (no real auth /
  enrollment / CRDT); do not point it at a remote host or use it for real secrets.
  **Now GENERATES TOTP codes in the browser, cross-client with the CLI (Phase 34,
  ADR 0024) — the first end-to-end product feature working across two clients + the
  server.** Three `#[wasm_bindgen]` exports wrap the core OTP primitive (ADR 0023):
  `totp(key, unix_time, period, t0, digits, algorithm)`, `hotp(key, counter, digits,
  algorithm)`, and `format_code(code, digits)`. Per the no-clock invariant **JS
  supplies the time** — `unix_time`/`t0`/`counter` arrive as `f64` and are validated
  to non-negative integers before the `u64` cast (`u64_from_f64`); the `algorithm`
  string map (`otp_algorithm_from_str`) mirrors the CLI's `totp_algorithm_from_str`,
  and TOTP/HOTP draw no entropy so `sigil-wasm/Cargo.lock` stays `getrandom`==0. A
  framework-free ESM module **`sigil-wasm/totp-vault.mjs`** (runs in Node + browser)
  reads/writes the **same sealed `SIGILcli` TOTP vault the `sigil totp` CLI uses** —
  `openVault` / `sealVault` / `addEntry` / `codeForEntry` / `newVault` (+ `base32Decode`)
  over `open_container` / `seal_to_container` / `totp` / `format_code`, doing no crypto
  itself. **The `TotpVault` / `TotpEntry` JSON schema is MIRRORED — not shared — between
  `cli/src/lib.rs` (`TotpVault`/`TotpEntry`/`TOTP_VAULT_VERSION`) and `totp-vault.mjs`
  and MUST stay in sync**: `TotpVault { version:1, entries }`, `TotpEntry { label,
  issuer? (omitted when absent, serde `skip_serializing_if`), secret (STANDARD base64
  of the RAW key bytes), algorithm (lowercase sha1/sha256/sha512), digits, period }`.
  Because a vault is just another opaque `SIGILcli` container it rides the existing
  `sync.mjs` op-log transport unchanged, so a secret added on ONE client and synced
  through the opaque op-log yields the SAME code on the other. The browser `demo/`
  gains a **TOTP authenticator vault** section (`demo/index.html` + `demo/main.js`:
  add a base32 secret, live per-entry codes, Seal→Push / Pull→Open). Proven by
  **`sigil-wasm/test/totp-interop.mjs`**: asserts the wasm TOTP KAT (RFC 6238 App B,
  T=59, sha1/256/512), then CLI `totp add` → push → browser pull → `openVault` →
  `codeForEntry(T=59)` == RFC vector `94287082` == an independent Node HMAC-SHA-1 TOTP,
  and the server returned the bytes verbatim (opaque). UNAUDITED, dev/localhost, GENERATE
  only (no verification / constant-time compare / zeroization); do NOT store real 2FA
  secrets. **The browser now also does TOTP import/export, at parity with the CLI** —
  another framework-free ESM module **`sigil-wasm/totp-migration.mjs`** gives it the
  same Google Authenticator bulk import (`otpauth-migration://offline?data=…`) + single
  `otpauth://` import/export as `sigil totp import`/`export`: `decodeMigrationUri` /
  `encodeMigrationUri` / `parseOtpauthUri` / `buildOtpauthUri` (+ `base32Encode`), wired
  into the demo (`demo/index.html` + `demo/main.js`). It is a **hand-rolled,
  dependency-free proto3 codec that MIRRORS `cli/src/migration.rs` (+ the `otpauth://`
  parse/build in `cli/src/lib.rs`) — no protobuf library, no wasm bridge; the codec now
  lives in BOTH Rust (cli) and JS (sigil-wasm) and MUST stay in sync**. Guarded by a
  Node CLI↔JS cross-tool agreement test **`sigil-wasm/test/migration-interop.mjs`**
  (builds the real CLI; proves both codecs wire-compatible BOTH ways — a GOLDEN Google
  Authenticator vector via JS, `sigil totp export --migration` decoded in JS [RUST→JS],
  and a JS-encoded migration URI imported by the CLI [JS→RUST]). `export` reveals the
  2FA secrets IN THE CLEAR by design; UNAUDITED, dev-only. ADR 0026.
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

# sigil-wasm — separate crate, wasm-bindgen binding over the core. Native fmt/
# clippy/test exercise the *_inner helpers; build-wasm.sh emits pkg-web/pkg-node
# (needs wasm-pack); then the Node round-trip proves seal/open in a JS runtime.
cargo fmt   --manifest-path sigil-wasm/Cargo.toml --all -- --check
cargo clippy --manifest-path sigil-wasm/Cargo.toml --all-targets -- -D warnings
cargo test  --manifest-path sigil-wasm/Cargo.toml
./sigil-wasm/build-wasm.sh                          # → pkg-web/ + pkg-node/ (gitignored)
node sigil-wasm/test/roundtrip.mjs                  # prints PASS, exits 0
node sigil-wasm/test/interop.mjs                    # wasm<->CLI SIGILcli interop (builds the real CLI, both directions); PASS
node sigil-wasm/test/hybrid-interop.mjs             # wasm<->CLI SIGILhyb hybrid public-key interop (builds the real CLI, both directions); PASS
node sigil-wasm/test/sync-interop.mjs               # wasm<->CLI opaque op-log sync (live sigild + real CLI, both directions); PASS
node sigil-wasm/test/totp-interop.mjs               # cross-client TOTP: CLI adds -> op-log -> browser code == RFC vector (wasm KAT + live sigild); PASS
node sigil-wasm/test/migration-interop.mjs          # CLI<->JS TOTP migration codec agreement (GOLDEN + RUST->JS + JS->RUST; builds the real CLI); PASS
grep -c 'name = "getrandom"' sigil-wasm/Cargo.lock  # must ALSO be 0 (JS supplies entropy)

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

- **License split:** clients/core/web/CLI = Apache-2.0 (incl. `sigil-wasm`, the
  client-side wasm binding); `sigild/` = BSL-1.1.
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
