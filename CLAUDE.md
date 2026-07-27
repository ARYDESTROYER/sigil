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

**Sigil (working name)** — a paid, multi-platform authenticator, **designed**
end-to-end-encrypted and post-quantum-*ready* (design intent, not a shipped
guarantee — nothing here is audited). This repo is the **pre-launch / pre-audit
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
  **NOTE (Phase 46): the "standalone / not wired into any flow" framing below is now
  TRUE ONLY OF THE SIGNATURE.** The hybrid KEM — through `hybrid_seal`/`hybrid_open` —
  is **LOAD-BEARING**: it wraps the per-vault key for device-to-device vault sharing
  (ADR 0035), so it is real product code and in scope for the audit. The hybrid
  SIGNATURE is still used by nothing (all request auth is classical Ed25519). Still
  UNAUDITED, still a custom KEM-then-AEAD (NOT RFC 9180 HPKE), and the SYSTEM is
  still NOT "post-quantum secure".
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
  composition — NOT RFC 9180 HPKE. **Phase 46: this flow is NO LONGER STANDALONE —
  it WRAPS THE PER-VAULT KEY for device-to-device vault sharing (`sigil vault share`
  → `wrap_vault_key` → `hybrid_seal_to_container`; sigild relays the OPAQUE envelope
  and cannot read it, ADR 0035), making the hybrid KEM real product code and IN
  SCOPE for the audit.** Still UNAUDITED, still NOT the product's ACCOUNT model, and
  there is NO out-of-band verification of a recipient's hybrid public key. ADR 0013.**
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
  e.g. Redis), dev-only — this v2 mode is now the **LEGACY** contract, superseded (when
  enabled) by the opt-in **multi-device contract v3** below; JWT/session issuance remains
  future. **No crypto
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
  `seq`), Mem holds it in-process. `GET …/ops` returns each op's **std-base64**
  `hash` (NOT hex — `handlers.go` emits `base64.StdEncoding`, and `docs/api.md`
  is the authority); a new
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
  **A REAL MULTI-DEVICE AUTH MODEL — op-log auth contract v3 (Phase 41, ADR 0031),
  opt-in + dev-gated:** when **`SIGILD_DEVICE_AUTH`** is truthy (requires
  `SIGILD_ENABLE_DEV_OPS`; **MUTUALLY EXCLUSIVE with `SIGILD_OPLOG_PUBKEY`** — with both
  set the server **REFUSES TO BOOT**, rc=1, `"invalid device-auth configuration"`), the one
  static v2 key is replaced by a **device registry**: each request carries a new
  **`X-Sigil-Device`** header naming an ENROLLED device and is verified against **THAT
  device's registered Ed25519 public key**. Signed message
  (`canonicalV3Message`, deviceauth.go): `"sigil-oplog-auth-v3\n" + DEVICE_ID + "\n" +
  METHOD + "\n" + PATH + "\n" + QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + BODY` —
  the domain bump v2→v3 **plus** the device segment mean **v2 signatures do not verify
  under v3** (401). Headers: `X-Sigil-Device`/`X-Sigil-Timestamp`/`X-Sigil-Nonce`/
  `X-Sigil-Signature` (+ `X-Sigil-Enroll-Token`, `X-Sigil-Admin-Token`); the 300 s window
  and per-process nonce cache are retained. **Five NEW dev-gated routes** (`501` when
  dev-ops off — never 404): **`POST /v1/devices/enroll`**, **`GET /v1/devices`**,
  **`POST /v1/devices/{deviceID}/revoke`**, **`POST /v1/vaults/{vaultID}/grants`**,
  **`GET /v1/vaults/{vaultID}/grants`**; the existing ops routes now also enforce
  **per-vault authorization** (POST ⇒ write, GET ops + ops/verify ⇒ read).
  **ENROLLMENT = two mandatory factors:** an operator token (**`SIGILD_ENROLL_TOKENS`**,
  comma-separated, each ≥16 chars, **held ONLY as SHA-256 digests**; optional
  **`SIGILD_ENROLL_TOKEN_TTL`**, a positive Go duration — unset ⇒ no expiry but still
  SINGLE-USE) **PLUS proof of possession** over a DIFFERENT domain
  (`canonicalEnrollMessage`): `"sigil-device-enroll-v1\n" + TOKEN_SHA256_HEX + "\n" +
  TIMESTAMP + "\n" + NONCE + "\n" + PUBLIC_KEY_B64 + "\n" + LABEL`, signed by the enrolling
  key and verified against the **SUBMITTED** public key (body `{"public_key","label"}`,
  proof in `X-Sigil-Signature`) — so a proof can never be replayed as a request signature.
  **VERIFY ORDER** (1:1 with the audit reason): headers → timestamp parses → inside 300 s →
  device resolves → **NOT revoked (checked BEFORE signature verification**, so revocation
  bites on the next request) → Ed25519 verifies under that device's key → nonce not
  replayed (recorded ONLY after a valid signature) → per-vault authorization.
  **AUTHORIZATION:** grants are `(vaultID, deviceID) -> read|write` (write implies read);
  ownership is **TRUST-ON-FIRST-WRITE** — the first device to authenticate a WRITE to an
  unclaimed vault becomes owner (atomic: mutex in mem, partial UNIQUE index in Postgres);
  reads never claim (403 on an unowned vault); only the owner may grant. **401 =
  unauthenticated, 403 = authorized-not-permitted**, but the client body is only
  `{"error":"unauthorized"}` / `{"error":"forbidden"}` — the typed reason
  (`unknown_device`/`revoked_device`/`unauthorized_vault`/`not_vault_owner`/
  `forbidden_device`/`bad_admin_token`/`bad_proof`/`enrollment_token_used`/… ) goes ONLY to
  the audit log + metrics, so **there is no auth oracle**. Optional
  **`SIGILD_ADMIN_TOKEN`** (≥16 chars) gates the operator routes (list all / revoke any);
  **unset ⇒ those routes are permanently 401 — there is NO implicit open-admin mode**. All
  four env vars are validated **fail-fast before the listener binds**.
  **STORAGE:** a new managed migration **`0002_devices.sql`** (0001_init untouched) creates
  **`sigil_devices`** / **`sigil_enrollment_tokens`** / **`sigil_device_grants`** (+ the
  partial unique index `sigil_device_grants_one_owner`) → **`sigild_schema_version` now
  reports 2**. `store.DeviceStore` is the seam: `MemDeviceStore` (non-durable) or
  `PostgresDeviceStore` **sharing the op-log's existing `pgxpool`** (no second pool, **no new
  dep** — `pgx` is still the only one). **The op-log blob is UNTOUCHED — this adds AUTH
  METADATA ONLY, so the hash chain and the zero-knowledge boundary are unaffected.** New
  metrics: `sigild_device_enrollments_total`, `sigild_device_revocations_total`,
  `sigild_vault_grants_total`, `sigild_vault_claims_total`, `sigild_oplog_authz_denied_total`,
  `sigild_device_enroll_denied_total{reason}` (+ new reasons on
  `sigild_oplog_auth_denied_total{reason}`); new audit events `device.enrolled` /
  `device.enroll_denied` / `device.revoked` / `vault.claimed` / `vault.granted` carrying
  `device_id` + `reason` but **never** a key/token/signature/nonce/blob.
  **HONEST LIMITS (do NOT paper over):** TOFU is a **dev ownership model, not an account
  model**; an enrollment token is **single-ATTEMPT not single-SUCCESS** (spent before the
  device row is created, so a duplicate-key enrollment burns it — fail-closed, issue a new
  token); the **replay nonce cache is per-process/in-memory** (multi-instance needs a shared
  store; enrollment nonces are prefix-separated in the shared namespace); **revoking a
  vault's owner ORPHANS the vault** (no ownership transfer); the **in-memory registry is
  non-durable** (a spent token becomes reusable after restart — warned at boot) and the
  **file backend was NOT extended** (device auth + `SIGILD_OPLOG_DIR` falls back to the
  in-memory registry, warned at boot); and it is still **dev-gated, pre-audit, UNAUDITED** —
  no user/account model, no session/token issuance, **no rate limiting on enrollment
  attempts**, no key rotation. Contract in [`docs/api.md`](docs/api.md); ADR 0031.
  **A BILLING / SUBSCRIPTION LAYER (Phase 45, ADR 0034) — opt-in + dev-gated, UNAUDITED,
  NEVER RUN AGAINST A LIVE PROVIDER ACCOUNT:** Sigil is a PAID product, so `sigild` now has
  a **provider-agnostic billing seam** (`internal/billing/`): ONE `billing.Provider`
  interface (`Name`/`CreateCheckout`/`VerifyWebhook`) with **three adapters** —
  **`stripe.go`** (international), **`razorpay.go`** and **`juspay.go`** (India) — a
  **normalized event vocabulary** (`checkout_completed`/`subscription_activated`/
  `subscription_renewed`/`subscription_canceled`/`payment_failed`/`ignored`) and an explicit
  **state machine** (`state.go`: `none`/`trialing`/`active`/`past_due`/`canceled` as a
  transition TABLE; `past_due` is still `Entitled`). **THE RULE THAT SHAPED IT: NO VENDOR
  SDKs.** Every adapter is `net/http` + `crypto/hmac` + `crypto/subtle` + `encoding/json` +
  `net/url` only, so **`sigild/go.mod` still has EXACTLY ONE direct require (`pgx`)** and the
  security-critical verification is ~30 readable lines per provider instead of an opaque
  library call. **HOSTED CHECKOUT ONLY** (Stripe `POST /v1/checkout/sessions` form-encoded,
  Razorpay `POST /v1/payment_links`, Juspay `POST /session`): we ask for a URL and hand it to
  the client, so **NO CARD DATA EVER ENTERS THIS PROCESS** — no struct field, log line, metric
  or column could hold a PAN/CVV/expiry (PCI scope SAQ-A; **not** an attestation).
  **THREE ROUTES, TWO AUTHS:** `POST /v1/billing/checkout` + `GET /v1/billing/subscription`
  reuse the **device-auth v3** choke point (`authenticateDevice`) and the **subject is the
  AUTHENTICATED DEVICE ID, never a body field**; `POST /v1/billing/webhook/{provider}` is
  authenticated **ONLY by the provider's own signature over the RAW body** (a provider has no
  device key). Verification is **real**: Stripe `HMAC-SHA256("<t>.<raw body>")` from
  `Stripe-Signature` (5-minute tolerance both directions, EVERY `v1` element compared, legacy
  `v0` ignored), Razorpay `HMAC-SHA256(raw body)` from `X-Razorpay-Signature`, Juspay either
  **`hmac` (the DEFAULT since Phase 51 — configurable header, default `X-Juspay-Signature`)**
  or `basic` (constant-time `Authorization: Basic`, an **EXPLICIT OPT-IN**) behind a
  swappable `juspayWebhookVerifier` seam — all constant-time
  (`hmac.Equal`/`subtle.ConstantTimeCompare`), verified over the RAW bytes BEFORE the JSON is
  parsed, every failure a coarse 401. ⭐ **IDEMPOTENCY (Phase 51, ADR 0039 — revising §4 of
  ADR 0034): the dedup key MUST be derived only from bytes the provider's SIGNATURE COVERS.**
  `billing.Event` gained `DedupKey` + `Event.IdempotencyKey()` (falls back to `ID`), and
  `internal/api/billing.go` passes `EventID: ev.IdempotencyKey()`. Stripe sets
  `DedupKey = env.ID` (its id is INSIDE the signed payload); **Razorpay ALWAYS sets
  `DedupKey = "body-" + hex(SHA-256(rawBody))`** — Razorpay signs the BODY ONLY, so a
  captured valid delivery replayed with a fresh **`X-Razorpay-Event-Id`** header still
  verifies, and keying on that header made every replay look like a NEW event (an
  attacker-driven, unbounded processed-events ledger); the header is now only a correlation
  LABEL on `Event.ID`. Juspay derives its id from the BODY too — so the invariant holds under
  `scheme=hmac` and is **VACUOUS under `scheme=basic`** (which authenticates the CONNECTION
  and covers no bytes). That asymmetry is why `hmac` is now the default: `cmd/server`
  requires `SIGILD_JUSPAY_WEBHOOK_SECRET` when the scheme is unset, choosing `basic` without
  its credentials is a BOOT FAILURE whose message names what was given up, and a `basic` boot
  logs a WARN naming the limitation EVERY start. Both schemes still fail CLOSED on an unset
  secret. The key is
  **fused with the state change into ONE atomic op** (`SubscriptionStore.ApplyWebhookEvent`:
  one mutex in mem, one tx with `ON CONFLICT DO NOTHING` + `SELECT … FOR UPDATE` in Postgres),
  so a **duplicate delivery is a no-op that still answers 200** (outcomes
  `accepted`/`ignored`/`duplicate`/`stale`/`illegal`/`unresolved` are ALL 200 — a non-2xx
  would put the provider into retry/backoff; 400 malformed, 401 bad signature, 404 unknown
  provider, 413 oversize, **500 store fault = the only retryable class**). **NEW ENV** (all
  validated fail-fast BEFORE the listener binds, NO network I/O at boot):
  **`SIGILD_BILLING_PROVIDERS`** (`stripe,razorpay,juspay`; unset ⇒ OFF; **requires
  `SIGILD_ENABLE_DEV_OPS` AND `SIGILD_DEVICE_AUTH`**), `SIGILD_BILLING_DEFAULT_PROVIDER`,
  `SIGILD_BILLING_SUCCESS_URL`/`_CANCEL_URL` (required, absolute http(s)),
  `SIGILD_STRIPE_SECRET_KEY`/`_WEBHOOK_SECRET`/`_PRICE_ID`/`_API_BASE_URL`,
  `SIGILD_RAZORPAY_KEY_ID`/`_KEY_SECRET`/`_WEBHOOK_SECRET`/`_AMOUNT_MINOR`/`_CURRENCY`/
  `_DESCRIPTION`/`_API_BASE_URL`, `SIGILD_JUSPAY_MERCHANT_ID`/`_API_KEY`/`_CLIENT_ID`/
  `_WEBHOOK_SCHEME`/`_WEBHOOK_USERNAME`/`_WEBHOOK_PASSWORD`/`_WEBHOOK_SECRET`/
  `_WEBHOOK_SIG_HEADER`/`_AMOUNT_MINOR`/`_CURRENCY`/`_API_BASE_URL` (enabling a provider
  WITHOUT its secrets is a BOOT ERROR). **STORAGE:** migration **`0003_billing.sql`**
  (0001/0002 untouched) creates **`sigil_subscriptions`** + **`sigil_billing_processed_events`**
  (PK `(provider, event_id)`) → **`sigild_schema_version` now reports 3**;
  `store.SubscriptionStore` is the seam (`MemSubscriptionStore`, non-durable, or
  `PostgresSubscriptionStore` **sharing the op-log's existing `pgxpool`** — no second pool, no
  new dep). **NO CARD DATA / NO PII COLUMN EXISTS**, the raw payload is never persisted, and
  `sigil_vault_ops` is untouched ⇒ zero-knowledge intact. New metrics
  `sigild_billing_checkouts_total{provider}`, `sigild_billing_webhooks_total{provider,outcome}`,
  `sigild_billing_webhook_rejected_total{reason}`,
  `sigild_billing_subscription_transitions_total{status}` (CLOSED label sets materialized at
  boot); new audit events `billing.checkout_created`/`checkout_failed`/`webhook`/
  `webhook_rejected`/`subscription_transition` carrying metadata only — **never a key, secret,
  signature header, or one byte of the raw body**. **DEFAULT = 501** on all three routes
  (never 404). **HONEST LIMITS:** **nothing has ever been run against a live provider
  account** (all tests drive a local `httptest` server); the **Juspay** adapter is explicitly
  **UNVERIFIED-AGAINST-LIVE-DASHBOARD** (header names / signed message / endpoint / event
  vocabulary must be confirmed first) and Razorpay's surrounding details are MEDIUM
  confidence; **no account model** (a subscription keys off the enrolled DEVICE); recurring
  subscription CREATION is unimplemented for the India adapters (one-time hosted page; their
  webhook sides do map subscription/mandate events); no entitlement enforcement, no
  fraud/chargeback/refund/proration/tax/dunning; **no PCI attestation**; the in-memory store
  is non-durable (a redelivery across a restart could double-apply); no rate limit on the
  webhook route; and **billing living inside `sigild` is PROVISIONAL** — a scaffold placement,
  not a final topology. Contract in [`docs/api.md`](docs/api.md), operator guide in
  [`docs/deployment.md`](docs/deployment.md) §13; ADR 0034, **ADR 0039** (the dedup-key
  invariant + the Juspay default).
- `sigild/` **DEVICE-TO-DEVICE VAULT SHARING (Phase 46, ADR 0035)** — a **key relay**,
  behind the SAME dev gate + the SAME v3 auth choke points (`authenticateDevice` /
  `authorizeVault` / `authorizeOpsRequest`; there is **no new auth path**), in
  `internal/api/sharing.go` + `internal/store/keysharing.go` +
  `internal/store/postgreskeysharing.go`. **Four routes** (`501` when dev-ops off, exactly
  like the device routes): **`PUT|GET /v1/devices/{deviceID}/hybrid-key`** (publish/fetch a
  device's hybrid PUBLIC key — publish is **self-only**, mismatched path ID ⇒ **403**;
  body ≤ **8 KiB** = `maxHybridKeyBodyBytes`; fetch 404s `hybrid_key_not_found`) and
  **`PUT|GET /v1/vaults/{vaultID}/keys/{deviceID}`** (deposit/collect an **opaque wrapped
  vault key** — PUT needs **write** and a first deposit CLAIMS an unowned vault
  (trust-on-first-write), returns **201** `{vaultID, device_id, size_bytes, created_at}`,
  `404 device_not_found` / `409 device_revoked` / `413` over `store.MaxKeyEnvelopeBytes` =
  **16 KiB**; GET requires the caller to **BE the addressee AND hold read** ⇒ otherwise
  **403, never 401/404**, and returns the **exact stored bytes** as
  `application/octet-stream`). **ZERO-KNOWLEDGE:** the server has no decapsulation key,
  decodes nothing, returns the envelope VERBATIM, and its ONLY look at key material is a
  **length check** (`ValidateHybridPublicKey`: `X25519PublicKeyLen` 32 /
  `MLKEM768EncapsKeyLen` 1184) — never a curve-point parse. Storage seam is
  `store.KeySharing` (embedded in `DeviceStore`, one conformance suite, Mem + Postgres);
  migration **`0004_key_sharing.sql`** adds `sigil_device_hybrid_keys` +
  `sigil_vault_key_envelopes` (+ index `sigil_vault_key_envelopes_by_recipient`), both
  UPSERTs, purely additive ⇒ **`sigild_schema_version` now 4**. Audit events
  `device.hybrid_key_published` / `vault.key_envelope_put` / `vault.key_envelope_get` carry
  metadata + a **`blob_sha256` fingerprint**, NEVER the bytes or any key; metrics
  `sigild_device_hybrid_keys_published_total` / `sigild_vault_key_envelopes_total` /
  `sigild_vault_key_envelope_fetches_total` (counts only, no vault/device label).
  **TWO MORE ROUTES for ROTATION (Phase 50, ADR 0038)** — same dev gate, and reusing the
  **EXISTING `authorizeOpsRequest` with `needWrite`**, i.e. the very check that authorizes
  depositing an envelope (a device that can deposit can already REPLACE any envelope, so
  enumerate+delete grants no new power): **`GET /v1/vaults/{vaultID}/keys`** →
  `{vaultID, recipients:[{device_id, sender_device_id, size_bytes, created_at}]}` —
  ⭐ **METADATA ONLY, NEVER a blob** (Postgres selects `octet_length(blob)`, so ciphertext
  never leaves the DB), sorted by recipient, unknown vault ⇒ empty list — and
  **`DELETE /v1/vaults/{vaultID}/keys/{deviceID}`** → `{vaultID, device_id, deleted:true}`,
  `404 envelope_not_found` when absent (a rotating client treats that as success). Store
  methods `ListKeyEnvelopeRecipients`/`DeleteKeyEnvelope` (+ `KeyEnvelopeMeta`) on Mem +
  Postgres; audit `vault.key_envelope_list` (`returned_count`) / `vault.key_envelope_delete`
  (`recipient_device_id` + caller) — **no `blob_sha256`, because neither route reads a blob**;
  metric `sigild_key_envelope_deletes_total` (count only). ⭐ **sigild gained NO knowledge of
  pins or safety numbers** — it stores none, serves none, validates none — and still has
  **exactly ONE direct dependency**.
  ⚠️ **HONEST SCOPE:** dev-gated/`501`, plain HTTP, UNAUDITED; verification of a published
  hybrid key is **CLIENT-SIDE ONLY** (pinning + safety numbers, ADR 0038) and **cannot
  protect FIRST contact** unless a human compares the digits; revocation stops FUTURE
  access but **cannot un-learn** a key a device already unwrapped (remediation = `vault
  rotate`, which protects **FUTURE content only** and is **manual** — no automatic re-wrap
  on revoke, no rotation schedule, **no forward secrecy**); one mailbox per (vault,
  recipient) so any writer can overwrite; **no rate limiting**; request signatures are
  **classical Ed25519** (the wrap is hybrid, the auth is not). Contract in
  [`docs/api.md`](docs/api.md); key hierarchy + the safety-number construction in
  [`docs/crypto-spec.md`](docs/crypto-spec.md).
- `sigild/` also carries **seven committed but INERT scaffold packages** (compile, do
  nothing, wired to nothing): `cmd/worker-audit`, `cmd/worker-breach`, `cmd/worker-rehash`
  (~15-line `main.go` stubs) and `internal/admin`, `internal/auth`, `internal/push`,
  `internal/vault` (6–7-line `doc.go` placeholders). They name future work only — note in
  particular that `internal/auth` is **NOT** where the real auth lives (that is
  `internal/api/deviceauth.go` + `internal/store/devicestore.go`).
- `web/apps/marketing/` — Next.js 15 stealth splash + waitlist. No-index, wallable.
  ⚠️ **Phase 51 corrected `app/security/page.tsx`, which was UNDER-claiming but still
  FALSE.** It said "nothing below is implemented" and listed ML-KEM-768 / ML-DSA-65 as
  "planned". Now Argon2id, XChaCha20-Poly1305, X25519, Ed25519, ML-KEM-768 and ML-DSA-65
  read **"Implemented; unaudited"**; ML-KEM-768 is additionally **load-bearing** (combined
  with X25519 into the hybrid KEM that wraps a vault key when a vault is shared);
  ML-DSA-65 is **"implemented; not yet in the authentication path"** (device auth is still
  Ed25519 alone); TLS `X25519MLKEM768` stays **"Designed; planned"**. A defined status
  vocabulary pins what the words mean — **"implemented" = the code exists in the
  pre-release repo and its own tests pass, NOT released and NOT reviewed** — and a
  dedicated paragraph states that implementing ML-KEM/ML-DSA does **NOT** make a system
  "post-quantum secure" and that we do not claim it does. ⚠️ **Premise correction, and an
  invariant for anyone writing about the PQ primitives:** the audit finding claimed they
  are "tested against FIPS vectors". **THAT IS FALSE IN THIS REPO** — `mlkem.rs:332` and
  `mldsa.rs:335` state plainly that **NO official FIPS 203 / FIPS 204 / NIST ACVP
  known-answer vector is embedded**; the **UPSTREAM RustCrypto crates** are ACVP-validated,
  and our correctness rests on round-trip/determinism tests plus that upstream vetting.
  The page therefore says the primitives are "covered by their own tests". **Never write
  that we verify against FIPS/ACVP vectors.** Public copy still obeys
  [`web/apps/marketing/MARKETING-CLAIMS.md`](web/apps/marketing/MARKETING-CLAIMS.md).
- `web/apps/webapp/` + `web/packages/sigil-wasm/` — Next.js 15 app running the libsigil
  core via **WebAssembly, entirely client-side** (over the `@sigil/wasm` loader that
  wasm-packs the repo-root `sigil-wasm` crate for a bundler target; ADR 0027). Now a
  **real (dev) authenticator UI**: a multi-account **encrypted TOTP vault** that
  **seals to a `SIGILcli` container** (Argon2id → XChaCha20-Poly1305, the same sealed
  format as the CLI/browser vault, cross-client-interoperable) and **persists ONLY the
  sealed container** in `localStorage` with an **in-memory password unlock** (password
  never persisted; boots into a lock screen when a sealed vault exists). **Add** by form
  / `otpauth://` / **Google Authenticator `otpauth-migration://` import**, **export**
  back out, live **codes + countdowns computed in the wasm**; entropy via
  `crypto.getRandomValues`; optional dev **Sync** of the sealed container to a localhost
  op-log (ADR 0028). **Now an installable, offline-capable, accessible PWA (Phase 39,
  ADR 0029):** a web **manifest** (`app/manifest.ts`) makes it installable, and a
  hand-rolled **service worker** (`public/sw.js`, registered by `app/register-sw.tsx`)
  precaches the app shell and runtime-caches JS/CSS/`.wasm` **cache-first**, so after the
  first online load codes still **generate offline in the wasm with no network** — the SW
  caches **only static assets** (the **sealed vault stays in `localStorage`**; cross-origin
  sync is left untouched). It is also **accessible** (ARIA/keyboard/focus/live-region,
  axe-clean). Playwright-proven (`tests/wasm.spec.ts` add-account == RFC vector + GA import
  + lock/reload/unlock persistence; `tests/offline.spec.ts` offline TOTP; `tests/a11y.spec.ts`
  axe). **Dev / no-index / UNAUDITED, not deployed**, kept OUT of the default `web` CI job
  (needs the Rust + wasm-pack toolchain) — a **separate `webapp` CI job** in
  `.github/workflows/web.yml` builds `@sigil/wasm` with a Rust + wasm-pack toolchain and
  runs the Playwright suite, while the marketing job stays Rust-free; `web/packages/sigil-wasm/build.sh`
  was made **cross-platform** (OS-agnostic PATH + wasm-bindgen discovery) for that runner.
  Like the repo's other CI mirrors, the `webapp` job is validated by-eye / YAML-parse
  locally and has not run on real GitHub Actions from here. **Now also ENROLLS + signs
  as a device (Phase 44, ADR 0033):** the Sync panel (`app/authenticator.tsx`) can
  `enrollDevice` this browser against a `SIGILD_DEVICE_AUTH` dev sigild and then
  push/pull via `pushContainerAuthed`/`pullContainersAuthed` (contract v3 signatures
  produced IN THE WASM); with no identity it stays unauthenticated exactly as before,
  and `explainAuthStatus` renders 401-vs-403 plainly. **The Ed25519 device seed is NEVER
  stored in plaintext**: it is sealed into a **SECOND `SIGILcli` container under the SAME
  vault password** and only that container is persisted (`localStorage` key
  **`sigil.webapp.device.v1`**, sealed plaintext `{version, device_id, seed, base_url}`);
  the decrypted seed is memory-only while unlocked — lock / reload / forget drop it, and
  forget deletes the sealed identity too. The enrollment token is an in-memory bearer
  secret cleared after use, never stored or logged. ⚠️ The enrollment UI itself is NOT
  Playwright-covered (the protocol is proven live in Node); the existing 8-test suite
  still passes. **Now ALSO SHARES vaults (Phase 48, ADR 0035/0036):** a **`SharingPanel`**
  in `app/authenticator.tsx` (over `sharing.mjs` re-exported by `@sigil/wasm`) gives the
  webapp the **FULL** flow — show/copy this device id, **publish** this device's hybrid
  key (`generateHybridIdentity` on first use → `publishHybridKey`), **convert** the
  password vault into a shared vault under a fresh random 32-byte key
  (`generateVaultKey`; the UI's `sigil vault rekey`, a **ONE-WAY DOOR**), **share** to a
  pasted recipient device id with read/write (`shareVault`), and **accept** a vault
  shared to this device (`acceptVault` → pull → open); `explainSharingStatus` renders
  401/403/404 distinctly. ⭐ **NOTHING NEW IS PERSISTED IN THE CLEAR:** the EXISTING
  sealed device-identity container was extended **v1→v2** (and **v2→v3** in Phase 50)
  rather than adding a store, so
  `sigil.webapp.device.v1` now seals `{version:3, device_id, seed, base_url,
  hybrid:{x25519_secret, mlkem_seed}, vault_keys:{...}, pins:{...}}` — the Ed25519 seed,
  the hybrid SECRET identity, every accepted vault key **and the hybrid-key PIN STORE**
  in ONE container under the vault
  password. `localStorage` still holds exactly TWO keys, both sealed containers
  (`sigil.webapp.vault.v1` + `sigil.webapp.device.v1`); the password and all decrypted
  secrets are memory-only and cleared on lock/forget/unload. **Unlock now opens the
  device identity FIRST, tries the password, then falls back to each held vault key**,
  so a shared vault re-opens after a reload. **Phase 50 (ADR 0038) added the key-trust UI
  to the same panel:** show this device's / a peer's **safety number** (`wasm.safetyNumber`),
  a `wasm.KeyPinMismatchError` catch that **BLOCKS the share** and renders both safety
  numbers with a deliberate re-pin (`wasm.repinHybridKey`) behind it, and **rotate**
  (`wasm.rotateVaultKey`) — with `onUpdateDevice({ pins: res.pins })` re-sealing the
  container so the pins persist. Do NOT store real 2FA secrets.
- `web/apps/webapp/` + `web/packages/sigil-wasm/` — **the first real product client
  surface** (no longer reserved). `web/packages/sigil-wasm` is the **`@sigil/wasm`**
  workspace loader package: its `build.sh` compiles the **repo-root `sigil-wasm` Rust
  crate** to WebAssembly for a **wasm-pack `--target bundler`** target and re-exports
  the wasm surface (`seal_record`/`open_record`, `seal_to_container`/`open_container`,
  `hybrid_*`, `totp`/`hotp`/`format_code`, …) behind an `initWasm()` awaitable +
  `index.d.ts`, PLUS re-uses the **proven, wasm-agnostic helpers** from the repo-root
  `sigil-wasm/{totp-vault,sync,totp-migration,device-auth,sharing}.mjs` by relative
  import (the same tested code, not a rewrite). Key bundling detail: rustc 1.85+ force-enables the wasm
  `reference-types`+`multivalue` target features, so wasm-bindgen emits `externref`,
  which Next.js 15's bundled (old `@webassemblyjs`) webpack parser cannot decode
  (`parseVec could not cast the value`); `build.sh` works around it with a **3-step
  strip** — cargo build to raw wasm, delete the `target_features` custom section (keeps
  the module in the MVP subset), then run `wasm-bindgen --target bundler` — output `pkg/`
  is gitignored. `web/apps/webapp` is a real **Next.js 15.1.6 / React 19 / Tailwind 3 /
  TS-strict** app-router app: `next.config.mjs` sets `webpack` `experiments.asyncWebAssembly
  = true` and carries the SAME no-index stealth headers as marketing (`X-Robots-Tag
  noindex/nofollow/noarchive`, nosniff, `no-referrer`, `X-Frame-Options DENY`) + an
  `app/robots.ts` (`Disallow: /`). Its page is a **live TOTP demo** (`app/page.tsx` +
  a `"use client"` `app/totp-demo.tsx` that dynamic-imports `@sigil/wasm` so the wasm
  loads only in the browser): it defaults to the PUBLIC RFC 6238 test seed
  (`GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ`, not a real secret) and shows the **wasm-computed**
  6-digit code + countdown (via `codeForEntry`/`base32Decode`; the wasm computes the
  code, never JS), with `?secret=` / `?t=` test hooks. **Dev / no-index / UNAUDITED**
  (loud pre-audit banner); it is **built via its own filter** and needs the Rust +
  wasm-pack toolchain — the default `web/` CI scripts still target **marketing only**,
  so marketing typecheck/lint/build and CI are unchanged and stay Rust-free (ADR 0027).
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
  Also **`sigil device enroll|list|revoke|grant`** — the CLIENT half of sigild's
  multi-device auth model (**contract v3**, ADR 0031; Phase 42), so the CLI is the
  FIRST client that speaks v3: `device enroll --token <t> [--label <name>] [--key
  <file>] [--server <url>] [--reuse-key]` (POST `/v1/devices/enroll`: generates —
  or with `--reuse-key` reuses — the key, signs the proof-of-possession challenge,
  and writes the server-assigned device ID into the 0600 identity file; it REFUSES
  to overwrite an existing identity file without `--reuse-key`), `device list
  --admin-token <t>` (GET `/v1/devices`, operator-only), `device revoke <deviceID>
  [--admin-token <t>] [--key <file>]` (POST `/v1/devices/{deviceID}/revoke` — self
  via `--key`, or operator via `--admin-token`), and `device grant <deviceID>
  --vault <id> --permission read|write [--key <file>]` (POST
  `/v1/vaults/{vaultID}/grants`, owner-only). `GET …/grants` has no subcommand yet.
  The **identity file is the EXISTING `sigil keygen` key file EXTENDED** with an
  OPTIONAL `device_id` (serde `default` + `skip_serializing_if`), so an old key file
  parses unchanged. **Contract selection is additive and driven by the identity**
  (`DeviceIdentity::auth` → `RequestAuth`): **no key ⇒ unsigned** (byte-identical
  legacy path) · **identity WITHOUT `device_id` ⇒ legacy v2** · **identity WITH
  `device_id` ⇒ v3** (adds `X-Sigil-Device`), so `push`/`pull` sign v3 automatically
  once their key is enrolled; **`SIGIL_DEVICE_ID`** forces v3 on an older key file.
  New env vars **`SIGIL_ENROLL_TOKEN`** / **`SIGIL_ADMIN_TOKEN`** / **`SIGIL_DEVICE_ID`**
  (flags win) beside the unchanged `SIGIL_SERVER`/`SIGIL_DEVICE_KEY`/`SIGIL_PASSWORD`;
  the default identity path `$HOME/.sigil/device.key` applies ONLY to the `device`
  subcommands (push/pull keep "no key means unsigned"). The CLI rebuilds the server's
  canonical bytes itself (`canonical_v3_message`/`canonical_enroll_message` in
  `cli/src/lib.rs`, fresh CSPRNG nonce + current unix seconds per request, signing via
  `sigil_core::sign`) — these **MUST stay byte-identical to sigild's `canonicalV3Message`
  /`canonicalEnrollMessage`**. Identity files are 0600 and the seed / enrollment token /
  admin token are NEVER printed. One new dependency EDGE only (`sha2`, for the
  enrollment-token digest — already in `cli/Cargo.lock` transitively, so no new package).
  Same honest scope as the server side: **dev op-log over PLAIN HTTP, no TLS,
  dev-gated + UNAUDITED**, trust-on-first-write ownership, single-ATTEMPT enrollment
  tokens, no account model / session issuance / key rotation, per-process replay cache.
  Also **`sigil device hybrid-publish`** and **`sigil vault rekey|share|accept|list`** —
  **DEVICE-TO-DEVICE VAULT SHARING** (Phase 46, ADR 0035), the FIRST load-bearing use of
  the PQ-hybrid primitives. ⚠️ **THE KEY HIERARCHY:** the human password seals a
  PERSONAL vault and is **NEVER shared, never wrapped, never sent**; a SHARED vault is
  sealed under a random 32-byte **VAULT KEY** (`generate_vault_key`, `VAULT_KEY_LEN` =
  32) that goes into the **SAME `SIGILcli` container with NO format change** (the
  container takes arbitrary password BYTES); that key is **WRAPPED per recipient** with
  `wrap_vault_key` → `hybrid_seal_to_container` (X25519 + ML-KEM-768 → AEAD, fresh
  ephemeral entropy per call) into an opaque **`SIGILhyb` envelope** (~1.2 KiB; observed
  1226 B) that sigild relays and cannot read; `unwrap_vault_key` reverses it and
  **rejects any recovered plaintext that is not exactly 32 bytes**. Commands: `device
  hybrid-publish [--key <f>] [--hybrid-key <f>] [--regenerate] [--server <url>]` (creates
  the hybrid identity if absent and PUTs only the PUBLIC half; refuses to silently
  overwrite a secret whose `.pub` is missing), `vault rekey --vault <id> [--file <f>]
  [--publish] [--keyring <f>]` (the one-way password→vault-key door; `--publish` also
  wraps to THIS device and uploads), `vault share --vault <id> --to <deviceID>
  [--permission read|write] [--envelope-out <f>]` (fetch recipient key → wrap → PUT
  envelope → **grant via the EXISTING grant route**, so authz and keys cannot drift),
  `vault accept --vault <id> [--hybrid-key <f>] [--envelope-out <f>] [--for <deviceID>]`
  (`--for` is a DIAGNOSTIC that asks for someone else's envelope so the server's 403 is
  externally testable; it never unwraps), `vault list [--keyring <f>]`. **Local state,
  never uploaded:** the hybrid SECRET identity at `<identity>.hybrid` (default
  `$HOME/.sigil/device.hybrid`, 0600) + `<identity>.hybrid.pub`, and the vault keyring
  `$HOME/.sigil/vault-keys.json` (`VAULT_KEYRING_FILE`, 0600,
  `{"version":1,"keys":{"<vaultID>":"<b64 32B>"}}`). **A vault key is NEVER printed** —
  only `vault_key_fingerprint` (first 16 hex chars of its SHA-256). `sigil totp
  add|list|code|remove|import|export` gained **`--vault-id <id>`** (open with the VAULT
  KEY for `<id>` instead of `SIGIL_PASSWORD`; `--vault <file>` keeps its old meaning, so
  every existing invocation is unchanged) + `--keyring <f>`, and `totp code` gained
  `--at <unix>`. New `CliError::Sharing` carries **no secret bytes**. Proof:
  **`cli/tests/e2e-sharing.sh`** (real sigild + real CLI, three devices, no mocks).
  Dev/localhost/plain-HTTP/UNAUDITED; custom KEM-then-AEAD (NOT RFC 9180 HPKE); the
  SYSTEM is NOT "post-quantum secure"; revocation cannot un-learn an accepted key.
  ⭐ Also **`sigil device safety-number|pins|repin`** and **`sigil vault rotate`** —
  **KEY VERIFICATION + ROTATION** (Phase 50, ADR 0038), the client-side answer to a
  **key-substituting server**. ⚠️ **THE CHOKE POINT is the FETCH:**
  `fetch_hybrid_key_pinned(server, device_id, auth, pins_path)` fetches a hybrid public
  key **and pin-checks it in ONE call**, and **EVERY wrap path (share AND rotate) goes
  through it**; the bare `fetch_hybrid_key` survives only where nothing is wrapped
  (safety-number display, the deliberate re-pin, desktop `check_server`). `check_and_pin`
  compares **decoded RAW bytes of BOTH halves**: unseen ⇒ `PinStatus::FirstSight` (pins,
  proceeds, **warns**); identical ⇒ `Match` (proceeds silently); **DIFFERENT ⇒
  `CliError::PinMismatch`, a HARD STOP** — nothing wrapped, nothing uploaded, **the pin
  store NOT mutated**. **There is NO flag/option/default anywhere that accepts a changed
  key.** Commands: `device safety-number [<deviceID>] [--pair <deviceID>]` (READ-ONLY —
  never pins or re-pins; no arg = this device's own number, works offline; `--pair` is the
  ORDER-INDEPENDENT pairwise number), `device pins [--pins <f>]` (what this client TRUSTS,
  + `pinned_at` and any **re-pin count**), `device repin <deviceID> --yes
  [--safety-number "<digits>"]` (⚠️ the **ONLY** thing that ever replaces a pin — refuses
  without `--yes`, and refuses if the supplied number ≠ what the server is serving RIGHT
  NOW), and `vault rotate --vault <id> --to <deviceID>... [--file <f>] [--keyring <f>]
  [--pins <f>]` → `rotate_vault_key`: load the current key, ⭐ **pin-check EVERY recipient
  FIRST** (a mismatch aborts before ANY local/remote mutation), fresh 32-byte key,
  `reseal_container` (open with old, seal with new — **never inspects the plaintext**),
  write **0600 via temp-file + rename**, `keyring_put` **AFTER** the file is in place,
  wrap+upsert per recipient, then `list_key_envelopes` + `delete_key_envelope` for
  everyone left out. **SAFETY NUMBER:** `hybrid_safety_digest` = `SHA-256("sigil-safety-
  number-v1\n" ‖ u32_be(len(device_id)) ‖ device_id ‖ u32_be(32) ‖ x25519_public_key ‖
  u32_be(1184) ‖ mlkem_encaps_key)`, `render_safety_number` = 6 groups × 5 digits (each =
  5 digest bytes big-endian mod 100000, zero-padded) ≈ 99.6 bits; `pairwise_safety_number`
  sorts the two digests **BYTEWISE** then hashes under `"sigil-safety-number-pair-v1\n"`,
  so both sides see the SAME string. It binds the **device id** and covers **BOTH** key
  halves. ⭐ **MIRRORED — NOT SHARED** with `sigil-wasm/sharing.mjs`; **MUST stay
  byte-identical** (both carry the same KAT `83791 28129 67801 50284 55242 77845`).
  **Local state:** the pin store `$HOME/.sigil/hybrid-pins.json` (`HYBRID_PIN_FILE`,
  `--pins` overrides, else follows `--keyring`'s dir; **0600 in the 0700 dir** via
  `write_secret_file`; `{"version":1,"pins":{"<devID>":{device_id, x25519_public_key,
  mlkem_encaps_key, safety_number, pinned_at, repins}}}`) — PUBLIC key material, but
  **security-critical LOCAL state**: anyone who can rewrite it can silence the alarm.
  ⚠️ **HONEST SCOPE:** pinning **cannot protect FIRST contact** (the safety number can,
  but only if a human actually compares it); a user who blindly re-pins defeats it;
  rotation protects **FUTURE content ONLY** (a device that already unwrapped a key keeps
  what it copied); UNAUDITED.
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
  **Now also AUTHENTICATES as an enrolled device (Phase 44) — the CLIENT half of
  sigild's multi-device auth contract v3 (ADR 0031) for JavaScript.** Three thin-shell
  `#[wasm_bindgen]` exports over sigil-core's classical Ed25519 —
  **`ed25519_public_key(seed)`**, **`ed25519_sign(seed, message)`**,
  **`ed25519_verify(public_key, message, signature)`** — let a browser client hold a
  device identity and sign with the SAME real crypto the CLI uses. The 32-byte seed is a
  **CALLER argument** (JS `crypto.getRandomValues`) and Ed25519 signing is
  deterministic, so **both `libsigil/Cargo.lock` and `sigil-wasm/Cargo.lock` stay
  `getrandom`==0**; an RFC 8032 KAT pins it (Rust tests now **26**). On top of them,
  **`sigil-wasm/device-auth.mjs`** is a framework-free, dependency-free ESM module
  (Node + browser) exporting `generateDeviceSeed` / `devicePublicKey`, `enrollDevice`,
  `signedFetch` / `makeSignedFetch`, `pushContainerAuthed` / `pullContainersAuthed`,
  `grantVaultAccess` / `listVaultGrants`, `revokeSelf` / `revokeDeviceAdmin` /
  `listDevices`, `sealDeviceIdentity` / `openDeviceIdentity`, plus `DeviceAuthError` +
  `explainAuthStatus`. **ALL signing is `wasm.ed25519_sign` — there is NO JS-side
  signing**; the enrollment token digest is `crypto.subtle` SHA-256 (lowercase hex).
  The canonical layouts (`canonicalV3Message` / `canonicalEnrollMessage` /
  `enrollTokenHash`) are **MIRRORED — not shared — from
  `sigild/internal/api/deviceauth.go` (source of truth) and `cli/src/lib.rs`**, so the
  layout now lives in **THREE implementations (Go, Rust, JS) that MUST stay
  byte-identical** — drift does NOT fail loudly, it just 401s every request; the interop
  tests are the guard. **`sync.mjs` was extended ADDITIVELY** with ONE optional
  `opts.fetch` (default `globalThis.fetch`) + an additive `err.status`, so the
  UNAUTHENTICATED path is behaviourally identical (which is why the older interop tests
  still pass). Proven by **`sigil-wasm/test/device-auth-interop.mjs`**, which boots a
  LIVE `sigild` with `SIGILD_DEVICE_AUTH=1` and asserts: unsigned request → 401; device
  A enrolls; the identity round-trips a password-sealed container with **no plaintext
  seed at rest**; A pushes/claims/pulls/opens byte-verbatim; device B enrolled but 403
  on A's vault; after a read grant B pulls but is still 403 on write; an admin revoke
  makes B 401 while A is unaffected; a tampered body and a stale timestamp are both 401;
  a spent enrollment token is 401. Dev / localhost / plain-HTTP / no TLS, UNAUDITED —
  request auth for a DEV op-log, NOT the product account/session/key-management model.
  ADR 0033 (how browser clients store the identity).
  **Now ALSO does DEVICE-TO-DEVICE VAULT SHARING (Phase 48) — the client half of the
  Phase 46 flow (ADR 0035) for JavaScript, so sharing is no longer CLI-only.** A NEW
  framework-free, dependency-free ESM module **`sigil-wasm/sharing.mjs`** (Node +
  browser) exports `generateHybridIdentity` / `hybridPublicIdentity`,
  `publishHybridKey` / `fetchHybridKey`, `generateVaultKey` / `vaultKeyFingerprint`,
  `wrapVaultKey` / `unwrapVaultKey` (which **rejects any recovered plaintext that is
  not exactly 32 bytes**), `putKeyEnvelope` / `getKeyEnvelope`, the two composed
  operations **`shareVault`** (fetch key → wrap → PUT envelope → grant through the
  **EXISTING** `grantVaultAccess`, so authorization and key distribution cannot drift)
  and **`acceptVault`**, plus `explainSharingStatus` (401 vs 403 vs 404/409/413).
  ⚠️ **NO Rust changed** — every wasm export it needs (`hybrid_x25519_public`,
  `hybrid_mlkem_encaps_key`, `hybrid_seal_to_container`, `hybrid_open_container`)
  already existed from Phase 31. It does **NO crypto itself**: the KEM/AEAD happens in
  the wasm and every signature goes through `device-auth.mjs`; ALL entropy (hybrid
  identity, vault key, per-wrap ephemeral X25519 secret + ML-KEM coin + AEAD nonce) is
  `crypto.getRandomValues`, so both `Cargo.lock`s stay `getrandom`==0. Semantics +
  byte layouts are **MIRRORED — not shared — from `cli/src/lib.rs` and
  `sigild/internal/api/sharing.go`** and MUST stay in sync (drift yields a 400/403 or
  an envelope the CLI cannot open). **`device-auth.mjs`'s sealed device-identity
  container was bumped v1→v2** to carry the sharing secrets, and **v2→v3 in Phase 50**
  to carry the hybrid-key **PIN STORE**: `sealDeviceIdentity` /
  `openDeviceIdentity` now round-trip `{version:3, device_id, seed, base_url,
  hybrid:{x25519_secret, mlkem_seed}, vault_keys:{<vaultId>: b64 32 bytes},
  pins:{version, pins:{<devID>:{…}}}}`, with
  `DEVICE_IDENTITY_VERSION = 3` and `SUPPORTED_DEVICE_IDENTITY_VERSIONS = [1,2,3]`;
  **v1 AND v2 containers still open** (→ `hybrid: null` / empty keyring / **EMPTY pin
  store**, i.e. everything is first-sight), so it is backward compatible, and the
  `pins` field is **omitted when empty** so a client that has never shared writes the
  shape it always did (ADR 0036, ADR 0038). ⭐ **The browser clients therefore STILL
  persist ONLY sealed containers** — nothing new goes into `localStorage` /
  `chrome.storage` in the clear. Proven by
  **`sigil-wasm/test/sharing-interop.mjs`** — boots a LIVE `sigild` + builds the REAL
  `sigil` binary and shares **BOTH ways**: (a) JS seals a vault under a random vault
  key, pushes, shares a **1226-byte** envelope → the real CLI accepts, unwraps to the
  SAME fingerprint, pulls and prints **94287082** at T=59 (the RFC 6238 vector);
  (b) CLI shares → JS accepts and both produce **94287082**, and the human password
  does NOT open that vault; an unauthorized third identity is **403** three ways; the
  relayed envelope is byte-identical ciphertext holding no key/seed; two wraps of the
  same key differ; the server logged only fingerprints. Dev / localhost / plain-HTTP,
  UNAUDITED. ADR 0035, ADR 0036.
  **Now ALSO PINS device keys, computes SAFETY NUMBERS and ROTATES vault keys (Phase 50,
  ADR 0038) — the JS half of the key-substitution defense**, in the SAME
  `sigil-wasm/sharing.mjs`: `safetyNumber` / `pairwiseSafetyNumber` /
  `hybridSafetyDigest` / `renderSafetyNumber` (+ `SAFETY_NUMBER_PREFIX` /
  `SAFETY_NUMBER_PAIR_PREFIX` / `SAFETY_NUMBER_GROUPS` / `SAFETY_NUMBER_BYTES_PER_GROUP`),
  `newPinStore` / `requirePinStore` / `checkAndPin` / `repinHybridKey` /
  `HYBRID_PIN_STORE_VERSION`, the ⭐ choke point **`fetchHybridKeyPinned(wasm, auth,
  deviceId, pins = auth.pins)`** (fetch + pin-check in ONE call; **every** wrap path —
  `shareVault` AND `rotateVaultKey` — goes through it), the catchable
  **`KeyPinMismatchError`** (carries `deviceId` + BOTH safety numbers), the transport
  `listKeyEnvelopes` / `deleteKeyEnvelope`, and **`rotateVaultKey`** (pin-check EVERY
  recipient FIRST → fresh key → re-seal → wrap+upsert per recipient → delete every other
  envelope; **returns** the new key + re-sealed container for the CALLER to persist and
  push). The safety-number construction is **MIRRORED — not shared — from
  `cli/src/lib.rs`** and **MUST stay byte-identical** (same KAT on both sides; divergence
  would make two people comparing digits wrongly conclude they were under attack). ⚠️
  **`requirePinStore` FAILS CLOSED** — a missing store **throws** rather than defaulting
  to empty, because the old fallback meant a caller that forgot its pins silently got
  "every key is first-sight", i.e. the control degraded into a no-op. Proven by
  **`sigil-wasm/test/pinning-interop.mjs`** (below). It does **NO crypto itself** (SHA-256
  via `crypto.subtle`, KEM/AEAD in the wasm), so `Cargo.lock`s stay `getrandom`==0.
- `extension/` — **no longer reserved**: a real **Manifest V3 browser extension**
  whose **popup is a multi-account encrypted TOTP vault**, running the libsigil core
  as **WebAssembly inside the extension page** — the **second real product client
  surface** (after `web/apps/webapp`; third over the core counting the demo `cli/`).
  It adds **NO cryptography and NO vault/migration logic of its own**:
  **`extension/build.sh`** (the only build step — there is **no bundler**, the popup
  is plain ESM) runs the repo-root `sigil-wasm/build-wasm.sh` (wasm-pack
  `--target web`) and **vendors** into a **gitignored `extension/vendor/`** the
  wasm-bindgen bindings (`sigil_wasm.js` + `sigil_wasm_bg.wasm` + `.d.ts`) plus
  **verbatim copies** of the proven, framework-free `sigil-wasm/totp-vault.mjs`,
  `totp-migration.mjs`, `sync.mjs`, `device-auth.mjs` and `sharing.mjs` (+ a `BUILD-INFO.txt`
  provenance stamp, so a stale `vendor/` is obvious). The **source** is `manifest.json` + `src/popup/popup.{html,css,js}`
  (UI glue + storage only; `popup.js` imports the vendored wasm via
  `chrome.runtime.getURL("vendor/sigil_wasm_bg.wasm")`). The vault seals into the
  **SAME `SIGILcli` container** the CLI and the webapp use (Argon2id →
  XChaCha20-Poly1305 over the mirrored `TotpVault` JSON), so **vaults stay
  cross-client interoperable** — no new at-rest format. Persistence mirrors the
  webapp (ADR 0028): **`chrome.storage.local` holds ONLY the sealed container**
  (base64, key `sigil.extension.vault.v1`); the plaintext vault and the password are
  **never** persisted, the **password lives only in memory** (closing the popup
  re-locks), so it boots setup / locked / unlocked. Add by form / `otpauth://` /
  **Google Authenticator `otpauth-migration://` import**, **export** back out
  (`otpauth://` or one migration URI, behind a loud secrets-in-the-clear warning),
  remove / lock / forget-vault; **codes + countdowns are computed in the wasm**,
  never in JS; salt+nonce from `crypto.getRandomValues`. **Now ALSO has a dev Sync
  panel and can ENROLL as a device (Phase 44, ADR 0033):** over the vendored
  `sync.mjs` + `device-auth.mjs` it push/pulls the sealed container to a localhost
  sigild — unauthenticated with no identity, or signed under **contract v3** via
  `pushContainerAuthed`/`pullContainersAuthed` once enrolled. **The Ed25519 device seed
  is NEVER stored in plaintext**: sealed into a **SECOND `SIGILcli` container under the
  SAME vault password**, persisted at `chrome.storage.local` key
  **`sigil.extension.device.v1`**; the seed is memory-only while unlocked and the
  single-use enrollment token is cleared right after use. **Now ALSO SHARES vaults
  (Phase 48, ADR 0035/0036) — the SAME full flow as the webapp**: a **Sharing (dev)**
  section in `popup.html` + `popup.js` (publish hybrid key / convert to shared /
  share to a pasted recipient device id with read/write / accept a vault shared to this
  device) over a **vendored `sharing.mjs`** — `build.sh` now copies it beside
  `totp-vault.mjs` / `totp-migration.mjs` / `sync.mjs` / `device-auth.mjs` (it imports
  two of them, so all five must stay siblings). Storage matches the webapp: the sealed
  device-identity container is the **v3 schema** carrying the hybrid secret, the vault
  keyring **and the Phase 50 pin store** beside the seed, so `chrome.storage.local` still
  holds only the two sealed
  containers, and **unlock opens the identity, tries the password, then falls back to
  each held vault key**. **Phase 50 (ADR 0038) added the same key-trust UI as the webapp**
  — safety numbers, a `KeyPinMismatchError` that **BLOCKS** the share and offers a
  deliberate `repinHybridKey`, and `rotateVaultKey` — with `persistDevice({...device,
  pins})` re-sealing the container so pins survive a reload. ⚠️ **`manifest.json` gained
  `"host_permissions": ["http://127.0.0.1/*", "http://localhost/*"]`** — MV3 extension
  pages cannot fetch cross-origin without an explicit host permission; it is
  deliberately **LOOPBACK-ONLY** (with an explanatory comment in the manifest) so the
  build **cannot reach a remote server**. The rest stays **minimal:**
  `"permissions": ["storage"]` and nothing else (no `tabs`, no
  `clipboardWrite`), **no background service worker / content script / options
  page**, and the MV3 CSP widened by exactly one keyword
  (`script-src 'self' 'wasm-unsafe-eval'`); a pinned **public** manifest `key` fixes
  the unpacked extension ID (no private half in this repo, not a signing key) so the
  headless test can address `chrome-extension://<id>/…`. **TEST HOOK:**
  `popup.html?t=<unix-seconds>` pins the clock (stops the 1 s tick) for deterministic
  vectors. Proven GREEN by **`extension/tests/extension.spec.mjs`** — a Playwright
  suite that loads the **REAL unpacked extension** in Chromium
  (`launchPersistentContext`, `channel: "chromium"`; the headless *shell* cannot load
  extensions) and asserts the wasm instantiates in-page → RFC 6238 `287082` at
  `?t=59`, storage holds **only** the sealed container (no plaintext secret / label /
  password), reload → locked → right password restores the vault, and the
  `otpauth://` + migration import/export paths round-trip (3 specs). ⚠️ The new
  enrollment UI is **NOT** Playwright-covered (the protocol is proven live in Node).
  **Dev / UNAUDITED / loaded unpacked / published to NO store**; sync is **loopback
  plain-HTTP only, no TLS**; generate-only (no verification / constant-time compare /
  zeroization); the reserved-stub ambitions (phishing protection, passkey provider,
  content scripts) are **NOT** implemented. Do NOT store real 2FA
  secrets. ADR 0030, ADR 0033.
- `desktop/` — **the NATIVE client column** (fourth client surface, FIRST native
  one): a **Tauri v2** desktop authenticator. **THE ARCHITECTURAL POINT: `sigil-core`
  is a plain NATIVE Rust dependency here — there is NO wasm, `wasm-bindgen` or
  `wasm-pack` anywhere under `desktop/`** (unlike `web/apps/webapp` and `extension/`,
  which run the core as WebAssembly). The core still reads **no clock and no RNG**
  (ADR 0007), so the native app supplies both: **entropy** via `sigil-cli`'s native
  `getrandom` path inside `seal_to_container`, and the **clock** via
  `std::time::SystemTime` (`sigil_desktop_core::now_unix`) passed **into** the core's
  `totp` as a `u64`. **Two crates:** **`sigil-desktop-core`** (`desktop/core`) holds
  **ALL** the authenticator logic **headless** and is `#![forbid(unsafe_code)]` +
  `#![deny(missing_docs)]` — `VaultSession` (`create`/`unlock`/`open_or_create`,
  `with_params`, `entries_at`/`entries_now`, `add_secret_base32`, `add_uri`,
  `import_text`/`import_file`, `remove`, `export_uris`, `export_migration_uri`,
  `save`), the `EntryView`/`ImportSummary` view models, `DesktopError`,
  `default_vault_path`, and the `BANNER_TITLE`/`BANNER_BODY`/`EXPORT_WARNING`
  constants, **plus the whole server-facing half in `desktop/core/src/net.rs`**
  (below); **`sigil-desktop`** (`desktop/src-tauri`) is a **thin shell** — a window,
  an `AppState { session: Mutex<Option<VaultSession>>, sync: Mutex<Option<DeviceConfig>> }`,
  and **twenty-one `#[tauri::command]`s**: the ten offline ones (`status`, `unlock`,
  `lock`, `list`, `add_secret`, `add_uri`, `import`, `remove`, `export_uris`,
  `export_migration`) **plus ELEVEN added in Phase 49** (`unlock_shared`, `set_server`,
  `sync_status`, `enroll`, `publish_hybrid`, `check_server`, `convert_to_shared`,
  `push`, `pull`, `share`, `accept`), each cloning the `DeviceConfig` out of the mutex
  **before** any network call so no lock is held across I/O. `desktop/ui` is framework-free HTML/CSS/JS —
  **no npm, no bundler, no CDN**. The split is deliberate: a GUI can't be clicked by a
  test runner, so all behaviour lives where tests can drive it. **REUSE, NOT
  REIMPLEMENT (the rule for this directory): NO crypto, container format or vault
  schema is defined here.** `sigil-desktop-core` path-depends on `sigil-core` **and on
  the `sigil-cli` LIBRARY target**, taking the `SIGILcli` container
  (`seal_vault`/`open_vault`), the `TotpVault`/`TotpEntry` schema and
  `TotpEntry::code_at`, `base32_decode`, `new_totp_entry`, `totp_algorithm_from_str`,
  `parse_otpauth_uri`/`entry_to_otpauth_uri`, and the Google Authenticator migration
  codec (`decode_migration_uri`/`encode_migration_uri`/`entry_to_migration_otp`/
  `migration_otp_to_entry`) straight from `cli/` — so there is **no fourth at-rest
  format and NO mirrored schema to keep in sync** (unlike the Rust↔JS mirrors of ADRs
  0020/0026), and **nothing under `cli/` was edited**. **SHARED VAULT:** the default
  path is **`$HOME/.sigil/totp-vault.sigil`** — byte-for-byte the CLI's default
  (fallback `./totp-vault.sigil` when `$HOME` is unset) — so the desktop app and
  `sigil totp` literally drive **ONE vault file**; dir `0700`, file `0600`, and
  `save()` writes a temp file then renames so an interrupted save can't truncate a
  good vault. **ONLY the sealed container is persisted**; the password is
  memory-only for the life of a `VaultSession` and **best-effort** zeroed on `Drop`
  (no `zeroize`, no volatile guarantee — documented, not claimed). **Trust boundary:**
  the webview holds **no** key material and does **no** crypto (password crosses the
  IPC once at unlock; codes arrive already computed) and
  `desktop/src-tauri/capabilities/default.json` grants **`core:default` ONLY** (no
  fs/shell/http/dialog plugin), so the frontend reaches disk only through the explicit
  commands; the export commands return `EXPORT_WARNING` **with** the payload so a UI
  can't drop it. Features: create/unlock/lock, live list (issuer/label + code +
  seconds remaining, recomputed ~1/s), add by base32 secret (algorithm/digits/period)
  or `otpauth://` URI, Google Authenticator `otpauth-migration://` import, remove,
  `otpauth://` + combined-migration export behind the loud warning; a pre-audit banner
  is rendered in the window **and** printed to stderr at startup from the same Rust
  constants. **`desktop/` is its OWN cargo workspace with its OWN `desktop/Cargo.lock`**
  (members `core` + `src-tauri`), **deliberately OUTSIDE the `libsigil` workspace**
  exactly like `cli/` and `sigil-wasm/`, so Tauri's platform stack and the transitive
  native `getrandom` can **never** perturb `libsigil/Cargo.lock` (which must stay
  `getrandom`==0). Proven by **`desktop/core/tests/cli_interop.rs`**, which builds the
  **REAL `sigil` binary** and drives it as a subprocess against **ONE shared vault
  file** in **both directions**, plus an RFC 6238 App B KAT in `desktop/core/src/lib.rs`
  (`T=59` → `94287082` at 8 digits / `287082` at 6). ⚠️ The interop test pins the clock
  by using **`period = u32::MAX`** (counter stays 0 until ~2106 ⇒ constant code) for the
  exact cross-process equality assertions — a **deliberate test artifice, NOT product
  behaviour**; an ordinary 30 s account is also checked with a bounded retry.
  **ON THE NETWORK SINCE PHASE 49 (ADR 0037):** `desktop/core/src/net.rs` adds device
  **enrollment**, **contract-v3 signed sync** and **vault sharing**, so all four client
  surfaces (CLI, webapp, MV3 extension, native desktop) are peers. Operations:
  `DeviceConfig` (`new`/`for_server` → state dir defaults to `$HOME/.sigil`) with
  `enroll`, `publish_hybrid`, `push_vault`/`push_vault_file`, `pull_vault`,
  `share_vault`, `accept_vault`, `status`, `check_server`, plus
  `VaultSession::convert_to_shared`/`unlock_shared` and the free `pull_and_adopt`;
  contract v3 when enrolled, legacy v2 when the identity has no device id, unsigned
  with no identity. ⭐ **THE RULE, EXTENDED TO THE PROTOCOL: `net.rs` imports 30
  symbols from the `sigil-cli` LIBRARY** (`enroll_device`, `push_op_auth`/
  `pull_ops_auth`, `publish_hybrid_key`/`fetch_hybrid_key`, `put_key_envelope`/
  `get_key_envelope`, `wrap_vault_key`/`unwrap_vault_key`, `grant_vault_access`,
  `keyring_get`/`keyring_put`, `load_*`/`save_*`, `generate_*`,
  `vault_key_fingerprint`, `RequestAuth`, `DeviceIdentity`, `VaultKeyring`,
  `CliError`, `VAULT_KEYRING_FILE`, `VAULT_KEY_LEN`) — so there is **NO HTTP client,
  NO signing path and NO canonical-message copy anywhere under `desktop/`**
  (grep-verified: zero v3-message/enroll-challenge domain strings, zero `ureq`/
  `reqwest`, zero direct Ed25519). The canonical bytes stay at **THREE**
  implementations (Go server / Rust CLI / JS browser, kept in sync only by interop
  tests); a fourth was deliberately avoided. Only app-level glue was written, because
  the CLI's path-resolution + error-explanation helpers live in `cli/src/main.rs` (the
  **binary**, not importable): `DeviceConfig` re-derives the file names and `net_error`
  maps `CliError` → typed `DesktopError`. **`cli/` was NOT edited.** **State files are
  the CLI's own, hence INTERCHANGEABLE** — `device.key` (Ed25519 seed + device id,
  0600), `device.hybrid` (X25519 secret + ML-KEM seed, 0600), `device.hybrid.pub`
  (public), `vault-keys.json` (vault id → 32-byte key, 0600), in a **0700** state dir;
  point `sigil --key` (or `HOME`) at it and it is the SAME device. Two shapes worth
  remembering: **`status()` is purely LOCAL** (no network, cannot fail because a server
  is down) and reports fingerprints only, while **`check_server` reports reachability
  as DATA** (`ServerCheck{reachable,hybrid_published,detail}`), not an error; and
  **`pull_and_adopt` OPENS the pulled container BEFORE writing** (temp file + rename,
  0600) so an unreadable container can never clobber a good vault. UI errors are tagged
  distinctly: `unauthenticated` (401) / `not authorized` (403) / `route disabled` (501)
  / `nothing there` (404) / `server unreachable` / `not enrolled` / `already enrolled`
  / `not a shared vault`. **NOTHING secret crosses the IPC, is printed or logged** —
  no seed / hybrid secret / vault key / password / enrollment token, only device ids +
  16-hex SHA-256 fingerprints (the only prints are the pre-audit banner); the
  enrollment token is a password-type field used for ONE call and cleared in a
  `finally`. ⚠️ **AT-REST ASYMMETRY: the desktop's secrets are 0600 PLAINTEXT files
  (the native model, same as the CLI) — the BROWSER clients are STRONGER at rest**
  (everything sealed in a `SIGILcli` container, ADR 0036); no zeroization anywhere.
  **The network proof is `desktop/core/tests/server_interop.rs`** — boots a REAL
  `sigild` (`SIGILD_ENABLE_DEV_OPS=1` + `SIGILD_DEVICE_AUTH=1`) on a free loopback port,
  builds the REAL `sigil` binary, and proves **both directions with `94287082`** (RFC
  6238 App B; the clock is pinned by **`period = 1_600_000_000`** so the counter equals
  App B's `T=59` counter from 2020 to 2071), plus the **403** for an enrolled-but-
  unauthorized third device, a clear **NotEnrolled** error instead of a panic, and a
  clear **Unreachable** error with the **offline flow still generating codes**. **Dev /
  UNAUDITED**, **NOT signed, NOT notarized, NOT distributed** (`tauri build` / the
  `.app` bundler was **not** run — the applicable build is `cargo build --release`),
  the **GUI is build-and-launch verified but NOT visually verified** on this machine
  (screencapture denied → no screenshot proof; all behaviour lives in the headless core
  the tests drive), the server side is **dev-gated / loopback / plain HTTP**, and there
  is still **no QR scanning, no code verification, no hardened zeroization**; the
  other native platforms (**mobile especially**) remain unbuilt. **Phase 50 (ADR 0038)
  reached the desktop for free, by the same reuse rule:** `net.rs` calls the library's
  `fetch_hybrid_key_pinned` / `rotate_vault_key` / `repin_hybrid_key` and keeps its pins
  in **the SAME `hybrid-pins.json`** in the same state dir (so a desktop pin and a
  `sigil` pin are ONE record — no second pin store, no second safety-number
  implementation), exposing `DeviceConfig::{peer_safety_number, pairwise_safety_number,
  pins, repin_device, rotate_vault}`; a mismatch is `DesktopError::KeyPinMismatch`, tagged
  across the IPC as **`"key changed"`**.
  ⭐ **Phase 51 made that alarm VISIBLE — it was raised but barely shown.** Before:
  `desktop/src-tauri/src/main.rs` tagged the error `"key changed"` but `desktop/ui/main.js`
  had NO handler and NO re-pin control, so a refused share flashed a 7-second toast — while
  the webapp and the extension both blocked and explained. A control the user cannot see is
  a control they do not have. Now IPC errors cross as a **STRUCTURED value**:
  `type CmdResult<T> = Result<T, IpcError>` where `IpcError { kind, message, key_change? }`;
  `key_change` is populated for **exactly one kind** (`"key changed"`) and carries
  `device_id` + `pinned_safety_number` + `presented_safety_number` — **PUBLIC material only,
  no key bytes and no seed**. `From<String> for IpcError` keeps every existing `?` site
  unchanged. `desktop/ui/{index.html,styles.css,main.js}` gained a `#pin-mismatch`
  `role="alert"` block that **BLOCKS the share and rotate buttons**, prints both safety
  numbers, and offers a `window.confirm`-guarded re-pin sending `expected` = the presented
  number so the native side re-checks it; wording matches the webapp/extension. It is reached
  from the single central `call()` error path, so every command's errors route through it,
  and non-key-change errors still toast exactly as before. ⚠️ **The REFUSAL itself did not
  change — only its visibility.** ⚠️ **Premise correction:** the audit finding that prompted
  this ALSO claimed the desktop did not surface safety-number / pinned-key views; that clause
  was WRONG — those views already existed and were NOT added. **The raising path also gained
  its first regression test:** `desktop/core/tests/server_interop.rs`
  `a_substituted_hybrid_key_raises_the_alarm_the_desktop_ui_renders` (the desktop was the
  ONLY client whose key-substitution defence had no test; the browser side is covered by
  `sigil-wasm/test/pinning-interop.mjs`). It boots a real sigild + the real `sigil` CLI, has
  the CLI publish K1, shares (which PINS K1), then runs `sigil device hybrid-publish
  --regenerate` so the SAME device id presents a DIFFERENT key — exactly what a hostile
  server does, and deliberately indistinguishable from a legitimate re-enrolment — then
  asserts the share is refused as `DesktopError::KeyPinMismatch` (not a generic error)
  carrying both numbers in the 6-groups-of-5-digits shape the UI prints, that rotation is
  refused too, that a re-pin to a WRONG number is refused and leaves the old pin standing,
  and that only a deliberate re-pin to the presented number lets sharing resume.
  MUTATION-TESTED: with the pin check in `cli/src/lib.rs` neutered to fail open it fails with
  *"SHARED TO A SUBSTITUTED KEY — the pin check did not fire"*.
  ⚠️ **A latent harness bug that new test exposed:** `Harness::start()` built its temp dir
  from pid + `now_unix()` in **SECONDS**, and `cargo` runs the tests in that file in PARALLEL
  threads of ONE process — so two harnesses starting in the same second got the SAME path and
  the second one's `remove_dir_all` deleted the first one's state, surfacing as a baffling
  "No such file or directory" in the OTHER test. Fixed with an `AtomicUsize` counter in the
  directory name. Do NOT store real 2FA
  secrets. ADR 0032, ADR 0037, ADR 0038.
- `web/apps/admin` — reserved. (`web/apps/webapp` + `web/packages/sigil-wasm`,
  `extension/` and `desktop/` are now real — see above.)

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

# Device-to-device vault sharing — the Phase 46 end-to-end proof (ADR 0035). Builds
# the REAL sigild + the REAL sigil CLI, boots sigild on a free loopback port with
# dev-ops + device auth v3, enrolls THREE devices with separate HOMEs, and asserts
# the positive path (two devices, same RFC 6238 code), the zero-knowledge check
# (returned bytes == uploaded bytes, no seed in the envelope, no envelope in the
# logs) and the negative paths (403 for an unauthorized device, 401 for a revoked
# one). Torn down on exit; nothing is exposed.
./cli/tests/e2e-sharing.sh                        # prints PASS
# Optional: run the identical proof against the durable Postgres backend (also
# exercises migration 0004): SIGILD_OPLOG_POSTGRES=<dsn> ./cli/tests/e2e-sharing.sh

# sigil-wasm — separate crate, wasm-bindgen binding over the core. Native fmt/
# clippy/test exercise the *_inner helpers (26 tests); build-wasm.sh emits
# pkg-web/pkg-node (needs wasm-pack); then the NINE Node tests below must all PASS.
cargo fmt   --manifest-path sigil-wasm/Cargo.toml --all -- --check
cargo clippy --manifest-path sigil-wasm/Cargo.toml --all-targets -- -D warnings
cargo test  --manifest-path sigil-wasm/Cargo.toml
./sigil-wasm/build-wasm.sh                          # → pkg-web/ + pkg-node/ (gitignored)
node sigil-wasm/test/roundtrip.mjs                  # 1/9 seal/open in a JS runtime; prints PASS, exits 0
node sigil-wasm/test/interop.mjs                    # 2/9 wasm<->CLI SIGILcli interop (builds the real CLI, both directions); PASS
node sigil-wasm/test/hybrid-interop.mjs             # 3/9 wasm<->CLI SIGILhyb hybrid public-key interop (builds the real CLI, both directions); PASS
node sigil-wasm/test/sync-interop.mjs               # 4/9 wasm<->CLI opaque op-log sync (live sigild + real CLI, both directions); PASS
node sigil-wasm/test/totp-interop.mjs               # 5/9 cross-client TOTP: CLI adds -> op-log -> browser code == RFC vector (wasm KAT + live sigild); PASS
node sigil-wasm/test/migration-interop.mjs          # 6/9 CLI<->JS TOTP migration codec agreement (GOLDEN + RUST->JS + JS->RUST; builds the real CLI); PASS
node sigil-wasm/test/device-auth-interop.mjs        # 7/9 JS client vs LIVE sigild with SIGILD_DEVICE_AUTH=1: enroll, sealed identity, claim/grant/revoke, tamper/stale/token-reuse; PASS
node sigil-wasm/test/sharing-interop.mjs            # 8/9 cross-client VAULT SHARING both ways (live sigild + real CLI): JS shares -> CLI accepts -> 94287082; CLI shares -> JS accepts -> 94287082; 403 negatives; PASS
node sigil-wasm/test/pinning-interop.mjs            # 9/9 KEY PINNING vs a SIMULATED MALICIOUS SERVER (a rewriting proxy in front of a live sigild swaps B's hybrid public key): CLI REFUSES + the stored envelope stays byte-identical and does NOT open with the attacker's secret; Rust<->JS safety numbers agree (per-device + order-independent pairwise + the shared KAT); rotation makes new content unreadable to the removed device while C still reads it; repin refuses without --yes and with a WRONG safety number; PASS
grep -c 'name = "getrandom"' sigil-wasm/Cargo.lock  # must ALSO be 0 (JS supplies entropy)

# Go server — fmt / vet / test / build
go=/opt/homebrew/bin/go
gofmt -l sigild            # must print nothing
$go -C sigild vet ./...
$go -C sigild test -race ./...   # -race is the gate; CI (sigild.yml) runs -race too since Phase 51
$go -C sigild build ./...

# sigild container (multi-stage → distroless, ~14 MB) — needs the Docker daemon
docker build --build-arg VERSION=$(git rev-parse --short HEAD) -t sigild:dev sigild

# Web — typecheck / lint / build (NEXT_TELEMETRY_DISABLED=1)
# NOTE: the root web scripts filter to MARKETING ONLY, so this stays Rust-free
# (marketing is the only surface in the default web CI build).
corepack pnpm -C web typecheck
corepack pnpm -C web lint
corepack pnpm -C web build

# webapp + @sigil/wasm — the wasm client surface. NOT in the default web scripts
# above; it needs the Rust + wasm-pack toolchain (build.sh compiles the repo-root
# sigil-wasm crate and does the target_features/externref strip). Build the wasm
# package first (webapp's own `prebuild` also runs it), then the app:
corepack pnpm --filter @sigil/wasm build        # -> web/packages/sigil-wasm/pkg (gitignored)
corepack pnpm --filter webapp typecheck
corepack pnpm --filter webapp lint
corepack pnpm --filter webapp build             # ONE benign warning: "async/await … asyncWebAssembly"
corepack pnpm --filter webapp exec playwright test   # headless chromium: 8 specs (wasm + offline + a11y), PASS

# extension — the MV3 popup authenticator. A STANDALONE pnpm project (NOT part of
# the web/ workspace), one devDependency (@playwright/test). It needs the Rust +
# wasm-pack toolchain: build.sh runs sigil-wasm/build-wasm.sh and vendors the wasm
# + the proven JS helpers into extension/vendor/ (gitignored — must exist before
# the extension can be loaded unpacked or tested). NOT wired into CI.
corepack pnpm -C extension install
./extension/build.sh                          # -> extension/vendor/ (gitignored)
corepack pnpm -C extension test               # `pretest` re-runs build.sh; 3 Playwright specs, PASS
# The suite loads the REAL unpacked extension in a full Chromium (channel:
# "chromium" — the headless SHELL cannot load extensions) and drives
# chrome-extension://<pinned-id>/src/popup/popup.html?t=59.
# Load it by hand: chrome://extensions -> Developer mode -> Load unpacked -> extension/

# desktop — the NATIVE Tauri v2 authenticator. Its OWN cargo workspace with its own
# desktop/Cargo.lock, INTENTIONALLY OUTSIDE the libsigil workspace (like cli/ and
# sigil-wasm/) so Tauri's platform stack + the transitive native getrandom can never
# perturb the wasm-pure core lockfile. NO wasm toolchain is involved here.
cargo fmt   --manifest-path desktop/Cargo.toml --all -- --check
cargo clippy --manifest-path desktop/Cargo.toml --all-targets -- -D warnings
cargo test  --manifest-path desktop/Cargo.toml   # 15 unit tests + 3 integration tests (2 files)
grep -c 'name = "getrandom"' libsigil/Cargo.lock # must STILL be 0 after desktop work
# Integration test 1 is THE VAULT INTEROP PROOF (desktop/core/tests/cli_interop.rs): it
# builds the real `sigil` binary itself and drives it against ONE shared vault file in
# both directions, so it needs no setup (~20 s: real Argon2id + a CLI build).
cargo test  --manifest-path desktop/Cargo.toml --test cli_interop -- --nocapture
# Integration test file 2 is THE NETWORK PROOF (desktop/core/tests/server_interop.rs) and
# now holds TWO tests: it builds a REAL sigild (go build ./cmd/server; GO=… overrides
# /opt/homebrew/bin/go) AND the real `sigil` binary, boots sigild on a free loopback port
# with dev ops + device auth v3, and proves (a) desktop<->CLI sharing BOTH ways (94287082
# each way) plus the 403 / NotEnrolled / Unreachable negatives, and (b) Phase 51's
# KEY-SUBSTITUTION ALARM: a device republishes a DIFFERENT hybrid key under the SAME id
# (`sigil device hybrid-publish --regenerate`), the share is refused as
# DesktopError::KeyPinMismatch carrying BOTH safety numbers, rotation is refused too, a
# re-pin to a WRONG number is refused, and only a deliberate re-pin resumes sharing.
# No setup, no mocks (~40 s). The two tests run in PARALLEL threads of one process, which
# is why Harness::start() now puts an AtomicUsize counter in its temp-dir name.
cargo test  --manifest-path desktop/Cargo.toml --test server_interop -- --nocapture
# The applicable build is cargo --release; `tauri build` (the .app bundler) has NOT
# been run, and the binary is unsigned / unnotarized / undistributed.
cargo build --manifest-path desktop/Cargo.toml --release   # -> ~8.6 MB native binary
./desktop/target/release/sigil-desktop                     # opens the window (needs a GUI session)
```

**Always run the relevant suite after changes and record the result in
`journal.md`.** CI mirrors these in `.github/workflows/` — **except**
`publish-sigild.yml`, which is deliberately **not** a mirror: it is
`workflow_dispatch`-only (no `push`/`pull_request` trigger) so nothing builds or
publishes automatically while in stealth.

**Every surface, and the cross-surface interop suite, now has a CI job.** The full
list of `.github/workflows/` (ten files):

- **`libsigil.yml`** — the core workspace: rustfmt / clippy `-D warnings` / `cargo test
  --all` / the `wasm32-unknown-unknown` build of `sigil-core`.
- **`cli.yml`** — mirrors it for the standalone `cli/` crate: rustfmt / clippy / test /
  build. ⚠️ **Neither of these two runs the `getrandom`==0 lockfile guard** — that check
  lives only in **`desktop.yml`** and **`interop.yml`**. Coverage still exists (a `cli/**`
  or `libsigil/**` change triggers `interop.yml`, which asserts `getrandom`==0 for BOTH
  `libsigil/Cargo.lock` and `sigil-wasm/Cargo.lock`), but do not assume the crate's own
  job checks it — run the `grep -c 'name = "getrandom"'` command locally, as the Build &
  test block above says.
- **`sigild.yml`** — gofmt/vet/**`go test -race ./...`**/build, with a Postgres service
  container (`SIGILD_TEST_POSTGRES`) so the integration tests run rather than skip.
  ⚠️ `-race` since Phase 51: the local gate always ran `-race`, so CI was the WEAKER of
  the two on a concurrent server whose op-log, nonce cache, rate limiter and subscription
  store are all shared mutable state with concurrency tests aimed at them.
- **`web.yml`** — a Rust-free `build` job for marketing **plus** a `webapp` job carrying
  the Rust + wasm-pack toolchain (`@sigil/wasm` build + the Playwright suite).
- **`extension.yml`** — Rust + wasm toolchain → `extension/build.sh`, then the
  real-extension Playwright run in chromium.
- **`desktop.yml`** — Rust + Tauri's Linux WebKitGTK system libs → fmt/clippy/test incl.
  the desktop↔CLI vault interop test, a release build, and a re-check that
  `libsigil/Cargo.lock` stays `getrandom`-free.
- **`interop.yml`** (added in commit `5735f80`; **second job added in Phase 51**) — **the
  cross-component suite, which until it existed ran in NO workflow at all.** Job 1
  (`interop`) carries all three toolchains at once (Rust + wasm32 + `wasm-pack` /
  `wasm-bindgen-cli@0.2.100`, Go, Node 22), runs the **`sigil-wasm` crate's own
  fmt/clippy/test** — which had no CI gate either, and which includes the golden
  `SIGILcli` / `SIGILhyb` header tests guarding the constants that MUST stay
  byte-identical with `cli/src/lib.rs` — builds the bindings and the real `sigil`
  binary, runs **all NINE Node interop tests** (roundtrip, interop, hybrid-interop,
  sync-interop, totp-interop, migration-interop, device-auth-interop, sharing-interop,
  pinning-interop), and re-asserts `getrandom`==0 in both lockfiles. Job 2
  (`e2e-sharing`, Phase 51) runs **`cli/tests/e2e-sharing.sh`** — the tenth
  cross-component proof and the only shell one, which was in the same position: run by
  nothing. It needs Go + Rust + bash + curl + python3 and no wasm, so it is a separate,
  parallel job. `e2e-sharing.sh` now resolves its Go as `$GO` → Homebrew → PATH (it
  hardcoded the macOS Homebrew path), and the job sets `GO: go`.
- **`security.yml`** — gitleaks (full history) + govulncheck + **cargo-audit across a
  matrix of ALL FOUR Rust workspaces** (`libsigil`, `cli`, `sigil-wasm`, `desktop`;
  Phase 51 — it audited `libsigil` only, which says nothing about the other three, and
  `desktop/` pulls the whole Tauri tree, by far the largest dependency surface here).
- **`release.yml`** — `workflow_dispatch`-only **and** deliberately **inert** (`if: false`
  on its job); cosign/SLSA signing deferred. It builds and publishes nothing.
- **`publish-sigild.yml`** — the manual, human-gated GHCR publish (see above).

⚠️ Like the repo's other CI mirrors, the `webapp`/`extension`/`desktop`/`interop`/
`security` jobs are **validated locally only** (YAML-parsed; each step mirrors a
known-green local command) — they have **not** been run on real GitHub Actions from
this machine, and the Tauri Linux system-dependency list in `desktop.yml` is by-eye
because the dev machine is macOS.
✅ **The "desktop CI cannot find Go" gap is CLOSED** (it was closed inside Phase 49 itself,
after the journal entry that flagged it — this note was stale until Phase 51 corrected it).
`desktop.yml` installs Go with `actions/setup-go@v5`, and `server_interop.rs`'s
`resolve_go()` resolves **`$GO` → `go` on PATH → `/opt/homebrew/bin/go`**, and **PANICS
rather than skipping** when Go is genuinely absent (a suite that silently skips reads green
while proving nothing — a failure mode this repo has already been bitten by). `desktop.yml`
still runs a bare `cargo test`, which now picks up **both** `server_interop` tests; that is
intended. `desktop.yml` was **not** modified in Phase 51 (only `sigild.yml`, `security.yml`
and `interop.yml` were). The separate `$GO` → Homebrew → PATH resolver added in Phase 51 is
in **`cli/tests/e2e-sharing.sh`**, which had the macOS Homebrew path hardcoded.

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
