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

- `libsigil/` — Rust crypto core.
  ⭐ **Phase 59 (ADR 0047) added the two rules that make an UNAUTHENTICATED container
  header safe to read, and both live HERE so nothing mirrors them.** A `SIGILcli`
  header's Argon2id work factors are *inputs* to the KDF, so they cannot be inside the
  AEAD — they are whatever the writer of the bytes chose, and Argon2id **allocates
  `m_cost` KiB in ONE block before doing any work**. Measured (macOS arm64, 24 GB RAM,
  `argon2` 0.5.3): `m_cost = 0xFFFF_FFF0` (≈4 TiB) ran **12.57 s**, peaked at a
  **≈90 GB memory footprint** and the process was **KILLED**; `t_cost = 0xFFFF_FFF0`
  allocates nothing and extrapolates to **≈282 days** for ONE open attempt (1 000
  passes at m=19456 measured 5.68 s). ⛔ **The delivery path is the zero-knowledge
  op-log, which BY DESIGN cannot inspect or filter what it relays** — so the property
  that makes the server safe is the property that stops it defending anyone here, and
  the refusal HAS to be client-side. **(1) A CEILING** in `kdf.rs`:
  **`Argon2Params::MAX_M_COST` = 262_144 KiB (256 MiB)**, **`MAX_T_COST` = 16**,
  **`MAX_P_COST` = 16** (all **INCLUSIVE**), a `const fn validate()`, and a new
  **`KdfError::ParamsTooLarge`** — deliberately DISTINCT from `InvalidParams`, because
  the values may be legal Argon2 parameters and are refused for what honouring them
  would cost. `derive_master_key` validates FIRST THING; both container parsers
  (`sigil_cli::open_container`, the wasm `open_container_inner`) validate EARLIER STILL
  so the error reads *"this container is hostile"* (`CliError::ParamsOutOfRange`) and
  not *"the KDF failed"*. Measured after: the real `sigil` binary refuses the same 4 TiB
  container in **0.00 s / 1.18 MB peak footprint**. 256 MiB was chosen so that **nothing
  that opens today stops opening** (4× `RECOMMENDED`'s 64 MiB, ≈13× the browsers'
  19 MiB), there is headroom to raise the work factor without a format break, it is
  above OWASP's highest current Argon2id recommendation, and ⭐ **a LOW-END PHONE can
  still survive one such allocation** — the bound is chosen for the weakest client that
  must open the vault, not a dev laptop. Bounded worst case (256 MiB × 16 × 16) measured
  **1.64 s**. ⭐ **A ceiling ONLY — no floor**: a low work factor is a WEAK container,
  not a DANGEROUS one, and refusing it would destroy data rather than protect it.
  **(2) THE NO-DOWNGRADE RATCHET**, `Argon2Params::no_downgrade(self, requested)` — the
  componentwise MAX with Argon2's `m_cost >= 8 * p_cost` floor honoured. ⚠️ **This is
  the ONE implementation**: `sigil_cli::no_downgrade` delegates, `reseal_container`
  applies it (so its `params` is a **FLOOR**, not an instruction), and JS reaches the
  same function through the wasm exports `container_params` / `reseal_params`. **A
  mirrored copy would be the wrong answer here specifically, because a drift downward is
  INVISIBLE** — it yields a container that still opens everywhere, just weaker.
  ⚠️ **HONEST LIMITS:** the ceiling **removes nothing** (a hostile blob stays in the
  op-log; there is no delete-op route and no quarantine, so every client re-parses and
  re-refuses it every sync — only the COST of the refusal changed); the ratchet makes a
  bounded cost **PERSISTENT** (a container accepted at exactly 256 MiB/16/16 keeps that
  1.64 s forever — the rule is a maximum, never a reset); and ⛔ **the ratchet does NOT
  cover every write** — `sigil totp …` saves through
  `save_vault(…, Argon2Params::RECOMMENDED)` and the desktop through
  `seal_vault(…, self.params)`, **neither of which reads the existing container**, so
  *"strength only goes up"* is true of the BROWSERS and of RE-KEYS and **not globally
  true of this system** (harmless today only because `RECOMMENDED` 64 MiB IS the
  strongest thing anything here writes).
  (`core` = suite registry + envelope codec +
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
  **The core also carries the **RECOVERY-KIT codec + derivation** (`recovery.rs`, Phase 54,
  ADR 0042): `encode_recovery_kit`/`decode_recovery_kit`/`format_recovery_kit`/
  `derive_recovery_keys` + `RecoveryKeys`/`RecoveryError`. FORMAT: 32-byte seed;
  `check = SHA-256("sigil-recovery-kit-v1\n" ‖ [0x01] ‖ seed)[0..2]`;
  `body = [0x01] ‖ seed(32) ‖ check(2)` = **35 bytes = 280 bits**; **Crockford base32** ⇒
  **exactly 56 characters, NO padding** (280/5 divides), printed as **7 groups of 8**.
  Crockford (no `I`/`L`/`O`/`U`) folds `O`→`0` and `I`/`L`→`1`, and ⚠️ **`U` is REJECTED,
  never folded** (folding it would let two distinct strings decode to the same value).
  ⭐ **DECODE ORDER IS CONTRACTUAL: length → alphabet → CHECKSUM → version** — the checksum
  COVERS the version byte and is checked first, so a flipped version bit reports *"not a
  valid code"* rather than *"unsupported version"* (a human holding paper must be told to
  check their typing). It is a **NEW codec** and deliberately does **NOT** touch the RFC 4648
  `base32_decode` used by TOTP (that one must stay `otpauth://`-interoperable).
  DERIVATION: **HKDF-SHA256 only** — `PRK = HKDF-Extract(salt="sigil-recovery-kit-v1",
  ikm=seed)` (⚠️ salt has NO trailing newline; the checksum domain DOES), then Expand to
  `"…/ed25519-device-seed"` (32) · `"…/x25519-secret"` (32) · `"…/mlkem-keygen-seed"` (64,
  `d‖z`), fed to the EXISTING deterministic `public_key_from_seed` / `x25519_public_key` /
  `ml_kem768_keygen`. ⭐ **ADR 0007 is what makes this possible** — the core reads no RNG, so
  a paper secret is just another entropy source and NOTHING in the core changed to
  accommodate recovery. **NO new dependency** (`hkdf` + `sha2` were already direct).
  **HKDF and NOT Argon2id, deliberately:** the input is 256 bits of CSPRNG, already uniform
  — there is no low-entropy password to stretch, only domain separation to provide.
  `RecoveryKeys`'s `Debug` prints `RecoveryKeys { <redacted> }`.**
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
  reads never claim (403 on an unowned vault); only the owner may grant.
  ⭐ **AND A REJECTED WRITE NEVER CLAIMS (Phase 57, ADR 0045).** The claim fired inside
  authorization, which runs BEFORE a handler's cheap shape checks, so a request the server
  was about to REJECT still took the vault: **50 empty-bodied appends across 50 made-up
  vault ids → 50× 400, 0 stored ops, 50 CLAIMS**, and a second device was then permanently
  403 on its own genuine first write. The per-vault rate limiter cannot bound it — it keys
  on the vault id the attacker varies, and vault ids are LOW-ENTROPY AND HUMAN-CHOSEN (the
  webapp defaults to the literal `"webapp-demo"`). Fix: a **`claimPrecondition`** +
  **`authorizeOpsWrite`** (`deviceauth.go`) evaluate a cheap, VAULT-INDEPENDENT predicate
  and downgrade `needWrite` → `needWriteNoClaim` when the request is going to be rejected,
  so it can never reach `ClaimVault`. Applied to `opsAppend` (empty body) and
  `keyEnvelopePut` (empty body / unknown recipient / revoked recipient, factored into
  `checkKeyEnvelopePut` and memoised so the verdict cannot drift from the response).
  ⚠️ **DELIBERATE BEHAVIOUR CHANGE:** an empty/malformed write to an **UNOWNED** vault now
  answers **403** (no grant, no ownership earned) instead of 400 — on a vault the caller may
  already write it still answers 400/404/409 exactly as before. ⚠️ **HONEST RESIDUAL:** a
  determined device can still squat ids with genuinely well-formed writes; **there is no
  per-account claim budget**, only a code comment naming it as the real bound.
  **401 = unauthenticated, 403 = authorized-not-permitted**, but the client body is only
  `{"error":"unauthorized"}` / `{"error":"forbidden"}` — the typed reason
  (`unknown_device`/`revoked_device`/`unauthorized_vault`/`not_vault_owner`/
  `forbidden_device`/`bad_admin_token`/`bad_proof`/`enrollment_token_used`/… ) goes ONLY to
  the audit log + metrics, so **there is no auth oracle**. ⚠️ **`/metrics` carries a NARROWER
  label set than the audit log (Phase 57):** `forbidden_account` (vault exists, other
  account) is **collapsed onto `unauthorized_vault`** by `authDenyMetricReason`, because the
  two are byte-identical to a client while the METRIC delta answered *"does this vault id
  exist?"* on an always-on unauthenticated surface. `not_vault_owner` / `forbidden_device`
  (the caller's own relationship to a resource it already reached) and
  `vault_owner_unresolved` (a repair state an operator must see) are deliberately kept —
  a narrowing, not a closure. Optional
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
  store; enrollment nonces are prefix-separated in the shared namespace); ~~**revoking a
  vault's owner ORPHANS the vault**~~ ⚠️ **RETIRED at the device level by Phase 52** —
  ownership belongs to an **ACCOUNT** and siblings inherit it, so revoking a vault's
  claimant no longer strands it (losing **every** device in an account still does,
  permanently — see the account bullet below); the **in-memory registry is
  non-durable** (a spent token becomes reusable after restart — warned at boot) and the
  **file backend was NOT extended** (device auth + `SIGILD_OPLOG_DIR` falls back to the
  in-memory registry, warned at boot); and it is still **dev-gated, pre-audit, UNAUDITED** —
  ⚠️ **TOFU is no longer "not an account model"** (Phase 52 added one; it is auth metadata,
  **not an identity system**, and TOFW simply moved up one level), but there is still no
  session/token issuance and no device-key rotation. **Enrollment CAN now be rate limited**
  (Phase 53, opt-in — but a **BACKSTOP, not a defence**; see the abuse-bounds bullet below)
  and **recovery now exists only as a PAPER KIT PRINTED IN ADVANCE** (Phase 54, ADR 0042).
  Contract in [`docs/api.md`](docs/api.md); ADR 0031 (+ a Phase 53 addendum), and
  **ADR 0040** (which revises limitations 1 and 4).
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
  reuse the **device-auth v3** choke point (`authenticateDevice`) and the **subject is
  SERVER-DERIVED, never a body field** (⚠️ since Phase 52 it is the authenticated device's
  **ACCOUNT ID** — `dev.AccountID` — not the device; a device with no account is a coarse
  403 before the provider or store is touched, and a provider-echoed **pre-0005 DEVICE
  subject** is *resolved* onto an account or **blanked**, never trusted to invent a row);
  `POST /v1/billing/webhook/{provider}` is
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
  confidence; ⚠️ **the subject is an ACCOUNT since Phase 52 (ADR 0040), not a device — but
  an account is NOT an identity** (no email/password/recovery), and every pre-`0005` device
  was adopted into its OWN singleton account, so an existing two-device customer has TWO
  billing subjects; recurring
  subscription CREATION is unimplemented for the India adapters (one-time hosted page; their
  webhook sides do map subscription/mandate events); entitlement enforcement now EXISTS but
  is **opt-in, write-only and never refuses reads** (Phase 55, ADR 0043); no
  fraud/chargeback/refund/proration/tax/dunning; **no PCI attestation**; the in-memory store
  is non-durable (a redelivery across a restart could double-apply); ⛔ **NO rate limit on
  the webhook route, DELIBERATELY — the one built in Phase 53 was REMOVED after it was
  reproduced shedding genuine signed deliveries** (ADR 0041); and **billing living inside
  `sigild` is PROVISIONAL** — a scaffold placement,
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
- `sigild/` **THE ACCOUNT MODEL (Phase 52, ADR 0040) — an ACCOUNT is now the subject of
  ENTITLEMENT and the OWNER of vaults**, in `internal/api/accounts.go` +
  `internal/store/accounts.go` + `postgresaccounts.go` + `adopt.go`. **WHY:** a DEVICE was
  the only subject, and two verified defects followed — `billing.go` set `Subject: dev.ID`
  so a customer who paid on their phone was **NOT entitled on their laptop**, and vault
  ownership was trust-on-first-write by DEVICE so **revoking a vault's owner ORPHANED the
  vault** (a limitation this repo recorded in ADR 0031, CLAUDE.md and the threat model).
  **THE MODEL IN ONE SENTENCE:** an account is a **server-assigned id on the device row**
  (`acct_` + b64url of 16 CSPRNG bytes); a **single-use INVITE** minted by a member device
  is the only way a second device joins; and ⭐ **NO REQUEST ANYWHERE NAMES AN ACCOUNT** —
  it is always `dev.AccountID` taken from the verified signature, which is the
  **structural** closure of every cross-account IDOR (there is nowhere to put an id, so
  such a request is unconstructible, not merely rejected). ⭐ **THE KEY DESIGN CHOICE: an
  invite rides the EXISTING `X-Sigil-Enroll-Token` header under the EXISTING
  `canonicalEnrollMessage`**, because that challenge already binds the token DIGEST and
  therefore already binds WHICH credential is in play — so there is **NO fourth canonical
  message and NO new Go/Rust/JS mirror** (still THREE), and **today's shipped clients can
  already join** (`sigil device enroll --token <invite>`; the browsers paste it into their
  existing enrollment-token field). A dedicated `sigil-account-join-v1` domain was
  considered and **REJECTED**: clearer, zero extra security, one more silent-drift surface.
  Classification happens **at the atomic write, not on the unauthenticated path** —
  enroll step 5 only asks "is this digest a configured OPERATOR token?", with **no early
  return and no invite lookup** (a DB round trip + a timing side channel on invite-hash
  existence); an **operator token ALWAYS founds a NEW account**, anything else is resolved
  as an invite at step 8. **Invites are single-SUCCESS** (redeem + insert are ONE atomic
  op) while operator tokens stay **single-ATTEMPT**. **FOUR ROUTES** (dev-gated, `501` by
  default with their OWN stub text, never 404; all reuse `authenticateDevice` verbatim):
  **`GET /v1/account`**, **`POST /v1/account/invites`**, **`GET /v1/account/invites`**,
  **`POST /v1/account/invites/{inviteID}/revoke`**. **OWNERSHIP:** `sigil_vault_owners`
  (`vault_id` PK → `account_id`) is the authority; TOFW **moved up one level** (first
  ACCOUNT to write an unclaimed vault owns it); **every sibling device has full access
  with NO grant row**; **`needOwner` is satisfied ONLY by account ownership** (a legacy
  `is_owner` grant NEVER satisfies it, though the flag is retained as the per-device VIEW
  so `GET …/grants` stays byte-identical — it gains an additive `owner_account_id`); a
  cross-account share is still a per-DEVICE grant (envelopes are addressed to a device).
  **REVOCATION gained a third path:** a member may revoke a **SIBLING** — and an unknown
  device and a foreign one both answer **403, never 404** (only the admin path keeps 404).
  **ENV** (validated fail-fast before the listener binds; out-of-range is an ERROR, never
  a clamp): **`SIGILD_ACCOUNT_MAX_DEVICES`** (default 10, `[1,1000]`),
  **`SIGILD_ACCOUNT_MAX_INVITES`** (default 5, `[1,100]`), **`SIGILD_ACCOUNT_INVITE_TTL`**
  (default 15m, `(0,24h]`). ⚠️ **There is deliberately NO `SIGILD_ACCOUNTS` switch** —
  accounts ride `SIGILD_DEVICE_AUTH` (a binary able to run either ownership model would
  have TWO ownership truths at once); setting any of the three WITHOUT device auth is a
  **BOOT ERROR**. **STORAGE:** migration **`0005_accounts.sql`** (0001–0004 untouched) adds
  `sigil_accounts` / `sigil_devices.account_id` (**deliberately NULLABLE**, so a rolled-back
  pre-0005 binary can still enroll) / `sigil_account_invites` (PK = the lowercase-hex
  **SHA-256 digest**; the secret is returned ONCE and never stored/logged/re-served; a
  separate PUBLIC `inv_` handle exists for listing + revocation) / `sigil_vault_owners`,
  plus an **adoption backfill** ⇒ **`sigild_schema_version` now reports 5**. **METRICS:**
  `sigild_accounts_created_total`, `sigild_account_invites_created_total`,
  `sigild_account_invites_revoked_total`, `sigild_account_joins_total` (counts only, **no
  id label ever**), one new enroll-deny label `account_full`, and three new auth-deny
  labels `missing_account`/`forbidden_account`/`vault_owner_unresolved`. **AUDIT:**
  `account.created`, `account.device_joined` (names the **inviter** — visibility, not
  prevention), `account.invite_created`, `account.invite_revoked`; `device.enrolled` /
  `device.revoked` / `vault.claimed` gain `account_id`; `device.enroll_denied` gains a
  fine-grained `invite_reason` that is **audit-log-ONLY** (never a body, never a metric
  label — every invite failure collapses onto an EXISTING coarse reason, so `/metrics`
  gains no oracle). **CLI:** `sigil account status | invite [--ttl N] [--pin-key <b64>] |
  invites | revoke-invite <inviteID>` — **no join subcommand**, by design.
  ⚠️ **FOUR THINGS THE FIX ROUND CHANGED — document the OUTCOME, not the first cut:**
  **(1) SEATS COUNT ACTIVE DEVICES ONLY** in all four sites; `device_count` on
  `GET /v1/account` **CHANGED MEANING** (active only) and a new **`revoked_device_count`**
  reports the rest, while `devices[]` still lists both. Counting revoked rows made the cap
  a **LIFETIME** limit that no operation could reverse, bricking an account under exactly
  the "revoke and re-enroll" remedy this model prescribes — and it was reachable as an
  attack. **(2) A device with NO account is 403, NOT 500** (`missing_account`) — a NULL
  account is a data state the server can see, not a fault; the body is byte-identical to
  every other 403 so no oracle appears. A new reason `vault_owner_unresolved` joined the
  same closed set. **(3) NEW OPERATOR COMMAND `sigild migrate adopt`** — re-runs 0005's
  backfill (mint `acct_mig_<device_id>` accounts for NULL-account devices, record ownership
  for vaults holding a legacy `is_owner` grant, re-key device-subject subscriptions),
  **idempotent, one transaction**, "nothing to adopt" when clean; **adoption is NEVER
  implicit on the authentication path** (an unauthenticated request must never mint an
  account), and sigild logs a **boot WARNING** ("ACCOUNT BACKFILL INCOMPLETE … `sigild
  migrate` will NOT fix this — 0005 is already recorded as applied. Run `sigild migrate
  adopt`") when unadopted rows exist. **(4) AN ORPHAN OWNER GRANT IS RECONCILED** inside
  `ClaimVault` (it writes **only the owner row** — not one grant row is created or
  re-permissioned), so a legitimately write-granted device gets **201** instead of the
  opaque 500 it used to get; unresolvable ⇒ coarse **403 `vault_owner_unresolved`**, never
  a 5xx. Also fixed a pre-existing **Postgres COLLATION flake** (`ORDER BY device_id` under
  `en_US.utf8` vs Go byte order → **`COLLATE "C"`** on every text `ORDER BY` in the store
  package), which made the only gate exercising 0005 red ~4 runs in 12.
  ⚠️ **HONEST LIMITS — the essentials (all 19 in ADR 0040):** ⭐ **THIS IS NOT AN IDENTITY
  SYSTEM AND THERE IS NO RECOVERY** — no email, no password, no recovery code, no operator
  break-glass; **lose or revoke EVERY device and the account is permanently unreachable,
  its vaults permanently unreadable by the customer AND by us, and its subscription
  stranded.** The orphan failure **NARROWED** (from "revoke one device" to "lose every
  device"); it was **NOT eliminated**, and "keep two devices enrolled" is a **mitigation,
  not a fix** — this must be written down before anyone charges real money. **Membership
  confers AUTHORIZATION, never DECRYPTION** (a joined device reads nothing until a member
  wraps the vault key to its hybrid public key, ADR 0035/0038) — corollary: **a hostile
  server can insert a device into any account and STILL cannot decrypt anything**; the only
  defence against the follow-on key-substitution attack is client-side pinning + safety
  numbers, which cannot protect first contact. **Membership is FLAT** (any member may
  invite, revoke every sibling, run checkout and administer every account-owned vault;
  revoking a compromised device does **NOT** revoke the devices it invited — visible in the
  audit log, not prevented) and **IMMUTABLE** (no transfer, merge, split or deletion).
  An **UNPINNED invite is a BEARER SECRET** over plain HTTP. **TOFW did not go away, it
  moved up one level.** **NO ACCOUNT MERGE:** every pre-0005 device is adopted into its OWN
  singleton account, so an existing two-device customer ends up with **TWO accounts and TWO
  billing subjects** (manual remedy, leaves a second subscription row to reconcile).
  **Entitlement is REPORTED unless `SIGILD_ENTITLEMENT_ENFORCE` is set** (Phase 55, ADR
  0043: then a lapsed account's WRITES answer 402 past grace, while ⭐ **reads and
  same-account key recovery are NEVER refused**). `SIGILD_ACCOUNT_MAX_DEVICES` is
  anti-freeloading, not anti-fraud. A compromised provider webhook secret now moves an
  **ACCOUNT's** status — and, with enforcement on, its SERVICE. `/metrics` is still
  always-on/unauthenticated and its per-reason
  counters a weak correlatable oracle (**pre-existing; deliberately not widened**). **Rate
  limiting** on `POST /v1/devices/enroll` and `POST /v1/account/invites` is **opt-in and a
  BACKSTOP** (Phase 53, ADR 0041; the caps still bound stored STATE, not request volume)
  and there is still **no sweep job** for expired invites. The replay
  nonce cache is **still per-process/in-memory** (invite consumption is DB-atomic and
  therefore multi-instance safe; **signed requests are not**). The in-memory registry is
  **still non-durable** and the **file backend was still not extended**. ⚠️ **ROLLBACK:** a
  pre-Phase-52 binary run after 0005 **enrolls devices with `account_id` NULL**; rollback
  is **survivable BUT any device enrolled during the rollback window needs `sigild migrate
  adopt` after rolling forward**, and the boot warning is how an operator knows. (The first
  design claimed "the one real breakage is billing" — **a verifier DISPROVED that on real
  Postgres**; do not repeat it.) `sigil_billing_processed_events.subject` **deliberately
  retains pre-0005 DEVICE ids** — cross-cutover reconciliation needs BOTH ids. Billing has
  still **never been run against a live provider account**; Juspay remains
  UNVERIFIED-AGAINST-LIVE-DASHBOARD. ⚠️ **CLIENT COVERAGE IS PARTIAL BY DESIGN:** the
  **CLI** and the **native desktop** got the full flow (show/mint/list/revoke); the
  **webapp** and **MV3 extension** can **JOIN** (the wire is unchanged) and **READ** the
  account and render the honest *"joined — waiting for a key from another device"* state,
  but have **no UI to MINT, list or revoke** an invite. Everything stays **dev-gated behind
  `SIGILD_ENABLE_DEV_OPS` + `SIGILD_DEVICE_AUTH`, `501` by default, plain HTTP, pre-audit,
  UNAUDITED — a real authorization model, not a reviewed one.** ⭐ **THE SENTENCE AN
  AUDITOR SHOULD BE ABLE TO CHECK:** an account is **auth metadata only**; the server still
  **never sees a vault key, a password or a plaintext**; **no request anywhere names an
  account**; entitlement and vault ownership derive **solely** from the account on the
  **verified signer's device row**; and **membership grants ciphertext access, never
  plaintext**. Contract in [`docs/api.md`](docs/api.md), operator guide in
  [`docs/deployment.md`](docs/deployment.md) §11.1 + §14; ADR 0040. Proofs:
  `cli/tests/e2e-accounts.sh` (real sigild + real CLI, four devices, four HOMEs) and
  `sigil-wasm/test/accounts-interop.mjs` (a JS client and the real Rust binary landing in
  ONE account).
  **ABUSE BOUNDS (Phase 53, ADR 0041) — opt-in, stdlib-only, NO new dependency:** a
  hand-written token bucket (the SAME `internal/api/ratelimit.go` type as the op-log
  limiter) now bounds **`POST /v1/devices/enroll`** (keyed on the **SOCKET PEER ADDRESS** —
  IPv4 full address, IPv6 **/64 prefix**; **`X-Forwarded-For` is deliberately IGNORED**,
  since without a trusted-proxy config it is attacker text and keying on it would let one
  client mint unlimited buckets) and **`POST /v1/account/invites`** (keyed **per ACCOUNT**).
  Env `SIGILD_ENROLL_RATE_LIMIT`/`_BURST` + `SIGILD_INVITE_RATE_LIMIT`/`_BURST`, **off by
  default**, validated fail-fast; over-rate is `429 rate_limited` + `Retry-After`. New
  metric `sigild_abuse_ratelimit_rejected_total{surface}` (closed set `enroll`/`invite`) and
  audit event `abuse.rate_limited` — ⚠️ **the source address is NEVER logged** (this server
  holds no personal data anywhere, and the proxy that would block already has it).
  ⚠️⚠️ **TWO PROPERTIES THAT MUST BE STATED AS LOUDLY AS THE FEATURE, both proven live:**
  (1) **IT IS A BACKSTOP, NOT A DEFENCE** — the only topology this repo documents
  (`deploy/caddy/Caddyfile`) is a reverse proxy, so every request arrives from ONE address
  and the enrollment limiter degrades to a **single global bucket**. An earlier revision
  rejected BEFORE the handler and was reproduced **refusing a LEGITIMATE customer holding a
  valid, unspent operator token** — a global account-creation OFF SWITCH. **Fixed two ways:
  the bucket is charged ONLY on the DENIAL path** (a request with a valid, unspent
  credential + a valid proof can NEVER be refused by it) **and `Allow` now FAILS OPEN at its
  key cap** (the old fail-closed branch let one IPv6 /48 fill 10,000 buckets and lock out
  everyone). (2) **IT DOES NOT REDUCE LOAD** — charging only on denial means the handler
  ALWAYS runs, including its DB work; the limiter replaces only the RESPONSE. Real
  per-source limiting belongs at the **EDGE**, and is configured **nowhere in `deploy/`**.
  ⛔ **THE WEBHOOK RATE LIMITER WAS BUILT, PROVEN HARMFUL, AND REMOVED.** An early Phase 53
  revision limited `POST /v1/billing/webhook/{provider}` **before signature verification**,
  keyed on the provider name. A verifier reproduced it live: one unauthenticated thread at
  **~137 forged req/s shed 15 of 15 genuine, correctly-signed Stripe deliveries with 429**;
  a longer flood shed ~2,000 consecutive genuine retries; **zero payment events applied**,
  and the customer was then refused 402 by Phase 55. A provider's retry budget is FINITE, so
  the event is lost **permanently**. ⭐ **THE RULE: you cannot safely shed traffic on a route
  where shedding costs money and the legitimate sender has a finite retry budget** — before
  verification, forged traffic spends the honest sender's quota (the only key, the provider
  name, is attacker-controlled too); after verification is no better, because an authentic
  burst is exactly what must never be dropped. What bounds it instead: the 64 KiB body cap
  and one HMAC over a size-capped buffer. **`SIGILD_WEBHOOK_RATE_LIMIT`/`_BURST` no longer
  exist**; setting them logs a loud boot WARNING naming the removal (added after a verifier
  pointed out they were otherwise **silently inert**). ADR 0041; `docs/deployment.md` §15.
  **ENTITLEMENT ENFORCEMENT (Phase 55, ADR 0043) — opt-in, OFF by default, byte-identical
  when unset:** behind **`SIGILD_ENTITLEMENT_ENFORCE`** (+ **`SIGILD_ENTITLEMENT_GRACE`**,
  default **14 days**, bounded `(0,365d]`) an account whose subscription lapsed longer ago
  than grace has **WRITES** refused with **402 Payment Required** and a machine-readable
  body (`payment_required`, `subscription_status`, `grace_ended_at`, `reads_allowed`,
  `key_recovery_allowed`, `checkout_path`) — **never collapsed into the coarse 401/403
  envelopes**, and reachable **only AFTER authn AND authz both succeed**, so it is no
  oracle. It requires `SIGILD_ENABLE_DEV_OPS` + `SIGILD_DEVICE_AUTH` +
  `SIGILD_BILLING_PROVIDERS` (each missing one is a **BOOT ERROR** — unlike the abuse
  limiters, a silently-moot payment gate is a business hazard). ⭐ **READS AND KEY RECOVERY
  ARE NEVER REFUSED:** `requireEntitlement` is called from **exactly THREE write handlers**
  (`opsAppend`, `keyEnvelopePut`, `vaultGrantCreate`) and **no read handler**, pinned by a
  test that **parses the package AST**. A lapsed customer can still list ops (a verifier
  drove it live and got the RFC 6238 vector **94287082**), collect envelopes, read the
  account, mint invites, enroll/revoke devices and pay; **`past_due` remains ENTITLED**.
  ⚠️ **A verifier found a real LOCKOUT and the fix closed it:** past grace a customer could
  not deposit a key envelope to their OWN new device (402) and could not print a recovery
  kit — one device failure from permanent loss, while the 402 body claimed
  `key_recovery_allowed: true`. **`sameAccountRecipient()` now exempts a key deposit AND its
  grant when the recipient is a device of the CALLER'S OWN ACCOUNT.** Every uncertainty
  **FAILS OPEN** (store fault / unreadable account / no anchor / no account id), and
  `entitlement.fail_open` is logged at **ERROR** because it means enforcement is silently
  not happening. Grace runs from the **LATER** of `updated_at` and `current_period_end`; a
  never-subscribed account is graced from its **creation time**, so ⚠️ **the grace window
  doubles as the buy-in window — there is no separate trial mechanism**. New metrics
  `sigild_entitlement_enforcing` (gauge) + `sigild_entitlement_decisions_total{outcome}`
  (closed set `entitled`/`grace`/`refused`/`fail_open`, **no account label**); audit
  `entitlement.grace`/`.refused`/`.fail_open`; response headers `X-Sigil-Entitlement`,
  `-Status`, `-Grace-Ends` on gated writes only; an additive `entitlement` block on
  `GET /v1/billing/subscription`. The verifier mutation-tested this phase hard: **15
  separate control mutations all went red.** ADR 0043; `docs/deployment.md` §16.
  **⚠️ NO MIGRATION was added by Phases 53–55 — `sigild_schema_version` is still 5.**
- `sigild/` **THE RECOVERY-KIT SERVER SIDE (Phase 54, ADR 0042) is ONE ROUTE and NOTHING
  ELSE.** ⭐ **`sigild` gained NO concept of "recovery"**: no table, no migration, no flag,
  no config. A recovery kit is an **ORDINARY MEMBER DEVICE** (label `"recovery-kit"`,
  visible in `GET /v1/account`), so the server sees only shapes it already relayed — one
  device row, one hybrid PUBLIC key, one opaque ~1226-byte `SIGILhyb` envelope per covered
  vault. The one addition is **`GET /v1/devices/{deviceID}/keys`** (`deviceKeyEnvelopeIndex`
  in `internal/api/sharing.go`), the index a kit needs on a **fresh machine** where it knows
  its own device id and nothing else: **SELF-ONLY** (a mismatched path id ⇒ **403 BEFORE any
  store read**; an **unknown device id is the SAME coarse 403, never 404** — no existence
  oracle), **METADATA ONLY** (Postgres selects `octet_length(blob)`, so ciphertext never
  leaves the DB), each row additionally filtered by the ordinary `authorizeVault(needRead)`
  (unauthorized vaults are **silently omitted**, not an error; `needRead` never claims),
  ordered by vault id, capped at **500** rows with `has_more` and ⚠️ **no cursor**. Response
  `{device_id, vaults:[{vaultID, sender_device_id, size_bytes, created_at}], has_more}`.
  **It needed NO migration** — the index `sigil_vault_key_envelopes_by_recipient` from
  `0004_key_sharing.sql` was created for exactly this query. New store method
  `ListKeyEnvelopesForRecipient` (Mem + Postgres, one conformance suite), metric
  `sigild_key_envelope_index_total`, audit `device.key_envelope_index`
  (`device_id`, `returned_count`; **no `blob_sha256`** — the route reads no blob).
- `sigild/` ⭐ **BROWSER ORIGINS / CORS (Phase 56, ADR 0044) — the fix for a hole that made
  the whole webapp unreachable.** Every signed request carries `X-Sigil-Device`/`-Timestamp`/
  `-Nonce`/`-Signature`, none of which is CORS-safelisted, so **a browser preflights every
  one of them**. `sigild` routed no `OPTIONS` and emitted **no `Access-Control-*` header
  anywhere** (`grep -rin access-control sigild/` found NOTHING; a real preflight answered
  **`405`**), so from a page on a different origin — i.e. the entire localhost dev topology,
  webapp on `:3000`, sigild on `:8080` — **enroll, sync, share, restore-from-kit and the
  entitlement read were ALL DEAD**, blocked in the browser before a byte was sent. The gap
  is **PRE-EXISTING since Phase 44**; the **MV3 extension was never affected** (a
  `host_permissions` page is exempt from CORS), which is why it went unnoticed. **New:**
  `internal/api/cors.go` + `cmd/server/corsconfig.go`, hand-written stdlib —
  **`sigild` still has EXACTLY ONE direct Go dependency (`pgx`)**.
  **`SIGILD_CORS_ORIGINS`** is a comma-separated list of **EXACT** origins
  (`http://127.0.0.1:3000,http://localhost:3000`), validated **fail-fast BEFORE the listener
  binds**; a path/query/fragment/trailing slash/credentials/non-`http(s)` scheme is a boot
  failure, and **`*` is REJECTED AT BOOT (rc=1, never binds)** rather than narrowed.
  ⭐ **UNSET = the middleware is NOT INSTALLED at all** — byte-identical to before (a
  verifier swept **45 responses across 9 paths × 5 methods** with an `Origin` header and
  found **ZERO `Access-Control-*` lines**, with `OPTIONS` still `405`). When on: it
  **ECHOES** an allowlisted origin (**never `*`**, never a value the request did not
  present), always sends **`Vary: Origin`**, answers a preflight **`204`** with the exact
  `X-Sigil-*` header list, exposes `X-Request-ID` + the three `X-Sigil-Entitlement*`
  headers (without which a browser cannot read its own grace warning), caches preflights
  **600 s**, and **NEVER sets `Access-Control-Allow-Credentials`**. It sits **innermost** so
  a preflight it answers is still counted / request-ID'd / access-logged, and an unknown
  origin's `OPTIONS` falls through to the mux → `405`, exactly as before (no probe
  distinguishing "route exists" from "origin allowed"). ⭐ **THE REASONING: this is SAFE
  because there is NO COOKIE and NO AMBIENT AUTHORITY** — every request is authenticated by
  a **per-request Ed25519 signature over a canonical message**, so a cross-origin page
  cannot forge one. That is also why **CORS here is NOT a CSRF control** and **not an
  authentication control**; the allowlist exists to make the browser-side error honest and
  the reachable surface deliberate. ⚠️ **PRODUCTION should serve the app and the API from the
  SAME ORIGIN behind the reverse proxy and set nothing here**; this is for the localhost dev
  topology, and the boot log says so. It constrains **browsers only** — `curl`, the CLI and
  the desktop ignore it — and it does not make plain HTTP safe.
- `sigild/` also carries **seven committed but INERT scaffold packages** (compile, do
  nothing, wired to nothing): `cmd/worker-audit`, `cmd/worker-breach`, `cmd/worker-rehash`
  (~15-line `main.go` stubs) and `internal/admin`, `internal/auth`, `internal/push`,
  `internal/vault` (`doc.go` placeholders). They name future work only — note in
  particular that `internal/auth` is **NOT** where the real auth lives (that is
  `internal/api/deviceauth.go` + `internal/store/devicestore.go`).
  ⚠️ **Phase 58 REWROTE those four `doc.go` files, because two of them were a reviewer
  trap in CODE** — an auditor browsing the tree hits them before reading any document.
  `internal/auth` said *"STATUS: not implemented"* and described **Ed25519-signed JWT
  bearer tokens minted at device registration**, a design that was **NEVER BUILT**, while
  ~640 lines of real request authentication live in `internal/api/deviceauth.go` (the
  mechanism is a **per-request contract-v3 Ed25519 signature**; there is no JWT anywhere
  in sigild). `internal/vault` said the same about the op-log while ~468 lines of it run
  in `internal/store/oplog*.go` + `handlers.go`. Both now point at the real files and say
  what is genuinely unbuilt (CRDT/Lamport merge semantics — the shipped log is an
  append-only per-vault `seq`). `admin` and `push` were clarified as **reserved names**;
  they are genuinely unbuilt. Comment-only changes; all four packages are still imported
  by **zero** files.
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
  (`sigil.webapp.vault.v1` + `sigil.webapp.device.v1`) — **THREE when Phase 58's passkey
  protection is on, all three still sealed containers**; the password and all decrypted
  secrets are memory-only and cleared on lock/forget/unload. **Unlock now opens the
  device identity FIRST, tries the password, then falls back to each held vault key**,
  so a shared vault re-opens after a reload. **Phase 50 (ADR 0038) added the key-trust UI
  to the same panel:** show this device's / a peer's **safety number** (`wasm.safetyNumber`),
  a `wasm.KeyPinMismatchError` catch that **BLOCKS the share** and renders both safety
  numbers with a deliberate re-pin (`wasm.repinHybridKey`) behind it, and **rotate**
  (`wasm.rotateVaultKey`) — with `onUpdateDevice({ pins: res.pins })` re-sealing the
  container so the pins persist. ⭐ **Phase 56 (ADR 0042/0043/0044) made the RECOVERY KIT
  and the PAYMENT WARNINGS reachable:** a **`RestorePanel` on BOTH the setup and the
  locked screens** (recovery is deliberately **NOT** behind an unlocked vault — a fresh
  install with no local state is exactly where a printed sheet is used), a `RecoveryPanel`
  (generate / cover / check / revoke) inside the vault, and an `EntitlementBlock` that
  reads `GET /v1/billing/subscription` on mount (the **only** warning channel a read-only
  client ever gets) plus `readEntitlementHeaders` on the sync path. The kit sheet is shown
  **ONCE** — 7×8 grouped code, safety number, kit id, account, server, vaults covered as of
  today, four warnings, print/copy — behind a *"I have written it down"* confirmation that
  **clears it from the DOM**; it lives in React state only, never `localStorage`, never a
  URL, never a log line. ⚠️ **A REAL LATENT BUG was fixed here:**
  `web/packages/sigil-wasm/index.mjs` **never re-exported the `recovery_*` wasm functions**,
  so every browser recovery call would have **thrown at runtime**; the missing `.d.ts` types
  were a **separate** gap (types and runtime were two distinct holes). New specs:
  `recovery.spec.ts`, `wrap-gate.spec.ts` (a **second profile that never saw the sheet** is
  refused, stores **no envelope**, and is told a wrong safety number is a mismatch — the
  gate was previously deletable with every spec staying green), `leak.spec.ts` (an
  **enumerating** sweep: every localStorage/sessionStorage key AND value, cookies, every
  IndexedDB record, every Cache Storage entry, the DOM after dismissal, every request
  URL/body, every console message from before the first navigation, and the address bar,
  against four spellings of the code — and, since Phase 57, ⭐ **the POSITIVE assertion of
  ADR 0036**: every persisted value must decode to bytes starting with the `SIGILcli` magic
  and every other surface must be EMPTY, because a planted plaintext `sessionStorage` write
  dumped the Ed25519 seed, the hybrid secret and every vault key while this suite passed
  19/19. ⚠️ Cache Storage — the one surface allowed to be non-empty, this being a PWA — is
  constrained by an **ALLOWLIST** (`/`, `/_next/`, static asset extensions); the first fix
  filtered only CROSS-origin entries, which was vacuous, since every plausible leak is
  same-origin and the extension caught the identical plant),
  `entitlement.spec.ts`, and ⭐ **`cors.spec.ts` — the
  ONLY spec that drives the UI against a REAL `sigild`** (both directions: allowlisted ⇒
  enrols, unlisted ⇒ blocked). ⚠️ It resolved Go as `process.env.GO ?? "/opt/homebrew/bin/go"`
  with **no PATH lookup**, so in CI it **`test.skip`ped itself** and that only browser-level
  proof silently vanished while the job stayed green — Phase 57 gave it a PATH lookup **and**
  `GO: go` on the workflow step (`actions/setup-go` alone did NOT fix it: it sets PATH, never
  `$GO`). ⚠️ Every other spec runs against
  `sigil-wasm/test/fake-sigild.mjs`, a **double** that used to be MORE PERMISSIVE than real
  sigild on four axes — **Phase 58 enforced all four in the double**: the catch-all now
  answers **501** for unimplemented `/v1/` routes (the "501 by default, never 404"
  invariant), the envelope PUT enforces the **16 KiB** cap, the hybrid-key PUT validates
  **both halves' lengths** (32 / 1184), and the envelope PUT checks the recipient
  **exists and is not revoked**. ⚠️ What is STILL laxer is now spelled out in its header:
  **no signature verification, no ownership/grant/authorization, no entitlement gate
  beyond a switch, no rate limiting, no nonce/replay window, no seat cap, no hash chain
  and no self-only check** on the per-device envelope index — a spec there proves what the
  BROWSER does and NOTHING about what sigild would allow. ⚠️ **print output is NOT
  verified** (headless Chromium cannot render a printed page, so `@media print` is by-eye).
  ⭐ **PHASE 58 (ADR 0046): the webapp is the ONLY client that can PROTECT ITS CONTAINERS
  WITH A PASSKEY.** New file **`sigil-wasm/passkey.mjs`** (framework-free ESM, browser-only,
  re-exported by `@sigil/wasm` — **both** `index.mjs` AND `index.d.ts`, the two-hole trap
  Phase 56 fell into). With protection on, BOTH `SIGILcli` containers are sealed under a
  32-byte **CONTAINER MASTER KEY** instead of the password, where
  `CMK = HKDF-SHA256(salt "sigil-recovery-kit-v1", ikm = the ADR 0042 kit seed, info
  "sigil-recovery-kit-v1/container-master-key", 32)` — so the **break-glass is the sheet
  the user ALREADY PRINTED**: no new artifact, no server. The CMK is ALSO wrapped into a
  **THIRD container** (`localStorage` key **`sigil.webapp.hwslot.v1`**) sealed under
  **`PRF_output(32) ‖ utf8(password)`** — ⭐ **PRF bytes FIRST** (a fixed-length prefix
  makes the parse unambiguous) and fed **STRAIGHT to the container's own Argon2id**, NOT
  through a cheap HKDF (an attacker who can drive the authenticator recovers `R` and must
  still face Argon2id over the password). ⭐ **AND, NEVER OR** — while protection is on
  there is **no password-only slot**; the two doors are (password AND passkey) and (the
  printed sheet). ⭐ **THE WRITE ORDER IS THE SAFETY PROPERTY:** enable is not atomic, so
  **containers are written FIRST and the slot LAST** — a crash leaves CMK-sealed containers
  with NO slot, the state the sheet alone recovers (slot-first left a slot beside
  password-sealed containers, where a sheet-derived CMK genuinely is not a door).
  Enabling **REFUSES without an active recovery kit** (fail-closed), the code is decoded +
  checksummed **offline** first, the **break-glass form renders unconditionally** on the
  locked screen (gating it on the deletable slot was a lockout), `createVault()` **clears a
  stale slot**, a surviving device identity is **left byte-for-byte in place and
  announced**, a kit **reprint re-seals the slot in the same operation**, and a protected
  **PERSONAL** vault refuses sync in **BOTH** directions (pull would overwrite the only
  copy). ⭐ **`sigild` gained NOTHING** — no route/header/canonical message/migration/
  table/metric/dependency; request auth is still classical Ed25519 contract v3. ⛔ Defends
  **STORAGE, never EXECUTION**; **NOT retroactive**. ⛔⛔ **WebAuthn does NOT work on
  `http://127.0.0.1`** (RP-ID rejects IP literals: `SecurityError: This is an invalid
  domain.`) — `playwright.config.ts` and the affected specs moved to **`http://localhost`**,
  and it also pins `workers: 2` (7-way contention produced ten unrelated failures) and
  `reuseExistingServer: false`. Proven by **`tests/passkey.spec.ts` — 26 specs** over CDP's
  (24 in Phase 58; Phase 59 added two for the REAL `authenticatorAttachment`, replacing a
  value the app had been INFERRING from the backup-eligible flag)
  **virtual authenticator** (`hasPrf: true` for the supported branch, omitting it for the
  unsupported one). Do NOT store real 2FA secrets.
  ⭐ **PHASE 59 (ADR 0047) touched every place this app WRITES.** A new
  **`sealParams(storageKey)`** helper reads the container about to be replaced and
  ratchets, and it is now passed at **all four** of this file's sealing call sites
  (`sealVault`, `sealDeviceIdentity`, and **both** `sealHwSlot` sites) — `ARGON2` is a
  **FLOOR, not an instruction**. `withVault` now calls **`wasm.cloneVault(vault)`**
  instead of rebuilding `{version, entries}` by hand, which used to silently delete
  `min_reader_version` and every field a newer client wrote — and then push the stripped
  vault over the newer one, because **the oldest writer wins** on the op-log. The
  migration import renders the batch note, keying its "INCOMPLETE" framing off
  `finalBatch` so a **finished** multi-QR import is not announced as incomplete. The
  passkey unlock path stopped **inferring** the authenticator attachment and now uses
  the real one from the ceremony.
  ⛔ **THE MISTAKE THIS PHASE MADE, AND THE THREE GUARDS IT BOUGHT.** An independent
  verifier reverted the **product** half of both fixes — `cloneVault(vault)` back to
  `{ version: vault.version, entries: [...vault.entries] }`, and five of the six
  `sealParams(...)` call sites back to the bare constant — and **the whole gate stayed
  green: webapp 50/50, extension 14/14, and the Rust↔JS schema interop passed.**
  Mutating the SAME logic inside `totp-vault.mjs` / `passkey.mjs` went red every time.
  **The module was guarded and the PRODUCT was not** — entry **#9** of
  `docs/engineering-lessons.md` recurring **inside the commit that added that
  document**, now recorded as entry **#10**. New: **`tests/schema.spec.ts`** (seeds a
  vault whose stored JSON carries fields this build has never heard of, drives a **REAL
  edit through the REAL UI**, then **decrypts what the app actually wrote**),
  **`extension/tests/schema.spec.mjs`** (the same through the real unpacked extension),
  and **`sigil-wasm/test/seal-params-guard.mjs`** — a **SOURCE-STRUCTURE** guard that
  enumerates every sealing call site in the two shipping browser sources (**6 across 2
  files**) and fails unless each is passed `sealParams(...)`, **and fails if it finds
  ZERO**, because a guard that checks nothing is worse than no guard. ⚠️ **It is
  structural on purpose and that is a limitation**: it proves each site *passes* the
  helper, **not** that the helper is correct. ⚠️ `tests/schema.spec.ts` needs the
  **NODE-target** wasm (`sigil-wasm/pkg-node`) in the TEST process to open the app's
  sealed container — `@sigil/wasm` is a **bundler-target** package Node cannot require —
  so `.github/workflows/web.yml` now also runs the repo-root `build-wasm.sh`.
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
  Architecture Decision Records (Nygard-style ADRs for load-bearing choices; latest is
  **0047**, the container parameter ceiling + the no-downgrade ratchet + the
  forward-compatible vault schema — which also carries **dated addenda on 0020, 0024,
  0025, 0026 and 0046**, per this repo's addendum rule: append, never rewrite).
  ⚠️ **Audit #4 found the STATUS BLOCKS an external
  reviewer reads FIRST were false** and would have scoped sigild's cryptography out of
  review: `api.md`, `architecture.md` and `deployment.md` each opened with *"performs no
  cryptography / holds no keys / runs no auth"* while `grep -rE
  'crypto/(ed25519|hmac|sha256|subtle|rand)' sigild --exclude '*_test.go'` returns **29
  hits** across `cmd/server` and `internal/{api,billing,store}`. Corrected everywhere: the
  true statement is **no crypto ON VAULT CONTENT and no key that can DECRYPT a vault** —
  sigild does plenty of crypto for **authentication, hash-chaining and webhook
  verification**, and it holds device public keys, published hybrid public keys and
  provider webhook secrets.
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
  ⭐ **Phase 58 closed the audit-#4 gap where the Caddyfile CONTRADICTED its own
  runbook:** it was a bare catch-all `reverse_proxy` with **no path matcher**, so the
  always-on, unauthenticated `GET /metrics` would have been **world-readable** at a
  public edge (account counts, enrolment volume, billing webhook outcomes,
  entitlement refusals) while `docs/deployment.md` said keep it internal. It now has
  `handle /metrics { respond 404 }` **before** the proxy — **404, not 403, because a
  403 confirms the route exists**. Nothing is deployed, so this is still unproven end
  to end. **Documentation is not a control.**
- `scripts/` — **`gate.sh`** (Phase 56), the documented way to run **everything**: it
  enumerates every suite dynamically, counts results instead of trusting exit codes,
  prints an inventory, and runs a **CI-drift check** asserting every node interop suite
  and shell e2e script is named in some workflow. ⚠️ **Audit #4 (Phase 57) found TWO
  blind spots in it, both fixed:** it began with a **hardcoded absolute `cd`**, so run
  from a git **worktree** it built and tested the MAIN checkout (a planted `getrandom`
  stanza in a worktree lockfile still printed `✓ getrandom==0`, and it bit the audit
  itself — one lens reported ALL GREEN about a tree it was not auditing); and it **never
  set `SIGILD_TEST_POSTGRES`**, so ~30 tests skipped while it counted only PASS/FAIL. It
  now resolves the repo **from its own location** and **prints the tree + commit it is
  gating**, starts a throwaway `postgres:16` on a free port, and **FAILS if any test
  skipped**. ⚠️ **A THIRD blind spot was found on 2026-07-30, and it is the widest of
  the three: the gate ran NEITHER SECURITY SCANNER.** Its coverage was a **strict subset
  of CI's**, so it structurally could not answer the one question it exists to answer —
  the `security` workflow was red on two jobs while the gate said ALL GREEN about that
  same commit. It now runs **`govulncheck`** and **`cargo audit --deny warnings` across
  all four lockfiles**, both mutation-proven THROUGH the gate (reverting `x/text` to
  v0.29.0 → `✗ 1 vulnerability(ies)` naming GO-2026-5970; dropping `RUSTSEC-2024-0429`
  from the ignore list → `✗ error: 1 denied warning found!`). ⭐ **`govulncheck` runs
  against a `go1.25.x` toolchain — the line we SHIP — not `$GO`**, resolved as
  `$SIGIL_SCAN_GO` → newest `~/go/bin/go1.25.*`; with none installed it **FAILS with
  install instructions** rather than silently scanning the dev machine's Go 1.26.3 and
  reporting three stdlib advisories that are not in the artifact. ⚠️ Two bugs in that new
  block were caught by testing it in isolation before commit: **`$HOME/.cargo/bin` was
  missing from `PATH`** so `cargo-audit` reported "not installed" where it was installed
  (now **appended**, not prepended, so the rustup toolchain still wins for
  `cargo`/`rustc`), and a **failed `cd sigild` printed `0 vulnerability(ies)`** — an empty
  scanner result is now an explicit failure, never a count. See *Build & test* below.
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
  ⭐ **Phase 59 (ADR 0047 + the 0025/0026 addenda) fixed TWO things this feature was
  SAYING that were not true, in the one feature whose entire purpose is not losing
  accounts.** (1) **A MULTI-QR IMPORT REPORTED PLAIN SUCCESS.** Google Authenticator
  splits a large export across several QR codes, each an independently-decodable
  `MigrationPayload` carrying `batch_size`/`batch_index`/`batch_id` with the accounts
  DIVIDED between them — and both codecs **consumed those three fields and threw them
  away**, so scanning the FIRST QR of a three-QR export imported a THIRD of the accounts
  and printed `imported N` with no warning. `decode_migration_payload`/
  `decode_migration_uri` now return a **`MigrationBatch`** (`otps` + the framing) with
  `is_complete()` / `is_final_batch()` / `batch_note()`. ⭐ **`is_final_batch()` is NOT a
  nicety:** the first cut told a user importing **batch 2 of 2** that *"0 more QR
  code(s) must be imported — this import is PARTIAL"*, i.e. told someone who had just
  finished that they had not — **a warning that cries wolf is one the next user ignores
  when it is real.** The final batch is still NAMED (this client keeps no
  cross-invocation state and genuinely cannot know whether the earlier QRs arrived) but
  is not called incomplete. Surfaced by **all four clients** (`sigil totp import`, the
  webapp, the extension, and the desktop via `ImportSummary { partial_batches,
  batches_outstanding }` — the UI keys its alarm off `batches_outstanding`, NOT off
  `partial_batches` being non-empty). (2) **A `--migration` EXPORT OF A NON-30 s ENTRY
  WAS A SILENT LIE.** The wire format has **no period field**, so a 60 s entry was
  exported as if it were 30 s and the receiving app computes **DIFFERENT CODES from the
  same secret** — an account that simply stops working, delivered as a successful
  export. `entry_to_migration_otp` now **REFUSES**, naming the label, the period and the
  plain `otpauth://` export that carries it. ⭐ **Refusal stays the DEFAULT**, with a new
  **`sigil totp export --migration --skip-unsupported`** so one unrepresentable account
  no longer costs the user the whole bulk-export path — it exports the rest and names
  each skipped entry **individually, with the reason, on stderr** (so it survives a pipe
  to a file), and the summary line says `PARTIAL`. `--skip-unsupported` without
  `--migration` is an error. ⚠️ **THAT ESCAPE HATCH EXISTS IN THE CLI ONLY** — the
  webapp, the MV3 extension and the desktop call the encoder over the WHOLE vault, so
  for them one 60 s entry now makes the migration export fail **WHOLESALE** where it
  previously produced a wrong one (right direction, unanswered usability regression).
  ⭐ **Phase 59 also made the VAULT SCHEMA changeable** (ADR 0047, the 0024 addendum):
  `TotpVault` and `TotpEntry` each gained **`#[serde(flatten)] extra`**, so an old
  client that merely opens and re-seals a vault no longer **DELETES** a newer client's
  data (serde used to drop unknown fields, and the JS clients rebuilt
  `{version, entries}` by hand — on a sync path where **the oldest writer wins**); a new
  **`min_reader_version`** (`TOTP_VAULT_READER_VERSION` = 1, `check_vault_readable`)
  separates *what wrote this* from *what a reader must understand*, refusing iff
  `(min_reader_version ?? version) > READER_VERSION` and therefore **FAILING CLOSED**
  when the field is absent — replacing the blanket `version != 1 ⇒ refuse` that made
  every addition a four-client flag day; and a stable per-entry **`uuid`**
  (`format_entry_uuid` / `random_entry_uuid` / `new_totp_entry_with_uuid`, RFC 4122 v4
  from CALLER-supplied entropy per ADR 0007). ⚠️ **NOTHING KEYS OFF THE uuid YET** —
  every lookup is still by `label`, deliberately. ⚠️ `extra` preserves **BYTES, NOT
  SEMANTICS**, and any code that rebuilds a vault field-by-field throws it away again.
  A test pins that `TotpVault::default()` still serializes to exactly
  `{"version":1,"entries":[]}`.
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
  `/v1/vaults/{vaultID}/grants`, **owning-ACCOUNT-only since Phase 52**). `GET …/grants`
  has no subcommand yet. ⚠️ **`device revoke` no longer refuses a non-self target
  client-side** — a device may revoke a **SIBLING** in its own account, and only the
  server's registry knows whether the target is one, so it decides and answers 403 if not
  (the CLI still insists the identity be enrolled, since an unsigned request could only
  ever be 401).
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
  dev-gated + UNAUDITED**, trust-on-first-write ownership (by ACCOUNT since Phase 52),
  single-ATTEMPT enrollment tokens, no identity / session issuance / key rotation /
  recovery, per-process replay cache.
  Also **`sigil account status | invite [--ttl <seconds>] [--pin-key <b64>] | invites |
  revoke-invite <inviteID>`** — the CLIENT half of the ACCOUNT model (Phase 52, ADR 0040),
  over `get_account` / `create_account_invite` / `list_account_invites` /
  `revoke_account_invite` in `cli/src/lib.rs`. ⭐ **There is NO join subcommand and NO
  `--account` flag anywhere, both by design:** joining is the ORDINARY `sigil device enroll
  --token <invite>` (an invite rides the EXISTING enroll header under the EXISTING
  challenge), and the server reads your account off the signature it just verified, so a
  request cannot name one. `account status` prints the account, its members, `N/limit
  active` **plus any revoked count with "a revoked device does not use a seat"**, marks
  `<- this device`, and — when the account has ONE device — prints a **NO RECOVERY** notice
  telling the user to enroll a second. `account invite` warns on **stderr BEFORE** printing
  the secret to stdout (bearer-secret vs pinned wording), prints the redeem command and the
  reminder that joining grants **AUTHORIZATION only** ("the new device reads nothing until
  you `sigil vault share` to it"). The secret is **never written to a file, never logged**,
  and `CreatedAccountInvite`'s `Debug` is **REDACTED** so a stray `{:?}` cannot leak it.
  `explain_account_error` renders 401/403/404/409/500/501 plainly — including that a 403
  may mean the device carries **NO ACCOUNT** (a pre-0005 enrollment), repaired with
  `sigild migrate adopt`. Every `sigil totp`/`vault`/`push`/`pull` invocation is unchanged.
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
  **`verify_recipient_for_wrap`** fetches a hybrid public key, **pin-checks it, checks any
  supplied safety number and refuses an unverified recovery kit — all in ONE call** — and
  **EVERY wrap path (share, rotate AND recovery cover) goes through it**, enforced BY TYPE
  (it is the only constructor of `VerifiedRecipient`, and the wrap path accepts nothing
  else). ⚠️ **`fetch_hybrid_key_pinned` NO LONGER EXISTS** — it was this rule's original
  choke point, superseded in Phase 54 and **DELETED in Phase 57** (audit #4) after sitting
  as a public `pub fn` with **zero callers** while every doc still recommended it by name:
  it pins but does NOT refuse a kit and does NOT honour a supplied safety number, so the
  next caller reaching for the familiar name got a weaker gate. A tombstone comment marks
  the spot. The bare `fetch_hybrid_key` survives only where nothing is wrapped
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
  ⭐ Also **`sigil recovery generate|cover|check|verify|restore|revoke`** — the
  **RECOVERY KIT** (Phase 54, ADR 0042), the answer to ADR 0040's limit 1. ⚠️ **A KIT IS AN
  ORDINARY MEMBER DEVICE** whose Ed25519 + hybrid private keys are HKDF-SHA256 derivations
  of 32 CSPRNG bytes **printed on paper** — never transmitted, never stored on a device,
  never derivable from anything the server holds. `generate` prints a sheet (the code, the
  device id, the account, the server, **the safety number**, the vaults covered *as of the
  print date*, four warnings) and covers every vault in the keyring; `cover` extends it to
  one more vault; `verify` checks a typed code **OFFLINE**; `check` reports what a kit can
  reach; `restore` runs on a **NEW install**; `revoke` retires the sheet. **THE SECRET IS
  ENTERABLE WITHOUT argv**: `--code` (kept for scripts, now warns on stderr that it lands in
  argv + shell history) → `--code-stdin` / non-TTY stdin → otherwise an **interactive prompt
  with echo disabled** (best-effort via `stty -echo` on `/dev/tty`, warning if it fails).
  **There is deliberately NO env var** (inherited by children, visible in `/proc/*/environ`).
  ⭐⭐ **THE SECURITY-CRITICAL PART, and why this phase needed two rounds: the wrap gate is a
  CHOKE POINT ENFORCED BY TYPE.** The FIRST implementation put the safety-number requirement
  on the `recovery cover` COMMAND — and a verifier proved live that `vault share --to
  <kitID>` and `vault rotate --to <kitID>` reached the **IDENTICAL wrap** through ordinary
  first-sight TOFU, showing the human the safety number only AFTER the wrap and upload had
  completed. **That is ADR 0038's own lesson ("the choke point is the FETCH, and EVERY wrap
  path goes through it") violated ONE PHASE after it was written down.** The fix:
  **`verify_recipient_for_wrap(server, device_id, auth, pins_path, expected_safety_number,
  known_recovery_kit)`** returns a **`VerifiedRecipient`** whose fields are **PRIVATE** and
  which has **NO other constructor** (built in exactly three literals, all inside that
  function), and the one wrap→deposit→grant path (`share_vault_to_known_key`) takes
  **`&VerifiedRecipient`** — so a caller **cannot reach the wrap without passing the gate**.
  Trust outcomes (`RecipientTrust`): **`Derived`** (pin `origin = "recovery-kit"` ⇒ **no
  fetch at all**) · **`Pinned`** (identical ⇒ proceed) · **different ⇒ `CliError::PinMismatch`**
  · first sight + matching `--safety-number` ⇒ **`VerifiedFirstSight`** · first sight + wrong
  number ⇒ **`CliError::SafetyNumberMismatch`** · first sight + **recipient is a recovery kit**
  + no number ⇒ **`CliError::UnverifiedRecoveryKit`** (REFUSE) · first sight + ordinary device
  ⇒ **`UnverifiedFirstSight`** (TOFU, warned, as ADR 0038 allows). ⭐ **EVERY refusal happens
  BEFORE the key is pinned** — pinning a refused key would let a retry see `Match` and
  silence its own alarm — and a supplied safety number is checked BEFORE the pin lookup, so
  it applies to pinned keys too. `vault share`/`vault rotate` gained **`--safety-number`**
  (bare digits with exactly one `--to`, else `<deviceID>=<digits>`, repeatable; compared
  digit-only so spacing never false-alarms), and `vault rotate` gained **`--drop`/
  `--drop-all-others`** with a fail-closed guard: it **REFUSES** when a current envelope
  holder is named by neither, flagging **"⚠️ THIS IS YOUR RECOVERY KIT"**.
  ⚠️⚠️ **THE RESIDUAL LIMIT, IN THESE WORDS:** the kit-DISCOVERY arm resolves a kit by device
  **LABEL** (`RECOVERY_DEVICE_LABEL = "recovery-kit"`) from **`GET /v1/account`** — a listing
  **the adversarial server serves**. **A server that renames or hides the label degrades
  `vault share`/`vault rotate` to a kit back to ordinary first-sight TOFU (warned and pinned)
  rather than a refusal.** The caller-ASSERTED paths (`recovery cover`, `recovery generate`,
  which pass `known_recovery_kit: true`) do NOT depend on the server, and **NO path anywhere
  accepts a CHANGED key or a mismatched safety number**. So the honest claim is **"refuses
  first-sight kit wraps against a server that does not lie about labels"**, **NOT** "refuses
  first-sight kit wraps". (A verifier judged this consistent with ADR 0038's accepted
  TOFU-on-first-contact limit and asked that the ADR say it in exactly those words.)
  ⭐ **THAT LABEL IS THE ONE REAL MIRROR IN THE RECOVERY WORK — and it had NO TEST until
  Phase 57.** The codec + derivation are **SINGLE-SOURCED** in `libsigil/core/src/recovery.rs`
  (the CLI imports them; the wasm exports are one-line shells), so `docs/crypto-spec.md`'s old
  "MIRRORED — NOT SHARED" line about the construction was wrong. The LABEL, though, existed as
  **THREE** hand-written literals (`cli/src/lib.rs`, `sigil-wasm/recovery.mjs`,
  `sigil-wasm/sharing.mjs`) — renaming it in BOTH JS files left every suite green. Now: the
  two JS copies are **one** (`sharing.mjs` imports it), and `recovery-interop.mjs` drives the
  **REAL `sigil` binary in both directions** expecting a refusal ⚠️ **pinned against a GOLDEN
  LITERAL** (`"recovery-kit"`), because a coordinated rename still passed a
  cross-language equality check — and the label is a **WIRE value** the server stores and
  older clients compare against, so it is **not free to change even "consistently"**.
  ⚠️ A **third** literal type in `web/packages/sigil-wasm/index.d.ts` still drifts silently
  (annotated in place; `tsc` cannot see it).
  ⚠️ **OTHER HONEST LIMITS:** whoever holds the paper has **FULL CONTROL of the account**
  (read every covered vault, revoke every device) — **stronger than a stolen locked phone**,
  since there is no OS lock and no vault password, and the kit's nominal `read` grant is
  **cosmetic** because account ownership authorizes it anyway; it recovers **KEYS, not
  DATA** (a vault never synced is gone); it opens only the vaults it was told to **COVER**;
  **a kit cannot be created after the loss**; it consumes a **seat**; and revoking it cannot
  un-learn what it already unwrapped. Local pin marker `PIN_ORIGIN_RECOVERY_KIT` (same
  string, different concern from the label). Proof: **`cli/tests/e2e-recovery.sh`** (twelve
  steps; **step 9c pins that SHARE and ROTATE obey the SAME rule as COVER**). ADR 0042.
  ⭐ **Phase 56 (ADR 0043) taught the CLI to render a `402`.** It previously dumped the
  server's raw JSON while `401`/`403`/`501` each got an explainer. **All five** explainers
  (`explain_sync_error`, `explain_device_error`, `explain_account_error`,
  `explain_sharing_error`, `explain_recovery_error`) gained a `402` arm via
  `explain_payment_required`, saying it is a **BILLING state, not an authentication or
  permission failure**, and that **reads and key recovery are unaffected** (`sigil pull`,
  opening a vault, `sigil totp code`, collecting envelopes, enrolling, revoking, and
  `recovery generate`/`cover` all still work while lapsed; what stops is `push` and sharing
  to a **different** account). ⚠️ **PRECISELY:** it still prints the server's JSON **first**
  and the prose **after**, matching this CLI's established `{e}\n  -> HTTP nnn: …`
  convention — the dump was **explained**, not removed. Also new: **`fetch_subscription`**
  in the library (a RAW-STRING read of `GET /v1/billing/subscription`, deliberately
  unparsed so the `entitlement` block is interpreted in exactly one place per client) —
  the function the desktop's grace warning needed and did not have.
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
  `HYBRID_PIN_STORE_VERSION`, the ⭐ choke point **`verifyRecipientForWrap(wasm, auth,
  deviceId, opts)`** (fetch + pin-check + safety-number check + recovery-kit refusal in ONE
  call; **every** wrap path — `shareVault`, `rotateVaultKey` AND `coverVault` — goes through
  it). ⚠️ **`fetchHybridKeyPinned` NO LONGER EXISTS**: superseded in Phase 54, **DELETED in
  Phase 57** (audit #4) — it survived with exactly ONE caller (a test) while the docs still
  named it as the gate, and an exported fetch-and-pin without the kit refusal is a
  ready-made bypass. The test's one call was **moved onto the real gate**, so its coverage
  is no longer illusory. Also the catchable
  **`KeyPinMismatchError`** (carries `deviceId` + BOTH safety numbers), the transport
  `listKeyEnvelopes` / `deleteKeyEnvelope`, and **`rotateVaultKey`** (pin-check EVERY
  recipient FIRST → fresh key → re-seal → wrap+upsert per recipient → delete every other
  envelope; **returns** the new key + re-sealed container for the CALLER to persist and
  push). The safety-number construction is **MIRRORED — not shared — from
  `cli/src/lib.rs`** and **MUST stay byte-identical** (same KAT on both sides; divergence
  would make two people comparing digits wrongly conclude they were under attack). ⚠️
  **`requirePinStore` FAILS CLOSED** — a missing store **throws** rather than defaulting
  to empty, because the old fallback meant a caller that forgot its pins silently got
  "every key is first-sight", i.e. the control degraded into a no-op. ⚠️ **That behaviour
  had NO TEST until Phase 57** — reverting it to fail open left every suite green — and is
  now asserted in **`sigil-wasm/test/pinning-interop.mjs`**, including that `shareVault`
  and `verifyRecipientForWrap` **refuse** rather than proceeding to an unpinned first
  sight. Proven by
  **`sigil-wasm/test/pinning-interop.mjs`** (below). It does **NO crypto itself** (SHA-256
  via `crypto.subtle`, KEM/AEAD in the wasm), so `Cargo.lock`s stay `getrandom`==0.
  **Phase 54 added the JS half of the RECOVERY KIT (ADR 0042):** six thin-shell wasm exports
  (`recovery_encode`/`recovery_decode`/`recovery_derive_ed25519_seed`/
  `recovery_derive_x25519_secret`/`recovery_derive_mlkem_seed`/`recovery_format`, adding **no
  cryptography and no codec** — all of it is `sigil-core`) plus a NEW framework-free ESM
  module **`sigil-wasm/recovery.mjs`** (`verifyRecoveryKit`, `deriveRecoveryIdentity`,
  `listRecoverableVaults`, `pinDerivedKey`/`derivedPin`, `generateRecoveryKit`, `coverVault`,
  `restoreFromKit`, `revokeRecoveryKit`, `formatRecoveryCode`, `explainRecoveryStatus`,
  `RECOVERY_DEVICE_LABEL`), and `sharing.mjs` gained the JS twin of the typed wrap gate —
  **`verifyRecipientForWrap`**, `UnverifiedRecoveryKitError`, `SafetyNumberMismatchError`,
  `RecipientsWouldBeDroppedError` and the four `TRUST_*` constants. The codec, the
  derivation and the trust rules are **MIRRORED — not shared — from `cli/src/lib.rs` +
  `libsigil/core/src/recovery.rs`** and MUST stay byte-identical (same KAT both sides;
  `sigil-wasm/test/recovery-interop.mjs` is the guard). ⚠️ **Phase 56 fixed a REAL LATENT
  BUG here:** `web/packages/sigil-wasm/index.mjs` re-exported all of `recovery.mjs` but
  **never re-exported the six `recovery_*` WASM functions themselves**, so every browser
  recovery call would have **thrown at runtime**; the missing `index.d.ts` types were a
  **SEPARATE** gap (types and runtime were two distinct holes, and closing one would not
  have closed the other). **Both are now closed**, and **both browser clients have the full
  recovery UI** (Phase 56). ⚠️ **Phase 58 fixed a silent under-report in `listRecoverableVaults`:**
  the per-device index route has a hard page cap (**500**, `maxRecipientIndexRows`) and **NO
  CURSOR**, and every client ignored `has_more` — so a kit covering more than 500 vaults would
  have recovered the first 500 and **REPORTED SUCCESS** to the one person who cannot check it
  against anything. The result now carries a non-enumerable **`truncated`** flag (so existing
  callers are byte-identical) and **`restoreFromKit` REFUSES** rather than restoring a prefix.
  ⭐ **Phase 58 also added `sigil-wasm/passkey.mjs` (ADR 0046)** — passkey protection of the
  browser's AT-REST seal. It is **browser-only** (needs `navigator.credentials` +
  `crypto.subtle`), does **no cryptography of its own** (SHA-256/HKDF via `crypto.subtle`,
  AEAD + Argon2id in the wasm), touches **no wire format and no Rust**, and is used by the
  **webapp only** — `extension/build.sh` does **NOT** vendor it, deliberately.
  ⛔ **Phase 59 fixed a LOCKOUT in that module: `userVerified` was computed and NEVER
  ENFORCED (ADR 0046's Phase 59 addendum).** CTAP 2.1's `hmac-secret` keys **TWO
  INDEPENDENT SECRETS per credential** (`CredRandomWithUV` / `CredRandomWithoutUV`) and
  the authenticator chooses by whether the ceremony verified a user, so a `UV=false`
  ceremony returns a *different, equally valid-looking* 32 bytes: at **enable** the slot
  is sealed under the wrong secret, at **unlock** it refuses, and — since an AEAD tag
  cannot tell a wrong password from a different key — a user holding a **WORKING passkey
  and the CORRECT password** was told *"wrong password or a different passkey"* and
  pushed onto the recovery sheet. ⛔ **The two-assertion determinism probe CANNOT catch
  it** (both probe assertions share one UV state, so they agree with each other and look
  healthy). `evaluatePrf` now checks the flag **BEFORE the PRF bytes are even looked at**
  and throws code **`uv_missing`**, with its own `explainPasskeyStatus` arm at enable and
  at unlock — ⚠️ **never folded into `slot_open_failed`**, because the passkey is fine,
  the password may be fine, and the fix is a real action the user can take. ⚠️ **ADR 0046
  limitation 8 is NARROWED, NOT RETIRED**: we still cannot verify that a human was
  verified, and a lying authenticator is still undetectable. The guarantee is narrower —
  **we never seal under, or try to open with, a secret from the wrong hmac-secret slot.**
  Same file, second correction: `evaluatePrf` now returns the **REAL
  `authenticatorAttachment`** from the ceremony (the webapp had been *inferring* it as
  `backupEligible ? "" : "platform"`, telling every holder of a **non-syncing SECURITY
  KEY** that their factor lived *"on this device only"* — the opposite of true, and the
  opposite of useful when the question is *"what do I have to keep safe?"*).
  ⚠️ **The guard is a NODE test, not Playwright, and that is forced:** Chrome's CDP
  virtual authenticator **cannot produce a "completed but unverified" assertion** (with
  `userVerification: "required"` it either verifies or the ceremony fails), so the
  Playwright passkey suite could not have covered this branch, at any size.
  **`sigil-wasm/test/passkey-uv-interop.mjs`** drives the SHIPPED `evaluatePrf` over a
  stubbed `navigator.credentials` — ⚠️ **that double is deliberately MORE PERMISSIVE than
  any real authenticator**, which is the point, so a PASS there is evidence about **our
  check**, not about any browser.
  ⭐ **Phase 59 also gave JS the NO-DOWNGRADE RATCHET and the FORWARD-COMPATIBLE SCHEMA**
  (ADR 0047). Two new thin-shell wasm exports — **`container_params`** (read a
  `SIGILcli` header with **no password, no KDF and no allocation**) and
  **`reseal_params`** (call `sigil-core`'s `Argon2Params::no_downgrade`) — plus
  `containerParams` / **`ratchetParams`** / **`cloneVault`** / `checkVaultReadable` /
  `formatEntryUuid` / `randomEntryUuid` / `TOTP_VAULT_READER_VERSION` in
  **`totp-vault.mjs`**, and `sharing.mjs`'s `rotateVaultKey` now ratchets instead of
  re-sealing at its hardcoded default. ⛔ **THE BUG:** every browser re-seal wrote a
  hardcoded `{m_cost:19456, t_cost:2, p_cost:1}` without reading the header it was
  replacing, so a vault the CLI wrote at **65536/4/2** came back from **ONE** browser
  edit at **19456/2/1** — a **3.4× cut in memory cost and half the passes**, silently,
  with no user action and no error, and **permanent** (a re-seal is where parameters are
  chosen). ⚠️ **`ratchetParams` FAILS OPEN** on a container it cannot parse (a corrupt
  stored value must never block a save) — it falls back to the client's own defaults,
  never to something weaker, so the dangerous direction still cannot happen.
  **`totp-migration.mjs`** gained `migrationBatchIsComplete` / `migrationBatchIsFinal` /
  `migrationBatchNote`, and ⚠️ **`decodeMigrationUri` NOW RETURNS A BATCH OBJECT, NOT AN
  ARRAY** (`{entries, version, batchSize, batchIndex, batchId, complete, finalBatch,
  batchNote}`) — a deliberate breaking change to this module's own API, chosen so that
  ignoring the framing is **visible at the call site** rather than possible by omission;
  every caller in the repo (webapp, extension, `demo/`) was updated in the same change.
  ⚠️ **`web/packages/sigil-wasm/index.mjs` had to re-export `container_params` +
  `reseal_params`** — without that, `ratchetParams` (which is handed the module namespace
  as its `wasm`) would call an undefined function and every browser re-seal would fall
  back to this build's own weaker defaults. **That is the two-hole trap from Phase 56
  again** (`index.mjs` AND `index.d.ts`), and it is why the re-export exists.
  **Phase 56 also added the JS half of ENTITLEMENT (ADR 0043):** a NEW framework-free ESM
  module **`sigil-wasm/entitlement.mjs`** (`getSubscription`, `entitlementState`,
  `describeEntitlement`, `readEntitlementHeaders`, `explainSubscriptionStatus`, the three
  `HEADER_*` constants and `PAYMENT_REQUIRED_CODE`) that reads sigild's warning headers,
  the additive `entitlement` block and the machine-readable `402`, and says the **true**
  thing about them — writes may be refused, **reads and same-account key recovery never
  are**, and a `402` is a **BILLING** state, not `401` and not `403`. It does **NO
  crypto** and holds **no state**; every request goes through the existing contract-v3
  `signedFetch`. It **had NO caller when it was written**; it now has three
  (`readEntitlementHeaders` is called from the webapp's and the extension's sync paths,
  and the whole module from their entitlement blocks). Guarded by
  **`sigil-wasm/test/entitlement-interop.mjs`** — the **only** thing in the repo that
  parses a **real** `sigild`'s entitlement bytes with the JS reader, since the browser
  suites use a double.
  ⚠️ **`sigil-wasm/test/fake-sigild.mjs` (NEW, Phase 56) is a SERVER DOUBLE, not a test.**
  It exists so a browser spec can drive a UI end to end without a Go toolchain; it verifies
  **no signature**, enforces **no ownership or grant**, implements **no entitlement gate**
  — it returns shapes. Everything cryptographic in those specs is still real (it relays
  exact bytes and holds no key, exactly as sigild does). ⚠️ It sends **NO CORS header
  unless a caller passes an explicit allowlist**: an earlier revision always sent
  `Access-Control-Allow-Origin: *`, which made six webapp specs pass green while the real
  path was dead. **A double must never be MORE permissive than the thing it doubles.**
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
  two of them, so all **seven** must stay siblings — `build.sh` also vendors
  **`recovery.mjs`** and, since Phase 56, **`entitlement.mjs`**, and the popup now has the
  **full recovery UI and an entitlement block**, not just the *wrap gate*). Storage matches the webapp: the sealed
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
  `otpauth://` + migration import/export paths round-trip (3 tests). ⭐ **Phase 56
  (ADR 0042/0043) added the SAME recovery + entitlement surfaces as the webapp:** a
  restore form reachable from the **locked/setup** views (`view-restore` — a fresh
  install is where a sheet is used), generate / cover / check / revoke, the one-shot kit
  sheet behind a *"written it down"* confirmation that clears it, and an entitlement
  block over the vendored `entitlement.mjs` (`build.sh` now vendors it beside
  `totp-vault.mjs` / `totp-migration.mjs` / `sync.mjs` / `device-auth.mjs` /
  `sharing.mjs` / `recovery.mjs`). ⭐ **The extension NEVER needed the CORS fix** — an MV3
  page with a `host_permissions` entry is **exempt from CORS**, which is why its suite
  stayed honest while the webapp's real path was dead (ADR 0044). Four new specs —
  `recovery.spec.mjs`, `wrap-gate.spec.mjs` (a second profile that never saw the sheet is
  refused and stores no envelope), `leak.spec.mjs` (the same enumerating sweep as the
  webapp — plus, since Phase 57, the **positive ADR 0036 assertion**: every value in
  `chrome.storage.local` must be a sealed `SIGILcli` container and
  `chrome.storage.session`/`sync`/`managed`, `sessionStorage`, cookies and IndexedDB must
  all be EMPTY) and `entitlement.spec.mjs` — brought it to **12 tests in 5 spec files** (now
  **14 in 6** with Phase 59's `schema.spec.mjs`), and
  they DO drive the enrollment UI, closing the old "enrollment UI is not Playwright-covered"
  gap. ⚠️ They run against the **`fake-sigild.mjs` double**, not a real server.
  Phase 57 also gave `popup.js`'s `authErr` a **402 arm** — it rendered a lapsed-account
  cross-account share as an anonymous `HTTP 402`, because no JS explainer had a 402 case;
  `explainAuthStatus` / `explainRecoveryStatus` now spell out that a 402 is a **BILLING
  state**, not an authentication or permission failure, and that reading is never refused.
  ⭐ **PHASE 59 (ADR 0047) applied the SAME three changes as the webapp**, through the
  vendored helpers: an `async sealParams(storageKey)` reading `chrome.storage.local` and
  ratcheting, passed at **both** of this popup's sealing sites (`sealVault`,
  `sealDeviceIdentity`); **`cloneVault`** in `withVault` instead of hand-rebuilding
  `{version, entries}` (which silently deleted a newer client's fields and then pushed
  the stripped vault over them); and the multi-QR batch note, keyed off
  `batch.finalBatch` so a **finished** import is not announced as incomplete. A new
  **`schema.spec.mjs`** proves the preservation property **through the real unpacked
  extension** — seeding a vault with fields no Sigil build has heard of, driving a real
  popup edit, and decrypting what the extension actually wrote — bringing the suite to
  **14 tests in 6 spec files**. ⚠️ It exists because a verifier reverted the PRODUCT half
  of the fix and the whole gate stayed green (see the webapp bullet); the module was
  covered and the popup was not.
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
  and **forty `#[tauri::command]`s** (count verified against
  `desktop/src-tauri/src/main.rs` — every one registered in `generate_handler!`; this
  line said "twenty-one", then "thirty-one", each stale within a phase or two): the ten
  offline ones (`status`, `unlock`,
  `lock`, `list`, `add_secret`, `add_uri`, `import`, `remove`, `export_uris`,
  `export_migration`), **ELEVEN added in Phase 49** (`unlock_shared`, `set_server`,
  `sync_status`, `enroll`, `publish_hybrid`, `check_server`, `convert_to_shared`,
  `push`, `pull`, `share`, `accept`), the Phase 50 key-trust ones (safety numbers,
  pins, re-pin, rotate) and **FOUR added in Phase 52** (`account_status`,
  `account_invite`, `account_invites`, `account_revoke_invite` — so the desktop has the
  **full** account flow, unlike the webapp and extension) and **NINE added in Phase 56**
  (`recovery_generate`/`_cover`/`_check`/`_verify`/`_restore`/`_revoke`/`_kits`,
  `entitlement_status`, `entitlement_refresh`), each cloning the `DeviceConfig` out of the mutex
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
  `verify_recipient_for_wrap` (the typed gate; it called `fetch_hybrid_key_pinned` before
  Phase 54, and that function no longer exists) / `rotate_vault_key` / `repin_hybrid_key`
  and keeps its pins
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
  directory name.
  ⭐ **Phase 56 (ADR 0042/0043) brought RECOVERY and ENTITLEMENT to the desktop, by the
  same REUSE-DO-NOT-REIMPLEMENT rule (ADR 0037).** `desktop/core/src/recovery.rs` +
  `entitlement.rs` and seven thin `#[tauri::command]`s (`recovery_generate` / `_cover` /
  `_check` / `_verify` / `_restore` / `_revoke` / `_kits`, plus `entitlement_status` /
  `entitlement_refresh` — **40 commands** now) call the `sigil-cli` library and add **NO
  fourth copy** of the kit codec, the HKDF derivation or the safety-number digest.
  ⚠️ **A REAL DEAD-CODE BUG was found and fixed:** the in-grace warning could never fire —
  `EntitlementView::from_subscription_block` had **ZERO production callers**, so `writes`
  was never `"grace"`. Root cause: the `sigil-cli` library exposed **no billing route at
  all**. Now wired end to end — new **`fetch_subscription`** in the CLI library →
  **`DeviceConfig::subscription()`** → the **`entitlement_refresh`** command → the UI —
  with a **real-server** test in `server_interop.rs` proving a desktop inside grace is
  **warned BEFORE any write is refused**. Mutation-confirmed. **`cli/` gained one function;
  nothing else under `cli/` was edited, and there is still no second HTTP client or signing
  path under `desktop/`.** Do NOT store real 2FA
  secrets. ADR 0032, ADR 0037, ADR 0038, ADR 0042, ADR 0043.
  ⭐ **Phase 59 (ADR 0047) reached the desktop by the same REUSE rule, and added no
  commands** (still **forty**): `ImportSummary` gained **`partial_batches`** (one note
  per multi-QR Google Authenticator batch seen) and **`batches_outstanding`**, plus
  `is_complete()`; the `import` command passes both across the IPC and `desktop/ui/main.js`
  keys its **"⚠️ INCOMPLETE"** framing off **`batches_outstanding`**, NOT off
  `partial_batches` being non-empty — importing **batch 2 of 2** used to be reported as
  *"0 more QR code(s) must be imported"*, i.e. telling a user who had just finished that
  they had not. ⚠️ `ImportSummary` is therefore **no longer `Copy`**. It inherits the
  container ceiling and the `min_reader_version` / unknown-field preservation for free
  (they are in `sigil-core` and the `sigil-cli` library). ⛔ **What it did NOT inherit:**
  `--skip-unsupported` — `export_migration_uri` calls `entry_to_migration_otp` over the
  whole vault, so a single non-30 s entry now makes the desktop's migration export fail
  **wholesale**; and the **no-downgrade ratchet does not cover `VaultSession::save`**,
  which seals at `self.params` without reading the existing container.
- `web/apps/admin` — reserved. (`web/apps/webapp` + `web/packages/sigil-wasm`,
  `extension/` and `desktop/` are now real — see above.)

## Toolchains (this machine — macOS arm64)

- **Go** 1.26.3 at `/opt/homebrew/bin/go` (go.mod directive: **1.25.0** — raised for
  the opt-in Postgres backend's `pgx`, which requires Go ≥ 1.25). ⚠️ **The dev toolchain
  is AHEAD of the shipped one and is itself vulnerable**: Go **1.26.3** carries
  GO-2026-5856 / -5039 / -5037, while the artifact is built by `golang:1.25-alpine` and
  CI pins setup-go **`1.25.x`**, where all three are fixed (1.25.11 / 1.25.12). That is
  fine for running tests, but **`govulncheck` must NOT be run with it** — it would report
  advisories that are not in the shipped binary. A **`go1.25.12`** is installed via
  `golang.org/dl` at `~/go/bin/go1.25.12` for exactly that, and `scripts/gate.sh` insists
  on it (`$SIGIL_SCAN_GO` overrides).
- **Rust** stable (rustc 1.96) via Homebrew `rustup`. ⚠️ The `~/.cargo/bin`
  proxies were **not** created, and `rustup run stable cargo` did not resolve
  subcommands. The reliable invocation is to put the toolchain bin on PATH:
  `export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/opt/homebrew/bin:$PATH"`
- **Node** 20.12 + **pnpm** 9.15 via Corepack (`corepack pnpm …`). CI uses Node 22.
- System `openssl` is **LibreSSL** — it CANNOT negotiate `X25519MLKEM768`. Any
  PQ-TLS verification needs OpenSSL 3.5+ / Go 1.24.x installed explicitly first.

## Build & test (these commands are known-green)

⭐ **`./scripts/gate.sh` is the documented way to run everything** (added Phase 56).
It runs every command below, and does several things a hand-rolled sweep does not:

- ⭐ it **RUNS ALL THREE SECURITY SCANNERS** — `govulncheck`, **`gitleaks`** and
  `cargo audit` — plus a **working-tree gitleaks scan** that CI does not do. ⚠️ **The
  first version of this block ran only TWO of `security.yml`'s THREE jobs, and the very
  next push went red on the third** (gitleaks, on the PUBLIC RFC 6238 seed
  `GEZDGNBVGY3TQOJQ…`, which trips `generic-api-key` only because Phase 59's new suites
  named the constant `RFC_SECRET` where every older suite says `RFC_SEED` — "seed" is not
  a trigger word). **A partial fix to "the gate is a subset of CI" is still that bug.**
  Accepted findings live in **`.gitleaksignore`**, pinned by fingerprint, and ⚠️ **need
  BOTH spellings** (`commit:path:rule:line` for the history scan, `path:rule:line` for the
  working-tree scan) or they reappear as permanent leaks. ⭐ **The working-tree scan exists
  because a history scan CANNOT see a secret you have not committed yet** — proven: an
  uncommitted file holding a random credential reports `no leaks found` from the history
  scan and `leaks found: 1` from the working-tree one.
- ⭐ it **RUNS BOTH OTHER SECURITY SCANNERS**, which for its first four phases it did NOT —
  making its coverage a **strict subset of CI's**, so it could not answer the question it
  exists to answer. On 2026-07-30 the `security` workflow was red on two jobs while this
  script printed ALL GREEN about that same commit. It now runs **`govulncheck`** (against
  a **`go1.25.x`** toolchain — the line the Dockerfile and CI actually ship, resolved as
  `$SIGIL_SCAN_GO` → newest `~/go/bin/go1.25.*`; **it FAILS rather than falling back** to
  the dev machine's Go 1.26.3, whose three stdlib advisories are not in the artifact) and
  **`cargo audit --deny warnings`** across all four lockfiles, where `desktop/` gets its
  acknowledged advisories from the checked-in `desktop/.cargo/audit.toml` and the other
  three must be warning-free outright;
- it **ENUMERATES** the suites **dynamically** — every Rust crate, every Go package,
  every `sigil-wasm/test/*.mjs`, every `cli/tests/*.sh`, every Playwright spec — so a
  newly added suite cannot be silently missed;
- it **RESOLVES THE REPO FROM ITS OWN LOCATION** and **prints `gating: <path> (<sha>)`**
  as its first line. ⚠️ It used to `cd` to a hardcoded absolute path, so running it from a
  git **worktree** gated the MAIN checkout instead — a planted `getrandom` stanza in the
  worktree's lockfile still printed `✓ getrandom==0`. That is not hypothetical: it
  **misled audit #4's own worktree-isolated lenses**, one of which reported ALL GREEN
  about a tree it was not looking at. **Check that first line matches the tree you meant.**
- it **COUNTS results instead of trusting exit codes**, and prints a closing
  **inventory** (a suite absent from that list is a suite nobody runs);
- ⭐ it **RUNS THE POSTGRES-GATED SUITE AND FAILS ON SKIPS.** Without a DSN ~30 tests
  skip, and PASS/FAIL counting hid that completely: **two real regressions survive a
  DSN-less run** (deleting migration `0005`'s ownership backfill, and dropping the
  active-device filter from the seat count — the Phase 52 account-bricking defect). It
  now starts a throwaway `postgres:16` on a free port when `SIGILD_TEST_POSTGRES` is
  unset, reports the skip count either way, and requires **`Postgres-gated suite RAN (0
  skips)`**. The Go numbers moved from *561 pass / 30 skip* to **640 pass / 0 fail /
  0 skip**;
- it includes a **CI-DRIFT CHECK** asserting that **every** node interop suite and
  shell e2e script is named in **some** workflow. ⚠️ This repo has **THREE TIMES**
  shipped a suite that no workflow ran — the nine interop tests for ~20 phases, then
  `accounts`+`recovery`, then `entitlement` — and it was **green locally every time**.
  The drift check is itself mutation-tested.

It also encodes two traps that make a **planted mutation appear to PASS locally**:

- **`sigil-wasm/test/fake-sigild.mjs` is a SERVER DOUBLE, not a test.** A naive
  `for t in test/*.mjs` loop runs it and **hangs**. `gate.sh` skips `fake-*` **and
  `*-helper.mjs`** (`sealed-store-helper.mjs` is a helper too). ⚠️ The **inventory line**
  used to exclude only `fake-*`, inflating the very count whose job is to make a missing
  suite visible; it now uses the same exclusion as the runner and the drift check.
  ⚠️ **The double USED TO BE MORE PERMISSIVE than real `sigild`** on four axes its header
  did not disclaim (catch-all `404`, no envelope size cap, no hybrid-key length check, no
  recipient existence/revocation check). **Phase 58 enforced all four inside the double**
  — the catch-all now answers **`501`** for unimplemented `/v1/` routes, restoring the
  *"501 by default, never 404"* invariant — and its header now states, in the file, what
  is **STILL** laxer: **no signature verification, no ownership/grant/authorization, no
  entitlement gate beyond a switch, no rate limiting, no nonce/replay window, no seat cap,
  no hash chain, no self-only check** on the per-device envelope index. **A double must
  never be more permissive than the thing it doubles** — that shape hid the CORS hole for
  twelve phases.
- It **REBUILDS the webapp and RE-VENDORS the extension first**, because webapp
  Playwright's `reuseExistingServer` will happily serve a **stale `.next`**, and
  `pnpm -C extension exec playwright test` **skips the `pretest` vendor hook** (use
  `pnpm test`). CI does both correctly; a local run does not unless you force it.
  ⚠️ **`reuseExistingServer` is now `false`** in `web/apps/webapp/playwright.config.ts`
  (Phase 58): binding to whatever `next start` happened to own port 3210 is a **false
  green** of exactly the kind this script exists to catch.
- ⭐ **Playwright SKIPS now count as FAILURES** (Phase 58), for the same reason they do in
  the Go block: a spec that quietly stops running looks exactly like one that passes. The
  `pw()` helper fails on `skipped` / `did not run` as well as `failed`.

`./scripts/gate.sh --quick` skips the shell e2e scripts **and nothing else** — in
particular it still starts the throwaway Postgres, deliberately, because a DSN-less run
silently skips ~30 tests and two real regressions have been shown to survive one. Set
`SIGILD_TEST_POSTGRES` yourself to point at an existing database instead. ⚠️ **This
paragraph used to warn that the usage line "also says it skips Postgres". That warning was
itself stale** (the line has read *"--quick skips ONLY the shell e2e scripts"* for some
time, with the Postgres reasoning spelled out directly beneath it) and was corrected on
2026-07-30 — one of **three** stale claims found in one sweep, alongside two entries in
journal.md's *"still open"* list that had already been fixed. ⭐ **A stale OPEN item is
worse than a stale status line: it points the next person's work at something already
done.** Re-verify that list at the START of a phase, not only when writing one.

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

# ACCOUNTS — the Phase 52 end-to-end proof (ADR 0040). Same shape: real sigild +
# real CLI, FOUR devices with four separate HOMEs, no mocks. Proves BOTH defects
# the account model exists to fix: (1) a device that JOINS by invite lands in the
# SAME account (the entitlement half), and (2) device A claims a vault, A is
# REVOKED, and its sibling B — granted NOTHING — still reads, writes, GRANTS on
# and ROTATES it (the orphaned-vault half; every one of those was a 403 before).
# Plus the boundary: an invite is SINGLE-USE, a device enrolled with its own
# OPERATOR token lands in a DIFFERENT account and is 403 three ways, a member may
# revoke a SIBLING but not a foreigner, and no invite secret is ever re-served.
./cli/tests/e2e-accounts.sh                       # prints PASS
# Optional, and the only gate that exercises migration 0005:
# SIGILD_OPLOG_POSTGRES=<dsn> ./cli/tests/e2e-accounts.sh

# RECOVERY KITS — the Phase 54 end-to-end proof (ADR 0042). Real sigild + real
# CLI, no mocks, twelve steps: generate a kit; scan the server log + DB for any
# leak of the printed secret; DESTROY device A and RESTORE on a clean machine
# (ephemeral vs --adopt); reject a mistyped code OFFLINE (server pointed at a dead
# port, so the checksum is doing the work); a foreign-account kit is 401; `vault
# rotate` REFUSES to silently drop the kit; a vault created after the print is
# uncovered until `recovery cover`; and — the security-critical step 9c — SHARE
# and ROTATE obey the SAME recovery-kit safety-number rule as COVER (this is the
# regression that the first implementation failed).
./cli/tests/e2e-recovery.sh                       # prints PASS
# MUTATION CHECK (run by hand, restore afterwards): disable the gate in
# verify_recipient_for_wrap and this script must go RED with
#   "expected 'recovery cover ...' to FAIL, but it succeeded".

# sigil-wasm — separate crate, wasm-bindgen binding over the core. Native fmt/
# clippy/test exercise the *_inner helpers (34 tests); build-wasm.sh emits
# pkg-web/pkg-node (needs wasm-pack); then the SIXTEEN Node suites below must all PASS.
cargo fmt   --manifest-path sigil-wasm/Cargo.toml --all -- --check
cargo clippy --manifest-path sigil-wasm/Cargo.toml --all-targets -- -D warnings
cargo test  --manifest-path sigil-wasm/Cargo.toml
./sigil-wasm/build-wasm.sh                          # → pkg-web/ + pkg-node/ (gitignored)
node sigil-wasm/test/roundtrip.mjs                  # 1/16 seal/open in a JS runtime; prints PASS, exits 0
node sigil-wasm/test/interop.mjs                    # 2/16 wasm<->CLI SIGILcli interop (builds the real CLI, both directions); PASS
node sigil-wasm/test/hybrid-interop.mjs             # 3/16 wasm<->CLI SIGILhyb hybrid public-key interop (builds the real CLI, both directions); PASS
node sigil-wasm/test/sync-interop.mjs               # 4/16 wasm<->CLI opaque op-log sync (live sigild + real CLI, both directions); PASS
node sigil-wasm/test/totp-interop.mjs               # 5/16 cross-client TOTP: CLI adds -> op-log -> browser code == RFC vector (wasm KAT + live sigild); PASS
node sigil-wasm/test/migration-interop.mjs          # 6/16 CLI<->JS TOTP migration codec agreement (GOLDEN + RUST->JS + JS->RUST; builds the real CLI); PASS
node sigil-wasm/test/device-auth-interop.mjs        # 7/16 JS client vs LIVE sigild with SIGILD_DEVICE_AUTH=1: enroll, sealed identity, claim/grant/revoke, tamper/stale/token-reuse; PASS
node sigil-wasm/test/sharing-interop.mjs            # 8/16 cross-client VAULT SHARING both ways (live sigild + real CLI): JS shares -> CLI accepts -> 94287082; CLI shares -> JS accepts -> 94287082; 403 negatives; PASS
node sigil-wasm/test/pinning-interop.mjs            # 9/16 KEY PINNING vs a SIMULATED MALICIOUS SERVER (a rewriting proxy in front of a live sigild swaps B's hybrid public key): CLI REFUSES + the stored envelope stays byte-identical and does NOT open with the attacker's secret; Rust<->JS safety numbers agree (per-device + order-independent pairwise + the shared KAT); rotation makes new content unreadable to the removed device while C still reads it; repin refuses without --yes and with a WRONG safety number; PASS
node sigil-wasm/test/accounts-interop.mjs            # 10/16 the ACCOUNT model from a BROWSER-STYLE JS client vs a LIVE sigild (device auth on): a JS device founds an account and mints an invite; the REAL `sigil` CLI redeems that JS-minted invite with the ORDINARY `device enroll --token` and lands in the SAME account; a second JS device joins too; a REVOKED device's sibling still reads and writes its vault; a separately-founded account is 403 and sees only itself; a redeemed invite is 401, a foreign invite handle 404, the open-invite quota 409, an unsigned account call 401; and a mint body carrying account_id/subject is IGNORED (no request names an account); PASS
node sigil-wasm/test/recovery-interop.mjs           # 11/16 the RECOVERY KIT codec + derivation, Rust <-> JS: the 56-char Crockford code round-trips, the shared known-answer vector (seed 0x42*32) yields identical ed25519/x25519/ML-KEM public material on both sides, U is REJECTED (never folded) while O/I/L fold, and a flipped version byte reports BAD CHECKSUM (not "unsupported version") because the checksum covers it; PASS
node sigil-wasm/test/entitlement-interop.mjs         # 12/16 the ENTITLEMENT reader vs a LIVE sigild with SIGILD_ENTITLEMENT_ENFORCE=1: the ONLY thing in the repo that parses the REAL server's warning headers, the additive `entitlement` block on GET /v1/billing/subscription and the machine-readable 402 with the JS reader (the browser suites use a DOUBLE), so a divergence between sigild's entitlementJSON / paymentRequiredResponse and entitlement.mjs would otherwise go red in NO job; PASS
node sigil-wasm/test/schema-interop.mjs             # 13/16 (Phase 59) the ONLY guard on TWO Rust<->JS mirrors that were silently LOSSY: the TotpVault/TotpEntry schema (serde DROPPED unknown fields; the JS clients rebuilt `{version, entries}` by hand, so an OLD client that merely opened and re-sealed a vault DELETED a newer client's data on a sync path where the OLDEST WRITER WINS) and the Google Authenticator BATCH FRAMING (both codecs discarded batch_size/batch_index/batch_id, so the first QR of a three-QR export imported a THIRD of the accounts and reported success). Drives the REAL `sigil` binary as the Rust half; 10 proofs, incl. min_reader_version failing closed, entry uuids, the period refusal + --skip-unsupported, the hostile-Argon2-header refusal on BOTH sides, and the JS ratchet vs the CLI's own rekey. Needs no server; PASS
node sigil-wasm/test/passkey-uv-interop.mjs         # 14/16 (Phase 59) the ONLY exercise of the passkey USER-VERIFICATION check. Chrome's CDP virtual authenticator CANNOT produce a "completed but unverified" assertion, so the Playwright passkey suite cannot reach this branch at all, at any size — and an unenforced UV means sealing the hardware slot with CTAP's OTHER hmac-secret key, i.e. the exact lockout ADR 0046 exists to prevent. Drives the SHIPPED evaluatePrf over a stubbed navigator.credentials (⚠️ a double MORE PERMISSIVE than any real authenticator — the point); 4 proofs; PASS
node sigil-wasm/test/seal-params-guard.mjs          # 15/16 (Phase 59) a SOURCE-STRUCTURE guard, not a behavioural one: every product re-seal site must ratchet its Argon2 parameters. A verifier proved mutating five of the six sites left webapp 50/50 and extension 14/14 GREEN, so this buys the regression guard for the failure that actually happens — a NEW call site that forgets. Checks 6 sealing sites across 2 product sources and FAILS if it finds ZERO; PASS
node sigil-wasm/test/portability-guard.mjs          # 16/16 ⚠️ NOT Phase 59 feature work — it belongs to the 2026-07-30 CI-portability repair that shares this working tree. The suites are WRITTEN on macOS and RUN on ubuntu-latest, and nothing checked the two agreed: six suites hardcoded /opt/homebrew/bin/go (ENOENT on every runner) and two shell proofs used `stat -f … || stat -c …`, which GNU stat does NOT fail on — so those jobs were RED for several phases while the macOS gate printed ALL GREEN. A SOURCE check, NOT a Linux run: it guards the two idioms that have actually bitten and CANNOT prove portability. PASS
# ⚠️ sigil-wasm/test/fake-sigild.mjs is a SERVER DOUBLE for the BROWSER suites, NOT a
# test — running it in a `test/*.mjs` loop HANGS. It sends NO CORS header unless a
# caller passes an explicit allowlist, deliberately matching real sigild (an earlier
# revision always sent `Access-Control-Allow-Origin: *` and hid a dead code path).
grep -c 'name = "getrandom"' sigil-wasm/Cargo.lock  # must ALSO be 0 (JS supplies entropy)

# Go server — fmt / vet / test / build
go=/opt/homebrew/bin/go
gofmt -l sigild            # must print nothing
$go -C sigild vet ./...
$go -C sigild test -race ./...   # -race is the gate; CI (sigild.yml) runs -race too since Phase 51
$go -C sigild build ./...

# SECURITY SCANNERS — the two checks CI runs that the gate did not until 2026-07-30.
# ⚠️ govulncheck MUST scan the toolchain we SHIP (go.mod `go 1.25.0`; Dockerfile
# `golang:1.25-alpine`; CI setup-go `1.25.x`), NOT this machine's Go 1.26.3 — the dev
# toolchain carries three stdlib advisories that are NOT in the artifact, and a scanner
# that cries wolf gets muted. Install the shipped line once:
$go install golang.org/dl/go1.25.12@latest && ~/go/bin/go1.25.12 download
(cd sigild && GOTOOLCHAIN=local ~/go/bin/go1.25.12 run golang.org/x/vuln/cmd/govulncheck@latest ./...)
# -> "No vulnerabilities found."
cargo install cargo-audit --locked            # once; lands in ~/.cargo/bin
for w in libsigil cli sigil-wasm desktop; do (cd $w && cargo audit --deny warnings); done
# -> all four exit 0. `desktop/` passes only because desktop/.cargo/audit.toml
#    acknowledges 17 upstream unmaintained/unsound advisories (0 vulnerabilities);
#    the other three carry NO audit.toml and must stay warning-free outright.

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
corepack pnpm --filter webapp exec playwright test   # headless chromium: 50 tests in 10 spec files, PASS
# ⛔ It serves on http://localhost:3210, NOT 127.0.0.1 — Chrome refuses WebAuthn on an IP
# literal, so every passkey spec (ADR 0046) fails there for a reason unrelated to the code.
# `workers: 2` and `reuseExistingServer: false` are also deliberate (see the config's comments).
# (wasm, offline, a11y, recovery, wrap-gate, leak, entitlement, and cors.spec.ts —
#  the ONE spec that builds + boots a REAL sigild and drives the UI against it.
#  ⚠️ cors.spec.ts test.skip()s ITSELF without a Go toolchain, so a run with no Go
#  is green while proving nothing about CORS; CI now installs Go for this job.)
# ⚠️ Playwright's reuseExistingServer will serve a STALE .next — build first (or use
# scripts/gate.sh, which does) or a planted mutation can appear to PASS.

# extension — the MV3 popup authenticator. A STANDALONE pnpm project (NOT part of
# the web/ workspace), one devDependency (@playwright/test). It needs the Rust +
# wasm-pack toolchain: build.sh runs sigil-wasm/build-wasm.sh and vendors the wasm
# + the proven JS helpers into extension/vendor/ (gitignored — must exist before
# the extension can be loaded unpacked or tested). NOT wired into CI.
corepack pnpm -C extension install
./extension/build.sh                          # -> extension/vendor/ (gitignored)
corepack pnpm -C extension test               # `pretest` re-runs build.sh; 14 tests in 6 spec files, PASS
# ⚠️ Use `pnpm test`, NOT `pnpm -C extension exec playwright test`: only the former
# runs the `pretest` vendor hook, so the latter can test a STALE extension/vendor/.
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
cargo test  --manifest-path desktop/Cargo.toml   # 25 unit + 7 integration (2 files) = 32
grep -c 'name = "getrandom"' libsigil/Cargo.lock # must STILL be 0 after desktop work
# Integration test 1 is THE VAULT INTEROP PROOF (desktop/core/tests/cli_interop.rs): it
# builds the real `sigil` binary itself and drives it against ONE shared vault file in
# both directions, so it needs no setup (~20 s: real Argon2id + a CLI build).
cargo test  --manifest-path desktop/Cargo.toml --test cli_interop -- --nocapture
# Integration test file 2 is THE NETWORK PROOF (desktop/core/tests/server_interop.rs) and
# holds SIX tests (CLAUDE.md said TWO until Phase 57 — it had not been recounted since
# Phase 51): it builds a REAL sigild (go build ./cmd/server; GO=… overrides
# /opt/homebrew/bin/go) AND the real `sigil` binary, boots sigild on a free loopback port
# with dev ops + device auth v3, and proves (a) desktop<->CLI sharing BOTH ways (94287082
# each way) plus the 403 / NotEnrolled / Unreachable negatives, (b) Phase 51's
# KEY-SUBSTITUTION ALARM: a device republishes a DIFFERENT hybrid key under the SAME id
# (`sigil device hybrid-publish --regenerate`), the share is refused as
# DesktopError::KeyPinMismatch carrying BOTH safety numbers, rotation is refused too, a
# re-pin to a WRONG number is refused, and only a deliberate re-pin resumes sharing,
# (c) a printed sheet recovering the vaults after every device is gone, (d) a sibling
# device refused a kit cover without the printed safety number, (e) a lapsed account
# refused WRITES but never reads or key recovery, and (f) a desktop inside its grace
# period WARNED before any write is refused.
# No setup, no mocks. The tests run in PARALLEL threads of one process, which
# is why Harness::start() puts an AtomicUsize counter in its temp-dir name.
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
  --all` / the `wasm32-unknown-unknown` build of `sigil-core`, **plus the `getrandom`==0
  guard on `libsigil/Cargo.lock`**.
- **`cli.yml`** — mirrors it for the standalone `cli/` crate: rustfmt / clippy / test /
  build, **plus a `getrandom`==0 guard on `../libsigil/Cargo.lock`** — `cli/` links
  `getrandom` natively on purpose, so this is the job where a leak into the wasm-pure
  core is most likely, and therefore where it is checked. The guard now runs in **four**
  workflows (`libsigil.yml`, `cli.yml`, `desktop.yml`, `interop.yml`); it previously ran
  in only the last two, so neither crate's own job checked its own invariant.
- **`sigild.yml`** — gofmt/vet/**`go test -race ./...`**/build, with a Postgres service
  container (`SIGILD_TEST_POSTGRES`) so the integration tests run rather than skip.
  ⚠️ `-race` since Phase 51: the local gate always ran `-race`, so CI was the WEAKER of
  the two on a concurrent server whose op-log, nonce cache, rate limiter and subscription
  store are all shared mutable state with concurrency tests aimed at them.
- **`web.yml`** — a Rust-free `build` job for marketing **plus** a `webapp` job carrying
  the Rust + wasm-pack toolchain (`@sigil/wasm` build + the Playwright suite) **and, since
  Phase 56, `actions/setup-go`**. ⚠️ The Go step is not optional: without it
  `tests/cors.spec.ts` **`test.skip`s itself**, so the ONLY browser-level proof of the
  CORS fix would silently skip while the job stayed green. The marketing `build` job
  stays toolchain-free.
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
  binary, runs **ALL SIXTEEN** Node interop suites (roundtrip, interop, hybrid-interop,
  sync-interop, totp-interop, migration-interop, device-auth-interop, sharing-interop,
  pinning-interop, accounts-interop, recovery-interop, **entitlement-interop** —
  the twelfth, added in Phase 56, and the **only** thing that parses a real `sigild`'s
  entitlement bytes with the JS reader — plus, added in **Phase 59**,
  **schema-interop** (the only guard on the vault schema and the migration batch
  framing across Rust and JS), **passkey-uv-interop** (the only exercise of the passkey
  user-verification check, which the Playwright suite structurally cannot reach) and
  **seal-params-guard** (no product re-seal site can silently downgrade Argon2); and
  **portability-guard**, which is ⚠️ **NOT Phase 59** but the 2026-07-30 CI-portability
  repair sharing the same working tree — the suites are written on macOS and run on
  ubuntu-latest, and nothing checked that the two agreed), and re-asserts `getrandom`==0 in both
  lockfiles. The other jobs run the **three** shell e2e scripts —
  **`cli/tests/e2e-sharing.sh`** (added Phase 51), plus **`e2e-accounts.sh`** and
  **`e2e-recovery.sh`**. They need Go + Rust + bash + curl + python3 and no wasm, so
  they are separate, parallel jobs; each resolves Go as `$GO` → Homebrew → PATH and the
  jobs set `GO: go`.
  ✅ **The "CI gap got wider" note from the Phase 53–55 journal entry is STALE** — it
  described the state while that work was in flight, and commit `fb3aa3f` closed it in
  the same commit: `accounts-interop`, `recovery-interop`, `e2e-accounts.sh` and
  `e2e-recovery.sh` are all wired. `scripts/gate.sh`'s **CI-drift check** now asserts
  this mechanically rather than by memory.
- **`security.yml`** — gitleaks (full history) + govulncheck + **cargo-audit across a
  matrix of ALL FOUR Rust workspaces** (`libsigil`, `cli`, `sigil-wasm`, `desktop`;
  Phase 51 — it audited `libsigil` only, which says nothing about the other three, and
  `desktop/` pulls the whole Tauri tree, by far the largest dependency surface here).
  ⭐ **BOTH non-gitleaks jobs were RED on `565e377` and were repaired on 2026-07-30.**
  (a) **govulncheck** flagged **GO-2026-5970** in `golang.org/x/text` **v0.29.0**,
  reachable via `pgx` (`store.NewPostgresVaultLog` → `pgxpool.NewWithConfig` →
  `norm.Form.Properties`); bumped to **v0.39.0** (and `x/sync` → 0.21.0) — both still
  INDIRECT, so `sigild` keeps **exactly one direct dependency**. ⚠️ Three *other* findings
  in a local run are an artifact of the SCANNING toolchain: this machine's Go is **1.26.3**
  (advisories GO-2026-5856/-5039/-5037) while the artifact is built by
  `golang:1.25-alpine` and CI pins setup-go **`1.25.x`**, where they are fixed in
  1.25.11/1.25.12 — verified clean with an installed `go1.25.12`. **`1.25.x` FLOATS on
  purpose**: pinning an exact patch would turn every stdlib backport into a red job.
  (b) **cargo-audit(desktop)** had **never passed**: it used `rustsec/audit-check@v2`,
  which fails on *warnings* with no acknowledgement mechanism, and the Tauri tree carries
  **17 unmaintained/unsound advisories and ZERO vulnerabilities** — so the job said the
  same thing on every commit, which is a reason to stop reading the one workflow where a
  real advisory would appear. Replaced with a direct **`cargo audit --deny warnings`**
  (using `dtolnay/rust-toolchain@stable` + `taiki-e/install-action@v2`, **both already
  used in this repo** — no new third-party action) plus a checked-in
  **`desktop/.cargo/audit.toml`** naming each accepted advisory with its owner and the
  condition that removes it. **STRICTLY STRONGER:** a *new* advisory now fails instead of
  hiding among sixteen permanent failures, and the acknowledgements are reviewable in a
  diff rather than buried in a CI flag. ⚠️ `libsigil`/`cli`/`sigil-wasm` have **no**
  `audit.toml` and must stay warning-free outright. ⭐ The GTK3/gtk-rs 0.18.x family
  (11 of the 17, incl. the one **unsound** `glib` entry) is **Linux-only and NOT in the
  macOS dependency graph at all** — `cargo tree -i atk`/`-i gdk`/`-i glib` return
  **nothing** on darwin; they are in `Cargo.lock` only because Cargo locks every platform,
  and `desktop/` has never been built for Linux from here. **That acknowledgement stops
  being theoretical the day a Linux desktop build becomes real.**
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
still runs a bare `cargo test`, which picks up **all six** `server_interop` tests; that is
intended. ⭐ **`resolve_go()`'s `$GO` → PATH → Homebrew order is the pattern the webapp's
`cors.spec.ts` was MISSING** — that spec resolved Go as `process.env.GO ?? "/opt/homebrew/bin/go"`
with **no PATH lookup**, so on CI it **`test.skip`ped ITSELF** and the only browser-level proof
of the Phase 56 CORS fix silently vanished while the job stayed green. ⚠️ **The earlier "fix"
of adding `actions/setup-go` to the webapp job did NOT work**: `setup-go` puts `go` on PATH and
**never sets `$GO`**. Phase 57 gave the spec a PATH lookup **and** set `GO: go` on the workflow
step (which `interop.yml` already did correctly). `desktop.yml` was **not** modified in Phase 51 (only `sigild.yml`, `security.yml`
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
