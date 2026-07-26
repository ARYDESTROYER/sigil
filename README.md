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
  three are **dev-only, NOT a finished production store** (no CRDT / merge, and no
  account model — device enrollment and per-vault authorization now exist, but only as
  the dev-gated, unaudited opt-in model described below; the Postgres backend has managed
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
  restore (dev backend only; no PITR/replication yet). `sigild` also now has an **opt-in
  multi-device auth model** (op-log auth **contract v3**, enabled with
  `SIGILD_DEVICE_AUTH`; mutually exclusive with the single-key `SIGILD_OPLOG_PUBKEY`, and
  the server refuses to boot if both are set): a **device registry** of per-device Ed25519
  keys, **enrollment** (`POST /v1/devices/enroll`) that requires an operator-provisioned
  single-use token **plus a proof of possession** of the enrolling key, **per-vault
  authorization** (read/write grants, with the first device to write to an unclaimed vault
  becoming its owner), and **revocation** — so a request names *which* device signed it
  (`X-Sigil-Device`), a revoked device is refused on its next request, and "authenticated
  but not allowed" is a distinct `403` rather than a blanket `401`. It stores **auth
  metadata only** (a new `0002_devices.sql` migration; `sigild_schema_version` → `2`, and
  `3` once the billing migration below is applied) —
  the opaque blob, its hash chain, and the zero-knowledge boundary are unchanged, and it
  adds no new dependency. **Dev-gated and off by default** (every device route returns
  `501` unless `SIGILD_ENABLE_DEV_OPS` is set), **UNAUDITED**, and **not an account
  model**: no user accounts, no session/JWT issuance, no key rotation, no rate limiting on
  enrollment attempts, a per-process replay cache, and trust-on-first-write ownership that
  orphans a vault if its owner is revoked. Do not expose it publicly or use it for real
  secrets. See [`docs/api.md`](docs/api.md) and
  [ADR 0031](docs/decisions/0031-multi-device-auth-model.md). Ships a distroless
  `Dockerfile`.
  **Payment / subscription support exists in code — and only in code.** Because
  Sigil is a paid product, `sigild` carries a provider-agnostic **billing seam**
  with three adapters — **Stripe** (international), **Razorpay** and **Juspay**
  (India) — behind three routes (`POST /v1/billing/checkout`,
  `POST /v1/billing/webhook/{provider}`, `GET /v1/billing/subscription`). It uses
  **hosted checkout only**, so **no card data ever reaches the server**; webhook
  signatures are really verified (HMAC over the raw request body, constant-time),
  duplicate deliveries are idempotent, and the adapters use **no vendor SDKs**
  (the server still has exactly one third-party dependency). Be clear about what
  that is **not**: it is **UNAUDITED**, **dev-gated and `501` by default**, and
  it has **never been run against a live provider account** — every test drives a
  local fake server with fake credentials, and the **Juspay** scheme in
  particular is explicitly unverified against a real dashboard. There is no
  account model (a subscription keys off an enrolled device), no entitlement
  enforcement, no fraud/chargeback/refund/tax handling, and no PCI attestation.
  **Nobody has been charged anything.** See
  [`docs/api.md`](docs/api.md#billing--subscriptions-dev-gated-opt-in--phase-45),
  [`docs/deployment.md`](docs/deployment.md) §13 and
  [ADR 0034](docs/decisions/0034-billing-provider-seam.md).
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
  (that is what a 2FA export is) — by design, guarded by a loud warning.
  The CLI can also **enroll as a device** and sync under **per-vault authorization**
  against a `SIGILD_DEVICE_AUTH` dev server: `sigil device enroll --token <t>` proves
  possession of a fresh key and stores the server-assigned device ID in the 0600
  identity file, after which `push`/`pull` sign under **contract v3** automatically
  (an un-enrolled key still signs the legacy contract, and no key is still unsigned —
  nothing existing changed). `sigil device grant <deviceID> --vault <id> --permission
  read|write` shares one of your vaults with another device, `sigil device list` and
  `sigil device revoke` (self, or operator with `--admin-token`) manage the registry.
  **Dev / localhost / plain HTTP, no TLS, UNAUDITED** — trust-on-first-write ownership,
  no account model, no session issuance, no key rotation.
  Standalone
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
  code == the RFC vector). It can now also **import from Google Authenticator and
  export**, matching the CLI — `sigil-wasm/totp-migration.mjs` gives the browser the
  same `otpauth-migration://` bulk import + `otpauth://` import/export as `sigil totp
  import`/`export`, and the demo wires it up. The migration codec is **mirrored** in
  Rust (`cli/src/migration.rs`) and JS (`sigil-wasm/totp-migration.mjs`) and kept in
  sync by a CLI↔JS cross-tool test (`node sigil-wasm/test/migration-interop.mjs`), so
  **both clients have full 2FA import/export**; `export` prints secrets **in the clear**
  by design. UNAUDITED, generation only — **do not store real 2FA
  secrets yet**. A **standalone crate** (own lockfile),
  **UNAUDITED**, a **demo of a building block** — a custom KEM-then-AEAD (not RFC
  9180 HPKE), not the product's account/key-management/sync model, and not for real
  secrets; the system is **not** "post-quantum secure". (Public copy still obeys
  [`web/apps/marketing/MARKETING-CLAIMS.md`](web/apps/marketing/MARKETING-CLAIMS.md).)
- `web/apps/marketing/` — Next.js 15 stealth splash + early-access waitlist +
  privacy/terms/imprint stubs. **No-index, password-wallable.**
- `web/apps/webapp/` + `web/packages/sigil-wasm/` — the **first in-browser webapp**
  (dev, UNAUDITED): a real Next.js 15 app that runs the **libsigil core via
  WebAssembly entirely client-side** through the **`@sigil/wasm`** loader package
  (which wasm-packs the `sigil-wasm` crate for a bundler target and reuses the proven
  TOTP-vault / sync / migration JS helpers). It is now a **working (dev, UNAUDITED)
  authenticator**: a multi-account **encrypted TOTP vault** with add/import
  (`otpauth://` + Google Authenticator)/export and live codes computed by the wasm (not
  JavaScript). Accounts seal into a `SIGILcli` container (interoperable with the CLI
  vault); a **password unlock** decrypts it in memory and **only the sealed container**
  is persisted in `localStorage` — a lost password is unrecoverable by design
  ([ADR 0028](docs/decisions/0028-webapp-vault-persistence-and-unlock.md)). It is an
  **installable, offline-capable, accessible** authenticator PWA — a manifest + service
  worker cache the app shell / JS / `.wasm` so codes still generate with **no network**
  (only static assets are cached; the sealed vault stays in `localStorage`), and it is
  ARIA/keyboard/focus-accessible and axe-clean, with a **separate `webapp` CI job** that
  builds `@sigil/wasm` and runs Playwright (offline + a11y proofs)
  ([ADR 0029](docs/decisions/0029-webapp-pwa-offline-a11y-and-ci.md)). No-index,
  **not deployed**, and built via its own filter (needs the Rust + wasm-pack toolchain),
  so it stays **out of the default `web` CI job** and marketing/CI stay Rust-free — see
  [ADR 0027](docs/decisions/0027-webapp-and-wasm-bundling.md). Do not store real 2FA
  secrets (dev, UNAUDITED).
- `extension/` — a **browser extension client** (Manifest V3) whose popup is the same
  wasm authenticator: a multi-account **encrypted TOTP vault** with add/import
  (`otpauth://` + Google Authenticator)/export and live codes computed by the wasm.
  It seals to the **same `SIGILcli` container** as the CLI and the webapp (so vaults
  stay cross-client), stores **only the sealed container** in `chrome.storage.local`
  with the password held in memory, and asks for **one permission** (`storage`). It
  vendors the wasm + the proven JS helpers via `extension/build.sh` rather than
  reimplementing them ([ADR 0030](docs/decisions/0030-browser-extension-client.md)).
  Its dev **Sync** panel can enroll this browser as a device and sign requests, and the
  manifest's `host_permissions` are deliberately **loopback-only** (`127.0.0.1` /
  `localhost`) so the build cannot reach a remote server.
  **Dev, UNAUDITED, loaded unpacked and published to no store**. Do not store
  real 2FA secrets.
- `desktop/` — a **native desktop client** (Tauri v2): the same encrypted TOTP vault
  as a real application window, with add/import (`otpauth://` + Google
  Authenticator)/export and live codes. Unlike the webapp and the extension it links
  the libsigil core **natively — no WebAssembly** — and it reuses the CLI's container,
  vault schema and migration codec rather than reimplementing them, so it opens the
  **same vault file as the CLI** (`$HOME/.sigil/totp-vault.sigil`): add an account in
  the app and `sigil totp code` prints it, and vice versa. Only the sealed container is
  stored; the password stays in memory. Its own cargo workspace, so the wasm-pure core
  is untouched ([ADR 0032](docs/decisions/0032-native-desktop-client.md)). **Dev,
  UNAUDITED, unsigned, unnotarized and not distributed** — no installer was built, and
  there is no sync, no device enrollment and no QR scanning. Do not store real 2FA
  secrets.
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
web/             Next.js marketing + webapp (in-browser wasm authenticator) + @sigil/wasm loader (admin reserved), pnpm workspace
extension/       MV3 browser extension — popup TOTP authenticator over the wasm (dev, unpublished)
desktop/         Tauri v2 native desktop authenticator — libsigil linked natively, shares the CLI's vault (dev, unsigned)
cli/             Rust demo CLI — `sigil` seals/opens a file via libsigil (pre-audit)
sigil-wasm/      Rust wasm-bindgen binding — in-browser seal/open demo over the core (pre-audit)
deploy/          terraform / nomad / caddy / systemd + local/ (loopback smoke) + preflight.sh
docs/            architecture, threat model, crypto spec, op-log API, sprint plan
docs/decisions/  Architecture Decision Records (ADRs)
```

All four clients that talk to the dev sync server — the `sigil` CLI, the `sigil-wasm`
JS client, `web/apps/webapp` and the MV3 extension — can now **enroll and authenticate
as devices** against a `SIGILD_DEVICE_AUTH` dev server (loopback plain HTTP, no TLS,
UNAUDITED; the native `desktop/` app still has no sync).

One native client now lives **in this repo** — `desktop/`, which links `libsigil`
directly as a Rust dependency. The remaining native platform clients
(iOS/Android/Windows/Linux/watchOS/wearOS) are **unbuilt**; they are intended to live
in **separate repositories** and consume `libsigil` as a versioned binary artifact.

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

# Native desktop app (separate workspace; Tauri v2, no wasm toolchain needed)
cargo test  --manifest-path desktop/Cargo.toml     # incl. the desktop <-> CLI vault interop proof
cargo build --manifest-path desktop/Cargo.toml --release

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
