# Sigil (working name)

A paid, multi-platform authenticator, **designed** end-to-end encrypted and
post-quantum-ready. (Design intent, not a shipped guarantee — nothing here is
audited; see the status note below.)

> **STATUS: pre-launch / pre-audit skeleton.** This repository is the
> foundation scaffold from the 72-hour deployment sprint — _not_ a shipping
> product. The sync server is a **dev-gated** skeleton (every stateful route
> returns `501` unless explicitly enabled), but the clients are no longer stubs:
> a CLI, an offline-capable web app, an MV3 browser extension and a native
> desktop app all exist, share one sealed vault format, and are exercised by
> tests that drive the real binaries. All of it is pre-audit. ⭐ Since Phase 61
> those clients **merge** a synced vault instead of adopting the newest snapshot,
> which fixes a reproduced multi-device **data loss** — but note the limit that
> came with it: deletions write tombstones that are **never pruned**, and past the
> server's 64 KiB per-op cap syncing stops permanently
> ([ADR 0049](docs/decisions/0049-entry-identity-and-the-mergeable-vault.md)).
> `libsigil` now has **real but UNAUDITED** crypto building blocks — an
> Argon2id KDF, an XChaCha20-Poly1305 + HKDF AEAD, a C-ABI `seal`/`open`
> over them, and a hybrid (X25519 + ML-KEM-768) public-key seal in two forms —
> **anonymous** (for file encryption) and, since Phase 60, **authenticated** (a
> static-static X25519 DH folded into the KEM). Most are still
> **not wired into any product flow**; the exception is that **authenticated**
> hybrid seal, which wraps vault keys for the dev-gated device-to-device **vault
> sharing** below — real, load-bearing, and **still unaudited**. ⛔ Note the
> asymmetry: **confidentiality is hybrid, authenticity is classical X25519 only**
> ([ADR 0048](docs/decisions/0048-authenticated-vault-key-envelopes.md)).
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
  (unaudited) **hybrid public-key encryption** layer in **two** forms. The
  **ANONYMOUS** one (`hybrid_seal`/`hybrid_open`) encapsulates to a recipient's
  **hybrid public key** with the hybrid KEM and then AEAD-`seal`s the record under
  the derived key (**KEM-then-AEAD**), returning `(eph_pub, mlkem_ct, envelope)`.
  ⚠️ It is HPKE `mode_base` — it has **no sender key** — so **anyone** holding the
  recipient's public key can produce a container it will open; this repo described
  it as "authenticated" until Phase 60, which was **wrong**, and using it to
  deliver a **key** was a vulnerability. It is now used only for **file**
  encryption. The **AUTHENTICATED** one (`hybrid_auth_seal`/`hybrid_auth_open`,
  `hybrid_auth.rs`) folds in a **static-static X25519 DH between sender and
  recipient** plus a **context-bound AAD** (purpose + vault + recipient + sender),
  so a forger needs the *sender's* secret; it is what wraps a vault key, and it is
  **load-bearing** ([ADR 0048](docs/decisions/0048-authenticated-vault-key-envelopes.md)).
  Both are caller-supplied
  ephemeral X25519 secret + ML-KEM coin + AEAD nonce (no in-core randomness),
  composing the hybrid KEM + AEAD + envelope codec with no new deps. **Both are a
  CUSTOM composition — NOT RFC 9180 HPKE — and UNAUDITED. ⛔ The authenticated
  form's sender authentication is CLASSICAL X25519 ONLY** (ML-KEM has no
  static-static analogue), is **implicit and non-transferable** rather than a
  signature, and does **not** make the system "post-quantum secure", plus a
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
  **Since Phase 59 the core also owns two rules that make an *unauthenticated container
  header* safe to read** ([ADR 0047](docs/decisions/0047-container-parameter-ceiling-and-no-downgrade-ratchet.md)):
  a **ceiling** on the Argon2id work factors a `SIGILcli` header may declare
  (`MAX_M_COST` 256 MiB / `MAX_T_COST` 16 / `MAX_P_COST` 16, checked **before a byte is
  allocated**, `KdfError::ParamsTooLarge`) — because those three fields are inputs to
  the KDF and therefore cannot be authenticated, Argon2id allocates `m_cost` KiB in one
  block, and a header claiming ~4 TiB was measured taking **12.57 s and a ≈90 GB memory
  footprint** before the process was killed (0.00 s and 1.18 MB after the fix); and a
  **no-downgrade ratchet** (`Argon2Params::no_downgrade`) so a re-seal can raise the
  work factor and never lower it. ⚠️ The ceiling is a **client-side parse bound, not a
  server filter** — the sync server stores opaque blobs and by design cannot inspect or
  filter what it relays, so a hostile container is refused cheaply by every client but
  is **never removed**.
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
  three are **dev-only, NOT a finished production store** (no CRDT / merge; device
  enrollment, per-vault authorization and an **account model** now exist, but only as
  the dev-gated, unaudited opt-in model described below — and an account is auth
  metadata, **not an identity**; the Postgres backend has managed
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
  `3`/`4`/`5` once the billing, key-sharing and account migrations below are applied) —
  the opaque blob, its hash chain, and the zero-knowledge boundary are unchanged, and it
  adds no new dependency. **Dev-gated and off by default** (every device route returns
  `501` unless `SIGILD_ENABLE_DEV_OPS` is set), **UNAUDITED**, no session/JWT issuance, no
  device-key rotation, and a per-process replay cache. Enrollment and invite minting **can**
  be rate limited (opt-in, `SIGILD_ENROLL_RATE_LIMIT` / `SIGILD_INVITE_RATE_LIMIT`) — but
  behind a reverse proxy that is **one global bucket** that charges only failed attempts, so
  it is a **backstop, not a defence**; real per-source limiting belongs at the edge
  ([ADR 0041](docs/decisions/0041-abuse-bounds-and-the-removed-webhook-limiter.md)).
  Do not expose it publicly or use it for real
  secrets. See [`docs/api.md`](docs/api.md) and
  [ADR 0031](docs/decisions/0031-multi-device-auth-model.md). Ships a distroless
  `Dockerfile`.
  **An ACCOUNT — not a device — is now what owns a vault and what a subscription belongs
  to.** Before this, paying on your phone did not entitle your laptop, and revoking the
  device that first wrote a vault **orphaned that vault forever**. An account is a
  **server-assigned id on the device row**; a **single-use invite** minted by a device
  already in the account is the only way another device joins, and it rides the
  **unchanged** enrollment path (`sigil device enroll --token <invite>`), so no client
  needed a new wire format. Ownership keys off the account, so a sibling device inherits
  it; entitlement keys off the account, so paying once covers your devices. ⭐ **No
  request anywhere names an account** — the server always reads it off the signature it
  just verified, which makes a cross-account request unconstructible rather than merely
  rejected. New: `GET /v1/account` + three invite routes, `sigil account status | invite |
  invites | revoke-invite`, migration `0005_accounts.sql` (`sigild_schema_version` → `5`).
  Be clear about what it is **not**: an account is **auth metadata only — not an identity
  system**. There is **no email, no password and no operator break-glass**, and the only
  recovery is a **paper kit you printed in advance** (below): lose or revoke *every* device
  having printed nothing, and the account, its vaults and its subscription are permanently
  unreachable, by you and by us. Membership is **flat** (any member may invite, revoke
  every other member and run checkout) and **immutable** (no transfer, merge or deletion);
  membership grants **authorization, never decryption** (a joined device reads nothing
  until an existing member shares a vault key to it); an unpinned invite is a **bearer
  secret** over plain HTTP; trust-on-first-write moved up a level rather than going away
  (⚠️ and a **rejected** write used to claim a vault anyway — an empty-bodied append
  answered `400` while taking the vault id permanently; fixed in Phase 57, though
  **nothing bounds squatting with well-formed writes**, see
  [ADR 0045](docs/decisions/0045-claim-precondition-rejected-writes-never-claim.md));
  and every device enrolled before the migration was adopted into its **own** account, so
  an existing two-device setup becomes two accounts. Dev-gated, `501` by default,
  **UNAUDITED**. See [`docs/api.md`](docs/api.md) and
  [ADR 0040](docs/decisions/0040-account-model.md).
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
  particular is explicitly unverified against a real dashboard. A subscription
  now keys off the buying device's **account** (above) rather than the device —
  but an account is **not an identity** (no email, no password, no operator
  break-glass), and every device enrolled before the account migration was adopted
  into its **own** account, so an existing two-device setup has two billing
  subjects. Entitlement **enforcement** now exists but is **off by default** and
  refuses **writes only** — ⭐ **reads and same-account key recovery are never
  refused**, so a lapsed subscription can never lock you out of the 2FA codes you
  already have ([ADR 0043](docs/decisions/0043-entitlement-enforcement.md)). There
  is no fraud/chargeback/refund/tax handling and no PCI attestation, and there is
  deliberately **no rate limiting on the webhook route** — the one built for it was
  removed after it was shown to shed genuine, correctly-signed payment deliveries.
  **Nobody has been charged anything.** See
  [`docs/api.md`](docs/api.md#billing--subscriptions-dev-gated-opt-in--phase-45),
  [`docs/deployment.md`](docs/deployment.md) §13 and
  [ADR 0034](docs/decisions/0034-billing-provider-seam.md).
  **Vaults can now be shared between enrolled devices, with post-quantum-hybrid
  key wrapping.** A shared vault is sealed under a random 32-byte *vault key*; that
  key is encrypted **to the recipient device's hybrid public key** (X25519 +
  ML-KEM-768) and the result is relayed through `sigild` as an **opaque envelope
  the server cannot read** — it holds no decapsulation key and returns the bytes
  byte-for-byte. Your **password is never shared and never wrapped**, and a vault
  key is never printed (only a short SHA-256 fingerprint, so two devices can check
  they match). Authorization reuses the existing per-vault grants, so a device that
  is not the addressee gets a `403`, and a revoked device a `401`.
  ⭐ **The envelope also proves WHO sent it** (Phase 60): the wrap mixes in a
  **static-static X25519 DH between sender and recipient** and is bound to an AAD
  naming the **purpose, the vault, the recipient and the sender**, so an envelope
  cannot be forged by someone who merely knows the recipient's published key, and
  cannot be moved between vaults, recipients or senders. Before that it could —
  anyone holding a device's **published** hybrid public key could install a vault
  key of their choosing, and the receiving side never consulted the pin store at
  all. Honest limits:
  it is **dev-gated (`501` by default), localhost/plain HTTP, and UNAUDITED**; the
  wrapping is a **custom KEM-then-AEAD composition, not RFC 9180 HPKE**, so the
  **system is not "post-quantum secure"**; ⛔ the **sender authentication is
  classical X25519 only** (ML-KEM has no static-static analogue, so
  confidentiality is hybrid while authenticity is not), is **not a signature** and
  cannot be shown to a third party; and ⛔ **every envelope shared before Phase 60
  must be re-shared** — old ones are refused, including those covering a recovery
  kit ([ADR 0048](docs/decisions/0048-authenticated-vault-key-envelopes.md)).
  **Every client
  that talks to the server can now share** — the `sigil` CLI, the webapp, the
  browser extension and the desktop app — and a vault shared from one opens on the
  others; still dev-gated and unaudited.
  **Clients pin the key they share to, and you can verify it by hand.** The first
  time a client sees another device's hybrid public key it records it, and if that
  key ever changes the client **refuses to share** rather than warning — nothing is
  wrapped and nothing is uploaded. Because pinning cannot help the *first* time you
  see a key, each client can also show a **safety number**: six groups of five digits
  derived from that device's key and id, which two people read to each other over a
  phone call or in person to confirm they match. A vault key can also be **rotated**
  and re-wrapped to the devices that keep access. ⭐ **Since Phase 60 the same pin
  check runs when you ACCEPT a vault, not only when you share one** — it never did
  before, which is why pinning did not stop the forgery above — and an accepted key
  must actually **open the vault** before it is written down, and can never
  silently replace a different key you already hold. Honest limits: **first contact
  is
  trust-on-first-use unless someone actually compares the safety number**, accepting
  a changed key is a deliberate command that a user can still get wrong, **rotation
  protects only content written afterwards** (a device that already unwrapped a key
  keeps what it copied), and this is **new, unaudited code** like everything around
  it. See
  [`docs/api.md`](docs/api.md#device-to-device-vault-sharing-dev-gated-opt-in--phase-46),
  [`docs/crypto-spec.md`](docs/crypto-spec.md#key-hierarchy-and-vault-sharing-hybrid_auth_seal--hybrid_auth_open-in-use),
  [ADR 0035](docs/decisions/0035-device-to-device-vault-sharing.md),
  [ADR 0038](docs/decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)
  and [ADR 0048](docs/decisions/0048-authenticated-vault-key-envelopes.md).
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
  Phase 59 fixed two things this feature was **saying that were not true**: a
  **multi-QR** Google Authenticator import (Google splits a large export across several
  QR codes) used to report plain success while carrying only that QR's share of the
  accounts, and now says which batch it was and whether anything is still outstanding —
  on **all four** clients; and a `--migration` export of an entry whose period is not
  30 s used to be emitted **as if it were**, producing an account that generates the
  **wrong codes** in the receiving app, and is now refused, with a new
  **`--skip-unsupported`** so one unrepresentable account no longer costs you the whole
  bulk export. ⚠️ That opt-in exists **in the CLI only** — the browser and desktop
  exports now fail wholesale on such an entry.
  The sealed vault's JSON also became **forward-compatible**: unknown fields are
  preserved through an edit (an older client used to silently delete a newer one's data
  on a sync path where the oldest writer wins) and a `min_reader_version` refuses only
  the vaults that genuinely need a newer reader, **failing closed** when it is absent.
  ⭐ **Phase 61 then fixed a multi-device data loss that had been reproduced end to
  end:** a vault synced as whole snapshots and every client **adopted the newest one**,
  so a device that had never pulled could push a snapshot that **destroyed an account
  added on another device** — and both pushes reported success. A vault is now a
  **two-phase set** merged by a stable per-entry id (random for new entries; derived
  deterministically from content for entries written before the id existed, so two
  devices holding the same old vault agree without communicating), and clients fold
  **every op in the log** into their local vault instead of taking the tip. ⭐ **That
  costs nothing on the wire — the op-log had stored every snapshot all along — so it
  also brings back accounts that were already shadowed.** `sigil totp add`/`import` now
  de-duplicate on an entry's **content** rather than its label, so `work@github` and
  `work@gitlab` both survive an import that used to silently keep one.
  ⛔ **Two honest limits, and they are not small.** Deleting an entry writes a
  **tombstone that is carried forever** — nothing prunes them, there is no `compact`
  command, and past the server's 64 KiB per-op cap `push` fails permanently with no
  supported way to shrink the vault (the clients warn from 75 %, which is a warning and
  not a fix). And the merge is correct **only because entries are immutable**: there is
  no rename or edit anywhere, and adding one would silently break convergence unless it
  is expressed as delete + add with a fresh id
  ([ADR 0049](docs/decisions/0049-entry-identity-and-the-mergeable-vault.md)).
  The CLI can also **enroll as a device** and sync under **per-vault authorization**
  against a `SIGILD_DEVICE_AUTH` dev server: `sigil device enroll --token <t>` proves
  possession of a fresh key and stores the server-assigned device ID in the 0600
  identity file, after which `push`/`pull` sign under **contract v3** automatically
  (an un-enrolled key still signs the legacy contract, and no key is still unsigned —
  nothing existing changed). `sigil device grant <deviceID> --vault <id> --permission
  read|write` shares one of your vaults with another device, `sigil device list` and
  `sigil device revoke` (self, a **sibling in your account**, or operator with
  `--admin-token`) manage the registry, and `sigil account status | invite | invites |
  revoke-invite` manages **which devices are yours** — an invite is redeemed by the
  ordinary `sigil device enroll --token <invite>`, so there is no join command and no
  `--account` flag anywhere.
  **Dev / localhost / plain HTTP, no TLS, UNAUDITED** — trust-on-first-write ownership
  (by account), no identity layer, no session issuance, no device-key rotation, and
  recovery only as a **paper kit printed in advance** (`sigil recovery generate`, below).
  The CLI is also the **reference client for sharing a vault between devices** (the
  webapp and the extension do the same thing from the browser) —
  `sigil device hybrid-publish` publishes this device's hybrid public key, `sigil
  vault rekey --yes` re-seals a vault under a random vault key (your password is never
  shared) — ⚠️ **a one-way door, which is why it needs `--yes`: afterwards your password
  does NOT open that vault (not "also" — instead), the new key lives in
  `~/.sigil/vault-keys.json` in the clear, and losing that one file loses the vault; run
  it without `--yes` to read the full warning** — `sigil vault share --to <deviceID>` wraps that key to the recipient's
  hybrid public key and uploads the opaque envelope, and `sigil vault accept`
  unwraps it on the other side; `sigil totp … --vault-id <id>` then opens the shared
  vault. Keys are never printed — only a short fingerprint. `sigil device
  safety-number` prints the digits you read aloud to verify a device's key before the
  first share, `sigil device pins` lists the keys this client trusts, and `sigil vault
  rotate --to <deviceID>…` re-keys a vault and re-wraps it to exactly those devices.
  **Dev-gated and
  UNAUDITED**, and revoking a device cannot make it forget a key it already
  accepted — rotation only protects what is written afterwards (see the sharing note
  above).
  `sigil clock` answers the question every authenticator user eventually has: **is my
  clock the problem?** A TOTP code is a function of a secret *and the current time*, so a
  device drifted past half a step starts having codes rejected — and a rejected code looks
  exactly like a wrong secret, which is why people re-scan the QR, re-import, delete and
  re-add the account, and none of it helps. It compares this machine against the server's
  ordinary HTTP `Date` header (no new endpoint, no new dependency), and `push`/`pull`
  warn on their own once you have drifted far enough to start losing codes.
  ⛔ **It is a diagnostic and never a correction — nothing here changes the clock your
  codes are generated from**, and offline it says **NO READING**, which is deliberately
  not the same answer as "your clock is fine"
  ([ADR 0050](docs/decisions/0050-confirmations-honest-claims-and-the-clock-diagnostic.md)).
  **The CLI can also print and use a RECOVERY KIT** (and since Phase 56 so can the
  webapp, the extension and the desktop app).
  `sigil recovery generate | cover | check | verify | restore | revoke` produces a
  56-character code on paper whose device and hybrid keys are derived from 32 bytes of
  local randomness — **never sent to the server, and not derivable from anything the
  server holds** — so a customer who loses every device can still get their vaults back,
  and we still cannot. The server gained **no concept of recovery**: a kit is an ordinary
  member device. ⚠️ Be equally clear about the cost: **whoever holds that paper controls
  the account** — read every covered vault, revoke every device, immediately and without
  notification, with no OS lock or vault password in the way. It recovers **keys, not
  data**, only for the vaults it was told to **cover**, and **it cannot be created after
  the loss**. All four clients can now generate, cover, check, revoke and **restore** —
  which matters because `restore` runs on a **new install**, so a customer whose only
  client was a browser previously could not use the sheet they printed. See
  [ADR 0042](docs/decisions/0042-recovery-kit.md).
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
  is persisted in `localStorage` — a lost password is unrecoverable by design, unless a
  **recovery kit** was printed in advance
  ([ADR 0028](docs/decisions/0028-webapp-vault-persistence-and-unlock.md),
  [ADR 0042](docs/decisions/0042-recovery-kit.md)). It can also, **optionally**, add a
  **passkey as a second AT-REST factor**: with protection on, both sealed containers are
  sealed under a container master key derived from that same printed sheet, and the key is
  wrapped in a third sealed container under a WebAuthn PRF output concatenated with the
  password — **AND, never OR**, with the printed sheet as the only break-glass. It defends
  **stored bytes, not a running page**, is **not retroactive**, is the **only** client with
  this UI, and the sync server learns nothing about it — no route, header, migration or
  dependency changed
  ([ADR 0046](docs/decisions/0046-passkey-protected-local-containers.md)). It is an
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
  is untouched ([ADR 0032](docs/decisions/0032-native-desktop-client.md)). It now also
  **enrolls as a device, syncs its sealed vault and shares vaults** like the other
  clients — by calling the CLI's own library rather than reimplementing the protocol
  ([ADR 0037](docs/decisions/0037-desktop-reuses-cli-library-for-protocol.md)), against a
  dev-gated loopback server. **Dev,
  UNAUDITED, unsigned, unnotarized and not distributed** — no installer was built, and
  **the desktop still has no QR scanning** (the browser clients gained it in Phase 63;
  it is a browser API and does not exist here). Do not store real 2FA
  secrets.
- **Across all four clients** (Phase 62,
  [ADR 0050](docs/decisions/0050-confirmations-honest-claims-and-the-clock-diagnostic.md)):
  deleting an account now requires a **confirmation that names it**, because the button
  sits inches from the code you came to read on a row that repaints every second — and
  because a deletion now writes a tombstone that propagates and is protected against
  being resurrected, so it is *more* permanent than it used to be. ⛔ **A confirmation is
  not an undo: a confirmed delete is still permanent**, and an undo was rejected on the
  merits rather than deferred (it would have to retract a tombstone, which is
  unretractable once another device has merged it, or hold your intent in memory, where
  closing a tab discards it). Every client can also **check whether its clock is the
  problem** — a reading, ⛔ **never a correction**, and offline it reports **no reading**
  rather than claiming your clock is fine. And two clients that had been telling you, in
  the product, that they *"cannot print"* a recovery kit — false since Phase 56, with the
  button on the same screen — now say the true thing.
- **A setup code from a stranger is now bounded** (Phase 63,
  [ADR 0051](docs/decisions/0051-provisioning-bounds-and-qr-ingest.md)). An
  `otpauth://` link asking for `period=4294967295` used to be **accepted and stored**, and
  the result was a "one-time password" whose six digits **never change** — measured the
  same at t=59, at t=1.9×10⁹ and at t=4×10⁹ — displayed with an ordinary countdown. That
  is the dangerous part: the entry looks exactly like a working second factor, so you
  believe you enabled 2FA while holding a **static secret in a rotating costume**, where a
  single screenshot or shoulder-surf stays valid indefinitely. Six bounds now apply
  wherever a code is read from text you did not write (`period ≤ 600 s`, secret ≤ 1 KiB,
  labels and issuers ≤ 256 characters, no control or text-direction-override characters
  that would make one account render as another — ordinary right-to-left script is
  untouched — 6–10 digits, and ≤ 512 accounts in one bulk import). ⭐ **The bounds apply
  when something is ADDED, never when something is READ:** a vault that already contains
  such an entry still opens and still generates its codes, and now shows a warning saying
  the code does not rotate — ⛔ **a warning, never a correction, and nothing is deleted or
  changed.** There is also deliberately **no lower bound** — a short secret is the
  service's choice, and refusing it would lock you out of an account you have to use.
- **The webapp and the extension can now read a setup QR code** from a pasted screenshot,
  a dropped file or a file picker (Phase 63; no camera, and the payload is shown for you
  to **confirm** before anything is written). It is a thin shell over the browser's own
  `BarcodeDetector`, which adds no dependency and keeps a hostile image inside the
  browser's hardened decoder rather than one of ours. ⛔ **It does not work everywhere:**
  Firefox and Safari do not implement that API, and it is **secure-context gated**, so a
  page served over plain HTTP from anything other than `localhost` gets no scanner at all.
  The product says exactly that, naming **both** causes, and tells you to paste the
  `otpauth://` link instead — which does the same job.
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
desktop/         Tauri v2 native desktop authenticator — libsigil linked natively, shares the CLI's vault, syncs + shares via the CLI's library (dev, unsigned)
cli/             Rust demo CLI — `sigil` seals/opens a file via libsigil (pre-audit)
sigil-wasm/      Rust wasm-bindgen binding — in-browser seal/open demo over the core (pre-audit)
deploy/          terraform / nomad / caddy / systemd + local/ (loopback smoke) + preflight.sh
docs/            architecture, threat model, crypto spec, op-log API, sprint plan
docs/decisions/  Architecture Decision Records (ADRs)
```

Every client in this repo — the `sigil` CLI, the `sigil-wasm` JS client,
`web/apps/webapp`, the MV3 extension and the native `desktop/` app — can now **enroll
and authenticate as devices, sync, and share vaults** against a `SIGILD_DEVICE_AUTH` dev
server (loopback plain HTTP, no TLS, UNAUDITED). ⚠️ A **browser** page additionally needs
its origin listed in **`SIGILD_CORS_ORIGINS`** (opt-in, off by default, no wildcard):
signed requests carry custom headers, so a browser preflights them, and `sigild` answered
every preflight `405` until Phase 56 — which meant the webapp could not reach a real
server at all. The MV3 extension was never affected, because a `host_permissions` page is
exempt from CORS. This is **not** an authentication control — every request is
authenticated by its own per-request signature — see
[ADR 0044](docs/decisions/0044-opt-in-cors-allowlist.md); in production, serve the app and
the API from the same origin behind the reverse proxy.

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

`./scripts/gate.sh` runs all of the below plus the Node interop suites, the shell
end-to-end scripts and the browser suites — enumerating them dynamically, counting
results rather than trusting exit codes, and checking that every suite on disk is
actually run by some CI workflow. It resolves the repository **from its own
location** (so it gates the tree you ran it from, and prints which one), starts a
throwaway `postgres:16` when no `SIGILD_TEST_POSTGRES` is set, and **fails if any
test skipped** — a green run that skipped the storage layer is not a green run.
The individual commands:

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
# The suite builds the real `sigil` binary AND a real sigild itself: it proves the
# shared vault file interoperates, and that the desktop enrolls/syncs/shares as a peer.
cargo test  --manifest-path desktop/Cargo.toml     # incl. the CLI vault + live-server interop proofs
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
