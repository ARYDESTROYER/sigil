# sigild HTTP API reference

> **STATUS: pre-audit skeleton.** `sigild` is the Sigil sync-server skeleton. It
> performs **no cryptography**, holds **no keys**, and stores **no plaintext**.
> The only stateful surface — the vault operation log — is a **dev-only,
> opt-in** store of **opaque client-encrypted blobs** the
> server never decrypts or interprets (in-memory by default, with optional
> file-backed or durable Postgres backends), **unauthenticated unless one of two
> opt-in auth contracts is configured** (legacy single-key **v2**, or the
> **multi-device v3** model with a device registry, per-vault authorization and
> revocation — itself dev-gated and unaudited). The same dev gate also opens a
> **vault-sharing relay** ([below](#device-to-device-vault-sharing-dev-gated-opt-in--phase-46)):
> the server parks a device's **public** hybrid key and an **opaque wrapped vault
> key** for a recipient device, returning both verbatim — it holds no
> decapsulation key and cannot read the envelope it relays. A **dev-gated, opt-in
> billing layer** (hosted checkout + provider webhooks, [below](#billing--subscriptions-dev-gated-opt-in--phase-45))
> stores subscription state but **no card data**, and has **never been run
> against a live payment provider**. Nothing
> here is audited or production-ready. See [`deployment.md`](deployment.md) for
> the (not-yet-applied) deploy story and [`sprint-72h.md`](sprint-72h.md) for
> scope. This reference describes the surface as wired in
> [`../sigild/internal/api/`](../sigild/internal/api/); the contract is not
> frozen.

All responses are JSON (`Content-Type: application/json`). Every request is
assigned (or honours an inbound) `X-Request-ID`, echoed on the response.

Errors use a single typed envelope:

```json
{ "error": "<stable_machine_code>", "detail": "<human-readable explanation>" }
```

Vault-scoped errors may additionally carry `"vaultID": "<id>"`. The set of error
codes is **not yet frozen** pre-audit.

---

## Probes

### `GET /healthz` — liveness

Always `200` while the process is serving. Performs no dependency checks.

```json
{ "status": "ok", "version": "<build version>" }
```

### `GET /readyz` — readiness

`200` when every *configured* dependency is healthy (or is unconfigured); `503`
when a configured dependency is unreachable, so a load balancer drains the
instance. The future `SIGILD_POSTGRES_ADDR` / `SIGILD_REDIS_ADDR` probes are
still a plain TCP dial only (no auth handshake — that is the production build's
job). The **active op-log backend**, however, now gets a **real** health check:
when the durable Postgres op-log backend (`SIGILD_OPLOG_POSTGRES`) is in use,
`/readyz` **pings its `pgxpool` connection pool** and returns `503` if that ping
fails; the in-memory and file-backed backends have no remote dependency (they do
not implement `store.Pinger`), so the live check is skipped for them and the
`oplog` key is **omitted entirely** rather than reported as `unconfigured`.

```json
{ "version": "<build version>", "checks": { "postgres": "ok|unreachable|unconfigured", "redis": "ok|unreachable|unconfigured", "oplog": "ok|unreachable" } }
```

The `postgres` / `redis` keys are always present and use the TCP-dial states
(`unconfigured` when the corresponding address env var is unset). The `oplog`
key appears **only** when the active backend implements `store.Pinger` (today:
the Postgres op-log backend) and is then only ever `ok` or `unreachable` — a
default instance therefore reports just
`{"checks":{"postgres":"unconfigured","redis":"unconfigured"},…}`.

### `GET /version` — build identity

Echoes the build name and injected version string. No secrets, no crypto.

```json
{ "name": "sigild", "version": "<build version>" }
```

The `version` value is injected at build time from the git short SHA via
`-ldflags` (default `"dev"`); see
[`../sigild/internal/buildinfo/buildinfo.go`](../sigild/internal/buildinfo/buildinfo.go).

---

## Metrics

### `GET /metrics` — Prometheus-text counters

**Always available** (independent of `SIGILD_ENABLE_DEV_OPS`), unauthenticated,
and **stdlib-only** — a hand-rendered
[Prometheus text exposition](https://prometheus.io/docs/instrumenting/exposition_formats/)
(`Content-Type: text/plain; version=0.0.4`) of process counters, so an operator
can scrape `sigild` without adding a metrics client library. It exposes **only
monotonic counters and the build version — never any blob, key, signature,
nonce, vault content, or other secret** (a metrics endpoint that leaked payload
would break the zero-knowledge property; this one cannot, because it holds
nothing but counts).

The exported series (names follow Prometheus conventions; the endpoint itself is
the source of truth for the exact strings):

| Metric | Type | Meaning |
|--------|------|---------|
| `sigild_http_requests_total{class="…"}` | counter | total HTTP responses served, by status class (`1xx`…`5xx`) |
| `sigild_oplog_appends_total` | counter | op-log appends accepted (`POST …/ops`) |
| `sigild_oplog_verify_total` | counter | chain verifies run (`GET …/ops/verify`) |
| `sigild_oplog_auth_denied_total{reason="…"}` | counter | request auth/authz denials, **labelled by reason** (the fixed enum below) |
| `sigild_oplog_authz_denied_total` | counter | requests denied by **per-vault authorization** (HTTP `403`) — a subset of the above, broken out so an operator can alert on `403`s alone |
| `sigild_oplog_ratelimit_rejected_total` | counter | appends rejected with `429` by the per-vault rate limiter |
| `sigild_device_enrollments_total` | counter | device enrollments accepted (`POST /v1/devices/enroll`) |
| `sigild_device_enroll_denied_total{reason="…"}` | counter | enrollment attempts denied, labelled by reason |
| `sigild_device_revocations_total` | counter | device revocations performed |
| `sigild_vault_grants_total` | counter | per-vault access grants created |
| `sigild_vault_claims_total` | counter | vault ownership claims (trust-on-first-write) |
| `sigild_device_hybrid_keys_published_total` | counter | device hybrid **public** key publishes, including re-publishes (`PUT /v1/devices/{deviceID}/hybrid-key`) |
| `sigild_vault_key_envelopes_total` | counter | opaque wrapped-vault-key envelopes deposited (`PUT /v1/vaults/{vaultID}/keys/{deviceID}`) |
| `sigild_vault_key_envelope_fetches_total` | counter | envelopes collected by their recipient (`GET /v1/vaults/{vaultID}/keys/{deviceID}`) |
| `sigild_billing_checkouts_total{provider="…"}` | counter | hosted checkout sessions created, by provider (`stripe`/`razorpay`/`juspay`) |
| `sigild_billing_webhooks_total{provider="…",outcome="…"}` | counter | **authenticated** webhooks handled, by provider and outcome (`accepted`, `ignored`, `duplicate`, `stale`, `illegal`, `unresolved`) |
| `sigild_billing_webhook_rejected_total{reason="…"}` | counter | webhooks rejected **before** application, by reason (`bad_signature`, `malformed`, `unknown_provider`, `payload_too_large`, `store_error`) |
| `sigild_billing_subscription_transitions_total{status="…"}` | counter | **applied** subscription status transitions, by target status (`none`, `trialing`, `active`, `past_due`, `canceled`) |
| `sigild_schema_version` | gauge | applied op-log DB migration version (`0` when the backend is not Postgres; **`4`** once `0004_key_sharing.sql` is applied) |
| `sigild_build_info{version="…"}` | gauge (`1`) | build identity; the version label carries the injected build SHA |

Counters are **process-lifetime and unlabelled by vault or device** (no per-vault
cardinality blow-up, and no vault ID or device ID — a device-ID label would let a
scrape enumerate the registry — is exported). The endpoint performs **no
cryptography** and reads no stored bytes; it only reports aggregate counts, and
it never exposes a public key, an enrollment token or its digest, an admin
token, a signature, or a nonce. The three **vault-sharing** counters follow the
same rule: they are counts only, carrying no envelope byte, no hybrid public key,
no vault key, and no vault or device ID as a label.

Every **billing** label above comes from a **closed set materialized at startup**
(the three provider names, the six outcomes, the five rejection reasons, the five
statuses), so a scrape can neither enumerate what is configured nor be made to
create a new series. The billing counters carry **no API key, webhook secret,
signature, event ID, subject/device ID, customer reference, or amount**.

`sigild_schema_version` reflects the applied op-log database migration version for
the **Postgres backend**; migrations are managed with an **operator CLI**, not an
HTTP endpoint — `sigild migrate` applies pending migrations and `sigild migrate
status` reports them (default auto-apply at boot, opt out with
`SIGILD_OPLOG_AUTO_MIGRATE=0`). See
[`deployment.md` §11](deployment.md#11-schema-migrations-postgres-backend).

---

## Vault operation log (DEV-ONLY)

> **READ THIS FIRST. This endpoint is a development scaffold, not a product.**
>
> - **DEV-GATED, default OFF.** It exists only when the server is started with
>   the environment variable **`SIGILD_ENABLE_DEV_OPS`** set (truthy). With the
>   variable **unset — the default and the only production-safe setting — every
>   verb on this route returns `501 Not Implemented`.** This preserves the
>   project guardrail of stubbing with `501` rather than shipping behaviour that
>   would poison the future audit.
> - **UNAUTHENTICATED BY DEFAULT.** With no auth configured there is no
>   identity and no per-vault access control: anyone who can reach the port can
>   read and append to any vault ID. Two **opt-in** contracts change that —
>   legacy **v2** (`SIGILD_OPLOG_PUBKEY`, one static key, no authorization) and
>   the **v3 multi-device model** (`SIGILD_DEVICE_AUTH` — device identity,
>   per-vault grants, revocation; see
>   [Multi-device auth model](#multi-device-auth-model-contract-v3--dev)). They
>   are mutually exclusive, and both are dev-gated and **UNAUDITED**.
> - **THREE BACKENDS behind the `VaultLog` seam.** With the dev flag on, the
>   op-log is served by one of three interchangeable backends, selected at
>   startup by **precedence `SIGILD_OPLOG_POSTGRES` > `SIGILD_OPLOG_DIR` >
>   in-memory**:
>   - **in-memory (default)** — a process-memory map; **lost on restart**, never
>     written to disk, not replicated.
>   - **file-backed** (**`SIGILD_OPLOG_DIR`**) — persists each vault's journal
>     under that directory for **local-dev durability** (the `vaultID` is
>     base64url-encoded to a safe flat filename, so it cannot escape the
>     directory). A local-dev convenience, still **not** the production store.
>   - **durable Postgres** (**`SIGILD_OPLOG_POSTGRES`** = a libpq DSN) — a real,
>     **durable and concurrent** backend on the `pgx` driver (`sigild`'s first
>     third-party dependency), with per-vault sequencing made concurrency-safe by
>     a transaction / advisory lock. This adds durability and concurrency but is
>     **NOT a finished production store**: it still has no auth model, no
>     enrollment, no CRDT/merge, and no production backup/replication (PITR).
>     (Schema changes _are_ now **managed migrations**, and a **`pg_dump`/restore
>     runbook** whose integrity gate is `/ops/verify` exists — see
>     [`deployment.md` §11](deployment.md#11-schema-migrations-postgres-backend).)
>
>   All three are the **same opaque, dev-only, unauthenticated `VaultLog`** — the
>   server does **no cryptography**, never decodes the bytes, and re-emits them
>   unchanged; the 64 KiB per-op cap and `413` apply to all. See
>   [`decisions/0006-file-backed-dev-op-log-backend.md`](decisions/0006-file-backed-dev-op-log-backend.md)
>   and [`decisions/0014-postgres-durable-oplog-backend.md`](decisions/0014-postgres-durable-oplog-backend.md).
> - **OPAQUE BLOBS ONLY.** The server treats each operation body as an opaque
>   byte string. It does **no cryptography**, never sees plaintext or keys, and
>   does **not** parse, validate, decrypt, order, merge, or otherwise interpret
>   the bytes. Confidentiality is entirely the client's responsibility — the
>   client is expected to encrypt before sending. `sigild` is dumb storage of
>   ciphertext, by design.
> - **NOT a real op log.** "Operation log" here means an append-and-read byte
>   journal with a monotonic per-vault sequence number and a per-op SHA-256
>   **hash chain** for **tamper-evidence** (see
>   [Op-log hash chain](#op-log-hash-chain-tamper-evidence) and `GET …/ops/verify`
>   below). That chain is tamper-*evident*, **not** tamper-*proof*: a hostile
>   server can still lie about it (real verification is client-side). There is
>   still **no** CRDT merge, no Lamport clock, no Merkle root, no signature
>   checking on ops, and no conflict resolution — those are deferred to the
>   production build.
> - **DO NOT EXPOSE PUBLICLY** and **DO NOT STORE REAL SECRETS.**

When `SIGILD_ENABLE_DEV_OPS` is set, the following two operations are served. A
single operation body is capped at **64 KiB**; an oversized request is rejected
with `413` (see [`../sigild/internal/api/middleware.go`](../sigild/internal/api/middleware.go)).

### `POST /v1/vaults/{vaultID}/ops` — append an operation

Append one opaque, client-encrypted blob to the named vault's log.

- **Request body:** raw opaque bytes (the client's ciphertext). The server does
  not require, parse, or impose any structure.
- **Success — `201 Created`:**

  ```json
  { "vaultID": "<vaultID>", "seq": <monotonic per-vault sequence number> }
  ```

  `seq` is assigned by the server, strictly increasing per vault, starting at 1.

- **Errors** (typed `{error, detail}` envelope):

  | Status | `error` code | When |
  |--------|--------------|------|
  | `413 Request Entity Too Large` | `payload_too_large` | body exceeds the 64 KiB per-operation cap |
  | `429 Too Many Requests` | `rate_limited` | the per-vault append rate limit is exceeded (only when `SIGILD_OPLOG_RATE_LIMIT` is set); the response carries a `Retry-After` header (seconds) |
  | `501 Not Implemented` | `not_implemented` | `SIGILD_ENABLE_DEV_OPS` is unset (the default) |

  **Optional per-vault rate limit.** By default appends are unthrottled. When
  `sigild` is started with **`SIGILD_OPLOG_RATE_LIMIT`** set (a positive
  sustained rate in appends/second per vault, optionally with
  **`SIGILD_OPLOG_RATE_BURST`** for the bucket depth), each vault gets an independent
  **token-bucket** limiter: appends beyond the vault's refill rate get `429
  rate_limited` with a `Retry-After` header telling the client when a token will
  be available. The limit is **per vault ID** (a busy vault cannot starve
  others), stdlib-only, and **off unless configured** — with the variable unset,
  behaviour is exactly as before. It shapes append *rate* only; it never inspects
  or interprets the opaque blob.

### `GET /v1/vaults/{vaultID}/ops?since=N&limit=M` — read operations

Return the vault's operations with sequence number **greater than `N`** (default
`since=0` returns from the beginning), in ascending `seq` order, **bounded** to at
most `limit` ops per response so a large vault is read in pages rather than one
unbounded slice.

- **Query:**
  - `since` (optional, integer, default `0`) — return ops with `seq > since`.
  - `limit` (optional, integer, default **`500`**, max **`1000`**) — cap the
    number of ops returned by this call. An out-of-range or non-integer value
    (`≤ 0`, `> 1000`, or non-numeric) is rejected with `400 bad_limit`.
- **Success — `200 OK`:**

  ```json
  {
    "vaultID": "<vaultID>",
    "ops": [
      { "seq": 1, "blob": "<base64 of the opaque stored bytes>", "hash": "<std-base64 SHA-256 chain hash>" }
    ],
    "next": <highest seq returned, to pass as the next `since`>,
    "has_more": <true if more ops exist beyond this page, else false>
  }
  ```

  `blob` is the standard base64 encoding of the exact opaque bytes that were
  POSTed — the server re-emits ciphertext it never decoded. An unknown vault ID
  returns an empty `ops` array, not an error.

  `hash` is the op's **standard-base64-encoded SHA-256 hash-chain link** — the
  tamper-evidence tip for that op, computed over the previous op's hash and this
  op's `(vaultID, seq, blob)` per the construction in
  [Op-log hash chain](#op-log-hash-chain-tamper-evidence) below. It fingerprints
  **ciphertext only** (the server does no crypto on the plaintext), and it lets a
  client re-derive and verify the chain **itself**, without trusting the server.

  **Pagination.** `has_more` is `true` when the vault holds ops with `seq` beyond
  the page just returned. A client drains the log by looping: request, process the
  page, then re-request with `since = next` until `has_more` is `false`. `next` is
  the highest `seq` in the page (unchanged from `since` when the page is empty), so
  the loop always makes progress and terminates. This bounds both server memory
  and response size regardless of vault length.

- **Errors** (typed `{error, detail}` envelope):

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `bad_limit` | `limit` is non-integer, `≤ 0`, or `> 1000` |
  | `501 Not Implemented` | `not_implemented` | `SIGILD_ENABLE_DEV_OPS` is unset |

### Op-log hash chain (tamper-evidence)

> **Tamper-EVIDENT, not tamper-PROOF, and not a security claim.** This detects
> after-the-fact tampering with the stored ops; it does **not** prevent it and
> does **not** make `sigild` a notarized, append-only-enforced, or
> Byzantine-fault-tolerant log. The **real** guarantee is **client-side**: verify
> the chain yourself from the per-op `hash` values. See the honesty note below.

Every stored op carries a **hash-chain link** so a verifier can detect whether
any op was **inserted, deleted, reordered, or modified**. Each op's hash commits
to the previous op's hash, so altering op *k* changes the hash of *k* and of
**every** op after it. The construction, shared by **all three backends**
(in-memory, file-backed, Postgres), is:

```
hash(seq) = SHA-256(
      "sigil-oplog-chain-v1"     // ASCII domain-separation label
   || len(vaultID) || vaultID    // length-prefixed vault ID (4-byte big-endian length, then bytes)
   || seq                        // 8-byte big-endian sequence number
   || prev_hash                  // previous op's 32-byte hash; genesis = 32 zero bytes
   || blob                       // the opaque client-encrypted bytes, verbatim
)
```

- **Genesis:** for the first op in a vault (`seq = 1`), `prev_hash` is 32 zero
  bytes.
- **Domain separation:** the `"sigil-oplog-chain-v1"` label and the length-prefix
  on `vaultID` make the field boundaries unambiguous, so a chain for one vault
  can never be confused with another and the version can be rotated later.
- **Opaque, zero-knowledge preserved:** the hash is taken over the **already
  client-encrypted** `blob`. Hashing ciphertext fingerprints it for
  tamper-evidence but reveals **no plaintext** and needs **no key** — the server
  still does no cryptography on vault contents. See
  [`threat-model.md`](threat-model.md).

The per-op `hash` is returned inline by `GET …/ops` (above), so a client can
recompute the chain locally and compare.

### `GET /v1/vaults/{vaultID}/ops/verify` — server-side chain check

Recompute a vault's entire hash chain server-side and report whether it is
intact. Same **dev-gate** and (optional) **auth** as the other op-log routes:
`501` when `SIGILD_ENABLE_DEV_OPS` is unset; `401` when `SIGILD_OPLOG_PUBKEY` is
set and the request is missing/invalid/stale/replayed (the signed message uses
the request's own method/path/query, exactly as for `GET …/ops`).

- **Success — `200 OK`:**

  ```json
  {
    "vaultID": "<vaultID>",
    "ok": true,
    "count": <number of ops in the vault>,
    "tip_hash": "<std-base64 SHA-256 of the last op's chain link>",
    "broken_at_seq": null
  }
  ```

  - `ok` — `true` if the recomputed chain matches every stored per-op hash. An
    empty vault is trivially intact (`ok = true`, `count = 0`).
  - `count` — how many ops were checked.
  - `tip_hash` — the last op's std-base64 chain hash (the vault's current tip); an empty
    vault has no ops, so there is no meaningful tip.
  - `broken_at_seq` — `null` when `ok` is `true`; otherwise the **first** `seq`
    whose recomputed hash does not match, i.e. where tamper-evidence tripped.

- **Errors:** `501 Not Implemented` when dev-ops is off; `401 Unauthorized` when
  auth is configured and the request fails it.

**Honesty note — what `/ops/verify` is and is NOT.** A server-side check is a
**convenience**, not a root of trust: a **malicious server can lie** — it can
recompute a perfectly consistent chain over data it has itself doctored, or
simply return `{"ok": true}`. So `/ops/verify` only catches **accidental**
corruption and a **non-adversarial** operator's storage faults. The guarantee
that actually resists a hostile server is **client-side**: the client keeps its
own tip hash and re-derives the chain from the per-op `hash` values in
`GET …/ops`. This is a **dev-scale, tamper-EVIDENT** down-payment on the
product's future **signed / Merkle-root** audit log — not a notarized,
append-only-enforced, or Byzantine-proof log.

### Authentication — contract v2 (LEGACY, optional, dev) — `SIGILD_OPLOG_PUBKEY`

> **SUPERSEDED, BUT STILL PRESENT.** Contract **v2** below is the original
> **single static key** mode. It is unchanged and still supported, but the
> **multi-device model (contract v3)** — [below](#multi-device-auth-model-contract-v3--dev)
> — is the model with device identity, per-vault authorization, and revocation.
> The two are **mutually exclusive**: setting both `SIGILD_DEVICE_AUTH` and
> `SIGILD_OPLOG_PUBKEY` makes `sigild` **refuse to boot** (a fail-fast config
> error before the listener binds), so exactly one contract is ever live.

> **DEV-ONLY, off by default, and intentionally minimal.** This is a
> **single static device key** check, not an account/enrollment system. Each
> request is signed with a **fresh per-request nonce**, and the server keeps a
> **time-bounded, in-memory seen-nonce cache**, so a captured request cannot be
> replayed within the 300-second timestamp window (**contract v2** — it
> **supersedes v1**). That cache is **per-process**; a multi-instance deployment
> would need a shared nonce store (e.g. Redis). Full device enrollment, a
> multi-device registry, and JWT bearer tokens (see
> [`../sigild/internal/auth/`](../sigild/internal/auth/)) remain **future**. Still
> plain-HTTP, dev-gated, and not for real secrets. See
> [`decisions/0008-device-key-request-auth.md`](decisions/0008-device-key-request-auth.md)
> and [`decisions/0010-op-log-auth-v2-nonce-replay.md`](decisions/0010-op-log-auth-v2-nonce-replay.md).

By default the dev op-log is **unauthenticated** (above). When `sigild` is
started — with dev-ops on — **and** the environment variable
**`SIGILD_OPLOG_PUBKEY`** is set to the **standard-base64 encoding of a 32-byte
Ed25519 public key**, the op-log additionally requires a per-request Ed25519
signature. With `SIGILD_OPLOG_PUBKEY` **unset (the default), there is no auth**
and behaviour is exactly as described above.

When configured, **both** `POST` and `GET /v1/vaults/{vaultID}/ops` requests
**MUST** carry three headers:

| Header | Value |
|--------|-------|
| `X-Sigil-Timestamp` | the signing timestamp, unix **seconds**, decimal ASCII (e.g. `1717900000`) |
| `X-Sigil-Nonce` | standard-base64 of a **fresh, per-request** random nonce of **≥ 16 bytes** from a CSPRNG; the exact header string is signed **verbatim** so both sides agree |
| `X-Sigil-Signature` | standard-base64 of the 64-byte Ed25519 signature over the message below |

The signed **message** (raw bytes) is a fixed 6-line ASCII prefix —
lines joined by a single `\n` (`0x0A`), **with a trailing `\n` after the
nonce** — immediately followed by the raw request **body** bytes:

```
sigil-oplog-auth-v2\n
{METHOD}\n          uppercase HTTP method — "POST" or "GET"
{PATH}\n            URL path, NO query — e.g. /v1/vaults/demo/ops
{QUERY}\n           raw query string, or "" if none — e.g. since=0
{TIMESTAMP}\n       same decimal value sent in X-Sigil-Timestamp
{NONCE}\n           EXACT X-Sigil-Nonce header string (base64 text, verbatim)
{BODY}              raw request body bytes; EMPTY for GET
```

That is, byte-for-byte:

```
MESSAGE = "sigil-oplog-auth-v2\n" + METHOD + "\n" + PATH + "\n" + QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + BODY
```

The client generates a fresh random `NONCE` (**≥ 16 CSPRNG bytes**,
standard-base64), sends it as `X-Sigil-Nonce`, signs `MESSAGE` with its 32-byte
Ed25519 secret seed (the demo `cli` uses `sigil_core::{sign,
public_key_from_seed}`), and sends the signature in `X-Sigil-Signature` and the
same timestamp in `X-Sigil-Timestamp`. This is **contract v2**; it **supersedes
v1** — a v1 message (which had no nonce line) no longer verifies, and there are
no external v1 clients to break, so it is a clean break.

The server, when `SIGILD_OPLOG_PUBKEY` is configured, verifies on both verbs, in
**this order**:

1. read `X-Sigil-Timestamp`, `X-Sigil-Nonce`, and `X-Sigil-Signature`; any
   missing or blank → `401`.
2. parse the timestamp as `int64`; if it is not an integer **or** the skew
   `abs(now - ts)` exceeds **300 seconds** → `401` (stale/skew).
3. reconstruct the v2 `MESSAGE` from the request method, path, raw query, the
   timestamp header, the **raw nonce header**, and the (size-limited) body;
   base64-decode the signature and `ed25519.Verify(pubkey, MESSAGE, sig)`; if it
   does not verify → `401`.
4. **replay check** — done **only after** a valid signature, so unauthenticated
   probes never touch the cache: if this nonce is already in the server's
   seen-nonce cache (and not yet expired) → `401` (replayed request); otherwise
   **record** the nonce with its timestamp and fall through to the normal
   append/read handler above.

The **seen-nonce cache** is in-memory, concurrency-safe, and **time-bounded**:
an entry is evicted once its timestamp is older than `now - 300s` — a nonce is
remembered for exactly as long as a request bearing it could still pass the
timestamp check (step 2) — with a hard size cap as a safety backstop. It is
therefore a **per-process** guard: a multi-instance deployment would need a
shared nonce store (e.g. Redis). A given nonce is thus accepted **at most once**
within the timestamp window.

All failures use the standard typed envelope with `401 Unauthorized` (a distinct
`detail` marks a replayed nonce; the `error` code stays `unauthorized`):

```json
{ "error": "unauthorized", "detail": "<reason>" }
```

The matching CLI key file (`sigil keygen --out <file>`) is JSON, written with
mode `0600`:

```json
{ "version": 1, "seed": "<std-base64 of 32 bytes>", "public_key": "<std-base64 of 32 bytes>" }
```

The same file is also the **device identity** file for contract v3: `sigil
device enroll` adds an **optional `"device_id"`** field to it. The field is
absent here by construction, and a key file **without** it keeps signing v2
exactly as before — see [Client support](#client-support-the-sigil-cli).

**Honest scope:** a single configured DEV device key; the seen-nonce replay
cache is **in-memory / per-process** (a multi-instance production deploy needs a
shared store); multi-device enrollment and a device registry exist only in
**contract v3** ([below](#multi-device-auth-model-contract-v3--dev)), never in
this mode, and JWT / session issuance is still future; and with
`SIGILD_OPLOG_PUBKEY` unset there is no auth at all.

### Audit log (structured server-side events)

Every op-log **append**, **list**, **verify**, and **auth denial** — plus every
device **enrollment**, **enrollment denial**, **revocation**, **vault ownership
claim**, and **grant** — emits a **structured audit event** to the server log
(alongside the request-scoped access log). Each event carries only **metadata
plus an integrity fingerprint** — never the payload:

| Field | Meaning |
|-------|---------|
| `event` | the audited action — `oplog.append`, `oplog.list`, `oplog.verify`, `oplog.auth_denied`, `device.enrolled`, `device.enroll_denied`, `device.revoked`, `vault.claimed`, `vault.granted` |
| `request_id` | the request's `X-Request-ID`, to correlate with the access log |
| `vault_id` | the target vault ID (opaque, client-chosen) |
| `seq` | the sequence number assigned (append) or the highest returned (list) |
| `size_bytes` | the opaque blob's length in bytes |
| `blob_sha256` | hex **SHA-256 fingerprint** of the opaque stored bytes — for integrity / traceability only |
| `auth` | on an append, which contract was active: `device` (v3), `ed25519` (legacy v2), or `none` |
| `reason` | on a denial, the fixed enum naming the single check that failed (see [the reason enum](#denial-reasons-audit--metrics-only)) |
| `device_id` | on the device events and on a denial, the device ID the client **presented** (empty in the legacy/no-auth modes; recorded even when it resolved to nothing, so probing is visible) |
| `label` / `permission` / `revoked_by` | the enrolled device's label; the permission granted; who performed a revocation (`admin`, or the device's own ID for self-revocation) |

The server logs a **fingerprint** of the ciphertext, **not** the ciphertext: it
**NEVER** writes the opaque blob content, any signature, nonce, timestamp value,
public key, enrollment token (or its digest), admin token, or other key material
to the log. Because the fingerprint is taken over bytes that are **already
client-encrypted**, an operator can prove *who appended what, when* without the
server ever seeing plaintext — the audit trail does not weaken the
zero-knowledge property (see [`threat-model.md`](threat-model.md)).

Request bodies are read under the **request context**: a client that
disconnects, or a read that exceeds the server's `http.Server` timeouts, cancels
the in-flight append/read (and, for the Postgres backend, releases the pooled
connection) rather than blocking a goroutine.

---

## Multi-device auth model (contract v3) — DEV

> **DEV-GATED, OPT-IN, and UNAUDITED.** This is a **real** auth model — real
> `crypto/ed25519` verification against a real device registry, real per-vault
> authorization, real revocation, no bypass path, no fallback "trusted" key, and
> no hardcoded credential — but it is **dev-gated** behind
> `SIGILD_ENABLE_DEV_OPS`, **off by default**, has **not been audited**, and is
> **not** the product's account/session model. There is no user account, no
> session or token issuance, no key rotation, no recovery, no hardware
> attestation, and **no rate limiting on enrollment attempts**. Still plain
> HTTP in dev. **Do not expose publicly and do not store real secrets.** See
> [`decisions/0031-multi-device-auth-model.md`](decisions/0031-multi-device-auth-model.md).

Contract **v3** replaces v2's one static key with a **device registry**: every
authenticated request names **which** enrolled device signed it, the server
verifies the signature against **that device's** registered Ed25519 public key,
refuses a **revoked** device, and then checks that the device holds a **grant**
on the requested vault.

### Configuration

| Variable | Required? | Meaning |
|----------|-----------|---------|
| `SIGILD_DEVICE_AUTH` | opt-in | `1`/`true` turns on the v3 model. **Requires `SIGILD_ENABLE_DEV_OPS`** (the op-log and its auth model are dev-gated) and is **MUTUALLY EXCLUSIVE with `SIGILD_OPLOG_PUBKEY`** — with both set, `sigild` **exits non-zero at startup** rather than running an ambiguous model. |
| `SIGILD_ENROLL_TOKENS` | **required when device auth is on** | Comma-separated operator-provisioned enrollment tokens (bootstrap bearer secrets). Each must be **≥ 16 characters**; duplicates are rejected. Only their **SHA-256 digests** ever reach the server's memory, the registry, the audit log, or `/metrics` — the plaintext is never stored. Without at least one token, **no device can ever enroll**. |
| `SIGILD_ENROLL_TOKEN_TTL` | optional | A **positive Go duration** (e.g. `24h`). A token then expires that long after it was **first registered** — registration is idempotent, so restarts do not extend the clock. **Unset ⇒ tokens never expire, but remain SINGLE-USE.** |
| `SIGILD_ADMIN_TOKEN` | optional | Operator token for the operator-only routes (list all devices, revoke **any** device); **≥ 16 characters**. **Unset ⇒ those paths are permanently `401`** — there is **no implicit open-admin mode**. Compared in constant time; never logged or exported. |

All four are parsed and validated **fail-fast, before the listener binds**; a
malformed value is a clear startup error, not a surprise at request time.

**Registry durability.** When the Postgres op-log backend
(`SIGILD_OPLOG_POSTGRES`) is active, the registry is durable and **shares that
backend's existing `pgxpool`** (no second pool, no new dependency), using tables
from migration `0002_devices.sql`; Postgres then enforces single-use tokens and
single-owner vault claims **across processes**. Otherwise the registry is
**in-memory and non-durable** — devices, grants and spent-token markers are lost
on restart, which means a **spent enrollment token becomes reusable after a
restart** (the server warns loudly at boot). The **file backend
(`SIGILD_OPLOG_DIR`) was not extended**: device auth alongside it falls back to
the in-memory registry, also warned at boot.

### Storage (migration `0002_devices.sql`)

Three tables are added on top of the untouched `0001_init`:

| Table | Holds |
|-------|-------|
| `sigil_devices` | `device_id` (PK), `public_key` (`bytea`, **UNIQUE** — a key identifies at most one device), `label`, `status`, `created_at`, `revoked_at` |
| `sigil_enrollment_tokens` | `token_hash` (PK, the SHA-256 **hex digest** — never the token), `issued_at`, `expires_at`, `used_at` (the single-use marker), `used_by` |
| `sigil_device_grants` | `(vault_id, device_id)` (PK), `permission`, `is_owner`, `created_at`; a **partial `UNIQUE` index `sigil_device_grants_one_owner (vault_id) WHERE is_owner`** makes the ownership claim atomic in the database |

The migration is **pure DDL over auth metadata**: Ed25519 **public** keys,
server-assigned IDs, labels, permissions, timestamps. It touches **nothing** in
`sigil_vault_ops` — the opaque blob, its per-op hash chain, and the
zero-knowledge boundary are **unaffected**. `sigild_schema_version` reports **2**
once applied (**3** once `0003_billing.sql` is applied — see
[Billing](#billing--subscriptions-dev-gated-opt-in--phase-45) — and **4** once
`0004_key_sharing.sql` is applied, see
[Vault sharing](#device-to-device-vault-sharing-dev-gated-opt-in--phase-46)).

### Signed request contract (v3)

Every authenticated request carries **four** headers:

| Header | Value |
|--------|-------|
| `X-Sigil-Device` | the server-assigned device ID returned at enrollment (`dev_` + raw-URL-base64 of 16 random bytes) |
| `X-Sigil-Timestamp` | signing time, unix **seconds**, decimal ASCII |
| `X-Sigil-Nonce` | standard-base64 of a **fresh, per-request** CSPRNG nonce (≥ 16 bytes); signed **verbatim** as the exact header text |
| `X-Sigil-Signature` | standard-base64 of the 64-byte Ed25519 signature over the message below |

The signed **message** is, byte-for-byte:

```
MESSAGE = "sigil-oplog-auth-v3\n" + DEVICE_ID + "\n" + METHOD + "\n" + PATH + "\n" + QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + BODY
```

```
sigil-oplog-auth-v3\n
{DEVICE_ID}\n       EXACT X-Sigil-Device header text
{METHOD}\n          uppercase HTTP method
{PATH}\n            URL path, NO query — e.g. /v1/vaults/demo/ops
{QUERY}\n           raw query string, or "" if none
{TIMESTAMP}\n       same decimal value sent in X-Sigil-Timestamp
{NONCE}\n           EXACT X-Sigil-Nonce header text (base64 text, verbatim)
{BODY}              raw request body bytes; EMPTY for GET
```

**v3 is a clean break from v2.** The domain line changed (`…-v2` → `…-v3`) *and*
a device-ID segment was inserted, so a **v2 signature does not verify under v3**
(`401`) — captured v2 traffic cannot be replayed into the device model.

**Verification order** maps 1:1 to the audited reason:

1. all four headers present → else `missing_headers`
2. timestamp parses as `int64` → else `bad_timestamp`
3. `abs(now - ts) ≤ 300 s` → else `stale_timestamp`
4. `X-Sigil-Device` resolves in the registry → else `unknown_device`
5. the device is **not revoked** → else `revoked_device`
6. the signature verifies under **that device's registered public key** → else
   `bad_signature`
7. the nonce has not been seen in-window → else `replayed`

Two orderings are load-bearing and deliberate:

- **Revocation (5) is checked BEFORE signature verification (6)**, so a revoked
  device is refused on its **very next request** no matter how well it signs.
- **The nonce is recorded ONLY after a valid signature (6)**, so unauthenticated
  probes can neither populate nor probe the replay cache.

The replay cache is the same time-bounded, concurrency-safe, **per-process
in-memory** cache as v2: an entry is remembered for exactly as long as a request
bearing it could still pass the 300 s window, with a hard size cap as a
backstop. **A multi-instance deployment needs a shared store (e.g. Redis)**;
device request nonces share one namespace (enrollment nonces are
prefix-separated).

### Authorization: per-vault grants + trust-on-first-write ownership

A grant maps `(vaultID, deviceID) -> permission`, where `permission` is `read`
or `write` and **`write` implies `read`**. Each route declares what it needs:

| Route | Needs |
|-------|-------|
| `POST /v1/vaults/{vaultID}/ops` | **write** |
| `GET /v1/vaults/{vaultID}/ops` | read |
| `GET /v1/vaults/{vaultID}/ops/verify` | read |
| `POST /v1/vaults/{vaultID}/grants` | **owner** |
| `GET /v1/vaults/{vaultID}/grants` | read |
| `PUT /v1/vaults/{vaultID}/keys/{deviceID}` | **write** (a first deposit **claims** an unowned vault, exactly like a first append) |
| `GET /v1/vaults/{vaultID}/keys/{deviceID}` | read **and** being the addressee |

**Ownership is TRUST ON FIRST WRITE (TOFU).** A vault with no owner is claimed
by the **first device that successfully authenticates a WRITE** to it; that
device becomes the owner with `write` permission. The claim is **atomic** in both
backends (a mutex in memory; the partial `UNIQUE` index in Postgres), so exactly
one of N concurrent first-writers wins and the losers get `403`. **Reads never
claim** — reading an unowned vault is `403`. Only the **owner** may grant another
device access, and the grantee must be an enrolled, non-revoked device.

> **Honest limitation.** TOFU is a **dev ownership model, not an account model.**
> It assumes the first writer of a high-entropy, client-chosen vault ID is its
> legitimate owner; an attacker who writes to an **unclaimed** ID first becomes
> its owner and locks the real owner out. Revoking a vault's **owner ORPHANS the
> vault** — there is **no ownership transfer**, so afterwards nobody can grant on
> it (existing grantees keep only what they already hold).

### `401` vs `403`, and the absence of an auth oracle

- **`401 Unauthorized`** — *unauthenticated*: the request did not prove it came
  from a known, active device (missing/stale/bad signature, unknown device,
  revoked device, replayed nonce, bad admin token).
- **`403 Forbidden`** — *authenticated, but not authorized*: a valid device
  signature, but no sufficient grant on the vault (`unauthorized_vault`), not
  the vault owner (`not_vault_owner`), or acting on another device
  (`forbidden_device`).
- **`500`** — the registry itself could not be read/written
  (`store_unavailable`), returned as `500` **specifically so an infrastructure
  fault is never mistaken for a credential verdict**.

The **response body is coarse on purpose**:

```json
{ "error": "unauthorized", "detail": "missing or invalid request signature" }
{ "error": "forbidden",    "detail": "device is not authorized for this vault" }
```

A prober therefore learns only the status class. The precise cause is a fixed
enum that goes **ONLY** to the audit log and the per-reason metric — there is
**no auth oracle** in the response.

#### Denial reasons (audit + metrics only)

`missing_headers`, `bad_timestamp`, `stale_timestamp`, `bad_signature`,
`replayed`, `unknown_device`, `revoked_device`, `unauthorized_vault`,
`not_vault_owner`, `forbidden_device`, `bad_admin_token`, `store_unavailable`;
and for enrollment: `bad_enrollment_token`, `enrollment_token_used`,
`enrollment_token_expired`, `bad_proof`, `malformed_key`, `device_exists`.

### `POST /v1/devices/enroll` — enroll a device

Registers a device's Ed25519 public key and returns its **server-assigned**
device ID (clients never choose their own ID, so an ID cannot be squatted).

**Two independent factors, both mandatory:**

1. an operator-provisioned **enrollment token** in `X-Sigil-Enroll-Token`,
   matched in **constant time** against the configured digests and then **spent
   atomically** — a token is **single-use**;
2. **proof of possession** — an Ed25519 signature in `X-Sigil-Signature` over the
   canonical enrollment challenge, verified against the **public key being
   submitted**. A bare public-key upload is **never** accepted.

The enrollment challenge uses a **different domain** from the request contract,
so a proof can never be repurposed as an op-log request signature (or the
reverse):

```
CHALLENGE = "sigil-device-enroll-v1\n" + TOKEN_SHA256_HEX + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + PUBLIC_KEY_B64 + "\n" + LABEL
```

`TOKEN_SHA256_HEX` is the lowercase hex SHA-256 of the presented token;
`PUBLIC_KEY_B64` and `LABEL` are the **exact strings from the JSON body**, so
both sides sign the same bytes with no re-encoding ambiguity. Binding the token
digest means a captured proof cannot be re-presented with a **different** token;
binding the public key means an interceptor cannot swap in **its own** key while
reusing a victim's token.

The v2/v3 replay protections apply: the same **300 s** timestamp window and a
fresh `X-Sigil-Nonce` checked against the shared replay cache (enrollment nonces
are prefix-namespaced so they cannot collide with request nonces), and the nonce
is recorded **only after a valid proof**.

- **Headers:** `X-Sigil-Enroll-Token`, `X-Sigil-Timestamp`, `X-Sigil-Nonce`,
  `X-Sigil-Signature` (the proof). No `X-Sigil-Device` — the device does not
  exist yet.
- **Request body** (JSON, capped at **8 KiB**):

  ```json
  { "public_key": "<standard-base64 of a raw 32-byte Ed25519 public key>", "label": "<human name, ≤ 128 chars>" }
  ```

- **Success — `201 Created`:**

  ```json
  { "device_id": "dev_<raw-url-base64>", "label": "laptop", "status": "active", "created_at": "<RFC3339>" }
  ```

  (`revoked_at` is present only once the device is revoked.) The response
  deliberately **omits the public key** — the client already has it, and the
  registry never echoes key material out of an endpoint that does not need to.

- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `invalid_request` | body unreadable / over 8 KiB, not a JSON object, or `label` too long |
  | `400 Bad Request` | `invalid_request` | `public_key` is not the standard-base64 of a **32-byte** Ed25519 public key (`malformed_key`) |
  | `401 Unauthorized` | `unauthorized` | missing headers, stale timestamp, unknown/spent/expired token, bad proof, or a replayed nonce — **all return the same body**, so a prober cannot distinguish them |
  | `409 Conflict` | `device_exists` | that public key is already enrolled |
  | `500` | `internal` | the registry could not be read/written |
  | `501 Not Implemented` | `not_implemented` | dev-ops off, or no registry configured |

> **Honest limitation — single-ATTEMPT, not single-SUCCESS.** The token is spent
> **before** the device row is created, so an enrollment that then conflicts on a
> duplicate key still **burns the token**. That is deliberately fail-closed (the
> server never silently permits a retry), but an operator must issue a **new**
> token after such a failure. There is also **no rate limiting on enrollment
> attempts** — the per-vault op-log limiter does not cover this route.

### `GET /v1/devices` — list devices (operator)

Requires the **operator admin token** in `X-Sigil-Admin-Token`. With
`SIGILD_ADMIN_TOKEN` unset the route is **permanently `401`** — there is no
implicit open-admin mode. Public keys are **not** included.

- **Success — `200 OK`:**

  ```json
  { "devices": [ { "device_id": "dev_…", "label": "laptop", "status": "active|revoked", "created_at": "<RFC3339>", "revoked_at": "<RFC3339, omitted when active>" } ] }
  ```

- **Errors:** `401 unauthorized` (missing/incorrect admin token, audited as
  `bad_admin_token`); `500 internal`; `501 not_implemented` when the model is off.

### `POST /v1/devices/{deviceID}/revoke` — revoke a device

A revoked device is rejected on its **very next request** (status is checked
before its signature is verified). Revocation is **idempotent**: revoking an
already-revoked device succeeds and keeps the original `revoked_at`. The device
row is **retained**, never deleted, so the audit trail stays explainable.

**Two authorized paths, neither a bypass:**

- the **operator admin token** (`X-Sigil-Admin-Token`) — may revoke **any**
  device; this is the break-glass path for a lost/stolen device; or
- **self-revocation** — a valid **v3-signed** request whose signing device **is**
  the device named in the path. A device may retire itself; it may **not** revoke
  another device (that is `403`, audited as `forbidden_device`).

- **Success — `200 OK`:** `{ "device_id": "dev_…", "status": "revoked" }`
- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `missing_device_id` / `invalid_request` | empty path segment; body unreadable or over 8 KiB |
  | `401 Unauthorized` | `unauthorized` | no admin token **and** no valid v3 signature |
  | `403 Forbidden` | `forbidden` | authenticated, but trying to revoke a **different** device |
  | `404 Not Found` | `device_not_found` | no such device |
  | `501 Not Implemented` | `not_implemented` | dev-ops off, or no registry configured |

### `POST /v1/vaults/{vaultID}/grants` — grant a device access to a vault

The requesting device must be the vault's **owner** (the device that claimed it
on first write); any other authorized device gets `403` (`not_vault_owner`). The
signature covers the body, so authorization runs **after** the body is read.

- **Auth:** the four v3 headers.
- **Request body** (JSON, capped at 8 KiB):

  ```json
  { "device_id": "dev_<grantee>", "permission": "read" }
  ```

- **Success — `201 Created`:**

  ```json
  { "device_id": "dev_<grantee>", "permission": "read", "owner": false, "created_at": "<RFC3339>" }
  ```

  Re-granting updates a non-owner grant's permission; an existing **owner** row
  is never downgraded.

- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `missing_vault_id` / `invalid_request` | empty vault ID; unreadable/oversized body; missing `device_id`; `permission` not `"read"` or `"write"` |
  | `401 Unauthorized` | `unauthorized` | the v3 signature check failed |
  | `403 Forbidden` | `forbidden` | authenticated but **not the vault owner**, or holding no grant at all |
  | `404 Not Found` | `device_not_found` | the grantee is not enrolled |
  | `409 Conflict` | `device_revoked` | the grantee is revoked — a grant to a revoked device is refused, not silently recorded |
  | `501 Not Implemented` | `not_implemented` | dev-ops off, or no registry configured |

### `GET /v1/vaults/{vaultID}/grants` — list a vault's grants

Any device with **read** access to the vault may see who else can reach it.

- **Auth:** the four v3 headers (`BODY` is empty for GET).
- **Success — `200 OK`:**

  ```json
  {
    "vaultID": "<vaultID>",
    "grants": [ { "device_id": "dev_…", "permission": "write", "owner": true, "created_at": "<RFC3339>" } ]
  }
  ```

- **Errors:** `400 missing_vault_id`; `401 unauthorized`; `403 forbidden` (no
  grant — including on an **unowned** vault, since reads never claim); `500
  internal`; `501 not_implemented`.

### Client support (the `sigil` CLI)

The **`sigil` CLI implements contract v3** — it was the first client to speak it,
covering four of the five device routes above (the **browser clients** now speak it
too — see [below](#client-support-the-browser--node-clients)). Commands (see
[`../cli/src/main.rs`](../cli/src/main.rs)):

| Command | Route it calls |
|---------|----------------|
| `sigil device enroll --token <t> [--label <name>] [--key <file>] [--server <url>] [--reuse-key]` | `POST /v1/devices/enroll` — generates (or, with `--reuse-key`, reuses) the key, signs the proof of possession, and writes the returned `device_id` into the `0600` identity file. It **refuses to overwrite** an existing identity file unless `--reuse-key` is given. |
| `sigil device list --admin-token <t> [--server <url>]` | `GET /v1/devices` |
| `sigil device revoke <deviceID> [--admin-token <t>] [--key <file>] [--server <url>]` | `POST /v1/devices/{deviceID}/revoke` — self-revocation with `--key`, or the operator path with `--admin-token` |
| `sigil device grant <deviceID> --vault <id> --permission read\|write [--key <file>] [--server <url>]` | `POST /v1/vaults/{vaultID}/grants` (owner-only) |

`GET /v1/vaults/{vaultID}/grants` has **no CLI subcommand yet**.

**Contract selection is additive and driven by the identity file**, so nothing
existing changed:

| Client state | Contract used |
|--------------|---------------|
| no `--key` and no `SIGIL_DEVICE_KEY` | **unsigned** (byte-identical to the legacy unauthenticated path) |
| identity file **without** `device_id` | **v2** (legacy, unchanged) |
| identity file **with** `device_id` (after `device enroll`) | **v3**, sending `X-Sigil-Device` |

`sigil push` / `sigil pull` therefore sign v3 automatically once the key they
were given is enrolled. `SIGIL_DEVICE_ID=<id>` forces v3 with that ID even for
an older key file. Tokens and the server URL may also come from the environment
— `SIGIL_ENROLL_TOKEN`, `SIGIL_ADMIN_TOKEN`, `SIGIL_DEVICE_ID`, plus the
existing `SIGIL_SERVER` / `SIGIL_DEVICE_KEY` — with the flags taking
precedence. The `device` subcommands default the identity path to
`$HOME/.sigil/device.key`; `push`/`pull` keep their old rule (no key ⇒
unsigned). The CLI never prints the seed, the enrollment token, or the admin
token.

The CLI builds the same canonical bytes as the server
(`canonical_v3_message` / `canonical_enroll_message` in
[`../cli/src/lib.rs`](../cli/src/lib.rs)), with a fresh CSPRNG nonce and the
current unix seconds per request. It is the same **dev-only, plain-HTTP,
UNAUDITED** posture as the server side: no TLS, do not point it at a remote host.

### Client support (the browser + Node clients)

The **browser clients speak contract v3 as well**, through
[`../sigil-wasm/device-auth.mjs`](../sigil-wasm/device-auth.mjs) — a framework-free,
dependency-free ESM module that runs in Node **and** the browser and is used by
`web/apps/webapp` (via the `@sigil/wasm` loader) and by the MV3 `extension/` (via
its vendored copy). It covers **all five** device routes:

| Module function | Route it calls |
|-----------------|----------------|
| `enrollDevice(wasm, {baseUrl, token, label, seed})` | `POST /v1/devices/enroll` (token **plus** proof of possession) |
| `pushContainerAuthed` / `pullContainersAuthed` | `POST` / `GET /v1/vaults/{vaultID}/ops`, v3-signed |
| `grantVaultAccess` / `listVaultGrants` | `POST` / `GET /v1/vaults/{vaultID}/grants` |
| `revokeSelf` / `revokeDeviceAdmin` | `POST /v1/devices/{deviceID}/revoke` (self-signed, or admin token) |
| `listDevices` | `GET /v1/devices` (admin token) |

Supporting surface: `generateDeviceSeed` / `devicePublicKey` (a 32-byte seed from
`crypto.getRandomValues`, public key derived in the wasm), `signedFetch` /
`makeSignedFetch` (a `fetch`-shaped signer), `sealDeviceIdentity` /
`openDeviceIdentity` (the identity is stored **sealed**, never in plaintext — see
[ADR 0033](decisions/0033-browser-device-identity-storage.md)), and
`DeviceAuthError` / `explainAuthStatus`, which turn the deliberately coarse `401`
vs `403` bodies into a plain-language explanation without inventing an oracle.
**All signing is `ed25519_sign` in the wasm** (`sigil-core`'s real Ed25519, added
to the binding alongside `ed25519_public_key` / `ed25519_verify`); the enrollment
token's SHA-256 digest comes from `crypto.subtle`. There is no JS-side signing.

The existing transport [`../sigil-wasm/sync.mjs`](../sigil-wasm/sync.mjs) was
extended **additively** with one optional `opts.fetch` (defaulting to the global
`fetch`) plus an additive `err.status`, so the **unauthenticated** dev path is
behaviourally identical and the authenticated path simply injects the signer.

**The canonical message layout now exists in three implementations** —
[`../sigild/internal/api/deviceauth.go`](../sigild/internal/api/deviceauth.go)
(Go, the source of truth), [`../cli/src/lib.rs`](../cli/src/lib.rs) (Rust), and
`device-auth.mjs` (JS: `canonicalV3Message` / `canonicalEnrollMessage` /
`enrollTokenHash`) — and they **must stay byte-identical**; a one-byte drift does
not fail loudly, it just yields `401` on every request. That is what the interop
tests guard: [`../sigil-wasm/test/device-auth-interop.mjs`](../sigil-wasm/test/device-auth-interop.mjs)
boots a **real** sigild with `SIGILD_DEVICE_AUTH=1` and drives the JS client
against it (enroll, claim, grant, revoke, tamper, stale, token reuse). Same
**dev-only, plain-HTTP, UNAUDITED** posture as the CLI: no TLS, loopback only.

### Default posture (all nine routes)

With **`SIGILD_ENABLE_DEV_OPS` unset** — the default and the only
production-safe setting — **every** device route **and every vault-sharing route**
(the four in the [next section](#device-to-device-vault-sharing-dev-gated-opt-in--phase-46))
returns:

```json
{ "error": "not_implemented", "detail": "device enrollment, per-vault authorization and vault sharing are not enabled on this server" }
```

`501`, never `404`, and never a partial or faked auth behaviour. The same `501`
applies when dev-ops is on but no registry is configured
(`SIGILD_DEVICE_AUTH` unset). The bodies of `PUT`/`POST` requests are drained and
discarded, and the envelope route keeps its size cap even while stubbed.
`GET /metrics` stays `200` throughout — it is never dev-gated.

---

## Device-to-device vault sharing (DEV-GATED, opt-in) — Phase 46

> **DEV-GATED, OPT-IN, and UNAUDITED.** These four routes let one enrolled device
> hand a vault's encryption key to another **without the server ever being able to
> read it**. The relay is real and the authorization is real (it is the *same* v3
> code path as the op-log, not a parallel one), but it is **gated off by default**
> (`501`), **plain HTTP in dev**, and the cryptography it carries is **unaudited**.
> The key hierarchy — a random per-vault key wrapped with the PQ-hybrid
> `hybrid_seal` path, the human password never shared — is specified in
> [`crypto-spec.md`](crypto-spec.md#key-hierarchy-and-vault-sharing-hybrid_seal--hybrid_open-in-use).
> See [ADR 0035](decisions/0035-device-to-device-vault-sharing.md).

### The shape of the flow

`sigild` is a **mailbox**, not a key manager. The sending client wraps a vault key
to the recipient's hybrid **public** key and uploads the resulting ciphertext; the
recipient collects those exact bytes and unwraps them locally.

```
device A                          sigild                          device B
   │  PUT /v1/devices/{A}/hybrid-key  ─▶ registry (public keys only)
   │  GET /v1/devices/{B}/hybrid-key  ◀─ B's X25519 + ML-KEM-768 public key
   │  ── wrap the 32-byte vault key with hybrid_seal (client-side) ──
   │  PUT /v1/vaults/{V}/keys/{B}     ─▶ stores OPAQUE envelope bytes verbatim
   │  POST /v1/vaults/{V}/grants      ─▶ authorize B on vault V (existing route)
                                          GET /v1/vaults/{V}/keys/{B}  ◀─ │
                                          (exact same bytes back)         │
                                     ── unwrap with B's hybrid secret ──  │
```

**Zero-knowledge.** The server holds no decapsulation key, decodes nothing, and
returns the envelope byte-for-byte. Its **only** inspection of key material is a
**length check** on a published hybrid public key (32 / 1184 bytes) — it never
parses a curve point or validates a KEM key, because that would be the server
performing cryptography on user key material.

### Configuration and storage

No new environment variable. The routes are live exactly when the multi-device
model is (`SIGILD_ENABLE_DEV_OPS` **and** a configured registry — see
[Configuration](#configuration) above), and they use that registry's backend.

Migration [`0004_key_sharing.sql`](../sigild/internal/store/migrations/0004_key_sharing.sql)
adds two tables on top of the untouched `0001`–`0003` (`sigild_schema_version` →
**4**):

| Table | Holds |
|-------|-------|
| `sigil_device_hybrid_keys` | `device_id` (PK, FK → `sigil_devices`, `ON DELETE CASCADE`), `x25519_public_key` (`bytea`), `mlkem_encaps_key` (`bytea`), `updated_at`. **Public** key material, stored verbatim |
| `sigil_vault_key_envelopes` | `(vault_id, recipient_device_id)` (PK; the FK is on the recipient), `sender_device_id`, `blob` (`bytea`, **ciphertext**), `created_at`; plus the index `sigil_vault_key_envelopes_by_recipient` |

Both are pure DDL over opaque bytes; `sigil_vault_ops`, its hash chain, the device
registry, the grants table and the billing tables are byte-for-byte unchanged.
`sender_device_id` is **audit metadata** — the device the server *authenticated* on
upload, never a claim read out of the blob. Both stores (in-memory and Postgres)
implement the one `store.KeySharing` seam and are held to one conformance suite.

**Upsert semantics, and what they do not do.** `PUT …/hybrid-key` is an upsert on
`device_id`, and `PUT …/keys/{deviceID}` is an upsert on
`(vault_id, recipient_device_id)` — re-sharing after a re-key replaces the
envelope. **Republishing a hybrid key does NOT re-wrap envelopes already deposited
for that device**: those were sealed to the old key and must be re-shared.

### Size caps

| Limit | Value | Enforced |
|-------|-------|----------|
| hybrid-key publish body | **8 KiB** (`maxHybridKeyBodyBytes`) | in the handler → `413 payload_too_large` |
| key envelope | **16 KiB** (`store.MaxKeyEnvelopeBytes`) | at the router (`limitBody`) **and** again in the store → `413 payload_too_large` |
| X25519 public key | exactly **32** bytes after base64 decode | `store.ValidateHybridPublicKey` → `400 invalid_request` |
| ML-KEM-768 encapsulation key | exactly **1184** bytes after base64 decode | as above |
| envelope may not be empty | ≥ 1 byte | → `400 empty_envelope` |

A real wrapped vault key is a `SIGILhyb` container of about **1.2 KiB** (observed
1226 bytes: 8-byte magic + version + 32-byte ephemeral X25519 public key +
1088-byte ML-KEM ciphertext + a small AEAD envelope), so 16 KiB is generous
headroom that still stops the relay being used as a blob store.

### `401` vs `403` on these routes

The [general rule](#401-vs-403-and-the-absence-of-an-auth-oracle) applies
unchanged, and two sharing-specific cases are worth stating because they are easy
to get backwards:

- Publishing into **another device's** hybrid-key slot is **`403`**
  (`forbidden_device`) — the request authenticated fine; it is simply not permitted.
- Requesting **another device's** envelope is **`403`** (`forbidden_device`), *not*
  `404` and *not* `401`. A `401` would be a lie (the caller did authenticate) and a
  `404` would leak whether an envelope exists for that device.
- A **revoked** device gets **`401`** everywhere, on its very next request —
  revocation is checked before the signature is even verified.

The response bodies stay coarse (`{"error":"forbidden", …}`); the precise reason
goes only to the audit log and the per-reason metric.

### `PUT /v1/devices/{deviceID}/hybrid-key` — publish my hybrid public key

Stores the **public** half of this device's X25519 + ML-KEM-768 identity so other
devices can wrap a vault key to it. The secret half never leaves the device.

- **Auth:** the four v3 headers. The path `deviceID` **must be the authenticated
  device's own ID**.
- **Request body** (JSON, ≤ 8 KiB); both fields are standard-base64 of **raw**
  public key bytes:

  ```json
  { "x25519_public_key": "<b64 32 bytes>", "mlkem_encaps_key": "<b64 1184 bytes>" }
  ```

- **Success — `200 OK`** (an upsert, so re-publishing is not an error):

  ```json
  { "device_id": "dev_…", "x25519_public_key": "<b64>", "mlkem_encaps_key": "<b64>", "updated_at": "<RFC3339>" }
  ```

  Unlike the device routes — which deliberately never echo an Ed25519 signing key —
  this route **does** return key material, because publishing it for others to
  fetch is the entire point and it is a **public** key.

- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `missing_device_id` / `invalid_request` | empty path device ID; body is not a JSON object; a field is not standard-base64; a decoded half is not exactly 32 / 1184 bytes |
  | `401 Unauthorized` | `unauthorized` | v3 signature check failed — including a **revoked** device |
  | `403 Forbidden` | `forbidden` | authenticated, but publishing into **another** device's slot |
  | `404 Not Found` | `device_not_found` | the device is not (or no longer) in the registry |
  | `413 Payload Too Large` | `payload_too_large` | body over 8 KiB |
  | `501 Not Implemented` | `not_implemented` | dev-ops off, or no registry configured |

### `GET /v1/devices/{deviceID}/hybrid-key` — fetch a device's hybrid public key

- **Auth:** the four v3 headers (`BODY` is empty for GET). **Any** authenticated,
  active device may fetch **any** device's key — they are public keys; requiring
  authentication only stops the registry being world-enumerable.
- **Success — `200 OK`:** the same `hybridKeyJSON` object as above.
- **Errors:** `400 missing_device_id`; `401 unauthorized` (including revoked);
  `404 hybrid_key_not_found` (**that device exists but has published no hybrid
  key** — distinct from `device_not_found`); `500 internal`; `501 not_implemented`.

### `PUT /v1/vaults/{vaultID}/keys/{deviceID}` — deposit a wrapped vault key

Uploads an **opaque** envelope addressed to one device. The body is the **raw
envelope bytes**, the same "opaque bytes in, opaque bytes out" shape as an op-log
append — the server never decodes it.

- **Auth:** the four v3 headers. Requires **`write`** on the vault, through the
  same `authorizeOpsRequest` choke point the op-log uses — so depositing the first
  envelope for an **unowned** vault **claims** it (trust-on-first-write), exactly as
  a first append would. A read-only grantee cannot deposit.
- **Request body:** `application/octet-stream`, 1 byte … 16 KiB. The v3 signature
  covers the body, so the body is read **before** authorization runs.
- **Success — `201 Created`:**

  ```json
  { "vaultID": "<vaultID>", "device_id": "dev_<recipient>", "size_bytes": 1226, "created_at": "<RFC3339>" }
  ```

- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `invalid_request` / `empty_envelope` | missing vault or device ID; unreadable body; empty envelope |
  | `401 Unauthorized` | `unauthorized` | v3 signature check failed — including a **revoked** sender |
  | `403 Forbidden` | `forbidden` | authenticated but holding no **write** grant on the vault (including an unowned vault claimed by someone else) |
  | `404 Not Found` | `device_not_found` | the **recipient** is not enrolled |
  | `409 Conflict` | `device_revoked` | the recipient is revoked — refused, not silently stored |
  | `413 Payload Too Large` | `payload_too_large` | body over 16 KiB |
  | `501 Not Implemented` | `not_implemented` | dev-ops off, or no registry configured |

### `GET /v1/vaults/{vaultID}/keys/{deviceID}` — collect my envelope

Returns the envelope **byte-for-byte as it was uploaded**.

- **Auth:** the four v3 headers. **Two** conditions, both required: the caller must
  **be the addressee** (`deviceID` == the authenticated device) **and** hold
  **`read`** on the vault — so an envelope cannot outlive a revoked grant.
- **Success — `200 OK`**, `Content-Type: application/octet-stream`, the exact
  stored bytes. No JSON, no base64, no re-framing.
- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `invalid_request` | missing vault or device ID |
  | `401 Unauthorized` | `unauthorized` | v3 signature check failed — including a **revoked** device |
  | `403 Forbidden` | `forbidden` | authenticated but **not the addressee**, or holding no read grant |
  | `404 Not Found` | `envelope_not_found` | nothing has been shared to this device for that vault |
  | `500 Internal Server Error` | `internal` | the store could not be read |
  | `501 Not Implemented` | `not_implemented` | dev-ops off, or no registry configured |

### Audit log

Three events, all **metadata plus a fingerprint** — the envelope bytes, the vault
key, the hybrid public keys, signatures and nonces are **never** logged:

| Event | Fields |
|-------|--------|
| `device.hybrid_key_published` | `request_id`, `device_id`. The key bytes are public, but are still not logged: an audit line is not a key-distribution channel |
| `vault.key_envelope_put` | `request_id`, `vault_id`, `recipient_device_id`, `sender_device_id`, `size_bytes`, `blob_sha256` (hex SHA-256 of the opaque envelope) |
| `vault.key_envelope_get` | `request_id`, `vault_id`, `recipient_device_id`, `size_bytes`, `blob_sha256` |

The shared `blob_sha256` lets an operator correlate "the sender uploaded X" with
"the recipient collected X" **without the server retaining the ciphertext**.
Denials are audited by the existing `oplog.auth_denied` path with the fixed reason
enum.

### Client support (the `sigil` CLI)

The CLI implements the whole flow (see [`../cli/src/main.rs`](../cli/src/main.rs)
and [`../cli/src/lib.rs`](../cli/src/lib.rs)):

| Command | Routes it calls |
|---------|-----------------|
| `sigil device hybrid-publish [--key <f>] [--hybrid-key <f>] [--regenerate] [--server <url>]` | `PUT /v1/devices/{deviceID}/hybrid-key` — generates the hybrid identity if absent (secret `0600`, never uploaded), publishes only the public half |
| `sigil vault rekey --vault <id> [--file <vaultfile>] [--publish] [--keyring <f>]` | none, unless `--publish` → `PUT /v1/vaults/{vaultID}/keys/{deviceID}` (wraps the new key to **this** device) |
| `sigil vault share --vault <id> --to <deviceID> [--permission read\|write] [--envelope-out <f>]` | `GET /v1/devices/{to}/hybrid-key`, then `PUT /v1/vaults/{vaultID}/keys/{to}`, then `POST /v1/vaults/{vaultID}/grants` |
| `sigil vault accept --vault <id> [--hybrid-key <f>] [--envelope-out <f>] [--for <deviceID>]` | `GET /v1/vaults/{vaultID}/keys/{deviceID}` — collect, unwrap, store the key locally |
| `sigil vault list [--keyring <f>]` | none — prints which vaults this device holds a key for, as **fingerprints only** |

Supporting client state, none of which is ever uploaded:

- the **hybrid secret identity** at `<identity>.hybrid` (default
  `$HOME/.sigil/device.hybrid`), mode `0600`, with the shareable public half at
  `<identity>.hybrid.pub`;
- the **vault keyring** at `$HOME/.sigil/vault-keys.json` (override with
  `--keyring`), mode `0600`, JSON `{"version":1,"keys":{"<vaultID>":"<b64 32 bytes>"}}`.

`sigil totp add|list|code|remove|import|export` gained **`--vault-id <id>`**, which
opens a file with the **vault key** for `<id>` instead of `SIGIL_PASSWORD`
(`--vault <file>` keeps its existing meaning, so every existing invocation behaves
exactly as before), plus `--keyring <file>`; `sigil totp code` gained `--at <unix>`
to pin the instant for reproducible testing. `--for <deviceID>` on `vault accept`
is a **diagnostic** that asks for someone else's envelope so the `403` rule is
testable from the outside — it never attempts to unwrap.

The CLI **never prints a vault key**: `rekey` / `share` / `accept` / `list` show
only `key_sha256=<16 hex chars>`, the first 8 bytes of the key's SHA-256, so two
devices can confirm they hold the same key without revealing it.

### Client support (the browser + Node clients)

The **browser clients implement the same flow**, through
[`../sigil-wasm/sharing.mjs`](../sigil-wasm/sharing.mjs) — a framework-free,
dependency-free ESM module that runs in Node **and** the browser and is used by
`web/apps/webapp` (via the `@sigil/wasm` loader) and by the MV3 `extension/` (via
its vendored copy). It covers all four routes, plus the two composed operations:

| Module function | Route it calls |
|-----------------|----------------|
| `publishHybridKey(wasm, auth, secretIdentity?)` | `PUT /v1/devices/{deviceID}/hybrid-key` — publishes only the public halves, into **this** device's slot |
| `fetchHybridKey(wasm, auth, deviceId)` | `GET /v1/devices/{deviceID}/hybrid-key` |
| `putKeyEnvelope(wasm, auth, vaultId, recipientDeviceId, envelopeBytes)` | `PUT /v1/vaults/{vaultID}/keys/{deviceID}` |
| `getKeyEnvelope(wasm, auth, vaultId, deviceId?)` | `GET /v1/vaults/{vaultID}/keys/{deviceID}` (defaults to `auth.deviceId`) |
| `shareVault(wasm, auth, {vaultId, recipientDeviceId, vaultKey, permission})` | `GET …/hybrid-key`, then `PUT …/keys/{to}`, then `POST …/grants` — the same three-step composition as `sigil vault share`, so authorization and key distribution cannot drift |
| `acceptVault(wasm, auth, {vaultId, secretIdentity?})` | `GET …/keys/{deviceID}` — collect, unwrap, return the 32-byte key |

`auth` is exactly the object `openDeviceIdentity` returns plus a `baseUrl`, so an
unlocked client passes its device identity straight in. Supporting surface:
`generateHybridIdentity` / `hybridPublicIdentity`, `generateVaultKey` /
`vaultKeyFingerprint` (the same 16-hex SHA-256 prefix the CLI prints — a vault key is
never rendered), `wrapVaultKey` / `unwrapVaultKey`, and `explainSharingStatus`, which
extends `explainAuthStatus` with the statuses only these routes produce (`403` not the
addressee / not permitted, `404` nothing published or shared yet, `409` revoked
recipient, `413` oversized). **All KEM/AEAD work happens in the wasm**
(`hybrid_seal_to_container` / `hybrid_open_container`) and every request signature goes
through `device-auth.mjs`; the module hand-rolls nothing. Entropy is JS-supplied
(`crypto.getRandomValues`) for the hybrid identity, each vault key, and the per-wrap
ephemeral X25519 secret / ML-KEM coin / AEAD nonce. `unwrapVaultKey` rejects any
recovered plaintext that is not exactly 32 bytes rather than using it as a key.

The browser clients store the hybrid secret identity and every accepted vault key
**inside their sealed device-identity container** (schema v2), never in plaintext web
storage — see [ADR 0036](decisions/0036-browser-sharing-secret-storage.md).

The semantics are **MIRRORED — not shared — from `sharing.go` (this server, the source
of truth) and `cli/src/lib.rs`**; drift yields a `400`/`403` or an envelope the CLI
cannot open, so the guard is
[`../sigil-wasm/test/sharing-interop.mjs`](../sigil-wasm/test/sharing-interop.mjs),
which boots a **real** sigild, builds the **real** `sigil` binary, and shares a vault
**both ways** between the JS client and the CLI (both ends reaching the same key
fingerprint and the same RFC 6238 code), plus the `403` negatives. The **desktop** client
does **not** implement sharing yet.

### Honest limits (read before believing any of the above)

- **Dev-gated (`501` by default), plain HTTP, localhost, UNAUDITED.** Do not
  expose it and do not store real 2FA secrets.
- **No out-of-band verification of a published hybrid public key.** A sender trusts
  what the registry serves; a malicious server could substitute its own key and
  receive a vault key wrapped to itself. There are no safety numbers, no key
  transparency, and no cross-signature.
- **Revocation does not un-share.** It stops **future** access; a device that
  already collected and unwrapped an envelope keeps the vault key. Remediation is a
  manual `vault rekey` + re-share — there is **no automatic re-wrap on revoke and
  no rotation schedule**.
- **No forward secrecy for a delivered vault key**, and republishing a hybrid key
  does not re-wrap already-deposited envelopes.
- **One mailbox per (vault, recipient).** A deposit is an upsert, so any device with
  `write` access can overwrite an envelope another writer deposited.
- **No rate limiting** on these routes — the per-vault limiter covers appends only.
- **Request authentication is classical Ed25519** (contract v3). The wrap is
  PQ-hybrid; the signature over the request is not, and **the system is not
  "post-quantum secure"**.
- **Client-side key storage is only as strong as its host.** The CLI's hybrid secret
  and keyring are `0600` files; the browser clients seal both into the device-identity
  container but hold them **unzeroized in JS memory** while the vault is unlocked.

---

## Billing / subscriptions (DEV-GATED, opt-in) — Phase 45

> **DEV-GATED, OPT-IN, UNAUDITED, and NEVER RUN AGAINST A LIVE PROVIDER
> ACCOUNT.** The signature verification, the state machine, the idempotency
> ledger and the storage are **real** — real `crypto/hmac` over the raw request
> body, real constant-time comparison, real transactional dedupe — but **no
> request in this repository has ever been sent to, or received from,
> `api.stripe.com`, `api.razorpay.com` or `api.juspay.in`.** Every test drives a
> local `httptest` server with fake credentials. Provider webhook schemes must be
> **confirmed against each merchant's live dashboard** before any real money
> moves; the **Juspay** scheme in particular is explicitly
> *UNVERIFIED-AGAINST-LIVE-DASHBOARD* (see below). This is not a payment
> integration you should point at production. See
> [`decisions/0034-billing-provider-seam.md`](decisions/0034-billing-provider-seam.md).

Sigil is a **paid** product, so `sigild` grew a **provider-agnostic billing
seam**: one `billing.Provider` interface, three adapters — **Stripe**
(international), **Razorpay** and **Juspay** (India) — a **normalized event
vocabulary**, a **subscription state machine**, and an **idempotent** apply path
backed by in-memory or Postgres storage.

Two properties frame everything below:

- **No card data ever reaches this server.** Every adapter uses the provider's
  **hosted checkout / payment-link** flow: `sigild` asks the provider for a URL
  and hands that URL to the client. There is deliberately **no field on any
  request, response, struct, log line, metric or database column** that could
  carry a PAN, CVV, expiry, cardholder name or billing address — and none that
  carries an email or phone number either. PCI scope stays at SAQ-A.
- **Zero-knowledge is untouched.** No billing handler reads, writes or derives
  anything about a vault blob, and migration `0003_billing.sql` touches nothing
  in `sigil_vault_ops`.

### Routes at a glance — and which auth applies to which

| Route | Auth | Body cap | Success |
|-------|------|----------|---------|
| `POST /v1/billing/checkout` | **device auth v3** (`authenticateDevice`, the *same* choke point as the ops routes) | 8 KiB | `201` + hosted checkout URL |
| `POST /v1/billing/webhook/{provider}` | **the provider's own signature over the raw body** — *no* device auth | 64 KiB | `200` + outcome |
| `GET /v1/billing/subscription` | **device auth v3** | — (no body) | `200` + the caller's status |

The split is deliberate and is the whole reason the webhook route exists outside
the device model: **checkout and subscription come from a device**, which holds
an enrolled Ed25519 key and can sign the v3 contract; **a webhook comes from the
payment provider**, which has no device key and cannot. So the webhook is
authenticated by the provider's HMAC (or, for Juspay's basic scheme, its
endpoint credentials) and by nothing else — and correspondingly it can **create
no session, read no vault, and name no subject of its own choosing**.

**The subject is server-derived.** A checkout's subject is the **authenticated
device ID** (`dev_…`), taken from the verified signature and **never** from the
request body; `GET /v1/billing/subscription` likewise reports only the caller's
own record and takes no subject parameter. A client therefore cannot buy — or
query — a subscription on another subject's behalf. There is **no account model
yet**: "subject" means "enrolled device", which is an honest scaffold, not the
product's billing identity (see the limits at the end of this section).

### Default posture — the deliberate `501`

Billing is **doubly off by default**. It requires *both*:

1. `SIGILD_ENABLE_DEV_OPS` (the whole stateful surface is dev-gated), **and**
2. `SIGILD_BILLING_PROVIDERS` naming at least one provider, **and** a
   subscription store, **and** a device registry (`SIGILD_DEVICE_AUTH`).

With any of those missing, **all three routes** return `501` — never `404`, and
never partial or faked behaviour:

```json
{ "error": "not_implemented", "detail": "billing is not enabled on this server" }
```

Body caps still apply before the stub runs, so an oversized request gets `413`
rather than `501`. `GET /metrics` stays `200` throughout (it is never dev-gated);
the billing counters simply read `0`.

### `POST /v1/billing/checkout` — create a hosted checkout session

**Auth: device auth v3.** Identical to the ops routes: `X-Sigil-Device`,
`X-Sigil-Timestamp`, `X-Sigil-Nonce`, `X-Sigil-Signature` over the canonical v3
message (`"sigil-oplog-auth-v3\n" + DEVICE_ID + …+ BODY`, see
[above](#signed-request-contract-v3)). The body is read **first** so it can be
covered by the signature, and only then authenticated — the same order the
op-log append uses. No billing-specific token, no API key, no second auth path.

Request body (optional; `{}` or an empty body is valid):

```json
{ "provider": "stripe", "plan": "price_1234" }
```

| Field | Meaning |
|-------|---------|
| `provider` | which enabled provider to use. Omitted ⇒ `SIGILD_BILLING_DEFAULT_PROVIDER`. |
| `plan` | optional per-request plan override — a Stripe **price ID**, or a Juspay **payment-page client ID**. Omitted ⇒ the adapter's configured default. |

Note what is **absent**: no subject (server-derived), no amount override, and no
payment-instrument field of any kind.

`201 Created`:

```json
{
  "provider": "stripe",
  "session_id": "cs_test_…",
  "url": "https://checkout.stripe.com/c/pay/cs_test_…",
  "expires_at": "2026-07-26T18:30:00Z"
}
```

`session_id` and `expires_at` are omitted when the provider does not return
them. The client redirects the customer to `url`; the card details are entered
**there**, at the provider.

| Status | `error` | When |
|--------|---------|------|
| `201` | — | session created |
| `400` | `invalid_request` | body unreadable, over 8 KiB, or not a JSON object |
| `400` | `unknown_provider` | `provider` names something not enabled on this server |
| `401` | `unauthorized` | device auth failed (missing/invalid/stale signature, unknown or revoked device, replayed nonce) — coarse body, exact reason only in the audit log |
| `413` | `payload_too_large` | `Content-Length` exceeds the 8 KiB cap |
| `500` | `internal` | reference generation, the subscription store, or an adapter reporting `ErrNotConfigured` (a **server** misconfiguration, deliberately not surfaced as a client error) |
| `502` | `provider_error` | the provider API call failed — `{"error":"provider_error","detail":"the payment provider could not create a checkout session"}` |
| `501` | `not_implemented` | billing off |

**Before** calling out to the provider, the server records `StartCheckout`
(subject → provider) so a webhook that races the HTTP response still has a row to
resolve against. The per-attempt reference is **server-generated**
(`"sigil-" + hex(12 random bytes)`) and used as the provider's idempotency key /
`reference_id` / `order_id`, so a client can neither collide with nor overwrite
another attempt. The outbound call is bounded twice: a 12 s request-scoped
context (`billingProviderTimeout`) on top of the adapter client's own 10 s
timeout, and at most 1 MiB of provider response is read.

### `POST /v1/billing/webhook/{provider}` — provider callback

**Auth: the provider's signature over the RAW request body. No device auth, no
session, no bearer token.** `{provider}` must be one of `stripe`, `razorpay`,
`juspay` **and** must be enabled on this server.

The body is read **once** and the exact bytes are kept: the signature is verified
over **those bytes first**, and only then is the JSON parsed. Verifying a
re-encoded payload would be a bug — a JSON round-trip reorders keys and drops
whitespace, so the MAC would never match (or, if "fixed" by re-signing, an
attacker could mutate the body freely).

#### Per-provider webhook contract

| Provider | Header carrying the signature | What is signed (the MAC message) | MAC / encoding | Timestamp bound |
|----------|-------------------------------|----------------------------------|----------------|-----------------|
| **Stripe** | `Stripe-Signature: t=<unix>,v1=<hex>[,v1=<hex>][,v0=…]` | `"<t>" + "." + RAW_BODY_BYTES` | HMAC-SHA256 keyed by the **endpoint signing secret** (`whsec_…`), lowercase hex | **yes** — `abs(now − t) ≤ 5 min` (`stripeDefaultTolerance`), checked in **both** directions |
| **Razorpay** | `X-Razorpay-Signature: <hex>` | `RAW_BODY_BYTES` — no timestamp, no prefix, no separator | HMAC-SHA256 keyed by the dashboard **webhook secret**, lowercase hex | **none in the scheme** — replay is bounded only by our idempotency ledger |
| **Juspay**, `scheme=basic` (default) | `Authorization: Basic base64(user:pass)` | *nothing* — this authenticates the **connection**, not the body | constant-time compare of both halves | none |
| **Juspay**, `scheme=hmac` | `X-Juspay-Signature` (**name configurable** via `SIGILD_JUSPAY_WEBHOOK_SIG_HEADER`) | `RAW_BODY_BYTES` | HMAC-SHA256 keyed by `SIGILD_JUSPAY_WEBHOOK_SECRET`, lowercase hex | none |

Details that matter:

- **Stripe**: **every** `v1` element is compared (Stripe sends more than one
  while an endpoint secret is being rotated — accepting any one is what makes
  rotation zero-downtime), with **no early exit**, so neither the number of
  candidates nor which matched is observable in timing. Legacy **`v0` elements
  are ignored**, never accepted — accepting them would be a downgrade path.
- **Razorpay**: the event ID comes from the **`X-Razorpay-Event-Id`** header.
  When it is absent, the adapter derives a **deterministic** ID
  (`"body-" + hex(SHA-256(raw body))`) so a byte-identical redelivery still
  deduplicates. *The header name is part of the unverified surface.*
- **Juspay, basic scheme — stated plainly**: HTTP Basic auth proves the caller
  knows a shared password; it does **not** prove the payload was not modified in
  transit. Prefer `scheme=hmac` where the dashboard offers it; where only basic
  is available the endpoint **must** be TLS-only and the credential treated as a
  bearer secret.
- All comparisons use `hmac.Equal` / `subtle.ConstantTimeCompare`; a hex string
  that fails to decode is simply "not equal", so a malformed and a wrong
  signature are indistinguishable.

#### Normalized event types

Each adapter maps its provider's vocabulary onto exactly one normalized type, so
the state machine and the HTTP layer never learn a provider dialect:

| Normalized type | Stripe | Razorpay | Juspay |
|-----------------|--------|----------|--------|
| `checkout_completed` | `checkout.session.completed` | `payment_link.paid` | `ORDER_SUCCEEDED` |
| `subscription_activated` | `customer.subscription.created` / `.updated` with object status `trialing`/`active` | `subscription.activated`, `subscription.authenticated`, `subscription.resumed` | `MANDATE_CREATED`, `MANDATE_ACTIVATED` |
| `subscription_renewed` | `invoice.paid`, `invoice.payment_succeeded` | `subscription.charged` | `TXN_CHARGED`, `MANDATE_NOTIFICATION_SUCCEEDED` |
| `subscription_canceled` | `customer.subscription.deleted`; `.created`/`.updated` with status `canceled`/`incomplete_expired` | `subscription.cancelled`, `subscription.completed`, `subscription.expired` | `MANDATE_REVOKED`, `MANDATE_EXPIRED`, `MANDATE_PAUSED` |
| `payment_failed` | `invoice.payment_failed`; `.created`/`.updated` with status `past_due`/`unpaid` | `subscription.halted`, `subscription.pending`, `payment.failed` | `ORDER_FAILED`, `TXN_FAILED`, `MANDATE_NOTIFICATION_FAILED` |
| `ignored` | anything else | anything else | anything else |

For Stripe the **status on the object** decides, not the event name alone: an
`updated` event is how Stripe reports a trial ending, a card failing, and a
cancellation scheduled at period end.

`ignored` is an explicit verdict, not a fallthrough bug: providers send events we
do not model (refund notices, mandate reminders, test pings), and those **must**
be a `200` with no state change so the provider does not enter a retry/backoff
loop against us.

**Subject attribution.** Each adapter writes our subject into the provider's
pass-through field at checkout and reads it back on the webhook: Stripe
`client_reference_id` **plus** `subscription_data[metadata][sigil_subject]`,
Razorpay `notes.sigil_subject`, Juspay `udf1` (with
`metadata.sigil_subject` as a fallback). The namespaced key is
**`sigil_subject`**. When an event carries no such marker, the store resolves the
subject from `(provider, subscription_ref)` instead.

#### Subscription state machine

States: `none` → *(implicit, no record)*, `trialing`, `active`, `past_due`,
`canceled`. Legal transitions (**everything else is rejected**):

```
none      -> trialing | active
trialing  -> active | past_due | canceled
active    -> active (renewal) | past_due | canceled
past_due  -> active | canceled
canceled  -> trialing | active          (a NEW purchase after cancellation)
```

`active -> active` is legal and is how a **renewal** is recorded (it carries a
new `current_period_end`). `canceled` is not a dead end — a customer who cancels
and buys again must be able to become active — but it can only be left by an
event targeting an active state, so a late `payment_failed` cannot revive a dead
subscription into `past_due`. There is **no transition into `none`**.

**Entitlement** (`entitled: true`) covers `trialing`, `active` **and
`past_due`** — a failed renewal opens a provider-side retry window, and cutting a
paying customer off the instant a card declines is both hostile and usually
wrong. Cancellation is where entitlement ends.

Separately from legality, an event whose `OccurredAt` **precedes the last event
applied** is dropped as **stale**, so an out-of-order `payment_failed` cannot
regress a subscription that has since gone active. Legality and ordering are two
independent guards; both must pass.

#### The idempotency guarantee

**A duplicate delivery is a no-op that still answers `200`.** Providers redeliver
— on their own retry schedule, and again whenever an operator replays an event
from a dashboard — so this is a documented behaviour to design for, not an edge
case.

The key is **`(provider, event_id)`**. Recording "we handled it" and applying the
state change are **fused into one atomic operation**
(`SubscriptionStore.ApplyWebhookEvent`): one mutex in the in-memory backend, one
**transaction** in Postgres, where the ledger insert is
`INSERT … ON CONFLICT (provider, event_id) DO NOTHING` and zero rows affected
*means* duplicate, with the subscription row taken `FOR UPDATE` so two events for
one subject serialize. A rollback leaves **both** the ledger and the record
untouched, so a retry is clean. Split across two calls, a crash in between would
either double-apply or lose an event; as one operation it cannot.

The response `status` reports the verdict:

```json
{ "provider": "stripe", "status": "accepted" }
```

| `status` | Meaning | State changed? |
|----------|---------|----------------|
| `accepted` | fresh, legal, in order — applied | **yes** |
| `ignored` | authentic but not a modeled event type | no |
| `duplicate` | `(provider, event_id)` already processed — **the idempotency guarantee** | no |
| `stale` | predates the last applied event | no |
| `illegal` | not a legal transition from the current status | no |
| `unresolved` | no subject on the event and none resolvable from its subscription reference. **Deliberately not recorded as processed**, so a later event can establish the binding and this one can then be redelivered | no |

#### Webhook status codes, and why

| Status | `error` | When |
|--------|---------|------|
| `200` | — | **every** handled outcome above (`accepted`/`ignored`/`duplicate`/`stale`/`illegal`/`unresolved`) — all of them mean "we handled it, stop retrying" |
| `400` | `invalid_request` | the signature was valid but the body is unparsable, or the body could not be read |
| `401` | `unauthorized` | signature verification failed — **for any reason** |
| `404` | `unknown_provider` | `{provider}` is not a configured webhook endpoint on this server |
| `413` | `payload_too_large` | body exceeds the 64 KiB cap |
| `500` | `internal` | **our store failed.** Deliberately the *only* error class a healthy provider should ever see, because it is the only one that *should* be retried |
| `501` | `not_implemented` | billing off |

The `401` body is **coarse on purpose**: a missing header, a malformed header, an
unparsable signature, a wrong secret, a tampered body, and a stale timestamp all
produce the identical response, so a prober cannot learn which check tripped. The
precise reason goes only to the server-side audit log and the per-reason metric.

### `GET /v1/billing/subscription` — the caller's own status

**Auth: device auth v3** (signed with an empty body). The subject is taken from
the verified signature, so this endpoint **cannot be used to enumerate other
subjects** — there is no query parameter and no subject field to supply.

`200 OK`:

```json
{
  "subject": "dev_AbCdEf…",
  "provider": "stripe",
  "status": "active",
  "entitled": true,
  "current_period_end": "2026-08-26T00:00:00Z",
  "updated_at": "2026-07-26T18:22:41Z"
}
```

"Never subscribed" is a valid answer, not a fault — it returns `200` with
`{"subject":"…","status":"none","entitled":false}`. `provider`,
`current_period_end` and `updated_at` are omitted when unset. `401` on failed
device auth, `500` on a store fault, `501` when billing is off.

### Configuration (environment)

| Variable | Required? | Meaning |
|----------|-----------|---------|
| `SIGILD_BILLING_PROVIDERS` | opt-in | Comma-separated: `stripe`, `razorpay`, `juspay`. **Unset ⇒ billing OFF.** Unknown or duplicate names are a **boot error**. Requires `SIGILD_ENABLE_DEV_OPS` **and** `SIGILD_DEVICE_AUTH`. |
| `SIGILD_BILLING_DEFAULT_PROVIDER` | optional | Which provider a checkout uses when the body names none. Must be one of the enabled providers. Unset ⇒ the first listed. |
| `SIGILD_BILLING_SUCCESS_URL` | **required when billing is on** | Absolute `http(s)` URL the provider returns a paying customer to. |
| `SIGILD_BILLING_CANCEL_URL` | **required when billing is on** | Absolute `http(s)` URL for an abandoned checkout. |
| `SIGILD_STRIPE_SECRET_KEY` | **required for `stripe`** | `sk_…`, sent as a bearer token. |
| `SIGILD_STRIPE_WEBHOOK_SECRET` | **required for `stripe`** | `whsec_…`, the **endpoint signing secret** — a *different* secret from the API key, used only as the HMAC key. |
| `SIGILD_STRIPE_PRICE_ID` | optional | Default `price_…` for the subscription line item. |
| `SIGILD_STRIPE_API_BASE_URL` | optional | API host override (default `https://api.stripe.com`). |
| `SIGILD_RAZORPAY_KEY_ID` / `SIGILD_RAZORPAY_KEY_SECRET` | **required for `razorpay`** | API credentials, sent as HTTP Basic auth. |
| `SIGILD_RAZORPAY_WEBHOOK_SECRET` | **required for `razorpay`** | Dashboard webhook secret; a *different* secret from the key secret. |
| `SIGILD_RAZORPAY_AMOUNT_MINOR` | optional | Default payment-link amount in **minor units** (paise). Must be a positive integer. |
| `SIGILD_RAZORPAY_CURRENCY` | optional | Default currency (adapter default `INR`). |
| `SIGILD_RAZORPAY_DESCRIPTION` | optional | Payment-link description. |
| `SIGILD_RAZORPAY_API_BASE_URL` | optional | API host override (default `https://api.razorpay.com`). |
| `SIGILD_JUSPAY_MERCHANT_ID` / `SIGILD_JUSPAY_API_KEY` | **required for `juspay`** | Merchant ID (sent as `x-merchantid`) and API key (Basic-auth username, empty password). |
| `SIGILD_JUSPAY_CLIENT_ID` | optional | Payment-page client ID. |
| `SIGILD_JUSPAY_WEBHOOK_SCHEME` | optional | `basic` (default) or `hmac`. Any other value is a **boot error**. |
| `SIGILD_JUSPAY_WEBHOOK_USERNAME` / `SIGILD_JUSPAY_WEBHOOK_PASSWORD` | **required for `scheme=basic`** | Endpoint Basic-auth credentials. |
| `SIGILD_JUSPAY_WEBHOOK_SECRET` | **required for `scheme=hmac`** | HMAC key. |
| `SIGILD_JUSPAY_WEBHOOK_SIG_HEADER` | optional | Signature header name for `scheme=hmac` (default `X-Juspay-Signature`) — configurable **because the real name is unconfirmed**. |
| `SIGILD_JUSPAY_AMOUNT_MINOR` | optional | Default amount in minor units (paise); rendered to the decimal major-unit string Juspay expects, by integer arithmetic only. |
| `SIGILD_JUSPAY_CURRENCY` | optional | Default currency. |
| `SIGILD_JUSPAY_API_BASE_URL` | optional | API host override (default `https://api.juspay.in`). |

All of it is **parsed and validated before the listener binds**. Enabling a
provider without its credentials is a **boot error**, never a runtime surprise: a
server that started half-configured would either reject real webhooks it could
not authenticate, or offer checkouts it could not create. Validation performs
**no network I/O**, so boot cannot contact a payment provider.

### Storage (migration `0003_billing.sql`)

Two tables on top of the untouched `0001_init` / `0002_devices`:

| Table | Holds |
|-------|-------|
| `sigil_subscriptions` | `subject` (PK), `provider`, `customer_ref`, `subscription_ref`, `status`, `current_period_end`, `last_event_at` (the ordering guard), `created_at`, `updated_at`; partial index `sigil_subscriptions_by_provider_ref (provider, subscription_ref) WHERE subscription_ref <> ''` for subject resolution |
| `sigil_billing_processed_events` | `(provider, event_id)` **PRIMARY KEY** — the idempotency key, enforced by the **database**, not by application timing — plus the **normalized** `event_type`, `subject`, `processed_at`; index `sigil_billing_processed_events_by_time (processed_at)` |

The migration is **pure DDL** and adds **no column that can hold a card number,
CVV, expiry, cardholder name, billing address, email or phone**. What is stored
is a set of **opaque provider handles** — useful for reconciling a record against
a provider dashboard, useless for charging anyone. The **raw webhook payload is
never persisted**. `sigild_schema_version` reports **3** once applied.

The Postgres backend **reuses the op-log's existing `pgxpool`** (no second pool,
no new dependency). With Postgres unconfigured, billing falls back to the
**in-memory** subscription store, which is **non-durable**: subscriptions *and*
the processed-event ledger are lost on restart, so a webhook redelivered across a
restart **would be applied twice**. `sigild` warns loudly about this at boot.

### Audit log

Five structured events, **metadata only** — never an API key, a webhook secret, a
signature header, one byte of the raw webhook body, an email/name/phone, or an
amount:

| Event | Fields |
|-------|--------|
| `billing.checkout_created` | `request_id`, `provider`, `subject`, `session_id` |
| `billing.checkout_failed` | `request_id`, `provider`, `subject`, `err` (a `ProviderError` carrying **only** provider + operation + HTTP status, or a transport error — never the provider's response body, which can echo customer data) |
| `billing.webhook` | `request_id`, `provider`, `event_type` (normalized), `event_id` (so a `duplicate` is explainable), `outcome` |
| `billing.webhook_rejected` | `request_id`, `provider`, `reason` — the fixed enum `unknown_provider` / `unreadable_body` / `payload_too_large` / `bad_signature` / `malformed` / `store_unavailable`, surfaced **only** here and in the metric, never to the caller |
| `billing.subscription_transition` | `request_id`, `provider`, `subject`, `from`, `to` — fires **once per applied transition**, never for a duplicate/stale/illegal delivery, so the trail is a faithful history of entitlement |

### Honest limits (read before believing any of the above)

- **Nothing has been run against a live provider account.** No live API call, no
  real webhook, no real payment. The Stripe scheme is implemented with **high**
  confidence, the Razorpay **webhook** scheme with high confidence and its
  surrounding details (notably the `X-Razorpay-Event-Id` header name and the
  exact subscription event names) with **medium**; the **Juspay** adapter is
  explicitly **UNVERIFIED-AGAINST-LIVE-DASHBOARD** — its header names, signed
  message, endpoint path, response envelope and event vocabulary are a
  best-supported reading and **must** be confirmed before use. That uncertainty
  is quarantined behind a small internal `juspayWebhookVerifier` seam so a
  correction touches one type in one file.
- **Checkout creates a one-time hosted payment page for the India adapters.**
  Razorpay's `/v1/payment_links` and Juspay's `/session` are one-time flows;
  **recurring subscription/mandate creation is not implemented**. Both adapters'
  *webhook* sides already map subscription/mandate events, so a subscription
  created out-of-band drives the state machine correctly. This is a deliberate
  omission, not an oversight.
- **No account model.** Subscriptions key off the **authenticated device**, so a
  user with two devices has two subjects. There is no user, no household, no
  organization, no seat model, and no transfer.
- **No invoicing, proration, tax, refunds, chargebacks, dunning or reconciliation
  job**, and no admin surface for billing.
- **No entitlement enforcement.** `entitled` is reported; nothing in the op-log
  or device routes consults it yet.
- **The in-memory store is non-durable** (see above), and there is **no PCI
  attestation** — hosted checkout keeps scope minimal, it does not certify
  anything.
- **In any real deployment webhooks must arrive over TLS.** The dev server speaks
  plain HTTP.

---

## What production will add (not in the skeleton)

The dev op-log is a wiring placeholder. A production sync server would add, at
minimum:

- **Authentication and authorization** — the dev op-log now *has* a real
  **multi-device model** (contract v3: device enrollment with proof of
  possession, a device registry, per-vault grants, and revocation — see
  [above](#multi-device-auth-model-contract-v3--dev)), but production still owes
  an **account model**, session/token issuance (JWT bearer tokens,
  [`../sigild/internal/auth/`](../sigild/internal/auth/)), **key rotation** and
  re-enrollment, recovery, **rate limiting on enrollment attempts**, a **shared**
  (not per-process) replay store, and an ownership model stronger than
  trust-on-first-write. The legacy `SIGILD_OPLOG_PUBKEY` mode remains only a
  single static DEV key with no authorization at all, and with neither contract
  configured the dev route is wide open.
- **Durable, replicated storage** — the opt-in **Postgres** dev backend
  (`SIGILD_OPLOG_POSTGRES`, [`decisions/0014-postgres-durable-oplog-backend.md`](decisions/0014-postgres-durable-oplog-backend.md))
  now gives the dev op-log a durable, concurrent home, but a production store
  still needs managed migrations, backups, a proven restore, and replication
  (and, for large blobs, an object store such as S3/R2) — none of which the dev
  backend provides.
- **Real operation / CRDT semantics** — signed, ordered operations with
  Lamport-clock / Merkle-root replay-and-drop detection and conflict-free merge,
  versus today's plain append-and-read byte journal. The dev op-log's per-op
  SHA-256 **hash chain** (above) is a **tamper-EVIDENT** down-payment on this —
  it detects modification/insertion/deletion of stored ops by a *client-side*
  verifier — but it is **not** the signed, Merkle-rooted, Byzantine-resistant
  audit log the production build owes: a hostile server can still lie about the
  chain, and there is no signature or CRDT merge on the ops themselves.

Even then, the server's stored bytes stay **opaque client ciphertext**: the
server never holds plaintext or keys. See
[`threat-model.md`](threat-model.md) and [`crypto-spec.md`](crypto-spec.md).
