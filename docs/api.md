# sigild HTTP API reference

> **STATUS: pre-audit skeleton.** `sigild` is the Sigil sync-server skeleton. It
> performs **no cryptography**, holds **no keys**, and stores **no plaintext**.
> The only stateful surface — the vault operation log — is a **dev-only,
> opt-in, unauthenticated** store of **opaque client-encrypted blobs** the
> server never decrypts or interprets (in-memory by default, with optional
> file-backed or durable Postgres backends). Nothing
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
| `sigild_http_requests_total` | counter | total HTTP requests served |
| `sigild_oplog_appends_total` | counter | op-log appends accepted (`POST …/ops`) |
| `sigild_oplog_verify_total` | counter | chain verifies run (`GET …/ops/verify`) |
| `sigild_oplog_auth_denied_total{reason="…"}` | counter | op-log auth denials, **labelled by reason** (missing / invalid / stale / replayed) |
| `sigild_oplog_ratelimit_rejected_total` | counter | appends rejected with `429` by the per-vault rate limiter |
| `sigild_schema_version` | gauge | applied op-log DB migration version (`0` when the backend is not Postgres) |
| `sigild_build_info{version="…"}` | gauge (`1`) | build identity; the version label carries the injected build SHA |

Counters are **process-lifetime and unlabelled by vault** (no per-vault
cardinality blow-up, and no vault ID — itself client-chosen and potentially
sensitive — is exported). The endpoint performs **no cryptography** and reads no
stored bytes; it only reports aggregate counts.

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
> - **UNAUTHENTICATED.** There is no auth, no identity, no per-vault access
>   control. Anyone who can reach the port can read and append to any vault ID.
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
      { "seq": 1, "blob": "<base64 of the opaque stored bytes>", "hash": "<hex SHA-256 chain hash>" }
    ],
    "next": <highest seq returned, to pass as the next `since`>,
    "has_more": <true if more ops exist beyond this page, else false>
  }
  ```

  `blob` is the standard base64 encoding of the exact opaque bytes that were
  POSTed — the server re-emits ciphertext it never decoded. An unknown vault ID
  returns an empty `ops` array, not an error.

  `hash` is the op's **hex-encoded SHA-256 hash-chain link** (64 hex chars) — the
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
    "tip_hash": "<hex SHA-256 of the last op's chain link>",
    "broken_at_seq": null
  }
  ```

  - `ok` — `true` if the recomputed chain matches every stored per-op hash. An
    empty vault is trivially intact (`ok = true`, `count = 0`).
  - `count` — how many ops were checked.
  - `tip_hash` — the last op's hex chain hash (the vault's current tip); an empty
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

### Authentication (optional, dev) — `SIGILD_OPLOG_PUBKEY`

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

The matching CLI key file is JSON, written with mode `0600`:

```json
{ "version": 1, "seed": "<std-base64 of 32 bytes>", "public_key": "<std-base64 of 32 bytes>" }
```

**Honest scope:** a single configured DEV device key; the seen-nonce replay
cache is **in-memory / per-process** (a multi-instance production deploy needs a
shared store); multi-device enrollment / registry / JWT auth is future; and with
`SIGILD_OPLOG_PUBKEY` unset there is no auth at all.

### Audit log (structured server-side events)

Every op-log **append**, **list**, and **auth denial** emits a **structured
audit event** to the server log (alongside the request-scoped access log). Each
event carries only **metadata plus an integrity fingerprint** — never the
payload:

| Field | Meaning |
|-------|---------|
| `event` | the audited action — e.g. `oplog.append`, `oplog.list`, `oplog.auth_denied` |
| `request_id` | the request's `X-Request-ID`, to correlate with the access log |
| `vault_id` | the target vault ID (opaque, client-chosen) |
| `seq` | the sequence number assigned (append) or the highest returned (list) |
| `size` | the opaque blob's length in bytes |
| `blob_sha256` | hex **SHA-256 fingerprint** of the opaque stored bytes — for integrity / traceability only |
| `auth` / `reason` | on a denial, why it failed (missing / invalid / stale / replayed signature) |

The server logs a **fingerprint** of the ciphertext, **not** the ciphertext: it
**NEVER** writes the opaque blob content, any signature, nonce, timestamp, or key
material to the log. Because the fingerprint is taken over bytes that are
**already client-encrypted**, an operator can prove *who appended what, when*
without the server ever seeing plaintext — the audit trail does not weaken the
zero-knowledge property (see [`threat-model.md`](threat-model.md)).

Request bodies are read under the **request context**: a client that
disconnects, or a read that exceeds the server's `http.Server` timeouts, cancels
the in-flight append/read (and, for the Postgres backend, releases the pooled
connection) rather than blocking a goroutine.

---

## What production will add (not in the skeleton)

The dev op-log is a wiring placeholder. A production sync server would add, at
minimum:

- **Authentication and authorization** — full device enrollment, a multi-device
  registry, JWT bearer tokens, and per-vault membership checks. The optional
  `SIGILD_OPLOG_PUBKEY` signature check (above) is only a single static DEV
  device key; its per-request nonce is checked against an in-memory,
  **per-process** replay cache (a multi-instance deploy would need a shared one),
  and with it unset the dev route is wide open.
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
