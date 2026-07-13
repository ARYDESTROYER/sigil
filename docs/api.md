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
fails; the in-memory and file-backed backends have no remote dependency and
report healthy.

```json
{ "version": "<build version>", "checks": { "postgres": "ok|unreachable|unconfigured", "redis": "ok|unreachable|unconfigured", "oplog": "ok|unreachable|unconfigured" } }
```

### `GET /version` — build identity

Echoes the build name and injected version string. No secrets, no crypto.

```json
{ "name": "sigild", "version": "<build version>" }
```

The `version` value is injected at build time from the git short SHA via
`-ldflags` (default `"dev"`); see
[`../sigild/internal/buildinfo/buildinfo.go`](../sigild/internal/buildinfo/buildinfo.go).

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
>     enrollment, no CRDT/merge, and no backup/restore or managed migrations.
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
>   journal with a monotonic per-vault sequence number. There is **no** CRDT
>   merge, no Lamport/Merkle verification, no signature checking, no conflict
>   resolution — those are deferred to the production build.
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
  | `501 Not Implemented` | `not_implemented` | `SIGILD_ENABLE_DEV_OPS` is unset (the default) |

### `GET /v1/vaults/{vaultID}/ops?since=N` — read operations

Return the vault's operations with sequence number **greater than `N`** (default
`since=0` returns from the beginning), in ascending `seq` order.

- **Query:** `since` (optional, integer, default `0`) — return ops with
  `seq > since`.
- **Success — `200 OK`:**

  ```json
  {
    "vaultID": "<vaultID>",
    "ops": [
      { "seq": 1, "blob": "<base64 of the opaque stored bytes>" }
    ],
    "next": <highest seq returned, to pass as the next `since`>
  }
  ```

  `blob` is the standard base64 encoding of the exact opaque bytes that were
  POSTed — the server re-emits ciphertext it never decoded. An unknown vault ID
  returns an empty `ops` array, not an error.

- **Errors:** `501 Not Implemented` (`not_implemented`) when
  `SIGILD_ENABLE_DEV_OPS` is unset.

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
  versus today's plain append-and-read byte journal.

Even then, the server's stored bytes stay **opaque client ciphertext**: the
server never holds plaintext or keys. See
[`threat-model.md`](threat-model.md) and [`crypto-spec.md`](crypto-spec.md).
