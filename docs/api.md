# sigild HTTP API reference

> **STATUS: pre-audit skeleton.** `sigild` is the Sigil sync-server skeleton. It
> performs **no cryptography**, holds **no keys**, and stores **no plaintext**.
> The only stateful surface — the vault operation log — is a **dev-only,
> opt-in, in-memory, unauthenticated** stub that stores **opaque
> client-encrypted blobs** the server never decrypts or interprets. Nothing
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

`200` when every *configured* dependency dials OK (or is unconfigured); `503`
when a configured dependency is unreachable, so a load balancer drains the
instance. The skeleton does a plain TCP dial only — no auth handshake, no real
pg/redis ping (that is the production build's job).

```json
{ "version": "<build version>", "checks": { "postgres": "ok|unreachable|unconfigured", "redis": "ok|unreachable|unconfigured" } }
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
> - **IN-MEMORY / NON-DURABLE.** Backed by a process-memory map. It is **lost on
>   restart**, never written to disk, and not replicated. No Postgres, no S3, no
>   backups.
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

---

## What production will add (not in the skeleton)

The dev op-log is a wiring placeholder. A production sync server would add, at
minimum:

- **Authentication and authorization** — device-key-authenticated requests and
  per-vault membership checks (none exist today; the dev route is wide open).
- **Durable, replicated storage** — a real Postgres/object-store (S3/R2) backend
  with migrations, backups, and a proven restore, replacing the in-memory map.
- **Real operation / CRDT semantics** — signed, ordered operations with
  Lamport-clock / Merkle-root replay-and-drop detection and conflict-free merge,
  versus today's plain append-and-read byte journal.

Even then, the server's stored bytes stay **opaque client ciphertext**: the
server never holds plaintext or keys. See
[`threat-model.md`](threat-model.md) and [`crypto-spec.md`](crypto-spec.md).
