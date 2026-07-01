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
> - **IN-MEMORY BY DEFAULT / OPTIONAL FILE-BACKED.** With the dev flag on, the
>   op-log is backed by a process-memory map by default — **lost on restart**,
>   never written to disk, not replicated. If **`SIGILD_OPLOG_DIR`** is also set,
>   a **file-backed** backend persists each vault's journal under that directory
>   for **local-dev durability** instead (the `vaultID` is base64url-encoded to a
>   safe flat filename, so it cannot escape the directory). Either way it is the
>   **same opaque, dev-only, unauthenticated `VaultLog`** — **not** the production
>   store. Production durability is still Postgres/S3 with backups, and is
>   unbuilt. See [`decisions/0006-file-backed-dev-op-log-backend.md`](decisions/0006-file-backed-dev-op-log-backend.md).
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
> **single static device key** check, not an account/enrollment system. A
> per-request **nonce** (contract **v2**) plus the 300-second timestamp window
> now let the server **reject replays** within the window — but the nonce store
> is **in-memory** (lost on restart, not shared across instances), so it is not a
> production replay defense. Full device enrollment, a multi-device registry, JWT
> bearer tokens (see [`../sigild/internal/auth/`](../sigild/internal/auth/)), and
> a shared/persistent nonce store remain **future**. Still plain-HTTP, dev-gated,
> and not for real secrets. See
> [`decisions/0008-device-key-request-auth.md`](decisions/0008-device-key-request-auth.md)
> and [`decisions/0012-nonce-replay-protection.md`](decisions/0012-nonce-replay-protection.md).

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
| `X-Sigil-Nonce` | a fresh per-request nonce, printable ASCII (`0x21`–`0x7E`, no space/control), **≤ 128 bytes** — the demo `cli` sends standard-base64 of 16 random bytes |
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
{NONCE}\n           same value sent in X-Sigil-Nonce
{BODY}              raw request body bytes; EMPTY for GET
```

That is, byte-for-byte:

```
MESSAGE = "sigil-oplog-auth-v2\n" + METHOD + "\n" + PATH + "\n" + QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + BODY
```

The client signs `MESSAGE` with its 32-byte Ed25519 secret seed (the demo `cli`
uses `sigil_core::{sign, public_key_from_seed}`) and sends the signature in
`X-Sigil-Signature`, the same timestamp in `X-Sigil-Timestamp`, and the same
nonce in `X-Sigil-Nonce`. **v2 is a hard cutover — v1 signatures no longer
verify** (the domain string and the message framing both differ).

The server, when `SIGILD_OPLOG_PUBKEY` is configured, verifies on both verbs:

1. read `X-Sigil-Timestamp`, `X-Sigil-Nonce`, `X-Sigil-Signature`; if a required
   header is missing/blank **or** the nonce is malformed (empty, `> 128` bytes,
   or contains a non-`0x21`–`0x7E` byte) → `401`. The nonce is validated **before**
   it is folded into the message, so it cannot shift the message framing.
2. parse the timestamp as `int64`; if it is not an integer **or** the skew
   `abs(now - ts)` exceeds **300 seconds** → `401` (stale/skew).
3. reconstruct `MESSAGE` from the request method, path, raw query, the timestamp
   header, the nonce header, and the (size-limited) body.
4. base64-decode the signature and `ed25519.Verify(pubkey, MESSAGE, sig)`; if it
   does not verify → `401`.
5. **replay guard:** check the nonce against the in-memory nonce store; a nonce
   already seen within its retention window (2× the skew window) → `401`. Only
   validly-signed requests reach this step, so unauthenticated traffic cannot
   populate the store.
6. on success, record the nonce and fall through to the normal append/read handler.

All failures use the standard typed envelope with `401 Unauthorized`:

```json
{ "error": "unauthorized", "detail": "<reason>" }
```

The matching CLI key file is JSON, written with mode `0600`:

```json
{ "version": 1, "seed": "<std-base64 of 32 bytes>", "public_key": "<std-base64 of 32 bytes>" }
```

**Honest scope:** a single configured DEV device key; replays are rejected only
by an **in-memory, per-process nonce store** (lost on restart, not shared across
instances — a captured request could still be replayed after a restart within its
window); multi-device enrollment / registry / JWT auth is future; and with
`SIGILD_OPLOG_PUBKEY` unset there is no auth at all.

---

## What production will add (not in the skeleton)

The dev op-log is a wiring placeholder. A production sync server would add, at
minimum:

- **Authentication and authorization** — full device enrollment, a multi-device
  registry, JWT bearer tokens, and per-vault membership checks. The optional
  `SIGILD_OPLOG_PUBKEY` signature check (above) is only a single static DEV
  device key; its replay guard is an **in-memory, per-process nonce store** (lost
  on restart, not shared across instances), so production still needs a
  shared/persistent nonce store; with the pubkey unset the dev route is wide open.
- **Durable, replicated storage** — a real Postgres/object-store (S3/R2) backend
  with migrations, backups, and a proven restore, replacing the in-memory map.
- **Real operation / CRDT semantics** — signed, ordered operations with
  Lamport-clock / Merkle-root replay-and-drop detection and conflict-free merge,
  versus today's plain append-and-read byte journal.

Even then, the server's stored bytes stay **opaque client ciphertext**: the
server never holds plaintext or keys. See
[`threat-model.md`](threat-model.md) and [`crypto-spec.md`](crypto-spec.md).
