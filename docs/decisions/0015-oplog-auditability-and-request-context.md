# 0015 — Op-log auditability and request-context propagation

- **Status:** Accepted — 2026-07.

## Context

The dev op-log ([`0003`](0003-dev-gated-opaque-op-log.md)) grew from an in-memory
map into a real seam with three backends — in-memory, file-backed
([`0006`](0006-file-backed-dev-op-log-backend.md)), and durable Postgres
([`0014`](0014-postgres-durable-oplog-backend.md)) — and an optional Ed25519
request-auth layer ([`0008`](0008-device-key-request-auth.md),
[`0010`](0010-op-log-auth-v2-nonce-replay.md)). But two gaps remained that make a
dev backend flaky and opaque to operate:

- **No request-context propagation.** The `VaultLog` interface (`Append` /
  `Since`) took no `context.Context`, so a client disconnect or a slow request
  could not cancel in-flight storage work. Against the networked Postgres backend
  that means a dropped client can pin a pooled connection until the query returns
  on its own; body reads were likewise unbounded by the request lifetime.
- **No visibility, and a readiness probe that lies about storage.** There was no
  record of *who appended what, when* — appends and auth denials left no
  structured trail — and `/readyz` only TCP-dialled the (future) `postgres` /
  `redis` addresses, so it reported ready even when the **active op-log backend**
  (the Postgres pool actually serving traffic) was unreachable.

The constraints from [`0003`](0003-dev-gated-opaque-op-log.md) still bind
absolutely: the server stores **opaque client-encrypted blobs** and does **no
crypto**; the op-log stays **dev-gated** (`SIGILD_ENABLE_DEV_OPS`, default `501`)
and **unauthenticated unless `SIGILD_OPLOG_PUBKEY`** is set. Adding
observability must **not** put any plaintext, key, blob content, or auth secret
into a log — that would puncture the zero-knowledge boundary the whole design
rests on.

## Decision

Harden the dev op-log for reliability and auditability, changing **none** of its
security posture:

- **(a) Propagate request context through `VaultLog`.** `Append` and `Since` take
  a `context.Context` threaded from the HTTP request, and request bodies are read
  under it. A cancelled or slow request (client disconnect, `http.Server`
  read/write/idle timeouts, or — for Postgres — `pgxpool` acquire limits) cancels
  the in-flight append/read instead of leaking a goroutine or pinning a pooled
  connection. The in-memory and file backends honour cancellation cheaply; the
  Postgres backend passes the context straight to `pgx`.
- **(b) `/readyz` pings the live backend.** Readiness now performs a **real**
  health check of the **active** op-log backend: when the Postgres backend is
  configured it **pings the `pgxpool`** and returns `503` if the DB is down (so a
  load balancer drains the instance); the in-memory and file backends have no
  remote dependency and report healthy. The future `SIGILD_POSTGRES_ADDR` /
  `SIGILD_REDIS_ADDR` probes remain plain TCP dials.
- **(c) A structured audit log — metadata + a fingerprint, never the content.**
  Every op-log **append**, **list**, and **auth denial** emits a structured event
  (`event`, `request_id`, `vault_id`, `seq`, `size`, `blob_sha256`, and the
  denial `reason`). The `blob_sha256` is a hex **SHA-256 fingerprint of the
  opaque stored bytes**, for integrity / traceability only. The server **NEVER**
  logs the blob content, any signature, nonce, timestamp, or key material.
  Because the fingerprint is taken over bytes that are **already
  client-encrypted**, the audit trail proves *who appended what, when* **without
  the server ever seeing plaintext** — the zero-knowledge boundary is preserved.

This is a **dev-backend** hardening. It does not change the gate, the opaque
contract, the 64 KiB cap, or the optional single-static-key auth model.

## Consequences

- The dev op-log is **more reliable** (cancellation/timeout-bounded work, no
  goroutine/connection leaks on client disconnect) and **auditable** (a
  structured, correlatable trail of appends, lists, and auth denials), and
  `/readyz` now tells the truth about the store that is actually serving traffic.
- **The zero-knowledge boundary is intact.** The audit log records only metadata
  and a fingerprint of the already-encrypted blob; it reveals nothing the server
  did not already hold, and the server still performs no crypto and cannot
  decrypt a vault. Auth denials (missing / invalid / stale / replayed signature)
  are visible without logging any secret. Provable by test: no blob content
  appears in the log output.
- **The security posture is unchanged.** Still `SIGILD_ENABLE_DEV_OPS`-gated and
  `501` by default, still unauthenticated unless `SIGILD_OPLOG_PUBKEY`, still
  opaque blobs only. Reliability + auditability are the **only** new properties.
- **Still not a production sync server.** This is dev-op-log hardening: a
  production audit log would be **signed and tamper-evident**, and the store would
  still owe auth / enrollment, per-vault authorization, CRDT / merge semantics,
  managed migrations, and backup / restore / replication — none of which this ADR
  adds.
- Documented in-sync: the real `/readyz` backend ping and the structured audit
  log are in [`../api.md`](../api.md); the request-context propagation,
  `http.Server` timeouts / `pgxpool` limits, and the audit log are in
  [`../architecture.md`](../architecture.md) §1–§2; and the zero-knowledge note is
  in [`../threat-model.md`](../threat-model.md).

Cross-links: builds on [0003](0003-dev-gated-opaque-op-log.md),
[0008](0008-device-key-request-auth.md), and
[0014](0014-postgres-durable-oplog-backend.md).
