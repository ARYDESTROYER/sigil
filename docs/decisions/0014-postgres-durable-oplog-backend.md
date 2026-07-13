# 0014 — Postgres durable op-log backend (`SIGILD_OPLOG_POSTGRES`)

- **Status:** Accepted — 2026-07.

## Context

[`0003`](0003-dev-gated-opaque-op-log.md) added a **dev-gated, opaque** vault
op-log to `sigild` behind a small `VaultLog` seam (the server does no
cryptography and never decodes the bytes), and
[`0006`](0006-file-backed-dev-op-log-backend.md) added a second, **file-backed**
backend for local-dev durability. Both are process-local: the in-memory map is
lost on restart, and the file backend is a single-node convenience with no
concurrency story beyond per-file locking. Nothing behind the seam is a **real,
durable, concurrent store**, so the demo path (`sigil push` → `sigil pull`)
cannot survive a realistic multi-writer or restart-heavy dev setup, and the
`VaultLog` interface has never been exercised by a networked database.

[`0005`](0005-stdlib-only-sigild.md) deliberately kept `sigild` **Go stdlib-only**
(no `go.sum`) while every endpoint was a stub, and explicitly said it would be
**superseded** "when durable storage and caching land." That time has come — but
only **partially**: we want one real store adapter, not the whole production data
layer.

The constraints from [`0003`](0003-dev-gated-opaque-op-log.md) still bind. The
server stores **opaque client-encrypted blobs** and does no crypto; the op-log
stays **dev-gated** (`SIGILD_ENABLE_DEV_OPS`, default `501`) and
**unauthenticated unless `SIGILD_OPLOG_PUBKEY`** is set
([`0008`](0008-device-key-request-auth.md),
[`0010`](0010-op-log-auth-v2-nonce-replay.md)). A Postgres backend must weaken
none of that.

## Decision

Add a **third, opt-in `VaultLog` backend backed by Postgres**, selected at
startup by the **`SIGILD_OPLOG_POSTGRES`** environment variable (a libpq/`pgx`
DSN), behind the **same `SIGILD_ENABLE_DEV_OPS` gate**:

- **Same `VaultLog` interface, same opaque contract.** The Postgres backend
  implements the identical seam as the in-memory and file backends: it stores
  each operation body as an **opaque `bytea`** and re-emits it unchanged. The
  server does **no cryptography**, never decodes/parses/orders/merges the bytes;
  the 64 KiB per-op cap and `413` still apply.
- **Selection precedence: `SIGILD_OPLOG_POSTGRES` > `SIGILD_OPLOG_DIR` >
  in-memory.** With the dev flag unset (the default and only production-safe
  setting) the route is still `501` and **no** backend is constructed. With the
  dev flag on: a Postgres DSN selects the Postgres backend; otherwise a set
  `SIGILD_OPLOG_DIR` selects the file backend; otherwise the in-memory default.
- **Concurrency-safe per-vault sequencing.** The monotonic per-vault `seq` is
  assigned inside a **transaction** (a per-`vaultID` advisory-lock / row-lock
  guard), so concurrent appenders to the same vault get gap-free, strictly
  increasing sequence numbers without races. Reads (`since > N`) come off an
  indexed `(vault_id, seq)` ordering.
- **This adds `sigild`'s first third-party dependency (`pgx`).** The module gains
  a **`go.sum`**. This **relaxes [ADR 0005](0005-stdlib-only-sigild.md)** for
  exactly this backend: the **core server and the in-memory / file-backed
  backends stay stdlib-only**; only the Postgres adapter links `pgx`, and it is
  dormant unless a DSN is configured.
- **It is still NOT a finished production store.** It gives the dev op-log
  durability and concurrency, but there is **no auth / enrollment model, no
  per-vault authorization, no CRDT / merge, no managed migrations, and no
  backup / restore / replication** around it. It remains **dev-gated**, remains
  **unauthenticated unless `SIGILD_OPLOG_PUBKEY`**, and **must not be exposed
  publicly or hold real secrets**.

## Consequences

- The dev op-log now has a **durable, concurrent** home in local dev when a DSN
  is set, and the `VaultLog` seam is exercised by a real networked database — the
  first production-store *adapter*, validating the interface against something
  other than process memory.
- **`sigild` is no longer strictly stdlib-only.** It carries one dependency
  (`pgx`) and now has a `go.sum`; CI resolves modules for the server for the
  first time. This is a deliberate, documented relaxation of
  [ADR 0005](0005-stdlib-only-sigild.md) (partially superseded by this ADR for
  the storage backend), not an accident — the honest framing is that `sigild` is
  "stdlib-only **except** the opt-in Postgres backend," not "stdlib-only."
- **Nothing about the security posture changes.** Still no crypto on the server,
  still opaque `bytea` blobs only, still `SIGILD_ENABLE_DEV_OPS`-gated and `501`
  by default, still unauthenticated unless `SIGILD_OPLOG_PUBKEY`. Durability +
  concurrency are the **only** new properties.
- **Production still owes** the real data layer: auth / enrollment, per-vault
  authorization, CRDT / merge semantics, managed migrations, backups with a
  proven restore, and replication (and an object store for large blobs). This ADR
  is one adapter, not that layer.
- Documented in-sync: the three backends and the `SIGILD_OPLOG_POSTGRES`
  selection/precedence are in [`../api.md`](../api.md); the Postgres backend and
  the stdlib-only relaxation are in [`../architecture.md`](../architecture.md)
  §1 and §4; the deploy-story storage note is in
  [`../deployment.md`](../deployment.md) §7; and
  [ADR 0005](0005-stdlib-only-sigild.md) carries a cross-reference back here.

Cross-links: builds on [0003](0003-dev-gated-opaque-op-log.md) and
[0006](0006-file-backed-dev-op-log-backend.md); partially supersedes
[0005](0005-stdlib-only-sigild.md).
