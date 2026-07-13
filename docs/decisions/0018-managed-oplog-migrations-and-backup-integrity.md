# 0018 — Managed op-log schema migrations and hash-chain-verified backup/restore

- **Status:** Accepted — 2026-07.

## Context

The durable Postgres op-log backend
([`0014`](0014-postgres-durable-oplog-backend.md)) created its schema with
**ad-hoc inline DDL** run at construction: `NewPostgresVaultLog` executed a
`CREATE TABLE IF NOT EXISTS` (plus an `ALTER TABLE … ADD COLUMN IF NOT EXISTS`
when the tamper-evidence hash column was added in
[`0016`](0016-tamper-evident-oplog-hash-chain.md)). That worked for a single
evolving dev table but had real gaps as soon as the backend is treated as a
persistence story rather than a scratch buffer:

1. **No ordered, tracked history.** Inline `IF NOT EXISTS` DDL is a set of
   idempotent statements with no notion of *version*, no record of *what was
   applied when*, and no way to reason about or audit the schema's evolution.
2. **No safe concurrent apply.** Two `sigild` instances booting against the same
   database would each run the DDL. `IF NOT EXISTS` masks the race for the current
   trivial schema, but any non-idempotent future change would be unsafe.
3. **No operator control.** Schema changes happened implicitly at process start,
   with no way to apply or inspect them as a separate, gated step.
4. **No stated backup story.** The durable backend had no documented backup /
   restore procedure and — more importantly — no way to *prove* a restore was
   faithful.

The hard constraints from [`0003`](0003-dev-gated-opaque-op-log.md) /
[`0014`](0014-postgres-durable-oplog-backend.md) bind absolutely: the server
stores **opaque client-encrypted blobs**, does **no crypto on the plaintext**,
stays **dev-gated** (`SIGILD_ENABLE_DEV_OPS`, default `501`), and adds **no new
dependency** (`pgx` remains the only third-party import).

## Decision

Replace the inline DDL with a **managed, versioned migration system** for the
Postgres backend, and document a **backup/restore runbook whose integrity is
validated by the existing hash chain** rather than a new mechanism.

- **Embedded, versioned migrations.** Migrations are `go:embed`'d SQL files under
  `sigild/internal/store/migrations/`, named `NNNN_description.sql`; the
  zero-padded leading integer is the version and they apply in ascending order.
  The baseline is **`0001_init.sql`** (version `1`), which creates the
  `sigil_vault_ops` table (opaque `bytea` `blob` + `bytea` `hash` +
  `(vault_id, seq)` primary key) and, for backward compatibility, cleanly adopts a
  legacy table created by the old inline code.
- **A `schema_migrations` tracking table** (`version`, `name`, `applied_at`)
  records what has been applied, making runs idempotent and **auditable**.
- **Auto-apply at boot, with an opt-out.** By default the backend applies pending
  migrations at construction (a fresh DB is set up exactly as the old inline DDL
  did — backward compatible; an up-to-date DB is a no-op). Setting
  **`SIGILD_OPLOG_AUTO_MIGRATE=0`** (`0`/`false`/`no`/`off`) disables auto-apply;
  boot then applies nothing and **fails fast** if the DB is behind the latest
  embedded migration, directing the operator to run `sigild migrate`.
- **An operator CLI (not an HTTP endpoint).** `sigild migrate` applies pending
  migrations; `sigild migrate status` reports each known migration as applied
  (with its timestamp) or pending and applies nothing. Both use
  `SIGILD_OPLOG_POSTGRES`.
- **Safe concurrent boots.** The whole run is serialized across instances by a
  **session-level `pg_advisory_lock`** on a fixed key, and each pending migration
  commits in its **own transaction**, so two instances cannot double-apply.
- **Observability.** The applied version is exported as the **`sigild_schema_version`**
  gauge on `GET /metrics` (0 for the mem/file backends).
- **Backup integrity via the hash chain.** A logical `pg_dump` / `pg_restore` (or
  `psql`) dumps the `blob` **and** `hash` columns as `bytea` **byte-for-byte**, so
  the per-op SHA-256 hash chain ([`0016`](0016-tamper-evident-oplog-hash-chain.md))
  survives a restore unchanged. The **post-restore integrity gate** is the
  existing server-side verifier, `GET /v1/vaults/{id}/ops/verify`: an intact
  restore returns `ok: true` with the **same `tip_hash`** the live server produced
  before the backup. No bespoke backup-authentication mechanism is introduced.

## Consequences

- **Auditable, ordered schema evolution.** Schema changes are now discrete,
  versioned, embedded artifacts tracked in `schema_migrations`, not implicit
  idempotent DDL — a reader (or auditor) can see exactly which migrations exist and
  which have been applied and when.
- **Safe concurrent boots.** The session advisory lock + per-migration transaction
  mean multiple `sigild` instances can boot against one database without
  double-applying; one migrates while the others wait and then observe an
  up-to-date schema.
- **Operator control with a safe default.** Auto-apply keeps the zero-config dev
  path working exactly as before; `SIGILD_OPLOG_AUTO_MIGRATE=0` gives a controlled
  deploy a fail-fast, migrate-as-a-separate-step posture.
- **Provable restores without new crypto.** Backup integrity reuses the tamper-
  evidence hash chain: because the chain commits each op to the previous over the
  exact stored bytes, a faithful dump/restore reproduces the same `tip_hash`, and
  `/ops/verify` is the check. Phase 28 verification ran a dump → drop → restore
  cycle and confirmed `/ops/verify` returned `ok: true` with an unchanged
  `tip_hash`.
- **Zero-knowledge intact; no new dependency.** Migrations are **pure DDL** over
  opaque `bytea` columns — the server still never decodes, parses, or decrypts a
  blob and does no cryptography. The migration runner and CLI are **pure stdlib +
  `pgx` + `go:embed`**; `pgx` stays the only third-party import
  ([`0005`](0005-stdlib-only-sigild.md), [`0014`](0014-postgres-durable-oplog-backend.md)).
- **Posture unchanged.** Still `SIGILD_ENABLE_DEV_OPS`-gated and `501` by default,
  still unauthenticated unless `SIGILD_OPLOG_PUBKEY`, still opaque blobs only.
  Migrations and backups matter **only** when `SIGILD_OPLOG_POSTGRES` is set.
- **Not a production change-management or persistence pipeline.** This is a real,
  ordered, tracked migration system and a chain-verified backup runbook for the
  **dev** Postgres backend — not down-migrations, online/zero-downtime rewrites,
  managed rollout tooling, PITR (WAL archiving), streaming replication, an object
  store, or restore-drill automation. Those remain unbuilt (see
  [`../deployment.md` §7](../deployment.md#7-what-is-not-yet-deployable)).
- Documented in-sync: the migration system and backup/restore runbook are
  [`../deployment.md` §11–§12](../deployment.md#11-schema-migrations-postgres-backend);
  the `sigild_schema_version` gauge and the migrate operator CLI are in
  [`../api.md`](../api.md#metrics); the component change is in
  [`../architecture.md`](../architecture.md).

Cross-links: builds on [0014](0014-postgres-durable-oplog-backend.md) (the
Postgres backend) and [0016](0016-tamper-evident-oplog-hash-chain.md) (the hash
chain it reuses for restore integrity); stays within the stdlib-only-except-`pgx`
posture of [0005](0005-stdlib-only-sigild.md).
