-- 0001_init: baseline op-log schema for the durable Postgres backend.
--
-- This migration is the managed replacement for the old ad-hoc inline DDL that
-- NewPostgresVaultLog used to run at construction. It MUST be idempotent AND
-- adopt a legacy table cleanly:
--
--   * CREATE TABLE IF NOT EXISTS      -> fresh DB gets the full table; a DB
--     created by the old inline code already has it (no-op).
--   * ALTER TABLE ... ADD COLUMN      -> a very old table that predates the
--     tamper-evidence hash chain gets the hash column added NULLABLE (a fresh
--     table already has it NOT NULL from CREATE TABLE above; acceptable for a
--     dev backend with no real data).
--
-- The (vault_id, seq) primary key enforces per-vault sequence uniqueness at the
-- database level. blob is the OPAQUE client-encrypted payload (never decoded by
-- the server). hash is the 32-byte SHA-256 chain hash (see oplogchain.go).
-- created_at is server-side bookkeeping only and is never returned to clients;
-- it carries a literal value in a pg_dump so backup/restore round-trips cleanly.

CREATE TABLE IF NOT EXISTS sigil_vault_ops (
	vault_id   text        NOT NULL,
	seq        bigint      NOT NULL,
	blob       bytea       NOT NULL,
	hash       bytea       NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (vault_id, seq)
);

ALTER TABLE sigil_vault_ops ADD COLUMN IF NOT EXISTS hash bytea;
