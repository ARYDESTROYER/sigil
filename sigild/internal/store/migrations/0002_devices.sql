-- 0002_devices: device registry, enrollment-token ledger, and per-vault
-- authorization grants for the multi-device auth model (Phase 41).
--
-- It applies cleanly ON TOP OF 0001_init and touches NOTHING in
-- sigil_vault_ops: the op-log rows (and their tamper-evidence hash chain) are
-- untouched, so a database migrated from 0001 keeps serving the existing
-- single-key / unauthenticated modes byte-for-byte unchanged.
--
-- ZERO-KNOWLEDGE: these tables hold AUTH METADATA ONLY — Ed25519 PUBLIC keys,
-- server-assigned IDs, labels, permissions, timestamps. No vault plaintext, no
-- key material that could decrypt anything, and no enrollment token in the
-- clear: a token is recorded only as its SHA-256 hex digest.
--
-- Every statement is IF NOT EXISTS so a partially-created schema adopts cleanly.

-- Enrolled client devices. device_id is server-assigned (128 bits of
-- crypto/rand, raw-URL base64, "dev_"-prefixed). public_key is the raw 32-byte
-- Ed25519 public key and is UNIQUE: a key identifies at most one device.
-- status is 'active' | 'revoked'; a revoked row is RETAINED (never deleted) so
-- the audit trail stays explainable.
CREATE TABLE IF NOT EXISTS sigil_devices (
	device_id  text        PRIMARY KEY,
	public_key bytea       NOT NULL UNIQUE,
	label      text        NOT NULL DEFAULT '',
	status     text        NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	revoked_at timestamptz
);

-- Operator-provisioned enrollment tokens, recorded by SHA-256 HEX DIGEST ONLY —
-- the token itself is never written to the database. used_at is the single-use
-- marker: a token with used_at set can never be spent again (the UPDATE that
-- consumes it is conditional on used_at IS NULL, so the single-use guarantee is
-- enforced by the database, not by application timing).
CREATE TABLE IF NOT EXISTS sigil_enrollment_tokens (
	token_hash text        PRIMARY KEY,
	issued_at  timestamptz NOT NULL DEFAULT now(),
	expires_at timestamptz,
	used_at    timestamptz,
	used_by    text
);

-- Per-vault authorization grants: (vault_id, device_id) -> permission.
-- permission is 'read' | 'write' (write implies read). is_owner marks the device
-- that claimed the vault on first write; the partial UNIQUE index below is what
-- makes that claim atomic — at most ONE owner row can ever exist per vault, so
-- concurrent first-writers resolve to a single winner in the database.
CREATE TABLE IF NOT EXISTS sigil_device_grants (
	vault_id   text        NOT NULL,
	device_id  text        NOT NULL,
	permission text        NOT NULL,
	is_owner   boolean     NOT NULL DEFAULT false,
	created_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (vault_id, device_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS sigil_device_grants_one_owner
	ON sigil_device_grants (vault_id) WHERE is_owner;

CREATE INDEX IF NOT EXISTS sigil_device_grants_by_device
	ON sigil_device_grants (device_id);
