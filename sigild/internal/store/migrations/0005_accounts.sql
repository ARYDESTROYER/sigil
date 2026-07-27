-- 0005_accounts: accounts as the subject of ENTITLEMENT and the OWNER of vaults
-- (Phase 52, ADR 0040).
--
-- WHAT IT DOES NOT TOUCH, stated first because it is the load-bearing promise:
--
--   * NOTHING in sigil_vault_ops. Not a row, not a column, not the blob, not the
--     tamper-evidence hash chain. GET /v1/vaults/{id}/ops/verify returns the
--     SAME tip_hash for every vault before and after this migration.
--   * NOT ONE ROW of sigil_device_grants is rewritten, deleted or
--     re-permissioned, and the partial unique index sigil_device_grants_one_owner
--     is left in place. The grant table stays exactly as it was, so
--     GET /v1/vaults/{id}/grants is byte-identical for existing data and
--     existing clients.
--   * Migrations 0001-0004 are not edited. This file is purely additive and
--     forward-only.
--
-- AUTH METADATA ONLY. No column created here can hold a vault key, a password, a
-- plaintext, a card detail, an email address, a phone number, a display name, a
-- bearer token, a signature or a nonce. An account invite is recorded ONLY as a
-- lowercase-hex SHA-256 DIGEST — the invite secret itself is never written to the
-- database, never logged and never re-served. This is pure DDL plus a metadata
-- backfill; it performs NO cryptography, so the zero-knowledge boundary is
-- unchanged.
--
-- The whole file runs in ONE transaction (the migration runner wraps it), so the
-- adoption backfill below is atomic: either every pre-existing device has an
-- account or none does.

-- One billing/ownership subject. There is deliberately no label and no status
-- column: a label is user data with no server-side use (and exactly where an
-- email would eventually get typed), and a status column that no route sets is
-- dead schema implying a feature that does not exist.
CREATE TABLE IF NOT EXISTS sigil_accounts (
	account_id           text        PRIMARY KEY,
	created_at           timestamptz NOT NULL DEFAULT now(),
	created_by_device_id text        NOT NULL DEFAULT ''
);

-- DELIBERATELY NULLABLE. A NOT NULL column with no default would make a
-- ROLLED-BACK pre-0005 binary unable to enroll a device at all. The invariant
-- ("every device has an account") is enforced in the APPLICATION, in both
-- backends, and a NULL observed at runtime FAILS CLOSED (missing_account -> 500)
-- rather than falling back to the device id.
ALTER TABLE sigil_devices ADD COLUMN IF NOT EXISTS account_id text
	REFERENCES sigil_accounts (account_id);

-- ADOPTION. Every already-enrolled device (active AND revoked) gets its OWN
-- singleton account. The id is a pure function of the device id, so there is no
-- RNG in SQL, the statement is re-runnable, and the 'acct_mig_' prefix makes an
-- adopted account self-evident in an audit trail. Predictability is harmless: an
-- account id is an IDENTIFIER, never a credential, and no request anywhere names
-- an account (the server always derives it from the verified signer's device
-- row).
--
-- CONSEQUENCE, WRITTEN DOWN RATHER THAN HIDDEN: there is NO account merge. A
-- customer who already had a phone and a laptop enrolled ends up with TWO
-- accounts and TWO billing subjects. The remedy is manual (revoke one, re-join
-- by invite, re-share, rotate) and is documented in docs/deployment.md.
INSERT INTO sigil_accounts (account_id, created_at, created_by_device_id)
SELECT 'acct_mig_' || d.device_id, d.created_at, d.device_id
  FROM sigil_devices d WHERE d.account_id IS NULL
ON CONFLICT (account_id) DO NOTHING;

UPDATE sigil_devices d SET account_id = 'acct_mig_' || d.device_id
 WHERE d.account_id IS NULL;

CREATE INDEX IF NOT EXISTS sigil_devices_by_account ON sigil_devices (account_id);

-- Single-use invitations: the ONLY way a second device joins an existing
-- account. invite_hash (the PRIMARY KEY) is the lowercase-hex SHA-256 of the
-- invite secret; the secret is returned exactly once, in the 201 that minted it.
-- invite_id is the PUBLIC handle used for listing and revocation, so no endpoint
-- ever has to echo the digest.
--
-- invitee_public_key, when non-null, PINS the invite to one Ed25519 public key so
-- an intercepted invite cannot be redeemed by anyone else. Nothing forces
-- pinning: an unpinned invite is a bearer secret for its TTL, the same exposure
-- class as the existing X-Sigil-Enroll-Token.
CREATE TABLE IF NOT EXISTS sigil_account_invites (
	invite_hash          text        PRIMARY KEY,
	invite_id            text        NOT NULL UNIQUE,
	account_id           text        NOT NULL REFERENCES sigil_accounts (account_id) ON DELETE CASCADE,
	created_by_device_id text        NOT NULL,
	invitee_public_key   bytea,
	created_at           timestamptz NOT NULL DEFAULT now(),
	expires_at           timestamptz NOT NULL,
	used_at              timestamptz,
	used_by_device_id    text,
	revoked_at           timestamptz
);

CREATE INDEX IF NOT EXISTS sigil_account_invites_open
	ON sigil_account_invites (account_id, expires_at)
	WHERE used_at IS NULL AND revoked_at IS NULL;

-- THE AUTHORIZATION AUTHORITY for vault ownership. Trust-on-first-write did not
-- go away — it moved up one level: the first ACCOUNT to write an unclaimed vault
-- owns it. The PRIMARY KEY on vault_id is what makes that claim single-winner
-- across concurrent processes.
--
-- The is_owner flag on sigil_device_grants remains as the per-DEVICE VIEW of the
-- same fact (so existing clients see an unchanged grants listing), but NO
-- authorization decision reads it any more.
CREATE TABLE IF NOT EXISTS sigil_vault_owners (
	vault_id             text        PRIMARY KEY,
	account_id           text        NOT NULL REFERENCES sigil_accounts (account_id),
	claimed_by_device_id text        NOT NULL DEFAULT '',
	claimed_at           timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS sigil_vault_owners_by_account
	ON sigil_vault_owners (account_id);

-- Backfill ownership from the existing owner grants, so every vault that had an
-- owner still has one — now expressed as the owning ACCOUNT. Reads the grants
-- table; writes nothing back to it.
INSERT INTO sigil_vault_owners (vault_id, account_id, claimed_by_device_id, claimed_at)
SELECT g.vault_id, d.account_id, g.device_id, g.created_at
  FROM sigil_device_grants g JOIN sigil_devices d ON d.device_id = g.device_id
 WHERE g.is_owner AND d.account_id IS NOT NULL
ON CONFLICT (vault_id) DO NOTHING;

-- ENTITLEMENT re-key: a subscription bought by a DEVICE becomes a subscription
-- held by that device's ACCOUNT, which is the entire point of this phase (pay on
-- the phone, be entitled on the laptop). The mapping is injective because
-- adoption is 1:1, and the NOT EXISTS guard makes a primary-key collision
-- impossible even against hand-edited data.
--
-- Rows whose subject names no device are LEFT ALONE. Billing history is never
-- deleted.
UPDATE sigil_subscriptions s
   SET subject = d.account_id, updated_at = now()
  FROM sigil_devices d
 WHERE s.subject = d.device_id
   AND d.account_id IS NOT NULL
   AND NOT EXISTS (SELECT 1 FROM sigil_subscriptions s2 WHERE s2.subject = d.account_id);

-- sigil_billing_processed_events.subject is DELIBERATELY NOT rewritten: it is an
-- append-only record of what was processed at the time, read by no logic.
-- Rewriting history to look like something that was not true then is worse than
-- a stale column nothing reads, and cross-cutover reconciliation needs BOTH ids
-- (see docs/deployment.md).
