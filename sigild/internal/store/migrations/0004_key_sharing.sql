-- 0004_key_sharing: device hybrid PUBLIC keys and the opaque key-envelope relay
-- that back device-to-device vault sharing (Phase 46).
--
-- It applies cleanly ON TOP OF 0001..0003 and touches NOTHING in them: the
-- op-log (and its tamper-evidence hash chain), the device registry, the
-- enrollment-token ledger, the grants table and the billing tables are all left
-- byte-for-byte as they were, so a database migrated from 0003 keeps serving
-- every existing mode unchanged. Sharing is purely ADDITIVE.
--
-- ZERO-KNOWLEDGE: neither table holds anything the server can decrypt.
--
--   * sigil_device_hybrid_keys holds PUBLIC key material — the public half of a
--     device's X25519 + ML-KEM-768 identity. The server stores and serves those
--     bytes verbatim and performs NO cryptography with them; it validates LENGTH
--     ONLY (32 / 1184) at the API boundary.
--   * sigil_vault_key_envelopes holds CIPHERTEXT: a vault key that the SENDING
--     CLIENT wrapped to the recipient device's hybrid public key. The server has
--     no decapsulation key, never decodes the blob, and returns the exact bytes
--     it was given. It is a mailbox, not a key manager.
--
-- Every statement is IF NOT EXISTS so a partially-created schema adopts cleanly.

-- One row per device that has PUBLISHED its hybrid public key. device_id is the
-- primary key, so publishing is an UPSERT: a device may re-publish (e.g. after
-- regenerating its local hybrid identity) and the new key replaces the old one.
-- Republishing does NOT re-wrap already-stored envelopes.
--
-- The FK to sigil_devices means only an ENROLLED device can have a key on file,
-- and deleting a device (which this server never does — revocation RETAINS the
-- row) would take its key with it.
CREATE TABLE IF NOT EXISTS sigil_device_hybrid_keys (
	device_id         text        PRIMARY KEY
	                              REFERENCES sigil_devices (device_id) ON DELETE CASCADE,
	x25519_public_key bytea       NOT NULL,
	mlkem_encaps_key  bytea       NOT NULL,
	updated_at        timestamptz NOT NULL DEFAULT now()
);

-- The opaque key-envelope relay: at most ONE envelope per (vault, recipient)
-- mailbox address, so re-sharing a vault to the same device REPLACES the
-- envelope (the sender may have re-keyed the vault). blob is the wrapped vault
-- key as CIPHERTEXT — stored and returned verbatim, never decoded here.
-- sender_device_id is audit metadata: the device the server AUTHENTICATED on
-- upload, not a claim read out of the blob.
CREATE TABLE IF NOT EXISTS sigil_vault_key_envelopes (
	vault_id            text        NOT NULL,
	recipient_device_id text        NOT NULL
	                                REFERENCES sigil_devices (device_id) ON DELETE CASCADE,
	sender_device_id    text        NOT NULL DEFAULT '',
	blob                bytea       NOT NULL,
	created_at          timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (vault_id, recipient_device_id)
);

-- A recipient asks "what is waiting for me?" per device across vaults; the
-- primary key already covers (vault_id, ...), so index the other direction.
CREATE INDEX IF NOT EXISTS sigil_vault_key_envelopes_by_recipient
	ON sigil_vault_key_envelopes (recipient_device_id);
