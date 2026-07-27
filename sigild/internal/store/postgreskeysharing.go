package store

// PostgresDeviceStore's implementation of the KeySharing seam: device hybrid
// PUBLIC keys and the opaque key-envelope relay, backed by the tables created in
// migration 0004_key_sharing.sql. It is the durable twin of the MemDeviceStore
// implementation in keysharing.go and shares its exact semantics, which the one
// backend-agnostic conformance suite enforces.
//
// ZERO-KNOWLEDGE: the blob column is written and read as opaque bytea. This file
// contains no cryptography, no decoding, and no interpretation of key material
// beyond the length check in ValidateHybridPublicKey.

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// pgForeignKeyViolation is the SQLSTATE for a foreign-key violation (23503),
// which here means "that device is not enrolled" — reported as
// ErrDeviceNotFound so both backends agree.
const pgForeignKeyViolation = "23503"

// isForeignKeyViolation reports whether err is a Postgres FK failure.
func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgForeignKeyViolation
}

// PutDeviceHybridKey publishes (or REPUBLISHES) a device's hybrid public key.
// The ON CONFLICT upsert is what makes re-publishing idempotent-ish: the stored
// key is replaced and updated_at refreshed, with no error and no duplicate row.
func (s *PostgresDeviceStore) PutDeviceHybridKey(ctx context.Context, k HybridPublicKey) error {
	if err := ValidateHybridPublicKey(k); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	_, err := s.pool.Exec(ctx,
		`INSERT INTO sigil_device_hybrid_keys
		     (device_id, x25519_public_key, mlkem_encaps_key, updated_at)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (device_id) DO UPDATE SET
		     x25519_public_key = EXCLUDED.x25519_public_key,
		     mlkem_encaps_key  = EXCLUDED.mlkem_encaps_key,
		     updated_at        = EXCLUDED.updated_at`,
		k.DeviceID, k.X25519PublicKey, k.MLKEMEncapsKey, k.UpdatedAt)
	if err != nil {
		if isForeignKeyViolation(err) {
			return ErrDeviceNotFound
		}
		return fmt.Errorf("put device hybrid key: %w", err)
	}
	return nil
}

// GetDeviceHybridKey reads a device's published hybrid public key, or
// ErrHybridKeyNotFound.
func (s *PostgresDeviceStore) GetDeviceHybridKey(ctx context.Context, deviceID string) (HybridPublicKey, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	var k HybridPublicKey
	err := s.pool.QueryRow(ctx,
		`SELECT device_id, x25519_public_key, mlkem_encaps_key, updated_at
		   FROM sigil_device_hybrid_keys WHERE device_id = $1`, deviceID).
		Scan(&k.DeviceID, &k.X25519PublicKey, &k.MLKEMEncapsKey, &k.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return HybridPublicKey{}, ErrHybridKeyNotFound
		}
		return HybridPublicKey{}, fmt.Errorf("get device hybrid key: %w", err)
	}
	return k, nil
}

// PutKeyEnvelope stores an opaque wrapped vault key in the (vault, recipient)
// mailbox, replacing any envelope already there (the sender may have re-keyed
// the vault). The blob is written as-is; nothing here inspects it.
func (s *PostgresDeviceStore) PutKeyEnvelope(ctx context.Context, e KeyEnvelope) error {
	if err := ValidateKeyEnvelope(e); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	_, err := s.pool.Exec(ctx,
		`INSERT INTO sigil_vault_key_envelopes
		     (vault_id, recipient_device_id, sender_device_id, blob, created_at)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (vault_id, recipient_device_id) DO UPDATE SET
		     sender_device_id = EXCLUDED.sender_device_id,
		     blob             = EXCLUDED.blob,
		     created_at       = EXCLUDED.created_at`,
		e.VaultID, e.RecipientDeviceID, e.SenderDeviceID, e.Blob, e.CreatedAt)
	if err != nil {
		if isForeignKeyViolation(err) {
			return ErrDeviceNotFound
		}
		return fmt.Errorf("put key envelope: %w", err)
	}
	return nil
}

// GetKeyEnvelope returns the envelope addressed to (vaultID, recipientDeviceID)
// with its blob byte-identical to what was uploaded, or ErrKeyEnvelopeNotFound.
func (s *PostgresDeviceStore) GetKeyEnvelope(ctx context.Context, vaultID, recipientDeviceID string) (KeyEnvelope, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	var e KeyEnvelope
	err := s.pool.QueryRow(ctx,
		`SELECT vault_id, recipient_device_id, sender_device_id, blob, created_at
		   FROM sigil_vault_key_envelopes
		  WHERE vault_id = $1 AND recipient_device_id = $2`, vaultID, recipientDeviceID).
		Scan(&e.VaultID, &e.RecipientDeviceID, &e.SenderDeviceID, &e.Blob, &e.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return KeyEnvelope{}, ErrKeyEnvelopeNotFound
		}
		return KeyEnvelope{}, fmt.Errorf("get key envelope: %w", err)
	}
	return e, nil
}

// ListKeyEnvelopeRecipients returns METADATA for every envelope stored for a
// vault, ordered by recipient device ID. It deliberately selects octet_length()
// rather than the blob itself: a vault owner needs to know WHICH devices hold a
// wrapped key, and the ciphertext never has to leave the database for that.
func (s *PostgresDeviceStore) ListKeyEnvelopeRecipients(ctx context.Context, vaultID string) ([]KeyEnvelopeMeta, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	rows, err := s.pool.Query(ctx,
		`SELECT vault_id, recipient_device_id, sender_device_id, octet_length(blob), created_at
		   FROM sigil_vault_key_envelopes
		  WHERE vault_id = $1
		  ORDER BY recipient_device_id`, vaultID)
	if err != nil {
		return nil, fmt.Errorf("list key envelopes: %w", err)
	}
	defer rows.Close()

	out := make([]KeyEnvelopeMeta, 0, 8)
	for rows.Next() {
		var m KeyEnvelopeMeta
		if err := rows.Scan(&m.VaultID, &m.RecipientDeviceID, &m.SenderDeviceID, &m.SizeBytes, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("list key envelopes: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list key envelopes: %w", err)
	}
	return out, nil
}

// DeleteKeyEnvelope removes the (vault, recipient) mailbox, reporting
// ErrKeyEnvelopeNotFound when no row matched so both backends agree.
func (s *PostgresDeviceStore) DeleteKeyEnvelope(ctx context.Context, vaultID, recipientDeviceID string) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	tag, err := s.pool.Exec(ctx,
		`DELETE FROM sigil_vault_key_envelopes
		  WHERE vault_id = $1 AND recipient_device_id = $2`, vaultID, recipientDeviceID)
	if err != nil {
		return fmt.Errorf("delete key envelope: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrKeyEnvelopeNotFound
	}
	return nil
}
