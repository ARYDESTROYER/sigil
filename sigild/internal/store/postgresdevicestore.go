package store

// PostgresDeviceStore is the durable, concurrency-safe DeviceStore backed by the
// tables created in migration 0002_devices.sql (sigil_devices,
// sigil_enrollment_tokens, sigil_device_grants). It is the durable twin of
// MemDeviceStore and shares its exact semantics, including the two atomic
// guarantees — single-use enrollment tokens and single-owner vault claims —
// which here are enforced by the DATABASE (a conditional UPDATE and a partial
// UNIQUE index), so they hold across CONCURRENT PROCESSES, not just goroutines.
//
// It reuses a caller-supplied *pgxpool.Pool (normally the one the Postgres
// op-log already opened), so device auth adds no second connection pool and no
// new dependency.
//
// ZERO-KNOWLEDGE: auth metadata only. No vault plaintext, no ciphertext, no
// token in the clear (tokens are stored as a SHA-256 hex digest).
//
// STATUS: pre-audit skeleton. Durable dev backend for a real auth model; the
// broader product story (accounts, recovery, rotation, attestation) is future.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgUniqueViolation is the SQLSTATE for a unique-constraint violation (23505),
// used to turn a duplicate device (ID or public key) into ErrDeviceExists.
const pgUniqueViolation = "23505"

// PostgresDeviceStore implements DeviceStore against a pgxpool connection pool.
type PostgresDeviceStore struct {
	pool *pgxpool.Pool
}

// compile-time check that PostgresDeviceStore satisfies DeviceStore.
var _ DeviceStore = (*PostgresDeviceStore)(nil)

// NewPostgresDeviceStore wraps an existing pool. The caller owns the pool's
// lifecycle (it is normally shared with PostgresVaultLog, whose construction
// already applied the migrations that create these tables).
func NewPostgresDeviceStore(pool *pgxpool.Pool) *PostgresDeviceStore {
	return &PostgresDeviceStore{pool: pool}
}

// Pool exposes the underlying pool so a caller that constructed this store can
// share it (e.g. for a readiness ping). It is not part of DeviceStore.
func (s *PostgresDeviceStore) Pool() *pgxpool.Pool { return s.pool }

// isUniqueViolation reports whether err is a Postgres unique-constraint failure.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgUniqueViolation
}

// CreateDevice inserts a device row. A duplicate device_id or public_key trips a
// unique constraint and is reported as ErrDeviceExists; an account_id that names
// no account trips the foreign key and is reported as ErrAccountNotFound; an
// EMPTY account_id is refused outright (the invariant fails closed here, so no
// authorization path ever has to guess).
//
// Production enrollment does not use this: it goes through
// CreateAccountWithFounder or JoinAccountWithInvite, which insert the device
// ATOMICALLY with the account decision.
func (s *PostgresDeviceStore) CreateDevice(ctx context.Context, d Device) error {
	if d.AccountID == "" {
		return errAccountRequired
	}
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	_, err := s.pool.Exec(ctx,
		`INSERT INTO sigil_devices (device_id, account_id, public_key, label, status, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		d.ID, d.AccountID, d.PublicKey, d.Label, string(d.Status), d.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDeviceExists
		}
		if isForeignKeyViolation(err) {
			return ErrAccountNotFound
		}
		return fmt.Errorf("create device: %w", err)
	}
	return nil
}

// deviceRowScanner is the minimal surface shared by pgx.Row and pgx.Rows so one
// scan helper serves both the single-row and multi-row device reads.
type deviceRowScanner interface {
	Scan(dest ...any) error
}

// scanDeviceRow decodes one sigil_devices row. account_id is NULLABLE in the
// schema (deliberately — see migration 0005) so a rolled-back pre-0005 binary
// can still INSERT; a NULL here decodes to the empty string, which every
// authorization path treats as a fail-closed invariant violation.
func scanDeviceRow(row deviceRowScanner) (Device, error) {
	var (
		d         Device
		accountID *string
		status    string
		revokedAt *time.Time
	)
	if err := row.Scan(&d.ID, &accountID, &d.PublicKey, &d.Label, &status, &d.CreatedAt, &revokedAt); err != nil {
		return Device{}, err
	}
	if accountID != nil {
		d.AccountID = *accountID
	}
	d.Status = DeviceStatus(status)
	if revokedAt != nil {
		d.RevokedAt = *revokedAt
	}
	return d, nil
}

// GetDevice reads one device by ID, or ErrDeviceNotFound.
func (s *PostgresDeviceStore) GetDevice(ctx context.Context, deviceID string) (Device, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	d, err := scanDeviceRow(s.pool.QueryRow(ctx,
		`SELECT device_id, account_id, public_key, label, status, created_at, revoked_at
		   FROM sigil_devices WHERE device_id = $1`, deviceID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Device{}, ErrDeviceNotFound
		}
		return Device{}, fmt.Errorf("get device: %w", err)
	}
	return d, nil
}

// ListDevices returns every device ordered by created_at then device_id.
//
// ORDERING IS BYTE-WISE, NOT LOCALE-WISE. Every text ORDER BY in this package
// carries COLLATE "C" so the SQL sort is the SAME sort Go's `<` performs on the
// same strings. Without it the order depends on the DATABASE's collation: under
// en_US.utf8 (the official postgres image, and the CI service container) the
// base64url device IDs — which mix case and contain '-' and '_' — sort
// differently from byte order, which made the ordering contract, and the tests
// that assert it, intermittently wrong. COLLATE "C" is the whole fix: identical
// results on every database regardless of how the cluster was initialised.
func (s *PostgresDeviceStore) ListDevices(ctx context.Context) ([]Device, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	rows, err := s.pool.Query(ctx,
		`SELECT device_id, account_id, public_key, label, status, created_at, revoked_at
		   FROM sigil_devices
		  ORDER BY created_at ASC, device_id COLLATE "C" ASC`)
	if err != nil {
		return nil, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()

	out := make([]Device, 0)
	for rows.Next() {
		d, err := scanDeviceRow(rows)
		if err != nil {
			return nil, fmt.Errorf("scan device: %w", err)
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate devices: %w", err)
	}
	return out, nil
}

// RevokeDevice marks a device revoked, idempotently: the UPDATE only fires while
// the device is still active, so a second revoke keeps the original revoked_at.
// An unknown device yields ErrDeviceNotFound.
func (s *PostgresDeviceStore) RevokeDevice(ctx context.Context, deviceID string, at time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	tag, err := s.pool.Exec(ctx,
		`UPDATE sigil_devices SET status = $2, revoked_at = $3
		  WHERE device_id = $1 AND status = $4`,
		deviceID, string(DeviceRevoked), at, string(DeviceActive))
	if err != nil {
		return fmt.Errorf("revoke device: %w", err)
	}
	if tag.RowsAffected() == 1 {
		return nil
	}
	// No row updated: either the device is unknown, or it is already revoked
	// (idempotent success). Distinguish with a read.
	var exists bool
	if err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM sigil_devices WHERE device_id = $1)`, deviceID).
		Scan(&exists); err != nil {
		return fmt.Errorf("revoke device: %w", err)
	}
	if !exists {
		return ErrDeviceNotFound
	}
	return nil
}

// RegisterEnrollmentToken records a token hash idempotently. ON CONFLICT DO
// NOTHING is what makes a restart safe: a token already marked used stays used,
// so a spent bootstrap token can never be resurrected by rebooting the server.
func (s *PostgresDeviceStore) RegisterEnrollmentToken(ctx context.Context, tokenHash string, issuedAt, expiresAt time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	var exp *time.Time
	if !expiresAt.IsZero() {
		exp = &expiresAt
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO sigil_enrollment_tokens (token_hash, issued_at, expires_at)
		 VALUES ($1, $2, $3) ON CONFLICT (token_hash) DO NOTHING`,
		tokenHash, issuedAt, exp); err != nil {
		return fmt.Errorf("register enrollment token: %w", err)
	}
	return nil
}

// ConsumeEnrollmentToken atomically spends a token inside a transaction: the row
// is locked FOR UPDATE, checked for used/expired, then marked. Two concurrent
// enrollments with the same token serialize on that lock and exactly one wins;
// the loser sees ErrEnrollTokenUsed.
func (s *PostgresDeviceStore) ConsumeEnrollmentToken(ctx context.Context, tokenHash, deviceID string, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var (
			usedAt    *time.Time
			expiresAt *time.Time
		)
		err := tx.QueryRow(ctx,
			`SELECT used_at, expires_at FROM sigil_enrollment_tokens
			  WHERE token_hash = $1 FOR UPDATE`, tokenHash).Scan(&usedAt, &expiresAt)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrEnrollTokenUnknown
			}
			return err
		}
		if usedAt != nil {
			return ErrEnrollTokenUsed
		}
		if expiresAt != nil && !now.Before(*expiresAt) {
			return ErrEnrollTokenExpired
		}
		_, err = tx.Exec(ctx,
			`UPDATE sigil_enrollment_tokens SET used_at = $2, used_by = $3
			  WHERE token_hash = $1 AND used_at IS NULL`,
			tokenHash, now, deviceID)
		return err
	})
	if err != nil {
		// Sentinels pass through untouched so callers can errors.Is them.
		if errors.Is(err, ErrEnrollTokenUnknown) || errors.Is(err, ErrEnrollTokenUsed) ||
			errors.Is(err, ErrEnrollTokenExpired) {
			return err
		}
		return fmt.Errorf("consume enrollment token: %w", err)
	}
	return nil
}

// GetGrant reads one grant, or ErrGrantNotFound.
func (s *PostgresDeviceStore) GetGrant(ctx context.Context, vaultID, deviceID string) (Grant, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	var (
		g    Grant
		perm string
	)
	err := s.pool.QueryRow(ctx,
		`SELECT vault_id, device_id, permission, is_owner, created_at
		   FROM sigil_device_grants WHERE vault_id = $1 AND device_id = $2`,
		vaultID, deviceID).Scan(&g.VaultID, &g.DeviceID, &perm, &g.Owner, &g.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Grant{}, ErrGrantNotFound
		}
		return Grant{}, fmt.Errorf("get grant: %w", err)
	}
	g.Perm = Permission(perm)
	return g, nil
}

// PutGrant upserts a NON-OWNER grant. The DO UPDATE is guarded by
// `WHERE NOT sigil_device_grants.is_owner`, so an owner row is never downgraded.
func (s *PostgresDeviceStore) PutGrant(ctx context.Context, vaultID, deviceID string, perm Permission, at time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	if _, err := s.pool.Exec(ctx,
		`INSERT INTO sigil_device_grants (vault_id, device_id, permission, is_owner, created_at)
		 VALUES ($1, $2, $3, false, $4)
		 ON CONFLICT (vault_id, device_id) DO UPDATE SET permission = EXCLUDED.permission
		 WHERE NOT sigil_device_grants.is_owner`,
		vaultID, deviceID, string(perm), at); err != nil {
		return fmt.Errorf("put grant: %w", err)
	}
	return nil
}

// ListGrants returns every grant on a vault, ordered by device ID — BYTE-WISE
// (COLLATE "C"), so the order matches Go's own string comparison on every
// database. See ListDevices for why.
func (s *PostgresDeviceStore) ListGrants(ctx context.Context, vaultID string) ([]Grant, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	rows, err := s.pool.Query(ctx,
		`SELECT vault_id, device_id, permission, is_owner, created_at
		   FROM sigil_device_grants WHERE vault_id = $1
		  ORDER BY device_id COLLATE "C" ASC`, vaultID)
	if err != nil {
		return nil, fmt.Errorf("list grants: %w", err)
	}
	defer rows.Close()

	out := make([]Grant, 0)
	for rows.Next() {
		var (
			g    Grant
			perm string
		)
		if err := rows.Scan(&g.VaultID, &g.DeviceID, &perm, &g.Owner, &g.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan grant: %w", err)
		}
		g.Perm = Permission(perm)
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate grants: %w", err)
	}
	return out, nil
}
