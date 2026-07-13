package store

// PostgresVaultLog is an OPTIONAL, durable, concurrency-safe VaultLog backed by
// a PostgreSQL table (via pgx). It exists so the DEV op-log can survive a
// restart AND serve concurrent writers/readers with a real database, which the
// in-memory MemVaultLog (non-durable) and the FileVaultLog (single-process
// file log) cannot. Selecting it is opt-in via SIGILD_OPLOG_POSTGRES (see
// cmd/server/main.go); unset keeps the file/in-memory backends.
//
// IT IS NOT A FINISHED PRODUCTION SYNC STORE. It adds durability and
// concurrency, but the surrounding server still has NO real auth model, NO
// device enrollment, NO CRDT/merge semantics, and NO backup/replication story.
// The production persistence design (Postgres + S3 for large blobs + Redis) is
// broader than this single table. Treat this as a durable DEV backend.
//
// Like every VaultLog it is OPAQUE: blobs are stored and returned byte-for-byte
// as a Postgres `bytea` and are never decrypted, parsed, or otherwise
// interpreted. It performs NO cryptography.
//
// STATUS: pre-audit skeleton. Durable Postgres backend for the DEV op-log;
// stores opaque client-encrypted blobs; no crypto; still UNAUTHENTICATED unless
// SIGILD_OPLOG_PUBKEY is set / dev-gated by SIGILD_ENABLE_DEV_OPS; NOT a
// finished production store (no auth model / enrollment / CRDT / backups).

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// opTimeout bounds every individual database operation so a wedged or slow
// server can never block an Append/Since (or startup Ping/schema) forever.
const opTimeout = 10 * time.Second

// createSchemaSQL creates the op-log table if it does not already exist. The
// (vault_id, seq) primary key enforces per-vault uniqueness of the sequence
// number at the database level; blob is the opaque bytea; hash is the op's
// tamper-evidence chain hash (32-byte SHA-256, see chainHash); created_at is
// server-side bookkeeping only and never returned to clients.
const createSchemaSQL = `
CREATE TABLE IF NOT EXISTS sigil_vault_ops (
	vault_id   text        NOT NULL,
	seq        bigint      NOT NULL,
	blob       bytea       NOT NULL,
	hash       bytea       NOT NULL,
	created_at timestamptz NOT NULL DEFAULT now(),
	PRIMARY KEY (vault_id, seq)
)`

// addHashColumnSQL upgrades a pre-existing table (created before the hash chain)
// by adding the hash column. It is a no-op on a fresh DB where createSchemaSQL
// already includes the column. The column is added NULLABLE here (an existing
// table may already hold rows that predate the chain); a fresh table gets it NOT
// NULL via createSchemaSQL. Acceptable for a DEV backend with no real data.
const addHashColumnSQL = `ALTER TABLE sigil_vault_ops ADD COLUMN IF NOT EXISTS hash bytea`

// Pool sizing/lifecycle for the dev Postgres backend. Op bodies are tiny (the
// server caps a single op at 64 KiB) and each Append/Since is a short-lived
// query, so a small pool is ample; bounded connection lifetimes recycle backend
// connections and a periodic health check evicts dead ones so a restarted
// database is picked up without bouncing the process.
const (
	poolMaxConns          = 10
	poolMaxConnLifetime   = time.Hour
	poolMaxConnIdleTime   = 30 * time.Minute
	poolHealthCheckPeriod = time.Minute
)

// PostgresVaultLog implements VaultLog against a pgxpool connection pool.
type PostgresVaultLog struct {
	pool *pgxpool.Pool
}

// compile-time checks that PostgresVaultLog satisfies VaultLog and Pinger.
var (
	_ VaultLog = (*PostgresVaultLog)(nil)
	_ Pinger   = (*PostgresVaultLog)(nil)
)

// NewPostgresVaultLog opens a pooled connection to dsn, verifies it with a Ping,
// and idempotently ensures the op-log schema exists. The supplied ctx bounds
// only construction (pool open + ping + schema); it is NOT retained. Per-op
// contexts derive from the CALLER's request context (see Append/Since), so a
// cancelled/slow request cancels the underlying database work.
//
// A returned pool must be released with Close.
func NewPostgresVaultLog(ctx context.Context, dsn string) (*PostgresVaultLog, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	cfg.MaxConns = poolMaxConns
	cfg.MaxConnLifetime = poolMaxConnLifetime
	cfg.MaxConnIdleTime = poolMaxConnIdleTime
	cfg.HealthCheckPeriod = poolHealthCheckPeriod

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("open postgres pool: %w", err)
	}

	// From here on, a failure must release the pool we just opened.
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	if _, err := pool.Exec(ctx, createSchemaSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ensure op-log schema: %w", err)
	}
	// Idempotently add the hash column to a table created before the chain existed.
	if _, err := pool.Exec(ctx, addHashColumnSQL); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ensure op-log hash column: %w", err)
	}

	return &PostgresVaultLog{pool: pool}, nil
}

// Append durably records a defensive COPY of blob as the next op for vaultID and
// returns the stored Op with its assigned 1-based Seq.
//
// CONCURRENCY: appends to the SAME vault are serialized by a transaction-scoped
// per-vault advisory lock (pg_advisory_xact_lock over hashtext(vaultID)); the
// lock is released automatically when the transaction commits or rolls back.
// While the lock is held we read the previous op's (seq, hash), compute this op's
// chain hash, and INSERT (vault, seq+1, blob, hash) in the same transaction, so
// concurrent appenders to one vault produce a strictly increasing, unique,
// contiguous sequence with no gaps AND an unbroken hash chain. Different vaults
// hash to (almost always) different advisory-lock keys and so proceed
// concurrently; the (vault_id, seq) primary key is the final backstop that
// rejects any duplicate seq even on an advisory-lock hash collision between two
// distinct vault IDs.
func (l *PostgresVaultLog) Append(ctx context.Context, vaultID string, blob []byte) (Op, error) {
	// Defensive copy so the caller cannot mutate stored bytes through the input
	// slice after this call, matching the Mem/File backends' contract.
	cp := make([]byte, len(blob))
	copy(cp, blob)

	// Derive from the CALLER's context so a cancelled/slow request cancels the DB
	// work, while still capping any single op at opTimeout.
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	var seq int64
	var hash [32]byte
	err := pgx.BeginFunc(ctx, l.pool, func(tx pgx.Tx) error {
		// Serialize concurrent appends to THIS vault. The lock is held for the
		// duration of the transaction and released on commit/rollback.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, vaultID); err != nil {
			return err
		}
		// Read the previous op (highest seq) to continue the chain. No row means
		// this is the genesis op: seq 0, prevHash = the 32 zero bytes.
		var prevSeq int64
		var prevHash []byte
		err := tx.QueryRow(ctx,
			`SELECT seq, hash FROM sigil_vault_ops WHERE vault_id = $1 ORDER BY seq DESC LIMIT 1`,
			vaultID,
		).Scan(&prevSeq, &prevHash)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		var prev [32]byte
		copy(prev[:], prevHash) // nil (no prior row) => stays genesis zeros
		seq = prevSeq + 1
		hash = chainHash(vaultID, uint64(seq), prev, cp)
		_, err = tx.Exec(ctx,
			`INSERT INTO sigil_vault_ops (vault_id, seq, blob, hash) VALUES ($1, $2, $3, $4)`,
			vaultID, seq, cp, hash[:],
		)
		return err
	})
	if err != nil {
		return Op{}, fmt.Errorf("append op: %w", err)
	}
	return Op{Seq: uint64(seq), Blob: cp, Hash: hash}, nil
}

// Since returns the vault's ops with Seq strictly greater than `since`, in
// ascending Seq order, each carrying a fresh COPY of its blob so callers cannot
// mutate stored bytes. A limit > 0 pushes a SQL `LIMIT` into the query so the
// database returns at most that many (earliest) rows; a limit <= 0 is unbounded
// (used by VerifyChain, which needs the whole chain). An unknown vault (no
// matching rows) yields an empty slice and nil error.
func (l *PostgresVaultLog) Since(ctx context.Context, vaultID string, since uint64, limit int) ([]Op, error) {
	// Derive from the CALLER's context (see Append) so a cancelled request
	// cancels the query; opTimeout caps a wedged read.
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	const baseQuery = `SELECT seq, blob, hash FROM sigil_vault_ops
		 WHERE vault_id = $1 AND seq > $2
		 ORDER BY seq ASC`
	var (
		rows pgx.Rows
		err  error
	)
	if limit > 0 {
		rows, err = l.pool.Query(ctx, baseQuery+` LIMIT $3`, vaultID, int64(since), limit)
	} else {
		rows, err = l.pool.Query(ctx, baseQuery, vaultID, int64(since))
	}
	if err != nil {
		return nil, fmt.Errorf("query ops: %w", err)
	}
	defer rows.Close()

	out := make([]Op, 0)
	for rows.Next() {
		var seq int64
		var blob, hashBytes []byte
		if err := rows.Scan(&seq, &blob, &hashBytes); err != nil {
			return nil, fmt.Errorf("scan op: %w", err)
		}
		// pgx already returns a fresh []byte per row for bytea, but copy
		// explicitly so the defensive-copy contract does not depend on driver
		// internals.
		cp := make([]byte, len(blob))
		copy(cp, blob)
		var hash [32]byte
		copy(hash[:], hashBytes)
		out = append(out, Op{Seq: uint64(seq), Blob: cp, Hash: hash})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate ops: %w", err)
	}
	return out, nil
}

// VerifyChain walks the vault's hash chain and reports whether it is intact,
// reading the ops through Since. See verifyChainVia / verifyChain for the
// tamper-evidence details.
func (l *PostgresVaultLog) VerifyChain(ctx context.Context, vaultID string) (VerifyResult, error) {
	return verifyChainVia(ctx, l, vaultID)
}

// Ping verifies the database is reachable, for the readiness probe. It bounds
// the check with opTimeout on top of the caller's ctx (which readyz already
// gives a short deadline), so a wedged database can never hang /readyz.
func (l *PostgresVaultLog) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	return l.pool.Ping(ctx)
}

// Close releases the underlying connection pool. It is safe to call once when
// the log is no longer needed (e.g. on shutdown or in tests).
func (l *PostgresVaultLog) Close() {
	l.pool.Close()
}
