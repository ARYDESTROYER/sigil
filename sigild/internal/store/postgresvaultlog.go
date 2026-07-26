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
// device enrollment, NO CRDT/merge semantics, and NO automated backup/replication
// or PITR story. (The schema IS now managed by versioned migrations — see
// migrate.go — and a manual pg_dump/restore runbook exists whose integrity gate
// is the /ops/verify hash chain; automated backup/replication does not.) The
// production persistence design (Postgres + S3 for large blobs + Redis) is
// broader than this single table. Treat this as a durable DEV backend.
//
// Like every VaultLog it is OPAQUE: blobs are stored and returned byte-for-byte
// as a Postgres `bytea` and are never decrypted, parsed, or otherwise
// interpreted. It performs NO cryptography.
//
// STATUS: pre-audit skeleton. Durable Postgres backend for the DEV op-log;
// stores opaque client-encrypted blobs; no crypto; still UNAUTHENTICATED unless
// SIGILD_OPLOG_PUBKEY is set / dev-gated by SIGILD_ENABLE_DEV_OPS; NOT a
// finished production store (no auth model / enrollment / CRDT / automated
// backup+replication, though schema migrations are now managed — see migrate.go).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// opTimeout bounds every individual database operation so a wedged or slow
// server can never block an Append/Since (or startup Ping/schema) forever.
const opTimeout = 10 * time.Second

// autoMigrateEnabled reports whether NewPostgresVaultLog should auto-apply
// pending schema migrations at construction. It is controlled by
// SIGILD_OPLOG_AUTO_MIGRATE: unset or truthy => ON (the default, backward
// compatible — a fresh DB is migrated exactly as the old inline DDL did);
// "0"/"false"/"no"/"off" (case-insensitive) => OFF, in which case construction
// does NOT apply anything and instead fails fast if the DB is unmigrated/behind,
// telling the operator to run `sigild migrate`.
func autoMigrateEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SIGILD_OPLOG_AUTO_MIGRATE"))) {
	case "0", "false", "no", "off":
		return false
	default:
		return true
	}
}

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
// and brings the op-log schema up to date via the managed migration system (see
// migrate.go). The supplied ctx bounds only construction (pool open + ping +
// migrate); it is NOT retained. Per-op contexts derive from the CALLER's request
// context (see Append/Since), so a cancelled/slow request cancels the underlying
// database work.
//
// Migration behaviour is controlled by SIGILD_OPLOG_AUTO_MIGRATE (see
// autoMigrateEnabled): ON by default, in which case pending migrations are
// applied at construction (a fresh DB is set up exactly as the old inline DDL
// did — backward compatible). When explicitly disabled, construction applies
// NOTHING and fails fast if the DB is behind the latest embedded migration,
// directing the operator to run `sigild migrate`.
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
	if autoMigrateEnabled() {
		// Apply pending migrations. On a fresh DB this creates the op-log schema
		// exactly like the old inline DDL; on an up-to-date DB it is a no-op.
		if _, err := Migrate(ctx, pool); err != nil {
			pool.Close()
			return nil, fmt.Errorf("apply op-log migrations: %w", err)
		}
	} else {
		// Auto-migrate disabled: never apply here. Fail fast if the DB is behind
		// the latest embedded migration so a misconfigured deploy is a clear
		// startup error rather than a runtime surprise.
		latest, err := latestMigrationVersion()
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("load op-log migrations: %w", err)
		}
		have, err := AppliedVersion(ctx, pool)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("read applied op-log migration version: %w", err)
		}
		if have < latest {
			pool.Close()
			return nil, fmt.Errorf("op-log database is at migration version %d but %d is required "+
				"and SIGILD_OPLOG_AUTO_MIGRATE is disabled; run `sigild migrate` to apply pending migrations",
				have, latest)
		}
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

// SchemaVersion returns the highest applied op-log migration version for this
// backend, for observability (the sigild_schema_version metric). It bounds the
// read with opTimeout on top of the caller's ctx.
func (l *PostgresVaultLog) SchemaVersion(ctx context.Context) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	return AppliedVersion(ctx, l.pool)
}

// Pool exposes the underlying connection pool so a caller can SHARE it with
// another adapter against the same database (the device registry does exactly
// that — see NewPostgresDeviceStore), instead of opening a second pool. The
// PostgresVaultLog retains ownership: the pool is released by Close.
func (l *PostgresVaultLog) Pool() *pgxpool.Pool { return l.pool }

// Close releases the underlying connection pool. It is safe to call once when
// the log is no longer needed (e.g. on shutdown or in tests).
func (l *PostgresVaultLog) Close() {
	l.pool.Close()
}
