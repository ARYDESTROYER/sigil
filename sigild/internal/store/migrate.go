package store

// Managed, versioned, auditable schema migrations for the durable Postgres
// op-log backend (Phase 28, ADR 0018). This replaces the old ad-hoc inline DDL
// that NewPostgresVaultLog ran at construction with a real migration system:
//
//   - Migrations are embedded .sql files under migrations/, one per migration,
//     named NNNN_description.sql. The leading zero-padded integer is the
//     version; migrations apply in ascending version order.
//   - A schema_migrations tracking table records which versions have been
//     applied and when, so a run is idempotent and auditable.
//   - The whole apply run is guarded by a SESSION-level pg_advisory_lock on a
//     fixed key, so two instances booting concurrently cannot double-apply.
//   - Each pending migration runs in its OWN transaction (migration SQL + the
//     schema_migrations INSERT), so a failure rolls back atomically and is
//     retried on the next run.
//
// Migrations are PURE INFRASTRUCTURE (DDL): they create/alter the table that
// holds OPAQUE client-encrypted blobs. They never decode, parse, or touch blob
// contents, and perform NO cryptography — the zero-knowledge boundary is intact.
//
// STATUS: pre-audit skeleton. Durable Postgres op-log operability; still NOT a
// finished production store (no auth model / enrollment / CRDT / backups).

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// migrationsFS embeds every SQL migration. Only .sql files live under
// migrations/, so the glob captures exactly the migration set.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrationAdvisoryLockKey is the fixed 64-bit key for the SESSION-level
// pg_advisory_lock held for the whole migration run. Any stable int64 works;
// this value is the ASCII of "SGIL_MGR" (S=0x53 G=0x47 I=0x49 L=0x4C _=0x5F
// M=0x4D G=0x47 R=0x52) so it is unlikely to collide with an unrelated
// application advisory lock. The high bit is clear, so it is a positive int64.
// DOCUMENTED so operators reason about it: two sigild instances booting against
// the same database serialize their migration runs on this key.
const migrationAdvisoryLockKey int64 = 0x5347494C5F4D4752

// pgUndefinedTable is the SQLSTATE for "relation does not exist" (42P01),
// returned when schema_migrations has not been created yet. It is treated as
// "no migrations applied" rather than an error.
const pgUndefinedTable = "42P01"

// createSchemaMigrationsSQL creates the migration-tracking table if absent. It
// is run (IF NOT EXISTS) at the start of every Migrate run, under the advisory
// lock, before any migration is applied.
const createSchemaMigrationsSQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
	version    bigint      PRIMARY KEY,
	name       text        NOT NULL,
	applied_at timestamptz NOT NULL DEFAULT now()
)`

// Migration is one embedded SQL migration.
type Migration struct {
	Version int64  // leading integer of the filename (e.g. 1)
	Name    string // filename stem, e.g. "0001_init"
	SQL     string // file contents
}

// AppliedMigration identifies a migration applied during a Migrate run.
type AppliedMigration struct {
	Version int64
	Name    string
}

// MigrationStatus reports whether a known migration has been applied.
type MigrationStatus struct {
	Version   int64
	Name      string
	Applied   bool
	AppliedAt time.Time // zero when not applied
}

// Querier is the minimal read surface shared by *pgxpool.Pool, *pgxpool.Conn and
// pgx.Tx, so AppliedVersion works with a pool, a pooled connection, or a tx.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// parseMigrationVersion extracts the leading zero-padded integer version from a
// migration filename of the form NNNN_description.sql. It rejects any filename
// that does not match that pattern with a clear error.
func parseMigrationVersion(filename string) (int64, error) {
	if !strings.HasSuffix(filename, ".sql") {
		return 0, fmt.Errorf("migration %q: filename must end in .sql", filename)
	}
	stem := strings.TrimSuffix(filename, ".sql")
	i := strings.IndexByte(stem, '_')
	if i <= 0 {
		return 0, fmt.Errorf("migration %q: must be named NNNN_description.sql", filename)
	}
	numStr := stem[:i]
	for _, r := range numStr {
		if r < '0' || r > '9' {
			return 0, fmt.Errorf("migration %q: version prefix %q must be all digits", filename, numStr)
		}
	}
	v, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("migration %q: bad version %q: %w", filename, numStr, err)
	}
	if v <= 0 {
		return 0, fmt.Errorf("migration %q: version must be a positive integer", filename)
	}
	if i+1 >= len(stem) {
		return 0, fmt.Errorf("migration %q: missing description after version", filename)
	}
	return v, nil
}

// loadMigrations parses, sorts, and validates the embedded migration set.
func loadMigrations() ([]Migration, error) {
	return loadMigrationsFromFS(migrationsFS, "migrations")
}

// loadMigrationsFromFS is loadMigrations with an injectable filesystem so the
// parse/sort/validation logic is unit-testable without the real embed.FS.
// It rejects a non-conforming filename and duplicate/out-of-order versions.
func loadMigrationsFromFS(fsys fs.FS, dir string) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read migrations dir: %w", err)
	}
	migs := make([]Migration, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			return nil, fmt.Errorf("migrations: unexpected subdirectory %q", e.Name())
		}
		v, err := parseMigrationVersion(e.Name())
		if err != nil {
			return nil, err
		}
		body, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("read migration %q: %w", e.Name(), err)
		}
		migs = append(migs, Migration{
			Version: v,
			Name:    strings.TrimSuffix(e.Name(), ".sql"),
			SQL:     string(body),
		})
	}
	// Deterministic ascending order by version.
	sort.Slice(migs, func(i, j int) bool { return migs[i].Version < migs[j].Version })
	// Reject duplicate versions (two files claiming the same NNNN). After the
	// sort, versions must be strictly increasing.
	for i := 1; i < len(migs); i++ {
		if migs[i].Version == migs[i-1].Version {
			return nil, fmt.Errorf("migrations: duplicate version %d (%q and %q)",
				migs[i].Version, migs[i-1].Name, migs[i].Name)
		}
	}
	return migs, nil
}

// latestMigrationVersion returns the highest embedded migration version (0 when
// there are none). Used by the auto-migrate-off fail-fast check.
func latestMigrationVersion() (int64, error) {
	migs, err := loadMigrations()
	if err != nil {
		return 0, err
	}
	if len(migs) == 0 {
		return 0, nil
	}
	return migs[len(migs)-1].Version, nil
}

// AppliedVersion returns the highest applied migration version (0 if none, or if
// the schema_migrations table does not exist yet). It accepts any Querier — a
// pool, a pooled connection, or a transaction.
func AppliedVersion(ctx context.Context, q Querier) (int64, error) {
	var v int64
	err := q.QueryRow(ctx, `SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == pgUndefinedTable {
			return 0, nil // tracking table absent => nothing applied
		}
		return 0, fmt.Errorf("read applied migration version: %w", err)
	}
	return v, nil
}

// Migrate applies all pending migrations in ascending version order and returns
// the migrations it applied (empty when the database is already up to date, so a
// second call is a no-op). The whole run is serialized across instances by a
// session-level advisory lock; each migration commits in its own transaction.
func Migrate(ctx context.Context, pool *pgxpool.Pool) ([]AppliedMigration, error) {
	migs, err := loadMigrations()
	if err != nil {
		return nil, err
	}

	// A dedicated pooled connection carries the SESSION-level advisory lock for
	// the whole run. Releasing a pooled connection does NOT drop a session
	// advisory lock, so we unlock explicitly before releasing the connection.
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationAdvisoryLockKey); err != nil {
		return nil, fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer func() {
		// Best-effort unlock on a background context so a cancelled run still
		// releases the lock and returns a clean connection to the pool.
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, migrationAdvisoryLockKey)
	}()

	// Ensure the tracking table exists before reading/writing it.
	if _, err := conn.Exec(ctx, createSchemaMigrationsSQL); err != nil {
		return nil, fmt.Errorf("ensure schema_migrations: %w", err)
	}

	current, err := AppliedVersion(ctx, conn)
	if err != nil {
		return nil, err
	}

	var applied []AppliedMigration
	for _, m := range migs {
		if m.Version <= current {
			continue
		}
		if err := applyOne(ctx, conn, m); err != nil {
			return applied, fmt.Errorf("apply migration %s: %w", m.Name, err)
		}
		applied = append(applied, AppliedMigration{Version: m.Version, Name: m.Name})
	}
	return applied, nil
}

// applyOne runs one migration in its own transaction: exec the migration SQL,
// insert the schema_migrations row, commit. A failure rolls the whole thing back
// so the migration is retried (not half-applied) on the next run.
func applyOne(ctx context.Context, conn *pgxpool.Conn, m Migration) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	if _, err := tx.Exec(ctx, m.SQL); err != nil {
		return fmt.Errorf("exec migration sql: %w", err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version, name) VALUES ($1, $2)`,
		m.Version, m.Name); err != nil {
		return fmt.Errorf("record migration: %w", err)
	}
	return tx.Commit(ctx)
}

// Status reports every known (embedded) migration with whether it has been
// applied and, if so, when. It applies NOTHING.
func Status(ctx context.Context, pool *pgxpool.Pool) ([]MigrationStatus, error) {
	migs, err := loadMigrations()
	if err != nil {
		return nil, err
	}

	appliedAt := make(map[int64]time.Time)
	rows, err := pool.Query(ctx, `SELECT version, applied_at FROM schema_migrations`)
	if err != nil {
		var pgErr *pgconn.PgError
		if !(errors.As(err, &pgErr) && pgErr.Code == pgUndefinedTable) {
			return nil, fmt.Errorf("read schema_migrations: %w", err)
		}
		// table absent => nothing applied; leave appliedAt empty
	} else {
		func() {
			defer rows.Close()
			for rows.Next() {
				var v int64
				var at time.Time
				if scanErr := rows.Scan(&v, &at); scanErr != nil {
					err = scanErr
					return
				}
				appliedAt[v] = at
			}
			if rows.Err() != nil {
				err = rows.Err()
			}
		}()
		if err != nil {
			return nil, fmt.Errorf("scan schema_migrations: %w", err)
		}
	}

	out := make([]MigrationStatus, 0, len(migs))
	for _, m := range migs {
		at, ok := appliedAt[m.Version]
		out = append(out, MigrationStatus{
			Version:   m.Version,
			Name:      m.Name,
			Applied:   ok,
			AppliedAt: at,
		})
	}
	return out, nil
}
