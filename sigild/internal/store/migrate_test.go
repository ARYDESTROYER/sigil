package store

// Tests for the managed migration system (migrate.go). The filename-parse and
// load/sort/validate tests are PURE UNIT tests (no database). The rest are
// integration tests GATED on SIGILD_TEST_POSTGRES (via requireDSN, shared with
// postgresvaultlog_test.go); with it unset they SKIP.
//
// The DB tests DROP and recreate sigil_vault_ops / schema_migrations to get a
// clean slate, so they require a DEDICATED test database (the same one the other
// Postgres tests use). Migrate recreates the schema, so the other tests — which
// open a PostgresVaultLog (auto-migrate ON) — are unaffected.

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ---- pure unit tests (no database) ----

func TestParseMigrationVersion(t *testing.T) {
	good := map[string]int64{
		"0001_init.sql":      1,
		"0002_add_index.sql": 2,
		"12_thing.sql":       12,
		"00010_x.sql":        10,
	}
	for name, want := range good {
		v, err := parseMigrationVersion(name)
		if err != nil {
			t.Errorf("parseMigrationVersion(%q) error = %v, want nil", name, err)
			continue
		}
		if v != want {
			t.Errorf("parseMigrationVersion(%q) = %d, want %d", name, v, want)
		}
	}
	bad := []string{
		"init.sql",      // no version prefix
		"0001init.sql",  // no underscore
		"_init.sql",     // empty version
		"0001_.sql",     // empty description
		"0001_init.txt", // wrong extension
		"abc_init.sql",  // non-digit version
		"0000_init.sql", // zero version
		"0001-init.sql", // wrong separator
	}
	for _, name := range bad {
		if _, err := parseMigrationVersion(name); err == nil {
			t.Errorf("parseMigrationVersion(%q) = nil error, want error", name)
		}
	}
}

func TestLoadMigrationsFromFS(t *testing.T) {
	fsys := fstest.MapFS{
		"m/0002_b.sql": &fstest.MapFile{Data: []byte("SELECT 2;")},
		"m/0001_a.sql": &fstest.MapFile{Data: []byte("SELECT 1;")},
	}
	migs, err := loadMigrationsFromFS(fsys, "m")
	if err != nil {
		t.Fatalf("loadMigrationsFromFS: %v", err)
	}
	if len(migs) != 2 || migs[0].Version != 1 || migs[1].Version != 2 {
		t.Fatalf("migs = %+v, want ascending [1,2]", migs)
	}
	if migs[0].Name != "0001_a" || migs[0].SQL != "SELECT 1;" {
		t.Fatalf("migs[0] = %+v, want name 0001_a / sql SELECT 1;", migs[0])
	}

	// Duplicate version rejected.
	dup := fstest.MapFS{
		"m/0001_a.sql": &fstest.MapFile{Data: []byte("x")},
		"m/0001_b.sql": &fstest.MapFile{Data: []byte("y")},
	}
	if _, err := loadMigrationsFromFS(dup, "m"); err == nil {
		t.Error("loadMigrationsFromFS(duplicate version) = nil error, want error")
	}

	// Non-conforming filename rejected.
	bad := fstest.MapFS{
		"m/notamigration.sql": &fstest.MapFile{Data: []byte("x")},
	}
	if _, err := loadMigrationsFromFS(bad, "m"); err == nil {
		t.Error("loadMigrationsFromFS(bad filename) = nil error, want error")
	}
}

// TestEmbeddedMigrationsLoad verifies the REAL embedded migration set parses,
// starts at 0001_init, and that latestMigrationVersion agrees with it.
func TestEmbeddedMigrationsLoad(t *testing.T) {
	migs, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migs) == 0 {
		t.Fatal("no embedded migrations found")
	}
	if migs[0].Version != 1 || migs[0].Name != "0001_init" {
		t.Fatalf("first embedded migration = %+v, want version 1 name 0001_init", migs[0])
	}
	lv, err := latestMigrationVersion()
	if err != nil {
		t.Fatalf("latestMigrationVersion: %v", err)
	}
	if lv != migs[len(migs)-1].Version {
		t.Fatalf("latestMigrationVersion = %d, want %d", lv, migs[len(migs)-1].Version)
	}
}

// ---- integration tests (gated on SIGILD_TEST_POSTGRES) ----

// migrateTestPool opens a raw pool (skipping without a DSN) and registers close.
func migrateTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := requireDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// dropOplogTables removes every table in the test database so a test starts
// from a genuinely fresh DB.
//
// It DISCOVERS the tables rather than hardcoding a list. An earlier version
// enumerated them by hand with the note "must be extended whenever a migration
// adds a table" — and that invariant duly broke: migrations 0003 (billing) and
// 0004 (key sharing) added four tables that were never added here, two of them
// carrying `REFERENCES sigil_devices ... ON DELETE CASCADE`. Those foreign keys
// made `DROP TABLE sigil_devices` fail with SQLSTATE 2BP01, which aborted the
// teardown HALF-DONE and left the database wedged: schema_migrations still
// claimed the latest version, so the auto-migrator applied nothing, and every
// subsequent Postgres test failed on a missing relation until someone manually
// dropped the schema.
//
// Discovering the tables removes the fragile human invariant entirely: a future
// migration can add as many tables as it likes and this still cleans up. CASCADE
// handles the dependency order for us, so no topological sort is needed either.
//
// This is a TEST-ONLY helper and only ever runs against the throwaway database
// named by SIGILD_TEST_POSTGRES.
func dropOplogTables(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := pool.Query(ctx,
		`SELECT tablename FROM pg_tables WHERE schemaname = current_schema()`)
	if err != nil {
		t.Fatalf("list tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			t.Fatalf("scan table name: %v", err)
		}
		tables = append(tables, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate tables: %v", err)
	}

	for _, name := range tables {
		// pgx cannot parameterise an identifier, so quote it explicitly. The
		// name comes from pg_tables (not from user input), and CASCADE drops
		// dependent foreign keys so ordering does not matter.
		stmt := fmt.Sprintf(`DROP TABLE IF EXISTS %q CASCADE`, name)
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("drop (%s): %v", stmt, err)
		}
	}
}

// wantAllMigrations returns the full embedded migration set, so the tests below
// assert against whatever migrations exist rather than a hardcoded count (which
// would break every time a migration is added).
func wantAllMigrations(t *testing.T) []Migration {
	t.Helper()
	migs, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	if len(migs) == 0 {
		t.Fatal("no embedded migrations")
	}
	return migs
}

// assertAppliedMatchesSet checks that `applied` is exactly the embedded
// migration set, in ascending version order.
func assertAppliedMatchesSet(t *testing.T, applied []AppliedMigration) {
	t.Helper()
	want := wantAllMigrations(t)
	if len(applied) != len(want) {
		t.Fatalf("applied = %+v, want the %d embedded migrations", applied, len(want))
	}
	for i, m := range want {
		if applied[i].Version != m.Version || applied[i].Name != m.Name {
			t.Fatalf("applied[%d] = %+v, want {%d %s}", i, applied[i], m.Version, m.Name)
		}
	}
}

// TestMigrateFreshDB: a fresh empty DB gets 0001 applied, AppliedVersion==1, the
// op-log table is usable (Append/Since/VerifyChain), and a second Migrate is a
// no-op (idempotent).
func TestMigrateFreshDB(t *testing.T) {
	pool := migrateTestPool(t)
	dropOplogTables(t, pool)
	ctx := context.Background()

	applied, err := Migrate(ctx, pool)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	assertAppliedMatchesSet(t, applied)
	if applied[0].Name != "0001_init" {
		t.Fatalf("first applied migration = %q, want 0001_init", applied[0].Name)
	}
	latest, err := latestMigrationVersion()
	if err != nil {
		t.Fatalf("latestMigrationVersion: %v", err)
	}
	if v, err := AppliedVersion(ctx, pool); err != nil || v != latest {
		t.Fatalf("AppliedVersion = (%d, %v), want (%d, nil)", v, err, latest)
	}

	// sigil_vault_ops usable through a PostgresVaultLog over the same pool.
	l := &PostgresVaultLog{pool: pool}
	vault := uniquePrefix() + "v"
	if _, err := l.Append(ctx, vault, []byte("op")); err != nil {
		t.Fatalf("Append after migrate: %v", err)
	}
	ops, err := l.Since(ctx, vault, 0, 0)
	if err != nil || len(ops) != 1 {
		t.Fatalf("Since = (%v, %v), want 1 op", ops, err)
	}
	if res, err := l.VerifyChain(ctx, vault); err != nil || !res.OK || res.Count != 1 {
		t.Fatalf("VerifyChain = (%+v, %v), want OK count 1", res, err)
	}
	if _, err := l.pool.Exec(ctx, `DELETE FROM sigil_vault_ops WHERE vault_id = $1`, vault); err != nil {
		t.Errorf("cleanup: %v", err)
	}

	// Idempotent: second Migrate applies nothing.
	again, err := Migrate(ctx, pool)
	if err != nil {
		t.Fatalf("Migrate again: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second Migrate applied %+v, want none", again)
	}
}

// TestMigrateStatus: Status reports pending before Migrate (no error even though
// schema_migrations is absent) and applied afterwards with a non-zero AppliedAt.
func TestMigrateStatus(t *testing.T) {
	pool := migrateTestPool(t)
	dropOplogTables(t, pool)
	ctx := context.Background()

	pre, err := Status(ctx, pool)
	if err != nil {
		t.Fatalf("Status pre: %v", err)
	}
	if len(pre) == 0 {
		t.Fatal("Status returned no migrations")
	}
	for _, s := range pre {
		if s.Applied {
			t.Fatalf("migration %s reported applied before Migrate", s.Name)
		}
	}

	if _, err := Migrate(ctx, pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}

	post, err := Status(ctx, pool)
	if err != nil {
		t.Fatalf("Status post: %v", err)
	}
	if !post[0].Applied || post[0].Version != 1 {
		t.Fatalf("post[0] = %+v, want applied version 1", post[0])
	}
	if post[0].AppliedAt.IsZero() {
		t.Fatal("applied migration has zero AppliedAt")
	}
}

// TestMigrateAdoptsLegacyTable: a DB with a hand-created sigil_vault_ops but no
// schema_migrations (as the OLD inline DDL left it) is adopted cleanly —
// Migrate applies the whole embedded set without error and AppliedVersion ends
// at the latest embedded version.
func TestMigrateAdoptsLegacyTable(t *testing.T) {
	pool := migrateTestPool(t)
	dropOplogTables(t, pool)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `CREATE TABLE sigil_vault_ops (
		vault_id   text        NOT NULL,
		seq        bigint      NOT NULL,
		blob       bytea       NOT NULL,
		hash       bytea,
		created_at timestamptz NOT NULL DEFAULT now(),
		PRIMARY KEY (vault_id, seq))`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}

	applied, err := Migrate(ctx, pool)
	if err != nil {
		t.Fatalf("Migrate adopt: %v", err)
	}
	assertAppliedMatchesSet(t, applied)
	latest, err := latestMigrationVersion()
	if err != nil {
		t.Fatalf("latestMigrationVersion: %v", err)
	}
	if v, err := AppliedVersion(ctx, pool); err != nil || v != latest {
		t.Fatalf("AppliedVersion after adopt = (%d, %v), want (%d, nil)", v, err, latest)
	}

	// Table still usable.
	l := &PostgresVaultLog{pool: pool}
	vault := uniquePrefix() + "v"
	if _, err := l.Append(ctx, vault, []byte("op")); err != nil {
		t.Fatalf("Append after adopt: %v", err)
	}
	if _, err := l.pool.Exec(ctx, `DELETE FROM sigil_vault_ops WHERE vault_id = $1`, vault); err != nil {
		t.Errorf("cleanup: %v", err)
	}
}

// TestNewPostgresVaultLogAutoMigrateOff: with SIGILD_OPLOG_AUTO_MIGRATE disabled
// and an unmigrated DB, construction FAILS FAST (does not apply) with an error
// pointing the operator at `sigild migrate`.
func TestNewPostgresVaultLogAutoMigrateOff(t *testing.T) {
	dsn := requireDSN(t)
	pool := migrateTestPool(t)
	dropOplogTables(t, pool) // unmigrated

	t.Setenv("SIGILD_OPLOG_AUTO_MIGRATE", "false")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	l, err := NewPostgresVaultLog(ctx, dsn)
	if err == nil {
		l.Close()
		t.Fatal("NewPostgresVaultLog(auto-migrate off, unmigrated DB) = nil error, want fail-fast error")
	}
	if !strings.Contains(err.Error(), "sigild migrate") {
		t.Fatalf("error = %q, want it to mention `sigild migrate`", err)
	}
}

// TestMigrateConcurrentNoDoubleApply: several goroutines (independent pools) call
// Migrate at once. The session advisory lock must serialize them so EXACTLY one
// applies 0001 and the rest apply nothing — no error, no duplicate row. Run under
// -race.
func TestMigrateConcurrentNoDoubleApply(t *testing.T) {
	dsn := requireDSN(t)
	setup := migrateTestPool(t)
	dropOplogTables(t, setup)

	const n = 4
	pools := make([]*pgxpool.Pool, n)
	for i := range pools {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		p, err := pgxpool.New(ctx, dsn)
		cancel()
		if err != nil {
			t.Fatalf("pool %d: %v", i, err)
		}
		pools[i] = p
		t.Cleanup(p.Close)
	}

	var wg sync.WaitGroup
	results := make([][]AppliedMigration, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			results[i], errs[i] = Migrate(ctx, pools[i])
		}(i)
	}
	wg.Wait()

	total := 0
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("Migrate[%d] error = %v", i, errs[i])
		}
		total += len(results[i])
	}
	// Across ALL concurrent runs each embedded migration must be applied exactly
	// once — the advisory lock serializes the runs, so the total equals the size
	// of the migration set, never more.
	migs := wantAllMigrations(t)
	if total != len(migs) {
		t.Fatalf("total migrations applied across %d concurrent runs = %d, want exactly %d (no double-apply)", n, total, len(migs))
	}
	latest, err := latestMigrationVersion()
	if err != nil {
		t.Fatalf("latestMigrationVersion: %v", err)
	}
	if v, err := AppliedVersion(context.Background(), setup); err != nil || v != latest {
		t.Fatalf("final AppliedVersion = (%d, %v), want (%d, nil)", v, err, latest)
	}
	var count int
	if err := setup.QueryRow(context.Background(),
		`SELECT count(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("count schema_migrations: %v", err)
	}
	if count != len(migs) {
		t.Fatalf("schema_migrations rows = %d, want exactly %d (one per migration)", count, len(migs))
	}
}
