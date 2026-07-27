package store

// Integration tests for migration 0005_accounts, GATED on SIGILD_TEST_POSTGRES
// (via requireDSN, shared with the other Postgres tests): with it unset every
// test here SKIPS, so `go test ./...` stays green with no database.
//
// The point of this file is the UPGRADE, not the fresh install: a database that
// already carries 0001-0004 WITH ROWS IN IT must adopt cleanly, and the two
// things that must not move — the op-log (blob + hash chain) and the grants
// table — must come out byte-for-byte identical.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// applyThrough applies every embedded migration up to and including version v,
// so a test can stand a database up at an OLD schema version and then upgrade it.
func applyThrough(t *testing.T, pool *pgxpool.Pool, v int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	migs, err := loadMigrations()
	if err != nil {
		t.Fatalf("loadMigrations: %v", err)
	}
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, createSchemaMigrationsSQL); err != nil {
		t.Fatalf("ensure schema_migrations: %v", err)
	}
	for _, m := range migs {
		if m.Version > v {
			break
		}
		if err := applyOne(ctx, conn, m); err != nil {
			t.Fatalf("apply %s: %v", m.Name, err)
		}
	}
}

// TestMigration0005AdoptsAnExistingDatabase is the upgrade proof: seed a
// version-4 schema with real rows, run Migrate, and check every invariant.
func TestMigration0005AdoptsAnExistingDatabase(t *testing.T) {
	requireDSN(t)
	pool := migrateTestPool(t)
	dropOplogTables(t, pool)
	applyThrough(t, pool, 4)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if v, err := AppliedVersion(ctx, pool); err != nil || v != 4 {
		t.Fatalf("seeded AppliedVersion = (%d, %v), want (4, nil)", v, err)
	}

	// ---- seed a pre-account world -------------------------------------------
	const (
		devLaptop  = "dev_seed_laptop"
		devPhone   = "dev_seed_phone"
		devRetired = "dev_seed_retired"
		vaultOwned = "vault_seed_owned"
		vaultShare = "vault_seed_shared"
	)
	seededAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	for i, id := range []string{devLaptop, devPhone, devRetired} {
		key := make([]byte, 32)
		key[0] = byte(i + 1)
		status := "active"
		if id == devRetired {
			status = "revoked"
		}
		if _, err := pool.Exec(ctx,
			`INSERT INTO sigil_devices (device_id, public_key, label, status, created_at)
			 VALUES ($1, $2, $3, $4, $5)`,
			id, key, id, status, seededAt); err != nil {
			t.Fatalf("seed device %s: %v", id, err)
		}
	}
	// One OWNER grant and two ordinary grants.
	grants := []struct {
		vault, device, perm string
		owner               bool
	}{
		{vaultOwned, devLaptop, "write", true},
		{vaultOwned, devPhone, "read", false},
		{vaultShare, devRetired, "write", false},
	}
	for _, g := range grants {
		if _, err := pool.Exec(ctx,
			`INSERT INTO sigil_device_grants (vault_id, device_id, permission, is_owner, created_at)
			 VALUES ($1, $2, $3, $4, $5)`,
			g.vault, g.device, g.perm, g.owner, seededAt); err != nil {
			t.Fatalf("seed grant: %v", err)
		}
	}
	// A DEVICE-keyed subscription and a processed billing event.
	if _, err := pool.Exec(ctx,
		`INSERT INTO sigil_subscriptions (subject, provider, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		devLaptop, "stripe", "active", seededAt, seededAt); err != nil {
		t.Fatalf("seed subscription: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO sigil_billing_processed_events (provider, event_id, event_type, subject)
		 VALUES ($1, $2, $3, $4)`,
		"stripe", "evt_seed_1", "checkout_completed", devLaptop); err != nil {
		t.Fatalf("seed processed event: %v", err)
	}
	// Two op-log rows, so the chain has something to be identical about.
	vl := &PostgresVaultLog{pool: pool}
	for _, blob := range [][]byte{[]byte("opaque-one"), []byte("opaque-two")} {
		if _, err := vl.Append(ctx, vaultOwned, blob); err != nil {
			t.Fatalf("seed op: %v", err)
		}
	}
	before, err := vl.VerifyChain(ctx, vaultOwned)
	if err != nil || !before.OK {
		t.Fatalf("pre-migration VerifyChain = (%+v, %v), want ok", before, err)
	}
	var grantsBefore int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sigil_device_grants`).Scan(&grantsBefore); err != nil {
		t.Fatalf("count grants: %v", err)
	}

	// ---- upgrade -------------------------------------------------------------
	applied, err := Migrate(ctx, pool)
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	if len(applied) != 1 || applied[0].Version != 5 || applied[0].Name != "0005_accounts" {
		t.Fatalf("applied = %+v, want exactly 0005_accounts", applied)
	}
	if v, err := AppliedVersion(ctx, pool); err != nil || v != 5 {
		t.Fatalf("AppliedVersion = (%d, %v), want (5, nil)", v, err)
	}

	// ---- every device adopted, 1:1, into acct_mig_||device_id ----------------
	var nullAccounts int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM sigil_devices WHERE account_id IS NULL`).Scan(&nullAccounts); err != nil {
		t.Fatalf("count null accounts: %v", err)
	}
	if nullAccounts != 0 {
		t.Fatalf("%d devices still have no account after 0005", nullAccounts)
	}
	for _, id := range []string{devLaptop, devPhone, devRetired} {
		var got string
		if err := pool.QueryRow(ctx,
			`SELECT account_id FROM sigil_devices WHERE device_id = $1`, id).Scan(&got); err != nil {
			t.Fatalf("read account for %s: %v", id, err)
		}
		if want := AdoptedAccountID(id); got != want {
			t.Fatalf("device %s adopted into %q, want %q", id, got, want)
		}
		var accounts int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM sigil_accounts WHERE account_id = $1`, got).Scan(&accounts); err != nil {
			t.Fatalf("count account: %v", err)
		}
		if accounts != 1 {
			t.Fatalf("account %s has %d rows, want 1 (adoption must be 1:1)", got, accounts)
		}
	}

	// ---- ownership backfilled from the is_owner grant, and ONLY that ---------
	var ownerRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sigil_vault_owners`).Scan(&ownerRows); err != nil {
		t.Fatalf("count owners: %v", err)
	}
	if ownerRows != 1 {
		t.Fatalf("sigil_vault_owners has %d rows, want exactly 1 (one is_owner grant was seeded)", ownerRows)
	}
	var ownerAccount, claimedBy string
	if err := pool.QueryRow(ctx,
		`SELECT account_id, claimed_by_device_id FROM sigil_vault_owners WHERE vault_id = $1`,
		vaultOwned).Scan(&ownerAccount, &claimedBy); err != nil {
		t.Fatalf("read owner: %v", err)
	}
	if ownerAccount != AdoptedAccountID(devLaptop) || claimedBy != devLaptop {
		t.Fatalf("owner = (%s, %s), want (%s, %s)",
			ownerAccount, claimedBy, AdoptedAccountID(devLaptop), devLaptop)
	}
	// No is_owner grant may be left without an owner row.
	var orphanOwners int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM sigil_device_grants g
		  WHERE g.is_owner
		    AND NOT EXISTS (SELECT 1 FROM sigil_vault_owners o WHERE o.vault_id = g.vault_id)`).
		Scan(&orphanOwners); err != nil {
		t.Fatalf("count orphan owners: %v", err)
	}
	if orphanOwners != 0 {
		t.Fatalf("%d is_owner grants have no owner row", orphanOwners)
	}

	// ---- the grants table was NOT rewritten ---------------------------------
	var grantsAfter int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sigil_device_grants`).Scan(&grantsAfter); err != nil {
		t.Fatalf("count grants after: %v", err)
	}
	if grantsAfter != grantsBefore {
		t.Fatalf("grant rows changed %d -> %d; 0005 must not touch sigil_device_grants", grantsBefore, grantsAfter)
	}
	for _, g := range grants {
		var perm string
		var owner bool
		if err := pool.QueryRow(ctx,
			`SELECT permission, is_owner FROM sigil_device_grants WHERE vault_id = $1 AND device_id = $2`,
			g.vault, g.device).Scan(&perm, &owner); err != nil {
			t.Fatalf("read grant (%s,%s): %v", g.vault, g.device, err)
		}
		if perm != g.perm || owner != g.owner {
			t.Fatalf("grant (%s,%s) = (%s,%v), want (%s,%v)", g.vault, g.device, perm, owner, g.perm, g.owner)
		}
	}

	// ---- ENTITLEMENT re-keyed onto the account ------------------------------
	var subject string
	if err := pool.QueryRow(ctx,
		`SELECT subject FROM sigil_subscriptions WHERE provider = 'stripe'`).Scan(&subject); err != nil {
		t.Fatalf("read subscription: %v", err)
	}
	if want := AdoptedAccountID(devLaptop); subject != want {
		t.Fatalf("subscription subject = %q, want the adopted account %q", subject, want)
	}
	var subRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sigil_subscriptions`).Scan(&subRows); err != nil {
		t.Fatalf("count subscriptions: %v", err)
	}
	if subRows != 1 {
		t.Fatalf("subscription rows = %d, want 1 (the re-key must UPDATE, never duplicate)", subRows)
	}

	// ---- the processed-event ledger is DELIBERATELY untouched ---------------
	var eventSubject string
	if err := pool.QueryRow(ctx,
		`SELECT subject FROM sigil_billing_processed_events WHERE event_id = 'evt_seed_1'`).
		Scan(&eventSubject); err != nil {
		t.Fatalf("read processed event: %v", err)
	}
	if eventSubject != devLaptop {
		t.Fatalf("processed-event subject = %q, want the ORIGINAL device id %q (history is append-only)",
			eventSubject, devLaptop)
	}

	// ---- the op-log and its hash chain are byte-for-byte unchanged ----------
	after, err := vl.VerifyChain(ctx, vaultOwned)
	if err != nil || !after.OK {
		t.Fatalf("post-migration VerifyChain = (%+v, %v), want ok", after, err)
	}
	if after.TipHash != before.TipHash || after.Count != before.Count {
		t.Fatalf("op-log chain moved: (%d, %x) -> (%d, %x)",
			before.Count, before.TipHash, after.Count, after.TipHash)
	}

	// ---- re-running Migrate is a clean no-op --------------------------------
	again, err := Migrate(ctx, pool)
	if err != nil {
		t.Fatalf("second Migrate: %v", err)
	}
	if len(again) != 0 {
		t.Fatalf("second Migrate applied %d migrations, want 0", len(again))
	}
	after2, err := vl.VerifyChain(ctx, vaultOwned)
	if err != nil || after2.TipHash != before.TipHash {
		t.Fatalf("a repeat Migrate moved the chain tip: %x -> %x (err %v)",
			before.TipHash, after2.TipHash, err)
	}
}
