package store

// Integration tests for PostgresDeviceStore and migration 0002_devices.
//
// GATED on SIGILD_TEST_POSTGRES (a libpq DSN) exactly like the op-log
// integration tests: with it unset every test here SKIPS, so `go test ./...`
// stays green with no database.
//
// The suite these run is the SAME backend-agnostic conformance suite the
// in-memory store runs (runDeviceStoreSuite), so both implementations are held
// to identical semantics — including the two atomic guarantees (single-use
// enrollment tokens, single-owner vault claims), which here are enforced by the
// database and therefore hold across processes.

import (
	"context"
	"testing"
	"time"
)

// newTestDeviceStore opens a pool against the integration DSN (skipping without
// one), applies migrations, and returns a PostgresDeviceStore. A t.Cleanup
// deletes every row this test created and closes the pool.
func newTestDeviceStore(t *testing.T) *PostgresDeviceStore {
	t.Helper()
	dsn := requireDSN(t)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	// NewPostgresVaultLog opens the pool AND applies migrations (0001 + 0002),
	// which is exactly the production boot path; the device store then shares
	// that pool, as cmd/server does.
	vl, err := NewPostgresVaultLog(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresVaultLog: %v", err)
	}
	s := NewPostgresDeviceStore(vl.Pool())

	// Snapshot which rows existed before, so cleanup removes only ours.
	before := time.Now().UTC()
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer ccancel()
		for _, q := range []string{
			// Sharing rows first: they FK-reference sigil_devices (ON DELETE
			// CASCADE would handle it, but deleting explicitly keeps the
			// cleanup readable and order-independent).
			`DELETE FROM sigil_vault_key_envelopes WHERE created_at >= $1`,
			`DELETE FROM sigil_device_hybrid_keys WHERE updated_at >= $1`,
			`DELETE FROM sigil_device_grants WHERE created_at >= $1`,
			`DELETE FROM sigil_enrollment_tokens WHERE issued_at >= $1`,
			// Account rows (Phase 52). Invites and vault-owner rows FK-reference
			// sigil_accounts, and sigil_devices does too, so accounts go LAST.
			`DELETE FROM sigil_account_invites WHERE created_at >= $1`,
			`DELETE FROM sigil_vault_owners WHERE claimed_at >= $1`,
			`DELETE FROM sigil_devices WHERE created_at >= $1`,
			`DELETE FROM sigil_accounts WHERE created_at >= $1`,
		} {
			if _, err := s.pool.Exec(cctx, q, before.Add(-time.Minute)); err != nil {
				t.Logf("cleanup %q: %v", q, err)
			}
		}
		vl.Close()
	})
	return s
}

// TestPostgresDeviceStoreSuite runs the shared conformance suite against the
// durable backend.
func TestPostgresDeviceStoreSuite(t *testing.T) {
	requireDSN(t)
	// One store instance is shared by the suite's subtests; every subtest
	// namespaces its own vault IDs / token hashes via uniqueTag(), and the
	// device-list assertions filter to the devices they created, so a shared
	// database is safe.
	s := newTestDeviceStore(t)
	runDeviceStoreSuite(t, func(t *testing.T) DeviceStore {
		t.Helper()
		return s
	})
}

// TestPostgresMigration0002AppliesOnTopOf0001 proves the new migration is part
// of the managed set, applies cleanly after the baseline, and leaves the applied
// version at (at least) 2 — i.e. an existing 0001-only database upgrades in
// place without touching the op-log tables.
func TestPostgresMigration0002AppliesOnTopOf0001(t *testing.T) {
	dsn := requireDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	vl, err := NewPostgresVaultLog(ctx, dsn) // applies pending migrations
	if err != nil {
		t.Fatalf("NewPostgresVaultLog: %v", err)
	}
	defer vl.Close()

	statuses, err := Status(ctx, vl.Pool())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	var saw0001, saw0002 bool
	for _, st := range statuses {
		switch st.Version {
		case 1:
			saw0001 = st.Applied
		case 2:
			saw0002 = st.Applied
			if st.Name != "0002_devices" {
				t.Fatalf("migration 2 name = %q, want 0002_devices", st.Name)
			}
		}
	}
	if !saw0001 || !saw0002 {
		t.Fatalf("migrations applied: 0001=%v 0002=%v, want both true", saw0001, saw0002)
	}

	version, err := vl.SchemaVersion(ctx)
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if version < 2 {
		t.Fatalf("applied schema version = %d, want >= 2", version)
	}

	// The op-log itself must still work after the device tables landed.
	vault := "vault-" + uniqueTag()
	if _, err := vl.Append(ctx, vault, []byte("opaque-after-0002")); err != nil {
		t.Fatalf("Append after 0002: %v", err)
	}
	res, err := vl.VerifyChain(ctx, vault)
	if err != nil || !res.OK {
		t.Fatalf("VerifyChain after 0002 = (%+v, %v), want ok", res, err)
	}
	if _, err := vl.Pool().Exec(ctx, `DELETE FROM sigil_vault_ops WHERE vault_id = $1`, vault); err != nil {
		t.Logf("cleanup ops: %v", err)
	}
}

// TestPostgresMigrateIsIdempotent re-runs Migrate against an up-to-date database
// and asserts it applies nothing (the advisory-locked run is a no-op).
func TestPostgresMigrate0002Idempotent(t *testing.T) {
	dsn := requireDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	vl, err := NewPostgresVaultLog(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresVaultLog: %v", err)
	}
	defer vl.Close()

	applied, err := Migrate(ctx, vl.Pool())
	if err != nil {
		t.Fatalf("Migrate (second run): %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("second Migrate applied %d migrations, want 0", len(applied))
	}
}
