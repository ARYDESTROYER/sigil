package store

// Integration tests for the RE-RUNNABLE account backfill (`sigild migrate
// adopt`), GATED on SIGILD_TEST_POSTGRES via requireDSN: with it unset every
// test here SKIPS, so `go test ./...` stays green with no database.
//
// WHAT IS BEING PROVED. Migration 0005 runs ONCE and is then recorded in
// schema_migrations forever. Its schema is deliberately compatible with a
// PRE-0005 BINARY (account_id is nullable so a rolled-back instance can still
// enroll), so an old instance running against an already-migrated database
// writes rows the backfill will never see again: devices with account_id NULL,
// and vaults with an is_owner grant and no owner row. Rolled forward, those
// devices are refused on every route and `sigild migrate` says "already up to
// date". This is the repair, and these tests are the proof that it works, is
// idempotent, and is a no-op when there is nothing to fix.

import (
	"context"
	"errors"
	"testing"
	"time"
)

// seedPreAccountRows writes exactly what a pre-0005 binary leaves behind against
// an already-migrated database: a device with a NULL account, and a vault it
// claimed via an is_owner grant with no sigil_vault_owners row.
func seedPreAccountRows(t *testing.T, s *PostgresDeviceStore, deviceID, vaultID string) {
	t.Helper()
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Millisecond)

	if _, err := s.pool.Exec(ctx,
		`INSERT INTO sigil_devices (device_id, account_id, public_key, label, status, created_at)
		 VALUES ($1, NULL, $2, 'pre-0005', 'active', $3)`,
		deviceID, testPubKey(t), at); err != nil {
		t.Fatalf("seed accountless device: %v", err)
	}
	if _, err := s.pool.Exec(ctx,
		`INSERT INTO sigil_device_grants (vault_id, device_id, permission, is_owner, created_at)
		 VALUES ($1, $2, 'write', true, $3)`, vaultID, deviceID, at); err != nil {
		t.Fatalf("seed orphan owner grant: %v", err)
	}
}

// TestAdoptOrphanAccountsRepairsARolledBackWrite is the repair proof: rows an
// old binary wrote after 0005 was applied are adopted, the vault gets its owner
// row, and a device that was refused everywhere becomes usable again.
func TestAdoptOrphanAccountsRepairsARolledBackWrite(t *testing.T) {
	requireDSN(t)
	s := newTestDeviceStore(t)
	ctx := context.Background()

	tag := uniqueTag()
	deviceID := "dev_pre0005_" + tag
	vaultID := "vault-pre0005-" + tag
	seedPreAccountRows(t, s, deviceID, vaultID)

	// The state the operator is stuck in.
	before, err := CountUnadoptedDevices(ctx, s.pool)
	if err != nil {
		t.Fatalf("CountUnadoptedDevices: %v", err)
	}
	if before < 1 {
		t.Fatalf("CountUnadoptedDevices = %d, want at least 1", before)
	}
	orphans, err := CountOrphanVaultOwnerGrants(ctx, s.pool)
	if err != nil {
		t.Fatalf("CountOrphanVaultOwnerGrants: %v", err)
	}
	if orphans < 1 {
		t.Fatalf("CountOrphanVaultOwnerGrants = %d, want at least 1", orphans)
	}
	stored, err := s.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if stored.AccountID != "" {
		t.Fatalf("seeded device already has account %q", stored.AccountID)
	}
	if _, err := s.GetVaultOwner(ctx, vaultID); err == nil {
		t.Fatal("seeded vault already has an owner row")
	}

	// THE REPAIR.
	rep, err := AdoptOrphanAccounts(ctx, s.pool)
	if err != nil {
		t.Fatalf("AdoptOrphanAccounts: %v", err)
	}
	if rep.Empty() {
		t.Fatal("AdoptOrphanAccounts reported nothing to do on a database that plainly had work")
	}
	if rep.DevicesAdopted < 1 || rep.AccountsCreated < 1 || rep.VaultOwnersBackfilled < 1 {
		t.Fatalf("report = %+v, want at least one of each", rep)
	}

	// The device now has its own singleton account, named so it is obvious in an
	// audit trail that a migration — not a human — created it.
	adopted, err := s.GetDevice(ctx, deviceID)
	if err != nil {
		t.Fatalf("GetDevice after adopt: %v", err)
	}
	want := AdoptedAccountID(deviceID)
	if adopted.AccountID != want {
		t.Fatalf("adopted account = %q, want %q", adopted.AccountID, want)
	}
	if _, err := s.GetAccount(ctx, want); err != nil {
		t.Fatalf("GetAccount(%s): %v", want, err)
	}
	// ...and the vault it had claimed is owned by that account.
	owner, err := s.GetVaultOwner(ctx, vaultID)
	if err != nil {
		t.Fatalf("GetVaultOwner after adopt: %v", err)
	}
	if owner.AccountID != want || owner.ClaimedByDeviceID != deviceID {
		t.Fatalf("owner = %+v, want account=%s device=%s", owner, want, deviceID)
	}

	// The counters agree that the specific rows are gone.
	afterDevices, err := CountUnadoptedDevices(ctx, s.pool)
	if err != nil {
		t.Fatalf("CountUnadoptedDevices after: %v", err)
	}
	if afterDevices != 0 {
		t.Fatalf("CountUnadoptedDevices after adopt = %d, want 0", afterDevices)
	}

	// IDEMPOTENT: a second run changes nothing and says so.
	second, err := AdoptOrphanAccounts(ctx, s.pool)
	if err != nil {
		t.Fatalf("second AdoptOrphanAccounts: %v", err)
	}
	if !second.Empty() {
		t.Fatalf("second run = %+v, want a no-op", second)
	}
	// And the adopted account was not re-minted or moved.
	again, err := s.GetDevice(ctx, deviceID)
	if err != nil || again.AccountID != want {
		t.Fatalf("device after second run = (%+v, %v), want account %q", again, err, want)
	}
}

// TestAdoptOrphanAccountsIsANoOpOnACleanDatabase: the command must be safe to
// run at any time, including when there is nothing wrong.
func TestAdoptOrphanAccountsIsANoOpOnACleanDatabase(t *testing.T) {
	requireDSN(t)
	s := newTestDeviceStore(t)
	ctx := context.Background()

	// A normally-enrolled device and a normally-claimed vault.
	dev := newTestDevice(t, "healthy")
	if err := createDevice(ctx, s, dev); err != nil {
		t.Fatalf("createDevice: %v", err)
	}
	vaultID := "vault-clean-" + uniqueTag()
	if _, _, err := s.ClaimVault(ctx, vaultID, dev.AccountID, dev.ID, time.Now().UTC()); err != nil {
		t.Fatalf("ClaimVault: %v", err)
	}

	rep, err := AdoptOrphanAccounts(ctx, s.pool)
	if err != nil {
		t.Fatalf("AdoptOrphanAccounts: %v", err)
	}
	if rep.DevicesAdopted != 0 || rep.AccountsCreated != 0 {
		t.Fatalf("clean database reported adoptions: %+v", rep)
	}
	// The healthy device's account was NOT rewritten into the adopted namespace.
	after, err := s.GetDevice(ctx, dev.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if after.AccountID != dev.AccountID {
		t.Fatalf("adopt MOVED a healthy device: %q -> %q", dev.AccountID, after.AccountID)
	}
	owner, err := s.GetVaultOwner(ctx, vaultID)
	if err != nil {
		t.Fatalf("GetVaultOwner: %v", err)
	}
	if owner.AccountID != dev.AccountID {
		t.Fatalf("adopt MOVED vault ownership: %q -> %q", dev.AccountID, owner.AccountID)
	}
}

// TestUnresolvableOwnerGrantIsRefusedThenRepairable: a claim over a vault whose
// only owner record names an ACCOUNTLESS device is refused with the explicit
// ErrVaultOwnerUnresolved sentinel — never an opaque database error — and the
// same claim succeeds after `sigild migrate adopt` has run.
//
// This is the pair the fix is for: name the state, and give the operator a way
// out of it.
func TestUnresolvableOwnerGrantIsRefusedThenRepairable(t *testing.T) {
	requireDSN(t)
	s := newTestDeviceStore(t)
	ctx := context.Background()

	tag := uniqueTag()
	oldDevice := "dev_unres_" + tag
	vaultID := "vault-unres-" + tag
	seedPreAccountRows(t, s, oldDevice, vaultID)

	writer := newTestDevice(t, "writer")
	if err := createDevice(ctx, s, writer); err != nil {
		t.Fatalf("createDevice: %v", err)
	}

	_, _, err := s.ClaimVault(ctx, vaultID, writer.AccountID, writer.ID, time.Now().UTC())
	if err == nil {
		t.Fatal("ClaimVault over an unresolvable owner grant succeeded")
	}
	if !errors.Is(err, ErrVaultOwnerUnresolved) {
		t.Fatalf("ClaimVault err = %v, want ErrVaultOwnerUnresolved (an opaque error is the 500)", err)
	}

	// REPAIR, then retry: the vault now resolves to the ADOPTED account of the
	// device that originally claimed it — not to the writer.
	if _, err := AdoptOrphanAccounts(ctx, s.pool); err != nil {
		t.Fatalf("AdoptOrphanAccounts: %v", err)
	}
	claimed, owner, err := s.ClaimVault(ctx, vaultID, writer.AccountID, writer.ID, time.Now().UTC())
	if err != nil {
		t.Fatalf("ClaimVault after repair: %v", err)
	}
	if claimed {
		t.Fatal("ClaimVault claimed a vault that already had an owner grant")
	}
	if owner.AccountID != AdoptedAccountID(oldDevice) {
		t.Fatalf("owner after repair = %q, want the adopted account %q",
			owner.AccountID, AdoptedAccountID(oldDevice))
	}
}
