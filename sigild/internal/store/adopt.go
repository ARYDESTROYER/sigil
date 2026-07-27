package store

// A RE-RUNNABLE REPAIR for the account backfill (`sigild migrate adopt`).
//
// WHY THIS EXISTS. Migration 0005 adopts every pre-existing device into its own
// singleton account, backfills vault ownership from the legacy is_owner grants,
// and re-keys subscriptions from the device to its account. It runs ONCE, and
// once it is recorded in schema_migrations it never runs again — which is
// correct for a migration and wrong for the data, because 0005's schema is
// deliberately compatible with a PRE-0005 BINARY:
//
//	sigil_devices.account_id is NULLABLE (a NOT NULL column would stop a
//	rolled-back binary enrolling at all), so an old instance still running
//	against an already-migrated database enrolls devices with account_id NULL
//	and claims vaults by writing an is_owner grant and no owner row.
//
// Roll forward and those rows are stranded: the new binary refuses them
// (missing_account / vault_owner_unresolved, coarse 403 — see api/deviceauth.go)
// and `sigild migrate` reports "already up to date". This is the operator's way
// out, and it is the ONLY way out: adoption deliberately never happens
// implicitly on the authentication path, where it would mean an unauthenticated
// request could mint an account.
//
// IT IS THE SAME THREE STATEMENTS 0005 RUNS, with the same idempotency guards,
// in ONE transaction. Running it when there is nothing to adopt changes nothing
// and reports zero. It is AUTH METADATA ONLY: no vault op, no blob, no hash
// chain, no key, no plaintext — sigil_vault_ops is not named anywhere in it.

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pgUndefinedColumn is the SQLSTATE for "column does not exist" (42703).
const pgUndefinedColumn = "42703"

// isUndefinedColumnOrTable reports whether err says the schema predates the
// account model. The counting helpers below treat that as "nothing to report"
// rather than an error: they run at boot, and a database migrated only to 0004
// must not be able to stop a server starting.
func isUndefinedColumnOrTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) &&
		(pgErr.Code == pgUndefinedTable || pgErr.Code == pgUndefinedColumn)
}

// AdoptionReport counts what a repair run changed. All zeros means the database
// was already consistent and nothing was written.
type AdoptionReport struct {
	// AccountsCreated is the number of singleton accounts minted for devices
	// that had none.
	AccountsCreated int
	// DevicesAdopted is the number of device rows given an account_id.
	DevicesAdopted int
	// VaultOwnersBackfilled is the number of vaults whose ownership was recorded
	// from an existing is_owner grant.
	VaultOwnersBackfilled int
	// SubscriptionsRekeyed is the number of subscription rows whose subject moved
	// from a device ID to that device's account ID.
	SubscriptionsRekeyed int
}

// Empty reports whether the run had nothing to do.
func (r AdoptionReport) Empty() bool {
	return r.AccountsCreated == 0 && r.DevicesAdopted == 0 &&
		r.VaultOwnersBackfilled == 0 && r.SubscriptionsRekeyed == 0
}

// CountUnadoptedDevices returns how many device rows carry no account. It is a
// pure read, used for the boot-time warning: an operator has no other way to
// learn that these rows exist, because every request from such a device answers
// the same coarse 403 every other refusal does.
//
// A missing account_id column (a database migrated only to 0004, or not at all)
// is reported as zero, not as an error — this must never be able to stop a boot.
func CountUnadoptedDevices(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	var n int
	err := pool.QueryRow(ctx,
		`SELECT count(*) FROM sigil_devices WHERE account_id IS NULL`).Scan(&n)
	if err != nil {
		if isUndefinedColumnOrTable(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("count unadopted devices: %w", err)
	}
	return n, nil
}

// CountOrphanVaultOwnerGrants returns how many vaults carry a legacy is_owner
// GRANT but no sigil_vault_owners row. Like CountUnadoptedDevices it is a pure
// read for the boot warning; a missing table reports zero.
//
// A write by the grant holder (or by any device the grant holder authorized)
// reconciles one of these automatically — ClaimVault adopts the grant holder's
// account. This count is what tells an operator how many are waiting, and
// AdoptOrphanAccounts is what fixes them all at once.
func CountOrphanVaultOwnerGrants(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	var n int
	err := pool.QueryRow(ctx,
		`SELECT count(*) FROM sigil_device_grants g
		  WHERE g.is_owner
		    AND NOT EXISTS (SELECT 1 FROM sigil_vault_owners o WHERE o.vault_id = g.vault_id)`).
		Scan(&n)
	if err != nil {
		if isUndefinedColumnOrTable(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("count orphan owner grants: %w", err)
	}
	return n, nil
}

// AdoptOrphanAccounts re-runs migration 0005's backfill over whatever state the
// database is in now. It is IDEMPOTENT — a second run reports zeros — and a
// no-op when there is nothing to adopt.
//
// The three steps, in the order they must happen:
//
//  1. mint an 'acct_mig_<device_id>' account for every device with none, and
//     stamp it onto the device (the account must exist before the FK is set);
//  2. record ownership for every vault holding a legacy is_owner grant whose
//     device now resolves to an account — after step 1, so a device adopted in
//     this very run also gets its vaults;
//  3. move any subscription whose subject is a DEVICE id onto that device's
//     account, guarded by the same NOT EXISTS 0005 uses so no primary key can
//     collide.
//
// The whole run is ONE transaction: either the database is fully repaired or it
// is untouched. Nothing here reads or writes sigil_vault_ops.
func AdoptOrphanAccounts(ctx context.Context, pool *pgxpool.Pool) (AdoptionReport, error) {
	var rep AdoptionReport
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`INSERT INTO sigil_accounts (account_id, created_at, created_by_device_id)
			 SELECT '`+AdoptedAccountPrefix+`' || d.device_id, d.created_at, d.device_id
			   FROM sigil_devices d WHERE d.account_id IS NULL
			 ON CONFLICT (account_id) DO NOTHING`)
		if err != nil {
			return fmt.Errorf("create adopted accounts: %w", err)
		}
		rep.AccountsCreated = int(tag.RowsAffected())

		tag, err = tx.Exec(ctx,
			`UPDATE sigil_devices d SET account_id = '`+AdoptedAccountPrefix+`' || d.device_id
			  WHERE d.account_id IS NULL`)
		if err != nil {
			return fmt.Errorf("adopt devices: %w", err)
		}
		rep.DevicesAdopted = int(tag.RowsAffected())

		tag, err = tx.Exec(ctx,
			`INSERT INTO sigil_vault_owners (vault_id, account_id, claimed_by_device_id, claimed_at)
			 SELECT g.vault_id, d.account_id, g.device_id, g.created_at
			   FROM sigil_device_grants g
			   JOIN sigil_devices d ON d.device_id = g.device_id
			  WHERE g.is_owner AND d.account_id IS NOT NULL
			 ON CONFLICT (vault_id) DO NOTHING`)
		if err != nil {
			return fmt.Errorf("backfill vault owners: %w", err)
		}
		rep.VaultOwnersBackfilled = int(tag.RowsAffected())

		tag, err = tx.Exec(ctx,
			`UPDATE sigil_subscriptions s
			    SET subject = d.account_id, updated_at = now()
			   FROM sigil_devices d
			  WHERE s.subject = d.device_id
			    AND d.account_id IS NOT NULL
			    AND NOT EXISTS (SELECT 1 FROM sigil_subscriptions s2 WHERE s2.subject = d.account_id)`)
		if err != nil {
			return fmt.Errorf("re-key subscriptions: %w", err)
		}
		rep.SubscriptionsRekeyed = int(tag.RowsAffected())
		return nil
	})
	if err != nil {
		return AdoptionReport{}, err
	}
	return rep, nil
}
