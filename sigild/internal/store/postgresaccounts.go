package store

// PostgresDeviceStore's implementation of the Accounts seam (Phase 52), backed
// by the tables created in migration 0005_accounts.sql (sigil_accounts,
// sigil_account_invites, sigil_vault_owners, plus sigil_devices.account_id).
//
// It reuses the SAME *pgxpool.Pool the op-log and the device registry already
// share — no second pool, no new dependency (pgx remains sigild's only direct
// require).
//
// The two guarantees that matter are enforced by the DATABASE, so they hold
// across CONCURRENT PROCESSES and not merely across goroutines:
//
//   - SINGLE-SUCCESS INVITES: consuming the invite, checking the inviter is
//     still active, enforcing the member cap and inserting the device are ONE
//     transaction. A conditional UPDATE ... RETURNING is the gate: exactly one
//     concurrent redemption can flip used_at, and if the subsequent device
//     INSERT fails the whole thing rolls back, leaving the invite usable.
//   - SINGLE-OWNER VAULTS: an INSERT ... ON CONFLICT (vault_id) DO NOTHING on
//     sigil_vault_owners, whose PRIMARY KEY makes at most one owner row possible.
//
// ZERO-KNOWLEDGE: auth metadata only. No vault plaintext, no ciphertext, no
// invite in the clear (an invite is stored ONLY as its SHA-256 hex digest), and
// no column here can hold an email, phone, name, password, session or key.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// The FK-violation helpers (pgForeignKeyViolation / isForeignKeyViolation) live
// in postgreskeysharing.go and are reused here to turn "that account does not
// exist" into ErrAccountNotFound rather than an opaque database error.

// GetAccount reads one account by ID, or ErrAccountNotFound.
func (s *PostgresDeviceStore) GetAccount(ctx context.Context, accountID string) (Account, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	var a Account
	err := s.pool.QueryRow(ctx,
		`SELECT account_id, created_at, created_by_device_id
		   FROM sigil_accounts WHERE account_id = $1`, accountID).
		Scan(&a.ID, &a.CreatedAt, &a.CreatedByDeviceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Account{}, ErrAccountNotFound
		}
		return Account{}, fmt.Errorf("get account: %w", err)
	}
	return a, nil
}

// CountActiveAccountDevices returns how many ACTIVE devices an account holds —
// the number the device cap is measured against. A revoked device is NOT a
// member for cap purposes, so revoking one frees its seat.
func (s *PostgresDeviceStore) CountActiveAccountDevices(ctx context.Context, accountID string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM sigil_devices
		  WHERE account_id = $1 AND status = 'active'`, accountID).Scan(&n); err != nil {
		return 0, fmt.Errorf("count active account devices: %w", err)
	}
	return n, nil
}

// ListAccountDevices returns every device in an account (active AND revoked),
// ordered by created_at then device_id (byte-wise; see ListDevices).
func (s *PostgresDeviceStore) ListAccountDevices(ctx context.Context, accountID string) ([]Device, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	rows, err := s.pool.Query(ctx,
		`SELECT device_id, account_id, public_key, label, status, created_at, revoked_at
		   FROM sigil_devices WHERE account_id = $1
		  ORDER BY created_at ASC, device_id COLLATE "C" ASC`, accountID)
	if err != nil {
		return nil, fmt.Errorf("list account devices: %w", err)
	}
	defer rows.Close()

	out := make([]Device, 0)
	for rows.Next() {
		d, err := scanDeviceRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate account devices: %w", err)
	}
	return out, nil
}

// CreateAccountWithFounder creates the account and its first device in ONE
// transaction, so a rejected device (duplicate ID or public key) leaves NO
// orphan account behind.
func (s *PostgresDeviceStore) CreateAccountWithFounder(ctx context.Context, a Account, d Device) error {
	if a.ID == "" {
		return errors.New("store: account id is required")
	}
	if d.AccountID != a.ID {
		return errors.New("store: founder device must carry the new account id")
	}
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx,
			`INSERT INTO sigil_accounts (account_id, created_at, created_by_device_id)
			 VALUES ($1, $2, $3) ON CONFLICT (account_id) DO NOTHING`,
			a.ID, a.CreatedAt, a.CreatedByDeviceID); err != nil {
			return err
		}
		return insertDeviceTx(ctx, tx, d)
	})
	if err != nil {
		if errors.Is(err, ErrDeviceExists) {
			return err
		}
		return fmt.Errorf("create account with founder: %w", err)
	}
	return nil
}

// insertDeviceTx inserts a device row inside an existing transaction, mapping a
// unique violation to ErrDeviceExists and an FK violation to ErrAccountNotFound.
func insertDeviceTx(ctx context.Context, tx pgx.Tx, d Device) error {
	if d.AccountID == "" {
		return errAccountRequired
	}
	_, err := tx.Exec(ctx,
		`INSERT INTO sigil_devices (device_id, account_id, public_key, label, status, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		d.ID, d.AccountID, d.PublicKey, d.Label, string(d.Status), d.CreatedAt)
	switch {
	case err == nil:
		return nil
	case isUniqueViolation(err):
		return ErrDeviceExists
	case isForeignKeyViolation(err):
		return ErrAccountNotFound
	default:
		return err
	}
}

// JoinAccountWithInvite redeems an invite and inserts the joining device in ONE
// transaction.
//
// The single conditional UPDATE below is the whole security argument: it flips
// used_at only while the invite is unused, unrevoked and unexpired, only when
// the pinned key (if any) matches, only while the INVITER is still active, and
// only while the account is under its member cap. Exactly one concurrent
// redemption can win it. A zero-row result is then classified by ONE read whose
// sole purpose is choosing the sentinel (and therefore the audit reason) — it
// authorizes nothing.
func (s *PostgresDeviceStore) JoinAccountWithInvite(ctx context.Context, inviteHash string, d Device, maxDevices int, now time.Time) (AccountInvite, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	var redeemed AccountInvite
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx,
			`UPDATE sigil_account_invites i
			    SET used_at = $2, used_by_device_id = $3
			  WHERE i.invite_hash = $1
			    AND i.used_at IS NULL
			    AND i.revoked_at IS NULL
			    AND i.expires_at > $2
			    AND (i.invitee_public_key IS NULL OR i.invitee_public_key = $4)
			    AND EXISTS (SELECT 1 FROM sigil_devices dv
			                 WHERE dv.device_id = i.created_by_device_id AND dv.status = 'active')
			    AND (SELECT count(*) FROM sigil_devices d2
			          WHERE d2.account_id = i.account_id AND d2.status = 'active') < $5
			 RETURNING i.account_id, i.invite_id, i.created_by_device_id,
			           i.created_at, i.expires_at`,
			inviteHash, now, d.ID, d.PublicKey, maxDevices).
			Scan(&redeemed.AccountID, &redeemed.InviteID, &redeemed.CreatedByDeviceID,
				&redeemed.CreatedAt, &redeemed.ExpiresAt)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return classifyInviteFailureTx(ctx, tx, inviteHash, d.PublicKey, maxDevices, now)
			}
			return err
		}
		redeemed.UsedAt = now
		redeemed.UsedByDeviceID = d.ID
		d.AccountID = redeemed.AccountID
		return insertDeviceTx(ctx, tx, d)
	})
	if err != nil {
		if isInviteSentinel(err) || errors.Is(err, ErrDeviceExists) || errors.Is(err, ErrAccountNotFound) {
			return AccountInvite{}, err
		}
		return AccountInvite{}, fmt.Errorf("join account with invite: %w", err)
	}
	// InviteHash is never selected, so the returned invite carries no digest.
	return redeemed, nil
}

// isInviteSentinel reports whether err is one of the invite/account sentinels
// that must pass through un-wrapped so callers can errors.Is them.
func isInviteSentinel(err error) bool {
	for _, sentinel := range []error{
		ErrInviteUnknown, ErrInviteRevoked, ErrInviteUsed, ErrInviteExpired,
		ErrInviteKeyMismatch, ErrInviterInactive, ErrAccountFull, ErrInviteLimit,
	} {
		if errors.Is(err, sentinel) {
			return true
		}
	}
	return false
}

// classifyInviteFailureTx explains WHY the conditional UPDATE matched no row.
// It is diagnosis only — the atomic UPDATE above is the sole authority, and this
// read grants nothing. The order mirrors the in-memory backend so both backends
// report the identical sentinel (and therefore the identical audit reason).
func classifyInviteFailureTx(ctx context.Context, tx pgx.Tx, inviteHash string, pub []byte, maxDevices int, now time.Time) error {
	var (
		accountID     string
		createdBy     string
		pinnedKey     []byte
		expiresAt     time.Time
		usedAt        *time.Time
		revokedAt     *time.Time
		inviterActive bool
		members       int
	)
	err := tx.QueryRow(ctx,
		`SELECT i.account_id, i.created_by_device_id, i.invitee_public_key, i.expires_at,
		        i.used_at, i.revoked_at,
		        COALESCE((SELECT dv.status = 'active' FROM sigil_devices dv
		                   WHERE dv.device_id = i.created_by_device_id), false),
		        (SELECT count(*) FROM sigil_devices d2
		          WHERE d2.account_id = i.account_id AND d2.status = 'active')
		   FROM sigil_account_invites i WHERE i.invite_hash = $1`, inviteHash).
		Scan(&accountID, &createdBy, &pinnedKey, &expiresAt, &usedAt, &revokedAt, &inviterActive, &members)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInviteUnknown
		}
		return err
	}
	switch {
	case revokedAt != nil:
		return ErrInviteRevoked
	case usedAt != nil:
		return ErrInviteUsed
	case !expiresAt.After(now):
		return ErrInviteExpired
	case len(pinnedKey) > 0 && !bytesEqual(pinnedKey, pub):
		return ErrInviteKeyMismatch
	case !inviterActive:
		return ErrInviterInactive
	case members >= maxDevices:
		return ErrAccountFull
	default:
		// Nothing observable explains it: report the safest (most restrictive)
		// verdict rather than inventing a success.
		return ErrInviteUnknown
	}
}

// bytesEqual is a plain byte comparison. It is NOT constant time on purpose:
// both operands here are PUBLIC key material, never a secret, and the invite
// digest lookup that precedes it is the credential check.
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// CreateAccountInvite records an invite by digest. The open-invite cap is
// enforced INSIDE the INSERT (an INSERT ... SELECT ... WHERE count < cap), so
// two concurrent mints cannot both slip past a separately-read count.
func (s *PostgresDeviceStore) CreateAccountInvite(ctx context.Context, inv AccountInvite, maxOpen int) error {
	if inv.InviteHash == "" || inv.InviteID == "" || inv.AccountID == "" {
		return errors.New("store: invite requires a digest, an id and an account")
	}
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	var pinned []byte
	if inv.Pinned() {
		pinned = inv.InviteePublicKey
	}
	tag, err := s.pool.Exec(ctx,
		`INSERT INTO sigil_account_invites
		     (invite_hash, invite_id, account_id, created_by_device_id, invitee_public_key,
		      created_at, expires_at)
		 SELECT $1, $2, $3, $4, $5, $6, $7
		  WHERE (SELECT count(*) FROM sigil_account_invites i
		          WHERE i.account_id = $3
		            AND i.used_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > $6) < $8`,
		inv.InviteHash, inv.InviteID, inv.AccountID, inv.CreatedByDeviceID, pinned,
		inv.CreatedAt, inv.ExpiresAt, maxOpen)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrInviteExists
		}
		if isForeignKeyViolation(err) {
			return ErrAccountNotFound
		}
		return fmt.Errorf("create account invite: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInviteLimit
	}
	return nil
}

// ListAccountInvites returns the account's OPEN invites, with invite_hash never
// selected at all — the redemption digest does not leave the database.
func (s *PostgresDeviceStore) ListAccountInvites(ctx context.Context, accountID string, now time.Time) ([]AccountInvite, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	rows, err := s.pool.Query(ctx,
		`SELECT invite_id, account_id, created_by_device_id, invitee_public_key,
		        created_at, expires_at
		   FROM sigil_account_invites
		  WHERE account_id = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > $2
		  ORDER BY created_at ASC, invite_id COLLATE "C" ASC`, accountID, now)
	if err != nil {
		return nil, fmt.Errorf("list account invites: %w", err)
	}
	defer rows.Close()

	out := make([]AccountInvite, 0)
	for rows.Next() {
		var inv AccountInvite
		if err := rows.Scan(&inv.InviteID, &inv.AccountID, &inv.CreatedByDeviceID,
			&inv.InviteePublicKey, &inv.CreatedAt, &inv.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan account invite: %w", err)
		}
		out = append(out, inv)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate account invites: %w", err)
	}
	return out, nil
}

// RevokeAccountInvite revokes an unredeemed invite. The WHERE clause is scoped
// by BOTH account_id and invite_id, so a foreign invite ID and a missing one
// produce the identical ErrInviteUnknown — there is no enumeration oracle.
func (s *PostgresDeviceStore) RevokeAccountInvite(ctx context.Context, accountID, inviteID string, at time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	tag, err := s.pool.Exec(ctx,
		`UPDATE sigil_account_invites SET revoked_at = $3
		  WHERE account_id = $1 AND invite_id = $2
		    AND used_at IS NULL AND revoked_at IS NULL`,
		accountID, inviteID, at)
	if err != nil {
		return fmt.Errorf("revoke account invite: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInviteUnknown
	}
	return nil
}

// ClaimVault atomically claims an unowned vault for an ACCOUNT and writes the
// matching per-device is_owner grant in the SAME transaction (the dual write:
// sigil_vault_owners is the authority, the grant row is the per-device view).
// The PRIMARY KEY on vault_id is what makes the claim single-winner across
// processes; ON CONFLICT DO NOTHING turns a lost race into rowsAffected == 0
// rather than an error, and the loser is then told WHO won.
func (s *PostgresDeviceStore) ClaimVault(ctx context.Context, vaultID, accountID, deviceID string, at time.Time) (bool, VaultOwner, error) {
	if accountID == "" {
		return false, VaultOwner{}, errors.New("store: claim requires an account id")
	}
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	var (
		claimed bool
		owner   VaultOwner
	)
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// RECONCILE FIRST. A vault claimed by a pre-0005 binary (a rolling deploy,
		// or the rollback window) has an is_owner GRANT and no owner row: 0005's
		// ownership backfill ran once and cannot see a claim made after it. Its
		// owner is knowable — the account of the device holding the grant — so
		// adopt it. Claiming for the caller instead would insert a SECOND is_owner
		// grant, which sigil_device_grants_one_owner rejects; the transaction would
		// roll back and a legitimately granted writer would get an opaque 500.
		reconciled, owned, rerr := reconcileOrphanOwnerTx(ctx, tx, vaultID, at)
		if rerr != nil {
			return rerr
		}
		if owned {
			owner = reconciled
			claimed = false
			return nil
		}

		tag, err := tx.Exec(ctx,
			`INSERT INTO sigil_vault_owners (vault_id, account_id, claimed_by_device_id, claimed_at)
			 VALUES ($1, $2, $3, $4) ON CONFLICT (vault_id) DO NOTHING`,
			vaultID, accountID, deviceID, at)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 1 {
			if _, err := tx.Exec(ctx,
				`INSERT INTO sigil_device_grants (vault_id, device_id, permission, is_owner, created_at)
				 VALUES ($1, $2, $3, true, $4)
				 ON CONFLICT (vault_id, device_id)
				 DO UPDATE SET permission = EXCLUDED.permission, is_owner = true`,
				vaultID, deviceID, string(PermWrite), at); err != nil {
				return err
			}
			claimed = true
			owner = VaultOwner{
				VaultID: vaultID, AccountID: accountID,
				ClaimedByDeviceID: deviceID, ClaimedAt: at,
			}
			return nil
		}
		return tx.QueryRow(ctx,
			`SELECT vault_id, account_id, claimed_by_device_id, claimed_at
			   FROM sigil_vault_owners WHERE vault_id = $1`, vaultID).
			Scan(&owner.VaultID, &owner.AccountID, &owner.ClaimedByDeviceID, &owner.ClaimedAt)
	})
	if err != nil {
		if errors.Is(err, ErrVaultOwnerUnresolved) {
			// Pass the sentinel through un-wrapped so the API layer can name the
			// state in the audit log instead of reporting a store fault.
			return false, VaultOwner{}, err
		}
		return false, VaultOwner{}, fmt.Errorf("claim vault: %w", err)
	}
	return claimed, owner, nil
}

// reconcileOrphanOwnerTx repairs the ORPHANED-OWNER state inside an existing
// transaction: a vault with a legacy is_owner GRANT but no sigil_vault_owners
// row. It returns owned=true (and the now-recorded owner) when it reconciled or
// when another transaction had already recorded an owner, owned=false when the
// vault is genuinely unclaimed, and ErrVaultOwnerUnresolved when the grant names
// a device that cannot be resolved to an account.
//
// It writes only sigil_vault_owners: NOT ONE GRANT ROW is created, rewritten or
// re-permissioned, so the grants listing stays byte-identical and no device
// gains access it did not already hold.
func reconcileOrphanOwnerTx(ctx context.Context, tx pgx.Tx, vaultID string, at time.Time) (VaultOwner, bool, error) {
	var (
		grantDevice  string
		grantAccount *string
	)
	err := tx.QueryRow(ctx,
		`SELECT g.device_id, d.account_id
		   FROM sigil_device_grants g
		   LEFT JOIN sigil_devices d ON d.device_id = g.device_id
		  WHERE g.vault_id = $1 AND g.is_owner
		  ORDER BY g.device_id COLLATE "C" ASC
		  LIMIT 1`, vaultID).Scan(&grantDevice, &grantAccount)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// No legacy owner grant: the vault is genuinely unclaimed.
		return VaultOwner{}, false, nil
	case err != nil:
		return VaultOwner{}, false, fmt.Errorf("read owner grant: %w", err)
	}
	if grantAccount == nil || *grantAccount == "" {
		return VaultOwner{}, false, ErrVaultOwnerUnresolved
	}

	if _, err := tx.Exec(ctx,
		`INSERT INTO sigil_vault_owners (vault_id, account_id, claimed_by_device_id, claimed_at)
		 VALUES ($1, $2, $3, $4) ON CONFLICT (vault_id) DO NOTHING`,
		vaultID, *grantAccount, grantDevice, at); err != nil {
		return VaultOwner{}, false, fmt.Errorf("adopt orphan vault owner: %w", err)
	}

	var owner VaultOwner
	if err := tx.QueryRow(ctx,
		`SELECT vault_id, account_id, claimed_by_device_id, claimed_at
		   FROM sigil_vault_owners WHERE vault_id = $1`, vaultID).
		Scan(&owner.VaultID, &owner.AccountID, &owner.ClaimedByDeviceID, &owner.ClaimedAt); err != nil {
		return VaultOwner{}, false, fmt.Errorf("read adopted vault owner: %w", err)
	}
	return owner, true, nil
}

// GetVaultOwner reads a vault's owning account, or ErrVaultOwnerNotFound.
func (s *PostgresDeviceStore) GetVaultOwner(ctx context.Context, vaultID string) (VaultOwner, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	var owner VaultOwner
	err := s.pool.QueryRow(ctx,
		`SELECT vault_id, account_id, claimed_by_device_id, claimed_at
		   FROM sigil_vault_owners WHERE vault_id = $1`, vaultID).
		Scan(&owner.VaultID, &owner.AccountID, &owner.ClaimedByDeviceID, &owner.ClaimedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return VaultOwner{}, ErrVaultOwnerNotFound
		}
		return VaultOwner{}, fmt.Errorf("get vault owner: %w", err)
	}
	return owner, nil
}
