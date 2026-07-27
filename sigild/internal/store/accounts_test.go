package store

// Tests for the account model (Phase 52).
//
// The bulk lives in runAccountsSuite, a BACKEND-AGNOSTIC conformance suite hung
// off runDeviceStoreSuite, so MemDeviceStore and PostgresDeviceStore are held to
// byte-for-byte the same contract — including the two atomic guarantees
// (single-SUCCESS invites, single-owner vault claims), which for Postgres are
// enforced by the database and therefore hold across processes.

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestInvite builds an unsaved invite for an account, minted by a device.
func newTestInvite(t *testing.T, accountID, byDeviceID string, ttl time.Duration) AccountInvite {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Millisecond)
	return AccountInvite{
		InviteHash:        "invhash-" + uniqueTag(),
		InviteID:          "inv_" + uniqueTag(),
		AccountID:         accountID,
		CreatedByDeviceID: byDeviceID,
		CreatedAt:         now,
		ExpiresAt:         now.Add(ttl),
	}
}

// joinWithInvite redeems inv for a fresh device and returns that device.
func joinWithInvite(t *testing.T, s DeviceStore, inv AccountInvite, label string, maxDevices int) (Device, error) {
	t.Helper()
	joiner := newTestDevice(t, label)
	_, err := s.JoinAccountWithInvite(context.Background(), inv.InviteHash, joiner, maxDevices, time.Now().UTC())
	return joiner, err
}

// putOwnerGrantDirect writes a LEGACY is_owner grant with NO matching
// sigil_vault_owners row — the state a PRE-0005 binary leaves behind when it
// claims a vault against an already-migrated database.
//
// It goes STRAIGHT AT THE BACKEND on purpose. No current API path can produce
// this state (ClaimVault writes both rows in one atomic operation), and a
// regression test for data drift has to be able to construct the drift.
func putOwnerGrantDirect(ctx context.Context, s DeviceStore, vaultID, deviceID string, at time.Time) error {
	switch st := s.(type) {
	case *MemDeviceStore:
		st.mu.Lock()
		defer st.mu.Unlock()
		if st.grants[vaultID] == nil {
			st.grants[vaultID] = make(map[string]Grant)
		}
		st.grants[vaultID][deviceID] = Grant{
			VaultID: vaultID, DeviceID: deviceID, Perm: PermWrite, Owner: true, CreatedAt: at,
		}
		return nil
	case *PostgresDeviceStore:
		_, err := st.pool.Exec(ctx,
			`INSERT INTO sigil_device_grants (vault_id, device_id, permission, is_owner, created_at)
			 VALUES ($1, $2, 'write', true, $3)`, vaultID, deviceID, at)
		return err
	default:
		return fmt.Errorf("putOwnerGrantDirect: unsupported store %T", s)
	}
}

func runAccountsSuite(t *testing.T, newStore func(*testing.T) DeviceStore) {
	t.Helper()
	ctx := context.Background()

	// (1) CreateAccountWithFounder is ATOMIC: account and device land together,
	// and a rejected device leaves NO orphan account.
	t.Run("CreateAccountWithFounderIsAtomic", func(t *testing.T) {
		s := newStore(t)
		founder := newTestDevice(t, "founder")
		if err := createDevice(ctx, s, founder); err != nil {
			t.Fatalf("CreateAccountWithFounder: %v", err)
		}

		account, err := s.GetAccount(ctx, founder.AccountID)
		if err != nil {
			t.Fatalf("GetAccount: %v", err)
		}
		if account.ID != founder.AccountID || account.CreatedByDeviceID != founder.ID {
			t.Fatalf("account = %+v, want id=%s created_by=%s", account, founder.AccountID, founder.ID)
		}
		stored, err := s.GetDevice(ctx, founder.ID)
		if err != nil {
			t.Fatalf("GetDevice: %v", err)
		}
		if stored.AccountID != founder.AccountID {
			t.Fatalf("device account = %q, want %q", stored.AccountID, founder.AccountID)
		}

		// A duplicate PUBLIC KEY is rejected AND leaves no orphan account.
		dup := newTestDevice(t, "dup")
		dup.PublicKey = founder.PublicKey
		if err := createDevice(ctx, s, dup); !errors.Is(err, ErrDeviceExists) {
			t.Fatalf("duplicate-key founder err = %v, want ErrDeviceExists", err)
		}
		if _, err := s.GetAccount(ctx, dup.AccountID); !errors.Is(err, ErrAccountNotFound) {
			t.Fatalf("a rejected founder left an ORPHAN account %s (err = %v)", dup.AccountID, err)
		}
	})

	// (2) A device with no account cannot exist: the invariant fails closed at
	// creation, so no authorization path ever has to guess.
	t.Run("CreateDeviceRejectsEmptyAccount", func(t *testing.T) {
		s := newStore(t)
		d := newTestDevice(t, "accountless")
		d.AccountID = ""
		if err := s.CreateDevice(ctx, d); err == nil {
			t.Fatal("CreateDevice accepted a device with no account id")
		}
		if _, err := s.GetDevice(ctx, d.ID); !errors.Is(err, ErrDeviceNotFound) {
			t.Fatalf("an accountless device was stored anyway (err = %v)", err)
		}
	})

	// (3) Invite lifecycle, and the digest NEVER leaves the store.
	t.Run("InviteLifecycleAndDigestNeverLeaves", func(t *testing.T) {
		s := newStore(t)
		founder := newTestDevice(t, "founder")
		if err := createDevice(ctx, s, founder); err != nil {
			t.Fatalf("createDevice: %v", err)
		}

		inv := newTestInvite(t, founder.AccountID, founder.ID, time.Hour)
		if err := s.CreateAccountInvite(ctx, inv, 5); err != nil {
			t.Fatalf("CreateAccountInvite: %v", err)
		}

		listed, err := s.ListAccountInvites(ctx, founder.AccountID, time.Now().UTC())
		if err != nil {
			t.Fatalf("ListAccountInvites: %v", err)
		}
		if len(listed) != 1 || listed[0].InviteID != inv.InviteID {
			t.Fatalf("listed = %+v, want the one minted invite", listed)
		}
		for _, got := range listed {
			if got.InviteHash != "" {
				t.Fatalf("ListAccountInvites returned the redemption DIGEST %q", got.InviteHash)
			}
		}

		if err := s.RevokeAccountInvite(ctx, founder.AccountID, inv.InviteID, time.Now().UTC()); err != nil {
			t.Fatalf("RevokeAccountInvite: %v", err)
		}
		if _, err := joinWithInvite(t, s, inv, "late", 10); !errors.Is(err, ErrInviteRevoked) {
			t.Fatalf("join with a revoked invite = %v, want ErrInviteRevoked", err)
		}
		// Revoking twice is indistinguishable from revoking a foreign invite.
		if err := s.RevokeAccountInvite(ctx, founder.AccountID, inv.InviteID, time.Now().UTC()); !errors.Is(err, ErrInviteUnknown) {
			t.Fatalf("second revoke = %v, want ErrInviteUnknown", err)
		}
		if err := s.RevokeAccountInvite(ctx, founder.AccountID, "inv_nope-"+uniqueTag(), time.Now().UTC()); !errors.Is(err, ErrInviteUnknown) {
			t.Fatalf("revoke of an unknown invite = %v, want ErrInviteUnknown", err)
		}
	})

	// (4) THE SINGLE-SUCCESS GUARANTEE: N concurrent redemptions of one invite
	// create EXACTLY ONE device.
	t.Run("ConcurrentJoinSingleWinner", func(t *testing.T) {
		s := newStore(t)
		founder := newTestDevice(t, "founder")
		if err := createDevice(ctx, s, founder); err != nil {
			t.Fatalf("createDevice: %v", err)
		}
		inv := newTestInvite(t, founder.AccountID, founder.ID, time.Hour)
		if err := s.CreateAccountInvite(ctx, inv, 5); err != nil {
			t.Fatalf("CreateAccountInvite: %v", err)
		}

		const workers = 8
		var wins, used int64
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				joiner := newTestDevice(t, fmt.Sprintf("racer-%d", i))
				_, err := s.JoinAccountWithInvite(ctx, inv.InviteHash, joiner, 100, time.Now().UTC())
				switch {
				case err == nil:
					atomic.AddInt64(&wins, 1)
				case errors.Is(err, ErrInviteUsed):
					atomic.AddInt64(&used, 1)
				default:
					t.Errorf("JoinAccountWithInvite: %v", err)
				}
			}(i)
		}
		wg.Wait()

		if wins != 1 {
			t.Fatalf("concurrent joins succeeded %d times, want exactly 1", wins)
		}
		if used != workers-1 {
			t.Fatalf("concurrent joins rejected %d times, want %d", used, workers-1)
		}
		members, err := s.ListAccountDevices(ctx, founder.AccountID)
		if err != nil {
			t.Fatalf("ListAccountDevices: %v", err)
		}
		if len(members) != 2 {
			t.Fatalf("account has %d devices, want 2 (founder + one joiner)", len(members))
		}
	})

	// (5) Every rejection path, each without consuming anything.
	t.Run("JoinRejections", func(t *testing.T) {
		s := newStore(t)
		founder := newTestDevice(t, "founder")
		if err := createDevice(ctx, s, founder); err != nil {
			t.Fatalf("createDevice: %v", err)
		}

		t.Run("unknown", func(t *testing.T) {
			ghost := AccountInvite{InviteHash: "nosuch-" + uniqueTag()}
			if _, err := joinWithInvite(t, s, ghost, "ghost", 10); !errors.Is(err, ErrInviteUnknown) {
				t.Fatalf("err = %v, want ErrInviteUnknown", err)
			}
		})

		t.Run("used", func(t *testing.T) {
			inv := newTestInvite(t, founder.AccountID, founder.ID, time.Hour)
			if err := s.CreateAccountInvite(ctx, inv, 50); err != nil {
				t.Fatalf("CreateAccountInvite: %v", err)
			}
			if _, err := joinWithInvite(t, s, inv, "first", 50); err != nil {
				t.Fatalf("first join: %v", err)
			}
			if _, err := joinWithInvite(t, s, inv, "second", 50); !errors.Is(err, ErrInviteUsed) {
				t.Fatalf("err = %v, want ErrInviteUsed", err)
			}
		})

		t.Run("expired", func(t *testing.T) {
			inv := newTestInvite(t, founder.AccountID, founder.ID, -time.Minute)
			if err := s.CreateAccountInvite(ctx, inv, 50); err != nil {
				t.Fatalf("CreateAccountInvite: %v", err)
			}
			if _, err := joinWithInvite(t, s, inv, "late", 50); !errors.Is(err, ErrInviteExpired) {
				t.Fatalf("err = %v, want ErrInviteExpired", err)
			}
		})

		t.Run("pinned_key_mismatch", func(t *testing.T) {
			inv := newTestInvite(t, founder.AccountID, founder.ID, time.Hour)
			inv.InviteePublicKey = testPubKey(t)
			if err := s.CreateAccountInvite(ctx, inv, 50); err != nil {
				t.Fatalf("CreateAccountInvite: %v", err)
			}
			if _, err := joinWithInvite(t, s, inv, "wrong-key", 50); !errors.Is(err, ErrInviteKeyMismatch) {
				t.Fatalf("err = %v, want ErrInviteKeyMismatch", err)
			}
			// The RIGHT key still works: the invite was not consumed.
			pinned := newTestDevice(t, "pinned")
			pinned.PublicKey = inv.InviteePublicKey
			if _, err := s.JoinAccountWithInvite(ctx, inv.InviteHash, pinned, 50, time.Now().UTC()); err != nil {
				t.Fatalf("pinned join with the right key: %v", err)
			}
		})

		t.Run("inviter_revoked", func(t *testing.T) {
			inviter := newTestDevice(t, "soon-revoked")
			if err := createDevice(ctx, s, inviter); err != nil {
				t.Fatalf("createDevice: %v", err)
			}
			inv := newTestInvite(t, inviter.AccountID, inviter.ID, time.Hour)
			if err := s.CreateAccountInvite(ctx, inv, 50); err != nil {
				t.Fatalf("CreateAccountInvite: %v", err)
			}
			if err := s.RevokeDevice(ctx, inviter.ID, time.Now().UTC()); err != nil {
				t.Fatalf("RevokeDevice: %v", err)
			}
			if _, err := joinWithInvite(t, s, inv, "orphan", 50); !errors.Is(err, ErrInviterInactive) {
				t.Fatalf("err = %v, want ErrInviterInactive", err)
			}
		})

		t.Run("account_full", func(t *testing.T) {
			solo := newTestDevice(t, "solo")
			if err := createDevice(ctx, s, solo); err != nil {
				t.Fatalf("createDevice: %v", err)
			}
			inv := newTestInvite(t, solo.AccountID, solo.ID, time.Hour)
			if err := s.CreateAccountInvite(ctx, inv, 50); err != nil {
				t.Fatalf("CreateAccountInvite: %v", err)
			}
			// The account already holds 1 device, so a cap of 1 is full.
			if _, err := joinWithInvite(t, s, inv, "overflow", 1); !errors.Is(err, ErrAccountFull) {
				t.Fatalf("err = %v, want ErrAccountFull", err)
			}
		})
	})

	// (6) SINGLE-SUCCESS, not single-attempt: a join that fails at the cap (or at
	// the device insert) leaves the invite USABLE. Contrast the OPERATOR token
	// path, which stays deliberately single-ATTEMPT.
	t.Run("FailedJoinLeavesInviteUsable", func(t *testing.T) {
		s := newStore(t)
		founder := newTestDevice(t, "founder")
		if err := createDevice(ctx, s, founder); err != nil {
			t.Fatalf("createDevice: %v", err)
		}
		inv := newTestInvite(t, founder.AccountID, founder.ID, time.Hour)
		if err := s.CreateAccountInvite(ctx, inv, 5); err != nil {
			t.Fatalf("CreateAccountInvite: %v", err)
		}

		// Blocked by the cap...
		if _, err := joinWithInvite(t, s, inv, "capped", 1); !errors.Is(err, ErrAccountFull) {
			t.Fatalf("capped join = %v, want ErrAccountFull", err)
		}
		// ...and blocked by a duplicate public key...
		clash := newTestDevice(t, "clash")
		clash.PublicKey = founder.PublicKey
		if _, err := s.JoinAccountWithInvite(ctx, inv.InviteHash, clash, 10, time.Now().UTC()); !errors.Is(err, ErrDeviceExists) {
			t.Fatalf("duplicate-key join = %v, want ErrDeviceExists", err)
		}
		// ...yet the invite is STILL redeemable.
		joiner, err := joinWithInvite(t, s, inv, "finally", 10)
		if err != nil {
			t.Fatalf("retry after two failures: %v", err)
		}
		stored, err := s.GetDevice(ctx, joiner.ID)
		if err != nil {
			t.Fatalf("GetDevice: %v", err)
		}
		if stored.AccountID != founder.AccountID {
			t.Fatalf("joiner account = %q, want the inviter's %q", stored.AccountID, founder.AccountID)
		}

		// The OPERATOR token contract is unchanged: single-ATTEMPT.
		tokenHash := "optoken-" + uniqueTag()
		if err := s.RegisterEnrollmentToken(ctx, tokenHash, time.Now().UTC(), time.Time{}); err != nil {
			t.Fatalf("RegisterEnrollmentToken: %v", err)
		}
		if err := s.ConsumeEnrollmentToken(ctx, tokenHash, "dev_attempt1", time.Now().UTC()); err != nil {
			t.Fatalf("ConsumeEnrollmentToken: %v", err)
		}
		if err := s.ConsumeEnrollmentToken(ctx, tokenHash, "dev_attempt2", time.Now().UTC()); !errors.Is(err, ErrEnrollTokenUsed) {
			t.Fatalf("second consume = %v, want ErrEnrollTokenUsed (operator tokens stay single-ATTEMPT)", err)
		}
	})

	// (7) The OPEN-invite cap counts only OPEN invites.
	t.Run("OpenInviteCap", func(t *testing.T) {
		s := newStore(t)
		founder := newTestDevice(t, "founder")
		if err := createDevice(ctx, s, founder); err != nil {
			t.Fatalf("createDevice: %v", err)
		}
		const maxOpen = 3
		open := make([]AccountInvite, 0, maxOpen)
		for i := 0; i < maxOpen; i++ {
			inv := newTestInvite(t, founder.AccountID, founder.ID, time.Hour)
			if err := s.CreateAccountInvite(ctx, inv, maxOpen); err != nil {
				t.Fatalf("CreateAccountInvite(%d): %v", i, err)
			}
			open = append(open, inv)
		}
		over := newTestInvite(t, founder.AccountID, founder.ID, time.Hour)
		if err := s.CreateAccountInvite(ctx, over, maxOpen); !errors.Is(err, ErrInviteLimit) {
			t.Fatalf("over-cap mint = %v, want ErrInviteLimit", err)
		}

		// Revoking one frees a slot: revoked invites do NOT count.
		if err := s.RevokeAccountInvite(ctx, founder.AccountID, open[0].InviteID, time.Now().UTC()); err != nil {
			t.Fatalf("RevokeAccountInvite: %v", err)
		}
		if err := s.CreateAccountInvite(ctx, over, maxOpen); err != nil {
			t.Fatalf("mint after revoke: %v", err)
		}

		// Neither do USED ones.
		if _, err := joinWithInvite(t, s, open[1], "joiner", 50); err != nil {
			t.Fatalf("join: %v", err)
		}
		another := newTestInvite(t, founder.AccountID, founder.ID, time.Hour)
		if err := s.CreateAccountInvite(ctx, another, maxOpen); err != nil {
			t.Fatalf("mint after redemption: %v", err)
		}

		// Nor EXPIRED ones: free a slot, spend it on an already-expired invite,
		// and the slot must still be free.
		if err := s.RevokeAccountInvite(ctx, founder.AccountID, over.InviteID, time.Now().UTC()); err != nil {
			t.Fatalf("RevokeAccountInvite: %v", err)
		}
		expired := newTestInvite(t, founder.AccountID, founder.ID, -time.Hour)
		if err := s.CreateAccountInvite(ctx, expired, maxOpen); err != nil {
			t.Fatalf("mint expired: %v", err)
		}
		refill := newTestInvite(t, founder.AccountID, founder.ID, time.Hour)
		if err := s.CreateAccountInvite(ctx, refill, maxOpen); err != nil {
			t.Fatalf("mint after an expired invite: %v (expired invites must not consume the cap)", err)
		}

		listed, err := s.ListAccountInvites(ctx, founder.AccountID, time.Now().UTC())
		if err != nil {
			t.Fatalf("ListAccountInvites: %v", err)
		}
		if len(listed) != maxOpen {
			t.Fatalf("open invites = %d, want %d (used/revoked/expired must not be listed)", len(listed), maxOpen)
		}
	})

	// (8) ClaimVault: single owner, the LOSER learns who won, and the is_owner
	// grant is written in the SAME call (the dual write).
	t.Run("ClaimVaultOwnershipIsAccountScoped", func(t *testing.T) {
		s := newStore(t)
		vault := "vault-acct-" + uniqueTag()
		a := newTestDevice(t, "A")
		b := newTestDevice(t, "B")
		for _, d := range []Device{a, b} {
			if err := createDevice(ctx, s, d); err != nil {
				t.Fatalf("createDevice: %v", err)
			}
		}
		at := time.Now().UTC().Truncate(time.Millisecond)

		if _, err := s.GetVaultOwner(ctx, vault); !errors.Is(err, ErrVaultOwnerNotFound) {
			t.Fatalf("GetVaultOwner(unclaimed) = %v, want ErrVaultOwnerNotFound", err)
		}

		claimed, owner, err := s.ClaimVault(ctx, vault, a.AccountID, a.ID, at)
		if err != nil || !claimed {
			t.Fatalf("first ClaimVault = (%v, %+v, %v), want claimed", claimed, owner, err)
		}
		if owner.AccountID != a.AccountID || owner.ClaimedByDeviceID != a.ID {
			t.Fatalf("owner = %+v, want account=%s device=%s", owner, a.AccountID, a.ID)
		}
		// The per-device VIEW was written by the same call.
		g, err := s.GetGrant(ctx, vault, a.ID)
		if err != nil {
			t.Fatalf("GetGrant(claimer): %v", err)
		}
		if !g.Owner || g.Perm != PermWrite {
			t.Fatalf("claimer grant = %+v, want owner=true perm=write", g)
		}

		// Another account loses, and is told WHO won.
		claimed, owner, err = s.ClaimVault(ctx, vault, b.AccountID, b.ID, at)
		if err != nil {
			t.Fatalf("second ClaimVault: %v", err)
		}
		if claimed {
			t.Fatal("second ClaimVault claimed an owned vault")
		}
		if owner.AccountID != a.AccountID {
			t.Fatalf("loser was told owner %q, want the winner %q", owner.AccountID, a.AccountID)
		}
		if _, err := s.GetGrant(ctx, vault, b.ID); !errors.Is(err, ErrGrantNotFound) {
			t.Fatalf("a lost claim wrote a grant for the loser (err = %v)", err)
		}
	})

	// (9) IMMUTABILITY: no exported mutator changes a device's account.
	t.Run("AccountIDIsImmutable", func(t *testing.T) {
		s := newStore(t)
		vault := "vault-immut-" + uniqueTag()
		d := newTestDevice(t, "subject")
		peer := newTestDevice(t, "peer")
		for _, dev := range []Device{d, peer} {
			if err := createDevice(ctx, s, dev); err != nil {
				t.Fatalf("createDevice: %v", err)
			}
		}
		at := time.Now().UTC()
		want := d.AccountID

		if _, _, err := s.ClaimVault(ctx, vault, d.AccountID, d.ID, at); err != nil {
			t.Fatalf("ClaimVault: %v", err)
		}
		if err := s.PutGrant(ctx, vault, peer.ID, PermRead, at); err != nil {
			t.Fatalf("PutGrant: %v", err)
		}
		if err := s.PutDeviceHybridKey(ctx, testHybridKey(t, d.ID)); err != nil {
			t.Fatalf("PutDeviceHybridKey: %v", err)
		}
		env := KeyEnvelope{VaultID: vault, RecipientDeviceID: d.ID, SenderDeviceID: peer.ID,
			Blob: testEnvelopeBlob(t, 64), CreatedAt: at}
		if err := s.PutKeyEnvelope(ctx, env); err != nil {
			t.Fatalf("PutKeyEnvelope: %v", err)
		}
		if err := s.DeleteKeyEnvelope(ctx, vault, d.ID); err != nil {
			t.Fatalf("DeleteKeyEnvelope: %v", err)
		}
		inv := newTestInvite(t, d.AccountID, d.ID, time.Hour)
		if err := s.CreateAccountInvite(ctx, inv, 5); err != nil {
			t.Fatalf("CreateAccountInvite: %v", err)
		}
		if err := s.RevokeAccountInvite(ctx, d.AccountID, inv.InviteID, at); err != nil {
			t.Fatalf("RevokeAccountInvite: %v", err)
		}
		if err := s.RevokeDevice(ctx, d.ID, at); err != nil {
			t.Fatalf("RevokeDevice: %v", err)
		}

		got, err := s.GetDevice(ctx, d.ID)
		if err != nil {
			t.Fatalf("GetDevice: %v", err)
		}
		if got.AccountID != want {
			t.Fatalf("account changed to %q after mutations, want %q — membership is IMMUTABLE", got.AccountID, want)
		}
	})

	// (10) A SIBLING (same account, no grant) sees the account own the vault.
	t.Run("SiblingInheritsOwnership", func(t *testing.T) {
		s := newStore(t)
		vault := "vault-sib-" + uniqueTag()
		founder := newTestDevice(t, "founder")
		if err := createDevice(ctx, s, founder); err != nil {
			t.Fatalf("createDevice: %v", err)
		}
		sibling := newTestDevice(t, "sibling")
		if err := joinAccount(ctx, s, founder.AccountID, sibling); err != nil {
			t.Fatalf("joinAccount: %v", err)
		}
		at := time.Now().UTC()
		if _, _, err := s.ClaimVault(ctx, vault, founder.AccountID, founder.ID, at); err != nil {
			t.Fatalf("ClaimVault: %v", err)
		}

		owner, err := s.GetVaultOwner(ctx, vault)
		if err != nil {
			t.Fatalf("GetVaultOwner: %v", err)
		}
		stored, err := s.GetDevice(ctx, sibling.ID)
		if err != nil {
			t.Fatalf("GetDevice: %v", err)
		}
		if owner.AccountID != stored.AccountID {
			t.Fatalf("sibling account %q does not own the vault (owner %q)", stored.AccountID, owner.AccountID)
		}
		// ...and holds NO grant row, which is the whole point.
		if _, err := s.GetGrant(ctx, vault, sibling.ID); !errors.Is(err, ErrGrantNotFound) {
			t.Fatalf("sibling unexpectedly holds a grant (err = %v)", err)
		}

		// Revoking the CLAIMER does not change who owns the vault.
		if err := s.RevokeDevice(ctx, founder.ID, at); err != nil {
			t.Fatalf("RevokeDevice: %v", err)
		}
		after, err := s.GetVaultOwner(ctx, vault)
		if err != nil {
			t.Fatalf("GetVaultOwner after revoke: %v", err)
		}
		if after.AccountID != owner.AccountID {
			t.Fatalf("revoking the claimer ORPHANED the vault: owner %q -> %q", owner.AccountID, after.AccountID)
		}
	})

	// (11) THE CAP IS ON CONCURRENT DEVICES, NOT LIFETIME ENROLLMENTS. Revoking a
	// device FREES its seat; the cap still holds against ACTIVE devices.
	//
	// This is the difference between a limit and a trap. Every remedy the account
	// model prescribes — a compromised device, a device that joined the wrong
	// account, a lost phone — is "revoke and re-enroll". If a revoked row kept its
	// seat, an account that replaced its devices N times could never enroll
	// another, and NOTHING anywhere could free one: when its surviving devices
	// died the account, its vaults and its subscription would be permanently
	// unreachable.
	t.Run("RevokedDeviceFreesItsSeat", func(t *testing.T) {
		s := newStore(t)
		founder := newTestDevice(t, "founder")
		if err := createDevice(ctx, s, founder); err != nil {
			t.Fatalf("createDevice: %v", err)
		}
		const maxDevices = 2

		countActive := func(where string) int {
			t.Helper()
			n, err := s.CountActiveAccountDevices(ctx, founder.AccountID)
			if err != nil {
				t.Fatalf("CountActiveAccountDevices (%s): %v", where, err)
			}
			return n
		}
		joinOne := func(label string) (Device, error) {
			t.Helper()
			inv := newTestInvite(t, founder.AccountID, founder.ID, time.Hour)
			if err := s.CreateAccountInvite(ctx, inv, 50); err != nil {
				t.Fatalf("CreateAccountInvite: %v", err)
			}
			return joinWithInvite(t, s, inv, label, maxDevices)
		}

		if got := countActive("start"); got != 1 {
			t.Fatalf("active members = %d, want 1", got)
		}
		second, err := joinOne("second")
		if err != nil {
			t.Fatalf("second join: %v", err)
		}
		if got := countActive("full"); got != maxDevices {
			t.Fatalf("active members = %d, want %d", got, maxDevices)
		}
		// THE CAP STILL HOLDS against active devices.
		if _, err := joinOne("overflow"); !errors.Is(err, ErrAccountFull) {
			t.Fatalf("join at the cap = %v, want ErrAccountFull", err)
		}

		// Revoke one, and the seat comes BACK.
		if err := s.RevokeDevice(ctx, second.ID, time.Now().UTC()); err != nil {
			t.Fatalf("RevokeDevice: %v", err)
		}
		if got := countActive("after revoke"); got != 1 {
			t.Fatalf("active members after revoke = %d, want 1 (a revoked device still holds a seat)", got)
		}
		replacement, err := joinOne("replacement")
		if err != nil {
			t.Fatalf("join after revoke = %v, want success (the revoked device's seat was never freed)", err)
		}
		if got := countActive("after replacement"); got != maxDevices {
			t.Fatalf("active members = %d, want %d", got, maxDevices)
		}
		// The revoked row is still LISTED — history is kept, it just does not
		// count against the limit.
		all, err := s.ListAccountDevices(ctx, founder.AccountID)
		if err != nil {
			t.Fatalf("ListAccountDevices: %v", err)
		}
		if len(all) != 3 {
			t.Fatalf("ListAccountDevices = %d rows, want 3 (founder + revoked + replacement)", len(all))
		}
		seen := map[string]DeviceStatus{}
		for _, d := range all {
			seen[d.ID] = d.Status
		}
		if seen[second.ID] != DeviceRevoked {
			t.Fatalf("revoked device status = %q, want revoked", seen[second.ID])
		}
		if seen[replacement.ID] != DeviceActive {
			t.Fatalf("replacement status = %q, want active", seen[replacement.ID])
		}
	})

	// (12) THE ORPHANED-OWNER STATE is reconciled, never faulted.
	//
	// A vault claimed by a PRE-0005 binary has a legacy is_owner GRANT and no
	// owner row (0005's ownership backfill runs once; a claim made after it is
	// invisible to it). Rolling forward, the next write used to reach ClaimVault,
	// which inserted the owner row and then a SECOND is_owner grant that collided
	// with sigil_device_grants_one_owner — the transaction rolled back and a
	// legitimately granted writer got an opaque 500.
	//
	// ClaimVault now ADOPTS the grant holder's account instead: the owner is
	// knowable, so it is recorded, and the caller is authorized exactly as it
	// would be against any pre-owned vault.
	t.Run("OrphanOwnerGrantIsReconciled", func(t *testing.T) {
		s := newStore(t)
		vault := "vault-orphan-" + uniqueTag()
		oldOwner := newTestDevice(t, "old-owner")
		writer := newTestDevice(t, "granted-writer")
		for _, d := range []Device{oldOwner, writer} {
			if err := createDevice(ctx, s, d); err != nil {
				t.Fatalf("createDevice: %v", err)
			}
		}
		at := time.Now().UTC().Truncate(time.Millisecond)

		// Construct the state DIRECTLY: an is_owner grant, no owner row. This is
		// what a pre-0005 binary leaves behind, and no current API path produces
		// it — which is precisely why it needs a regression test.
		if err := putOwnerGrantDirect(ctx, s, vault, oldOwner.ID, at); err != nil {
			t.Fatalf("seed orphan owner grant: %v", err)
		}
		if _, err := s.GetVaultOwner(ctx, vault); !errors.Is(err, ErrVaultOwnerNotFound) {
			t.Fatalf("seeded state already has an owner row (err = %v)", err)
		}
		// A second device holds an explicit write grant, exactly as the old binary
		// would have granted it.
		if err := s.PutGrant(ctx, vault, writer.ID, PermWrite, at); err != nil {
			t.Fatalf("PutGrant: %v", err)
		}

		// The granted writer's next write reaches ClaimVault. It must NOT error.
		claimed, owner, err := s.ClaimVault(ctx, vault, writer.AccountID, writer.ID, at)
		if err != nil {
			t.Fatalf("ClaimVault over an orphan owner grant: %v (this is the 500)", err)
		}
		if claimed {
			t.Fatal("ClaimVault CLAIMED a vault that already had an owner grant")
		}
		if owner.AccountID != oldOwner.AccountID {
			t.Fatalf("adopted owner = %q, want the grant holder's account %q",
				owner.AccountID, oldOwner.AccountID)
		}
		// The reconciliation is now persistent...
		stored, err := s.GetVaultOwner(ctx, vault)
		if err != nil {
			t.Fatalf("GetVaultOwner after reconcile: %v", err)
		}
		if stored.AccountID != oldOwner.AccountID {
			t.Fatalf("stored owner = %q, want %q", stored.AccountID, oldOwner.AccountID)
		}
		// ...and it wrote NO grant row for the caller: nobody gained access.
		if g, gerr := s.GetGrant(ctx, vault, writer.ID); gerr != nil || g.Owner {
			t.Fatalf("writer grant after reconcile = (%+v, %v), want the original non-owner write grant", g, gerr)
		}
		// It is idempotent.
		claimed, owner, err = s.ClaimVault(ctx, vault, writer.AccountID, writer.ID, at)
		if err != nil || claimed || owner.AccountID != oldOwner.AccountID {
			t.Fatalf("second ClaimVault = (%v, %+v, %v), want (false, the same owner, nil)", claimed, owner, err)
		}
	})
}

// TestNoAccountIDUpdateInStoreSources is a SOURCE-LEVEL invariant: nothing on a
// REQUEST PATH may UPDATE sigil_devices.account_id. Membership is assigned once
// at enrollment and never moves — no transfer route, no "switch account", no
// lazy adoption on a read path. A grep is the cheapest way to keep that true as
// the file grows.
//
// adopt.go is deliberately NOT in this list and is the ONLY exception: it is the
// operator command `sigild migrate adopt`, which assigns an account to rows that
// have NONE (account_id IS NULL). It is reachable only from a shell, never from
// an HTTP handler — which is exactly why adoption is an explicit operator action
// and not something the authentication path does implicitly.
func TestNoAccountIDUpdateInStoreSources(t *testing.T) {
	for _, name := range []string{
		"devicestore.go", "accounts.go", "postgresdevicestore.go", "postgresaccounts.go",
		"keysharing.go", "postgreskeysharing.go",
	} {
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		lower := strings.ToLower(string(body))
		for idx := 0; ; {
			at := strings.Index(lower[idx:], "update sigil_devices")
			if at < 0 {
				break
			}
			start := idx + at
			// Inspect the statement up to the next semicolon or backtick.
			end := len(lower)
			if stop := strings.IndexAny(lower[start:], ";`"); stop >= 0 {
				end = start + stop
			}
			if strings.Contains(lower[start:end], "account_id") {
				t.Fatalf("%s contains an UPDATE of sigil_devices.account_id:\n%s", name, string(body[start:end]))
			}
			idx = end
		}
	}
}

// TestNewAccountIDNeverAdoptedPrefix: a generated account ID can never collide
// with migration 0005's deterministic adopted namespace, because that would be a
// silent account MERGE. The generator FAILS rather than returning one.
func TestNewAccountIDNeverAdoptedPrefix(t *testing.T) {
	seen := make(map[string]struct{}, 10000)
	for i := 0; i < 10000; i++ {
		id, err := NewAccountID()
		if err != nil {
			t.Fatalf("NewAccountID: %v", err)
		}
		if !strings.HasPrefix(id, accountIDPrefix) {
			t.Fatalf("account ID %q missing %q prefix", id, accountIDPrefix)
		}
		if strings.HasPrefix(id, AdoptedAccountPrefix) {
			t.Fatalf("generated account ID %q collided with the adopted prefix", id)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate account ID %q after %d draws", id, i)
		}
		seen[id] = struct{}{}
	}

	// Force the collision: entropy whose raw-URL base64 begins "mig_". The
	// generator must ERROR, never return it.
	head, err := base64.RawURLEncoding.DecodeString("mig_")
	if err != nil {
		t.Fatalf("decode forced prefix: %v", err)
	}
	forced := append(head, make([]byte, accountIDBytes-len(head))...)
	if id, gerr := newAccountIDFrom(forced); gerr == nil {
		t.Fatalf("newAccountIDFrom returned %q for adopted-prefix entropy, want an error", id)
	}
}
