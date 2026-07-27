package store

// Tests for the device registry / enrollment-token ledger / grant model.
//
// The bulk lives in runDeviceStoreSuite, a BACKEND-AGNOSTIC conformance suite so
// the in-memory and Postgres implementations are held to byte-for-byte the same
// contract. MemDeviceStore runs it here; PostgresDeviceStore runs it in
// postgresdevicestore_test.go (gated on SIGILD_TEST_POSTGRES).

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var deviceTestCounter atomic.Uint64

// uniqueTag returns a string unique to this test run, used to namespace vault
// IDs and token hashes so a shared Postgres database never has cross-run
// interference.
func uniqueTag() string {
	return fmt.Sprintf("t%d-%d", time.Now().UnixNano(), deviceTestCounter.Add(1))
}

// testPubKey returns a fresh, valid 32-byte Ed25519 public key.
func testPubKey(t *testing.T) []byte {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return pub
}

// newTestDevice builds an unsaved Device with a fresh ID, key and its OWN fresh
// account. Every device gets a distinct account unless a test deliberately joins
// one (see joinAccount), which mirrors production: an operator token always
// founds a new account.
func newTestDevice(t *testing.T, label string) Device {
	t.Helper()
	id, err := NewDeviceID()
	if err != nil {
		t.Fatalf("NewDeviceID: %v", err)
	}
	accountID, err := NewAccountID()
	if err != nil {
		t.Fatalf("NewAccountID: %v", err)
	}
	return Device{
		ID:        id,
		AccountID: accountID,
		PublicKey: testPubKey(t),
		Label:     label,
		Status:    DeviceActive,
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
	}
}

// createDevice registers d together with its own singleton account, which is
// exactly what operator-token enrollment does. Since Phase 52 a device cannot
// exist without an account, so this is the only sensible way for a test to seed
// one.
func createDevice(ctx context.Context, s DeviceStore, d Device) error {
	return s.CreateAccountWithFounder(ctx, Account{
		ID:                d.AccountID,
		CreatedAt:         d.CreatedAt,
		CreatedByDeviceID: d.ID,
	}, d)
}

// claimVaultOwner keeps the two-value shape of the removed ClaimVaultOwner so the
// pre-existing single-owner assertions read unchanged. Ownership is now an
// ACCOUNT property, so it claims on behalf of d's account.
func claimVaultOwner(ctx context.Context, s DeviceStore, vaultID string, d Device, at time.Time) (bool, error) {
	claimed, _, err := s.ClaimVault(ctx, vaultID, d.AccountID, d.ID, at)
	return claimed, err
}

// joinAccount registers d as a SIBLING of an existing account, bypassing the
// invite flow. It exists so a test can build a multi-device account directly;
// production has no such path (the only way in is an invite).
func joinAccount(ctx context.Context, s DeviceStore, accountID string, d Device) error {
	d.AccountID = accountID
	return s.CreateDevice(ctx, d)
}

func TestMemDeviceStoreSuite(t *testing.T) {
	runDeviceStoreSuite(t, func(t *testing.T) DeviceStore {
		t.Helper()
		return NewMemDeviceStore()
	})
}

// runDeviceStoreSuite exercises the full DeviceStore contract against a backend
// produced by newStore. Every subtest gets its own store instance (for the
// Postgres backend, the same database with run-unique IDs).
func runDeviceStoreSuite(t *testing.T, newStore func(*testing.T) DeviceStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("CreateGetList", func(t *testing.T) {
		s := newStore(t)
		d1 := newTestDevice(t, "laptop")
		d2 := newTestDevice(t, "phone")
		d2.CreatedAt = d1.CreatedAt.Add(time.Second)

		for _, d := range []Device{d1, d2} {
			if err := createDevice(ctx, s, d); err != nil {
				t.Fatalf("CreateDevice(%s): %v", d.Label, err)
			}
		}

		got, err := s.GetDevice(ctx, d1.ID)
		if err != nil {
			t.Fatalf("GetDevice: %v", err)
		}
		if got.ID != d1.ID || got.Label != "laptop" || got.Status != DeviceActive {
			t.Fatalf("GetDevice = %+v, want id=%s label=laptop status=active", got, d1.ID)
		}
		if string(got.PublicKey) != string(d1.PublicKey) {
			t.Fatal("GetDevice returned a different public key than was stored")
		}
		if !got.Active() {
			t.Fatal("freshly enrolled device is not Active()")
		}

		// List must contain both, in CreatedAt order. Filter to OUR devices so a
		// shared database's other rows do not affect the assertion.
		all, err := s.ListDevices(ctx)
		if err != nil {
			t.Fatalf("ListDevices: %v", err)
		}
		var ours []string
		for _, d := range all {
			if d.ID == d1.ID || d.ID == d2.ID {
				ours = append(ours, d.ID)
			}
		}
		if len(ours) != 2 {
			t.Fatalf("ListDevices returned %d of our 2 devices", len(ours))
		}
		if ours[0] != d1.ID || ours[1] != d2.ID {
			t.Fatalf("ListDevices order = %v, want [%s %s] (by created_at)", ours, d1.ID, d2.ID)
		}
	})

	t.Run("GetUnknownDevice", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.GetDevice(ctx, "dev_does-not-exist-"+uniqueTag()); !errors.Is(err, ErrDeviceNotFound) {
			t.Fatalf("GetDevice(unknown) err = %v, want ErrDeviceNotFound", err)
		}
	})

	t.Run("DuplicatePublicKeyRejected", func(t *testing.T) {
		s := newStore(t)
		d := newTestDevice(t, "first")
		if err := createDevice(ctx, s, d); err != nil {
			t.Fatalf("CreateDevice: %v", err)
		}
		// A DIFFERENT device ID but the SAME public key must be rejected: a key
		// identifies at most one device.
		dup := newTestDevice(t, "second")
		dup.PublicKey = d.PublicKey
		if err := createDevice(ctx, s, dup); !errors.Is(err, ErrDeviceExists) {
			t.Fatalf("CreateDevice(duplicate key) err = %v, want ErrDeviceExists", err)
		}
		// The same ID must also be rejected.
		again := d
		again.PublicKey = testPubKey(t)
		if err := createDevice(ctx, s, again); !errors.Is(err, ErrDeviceExists) {
			t.Fatalf("CreateDevice(duplicate id) err = %v, want ErrDeviceExists", err)
		}
	})

	t.Run("RevokeIsIdempotentAndSticky", func(t *testing.T) {
		s := newStore(t)
		d := newTestDevice(t, "to-revoke")
		if err := createDevice(ctx, s, d); err != nil {
			t.Fatalf("CreateDevice: %v", err)
		}

		at := time.Now().UTC().Truncate(time.Millisecond)
		if err := s.RevokeDevice(ctx, d.ID, at); err != nil {
			t.Fatalf("RevokeDevice: %v", err)
		}
		got, err := s.GetDevice(ctx, d.ID)
		if err != nil {
			t.Fatalf("GetDevice after revoke: %v", err)
		}
		if got.Status != DeviceRevoked || got.Active() {
			t.Fatalf("status after revoke = %q (active=%v), want revoked", got.Status, got.Active())
		}
		if got.RevokedAt.IsZero() {
			t.Fatal("RevokedAt is zero after revoke")
		}
		first := got.RevokedAt

		// Second revoke: no error, and the original timestamp is preserved.
		if err := s.RevokeDevice(ctx, d.ID, at.Add(time.Hour)); err != nil {
			t.Fatalf("second RevokeDevice: %v", err)
		}
		got, err = s.GetDevice(ctx, d.ID)
		if err != nil {
			t.Fatalf("GetDevice after second revoke: %v", err)
		}
		if !got.RevokedAt.Equal(first) {
			t.Fatalf("RevokedAt changed on re-revoke: %v -> %v", first, got.RevokedAt)
		}

		if err := s.RevokeDevice(ctx, "dev_missing-"+uniqueTag(), at); !errors.Is(err, ErrDeviceNotFound) {
			t.Fatalf("RevokeDevice(unknown) err = %v, want ErrDeviceNotFound", err)
		}
	})

	t.Run("EnrollmentTokenSingleUse", func(t *testing.T) {
		s := newStore(t)
		hash := "hash-" + uniqueTag()
		issued := time.Now().UTC()

		// Unknown before registration.
		if err := s.ConsumeEnrollmentToken(ctx, hash, "dev_x", issued); !errors.Is(err, ErrEnrollTokenUnknown) {
			t.Fatalf("consume(unregistered) err = %v, want ErrEnrollTokenUnknown", err)
		}

		if err := s.RegisterEnrollmentToken(ctx, hash, issued, time.Time{}); err != nil {
			t.Fatalf("RegisterEnrollmentToken: %v", err)
		}
		// Re-registration is idempotent.
		if err := s.RegisterEnrollmentToken(ctx, hash, issued, time.Time{}); err != nil {
			t.Fatalf("re-RegisterEnrollmentToken: %v", err)
		}

		if err := s.ConsumeEnrollmentToken(ctx, hash, "dev_a", issued); err != nil {
			t.Fatalf("first consume: %v", err)
		}
		// SINGLE-USE: the second consume must fail.
		if err := s.ConsumeEnrollmentToken(ctx, hash, "dev_b", issued); !errors.Is(err, ErrEnrollTokenUsed) {
			t.Fatalf("second consume err = %v, want ErrEnrollTokenUsed", err)
		}
		// And re-registering (i.e. a server restart with the same env) must NOT
		// resurrect a spent token.
		if err := s.RegisterEnrollmentToken(ctx, hash, issued, time.Time{}); err != nil {
			t.Fatalf("re-register after use: %v", err)
		}
		if err := s.ConsumeEnrollmentToken(ctx, hash, "dev_c", issued); !errors.Is(err, ErrEnrollTokenUsed) {
			t.Fatalf("consume after re-register err = %v, want ErrEnrollTokenUsed", err)
		}
	})

	t.Run("EnrollmentTokenExpiry", func(t *testing.T) {
		s := newStore(t)
		hash := "hash-exp-" + uniqueTag()
		issued := time.Now().UTC()
		expires := issued.Add(time.Hour)
		if err := s.RegisterEnrollmentToken(ctx, hash, issued, expires); err != nil {
			t.Fatalf("RegisterEnrollmentToken: %v", err)
		}
		// Past the expiry: rejected, and NOT consumed.
		if err := s.ConsumeEnrollmentToken(ctx, hash, "dev_a", expires.Add(time.Second)); !errors.Is(err, ErrEnrollTokenExpired) {
			t.Fatalf("expired consume err = %v, want ErrEnrollTokenExpired", err)
		}
		// Still spendable inside the window (proving the rejection consumed nothing).
		if err := s.ConsumeEnrollmentToken(ctx, hash, "dev_a", issued.Add(time.Minute)); err != nil {
			t.Fatalf("in-window consume after an expired attempt: %v", err)
		}
	})

	t.Run("EnrollmentTokenConcurrentSingleWinner", func(t *testing.T) {
		s := newStore(t)
		hash := "hash-race-" + uniqueTag()
		now := time.Now().UTC()
		if err := s.RegisterEnrollmentToken(ctx, hash, now, time.Time{}); err != nil {
			t.Fatalf("RegisterEnrollmentToken: %v", err)
		}

		const workers = 16
		var wins, used int64
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				switch err := s.ConsumeEnrollmentToken(ctx, hash, fmt.Sprintf("dev_%d", i), now); {
				case err == nil:
					atomic.AddInt64(&wins, 1)
				case errors.Is(err, ErrEnrollTokenUsed):
					atomic.AddInt64(&used, 1)
				default:
					t.Errorf("unexpected consume error: %v", err)
				}
			}(i)
		}
		wg.Wait()

		if wins != 1 {
			t.Fatalf("concurrent consumes succeeded %d times, want exactly 1", wins)
		}
		if used != workers-1 {
			t.Fatalf("concurrent consumes rejected %d times, want %d", used, workers-1)
		}
	})

	t.Run("ClaimVaultOwnerAndGrants", func(t *testing.T) {
		s := newStore(t)
		vault := "vault-" + uniqueTag()
		owner := newTestDevice(t, "owner")
		other := newTestDevice(t, "other")
		for _, d := range []Device{owner, other} {
			if err := createDevice(ctx, s, d); err != nil {
				t.Fatalf("CreateDevice: %v", err)
			}
		}
		at := time.Now().UTC()

		// No grant before anything happens.
		if _, err := s.GetGrant(ctx, vault, owner.ID); !errors.Is(err, ErrGrantNotFound) {
			t.Fatalf("GetGrant(fresh vault) err = %v, want ErrGrantNotFound", err)
		}

		claimed, err := claimVaultOwner(ctx, s, vault, owner, at)
		if err != nil {
			t.Fatalf("ClaimVaultOwner: %v", err)
		}
		if !claimed {
			t.Fatal("first ClaimVaultOwner returned false, want true")
		}
		// A second device cannot claim an owned vault.
		claimed, err = claimVaultOwner(ctx, s, vault, other, at)
		if err != nil {
			t.Fatalf("second ClaimVaultOwner: %v", err)
		}
		if claimed {
			t.Fatal("second ClaimVaultOwner returned true, want false (vault already owned)")
		}

		g, err := s.GetGrant(ctx, vault, owner.ID)
		if err != nil {
			t.Fatalf("GetGrant(owner): %v", err)
		}
		if !g.Owner || g.Perm != PermWrite {
			t.Fatalf("owner grant = %+v, want owner=true perm=write", g)
		}
		if _, err := s.GetGrant(ctx, vault, other.ID); !errors.Is(err, ErrGrantNotFound) {
			t.Fatalf("GetGrant(loser) err = %v, want ErrGrantNotFound", err)
		}

		// Owner grants the other device read access.
		if err := s.PutGrant(ctx, vault, other.ID, PermRead, at); err != nil {
			t.Fatalf("PutGrant: %v", err)
		}
		g, err = s.GetGrant(ctx, vault, other.ID)
		if err != nil {
			t.Fatalf("GetGrant(grantee): %v", err)
		}
		if g.Owner || g.Perm != PermRead {
			t.Fatalf("grantee grant = %+v, want owner=false perm=read", g)
		}
		// Upgrade read -> write.
		if err := s.PutGrant(ctx, vault, other.ID, PermWrite, at); err != nil {
			t.Fatalf("PutGrant(upgrade): %v", err)
		}
		g, _ = s.GetGrant(ctx, vault, other.ID)
		if g.Perm != PermWrite {
			t.Fatalf("upgraded grant perm = %q, want write", g.Perm)
		}
		// PutGrant must NEVER downgrade or un-own the owner.
		if err := s.PutGrant(ctx, vault, owner.ID, PermRead, at); err != nil {
			t.Fatalf("PutGrant(owner): %v", err)
		}
		g, _ = s.GetGrant(ctx, vault, owner.ID)
		if !g.Owner || g.Perm != PermWrite {
			t.Fatalf("owner grant after PutGrant = %+v, want owner=true perm=write (never downgraded)", g)
		}

		grants, err := s.ListGrants(ctx, vault)
		if err != nil {
			t.Fatalf("ListGrants: %v", err)
		}
		if len(grants) != 2 {
			t.Fatalf("ListGrants returned %d grants, want 2", len(grants))
		}
		if grants[0].DeviceID > grants[1].DeviceID {
			t.Fatalf("ListGrants not ordered by device ID: %v", grants)
		}
	})

	t.Run("ClaimVaultOwnerConcurrentSingleWinner", func(t *testing.T) {
		s := newStore(t)
		vault := "vault-race-" + uniqueTag()
		at := time.Now().UTC()

		const workers = 16
		devs := make([]Device, workers)
		for i := range devs {
			devs[i] = newTestDevice(t, fmt.Sprintf("racer-%d", i))
			if err := createDevice(ctx, s, devs[i]); err != nil {
				t.Fatalf("CreateDevice: %v", err)
			}
		}

		var wins int64
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				ok, err := claimVaultOwner(ctx, s, vault, devs[i], at)
				if err != nil {
					t.Errorf("ClaimVaultOwner: %v", err)
					return
				}
				if ok {
					atomic.AddInt64(&wins, 1)
				}
			}(i)
		}
		wg.Wait()

		if wins != 1 {
			t.Fatalf("concurrent claims won %d times, want exactly 1", wins)
		}
		grants, err := s.ListGrants(ctx, vault)
		if err != nil {
			t.Fatalf("ListGrants: %v", err)
		}
		owners := 0
		for _, g := range grants {
			if g.Owner {
				owners++
			}
		}
		if owners != 1 {
			t.Fatalf("vault has %d owner grants, want exactly 1", owners)
		}
	})

	t.Run("ConcurrentMixedOperations", func(t *testing.T) {
		// Hammers the store from many goroutines so -race can surface any data
		// race across create/get/list/revoke/grant paths.
		s := newStore(t)
		vault := "vault-mixed-" + uniqueTag()
		at := time.Now().UTC()

		const workers = 24
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				d := newTestDevice(t, fmt.Sprintf("mixed-%d", i))
				if err := createDevice(ctx, s, d); err != nil {
					t.Errorf("CreateDevice: %v", err)
					return
				}
				if _, err := s.GetDevice(ctx, d.ID); err != nil {
					t.Errorf("GetDevice: %v", err)
				}
				if _, err := claimVaultOwner(ctx, s, vault, d, at); err != nil {
					t.Errorf("ClaimVaultOwner: %v", err)
				}
				if _, err := s.ListDevices(ctx); err != nil {
					t.Errorf("ListDevices: %v", err)
				}
				if _, err := s.ListGrants(ctx, vault); err != nil {
					t.Errorf("ListGrants: %v", err)
				}
				if err := s.RevokeDevice(ctx, d.ID, at); err != nil {
					t.Errorf("RevokeDevice: %v", err)
				}
			}(i)
		}
		wg.Wait()
	})

	// Device hybrid public keys + the opaque key-envelope relay (Phase 46) are
	// part of the SAME conformance suite, so mem and Postgres are held to
	// identical behaviour here too.
	runKeySharingSuite(t, newStore)
	// The account model (Phase 52) likewise: accounts, invites and ACCOUNT-scoped
	// vault ownership are one contract across both backends.
	runAccountsSuite(t, newStore)
}

// TestPermissionAllows pins the permission lattice: write implies read, read
// does not imply write, and an unknown level allows nothing.
func TestPermissionAllows(t *testing.T) {
	cases := []struct {
		have Permission
		need Permission
		want bool
	}{
		{PermWrite, PermWrite, true},
		{PermWrite, PermRead, true},
		{PermRead, PermRead, true},
		{PermRead, PermWrite, false},
		{Permission("admin"), PermRead, false},
		{Permission(""), PermRead, false},
	}
	for _, c := range cases {
		if got := c.have.Allows(c.need); got != c.want {
			t.Errorf("Permission(%q).Allows(%q) = %v, want %v", c.have, c.need, got, c.want)
		}
	}
	if ValidPermission("admin") || ValidPermission("") {
		t.Fatal("ValidPermission accepted a level outside {read, write}")
	}
	if !ValidPermission(PermRead) || !ValidPermission(PermWrite) {
		t.Fatal("ValidPermission rejected a defined level")
	}
}

// TestNewDeviceIDUniqueAndPrefixed checks device IDs are server-assigned,
// prefixed, and unguessable-by-collision.
func TestNewDeviceIDUnique(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		id, err := NewDeviceID()
		if err != nil {
			t.Fatalf("NewDeviceID: %v", err)
		}
		if len(id) <= len(deviceIDPrefix) || id[:len(deviceIDPrefix)] != deviceIDPrefix {
			t.Fatalf("device ID %q missing %q prefix", id, deviceIDPrefix)
		}
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate device ID %q after %d draws", id, i)
		}
		seen[id] = struct{}{}
	}
}

// TestMemDeviceStoreDefensiveCopy proves a caller cannot mutate a stored public
// key through the slice it passed in or the one it got back.
func TestMemDeviceStoreDefensiveCopy(t *testing.T) {
	ctx := context.Background()
	s := NewMemDeviceStore()
	d := newTestDevice(t, "copy")
	original := make([]byte, len(d.PublicKey))
	copy(original, d.PublicKey)

	if err := createDevice(ctx, s, d); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	d.PublicKey[0] ^= 0xff // mutate the caller's slice after storing

	got, err := s.GetDevice(ctx, d.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if string(got.PublicKey) != string(original) {
		t.Fatal("stored public key changed when the caller mutated its input slice")
	}
	got.PublicKey[0] ^= 0xff // mutate the returned slice

	again, _ := s.GetDevice(ctx, d.ID)
	if string(again.PublicKey) != string(original) {
		t.Fatal("stored public key changed when the caller mutated a returned slice")
	}
}
