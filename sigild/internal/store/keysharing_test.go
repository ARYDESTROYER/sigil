package store

// Conformance suite for the KeySharing seam: device hybrid PUBLIC keys and the
// opaque key-envelope relay.
//
// Like the rest of the device-store suite this is BACKEND-AGNOSTIC — it is
// called from runDeviceStoreSuite, so MemDeviceStore runs it here and
// PostgresDeviceStore runs the identical assertions (gated on
// SIGILD_TEST_POSTGRES). The headline assertion is VERBATIM RELAY: whatever
// bytes go in come back byte-identical, because the server does no cryptography
// on them and cannot read them.

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"
)

// testHybridKey builds a shape-valid hybrid public key for a device. The bytes
// are random: the server never interprets them, so any bytes of the right length
// are as good as a real key for the store's purposes.
func testHybridKey(t *testing.T, deviceID string) HybridPublicKey {
	t.Helper()
	x := make([]byte, X25519PublicKeyLen)
	m := make([]byte, MLKEM768EncapsKeyLen)
	if _, err := rand.Read(x); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if _, err := rand.Read(m); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return HybridPublicKey{
		DeviceID:        deviceID,
		X25519PublicKey: x,
		MLKEMEncapsKey:  m,
		UpdatedAt:       time.Now().UTC().Truncate(time.Millisecond),
	}
}

// testEnvelopeBlob returns n pseudo-random bytes standing in for a client's
// hybrid-sealed wrapped vault key.
func testEnvelopeBlob(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func runKeySharingSuite(t *testing.T, newStore func(*testing.T) DeviceStore) {
	t.Helper()
	ctx := context.Background()

	t.Run("HybridKeyPublishFetchRepublish", func(t *testing.T) {
		s := newStore(t)
		d := newTestDevice(t, "laptop")
		if err := createDevice(ctx, s, d); err != nil {
			t.Fatalf("CreateDevice: %v", err)
		}

		// Not published yet.
		if _, err := s.GetDeviceHybridKey(ctx, d.ID); !errors.Is(err, ErrHybridKeyNotFound) {
			t.Fatalf("GetDeviceHybridKey before publish = %v, want ErrHybridKeyNotFound", err)
		}

		k := testHybridKey(t, d.ID)
		if err := s.PutDeviceHybridKey(ctx, k); err != nil {
			t.Fatalf("PutDeviceHybridKey: %v", err)
		}
		got, err := s.GetDeviceHybridKey(ctx, d.ID)
		if err != nil {
			t.Fatalf("GetDeviceHybridKey: %v", err)
		}
		// VERBATIM: the stored key is byte-identical to what was published.
		if !bytes.Equal(got.X25519PublicKey, k.X25519PublicKey) ||
			!bytes.Equal(got.MLKEMEncapsKey, k.MLKEMEncapsKey) {
			t.Fatal("stored hybrid key is not byte-identical to the published one")
		}
		if got.DeviceID != d.ID {
			t.Fatalf("device_id = %q, want %q", got.DeviceID, d.ID)
		}

		// Re-publishing is allowed and REPLACES the key (upsert, no error).
		k2 := testHybridKey(t, d.ID)
		k2.UpdatedAt = k.UpdatedAt.Add(time.Second)
		if err := s.PutDeviceHybridKey(ctx, k2); err != nil {
			t.Fatalf("republish: %v", err)
		}
		got2, err := s.GetDeviceHybridKey(ctx, d.ID)
		if err != nil {
			t.Fatalf("GetDeviceHybridKey after republish: %v", err)
		}
		if !bytes.Equal(got2.X25519PublicKey, k2.X25519PublicKey) {
			t.Fatal("republish did not replace the stored key")
		}
	})

	t.Run("HybridKeyRejectsMalformedAndUnknownDevice", func(t *testing.T) {
		s := newStore(t)
		d := newTestDevice(t, "laptop")
		if err := createDevice(ctx, s, d); err != nil {
			t.Fatalf("CreateDevice: %v", err)
		}

		bad := testHybridKey(t, d.ID)
		bad.X25519PublicKey = bad.X25519PublicKey[:16]
		if err := s.PutDeviceHybridKey(ctx, bad); !errors.Is(err, ErrHybridKeyMalformed) {
			t.Fatalf("short x25519 key = %v, want ErrHybridKeyMalformed", err)
		}
		bad2 := testHybridKey(t, d.ID)
		bad2.MLKEMEncapsKey = append(bad2.MLKEMEncapsKey, 0)
		if err := s.PutDeviceHybridKey(ctx, bad2); !errors.Is(err, ErrHybridKeyMalformed) {
			t.Fatalf("long mlkem key = %v, want ErrHybridKeyMalformed", err)
		}

		// An unenrolled device cannot have a key on file.
		orphan := testHybridKey(t, "dev_not-enrolled-"+uniqueTag())
		if err := s.PutDeviceHybridKey(ctx, orphan); !errors.Is(err, ErrDeviceNotFound) {
			t.Fatalf("publish for unknown device = %v, want ErrDeviceNotFound", err)
		}
	})

	t.Run("KeyEnvelopeRelayIsVerbatim", func(t *testing.T) {
		s := newStore(t)
		sender := newTestDevice(t, "A")
		recipient := newTestDevice(t, "B")
		for _, d := range []Device{sender, recipient} {
			if err := createDevice(ctx, s, d); err != nil {
				t.Fatalf("CreateDevice: %v", err)
			}
		}
		vault := "vault-share-" + uniqueTag()

		if _, err := s.GetKeyEnvelope(ctx, vault, recipient.ID); !errors.Is(err, ErrKeyEnvelopeNotFound) {
			t.Fatalf("GetKeyEnvelope before put = %v, want ErrKeyEnvelopeNotFound", err)
		}

		blob := testEnvelopeBlob(t, 1200)
		env := KeyEnvelope{
			VaultID:           vault,
			RecipientDeviceID: recipient.ID,
			SenderDeviceID:    sender.ID,
			Blob:              blob,
			CreatedAt:         time.Now().UTC().Truncate(time.Millisecond),
		}
		if err := s.PutKeyEnvelope(ctx, env); err != nil {
			t.Fatalf("PutKeyEnvelope: %v", err)
		}

		got, err := s.GetKeyEnvelope(ctx, vault, recipient.ID)
		if err != nil {
			t.Fatalf("GetKeyEnvelope: %v", err)
		}
		// THE POINT: the relay returns exactly the ciphertext it was handed.
		if !bytes.Equal(got.Blob, blob) {
			t.Fatal("relayed envelope is not byte-identical to the uploaded one")
		}
		if got.SenderDeviceID != sender.ID || got.RecipientDeviceID != recipient.ID || got.VaultID != vault {
			t.Fatalf("envelope metadata = %+v, want vault=%s sender=%s recipient=%s",
				got, vault, sender.ID, recipient.ID)
		}

		// Mailboxes are per (vault, recipient): the sender has none for itself.
		if _, err := s.GetKeyEnvelope(ctx, vault, sender.ID); !errors.Is(err, ErrKeyEnvelopeNotFound) {
			t.Fatalf("envelope for a different recipient = %v, want ErrKeyEnvelopeNotFound", err)
		}
		// ...nor does the same recipient on a different vault.
		if _, err := s.GetKeyEnvelope(ctx, vault+"-other", recipient.ID); !errors.Is(err, ErrKeyEnvelopeNotFound) {
			t.Fatalf("envelope for a different vault = %v, want ErrKeyEnvelopeNotFound", err)
		}

		// Re-sharing REPLACES the envelope (the sender may have re-keyed).
		blob2 := testEnvelopeBlob(t, 900)
		env.Blob = blob2
		env.CreatedAt = env.CreatedAt.Add(time.Second)
		if err := s.PutKeyEnvelope(ctx, env); err != nil {
			t.Fatalf("re-put envelope: %v", err)
		}
		got2, err := s.GetKeyEnvelope(ctx, vault, recipient.ID)
		if err != nil {
			t.Fatalf("GetKeyEnvelope after re-put: %v", err)
		}
		if !bytes.Equal(got2.Blob, blob2) {
			t.Fatal("re-sharing did not replace the stored envelope")
		}
	})

	t.Run("KeyEnvelopeListAndDelete", func(t *testing.T) {
		// Phase 50 rotation support: an owner enumerates which devices hold a
		// wrapped key and deletes the stale ones. METADATA only — no blob leaves
		// the store through the listing.
		s := newStore(t)
		sender := newTestDevice(t, "A")
		b := newTestDevice(t, "B")
		c := newTestDevice(t, "C")
		for _, d := range []Device{sender, b, c} {
			if err := createDevice(ctx, s, d); err != nil {
				t.Fatalf("CreateDevice: %v", err)
			}
		}
		vault := "vault-rotate-" + uniqueTag()

		// An unknown vault lists empty rather than erroring.
		if got, err := s.ListKeyEnvelopeRecipients(ctx, vault); err != nil || len(got) != 0 {
			t.Fatalf("list on empty vault = (%v, %v), want ([], nil)", got, err)
		}
		// Deleting nothing is ErrKeyEnvelopeNotFound, so a caller can tell
		// "removed" from "already absent".
		if err := s.DeleteKeyEnvelope(ctx, vault, b.ID); !errors.Is(err, ErrKeyEnvelopeNotFound) {
			t.Fatalf("delete missing = %v, want ErrKeyEnvelopeNotFound", err)
		}

		blobB := testEnvelopeBlob(t, 1226)
		blobC := testEnvelopeBlob(t, 700)
		now := time.Now().UTC().Truncate(time.Millisecond)
		for _, e := range []KeyEnvelope{
			{VaultID: vault, RecipientDeviceID: b.ID, SenderDeviceID: sender.ID, Blob: blobB, CreatedAt: now},
			{VaultID: vault, RecipientDeviceID: c.ID, SenderDeviceID: sender.ID, Blob: blobC, CreatedAt: now},
			// A DIFFERENT vault must not appear in this vault's listing.
			{VaultID: vault + "-other", RecipientDeviceID: b.ID, SenderDeviceID: sender.ID, Blob: blobB, CreatedAt: now},
		} {
			if err := s.PutKeyEnvelope(ctx, e); err != nil {
				t.Fatalf("PutKeyEnvelope: %v", err)
			}
		}

		got, err := s.ListKeyEnvelopeRecipients(ctx, vault)
		if err != nil {
			t.Fatalf("ListKeyEnvelopeRecipients: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("listed %d recipients, want 2 (%+v)", len(got), got)
		}
		// Sorted by recipient device ID, so the order is stable across backends.
		if got[0].RecipientDeviceID > got[1].RecipientDeviceID {
			t.Fatalf("listing is not sorted by recipient: %+v", got)
		}
		sizes := map[string]int{}
		for _, m := range got {
			sizes[m.RecipientDeviceID] = m.SizeBytes
			if m.SenderDeviceID != sender.ID || m.VaultID != vault {
				t.Fatalf("metadata = %+v, want vault=%s sender=%s", m, vault, sender.ID)
			}
		}
		if sizes[b.ID] != len(blobB) || sizes[c.ID] != len(blobC) {
			t.Fatalf("sizes = %v, want B=%d C=%d", sizes, len(blobB), len(blobC))
		}

		// Delete C's mailbox: C can no longer collect, B is untouched, and the
		// other vault's envelope is untouched.
		if err := s.DeleteKeyEnvelope(ctx, vault, c.ID); err != nil {
			t.Fatalf("DeleteKeyEnvelope: %v", err)
		}
		if _, err := s.GetKeyEnvelope(ctx, vault, c.ID); !errors.Is(err, ErrKeyEnvelopeNotFound) {
			t.Fatalf("get after delete = %v, want ErrKeyEnvelopeNotFound", err)
		}
		if _, err := s.GetKeyEnvelope(ctx, vault, b.ID); err != nil {
			t.Fatalf("deleting C removed B's envelope: %v", err)
		}
		if _, err := s.GetKeyEnvelope(ctx, vault+"-other", b.ID); err != nil {
			t.Fatalf("deleting in one vault affected another: %v", err)
		}
		if err := s.DeleteKeyEnvelope(ctx, vault, c.ID); !errors.Is(err, ErrKeyEnvelopeNotFound) {
			t.Fatalf("second delete = %v, want ErrKeyEnvelopeNotFound", err)
		}
	})

	t.Run("KeyEnvelopeRecipientIndex", func(t *testing.T) {
		// Phase 54 (the recovery kit): a device that knows NO vault ids asks
		// which envelopes are addressed to IT. METADATA only, sorted by vault
		// id, and strictly scoped to the one recipient.
		s := newStore(t)
		sender := newTestDevice(t, "A")
		b := newTestDevice(t, "B")
		c := newTestDevice(t, "C")
		for _, d := range []Device{sender, b, c} {
			if err := createDevice(ctx, s, d); err != nil {
				t.Fatalf("CreateDevice: %v", err)
			}
		}

		// An unknown recipient is an EMPTY slice, never an error — a kit that
		// was never covered must read as "nothing to recover", not as a fault.
		if got, err := s.ListKeyEnvelopesForRecipient(ctx, "dev_nobody"); err != nil || len(got) != 0 {
			t.Fatalf("index for unknown recipient = (%v, %v), want ([], nil)", got, err)
		}

		tag := uniqueTag()
		// Deliberately deposited out of order, so a passing sort assertion
		// cannot be an accident of insertion order.
		vZ := "vault-z-" + tag
		vA := "vault-a-" + tag
		vM := "vault-m-" + tag
		blobZ := testEnvelopeBlob(t, 1226)
		blobA := testEnvelopeBlob(t, 900)
		blobOther := testEnvelopeBlob(t, 700)
		now := time.Now().UTC().Truncate(time.Millisecond)
		for _, e := range []KeyEnvelope{
			{VaultID: vZ, RecipientDeviceID: b.ID, SenderDeviceID: sender.ID, Blob: blobZ, CreatedAt: now},
			{VaultID: vA, RecipientDeviceID: b.ID, SenderDeviceID: sender.ID, Blob: blobA, CreatedAt: now},
			// Addressed to SOMEONE ELSE: it must never appear in B's index.
			{VaultID: vM, RecipientDeviceID: c.ID, SenderDeviceID: sender.ID, Blob: blobOther, CreatedAt: now},
		} {
			if err := s.PutKeyEnvelope(ctx, e); err != nil {
				t.Fatalf("PutKeyEnvelope: %v", err)
			}
		}

		got, err := s.ListKeyEnvelopesForRecipient(ctx, b.ID)
		if err != nil {
			t.Fatalf("ListKeyEnvelopesForRecipient: %v", err)
		}
		if len(got) != 2 {
			t.Fatalf("index listed %d rows, want 2 (%+v)", len(got), got)
		}
		// Sorted BYTE-WISE by vault id (COLLATE "C" in Postgres), so both
		// backends agree regardless of database locale.
		if got[0].VaultID > got[1].VaultID {
			t.Fatalf("index is not sorted by vault id: %+v", got)
		}
		if got[0].VaultID != vA || got[1].VaultID != vZ {
			t.Fatalf("index = %+v, want [%s %s]", got, vA, vZ)
		}
		for _, m := range got {
			if m.RecipientDeviceID != b.ID {
				t.Fatalf("index leaked another recipient's row: %+v", m)
			}
			if m.SenderDeviceID != sender.ID {
				t.Fatalf("index row = %+v, want sender %s", m, sender.ID)
			}
		}
		if got[0].SizeBytes != len(blobA) || got[1].SizeBytes != len(blobZ) {
			t.Fatalf("index sizes = (%d, %d), want (%d, %d)",
				got[0].SizeBytes, got[1].SizeBytes, len(blobA), len(blobZ))
		}
		// ⭐ METADATA ONLY. KeyEnvelopeMeta has no blob field at all — this
		// asserts the runtime consequence: none of the deposited ciphertext is
		// reachable through the index.
		for _, m := range got {
			for _, blob := range [][]byte{blobA, blobZ, blobOther} {
				if bytes.Contains([]byte(m.VaultID+m.RecipientDeviceID+m.SenderDeviceID), blob) {
					t.Fatalf("index row carries envelope bytes: %+v", m)
				}
			}
		}

		// Deleting an envelope removes it from the index too.
		if err := s.DeleteKeyEnvelope(ctx, vZ, b.ID); err != nil {
			t.Fatalf("DeleteKeyEnvelope: %v", err)
		}
		after, err := s.ListKeyEnvelopesForRecipient(ctx, b.ID)
		if err != nil {
			t.Fatalf("ListKeyEnvelopesForRecipient after delete: %v", err)
		}
		if len(after) != 1 || after[0].VaultID != vA {
			t.Fatalf("index after delete = %+v, want just %s", after, vA)
		}
	})

	t.Run("KeyEnvelopeRejectsBadSizeAndUnknownRecipient", func(t *testing.T) {
		s := newStore(t)
		d := newTestDevice(t, "B")
		if err := createDevice(ctx, s, d); err != nil {
			t.Fatalf("CreateDevice: %v", err)
		}
		vault := "vault-bad-" + uniqueTag()

		empty := KeyEnvelope{VaultID: vault, RecipientDeviceID: d.ID, Blob: nil, CreatedAt: time.Now().UTC()}
		if err := s.PutKeyEnvelope(ctx, empty); !errors.Is(err, ErrKeyEnvelopeMalformed) {
			t.Fatalf("empty envelope = %v, want ErrKeyEnvelopeMalformed", err)
		}
		huge := KeyEnvelope{
			VaultID:           vault,
			RecipientDeviceID: d.ID,
			Blob:              make([]byte, MaxKeyEnvelopeBytes+1),
			CreatedAt:         time.Now().UTC(),
		}
		if err := s.PutKeyEnvelope(ctx, huge); !errors.Is(err, ErrKeyEnvelopeMalformed) {
			t.Fatalf("oversized envelope = %v, want ErrKeyEnvelopeMalformed", err)
		}

		orphan := KeyEnvelope{
			VaultID:           vault,
			RecipientDeviceID: "dev_not-enrolled-" + uniqueTag(),
			Blob:              testEnvelopeBlob(t, 64),
			CreatedAt:         time.Now().UTC(),
		}
		if err := s.PutKeyEnvelope(ctx, orphan); !errors.Is(err, ErrDeviceNotFound) {
			t.Fatalf("envelope for unknown recipient = %v, want ErrDeviceNotFound", err)
		}
	})

	t.Run("KeySharingConcurrent", func(t *testing.T) {
		// -race coverage for the sharing paths.
		s := newStore(t)
		vault := "vault-conc-" + uniqueTag()
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				d := newTestDevice(t, "conc")
				if err := createDevice(ctx, s, d); err != nil {
					t.Errorf("CreateDevice: %v", err)
					return
				}
				if err := s.PutDeviceHybridKey(ctx, testHybridKey(t, d.ID)); err != nil {
					t.Errorf("PutDeviceHybridKey: %v", err)
				}
				if _, err := s.GetDeviceHybridKey(ctx, d.ID); err != nil {
					t.Errorf("GetDeviceHybridKey: %v", err)
				}
				env := KeyEnvelope{
					VaultID:           vault,
					RecipientDeviceID: d.ID,
					SenderDeviceID:    d.ID,
					Blob:              testEnvelopeBlob(t, 256),
					CreatedAt:         time.Now().UTC(),
				}
				if err := s.PutKeyEnvelope(ctx, env); err != nil {
					t.Errorf("PutKeyEnvelope: %v", err)
				}
				if _, err := s.GetKeyEnvelope(ctx, vault, d.ID); err != nil {
					t.Errorf("GetKeyEnvelope: %v", err)
				}
			}()
		}
		wg.Wait()
	})
}

// TestValidateHybridPublicKeyShapeOnly pins that validation is a LENGTH check
// and nothing more: all-zero bytes of the right length are accepted, because
// interpreting key material is the client's job, not the server's.
func TestValidateHybridPublicKeyShapeOnly(t *testing.T) {
	ok := HybridPublicKey{
		DeviceID:        "dev_x",
		X25519PublicKey: make([]byte, X25519PublicKeyLen),
		MLKEMEncapsKey:  make([]byte, MLKEM768EncapsKeyLen),
	}
	if err := ValidateHybridPublicKey(ok); err != nil {
		t.Fatalf("all-zero key of the right length = %v, want accepted (shape-only check)", err)
	}
	for _, bad := range []HybridPublicKey{
		{X25519PublicKey: make([]byte, 31), MLKEMEncapsKey: make([]byte, MLKEM768EncapsKeyLen)},
		{X25519PublicKey: make([]byte, X25519PublicKeyLen), MLKEMEncapsKey: make([]byte, 1183)},
		{},
	} {
		if err := ValidateHybridPublicKey(bad); !errors.Is(err, ErrHybridKeyMalformed) {
			t.Fatalf("wrong-shaped key = %v, want ErrHybridKeyMalformed", err)
		}
	}
}

// TestMemKeySharingDefensiveCopy: mutating the caller's slices after a Put, or
// the returned slices after a Get, must not change stored state.
func TestMemKeySharingDefensiveCopy(t *testing.T) {
	ctx := context.Background()
	s := NewMemDeviceStore()
	d := newTestDevice(t, "laptop")
	if err := createDevice(ctx, s, d); err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	k := testHybridKey(t, d.ID)
	original := append([]byte(nil), k.X25519PublicKey...)
	if err := s.PutDeviceHybridKey(ctx, k); err != nil {
		t.Fatalf("PutDeviceHybridKey: %v", err)
	}
	k.X25519PublicKey[0] ^= 0xff // mutate the caller's slice after storing
	got, err := s.GetDeviceHybridKey(ctx, d.ID)
	if err != nil {
		t.Fatalf("GetDeviceHybridKey: %v", err)
	}
	if !bytes.Equal(got.X25519PublicKey, original) {
		t.Fatal("mutating the caller's key slice changed stored state")
	}
	got.X25519PublicKey[0] ^= 0xff // mutate the returned slice
	again, _ := s.GetDeviceHybridKey(ctx, d.ID)
	if !bytes.Equal(again.X25519PublicKey, original) {
		t.Fatal("mutating a returned key slice changed stored state")
	}

	blob := testEnvelopeBlob(t, 128)
	originalBlob := append([]byte(nil), blob...)
	env := KeyEnvelope{VaultID: "v1", RecipientDeviceID: d.ID, Blob: blob, CreatedAt: time.Now().UTC()}
	if err := s.PutKeyEnvelope(ctx, env); err != nil {
		t.Fatalf("PutKeyEnvelope: %v", err)
	}
	blob[0] ^= 0xff
	gotEnv, err := s.GetKeyEnvelope(ctx, "v1", d.ID)
	if err != nil {
		t.Fatalf("GetKeyEnvelope: %v", err)
	}
	if !bytes.Equal(gotEnv.Blob, originalBlob) {
		t.Fatal("mutating the caller's blob changed stored state")
	}
}
