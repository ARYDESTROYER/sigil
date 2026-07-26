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
		if err := s.CreateDevice(ctx, d); err != nil {
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
		if err := s.CreateDevice(ctx, d); err != nil {
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
			if err := s.CreateDevice(ctx, d); err != nil {
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

	t.Run("KeyEnvelopeRejectsBadSizeAndUnknownRecipient", func(t *testing.T) {
		s := newStore(t)
		d := newTestDevice(t, "B")
		if err := s.CreateDevice(ctx, d); err != nil {
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
				if err := s.CreateDevice(ctx, d); err != nil {
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
	if err := s.CreateDevice(ctx, d); err != nil {
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
