package store

// Device hybrid PUBLIC keys and the opaque KEY-ENVELOPE relay (Phase 46).
//
// This is the persistence seam behind DEVICE-TO-DEVICE VAULT SHARING. A shared
// vault is sealed by the CLIENT under a random 32-byte vault key; that key is
// then wrapped to each authorized device with the client's hybrid public-key
// encryption (X25519 + ML-KEM-768 -> AEAD) and the resulting OPAQUE envelope is
// parked here for the recipient to collect.
//
// ZERO-KNOWLEDGE INVARIANT — the whole point of this file:
//
//   - A hybrid public key is PUBLIC key material. The server stores and serves
//     the exact bytes it was given and performs NO cryptography with them: it
//     validates LENGTH ONLY (32 / 1184) and never parses, decodes, validates as
//     a curve point, or otherwise interprets them.
//   - A key envelope is CIPHERTEXT the server cannot read. It is stored and
//     returned VERBATIM. The server has no decapsulation key, derives nothing,
//     and never sees a vault key or any plaintext.
//
// So the relay is exactly that: a mailbox. Compromising it yields public keys,
// device IDs, and ciphertext.
//
// STATUS: pre-audit skeleton, DEV-ONLY, UNAUDITED, dev-gated at the API layer.
// There is no account model, no key rotation, no forward secrecy for an already
// delivered envelope, and no revocation of a vault key that a device already
// accepted (revoking a device stops FUTURE access; it cannot un-learn a key).

import (
	"context"
	"errors"
	"time"
)

// Key-sharing sentinel errors. They carry no secret material.
var (
	// ErrHybridKeyNotFound is returned when a device has not published a hybrid
	// public key (yet). It is distinct from ErrDeviceNotFound: the device may
	// exist and simply have no key.
	ErrHybridKeyNotFound = errors.New("store: device hybrid key not found")
	// ErrKeyEnvelopeNotFound is returned when no envelope is addressed to
	// (vaultID, recipientDeviceID).
	ErrKeyEnvelopeNotFound = errors.New("store: key envelope not found")
	// ErrHybridKeyMalformed is returned when a hybrid public key does not have
	// the exact expected byte lengths. This is the ONLY validation the server
	// performs on key material — a shape check, never an interpretation.
	ErrHybridKeyMalformed = errors.New("store: hybrid public key has the wrong shape")
	// ErrKeyEnvelopeMalformed is returned when an envelope blob is empty or
	// exceeds MaxKeyEnvelopeBytes. The CONTENT is never inspected.
	ErrKeyEnvelopeMalformed = errors.New("store: key envelope blob has the wrong size")
)

// Fixed byte lengths of the two halves of a hybrid public key. They are the
// FIPS 203 / RFC 7748 sizes the client's hybrid KEM uses, recorded here ONLY so
// the server can reject an obviously malformed upload. The server does not know
// (and does not care) what is inside them.
const (
	// X25519PublicKeyLen is the raw X25519 public key length.
	X25519PublicKeyLen = 32
	// MLKEM768EncapsKeyLen is the ML-KEM-768 (FIPS 203) encapsulation key length.
	MLKEM768EncapsKeyLen = 1184
)

// MaxKeyEnvelopeBytes caps one wrapped-vault-key envelope. The client's hybrid
// container for a 32-byte vault key is ~1.2 KiB (8 magic + 1 version + 32
// ephemeral X25519 public key + 1088 ML-KEM ciphertext + a small AEAD envelope),
// so this is generous headroom while keeping the relay from being used as a blob
// store. Enforced at BOTH the API boundary (413) and here (defence in depth).
const MaxKeyEnvelopeBytes = 16 << 10 // 16 KiB

// HybridPublicKey is one device's PUBLISHED hybrid public key: the public half
// of its X25519 + ML-KEM-768 identity, which other devices encrypt a wrapped
// vault key to.
//
// Both fields are OPAQUE PUBLIC bytes to this server. They are stored and served
// verbatim.
type HybridPublicKey struct {
	DeviceID string
	// X25519PublicKey is exactly X25519PublicKeyLen raw bytes.
	X25519PublicKey []byte
	// MLKEMEncapsKey is exactly MLKEM768EncapsKeyLen raw bytes.
	MLKEMEncapsKey []byte
	// UpdatedAt is when this key was (re-)published.
	UpdatedAt time.Time
}

// clone returns a deep copy so a caller can never mutate stored state through a
// returned key's slices.
func (k HybridPublicKey) clone() HybridPublicKey {
	x := make([]byte, len(k.X25519PublicKey))
	copy(x, k.X25519PublicKey)
	m := make([]byte, len(k.MLKEMEncapsKey))
	copy(m, k.MLKEMEncapsKey)
	k.X25519PublicKey = x
	k.MLKEMEncapsKey = m
	return k
}

// ValidateHybridPublicKey performs the ONLY check the server makes on published
// key material: that each half has its exact expected length. It does NOT decode
// a curve point, check for a low-order/identity element, or verify that the two
// halves belong together — that is the CLIENT's business, and doing it here
// would be the server performing cryptography on user key material.
func ValidateHybridPublicKey(k HybridPublicKey) error {
	if len(k.X25519PublicKey) != X25519PublicKeyLen || len(k.MLKEMEncapsKey) != MLKEM768EncapsKeyLen {
		return ErrHybridKeyMalformed
	}
	return nil
}

// KeyEnvelope is one wrapped vault key addressed to one device.
//
// Blob is CIPHERTEXT the server cannot read: the client's hybrid-sealed
// container holding the 32-byte vault key. The server stores and returns those
// exact bytes and performs no cryptography on them. SenderDeviceID is metadata
// for the audit trail — it is the device the server AUTHENTICATED when the
// envelope was uploaded, not a claim carried inside the blob.
type KeyEnvelope struct {
	VaultID           string
	RecipientDeviceID string
	SenderDeviceID    string
	Blob              []byte
	CreatedAt         time.Time
}

// clone returns a deep copy so a caller cannot mutate stored bytes.
func (e KeyEnvelope) clone() KeyEnvelope {
	b := make([]byte, len(e.Blob))
	copy(b, e.Blob)
	e.Blob = b
	return e
}

// ValidateKeyEnvelope checks the envelope's SIZE only — never its content. An
// empty blob is rejected (an empty envelope can only be a client bug) and an
// oversized one is rejected so the relay is not a general blob store.
func ValidateKeyEnvelope(e KeyEnvelope) error {
	if len(e.Blob) == 0 || len(e.Blob) > MaxKeyEnvelopeBytes {
		return ErrKeyEnvelopeMalformed
	}
	return nil
}

// KeySharing is the storage seam for device hybrid public keys and the opaque
// key-envelope relay. It is embedded in DeviceStore so both backends implement
// it, and it is held to one backend-agnostic conformance suite.
//
// Implementations MUST be safe for concurrent use.
type KeySharing interface {
	// PutDeviceHybridKey publishes (or REPUBLISHES) a device's hybrid public
	// key. It is an UPSERT keyed by DeviceID: re-publishing replaces the stored
	// key and refreshes UpdatedAt. It returns ErrHybridKeyMalformed for a
	// wrong-shaped key and ErrDeviceNotFound when the device is not registered.
	//
	// Republishing does NOT re-wrap any already-delivered envelope: envelopes
	// sealed to the OLD key stay as they are, and a recipient that rotated its
	// key must be re-shared to.
	PutDeviceHybridKey(ctx context.Context, k HybridPublicKey) error
	// GetDeviceHybridKey returns a device's published hybrid public key, or
	// ErrHybridKeyNotFound when it has not published one.
	GetDeviceHybridKey(ctx context.Context, deviceID string) (HybridPublicKey, error)

	// PutKeyEnvelope stores an opaque wrapped vault key addressed to
	// (VaultID, RecipientDeviceID). It is an UPSERT on that pair: re-sharing a
	// vault to the same device replaces the envelope (the sender may have
	// re-keyed the vault). It returns ErrKeyEnvelopeMalformed for a bad size and
	// ErrDeviceNotFound when the recipient is not registered.
	PutKeyEnvelope(ctx context.Context, e KeyEnvelope) error
	// GetKeyEnvelope returns the envelope addressed to (vaultID,
	// recipientDeviceID) with its Blob EXACTLY as stored, or
	// ErrKeyEnvelopeNotFound.
	GetKeyEnvelope(ctx context.Context, vaultID, recipientDeviceID string) (KeyEnvelope, error)
}

// ---------------------------------------------------------------------------
// In-memory implementation (MemDeviceStore).
// ---------------------------------------------------------------------------

// envelopeKey is the composite map key for the (vaultID, recipientDeviceID)
// mailbox address.
type envelopeKey struct {
	vaultID   string
	recipient string
}

// PutDeviceHybridKey publishes/republishes a device's hybrid public key.
func (s *MemDeviceStore) PutDeviceHybridKey(ctx context.Context, k HybridPublicKey) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateHybridPublicKey(k); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[k.DeviceID]; !ok {
		return ErrDeviceNotFound
	}
	s.hybridKeys[k.DeviceID] = k.clone()
	return nil
}

// GetDeviceHybridKey returns a COPY of the published key, or
// ErrHybridKeyNotFound.
func (s *MemDeviceStore) GetDeviceHybridKey(ctx context.Context, deviceID string) (HybridPublicKey, error) {
	if err := ctx.Err(); err != nil {
		return HybridPublicKey{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.hybridKeys[deviceID]
	if !ok {
		return HybridPublicKey{}, ErrHybridKeyNotFound
	}
	return k.clone(), nil
}

// PutKeyEnvelope stores/replaces the envelope addressed to (vault, recipient).
func (s *MemDeviceStore) PutKeyEnvelope(ctx context.Context, e KeyEnvelope) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := ValidateKeyEnvelope(e); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[e.RecipientDeviceID]; !ok {
		return ErrDeviceNotFound
	}
	s.envelopes[envelopeKey{vaultID: e.VaultID, recipient: e.RecipientDeviceID}] = e.clone()
	return nil
}

// GetKeyEnvelope returns a COPY of the stored envelope, byte-identical to what
// was uploaded, or ErrKeyEnvelopeNotFound.
func (s *MemDeviceStore) GetKeyEnvelope(ctx context.Context, vaultID, recipientDeviceID string) (KeyEnvelope, error) {
	if err := ctx.Err(); err != nil {
		return KeyEnvelope{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.envelopes[envelopeKey{vaultID: vaultID, recipient: recipientDeviceID}]
	if !ok {
		return KeyEnvelope{}, ErrKeyEnvelopeNotFound
	}
	return e.clone(), nil
}
