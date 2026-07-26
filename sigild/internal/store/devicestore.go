package store

// Device registry, enrollment-token ledger, and per-vault authorization grants
// for the DEV op-log's multi-device auth model (Phase 41).
//
// This is the persistence seam behind sigild's real request authentication: a
// device is an Ed25519 public key with a server-assigned ID and a status, an
// enrollment token is an operator-provisioned single-use bearer secret recorded
// ONLY as a SHA-256 hash, and a grant maps (vaultID, deviceID) -> permission.
//
// ZERO-KNOWLEDGE INVARIANT: none of this touches vault contents. The store holds
// AUTH METADATA ONLY — public keys, IDs, labels, timestamps, permissions. It
// never sees, stores, or derives anything about the opaque client-encrypted
// blobs in the op-log, and it performs NO cryptography beyond hashing a bearer
// token so the plaintext token is never persisted.
//
// STATUS: pre-audit skeleton. Real Ed25519 verification (crypto/ed25519, in the
// api layer) over a real registry — no bypass, no placeholder credential — but
// the surrounding product model (accounts, recovery, key rotation, hardware
// attestation) does not exist yet.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

// Device-registry sentinel errors. Callers map these to HTTP outcomes; they
// carry no secret material.
var (
	// ErrDeviceNotFound is returned when no device has the requested ID.
	ErrDeviceNotFound = errors.New("store: device not found")
	// ErrDeviceExists is returned when enrolling a public key that is already
	// registered (a public key identifies at most one device).
	ErrDeviceExists = errors.New("store: device already exists")
	// ErrGrantNotFound is returned when a (vaultID, deviceID) pair has no grant.
	ErrGrantNotFound = errors.New("store: grant not found")
	// ErrEnrollTokenUnknown is returned when a presented enrollment token has
	// never been registered with this store.
	ErrEnrollTokenUnknown = errors.New("store: enrollment token unknown")
	// ErrEnrollTokenUsed is returned when a single-use enrollment token has
	// already been consumed. A token is never silently reusable.
	ErrEnrollTokenUsed = errors.New("store: enrollment token already used")
	// ErrEnrollTokenExpired is returned when a time-limited enrollment token is
	// presented after its expiry.
	ErrEnrollTokenExpired = errors.New("store: enrollment token expired")
)

// DeviceStatus is a device's lifecycle state. A revoked device is rejected on
// its very next request; the record is retained (not deleted) so the audit trail
// and any grants it holds stay explainable.
type DeviceStatus string

const (
	// DeviceActive is an enrolled device whose signatures are accepted.
	DeviceActive DeviceStatus = "active"
	// DeviceRevoked is a device whose signatures are rejected immediately.
	DeviceRevoked DeviceStatus = "revoked"
)

// Permission is the access level a grant confers on one (vaultID, deviceID)
// pair. PermWrite IMPLIES PermRead (see Allows); there is no write-only level.
type Permission string

const (
	// PermRead allows listing/verifying a vault's op-log.
	PermRead Permission = "read"
	// PermWrite allows appending to a vault's op-log, and implies PermRead.
	PermWrite Permission = "write"
)

// Allows reports whether a device holding permission p may perform an operation
// that requires need. Write implies read; read does not imply write.
func (p Permission) Allows(need Permission) bool {
	switch p {
	case PermWrite:
		return need == PermRead || need == PermWrite
	case PermRead:
		return need == PermRead
	default:
		return false
	}
}

// ValidPermission reports whether p is one of the two defined levels. Anything
// else is rejected at the API boundary rather than stored.
func ValidPermission(p Permission) bool {
	return p == PermRead || p == PermWrite
}

// Device is one enrolled client device: an Ed25519 public key with a
// server-assigned ID, an operator/user-supplied label, and a status.
//
// PublicKey is a raw 32-byte Ed25519 public key. It is PUBLIC by construction —
// but it is still never emitted to logs or metrics (see the api audit layer).
type Device struct {
	ID        string
	PublicKey []byte
	Label     string
	Status    DeviceStatus
	CreatedAt time.Time
	RevokedAt time.Time // zero unless Status == DeviceRevoked
}

// Active reports whether the device may authenticate right now.
func (d Device) Active() bool { return d.Status == DeviceActive }

// clone returns a deep copy so a caller can never mutate stored state through a
// returned Device's PublicKey slice.
func (d Device) clone() Device {
	cp := make([]byte, len(d.PublicKey))
	copy(cp, d.PublicKey)
	d.PublicKey = cp
	return d
}

// Grant authorizes one device on one vault. Owner marks the device that claimed
// the vault (see ClaimVaultOwner) — the only device allowed to grant others
// access.
type Grant struct {
	VaultID   string
	DeviceID  string
	Perm      Permission
	Owner     bool
	CreatedAt time.Time
}

// deviceIDBytes is the entropy behind a server-assigned device ID: 16 bytes
// (128 bits) of crypto/rand, rendered as raw-URL base64 so the ID is safe in a
// path segment, an HTTP header, and a SQL text column.
const deviceIDBytes = 16

// deviceIDPrefix makes a device ID self-describing in logs and audit trails.
const deviceIDPrefix = "dev_"

// NewDeviceID returns a fresh, unguessable, server-assigned device ID. IDs are
// assigned by the SERVER (never chosen by the client) so a client cannot squat
// an ID or collide with an existing device.
func NewDeviceID() (string, error) {
	raw := make([]byte, deviceIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate device id: %w", err)
	}
	return deviceIDPrefix + base64.RawURLEncoding.EncodeToString(raw), nil
}

// DeviceStore is the persistence seam for the device registry, the enrollment
// token ledger, and per-vault authorization grants. It mirrors the VaultLog
// seam: context-aware, concurrency-safe, with interchangeable backends
// (MemDeviceStore for dev/tests, PostgresDeviceStore for durability).
//
// Implementations MUST be safe for concurrent use, and the two atomic
// operations below (ConsumeEnrollmentToken, ClaimVaultOwner) MUST be atomic
// across concurrent callers AND across processes for a shared backend — they are
// the single-use and single-owner guarantees.
type DeviceStore interface {
	// CreateDevice registers d (ID, PublicKey, Label, Status, CreatedAt already
	// set by the caller). It returns ErrDeviceExists if the public key — or the
	// ID — is already registered.
	CreateDevice(ctx context.Context, d Device) error
	// GetDevice returns the device with the given ID, or ErrDeviceNotFound.
	GetDevice(ctx context.Context, deviceID string) (Device, error)
	// ListDevices returns every registered device, ordered by CreatedAt then ID.
	ListDevices(ctx context.Context) ([]Device, error)
	// RevokeDevice marks a device revoked as of at. Revoking an already-revoked
	// device is idempotent (no error, the original RevokedAt is kept). An unknown
	// device yields ErrDeviceNotFound.
	RevokeDevice(ctx context.Context, deviceID string, at time.Time) error

	// RegisterEnrollmentToken records an operator-provisioned enrollment token by
	// its SHA-256 hash (hex). It is IDEMPOTENT: re-registering a known token hash
	// keeps the original issuedAt/expiresAt and, crucially, does NOT clear a
	// used marker — so a restart can never resurrect a spent token. A zero
	// expiresAt means "no expiry".
	RegisterEnrollmentToken(ctx context.Context, tokenHash string, issuedAt, expiresAt time.Time) error
	// ConsumeEnrollmentToken atomically marks a registered token as used by
	// deviceID at now. It returns ErrEnrollTokenUnknown, ErrEnrollTokenUsed, or
	// ErrEnrollTokenExpired without consuming anything in those cases. Exactly
	// one concurrent caller can succeed for a given token.
	ConsumeEnrollmentToken(ctx context.Context, tokenHash, deviceID string, now time.Time) error

	// GetGrant returns the grant for (vaultID, deviceID), or ErrGrantNotFound.
	GetGrant(ctx context.Context, vaultID, deviceID string) (Grant, error)
	// PutGrant creates or updates a NON-OWNER grant for (vaultID, deviceID). It
	// never changes vault ownership: an existing owner grant is left untouched
	// (its permission is already the maximum).
	PutGrant(ctx context.Context, vaultID, deviceID string, perm Permission, at time.Time) error
	// ListGrants returns every grant on a vault, ordered by DeviceID.
	ListGrants(ctx context.Context, vaultID string) ([]Grant, error)
	// ClaimVaultOwner atomically makes deviceID the owner of vaultID (with
	// PermWrite) IF and ONLY IF the vault has no owner yet. It returns true when
	// this call performed the claim, false when the vault was already owned (by
	// this or any other device). This is the trust-on-first-write rule.
	ClaimVaultOwner(ctx context.Context, vaultID, deviceID string, at time.Time) (bool, error)
}

// MemDeviceStore is a concurrency-safe, in-memory DeviceStore for local dev and
// tests. It is NOT durable: every device, token marker, and grant is lost on
// restart, which for enrollment tokens means a spent token becomes usable again
// after a restart. Use the Postgres backend when that matters.
type MemDeviceStore struct {
	mu        sync.Mutex
	devices   map[string]Device            // device ID -> device
	byKey     map[string]string            // base64(pubkey) -> device ID
	tokens    map[string]*enrollTokenState // token SHA-256 hex -> state
	grants    map[string]map[string]Grant  // vault ID -> device ID -> grant
	vaultOwnr map[string]string            // vault ID -> owning device ID
}

// enrollTokenState is one registered enrollment token's ledger entry. The token
// itself is NEVER stored — only its SHA-256 hash (the map key).
type enrollTokenState struct {
	issuedAt  time.Time
	expiresAt time.Time // zero => never expires
	usedAt    time.Time // zero => unused
	usedBy    string
}

// NewMemDeviceStore returns an empty, ready-to-use in-memory device store.
func NewMemDeviceStore() *MemDeviceStore {
	return &MemDeviceStore{
		devices:   make(map[string]Device),
		byKey:     make(map[string]string),
		tokens:    make(map[string]*enrollTokenState),
		grants:    make(map[string]map[string]Grant),
		vaultOwnr: make(map[string]string),
	}
}

// compile-time check that MemDeviceStore satisfies DeviceStore.
var _ DeviceStore = (*MemDeviceStore)(nil)

// CreateDevice registers a device, rejecting a duplicate ID or public key.
func (s *MemDeviceStore) CreateDevice(ctx context.Context, d Device) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	keyID := base64.StdEncoding.EncodeToString(d.PublicKey)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[d.ID]; ok {
		return ErrDeviceExists
	}
	if _, ok := s.byKey[keyID]; ok {
		return ErrDeviceExists
	}
	s.devices[d.ID] = d.clone()
	s.byKey[keyID] = d.ID
	return nil
}

// GetDevice returns a COPY of the stored device, or ErrDeviceNotFound.
func (s *MemDeviceStore) GetDevice(ctx context.Context, deviceID string) (Device, error) {
	if err := ctx.Err(); err != nil {
		return Device{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[deviceID]
	if !ok {
		return Device{}, ErrDeviceNotFound
	}
	return d.clone(), nil
}

// ListDevices returns copies of every device, ordered by CreatedAt then ID.
func (s *MemDeviceStore) ListDevices(ctx context.Context) ([]Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	out := make([]Device, 0, len(s.devices))
	for _, d := range s.devices {
		out = append(out, d.clone())
	}
	s.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// RevokeDevice marks a device revoked. It is idempotent: an already-revoked
// device keeps its original RevokedAt.
func (s *MemDeviceStore) RevokeDevice(ctx context.Context, deviceID string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[deviceID]
	if !ok {
		return ErrDeviceNotFound
	}
	if d.Status == DeviceRevoked {
		return nil
	}
	d.Status = DeviceRevoked
	d.RevokedAt = at
	s.devices[deviceID] = d
	return nil
}

// RegisterEnrollmentToken records a token hash idempotently, never clearing an
// existing used marker.
func (s *MemDeviceStore) RegisterEnrollmentToken(ctx context.Context, tokenHash string, issuedAt, expiresAt time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tokens[tokenHash]; ok {
		return nil // already known: keep issuedAt/expiresAt AND any used marker
	}
	s.tokens[tokenHash] = &enrollTokenState{issuedAt: issuedAt, expiresAt: expiresAt}
	return nil
}

// ConsumeEnrollmentToken atomically spends a token. Unknown/expired/used tokens
// are rejected without consuming anything.
func (s *MemDeviceStore) ConsumeEnrollmentToken(ctx context.Context, tokenHash, deviceID string, now time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.tokens[tokenHash]
	if !ok {
		return ErrEnrollTokenUnknown
	}
	if !st.usedAt.IsZero() {
		return ErrEnrollTokenUsed
	}
	if !st.expiresAt.IsZero() && !now.Before(st.expiresAt) {
		return ErrEnrollTokenExpired
	}
	st.usedAt = now
	st.usedBy = deviceID
	return nil
}

// GetGrant returns the grant for (vaultID, deviceID), or ErrGrantNotFound.
func (s *MemDeviceStore) GetGrant(ctx context.Context, vaultID, deviceID string) (Grant, error) {
	if err := ctx.Err(); err != nil {
		return Grant{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.grants[vaultID][deviceID]
	if !ok {
		return Grant{}, ErrGrantNotFound
	}
	return g, nil
}

// PutGrant creates or updates a non-owner grant. An existing OWNER grant is left
// untouched (ownership is not transferable here, and PermWrite is already max).
func (s *MemDeviceStore) PutGrant(ctx context.Context, vaultID, deviceID string, perm Permission, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.grants[vaultID] == nil {
		s.grants[vaultID] = make(map[string]Grant)
	}
	if existing, ok := s.grants[vaultID][deviceID]; ok && existing.Owner {
		return nil
	}
	s.grants[vaultID][deviceID] = Grant{
		VaultID: vaultID, DeviceID: deviceID, Perm: perm, Owner: false, CreatedAt: at,
	}
	return nil
}

// ListGrants returns every grant on a vault, ordered by device ID.
func (s *MemDeviceStore) ListGrants(ctx context.Context, vaultID string) ([]Grant, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	out := make([]Grant, 0, len(s.grants[vaultID]))
	for _, g := range s.grants[vaultID] {
		out = append(out, g)
	}
	s.mu.Unlock()

	sort.Slice(out, func(i, j int) bool { return out[i].DeviceID < out[j].DeviceID })
	return out, nil
}

// ClaimVaultOwner atomically claims an unowned vault. The whole check-and-set
// runs under the single mutex, so exactly one of N concurrent claimants wins.
func (s *MemDeviceStore) ClaimVaultOwner(ctx context.Context, vaultID, deviceID string, at time.Time) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, owned := s.vaultOwnr[vaultID]; owned {
		return false, nil
	}
	s.vaultOwnr[vaultID] = deviceID
	if s.grants[vaultID] == nil {
		s.grants[vaultID] = make(map[string]Grant)
	}
	s.grants[vaultID][deviceID] = Grant{
		VaultID: vaultID, DeviceID: deviceID, Perm: PermWrite, Owner: true, CreatedAt: at,
	}
	return true, nil
}
