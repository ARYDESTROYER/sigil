package store

// Accounts: the subject of ENTITLEMENT and the OWNER of vaults (Phase 52).
//
// WHY THIS EXISTS. Before this file, a subscription was bought by a DEVICE and a
// vault was owned by a DEVICE. Both are defects for a paid, multi-device
// product: a customer who paid on their phone was not entitled on their laptop,
// and revoking a vault's owner ORPHANED the vault because there was no larger
// subject to fall back to. An account is that larger subject.
//
// THE WHOLE MODEL IN ONE SENTENCE: an account is a server-assigned ID on a
// device row; a single-use INVITE minted by a member device is the only way a
// second device gets that same ID; entitlement and vault ownership key off that
// ID instead of the device ID.
//
// AUTH METADATA ONLY. There is no email, no password, no session, no PII, no key
// material and no recovery here. An account confers AUTHORIZATION, never
// DECRYPTION: a joined device can authenticate and see its entitlement, and can
// read nothing until an existing member wraps the vault key to its hybrid public
// key (a deliberate client-side action — see keysharing.go and ADR 0035). The
// zero-knowledge boundary is untouched: nothing in this file sees a vault key, a
// password or a plaintext, and an invite is recorded ONLY as a SHA-256 digest.
//
// NO REQUEST ANYWHERE NAMES AN ACCOUNT. The API layer always derives the account
// from the verified signer's device row, so there is no path, query or body field
// that can steer which account an operation lands in.
//
// HONEST LIMITS (do not soften): membership is FLAT (any member may invite,
// revoke any sibling, run checkout and administer every account-owned vault) and
// IMMUTABLE (no transfer, no merge, no deletion). There is NO RECOVERY: lose or
// revoke every device in an account and the account is permanently unreachable.
// Trust-on-first-write did not go away, it moved up one level — the first
// ACCOUNT to write an unclaimed vault owns it. Still dev-gated, pre-audit,
// UNAUDITED.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Account-model sentinel errors. Like the device sentinels they carry no secret
// material; the API layer maps them onto a COARSE client response and reports
// the fine-grained cause only to the audit log.
var (
	// ErrAccountNotFound is returned when no account has the requested ID.
	ErrAccountNotFound = errors.New("store: account not found")
	// ErrInviteUnknown is returned when a presented invite digest matches no
	// stored invite.
	ErrInviteUnknown = errors.New("store: account invite unknown")
	// ErrInviteUsed is returned when an invite has already been redeemed. An
	// invite is SINGLE-SUCCESS: consumption and the device insert are one atomic
	// operation, so exactly one device can ever join with it.
	ErrInviteUsed = errors.New("store: account invite already used")
	// ErrInviteExpired is returned when an invite is presented after its TTL.
	ErrInviteExpired = errors.New("store: account invite expired")
	// ErrInviteRevoked is returned when an invite was revoked before use.
	ErrInviteRevoked = errors.New("store: account invite revoked")
	// ErrInviteKeyMismatch is returned when a PINNED invite (one bound to a
	// specific invitee public key) is presented by a different key.
	ErrInviteKeyMismatch = errors.New("store: account invite is pinned to another key")
	// ErrInviterInactive is returned when the device that minted the invite has
	// since been revoked. Revoking a device kills its outstanding invitations.
	ErrInviterInactive = errors.New("store: inviting device is not active")
	// ErrInviteLimit is returned when an account already holds the maximum number
	// of OPEN invites.
	ErrInviteLimit = errors.New("store: account has too many open invites")
	// ErrAccountFull is returned when an account already holds the maximum number
	// of member devices.
	ErrAccountFull = errors.New("store: account has reached its device limit")
	// ErrVaultOwnerNotFound is returned when a vault has never been claimed.
	ErrVaultOwnerNotFound = errors.New("store: vault owner not found")
	// ErrVaultOwnerUnresolved is returned by ClaimVault when a vault is in the
	// ORPHANED-OWNER state — it carries a legacy is_owner GRANT but no owner row,
	// and the granted device cannot be resolved to an account (it is gone, or its
	// account_id is NULL because a pre-0005 binary enrolled it).
	//
	// That state cannot be claimed (inserting a second is_owner grant would
	// collide with the partial unique index sigil_device_grants_one_owner) and it
	// cannot be reconciled (there is no account to adopt), so it is refused
	// EXPLICITLY rather than surfacing as an opaque database error. The repair is
	// `sigild migrate adopt`, which gives the orphaned device an account; the
	// reconciliation then succeeds on the next write.
	ErrVaultOwnerUnresolved = errors.New("store: vault has an owner grant but no resolvable owning account")
	// ErrInviteExists is returned when an invite digest is already stored. It is
	// unreachable in practice (an invite secret is 256 bits of crypto/rand) and
	// exists so a collision can never silently overwrite an outstanding invite.
	ErrInviteExists = errors.New("store: account invite already exists")
)

// Account is one billing/ownership subject: a server-assigned ID and nothing
// else that could identify a human.
//
// CreatedByDeviceID is AUDIT METADATA ONLY. It records which device founded the
// account so an operator can explain the trail; it confers NO power whatsoever —
// membership is flat, and the founder has exactly the same rights as any device
// that later joined by invite.
type Account struct {
	ID                string
	CreatedAt         time.Time
	CreatedByDeviceID string
}

// VaultOwner is the AUTHORITY on who owns a vault: an (accountID) claim on a
// vault ID, made by the first account to write it (trust-on-first-write, one
// level up from the device model it replaces).
//
// The matching is_owner row in sigil_device_grants is the per-DEVICE VIEW of the
// same fact, retained so GET /v1/vaults/{id}/grants stays byte-identical for
// existing data and existing clients. No authorization decision reads is_owner.
type VaultOwner struct {
	VaultID           string
	AccountID         string
	ClaimedByDeviceID string
	ClaimedAt         time.Time
}

// AccountInvite is a single-use credential that lets ONE more device join an
// existing account.
//
// InviteHash is the lowercase-hex SHA-256 of the invite secret. The SECRET
// ITSELF IS NEVER STORED, never logged, never re-served, and never appears in a
// metric; it is returned exactly once, in the 201 that minted it. InviteHash is
// likewise never returned by any List method (it is a bearer-equivalent lookup
// key), which is what InviteID exists for: a PUBLIC handle for listing and
// revocation.
//
// InviteePublicKey, when non-nil, PINS the invite to one Ed25519 public key so
// an intercepted invite cannot be redeemed by anyone else. Nothing forces
// pinning; an unpinned invite is a bearer secret for its TTL.
type AccountInvite struct {
	InviteHash        string
	InviteID          string
	AccountID         string
	CreatedByDeviceID string
	InviteePublicKey  []byte
	CreatedAt         time.Time
	ExpiresAt         time.Time
	UsedAt            time.Time
	UsedByDeviceID    string
	RevokedAt         time.Time
}

// Open reports whether the invite could still be redeemed at now: unused,
// unrevoked and inside its TTL. It says nothing about the inviter's status or
// the account's device cap — those are checked atomically at redemption.
func (i AccountInvite) Open(now time.Time) bool {
	return i.UsedAt.IsZero() && i.RevokedAt.IsZero() && i.ExpiresAt.After(now)
}

// Pinned reports whether the invite is bound to a specific invitee public key.
func (i AccountInvite) Pinned() bool { return len(i.InviteePublicKey) > 0 }

// clone returns a deep copy so a caller can never mutate stored state through a
// returned invite's key slice.
func (i AccountInvite) clone() AccountInvite {
	if i.InviteePublicKey != nil {
		cp := make([]byte, len(i.InviteePublicKey))
		copy(cp, i.InviteePublicKey)
		i.InviteePublicKey = cp
	}
	return i
}

// redacted returns a copy with the digest ZEROED, for anything that leaves the
// store. The digest is the redemption lookup key; a listing endpoint has no
// business handing it back out.
func (i AccountInvite) redacted() AccountInvite {
	c := i.clone()
	c.InviteHash = ""
	return c
}

// accountIDBytes is the entropy behind a server-assigned account ID: 16 bytes
// (128 bits) of crypto/rand, matching NewDeviceID.
const accountIDBytes = 16

// accountIDPrefix makes an account ID self-describing in an audit trail.
const accountIDPrefix = "acct_"

// AdoptedAccountPrefix marks an account created by migration 0005's ADOPTION
// step: every device enrolled before accounts existed was given its own
// singleton account, named deterministically from its device ID so the backfill
// is a pure function (no RNG in SQL, re-runnable) and an adopted account is
// self-evident in an audit trail.
//
// NewAccountID refuses to return an ID with this prefix, so a freshly generated
// account can never silently MERGE into a migrated one.
const AdoptedAccountPrefix = accountIDPrefix + "mig_"

// AdoptedAccountID returns the account ID migration 0005 assigns to a
// pre-existing device. It is exported so tests (and an operator reading the
// runbook) can reproduce the backfill without re-deriving the string in SQL.
func AdoptedAccountID(deviceID string) string { return AdoptedAccountPrefix + deviceID }

// NewAccountID returns a fresh, unguessable, server-assigned account ID.
//
// An account ID is an IDENTIFIER, never a credential: no request names an
// account, so predicting one buys nothing. It is generated from crypto/rand
// anyway, and is checked against AdoptedAccountPrefix so a generated ID can
// never collide with migration 0005's deterministic adopted namespace.
func NewAccountID() (string, error) {
	raw := make([]byte, accountIDBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate account id: %w", err)
	}
	return newAccountIDFrom(raw)
}

// newAccountIDFrom builds an account ID from caller-supplied entropy. Split out
// so the adopted-prefix guard is testable without waiting on a 1-in-16-million
// random draw.
func newAccountIDFrom(raw []byte) (string, error) {
	id := accountIDPrefix + base64.RawURLEncoding.EncodeToString(raw)
	if strings.HasPrefix(id, AdoptedAccountPrefix) {
		// Fail closed rather than hand back an ID that would look like — and could
		// merge with — a migration-adopted account.
		return "", errors.New("generate account id: collided with the adopted-account prefix")
	}
	return id, nil
}

// Accounts is the persistence seam for the account model. It is EMBEDDED into
// DeviceStore (exactly as KeySharing already is) because it lives in the same
// auth-metadata store, shares its backends, and is held to one backend-agnostic
// conformance suite.
//
// Implementations MUST be safe for concurrent use, and the two ATOMIC operations
// below (JoinAccountWithInvite, ClaimVault) MUST be atomic across concurrent
// callers AND across processes for a shared backend — they are the
// single-success and single-owner guarantees.
type Accounts interface {
	// GetAccount returns the account with the given ID, or ErrAccountNotFound.
	GetAccount(ctx context.Context, accountID string) (Account, error)
	// ListAccountDevices returns every device in an account (active AND revoked),
	// ordered by CreatedAt then ID (byte-wise on ID in every backend).
	ListAccountDevices(ctx context.Context, accountID string) ([]Device, error)
	// CountActiveAccountDevices returns how many ACTIVE (non-revoked) devices an
	// account holds.
	//
	// THIS — NOT len(ListAccountDevices) — IS WHAT THE DEVICE CAP MEANS. The cap
	// bounds CONCURRENT devices, so a revoked device frees its seat. Counting
	// revoked rows would turn it into a lifetime-enrollment cap that no operation
	// anywhere could ever reverse.
	CountActiveAccountDevices(ctx context.Context, accountID string) (int, error)

	// CreateAccountWithFounder atomically creates an account and its FIRST
	// device. It is used ONLY by operator-token enrollment: an operator token
	// always founds a NEW account, never joins an existing one. A duplicate
	// device ID or public key yields ErrDeviceExists and leaves NO orphan
	// account behind.
	CreateAccountWithFounder(ctx context.Context, a Account, d Device) error

	// JoinAccountWithInvite atomically redeems an invite AND inserts the joining
	// device AND enforces the account's member cap.
	//
	// ATOMICITY IS THE POINT: consumption and insertion are one operation, so N
	// concurrent redemptions of one invite create exactly ONE device, and a
	// failed insert leaves the invite USABLE (invites are single-SUCCESS, unlike
	// operator enrollment tokens, which stay deliberately single-ATTEMPT).
	//
	// It returns the REDEEMED invite so the API layer can name the account, the
	// inviter and the PUBLIC invite handle in its audit record without a second
	// (racy) lookup — the redeemed invite is no longer "open", so it could not be
	// read back afterwards. The returned InviteHash is ZEROED: the redemption
	// digest never leaves the store.
	//
	// It returns, without consuming anything: ErrInviteUnknown, ErrInviteRevoked,
	// ErrInviteUsed, ErrInviteExpired, ErrInviteKeyMismatch, ErrInviterInactive,
	// ErrAccountFull, or ErrDeviceExists.
	JoinAccountWithInvite(ctx context.Context, inviteHash string, d Device, maxDevices int, now time.Time) (AccountInvite, error)

	// CreateAccountInvite records a new invite by DIGEST, refusing with
	// ErrInviteLimit when the account already holds maxOpen open invites.
	CreateAccountInvite(ctx context.Context, inv AccountInvite, maxOpen int) error
	// ListAccountInvites returns the account's OPEN invites at now, ordered by
	// CreatedAt then InviteID. Every returned row has InviteHash ZEROED — the
	// redemption digest never leaves the store.
	ListAccountInvites(ctx context.Context, accountID string, now time.Time) ([]AccountInvite, error)
	// RevokeAccountInvite revokes an unredeemed invite, scoped by BOTH accountID
	// and inviteID so a foreign invite ID and a missing one are indistinguishable
	// (both ErrInviteUnknown).
	RevokeAccountInvite(ctx context.Context, accountID, inviteID string, at time.Time) error

	// ClaimVault atomically makes accountID the owner of vaultID IF AND ONLY IF
	// the vault has no owner yet, and writes the matching is_owner grant row for
	// deviceID in the SAME operation (the dual write). It returns claimed=true
	// when this call performed the claim; when claimed=false the returned
	// VaultOwner names the WINNER, so a caller can tell a lost race against a
	// SIBLING (legitimate — allow) from one against a stranger (deny).
	//
	// IT ALSO RECONCILES THE ORPHANED-OWNER STATE: a vault carrying a legacy
	// is_owner GRANT but no owner row (a claim made by a pre-0005 binary during a
	// rolling deploy or a rollback window) has a KNOWABLE owner — the account of
	// the device holding that grant — so it is ADOPTED and returned with
	// claimed=false. Claiming it for the caller instead would attempt a second
	// is_owner grant, which the partial unique index rejects, and a legitimately
	// granted writer would be refused with an unexplained 500. When that device
	// cannot be resolved to an account the state is refused explicitly with
	// ErrVaultOwnerUnresolved (see `sigild migrate adopt`).
	ClaimVault(ctx context.Context, vaultID, accountID, deviceID string, at time.Time) (claimed bool, owner VaultOwner, err error)
	// GetVaultOwner returns a vault's owning account, or ErrVaultOwnerNotFound
	// when the vault has never been claimed.
	GetVaultOwner(ctx context.Context, vaultID string) (VaultOwner, error)
}

// ---------------------------------------------------------------------------
// In-memory implementation (MemDeviceStore).
// ---------------------------------------------------------------------------

// GetAccount returns a copy of the stored account, or ErrAccountNotFound.
func (s *MemDeviceStore) GetAccount(ctx context.Context, accountID string) (Account, error) {
	if err := ctx.Err(); err != nil {
		return Account{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[accountID]
	if !ok {
		return Account{}, ErrAccountNotFound
	}
	return a, nil
}

// ListAccountDevices returns every device in the account, ordered by CreatedAt
// then ID. An unknown account yields an empty slice, not an error: the API layer
// only ever asks about the caller's OWN account, which exists by construction.
func (s *MemDeviceStore) ListAccountDevices(ctx context.Context, accountID string) ([]Device, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	out := make([]Device, 0, len(s.devices))
	for _, d := range s.devices {
		if d.AccountID == accountID {
			out = append(out, d.clone())
		}
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

// countActiveMembersLocked returns how many ACTIVE devices an account holds. It
// assumes s.mu is held. It is the ONE definition of "a seat" for the in-memory
// backend, so the cap enforced at redemption and the count reported by
// GET /v1/account can never disagree.
func (s *MemDeviceStore) countActiveMembersLocked(accountID string) int {
	n := 0
	for _, dev := range s.devices {
		if dev.AccountID == accountID && dev.Active() {
			n++
		}
	}
	return n
}

// CountActiveAccountDevices returns how many ACTIVE (non-revoked) devices an
// account holds — the number the device cap is measured against. It is separate
// from ListAccountDevices, which deliberately returns active AND revoked rows so
// an operator can still see the full history.
func (s *MemDeviceStore) CountActiveAccountDevices(ctx context.Context, accountID string) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.countActiveMembersLocked(accountID), nil
}

// CreateAccountWithFounder creates the account and its first device under the
// single mutex, so the pair is atomic: a rejected device leaves no account.
func (s *MemDeviceStore) CreateAccountWithFounder(ctx context.Context, a Account, d Device) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.ID == "" {
		return errors.New("store: account id is required")
	}
	if d.AccountID != a.ID {
		return errors.New("store: founder device must carry the new account id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.insertDeviceLocked(d); err != nil {
		return err
	}
	if _, exists := s.accounts[a.ID]; !exists {
		s.accounts[a.ID] = a
	}
	return nil
}

// JoinAccountWithInvite redeems an invite and inserts the device under ONE
// mutex. The device insert happens BEFORE the invite is marked used, so a
// rejected device (duplicate key) leaves the invite usable — single-SUCCESS.
func (s *MemDeviceStore) JoinAccountWithInvite(ctx context.Context, inviteHash string, d Device, maxDevices int, now time.Time) (AccountInvite, error) {
	if err := ctx.Err(); err != nil {
		return AccountInvite{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	inv, ok := s.invites[inviteHash]
	if !ok {
		return AccountInvite{}, ErrInviteUnknown
	}
	if !inv.RevokedAt.IsZero() {
		return AccountInvite{}, ErrInviteRevoked
	}
	if !inv.UsedAt.IsZero() {
		return AccountInvite{}, ErrInviteUsed
	}
	if !inv.ExpiresAt.After(now) {
		return AccountInvite{}, ErrInviteExpired
	}
	if inv.Pinned() && !bytes.Equal(inv.InviteePublicKey, d.PublicKey) {
		return AccountInvite{}, ErrInviteKeyMismatch
	}
	inviter, known := s.devices[inv.CreatedByDeviceID]
	if !known || !inviter.Active() {
		return AccountInvite{}, ErrInviterInactive
	}
	// THE CAP COUNTS CONCURRENT DEVICES, NOT LIFETIME ENROLLMENTS. Revoked rows
	// are excluded, so revoking a device FREES its seat. Counting them would make
	// the limit a lifetime cap, which would be a trap rather than a limit: every
	// remedy this model prescribes (a compromised device, a device that joined the
	// wrong account, a lost phone) is "revoke and re-enroll", and each one would
	// burn a seat permanently until the account could never enroll again — with
	// nothing anywhere able to free one.
	if s.countActiveMembersLocked(inv.AccountID) >= maxDevices {
		return AccountInvite{}, ErrAccountFull
	}

	d.AccountID = inv.AccountID
	if err := s.insertDeviceLocked(d); err != nil {
		return AccountInvite{}, err
	}
	inv.UsedAt = now
	inv.UsedByDeviceID = d.ID
	return inv.redacted(), nil
}

// CreateAccountInvite records an invite by digest, enforcing the per-account
// open-invite cap under the same mutex that counts it.
func (s *MemDeviceStore) CreateAccountInvite(ctx context.Context, inv AccountInvite, maxOpen int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if inv.InviteHash == "" || inv.InviteID == "" || inv.AccountID == "" {
		return errors.New("store: invite requires a digest, an id and an account")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.accounts[inv.AccountID]; !ok {
		return ErrAccountNotFound
	}
	if _, dup := s.invites[inv.InviteHash]; dup {
		return ErrInviteExists
	}
	open := 0
	for _, existing := range s.invites {
		if existing.AccountID == inv.AccountID && existing.Open(inv.CreatedAt) {
			open++
		}
	}
	if open >= maxOpen {
		return ErrInviteLimit
	}
	cp := inv.clone()
	s.invites[inv.InviteHash] = &cp
	return nil
}

// ListAccountInvites returns the account's OPEN invites with the digest zeroed.
func (s *MemDeviceStore) ListAccountInvites(ctx context.Context, accountID string, now time.Time) ([]AccountInvite, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	out := make([]AccountInvite, 0, len(s.invites))
	for _, inv := range s.invites {
		if inv.AccountID == accountID && inv.Open(now) {
			out = append(out, inv.redacted())
		}
	}
	s.mu.Unlock()

	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].InviteID < out[j].InviteID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out, nil
}

// RevokeAccountInvite revokes an unredeemed invite scoped to (account, id).
func (s *MemDeviceStore) RevokeAccountInvite(ctx context.Context, accountID, inviteID string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, inv := range s.invites {
		if inv.AccountID != accountID || inv.InviteID != inviteID {
			continue
		}
		if !inv.UsedAt.IsZero() || !inv.RevokedAt.IsZero() {
			return ErrInviteUnknown
		}
		inv.RevokedAt = at
		return nil
	}
	return ErrInviteUnknown
}

// ClaimVault atomically claims an unowned vault for an ACCOUNT and writes the
// matching per-device is_owner grant. The whole check-and-set runs under the
// single mutex, so exactly one of N concurrent claimants wins and every loser is
// told WHO won.
func (s *MemDeviceStore) ClaimVault(ctx context.Context, vaultID, accountID, deviceID string, at time.Time) (bool, VaultOwner, error) {
	if err := ctx.Err(); err != nil {
		return false, VaultOwner{}, err
	}
	if accountID == "" {
		return false, VaultOwner{}, errors.New("store: claim requires an account id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if owner, owned := s.vaultOwners[vaultID]; owned {
		return false, owner, nil
	}

	// RECONCILE THE ORPHANED-OWNER STATE before claiming. A vault claimed by a
	// pre-0005 binary (a rolling deploy, or a rollback window) has an is_owner
	// GRANT and no owner row. Its owner is knowable — it is the account of the
	// device holding that grant — so adopt it instead of claiming for the caller.
	// Claiming would try to write a SECOND is_owner grant, which the partial
	// unique index rejects, and the caller (possibly a legitimately granted
	// writer) would see an unexplained 500.
	if legacy, found := s.ownerGrantDeviceLocked(vaultID); found {
		dev, known := s.devices[legacy]
		if !known || dev.AccountID == "" {
			return false, VaultOwner{}, ErrVaultOwnerUnresolved
		}
		adopted := VaultOwner{
			VaultID:           vaultID,
			AccountID:         dev.AccountID,
			ClaimedByDeviceID: legacy,
			ClaimedAt:         at,
		}
		s.vaultOwners[vaultID] = adopted
		// claimed=false: this call did not claim the vault, it recorded an
		// ownership that already existed. The caller is then authorized exactly as
		// it would have been against any pre-existing owner.
		return false, adopted, nil
	}

	owner := VaultOwner{
		VaultID:           vaultID,
		AccountID:         accountID,
		ClaimedByDeviceID: deviceID,
		ClaimedAt:         at,
	}
	s.vaultOwners[vaultID] = owner
	if s.grants[vaultID] == nil {
		s.grants[vaultID] = make(map[string]Grant)
	}
	s.grants[vaultID][deviceID] = Grant{
		VaultID: vaultID, DeviceID: deviceID, Perm: PermWrite, Owner: true, CreatedAt: at,
	}
	return true, owner, nil
}

// ownerGrantDeviceLocked returns the device ID of the vault's legacy is_owner
// grant, if there is one. It assumes s.mu is held. There can be at most one (the
// Postgres backend enforces it with a partial unique index, and this backend
// only ever writes one), so the lowest ID is returned for determinism.
func (s *MemDeviceStore) ownerGrantDeviceLocked(vaultID string) (string, bool) {
	found := ""
	for deviceID, g := range s.grants[vaultID] {
		if g.Owner && (found == "" || deviceID < found) {
			found = deviceID
		}
	}
	return found, found != ""
}

// GetVaultOwner returns the vault's owning account, or ErrVaultOwnerNotFound.
func (s *MemDeviceStore) GetVaultOwner(ctx context.Context, vaultID string) (VaultOwner, error) {
	if err := ctx.Err(); err != nil {
		return VaultOwner{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	owner, ok := s.vaultOwners[vaultID]
	if !ok {
		return VaultOwner{}, ErrVaultOwnerNotFound
	}
	return owner, nil
}
