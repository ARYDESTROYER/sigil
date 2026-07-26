package store

// Subscription persistence for the billing layer (Phase 45).
//
// TWO THINGS LIVE HERE, and they are deliberately fused into ONE atomic
// operation (ApplyWebhookEvent):
//
//  1. the SUBSCRIPTION record for a subject — provider, provider-side customer
//     and subscription references, status, current-period-end, timestamps; and
//  2. the PROCESSED-EVENTS ledger, keyed by (provider, event_id).
//
// They are fused because a payment provider WILL deliver the same webhook more
// than once — that is the documented behaviour of every provider here, not an
// edge case — and "record that we handled it" and "apply what it says" must
// either both happen or neither. Split across two calls, a crash in between
// either double-applies an event or loses one. As one operation (one mutex in
// memory, one transaction in Postgres) a duplicate delivery is a guaranteed
// no-op.
//
// WHAT IS NEVER STORED: no card number, no CVV, no expiry, no cardholder name,
// no billing address, no email, no phone. There is no column, field or parameter
// that could carry one. Every payment instrument detail lives with the provider,
// because sigild only ever uses HOSTED checkout. The provider references stored
// here are opaque handles, useful for reconciling against a dashboard and
// useless for charging anyone.
//
// ZERO-KNOWLEDGE, unchanged: nothing here reads, writes or derives anything
// about a vault blob.
//
// STATUS: pre-audit. Real state machine, real idempotency, real durability —
// but no invoicing, no proration, no dunning, no tax, no refunds.

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/billing"
)

// ErrSubscriptionNotFound is returned when a subject has no subscription
// record. Callers normally translate it to billing.StatusNone rather than an
// error: "never subscribed" is a valid answer, not a fault.
var ErrSubscriptionNotFound = errors.New("store: subscription not found")

// Subscription is one subject's billing record.
//
// Subject is OUR identifier for the payer (in the current dev model, the
// enrolled device ID that ran checkout). CustomerRef/SubscriptionRef are the
// PROVIDER's opaque handles.
type Subscription struct {
	Subject          string
	Provider         string
	CustomerRef      string
	SubscriptionRef  string
	Status           billing.Status
	CurrentPeriodEnd time.Time
	// LastEventAt is the OccurredAt of the most recent event applied. It is the
	// ordering guard: a delivery older than this is stale and is discarded, so an
	// out-of-order "payment failed" cannot regress a subscription that has since
	// gone active.
	LastEventAt time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// SubscriptionEvent is a normalized billing event ready to be applied. The API
// layer builds it from a billing.Event: the provider adapter decides WHAT
// happened, the API layer decides which STATUS that targets, and the store
// decides whether the transition is allowed and whether it has already been
// seen.
type SubscriptionEvent struct {
	// Provider + EventID form the idempotency key.
	Provider string
	EventID  string
	// EventType is the normalized type, recorded in the ledger for auditability.
	EventType string
	// Subject is our subject reference when the provider echoed one back. When
	// EMPTY, the store resolves the subject from (Provider, SubscriptionRef).
	Subject string
	// CustomerRef / SubscriptionRef are the provider's handles. SubscriptionRef
	// doubles as the fallback lookup key for subject resolution.
	CustomerRef     string
	SubscriptionRef string
	// Target is the status this event drives the subscription to.
	Target billing.Status
	// OccurredAt is the provider's event timestamp, used for the staleness
	// guard. Zero means "unknown", which is treated as never-stale.
	OccurredAt time.Time
	// CurrentPeriodEnd is the new paid-through date, when known.
	CurrentPeriodEnd time.Time
}

// ApplyResult is the verdict of ApplyWebhookEvent. Every one of these is a
// SUCCESSFUL outcome at the HTTP layer (a 200): a provider must never be given a
// non-2xx for an event we understood, or it enters a retry/backoff loop.
type ApplyResult string

const (
	// ApplyApplied: the event was fresh, legal and in order; state changed.
	ApplyApplied ApplyResult = "applied"
	// ApplyDuplicate: (provider, event_id) was already processed. No state
	// change — this is the idempotency guarantee.
	ApplyDuplicate ApplyResult = "duplicate"
	// ApplyStale: the event predates the last one applied. No state change.
	ApplyStale ApplyResult = "stale"
	// ApplyIllegal: the transition is not legal from the current status (e.g. a
	// renewal for a subject that never subscribed). No state change. Recorded as
	// processed so a redelivery is cheap.
	ApplyIllegal ApplyResult = "illegal"
	// ApplyUnresolved: the event named no subject and none could be resolved
	// from its subscription reference. No state change, and deliberately NOT
	// recorded as processed — a later event may establish the binding.
	ApplyUnresolved ApplyResult = "unresolved"
)

// ApplyOutcome reports what ApplyWebhookEvent did. From/To are the statuses
// involved (equal when nothing moved); Subscription is the record AFTER the
// call, zero-valued when there is none.
type ApplyOutcome struct {
	Result       ApplyResult
	From         billing.Status
	To           billing.Status
	Subscription Subscription
}

// Changed reports whether this outcome moved the subscription's status. Used for
// the transition metric/audit line, which must fire once per real transition and
// never for a duplicate.
func (o ApplyOutcome) Changed() bool {
	return o.Result == ApplyApplied && o.From != o.To
}

// SubscriptionStore is the billing persistence seam, mirroring the VaultLog and
// DeviceStore seams: context-aware, concurrency-safe, interchangeable backends
// (MemSubscriptionStore for dev/tests, PostgresSubscriptionStore for
// durability).
//
// Implementations MUST be safe for concurrent use, and ApplyWebhookEvent MUST be
// ATOMIC across concurrent callers AND across processes for a shared backend —
// that atomicity is the idempotency guarantee.
type SubscriptionStore interface {
	// GetSubscription returns a subject's record, or ErrSubscriptionNotFound.
	GetSubscription(ctx context.Context, subject string) (Subscription, error)
	// ApplyWebhookEvent atomically dedupes on (Provider, EventID) and, if the
	// event is fresh, resolves the subject, checks the transition against the
	// state machine and the staleness guard, and applies it.
	ApplyWebhookEvent(ctx context.Context, ev SubscriptionEvent) (ApplyOutcome, error)
	// StartCheckout records that a subject has begun checkout with a provider,
	// binding subject -> provider before any webhook arrives. It NEVER changes
	// status (a started checkout is not a paid subscription) and never overwrites
	// an existing provider reference. It exists so a webhook that arrives with
	// only a provider reference still has a row to resolve against.
	StartCheckout(ctx context.Context, subject, provider string, at time.Time) error
}

// ---------------------------------------------------------------------------
// In-memory backend
// ---------------------------------------------------------------------------

// MemSubscriptionStore is a concurrency-safe, in-memory SubscriptionStore for
// local dev and tests. It is NOT durable: subscriptions AND the processed-event
// ledger are lost on restart, which means a webhook redelivered across a restart
// would be applied twice. Use the Postgres backend when that matters.
type MemSubscriptionStore struct {
	mu        sync.Mutex
	subs      map[string]Subscription // subject -> record
	byRef     map[string]string       // provider "\x00" ref -> subject
	processed map[string]time.Time    // provider "\x00" event id -> processed at
}

// NewMemSubscriptionStore returns an empty, ready-to-use in-memory store.
func NewMemSubscriptionStore() *MemSubscriptionStore {
	return &MemSubscriptionStore{
		subs:      make(map[string]Subscription),
		byRef:     make(map[string]string),
		processed: make(map[string]time.Time),
	}
}

var _ SubscriptionStore = (*MemSubscriptionStore)(nil)

// refKey builds a collision-free composite map key. A NUL separator cannot occur
// in a provider name or a provider reference, so "a\x00bc" can never collide
// with "ab\x00c".
func refKey(provider, ref string) string { return provider + "\x00" + ref }

// GetSubscription returns a copy of the subject's record.
func (s *MemSubscriptionStore) GetSubscription(ctx context.Context, subject string) (Subscription, error) {
	if err := ctx.Err(); err != nil {
		return Subscription{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.subs[subject]
	if !ok {
		return Subscription{}, ErrSubscriptionNotFound
	}
	return sub, nil
}

// StartCheckout binds subject -> provider without changing status.
func (s *MemSubscriptionStore) StartCheckout(ctx context.Context, subject, provider string, at time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sub, ok := s.subs[subject]
	if !ok {
		s.subs[subject] = Subscription{
			Subject:   subject,
			Provider:  provider,
			Status:    billing.StatusNone,
			CreatedAt: at,
			UpdatedAt: at,
		}
		return nil
	}
	// An existing record keeps its status and refs; only the provider marker and
	// the updated_at move, and only when the subject is not mid-subscription
	// with another provider's live record.
	if sub.Status == billing.StatusNone || sub.Status == billing.StatusCanceled {
		sub.Provider = provider
	}
	sub.UpdatedAt = at
	s.subs[subject] = sub
	return nil
}

// ApplyWebhookEvent is the atomic dedupe-resolve-validate-apply operation. The
// whole sequence runs under ONE mutex, so two concurrent deliveries of the same
// event produce exactly one state change.
func (s *MemSubscriptionStore) ApplyWebhookEvent(ctx context.Context, ev SubscriptionEvent) (ApplyOutcome, error) {
	if err := ctx.Err(); err != nil {
		return ApplyOutcome{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	eventKey := refKey(ev.Provider, ev.EventID)

	// 1) Resolve the subject BEFORE touching the ledger: an unresolvable event is
	//    not recorded as processed, so a later event that establishes the binding
	//    can still be followed by a redelivery of this one.
	subject := ev.Subject
	if subject == "" && ev.SubscriptionRef != "" {
		subject = s.byRef[refKey(ev.Provider, ev.SubscriptionRef)]
	}
	if subject == "" {
		return ApplyOutcome{Result: ApplyUnresolved}, nil
	}

	// 2) Idempotency: already processed => no-op.
	if _, seen := s.processed[eventKey]; seen {
		cur := s.subs[subject]
		return ApplyOutcome{
			Result: ApplyDuplicate, From: cur.Status, To: cur.Status, Subscription: cur,
		}, nil
	}

	cur, exists := s.subs[subject]
	from := billing.StatusNone
	if exists && cur.Status != "" {
		from = cur.Status
	}

	// 3) Staleness guard (independent of legality): an event older than the last
	//    one applied is dropped, so out-of-order delivery cannot regress state.
	if exists && !ev.OccurredAt.IsZero() && !cur.LastEventAt.IsZero() && ev.OccurredAt.Before(cur.LastEventAt) {
		s.processed[eventKey] = time.Now().UTC()
		return ApplyOutcome{Result: ApplyStale, From: from, To: from, Subscription: cur}, nil
	}

	// 4) Legality.
	if !billing.CanTransition(from, ev.Target) {
		s.processed[eventKey] = time.Now().UTC()
		return ApplyOutcome{Result: ApplyIllegal, From: from, To: ev.Target, Subscription: cur}, nil
	}

	// 5) Apply.
	now := time.Now().UTC()
	if !exists {
		cur = Subscription{Subject: subject, CreatedAt: now}
	}
	cur.Subject = subject
	cur.Provider = ev.Provider
	cur.Status = ev.Target
	if ev.CustomerRef != "" {
		cur.CustomerRef = ev.CustomerRef
	}
	if ev.SubscriptionRef != "" {
		cur.SubscriptionRef = ev.SubscriptionRef
		s.byRef[refKey(ev.Provider, ev.SubscriptionRef)] = subject
	}
	if !ev.CurrentPeriodEnd.IsZero() {
		cur.CurrentPeriodEnd = ev.CurrentPeriodEnd
	}
	if !ev.OccurredAt.IsZero() {
		cur.LastEventAt = ev.OccurredAt
	}
	cur.UpdatedAt = now
	s.subs[subject] = cur
	s.processed[eventKey] = now

	return ApplyOutcome{Result: ApplyApplied, From: from, To: ev.Target, Subscription: cur}, nil
}
