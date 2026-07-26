package store

// PostgresSubscriptionStore is the durable, concurrency-safe SubscriptionStore
// backed by the tables created in migration 0003_billing.sql
// (sigil_subscriptions, sigil_billing_processed_events). It is the durable twin
// of MemSubscriptionStore and shares its exact semantics — including the
// idempotency guarantee, which here is enforced by the DATABASE (a PRIMARY KEY
// plus ON CONFLICT DO NOTHING inside the applying transaction), so it holds
// across CONCURRENT PROCESSES, not merely goroutines.
//
// It reuses a caller-supplied *pgxpool.Pool (normally the one the Postgres
// op-log already opened), so billing adds no second connection pool and no new
// dependency — go.mod still has exactly one direct require.
//
// NO CARD DATA: see the banner in 0003_billing.sql. Every column touched here is
// an opaque provider handle, a status string or a timestamp.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ARYDESTROYER/sigil/sigild/internal/billing"
)

// PostgresSubscriptionStore implements SubscriptionStore against a pgxpool pool.
type PostgresSubscriptionStore struct {
	pool *pgxpool.Pool
}

var _ SubscriptionStore = (*PostgresSubscriptionStore)(nil)

// NewPostgresSubscriptionStore wraps an existing pool. The caller owns the
// pool's lifecycle (it is normally shared with PostgresVaultLog, whose
// construction already applied the migrations that create these tables).
func NewPostgresSubscriptionStore(pool *pgxpool.Pool) *PostgresSubscriptionStore {
	return &PostgresSubscriptionStore{pool: pool}
}

// subscriptionColumns is the shared SELECT list, so every read decodes the same
// shape.
const subscriptionColumns = `subject, provider, customer_ref, subscription_ref, status,
	current_period_end, last_event_at, created_at, updated_at`

// scanSubscription decodes one row of subscriptionColumns. The three nullable
// timestamps decode through pointers so a NULL becomes the zero time.
func scanSubscription(row pgx.Row) (Subscription, error) {
	var (
		sub         Subscription
		status      string
		periodEnd   *time.Time
		lastEventAt *time.Time
	)
	err := row.Scan(&sub.Subject, &sub.Provider, &sub.CustomerRef, &sub.SubscriptionRef,
		&status, &periodEnd, &lastEventAt, &sub.CreatedAt, &sub.UpdatedAt)
	if err != nil {
		return Subscription{}, err
	}
	sub.Status = billing.Status(status)
	if periodEnd != nil {
		sub.CurrentPeriodEnd = *periodEnd
	}
	if lastEventAt != nil {
		sub.LastEventAt = *lastEventAt
	}
	return sub, nil
}

// GetSubscription reads one subject's record, or ErrSubscriptionNotFound.
func (s *PostgresSubscriptionStore) GetSubscription(ctx context.Context, subject string) (Subscription, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	sub, err := scanSubscription(s.pool.QueryRow(ctx,
		`SELECT `+subscriptionColumns+` FROM sigil_subscriptions WHERE subject = $1`, subject))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Subscription{}, ErrSubscriptionNotFound
		}
		return Subscription{}, fmt.Errorf("get subscription: %w", err)
	}
	return sub, nil
}

// StartCheckout binds subject -> provider without changing status. It inserts a
// 'none' row when absent, and otherwise only re-points the provider marker for a
// subject that is not currently subscribed — a live subscription's provider is
// never silently switched out from under it.
func (s *PostgresSubscriptionStore) StartCheckout(ctx context.Context, subject, provider string, at time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	_, err := s.pool.Exec(ctx,
		`INSERT INTO sigil_subscriptions (subject, provider, status, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $4)
		 ON CONFLICT (subject) DO UPDATE SET
		   provider = CASE WHEN sigil_subscriptions.status IN ('none', 'canceled')
		                   THEN EXCLUDED.provider ELSE sigil_subscriptions.provider END,
		   updated_at = EXCLUDED.updated_at`,
		subject, provider, string(billing.StatusNone), at)
	if err != nil {
		return fmt.Errorf("start checkout: %w", err)
	}
	return nil
}

// ApplyWebhookEvent is the atomic dedupe-resolve-validate-apply operation.
//
// EVERYTHING happens in ONE transaction:
//
//  1. resolve the subject (by the event's own subject, else by
//     (provider, subscription_ref));
//  2. claim the event in sigil_billing_processed_events with ON CONFLICT DO
//     NOTHING — zero rows affected means a concurrent or earlier delivery
//     already owns it, so this one is a duplicate;
//  3. SELECT ... FOR UPDATE the subscription row, so two events for the same
//     subject serialize;
//  4. apply the staleness guard, then the state machine, then the write.
//
// A rollback at any point leaves BOTH the ledger and the record untouched, so
// the event is retried cleanly. That is why the two are not separate calls.
func (s *PostgresSubscriptionStore) ApplyWebhookEvent(ctx context.Context, ev SubscriptionEvent) (ApplyOutcome, error) {
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ApplyOutcome{}, fmt.Errorf("apply webhook event: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful Commit

	// 1) Subject resolution.
	subject := ev.Subject
	if subject == "" && ev.SubscriptionRef != "" {
		err := tx.QueryRow(ctx,
			`SELECT subject FROM sigil_subscriptions
			  WHERE provider = $1 AND subscription_ref = $2
			  ORDER BY updated_at DESC LIMIT 1`,
			ev.Provider, ev.SubscriptionRef).Scan(&subject)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return ApplyOutcome{}, fmt.Errorf("apply webhook event: resolve subject: %w", err)
		}
	}
	if subject == "" {
		// Deliberately NOT recorded as processed: a later event may establish the
		// binding, and this one should then be applicable on redelivery.
		return ApplyOutcome{Result: ApplyUnresolved}, nil
	}

	// 2) Claim the event. Zero rows => already processed => duplicate.
	tag, err := tx.Exec(ctx,
		`INSERT INTO sigil_billing_processed_events (provider, event_id, event_type, subject)
		 VALUES ($1, $2, $3, $4) ON CONFLICT (provider, event_id) DO NOTHING`,
		ev.Provider, ev.EventID, ev.EventType, subject)
	if err != nil {
		return ApplyOutcome{}, fmt.Errorf("apply webhook event: claim: %w", err)
	}
	if tag.RowsAffected() == 0 {
		cur, curErr := scanSubscription(tx.QueryRow(ctx,
			`SELECT `+subscriptionColumns+` FROM sigil_subscriptions WHERE subject = $1`, subject))
		if curErr != nil && !errors.Is(curErr, pgx.ErrNoRows) {
			return ApplyOutcome{}, fmt.Errorf("apply webhook event: read current: %w", curErr)
		}
		if err := tx.Commit(ctx); err != nil {
			return ApplyOutcome{}, fmt.Errorf("apply webhook event: commit: %w", err)
		}
		return ApplyOutcome{
			Result: ApplyDuplicate, From: cur.Status, To: cur.Status, Subscription: cur,
		}, nil
	}

	// 3) Lock the subscription row so concurrent events for one subject
	//    serialize behind each other rather than interleaving.
	cur, err := scanSubscription(tx.QueryRow(ctx,
		`SELECT `+subscriptionColumns+` FROM sigil_subscriptions WHERE subject = $1 FOR UPDATE`, subject))
	exists := true
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			return ApplyOutcome{}, fmt.Errorf("apply webhook event: lock row: %w", err)
		}
		exists = false
		cur = Subscription{}
	}

	from := billing.StatusNone
	if exists && cur.Status != "" {
		from = cur.Status
	}

	// 4a) Staleness guard.
	if exists && !ev.OccurredAt.IsZero() && !cur.LastEventAt.IsZero() && ev.OccurredAt.Before(cur.LastEventAt) {
		if err := tx.Commit(ctx); err != nil { // keeps the ledger claim: handled, no-op
			return ApplyOutcome{}, fmt.Errorf("apply webhook event: commit: %w", err)
		}
		return ApplyOutcome{Result: ApplyStale, From: from, To: from, Subscription: cur}, nil
	}

	// 4b) State machine.
	if !billing.CanTransition(from, ev.Target) {
		if err := tx.Commit(ctx); err != nil { // keeps the ledger claim: handled, no-op
			return ApplyOutcome{}, fmt.Errorf("apply webhook event: commit: %w", err)
		}
		return ApplyOutcome{Result: ApplyIllegal, From: from, To: ev.Target, Subscription: cur}, nil
	}

	// 4c) Apply. COALESCE/NULLIF keep an existing reference when the event does
	//     not carry a fresher one, so a sparse event never blanks a good handle.
	now := time.Now().UTC()
	var (
		periodEnd   *time.Time
		lastEventAt *time.Time
	)
	if !ev.CurrentPeriodEnd.IsZero() {
		pe := ev.CurrentPeriodEnd
		periodEnd = &pe
	}
	if !ev.OccurredAt.IsZero() {
		oa := ev.OccurredAt
		lastEventAt = &oa
	}

	_, err = tx.Exec(ctx,
		`INSERT INTO sigil_subscriptions
		   (subject, provider, customer_ref, subscription_ref, status,
		    current_period_end, last_event_at, created_at, updated_at)
		 VALUES ($1, $2, COALESCE($3, ''), COALESCE($4, ''), $5, $6, $7, $8, $8)
		 ON CONFLICT (subject) DO UPDATE SET
		   provider           = EXCLUDED.provider,
		   customer_ref       = COALESCE(NULLIF(EXCLUDED.customer_ref, ''), sigil_subscriptions.customer_ref),
		   subscription_ref   = COALESCE(NULLIF(EXCLUDED.subscription_ref, ''), sigil_subscriptions.subscription_ref),
		   status             = EXCLUDED.status,
		   current_period_end = COALESCE(EXCLUDED.current_period_end, sigil_subscriptions.current_period_end),
		   last_event_at      = COALESCE(EXCLUDED.last_event_at, sigil_subscriptions.last_event_at),
		   updated_at         = EXCLUDED.updated_at`,
		subject, ev.Provider, ev.CustomerRef, ev.SubscriptionRef, string(ev.Target),
		periodEnd, lastEventAt, now)
	if err != nil {
		return ApplyOutcome{}, fmt.Errorf("apply webhook event: upsert: %w", err)
	}

	updated, err := scanSubscription(tx.QueryRow(ctx,
		`SELECT `+subscriptionColumns+` FROM sigil_subscriptions WHERE subject = $1`, subject))
	if err != nil {
		return ApplyOutcome{}, fmt.Errorf("apply webhook event: read back: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return ApplyOutcome{}, fmt.Errorf("apply webhook event: commit: %w", err)
	}
	return ApplyOutcome{Result: ApplyApplied, From: from, To: ev.Target, Subscription: updated}, nil
}
