package store

// Integration tests for PostgresSubscriptionStore. Like the other Postgres
// tests they are GATED on SIGILD_TEST_POSTGRES (a pgx DSN): with it unset every
// test here SKIPS, so `go test ./...` stays green with no database and never
// touches the network.
//
// Each subtest namespaces its subjects and event IDs with a per-run unique
// prefix, and a t.Cleanup deletes every row under that prefix, so repeated and
// parallel runs never collide.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ARYDESTROYER/sigil/sigild/internal/billing"
)

// newBillingTestPool opens a migrated pool (skipping without a DSN). Migrations
// run here, which is itself the proof that 0003 applies on top of 0001+0002.
func newBillingTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("SIGILD_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("set SIGILD_TEST_POSTGRES to run the Postgres integration tests")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pgxpool.New: %v", err)
	}
	if _, err := Migrate(ctx, pool); err != nil {
		pool.Close()
		t.Fatalf("Migrate: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// cleanupBilling deletes every billing row under prefix.
func cleanupBilling(t *testing.T, pool *pgxpool.Pool, prefix string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := pool.Exec(ctx, `DELETE FROM sigil_subscriptions WHERE subject LIKE $1`, prefix+"%"); err != nil {
		t.Errorf("cleanup subscriptions: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM sigil_billing_processed_events WHERE event_id LIKE $1`, prefix+"%"); err != nil {
		t.Errorf("cleanup processed events: %v", err)
	}
}

// TestPostgresSubscriptionStore runs the SAME behaviour suite as the in-memory
// backend, so the two cannot drift apart on idempotency, staleness, legality or
// subject resolution.
func TestPostgresSubscriptionStore(t *testing.T) {
	pool := newBillingTestPool(t)
	prefix := uniquePrefix()
	t.Cleanup(func() { cleanupBilling(t, pool, prefix) })

	runSubscriptionStoreSuite(t, func(t *testing.T) SubscriptionStore {
		return NewPostgresSubscriptionStore(pool)
	}, prefix)
}

// TestBillingMigrationAppliesOnTopOfDevices proves migration 0003 applies
// cleanly after 0001 and 0002, that it is recorded in schema_migrations, and
// that a second run is a no-op.
func TestBillingMigrationAppliesOnTopOfDevices(t *testing.T) {
	pool := newBillingTestPool(t)
	ctx := context.Background()

	statuses, err := Status(ctx, pool)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	want := map[int64]string{1: "0001_init", 2: "0002_devices", 3: "0003_billing"}
	seen := make(map[int64]bool)
	for _, s := range statuses {
		if name, ok := want[s.Version]; ok {
			if s.Name != name {
				t.Fatalf("migration %d named %q, want %q", s.Version, s.Name, name)
			}
			if !s.Applied {
				t.Fatalf("migration %s is not applied", s.Name)
			}
			seen[s.Version] = true
		}
	}
	for v, name := range want {
		if !seen[v] {
			t.Fatalf("migration %s (%d) is missing from the embedded set", name, v)
		}
	}

	version, err := AppliedVersion(ctx, pool)
	if err != nil {
		t.Fatalf("AppliedVersion: %v", err)
	}
	if version < 3 {
		t.Fatalf("applied version = %d, want >= 3", version)
	}

	// Re-running applies nothing.
	applied, err := Migrate(ctx, pool)
	if err != nil {
		t.Fatalf("re-Migrate: %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("re-run applied %d migrations, want 0", len(applied))
	}

	// The device tables from 0002 are untouched and still queryable — 0003 must
	// not have disturbed anything that came before it.
	var n int64
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sigil_devices`).Scan(&n); err != nil {
		t.Fatalf("0003 disturbed the 0002 device tables: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sigil_vault_ops`).Scan(&n); err != nil {
		t.Fatalf("0003 disturbed the 0001 op-log table: %v", err)
	}
}

// TestPostgresSubscriptionDurability proves state survives a new store instance
// over the same database — the whole point of the durable backend.
func TestPostgresSubscriptionDurability(t *testing.T) {
	pool := newBillingTestPool(t)
	prefix := uniquePrefix()
	t.Cleanup(func() { cleanupBilling(t, pool, prefix) })

	ctx := context.Background()
	subject := prefix + "durable"

	first := NewPostgresSubscriptionStore(pool)
	if _, err := first.ApplyWebhookEvent(ctx, SubscriptionEvent{
		Provider: "stripe", EventID: prefix + "d1", EventType: "checkout_completed",
		Subject: subject, SubscriptionRef: prefix + "sub-d",
		Target: billing.StatusActive, OccurredAt: t0,
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// A fresh store over the same database sees the record AND the ledger.
	second := NewPostgresSubscriptionStore(pool)
	got, err := second.GetSubscription(ctx, subject)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != billing.StatusActive {
		t.Fatalf("status = %q", got.Status)
	}
	out, err := second.ApplyWebhookEvent(ctx, SubscriptionEvent{
		Provider: "stripe", EventID: prefix + "d1", Subject: subject,
		Target: billing.StatusActive, OccurredAt: t0,
	})
	if err != nil {
		t.Fatalf("redeliver: %v", err)
	}
	if out.Result != ApplyDuplicate {
		t.Fatalf("redelivery across instances = %q, want duplicate", out.Result)
	}
}

// TestPostgresProcessedEventsLedgerShape asserts the ledger holds only
// metadata: the normalized event type, never a raw provider payload.
func TestPostgresProcessedEventsLedgerShape(t *testing.T) {
	pool := newBillingTestPool(t)
	prefix := uniquePrefix()
	t.Cleanup(func() { cleanupBilling(t, pool, prefix) })

	ctx := context.Background()
	s := NewPostgresSubscriptionStore(pool)
	subject := prefix + "ledger"
	if _, err := s.ApplyWebhookEvent(ctx, SubscriptionEvent{
		Provider: "razorpay", EventID: prefix + "L1", EventType: "subscription_activated",
		Subject: subject, Target: billing.StatusActive, OccurredAt: t0,
	}); err != nil {
		t.Fatalf("apply: %v", err)
	}

	var eventType, gotSubject string
	err := pool.QueryRow(ctx,
		`SELECT event_type, subject FROM sigil_billing_processed_events
		  WHERE provider = 'razorpay' AND event_id = $1`, prefix+"L1").
		Scan(&eventType, &gotSubject)
	if err != nil {
		t.Fatalf("read ledger: %v", err)
	}
	if eventType != "subscription_activated" {
		t.Fatalf("event_type = %q, want the NORMALIZED type", eventType)
	}
	if gotSubject != subject {
		t.Fatalf("subject = %q", gotSubject)
	}
}
