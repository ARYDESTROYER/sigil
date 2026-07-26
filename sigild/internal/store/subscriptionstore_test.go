package store

// SubscriptionStore semantics, exercised against the in-memory backend. The
// Postgres backend is held to the SAME assertions by
// postgressubscriptionstore_test.go (gated on SIGILD_TEST_POSTGRES), so the two
// backends cannot drift.

import (
	"context"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/billing"
)

// t0 is a fixed base time so event ordering in these tests is explicit rather
// than dependent on wall-clock timing.
var t0 = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// runSubscriptionStoreSuite is the shared behaviour suite. newStore must return
// a FRESH, EMPTY store; subject/eventID prefixes keep concurrent Postgres runs
// from colliding.
func runSubscriptionStoreSuite(t *testing.T, newStore func(t *testing.T) SubscriptionStore, prefix string) {
	t.Helper()
	ctx := context.Background()

	t.Run("unknown subject is not found", func(t *testing.T) {
		s := newStore(t)
		if _, err := s.GetSubscription(ctx, prefix+"nobody"); err != ErrSubscriptionNotFound {
			t.Fatalf("err = %v, want ErrSubscriptionNotFound", err)
		}
	})

	t.Run("checkout completed activates", func(t *testing.T) {
		s := newStore(t)
		subject := prefix + "activate"
		out, err := s.ApplyWebhookEvent(ctx, SubscriptionEvent{
			Provider: "stripe", EventID: prefix + "e1", EventType: "checkout_completed",
			Subject: subject, SubscriptionRef: prefix + "sub1", CustomerRef: prefix + "cus1",
			Target: billing.StatusActive, OccurredAt: t0,
			CurrentPeriodEnd: t0.Add(30 * 24 * time.Hour),
		})
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if out.Result != ApplyApplied || out.From != billing.StatusNone || out.To != billing.StatusActive {
			t.Fatalf("outcome = %+v", out)
		}
		if !out.Changed() {
			t.Fatal("Changed() = false for a real transition")
		}
		got, err := s.GetSubscription(ctx, subject)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Status != billing.StatusActive || got.Provider != "stripe" {
			t.Fatalf("stored = %+v", got)
		}
		if got.SubscriptionRef != prefix+"sub1" || got.CustomerRef != prefix+"cus1" {
			t.Fatalf("refs = %q/%q", got.SubscriptionRef, got.CustomerRef)
		}
		if !got.CurrentPeriodEnd.Equal(t0.Add(30 * 24 * time.Hour)) {
			t.Fatalf("period end = %v", got.CurrentPeriodEnd)
		}
	})

	// IDEMPOTENCY: the same (provider, event_id) delivered twice produces ONE
	// state change. Every provider here WILL redeliver.
	t.Run("duplicate event is a no-op", func(t *testing.T) {
		s := newStore(t)
		subject := prefix + "dup"
		ev := SubscriptionEvent{
			Provider: "stripe", EventID: prefix + "dup-evt", EventType: "checkout_completed",
			Subject: subject, SubscriptionRef: prefix + "subdup",
			Target: billing.StatusActive, OccurredAt: t0,
		}
		first, err := s.ApplyWebhookEvent(ctx, ev)
		if err != nil {
			t.Fatalf("first: %v", err)
		}
		if first.Result != ApplyApplied {
			t.Fatalf("first result = %q", first.Result)
		}
		second, err := s.ApplyWebhookEvent(ctx, ev)
		if err != nil {
			t.Fatalf("second: %v", err)
		}
		if second.Result != ApplyDuplicate {
			t.Fatalf("second result = %q, want duplicate", second.Result)
		}
		if second.Changed() {
			t.Fatal("a duplicate must not report a change")
		}
		if second.Subscription.Status != billing.StatusActive {
			t.Fatalf("duplicate returned status %q", second.Subscription.Status)
		}
	})

	// The dedupe key is (provider, event_id): the SAME id from a DIFFERENT
	// provider is a different event.
	t.Run("dedupe is scoped per provider", func(t *testing.T) {
		s := newStore(t)
		id := prefix + "shared-id"
		a := prefix + "sub-a"
		b := prefix + "sub-b"
		if _, err := s.ApplyWebhookEvent(ctx, SubscriptionEvent{
			Provider: "stripe", EventID: id, Subject: a,
			Target: billing.StatusActive, OccurredAt: t0,
		}); err != nil {
			t.Fatalf("stripe: %v", err)
		}
		out, err := s.ApplyWebhookEvent(ctx, SubscriptionEvent{
			Provider: "razorpay", EventID: id, Subject: b,
			Target: billing.StatusActive, OccurredAt: t0,
		})
		if err != nil {
			t.Fatalf("razorpay: %v", err)
		}
		if out.Result != ApplyApplied {
			t.Fatalf("result = %q, want applied", out.Result)
		}
	})

	t.Run("illegal transition is rejected without changing state", func(t *testing.T) {
		s := newStore(t)
		subject := prefix + "illegal"
		// A payment failure for a subject that never subscribed: none -> past_due
		// is not a legal move.
		out, err := s.ApplyWebhookEvent(ctx, SubscriptionEvent{
			Provider: "stripe", EventID: prefix + "ill-1", Subject: subject,
			Target: billing.StatusPastDue, OccurredAt: t0,
		})
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if out.Result != ApplyIllegal {
			t.Fatalf("result = %q, want illegal", out.Result)
		}
		if out.Changed() {
			t.Fatal("an illegal transition must not report a change")
		}
		if _, err := s.GetSubscription(ctx, subject); err != ErrSubscriptionNotFound {
			t.Fatalf("an illegal event created a record: %v", err)
		}
	})

	// OUT-OF-ORDER DELIVERY must not regress a live subscription. Providers do
	// not guarantee ordering.
	t.Run("stale event does not regress an active subscription", func(t *testing.T) {
		s := newStore(t)
		subject := prefix + "stale"
		ref := prefix + "sub-stale"

		if _, err := s.ApplyWebhookEvent(ctx, SubscriptionEvent{
			Provider: "stripe", EventID: prefix + "st-1", Subject: subject,
			SubscriptionRef: ref, Target: billing.StatusActive, OccurredAt: t0.Add(time.Hour),
		}); err != nil {
			t.Fatalf("activate: %v", err)
		}

		// A payment-failure event that OCCURRED EARLIER but arrives later.
		out, err := s.ApplyWebhookEvent(ctx, SubscriptionEvent{
			Provider: "stripe", EventID: prefix + "st-0", Subject: subject,
			SubscriptionRef: ref, Target: billing.StatusPastDue, OccurredAt: t0,
		})
		if err != nil {
			t.Fatalf("stale apply: %v", err)
		}
		if out.Result != ApplyStale {
			t.Fatalf("result = %q, want stale", out.Result)
		}
		got, err := s.GetSubscription(ctx, subject)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Status != billing.StatusActive {
			t.Fatalf("status regressed to %q", got.Status)
		}
		// The stale event is recorded as handled, so a redelivery is a duplicate
		// rather than being re-evaluated.
		again, err := s.ApplyWebhookEvent(ctx, SubscriptionEvent{
			Provider: "stripe", EventID: prefix + "st-0", Subject: subject,
			SubscriptionRef: ref, Target: billing.StatusPastDue, OccurredAt: t0,
		})
		if err != nil {
			t.Fatalf("stale redelivery: %v", err)
		}
		if again.Result != ApplyDuplicate {
			t.Fatalf("stale redelivery result = %q, want duplicate", again.Result)
		}
	})

	t.Run("full lifecycle", func(t *testing.T) {
		s := newStore(t)
		subject := prefix + "life"
		ref := prefix + "sub-life"
		steps := []struct {
			id     string
			target billing.Status
			at     time.Time
			want   ApplyResult
			status billing.Status
		}{
			{"l1", billing.StatusTrialing, t0, ApplyApplied, billing.StatusTrialing},
			{"l2", billing.StatusActive, t0.Add(1 * time.Hour), ApplyApplied, billing.StatusActive},
			{"l3", billing.StatusActive, t0.Add(2 * time.Hour), ApplyApplied, billing.StatusActive}, // renewal
			{"l4", billing.StatusPastDue, t0.Add(3 * time.Hour), ApplyApplied, billing.StatusPastDue},
			{"l5", billing.StatusActive, t0.Add(4 * time.Hour), ApplyApplied, billing.StatusActive}, // recovered
			{"l6", billing.StatusCanceled, t0.Add(5 * time.Hour), ApplyApplied, billing.StatusCanceled},
			{"l7", billing.StatusPastDue, t0.Add(6 * time.Hour), ApplyIllegal, billing.StatusCanceled}, // cannot revive
			{"l8", billing.StatusActive, t0.Add(7 * time.Hour), ApplyApplied, billing.StatusActive},    // re-subscribed
		}
		for _, step := range steps {
			out, err := s.ApplyWebhookEvent(ctx, SubscriptionEvent{
				Provider: "stripe", EventID: prefix + step.id, Subject: subject,
				SubscriptionRef: ref, Target: step.target, OccurredAt: step.at,
			})
			if err != nil {
				t.Fatalf("%s: %v", step.id, err)
			}
			if out.Result != step.want {
				t.Fatalf("%s: result = %q, want %q", step.id, out.Result, step.want)
			}
			got, err := s.GetSubscription(ctx, subject)
			if err != nil {
				t.Fatalf("%s: get: %v", step.id, err)
			}
			if got.Status != step.status {
				t.Fatalf("%s: status = %q, want %q", step.id, got.Status, step.status)
			}
		}
	})

	// SUBJECT RESOLUTION: most provider events carry only the provider's own
	// subscription handle. The store must resolve it back to our subject.
	t.Run("subject resolved from subscription ref", func(t *testing.T) {
		s := newStore(t)
		subject := prefix + "resolve"
		ref := prefix + "sub-resolve"

		if _, err := s.ApplyWebhookEvent(ctx, SubscriptionEvent{
			Provider: "stripe", EventID: prefix + "r1", Subject: subject,
			SubscriptionRef: ref, Target: billing.StatusActive, OccurredAt: t0,
		}); err != nil {
			t.Fatalf("bind: %v", err)
		}

		// No Subject on this one — only the provider's ref.
		out, err := s.ApplyWebhookEvent(ctx, SubscriptionEvent{
			Provider: "stripe", EventID: prefix + "r2", SubscriptionRef: ref,
			Target: billing.StatusCanceled, OccurredAt: t0.Add(time.Hour),
		})
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if out.Result != ApplyApplied {
			t.Fatalf("result = %q, want applied", out.Result)
		}
		if out.Subscription.Subject != subject {
			t.Fatalf("resolved subject = %q, want %q", out.Subscription.Subject, subject)
		}
	})

	t.Run("unresolvable event is not recorded as processed", func(t *testing.T) {
		s := newStore(t)
		ev := SubscriptionEvent{
			Provider: "stripe", EventID: prefix + "orphan",
			SubscriptionRef: prefix + "never-seen",
			Target:          billing.StatusActive, OccurredAt: t0,
		}
		out, err := s.ApplyWebhookEvent(ctx, ev)
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if out.Result != ApplyUnresolved {
			t.Fatalf("result = %q, want unresolved", out.Result)
		}
		// Not marked processed: after the binding exists, the same event id
		// applies rather than being swallowed as a duplicate.
		if _, err := s.ApplyWebhookEvent(ctx, SubscriptionEvent{
			Provider: "stripe", EventID: prefix + "bind", Subject: prefix + "late",
			SubscriptionRef: prefix + "never-seen", Target: billing.StatusActive, OccurredAt: t0,
		}); err != nil {
			t.Fatalf("bind: %v", err)
		}
		retry, err := s.ApplyWebhookEvent(ctx, ev)
		if err != nil {
			t.Fatalf("retry: %v", err)
		}
		if retry.Result == ApplyDuplicate {
			t.Fatal("an unresolved event was recorded as processed")
		}
	})

	t.Run("start checkout binds provider without granting status", func(t *testing.T) {
		s := newStore(t)
		subject := prefix + "start"
		if err := s.StartCheckout(ctx, subject, "razorpay", t0); err != nil {
			t.Fatalf("start: %v", err)
		}
		got, err := s.GetSubscription(ctx, subject)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if got.Status != billing.StatusNone {
			t.Fatalf("status = %q, want none — starting checkout is not paying", got.Status)
		}
		if got.Provider != "razorpay" {
			t.Fatalf("provider = %q", got.Provider)
		}
		if got.Status.Entitled() {
			t.Fatal("a started checkout must not entitle anyone")
		}
		// Idempotent, and it never upgrades an active subscription.
		if err := s.StartCheckout(ctx, subject, "stripe", t0.Add(time.Minute)); err != nil {
			t.Fatalf("restart: %v", err)
		}
		if _, err := s.ApplyWebhookEvent(ctx, SubscriptionEvent{
			Provider: "stripe", EventID: prefix + "sc1", Subject: subject,
			Target: billing.StatusActive, OccurredAt: t0.Add(time.Hour),
		}); err != nil {
			t.Fatalf("activate: %v", err)
		}
		if err := s.StartCheckout(ctx, subject, "juspay", t0.Add(2*time.Hour)); err != nil {
			t.Fatalf("start over active: %v", err)
		}
		after, err := s.GetSubscription(ctx, subject)
		if err != nil {
			t.Fatalf("get: %v", err)
		}
		if after.Status != billing.StatusActive {
			t.Fatalf("StartCheckout changed status to %q", after.Status)
		}
		if after.Provider != "stripe" {
			t.Fatalf("StartCheckout re-pointed a LIVE subscription's provider to %q", after.Provider)
		}
	})

	// Concurrency: N goroutines deliver the SAME event; exactly one applies.
	t.Run("concurrent duplicate deliveries apply once", func(t *testing.T) {
		s := newStore(t)
		subject := prefix + "race"
		const n = 8
		ev := SubscriptionEvent{
			Provider: "stripe", EventID: prefix + "race-evt", Subject: subject,
			SubscriptionRef: prefix + "sub-race", Target: billing.StatusActive, OccurredAt: t0,
		}
		var (
			wg      sync.WaitGroup
			mu      sync.Mutex
			applied int
			results = make([]ApplyResult, 0, n)
		)
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				out, err := s.ApplyWebhookEvent(ctx, ev)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					t.Errorf("concurrent apply: %v", err)
					return
				}
				results = append(results, out.Result)
				if out.Result == ApplyApplied {
					applied++
				}
			}()
		}
		wg.Wait()
		if applied != 1 {
			t.Fatalf("applied %d times, want exactly 1 (results: %v)", applied, results)
		}
	})
}

func TestMemSubscriptionStore(t *testing.T) {
	runSubscriptionStoreSuite(t, func(*testing.T) SubscriptionStore {
		return NewMemSubscriptionStore()
	}, "mem-")
}

func TestMemSubscriptionStoreHonoursContext(t *testing.T) {
	s := NewMemSubscriptionStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.GetSubscription(ctx, "x"); err == nil {
		t.Fatal("GetSubscription ignored a cancelled context")
	}
	if _, err := s.ApplyWebhookEvent(ctx, SubscriptionEvent{Provider: "stripe", EventID: "e"}); err == nil {
		t.Fatal("ApplyWebhookEvent ignored a cancelled context")
	}
	if err := s.StartCheckout(ctx, "x", "stripe", t0); err == nil {
		t.Fatal("StartCheckout ignored a cancelled context")
	}
}

// TestRefKeyIsCollisionFree: the composite map key must not let two different
// (provider, ref) pairs alias each other.
func TestRefKeyIsCollisionFree(t *testing.T) {
	if refKey("a", "bc") == refKey("ab", "c") {
		t.Fatal("refKey collides across a boundary")
	}
}

// TestPersistedShapeCarriesNoCardDataOrPII is a structural guard on the PCI and
// privacy boundary: neither the persisted subscription nor the inbound event may
// ever grow a payment-instrument or contact field. A regression here is a
// compliance change, not a style issue, so it is asserted mechanically over the
// real struct definitions.
func TestPersistedShapeCarriesNoCardDataOrPII(t *testing.T) {
	forbidden := []string{
		"card", "pan", "cvv", "cvc", "expiry", "expmonth", "expyear",
		"cardholder", "email", "phone", "address", "postal", "zip", "iban",
	}
	for _, target := range []any{Subscription{}, SubscriptionEvent{}} {
		typ := reflect.TypeOf(target)
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			for _, bad := range forbidden {
				if strings.Contains(name, bad) {
					t.Fatalf("%s.%s looks like payment-instrument or contact data; it must never be persisted here",
						typ.Name(), typ.Field(i).Name)
				}
			}
		}
	}
}
