package billing

// Subscription state machine tests. These pin the transition table exactly: any
// future edit to state.go that changes which moves are legal fails here loudly,
// which for money-adjacent state is the point.

import "testing"

func TestCanTransitionLegalMoves(t *testing.T) {
	legal := []struct{ from, to Status }{
		{StatusNone, StatusTrialing},
		{StatusNone, StatusActive},
		{StatusTrialing, StatusActive},
		{StatusTrialing, StatusPastDue},
		{StatusTrialing, StatusCanceled},
		{StatusActive, StatusActive}, // renewal
		{StatusActive, StatusPastDue},
		{StatusActive, StatusCanceled},
		{StatusPastDue, StatusActive},
		{StatusPastDue, StatusCanceled},
		{StatusCanceled, StatusTrialing},
		{StatusCanceled, StatusActive},
	}
	for _, tc := range legal {
		if !CanTransition(tc.from, tc.to) {
			t.Fatalf("%s -> %s should be legal", tc.from, tc.to)
		}
	}
}

func TestCanTransitionIllegalMoves(t *testing.T) {
	illegal := []struct {
		from, to Status
		why      string
	}{
		{StatusNone, StatusPastDue, "a payment cannot fail for a subscription that never existed"},
		{StatusNone, StatusCanceled, "nothing to cancel"},
		{StatusNone, StatusNone, "none is not a destination"},
		{StatusActive, StatusTrialing, "a paid subscription never falls back into trial"},
		{StatusActive, StatusNone, "none is not a destination"},
		{StatusTrialing, StatusTrialing, "a trial does not re-start itself"},
		{StatusPastDue, StatusTrialing, "dunning does not become a trial"},
		{StatusPastDue, StatusPastDue, "repeated failures are not a transition"},
		{StatusCanceled, StatusPastDue, "a late payment failure cannot revive a dead subscription"},
		{StatusCanceled, StatusCanceled, "already canceled"},
	}
	for _, tc := range illegal {
		if CanTransition(tc.from, tc.to) {
			t.Fatalf("%s -> %s should be illegal (%s)", tc.from, tc.to, tc.why)
		}
	}
}

// TestCanTransitionFailsClosedOnUnknownStatus: a corrupt or hand-edited status
// must not be able to reach any state.
func TestCanTransitionFailsClosedOnUnknownStatus(t *testing.T) {
	bogus := Status("gold_tier")
	for _, s := range Statuses {
		if CanTransition(bogus, s) {
			t.Fatalf("unknown -> %s should be illegal", s)
		}
		if CanTransition(s, bogus) {
			t.Fatalf("%s -> unknown should be illegal", s)
		}
	}
}

func TestValidStatus(t *testing.T) {
	for _, s := range Statuses {
		if !ValidStatus(s) {
			t.Fatalf("%q should be valid", s)
		}
	}
	for _, s := range []Status{"", "ACTIVE", "paid", "expired"} {
		if ValidStatus(s) {
			t.Fatalf("%q should be invalid", s)
		}
	}
}

func TestEntitled(t *testing.T) {
	entitled := map[Status]bool{
		StatusNone:     false,
		StatusTrialing: true,
		StatusActive:   true,
		// past_due keeps entitlement on purpose: the provider is still retrying,
		// and cutting a paying customer off the instant a card declines is wrong.
		StatusPastDue:  true,
		StatusCanceled: false,
	}
	for s, want := range entitled {
		if s.Entitled() != want {
			t.Fatalf("%s.Entitled() = %v, want %v", s, s.Entitled(), want)
		}
	}
}

func TestTargetStatus(t *testing.T) {
	tests := []struct {
		event  EventType
		trial  bool
		want   Status
		drives bool
	}{
		{EventCheckoutCompleted, false, StatusActive, true},
		{EventCheckoutCompleted, true, StatusTrialing, true},
		{EventSubscriptionActivated, false, StatusActive, true},
		{EventSubscriptionActivated, true, StatusTrialing, true},
		{EventSubscriptionRenewed, false, StatusActive, true},
		// A renewal is a successful charge; it ends a trial rather than extending
		// it, so the trial flag must not divert it.
		{EventSubscriptionRenewed, true, StatusActive, true},
		{EventSubscriptionCanceled, false, StatusCanceled, true},
		{EventPaymentFailed, false, StatusPastDue, true},
		{EventIgnored, false, StatusNone, false},
		{EventType("something_else"), false, StatusNone, false},
	}
	for _, tc := range tests {
		got, drives := TargetStatus(tc.event, tc.trial)
		if drives != tc.drives {
			t.Fatalf("TargetStatus(%q, %v) drives = %v, want %v", tc.event, tc.trial, drives, tc.drives)
		}
		if drives && got != tc.want {
			t.Fatalf("TargetStatus(%q, %v) = %q, want %q", tc.event, tc.trial, got, tc.want)
		}
	}
}

// TestEveryEventTypeIsHandled guards against an EventType being added without a
// TargetStatus decision: every declared type must either drive a transition or
// be deliberately non-driving.
func TestEveryEventTypeIsHandled(t *testing.T) {
	for _, et := range EventTypes {
		status, drives := TargetStatus(et, false)
		if et == EventIgnored {
			if drives {
				t.Fatalf("%q must not drive a transition", et)
			}
			continue
		}
		if !drives {
			t.Fatalf("%q drives no transition; add it to TargetStatus", et)
		}
		if !ValidStatus(status) {
			t.Fatalf("%q targets an invalid status %q", et, status)
		}
	}
}
