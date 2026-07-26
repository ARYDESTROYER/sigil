package billing

// The subscription state machine.
//
// It is written down here, once, as an explicit transition table rather than
// scattered if-statements, because money-adjacent state that drifts is how a
// customer ends up either paying for nothing or getting the product for free.
//
// STATES
//
//	none      no subscription has ever existed for this subject
//	trialing  the provider says the subscription is inside its trial period
//	active    paid and current
//	past_due  a renewal payment failed; the subscription still exists and can
//	          recover to active when the retry succeeds
//	canceled  terminated (by the customer, by the provider, or by dunning)
//
// LEGAL TRANSITIONS (everything not listed is REJECTED)
//
//	none      -> trialing | active
//	trialing  -> active | past_due | canceled
//	active    -> active (renewal) | past_due | canceled
//	past_due  -> active | canceled
//	canceled  -> trialing | active        (a NEW purchase after cancellation)
//
// Notes on the deliberate choices:
//
//   - active -> active is legal and is how a renewal is recorded: the renewal
//     carries a new current-period-end, so the transition is meaningful even
//     though the status does not change.
//   - canceled is NOT a dead end, because a customer who cancels and later buys
//     again must be able to become active. It can only be left by an event that
//     targets an ACTIVE state (a fresh checkout, an activation, or a successful
//     charge) — never by a payment failure, so a late "payment failed" for a dead
//     subscription cannot revive it into past_due.
//   - There is no transition INTO none. none is only the initial, implicit state
//     of a subject with no record.
//
// SEPARATELY from legality, the store rejects STALE events by timestamp: a
// delivery whose OccurredAt precedes the last event already applied is dropped,
// so an out-of-order "past_due" that overtakes a later "active" cannot regress a
// healthy subscription. Legality and ordering are two independent guards; both
// must pass for a transition to be applied.

// Status is a subscription's lifecycle state.
type Status string

const (
	// StatusNone is the implicit state of a subject with no subscription record.
	StatusNone Status = "none"
	// StatusTrialing is an active subscription inside its trial period.
	StatusTrialing Status = "trialing"
	// StatusActive is a paid, current subscription.
	StatusActive Status = "active"
	// StatusPastDue is a subscription whose renewal payment failed and which the
	// provider is retrying.
	StatusPastDue Status = "past_due"
	// StatusCanceled is a terminated subscription.
	StatusCanceled Status = "canceled"
)

// Statuses is the closed set of statuses in a stable order, used for the fixed
// metric label set and for validation.
var Statuses = []Status{StatusNone, StatusTrialing, StatusActive, StatusPastDue, StatusCanceled}

// ValidStatus reports whether s is one of the defined states. Anything else is
// rejected at the boundary rather than persisted, so a corrupt or hand-edited
// database row cannot introduce a state the machine has no rules for.
func ValidStatus(s Status) bool {
	switch s {
	case StatusNone, StatusTrialing, StatusActive, StatusPastDue, StatusCanceled:
		return true
	default:
		return false
	}
}

// Entitled reports whether a subject in this state should be served the paid
// product right now. past_due is deliberately INCLUDED: a failed renewal starts
// a provider-side retry window, and cutting a paying customer off the instant a
// card declines is both hostile and usually wrong. Cancellation is the point at
// which entitlement ends.
func (s Status) Entitled() bool {
	return s == StatusTrialing || s == StatusActive || s == StatusPastDue
}

// transitions is the transition table. transitions[from][to] == true means the
// move is legal. It is built once at init and never mutated.
var transitions = map[Status]map[Status]bool{
	StatusNone: {
		StatusTrialing: true,
		StatusActive:   true,
	},
	StatusTrialing: {
		StatusActive:   true,
		StatusPastDue:  true,
		StatusCanceled: true,
	},
	StatusActive: {
		StatusActive:   true, // renewal
		StatusPastDue:  true,
		StatusCanceled: true,
	},
	StatusPastDue: {
		StatusActive:   true,
		StatusCanceled: true,
	},
	StatusCanceled: {
		StatusTrialing: true, // a new purchase after cancellation
		StatusActive:   true,
	},
}

// CanTransition reports whether from -> to is a legal move. An unknown state on
// either side is illegal (fail closed).
func CanTransition(from, to Status) bool {
	if !ValidStatus(from) || !ValidStatus(to) {
		return false
	}
	return transitions[from][to]
}

// TargetStatus maps a normalized event to the status it drives the subscription
// to, and reports whether the event drives a transition at all.
//
// trial reports the provider's trial flag (Event.Trial): an activation while in
// trial lands on StatusTrialing rather than StatusActive, which is what makes
// trialing reachable at all.
//
// EventIgnored (and any unknown type) returns ok == false: the webhook is
// accepted and acknowledged, but touches no state.
func TargetStatus(t EventType, trial bool) (Status, bool) {
	switch t {
	case EventCheckoutCompleted, EventSubscriptionActivated:
		if trial {
			return StatusTrialing, true
		}
		return StatusActive, true
	case EventSubscriptionRenewed:
		// A renewal always lands on active: it is the successful payment that
		// ends a trial or clears a past_due.
		return StatusActive, true
	case EventSubscriptionCanceled:
		return StatusCanceled, true
	case EventPaymentFailed:
		return StatusPastDue, true
	default:
		return StatusNone, false
	}
}
