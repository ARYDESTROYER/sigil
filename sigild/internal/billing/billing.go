// Package billing is sigild's provider-agnostic subscription/payment seam.
//
// # WHAT THIS IS
//
// Sigil is a PAID product. This package defines the one interface every payment
// provider adapter implements (Provider), the NORMALIZED event vocabulary the
// rest of the server reasons about (Event / EventType), and the subscription
// state machine those events drive (state.go). Three adapters live beside it:
// stripe.go (international), razorpay.go and juspay.go (India).
//
// HARD RULES THIS PACKAGE ENFORCES BY CONSTRUCTION
//
//  1. NO VENDOR SDKs. Every adapter is net/http + crypto/hmac + encoding/json +
//     net/url only. sigild's go.mod still has exactly ONE direct require (pgx,
//     ADR 0014). A payment SDK is a large, opaque, network-capable dependency in
//     the same process as an E2EE sync server — that is not a trade we make.
//
//  2. NEVER TOUCH CARD DATA. Every adapter uses the provider's HOSTED CHECKOUT /
//     payment-link flow: we ask the provider for a URL and hand that URL to the
//     client. A PAN, CVV or expiry date never reaches this process, so PCI scope
//     stays at SAQ-A. There is deliberately NO field on CheckoutRequest,
//     CheckoutSession or Event that could carry one, and no adapter parses one.
//
//  3. NO SECRETS IN CODE OR LOGS. Keys and webhook secrets arrive from the
//     environment (see cmd/server/billingconfig.go), are held only in an adapter
//     struct, and are never logged, never returned in an error, and never
//     exported on /metrics. Provider errors carry a STATUS CODE and nothing
//     else (see ProviderError) precisely so a response body — which may contain
//     provider-side PII — can never leak into a log line.
//
//  4. NO LIVE API CALLS IN TESTS. Every adapter takes an injectable base URL and
//     an injectable HTTP client, so the whole test suite points at a local
//     httptest server. Nothing here reaches the public internet.
//
//  5. REAL VERIFICATION, NO FAKES. Webhook signature checks are genuine HMAC
//     comparisons done in constant time (hmac.Equal) over the EXACT RAW BYTES of
//     the request body — never over re-serialized JSON, because a re-encode
//     changes key order and whitespace and would silently break verification (or,
//     worse, accept a tampered body). Where a provider's documented scheme is
//     uncertain, the adapter says so IN THE FILE, loudly, rather than guessing
//     silently (see juspay.go).
//
// STATUS: pre-audit. This is a working billing layer, not a certified one. It is
// dev-gated behind SIGILD_ENABLE_DEV_OPS and additionally opt-in via
// SIGILD_BILLING_PROVIDERS; with either unset every billing route returns 501.
package billing

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Provider names. These are the exact strings used in the webhook route path
// (/v1/billing/webhook/{provider}), in SIGILD_BILLING_PROVIDERS, and as the
// fixed label set on the billing metrics — so the label set is closed and a
// scrape can never be made to enumerate anything configuration-dependent.
const (
	ProviderStripe   = "stripe"
	ProviderRazorpay = "razorpay"
	ProviderJuspay   = "juspay"
)

// SupportedProviders is the closed set of adapter names, in a stable order.
var SupportedProviders = []string{ProviderStripe, ProviderRazorpay, ProviderJuspay}

// EventType is the NORMALIZED event vocabulary. Every adapter maps its
// provider-specific event names onto exactly one of these, so the state machine
// and the HTTP layer never learn a provider's dialect.
//
// EventIgnored is the explicit "accepted and ignored" verdict: a provider will
// send us many events we do not care about (refund notifications, mandate
// reminders, test pings). Those MUST be a 200 with no state change — never a
// crash, never a 500 — so that a provider does not enter retry/backoff loops
// against us over an event we simply do not model.
type EventType string

const (
	EventCheckoutCompleted     EventType = "checkout_completed"
	EventSubscriptionActivated EventType = "subscription_activated"
	EventSubscriptionRenewed   EventType = "subscription_renewed"
	EventSubscriptionCanceled  EventType = "subscription_canceled"
	EventPaymentFailed         EventType = "payment_failed"
	EventIgnored               EventType = "ignored"
)

// EventTypes is the closed set of normalized event types, in a stable order.
// Used for the fixed metric label set.
var EventTypes = []EventType{
	EventCheckoutCompleted,
	EventSubscriptionActivated,
	EventSubscriptionRenewed,
	EventSubscriptionCanceled,
	EventPaymentFailed,
	EventIgnored,
}

// Event is one normalized, provider-agnostic billing event.
//
// PII BOUNDARY: there is deliberately no email, name, address, phone or card
// field here, and no adapter populates one. Everything on this struct is either
// an opaque provider reference or a timestamp, so an Event can be audit-logged
// whole without leaking a customer's identity. Subject is OUR OWN identifier
// (the enrolled device that bought the subscription), not the provider's.
type Event struct {
	// Provider is the adapter that produced this event (one of the Provider*
	// constants).
	Provider string
	// ID is the PROVIDER's event identifier. Together with Provider it is the
	// idempotency key: a provider WILL deliver the same event more than once.
	ID string
	// Type is the normalized type. EventIgnored means "understood, not modeled".
	Type EventType
	// Subject is OUR subject reference (the enrolled device ID that initiated
	// checkout), recovered from whatever pass-through field the provider offers
	// (Stripe client_reference_id / metadata, Razorpay notes, Juspay udf1). It is
	// EMPTY when the provider event carries no such marker; the store then
	// resolves the subject from SubscriptionRef instead.
	Subject string
	// CustomerRef / SubscriptionRef are the provider's own opaque identifiers.
	// They are stored so later events can be correlated back to a subject, and
	// so an operator can find the record in the provider dashboard.
	CustomerRef     string
	SubscriptionRef string
	// Trial reports that the provider says this subscription is in its trial
	// period, which routes an activation to StatusTrialing instead of
	// StatusActive.
	Trial bool
	// OccurredAt is the provider's timestamp for the event. It is the ordering
	// key used to discard stale/out-of-order deliveries; zero means "unknown",
	// which the store treats as "cannot be judged stale".
	OccurredAt time.Time
	// CurrentPeriodEnd is when the paid period ends, when the provider reports
	// it. Zero means unknown.
	CurrentPeriodEnd time.Time
}

// CheckoutRequest asks a provider for a HOSTED checkout session.
//
// NOTE WHAT IS ABSENT: no card number, no CVV, no expiry, no cardholder name,
// no billing address. The whole point of the hosted flow is that those fields
// exist only between the customer's browser and the provider.
type CheckoutRequest struct {
	// Subject is the SERVER-DERIVED subject reference (the authenticated device
	// ID). It is never taken from the request body — a client must not be able
	// to buy a subscription on someone else's behalf.
	Subject string
	// Reference is a unique per-attempt reference, used as the provider's
	// idempotency key / reference_id / order_id. The caller generates it.
	Reference string
	// PlanRef optionally overrides the adapter's configured plan (a Stripe price
	// ID, a Juspay payment-page client ID, ...). Empty => adapter default.
	PlanRef string
	// AmountMinor / Currency optionally override the adapter's configured
	// amount, in the currency's minor unit (paise, cents). Used by the
	// amount-based providers (Razorpay, Juspay). 0 / "" => adapter default.
	AmountMinor int64
	Currency    string
	// Quantity is the number of units for the plan (Stripe line item). <=0 => 1.
	Quantity int64
	// SuccessURL / CancelURL are where the provider returns the customer.
	SuccessURL string
	CancelURL  string
}

// CheckoutSession is what the customer is redirected to. URL is the provider's
// HOSTED page — sigild never renders a card form.
type CheckoutSession struct {
	Provider  string
	SessionID string
	URL       string
	ExpiresAt time.Time
}

// Provider is the seam. Three adapters implement it; the HTTP layer knows
// nothing else about payments.
//
// Implementations MUST be safe for concurrent use (they are, being immutable
// config plus an *http.Client).
type Provider interface {
	// Name returns the adapter's stable name (a Provider* constant).
	Name() string
	// CreateCheckout asks the provider for a hosted checkout session/link. It
	// performs exactly one outbound HTTPS POST and returns the URL to redirect
	// the customer to. It never sees card data.
	CreateCheckout(ctx context.Context, req CheckoutRequest) (CheckoutSession, error)
	// VerifyWebhook authenticates an inbound webhook and normalizes it.
	//
	// CONTRACT: rawBody MUST be the exact bytes read off the wire, before any
	// JSON round-trip. The implementation verifies the signature over those
	// bytes FIRST and only then parses them. It returns ErrBadSignature for a
	// failed/absent signature and ErrMalformedWebhook for a body it cannot
	// parse; an authentic but unmodeled event returns an Event with Type
	// EventIgnored and a nil error.
	VerifyWebhook(headers http.Header, rawBody []byte) (Event, error)
}

// Sentinel errors the HTTP layer maps to status codes. They are deliberately
// COARSE: the caller learns "bad signature" or "malformed", never which of the
// several checks inside tripped, so a prober cannot use the response to tune an
// attack. The precise reason goes only to the server-side audit log.
var (
	// ErrBadSignature: the request did not carry a valid provider signature.
	// Covers a missing header, a malformed header, an unparsable signature, a
	// wrong secret, a tampered body, and a timestamp outside tolerance — all one
	// verdict on the wire (401).
	ErrBadSignature = errors.New("billing: webhook signature verification failed")
	// ErrMalformedWebhook: the signature was fine but the body is not a payload
	// we can parse at all (400).
	ErrMalformedWebhook = errors.New("billing: malformed webhook payload")
	// ErrNotConfigured: an adapter was asked to do something its configuration
	// does not support (e.g. checkout with no plan configured). It is a server
	// configuration fault, not a client error.
	ErrNotConfigured = errors.New("billing: provider is not configured for this operation")
)

// ProviderError reports a failed provider API call.
//
// IT CARRIES A STATUS CODE AND NOTHING ELSE. That is deliberate: a provider's
// error body can echo customer data (an email in a "customer already exists"
// message) or request parameters, and this error string ends up in logs. A bare
// status code is enough to page an operator and impossible to leak with.
type ProviderError struct {
	Provider   string
	Op         string
	StatusCode int
}

func (e *ProviderError) Error() string {
	return fmt.Sprintf("billing: %s %s failed with HTTP %d", e.Provider, e.Op, e.StatusCode)
}

// defaultHTTPTimeout bounds every outbound provider call. A checkout request is
// a single small POST; if a provider is slower than this the customer is better
// served by a clean error than a hung request holding a server goroutine.
const defaultHTTPTimeout = 10 * time.Second

// maxProviderResponseBytes caps how much of a provider response we will read. A
// checkout session response is a few kilobytes; the cap stops a hostile or
// broken upstream from ballooning server memory.
const maxProviderResponseBytes = 1 << 20 // 1 MiB

// newHTTPClient returns the default outbound client. Adapters accept an
// injectable client so tests can point at an httptest server (and so a
// deployment can install a proxy-aware transport) — nothing in this package
// dials a hardcoded host.
func newHTTPClient() *http.Client {
	return &http.Client{Timeout: defaultHTTPTimeout}
}

// clockOrDefault returns now, defaulting to time.Now. Every adapter takes an
// injectable clock so the Stripe timestamp-tolerance window is testable without
// sleeping.
func clockOrDefault(now func() time.Time) func() time.Time {
	if now != nil {
		return now
	}
	return time.Now
}

// trimBaseURL normalizes a configured base URL (drops a trailing slash) so
// joining a path never produces a double slash.
func trimBaseURL(base, fallback string) string {
	if strings.TrimSpace(base) == "" {
		base = fallback
	}
	return strings.TrimRight(strings.TrimSpace(base), "/")
}

// doJSON performs one provider API call and decodes a JSON response into out.
//
// It reads at most maxProviderResponseBytes, treats any non-2xx as a
// ProviderError carrying ONLY the status code, and never logs or embeds the
// response body.
func doJSON(ctx context.Context, client *http.Client, req *http.Request, provider, op string, out any) error {
	resp, err := client.Do(req)
	if err != nil {
		// The transport error can name the host but never a credential (the key
		// travels in a header, not the URL). Wrapping keeps the cause for
		// context-cancellation checks.
		return fmt.Errorf("billing: %s %s: %w", provider, op, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxProviderResponseBytes))
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxProviderResponseBytes))
	if err != nil {
		return fmt.Errorf("billing: %s %s: read response: %w", provider, op, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &ProviderError{Provider: provider, Op: op, StatusCode: resp.StatusCode}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		// Note: the malformed body itself is NOT included in the error.
		return fmt.Errorf("billing: %s %s: response was not valid JSON", provider, op)
	}
	return nil
}

// constantTimeHexEqual reports whether hexSig decodes to mac, comparing in
// CONSTANT TIME.
//
// Why constant time matters here: a byte-at-a-time comparison that returns early
// leaks, through response timing, how many leading bytes of a forged signature
// were correct — enough, over many requests, to forge a signature without the
// secret. hmac.Equal is subtle.ConstantTimeCompare underneath.
//
// A hex string that does not decode is simply "not equal" — no early distinct
// error, so a malformed signature and a wrong signature are indistinguishable.
func constantTimeHexEqual(hexSig string, mac []byte) bool {
	sig, err := hex.DecodeString(strings.TrimSpace(hexSig))
	if err != nil {
		return false
	}
	return hmac.Equal(sig, mac)
}

// stringField pulls a string out of a decoded JSON map, returning "" for a
// missing key or a non-string value. Providers vary in whether a note/metadata
// value is a string or a number, so this never panics on a surprise type.
func stringField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// subjectMetadataKey is the key each adapter writes OUR subject reference under
// in the provider's pass-through field (Stripe metadata, Razorpay notes, Juspay
// order metadata), and reads it back from on the webhook. It is a namespaced
// key so it cannot collide with a merchant's own metadata.
const subjectMetadataKey = "sigil_subject"

// unixTime converts a provider's unix-seconds timestamp to a time.Time, mapping
// 0 (and negatives) to the zero time meaning "unknown".
func unixTime(sec int64) time.Time {
	if sec <= 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}
