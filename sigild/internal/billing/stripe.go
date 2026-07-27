package billing

// STRIPE ADAPTER — international card/wallet payments.
//
// ============================ SCHEME IMPLEMENTED ============================
//
// WEBHOOK AUTHENTICATION (Stripe signed webhooks, "v1" scheme):
//
//	Header:   Stripe-Signature: t=1614556800,v1=<hex>,v1=<hex>[,v0=<hex>]
//	Message:  <t> "." <RAW REQUEST BODY BYTES>
//	MAC:      HMAC-SHA256 keyed by the ENDPOINT SIGNING SECRET (whsec_...)
//	Encoding: lowercase hex
//	Compare:  constant time, against EVERY v1 element (Stripe sends more than one
//	          while an endpoint secret is being rotated — accepting any one of
//	          them is what makes rotation zero-downtime)
//	Replay:   reject when |now - t| exceeds the tolerance (default 5 minutes,
//	          Stripe's own documented default)
//
// v0 elements are ignored: they are a legacy scheme, and accepting them would be
// a downgrade path.
//
// CHECKOUT: POST {base}/v1/checkout/sessions, application/x-www-form-urlencoded
// (Stripe's API is form-encoded, not JSON, on the request side), authenticated
// with `Authorization: Bearer sk_...`. mode=subscription with a single line item
// referencing a configured PRICE ID. The response's `url` is Stripe's HOSTED
// Checkout page — the customer's card details go there, never here.
//
// ============================== CONFIDENCE ==================================
//
// HIGH. Stripe's signed-webhook construction (`t=`/`v1=`, the "<t>.<payload>"
// signed message, HMAC-SHA256 over the raw body, hex, 5-minute default
// tolerance, multiple v1 values during secret rotation) and the form-encoded
// Checkout Sessions endpoint are long-standing, stable and unambiguous. This
// adapter is written directly against that scheme.
//
// Still UNVERIFIED-AGAINST-LIVE-DASHBOARD in the narrow sense that no request in
// this repository has ever been sent to or received from api.stripe.com: the
// tests construct signatures with a fake secret and drive a local httptest
// server. Before taking real money, replay a real event from the Stripe CLI
// (`stripe listen`) against this endpoint and confirm the exact line-item /
// price parameters against the account's product catalogue.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// stripeDefaultBaseURL is the production API host. It is only ever a DEFAULT:
// StripeConfig.BaseURL overrides it, which is how tests stay offline.
const stripeDefaultBaseURL = "https://api.stripe.com"

// stripeDefaultTolerance is the webhook timestamp window. Stripe's own default
// is 5 minutes; a signed payload older than this is rejected even with a valid
// MAC, which bounds how long a captured webhook remains replayable.
const stripeDefaultTolerance = 5 * time.Minute

// stripeSignatureHeader is the header carrying the signature scheme elements.
const stripeSignatureHeader = "Stripe-Signature"

// StripeConfig configures the adapter. Secrets come from the environment (see
// cmd/server/billingconfig.go) and are never logged or exported.
type StripeConfig struct {
	// SecretKey is the API secret (sk_...). Sent as a bearer token, never logged.
	SecretKey string
	// WebhookSecret is the ENDPOINT SIGNING SECRET (whsec_...). It is a
	// different secret from SecretKey and is used only as the HMAC key.
	WebhookSecret string
	// PriceID is the default Stripe price the checkout subscribes the customer
	// to. CheckoutRequest.PlanRef overrides it per request.
	PriceID string
	// BaseURL overrides the API host. Empty => stripeDefaultBaseURL. Tests set
	// this to an httptest server so no test ever reaches the internet.
	BaseURL string
	// HTTPClient overrides the outbound client (timeouts, proxies, test
	// transports). Empty => a 10 s-timeout client.
	HTTPClient *http.Client
	// Now is the injectable clock used for the webhook timestamp tolerance.
	// Empty => time.Now. Injectable so the stale-timestamp path is testable
	// without sleeping.
	Now func() time.Time
	// Tolerance overrides the timestamp window. <=0 => stripeDefaultTolerance.
	Tolerance time.Duration
}

// StripeProvider implements Provider against Stripe. It is immutable after
// construction and safe for concurrent use.
type StripeProvider struct {
	secretKey     string
	webhookSecret string
	priceID       string
	baseURL       string
	client        *http.Client
	now           func() time.Time
	tolerance     time.Duration
}

var _ Provider = (*StripeProvider)(nil)

// NewStripe builds the adapter. It performs NO network I/O — construction is
// pure, so wiring it at boot cannot hang startup or contact a provider.
func NewStripe(cfg StripeConfig) *StripeProvider {
	tol := cfg.Tolerance
	if tol <= 0 {
		tol = stripeDefaultTolerance
	}
	client := cfg.HTTPClient
	if client == nil {
		client = newHTTPClient()
	}
	return &StripeProvider{
		secretKey:     cfg.SecretKey,
		webhookSecret: cfg.WebhookSecret,
		priceID:       cfg.PriceID,
		baseURL:       trimBaseURL(cfg.BaseURL, stripeDefaultBaseURL),
		client:        client,
		now:           clockOrDefault(cfg.Now),
		tolerance:     tol,
	}
}

// Name implements Provider.
func (p *StripeProvider) Name() string { return ProviderStripe }

// CreateCheckout creates a hosted Stripe Checkout Session in subscription mode
// and returns its URL.
//
// The request is form-encoded (Stripe's wire format) and carries:
//
//	mode=subscription
//	line_items[0][price]=<price id>          the plan; never an amount we invent
//	line_items[0][quantity]=<n>
//	success_url / cancel_url                 where Stripe returns the customer
//	client_reference_id=<subject>            OUR subject, echoed back on the
//	                                         checkout.session.completed webhook
//	subscription_data[metadata][sigil_subject]=<subject>
//	                                         the same marker copied onto the
//	                                         SUBSCRIPTION, so later subscription
//	                                         and invoice events are attributable
//
// The Idempotency-Key header carries the caller's per-attempt reference, so a
// retried checkout does not create a second session.
func (p *StripeProvider) CreateCheckout(ctx context.Context, req CheckoutRequest) (CheckoutSession, error) {
	price := req.PlanRef
	if price == "" {
		price = p.priceID
	}
	if price == "" {
		return CheckoutSession{}, fmt.Errorf("%w: stripe has no price ID configured", ErrNotConfigured)
	}
	if p.secretKey == "" {
		return CheckoutSession{}, fmt.Errorf("%w: stripe has no secret key configured", ErrNotConfigured)
	}
	qty := req.Quantity
	if qty <= 0 {
		qty = 1
	}

	form := url.Values{}
	form.Set("mode", "subscription")
	form.Set("line_items[0][price]", price)
	form.Set("line_items[0][quantity]", strconv.FormatInt(qty, 10))
	form.Set("success_url", req.SuccessURL)
	form.Set("cancel_url", req.CancelURL)
	form.Set("client_reference_id", req.Subject)
	form.Set("subscription_data[metadata]["+subjectMetadataKey+"]", req.Subject)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.baseURL+"/v1/checkout/sessions", strings.NewReader(form.Encode()))
	if err != nil {
		return CheckoutSession{}, fmt.Errorf("billing: stripe checkout: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// The key travels in a header, never in the URL or a log line.
	httpReq.Header.Set("Authorization", "Bearer "+p.secretKey)
	if req.Reference != "" {
		httpReq.Header.Set("Idempotency-Key", req.Reference)
	}

	var out struct {
		ID        string `json:"id"`
		URL       string `json:"url"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := doJSON(ctx, p.client, httpReq, ProviderStripe, "checkout", &out); err != nil {
		return CheckoutSession{}, err
	}
	if out.URL == "" {
		return CheckoutSession{}, fmt.Errorf("billing: stripe checkout: response contained no checkout URL")
	}
	return CheckoutSession{
		Provider:  ProviderStripe,
		SessionID: out.ID,
		URL:       out.URL,
		ExpiresAt: unixTime(out.ExpiresAt),
	}, nil
}

// VerifyWebhook authenticates and normalizes a Stripe webhook.
//
// ORDER MATTERS: the signature is verified over rawBody FIRST; the body is only
// parsed afterwards. Verifying over a re-encoded payload would be a bug (Go's
// json round-trip reorders keys and drops whitespace, so the MAC would never
// match — or, if someone "fixed" that by re-signing, an attacker could mutate
// semantically-significant whitespace).
func (p *StripeProvider) VerifyWebhook(headers http.Header, rawBody []byte) (Event, error) {
	if err := p.verifySignature(headers.Get(stripeSignatureHeader), rawBody); err != nil {
		return Event{}, err
	}
	return parseStripeEvent(rawBody)
}

// verifySignature implements the Stripe-Signature check. Every failure mode
// returns the SAME ErrBadSignature.
func (p *StripeProvider) verifySignature(header string, rawBody []byte) error {
	if p.webhookSecret == "" || header == "" {
		return ErrBadSignature
	}
	ts, v1s, ok := parseStripeSignatureHeader(header)
	if !ok || len(v1s) == 0 {
		return ErrBadSignature
	}

	// Timestamp tolerance bounds replay of a captured, validly-signed delivery.
	// Checked in BOTH directions: a far-future timestamp is as suspect as a stale
	// one (it would otherwise stay replayable for as long as the clock skew).
	skew := p.now().Unix() - ts
	if skew < 0 {
		skew = -skew
	}
	if float64(skew) > math.Abs(p.tolerance.Seconds()) {
		return ErrBadSignature
	}

	// Signed message: "<t>.<raw body>". Built from the RAW bytes.
	mac := hmac.New(sha256.New, []byte(p.webhookSecret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(rawBody)
	want := mac.Sum(nil)

	// Compare against EVERY v1 element with no early exit, so neither the number
	// of candidate signatures nor which one matched is observable in timing.
	var matched bool
	for _, sig := range v1s {
		if constantTimeHexEqual(sig, want) {
			matched = true
		}
	}
	if !matched {
		return ErrBadSignature
	}
	return nil
}

// parseStripeSignatureHeader splits "t=...,v1=...,v1=..." into the timestamp and
// the list of v1 hex signatures. Unknown elements (notably the legacy v0) are
// ignored. ok is false if there is no parsable t element.
func parseStripeSignatureHeader(header string) (ts int64, v1s []string, ok bool) {
	var haveTS bool
	for _, part := range strings.Split(header, ",") {
		key, value, found := strings.Cut(strings.TrimSpace(part), "=")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "t":
			parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil {
				return 0, nil, false
			}
			ts, haveTS = parsed, true
		case "v1":
			v1s = append(v1s, value)
		default:
			// v0 and anything future: deliberately ignored, never accepted.
		}
	}
	return ts, v1s, haveTS
}

// stripeEnvelope is the outer shape of every Stripe event.
type stripeEnvelope struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Created int64  `json:"created"`
	Data    struct {
		Object json.RawMessage `json:"object"`
	} `json:"data"`
}

// stripeObject is the union of the few fields we read across the event objects
// we model (checkout session, subscription, invoice). Fields absent on a given
// object simply decode to their zero value.
//
// Customer / Subscription are RawMessage because Stripe sends either a bare ID
// string or, when the caller expands it, a nested object.
type stripeObject struct {
	ID                string            `json:"id"`
	ClientReferenceID string            `json:"client_reference_id"`
	Customer          json.RawMessage   `json:"customer"`
	Subscription      json.RawMessage   `json:"subscription"`
	Status            string            `json:"status"`
	CurrentPeriodEnd  int64             `json:"current_period_end"`
	Metadata          map[string]string `json:"metadata"`
}

// stripeRef extracts an ID from a field that may be a bare string or an
// expanded object with an "id".
func stripeRef(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var obj struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil {
		return obj.ID
	}
	return ""
}

// parseStripeEvent maps an AUTHENTIC Stripe payload onto the normalized Event.
// Anything we do not model becomes EventIgnored with a nil error — accepted and
// acknowledged, no state change.
func parseStripeEvent(rawBody []byte) (Event, error) {
	var env stripeEnvelope
	if err := json.Unmarshal(rawBody, &env); err != nil {
		return Event{}, ErrMalformedWebhook
	}
	if env.ID == "" || env.Type == "" {
		return Event{}, ErrMalformedWebhook
	}

	ev := Event{
		Provider: ProviderStripe,
		ID:       env.ID,
		// Stripe's event id lives INSIDE the signed payload (and the signed
		// message is "<timestamp>.<body>"), so the id is already covered by the
		// signature and is a safe idempotency key. Set explicitly rather than
		// left to the ID fallback so the guarantee is visible at the call site.
		DedupKey:   env.ID,
		Type:       EventIgnored,
		OccurredAt: unixTime(env.Created),
	}

	var obj stripeObject
	if len(env.Data.Object) > 0 {
		// A non-object data payload is not fatal: the event is simply one we
		// cannot attribute, so it is ignored rather than rejected.
		_ = json.Unmarshal(env.Data.Object, &obj)
	}

	ev.CustomerRef = stripeRef(obj.Customer)
	ev.Subject = obj.ClientReferenceID
	if ev.Subject == "" {
		ev.Subject = obj.Metadata[subjectMetadataKey]
	}
	ev.CurrentPeriodEnd = unixTime(obj.CurrentPeriodEnd)
	ev.Trial = obj.Status == "trialing"

	switch env.Type {
	case "checkout.session.completed":
		ev.Type = EventCheckoutCompleted
		ev.SubscriptionRef = stripeRef(obj.Subscription)
	case "customer.subscription.created", "customer.subscription.updated":
		// The status ON THE OBJECT decides: an "updated" event is how Stripe
		// reports a trial ending, a card failing, and a cancellation scheduled at
		// period end, so keying off the event name alone would misclassify them.
		ev.SubscriptionRef = obj.ID
		switch obj.Status {
		case "trialing", "active":
			ev.Type = EventSubscriptionActivated
		case "past_due", "unpaid":
			ev.Type = EventPaymentFailed
		case "canceled", "incomplete_expired":
			ev.Type = EventSubscriptionCanceled
		default:
			ev.Type = EventIgnored
		}
	case "customer.subscription.deleted":
		ev.Type = EventSubscriptionCanceled
		ev.SubscriptionRef = obj.ID
	case "invoice.paid", "invoice.payment_succeeded":
		ev.Type = EventSubscriptionRenewed
		ev.SubscriptionRef = stripeRef(obj.Subscription)
	case "invoice.payment_failed":
		ev.Type = EventPaymentFailed
		ev.SubscriptionRef = stripeRef(obj.Subscription)
	default:
		ev.Type = EventIgnored
	}
	return ev, nil
}
