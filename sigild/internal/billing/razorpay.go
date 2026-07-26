package billing

// RAZORPAY ADAPTER — India (UPI, cards, netbanking, wallets).
//
// ============================ SCHEME IMPLEMENTED ============================
//
// WEBHOOK AUTHENTICATION:
//
//	Header:   X-Razorpay-Signature: <hex>
//	Message:  the RAW REQUEST BODY BYTES, exactly as received (no timestamp, no
//	          prefix, no separator — unlike Stripe)
//	MAC:      HMAC-SHA256 keyed by the WEBHOOK SECRET configured in the Razorpay
//	          dashboard for this endpoint
//	Encoding: lowercase hex
//	Compare:  constant time
//
// There is NO timestamp element in this scheme, so there is no in-scheme replay
// bound; replay protection comes from our own idempotency layer instead (dedupe
// on (provider, event_id), see internal/store). The event id is taken from the
// X-Razorpay-Event-Id header, which Razorpay sends alongside the signature; when
// it is absent we fall back to a SHA-256 of the raw body, which is deterministic
// and therefore still deduplicates a byte-identical redelivery.
//
// CHECKOUT: POST {base}/v1/payment_links (JSON), HTTP Basic auth with
// key_id:key_secret. The response's `short_url` is Razorpay's HOSTED payment
// page. Card details go there, never here.
//
// ============================== CONFIDENCE ==================================
//
// HIGH for the webhook scheme: "hex HMAC-SHA256 of the raw request body, keyed
// by the dashboard webhook secret, in X-Razorpay-Signature" is Razorpay's
// documented and widely-implemented construction, and is what their own SDK's
// verify helper does.
//
// MEDIUM for the surrounding details, explicitly UNVERIFIED-AGAINST-LIVE-
// DASHBOARD:
//   - the X-Razorpay-Event-Id header name (hence the deterministic fallback);
//   - the exact set of subscription event names Razorpay emits for a given plan
//     configuration (the mapping below covers the documented ones, and anything
//     unrecognized is accepted-and-ignored, which is the safe direction).
//
// SCOPE, STATED HONESTLY: CreateCheckout creates a PAYMENT LINK — a hosted,
// one-time payment page. Creating a recurring Razorpay SUBSCRIPTION (the
// /v1/subscriptions API, with a pre-created plan and customer) is NOT
// implemented here. The webhook side already maps Razorpay's subscription
// events, so a subscription created out-of-band in the dashboard drives this
// state machine correctly; wiring subscription CREATION is the next step and is
// a deliberate omission, not an oversight.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// razorpayDefaultBaseURL is the production API host; only ever a DEFAULT.
const razorpayDefaultBaseURL = "https://api.razorpay.com"

// Razorpay webhook headers.
const (
	razorpaySignatureHeader = "X-Razorpay-Signature"
	razorpayEventIDHeader   = "X-Razorpay-Event-Id"
)

// razorpayDefaultCurrency is the fallback currency for a payment link when
// neither the request nor the configuration names one.
const razorpayDefaultCurrency = "INR"

// RazorpayConfig configures the adapter. Secrets come from the environment and
// are never logged or exported.
type RazorpayConfig struct {
	// KeyID / KeySecret are the API credentials, sent as HTTP Basic auth.
	KeyID     string
	KeySecret string
	// WebhookSecret is the dashboard-configured webhook secret. It is a
	// DIFFERENT secret from KeySecret and is used only as the HMAC key.
	WebhookSecret string
	// AmountMinor / Currency / Description are the default payment-link terms.
	// CheckoutRequest may override the first two per request.
	AmountMinor int64
	Currency    string
	Description string
	// BaseURL overrides the API host. Empty => razorpayDefaultBaseURL. Tests
	// point this at an httptest server so no test reaches the internet.
	BaseURL string
	// HTTPClient overrides the outbound client. Empty => 10 s-timeout client.
	HTTPClient *http.Client
	// Now is the injectable clock (used only for the OccurredAt fallback; this
	// scheme has no timestamp to tolerate). Empty => time.Now.
	Now func() time.Time
}

// RazorpayProvider implements Provider against Razorpay. Immutable after
// construction; safe for concurrent use.
type RazorpayProvider struct {
	keyID         string
	keySecret     string
	webhookSecret string
	amountMinor   int64
	currency      string
	description   string
	baseURL       string
	client        *http.Client
	now           func() time.Time
}

var _ Provider = (*RazorpayProvider)(nil)

// NewRazorpay builds the adapter. No network I/O at construction.
func NewRazorpay(cfg RazorpayConfig) *RazorpayProvider {
	client := cfg.HTTPClient
	if client == nil {
		client = newHTTPClient()
	}
	currency := cfg.Currency
	if currency == "" {
		currency = razorpayDefaultCurrency
	}
	return &RazorpayProvider{
		keyID:         cfg.KeyID,
		keySecret:     cfg.KeySecret,
		webhookSecret: cfg.WebhookSecret,
		amountMinor:   cfg.AmountMinor,
		currency:      currency,
		description:   cfg.Description,
		baseURL:       trimBaseURL(cfg.BaseURL, razorpayDefaultBaseURL),
		client:        client,
		now:           clockOrDefault(cfg.Now),
	}
}

// Name implements Provider.
func (p *RazorpayProvider) Name() string { return ProviderRazorpay }

// razorpayLinkRequest is the JSON body of POST /v1/payment_links.
//
// `notes` is Razorpay's pass-through key/value map: whatever we put there comes
// back on the webhook, which is how a payment is attributed to OUR subject
// without ever asking the provider to store one of our secrets.
//
// `notify` is explicitly all-false: we do not hand Razorpay a customer email or
// phone number to notify, because we do not collect one — that keeps PII out of
// this request entirely.
type razorpayLinkRequest struct {
	Amount         int64             `json:"amount"`
	Currency       string            `json:"currency"`
	Description    string            `json:"description,omitempty"`
	ReferenceID    string            `json:"reference_id,omitempty"`
	CallbackURL    string            `json:"callback_url,omitempty"`
	CallbackMethod string            `json:"callback_method,omitempty"`
	Notes          map[string]string `json:"notes,omitempty"`
	Notify         struct {
		SMS   bool `json:"sms"`
		Email bool `json:"email"`
	} `json:"notify"`
}

// CreateCheckout creates a hosted Razorpay Payment Link and returns its
// short_url.
func (p *RazorpayProvider) CreateCheckout(ctx context.Context, req CheckoutRequest) (CheckoutSession, error) {
	if p.keyID == "" || p.keySecret == "" {
		return CheckoutSession{}, fmt.Errorf("%w: razorpay has no API key configured", ErrNotConfigured)
	}
	amount := req.AmountMinor
	if amount <= 0 {
		amount = p.amountMinor
	}
	if amount <= 0 {
		return CheckoutSession{}, fmt.Errorf("%w: razorpay has no amount configured", ErrNotConfigured)
	}
	currency := req.Currency
	if currency == "" {
		currency = p.currency
	}

	body := razorpayLinkRequest{
		Amount:         amount,
		Currency:       currency,
		Description:    p.description,
		ReferenceID:    req.Reference,
		CallbackURL:    req.SuccessURL,
		CallbackMethod: "get",
		Notes:          map[string]string{subjectMetadataKey: req.Subject},
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return CheckoutSession{}, fmt.Errorf("billing: razorpay checkout: encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.baseURL+"/v1/payment_links", bytes.NewReader(encoded))
	if err != nil {
		return CheckoutSession{}, fmt.Errorf("billing: razorpay checkout: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// Credentials travel in the Authorization header, never in the URL.
	httpReq.SetBasicAuth(p.keyID, p.keySecret)

	var out struct {
		ID       string `json:"id"`
		ShortURL string `json:"short_url"`
		ExpireBy int64  `json:"expire_by"`
	}
	if err := doJSON(ctx, p.client, httpReq, ProviderRazorpay, "checkout", &out); err != nil {
		return CheckoutSession{}, err
	}
	if out.ShortURL == "" {
		return CheckoutSession{}, fmt.Errorf("billing: razorpay checkout: response contained no payment link URL")
	}
	return CheckoutSession{
		Provider:  ProviderRazorpay,
		SessionID: out.ID,
		URL:       out.ShortURL,
		ExpiresAt: unixTime(out.ExpireBy),
	}, nil
}

// VerifyWebhook authenticates and normalizes a Razorpay webhook. The signature
// is verified over rawBody FIRST; only then is the body parsed.
func (p *RazorpayProvider) VerifyWebhook(headers http.Header, rawBody []byte) (Event, error) {
	if err := p.verifySignature(headers.Get(razorpaySignatureHeader), rawBody); err != nil {
		return Event{}, err
	}
	return p.parseEvent(headers.Get(razorpayEventIDHeader), rawBody)
}

// verifySignature checks the hex HMAC-SHA256 of the RAW body. Every failure
// mode returns the same ErrBadSignature.
func (p *RazorpayProvider) verifySignature(header string, rawBody []byte) error {
	if p.webhookSecret == "" || header == "" {
		return ErrBadSignature
	}
	mac := hmac.New(sha256.New, []byte(p.webhookSecret))
	mac.Write(rawBody)
	if !constantTimeHexEqual(header, mac.Sum(nil)) {
		return ErrBadSignature
	}
	return nil
}

// razorpayEnvelope is the outer shape of a Razorpay webhook.
//
// payload is a map of entity-name -> {"entity": {...}}; which keys are present
// is listed in `contains`. We decode it loosely (map[string]json.RawMessage) so
// an unfamiliar entity can never break parsing.
type razorpayEnvelope struct {
	Event     string                     `json:"event"`
	CreatedAt int64                      `json:"created_at"`
	Payload   map[string]json.RawMessage `json:"payload"`
}

// razorpayEntity is the union of the fields we read from the entities we model
// (subscription, payment_link, payment). Absent fields decode to zero values.
type razorpayEntity struct {
	ID         string         `json:"id"`
	Status     string         `json:"status"`
	CurrentEnd int64          `json:"current_end"`
	CustomerID string         `json:"customer_id"`
	Notes      map[string]any `json:"notes"`
}

// razorpayEntityFrom pulls payload[name].entity out of the envelope.
func razorpayEntityFrom(payload map[string]json.RawMessage, name string) (razorpayEntity, bool) {
	raw, ok := payload[name]
	if !ok {
		return razorpayEntity{}, false
	}
	var wrapper struct {
		Entity razorpayEntity `json:"entity"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return razorpayEntity{}, false
	}
	return wrapper.Entity, true
}

// parseEvent maps an AUTHENTIC Razorpay payload onto the normalized Event.
//
// eventIDHeader is the X-Razorpay-Event-Id value. When it is absent we derive a
// DETERMINISTIC id from the body hash so redelivery of the identical body is
// still deduplicated — documented above as part of the unverified surface.
func (p *RazorpayProvider) parseEvent(eventIDHeader string, rawBody []byte) (Event, error) {
	var env razorpayEnvelope
	if err := json.Unmarshal(rawBody, &env); err != nil {
		return Event{}, ErrMalformedWebhook
	}
	if env.Event == "" {
		return Event{}, ErrMalformedWebhook
	}

	eventID := eventIDHeader
	if eventID == "" {
		sum := sha256.Sum256(rawBody)
		eventID = "body-" + hex.EncodeToString(sum[:])
	}

	occurred := unixTime(env.CreatedAt)
	if occurred.IsZero() {
		occurred = p.now().UTC()
	}

	ev := Event{
		Provider:   ProviderRazorpay,
		ID:         eventID,
		Type:       EventIgnored,
		OccurredAt: occurred,
	}

	// Prefer the subscription entity for refs/subject; fall back to the payment
	// link, then the payment. Each carries `notes`, so the subject survives
	// whichever entity the event is about.
	sub, hasSub := razorpayEntityFrom(env.Payload, "subscription")
	link, hasLink := razorpayEntityFrom(env.Payload, "payment_link")
	pay, hasPay := razorpayEntityFrom(env.Payload, "payment")
	switch {
	case hasSub:
		ev.SubscriptionRef = sub.ID
		ev.CustomerRef = sub.CustomerID
		ev.Subject = stringField(sub.Notes, subjectMetadataKey)
		ev.CurrentPeriodEnd = unixTime(sub.CurrentEnd)
		ev.Trial = sub.Status == "created" || sub.Status == "authenticated"
	case hasLink:
		ev.SubscriptionRef = link.ID
		ev.CustomerRef = link.CustomerID
		ev.Subject = stringField(link.Notes, subjectMetadataKey)
	case hasPay:
		ev.CustomerRef = pay.CustomerID
		ev.Subject = stringField(pay.Notes, subjectMetadataKey)
	}

	switch env.Event {
	case "payment_link.paid":
		ev.Type = EventCheckoutCompleted
		// A paid link is a completed purchase, not a trial.
		ev.Trial = false
	case "subscription.activated", "subscription.authenticated", "subscription.resumed":
		ev.Type = EventSubscriptionActivated
	case "subscription.charged":
		ev.Type = EventSubscriptionRenewed
		ev.Trial = false
	case "subscription.cancelled", "subscription.completed", "subscription.expired":
		ev.Type = EventSubscriptionCanceled
	case "subscription.halted", "subscription.pending", "payment.failed":
		ev.Type = EventPaymentFailed
	default:
		// Authentic but unmodeled (refunds, settlements, test pings, anything
		// Razorpay adds later): accepted and ignored, never an error.
		ev.Type = EventIgnored
	}
	return ev, nil
}
