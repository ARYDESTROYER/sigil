package billing

// JUSPAY ADAPTER — India (HyperCheckout / Express Checkout).
//
// ###########################################################################
// #                                                                         #
// #   UNVERIFIED-AGAINST-LIVE-DASHBOARD                                     #
// #                                                                         #
// #   This is the adapter whose provider contract I am LEAST certain of.    #
// #   Everything below is my best-supported reading, implemented honestly   #
// #   and REAL (the HMAC is a real constant-time HMAC; the Basic-auth check #
// #   is a real constant-time credential comparison) — but the exact header #
// #   names, the exact signed message, and the exact event vocabulary MUST  #
// #   be confirmed against the merchant's live Juspay dashboard before any  #
// #   real money moves. Do not read the specificity below as certainty.     #
// #                                                                         #
// ###########################################################################
//
// ========================= WHAT IS IMPLEMENTED =============================
//
// Juspay's webhook authentication has, historically, been endpoint-level HTTP
// BASIC AUTH: the merchant configures a username/password in the dashboard and
// Juspay sends them in the Authorization header of every webhook. Newer parts of
// their stack expose signature-based verification instead. Because I cannot
// confirm which applies to a given merchant account, this adapter implements
// BOTH behind a small internal seam (juspayWebhookVerifier) and selects one by
// configuration:
//
//	scheme=basic (default)
//	    Authorization: Basic base64(username ":" password)
//	    Both halves compared in CONSTANT TIME against the configured pair.
//	    CONFIDENCE: MEDIUM-HIGH that this is a supported mode; it is the mode
//	    described in Juspay's webhook setup material.
//
//	scheme=hmac
//	    <configurable header>: <hex HMAC-SHA256 of the RAW REQUEST BODY,
//	                            keyed by the configured webhook secret>
//	    Header name defaults to X-Juspay-Signature and is CONFIGURABLE precisely
//	    because I am not certain of it.
//	    CONFIDENCE: LOW on the header name and on whether the signed message is
//	    the bare body (as implemented) or a body-with-timestamp construction like
//	    Stripe's. If the merchant's dashboard documents a timestamped message,
//	    THIS MUST BE CHANGED before use.
//
// The seam exists so the scheme can be swapped — or a third one added — WITHOUT
// touching the Provider interface, the state machine, the store, or any HTTP
// handler. That containment is the point: the uncertainty is quarantined to one
// small type in one file.
//
// Note the security asymmetry, stated plainly: Basic auth authenticates the
// CONNECTION, not the BODY. It proves the caller knows a shared password; it
// does NOT prove the payload was not modified by anything sitting between
// Juspay and us. The HMAC scheme does bind the body. Where the choice exists,
// prefer hmac; where only basic is available, the endpoint MUST be TLS-only and
// the credential treated as a bearer secret.
//
// CHECKOUT: POST {base}/session (JSON) with the merchant ID header and the API
// key as HTTP Basic auth, action=paymentPage. The response's payment_links.web
// is Juspay's HOSTED payment page. Card details go there, never here.
// CONFIDENCE: MEDIUM on the endpoint path and request field names; LOW on the
// exact response envelope. Also UNVERIFIED-AGAINST-LIVE-DASHBOARD.
//
// SCOPE: like the Razorpay adapter, this creates a hosted ONE-TIME payment page.
// Recurring mandate creation is not implemented; the webhook side maps Juspay's
// mandate events so an out-of-band mandate still drives the state machine.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// juspayDefaultBaseURL is the production API host; only ever a DEFAULT.
// UNVERIFIED: confirm the merchant's assigned host (Juspay issues per-region /
// per-tenant hosts) before use.
const juspayDefaultBaseURL = "https://api.juspay.in"

// juspayDefaultSignatureHeader is the header the hmac scheme reads. It is a
// DEFAULT because the real name is unconfirmed — see the banner above.
const juspayDefaultSignatureHeader = "X-Juspay-Signature"

// Juspay webhook scheme names, as accepted by SIGILD_JUSPAY_WEBHOOK_SCHEME.
const (
	// JuspaySchemeBasic authenticates the endpoint with HTTP Basic credentials.
	JuspaySchemeBasic = "basic"
	// JuspaySchemeHMAC authenticates the BODY with a hex HMAC-SHA256.
	JuspaySchemeHMAC = "hmac"
)

// JuspayConfig configures the adapter. Secrets come from the environment and are
// never logged or exported.
type JuspayConfig struct {
	// MerchantID is the merchant identifier sent on API calls.
	MerchantID string
	// APIKey is the API credential (sent as the Basic-auth username with an
	// empty password, which is Juspay's documented API convention).
	APIKey string
	// ClientID is the payment-page client identifier used when creating a
	// session. CheckoutRequest.PlanRef overrides it per request.
	ClientID string
	// WebhookScheme selects the verifier: JuspaySchemeBasic (default) or
	// JuspaySchemeHMAC.
	WebhookScheme string
	// WebhookUsername / WebhookPassword are the credentials for the basic
	// scheme.
	WebhookUsername string
	WebhookPassword string
	// WebhookSecret is the HMAC key for the hmac scheme.
	WebhookSecret string
	// WebhookSignatureHeader overrides the header name the hmac scheme reads.
	// Empty => juspayDefaultSignatureHeader. Configurable BECAUSE the real name
	// is unconfirmed.
	WebhookSignatureHeader string
	// AmountMinor / Currency are the default session terms; CheckoutRequest may
	// override them.
	AmountMinor int64
	Currency    string
	// BaseURL overrides the API host. Empty => juspayDefaultBaseURL. Tests point
	// this at an httptest server so no test reaches the internet.
	BaseURL string
	// HTTPClient overrides the outbound client. Empty => 10 s-timeout client.
	HTTPClient *http.Client
	// Now is the injectable clock (OccurredAt fallback). Empty => time.Now.
	Now func() time.Time
}

// juspayWebhookVerifier is the SWAPPABLE authentication seam. Adding or
// replacing a Juspay webhook scheme means writing one of these; nothing outside
// this file changes.
type juspayWebhookVerifier interface {
	// verify returns nil when the request is authentic, ErrBadSignature
	// otherwise. It receives the RAW body bytes, never a re-encoded payload.
	verify(headers http.Header, rawBody []byte) error
	// scheme names the mechanism, for the adapter's own diagnostics. It never
	// includes any credential.
	scheme() string
}

// juspayBasicVerifier authenticates the CONNECTION with HTTP Basic credentials.
//
// It compares BOTH halves in constant time and with NO early exit, so neither a
// correct-username/wrong-password nor a wrong-username outcome is distinguishable
// by timing. An absent or malformed Authorization header is the same verdict as
// a wrong one.
type juspayBasicVerifier struct {
	username string
	password string
}

func (v *juspayBasicVerifier) scheme() string { return JuspaySchemeBasic }

func (v *juspayBasicVerifier) verify(headers http.Header, _ []byte) error {
	if v.username == "" || v.password == "" {
		// Fail closed: an unconfigured verifier accepts nothing.
		return ErrBadSignature
	}
	header := headers.Get("Authorization")
	const prefix = "Basic "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ErrBadSignature
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(prefix):]))
	if err != nil {
		return ErrBadSignature
	}
	user, pass, found := strings.Cut(string(decoded), ":")
	if !found {
		return ErrBadSignature
	}
	// Bitwise-OR both comparisons, then require both: no short circuit.
	okUser := subtle.ConstantTimeCompare([]byte(user), []byte(v.username))
	okPass := subtle.ConstantTimeCompare([]byte(pass), []byte(v.password))
	if okUser&okPass != 1 {
		return ErrBadSignature
	}
	return nil
}

// juspayHMACVerifier authenticates the BODY with a hex HMAC-SHA256 over the RAW
// bytes, keyed by the configured webhook secret.
//
// UNVERIFIED: the header name and the exact signed message are unconfirmed. If
// the merchant's dashboard documents a timestamped message ("<t>.<body>", as
// Stripe uses), this verifier must be updated to match — and, being behind the
// juspayWebhookVerifier seam, that is a change to this type alone.
type juspayHMACVerifier struct {
	secret string
	header string
}

func (v *juspayHMACVerifier) scheme() string { return JuspaySchemeHMAC }

func (v *juspayHMACVerifier) verify(headers http.Header, rawBody []byte) error {
	if v.secret == "" {
		return ErrBadSignature
	}
	sig := headers.Get(v.header)
	if sig == "" {
		return ErrBadSignature
	}
	mac := hmac.New(sha256.New, []byte(v.secret))
	mac.Write(rawBody)
	if !constantTimeHexEqual(sig, mac.Sum(nil)) {
		return ErrBadSignature
	}
	return nil
}

// JuspayProvider implements Provider against Juspay. Immutable after
// construction; safe for concurrent use.
type JuspayProvider struct {
	merchantID  string
	apiKey      string
	clientID    string
	amountMinor int64
	currency    string
	baseURL     string
	client      *http.Client
	now         func() time.Time
	verifier    juspayWebhookVerifier
}

var _ Provider = (*JuspayProvider)(nil)

// ValidJuspayScheme reports whether s names a supported webhook scheme. An empty
// string means "default" (basic) and is valid.
func ValidJuspayScheme(s string) bool {
	switch s {
	case "", JuspaySchemeBasic, JuspaySchemeHMAC:
		return true
	default:
		return false
	}
}

// NewJuspay builds the adapter, selecting the webhook verifier from the
// configured scheme. No network I/O at construction. An unknown scheme selects
// the basic verifier with empty credentials, which fails closed (accepts
// nothing) — cmd/server rejects an unknown scheme at boot, so this is only ever
// a defensive default.
func NewJuspay(cfg JuspayConfig) *JuspayProvider {
	client := cfg.HTTPClient
	if client == nil {
		client = newHTTPClient()
	}
	sigHeader := cfg.WebhookSignatureHeader
	if strings.TrimSpace(sigHeader) == "" {
		sigHeader = juspayDefaultSignatureHeader
	}

	var verifier juspayWebhookVerifier
	switch cfg.WebhookScheme {
	case JuspaySchemeHMAC:
		verifier = &juspayHMACVerifier{secret: cfg.WebhookSecret, header: sigHeader}
	default:
		verifier = &juspayBasicVerifier{username: cfg.WebhookUsername, password: cfg.WebhookPassword}
	}

	return &JuspayProvider{
		merchantID:  cfg.MerchantID,
		apiKey:      cfg.APIKey,
		clientID:    cfg.ClientID,
		amountMinor: cfg.AmountMinor,
		currency:    cfg.Currency,
		baseURL:     trimBaseURL(cfg.BaseURL, juspayDefaultBaseURL),
		client:      client,
		now:         clockOrDefault(cfg.Now),
		verifier:    verifier,
	}
}

// Name implements Provider.
func (p *JuspayProvider) Name() string { return ProviderJuspay }

// WebhookScheme reports which verifier is active. Used only for a boot-time log
// line; it names the MECHANISM and never a credential.
func (p *JuspayProvider) WebhookScheme() string { return p.verifier.scheme() }

// juspaySessionRequest is the JSON body of POST /session.
//
// UDF1 carries OUR subject reference: Juspay's user-defined fields are its
// pass-through mechanism, so the subject comes back on the webhook without ever
// storing anything sensitive at the provider. `metadata` carries the same marker
// as a belt-and-braces fallback.
type juspaySessionRequest struct {
	OrderID     string            `json:"order_id"`
	Amount      string            `json:"amount"`
	Currency    string            `json:"currency"`
	CustomerID  string            `json:"customer_id"`
	Action      string            `json:"action"`
	ClientID    string            `json:"payment_page_client_id,omitempty"`
	ReturnURL   string            `json:"return_url,omitempty"`
	Description string            `json:"description,omitempty"`
	UDF1        string            `json:"udf1,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}

// CreateCheckout creates a hosted Juspay payment page and returns its web link.
func (p *JuspayProvider) CreateCheckout(ctx context.Context, req CheckoutRequest) (CheckoutSession, error) {
	if p.merchantID == "" || p.apiKey == "" {
		return CheckoutSession{}, fmt.Errorf("%w: juspay has no merchant credentials configured", ErrNotConfigured)
	}
	amount := req.AmountMinor
	if amount <= 0 {
		amount = p.amountMinor
	}
	if amount <= 0 {
		return CheckoutSession{}, fmt.Errorf("%w: juspay has no amount configured", ErrNotConfigured)
	}
	currency := req.Currency
	if currency == "" {
		currency = p.currency
	}
	clientID := req.PlanRef
	if clientID == "" {
		clientID = p.clientID
	}
	if req.Reference == "" {
		return CheckoutSession{}, fmt.Errorf("%w: juspay requires a unique order reference", ErrNotConfigured)
	}

	body := juspaySessionRequest{
		OrderID:    req.Reference,
		Amount:     juspayAmountString(amount),
		Currency:   currency,
		CustomerID: req.Subject,
		Action:     "paymentPage",
		ClientID:   clientID,
		ReturnURL:  req.SuccessURL,
		UDF1:       req.Subject,
		Metadata:   map[string]string{subjectMetadataKey: req.Subject},
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return CheckoutSession{}, fmt.Errorf("billing: juspay checkout: encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.baseURL+"/session", bytes.NewReader(encoded))
	if err != nil {
		return CheckoutSession{}, fmt.Errorf("billing: juspay checkout: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-merchantid", p.merchantID)
	// Juspay's API convention: the API key is the Basic-auth USERNAME with an
	// empty password. The credential travels in a header, never in the URL.
	httpReq.SetBasicAuth(p.apiKey, "")

	var out struct {
		ID           string `json:"id"`
		OrderID      string `json:"order_id"`
		PaymentLinks struct {
			Web    string `json:"web"`
			Mobile string `json:"mobile"`
			IFrame string `json:"iframe"`
		} `json:"payment_links"`
	}
	if err := doJSON(ctx, p.client, httpReq, ProviderJuspay, "checkout", &out); err != nil {
		return CheckoutSession{}, err
	}
	link := out.PaymentLinks.Web
	if link == "" {
		link = out.PaymentLinks.Mobile
	}
	if link == "" {
		return CheckoutSession{}, fmt.Errorf("billing: juspay checkout: response contained no payment page URL")
	}
	sessionID := out.ID
	if sessionID == "" {
		sessionID = out.OrderID
	}
	return CheckoutSession{
		Provider:  ProviderJuspay,
		SessionID: sessionID,
		URL:       link,
	}, nil
}

// juspayAmountString renders a minor-unit amount as the decimal major-unit
// string Juspay's API expects (e.g. 49900 -> "499.00"). Kept integer-only
// (no float arithmetic) so no amount is ever mangled by rounding.
func juspayAmountString(minor int64) string {
	neg := minor < 0
	if neg {
		minor = -minor
	}
	major := minor / 100
	rem := minor % 100
	s := fmt.Sprintf("%d.%02d", major, rem)
	if neg {
		s = "-" + s
	}
	return s
}

// VerifyWebhook authenticates and normalizes a Juspay webhook. Authentication
// runs over the RAW body FIRST (for the hmac scheme; the basic scheme does not
// bind the body at all — see the banner), and only then is the body parsed.
func (p *JuspayProvider) VerifyWebhook(headers http.Header, rawBody []byte) (Event, error) {
	if err := p.verifier.verify(headers, rawBody); err != nil {
		return Event{}, err
	}
	return p.parseEvent(rawBody)
}

// juspayEnvelope is the outer shape of a Juspay webhook.
// UNVERIFIED: field names follow Juspay's documented webhook body
// (id / event_name / date_created / content).
type juspayEnvelope struct {
	ID          string `json:"id"`
	EventName   string `json:"event_name"`
	DateCreated string `json:"date_created"`
	Content     struct {
		Order   json.RawMessage `json:"order"`
		Mandate json.RawMessage `json:"mandate"`
	} `json:"content"`
}

// juspayOrder / juspayMandate are the entity shapes we read.
type juspayOrder struct {
	OrderID    string            `json:"order_id"`
	Status     string            `json:"status"`
	CustomerID string            `json:"customer_id"`
	UDF1       string            `json:"udf1"`
	Metadata   map[string]string `json:"metadata"`
}

type juspayMandate struct {
	MandateID  string            `json:"mandate_id"`
	Status     string            `json:"status"`
	CustomerID string            `json:"customer_id"`
	EndDate    string            `json:"end_date"`
	Metadata   map[string]string `json:"metadata"`
}

// parseEvent maps an AUTHENTIC Juspay payload onto the normalized Event.
// Anything unmodeled is accepted-and-ignored.
//
// UNVERIFIED: the event-name vocabulary below is my best reading of Juspay's
// order and mandate events. Confirm it against the live dashboard; the
// ignore-by-default behaviour means an unrecognized name is safe (a 200 with no
// state change) rather than dangerous.
func (p *JuspayProvider) parseEvent(rawBody []byte) (Event, error) {
	var env juspayEnvelope
	if err := json.Unmarshal(rawBody, &env); err != nil {
		return Event{}, ErrMalformedWebhook
	}
	if env.EventName == "" {
		return Event{}, ErrMalformedWebhook
	}

	eventID := env.ID
	if eventID == "" {
		// Deterministic fallback so a byte-identical redelivery still dedupes.
		sum := sha256.Sum256(rawBody)
		eventID = "body-" + hex.EncodeToString(sum[:])
	}

	occurred := p.now().UTC()
	if env.DateCreated != "" {
		if t, err := time.Parse(time.RFC3339, env.DateCreated); err == nil {
			occurred = t.UTC()
		}
	}

	ev := Event{
		Provider:   ProviderJuspay,
		ID:         eventID,
		Type:       EventIgnored,
		OccurredAt: occurred,
	}

	if len(env.Content.Order) > 0 {
		var order juspayOrder
		if err := json.Unmarshal(env.Content.Order, &order); err == nil {
			ev.SubscriptionRef = order.OrderID
			ev.CustomerRef = order.CustomerID
			ev.Subject = order.UDF1
			if ev.Subject == "" {
				ev.Subject = order.Metadata[subjectMetadataKey]
			}
		}
	}
	if len(env.Content.Mandate) > 0 {
		var mandate juspayMandate
		if err := json.Unmarshal(env.Content.Mandate, &mandate); err == nil {
			if mandate.MandateID != "" {
				ev.SubscriptionRef = mandate.MandateID
			}
			if ev.CustomerRef == "" {
				ev.CustomerRef = mandate.CustomerID
			}
			if ev.Subject == "" {
				ev.Subject = mandate.Metadata[subjectMetadataKey]
			}
			if t, err := time.Parse(time.RFC3339, mandate.EndDate); err == nil {
				ev.CurrentPeriodEnd = t.UTC()
			}
		}
	}

	switch strings.ToUpper(env.EventName) {
	case "ORDER_SUCCEEDED":
		ev.Type = EventCheckoutCompleted
	case "ORDER_FAILED":
		ev.Type = EventPaymentFailed
	case "MANDATE_CREATED", "MANDATE_ACTIVATED":
		ev.Type = EventSubscriptionActivated
	case "MANDATE_REVOKED", "MANDATE_EXPIRED", "MANDATE_PAUSED":
		ev.Type = EventSubscriptionCanceled
	case "TXN_CHARGED", "MANDATE_NOTIFICATION_SUCCEEDED":
		ev.Type = EventSubscriptionRenewed
	case "TXN_FAILED", "MANDATE_NOTIFICATION_FAILED":
		ev.Type = EventPaymentFailed
	default:
		ev.Type = EventIgnored
	}
	return ev, nil
}
