package api

// HTTP surface for the billing / subscription layer (Phase 45):
//
//	POST /v1/billing/checkout           device-authed; ask a provider for a
//	                                    HOSTED checkout session and return its URL
//	POST /v1/billing/webhook/{provider} provider-signature-authed ONLY
//	GET  /v1/billing/subscription       device-authed; the caller's status
//
// ALL of these are DEV-GATED exactly like the ops and device routes: with
// SIGILD_ENABLE_DEV_OPS unset — or billing not configured — every one returns
// 501, never 404 and never a partial implementation.
//
// TWO DIFFERENT AUTHENTICATIONS, DELIBERATELY:
//
//   - checkout and subscription come FROM A DEVICE, so they reuse the EXISTING
//     device-auth v3 choke point (authenticateDevice) verbatim. There is no
//     second auth path, no billing-specific token, no API key.
//   - the webhook comes FROM THE PROVIDER, which has no device key and cannot
//     sign our v3 contract. It is authenticated by the PROVIDER's own signature
//     over the raw body, verified inside the adapter. That is the only reason
//     this endpoint exists outside the device model, and it is why it can create
//     no session, read no vault, and name no subject of its own choosing.
//
// THE SUBJECT IS SERVER-DERIVED. A checkout's subject is the AUTHENTICATED
// DEVICE ID; it is never read from the request body. A client therefore cannot
// buy — or query — a subscription on another subject's behalf.
//
// NO CARD DATA CROSSES THIS FILE. Checkout returns a provider-hosted URL; the
// customer's card details go to the provider, never here. No handler, struct or
// log line below can carry a PAN, CVV or expiry.
//
// ZERO-KNOWLEDGE, unchanged: no handler here reads, writes or touches a vault
// blob.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/billing"
	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

// Body caps. A checkout request is a couple of short strings; a provider webhook
// is a JSON event that can legitimately run to tens of kilobytes (Stripe invoice
// objects with many line items), so it gets the same 64 KiB budget as an op.
const (
	maxCheckoutBodyBytes = 8 << 10  // 8 KiB
	maxWebhookBodyBytes  = 64 << 10 // 64 KiB
)

// billingProviderTimeout bounds the outbound provider call made while serving a
// checkout request, on top of the provider client's own timeout, so a wedged
// upstream can never outlive the server's write deadline.
const billingProviderTimeout = 12 * time.Second

// BillingConfig wires the billing layer. It is entirely OPT-IN: with no
// providers configured (the default) Enabled() is false and every billing route
// serves the deliberate 501.
type BillingConfig struct {
	// Providers maps a provider name (billing.Provider* constant) to its
	// adapter. Only configured providers get a live webhook route.
	Providers map[string]billing.Provider
	// DefaultProvider is used by POST /v1/billing/checkout when the request does
	// not name one. It is always one of the keys of Providers.
	DefaultProvider string
	// Subscriptions is the durable (or in-memory) subscription + processed-event
	// store.
	Subscriptions store.SubscriptionStore
	// SuccessURL / CancelURL are where a provider returns the customer after a
	// hosted checkout.
	SuccessURL string
	CancelURL  string
}

// Enabled reports whether billing is configured. Both halves are required: an
// adapter with nowhere to record its events would silently lose money-relevant
// state, so a half-configured billing layer stays OFF.
func (c BillingConfig) Enabled() bool {
	return len(c.Providers) > 0 && c.Subscriptions != nil
}

// billingEnabled reports whether this router serves live billing routes.
func (h *handlers) billingEnabled() bool { return h.cfg.Billing.Enabled() && h.devices != nil }

// billingNotImplemented is the deliberate 501 for every billing route when
// billing is off (dev-ops off, no providers configured, or no device registry to
// authenticate a buyer against). 501 rather than 404 so the surface is
// discoverable and unambiguous, and rather than any partial/faked behaviour.
func (h *handlers) billingNotImplemented(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		_, _ = io.Copy(io.Discard, r.Body)
	}
	writeJSON(w, http.StatusNotImplemented, apiError{
		Error:  "not_implemented",
		Detail: "billing is not enabled on this server",
	})
}

// checkoutRequestBody is the JSON body of POST /v1/billing/checkout.
//
// NOTE WHAT IS NOT HERE: no subject (server-derived from the authenticated
// device), no amount override, and above all no payment-instrument field of any
// kind. A client picks a provider and a plan; that is all it may influence.
type checkoutRequestBody struct {
	Provider string `json:"provider"`
	Plan     string `json:"plan"`
}

// checkoutResponse is what the client redirects the customer to.
type checkoutResponse struct {
	Provider  string `json:"provider"`
	SessionID string `json:"session_id,omitempty"`
	URL       string `json:"url"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

// newCheckoutReference returns a fresh, unguessable per-attempt reference used
// as the provider's idempotency key / reference_id / order_id. It is generated
// by the SERVER (never supplied by the client) so a client cannot collide with,
// or overwrite, another attempt.
func newCheckoutReference() (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "sigil-" + hex.EncodeToString(raw[:]), nil
}

// billingCheckout creates a hosted checkout session for the authenticated
// device and returns the provider's URL.
func (h *handlers) billingCheckout(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxCheckoutBodyBytes+1))
	if err != nil || len(body) > maxCheckoutBodyBytes {
		writeError(w, http.StatusBadRequest, "invalid_request", "could not read request body")
		return
	}
	// The v3 signature covers the body, so authenticate AFTER reading it. This is
	// the SAME choke point the ops and device routes use — no second auth path.
	dev, out := h.authenticateDevice(r, body)
	if !out.allowed() {
		h.denyOps(w, r, "", out)
		return
	}

	var req checkoutRequestBody
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_request", "body must be a JSON object")
			return
		}
	}

	name := req.Provider
	if name == "" {
		name = h.cfg.Billing.DefaultProvider
	}
	provider, ok := h.cfg.Billing.Providers[name]
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown_provider",
			"that payment provider is not enabled on this server")
		return
	}

	reference, err := newCheckoutReference()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}

	// Bind subject -> provider BEFORE calling out, so a webhook that races the
	// HTTP response still has a row to resolve against.
	if err := h.cfg.Billing.Subscriptions.StartCheckout(r.Context(), dev.ID, name, time.Now().UTC()); err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), billingProviderTimeout)
	defer cancel()
	session, err := provider.CreateCheckout(ctx, billing.CheckoutRequest{
		Subject:    dev.ID, // SERVER-DERIVED, never from the body
		Reference:  reference,
		PlanRef:    req.Plan,
		SuccessURL: h.cfg.Billing.SuccessURL,
		CancelURL:  h.cfg.Billing.CancelURL,
	})
	if err != nil {
		// The error may name the provider and an HTTP status, never a secret
		// (see billing.ProviderError). It is logged, not returned.
		h.auditCheckoutFailed(r, name, dev.ID, err)
		if errors.Is(err, billing.ErrNotConfigured) {
			writeError(w, http.StatusInternalServerError, "internal", "")
			return
		}
		writeError(w, http.StatusBadGateway, "provider_error",
			"the payment provider could not create a checkout session")
		return
	}

	h.auditCheckoutCreated(r, name, dev.ID, session.SessionID)
	h.metrics.incBillingCheckout(name)

	resp := checkoutResponse{
		Provider:  session.Provider,
		SessionID: session.SessionID,
		URL:       session.URL,
	}
	if !session.ExpiresAt.IsZero() {
		resp.ExpiresAt = session.ExpiresAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusCreated, resp)
}

// webhookResponse is the acknowledgement body. Status is the store's verdict
// (accepted / ignored / duplicate / stale / rejected / unresolved) — useful in a
// provider dashboard's delivery log, and carrying nothing sensitive.
type webhookResponse struct {
	Provider string `json:"provider"`
	Status   string `json:"status"`
}

// billingWebhook authenticates an inbound provider webhook by the PROVIDER's own
// signature over the RAW request body, then applies it idempotently.
//
// STATUS CODES, and why:
//
//	200  accepted / ignored / duplicate / stale / rejected / unresolved.
//	     Every one of these means "we handled it, stop retrying". A provider that
//	     receives a non-2xx enters exponential retry, so returning an error for
//	     an event we simply do not model would generate load and noise forever.
//	400  the signature was valid but the body is unparsable.
//	401  signature verification failed — for ANY reason.
//	413  the body exceeded the cap.
//	500  our store failed. This one SHOULD be retried, so it is deliberately the
//	     only error class a healthy provider will see.
//
// The 401 body is COARSE: a missing header, a malformed header, a wrong secret,
// a tampered body and a stale timestamp all produce the identical response, so a
// prober cannot learn which check tripped. The precise reason goes only to the
// audit log and the per-reason metric.
func (h *handlers) billingWebhook(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	provider, ok := h.cfg.Billing.Providers[name]
	if !ok {
		_, _ = io.Copy(io.Discard, io.LimitReader(r.Body, maxWebhookBodyBytes))
		h.auditWebhookRejected(r, name, "unknown_provider")
		h.metrics.incBillingWebhookRejected("unknown_provider")
		writeError(w, http.StatusNotFound, "unknown_provider",
			"no webhook endpoint is configured for that provider")
		return
	}

	// Read the body ONCE, and keep the EXACT bytes. Everything downstream —
	// signature verification first, JSON parsing second — works from this slice.
	// Re-encoding before verification would change key order and whitespace and
	// break (or, worse, weaken) the MAC.
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxWebhookBodyBytes+1))
	if err != nil {
		h.auditWebhookRejected(r, name, "unreadable_body")
		h.metrics.incBillingWebhookRejected("malformed")
		writeError(w, http.StatusBadRequest, "invalid_request", "could not read request body")
		return
	}
	if len(raw) > maxWebhookBodyBytes {
		h.auditWebhookRejected(r, name, "payload_too_large")
		h.metrics.incBillingWebhookRejected("payload_too_large")
		writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
			"request body exceeds the webhook size limit")
		return
	}

	ev, err := provider.VerifyWebhook(r.Header, raw)
	switch {
	case err == nil:
	case errors.Is(err, billing.ErrBadSignature):
		h.auditWebhookRejected(r, name, "bad_signature")
		h.metrics.incBillingWebhookRejected("bad_signature")
		// Coarse on purpose. Never echo the header, the body, or the reason.
		writeError(w, http.StatusUnauthorized, "unauthorized", "webhook authentication failed")
		return
	default:
		// ErrMalformedWebhook, and anything unexpected, are one client-visible
		// verdict: we could not parse what you sent.
		h.auditWebhookRejected(r, name, "malformed")
		h.metrics.incBillingWebhookRejected("malformed")
		writeError(w, http.StatusBadRequest, "invalid_request", "webhook payload could not be parsed")
		return
	}

	// Authentic. Does it drive a transition at all?
	target, drives := billing.TargetStatus(ev.Type, ev.Trial)
	if !drives {
		h.auditWebhook(r, ev, "ignored")
		h.metrics.incBillingWebhook(name, "ignored")
		writeJSON(w, http.StatusOK, webhookResponse{Provider: name, Status: "ignored"})
		return
	}

	outcome, err := h.cfg.Billing.Subscriptions.ApplyWebhookEvent(r.Context(), store.SubscriptionEvent{
		Provider: ev.Provider,
		// NOT ev.ID: the idempotency key must come from bytes the provider's
		// signature covers, or a replay with a fresh (unsigned) event-id header
		// would be processed as a new event. See billing.Event.DedupKey.
		EventID:          ev.IdempotencyKey(),
		EventType:        string(ev.Type),
		Subject:          ev.Subject,
		CustomerRef:      ev.CustomerRef,
		SubscriptionRef:  ev.SubscriptionRef,
		Target:           target,
		OccurredAt:       ev.OccurredAt,
		CurrentPeriodEnd: ev.CurrentPeriodEnd,
	})
	if err != nil {
		h.auditWebhookRejected(r, name, "store_unavailable")
		h.metrics.incBillingWebhookRejected("store_error")
		// The ONLY retryable class: a provider re-delivering after a store fault
		// is exactly what we want.
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}

	status := string(outcome.Result)
	if outcome.Result == store.ApplyApplied {
		status = "accepted"
	}
	h.auditWebhook(r, ev, status)
	h.metrics.incBillingWebhook(name, status)
	if outcome.Changed() {
		h.auditSubscriptionTransition(r, ev.Provider, outcome.Subscription.Subject,
			string(outcome.From), string(outcome.To))
		h.metrics.incBillingTransition(outcome.To)
	}
	writeJSON(w, http.StatusOK, webhookResponse{Provider: name, Status: status})
}

// subscriptionResponse is the caller's own billing status.
type subscriptionResponse struct {
	Subject          string `json:"subject"`
	Provider         string `json:"provider,omitempty"`
	Status           string `json:"status"`
	Entitled         bool   `json:"entitled"`
	CurrentPeriodEnd string `json:"current_period_end,omitempty"`
	UpdatedAt        string `json:"updated_at,omitempty"`
}

// billingSubscription returns the AUTHENTICATED DEVICE's subscription status.
// The subject is taken from the verified signature, never from a query
// parameter, so this endpoint cannot be used to enumerate other subjects.
func (h *handlers) billingSubscription(w http.ResponseWriter, r *http.Request) {
	dev, out := h.authenticateDevice(r, nil)
	if !out.allowed() {
		h.denyOps(w, r, "", out)
		return
	}

	sub, err := h.cfg.Billing.Subscriptions.GetSubscription(r.Context(), dev.ID)
	if err != nil {
		if errors.Is(err, store.ErrSubscriptionNotFound) {
			// "Never subscribed" is a valid answer, not a fault.
			writeJSON(w, http.StatusOK, subscriptionResponse{
				Subject: dev.ID, Status: string(billing.StatusNone), Entitled: false,
			})
			return
		}
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}

	status := sub.Status
	if status == "" {
		status = billing.StatusNone
	}
	resp := subscriptionResponse{
		Subject:  sub.Subject,
		Provider: sub.Provider,
		Status:   string(status),
		Entitled: status.Entitled(),
	}
	if !sub.CurrentPeriodEnd.IsZero() {
		resp.CurrentPeriodEnd = sub.CurrentPeriodEnd.UTC().Format(time.RFC3339)
	}
	if !sub.UpdatedAt.IsZero() {
		resp.UpdatedAt = sub.UpdatedAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, http.StatusOK, resp)
}
