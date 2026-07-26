package billing

// Stripe adapter tests.
//
// EVERY credential here is OBVIOUSLY FAKE (whsec_test_..., sk_test_fake_...) and
// exists only inside this test binary. NO test in this file reaches the network:
// the adapter's BaseURL is pointed at a local httptest server, and the webhook
// tests do not make outbound calls at all.
//
// Every expected HMAC is COMPUTED INSIDE THE TEST from the fake secret, so the
// vectors are self-evidently correct rather than copied from somewhere.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Fake, non-functional test credentials. They match no real account and cannot
// be mistaken for one.
const (
	fakeStripeSecretKey     = "sk_test_fake_key_not_a_real_stripe_key"
	fakeStripeWebhookSec999 = "whsec_test_fake_endpoint_secret_0000000000"
)

// fixedClock returns a clock function pinned to t.
func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// stripeSignature builds a real Stripe-Signature header for body at time ts,
// keyed by secret. This is the CLIENT side of the scheme, written out
// explicitly so the test vector is verifiable by reading it.
func stripeSignature(secret string, ts int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return "t=" + strconv.FormatInt(ts, 10) + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

// newTestStripe returns an adapter with the fake webhook secret and a clock
// pinned to now.
func newTestStripe(now time.Time) *StripeProvider {
	return NewStripe(StripeConfig{
		SecretKey:     fakeStripeSecretKey,
		WebhookSecret: fakeStripeWebhookSec999,
		PriceID:       "price_test_fake_0001",
		Now:           fixedClock(now),
	})
}

// stripeBody is a minimal, valid checkout.session.completed payload.
func stripeBody(eventID string) []byte {
	return []byte(`{"id":"` + eventID + `","type":"checkout.session.completed","created":1700000000,` +
		`"data":{"object":{"id":"cs_test_1","client_reference_id":"dev_abc",` +
		`"customer":"cus_test_1","subscription":"sub_test_1"}}}`)
}

func TestStripeValidSignatureAccepted(t *testing.T) {
	now := time.Unix(1700000010, 0)
	p := newTestStripe(now)
	body := stripeBody("evt_ok")

	h := http.Header{}
	h.Set(stripeSignatureHeader, stripeSignature(fakeStripeWebhookSec999, now.Unix(), body))

	ev, err := p.VerifyWebhook(h, body)
	if err != nil {
		t.Fatalf("VerifyWebhook: %v", err)
	}
	if ev.Provider != ProviderStripe || ev.ID != "evt_ok" {
		t.Fatalf("event = %+v, want stripe/evt_ok", ev)
	}
	if ev.Type != EventCheckoutCompleted {
		t.Fatalf("type = %q, want %q", ev.Type, EventCheckoutCompleted)
	}
	if ev.Subject != "dev_abc" {
		t.Fatalf("subject = %q, want dev_abc", ev.Subject)
	}
	if ev.SubscriptionRef != "sub_test_1" || ev.CustomerRef != "cus_test_1" {
		t.Fatalf("refs = %q/%q, want sub_test_1/cus_test_1", ev.SubscriptionRef, ev.CustomerRef)
	}
}

func TestStripeTamperedBodyRejected(t *testing.T) {
	now := time.Unix(1700000010, 0)
	p := newTestStripe(now)
	body := stripeBody("evt_tamper")

	h := http.Header{}
	h.Set(stripeSignatureHeader, stripeSignature(fakeStripeWebhookSec999, now.Unix(), body))

	// Flip one byte of the payload; the signature is now over different bytes.
	tampered := append([]byte(nil), body...)
	tampered[len(tampered)-3] ^= 0x01

	if _, err := p.VerifyWebhook(h, tampered); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered body: err = %v, want ErrBadSignature", err)
	}
}

func TestStripeWrongSecretRejected(t *testing.T) {
	now := time.Unix(1700000010, 0)
	p := newTestStripe(now)
	body := stripeBody("evt_wrongsecret")

	h := http.Header{}
	h.Set(stripeSignatureHeader, stripeSignature("whsec_test_fake_WRONG_secret_00000", now.Unix(), body))

	if _, err := p.VerifyWebhook(h, body); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong secret: err = %v, want ErrBadSignature", err)
	}
}

func TestStripeMalformedOrMissingHeaderRejected(t *testing.T) {
	now := time.Unix(1700000010, 0)
	p := newTestStripe(now)
	body := stripeBody("evt_hdr")

	cases := map[string]string{
		"missing":           "",
		"no elements":       "garbage",
		"no v1":             "t=1700000010",
		"no t":              "v1=" + strings.Repeat("ab", 32),
		"non-numeric t":     "t=notanumber,v1=" + strings.Repeat("ab", 32),
		"only legacy v0":    "t=1700000010,v0=" + strings.Repeat("ab", 32),
		"non-hex signature": "t=1700000010,v1=zzzz",
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			h := http.Header{}
			if header != "" {
				h.Set(stripeSignatureHeader, header)
			}
			if _, err := p.VerifyWebhook(h, body); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("err = %v, want ErrBadSignature", err)
			}
		})
	}
}

func TestStripeStaleTimestampRejected(t *testing.T) {
	now := time.Unix(1700000000, 0)
	p := newTestStripe(now)
	body := stripeBody("evt_stale")

	// 10 minutes old: a PERFECTLY VALID MAC, rejected purely on the timestamp
	// tolerance. That is the point of the window — it bounds replay of a
	// captured, authentic delivery.
	stale := now.Add(-10 * time.Minute).Unix()
	h := http.Header{}
	h.Set(stripeSignatureHeader, stripeSignature(fakeStripeWebhookSec999, stale, body))
	if _, err := p.VerifyWebhook(h, body); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("stale: err = %v, want ErrBadSignature", err)
	}

	// Far-future is rejected symmetrically.
	future := now.Add(10 * time.Minute).Unix()
	h2 := http.Header{}
	h2.Set(stripeSignatureHeader, stripeSignature(fakeStripeWebhookSec999, future, body))
	if _, err := p.VerifyWebhook(h2, body); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("future: err = %v, want ErrBadSignature", err)
	}

	// Just inside the window is accepted, proving the boundary is the tolerance
	// and not something incidental.
	fresh := now.Add(-4 * time.Minute).Unix()
	h3 := http.Header{}
	h3.Set(stripeSignatureHeader, stripeSignature(fakeStripeWebhookSec999, fresh, body))
	if _, err := p.VerifyWebhook(h3, body); err != nil {
		t.Fatalf("in-window: err = %v, want nil", err)
	}
}

// TestStripeMultipleV1Values covers secret rotation: Stripe sends several v1
// elements while an endpoint has two live secrets, and ANY valid one must be
// accepted — otherwise rotation drops events.
func TestStripeMultipleV1Values(t *testing.T) {
	now := time.Unix(1700000010, 0)
	p := newTestStripe(now)
	body := stripeBody("evt_rotate")
	ts := now.Unix()

	good := stripeSignature(fakeStripeWebhookSec999, ts, body)
	goodHex := strings.TrimPrefix(strings.Split(good, ",")[1], "v1=")
	bogus := strings.Repeat("00", 32)

	for _, header := range []string{
		"t=" + strconv.FormatInt(ts, 10) + ",v1=" + bogus + ",v1=" + goodHex,
		"t=" + strconv.FormatInt(ts, 10) + ",v1=" + goodHex + ",v1=" + bogus,
		"t=" + strconv.FormatInt(ts, 10) + ",v0=" + bogus + ",v1=" + bogus + ",v1=" + goodHex,
	} {
		h := http.Header{}
		h.Set(stripeSignatureHeader, header)
		if _, err := p.VerifyWebhook(h, body); err != nil {
			t.Fatalf("header %q: err = %v, want nil", header, err)
		}
	}

	// All-bogus is still rejected.
	h := http.Header{}
	h.Set(stripeSignatureHeader, "t="+strconv.FormatInt(ts, 10)+",v1="+bogus+",v1="+strings.Repeat("11", 32))
	if _, err := p.VerifyWebhook(h, body); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("all-bogus: err = %v, want ErrBadSignature", err)
	}
}

// TestStripeVerifiesRawBytesNotReencodedJSON is the load-bearing proof that
// verification runs over the EXACT bytes received.
//
// It signs a body with deliberately odd key order and whitespace, confirms it
// verifies, then re-serializes the SAME JSON through encoding/json (producing
// different bytes with the same meaning) and confirms the original signature no
// longer verifies. If the adapter had verified over a re-encoded payload, the
// second check would pass — and a MITM could then reorder or reshape the JSON
// freely.
func TestStripeVerifiesRawBytesNotReencodedJSON(t *testing.T) {
	now := time.Unix(1700000010, 0)
	p := newTestStripe(now)

	odd := []byte("{\n  \"type\" : \"checkout.session.completed\",\n" +
		"  \"created\":1700000000,\n" +
		"  \"data\" : { \"object\" : { \"client_reference_id\" : \"dev_raw\" } },\n" +
		"  \"id\":\"evt_raw\"\n}")

	h := http.Header{}
	h.Set(stripeSignatureHeader, stripeSignature(fakeStripeWebhookSec999, now.Unix(), odd))

	ev, err := p.VerifyWebhook(h, odd)
	if err != nil {
		t.Fatalf("raw body with odd formatting must verify: %v", err)
	}
	if ev.Subject != "dev_raw" {
		t.Fatalf("subject = %q, want dev_raw", ev.Subject)
	}

	var generic map[string]any
	if err := json.Unmarshal(odd, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	reencoded, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(reencoded) == string(odd) {
		t.Fatal("re-encoded bytes are identical; the test proves nothing")
	}
	if _, err := p.VerifyWebhook(h, reencoded); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("re-encoded body verified under the original signature: the adapter is NOT checking raw bytes (err = %v)", err)
	}
}

// TestStripeEventMapping pins the provider-event -> normalized-event table,
// including the unknown/irrelevant case which must be accepted-and-ignored.
func TestStripeEventMapping(t *testing.T) {
	tests := []struct {
		name  string
		body  string
		want  EventType
		trial bool
	}{
		{"checkout completed", `{"id":"e1","type":"checkout.session.completed","data":{"object":{"subscription":"sub_1"}}}`, EventCheckoutCompleted, false},
		{"subscription active", `{"id":"e2","type":"customer.subscription.created","data":{"object":{"id":"sub_1","status":"active"}}}`, EventSubscriptionActivated, false},
		{"subscription trialing", `{"id":"e3","type":"customer.subscription.updated","data":{"object":{"id":"sub_1","status":"trialing"}}}`, EventSubscriptionActivated, true},
		{"subscription past_due", `{"id":"e4","type":"customer.subscription.updated","data":{"object":{"id":"sub_1","status":"past_due"}}}`, EventPaymentFailed, false},
		{"subscription canceled status", `{"id":"e5","type":"customer.subscription.updated","data":{"object":{"id":"sub_1","status":"canceled"}}}`, EventSubscriptionCanceled, false},
		{"subscription deleted", `{"id":"e6","type":"customer.subscription.deleted","data":{"object":{"id":"sub_1"}}}`, EventSubscriptionCanceled, false},
		{"invoice paid", `{"id":"e7","type":"invoice.paid","data":{"object":{"subscription":"sub_1"}}}`, EventSubscriptionRenewed, false},
		{"invoice payment_succeeded", `{"id":"e8","type":"invoice.payment_succeeded","data":{"object":{"subscription":"sub_1"}}}`, EventSubscriptionRenewed, false},
		{"invoice payment_failed", `{"id":"e9","type":"invoice.payment_failed","data":{"object":{"subscription":"sub_1"}}}`, EventPaymentFailed, false},
		{"unknown type ignored", `{"id":"e10","type":"charge.refunded","data":{"object":{"id":"ch_1"}}}`, EventIgnored, false},
		{"unmodeled sub status ignored", `{"id":"e11","type":"customer.subscription.updated","data":{"object":{"id":"sub_1","status":"incomplete"}}}`, EventIgnored, false},
		{"expanded customer object", `{"id":"e12","type":"invoice.paid","data":{"object":{"customer":{"id":"cus_x"},"subscription":"sub_1"}}}`, EventSubscriptionRenewed, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ev, err := parseStripeEvent([]byte(tc.body))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if ev.Type != tc.want {
				t.Fatalf("type = %q, want %q", ev.Type, tc.want)
			}
			if ev.Trial != tc.trial {
				t.Fatalf("trial = %v, want %v", ev.Trial, tc.trial)
			}
		})
	}
}

func TestStripeMalformedPayloadRejected(t *testing.T) {
	now := time.Unix(1700000010, 0)
	p := newTestStripe(now)
	for _, body := range []string{`not json at all`, `{"type":"x"}`, `{"id":"e"}`, ``} {
		h := http.Header{}
		h.Set(stripeSignatureHeader, stripeSignature(fakeStripeWebhookSec999, now.Unix(), []byte(body)))
		_, err := p.VerifyWebhook(h, []byte(body))
		if !errors.Is(err, ErrMalformedWebhook) {
			t.Fatalf("body %q: err = %v, want ErrMalformedWebhook", body, err)
		}
	}
}

func TestStripeExpandedCustomerRef(t *testing.T) {
	ev, err := parseStripeEvent([]byte(`{"id":"e","type":"invoice.paid","data":{"object":{"customer":{"id":"cus_expanded"},"subscription":"sub_1"}}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.CustomerRef != "cus_expanded" {
		t.Fatalf("customer ref = %q, want cus_expanded", ev.CustomerRef)
	}
}

// TestStripeCreateCheckout drives a LOCAL httptest server standing in for
// api.stripe.com and asserts the exact request shape. No network.
func TestStripeCreateCheckout(t *testing.T) {
	var (
		gotPath   string
		gotAuth   string
		gotIdem   string
		gotCT     string
		gotForm   url.Values
		serverHit int
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverHit++
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotIdem = r.Header.Get("Idempotency-Key")
		gotCT = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		gotForm, _ = url.ParseQuery(string(raw))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cs_test_created","url":"https://checkout.stripe.test/pay/cs_test_created","expires_at":1700003600}`))
	}))
	defer srv.Close()

	p := NewStripe(StripeConfig{
		SecretKey:     fakeStripeSecretKey,
		WebhookSecret: fakeStripeWebhookSec999,
		PriceID:       "price_test_fake_0001",
		BaseURL:       srv.URL,
		HTTPClient:    srv.Client(),
	})

	session, err := p.CreateCheckout(context.Background(), CheckoutRequest{
		Subject:    "dev_buyer",
		Reference:  "sigil-ref-1",
		SuccessURL: "https://app.test/ok",
		CancelURL:  "https://app.test/cancel",
	})
	if err != nil {
		t.Fatalf("CreateCheckout: %v", err)
	}

	if serverHit != 1 {
		t.Fatalf("server hit %d times, want 1", serverHit)
	}
	if gotPath != "/v1/checkout/sessions" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotAuth != "Bearer "+fakeStripeSecretKey {
		t.Fatalf("authorization header not the bearer key")
	}
	if gotIdem != "sigil-ref-1" {
		t.Fatalf("idempotency key = %q", gotIdem)
	}
	if gotCT != "application/x-www-form-urlencoded" {
		t.Fatalf("content-type = %q", gotCT)
	}
	for k, want := range map[string]string{
		"mode":                    "subscription",
		"line_items[0][price]":    "price_test_fake_0001",
		"line_items[0][quantity]": "1",
		"success_url":             "https://app.test/ok",
		"cancel_url":              "https://app.test/cancel",
		"client_reference_id":     "dev_buyer",
		"subscription_data[metadata][" + subjectMetadataKey + "]": "dev_buyer",
	} {
		if got := gotForm.Get(k); got != want {
			t.Fatalf("form[%q] = %q, want %q", k, got, want)
		}
	}
	// PROOF OF THE PCI BOUNDARY: no card-ish parameter is sent, because none
	// exists anywhere in the request path.
	for _, forbidden := range []string{"card", "number", "cvc", "cvv", "exp_month", "exp_year", "pan"} {
		for key := range gotForm {
			if strings.Contains(strings.ToLower(key), forbidden) {
				t.Fatalf("checkout form carried a card-ish parameter %q", key)
			}
		}
	}

	if session.URL != "https://checkout.stripe.test/pay/cs_test_created" {
		t.Fatalf("url = %q", session.URL)
	}
	if session.SessionID != "cs_test_created" {
		t.Fatalf("session id = %q", session.SessionID)
	}
	if session.ExpiresAt.IsZero() {
		t.Fatal("expires_at not decoded")
	}
}

func TestStripeCreateCheckoutProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		// A realistic provider error body, which must NOT surface in our error.
		_, _ = w.Write([]byte(`{"error":{"message":"No such price: price_x for customer buyer@example.com"}}`))
	}))
	defer srv.Close()

	p := NewStripe(StripeConfig{
		SecretKey: fakeStripeSecretKey, WebhookSecret: fakeStripeWebhookSec999,
		PriceID: "price_x", BaseURL: srv.URL, HTTPClient: srv.Client(),
	})
	_, err := p.CreateCheckout(context.Background(), CheckoutRequest{Subject: "dev_x", Reference: "r"})
	if err == nil {
		t.Fatal("want an error")
	}
	var perr *ProviderError
	if !errors.As(err, &perr) {
		t.Fatalf("err = %v, want *ProviderError", err)
	}
	if perr.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d", perr.StatusCode)
	}
	// The provider's response body (which contained an email address) must not
	// have leaked into the error string.
	if strings.Contains(err.Error(), "example.com") || strings.Contains(err.Error(), "No such price") {
		t.Fatalf("provider response body leaked into the error: %q", err.Error())
	}
}

func TestStripeCreateCheckoutUnconfigured(t *testing.T) {
	p := NewStripe(StripeConfig{WebhookSecret: fakeStripeWebhookSec999})
	if _, err := p.CreateCheckout(context.Background(), CheckoutRequest{Subject: "dev"}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestStripeNameAndNoSecretInErrors(t *testing.T) {
	p := newTestStripe(time.Unix(1700000000, 0))
	if p.Name() != ProviderStripe {
		t.Fatalf("name = %q", p.Name())
	}
	h := http.Header{}
	h.Set(stripeSignatureHeader, "t=1,v1=deadbeef")
	_, err := p.VerifyWebhook(h, []byte("{}"))
	if err == nil {
		t.Fatal("want an error")
	}
	if strings.Contains(err.Error(), fakeStripeWebhookSec999) || strings.Contains(err.Error(), fakeStripeSecretKey) {
		t.Fatalf("a secret leaked into an error string: %q", err.Error())
	}
}
