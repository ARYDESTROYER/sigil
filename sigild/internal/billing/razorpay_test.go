package billing

// Razorpay adapter tests.
//
// EVERY credential here is OBVIOUSLY FAKE (rzp_test_..., a literal
// "razorpay_test_fake_webhook_secret") and exists only in this test binary. NO
// test here reaches the network — checkout drives a local httptest server.
//
// Expected HMACs are COMPUTED IN THE TEST from the fake secret.

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
	"strings"
	"testing"
	"time"
)

const (
	fakeRazorpayKeyID     = "rzp_test_fake_key_id_0000"
	fakeRazorpayKeySecret = "rzp_test_fake_key_secret_0000"
	fakeRazorpayWebhookSe = "razorpay_test_fake_webhook_secret_0000"
)

// razorpaySignature builds a real X-Razorpay-Signature for body: the hex
// HMAC-SHA256 of the RAW body keyed by secret. No timestamp, no prefix — that
// difference from Stripe is the whole scheme.
func razorpaySignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func newTestRazorpay() *RazorpayProvider {
	return NewRazorpay(RazorpayConfig{
		KeyID:         fakeRazorpayKeyID,
		KeySecret:     fakeRazorpayKeySecret,
		WebhookSecret: fakeRazorpayWebhookSe,
		AmountMinor:   49900,
		Currency:      "INR",
		Description:   "Sigil subscription",
		Now:           fixedClock(time.Unix(1700000000, 0)),
	})
}

func razorpayBody() []byte {
	return []byte(`{"entity":"event","event":"subscription.charged","created_at":1700000000,` +
		`"payload":{"subscription":{"entity":{"id":"sub_rzp_1","status":"active",` +
		`"current_end":1702592000,"customer_id":"cust_rzp_1","notes":{"sigil_subject":"dev_rzp"}}}}}`)
}

func TestRazorpayValidSignatureAccepted(t *testing.T) {
	p := newTestRazorpay()
	body := razorpayBody()

	h := http.Header{}
	h.Set(razorpaySignatureHeader, razorpaySignature(fakeRazorpayWebhookSe, body))
	h.Set(razorpayEventIDHeader, "evt_rzp_1")

	ev, err := p.VerifyWebhook(h, body)
	if err != nil {
		t.Fatalf("VerifyWebhook: %v", err)
	}
	if ev.Provider != ProviderRazorpay || ev.ID != "evt_rzp_1" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Type != EventSubscriptionRenewed {
		t.Fatalf("type = %q, want %q", ev.Type, EventSubscriptionRenewed)
	}
	if ev.Subject != "dev_rzp" {
		t.Fatalf("subject = %q, want dev_rzp (from notes)", ev.Subject)
	}
	if ev.SubscriptionRef != "sub_rzp_1" || ev.CustomerRef != "cust_rzp_1" {
		t.Fatalf("refs = %q/%q", ev.SubscriptionRef, ev.CustomerRef)
	}
	if ev.CurrentPeriodEnd.IsZero() {
		t.Fatal("current_end not decoded")
	}
}

func TestRazorpayTamperedBodyRejected(t *testing.T) {
	p := newTestRazorpay()
	body := razorpayBody()

	h := http.Header{}
	h.Set(razorpaySignatureHeader, razorpaySignature(fakeRazorpayWebhookSe, body))

	tampered := []byte(strings.Replace(string(body), "dev_rzp", "dev_XXX", 1))
	if _, err := p.VerifyWebhook(h, tampered); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered: err = %v, want ErrBadSignature", err)
	}
}

func TestRazorpayWrongSecretRejected(t *testing.T) {
	p := newTestRazorpay()
	body := razorpayBody()

	h := http.Header{}
	h.Set(razorpaySignatureHeader, razorpaySignature("razorpay_test_fake_WRONG_secret", body))
	if _, err := p.VerifyWebhook(h, body); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong secret: err = %v, want ErrBadSignature", err)
	}
}

func TestRazorpayMalformedOrMissingHeaderRejected(t *testing.T) {
	p := newTestRazorpay()
	body := razorpayBody()

	cases := map[string]string{
		"missing":        "",
		"not hex":        "zzzznothex",
		"wrong length":   "abcd",
		"empty-ish":      "   ",
		"valid-hex-junk": strings.Repeat("00", 32),
	}
	for name, sig := range cases {
		t.Run(name, func(t *testing.T) {
			h := http.Header{}
			if sig != "" {
				h.Set(razorpaySignatureHeader, sig)
			}
			if _, err := p.VerifyWebhook(h, body); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("err = %v, want ErrBadSignature", err)
			}
		})
	}
}

// TestRazorpayVerifiesRawBytesNotReencodedJSON: the same load-bearing proof as
// for Stripe. A body with odd key order/whitespace verifies as received; the
// same JSON re-serialized does not.
func TestRazorpayVerifiesRawBytesNotReencodedJSON(t *testing.T) {
	p := newTestRazorpay()

	odd := []byte("{\n\t\"payload\" : { \"subscription\" : { \"entity\" : { \"id\" : \"sub_raw\", " +
		"\"notes\" : { \"sigil_subject\" : \"dev_raw\" } } } },\n" +
		"\t\"created_at\" : 1700000000,\n\t\"event\":\"subscription.activated\"\n}")

	h := http.Header{}
	h.Set(razorpaySignatureHeader, razorpaySignature(fakeRazorpayWebhookSe, odd))
	h.Set(razorpayEventIDHeader, "evt_raw")

	ev, err := p.VerifyWebhook(h, odd)
	if err != nil {
		t.Fatalf("raw body must verify: %v", err)
	}
	if ev.Subject != "dev_raw" || ev.Type != EventSubscriptionActivated {
		t.Fatalf("event = %+v", ev)
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
		t.Fatal("re-encoded bytes identical; the test proves nothing")
	}
	if _, err := p.VerifyWebhook(h, reencoded); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("re-encoded body verified: NOT checking raw bytes (err = %v)", err)
	}
}

// TestRazorpayEventIDFallback: with no X-Razorpay-Event-Id header the adapter
// derives a DETERMINISTIC id from the body, so a byte-identical redelivery still
// deduplicates.
func TestRazorpayEventIDFallback(t *testing.T) {
	p := newTestRazorpay()
	body := razorpayBody()
	h := http.Header{}
	h.Set(razorpaySignatureHeader, razorpaySignature(fakeRazorpayWebhookSe, body))

	first, err := p.VerifyWebhook(h, body)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := p.VerifyWebhook(h, body)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if first.ID == "" || first.ID != second.ID {
		t.Fatalf("fallback ids differ or empty: %q vs %q", first.ID, second.ID)
	}
	if !strings.HasPrefix(first.ID, "body-") {
		t.Fatalf("fallback id = %q, want a body- prefix", first.ID)
	}
}

func TestRazorpayEventMapping(t *testing.T) {
	p := newTestRazorpay()
	tests := []struct {
		event string
		want  EventType
	}{
		{"payment_link.paid", EventCheckoutCompleted},
		{"subscription.activated", EventSubscriptionActivated},
		{"subscription.authenticated", EventSubscriptionActivated},
		{"subscription.resumed", EventSubscriptionActivated},
		{"subscription.charged", EventSubscriptionRenewed},
		{"subscription.cancelled", EventSubscriptionCanceled},
		{"subscription.completed", EventSubscriptionCanceled},
		{"subscription.expired", EventSubscriptionCanceled},
		{"subscription.halted", EventPaymentFailed},
		{"subscription.pending", EventPaymentFailed},
		{"payment.failed", EventPaymentFailed},
		{"refund.processed", EventIgnored},
		{"settlement.processed", EventIgnored},
	}
	for _, tc := range tests {
		t.Run(tc.event, func(t *testing.T) {
			body := []byte(`{"event":"` + tc.event + `","created_at":1700000000,"payload":{}}`)
			ev, err := p.parseEvent("evt_"+tc.event, body)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if ev.Type != tc.want {
				t.Fatalf("type = %q, want %q", ev.Type, tc.want)
			}
		})
	}
}

func TestRazorpaySubjectFromPaymentLinkNotes(t *testing.T) {
	p := newTestRazorpay()
	body := []byte(`{"event":"payment_link.paid","created_at":1700000000,` +
		`"payload":{"payment_link":{"entity":{"id":"plink_1","notes":{"sigil_subject":"dev_link"}}},` +
		`"payment":{"entity":{"id":"pay_1"}}}}`)
	ev, err := p.parseEvent("evt_link", body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.Subject != "dev_link" || ev.SubscriptionRef != "plink_1" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Type != EventCheckoutCompleted {
		t.Fatalf("type = %q", ev.Type)
	}
}

// TestRazorpayNonStringNoteDoesNotPanic: notes values are merchant-controlled
// and may be numbers or objects; a surprise type must be ignored, not fatal.
func TestRazorpayNonStringNoteDoesNotPanic(t *testing.T) {
	p := newTestRazorpay()
	body := []byte(`{"event":"subscription.activated","created_at":1700000000,` +
		`"payload":{"subscription":{"entity":{"id":"s","notes":{"sigil_subject":12345}}}}}`)
	ev, err := p.parseEvent("evt_x", body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if ev.Subject != "" {
		t.Fatalf("subject = %q, want empty for a non-string note", ev.Subject)
	}
}

func TestRazorpayMalformedPayloadRejected(t *testing.T) {
	p := newTestRazorpay()
	for _, body := range []string{"not json", `{"created_at":1}`, ""} {
		h := http.Header{}
		h.Set(razorpaySignatureHeader, razorpaySignature(fakeRazorpayWebhookSe, []byte(body)))
		if _, err := p.VerifyWebhook(h, []byte(body)); !errors.Is(err, ErrMalformedWebhook) {
			t.Fatalf("body %q: err = %v, want ErrMalformedWebhook", body, err)
		}
	}
}

// TestRazorpayCreateCheckout drives a LOCAL httptest server. No network.
func TestRazorpayCreateCheckout(t *testing.T) {
	var (
		gotPath string
		gotUser string
		gotPass string
		gotBody razorpayLinkRequest
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotUser, gotPass, _ = r.BasicAuth()
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"plink_created","short_url":"https://rzp.test/i/abc","expire_by":1700003600}`))
	}))
	defer srv.Close()

	p := NewRazorpay(RazorpayConfig{
		KeyID: fakeRazorpayKeyID, KeySecret: fakeRazorpayKeySecret,
		WebhookSecret: fakeRazorpayWebhookSe,
		AmountMinor:   49900, Currency: "INR", Description: "Sigil subscription",
		BaseURL: srv.URL, HTTPClient: srv.Client(),
	})

	session, err := p.CreateCheckout(context.Background(), CheckoutRequest{
		Subject:    "dev_buyer",
		Reference:  "sigil-ref-9",
		SuccessURL: "https://app.test/ok",
	})
	if err != nil {
		t.Fatalf("CreateCheckout: %v", err)
	}
	if gotPath != "/v1/payment_links" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotUser != fakeRazorpayKeyID || gotPass != fakeRazorpayKeySecret {
		t.Fatal("basic auth did not carry the configured key pair")
	}
	if gotBody.Amount != 49900 || gotBody.Currency != "INR" {
		t.Fatalf("amount/currency = %d/%q", gotBody.Amount, gotBody.Currency)
	}
	if gotBody.ReferenceID != "sigil-ref-9" {
		t.Fatalf("reference_id = %q", gotBody.ReferenceID)
	}
	if gotBody.Notes[subjectMetadataKey] != "dev_buyer" {
		t.Fatalf("notes did not carry the subject: %+v", gotBody.Notes)
	}
	// We hand Razorpay no contact detail to notify, so no PII leaves this
	// process.
	if gotBody.Notify.SMS || gotBody.Notify.Email {
		t.Fatal("checkout requested provider-side notification, which would imply we sent contact PII")
	}
	if session.URL != "https://rzp.test/i/abc" || session.SessionID != "plink_created" {
		t.Fatalf("session = %+v", session)
	}
}

func TestRazorpayCreateCheckoutProviderError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"description":"Authentication failed for buyer@example.com"}}`))
	}))
	defer srv.Close()

	p := NewRazorpay(RazorpayConfig{
		KeyID: fakeRazorpayKeyID, KeySecret: fakeRazorpayKeySecret,
		WebhookSecret: fakeRazorpayWebhookSe, AmountMinor: 100,
		BaseURL: srv.URL, HTTPClient: srv.Client(),
	})
	_, err := p.CreateCheckout(context.Background(), CheckoutRequest{Subject: "d", Reference: "r"})
	var perr *ProviderError
	if !errors.As(err, &perr) || perr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("err = %v, want ProviderError(401)", err)
	}
	if strings.Contains(err.Error(), "example.com") {
		t.Fatalf("provider body leaked into the error: %q", err.Error())
	}
}

func TestRazorpayCreateCheckoutUnconfigured(t *testing.T) {
	p := NewRazorpay(RazorpayConfig{WebhookSecret: fakeRazorpayWebhookSe})
	if _, err := p.CreateCheckout(context.Background(), CheckoutRequest{Subject: "d"}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	// Keys present, amount missing => still a configuration error, never a
	// zero-value charge.
	p2 := NewRazorpay(RazorpayConfig{KeyID: fakeRazorpayKeyID, KeySecret: fakeRazorpayKeySecret})
	if _, err := p2.CreateCheckout(context.Background(), CheckoutRequest{Subject: "d"}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestRazorpayName(t *testing.T) {
	if newTestRazorpay().Name() != ProviderRazorpay {
		t.Fatal("name mismatch")
	}
}
