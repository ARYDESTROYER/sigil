package billing

// Juspay adapter tests.
//
// EVERY credential here is OBVIOUSLY FAKE and exists only in this test binary.
// NO test here reaches the network — checkout drives a local httptest server.
//
// These tests verify what the adapter ACTUALLY DOES, honestly: they do not claim
// the implemented scheme is Juspay's. The provider contract is
// UNVERIFIED-AGAINST-LIVE-DASHBOARD (see the banner in juspay.go); what these
// tests prove is that both implemented schemes are REAL and correctly enforced —
// constant-time, fail-closed, over raw bytes for the hmac scheme — and that the
// verifier can be swapped without touching anything outside juspay.go.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
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
	fakeJuspayMerchantID = "juspay_test_fake_merchant"
	fakeJuspayAPIKey     = "juspay_test_fake_api_key_0000"
	fakeJuspayWebhookUsr = "juspay_test_fake_webhook_user"
	fakeJuspayWebhookPwd = "juspay_test_fake_webhook_password"
	fakeJuspayWebhookSec = "juspay_test_fake_webhook_secret_0000"
)

func juspayBody(eventName string) []byte {
	return []byte(`{"id":"evt_jp_1","event_name":"` + eventName + `","date_created":"2023-11-14T22:13:20Z",` +
		`"content":{"order":{"order_id":"order_jp_1","status":"CHARGED","customer_id":"cust_jp_1","udf1":"dev_jp"}}}`)
}

func newTestJuspayBasic() *JuspayProvider {
	return NewJuspay(JuspayConfig{
		MerchantID:      fakeJuspayMerchantID,
		APIKey:          fakeJuspayAPIKey,
		WebhookScheme:   JuspaySchemeBasic,
		WebhookUsername: fakeJuspayWebhookUsr,
		WebhookPassword: fakeJuspayWebhookPwd,
		AmountMinor:     49900,
		Currency:        "INR",
		Now:             fixedClock(time.Unix(1700000000, 0)),
	})
}

func newTestJuspayHMAC() *JuspayProvider {
	return NewJuspay(JuspayConfig{
		MerchantID:    fakeJuspayMerchantID,
		APIKey:        fakeJuspayAPIKey,
		WebhookScheme: JuspaySchemeHMAC,
		WebhookSecret: fakeJuspayWebhookSec,
		AmountMinor:   49900,
		Currency:      "INR",
		Now:           fixedClock(time.Unix(1700000000, 0)),
	})
}

func basicHeader(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

func juspayHMACSignature(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// ---- basic scheme ----

func TestJuspayBasicValidCredentialsAccepted(t *testing.T) {
	p := newTestJuspayBasic()
	if p.WebhookScheme() != JuspaySchemeBasic {
		t.Fatalf("scheme = %q", p.WebhookScheme())
	}
	body := juspayBody("ORDER_SUCCEEDED")

	h := http.Header{}
	h.Set("Authorization", basicHeader(fakeJuspayWebhookUsr, fakeJuspayWebhookPwd))

	ev, err := p.VerifyWebhook(h, body)
	if err != nil {
		t.Fatalf("VerifyWebhook: %v", err)
	}
	if ev.Provider != ProviderJuspay || ev.ID != "evt_jp_1" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Type != EventCheckoutCompleted {
		t.Fatalf("type = %q, want %q", ev.Type, EventCheckoutCompleted)
	}
	if ev.Subject != "dev_jp" || ev.SubscriptionRef != "order_jp_1" {
		t.Fatalf("subject/ref = %q/%q", ev.Subject, ev.SubscriptionRef)
	}
	if !ev.OccurredAt.Equal(time.Date(2023, 11, 14, 22, 13, 20, 0, time.UTC)) {
		t.Fatalf("occurred_at = %v", ev.OccurredAt)
	}
}

func TestJuspayBasicWrongCredentialsRejected(t *testing.T) {
	p := newTestJuspayBasic()
	body := juspayBody("ORDER_SUCCEEDED")

	cases := map[string]string{
		"missing":          "",
		"wrong password":   basicHeader(fakeJuspayWebhookUsr, "wrong"),
		"wrong username":   basicHeader("wrong", fakeJuspayWebhookPwd),
		"both wrong":       basicHeader("wrong", "wrong"),
		"not basic":        "Bearer " + fakeJuspayWebhookPwd,
		"not base64":       "Basic !!!!not-base64!!!!",
		"no colon":         "Basic " + base64.StdEncoding.EncodeToString([]byte("nocolonhere")),
		"prefix only":      "Basic ",
		"empty credential": basicHeader("", ""),
	}
	for name, header := range cases {
		t.Run(name, func(t *testing.T) {
			h := http.Header{}
			if header != "" {
				h.Set("Authorization", header)
			}
			if _, err := p.VerifyWebhook(h, body); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("err = %v, want ErrBadSignature", err)
			}
		})
	}
}

// TestJuspayBasicFailsClosedWhenUnconfigured: a verifier with no credentials
// must accept NOTHING. An "unconfigured means open" bug on a payment webhook
// would let anyone mint subscriptions.
func TestJuspayBasicFailsClosedWhenUnconfigured(t *testing.T) {
	p := NewJuspay(JuspayConfig{MerchantID: fakeJuspayMerchantID, APIKey: fakeJuspayAPIKey})
	h := http.Header{}
	h.Set("Authorization", basicHeader("", ""))
	if _, err := p.VerifyWebhook(h, juspayBody("ORDER_SUCCEEDED")); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("unconfigured verifier accepted a request: %v", err)
	}
	// Even a completely empty header set must be refused.
	if _, err := p.VerifyWebhook(http.Header{}, juspayBody("ORDER_SUCCEEDED")); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("unconfigured verifier accepted an unauthenticated request: %v", err)
	}
}

// ---- hmac scheme ----

func TestJuspayHMACValidSignatureAccepted(t *testing.T) {
	p := newTestJuspayHMAC()
	if p.WebhookScheme() != JuspaySchemeHMAC {
		t.Fatalf("scheme = %q", p.WebhookScheme())
	}
	body := juspayBody("MANDATE_ACTIVATED")

	h := http.Header{}
	h.Set(juspayDefaultSignatureHeader, juspayHMACSignature(fakeJuspayWebhookSec, body))

	ev, err := p.VerifyWebhook(h, body)
	if err != nil {
		t.Fatalf("VerifyWebhook: %v", err)
	}
	if ev.Type != EventSubscriptionActivated {
		t.Fatalf("type = %q", ev.Type)
	}
}

func TestJuspayHMACTamperedAndWrongSecretRejected(t *testing.T) {
	p := newTestJuspayHMAC()
	body := juspayBody("ORDER_SUCCEEDED")

	good := http.Header{}
	good.Set(juspayDefaultSignatureHeader, juspayHMACSignature(fakeJuspayWebhookSec, body))
	tampered := []byte(strings.Replace(string(body), "dev_jp", "dev_XX", 1))
	if _, err := p.VerifyWebhook(good, tampered); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("tampered: err = %v, want ErrBadSignature", err)
	}

	wrong := http.Header{}
	wrong.Set(juspayDefaultSignatureHeader, juspayHMACSignature("juspay_test_fake_WRONG_secret", body))
	if _, err := p.VerifyWebhook(wrong, body); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("wrong secret: err = %v, want ErrBadSignature", err)
	}

	for _, sig := range []string{"", "zzz", strings.Repeat("00", 32)} {
		h := http.Header{}
		if sig != "" {
			h.Set(juspayDefaultSignatureHeader, sig)
		}
		if _, err := p.VerifyWebhook(h, body); !errors.Is(err, ErrBadSignature) {
			t.Fatalf("sig %q: err = %v, want ErrBadSignature", sig, err)
		}
	}
}

// TestJuspayHMACVerifiesRawBytesNotReencodedJSON: the same raw-bytes proof.
func TestJuspayHMACVerifiesRawBytesNotReencodedJSON(t *testing.T) {
	p := newTestJuspayHMAC()
	odd := []byte("{  \"content\" : { \"order\" : { \"udf1\" : \"dev_raw\", \"order_id\":\"o1\" } },\n" +
		"   \"event_name\"  :  \"ORDER_SUCCEEDED\", \"id\" : \"evt_raw\" }")

	h := http.Header{}
	h.Set(juspayDefaultSignatureHeader, juspayHMACSignature(fakeJuspayWebhookSec, odd))

	ev, err := p.VerifyWebhook(h, odd)
	if err != nil {
		t.Fatalf("raw body must verify: %v", err)
	}
	if ev.Subject != "dev_raw" {
		t.Fatalf("subject = %q", ev.Subject)
	}

	var generic map[string]any
	if err := json.Unmarshal(odd, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	reencoded, _ := json.Marshal(generic)
	if string(reencoded) == string(odd) {
		t.Fatal("re-encoded bytes identical; the test proves nothing")
	}
	if _, err := p.VerifyWebhook(h, reencoded); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("re-encoded body verified: NOT checking raw bytes (err = %v)", err)
	}
}

// TestJuspayHMACCustomHeaderName: the header name is configurable BECAUSE the
// real one is unconfirmed. Swapping it must work without touching anything else.
func TestJuspayHMACCustomHeaderName(t *testing.T) {
	p := NewJuspay(JuspayConfig{
		MerchantID: fakeJuspayMerchantID, APIKey: fakeJuspayAPIKey,
		WebhookScheme: JuspaySchemeHMAC, WebhookSecret: fakeJuspayWebhookSec,
		WebhookSignatureHeader: "X-Custom-Signature",
	})
	body := juspayBody("ORDER_SUCCEEDED")

	h := http.Header{}
	h.Set("X-Custom-Signature", juspayHMACSignature(fakeJuspayWebhookSec, body))
	if _, err := p.VerifyWebhook(h, body); err != nil {
		t.Fatalf("custom header: %v", err)
	}

	// The DEFAULT header no longer authenticates anything on this instance.
	h2 := http.Header{}
	h2.Set(juspayDefaultSignatureHeader, juspayHMACSignature(fakeJuspayWebhookSec, body))
	if _, err := p.VerifyWebhook(h2, body); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("default header accepted after override: %v", err)
	}
}

// TestJuspayDefaultSchemeBindsTheBody: with NO scheme configured the adapter
// selects the HMAC verifier, not basic. Basic authenticates the CONNECTION and
// not the PAYLOAD, so it must never be what an operator gets by leaving a
// variable unset — and an unconfigured default still fails closed.
func TestJuspayDefaultSchemeBindsTheBody(t *testing.T) {
	p := NewJuspay(JuspayConfig{MerchantID: "m", APIKey: "k"}) // no WebhookScheme
	if p.WebhookScheme() != JuspaySchemeHMAC {
		t.Fatalf("default scheme = %q, want %q (the body-binding one)",
			p.WebhookScheme(), JuspaySchemeHMAC)
	}

	body := juspayBody("ORDER_SUCCEEDED")
	// Fails closed with no secret: valid-looking basic credentials get nowhere,
	// and so does any signature.
	creds := http.Header{}
	creds.Set("Authorization", basicHeader(fakeJuspayWebhookUsr, fakeJuspayWebhookPwd))
	if _, err := p.VerifyWebhook(creds, body); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("unconfigured default accepted basic credentials: %v", err)
	}
	sig := http.Header{}
	sig.Set(juspayDefaultSignatureHeader, juspayHMACSignature(fakeJuspayWebhookSec, body))
	if _, err := p.VerifyWebhook(sig, body); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("unconfigured default accepted a signature: %v", err)
	}

	// Basic remains available — by name only.
	explicit := NewJuspay(JuspayConfig{
		MerchantID: "m", APIKey: "k",
		WebhookScheme:   JuspaySchemeBasic,
		WebhookUsername: fakeJuspayWebhookUsr,
		WebhookPassword: fakeJuspayWebhookPwd,
	})
	if explicit.WebhookScheme() != JuspaySchemeBasic {
		t.Fatalf("explicit scheme = %q, want basic", explicit.WebhookScheme())
	}
	if _, err := explicit.VerifyWebhook(creds, body); err != nil {
		t.Fatalf("explicit basic must still work: %v", err)
	}
}

// TestJuspayVerifierSeamIsSwappable is the structural claim made in the file
// banner: the scheme is one small type, selected at construction, and swapping
// it changes nothing about the Provider interface.
func TestJuspayVerifierSeamIsSwappable(t *testing.T) {
	var _ juspayWebhookVerifier = &juspayBasicVerifier{}
	var _ juspayWebhookVerifier = &juspayHMACVerifier{}

	basic := newTestJuspayBasic()
	hmacP := newTestJuspayHMAC()
	var _ Provider = basic
	var _ Provider = hmacP

	if basic.WebhookScheme() == hmacP.WebhookScheme() {
		t.Fatal("the two constructions selected the same verifier")
	}
	// The basic instance must NOT accept an hmac-signed request, and vice versa:
	// each construction enforces exactly one scheme, with no fallback.
	body := juspayBody("ORDER_SUCCEEDED")
	sigHeaders := http.Header{}
	sigHeaders.Set(juspayDefaultSignatureHeader, juspayHMACSignature(fakeJuspayWebhookSec, body))
	if _, err := basic.VerifyWebhook(sigHeaders, body); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("basic verifier accepted an hmac signature: %v", err)
	}
	basicHeaders := http.Header{}
	basicHeaders.Set("Authorization", basicHeader(fakeJuspayWebhookUsr, fakeJuspayWebhookPwd))
	if _, err := hmacP.VerifyWebhook(basicHeaders, body); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("hmac verifier accepted basic credentials: %v", err)
	}
}

func TestJuspayEventMapping(t *testing.T) {
	p := newTestJuspayBasic()
	tests := []struct {
		event string
		want  EventType
	}{
		{"ORDER_SUCCEEDED", EventCheckoutCompleted},
		{"ORDER_FAILED", EventPaymentFailed},
		{"MANDATE_CREATED", EventSubscriptionActivated},
		{"MANDATE_ACTIVATED", EventSubscriptionActivated},
		{"MANDATE_REVOKED", EventSubscriptionCanceled},
		{"MANDATE_EXPIRED", EventSubscriptionCanceled},
		{"MANDATE_PAUSED", EventSubscriptionCanceled},
		{"TXN_CHARGED", EventSubscriptionRenewed},
		{"TXN_FAILED", EventPaymentFailed},
		{"ORDER_REFUNDED", EventIgnored},
		{"SOMETHING_NEW_JUSPAY_ADDS_LATER", EventIgnored},
	}
	for _, tc := range tests {
		t.Run(tc.event, func(t *testing.T) {
			ev, err := p.parseEvent(juspayBody(tc.event))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if ev.Type != tc.want {
				t.Fatalf("type = %q, want %q", ev.Type, tc.want)
			}
		})
	}
}

func TestJuspayMalformedPayloadRejected(t *testing.T) {
	p := newTestJuspayBasic()
	h := http.Header{}
	h.Set("Authorization", basicHeader(fakeJuspayWebhookUsr, fakeJuspayWebhookPwd))
	for _, body := range []string{"not json", `{"id":"e"}`, ""} {
		if _, err := p.VerifyWebhook(h, []byte(body)); !errors.Is(err, ErrMalformedWebhook) {
			t.Fatalf("body %q: err = %v, want ErrMalformedWebhook", body, err)
		}
	}
}

func TestJuspayEventIDFallbackDeterministic(t *testing.T) {
	p := newTestJuspayBasic()
	body := []byte(`{"event_name":"ORDER_SUCCEEDED","content":{"order":{"order_id":"o","udf1":"d"}}}`)
	a, err := p.parseEvent(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	b, err := p.parseEvent(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if a.ID == "" || a.ID != b.ID || !strings.HasPrefix(a.ID, "body-") {
		t.Fatalf("fallback ids = %q / %q", a.ID, b.ID)
	}
}

func TestJuspayAmountString(t *testing.T) {
	for _, tc := range []struct {
		minor int64
		want  string
	}{
		{49900, "499.00"},
		{1, "0.01"},
		{100, "1.00"},
		{105, "1.05"},
		{123456, "1234.56"},
	} {
		if got := juspayAmountString(tc.minor); got != tc.want {
			t.Fatalf("juspayAmountString(%d) = %q, want %q", tc.minor, got, tc.want)
		}
	}
}

// TestJuspayCreateCheckout drives a LOCAL httptest server. No network.
func TestJuspayCreateCheckout(t *testing.T) {
	var (
		gotPath     string
		gotMerchant string
		gotUser     string
		gotBody     juspaySessionRequest
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMerchant = r.Header.Get("x-merchantid")
		gotUser, _, _ = r.BasicAuth()
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"sess_jp_1","order_id":"sigil-ref-3","payment_links":{"web":"https://pay.juspay.test/s/abc"}}`))
	}))
	defer srv.Close()

	p := NewJuspay(JuspayConfig{
		MerchantID: fakeJuspayMerchantID, APIKey: fakeJuspayAPIKey,
		ClientID:        "pp_client_test",
		WebhookScheme:   JuspaySchemeBasic,
		WebhookUsername: fakeJuspayWebhookUsr, WebhookPassword: fakeJuspayWebhookPwd,
		AmountMinor: 49900, Currency: "INR",
		BaseURL: srv.URL, HTTPClient: srv.Client(),
	})

	session, err := p.CreateCheckout(context.Background(), CheckoutRequest{
		Subject:    "dev_buyer",
		Reference:  "sigil-ref-3",
		SuccessURL: "https://app.test/ok",
	})
	if err != nil {
		t.Fatalf("CreateCheckout: %v", err)
	}
	if gotPath != "/session" {
		t.Fatalf("path = %q", gotPath)
	}
	if gotMerchant != fakeJuspayMerchantID {
		t.Fatalf("merchant header = %q", gotMerchant)
	}
	if gotUser != fakeJuspayAPIKey {
		t.Fatalf("basic-auth username = %q, want the API key", gotUser)
	}
	if gotBody.OrderID != "sigil-ref-3" || gotBody.Amount != "499.00" || gotBody.Currency != "INR" {
		t.Fatalf("body = %+v", gotBody)
	}
	if gotBody.Action != "paymentPage" || gotBody.ClientID != "pp_client_test" {
		t.Fatalf("body = %+v", gotBody)
	}
	if gotBody.UDF1 != "dev_buyer" || gotBody.Metadata[subjectMetadataKey] != "dev_buyer" {
		t.Fatalf("subject not passed through: %+v", gotBody)
	}
	if session.URL != "https://pay.juspay.test/s/abc" || session.SessionID != "sess_jp_1" {
		t.Fatalf("session = %+v", session)
	}
}

func TestJuspayCreateCheckoutProviderErrorAndUnconfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error_message":"merchant blocked: contact ops@example.com"}`))
	}))
	defer srv.Close()

	p := NewJuspay(JuspayConfig{
		MerchantID: fakeJuspayMerchantID, APIKey: fakeJuspayAPIKey,
		AmountMinor: 100, BaseURL: srv.URL, HTTPClient: srv.Client(),
	})
	_, err := p.CreateCheckout(context.Background(), CheckoutRequest{Subject: "d", Reference: "r"})
	var perr *ProviderError
	if !errors.As(err, &perr) || perr.StatusCode != http.StatusForbidden {
		t.Fatalf("err = %v, want ProviderError(403)", err)
	}
	if strings.Contains(err.Error(), "example.com") {
		t.Fatalf("provider body leaked: %q", err.Error())
	}

	// Missing credentials / amount / reference are all configuration errors.
	bare := NewJuspay(JuspayConfig{})
	if _, err := bare.CreateCheckout(context.Background(), CheckoutRequest{Subject: "d", Reference: "r"}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	noAmount := NewJuspay(JuspayConfig{MerchantID: "m", APIKey: "k"})
	if _, err := noAmount.CreateCheckout(context.Background(), CheckoutRequest{Subject: "d", Reference: "r"}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
	noRef := NewJuspay(JuspayConfig{MerchantID: "m", APIKey: "k", AmountMinor: 100})
	if _, err := noRef.CreateCheckout(context.Background(), CheckoutRequest{Subject: "d"}); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestValidJuspayScheme(t *testing.T) {
	for _, s := range []string{"", JuspaySchemeBasic, JuspaySchemeHMAC} {
		if !ValidJuspayScheme(s) {
			t.Fatalf("%q should be valid", s)
		}
	}
	for _, s := range []string{"BASIC", "hmac256", "none", "jwt"} {
		if ValidJuspayScheme(s) {
			t.Fatalf("%q should be invalid", s)
		}
	}
}

func TestJuspayName(t *testing.T) {
	if newTestJuspayBasic().Name() != ProviderJuspay {
		t.Fatal("name mismatch")
	}
}
