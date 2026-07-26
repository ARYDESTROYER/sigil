package billing

// Package-level invariants that hold across ALL adapters.

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

// blockingTransport fails every outbound request. Installing it proves a code
// path made NO network call — the strongest form of "this test is offline".
type blockingTransport struct{ t *testing.T }

func (b *blockingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	b.t.Errorf("an outbound HTTP request escaped to %s — tests must never reach the network", r.URL.Host)
	return nil, errors.New("blocked")
}

// allAdapters returns one instance of each adapter, all sharing a client whose
// transport refuses to dial. NONE of them is given a BaseURL, so if any of the
// paths exercised below did make a request it would go to the real provider host
// — and the transport would catch it.
func allAdapters(t *testing.T) []Provider {
	t.Helper()
	client := &http.Client{Transport: &blockingTransport{t: t}}
	return []Provider{
		NewStripe(StripeConfig{HTTPClient: client}),
		NewRazorpay(RazorpayConfig{HTTPClient: client}),
		NewJuspay(JuspayConfig{HTTPClient: client}),
	}
}

// TestConstructionAndMisconfigurationMakeNoNetworkCall: building an adapter is
// pure, and an unconfigured checkout fails locally rather than by round-tripping
// to a provider. This matters at BOOT: cmd/server constructs all three adapters
// before the listener binds, and startup must not depend on a payment provider
// being reachable.
func TestConstructionAndMisconfigurationMakeNoNetworkCall(t *testing.T) {
	for _, p := range allAdapters(t) {
		if p.Name() == "" {
			t.Fatal("adapter reported an empty name")
		}
		_, err := p.CreateCheckout(context.Background(), CheckoutRequest{Subject: "dev_x"})
		if !errors.Is(err, ErrNotConfigured) {
			t.Fatalf("%s: err = %v, want ErrNotConfigured with no network call", p.Name(), err)
		}
	}
}

// TestUnconfiguredWebhookVerificationFailsClosed: an adapter with no webhook
// secret must reject EVERYTHING. "Unconfigured means open" on a payment webhook
// would let anyone mint a subscription.
func TestUnconfiguredWebhookVerificationFailsClosed(t *testing.T) {
	body := []byte(`{"id":"e","type":"checkout.session.completed","event":"payment_link.paid","event_name":"ORDER_SUCCEEDED"}`)
	for _, p := range allAdapters(t) {
		for _, h := range []http.Header{
			{},
			{"Stripe-Signature": {"t=1,v1=00"}},
			{"X-Razorpay-Signature": {"00"}},
			{"X-Juspay-Signature": {"00"}},
			{"Authorization": {"Basic YTpi"}},
		} {
			if _, err := p.VerifyWebhook(h, body); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("%s: unconfigured adapter accepted a webhook (err = %v)", p.Name(), err)
			}
		}
	}
}

// TestAdapterNamesMatchSupportedProviders keeps the closed metric label set and
// the webhook route names in lockstep with the adapters that actually exist.
func TestAdapterNamesMatchSupportedProviders(t *testing.T) {
	got := make(map[string]bool)
	for _, p := range allAdapters(t) {
		got[p.Name()] = true
	}
	if len(got) != len(SupportedProviders) {
		t.Fatalf("adapter names = %v, SupportedProviders = %v", got, SupportedProviders)
	}
	for _, name := range SupportedProviders {
		if !got[name] {
			t.Fatalf("SupportedProviders lists %q but no adapter reports it", name)
		}
	}
}

// TestEventAndCheckoutShapesCarryNoCardDataOrPII is the PCI/privacy boundary as
// a mechanical assertion over the real struct definitions. If someone adds a
// "CardLast4" or "CustomerEmail" field, this fails — which is the intent: those
// belong at the provider, not here.
func TestEventAndCheckoutShapesCarryNoCardDataOrPII(t *testing.T) {
	forbidden := []string{
		"card", "pan", "cvv", "cvc", "expiry", "expmonth", "expyear",
		"cardholder", "email", "phone", "address", "postal", "zip", "iban", "bank",
	}
	for _, target := range []any{Event{}, CheckoutRequest{}, CheckoutSession{}} {
		typ := reflect.TypeOf(target)
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			for _, bad := range forbidden {
				if strings.Contains(name, bad) {
					t.Fatalf("%s.%s looks like payment-instrument or contact data; hosted checkout means it must not exist here",
						typ.Name(), typ.Field(i).Name)
				}
			}
		}
	}
}

// TestProviderErrorCarriesOnlyAStatusCode: the error surfaced from a failed
// provider call must never be able to carry a response body (which can contain
// customer data) or a credential.
func TestProviderErrorCarriesOnlyAStatusCode(t *testing.T) {
	typ := reflect.TypeOf(ProviderError{})
	want := map[string]bool{"Provider": true, "Op": true, "StatusCode": true}
	if typ.NumField() != len(want) {
		t.Fatalf("ProviderError has %d fields; it must stay {Provider, Op, StatusCode}", typ.NumField())
	}
	for i := 0; i < typ.NumField(); i++ {
		if !want[typ.Field(i).Name] {
			t.Fatalf("ProviderError gained field %q — it must never carry a body or credential", typ.Field(i).Name)
		}
	}
	e := &ProviderError{Provider: "stripe", Op: "checkout", StatusCode: 402}
	if !strings.Contains(e.Error(), "402") {
		t.Fatalf("error text = %q", e.Error())
	}
}

// TestTrimBaseURLAndClockDefaults covers the small shared helpers.
func TestTrimBaseURLAndClockDefaults(t *testing.T) {
	if got := trimBaseURL("", "https://fallback.test"); got != "https://fallback.test" {
		t.Fatalf("trimBaseURL empty = %q", got)
	}
	if got := trimBaseURL("  https://x.test/  ", "https://fallback.test"); got != "https://x.test" {
		t.Fatalf("trimBaseURL trailing slash = %q", got)
	}
	fixed := time.Unix(1234, 0)
	if got := clockOrDefault(func() time.Time { return fixed })(); !got.Equal(fixed) {
		t.Fatalf("clockOrDefault ignored the injected clock")
	}
	if clockOrDefault(nil)().IsZero() {
		t.Fatal("clockOrDefault(nil) returned a zero clock")
	}
}

func TestUnixTime(t *testing.T) {
	if !unixTime(0).IsZero() || !unixTime(-5).IsZero() {
		t.Fatal("non-positive unix seconds must map to the zero time (unknown)")
	}
	if got := unixTime(1700000000); got.Unix() != 1700000000 {
		t.Fatalf("unixTime = %v", got)
	}
}

func TestConstantTimeHexEqual(t *testing.T) {
	mac := []byte{0xde, 0xad, 0xbe, 0xef}
	if !constantTimeHexEqual("deadbeef", mac) {
		t.Fatal("matching hex rejected")
	}
	if !constantTimeHexEqual("  deadbeef  ", mac) {
		t.Fatal("surrounding whitespace should be tolerated")
	}
	for _, bad := range []string{"deadbeee", "dead", "", "zzzz", "DEADBEEFF"} {
		if constantTimeHexEqual(bad, mac) {
			t.Fatalf("%q was accepted", bad)
		}
	}
	// Uppercase hex decodes to the same bytes and must match: providers are not
	// required to lowercase.
	if !constantTimeHexEqual("DEADBEEF", mac) {
		t.Fatal("uppercase hex rejected")
	}
}

func TestStringField(t *testing.T) {
	m := map[string]any{"a": "x", "b": 12, "c": nil}
	if stringField(m, "a") != "x" {
		t.Fatal("string value not returned")
	}
	for _, k := range []string{"b", "c", "missing"} {
		if stringField(m, k) != "" {
			t.Fatalf("key %q returned a non-empty value", k)
		}
	}
	if stringField(nil, "a") != "" {
		t.Fatal("nil map must be safe")
	}
}
