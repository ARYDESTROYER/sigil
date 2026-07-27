package api

// HTTP-surface tests for the billing routes.
//
// EVERY credential here is OBVIOUSLY FAKE (whsec_test_..., rzp_test_...) and
// lives only in this test binary. NO test reaches the network: the provider
// adapters point at a local httptest server, and the webhook tests make no
// outbound call at all.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/billing"
	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

// Fake, non-functional test credentials.
const (
	apiTestStripeSecretKey  = "sk_test_fake_key_for_api_tests"
	apiTestStripeWebhookSec = "whsec_test_fake_api_endpoint_secret_00"
	apiTestRazorpayKeyID    = "rzp_test_fake_api_key_id"
	apiTestRazorpayKeySec   = "rzp_test_fake_api_key_secret"
	apiTestRazorpayHookSec  = "razorpay_test_fake_api_webhook_secret"
)

// billingEnv bundles a router with the device model AND billing enabled, plus
// direct handles on the stores and the stand-in provider server.
type billingTestEnv struct {
	*deviceEnv
	subs      *store.MemSubscriptionStore
	provider  *httptest.Server
	lastForm  func() string
	checkouts *int
}

// newBillingEnv builds a fully wired billing router. The provider adapters are
// pointed at a LOCAL httptest server standing in for Stripe.
func newBillingEnv(t *testing.T) *billingTestEnv {
	t.Helper()

	var (
		checkouts int
		lastBody  string
	)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkouts++
		raw, _ := io.ReadAll(r.Body)
		lastBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"cs_test_api","url":"https://checkout.test/pay/cs_test_api","expires_at":1900000000}`))
	}))
	t.Cleanup(provider.Close)

	devices := store.NewMemDeviceStore()
	hash := EnrollTokenHash(testEnrollToken)
	if err := devices.RegisterEnrollmentToken(t.Context(), hash, time.Now().UTC(), time.Time{}); err != nil {
		t.Fatalf("RegisterEnrollmentToken: %v", err)
	}
	subs := store.NewMemSubscriptionStore()

	router := NewRouter(Config{
		Version:           "test",
		Logger:            discardLogger(),
		DevOpsEnabled:     true,
		Devices:           devices,
		EnrollTokenHashes: []string{hash},
		AdminToken:        testAdminToken,
		Billing: BillingConfig{
			Providers: map[string]billing.Provider{
				billing.ProviderStripe: billing.NewStripe(billing.StripeConfig{
					SecretKey:     apiTestStripeSecretKey,
					WebhookSecret: apiTestStripeWebhookSec,
					PriceID:       "price_test_api",
					BaseURL:       provider.URL,
					HTTPClient:    provider.Client(),
				}),
				billing.ProviderRazorpay: billing.NewRazorpay(billing.RazorpayConfig{
					KeyID:         apiTestRazorpayKeyID,
					KeySecret:     apiTestRazorpayKeySec,
					WebhookSecret: apiTestRazorpayHookSec,
					AmountMinor:   49900,
					BaseURL:       provider.URL,
					HTTPClient:    provider.Client(),
				}),
			},
			DefaultProvider: billing.ProviderStripe,
			Subscriptions:   subs,
			SuccessURL:      "https://app.test/ok",
			CancelURL:       "https://app.test/cancel",
		},
	})

	return &billingTestEnv{
		deviceEnv: &deviceEnv{router: router, devices: devices},
		subs:      subs,
		provider:  provider,
		lastForm:  func() string { return lastBody },
		checkouts: &checkouts,
	}
}

// stripeWebhookRequest builds a request with a REAL Stripe signature over the
// exact body bytes.
func stripeWebhookRequest(body []byte, secret string, ts int64) *http.Request {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/billing/webhook/stripe", bytes.NewReader(body))
	req.Header.Set("Stripe-Signature",
		"t="+strconv.FormatInt(ts, 10)+",v1="+hex.EncodeToString(mac.Sum(nil)))
	return req
}

func serve(router http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// ---- dev-gating ----

// TestBillingRoutes501WhenDevOpsOff is the default-posture assertion: with
// SIGILD_ENABLE_DEV_OPS off, every billing route is 501 — exactly like the ops
// and device routes.
func TestBillingRoutes501WhenDevOpsOff(t *testing.T) {
	router := NewRouter(Config{Version: "test", Logger: discardLogger()})
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodPost, "/v1/billing/checkout"},
		{http.MethodPost, "/v1/billing/webhook/stripe"},
		{http.MethodGet, "/v1/billing/subscription"},
	} {
		rec := serve(router, httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}")))
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("%s %s = %d, want 501", tc.method, tc.path, rec.Code)
		}
		var body apiError
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("501 body not JSON: %v", err)
		}
		if body.Error != "not_implemented" {
			t.Fatalf("501 error code = %q", body.Error)
		}
	}
}

// TestBillingRoutes501WhenNotConfigured: dev-ops and the device model ON, but no
// billing providers => still 501. Billing is separately opt-in.
func TestBillingRoutes501WhenNotConfigured(t *testing.T) {
	env := newDeviceEnv(t)
	for _, tc := range []struct {
		method, path string
	}{
		{http.MethodPost, "/v1/billing/checkout"},
		{http.MethodPost, "/v1/billing/webhook/stripe"},
		{http.MethodGet, "/v1/billing/subscription"},
	} {
		rec := serve(env.router, httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}")))
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("%s %s = %d, want 501", tc.method, tc.path, rec.Code)
		}
	}
}

// TestBillingConfigEnabled pins the two-part requirement: a provider set alone,
// or a store alone, is NOT enough.
func TestBillingConfigEnabled(t *testing.T) {
	if (BillingConfig{}).Enabled() {
		t.Fatal("empty config reported enabled")
	}
	if (BillingConfig{Providers: map[string]billing.Provider{"stripe": nil}}).Enabled() {
		t.Fatal("providers with no store reported enabled")
	}
	if (BillingConfig{Subscriptions: store.NewMemSubscriptionStore()}).Enabled() {
		t.Fatal("store with no providers reported enabled")
	}
	if !(BillingConfig{
		Providers:     map[string]billing.Provider{"stripe": nil},
		Subscriptions: store.NewMemSubscriptionStore(),
	}).Enabled() {
		t.Fatal("fully configured billing reported disabled")
	}
}

// ---- checkout: device auth ----

func TestCheckoutRequiresDeviceAuth(t *testing.T) {
	env := newBillingEnv(t)

	// No signature at all.
	rec := serve(env.router, httptest.NewRequest(http.MethodPost, "/v1/billing/checkout",
		strings.NewReader(`{"provider":"stripe"}`)))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned checkout = %d, want 401", rec.Code)
	}
	if *env.checkouts != 0 {
		t.Fatal("an unauthenticated request reached the payment provider")
	}
}

func TestCheckoutHappyPath(t *testing.T) {
	env := newBillingEnv(t)
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "buyer")

	rec := v3Post(t, env.deviceEnv, dev, "/v1/billing/checkout", []byte(`{"provider":"stripe"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("checkout = %d (body %s)", rec.Code, rec.Body.String())
	}
	var resp checkoutResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body: %v", err)
	}
	if resp.URL != "https://checkout.test/pay/cs_test_api" {
		t.Fatalf("url = %q", resp.URL)
	}
	if resp.Provider != billing.ProviderStripe {
		t.Fatalf("provider = %q", resp.Provider)
	}
	if *env.checkouts != 1 {
		t.Fatalf("provider hit %d times", *env.checkouts)
	}

	// THE SUBJECT IS SERVER-DERIVED: the outbound request carries the
	// AUTHENTICATED device ID, regardless of anything in the body.
	if !strings.Contains(env.lastForm(), dev.ID) {
		t.Fatalf("outbound checkout did not carry the authenticated device as subject: %s", env.lastForm())
	}

	// StartCheckout bound the subject without granting entitlement.
	sub, err := env.subs.GetSubscription(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("GetSubscription: %v", err)
	}
	if sub.Status.Entitled() {
		t.Fatalf("starting checkout entitled the device (status %q)", sub.Status)
	}
}

// TestCheckoutSubjectCannotBeSpoofed: a client cannot buy for someone else. The
// body has no subject field, and anything it does send is ignored.
func TestCheckoutSubjectCannotBeSpoofed(t *testing.T) {
	env := newBillingEnv(t)
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "buyer")

	body := []byte(`{"provider":"stripe","subject":"dev_someone_else","client_reference_id":"dev_victim"}`)
	rec := v3Post(t, env.deviceEnv, dev, "/v1/billing/checkout", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("checkout = %d", rec.Code)
	}
	form := env.lastForm()
	if strings.Contains(form, "dev_someone_else") || strings.Contains(form, "dev_victim") {
		t.Fatalf("a client-supplied subject reached the provider: %s", form)
	}
	if !strings.Contains(form, dev.ID) {
		t.Fatalf("outbound subject was not the authenticated device: %s", form)
	}
}

func TestCheckoutUnknownProvider(t *testing.T) {
	env := newBillingEnv(t)
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "buyer")

	rec := v3Post(t, env.deviceEnv, dev, "/v1/billing/checkout", []byte(`{"provider":"paypal"}`))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown provider = %d, want 400", rec.Code)
	}
	if *env.checkouts != 0 {
		t.Fatal("an unknown-provider request reached a provider")
	}
}

func TestCheckoutDefaultsToConfiguredProvider(t *testing.T) {
	env := newBillingEnv(t)
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "buyer")

	rec := v3Post(t, env.deviceEnv, dev, "/v1/billing/checkout", []byte(`{}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("checkout = %d (%s)", rec.Code, rec.Body.String())
	}
	var resp checkoutResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Provider != billing.ProviderStripe {
		t.Fatalf("provider = %q, want the configured default", resp.Provider)
	}
}

// TestCheckoutProviderFailure: an upstream error becomes a 502 and never leaks
// the provider's response body.
func TestCheckoutProviderFailure(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"message":"account for ops@example.com is suspended"}}`))
	}))
	defer failing.Close()

	devices := store.NewMemDeviceStore()
	hash := EnrollTokenHash(testEnrollToken)
	if err := devices.RegisterEnrollmentToken(t.Context(), hash, time.Now().UTC(), time.Time{}); err != nil {
		t.Fatalf("RegisterEnrollmentToken: %v", err)
	}
	router := NewRouter(Config{
		Version: "test", Logger: discardLogger(), DevOpsEnabled: true,
		Devices: devices, EnrollTokenHashes: []string{hash},
		Billing: BillingConfig{
			Providers: map[string]billing.Provider{
				billing.ProviderStripe: billing.NewStripe(billing.StripeConfig{
					SecretKey: apiTestStripeSecretKey, WebhookSecret: apiTestStripeWebhookSec,
					PriceID: "price_x", BaseURL: failing.URL, HTTPClient: failing.Client(),
				}),
			},
			DefaultProvider: billing.ProviderStripe,
			Subscriptions:   store.NewMemSubscriptionStore(),
			SuccessURL:      "https://app.test/ok", CancelURL: "https://app.test/cancel",
		},
	})
	env := &deviceEnv{router: router, devices: devices}
	dev := enrollDevice(t, env, testEnrollToken, "buyer")

	rec := v3Post(t, env, dev, "/v1/billing/checkout", []byte(`{}`))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502 (body %s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "example.com") || strings.Contains(rec.Body.String(), "suspended") {
		t.Fatalf("the provider's response body leaked to the client: %s", rec.Body.String())
	}
}

// ---- webhook ----

func TestWebhookRejectsBadSignature(t *testing.T) {
	env := newBillingEnv(t)
	body := []byte(`{"id":"evt_bad","type":"checkout.session.completed","created":1700000000,"data":{"object":{}}}`)

	// Signed with the WRONG secret.
	req := stripeWebhookRequest(body, "whsec_test_fake_WRONG", time.Now().Unix())
	rec := serve(env.router, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	// The response must not say WHICH check failed.
	for _, leak := range []string{"timestamp", "stale", "secret", "hmac", "v1", "tolerance", "header"} {
		if strings.Contains(strings.ToLower(rec.Body.String()), leak) {
			t.Fatalf("401 body leaked the failing check (%q): %s", leak, rec.Body.String())
		}
	}

	// Entirely unsigned.
	unsigned := httptest.NewRequest(http.MethodPost, "/v1/billing/webhook/stripe", bytes.NewReader(body))
	if rec := serve(env.router, unsigned); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned = %d, want 401", rec.Code)
	}
}

func TestWebhookRejectsTamperedBody(t *testing.T) {
	env := newBillingEnv(t)
	body := []byte(`{"id":"evt_t","type":"checkout.session.completed","created":1700000000,` +
		`"data":{"object":{"client_reference_id":"dev_a","subscription":"sub_1"}}}`)
	req := stripeWebhookRequest(body, apiTestStripeWebhookSec, time.Now().Unix())

	// Replace the body AFTER signing: the header no longer matches the bytes.
	tampered := bytes.Replace(body, []byte("dev_a"), []byte("dev_b"), 1)
	req.Body = io.NopCloser(bytes.NewReader(tampered))
	req.ContentLength = int64(len(tampered))

	if rec := serve(env.router, req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("tampered = %d, want 401", rec.Code)
	}
}

func TestWebhookMalformedBodyIs400(t *testing.T) {
	env := newBillingEnv(t)
	body := []byte(`this is not json`)
	req := stripeWebhookRequest(body, apiTestStripeWebhookSec, time.Now().Unix())
	rec := serve(env.router, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
}

func TestWebhookUnknownProviderIs404(t *testing.T) {
	env := newBillingEnv(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/billing/webhook/paypal", strings.NewReader(`{}`))
	if rec := serve(env.router, req); rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	// A provider that is compiled in but NOT configured on this server is also
	// 404 — the route reflects configuration, not the code base.
	req2 := httptest.NewRequest(http.MethodPost, "/v1/billing/webhook/juspay", strings.NewReader(`{}`))
	if rec := serve(env.router, req2); rec.Code != http.StatusNotFound {
		t.Fatalf("unconfigured provider = %d, want 404", rec.Code)
	}
}

// TestWebhookIgnoredEventIs200: an authentic event we do not model must be a
// 200 with no state change, never a 500 and never a retry-inducing error.
func TestWebhookIgnoredEventIs200(t *testing.T) {
	env := newBillingEnv(t)
	body := []byte(`{"id":"evt_ignore","type":"charge.refunded","created":1700000000,"data":{"object":{"id":"ch_1"}}}`)
	req := stripeWebhookRequest(body, apiTestStripeWebhookSec, time.Now().Unix())
	rec := serve(env.router, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	var resp webhookResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body: %v", err)
	}
	if resp.Status != "ignored" {
		t.Fatalf("status = %q, want ignored", resp.Status)
	}
}

// TestWebhookIdempotency is the money-critical one: the SAME event delivered
// twice produces ONE state change and TWO 200s.
func TestWebhookIdempotency(t *testing.T) {
	env := newBillingEnv(t)
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "buyer")

	body := []byte(`{"id":"evt_dup_1","type":"checkout.session.completed","created":1700000000,` +
		`"data":{"object":{"client_reference_id":"` + dev.ID + `","customer":"cus_1","subscription":"sub_1"}}}`)

	first := serve(env.router, stripeWebhookRequest(body, apiTestStripeWebhookSec, time.Now().Unix()))
	if first.Code != http.StatusOK {
		t.Fatalf("first = %d (%s)", first.Code, first.Body.String())
	}
	var r1 webhookResponse
	_ = json.Unmarshal(first.Body.Bytes(), &r1)
	if r1.Status != "accepted" {
		t.Fatalf("first status = %q, want accepted", r1.Status)
	}

	second := serve(env.router, stripeWebhookRequest(body, apiTestStripeWebhookSec, time.Now().Unix()))
	if second.Code != http.StatusOK {
		t.Fatalf("second = %d, want 200 — a duplicate must not error", second.Code)
	}
	var r2 webhookResponse
	_ = json.Unmarshal(second.Body.Bytes(), &r2)
	if r2.Status != "duplicate" {
		t.Fatalf("second status = %q, want duplicate", r2.Status)
	}

	sub, err := env.subs.GetSubscription(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("GetSubscription: %v", err)
	}
	if sub.Status != billing.StatusActive {
		t.Fatalf("status = %q", sub.Status)
	}
}

// TestWebhookRazorpayReplayWithFreshHeaderIDIsOneEvent: Razorpay's signature
// covers the BODY ONLY, so a captured delivery replayed with a brand-new
// X-Razorpay-Event-Id header still verifies. It must still be ONE event —
// otherwise an attacker with a single captured webhook could grow the
// processed-events ledger without bound, one forged header at a time.
func TestWebhookRazorpayReplayWithFreshHeaderIDIsOneEvent(t *testing.T) {
	env := newBillingEnv(t)
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "buyer")

	body := []byte(`{"event":"subscription.activated","created_at":1700000000,` +
		`"payload":{"subscription":{"entity":{"id":"sub_replay","status":"active",` +
		`"customer_id":"cus_replay","notes":{"sigil_subject":"` + dev.ID + `"}}}}}`)
	mac := hmac.New(sha256.New, []byte(apiTestRazorpayHookSec))
	mac.Write(body)
	sig := hex.EncodeToString(mac.Sum(nil))

	post := func(eventID string) webhookResponse {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/billing/webhook/razorpay", bytes.NewReader(body))
		req.Header.Set("X-Razorpay-Signature", sig)
		req.Header.Set("X-Razorpay-Event-Id", eventID)
		rec := serve(env.router, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
		}
		var resp webhookResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return resp
	}

	if got := post("evt_rzp_genuine").Status; got != "accepted" {
		t.Fatalf("first status = %q, want accepted", got)
	}
	// Same bytes, same (valid) signature, attacker-chosen id.
	if got := post("evt_rzp_forged_1").Status; got != "duplicate" {
		t.Fatalf("replay status = %q, want duplicate — the dedup key is outside the signature", got)
	}
	if got := post("evt_rzp_forged_2").Status; got != "duplicate" {
		t.Fatalf("second replay status = %q, want duplicate", got)
	}
	// ...and with NO id header at all.
	req := httptest.NewRequest(http.MethodPost, "/v1/billing/webhook/razorpay", bytes.NewReader(body))
	req.Header.Set("X-Razorpay-Signature", sig)
	rec := serve(env.router, req)
	var resp webhookResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "duplicate" {
		t.Fatalf("header-less replay status = %q, want duplicate", resp.Status)
	}
}

// TestWebhookRazorpaySignedOverRawBody exercises the second provider end to end
// through the router, including the raw-byte requirement.
func TestWebhookRazorpaySignedOverRawBody(t *testing.T) {
	env := newBillingEnv(t)
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "buyer")

	// Deliberately odd whitespace/key order: it must verify as received.
	body := []byte("{ \"payload\" : { \"subscription\" : { \"entity\" : { \"id\" : \"sub_rz\", " +
		"\"notes\" : { \"sigil_subject\" : \"" + dev.ID + "\" } } } },\n" +
		"  \"created_at\":1700000000, \"event\" : \"subscription.activated\" }")

	mac := hmac.New(sha256.New, []byte(apiTestRazorpayHookSec))
	mac.Write(body)
	req := httptest.NewRequest(http.MethodPost, "/v1/billing/webhook/razorpay", bytes.NewReader(body))
	req.Header.Set("X-Razorpay-Signature", hex.EncodeToString(mac.Sum(nil)))
	req.Header.Set("X-Razorpay-Event-Id", "evt_rzp_api_1")

	rec := serve(env.router, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	var resp webhookResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "accepted" {
		t.Fatalf("status = %q", resp.Status)
	}
	sub, err := env.subs.GetSubscription(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("GetSubscription: %v", err)
	}
	if sub.Status != billing.StatusActive || sub.Provider != billing.ProviderRazorpay {
		t.Fatalf("subscription = %+v", sub)
	}
}

// TestWebhookIllegalTransitionIs200NoChange: an authentic but nonsensical
// sequence is acknowledged, not errored, and changes nothing.
func TestWebhookIllegalTransitionIs200NoChange(t *testing.T) {
	env := newBillingEnv(t)
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "buyer")

	// invoice.payment_failed for a device that never subscribed: none -> past_due
	// is illegal.
	body := []byte(`{"id":"evt_ill","type":"invoice.payment_failed","created":1700000000,` +
		`"data":{"object":{"client_reference_id":"` + dev.ID + `","subscription":"sub_none"}}}`)
	rec := serve(env.router, stripeWebhookRequest(body, apiTestStripeWebhookSec, time.Now().Unix()))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var resp webhookResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "illegal" {
		t.Fatalf("status = %q, want illegal", resp.Status)
	}
	if _, err := env.subs.GetSubscription(t.Context(), dev.ID); err == nil {
		t.Fatal("an illegal event created a subscription record")
	}
}

// TestWebhookStaleEventDoesNotRegress drives the ordering guard through HTTP.
func TestWebhookStaleEventDoesNotRegress(t *testing.T) {
	env := newBillingEnv(t)
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "buyer")
	now := time.Now().Unix()

	activate := []byte(`{"id":"evt_a","type":"checkout.session.completed","created":` +
		strconv.FormatInt(now, 10) + `,"data":{"object":{"client_reference_id":"` + dev.ID +
		`","subscription":"sub_ord"}}}`)
	if rec := serve(env.router, stripeWebhookRequest(activate, apiTestStripeWebhookSec, now)); rec.Code != http.StatusOK {
		t.Fatalf("activate = %d", rec.Code)
	}

	// A payment failure that OCCURRED an hour EARLIER, delivered now.
	stale := []byte(`{"id":"evt_b","type":"invoice.payment_failed","created":` +
		strconv.FormatInt(now-3600, 10) + `,"data":{"object":{"subscription":"sub_ord"}}}`)
	rec := serve(env.router, stripeWebhookRequest(stale, apiTestStripeWebhookSec, now))
	if rec.Code != http.StatusOK {
		t.Fatalf("stale = %d", rec.Code)
	}
	var resp webhookResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "stale" {
		t.Fatalf("status = %q, want stale", resp.Status)
	}
	sub, err := env.subs.GetSubscription(t.Context(), dev.ID)
	if err != nil {
		t.Fatalf("GetSubscription: %v", err)
	}
	if sub.Status != billing.StatusActive {
		t.Fatalf("an out-of-order event regressed the subscription to %q", sub.Status)
	}
}

// TestWebhookNeedsNoDeviceAuth: a provider has no device key. The webhook must
// be reachable with the provider signature ALONE.
func TestWebhookNeedsNoDeviceAuth(t *testing.T) {
	env := newBillingEnv(t)
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "buyer")

	body := []byte(`{"id":"evt_nodev","type":"checkout.session.completed","created":1700000000,` +
		`"data":{"object":{"client_reference_id":"` + dev.ID + `","subscription":"sub_nd"}}}`)
	req := stripeWebhookRequest(body, apiTestStripeWebhookSec, time.Now().Unix())
	// Note: NO X-Sigil-Device / -Timestamp / -Nonce / -Signature headers.
	rec := serve(env.router, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
}

func TestWebhookOversizedBodyIs413(t *testing.T) {
	env := newBillingEnv(t)
	huge := bytes.Repeat([]byte("a"), maxWebhookBodyBytes+1024)
	req := httptest.NewRequest(http.MethodPost, "/v1/billing/webhook/stripe", bytes.NewReader(huge))
	req.Header.Set("Stripe-Signature", "t=1,v1=00")
	rec := serve(env.router, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

// ---- subscription status ----

func TestSubscriptionRequiresDeviceAuth(t *testing.T) {
	env := newBillingEnv(t)
	rec := serve(env.router, httptest.NewRequest(http.MethodGet, "/v1/billing/subscription", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

func TestSubscriptionReportsCallerStatus(t *testing.T) {
	env := newBillingEnv(t)
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "buyer")

	// Before any payment: "none", not entitled.
	rec := v3Get(t, env.deviceEnv, dev, "/v1/billing/subscription")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d (%s)", rec.Code, rec.Body.String())
	}
	var resp subscriptionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body: %v", err)
	}
	if resp.Status != string(billing.StatusNone) || resp.Entitled {
		t.Fatalf("resp = %+v", resp)
	}
	if resp.Subject != dev.ID {
		t.Fatalf("subject = %q, want the authenticated device", resp.Subject)
	}

	// After an activating webhook: "active", entitled.
	body := []byte(`{"id":"evt_status","type":"checkout.session.completed","created":1700000000,` +
		`"data":{"object":{"client_reference_id":"` + dev.ID + `","subscription":"sub_st"}}}`)
	if r := serve(env.router, stripeWebhookRequest(body, apiTestStripeWebhookSec, time.Now().Unix())); r.Code != http.StatusOK {
		t.Fatalf("webhook = %d", r.Code)
	}

	rec2 := v3Get(t, env.deviceEnv, dev, "/v1/billing/subscription")
	var resp2 subscriptionResponse
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("body: %v", err)
	}
	if resp2.Status != string(billing.StatusActive) || !resp2.Entitled {
		t.Fatalf("resp = %+v", resp2)
	}
	if resp2.Provider != billing.ProviderStripe {
		t.Fatalf("provider = %q", resp2.Provider)
	}
}

// TestSubscriptionIsPerDevice: one device's payment does not entitle another.
func TestSubscriptionIsPerDevice(t *testing.T) {
	env := newBillingEnv(t)
	payer := enrollDevice(t, env.deviceEnv, testEnrollToken, "payer")

	// A second enrollment token for the freeloader.
	other := "test-enrollment-token-0000000002"
	hash := EnrollTokenHash(other)
	if err := env.devices.RegisterEnrollmentToken(t.Context(), hash, time.Now().UTC(), time.Time{}); err != nil {
		t.Fatalf("RegisterEnrollmentToken: %v", err)
	}

	body := []byte(`{"id":"evt_perdev","type":"checkout.session.completed","created":1700000000,` +
		`"data":{"object":{"client_reference_id":"` + payer.ID + `","subscription":"sub_pd"}}}`)
	if r := serve(env.router, stripeWebhookRequest(body, apiTestStripeWebhookSec, time.Now().Unix())); r.Code != http.StatusOK {
		t.Fatalf("webhook = %d", r.Code)
	}

	// The freeloader must not be able to read the payer's status, nor inherit it.
	// It cannot even name another subject: the endpoint takes none.
	rec := v3Get(t, env.deviceEnv, payer, "/v1/billing/subscription?subject=someone_else")
	var resp subscriptionResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Subject != payer.ID {
		t.Fatalf("a query parameter changed the subject to %q", resp.Subject)
	}
}

// ---- observability ----

// TestBillingMetricsExposeNoSecrets checks the counters exist, move, and carry
// only closed-set labels — never a secret, a signature, an event ID, a subject,
// or an amount.
func TestBillingMetricsExposeNoSecrets(t *testing.T) {
	env := newBillingEnv(t)
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "buyer")

	if rec := v3Post(t, env.deviceEnv, dev, "/v1/billing/checkout", []byte(`{}`)); rec.Code != http.StatusCreated {
		t.Fatalf("checkout = %d", rec.Code)
	}
	body := []byte(`{"id":"evt_metrics","type":"checkout.session.completed","created":1700000000,` +
		`"data":{"object":{"client_reference_id":"` + dev.ID + `","subscription":"sub_m"}}}`)
	if r := serve(env.router, stripeWebhookRequest(body, apiTestStripeWebhookSec, time.Now().Unix())); r.Code != http.StatusOK {
		t.Fatalf("webhook = %d", r.Code)
	}
	serve(env.router, stripeWebhookRequest(body, "whsec_test_fake_WRONG", time.Now().Unix()))

	rec := serve(env.router, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics = %d", rec.Code)
	}
	out := rec.Body.String()

	for _, want := range []string{
		`sigild_billing_checkouts_total{provider="stripe"} 1`,
		`sigild_billing_webhooks_total{provider="stripe",outcome="accepted"} 1`,
		`sigild_billing_webhook_rejected_total{reason="bad_signature"} 1`,
		`sigild_billing_subscription_transitions_total{status="active"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("/metrics missing %q\n%s", want, out)
		}
	}

	// NOTHING sensitive may appear in the exposition.
	for _, forbidden := range []string{
		apiTestStripeSecretKey, apiTestStripeWebhookSec,
		apiTestRazorpayKeyID, apiTestRazorpayKeySec, apiTestRazorpayHookSec,
		dev.ID, "evt_metrics", "sub_m", "cs_test_api", "whsec", "sk_test", "rzp_test",
	} {
		if strings.Contains(out, forbidden) {
			t.Fatalf("/metrics leaked %q", forbidden)
		}
	}
}

// TestBillingAuditLogsNoSecretsOrBodies asserts the audit trail records metadata
// only: never a secret, never a signature header, never a byte of the raw
// webhook body.
func TestBillingAuditLogsNoSecretsOrBodies(t *testing.T) {
	var logs bytes.Buffer
	devices := store.NewMemDeviceStore()
	hash := EnrollTokenHash(testEnrollToken)
	if err := devices.RegisterEnrollmentToken(t.Context(), hash, time.Now().UTC(), time.Time{}); err != nil {
		t.Fatalf("RegisterEnrollmentToken: %v", err)
	}
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"cs_audit","url":"https://checkout.test/pay/cs_audit"}`))
	}))
	defer provider.Close()

	router := NewRouter(Config{
		Version: "test", Logger: slog.New(slog.NewJSONHandler(&logs, nil)), DevOpsEnabled: true,
		Devices: devices, EnrollTokenHashes: []string{hash},
		Billing: BillingConfig{
			Providers: map[string]billing.Provider{
				billing.ProviderStripe: billing.NewStripe(billing.StripeConfig{
					SecretKey: apiTestStripeSecretKey, WebhookSecret: apiTestStripeWebhookSec,
					PriceID: "price_audit", BaseURL: provider.URL, HTTPClient: provider.Client(),
				}),
			},
			DefaultProvider: billing.ProviderStripe,
			Subscriptions:   store.NewMemSubscriptionStore(),
			SuccessURL:      "https://app.test/ok", CancelURL: "https://app.test/cancel",
		},
	})
	env := &deviceEnv{router: router, devices: devices}
	dev := enrollDevice(t, env, testEnrollToken, "buyer")

	if rec := v3Post(t, env, dev, "/v1/billing/checkout", []byte(`{}`)); rec.Code != http.StatusCreated {
		t.Fatalf("checkout = %d", rec.Code)
	}

	secretMarker := "SUPER_SECRET_MARKER_IN_BODY"
	body := []byte(`{"id":"evt_audit","type":"checkout.session.completed","created":1700000000,` +
		`"data":{"object":{"client_reference_id":"` + dev.ID + `","subscription":"` + secretMarker + `"}}}`)
	mac := hmac.New(sha256.New, []byte(apiTestStripeWebhookSec))
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	sigHeader := "t=" + ts + ",v1=" + hex.EncodeToString(mac.Sum(nil))

	req := httptest.NewRequest(http.MethodPost, "/v1/billing/webhook/stripe", bytes.NewReader(body))
	req.Header.Set("Stripe-Signature", sigHeader)
	if rec := serve(router, req); rec.Code != http.StatusOK {
		t.Fatalf("webhook = %d (%s)", rec.Code, rec.Body.String())
	}

	logged := logs.String()
	if !strings.Contains(logged, "billing.checkout_created") ||
		!strings.Contains(logged, "billing.webhook") ||
		!strings.Contains(logged, "billing.subscription_transition") {
		t.Fatalf("expected billing audit events are missing:\n%s", logged)
	}
	for _, forbidden := range []string{
		apiTestStripeSecretKey, apiTestStripeWebhookSec, sigHeader,
		secretMarker, string(body), "whsec", "sk_test",
	} {
		if strings.Contains(logged, forbidden) {
			t.Fatalf("audit log leaked %q:\n%s", forbidden, logged)
		}
	}
}
