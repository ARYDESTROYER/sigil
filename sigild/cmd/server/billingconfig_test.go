package main

// Boot-time billing configuration tests.
//
// EVERY credential here is OBVIOUSLY FAKE. validateBillingConfig performs NO
// network I/O, so none of these tests can contact a payment provider.

import (
	"strings"
	"testing"

	"github.com/ARYDESTROYER/sigil/sigild/internal/billing"
)

// Fake, non-functional credentials for the config tests.
const (
	cfgStripeKey     = "sk_test_fake_config_key"
	cfgStripeHook    = "whsec_test_fake_config_secret"
	cfgRazorpayID    = "rzp_test_fake_config_id"
	cfgRazorpaySec   = "rzp_test_fake_config_secret"
	cfgRazorpayHook  = "razorpay_test_fake_config_webhook"
	cfgJuspayMerch   = "juspay_test_fake_config_merchant"
	cfgJuspayKey     = "juspay_test_fake_config_api_key"
	cfgJuspayHookUsr = "juspay_test_fake_config_user"
	cfgJuspayHookPwd = "juspay_test_fake_config_password"
	cfgJuspayHookSec = "juspay_test_fake_config_webhook_secret"
)

// baseEnv is a valid, fully-configured single-provider environment.
func baseEnv() billingEnv {
	return billingEnv{
		Providers:           "stripe",
		DevOps:              "1",
		DeviceAuth:          "1",
		SuccessURL:          "https://app.test/ok",
		CancelURL:           "https://app.test/cancel",
		StripeSecretKey:     cfgStripeKey,
		StripeWebhookSecret: cfgStripeHook,
		StripePriceID:       "price_test_fake",
	}
}

// TestBillingOffByDefault: the DEFAULT POSTURE. No provider list => billing off,
// and nothing else in the environment can switch it on.
func TestBillingOffByDefault(t *testing.T) {
	cfg, err := validateBillingConfig(billingEnv{})
	if err != nil {
		t.Fatalf("empty env: %v", err)
	}
	if cfg.Enabled || len(cfg.Providers) != 0 {
		t.Fatalf("billing enabled with no configuration: %+v", cfg)
	}

	// A pre-staged key with no provider list must NOT enable anything.
	stale := billingEnv{
		DevOps: "1", DeviceAuth: "1",
		StripeSecretKey: cfgStripeKey, StripeWebhookSecret: cfgStripeHook,
		SuccessURL: "https://app.test/ok", CancelURL: "https://app.test/cancel",
	}
	cfg2, err := validateBillingConfig(stale)
	if err != nil {
		t.Fatalf("stale env: %v", err)
	}
	if cfg2.Enabled {
		t.Fatal("a stale provider key silently enabled billing")
	}
}

func TestBillingRequiresDevOpsAndDeviceAuth(t *testing.T) {
	noDevOps := baseEnv()
	noDevOps.DevOps = ""
	if _, err := validateBillingConfig(noDevOps); err == nil {
		t.Fatal("billing enabled without the dev-ops gate")
	} else if !strings.Contains(err.Error(), "SIGILD_ENABLE_DEV_OPS") {
		t.Fatalf("err = %v", err)
	}

	noDeviceAuth := baseEnv()
	noDeviceAuth.DeviceAuth = ""
	if _, err := validateBillingConfig(noDeviceAuth); err == nil {
		t.Fatal("billing enabled without device auth")
	} else if !strings.Contains(err.Error(), "SIGILD_DEVICE_AUTH") {
		t.Fatalf("err = %v", err)
	}
}

// TestEnablingProviderWithoutSecretsIsBootError is the fail-fast rule: a
// half-configured provider must stop the process, not surface at request time.
func TestEnablingProviderWithoutSecretsIsBootError(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*billingEnv)
		want   string
	}{
		{"stripe no secret key", func(e *billingEnv) { e.StripeSecretKey = "" }, "SIGILD_STRIPE_SECRET_KEY"},
		{"stripe no webhook secret", func(e *billingEnv) { e.StripeWebhookSecret = "" }, "SIGILD_STRIPE_WEBHOOK_SECRET"},
		{"stripe blank webhook secret", func(e *billingEnv) { e.StripeWebhookSecret = "   " }, "SIGILD_STRIPE_WEBHOOK_SECRET"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := baseEnv()
			tc.mutate(&env)
			_, err := validateBillingConfig(env)
			if err == nil {
				t.Fatal("want a boot error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to name %s", err, tc.want)
			}
			// The error must name the VARIABLE, never a credential value.
			for _, secret := range []string{cfgStripeKey, cfgStripeHook} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("a credential leaked into the boot error: %v", err)
				}
			}
		})
	}
}

func TestRazorpayRequiresAllThreeSecrets(t *testing.T) {
	full := func() billingEnv {
		e := baseEnv()
		e.Providers = "razorpay"
		e.RazorpayKeyID = cfgRazorpayID
		e.RazorpayKeySecret = cfgRazorpaySec
		e.RazorpayWebhookSecret = cfgRazorpayHook
		e.RazorpayAmountMinor = "49900"
		return e
	}
	if _, err := validateBillingConfig(full()); err != nil {
		t.Fatalf("fully configured razorpay: %v", err)
	}
	for name, drop := range map[string]func(*billingEnv){
		"SIGILD_RAZORPAY_KEY_ID":         func(e *billingEnv) { e.RazorpayKeyID = "" },
		"SIGILD_RAZORPAY_KEY_SECRET":     func(e *billingEnv) { e.RazorpayKeySecret = "" },
		"SIGILD_RAZORPAY_WEBHOOK_SECRET": func(e *billingEnv) { e.RazorpayWebhookSecret = "" },
	} {
		e := full()
		drop(&e)
		_, err := validateBillingConfig(e)
		if err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("dropping %s: err = %v", name, err)
		}
	}
}

// TestJuspaySchemeSelection: each scheme demands ITS OWN credentials, and an
// unknown scheme is refused at boot rather than silently defaulting.
func TestJuspaySchemeSelection(t *testing.T) {
	base := func() billingEnv {
		e := baseEnv()
		e.Providers = "juspay"
		e.JuspayMerchantID = cfgJuspayMerch
		e.JuspayAPIKey = cfgJuspayKey
		e.JuspayAmountMinor = "49900"
		return e
	}

	t.Run("basic requires username and password", func(t *testing.T) {
		e := base()
		e.JuspayWebhookScheme = billing.JuspaySchemeBasic
		if _, err := validateBillingConfig(e); err == nil ||
			!strings.Contains(err.Error(), "SIGILD_JUSPAY_WEBHOOK_USERNAME") {
			t.Fatalf("err = %v", err)
		}
		e.JuspayWebhookUsername = cfgJuspayHookUsr
		if _, err := validateBillingConfig(e); err == nil ||
			!strings.Contains(err.Error(), "SIGILD_JUSPAY_WEBHOOK_PASSWORD") {
			t.Fatalf("err = %v", err)
		}
		e.JuspayWebhookPassword = cfgJuspayHookPwd
		cfg, err := validateBillingConfig(e)
		if err != nil {
			t.Fatalf("configured basic: %v", err)
		}
		if cfg.JuspayScheme != billing.JuspaySchemeBasic {
			t.Fatalf("scheme = %q", cfg.JuspayScheme)
		}
	})

	// The default is the scheme that BINDS THE BODY. basic authenticates only
	// the connection, so nobody may arrive at it by leaving a variable unset:
	// with no scheme set, hmac is selected and its secret becomes required.
	t.Run("default scheme is hmac, the body-binding one", func(t *testing.T) {
		e := base()
		e.JuspayWebhookUsername = cfgJuspayHookUsr
		e.JuspayWebhookPassword = cfgJuspayHookPwd
		if _, err := validateBillingConfig(e); err == nil ||
			!strings.Contains(err.Error(), "SIGILD_JUSPAY_WEBHOOK_SECRET") {
			t.Fatalf("unset scheme must default to hmac and demand its secret; err = %v", err)
		}
		e.JuspayWebhookSecret = cfgJuspayHookSec
		cfg, err := validateBillingConfig(e)
		if err != nil {
			t.Fatalf("default scheme: %v", err)
		}
		if cfg.JuspayScheme != billing.JuspaySchemeHMAC {
			t.Fatalf("scheme = %q, want hmac", cfg.JuspayScheme)
		}
	})

	// ...and basic is still reachable, but only by naming it.
	t.Run("basic is an explicit opt-in that names its limitation", func(t *testing.T) {
		e := base()
		e.JuspayWebhookScheme = billing.JuspaySchemeBasic
		_, err := validateBillingConfig(e)
		if err == nil || !strings.Contains(err.Error(), "authenticates the CONNECTION") {
			t.Fatalf("the basic opt-in must state its limitation; err = %v", err)
		}
		e.JuspayWebhookUsername = cfgJuspayHookUsr
		e.JuspayWebhookPassword = cfgJuspayHookPwd
		cfg, err := validateBillingConfig(e)
		if err != nil {
			t.Fatalf("explicit basic: %v", err)
		}
		if cfg.JuspayScheme != billing.JuspaySchemeBasic {
			t.Fatalf("scheme = %q, want basic", cfg.JuspayScheme)
		}
	})

	t.Run("hmac requires a secret", func(t *testing.T) {
		e := base()
		e.JuspayWebhookScheme = billing.JuspaySchemeHMAC
		if _, err := validateBillingConfig(e); err == nil ||
			!strings.Contains(err.Error(), "SIGILD_JUSPAY_WEBHOOK_SECRET") {
			t.Fatalf("err = %v", err)
		}
		e.JuspayWebhookSecret = cfgJuspayHookSec
		cfg, err := validateBillingConfig(e)
		if err != nil {
			t.Fatalf("configured hmac: %v", err)
		}
		if cfg.JuspayScheme != billing.JuspaySchemeHMAC {
			t.Fatalf("scheme = %q", cfg.JuspayScheme)
		}
	})

	t.Run("unknown scheme is refused", func(t *testing.T) {
		e := base()
		e.JuspayWebhookScheme = "jwt"
		e.JuspayWebhookSecret = cfgJuspayHookSec
		if _, err := validateBillingConfig(e); err == nil ||
			!strings.Contains(err.Error(), "SIGILD_JUSPAY_WEBHOOK_SCHEME") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestProviderListValidation(t *testing.T) {
	t.Run("unknown provider", func(t *testing.T) {
		e := baseEnv()
		e.Providers = "stripe,paypal"
		if _, err := validateBillingConfig(e); err == nil || !strings.Contains(err.Error(), "paypal") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("duplicate provider", func(t *testing.T) {
		e := baseEnv()
		e.Providers = "stripe,stripe"
		if _, err := validateBillingConfig(e); err == nil || !strings.Contains(err.Error(), "duplicate") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("whitespace and case tolerated", func(t *testing.T) {
		e := baseEnv()
		e.Providers = "  STRIPE , "
		cfg, err := validateBillingConfig(e)
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if _, ok := cfg.Providers[billing.ProviderStripe]; !ok {
			t.Fatalf("providers = %+v", cfg.Providers)
		}
	})
}

func TestDefaultProviderMustBeEnabled(t *testing.T) {
	e := baseEnv()
	e.DefaultProvider = "razorpay"
	if _, err := validateBillingConfig(e); err == nil ||
		!strings.Contains(err.Error(), "SIGILD_BILLING_DEFAULT_PROVIDER") {
		t.Fatalf("err = %v", err)
	}

	// Unset => first listed.
	e2 := baseEnv()
	e2.Providers = "razorpay,stripe"
	e2.RazorpayKeyID = cfgRazorpayID
	e2.RazorpayKeySecret = cfgRazorpaySec
	e2.RazorpayWebhookSecret = cfgRazorpayHook
	cfg, err := validateBillingConfig(e2)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if cfg.DefaultProvider != billing.ProviderRazorpay {
		t.Fatalf("default = %q, want the first listed", cfg.DefaultProvider)
	}
	if names := cfg.ProviderNames(); len(names) != 2 {
		t.Fatalf("ProviderNames = %v", names)
	}
}

func TestReturnURLsAreRequiredAndAbsolute(t *testing.T) {
	for name, mutate := range map[string]func(*billingEnv){
		"missing success": func(e *billingEnv) { e.SuccessURL = "" },
		"missing cancel":  func(e *billingEnv) { e.CancelURL = "" },
		"relative":        func(e *billingEnv) { e.SuccessURL = "/ok" },
		"no scheme":       func(e *billingEnv) { e.CancelURL = "app.test/cancel" },
		"bad scheme":      func(e *billingEnv) { e.SuccessURL = "ftp://app.test/ok" },
	} {
		t.Run(name, func(t *testing.T) {
			e := baseEnv()
			mutate(&e)
			if _, err := validateBillingConfig(e); err == nil {
				t.Fatal("want a boot error")
			}
		})
	}
}

func TestBaseURLOverrideValidation(t *testing.T) {
	e := baseEnv()
	e.StripeBaseURL = "http://127.0.0.1:9999"
	if _, err := validateBillingConfig(e); err != nil {
		t.Fatalf("valid override rejected: %v", err)
	}

	e.StripeBaseURL = "not a url at all"
	if _, err := validateBillingConfig(e); err == nil {
		t.Fatal("an invalid base URL was accepted")
	}
}

func TestAmountValidation(t *testing.T) {
	base := func() billingEnv {
		e := baseEnv()
		e.Providers = "razorpay"
		e.RazorpayKeyID = cfgRazorpayID
		e.RazorpayKeySecret = cfgRazorpaySec
		e.RazorpayWebhookSecret = cfgRazorpayHook
		return e
	}
	for _, bad := range []string{"0", "-100", "4.99", "lots"} {
		e := base()
		e.RazorpayAmountMinor = bad
		if _, err := validateBillingConfig(e); err == nil {
			t.Fatalf("amount %q was accepted", bad)
		}
	}
	e := base()
	e.RazorpayAmountMinor = "49900"
	if _, err := validateBillingConfig(e); err != nil {
		t.Fatalf("valid amount rejected: %v", err)
	}
}

// TestAllThreeProvidersTogether: the realistic production shape.
func TestAllThreeProvidersTogether(t *testing.T) {
	e := billingEnv{
		Providers:  "stripe,razorpay,juspay",
		DevOps:     "1",
		DeviceAuth: "1",
		SuccessURL: "https://app.test/ok",
		CancelURL:  "https://app.test/cancel",

		StripeSecretKey: cfgStripeKey, StripeWebhookSecret: cfgStripeHook,
		StripePriceID: "price_test_fake",

		RazorpayKeyID: cfgRazorpayID, RazorpayKeySecret: cfgRazorpaySec,
		RazorpayWebhookSecret: cfgRazorpayHook, RazorpayAmountMinor: "49900",

		JuspayMerchantID: cfgJuspayMerch, JuspayAPIKey: cfgJuspayKey,
		JuspayWebhookScheme: billing.JuspaySchemeHMAC, JuspayWebhookSecret: cfgJuspayHookSec,
		JuspayAmountMinor: "49900",
	}
	cfg, err := validateBillingConfig(e)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if len(cfg.Providers) != 3 {
		t.Fatalf("providers = %d, want 3", len(cfg.Providers))
	}
	for _, name := range billing.SupportedProviders {
		p, ok := cfg.Providers[name]
		if !ok {
			t.Fatalf("provider %q missing", name)
		}
		if p.Name() != name {
			t.Fatalf("provider %q reports name %q", name, p.Name())
		}
	}
	if got := strings.Join(cfg.ProviderNames(), ","); got != "stripe,razorpay,juspay" {
		t.Fatalf("ProviderNames = %q", got)
	}
}
