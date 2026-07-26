package main

// Billing configuration (Phase 45) — parsed and validated BEFORE the listener
// binds, so a misconfigured payment layer is a clear startup failure rather than
// a surprise the first time a customer tries to pay (or, far worse, the first
// time a provider sends a webhook we then fail to authenticate).
//
// EVERYTHING IS OPT-IN. With SIGILD_BILLING_PROVIDERS unset, billing is OFF, the
// three /v1/billing routes serve their 501 stub, and nothing else about the
// server changes.
//
// ENVIRONMENT
//
//	SIGILD_BILLING_PROVIDERS        comma-separated: stripe,razorpay,juspay.
//	                                Unset => billing OFF. Requires
//	                                SIGILD_ENABLE_DEV_OPS (the whole stateful
//	                                surface is dev-gated) and SIGILD_DEVICE_AUTH
//	                                (checkout is authenticated as an ENROLLED
//	                                DEVICE — there is no second auth path).
//	SIGILD_BILLING_DEFAULT_PROVIDER which provider a checkout uses when the
//	                                request names none. Must be one of the
//	                                enabled providers. Unset => the first listed.
//	SIGILD_BILLING_SUCCESS_URL      where the provider returns a paying customer.
//	SIGILD_BILLING_CANCEL_URL       where the provider returns an abandoning one.
//	                                Both REQUIRED when billing is on.
//
//	SIGILD_STRIPE_SECRET_KEY        sk_...   REQUIRED when stripe is enabled
//	SIGILD_STRIPE_WEBHOOK_SECRET    whsec_.. REQUIRED when stripe is enabled
//	SIGILD_STRIPE_PRICE_ID          price_.. default plan
//	SIGILD_STRIPE_API_BASE_URL      optional API host override
//
//	SIGILD_RAZORPAY_KEY_ID          rzp_...  REQUIRED when razorpay is enabled
//	SIGILD_RAZORPAY_KEY_SECRET               REQUIRED when razorpay is enabled
//	SIGILD_RAZORPAY_WEBHOOK_SECRET           REQUIRED when razorpay is enabled
//	SIGILD_RAZORPAY_AMOUNT_MINOR    default amount in paise
//	SIGILD_RAZORPAY_CURRENCY        default currency (INR)
//	SIGILD_RAZORPAY_DESCRIPTION     payment-link description
//	SIGILD_RAZORPAY_API_BASE_URL    optional API host override
//
//	SIGILD_JUSPAY_MERCHANT_ID                REQUIRED when juspay is enabled
//	SIGILD_JUSPAY_API_KEY                    REQUIRED when juspay is enabled
//	SIGILD_JUSPAY_CLIENT_ID         payment-page client id
//	SIGILD_JUSPAY_WEBHOOK_SCHEME    basic (default) | hmac
//	SIGILD_JUSPAY_WEBHOOK_USERNAME           REQUIRED for scheme=basic
//	SIGILD_JUSPAY_WEBHOOK_PASSWORD           REQUIRED for scheme=basic
//	SIGILD_JUSPAY_WEBHOOK_SECRET             REQUIRED for scheme=hmac
//	SIGILD_JUSPAY_WEBHOOK_SIG_HEADER optional header-name override (the real name
//	                                 is UNVERIFIED — see internal/billing/juspay.go)
//	SIGILD_JUSPAY_AMOUNT_MINOR      default amount in paise
//	SIGILD_JUSPAY_CURRENCY          default currency (INR)
//	SIGILD_JUSPAY_API_BASE_URL      optional API host override
//
// FAIL-FAST RULE: enabling a provider WITHOUT its secrets is a BOOT ERROR, never
// a runtime surprise. A server that starts with a half-configured payment
// provider would accept webhooks it cannot authenticate (rejecting real events)
// or offer checkouts it cannot create — both are worse than not starting.
//
// SECRETS: every value above comes from the environment. Nothing is defaulted to
// a credential, nothing is written to the repository, and the boot log records
// only WHICH providers are enabled and which Juspay scheme is active — never a
// key, a secret, a username or a password.

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/ARYDESTROYER/sigil/sigild/internal/billing"
)

// billingEnv is the raw environment for the billing layer, injected so
// validation is unit-testable without touching the process environment.
type billingEnv struct {
	Providers       string
	DefaultProvider string
	DevOps          string
	DeviceAuth      string
	SuccessURL      string
	CancelURL       string

	StripeSecretKey     string
	StripeWebhookSecret string
	StripePriceID       string
	StripeBaseURL       string

	RazorpayKeyID         string
	RazorpayKeySecret     string
	RazorpayWebhookSecret string
	RazorpayAmountMinor   string
	RazorpayCurrency      string
	RazorpayDescription   string
	RazorpayBaseURL       string

	JuspayMerchantID      string
	JuspayAPIKey          string
	JuspayClientID        string
	JuspayWebhookScheme   string
	JuspayWebhookUsername string
	JuspayWebhookPassword string
	JuspayWebhookSecret   string
	JuspayWebhookSigHdr   string
	JuspayAmountMinor     string
	JuspayCurrency        string
	JuspayBaseURL         string
}

// billingConfig is the validated result. Providers holds constructed adapters
// keyed by name; the secrets live inside them and are never re-exposed.
type billingConfig struct {
	Enabled         bool
	Providers       map[string]billing.Provider
	DefaultProvider string
	SuccessURL      string
	CancelURL       string
	// JuspayScheme is recorded ONLY so the boot log can say which webhook
	// mechanism is active (it names a mechanism, never a credential).
	JuspayScheme string
}

// ProviderNames returns the enabled provider names in the canonical order, for
// the boot log.
func (c billingConfig) ProviderNames() []string {
	out := make([]string, 0, len(c.Providers))
	for _, name := range billing.SupportedProviders {
		if _, ok := c.Providers[name]; ok {
			out = append(out, name)
		}
	}
	return out
}

// validateBillingConfig parses + validates the billing environment and fails
// fast on any misconfiguration. It never calls os.Exit and performs NO network
// I/O, so it is fully unit-testable and cannot contact a provider at boot.
func validateBillingConfig(env billingEnv) (billingConfig, error) {
	names, err := parseProviderList(env.Providers)
	if err != nil {
		return billingConfig{}, fmt.Errorf("SIGILD_BILLING_PROVIDERS: %w", err)
	}
	if len(names) == 0 {
		// Billing off. Everything else in env is ignored, so a stale/pre-staged
		// key cannot silently switch payments on.
		return billingConfig{}, nil
	}

	if !truthy(env.DevOps) {
		return billingConfig{}, errors.New("SIGILD_BILLING_PROVIDERS requires SIGILD_ENABLE_DEV_OPS: the billing surface is dev-gated like every other stateful route")
	}
	if !truthy(env.DeviceAuth) {
		return billingConfig{}, errors.New("SIGILD_BILLING_PROVIDERS requires SIGILD_DEVICE_AUTH: checkout and subscription status are authenticated as an ENROLLED DEVICE (contract v3), and there is no second auth path")
	}

	successURL, err := requireURL("SIGILD_BILLING_SUCCESS_URL", env.SuccessURL)
	if err != nil {
		return billingConfig{}, err
	}
	cancelURL, err := requireURL("SIGILD_BILLING_CANCEL_URL", env.CancelURL)
	if err != nil {
		return billingConfig{}, err
	}

	cfg := billingConfig{
		Enabled:    true,
		Providers:  make(map[string]billing.Provider, len(names)),
		SuccessURL: successURL,
		CancelURL:  cancelURL,
	}

	for _, name := range names {
		switch name {
		case billing.ProviderStripe:
			p, err := buildStripe(env)
			if err != nil {
				return billingConfig{}, err
			}
			cfg.Providers[name] = p
		case billing.ProviderRazorpay:
			p, err := buildRazorpay(env)
			if err != nil {
				return billingConfig{}, err
			}
			cfg.Providers[name] = p
		case billing.ProviderJuspay:
			p, scheme, err := buildJuspay(env)
			if err != nil {
				return billingConfig{}, err
			}
			cfg.Providers[name] = p
			cfg.JuspayScheme = scheme
		}
	}

	def := strings.TrimSpace(env.DefaultProvider)
	if def == "" {
		def = names[0]
	}
	if _, ok := cfg.Providers[def]; !ok {
		return billingConfig{}, fmt.Errorf("SIGILD_BILLING_DEFAULT_PROVIDER: %q is not one of the enabled providers (%s)",
			def, strings.Join(names, ", "))
	}
	cfg.DefaultProvider = def

	return cfg, nil
}

// parseProviderList splits and validates the comma-separated provider list,
// rejecting unknown names and duplicates. An empty/blank value yields no
// providers and no error (billing off).
func parseProviderList(s string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	for _, part := range strings.Split(s, ",") {
		name := strings.ToLower(strings.TrimSpace(part))
		if name == "" {
			continue
		}
		known := false
		for _, supported := range billing.SupportedProviders {
			if name == supported {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("unknown provider %q (supported: %s)",
				name, strings.Join(billing.SupportedProviders, ", "))
		}
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("duplicate provider %q", name)
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	return out, nil
}

// requireURL validates a required absolute http(s) URL. A relative or
// scheme-less value would silently produce a broken redirect at the provider, so
// it is rejected at boot.
func requireURL(name, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("%s: is required when billing is enabled", name)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%s: not a valid URL: %w", name, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("%s: must be an absolute http(s) URL", name)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%s: must include a host", name)
	}
	return raw, nil
}

// requireSecret enforces that an enabled provider's credential is present. The
// value is returned but NEVER logged, and its length/content are never reported
// in the error — only the variable name.
func requireSecret(name, raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", fmt.Errorf("%s: is required when that provider is enabled (enabling a provider without its credentials would accept webhooks it cannot authenticate)", name)
	}
	return v, nil
}

// optionalBaseURL validates an API host override. Empty is fine (the adapter
// uses its production default); a set value must be an absolute http(s) URL.
func optionalBaseURL(name, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%s: not a valid URL: %w", name, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" || u.Host == "" {
		return "", fmt.Errorf("%s: must be an absolute http(s) URL", name)
	}
	return raw, nil
}

// parseAmountMinor parses an optional minor-unit amount (paise/cents). Empty =>
// 0 (the adapter then requires a per-request amount). A set value must be a
// positive integer — a zero or negative charge is a configuration error.
func parseAmountMinor(name, raw string) (int64, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	v, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s: must be an integer number of minor units: %w", name, err)
	}
	if v <= 0 {
		return 0, fmt.Errorf("%s: must be positive, got %d", name, v)
	}
	return v, nil
}

// buildStripe validates Stripe's environment and constructs the adapter.
func buildStripe(env billingEnv) (billing.Provider, error) {
	secretKey, err := requireSecret("SIGILD_STRIPE_SECRET_KEY", env.StripeSecretKey)
	if err != nil {
		return nil, err
	}
	webhookSecret, err := requireSecret("SIGILD_STRIPE_WEBHOOK_SECRET", env.StripeWebhookSecret)
	if err != nil {
		return nil, err
	}
	baseURL, err := optionalBaseURL("SIGILD_STRIPE_API_BASE_URL", env.StripeBaseURL)
	if err != nil {
		return nil, err
	}
	return billing.NewStripe(billing.StripeConfig{
		SecretKey:     secretKey,
		WebhookSecret: webhookSecret,
		PriceID:       strings.TrimSpace(env.StripePriceID),
		BaseURL:       baseURL,
	}), nil
}

// buildRazorpay validates Razorpay's environment and constructs the adapter.
func buildRazorpay(env billingEnv) (billing.Provider, error) {
	keyID, err := requireSecret("SIGILD_RAZORPAY_KEY_ID", env.RazorpayKeyID)
	if err != nil {
		return nil, err
	}
	keySecret, err := requireSecret("SIGILD_RAZORPAY_KEY_SECRET", env.RazorpayKeySecret)
	if err != nil {
		return nil, err
	}
	webhookSecret, err := requireSecret("SIGILD_RAZORPAY_WEBHOOK_SECRET", env.RazorpayWebhookSecret)
	if err != nil {
		return nil, err
	}
	amount, err := parseAmountMinor("SIGILD_RAZORPAY_AMOUNT_MINOR", env.RazorpayAmountMinor)
	if err != nil {
		return nil, err
	}
	baseURL, err := optionalBaseURL("SIGILD_RAZORPAY_API_BASE_URL", env.RazorpayBaseURL)
	if err != nil {
		return nil, err
	}
	return billing.NewRazorpay(billing.RazorpayConfig{
		KeyID:         keyID,
		KeySecret:     keySecret,
		WebhookSecret: webhookSecret,
		AmountMinor:   amount,
		Currency:      strings.TrimSpace(env.RazorpayCurrency),
		Description:   strings.TrimSpace(env.RazorpayDescription),
		BaseURL:       baseURL,
	}), nil
}

// buildJuspay validates Juspay's environment and constructs the adapter,
// selecting and validating the webhook scheme. It returns the scheme name so the
// boot log can record WHICH mechanism is active — and, with it, that the scheme
// is UNVERIFIED against a live dashboard (see internal/billing/juspay.go).
func buildJuspay(env billingEnv) (billing.Provider, string, error) {
	merchantID, err := requireSecret("SIGILD_JUSPAY_MERCHANT_ID", env.JuspayMerchantID)
	if err != nil {
		return nil, "", err
	}
	apiKey, err := requireSecret("SIGILD_JUSPAY_API_KEY", env.JuspayAPIKey)
	if err != nil {
		return nil, "", err
	}

	scheme := strings.ToLower(strings.TrimSpace(env.JuspayWebhookScheme))
	if !billing.ValidJuspayScheme(scheme) {
		return nil, "", fmt.Errorf("SIGILD_JUSPAY_WEBHOOK_SCHEME: must be %q or %q",
			billing.JuspaySchemeBasic, billing.JuspaySchemeHMAC)
	}
	if scheme == "" {
		scheme = billing.JuspaySchemeBasic
	}

	cfg := billing.JuspayConfig{
		MerchantID:             merchantID,
		APIKey:                 apiKey,
		ClientID:               strings.TrimSpace(env.JuspayClientID),
		WebhookScheme:          scheme,
		WebhookSignatureHeader: strings.TrimSpace(env.JuspayWebhookSigHdr),
		Currency:               strings.TrimSpace(env.JuspayCurrency),
	}
	switch scheme {
	case billing.JuspaySchemeHMAC:
		secret, err := requireSecret("SIGILD_JUSPAY_WEBHOOK_SECRET", env.JuspayWebhookSecret)
		if err != nil {
			return nil, "", err
		}
		cfg.WebhookSecret = secret
	default:
		user, err := requireSecret("SIGILD_JUSPAY_WEBHOOK_USERNAME", env.JuspayWebhookUsername)
		if err != nil {
			return nil, "", err
		}
		pass, err := requireSecret("SIGILD_JUSPAY_WEBHOOK_PASSWORD", env.JuspayWebhookPassword)
		if err != nil {
			return nil, "", err
		}
		cfg.WebhookUsername = user
		cfg.WebhookPassword = pass
	}

	amount, err := parseAmountMinor("SIGILD_JUSPAY_AMOUNT_MINOR", env.JuspayAmountMinor)
	if err != nil {
		return nil, "", err
	}
	cfg.AmountMinor = amount

	baseURL, err := optionalBaseURL("SIGILD_JUSPAY_API_BASE_URL", env.JuspayBaseURL)
	if err != nil {
		return nil, "", err
	}
	cfg.BaseURL = baseURL

	return billing.NewJuspay(cfg), scheme, nil
}
