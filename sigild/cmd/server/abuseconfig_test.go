package main

// Fail-fast validation tests for the abuse-bound environment (Phase 53). Like
// the other config tests these drive the extracted validator directly (it never
// calls os.Exit — main does that on its error), proving an operator finds out
// about a bad value BEFORE the listener binds.
//
// The property that matters most here: a malformed value must be an ERROR, not
// a silent fall back to "unlimited". A rate limiter that quietly disables itself
// on a typo is worse than no limiter, because the operator believes the route is
// protected when it is not.

import (
	"strings"
	"testing"
)

// TestAbuseConfigDefaultsToOff: with nothing set every rate is 0, which
// api.NewRouter turns into "no limiter installed" — the un-opted-in server is
// byte-identical to Phase 52.
func TestAbuseConfigDefaultsToOff(t *testing.T) {
	cfg, err := validateAbuseConfig(abuseEnv{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Enabled() {
		t.Fatalf("Enabled() = true with nothing set, want false")
	}
	if cfg.EnrollRate != 0 || cfg.InviteRate != 0 {
		t.Fatalf("rates = %+v, want all zero (off by default)", cfg)
	}
	if cfg.EnrollBurst != 0 || cfg.InviteBurst != 0 {
		t.Fatalf("bursts = %+v, want all zero when no rate is set", cfg)
	}
}

// TestAbuseConfigParsesEachSurface: each pair is parsed independently, so one
// surface can be limited without the other. (There is no webhook surface: that
// limiter was removed for shedding payment events — see api.billingWebhook.)
func TestAbuseConfigParsesEachSurface(t *testing.T) {
	cfg, err := validateAbuseConfig(abuseEnv{
		EnrollRate: "5", EnrollBurst: "20",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.EnrollRate != 5 || cfg.EnrollBurst != 20 {
		t.Fatalf("enroll = (%v, %d), want (5, 20)", cfg.EnrollRate, cfg.EnrollBurst)
	}
	// The unconfigured surface stays off, and Enabled() reports the whole.
	if cfg.InviteRate != 0 || cfg.InviteBurst != 0 {
		t.Fatalf("invite = (%v, %d), want (0, 0) — unconfigured", cfg.InviteRate, cfg.InviteBurst)
	}
	if !cfg.Enabled() {
		t.Fatal("Enabled() = false with one surface configured, want true")
	}
}

// TestAbuseConfigDefaultsBurstFromRate: a positive rate with no burst gets
// ceil(rate), floored at 1 — the same rule the op-log limiter uses, so all three
// limiters in this server share one contract.
func TestAbuseConfigDefaultsBurstFromRate(t *testing.T) {
	cfg, err := validateAbuseConfig(abuseEnv{EnrollRate: "2.5", InviteRate: "0.1"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.EnrollBurst != 3 {
		t.Fatalf("EnrollBurst = %d, want 3 (ceil(2.5))", cfg.EnrollBurst)
	}
	if cfg.InviteBurst != 1 {
		t.Fatalf("InviteBurst = %d, want 1 (floored)", cfg.InviteBurst)
	}
}

// TestAbuseConfigRejectsMalformed: every bad value is a startup error naming the
// variable that caused it — never a silent fallback to unlimited.
func TestAbuseConfigRejectsMalformed(t *testing.T) {
	cases := map[string]struct {
		env      abuseEnv
		wantName string
	}{
		"enroll rate not a number": {abuseEnv{EnrollRate: "fast"}, "SIGILD_ENROLL_RATE_LIMIT"},
		"enroll rate negative":     {abuseEnv{EnrollRate: "-1"}, "SIGILD_ENROLL_RATE_LIMIT"},
		"enroll rate infinite":     {abuseEnv{EnrollRate: "Inf"}, "SIGILD_ENROLL_RATE_LIMIT"},
		"enroll rate NaN":          {abuseEnv{EnrollRate: "NaN"}, "SIGILD_ENROLL_RATE_LIMIT"},
		"enroll burst not an int":  {abuseEnv{EnrollRate: "5", EnrollBurst: "lots"}, "SIGILD_ENROLL_RATE_BURST"},
		"enroll burst negative":    {abuseEnv{EnrollRate: "5", EnrollBurst: "-2"}, "SIGILD_ENROLL_RATE_BURST"},
		"invite rate not a number": {abuseEnv{InviteRate: "some"}, "SIGILD_INVITE_RATE_LIMIT"},
		"invite burst not an int":  {abuseEnv{InviteRate: "5", InviteBurst: "x"}, "SIGILD_INVITE_RATE_BURST"},
	}
	for name, c := range cases {
		cfg, err := validateAbuseConfig(c.env)
		if err == nil {
			t.Errorf("%s: accepted a malformed value (got %+v), want an error", name, cfg)
			continue
		}
		if !strings.Contains(err.Error(), c.wantName) {
			t.Errorf("%s: error %q does not name %s", name, err, c.wantName)
		}
	}
}

// TestAbuseConfigNeedsNoDevGate: unlike the SIGILD_ACCOUNT_* settings, these do
// NOT refuse to boot without SIGILD_ENABLE_DEV_OPS. Those change who OWNS a
// vault, so a silently-ignored value is an ownership surprise; a rate limit is
// purely protective, and a boot warning (logAbuseBounds) is the right weight for
// "configured but currently moot".
func TestAbuseConfigNeedsNoDevGate(t *testing.T) {
	cfg, err := validateAbuseConfig(abuseEnv{EnrollRate: "5", InviteRate: "1"})
	if err != nil {
		t.Fatalf("abuse limits without the dev gate should validate, got %v", err)
	}
	if !cfg.Enabled() {
		t.Fatal("Enabled() = false, want true")
	}
}
