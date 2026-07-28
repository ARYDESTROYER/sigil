package main

// Fail-fast validation tests for the entitlement-enforcement environment
// (Phase 55). Like the other config tests these drive the extracted validator
// directly (it never calls os.Exit — main does that on its error), proving an
// operator finds out about a bad value BEFORE the listener binds.
//
// The properties that matter most here:
//
//   - OFF BY DEFAULT. With nothing set, nothing is enforced.
//   - NO SILENTLY INERT KNOB. This is the one setting that can stop serving a
//     paying customer, so enabling it without the machinery it depends on is a
//     refusal to boot, not a shrug.
//   - THE DEFAULT GRACE IS GENEROUS, and it comes from the api package so the
//     server and the enforcement code can never disagree about it.

import (
	"strings"
	"testing"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/api"
)

// fullyConfigured is the environment in which enforcement is legal: dev ops,
// device auth and at least one billing provider.
func fullyConfigured(enforce, grace string) entitlementEnv {
	return entitlementEnv{
		Enforce:    enforce,
		Grace:      grace,
		DevOps:     "1",
		DeviceAuth: "1",
		Billing:    "stripe",
	}
}

// TestEntitlementDefaultsToOff: nothing set => no enforcement at all.
func TestEntitlementDefaultsToOff(t *testing.T) {
	cfg, err := validateEntitlementConfig(entitlementEnv{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Enforce {
		t.Fatal("Enforce = true with nothing set, want false")
	}
	if cfg.Grace != 0 {
		t.Fatalf("Grace = %s with nothing set, want 0 (no policy installed)", cfg.Grace)
	}
}

// TestEntitlementOffIgnoresEverythingElse: an un-opted-in server does not care
// whether device auth or billing are on.
func TestEntitlementOffIgnoresEverythingElse(t *testing.T) {
	cfg, err := validateEntitlementConfig(entitlementEnv{DevOps: "1", DeviceAuth: "1", Billing: "stripe"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Enforce {
		t.Fatal("Enforce = true without SIGILD_ENTITLEMENT_ENFORCE")
	}
}

// TestEntitlementUsesTheGenerousDefaultGrace: switching enforcement on without
// naming a window gets the api package's default, not zero.
//
// This is load-bearing: a zero here would mean "refuse the instant a
// subscription lapses", which is precisely the behaviour the grace period exists
// to prevent.
func TestEntitlementUsesTheGenerousDefaultGrace(t *testing.T) {
	cfg, err := validateEntitlementConfig(fullyConfigured("1", ""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !cfg.Enforce {
		t.Fatal("Enforce = false with SIGILD_ENTITLEMENT_ENFORCE=1")
	}
	if cfg.Grace != api.DefaultEntitlementGrace {
		t.Fatalf("Grace = %s, want the api package default %s", cfg.Grace, api.DefaultEntitlementGrace)
	}
	if cfg.Grace < 7*24*time.Hour {
		t.Fatalf("the default grace is %s — too short to survive a holiday weekend, let alone a "+
			"disputed card; being over-generous costs revenue, being under-generous costs "+
			"somebody their 2FA", cfg.Grace)
	}
}

// TestEntitlementParsesAnExplicitGrace.
func TestEntitlementParsesAnExplicitGrace(t *testing.T) {
	cfg, err := validateEntitlementConfig(fullyConfigured("true", "72h"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Grace != 72*time.Hour {
		t.Fatalf("Grace = %s, want 72h", cfg.Grace)
	}
}

// TestEntitlementRejectsMissingPrerequisites: enforcement without the machinery
// it needs is a BOOT ERROR, never a silently inert setting.
func TestEntitlementRejectsMissingPrerequisites(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  entitlementEnv
		want string
	}{
		{
			name: "no dev ops",
			env:  entitlementEnv{Enforce: "1", DeviceAuth: "1", Billing: "stripe"},
			want: "SIGILD_ENABLE_DEV_OPS",
		},
		{
			name: "no device auth",
			env:  entitlementEnv{Enforce: "1", DevOps: "1", Billing: "stripe"},
			want: "SIGILD_DEVICE_AUTH",
		},
		{
			name: "no billing",
			env:  entitlementEnv{Enforce: "1", DevOps: "1", DeviceAuth: "1"},
			want: "SIGILD_BILLING_PROVIDERS",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateEntitlementConfig(tc.env)
			if err == nil {
				t.Fatal("accepted enforcement without its prerequisites")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name %s", err, tc.want)
			}
		})
	}
}

// TestGraceWithoutEnforceIsAnError: a grace period configured on a server that
// enforces nothing is an inert setting an operator believes is doing something.
func TestGraceWithoutEnforceIsAnError(t *testing.T) {
	_, err := validateEntitlementConfig(entitlementEnv{
		Grace: "72h", DevOps: "1", DeviceAuth: "1", Billing: "stripe",
	})
	if err == nil {
		t.Fatal("accepted SIGILD_ENTITLEMENT_GRACE without SIGILD_ENTITLEMENT_ENFORCE")
	}
	if !strings.Contains(err.Error(), "SIGILD_ENTITLEMENT_ENFORCE") {
		t.Fatalf("error %q does not name the missing switch", err)
	}
}

// TestEntitlementRejectsBadGrace: an out-of-range or unparseable window is an
// ERROR, never a silent clamp. Zero especially: it would mean "refuse
// immediately", the exact opposite of what the operator was configuring.
func TestEntitlementRejectsBadGrace(t *testing.T) {
	for _, bad := range []string{"0", "-1h", "0s", "8761h", "forever", "72"} {
		t.Run(bad, func(t *testing.T) {
			if _, err := validateEntitlementConfig(fullyConfigured("1", bad)); err == nil {
				t.Fatalf("accepted SIGILD_ENTITLEMENT_GRACE=%q", bad)
			}
		})
	}
}

// TestEntitlementAcceptsTheCeiling: exactly the maximum is legal; one hour over
// is not.
func TestEntitlementAcceptsTheCeiling(t *testing.T) {
	cfg, err := validateEntitlementConfig(fullyConfigured("1", entitlementMaxGrace.String()))
	if err != nil {
		t.Fatalf("rejected the documented ceiling: %v", err)
	}
	if cfg.Grace != entitlementMaxGrace {
		t.Fatalf("Grace = %s, want %s", cfg.Grace, entitlementMaxGrace)
	}
	if _, err := validateEntitlementConfig(fullyConfigured("1", (entitlementMaxGrace + time.Hour).String())); err == nil {
		t.Fatal("accepted a grace period past the ceiling")
	}
}
