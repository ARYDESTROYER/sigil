package main

// Fail-fast validation tests for the multi-device auth model's environment.
// Like the other config tests these exercise the extracted validator directly
// (it never calls os.Exit — main does that on its error).

import (
	"testing"
	"time"
)

// validEnv is a minimal, fully-valid device-auth environment.
func validEnv() deviceAuthEnv {
	return deviceAuthEnv{
		DeviceAuth: "1",
		DevOps:     "1",
		Tokens:     "enrollment-token-aaaaaaaaaaaa",
	}
}

// TestDeviceAuthOffByDefault is the BACKWARD-COMPATIBILITY guard: with
// SIGILD_DEVICE_AUTH unset the model is OFF, and nothing else in the
// environment can switch it on by accident.
func TestDeviceAuthOffByDefault(t *testing.T) {
	for name, env := range map[string]deviceAuthEnv{
		"all empty":        {},
		"dev ops on only":  {DevOps: "1"},
		"tokens staged":    {DevOps: "1", Tokens: "enrollment-token-aaaaaaaaaaaa"},
		"admin staged":     {DevOps: "1", AdminToken: "admin-token-aaaaaaaaaaaaaaaa"},
		"explicitly false": {DeviceAuth: "0", DevOps: "1", Tokens: "enrollment-token-aaaaaaaaaaaa"},
		"garbage value":    {DeviceAuth: "yes-please", DevOps: "1", Tokens: "enrollment-token-aaaaaaaaaaaa"},
	} {
		cfg, err := validateDeviceAuthConfig(env)
		if err != nil {
			t.Errorf("%s: unexpected error %v", name, err)
		}
		if cfg.Enabled {
			t.Errorf("%s: device auth enabled, want off", name)
		}
	}
}

func TestDeviceAuthValidConfig(t *testing.T) {
	env := validEnv()
	env.TokenTTL = "24h"
	env.AdminToken = "admin-token-aaaaaaaaaaaaaaaa"
	env.Tokens = " token-one-aaaaaaaaaaaaaaaa , token-two-bbbbbbbbbbbbbbbb ,, "

	cfg, err := validateDeviceAuthConfig(env)
	if err != nil {
		t.Fatalf("validateDeviceAuthConfig: %v", err)
	}
	if !cfg.Enabled {
		t.Fatal("device auth not enabled")
	}
	if len(cfg.Tokens) != 2 || cfg.Tokens[0] != "token-one-aaaaaaaaaaaaaaaa" || cfg.Tokens[1] != "token-two-bbbbbbbbbbbbbbbb" {
		t.Fatalf("tokens = %q, want the two trimmed tokens", cfg.Tokens)
	}
	if cfg.TokenTTL != 24*time.Hour {
		t.Fatalf("TTL = %v, want 24h", cfg.TokenTTL)
	}
	if cfg.AdminToken != "admin-token-aaaaaaaaaaaaaaaa" {
		t.Fatalf("admin token = %q", cfg.AdminToken)
	}
}

// TestDeviceAuthRejectsMisconfiguration: every way to configure the model wrong
// must be a startup error, not a silently-degraded auth posture.
func TestDeviceAuthRejectsMisconfiguration(t *testing.T) {
	cases := map[string]func(e *deviceAuthEnv){
		"without dev ops":           func(e *deviceAuthEnv) { e.DevOps = "" },
		"with no enrollment tokens": func(e *deviceAuthEnv) { e.Tokens = "" },
		"with only blank tokens":    func(e *deviceAuthEnv) { e.Tokens = " , , " },
		"with a short token":        func(e *deviceAuthEnv) { e.Tokens = "tiny" },
		"with a duplicate token":    func(e *deviceAuthEnv) { e.Tokens = "same-token-aaaaaaaaaaaaaa,same-token-aaaaaaaaaaaaaa" },
		"alongside the legacy pubkey": func(e *deviceAuthEnv) {
			e.OpLogPubKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
		},
		"with a bad TTL":         func(e *deviceAuthEnv) { e.TokenTTL = "soon" },
		"with a zero TTL":        func(e *deviceAuthEnv) { e.TokenTTL = "0s" },
		"with a negative TTL":    func(e *deviceAuthEnv) { e.TokenTTL = "-1h" },
		"with a short admin tok": func(e *deviceAuthEnv) { e.AdminToken = "short" },
	}
	for name, mutate := range cases {
		env := validEnv()
		mutate(&env)
		if _, err := validateDeviceAuthConfig(env); err == nil {
			t.Errorf("validateDeviceAuthConfig %s = nil error, want error", name)
		}
	}
}

func TestParseEnrollTokens(t *testing.T) {
	got, err := parseEnrollTokens("")
	if err != nil || len(got) != 0 {
		t.Fatalf("parseEnrollTokens(\"\") = (%v, %v), want (empty, nil)", got, err)
	}
	if _, err := parseEnrollTokens("short"); err == nil {
		t.Error("a token shorter than the minimum was accepted")
	}
	// Exactly at the minimum length is fine.
	min := "0123456789abcdef" // 16 chars
	if len(min) != minEnrollTokenLen {
		t.Fatalf("test fixture is %d chars, expected %d", len(min), minEnrollTokenLen)
	}
	if got, err := parseEnrollTokens(min); err != nil || len(got) != 1 {
		t.Fatalf("parseEnrollTokens(min-length) = (%v, %v), want one token", got, err)
	}
}

func TestParseTokenTTL(t *testing.T) {
	if d, err := parseTokenTTL(""); err != nil || d != 0 {
		t.Fatalf("parseTokenTTL(\"\") = (%v, %v), want (0, nil)", d, err)
	}
	if d, err := parseTokenTTL(" 90m "); err != nil || d != 90*time.Minute {
		t.Fatalf("parseTokenTTL(\"90m\") = (%v, %v), want 90m", d, err)
	}
	for _, bad := range []string{"nope", "0", "0s", "-5m"} {
		if _, err := parseTokenTTL(bad); err == nil {
			t.Errorf("parseTokenTTL(%q) = nil error, want error", bad)
		}
	}
}
