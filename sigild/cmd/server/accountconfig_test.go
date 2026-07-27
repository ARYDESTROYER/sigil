package main

// Fail-fast validation tests for the account model's environment (Phase 52).
// Like the other config tests these drive the extracted validator directly (it
// never calls os.Exit — main does that on its error), and they prove the
// operator finds out about a bad value BEFORE the listener binds.

import (
	"strings"
	"testing"
	"time"
)

// TestAccountConfigDefaults: with nothing set, the defaults apply and no error
// is raised — including when device auth is off, because the settings are simply
// unused then.
func TestAccountConfigDefaults(t *testing.T) {
	for name, env := range map[string]accountEnv{
		"nothing set":              {},
		"device auth on, no knobs": {DeviceAuth: "1"},
	} {
		cfg, err := validateAccountConfig(env)
		if err != nil {
			t.Fatalf("%s: unexpected error %v", name, err)
		}
		if cfg.MaxDevices != defaultAccountMaxDevices {
			t.Errorf("%s: MaxDevices = %d, want %d", name, cfg.MaxDevices, defaultAccountMaxDevices)
		}
		if cfg.MaxInvites != defaultAccountMaxInvites {
			t.Errorf("%s: MaxInvites = %d, want %d", name, cfg.MaxInvites, defaultAccountMaxInvites)
		}
		if cfg.InviteTTL != defaultAccountInviteTTL {
			t.Errorf("%s: InviteTTL = %s, want %s", name, cfg.InviteTTL, defaultAccountInviteTTL)
		}
	}
}

// TestAccountConfigRequiresDeviceAuth: setting any account knob WITHOUT
// SIGILD_DEVICE_AUTH is a boot error. A knob that silently does nothing is worse
// than a refusal — the operator would believe a cap was in force when it was not.
func TestAccountConfigRequiresDeviceAuth(t *testing.T) {
	for name, env := range map[string]accountEnv{
		"max devices": {MaxDevices: "4"},
		"max invites": {MaxInvites: "2"},
		"invite ttl":  {InviteTTL: "5m"},
		"all three":   {MaxDevices: "4", MaxInvites: "2", InviteTTL: "5m"},
	} {
		if _, err := validateAccountConfig(env); err == nil {
			t.Errorf("%s: accepted account settings with device auth off, want an error", name)
		} else if !strings.Contains(err.Error(), "SIGILD_DEVICE_AUTH") {
			t.Errorf("%s: error %q does not name SIGILD_DEVICE_AUTH", name, err)
		}
	}
}

// TestAccountConfigRejectsOutOfRange: a malformed or out-of-range value is an
// ERROR, never a silent clamp. An operator who typed 10000 meant something.
func TestAccountConfigRejectsOutOfRange(t *testing.T) {
	cases := map[string]accountEnv{
		"devices not a number": {DeviceAuth: "1", MaxDevices: "many"},
		"devices zero":         {DeviceAuth: "1", MaxDevices: "0"},
		"devices negative":     {DeviceAuth: "1", MaxDevices: "-1"},
		"devices too large":    {DeviceAuth: "1", MaxDevices: "1001"},
		"invites not a number": {DeviceAuth: "1", MaxInvites: "lots"},
		"invites zero":         {DeviceAuth: "1", MaxInvites: "0"},
		"invites too large":    {DeviceAuth: "1", MaxInvites: "101"},
		"ttl not a duration":   {DeviceAuth: "1", InviteTTL: "fifteen minutes"},
		"ttl zero":             {DeviceAuth: "1", InviteTTL: "0s"},
		"ttl negative":         {DeviceAuth: "1", InviteTTL: "-5m"},
		"ttl beyond a day":     {DeviceAuth: "1", InviteTTL: "25h"},
	}
	for name, env := range cases {
		if cfg, err := validateAccountConfig(env); err == nil {
			t.Errorf("%s: accepted, want an error (got %+v)", name, cfg)
		}
	}
}

// TestAccountConfigAcceptsBoundaries: the extremes of each range are valid.
func TestAccountConfigAcceptsBoundaries(t *testing.T) {
	cfg, err := validateAccountConfig(accountEnv{
		DeviceAuth: "1",
		MaxDevices: "1",
		MaxInvites: "100",
		InviteTTL:  "24h",
	})
	if err != nil {
		t.Fatalf("boundary values rejected: %v", err)
	}
	if cfg.MaxDevices != minAccountMaxDevices || cfg.MaxInvites != maxAccountMaxInvites {
		t.Fatalf("cfg = %+v, want the boundary values", cfg)
	}
	if cfg.InviteTTL != maxAccountInviteTTL {
		t.Fatalf("InviteTTL = %s, want %s", cfg.InviteTTL, maxAccountInviteTTL)
	}

	upper, err := validateAccountConfig(accountEnv{DeviceAuth: "1", MaxDevices: "1000", MaxInvites: "1"})
	if err != nil {
		t.Fatalf("upper device bound rejected: %v", err)
	}
	if upper.MaxDevices != maxAccountMaxDevices || upper.MaxInvites != minAccountMaxInvites {
		t.Fatalf("cfg = %+v, want the boundary values", upper)
	}
}

// TestParseBoundedDurationRoundTrip pins the small helper directly.
func TestParseBoundedDurationRoundTrip(t *testing.T) {
	got, err := parseBoundedDuration("90s", time.Minute, time.Hour)
	if err != nil || got != 90*time.Second {
		t.Fatalf("parseBoundedDuration = (%s, %v), want 1m30s", got, err)
	}
	if got, err := parseBoundedDuration("", time.Minute, time.Hour); err != nil || got != time.Minute {
		t.Fatalf("empty value = (%s, %v), want the default", got, err)
	}
}
