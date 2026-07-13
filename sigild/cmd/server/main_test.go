package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

// These test the extracted, fail-fast config parsers/validators directly (they
// never call os.Exit — main does that on their error). Good and bad inputs only.

func TestValidateListenAddr(t *testing.T) {
	good := []string{":8080", "127.0.0.1:9000", "0.0.0.0:80", "[::1]:8080"}
	for _, s := range good {
		if err := validateListenAddr(s); err != nil {
			t.Errorf("validateListenAddr(%q) = %v, want nil", s, err)
		}
	}
	bad := []string{"", "8080", "not-an-addr", "127.0.0.1"}
	for _, s := range bad {
		if err := validateListenAddr(s); err == nil {
			t.Errorf("validateListenAddr(%q) = nil, want error", s)
		}
	}
}

func TestParseRateLimit(t *testing.T) {
	cases := []struct {
		in   string
		want float64
	}{
		{"", 0},      // unset => disabled
		{"  ", 0},    // blank => disabled
		{"0", 0},     // explicit zero
		{"1.5", 1.5}, //
		{"100", 100}, //
		{"0.001", 0.001},
	}
	for _, c := range cases {
		got, err := parseRateLimit(c.in)
		if err != nil {
			t.Errorf("parseRateLimit(%q) error = %v, want nil", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseRateLimit(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"abc", "-1", "1.2.3", "NaN", "Inf", "-0.5"} {
		if _, err := parseRateLimit(bad); err == nil {
			t.Errorf("parseRateLimit(%q) = nil error, want error", bad)
		}
	}
}

func TestParseRateBurst(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{" ", 0},
		{"0", 0},
		{"5", 5},
		{"1000", 1000},
	}
	for _, c := range cases {
		got, err := parseRateBurst(c.in)
		if err != nil {
			t.Errorf("parseRateBurst(%q) error = %v, want nil", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseRateBurst(%q) = %v, want %v", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"abc", "-2", "1.5"} {
		if _, err := parseRateBurst(bad); err == nil {
			t.Errorf("parseRateBurst(%q) = nil error, want error", bad)
		}
	}
}

func TestEffectiveBurst(t *testing.T) {
	cases := []struct {
		rate  float64
		burst int
		want  int
	}{
		{5, 3, 3},     // explicit burst wins
		{5, 0, 5},     // default = ceil(rate)
		{0.5, 0, 1},   // ceil(0.5)=1
		{2.1, 0, 3},   // ceil(2.1)=3
		{0.001, 0, 1}, // floored at 1
	}
	for _, c := range cases {
		if got := effectiveBurst(c.rate, c.burst); got != c.want {
			t.Errorf("effectiveBurst(%v, %d) = %d, want %d", c.rate, c.burst, got, c.want)
		}
	}
}

func TestParseOpLogPubKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	enc := base64.StdEncoding.EncodeToString(pub)
	got, err := parseOpLogPubKey(enc)
	if err != nil {
		t.Fatalf("parseOpLogPubKey(valid) error = %v", err)
	}
	if !pub.Equal(got) {
		t.Fatal("parseOpLogPubKey round-trip mismatch")
	}

	// Bad base64.
	if _, err := parseOpLogPubKey("not base64 !!!"); err == nil {
		t.Error("parseOpLogPubKey(bad base64) = nil error, want error")
	}
	// Valid base64 but wrong length (16 bytes).
	short := base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := parseOpLogPubKey(short); err == nil {
		t.Error("parseOpLogPubKey(wrong length) = nil error, want error")
	}
}
