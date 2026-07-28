package main

import (
	"strings"
	"testing"
)

func TestCORSOriginsOffByDefault(t *testing.T) {
	got, err := validateCORSOrigins("")
	if err != nil {
		t.Fatalf("unset must be valid, got %v", err)
	}
	if got != nil {
		t.Fatalf("unset must yield no origins, got %v", got)
	}
	if got, err := validateCORSOrigins("   "); err != nil || got != nil {
		t.Fatalf("blank must yield (nil, nil), got (%v, %v)", got, err)
	}
}

func TestCORSOriginsParsesAndNormalizes(t *testing.T) {
	got, err := validateCORSOrigins(
		" http://127.0.0.1:3210 , HTTP://LOCALHOST:3000,https://app.example ,http://127.0.0.1:3210")
	if err != nil {
		t.Fatalf("valid list rejected: %v", err)
	}
	want := []string{"http://127.0.0.1:3210", "http://localhost:3000", "https://app.example"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v (duplicates must collapse)", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// ⭐ The wildcard is refused OUTRIGHT — not accepted, not narrowed, not warned
// about. An API carrying per-request signed credentials must not be openable by
// a typo.
func TestCORSOriginsRejectsWildcard(t *testing.T) {
	for _, raw := range []string{"*", "http://localhost:3000,*", " * "} {
		if _, err := validateCORSOrigins(raw); err == nil {
			t.Fatalf("%q was accepted; a wildcard must be a boot error", raw)
		} else if !strings.Contains(err.Error(), "wildcard") {
			t.Fatalf("%q: error %q should name the wildcard", raw, err)
		}
	}
}

func TestCORSOriginsRejectsMalformed(t *testing.T) {
	for _, raw := range []string{
		"localhost:3000",                 // no scheme
		"ftp://localhost:3000",           // wrong scheme
		"http://",                        // no host
		"http://localhost:3000/",         // trailing slash is not an origin
		"http://localhost:3000/app",      // path
		"http://localhost:3000?x=1",      // query
		"http://localhost:3000#f",        // fragment
		"http://user:pw@localhost:3000",  // credentials
		"chrome-extension://abcdefghijk", // not an http(s) origin
		",",                              // set, but empty
	} {
		if _, err := validateCORSOrigins(raw); err == nil {
			t.Fatalf("%q was accepted, want a boot error", raw)
		}
	}
}
