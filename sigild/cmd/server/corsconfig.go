package main

// SIGILD_CORS_ORIGINS — the browser origin allowlist, validated BEFORE the
// listener binds (see internal/api/cors.go for what the middleware does and,
// more importantly, for what it deliberately does NOT do).
//
//	SIGILD_CORS_ORIGINS   comma-separated EXACT origins, e.g.
//	                      "http://127.0.0.1:3000,http://localhost:3000".
//	                      UNSET (the default) => no CORS middleware is installed
//	                      and no response carries an Access-Control-* header.
//
// Every entry must be an absolute http(s) origin: scheme + host (+ optional
// port) and NOTHING else — no path, no query, no fragment, no credentials. `*`
// is REJECTED outright rather than accepted-and-narrowed, because a wildcard on
// an API that carries per-request signed credentials must not be reachable by a
// typo. A malformed value is a startup failure, never a silent fallback.

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// validateCORSOrigins parses and normalizes SIGILD_CORS_ORIGINS.
//
// Returns nil (and no error) for an empty value: CORS stays OFF.
func validateCORSOrigins(raw string) ([]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	seen := make(map[string]struct{})
	var out []string
	for _, part := range strings.Split(raw, ",") {
		entry := strings.TrimSpace(part)
		if entry == "" {
			continue
		}
		origin, err := normalizeCORSOrigin(entry)
		if err != nil {
			return nil, fmt.Errorf("origin %q: %w", entry, err)
		}
		if _, dup := seen[origin]; dup {
			continue
		}
		seen[origin] = struct{}{}
		out = append(out, origin)
	}
	if len(out) == 0 {
		return nil, errors.New("set but contains no origins (did you leave a stray comma?)")
	}
	return out, nil
}

// normalizeCORSOrigin validates ONE entry and returns it in the exact form a
// browser puts in the Origin header: lowercase scheme, lowercase host, explicit
// port only when the entry carried one.
func normalizeCORSOrigin(entry string) (string, error) {
	if entry == "*" {
		return "", errors.New(
			"a wildcard is REFUSED: this API carries per-request signed credentials, so every " +
				"origin allowed to reach it must be named explicitly. In production serve the app " +
				"and the API from the SAME origin behind the reverse proxy and set nothing here")
	}
	u, err := url.Parse(entry)
	if err != nil {
		return "", fmt.Errorf("is not a URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
	default:
		return "", errors.New(`must start with "http://" or "https://"`)
	}
	if u.Host == "" {
		return "", errors.New("has no host")
	}
	if u.User != nil {
		return "", errors.New("must not carry credentials")
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", errors.New(
			"must be a bare origin — scheme, host and optional port only, with no trailing slash, " +
				"path, query or fragment (an Origin header never carries one)")
	}
	if u.Hostname() == "" {
		return "", errors.New("has no host")
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host), nil
}
