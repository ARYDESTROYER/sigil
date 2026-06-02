// Package auth will hold sigild's request authentication: verifying the
// Ed25519-signed JWT bearer tokens minted at device registration and checking
// each device's not-valid-after timestamp before any request is served.
//
// STATUS: pre-audit skeleton — not implemented.
package auth
