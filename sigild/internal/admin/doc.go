// Package admin will hold the self-host operator endpoints (backup, restore,
// user create/disable, vault audit, audit-log export), also used by Sigil
// Cloud's internal tooling.
//
// STATUS: RESERVED NAME ONLY — empty, imported by nothing, and accurate as a
// statement about the future rather than the present.
// Nothing here is implemented. The operator surface that DOES exist is the
// `sigild migrate` / `sigild migrate adopt` subcommand in cmd/server, the
// admin-token-gated device routes in internal/api/devices.go, and GET /metrics.
package admin
