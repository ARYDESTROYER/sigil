// Package auth is a RESERVED NAME. It is empty, imported by nothing, and it is
// NOT where sigild's request authentication lives.
//
// ⚠️ READ THIS BEFORE CONCLUDING ANYTHING ABOUT sigild's AUTH.
//
// Request authentication IS IMPLEMENTED, in internal/api:
//
//	internal/api/deviceauth.go   the device-auth contract v3: per-request
//	                             Ed25519 signature over a canonical message,
//	                             enrollment proof-of-possession, the verify
//	                             ORDER, revocation, per-vault authorization
//	                             and the account boundary
//	internal/api/opsauth.go      the legacy single-key op-log contract (v2)
//	internal/store/devicestore.go the device registry those checks read
//
// An earlier version of this file described a design that was NEVER BUILT —
// "Ed25519-signed JWT bearer tokens minted at device registration" — and said
// STATUS: not implemented. Both statements were false by the time anyone read
// them: there is no JWT anywhere in sigild, and there are several hundred lines
// of working request authentication in the files above. A reader who opened this
// package to find out how sigild authenticates would have been misdirected
// twice, which is the opposite of what a pre-audit foundation is for.
//
// The name is kept only because a future extraction of that logic out of
// internal/api would land here. It holds no code and no plan.
package auth
