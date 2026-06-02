// Package push will fan out opaque wake notifications (vault ID + wake hint
// only, never code data) over APNS, FCM, Web Push, and the long-lived gRPC
// sync streams for foreground clients.
//
// STATUS: pre-audit skeleton — not implemented.
package push
