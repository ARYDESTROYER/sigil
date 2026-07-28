// Package push will fan out opaque wake notifications (vault ID + wake hint
// only, never code data) over APNS, FCM, Web Push, and the long-lived gRPC
// sync streams for foreground clients.
//
// STATUS: RESERVED NAME ONLY — empty, imported by nothing, and accurate as a
// statement about the future rather than the present.
// Nothing here is implemented, and no client polls or subscribes for wake
// notifications today — clients sync only when a human asks them to.
package push
