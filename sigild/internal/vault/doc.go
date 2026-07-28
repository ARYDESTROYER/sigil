// Package vault is a RESERVED NAME. It is empty, imported by nothing, and it is
// NOT where the vault op-log lives.
//
// ⚠️ The encrypted-blob operation log IS IMPLEMENTED, in:
//
//	internal/store/vaultlog.go        the VaultLog seam
//	internal/store/memvaultlog.go     in-memory backend
//	internal/store/filevaultlog.go    file-backed backend
//	internal/store/postgresvaultlog.go durable Postgres backend
//	internal/store/oplogchain.go      the per-op SHA-256 hash chain
//	internal/api/handlers.go          the HTTP surface
//
// An earlier version of this file said STATUS: not implemented, which was false:
// the op-log is one of the oldest working parts of this server, and it is
// tamper-evident and covered by conformance tests across all three backends.
//
// It also described CRDT operations keyed by Lamport clock in object storage.
// That remains genuinely UNBUILT — the shipped op-log is an append-only sequence
// with a monotonic per-vault seq, and there is no merge semantics. That gap is
// real and is recorded in docs/architecture.md; it is the only part of the old
// description that was accurate about the future.
package vault
