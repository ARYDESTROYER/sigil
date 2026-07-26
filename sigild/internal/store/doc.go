// Package store will hold the persistence adapters: PostgreSQL (accounts,
// devices, vault + op metadata) via pgx, S3-compatible object storage for the
// encrypted blobs, and Redis for sessions and rate limits.
//
// STATUS: pre-audit skeleton. The full production data layer above is not built
// yet. What exists today:
//
//   - the minimal KV interface (see store.go) with a concurrency-safe in-memory
//     MemKV for wiring and tests (non-durable);
//   - the VaultLog seam (see vaultlog.go) for the dev-gated, opaque op-log, with
//     three interchangeable backends: in-memory MemVaultLog (non-durable), the
//     file-backed FileVaultLog (single-process local-dev durability), and the
//     opt-in PostgresVaultLog (durable + concurrent, on the pgx driver — the
//     first real production-store *adapter*, selected via SIGILD_OPLOG_POSTGRES).
//   - the DeviceStore seam (see devicestore.go) for the opt-in MULTI-DEVICE auth
//     model: a device registry (Ed25519 public keys + status), a single-use
//     enrollment-token ledger (tokens stored only as SHA-256 digests), and
//     per-vault authorization grants. Two backends: the concurrency-safe
//     in-memory MemDeviceStore and the durable PostgresDeviceStore (tables from
//     migration 0002_devices, sharing the op-log's pool). Both enforce the same
//     two ATOMIC guarantees — a token can be spent exactly once, and a vault has
//     at most one owner — in memory via a mutex and in Postgres via a
//     conditional UPDATE plus a partial UNIQUE index (so they hold across
//     processes). It holds AUTH METADATA ONLY: no vault plaintext, no ciphertext.
//
// Every VaultLog stores OPAQUE client-encrypted blobs and performs NO
// cryptography on the plaintext. Each op additionally carries a SHA-256 chain
// hash (see oplogchain.go) that makes the log tamper-EVIDENT: any later
// insertion/deletion/modification of a stored op is DETECTABLE via VerifyChain.
// The hash is computed over the ciphertext blob only (it fingerprints
// ciphertext), so it does not weaken the server's zero-knowledge property. This
// is tamper-EVIDENT, not tamper-PROOF: it does not prevent a malicious server
// from rewriting the chain or lying about VerifyChain — the trustworthy check is
// client-side.
//
// Even the Postgres backend is a durable DEV backend, not the finished
// production store: there is still no auth/enrollment model, no per-vault
// authorization, no CRDT/merge, no S3 offload for large blobs, no managed
// migrations, and no backup/replication.
package store
