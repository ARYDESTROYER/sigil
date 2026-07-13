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
//
// Every VaultLog stores OPAQUE client-encrypted blobs and performs NO
// cryptography. Even the Postgres backend is a durable DEV backend, not the
// finished production store: there is still no auth/enrollment model, no
// per-vault authorization, no CRDT/merge, no S3 offload for large blobs, no
// managed migrations, and no backup/replication.
package store
