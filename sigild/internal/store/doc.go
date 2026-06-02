// Package store will hold the persistence adapters: PostgreSQL (accounts,
// devices, vault + op metadata) via pgx, S3-compatible object storage for the
// encrypted blobs, and Redis for sessions and rate limits.
//
// STATUS: pre-audit skeleton. The production adapters above are not implemented
// yet. As a building block this package defines the minimal KV interface
// (see store.go) and a concurrency-safe in-memory implementation
// (MemKV) used for wiring and tests. It performs NO encryption and provides NO
// durability — it is not a substitute for the real PostgreSQL/S3/Redis backends.
package store
