// Package store will hold the persistence adapters: PostgreSQL (accounts,
// devices, vault + op metadata) via pgx, S3-compatible object storage for the
// encrypted blobs, and Redis for sessions and rate limits.
//
// STATUS: pre-audit skeleton — not implemented.
package store
