package store

import "sync"

// Op is a single entry in a vault's operation log. Seq is a 1-based, strictly
// increasing sequence number assigned per vault. Blob is the client-encrypted
// operation payload: it is OPAQUE to the server, which never decrypts, parses,
// or otherwise interprets it.
//
// encoding/json marshals Blob ([]byte) as a base64 string automatically; API
// responses rely on that.
//
// STATUS: pre-audit skeleton.
type Op struct {
	Seq  uint64 `json:"seq"`
	Blob []byte `json:"blob"`
}

// VaultLog is an append-only log of opaque, client-encrypted operations, keyed
// by vault ID. It is the seam the real op log will implement; the in-memory
// MemVaultLog satisfies it for dev wiring and tests.
//
// Implementations must be safe for concurrent use. Blobs are treated as opaque:
// the log applies NO encryption, encoding, decryption, or interpretation. The
// server stores exactly the bytes it was given and hands them back unchanged.
//
// STATUS: pre-audit skeleton. The production op log must add authentication, a
// durable store, and real op/CRDT merge semantics; this provides none of those.
type VaultLog interface {
	// Append records blob as the next operation for vaultID and returns the
	// stored Op (with its assigned Seq).
	Append(vaultID string, blob []byte) (Op, error)
	// Since returns the vault's ops with Seq strictly greater than `since`, in
	// ascending Seq order. An unknown vault yields an empty slice and nil error.
	Since(vaultID string, since uint64) ([]Op, error)
}

// MemVaultLog is a concurrency-safe, in-memory VaultLog. Each vault gets an
// append-only slice of ops; Seq is 1-based and strictly increasing per vault.
//
// It is for local/dev wiring and tests ONLY: it is NOT durable, holds
// everything in process memory, performs NO cryptography, and provides NO
// op/CRDT merge semantics beyond raw append/read.
//
// STATUS: pre-audit skeleton. In-memory, non-durable; stores opaque
// client-encrypted blobs; performs no crypto.
type MemVaultLog struct {
	mu   sync.Mutex
	logs map[string][]Op
}

// NewMemVaultLog returns an empty, ready-to-use MemVaultLog.
func NewMemVaultLog() *MemVaultLog {
	return &MemVaultLog{logs: make(map[string][]Op)}
}

// compile-time check that MemVaultLog satisfies VaultLog.
var _ VaultLog = (*MemVaultLog)(nil)

// Append stores a defensive COPY of blob as the next op for vaultID and returns
// the stored Op. Copying on the way in ensures the caller cannot mutate stored
// bytes through the original slice after the call. Seq is 1-based per vault.
func (l *MemVaultLog) Append(vaultID string, blob []byte) (Op, error) {
	cp := make([]byte, len(blob))
	copy(cp, blob)

	l.mu.Lock()
	defer l.mu.Unlock()

	seq := uint64(len(l.logs[vaultID])) + 1
	op := Op{Seq: seq, Blob: cp}
	l.logs[vaultID] = append(l.logs[vaultID], op)
	return op, nil
}

// Since returns ops for vaultID with Seq > since, ascending, each carrying a
// defensive COPY of its blob so callers cannot mutate stored bytes through the
// returned slices. An unknown vault yields an empty slice and nil error.
func (l *MemVaultLog) Since(vaultID string, since uint64) ([]Op, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	ops := l.logs[vaultID]
	out := make([]Op, 0, len(ops))
	for _, op := range ops {
		if op.Seq <= since {
			continue
		}
		cp := make([]byte, len(op.Blob))
		copy(cp, op.Blob)
		out = append(out, Op{Seq: op.Seq, Blob: cp})
	}
	return out, nil
}
