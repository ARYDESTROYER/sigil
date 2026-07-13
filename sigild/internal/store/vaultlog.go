package store

import (
	"context"
	"sync"
)

// Op is a single entry in a vault's operation log. Seq is a 1-based, strictly
// increasing sequence number assigned per vault. Blob is the client-encrypted
// operation payload: it is OPAQUE to the server, which never decrypts, parses,
// or otherwise interprets it. Hash is the tamper-evidence chain hash binding this
// op to its vault, seq, all prior ops, and blob (see chainHash in oplogchain.go).
//
// encoding/json marshals Blob ([]byte) as a base64 string automatically; API
// responses rely on that. Hash is json:"-" because encoding/json would render a
// [32]byte as a numeric array; the API layer emits it explicitly as std-base64
// (see the ops handlers).
//
// STATUS: pre-audit skeleton.
type Op struct {
	Seq  uint64   `json:"seq"`
	Blob []byte   `json:"blob"`
	Hash [32]byte `json:"-"`
}

// VaultLog is an append-only log of opaque, client-encrypted operations, keyed
// by vault ID. It is the seam the real op log will implement; the in-memory
// MemVaultLog satisfies it for dev wiring and tests.
//
// Implementations must be safe for concurrent use. Blobs are treated as opaque:
// the log applies NO encryption, encoding, decryption, or interpretation. The
// server stores exactly the bytes it was given and hands them back unchanged.
//
// Both methods take a context so a cancelled or timed-out request cancels the
// underlying work (e.g. a slow database op). Fast local backends check it at
// entry and are otherwise synchronous; a remote backend threads it into the
// driver. A cancelled ctx yields ctx.Err() promptly.
//
// STATUS: pre-audit skeleton. The production op log must add authentication, a
// durable store, and real op/CRDT merge semantics; this provides none of those.
type VaultLog interface {
	// Append records blob as the next operation for vaultID and returns the
	// stored Op (with its assigned Seq).
	Append(ctx context.Context, vaultID string, blob []byte) (Op, error)
	// Since returns the vault's ops with Seq strictly greater than `since`, in
	// ascending Seq order. An unknown vault yields an empty slice and nil error.
	// Each returned Op carries its stored chain Hash.
	Since(ctx context.Context, vaultID string, since uint64) ([]Op, error)
	// VerifyChain walks the vault's op hash chain (see oplogchain.go) and reports
	// whether it is intact. It is tamper-EVIDENT verification: it DETECTS an
	// insertion/deletion/modification of a stored op, but does not prevent one,
	// and a dishonest server can lie about the result — the trustworthy check is
	// client-side. An unknown/empty vault verifies OK with Count 0 and a genesis
	// (zero) tip. It honours ctx.
	VerifyChain(ctx context.Context, vaultID string) (VerifyResult, error)
}

// Pinger is an OPTIONAL capability a VaultLog backend may implement to expose a
// live health check to the readiness probe. A backend that depends on a remote
// resource (PostgresVaultLog -> its database) implements Ping so /readyz can
// verify that dependency is actually reachable, not merely that the process is
// up. Backends with no external dependency (MemVaultLog, FileVaultLog) do NOT
// implement it; readyz simply skips the live check for them.
type Pinger interface {
	// Ping verifies the backend's underlying dependency is reachable, honouring
	// ctx for cancellation/timeout. A nil return means healthy.
	Ping(ctx context.Context) error
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
//
// The op is fast and purely in-memory; ctx is honoured only as a cheap entry
// check so an already-cancelled request returns ctx.Err() without doing work.
func (l *MemVaultLog) Append(ctx context.Context, vaultID string, blob []byte) (Op, error) {
	if err := ctx.Err(); err != nil {
		return Op{}, err
	}

	cp := make([]byte, len(blob))
	copy(cp, blob)

	l.mu.Lock()
	defer l.mu.Unlock()

	ops := l.logs[vaultID]
	seq := uint64(len(ops)) + 1
	// Continue the chain from the previous op's hash (genesis zeros for the first).
	var prev [32]byte
	if n := len(ops); n > 0 {
		prev = ops[n-1].Hash
	}
	op := Op{Seq: seq, Blob: cp, Hash: chainHash(vaultID, seq, prev, cp)}
	l.logs[vaultID] = append(l.logs[vaultID], op)
	return op, nil
}

// Since returns ops for vaultID with Seq > since, ascending, each carrying a
// defensive COPY of its blob so callers cannot mutate stored bytes through the
// returned slices. An unknown vault yields an empty slice and nil error. ctx is
// honoured as a cheap entry check (see Append).
func (l *MemVaultLog) Since(ctx context.Context, vaultID string, since uint64) ([]Op, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

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
		out = append(out, Op{Seq: op.Seq, Blob: cp, Hash: op.Hash})
	}
	return out, nil
}

// VerifyChain walks the vault's hash chain and reports whether it is intact. It
// reads the ops through Since (which takes l.mu), so it must NOT be called while
// holding l.mu. See verifyChainVia / verifyChain for the tamper-evidence details.
func (l *MemVaultLog) VerifyChain(ctx context.Context, vaultID string) (VerifyResult, error) {
	return verifyChainVia(ctx, l, vaultID)
}
