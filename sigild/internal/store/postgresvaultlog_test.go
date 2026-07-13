package store

// Integration tests for PostgresVaultLog. They are GATED on SIGILD_TEST_POSTGRES
// (a libpq DSN, e.g. "postgres://user:pass@localhost:5432/sigil_test"): with it
// unset, every test here SKIPS, so `go test ./...` stays green with no database.
//
// Each test uses a UNIQUE vault-id prefix (nanosecond + counter) so parallel or
// repeated runs never collide, and a t.Cleanup deletes every row under that
// prefix. Tests are white-box (package store) so cleanup and the reconnect test
// can reach the unexported pool directly.

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var pgTestCounter atomic.Uint64

// requireDSN returns the integration DSN or skips the test if it is unset.
func requireDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("SIGILD_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("set SIGILD_TEST_POSTGRES to run the Postgres integration tests")
	}
	return dsn
}

// uniquePrefix returns a vault-id prefix unique to this test run. It contains
// only digits and hyphens, so it carries no LIKE metacharacters and is safe to
// interpolate into the cleanup DELETE ... LIKE.
func uniquePrefix() string {
	return fmt.Sprintf("itest-%d-%d-", time.Now().UnixNano(), pgTestCounter.Add(1))
}

// newTestLog opens a PostgresVaultLog (skipping without a DSN) and returns it
// with a unique vault-id prefix. A t.Cleanup deletes all rows under the prefix
// and closes the pool.
func newTestLog(t *testing.T) (*PostgresVaultLog, string) {
	t.Helper()
	dsn := requireDSN(t)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	l, err := NewPostgresVaultLog(ctx, dsn)
	if err != nil {
		t.Fatalf("NewPostgresVaultLog: %v", err)
	}

	prefix := uniquePrefix()
	t.Cleanup(func() {
		cleanup(t, l, prefix)
		l.Close()
	})
	return l, prefix
}

// cleanup deletes every op row whose vault_id begins with prefix.
func cleanup(t *testing.T, l *PostgresVaultLog, prefix string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := l.pool.Exec(ctx, `DELETE FROM sigil_vault_ops WHERE vault_id LIKE $1`, prefix+"%"); err != nil {
		t.Errorf("cleanup delete: %v", err)
	}
}

func TestPostgresVaultLogSeqIncrements(t *testing.T) {
	ctx := context.Background()
	l, prefix := newTestLog(t)
	vault := prefix + "v"
	for i := uint64(1); i <= 3; i++ {
		op, err := l.Append(ctx, vault, []byte{byte(i)})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if op.Seq != i {
			t.Fatalf("Append %d seq = %d, want %d", i, op.Seq, i)
		}
	}
}

func TestPostgresVaultLogSeqIsPerVault(t *testing.T) {
	ctx := context.Background()
	l, prefix := newTestLog(t)
	a, b := prefix+"a", prefix+"b"
	a1, _ := l.Append(ctx, a, []byte("x"))
	b1, _ := l.Append(ctx, b, []byte("y"))
	a2, _ := l.Append(ctx, a, []byte("z"))
	if a1.Seq != 1 || a2.Seq != 2 {
		t.Fatalf("vault a seqs = %d,%d, want 1,2", a1.Seq, a2.Seq)
	}
	if b1.Seq != 1 {
		t.Fatalf("vault b first seq = %d, want 1 (per-vault numbering)", b1.Seq)
	}
}

func TestPostgresVaultLogSinceZeroReturnsAll(t *testing.T) {
	ctx := context.Background()
	l, prefix := newTestLog(t)
	vault := prefix + "v"
	for i := 0; i < 3; i++ {
		if _, err := l.Append(ctx, vault, []byte{byte(i)}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	ops, err := l.Since(ctx, vault, 0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(ops) != 3 {
		t.Fatalf("Since(0) len = %d, want 3", len(ops))
	}
	for i, op := range ops {
		if op.Seq != uint64(i+1) {
			t.Fatalf("ops[%d].Seq = %d, want %d (ascending)", i, op.Seq, i+1)
		}
	}
}

func TestPostgresVaultLogSinceFilters(t *testing.T) {
	ctx := context.Background()
	l, prefix := newTestLog(t)
	vault := prefix + "v"
	for i := 0; i < 5; i++ {
		if _, err := l.Append(ctx, vault, []byte{byte(i)}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	ops, err := l.Since(ctx, vault, 3)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("Since(3) len = %d, want 2", len(ops))
	}
	if ops[0].Seq != 4 || ops[1].Seq != 5 {
		t.Fatalf("Since(3) seqs = %d,%d, want 4,5", ops[0].Seq, ops[1].Seq)
	}
}

func TestPostgresVaultLogSinceUnknownVault(t *testing.T) {
	l, prefix := newTestLog(t)
	ops, err := l.Since(context.Background(), prefix+"nope", 0)
	if err != nil {
		t.Fatalf("Since unknown vault err = %v, want nil", err)
	}
	if len(ops) != 0 {
		t.Fatalf("Since unknown vault len = %d, want 0", len(ops))
	}
}

// TestPostgresVaultLogDefensiveCopy verifies mutating an input blob after Append
// AND mutating a returned blob both leave the stored value untouched.
func TestPostgresVaultLogDefensiveCopy(t *testing.T) {
	ctx := context.Background()
	l, prefix := newTestLog(t)
	vault := prefix + "v"

	in := []byte("opaque")
	if _, err := l.Append(ctx, vault, in); err != nil {
		t.Fatalf("Append: %v", err)
	}
	in[0] = 'X' // mutate caller's slice after Append

	ops, err := l.Since(ctx, vault, 0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if !bytes.Equal(ops[0].Blob, []byte("opaque")) {
		t.Fatalf("stored blob mutated via input slice: %q", ops[0].Blob)
	}

	ops[0].Blob[0] = 'Y' // mutate returned slice

	again, err := l.Since(ctx, vault, 0)
	if err != nil {
		t.Fatalf("Since again: %v", err)
	}
	if !bytes.Equal(again[0].Blob, []byte("opaque")) {
		t.Fatalf("stored blob mutated via returned slice: %q", again[0].Blob)
	}
}

// TestPostgresVaultLogOpaqueBinaryIntegrity round-trips a blob containing NUL,
// 0xff and other binary bytes, byte-for-byte, through the bytea column.
func TestPostgresVaultLogOpaqueBinaryIntegrity(t *testing.T) {
	ctx := context.Background()
	l, prefix := newTestLog(t)
	vault := prefix + "bin"
	blob := []byte{0x00, 0xff, 0x10, 0x00, 0x7f, 0x80, 0x01, 0xfe}

	if _, err := l.Append(ctx, vault, blob); err != nil {
		t.Fatalf("Append: %v", err)
	}
	ops, err := l.Since(ctx, vault, 0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(ops) != 1 {
		t.Fatalf("len = %d, want 1", len(ops))
	}
	if !bytes.Equal(ops[0].Blob, blob) {
		t.Fatalf("binary blob mangled: got %v, want %v", ops[0].Blob, blob)
	}
}

// TestPostgresVaultLogConcurrentAppends appends from many goroutines to the SAME
// vault and asserts a unique, contiguous 1..N seq set. This exercises the
// advisory-lock + MAX(seq)+1 mechanism under contention. Run under -race.
func TestPostgresVaultLogConcurrentAppends(t *testing.T) {
	ctx := context.Background()
	l, prefix := newTestLog(t)
	vault := prefix + "v"

	const workers = 16
	const perWorker = 25
	const total = workers * perWorker

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				if _, err := l.Append(ctx, vault, []byte("op")); err != nil {
					t.Errorf("Append: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	ops, err := l.Since(ctx, vault, 0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(ops) != total {
		t.Fatalf("total ops = %d, want %d", len(ops), total)
	}
	seen := make(map[uint64]bool, total)
	for _, op := range ops {
		if op.Seq < 1 || op.Seq > total {
			t.Fatalf("seq %d out of range 1..%d", op.Seq, total)
		}
		if seen[op.Seq] {
			t.Fatalf("duplicate seq %d", op.Seq)
		}
		seen[op.Seq] = true
	}
	if len(seen) != total {
		t.Fatalf("unique seqs = %d, want %d (contiguous 1..N)", len(seen), total)
	}
}

// TestPostgresVaultLogDurabilityAcrossReconnect is the core durability test: a
// SECOND PostgresVaultLog over the same DSN (simulated restart, fresh pool) must
// read the prior ops byte-identically and continue numbering at seq 4.
func TestPostgresVaultLogDurabilityAcrossReconnect(t *testing.T) {
	dsn := requireDSN(t)
	opCtx := context.Background()
	prefix := uniquePrefix()
	vault := prefix + "v"

	blobs := [][]byte{[]byte("first"), []byte("second"), []byte("third")}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	l1, err := NewPostgresVaultLog(ctx, dsn)
	cancel()
	if err != nil {
		t.Fatalf("NewPostgresVaultLog #1: %v", err)
	}
	for i, b := range blobs {
		op, err := l1.Append(opCtx, vault, b)
		if err != nil {
			l1.Close()
			t.Fatalf("Append %d: %v", i, err)
		}
		if op.Seq != uint64(i+1) {
			l1.Close()
			t.Fatalf("Append %d seq = %d, want %d", i, op.Seq, i+1)
		}
	}
	// Drop the first pool entirely, then reconnect with a brand-new one.
	l1.Close()

	ctx2, cancel2 := context.WithTimeout(context.Background(), 15*time.Second)
	l2, err := NewPostgresVaultLog(ctx2, dsn)
	cancel2()
	if err != nil {
		t.Fatalf("NewPostgresVaultLog #2 (reconnect): %v", err)
	}
	t.Cleanup(func() {
		cleanup(t, l2, prefix)
		l2.Close()
	})

	ops, err := l2.Since(opCtx, vault, 0)
	if err != nil {
		t.Fatalf("Since after reconnect: %v", err)
	}
	if len(ops) != 3 {
		t.Fatalf("after reconnect Since(0) len = %d, want 3", len(ops))
	}
	for i, op := range ops {
		if op.Seq != uint64(i+1) {
			t.Fatalf("after reconnect ops[%d].Seq = %d, want %d", i, op.Seq, i+1)
		}
		if !bytes.Equal(op.Blob, blobs[i]) {
			t.Fatalf("after reconnect ops[%d].Blob = %q, want %q", i, op.Blob, blobs[i])
		}
	}

	// A 4th append must continue at seq 4 (derived from the durable MAX(seq)).
	op4, err := l2.Append(opCtx, vault, []byte("fourth"))
	if err != nil {
		t.Fatalf("Append #4 after reconnect: %v", err)
	}
	if op4.Seq != 4 {
		t.Fatalf("4th append seq = %d, want 4 (seq derived from durable state)", op4.Seq)
	}
}

// TestPostgresVaultLogVerifyChainOK appends three ops and confirms VerifyChain
// reports an intact chain (OK, Count 3, tip == last stored hash), and that the
// stored hashes chain correctly under chainHash.
func TestPostgresVaultLogVerifyChainOK(t *testing.T) {
	ctx := context.Background()
	l, prefix := newTestLog(t)
	vault := prefix + "v"

	blobs := [][]byte{[]byte("first"), {0x00, 0xff, 0x01}, []byte("third-op")}
	var prev [32]byte
	var last [32]byte
	for i, b := range blobs {
		op, err := l.Append(ctx, vault, b)
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if want := chainHash(vault, uint64(i+1), prev, b); op.Hash != want {
			t.Fatalf("op%d.Hash = %x, want %x", i+1, op.Hash, want)
		}
		prev = op.Hash
		last = op.Hash
	}

	res, err := l.VerifyChain(ctx, vault)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.OK || res.Count != 3 || res.BrokenAtSeq != 0 || res.TipHash != last {
		t.Fatalf("VerifyChain = %+v, want OK count 3 tip %x", res, last)
	}
}

// TestPostgresVaultLogVerifyChainDetectsTamper directly corrupts a stored row's
// hash column and confirms VerifyChain reports OK=false broken at that seq.
func TestPostgresVaultLogVerifyChainDetectsTamper(t *testing.T) {
	ctx := context.Background()
	l, prefix := newTestLog(t)
	vault := prefix + "v"

	for i := 0; i < 3; i++ {
		if _, err := l.Append(ctx, vault, []byte{byte('a' + i)}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	// Overwrite op2's stored hash with 32 zero bytes, directly in the DB.
	if _, err := l.pool.Exec(ctx,
		`UPDATE sigil_vault_ops SET hash = $1 WHERE vault_id = $2 AND seq = 2`,
		make([]byte, 32), vault); err != nil {
		t.Fatalf("tamper UPDATE: %v", err)
	}

	res, err := l.VerifyChain(ctx, vault)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.OK {
		t.Fatal("VerifyChain OK = true after DB tamper, want false")
	}
	if res.BrokenAtSeq != 2 {
		t.Fatalf("VerifyChain BrokenAtSeq = %d, want 2", res.BrokenAtSeq)
	}
	if res.Count != 3 {
		t.Fatalf("VerifyChain Count = %d, want 3", res.Count)
	}
}

// TestPostgresVaultLogChainMatchesMem is the cross-backend consistency proof
// including Postgres: for the SAME (vaultID, blobs) input, Postgres and
// MemVaultLog produce the IDENTICAL per-op hash sequence and the identical
// VerifyChain tip — demonstrating chainHash is backend-independent.
func TestPostgresVaultLogChainMatchesMem(t *testing.T) {
	ctx := context.Background()
	l, prefix := newTestLog(t)
	vault := prefix + "v"

	blobs := [][]byte{[]byte("alpha"), {0x00, 0xff}, []byte("gamma-op"), {}}
	mem := NewMemVaultLog()
	for i, b := range blobs {
		po, err := l.Append(ctx, vault, b)
		if err != nil {
			t.Fatalf("pg Append %d: %v", i, err)
		}
		mo, err := mem.Append(ctx, vault, b)
		if err != nil {
			t.Fatalf("mem Append %d: %v", i, err)
		}
		if po.Hash != mo.Hash {
			t.Fatalf("op%d hash mismatch: postgres %x vs mem %x", i+1, po.Hash, mo.Hash)
		}
	}

	pgRes, err := l.VerifyChain(ctx, vault)
	if err != nil {
		t.Fatalf("pg VerifyChain: %v", err)
	}
	memRes, err := mem.VerifyChain(ctx, vault)
	if err != nil {
		t.Fatalf("mem VerifyChain: %v", err)
	}
	if pgRes.TipHash != memRes.TipHash {
		t.Fatalf("tip hash differs: postgres %x vs mem %x", pgRes.TipHash, memRes.TipHash)
	}
}

// TestPostgresVaultLogContextCancelled verifies request-context propagation into
// the driver: a cancelled context passed to Append/Since cancels the DB work and
// returns promptly with a non-nil error (rather than running the query).
func TestPostgresVaultLogContextCancelled(t *testing.T) {
	l, prefix := newTestLog(t)
	vault := prefix + "v"

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := l.Append(ctx, vault, []byte("op")); err == nil {
		t.Fatal("Append with cancelled ctx returned nil error, want cancellation error")
	}
	if _, err := l.Since(ctx, vault, 0); err == nil {
		t.Fatal("Since with cancelled ctx returned nil error, want cancellation error")
	}

	// Sanity: with a live context the same log still works (nothing was persisted
	// by the cancelled calls).
	ops, err := l.Since(context.Background(), vault, 0)
	if err != nil {
		t.Fatalf("Since after cancelled calls: %v", err)
	}
	if len(ops) != 0 {
		t.Fatalf("cancelled Append persisted an op: len = %d, want 0", len(ops))
	}
}
