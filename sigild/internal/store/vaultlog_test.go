package store

import (
	"bytes"
	"sync"
	"testing"
)

func TestMemVaultLogSeqIncrements(t *testing.T) {
	l := NewMemVaultLog()
	for i := uint64(1); i <= 3; i++ {
		op, err := l.Append("v1", []byte{byte(i)})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if op.Seq != i {
			t.Fatalf("Append %d seq = %d, want %d", i, op.Seq, i)
		}
	}
}

func TestMemVaultLogSeqIsPerVault(t *testing.T) {
	l := NewMemVaultLog()
	a1, _ := l.Append("a", []byte("x"))
	b1, _ := l.Append("b", []byte("y"))
	a2, _ := l.Append("a", []byte("z"))
	if a1.Seq != 1 || a2.Seq != 2 {
		t.Fatalf("vault a seqs = %d,%d, want 1,2", a1.Seq, a2.Seq)
	}
	if b1.Seq != 1 {
		t.Fatalf("vault b first seq = %d, want 1 (per-vault numbering)", b1.Seq)
	}
}

func TestMemVaultLogSinceZeroReturnsAll(t *testing.T) {
	l := NewMemVaultLog()
	for i := 0; i < 3; i++ {
		if _, err := l.Append("v1", []byte{byte(i)}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	ops, err := l.Since("v1", 0)
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

func TestMemVaultLogSinceFilters(t *testing.T) {
	l := NewMemVaultLog()
	for i := 0; i < 5; i++ {
		if _, err := l.Append("v1", []byte{byte(i)}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	ops, err := l.Since("v1", 3)
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

func TestMemVaultLogSinceUnknownVault(t *testing.T) {
	l := NewMemVaultLog()
	ops, err := l.Since("nope", 0)
	if err != nil {
		t.Fatalf("Since unknown vault err = %v, want nil", err)
	}
	if len(ops) != 0 {
		t.Fatalf("Since unknown vault len = %d, want 0", len(ops))
	}
}

// TestMemVaultLogDefensiveCopy verifies that mutating an input blob after Append
// AND mutating a returned blob both leave the stored value untouched.
func TestMemVaultLogDefensiveCopy(t *testing.T) {
	l := NewMemVaultLog()
	in := []byte("opaque")
	if _, err := l.Append("v1", in); err != nil {
		t.Fatalf("Append: %v", err)
	}
	in[0] = 'X' // mutate caller's slice after Append

	ops, err := l.Since("v1", 0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if !bytes.Equal(ops[0].Blob, []byte("opaque")) {
		t.Fatalf("stored blob mutated via input slice: %q", ops[0].Blob)
	}

	ops[0].Blob[0] = 'Y' // mutate returned slice

	again, err := l.Since("v1", 0)
	if err != nil {
		t.Fatalf("Since again: %v", err)
	}
	if !bytes.Equal(again[0].Blob, []byte("opaque")) {
		t.Fatalf("stored blob mutated via returned slice: %q", again[0].Blob)
	}
}

// TestMemVaultLogConcurrentAppends runs many goroutines appending to the same
// vault under the race detector. It asserts the total count and that every seq
// is unique and contiguous (1..N).
func TestMemVaultLogConcurrentAppends(t *testing.T) {
	l := NewMemVaultLog()
	const workers = 16
	const perWorker = 100
	const total = workers * perWorker

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				if _, err := l.Append("v1", []byte("op")); err != nil {
					t.Errorf("Append: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	ops, err := l.Since("v1", 0)
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
