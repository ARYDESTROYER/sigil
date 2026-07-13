package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// base64RawURL mirrors the production safe-filename encoding so a test can find
// a specific vault's on-disk file by id.
func base64RawURL(vaultID string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(vaultID))
}

func TestFileVaultLogSeqIncrements(t *testing.T) {
	ctx := t.Context()
	l, err := NewFileVaultLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileVaultLog: %v", err)
	}
	for i := uint64(1); i <= 3; i++ {
		op, err := l.Append(ctx, "v1", []byte{byte(i)})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if op.Seq != i {
			t.Fatalf("Append %d seq = %d, want %d", i, op.Seq, i)
		}
	}
}

func TestFileVaultLogSeqIsPerVault(t *testing.T) {
	ctx := t.Context()
	l, err := NewFileVaultLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileVaultLog: %v", err)
	}
	a1, _ := l.Append(ctx, "a", []byte("x"))
	b1, _ := l.Append(ctx, "b", []byte("y"))
	a2, _ := l.Append(ctx, "a", []byte("z"))
	if a1.Seq != 1 || a2.Seq != 2 {
		t.Fatalf("vault a seqs = %d,%d, want 1,2", a1.Seq, a2.Seq)
	}
	if b1.Seq != 1 {
		t.Fatalf("vault b first seq = %d, want 1 (per-vault numbering)", b1.Seq)
	}
}

func TestFileVaultLogSinceZeroReturnsAll(t *testing.T) {
	ctx := t.Context()
	l, err := NewFileVaultLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileVaultLog: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := l.Append(ctx, "v1", []byte{byte(i)}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	ops, err := l.Since(ctx, "v1", 0)
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

func TestFileVaultLogSinceFilters(t *testing.T) {
	ctx := t.Context()
	l, err := NewFileVaultLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileVaultLog: %v", err)
	}
	for i := 0; i < 5; i++ {
		if _, err := l.Append(ctx, "v1", []byte{byte(i)}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	ops, err := l.Since(ctx, "v1", 3)
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

func TestFileVaultLogSinceUnknownVault(t *testing.T) {
	l, err := NewFileVaultLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileVaultLog: %v", err)
	}
	ops, err := l.Since(t.Context(), "nope", 0)
	if err != nil {
		t.Fatalf("Since unknown vault err = %v, want nil", err)
	}
	if len(ops) != 0 {
		t.Fatalf("Since unknown vault len = %d, want 0", len(ops))
	}
}

// TestFileVaultLogDurabilityAcrossRestart is the core durability test: a NEW
// FileVaultLog over the same dir (simulated restart) must re-derive seqs from
// disk, return prior ops byte-identically, and continue numbering at seq 4.
func TestFileVaultLogDurabilityAcrossRestart(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()

	blobs := [][]byte{[]byte("first"), []byte("second"), []byte("third")}

	l1, err := NewFileVaultLog(dir)
	if err != nil {
		t.Fatalf("NewFileVaultLog #1: %v", err)
	}
	for i, b := range blobs {
		op, err := l1.Append(ctx, "v", b)
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		if op.Seq != uint64(i+1) {
			t.Fatalf("Append %d seq = %d, want %d", i, op.Seq, i+1)
		}
	}

	// Simulated restart: brand-new instance over the same directory.
	l2, err := NewFileVaultLog(dir)
	if err != nil {
		t.Fatalf("NewFileVaultLog #2 (restart): %v", err)
	}

	ops, err := l2.Since(ctx, "v", 0)
	if err != nil {
		t.Fatalf("Since after restart: %v", err)
	}
	if len(ops) != 3 {
		t.Fatalf("after restart Since(0) len = %d, want 3", len(ops))
	}
	for i, op := range ops {
		if op.Seq != uint64(i+1) {
			t.Fatalf("after restart ops[%d].Seq = %d, want %d", i, op.Seq, i+1)
		}
		if !bytes.Equal(op.Blob, blobs[i]) {
			t.Fatalf("after restart ops[%d].Blob = %q, want %q", i, op.Blob, blobs[i])
		}
	}

	// A 4th append must continue at seq 4 (counter re-derived from disk).
	op4, err := l2.Append(ctx, "v", []byte("fourth"))
	if err != nil {
		t.Fatalf("Append #4 after restart: %v", err)
	}
	if op4.Seq != 4 {
		t.Fatalf("4th append seq = %d, want 4 (counter re-derived from disk)", op4.Seq)
	}
}

// TestFileVaultLogPathTraversalSafety asserts that hostile vaultIDs cannot write
// outside the base dir, yet remain retrievable under their exact id string.
func TestFileVaultLogPathTraversalSafety(t *testing.T) {
	ctx := t.Context()
	base := t.TempDir()
	// Put the log in a subdir so we can scan the PARENT for any escapees.
	dir := filepath.Join(base, "oplog")

	l, err := NewFileVaultLog(dir)
	if err != nil {
		t.Fatalf("NewFileVaultLog: %v", err)
	}

	hostile := []string{"../escape", "a/b/c", "..", "../../etc/passwd"}
	for i, id := range hostile {
		blob := []byte{byte(i), 0xAA}
		if _, err := l.Append(ctx, id, blob); err != nil {
			t.Fatalf("Append(%q): %v", id, err)
		}
	}

	// (a) No file may exist anywhere under `base` except inside `dir`. Walk the
	// whole base tree; every regular file must live under dir.
	err = filepath.Walk(base, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			return rerr
		}
		// A file inside dir has a rel path that does not start with "..".
		if rel == ".." || filepath.IsAbs(rel) || (len(rel) >= 2 && rel[:2] == "..") {
			t.Fatalf("file escaped base dir: %q (rel to oplog dir: %q)", path, rel)
		}
		// Also ensure it is a flat file directly under dir (no nested subdirs
		// created by an "a/b/c"-style id).
		if filepath.Dir(path) != dir {
			t.Fatalf("file not flat under oplog dir: %q", path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}

	// (b) Each hostile id's data is retrievable under the SAME id string.
	for i, id := range hostile {
		ops, err := l.Since(ctx, id, 0)
		if err != nil {
			t.Fatalf("Since(%q): %v", id, err)
		}
		if len(ops) != 1 {
			t.Fatalf("Since(%q) len = %d, want 1", id, len(ops))
		}
		want := []byte{byte(i), 0xAA}
		if !bytes.Equal(ops[0].Blob, want) {
			t.Fatalf("Since(%q) blob = %v, want %v", id, ops[0].Blob, want)
		}
	}
}

// TestFileVaultLogOpaqueBinaryIntegrity round-trips a blob with NUL, 0xff and
// other binary bytes through a simulated restart, byte-for-byte.
func TestFileVaultLogOpaqueBinaryIntegrity(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	blob := []byte{0x00, 0xff, 0x10, 0x00, 0x7f, 0x80, 0x01, 0xfe}

	l1, err := NewFileVaultLog(dir)
	if err != nil {
		t.Fatalf("NewFileVaultLog #1: %v", err)
	}
	if _, err := l1.Append(ctx, "bin", blob); err != nil {
		t.Fatalf("Append: %v", err)
	}

	l2, err := NewFileVaultLog(dir) // restart
	if err != nil {
		t.Fatalf("NewFileVaultLog #2: %v", err)
	}
	ops, err := l2.Since(ctx, "bin", 0)
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

// TestFileVaultLogContextCancelled verifies the cheap entry check: an
// already-cancelled context makes Append and Since return ctx.Err() promptly and
// Append writes nothing to disk.
func TestFileVaultLogContextCancelled(t *testing.T) {
	dir := t.TempDir()
	l, err := NewFileVaultLog(dir)
	if err != nil {
		t.Fatalf("NewFileVaultLog: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := l.Append(ctx, "v1", []byte("op")); err != context.Canceled {
		t.Fatalf("Append with cancelled ctx err = %v, want context.Canceled", err)
	}
	if _, err := l.Since(ctx, "v1", 0); err != context.Canceled {
		t.Fatalf("Since with cancelled ctx err = %v, want context.Canceled", err)
	}
	// The cancelled Append must not have created/written a file: a fresh live
	// read is empty.
	ops, err := l.Since(context.Background(), "v1", 0)
	if err != nil {
		t.Fatalf("Since after cancelled Append: %v", err)
	}
	if len(ops) != 0 {
		t.Fatalf("cancelled Append still stored an op: len = %d, want 0", len(ops))
	}
}

// TestFileVaultLogConcurrentAppends appends from many goroutines and asserts a
// unique, contiguous 1..N seq set. Run under -race.
func TestFileVaultLogConcurrentAppends(t *testing.T) {
	ctx := t.Context()
	l, err := NewFileVaultLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileVaultLog: %v", err)
	}
	const workers = 16
	const perWorker = 50
	const total = workers * perWorker

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func() {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				if _, err := l.Append(ctx, "v1", []byte("op")); err != nil {
					t.Errorf("Append: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()

	ops, err := l.Since(ctx, "v1", 0)
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

// TestFileVaultLogDefensiveCopy verifies mutating an input blob after Append AND
// mutating a returned blob both leave the stored value untouched.
func TestFileVaultLogDefensiveCopy(t *testing.T) {
	ctx := t.Context()
	l, err := NewFileVaultLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileVaultLog: %v", err)
	}
	in := []byte("opaque")
	if _, err := l.Append(ctx, "v1", in); err != nil {
		t.Fatalf("Append: %v", err)
	}
	in[0] = 'X' // mutate caller's slice after Append

	ops, err := l.Since(ctx, "v1", 0)
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if !bytes.Equal(ops[0].Blob, []byte("opaque")) {
		t.Fatalf("stored blob mutated via input slice: %q", ops[0].Blob)
	}

	ops[0].Blob[0] = 'Y' // mutate returned slice

	again, err := l.Since(ctx, "v1", 0)
	if err != nil {
		t.Fatalf("Since again: %v", err)
	}
	if !bytes.Equal(again[0].Blob, []byte("opaque")) {
		t.Fatalf("stored blob mutated via returned slice: %q", again[0].Blob)
	}
}

// TestFileVaultLogTruncatedTrailingRecordIgnored writes two valid records then a
// deliberately truncated third record (length prefix promising more bytes than
// follow), as a crash mid-write would leave. Since must return the two complete
// records without error or panic, and Append must continue at seq 3.
func TestFileVaultLogTruncatedTrailingRecordIgnored(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	l, err := NewFileVaultLog(dir)
	if err != nil {
		t.Fatalf("NewFileVaultLog: %v", err)
	}
	if _, err := l.Append(ctx, "v", []byte("aa")); err != nil {
		t.Fatalf("Append 1: %v", err)
	}
	if _, err := l.Append(ctx, "v", []byte("bb")); err != nil {
		t.Fatalf("Append 2: %v", err)
	}

	// Append a partial record by hand: a 4-byte length prefix claiming 10 bytes
	// but only 3 bytes of blob follow (a torn write).
	path := filepath.Join(dir, base64RawURL("v")+".log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open for torn write: %v", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], 10)
	if _, err := f.Write(lenBuf[:]); err != nil {
		t.Fatalf("write torn len: %v", err)
	}
	if _, err := f.Write([]byte{0x01, 0x02, 0x03}); err != nil {
		t.Fatalf("write torn blob: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close torn: %v", err)
	}

	// Fresh instance (restart) so the counter is rebuilt from the torn file.
	l2, err := NewFileVaultLog(dir)
	if err != nil {
		t.Fatalf("NewFileVaultLog #2: %v", err)
	}
	ops, err := l2.Since(ctx, "v", 0)
	if err != nil {
		t.Fatalf("Since over torn file: %v", err)
	}
	if len(ops) != 2 {
		t.Fatalf("Since over torn file len = %d, want 2 (trailing torn record ignored)", len(ops))
	}
	if !bytes.Equal(ops[0].Blob, []byte("aa")) || !bytes.Equal(ops[1].Blob, []byte("bb")) {
		t.Fatalf("torn-file ops = %q,%q, want aa,bb", ops[0].Blob, ops[1].Blob)
	}

	// Next append must continue at seq 3, overwriting nothing (append-only).
	op3, err := l2.Append(ctx, "v", []byte("cc"))
	if err != nil {
		t.Fatalf("Append after torn: %v", err)
	}
	if op3.Seq != 3 {
		t.Fatalf("append after torn seq = %d, want 3", op3.Seq)
	}
}
