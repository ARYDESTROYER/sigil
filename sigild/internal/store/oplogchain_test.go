package store

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// newFileLog is a small helper that builds a FileVaultLog in a temp dir.
func newFileLog(t *testing.T) *FileVaultLog {
	t.Helper()
	l, err := NewFileVaultLog(t.TempDir())
	if err != nil {
		t.Fatalf("NewFileVaultLog: %v", err)
	}
	return l
}

// TestChainHashDeterministicAndSensitive proves chainHash is a pure function of
// its inputs (same input -> same output) and that flipping ANY input — vaultID,
// seq, prevHash, or blob — changes the output. This is the whole basis of the
// tamper-evidence property.
func TestChainHashDeterministicAndSensitive(t *testing.T) {
	var zero [32]byte
	base := chainHash("v", 1, zero, []byte("blob"))

	if again := chainHash("v", 1, zero, []byte("blob")); again != base {
		t.Fatalf("chainHash not deterministic: %x vs %x", again, base)
	}
	if got := chainHash("w", 1, zero, []byte("blob")); got == base {
		t.Fatal("chainHash insensitive to vaultID")
	}
	if got := chainHash("v", 2, zero, []byte("blob")); got == base {
		t.Fatal("chainHash insensitive to seq")
	}
	var prev [32]byte
	prev[0] = 1
	if got := chainHash("v", 1, prev, []byte("blob")); got == base {
		t.Fatal("chainHash insensitive to prevHash")
	}
	if got := chainHash("v", 1, zero, []byte("bloc")); got == base {
		t.Fatal("chainHash insensitive to blob")
	}

	// Unambiguous encoding: the length-prefix on vaultID means the vault/blob
	// boundary cannot be shifted to collide. ("ab","c...") must differ from
	// ("a","bc...") even though a naive concat would be identical.
	if chainHash("ab", 1, zero, []byte("c")) == chainHash("a", 1, zero, []byte("bc")) {
		t.Fatal("chainHash boundary is ambiguous (length prefix not effective)")
	}
}

// verifyChainOKForBackend appends three ops, asserts VerifyChain reports an
// intact chain (OK, Count 3, stable TipHash across repeated verifies), and that
// the returned per-op Hash values chain correctly under chainHash.
func verifyChainOKForBackend(t *testing.T, l VaultLog) {
	t.Helper()
	ctx := t.Context()
	const vault = "chain-vault"
	blobs := [][]byte{[]byte("first"), {0x00, 0xff, 0x01}, []byte("third-op")}

	stored := make([]Op, 0, len(blobs))
	for _, b := range blobs {
		op, err := l.Append(ctx, vault, b)
		if err != nil {
			t.Fatalf("Append: %v", err)
		}
		stored = append(stored, op)
	}

	// The returned hashes chain correctly: op1 from genesis, op2 from op1, etc.
	var prev [32]byte
	for i, op := range stored {
		want := chainHash(vault, uint64(i+1), prev, blobs[i])
		if op.Hash != want {
			t.Fatalf("op%d.Hash = %x, want %x", i+1, op.Hash, want)
		}
		prev = op.Hash
	}
	// Explicit headline: op2 == chainHash(vault, 2, op1.Hash, blob2).
	if stored[1].Hash != chainHash(vault, 2, stored[0].Hash, blobs[1]) {
		t.Fatal("op2 hash does not chain onto op1 hash")
	}

	res, err := l.VerifyChain(ctx, vault)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.OK {
		t.Fatalf("VerifyChain OK = false (broken at %d), want true", res.BrokenAtSeq)
	}
	if res.Count != 3 {
		t.Fatalf("VerifyChain Count = %d, want 3", res.Count)
	}
	if res.BrokenAtSeq != 0 {
		t.Fatalf("VerifyChain BrokenAtSeq = %d, want 0 when OK", res.BrokenAtSeq)
	}
	if res.TipHash != stored[2].Hash {
		t.Fatalf("VerifyChain TipHash = %x, want last op hash %x", res.TipHash, stored[2].Hash)
	}

	// Verifying again is stable (idempotent) and yields the same tip.
	res2, err := l.VerifyChain(ctx, vault)
	if err != nil {
		t.Fatalf("VerifyChain (2nd): %v", err)
	}
	if res2 != res {
		t.Fatalf("VerifyChain not stable: %+v vs %+v", res2, res)
	}
}

func TestMemVaultLogVerifyChainOK(t *testing.T)  { verifyChainOKForBackend(t, NewMemVaultLog()) }
func TestFileVaultLogVerifyChainOK(t *testing.T) { verifyChainOKForBackend(t, newFileLog(t)) }

// TestVaultLogChainCrossBackendConsistency is the cross-backend proof: for the
// SAME (vaultID, blobs) input, MemVaultLog and FileVaultLog produce the IDENTICAL
// hash sequence and the identical VerifyChain tip. This demonstrates chainHash is
// backend-independent. (Postgres is checked against Mem in the gated
// postgresvaultlog_test.go.)
func TestVaultLogChainCrossBackendConsistency(t *testing.T) {
	ctx := t.Context()
	const vault = "x-backend"
	blobs := [][]byte{[]byte("alpha"), {0x00, 0xff}, []byte("gamma-op"), {}}

	mem := NewMemVaultLog()
	file := newFileLog(t)

	for i, b := range blobs {
		mo, err := mem.Append(ctx, vault, b)
		if err != nil {
			t.Fatalf("mem Append %d: %v", i, err)
		}
		fo, err := file.Append(ctx, vault, b)
		if err != nil {
			t.Fatalf("file Append %d: %v", i, err)
		}
		if mo.Seq != fo.Seq {
			t.Fatalf("op%d seq: mem %d vs file %d", i+1, mo.Seq, fo.Seq)
		}
		if mo.Hash != fo.Hash {
			t.Fatalf("op%d hash mismatch across backends: mem %x vs file %x", i+1, mo.Hash, fo.Hash)
		}
	}

	memRes, err := mem.VerifyChain(ctx, vault)
	if err != nil {
		t.Fatalf("mem VerifyChain: %v", err)
	}
	fileRes, err := file.VerifyChain(ctx, vault)
	if err != nil {
		t.Fatalf("file VerifyChain: %v", err)
	}
	if !memRes.OK || !fileRes.OK {
		t.Fatalf("VerifyChain not OK: mem %+v file %+v", memRes, fileRes)
	}
	if memRes.TipHash != fileRes.TipHash {
		t.Fatalf("tip hash differs across backends: mem %x vs file %x", memRes.TipHash, fileRes.TipHash)
	}
}

// TestMemVaultLogVerifyChainDetectsTamper corrupts a stored op via a white-box
// mutation of the internal slice (the API gives no way to alter a stored op) and
// confirms VerifyChain reports OK=false broken at the corrupted seq.
func TestMemVaultLogVerifyChainDetectsTamper(t *testing.T) {
	ctx := t.Context()
	const vault = "tamper"
	l := NewMemVaultLog()
	for i := 0; i < 3; i++ {
		if _, err := l.Append(ctx, vault, []byte{byte('a' + i)}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	// White-box: flip a byte of op2's stored blob, leaving its stored hash intact.
	l.logs[vault][1].Blob[0] ^= 0xff

	res, err := l.VerifyChain(ctx, vault)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.OK {
		t.Fatal("VerifyChain OK = true after tamper, want false")
	}
	if res.BrokenAtSeq != 2 {
		t.Fatalf("VerifyChain BrokenAtSeq = %d, want 2", res.BrokenAtSeq)
	}
	if res.Count != 3 {
		t.Fatalf("VerifyChain Count = %d, want 3", res.Count)
	}
}

// TestFileVaultLogVerifyChainDetectsTamper flips a byte inside op2's on-disk
// record and confirms VerifyChain (over a fresh instance re-reading the file)
// reports OK=false broken at seq 2. Fixed 4-byte blobs make the record offset
// deterministic: header || rec1 || [rec2 len prefix] then op2's first blob byte.
func TestFileVaultLogVerifyChainDetectsTamper(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	const vault = "tamper"

	l, err := NewFileVaultLog(dir)
	if err != nil {
		t.Fatalf("NewFileVaultLog: %v", err)
	}
	blobs := [][]byte{[]byte("aaaa"), []byte("bbbb"), []byte("cccc")} // all 4 bytes
	for _, b := range blobs {
		if _, err := l.Append(ctx, vault, b); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	// recSize = 4 (len) + 4 (blob) + 32 (hash); op2's blob byte 0 sits just past
	// the header, rec1, and rec2's own 4-byte length prefix.
	recSize := 4 + len(blobs[0]) + 32
	off := int64(fileHeaderLen + recSize + 4)

	path := filepath.Join(dir, base64RawURL(vault)+".log")
	corruptFileByte(t, path, off)

	// Fresh instance so nothing is served from memory: it re-reads the file.
	l2, err := NewFileVaultLog(dir)
	if err != nil {
		t.Fatalf("NewFileVaultLog #2: %v", err)
	}
	res, err := l2.VerifyChain(ctx, vault)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if res.OK {
		t.Fatal("VerifyChain OK = true after on-disk tamper, want false")
	}
	if res.BrokenAtSeq != 2 {
		t.Fatalf("VerifyChain BrokenAtSeq = %d, want 2", res.BrokenAtSeq)
	}
}

// corruptFileByte flips (XOR 0xff) the byte at off in the file at path.
func corruptFileByte(t *testing.T, path string, off int64) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open for corrupt: %v", err)
	}
	defer f.Close()
	var b [1]byte
	if _, err := f.ReadAt(b[:], off); err != nil {
		t.Fatalf("read byte at %d: %v", off, err)
	}
	b[0] ^= 0xff
	if _, err := f.WriteAt(b[:], off); err != nil {
		t.Fatalf("write byte at %d: %v", off, err)
	}
}

// TestVaultLogVerifyChainEmptyVault confirms an unknown/empty vault verifies OK
// with Count 0 and a genesis (zero) tip, on both stdlib backends.
func TestVaultLogVerifyChainEmptyVault(t *testing.T) {
	backends := map[string]VaultLog{"mem": NewMemVaultLog(), "file": newFileLog(t)}
	var zero [32]byte
	for name, l := range backends {
		res, err := l.VerifyChain(t.Context(), "never-touched")
		if err != nil {
			t.Fatalf("%s VerifyChain empty: %v", name, err)
		}
		if !res.OK || res.Count != 0 || res.BrokenAtSeq != 0 || res.TipHash != zero {
			t.Fatalf("%s VerifyChain empty = %+v, want OK count 0 genesis tip", name, res)
		}
	}
}

// TestVaultLogVerifyChainContextCancelled confirms VerifyChain honours an
// already-cancelled context (via its underlying Since) on both stdlib backends.
func TestVaultLogVerifyChainContextCancelled(t *testing.T) {
	backends := map[string]VaultLog{"mem": NewMemVaultLog(), "file": newFileLog(t)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for name, l := range backends {
		if _, err := l.VerifyChain(ctx, "v"); err != context.Canceled {
			t.Fatalf("%s VerifyChain cancelled err = %v, want context.Canceled", name, err)
		}
	}
}

// TestFileVaultLogRejectsLegacyFile confirms the v2 format bump is enforced: a
// file that lacks the v2 header (as a legacy v1 file would) is rejected with a
// clear error on both read (Since) and write (Append), rather than being
// misparsed.
func TestFileVaultLogRejectsLegacyFile(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	const vault = "legacy"

	l, err := NewFileVaultLog(dir)
	if err != nil {
		t.Fatalf("NewFileVaultLog: %v", err)
	}

	// Hand-write a "v1"-style file: length-prefixed records, NO header. Make it
	// >= header length so validation reaches the magic check (bad magic) rather
	// than a short-read, exercising the legacy-rejection path proper.
	path := filepath.Join(dir, base64RawURL(vault)+".log")
	// [4-byte len=8]["01234567"] — no magic/version up front (12 bytes).
	legacy := append([]byte{0x00, 0x00, 0x00, 0x08}, []byte("01234567")...)
	if err := os.WriteFile(path, legacy, 0o600); err != nil {
		t.Fatalf("write legacy file: %v", err)
	}

	if _, err := l.Since(ctx, vault, 0); err == nil {
		t.Fatal("Since over a headerless (v1) file returned nil error, want a clear format error")
	}
	if _, err := l.Append(ctx, vault, []byte("x")); err == nil {
		t.Fatal("Append onto a headerless (v1) file returned nil error, want a clear format error")
	}
}

// TestFileVaultLogEmptyFileTolerated confirms a zero-length vault file (as a
// crash between file-create and the header write would leave) is treated as an
// empty log, NOT a format error: Since returns nothing and Append writes the
// header + first record and continues at seq 1.
func TestFileVaultLogEmptyFileTolerated(t *testing.T) {
	ctx := t.Context()
	dir := t.TempDir()
	const vault = "empty0"

	l, err := NewFileVaultLog(dir)
	if err != nil {
		t.Fatalf("NewFileVaultLog: %v", err)
	}
	path := filepath.Join(dir, base64RawURL(vault)+".log")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("create empty file: %v", err)
	}

	ops, err := l.Since(ctx, vault, 0)
	if err != nil {
		t.Fatalf("Since over empty file: %v", err)
	}
	if len(ops) != 0 {
		t.Fatalf("Since over empty file len = %d, want 0", len(ops))
	}
	op, err := l.Append(ctx, vault, []byte("first"))
	if err != nil {
		t.Fatalf("Append over empty file: %v", err)
	}
	if op.Seq != 1 {
		t.Fatalf("first Append over empty file seq = %d, want 1", op.Seq)
	}
	// And it verifies: a fresh instance re-reads the now-headered file.
	l2, err := NewFileVaultLog(dir)
	if err != nil {
		t.Fatalf("NewFileVaultLog #2: %v", err)
	}
	res, err := l2.VerifyChain(ctx, vault)
	if err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}
	if !res.OK || res.Count != 1 {
		t.Fatalf("VerifyChain = %+v, want OK count 1", res)
	}
}
