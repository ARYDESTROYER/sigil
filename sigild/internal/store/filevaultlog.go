package store

// FileVaultLog is an OPTIONAL, LOCAL-DEV durable VaultLog backed by per-vault
// append-only files under a base directory. It exists to prove the VaultLog
// seam supports multiple backends and to let the DEV op-log survive a restart;
// the in-memory MemVaultLog remains the default.
//
// IT IS NOT THE PRODUCTION STORE. Production persistence is PostgreSQL + S3 +
// Redis (see doc.go). This backend has no authentication, no replication, no
// fsync-on-rename atomicity guarantees beyond a per-record fsync, and no real
// op/CRDT merge semantics — it is a raw append/read file log.
//
// Like every VaultLog it is OPAQUE: blobs are stored and returned byte-for-byte
// and are never decrypted, parsed, or otherwise interpreted. It performs NO
// cryptography.
//
// STATUS: pre-audit skeleton. LOCAL-DEV durable backend only; stores opaque
// client-encrypted blobs; no crypto; UNAUTHENTICATED / dev-only.

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// On-disk format v2 (this file). Each vault file begins with a fixed HEADER, then
// a sequence of records:
//
//	HEADER : "SIGILflog" (9 bytes) || version byte (0x02)          = 10 bytes
//	RECORD : [4-byte big-endian uint32 blob-len][blob][32-byte hash]
//
// The 32-byte hash is the op's tamper-evidence chain hash (see chainHash). The
// header lets us reject a legacy v1 file (records with no hash), which predates
// the chain. This is a DEV backend with no real data, so a hard format bump —
// v1 files are unsupported and yield a clear error — is acceptable.
const (
	fileMagic         = "SIGILflog"
	fileFormatVersion = 2
	fileHeaderLen     = len(fileMagic) + 1 // magic + 1 version byte
)

// fileHeader is the exact 10-byte header written when a vault file is created.
var fileHeader = append([]byte(fileMagic), fileFormatVersion)

// FileVaultLog persists each vault's ops to its own append-only file under dir.
//
// Seq is implicit: it is the 1-based position of the record within the file.
// The first record is Seq 1, the second Seq 2, and so on. The in-memory `seqs`
// map caches the current max seq per vault so Append need not rescan; `tips`
// caches the last stored hash per vault so Append can continue the chain without
// re-reading. Both are rebuilt lazily by scanning the on-disk file the first time
// a vault is touched, which re-derives correct seqs (and the chain tip) after a
// restart.
type FileVaultLog struct {
	dir string

	mu sync.Mutex
	// seqs caches the current max seq per vault. A vault absent from the map has
	// not been loaded yet; its counter is rebuilt from disk on first touch.
	seqs map[string]uint64
	// tips caches the last stored chain hash per vault (genesis zeros when the
	// vault has no ops), so Append can chain onto it. Rebuilt from disk with seqs.
	tips   map[string][32]byte
	loaded map[string]bool
}

// compile-time check that FileVaultLog satisfies VaultLog.
var _ VaultLog = (*FileVaultLog)(nil)

// NewFileVaultLog creates (if needed) the base dir with 0o700 perms and returns
// a ready-to-use FileVaultLog. Per-vault counters are rebuilt lazily on first
// touch, so construction does not scan the whole directory.
func NewFileVaultLog(dir string) (*FileVaultLog, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &FileVaultLog{
		dir:    dir,
		seqs:   make(map[string]uint64),
		tips:   make(map[string][32]byte),
		loaded: make(map[string]bool),
	}, nil
}

// pathFor maps an untrusted vaultID to a safe, flat filename inside dir.
//
// SECURITY: vaultID arrives from the untrusted HTTP path. We base64url-encode
// the raw vaultID bytes (RawURLEncoding: no '/', no '+', no '=' padding) and
// append ".log". The result therefore contains NO path separators and NO ".."
// sequences, so filepath.Join can never escape dir — a vaultID like
// "../../etc/passwd", "a/b/c", or ".." all map to ordinary flat filenames that
// live directly under dir. The encoding is reversible, so distinct vaultIDs map
// to distinct files and never collide.
func (l *FileVaultLog) pathFor(vaultID string) string {
	name := base64.RawURLEncoding.EncodeToString([]byte(vaultID)) + ".log"
	return filepath.Join(l.dir, name)
}

// ensureLoaded rebuilds the cached seq counter AND chain tip for vaultID from
// disk if it has not been loaded yet. Caller must hold l.mu.
func (l *FileVaultLog) ensureLoaded(vaultID string) error {
	if l.loaded[vaultID] {
		return nil
	}
	n, tip, err := scanFile(l.pathFor(vaultID))
	if err != nil {
		return err
	}
	l.seqs[vaultID] = n
	l.tips[vaultID] = tip
	l.loaded[vaultID] = true
	return nil
}

// scanFile validates the header (for an existing file) and walks every complete
// record, returning the record count and the LAST record's stored hash (the chain
// tip; genesis zeros when there are no records). A missing file yields (0, zero,
// nil). A file with a missing/incorrect header — e.g. a legacy v1 file — yields a
// clear error. A truncated trailing record (crash mid-write) is ignored.
func scanFile(path string) (uint64, [32]byte, error) {
	var tip [32]byte
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, tip, nil
		}
		return 0, tip, err
	}
	defer f.Close()

	r := bufio.NewReader(f)
	empty, err := readHeader(r)
	if err != nil {
		return 0, tip, err
	}
	if empty {
		return 0, tip, nil
	}
	var n uint64
	for {
		_, hash, ok, err := readRecord(r)
		if err != nil {
			return 0, tip, err
		}
		if !ok {
			// Clean EOF or a truncated trailing record: stop.
			return n, tip, nil
		}
		n++
		tip = hash
	}
}

// readHeader reads and validates the fixed v2 file header from r.
//
// It reports empty=true for a ZERO-length stream — a valid empty log (a file that
// was created but not yet written, e.g. a crash between create and the header
// write). Callers treat that like a missing file, not an error. A NON-empty
// stream must carry a valid header: a wrong magic (e.g. a legacy v1 file, which
// had no header) or an unsupported version yields a clear error.
func readHeader(r *bufio.Reader) (empty bool, err error) {
	if _, perr := r.Peek(1); errors.Is(perr, io.EOF) {
		return true, nil
	}
	var hdr [fileHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return false, fmt.Errorf("op-log file: read header: %w", err)
	}
	if string(hdr[:len(fileMagic)]) != fileMagic {
		return false, fmt.Errorf("op-log file: bad magic %q (a legacy v1 file predates the hash chain and is unsupported; expected a v%d file)",
			hdr[:len(fileMagic)], fileFormatVersion)
	}
	if v := hdr[len(fileMagic)]; v != fileFormatVersion {
		return false, fmt.Errorf("op-log file: unsupported format version %d (want %d)", v, fileFormatVersion)
	}
	return false, nil
}

// readRecord reads one framed record ([4-byte len][blob][32-byte hash]) from r.
// It returns (blob, hash, true, nil) for a complete record, (nil, zero, false,
// nil) at a clean EOF or when the trailing record is truncated (a partial length
// prefix, a short blob, or a short hash), and a non-nil error only for genuine
// I/O failures. Treating truncation as a clean stop makes a crash mid-Append
// recoverable: the partial last record is simply ignored.
func readRecord(r *bufio.Reader) ([]byte, [32]byte, bool, error) {
	var hash [32]byte

	var lenBuf [4]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// Clean EOF (no more records) or a partial length prefix: ignore.
			return nil, hash, false, nil
		}
		return nil, hash, false, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	blob := make([]byte, n)
	if _, err := io.ReadFull(r, blob); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// Length prefix promised more bytes than exist: truncated trailing
			// record from a crash mid-write — ignore it.
			return nil, hash, false, nil
		}
		return nil, hash, false, err
	}
	if _, err := io.ReadFull(r, hash[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// Blob written but the trailing hash was torn off mid-write: ignore.
			return nil, hash, false, nil
		}
		return nil, hash, false, err
	}
	return blob, hash, true, nil
}

// Append durably records a defensive COPY of blob as the next op for vaultID and
// returns the stored Op. It writes one framed record and fsyncs before
// returning. Seq is 1-based per vault and is derived from the cached counter
// (which is rebuilt from disk on first touch, so it is correct after a restart).
//
// The write is local and synchronous; ctx is honoured as a cheap entry check so
// an already-cancelled request returns ctx.Err() before touching the disk.
func (l *FileVaultLog) Append(ctx context.Context, vaultID string, blob []byte) (Op, error) {
	if err := ctx.Err(); err != nil {
		return Op{}, err
	}

	cp := make([]byte, len(blob))
	copy(cp, blob)

	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.ensureLoaded(vaultID); err != nil {
		return Op{}, err
	}

	f, err := os.OpenFile(l.pathFor(vaultID), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return Op{}, err
	}
	// Best-effort close on every path; the durability barrier is the explicit
	// fsync below, which we check.
	defer f.Close()

	// A brand-new (zero-length) file needs its header before the first record.
	// ensureLoaded has already rejected any pre-existing file with a bad header,
	// so a non-empty file here is guaranteed to be a valid v2 file.
	if info, err := f.Stat(); err != nil {
		return Op{}, err
	} else if info.Size() == 0 {
		if _, err := f.Write(fileHeader); err != nil {
			return Op{}, err
		}
	}

	seq := l.seqs[vaultID] + 1
	hash := chainHash(vaultID, seq, l.tips[vaultID], cp)

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(cp)))
	if _, err := f.Write(lenBuf[:]); err != nil {
		return Op{}, err
	}
	if _, err := f.Write(cp); err != nil {
		return Op{}, err
	}
	if _, err := f.Write(hash[:]); err != nil {
		return Op{}, err
	}
	if err := f.Sync(); err != nil {
		return Op{}, err
	}

	// Commit the in-memory counters only after the record is durably on disk.
	l.seqs[vaultID] = seq
	l.tips[vaultID] = hash
	return Op{Seq: seq, Blob: cp, Hash: hash}, nil
}

// Since returns the vault's ops with Seq strictly greater than `since`, in
// ascending Seq order, each carrying a defensive COPY of its blob. A missing
// file (unknown vault) yields an empty slice and nil error. A truncated trailing
// record is skipped gracefully (no error, no panic). ctx is honoured as a cheap
// entry check (see Append).
func (l *FileVaultLog) Since(ctx context.Context, vaultID string, since uint64) ([]Op, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.Open(l.pathFor(vaultID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []Op{}, nil
		}
		return nil, err
	}
	defer f.Close()

	r := bufio.NewReader(f)
	empty, err := readHeader(r)
	if err != nil {
		return nil, err
	}
	if empty {
		return []Op{}, nil
	}
	out := make([]Op, 0)
	var seq uint64
	for {
		blob, hash, ok, err := readRecord(r)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}
		seq++
		if seq <= since {
			continue
		}
		// readRecord already allocated a fresh slice per record, so it is an
		// independent defensive copy; hand it straight to the caller.
		out = append(out, Op{Seq: seq, Blob: blob, Hash: hash})
	}
	return out, nil
}

// VerifyChain walks the vault's hash chain and reports whether it is intact. It
// reads through Since (which takes l.mu), so it must NOT be called while holding
// l.mu. See verifyChainVia / verifyChain for the tamper-evidence details.
func (l *FileVaultLog) VerifyChain(ctx context.Context, vaultID string) (VerifyResult, error) {
	return verifyChainVia(ctx, l, vaultID)
}
