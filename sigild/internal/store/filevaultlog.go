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
	"io"
	"os"
	"path/filepath"
	"sync"
)

// FileVaultLog persists each vault's ops to its own append-only file under dir.
//
// On-disk record framing (one op per record):
//
//	[4-byte big-endian uint32 length][that many raw opaque blob bytes]
//
// Seq is implicit: it is the 1-based position of the record within the file.
// The first record is Seq 1, the second Seq 2, and so on. The in-memory `seqs`
// map caches the current max seq per vault so Append need not rescan; it is
// rebuilt lazily by counting on-disk records the first time a vault is touched,
// which is what re-derives correct seqs after a restart.
type FileVaultLog struct {
	dir string

	mu sync.Mutex
	// seqs caches the current max seq per vault. A vault absent from the map has
	// not been loaded yet; its counter is rebuilt from disk on first touch.
	seqs   map[string]uint64
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

// ensureLoaded rebuilds the cached seq counter for vaultID from disk if it has
// not been loaded yet. Caller must hold l.mu.
func (l *FileVaultLog) ensureLoaded(vaultID string) error {
	if l.loaded[vaultID] {
		return nil
	}
	n, err := l.countRecords(l.pathFor(vaultID))
	if err != nil {
		return err
	}
	l.seqs[vaultID] = n
	l.loaded[vaultID] = true
	return nil
}

// countRecords returns the number of complete framed records in the file at
// path. A missing file counts as 0. A truncated trailing record (e.g. a crash
// mid-write) is ignored rather than treated as an error.
func (l *FileVaultLog) countRecords(path string) (uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	defer f.Close()

	r := bufio.NewReader(f)
	var n uint64
	for {
		_, ok, err := readRecord(r)
		if err != nil {
			return 0, err
		}
		if !ok {
			// Clean EOF or a truncated trailing record: stop counting.
			return n, nil
		}
		n++
	}
}

// readRecord reads one framed record from r. It returns (blob, true, nil) for a
// complete record, (nil, false, nil) at a clean EOF or when the trailing record
// is truncated (a partial length prefix or a short blob), and a non-nil error
// only for genuine I/O failures. Treating truncation as a clean stop makes a
// crash mid-Append recoverable: the partial last record is simply ignored.
func readRecord(r *bufio.Reader) ([]byte, bool, error) {
	var lenBuf [4]byte
	_, err := io.ReadFull(r, lenBuf[:])
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// Clean EOF (no more records) or a partial length prefix: ignore.
			return nil, false, nil
		}
		return nil, false, err
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	blob := make([]byte, n)
	_, err = io.ReadFull(r, blob)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			// Length prefix promised more bytes than exist: truncated trailing
			// record from a crash mid-write — ignore it.
			return nil, false, nil
		}
		return nil, false, err
	}
	return blob, true, nil
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

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(cp)))
	if _, err := f.Write(lenBuf[:]); err != nil {
		return Op{}, err
	}
	if _, err := f.Write(cp); err != nil {
		return Op{}, err
	}
	if err := f.Sync(); err != nil {
		return Op{}, err
	}

	seq := l.seqs[vaultID] + 1
	l.seqs[vaultID] = seq
	return Op{Seq: seq, Blob: cp}, nil
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
	out := make([]Op, 0)
	var seq uint64
	for {
		blob, ok, err := readRecord(r)
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
		out = append(out, Op{Seq: seq, Blob: blob})
	}
	return out, nil
}
