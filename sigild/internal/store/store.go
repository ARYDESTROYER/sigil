package store

import (
	"errors"
	"sort"
	"sync"
)

// ErrNotFound is returned by KV.Get when the requested key is absent.
var ErrNotFound = errors.New("store: key not found")

// KV is a minimal key/value store over opaque byte values. It is the seam the
// real persistence adapters (PostgreSQL/Redis) will implement; the in-memory
// MemKV satisfies it for wiring and tests.
//
// Implementations must be safe for concurrent use. Values are treated as opaque
// blobs: the store applies no encryption, encoding, or interpretation.
//
// STATUS: pre-audit skeleton.
type KV interface {
	// Put stores value under key, overwriting any existing value.
	Put(key string, value []byte) error
	// Get returns the value stored under key, or ErrNotFound if absent.
	Get(key string) ([]byte, error)
	// List returns all stored keys in lexicographically sorted order.
	List() ([]string, error)
}

// MemKV is a concurrency-safe, in-memory KV implementation backed by a map
// guarded by a sync.RWMutex. It is intended for tests and local wiring only:
// it is not durable and holds everything in process memory.
type MemKV struct {
	mu sync.RWMutex
	m  map[string][]byte
}

// NewMemKV returns an empty, ready-to-use MemKV.
func NewMemKV() *MemKV {
	return &MemKV{m: make(map[string][]byte)}
}

// compile-time check that MemKV satisfies KV.
var _ KV = (*MemKV)(nil)

// Put stores a copy of value under key, overwriting any existing value. The
// copy ensures the caller cannot mutate stored data through the original slice.
func (s *MemKV) Put(key string, value []byte) error {
	cp := make([]byte, len(value))
	copy(cp, value)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[key] = cp
	return nil
}

// Get returns a copy of the value stored under key, or ErrNotFound if the key
// is absent. The copy prevents callers from mutating stored data.
func (s *MemKV) Get(key string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	v, ok := s.m[key]
	if !ok {
		return nil, ErrNotFound
	}
	cp := make([]byte, len(v))
	copy(cp, v)
	return cp, nil
}

// List returns all stored keys in lexicographically sorted order.
func (s *MemKV) List() ([]string, error) {
	s.mu.RLock()
	keys := make([]string, 0, len(s.m))
	for k := range s.m {
		keys = append(keys, k)
	}
	s.mu.RUnlock()

	sort.Strings(keys)
	return keys, nil
}
