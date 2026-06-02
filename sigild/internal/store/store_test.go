package store

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func TestMemKVPutGet(t *testing.T) {
	s := NewMemKV()
	want := []byte("hello vault")
	if err := s.Put("k1", want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get("k1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Get = %q, want %q", got, want)
	}
}

func TestMemKVPutOverwrites(t *testing.T) {
	s := NewMemKV()
	if err := s.Put("k", []byte("v1")); err != nil {
		t.Fatalf("Put v1: %v", err)
	}
	if err := s.Put("k", []byte("v2")); err != nil {
		t.Fatalf("Put v2: %v", err)
	}
	got, err := s.Get("k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, []byte("v2")) {
		t.Fatalf("Get = %q, want v2", got)
	}
}

func TestMemKVGetMissing(t *testing.T) {
	s := NewMemKV()
	_, err := s.Get("nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get missing err = %v, want ErrNotFound", err)
	}
}

func TestMemKVList(t *testing.T) {
	s := NewMemKV()
	// Insert out of order; List must return sorted keys.
	for _, k := range []string{"c", "a", "b"} {
		if err := s.Put(k, []byte(k)); err != nil {
			t.Fatalf("Put %q: %v", k, err)
		}
	}
	keys, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"a", "b", "c"}
	if len(keys) != len(want) {
		t.Fatalf("List = %v, want %v", keys, want)
	}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("List = %v, want %v", keys, want)
		}
	}
}

func TestMemKVListEmpty(t *testing.T) {
	s := NewMemKV()
	keys, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 0 {
		t.Fatalf("List on empty store = %v, want empty", keys)
	}
}

// TestMemKVStoresCopy verifies that mutating the caller's slice after Put, or
// the returned slice after Get, does not corrupt stored data.
func TestMemKVStoresCopy(t *testing.T) {
	s := NewMemKV()
	in := []byte("secret")
	if err := s.Put("k", in); err != nil {
		t.Fatalf("Put: %v", err)
	}
	in[0] = 'X' // mutate caller's slice after Put

	got, err := s.Get("k")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, []byte("secret")) {
		t.Fatalf("stored value mutated via input slice: %q", got)
	}

	got[0] = 'Y' // mutate returned slice
	again, err := s.Get("k")
	if err != nil {
		t.Fatalf("Get again: %v", err)
	}
	if !bytes.Equal(again, []byte("secret")) {
		t.Fatalf("stored value mutated via returned slice: %q", again)
	}
}

// TestMemKVConcurrent exercises the RWMutex under the race detector: many
// goroutines Put/Get/List concurrently. The test passes if it does not race or
// panic and all written keys are retrievable afterwards.
func TestMemKVConcurrent(t *testing.T) {
	s := NewMemKV()
	const workers = 16
	const perWorker = 100

	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(w int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				key := fmt.Sprintf("w%d-k%d", w, i)
				if err := s.Put(key, []byte(key)); err != nil {
					t.Errorf("Put %q: %v", key, err)
					return
				}
				if _, err := s.Get(key); err != nil {
					t.Errorf("Get %q: %v", key, err)
					return
				}
				_, _ = s.List()
			}
		}(w)
	}
	wg.Wait()

	keys, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != workers*perWorker {
		t.Fatalf("List len = %d, want %d", len(keys), workers*perWorker)
	}
}
