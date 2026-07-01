package api

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

func TestNonceStoreFreshAccepted(t *testing.T) {
	s := newNonceStore(300, 100)
	if !s.checkAndRecord("n1", 1000) {
		t.Fatal("first use of a nonce must be accepted")
	}
	if !s.checkAndRecord("n2", 1000) {
		t.Fatal("a distinct nonce must also be accepted")
	}
}

func TestNonceStoreReplayRejected(t *testing.T) {
	s := newNonceStore(300, 100)
	if !s.checkAndRecord("n1", 1000) {
		t.Fatal("first use accepted")
	}
	if s.checkAndRecord("n1", 1000) {
		t.Fatal("immediate replay must be rejected")
	}
	// Still within the TTL window (expiry is now+300 = 1300; 1299 < 1300).
	if s.checkAndRecord("n1", 1299) {
		t.Fatal("replay within the TTL window must be rejected")
	}
}

func TestNonceStoreReacceptedAfterExpiry(t *testing.T) {
	s := newNonceStore(300, 100)
	if !s.checkAndRecord("n1", 1000) {
		t.Fatal("first use accepted")
	}
	// At now == expiry (1000+300), the entry is expired and the same nonce value
	// (necessarily carried by a request with a fresh, in-skew timestamp) is fresh.
	if !s.checkAndRecord("n1", 1300) {
		t.Fatal("a nonce at/after its TTL must be re-accepted")
	}
}

func TestNonceStoreCapFailsClosedThenReclaims(t *testing.T) {
	s := newNonceStore(300, 3)
	for i := 0; i < 3; i++ {
		if !s.checkAndRecord("live"+strconv.Itoa(i), 1000) {
			t.Fatalf("nonce %d should be accepted", i)
		}
	}
	// At capacity with all-live nonces: a new nonce fails closed.
	if s.checkAndRecord("overflow", 1000) {
		t.Fatal("at capacity with live nonces, a new nonce must fail closed")
	}
	// Once the live nonces expire, the next call reclaims their space and succeeds.
	if !s.checkAndRecord("after", 1300) {
		t.Fatal("expired entries must be reclaimed so a fresh nonce is accepted")
	}
}

func TestNonceStoreConcurrent(t *testing.T) {
	// Run with -race: checkAndRecord must be a safe atomic read-modify-write.
	s := newNonceStore(300, 1_000_000)
	var wg sync.WaitGroup
	const goroutines, per = 16, 100
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for j := 0; j < per; j++ {
				n := "g" + strconv.Itoa(g) + "-" + strconv.Itoa(j)
				if !s.checkAndRecord(n, 1000) {
					t.Errorf("unique nonce %s should be accepted", n)
				}
			}
		}(g)
	}
	wg.Wait()
	// A replay of a known nonce is still rejected after the concurrent storm.
	if s.checkAndRecord("g0-0", 1000) {
		t.Fatal("replay after concurrent inserts must be rejected")
	}
}

func TestNonceStoreConcurrentSameNonceSingleWinner(t *testing.T) {
	// The security-load-bearing property: when many goroutines race the IDENTICAL
	// nonce, EXACTLY ONE checkAndRecord returns true (the rest see a replay). A
	// TOCTOU double-accept in the read-modify-write would fail this. Run under -race.
	s := newNonceStore(600, 100)
	const goroutines = 64
	var wins int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // release all goroutines at once to maximize contention
			if s.checkAndRecord("contended", 1000) {
				atomic.AddInt64(&wins, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one goroutine must win the identical nonce; got %d", wins)
	}
}

func TestNonceStoreCoversFullSkewWindow(t *testing.T) {
	// Regression for the 2x-skew boundary: the store's retention (nonceStoreTTL)
	// must cover the FULL closed interval on which a byte-identical replay still
	// passes authorizeOps' inclusive skew gate. Worst case the earliest first
	// receipt is server-time ts-opsAuthSkew, and the latest a replay still verifies
	// is server-time ts+opsAuthSkew (skew == +opsAuthSkew passes). A nonce first
	// seen at ts-skew must therefore STILL be a replay at ts+skew. With
	// nonceStoreTTL == 2*opsAuthSkew this fails by one tick; the +1 closes it.
	s := newNonceStore(nonceStoreTTL, 100)
	const ts = int64(1_000_000)
	firstReceipt := ts - opsAuthSkew
	if !s.checkAndRecord("n", firstReceipt) {
		t.Fatal("first receipt must be accepted")
	}
	latestReplay := ts + opsAuthSkew
	if s.checkAndRecord("n", latestReplay) {
		t.Fatalf("a replay at the latest still-timestamp-valid instant (now=%d) must be rejected", latestReplay)
	}
}
