package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

// devOpsRouter returns a router with the DEV-ONLY op-log enabled.
func devOpsRouter() http.Handler {
	return NewRouter(Config{Version: "test", Logger: discardLogger(), DevOpsEnabled: true})
}

// TestVaultOpsDefaultStill501 confirms the default (DevOpsEnabled=false) path is
// unchanged: both verbs return 501.
func TestVaultOpsDefaultStill501(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/v1/vaults/v1/ops", nil)
		testRouter().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("%s default ops status = %d, want 501", method, rec.Code)
		}
	}
}

func TestVaultOpsAppendAndList(t *testing.T) {
	router := devOpsRouter()

	// Two opaque payloads — distinct bytes so we can assert byte-equality.
	op1 := []byte{0x00, 0x01, 0x02, 0xff}
	op2 := []byte("second-opaque-blob")

	// POST op1 -> 201, seq=1.
	seq1 := postOp(t, router, "vaultA", op1)
	if seq1 != 1 {
		t.Fatalf("first POST seq = %d, want 1", seq1)
	}
	// POST op2 -> 201, seq=2.
	seq2 := postOp(t, router, "vaultA", op2)
	if seq2 != 2 {
		t.Fatalf("second POST seq = %d, want 2", seq2)
	}

	// GET ?since=0 -> both ops, in order, blobs decode to exactly what we posted.
	list := getOps(t, router, "vaultA", "0")
	if len(list.Ops) != 2 {
		t.Fatalf("since=0 returned %d ops, want 2", len(list.Ops))
	}
	if list.Ops[0].Seq != 1 || list.Ops[1].Seq != 2 {
		t.Fatalf("since=0 seqs = %d,%d, want 1,2", list.Ops[0].Seq, list.Ops[1].Seq)
	}
	if !bytes.Equal(list.Ops[0].Blob, op1) {
		t.Fatalf("op1 blob = %x, want %x (server must store bytes opaquely/unchanged)", list.Ops[0].Blob, op1)
	}
	if !bytes.Equal(list.Ops[1].Blob, op2) {
		t.Fatalf("op2 blob = %x, want %x (server must store bytes opaquely/unchanged)", list.Ops[1].Blob, op2)
	}
	if list.Next != 2 {
		t.Fatalf("since=0 next = %d, want 2", list.Next)
	}

	// GET ?since=1 -> only seq=2.
	list = getOps(t, router, "vaultA", "1")
	if len(list.Ops) != 1 || list.Ops[0].Seq != 2 {
		t.Fatalf("since=1 ops = %+v, want only seq=2", list.Ops)
	}
	if !bytes.Equal(list.Ops[0].Blob, op2) {
		t.Fatalf("since=1 blob = %x, want %x", list.Ops[0].Blob, op2)
	}
}

// getOpsQuery GETs a vault's ops with an explicit raw query string (e.g.
// "since=2&limit=2"), asserting 200, and returns the decoded page.
func getOpsQuery(t *testing.T, router http.Handler, vaultID, query string) opsListResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	url := "/v1/vaults/" + vaultID + "/ops"
	if query != "" {
		url += "?" + query
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %q status = %d, want 200 (body: %s)", url, rec.Code, rec.Body.String())
	}
	var resp opsListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("GET body not JSON: %v", err)
	}
	return resp
}

// TestVaultOpsListPagination walks a 5-op vault two-at-a-time via ?limit=2,
// asserting has_more/next drive the cursor and the last (short) page ends the walk.
func TestVaultOpsListPagination(t *testing.T) {
	router := devOpsRouter()
	for i := 0; i < 5; i++ {
		postOp(t, router, "pg", []byte{byte(i)})
	}

	// Page 1: since=0, limit=2 -> seq 1,2; a full page => has_more true; next=2.
	p := getOpsQuery(t, router, "pg", "limit=2")
	if len(p.Ops) != 2 || p.Ops[0].Seq != 1 || p.Ops[1].Seq != 2 {
		t.Fatalf("page1 ops = %+v, want seq 1,2", p.Ops)
	}
	if !p.HasMore {
		t.Fatal("page1 has_more = false, want true (page filled to limit)")
	}
	if p.Next != 2 {
		t.Fatalf("page1 next = %d, want 2", p.Next)
	}

	// Page 2: since=2, limit=2 -> seq 3,4; still a full page => has_more true; next=4.
	p = getOpsQuery(t, router, "pg", "since=2&limit=2")
	if len(p.Ops) != 2 || p.Ops[0].Seq != 3 || p.Ops[1].Seq != 4 {
		t.Fatalf("page2 ops = %+v, want seq 3,4", p.Ops)
	}
	if !p.HasMore {
		t.Fatal("page2 has_more = false, want true")
	}
	if p.Next != 4 {
		t.Fatalf("page2 next = %d, want 4", p.Next)
	}

	// Page 3: since=4, limit=2 -> only seq 5 (short page) => has_more false; next=5.
	p = getOpsQuery(t, router, "pg", "since=4&limit=2")
	if len(p.Ops) != 1 || p.Ops[0].Seq != 5 {
		t.Fatalf("page3 ops = %+v, want only seq 5", p.Ops)
	}
	if p.HasMore {
		t.Fatal("page3 has_more = true, want false (last, short page)")
	}
	if p.Next != 5 {
		t.Fatalf("page3 next = %d, want 5", p.Next)
	}
}

// TestVaultOpsBadLimitIs400 confirms an explicitly non-numeric ?limit= is a 400
// bad_limit (an ABSENT/empty limit instead defaults — covered by other tests).
func TestVaultOpsBadLimitIs400(t *testing.T) {
	router := devOpsRouter()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/vaults/v1/ops?limit=abc", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad limit status = %d, want 400", rec.Code)
	}
	var body apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if body.Error != "bad_limit" {
		t.Fatalf("bad limit error = %q, want bad_limit", body.Error)
	}
}

// TestVaultOpsLimitClamped confirms an out-of-range but numeric limit is clamped
// into [1, maxOpsPageLimit] rather than rejected: ?limit=0 clamps up to 1.
func TestVaultOpsLimitClamped(t *testing.T) {
	router := devOpsRouter()
	for i := 0; i < 3; i++ {
		postOp(t, router, "clamp", []byte{byte(i)})
	}
	// limit=0 -> clamped to 1: exactly one op, has_more true (more remain).
	p := getOpsQuery(t, router, "clamp", "limit=0")
	if len(p.Ops) != 1 || p.Ops[0].Seq != 1 {
		t.Fatalf("limit=0 ops = %+v, want a single op seq 1 (clamped to 1)", p.Ops)
	}
	if !p.HasMore {
		t.Fatal("limit=0 has_more = false, want true (clamped page of 1, 3 ops present)")
	}
}

// TestVaultOpsListDefaultLimitNoHasMore confirms the default (no ?limit=) returns
// everything under the default cap with has_more false.
func TestVaultOpsListDefaultLimitNoHasMore(t *testing.T) {
	router := devOpsRouter()
	for i := 0; i < 3; i++ {
		postOp(t, router, "def", []byte{byte(i)})
	}
	p := getOpsQuery(t, router, "def", "since=0")
	if len(p.Ops) != 3 {
		t.Fatalf("default limit returned %d ops, want 3", len(p.Ops))
	}
	if p.HasMore {
		t.Fatal("default-limit has_more = true, want false (3 < default cap)")
	}
	if p.Next != 3 {
		t.Fatalf("default-limit next = %d, want 3", p.Next)
	}
}

func TestVaultOpsEmptyBodyIs400(t *testing.T) {
	router := devOpsRouter()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/vaultA/ops", bytes.NewReader(nil))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty POST status = %d, want 400", rec.Code)
	}
	var body apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if body.Error != "empty_op" {
		t.Fatalf("empty POST error = %q, want empty_op", body.Error)
	}
}

func TestVaultOpsBadSinceIs400(t *testing.T) {
	router := devOpsRouter()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/vaults/vaultA/ops?since=abc", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad since status = %d, want 400", rec.Code)
	}
	var body apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if body.Error != "bad_since" {
		t.Fatalf("bad since error = %q, want bad_since", body.Error)
	}
}

// TestVaultOpsOversizedStill413WhenEnabled confirms the limitBody cap still
// applies to POST when the dev op-log is enabled.
func TestVaultOpsOversizedStill413WhenEnabled(t *testing.T) {
	router := devOpsRouter()
	oversized := bytes.Repeat([]byte("a"), maxOpsBodyBytes+1)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/vaultA/ops", bytes.NewReader(oversized))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized POST status = %d, want 413", rec.Code)
	}
	var body apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("413 body not JSON: %v", err)
	}
	if body.Error != "payload_too_large" {
		t.Fatalf("413 error = %q, want payload_too_large", body.Error)
	}
}

// --- helpers ---

func postOp(t *testing.T, router http.Handler, vaultID string, blob []byte) uint64 {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/vaults/"+vaultID+"/ops", bytes.NewReader(blob))
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		VaultID string `json:"vaultID"`
		Seq     uint64 `json:"seq"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("POST body not JSON: %v", err)
	}
	if resp.VaultID != vaultID {
		t.Fatalf("POST vaultID = %q, want %q", resp.VaultID, vaultID)
	}
	return resp.Seq
}

type opsListResponse struct {
	VaultID string     `json:"vaultID"`
	Ops     []store.Op `json:"ops"`
	Next    uint64     `json:"next"`
	HasMore bool       `json:"has_more"`
}

func getOps(t *testing.T, router http.Handler, vaultID, since string) opsListResponse {
	t.Helper()
	rec := httptest.NewRecorder()
	url := "/v1/vaults/" + vaultID + "/ops"
	if since != "" {
		url += "?since=" + since
	}
	req := httptest.NewRequest(http.MethodGet, url, nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var resp opsListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("GET body not JSON: %v", err)
	}
	return resp
}
