package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// wire shapes that include the tamper-evidence hash fields (the helpers in
// vaultops_test.go decode into store.Op, whose Hash is json:"-").

type verifyOpJSON struct {
	Seq  uint64 `json:"seq"`
	Blob []byte `json:"blob"`
	Hash string `json:"hash"`
}

type verifyListJSON struct {
	VaultID string         `json:"vaultID"`
	Ops     []verifyOpJSON `json:"ops"`
	Next    uint64         `json:"next"`
}

type verifyResultJSON struct {
	VaultID     string `json:"vaultID"`
	OK          bool   `json:"ok"`
	Count       uint64 `json:"count"`
	TipHash     string `json:"tip_hash"`
	BrokenAtSeq uint64 `json:"broken_at_seq"`
}

// getOpsWithHash GETs a vault's ops and decodes them including the hash field.
func getOpsWithHash(t *testing.T, router http.Handler, vaultID string) verifyListJSON {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/vaults/"+vaultID+"/ops?since=0", nil)
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ops status = %d, want 200 (body: %s)", rec.Code, rec.Body.String())
	}
	var out verifyListJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("GET /ops body not JSON: %v", err)
	}
	return out
}

// getVerify GETs a vault's /ops/verify and returns the status code plus the
// decoded result (decoded only on 200).
func getVerify(t *testing.T, router http.Handler, vaultID string) (int, verifyResultJSON) {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/vaults/"+vaultID+"/ops/verify", nil)
	router.ServeHTTP(rec, req)
	var out verifyResultJSON
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("verify body not JSON: %v", err)
		}
	}
	return rec.Code, out
}

// assertHash32 asserts s is std-base64 of exactly 32 bytes and returns it.
func assertHash32(t *testing.T, s string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("hash %q not std-base64: %v", s, err)
	}
	if len(raw) != 32 {
		t.Fatalf("hash decodes to %d bytes, want 32", len(raw))
	}
	return s
}

// TestVaultOpsListIncludesHash confirms GET /ops now returns each op's chain
// hash as std-base64 of 32 bytes, that distinct ops have distinct hashes, and
// that the last op's hash equals the /ops/verify tip.
func TestVaultOpsListIncludesHash(t *testing.T) {
	router := devOpsRouter()
	postOp(t, router, "hv", []byte("op-one"))
	postOp(t, router, "hv", []byte("op-two"))

	list := getOpsWithHash(t, router, "hv")
	if len(list.Ops) != 2 {
		t.Fatalf("got %d ops, want 2", len(list.Ops))
	}
	h1 := assertHash32(t, list.Ops[0].Hash)
	h2 := assertHash32(t, list.Ops[1].Hash)
	if h1 == h2 {
		t.Fatal("distinct ops share the same hash")
	}

	// The verify tip must equal the last op's hash (both std-base64 of the same
	// 32-byte chain hash).
	code, res := getVerify(t, router, "hv")
	if code != http.StatusOK {
		t.Fatalf("verify status = %d, want 200", code)
	}
	if res.TipHash != h2 {
		t.Fatalf("verify tip_hash = %q, want last op hash %q", res.TipHash, h2)
	}
}

// TestVaultOpsVerifyOK confirms GET /ops/verify reports an intact chain after
// appends: ok=true, count matches, tip present, broken_at_seq omitted (0).
func TestVaultOpsVerifyOK(t *testing.T) {
	router := devOpsRouter()
	for i := 0; i < 3; i++ {
		postOp(t, router, "vok", []byte{byte(i)})
	}

	code, res := getVerify(t, router, "vok")
	if code != http.StatusOK {
		t.Fatalf("verify status = %d, want 200", code)
	}
	if !res.OK {
		t.Fatalf("verify ok = false (broken at %d), want true", res.BrokenAtSeq)
	}
	if res.Count != 3 {
		t.Fatalf("verify count = %d, want 3", res.Count)
	}
	if res.BrokenAtSeq != 0 {
		t.Fatalf("verify broken_at_seq = %d, want 0/omitted when ok", res.BrokenAtSeq)
	}
	assertHash32(t, res.TipHash)
	if res.VaultID != "vok" {
		t.Fatalf("verify vaultID = %q, want vok", res.VaultID)
	}
}

// TestVaultOpsVerifyEmptyVault confirms /ops/verify on a never-written vault
// reports ok=true with count 0 (a genesis chain).
func TestVaultOpsVerifyEmptyVault(t *testing.T) {
	router := devOpsRouter()
	code, res := getVerify(t, router, "empty")
	if code != http.StatusOK {
		t.Fatalf("verify status = %d, want 200", code)
	}
	if !res.OK || res.Count != 0 {
		t.Fatalf("empty verify = %+v, want ok=true count=0", res)
	}
}

// TestVaultOpsVerifyDefaultStill501 confirms the default (DevOpsEnabled=false)
// path keeps /ops/verify at a deliberate 501 (not a 404), preserving posture.
func TestVaultOpsVerifyDefaultStill501(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/vaults/v1/ops/verify", nil)
	testRouter().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("default /ops/verify status = %d, want 501", rec.Code)
	}
	var body apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("501 body not JSON: %v", err)
	}
	if body.Error != "not_implemented" {
		t.Fatalf("default /ops/verify error = %q, want not_implemented", body.Error)
	}
}
