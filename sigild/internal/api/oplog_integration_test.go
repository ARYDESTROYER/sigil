package api

// STATUS: pre-audit skeleton, test-only.
//
// Real-socket HTTP integration tests for the DEV-ONLY vault op-log. These spin
// up an actual httptest.NewServer (a real TCP listener) and drive it with a
// real net/http client, so they exercise the full request/response path —
// routing, middleware chain, body-cap, JSON encoding, and base64 marshalling of
// opaque blobs — that the in-process httptest.NewRecorder tests in
// vaultops_test.go cannot reach. They COMPLEMENT, and deliberately do not
// duplicate, those recorder tests.
//
// Reminder of the invariants under test (all pre-audit, all enforced by the
// production guardrails): sigild performs NO cryptography, stores OPAQUE blobs
// it never interprets, and the op-log is dev-gated — it 501s unless
// DevOpsEnabled is set. These tests assert that behaviour over the wire; they
// change no production code.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// --- over-the-wire response shapes (mirror the handler structs exactly) ---

type wireAppendResp struct {
	VaultID string `json:"vaultID"`
	Seq     uint64 `json:"seq"`
}

// wireOp mirrors store.Op as it appears on the wire: Blob is a base64 string,
// not []byte, because we decode it ourselves to prove the round-trip rather than
// leaning on encoding/json's automatic []byte handling.
type wireOp struct {
	Seq  uint64 `json:"seq"`
	Blob string `json:"blob"`
}

type wireListResp struct {
	VaultID string   `json:"vaultID"`
	Ops     []wireOp `json:"ops"`
	Next    uint64   `json:"next"`
}

// --- small real-socket helpers ---

// newDevServer starts a real HTTP server with the dev op-log enabled.
func newDevServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(NewRouter(Config{
		Version:       "itest",
		Logger:        discardLogger(),
		DevOpsEnabled: true,
	}))
	t.Cleanup(srv.Close)
	return srv
}

// postOpWire POSTs an opaque payload to a vault over the socket and returns the
// decoded append response plus the raw status code.
func postOpWire(t *testing.T, srv *httptest.Server, vaultID string, blob []byte) (int, wireAppendResp) {
	t.Helper()
	resp, err := http.Post(srv.URL+"/v1/vaults/"+vaultID+"/ops",
		"application/octet-stream", bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("POST %s: %v", vaultID, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read POST body: %v", err)
	}
	var out wireAppendResp
	if resp.StatusCode == http.StatusCreated {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("POST body not JSON (%s): %v", body, err)
		}
	}
	return resp.StatusCode, out
}

// mustAppend POSTs and asserts a 201 with the expected seq, returning nothing.
func mustAppend(t *testing.T, srv *httptest.Server, vaultID string, blob []byte, wantSeq uint64) {
	t.Helper()
	code, resp := postOpWire(t, srv, vaultID, blob)
	if code != http.StatusCreated {
		t.Fatalf("POST %s status = %d, want 201", vaultID, code)
	}
	if resp.VaultID != vaultID {
		t.Fatalf("POST %s echoed vaultID = %q, want %q", vaultID, resp.VaultID, vaultID)
	}
	if resp.Seq != wantSeq {
		t.Fatalf("POST %s seq = %d, want %d", vaultID, resp.Seq, wantSeq)
	}
}

// listOpsWire GETs a vault's ops over the socket. since == "" omits the query
// param entirely. It asserts a 200 and returns the decoded list response.
func listOpsWire(t *testing.T, srv *httptest.Server, vaultID, since string) wireListResp {
	t.Helper()
	url := srv.URL + "/v1/vaults/" + vaultID + "/ops"
	if since != "" {
		url += "?since=" + since
	}
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read GET body: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, want 200 (body: %s)", url, resp.StatusCode, body)
	}
	var out wireListResp
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("GET body not JSON (%s): %v", body, err)
	}
	if out.VaultID != vaultID {
		t.Fatalf("GET echoed vaultID = %q, want %q", out.VaultID, vaultID)
	}
	return out
}

// decodeBlob base64-decodes a wire blob, failing the test on malformed input.
func decodeBlob(t *testing.T, b64 string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("blob %q is not valid base64: %v", b64, err)
	}
	return raw
}

// --- tests ---

// TestOplogIntegrationAppendListLifecycle drives a full append→list cycle over a
// real socket: POST three distinct opaque payloads to one vault (assigned seq
// 1,2,3), then GET ?since=0 and assert the three ops come back in ascending seq
// order, each blob base64-decodes to EXACTLY the posted bytes, and next == 3.
func TestOplogIntegrationAppendListLifecycle(t *testing.T) {
	srv := newDevServer(t)

	payloads := [][]byte{
		[]byte("first-opaque-op"),
		{0x01, 0x02, 0x03, 0x04, 0x05},
		[]byte("third-and-final"),
	}
	for i, p := range payloads {
		mustAppend(t, srv, "alpha", p, uint64(i+1))
	}

	list := listOpsWire(t, srv, "alpha", "0")
	if len(list.Ops) != 3 {
		t.Fatalf("since=0 returned %d ops, want 3", len(list.Ops))
	}
	for i, op := range list.Ops {
		wantSeq := uint64(i + 1)
		if op.Seq != wantSeq {
			t.Fatalf("ops[%d].seq = %d, want %d (ascending)", i, op.Seq, wantSeq)
		}
		got := decodeBlob(t, op.Blob)
		if !bytes.Equal(got, payloads[i]) {
			t.Fatalf("ops[%d] blob = %x, want %x (server must round-trip bytes unchanged)", i, got, payloads[i])
		}
	}
	if list.Next != 3 {
		t.Fatalf("since=0 next = %d, want 3", list.Next)
	}
}

// TestOplogIntegrationSinceCursor exercises ?since= cursor semantics over the
// wire against a vault holding three ops: since=1 returns only seq 2,3; since=3
// returns no ops with next staying at 3 (the handler reports next == since when
// nothing matches); and an omitted since param returns all three.
func TestOplogIntegrationSinceCursor(t *testing.T) {
	srv := newDevServer(t)
	for i := 0; i < 3; i++ {
		mustAppend(t, srv, "cursor", []byte{byte(i)}, uint64(i+1))
	}

	t.Run("since=1 skips seq 1", func(t *testing.T) {
		list := listOpsWire(t, srv, "cursor", "1")
		if len(list.Ops) != 2 || list.Ops[0].Seq != 2 || list.Ops[1].Seq != 3 {
			t.Fatalf("since=1 ops = %+v, want seq 2,3", list.Ops)
		}
		if list.Next != 3 {
			t.Fatalf("since=1 next = %d, want 3", list.Next)
		}
	})

	t.Run("since=3 is empty, next holds at since", func(t *testing.T) {
		list := listOpsWire(t, srv, "cursor", "3")
		if len(list.Ops) != 0 {
			t.Fatalf("since=3 ops = %+v, want empty", list.Ops)
		}
		// Handler sets next := since and only bumps it past a returned op's seq;
		// with nothing returned, next stays at the since value (3).
		if list.Next != 3 {
			t.Fatalf("since=3 next = %d, want 3 (== since)", list.Next)
		}
	})

	t.Run("no since param returns all", func(t *testing.T) {
		list := listOpsWire(t, srv, "cursor", "")
		if len(list.Ops) != 3 {
			t.Fatalf("no-since returned %d ops, want 3", len(list.Ops))
		}
		if list.Ops[0].Seq != 1 || list.Ops[2].Seq != 3 {
			t.Fatalf("no-since seqs = %d..%d, want 1..3", list.Ops[0].Seq, list.Ops[2].Seq)
		}
		if list.Next != 3 {
			t.Fatalf("no-since next = %d, want 3", list.Next)
		}
	})
}

// TestOplogIntegrationOpaqueBinaryIntegrity confirms the server treats the body
// as raw opaque bytes — never decoded, parsed, or normalized. A payload with NUL
// bytes, a high byte, and non-UTF8 content must round-trip byte-identically
// through POST + GET over the socket.
func TestOplogIntegrationOpaqueBinaryIntegrity(t *testing.T) {
	srv := newDevServer(t)

	// NUL bytes, a high/0xff byte, a control byte, an ASCII letter — not valid
	// UTF-8, and deliberately full of bytes that a naive string path would mangle.
	payload := []byte{0x00, 0xff, 0x10, 'A', 0x00}
	mustAppend(t, srv, "binvault", payload, 1)

	list := listOpsWire(t, srv, "binvault", "0")
	if len(list.Ops) != 1 {
		t.Fatalf("binary vault returned %d ops, want 1", len(list.Ops))
	}
	got := decodeBlob(t, list.Ops[0].Blob)
	if !bytes.Equal(got, payload) {
		t.Fatalf("binary blob round-trip = %x, want %x (server must store raw bytes opaquely)", got, payload)
	}
}

// TestOplogIntegrationMultiVaultIndependence confirms per-vault seq sequences and
// listing isolation over the wire: vault "alpha" and vault "beta" each number
// their ops from 1, and listing one never surfaces the other's ops.
func TestOplogIntegrationMultiVaultIndependence(t *testing.T) {
	srv := newDevServer(t)

	alphaPayloads := [][]byte{[]byte("alpha-1"), []byte("alpha-2")}
	betaPayloads := [][]byte{[]byte("beta-1")}

	mustAppend(t, srv, "alpha", alphaPayloads[0], 1)
	mustAppend(t, srv, "beta", betaPayloads[0], 1) // beta's FIRST op is seq 1, not 2
	mustAppend(t, srv, "alpha", alphaPayloads[1], 2)

	alpha := listOpsWire(t, srv, "alpha", "0")
	if len(alpha.Ops) != 2 {
		t.Fatalf("alpha returned %d ops, want 2", len(alpha.Ops))
	}
	for i, op := range alpha.Ops {
		if op.Seq != uint64(i+1) {
			t.Fatalf("alpha ops[%d].seq = %d, want %d", i, op.Seq, i+1)
		}
		if got := decodeBlob(t, op.Blob); !bytes.Equal(got, alphaPayloads[i]) {
			t.Fatalf("alpha ops[%d] blob = %x, want %x", i, got, alphaPayloads[i])
		}
	}

	beta := listOpsWire(t, srv, "beta", "0")
	if len(beta.Ops) != 1 {
		t.Fatalf("beta returned %d ops, want 1", len(beta.Ops))
	}
	if beta.Ops[0].Seq != 1 {
		t.Fatalf("beta first op seq = %d, want 1 (independent per-vault numbering)", beta.Ops[0].Seq)
	}
	if got := decodeBlob(t, beta.Ops[0].Blob); !bytes.Equal(got, betaPayloads[0]) {
		t.Fatalf("beta blob = %x, want %x (no cross-vault leakage)", got, betaPayloads[0])
	}
}

// TestOplogIntegrationProbes checks the liveness/readiness/version probes over a
// real socket, including that the injected Version ("itest") is echoed back.
func TestOplogIntegrationProbes(t *testing.T) {
	srv := newDevServer(t)

	t.Run("healthz", func(t *testing.T) {
		var body struct {
			Status  string `json:"status"`
			Version string `json:"version"`
		}
		getJSON(t, srv.URL+"/healthz", http.StatusOK, &body)
		if body.Status != "ok" || body.Version != "itest" {
			t.Fatalf("healthz = %+v, want {ok itest}", body)
		}
	})

	t.Run("version", func(t *testing.T) {
		var body struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		getJSON(t, srv.URL+"/version", http.StatusOK, &body)
		if body.Name != "sigild" || body.Version != "itest" {
			t.Fatalf("version = %+v, want {sigild itest}", body)
		}
	})

	t.Run("readyz with deps unconfigured is 200", func(t *testing.T) {
		// PostgresAddr/RedisAddr are unset, so dialState reports "unconfigured"
		// (not "unreachable") and readyz stays 200.
		resp, err := http.Get(srv.URL + "/readyz")
		if err != nil {
			t.Fatalf("GET /readyz: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("readyz status = %d, want 200 (deps unconfigured)", resp.StatusCode)
		}
	})
}

// TestOplogIntegrationGatingDisabled confirms the dev gate over a real socket:
// with DevOpsEnabled=false the ops path 501s for BOTH GET and POST, while the
// probes still answer 200.
func TestOplogIntegrationGatingDisabled(t *testing.T) {
	srv := httptest.NewServer(NewRouter(Config{
		Version:       "itest",
		Logger:        discardLogger(),
		DevOpsEnabled: false,
	}))
	defer srv.Close()

	t.Run("POST ops is 501", func(t *testing.T) {
		resp, err := http.Post(srv.URL+"/v1/vaults/gated/ops",
			"application/octet-stream", bytes.NewReader([]byte("x")))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotImplemented {
			t.Fatalf("disabled POST status = %d, want 501", resp.StatusCode)
		}
		var body apiError
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("501 body not JSON: %v", err)
		}
		if body.Error != "not_implemented" {
			t.Fatalf("disabled POST error = %q, want not_implemented", body.Error)
		}
	})

	t.Run("GET ops is 501", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/v1/vaults/gated/ops")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNotImplemented {
			t.Fatalf("disabled GET status = %d, want 501", resp.StatusCode)
		}
	})

	t.Run("probes still 200 when gated", func(t *testing.T) {
		for _, path := range []string{"/healthz", "/readyz", "/version"} {
			resp, err := http.Get(srv.URL + path)
			if err != nil {
				t.Fatalf("GET %s: %v", path, err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("gated %s status = %d, want 200", path, resp.StatusCode)
			}
		}
	})
}

// TestOplogIntegrationErrorShapes checks the typed error responses over the wire:
// an empty POST body is 400 empty_op; a non-numeric ?since is 400 bad_since; and
// a body over the 64 KiB cap is 413.
func TestOplogIntegrationErrorShapes(t *testing.T) {
	srv := newDevServer(t)

	t.Run("empty body -> 400 empty_op", func(t *testing.T) {
		resp, err := http.Post(srv.URL+"/v1/vaults/errs/ops",
			"application/octet-stream", bytes.NewReader(nil))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("empty POST status = %d, want 400", resp.StatusCode)
		}
		var body apiError
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("400 body not JSON: %v", err)
		}
		if body.Error != "empty_op" {
			t.Fatalf("empty POST error = %q, want empty_op", body.Error)
		}
	})

	t.Run("non-numeric since -> 400 bad_since", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/v1/vaults/errs/ops?since=notanumber")
		if err != nil {
			t.Fatalf("GET: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("bad since status = %d, want 400", resp.StatusCode)
		}
		var body apiError
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("400 body not JSON: %v", err)
		}
		if body.Error != "bad_since" {
			t.Fatalf("bad since error = %q, want bad_since", body.Error)
		}
	})

	t.Run("oversized body -> 413", func(t *testing.T) {
		oversized := bytes.Repeat([]byte("a"), maxOpsBodyBytes+1) // 64 KiB + 1
		resp, err := http.Post(srv.URL+"/v1/vaults/errs/ops",
			"application/octet-stream", bytes.NewReader(oversized))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized POST status = %d, want 413", resp.StatusCode)
		}
	})
}

// getJSON GETs a URL, asserts the status, and decodes the JSON body into v.
func getJSON(t *testing.T, url string, wantStatus int, v any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != wantStatus {
		t.Fatalf("GET %s status = %d, want %d", url, resp.StatusCode, wantStatus)
	}
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("GET %s body not JSON: %v", url, err)
	}
}
