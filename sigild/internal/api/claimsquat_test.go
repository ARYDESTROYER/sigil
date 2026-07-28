package api

// Regression tests for VAULT-ID SQUATTING BY A REJECTED REQUEST (Phase 57).
//
// THE DEFECT: trust-on-first-write fired inside the authorization step, which
// runs BEFORE a handler's cheap request-shape checks. A request the server was
// about to REJECT therefore still CLAIMED the vault on its way out. One enrolled
// device sending 50 empty-bodied appends — one per made-up vault id — produced
// 50x 400 and 0 stored ops, yet took permanent ownership of all 50 ids, locking
// their rightful owners out with a 403 forever. The per-vault rate limiter could
// not bound it: it keys on the very vault id the attacker varies each request.
//
// THE FIX: the handler's cheap, vault-INDEPENDENT validation is evaluated as a
// claimPrecondition. A request that fails it is authorized at needWriteNoClaim,
// so it can never claim. Authentication and authorization still run first and
// are unchanged — only the CLAIM side effect moved.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// claimsTotal scrapes sigild_vault_claims_total off the always-on /metrics
// endpoint. Counters are per-router, so this is the count for THIS test's server.
func claimsTotal(t *testing.T, router http.Handler) int {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, line := range strings.Split(rec.Body.String(), "\n") {
		if strings.HasPrefix(line, "sigild_vault_claims_total ") {
			var n int
			if _, err := fmt.Sscanf(line, "sigild_vault_claims_total %d", &n); err != nil {
				t.Fatalf("parse %q: %v", line, err)
			}
			return n
		}
	}
	t.Fatalf("sigild_vault_claims_total missing from /metrics")
	return 0
}

// TestRejectedOpAppendDoesNotClaimVault is the auditor's exact scenario, shrunk:
// device A sends empty-bodied appends to fresh vault ids, and every one of them
// must leave the vault UNOWNED — proven by having a DIFFERENT device then claim
// it with a genuine write.
func TestRejectedOpAppendDoesNotClaimVault(t *testing.T) {
	env := newDeviceEnvWithTokens(t,
		[]string{testEnrollToken, testEnrollToken + "-b"}, testAdminToken)
	devA := enrollDevice(t, env, testEnrollToken, "A")
	devB := enrollDevice(t, env, testEnrollToken+"-b", "B")

	before := claimsTotal(t, env.router)

	// A sprays empty bodies across 10 distinct, never-seen vault ids.
	vaults := make([]string, 10)
	for i := range vaults {
		vaults[i] = fmt.Sprintf("squat-%d", i)
		rec := v3Post(t, env, devA, "/v1/vaults/"+vaults[i]+"/ops", nil)
		// The request is REFUSED. On an unowned vault the refusal is a 403: the
		// caller holds no grant and — this is the fix — earned no ownership. It
		// must never be a 2xx.
		if rec.Code/100 == 2 {
			t.Fatalf("empty append to %s = %d, want a refusal", vaults[i], rec.Code)
		}
	}

	if got := claimsTotal(t, env.router); got != before {
		t.Fatalf("sigild_vault_claims_total = %d, want %d: a REJECTED request claimed a vault", got, before)
	}

	// PROOF the ids are still unowned: B claims every one of them with a genuine
	// write. Before the fix each of these was a permanent 403.
	for _, v := range vaults {
		rec := v3Post(t, env, devB, "/v1/vaults/"+v+"/ops", []byte("real op"))
		if rec.Code != http.StatusCreated {
			t.Fatalf("B genuine append to %s = %d, want 201 (body %s): A's rejected "+
				"empty POST squatted the vault id", v, rec.Code, rec.Body.String())
		}
	}
	if got := claimsTotal(t, env.router); got != before+len(vaults) {
		t.Fatalf("sigild_vault_claims_total = %d, want %d after B's genuine writes",
			got, before+len(vaults))
	}

	// And the 400 path still exists where it is meaningful: on a vault the caller
	// MAY write, an empty body is answered 400 (not silently accepted).
	rec := v3Post(t, env, devB, "/v1/vaults/"+vaults[0]+"/ops", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("owner empty append = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "empty_op") {
		t.Fatalf("owner empty append body = %s, want empty_op", rec.Body.String())
	}
	// ...and that 400 claimed nothing new either.
	if got := claimsTotal(t, env.router); got != before+len(vaults) {
		t.Fatalf("sigild_vault_claims_total = %d, want %d: the 400 claimed something",
			got, before+len(vaults))
	}
}

// TestRejectedKeyEnvelopePutDoesNotClaimVault is the same defect on the sharing
// surface: an envelope PUT that is going to be rejected (empty body, unknown
// recipient, revoked recipient) must not claim the vault either.
func TestRejectedKeyEnvelopePutDoesNotClaimVault(t *testing.T) {
	env := newShareEnv(t)
	devC := enrollDevice(t, env.deviceEnv, testEnrollToken+"-c", "C")

	before := claimsTotal(t, env.router)

	cases := []struct {
		name      string
		vault     string
		recipient string
		body      []byte
	}{
		{"empty body", "squat-empty", env.devB.ID, nil},
		{"unknown recipient", "squat-unknown", "dev_does_not_exist", randBytes(t, 128)},
	}
	for _, tc := range cases {
		path := "/v1/vaults/" + tc.vault + "/keys/" + tc.recipient
		rec := v3Put(t, env.deviceEnv, env.devA, path, tc.body)
		if rec.Code/100 == 2 {
			t.Fatalf("%s: PUT %s = %d, want a refusal", tc.name, path, rec.Code)
		}
	}

	// A revoked recipient (409) is the third rejection shape.
	if err := env.devices.RevokeDevice(t.Context(), devC.ID, time.Now().UTC()); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	revokedPath := "/v1/vaults/squat-revoked/keys/" + devC.ID
	if rec := v3Put(t, env.deviceEnv, env.devA, revokedPath, randBytes(t, 128)); rec.Code/100 == 2 {
		t.Fatalf("PUT to a revoked recipient = %d, want a refusal", rec.Code)
	}

	if got := claimsTotal(t, env.router); got != before {
		t.Fatalf("sigild_vault_claims_total = %d, want %d: a REJECTED envelope PUT claimed a vault", got, before)
	}

	// PROOF: a DIFFERENT device can still claim every one of those ids.
	for _, v := range []string{"squat-empty", "squat-unknown", "squat-revoked"} {
		path := "/v1/vaults/" + v + "/keys/" + env.devB.ID
		if rec := v3Put(t, env.deviceEnv, env.devB, path, randBytes(t, 128)); rec.Code != http.StatusCreated {
			t.Fatalf("B genuine PUT to %s = %d, want 201 (body %s): A's rejected PUT squatted it",
				v, rec.Code, rec.Body.String())
		}
	}

	// The rejection responses themselves are unchanged on a vault the caller owns.
	owned := "/v1/vaults/" + env.vault + "/keys/" + env.devB.ID
	if rec := v3Put(t, env.deviceEnv, env.devA, owned, randBytes(t, 128)); rec.Code != http.StatusCreated {
		t.Fatalf("A claims its own vault = %d, want 201", rec.Code)
	}
	if rec := v3Put(t, env.deviceEnv, env.devA, owned, nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("owner empty envelope = %d, want 400 (body %s)", rec.Code, rec.Body.String())
	}
	unknown := "/v1/vaults/" + env.vault + "/keys/dev_nope"
	if rec := v3Put(t, env.deviceEnv, env.devA, unknown, randBytes(t, 128)); rec.Code != http.StatusNotFound {
		t.Fatalf("owner unknown recipient = %d, want 404 (body %s)", rec.Code, rec.Body.String())
	}
	revoked := "/v1/vaults/" + env.vault + "/keys/" + devC.ID
	if rec := v3Put(t, env.deviceEnv, env.devA, revoked, randBytes(t, 128)); rec.Code != http.StatusConflict {
		t.Fatalf("owner revoked recipient = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
}
