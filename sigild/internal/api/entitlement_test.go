package api

// Tests for ENTITLEMENT ENFORCEMENT (Phase 55).
//
// The two that are the phase's reason to exist are marked ★:
//
//	★ TestAfterGraceWritesRefusedReadsAndKeyRecoveryStillWork
//	     the whole asymmetry, exercised over the real router: every write 402s
//	     while every read — and every key-recovery route — still answers 200.
//	★ TestRequireEntitlementIsCalledFromWriteHandlersOnly
//	     the same asymmetry proved STRUCTURALLY, by parsing this package's own
//	     source. A future edit that gates a read fails this test, not a customer.
//
// Everything else is the boundary: off by default, past_due is still entitled,
// grace warns instead of refusing, 402 is never an auth oracle, and any
// uncertainty fails OPEN.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/billing"
	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

// Two obviously-fake credentials for the stand-in provider. Nothing here makes a
// network call: no test in this file invokes checkout.
const (
	entTestStripeKey  = "sk_test_fake_entitlement_tests"
	entTestStripeHook = "whsec_test_fake_entitlement_tests_00"
)

// entEnv bundles a router with the device model, billing AND (optionally)
// entitlement enforcement wired over in-memory stores a test can drive directly.
type entEnv struct {
	*deviceEnv
	subs *store.MemSubscriptionStore
	logs *bytes.Buffer
}

// entOptions configures newEntitlementEnv.
type entOptions struct {
	enforce bool
	grace   time.Duration
	tokens  []string
	// subs overrides the subscription store, so a test can inject a failing one.
	subs store.SubscriptionStore
}

// newEntitlementEnv builds the router. With enforce false it is byte-identical
// in configuration to a Phase 54 billing server.
func newEntitlementEnv(t *testing.T, opts entOptions) *entEnv {
	t.Helper()
	if len(opts.tokens) == 0 {
		opts.tokens = []string{testEnrollToken}
	}

	devices := store.NewMemDeviceStore()
	hashes := make([]string, 0, len(opts.tokens))
	for _, tok := range opts.tokens {
		h := EnrollTokenHash(tok)
		hashes = append(hashes, h)
		if err := devices.RegisterEnrollmentToken(t.Context(), h, time.Now().UTC(), time.Time{}); err != nil {
			t.Fatalf("RegisterEnrollmentToken: %v", err)
		}
	}

	mem := store.NewMemSubscriptionStore()
	var subs store.SubscriptionStore = mem
	if opts.subs != nil {
		subs = opts.subs
	}

	var logs bytes.Buffer
	router := NewRouter(Config{
		Version:           "test",
		Logger:            slog.New(slog.NewJSONHandler(&logs, nil)),
		DevOpsEnabled:     true,
		Devices:           devices,
		EnrollTokenHashes: hashes,
		AdminToken:        testAdminToken,
		Billing: BillingConfig{
			Providers: map[string]billing.Provider{
				billing.ProviderStripe: billing.NewStripe(billing.StripeConfig{
					SecretKey:     entTestStripeKey,
					WebhookSecret: entTestStripeHook,
					PriceID:       "price_test_entitlement",
				}),
			},
			DefaultProvider: billing.ProviderStripe,
			Subscriptions:   subs,
			SuccessURL:      "https://app.test/ok",
			CancelURL:       "https://app.test/cancel",
		},
		EntitlementEnforce: opts.enforce,
		EntitlementGrace:   opts.grace,
	})
	return &entEnv{
		deviceEnv: &deviceEnv{router: router, devices: devices},
		subs:      mem,
		logs:      &logs,
	}
}

// seedStatus drives the subscription store to a status through the REAL state
// machine, so the record a test asserts against is one the server could actually
// have produced. eventID must be unique per call (it is the idempotency key).
func seedStatus(t *testing.T, subs *store.MemSubscriptionStore, subject string, target billing.Status, eventID string) {
	t.Helper()
	out, err := subs.ApplyWebhookEvent(context.Background(), store.SubscriptionEvent{
		Provider:        billing.ProviderStripe,
		EventID:         eventID,
		EventType:       "test",
		Subject:         subject,
		SubscriptionRef: "sub_" + subject,
		Target:          target,
		OccurredAt:      time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("seed %s: %v", target, err)
	}
	if out.Result != store.ApplyApplied {
		t.Fatalf("seed %s: result = %s, want applied", target, out.Result)
	}
}

// entitle puts a subject into the active state.
func entitle(t *testing.T, env *entEnv, subject string) {
	t.Helper()
	seedStatus(t, env.subs, subject, billing.StatusActive, "ev-active-"+subject)
}

// lapse cancels a subject's ACTIVE subscription, then waits past a millisecond
// so a millisecond-scale grace period has provably expired. The wait is real,
// not simulated: the anchor is the store's own UpdatedAt, which a test cannot
// backdate through the public interface.
func lapse(t *testing.T, env *entEnv, subject string) {
	t.Helper()
	seedStatus(t, env.subs, subject, billing.StatusCanceled, "ev-cancel-"+subject)
	time.Sleep(5 * time.Millisecond)
}

// tinyGrace is a grace period that lapse() provably outlives.
const tinyGrace = time.Millisecond

// assertNoEntitlementHeaders fails if a response carries any warning header.
func assertNoEntitlementHeaders(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	for _, h := range []string{headerEntitlement, headerEntitlementStatus, headerEntitlementGraceEnds} {
		if v := rec.Header().Get(h); v != "" {
			t.Fatalf("%s carried %s: %q, want no entitlement header", what, h, v)
		}
	}
}

// assertPaymentRequired asserts the 402 contract: the distinct status, the
// distinct error code, the reassurance fields, and that it is NEITHER of the
// coarse auth envelopes.
func assertPaymentRequired(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code != http.StatusPaymentRequired {
		t.Fatalf("%s status = %d, want 402 (body: %s)", what, rec.Code, rec.Body.String())
	}
	var body paymentRequiredResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("%s: 402 body not JSON: %v", what, err)
	}
	if body.Error != "payment_required" {
		t.Fatalf("%s: error = %q, want payment_required", what, body.Error)
	}
	// It must never collapse into an auth verdict — a client that treated this as
	// 401 would wipe its credentials, and one that treated it as 403 would tell
	// the user they lost access to their vault.
	for _, wrong := range []string{`"unauthorized"`, `"forbidden"`} {
		if strings.Contains(rec.Body.String(), wrong) {
			t.Fatalf("%s: 402 body reads as an auth failure (%s): %s", what, wrong, rec.Body.String())
		}
	}
	if !body.ReadsAllowed || !body.KeyRecoveryAllowed {
		t.Fatalf("%s: 402 body = %+v, want reads_allowed and key_recovery_allowed true", what, body)
	}
	if body.CheckoutPath == "" {
		t.Fatalf("%s: 402 body names no way to pay: %s", what, rec.Body.String())
	}
	if rec.Header().Get(headerEntitlement) != "lapsed" {
		t.Fatalf("%s: %s = %q, want lapsed", what, headerEntitlement, rec.Header().Get(headerEntitlement))
	}
}

// assertOK fails unless the response is a 2xx.
func assertOK(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	if rec.Code < 200 || rec.Code > 299 {
		t.Fatalf("%s status = %d, want 2xx (body: %s)", what, rec.Code, rec.Body.String())
	}
	if rec.Code == http.StatusPaymentRequired {
		t.Fatalf("%s was refused for payment — reads and key recovery must NEVER be refused", what)
	}
}

// ---------------------------------------------------------------------------
// Off by default.
// ---------------------------------------------------------------------------

// TestEnforcementOffByDefault: a router built without EntitlementEnforce serves
// a long-canceled account exactly as before — no refusal, no warning header, no
// entitlement block on the subscription route, and the gauge reads 0.
func TestEnforcementOffByDefault(t *testing.T) {
	env := newEntitlementEnv(t, entOptions{})
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "laptop")
	entitle(t, env, dev.Account)
	lapse(t, env, dev.Account)

	rec := v3Post(t, env.deviceEnv, dev, "/v1/vaults/vaultA/ops", []byte("op-1"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("append status = %d, want 201 with enforcement off (body: %s)", rec.Code, rec.Body.String())
	}
	assertNoEntitlementHeaders(t, rec, "append with enforcement off")

	sub := v3Get(t, env.deviceEnv, dev, "/v1/billing/subscription")
	assertOK(t, sub, "subscription")
	if strings.Contains(sub.Body.String(), `"entitlement"`) {
		t.Fatalf("subscription response gained an entitlement block with enforcement off: %s", sub.Body.String())
	}

	metrics := httptest.NewRecorder()
	env.router.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), "sigild_entitlement_enforcing 0") {
		t.Fatal("sigild_entitlement_enforcing is not 0 with enforcement off")
	}
	// Nothing was decided, so every outcome counter must still be zero.
	for _, o := range entitlementOutcomes {
		want := `sigild_entitlement_decisions_total{outcome="` + string(o) + `"} 0`
		if !strings.Contains(metrics.Body.String(), want) {
			t.Fatalf("missing or non-zero %s", want)
		}
	}
}

// TestEnforcementInertWithoutBilling: switching enforcement on but wiring no
// billing leaves the policy OFF rather than refusing every account. cmd/server
// refuses that combination at boot; the router refuses to half-apply it.
func TestEnforcementInertWithoutBilling(t *testing.T) {
	devices := store.NewMemDeviceStore()
	h := EnrollTokenHash(testEnrollToken)
	if err := devices.RegisterEnrollmentToken(t.Context(), h, time.Now().UTC(), time.Time{}); err != nil {
		t.Fatalf("RegisterEnrollmentToken: %v", err)
	}
	router := NewRouter(Config{
		Version:            "test",
		Logger:             discardLogger(),
		DevOpsEnabled:      true,
		Devices:            devices,
		EnrollTokenHashes:  []string{h},
		EntitlementEnforce: true,
	})
	env := &deviceEnv{router: router, devices: devices}
	dev := enrollDevice(t, env, testEnrollToken, "laptop")

	rec := v3Post(t, env, dev, "/v1/vaults/vaultA/ops", []byte("op-1"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("append status = %d, want 201 (enforcement must not half-apply): %s", rec.Code, rec.Body.String())
	}
}

// TestGatedRoutesStay501WithDevOpsOff: enforcement never changes what a gated
// route answers when the dev gate is off. A 402 there would leak that billing is
// configured on a server that is supposed to look entirely unimplemented — and
// it would put a payment verdict ahead of the feature gate, which is the wrong
// order.
func TestGatedRoutesStay501WithDevOpsOff(t *testing.T) {
	router := NewRouter(Config{
		Version:            "test",
		Logger:             discardLogger(),
		DevOpsEnabled:      false,
		EntitlementEnforce: true,
		EntitlementGrace:   tinyGrace,
	})
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/v1/vaults/vaultA/ops"},
		{http.MethodPut, "/v1/vaults/vaultA/keys/dev_x"},
		{http.MethodPost, "/v1/vaults/vaultA/grants"},
		{http.MethodGet, "/v1/vaults/vaultA/ops"},
		{http.MethodGet, "/v1/billing/subscription"},
	} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, bytes.NewReader(nil)))
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("%s %s = %d, want 501 with dev-ops off (body: %s)",
				tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
}

// ---------------------------------------------------------------------------
// Entitled, and past_due.
// ---------------------------------------------------------------------------

// TestEntitledAccountUnaffected: an active subscription writes exactly as it
// always did, with no warning header and no visible change.
func TestEntitledAccountUnaffected(t *testing.T) {
	env := newEntitlementEnv(t, entOptions{enforce: true, grace: tinyGrace})
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "laptop")
	entitle(t, env, dev.Account)

	rec := v3Post(t, env.deviceEnv, dev, "/v1/vaults/vaultA/ops", []byte("op-1"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("append status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	assertNoEntitlementHeaders(t, rec, "append while entitled")

	sub := v3Get(t, env.deviceEnv, dev, "/v1/billing/subscription")
	assertOK(t, sub, "subscription")
	var body subscriptionResponse
	if err := json.Unmarshal(sub.Body.Bytes(), &body); err != nil {
		t.Fatalf("subscription body: %v", err)
	}
	if body.Entitlement == nil || body.Entitlement.Writes != "allowed" || body.Entitlement.Reads != "allowed" {
		t.Fatalf("entitlement block = %+v, want writes+reads allowed", body.Entitlement)
	}
}

// TestPastDueIsStillEntitled: this is THE property that keeps a declined card
// from costing anyone their codes. A failed renewal is a provider retry window,
// not a cutoff — so past_due writes normally even with a one-millisecond grace.
func TestPastDueIsStillEntitled(t *testing.T) {
	env := newEntitlementEnv(t, entOptions{enforce: true, grace: tinyGrace})
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "laptop")
	entitle(t, env, dev.Account)
	seedStatus(t, env.subs, dev.Account, billing.StatusPastDue, "ev-pastdue")
	time.Sleep(5 * time.Millisecond) // well past the grace period, if it applied

	rec := v3Post(t, env.deviceEnv, dev, "/v1/vaults/vaultA/ops", []byte("op-1"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("past_due append status = %d, want 201 — a failed card must not cost a write (body: %s)",
			rec.Code, rec.Body.String())
	}
	assertNoEntitlementHeaders(t, rec, "append while past_due")
}

// ---------------------------------------------------------------------------
// Grace.
// ---------------------------------------------------------------------------

// TestLapsedInsideGraceStillWorksAndWarns: everything still functions, and the
// client is told — in a response header, in the subscription body, and in the
// audit log.
func TestLapsedInsideGraceStillWorksAndWarns(t *testing.T) {
	env := newEntitlementEnv(t, entOptions{enforce: true, grace: time.Hour})
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "laptop")
	entitle(t, env, dev.Account)
	seedStatus(t, env.subs, dev.Account, billing.StatusCanceled, "ev-cancel")

	rec := v3Post(t, env.deviceEnv, dev, "/v1/vaults/vaultA/ops", []byte("op-1"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("in-grace append status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(headerEntitlement); got != "grace" {
		t.Fatalf("%s = %q, want grace", headerEntitlement, got)
	}
	if got := rec.Header().Get(headerEntitlementStatus); got != string(billing.StatusCanceled) {
		t.Fatalf("%s = %q, want canceled", headerEntitlementStatus, got)
	}
	ends := rec.Header().Get(headerEntitlementGraceEnds)
	if ends == "" {
		t.Fatal("no grace-end instant advertised; a warning a client cannot act on is not a warning")
	}
	if _, err := time.Parse(time.RFC3339, ends); err != nil {
		t.Fatalf("%s = %q, not RFC3339: %v", headerEntitlementGraceEnds, ends, err)
	}

	// The read-only warning channel.
	sub := v3Get(t, env.deviceEnv, dev, "/v1/billing/subscription")
	assertOK(t, sub, "subscription")
	var body subscriptionResponse
	if err := json.Unmarshal(sub.Body.Bytes(), &body); err != nil {
		t.Fatalf("subscription body: %v", err)
	}
	if body.Entitlement == nil || body.Entitlement.Writes != "grace" || body.Entitlement.Reads != "allowed" {
		t.Fatalf("entitlement block = %+v, want writes=grace reads=allowed", body.Entitlement)
	}

	if !strings.Contains(env.logs.String(), auditEventEntitlementGrace) {
		t.Fatal("no entitlement.grace audit line was emitted")
	}
	assertNoSecretsInLogs(t, env.logs.String())
}

// ---------------------------------------------------------------------------
// ★ After grace: writes refused, reads and key recovery untouched.
// ---------------------------------------------------------------------------

// TestAfterGraceWritesRefusedReadsAndKeyRecoveryStillWork is the phase's reason
// to exist.
//
// It seeds a fully working account — an op in a vault, a published hybrid key,
// an envelope waiting for the device — then cancels the subscription and lets
// grace expire, and asserts BOTH halves over the real router:
//
//	every WRITE that grows state or reaches ANOTHER account -> 402
//	every READ, and every route a customer needs to GET THEIR KEYS OUT
//	(including giving a SAME-ACCOUNT device the key)          -> 2xx
func TestAfterGraceWritesRefusedReadsAndKeyRecoveryStillWork(t *testing.T) {
	const otherToken = "test-enrollment-token-0000000055"
	env := newEntitlementEnv(t, entOptions{
		enforce: true, grace: tinyGrace,
		tokens: []string{testEnrollToken, otherToken},
	})
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "laptop")
	// A device in a DIFFERENT account: an operator token always founds a new one.
	stranger := enrollDevice(t, env.deviceEnv, otherToken, "stranger")
	if stranger.Account == dev.Account {
		t.Fatal("an operator token must found a NEW account")
	}
	entitle(t, env, dev.Account)

	// Seed real state while entitled.
	publishHybridKey(t, env.deviceEnv, dev)
	if rec := v3Post(t, env.deviceEnv, dev, "/v1/vaults/vaultA/ops", []byte("op-while-paid")); rec.Code != http.StatusCreated {
		t.Fatalf("seed append status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	envelope := randBytes(t, 128)
	if rec := v3Put(t, env.deviceEnv, dev, "/v1/vaults/vaultA/keys/"+dev.ID, envelope); rec.Code != http.StatusCreated {
		t.Fatalf("seed envelope status = %d (body: %s)", rec.Code, rec.Body.String())
	}

	lapse(t, env, dev.Account)

	// ---- WRITES THAT GROW STATE OR REACH ANOTHER ACCOUNT: refused. ----
	assertPaymentRequired(t,
		v3Post(t, env.deviceEnv, dev, "/v1/vaults/vaultA/ops", []byte("op-after-grace")),
		"POST /ops after grace")
	assertPaymentRequired(t,
		v3Put(t, env.deviceEnv, dev, "/v1/vaults/vaultA/keys/"+stranger.ID, randBytes(t, 64)),
		"PUT key envelope to ANOTHER ACCOUNT's device after grace")
	strangerGrant, err := json.Marshal(grantRequest{DeviceID: stranger.ID, Permission: string(store.PermRead)})
	if err != nil {
		t.Fatalf("marshal grant: %v", err)
	}
	assertPaymentRequired(t,
		v3Post(t, env.deviceEnv, dev, "/v1/vaults/vaultA/grants", strangerGrant),
		"POST grant to ANOTHER ACCOUNT's device after grace")

	// ---- ⭐ ESTABLISHING KEY ACCESS INSIDE YOUR OWN ACCOUNT: never refused. ----
	//
	// This is the regression assertion for the defect this fix round closed. Past
	// grace, a customer whose phone died could enroll a replacement but could not
	// be given the VAULT KEY for it, so the new device downloaded ciphertext it
	// could never open — and could not print a recovery kit either (a kit is an
	// ordinary member device, so it lands on exactly this path).
	sibling := joinByInvite(t, env.deviceEnv, mintInvite(t, env.deviceEnv, dev, nil).Invite, "replacement-phone")
	if sibling.Account != dev.Account {
		t.Fatalf("sibling account = %q, want %q", sibling.Account, dev.Account)
	}
	if rec := v3Put(t, env.deviceEnv, dev, "/v1/vaults/vaultA/keys/"+sibling.ID, randBytes(t, 64)); rec.Code != http.StatusCreated {
		t.Fatalf("PUT key envelope to a SAME-ACCOUNT device after grace = %d, want 201: a lapsed customer must still be able to get their own keys onto their own replacement device (body: %s)",
			rec.Code, rec.Body.String())
	}
	siblingGrant, err := json.Marshal(grantRequest{DeviceID: sibling.ID, Permission: string(store.PermRead)})
	if err != nil {
		t.Fatalf("marshal grant: %v", err)
	}
	if rec := v3Post(t, env.deviceEnv, dev, "/v1/vaults/vaultA/grants", siblingGrant); rec.Code != http.StatusCreated {
		t.Fatalf("POST grant to a SAME-ACCOUNT device after grace = %d, want 201: the deposit and its grant are one operation, so gating half of it half-completes a recovery kit (body: %s)",
			rec.Code, rec.Body.String())
	}

	// The refusal changed nothing: the op written while paid is still the tip.
	// (Asserted below by reading it back.)

	// ---- READS AND KEY RECOVERY: every one still served. ----
	list := v3Get(t, env.deviceEnv, dev, "/v1/vaults/vaultA/ops")
	assertOK(t, list, "GET /ops after grace")
	if !strings.Contains(list.Body.String(), "op-while-paid") &&
		!strings.Contains(list.Body.String(), "b3Atd2hpbGUtcGFpZA==") {
		// Blob is std-base64 in the wire shape; accept either rendering.
		var page struct {
			Ops []opJSON `json:"ops"`
		}
		if err := json.Unmarshal(list.Body.Bytes(), &page); err != nil {
			t.Fatalf("ops page: %v", err)
		}
		if len(page.Ops) != 1 || !bytes.Equal(page.Ops[0].Blob, []byte("op-while-paid")) {
			t.Fatalf("lapsed account could not read back its own op: %s", list.Body.String())
		}
	}

	assertOK(t, v3Get(t, env.deviceEnv, dev, "/v1/vaults/vaultA/ops/verify"),
		"GET /ops/verify after grace")

	// ⭐ KEY RECOVERY: the envelope comes back byte-identical, so the customer can
	// still unwrap the vault key and read the codes they already have.
	got := v3Get(t, env.deviceEnv, dev, "/v1/vaults/vaultA/keys/"+dev.ID)
	assertOK(t, got, "GET key envelope after grace")
	if !bytes.Equal(got.Body.Bytes(), envelope) {
		t.Fatal("the key envelope served to a lapsed account was not byte-identical")
	}

	assertOK(t, v3Get(t, env.deviceEnv, dev, "/v1/devices/"+dev.ID+"/keys"),
		"GET per-device envelope index after grace")
	assertOK(t, v3Get(t, env.deviceEnv, dev, "/v1/vaults/vaultA/keys"),
		"GET envelope listing after grace")
	assertOK(t, v3Get(t, env.deviceEnv, dev, "/v1/devices/"+dev.ID+"/hybrid-key"),
		"GET hybrid key after grace")
	assertOK(t, v3Get(t, env.deviceEnv, dev, "/v1/vaults/vaultA/grants"),
		"GET grants after grace")
	assertOK(t, v3Get(t, env.deviceEnv, dev, "/v1/account"),
		"GET account after grace")
	assertOK(t, v3Get(t, env.deviceEnv, dev, "/v1/billing/subscription"),
		"GET subscription after grace")

	// Minting an invite is NOT gated: a customer must always be able to enroll a
	// second device, because losing every device is the one unrecoverable state.
	assertOK(t, v3Post(t, env.deviceEnv, dev, "/v1/account/invites", nil),
		"POST invite after grace")

	// Deleting a stale envelope is a SECURITY REMEDIATION and is NOT gated:
	// rotating away from a compromised device must not depend on the bill.
	assertOK(t, v3Delete(t, env.deviceEnv, dev, "/v1/vaults/vaultA/keys/"+dev.ID),
		"DELETE key envelope after grace")

	// The audit trail records the refusals and never a read refusal.
	logs := env.logs.String()
	if !strings.Contains(logs, auditEventEntitlementRefused) {
		t.Fatal("no entitlement.refused audit line was emitted")
	}
	assertNoSecretsInLogs(t, logs)

	// Metrics moved, and carry no account label.
	metrics := httptest.NewRecorder()
	env.router.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metrics.Body.String(), "sigild_entitlement_enforcing 1") {
		t.Fatal("sigild_entitlement_enforcing is not 1 with enforcement on")
	}
	if strings.Contains(metrics.Body.String(), `sigild_entitlement_decisions_total{outcome="refused"} 0`) {
		t.Fatal("the refused counter did not move")
	}
	if strings.Contains(metrics.Body.String(), dev.Account) {
		t.Fatal("/metrics leaked an account ID")
	}
}

// TestNeverSubscribedIsGracedFromAccountCreation: an account that never bought
// anything is graced from the moment it was created, so "never subscribe" is not
// a permanent free tier — but writes are still served for the whole window.
func TestNeverSubscribedIsGracedFromAccountCreation(t *testing.T) {
	// Long grace: a brand-new account writes normally.
	long := newEntitlementEnv(t, entOptions{enforce: true, grace: time.Hour})
	devLong := enrollDevice(t, long.deviceEnv, testEnrollToken, "fresh")
	rec := v3Post(t, long.deviceEnv, devLong, "/v1/vaults/vaultA/ops", []byte("op-1"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("fresh account append status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(headerEntitlement); got != "grace" {
		t.Fatalf("%s = %q, want grace for a never-subscribed account", headerEntitlement, got)
	}

	// Tiny grace: the same account, past its window, is refused on writes only.
	short := newEntitlementEnv(t, entOptions{enforce: true, grace: tinyGrace})
	devShort := enrollDevice(t, short.deviceEnv, testEnrollToken, "fresh")
	time.Sleep(5 * time.Millisecond)
	assertPaymentRequired(t,
		v3Post(t, short.deviceEnv, devShort, "/v1/vaults/vaultA/ops", []byte("op-1")),
		"never-subscribed append past grace")
	assertOK(t, v3Get(t, short.deviceEnv, devShort, "/v1/vaults/vaultA/ops"),
		"never-subscribed read past grace")
}

// ---------------------------------------------------------------------------
// 402 is not an auth oracle.
// ---------------------------------------------------------------------------

// TestPaymentRequiredIsNotAnAuthOracle: the gate runs strictly AFTER
// authentication and authorization, so only a verified member of the account
// ever sees a 402. An unsigned request still gets 401 and an unauthorized device
// still gets 403 — neither learns anything about anybody's billing state.
func TestPaymentRequiredIsNotAnAuthOracle(t *testing.T) {
	env := newEntitlementEnv(t, entOptions{
		enforce: true, grace: tinyGrace,
		tokens: []string{testEnrollToken, testEnrollToken + "-b"},
	})
	owner := enrollDevice(t, env.deviceEnv, testEnrollToken, "owner")
	stranger := enrollDevice(t, env.deviceEnv, testEnrollToken+"-b", "stranger")
	entitle(t, env, owner.Account)
	if rec := v3Post(t, env.deviceEnv, owner, "/v1/vaults/vaultA/ops", []byte("claim")); rec.Code != http.StatusCreated {
		t.Fatalf("claim status = %d (body: %s)", rec.Code, rec.Body.String())
	}
	lapse(t, env, owner.Account)

	// Unsigned: 401, as always.
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/vaults/vaultA/ops", bytes.NewReader([]byte("x"))))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned write status = %d, want 401 — never 402 (body: %s)", rec.Code, rec.Body.String())
	}

	// Authenticated but not authorized on this vault: 403, as always. The
	// stranger's OWN account is fully entitled, so a 402 here would be leaking
	// the OWNER's billing state to a third party.
	entitle(t, env, stranger.Account)
	assertForbidden(t, v3Post(t, env.deviceEnv, stranger, "/v1/vaults/vaultA/ops", []byte("x")))

	// And the owner, who IS authorized, gets the 402.
	assertPaymentRequired(t, v3Post(t, env.deviceEnv, owner, "/v1/vaults/vaultA/ops", []byte("x")),
		"owner write after grace")
}

// ---------------------------------------------------------------------------
// Fail open.
// ---------------------------------------------------------------------------

// brokenSubscriptionStore fails every read, standing in for a database outage.
type brokenSubscriptionStore struct{}

var errBrokenStore = errors.New("subscription store is down")

func (brokenSubscriptionStore) GetSubscription(context.Context, string) (store.Subscription, error) {
	return store.Subscription{}, errBrokenStore
}

func (brokenSubscriptionStore) ApplyWebhookEvent(context.Context, store.SubscriptionEvent) (store.ApplyOutcome, error) {
	return store.ApplyOutcome{}, errBrokenStore
}

func (brokenSubscriptionStore) StartCheckout(context.Context, string, string, time.Time) error {
	return errBrokenStore
}

// TestEntitlementFailsOpenWhenTheStoreIsDown: a subscription-store outage must
// never cost a customer a write. The request is SERVED, and the fact that
// enforcement silently stopped happening is logged at ERROR so an operator finds
// out from their logs and not from a revenue report.
func TestEntitlementFailsOpenWhenTheStoreIsDown(t *testing.T) {
	env := newEntitlementEnv(t, entOptions{
		enforce: true, grace: tinyGrace, subs: brokenSubscriptionStore{},
	})
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "laptop")

	rec := v3Post(t, env.deviceEnv, dev, "/v1/vaults/vaultA/ops", []byte("op-1"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("append status = %d with a broken store, want 201 (fail OPEN): %s", rec.Code, rec.Body.String())
	}
	assertNoEntitlementHeaders(t, rec, "append during a store outage")
	if !strings.Contains(env.logs.String(), auditEventEntitlementFailOpen) {
		t.Fatal("no entitlement.fail_open audit line was emitted")
	}

	metrics := httptest.NewRecorder()
	env.router.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(metrics.Body.String(), `sigild_entitlement_decisions_total{outcome="fail_open"} 0`) {
		t.Fatal("the fail_open counter did not move")
	}
}

// ---------------------------------------------------------------------------
// The pure policy.
// ---------------------------------------------------------------------------

// TestDecideBoundaries pins the transition arithmetic without any HTTP.
func TestDecideBoundaries(t *testing.T) {
	p := entitlementPolicy{Active: true, Grace: time.Hour}
	base := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)

	for _, tc := range []struct {
		name   string
		status billing.Status
		anchor time.Time
		now    time.Time
		want   entitlementOutcome
	}{
		{"active", billing.StatusActive, time.Time{}, base, entitlementEntitled},
		{"trialing", billing.StatusTrialing, time.Time{}, base, entitlementEntitled},
		{"past_due is entitled", billing.StatusPastDue, base.Add(-10 * time.Hour), base, entitlementEntitled},
		{"canceled, inside grace", billing.StatusCanceled, base, base.Add(59 * time.Minute), entitlementGrace},
		{"canceled, one ns inside", billing.StatusCanceled, base, base.Add(time.Hour - 1), entitlementGrace},
		{"canceled, exactly at the boundary", billing.StatusCanceled, base, base.Add(time.Hour), entitlementRefused},
		{"canceled, past grace", billing.StatusCanceled, base, base.Add(2 * time.Hour), entitlementRefused},
		{"none, past grace", billing.StatusNone, base, base.Add(2 * time.Hour), entitlementRefused},
		{"undatable lapse fails open", billing.StatusCanceled, time.Time{}, base, entitlementFailOpen},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := p.decide(tc.status, tc.anchor, tc.now)
			if got.Outcome != tc.want {
				t.Fatalf("decide = %s, want %s", got.Outcome, tc.want)
			}
		})
	}
}

// TestLapseAnchorTakesTheLaterInstant: a subscription canceled mid-period is
// graced from the END of the period it already paid for, never from the moment
// of cancellation. The rule must always err toward serving the customer.
func TestLapseAnchorTakesTheLaterInstant(t *testing.T) {
	updated := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := updated.Add(20 * 24 * time.Hour)

	if got := lapseAnchor(store.Subscription{UpdatedAt: updated, CurrentPeriodEnd: periodEnd}); !got.Equal(periodEnd) {
		t.Fatalf("anchor = %s, want the paid-through date %s", got, periodEnd)
	}
	if got := lapseAnchor(store.Subscription{UpdatedAt: updated, CurrentPeriodEnd: updated.Add(-time.Hour)}); !got.Equal(updated) {
		t.Fatalf("anchor = %s, want the later update %s", got, updated)
	}
	if got := lapseAnchor(store.Subscription{}); !got.IsZero() {
		t.Fatalf("anchor = %s, want zero (undatable -> fail open)", got)
	}
}

// TestZeroGraceFallsBackToTheDefault: a policy built with no duration uses the
// deliberately generous default rather than refusing instantly.
func TestZeroGraceFallsBackToTheDefault(t *testing.T) {
	p := entitlementPolicy{Active: true}
	base := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if got := p.decide(billing.StatusCanceled, base, base.Add(DefaultEntitlementGrace-time.Second)); got.Outcome != entitlementGrace {
		t.Fatalf("outcome = %s just inside the default grace, want grace", got.Outcome)
	}
	if got := p.decide(billing.StatusCanceled, base, base.Add(DefaultEntitlementGrace+time.Second)); got.Outcome != entitlementRefused {
		t.Fatalf("outcome = %s past the default grace, want refused", got.Outcome)
	}
}

// ---------------------------------------------------------------------------
// ★ The asymmetry, proved structurally.
// ---------------------------------------------------------------------------

// entitlementCallSites are the ONLY handlers permitted to gate on payment. All
// three are WRITES. Changing this list is a deliberate act with a security
// consequence, which is exactly why it must be edited to change behaviour.
var entitlementCallSites = []string{
	"opsAppend",        // POST /v1/vaults/{id}/ops
	"keyEnvelopePut",   // PUT  /v1/vaults/{id}/keys/{deviceID}
	"vaultGrantCreate", // POST /v1/vaults/{id}/grants
}

// mustNeverGate names the routes a lapsed customer depends on. They are listed
// explicitly (rather than left implied by the equality check) so a failure says
// WHICH guarantee was broken.
var mustNeverGate = []string{
	"opsList", "opsVerify", // read the codes you already have
	"keyEnvelopeGet", "deviceKeyEnvelopeIndex", "keyEnvelopeList", // get your keys out
	"keyEnvelopeDelete",                              // revoke a compromised device's copy
	"deviceHybridKeyFetch", "deviceHybridKeyPublish", // participate in key exchange
	"vaultGrantList", "devicesList", "devicesEnroll", "devicesRevoke",
	"accountGet", "accountInviteCreate", "accountInviteList", "accountInviteRevoke",
	"billingCheckout", "billingSubscription", "billingWebhook", // always be able to pay
	"healthz", "readyz", "version", "metricsHandler",
}

// TestRequireEntitlementIsCalledFromWriteHandlersOnly parses THIS PACKAGE'S OWN
// SOURCE and fails if the gate ever appears anywhere but the three write
// handlers.
//
// WHY A SOURCE-LEVEL TEST. The guarantee "a customer who stops paying can still
// read their 2FA codes" is only as strong as the discipline of every future
// edit. A behavioural test proves today's routes; this proves the SHAPE, so
// adding the check to a read handler — or to a helper a read handler calls —
// fails here rather than in production.
func TestRequireEntitlementIsCalledFromWriteHandlersOnly(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	fset := token.NewFileSet()
	callers := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(".", name), nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// The definition itself, and its own file's helpers, are not call sites.
			if fn.Name.Name == "requireEntitlement" {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "requireEntitlement" {
					return true
				}
				callers[fn.Name.Name] = true
				return true
			})
		}
	}

	got := make([]string, 0, len(callers))
	for name := range callers {
		got = append(got, name)
	}
	sort.Strings(got)
	want := append([]string(nil), entitlementCallSites...)
	sort.Strings(want)

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("requireEntitlement call sites = %v, want exactly %v.\n"+
			"⭐ READS AND KEY RECOVERY MUST NEVER BE REFUSED FOR NON-PAYMENT. If you are "+
			"adding a gate, it must be a WRITE, and you must update entitlementCallSites "+
			"deliberately. If you are removing one, say why in the commit.", got, want)
	}

	for _, handler := range mustNeverGate {
		if callers[handler] {
			t.Fatalf("%s gates on entitlement. A customer who stopped paying must still be "+
				"able to reach it — this is the guarantee the whole phase exists to make.", handler)
		}
	}
}

// assertNoSecretsInLogs fails if the audit stream contains anything that must
// never be logged. Entitlement lines carry an account id, a status, a timestamp
// and a surface name — nothing else.
func assertNoSecretsInLogs(t *testing.T, logs string) {
	t.Helper()
	for _, banned := range []string{
		entTestStripeKey, entTestStripeHook, testEnrollToken, testAdminToken,
		"card", "cvv", "pan", "password",
	} {
		if strings.Contains(strings.ToLower(logs), strings.ToLower(banned)) {
			t.Fatalf("audit log contains %q, which must never be logged", banned)
		}
	}
}
