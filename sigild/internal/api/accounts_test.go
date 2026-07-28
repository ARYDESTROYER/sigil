package api

// HTTP-surface tests for the ACCOUNT model (Phase 52).
//
// The two that are the phase's reason to exist are marked ★:
//
//	★ TestEntitlementFollowsTheAccount   — pay on one device, be entitled on its
//	                                       sibling (defect #1)
//	★ TestSiblingSurvivesOwnerRevocation — revoking a vault's claimer no longer
//	                                       orphans the vault (defect #2)
//
// Everything else is the boundary: no request may name an account, no status
// code may distinguish one invite failure from another, and nothing secret may
// reach a body, a metric or a log line.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

// mintInvite mints an invite as dev and returns the 201 body.
func mintInvite(t *testing.T, env *deviceEnv, dev testDevice, body []byte) inviteCreatedResponse {
	t.Helper()
	rec := v3Post(t, env, dev, "/v1/account/invites", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("mint invite status = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	var out inviteCreatedResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("invite body not JSON: %v", err)
	}
	if out.Invite == "" || out.InviteID == "" {
		t.Fatalf("invite response = %+v, want a secret and a handle", out)
	}
	return out
}

// joinByInvite enrolls a NEW device presenting an invite in the SAME
// X-Sigil-Enroll-Token header an operator token uses. Nothing about the request
// shape differs — which is the point: no wire change was needed for a client to
// join an account.
func joinByInvite(t *testing.T, env *deviceEnv, invite, label string) testDevice {
	t.Helper()
	return enrollDevice(t, env, invite, label)
}

// TestAccountRoutesRequireAuthentication: unsigned is 401, and a REVOKED device
// is 401 too — revocation still bites before the signature is checked.
func TestAccountRoutesRequireAuthentication(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "laptop")

	for _, path := range []string{"/v1/account", "/v1/account/invites"} {
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		assertUnauthorized(t, rec)
	}
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/account/invites", nil))
	assertUnauthorized(t, rec)

	if err := env.devices.RevokeDevice(context.Background(), dev.ID, time.Now().UTC()); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	assertUnauthorized(t, v3Post(t, env, dev, "/v1/account/invites", nil))
	assertUnauthorized(t, v3Get(t, env, dev, "/v1/account"))
}

// TestMintIgnoresAccountFieldsInBody: no body field can steer which account an
// invite lands in — there IS no such field, and anything sent is ignored.
func TestMintIgnoresAccountFieldsInBody(t *testing.T) {
	env := newDeviceEnvWithTokens(t, []string{"tok-a-0000000000000000", "tok-b-0000000000000000"}, "")
	devA := enrollDevice(t, env, "tok-a-0000000000000000", "A")
	devB := enrollDevice(t, env, "tok-b-0000000000000000", "B")
	if devA.Account == devB.Account {
		t.Fatal("two operator tokens produced the SAME account")
	}

	body := []byte(`{"account_id":"` + devB.Account + `","subject":"` + devB.Account + `"}`)
	out := mintInvite(t, env, devA, body)
	if out.AccountID != devA.Account {
		t.Fatalf("invite landed in account %q, want the caller's own %q", out.AccountID, devA.Account)
	}

	// And redeeming it joins A, not B.
	joiner := joinByInvite(t, env, out.Invite, "joined")
	if joiner.Account != devA.Account {
		t.Fatalf("joiner landed in %q, want A's account %q", joiner.Account, devA.Account)
	}
}

// TestInviteSecretIsReturnedExactlyOnce: the secret appears in the mint response
// and NOWHERE else — not in a listing, not in /metrics, not in the audit log.
func TestInviteSecretIsReturnedExactlyOnce(t *testing.T) {
	var logs bytes.Buffer
	devices := store.NewMemDeviceStore()
	hash := EnrollTokenHash(testEnrollToken)
	if err := devices.RegisterEnrollmentToken(context.Background(), hash, time.Now().UTC(), time.Time{}); err != nil {
		t.Fatalf("RegisterEnrollmentToken: %v", err)
	}
	router := NewRouter(Config{
		Version:           "test",
		Logger:            slog.New(slog.NewJSONHandler(&logs, nil)),
		DevOpsEnabled:     true,
		Devices:           devices,
		EnrollTokenHashes: []string{hash},
	})
	env := &deviceEnv{router: router, devices: devices}
	dev := enrollDevice(t, env, testEnrollToken, "laptop")

	out := mintInvite(t, env, dev, nil)
	digest := EnrollTokenHash(out.Invite)

	listRec := v3Get(t, env, dev, "/v1/account/invites")
	if listRec.Code != http.StatusOK {
		t.Fatalf("list status = %d (body %s)", listRec.Code, listRec.Body.String())
	}
	if strings.Contains(listRec.Body.String(), out.Invite) {
		t.Fatalf("the invite SECRET was re-served by the listing: %s", listRec.Body.String())
	}
	if strings.Contains(listRec.Body.String(), digest) {
		t.Fatalf("the invite DIGEST was served by the listing: %s", listRec.Body.String())
	}
	var listed struct {
		Invites []inviteJSON `json:"invites"`
	}
	if err := json.Unmarshal(listRec.Body.Bytes(), &listed); err != nil {
		t.Fatalf("list body: %v", err)
	}
	if len(listed.Invites) != 1 || listed.Invites[0].InviteID != out.InviteID {
		t.Fatalf("listing = %+v, want the one minted invite by its PUBLIC handle", listed.Invites)
	}

	metrics := httptest.NewRecorder()
	router.ServeHTTP(metrics, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if strings.Contains(metrics.Body.String(), out.Invite) || strings.Contains(metrics.Body.String(), digest) {
		t.Fatal("/metrics leaked an invite secret or digest")
	}

	if strings.Contains(logs.String(), out.Invite) {
		t.Fatalf("the audit log leaked the invite SECRET")
	}
	if strings.Contains(logs.String(), digest) {
		t.Fatalf("the audit log leaked the invite DIGEST")
	}
	if strings.Contains(logs.String(), testEnrollToken) {
		t.Fatalf("the audit log leaked an enrollment token")
	}
	if !strings.Contains(logs.String(), out.InviteID) {
		t.Fatal("the audit log did not record the PUBLIC invite handle")
	}
}

// TestInviteQuotaAndRevocation: the open-invite cap answers 409 invite_limit, and
// a foreign or missing invite ID is indistinguishable (both 404).
func TestInviteQuotaAndRevocation(t *testing.T) {
	devices := store.NewMemDeviceStore()
	tokens := []string{"tok-a-0000000000000000", "tok-b-0000000000000000"}
	hashes := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		h := EnrollTokenHash(tok)
		hashes = append(hashes, h)
		if err := devices.RegisterEnrollmentToken(context.Background(), h, time.Now().UTC(), time.Time{}); err != nil {
			t.Fatalf("RegisterEnrollmentToken: %v", err)
		}
	}
	router := NewRouter(Config{
		Version:           "test",
		Logger:            discardLogger(),
		DevOpsEnabled:     true,
		Devices:           devices,
		EnrollTokenHashes: hashes,
		AccountMaxInvites: 2,
	})
	env := &deviceEnv{router: router, devices: devices}
	devA := enrollDevice(t, env, tokens[0], "A")
	devB := enrollDevice(t, env, tokens[1], "B")

	first := mintInvite(t, env, devA, nil)
	_ = mintInvite(t, env, devA, nil)
	over := v3Post(t, env, devA, "/v1/account/invites", nil)
	if over.Code != http.StatusConflict {
		t.Fatalf("over-quota mint = %d, want 409 (body %s)", over.Code, over.Body.String())
	}
	if !strings.Contains(over.Body.String(), "invite_limit") {
		t.Fatalf("over-quota body = %s, want invite_limit", over.Body.String())
	}

	// B cannot revoke A's invite, and cannot tell it apart from one that does
	// not exist: both are 404.
	foreign := v3Post(t, env, devB, "/v1/account/invites/"+first.InviteID+"/revoke", nil)
	missing := v3Post(t, env, devB, "/v1/account/invites/inv_does-not-exist/revoke", nil)
	for name, rec := range map[string]*httptest.ResponseRecorder{"foreign": foreign, "missing": missing} {
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s invite revoke = %d, want 404 (body %s)", name, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), "invite_not_found") {
			t.Fatalf("%s revoke body = %s, want invite_not_found", name, rec.Body.String())
		}
	}
	if foreign.Body.String() != missing.Body.String() {
		t.Fatalf("a foreign invite (%s) is distinguishable from a missing one (%s)",
			foreign.Body.String(), missing.Body.String())
	}

	// A revokes its own, and the invite no longer works.
	if rec := v3Post(t, env, devA, "/v1/account/invites/"+first.InviteID+"/revoke", nil); rec.Code != http.StatusOK {
		t.Fatalf("self revoke = %d (body %s)", rec.Code, rec.Body.String())
	}
	pub, priv := newClientKeypair(t)
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, buildEnrollRequest(t, first.Invite, pub, priv, "late", time.Now().Unix(), randNonce(t)))
	assertUnauthorized(t, rec)
}

// TestAccountGetShowsOnlyMyMembers: GET /v1/account is scoped to the caller's
// own account, and there is no way to ask about another.
func TestAccountGetShowsOnlyMyMembers(t *testing.T) {
	env := newDeviceEnvWithTokens(t, []string{"tok-a-0000000000000000", "tok-b-0000000000000000"}, "")
	devA := enrollDevice(t, env, "tok-a-0000000000000000", "A")
	devB := enrollDevice(t, env, "tok-b-0000000000000000", "B")

	invite := mintInvite(t, env, devA, nil)
	sibling := joinByInvite(t, env, invite.Invite, "A-phone")

	rec := v3Get(t, env, devA, "/v1/account")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /v1/account = %d (body %s)", rec.Code, rec.Body.String())
	}
	var resp accountResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body: %v", err)
	}
	if resp.AccountID != devA.Account || resp.DeviceCount != 2 {
		t.Fatalf("account = %+v, want %s with 2 devices", resp, devA.Account)
	}
	ids := map[string]bool{}
	for _, d := range resp.Devices {
		ids[d.DeviceID] = true
		if d.AccountID != devA.Account {
			t.Fatalf("member %s reports account %q", d.DeviceID, d.AccountID)
		}
	}
	if !ids[devA.ID] || !ids[sibling.ID] {
		t.Fatalf("members = %+v, want the founder and the joiner", resp.Devices)
	}
	if ids[devB.ID] {
		t.Fatal("A's account listing included a device from ANOTHER account")
	}

	// B sees only B.
	recB := v3Get(t, env, devB, "/v1/account")
	var respB accountResponse
	if err := json.Unmarshal(recB.Body.Bytes(), &respB); err != nil {
		t.Fatalf("body: %v", err)
	}
	if respB.AccountID != devB.Account || respB.DeviceCount != 1 {
		t.Fatalf("B's account = %+v, want %s with 1 device", respB, devB.Account)
	}
}

// TestInviteEnrollIsWireIdenticalToOperatorEnroll: an invite rides the EXISTING
// header under the EXISTING canonical challenge. The signed bytes differ ONLY
// where the token digest does — no new domain, no new header, no fourth
// canonical layout to keep byte-identical across Go/Rust/JS.
func TestInviteEnrollIsWireIdenticalToOperatorEnroll(t *testing.T) {
	env := newDeviceEnv(t)
	devA := enrollDevice(t, env, testEnrollToken, "A")
	invite := mintInvite(t, env, devA, nil)

	pub, priv := newClientKeypair(t)
	ts, nonce, label := time.Now().Unix(), randNonce(t), "joiner"
	req := buildEnrollRequest(t, invite.Invite, pub, priv, label, ts, nonce)

	// The header the request carries, and the message it signed, are exactly the
	// operator-enrollment shapes with a different credential in them.
	if req.Header.Get(headerEnrollToken) != invite.Invite {
		t.Fatal("the invite did not ride X-Sigil-Enroll-Token")
	}
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	tsStr := strconv.FormatInt(ts, 10)
	wantMsg := canonicalEnrollMessage(EnrollTokenHash(invite.Invite), tsStr, nonce, pubB64, label)
	operatorMsg := canonicalEnrollMessage(EnrollTokenHash(testEnrollToken), tsStr, nonce, pubB64, label)
	if len(wantMsg) != len(operatorMsg) {
		t.Fatal("the invite challenge is not the same SHAPE as the operator challenge")
	}
	if !bytes.HasPrefix(wantMsg, []byte(enrollDomain)) {
		t.Fatal("the invite challenge does not use the EXISTING enrollment domain")
	}

	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("invite enroll = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	var out deviceJSON
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("body: %v", err)
	}
	if out.AccountID != devA.Account {
		t.Fatalf("joiner account = %q, want the inviter's %q", out.AccountID, devA.Account)
	}
}

// TestOperatorTokenAlwaysFoundsANewAccount: there is no operator path that
// inserts a device into an EXISTING account. That would be a trust-model
// expansion smuggled in as convenience.
func TestOperatorTokenAlwaysFoundsANewAccount(t *testing.T) {
	env := newDeviceEnvWithTokens(t, []string{"tok-a-0000000000000000", "tok-b-0000000000000000"}, "")
	devA := enrollDevice(t, env, "tok-a-0000000000000000", "A")
	devB := enrollDevice(t, env, "tok-b-0000000000000000", "B")
	if devA.Account == devB.Account {
		t.Fatal("two operator-token enrollments landed in the SAME account")
	}
	if devA.Account == "" || devB.Account == "" {
		t.Fatal("an operator enrollment produced no account")
	}
}

// ★ TestEntitlementFollowsTheAccount is DEFECT #1's regression test: a customer
// who pays on one device is entitled on their other device, and a device in
// ANOTHER account is not.
func TestEntitlementFollowsTheAccount(t *testing.T) {
	env := newBillingEnv(t)
	// A second operator token for the unrelated third account.
	other := "test-enrollment-token-0000000003"
	if err := env.devices.RegisterEnrollmentToken(t.Context(), EnrollTokenHash(other), time.Now().UTC(), time.Time{}); err != nil {
		t.Fatalf("RegisterEnrollmentToken: %v", err)
	}
	env2 := newRouterWithExtraToken(t, env, other)

	devA := enrollDevice(t, env2, testEnrollToken, "A-laptop")

	// A runs checkout, and the provider webhook activates the subscription.
	if rec := v3Post(t, env2, devA, "/v1/billing/checkout", []byte(`{"provider":"stripe"}`)); rec.Code != http.StatusCreated {
		t.Fatalf("checkout = %d (body %s)", rec.Code, rec.Body.String())
	}
	body := []byte(`{"id":"evt_acct","type":"checkout.session.completed","created":1700000000,` +
		`"data":{"object":{"client_reference_id":"` + devA.Account + `","subscription":"sub_acct"}}}`)
	if rec := serve(env2.router, stripeWebhookRequest(body, apiTestStripeWebhookSec, time.Now().Unix())); rec.Code != http.StatusOK {
		t.Fatalf("webhook = %d (body %s)", rec.Code, rec.Body.String())
	}

	// B joins A's account by invite — and is entitled WITHOUT ever running
	// checkout. This is the whole point of the phase.
	invite := mintInvite(t, env2, devA, nil)
	devB := joinByInvite(t, env2, invite.Invite, "A-phone")
	if devB.Account != devA.Account {
		t.Fatalf("joiner account = %q, want %q", devB.Account, devA.Account)
	}

	recB := v3Get(t, env2, devB, "/v1/billing/subscription")
	var respB subscriptionResponse
	if err := json.Unmarshal(recB.Body.Bytes(), &respB); err != nil {
		t.Fatalf("body: %v", err)
	}
	if respB.Subject != devA.Account {
		t.Fatalf("sibling subject = %q, want the shared account %q", respB.Subject, devA.Account)
	}
	if !respB.Entitled {
		t.Fatalf("a sibling of the payer is NOT entitled: %+v — this is the defect", respB)
	}

	// A device in a DIFFERENT account inherits nothing.
	devC := enrollDevice(t, env2, other, "C")
	recC := v3Get(t, env2, devC, "/v1/billing/subscription")
	var respC subscriptionResponse
	if err := json.Unmarshal(recC.Body.Bytes(), &respC); err != nil {
		t.Fatalf("body: %v", err)
	}
	if respC.Entitled || respC.Status != "none" {
		t.Fatalf("an unrelated account inherited entitlement: %+v", respC)
	}
}

// newRouterWithExtraToken rebuilds a billing router over the SAME stores with an
// extra enrollment token registered, so a test can enroll a third account.
func newRouterWithExtraToken(t *testing.T, env *billingTestEnv, extra string) *deviceEnv {
	t.Helper()
	cfg := billingConfigFor(env)
	router := NewRouter(Config{
		Version:           "test",
		Logger:            discardLogger(),
		DevOpsEnabled:     true,
		Devices:           env.devices,
		EnrollTokenHashes: []string{EnrollTokenHash(testEnrollToken), EnrollTokenHash(extra)},
		AdminToken:        testAdminToken,
		Billing:           cfg,
	})
	return &deviceEnv{router: router, devices: env.devices}
}

// TestCheckoutSubjectIsTheAccountNotTheDevice pins the substitution at the
// provider boundary: the outbound checkout names the ACCOUNT, and a body that
// tries to name a subject is ignored.
func TestCheckoutSubjectIsTheAccountNotTheDevice(t *testing.T) {
	env := newBillingEnv(t)
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "buyer")

	body := []byte(`{"provider":"stripe","subject":"acct_someone_else","account_id":"acct_victim"}`)
	if rec := v3Post(t, env.deviceEnv, dev, "/v1/billing/checkout", body); rec.Code != http.StatusCreated {
		t.Fatalf("checkout = %d (body %s)", rec.Code, rec.Body.String())
	}
	form := env.lastForm()
	if strings.Contains(form, "acct_someone_else") || strings.Contains(form, "acct_victim") {
		t.Fatalf("a client-supplied account reached the provider: %s", form)
	}
	if !strings.Contains(form, dev.Account) {
		t.Fatalf("the provider did not receive dev.AccountID: %s", form)
	}
	if strings.Contains(form, dev.ID) {
		t.Fatalf("the provider received the DEVICE id as subject: %s", form)
	}
}

// accountlessDeviceStore strips the account from every device it returns, so a
// test can drive the INVARIANT VIOLATION path without being able to store such a
// device (the store refuses to create one).
type accountlessDeviceStore struct {
	store.DeviceStore
}

func (s accountlessDeviceStore) GetDevice(ctx context.Context, deviceID string) (store.Device, error) {
	d, err := s.DeviceStore.GetDevice(ctx, deviceID)
	d.AccountID = ""
	return d, err
}

// TestMissingAccountFailsClosed: a device with no account is refused EVERYWHERE
// and NEVER silently falls back to the device ID. The provider and the
// subscription store are not touched.
//
// The refusal is a COARSE 403 — not a 500. A 500 is for a fault the server
// cannot see; this is a data state it reads plainly, and it is reachable (a
// pre-0005 binary writing to an already-migrated database enrols devices with a
// NULL account). Answering 500 buried a repairable condition behind a code
// meaning "the server broke", with no way for an operator to tell the two apart.
// The body is byte-identical to every other 403, so no oracle is created; the
// typed reason reaches only the audit log, and the repair is
// `sigild migrate adopt`.
func TestMissingAccountFailsClosed(t *testing.T) {
	env := newBillingEnv(t)
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "buyer")

	broken := NewRouter(Config{
		Version:           "test",
		Logger:            discardLogger(),
		DevOpsEnabled:     true,
		Devices:           accountlessDeviceStore{env.devices},
		EnrollTokenHashes: []string{EnrollTokenHash(testEnrollToken)},
		Billing:           billingConfigFor(env),
	})
	brokenEnv := &deviceEnv{router: broken, devices: env.devices}
	callsBefore := *env.checkouts

	cases := map[string]*httptest.ResponseRecorder{
		"checkout":     v3Post(t, brokenEnv, dev, "/v1/billing/checkout", []byte(`{"provider":"stripe"}`)),
		"subscription": v3Get(t, brokenEnv, dev, "/v1/billing/subscription"),
		"ops_write":    v3Post(t, brokenEnv, dev, "/v1/vaults/vaultZ/ops", []byte("op")),
		"ops_read":     v3Get(t, brokenEnv, dev, "/v1/vaults/vaultZ/ops"),
		"account":      v3Get(t, brokenEnv, dev, "/v1/account"),
	}
	for name, rec := range cases {
		if rec.Code != http.StatusForbidden {
			t.Fatalf("%s with no account = %d, want 403 (body %s)", name, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "missing_account") {
			t.Fatalf("%s leaked the internal reason: %s", name, rec.Body.String())
		}
		// Byte-identical to every other 403: no oracle.
		if !strings.Contains(rec.Body.String(), `"error":"forbidden"`) {
			t.Fatalf("%s body is not the coarse forbidden body: %s", name, rec.Body.String())
		}
	}
	if *env.checkouts != callsBefore {
		t.Fatal("an accountless device reached the payment provider")
	}
	if _, err := env.subs.GetSubscription(t.Context(), dev.ID); err == nil {
		t.Fatal("an accountless checkout created a DEVICE-keyed subscription row")
	}
	// And the vault was not claimed by the accountless write.
	if _, err := env.devices.GetVaultOwner(t.Context(), "vaultZ"); err == nil {
		t.Fatal("an accountless write claimed a vault")
	}
}

// TestResolveBillingSubjectMapsLegacyDeviceIDs: a webhook echoing a pre-0005
// DEVICE id updates the ACCOUNT's existing row and creates no orphan; one
// echoing an unknown string is BLANKED and creates nothing.
func TestResolveBillingSubjectMapsLegacyDeviceIDs(t *testing.T) {
	env := newBillingEnv(t)
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "buyer")

	if rec := v3Post(t, env.deviceEnv, dev, "/v1/billing/checkout", []byte(`{"provider":"stripe"}`)); rec.Code != http.StatusCreated {
		t.Fatalf("checkout = %d", rec.Code)
	}

	// An IN-FLIGHT pre-cutover checkout: the provider echoes the DEVICE id.
	legacy := []byte(`{"id":"evt_legacy","type":"checkout.session.completed","created":1700000000,` +
		`"data":{"object":{"client_reference_id":"` + dev.ID + `","subscription":"sub_legacy"}}}`)
	rec := serve(env.router, stripeWebhookRequest(legacy, apiTestStripeWebhookSec, time.Now().Unix()))
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy webhook = %d (body %s)", rec.Code, rec.Body.String())
	}
	var resp webhookResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Status != "accepted" {
		t.Fatalf("legacy webhook status = %q, want accepted", resp.Status)
	}
	sub, err := env.subs.GetSubscription(t.Context(), dev.Account)
	if err != nil {
		t.Fatalf("the account's row was not updated: %v", err)
	}
	if !sub.Status.Entitled() {
		t.Fatalf("account status = %q, want entitled", sub.Status)
	}
	if _, err := env.subs.GetSubscription(t.Context(), dev.ID); err == nil {
		t.Fatal("a device-keyed ORPHAN subscription row was created")
	}

	// A subject naming NEITHER an account nor a device is blanked, and with no
	// resolvable subscription reference the event is "unresolved" — a 200 that
	// creates nothing.
	bogus := []byte(`{"id":"evt_bogus","type":"checkout.session.completed","created":1700000000,` +
		`"data":{"object":{"client_reference_id":"acct_not_a_real_subject","subscription":"sub_never_seen"}}}`)
	rec2 := serve(env.router, stripeWebhookRequest(bogus, apiTestStripeWebhookSec, time.Now().Unix()))
	if rec2.Code != http.StatusOK {
		t.Fatalf("bogus webhook = %d, want 200", rec2.Code)
	}
	var resp2 webhookResponse
	_ = json.Unmarshal(rec2.Body.Bytes(), &resp2)
	if resp2.Status != "unresolved" {
		t.Fatalf("bogus webhook status = %q, want unresolved", resp2.Status)
	}
	if _, err := env.subs.GetSubscription(t.Context(), "acct_not_a_real_subject"); err == nil {
		t.Fatal("a provider-supplied string INVENTED a subscription row")
	}
}

// ★ TestSiblingSurvivesOwnerRevocation is DEFECT #2's regression test: revoking
// the device that claimed a vault no longer orphans it. Before Phase 52 every
// assertion below was a 403.
func TestSiblingSurvivesOwnerRevocation(t *testing.T) {
	env := newDeviceEnv(t)
	devA := enrollDevice(t, env, testEnrollToken, "A-laptop")
	invite := mintInvite(t, env, devA, nil)
	devB := joinByInvite(t, env, invite.Invite, "A-phone")
	// A third device, in ANOTHER account, that B can grant access to.
	if err := env.devices.RegisterEnrollmentToken(context.Background(),
		EnrollTokenHash("tok-outsider-000000000000"), time.Now().UTC(), time.Time{}); err != nil {
		t.Fatalf("RegisterEnrollmentToken: %v", err)
	}
	outsiderEnv := newDeviceEnvSharing(t, env, "tok-outsider-000000000000")
	outsider := enrollDevice(t, outsiderEnv, "tok-outsider-000000000000", "outsider")

	// A claims the vault, then is revoked.
	if rec := v3Post(t, env, devA, "/v1/vaults/vaultA/ops", []byte("first")); rec.Code != http.StatusCreated {
		t.Fatalf("A claim = %d (body %s)", rec.Code, rec.Body.String())
	}
	if err := env.devices.RevokeDevice(context.Background(), devA.ID, time.Now().UTC()); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}

	// B holds NO grant row on that vault...
	if _, err := env.devices.GetGrant(context.Background(), "vaultA", devB.ID); err == nil {
		t.Fatal("the sibling unexpectedly holds a grant — the test is not proving inheritance")
	}
	// ...yet can append, grant, list envelopes and delete one.
	if rec := v3Post(t, outsiderEnv, devB, "/v1/vaults/vaultA/ops", []byte("second")); rec.Code != http.StatusCreated {
		t.Fatalf("sibling append = %d, want 201 (body %s) — the vault was ORPHANED", rec.Code, rec.Body.String())
	}
	grantBody, _ := json.Marshal(grantRequest{DeviceID: outsider.ID, Permission: "read"})
	if rec := v3Post(t, outsiderEnv, devB, "/v1/vaults/vaultA/grants", grantBody); rec.Code != http.StatusCreated {
		t.Fatalf("sibling grant = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
	if rec := v3Get(t, outsiderEnv, devB, "/v1/vaults/vaultA/keys"); rec.Code != http.StatusOK {
		t.Fatalf("sibling key list = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	del := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/v1/vaults/vaultA/keys/"+outsider.ID, nil)
	signV3(t, req, devB, time.Now().Unix(), randNonce(t), nil)
	outsiderEnv.router.ServeHTTP(del, req)
	if del.Code != http.StatusNotFound {
		// 404 envelope_not_found is the AUTHORIZED answer for "nothing to delete";
		// a 403 would mean the sibling could not reach the route at all.
		t.Fatalf("sibling envelope delete = %d, want 404 envelope_not_found (body %s)", del.Code, del.Body.String())
	}
}

// newDeviceEnvSharing builds a SECOND router over the SAME registry with an
// extra enrollment token, so a test can enroll a device in another account
// without disturbing the first router's state.
func newDeviceEnvSharing(t *testing.T, env *deviceEnv, extra string) *deviceEnv {
	t.Helper()
	router := NewRouter(Config{
		Version:           "test",
		Logger:            discardLogger(),
		DevOpsEnabled:     true,
		Devices:           env.devices,
		EnrollTokenHashes: []string{EnrollTokenHash(testEnrollToken), EnrollTokenHash(extra)},
		AdminToken:        testAdminToken,
	})
	return &deviceEnv{router: router, devices: env.devices}
}

// TestWriteNoClaimStillCannotClaim re-asserts the Phase 51 fix against the NEW
// authority (sigil_vault_owners): a read-shaped route must never make its caller
// an owner.
func TestWriteNoClaimStillCannotClaim(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "laptop")

	assertForbidden(t, v3Get(t, env, dev, "/v1/vaults/never-claimed/keys"))
	if _, err := env.devices.GetVaultOwner(context.Background(), "never-claimed"); err == nil {
		t.Fatal("GET …/keys CLAIMED an unowned vault")
	}
	if grants, _ := env.devices.ListGrants(context.Background(), "never-claimed"); len(grants) != 0 {
		t.Fatalf("GET …/keys created %d grants, want 0", len(grants))
	}
}

// TestNeedOwnerIsAccountOwnershipOnly: a device holding an IS_OWNER GRANT on a
// vault its ACCOUNT does not own is still 403 on a needOwner route. Ownership is
// an ACCOUNT property, full stop, and no grant row — not even the owner flag —
// can confer it.
//
// THE STATE UNDER TEST IS DATA DRIFT THE API CANNOT PRODUCE, which is the whole
// point: ClaimVault writes the owner row and the is_owner grant together, so the
// two can only disagree if something else wrote them (a pre-0005 binary, a
// hand-edited row, a future bug). It is constructed here by calling ClaimVault
// with one account's ID and ANOTHER account's device ID — real rows in the real
// store, in both backends, with no test double at the seam.
//
// An earlier version of this test used PutGrant, which writes Owner:false. It
// therefore never built an is_owner grant at all and only re-tested "a write
// grant is not ownership" (already covered by TestCrossAccountIsolation) — it
// survived a mutation that made authorizeByGrant honour a legacy owner grant.
// This version fails against that mutation.
func TestNeedOwnerIsAccountOwnershipOnly(t *testing.T) {
	env := newDeviceEnvWithTokens(t, []string{"tok-a-0000000000000000", "tok-b-0000000000000000"}, "")
	devA := enrollDevice(t, env, "tok-a-0000000000000000", "A")
	devB := enrollDevice(t, env, "tok-b-0000000000000000", "B")
	if devA.Account == devB.Account {
		t.Fatal("two operator tokens produced the SAME account")
	}

	// THE DRIFT: vault "driftVault" is owned by account A, while the is_owner
	// GRANT row on it names device B — a device of account B.
	ctx := context.Background()
	claimed, owner, err := env.devices.ClaimVault(ctx, "driftVault", devA.Account, devB.ID, time.Now().UTC())
	if err != nil || !claimed {
		t.Fatalf("seed drift: ClaimVault = (%v, %+v, %v), want claimed", claimed, owner, err)
	}
	if owner.AccountID != devA.Account {
		t.Fatalf("seeded owner = %q, want A's account %q", owner.AccountID, devA.Account)
	}
	grant, err := env.devices.GetGrant(ctx, "driftVault", devB.ID)
	if err != nil {
		t.Fatalf("seed drift: GetGrant: %v", err)
	}
	if !grant.Owner {
		t.Fatalf("seeded grant = %+v, want is_owner=true — the test is not testing what it claims to", grant)
	}

	// B's owner GRANT is a write grant, so B can write...
	if rec := v3Post(t, env, devB, "/v1/vaults/driftVault/ops", []byte("granted")); rec.Code != http.StatusCreated {
		t.Fatalf("granted write = %d (body %s)", rec.Code, rec.Body.String())
	}
	// ...but it must NOT let B ADMINISTER a vault account A owns.
	body, _ := json.Marshal(grantRequest{DeviceID: devB.ID, Permission: "read"})
	assertForbidden(t, v3Post(t, env, devB, "/v1/vaults/driftVault/grants", body))

	// And the account that genuinely owns it still can, WITHOUT any grant row of
	// its own — so the 403 above is about ownership, not about being locked out.
	if _, gerr := env.devices.GetGrant(ctx, "driftVault", devA.ID); !errors.Is(gerr, store.ErrGrantNotFound) {
		t.Fatalf("device A unexpectedly holds a grant (err = %v)", gerr)
	}
	if rec := v3Post(t, env, devA, "/v1/vaults/driftVault/grants", body); rec.Code != http.StatusCreated {
		t.Fatalf("owning account grant = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestCrossAccountIsolation: a device of account B cannot reach account A's
// vault in ANY of the ways the surface offers, and a READ grant does not become
// a write or an ownership.
func TestCrossAccountIsolation(t *testing.T) {
	env := newDeviceEnvWithTokens(t, []string{"tok-a-0000000000000000", "tok-b-0000000000000000"}, "")
	devA := enrollDevice(t, env, "tok-a-0000000000000000", "A")
	devB := enrollDevice(t, env, "tok-b-0000000000000000", "B")

	if rec := v3Post(t, env, devA, "/v1/vaults/vaultA/ops", []byte("first")); rec.Code != http.StatusCreated {
		t.Fatalf("A claim = %d", rec.Code)
	}

	for _, path := range []string{
		"/v1/vaults/vaultA/ops",
		"/v1/vaults/vaultA/ops/verify",
		"/v1/vaults/vaultA/grants",
		"/v1/vaults/vaultA/keys",
		"/v1/vaults/vaultA/keys/" + devA.ID,
	} {
		assertForbidden(t, v3Get(t, env, devB, path))
	}
	assertForbidden(t, v3Post(t, env, devB, "/v1/vaults/vaultA/ops", []byte("intrusion")))

	// A grants B READ. B can now read, but nothing more.
	grantBody, _ := json.Marshal(grantRequest{DeviceID: devB.ID, Permission: "read"})
	if rec := v3Post(t, env, devA, "/v1/vaults/vaultA/grants", grantBody); rec.Code != http.StatusCreated {
		t.Fatalf("grant = %d (body %s)", rec.Code, rec.Body.String())
	}
	if rec := v3Get(t, env, devB, "/v1/vaults/vaultA/ops"); rec.Code != http.StatusOK {
		t.Fatalf("granted read = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	assertForbidden(t, v3Post(t, env, devB, "/v1/vaults/vaultA/ops", []byte("still no")))
	assertForbidden(t, v3Post(t, env, devB, "/v1/vaults/vaultA/grants", grantBody))
	// Someone ELSE's envelope stays 403 — never 401, never 404.
	assertForbidden(t, v3Get(t, env, devB, "/v1/vaults/vaultA/keys/"+devA.ID))
}

// TestSiblingRevocation: a member may revoke a sibling; a non-member may not;
// and a NON-ADMIN caller gets 403 for an unknown device — never a 404, which
// would be an existence oracle.
func TestSiblingRevocation(t *testing.T) {
	env := newDeviceEnvWithTokens(t,
		[]string{"tok-a-0000000000000000", "tok-b-0000000000000000"}, testAdminToken)
	devA := enrollDevice(t, env, "tok-a-0000000000000000", "A")
	outsider := enrollDevice(t, env, "tok-b-0000000000000000", "outsider")

	invite := mintInvite(t, env, devA, nil)
	sibling := joinByInvite(t, env, invite.Invite, "A-phone")

	// A member revokes its sibling.
	if rec := v3Post(t, env, devA, "/v1/devices/"+sibling.ID+"/revoke", nil); rec.Code != http.StatusOK {
		t.Fatalf("sibling revoke = %d, want 200 (body %s)", rec.Code, rec.Body.String())
	}
	stored, err := env.devices.GetDevice(context.Background(), sibling.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if stored.Status != store.DeviceRevoked {
		t.Fatalf("sibling status = %q, want revoked", stored.Status)
	}

	// A non-member may not.
	assertForbidden(t, v3Post(t, env, outsider, "/v1/devices/"+devA.ID+"/revoke", nil))

	// An UNKNOWN device is 403 to a non-admin, NOT 404.
	unknown := v3Post(t, env, outsider, "/v1/devices/dev_does-not-exist/revoke", nil)
	if unknown.Code != http.StatusForbidden {
		t.Fatalf("unknown-device revoke as a non-admin = %d, want 403 (an existence oracle otherwise)", unknown.Code)
	}
	foreign := v3Post(t, env, outsider, "/v1/devices/"+devA.ID+"/revoke", nil)
	if unknown.Body.String() != foreign.Body.String() {
		t.Fatalf("unknown (%s) is distinguishable from foreign (%s)",
			unknown.Body.String(), foreign.Body.String())
	}

	// The ADMIN path keeps its 404 (an operator can already enumerate devices).
	adminReq := httptest.NewRequest(http.MethodPost, "/v1/devices/dev_still-missing/revoke", nil)
	adminReq.Header.Set(headerAdminToken, testAdminToken)
	adminRec := httptest.NewRecorder()
	env.router.ServeHTTP(adminRec, adminReq)
	if adminRec.Code != http.StatusNotFound {
		t.Fatalf("admin revoke of an unknown device = %d, want 404", adminRec.Code)
	}
}

// TestAccountDenialBodiesAreCoarse: every new denial answers with the SAME two
// bodies, and no response anywhere names the internal reason.
func TestAccountDenialBodiesAreCoarse(t *testing.T) {
	env := newDeviceEnvWithTokens(t, []string{"tok-a-0000000000000000", "tok-b-0000000000000000"}, "")
	devA := enrollDevice(t, env, "tok-a-0000000000000000", "A")
	devB := enrollDevice(t, env, "tok-b-0000000000000000", "B")
	if rec := v3Post(t, env, devA, "/v1/vaults/vaultA/ops", []byte("first")); rec.Code != http.StatusCreated {
		t.Fatalf("A claim = %d", rec.Code)
	}

	forbidden := []*httptest.ResponseRecorder{
		v3Get(t, env, devB, "/v1/vaults/vaultA/ops"),                // forbidden_account
		v3Get(t, env, devB, "/v1/vaults/unclaimed-vault/ops"),       // unauthorized_vault
		v3Post(t, env, devB, "/v1/devices/"+devA.ID+"/revoke", nil), // forbidden_device
	}
	for i, rec := range forbidden {
		if rec.Code != http.StatusForbidden {
			t.Fatalf("case %d = %d, want 403 (body %s)", i, rec.Code, rec.Body.String())
		}
		var body apiError
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("case %d body: %v", i, err)
		}
		if body.Error != "forbidden" {
			t.Fatalf("case %d error = %q, want forbidden", i, body.Error)
		}
		for _, leak := range []string{
			"forbidden_account", "unauthorized_vault", "forbidden_device",
			"missing_account", "not_vault_owner", "account_full",
		} {
			if strings.Contains(rec.Body.String(), leak) {
				t.Fatalf("case %d leaked the internal reason %q: %s", i, leak, rec.Body.String())
			}
		}
	}
}

// TestAuthDenyMetricIsNotAVaultExistenceOracle pins the Phase 57 fix for a real
// oracle: /metrics is UNAUTHENTICATED and ALWAYS ON, and it used to move a
// DIFFERENT counter depending on whether the probed vault existed —
// forbidden_account for a vault owned by another account, unauthorized_vault for
// a vault id that had never existed — even though the client-visible answer was
// byte-identical in both cases (403 {"error":"forbidden"}).
//
// A scrape before and after one request therefore answered "does this vault id
// exist?". The two now share ONE coarse label; the fine reason still reaches the
// audit log (asserted below), which is the pattern the enroll path already used.
func TestAuthDenyMetricIsNotAVaultExistenceOracle(t *testing.T) {
	var logs bytes.Buffer
	devices := store.NewMemDeviceStore()
	for _, tok := range []string{"tok-a-0000000000000000", "tok-b-0000000000000000"} {
		if err := devices.RegisterEnrollmentToken(context.Background(),
			EnrollTokenHash(tok), time.Now().UTC(), time.Time{}); err != nil {
			t.Fatalf("RegisterEnrollmentToken: %v", err)
		}
	}
	env := &deviceEnv{devices: devices, router: NewRouter(Config{
		Version:       "test",
		Logger:        slog.New(slog.NewJSONHandler(&logs, nil)),
		DevOpsEnabled: true,
		Devices:       devices,
		EnrollTokenHashes: []string{
			EnrollTokenHash("tok-a-0000000000000000"),
			EnrollTokenHash("tok-b-0000000000000000"),
		},
	})}
	devA := enrollDevice(t, env, "tok-a-0000000000000000", "A")
	devB := enrollDevice(t, env, "tok-b-0000000000000000", "B")
	if rec := v3Post(t, env, devA, "/v1/vaults/vaultExists/ops", []byte("first")); rec.Code != http.StatusCreated {
		t.Fatalf("A claim = %d", rec.Code)
	}

	scrape := func() map[string]int {
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		out := map[string]int{}
		for _, line := range strings.Split(rec.Body.String(), "\n") {
			if !strings.HasPrefix(line, "sigild_oplog_auth_denied_total{") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) != 2 {
				continue
			}
			var n int
			if _, err := fmt.Sscanf(parts[1], "%d", &n); err == nil {
				out[parts[0]] = n
			}
		}
		return out
	}
	delta := func(before, after map[string]int) []string {
		var moved []string
		for k, v := range after {
			if v != before[k] {
				moved = append(moved, k)
			}
		}
		sort.Strings(moved)
		return moved
	}

	// Probe a vault that EXISTS (owned by another account).
	b1 := scrape()
	if rec := v3Get(t, env, devB, "/v1/vaults/vaultExists/ops"); rec.Code != http.StatusForbidden {
		t.Fatalf("probe of an existing vault = %d, want 403", rec.Code)
	}
	existsMoved := delta(b1, scrape())

	// Probe a vault id that has NEVER existed.
	b2 := scrape()
	if rec := v3Get(t, env, devB, "/v1/vaults/vaultNeverExisted/ops"); rec.Code != http.StatusForbidden {
		t.Fatalf("probe of a never-existent vault = %d, want 403", rec.Code)
	}
	missingMoved := delta(b2, scrape())

	if len(existsMoved) == 0 || len(missingMoved) == 0 {
		t.Fatalf("no counter moved at all (exists=%v missing=%v)", existsMoved, missingMoved)
	}
	if !reflect.DeepEqual(existsMoved, missingMoved) {
		t.Fatalf("/metrics distinguishes an EXISTING vault from a never-existent one: "+
			"exists moved %v, missing moved %v — that is a vault-existence oracle on an "+
			"unauthenticated, always-on endpoint", existsMoved, missingMoved)
	}
	if strings.Contains(scrapeBody(t, env.router), `reason="forbidden_account"`) {
		t.Fatalf("forbidden_account is still an exported metric label")
	}

	// The operator has NOT lost the signal: the fine reason is in the audit log.
	text := logs.String()
	for _, want := range []string{"forbidden_account", "unauthorized_vault"} {
		if !strings.Contains(text, want) {
			t.Fatalf("audit log lost the fine-grained reason %q:\n%s", want, text)
		}
	}
}

// scrapeBody returns the raw /metrics text for a router.
func scrapeBody(t *testing.T, router http.Handler) string {
	t.Helper()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	return rec.Body.String()
}

// TestAccountFullNeedsAValidCredentialFirst: account_full is a distinct 409, and
// it is reachable ONLY after a resolved invite AND a valid proof of possession —
// exactly like device_exists. A prober with no invite learns nothing.
func TestAccountFullNeedsAValidCredentialFirst(t *testing.T) {
	devices := store.NewMemDeviceStore()
	hash := EnrollTokenHash(testEnrollToken)
	if err := devices.RegisterEnrollmentToken(context.Background(), hash, time.Now().UTC(), time.Time{}); err != nil {
		t.Fatalf("RegisterEnrollmentToken: %v", err)
	}
	router := NewRouter(Config{
		Version:           "test",
		Logger:            discardLogger(),
		DevOpsEnabled:     true,
		Devices:           devices,
		EnrollTokenHashes: []string{hash},
		AccountMaxDevices: 1, // the founder alone fills the account
	})
	env := &deviceEnv{router: router, devices: devices}
	dev := enrollDevice(t, env, testEnrollToken, "only")

	// Minting is refused up front...
	rec := v3Post(t, env, dev, "/v1/account/invites", nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "account_full") {
		t.Fatalf("mint at cap = %d (%s), want 409 account_full", rec.Code, rec.Body.String())
	}

	// ...and a credential minted BEFORE the cap was reached still cannot exceed
	// it. Seed one directly so the cap is the only thing standing in the way.
	secret := "join_test_secret_for_full_account"
	inv := store.AccountInvite{
		InviteHash:        EnrollTokenHash(secret),
		InviteID:          "inv_full_test",
		AccountID:         dev.Account,
		CreatedByDeviceID: dev.ID,
		CreatedAt:         time.Now().UTC(),
		ExpiresAt:         time.Now().UTC().Add(time.Hour),
	}
	if err := devices.CreateAccountInvite(context.Background(), inv, 5); err != nil {
		t.Fatalf("CreateAccountInvite: %v", err)
	}
	pub, priv := newClientKeypair(t)
	full := httptest.NewRecorder()
	env.router.ServeHTTP(full, buildEnrollRequest(t, secret, pub, priv, "overflow", time.Now().Unix(), randNonce(t)))
	if full.Code != http.StatusConflict || !strings.Contains(full.Body.String(), "account_full") {
		t.Fatalf("join at cap = %d (%s), want 409 account_full", full.Code, full.Body.String())
	}

	// A BAD credential with a valid proof is still the coarse 401 — the cap is
	// never revealed to someone who did not hold an invite.
	bad := httptest.NewRecorder()
	pub2, priv2 := newClientKeypair(t)
	env.router.ServeHTTP(bad, buildEnrollRequest(t, "join_not_a_real_invite_at_all", pub2, priv2,
		"prober", time.Now().Unix(), randNonce(t)))
	assertUnauthorized(t, bad)
}

// ★ TestRevokedDeviceFreesASeat: the device cap bounds CONCURRENT devices, not
// LIFETIME enrollments. Revoking a member FREES its seat, over the whole HTTP
// surface — GET /v1/account, POST /v1/account/invites and the join itself.
//
// WHY THIS IS THE WORST BUG THIS PHASE COULD HAVE SHIPPED: every remedy the
// account model prescribes is "revoke and re-enroll" — a compromised device, a
// device that joined the wrong account, a lost phone. If a revoked row kept its
// seat, each remedy would burn one permanently. At the default of 10 an account
// that replaced its devices ten times could never enroll another; when its
// surviving devices died the account, its vaults and its subscription would be
// unreachable forever, with NO operation anywhere able to free a seat. It is
// also an ATTACK: nothing rate-limits enrolment or invite minting, so a device
// that got in through a leaked bearer invite could mint invites and join
// throwaways until the cap was exhausted.
func TestRevokedDeviceFreesASeat(t *testing.T) {
	devices := store.NewMemDeviceStore()
	hash := EnrollTokenHash(testEnrollToken)
	if err := devices.RegisterEnrollmentToken(context.Background(), hash, time.Now().UTC(), time.Time{}); err != nil {
		t.Fatalf("RegisterEnrollmentToken: %v", err)
	}
	router := NewRouter(Config{
		Version:           "test",
		Logger:            discardLogger(),
		DevOpsEnabled:     true,
		Devices:           devices,
		EnrollTokenHashes: []string{hash},
		AdminToken:        testAdminToken,
		AccountMaxDevices: 2,
	})
	env := &deviceEnv{router: router, devices: devices}
	founder := enrollDevice(t, env, testEnrollToken, "founder")

	readAccount := func(dev testDevice, where string) accountResponse {
		t.Helper()
		rec := v3Get(t, env, dev, "/v1/account")
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /v1/account (%s) = %d (body %s)", where, rec.Code, rec.Body.String())
		}
		var out accountResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("account body not JSON: %v", err)
		}
		return out
	}

	// Fill the account to 2/2.
	second := joinByInvite(t, env, mintInvite(t, env, founder, nil).Invite, "phone")
	acct := readAccount(founder, "full")
	if acct.DeviceCount != 2 || acct.DeviceLimit != 2 || acct.RevokedDeviceCount != 0 {
		t.Fatalf("account at cap = %+v, want device_count=2 limit=2 revoked=0", acct)
	}
	// The cap HOLDS against active devices.
	rec := v3Post(t, env, founder, "/v1/account/invites", nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "account_full") {
		t.Fatalf("mint at cap = %d (%s), want 409 account_full", rec.Code, rec.Body.String())
	}

	// Revoke the second device — the remedy the model prescribes.
	if rec := v3Post(t, env, founder, "/v1/devices/"+second.ID+"/revoke", nil); rec.Code != http.StatusOK {
		t.Fatalf("sibling revoke = %d (body %s)", rec.Code, rec.Body.String())
	}

	// THE SEAT CAME BACK: the count drops, the revoked row is reported
	// separately, and it is still LISTED so no history is hidden.
	after := readAccount(founder, "after revoke")
	if after.DeviceCount != 1 {
		t.Fatalf("device_count after revoke = %d, want 1 (a revoked device still holds a seat)", after.DeviceCount)
	}
	if after.RevokedDeviceCount != 1 {
		t.Fatalf("revoked_device_count = %d, want 1", after.RevokedDeviceCount)
	}
	if len(after.Devices) != 2 {
		t.Fatalf("devices listed = %d, want 2 (history is kept, it just does not count)", len(after.Devices))
	}

	// And the account can enroll again — permanently-stuck was the whole defect.
	replacement := joinByInvite(t, env, mintInvite(t, env, founder, nil).Invite, "new-phone")
	if replacement.Account != founder.Account {
		t.Fatalf("replacement joined %q, want the founder's account %q", replacement.Account, founder.Account)
	}
	refilled := readAccount(founder, "refilled")
	if refilled.DeviceCount != 2 || refilled.RevokedDeviceCount != 1 {
		t.Fatalf("refilled account = %+v, want device_count=2 revoked_device_count=1", refilled)
	}
	// ...and the cap holds again at the new 2/2.
	rec = v3Post(t, env, founder, "/v1/account/invites", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("mint at the refilled cap = %d, want 409 (body %s)", rec.Code, rec.Body.String())
	}
	// The revoked device is still revoked: freeing its SEAT never un-revoked it.
	assertUnauthorized(t, v3Get(t, env, second, "/v1/account"))
}

// unresolvedOwnerStore makes ClaimVault report the ORPHANED-OWNER state that
// cannot be reconciled: a vault with a legacy is_owner grant whose device has no
// account at all.
//
// It is a double because no real backend can be driven into that state in
// memory — MemDeviceStore refuses to store an accountless device, and the
// Postgres path needs a NULL account_id column value that only a pre-0005 binary
// writes. The RECONCILABLE case is covered for real, in both backends, by
// runAccountsSuite/OrphanOwnerGrantIsReconciled in the store package; that is
// also where the original 500 lived, since the collision it came from is the
// partial unique index sigil_device_grants_one_owner.
type unresolvedOwnerStore struct {
	store.DeviceStore
	vaultID string
}

func (s unresolvedOwnerStore) ClaimVault(ctx context.Context, vaultID, accountID, deviceID string, at time.Time) (bool, store.VaultOwner, error) {
	if vaultID == s.vaultID {
		return false, store.VaultOwner{}, store.ErrVaultOwnerUnresolved
	}
	return s.DeviceStore.ClaimVault(ctx, vaultID, accountID, deviceID, at)
}

// TestUnresolvableVaultOwnerIsForbiddenNotAFault: a vault whose ownership cannot
// be resolved is a coarse 403, never an opaque 500.
//
// Both halves matter. The state is REAL and reachable — a pre-0005 binary claims
// a vault by writing an is_owner grant and no owner row, and enrolls devices
// with account_id NULL — and it is REPAIRABLE (`sigild migrate adopt`). A 500
// meant an operator could not tell a repairable data state from a database
// outage, while a client saw "the server broke" forever. It still fails CLOSED,
// and the body stays byte-identical to every other 403 so no oracle appears.
func TestUnresolvableVaultOwnerIsForbiddenNotAFault(t *testing.T) {
	devices := store.NewMemDeviceStore()
	hash := EnrollTokenHash(testEnrollToken)
	if err := devices.RegisterEnrollmentToken(context.Background(), hash, time.Now().UTC(), time.Time{}); err != nil {
		t.Fatalf("RegisterEnrollmentToken: %v", err)
	}
	var logs bytes.Buffer
	router := NewRouter(Config{
		Version:           "test",
		Logger:            slog.New(slog.NewJSONHandler(&logs, nil)),
		DevOpsEnabled:     true,
		Devices:           unresolvedOwnerStore{DeviceStore: devices, vaultID: "vault-orphaned"},
		EnrollTokenHashes: []string{hash},
	})
	env := &deviceEnv{router: router, devices: devices}
	dev := enrollDevice(t, env, testEnrollToken, "writer")

	rec := v3Post(t, env, dev, "/v1/vaults/vault-orphaned/ops", []byte("push"))
	if rec.Code == http.StatusInternalServerError {
		t.Fatalf("unresolvable vault owner = 500 %s, want a coarse 403", rec.Body.String())
	}
	assertForbidden(t, rec)
	if strings.Contains(rec.Body.String(), "vault_owner_unresolved") {
		t.Fatalf("the typed reason leaked to the client: %s", rec.Body.String())
	}

	// The operator DOES get to see it — that is the whole point of naming the
	// state instead of reporting a fault.
	if !strings.Contains(logs.String(), "vault_owner_unresolved") {
		t.Fatalf("audit log does not name the state:\n%s", logs.String())
	}

	// A different vault is unaffected: the refusal is about that vault's data,
	// not a broken server.
	if rec := v3Post(t, env, dev, "/v1/vaults/vault-fine/ops", []byte("push")); rec.Code != http.StatusCreated {
		t.Fatalf("unrelated vault write = %d, want 201 (body %s)", rec.Code, rec.Body.String())
	}
}

// TestAccountMetricsCarryNoIdentifiers: /metrics must never let an
// unauthenticated scrape enumerate accounts, devices or invites.
func TestAccountMetricsCarryNoIdentifiers(t *testing.T) {
	env := newDeviceEnv(t)
	devA := enrollDevice(t, env, testEnrollToken, "A")
	invite := mintInvite(t, env, devA, nil)
	sibling := joinByInvite(t, env, invite.Invite, "phone")
	second := mintInvite(t, env, devA, nil)
	if rec := v3Post(t, env, devA, "/v1/account/invites/"+second.InviteID+"/revoke", nil); rec.Code != http.StatusOK {
		t.Fatalf("revoke = %d", rec.Code)
	}
	if rec := v3Post(t, env, devA, "/v1/vaults/vaultA/ops", []byte("op")); rec.Code != http.StatusCreated {
		t.Fatalf("append = %d", rec.Code)
	}
	if rec := v3Get(t, env, sibling, "/v1/account"); rec.Code != http.StatusOK {
		t.Fatalf("account = %d", rec.Code)
	}

	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := rec.Body.String()
	for _, want := range []string{
		"sigild_accounts_created_total",
		"sigild_account_invites_created_total",
		"sigild_account_invites_revoked_total",
		"sigild_account_joins_total",
		`sigild_oplog_auth_denied_total{reason="missing_account"}`,
		`sigild_device_enroll_denied_total{reason="account_full"}`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/metrics missing %q", want)
		}
	}
	for _, leak := range []string{"acct_", "dev_", "inv_", "join_"} {
		if strings.Contains(body, leak) {
			t.Fatalf("/metrics leaked an identifier prefix %q:\n%s", leak, body)
		}
	}
}

// TestAccountRoutesAre501WhenDisabled: dev-gated routes answer 501, never 404 —
// with dev-ops off, and with dev-ops on but no device registry.
func TestAccountRoutesAre501WhenDisabled(t *testing.T) {
	paths := []struct{ method, path string }{
		{http.MethodGet, "/v1/account"},
		{http.MethodPost, "/v1/account/invites"},
		{http.MethodGet, "/v1/account/invites"},
		{http.MethodPost, "/v1/account/invites/inv_x/revoke"},
	}
	for _, cfg := range []Config{
		{Version: "test", Logger: discardLogger()},                                     // dev-ops off
		{Version: "test", Logger: discardLogger(), DevOpsEnabled: true},                // no registry
		{Version: "test", Logger: discardLogger(), Devices: store.NewMemDeviceStore()}, // registry, no dev-ops
	} {
		router := NewRouter(cfg)
		for _, p := range paths {
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(p.method, p.path, nil))
			if rec.Code != http.StatusNotImplemented {
				t.Fatalf("%s %s = %d, want 501 (body %s)", p.method, p.path, rec.Code, rec.Body.String())
			}
			var body apiError
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("501 body not JSON: %v", err)
			}
			if body.Error != "not_implemented" {
				t.Fatalf("%s %s error = %q, want not_implemented", p.method, p.path, body.Error)
			}
			if !strings.Contains(body.Detail, "account model") {
				t.Fatalf("%s %s detail = %q, want the ACCOUNT stub's text", p.method, p.path, body.Detail)
			}
		}
	}
}

// TestGrantsListNamesTheOwningAccount: members of the owning account hold access
// that appears in NO grant row, so the listing must say who owns the vault or it
// reads as "nobody has access".
func TestGrantsListNamesTheOwningAccount(t *testing.T) {
	env := newDeviceEnv(t)
	dev := enrollDevice(t, env, testEnrollToken, "laptop")
	if rec := v3Post(t, env, dev, "/v1/vaults/vaultA/ops", []byte("first")); rec.Code != http.StatusCreated {
		t.Fatalf("claim = %d", rec.Code)
	}

	rec := v3Get(t, env, dev, "/v1/vaults/vaultA/grants")
	if rec.Code != http.StatusOK {
		t.Fatalf("grants = %d (body %s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		VaultID        string      `json:"vaultID"`
		OwnerAccountID string      `json:"owner_account_id"`
		Grants         []grantJSON `json:"grants"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("body: %v", err)
	}
	if resp.OwnerAccountID != dev.Account {
		t.Fatalf("owner_account_id = %q, want %q", resp.OwnerAccountID, dev.Account)
	}
	// The per-device VIEW is unchanged, so existing clients see what they always did.
	if len(resp.Grants) != 1 || resp.Grants[0].DeviceID != dev.ID || !resp.Grants[0].Owner {
		t.Fatalf("grants = %+v, want the unchanged single owner row", resp.Grants)
	}
}
