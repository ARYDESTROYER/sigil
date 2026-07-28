package api

// Tests for the ABUSE BOUNDS (Phase 53): request-volume limits on the three
// routes that had none — unauthenticated device enrollment, account-invite
// minting, and the provider webhook.
//
// The four properties every one of these limiters must have, and which the
// tests below pin:
//
//	1. over-rate is 429 with Retry-After and the shared rate_limited envelope
//	2. under-rate traffic is completely unaffected (including a legitimate
//	   provider burst, which must never be dropped)
//	3. the limiter is bounded and evicts, so it cannot be grown without limit
//	4. nothing new is leaked: no source address reaches /metrics or the audit log

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

// limitedEnv is a deviceEnv whose router has abuse limiters configured, plus the
// captured audit stream so a test can assert what was (and was not) logged.
type limitedEnv struct {
	*deviceEnv
	logs *bytes.Buffer
}

// newLimitedEnv builds a dev-ops + device-auth router with the given abuse
// limits and the given operator enrollment tokens.
func newLimitedEnv(t *testing.T, tokens []string, cfg Config) *limitedEnv {
	t.Helper()
	devices := store.NewMemDeviceStore()
	hashes := make([]string, 0, len(tokens))
	for _, tok := range tokens {
		h := EnrollTokenHash(tok)
		hashes = append(hashes, h)
		if err := devices.RegisterEnrollmentToken(t.Context(), h, time.Now().UTC(), time.Time{}); err != nil {
			t.Fatalf("RegisterEnrollmentToken: %v", err)
		}
	}
	logs := &bytes.Buffer{}
	cfg.Version = "test"
	cfg.Logger = slog.New(slog.NewJSONHandler(logs, nil))
	cfg.DevOpsEnabled = true
	cfg.Devices = devices
	cfg.EnrollTokenHashes = hashes
	cfg.AdminToken = testAdminToken
	return &limitedEnv{
		deviceEnv: &deviceEnv{router: NewRouter(cfg), devices: devices},
		logs:      logs,
	}
}

// assertRateLimited asserts the shared 429 contract: the typed rate_limited
// envelope plus a positive Retry-After, and no leak of the limiter's key.
func assertRateLimited(t *testing.T, rec *httptest.ResponseRecorder, mustNotContain ...string) {
	t.Helper()
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (body: %s)", rec.Code, rec.Body.String())
	}
	retry := rec.Header().Get("Retry-After")
	if retry == "" {
		t.Fatal("429 missing Retry-After header")
	}
	if n, err := strconv.Atoi(retry); err != nil || n < 1 {
		t.Fatalf("Retry-After = %q, want a positive whole number of seconds", retry)
	}
	var body apiError
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("429 body not JSON: %v", err)
	}
	if body.Error != "rate_limited" {
		t.Fatalf("429 error = %q, want rate_limited", body.Error)
	}
	for _, leak := range mustNotContain {
		if strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("429 body leaked the limiter key %q: %s", leak, rec.Body.String())
		}
	}
}

// enrollFrom performs a full, VALID enrollment attempt from a chosen source
// address and returns the recorder without asserting the status.
func enrollFrom(t *testing.T, env *limitedEnv, token, addr string) *httptest.ResponseRecorder {
	t.Helper()
	pub, priv := newClientKeypair(t)
	req := buildEnrollRequest(t, token, pub, priv, "dev", time.Now().Unix(), randNonce(t))
	req.RemoteAddr = addr
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, req)
	return rec
}

// ---- 1. enrollment: keyed on the SOURCE ADDRESS, because it is unauthenticated ----

// TestEnrollRateLimitedBySourceAddress: repeated FAILING attempts from one
// address exhaust that address's bucket and then answer 429, while a DIFFERENT
// address is completely unaffected (independent bucket).
func TestEnrollRateLimitedBySourceAddress(t *testing.T) {
	env := newLimitedEnv(t, []string{testEnrollToken}, Config{
		EnrollRateLimit: 0.001, EnrollRateBurst: 2, // negligible refill
	})

	// Attempt 1 SUCCEEDS (the operator token is unspent) and must cost nothing.
	if rec := enrollFrom(t, env, testEnrollToken, "198.51.100.7:40000"); rec.Code != http.StatusCreated {
		t.Fatalf("first enrolment = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	// Every later attempt from that address FAILS (the token is spent), and only
	// failures spend the bucket: two 401s, then 429s.
	var denied, limited int
	for i := 0; i < 5; i++ {
		rec := enrollFrom(t, env, testEnrollToken, "198.51.100.7:40000")
		if rec.Code == http.StatusTooManyRequests {
			assertRateLimited(t, rec, "198.51.100.7")
			limited++
			continue
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401 (spent token) or 429", i, rec.Code)
		}
		denied++
	}
	if denied != 2 {
		t.Fatalf("un-limited denials = %d, want 2 (== burst; only failures charge the bucket)", denied)
	}
	if limited != 3 {
		t.Fatalf("limited attempts = %d, want 3", limited)
	}

	// A different source address has its own full bucket, and the token it
	// presents is now spent — so it must reach the HANDLER (401), not the
	// limiter (429). That distinction is the whole assertion.
	rec := enrollFrom(t, env, testEnrollToken, "203.0.113.9:40000")
	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("a different source address was rate limited: %s", rec.Body.String())
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (spent token reached the handler)", rec.Code)
	}
}

// ★ TestValidEnrolmentIsNeverRateLimited is the regression test for the defect
// that reshaped this limiter. An attacker floods the enrollment route with junk
// from the SAME apparent source address — which, behind the reverse proxy this
// repo documents, is every address — and a LEGITIMATE new customer then arrives
// with a VALID, unspent operator token. The customer MUST be enrolled.
//
// The old limiter refused them 429 (reproduced live), which is a global switch
// for turning off account creation and invite redemption — the join path for
// somebody who just lost a device.
func TestValidEnrolmentIsNeverRateLimited(t *testing.T) {
	const customerToken = "test-enrollment-token-0000000009"
	env := newLimitedEnv(t, []string{testEnrollToken, customerToken}, Config{
		EnrollRateLimit: 0.001, EnrollRateBurst: 2, // negligible refill
	})

	// The flood: 30 junk attempts, all from one address, all refused.
	var sawLimit bool
	for i := 0; i < 30; i++ {
		rec := enrollFrom(t, env, "not-a-real-enrollment-token-xxxxx", "198.51.100.7:40000")
		if rec.Code == http.StatusTooManyRequests {
			sawLimit = true
			continue
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("junk attempt %d = %d, want 401 or 429", i, rec.Code)
		}
	}
	if !sawLimit {
		t.Fatal("the junk flood was never limited: the limiter did nothing at all")
	}

	// The legitimate customer, from the SAME apparent address, with a VALID token.
	rec := enrollFrom(t, env, customerToken, "198.51.100.7:40000")
	if rec.Code == http.StatusTooManyRequests {
		t.Fatal("a VALID enrolment was refused 429 after a junk flood from the same address: the limiter must never be able to deny a legitimate user")
	}
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid enrolment = %d, want 201 (body: %s)", rec.Code, rec.Body.String())
	}
	// And it cost no token: the very next failing attempt must still be limited
	// exactly as before, i.e. the success neither spent nor refilled the bucket.
	if got := enrollFrom(t, env, "not-a-real-enrollment-token-xxxxx", "198.51.100.7:40000"); got.Code != http.StatusTooManyRequests {
		t.Fatalf("post-success junk attempt = %d, want 429 (a success must not refill the bucket)", got.Code)
	}
}

// ★ TestEnrollRateLimitIgnoresForwardedFor pins the key derivation AT THE CALL
// SITE, which TestClientRateKey cannot: it exercises the pure function in
// isolation, so a wrapper that read X-Forwarded-For instead would leave it green
// while defeating the limiter entirely (an attacker mints one bucket per header
// value, and fills the bounded map doing it). A verifier mutated exactly that
// and the whole suite stayed green.
//
// Both directions are asserted:
//
//	same peer, DIFFERENT forwarded-for  -> ONE bucket   (a header cannot mint one)
//	different peer, SAME forwarded-for  -> TWO buckets  (the peer is the key)
func TestEnrollRateLimitIgnoresForwardedFor(t *testing.T) {
	env := newLimitedEnv(t, []string{testEnrollToken}, Config{
		EnrollRateLimit: 0.001, EnrollRateBurst: 1, // one failure, then 429
	})

	enroll := func(addr, xff string) *httptest.ResponseRecorder {
		t.Helper()
		pub, priv := newClientKeypair(t)
		req := buildEnrollRequest(t, "not-a-real-enrollment-token-xxxxx", pub, priv, "dev",
			time.Now().Unix(), randNonce(t))
		req.RemoteAddr = addr
		req.Header.Set("X-Forwarded-For", xff)
		req.Header.Set("X-Real-IP", xff)
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		return rec
	}

	// Direction 1: one peer, many claimed forwarded-for values => ONE bucket.
	if rec := enroll("198.51.100.7:40000", "10.0.0.1"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first attempt = %d, want 401 (bad token reaches the handler)", rec.Code)
	}
	for i, spoof := range []string{"10.0.0.2", "10.0.0.3", "203.0.113.250"} {
		rec := enroll("198.51.100.7:40000", spoof)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("spoofed forwarded-for %d (%s) = %d, want 429: the limiter key MUST be the socket peer, never a client-supplied header (a header key lets one client mint unlimited buckets)",
				i, spoof, rec.Code)
		}
	}

	// Direction 2: a different peer claiming the SAME forwarded-for gets its own
	// bucket, so the peer really is what is being keyed on.
	if rec := enroll("203.0.113.9:40000", "10.0.0.1"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("different peer, same forwarded-for = %d, want 401 (independent bucket keyed on the PEER)", rec.Code)
	}
}

// TestEnrollUnderRateIsUnaffected: with a limiter configured but traffic under
// the rate, enrollment behaves EXACTLY as it does with no limiter — every valid
// attempt succeeds and the invite/operator semantics are untouched.
func TestEnrollUnderRateIsUnaffected(t *testing.T) {
	env := newLimitedEnv(t, []string{testEnrollToken}, Config{
		EnrollRateLimit: 100, EnrollRateBurst: 50,
	})
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "laptop")
	if dev.Account == "" {
		t.Fatal("enrolment under the rate did not produce an account")
	}
	// Joining by invite goes through the same limited route and must also work.
	invite := mintInvite(t, env.deviceEnv, dev, nil)
	sibling := joinByInvite(t, env.deviceEnv, invite.Invite, "phone")
	if sibling.Account != dev.Account {
		t.Fatalf("sibling account = %q, want %q", sibling.Account, dev.Account)
	}
}

// TestEnrollRateLimitOffByDefault: with no rate configured no limiter is
// installed, so no volume of attempts is ever 429'd.
func TestEnrollRateLimitOffByDefault(t *testing.T) {
	env := newLimitedEnv(t, []string{testEnrollToken}, Config{})
	for i := 0; i < 40; i++ {
		rec := enrollFrom(t, env, testEnrollToken, "198.51.100.7:40000")
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d got 429 with no limiter configured", i)
		}
	}
}

// TestGatedEnrollStubIsNeverRateLimited: with the dev gate off the route answers
// 501 — never 404 and never 429. A limiter on the stub would turn the abuse
// bound into a probe for whether the feature is enabled.
func TestGatedEnrollStubIsNeverRateLimited(t *testing.T) {
	router := NewRouter(Config{
		Version: "test", Logger: discardLogger(),
		DevOpsEnabled:   false, // gate OFF
		EnrollRateLimit: 0.001, EnrollRateBurst: 1,
		InviteRateLimit: 0.001, InviteRateBurst: 1,
	})
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/devices/enroll", strings.NewReader("{}"))
		req.RemoteAddr = "198.51.100.7:40000"
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("attempt %d status = %d, want 501 (gated routes answer 501 uniformly)", i, rec.Code)
		}
	}
	for i := 0; i < 5; i++ {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/account/invites", strings.NewReader("{}"))
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotImplemented {
			t.Fatalf("invite attempt %d status = %d, want 501", i, rec.Code)
		}
	}
}

// ---- 2. invite minting: keyed on the ACCOUNT, not the device ----

// TestInviteRateLimitedByAccountNotDevice is the load-bearing invite assertion:
// two devices of the SAME account share ONE bucket (so adding devices does not
// multiply the minting rate), while a device of a DIFFERENT account is
// untouched.
func TestInviteRateLimitedByAccountNotDevice(t *testing.T) {
	const secondToken = "test-enrollment-token-0000000002"
	env := newLimitedEnv(t, []string{testEnrollToken, secondToken}, Config{
		InviteRateLimit: 0.001, InviteRateBurst: 2,
	})

	devA := enrollDevice(t, env.deviceEnv, testEnrollToken, "A")
	// A sibling in the SAME account: minted with the account's first token.
	first := mintInvite(t, env.deviceEnv, devA, nil) // spends bucket token 1
	sibling := joinByInvite(t, env.deviceEnv, first.Invite, "A-phone")
	if sibling.Account != devA.Account {
		t.Fatalf("sibling is in account %q, want %q", sibling.Account, devA.Account)
	}

	// Token 2 of the SHARED bucket, spent by the SIBLING device.
	if rec := v3Post(t, env.deviceEnv, sibling, "/v1/account/invites", nil); rec.Code != http.StatusCreated {
		t.Fatalf("sibling mint = %d, want 201 (burst not yet exhausted)", rec.Code)
	}
	// The bucket is now empty for the ACCOUNT. Either device must be limited —
	// this is what a per-device key would have got wrong.
	assertRateLimited(t, v3Post(t, env.deviceEnv, devA, "/v1/account/invites", nil), devA.Account, devA.ID)
	assertRateLimited(t, v3Post(t, env.deviceEnv, sibling, "/v1/account/invites", nil), sibling.Account)

	// A device in a DIFFERENT account has its own full bucket.
	devB := enrollDevice(t, env.deviceEnv, secondToken, "B")
	if devB.Account == devA.Account {
		t.Fatal("an operator token must found a NEW account")
	}
	if rec := v3Post(t, env.deviceEnv, devB, "/v1/account/invites", nil); rec.Code != http.StatusCreated {
		t.Fatalf("other account mint = %d, want 201 (independent bucket)", rec.Code)
	}
}

// TestInviteRateLimitOffByDefault: with no rate configured, minting is bounded
// only by the per-account OPEN-INVITE STATE cap, exactly as before.
func TestInviteRateLimitOffByDefault(t *testing.T) {
	env := newLimitedEnv(t, []string{testEnrollToken}, Config{AccountMaxInvites: 50})
	dev := enrollDevice(t, env.deviceEnv, testEnrollToken, "A")
	for i := 0; i < 20; i++ {
		if rec := v3Post(t, env.deviceEnv, dev, "/v1/account/invites", nil); rec.Code != http.StatusCreated {
			t.Fatalf("mint %d = %d, want 201 with no limiter configured (body: %s)", i, rec.Code, rec.Body.String())
		}
	}
}

// ---- 3. the billing webhook: DELIBERATELY UNLIMITED ----

// ★ TestWebhookIsNeverRateLimited is the regression test for the defect that
// removed the webhook limiter. A forged flood — hundreds of unauthenticated
// requests with garbage signatures — must not cost a genuine, correctly-signed
// delivery ANYTHING. The old limiter keyed on the provider name, which forged
// traffic supplies too, so both spent the same tokens: a live reproduction shed
// 15 of 15 genuine deliveries and lost the payment events permanently.
//
// The assertion is therefore: after the flood, every genuine delivery is still
// 200 and is still APPLIED, and no request anywhere on this route can produce a
// 429.
func TestWebhookIsNeverRateLimited(t *testing.T) {
	base := newBillingEnv(t)
	dev := enrollDevice(t, base.deviceEnv, testEnrollToken, "buyer")

	// The forged flood. Every one of these is refused (401), and none of them may
	// leave a mark that a later authentic delivery pays for.
	for i := 0; i < 200; i++ {
		bad := httptest.NewRequest(http.MethodPost, "/v1/billing/webhook/stripe",
			bytes.NewReader(stripeEvent("evt_forged_"+strconv.Itoa(i), dev.Account)))
		bad.Header.Set("Stripe-Signature", "t=1700000000,v1=deadbeef")
		rec := serve(base.router, bad)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("forged request %d got 429 — this route must carry no rate limiter", i)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("forged request %d = %d, want 401", i, rec.Code)
		}
	}

	// The genuine burst, immediately after. Not one may be shed.
	ts := time.Now().Unix()
	for i := 0; i < 15; i++ {
		body := stripeEvent("evt_genuine_"+strconv.Itoa(i), dev.Account)
		rec := serve(base.router, stripeWebhookRequest(body, apiTestStripeWebhookSec, ts))
		if rec.Code != http.StatusOK {
			t.Fatalf("genuine delivery %d = %d, want 200 — a forged flood must never shed a real payment event (body: %s)",
				i, rec.Code, rec.Body.String())
		}
	}
	// And they were APPLIED, not merely acknowledged.
	sub, err := base.subs.GetSubscription(t.Context(), dev.Account)
	if err != nil {
		t.Fatalf("GetSubscription: %v", err)
	}
	if !sub.Status.Entitled() {
		t.Fatalf("subscription status = %q, want an entitled status after the genuine burst", sub.Status)
	}
}

// TestNoWebhookRateLimitSurfaceExists pins the removal structurally: the abuse
// surface enum — which is the closed label set on the abuse metric — must not
// name the webhook, and /metrics must not publish a webhook abuse counter or a
// rate_limited webhook rejection reason. A reintroduced limiter would have to
// re-add one of these, and this test would fail.
func TestNoWebhookRateLimitSurfaceExists(t *testing.T) {
	for _, s := range abuseRateLimitSurfaces {
		if s == "webhook" {
			t.Fatal("abuseRateLimitSurfaces still names the webhook: the billing webhook must carry no rate limiter (it sheds payment events)")
		}
	}
	env := newLimitedEnv(t, []string{testEnrollToken}, Config{})
	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	for _, forbidden := range []string{
		`sigild_abuse_ratelimit_rejected_total{surface="webhook"}`,
		`sigild_billing_webhook_rejected_total{reason="rate_limited"}`,
	} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Fatalf("/metrics still publishes %q", forbidden)
		}
	}
}

// stripeEvent builds a distinct, well-formed checkout-completed event.
func stripeEvent(id, subject string) []byte {
	return []byte(`{"id":"` + id + `","type":"checkout.session.completed","created":1700000000,` +
		`"data":{"object":{"client_reference_id":"` + subject + `","subscription":"sub_` + id + `"}}}`)
}

// ---- 4. the limiter itself: bounded, evicting, and key derivation ----

// TestClientRateKey pins the key derivation, including the two choices that
// matter: an IPv6 peer is bucketed by its /64 prefix (so one allocation cannot
// walk 2^64 buckets), and anything unparseable collapses onto ONE shared bucket
// rather than being waved through.
func TestClientRateKey(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"198.51.100.7:40000", "198.51.100.7"},
		{"198.51.100.7", "198.51.100.7"},
		// The same IPv4 client presented as an IPv4-mapped IPv6 address must land
		// in the SAME bucket, not a second one.
		{"[::ffff:198.51.100.7]:40000", "198.51.100.7"},
		// Two addresses inside one /64 share a bucket...
		{"[2001:db8:1:2::1]:443", "2001:db8:1:2::/64"},
		{"[2001:db8:1:2::dead:beef]:443", "2001:db8:1:2::/64"},
		// ...and a different /64 does not.
		{"[2001:db8:1:3::1]:443", "2001:db8:1:3::/64"},
		// A zone is stripped so one link-local peer is one bucket.
		{"[fe80::1%eth0]:443", "fe80::/64"},
		// Unattributable => the single shared bucket (never "allow").
		{"", unattributedRateKey},
		{"not-an-address", unattributedRateKey},
		{"@", unattributedRateKey},
	}
	for _, c := range cases {
		if got := clientRateKey(c.in); got != c.want {
			t.Fatalf("clientRateKey(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestAbuseLimiterBoundedAndEvicts drives the injected clock to prove the map is
// bounded at its configured cap, that idle (fully-refilled) buckets are evicted
// to admit a new key, and that at the cap with everything actively limited a new
// key is ADMITTED — this limiter FAILS OPEN at its cap. Fail-closed was the
// weapon: one IPv6 /48 could fill every bucket and then refuse everyone else,
// turning a memory bound into a global outage on an availability-critical
// unauthenticated route. The map still never grows past the cap.
func TestAbuseLimiterBoundedAndEvicts(t *testing.T) {
	const maxKeys = 32
	rl := newRateLimiterWithMax(1, 1, maxKeys)
	now := time.Unix(1_000_000, 0)
	rl.now = func() time.Time { return now }

	// Fill to the cap with ACTIVE (just-drained) buckets.
	for i := 0; i < maxKeys; i++ {
		if !rl.Allow("k" + itoa(i)) {
			t.Fatalf("key %d rejected while filling", i)
		}
	}
	if len(rl.buckets) != maxKeys {
		t.Fatalf("bucket count = %d, want %d", len(rl.buckets), maxKeys)
	}
	// ⭐ Nothing is idle, so the map cannot grow — but the verdict is ADMIT. The
	// old behaviour (refuse) meant that filling the map REFUSED EVERY OTHER KEY,
	// and the map is fillable by an attacker: one IPv6 /48 yields 65536 distinct
	// /64 keys. That turned a memory bound into a global outage on an
	// availability-critical unauthenticated route, so the limiter FAILS OPEN.
	if !rl.Allow("fresh-at-cap") {
		t.Fatal("a new key was REFUSED at the key cap: the limiter must fail OPEN, or filling the map becomes a denial-of-service weapon")
	}
	if len(rl.buckets) > maxKeys {
		t.Fatalf("bucket count = %d, want <= %d (still bounded — fail open must not mean grow)", len(rl.buckets), maxKeys)
	}
	// Advance past a full refill: every bucket is now idle and evictable.
	now = now.Add(time.Hour)
	if !rl.Allow("fresh-after-idle") {
		t.Fatal("a new key was rejected after the buckets went idle, want admission")
	}
	if len(rl.buckets) > maxKeys {
		t.Fatalf("post-evict bucket count = %d, want <= %d", len(rl.buckets), maxKeys)
	}
}

// ★ TestAbuseObservabilityLeaksNoAddress: the counters exist under the closed
// two-value surface label, and NEITHER /metrics NOR the audit log carries the
// source address of a rate-limited enrolment. sigild holds no personal data
// anywhere; a rate limiter must not be the thing that introduces some.
func TestAbuseObservabilityLeaksNoAddress(t *testing.T) {
	const addr = "203.0.113.77"
	env := newLimitedEnv(t, []string{testEnrollToken}, Config{
		EnrollRateLimit: 0.001, EnrollRateBurst: 1,
		InviteRateLimit: 0.001, InviteRateBurst: 1,
	})

	// Enrol one real device (a SUCCESS, which costs no token), then burn the
	// enrolment bucket with FAILING attempts from the same distinctive address.
	dev := func() testDevice {
		pub, priv := newClientKeypair(t)
		req := buildEnrollRequest(t, testEnrollToken, pub, priv, "A", time.Now().Unix(), randNonce(t))
		req.RemoteAddr = addr + ":51000"
		rec := httptest.NewRecorder()
		env.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("enrol = %d (%s)", rec.Code, rec.Body.String())
		}
		var out deviceJSON
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("enrol body: %v", err)
		}
		return testDevice{ID: out.DeviceID, Account: out.AccountID, Pub: pub, Priv: priv}
	}()
	if rec := enrollFrom(t, env, testEnrollToken, addr+":51001"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("spent-token attempt = %d, want 401 (it spends the single burst token)", rec.Code)
	}
	assertRateLimited(t, enrollFrom(t, env, testEnrollToken, addr+":51001"))

	// And the invite bucket, so both surfaces have a sample.
	if rec := v3Post(t, env.deviceEnv, dev, "/v1/account/invites", nil); rec.Code != http.StatusCreated {
		t.Fatalf("first mint = %d", rec.Code)
	}
	assertRateLimited(t, v3Post(t, env.deviceEnv, dev, "/v1/account/invites", nil))

	rec := httptest.NewRecorder()
	env.router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	metrics := rec.Body.String()
	for _, want := range []string{
		`sigild_abuse_ratelimit_rejected_total{surface="enroll"} 1`,
		`sigild_abuse_ratelimit_rejected_total{surface="invite"} 1`,
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("/metrics missing %q:\n%s", want, metrics)
		}
	}
	logged := env.logs.String()
	if !strings.Contains(logged, `"event":"abuse.rate_limited"`) {
		t.Fatalf("audit log missing the abuse.rate_limited event:\n%s", logged)
	}
	// The account IS logged for the invite surface (it is already everywhere in
	// this stream); the ADDRESS is logged nowhere, on either surface.
	if !strings.Contains(logged, `"surface":"invite","subject":"`+dev.Account+`"`) {
		t.Fatalf("invite rate-limit line did not record the account subject:\n%s", logged)
	}
	if !strings.Contains(logged, `"surface":"enroll","subject":""`) {
		t.Fatalf("enroll rate-limit line should record an EMPTY subject:\n%s", logged)
	}
	for _, leak := range []string{addr, "51000", "51001"} {
		if strings.Contains(metrics, leak) {
			t.Fatalf("/metrics leaked the source address fragment %q", leak)
		}
		if strings.Contains(logged, leak) {
			t.Fatalf("audit log leaked the source address fragment %q:\n%s", leak, logged)
		}
	}
}

// TestAbuseLimitsDoNotWeakenExistingControls: with both limiters on and
// plenty of budget, the v3 contract still behaves exactly as before — an
// unsigned request is 401, a revoked device is 401, and a non-member device is
// 403 on someone else's vault. A rate limiter must not become an auth shortcut.
func TestAbuseLimitsDoNotWeakenExistingControls(t *testing.T) {
	const secondToken = "test-enrollment-token-0000000003"
	env := newLimitedEnv(t, []string{testEnrollToken, secondToken}, Config{
		EnrollRateLimit: 1000, EnrollRateBurst: 500,
		InviteRateLimit: 1000, InviteRateBurst: 500,
	})
	devA := enrollDevice(t, env.deviceEnv, testEnrollToken, "A")
	devB := enrollDevice(t, env.deviceEnv, secondToken, "B")

	if rec := v3Post(t, env.deviceEnv, devA, "/v1/vaults/vaultA/ops", []byte("op")); rec.Code != http.StatusCreated {
		t.Fatalf("A claim = %d, want 201", rec.Code)
	}
	// Unsigned => 401.
	unsigned := httptest.NewRecorder()
	env.router.ServeHTTP(unsigned, httptest.NewRequest(http.MethodGet, "/v1/vaults/vaultA/ops", nil))
	if unsigned.Code != http.StatusUnauthorized {
		t.Fatalf("unsigned = %d, want 401", unsigned.Code)
	}
	// Another account => 403, not 401 and not 429.
	assertForbidden(t, v3Get(t, env.deviceEnv, devB, "/v1/vaults/vaultA/ops"))
	// Revocation still bites before signature verification.
	if err := env.devices.RevokeDevice(t.Context(), devB.ID, time.Now().UTC()); err != nil {
		t.Fatalf("RevokeDevice: %v", err)
	}
	if rec := v3Get(t, env.deviceEnv, devB, "/v1/account"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked device = %d, want 401", rec.Code)
	}
}
