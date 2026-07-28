package api

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/ARYDESTROYER/sigil/sigild/internal/billing"
)

// Metrics holds sigild's process observability counters. They are exported in
// Prometheus text exposition format at GET /metrics.
//
// DESIGN: the counters live on this struct (constructed per-router by
// newMetrics), NOT in package-level globals. That keeps them test-isolatable —
// each NewRouter gets a fresh, independent Metrics so a test can assert an exact
// delta without cross-test interference — and lets the /metrics values be
// process-scoped to a single server instance.
//
// All fields are read/written with sync/atomic, so increments are cheap and safe
// for concurrent use with no lock. The maps are built once at construction and
// never structurally modified afterwards (only their atomic values change), so
// concurrent reads during a scrape and concurrent increments do not race.
//
// It exposes ONLY counters and the build version — no secrets, no vault data, no
// blob content. It is therefore safe to serve unauthenticated (operational).
type Metrics struct {
	version string

	// schemaVersion is the applied op-log DB migration version reported by the
	// sigild_schema_version gauge. It is a config-time value fixed at
	// construction (0 when the backend is not Postgres), never mutated, so like
	// version it needs no atomic.
	schemaVersion int64

	// httpRequestsTotal counts every HTTP response the server produced; the
	// httpByClass buckets split that by status class (index = status/100, so
	// index 2 == 2xx). Index 0 and any out-of-range class are never emitted.
	httpRequestsTotal atomic.Int64
	httpByClass       [6]atomic.Int64

	oplogAppendsTotal     atomic.Int64
	oplogVerifyTotal      atomic.Int64
	oplogRateLimitedTotal atomic.Int64

	// Abuse-bound counters (Phase 53), keyed by the CLOSED three-value surface
	// set. Counts ONLY: never a source address (which is personal data this
	// server otherwise never retains — see auditRateLimited), never an account,
	// device or vault ID, never a token, key, signature or nonce. Built once at
	// construction; only the atomic values mutate.
	abuseRateLimited map[string]*atomic.Int64

	// Device-model counters (Phase 41). Counts ONLY — never a device's public
	// key, an enrollment token (or its digest), an admin token, a signature, a
	// nonce, or a vault/device ID as a label (an ID label would let a scrape
	// enumerate the registry).
	deviceEnrollmentsTotal atomic.Int64
	deviceRevocationsTotal atomic.Int64
	vaultGrantsTotal       atomic.Int64
	vaultClaimsTotal       atomic.Int64
	authzDeniedTotal       atomic.Int64

	// Account-model counters (Phase 52). Counts ONLY. No account, device, vault
	// or invite ID may EVER become a label here — /metrics is always-on and
	// unauthenticated, so an ID label would let a scrape enumerate the registry,
	// and a fine-grained invite-failure label would be a correlatable oracle.
	// Invite-failure fidelity goes to the audit log alone.
	accountsCreatedTotal       atomic.Int64
	accountInvitesCreatedTotal atomic.Int64
	accountInvitesRevokedTotal atomic.Int64
	accountJoinsTotal          atomic.Int64

	// Vault-sharing counters (Phase 46). Counts ONLY — never an envelope byte,
	// a hybrid public key, a vault key, or a vault/device ID as a label.
	hybridKeyPublishesTotal atomic.Int64
	keyEnvelopePutsTotal    atomic.Int64
	keyEnvelopeGetsTotal    atomic.Int64
	keyEnvelopeDeletesTotal atomic.Int64
	keyEnvelopeIndexTotal   atomic.Int64

	// entitlementEnforcing is 1 when this router enforces payment on its three
	// WRITE surfaces, 0 otherwise. Like schemaVersion it is a config-time value
	// fixed before serving starts and never mutated, so it needs no atomic. It is
	// exported as a gauge so an operator can see at a glance whether enforcement
	// is actually on — a knob believed to be on but silently inert is exactly the
	// failure this repo keeps refusing to ship.
	entitlementEnforcing int64
	// entitlementDecisions counts enforcement verdicts, keyed by the CLOSED
	// four-value outcome set. Counts ONLY — never an account id, a subject, a
	// provider reference, an amount or a timestamp. /metrics is always-on and
	// unauthenticated, so an id label here would let a scrape enumerate which
	// customers are behind on payment.
	entitlementDecisions map[entitlementOutcome]*atomic.Int64

	// authDenied counts request auth/authz denials, keyed by the fixed
	// authReason enum so /metrics can label each by reason. Built once
	// (immutable key set); only the atomic values mutate.
	authDenied map[authReason]*atomic.Int64
	// enrollDenied counts enrollment denials by reason, over the enrollment
	// subset of the same enum.
	enrollDenied map[authReason]*atomic.Int64

	// Billing counters (Phase 45). Every label below comes from a CLOSED,
	// compile-time set — the three provider names, the normalized webhook
	// outcomes, a fixed rejection-reason enum, and the subscription statuses.
	//
	// They count ONLY. There is never an API key, a webhook secret, a signature,
	// a raw webhook body, an event ID, a subject/device ID, an email address, an
	// amount, or any card field here — a labeled metric with an unbounded label
	// would both explode cardinality and let an unauthenticated scrape enumerate
	// customers, so the label sets are closed by construction.
	billingCheckouts       map[string]*atomic.Int64         // provider
	billingWebhooks        map[string]*atomic.Int64         // provider|outcome
	billingWebhookRejected map[string]*atomic.Int64         // reason
	billingSubTransitions  map[billing.Status]*atomic.Int64 // to-status
}

// authDenyReasons is the fixed, exhaustive set of non-OK request-auth reasons,
// in a stable order so the /metrics output is deterministic. The first five are
// the v2 contract's; the rest are added by the v3 device model.
var authDenyReasons = []authReason{
	reasonMissingHeaders,
	reasonBadTimestamp,
	reasonStaleTimestamp,
	reasonBadSignature,
	reasonReplayed,
	reasonUnknownDevice,
	reasonRevokedDevice,
	reasonUnauthorizedVault,
	reasonNotVaultOwner,
	reasonForbiddenDevice,
	reasonBadAdminToken,
	reasonStoreUnavailable,
	reasonMissingAccount,
	reasonVaultOwnerUnresolved,
}

// authDenyMetricReason collapses request-auth reasons that a CLIENT CANNOT TELL
// APART onto ONE coarse metric label, and is the last step before a counter is
// incremented. The FINE-GRAINED reason still goes to the audit log unchanged —
// that surface is server-side and authenticated by being server-side; /metrics is
// UNAUTHENTICATED AND ALWAYS ON.
//
// ⭐ WHY (Phase 57). The client-visible answer to "I am not allowed on this
// vault" is byte-identical in both cases — the same 403, the same
// {"error":"forbidden"} — but the METRIC delta was not: a probe of a vault that
// EXISTS and belongs to somebody else moved forbidden_account, while a probe of a
// vault that has never existed moved unauthorized_vault. Scraping /metrics before
// and after a single request therefore answered "does this vault id exist?", which
// is precisely the oracle ADR 0040 limitation 11 says this model deliberately does
// not widen. The enrollment side was collapsed for exactly this reason
// (enrollDenyReasons); the auth-deny side was missed.
//
// DELIBERATELY NOT COLLAPSED: not_vault_owner and forbidden_device describe the
// CALLER's own relationship to a resource it already reached, not the existence of
// something it guessed at, so they leak nothing a prober did not already hold.
// vault_owner_unresolved is retained too — it names a server-side DATA-REPAIR
// state (a pre-0005 ownership grant needing the backfill) that an operator must be
// able to see, and reaching it requires that legacy row to already exist. That is
// an honest, narrow residue, not a claim that the oracle is fully closed.
func authDenyMetricReason(reason authReason) authReason {
	if reason == reasonForbiddenAccount {
		return reasonUnauthorizedVault
	}
	return reason
}

// enrollDenyReasons is the fixed set of enrollment-denial reasons, in a stable
// order. It deliberately does NOT distinguish anything the client is told: the
// split exists only for the operator's metrics.
//
// Phase 52 adds exactly ONE label (account_full) and no more. Every account-
// invite failure collapses onto an EXISTING label — unknown/revoked/inactive
// inviter -> bad_enrollment_token, used -> enrollment_token_used, expired ->
// enrollment_token_expired, pinned-key mismatch -> bad_proof — because /metrics
// is unauthenticated and a per-cause counter there would be a weak oracle on
// invite state. The fine-grained cause goes to the audit log only.
var enrollDenyReasons = []authReason{
	reasonMissingHeaders,
	reasonStaleTimestamp,
	reasonBadEnrollToken,
	reasonEnrollTokenUsed,
	reasonEnrollTokenExpired,
	reasonBadProof,
	reasonMalformedKey,
	reasonDeviceExists,
	reasonReplayed,
	reasonAccountFull,
	reasonStoreUnavailable,
}

// billingWebhookOutcomes is the closed set of webhook outcomes, in a stable
// order. "accepted" is a state change; every other value is an acknowledged
// no-op (all of them are HTTP 200 — see billingWebhook).
var billingWebhookOutcomes = []string{
	"accepted",
	"ignored",
	"duplicate",
	"stale",
	"illegal",
	"unresolved",
}

// billingRejectReasons is the closed set of reasons a webhook was NOT accepted.
// Like the auth reasons these are a fixed enum naming which class of check
// failed; they are surfaced only to the operator (audit log + this metric),
// never to the caller.
//
// There is deliberately NO "rate_limited" value: the webhook route carries no
// rate limiter (see billingWebhook — shedding traffic there loses payment
// events), so a counter for it would name a rejection that cannot happen.
var billingRejectReasons = []string{
	"bad_signature",
	"malformed",
	"unknown_provider",
	"payload_too_large",
	"store_error",
}

// billingWebhookKey builds the composite map key for the two-label webhook
// counter. Both halves come from closed sets, so the key space is fixed.
func billingWebhookKey(provider, outcome string) string { return provider + "|" + outcome }

// newMetrics returns a fresh, zeroed Metrics for one router/server instance.
// schemaVersion is the applied op-log DB migration version (0 for mem/file).
func newMetrics(version string, schemaVersion int64) *Metrics {
	m := &Metrics{
		version:                version,
		schemaVersion:          schemaVersion,
		abuseRateLimited:       make(map[string]*atomic.Int64, len(abuseRateLimitSurfaces)),
		entitlementDecisions:   make(map[entitlementOutcome]*atomic.Int64, len(entitlementOutcomes)),
		authDenied:             make(map[authReason]*atomic.Int64, len(authDenyReasons)),
		enrollDenied:           make(map[authReason]*atomic.Int64, len(enrollDenyReasons)),
		billingCheckouts:       make(map[string]*atomic.Int64, len(billing.SupportedProviders)),
		billingWebhooks:        make(map[string]*atomic.Int64),
		billingWebhookRejected: make(map[string]*atomic.Int64, len(billingRejectReasons)),
		billingSubTransitions:  make(map[billing.Status]*atomic.Int64, len(billing.Statuses)),
	}
	for _, s := range abuseRateLimitSurfaces {
		m.abuseRateLimited[s] = new(atomic.Int64)
	}
	for _, o := range entitlementOutcomes {
		m.entitlementDecisions[o] = new(atomic.Int64)
	}
	for _, r := range authDenyReasons {
		m.authDenied[r] = new(atomic.Int64)
	}
	for _, r := range enrollDenyReasons {
		m.enrollDenied[r] = new(atomic.Int64)
	}
	// Billing label sets are fully materialized here — the maps are never
	// structurally modified afterwards, so a concurrent scrape and a concurrent
	// increment cannot race.
	for _, p := range billing.SupportedProviders {
		m.billingCheckouts[p] = new(atomic.Int64)
		for _, o := range billingWebhookOutcomes {
			m.billingWebhooks[billingWebhookKey(p, o)] = new(atomic.Int64)
		}
	}
	for _, reason := range billingRejectReasons {
		m.billingWebhookRejected[reason] = new(atomic.Int64)
	}
	for _, s := range billing.Statuses {
		m.billingSubTransitions[s] = new(atomic.Int64)
	}
	return m
}

// incBillingCheckout records one hosted checkout session created. An unknown
// provider name (impossible — it comes from the configured, closed set) is
// ignored rather than mutating the map concurrently.
func (m *Metrics) incBillingCheckout(provider string) {
	if c := m.billingCheckouts[provider]; c != nil {
		c.Add(1)
	}
}

// incBillingWebhook records one ACCEPTED webhook by provider and outcome.
func (m *Metrics) incBillingWebhook(provider, outcome string) {
	if c := m.billingWebhooks[billingWebhookKey(provider, outcome)]; c != nil {
		c.Add(1)
	}
}

// incBillingWebhookRejected records one webhook rejected before it could be
// applied, by the fixed reason enum.
func (m *Metrics) incBillingWebhookRejected(reason string) {
	if c := m.billingWebhookRejected[reason]; c != nil {
		c.Add(1)
	}
}

// incBillingTransition records one REAL subscription status change, labeled by
// the status moved TO. It fires once per applied transition and never for a
// duplicate, stale or illegal delivery.
func (m *Metrics) incBillingTransition(to billing.Status) {
	if c := m.billingSubTransitions[to]; c != nil {
		c.Add(1)
	}
}

// observeHTTP records one served response by total and status class.
func (m *Metrics) observeHTTP(status int) {
	m.httpRequestsTotal.Add(1)
	if class := status / 100; class >= 1 && class <= 5 {
		m.httpByClass[class].Add(1)
	}
}

// incAppend records one successful op-log append.
func (m *Metrics) incAppend() { m.oplogAppendsTotal.Add(1) }

// incVerify records one op-log chain verification.
func (m *Metrics) incVerify() { m.oplogVerifyTotal.Add(1) }

// incRateLimited records one op-log request rejected by the rate limiter.
func (m *Metrics) incRateLimited() { m.oplogRateLimitedTotal.Add(1) }

// incAbuseRateLimited records one request rejected by an abuse-bound limiter,
// labeled by the closed surface set. An unknown surface (impossible — it comes
// from the compile-time constants) is ignored rather than mutating the map
// concurrently.
func (m *Metrics) incAbuseRateLimited(surface string) {
	if c := m.abuseRateLimited[surface]; c != nil {
		c.Add(1)
	}
}

// incEntitlement records one entitlement enforcement verdict, labeled by the
// closed outcome set. An unknown outcome (impossible — it comes from the
// compile-time constants) is ignored rather than mutating the map concurrently.
func (m *Metrics) incEntitlement(outcome entitlementOutcome) {
	if c := m.entitlementDecisions[outcome]; c != nil {
		c.Add(1)
	}
}

// incAuthDenied records one request auth/authz denial by reason. The reason is
// first collapsed through authDenyMetricReason so this UNAUTHENTICATED, always-on
// surface never distinguishes two denials the client is told nothing apart about
// (the audit log keeps the fine-grained reason). An unknown reason (should not
// occur — reason comes from the fixed enum) is ignored rather than mutating the
// map concurrently.
func (m *Metrics) incAuthDenied(reason authReason) {
	if c := m.authDenied[authDenyMetricReason(reason)]; c != nil {
		c.Add(1)
	}
}

// incEnrollDenied records one denied device-enrollment attempt by reason.
func (m *Metrics) incEnrollDenied(reason authReason) {
	if c := m.enrollDenied[reason]; c != nil {
		c.Add(1)
	}
}

// incEnrollment records one successful device enrollment.
func (m *Metrics) incEnrollment() { m.deviceEnrollmentsTotal.Add(1) }

// incRevocation records one device revocation.
func (m *Metrics) incRevocation() { m.deviceRevocationsTotal.Add(1) }

// incGrant records one per-vault access grant.
func (m *Metrics) incGrant() { m.vaultGrantsTotal.Add(1) }

// incVaultClaim records one trust-on-first-write vault ownership claim (now by
// ACCOUNT, Phase 52).
func (m *Metrics) incVaultClaim() { m.vaultClaimsTotal.Add(1) }

// incAccountCreated records one account founded by an operator-token enrollment.
func (m *Metrics) incAccountCreated() { m.accountsCreatedTotal.Add(1) }

// incAccountInviteCreated records one minted account invite.
func (m *Metrics) incAccountInviteCreated() { m.accountInvitesCreatedTotal.Add(1) }

// incAccountInviteRevoked records one invite revoked before use.
func (m *Metrics) incAccountInviteRevoked() { m.accountInvitesRevokedTotal.Add(1) }

// incAccountJoin records one device joining an EXISTING account by invite.
func (m *Metrics) incAccountJoin() { m.accountJoinsTotal.Add(1) }

// incHybridKeyPublish records one device hybrid public key publish/republish.
func (m *Metrics) incHybridKeyPublish() { m.hybridKeyPublishesTotal.Add(1) }

// incKeyEnvelopePut records one opaque wrapped-vault-key deposit.
func (m *Metrics) incKeyEnvelopePut() { m.keyEnvelopePutsTotal.Add(1) }

// incKeyEnvelopeGet records one envelope collected by its recipient.
func (m *Metrics) incKeyEnvelopeGet() { m.keyEnvelopeGetsTotal.Add(1) }

// incKeyEnvelopeDelete records one envelope removed by a vault owner during a
// key rotation (Phase 50). A counter only — no vault ID, no device ID, no blob.
func (m *Metrics) incKeyEnvelopeDelete() { m.keyEnvelopeDeletesTotal.Add(1) }

// incKeyEnvelopeIndex records one device asking which vaults hold a wrapped key
// for it (Phase 54). A counter only — no device ID, no vault ID, no blob.
func (m *Metrics) incKeyEnvelopeIndex() { m.keyEnvelopeIndexTotal.Add(1) }

// incAuthzDenied records one AUTHORIZATION denial (a 403), i.e. an
// authenticated device that was not permitted. It is counted separately from the
// per-reason breakdown so an operator can alert on 403s alone.
func (m *Metrics) incAuthzDenied() { m.authzDeniedTotal.Add(1) }

// writePrometheus emits the counters in Prometheus text exposition format
// (# HELP / # TYPE / samples). Output ordering is deterministic.
func (m *Metrics) writePrometheus(w io.Writer) {
	var b strings.Builder

	b.WriteString("# HELP sigild_build_info Build metadata; the value is always 1.\n")
	b.WriteString("# TYPE sigild_build_info gauge\n")
	b.WriteString(`sigild_build_info{version="`)
	b.WriteString(escapeLabelValue(m.version))
	b.WriteString("\"} 1\n")

	b.WriteString("# HELP sigild_schema_version Applied op-log DB migration version (0 when the backend is not Postgres).\n")
	b.WriteString("# TYPE sigild_schema_version gauge\n")
	b.WriteString("sigild_schema_version ")
	b.WriteString(strconv.FormatInt(m.schemaVersion, 10))
	b.WriteByte('\n')

	b.WriteString("# HELP sigild_http_requests_total Total HTTP responses served, by status class.\n")
	b.WriteString("# TYPE sigild_http_requests_total counter\n")
	for class := 1; class <= 5; class++ {
		b.WriteString(`sigild_http_requests_total{class="`)
		b.WriteString(strconv.Itoa(class))
		b.WriteString(`xx"} `)
		b.WriteString(strconv.FormatInt(m.httpByClass[class].Load(), 10))
		b.WriteByte('\n')
	}

	writeCounter(&b, "sigild_oplog_appends_total",
		"Total op-log appends accepted.", m.oplogAppendsTotal.Load())
	writeCounter(&b, "sigild_oplog_verify_total",
		"Total op-log chain verifications served.", m.oplogVerifyTotal.Load())
	writeCounter(&b, "sigild_oplog_ratelimit_rejected_total",
		"Total op-log requests rejected by the per-vault rate limiter.", m.oplogRateLimitedTotal.Load())

	// Abuse bounds. The surface label is a closed three-value set; there is
	// deliberately no key label, so a scrape cannot learn WHICH address, account
	// or provider was limited.
	b.WriteString("# HELP sigild_abuse_ratelimit_rejected_total Total requests rejected by an abuse-bound rate limiter, by surface.\n")
	b.WriteString("# TYPE sigild_abuse_ratelimit_rejected_total counter\n")
	for _, s := range abuseRateLimitSurfaces {
		b.WriteString(`sigild_abuse_ratelimit_rejected_total{surface="`)
		b.WriteString(s)
		b.WriteString(`"} `)
		b.WriteString(strconv.FormatInt(m.abuseRateLimited[s].Load(), 10))
		b.WriteByte('\n')
	}

	// Entitlement enforcement (Phase 55). The gauge says whether it is on; the
	// counter says what it decided. The outcome label is a closed four-value set
	// and there is deliberately NO account/subject label, so a scrape can never
	// learn WHO was refused — only how often anyone was.
	b.WriteString("# HELP sigild_entitlement_enforcing 1 when payment enforcement is active on the WRITE surfaces (reads are never enforced), else 0.\n")
	b.WriteString("# TYPE sigild_entitlement_enforcing gauge\n")
	b.WriteString("sigild_entitlement_enforcing ")
	b.WriteString(strconv.FormatInt(m.entitlementEnforcing, 10))
	b.WriteByte('\n')

	b.WriteString("# HELP sigild_entitlement_decisions_total Total entitlement checks on WRITE requests, by outcome.\n")
	b.WriteString("# TYPE sigild_entitlement_decisions_total counter\n")
	for _, o := range entitlementOutcomes {
		b.WriteString(`sigild_entitlement_decisions_total{outcome="`)
		b.WriteString(string(o))
		b.WriteString(`"} `)
		b.WriteString(strconv.FormatInt(m.entitlementDecisions[o].Load(), 10))
		b.WriteByte('\n')
	}

	writeCounter(&b, "sigild_device_enrollments_total",
		"Total device enrollments accepted.", m.deviceEnrollmentsTotal.Load())
	writeCounter(&b, "sigild_device_revocations_total",
		"Total device revocations performed.", m.deviceRevocationsTotal.Load())
	writeCounter(&b, "sigild_vault_grants_total",
		"Total per-vault access grants created.", m.vaultGrantsTotal.Load())
	writeCounter(&b, "sigild_vault_claims_total",
		"Total vault ownership claims (trust on first write).", m.vaultClaimsTotal.Load())
	writeCounter(&b, "sigild_accounts_created_total",
		"Total accounts created (operator-token enrollments).", m.accountsCreatedTotal.Load())
	writeCounter(&b, "sigild_account_invites_created_total",
		"Total account invites minted.", m.accountInvitesCreatedTotal.Load())
	writeCounter(&b, "sigild_account_invites_revoked_total",
		"Total account invites revoked before use.", m.accountInvitesRevokedTotal.Load())
	writeCounter(&b, "sigild_account_joins_total",
		"Total devices that joined an existing account by invite.", m.accountJoinsTotal.Load())
	writeCounter(&b, "sigild_device_hybrid_keys_published_total",
		"Total device hybrid public key publishes (including re-publishes).", m.hybridKeyPublishesTotal.Load())
	writeCounter(&b, "sigild_vault_key_envelopes_total",
		"Total opaque wrapped-vault-key envelopes deposited.", m.keyEnvelopePutsTotal.Load())
	writeCounter(&b, "sigild_vault_key_envelope_fetches_total",
		"Total opaque wrapped-vault-key envelopes collected by their recipient.", m.keyEnvelopeGetsTotal.Load())
	writeCounter(&b, "sigild_key_envelope_deletes_total",
		"Total opaque wrapped-vault-key envelopes deleted during a vault key rotation.", m.keyEnvelopeDeletesTotal.Load())
	writeCounter(&b, "sigild_key_envelope_index_total",
		"Total per-device key-envelope index reads (which vaults hold a wrapped key for the caller).", m.keyEnvelopeIndexTotal.Load())
	writeCounter(&b, "sigild_oplog_authz_denied_total",
		"Total requests denied by per-vault authorization (HTTP 403).", m.authzDeniedTotal.Load())

	b.WriteString("# HELP sigild_oplog_auth_denied_total Total requests denied by request auth/authz, by reason.\n")
	b.WriteString("# TYPE sigild_oplog_auth_denied_total counter\n")
	for _, r := range authDenyReasons {
		b.WriteString(`sigild_oplog_auth_denied_total{reason="`)
		b.WriteString(string(r))
		b.WriteString(`"} `)
		b.WriteString(strconv.FormatInt(m.authDenied[r].Load(), 10))
		b.WriteByte('\n')
	}

	b.WriteString("# HELP sigild_device_enroll_denied_total Total device enrollment attempts denied, by reason.\n")
	b.WriteString("# TYPE sigild_device_enroll_denied_total counter\n")
	for _, r := range enrollDenyReasons {
		b.WriteString(`sigild_device_enroll_denied_total{reason="`)
		b.WriteString(string(r))
		b.WriteString(`"} `)
		b.WriteString(strconv.FormatInt(m.enrollDenied[r].Load(), 10))
		b.WriteByte('\n')
	}

	// Billing. Counts only, over closed label sets: provider names, normalized
	// outcomes, a fixed reason enum, and subscription statuses. Nothing here can
	// carry a secret, a signature, a webhook body, a subject ID, an email or an
	// amount.
	b.WriteString("# HELP sigild_billing_checkouts_total Total hosted checkout sessions created, by provider.\n")
	b.WriteString("# TYPE sigild_billing_checkouts_total counter\n")
	for _, p := range billing.SupportedProviders {
		b.WriteString(`sigild_billing_checkouts_total{provider="`)
		b.WriteString(p)
		b.WriteString(`"} `)
		b.WriteString(strconv.FormatInt(m.billingCheckouts[p].Load(), 10))
		b.WriteByte('\n')
	}

	b.WriteString("# HELP sigild_billing_webhooks_total Total authenticated webhooks handled, by provider and outcome.\n")
	b.WriteString("# TYPE sigild_billing_webhooks_total counter\n")
	for _, p := range billing.SupportedProviders {
		for _, o := range billingWebhookOutcomes {
			b.WriteString(`sigild_billing_webhooks_total{provider="`)
			b.WriteString(p)
			b.WriteString(`",outcome="`)
			b.WriteString(o)
			b.WriteString(`"} `)
			b.WriteString(strconv.FormatInt(m.billingWebhooks[billingWebhookKey(p, o)].Load(), 10))
			b.WriteByte('\n')
		}
	}

	b.WriteString("# HELP sigild_billing_webhook_rejected_total Total webhooks rejected before application, by reason.\n")
	b.WriteString("# TYPE sigild_billing_webhook_rejected_total counter\n")
	for _, reason := range billingRejectReasons {
		b.WriteString(`sigild_billing_webhook_rejected_total{reason="`)
		b.WriteString(reason)
		b.WriteString(`"} `)
		b.WriteString(strconv.FormatInt(m.billingWebhookRejected[reason].Load(), 10))
		b.WriteByte('\n')
	}

	b.WriteString("# HELP sigild_billing_subscription_transitions_total Total applied subscription status transitions, by target status.\n")
	b.WriteString("# TYPE sigild_billing_subscription_transitions_total counter\n")
	for _, s := range billing.Statuses {
		b.WriteString(`sigild_billing_subscription_transitions_total{status="`)
		b.WriteString(string(s))
		b.WriteString(`"} `)
		b.WriteString(strconv.FormatInt(m.billingSubTransitions[s].Load(), 10))
		b.WriteByte('\n')
	}

	_, _ = io.WriteString(w, b.String())
}

// writeCounter emits a single (unlabeled) counter with its HELP/TYPE lines.
func writeCounter(b *strings.Builder, name, help string, v int64) {
	b.WriteString("# HELP ")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(help)
	b.WriteByte('\n')
	b.WriteString("# TYPE ")
	b.WriteString(name)
	b.WriteString(" counter\n")
	b.WriteString(name)
	b.WriteByte(' ')
	b.WriteString(strconv.FormatInt(v, 10))
	b.WriteByte('\n')
}

// escapeLabelValue escapes a Prometheus label value: backslash, double-quote,
// and newline, per the text exposition format.
func escapeLabelValue(s string) string {
	if !strings.ContainsAny(s, "\\\"\n") {
		return s
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(s)
}

// metricsHandler serves the Prometheus text exposition. It is ALWAYS wired (not
// dev-gated): it exposes only counters and the build version, never secrets or
// vault material, so it is safe to expose for operational scraping.
func (h *handlers) metricsHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	h.metrics.writePrometheus(w)
}

// countRequests is middleware that records every served response into m by
// status class. It is placed OUTERMOST in the chain so a response written by the
// panic recoverer (a 500) is still counted.
func countRequests(m *Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			m.observeHTTP(rec.status)
		})
	}
}
