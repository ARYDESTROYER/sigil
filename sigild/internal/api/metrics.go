package api

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
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

	// Device-model counters (Phase 41). Counts ONLY — never a device's public
	// key, an enrollment token (or its digest), an admin token, a signature, a
	// nonce, or a vault/device ID as a label (an ID label would let a scrape
	// enumerate the registry).
	deviceEnrollmentsTotal atomic.Int64
	deviceRevocationsTotal atomic.Int64
	vaultGrantsTotal       atomic.Int64
	vaultClaimsTotal       atomic.Int64
	authzDeniedTotal       atomic.Int64

	// authDenied counts request auth/authz denials, keyed by the fixed
	// authReason enum so /metrics can label each by reason. Built once
	// (immutable key set); only the atomic values mutate.
	authDenied map[authReason]*atomic.Int64
	// enrollDenied counts enrollment denials by reason, over the enrollment
	// subset of the same enum.
	enrollDenied map[authReason]*atomic.Int64
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
}

// enrollDenyReasons is the fixed set of enrollment-denial reasons, in a stable
// order. It deliberately does NOT distinguish anything the client is told: the
// split exists only for the operator's metrics.
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
	reasonStoreUnavailable,
}

// newMetrics returns a fresh, zeroed Metrics for one router/server instance.
// schemaVersion is the applied op-log DB migration version (0 for mem/file).
func newMetrics(version string, schemaVersion int64) *Metrics {
	m := &Metrics{
		version:       version,
		schemaVersion: schemaVersion,
		authDenied:    make(map[authReason]*atomic.Int64, len(authDenyReasons)),
		enrollDenied:  make(map[authReason]*atomic.Int64, len(enrollDenyReasons)),
	}
	for _, r := range authDenyReasons {
		m.authDenied[r] = new(atomic.Int64)
	}
	for _, r := range enrollDenyReasons {
		m.enrollDenied[r] = new(atomic.Int64)
	}
	return m
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

// incAuthDenied records one request auth/authz denial by reason. An unknown
// reason (should not occur — reason comes from the fixed enum) is ignored rather
// than mutating the map concurrently.
func (m *Metrics) incAuthDenied(reason authReason) {
	if c := m.authDenied[reason]; c != nil {
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

// incVaultClaim records one trust-on-first-write vault ownership claim.
func (m *Metrics) incVaultClaim() { m.vaultClaimsTotal.Add(1) }

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

	writeCounter(&b, "sigild_device_enrollments_total",
		"Total device enrollments accepted.", m.deviceEnrollmentsTotal.Load())
	writeCounter(&b, "sigild_device_revocations_total",
		"Total device revocations performed.", m.deviceRevocationsTotal.Load())
	writeCounter(&b, "sigild_vault_grants_total",
		"Total per-vault access grants created.", m.vaultGrantsTotal.Load())
	writeCounter(&b, "sigild_vault_claims_total",
		"Total vault ownership claims (trust on first write).", m.vaultClaimsTotal.Load())
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
