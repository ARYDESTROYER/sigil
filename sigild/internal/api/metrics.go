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

	// httpRequestsTotal counts every HTTP response the server produced; the
	// httpByClass buckets split that by status class (index = status/100, so
	// index 2 == 2xx). Index 0 and any out-of-range class are never emitted.
	httpRequestsTotal atomic.Int64
	httpByClass       [6]atomic.Int64

	oplogAppendsTotal     atomic.Int64
	oplogVerifyTotal      atomic.Int64
	oplogRateLimitedTotal atomic.Int64

	// authDenied counts op-log auth denials, keyed by the fixed authReason enum
	// so /metrics can label each by reason. Built once (immutable key set); only
	// the atomic values mutate.
	authDenied map[authReason]*atomic.Int64
}

// authDenyReasons is the fixed, exhaustive set of non-OK auth reasons, in a
// stable order so the /metrics output is deterministic.
var authDenyReasons = []authReason{
	reasonMissingHeaders,
	reasonBadTimestamp,
	reasonStaleTimestamp,
	reasonBadSignature,
	reasonReplayed,
}

// newMetrics returns a fresh, zeroed Metrics for one router/server instance.
func newMetrics(version string) *Metrics {
	m := &Metrics{
		version:    version,
		authDenied: make(map[authReason]*atomic.Int64, len(authDenyReasons)),
	}
	for _, r := range authDenyReasons {
		m.authDenied[r] = new(atomic.Int64)
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

// incAuthDenied records one op-log auth denial by reason. An unknown reason
// (should not occur — reason comes from the fixed enum) is ignored rather than
// mutating the map concurrently.
func (m *Metrics) incAuthDenied(reason authReason) {
	if c := m.authDenied[reason]; c != nil {
		c.Add(1)
	}
}

// writePrometheus emits the counters in Prometheus text exposition format
// (# HELP / # TYPE / samples). Output ordering is deterministic.
func (m *Metrics) writePrometheus(w io.Writer) {
	var b strings.Builder

	b.WriteString("# HELP sigild_build_info Build metadata; the value is always 1.\n")
	b.WriteString("# TYPE sigild_build_info gauge\n")
	b.WriteString(`sigild_build_info{version="`)
	b.WriteString(escapeLabelValue(m.version))
	b.WriteString("\"} 1\n")

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

	b.WriteString("# HELP sigild_oplog_auth_denied_total Total op-log requests denied by request auth, by reason.\n")
	b.WriteString("# TYPE sigild_oplog_auth_denied_total counter\n")
	for _, r := range authDenyReasons {
		b.WriteString(`sigild_oplog_auth_denied_total{reason="`)
		b.WriteString(string(r))
		b.WriteString(`"} `)
		b.WriteString(strconv.FormatInt(m.authDenied[r].Load(), 10))
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
