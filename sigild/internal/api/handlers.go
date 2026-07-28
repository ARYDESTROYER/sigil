package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

type handlers struct {
	cfg Config
	// log backs the DEV-ONLY vault op-log. It is nil unless cfg.DevOpsEnabled,
	// in which case NewRouter wires an in-memory MemVaultLog and routes
	// opsAppend/opsList here instead of the 501 stub.
	log store.VaultLog
	// nonces is the request-auth replay cache, shared by the v2 op-log contract
	// and the v3 device contract (enrollment nonces are namespaced, see
	// enrollNoncePrefix). NewRouter constructs it whenever ANY auth mode is on
	// (cfg.OpLogPubKey set, or a device registry wired); it is nil otherwise and
	// the auth paths return before touching it.
	nonces *nonceCache
	// devices backs the v3 multi-device auth model: the device registry, the
	// enrollment-token ledger, and per-vault grants. It is nil unless the device
	// model is configured AND cfg.DevOpsEnabled — nil means the server keeps its
	// existing legacy-v2 / no-auth behaviour exactly.
	devices store.DeviceStore
	// metrics holds this router's observability counters. NewRouter always
	// constructs it (non-nil), so every handler can increment without a guard.
	metrics *Metrics
	// inviteLimiter bounds invite MINTING per ACCOUNT (Phase 53). It is nil
	// unless a positive rate was configured — nil means "not configured" and
	// allowAbuse short-circuits, so an un-opted-in server does no extra work.
	// The enrollment limiter is not here: it is a route wrapper, because it
	// charges the bucket from the handler's OUTCOME (see rateLimitEnroll).
	//
	// ⛔ There is deliberately no webhook limiter: shedding traffic on the
	// billing webhook loses payment events (see billingWebhook).
	inviteLimiter *rateLimiter
	// entitlement is the payment-enforcement policy (Phase 55). Its ZERO VALUE
	// IS OFF, and NewRouter leaves it zero unless enforcement was explicitly
	// enabled AND both the device model and billing are live. See
	// entitlement.go — in particular, no READ handler ever consults it.
	entitlement entitlementPolicy
}

// denyOps records an auth/authz denial (audit line + metrics) and writes the
// typed error. It is the single choke point shared by the ops and device
// handlers so the audit event, the per-reason metric, and the response stay in
// lockstep. The client learns only the status class; the precise reason goes
// only to the audit log.
func (h *handlers) denyOps(w http.ResponseWriter, r *http.Request, vaultID string, out authOutcome) {
	h.auditAuthDenied(r, vaultID, out.DeviceID, out.Reason)
	h.metrics.incAuthDenied(out.Reason)
	if authStatus(out.Reason) == http.StatusForbidden {
		h.metrics.incAuthzDenied()
	}
	writeAuthError(w, out.Reason)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// healthz is a pure liveness probe: the process is up and serving.
func (h *handlers) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": h.cfg.Version,
	})
}

// version reports the build's name and injected version string. It exposes no
// secrets and performs no cryptography — it simply echoes the value threaded in
// from buildinfo at build time (via api.Config.Version). Useful for confirming
// which build is deployed without parsing the liveness probe.
func (h *handlers) version(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"name":    "sigild",
		"version": h.cfg.Version,
	})
}

// readyzPingTimeout bounds the live op-log backend health check so a wedged
// database can never hang the readiness probe. It is deliberately short: a slow
// backend should drain the instance, not stall the load balancer's probe.
const readyzPingTimeout = 2 * time.Second

// readyz reports whether sigild's dependencies are reachable. Configured
// host:port targets get a plain TCP dial. Additionally, when the DEV op-log is
// on and its backend can report live health (implements store.Pinger — i.e. the
// Postgres backend), we ping the REAL dependency rather than merely dialing, so a
// load balancer drains an instance whose database is down. Mem/File have no
// external dependency and do not implement Pinger, so the live check is skipped
// for them (and h.log is nil when dev-ops is off). Any "unreachable" check makes
// the whole probe 503.
func (h *handlers) readyz(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{
		"postgres": dialState(h.cfg.PostgresAddr),
		"redis":    dialState(h.cfg.RedisAddr),
	}
	if p, ok := h.log.(store.Pinger); ok {
		ctx, cancel := context.WithTimeout(r.Context(), readyzPingTimeout)
		defer cancel()
		if err := p.Ping(ctx); err != nil {
			checks["oplog"] = "unreachable"
		} else {
			checks["oplog"] = "ok"
		}
	}
	status := http.StatusOK
	for _, state := range checks {
		if state == "unreachable" {
			status = http.StatusServiceUnavailable
		}
	}
	writeJSON(w, status, map[string]any{
		"version": h.cfg.Version,
		"checks":  checks,
	})
}

func dialState(addr string) string {
	if addr == "" {
		return "unconfigured"
	}
	conn, err := net.DialTimeout("tcp", addr, 750*time.Millisecond)
	if err != nil {
		return "unreachable"
	}
	_ = conn.Close()
	return "ok"
}

// opsNotImplemented is the deliberate 501 for the vault operation log. On POST
// it first drains the (size-capped) request body so an oversized payload is
// rejected with 413 before we reach the not-implemented response.
func (h *handlers) opsNotImplemented(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			if maxErr := (*http.MaxBytesError)(nil); errors.As(err, &maxErr) {
				writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
					"request body exceeds the per-operation size limit")
				return
			}
			writeError(w, http.StatusBadRequest, "invalid_request",
				"could not read request body")
			return
		}
	}
	writeJSON(w, http.StatusNotImplemented, apiError{
		Error:   "not_implemented",
		Detail:  "vault operation log is not implemented in the pre-audit skeleton",
		VaultID: r.PathValue("vaultID"),
	})
}

// opsAppend appends one opaque, client-encrypted operation to a vault's log.
//
// DEV-ONLY: this handler is wired ONLY when cfg.DevOpsEnabled is set. It is
// UNAUTHENTICATED, backed by an IN-MEMORY, NON-DURABLE op-log, and performs NO
// cryptography — it treats the request body as opaque bytes and never decrypts,
// parses, or interprets them. Do NOT expose publicly; this is a dev skeleton,
// not production. The body is already capped upstream by limitBody (oversized
// -> 413).
func (h *handlers) opsAppend(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")
	if vaultID == "" {
		writeError(w, http.StatusBadRequest, "missing_vault_id", "vault ID is required")
		return
	}

	blob, err := io.ReadAll(r.Body)
	if err != nil {
		if maxErr := (*http.MaxBytesError)(nil); errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
				"request body exceeds the per-operation size limit")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "could not read request body")
		return
	}
	// Authenticate + authorize. In the v3 device model this resolves
	// X-Sigil-Device, verifies the signature under THAT device's registered key,
	// rejects a revoked device, and requires WRITE access to THIS vault (claiming
	// an unowned vault on first write). In legacy v2 mode it is the unchanged
	// single-key signature check; with no auth configured it always allows. Must
	// run AFTER the body is read (it is part of the signed message) and BEFORE we
	// append.
	//
	// ⭐ THE CLAIM PRECONDITION (Phase 57): an EMPTY body is rejected below with a
	// 400, so such a request must not be able to CLAIM an unowned vault on its way
	// to that rejection. Passing it here downgrades needWrite to needWriteNoClaim,
	// which is the whole fix — the authorization checks themselves are untouched
	// and still run first. On an unowned vault the empty write therefore answers
	// 403 (it holds no grant and earned no ownership) rather than 400; on a vault
	// the caller may write it still answers 400. Either way: nothing is claimed.
	//
	// The abuse limiter cannot substitute for this ordering: SIGILD_OPLOG_RATE_LIMIT
	// keys on the vault id, and a squatter varies the vault id every request. A
	// per-ACCOUNT claim budget is the real bound and is NOT implemented — see
	// claimPrecondition for the honest limit.
	bodyEmpty := len(blob) == 0
	dev, out := h.authorizeOpsWrite(r, blob, vaultID, func() bool { return !bodyEmpty })
	if !out.allowed() {
		h.denyOps(w, r, vaultID, out)
		return
	}
	// ENTITLEMENT (Phase 55), strictly AFTER authentication and authorization so
	// the 402 can never become an oracle for a caller who was going to be refused
	// anyway. Off by default; inside grace this only sets warning headers. The
	// MATCHING READ ROUTE (opsList) HAS NO SUCH CHECK, on purpose: a customer who
	// stopped paying can still read every code they already have.
	//
	// Note the ordering consequence, accepted knowingly: a first write to an
	// unclaimed vault has already CLAIMED it above before we refuse here. That is
	// harmless — the claim binds the vault to the caller's own account, which is
	// the same party that would pay — and keeping the claim inside the single
	// authorization choke point is worth more than avoiding it.
	if !h.requireEntitlement(w, r, dev, entitlementSurfaceOpsAppend) {
		return
	}
	if bodyEmpty {
		writeError(w, http.StatusBadRequest, "empty_op", "operation body must not be empty")
		return
	}

	op, err := h.log.Append(r.Context(), vaultID, blob)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	h.auditAppend(r, vaultID, op.Seq, blob)
	h.metrics.incAppend()
	writeJSON(w, http.StatusCreated, struct {
		VaultID string `json:"vaultID"`
		Seq     uint64 `json:"seq"`
	}{VaultID: vaultID, Seq: op.Seq})
}

// Op-log listing page sizing. A GET never returns an unbounded response: the
// handler always requests at most maxOpsPageLimit ops, defaulting to
// defaultOpsPageLimit when the client omits ?limit=, and clamping any explicit
// value into [1, maxOpsPageLimit]. A client pages forward with since=next until
// has_more is false.
const (
	defaultOpsPageLimit = 500
	maxOpsPageLimit     = 1000
)

// opsList returns a vault's operations with Seq greater than ?since= (default
// 0), in ascending order, capped at ?limit= (default defaultOpsPageLimit, clamped
// to [1, maxOpsPageLimit]). Next is the max returned Seq, or the `since` value
// when nothing matched, so a caller can poll forward. HasMore is true when the
// page was filled exactly to the limit — i.e. more ops may remain.
//
// DEV-ONLY: wired ONLY when cfg.DevOpsEnabled is set. UNAUTHENTICATED,
// IN-MEMORY, NON-DURABLE, performs NO cryptography. Each Op.Blob is the opaque
// client-encrypted payload exactly as stored; encoding/json marshals it ([]byte)
// as a base64 string automatically. Do NOT expose publicly.
func (h *handlers) opsList(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")
	if vaultID == "" {
		writeError(w, http.StatusBadRequest, "missing_vault_id", "vault ID is required")
		return
	}

	// Authenticate + authorize for READ. GET carries no body, so the signed body
	// is empty. In the v3 device model an unowned vault is NOT claimed by a read:
	// a device with no grant gets 403.
	if out := h.authorizeOpsRequest(r, nil, vaultID, needRead); !out.allowed() {
		h.denyOps(w, r, vaultID, out)
		return
	}

	var since uint64
	if raw := r.URL.Query().Get("since"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_since",
				"since must be a non-negative integer")
			return
		}
		since = parsed
	}

	// limit: absent (or empty) => default; explicitly non-numeric => 400; a valid
	// number is clamped into [1, maxOpsPageLimit] so a client can neither request
	// an unbounded response nor a nonsensical page size.
	limit := defaultOpsPageLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, "bad_limit",
				"limit must be an integer")
			return
		}
		switch {
		case parsed < 1:
			limit = 1
		case parsed > maxOpsPageLimit:
			limit = maxOpsPageLimit
		default:
			limit = parsed
		}
	}

	ops, err := h.log.Since(r.Context(), vaultID, since, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	h.auditList(r, vaultID, since, len(ops))

	next := since
	wire := make([]opJSON, len(ops))
	for i, op := range ops {
		if op.Seq > next {
			next = op.Seq
		}
		wire[i] = opJSON{
			Seq:  op.Seq,
			Blob: op.Blob,
			Hash: base64.StdEncoding.EncodeToString(op.Hash[:]),
		}
	}
	// A page filled exactly to the limit MAY have more behind it; the client
	// should fetch again with since=next.
	hasMore := len(ops) == limit
	writeJSON(w, http.StatusOK, struct {
		VaultID string   `json:"vaultID"`
		Ops     []opJSON `json:"ops"`
		Next    uint64   `json:"next"`
		HasMore bool     `json:"has_more"`
	}{VaultID: vaultID, Ops: wire, Next: next, HasMore: hasMore})
}

// opJSON is the wire shape of one op. Blob ([]byte) marshals to std-base64
// automatically; Hash is emitted explicitly as std-base64 (encoding/json would
// otherwise render the [32]byte as a numeric array).
type opJSON struct {
	Seq  uint64 `json:"seq"`
	Blob []byte `json:"blob"`
	Hash string `json:"hash"`
}

// opsVerify walks a vault's op-log hash chain and reports whether it is intact.
//
// DEV-ONLY: wired ONLY when cfg.DevOpsEnabled is set, and (like the other ops
// routes) guarded by authorizeOps when a device key is configured. This is
// tamper-EVIDENT verification: it DETECTS an insertion/deletion/modification of a
// stored op, but does not prevent one. It is NOT append-only-enforced, notarized,
// or Byzantine-proof, and a dishonest server can lie about this result — the
// trustworthy check is CLIENT-SIDE, recomputing the chain from the per-op hashes
// returned by GET /ops. The chain fingerprints the OPAQUE ciphertext only.
func (h *handlers) opsVerify(w http.ResponseWriter, r *http.Request) {
	vaultID := r.PathValue("vaultID")
	if vaultID == "" {
		writeError(w, http.StatusBadRequest, "missing_vault_id", "vault ID is required")
		return
	}

	// Authenticate + authorize for READ (GET carries no body). Same rules as
	// opsList: no grant on the vault => 403, and a read never claims ownership.
	if out := h.authorizeOpsRequest(r, nil, vaultID, needRead); !out.allowed() {
		h.denyOps(w, r, vaultID, out)
		return
	}

	res, err := h.log.VerifyChain(r.Context(), vaultID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal", "")
		return
	}
	h.auditVerify(r, vaultID, res.OK, res.Count)
	h.metrics.incVerify()

	writeJSON(w, http.StatusOK, struct {
		VaultID string `json:"vaultID"`
		OK      bool   `json:"ok"`
		Count   uint64 `json:"count"`
		TipHash string `json:"tip_hash"`
		// BrokenAtSeq is the seq of the first broken link; omitted when ok.
		BrokenAtSeq uint64 `json:"broken_at_seq,omitempty"`
	}{
		VaultID:     vaultID,
		OK:          res.OK,
		Count:       res.Count,
		TipHash:     base64.StdEncoding.EncodeToString(res.TipHash[:]),
		BrokenAtSeq: res.BrokenAtSeq,
	})
}
