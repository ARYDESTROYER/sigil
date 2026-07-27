// Package api wires sigild's HTTP surface.
//
// STATUS: pre-audit skeleton. The router exposes only liveness/readiness and a
// 501 stub for the vault operation log. Real authentication, the CRDT op log,
// device enrollment, recovery and admin endpoints are deferred (see the brief,
// section 14, and docs/sprint-72h.md).
package api

import (
	"crypto/ed25519"
	"log/slog"
	"net/http"

	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

// Config holds the server's runtime configuration.
type Config struct {
	Version string
	// PostgresAddr / RedisAddr are "host:port" reachability targets used by the
	// readiness probe. The production build will swap the plain TCP dial for a
	// real pgx / redis client ping.
	PostgresAddr string
	RedisAddr    string
	Logger       *slog.Logger
	// DevOpsEnabled gates the DEV-ONLY vault op-log. It defaults to false, which
	// keeps the vault-ops routes at their 501 stub. When true, the routes serve
	// an UNAUTHENTICATED, in-memory, non-durable op-log of opaque
	// client-encrypted blobs — for local development ONLY, never production.
	DevOpsEnabled bool
	// VaultLog is OPTIONAL. When DevOpsEnabled is true, NewRouter uses this
	// backend if it is non-nil; otherwise it falls back to an in-memory
	// MemVaultLog (the default). It lets local dev select a durable
	// FileVaultLog without changing handler behaviour. It is ignored when
	// DevOpsEnabled is false (the routes stay at their 501 stub).
	VaultLog store.VaultLog
	// OpLogPubKey, when non-nil AND DevOpsEnabled is true, turns on Ed25519
	// request-authentication for the dev op-log: every GET/POST
	// /v1/vaults/{vaultID}/ops must carry a valid X-Sigil-Timestamp +
	// X-Sigil-Nonce + X-Sigil-Signature per the op-log auth contract v2 (see
	// opsauth.go). nil (the default) means NO auth — unchanged, UNAUTHENTICATED
	// behaviour.
	//
	// HONEST SCOPE: this is a SINGLE configured DEV device key. Each request
	// carries a fresh nonce and the server keeps a PER-PROCESS/in-memory replay
	// cache, so a captured request cannot be replayed within the timestamp
	// window against this instance — but a multi-instance deploy needs a shared
	// store (e.g. Redis). Real device enrollment, a multi-device registry, and
	// JWT bearer tokens (see internal/auth) remain FUTURE. Dev-only; do NOT
	// expose publicly.
	OpLogPubKey ed25519.PublicKey
	// OpLogRateLimit is the per-vault write rate cap for the dev op-log, in
	// requests/second. 0 (the default) DISABLES rate limiting entirely (no
	// wrapper is installed; behaviour is unchanged). A positive value, together
	// with DevOpsEnabled, wraps POST /v1/vaults/{vaultID}/ops in a per-vault
	// token-bucket limiter that returns 429 when a vault exceeds its rate. GET
	// routes are never write-rate-limited. Dev-only.
	OpLogRateLimit float64
	// OpLogRateBurst is the token-bucket capacity (max burst) for OpLogRateLimit.
	// It is only consulted when OpLogRateLimit > 0; a value < 1 is clamped up to
	// 1 by the limiter so single requests always pass.
	OpLogRateBurst int
	// SchemaVersion is the applied op-log DB migration version, surfaced by the
	// sigild_schema_version metric. main.go sets it from the Postgres backend's
	// applied migration version; it stays 0 for the mem/file backends (which
	// have no migrations).
	SchemaVersion int64

	// ---- Multi-device auth model (Phase 41). OPT-IN; all default OFF. ----

	// Devices, when non-nil AND DevOpsEnabled is true, turns on the v3
	// MULTI-DEVICE auth model: every ops request must carry X-Sigil-Device
	// naming an enrolled device, the signature is verified against THAT device's
	// registered Ed25519 public key, a revoked device is rejected immediately,
	// and the device must hold a per-vault grant (401 vs 403 are distinct).
	// It also wires the device routes (enroll / list / revoke / grants).
	//
	// nil (the default) leaves behaviour EXACTLY as before: legacy contract v2
	// against OpLogPubKey when that is set, or no auth at all. When Devices is
	// non-nil the v3 model takes precedence and OpLogPubKey is ignored (the
	// server refuses to start with both configured — see cmd/server).
	Devices store.DeviceStore
	// EnrollTokenHashes are the lowercase hex SHA-256 digests of the
	// operator-provisioned enrollment tokens (from SIGILD_ENROLL_TOKENS). The
	// PLAINTEXT tokens never reach this struct, are never stored, and are never
	// logged. An empty slice means NO device can enroll.
	EnrollTokenHashes []string
	// Billing wires the OPT-IN subscription/payment layer (Phase 45). With no
	// providers configured (the default) Billing.Enabled() is false and every
	// /v1/billing route returns the deliberate 501 — exactly like the ops and
	// device routes, and exactly like a server with billing compiled in but
	// never switched on.
	//
	// It additionally requires Devices: checkout and subscription status are
	// authenticated with the EXISTING device-auth v3 contract, so without a
	// device registry there is nobody to authenticate a buyer as. cmd/server
	// rejects that combination at boot; the router gates on it defensively.
	//
	// NO CARD DATA passes through this configuration or the handlers behind it:
	// every provider is used through its HOSTED checkout flow.
	Billing BillingConfig
	// AdminToken is the OPTIONAL operator token (SIGILD_ADMIN_TOKEN) that
	// authorizes the operator-only device routes (list all devices, revoke any
	// device). Empty (the default) means those operator paths are permanently
	// unauthorized — there is no implicit open-admin mode. It is compared in
	// constant time and never logged or exported.
	AdminToken string
}

// NewRouter returns the sigild HTTP handler.
func NewRouter(cfg Config) http.Handler {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	h := &handlers{cfg: cfg, metrics: newMetrics(cfg.Version, cfg.SchemaVersion)}
	// The v3 multi-device model is active only when a registry is wired AND the
	// dev op-log is on — it is dev-gated exactly like the ops routes. When it is
	// off nothing below changes: the legacy v2 single-key path (or no auth) is
	// used verbatim.
	deviceAuth := cfg.DevOpsEnabled && cfg.Devices != nil
	if deviceAuth {
		h.devices = cfg.Devices
	}
	// Request-auth enabled (either contract) => attach the in-memory replay cache
	// so a captured, validly-signed request cannot be replayed within the
	// timestamp window. Per-process/in-memory only (a multi-instance deploy needs
	// a shared store, e.g. Redis); dev-only. nil when auth is off entirely (the
	// auth paths return before touching it).
	if cfg.OpLogPubKey != nil || deviceAuth {
		h.nonces = newNonceCache()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", h.healthz)
	mux.HandleFunc("GET /readyz", h.readyz)
	mux.HandleFunc("GET /version", h.version)
	// Operational metrics: ALWAYS available (never dev-gated). It exposes only
	// process counters and the build version — no secrets, no vault material.
	mux.HandleFunc("GET /metrics", h.metricsHandler)

	if cfg.DevOpsEnabled {
		// DEV-ONLY op-log: UNAUTHENTICATED. Stores opaque client-encrypted
		// blobs; performs no crypto. Never expose publicly. POST is body-capped
		// (oversized -> 413); GET reads only. Backend selection: use the
		// caller-supplied cfg.VaultLog if set (e.g. a durable FileVaultLog),
		// else default to a non-durable in-memory MemVaultLog. Handler
		// behaviour is identical for either backend.
		if cfg.VaultLog != nil {
			h.log = cfg.VaultLog
		} else {
			h.log = store.NewMemVaultLog()
		}
		// POST append: body-capped, then (optionally) per-vault rate-limited.
		// The rate limiter wraps OUTSIDE limitBody so an over-rate request is
		// rejected with 429 before any body handling; it is installed only when a
		// positive rate is configured (0 => no wrapper, behaviour unchanged). GET
		// routes are never write-rate-limited.
		var appendHandler http.Handler = limitBody(maxOpsBodyBytes, http.HandlerFunc(h.opsAppend))
		if cfg.OpLogRateLimit > 0 {
			appendHandler = rateLimitOps(newRateLimiter(cfg.OpLogRateLimit, cfg.OpLogRateBurst), h.metrics, appendHandler)
		}
		mux.Handle("POST /v1/vaults/{vaultID}/ops", appendHandler)
		mux.Handle("GET /v1/vaults/{vaultID}/ops", http.HandlerFunc(h.opsList))
		// Tamper-evidence: walk the op-log hash chain. Same dev-gate + auth-guard
		// as the other ops routes.
		mux.Handle("GET /v1/vaults/{vaultID}/ops/verify", http.HandlerFunc(h.opsVerify))
	} else {
		// Default: vault operation log is intentionally unimplemented in the
		// skeleton. We return 501 rather than fake any crypto/vault/CRDT/auth
		// behaviour. The body is capped at 64 KiB per operation: oversized
		// requests get 413, well-formed small requests fall through to 501.
		ops := limitBody(maxOpsBodyBytes, http.HandlerFunc(h.opsNotImplemented))
		mux.Handle("GET /v1/vaults/{vaultID}/ops", ops)
		mux.Handle("POST /v1/vaults/{vaultID}/ops", ops)
		// The verify route is a distinct path, so register its own 501 stub
		// (it would otherwise 404 instead of the deliberate not-implemented 501).
		mux.Handle("GET /v1/vaults/{vaultID}/ops/verify", http.HandlerFunc(h.opsNotImplemented))
	}

	// Device routes (enrollment, listing, revocation, per-vault grants). They are
	// dev-gated exactly like the ops routes AND additionally require a configured
	// device registry: with either off, every one of them returns the deliberate
	// 501 rather than 404 or any partial auth behaviour.
	if deviceAuth {
		mux.Handle("POST /v1/devices/enroll", http.HandlerFunc(h.devicesEnroll))
		mux.Handle("GET /v1/devices", http.HandlerFunc(h.devicesList))
		mux.Handle("POST /v1/devices/{deviceID}/revoke", http.HandlerFunc(h.devicesRevoke))
		mux.Handle("POST /v1/vaults/{vaultID}/grants", http.HandlerFunc(h.vaultGrantCreate))
		mux.Handle("GET /v1/vaults/{vaultID}/grants", http.HandlerFunc(h.vaultGrantList))
		// Vault sharing (Phase 46): device hybrid PUBLIC keys and the opaque
		// key-envelope relay. Same dev-gate and same auth choke points as the
		// routes above — see sharing.go for the authorization rules. The
		// envelope PUT is body-capped (oversized -> 413) before the handler runs.
		mux.Handle("PUT /v1/devices/{deviceID}/hybrid-key", http.HandlerFunc(h.deviceHybridKeyPublish))
		mux.Handle("GET /v1/devices/{deviceID}/hybrid-key", http.HandlerFunc(h.deviceHybridKeyFetch))
		mux.Handle("PUT /v1/vaults/{vaultID}/keys/{deviceID}",
			limitBody(store.MaxKeyEnvelopeBytes, http.HandlerFunc(h.keyEnvelopePut)))
		mux.Handle("GET /v1/vaults/{vaultID}/keys/{deviceID}", http.HandlerFunc(h.keyEnvelopeGet))
		// Rotation support (Phase 50): an owner lists which devices still hold a
		// wrapped key for a vault, and deletes the stale envelopes of devices it
		// is rotating away from. Both need WRITE on the vault, through the SAME
		// authorizeOpsRequest choke point the envelope PUT uses — there is no new
		// auth path. The list route returns METADATA only, never a blob.
		mux.Handle("GET /v1/vaults/{vaultID}/keys", http.HandlerFunc(h.keyEnvelopeList))
		mux.Handle("DELETE /v1/vaults/{vaultID}/keys/{deviceID}", http.HandlerFunc(h.keyEnvelopeDelete))
	} else {
		stub := http.HandlerFunc(h.deviceNotImplemented)
		mux.Handle("POST /v1/devices/enroll", stub)
		mux.Handle("GET /v1/devices", stub)
		mux.Handle("POST /v1/devices/{deviceID}/revoke", stub)
		mux.Handle("POST /v1/vaults/{vaultID}/grants", stub)
		mux.Handle("GET /v1/vaults/{vaultID}/grants", stub)
		mux.Handle("PUT /v1/devices/{deviceID}/hybrid-key", stub)
		mux.Handle("GET /v1/devices/{deviceID}/hybrid-key", stub)
		mux.Handle("PUT /v1/vaults/{vaultID}/keys/{deviceID}",
			limitBody(store.MaxKeyEnvelopeBytes, stub))
		mux.Handle("GET /v1/vaults/{vaultID}/keys/{deviceID}", stub)
		mux.Handle("GET /v1/vaults/{vaultID}/keys", stub)
		mux.Handle("DELETE /v1/vaults/{vaultID}/keys/{deviceID}", stub)
	}

	// Billing routes (hosted checkout, provider webhooks, subscription status).
	// Dev-gated exactly like everything else stateful AND additionally opt-in via
	// their own configuration: with either off, all three return the deliberate
	// 501 rather than 404 or any partial behaviour. Bodies are capped
	// (oversized -> 413) before any handler runs.
	if h.billingEnabled() {
		mux.Handle("POST /v1/billing/checkout",
			limitBody(maxCheckoutBodyBytes, http.HandlerFunc(h.billingCheckout)))
		// The webhook is authenticated by the PROVIDER's signature over the raw
		// body, not by the device contract — see billing.go for why that is the
		// only endpoint outside the device model.
		mux.Handle("POST /v1/billing/webhook/{provider}",
			limitBody(maxWebhookBodyBytes, http.HandlerFunc(h.billingWebhook)))
		mux.Handle("GET /v1/billing/subscription", http.HandlerFunc(h.billingSubscription))
	} else {
		stub := http.HandlerFunc(h.billingNotImplemented)
		mux.Handle("POST /v1/billing/checkout", limitBody(maxCheckoutBodyBytes, stub))
		mux.Handle("POST /v1/billing/webhook/{provider}", limitBody(maxWebhookBodyBytes, stub))
		mux.Handle("GET /v1/billing/subscription", stub)
	}

	// Outermost first: count every response (even a recoverer-written 500),
	// recover panics, assign a request ID, then access-log.
	return chain(mux,
		countRequests(h.metrics),
		recoverer(cfg.Logger),
		requestID,
		accessLog(cfg.Logger),
	)
}
