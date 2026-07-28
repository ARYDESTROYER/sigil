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
	"time"

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
	// ---- Abuse bounds (Phase 53). ALL OPT-IN; every one defaults OFF. ----
	//
	// Each pair configures one hand-written token bucket (the same mechanism
	// OpLogRateLimit uses; no dependency was added). A rate of 0 — the default —
	// installs NO limiter at all, so an un-opted-in server behaves exactly as it
	// did before. A burst < 1 is clamped up to 1 by the limiter so single
	// requests always pass.

	// EnrollRateLimit caps POST /v1/devices/enroll per SOURCE ADDRESS
	// (requests/second). Enrollment is the one UNAUTHENTICATED write path in
	// this server, so the limiter wraps the handler and rejects before the body
	// is read and before the database is touched. See clientRateKey for why the
	// key is the socket peer and never a forwarded-for header.
	EnrollRateLimit float64
	// EnrollRateBurst is that bucket's capacity.
	EnrollRateBurst int

	// InviteRateLimit caps POST /v1/account/invites per ACCOUNT
	// (requests/second) — not per device. Membership is flat and the open-invite
	// cap it complements is per-account, so keying on the device would let an
	// account with N devices mint at N times the intended rate.
	InviteRateLimit float64
	// InviteRateBurst is that bucket's capacity.
	InviteRateBurst int

	// ⛔ There is NO webhook rate limit, deliberately. One existed in Phase 53 and
	// was removed after it demonstrably destroyed payment events: forged traffic
	// spends the same tokens as authentic provider deliveries, and the provider's
	// retry budget is finite. See billingWebhook.

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
	// ---- Account model (Phase 52). Rides Devices; no separate flag. ----
	//
	// There is deliberately NO SIGILD_ACCOUNTS switch: a binary that could run
	// either ownership model would have two ownership truths at once. Accounts
	// are active exactly when the v3 device model is (which already requires the
	// dev-ops gate).

	// AccountMaxDevices caps how many devices one account may hold. 0 => the
	// package default (defaultAccountMaxDevices). It is ANTI-FREELOADING, not
	// anti-fraud: ten devices in one account is indistinguishable from household
	// sharing versus a small business, and there is no per-seat model.
	AccountMaxDevices int
	// AccountMaxInvites caps how many OPEN (unused, unexpired, unrevoked)
	// invites one account may hold. 0 => the package default. It bounds stored
	// STATE, not request volume — there is no rate limit on invite minting.
	AccountMaxInvites int
	// AccountInviteTTL is how long a freshly minted invite stays redeemable.
	// 0 => the package default. A client may request a SHORTER life, never a
	// longer one.
	AccountInviteTTL time.Duration

	// ---- Entitlement enforcement (Phase 55). OPT-IN; defaults OFF. ----
	//
	// With EntitlementEnforce false (the default) NOTHING changes: no handler
	// reads the subscription store, no header is set, no audit line is written
	// and no metric moves. That is the ADR 0040 limitation-8 behaviour —
	// entitlement REPORTED, never enforced — preserved byte for byte.

	// EntitlementEnforce turns on payment enforcement for the three WRITE
	// surfaces (op-log append, key-envelope deposit, vault grant). It is
	// meaningful only alongside the device model AND billing: without an account
	// there is no subject to bill, and without a subscription store there is
	// nothing to read. NewRouter gates on all three, and cmd/server refuses to
	// boot if this is set without them.
	//
	// ⭐ IT CAN NEVER REFUSE A READ. requireEntitlement is called from write
	// handlers only; the read path holds no entitlement code at all. See
	// entitlement.go.
	EntitlementEnforce bool
	// EntitlementGrace is how long after entitlement lapses writes keep working
	// (warned, not refused). 0 => DefaultEntitlementGrace. It stacks ON TOP of
	// billing's past_due-is-entitled rule, so a declined card costs a customer
	// nothing until the provider's retries AND this window have both run out.
	EntitlementGrace time.Duration

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
	// Abuse bounds (Phase 53). Each limiter exists ONLY when a positive rate is
	// configured; nil means "not configured" and allowAbuse short-circuits, so
	// the default path does no work. The enroll limiter is a route wrapper (it
	// charges the bucket from the handler's OUTCOME, so a successful enrolment is
	// never refused); the invite limiter lives at its handler's choke point
	// because its key is not known until the caller is authenticated.
	var enrollLimiter *rateLimiter
	if cfg.EnrollRateLimit > 0 {
		enrollLimiter = newRateLimiterWithMax(cfg.EnrollRateLimit, cfg.EnrollRateBurst, abuseLimiterMaxKeys)
	}
	if cfg.InviteRateLimit > 0 {
		h.inviteLimiter = newRateLimiterWithMax(cfg.InviteRateLimit, cfg.InviteRateBurst, abuseLimiterMaxKeys)
	}

	// Entitlement enforcement (Phase 55). Active ONLY when it was explicitly
	// switched on AND the device model is live (there is an account to bill) AND
	// billing is configured (there is a subscription store to read). Any one of
	// the three missing leaves the zero policy, and requireEntitlement returns on
	// its first line — so an un-opted-in or half-configured server does no
	// entitlement work whatsoever.
	if cfg.EntitlementEnforce && deviceAuth && h.billingEnabled() {
		grace := cfg.EntitlementGrace
		if grace <= 0 {
			grace = DefaultEntitlementGrace
		}
		h.entitlement = entitlementPolicy{Active: true, Grace: grace}
		h.metrics.entitlementEnforcing = 1
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
		// Enrollment is the one UNAUTHENTICATED write path here, so the abuse
		// limiter wraps it OUTSIDE the handler — but it charges the bucket from
		// the handler's OUTCOME, so a SUCCESSFUL enrolment can never be refused
		// (see rateLimitEnroll for the denial this shape exists to prevent).
		// Unconfigured (the default) => no wrapper at all.
		var enrollHandler http.Handler = http.HandlerFunc(h.devicesEnroll)
		if enrollLimiter != nil {
			enrollHandler = rateLimitEnroll(enrollLimiter, h, enrollHandler)
		}
		mux.Handle("POST /v1/devices/enroll", enrollHandler)
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
		// Recovery support (Phase 54): the per-DEVICE envelope index, so a
		// client restored from a printed recovery kit — which knows no vault
		// ids at all — can discover what it is able to decrypt. SELF-ONLY and
		// METADATA-ONLY, over the SAME authenticateDevice / authorizeVault
		// choke points; no new auth path, and no migration (it reads the
		// by-recipient index 0004 already created).
		mux.Handle("GET /v1/devices/{deviceID}/keys", http.HandlerFunc(h.deviceKeyEnvelopeIndex))
		// Account model (Phase 52): membership and single-use invites. Same dev
		// gate and the same authenticateDevice choke point — no new auth path.
		// NOTHING here names an account: every one of them derives it from the
		// verified signer's device row.
		mux.Handle("GET /v1/account", http.HandlerFunc(h.accountGet))
		mux.Handle("POST /v1/account/invites",
			limitBody(maxAccountBodyBytes, http.HandlerFunc(h.accountInviteCreate)))
		mux.Handle("GET /v1/account/invites", http.HandlerFunc(h.accountInviteList))
		mux.Handle("POST /v1/account/invites/{inviteID}/revoke",
			limitBody(maxAccountBodyBytes, http.HandlerFunc(h.accountInviteRevoke)))
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
		mux.Handle("GET /v1/devices/{deviceID}/keys", stub)
		// The account routes get their OWN 501 stub (not the device one), so its
		// detail string names this surface and the device stub's text — which
		// existing tests assert — is untouched.
		acct := http.HandlerFunc(h.accountNotImplemented)
		mux.Handle("GET /v1/account", acct)
		mux.Handle("POST /v1/account/invites", limitBody(maxAccountBodyBytes, acct))
		mux.Handle("GET /v1/account/invites", acct)
		mux.Handle("POST /v1/account/invites/{inviteID}/revoke",
			limitBody(maxAccountBodyBytes, acct))
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
