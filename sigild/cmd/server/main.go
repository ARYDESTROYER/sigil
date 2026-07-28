// Command sigild is the Sigil sync server.
//
// STATUS: pre-audit skeleton. It serves liveness/readiness probes and a
// not-yet-implemented vault-ops endpoint. It performs NO cryptography, stores
// NO vault data, and understands NO vault format — see docs/sprint-72h.md and
// section 14 of the product brief ("what sigild does not do").
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ARYDESTROYER/sigil/sigild/internal/api"
	"github.com/ARYDESTROYER/sigil/sigild/internal/billing"
	"github.com/ARYDESTROYER/sigil/sigild/internal/buildinfo"
	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

func main() {
	// Subcommand dispatch BEFORE any server setup. sigild takes no flags (all
	// config is env), so any first argument is a subcommand. `sigild migrate`
	// and `sigild migrate status` operate on the Postgres op-log backend; no
	// argument runs the server exactly as before.
	if len(os.Args) > 1 {
		if err := runSubcommand(context.Background(), os.Args[1:], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "sigild:", err)
			os.Exit(1)
		}
		return
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	// Fail-fast config validation: reject malformed env BEFORE binding the
	// listener, so a misconfiguration is a clear startup error rather than a
	// surprise at request time. Each parser is extracted (below) so it is
	// unit-testable without invoking os.Exit.
	addr := getenv("SIGILD_ADDR", ":8080")
	if err := validateListenAddr(addr); err != nil {
		logger.Error("invalid SIGILD_ADDR", "value", addr, "err", err)
		os.Exit(1)
	}
	rate, err := parseRateLimit(os.Getenv("SIGILD_OPLOG_RATE_LIMIT"))
	if err != nil {
		logger.Error("invalid SIGILD_OPLOG_RATE_LIMIT", "err", err)
		os.Exit(1)
	}
	burst, err := parseRateBurst(os.Getenv("SIGILD_OPLOG_RATE_BURST"))
	if err != nil {
		logger.Error("invalid SIGILD_OPLOG_RATE_BURST", "err", err)
		os.Exit(1)
	}
	// When rate limiting is on, resolve the effective burst (defaulting to
	// ceil(rate) when unset). When rate is 0 (disabled) burst is irrelevant.
	if rate > 0 {
		burst = effectiveBurst(rate, burst)
	}

	// Browser origin allowlist, validated BEFORE binding too. OPT-IN and OFF by
	// default: unset installs no CORS middleware and no response carries an
	// Access-Control-* header. A malformed entry — or a wildcard — is a startup
	// failure rather than a permissive fallback. See internal/api/cors.go.
	corsOrigins, err := validateCORSOrigins(os.Getenv("SIGILD_CORS_ORIGINS"))
	if err != nil {
		logger.Error("invalid SIGILD_CORS_ORIGINS", "err", err)
		os.Exit(1)
	}

	devOps := truthy(os.Getenv("SIGILD_ENABLE_DEV_OPS"))

	// Multi-device auth model config, validated BEFORE binding. All of it is
	// OPT-IN: with SIGILD_DEVICE_AUTH unset the model is OFF and the server
	// behaves EXACTLY as it did before (legacy single-key contract v2 when
	// SIGILD_OPLOG_PUBKEY is set, otherwise unauthenticated).
	deviceAuth, err := validateDeviceAuthConfig(deviceAuthEnv{
		DeviceAuth:  os.Getenv("SIGILD_DEVICE_AUTH"),
		DevOps:      os.Getenv("SIGILD_ENABLE_DEV_OPS"),
		OpLogPubKey: os.Getenv("SIGILD_OPLOG_PUBKEY"),
		Tokens:      os.Getenv("SIGILD_ENROLL_TOKENS"),
		TokenTTL:    os.Getenv("SIGILD_ENROLL_TOKEN_TTL"),
		AdminToken:  os.Getenv("SIGILD_ADMIN_TOKEN"),
	})
	if err != nil {
		logger.Error("invalid device-auth configuration", "err", err)
		os.Exit(1)
	}

	// Account-model config, validated BEFORE binding too. There is deliberately
	// NO on/off switch: accounts ride SIGILD_DEVICE_AUTH (which already requires
	// the dev-ops gate), because a binary that could run either ownership model
	// would have two ownership truths at once. Setting any of these WITHOUT
	// device auth is a BOOT ERROR, consistent with the billing-without-device-auth
	// refusal — a knob that silently does nothing is worse than a refusal.
	accountCfg, err := validateAccountConfig(accountEnv{
		DeviceAuth: os.Getenv("SIGILD_DEVICE_AUTH"),
		MaxDevices: os.Getenv("SIGILD_ACCOUNT_MAX_DEVICES"),
		MaxInvites: os.Getenv("SIGILD_ACCOUNT_MAX_INVITES"),
		InviteTTL:  os.Getenv("SIGILD_ACCOUNT_INVITE_TTL"),
	})
	if err != nil {
		logger.Error("invalid account configuration", "err", err)
		os.Exit(1)
	}

	// Abuse bounds (Phase 53), validated BEFORE binding too. All six values are
	// OPT-IN and default OFF: unset installs no limiter, so an un-opted-in server
	// behaves exactly as it did before. A malformed value is a startup failure,
	// never a silent fallback to "unlimited" — a rate limiter that quietly
	// disabled itself on a typo would be worse than none, because an operator
	// would believe the route was protected.
	abuseCfg, err := validateAbuseConfig(abuseEnv{
		EnrollRate:  os.Getenv("SIGILD_ENROLL_RATE_LIMIT"),
		EnrollBurst: os.Getenv("SIGILD_ENROLL_RATE_BURST"),
		InviteRate:  os.Getenv("SIGILD_INVITE_RATE_LIMIT"),
		InviteBurst: os.Getenv("SIGILD_INVITE_RATE_BURST"),
	})
	if err != nil {
		logger.Error("invalid abuse rate-limit configuration", "err", err)
		os.Exit(1)
	}

	// Entitlement enforcement (Phase 55), validated BEFORE binding too. OPT-IN
	// and OFF BY DEFAULT: with SIGILD_ENTITLEMENT_ENFORCE unset, nothing is
	// enforced and the server behaves exactly as it did before.
	//
	// Enabling it WITHOUT dev-ops, device auth and billing is a BOOT ERROR rather
	// than a silently inert knob — this one decides whether a paying customer's
	// writes are served, and an operator who believes enforcement is on when it
	// is not is exactly the person who will discover the truth from a revenue
	// report. It performs no network I/O and reads no store.
	entitlementCfg, err := validateEntitlementConfig(entitlementEnv{
		Enforce:    os.Getenv("SIGILD_ENTITLEMENT_ENFORCE"),
		Grace:      os.Getenv("SIGILD_ENTITLEMENT_GRACE"),
		DevOps:     os.Getenv("SIGILD_ENABLE_DEV_OPS"),
		DeviceAuth: os.Getenv("SIGILD_DEVICE_AUTH"),
		Billing:    os.Getenv("SIGILD_BILLING_PROVIDERS"),
	})
	if err != nil {
		logger.Error("invalid entitlement configuration", "err", err)
		os.Exit(1)
	}

	// Billing config, validated BEFORE binding too. Entirely OPT-IN: with
	// SIGILD_BILLING_PROVIDERS unset billing is OFF and the /v1/billing routes
	// stay at their 501 stub. Enabling a provider without its credentials is a
	// BOOT ERROR, never a runtime surprise — a server that accepted webhooks it
	// could not authenticate would silently reject real payment events.
	// validateBillingConfig performs NO network I/O, so this cannot contact a
	// payment provider at startup.
	billingCfg, err := validateBillingConfig(billingEnv{
		Providers:             os.Getenv("SIGILD_BILLING_PROVIDERS"),
		DefaultProvider:       os.Getenv("SIGILD_BILLING_DEFAULT_PROVIDER"),
		DevOps:                os.Getenv("SIGILD_ENABLE_DEV_OPS"),
		DeviceAuth:            os.Getenv("SIGILD_DEVICE_AUTH"),
		SuccessURL:            os.Getenv("SIGILD_BILLING_SUCCESS_URL"),
		CancelURL:             os.Getenv("SIGILD_BILLING_CANCEL_URL"),
		StripeSecretKey:       os.Getenv("SIGILD_STRIPE_SECRET_KEY"),
		StripeWebhookSecret:   os.Getenv("SIGILD_STRIPE_WEBHOOK_SECRET"),
		StripePriceID:         os.Getenv("SIGILD_STRIPE_PRICE_ID"),
		StripeBaseURL:         os.Getenv("SIGILD_STRIPE_API_BASE_URL"),
		RazorpayKeyID:         os.Getenv("SIGILD_RAZORPAY_KEY_ID"),
		RazorpayKeySecret:     os.Getenv("SIGILD_RAZORPAY_KEY_SECRET"),
		RazorpayWebhookSecret: os.Getenv("SIGILD_RAZORPAY_WEBHOOK_SECRET"),
		RazorpayAmountMinor:   os.Getenv("SIGILD_RAZORPAY_AMOUNT_MINOR"),
		RazorpayCurrency:      os.Getenv("SIGILD_RAZORPAY_CURRENCY"),
		RazorpayDescription:   os.Getenv("SIGILD_RAZORPAY_DESCRIPTION"),
		RazorpayBaseURL:       os.Getenv("SIGILD_RAZORPAY_API_BASE_URL"),
		JuspayMerchantID:      os.Getenv("SIGILD_JUSPAY_MERCHANT_ID"),
		JuspayAPIKey:          os.Getenv("SIGILD_JUSPAY_API_KEY"),
		JuspayClientID:        os.Getenv("SIGILD_JUSPAY_CLIENT_ID"),
		JuspayWebhookScheme:   os.Getenv("SIGILD_JUSPAY_WEBHOOK_SCHEME"),
		JuspayWebhookUsername: os.Getenv("SIGILD_JUSPAY_WEBHOOK_USERNAME"),
		JuspayWebhookPassword: os.Getenv("SIGILD_JUSPAY_WEBHOOK_PASSWORD"),
		JuspayWebhookSecret:   os.Getenv("SIGILD_JUSPAY_WEBHOOK_SECRET"),
		JuspayWebhookSigHdr:   os.Getenv("SIGILD_JUSPAY_WEBHOOK_SIG_HEADER"),
		JuspayAmountMinor:     os.Getenv("SIGILD_JUSPAY_AMOUNT_MINOR"),
		JuspayCurrency:        os.Getenv("SIGILD_JUSPAY_CURRENCY"),
		JuspayBaseURL:         os.Getenv("SIGILD_JUSPAY_API_BASE_URL"),
	})
	if err != nil {
		logger.Error("invalid billing configuration", "err", err)
		os.Exit(1)
	}

	cfg := api.Config{
		Version: buildinfo.Version,
		// host:port reachability targets; empty => reported "unconfigured".
		// The production build will replace plain dials with real pgx/redis pings.
		PostgresAddr:   os.Getenv("SIGILD_POSTGRES_ADDR"),
		RedisAddr:      os.Getenv("SIGILD_REDIS_ADDR"),
		Logger:         logger,
		DevOpsEnabled:  devOps,
		OpLogRateLimit: rate,
		OpLogRateBurst: burst,

		EnrollRateLimit: abuseCfg.EnrollRate,
		EnrollRateBurst: abuseCfg.EnrollBurst,
		InviteRateLimit: abuseCfg.InviteRate,
		InviteRateBurst: abuseCfg.InviteBurst,

		CORSOrigins: corsOrigins,
	}
	if len(corsOrigins) > 0 {
		logger.Warn("CORS ENABLED for an explicit browser origin allowlist — this is for the LOCALHOST DEV topology; in production serve the app and the API from the SAME origin behind the reverse proxy. No credentials mode is enabled and no wildcard is possible; every request is still authenticated by its own per-request signature",
			"origins", strings.Join(corsOrigins, ","))
	}
	if devOps && rate > 0 {
		logger.Warn("DEV op-log per-vault RATE LIMIT enabled — dev-only",
			"rate_per_sec", rate, "burst", burst)
	}
	logAbuseBounds(logger, abuseCfg, devOps)
	if devOps {
		// Backend selection for the DEV op-log, in PRECEDENCE order:
		//   1. SIGILD_OPLOG_POSTGRES (a DSN) => durable, CONCURRENT Postgres backend
		//   2. SIGILD_OPLOG_DIR            => durable, single-process file backend
		//   3. neither                     => non-durable in-memory backend
		// All three store OPAQUE client-encrypted blobs, do NO crypto, and are
		// still UNAUTHENTICATED unless SIGILD_OPLOG_PUBKEY is set below. None is
		// the production store (production = Postgres/S3/Redis with a real auth
		// model, enrollment, CRDT and backups — none of which this has).
		// pgPool is non-nil only when the Postgres op-log backend is selected. The
		// device registry SHARES that pool (no second pool, no new dependency).
		var pgPool *pgxpool.Pool
		switch {
		case os.Getenv("SIGILD_OPLOG_POSTGRES") != "":
			dsn := os.Getenv("SIGILD_OPLOG_POSTGRES")
			// Bound construction (pool open + ping + schema) so a bad/unreachable
			// DSN fails fast rather than hanging startup.
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			pgLog, err := store.NewPostgresVaultLog(ctx, dsn)
			cancel()
			if err != nil {
				// An explicitly-configured DSN that cannot connect / ensure schema
				// is a fatal misconfiguration, not a fallback to another backend.
				logger.Error("failed to open Postgres dev op-log", "err", err)
				os.Exit(1)
			}
			cfg.VaultLog = pgLog
			pgPool = pgLog.Pool()
			// Surface the applied migration version via the sigild_schema_version
			// metric (0 for the mem/file backends, which have no migrations).
			svCtx, svCancel := context.WithTimeout(context.Background(), 10*time.Second)
			sv, err := pgLog.SchemaVersion(svCtx)
			svCancel()
			if err != nil {
				logger.Error("failed to read op-log schema version", "err", err)
				os.Exit(1)
			}
			cfg.SchemaVersion = sv
			logger.Warn("DEV op-log enabled: DURABLE POSTGRES backend active — UNAUTHENTICATED, dev-only, NOT a finished production store (no auth model / enrollment / CRDT / backups) — do NOT expose publicly", "schema_version", sv)
		case os.Getenv("SIGILD_OPLOG_DIR") != "":
			// Optional durable LOCAL-DEV backend: persist the dev op-log to
			// per-vault append-only files so it survives a restart. Still
			// UNAUTHENTICATED / dev-only and NOT the production store.
			dir := os.Getenv("SIGILD_OPLOG_DIR")
			fileLog, err := store.NewFileVaultLog(dir)
			if err != nil {
				logger.Error("failed to open file-backed dev op-log", "dir", dir, "err", err)
				os.Exit(1)
			}
			cfg.VaultLog = fileLog
			logger.Warn("DEV op-log enabled: FILE-BACKED durable backend active — UNAUTHENTICATED, dev-only, NOT the production store — do NOT expose publicly", "dir", dir)
		default:
			logger.Warn("DEV op-log enabled: UNAUTHENTICATED, in-memory, non-durable — do NOT expose publicly")
		}

		// Optional op-log request-auth: if SIGILD_OPLOG_PUBKEY is set, it MUST be
		// the standard-base64 of a 32-byte Ed25519 public key. When set, every
		// GET/POST vault-ops request must carry a valid X-Sigil-Timestamp +
		// X-Sigil-Nonce + X-Sigil-Signature per the op-log auth contract v2 (see
		// internal/api/opsauth.go). Unset => no auth (unchanged). HONEST SCOPE: a
		// SINGLE configured DEV device key; the per-request nonce + PER-PROCESS
		// in-memory replay cache stop replays within the timestamp window against
		// this instance (a multi-instance deploy needs a shared store, e.g.
		// Redis); full device enrollment is FUTURE. Only meaningful while dev-ops
		// is on.
		if raw := os.Getenv("SIGILD_OPLOG_PUBKEY"); raw != "" {
			pub, err := parseOpLogPubKey(raw)
			if err != nil {
				logger.Error("invalid SIGILD_OPLOG_PUBKEY", "err", err)
				os.Exit(1)
			}
			cfg.OpLogPubKey = pub
			logger.Warn("DEV op-log request AUTH ENABLED: Ed25519, SINGLE configured DEV device key, per-request nonce + per-process in-memory replay cache (not replay-proof across instances) — dev-only, do NOT expose publicly")
		}

		// Optional MULTI-DEVICE auth model (contract v3). When SIGILD_DEVICE_AUTH
		// is on, every ops request must name an ENROLLED device via X-Sigil-Device
		// and hold a per-vault grant; the legacy single key is refused alongside it
		// (validateDeviceAuthConfig already rejected that combination). The registry
		// is durable when the Postgres op-log backend is active (sharing its pool,
		// tables from migration 0002), otherwise in-memory and non-durable — which
		// means a spent enrollment token becomes usable again after a restart.
		if deviceAuth.Enabled {
			if pgPool != nil {
				cfg.Devices = store.NewPostgresDeviceStore(pgPool)
				warnUnadoptedRows(logger, pgPool)
			} else {
				cfg.Devices = store.NewMemDeviceStore()
				logger.Warn("DEVICE AUTH: registry is IN-MEMORY and NON-DURABLE — devices, grants, ACCOUNTS, account MEMBERSHIPS, account INVITES and VAULT-OWNER rows are all lost on restart (which also means a spent enrollment token or a spent invite becomes reusable); use the Postgres op-log backend for durability")
			}
			cfg.AdminToken = deviceAuth.AdminToken
			cfg.AccountMaxDevices = accountCfg.MaxDevices
			cfg.AccountMaxInvites = accountCfg.MaxInvites
			cfg.AccountInviteTTL = accountCfg.InviteTTL

			// Register the operator-provisioned enrollment tokens by DIGEST. This
			// is idempotent, so a restart never resurrects a token that has already
			// been spent (the durable backend keeps the used marker).
			issuedAt := time.Now().UTC()
			var expiresAt time.Time
			if deviceAuth.TokenTTL > 0 {
				expiresAt = issuedAt.Add(deviceAuth.TokenTTL)
			}
			regCtx, regCancel := context.WithTimeout(context.Background(), 15*time.Second)
			for _, token := range deviceAuth.Tokens {
				hash := api.EnrollTokenHash(token)
				cfg.EnrollTokenHashes = append(cfg.EnrollTokenHashes, hash)
				if err := cfg.Devices.RegisterEnrollmentToken(regCtx, hash, issuedAt, expiresAt); err != nil {
					regCancel()
					logger.Error("failed to register enrollment token", "err", err)
					os.Exit(1)
				}
			}
			regCancel()

			logger.Warn("DEV op-log MULTI-DEVICE AUTH ENABLED (contract v3): per-device Ed25519 keys, per-vault authorization, revocation — dev-only, UNAUDITED, do NOT expose publicly",
				"enrollment_tokens", len(cfg.EnrollTokenHashes),
				"token_ttl", deviceAuth.TokenTTL.String(),
				"admin_token_configured", cfg.AdminToken != "",
				"registry", map[bool]string{true: "postgres", false: "memory"}[pgPool != nil])

			// Accounts are ON whenever device auth is. Named at boot because it
			// changes who owns a vault and who is entitled.
			logger.Warn("ACCOUNT MODEL ACTIVE: entitlement and vault ownership key off the ACCOUNT of the signing device, not the device. Membership is FLAT (any member may invite, revoke any sibling, run checkout and administer every account-owned vault) and there is NO RECOVERY UNLESS A RECOVERY KIT WAS GENERATED IN ADVANCE — lose or revoke every device in an account that never printed a kit and it is permanently unreachable. A kit cannot be created after the fact. Dev-only, UNAUDITED",
				"max_devices_per_account", cfg.AccountMaxDevices,
				"max_open_invites_per_account", cfg.AccountMaxInvites,
				"invite_ttl", cfg.AccountInviteTTL.String())
		}

		// Billing. validateBillingConfig has already required dev-ops AND device
		// auth, so reaching here means both are on. The subscription store is
		// durable when the Postgres op-log backend is active (sharing its pool,
		// tables from migration 0003), otherwise in-memory and non-durable —
		// which for the processed-event ledger means a webhook redelivered across
		// a restart would be applied twice.
		if billingCfg.Enabled {
			if pgPool != nil {
				cfg.Billing.Subscriptions = store.NewPostgresSubscriptionStore(pgPool)
			} else {
				cfg.Billing.Subscriptions = store.NewMemSubscriptionStore()
				logger.Warn("BILLING: subscription store is IN-MEMORY and NON-DURABLE — subscriptions and the processed-webhook ledger are lost on restart, so a redelivered webhook could be applied twice; use the Postgres op-log backend for durability")
			}
			cfg.Billing.Providers = billingCfg.Providers
			cfg.Billing.DefaultProvider = billingCfg.DefaultProvider
			cfg.Billing.SuccessURL = billingCfg.SuccessURL
			cfg.Billing.CancelURL = billingCfg.CancelURL

			// Entitlement enforcement rides billing + device auth (both are on
			// here, and validateEntitlementConfig already required them). The
			// router gates on all three defensively as well.
			cfg.EntitlementEnforce = entitlementCfg.Enforce
			cfg.EntitlementGrace = entitlementCfg.Grace
			logEntitlementEnforcement(logger, entitlementCfg)

			// Logs WHICH providers are enabled and which Juspay webhook scheme is
			// active. NEVER a key, secret, username or password.
			logger.Warn("BILLING ENABLED — hosted checkout only (no card data ever reaches this server); UNAUDITED, dev-gated, do NOT take real payments before verifying each provider's webhook scheme against its live dashboard",
				"providers", strings.Join(billingCfg.ProviderNames(), ","),
				"default_provider", billingCfg.DefaultProvider,
				"store", map[bool]string{true: "postgres", false: "memory"}[pgPool != nil])
			if billingCfg.JuspayScheme != "" {
				logger.Warn("BILLING: the Juspay webhook scheme is UNVERIFIED-AGAINST-LIVE-DASHBOARD — confirm it before accepting real payments",
					"juspay_webhook_scheme", billingCfg.JuspayScheme)
			}
			if billingCfg.JuspayScheme == billing.JuspaySchemeBasic {
				// It is an explicit opt-in, so this is not a boot failure — but
				// the limitation is named every single time the server starts.
				logger.Warn("BILLING: the Juspay webhook scheme is BASIC, which authenticates the CONNECTION and NOT the PAYLOAD — anyone holding the credential can post any body, and a modified body cannot be detected; prefer SIGILD_JUSPAY_WEBHOOK_SCHEME=hmac (the default), and if basic is unavoidable serve this endpoint over TLS only and treat the credential as a bearer secret",
					"juspay_webhook_scheme", billingCfg.JuspayScheme)
			}
		}
	} else if billingCfg.Enabled {
		// Unreachable in practice (validateBillingConfig requires dev-ops), but
		// stated explicitly: billing never runs outside the dev gate.
		logger.Error("billing was configured without the dev-ops gate")
		os.Exit(1)
	}

	// Server-wide timeouts bound how long a single connection may tie up
	// resources, so a slow or stuck client cannot hold a goroutine/socket open
	// indefinitely. Op bodies are tiny (a single op is capped at 64 KiB, see
	// api.maxOpsBodyBytes) and every handler is fast, so a 15 s read/write budget
	// is generous; IdleTimeout reaps idle keep-alive connections after 60 s.
	// ReadHeaderTimeout stays as a tight guard against slow-header (Slowloris)
	// attacks.
	srv := &http.Server{
		Addr:              addr,
		Handler:           api.NewRouter(cfg),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		logger.Info("sigild listening", "addr", addr, "version", buildinfo.Version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("listen failed", "err", err)
			os.Exit(1)
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
}

// warnUnadoptedRows warns at boot when the database holds device rows with no
// account, or vaults whose only ownership record is a legacy is_owner grant.
//
// THIS IS THE ONLY SIGNAL AN OPERATOR GETS. Both states are produced by a
// PRE-0005 BINARY writing to an already-migrated database (a rolling deploy, or
// a rollback window): 0005's account_id column is deliberately nullable so an
// old binary can still enroll, and 0005's backfill is recorded in
// schema_migrations so `sigild migrate` reports "already up to date" forever
// after. Requests from those devices are refused with the same coarse 403 every
// other refusal uses — by design, so there is no oracle — which means the
// refusal itself tells an operator nothing.
//
// It NEVER blocks the boot: a read failure, or a schema that predates the
// account model, is logged at debug and ignored.
func warnUnadoptedRows(logger *slog.Logger, pool *pgxpool.Pool) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	devices, err := store.CountUnadoptedDevices(ctx, pool)
	if err != nil {
		logger.Debug("could not count unadopted devices", "err", err)
		return
	}
	vaults, err := store.CountOrphanVaultOwnerGrants(ctx, pool)
	if err != nil {
		logger.Debug("could not count orphan owner grants", "err", err)
		return
	}
	if devices == 0 && vaults == 0 {
		return
	}
	logger.Warn("ACCOUNT BACKFILL INCOMPLETE: this database holds rows written by a PRE-ACCOUNT-MODEL binary after migration 0005 was applied. Devices with no account are refused on EVERY route (a coarse 403, indistinguishable from any other refusal), and a vault whose only ownership record is a legacy owner grant cannot be claimed. `sigild migrate` will NOT fix this — 0005 is already recorded as applied. Run `sigild migrate adopt` (idempotent) to repair it",
		"devices_without_account", devices,
		"vaults_with_owner_grant_but_no_owner_row", vaults)
}

// usageText documents the (few) sigild invocations. Printed on an unknown
// subcommand.
const usageText = `usage:
  sigild                 run the sync server (config via environment)
  sigild migrate         apply pending op-log database migrations
  sigild migrate status  show migration status (applies nothing)
  sigild migrate adopt   re-run the account backfill: give every device without
                         an account its own singleton account, record ownership
                         for vaults holding a legacy owner grant, and re-key
                         device-subject subscriptions. Idempotent; a no-op when
                         there is nothing to adopt. Needed after a pre-0005
                         binary wrote to an already-migrated database.`

// runSubcommand dispatches a sigild subcommand. args is os.Args[1:]. It writes
// human output to out and returns an error (main maps that to a non-zero exit).
// It never calls os.Exit, so it is unit-testable.
func runSubcommand(ctx context.Context, args []string, out io.Writer) error {
	switch args[0] {
	case "migrate":
		return runMigrate(ctx, args[1:], out)
	default:
		return fmt.Errorf("unknown subcommand %q\n\n%s", args[0], usageText)
	}
}

// migrateMode is what `sigild migrate ...` was asked to do.
type migrateMode int

const (
	// migrateApply applies pending migrations (`sigild migrate`).
	migrateApply migrateMode = iota
	// migrateStatus reports and applies nothing (`sigild migrate status`).
	migrateStatus
	// migrateAdopt re-runs the account backfill (`sigild migrate adopt`).
	migrateAdopt
)

// parseMigrateArgs interprets the arguments after `migrate`. No args => apply
// pending; "status" => report only; "adopt" => re-run the account backfill.
// Anything else is an error. Kept separate so arg parsing is unit-testable
// without a database.
func parseMigrateArgs(args []string) (migrateMode, error) {
	switch {
	case len(args) == 0:
		return migrateApply, nil
	case len(args) == 1 && args[0] == "status":
		return migrateStatus, nil
	case len(args) == 1 && args[0] == "adopt":
		return migrateAdopt, nil
	default:
		return migrateApply, fmt.Errorf("unknown migrate argument %q (want: `sigild migrate`, `sigild migrate status` or `sigild migrate adopt`)",
			strings.Join(args, " "))
	}
}

// runMigrate applies pending op-log migrations (or, with "status", reports
// them). Migrations only apply to the Postgres backend, so SIGILD_OPLOG_POSTGRES
// must be set; otherwise it returns a clear error. Arg parsing and the
// missing-DSN check happen BEFORE any connection, so those paths are unit-
// testable without a database.
func runMigrate(ctx context.Context, args []string, out io.Writer) error {
	mode, err := parseMigrateArgs(args)
	if err != nil {
		return err
	}
	dsn := os.Getenv("SIGILD_OPLOG_POSTGRES")
	if dsn == "" {
		return errors.New("migrations apply only to the Postgres backend: set SIGILD_OPLOG_POSTGRES to the database DSN")
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return fmt.Errorf("open postgres pool: %w", err)
	}
	defer pool.Close()

	switch mode {
	case migrateStatus:
		statuses, err := store.Status(ctx, pool)
		if err != nil {
			return fmt.Errorf("read migration status: %w", err)
		}
		for _, s := range statuses {
			if s.Applied {
				fmt.Fprintf(out, "[applied] %s  (%s)\n", s.Name, s.AppliedAt.UTC().Format(time.RFC3339))
			} else {
				fmt.Fprintf(out, "[pending] %s\n", s.Name)
			}
		}
		return nil

	case migrateAdopt:
		// The account backfill, re-run against whatever state the database is in.
		// This is the ONLY repair for device rows written by a pre-0005 binary
		// after 0005 was applied: schema_migrations already records 0005, so
		// `sigild migrate` will never re-run it. Adoption is deliberately NOT
		// automatic on the authentication path — an unauthenticated request must
		// never be able to mint an account.
		rep, err := store.AdoptOrphanAccounts(ctx, pool)
		if err != nil {
			return fmt.Errorf("adopt orphan accounts: %w", err)
		}
		if rep.Empty() {
			fmt.Fprintln(out, "nothing to adopt: every device has an account and every owner grant has an owner row")
			return nil
		}
		fmt.Fprintf(out, "adopted %d device(s) into %d new account(s)\n",
			rep.DevicesAdopted, rep.AccountsCreated)
		fmt.Fprintf(out, "recorded ownership for %d vault(s) from existing owner grants\n",
			rep.VaultOwnersBackfilled)
		fmt.Fprintf(out, "re-keyed %d subscription(s) from a device subject to its account\n",
			rep.SubscriptionsRekeyed)
		return nil
	}

	applied, err := store.Migrate(ctx, pool)
	if err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	if len(applied) == 0 {
		fmt.Fprintln(out, "op-log database is already up to date; no migrations applied")
		return nil
	}
	for _, m := range applied {
		fmt.Fprintf(out, "applied migration %d %s\n", m.Version, m.Name)
	}
	return nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// truthy reports whether an env value enables a flag: "1", "true", or "TRUE"
// (case-insensitive). Anything else (including empty) is false.
func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true":
		return true
	default:
		return false
	}
}

// validateListenAddr checks SIGILD_ADDR is a bind address net/http can listen on.
// It must be non-empty and resolvable as a TCP address (host:port, where host
// may be empty for all-interfaces, e.g. ":8080"). A bare port with no colon, or
// garbage, is rejected.
func validateListenAddr(s string) error {
	if s == "" {
		return errors.New("must not be empty")
	}
	if _, err := net.ResolveTCPAddr("tcp", s); err != nil {
		return fmt.Errorf("not a valid TCP listen address (want host:port, e.g. \":8080\"): %w", err)
	}
	return nil
}

// parseRateLimit parses SIGILD_OPLOG_RATE_LIMIT (per-vault requests/second). An
// empty value means 0 (rate limiting disabled). A set value must parse as a
// finite, non-negative float; anything else is an error.
func parseRateLimit(s string) (float64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, fmt.Errorf("must be a number: %w", err)
	}
	if math.IsNaN(v) || math.IsInf(v, 0) {
		return 0, fmt.Errorf("must be finite, got %v", s)
	}
	if v < 0 {
		return 0, fmt.Errorf("must be non-negative, got %v", v)
	}
	return v, nil
}

// parseRateBurst parses SIGILD_OPLOG_RATE_BURST (token-bucket capacity). An empty
// value means 0 (caller derives a default from the rate). A set value must parse
// as a non-negative int.
func parseRateBurst(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("must be an integer: %w", err)
	}
	if v < 0 {
		return 0, fmt.Errorf("must be non-negative, got %d", v)
	}
	return v, nil
}

// effectiveBurst resolves the burst to use for a positive rate: an explicit
// positive burst wins; otherwise default to ceil(rate), floored at 1 so at least
// a single request always passes.
func effectiveBurst(rate float64, burst int) int {
	if burst > 0 {
		return burst
	}
	b := int(math.Ceil(rate))
	if b < 1 {
		b = 1
	}
	return b
}

// ---- Multi-device auth model configuration (Phase 41) ----
//
// Environment, ALL optional; unset => the model is OFF and the server behaves
// exactly as it did before:
//
//	SIGILD_DEVICE_AUTH        "1"/"true" turns on the v3 multi-device model.
//	                          Requires SIGILD_ENABLE_DEV_OPS (the whole op-log is
//	                          dev-gated) and is MUTUALLY EXCLUSIVE with
//	                          SIGILD_OPLOG_PUBKEY (one auth contract at a time).
//	SIGILD_ENROLL_TOKENS      comma-separated operator-provisioned enrollment
//	                          tokens (bootstrap secrets). REQUIRED when device
//	                          auth is on — without one, no device can enroll.
//	                          Each must be >= minEnrollTokenLen chars. Only their
//	                          SHA-256 digests are ever stored or compared.
//	SIGILD_ENROLL_TOKEN_TTL   optional Go duration (e.g. "24h"). When set, a
//	                          token expires TTL after it was first registered
//	                          (registration is idempotent, so restarts do not
//	                          extend the clock). Unset => tokens do not expire,
//	                          but remain SINGLE-USE.
//	SIGILD_ADMIN_TOKEN        optional operator token for the operator-only device
//	                          routes (list all devices, revoke any device). Unset
//	                          => those paths are permanently unauthorized; there
//	                          is no implicit open-admin mode.

// minEnrollTokenLen is the minimum length of an operator-provisioned enrollment
// or admin token. These are bearer secrets, so a short one is a configuration
// error the server refuses to start with rather than a weak-but-working setup.
const minEnrollTokenLen = 16

// deviceAuthEnv is the raw environment for the device-auth model, injected so
// validation is unit-testable without touching the process environment.
type deviceAuthEnv struct {
	DeviceAuth  string
	DevOps      string
	OpLogPubKey string
	Tokens      string
	TokenTTL    string
	AdminToken  string
}

// deviceAuthConfig is the validated result.
type deviceAuthConfig struct {
	Enabled    bool
	Tokens     []string // PLAINTEXT, used only to compute digests at boot
	TokenTTL   time.Duration
	AdminToken string
}

// validateDeviceAuthConfig parses + validates the device-auth environment and
// fails fast on any misconfiguration, BEFORE the listener binds. It never calls
// os.Exit, so it is unit-testable.
//
// When SIGILD_DEVICE_AUTH is not truthy it returns a disabled config and ignores
// everything else, so a stale/pre-staged SIGILD_ENROLL_TOKENS cannot silently
// switch the auth model on.
func validateDeviceAuthConfig(env deviceAuthEnv) (deviceAuthConfig, error) {
	if !truthy(env.DeviceAuth) {
		return deviceAuthConfig{}, nil
	}
	if !truthy(env.DevOps) {
		return deviceAuthConfig{}, errors.New("SIGILD_DEVICE_AUTH requires SIGILD_ENABLE_DEV_OPS: the op-log and its auth model are dev-gated")
	}
	if strings.TrimSpace(env.OpLogPubKey) != "" {
		return deviceAuthConfig{}, errors.New("SIGILD_DEVICE_AUTH and SIGILD_OPLOG_PUBKEY are mutually exclusive: the multi-device contract (v3) replaces the single-static-key contract (v2); unset SIGILD_OPLOG_PUBKEY to migrate")
	}

	tokens, err := parseEnrollTokens(env.Tokens)
	if err != nil {
		return deviceAuthConfig{}, fmt.Errorf("SIGILD_ENROLL_TOKENS: %w", err)
	}
	if len(tokens) == 0 {
		return deviceAuthConfig{}, errors.New("SIGILD_DEVICE_AUTH requires SIGILD_ENROLL_TOKENS: without an enrollment token no device can ever enroll")
	}

	ttl, err := parseTokenTTL(env.TokenTTL)
	if err != nil {
		return deviceAuthConfig{}, fmt.Errorf("SIGILD_ENROLL_TOKEN_TTL: %w", err)
	}

	admin := strings.TrimSpace(env.AdminToken)
	if admin != "" && len(admin) < minEnrollTokenLen {
		return deviceAuthConfig{}, fmt.Errorf("SIGILD_ADMIN_TOKEN: must be at least %d characters", minEnrollTokenLen)
	}

	return deviceAuthConfig{Enabled: true, Tokens: tokens, TokenTTL: ttl, AdminToken: admin}, nil
}

// parseEnrollTokens splits a comma-separated token list, trimming whitespace and
// rejecting duplicates and short (weak) tokens. An empty/blank value yields no
// tokens and no error; the caller decides whether that is fatal.
func parseEnrollTokens(s string) ([]string, error) {
	seen := make(map[string]struct{})
	var out []string
	for _, part := range strings.Split(s, ",") {
		token := strings.TrimSpace(part)
		if token == "" {
			continue
		}
		if len(token) < minEnrollTokenLen {
			return nil, fmt.Errorf("each token must be at least %d characters (a short bootstrap secret is guessable)", minEnrollTokenLen)
		}
		if _, dup := seen[token]; dup {
			return nil, errors.New("duplicate token in list")
		}
		seen[token] = struct{}{}
		out = append(out, token)
	}
	return out, nil
}

// parseTokenTTL parses an optional Go duration. Empty => 0 (no expiry). A set
// value must be a positive duration.
func parseTokenTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("must be a Go duration such as \"24h\": %w", err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("must be positive, got %s", d)
	}
	return d, nil
}

// ---- Account model configuration (Phase 52) ----
//
// Environment, ALL optional; unset => the package defaults apply:
//
//	SIGILD_ACCOUNT_MAX_DEVICES  member devices per account. Default 10, range
//	                            [1, 1000]. Anti-freeloading, NOT anti-fraud.
//	SIGILD_ACCOUNT_MAX_INVITES  OPEN (unused/unexpired/unrevoked) invites per
//	                            account. Default 5, range [1, 100]. It bounds
//	                            stored STATE, not request volume — there is no
//	                            rate limit on invite minting.
//	SIGILD_ACCOUNT_INVITE_TTL   Go duration. Default 15m, must be > 0 and <= 24h.
//
// There is NO SIGILD_ACCOUNTS flag: accounts ride SIGILD_DEVICE_AUTH. Setting
// any of the three WITHOUT device auth is a boot error rather than a silently
// ignored knob.

// Account-model bounds. They mirror the api package's defaults; validation lives
// here so a malformed value is a startup failure, not a request-time surprise.
const (
	defaultAccountMaxDevices = 10
	minAccountMaxDevices     = 1
	maxAccountMaxDevices     = 1000
	defaultAccountMaxInvites = 5
	minAccountMaxInvites     = 1
	maxAccountMaxInvites     = 100
	defaultAccountInviteTTL  = 15 * time.Minute
	maxAccountInviteTTL      = 24 * time.Hour
)

// accountEnv is the raw environment for the account model, injected so
// validation is unit-testable without touching the process environment.
type accountEnv struct {
	DeviceAuth string
	MaxDevices string
	MaxInvites string
	InviteTTL  string
}

// accountConfig is the validated result.
type accountConfig struct {
	MaxDevices int
	MaxInvites int
	InviteTTL  time.Duration
}

// validateAccountConfig parses + validates the account-model environment and
// fails fast on any misconfiguration, BEFORE the listener binds. It performs no
// network I/O and never calls os.Exit, so it is unit-testable.
func validateAccountConfig(env accountEnv) (accountConfig, error) {
	set := strings.TrimSpace(env.MaxDevices) != "" ||
		strings.TrimSpace(env.MaxInvites) != "" ||
		strings.TrimSpace(env.InviteTTL) != ""
	if set && !truthy(env.DeviceAuth) {
		return accountConfig{}, errors.New("the SIGILD_ACCOUNT_* settings require SIGILD_DEVICE_AUTH: the account model rides the multi-device auth contract and has no separate switch")
	}

	maxDevices, err := parseBoundedInt(env.MaxDevices, defaultAccountMaxDevices, minAccountMaxDevices, maxAccountMaxDevices)
	if err != nil {
		return accountConfig{}, fmt.Errorf("SIGILD_ACCOUNT_MAX_DEVICES: %w", err)
	}
	maxInvites, err := parseBoundedInt(env.MaxInvites, defaultAccountMaxInvites, minAccountMaxInvites, maxAccountMaxInvites)
	if err != nil {
		return accountConfig{}, fmt.Errorf("SIGILD_ACCOUNT_MAX_INVITES: %w", err)
	}
	ttl, err := parseBoundedDuration(env.InviteTTL, defaultAccountInviteTTL, maxAccountInviteTTL)
	if err != nil {
		return accountConfig{}, fmt.Errorf("SIGILD_ACCOUNT_INVITE_TTL: %w", err)
	}
	return accountConfig{MaxDevices: maxDevices, MaxInvites: maxInvites, InviteTTL: ttl}, nil
}

// parseBoundedInt parses an optional integer env value into [min, max]. An empty
// value yields def; an out-of-range or unparseable value is an ERROR, never a
// silent clamp — an operator who typed 10000 meant something, and quietly
// serving 1000 hides it.
func parseBoundedInt(s string, def, minValue, maxValue int) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("must be an integer: %w", err)
	}
	if v < minValue || v > maxValue {
		return 0, fmt.Errorf("must be between %d and %d, got %d", minValue, maxValue, v)
	}
	return v, nil
}

// parseBoundedDuration parses an optional Go duration into (0, max]. Empty =>
// def; zero, negative, over the ceiling, or unparseable is an error.
func parseBoundedDuration(s string, def, maxValue time.Duration) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("must be a Go duration such as \"15m\": %w", err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("must be positive, got %s", d)
	}
	if d > maxValue {
		return 0, fmt.Errorf("must be at most %s, got %s", maxValue, d)
	}
	return d, nil
}

// ---- Abuse bounds configuration (Phase 53) ----
//
// Environment, ALL optional; unset => that limiter is NOT INSTALLED and the
// route behaves exactly as it did before:
//
//	SIGILD_ENROLL_RATE_LIMIT   POST /v1/devices/enroll, per SOURCE ADDRESS
//	SIGILD_ENROLL_RATE_BURST   (requests/second, bucket depth). Enrollment is the
//	                           one unauthenticated write path. ⚠️ It charges the
//	                           bucket only on the DENIAL path, so the handler and
//	                           its database work ALWAYS run and only the RESPONSE
//	                           is replaced: it bounds how useful flooding is, NOT
//	                           what it costs us. That is the deliberate trade that
//	                           makes it unable to refuse a valid enrolment.
//	                           ⚠️ Behind a reverse proxy every request appears to
//	                           come from the proxy and shares ONE bucket — see
//	                           clientRateKey. Rate-limit at the proxy instead.
//	SIGILD_INVITE_RATE_LIMIT   POST /v1/account/invites, per ACCOUNT (not per
//	SIGILD_INVITE_RATE_BURST   device: membership is flat and the open-invite cap
//	                           is per-account).
// ⛔ THERE IS NO SIGILD_WEBHOOK_RATE_LIMIT. One existed in Phase 53 and was
// REMOVED: on POST /v1/billing/webhook/{provider} the limiter's only possible
// key is the provider name, which forged traffic controls too, so an anonymous
// flood spent the same tokens as authentic Stripe deliveries and destroyed
// payment events in a live reproduction. Volume protection for that route
// belongs at the edge, where sources are distinguishable. Setting the old
// variables now does nothing; they are not read anywhere.
//
// These deliberately do NOT require SIGILD_ENABLE_DEV_OPS / SIGILD_DEVICE_AUTH,
// unlike the SIGILD_ACCOUNT_* settings. Those change WHO OWNS a vault, so a
// silently-ignored value there would be an ownership surprise; a rate limit is
// purely protective, and refusing to boot because a protective knob is currently
// moot would be a worse failure than the boot warning logAbuseBounds emits.

// abuseEnv is the raw environment for the abuse limiters, injected so validation
// is unit-testable without touching the process environment.
type abuseEnv struct {
	EnrollRate  string
	EnrollBurst string
	InviteRate  string
	InviteBurst string
}

// abuseConfig is the validated result. A zero rate means "not configured", which
// api.NewRouter turns into "no limiter installed".
type abuseConfig struct {
	EnrollRate  float64
	EnrollBurst int
	InviteRate  float64
	InviteBurst int
}

// Enabled reports whether any abuse limiter is configured.
func (c abuseConfig) Enabled() bool {
	return c.EnrollRate > 0 || c.InviteRate > 0
}

// validateAbuseConfig parses + validates the abuse-bound environment and fails
// fast on any malformed value, BEFORE the listener binds. It performs no network
// I/O and never calls os.Exit, so it is unit-testable.
//
// It reuses parseRateLimit / parseRateBurst / effectiveBurst verbatim, so all
// four rate limiters in this server share one parsing contract: a non-negative
// finite rate, a non-negative integer burst, and a burst defaulting to
// ceil(rate) when a positive rate is set without one.
func validateAbuseConfig(env abuseEnv) (abuseConfig, error) {
	var cfg abuseConfig
	var err error

	if cfg.EnrollRate, cfg.EnrollBurst, err = parseLimiterPair(env.EnrollRate, env.EnrollBurst); err != nil {
		return abuseConfig{}, fmt.Errorf("SIGILD_ENROLL_RATE_LIMIT/SIGILD_ENROLL_RATE_BURST: %w", err)
	}
	if cfg.InviteRate, cfg.InviteBurst, err = parseLimiterPair(env.InviteRate, env.InviteBurst); err != nil {
		return abuseConfig{}, fmt.Errorf("SIGILD_INVITE_RATE_LIMIT/SIGILD_INVITE_RATE_BURST: %w", err)
	}
	return cfg, nil
}

// parseLimiterPair parses one (rate, burst) pair. An empty rate yields (0, 0) —
// the limiter is not installed. A positive rate resolves its burst through
// effectiveBurst, exactly as the op-log limiter does.
func parseLimiterPair(rawRate, rawBurst string) (float64, int, error) {
	r, err := parseRateLimit(rawRate)
	if err != nil {
		return 0, 0, err
	}
	b, err := parseRateBurst(rawBurst)
	if err != nil {
		return 0, 0, err
	}
	if r > 0 {
		b = effectiveBurst(r, b)
	}
	return r, b, nil
}

// logAbuseBounds names every configured abuse limiter at boot, and warns when
// one is configured but the route it protects is gated off.
//
// The second half matters: the enroll, invite and webhook routes are all
// dev-gated, so a limiter configured on a server without SIGILD_ENABLE_DEV_OPS
// protects a route that only ever answers 501. That is harmless, but an operator
// who set it believes something is protected — so it is said out loud rather
// than being a silently inert knob.
func logAbuseBounds(logger *slog.Logger, cfg abuseConfig, devOps bool) {
	// A RETIRED knob must never be silently ignored. SIGILD_WEBHOOK_RATE_LIMIT
	// existed in Phase 53 and was removed when a live reproduction showed it let
	// anonymous forged traffic spend an authentic provider's quota and destroy
	// payment events. An operator upgrading with it still in an EnvironmentFile
	// would otherwise boot clean and believe the webhook route was protected —
	// which is the most dangerous possible misunderstanding of a removal.
	//
	// This WARNS rather than refusing to boot, for the reason given above: a
	// protective knob that has become moot should not take a payments server
	// down. Everything that CHANGES BEHAVIOUR still fails fast.
	for _, retired := range []string{"SIGILD_WEBHOOK_RATE_LIMIT", "SIGILD_WEBHOOK_RATE_BURST"} {
		if os.Getenv(retired) != "" {
			logger.Warn("RETIRED SETTING IGNORED: this variable is set but is no longer read. The webhook rate limiter was REMOVED because its only possible key is the provider name, which forged traffic also controls, so an anonymous flood spent authentic deliveries' quota and destroyed payment events. THE WEBHOOK ROUTE IS NOT RATE LIMITED — bound it at the edge, where sources are distinguishable",
				"setting", retired)
		}
	}
	if !cfg.Enabled() {
		return
	}
	logger.Warn("ABUSE RATE LIMITS ENABLED (per-process, in-memory token buckets) — these bound REQUEST VOLUME; the SIGILD_ACCOUNT_* caps bound stored STATE. A multi-instance deploy divides each budget across instances (there is no shared limiter store)",
		"enroll_per_sec", cfg.EnrollRate, "enroll_burst", cfg.EnrollBurst,
		"invite_per_sec", cfg.InviteRate, "invite_burst", cfg.InviteBurst)
	if cfg.EnrollRate > 0 {
		logger.Warn("ABUSE: the enrollment limiter keys on the SOCKET PEER ADDRESS and IGNORES X-Forwarded-For (untrusted input would let one client mint unlimited buckets). BEHIND A REVERSE PROXY — THE ONLY TOPOLOGY THIS REPO SHIPS — ALL ENROLMENTS SHARE ONE BUCKET, so this is a BACKSTOP, not a defence: rate-limit at the proxy, which knows the real peer. It charges the bucket ONLY for FAILED attempts, so a valid enrolment is never refused by it")
	}
	if !devOps {
		logger.Warn("ABUSE: rate limits are configured but SIGILD_ENABLE_DEV_OPS is off, so the enroll and invite routes answer 501 and NOTHING IS BEING LIMITED. This is not an error — the setting is simply inert until the dev gate is on")
	}
}

// ---- Entitlement enforcement configuration (Phase 55) ----
//
//	SIGILD_ENTITLEMENT_ENFORCE  truthy => refuse WRITES from an account whose
//	                            subscription lapsed more than the grace period
//	                            ago. UNSET (the default) => nothing is enforced
//	                            and the server behaves exactly as before.
//	SIGILD_ENTITLEMENT_GRACE    how long after a lapse writes keep working
//	                            (warned, not refused). Default 14 DAYS, bounded
//	                            to (0, 365d].
//
// ⭐ WHAT ENFORCEMENT CAN AND CANNOT DO, because an operator must know before
// switching it on:
//
//	REFUSED after grace   POST /v1/vaults/{id}/ops          (new op-log entries)
//	                      PUT  /v1/vaults/{id}/keys/{dev}   ONLY when {dev}
//	                      POST /v1/vaults/{id}/grants       belongs to ANOTHER
//	                                                        account
//	NEVER REFUSED         every GET — the op-log, the chain verification, key
//	                      envelopes, the per-device envelope index, hybrid keys,
//	                      grants, devices, the account, invites — plus device
//	                      enrollment and REVOCATION, envelope DELETION, invite
//	                      minting, every billing route including checkout, AND
//	                      ⭐ depositing a wrapped vault key (with its grant) to a
//	                      device of the CALLER'S OWN ACCOUNT, which is what makes
//	                      replacing a dead device and printing a RECOVERY KIT
//	                      work while lapsed.
//
// The line is drawn so a lapsed customer keeps every 2FA code they already have,
// can always establish the key access needed to read them on their own devices,
// can always revoke a stolen device, and can always pay. Refusing any of those
// over a declined card would be a security failure we caused. (The narrower
// earlier line — reads only — was reproduced leaving a lapsed customer with a
// new phone full of ciphertext it could never decrypt, and unable to print a
// recovery kit.)
//
// UNLIKE the abuse limiters (which are purely protective and merely inert
// without the dev gate), this REQUIRES SIGILD_ENABLE_DEV_OPS, SIGILD_DEVICE_AUTH
// and SIGILD_BILLING_PROVIDERS: it decides whether customers are served, and a
// setting that silently does nothing there is a business and support hazard.

// entitlementDefaultGrace / entitlementMaxGrace bound the configured window. The
// default is deliberately generous (see api.DefaultEntitlementGrace) and is
// taken from the api package so the two cannot drift.
const (
	entitlementDefaultGrace = api.DefaultEntitlementGrace
	entitlementMaxGrace     = 365 * 24 * time.Hour
)

// entitlementEnv is the raw environment, injected so validation is unit-testable
// without touching the process environment.
type entitlementEnv struct {
	Enforce    string
	Grace      string
	DevOps     string
	DeviceAuth string
	Billing    string
}

// entitlementConfig is the validated result. Enforce false => the api layer
// installs no policy at all.
type entitlementConfig struct {
	Enforce bool
	Grace   time.Duration
}

// validateEntitlementConfig parses + validates the enforcement environment and
// fails fast BEFORE the listener binds. It performs no network I/O, reads no
// store, and never calls os.Exit.
func validateEntitlementConfig(env entitlementEnv) (entitlementConfig, error) {
	enforce := truthy(env.Enforce)
	graceSet := strings.TrimSpace(env.Grace) != ""

	if graceSet && !enforce {
		return entitlementConfig{}, errors.New("SIGILD_ENTITLEMENT_GRACE requires SIGILD_ENTITLEMENT_ENFORCE: a grace period with nothing to be graceful about is an inert setting, and an operator who set it believes writes are being enforced")
	}
	if !enforce {
		return entitlementConfig{}, nil
	}
	if !truthy(env.DevOps) {
		return entitlementConfig{}, errors.New("SIGILD_ENTITLEMENT_ENFORCE requires SIGILD_ENABLE_DEV_OPS: the routes it gates all answer 501 without the dev gate")
	}
	if !truthy(env.DeviceAuth) {
		return entitlementConfig{}, errors.New("SIGILD_ENTITLEMENT_ENFORCE requires SIGILD_DEVICE_AUTH: entitlement is a property of an ACCOUNT, and accounts exist only under the multi-device auth model")
	}
	if strings.TrimSpace(env.Billing) == "" {
		return entitlementConfig{}, errors.New("SIGILD_ENTITLEMENT_ENFORCE requires SIGILD_BILLING_PROVIDERS: with no subscription store there is nothing to read, and enforcement would refuse every account or (as it in fact does) fail open for every one")
	}

	grace, err := parseBoundedDuration(env.Grace, entitlementDefaultGrace, entitlementMaxGrace)
	if err != nil {
		return entitlementConfig{}, fmt.Errorf("SIGILD_ENTITLEMENT_GRACE: %w", err)
	}
	return entitlementConfig{Enforce: true, Grace: grace}, nil
}

// logEntitlementEnforcement names, at every boot, exactly what enforcement will
// and will not refuse. It is a Warn even on the happy path: this is the one
// setting in this server that can stop serving a paying customer, so it is never
// allowed to be a quiet line in a config dump.
func logEntitlementEnforcement(logger *slog.Logger, cfg entitlementConfig) {
	if !cfg.Enforce {
		return
	}
	logger.Warn("ENTITLEMENT ENFORCEMENT ENABLED: after an account's subscription lapses AND its grace period expires, WRITES are refused with HTTP 402 (new op-log entries; new key envelopes and new vault grants ONLY when addressed to a device of ANOTHER account). READS ARE NEVER REFUSED — the op-log, chain verification, key envelopes, the per-device envelope index, hybrid keys, grants, devices, the account and every billing route (including checkout) all keep working, as do device enrollment, device REVOCATION and envelope DELETION. ESTABLISHING KEY ACCESS WITHIN YOUR OWN ACCOUNT IS ALSO NEVER REFUSED: depositing a wrapped vault key to a SAME-ACCOUNT device, and the grant that accompanies it, are exempt, so replacing a dead device and printing a RECOVERY KIT both still work. A lapsed customer therefore keeps every code they have, can always get the keys to read them onto their own devices, can always revoke a stolen device, and can always pay. past_due is still ENTITLED (a declined card starts a provider retry window, not a cutoff), and the grace period runs from the LATER of the subscription's last update and its paid-through date. An account that NEVER subscribed is graced from its creation time, so the same window doubles as the buy-in window. Any uncertainty FAILS OPEN (a subscription-store fault serves the request and logs entitlement.fail_open at error level). Dev-gated, UNAUDITED",
		"grace", cfg.Grace.String())
}

// parseOpLogPubKey parses SIGILD_OPLOG_PUBKEY: the standard-base64 encoding of a
// 32-byte Ed25519 public key. Invalid base64 or a wrong length is an error.
func parseOpLogPubKey(s string) (ed25519.PublicKey, error) {
	pub, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not valid standard base64: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("must decode to a %d-byte Ed25519 public key, got %d bytes",
			ed25519.PublicKeySize, len(pub))
	}
	return ed25519.PublicKey(pub), nil
}
