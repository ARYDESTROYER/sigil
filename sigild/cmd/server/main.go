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
	}
	if devOps && rate > 0 {
		logger.Warn("DEV op-log per-vault RATE LIMIT enabled — dev-only",
			"rate_per_sec", rate, "burst", burst)
	}
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
			} else {
				cfg.Devices = store.NewMemDeviceStore()
				logger.Warn("DEVICE AUTH: registry is IN-MEMORY and NON-DURABLE — devices, grants and spent enrollment tokens are lost on restart; use the Postgres op-log backend for durability")
			}
			cfg.AdminToken = deviceAuth.AdminToken

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

// usageText documents the (few) sigild invocations. Printed on an unknown
// subcommand.
const usageText = `usage:
  sigild                 run the sync server (config via environment)
  sigild migrate         apply pending op-log database migrations
  sigild migrate status  show migration status (applies nothing)`

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

// parseMigrateArgs interprets the arguments after `migrate`. No args => apply
// pending (statusOnly=false); the single arg "status" => report only
// (statusOnly=true). Anything else is an error. Kept separate so arg parsing is
// unit-testable without a database.
func parseMigrateArgs(args []string) (statusOnly bool, err error) {
	switch {
	case len(args) == 0:
		return false, nil
	case len(args) == 1 && args[0] == "status":
		return true, nil
	default:
		return false, fmt.Errorf("unknown migrate argument %q (want: `sigild migrate` or `sigild migrate status`)",
			strings.Join(args, " "))
	}
}

// runMigrate applies pending op-log migrations (or, with "status", reports
// them). Migrations only apply to the Postgres backend, so SIGILD_OPLOG_POSTGRES
// must be set; otherwise it returns a clear error. Arg parsing and the
// missing-DSN check happen BEFORE any connection, so those paths are unit-
// testable without a database.
func runMigrate(ctx context.Context, args []string, out io.Writer) error {
	statusOnly, err := parseMigrateArgs(args)
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

	if statusOnly {
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
