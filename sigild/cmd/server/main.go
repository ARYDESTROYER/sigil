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
