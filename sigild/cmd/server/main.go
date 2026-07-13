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
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/api"
	"github.com/ARYDESTROYER/sigil/sigild/internal/buildinfo"
	"github.com/ARYDESTROYER/sigil/sigild/internal/store"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	addr := getenv("SIGILD_ADDR", ":8080")
	devOps := truthy(os.Getenv("SIGILD_ENABLE_DEV_OPS"))
	cfg := api.Config{
		Version: buildinfo.Version,
		// host:port reachability targets; empty => reported "unconfigured".
		// The production build will replace plain dials with real pgx/redis pings.
		PostgresAddr:  os.Getenv("SIGILD_POSTGRES_ADDR"),
		RedisAddr:     os.Getenv("SIGILD_REDIS_ADDR"),
		Logger:        logger,
		DevOpsEnabled: devOps,
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
			logger.Warn("DEV op-log enabled: DURABLE POSTGRES backend active — UNAUTHENTICATED, dev-only, NOT a finished production store (no auth model / enrollment / CRDT / backups) — do NOT expose publicly")
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
			pub, err := base64.StdEncoding.DecodeString(raw)
			if err != nil {
				logger.Error("SIGILD_OPLOG_PUBKEY is not valid standard base64", "err", err)
				os.Exit(1)
			}
			if len(pub) != ed25519.PublicKeySize {
				logger.Error("SIGILD_OPLOG_PUBKEY must decode to a 32-byte Ed25519 public key",
					"got_bytes", len(pub), "want_bytes", ed25519.PublicKeySize)
				os.Exit(1)
			}
			cfg.OpLogPubKey = ed25519.PublicKey(pub)
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
