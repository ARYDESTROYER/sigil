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
		// Optional durable LOCAL-DEV backend: if SIGILD_OPLOG_DIR is set, persist
		// the dev op-log to per-vault append-only files there so it survives a
		// restart. It is still UNAUTHENTICATED / dev-only and is NOT the
		// production store (production = Postgres/S3/Redis). Unset => in-memory.
		if dir := os.Getenv("SIGILD_OPLOG_DIR"); dir != "" {
			fileLog, err := store.NewFileVaultLog(dir)
			if err != nil {
				logger.Error("failed to open file-backed dev op-log", "dir", dir, "err", err)
				os.Exit(1)
			}
			cfg.VaultLog = fileLog
			logger.Warn("DEV op-log enabled: FILE-BACKED durable backend active — UNAUTHENTICATED, dev-only, NOT the production store — do NOT expose publicly", "dir", dir)
		} else {
			logger.Warn("DEV op-log enabled: UNAUTHENTICATED, in-memory, non-durable — do NOT expose publicly")
		}

		// Optional op-log request-auth: if SIGILD_OPLOG_PUBKEY is set, it MUST be
		// the standard-base64 of a 32-byte Ed25519 public key. When set, every
		// GET/POST vault-ops request must carry a valid X-Sigil-Timestamp +
		// X-Sigil-Nonce + X-Sigil-Signature over the v2 canonical message (see
		// internal/api/opsauth.go), and a bounded in-memory nonce store rejects
		// in-window replays. Unset => no auth (unchanged). HONEST SCOPE: a SINGLE
		// configured DEV device key; the nonce store is in-memory (lost on
		// restart, not shared across instances); full device enrollment is FUTURE.
		// Only meaningful while dev-ops is on.
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
			logger.Warn("DEV op-log request AUTH ENABLED: Ed25519 (v2, per-request nonce), SINGLE configured DEV device key, in-memory replay guard (lost on restart, not shared across instances) — dev-only, do NOT expose publicly")
		}
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           api.NewRouter(cfg),
		ReadHeaderTimeout: 5 * time.Second,
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
