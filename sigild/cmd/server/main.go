// Command sigild is the Sigil sync server.
//
// STATUS: pre-audit skeleton. It serves liveness/readiness probes and a
// not-yet-implemented vault-ops endpoint. It performs NO cryptography, stores
// NO vault data, and understands NO vault format — see docs/sprint-72h.md and
// section 14 of the product brief ("what sigild does not do").
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ARYDESTROYER/sigil/sigild/internal/api"
	"github.com/ARYDESTROYER/sigil/sigild/internal/buildinfo"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	addr := getenv("SIGILD_ADDR", ":8080")
	cfg := api.Config{
		Version: buildinfo.Version,
		// host:port reachability targets; empty => reported "unconfigured".
		// The production build will replace plain dials with real pgx/redis pings.
		PostgresAddr: os.Getenv("SIGILD_POSTGRES_ADDR"),
		RedisAddr:    os.Getenv("SIGILD_REDIS_ADDR"),
		Logger:       logger,
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
