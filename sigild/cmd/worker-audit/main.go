// Command worker-audit will ship the append-only, signed audit log to
// ClickHouse for long-term (7-year) retention.
//
// STATUS: pre-audit skeleton — not implemented.
package main

import (
	"log/slog"
	"os"
)

func main() {
	slog.New(slog.NewJSONHandler(os.Stdout, nil)).
		Info("worker-audit skeleton: not implemented")
}
