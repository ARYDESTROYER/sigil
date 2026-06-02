// Command worker-rehash will re-run Argon2id rehashing of master-password auth
// verifiers when parameters are bumped.
//
// STATUS: pre-audit skeleton — not implemented.
package main

import (
	"log/slog"
	"os"
)

func main() {
	slog.New(slog.NewJSONHandler(os.Stdout, nil)).
		Info("worker-rehash skeleton: not implemented")
}
