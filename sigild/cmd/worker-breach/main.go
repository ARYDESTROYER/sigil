// Command worker-breach will ingest the Have I Been Pwned breach feed used by
// the (client-side-evaluated) breach-monitoring feature.
//
// STATUS: pre-audit skeleton — not implemented.
package main

import (
	"log/slog"
	"os"
)

func main() {
	slog.New(slog.NewJSONHandler(os.Stdout, nil)).
		Info("worker-breach skeleton: not implemented")
}
