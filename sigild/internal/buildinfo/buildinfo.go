// Package buildinfo carries version metadata injected at build time.
package buildinfo

// Version is overridden at build time with the git SHA via:
//
//	go build -ldflags "-X github.com/ARYDESTROYER/sigil/sigild/internal/buildinfo.Version=$(git rev-parse --short HEAD)"
var Version = "dev"
