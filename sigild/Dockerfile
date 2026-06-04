# syntax=docker/dockerfile:1
#
# SKELETON / pre-audit container image for sigild, the Sigil sync server.
#
# What this builds: a hermetic, multi-stage, NON-root, minimal image of the
# sigild HTTP skeleton. sigild performs NO cryptography and stores NO vault
# data; this image is no exception. It is part of the pre-audit foundation
# scaffold and makes no security guarantees.
#
# No Docker HEALTHCHECK: the final image is distroless and has no shell, so a
# shell-based HEALTHCHECK is impossible by design. Liveness is the orchestrator's
# responsibility — it issues an HTTP probe against /healthz (the Nomad job and
# Caddy config already do this). /version and /readyz are also available.
#
# Secrets: none are baked into the image. Runtime configuration (SIGILD_ADDR,
# SIGILD_POSTGRES_ADDR, SIGILD_REDIS_ADDR, and any future credentials) is
# supplied by the runtime environment, never committed to the image layers.
#
# Build:
#   docker build --build-arg VERSION=$(git rev-parse --short HEAD) -t sigild .
# (run from the sigild/ directory — the build context is sigild/.)

# ---- builder stage ---------------------------------------------------------
FROM golang:1.24-alpine AS builder

# VERSION is stamped into the binary via -ldflags. Defaults to "dev" so the
# image still builds without an explicit build-arg.
ARG VERSION=dev

WORKDIR /src

# sigild is stdlib-only, so there is no go.sum to copy and no module download
# step. Copy go.mod first to keep the layer cache warm, then the source.
COPY go.mod ./
COPY . ./

# Static, reproducible-ish build: CGO off, stripped (-s -w), -trimpath, with the
# build version injected into buildinfo.Version.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w -X github.com/ARYDESTROYER/sigil/sigild/internal/buildinfo.Version=${VERSION}" \
    -o /out/sigild \
    ./cmd/server

# ---- final stage -----------------------------------------------------------
# distroless static: no shell, no package manager, runs as an unprivileged user.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/sigild /usr/local/bin/sigild

USER nonroot
EXPOSE 8080
ENV SIGILD_ADDR=":8080"

ENTRYPOINT ["/usr/local/bin/sigild"]
