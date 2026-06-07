# 0005 — `sigild` is Go stdlib-only

- **Status:** Accepted — 2026-06.

## Context

`sigild` ([`../../sigild/`](../../sigild/)) is the sync-server skeleton built
during the foundation sprint. At this stage it does **no cryptography** and has
**no real backing stores** — its job is to serve probes (`/healthz`, `/readyz`,
`/version`), the request-ID / access-log / panic-recovery middleware, and the
dev-gated opaque op-log ([ADR 0003](0003-dev-gated-opaque-op-log.md)). A
production sync server will eventually need a Postgres driver, a Redis client,
and an object-store SDK — but none of those endpoints exist yet, and adding
their SDKs now would mean carrying third-party modules (and a `go.sum`, a
vulnerability surface, and network access in CI) for code paths that are still
stubs.

## Decision

Keep `sigild` **Go standard-library only** for the skeleton: no third-party
modules, and therefore **no `go.sum`**. Everything it does today is expressed
with the stdlib — `net/http` (the Go 1.22+ method+pattern mux), `encoding/json`,
`encoding/base64`, `sync`, `log/slog`, `os`, `net` (the `readyz` probe uses a
plain `net.DialTimeout` reachability check rather than a real `pgx`/`redis`
ping), and `net/http/httptest` for tests.

Real drivers (`pgx`/Postgres, Redis, S3/R2) arrive **with the real endpoints**
they serve — not before.

## Consequences

- **Hermetic, offline, dependency-light** builds and tests: CI needs no network
  to resolve modules, the build is reproducible, and the dependency/vulnerability
  surface is near zero (`go.mod` has no `require` block; there is no `go.sum`).
- `readyz` reports reachability via a TCP dial, not a real database handshake —
  it is honestly documented as the skeleton's check, to be swapped for real
  pings in the production build (see [`../api.md`](../api.md)).
- When durable storage and caching land, this ADR will be **superseded** by one
  that introduces the chosen drivers and the `go.sum` they bring.
- This keeps the server's near-term surface small and auditable; it is a
  skeleton decision, not a claim that the server is production-ready. See
  [`../architecture.md`](../architecture.md) §4 and [`../../CLAUDE.md`](../../CLAUDE.md).
