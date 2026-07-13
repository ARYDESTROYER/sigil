# sigild

The Sigil sync server (Go). **Pre-audit skeleton** — it serves liveness/
readiness probes and a deliberate `501` for the vault op log. It performs no
cryptography, stores no vault data, and understands no vault format (by design;
brief §14).

- `cmd/server/` — the HTTP server (graceful shutdown, structured logging).
- `cmd/worker-{rehash,audit,breach}/` — background-worker stubs.
- `internal/api/` — router + handlers (`/healthz`, `/readyz`, `/v1/vaults/{id}/ops`).
- `internal/{auth,vault,push,admin,store}/` — reserved packages (not implemented).
- `internal/buildinfo/` — version injected at build time via `-ldflags`.

Run `go -C sigild test ./...` etc. (see [`../CLAUDE.md`](../CLAUDE.md)). Almost
entirely Go stdlib: the one third-party dependency is `pgx`, linked only by the
**opt-in** durable Postgres op-log backend (`SIGILD_OPLOG_POSTGRES`); the core
server and the in-memory / file-backed dev backends stay stdlib-only. The
Postgres integration tests skip unless `SIGILD_TEST_POSTGRES` is set, so a plain
`go test ./...` stays hermetic and green with no database.
