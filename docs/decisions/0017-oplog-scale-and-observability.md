# 0017 — Op-log scale & observability: pagination, per-vault rate limiting, `/metrics`, and fail-fast config

- **Status:** Accepted — 2026-07.

## Context

The dev op-log ([`0003`](0003-dev-gated-opaque-op-log.md)) grew a durable
Postgres backend ([`0014`](0014-postgres-durable-oplog-backend.md)), a structured
audit log with request-context propagation
([`0015`](0015-oplog-auditability-and-request-context.md)), and a per-op
tamper-evident hash chain ([`0016`](0016-tamper-evident-oplog-hash-chain.md)).
Those made it durable, auditable, and integrity-checkable — but three
operational gaps remained, and one hardening gap:

1. **Unbounded reads.** `GET …/ops?since=N` returned **every** op after `N` in a
   single response. A long-lived vault means an unbounded slice held in memory
   and an unbounded response body — a memory/latency footgun as vaults grow, and
   no way for a client to page.
2. **Unbounded appends.** `POST …/ops` had no throttle. A single vault (or a
   buggy/hostile client) could hammer the backend — the durable Postgres backend
   especially — with no per-vault back-pressure.
3. **No observability.** There was no way to see request/append/verify/denial
   volume without scraping logs. Reaching for a Prometheus **client library**
   would add a dependency to a surface that is otherwise Go-stdlib-only except
   for `pgx` ([`0005`](0005-stdlib-only-sigild.md), [`0014`](0014-postgres-durable-oplog-backend.md)).
4. **Late config failure.** A malformed env var (bad address, non-numeric limit,
   invalid pubkey) would either be ignored or blow up at first request rather
   than at boot, so a misconfigured instance could start and *look* healthy.

The constraints from [`0003`](0003-dev-gated-opaque-op-log.md) bind absolutely:
the server stores **opaque blobs** and does **no crypto on the plaintext**; the
op-log stays **dev-gated** (`SIGILD_ENABLE_DEV_OPS`, default `501`) and
**unauthenticated unless `SIGILD_OPLOG_PUBKEY`**. Any scale/observability work
must preserve zero-knowledge, add **no new dependency**, and not weaken the
default posture.

## Decision

Add four **pure Go stdlib** capabilities — **no new dependency** (`pgx` stays the
only third-party import), and **none** changing the dev-gated / opaque /
unauthenticated-by-default posture:

- **Bounded, paginated reads.** `GET …/ops` takes an optional **`limit`**
  (default **500**, max **1000**); an out-of-range or non-integer value is
  rejected with **`400 bad_limit`**. The response gains a **`has_more`** boolean
  alongside `next`. A client drains a vault by looping `since = next` until
  `has_more` is `false`. This bounds server memory and response size regardless
  of vault length, in every backend (Mem/File/Postgres apply the same cap; the
  Postgres backend uses it as a `LIMIT`).
- **Per-vault token-bucket rate limiting.** When **`SIGILD_OPLOG_RATE_LIMIT`** is
  set (positive sustained appends/second per vault, with optional
  **`SIGILD_OPLOG_RATE_BURST`** bucket depth), each **vault ID** gets an independent
  stdlib token-bucket limiter. An append over the vault's refill rate gets
  **`429 rate_limited`** with a **`Retry-After`** header. Per-vault isolation
  means one busy vault cannot starve others. **Off by default** — unset ⇒ no
  throttle, behaviour unchanged. It shapes append *rate* only and **never
  inspects the opaque blob**.
- **A stdlib `/metrics` endpoint.** A new **always-available** (independent of the
  dev gate), unauthenticated **`GET /metrics`** renders a hand-written
  **Prometheus text exposition** of process counters — HTTP requests, op-log
  appends, verifies, auth denials **by reason**, rate-limit rejections, and a
  `build_info` series carrying the build version. It exposes **only aggregate
  counters and the build version — never a blob, key, signature, nonce, vault
  content, or vault ID** — and does **no cryptography**, so it cannot leak
  plaintext or weaken zero-knowledge. Counters are process-lifetime and
  **unlabelled by vault** (no per-vault cardinality blow-up, no client-chosen ID
  exported).
- **Fail-fast config validation.** At startup `sigild` **validates its
  configuration and refuses to boot on a malformed value** (bad `SIGILD_ADDR`,
  non-numeric `SIGILD_OPLOG_RATE_LIMIT` / `SIGILD_OPLOG_RATE_BURST`, a
  `SIGILD_OPLOG_PUBKEY` that is not base64 of a 32-byte key, etc.), exiting
  non-zero with a clear message rather than starting misconfigured and failing
  later at request time.

## Consequences

- **Bounded resource use.** Reads are paginated and appends are optionally
  throttled per vault, so a large or busy vault can no longer blow up server
  memory, response size, or backend load. Clients get an explicit, terminating
  paging protocol (`since=next` until `has_more=false`).
- **Operable without new deps.** `/metrics` gives request/append/verify/denial/
  rate-limit visibility for a Prometheus scrape, and the counters stay
  **stdlib-rendered** — the stdlib-only-except-`pgx` posture
  ([`0005`](0005-stdlib-only-sigild.md), [`0014`](0014-postgres-durable-oplog-backend.md))
  is preserved.
- **Zero-knowledge intact.** The rate limiter keys on the vault ID but never
  reads the blob; `/metrics` exports only counts and the version — no blob, key,
  or vault ID. The server still holds no plaintext and no key (see
  [`../threat-model.md`](../threat-model.md)).
- **Misconfiguration surfaces at boot.** Fail-fast validation turns a bad env var
  into a failed unit start (Shape 1 systemd) instead of a silently-wrong running
  instance.
- **Security posture unchanged.** Still `SIGILD_ENABLE_DEV_OPS`-gated and `501` by
  default, still unauthenticated unless `SIGILD_OPLOG_PUBKEY`, still opaque blobs
  only, still no crypto on the plaintext. `/metrics` is the only always-on
  addition, and it is counters-only. The rate limiter and pagination bounds are
  the only new behaviours, both dev-op-scoped or off-by-default.
- **Not production SLOs.** These are dev-scale operability primitives — an
  in-process rate limiter (per-process, not a distributed quota), process-local
  counters (reset on restart, not a durable TSDB), and boot-time validation — not
  the production build's rate-limit tier, metrics pipeline, or config management.
- Documented in-sync: the `?limit` / `has_more` pagination, the `429
  rate_limited` + `Retry-After` rate limit, and the `/metrics` endpoint are in
  [`../api.md`](../api.md); the component change is in
  [`../architecture.md`](../architecture.md) §1 and §4; and the scrape target,
  the rate-limit knobs, and fail-fast config validation are in
  [`../deployment.md`](../deployment.md) §6–§7.

Cross-links: builds on [0014](0014-postgres-durable-oplog-backend.md),
[0015](0015-oplog-auditability-and-request-context.md), and
[0016](0016-tamper-evident-oplog-hash-chain.md); stays within the stdlib-only
posture of [0005](0005-stdlib-only-sigild.md).
