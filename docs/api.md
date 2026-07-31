# sigild HTTP API reference

> **STATUS: pre-audit skeleton.** `sigild` is the Sigil sync-server skeleton.
> ⭐ **Be precise about what it does and does not do with cryptography, because an
> earlier version of this line was simply false.** `sigild` performs **no
> cryptography on vault content**, holds **no key that can decrypt a vault**, and
> stores **no plaintext**: it never decodes a blob or an envelope, and it has no
> decapsulation key. It does, however, perform **real cryptography for
> authentication and integrity** — Ed25519 signature verification on every
> authenticated request, SHA-256 for the op-log hash chain, enrollment/admin token
> digests, and constant-time HMAC verification of provider webhooks — and it
> **does hold keys of a kind**: devices' Ed25519 **public** keys, devices'
> published hybrid **public** keys, and provider webhook **secrets** in its
> configuration. None of those can open a vault. That distinction is the whole
> trust boundary; "no cryptography" full stop is not the claim.
>
> The only stateful surface — the vault operation log — is a **dev-only,
> opt-in** store of **opaque client-encrypted blobs** the
> server never decrypts or interprets (in-memory by default, with optional
> file-backed or durable Postgres backends), **unauthenticated unless one of two
> opt-in auth contracts is configured** (legacy single-key **v2**, or the
> **multi-device v3** model with a device registry, per-vault authorization and
> revocation — itself dev-gated and unaudited). The same dev gate also opens a
> **vault-sharing relay** ([below](#device-to-device-vault-sharing-dev-gated-opt-in--phase-46)):
> the server parks a device's **public** hybrid key and an **opaque wrapped vault
> key** for a recipient device, returning both verbatim — it holds no
> decapsulation key and cannot read the envelope it relays. On top of the v3
> model sits an **account** ([below](#account-model-dev-gated--phase-52)): a
> server-assigned id on the device row that **entitlement** and **vault
> ownership** key off instead of the device. It is **auth metadata only** — no
> email, no password, no session, **no identity system** — and ⭐ **no request
> anywhere names an account**. The only recovery is a **paper kit printed in
> advance** ([below](#recovery-kits-dev-gated--phase-54)), which the server sees
> as an ordinary device and has **no concept of**. ⭐ **The same is true of
> passkeys:** Phase 58 gave the webapp an optional **second at-rest factor** for its
> local sealed containers ([ADR 0046](decisions/0046-passkey-protected-local-containers.md)),
> and `sigild` gained **nothing at all** — no route, no header, no canonical
> message, no migration, no table, no metric, no dependency, and no
> `sigild_schema_version` bump. Request authentication is still the classical
> Ed25519 contract-v3 signature. **Nothing in this reference changed for it**, and a
> server cannot disable, weaken, detect or observe it. A **dev-gated, opt-in
> billing layer** (hosted checkout + provider webhooks, [below](#billing--subscriptions-dev-gated-opt-in--phase-45))
> stores subscription state but **no card data**, and has **never been run
> against a live payment provider**; since Phase 55 it can, **opt-in**, refuse a
> lapsed account's **writes** with `402` — ⭐ **never its reads**
> ([below](#entitlement-enforcement-opt-in--phase-55)). Nothing
> here is audited or production-ready. See [`deployment.md`](deployment.md) for
> the (not-yet-applied) deploy story and [`sprint-72h.md`](sprint-72h.md) for
> scope. This reference describes the surface as wired in
> [`../sigild/internal/api/`](../sigild/internal/api/); the contract is not
> frozen.

All responses are JSON (`Content-Type: application/json`). Every request is
assigned (or honours an inbound) `X-Request-ID`, echoed on the response.

Errors use a single typed envelope:

```json
{ "error": "<stable_machine_code>", "detail": "<human-readable explanation>" }
```

Vault-scoped errors may additionally carry `"vaultID": "<id>"`. The set of error
codes is **not yet frozen** pre-audit.

---

## Probes

### `GET /healthz` — liveness

Always `200` while the process is serving. Performs no dependency checks.

```json
{ "status": "ok", "version": "<build version>" }
```

### `GET /readyz` — readiness

`200` when every *configured* dependency is healthy (or is unconfigured); `503`
when a configured dependency is unreachable, so a load balancer drains the
instance. The future `SIGILD_POSTGRES_ADDR` / `SIGILD_REDIS_ADDR` probes are
still a plain TCP dial only (no auth handshake — that is the production build's
job). The **active op-log backend**, however, now gets a **real** health check:
when the durable Postgres op-log backend (`SIGILD_OPLOG_POSTGRES`) is in use,
`/readyz` **pings its `pgxpool` connection pool** and returns `503` if that ping
fails; the in-memory and file-backed backends have no remote dependency (they do
not implement `store.Pinger`), so the live check is skipped for them and the
`oplog` key is **omitted entirely** rather than reported as `unconfigured`.

```json
{ "version": "<build version>", "checks": { "postgres": "ok|unreachable|unconfigured", "redis": "ok|unreachable|unconfigured", "oplog": "ok|unreachable" } }
```

The `postgres` / `redis` keys are always present and use the TCP-dial states
(`unconfigured` when the corresponding address env var is unset). The `oplog`
key appears **only** when the active backend implements `store.Pinger` (today:
the Postgres op-log backend) and is then only ever `ok` or `unreachable` — a
default instance therefore reports just
`{"checks":{"postgres":"unconfigured","redis":"unconfigured"},…}`.

### `GET /version` — build identity

Echoes the build name and injected version string. No secrets, no crypto.

```json
{ "name": "sigild", "version": "<build version>" }
```

The `version` value is injected at build time from the git short SHA via
`-ldflags` (default `"dev"`); see
[`../sigild/internal/buildinfo/buildinfo.go`](../sigild/internal/buildinfo/buildinfo.go).

---

## Metrics

### `GET /metrics` — Prometheus-text counters

**Always available** (independent of `SIGILD_ENABLE_DEV_OPS`), unauthenticated,
and **stdlib-only** — a hand-rendered
[Prometheus text exposition](https://prometheus.io/docs/instrumenting/exposition_formats/)
(`Content-Type: text/plain; version=0.0.4`) of process counters, so an operator
can scrape `sigild` without adding a metrics client library. It exposes **only
monotonic counters and the build version — never any blob, key, signature,
nonce, vault content, or other secret** (a metrics endpoint that leaked payload
would break the zero-knowledge property; this one cannot, because it holds
nothing but counts).

The exported series (names follow Prometheus conventions; the endpoint itself is
the source of truth for the exact strings):

| Metric | Type | Meaning |
|--------|------|---------|
| `sigild_http_requests_total{class="…"}` | counter | total HTTP responses served, by status class (`1xx`…`5xx`) |
| `sigild_oplog_appends_total` | counter | op-log appends accepted (`POST …/ops`) |
| `sigild_oplog_verify_total` | counter | chain verifies run (`GET …/ops/verify`) |
| `sigild_oplog_auth_denied_total{reason="…"}` | counter | request auth/authz denials, **labelled by reason** (the fixed enum below). ⚠️ The label set is **narrower than the audit log's**: reasons a client cannot tell apart are **collapsed** here — see the note under [Denial reasons](#denial-reasons-audit--metrics-only) |
| `sigild_oplog_authz_denied_total` | counter | requests denied by **per-vault authorization** (HTTP `403`) — a subset of the above, broken out so an operator can alert on `403`s alone |
| `sigild_oplog_ratelimit_rejected_total` | counter | appends rejected with `429` by the per-vault rate limiter |
| `sigild_abuse_ratelimit_rejected_total{surface="…"}` | counter | requests rejected with `429` by an **abuse-bound** limiter, over the closed set `enroll` / `invite` ([below](#abuse-rate-limiting-enrollment--invite-minting)). Counts only — **no address, account or key label**, so a scrape cannot learn *who* was limited |
| `sigild_device_enrollments_total` | counter | device enrollments accepted (`POST /v1/devices/enroll`) |
| `sigild_device_enroll_denied_total{reason="…"}` | counter | enrollment attempts denied, labelled by reason |
| `sigild_device_revocations_total` | counter | device revocations performed |
| `sigild_vault_grants_total` | counter | per-vault access grants created |
| `sigild_vault_claims_total` | counter | vault ownership claims (trust-on-first-write — **by account** since Phase 52) |
| `sigild_accounts_created_total` | counter | accounts created (an **operator-token** enrollment always founds a new one) |
| `sigild_account_invites_created_total` | counter | account invites minted (`POST /v1/account/invites`) |
| `sigild_account_invites_revoked_total` | counter | account invites revoked before use |
| `sigild_account_joins_total` | counter | devices that joined an **existing** account by redeeming an invite |
| `sigild_device_hybrid_keys_published_total` | counter | device hybrid **public** key publishes, including re-publishes (`PUT /v1/devices/{deviceID}/hybrid-key`) |
| `sigild_vault_key_envelopes_total` | counter | opaque wrapped-vault-key envelopes deposited (`PUT /v1/vaults/{vaultID}/keys/{deviceID}`) |
| `sigild_vault_key_envelope_fetches_total` | counter | envelopes collected by their recipient (`GET /v1/vaults/{vaultID}/keys/{deviceID}`) |
| `sigild_key_envelope_deletes_total` | counter | envelopes deleted during a vault key rotation (`DELETE /v1/vaults/{vaultID}/keys/{deviceID}`). A count only — no vault ID, no device ID, no blob |
| `sigild_key_envelope_index_total` | counter | per-device envelope-index reads (`GET /v1/devices/{deviceID}/keys`) — which vaults hold a wrapped key for the caller. A count only |
| `sigild_entitlement_enforcing` | gauge (`0`/`1`) | `1` when payment enforcement is active on the three **write** surfaces (reads are never enforced). Exported so an operator can see at a glance whether a knob believed to be on actually is |
| `sigild_entitlement_decisions_total{outcome="…"}` | counter | entitlement verdicts on **write** requests, over the closed set `entitled` / `grace` / `refused` / `fail_open`. **No account or subject label** — a scrape must never be able to enumerate which customers are behind on payment |
| `sigild_billing_checkouts_total{provider="…"}` | counter | hosted checkout sessions created, by provider (`stripe`/`razorpay`/`juspay`) |
| `sigild_billing_webhooks_total{provider="…",outcome="…"}` | counter | **authenticated** webhooks handled, by provider and outcome (`accepted`, `ignored`, `duplicate`, `stale`, `illegal`, `unresolved`) |
| `sigild_billing_webhook_rejected_total{reason="…"}` | counter | webhooks rejected **before** application, by reason (`bad_signature`, `malformed`, `unknown_provider`, `payload_too_large`, `store_error`) |
| `sigild_billing_subscription_transitions_total{status="…"}` | counter | **applied** subscription status transitions, by target status (`none`, `trialing`, `active`, `past_due`, `canceled`) |
| `sigild_schema_version` | gauge | applied op-log DB migration version (`0` when the backend is not Postgres; **`5`** once `0005_accounts.sql` is applied) |
| `sigild_build_info{version="…"}` | gauge (`1`) | build identity; the version label carries the injected build SHA |

Counters are **process-lifetime and unlabelled by vault or device** (no per-vault
cardinality blow-up, and no vault ID or device ID — a device-ID label would let a
scrape enumerate the registry — is exported). The endpoint performs **no
cryptography** and reads no stored bytes; it only reports aggregate counts, and
it never exposes a public key, an enrollment token or its digest, an admin
token, a signature, or a nonce. The four **vault-sharing** counters
(`sigild_device_hybrid_keys_published_total`, `sigild_vault_key_envelopes_total`,
`sigild_vault_key_envelope_fetches_total`, `sigild_key_envelope_deletes_total`)
follow the same rule: they are counts only, carrying no envelope byte, no hybrid
public key, no vault key, and no vault or device ID as a label.

The four **account** counters (Phase 52) follow the same rule and are counts only:
**no account id, device id, vault id or invite handle may ever become a label**, and
the account model deliberately added **no fine-grained invite-failure counter** —
`/metrics` is always-on and unauthenticated, so a per-cause counter there would be a
weak correlatable oracle on invite state. Every invite failure collapses onto an
**existing** coarse label on `sigild_device_enroll_denied_total{reason}` (whose only
new value is `account_full`); the fine-grained cause goes to the audit log alone.

Every **billing** label above comes from a **closed set materialized at startup**
(the three provider names, the six outcomes, the five rejection reasons, the five
statuses), so a scrape can neither enumerate what is configured nor be made to
create a new series. The billing counters carry **no API key, webhook secret,
signature, event ID, subject/device ID, customer reference, or amount**.

`sigild_schema_version` reflects the applied op-log database migration version for
the **Postgres backend**; migrations are managed with an **operator CLI**, not an
HTTP endpoint — `sigild migrate` applies pending migrations and `sigild migrate
status` reports them (default auto-apply at boot, opt out with
`SIGILD_OPLOG_AUTO_MIGRATE=0`). See
[`deployment.md` §11](deployment.md#11-schema-migrations-postgres-backend).

---

## Cross-origin requests (`SIGILD_CORS_ORIGINS`) — opt-in, OFF by default

> ⚠️ **This is not an authentication control and not a CSRF control.** `sigild`
> issues **no cookie, no session and no ambient bearer token**; every
> authenticated request is authenticated by a **per-request Ed25519 signature**
> over a canonical message ([contract v3](#signed-request-contract-v3)). A
> cross-origin page holds no device key, so it cannot forge a request whatever
> CORS says. The allowlist exists so the browser half of the product works at
> all, so the set of pages permitted to reach a server is a deliberate operator
> decision, and so a browser-side failure is an honest configuration error. See
> [ADR 0044](decisions/0044-opt-in-cors-allowlist.md).

Every signed request carries `X-Sigil-Device`, `X-Sigil-Timestamp`,
`X-Sigil-Nonce` and `X-Sigil-Signature`. None of those is a CORS-safelisted
request header, so a **browser preflights every one of them**. Before Phase 56
`sigild` routed no `OPTIONS` and emitted no `Access-Control-*` header, so a
preflight was answered `405` and a browser page on a different origin than the
API could not reach it at all. (An MV3 extension page with a matching
`host_permissions` entry is exempt from CORS and was never affected.)

**Unset — the default — means no CORS at all.** The middleware is **not
installed**: no response carries an `Access-Control-*` header, no response
carries `Vary: Origin`, and `OPTIONS` falls through to the mux and is answered
`405`. This is byte-identical to a pre-Phase-56 server.

| Variable | Default | Meaning |
|----------|---------|---------|
| `SIGILD_CORS_ORIGINS` | unset ⇒ **off** | comma-separated **exact** origins (scheme + host + optional port, nothing else), e.g. `http://127.0.0.1:3000,http://localhost:3000` |

Validated **fail-fast before the listener binds**. A path, query, fragment,
trailing slash, embedded credentials, a non-`http(s)` scheme, or a value that
leaves no origins at all is a **startup failure**. **`*` is REFUSED at boot**
(exit code 1, the listener never binds) rather than accepted and narrowed.

**Behaviour when an allowlist is configured:**

| | |
|---|---|
| `Vary: Origin` | added to **every** response the middleware touches, allowed or not |
| `Access-Control-Allow-Origin` | the **echoed** request origin, and only when it is on the list — never `*`, never a value the request did not present |
| `Access-Control-Allow-Credentials` | ⛔ **never set** |
| `Access-Control-Expose-Headers` | `X-Request-ID`, **`Date`**, `X-Sigil-Entitlement`, `X-Sigil-Entitlement-Status`, `X-Sigil-Entitlement-Grace-Ends` — without this a browser client cannot read its own [grace warning](#warning-headers), nor the server clock its [clock-skew diagnostic](#the-date-header-and-the-client-clock-skew-diagnostic) compares against |
| preflight from an **allowed** origin | **`204`**, with `Access-Control-Allow-Methods` (`GET, HEAD, POST, PUT, DELETE, OPTIONS`), an explicit `Access-Control-Allow-Headers` (`Content-Type, X-Request-ID, X-Sigil-Device, X-Sigil-Timestamp, X-Sigil-Nonce, X-Sigil-Signature, X-Sigil-Enroll-Token, X-Sigil-Admin-Token`) and `Access-Control-Max-Age: 600` |
| preflight from an **unknown** origin | falls through to the mux → `405`, exactly as before — so there is no probe distinguishing *"this route exists"* from *"your origin is allowed"* |
| a preflight the middleware answers | reaches **no handler**: no op-log, no device registry, no rate limiter, no database |

A preflight the middleware answers is still counted, still assigned an
`X-Request-ID` and still access-logged (the middleware sits innermost in the
chain).

⚠️ **Limits.** CORS constrains **browsers and nothing else** — `curl`, the `sigil`
CLI and the desktop app ignore it entirely, and it is **not an access control**.
It does not make the dev transport safe: an allowlisted origin over plain
`http://` is still cleartext. Matching is exact (no wildcards, no subdomain
patterns), so changing the list is a restart, and an origin removed from the list
can still have up to ten minutes of cached preflight in an already-open browser.
No Private Network Access header is sent. **In production, serve the app and the
API from the same origin behind the reverse proxy and set nothing here** — see
[`deployment.md` §18](deployment.md#18-browser-origins--cors-operator-guide--opt-in).

### The `Date` header and the client clock-skew diagnostic

Every response `sigild` produces carries a standard HTTP **`Date`** header (RFC
9110 §6.6.1) — Go's `net/http` stamps it, and nothing here adds, removes or
rewrites it. There is **no time endpoint**, and none is planned: `Date` is already
on the wire on every response, including non-2xx ones.

Clients use it as a **clock reference**. A TOTP code is a function of a secret and
the current time, so a device whose clock has drifted past half a step starts
having codes rejected — and to the user that is indistinguishable from a wrong
secret. Every Sigil client can compare its own clock against the server's and say
which it is: `sigil clock`, the desktop's `clock_skew` command, and the browser
clients' *Check clock* control (all over
[`sigil-wasm/clock-skew.mjs`](../sigil-wasm/clock-skew.mjs) or its Rust twin in
`cli/src/lib.rs`). The reading is normally taken from an unauthenticated
`GET /healthz`, which is never dev-gated and never rate limited, so it works
against a server whose entire stateful surface is still answering `501`.

⚠️ **`Date` is NOT a CORS-safelisted response header**, so a browser on a
different origin reads **`null`** for it unless the server exposes it — measured,
not assumed: with a real Chromium against a real `sigild`, the only readable
headers were `content-length`, `content-type` and `x-request-id`. That is why
`Date` is on the `Access-Control-Expose-Headers` list above. It is exposed only
when an allowlist is configured; **with `SIGILD_CORS_ORIGINS` unset the middleware
is not installed and nothing changes**, and the header itself has always been sent
and has always been readable by `curl`, the CLI and the desktop.

⛔ **This is a client-side DIAGNOSTIC and it is not a security control.** The
server does no clock validation of any kind: it never rejects a request for a
skewed clock on this basis (the ±300 s window on the signed-request contract is a
separate, unrelated mechanism), and it offers no time-sync service. The reading is
an unauthenticated plaintext header over plain HTTP, so anyone who can see the
traffic can change it — a hostile or merely wrong server can make the hint wrong
in either direction. **No key, signature, envelope or generated code depends on
it.** Clients never generate codes against server time — see
[ADR 0050](decisions/0050-confirmations-honest-claims-and-the-clock-diagnostic.md).

---

## Vault operation log (DEV-ONLY)

> **READ THIS FIRST. This endpoint is a development scaffold, not a product.**
>
> - **DEV-GATED, default OFF.** It exists only when the server is started with
>   the environment variable **`SIGILD_ENABLE_DEV_OPS`** set (truthy). With the
>   variable **unset — the default and the only production-safe setting — every
>   verb on this route returns `501 Not Implemented`.** This preserves the
>   project guardrail of stubbing with `501` rather than shipping behaviour that
>   would poison the future audit.
> - **UNAUTHENTICATED BY DEFAULT.** With no auth configured there is no
>   identity and no per-vault access control: anyone who can reach the port can
>   read and append to any vault ID. Two **opt-in** contracts change that —
>   legacy **v2** (`SIGILD_OPLOG_PUBKEY`, one static key, no authorization) and
>   the **v3 multi-device model** (`SIGILD_DEVICE_AUTH` — device identity,
>   per-vault grants, revocation; see
>   [Multi-device auth model](#multi-device-auth-model-contract-v3--dev)). They
>   are mutually exclusive, and both are dev-gated and **UNAUDITED**.
> - **THREE BACKENDS behind the `VaultLog` seam.** With the dev flag on, the
>   op-log is served by one of three interchangeable backends, selected at
>   startup by **precedence `SIGILD_OPLOG_POSTGRES` > `SIGILD_OPLOG_DIR` >
>   in-memory**:
>   - **in-memory (default)** — a process-memory map; **lost on restart**, never
>     written to disk, not replicated.
>   - **file-backed** (**`SIGILD_OPLOG_DIR`**) — persists each vault's journal
>     under that directory for **local-dev durability** (the `vaultID` is
>     base64url-encoded to a safe flat filename, so it cannot escape the
>     directory). A local-dev convenience, still **not** the production store.
>   - **durable Postgres** (**`SIGILD_OPLOG_POSTGRES`** = a libpq DSN) — a real,
>     **durable and concurrent** backend on the `pgx` driver (`sigild`'s first
>     third-party dependency), with per-vault sequencing made concurrency-safe by
>     a transaction / advisory lock. This adds durability and concurrency but is
>     **NOT a finished production store**: it still has no auth model, no
>     enrollment, no CRDT/merge, and no production backup/replication (PITR).
>     (Schema changes _are_ now **managed migrations**, and a **`pg_dump`/restore
>     runbook** whose integrity gate is `/ops/verify` exists — see
>     [`deployment.md` §11](deployment.md#11-schema-migrations-postgres-backend).)
>
>   All three are the **same opaque, dev-only, unauthenticated `VaultLog`** — the
>   server does **no cryptography**, never decodes the bytes, and re-emits them
>   unchanged; the 64 KiB per-op cap and `413` apply to all. See
>   [`decisions/0006-file-backed-dev-op-log-backend.md`](decisions/0006-file-backed-dev-op-log-backend.md)
>   and [`decisions/0014-postgres-durable-oplog-backend.md`](decisions/0014-postgres-durable-oplog-backend.md).
> - **OPAQUE BLOBS ONLY.** The server treats each operation body as an opaque
>   byte string. It does **no cryptography**, never sees plaintext or keys, and
>   does **not** parse, validate, decrypt, order, merge, or otherwise interpret
>   the bytes. Confidentiality is entirely the client's responsibility — the
>   client is expected to encrypt before sending. `sigild` is dumb storage of
>   ciphertext, by design.
> - **NOT a real op log.** "Operation log" here means an append-and-read byte
>   journal with a monotonic per-vault sequence number and a per-op SHA-256
>   **hash chain** for **tamper-evidence** (see
>   [Op-log hash chain](#op-log-hash-chain-tamper-evidence) and `GET …/ops/verify`
>   below). That chain is tamper-*evident*, **not** tamper-*proof*: a hostile
>   server can still lie about it (real verification is client-side). There is
>   still **no** CRDT merge, no Lamport clock, no Merkle root, no signature
>   checking on ops, and no conflict resolution — those are deferred to the
>   production build.
> - **DO NOT EXPOSE PUBLICLY** and **DO NOT STORE REAL SECRETS.**

When `SIGILD_ENABLE_DEV_OPS` is set, the following two operations are served. A
single operation body is capped at **64 KiB**; an oversized request is rejected
with `413` (see [`../sigild/internal/api/middleware.go`](../sigild/internal/api/middleware.go)).

### `POST /v1/vaults/{vaultID}/ops` — append an operation

Append one opaque, client-encrypted blob to the named vault's log.

- **Request body:** raw opaque bytes (the client's ciphertext). The server does
  not require, parse, or impose any structure.
- **Success — `201 Created`:**

  ```json
  { "vaultID": "<vaultID>", "seq": <monotonic per-vault sequence number> }
  ```

  `seq` is assigned by the server, strictly increasing per vault, starting at 1.

- **Errors** (typed `{error, detail}` envelope):

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `empty_op` | the body is empty — **but see the claim precondition below: on an *unowned* vault this is `403`, not `400`** |
  | `413 Request Entity Too Large` | `payload_too_large` | body exceeds the 64 KiB per-operation cap |
  | `429 Too Many Requests` | `rate_limited` | the per-vault append rate limit is exceeded (only when `SIGILD_OPLOG_RATE_LIMIT` is set); the response carries a `Retry-After` header (seconds) |
  | `501 Not Implemented` | `not_implemented` | `SIGILD_ENABLE_DEV_OPS` is unset (the default) |

  Under device auth v3 the usual `401` / `403` / `402` also apply (see
  [`401` vs `403`](#401-vs-403-and-the-absence-of-an-auth-oracle) and
  [Entitlement enforcement](#entitlement-enforcement-opt-in--phase-55)).

  ⭐ **THE CLAIM PRECONDITION — a rejected write never claims a vault
  ([ADR 0045](decisions/0045-claim-precondition-rejected-writes-never-claim.md)).**
  This route is one of the two that take **trust-on-first-write** ownership. The
  claim used to fire inside the authorization step, which runs **before** the
  handler's cheap request-shape checks — so an **empty-bodied** append answered
  `400` and stored nothing while still taking **permanent** ownership of the vault
  id it named. Reproduced live: 50 empty appends across 50 made-up vault ids
  produced 50× `400`, zero stored ops and **50 claims**, after which a second
  device was `403` forever on its own genuine first write. The per-vault rate
  limiter cannot bound that — it keys on the very vault id the attacker varies.
  A well-formedness check is now evaluated **before** the claim, and a request
  that fails it is authorized at a level that cannot claim.
  > ⚠️ **The observable change:** an **empty** append to an **UNOWNED** vault now
  > answers **`403` forbidden** (the caller holds no grant and no longer earns
  > ownership on the way past) instead of `400`. On a vault the caller may already
  > write, it still answers **`400 empty_op`**, unchanged. Ownership is not taken
  > either way.
  >
  > **Honest limit:** this removes the *free* path to a claim, not squatting. A
  > determined device can still squat ids with genuinely well-formed writes, each
  > of which is stored, entitlement-checked and audited. **There is no per-account
  > claim budget.**

  **Optional per-vault rate limit.** By default appends are unthrottled. When
  `sigild` is started with **`SIGILD_OPLOG_RATE_LIMIT`** set (a positive
  sustained rate in appends/second per vault, optionally with
  **`SIGILD_OPLOG_RATE_BURST`** for the bucket depth), each vault gets an independent
  **token-bucket** limiter: appends beyond the vault's refill rate get `429
  rate_limited` with a `Retry-After` header telling the client when a token will
  be available. The limit is **per vault ID** (a busy vault cannot starve
  others), stdlib-only, and **off unless configured** — with the variable unset,
  behaviour is exactly as before. It shapes append *rate* only; it never inspects
  or interprets the opaque blob.

### `GET /v1/vaults/{vaultID}/ops?since=N&limit=M` — read operations

Return the vault's operations with sequence number **greater than `N`** (default
`since=0` returns from the beginning), in ascending `seq` order, **bounded** to at
most `limit` ops per response so a large vault is read in pages rather than one
unbounded slice.

- **Query:**
  - `since` (optional, integer, default `0`) — return ops with `seq > since`.
  - `limit` (optional, integer, default **`500`**, max **`1000`**) — cap the
    number of ops returned by this call. An out-of-range value is **CLAMPED**,
    not rejected: `≤ 0` clamps to `1` and `> 1000` clamps to `1000`, both
    returning `200`. Only a **non-integer** value (e.g. `?limit=abc`) is
    rejected, with `400 bad_limit`.
- **Success — `200 OK`:**

  ```json
  {
    "vaultID": "<vaultID>",
    "ops": [
      { "seq": 1, "blob": "<base64 of the opaque stored bytes>", "hash": "<std-base64 SHA-256 chain hash>" }
    ],
    "next": <highest seq returned, to pass as the next `since`>,
    "has_more": <true if more ops exist beyond this page, else false>
  }
  ```

  `blob` is the standard base64 encoding of the exact opaque bytes that were
  POSTed — the server re-emits ciphertext it never decoded. An unknown vault ID
  returns an empty `ops` array, not an error.

  `hash` is the op's **standard-base64-encoded SHA-256 hash-chain link** — the
  tamper-evidence tip for that op, computed over the previous op's hash and this
  op's `(vaultID, seq, blob)` per the construction in
  [Op-log hash chain](#op-log-hash-chain-tamper-evidence) below. It fingerprints
  **ciphertext only** (the server does no crypto on the plaintext), and it lets a
  client re-derive and verify the chain **itself**, without trusting the server.

  **Pagination.** `has_more` is `true` when the vault holds ops with `seq` beyond
  the page just returned. A client drains the log by looping: request, process the
  page, then re-request with `since = next` until `has_more` is `false`. `next` is
  the highest `seq` in the page (unchanged from `since` when the page is empty), so
  the loop always makes progress and terminates. This bounds both server memory
  and response size regardless of vault length.

- **Errors** (typed `{error, detail}` envelope):

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `bad_limit` | `limit` is non-integer, `≤ 0`, or `> 1000` |
  | `501 Not Implemented` | `not_implemented` | `SIGILD_ENABLE_DEV_OPS` is unset |

### Op-log hash chain (tamper-evidence)

> **Tamper-EVIDENT, not tamper-PROOF, and not a security claim.** This detects
> after-the-fact tampering with the stored ops; it does **not** prevent it and
> does **not** make `sigild` a notarized, append-only-enforced, or
> Byzantine-fault-tolerant log. The **real** guarantee is **client-side**: verify
> the chain yourself from the per-op `hash` values. See the honesty note below.

Every stored op carries a **hash-chain link** so a verifier can detect whether
any op was **inserted, deleted, reordered, or modified**. Each op's hash commits
to the previous op's hash, so altering op *k* changes the hash of *k* and of
**every** op after it. The construction, shared by **all three backends**
(in-memory, file-backed, Postgres), is:

```
hash(seq) = SHA-256(
      "sigil-oplog-chain-v1"     // ASCII domain-separation label
   || len(vaultID) || vaultID    // length-prefixed vault ID (4-byte big-endian length, then bytes)
   || seq                        // 8-byte big-endian sequence number
   || prev_hash                  // previous op's 32-byte hash; genesis = 32 zero bytes
   || blob                       // the opaque client-encrypted bytes, verbatim
)
```

- **Genesis:** for the first op in a vault (`seq = 1`), `prev_hash` is 32 zero
  bytes.
- **Domain separation:** the `"sigil-oplog-chain-v1"` label and the length-prefix
  on `vaultID` make the field boundaries unambiguous, so a chain for one vault
  can never be confused with another and the version can be rotated later.
- **Opaque, zero-knowledge preserved:** the hash is taken over the **already
  client-encrypted** `blob`. Hashing ciphertext fingerprints it for
  tamper-evidence but reveals **no plaintext** and needs **no key** — the server
  still does no cryptography on vault contents. See
  [`threat-model.md`](threat-model.md).

The per-op `hash` is returned inline by `GET …/ops` (above), so a client can
recompute the chain locally and compare.

### `GET /v1/vaults/{vaultID}/ops/verify` — server-side chain check

Recompute a vault's entire hash chain server-side and report whether it is
intact. Same **dev-gate** and (optional) **auth** as the other op-log routes:
`501` when `SIGILD_ENABLE_DEV_OPS` is unset; `401` when `SIGILD_OPLOG_PUBKEY` is
set and the request is missing/invalid/stale/replayed (the signed message uses
the request's own method/path/query, exactly as for `GET …/ops`).

- **Success — `200 OK`:**

  ```json
  {
    "vaultID": "<vaultID>",
    "ok": true,
    "count": <number of ops in the vault>,
    "tip_hash": "<std-base64 SHA-256 of the last op's chain link>",
    "broken_at_seq": null
  }
  ```

  - `ok` — `true` if the recomputed chain matches every stored per-op hash. An
    empty vault is trivially intact (`ok = true`, `count = 0`).
  - `count` — how many ops were checked.
  - `tip_hash` — the last op's std-base64 chain hash (the vault's current tip); an empty
    vault has no ops, so there is no meaningful tip.
  - `broken_at_seq` — `null` when `ok` is `true`; otherwise the **first** `seq`
    whose recomputed hash does not match, i.e. where tamper-evidence tripped.

- **Errors:** `501 Not Implemented` when dev-ops is off; `401 Unauthorized` when
  auth is configured and the request fails it.

**Honesty note — what `/ops/verify` is and is NOT.** A server-side check is a
**convenience**, not a root of trust: a **malicious server can lie** — it can
recompute a perfectly consistent chain over data it has itself doctored, or
simply return `{"ok": true}`. So `/ops/verify` only catches **accidental**
corruption and a **non-adversarial** operator's storage faults. The guarantee
that actually resists a hostile server is **client-side**: the client keeps its
own tip hash and re-derives the chain from the per-op `hash` values in
`GET …/ops`. This is a **dev-scale, tamper-EVIDENT** down-payment on the
product's future **signed / Merkle-root** audit log — not a notarized,
append-only-enforced, or Byzantine-proof log.

### Authentication — contract v2 (LEGACY, optional, dev) — `SIGILD_OPLOG_PUBKEY`

> **SUPERSEDED, BUT STILL PRESENT.** Contract **v2** below is the original
> **single static key** mode. It is unchanged and still supported, but the
> **multi-device model (contract v3)** — [below](#multi-device-auth-model-contract-v3--dev)
> — is the model with device identity, per-vault authorization, and revocation.
> The two are **mutually exclusive**: setting both `SIGILD_DEVICE_AUTH` and
> `SIGILD_OPLOG_PUBKEY` makes `sigild` **refuse to boot** (a fail-fast config
> error before the listener binds), so exactly one contract is ever live.

> **DEV-ONLY, off by default, and intentionally minimal.** This is a
> **single static device key** check, not an account/enrollment system. Each
> request is signed with a **fresh per-request nonce**, and the server keeps a
> **time-bounded, in-memory seen-nonce cache**, so a captured request cannot be
> replayed within the 300-second timestamp window (**contract v2** — it
> **supersedes v1**). That cache is **per-process**; a multi-instance deployment
> would need a shared nonce store (e.g. Redis). Full device enrollment, a
> multi-device registry, and JWT bearer tokens (see
> [`../sigild/internal/auth/`](../sigild/internal/auth/)) remain **future**. Still
> plain-HTTP, dev-gated, and not for real secrets. See
> [`decisions/0008-device-key-request-auth.md`](decisions/0008-device-key-request-auth.md)
> and [`decisions/0010-op-log-auth-v2-nonce-replay.md`](decisions/0010-op-log-auth-v2-nonce-replay.md).

By default the dev op-log is **unauthenticated** (above). When `sigild` is
started — with dev-ops on — **and** the environment variable
**`SIGILD_OPLOG_PUBKEY`** is set to the **standard-base64 encoding of a 32-byte
Ed25519 public key**, the op-log additionally requires a per-request Ed25519
signature. With `SIGILD_OPLOG_PUBKEY` **unset (the default), there is no auth**
and behaviour is exactly as described above.

When configured, **both** `POST` and `GET /v1/vaults/{vaultID}/ops` requests
**MUST** carry three headers:

| Header | Value |
|--------|-------|
| `X-Sigil-Timestamp` | the signing timestamp, unix **seconds**, decimal ASCII (e.g. `1717900000`) |
| `X-Sigil-Nonce` | standard-base64 of a **fresh, per-request** random nonce of **≥ 16 bytes** from a CSPRNG; the exact header string is signed **verbatim** so both sides agree |
| `X-Sigil-Signature` | standard-base64 of the 64-byte Ed25519 signature over the message below |

The signed **message** (raw bytes) is a fixed 6-line ASCII prefix —
lines joined by a single `\n` (`0x0A`), **with a trailing `\n` after the
nonce** — immediately followed by the raw request **body** bytes:

```
sigil-oplog-auth-v2\n
{METHOD}\n          uppercase HTTP method — "POST" or "GET"
{PATH}\n            URL path, NO query — e.g. /v1/vaults/demo/ops
{QUERY}\n           raw query string, or "" if none — e.g. since=0
{TIMESTAMP}\n       same decimal value sent in X-Sigil-Timestamp
{NONCE}\n           EXACT X-Sigil-Nonce header string (base64 text, verbatim)
{BODY}              raw request body bytes; EMPTY for GET
```

That is, byte-for-byte:

```
MESSAGE = "sigil-oplog-auth-v2\n" + METHOD + "\n" + PATH + "\n" + QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + BODY
```

The client generates a fresh random `NONCE` (**≥ 16 CSPRNG bytes**,
standard-base64), sends it as `X-Sigil-Nonce`, signs `MESSAGE` with its 32-byte
Ed25519 secret seed (the demo `cli` uses `sigil_core::{sign,
public_key_from_seed}`), and sends the signature in `X-Sigil-Signature` and the
same timestamp in `X-Sigil-Timestamp`. This is **contract v2**; it **supersedes
v1** — a v1 message (which had no nonce line) no longer verifies, and there are
no external v1 clients to break, so it is a clean break.

The server, when `SIGILD_OPLOG_PUBKEY` is configured, verifies on both verbs, in
**this order**:

1. read `X-Sigil-Timestamp`, `X-Sigil-Nonce`, and `X-Sigil-Signature`; any
   missing or blank → `401`.
2. parse the timestamp as `int64`; if it is not an integer **or** the skew
   `abs(now - ts)` exceeds **300 seconds** → `401` (stale/skew).
3. reconstruct the v2 `MESSAGE` from the request method, path, raw query, the
   timestamp header, the **raw nonce header**, and the (size-limited) body;
   base64-decode the signature and `ed25519.Verify(pubkey, MESSAGE, sig)`; if it
   does not verify → `401`.
4. **replay check** — done **only after** a valid signature, so unauthenticated
   probes never touch the cache: if this nonce is already in the server's
   seen-nonce cache (and not yet expired) → `401` (replayed request); otherwise
   **record** the nonce with its timestamp and fall through to the normal
   append/read handler above.

The **seen-nonce cache** is in-memory, concurrency-safe, and **time-bounded**:
an entry is evicted once its timestamp is older than `now - 300s` — a nonce is
remembered for exactly as long as a request bearing it could still pass the
timestamp check (step 2) — with a hard size cap as a safety backstop. It is
therefore a **per-process** guard: a multi-instance deployment would need a
shared nonce store (e.g. Redis). A given nonce is thus accepted **at most once**
within the timestamp window.

All failures use the standard typed envelope with `401 Unauthorized` (a distinct
`detail` marks a replayed nonce; the `error` code stays `unauthorized`):

```json
{ "error": "unauthorized", "detail": "<reason>" }
```

The matching CLI key file (`sigil keygen --out <file>`) is JSON, written with
mode `0600`:

```json
{ "version": 1, "seed": "<std-base64 of 32 bytes>", "public_key": "<std-base64 of 32 bytes>" }
```

The same file is also the **device identity** file for contract v3: `sigil
device enroll` adds an **optional `"device_id"`** field to it. The field is
absent here by construction, and a key file **without** it keeps signing v2
exactly as before — see [Client support](#client-support-the-sigil-cli).

**Honest scope:** a single configured DEV device key; the seen-nonce replay
cache is **in-memory / per-process** (a multi-instance production deploy needs a
shared store); multi-device enrollment and a device registry exist only in
**contract v3** ([below](#multi-device-auth-model-contract-v3--dev)), never in
this mode, and JWT / session issuance is still future; and with
`SIGILD_OPLOG_PUBKEY` unset there is no auth at all.

### Audit log (structured server-side events)

Every op-log **append**, **list**, **verify**, and **auth denial** — plus every
device **enrollment**, **enrollment denial**, **revocation**, **vault ownership
claim**, and **grant** — emits a **structured audit event** to the server log
(alongside the request-scoped access log). Each event carries only **metadata
plus an integrity fingerprint** — never the payload:

| Field | Meaning |
|-------|---------|
| `event` | the audited action — `oplog.append`, `oplog.list`, `oplog.verify`, `oplog.auth_denied`, `device.enrolled`, `device.enroll_denied`, `device.revoked`, `vault.claimed`, `vault.granted` |
| `request_id` | the request's `X-Request-ID`, to correlate with the access log |
| `vault_id` | the target vault ID (opaque, client-chosen) |
| `seq` | the sequence number assigned (append) or the highest returned (list) |
| `size_bytes` | the opaque blob's length in bytes |
| `blob_sha256` | hex **SHA-256 fingerprint** of the opaque stored bytes — for integrity / traceability only |
| `auth` | on an append, which contract was active: `device` (v3), `ed25519` (legacy v2), or `none` |
| `reason` | on a denial, the fixed enum naming the single check that failed (see [the reason enum](#denial-reasons-audit--metrics-only)) |
| `device_id` | on the device events and on a denial, the device ID the client **presented** (empty in the legacy/no-auth modes; recorded even when it resolved to nothing, so probing is visible) |
| `label` / `permission` / `revoked_by` | the enrolled device's label; the permission granted; who performed a revocation (`admin`, or the device's own ID for self-revocation) |

The server logs a **fingerprint** of the ciphertext, **not** the ciphertext: it
**NEVER** writes the opaque blob content, any signature, nonce, timestamp value,
public key, enrollment token (or its digest), admin token, or other key material
to the log. Because the fingerprint is taken over bytes that are **already
client-encrypted**, an operator can prove *who appended what, when* without the
server ever seeing plaintext — the audit trail does not weaken the
zero-knowledge property (see [`threat-model.md`](threat-model.md)).

Request bodies are read under the **request context**: a client that
disconnects, or a read that exceeds the server's `http.Server` timeouts, cancels
the in-flight append/read (and, for the Postgres backend, releases the pooled
connection) rather than blocking a goroutine.

---

## Multi-device auth model (contract v3) — DEV

> **DEV-GATED, OPT-IN, and UNAUDITED.** This is a **real** auth model — real
> `crypto/ed25519` verification against a real device registry, real per-vault
> authorization, real revocation, no bypass path, no fallback "trusted" key, and
> no hardcoded credential — but it is **dev-gated** behind
> `SIGILD_ENABLE_DEV_OPS`, **off by default**, has **not been audited**, and is
> **not** the product's account/session model. There is no user account, no
> session or token issuance, no key rotation and no hardware attestation. Since
> Phase 54 there **is** a **recovery kit** — but it is a paper key printed in
> advance ([below](#recovery-kits-dev-gated--phase-54)), **not** an identity or
> reset mechanism. Enrollment can now be **rate limited** (opt-in,
> [below](#abuse-rate-limiting-enrollment--invite-minting)) — read that section's
> two caveats before treating it as a defence. Still plain
> HTTP in dev. **Do not expose publicly and do not store real secrets.** See
> [`decisions/0031-multi-device-auth-model.md`](decisions/0031-multi-device-auth-model.md).

Contract **v3** replaces v2's one static key with a **device registry**: every
authenticated request names **which** enrolled device signed it, the server
verifies the signature against **that device's** registered Ed25519 public key,
refuses a **revoked** device, and then checks that the device holds a **grant**
on the requested vault.

### Configuration

| Variable | Required? | Meaning |
|----------|-----------|---------|
| `SIGILD_DEVICE_AUTH` | opt-in | `1`/`true` turns on the v3 model. **Requires `SIGILD_ENABLE_DEV_OPS`** (the op-log and its auth model are dev-gated) and is **MUTUALLY EXCLUSIVE with `SIGILD_OPLOG_PUBKEY`** — with both set, `sigild` **exits non-zero at startup** rather than running an ambiguous model. |
| `SIGILD_ENROLL_TOKENS` | **required when device auth is on** | Comma-separated operator-provisioned enrollment tokens (bootstrap bearer secrets). Each must be **≥ 16 characters**; duplicates are rejected. Only their **SHA-256 digests** ever reach the server's memory, the registry, the audit log, or `/metrics` — the plaintext is never stored. Without at least one token, **no device can ever enroll**. |
| `SIGILD_ENROLL_TOKEN_TTL` | optional | A **positive Go duration** (e.g. `24h`). A token then expires that long after it was **first registered** — registration is idempotent, so restarts do not extend the clock. **Unset ⇒ tokens never expire, but remain SINGLE-USE.** |
| `SIGILD_ADMIN_TOKEN` | optional | Operator token for the operator-only routes (list all devices, revoke **any** device); **≥ 16 characters**. **Unset ⇒ those paths are permanently `401`** — there is **no implicit open-admin mode**. Compared in constant time; never logged or exported. |
| `SIGILD_ACCOUNT_MAX_DEVICES` | optional | Member devices per account. Default **10**, range `[1, 1000]`. Counts **ACTIVE devices only** — a revoked device frees its seat. Anti-freeloading, **not** anti-fraud. |
| `SIGILD_ACCOUNT_MAX_INVITES` | optional | **Open** (unused, unexpired, unrevoked) invites per account. Default **5**, range `[1, 100]`. It bounds stored **state**, not request volume; request volume is the separate, opt-in `SIGILD_INVITE_RATE_LIMIT` below. |
| `SIGILD_ACCOUNT_INVITE_TTL` | optional | Go duration; how long a freshly minted invite stays redeemable. Default **15m**, must be `> 0` and `<= 24h`. A client may request a **shorter** life, never a longer one. |
| `SIGILD_ENROLL_RATE_LIMIT` / `SIGILD_ENROLL_RATE_BURST` | optional | **Failed**-enrollment token bucket, keyed on the **socket peer address**. Unset ⇒ **no limiter installed**. See [Abuse rate limiting](#abuse-rate-limiting-enrollment--invite-minting) — and read its caveats, because it is a **backstop, not a defence**. |
| `SIGILD_INVITE_RATE_LIMIT` / `SIGILD_INVITE_RATE_BURST` | optional | Invite-minting token bucket, keyed **per account** (not per device). Unset ⇒ no limiter installed. |

All eleven are parsed and validated **fail-fast, before the listener binds**; a
malformed value is a clear startup error, not a surprise at request time. An
account value **outside its range is an error, never a silent clamp**.

⚠️ The four rate-limit variables deliberately **do not require**
`SIGILD_ENABLE_DEV_OPS` or `SIGILD_DEVICE_AUTH`, unlike the `SIGILD_ACCOUNT_*`
settings. Those change *who owns a vault*, so a silently-ignored value there
would be an ownership surprise; a rate limit is purely protective, and refusing
to boot because a protective knob is currently moot is the worse failure. Setting
one without the dev gate is a **boot WARNING** naming that nothing is being
limited, not an error.

> **There is deliberately no `SIGILD_ACCOUNTS` switch.** The account model
> ([below](#account-model-dev-gated--phase-52)) rides `SIGILD_DEVICE_AUTH`,
> because a binary that could run either ownership model would hold **two
> ownership truths at once**. Setting any `SIGILD_ACCOUNT_*` variable **without**
> `SIGILD_DEVICE_AUTH` is a **boot error** — a knob that silently does nothing is
> worse than a refusal.

**Registry durability.** When the Postgres op-log backend
(`SIGILD_OPLOG_POSTGRES`) is active, the registry is durable and **shares that
backend's existing `pgxpool`** (no second pool, no new dependency), using tables
from migration `0002_devices.sql`; Postgres then enforces single-use tokens and
single-owner vault claims **across processes**. Otherwise the registry is
**in-memory and non-durable** — devices, grants and spent-token markers are lost
on restart, which means a **spent enrollment token becomes reusable after a
restart** (the server warns loudly at boot). The **file backend
(`SIGILD_OPLOG_DIR`) was not extended**: device auth alongside it falls back to
the in-memory registry, also warned at boot.

### Abuse rate limiting (enrollment + invite minting)

Added in **Phase 53** ([ADR 0041](decisions/0041-abuse-bounds-and-the-removed-webhook-limiter.md)),
**off by default**. Two stdlib token buckets — no new dependency; `sigild` still
has exactly one direct Go dependency:

| Route | Key | Charged when | Env |
|-------|-----|--------------|-----|
| `POST /v1/devices/enroll` | the **socket peer address** (IPv4 full address; IPv6 **/64 prefix**; an unparseable address shares one bucket) | ⭐ **only when the attempt FAILS** | `SIGILD_ENROLL_RATE_LIMIT` / `_BURST` |
| `POST /v1/account/invites` | the caller's **account id** (siblings share one bucket) | on every mint | `SIGILD_INVITE_RATE_LIMIT` / `_BURST` |

Over-rate is the **same** `429` contract the per-vault op-log limiter uses:

```json
{ "error": "rate_limited", "detail": "too many failed enrollment attempts from this source address" }
{ "error": "rate_limited", "detail": "too many invites minted by this account" }
```

with a `Retry-After` header in whole seconds (`ceil(1 / rate)`, minimum 1, fixed
per limiter). ⚠️ The `detail` names the **surface, never the key** — it must not
tell a caller which address bucket, which account, or which peer it collided
with. The limiter is installed **only on the live route**; the dev-gated `501`
stub is never limited, or the limiter itself would become a probe for whether the
feature is on.

**Two properties that matter as much as the feature, both proven live:**

- ⚠️ **This is a BACKSTOP, not a defence.** The only deployment topology this repo
  documents is a **reverse proxy**, so every request reaches `sigild` from one
  address and the enrollment limiter degrades to a **single global bucket**.
  `X-Forwarded-For` is deliberately **not** consulted (without a trusted-proxy
  configuration it is attacker-supplied text, and keying on it would let one
  client mint unlimited buckets). An earlier revision rejected *before* the
  handler and was reproduced **refusing a legitimate customer holding a valid,
  unspent operator token** — a global account-creation off switch. Two changes
  fixed it: the bucket is charged **only on the denial path**, so **a request
  carrying a valid, unspent credential and a valid proof of possession can never
  be refused by it**; and the limiter now **fails open at its key cap** instead of
  closed (the old branch let one IPv6 /48 fill 10,000 buckets and lock out
  everyone else). **Real per-source limiting belongs at the edge.**
- ⚠️ **It does not reduce load.** Charging only on the denial path means the
  handler **always runs**, including its database work; the limiter replaces only
  the **response**. It bounds how useful flooding is, not what it costs the
  server.

Observability: `sigild_abuse_ratelimit_rejected_total{surface}` over the closed
set `{enroll, invite}`, and the audit event `abuse.rate_limited`
(`request_id`, `surface`, `subject`). ⚠️ **The source address is deliberately not
logged**, and `subject` is **empty** on the enrollment surface (it is the account
id on the invite surface): this server holds no personal data anywhere, an IP
address is personal data in most regimes, and it would not change what an
operator does — the proxy or firewall that would act already has the address.

⛔ **`POST /v1/billing/webhook/{provider}` is deliberately NOT rate limited**, and
`SIGILD_WEBHOOK_RATE_LIMIT` / `_BURST` **no longer exist** (setting either now
logs a boot WARNING). See [Billing → honest limits](#honest-limits-read-before-believing-any-of-the-above-1).

### Storage (migration `0002_devices.sql`)

Three tables are added on top of the untouched `0001_init`:

| Table | Holds |
|-------|-------|
| `sigil_devices` | `device_id` (PK), `public_key` (`bytea`, **UNIQUE** — a key identifies at most one device), `label`, `status`, `created_at`, `revoked_at`, and — since `0005_accounts.sql` — a **nullable** `account_id` |
| `sigil_enrollment_tokens` | `token_hash` (PK, the SHA-256 **hex digest** — never the token), `issued_at`, `expires_at`, `used_at` (the single-use marker), `used_by` |
| `sigil_device_grants` | `(vault_id, device_id)` (PK), `permission`, `is_owner`, `created_at`; a **partial `UNIQUE` index `sigil_device_grants_one_owner (vault_id) WHERE is_owner`** makes the ownership claim atomic in the database |

The migration is **pure DDL over auth metadata**: Ed25519 **public** keys,
server-assigned IDs, labels, permissions, timestamps. It touches **nothing** in
`sigil_vault_ops` — the opaque blob, its per-op hash chain, and the
zero-knowledge boundary are **unaffected**. `sigild_schema_version` reports **2**
once applied (**3** once `0003_billing.sql` is applied — see
[Billing](#billing--subscriptions-dev-gated-opt-in--phase-45) — **4** once
`0004_key_sharing.sql` is applied, see
[Vault sharing](#device-to-device-vault-sharing-dev-gated-opt-in--phase-46) —
and **5** once `0005_accounts.sql` is applied, see
[Account model](#storage-migration-0005_accountssql)).

### Signed request contract (v3)

Every authenticated request carries **four** headers:

| Header | Value |
|--------|-------|
| `X-Sigil-Device` | the server-assigned device ID returned at enrollment (`dev_` + raw-URL-base64 of 16 random bytes) |
| `X-Sigil-Timestamp` | signing time, unix **seconds**, decimal ASCII |
| `X-Sigil-Nonce` | standard-base64 of a **fresh, per-request** CSPRNG nonce (≥ 16 bytes); signed **verbatim** as the exact header text |
| `X-Sigil-Signature` | standard-base64 of the 64-byte Ed25519 signature over the message below |

The signed **message** is, byte-for-byte:

```
MESSAGE = "sigil-oplog-auth-v3\n" + DEVICE_ID + "\n" + METHOD + "\n" + PATH + "\n" + QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + BODY
```

```
sigil-oplog-auth-v3\n
{DEVICE_ID}\n       EXACT X-Sigil-Device header text
{METHOD}\n          uppercase HTTP method
{PATH}\n            URL path, NO query — e.g. /v1/vaults/demo/ops
{QUERY}\n           raw query string, or "" if none
{TIMESTAMP}\n       same decimal value sent in X-Sigil-Timestamp
{NONCE}\n           EXACT X-Sigil-Nonce header text (base64 text, verbatim)
{BODY}              raw request body bytes; EMPTY for GET
```

**v3 is a clean break from v2.** The domain line changed (`…-v2` → `…-v3`) *and*
a device-ID segment was inserted, so a **v2 signature does not verify under v3**
(`401`) — captured v2 traffic cannot be replayed into the device model.

**Verification order** maps 1:1 to the audited reason:

1. all four headers present → else `missing_headers`
2. timestamp parses as `int64` → else `bad_timestamp`
3. `abs(now - ts) ≤ 300 s` → else `stale_timestamp`
4. `X-Sigil-Device` resolves in the registry → else `unknown_device`
5. the device is **not revoked** → else `revoked_device`
6. the signature verifies under **that device's registered public key** → else
   `bad_signature`
7. the nonce has not been seen in-window → else `replayed`

Two orderings are load-bearing and deliberate:

- **Revocation (5) is checked BEFORE signature verification (6)**, so a revoked
  device is refused on its **very next request** no matter how well it signs.
- **The nonce is recorded ONLY after a valid signature (6)**, so unauthenticated
  probes can neither populate nor probe the replay cache.

The replay cache is the same time-bounded, concurrency-safe, **per-process
in-memory** cache as v2: an entry is remembered for exactly as long as a request
bearing it could still pass the 300 s window, with a hard size cap as a
backstop. **A multi-instance deployment needs a shared store (e.g. Redis)**;
device request nonces share one namespace (enrollment nonces are
prefix-separated).

### Authorization: account ownership + per-vault grants (trust-on-first-write)

Ownership belongs to an **account** and a grant maps `(vaultID, deviceID) ->
permission`, where `permission` is `read` or `write` and **`write` implies
`read`**. Each route declares what it needs:

| Route | Needs |
|-------|-------|
| `POST /v1/vaults/{vaultID}/ops` | **write** |
| `GET /v1/vaults/{vaultID}/ops` | read |
| `GET /v1/vaults/{vaultID}/ops/verify` | read |
| `POST /v1/vaults/{vaultID}/grants` | **owner** |
| `GET /v1/vaults/{vaultID}/grants` | read |
| `PUT /v1/vaults/{vaultID}/keys/{deviceID}` | **write** (a first deposit **claims** an unowned vault, exactly like a first append) |
| `GET /v1/vaults/{vaultID}/keys/{deviceID}` | read **and** being the addressee |
| `GET /v1/vaults/{vaultID}/keys` | **write** (rotation support; metadata only) |
| `DELETE /v1/vaults/{vaultID}/keys/{deviceID}` | **write** (rotation support) |
| `GET /v1/devices/{deviceID}/keys` | **being that device** (self-only), then **read** per listed vault — unauthorized vaults are silently filtered, not an error |

**Ownership is TRUST ON FIRST WRITE — by ACCOUNT (Phase 52).** A vault with no
owner is claimed by the **first account that successfully authenticates a WRITE**
to it. The claim is **atomic** in both backends (a mutex in memory; the
`sigil_vault_owners` **PRIMARY KEY** in Postgres), so exactly one of N concurrent
first-writers wins — and a loser belonging to the **winning account** is allowed
through, because two siblings racing a legitimate first write must both succeed.
**Reads and `GET`/`DELETE …/keys` never claim** — reading an unowned vault is
`403`.

Three rules follow, and they are the whole authorization model:

1. **Every device of the owning account has full access to that vault, with no
   grant row of its own.** This is the fix for the orphaning defect: revoking the
   device that happened to claim a vault no longer strands it.
2. **Ownership (`needOwner`) is satisfied ONLY by account ownership.** A legacy
   `is_owner` grant row **never** satisfies it, so data drift cannot hand
   ownership powers to a non-owning account.
3. **A cross-account share is still a per-DEVICE grant.** Key envelopes are
   addressed to a *device's* hybrid identity, so an account-wide grant would
   authorize devices holding no envelope — authorization and knowledge would
   drift apart.

The `is_owner` flag on `sigil_device_grants` is **retained as the per-device VIEW**
of the same fact (so `GET …/grants` stays byte-identical for existing data and
existing clients), but **no authorization decision reads it**.

> **Honest limitation.** Trust-on-first-write **did not go away — it moved up one
> level.** An attacker who writes to an **unclaimed**, high-entropy vault ID
> first becomes its owning account and locks the real owner out with a `403`.
> Ownership **never moves between accounts** (no transfer, merge or split), and
> while revoking one device no longer orphans a vault, **losing or revoking every
> device in an account does** — permanently, unless a **recovery kit was printed
> in advance** ([below](#recovery-kits-dev-gated--phase-54)); there is no other
> recovery (see [Account model → honest limits](#account-model--honest-limits)).

### `401` vs `403`, and the absence of an auth oracle

- **`401 Unauthorized`** — *unauthenticated*: the request did not prove it came
  from a known, active device (missing/stale/bad signature, unknown device,
  revoked device, replayed nonce, bad admin token).
- **`403 Forbidden`** — *authenticated, but not authorized*: a valid device
  signature, but no sufficient grant on the vault (`unauthorized_vault`), the
  vault belongs to another account (`forbidden_account`), not the vault's owning
  account (`not_vault_owner`), acting on another account's device
  (`forbidden_device`), **the signing device carries no account at all**
  (`missing_account`), or **the vault's only ownership record is a legacy owner
  grant whose device resolves to no account** (`vault_owner_unresolved`).
- **`500`** — the registry itself could not be read/written
  (`store_unavailable`), returned as `500` **specifically so an infrastructure
  fault is never mistaken for a credential verdict**.

> **Only a genuine FAULT is a `500`.** `missing_account` and
> `vault_owner_unresolved` are **data states the server can read plainly** — both
> are produced by a **pre-0005 binary** writing to an already-migrated database
> (a rolling deploy or a rollback window) — so they are **refusals, not
> malfunctions**, and answer `403`. They still **fail closed**: such a device is
> refused everywhere and the server **never falls back to the device ID**, which
> would silently resurrect the model the account replaced. The client body is
> **byte-identical to every other `403`**, so no oracle appears; the typed reason
> reaches only the audit log and the already-closed metric label set. The repair
> is **`sigild migrate adopt`** (see
> [`deployment.md` §11](deployment.md#11-schema-migrations-postgres-backend)).
>
> ⚠️ **The comment at `sigild/internal/store/migrations/0005_accounts.sql:42` is
> STALE.** It says a NULL account "FAILS CLOSED (`missing_account` -> 500)". The
> behaviour is **`403`**, as documented here. That file is an **applied
> migration** and must not be edited — changing an applied migration's bytes is
> worse than a stale comment — so **this reference is the authority**.

The **response body is coarse on purpose**:

```json
{ "error": "unauthorized", "detail": "missing or invalid request signature" }
{ "error": "forbidden",    "detail": "device is not authorized for this vault" }
```

A prober therefore learns only the status class. The precise cause is a fixed
enum that goes **ONLY** to the audit log and the per-reason metric — there is
**no auth oracle** in the response.

#### Denial reasons (audit + metrics only)

`missing_headers`, `bad_timestamp`, `stale_timestamp`, `bad_signature`,
`replayed`, `unknown_device`, `revoked_device`, `unauthorized_vault`,
`not_vault_owner`, `forbidden_device`, `bad_admin_token`, `store_unavailable`,
plus the account-model reasons `missing_account`, `forbidden_account` and
`vault_owner_unresolved`;
and for enrollment: `bad_enrollment_token`, `enrollment_token_used`,
`enrollment_token_expired`, `bad_proof`, `malformed_key`, `device_exists`,
`account_full`.

> ⭐ **`forbidden_account` reaches the AUDIT LOG only — on `/metrics` it is
> collapsed onto `unauthorized_vault`.** The two are byte-identical from a client
> (the same `403`, the same `{"error":"forbidden"}`), but the metric distinguished
> them: `forbidden_account` means the vault **exists and belongs to another
> account**, `unauthorized_vault` covers a vault that has **never existed**. So
> scraping the always-on, unauthenticated `/metrics` before and after one request
> answered *"does this vault id exist?"* — a **vault-existence oracle**, and
> exactly the widening [ADR 0040](decisions/0040-account-model.md) limitation 11
> says this model deliberately does not do. The enrollment side was already
> collapsed for this reason; the auth-deny side was missed. The rule:
> **`/metrics` must never distinguish two outcomes the client is told nothing
> apart about.**
>
> Deliberately **not** collapsed: `not_vault_owner` and `forbidden_device`
> describe the caller's own relationship to a resource it **already reached**, so
> they signal no existence the caller did not already hold; and
> `vault_owner_unresolved` names a server-side **data-repair** state an operator
> must be able to see (§ `sigild migrate adopt`). This is a **narrowing, not a
> closure** — `/metrics` remains a weak correlatable oracle, as
> [ADR 0040](decisions/0040-account-model.md) limitation 11 already said.

Account-**invite** failures carry a second, **finer** cause that goes to the
**audit log only** — never a response body, never a metric label:
`invite_unknown`, `invite_revoked`, `inviter_inactive`, `invite_used`,
`invite_expired`, `invite_key_mismatch`, `account_full`, `device_exists`,
`store_unavailable`. From a client, an unknown / used / expired / revoked invite
and a revoked inviter are **indistinguishable**.

### `POST /v1/devices/enroll` — enroll a device

Registers a device's Ed25519 public key and returns its **server-assigned**
device ID (clients never choose their own ID, so an ID cannot be squatted).

**Two independent factors, both mandatory:**

1. a **credential** in `X-Sigil-Enroll-Token` — either an operator-provisioned
   **enrollment token** (matched in **constant time** against the configured
   digests and then **spent atomically**; **single-use**) **or, since Phase 52,
   an account INVITE** (see [Account model](#account-model-dev-gated--phase-52));
2. **proof of possession** — an Ed25519 signature in `X-Sigil-Signature` over the
   canonical enrollment challenge, verified against the **public key being
   submitted**. A bare public-key upload is **never** accepted.

> ⭐ **AN INVITE IS PRESENTED IN THE EXISTING HEADER, UNDER THE EXISTING
> CHALLENGE.** Nothing about the wire changed to make joining work — no new
> header, no new signed-message domain, **no fourth canonical message to keep
> byte-identical across Go/Rust/JS** — because the challenge below already binds
> the credential's **SHA-256 digest**, and the digest already binds *which*
> credential is in play. **Today's shipped clients can already join an account:**
> `sigil device enroll --token <invite>`, or pasting the invite into the webapp's
> or extension's existing enrollment-token field.
>
> **Which one it is, is decided at the atomic write, not on the unauthenticated
> path.** The server checks only whether the presented digest matches a
> configured **operator** token — with **no early return** and **no invite
> lookup**, which would be a database round trip on the unauthenticated path and
> a timing side channel on invite-hash existence. The proof and nonce checks are
> byte-identical to Phase 41. Then:
>
> - an **operator token always founds a NEW account** (there is no operator route
>   that inserts a device into an existing account); and
> - **anything else is resolved as an INVITE**, which always **joins the
>   inviter's** account and never founds one.
>
> **Invites are single-SUCCESS; operator tokens stay single-ATTEMPT.** Redemption
> and the device insert are **one** operation, so N concurrent redemptions create
> exactly one device and a failed insert leaves the invite usable.

The enrollment challenge uses a **different domain** from the request contract,
so a proof can never be repurposed as an op-log request signature (or the
reverse):

```
CHALLENGE = "sigil-device-enroll-v1\n" + TOKEN_SHA256_HEX + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + PUBLIC_KEY_B64 + "\n" + LABEL
```

`TOKEN_SHA256_HEX` is the lowercase hex SHA-256 of the presented token;
`PUBLIC_KEY_B64` and `LABEL` are the **exact strings from the JSON body**, so
both sides sign the same bytes with no re-encoding ambiguity. Binding the token
digest means a captured proof cannot be re-presented with a **different** token;
binding the public key means an interceptor cannot swap in **its own** key while
reusing a victim's token.

The v2/v3 replay protections apply: the same **300 s** timestamp window and a
fresh `X-Sigil-Nonce` checked against the shared replay cache (enrollment nonces
are prefix-namespaced so they cannot collide with request nonces), and the nonce
is recorded **only after a valid proof**.

- **Headers:** `X-Sigil-Enroll-Token`, `X-Sigil-Timestamp`, `X-Sigil-Nonce`,
  `X-Sigil-Signature` (the proof). No `X-Sigil-Device` — the device does not
  exist yet.
- **Request body** (JSON, capped at **8 KiB**):

  ```json
  { "public_key": "<standard-base64 of a raw 32-byte Ed25519 public key>", "label": "<human name, ≤ 128 chars>" }
  ```

- **Success — `201 Created`:**

  ```json
  { "device_id": "dev_<raw-url-base64>", "account_id": "acct_<raw-url-base64>", "label": "laptop", "status": "active", "created_at": "<RFC3339>" }
  ```

  (`revoked_at` is present only once the device is revoked.) The response
  deliberately **omits the public key** — the client already has it, and the
  registry never echoes key material out of an endpoint that does not need to.
  **`account_id` is ADDITIVE** (Phase 52): it names the account the device landed
  in — a **new** one for an operator token, the **inviter's** for an invite — and
  is **omitted when empty**, so a device row written by a rolled-back pre-0005
  binary renders the shape it always did. Existing clients ignore it.

- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `invalid_request` | body unreadable / over 8 KiB, not a JSON object, or `label` too long |
  | `400 Bad Request` | `invalid_request` | `public_key` is not the standard-base64 of a **32-byte** Ed25519 public key (`malformed_key`) |
  | `401 Unauthorized` | `unauthorized` | missing headers, stale timestamp, unknown/spent/expired token, an unknown/used/expired/revoked **invite**, a revoked inviter, a **pinned-invite key mismatch**, bad proof, or a replayed nonce — **all return the same body**, so a prober cannot distinguish them |
  | `409 Conflict` | `device_exists` | that public key is already enrolled |
  | `409 Conflict` | `account_full` | the invite resolved, but the target account is at `SIGILD_ACCOUNT_MAX_DEVICES` **active** devices. Reachable **only after** a credential and a valid proof have been accepted — exactly like `device_exists` — so the distinct status leaks nothing the caller did not already hold |
  | `429 Too Many Requests` | `rate_limited` | only when `SIGILD_ENROLL_RATE_LIMIT` is set, and only ever **replacing a failed attempt's response** — a `2xx` is never rate limited (see [Abuse rate limiting](#abuse-rate-limiting-enrollment--invite-minting)). Carries `Retry-After` |
  | `500` | `internal` | the registry could not be read/written |
  | `501 Not Implemented` | `not_implemented` | dev-ops off, or no registry configured |

> **Honest limitation — single-ATTEMPT, not single-SUCCESS.** The token is spent
> **before** the device row is created, so an enrollment that then conflicts on a
> duplicate key still **burns the token**. That is deliberately fail-closed (the
> server never silently permits a retry), but an operator must issue a **new**
> token after such a failure. Enrollment **can** now be rate limited
> ([above](#abuse-rate-limiting-enrollment--invite-minting)), but only failures
> are charged and behind a reverse proxy it is one global bucket — a **backstop,
> not a defence**.
>
> **Account INVITES are different, on purpose: they are single-SUCCESS.** An
> operator can re-mint a token from a shell; a customer mid-flow on a phone
> cannot. Redemption and the device insert are one atomic operation, so a failed
> insert leaves the invite usable.

### `GET /v1/devices` — list devices (operator)

Requires the **operator admin token** in `X-Sigil-Admin-Token`. With
`SIGILD_ADMIN_TOKEN` unset the route is **permanently `401`** — there is no
implicit open-admin mode. Public keys are **not** included.

- **Success — `200 OK`:**

  ```json
  { "devices": [ { "device_id": "dev_…", "account_id": "acct_…", "label": "laptop", "status": "active|revoked", "created_at": "<RFC3339>", "revoked_at": "<RFC3339, omitted when active>" } ] }
  ```

  (`account_id` is additive and omitted when empty — see the enrollment response.)

- **Errors:** `401 unauthorized` (missing/incorrect admin token, audited as
  `bad_admin_token`); `500 internal`; `501 not_implemented` when the model is off.

### `POST /v1/devices/{deviceID}/revoke` — revoke a device

A revoked device is rejected on its **very next request** (status is checked
before its signature is verified). Revocation is **idempotent**: revoking an
already-revoked device succeeds and keeps the original `revoked_at`. The device
row is **retained**, never deleted, so the audit trail stays explainable.

**Three authorized paths, none a bypass:**

- the **operator admin token** (`X-Sigil-Admin-Token`) — may revoke **any**
  device; this is the break-glass path for a lost/stolen device;
- **self-revocation** — a valid **v3-signed** request whose signing device **is**
  the device named in the path; or
- **sibling revocation (Phase 52)** — a valid v3-signed request from **another
  device of the SAME account**. Membership is **flat**, so this is symmetric:
  ⚠️ **one compromised member device can revoke every other device in its
  account.** That is visible in the audit log (`device.revoked` records
  `revoked_by` and `account_id`); it is not prevented.

**No existence oracle on the non-admin paths:** an **unknown** device and a
device belonging to **another account** both answer `403` (audited as
`forbidden_device`), never `404`. Only the **admin** path keeps its `404` — an
operator holding the admin token can already enumerate the registry via
`GET /v1/devices`.

- **Success — `200 OK`:** `{ "device_id": "dev_…", "status": "revoked" }`
- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `missing_device_id` / `invalid_request` | empty path segment; body unreadable or over 8 KiB |
  | `401 Unauthorized` | `unauthorized` | no admin token **and** no valid v3 signature |
  | `403 Forbidden` | `forbidden` | authenticated, but the target is neither this device nor a sibling in its account — **or does not exist**; also when the signing device carries no account (`missing_account`) |
  | `404 Not Found` | `device_not_found` | no such device — **admin path only** |
  | `501 Not Implemented` | `not_implemented` | dev-ops off, or no registry configured |

### `POST /v1/vaults/{vaultID}/grants` — grant a device access to a vault

The requesting device must belong to the vault's **owning ACCOUNT** (Phase 52 —
any member qualifies, not only the device that happened to claim it); any other
authorized device gets `403` (`not_vault_owner`). ⚠️ **A legacy `is_owner` grant
row does NOT satisfy this** — ownership is an account property, full stop. The
signature covers the body, so authorization runs **after** the body is read.

- **Auth:** the four v3 headers.
- **Request body** (JSON, capped at 8 KiB):

  ```json
  { "device_id": "dev_<grantee>", "permission": "read" }
  ```

- **Success — `201 Created`:**

  ```json
  { "device_id": "dev_<grantee>", "permission": "read", "owner": false, "created_at": "<RFC3339>" }
  ```

  Re-granting updates a non-owner grant's permission; an existing **owner** row
  is never downgraded.

- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `missing_vault_id` / `invalid_request` | empty vault ID; unreadable/oversized body; missing `device_id`; `permission` not `"read"` or `"write"` |
  | `401 Unauthorized` | `unauthorized` | the v3 signature check failed |
  | `403 Forbidden` | `forbidden` | authenticated but **not the vault owner**, or holding no grant at all |
  | `404 Not Found` | `device_not_found` | the grantee is not enrolled |
  | `409 Conflict` | `device_revoked` | the grantee is revoked — a grant to a revoked device is refused, not silently recorded |
  | `501 Not Implemented` | `not_implemented` | dev-ops off, or no registry configured |

### `GET /v1/vaults/{vaultID}/grants` — list a vault's grants

Any device with **read** access to the vault may see who else can reach it.

- **Auth:** the four v3 headers (`BODY` is empty for GET).
- **Success — `200 OK`:**

  ```json
  {
    "vaultID": "<vaultID>",
    "owner_account_id": "acct_…",
    "grants": [ { "device_id": "dev_…", "permission": "write", "owner": true, "created_at": "<RFC3339>" } ]
  }
  ```

  **`owner_account_id` is ADDITIVE (Phase 52) and load-bearing for
  comprehension:** every device of the owning account holds full access **without
  appearing in a grant row**, so without this field the response would read as
  "nobody owns this vault". It is **omitted when the vault is unclaimed**. The
  `grants` array and its `owner` flag are **byte-identical to before** — the flag
  is retained as the per-device *view* of ownership, and no authorization
  decision reads it.

- **Errors:** `400 missing_vault_id`; `401 unauthorized`; `403 forbidden` (no
  grant — including on an **unowned** vault, since reads never claim); `500
  internal`; `501 not_implemented`.

### Client support (the `sigil` CLI)

The **`sigil` CLI implements contract v3** — it was the first client to speak it,
covering four of the five device routes above. **All four client surfaces now speak
it**: the CLI, the webapp and the MV3 extension (see
[below](#client-support-the-browser--node-clients)), and the **native desktop app**,
which does not implement the contract at all but *links this CLI's library target* and
calls `enroll_device` / `push_op_auth` / `pull_ops_auth` directly
([ADR 0037](decisions/0037-desktop-reuses-cli-library-for-protocol.md)) — so the
canonical message has **three** implementations, not four. Commands (see
[`../cli/src/main.rs`](../cli/src/main.rs)):

| Command | Route it calls |
|---------|----------------|
| `sigil device enroll --token <t> [--label <name>] [--key <file>] [--server <url>] [--reuse-key]` | `POST /v1/devices/enroll` — generates (or, with `--reuse-key`, reuses) the key, signs the proof of possession, and writes the returned `device_id` into the `0600` identity file. It **refuses to overwrite** an existing identity file unless `--reuse-key` is given. |
| `sigil device list --admin-token <t> [--server <url>]` | `GET /v1/devices` |
| `sigil device revoke <deviceID> [--admin-token <t>] [--key <file>] [--server <url>]` | `POST /v1/devices/{deviceID}/revoke` — self-revocation with `--key`, or the operator path with `--admin-token` |
| `sigil device grant <deviceID> --vault <id> --permission read\|write [--key <file>] [--server <url>]` | `POST /v1/vaults/{vaultID}/grants` (owner-only) |

`GET /v1/vaults/{vaultID}/grants` has **no CLI subcommand yet**.

**Contract selection is additive and driven by the identity file**, so nothing
existing changed:

| Client state | Contract used |
|--------------|---------------|
| no `--key` and no `SIGIL_DEVICE_KEY` | **unsigned** (byte-identical to the legacy unauthenticated path) |
| identity file **without** `device_id` | **v2** (legacy, unchanged) |
| identity file **with** `device_id` (after `device enroll`) | **v3**, sending `X-Sigil-Device` |

`sigil push` / `sigil pull` therefore sign v3 automatically once the key they
were given is enrolled. `SIGIL_DEVICE_ID=<id>` forces v3 with that ID even for
an older key file. Tokens and the server URL may also come from the environment
— `SIGIL_ENROLL_TOKEN`, `SIGIL_ADMIN_TOKEN`, `SIGIL_DEVICE_ID`, plus the
existing `SIGIL_SERVER` / `SIGIL_DEVICE_KEY` — with the flags taking
precedence. The `device` subcommands default the identity path to
`$HOME/.sigil/device.key`; `push`/`pull` keep their old rule (no key ⇒
unsigned). The CLI never prints the seed, the enrollment token, or the admin
token.

The CLI builds the same canonical bytes as the server
(`canonical_v3_message` / `canonical_enroll_message` in
[`../cli/src/lib.rs`](../cli/src/lib.rs)), with a fresh CSPRNG nonce and the
current unix seconds per request. It is the same **dev-only, plain-HTTP,
UNAUDITED** posture as the server side: no TLS, do not point it at a remote host.

### Client support (the browser + Node clients)

The **browser clients speak contract v3 as well**, through
[`../sigil-wasm/device-auth.mjs`](../sigil-wasm/device-auth.mjs) — a framework-free,
dependency-free ESM module that runs in Node **and** the browser and is used by
`web/apps/webapp` (via the `@sigil/wasm` loader) and by the MV3 `extension/` (via
its vendored copy). It covers **all five** device routes:

| Module function | Route it calls |
|-----------------|----------------|
| `enrollDevice(wasm, {baseUrl, token, label, seed})` | `POST /v1/devices/enroll` (token **plus** proof of possession) |
| `pushContainerAuthed` / `pullContainersAuthed` | `POST` / `GET /v1/vaults/{vaultID}/ops`, v3-signed |
| `grantVaultAccess` / `listVaultGrants` | `POST` / `GET /v1/vaults/{vaultID}/grants` |
| `revokeSelf` / `revokeDeviceAdmin` | `POST /v1/devices/{deviceID}/revoke` (self-signed, or admin token) |
| `listDevices` | `GET /v1/devices` (admin token) |

Supporting surface: `generateDeviceSeed` / `devicePublicKey` (a 32-byte seed from
`crypto.getRandomValues`, public key derived in the wasm), `signedFetch` /
`makeSignedFetch` (a `fetch`-shaped signer), `sealDeviceIdentity` /
`openDeviceIdentity` (the identity is stored **sealed**, never in plaintext — see
[ADR 0033](decisions/0033-browser-device-identity-storage.md)), and
`DeviceAuthError` / `explainAuthStatus`, which turn the deliberately coarse `401`
vs `403` bodies into a plain-language explanation without inventing an oracle.
**All signing is `ed25519_sign` in the wasm** (`sigil-core`'s real Ed25519, added
to the binding alongside `ed25519_public_key` / `ed25519_verify`); the enrollment
token's SHA-256 digest comes from `crypto.subtle`. There is no JS-side signing.

The existing transport [`../sigil-wasm/sync.mjs`](../sigil-wasm/sync.mjs) was
extended **additively** with one optional `opts.fetch` (defaulting to the global
`fetch`) plus an additive `err.status`, so the **unauthenticated** dev path is
behaviourally identical and the authenticated path simply injects the signer.

**The canonical message layout exists in three implementations — and deliberately
stopped there** —
[`../sigild/internal/api/deviceauth.go`](../sigild/internal/api/deviceauth.go)
(Go, the source of truth), [`../cli/src/lib.rs`](../cli/src/lib.rs) (Rust), and
`device-auth.mjs` (JS: `canonicalV3Message` / `canonicalEnrollMessage` /
`enrollTokenHash`). The **native desktop client added no fourth copy**: it calls the
Rust one through the `sigil-cli` library
([ADR 0037](decisions/0037-desktop-reuses-cli-library-for-protocol.md)). The three
**must stay byte-identical**; a one-byte drift does
not fail loudly, it just yields `401` on every request. That is what the interop
tests guard: [`../sigil-wasm/test/device-auth-interop.mjs`](../sigil-wasm/test/device-auth-interop.mjs)
boots a **real** sigild with `SIGILD_DEVICE_AUTH=1` and drives the JS client
against it (enroll, claim, grant, revoke, tamper, stale, token reuse). Same
**dev-only, plain-HTTP, UNAUDITED** posture as the CLI: no TLS, loopback only.

### Default posture (all twelve routes)

With **`SIGILD_ENABLE_DEV_OPS` unset** — the default and the only
production-safe setting — **every** device route (the **five** above) **and every
vault-sharing route** (the **seven** in the
[next section](#device-to-device-vault-sharing-dev-gated-opt-in--phase-46) — the
original four, the two Phase 50 rotation routes, and the Phase 54 per-device
envelope index `GET /v1/devices/{deviceID}/keys`) returns:

```json
{ "error": "not_implemented", "detail": "device enrollment, per-vault authorization and vault sharing are not enabled on this server" }
```

`501`, never `404`, and never a partial or faked auth behaviour. The same `501`
applies when dev-ops is on but no registry is configured
(`SIGILD_DEVICE_AUTH` unset). The bodies of `PUT`/`POST` requests are drained and
discarded, and the envelope route keeps its size cap even while stubbed.
`GET /metrics` stays `200` throughout — it is never dev-gated.

The **four account routes** ([below](#account-model-dev-gated--phase-52)) are
gated identically but answer their **own** `501` stub, whose detail names that
surface:

```json
{ "error": "not_implemented", "detail": "the account model (membership and invites) is not enabled on this server" }
```

---

## Account model (DEV-GATED) — Phase 52

> **DEV-GATED and UNAUDITED, and explicitly NOT an identity system.** An account
> is **auth metadata only**: a server-assigned id on a device row. There is **no
> email, no password, no session, no PII, and no operator break-glass — the only
> recovery is a **paper kit printed in advance**
> ([below](#recovery-kits-dev-gated--phase-54)).** It is
> active exactly when the v3 device model is (which already requires
> `SIGILD_ENABLE_DEV_OPS`); there is deliberately **no separate switch**. See
> [ADR 0040](decisions/0040-account-model.md).

**Why it exists.** Before Phase 52 the only subject was a **device**, and two
defects followed: a subscription belonged to a device, so **paying on your phone
did not entitle your laptop**; and a vault was owned by a device, so **revoking
that device orphaned the vault forever**. An account is the larger subject both
of those needed.

**The model in one sentence:** an account is a **server-assigned id on the device
row**; a **single-use invite** minted by a member device is the only way a second
device joins; and ⭐ **no request anywhere names an account** — the server always
takes it from the device row of the signature it just verified.

That last clause is structural, not defensive: there is **no path segment, no
query parameter and no body field** anywhere in this API that names an account,
so a cross-account request is **unconstructible**, not merely rejected. (A mint
body carrying `account_id` or `subject` is ignored by `encoding/json`.)

**What membership does and does not buy.** Membership confers **AUTHORIZATION,
never DECRYPTION**. A joined device can authenticate and see its entitlement, and
reads **nothing** until an existing member wraps the vault key to its hybrid
public key
([vault sharing](#device-to-device-vault-sharing-dev-gated-opt-in--phase-46)).
The corollary is the reassuring half: **a hostile server can insert a device into
any account** — it owns the registry — **and still cannot decrypt anything.**

### How a second device joins

There is **no join route**. A member mints an invite and the joining device
presents it as its ordinary enrollment token:

```
device already in the account          the joining device
──────────────────────────────         ─────────────────────────────────────────
POST /v1/account/invites        ──▶     (paste the invite secret)
  201 { "invite": "join_…" }            POST /v1/devices/enroll
                                          X-Sigil-Enroll-Token: join_…
                                          + the SAME proof of possession
                                        201 { "device_id": …, "account_id": … }
```

The invite rides the **existing `X-Sigil-Enroll-Token` header** under the
**existing enrollment challenge**, because that challenge already binds the
credential's SHA-256 **digest**. **No new header, no new signed-message domain,
no fourth canonical message** — see
[`POST /v1/devices/enroll`](#post-v1devicesenroll--enroll-a-device).

### Configuration

The three `SIGILD_ACCOUNT_*` variables are documented with the rest of the v3
configuration [above](#configuration). Summary: `SIGILD_ACCOUNT_MAX_DEVICES`
(default **10**), `SIGILD_ACCOUNT_MAX_INVITES` (default **5**),
`SIGILD_ACCOUNT_INVITE_TTL` (default **15m**) — all validated fail-fast before
the listener binds, and all a **boot error** without `SIGILD_DEVICE_AUTH`.

### Storage (migration `0005_accounts.sql`)

| Table / column | Holds |
|----------------|-------|
| `sigil_accounts` | `account_id` (PK, `acct_` + raw-URL-base64 of 16 CSPRNG bytes), `created_at`, `created_by_device_id`. **No label and no status column** — a label is user data with no server-side use (and exactly where an email would get typed); a status column no route sets is dead schema |
| `sigil_devices.account_id` | **Nullable**, referencing `sigil_accounts`. Deliberately nullable so a rolled-back pre-0005 binary can still enroll; the "every device has an account" invariant is enforced in the **application** |
| `sigil_account_invites` | `invite_hash` (PK — the lowercase-hex **SHA-256** of the secret; the secret itself is **never** stored), `invite_id` (the **public** handle, UNIQUE), `account_id`, `created_by_device_id`, `invitee_public_key` (nullable — the pin), `created_at`, `expires_at`, `used_at`, `used_by_device_id`, `revoked_at` |
| `sigil_vault_owners` | `vault_id` (**PK** — what makes the claim single-winner across processes), `account_id`, `claimed_by_device_id`, `claimed_at`. **This is the authority on vault ownership** |

The migration ends with an **adoption backfill**, inside its single transaction:
every already-enrolled device (active **and** revoked) gets its own singleton
account named `acct_mig_<device_id>`; vault ownership is backfilled from existing
`is_owner` grants (reading that table, writing nothing back to it); and
subscriptions whose subject names a device are re-keyed to that device's account.
`sigil_billing_processed_events.subject` is deliberately **not** rewritten.

It is **pure DDL plus a metadata backfill**: **no column created here can hold a
vault key, a password, a plaintext, a card detail, an email, a phone number, a
display name, a bearer token, a signature or a nonce**, and `sigil_vault_ops` is
not named anywhere in it — so the opaque blob and its tamper-evidence hash chain
are byte-for-byte unchanged and `GET …/ops/verify` returns the **same
`tip_hash`** before and after. `sigild_schema_version` reports **5** once applied.

⚠️ **The comment at `0005_accounts.sql:42` is STALE:** it says a NULL account
"FAILS CLOSED (`missing_account` -> 500)". The behaviour is **`403`** (see
[`401` vs `403`](#401-vs-403-and-the-absence-of-an-auth-oracle)). That file is an
**applied migration** and is not edited; this reference is the authority.

### `GET /v1/account` — the caller's own account

Returns the **authenticated device's** account and its members. There is no route
that reads another account and none that enumerates accounts.

- **Auth:** the four v3 headers (`BODY` is empty for GET).
- **Success — `200 OK`:**

  ```json
  {
    "account_id": "acct_…",
    "created_at": "<RFC3339>",
    "device_count": 2,
    "revoked_device_count": 1,
    "device_limit": 10,
    "devices": [
      { "device_id": "dev_…", "account_id": "acct_…", "label": "laptop", "status": "active", "created_at": "<RFC3339>" },
      { "device_id": "dev_…", "account_id": "acct_…", "label": "old phone", "status": "revoked", "created_at": "<RFC3339>", "revoked_at": "<RFC3339>" }
    ]
  }
  ```

  ⚠️ **`device_count` COUNTS ACTIVE DEVICES ONLY**, because that is what
  `device_limit` bounds: the cap is on **concurrent** devices, so **a revoked
  device frees its seat**. `revoked_device_count` (new) reports the rest
  separately rather than folding history into the limit, and `devices[]` still
  lists **both**, so nothing is hidden.
  <br>*(This is a behaviour change from the first cut of Phase 52, where revoked
  devices consumed seats permanently — which turned the cap into a lifetime
  enrollment limit that no operation could reverse, bricking an account under
  exactly the "revoke and re-enroll" remedy this model prescribes.)*
  <br>`created_at` is omitted if the account row cannot be read.

- **Errors:** `401 unauthorized`; `403 forbidden` (the signing device carries no
  account — audited as `missing_account`, repaired with `sigild migrate adopt`);
  `500 internal`; `501 not_implemented`.

### `POST /v1/account/invites` — mint a single-use invite

Mints an invite for the **caller's** account. The secret is returned **exactly
once, here** — it is never re-served, never logged, never a metric label, and
only its SHA-256 digest is stored.

- **Auth:** the four v3 headers (the signature covers the body, so authentication
  runs after the body is read).
- **Request body** (JSON, optional, capped at **8 KiB**):

  ```json
  { "ttl_seconds": 300, "invitee_public_key": "<standard-base64 of a raw 32-byte Ed25519 public key>" }
  ```

  Both fields are optional. `ttl_seconds` may only **shorten** the invite's life
  — a value longer than the server's configured ceiling is ignored, never
  honoured. `invitee_public_key` **PINS** the invite to one key, so an
  intercepted invite cannot be redeemed by anyone else. **Note what is not here:
  no `account_id` and no `subject`.**

- **Success — `201 Created`:**

  ```json
  { "invite_id": "inv_…", "invite": "join_…", "account_id": "acct_…", "expires_at": "<RFC3339>", "pinned": false }
  ```

- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `invalid_request` | body unreadable / over 8 KiB, not a JSON object, or `invitee_public_key` is not the standard-base64 of a **32-byte** key |
  | `401 Unauthorized` | `unauthorized` | the v3 signature check failed |
  | `403 Forbidden` | `forbidden` | the signing device carries no account (`missing_account`) |
  | `409 Conflict` | `account_full` | the account is already at `SIGILD_ACCOUNT_MAX_DEVICES` **active** devices — refused early, because minting an invite that could only ever fail is worse than a clear `409` |
  | `409 Conflict` | `invite_limit` | the account already holds `SIGILD_ACCOUNT_MAX_INVITES` **open** invites |
  | `429 Too Many Requests` | `rate_limited` | only when `SIGILD_INVITE_RATE_LIMIT` is set — the **per-account** bucket is empty ([above](#abuse-rate-limiting-enrollment--invite-minting)). Carries `Retry-After`. ⚠️ This check runs **after** authentication, so it does **not** make an unauthenticated flood of this route cheaper |
  | `500` | `internal` | the registry could not be read/written |
  | `501 Not Implemented` | `not_implemented` | the account model is not enabled |

> ⚠️ **An UNPINNED invite is a BEARER SECRET for its whole TTL**, and the dev
> transport is **plain HTTP with no TLS**. Anyone who reads it in time can join
> the account and inherit its entitlement. Pinning closes that; **nothing forces
> pinning**.

### `GET /v1/account/invites` — list this account's open invites

**METADATA ONLY.** The secret and its digest are never served — a minted invite
can never be recovered from the server.

- **Auth:** the four v3 headers.
- **Success — `200 OK`:**

  ```json
  {
    "invites": [
      { "invite_id": "inv_…", "created_by_device_id": "dev_…", "created_at": "<RFC3339>", "expires_at": "<RFC3339>", "pinned": true }
    ]
  }
  ```

  Only **open** invites (unused, unrevoked, unexpired) are listed, ordered by
  `created_at` then `invite_id`.

- **Errors:** `401 unauthorized`; `403 forbidden` (`missing_account`);
  `500 internal`; `501 not_implemented`.

### `POST /v1/account/invites/{inviteID}/revoke` — kill an unredeemed invite

`{inviteID}` is the **public handle** (`inv_…`), never the digest.

- **Auth:** the four v3 headers.
- **Success — `200 OK`:** `{ "invite_id": "inv_…", "revoked": true }`
- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `missing_invite_id` / `invalid_request` | empty path segment; body unreadable or over 8 KiB |
  | `401 Unauthorized` | `unauthorized` | the v3 signature check failed |
  | `403 Forbidden` | `forbidden` | the signing device carries no account (`missing_account`) |
  | `404 Not Found` | `invite_not_found` | no such **open** invite |
  | `500` | `internal` | the registry could not be read/written |
  | `501 Not Implemented` | `not_implemented` | the account model is not enabled |

> **No enumeration oracle.** The store scopes the update by
> `(account_id, invite_id)`, so an invite handle belonging to **another account**
> and one that **never existed** are indistinguishable — both `404`.

### Audit log

Four new events, all **metadata only**. They carry account ids, device ids, the
**public** invite handle, an expiry and a fixed reason enum — and **never** an
invite secret, an invite digest, an enrollment token, a key, a signature, a nonce
or one byte of a blob.

| Event | Fields |
|-------|--------|
| `account.created` | `request_id`, `account_id`, `created_by_device_id` — an operator-token enrollment founded a new account |
| `account.device_joined` | `request_id`, `account_id`, `device_id`, `invited_by`, `invite_id` — names the **inviter**, which is what makes a planted device *visible* after the fact (flat membership means it is not *prevented*) |
| `account.invite_created` | `request_id`, `invite_id`, `account_id`, `device_id`, `expires_at`, `pinned` |
| `account.invite_revoked` | `request_id`, `invite_id`, `account_id`, `device_id` |

Existing events gained fields: `device.enrolled` and `device.revoked` carry
`account_id` (and `device.revoked`'s `revoked_by` may now be a **sibling** device
id); `vault.claimed` carries `account_id` beside the claiming `device_id`;
`device.enroll_denied` carries a fine-grained `invite_reason` **in addition to**
the coarse `reason`; and the billing events carry both the account `subject` and
the `device_id` that ran the checkout.

### Client support

| Client | What it can do |
|--------|----------------|
| **`sigil` CLI** | **full** — `sigil account status`, `sigil account invite [--ttl <seconds>] [--pin-key <b64>]`, `sigil account invites`, `sigil account revoke-invite <inviteID>`. Joining is the ordinary `sigil device enroll --token <invite>`; there is **no join subcommand**, by design |
| **Native desktop** | **full** — the same four operations, over `DeviceConfig::{account, create_invite, list_invites, revoke_invite}` and four new Tauri commands, reusing the `sigil-cli` library exactly as [ADR 0037](decisions/0037-desktop-reuses-cli-library-for-protocol.md) requires |
| **Webapp / MV3 extension** | **partial, by design** — both can **JOIN** (an invite pastes into their existing enrollment-token field, since the wire is unchanged) and can **READ** the account (`getAccount`) and render the honest *"joined — waiting for a key from another device"* state. Neither has a UI to **mint**, list or revoke an invite |

The JS half lives in
[`../sigil-wasm/device-auth.mjs`](../sigil-wasm/device-auth.mjs) —
`getAccount` / `createAccountInvite` / `listAccountInvites` /
`revokeAccountInvite`, every one an ordinary `signedFetch` v3 request. It adds
**no canonical message and no header**, and joining is the **unchanged**
`enrollDevice`.

### Account model — honest limits

All nineteen are enumerated in
[ADR 0040](decisions/0040-account-model.md#bad--honest-limitations-all-real-none-papered-over).
The ones that change what this API *means*:

1. ⚠️ **STILL NOT AN IDENTITY SYSTEM — and recovery exists only if it was printed
   in advance.** There is no email, no password, and **no operator break-glass**.
   Since Phase 54 a customer *can* print a **recovery kit**
   ([below](#recovery-kits-dev-gated--phase-54)) — 56 characters on paper that
   derive an ordinary member device — which addresses the **data** half of this
   limitation. ⚠️ **A kit cannot be created after the loss.** Lose or revoke every
   device **without having printed one**, and the account is permanently
   unreachable, its vaults permanently unreadable by the customer AND by us, and
   its subscription stranded. The orphan failure **narrowed** again; it was **not
   eliminated**. And the kit brings a risk of its own: **whoever holds the paper
   holds the account.**
2. **Membership is FLAT.** Any member may invite, revoke **every** other member,
   run checkout and administer every account-owned vault. **Revoking a
   compromised device does NOT revoke the devices it invited** — the audit log
   names the inviter, but nothing prevents it. No quorum, no re-authentication.
3. **Trust-on-first-write moved up a level; it did not go away.** The first
   *account* to write an unclaimed vault owns it.
4. **Ownership never moves between accounts and membership is immutable** — no
   transfer, merge, split or account deletion. A device in the wrong account can
   only be revoked and re-enrolled.
5. **NO ACCOUNT MERGE.** Every device enrolled before `0005` is adopted into its
   **own** singleton account, so an existing two-device customer ends up with
   **two accounts and two billing subjects**. The remedy is manual and leaves a
   second subscription row for an operator to reconcile.
6. **Entitlement CAN now be enforced, but only on writes, and only opt-in.**
   `SIGILD_ENTITLEMENT_ENFORCE` (**off by default**) makes a lapsed account's
   **writes** answer `402` past the grace period
   ([below](#entitlement-enforcement-opt-in--phase-55)). ⭐ **Reads and
   same-account key recovery are never refused**, and `past_due` stays entitled.
   With the switch unset, this limitation still reads exactly as written.
7. **`SIGILD_ACCOUNT_MAX_DEVICES` is anti-freeloading, not anti-fraud**, and a
   compromised provider webhook secret now moves an **account's** status rather
   than one device's — which, with enforcement on, means it can move an account's
   **service**.
8. **Rate limiting is opt-in and is a BACKSTOP.**
   `POST /v1/devices/enroll` and `POST /v1/account/invites` can be bounded
   ([above](#abuse-rate-limiting-enrollment--invite-minting)), but behind a
   reverse proxy the enrollment bucket is global, only failures are charged, and
   the handler still runs. The device/invite caps bound stored **state**, not
   request volume, and there is still **no sweep job for expired invites**.
9. **The replay nonce cache is still per-process and in-memory.** Invite
   consumption is DB-atomic and therefore multi-instance safe; **signed requests
   are not**.
10. **The in-memory registry is still non-durable** (accounts, memberships,
    invites and vault-owner rows all vanish on restart — warned at boot), and the
    **file op-log backend was still not extended**.
11. ⚠️ **Rollback is survivable but not free.** A pre-Phase-52 binary run after
    `0005` is applied enrolls devices with `account_id NULL`; rolling forward,
    those devices are refused everywhere with a coarse `403`. **Any device
    enrolled during a rollback window needs `sigild migrate adopt` afterwards**,
    and the **boot warning** is how an operator knows. See
    [`deployment.md` §11](deployment.md#11-schema-migrations-postgres-backend).
12. **Still dev-gated, `501` by default, plain HTTP, pre-audit, UNAUDITED** — a
    real authorization model, **not a reviewed one**.

---

## Device-to-device vault sharing (DEV-GATED, opt-in) — Phase 46

> **DEV-GATED, OPT-IN, and UNAUDITED.** These **seven** routes let one enrolled device
> hand a vault's encryption key to another **without the server ever being able to
> read it**. The relay is real and the authorization is real (it is the *same* v3
> code path as the op-log, not a parallel one), but it is **gated off by default**
> (`501`), **plain HTTP in dev**, and the cryptography it carries is **unaudited**.
> The key hierarchy — a random per-vault key wrapped with the PQ-hybrid
> `hybrid_auth_seal` path, the human password never shared — is specified in
> [`crypto-spec.md`](crypto-spec.md#key-hierarchy-and-vault-sharing-hybrid_auth_seal--hybrid_auth_open-in-use).
> See [ADR 0035](decisions/0035-device-to-device-vault-sharing.md).
>
> ⚠️ **Phase 60 changed the ENVELOPE BYTES, and nothing else on this surface.**
> The wrap was **anonymous** (`hybrid_seal`, HPKE `mode_base`), so anyone holding
> a recipient's **published** hybrid public key — which `GET
> /v1/devices/{deviceID}/hybrid-key` serves to every authenticated device — could
> mint an envelope the recipient would accept and install a vault key **of their
> own choosing**. The wrap is now **authenticated and context-bound**
> (`SIGILhyb` **version 2**; a version-1 container is **refused** by clients
> wherever a vault key is expected), and the envelope is **no longer a fixed
> size**. ⭐ **`sigild` changed by ZERO lines** — no route, header, canonical
> message, migration, table, metric or dependency; the blob was opaque before and
> is opaque now. ⛔ **Every envelope deposited before Phase 60 must be
> re-issued**, and there is no migration. See
> [ADR 0048](decisions/0048-authenticated-vault-key-envelopes.md).
>
> **Phase 50 added the last two** (`GET …/keys`, `DELETE …/keys/{deviceID}`) to
> support **vault key rotation**, and added a purely **client-side** trust control
> around the fetch: clients **pin** a device's hybrid public key and refuse to wrap
> to a changed one, verifiable out of band with a **safety number**
> ([ADR 0038](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)).
> **`sigild` gained no knowledge of any of that** — it does not store, serve or
> validate a pin or a safety number, and it still performs no cryptography.
>
> **Phase 54 added the seventh** (`GET /v1/devices/{deviceID}/keys`, a **self-only,
> metadata-only** index of which vaults hold a wrapped key for one device) to
> support the **recovery kit** ([below](#recovery-kits-dev-gated--phase-54)). It
> needed **no migration** — the index `sigil_vault_key_envelopes_by_recipient`
> from `0004_key_sharing.sql` was created for exactly this query — so
> `sigild_schema_version` stays **5**, and `sigild` still has **no concept of
> "recovery"**.

### The shape of the flow

`sigild` is a **mailbox**, not a key manager. The sending client wraps a vault key
to the recipient's hybrid **public** key and uploads the resulting ciphertext; the
recipient collects those exact bytes and unwraps them locally.

```
device A                          sigild                          device B
   │  PUT /v1/devices/{A}/hybrid-key  ─▶ registry (public keys only)
   │  GET /v1/devices/{B}/hybrid-key  ◀─ B's X25519 + ML-KEM-768 public key
   │  ── wrap the 32-byte vault key with hybrid_seal (client-side) ──
   │  PUT /v1/vaults/{V}/keys/{B}     ─▶ stores OPAQUE envelope bytes verbatim
   │  POST /v1/vaults/{V}/grants      ─▶ authorize B on vault V (existing route)
                                          GET /v1/vaults/{V}/keys/{B}  ◀─ │
                                          (exact same bytes back)         │
                                     ── unwrap with B's hybrid secret ──  │
```

**Zero-knowledge.** The server holds no decapsulation key, decodes nothing, and
returns the envelope byte-for-byte. Its **only** inspection of key material is a
**length check** on a published hybrid public key (32 / 1184 bytes) — it never
parses a curve point or validates a KEM key, because that would be the server
performing cryptography on user key material.

### Configuration and storage

No new environment variable. The routes are live exactly when the multi-device
model is (`SIGILD_ENABLE_DEV_OPS` **and** a configured registry — see
[Configuration](#configuration) above), and they use that registry's backend.

Migration [`0004_key_sharing.sql`](../sigild/internal/store/migrations/0004_key_sharing.sql)
adds two tables on top of the untouched `0001`–`0003` (`sigild_schema_version` →
**4**):

| Table | Holds |
|-------|-------|
| `sigil_device_hybrid_keys` | `device_id` (PK, FK → `sigil_devices`, `ON DELETE CASCADE`), `x25519_public_key` (`bytea`), `mlkem_encaps_key` (`bytea`), `updated_at`. **Public** key material, stored verbatim |
| `sigil_vault_key_envelopes` | `(vault_id, recipient_device_id)` (PK; the FK is on the recipient), `sender_device_id`, `blob` (`bytea`, **ciphertext**), `created_at`; plus the index `sigil_vault_key_envelopes_by_recipient` |

Both are pure DDL over opaque bytes; `sigil_vault_ops`, its hash chain, the device
registry, the grants table and the billing tables are byte-for-byte unchanged.
`sender_device_id` is **audit metadata** — the device the server *authenticated* on
upload, never a claim read out of the blob. Both stores (in-memory and Postgres)
implement the one `store.KeySharing` seam and are held to one conformance suite.

**Upsert semantics, and what they do not do.** `PUT …/hybrid-key` is an upsert on
`device_id`, and `PUT …/keys/{deviceID}` is an upsert on
`(vault_id, recipient_device_id)` — re-sharing after a re-key replaces the
envelope. **Republishing a hybrid key does NOT re-wrap envelopes already deposited
for that device**: those were sealed to the old key and must be re-shared.

### Size caps

| Limit | Value | Enforced |
|-------|-------|----------|
| hybrid-key publish body | **8 KiB** (`maxHybridKeyBodyBytes`) | in the handler → `413 payload_too_large` |
| key envelope | **16 KiB** (`store.MaxKeyEnvelopeBytes`) | at the router (`limitBody`) **and** again in the store → `413 payload_too_large` |
| X25519 public key | exactly **32** bytes after base64 decode | `store.ValidateHybridPublicKey` → `400 invalid_request` |
| ML-KEM-768 encapsulation key | exactly **1184** bytes after base64 decode | as above |
| envelope may not be empty | ≥ 1 byte | → `400 empty_envelope` |

A real wrapped vault key is a `SIGILhyb` container of about **1.3 KiB**:

```
  magic(8) ‖ version(1) ‖ eph_x25519_pub(32) ‖ mlkem_ct(1088) ‖ envelope
```

⚠️ **Its length is NOT fixed.** Since Phase 60 the envelope carries a
**context-bound AAD** naming the purpose, the vault and both device ids
([ADR 0048](decisions/0048-authenticated-vault-key-envelopes.md)), so:

```
  bytes = 1244 + len(vault_id) + len(recipient_device_id) + len(sender_device_id)
```

Measured **1310 bytes** for a 14-character vault id and two server-assigned
device ids (26 characters each: `dev_` + 22 base64url chars). ⚠️ Do **not**
hard-code a length: `size_bytes` in the responses below varies with the
identifiers, and the examples show one plausible value, not a constant.

⚠️ **`version` is `2`** for a vault-key envelope (**authenticated**); clients
**refuse** a version-1 (anonymous) container here, because it carries no sender.
Version 1 is still correct for the unrelated `sigil hybrid-seal` **file**
container, which *is* a flat 1226 bytes — the two must not be conflated, since a
forged file container being byte-shaped like a genuine wrap is exactly the defect
ADR 0048 closed. `sigild` reads none of this: the envelope is opaque to it and
only the **16 KiB** cap applies, which stays generous headroom while still
stopping the relay being used as a blob store.

### `401` vs `403` on these routes

The [general rule](#401-vs-403-and-the-absence-of-an-auth-oracle) applies
unchanged, and two sharing-specific cases are worth stating because they are easy
to get backwards:

- Publishing into **another device's** hybrid-key slot is **`403`**
  (`forbidden_device`) — the request authenticated fine; it is simply not permitted.
- Requesting **another device's** envelope is **`403`** (`forbidden_device`), *not*
  `404` and *not* `401`. A `401` would be a lie (the caller did authenticate) and a
  `404` would leak whether an envelope exists for that device.
- A **revoked** device gets **`401`** everywhere, on its very next request —
  revocation is checked before the signature is even verified.

The response bodies stay coarse (`{"error":"forbidden", …}`); the precise reason
goes only to the audit log and the per-reason metric.

### `PUT /v1/devices/{deviceID}/hybrid-key` — publish my hybrid public key

Stores the **public** half of this device's X25519 + ML-KEM-768 identity so other
devices can wrap a vault key to it. The secret half never leaves the device.

- **Auth:** the four v3 headers. The path `deviceID` **must be the authenticated
  device's own ID**.
- **Request body** (JSON, ≤ 8 KiB); both fields are standard-base64 of **raw**
  public key bytes:

  ```json
  { "x25519_public_key": "<b64 32 bytes>", "mlkem_encaps_key": "<b64 1184 bytes>" }
  ```

- **Success — `200 OK`** (an upsert, so re-publishing is not an error):

  ```json
  { "device_id": "dev_…", "x25519_public_key": "<b64>", "mlkem_encaps_key": "<b64>", "updated_at": "<RFC3339>" }
  ```

  Unlike the device routes — which deliberately never echo an Ed25519 signing key —
  this route **does** return key material, because publishing it for others to
  fetch is the entire point and it is a **public** key.

- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `missing_device_id` / `invalid_request` | empty path device ID; body is not a JSON object; a field is not standard-base64; a decoded half is not exactly 32 / 1184 bytes |
  | `401 Unauthorized` | `unauthorized` | v3 signature check failed — including a **revoked** device |
  | `403 Forbidden` | `forbidden` | authenticated, but publishing into **another** device's slot |
  | `404 Not Found` | `device_not_found` | the device is not (or no longer) in the registry |
  | `413 Payload Too Large` | `payload_too_large` | body over 8 KiB |
  | `501 Not Implemented` | `not_implemented` | dev-ops off, or no registry configured |

### `GET /v1/devices/{deviceID}/hybrid-key` — fetch a device's hybrid public key

- **Auth:** the four v3 headers (`BODY` is empty for GET). **Any** authenticated,
  active device may fetch **any** device's key — they are public keys; requiring
  authentication only stops the registry being world-enumerable.
- **Success — `200 OK`:** the same `hybridKeyJSON` object as above.
- **Errors:** `400 missing_device_id`; `401 unauthorized` (including revoked);
  `404 hybrid_key_not_found` (**that device exists but has published no hybrid
  key** — distinct from `device_not_found`); `500 internal`; `501 not_implemented`.

### `PUT /v1/vaults/{vaultID}/keys/{deviceID}` — deposit a wrapped vault key

Uploads an **opaque** envelope addressed to one device. The body is the **raw
envelope bytes**, the same "opaque bytes in, opaque bytes out" shape as an op-log
append — the server never decodes it.

- **Auth:** the four v3 headers. Requires **`write`** on the vault, through the
  same `authorizeOpsRequest` choke point the op-log uses — so depositing the first
  envelope for an **unowned** vault **claims** it (trust-on-first-write), exactly as
  a first append would. A read-only grantee cannot deposit.
- **Request body:** `application/octet-stream`, 1 byte … 16 KiB. The v3 signature
  covers the body, so the body is read **before** authorization runs.
- **Success — `201 Created`:**

  ```json
  { "vaultID": "<vaultID>", "device_id": "dev_<recipient>", "size_bytes": 1310, "created_at": "<RFC3339>" }
  ```

- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `invalid_request` / `empty_envelope` | missing vault or device ID; unreadable body; empty envelope |
  | `401 Unauthorized` | `unauthorized` | v3 signature check failed — including a **revoked** sender |
  | `403 Forbidden` | `forbidden` | authenticated but holding no **write** grant on the vault (including an unowned vault claimed by someone else) |
  | `404 Not Found` | `device_not_found` | the **recipient** is not enrolled |
  | `409 Conflict` | `device_revoked` | the recipient is revoked — refused, not silently stored |
  | `413 Payload Too Large` | `payload_too_large` | body over 16 KiB |
  | `501 Not Implemented` | `not_implemented` | dev-ops off, or no registry configured |

  ⭐ **THE CLAIM PRECONDITION applies here too**
  ([ADR 0045](decisions/0045-claim-precondition-rejected-writes-never-claim.md)).
  This is the **second** claiming route, so the same defect applied: a deposit the
  server was going to refuse — empty body, unknown recipient, revoked recipient —
  still took ownership of an unowned vault on its way to the refusal. Those three
  checks are cheap and **vault-independent**, so they are now evaluated **before**
  the claim, and a request that fails any of them is authorized at a level that
  cannot claim.
  > ⚠️ **The observable change is the same:** on an **UNOWNED** vault those three
  > cases now answer **`403`** rather than `400` / `404` / `409`. On a vault the
  > caller may already write, the statuses above are **unchanged**. The verdict is
  > computed once and reused to write the response, so the refusal cannot drift
  > from the precondition that gated it.

### `GET /v1/vaults/{vaultID}/keys/{deviceID}` — collect my envelope

Returns the envelope **byte-for-byte as it was uploaded**.

- **Auth:** the four v3 headers. **Two** conditions, both required: the caller must
  **be the addressee** (`deviceID` == the authenticated device) **and** hold
  **`read`** on the vault — so an envelope cannot outlive a revoked grant.
- **Success — `200 OK`**, `Content-Type: application/octet-stream`, the exact
  stored bytes. No JSON, no base64, no re-framing.
- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `invalid_request` | missing vault or device ID |
  | `401 Unauthorized` | `unauthorized` | v3 signature check failed — including a **revoked** device |
  | `403 Forbidden` | `forbidden` | authenticated but **not the addressee**, or holding no read grant |
  | `404 Not Found` | `envelope_not_found` | nothing has been shared to this device for that vault |
  | `500 Internal Server Error` | `internal` | the store could not be read |
  | `501 Not Implemented` | `not_implemented` | dev-ops off, or no registry configured |

### `GET /v1/vaults/{vaultID}/keys` — list who holds a wrapped key (METADATA ONLY)

Added in **Phase 50** to support **key rotation**
([ADR 0038](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)). A
client rotating a vault key must know which devices still hold an envelope, so it
can delete the ones it did not re-wrap to — re-wrapping alone would leave a removed
device's old envelope sitting in its mailbox.

- **Auth:** the four v3 headers. Requires **`write`** on the vault, through the
  **same `authorizeOpsRequest` choke point** that authorizes depositing an envelope
  — **no new auth path**. That is the right bar rather than a stricter one: a device
  that can deposit an envelope can already **replace** any envelope in the vault, so
  enumerating them grants it no new power. A read-only grantee gets `403`.
- ⭐ **Metadata only — never a blob.** The response carries a recipient device ID, the
  sender's device ID, the envelope's **size** and its timestamp. It **cannot** be used
  to bulk-download ciphertext, and the server still decodes nothing. The Postgres
  backend selects `octet_length(blob)` rather than the blob, so the ciphertext never
  leaves the database for this route.
- **Ordering:** by recipient device ID, stable across backends. An unknown vault is
  **not** an error — it lists zero recipients.
- **Success — `200 OK`:**

  ```json
  {
    "vaultID": "<vaultID>",
    "recipients": [
      { "device_id": "dev_B", "sender_device_id": "dev_A", "size_bytes": 1310, "created_at": "<RFC3339>" }
    ]
  }
  ```

- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `invalid_request` | missing vault ID |
  | `401 Unauthorized` | `unauthorized` | v3 signature check failed — including a **revoked** device |
  | `403 Forbidden` | `forbidden` | authenticated but holding no **write** grant on the vault |
  | `500 Internal Server Error` | `internal` | the store could not be read |
  | `501 Not Implemented` | `not_implemented` | dev-ops off, or no registry configured |

### `DELETE /v1/vaults/{vaultID}/keys/{deviceID}` — remove a device's envelope

Removes the envelope addressed to one device, so a device rotated **away** from a
vault cannot collect the **new** key.

- **Auth:** identical to the list route — the four v3 headers and **`write`** on the
  vault, through the same `authorizeOpsRequest` choke point.
- ⚠️ **What it does and does not do.** It stops that device collecting anything
  **new**. It **cannot** make a device forget a key it already unwrapped, and it does
  not touch the op-log: the sealed containers that device already pulled stay openable
  offline forever.
- **Success — `200 OK`:**

  ```json
  { "vaultID": "<vaultID>", "device_id": "dev_B", "deleted": true }
  ```

- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `invalid_request` | missing vault or device ID |
  | `401 Unauthorized` | `unauthorized` | v3 signature check failed — including a **revoked** device |
  | `403 Forbidden` | `forbidden` | authenticated but holding no **write** grant on the vault |
  | `404 Not Found` | `envelope_not_found` | nothing was addressed to that device for this vault |
  | `500 Internal Server Error` | `internal` | the store could not be written |
  | `501 Not Implemented` | `not_implemented` | dev-ops off, or no registry configured |

  A rotating client treats the `404` as **success**, not failure: the desired end
  state ("no envelope for that device") already holds. `delete_key_envelope` /
  `deleteKeyEnvelope` therefore return `false` rather than raising.

### `GET /v1/devices/{deviceID}/keys` — which vaults hold a key for ME (SELF-ONLY, METADATA ONLY)

Added in **Phase 54** ([ADR 0042](decisions/0042-recovery-kit.md)). A device
restoring itself on a fresh machine — the case a **recovery kit** exists for —
knows its own device id and **nothing else**: not which vaults it can open, not
which account it belongs to. This is the one route that answers *"which vaults
hold a wrapped key addressed to me?"*

- **Auth:** the four v3 headers. ⭐ **Self-only**, and the check runs **before any
  store read**: if `deviceID` is not the authenticated device's own id the answer
  is **`403`** (`forbidden_device`). An **unknown** device id is the **same coarse
  `403`, never a `404`** — there is no existence oracle on the registry here.
- ⭐ **Metadata only — never a blob.** The Postgres backend selects
  `octet_length(blob)`, so the ciphertext never leaves the database for this
  route. Collecting an envelope is still the separate
  `GET /v1/vaults/{vaultID}/keys/{deviceID}`.
- **Per-vault filtering:** each candidate row is checked with the ordinary
  `authorizeVault(… needRead)`, and a vault the caller may not read is **silently
  omitted** rather than raising — so the list is exactly "what I may fetch".
  `needRead` **never claims** an unowned vault.
- **Ordering** is by vault id, stable across backends. An unknown recipient is
  **not** an error — it lists zero vaults.
- **Success — `200 OK`:**

  ```json
  {
    "device_id": "dev_B",
    "vaults": [
      { "vaultID": "demo", "sender_device_id": "dev_A", "size_bytes": 1310, "created_at": "<RFC3339>" }
    ],
    "has_more": false
  }
  ```

  At most **500** rows (`maxRecipientIndexRows`) are returned; beyond that
  `has_more` is `true`. ⚠️ There is deliberately **no cursor** — a device with
  more than 500 covered vaults cannot page past the first 500.

  > ⚠️ **AND NO CLIENT IN THIS REPO READS `has_more` ON THIS ROUTE** (found by the
  > fourth audit). A **recovery kit covering more than 500 vaults would silently
  > recover the first 500 and report success** — the worst shape a truncation can
  > take, because the person using it is by definition unable to check against
  > anything else. The server is honest; the clients ignore the flag. No cursor
  > exists to fix it with, so closing this properly means adding one. Until then,
  > treat 500 covered vaults as the kit's real ceiling.

- **Errors:**

  | Status | `error` code | When |
  |--------|--------------|------|
  | `400 Bad Request` | `missing_device_id` | no device ID in the path |
  | `401 Unauthorized` | `unauthorized` | v3 signature check failed — including a **revoked** device |
  | `403 Forbidden` | `forbidden` | the path device is **not** the authenticated device — **and the same answer for an unknown device id** |
  | `500 Internal Server Error` | `internal` | the store could not be read |
  | `501 Not Implemented` | `not_implemented` | dev-ops off, or no registry configured |

### Audit log

Six events, all **metadata plus (where there is a blob) a fingerprint** — the
envelope bytes, the vault key, the hybrid public keys, signatures and nonces are
**never** logged:

| Event | Fields |
|-------|--------|
| `device.hybrid_key_published` | `request_id`, `device_id`. The key bytes are public, but are still not logged: an audit line is not a key-distribution channel |
| `vault.key_envelope_put` | `request_id`, `vault_id`, `recipient_device_id`, `sender_device_id`, `size_bytes`, `blob_sha256` (hex SHA-256 of the opaque envelope) |
| `vault.key_envelope_get` | `request_id`, `vault_id`, `recipient_device_id`, `size_bytes`, `blob_sha256` |
| `vault.key_envelope_list` | `request_id`, `vault_id`, `device_id` (the caller), `returned_count`. **No `blob_sha256`** — the route never reads a blob, so there is nothing to fingerprint |
| `vault.key_envelope_delete` | `request_id`, `vault_id`, `recipient_device_id`, `device_id` (the caller). Records **who removed whose** envelope; again no blob is read |
| `device.key_envelope_index` | `request_id`, `device_id` (the caller, who is also the subject — the route is self-only), `returned_count`. **No `blob_sha256`**, no vault list: the route reads no blob, and the log is not a place to mirror a device's coverage |

The shared `blob_sha256` lets an operator correlate "the sender uploaded X" with
"the recipient collected X" **without the server retaining the ciphertext**.
Denials are audited by the existing `oplog.auth_denied` path with the fixed reason
enum.

### Client support (the `sigil` CLI)

The CLI implements the whole flow (see [`../cli/src/main.rs`](../cli/src/main.rs)
and [`../cli/src/lib.rs`](../cli/src/lib.rs)):

| Command | Routes it calls |
|---------|-----------------|
| `sigil device hybrid-publish [--key <f>] [--hybrid-key <f>] [--regenerate] [--server <url>]` | `PUT /v1/devices/{deviceID}/hybrid-key` — generates the hybrid identity if absent (secret `0600`, never uploaded), publishes only the public half |
| `sigil vault rekey --vault <id> [--file <vaultfile>] [--publish] [--keyring <f>]` | none, unless `--publish` → `PUT /v1/vaults/{vaultID}/keys/{deviceID}` (wraps the new key to **this** device) |
| `sigil vault share --vault <id> --to <deviceID> [--permission read\|write] [--pins <f>] [--envelope-out <f>]` | `GET /v1/devices/{to}/hybrid-key` **through the pin check**, then `PUT /v1/vaults/{vaultID}/keys/{to}`, then `POST /v1/vaults/{vaultID}/grants`. **Refuses** (nothing wrapped, nothing uploaded) if the recipient's key changed since it was pinned |
| `sigil vault accept --vault <id> [--hybrid-key <f>] [--envelope-out <f>] [--for <deviceID>]` | `GET /v1/vaults/{vaultID}/keys/{deviceID}` — collect, unwrap, store the key locally |
| `sigil vault rotate --vault <id> --to <deviceID> [--to <deviceID> …] [--file <f>] [--pins <f>]` | `GET /v1/devices/{to}/hybrid-key` **for every recipient first** (a pin mismatch aborts before anything is touched), then `PUT …/keys/{to}` per recipient, then `GET /v1/vaults/{vaultID}/keys` and `DELETE …/keys/{deviceID}` for every device **not** named |
| `sigil vault list [--keyring <f>]` | none — prints which vaults this device holds a key for, as **fingerprints only** |
| `sigil device safety-number [<deviceID>] [--pair <deviceID>]` | `GET /v1/devices/{deviceID}/hybrid-key` when given a target (**read-only — never pins and never re-pins**); with no argument it is purely local and works offline |
| `sigil device pins [--pins <f>]` | none — lists the hybrid public keys this client **trusts**, their safety numbers, when they were pinned, and any **re-pin count** |
| `sigil device repin <deviceID> --yes [--safety-number "<digits>"]` | `GET /v1/devices/{deviceID}/hybrid-key`, then replaces the local pin. ⚠️ The **only** way a changed key is ever accepted: refuses without `--yes`, and refuses if the `--safety-number` supplied does not match the key the server is presenting right now |

Supporting client state, none of which is ever uploaded:

- the **hybrid secret identity** at `<identity>.hybrid` (default
  `$HOME/.sigil/device.hybrid`), mode `0600`, with the shareable public half at
  `<identity>.hybrid.pub`;
- the **vault keyring** at `$HOME/.sigil/vault-keys.json` (override with
  `--keyring`), mode `0600`, JSON `{"version":1,"keys":{"<vaultID>":"<b64 32 bytes>"}}`;
- the **hybrid-key pin store** at `$HOME/.sigil/hybrid-pins.json` (override with
  `--pins`; it also follows `--keyring`'s directory), mode `0600` in the `0700` state
  dir, JSON `{"version":1,"pins":{"<deviceID>":{device_id, x25519_public_key,
  mlkem_encaps_key, safety_number, pinned_at, repins}}}`. It holds only **public** key
  material, but it is security-critical **local** state — an attacker who can rewrite
  it can silence the key-substitution alarm — so it gets the same treatment as a
  secret. The **desktop app uses the same file in the same directory**, so a `sigil`
  pin and a desktop pin are one record ([ADR 0037](decisions/0037-desktop-reuses-cli-library-for-protocol.md)).

`sigil totp add|list|code|remove|import|export` gained **`--vault-id <id>`**, which
opens a file with the **vault key** for `<id>` instead of `SIGIL_PASSWORD`
(`--vault <file>` keeps its existing meaning, so every existing invocation behaves
exactly as before), plus `--keyring <file>`; `sigil totp code` gained `--at <unix>`
to pin the instant for reproducible testing. `--for <deviceID>` on `vault accept`
is a **diagnostic** that asks for someone else's envelope so the `403` rule is
testable from the outside — it never attempts to unwrap.

The CLI **never prints a vault key**: `rekey` / `share` / `accept` / `list` show
only `key_sha256=<16 hex chars>`, the first 8 bytes of the key's SHA-256, so two
devices can confirm they hold the same key without revealing it.

### Client support (the browser + Node clients)

The **browser clients implement the same flow**, through
[`../sigil-wasm/sharing.mjs`](../sigil-wasm/sharing.mjs) — a framework-free,
dependency-free ESM module that runs in Node **and** the browser and is used by
`web/apps/webapp` (via the `@sigil/wasm` loader) and by the MV3 `extension/` (via
its vendored copy). It covers all four routes, plus the two composed operations:

| Module function | Route it calls |
|-----------------|----------------|
| `publishHybridKey(wasm, auth, secretIdentity?)` | `PUT /v1/devices/{deviceID}/hybrid-key` — publishes only the public halves, into **this** device's slot |
| `fetchHybridKey(wasm, auth, deviceId)` | `GET /v1/devices/{deviceID}/hybrid-key` |
| `putKeyEnvelope(wasm, auth, vaultId, recipientDeviceId, envelopeBytes)` | `PUT /v1/vaults/{vaultID}/keys/{deviceID}` |
| `getKeyEnvelope(wasm, auth, vaultId, deviceId?)` | `GET /v1/vaults/{vaultID}/keys/{deviceID}` (defaults to `auth.deviceId`) |
| `verifyRecipientForWrap(wasm, auth, deviceId, opts?)` | `GET /v1/devices/{deviceID}/hybrid-key` **plus the pin check, the safety-number check and the recovery-kit refusal, in one call** — ⭐ **the gate every wrap path goes through**, and the only thing that produces a value the wrap accepts. `pins` defaults to `auth.pins`. **Throws `KeyPinMismatchError`** on a changed key. (The older `fetchHybridKeyPinned` / `fetch_hybrid_key_pinned` were **superseded in Phase 54 and DELETED in Phase 57** — they pinned but did not refuse an unverified recovery kit, so a caller reaching for the familiar name got a weaker gate; see [ADR 0038](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)'s addenda) |
| `listKeyEnvelopes(wasm, auth, vaultId)` | `GET /v1/vaults/{vaultID}/keys` — metadata only |
| `deleteKeyEnvelope(wasm, auth, vaultId, deviceId)` | `DELETE /v1/vaults/{vaultID}/keys/{deviceID}` — returns `false` on a `404` rather than raising |
| `shareVault(wasm, auth, {vaultId, recipientDeviceId, vaultKey, permission, pins?})` | `GET …/hybrid-key` **through `verifyRecipientForWrap`**, then `PUT …/keys/{to}`, then `POST …/grants` — the same composition as `sigil vault share`, so authorization and key distribution cannot drift. Returns `pinStatus` + `safetyNumber` so a UI can say whether the key has ever been human-verified |
| `acceptVault(wasm, auth, {vaultId, secretIdentity?})` | `GET …/keys/{deviceID}` — collect, unwrap, return the 32-byte key |
| `rotateVaultKey(wasm, auth, {vaultId, recipientDeviceIds, sealedVault, oldVaultKey, params, pins?})` | pin-checks **every** recipient first, then `PUT …/keys/{to}` per recipient, then `GET …/keys` + `DELETE …/keys/{deviceID}` for everyone else. Returns the new key and the re-sealed container — **the caller persists and pushes them** |

`auth` is exactly the object `openDeviceIdentity` returns plus a `baseUrl`, so an
unlocked client passes its device identity straight in. Supporting surface:
`generateHybridIdentity` / `hybridPublicIdentity`, `generateVaultKey` /
`vaultKeyFingerprint` (the same 16-hex SHA-256 prefix the CLI prints — a vault key is
never rendered), `wrapVaultKey` / `unwrapVaultKey`, and `explainSharingStatus`, which
extends `explainAuthStatus` with the statuses only these routes produce (`403` not the
addressee / not permitted, `404` nothing published or shared yet, `409` revoked
recipient, `413` oversized). **All KEM/AEAD work happens in the wasm**
(`hybrid_seal_to_container` / `hybrid_open_container`) and every request signature goes
through `device-auth.mjs`; the module hand-rolls nothing. Entropy is JS-supplied
(`crypto.getRandomValues`) for the hybrid identity, each vault key, and the per-wrap
ephemeral X25519 secret / ML-KEM coin / AEAD nonce. `unwrapVaultKey` rejects any
recovered plaintext that is not exactly 32 bytes rather than using it as a key.

The browser clients store the hybrid secret identity, every accepted vault key **and
(since Phase 50) the hybrid-key pin store** inside their sealed device-identity
container — schema **v3**, field `pins` — never in plaintext web storage. A v1 or v2
container still opens and yields an **empty** pin store, so an existing client keeps
working and simply pins on next use. See
[ADR 0036](decisions/0036-browser-sharing-secret-storage.md) and
[ADR 0038](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md).

⚠️ **That container is sealed under the vault password — except in the webapp with
passkey protection on**, where both it and the TOTP vault are sealed under a
**container master key** derived from the printed recovery seed, and the CMK itself
is wrapped in a third sealed container under a WebAuthn PRF output concatenated with
the password ([ADR 0046](decisions/0046-passkey-protected-local-containers.md)). That
is an **at-rest** change on one client only. It is invisible on the wire: this server
sees the same signed requests and the same opaque bytes either way.

The pinning surface itself calls **no route**: `safetyNumber` / `pairwiseSafetyNumber`
/ `renderSafetyNumber`, `newPinStore` / `requirePinStore` / `checkAndPin` /
`repinHybridKey` and the `KeyPinMismatchError` class are pure local computation over
`crypto.subtle`. `requirePinStore` **fails closed**: a missing store throws rather than
defaulting to an empty one, so a caller that forgets to pass its pins cannot silently
degrade pinning into a no-op.

The semantics are **MIRRORED — not shared — from `sharing.go` (this server, the source
of truth) and `cli/src/lib.rs`**; drift yields a `400`/`403` or an envelope the CLI
cannot open, so the guard is
[`../sigil-wasm/test/sharing-interop.mjs`](../sigil-wasm/test/sharing-interop.mjs),
which boots a **real** sigild, builds the **real** `sigil` binary, and shares a vault
**both ways** between the JS client and the CLI (both ends reaching the same key
fingerprint and the same RFC 6238 code), plus the `403` negatives.

### Client support (the native desktop app)

The **desktop client was the last holdout, and no longer is**: `desktop/core/src/net.rs`
implements enrollment, contract-v3 signed sync **and** sharing, so **all four client
surfaces** (CLI, webapp, MV3 extension, native desktop) now drive these routes. It is
the odd one out in *how*: rather than mirroring the protocol a fourth time it **links
the `sigil-cli` library** and calls `publish_hybrid_key` / `fetch_hybrid_key`,
`put_key_envelope` / `get_key_envelope`, `wrap_vault_key` / `unwrap_vault_key` and
`grant_vault_access` — the same functions the `sigil` binary calls — behind
`DeviceConfig::{enroll, publish_hybrid, push_vault, pull_vault, share_vault,
accept_vault, status, check_server}` and eleven Tauri commands
([ADR 0037](decisions/0037-desktop-reuses-cli-library-for-protocol.md)). Consequences
worth knowing when reading the rest of this document:

- **There is no desktop HTTP client, signer or canonical message.** Everything on the
  wire is produced by `sigil-cli`, so the desktop cannot drift from the CLI's bytes.
- **Its state files are the CLI's files** — `device.key`, `device.hybrid`(`.pub`) and
  `vault-keys.json`, mode `0600` in a `0700` state directory that defaults to
  `$HOME/.sigil`. Point `sigil --key` (or `HOME`) at a desktop state directory and it is
  the same device on this server.
- **Contract selection is the CLI's rule**, unchanged: v3 when enrolled, legacy v2 for
  an identity with no device id, unsigned with no identity.
- **Phase 50 came for free, for the same reason.** The desktop calls
  `verify_recipient_for_wrap` (the gate; it called the since-deleted
  `fetch_hybrid_key_pinned` before Phase 54), `rotate_vault_key` and
  `repin_hybrid_key` from the same
  library and keeps its pins in the **same `hybrid-pins.json`** in the same state dir,
  so there is no second pin store and no second safety-number implementation to keep in
  sync. `DeviceConfig::{peer_safety_number, pairwise_safety_number, pins, repin_device,
  rotate_vault}` surface it, and a mismatch reaches the UI as
  `DesktopError::KeyPinMismatch`, tagged `"key changed"`.
- **Proof:** [`../desktop/core/tests/server_interop.rs`](../desktop/core/tests/server_interop.rs)
  boots a **real** sigild (dev-ops + device auth) and builds the **real** `sigil`
  binary, and shares a vault **both ways** — desktop → CLI and CLI → desktop, each
  reaching the same key fingerprint and the same RFC 6238 code — plus the `403` for an
  unauthorized third device, a clear not-enrolled error rather than a panic, and a clear
  unreachable error with the offline flow still generating codes.

### Honest limits (read before believing any of the above)

- **Dev-gated (`501` by default), plain HTTP, localhost, UNAUDITED.** Do not
  expose it and do not store real 2FA secrets.
- **Key substitution is blocked after first contact — not at it.** Clients pin a
  device's hybrid public key and hard-refuse a changed one, so a registry that
  substitutes a key after you have seen the real one is stopped with nothing wrapped
  and nothing uploaded. The **first** fetch is still trust-on-first-use: the
  **safety number** exists to close that window, but only if a human actually
  compares it out of band, and a user who re-pins without checking gives the
  attacker what the block prevented. There is still **no key transparency and no
  cross-signature** binding a hybrid key to the device's enrolled Ed25519 identity
  ([ADR 0038](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)).
- **Revocation does not un-share, and rotation only protects the future.** Revocation
  stops **future server access**; a device that already collected and unwrapped an
  envelope keeps the vault key and whatever it copied. `vault rotate` is the
  remediation — a fresh key, the vault re-sealed, re-wrapped to exactly the named
  devices, every other envelope deleted — but it is **manual and owner-driven**:
  nothing re-keys automatically on revoke and there is **no rotation schedule**.
- **No forward secrecy for a delivered vault key**, and republishing a hybrid key
  does not re-wrap already-deposited envelopes.
- **One mailbox per (vault, recipient).** A deposit is an upsert, so any device with
  `write` access can overwrite an envelope another writer deposited.
- **No rate limiting** on these routes — the per-vault limiter covers appends only,
  and the abuse limiters cover enrollment and invite minting only.
- **Request authentication is classical Ed25519** (contract v3). The wrap is
  PQ-hybrid; the signature over the request is not, and **the system is not
  "post-quantum secure"**.
- **Client-side key storage is only as strong as its host, and differs per client.**
  The CLI **and the native desktop app** keep the hybrid secret and the keyring in the
  *same* `0600` plaintext files; the browser clients seal both into the device-identity
  container (stronger at rest) but hold them **unzeroized in JS memory** while the vault
  is unlocked. Nothing is zeroized on any client. Since Phase 58 the **webapp** can add a
  second at-rest factor (a WebAuthn PRF output) to that container
  ([ADR 0046](decisions/0046-passkey-protected-local-containers.md)); the extension and
  the desktop cannot, so the per-client asymmetry is now three-way.

---

## Recovery kits (DEV-GATED) — Phase 54

> **DEV-GATED and UNAUDITED.** ⭐ **`sigild` has NO concept of "recovery".** There
> is no recovery table, no recovery flag, no recovery route, and **no migration**
> — `sigild_schema_version` stays **5**. This section exists because an operator
> and an auditor need to know what a recovery kit *looks like on the wire*, which
> is: **an ordinary device**. See [ADR 0042](decisions/0042-recovery-kit.md), and
> [`crypto-spec.md`](crypto-spec.md#recovery-kit--a-printable-paper-key) for the
> format and derivation.

A **recovery kit** is a member device whose Ed25519 identity and hybrid
(X25519 + ML-KEM-768) identity are **HKDF-SHA256 derivations of 32 bytes of
client CSPRNG printed on paper** — never transmitted, never stored on a device,
and **never derivable from anything the server holds**.

**Everything the server sees, it already served before:**

| What the kit does | The request it makes | What the server stores |
|-------------------|----------------------|------------------------|
| joins the account | `POST /v1/devices/enroll` with an ordinary invite + proof of possession | one more device row, label `"recovery-kit"` |
| publishes its key | `PUT /v1/devices/{kitID}/hybrid-key` | one more **public** hybrid key |
| is covered for a vault | `PUT /v1/vaults/{vaultID}/keys/{kitID}` + `POST /v1/vaults/{vaultID}/grants` | one more **opaque** ~1.3 KiB `SIGILhyb` envelope (length varies with the ids), and a grant |
| finds itself after a restore | `GET /v1/devices/{kitID}/keys` ([above](#get-v1devicesdeviceidkeys--which-vaults-hold-a-key-for-me-self-only-metadata-only)) | nothing — it is a read |
| collects a key | `GET /v1/vaults/{vaultID}/keys/{kitID}` | nothing — it is a read |
| is retired | `POST /v1/devices/{kitID}/revoke` | the ordinary revocation |

**The label is deliberately visible.** A kit enrols under the device label
`"recovery-kit"`, which appears in `GET /v1/account`. Hiding it would buy only
protection against targeted denial and would cost every client the ability to
show a user whether recovery is set up.

⭐ **The security-critical part is entirely client-side.** Wrapping a vault key to
a kit goes through the same pinned-fetch choke point as any other wrap
([ADR 0038](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)),
with one extra rule: a **first-sight** wrap to a device the client believes is a
recovery kit is **REFUSED** unless the caller supplies the safety number printed
on the sheet. `sigild` neither knows nor enforces this — it stores no pin, no
safety number and no trust state.

⚠️ **The residual limit, stated exactly.** Recognising that a recipient *is* a
kit resolves the device **label** from `GET /v1/account` — a listing the
**adversarial server serves**. **A server that renames or hides the label
degrades `vault share` / `vault rotate` to a kit back to ordinary first-sight
TOFU (warned and pinned) rather than a refusal.** The caller-**asserted** paths
(`sigil recovery cover`, `sigil recovery generate`) do not depend on the server
and are unaffected, and **no path anywhere accepts a changed key or a mismatched
safety number**. So the honest claim is **"refuses first-sight kit wraps against a
server that does not lie about labels"**, *not* "refuses first-sight kit wraps".

### Honest limits

- ⚠️ **WHOEVER HOLDS THE PAPER HAS FULL CONTROL OF THE ACCOUNT** — read every
  covered vault, revoke every device. It is **stronger than a stolen locked
  phone**: no OS lock, no biometric, no vault password stands in front of it. Its
  nominal `read` grant is **cosmetic**, because account ownership authorizes it
  regardless.
- ⚠️ **It recovers KEYS, not DATA.** A vault that was never synced to this server
  is gone.
- ⚠️ **It only opens the vaults it was told to COVER**, as of the print date. A
  vault created later needs `sigil recovery cover`, and nothing reminds anyone.
- ⚠️ **A kit cannot be created after the loss.**
- ⚠️ **A kit consumes a seat** against `SIGILD_ACCOUNT_MAX_DEVICES`, appears in
  `GET /v1/account`, and can be revoked by **any** member — membership is flat.
- **Client coverage is now complete across all four surfaces** (Phase 56). The
  **`sigil` CLI** (`recovery generate | cover | check | verify | restore |
  revoke`), the **webapp** (a `RecoveryPanel` in the unlocked vault plus a
  `RestorePanel` on **both the setup and locked screens** — restore is
  deliberately not behind an unlocked vault, because a fresh install is where it
  is needed), the **MV3 extension** (the same flow, restore reachable from the
  locked/setup views) and the **desktop** (`recovery_*` commands over the
  `sigil-cli` library — no second copy of the codec or derivation) can all
  generate, cover, check, revoke and **restore**. ⚠️ The browser suites drive a
  **test double**, not a real `sigild`; real-server conformance stays in
  `cli/tests/e2e-recovery.sh` and `sigil-wasm/test/recovery-interop.mjs`. Print
  output is **not** verified — headless Chromium cannot render a printed page, so
  the `@media print` rules are by-eye.
- ⚠️ **Dev-gated, plain HTTP, UNAUDITED.**

---

## Billing / subscriptions (DEV-GATED, opt-in) — Phase 45

> **DEV-GATED, OPT-IN, UNAUDITED, and NEVER RUN AGAINST A LIVE PROVIDER
> ACCOUNT.** The signature verification, the state machine, the idempotency
> ledger and the storage are **real** — real `crypto/hmac` over the raw request
> body, real constant-time comparison, real transactional dedupe — but **no
> request in this repository has ever been sent to, or received from,
> `api.stripe.com`, `api.razorpay.com` or `api.juspay.in`.** Every test drives a
> local `httptest` server with fake credentials. Provider webhook schemes must be
> **confirmed against each merchant's live dashboard** before any real money
> moves; the **Juspay** scheme in particular is explicitly
> *UNVERIFIED-AGAINST-LIVE-DASHBOARD* (see below). This is not a payment
> integration you should point at production. See
> [`decisions/0034-billing-provider-seam.md`](decisions/0034-billing-provider-seam.md).

Sigil is a **paid** product, so `sigild` grew a **provider-agnostic billing
seam**: one `billing.Provider` interface, three adapters — **Stripe**
(international), **Razorpay** and **Juspay** (India) — a **normalized event
vocabulary**, a **subscription state machine**, and an **idempotent** apply path
backed by in-memory or Postgres storage.

Two properties frame everything below:

- **No card data ever reaches this server.** Every adapter uses the provider's
  **hosted checkout / payment-link** flow: `sigild` asks the provider for a URL
  and hands that URL to the client. There is deliberately **no field on any
  request, response, struct, log line, metric or database column** that could
  carry a PAN, CVV, expiry, cardholder name or billing address — and none that
  carries an email or phone number either. PCI scope stays at SAQ-A.
- **Zero-knowledge is untouched.** No billing handler reads, writes or derives
  anything about a vault blob, and migration `0003_billing.sql` touches nothing
  in `sigil_vault_ops`.

### Routes at a glance — and which auth applies to which

| Route | Auth | Body cap | Success |
|-------|------|----------|---------|
| `POST /v1/billing/checkout` | **device auth v3** (`authenticateDevice`, the *same* choke point as the ops routes) | 8 KiB | `201` + hosted checkout URL |
| `POST /v1/billing/webhook/{provider}` | **the provider's own signature over the raw body** — *no* device auth | 64 KiB | `200` + outcome |
| `GET /v1/billing/subscription` | **device auth v3** | — (no body) | `200` + the caller's status |

The split is deliberate and is the whole reason the webhook route exists outside
the device model: **checkout and subscription come from a device**, which holds
an enrolled Ed25519 key and can sign the v3 contract; **a webhook comes from the
payment provider**, which has no device key and cannot. So the webhook is
authenticated by the provider's HMAC (or, for Juspay's basic scheme, its
endpoint credentials) and by nothing else — and correspondingly it can **create
no session, read no vault, and name no subject of its own choosing**.

**The subject is server-derived.** Since Phase 52 a checkout's subject is the
authenticated device's **ACCOUNT ID** (`acct_…`), derived from the verified
signature and **never** read from the request body;
`GET /v1/billing/subscription` likewise reports only the caller's own account and
takes no subject parameter. A client therefore cannot buy — or query — a
subscription on another subject's behalf, because there is no body, query or path
field anywhere that names one. "Subject" now means **account**, so paying on one
device entitles the others ([Account model](#account-model-dev-gated--phase-52));
it is still **not** an identity — no email, no password, and no recovery beyond a
**paper kit printed in advance** (see the limits at the end of this section).

### Default posture — the deliberate `501`

Billing is **doubly off by default**. It requires *both*:

1. `SIGILD_ENABLE_DEV_OPS` (the whole stateful surface is dev-gated), **and**
2. `SIGILD_BILLING_PROVIDERS` naming at least one provider, **and** a
   subscription store, **and** a device registry (`SIGILD_DEVICE_AUTH`).

With any of those missing, **all three routes** return `501` — never `404`, and
never partial or faked behaviour:

```json
{ "error": "not_implemented", "detail": "billing is not enabled on this server" }
```

Body caps still apply before the stub runs, so an oversized request gets `413`
rather than `501`. `GET /metrics` stays `200` throughout (it is never dev-gated);
the billing counters simply read `0`.

### `POST /v1/billing/checkout` — create a hosted checkout session

**Auth: device auth v3.** Identical to the ops routes: `X-Sigil-Device`,
`X-Sigil-Timestamp`, `X-Sigil-Nonce`, `X-Sigil-Signature` over the canonical v3
message (`"sigil-oplog-auth-v3\n" + DEVICE_ID + …+ BODY`, see
[above](#signed-request-contract-v3)). The body is read **first** so it can be
covered by the signature, and only then authenticated — the same order the
op-log append uses. No billing-specific token, no API key, no second auth path.

Request body (optional; `{}` or an empty body is valid):

```json
{ "provider": "stripe", "plan": "price_1234" }
```

| Field | Meaning |
|-------|---------|
| `provider` | which enabled provider to use. Omitted ⇒ `SIGILD_BILLING_DEFAULT_PROVIDER`. |
| `plan` | optional per-request plan override — a Stripe **price ID**, or a Juspay **payment-page client ID**. Omitted ⇒ the adapter's configured default. |

Note what is **absent**: no subject (server-derived), no amount override, and no
payment-instrument field of any kind.

⭐ **The subject is the authenticated device's ACCOUNT (Phase 52), not the
device.** That is the whole point of the account model on this route: a customer
who pays on their phone is entitled on their laptop, and a cancel, refund or
chargeback demotes the **account** at once rather than one device. It is still
**server-derived** — there is no body, query or path field anywhere that names a
subject — and a device carrying **no account** is refused with a coarse `403`
(`missing_account`) **before** the provider or the store is touched, never
falling back to the device id.

`201 Created`:

```json
{
  "provider": "stripe",
  "session_id": "cs_test_…",
  "url": "https://checkout.stripe.com/c/pay/cs_test_…",
  "expires_at": "2026-07-26T18:30:00Z"
}
```

`session_id` and `expires_at` are omitted when the provider does not return
them. The client redirects the customer to `url`; the card details are entered
**there**, at the provider.

| Status | `error` | When |
|--------|---------|------|
| `201` | — | session created |
| `400` | `invalid_request` | body unreadable, over 8 KiB, or not a JSON object |
| `400` | `unknown_provider` | `provider` names something not enabled on this server |
| `401` | `unauthorized` | device auth failed (missing/invalid/stale signature, unknown or revoked device, replayed nonce) — coarse body, exact reason only in the audit log |
| `413` | `payload_too_large` | `Content-Length` exceeds the 8 KiB cap |
| `500` | `internal` | reference generation, the subscription store, or an adapter reporting `ErrNotConfigured` (a **server** misconfiguration, deliberately not surfaced as a client error) |
| `502` | `provider_error` | the provider API call failed — `{"error":"provider_error","detail":"the payment provider could not create a checkout session"}` |
| `501` | `not_implemented` | billing off |

**Before** calling out to the provider, the server records `StartCheckout`
(subject → provider) so a webhook that races the HTTP response still has a row to
resolve against. The per-attempt reference is **server-generated**
(`"sigil-" + hex(12 random bytes)`) and used as the provider's idempotency key /
`reference_id` / `order_id`, so a client can neither collide with nor overwrite
another attempt. The outbound call is bounded twice: a 12 s request-scoped
context (`billingProviderTimeout`) on top of the adapter client's own 10 s
timeout, and at most 1 MiB of provider response is read.

### `POST /v1/billing/webhook/{provider}` — provider callback

**Auth: the provider's signature over the RAW request body. No device auth, no
session, no bearer token.** `{provider}` must be one of `stripe`, `razorpay`,
`juspay` **and** must be enabled on this server.

The body is read **once** and the exact bytes are kept: the signature is verified
over **those bytes first**, and only then is the JSON parsed. Verifying a
re-encoded payload would be a bug — a JSON round-trip reorders keys and drops
whitespace, so the MAC would never match (or, if "fixed" by re-signing, an
attacker could mutate the body freely).

#### Per-provider webhook contract

| Provider | Header carrying the signature | What is signed (the MAC message) | MAC / encoding | Timestamp bound |
|----------|-------------------------------|----------------------------------|----------------|-----------------|
| **Stripe** | `Stripe-Signature: t=<unix>,v1=<hex>[,v1=<hex>][,v0=…]` | `"<t>" + "." + RAW_BODY_BYTES` | HMAC-SHA256 keyed by the **endpoint signing secret** (`whsec_…`), lowercase hex | **yes** — `abs(now − t) ≤ 5 min` (`stripeDefaultTolerance`), checked in **both** directions |
| **Razorpay** | `X-Razorpay-Signature: <hex>` | `RAW_BODY_BYTES` — no timestamp, no prefix, no separator | HMAC-SHA256 keyed by the dashboard **webhook secret**, lowercase hex | **none in the scheme** — replay is bounded only by our idempotency ledger |
| **Juspay**, `scheme=hmac` (**default**) | `X-Juspay-Signature` (**name configurable** via `SIGILD_JUSPAY_WEBHOOK_SIG_HEADER`) | `RAW_BODY_BYTES` | HMAC-SHA256 keyed by `SIGILD_JUSPAY_WEBHOOK_SECRET`, lowercase hex | none |
| **Juspay**, `scheme=basic` (**explicit opt-in only**) | `Authorization: Basic base64(user:pass)` | *nothing* — this authenticates the **connection**, not the body | constant-time compare of both halves | none |

Details that matter:

- **Stripe**: **every** `v1` element is compared (Stripe sends more than one
  while an endpoint secret is being rotated — accepting any one is what makes
  rotation zero-downtime), with **no early exit**, so neither the number of
  candidates nor which matched is observable in timing. Legacy **`v0` elements
  are ignored**, never accepted — accepting them would be a downgrade path.
- **Razorpay**: the **idempotency key is derived from the signed body**, always —
  `"body-" + hex(SHA-256(raw body))`. The **`X-Razorpay-Event-Id`** header is kept
  only as a **correlation label** for the dashboard and the audit log, and is never
  a security decision, because Razorpay's signature covers the body and nothing
  else: a captured valid delivery replayed with a fresh header would otherwise
  look like a new event ([ADR 0039](decisions/0039-webhook-idempotency-from-signed-bytes.md)).
  *The header name is part of the unverified surface.*
- **Juspay, basic scheme — stated plainly**: HTTP Basic auth proves the caller
  knows a shared password; it does **not** prove the payload was not modified in
  transit, and anyone holding the credential can post any body. `hmac` is
  therefore the **default**, and `basic` must be requested by name; where only
  basic is available the endpoint **must** be TLS-only and the credential treated
  as a bearer secret. `sigild` logs a `WARN` naming that limitation at every boot
  under `scheme=basic`.
- All comparisons use `hmac.Equal` / `subtle.ConstantTimeCompare`; a hex string
  that fails to decode is simply "not equal", so a malformed and a wrong
  signature are indistinguishable.

#### Normalized event types

Each adapter maps its provider's vocabulary onto exactly one normalized type, so
the state machine and the HTTP layer never learn a provider dialect:

| Normalized type | Stripe | Razorpay | Juspay |
|-----------------|--------|----------|--------|
| `checkout_completed` | `checkout.session.completed` | `payment_link.paid` | `ORDER_SUCCEEDED` |
| `subscription_activated` | `customer.subscription.created` / `.updated` with object status `trialing`/`active` | `subscription.activated`, `subscription.authenticated`, `subscription.resumed` | `MANDATE_CREATED`, `MANDATE_ACTIVATED` |
| `subscription_renewed` | `invoice.paid`, `invoice.payment_succeeded` | `subscription.charged` | `TXN_CHARGED`, `MANDATE_NOTIFICATION_SUCCEEDED` |
| `subscription_canceled` | `customer.subscription.deleted`; `.created`/`.updated` with status `canceled`/`incomplete_expired` | `subscription.cancelled`, `subscription.completed`, `subscription.expired` | `MANDATE_REVOKED`, `MANDATE_EXPIRED`, `MANDATE_PAUSED` |
| `payment_failed` | `invoice.payment_failed`; `.created`/`.updated` with status `past_due`/`unpaid` | `subscription.halted`, `subscription.pending`, `payment.failed` | `ORDER_FAILED`, `TXN_FAILED`, `MANDATE_NOTIFICATION_FAILED` |
| `ignored` | anything else | anything else | anything else |

For Stripe the **status on the object** decides, not the event name alone: an
`updated` event is how Stripe reports a trial ending, a card failing, and a
cancellation scheduled at period end.

`ignored` is an explicit verdict, not a fallthrough bug: providers send events we
do not model (refund notices, mandate reminders, test pings), and those **must**
be a `200` with no state change so the provider does not enter a retry/backoff
loop against us.

**Subject attribution.** Each adapter writes our subject into the provider's
pass-through field at checkout and reads it back on the webhook: Stripe
`client_reference_id` **plus** `subscription_data[metadata][sigil_subject]`,
Razorpay `notes.sigil_subject`, Juspay `udf1` (with
`metadata.sigil_subject` as a fallback). The namespaced key is
**`sigil_subject`**. When an event carries no such marker, the store resolves the
subject from `(provider, subscription_ref)` instead.

#### Subscription state machine

States: `none` → *(implicit, no record)*, `trialing`, `active`, `past_due`,
`canceled`. Legal transitions (**everything else is rejected**):

```
none      -> trialing | active
trialing  -> active | past_due | canceled
active    -> active (renewal) | past_due | canceled
past_due  -> active | canceled
canceled  -> trialing | active          (a NEW purchase after cancellation)
```

`active -> active` is legal and is how a **renewal** is recorded (it carries a
new `current_period_end`). `canceled` is not a dead end — a customer who cancels
and buys again must be able to become active — but it can only be left by an
event targeting an active state, so a late `payment_failed` cannot revive a dead
subscription into `past_due`. There is **no transition into `none`**.

**Entitlement** (`entitled: true`) covers `trialing`, `active` **and
`past_due`** — a failed renewal opens a provider-side retry window, and cutting a
paying customer off the instant a card declines is both hostile and usually
wrong. Cancellation is where entitlement ends.

Separately from legality, an event whose `OccurredAt` **precedes the last event
applied** is dropped as **stale**, so an out-of-order `payment_failed` cannot
regress a subscription that has since gone active. Legality and ordering are two
independent guards; both must pass.

#### The idempotency guarantee

**A duplicate delivery is a no-op that still answers `200`.** Providers redeliver
— on their own retry schedule, and again whenever an operator replays an event
from a dashboard — so this is a documented behaviour to design for, not an edge
case.

⭐ **The key is derived only from bytes the provider's signature covers**
([ADR 0039](decisions/0039-webhook-idempotency-from-signed-bytes.md)). Nothing an
attacker can vary while keeping a captured signature valid may feed it — otherwise
a replay with one header changed is not a duplicate at all, and the guarantee
above is false. Per provider:

| Provider | Idempotency key | Why it is covered |
|----------|-----------------|-------------------|
| **Stripe** | the event id **inside** the JSON payload | the signed message is `"<t>.<raw body>"`, so the id is inside it |
| **Razorpay** | **always** `"body-" + hex(SHA-256(raw body))` | the signature covers the body and nothing else, so a byte-identical body is exactly one event whatever the headers say |
| **Juspay** | the id parsed out of the **body**, else `"body-" + hex(SHA-256(raw body))` | both forms come out of the body, never a header — so under `scheme=hmac` the key is signature-covered. ⚠️ Under `scheme=basic` the invariant is **vacuous**: that scheme covers no bytes at all |

The key is therefore **`(provider, dedup key)`** — stored in the `event_id` column
of the ledger, which is why the API and the schema still speak of an event id.
Recording "we handled it" and applying the state change are **fused into one
atomic operation**
(`SubscriptionStore.ApplyWebhookEvent`): one mutex in the in-memory backend, one
**transaction** in Postgres, where the ledger insert is
`INSERT … ON CONFLICT (provider, event_id) DO NOTHING` and zero rows affected
*means* duplicate, with the subscription row taken `FOR UPDATE` so two events for
one subject serialize. A rollback leaves **both** the ledger and the record
untouched, so a retry is clean. Split across two calls, a crash in between would
either double-apply or lose an event; as one operation it cannot.

The response `status` reports the verdict:

```json
{ "provider": "stripe", "status": "accepted" }
```

| `status` | Meaning | State changed? |
|----------|---------|----------------|
| `accepted` | fresh, legal, in order — applied | **yes** |
| `ignored` | authentic but not a modeled event type | no |
| `duplicate` | `(provider, dedup key)` already processed — **the idempotency guarantee** | no |
| `stale` | predates the last applied event | no |
| `illegal` | not a legal transition from the current status | no |
| `unresolved` | no subject on the event and none resolvable from its subscription reference. **Deliberately not recorded as processed**, so a later event can establish the binding and this one can then be redelivered | no |

#### Webhook status codes, and why

| Status | `error` | When |
|--------|---------|------|
| `200` | — | **every** handled outcome above (`accepted`/`ignored`/`duplicate`/`stale`/`illegal`/`unresolved`) — all of them mean "we handled it, stop retrying" |
| `400` | `invalid_request` | the signature was valid but the body is unparsable, or the body could not be read |
| `401` | `unauthorized` | signature verification failed — **for any reason** |
| `404` | `unknown_provider` | `{provider}` is not a configured webhook endpoint on this server |
| `413` | `payload_too_large` | body exceeds the 64 KiB cap |
| `500` | `internal` | **our store failed.** Deliberately the *only* error class a healthy provider should ever see, because it is the only one that *should* be retried |
| `501` | `not_implemented` | billing off |

The `401` body is **coarse on purpose**: a missing header, a malformed header, an
unparsable signature, a wrong secret, a tampered body, and a stale timestamp all
produce the identical response, so a prober cannot learn which check tripped. The
precise reason goes only to the server-side audit log and the per-reason metric.

### `GET /v1/billing/subscription` — the caller's own status

**Auth: device auth v3** (signed with an empty body). The subject is **derived
from** the verified signature, so this endpoint **cannot be used to enumerate
other subjects** — there is no query parameter and no subject field to supply.
Since Phase 52 the subject is the signing device's **ACCOUNT**, so a **sibling
device that never ran checkout still sees the account's entitlement**.

`200 OK`:

```json
{
  "subject": "acct_AbCdEf…",
  "provider": "stripe",
  "status": "active",
  "entitled": true,
  "current_period_end": "2026-08-26T00:00:00Z",
  "updated_at": "2026-07-26T18:22:41Z",
  "entitlement": { "enforced": true, "writes": "allowed", "reads": "allowed" }
}
```

"Never subscribed" is a valid answer, not a fault — it returns `200` with
`{"subject":"…","status":"none","entitled":false}`. `provider`,
`current_period_end` and `updated_at` are omitted when unset. `401` on failed
device auth, **`403` when the signing device carries no account**
(`missing_account`), `500` on a store fault, `501` when billing is off.

The **`entitlement` block is additive and present only when
`SIGILD_ENTITLEMENT_ENFORCE` is on** ([below](#entitlement-enforcement-opt-in--phase-55));
with enforcement off this response is **byte-identical** to before. `writes` is
`allowed` / `grace` / `refused`, `reads` is the constant `"allowed"` (the
guarantee is stated in the payload, not only in this document), and
`grace_ends_at` (RFC3339) appears when applicable. ⭐ **This is the warning channel
for read-only clients**, which are never refused and would otherwise discover a
lapse only on their first write.

> **Cross-cutover subjects.** A hosted checkout started **before** migration
> `0005` put a **device** id into the provider's metadata, and a provider echoes
> that back forever. Incoming webhook subjects are therefore **resolved, not
> trusted**: a known account passes through, an enrolled device becomes its
> account, and anything else is **blanked** so the store falls back to its
> `(provider, subscription_ref)` lookup and, failing that, answers `unresolved`
> (a `200` that changes nothing). A provider-supplied string can never **invent**
> a subscription row. This is a lookup on an already-signature-verified value, so
> it adds no trust — it can only narrow what an event may touch.

### Configuration (environment)

| Variable | Required? | Meaning |
|----------|-----------|---------|
| `SIGILD_BILLING_PROVIDERS` | opt-in | Comma-separated: `stripe`, `razorpay`, `juspay`. **Unset ⇒ billing OFF.** Unknown or duplicate names are a **boot error**. Requires `SIGILD_ENABLE_DEV_OPS` **and** `SIGILD_DEVICE_AUTH`. |
| `SIGILD_BILLING_DEFAULT_PROVIDER` | optional | Which provider a checkout uses when the body names none. Must be one of the enabled providers. Unset ⇒ the first listed. |
| `SIGILD_BILLING_SUCCESS_URL` | **required when billing is on** | Absolute `http(s)` URL the provider returns a paying customer to. |
| `SIGILD_BILLING_CANCEL_URL` | **required when billing is on** | Absolute `http(s)` URL for an abandoned checkout. |
| `SIGILD_STRIPE_SECRET_KEY` | **required for `stripe`** | `sk_…`, sent as a bearer token. |
| `SIGILD_STRIPE_WEBHOOK_SECRET` | **required for `stripe`** | `whsec_…`, the **endpoint signing secret** — a *different* secret from the API key, used only as the HMAC key. |
| `SIGILD_STRIPE_PRICE_ID` | optional | Default `price_…` for the subscription line item. |
| `SIGILD_STRIPE_API_BASE_URL` | optional | API host override (default `https://api.stripe.com`). |
| `SIGILD_RAZORPAY_KEY_ID` / `SIGILD_RAZORPAY_KEY_SECRET` | **required for `razorpay`** | API credentials, sent as HTTP Basic auth. |
| `SIGILD_RAZORPAY_WEBHOOK_SECRET` | **required for `razorpay`** | Dashboard webhook secret; a *different* secret from the key secret. |
| `SIGILD_RAZORPAY_AMOUNT_MINOR` | optional | Default payment-link amount in **minor units** (paise). Must be a positive integer. |
| `SIGILD_RAZORPAY_CURRENCY` | optional | Default currency (adapter default `INR`). |
| `SIGILD_RAZORPAY_DESCRIPTION` | optional | Payment-link description. |
| `SIGILD_RAZORPAY_API_BASE_URL` | optional | API host override (default `https://api.razorpay.com`). |
| `SIGILD_JUSPAY_MERCHANT_ID` / `SIGILD_JUSPAY_API_KEY` | **required for `juspay`** | Merchant ID (sent as `x-merchantid`) and API key (Basic-auth username, empty password). |
| `SIGILD_JUSPAY_CLIENT_ID` | optional | Payment-page client ID. |
| `SIGILD_JUSPAY_WEBHOOK_SCHEME` | optional | **`hmac` (default)** or `basic`. Any other value is a **boot error**. `hmac` binds the body; `basic` authenticates only the **connection**, so it must be asked for by name and is warned about at every boot ([ADR 0039](decisions/0039-webhook-idempotency-from-signed-bytes.md)). |
| `SIGILD_JUSPAY_WEBHOOK_SECRET` | **required for `scheme=hmac`, i.e. whenever the scheme is unset** | HMAC key. |
| `SIGILD_JUSPAY_WEBHOOK_USERNAME` / `SIGILD_JUSPAY_WEBHOOK_PASSWORD` | **required for `scheme=basic`** | Endpoint Basic-auth credentials. Missing either is a **boot failure** whose message names what `basic` gives up. |
| `SIGILD_JUSPAY_WEBHOOK_SIG_HEADER` | optional | Signature header name for `scheme=hmac` (default `X-Juspay-Signature`) — configurable **because the real name is unconfirmed**. |
| `SIGILD_JUSPAY_AMOUNT_MINOR` | optional | Default amount in minor units (paise); rendered to the decimal major-unit string Juspay expects, by integer arithmetic only. |
| `SIGILD_JUSPAY_CURRENCY` | optional | Default currency. |
| `SIGILD_JUSPAY_API_BASE_URL` | optional | API host override (default `https://api.juspay.in`). |
| `SIGILD_ENTITLEMENT_ENFORCE` | opt-in | `1`/`true` makes a lapsed account's **writes** answer `402` past the grace period ([below](#entitlement-enforcement-opt-in--phase-55)). **Unset ⇒ OFF and byte-identical behaviour.** Requires `SIGILD_ENABLE_DEV_OPS` **and** `SIGILD_DEVICE_AUTH` **and** `SIGILD_BILLING_PROVIDERS` — each missing one is a **boot error** with a message saying why. |
| `SIGILD_ENTITLEMENT_GRACE` | optional | Go duration; how long after entitlement lapses writes keep working (**warned, not refused**). Default **14 days** (`336h`), bounded to `(0, 365d]`. Setting it **without** `SIGILD_ENTITLEMENT_ENFORCE` is a **boot error** — an inert grace period means an operator believes writes are being enforced when they are not. |

⛔ **`SIGILD_WEBHOOK_RATE_LIMIT` and `SIGILD_WEBHOOK_RATE_BURST` no longer exist.**
They were built in Phase 53 and **removed** when a live reproduction showed the
limiter shedding genuine, correctly-signed provider deliveries
([ADR 0041](decisions/0041-abuse-bounds-and-the-removed-webhook-limiter.md)).
Setting either now emits a **boot WARNING** naming the removal, rather than being
silently inert — but it **does not fail boot**, because a protective knob that has
become moot must not take a payments server down.

All of it is **parsed and validated before the listener binds**. Enabling a
provider without its credentials is a **boot error**, never a runtime surprise: a
server that started half-configured would either reject real webhooks it could
not authenticate, or offer checkouts it could not create. Validation performs
**no network I/O**, so boot cannot contact a payment provider.

### Storage (migration `0003_billing.sql`)

Two tables on top of the untouched `0001_init` / `0002_devices`:

| Table | Holds |
|-------|-------|
| `sigil_subscriptions` | `subject` (PK), `provider`, `customer_ref`, `subscription_ref`, `status`, `current_period_end`, `last_event_at` (the ordering guard), `created_at`, `updated_at`; partial index `sigil_subscriptions_by_provider_ref (provider, subscription_ref) WHERE subscription_ref <> ''` for subject resolution |
| `sigil_billing_processed_events` | `(provider, event_id)` **PRIMARY KEY** — the idempotency key, enforced by the **database**, not by application timing. ⚠️ The `event_id` **column** holds the **dedup key** (`Event.IdempotencyKey()`), which for Razorpay is a body hash rather than the provider's own event id — the column name predates [ADR 0039](decisions/0039-webhook-idempotency-from-signed-bytes.md) and was not migrated. Plus the **normalized** `event_type`, `subject`, `processed_at`; index `sigil_billing_processed_events_by_time (processed_at)` |

The migration is **pure DDL** and adds **no column that can hold a card number,
CVV, expiry, cardholder name, billing address, email or phone**. What is stored
is a set of **opaque provider handles** — useful for reconciling a record against
a provider dashboard, useless for charging anyone. The **raw webhook payload is
never persisted**. `sigild_schema_version` reports **3** once applied.

The Postgres backend **reuses the op-log's existing `pgxpool`** (no second pool,
no new dependency). With Postgres unconfigured, billing falls back to the
**in-memory** subscription store, which is **non-durable**: subscriptions *and*
the processed-event ledger are lost on restart, so a webhook redelivered across a
restart **would be applied twice**. `sigild` warns loudly about this at boot.

### Audit log

Five structured events, **metadata only** — never an API key, a webhook secret, a
signature header, one byte of the raw webhook body, an email/name/phone, or an
amount:

| Event | Fields |
|-------|--------|
| `billing.checkout_created` | `request_id`, `provider`, `subject`, `session_id` |
| `billing.checkout_failed` | `request_id`, `provider`, `subject`, `err` (a `ProviderError` carrying **only** provider + operation + HTTP status, or a transport error — never the provider's response body, which can echo customer data) |
| `billing.webhook` | `request_id`, `provider`, `event_type` (normalized), `event_id` — the provider's own **correlation** id, so a `duplicate` is explainable in the dashboard; note it is **not** the idempotency key (see above) — and `outcome` |
| `billing.webhook_rejected` | `request_id`, `provider`, `reason` — the fixed enum `unknown_provider` / `unreadable_body` / `payload_too_large` / `bad_signature` / `malformed` / `store_unavailable`, surfaced **only** here and in the metric, never to the caller |
| `billing.subscription_transition` | `request_id`, `provider`, `subject`, `from`, `to` — fires **once per applied transition**, never for a duplicate/stale/illegal delivery, so the trail is a faithful history of entitlement |

### Honest limits (read before believing any of the above)

- **Nothing has been run against a live provider account.** No live API call, no
  real webhook, no real payment. The Stripe scheme is implemented with **high**
  confidence, the Razorpay **webhook** scheme with high confidence and its
  surrounding details (notably the `X-Razorpay-Event-Id` header name and the
  exact subscription event names) with **medium** — which is a further reason the
  idempotency key no longer depends on that header at all; the **Juspay** adapter is
  explicitly **UNVERIFIED-AGAINST-LIVE-DASHBOARD** — its header names, signed
  message, endpoint path, response envelope and event vocabulary are a
  best-supported reading and **must** be confirmed before use. That uncertainty
  is quarantined behind a small internal `juspayWebhookVerifier` seam so a
  correction touches one type in one file.
- **Checkout creates a one-time hosted payment page for the India adapters.**
  Razorpay's `/v1/payment_links` and Juspay's `/session` are one-time flows;
  **recurring subscription/mandate creation is not implemented**. Both adapters'
  *webhook* sides already map subscription/mandate events, so a subscription
  created out-of-band drives the state machine correctly. This is a deliberate
  omission, not an oversight.
- **An ACCOUNT is now the subject — but it is not an identity.** Since Phase 52 a
  subscription keys off the signing device's **account**
  ([above](#account-model-dev-gated--phase-52)), so a user's devices share one
  subject. There is still **no user record, no email, no household, no
  organization, no seat model, no transfer, and no recovery beyond a paper kit
  printed in advance**; ⚠️ **every device
  enrolled before migration `0005` was adopted into its OWN singleton account**,
  so an existing two-device customer has **two accounts and two billing
  subjects**, reconcilable only by hand. A compromised provider webhook secret
  now moves an **account's** status rather than one device's.
- **No invoicing, proration, tax, refunds, chargebacks, dunning or reconciliation
  job**, and no admin surface for billing.
- **Entitlement enforcement exists, is OFF by default, and refuses only writes.**
  See [below](#entitlement-enforcement-opt-in--phase-55). With
  `SIGILD_ENTITLEMENT_ENFORCE` unset, `entitled` is reported and consulted by
  nothing, exactly as before. There is still **no dunning, no notification and no
  reconciliation** — the only warnings are response headers, the additive
  `entitlement` block, and the server's own audit log.
- ⛔ **No rate limiting on `POST /v1/billing/webhook/{provider}`, deliberately, and
  the limiter that once existed was REMOVED.** An early Phase 53 revision limited
  it before signature verification, keyed on the provider name — the only key
  available at that point, and one **forged traffic controls too**. A verifier
  reproduced the consequence on a live server: one unauthenticated thread at
  ~137 forged requests/second caused **15 of 15 genuine, correctly-signed Stripe
  deliveries to be shed with `429`**; a longer flood shed roughly **2,000
  consecutive genuine retries**; **zero payment events were applied**, and the
  customer was then refused with `402` by entitlement enforcement. Because a
  provider's retry budget is **finite**, such an event is lost **permanently**.
  ⭐ **The rule:** you cannot safely shed traffic on a route where shedding costs
  money and the legitimate sender has a finite retry budget — limiting *before*
  verification lets anonymous traffic spend the honest sender's quota, and
  limiting *after* verification is no better, because an authentic burst is
  exactly what must never be dropped. What bounds the work instead is the **64 KiB
  body cap** and the cost of **one HMAC over a size-capped buffer** — no database
  round trip, no state created. Volume protection for this route belongs at the
  **edge** ([ADR 0041](decisions/0041-abuse-bounds-and-the-removed-webhook-limiter.md)).
- **The in-memory store is non-durable** (see above), and there is **no PCI
  attestation** — hosted checkout keeps scope minimal, it does not certify
  anything.
- **In any real deployment webhooks must arrive over TLS.** The dev server speaks
  plain HTTP.

---

## Entitlement enforcement (opt-in) — Phase 55

> **OFF BY DEFAULT, DEV-GATED, UNAUDITED.** With `SIGILD_ENTITLEMENT_ENFORCE`
> unset, **no handler reads the subscription store, no header is set, no audit
> line is written and no metric moves** — every response is byte-identical to a
> server built before this existed. See
> [ADR 0043](decisions/0043-entitlement-enforcement.md).

Until Phase 55, entitlement was **reported and never enforced**
([ADR 0040](decisions/0040-account-model.md) limitation 8). It can now be
enforced — very narrowly, and asymmetrically, for one reason:

> **This product holds a customer's second factor. Gating it on payment status
> means a declined card can lock a person out of their own bank login.**

### ⭐ What is refused, and what is never refused

| Method + path | Past grace |
|---------------|-----------|
| `POST /v1/vaults/{vaultID}/ops` | **`402`** — new op-log entries |
| `PUT /v1/vaults/{vaultID}/keys/{deviceID}` | **`402` ONLY when `{deviceID}` belongs to ANOTHER account** |
| `POST /v1/vaults/{vaultID}/grants` | **`402` ONLY when the grantee belongs to ANOTHER account** |
| **everything else** | **never refused** |

"Everything else" is exhaustive and worth reading: every `GET` (the op-log, chain
verification, key envelopes, the per-device envelope index, hybrid keys, grants,
devices, the account, invites, the subscription itself), plus device
**enrollment**, device **revocation**, hybrid-key **publish**, envelope
**deletion**, invite **minting**, every billing route **including checkout** — and
⭐ **depositing a wrapped vault key (with the grant that accompanies it) to a
device of the CALLER'S OWN ACCOUNT.**

Two guarantees follow, and both were driven live by a verifier:

- **A lapsed customer keeps every 2FA code they already have.** (Verified: a
  lapsed account still produced the RFC 6238 vector `94287082`.) `past_due`
  remains **entitled** — a declined card starts the provider's retry window, not
  a cutoff.
- **A lapsed customer can still get the keys onto their own devices.** ⚠️ The
  first cut refused this, and a verifier found the lockout: past grace a customer
  whose phone had died could enroll a replacement and then **could not receive the
  vault key for it** (`402`), so the new phone held ciphertext it could never
  decrypt — and **printing a recovery kit was refused too**, leaving them one
  device failure from permanent loss, while the `402` body claimed
  `key_recovery_allowed: true`. Establishing key access within your own account is
  now in the never-refused set.

The asymmetry is **mechanically enforced**: a test parses the package's AST and
fails if the enforcement call set ever changes, so a future read handler cannot
quietly acquire a payment check.

### The `402` response

```json
{
  "error": "payment_required",
  "detail": "this account's subscription has lapsed and its grace period has ended, so new writes are refused; reading your existing vault contents, collecting your key envelopes, and giving another device of THIS account the key to a vault (including creating a recovery kit) are NOT affected",
  "subscription_status": "canceled",
  "grace_ended_at": "2026-07-14T00:00:00Z",
  "reads_allowed": true,
  "key_recovery_allowed": true,
  "checkout_path": "/v1/billing/checkout"
}
```

`reads_allowed` and `key_recovery_allowed` are **always `true`**;
`grace_ended_at` is omitted when no anchor date could be established.
`subscription_status` is from the closed billing enum.

⭐ **It is deliberately NOT collapsed into `401`/`403`.** A client must be able to
tell *"pay to continue"* from *"your key is wrong"* and from *"you may not touch
this vault"*, and act on it. **No auth oracle is created**, because the gate runs
strictly **after authentication AND authorization have both succeeded** — an
unauthenticated or unauthorized caller gets its `401`/`403` exactly as before and
can never see a `402`, so the only party who learns an account's billing state is
a **verified member of that account**, which `GET /v1/billing/subscription`
already tells them. With the dev gate off, every gated route stays `501`, never
`402`.

### Warning headers

Set on gated **write** responses only — on the successful `2xx` while in grace,
and on the `402` itself. An entitled account's responses carry none of them.

| Header | Value |
|--------|-------|
| `X-Sigil-Entitlement` | `grace` or `lapsed` |
| `X-Sigil-Entitlement-Status` | the billing status from the closed enum |
| `X-Sigil-Entitlement-Grace-Ends` | RFC3339 UTC instant (omitted when unknown) |

⚠️ **They are not readable cross-origin unless the server exposes them.** They are
not CORS-safelisted response headers, so a browser client can only read them when
[`SIGILD_CORS_ORIGINS`](#cross-origin-requests-sigild_cors_origins--opt-in-off-by-default)
lists its origin (the middleware then sets `Access-Control-Expose-Headers`), or
when the client is same-origin or an extension page.

### Client support (Phase 56)

Until Phase 56 these three channels — the headers above, the additive
`entitlement` block on
[`GET /v1/billing/subscription`](#get-v1billingsubscription--the-callers-own-status)
and the `402` body — had **no client readers at all**.

| Client | What it reads |
|--------|---------------|
| **webapp** + **MV3 extension** | `sigil-wasm/entitlement.mjs` (`getSubscription` / `entitlementState` / `describeEntitlement` / `readEntitlementHeaders` / `explainSubscriptionStatus`): the subscription route is read on mount — the only warning channel a **read-only** client ever sees, since it is never refused — and the warning headers are read off a successful write |
| **desktop** | `DeviceConfig::subscription()` → the `entitlement_refresh` command → a banner, over the CLI library's `fetch_subscription` (no second HTTP client, no second signing path) |
| **`sigil` CLI** | all five error explainers (sync, device, account, sharing, recovery) render a `402` as a **billing state, not an auth or permission failure**, and say that reads and same-account key recovery are unaffected — printed after the server's body, in this CLI's `{e}\n  -> HTTP nnn: …` form |

A server with enforcement **off** (the default) sends no header and no
`entitlement` block; clients report that as "not enforced" and show nothing.
Conformance against a **real** `sigild`'s bytes is
`sigil-wasm/test/entitlement-interop.mjs` — the browser suites use a test double.

### Where grace is measured from

- **With a subscription record:** the **later** of `updated_at` and
  `current_period_end`. Taking the later is customer-favouring on purpose — a
  subscription canceled mid-period keeps working until the period it was
  **already paid for** ends, and any later touch of the row can only **extend**
  service.
- **With no record at all** (never subscribed): the **account's creation time**.
  ⚠️ This makes the grace period double as the **buy-in window** — a trial by side
  effect. There is no separate trial mechanism in this server.

The boundary is exclusive: exactly at `anchor + grace`, writes are refused.

### Every uncertainty FAILS OPEN

Enforcement not configured, a subscription-store fault, an unreadable account
row, no anchor date, or a device carrying no account (an authorization state
already refused upstream with `403`, which must never be re-served as a payment
problem) all **allow** the request. A database blip must never cost a customer
their vault. `entitlement.fail_open` is logged at **error** level, because it
means enforcement is silently *not* happening.

### Observability

`sigild_entitlement_enforcing` (gauge) and
`sigild_entitlement_decisions_total{outcome}` over the closed set
`entitled` / `grace` / `refused` / `fail_open` — **no account or subject label**.
Audit events `entitlement.grace` (warn), `entitlement.refused` (warn) and
`entitlement.fail_open` (error) carry `account_id`, `device_id`, a
`subscription_status`, a grace instant and a fixed `surface`
(`ops_append` / `key_envelope_put` / `vault_grant`) — never a token, key,
signature, nonce, card field or byte of ciphertext. By its **absence** from that
stream, the audit log is also the evidence that no read was ever refused.

### Honest limits

- ⚠️ **A vault claim happens before the refusal.** A first write to an *unclaimed*
  vault is claimed by the authorization step and only then refused with `402`.
  Accepted knowingly: the claim binds the vault to the caller's **own** account.
- ⚠️ **Enforcement depends on a durable subscription store.** With the in-memory
  store, a restart loses every subscription and every account then **fails open**
  — free service, silently, until the store is repopulated.
- **No dunning, notification, email, invoice or reconciliation**, and **no
  per-account override**: one grace period for the whole server.
- **Refusal is not revocation.** Nothing is deleted and nothing expires; a lapsed
  account's data stays where it is (and keeps costing storage).
- **`past_due` is entitled**, so a genuinely failed card buys the provider's whole
  retry window *plus* the grace period. Deliberate, and a real revenue leak.
- **All billing caveats still hold** — never run against a live provider account,
  Juspay *UNVERIFIED-AGAINST-LIVE-DASHBOARD*, and a compromised provider webhook
  secret can now move an account's **service**, not just its reported status.

---

## What production will add (not in the skeleton)

The dev op-log is a wiring placeholder. A production sync server would add, at
minimum:

- **Authentication and authorization** — the dev op-log now *has* a real
  **multi-device model** (contract v3: device enrollment with proof of
  possession, a device registry, per-vault grants, and revocation — see
  [above](#multi-device-auth-model-contract-v3--dev)) and a real (if minimal)
  **account model** on top of it
  ([above](#account-model-dev-gated--phase-52)), but production still owes an
  **identity** layer — no email, no password, no operator break-glass; the only
  recovery is a **paper kit printed in advance**
  ([above](#recovery-kits-dev-gated--phase-54)) — plus session/token issuance
  (JWT bearer tokens, [`../sigild/internal/auth/`](../sigild/internal/auth/)),
  **key rotation** and re-enrollment, **rate limiting that actually works
  per-source** (what exists today is a proxy-blind backstop, [above](#abuse-rate-limiting-enrollment--invite-minting)),
  a **shared** (not per-process) replay store, roles inside an account (membership
  is flat), account transfer/merge/deletion, and an ownership model stronger than
  trust-on-first-write. The legacy `SIGILD_OPLOG_PUBKEY` mode remains only a
  single static DEV key with no authorization at all, and with neither contract
  configured the dev route is wide open.
- **Durable, replicated storage** — the opt-in **Postgres** dev backend
  (`SIGILD_OPLOG_POSTGRES`, [`decisions/0014-postgres-durable-oplog-backend.md`](decisions/0014-postgres-durable-oplog-backend.md))
  now gives the dev op-log a durable, concurrent home, but a production store
  still needs managed migrations, backups, a proven restore, and replication
  (and, for large blobs, an object store such as S3/R2) — none of which the dev
  backend provides.
- **Real operation / CRDT semantics** — signed, ordered operations with
  Lamport-clock / Merkle-root replay-and-drop detection and conflict-free merge,
  versus today's plain append-and-read byte journal. The dev op-log's per-op
  SHA-256 **hash chain** (above) is a **tamper-EVIDENT** down-payment on this —
  it detects modification/insertion/deletion of stored ops by a *client-side*
  verifier — but it is **not** the signed, Merkle-rooted, Byzantine-resistant
  audit log the production build owes: a hostile server can still lie about the
  chain, and there is no signature or CRDT merge on the ops themselves.

Even then, the server's stored bytes stay **opaque client ciphertext**: the
server never holds plaintext or keys. See
[`threat-model.md`](threat-model.md) and [`crypto-spec.md`](crypto-spec.md).
