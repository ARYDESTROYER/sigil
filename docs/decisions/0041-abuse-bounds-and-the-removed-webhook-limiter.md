# 0041 — Abuse bounds on enrollment and invite minting, and the webhook rate limiter that was built, proven harmful, and removed

- **Status:** Accepted (2026-07)
- **Date:** 2026-07-28
- **Revises (does not supersede):** limitation 12 of
  [0040](0040-account-model.md) ("**No rate limiting** on
  `POST /v1/devices/enroll` or `POST /v1/account/invites`"). 0040's body is
  unchanged; it carries a dated addendum pointing here.
- **Builds on:** [0017](0017-oplog-scale-and-observability.md) (the stdlib
  token-bucket limiter this reuses verbatim, and its `429` + `Retry-After`
  contract), [0031](0031-multi-device-auth-model.md) (the enrollment path being
  bounded), [0034](0034-billing-provider-seam.md) /
  [0039](0039-webhook-idempotency-from-signed-bytes.md) (the webhook route the
  removed limiter sat on), [0005](0005-stdlib-only-sigild.md) (why this is
  hand-written rather than a dependency).

## Context

[ADR 0040](0040-account-model.md) recorded, as limitation 12, that the account
model's caps bound **stored state** and not **request volume**: nothing limited
`POST /v1/devices/enroll` (the one unauthenticated write path in the server) or
`POST /v1/account/invites`.

That is the whole starting position. What made this phase worth an ADR is not
the token bucket — [ADR 0017](0017-oplog-scale-and-observability.md) already had
one — it is **two things a verifier proved on a live server that a reasonable
reading of the diff would have missed**, and a third route where the obvious
implementation **destroyed customer payments**.

## Decision

### 1. Two limiters, hand-written, no new dependency

`sigild` limits `POST /v1/devices/enroll` (keyed on the **socket peer address**)
and `POST /v1/account/invites` (keyed **per account**), with the existing
`internal/api/ratelimit.go` token bucket — `sync.Mutex` + map + `time`, a
`10_000`-key cap (`abuseLimiterMaxKeys`) and idle eviction. Over-rate is the same
`429 rate_limited` + `Retry-After` envelope the op-log limiter already returns,
so a client sees **one** rate-limit contract across the whole server.

| Variable | Default | Meaning |
|----------|---------|---------|
| `SIGILD_ENROLL_RATE_LIMIT` / `SIGILD_ENROLL_RATE_BURST` | unset ⇒ **no limiter installed** | failed enrollments/sec per source address; bucket depth |
| `SIGILD_INVITE_RATE_LIMIT` / `SIGILD_INVITE_RATE_BURST` | unset ⇒ **no limiter installed** | invites/sec per account; bucket depth |

All four are validated **fail-fast before the listener binds**, through the same
`parseRateLimit` / `parseRateBurst` / `effectiveBurst` helpers as the op-log
limiter, so the four limiters in this server share one parsing contract.
`sigild/go.mod` still has **exactly one direct require** (`pgx`).

Unlike the `SIGILD_ACCOUNT_*` settings, these deliberately **do not require**
`SIGILD_ENABLE_DEV_OPS` / `SIGILD_DEVICE_AUTH`. Those change *who owns a vault*,
so a silently-ignored value there is an ownership surprise; a rate limit is
purely protective, and refusing to boot because a protective knob is currently
moot is a worse failure than the boot warning `logAbuseBounds` emits.

The metric is `sigild_abuse_ratelimit_rejected_total{surface}` over the **closed**
set `{enroll, invite}` — counts only, **no key label**, so a scrape cannot learn
*which* address or account was limited. The audit event is
`abuse.rate_limited` (`surface`, `subject`), and ⚠️ **the source address is
deliberately not logged**: this server holds no personal data anywhere, an IP
address is personal data in most regimes, and writing one into an otherwise
keep-forever audit stream would create retention, minimisation and erasure
obligations that nothing else here has — for information the reverse proxy doing
the actual blocking already holds at a layer designed to hold it. `subject` is
the **account id** on the invite surface and **empty** on enrollment.

### 2. ⚠️ It is a BACKSTOP, not a defence — and this must be documented as prominently as the feature

The only deployment topology this repo documents
([`../../deploy/caddy/Caddyfile`](../../deploy/caddy/Caddyfile),
[`../../deploy/local/Caddyfile.local`](../../deploy/local/Caddyfile.local)) is a
**reverse proxy**. Behind one, every request reaches `sigild` from **one**
address, so `clientRateKey` returns one key for all traffic and the enrollment
limiter degrades to a **single global bucket**.

`X-Forwarded-For` is **not consulted, on purpose**: `sigild` has no
trusted-proxy configuration, so a forwarded-for header is attacker-supplied
text, and keying on it would let one client mint unlimited buckets — a no-op
limiter that also fills the bounded map, which is strictly worse than no limiter.
(`TestEnrollRateLimitIgnoresForwardedFor` pins this **at the call site**, not
just on the pure function, because a wrapper that read the header would satisfy
every unit test of `clientRateKey` while defeating it completely.)

An **earlier revision of this phase shipped the obvious "reject before the
handler" shape, and a verifier reproduced the consequence live**: an attacker
sending junk from one address drew `{401 ×5, 429 ×25}`, and the next request — a
legitimate new customer presenting a **valid, unspent operator token** — was
refused `429`. Behind a proxy, "one address" is every address, so that limiter
was **a global switch for turning off account creation and invite redemption**:
precisely the join path somebody uses **after losing a device**.

Two changes fixed it, and both are load-bearing:

- ⭐ **The bucket is charged ONLY on the DENIAL path.** `rateLimitEnroll`
  buffers the handler's response; a **2xx** (a valid, unspent credential plus a
  valid proof of possession) is flushed through untouched and costs **nothing**,
  so **a successful enrollment can never be refused by the limiter, in any bucket
  state whatsoever**. Only a non-2xx consumes a token, and when the bucket is
  empty the buffered denial is discarded and replaced by the `429`.
- ⭐ **`Allow` FAILS OPEN at its key cap**, where it used to fail closed. The old
  branch meant one IPv6 /48 could fill 10,000 buckets and lock out everyone else
  — a bounded map turned into a denial weapon. IPv6 is now bucketed by **/64
  prefix** (a single host is routinely handed a /64) and IPv4 by full address; an
  unparseable `RemoteAddr` shares one bucket (`unattributedRateKey`) rather than
  being allowed, because a limiter you can disable by making yourself
  unidentifiable is not a limiter.

**Real per-source limiting belongs at the edge**, which is the component that
actually knows the peer. `sigild` warns this at every boot when the enrollment
limiter is configured.

### 3. ⚠️ It does not reduce load, and the name is misleading about that

Charging only on the denial path means **the handler always runs**, including its
database work; the limiter replaces only the **response**. It bounds **how useful
flooding is, not what it costs the server.** A work bound for this route would
have to reject *before* the handler — which is exactly the shape that denied a
legitimate customer in §2. That trade was made knowingly and is stated here so
nobody reads "rate limit" as "load shed".

### 4. ⛔ THE WEBHOOK RATE LIMITER WAS BUILT, PROVEN HARMFUL, AND REMOVED

An early revision of this phase also limited
`POST /v1/billing/webhook/{provider}` — **before signature verification**, keyed
on the **provider name**, since that is the only key available before the body is
authenticated.

A verifier reproduced the consequence on a live server. One unauthenticated
thread at roughly **137 forged requests/second** caused **15 of 15 genuine,
correctly-signed Stripe deliveries to be shed with `429`**. A longer flood shed
roughly **2,000 consecutive genuine retries**. **Zero payment events were
applied**, and the customer was then refused with `402` by the entitlement
enforcement of [ADR 0043](0043-entitlement-enforcement.md) — a paying customer
locked out of writes because an anonymous attacker spent their provider's retry
budget. Because a provider's retry budget is **finite**, the event is lost
**permanently**: there is no later delivery to recover it.

⭐ **The rule this teaches, and the reason it is recorded rather than fixed:**

> **You cannot safely shed traffic on a route where shedding costs money and the
> legitimate sender has a finite retry budget.**

Both placements fail, and they fail for independent reasons:

- **Limiting BEFORE verification** lets anonymous forged traffic spend the honest
  sender's quota. The only key available at that point — the provider name in the
  path — is **attacker-controlled too**, so there is no key that separates them.
- **Limiting AFTER verification is no better.** An authentic burst (a provider
  catching up after an outage, a batch of renewals) is **exactly the traffic that
  must never be dropped**. A limiter that only ever fires on authentic events is
  a limiter that only ever destroys revenue.

So the route is **not rate limited at all**. What bounds the work instead is what
already bounded it: the **64 KiB body cap** and the cost of **one HMAC over a
size-capped buffer** — no database round trip, no state created, nothing
persisted, before the signature verifies. Volume protection for that route
belongs at the **edge**.

`SIGILD_WEBHOOK_RATE_LIMIT` and `SIGILD_WEBHOOK_RATE_BURST` **no longer exist**.
Setting either now emits a **loud boot WARNING** naming the removal and its
reason (added after a verifier pointed out they were otherwise **silently
inert** — an operator upgrading with the variable still in an `EnvironmentFile`
would boot clean and believe the webhook route was protected, which is the most
dangerous possible misunderstanding of a removal). It **warns rather than
refusing to boot**, because a protective knob that has become moot must not take
a payments server down; everything that *changes behaviour* still fails fast.

## The sentence an auditor should be able to check

> A request carrying a **valid, unspent credential and a valid proof of
> possession** can never be refused by the enrollment limiter; the limiter's key
> is the **socket peer address only** and is degraded to one global bucket in the
> only topology this repo documents; and **`POST /v1/billing/webhook/{provider}`
> is deliberately not rate limited**, because on that route shedding destroys
> payments.

## Consequences

### Good

- **A flood of failed enrollments no longer buys an unlimited supply of detailed
  denials**, and invite minting is bounded per account rather than only by the
  open-invite cap.
- **The controls cannot deny a legitimate user.** That property is structural
  (the 2xx short-circuit, and fail-open at the key cap), not a tuning choice.
- **No new dependency**, no new response contract, no new metric label space
  (both new label sets are closed), and no new personal data anywhere.
- **A dangerous mechanism was deleted rather than tuned.** The webhook limiter's
  failure mode was reproduced, understood and recorded; removing it is the
  finding, not a regression.
- **A retired knob is loud, not silent.** An operator cannot carry
  `SIGILD_WEBHOOK_RATE_LIMIT` forward and believe it still does something.

### Bad / honest limitations

1. ⚠️ **This is a backstop, not a defence.** Behind the documented reverse-proxy
   topology the enrollment limiter is one global bucket. Edge limiting is the
   real control and **is not configured anywhere in `deploy/`** — no Caddy
   `rate_limit`, no firewall rule, no fail2ban. That is a gap, stated as one.
2. ⚠️ **It does not reduce load.** See §3. Every limited request still runs its
   handler and its database work.
3. ⚠️ **`POST /v1/billing/webhook/{provider}` has no volume bound at all**, by
   deliberate decision (§4). A flood there is answered as fast as HMAC over ≤ 64
   KiB allows.
4. **The limiters are per-process and in-memory.** A multi-instance deployment
   divides each budget across instances; there is no shared limiter store, the
   same limitation the replay nonce cache has carried since
   [ADR 0010](0010-op-log-auth-v2-nonce-replay.md).
5. **Nothing else is limited.** The sharing routes, the op-log read routes,
   `GET /metrics`, and every other surface are unbounded; the op-log limiter
   still covers appends only.
6. **Off by default.** Unset means no limiter is installed, which is the right
   default for a dev server and the wrong one for anything exposed — and nothing
   here should be exposed.
7. **Still dev-gated and UNAUDITED.** The routes being limited answer `501`
   without `SIGILD_ENABLE_DEV_OPS`; a limiter configured on such a server is
   inert, and says so at boot.

### Neutral

- The limiter type, the `429` body, the `Retry-After` header and the
  parse/validate helpers are **reused verbatim** from
  [ADR 0017](0017-oplog-scale-and-observability.md); this phase added surfaces,
  not a second mechanism.
- `rateLimitEnroll` is installed **only on the live (dev-gated) route**. The
  `501` stub is never rate limited — a gated route must answer `501` uniformly,
  or the limiter itself becomes a probe for whether the feature is on.

## Alternatives rejected

- **Reject before the handler on enrollment** (the obvious shape). Rejected after
  a live reproduction: it refused a legitimate customer holding a valid operator
  token, and behind a proxy it was a **global account-creation off switch**. See
  §2.
- **Fail closed at the limiter's key cap** (the original code). Rejected: one
  IPv6 allocation could fill the map and lock out every other source. See §2.
- **Key on `X-Forwarded-For` / `X-Real-IP`.** Rejected: without a trusted-proxy
  configuration those are attacker-supplied strings, so keying on them yields
  unlimited buckets — a no-op limiter that also exhausts the map.
- **Rate limit `POST /v1/billing/webhook/{provider}`, before or after
  verification.** Rejected on evidence. Before verification, forged traffic
  spends the honest sender's quota; after verification, an authentic burst is
  exactly what must not be dropped. Shedding on that route destroys payment
  events permanently. See §4.
- **Log the source address on a rate-limit denial.** Rejected: it would put
  personal data into the one component of this system that holds none, without
  changing what an operator does — the proxy or firewall that would act already
  has the address.
- **A per-cause / per-key metric label.** Rejected for the same reason
  [ADR 0040](0040-account-model.md) limitation 11 gives: `/metrics` is always-on
  and unauthenticated, so a key label would be a correlatable oracle.
- **A rate-limiting dependency** (`golang.org/x/time/rate`, or a middleware
  library). Rejected: the existing bucket is ~40 lines, already tested, and
  `sigild` keeps exactly one direct dependency
  ([ADR 0005](0005-stdlib-only-sigild.md) / [0014](0014-postgres-durable-oplog-backend.md)).

## References

- Code: [`../../sigild/internal/api/ratelimit.go`](../../sigild/internal/api/ratelimit.go)
  (`clientRateKey`, `rateLimitEnroll`, `allowAbuse`, `writeRateLimited`,
  `unattributedRateKey`, `abuseLimiterMaxKeys`),
  [`router.go`](../../sigild/internal/api/router.go),
  [`accounts.go`](../../sigild/internal/api/accounts.go),
  [`audit.go`](../../sigild/internal/api/audit.go) (`auditRateLimited`),
  [`metrics.go`](../../sigild/internal/api/metrics.go),
  [`../../sigild/cmd/server/main.go`](../../sigild/cmd/server/main.go)
  (`validateAbuseConfig`, `logAbuseBounds`).
- Tests: [`../../sigild/internal/api/abuse_test.go`](../../sigild/internal/api/abuse_test.go),
  [`../../sigild/cmd/server/abuseconfig_test.go`](../../sigild/cmd/server/abuseconfig_test.go).
- Contract: [`../api.md`](../api.md).
- Operator runbook: [`../deployment.md`](../deployment.md) §15.
- Adversaries: [`../threat-model.md`](../threat-model.md).
