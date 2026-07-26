# 0034 — Provider-agnostic billing seam in `sigild` (Stripe / Razorpay / Juspay, stdlib-only adapters, hosted checkout, idempotent webhooks)

- **Status:** Accepted (2026-07)
- **Date:** 2026-07-26
- **Relates to:** [0005](0005-stdlib-only-sigild.md) (stdlib-only `sigild`, as
  relaxed by [0014](0014-postgres-durable-oplog-backend.md) for `pgx`),
  [0031](0031-multi-device-auth-model.md) (device auth v3 — the identity billing
  keys off), [0003](0003-dev-gated-opaque-op-log.md) (the dev-gate convention),
  [0018](0018-managed-oplog-migrations-and-backup-integrity.md) (the migration
  machinery `0003_billing.sql` rides on).

## Context

Sigil is a **paid** product. Until now nothing in the repository could take
money, and the payment story was an unwritten assumption — which is the worst
place for it to be, because payment integration decisions (which providers, how
webhooks are authenticated, where subscription state lives, whether a vendor SDK
enters the process) are hard to reverse once written and are exactly the sort of
thing an auditor will ask about.

Three forces shaped the problem:

1. **Two markets, two payment worlds.** India's payment rails (UPI, netbanking,
   card mandates) are served by **Razorpay** and **Juspay**; the rest of the
   world is served by **Stripe**. There is no single provider that covers both
   well, so "pick one processor" was never available. Any design had to assume
   **at least three** providers, each with its own webhook scheme, its own event
   vocabulary and its own checkout API.
2. **`sigild` is a one-dependency server.** [ADR 0005](0005-stdlib-only-sigild.md)
   made `sigild` Go-stdlib-only; [ADR 0014](0014-postgres-durable-oplog-backend.md)
   relaxed that exactly once, for `pgx`, and said so loudly. Every payment
   provider ships an official Go SDK, and using three of them would add a large,
   opaque, **network-capable** dependency surface to the same process as an
   end-to-end-encrypted sync server — the process whose entire value proposition
   is that it holds nothing worth stealing. It would also bury the security-
   critical code (signature verification) inside a vendor library, where it
   cannot be read in a review.
3. **The guardrail: don't fake crypto or auth.** `CLAUDE.md` forbids stubbing
   something that would poison a future audit. A billing layer with a "TODO:
   verify signature" or a `==` string comparison on an HMAC would be precisely
   that. Either the verification is real, or the routes stay `501`.

There was also a genuine architectural question with no clean answer available
today: **should billing live inside the sync server at all?** It should probably
not, long-term (see Consequences). But the device identity, the fail-fast config
plumbing, the store seams, the audit log and the `/metrics` endpoint all already
exist here, and standing up a second service to hold five hundred lines of state
machine would have been ceremony rather than architecture at this stage.

## Decision

Build a **provider-agnostic billing seam inside `sigild`**, opt-in and dev-gated,
with the following load-bearing choices.

### 1. One interface, three adapters — and **no vendor SDKs**

`billing.Provider` is the entire seam:

```go
type Provider interface {
    Name() string
    CreateCheckout(ctx context.Context, req CheckoutRequest) (CheckoutSession, error)
    VerifyWebhook(headers http.Header, rawBody []byte) (Event, error)
}
```

Three adapters implement it — `stripe.go`, `razorpay.go`, `juspay.go` — and the
HTTP layer knows nothing else about payments. Every adapter is written with
**`net/http` + `crypto/hmac` + `crypto/sha256` + `crypto/subtle` +
`encoding/json` + `net/url` only**. No payment SDK enters the module:
`sigild/go.mod` still has **exactly one direct require** (`pgx`).

This is a deliberate trade. We give up SDK conveniences (typed event structs,
retry helpers, API-version pinning) and take on the obligation to track each
provider's wire format ourselves. In exchange we keep the one-dependency posture
that makes this server auditable, and — more importantly — the **signature
verification is ~30 readable lines per provider** rather than an opaque library
call. A reviewer can check the security-critical path by reading it.

Adapters take an **injectable base URL and HTTP client**, so the whole test suite
points at a local `httptest` server and nothing in this repository reaches the
public internet.

### 2. Hosted checkout only — the server never touches card data

Every adapter uses the provider's **hosted checkout / payment-link** flow:
`sigild` performs one outbound POST asking for a URL
(Stripe `POST /v1/checkout/sessions`, Razorpay `POST /v1/payment_links`, Juspay
`POST /session`) and hands that URL to the client. The customer's card details
exist only between their browser and the provider.

This is enforced **by construction, not by convention**: there is no field on
`CheckoutRequest`, `CheckoutSession` or `Event` that could carry a PAN, CVV,
expiry, cardholder name or billing address; no adapter parses one; no audit line
or metric can emit one; and migration `0003_billing.sql` has no column that could
store one (nor an email or phone number). PCI scope stays at **SAQ-A**.

### 3. Real webhook verification: raw-body HMAC, constant-time, timestamp-bounded

`VerifyWebhook` receives the **exact bytes read off the wire** and verifies over
**those bytes first**, parsing the JSON only afterwards. Verifying a re-encoded
payload would be a bug: a Go JSON round-trip reorders keys and drops whitespace,
so the MAC would never match — and "fixing" that by re-signing would let an
attacker mutate the body freely.

| Provider | Signed message | Key | Replay bound |
|----------|----------------|-----|--------------|
| Stripe | `"<t>" + "." + raw body`, from `Stripe-Signature: t=…,v1=…` | endpoint signing secret (`whsec_…`) | `abs(now − t) ≤ 5 min`, checked in both directions |
| Razorpay | raw body, from `X-Razorpay-Signature` | dashboard webhook secret | none in-scheme — the idempotency ledger is the bound |
| Juspay `hmac` | raw body, from a configurable header (default `X-Juspay-Signature`) | configured webhook secret | none in-scheme |
| Juspay `basic` | *(none — authenticates the connection)* | `Authorization: Basic` credentials | none |

All comparisons are **constant time** (`hmac.Equal`, `subtle.ConstantTimeCompare`)
with **no early exit** — Stripe's multiple `v1` elements (sent during secret
rotation) are all compared, so neither the count nor which one matched is
observable in timing. An undecodable hex signature is simply "not equal".
Legacy Stripe `v0` elements are ignored, never accepted — accepting them would be
a downgrade path. An **unconfigured verifier fails closed**: it accepts nothing.

Every failure mode — missing header, malformed header, wrong secret, tampered
body, stale timestamp — returns the **same** coarse `401`. The precise reason
goes only to the audit log and a per-reason metric, so a prober cannot learn
which check tripped.

Juspay's uncertainty is quarantined behind a small internal
`juspayWebhookVerifier` interface with two implementations selected by
`SIGILD_JUSPAY_WEBHOOK_SCHEME`, so correcting the scheme means rewriting one type
in one file — not touching the `Provider` interface, the state machine, the store
or any handler.

### 4. Idempotency keyed on the provider event ID, fused with the state change

Every provider redelivers events — on its own retry schedule, and again whenever
an operator replays one from a dashboard. So handling is idempotent on
**`(provider, event_id)`**, and — the load-bearing part — **recording that we
handled an event and applying what it says are ONE atomic operation**
(`SubscriptionStore.ApplyWebhookEvent`): one mutex in the in-memory backend, one
**transaction** in Postgres where the ledger claim is
`INSERT … ON CONFLICT (provider, event_id) DO NOTHING` (zero rows affected *means*
duplicate) and the subscription row is taken `FOR UPDATE`. Split into two calls,
a crash in between would double-apply or lose an event; fused, a duplicate
delivery is a guaranteed **no-op that still answers `200`**.

Where a provider gives no event ID, the adapter derives a **deterministic** one
from `SHA-256(raw body)`, so a byte-identical redelivery still deduplicates.

Separately, an explicit **state machine** (`state.go`, a transition table, not
scattered `if`s) governs `none`/`trialing`/`active`/`past_due`/`canceled`, and a
**staleness guard** drops any event older than the last applied one. Legality and
ordering are independent guards; both must pass.

### 5. Two authentications, deliberately — and a server-derived subject

- `POST /v1/billing/checkout` and `GET /v1/billing/subscription` come **from a
  device**, so they reuse the **existing device-auth v3 choke point**
  (`authenticateDevice`) verbatim. No billing-specific token, no API key, no
  second auth path.
- `POST /v1/billing/webhook/{provider}` comes **from the provider**, which has no
  device key and cannot sign the v3 contract. It is authenticated by the
  provider's signature and nothing else — which is why it can create no session,
  read no vault, and name no subject of its own choosing.

The **subject is server-derived**: a checkout's subject is the authenticated
device ID, never a body field, and the subscription route reports only the
caller's own record with no subject parameter. A client cannot buy — or query — a
subscription on another subject's behalf.

### 6. Dev-gated by default, fail-fast on configuration

All three routes return the deliberate **`501`** unless
`SIGILD_ENABLE_DEV_OPS` **and** `SIGILD_DEVICE_AUTH` **and**
`SIGILD_BILLING_PROVIDERS` are all set — `501`, never `404`, and never partial
behaviour. Configuration is parsed and validated **before the listener binds**,
with **no network I/O**: an unknown/duplicate provider, a missing credential for
an enabled provider, a non-absolute return URL, a non-positive amount or an
unknown Juspay scheme makes `sigild` exit non-zero. A server that started
half-configured would reject real webhooks it could not authenticate, or offer
checkouts it could not create — both are worse than not starting.

## Consequences

### Good

- **The one-dependency posture survives.** `sigild/go.mod` still has exactly one
  direct require. A payment integration did not become a supply-chain event.
- **The security-critical code is small and readable.** Signature verification is
  a few dozen lines per provider, in this repository, testable offline — which is
  what makes it reviewable at audit time.
- **No card data anywhere.** Not in a struct, a log line, a metric, or a column.
  PCI scope stays SAQ-A by construction rather than by discipline.
- **The seam is genuinely provider-agnostic.** Adding a fourth provider is one
  file implementing one interface; the state machine, storage, HTTP layer, audit
  log and metrics do not change. Swapping Juspay's scheme is one type.
- **Zero-knowledge is untouched.** `0003_billing.sql` touches nothing in
  `sigil_vault_ops`; no billing handler reads a vault blob; a deployment that
  never enables billing simply has two empty tables.
- **The idempotency guarantee is enforced by the database**, not by application
  timing, so it holds across concurrent processes.

### Bad / accepted costs

- **We now track three wire formats by hand.** Without SDKs, a provider changing
  an event name or a header is our problem to notice. The `ignored`-by-default
  mapping makes an unrecognized event safe (a `200`, no state change) rather than
  dangerous, but "safe" is not "correct".
- **No API-version pinning** of the kind an SDK provides.

### Honest limits — record these; they are the reason this is not production

- **NOTHING HAS BEEN RUN AGAINST A LIVE PROVIDER ACCOUNT.** No request in this
  repository has ever reached `api.stripe.com`, `api.razorpay.com` or
  `api.juspay.in`. Every test drives a local `httptest` server with fake
  credentials. Before real money moves, each provider must be exercised against
  its live dashboard.
- **The Juspay adapter is explicitly UNVERIFIED-AGAINST-LIVE-DASHBOARD.** Its
  webhook header names, the exact signed message, the endpoint path, the response
  envelope and the event vocabulary are a best-supported reading, not a confirmed
  contract. Both schemes it implements are real (a real constant-time HMAC; a
  real constant-time credential comparison), but **which** one a given merchant
  account uses, and under what header, **must be confirmed before production**.
  The `hmac` scheme in particular signs the **bare body**; if the dashboard
  documents a timestamped construction (as Stripe uses), the verifier must be
  changed. Note also that Juspay's `basic` scheme authenticates the **connection,
  not the body** — it does not defend against a tampered payload, so it requires
  TLS unconditionally.
- **Razorpay's surrounding details are MEDIUM confidence** — notably the
  `X-Razorpay-Event-Id` header name (hence the deterministic body-hash fallback)
  and the exact subscription event names for a given plan configuration. The
  webhook signing scheme itself is high confidence.
- **No account model.** Subscriptions key off the **authenticated device subject**
  (`dev_…`), because that is the only identity `sigild` has. One human with two
  devices is two subjects. This is a scaffold, not the product's billing
  identity, and it will have to be migrated when accounts exist.
- **No recurring-subscription creation for the India adapters.** Razorpay's
  payment link and Juspay's session are **one-time hosted pages**; their webhook
  sides map subscription/mandate events, so a subscription created out-of-band
  drives the state machine correctly. Wiring creation is deliberate future work.
- **No fraud, chargeback, refund, dispute, proration, tax, dunning, invoicing or
  reconciliation handling**, no billing admin surface, and **no entitlement
  enforcement** — `entitled` is reported and consulted by nothing.
- **No PCI attestation.** Hosted checkout keeps card data out of the process,
  which minimizes scope. It certifies nothing, and nobody has assessed it.
- **The in-memory subscription store is non-durable** — subscriptions and the
  processed-event ledger are lost on restart, so a webhook redelivered across a
  restart can be applied twice. Only the Postgres backend gives the idempotency
  guarantee across restarts and processes.
- **No rate limiting on the webhook endpoint**, and (Stripe aside) **no in-scheme
  replay bound** — the ledger is the only one.
- **Billing living inside `sigild` is PROVISIONAL.** A zero-knowledge sync server
  is not the obvious long-term home for money-adjacent state: a production shape
  would likely separate billing into its own service and database, with its own
  blast radius and compliance surface, and have `sigild` consume an entitlement
  rather than compute one. It is here because the identity, config, storage and
  observability plumbing already are. Treat the location as a scaffold decision,
  reversible by a later ADR.

## Alternatives considered

- **Use the official Stripe/Razorpay/Juspay Go SDKs.** Rejected: three large,
  network-capable dependencies in an E2EE server's process, and the
  security-critical verification hidden inside a vendor library. The
  one-dependency posture ([ADR 0005](0005-stdlib-only-sigild.md) /
  [0014](0014-postgres-durable-oplog-backend.md)) is worth more than the
  convenience.
- **Stripe only, ship India later.** Rejected: India is a primary market, and
  retrofitting a second provider into a Stripe-shaped codebase is exactly how a
  provider-specific vocabulary leaks into the state machine and the database.
  Designing for three from the start cost one interface.
- **A separate billing service.** The right long-term answer, and explicitly left
  open above — but premature now: it would duplicate the config, storage, audit
  and metrics plumbing that already exists here, to hold a state machine that is
  currently a few hundred lines.
- **Store the raw webhook payload for later reprocessing.** Rejected: provider
  payloads can carry customer PII, and persisting them would put personal data
  into a database whose entire posture is "we hold nothing sensitive". Only the
  **normalized** event type and opaque handles are stored.
- **Verify webhooks by re-serializing the parsed JSON.** Rejected as an active
  vulnerability: it breaks the MAC, and any "fix" for that breaks integrity.
- **Return a non-2xx for events we do not model.** Rejected: it drives providers
  into exponential retry loops over events we deliberately ignore. `ignored` is a
  `200`.
