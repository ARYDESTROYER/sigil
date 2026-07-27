# 0039 — Webhook idempotency keys must be derived from bytes the provider's signature covers

- **Status:** Accepted (2026-07)
- **Date:** 2026-07-27
- **Revises:** [0034](0034-billing-provider-seam.md) §4 ("Idempotency keyed on the
  provider event ID"). The rest of 0034 — the seam, the no-SDK rule, hosted
  checkout, the state machine, the fused atomic apply — stands unchanged; only
  **which value** is used as the ledger key changes, plus the default Juspay
  webhook scheme that follows from the same principle.
- **Relates to:** [0031](0031-multi-device-auth-model.md) (device auth v3 — the
  contract that protects the *other* two billing routes),
  [0003](0003-dev-gated-opaque-op-log.md) (the dev-gate convention),
  [0010](0010-op-log-auth-v2-nonce-replay.md) (the same "bind the anti-replay
  material into the signed message" reasoning, applied to our own contract).

## Context

[ADR 0034](0034-billing-provider-seam.md) made webhook handling idempotent on
`(provider, event_id)`, and fused the ledger claim and the state change into one
atomic operation. That fusion is right and is not in question here. **Where the
`event_id` came from was wrong for one provider.**

Razorpay signs the **body and nothing else**: `HMAC-SHA256(raw body)` in
`X-Razorpay-Signature`, with no timestamp element and no header covered. The
adapter nevertheless took the event id from the **`X-Razorpay-Event-Id` header**,
falling back to a body hash only when that header was absent.

Those two facts together produce the defect. A captured, genuinely-signed delivery
can be replayed with **any headers the attacker likes** — the signature still
verifies, because the signature says nothing about headers. Changing one header
therefore changed the idempotency key, and the delivery was processed as a **new
event**:

```
  captured delivery          replay 1                    replay 2
  body B, sig=HMAC(B)        body B, sig=HMAC(B)         body B, sig=HMAC(B)
  X-Razorpay-Event-Id: e1    X-Razorpay-Event-Id: e2     X-Razorpay-Event-Id: e3
        │                          │                           │
        ▼                          ▼                           ▼
  key (razorpay,e1)          key (razorpay,e2)  ← NEW      key (razorpay,e3)  ← NEW
```

The blast radius was bounded but real. The **state machine** is idempotent, checks
legality against a transition table, and drops out-of-order events with the
staleness guard, so a replayed `subscription.activated` could not walk a
subscription anywhere it had not already been. What it *could* do is append an
unbounded number of rows to `sigil_billing_processed_events` on demand — an
attacker-controlled write amplification against the database, from an endpoint
that has **no rate limiting** (0034 records that limit and it is still true).
More importantly, the idempotency guarantee itself was **not what the
documentation said it was**: "a duplicate delivery is a no-op" held only for
duplicates the attacker chose not to relabel.

The same reasoning exposed a second, separate weakness one layer up. Juspay's
adapter supports two webhook schemes, and the **default was `basic`** — HTTP Basic
credentials, which authenticate the **connection** and cover **no bytes at all**.
An operator who enabled Juspay and never read the scheme variable got
connection-only authentication *by accident*. The uncertainty that had motivated
that default was about the **hmac scheme's header name**, which is a configuration
problem; the thing it traded away was payload integrity, which is a security
problem. Those are not the same kind of cost.

## Decision

### 1. The invariant

> **An idempotency key MUST be a function of bytes the provider's signature
> covers.** Nothing an attacker can vary while keeping a captured signature valid
> may feed it.

This is stated once, in `billing.Event`, and every adapter upholds it.

### 2. `Event.DedupKey`, separate from `Event.ID`

`billing.Event` gains a `DedupKey` field and an `IdempotencyKey()` accessor:

```go
// DedupKey is the idempotency key, and it MUST be derived only from material
// COVERED BY THE PROVIDER'S SIGNATURE. Empty means "no separate key" and
// callers fall back to ID.
DedupKey string

func (e Event) IdempotencyKey() string {
    if e.DedupKey != "" { return e.DedupKey }
    return e.ID
}
```

`Event.ID` is **demoted to a correlation label**: it is what an operator pastes
into a provider dashboard and what appears in the audit log, and it is documented
as *not* a security value. `sigild/internal/api/billing.go` passes
`EventID: ev.IdempotencyKey()` to the store, so there is exactly one place where
the ledger key is chosen and it cannot silently revert to the header.

Per provider:

| Provider | `DedupKey` | Why it satisfies the invariant |
|----------|-----------|-------------------------------|
| **Razorpay** | **always** `"body-" + hex(SHA-256(raw body))` | The signature covers the body, so a byte-identical body is exactly **one** event whatever the headers say. `X-Razorpay-Event-Id` is kept on `Event.ID` for correlation only. |
| **Stripe** | `env.ID` — the event id **inside** the JSON payload | The signed message is `"<t>.<raw body>"`, so the id is already covered. Set explicitly rather than left to the `ID` fallback, so the guarantee is visible at the call site. |
| **Juspay** | the id parsed out of the **body**, or `"body-" + hex(SHA-256(raw body))` when the payload carries none | Both forms come out of the body, never a header — so under `scheme=hmac` the key is signature-covered. |

Note what changed and what did not: Razorpay's fallback was already a body hash.
The fix is that the body hash is now the **only** thing that keys the ledger,
rather than a fallback used when a header the attacker controls happens to be
missing.

### 3. Juspay's default webhook scheme is `hmac`

`NewJuspay`'s switch is inverted: `case JuspaySchemeBasic` selects the
connection-authenticating verifier and **`default` selects HMAC**. An empty or
unrecognized scheme therefore lands on the body-binding verifier with **no secret
configured**, which accepts nothing — it fails closed rather than degrading to
connection-only authentication.

`cmd/server/billingconfig.go` follows: `SIGILD_JUSPAY_WEBHOOK_SECRET` is
**required when the scheme is unset**, choosing `basic` without its credentials is
a **boot failure** whose message names what was opted into, and a server booting
with `scheme=basic` logs a `WARN` every start stating that Basic authenticates the
connection and not the payload. Both schemes still work; the weaker one now has to
be **asked for by name**.

### 4. The scope note that goes with it

The invariant holds for **Stripe**, **Razorpay**, and **Juspay under
`scheme=hmac`**. Under **Juspay `scheme=basic` it is vacuous** — that scheme
covers no bytes, so there is nothing for a dedup key to be derived *from*, and the
integrity property this ADR is about does not exist there at all. This is recorded
in [`../threat-model.md`](../threat-model.md) beside adversary classes K
(replayer) and L (body tamperer) rather than left implicit.

## Consequences

### Good

- **The documented idempotency guarantee is now true for every provider**, not
  just for the providers whose event id happens to sit inside the signed payload.
- **The processed-events ledger can no longer be grown on demand** by replaying
  one captured delivery with fresh headers.
- **The rule is checkable by reading one field.** A future fourth adapter has a
  named invariant to satisfy and an accessor that makes violating it deliberate
  rather than accidental — the previous shape made the *wrong* choice the easy one.
- **The weaker Juspay scheme is now a decision, not a default.** Getting
  connection-only authentication requires setting a variable to `basic` and
  reading a `WARN` at every boot.
- **No new dependency, no interface change.** One field, one accessor, one
  inverted switch; `sigild/go.mod` still has exactly one direct require.

### Bad / accepted costs

- **Razorpay's dedup key is no longer human-recognizable.** The ledger stores a
  body hash where an operator might have expected the dashboard's event id. That
  id is still on `Event.ID` and in the audit log, so correlation survives — but a
  reader of the table alone now needs to know the mapping.
- **A provider that legitimately redelivers a semantically-identical event with a
  different body** (a re-serialization, a changed `created_at`) would be treated as
  two events under a body-derived key. For Razorpay this is the correct trade — the
  alternative admits attacker-chosen keys — but it is a behavioural difference from
  keying on a provider-assigned id, and it is untested against a live account.
- **Flipping Juspay's default is a breaking configuration change** for any
  deployment that relied on the old default. There is none — nothing has ever run
  against a live provider account — but it would be one if there were, so it is
  called out here rather than discovered at boot.

### Honest limits

- **Still never run against a live provider account.** Every test drives a local
  `httptest` server with fake credentials. This ADR changes which bytes a key is
  derived from; it does not change the fact that Razorpay's and Juspay's wire
  details remain **medium confidence** and **unverified against a live dashboard**
  respectively (0034 records both, and both still stand).
- **The invariant is vacuous under Juspay `scheme=basic`**, as above. No amount of
  key derivation fixes an authentication scheme that covers no bytes.
- **Still no rate limiting on the webhook route.** This closes the
  unbounded-ledger-growth path that ran *through* the idempotency key; it does not
  bound request volume, and 0034's note stands.
- **Still no in-scheme replay bound for Razorpay or Juspay.** Neither signs a
  timestamp, so the ledger remains the only replay bound for them — it is simply a
  ledger that can no longer be tricked into seeing one event as many.
- **The in-memory subscription store is still non-durable**, so a redelivery
  across a restart can still be applied twice. Only the Postgres backend gives the
  guarantee across restarts and processes.
- **UNAUDITED**, dev-gated, `501` by default, like everything around it.

## Verification

Both halves were checked by **mutation**, not by inspection:

- Reverting `EventID: ev.IdempotencyKey()` to `EventID: ev.ID` makes the replay
  succeed — the second delivery returns `"accepted"`, i.e. the attack works — and
  `TestWebhookRazorpayReplayWithFreshHeaderIDIsOneEvent` fails. Restored, the
  `sigild` suite is green under `go test -race`.
- Against a live local server the forgery set behaves: a wrong secret, a tampered
  body and a missing signature header are `401`, `401`, `401`.

## Alternatives considered

- **Keep the header id and add a rate limit to the webhook route.** Rejected as
  treating the symptom. A rate limit is worth having on its own merits, but it
  would leave the idempotency key attacker-controlled, and the documented "a
  duplicate delivery is a no-op" would still be false.
- **Include the header id in the signed message.** Not ours to decide — the
  provider defines what it signs. We can only choose what to key on among the
  bytes it *does* sign.
- **Use the body hash as the dedup key for every provider, uniformly.** Rejected
  for Stripe: its event id is inside the signed payload, is stable across
  redeliveries, and is what an operator sees in the dashboard. Using it is both
  safe and more useful, and the per-provider table above makes the reasoning
  explicit at each site.
- **Drop the `basic` scheme entirely.** Rejected: it is reportedly what some
  Juspay merchant accounts offer, and removing it would leave such an account with
  no working configuration at all. Making it an explicit, warned opt-in keeps it
  available without letting anyone arrive at it by accident.
- **Reject deliveries whose `X-Razorpay-Event-Id` disagrees with a previously-seen
  id for the same body.** Rejected as a state machine that exists only to police an
  untrusted header, adding storage and failure modes to defend a value we had
  already decided not to trust.
