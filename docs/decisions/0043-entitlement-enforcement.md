# 0043 — Entitlement enforcement: writes may be refused with `402`, reads and same-account key recovery never are

- **Status:** Accepted (2026-07)
- **Date:** 2026-07-28
- **Revises (does not supersede):** limitation 8 of
  [0040](0040-account-model.md) ("**Entitlement is REPORTED, never ENFORCED.** No
  route refuses service to an unentitled account"). 0040's body is unchanged; it
  carries a dated addendum pointing here.
- **Builds on:** [0040](0040-account-model.md) (the **account** is the subject
  being evaluated, and the invariant that **no request names an account** is what
  keeps this from becoming an oracle), [0034](0034-billing-provider-seam.md) (the
  subscription store and the `billing.Status` state machine this reads),
  [0031](0031-multi-device-auth-model.md) (the `authenticateDevice` /
  `authorizeVault` choke points the gate sits strictly *after*),
  [0042](0042-recovery-kit.md) (a recovery kit is an ordinary member device, which
  is why printing one had to survive a lapse).

## Context

Sigil is a paid product whose server, until this phase, never asked whether
anyone had paid. `GET /v1/billing/subscription` would tell a client its account
was `canceled`, and every route then served it anyway
([ADR 0040](0040-account-model.md) limitation 8).

The reason it was deferred is the reason it is dangerous, and it has not gone
away:

> **This product holds a customer's second factor. Gating it on payment status
> means a declined card can lock a person out of their own bank login.** That is
> not a billing inconvenience; it is a security failure we would have caused.

So the question was never "should entitlement be enforced" but **"what exactly
may be refused, such that a non-paying customer is inconvenienced and never
harmed"**. The answer is an asymmetry, and the whole of this ADR is that
asymmetry and the two rounds it took to get its boundary right.

## Decision

### 1. Enforcement is opt-in, and OFF means byte-identical

`SIGILD_ENTITLEMENT_ENFORCE` (unset by default) turns it on;
`SIGILD_ENTITLEMENT_GRACE` sets the window.

| Variable | Default | Bounds | Meaning |
|----------|---------|--------|---------|
| `SIGILD_ENTITLEMENT_ENFORCE` | unset ⇒ **off** | `1` / `true` (case-insensitive) | refuse **writes** from an account whose subscription lapsed longer ago than the grace period |
| `SIGILD_ENTITLEMENT_GRACE` | **14 days** (`api.DefaultEntitlementGrace`) | `(0, 365d]`, a Go duration | how long after a lapse writes keep working — **warned, not refused** |

"Off" is **structural, not conditional**: `entitlementPolicy`'s zero value is
inactive and `requireEntitlement` returns on its first line — *no store read, no
header, no log line, no metric*. `entitlementBlock` returns `nil`, so the
`entitlement` key is **absent** from `GET /v1/billing/subscription` and that
response is byte-identical for every server that has not opted in.

⚠️ **Unlike the abuse limiters of [ADR 0041](0041-abuse-bounds-and-the-removed-webhook-limiter.md),
this REQUIRES its prerequisites.** `SIGILD_ENABLE_DEV_OPS`, `SIGILD_DEVICE_AUTH`
and `SIGILD_BILLING_PROVIDERS` must all be set, and setting
`SIGILD_ENTITLEMENT_GRACE` without `SIGILD_ENTITLEMENT_ENFORCE` is a **boot
error** — each with a message saying *why*. A rate limit that is silently moot is
harmless; **a payment gate that is silently moot is a business and support
hazard**, and an operator who set a grace period believes writes are being
enforced. The default is 14 days *because* the costs are not comparable: too
generous means two extra weeks of free use; too strict means somebody cannot log
in to their bank.

The router re-checks (`cfg.EntitlementEnforce && deviceAuth && billingEnabled()`),
so a half-configured server holds a **zero policy** rather than a partly-armed
one, and `sigild_entitlement_enforcing` exports the answer as a gauge — a knob
believed to be on but silently inert is exactly the failure this repo keeps
refusing to ship.

### 2. ⭐ READS ARE NEVER REFUSED, and the asymmetry is the shape of the code

`requireEntitlement` is called from **exactly three handlers**, and all three are
writes: `opsAppend`, `keyEnvelopePut`, `vaultGrantCreate`. **No read handler
calls it.** The read path contains **no entitlement code at all** — there is
nothing to misconfigure, no store to be down, and no branch that could refuse.

That is not a convention. `entitlement_test.go` **parses the package's AST** and
fails if the call set ever changes, so the asymmetry is mechanically enforced
rather than remembered.

A customer whose subscription has fully lapsed can therefore always: read every
op in every vault they hold (**generate every 2FA code they already have**),
collect every key envelope addressed to them, enumerate which vaults hold a key
for them, publish a hybrid key, enroll a device, **revoke** a device, delete a
stale envelope, mint an invite, read their account, and run checkout to pay.

A verifier drove this live and confirmed a lapsed account still produced the
RFC 6238 vector `94287082`, and that **`past_due` remains entitled** — a declined
card starts the provider's retry window, not a cutoff.

### 3. ⭐ AND: establishing key access within your own account is never refused either

"Reads are never refused" was the **first** boundary, and a verifier proved it
insufficient by driving the failure it allows.

Past grace, a customer whose phone had just died could enroll a replacement — and
then **could not receive the vault key for it** (`PUT …/keys/{device}` → `402`),
so the new phone downloaded ciphertext it could never decrypt. **Printing a
recovery kit was refused for the same reason**, since a kit is an ordinary member
device ([ADR 0042](0042-recovery-kit.md)) and covering it is a key deposit. The
customer was left **one device failure away from permanent loss** — while the
`402` body claimed `key_recovery_allowed: true`. The response was making a
promise the code did not keep.

**A read-only guarantee over data you cannot decrypt is not a guarantee.** So the
rule became **getting your own data out is never refused**, which necessarily
includes establishing the key material needed to read it:

> `sameAccountRecipient()` exempts a key-envelope deposit **and the grant that
> accompanies it** whenever the recipient device belongs to the **caller's own
> account** — which covers replacing a lost device, and generating or covering a
> recovery kit.

What is still refused after grace: **new op-log writes**, and **shares to a
device of a different account**. Those grow what we store for a non-paying
customer, or extend the product to somebody else; neither is "getting your own
data out".

`sameAccountRecipient` is **deliberately conservative**: an unknown device, a
registry error, a caller with no account or an empty recipient all resolve to
"not exempt", so a store fault can never be used to *bypass* enforcement — and
since enforcement is itself fail-open (§5), the customer is never the one who
pays for the ambiguity.

### 4. `402` is not `401` and not `403`, and it is not an oracle

A refusal is **HTTP 402 Payment Required** with its own machine-readable body
(`"error": "payment_required"`), never collapsed into the coarse
`unauthorized` / `forbidden` envelopes. Both halves of that are deliberate:

- A client must be able to tell *"pay to continue"* from *"your key is wrong"*
  and from *"you may not touch this vault"*, and act on it. The body names the
  checkout route, states the account's own status, and states what is **still**
  available (`reads_allowed`, `key_recovery_allowed` — both always `true`, and
  since §3 both actually true).
- The coarse auth bodies exist so a prober cannot learn *which* check failed. **No
  such oracle is created here**, because the gate runs strictly **after
  authentication AND authorization have both succeeded**. An unauthenticated or
  unauthorized caller gets its `401`/`403` exactly as before and can never see a
  `402` — so the only party who learns an account's billing state is a **verified
  member of that account**, which `GET /v1/billing/subscription` already tells
  them. With the dev gate off, every gated route stays `501`, never `402`.

**Warnings arrive before refusals.** Inside grace the request is **served** and
the client is told: `X-Sigil-Entitlement: grace`, plus the status and the instant
writes stop, on the successful 2xx. An **additive `entitlement` block** on
`GET /v1/billing/subscription` is the warning channel for read-only clients,
which are never refused and would otherwise discover the lapse only on their
first write.

### 5. Every uncertainty FAILS OPEN

| Condition | Verdict |
|-----------|---------|
| enforcement not configured | **allow** — and do no store work at all |
| the subscription store errors | **allow** (`subscription_store_error`) |
| the account row cannot be read | **allow** (`account_unreadable`) |
| no anchor date can be established | **allow** (`no_lapse_anchor`) |
| the device carries no account | **allow** — an *authorization* state, already refused upstream with a `403`; it must never be re-served as a payment problem |

A database blip must never cost a customer their vault. `entitlement.fail_open`
is logged at **error** level precisely because it means enforcement is silently
**not** happening — an operator must see a store fault handing out free service,
rather than discover it in a revenue report.

### 6. Where the grace period is measured from

Refusal never follows a payment event directly. On top of `past_due` already
being entitled, grace runs from an **anchor**:

- **With a subscription record:** the **later** of `UpdatedAt` and
  `CurrentPeriodEnd`. Taking the later is the customer-favouring choice on
  purpose — a subscription canceled mid-period keeps working until the period it
  was **already paid for** ends, and any later touch of the row can only
  **extend** service, which is the direction a mistake here must always fail in.
- **With no record at all** (never subscribed): the **account's creation time**.
  Otherwise "never subscribe" would be a permanent free tier and enforcement
  would close nothing. ⚠️ **This makes the grace period double as the buy-in
  window** — a trial by side effect. There is no separate trial mechanism in this
  server, and it is named as such rather than dressed up as one.

The boundary is exclusive: exactly at `anchor + grace`, writes are refused.

### 7. Observability

`sigild_entitlement_enforcing` (gauge, `0`/`1`, no label) and
`sigild_entitlement_decisions_total{outcome}` over the **closed** set
`{entitled, grace, refused, fail_open}` — counts only, and **deliberately no
account or subject label**, so an always-on unauthenticated scrape can never
learn *who* was refused, only how often anyone was.

Audit events `entitlement.grace` (warn), `entitlement.refused` (warn) and
`entitlement.fail_open` (error) carry an account id, a device id, a status from
the closed billing enum, a grace instant and a fixed `surface`
(`ops_append` / `key_envelope_put` / `vault_grant`) — **never** a token, key,
signature, nonce, card field or byte of ciphertext. `surface` is an audit field
only, never a metric label. By its **absence** from that stream, the log is also
the evidence that no read was ever refused.

**Zero-knowledge is unchanged**: nothing in this file reads a blob, a key, a
password or a plaintext.

## The sentence an auditor should be able to check

> Enforcement is called from exactly **three write handlers** and from nowhere
> else (checked by a test that parses the package's AST); **no read path contains
> any entitlement code**; depositing a vault key to a device of the **caller's
> own account** — including a recovery kit — is exempt; every uncertainty
> **allows**; and a `402` is reachable **only** after both authentication and
> authorization have already succeeded.

## Consequences

### Good

- **The paid product can actually refuse a non-paying account** without ever
  refusing the thing customers need most: their existing codes.
- **The dangerous half is impossible by construction, not by care.** A future
  contributor cannot add an entitlement check to a read handler without a test
  failing.
- **A lapsed customer cannot be trapped.** They can replace a dead device, obtain
  the keys for it, print a recovery kit, revoke a stolen device, and pay.
- **`402` is honest and actionable**, and creates no new oracle because it lives
  downstream of both existing choke points.
- **Off is genuinely off** — byte-identical responses, no store reads, no
  headers, no logs, no metric movement.
- **No new dependency, no new table, no migration.** `sigild_schema_version`
  stays **5**.
- **The verifier mutation-tested this phase hard: 15 separate control mutations
  all went red**, including the read-path exemption, the same-account exemption,
  the `past_due` classification, the anchor choice and the fail-open branches.

### Bad / honest limitations

1. ⚠️ **This is still a payment gate on a security product.** The blast radius of
   a bug here is a customer refused a write they were entitled to. Every
   uncertainty fails open specifically because that is the failure we can afford;
   nothing makes the gate *correct*, only *safe when wrong*.
2. ⚠️ **A never-subscribed account is graced from its creation time, which is a
   trial nobody designed.** There is no trial state, no trial length independent
   of the grace window, and no way to extend one account's window without
   extending everyone's.
3. **Enforcement depends on the subscription store, which is only durable under
   Postgres.** With the in-memory store, a restart loses every subscription and
   every account then fails open — free service, silently, until the store is
   repopulated.
4. **A vault claim happens before the refusal.** A first write to an *unclaimed*
   vault is claimed by the authorization step and only then refused with `402`.
   Accepted knowingly: the claim binds the vault to the caller's **own** account
   — the same party that would pay — and keeping the claim inside the single
   authorization choke point is worth more than avoiding it.
5. **There is no dunning, no notification, no email, no invoice and no
   reconciliation.** The only warnings are response headers, the additive
   subscription block, and the server's own audit log. A customer who never
   writes and never reads their subscription route learns nothing until they are
   refused.
6. **No per-account override.** There is one grace period for the whole server;
   an operator cannot extend one customer's window, grant a comp, or exempt an
   account, other than by moving its subscription state through the billing
   provider.
7. **Refusal is not revocation.** Nothing is deleted, nothing expires, and a
   lapsed account's data stays exactly where it was — which is correct, and also
   means a non-paying account costs storage indefinitely.
8. **`past_due` is entitled**, so a genuinely failed card buys the provider's
   whole retry window *plus* the grace period before anything happens. That is
   deliberate and it is also a real revenue leak.
9. **All the billing caveats still hold.** Billing has never been run against a
   live provider account, the **Juspay** adapter remains
   *UNVERIFIED-AGAINST-LIVE-DASHBOARD*, and a compromised provider webhook secret
   can now move an account's **entitlement**, which since this phase means it can
   move an account's **service**.
10. **Dev-gated, `501` by default, plain HTTP, pre-audit, UNAUDITED.**

### Neutral

- `GET /v1/billing/subscription` gained an **additive**, `omitempty`
  `entitlement` block; clients that ignore unknown fields are unaffected.
- Three response headers (`X-Sigil-Entitlement`,
  `X-Sigil-Entitlement-Status`, `X-Sigil-Entitlement-Grace-Ends`) appear **only**
  on gated writes that are in grace or refused. An entitled account's responses
  carry none of them.

## Alternatives rejected

- **Gate reads too** (refuse `GET …/ops` for a lapsed account). Rejected
  outright: it locks a person out of their own second factor over a declined
  card. This is the decision the whole ADR exists to record.
- **Gate writes only, with no same-account exemption** — the first
  implementation. Rejected on a live reproduction: it left a lapsed customer with
  a replacement phone full of ciphertext it could never decrypt, unable to print
  a recovery kit, one device failure from permanent loss — while the `402` body
  claimed key recovery was allowed. See §3.
- **Collapse the refusal into the existing `403`.** Rejected: a client could not
  distinguish "pay" from "you are not authorized", and no oracle is created by
  the distinct status because the gate is strictly downstream of authorization.
- **Return `402` before authorization** (cheaper — no vault lookup). Rejected: it
  would turn the status into an oracle on an account's billing state for callers
  who were going to be refused anyway.
- **Fail closed on a store error.** Rejected: a database blip would refuse every
  paying customer at once. The counter-risk — free service during an outage — is
  logged at error level so it is visible.
- **A short grace period (hours/days).** Rejected in favour of 14 days by
  default, for the asymmetry in §1.
- **An account/subject label on the enforcement metric.** Rejected for the same
  reason as [ADR 0040](0040-account-model.md) limitation 11: `/metrics` is
  always-on and unauthenticated, so the label would let a scrape enumerate which
  customers are behind on payment.
- **Deleting or expiring a lapsed account's data.** Not considered seriously and
  recorded so it is not mistaken for an oversight: the server cannot read the
  data it would be deleting, and destroying a customer's second factor over a
  billing state is the same failure as refusing reads, made irreversible.

## References

- Code: [`../../sigild/internal/api/entitlement.go`](../../sigild/internal/api/entitlement.go)
  (`requireEntitlement`, `sameAccountRecipient`, `evaluateEntitlement`,
  `lapseAnchor`, `writePaymentRequired`, `entitlementBlock`),
  [`handlers.go`](../../sigild/internal/api/handlers.go) (`opsAppend`),
  [`sharing.go`](../../sigild/internal/api/sharing.go) (`keyEnvelopePut`),
  [`devices.go`](../../sigild/internal/api/devices.go) (`vaultGrantCreate`),
  [`router.go`](../../sigild/internal/api/router.go),
  [`audit.go`](../../sigild/internal/api/audit.go),
  [`metrics.go`](../../sigild/internal/api/metrics.go),
  [`../../sigild/cmd/server/main.go`](../../sigild/cmd/server/main.go)
  (`validateEntitlementConfig`, `logEntitlementEnforcement`).
- Tests: [`../../sigild/internal/api/entitlement_test.go`](../../sigild/internal/api/entitlement_test.go)
  (including the AST test that pins the call set),
  [`../../sigild/cmd/server/entitlementconfig_test.go`](../../sigild/cmd/server/entitlementconfig_test.go).
- Contract: [`../api.md`](../api.md) — the `402` body, headers and the
  refused/never-refused table.
- Operator runbook: [`../deployment.md`](../deployment.md) §16.
- Adversaries: [`../threat-model.md`](../threat-model.md).

## The warning channels now have readers (added Phase 56, 2026-07-28)

Per this repo's addendum rule the text above is left untouched; this section
records only what changed.

**When this ADR was written, the three warning channels it designed — the
`X-Sigil-Entitlement*` response headers (§4), the additive `entitlement` block on
`GET /v1/billing/subscription` (§4), and the machine-readable `402` body (§4) —
had NO CLIENT READERS AT ALL.** Every one of them was a signal `sigild` emitted
into silence: a customer inside their grace period was never told, and a refusal
rendered as whatever raw text the client happened to print. Phase 56 built the
readers.

- **Webapp + MV3 extension**, over the new framework-free
  [`../../sigil-wasm/entitlement.mjs`](../../sigil-wasm/entitlement.mjs)
  (`getSubscription` / `entitlementState` / `describeEntitlement` /
  `readEntitlementHeaders` / `explainSubscriptionStatus`): an entitlement block
  reads the subscription route on mount — the **only** warning channel a
  read-only client ever sees, since it is never refused — and the sync path reads
  the warning headers off a successful write. A server with enforcement **off**
  (the default) sends neither, which is reported as `off` and **renders
  nothing**.
- **Desktop.** §4's warning was **dead code** here: `from_subscription_block`
  had **zero production callers**, so the `writes = "grace"` state could never be
  reached and a desktop inside grace was never warned. The root cause was that
  the `sigil-cli` library exposed **no billing route at all**. It is now wired end
  to end — `fetch_subscription` (CLI library) → `DeviceConfig::subscription()` →
  the `entitlement_refresh` Tauri command → the UI banner — with a **real-server**
  test in `desktop/core/tests/server_interop.rs` proving a desktop inside grace is
  warned **before** any write is refused. Per
  [ADR 0037](0037-desktop-reuses-cli-library-for-protocol.md) this added no second
  HTTP client and no second request-signing path.
- **CLI.** A `402` was previously printed as a raw JSON dump while `401`, `403`
  and `501` each got an explainer. All five explainers (`explain_sync_error`,
  `explain_device_error`, `explain_account_error`, `explain_sharing_error`,
  `explain_recovery_error`) gained a `402` arm stating that it is a **billing
  state, not an authentication or permission failure**, and that reads and
  same-account key recovery are unaffected. ⚠️ Precisely: it still prints the
  server's body **first** and the prose **after**, matching this CLI's
  established `{e}\n  -> HTTP nnn: …` convention — the JSON was not removed, it
  was explained.

**Conformance against the real bytes** is
[`../../sigil-wasm/test/entitlement-interop.mjs`](../../sigil-wasm/test/entitlement-interop.mjs)
(now wired into `interop.yml`, 12/12). It is the **only** thing in the repo that
parses a real `sigild`'s entitlement headers, `entitlement` block and `402` body
with the JS reader — the browser suites use a test double — so a divergence
between `entitlementJSON` / `paymentRequiredResponse` and the JS parser would
otherwise go red in **no** job, and the failure mode is a client telling a paying
customer the wrong thing about their own subscription.

**What is NOT retired.** Limitation 5 is **narrowed, not closed**: there is still
**no dunning, no notification, no email, no invoice and no reconciliation**. The
only warnings remain the response headers, the subscription block and the audit
log — what changed is that clients now read them. Every other limitation stands
as written, including that this is a payment gate on a security product, that a
never-subscribed account is graced from its creation time, that enforcement is
durable only under Postgres, and that all of it is dev-gated, plain HTTP,
pre-audit and **UNAUDITED**.
