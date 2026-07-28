# 0045 — A rejected write never claims a vault (the claim precondition)

- **Status:** Accepted (2026-07)
- **Date:** 2026-07-28
- **Builds on:** [0031](0031-multi-device-auth-model.md) (trust-on-first-write and
  the `needWrite` / `needWriteNoClaim` access levels), [0040](0040-account-model.md)
  (ownership moved from the device to the **account**, but the claim *trigger* did
  not move), [0035](0035-device-to-device-vault-sharing.md) (the key-envelope
  deposit, the second route that claims), [0017](0017-oplog-scale-and-observability.md)
  (the per-vault rate limiter that cannot bound this).
- **Found by:** the fourth full-repo adversarial audit, against `ab37e05`.

## Context

Ownership of a vault is **trust-on-first-write**: the first account that
successfully authenticates a write to an unowned vault becomes its owner, and
after that everyone else gets `403` forever. Ownership never moves between
accounts — there is no transfer, no merge, no release.

The claim fired **inside the authorization step**, in `authorizeVault(…,
needWrite)`. Authorization runs before a handler gets to look at the request at
all. So a request the server was about to **reject** still took ownership on its
way to the rejection.

The reproduction, run live against a real `sigild` with dev ops + device auth v3:

- one enrolled device sent **50 empty-bodied `POST /v1/vaults/{id}/ops`**, each
  to a different, never-seen vault id;
- every response was **`400 empty_op`** and **not one op was stored**;
- `sigild_vault_claims_total` rose by **50**;
- a second device then made a **genuine** first write to one of those ids and was
  answered **`403`** — permanently, on a vault it had every right to.

`PUT /v1/vaults/{vaultID}/keys/{deviceID}` had the same shape, through its
empty-body, unknown-recipient and revoked-recipient rejections.

Three things make this worse than an ordinary ordering bug:

1. **The rate limiter cannot bound it.** `SIGILD_OPLOG_RATE_LIMIT` keys on the
   vault id, and a squatter varies the vault id on every request. During the
   reproduction the limiter never fired once.
2. **Vault ids are low-entropy and human-chosen.** They are client-supplied
   strings, not server-assigned handles; the webapp's default is the literal
   `"webapp-demo"`. Guessing is not required.
3. **A claim is free and permanent.** The attacker stores nothing, pays no
   entitlement check and leaves no op behind — but the id is gone for good.

This is the sibling of the finding the third audit fixed. That one was a
*read-shaped* route wired to `needWrite`, and the fix was the
`needWriteNoClaim` level ([journal, Audit #3 follow-up](../../journal.md)). This
one is a *write-shaped* route whose write was never going to be applied. The
level existed; nothing was using it for this case.

## Decision

**A write that the server is going to reject must not be able to claim a vault.**

The mechanism is a `claimPrecondition` — a cheap, **vault-independent** predicate
supplied by the handler and evaluated after authentication, before authorization
(`sigild/internal/api/deviceauth.go`):

```go
type claimPrecondition func() bool

func (h *handlers) authorizeOpsWrite(r *http.Request, body []byte, vaultID string,
    wellFormed claimPrecondition) (store.Device, authOutcome)
```

When `wellFormed()` reports false, and **only** then, the required access level is
downgraded from `needWrite` to `needWriteNoClaim`. The permission demanded is
identical; the difference is that `needWriteNoClaim` can never reach
`ClaimVault`.

Four properties are deliberate:

1. **Nothing about the verify order changed.** Authentication still precedes
   authorization; authorization still precedes the handler's answer. The
   precondition changes only whether the vault is **claimed** — never whether the
   request is *allowed*.
2. **A precondition must be cheap and vault-independent** — a body-shape check, or
   a lookup of a device named in the path. If it could depend on the vault's own
   state, the downgrade would itself become an oracle for that state.
3. **It is evaluated on the device-auth path only.** In the legacy v2 and
   unauthenticated modes nothing ever claims, so there is nothing to suppress and
   the predicate is not called.
4. **The verdict is memoised and reused to write the response**, so each check runs
   at most once and the rejection cannot drift from the precondition that gated
   it. In `sharing.go` the three shape checks were factored into one
   `checkKeyEnvelopePut` for exactly that reason.

Applied at both claiming routes: `opsAppend` (empty body) and `keyEnvelopePut`
(empty body, unknown recipient, revoked recipient).

## Consequences

### ⚠️ One client-visible status changed, and it is documented as such

**An empty or malformed write to an UNOWNED vault now answers `403`, not `400`.**

The caller holds no grant on that vault and no longer earns ownership on the way
past, so authorization refuses it before the handler ever forms its `400`. On a
vault the caller **may already write**, the answer is unchanged: `400 empty_op`,
`404 device_not_found`, `409 device_revoked`, exactly as before.

That is a real behaviour change in a documented case, which is why this is an ADR
and not a bug-fix line in the journal. It is recorded in
[`api.md`](../api.md#post-v1vaultsvaultidops--append-an-operation).

We considered answering `400` anyway by evaluating shape before authorization.
Rejected: a `400` on an unowned vault would tell an unauthorized caller that its
*request* was well-formed enough to be judged, on a vault it has no relationship
to — a small oracle bought for cosmetic consistency. Coarse-and-boring wins.

### Verified live, both directions

- 25 rejected appends across 25 fresh vault ids → **0 claims**
  (`sigild_vault_claims_total` unmoved), and a **different** device then claimed
  all 25 with genuine writes.
- Legitimate trust-on-first-write still claims normally on the first well-formed
  append and the first well-formed envelope deposit.
- `sigild/internal/api/claimsquat_test.go` pins both handlers, scraping
  `sigild_vault_claims_total` off `/metrics` rather than asserting on internals.

### ⚠️ Honest limit — this removes the FREE claim, not squatting

A determined device can still squat vault ids by sending **genuinely well-formed**
writes. Each one is stored, entitlement-checked and audited, so it costs the
attacker something — but nothing bounds the total.

**The real bound is a per-ACCOUNT claim budget, and it is not implemented.** It
must never be keyed on the vault id, which the attacker controls. There is a code
comment naming this at `claimPrecondition`, and nothing else.

**Trust-on-first-write remains a dev ownership model, not an account model.**
[ADR 0040](0040-account-model.md)'s honest limitation stands: an attacker who
writes to an unclaimed vault id first becomes its owning account, ownership never
moves between accounts, and losing every device in an account still loses the
vault unless a recovery kit was printed in advance.

### Scope

`sigild` is still dev-gated (`501` by default), plain HTTP, pre-audit and
**UNAUDITED**. The op-log blob is untouched: this is an ordering change in the
authorization path and adds no crypto, no column and no migration —
`sigild_schema_version` stays **5**.
