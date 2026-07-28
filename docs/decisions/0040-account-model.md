# 0040 — Accounts as the subject of entitlement and the owner of vaults (server-assigned account id on the device row, single-use invites over the unchanged enrollment challenge)

- **Status:** Accepted (2026-07)
- **Date:** 2026-07-28
- **Revises (does not supersede):** limitations 1 and 4 of
  [0031](0031-multi-device-auth-model.md) (trust-on-first-write is "not an
  account model"; "revoking a vault's owner ORPHANS the vault"), and the
  "**no account model** — a subscription keys off the enrolled DEVICE"
  limitation of [0034](0034-billing-provider-seam.md). 0031's and 0034's bodies
  are unchanged; 0031 carries a dated addendum pointing here.
- **Builds on:** [0031](0031-multi-device-auth-model.md) (the device registry and
  contract v3, whose choke points this reuses verbatim),
  [0034](0034-billing-provider-seam.md) (the billing seam whose subject this
  moves), [0035](0035-device-to-device-vault-sharing.md) (the key relay that
  still does the decryption half), [0018](0018-managed-oplog-migrations-and-backup-integrity.md)
  (the migration machinery `0005_accounts.sql` rides on).

## Context

Sigil is a **paid, multi-device** product. Until this phase the only subject the
server had was a **device**, and two verified defects followed directly from
that:

1. **Entitlement was per-device.** `sigild/internal/api/billing.go` set
   `Subject: dev.ID` on both the checkout and the status route, so a customer
   who paid on their phone was **not entitled on their laptop**. Every device
   would have had to buy its own subscription. For a product whose whole premise
   is "your 2FA on all your devices", that is not a rough edge; it is the
   business model failing to work.
2. **Vault ownership was per-device, so revocation orphaned vaults.**
   Trust-on-first-write bound a vault to the *device* that first wrote it. Revoke
   that device — the prescribed remedy for a lost or compromised phone — and
   nobody could ever grant on that vault again. This repo already recorded the
   defect in three places ([ADR 0031](0031-multi-device-auth-model.md)
   limitation 4, `CLAUDE.md`, [`../threat-model.md`](../threat-model.md)); it was
   documented, not fixed.

Both defects have the same shape: **the subject was too small**. A device is the
unit that holds a key and signs a request. It is the wrong unit to bill, and the
wrong unit to own long-lived shared state.

The constraint that shaped the answer is the repo's standing guardrail
(`CLAUDE.md`: *don't fake crypto/auth*, and *don't invent decisions that were not
made*). An "account model" in most products means identity: email, password,
recovery, support-desk break-glass. **None of that exists here and none of it was
built.** What was needed was the smallest thing that makes entitlement and
ownership survive a device change — and an honest statement of everything it is
still not.

## Decision

Introduce an **account** as the subject of entitlement and the owner of vaults.
The whole model in one sentence:

> An account is a **server-assigned id on the device row**; a **single-use
> invite** minted by a member device is the only way a second device joins; and
> ⭐ **no request anywhere names an account** — the account is always
> `dev.AccountID`, taken from the device row of the signature the server just
> verified.

### 1. An account is auth metadata on the device row — nothing more

`sigil_accounts` holds an id, a creation time, and the device that founded it.
There is deliberately **no label and no status column**: a label is user data
with no server-side use (and exactly where an email would eventually get typed),
and a status column no route sets is dead schema implying a feature that does not
exist. `sigil_devices` gains a **nullable** `account_id` referencing it.

Account ids are `acct_` + `base64.RawURLEncoding` of 16 `crypto/rand` bytes.
`NewAccountID` **refuses** to return an id carrying the `acct_mig_` prefix, so a
freshly generated account can never collide with — or silently merge into —
migration 0005's deterministic adopted namespace (§6).

`CreatedByDeviceID` is **audit metadata only**. It records who founded the
account so an operator can explain the trail; it confers **no power whatsoever**.
Membership is flat (§7, limitation 3).

**Zero-knowledge is untouched.** Nothing here sees a vault key, a password or a
plaintext; an invite is recorded only as a SHA-256 digest; `sigil_vault_ops` is
not named anywhere in the migration.

### 2. No request names an account

This is the structural rule, and it is what closes every cross-account IDOR
before it can exist. There is **no path segment, no query parameter and no body
field anywhere in the API that names an account.** Every handler derives the
account from `dev.AccountID` after `authenticateDevice` has verified the
signature.

The consequence worth stating plainly: a client cannot construct a request that
reads or writes another account's state — not by guessing an id, because **there
is nowhere to put one**. That is a stronger property than "such requests are
rejected", and it is why `GET /v1/account` is always "mine" and there is no route
that enumerates accounts.

A JSON body carrying `account_id` or `subject` is simply ignored by
`encoding/json`, which the interop suite pins as a property.

### 3. An invite rides the EXISTING enrollment challenge — no fourth canonical message

A second device joins by presenting a **single-use invite** minted by a device
already in the account. The invite travels in the **existing
`X-Sigil-Enroll-Token` header**, under the **existing `canonicalEnrollMessage`**
from [ADR 0031](0031-multi-device-auth-model.md) §2:

```
CHALLENGE = "sigil-device-enroll-v1\n" + TOKEN_SHA256_HEX + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + PUBLIC_KEY_B64 + "\n" + LABEL
```

**Why this works without a change:** the challenge already binds the token's
**SHA-256 digest**, and the digest already binds **which credential is in play**.
An invite is just another bearer credential presented in that header; a proof
over one credential cannot be replayed for another, exactly as before.

**What that buys:** there is **no fourth canonical message** and **no new
Go/Rust/JS mirror** to keep byte-identical. The canonical layout still exists in
exactly **three** implementations
(`sigild/internal/api/deviceauth.go`, `cli/src/lib.rs`,
`sigil-wasm/device-auth.mjs`), and **today's shipped clients can already join** —
`sigil device enroll --token <invite>` and the browser clients' existing
enrollment-token field work unchanged.

**Rejected alternative: a dedicated `sigil-account-join-v1` domain** (a fourth
canonical message, plus a new `X-Sigil-Invite` header). It would have read more
clearly at the call site and bought **zero additional security** — the digest
binding is already the discriminator — at the cost of a **fourth silent-drift
surface**. Drift between these implementations does not fail loudly; it 401s
every request, and only an interop test catches it. Adding one more copy for
legibility was not a trade worth making.

**The classification happens at the atomic write, not on the unauthenticated
path.** Step 5 of enrollment now resolves only *whether the presented digest is
one of the configured OPERATOR tokens*, **without an early return** and
**without looking up invites**: an advisory invite lookup there would be a
database round trip on the unauthenticated path and a timing side channel on
invite-hash existence. Steps 6 (proof of possession) and 7 (nonce) are
byte-identical to Phase 41. The branch happens at step 8, where a **single atomic
store operation** is the only authority.

- **An operator token always founds a NEW account.** There is no operator route
  that inserts a device into an existing account — that would be a real
  trust-model expansion smuggled in as convenience.
- **An invite always JOINS the inviter's account**, and never founds one.

**Invites are single-SUCCESS; operator tokens stay single-ATTEMPT.**
`JoinAccountWithInvite` consumes the invite, checks the inviter is still active,
enforces the member cap and inserts the device in **one** operation (a mutex in
memory; one transaction in Postgres), so N concurrent redemptions create exactly
one device and a failed insert leaves the invite usable. Operator tokens keep
Phase 41's deliberately fail-closed single-ATTEMPT semantics: an operator can
re-mint a token from a shell, but a customer mid-flow on a phone cannot, which is
precisely why the two classes differ.

**Invite properties.** 256 bits of `crypto/rand` behind a `join_` prefix; stored
**only** as a SHA-256 digest; returned exactly **once**, in the 201 that minted
it — never re-served, never logged, never a metric label. A separate **public
handle** (`inv_…`) exists for listing and revocation so no endpoint ever echoes
the redemption digest. A client may **shorten** an invite's TTL, never lengthen
it. `invitee_public_key` optionally **pins** the invite to one Ed25519 public key
so an intercepted invite is useless to anyone else — **nothing forces pinning**
(limitation 4).

### 4. Entitlement keys off the account

`POST /v1/billing/checkout` and `GET /v1/billing/subscription` now use
`subject = dev.AccountID`. The subject remains **server-derived** — it is still
never read from a body, query or path — so nobody can buy or query on another
subject's behalf. Pay on the phone, be entitled on the laptop; a cancel, refund
or chargeback demotes the **whole account at once** instead of one device.

A device with no account is refused **before** the provider or the store is
touched; there is **no fallback to `dev.ID`**, because that would silently
re-create the defect accounts exist to fix.

**Provider-echoed subjects are resolved, not trusted.** A hosted checkout started
*before* migration 0005 put a **device** id into the provider's metadata, and a
provider echoes that back forever. `resolveBillingSubject` maps the echoed value:
a known account passes through; an enrolled device becomes its account; anything
else is **blanked**, so the store falls back to its `(provider, subscription_ref)`
lookup and, failing that, answers `unresolved` (a 200 that changes nothing). A
provider-supplied string must never **invent** a subscription row. This is a
lookup on an already-signature-verified value, so it adds no trust — it can only
narrow what an event may touch.

### 5. Vault ownership keys off the account

A new `sigil_vault_owners` table (`vault_id` **PRIMARY KEY**, `account_id`) is
**the** authority on who owns a vault. Trust-on-first-write did not go away — it
**moved up one level**: the first *account* to authenticate a write to an
unclaimed vault owns it. The primary key makes the claim single-winner across
concurrent processes; a loser belonging to the **winning** account is allowed
through, because two siblings racing a legitimate first write must both succeed.

Every device of the owning account then has full access **without a per-device
grant row**. That is the orphaning fix: revoking the device that happened to
claim a vault no longer strands it, because its siblings inherit ownership from
the account.

Lookup is **owner-first and costs nothing**: a member of the owning account
resolves in one query (`GetVaultOwner`), replacing the one query (`GetGrant`) the
previous implementation made.

- **`needOwner` is satisfied ONLY by account ownership.** A legacy `is_owner`
  grant row never satisfies it, so data drift can never hand ownership powers to
  a non-owning account. One rule, checkable in one sentence.
- **The `is_owner` flag on `sigil_device_grants` is retained as the per-DEVICE
  VIEW of the same fact**, so `GET /v1/vaults/{id}/grants` stays byte-identical
  for existing data and existing clients. **No authorization decision reads it.**
  (`GET …/grants` gains an additive `owner_account_id`, because without it an
  account-owned vault would read as "nobody owns this".)
- **A cross-account share stays a per-DEVICE grant.** Key envelopes are addressed
  to a *device's* hybrid identity ([ADR 0035](0035-device-to-device-vault-sharing.md)),
  so an account-wide grant would authorize devices that hold no envelope —
  authorization and knowledge would drift apart.
- **Reads and `needWriteNoClaim` still never claim** (the Phase 51 fix, preserved
  verbatim): only `needWrite` may reach `ClaimVault`.
- **Sibling revocation.** A member may revoke another device of the **same**
  account (a third authorized path beside the admin token and self-revocation).
  On the non-admin path an **unknown** device and a **foreign** device both
  answer `403`, never `404`, so there is no existence oracle; only the admin
  path — which can already enumerate the registry — keeps its `404`.

### 6. Pre-0005 rows are ADOPTED, explicitly and never implicitly

`sigil_devices.account_id` is **deliberately nullable**. A `NOT NULL` column with
no default would make a rolled-back pre-0005 binary unable to enroll at all. The
invariant ("every device has an account") is enforced in the **application**, in
both backends.

Migration `0005_accounts.sql` therefore ends with a **backfill**, all inside the
migration's single transaction: every already-enrolled device (active **and**
revoked) gets its own singleton account named `acct_mig_<device_id>` — a pure
function of the device id, so there is no RNG in SQL and the statement is
re-runnable; vault ownership is backfilled from existing `is_owner` grants
(reading the grants table, writing nothing back to it); and subscriptions whose
subject names a device are re-keyed to that device's account, guarded by a
`NOT EXISTS` so no primary key can collide. `sigil_billing_processed_events.subject`
is deliberately **not** rewritten (limitation 16).

Three things follow, and all three are load-bearing:

- **A rolled-back binary keeps writing NULL-account rows.** 0005's schema is
  compatible with a pre-account binary by design, so an old instance running
  against an already-migrated database enrolls devices with `account_id NULL`
  and claims vaults by writing an `is_owner` grant and no owner row.
- **`sigild migrate` will never repair those.** 0005 is already recorded in
  `schema_migrations`, so it never runs again — which is correct for a migration
  and wrong for the data.
- **The repair is an explicit operator command: `sigild migrate adopt`.** It
  re-runs the same three statements over whatever state the database is in now,
  in **one transaction**, **idempotently**, and reports "nothing to adopt" when
  clean. **Adoption never happens implicitly on the authentication path** — an
  unauthenticated request must never be able to mint an account.

Because the refusal for those rows is the same coarse `403` as every other
refusal (§7), an operator has no way to *discover* them from traffic. So `sigild`
**warns at boot** when the database holds device rows with no account or vaults
whose only ownership record is a legacy owner grant, naming the counts and
saying explicitly that ``sigild migrate`` will not fix it and ``sigild migrate
adopt`` will. The warning never blocks a boot: a read failure, or a schema older
than 0005, is logged at debug and ignored.

### 7. Failure modes: a data state is a 403, never a 500

Two new typed reasons join the closed enum, both **coarse 403s**:

- **`missing_account`** — an authenticated device carries no account id. It is an
  invariant violation, but it is a **data state the server can read plainly**
  (a device enrolled by a pre-0005 binary during a rollback), not a fault. A 500
  would hide a reachable, repairable condition behind a code that means "the
  server broke". It still **fails closed** — the device is refused everywhere and
  the server never falls back to the device id.
- **`vault_owner_unresolved`** — the same NULL-account state seen from the vault
  side: the vault carries a legacy `is_owner` grant but no owner row, and the
  granted device cannot be resolved to an account.

**The orphaned-owner state is RECONCILED, not faulted.** `ClaimVault` adopts the
grant holder's account and reports `claimed=false`, writing **only the owner
row** — not one grant row is created or re-permissioned — so a legitimately
write-granted device gets its `201` instead of the opaque 500 it used to get.
Only when the grant holder cannot be resolved at all is it the coarse 403 above.

Two further reasons exist for the audit log alone: **`forbidden_account`** (the
vault belongs to another account and the caller holds no per-device grant —
client-visibly identical to `unauthorized_vault`; the split lets the audit log
distinguish "someone else's vault" from "nobody's vault yet") and
**`account_full`**, which is the one new *response* code: a `409` on enrollment,
reachable **only after** a credential and a valid proof of possession have been
accepted — exactly like `device_exists` — so a distinct status leaks nothing the
caller did not already hold.

**Every account-invite failure collapses onto an EXISTING coarse reason.**
Unknown / revoked / inviter-revoked → `bad_enrollment_token`; used →
`enrollment_token_used`; expired → `enrollment_token_expired`; pinned-key
mismatch → `bad_proof`. The fine-grained cause (`invite_unknown`,
`invite_revoked`, `inviter_inactive`, `invite_used`, `invite_expired`,
`invite_key_mismatch`, …) goes to the **audit log only** — never a response body
and never a `/metrics` label, because that endpoint is always-on and
unauthenticated and a per-cause counter there would be a correlatable oracle
(limitation 11).

**A foreign invite handle and a missing one are indistinguishable** (both `404
invite_not_found`), because revocation is scoped by `(account_id, invite_id)` in
the store.

### 8. Seats count ACTIVE devices only

`SIGILD_ACCOUNT_MAX_DEVICES` bounds **concurrent** devices, so **a revoked device
frees its seat**. This is enforced in all four sites that count members (the
in-memory redemption path, the Postgres redemption path, the invite-mint
pre-check, and `GET /v1/account`), from one definition per backend, so the cap
enforced at redemption and the number reported to a client can never disagree.

Counting revoked rows would turn the cap into a **lifetime enrollment limit** that
no operation anywhere could reverse — and every remedy this model prescribes
("revoke and re-enroll" for a compromised device, a wrong-account join, or a lost
phone) would burn a seat permanently until the account could never enroll again.
It was also reachable as an attack.

⚠️ **`device_count` therefore CHANGED MEANING.** It is now **active devices only**;
a new **`revoked_device_count`** reports the rest. The `devices[]` array still
lists **both**, so history stays visible without consuming the limit.

### 9. Configuration, storage, and the surface

**No `SIGILD_ACCOUNTS` switch exists, deliberately.** Accounts ride
`SIGILD_DEVICE_AUTH` (which already requires the dev-ops gate), because a binary
that could run either ownership model would have **two ownership truths at once**.
Setting any account variable *without* device auth is a **boot error**, not a
silently ignored knob.

| Variable | Default | Range | Meaning |
|----------|---------|-------|---------|
| `SIGILD_ACCOUNT_MAX_DEVICES` | `10` | `[1, 1000]` | member devices per account (**active** only) |
| `SIGILD_ACCOUNT_MAX_INVITES` | `5` | `[1, 100]` | **open** (unused, unexpired, unrevoked) invites per account |
| `SIGILD_ACCOUNT_INVITE_TTL` | `15m` | `(0, 24h]` | how long a freshly minted invite stays redeemable |

All three are validated **fail-fast before the listener binds**; an out-of-range
value is an **error, never a silent clamp** (an operator who typed `10000` meant
something, and quietly serving `1000` hides it).

**Four routes**, all dev-gated behind `SIGILD_ENABLE_DEV_OPS` + a configured
registry, returning a deliberate `501` — never a `404` — when off:
`GET /v1/account`, `POST /v1/account/invites`, `GET /v1/account/invites`,
`POST /v1/account/invites/{inviteID}/revoke`. All four reuse
`authenticateDevice` verbatim: **no new auth path, no new header, no new signed
message.**

**Migration `0005_accounts.sql`** (0001–0004 untouched) adds `sigil_accounts`,
`sigil_devices.account_id`, `sigil_account_invites`, `sigil_vault_owners` and the
backfill ⇒ **`sigild_schema_version` now reports 5**. It is pure DDL plus a
metadata backfill over auth metadata; it names `sigil_vault_ops` nowhere, so the
opaque blob and its tamper-evidence hash chain are byte-for-byte unchanged and
`GET …/ops/verify` returns the same `tip_hash` before and after.

**Metrics** (counts only, no id label ever):
`sigild_accounts_created_total`, `sigild_account_invites_created_total`,
`sigild_account_invites_revoked_total`, `sigild_account_joins_total`, plus
`account_full` on `sigild_device_enroll_denied_total{reason}` and
`missing_account` / `forbidden_account` / `vault_owner_unresolved` on
`sigild_oplog_auth_denied_total{reason}`.

**Audit events:** `account.created`, `account.device_joined` (which names the
**inviter** — what makes a planted device *visible* after the fact; flat
membership means it is not *prevented*), `account.invite_created`,
`account.invite_revoked`. They carry account ids, device ids, the **public**
invite handle, an expiry and a fixed reason enum — and **never** an invite
secret, an invite digest, an enrollment token, a key, a signature, a nonce or one
byte of a blob.

**Client surface.** The `sigil` CLI gains
`sigil account status | invite [--ttl N] [--pin-key <b64>] | invites |
revoke-invite <inviteID>`. There is **no join subcommand** — joining is the
ordinary `sigil device enroll --token <invite>`, which is the point of §3.

## The sentence an auditor should be able to check

> An account is **auth metadata only**; the server still **never sees a vault
> key, a password or a plaintext**; **no request anywhere names an account**;
> entitlement and vault ownership derive **solely** from the account on the
> **verified signer's device row**; and **membership grants ciphertext access,
> never plaintext**.

## Consequences

### Good

- **The paid product works across a customer's devices.** Buying on one device
  entitles the account; a sibling device that never ran checkout sees the same
  entitlement, and a cancellation demotes the account once rather than
  device-by-device.
- **Revoking a device no longer orphans its vaults.** A sibling that was granted
  nothing still reads, writes, grants on and rotates the key of a vault its
  revoked sibling claimed. This is the defect ADR 0031 recorded as limitation 4,
  now closed at the level it was broken at.
- **Cross-account IDOR is closed structurally, not defensively.** There is no
  request shape that names an account, so there is nothing to filter.
- **No new wire format and no fourth canonical message.** Shipped clients can
  join an account today, and the byte-identical-mirror burden did not grow.
- **No new dependency.** `sigild/go.mod` still has exactly one direct require
  (`pgx`); the account store shares the op-log's existing `pgxpool`.
- **Zero-knowledge is unchanged**, and provably so: `sigil_vault_ops` is
  untouched, the hash chain re-verifies to the same tip, and no handler here
  reads a blob.

### Bad / honest limitations (all real; none papered over)

1. ⚠️ **THIS IS NOT AN IDENTITY SYSTEM, AND THERE IS NO RECOVERY.** No email, no
   password, no recovery code, no operator break-glass. An account is reachable
   only through a member device's private key. **Lose or revoke every device and
   the account is permanently unreachable, its vaults permanently unreadable by
   the customer AND by us, and its subscription stranded.** The orphan failure
   **narrowed** — from "revoke one device" to "lose every device" — it was **not
   eliminated**. The guidance is "keep two devices enrolled", which is a
   **mitigation, not a fix**. *This must be written down before anyone charges
   real money.*
2. **Membership confers AUTHORIZATION, never DECRYPTION.** A joined device can
   authenticate and see its entitlement but reads **nothing** until an existing
   member wraps the vault key to its hybrid public key
   ([ADR 0035](0035-device-to-device-vault-sharing.md) /
   [0038](0038-key-pinning-safety-numbers-and-vault-rotation.md)). The corollary
   is the reassuring half: **a hostile server can insert a device into any
   account** — it owns the registry — **and still cannot decrypt anything.** The
   only defence against the follow-on key-substitution attack is **client-side
   pinning + safety numbers**, which cannot protect first contact.
3. **Membership is FLAT.** Any member may invite, revoke every other member, run
   checkout, and administer every account-owned vault. **Revoking a compromised
   device does NOT revoke the devices it invited.** The audit log names the
   inviter, so it is **visible**, not **prevented**. There is no quorum, no
   admin/member split, and no re-authentication for sensitive actions.
4. **An unpinned invite is a BEARER SECRET**, and the dev transport is **plain
   HTTP with no TLS**. Pinned invites (`--pin-key`) close this, but **nothing
   forces pinning**.
5. **Trust-on-first-write did not go away — it moved up one level.** The first
   *account* to write an unclaimed vault owns it. An attacker who reaches an
   unclaimed, high-entropy vault id first still wins it and still locks the
   legitimate owner out with a `403`.
6. **Ownership never moves between accounts, and membership is immutable.** No
   transfer, no merge, no split, no account deletion. A device enrolled into the
   wrong account can only be revoked and re-enrolled.
7. **NO ACCOUNT MERGE.** Every device enrolled before 0005 is adopted into its
   **own singleton account**, so an existing two-device customer ends up with
   **TWO accounts and TWO billing subjects**. The remedy is manual (revoke one,
   re-join by invite, re-share, rotate) and **leaves a second subscription row
   for an operator to reconcile**.
8. **Entitlement is REPORTED, never ENFORCED.** No route refuses service to an
   unentitled account. Gating the op-log on payment status would lock a customer
   out of their own 2FA codes over a failed card and needs grace periods and
   dunning that do not exist. What changed is only that a cancel/refund now
   demotes the **whole account at once**.
9. **`SIGILD_ACCOUNT_MAX_DEVICES` is anti-freeloading, not anti-fraud.** Ten
   devices in one account is indistinguishable from household sharing versus a
   small business, and there is no per-seat model.
10. **The billing trust assumption's blast radius grew with the subject.** A
    compromised provider webhook secret now moves an **account's** status rather
    than one device's.
11. **`/metrics` is always-on and unauthenticated, and its per-reason counters
    are a weak correlatable oracle** (pre-existing). This phase deliberately does
    **not** widen it: every invite failure collapses onto an existing coarse
    label and all fidelity goes to the audit log.
12. **No rate limiting** on `POST /v1/devices/enroll` or
    `POST /v1/account/invites`. The caps bound stored **state**, not request
    volume. There is also **no sweep job for expired invites** — they stop being
    listed and stop being redeemable, but the rows remain.
13. **The replay nonce cache is still per-process and in-memory.** Invite
    consumption is DB-atomic and therefore multi-instance safe; **signed requests
    are not**.
14. **The in-memory registry is still non-durable** — accounts, memberships,
    invites and vault-owner rows are all lost on restart (warned at boot) — and
    the **file op-log backend was still not extended**: device auth plus
    `SIGILD_OPLOG_DIR` still falls back to the in-memory registry.
15. ⚠️ **ROLLBACK IS SURVIVABLE BUT NOT FREE.** A pre-Phase-52 binary run after
    0005 is applied **enrolls devices with `account_id NULL`**, and on rolling
    forward those devices were (before the fix round) refused on every route with
    **no repair path**. That is now handled — a coarse `403` rather than a `500`,
    plus `sigild migrate adopt`, plus the boot warning — so the accurate story
    is: **any device enrolled during a rollback window needs `sigild migrate
    adopt` after rolling forward, and the boot warning is how an operator knows.**
16. **`sigil_billing_processed_events.subject` deliberately retains pre-0005
    DEVICE ids.** It is an append-only record of what was processed at the time,
    read by no logic; rewriting history to look like something that was not true
    then is worse than a stale column nothing reads. **Cross-cutover
    reconciliation needs BOTH ids.**
17. **Billing has still never been run against a live provider account**, the
    **Juspay** adapter remains **UNVERIFIED-AGAINST-LIVE-DASHBOARD**, and there
    is no invoicing, proration, tax, refund, dunning or PCI attestation.
18. **Client coverage is PARTIAL BY DESIGN.** The **`sigil` CLI** and the
    **native desktop app** got the full flow (show the account, mint, list and
    revoke invites). The **webapp** and the **MV3 extension** can already **JOIN**
    — an invite pastes into their existing enrollment-token field, since the wire
    is unchanged — and can **read** the account and show the honest "joined —
    waiting for a key from another device" state, but **have no UI to MINT, list
    or revoke an invite**. Do not read this as done.
19. **Everything stays dev-gated** behind `SIGILD_ENABLE_DEV_OPS` +
    `SIGILD_DEVICE_AUTH`, **`501` by default, plain HTTP, pre-audit, UNAUDITED.**
    This is a **real authorization model, not a reviewed one**.

### Neutral

- The `Accounts` interface is **embedded into `DeviceStore`** exactly as
  `KeySharing` already is: same auth-metadata store, same backends, one
  backend-agnostic conformance suite.
- `deviceJSON` gained an **additive** `account_id` (omitted when empty), and
  `GET …/grants` an additive `owner_account_id`. Existing clients ignore unknown
  fields, and a row written by a rolled-back binary renders the shape it always
  did.
- A pre-existing Postgres **collation** flake was fixed while here: `ORDER BY
  device_id` sorts locale-wise under `en_US.utf8` and byte-wise in Go, so every
  text `ORDER BY` in the store package now carries **`COLLATE "C"`**. It made the
  only gate exercising 0005 red in roughly 4 of 12 runs.

## Alternatives rejected

- **A dedicated `sigil-account-join-v1` challenge domain and an
  `X-Sigil-Invite` header** — clearer at the call site, zero additional security
  (the enrollment challenge already binds the credential's digest), and a fourth
  byte-identical mirror to maintain across Go, Rust and JS. See §3.
- **A `SIGILD_ACCOUNTS` on/off switch** — a binary able to run either ownership
  model would hold two ownership truths at once. Accounts ride
  `SIGILD_DEVICE_AUTH`; setting an account variable without it is a boot error.
- **A real identity system** (email, password, recovery codes, operator
  break-glass) — a much larger design that this pre-audit skeleton must not fake,
  and one that would put PII and a recovery oracle into a server whose entire
  premise is that it holds neither. The cost is limitation 1, stated loudly
  rather than hidden.
- **Automatic adoption on the authentication path** — it would repair NULL-account
  rows without operator action, and it would let an **unauthenticated request
  mint an account**. Adoption is an explicit operator command instead.
- **Account-wide grants for cross-account shares** — key envelopes are addressed
  to a *device's* hybrid identity, so an account-wide grant would authorize
  devices holding no envelope; authorization and knowledge would drift apart.
- **A `NOT NULL` `account_id`** — it would make a rolled-back binary unable to
  enroll at all. The invariant is enforced in the application instead, failing
  closed at a coarse 403.
- **Counting revoked devices against the seat cap** — turns the cap into an
  irreversible lifetime limit that bricks the account under exactly the remedy
  this model prescribes. See §8.
- **Rewriting `sigil_billing_processed_events.subject`** — falsifying an
  append-only processing record to look retroactively consistent. See
  limitation 16.
- **A fine-grained invite-failure metric label** — `/metrics` is unauthenticated;
  the fidelity lives in the audit log instead. See limitation 11.

## References

- Code: [`../../sigild/internal/api/accounts.go`](../../sigild/internal/api/accounts.go),
  [`deviceauth.go`](../../sigild/internal/api/deviceauth.go),
  [`devices.go`](../../sigild/internal/api/devices.go),
  [`billing.go`](../../sigild/internal/api/billing.go),
  [`router.go`](../../sigild/internal/api/router.go),
  [`../../sigild/internal/store/accounts.go`](../../sigild/internal/store/accounts.go),
  [`postgresaccounts.go`](../../sigild/internal/store/postgresaccounts.go),
  [`adopt.go`](../../sigild/internal/store/adopt.go),
  [`migrations/0005_accounts.sql`](../../sigild/internal/store/migrations/0005_accounts.sql),
  [`../../sigild/cmd/server/main.go`](../../sigild/cmd/server/main.go),
  [`../../cli/src/main.rs`](../../cli/src/main.rs),
  [`../../cli/src/lib.rs`](../../cli/src/lib.rs),
  [`../../sigil-wasm/device-auth.mjs`](../../sigil-wasm/device-auth.mjs),
  [`../../desktop/core/src/net.rs`](../../desktop/core/src/net.rs).
- Proofs: [`../../cli/tests/e2e-accounts.sh`](../../cli/tests/e2e-accounts.sh)
  (real sigild + real CLI, four devices, four HOMEs),
  [`../../sigil-wasm/test/accounts-interop.mjs`](../../sigil-wasm/test/accounts-interop.mjs)
  (a JS client and the real Rust binary landing in **one** account).
- Contract: [`../api.md`](../api.md) — the authoritative HTTP surface.
- Adversaries/defenses: [`../threat-model.md`](../threat-model.md).
- Operator runbook: [`../deployment.md`](../deployment.md) §11 (migration 0005 and
  `sigild migrate adopt`) and §14.
- Prior art in this repo: [ADR 0031](0031-multi-device-auth-model.md) (the device
  registry and contract v3 this reuses),
  [ADR 0034](0034-billing-provider-seam.md) (the billing subject this moves),
  [ADR 0035](0035-device-to-device-vault-sharing.md) (the key relay that does the
  decryption half membership does not).

## Three limitations revised by Phases 53–55 (added Phase 55, 2026-07-28)

Per this repo's addendum rule the text above is left untouched; this section
records only what changed and which ADR changed it.

- **Limitation 1 ("THIS IS NOT AN IDENTITY SYSTEM, AND THERE IS NO RECOVERY …
  *this must be written down before anyone charges real money*") — the DATA half
  is addressed; the IDENTITY half is NOT.**
  [ADR 0042](0042-recovery-kit.md) adds a **recovery kit**: an **ordinary member
  device** whose Ed25519 and hybrid private keys are HKDF-SHA256 derivations of
  32 bytes of client CSPRNG **printed on paper** — never transmitted, never
  stored on a device, never derivable from anything the server holds. `sigild`
  gained **no concept of recovery**: no table, no migration
  (`sigild_schema_version` stays **5**), one metadata-only self-only route
  (`GET /v1/devices/{deviceID}/keys`).
  ⚠️ **What is still true as written:** there is still **no email, no password,
  no operator break-glass and no identity system**, and a customer who never
  printed a kit is in exactly the position limitation 1 describes — **a kit
  cannot be created after the loss**. It recovers **keys, not data** (a vault
  never synced is gone) and only the vaults it was told to **cover**.
  ⚠️ **And a new risk exists that did not before:** whoever holds the paper has
  **full control of the account** — read every covered vault, revoke every device
  — with no OS lock and no vault password in front of it. The kit's nominal
  `read` grant is cosmetic, because §5 above authorizes it through **account
  ownership**.
- **Limitation 8 ("Entitlement is REPORTED, never ENFORCED") — retired, behind an
  opt-in switch, and deliberately asymmetric.**
  [ADR 0043](0043-entitlement-enforcement.md) adds `SIGILD_ENTITLEMENT_ENFORCE`
  (**off by default**, byte-identical behaviour when unset) with
  `SIGILD_ENTITLEMENT_GRACE` (default **14 days**): past grace, an account whose
  subscription lapsed has **writes** refused with **`402 Payment Required`** and
  a machine-readable body — never collapsed into the coarse `401`/`403` envelopes,
  and reachable only *after* authentication and authorization have both
  succeeded, so it is no oracle. ⭐ **READS AND SAME-ACCOUNT KEY RECOVERY ARE
  NEVER REFUSED** — a lapsed customer can still read every code they already
  have, collect their envelopes, give the vault key to a **replacement device of
  their own account**, print a **recovery kit**, revoke a stolen device, and pay.
  `past_due` remains **entitled**. The concern this limitation recorded — *"gating
  the op-log on payment status would lock a customer out of their own 2FA codes
  over a failed card"* — is therefore honoured, not overturned.
- **Limitation 12's first clause ("No rate limiting on `POST
  /v1/devices/enroll` or `POST /v1/account/invites`") — addressed, with two
  properties that must be read alongside it.**
  [ADR 0041](0041-abuse-bounds-and-the-removed-webhook-limiter.md) adds opt-in
  stdlib token buckets (`SIGILD_ENROLL_RATE_LIMIT`/`_BURST` keyed on the socket
  peer address, `SIGILD_INVITE_RATE_LIMIT`/`_BURST` keyed per account; `429` +
  `Retry-After`; still exactly one direct Go dependency).
  ⚠️ **It is a BACKSTOP, not a defence:** behind the only topology this repo
  documents — a reverse proxy — every request arrives from one address and the
  enrollment limiter degrades to a single global bucket. It charges the bucket
  **only on the denial path**, so a request carrying a valid, unspent credential
  and a valid proof can **never** be refused by it, and it **fails open** at its
  key cap. ⚠️ **It also does not reduce load:** the handler always runs,
  including its database work; the limiter replaces only the response.
  **The second clause of limitation 12 is unchanged — there is still no sweep job
  for expired invites.**

## Limitation 18 (partial client coverage) is narrowed, not closed (added Phase 56, 2026-07-28)

Per this repo's addendum rule the text above is left untouched.

**What changed.** Phase 56 built the recovery-kit lifecycle and an entitlement
warning surface on the **webapp**, the **MV3 extension** and the **desktop**
([ADR 0042](0042-recovery-kit.md) addendum, [ADR 0043](0043-entitlement-enforcement.md)
addendum). Two consequences for this ADR:

- **Limitation 1's addendum reads differently now.** When it was written, the
  recovery kit existed only in the `sigil` CLI, and `restore` runs on a **new
  install** — precisely the situation a customer who lost every device is in — so
  **a customer whose only client was a browser could not recover, and their
  printed sheet was useless to them.** All four client surfaces can now generate,
  cover, check, revoke **and restore**. Everything else in that addendum is
  unchanged: there is still no email, no password, no operator break-glass, a kit
  still cannot be created after the loss, and whoever holds the paper holds the
  account.
- **Limitation 18 is narrowed.** The webapp and the extension are no longer
  "wrap-gate consumers only". ⚠️ **But its central claim still stands: they still
  have NO UI to MINT, LIST or REVOKE an ordinary invite.** (Browser `recovery
  generate` mints one internally, pinned to the kit's own public key, as a step in
  printing a sheet — that is not an invite-management UI.) Account **minting**
  remains a CLI and desktop capability. Do not read limitation 18 as done.

Every other limitation in this ADR stands as written.
