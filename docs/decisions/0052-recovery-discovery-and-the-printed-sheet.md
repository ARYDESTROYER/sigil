# 0052 — Recovery discovery, the printed sheet, and the stranger's vault

- **Status:** Accepted (2026-08)
- **Date:** 2026-08-07
- **Builds on:** [0042](0042-recovery-kit.md) (the recovery kit itself — this
  decision is about the one route it invented, `GET /v1/devices/{deviceID}/keys`),
  [0040](0040-account-model.md) (**limitation 1**: lose every device and the
  account is permanently unreachable — which is why a kit that half-works is not
  a small problem), [0035](0035-device-to-device-vault-sharing.md) (the key
  relay), [0038](0038-key-pinning-safety-numbers-and-vault-rotation.md) (pinning,
  safety numbers, and the rule that **the choke point is the FETCH**),
  [0048](0048-authenticated-vault-key-envelopes.md) (⭐ **the premise this
  decision turns on**: `mode_auth` proves **who** deposited an envelope and says
  **nothing** about whether they are trusted),
  [0041](0041-abuse-bounds-and-the-removed-webhook-limiter.md) (a protective
  bound that breaks the legitimate path is worse than no bound — read before
  proposing anything server-side here),
  [0047](0047-container-parameter-ceiling-and-no-downgrade-ratchet.md) (a
  zero-knowledge relay cannot filter what it relays, so validation is the
  client's duty).
- **Revises (does not supersede):** the *"a kit covering more than 500 vaults
  silently recovers the first 500 and reports success"* limitation of
  [0042](0042-recovery-kit.md), and the assertion in
  [`../api.md`](../api.md) that closing it required a **cursor**. It did not.

## Context

Three things were established against a **real `sigild`**, with two real accounts
and contract-v3 signatures throughout, before any code was written.

### 1. ⛔ The Rust CLI silently restored a partial vault set and reported success

`list_recoverable_vaults`'s wire deserializer had **only** a `vaults` field.
`recovery_restore` never looked at `has_more`. So when the per-device envelope
index was truncated, the CLI restored the visible prefix and returned a
success-shaped report.

That is the worst possible failure for the one mechanism whose entire job is
answering *"did I get everything back?"*, and it lands on the one person who — by
construction, having lost every device — has nothing left to check it against.
The JS half has refused on that flag since Phase 58. Rust did not.

### 2. ⛔ A third party can crowd the listing

`GET /v1/devices/{deviceID}/keys` is **one page, capped at 500 rows, with no
cursor**. Any account may deposit an opaque envelope addressed to a device id it
knows and then grant that device `read` on a vault it claimed itself —
trust-on-first-write caps nothing. Measured:

```
BEFORE:  count: 1    truncated: false   real vault visible: true
attacker floods 520 vaults ......... done in 0.6s   <- junk bytes
AFTER:   count: 500  truncated: true    real vault PUSHED OUT
```

⚠️ **That 0.6 s is the JUNK-BYTES variant.** The shipped test
(`cli/tests/recovery_index_flood.rs`) plants **genuine authenticated** envelopes
instead — see §3 — and prints **~3 s** for the same 520. Crowding the listing only
ever needed the cheap variant; the expensive one exists to prove what a restore
does with a row it can actually *open*. Both are trivially affordable, and any
figure quoted elsewhere in the docs carries the same qualifier.

⚠️ **The obvious mechanism does not work, and this matters for anyone reproducing
it.** A bare deposit is *not* counted: `deviceKeyEnvelopeIndex` filters every row
through `authorizeVault(needRead)`, so deposit-only measures `count: 3,
truncated: false`. The attacker must **also grant read**.

⚠️ **Reachability.** The kit's device id is 128 bits of CSPRNG and unguessable —
but it is **not secret**. `GET /v1/vaults/{id}/grants` discloses it with `read`
alone, so any current **or former** collaborator on a covered vault keeps it
permanently, and revocation cannot un-learn it.

### 3. ⛔⛔ The sharpest one, and it was found only by attacking our own fix

The first flood deposited **junk bytes**, which the AEAD could only ever refuse.
Replacing it with **genuine, correctly authenticated** envelopes changed the
answer completely.

Every input to a vault-key wrap is **public**: `sigild` serves any device's
published hybrid key to any authenticated device (`deviceHybridKeyFetch` says so
in its own comment), and the AAD is `(purpose, vault id, recipient id, sender
id)`. So a stranger can mint an envelope that authenticates **perfectly**. A
restore runs on a machine with an **empty pin store**, so
`verify_sender_for_unwrap(…, expected_safety_number: None)` returned
`UnverifiedFirstSight`, **pinned the stranger's key**, unwrapped, opened their
container, and reported it as a **recovered vault**.

Mutating the fix off produced this, which is the single most useful line in the
phase:

```
left:  ["zz-real-vault", "aaa-spam-00000", "aaa-spam-00001",
        "aaa-spam-00002", "aaa-spam-00003", "aaa-spam-00004"]
right: ["zz-real-vault"]
```

Five vaults belonging to a stranger, handed back as the user's own.

## Decision

### 1. A truncated index is a REFUSAL, never a partial

With no vault ids supplied and `has_more: true`, a restore **refuses**, writes
nothing, and names the way out. Rust now does what JS has done since Phase 58.

### 2. ⭐ The printed sheet is the discovery channel nothing can touch

`render_recovery_sheet` **already printed the covered vault ids** on its `covers`
line. Passing them (`sigil recovery restore --vault <id> …`, `vaultIds` in JS,
`vault_ids` on the Tauri command) makes the restore ask **each vault directly** —
`GET /v1/vaults/{id}/keys` and `GET /v1/vaults/{id}/keys/{deviceID}`, both
addressed **by vault id**, where there is nothing to crowd out.

⭐ **This is the instinct this project keeps returning to: use what the system
already has.** [0048](0048-authenticated-vault-key-envelopes.md) authenticated
with the already-published hybrid key rather than adding a signature route;
[0049](0049-entry-identity-and-the-mergeable-vault.md) folded ops the op-log was
already storing. Here the answer was already on paper, in the user's hand, and
**an attacker cannot reach a sheet printed before they acted**.

It is also **retroactive**: every sheet printed since Phase 54 carries the
`covers` line, so no already-printed kit is left behind.

### 3. ⭐ The index may only INTRODUCE a vault from your own account

The rule, in one sentence:

> A vault **named on the sheet** is vouched for **by the user**. A vault the
> **index alone** introduced is processed only if its `sender_device_id` is a
> device in the kit's **own account**.

The account device list comes from the `get_account` call `recovery_restore`
**already made**. `AccountInfo.devices` lists **active and revoked** members,
which is load-bearing: the device that covered a vault may since have been
revoked, and that must not break its own recovery.

The verdict is reached **from the index row alone, before any network call for
that row**, so a flood costs nothing: no fetch, no unwrap, and above all **no pin
of the stranger's key**. The ignored rows are reported as **one count**, never one
line each — rendering a flood row by row buries the real result, which is exactly
what the flood is for.

### 4. The sheet path is not gated behind the route it exists to bypass

`list_recoverable_vaults` was called **unconditionally**, with `?`. A server that
made that one route fail killed the sheet path too — so the phrase *"the
discovery path that cannot be denied"*, written three times in the new code, was
**falsifiable as shipped**. When vault ids were supplied, an index failure now
**degrades** (empty, `truncated: true`, the failure recorded in `index_error` and
rendered); with no ids it still propagates, because there is nothing to fall back
on.

### 5. A per-vault failure is a per-vault failure

`pull_ops_auth`, the keyring writes and the file writes propagated with `?`.
Since sheet vaults are processed **first**, a single hostile row could return
`Err` **after** the user's real vaults were already on disk — telling them the
recovery failed while their vaults sat in `~/.sigil`, with the report never
printed. These now record into `skipped`.

⚠️ One subtlety was resolved rather than papered over: a failed **keyring** write
on the success path must not simply be non-fatal, or a vault lands in the report
while its key was never persisted — a container on disk that cannot be opened,
reported as recovered. The helper returns whether the key is actually on disk and
the vault is not counted when it is not.

### 6. The generate-time warning reaches all four clients

`index_truncated` is reported at **kit generation**, which is the one moment the
user can still act — re-print, reduce coverage, copy the `covers` line carefully.
By restore time the paper is fixed. It was reaching **one client of four**, on a
path whose pre-print sanity check had simultaneously been relaxed. CLAUDE.md's
own Phase 62 rule applies: **a false-by-omission rendering is a class, not an
instance.**

### 7. ⛔ The browsers were revoking a working kit, and that is now fixed

The Rust pre-print check was relaxed to tolerate a truncated index. **The JS twin
was not**, and its throw is caught by a handler that calls `revokeSelf`. So a
stranger crowding the listing could stop the webapp and the MV3 extension **ever
printing a recovery kit** — a denial of the last line of defence under
[0040](0040-account-model.md) limitation 1, **strictly worse** than the truncation
this phase set out to fix.

⚠️ The attack is not "flood before generate" — a kit's device id does not exist
until it is enrolled. It is a **race**: `GET /v1/vaults/{id}/grants` discloses the
new kit id the instant it is granted read, and the remaining steps are many round
trips wide. The regression test wins that race against a real server.

### 8. ⭐ `sigild`'s BEHAVIOUR is unchanged — and here is the argument, not the assertion

`sigild` gains no route, header, canonical message, migration, table, metric or
dependency; `sigild_schema_version` stays **5**; it still has exactly **one**
direct Go dependency. The **only** change to `sigild` in this phase is a
**comment** (see §9). Every option was weighed:

- **A cursor** does not help. The flooder simply bloats what must be paged
  through, and it converts one bounded request into an unbounded loop on a client
  that by construction has no local state and no way to know when to stop.
- **Capping the scan** is *worse than the disease*. An unauthorized row is
  `continue`d **without consuming the row budget**, so a cap would let an attacker
  who deposits and grants **nothing** push genuine rows past it — turning a
  slow-but-**correct** listing into an **empty** one. That is
  [0041](0041-abuse-bounds-and-the-removed-webhook-limiter.md) exactly: a
  protective bound that breaks the legitimate path.
- **Ordering the caller's own account first** only half-closes it — a
  cross-account-covered vault stays crowdable — and with no version marker no
  client could ever *rely* on it, so it would be defence-in-depth that nothing can
  key off.
- **A per-recipient cap on addressing accounts** is the removed webhook limiter in
  a new costume: the attacker fills it and the next genuine collaborator's key
  deposit is refused, against a user who may be mid-recovery.

The duty therefore sits where the information to settle it exists — the client,
holding the paper.

### 9. The `sigild` comment that was false

`maxRecipientIndexRows` justified having no cursor with *"the realistic count is
single digits and a cursor would be dead code"*. **The count is not the user's; it
is an attacker's.** That comment is now replaced with the measurement, the
reasoning above, and the residual in §"Honest limits". It is a **comment-only**
change — `git diff --stat sigild/` is non-empty and this ADR says so rather than
reaching for *"`sigild` gained nothing"*.

## Consequences

**Positive.**

- The one flow that exists because everything else is already lost can no longer
  report a partial as complete, on any client.
- A flood no longer denies recovery: the sheet's ids reach the envelopes directly.
- A stranger can no longer have their vault presented to a victim as the victim's
  own, and their key is no longer pinned into the victim's fresh trust store.
- A dead index route, and a single hostile row, are both survivable.
- The fix is retroactive to every sheet printed since Phase 54.

**Negative / accepted.**

- `sigil recovery restore` grew a flag, and a user restoring blind under a live
  flood must now type vault ids they previously did not need. That is the correct
  trade against a silent partial, but it is more work in a crisis.
- A **legitimate** kit covering more than 500 vaults now refuses a blind restore
  where it previously produced a partial. It has a working path (the sheet); the
  refusal is deliberate.
- A genuine **cross-account** share to a kit, discovered only through the index,
  is now ignored rather than unwrapped. It is reported with the remedy
  (`sigil vault accept` from a working device), and it was never part of the kit
  coverage model in [0042](0042-recovery-kit.md).

## ⛔ Honest limits — as loud as the feature

1. **Coverage drifts, and the sheet is a snapshot.** The `covers` line is what the
   kit could open **on the print date**. A vault covered afterwards is on no
   sheet, and the index is its only discovery path — so under a live flood it
   stays invisible. The sheet says so, `recovery cover` prints the current restore
   command, and `recovery check` prints it too. **Nothing anywhere may imply the
   sheet is a complete list.**
2. **§3 defends against a THIRD PARTY, not against the SERVER.** The account
   device list is served by the same server, so a hostile one could omit a genuine
   sender and cause a legitimate index-only row to be ignored. That outcome is
   *reported*, not silent, and a server wanting to deny recovery can already
   withhold the envelope outright — so it is handed no capability it did not have.
3. **The unbounded scan is real, pre-existing, and NOT fixed.** An unauthorized
   row costs a store round trip, neither consumes the row budget nor ends the
   loop, and `ListKeyEnvelopesForRecipient` has **no `LIMIT`**. A stranger who
   deposits and grants nothing makes the handler scan without bound. It is a
   **latency** denial — the listing it returns stays correct and complete — and
   bounding it correctly means pushing the authorization filter **into the query**,
   not capping the scan. Recorded here and in the threat model.
4. **Vault-id squatting is the root and is untouched.** Every variant of this
   attack costs the attacker one claimed vault, and there is **no per-account claim
   budget** ([0045](0045-claim-precondition-rejected-writes-never-claim.md) records
   the same gap).
5. **The kit's device id leaks from `GET /v1/vaults/{id}/grants` with `read`
   alone.** Narrowing that to `needWriteNoClaim` would match `keyEnvelopeList` and
   cut the disclosure population, but it is a documented API contract change and it
   only narrows rather than closes. Deliberately **not** done here.
6. **Generate-time `index_truncated == true` is proven in JS only, and the gap is
   wider than "the library field".** The Rust and desktop side assert only the
   false case, because making it true requires winning the enrol→pre-print race and
   `recovery_generate` offers no interception point in Rust the way
   `globalThis.fetch` does in JS. A verifier confirmed that hardcoding **both**
   `index_truncated` sites in `cli/src/lib.rs` to `false` leaves the entire CLI and
   desktop suites green. ⚠️ **And the RENDERED warning is asserted by nothing at
   all** — `cli/src/main.rs`'s print statement has no test, and **nothing anywhere
   renders `desktop/ui/`**, so the desktop's truncation paragraph and its whole
   restore-report block are covered only by review. The JS half *is* genuinely
   proven (hardcoding its three sites goes red).
7. ⚠️ **A TYPED VAULT ID IS EXEMPT FROM THE SENDER CHECK, BY DESIGN — so §3 does not
   make a restore immune, it makes the INDEX untrusted.** A vault id the user
   supplies is processed whatever its sender says, because the sheet *is* the user
   vouching for it. A stranger who granted the kit `read` on a vault whose id the
   user then types will therefore still be reached through first-sight TOFU: their
   key is pinned and their envelope unwrapped. That is the correct trade — the
   alternative refuses a genuine cross-account share the user is deliberately
   naming — but it means the honest claim is *"the index cannot introduce a
   stranger's vault"*, **not** *"a stranger's vault can never be restored"*.
8. **§9 is a comment, and a comment is not a control.**
9. ⚠️ **`indexError`'s RENDERING in the two browsers is pinned by nothing** — it is
   deletable with every browser test green. The library behaviour *is* pinned
   (`recovery-interop.mjs` drives a real server with that route failing); what is
   unguarded is only the two browsers drawing it. Reaching it in a spec needs a
   route intercept the test double does not currently support.
10. ⚠️ **The browser test double is single-account**, so §3's own-account filter can
   never fire there via enrolment. The specs reach the rule by planting a sender
   that was never enrolled — faithful, because the client's test is
   `accountDevices.has(sender)` — but a browser spec still cannot distinguish
   *"another account's device"* from *"a device that does not exist"*. Only the
   real-server suites can.
11. **Dev-gated, plain HTTP in dev, pre-audit, UNAUDITED.** Do not store real 2FA
   secrets.
