# 0049 — Entry identity, and a vault that merges instead of overwriting

- **Status:** Accepted (2026-07)
- **Date:** 2026-07-31
- **Builds on:** [0047](0047-container-parameter-ceiling-and-no-downgrade-ratchet.md)
  (which **added the `uuid` field and deliberately left it dead** — this decision
  is the semantics half that ADR deferred, and it is also why the schema could
  gain `tombstones` at all without a flag day),
  [0024](0024-wasm-totp-vault-and-cross-client-totp.md) (the `TotpVault` /
  `TotpEntry` JSON mirrored between Rust and JS — it carries a dated addendum
  pointing here), [0003](0003-dev-gated-opaque-op-log.md) (the opaque op-log,
  which is why the merge **must** live in the client and **can** be retroactive),
  [0025](0025-totp-import-export.md) / [0026](0026-browser-totp-import-export.md)
  (import/export, whose de-duplication rule changes here),
  [0007](0007-caller-supplied-entropy-in-core.md) (caller-supplied entropy — why a
  minted id is a v4 UUID formatted from bytes the *caller* draws, and why the
  derivation reads no clock and no RNG),
  [0037](0037-desktop-reuses-cli-library-for-protocol.md) (reuse, do not
  reimplement — why the desktop gets this for free).
- **Changes nothing in:** `sigild`. No route, no header, no canonical message, no
  migration, no table, no metric, no dependency, no schema-version bump. ⭐ **Not
  one byte of the wire protocol changed**, and that is load-bearing rather than
  incidental — see §4.

## Context

### The defect: both devices reported success, and one of them was lying

A vault syncs as a whole **sealed snapshot** through an append-only op-log. Every
client **adopted the newest snapshot wholesale** — `desktop/core/src/net.rs`'s
`pull_and_adopt` wrote the pulled container over the local vault, and the browser
clients took `ops[ops.length - 1]`.

Reproduced end to end before any of this was written, with the **real `sigil`
binary against a real `sigild`**:

```
=== what each op on the server contains ===
  op-1.sigil -> github          <- device A
  op-2.sigil -> gitlab          <- device B, which never pulled
=== the NEWEST op is what every browser client and pull_and_adopt adopt ===
  newest = op-2.sigil
  ⛔ the newest op contains ONLY gitlab
```

Device A adds `github` and pushes. Device B — which never pulled — adds `gitlab`
and pushes. B's snapshot is now the tip, it has never seen `github`, and **the
moment any client adopts the tip that account is gone**. Both pushes reported
success. The user is told nothing, and finds out when a code they need is not
there.

⭐ **A precision the original finding lacked, and it determined the shape of the
fix.** "Multi-device sync is last-writer-wins" is true of the *product* but **not
of the op-log, and not of `sigil pull`**, which writes every op to a separate file
and loses nothing. The loss happens at **adoption**. So the op-log was never the
problem and did not need to change — **the merge belongs in the client**, which is
also the only place it *can* live, because `sigild` cannot read the blob
([0003](0003-dev-gated-opaque-op-log.md)).

### The second defect: import de-duplicated on the label

`add` and `import` refused an entry whose **`label`** already existed. A user with
`work@github` and `work@gitlab` — or two `alice@example.com` accounts at different
issuers, which is the ordinary case for anyone with a work and a personal login —
had the second one **silently skipped by an import that reported success**. This
is the same failure class ADR 0047 §4 found in the multi-QR importer: the feature
whose entire purpose is not losing accounts, losing accounts quietly.

### Why the field to key on already existed

[ADR 0047](0047-container-parameter-ceiling-and-no-downgrade-ratchet.md) added a
per-entry `uuid` and then, in its own words, declined to use it:

> **A stable per-entry id** (`uuid`, a lowercase RFC 4122 v4 formatted from 16
> bytes of **caller-supplied** entropy […]) is added alongside. ⚠️ **Nothing keys
> off it yet.** Every lookup is still by `label`, deliberately: changing entry
> identity is a semantics decision, not a forward-compatibility one. This only
> makes that change possible later.

and recorded the cost as limitation 7:

> ⚠️ **The entry `uuid` is dead weight today.** It is written, mirrored, tested
> and used by nothing; identity is still the label. Nothing enforces uniqueness,
> and a duplicated vault file yields duplicated ids that no code objects to.

That deferral is the reason this change is small. The field is already in the
schema, already mirrored across four clients, already round-tripped by the
forward-compatibility rules, and **already being written by shipping builds**. All
that was missing was the decision about what it *means*.

## Decision

### 1. Identity is the `uuid`: MINTED for new entries, DERIVED for legacy ones

An entry's merge identity is its `uuid` when it has one, and otherwise a
**content-derived** id:

| entry | id | why |
|---|---|---|
| created by any Phase-61+ client | **minted** — random v4, 16 bytes of caller-supplied entropy ([0007](0007-caller-supplied-entropy-in-core.md)) | a new account is a *new thing*; two accounts that happen to share every field are still two accounts |
| written before the field existed | **derived** — RFC 9562 **version 8**, over the entry's content | two devices holding copies of the same old vault must arrive at the **same** id with no communication |

⭐ **Determinism matters for exactly one of these, and only across the migration
boundary.** A legacy entry has no id, and both devices must invent one *before*
they can merge. If those ids were random, then on first sync of any existing
multi-device vault:

- **every account in it duplicates**, because A's copy and B's copy of the same
  entry have different ids and the union keeps both; and
- **a delete can never work across the boundary** — a tombstone naming A's id
  says nothing about B's copy, so the entry comes back on the next merge, forever.

Deriving the id from the content makes both devices agree without either knowing
the other exists. The derivation is
[`libsigil/core/src/entry_id.rs`](../../libsigil/core/src/entry_id.rs); the
byte-exact transcript and its golden vector are in
[`../crypto-spec.md`](../crypto-spec.md).

⭐ **It is NOT a mirrored Rust/JS pair, deliberately**, unlike the vault schema
([0024](0024-wasm-totp-vault-and-cross-client-totp.md)) and the safety-number
digest ([0038](0038-key-pinning-safety-numbers-and-vault-rotation.md)). It lives
in `sigil-core`; the CLI and the desktop call it directly and the browsers reach
*the same bytes* through a one-line `wasm_bindgen` shell. The reason is the
failure mode: **a drift here is invisible**. It produces a vault that opens
correctly on every client and merely duplicates or mis-suppresses some entries —
no error, no exception, nothing to notice. A mirrored constant with a golden test
is an acceptable risk for a *format*; it is not an acceptable risk for a
*decision procedure* whose failure is silent divergence.

**Version 8 and not version 5.** RFC 9562 §5.5 defines version 5 as *"name-based,
SHA-1"*. This is SHA-256, so stamping a `5` would be a false statement encoded in
a wire format. Version 8 is the standard's "custom / implementation-defined"
version, which is exactly what this is.

### 2. A content FINGERPRINT is not an identity, and is used only for import

Two different questions, two different mechanisms, and conflating them is a bug
this code has already had:

| question | function | used by |
|---|---|---|
| *which entry is this?* | `entry_identity` — the `uuid` | the **merge** |
| *have I already got this account?* | `entry_fingerprint` — the content | **`add` and `import`** |

The import path **must** ask the second question. A freshly imported entry carries
no id at all, while the copy already in the vault carries a **random** one, so
comparing identities would never match and re-importing the same Google
Authenticator export would duplicate every account in it.

The fingerprint commits to `(issuer, label, secret, algorithm, digits, period)` —
exactly what makes two rows the same account — which is why `work@github` and
`work@gitlab` now both survive. ⭐ **It is a fingerprint, not an identity:** it is
a question asked *once*, at the moment of insertion, about content; it is never
stored, never merged on, and never the thing a tombstone names. Two entries with
identical content are the *same account* for the purpose of "should I add this
again?", and remain *different entries* for the purpose of "which one did you
delete?". Using the fingerprint as the identity would mean a user could not
deliberately hold the same secret twice, and — worse — that deleting one copy
deleted both.

### 3. The vault is a 2P-Set, and tombstone wins

```text
  entries    = (local.entries ∪ remote.entries)        keyed by identity
  tombstones = (local.tombstones ∪ remote.tombstones)  keyed by uuid
  result     = entries MINUS every id named by a tombstone     // DELETE WINS
```

A two-phase set: `entries` is the add-set, `tombstones` the remove-set, and the
merge is their union with the remove-set winning. It is the simplest convergent
structure that exists — commutative, associative and idempotent — so devices agree
regardless of pull order, duplicate delivery, or how many devices are involved.
Boring on purpose.

⭐ **Tombstone-wins is safe here, and the reason is structural rather than a
policy.** The textbook objection to a 2P-Set is *"a removed element can never come
back"*. It does not bite, because **a genuine re-add mints a FRESH uuid** — the
user adding an account again is creating a new entry with a new id, which no
tombstone names. So a "re-add" of an id that is already tombstoned is **not a user
action at all**: it is a stale snapshot or a hostile writer, and it *should* lose.
The flaw is dodged by construction, not papered over.

⭐ **No clock is in the correctness path.** No Lamport counter, no vector clock,
no per-entry revision, no timestamp tiebreak — because **entries are immutable**.
`add`, `import` and `remove` are the complete mutation surface across all four
clients: there is no rename, no edit, no in-place field change anywhere. A uuid
therefore names one fixed `(label, issuer, secret, algorithm, digits, period)`
forever, so *"which version of entry U wins"* is a question that cannot be asked.
`deleted_at` **is** written, but nothing branches on it (see limit 6).

⭐ **Every field combines by an order-independent rule, including the ones this
build does not understand.** The rules are `max` (`version`, `min_reader_version`,
the unknown-field `extra` maps at **both** the vault and the tombstone level, and
the entry tiebreak), `min` (`deleted_at`) and set union (entries, tombstones).
Where two entries claim the same id with different content, the winner is the
lexicographically greater **canonical** JSON — deterministic and order-independent,
unlike "local wins", which would break convergence outright.

⚠️ **That was not always true, and the exception was real.** Tombstone-level
unknown fields merged **first-seen-wins**, so two vaults whose tombstones shared a
uuid but carried different values for an unknown key **did not converge** — while
the doc comment beside the code claimed unqualified commutativity. It was found by
an adversarial verifier reading the claim against the code, and it was **fixed
rather than documented away**: a forward-compatibility field is precisely what a
*future* version writes and a *current* one must carry through a merge in either
order, so an exception there is a convergence bug, not a wording problem. Both
mirrors now use one canonical-JSON max rule, and both record the old behaviour in
place so it cannot be reintroduced innocently.

### 4. ⭐ Merge EVERY op, not the tip — the whole fix, free on the wire

The clients no longer read `ops[ops.length - 1]`. They fold **every** op in the
log into their **local** vault:

```text
  vault = local ⊕ op₁ ⊕ op₂ ⊕ … ⊕ opₙ
```

This is the entire fix. Everything else — the ids, the tombstones, the merge rules
— exists to make this fold well-defined.

**It costs nothing on the wire, because the op-log already stored every
snapshot.** `sigild` is an append-only log ([0003](0003-dev-gated-opaque-op-log.md));
it never deleted, mutated or compacted an op. The bytes needed to reconstruct
`github` in the reproduction above **were on the server the whole time** — every
client simply threw them away on the way in. No new route, no new field, no
protocol version, no server change; the fold starts at `local` rather than at a
fresh vault, so a client's own unpushed work is preserved too.

⭐ **The consequence worth stating loudly: this is RETROACTIVE.** A vault whose
accounts were shadowed by last-writer-wins on a real server, before this change
existed, is repaired the first time an updated client syncs it — the shadowing
snapshots are still in the log, and they are now merged instead of discarded. The
data was never destroyed server-side; it was destroyed *locally*, on adoption, and
only the local copies were lost. Any device that still holds one, or any op still
in the log, brings the account back.

⚠️ **What this does NOT recover:** anything that was only ever local and got
overwritten by an adopted snapshot without having been pushed first, and anything
in a vault that was never synced at all. The op-log can only return what reached
it.

### 5. Guarding the property the design rests on

The merge is correct **because entries are immutable**, which is a property of
code that does not exist rather than of code that does — the easiest kind to
destroy by accident, months from now, in good faith.

`sigil-wasm/test/merge-guard.mjs` (**51** structural checks across the shipping
clients, measured by running it) therefore fails the build if any shipping source
writes an entry content field in place, declares an edit-shaped operation
(`rename*` / `edit[Ee]ntry*` / `update[Ee]ntry*` / `set(Label|Secret|…)`), adds a
mutating `sigil totp` subcommand outside `{add, code, export, import, list,
remove, sync}`, or deletes the in-code warning that explains why there is no
revision field. Each file carries an **exact expected count with a written
justification**, so a *missing* hit is a failure too and a stale entry has to be
re-justified rather than silently absorbed.

⚠️ **It is a source check, not a proof** — see limit 3.

## The sentence an auditor should be able to check

> A TOTP entry has one identity — a random `uuid` when it was created by a build
> that mints them, and a **deterministic, content-derived** v8 UUID when it
> predates the field, so that two devices holding the same old vault agree without
> communicating; a vault is a **2P-Set** of entries and tombstones whose merge is
> commutative, associative and idempotent **on every field including the unknown
> ones**; every client folds **every op in the log** into its **local** vault
> rather than adopting the newest snapshot; the de-duplication done at import is a
> **content fingerprint** and is deliberately not the merge identity; and
> `sigild` was not modified at all.

## Consequences

### Good

- **The reproduced data loss is gone**, verified by an independent verifier
  against a real server, with no mutation surviving.
- **It is retroactive.** Data already shadowed on a real op-log comes back,
  because the log kept every snapshot and the client now merges them.
- **Nothing on the wire changed** — no route, header, migration, schema version or
  dependency, and old and new clients keep talking to the same `sigild`.
- **A vault converges regardless of pull order, duplicate delivery or device
  count**, and two devices that have seen the same snapshots serialize to
  **byte-identical** plaintext, which makes convergence a testable equality rather
  than a claim.
- **`work@github` and `work@gitlab` both survive an import**, and re-importing the
  same export is still idempotent.
- **ADR 0047's dead field became load-bearing** without a schema change, which is
  what its forward-compatibility rules were built for. The first real test of that
  design, and it held.

### Bad / honest limitations — every one of them real

1. ⛔ **TOMBSTONES GROW WITHOUT BOUND, AND THERE IS NO COMPACTION.** The remove-set
   never shrinks. Every removal appends a tombstone (~55–95 bytes of JSON) that
   must be carried **forever**, because dropping it resurrects the entry on the
   next merge with any device still holding a pre-delete snapshot. `sigil totp
   compact` **does not exist** and nothing anywhere prunes a tombstone.
   ⛔ **There is a hard stop:** `sigild` caps one op body at **64 KiB**
   (`maxOpsBodyBytes`) and answers **413** above it. Past that, **`push` fails and
   there is no supported way to shrink the vault** — the user discovers it at the
   moment they lose the ability to sync, which is the exact outcome this phase
   exists to prevent, arrived at by a different road.
   ⭐ **What is actually built is a WARNING, not a fix:** every client that seals a
   vault for push checks its size first and warns from **75 %** of the cap (48 KiB),
   and the 413 has a written explainer naming the cause, confirming that **nothing
   is lost locally** and that codes still work, and pointing at the only way out
   (export into a fresh vault id — which prints secrets in the clear). That is
   strictly less than compaction and is not pretended to be more.
2. ⚠️ **Two devices editing the same entry is resolved by a RULE, not by intent.**
   If two snapshots claim the same id with different content, the merge keeps the
   lexicographically greater canonical JSON. That is deterministic and convergent;
   it is **not** "the change the user meant". Today it is unreachable through the
   product (entries are immutable, and a same-id conflict means a hand-edited file,
   a hostile writer, or a legacy-id collision), which is why a rule is enough — but
   it is a tiebreak, not a merge of intent, and it silently discards one side.
3. ⛔⛔ **THE DESIGN IS CORRECT ONLY BECAUSE ENTRIES ARE IMMUTABLE.** If a rename,
   a period change or an in-place secret update is ever added, **this merge becomes
   wrong** — it will silently keep whichever copy sorts higher, with no clock and
   no revision to appeal to. **An edit must be implemented as delete + add with a
   fresh uuid, or the merge needs a revision rule FIRST.** The guard in §5 makes
   that decision loud rather than silent; ⚠️ **it does not make it impossible**. It
   is a source-structure check, and it cannot catch an edit routed through a helper
   it does not know about, or an entry rebuilt field-by-field into a new object
   literal under the same uuid. It was chosen over structural enforcement (private
   fields + accessors) for a stated reason: `TotpEntry` is a **mirrored** schema
   whose JS half is a plain object literal that no language feature can seal, so a
   structural fix would cover one of two implementations and two of four shipping
   clients **while reading as if it covered all of them** — the worst outcome
   available. It raises the cost of adding an edit accidentally; it does not
   prevent one.
4. ⚠️ **A v1 reader can still open a merged vault, and *"this snapshot came from a
   build that cannot delete"* is a real state.** Nothing bumps `min_reader_version`
   for tombstones — deliberately, since refusing would be the flag day ADR 0047
   abolished — so a merged vault still declares `version: 1` and opens on older
   clients. A build carrying ADR 0047's `extra` preservation will **round-trip
   `tombstones` it does not understand**, so the removals survive; ⛔ **a build
   older than ADR 0047 will strip them**, and every entry those tombstones
   suppressed comes back on the next merge. Even on a preserving client, a delete
   performed by a pre-Phase-61 build records **no tombstone at all** (it just drops
   the entry), so that removal is undone by the next merge with any device that
   still has the entry. The mixed-version window is real, it is silent, and the
   only defence is upgrading every client.
5. ⚠️ **A first merge reorders a hand-arranged vault, once.** Canonicalization
   sorts entries by `uuid` — chosen precisely *because* it is ASCII hex, so Rust's
   byte-wise `Ord` and JavaScript's UTF-16 comparison agree exactly; sorting on
   user text would let the two languages order some non-ASCII strings differently
   and produce different canonical bytes for the same set. Display order is each
   client's own business, but the stored order changes.
6. ⚠️ **`deleted_at` is written and read by nothing.** It exists so a *future*
   compaction has a field to key on — the only safe prune rule is "drop tombstones
   older than a retention window every device is guaranteed to have synced within",
   and that needs a timestamp. It is merged by `min`, so a wrong or hostile clock
   can only make a delete look **earlier**, never postpone it. Nothing branches on
   it today, and **a merge rule that does must revisit the no-clock argument in
   §3 first.**
7. ⚠️ **A derived id is a commitment to the entry's full content, including the
   secret.** It is an identifier, not a secret and not a key — but it is computed
   *over* the secret, so anyone holding a candidate `(issuer, label, secret,
   algorithm, digits, period)` can confirm it against a v8 id they can see. Ids
   live only inside the sealed vault, so this is not a new exposure; it is a reason
   the derivation is used **only** to bootstrap legacy entries and to answer the
   import question, and never as the id of a newly created entry.
8. ⚠️ **Ids are stable within a vault's lifetime, not across export/import.** The
   `otpauth://` and migration formats carry no entry id (they are interop formats),
   so a round-trip through either mints fresh ids — inherited unchanged from ADR
   0047 limitation 10.
9. ⚠️ **The browser and desktop size warnings are not behaviourally tested.** The
   webapp's and extension's calls are covered *structurally* by the guard and the
   underlying function is covered by the interop suite, but no Playwright spec
   drives a >48 KiB vault through a browser push, and the desktop's toast — which
   crosses the IPC as a new `PushOutcome` field — is by-eye. Only the CLI's warning
   is proven end to end against a real server.
10. ⚠️ **The size test fixture is tuned, not derived.** 750 tombstones seals to
    ~54 KiB, inside the 48–64 KiB warn band. An earlier attempt used 900 and landed
    597 bytes below the push cap — one JSON tweak from failing for the wrong
    reason. It is commented, but it is a magic number a schema change could move.
11. ⚠️ **The 64 KiB cap is now a fourth hand-written copy** (Go, Rust, JS, plus the
    desktop delegating to Rust). The guard asserts all of them agree, because a
    silent drift makes the warning fire at the wrong size — or after the wall.
12. ⚠️ **Everything here is UNAUDITED**, pre-audit and dev-only, like the rest of
    the repo.

### Neutral

- **"CRDT" is used here in a precise and limited sense.** The *entry set* is a
  2P-Set with a convergent merge, and that claim is now true on every field. It is
  **not** a general-purpose CRDT for a mutable record: there is no clock, no
  revision and no register semantics, and the convergence argument depends
  entirely on limit 3. An unqualified "the vault is a CRDT" was an over-claim that
  a verifier caught in a shipped code comment, and it is not repeated here.
- The merge is **idempotent**, so re-pulling ops already folded in is free, and a
  duplicate delivery is not a correctness concern.
- The desktop inherited all of this without new logic, by
  [0037](0037-desktop-reuses-cli-library-for-protocol.md)'s reuse rule; it gained
  exactly one new command (`remove_by_id`, bringing the total to **41**) and one
  changed return type.

## Alternatives rejected

- **Use the `label` as the identity.** It is what the code did, and it is exactly
  the second defect: labels are neither unique (two `alice@example.com` accounts at
  different issuers) nor stable enough to key deletion on. Also incompatible with
  ever supporting a rename.
- **Use the content fingerprint as the identity.** Tempting, because it needs no
  new field and is deterministic everywhere. Rejected: a user could then not hold
  the same secret twice, and deleting one copy would delete both. Content answers
  *"is this the same account?"*, not *"is this the same entry?"*.
- **Mint a random id for legacy entries too.** Simplest code, catastrophic
  behaviour: on first sync of any existing multi-device vault it duplicates every
  account and makes deletion impossible across the migration boundary. This is the
  single decision the whole `entry_id` transcript exists to serve.
- **Mirror the derivation in JavaScript** rather than adding a wasm shell.
  Rejected — a drift is invisible (see §1). The same reasoning ADR 0047 used to
  refuse a JS copy of `no_downgrade`.
- **Last-write-wins with a timestamp.** Rejected: it needs a trustworthy clock on
  every client, which we do not have and would not want in the correctness path,
  and it *still* loses data — it would simply lose it more predictably.
- **A vector clock or a Lamport counter per entry.** Rejected as unnecessary given
  immutability, and as a real cost: per-entry metadata that grows with the device
  count, in a vault that already has an unsolved growth problem (limit 1). If edits
  are ever added, this is the decision to revisit.
- **An add-only set (no tombstones), leaving deletion unsupported.** Rejected: it
  makes the growth problem disappear by removing a feature users have and rely on.
- **Merge on the server.** Impossible without destroying the property the
  architecture exists for: `sigild` would have to read a blob it is designed to be
  unable to interpret ([0003](0003-dev-gated-opaque-op-log.md)). Worth stating
  because it is the first thing a reader will reach for — and because it is what
  makes "merge every op in the client" the only available answer.
- **A server-side compaction or delete-op route to bound tombstone growth.** Same
  objection, plus it would give the server the ability to *suppress* a delete.
  Compaction has to be a client-side, retention-window rule; it is not built, and
  limit 1 says so rather than implying otherwise.
