# 0050 — The product stops harming and lying to its user

- **Status:** Accepted (2026-07)
- **Date:** 2026-07-31
- **Builds on:** [0049](0049-entry-identity-and-the-mergeable-vault.md) (the
  2P-Set merge — it is what **raised the stakes** of a mis-clicked delete, and it
  is also the reason the answer here is a confirmation and not an undo),
  [0042](0042-recovery-kit.md) (the printed kit — the capability two clients were
  telling the user, in the product, that they did not have),
  [0035](0035-device-to-device-vault-sharing.md) (the password → vault-key
  conversion `vault rekey` performs, the one-way door),
  [0023](0023-totp-hotp-primitive-and-cli-vault.md) /
  [0007](0007-caller-supplied-entropy-in-core.md) (the core reads **no clock**;
  the instant is always the caller's — which is precisely why a *client's* clock
  being wrong is a product problem the core cannot see),
  [0044](0044-opt-in-cors-allowlist.md) (the CORS allowlist — the one place
  `sigild` changed),
  [0037](0037-desktop-reuses-cli-library-for-protocol.md) (reuse, do not
  reimplement — why the desktop's clock reading is the CLI library's).
- **Changes in `sigild`:** ⚠️ **ONE additive line, and this ADR says so plainly
  rather than repeating the "`sigild` gained nothing" sentence that several
  recent phases could truthfully use.** `"Date",` in
  `corsExposedResponseHeaders` (`sigild/internal/api/cors.go`), plus the
  assertion for it in `cors_test.go`. No route, no new header, no canonical
  message, no migration, no table, no metric, no dependency, no schema-version
  bump. See §5 for why it is necessary and why it discloses nothing.

## Context

Phases 47–49 fixed things the system did wrong: an unauthenticated container
header, an anonymous key wrap, a vault that overwrote itself. This one fixes
things the **product** did wrong — to the person using it. Four defects, one
theme: *the client either destroyed something on a single click, or told the user
something that was not true, or left them debugging the wrong thing.* None of
them is a cryptographic flaw. All of them lose the user their accounts.

### Defect 1 — a one-click delete of a second factor, on a row that re-renders every second

Every client's account row carried a bare **Remove** button wired straight to the
removal. It sits inches from the code the user opened the app to read, on a row
that repaints once a second. A mis-click is the *expected* case, not the exotic
one — and what it destroys is a TOTP secret, which is frequently the only thing
standing between the user and the account it protects. Losing it can mean losing
that account permanently, with no help available from us, because we cannot read
it either.

⭐ **And [ADR 0049](0049-entry-identity-and-the-mergeable-vault.md) — landed one
phase earlier — RAISED the stakes rather than lowering them.** Before it, a
delete wrote a snapshot; a device that had not pulled might, by pure accident,
push an older snapshot back and *resurrect* the entry. That was a data-loss bug
and it was fixed. But the fix means a removal now writes a **tombstone** that
propagates to every device and is **specifically protected against
resurrection** (0049 §3: tombstone wins; a stale snapshot re-adding the same id
**loses**). The accidental safety net was removed on purpose. **A mis-click is
now more permanent than it used to be**, and nothing in the UI had been adjusted
to match.

### Defect 2 — two clients told the user, in the product, that they could not print a recovery kit

The webapp's and the extension's account panels both contained the sentence *"a
recovery kit was printed in advance … this app cannot print one"*. That was
**true until Phase 56 and false ever since** — both clients gained a full
recovery UI in that phase, and in the webapp the **Generate a kit** button is on
the same screen as the sentence denying it exists.

This is the worst class of documentation defect this repo has. A stale status
line in a `.md` misleads a maintainer. A stale *capability* claim inside the
product, about the **single control that prevents permanent, unrecoverable loss
of every account in the vault**, does not merely fail to help — **it routes the
user past the fix**. [ADR 0040](0040-account-model.md) limitation 1 is blunt
about the consequence: lose every device and the account is permanently
unreachable, by the customer *and* by us. [ADR 0042](0042-recovery-kit.md) exists
to give them one way out. Two of the four clients were talking them out of taking
it.

⚠️ The webapp carried the identical false sentence and the finding that started
this work **did not name it** — it named the extension. It was found by grepping
for the claim rather than by trusting the report. That is the general rule here:
*a false sentence is a class, not an instance; sweep for it.*

### Defect 3 — `vault rekey` dropped the password with no acknowledgement

`sigil vault rekey` converts a **password**-sealed vault into a **vault-key**
sealed one ([0035](0035-device-to-device-vault-sharing.md)). It is a **one-way
door**: afterwards `SIGIL_PASSWORD` does not open that vault — not "as well as",
**instead** — and the fresh random key lives in `~/.sigil/vault-keys.json`, mode
`0600` but **in the clear**. Lose that one file (wiped home directory, a backup
that skipped dotfiles, a fresh install) and the vault is unreadable by the user
and by us, password or not.

It ran on a bare invocation. Worse, the failure it sets up is **silently
misdiagnosed**: the next ordinary `sigil totp list` fails with
`could not open record: Aead(Authentication)` — **byte-identical to what a wrong
password produces** — so a user who converted a vault last month concludes they
mistyped, and retypes forever.

### Defect 4 — the most common real-world authenticator failure was reported nowhere

A TOTP code is a function of a shared secret **and the current time**. When a
device's clock drifts past half a step, the codes it produces start falling
outside the window a verifier accepts — and **to the user a rejected code is
indistinguishable from a wrong secret**. So they re-scan the QR, re-import the
export, delete and re-add the account (see defect 1), and none of it helps,
because nothing was ever wrong with the secret.

No Sigil client reported this anywhere, on any surface.

⚠️ **Say this accurately and keep saying it accurately.** RFC 6238 §5.2 permits a
verifier to accept a code from one time step either side, and real verifiers
commonly do. A drift just over half a step therefore **often still validates**;
the further it drifts the more certainly it does not. The honest claim is
**"likely to be rejected, and increasingly certain"** — **never** "every code
will be rejected". The first version of this feature's copy overstated it in
eight places and was corrected; do not reintroduce it here or in the product.

## Decision

### 1. A destructive delete requires a confirmation that NAMES the entry

The **three GUI clients** — webapp, MV3 extension and native desktop — gate a
single-entry delete behind a confirmation that states **which account** is about
to be destroyed, that the deletion is **permanent**, and what happens on the
other devices.

⚠️ **The CLI deliberately does NOT gate**, and an earlier draft of this ADR
claimed it did. `sigil totp remove <label>` is already a typed statement of
intent; a prompt would break every script and every e2e suite that drives it, and
a tool that asks "are you sure?" at a shell is a tool people learn to pipe `yes`
into. Instead it **prints the consequence** after acting, and `merge-guard.mjs`
makes that exemption conditional on the sentence still being there — so the CLI is
exempt from the confirmation rule but not from the honesty rule.

The confirmation copy is itself constrained by two rules learned the hard way in
this phase:

- ⛔ **It must not overclaim propagation.** The first draft said the deletion *"is
  synced to every other device holding it"*. **False.** Sigil syncs **only when
  the user asks it to**. The shipped wording is: the deletion reaches every other
  device *the next time you Push and they Pull*; **until you do — and forever, if
  you never sync — it applies to this device alone.*
- ⛔ **It must not promise reversal.** It says it cannot be undone from here, and
  that if the secret exists nowhere else the account it protects may be lost.

### 2. ⭐ A confirmation, and deliberately NOT an undo

An undo was considered and rejected, because in a merged vault it has only two
possible implementations and both are worse:

1. **Write the tombstone, then retract it.** Retracting a tombstone is exactly
   the **resurrection** [ADR 0049 §3](0049-entry-identity-and-the-mergeable-vault.md)
   is built to prevent, and it is **unretractable the moment any other device has
   merged it** — the tombstone has already won there, permanently, by design. An
   undo that works only until someone else syncs is a promise the product cannot
   keep.
2. **Hold the delete pending in memory** and commit it later. Closing a browser
   tab or an extension popup then silently discards the user's intent, and the
   entry the user believes is gone is still on their device and still on every
   other device.

⭐ **So the gate goes BEFORE the irreversible act, never after it.** The tombstone
is written at commit and never before. This is the only version that does not
fight the merge semantics, and it is why "add an undo" is not a future work item
for this decision — it is a design that was rejected on the merits.

### 3. The false recovery claims are deleted, and reduced to ONE string per client

Both browser clients now hold a single `RECOVERY_ADVICE` constant, used
everywhere the subject comes up, that says the true thing: **a kit cannot be
created after access is lost — but this app CAN print one right now**, and it
names the control. The part that remains true is kept and is a property of the
design, not of the client: *a kit cannot be created after the fact*
([0042](0042-recovery-kit.md)).

One string per client is the point. The defect was drift between a capability and
a sentence about it; a single constant is the cheapest structure that makes the
next drift a one-line edit rather than a hunt.

### 4. `sigil vault rekey` requires `--yes`, and says what is lost

The command refuses without `--yes` and prints the full consequence first: the
password stops opening the vault, every later command must name the vault
(`--vault-id`), the key file becomes the **only** thing that opens it, and it
should be backed up. ⭐ **A refusal, not a prompt** — it must behave identically
in a script and at a terminal, and the operator has to type the
acknowledgement. The desktop gates the same conversion in its own dialog with the
same facts, including *where* the key then lives.

A separate hint (`rekey_hint`) catches the aftermath: when an open fails and the
keyring names vaults, the error explains that a converted vault fails **exactly
like a wrong password**, so the user stops retyping.

### 5. A clock-skew DIAGNOSTIC on all four clients — and the one line `sigild` gained

⭐ **The source of truth was already on the wire.** Every response Go's
`net/http` produces carries a `Date` header (RFC 9110 §6.6.1), so any `sigild` a
client already talks to is a clock reference. **No new route, no new endpoint, no
new dependency.** The reading is taken from one unauthenticated `GET /healthz`,
and it is deliberately its **own** request rather than a value threaded out of
push/pull — the reading must still be available when the sync itself **failed**,
which is exactly the moment the user is trying to work out what is wrong.

- **Rust** (`cli/src/lib.rs`): `CLOCK_SKEW_WARN_SECONDS = 15`, `ClockSkew`,
  `parse_http_date`, `server_clock_skew`. The date parse is hand-rolled — a
  date-parsing crate for one 29-character fixed-width field would be a new
  dependency in a repo whose whole posture is *don't*.
- **CLI**: a new `sigil clock [--server <url>]`, plus a stderr warning appended to
  `push` and `pull` — so a broken clock is found while doing something else,
  long before the user is sitting in front of a rejected login.
- **JavaScript** (`sigil-wasm/clock-skew.mjs`, re-exported by `@sigil/wasm` and
  vendored into the extension): `parseHttpDate`, `skewFromDateHeader`,
  `readClockSkew`, `fetchClockSkew`, `describeClockSkew`. It imports nothing —
  no crypto, no auth, no storage.
- **Desktop**: a `clock_skew` Tauri command over `DeviceConfig::clock()`, which
  calls the CLI library ([0037](0037-desktop-reuses-cli-library-for-protocol.md))
  rather than adding a second HTTP client.

**The threshold is 15 seconds** — half of the default 30-second step, the point
at which drift starts costing the user codes rather than merely being untidy. It
is **mirrored, not shared**, between Rust and JS, and
`sigil-wasm/test/clock-skew-interop.mjs` §3 guards it two ways: the literal
(both sides pinned to the golden `15`, because a *coordinated* retune passes a
cross-language equality check while changing what every client tells a user —
the same lesson as the `"recovery-kit"` label in Phase 57), and the **behaviour**
(the real `sigil clock` binary and the JS reader judge one identical `Date`
reading at offsets 0, ±14, ±15, ±16, ±17, ±60 and must return the same verdict,
exit status and direction word).

⛔ **A mis-parse must be `null`, never a wrong number.** `Date.parse` is
permissive and its non-ISO behaviour is implementation-defined —
`Date.parse("12345")` returns a finite number (the year 12345), and the first JS
version turned a nonsensical header into a confident reading ~10,000 years out,
i.e. a screaming skew warning aimed at a user whose clock was **perfect**. The JS
half now shape-checks RFC 9110 IMF-fixdate *before* trusting `Date.parse`; the
Rust half hand-rolls the whole parse and never had the exposure.

#### ⚠️ The one `sigild` line, and why it was needed

`Date` is **not** one of the seven CORS-safelisted response headers, so a browser
on a different origin reads **`null`** for it. This was **measured, not assumed**:
probed with a real Chromium against a real `sigild`, the only readable headers
were `content-length`, `content-type` and `x-request-id`. **Without the line, the
browser half of the diagnostic is dead** — it would silently report *no reading*
forever, on the two clients that most need it.

So `corsExposedResponseHeaders` gained `"Date",` — additive, one line, with a
test asserting it. It discloses **nothing**: the header is already sent on every
response and already readable by `curl`, the CLI and the desktop; all that
changes is whether same-machine JavaScript may read a value the browser already
received. And the middleware is **not installed at all unless
`SIGILD_CORS_ORIGINS` is set** ([0044](0044-opt-in-cors-allowlist.md)) — with it
unset, `sigild` is byte-identical to before.

### 6. ⛔⛔ It REPORTS. It never CORRECTS.

Nothing in this feature feeds the clock used to **generate** codes. `sigil-core`
reads no clock at all ([0007](0007-caller-supplied-entropy-in-core.md)) and the
instant is always supplied by the caller from the system clock — that stays true
on every client, and is asserted by a desktop test that takes a reading a billion
seconds out and then still prints the RFC 6238 vector `94287082`.

A client that silently generated codes against a server-supplied time would
produce codes the user **cannot reproduce, cannot compare against any other
authenticator, and cannot reason about when the server is wrong or hostile**. ⭐ *A
wrong code the user can explain beats a right code they cannot trust.*

### 7. ⭐ "No reading" is a distinct answer from "your clock is fine"

An offline client, a server that answers with no usable `Date`, or a browser on
an origin the server has not allowlisted, all produce **`state: "unavailable"`**
(`available: false` on the desktop) with a reason, rendered as **NO CLOCK
READING — this is not a report that your clock is fine, it is the absence of a
report.** Saying "fine" when we could not ask is the same class of lie as the
stale capability claims this same decision removes, and the CLI's push/pull
warning is silent in that case rather than reassuring.

## Consequences

### Positive

- A mis-click can no longer destroy a second factor on any of the four clients,
  and the confirmation names the account rather than asking a generic
  "are you sure?".
- Two clients stopped steering users away from the one control
  ([0042](0042-recovery-kit.md)) that prevents permanent account loss.
- `vault rekey`'s one-way door is acknowledged before it is walked through, and
  its silently-misdiagnosed aftermath now explains itself.
- The most common real-world authenticator failure is reported on all four
  surfaces, from a clock reference that already existed on the wire.
- **The delete gates are guarded structurally.** `sigil-wasm/test/merge-guard.mjs`
  §3b now *locates the destructive call and walks outward* — `desktopDeleteGate`,
  `extensionDeleteGate`, `webappDeleteGate` — instead of asking "does this
  pattern appear anywhere in the file?". That rewrite was forced by two
  mutations that survived the first version (§Verification below).
- The webapp and the extension gained behavioural specs (`user-safety.spec.ts`,
  `user-safety.spec.mjs`) that drive the **real shipping UI**, so reverting the
  product file — not merely the shared module — turns them red. That distinction
  is `docs/engineering-lessons.md` entry 10, and it is why they were written at
  this level.

### ⛔ Negative / honest limits — state these as loudly as the features

1. ⛔ **A confirmation is not an undo. A confirmed delete is still permanent.**
   The tombstone propagates and is protected against resurrection
   ([0049](0049-entry-identity-and-the-mergeable-vault.md) §3). This decision
   makes destruction *deliberate*; it does not make it *reversible*, and by §2 it
   never will within this design.
2. ⛔ **The clock feature is a READING, never a correction.** It cannot fix a
   clock, will not offset one, and a user who ignores it keeps generating
   rejected codes. The only remedy it offers is "turn automatic time sync on".
3. ⛔ **An offline client gets NO reading — and that is not a report that the
   clock is fine.** The single most likely real-world situation (a laptop with a
   dead clock battery, offline in a hotel) is precisely the one where this
   feature can say nothing useful. It is rendered as an explicit absence, but an
   absence is what it is.
4. ⚠️ **It is not a security control, and the reading is not trustworthy.** It
   comes from an unauthenticated plaintext header over plain HTTP; anyone who can
   see the traffic can change it. A hostile or merely wrong server can make the
   hint wrong in either direction — it can claim skew where there is none, or
   stay silent where there is. **No key, signature, envelope or generated code
   depends on it**, which is the only reason that is acceptable.
5. ⚠️ **The desktop clock UI is BY-EYE ONLY.** `DeviceConfig::clock()` has a real
   test against real HTTP (all three states, plus the never-corrects property),
   but the panel in `desktop/ui/` that renders it is unrendered by any test — as
   is the desktop's delete confirmation dialog. `desktopDeleteGate` is a
   **source-structure** check: it proves the confirmation is on the path to the
   destructive call, and **nothing** about whether the window actually shows it.
   The desktop remains the least-verified client; it is now less so, not fixed.
6. ⚠️ **The browser clock and delete specs run against
   `sigil-wasm/test/fake-sigild.mjs`, a DOUBLE** — no signature verification, no
   authorization, no entitlement gate, no replay window. A spec there proves what
   the **browser** does and nothing about what `sigild` would allow. The
   server-side half is proven by `clock-skew-interop.mjs` against a real
   `sigild`.
7. ⚠️ **The threshold mirror is guarded in TWO languages, not three.**
   `web/packages/sigil-wasm/index.d.ts` re-declares the type surface by hand and
   `tsc` cannot see drift in it — the same third-literal problem Phase 57 recorded
   for the `"recovery-kit"` label. Not closed.
8. ⚠️ **The delete gates are source-structure checks and can false-alarm a
   legitimate refactor.** Moving the desktop confirmation into a helper
   (`if (!confirmDelete(who)) return;`) goes red although it is correct. That is
   deliberate — fail closed, loudly, with a message naming the fix — but it is a
   maintenance cost, and a maintainer under time pressure could "fix" it by
   weakening the gate rather than updating it. That is the failure mode
   [`docs/engineering-lessons.md`](../engineering-lessons.md) entry **3** records
   (a control that was relaxed until it degraded into a no-op *while still
   reporting success*), and the reason its "what changed as a result" list
   requires a source-structure guard to fail when it matches **nothing** — a
   guard that silently stops matching is indistinguishable from one that passes.
9. ⚠️ **The guard machinery is a hand-rolled scanner, not a parser.** `blank()`
   uses the standard previous-token heuristic for regex literals and treats `//`
   as a comment wherever it appears outside a string, so a bare URL in JSX *text*
   would be blanked. None exists in the three files today, and every failure mode
   is red rather than green — but a parser would mean a new dependency, which this
   repo does not take.
10. ⚠️ **Nobody has read the whole phase's new copy end to end hunting for further
    overstatements.** Two were found and swept (`"every code"`,
    `"is synced to every other device"`); others may remain.
11. Everything here remains **dev-gated, plain HTTP, pre-audit and UNAUDITED**.

### Neutral

- **`sigild` was modified.** One additive line, and this ADR opens by saying so
  rather than reaching for the "`sigild` gained nothing" sentence that
  [0035](0035-device-to-device-vault-sharing.md)-era, [0046](0046-passkey-protected-local-containers.md),
  [0048](0048-authenticated-vault-key-envelopes.md) and
  [0049](0049-entry-identity-and-the-mergeable-vault.md) could each truthfully
  use. That sentence is valuable **because** it is checked, and it is checked by
  being willing to say the opposite.
- The clock threshold and the skew *description* are a Rust↔JS **mirror**, joining
  the small set this repo maintains (the container constants, the safety number,
  the migration codec, the entry-id derivation). Mirrors drift silently; the
  interop suite is the guard.
- `sigil clock` reads `GET /healthz`, which is never dev-gated, never rate
  limited and returns no data — so the diagnostic works against a `sigild` with
  every stateful route still answering `501`.

## Verification

- `sigil-wasm/test/clock-skew-interop.mjs` — the Rust↔JS threshold (literal **and**
  behaviour, against the real `sigil` binary and a real `sigild`), the offline
  *no reading* outcome, and `Date` readable **cross-origin**. Mutation-proven by
  changing the **Rust** constant only: `15 → 45` and `15 → 16` both go red, the
  second being the tightest possible change.
- `web/apps/webapp/tests/user-safety.spec.ts` and
  `extension/tests/user-safety.spec.mjs` — the delete confirmation, the corrected
  recovery sentence and the clock panel, driven through the **real** shipping UI.
  They assert the honest propagation wording positively and assert the
  overclaiming sentence is **absent**.
- `desktop/core/tests/server_interop.rs` —
  `the_desktop_clock_diagnostic_reports_all_three_states_and_never_corrects`:
  a real `sigild` (unenrolled, because the reading comes off unauthenticated
  `/healthz` and a user with a broken clock frequently cannot authenticate), a
  fixed past `Date`, a fixed future `Date`, a dead port, a server that sends no
  `Date` — and then, after a reading a billion seconds out, the vault still
  prints `94287082`. Mutation-proven twice (`skewed: skew.significant() → false`
  and the error arm's `available: false → true` both panic).
- `sigil-wasm/test/merge-guard.mjs` — the three delete gates, plus a **self-test
  that runs each predicate against specimens that are the surviving mutations
  themselves**, and good shapes so a predicate that returns `false` forever is
  caught. 108 structural checks.
- ⚠️ **Two mutations SURVIVED the first version of these guards**, which is why
  §3b was rewritten rather than patched. See `journal.md` for the reproduction:
  the desktop check required `window.confirm(` *anywhere* in a file containing
  **six** such calls, and the extension check banned exactly one spelling of the
  bypass. Both now fail red, and the webapp check had the same class of hole
  (`onClick={onRemove}` banned literally, `onClick={() => onRemove()}` walked
  past it).
- `sigild/internal/api/cors_test.go` — `Date` is on
  `Access-Control-Expose-Headers`.
- `./scripts/gate.sh` — full green apart from the documentation counts this ADR
  ships with.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| **An undo instead of a confirmation** | Both possible implementations are worse — see §2. It would either retract a tombstone (the resurrection [0049](0049-entry-identity-and-the-mergeable-vault.md) prevents, unretractable once merged) or hold intent in memory, where closing a popup discards it. |
| **A soft-delete / trash bin** | That is what a tombstone already is at the data layer, and exposing it as a reversible UI state re-creates the retraction problem. It also keeps the secret on disk after the user asked for it to be gone. |
| **Correct the clock: generate codes against server time** | ⛔ Rejected outright. It produces codes the user cannot reproduce or check anywhere else, silently trusts an unauthenticated header, and breaks the property that the core reads no clock ([0007](0007-caller-supplied-entropy-in-core.md)). |
| **A new `GET /v1/time` route on `sigild`** | Unnecessary: every response already carries `Date` (RFC 9110 §6.6.1). A new route would be a new dev-gated surface, a new stub, a new contract and a new thing to keep honest. |
| **NTP / a time library on the clients** | A new dependency on every client, on all four platforms, to answer a question one existing response header already answers — and it would not tell the user anything the server comparison does not. |
| **Expose `Date` to `*` / drop the CORS allowlist** | `*` is refused **at boot** by [0044](0044-opt-in-cors-allowlist.md) and that stays. The exposure rides the existing opt-in allowlist and is inert when it is unset. |
| **A prompt instead of `--yes` on `vault rekey`** | A prompt behaves differently in a script than at a terminal. A refusal is identical in both, and forces the acknowledgement to be typed. |
| **Fix the false recovery sentence in place** | Done once already, elsewhere, and it drifted. One constant per client is the structure that makes the next drift a single edit. |
