# Engineering lessons — how this project has actually failed

**Status: internal, pre-audit.** This document is a consolidated record of the
mistakes made building Sigil, what each one cost, and what changed as a result.
It exists because the same failure keeps recurring in different costumes, and
because a reviewer is better served by knowing our failure modes than by a
document that implies there were none.

`journal.md` is the chronological record; this is the pattern extracted from it.
Nothing here is hypothetical — every entry happened, and the fixes named at the
end are in the repository.

---

## The one failure mode this project has, in thirteen disguises

> **Work that quietly does not run looks exactly like work that passes.**

Every serious defect found here has been an instance of it. Not a wrong
algorithm — a *green signal that meant nothing*.

| # | What happened | Why it read as success |
|---|---|---|
| 1 | The Postgres integration suite **skipped** whenever `SIGILD_TEST_POSTGRES` was unset. A broken teardown shipped CI-red. | `go test ./...` exits 0 on a skip. |
| 2 | A literal **NUL byte** in `extension/src/popup/popup.js` made the file binary, so `grep` silently skipped it — and a security sweep for plaintext secrets "came back clean". | An empty grep looks like an absence of findings. |
| 3 | `requirePinStore(null)` **returned an empty store** instead of throwing, so the key-pinning control degraded into a no-op that still reported success. | The control "ran". |
| 4 | Nine cross-component interop suites ran in **no workflow at all** for roughly twenty phases. Then `accounts`/`recovery` repeated it. Then `entitlement-interop` repeated it again. | They were green locally, every time. |
| 5 | A security test named for a control **survived a mutation of that control**. Four other planted mutations were caught; that one was theatre. | A passing test. |
| 6 | `scripts/gate.sh` — written *specifically* to stop this class of problem — began with a hardcoded absolute path, so run from a git worktree it tested the **main checkout instead**. A `getrandom` stanza planted in a worktree lockfile still printed `getrandom==0`. | The gate said green about a tree it was not looking at. |
| 7 | A test double (`fake-sigild.mjs`) sent `Access-Control-Allow-Origin`, which **real `sigild` does not**. Six webapp specs passed while the app could not reach a real server at all. | The mock was more permissive than the thing it stood in for. |
| 8 | `cors.spec.ts` resolved Go via a hardcoded macOS path, so on CI it **`test.skip`ped itself** — leaving the only browser-level proof of a fix with zero coverage. Adding `actions/setup-go` did **not** fix it, because that sets `PATH` and never `$GO`. | A skipped file and a green job are indistinguishable. |
| 9 | No test asserted the "browsers persist only sealed containers" invariant. A planted plaintext write of the device seed, hybrid secret and every vault key passed **19/19 and 12/12**. | The suites checked for one needle, not for the property. |
| 10 | Two Phase 59 fixes were **guarded in the library and unguarded in the product**. A verifier reverted `cloneVault(vault)` in `authenticator.tsx` to the pre-fix `{ version, entries }` shape, and five of six `sealParams(...)` call sites to the bare constant — **webapp 50/50 and extension 14/14 stayed green** both times. Mutating the *same* logic inside `totp-vault.mjs` / `passkey.mjs` went red every time. | The module was covered, so the coverage *looked* real — while the fix in the shipping app was deletable without a single red light. |
| 11 | A capability probe for `BarcodeDetector` was run on **`about:blank`** and reported the API absent. `BarcodeDetector` is **secure-context gated**: the *same* browser, in the *same* session, exposes it on `http://localhost` and hides it on `about:blank`. The probe was correct about the page and wrong about the browser. | A negative result from a real measurement, on a real browser, reads as a fact about the browser. |
| 12 | ⭐ **In `scripts/gate.sh` itself, for the fourth time.** The Rust block was `t=$(cargo test … \| grep -E 'test result:')` followed by `grep -q FAILED && bad \|\| ok`. A crate that does not **compile** emits no `test result:` line at all, so `$t` is empty, `grep -q FAILED` does not match, and the gate printed a **PASS with a blank count**. Reproduced against a nonexistent manifest before the fix and after it (`OK-branch taken` → `✗ … produced NO 'test result:' line`). Adjacent, same commit: the `cargo build --bin sigil` line **discarded its exit code**, so a failed rebuild left the *previous* binary on disk for every node interop suite to test. | An empty result was treated as a count of zero failures rather than as an absence of evidence. |
| 13 | A **source-structure guard** written in Phase 64 to protect the one product layer with no behavioural coverage checked that the token `vaultIds` *appeared* and was not a literal `[]`. It never related the value **passed** to the value **bound**, so `vaultIds: vaultIds.slice(0, 0)` and `&vaults[..0]` both passed it while sending an **empty list** — the exact invisible failure it was written to catch. ⚠️ `cargo check` was clean on the second, so the type system did not catch it either. **The seventh guard in this repo to fail on its own subject matter.** | The guard ran, named the right file, and printed `ok`. |

The common shape: **the measurement was broken, not the code.** In most of these
the product was fine; what failed was the thing that was supposed to notice.

⚠️ **Entry 10 happened inside the commit that added this document**, which is the
most useful thing about it. Writing the pattern down did not prevent the pattern.
The fix was three new guards at the level that can see it — a Playwright spec in
each browser client that drives a **real UI edit** and then decrypts what the app
actually wrote, plus a source-structure guard enumerating every sealing call site
in the shipping sources and failing if it finds **zero**. ⚠️ That last one is
explicitly a regression guard for *a new call site that forgets*, not proof that
the helper it checks for is correct; it says so in its own header.

---

## Reasoning errors, separately

These are not tooling gaps. They are wrong conclusions drawn confidently.

**A no-op edit read as evidence.** A timing hypothesis was "ruled out" by raising
a Playwright timeout from 20 s to 150 s and observing no change. That option is
documented as **ignored** — `locator.isVisible({ timeout })` does not wait. The
parameter was never read, so the experiment could not have answered the question
either way. This led to a long instrumentation hunt for a React defect that did
not exist. *Before concluding a hypothesis is dead, check the knob is connected.*

**A snapshot mistaken for an outcome.** A failure artifact showed an unlocked
vault with the correct code, and was reported as the fix working. It was a
sanity-check step earlier in the same test.

**Instrumentation anchored on a non-unique string.** A probe was inserted at the
first match of `setPhase("unlocked")`, which was in a different function, so it
fired during an unrelated step and actively misled the investigation.

**A fix tested where the fix did not exist.** A `gate.sh` correction was
"verified" inside a git worktree, which checks out `HEAD` — i.e. the old script.
The same trap nearly recurred when worktree isolation was almost used for an
agent verifying *uncommitted* work.

**Claims repeated without re-checking.** A doc pass reported that four test
suites ran in no workflow; the same commit had already wired them. That stale
claim was then repeated downstream before anyone verified it.

**⭐ A wrong premise handed down as an instruction — and the agent that refused
it.** This is the sharpest instance this document has, because it is the thesis
happening to the person writing the thesis, and because it nearly deleted working
code.

Phase 63 added QR ingest over the platform's `BarcodeDetector`. A capability probe
was run to decide whether that API exists in desktop Chromium. It was run on
**`about:blank`**, which is **not a secure context**, and `BarcodeDetector` is
secure-context gated. It reported `undefined`. The conclusion drawn — *"this
browser cannot scan"* — was false about the browser and true only about that page.

What happened next is the part worth keeping. The orchestrator **acted on the
premise**: it stopped a running workflow and instructed an agent to **delete the
QR work as unusable**. The agent **re-measured instead of obeying**, in one
browser and one session:

```
about:blank              isSecureContext=false   BarcodeDetector=undefined
http://<LAN-IP>:port     isSecureContext=false   BarcodeDetector=undefined
http://localhost:53838/  isSecureContext=true    BarcodeDetector=function  [… "qr_code" …]
http://127.0.0.1:53838/  isSecureContext=true    BarcodeDetector=function  [… "qr_code" …]
```

The feature was correct and was kept.

⭐ **The lesson is not "measure carefully".** Everyone already believes that, and
it would not have helped — the probe *was* a real measurement on a real browser,
which is exactly why its answer was persuasive. The lesson is:

> **An instruction from the orchestrator is a claim like any other. An agent that
> verifies a premise instead of executing it is doing the job correctly, not
> being insubordinate.**

Every other entry in this document is about distrusting a green signal from our
own tooling. This one extends it one level up: the *briefing* is our own tooling
too. A directive that begins "X does not exist, therefore delete Y" is a claim
plus a conclusion, and the claim is the cheaper of the two to check.

⭐ It also produced a real product finding, which is why the mistake was worth
having. `BarcodeDetector` being secure-context gated is not a testing curiosity:
serving the app over plain HTTP from a LAN address — **a phone pointed at a dev
laptop, the obvious way someone would try to scan a code** — silently loses the
API. That is why `qrSupport()` is a runtime probe rather than a build-time one,
and why the message the user sees names the page's **origin** as a cause and not
only the browser brand.

**⭐ An attack test that could only fail one way, and the defect it hid.** Phase 64
reproduced a flood of a recovery kit's discovery index by depositing **520
envelopes of junk bytes**. It passed, and it proved the listing could be crowded.
It could prove nothing else: junk can only ever be refused by the AEAD, so every
planted row landed in `skipped` no matter what the restore did with a row it
could actually *open*.

Rewriting the same flood to mint **genuine, correctly authenticated** envelopes —
which any account can do, because every input to a vault-key wrap is public —
changed the answer completely. With the new trust rule mutated off, the restore
returned **six** vaults:

```
left:  ["zz-real-vault", "aaa-spam-00000", "aaa-spam-00001",
        "aaa-spam-00002", "aaa-spam-00003", "aaa-spam-00004"]
right: ["zz-real-vault"]
```

Five vaults belonging to a stranger, handed to the one person who by construction
has nothing left to check them against. The original test would have stayed green
through all of it.

⭐ **The lesson: build the attacker who is trying to SUCCEED, not the one who is
trying to be refused.** A negative-only adversary measures your error path; it
says nothing about your success path. Ask of every attack test: *if the control
were absent, is my attacker strong enough that something bad would actually
happen?* If the answer is no, the test is a shape, not a proof.

**⭐ An invariant closed for one instance and missed for its twin.** Phase 64
wrote down, in its own ADR, that a restore must never report a vault as recovered
when the result cannot be opened — and enforced it for a failed **keyring write**.
An independent verifier then found the *same* invariant broken by the **file
name**: `sanitize_file_stem` is not injective, so `team.vault` and `team_vault`
both became `team_vault.sigil`, the second silently replacing the first while both
were reported recovered. **Reachable with no attacker at all.**

⭐ The lesson is not "be more careful". It is that **stating an invariant is not
sweeping for it.** When a defect is characterised precisely enough to write down —
*"a container on disk that cannot be opened, reported as recovered"* — that
sentence is a **grep-able specification**, and the next step is to enumerate every
way it can happen, not to fix the instance in front of you. The same rule already
appears in this document as *"a false sentence is a class, not an instance"*; this
is its constructive twin.

**Documentation that was true when written.** Several status blocks told a
reader that `sigild` "performs no cryptography" and "holds no keys" while there
were crypto call sites in fifteen non-test files. A threat-model row advertised
recovery delegates with a seven-day veto window that has never existed. Both
would have scoped real code out of a review.

**A gate whose coverage was a strict subset of CI's.** `scripts/gate.sh` was
built to be the answer to "will this pass?" — and it ran neither security
scanner. The `security` workflow went red on two jobs (a `golang.org/x/text`
advisory reachable through `pgx`, and a permanently-failing `cargo-audit`) while
the gate reported ALL GREEN on the exact commit that broke them. It did not
disagree with CI; it never asked the question. **A pre-push gate can only tell
you CI will pass if it is a superset of CI.**

**A check that was always red, and therefore was not a check.** The
`cargo-audit` job used an action that fails on *warnings* with no way to
acknowledge one. `desktop/` pulls the whole Tauri tree: seventeen
unmaintained/unsound advisories on crates nobody here chose, and **zero
vulnerabilities**. So the job failed identically on every commit for as long as
it had existed. That is worse than not running it — a permanently red check
trains a reviewer to skip the one workflow where a real advisory would appear.
The fix was not to silence it but to make the accepted advisories *explicit and
reviewable in the repo*, so that anything **new** fails loudly.

---

## What changed as a result

These are controls, not intentions:

- **`scripts/gate.sh`** runs every suite, **enumerated dynamically** so a new one
  cannot be missed; **counts results** rather than trusting exit codes; resolves
  the repo from its own location and **prints which tree and commit it gated**;
  starts a throwaway Postgres and **fails if any test skipped**; and carries a
  **CI-drift check** asserting every suite on disk is named in some workflow.
  That drift check is itself mutation-tested. It also runs **both security
  scanners** (`govulncheck` against the toolchain we *ship*, not the newer one
  the dev machine happens to have; `cargo audit --deny warnings` across all four
  lockfiles), so a green gate can no longer coexist with a red `security`
  workflow.
- **An accepted advisory is written down, with an owner and an expiry
  condition.** `desktop/.cargo/audit.toml` lists each one, why it is tolerable,
  who can actually fix it, and what would remove it — and `--deny warnings`
  means anything *not* on that list fails. Suppression that lives in a diff can
  be reviewed; suppression that lives in a CI flag cannot.
- **Mutation testing is the default standard of proof** for anything
  security-relevant. A control whose mutation survives the suite is treated as
  broken, and several were.
- **Adversarial verification is a separate step from building**, with an explicit
  pass/fail acceptance criterion (for example "no lockout", or "reads are never
  refused"). Verifiers are told that a skipped suite, an unexercised control and a
  mock more permissive than the real thing are all *broken*.
- **Test doubles must not be more permissive than the real thing**, and where they
  are, the file says so in its own header.
- **A fix that lands in a shared library AND in a product must be guarded in the
  product too.** Library-level coverage of a shared helper says nothing about
  whether the shipping app still calls it. Where behavioural coverage of every
  call site would be disproportionate, a **source-structure guard** that
  enumerates the call sites is the accepted substitute — and it must fail when it
  finds *none*, or a rename silently turns it into a no-op.
- **Every terminal assertion waits.** `isVisible()` is banned as an outcome check
  in the browser suites; the suites were swept for it.
- **Claims are grepped against the code** before they are written down — env vars,
  metric names, route counts, test counts, command counts.
- **A premise in an instruction is checked before it is acted on**, especially
  when acting on it means deleting work. The cost of re-running a capability probe
  on a correct origin is seconds; the cost of removing a working feature on a bad
  one is the feature. Where a browser capability is involved, the probe must run
  on a **representative origin** — a secure context, not `about:blank` — because a
  negative on the wrong page is indistinguishable from a negative on the platform.
- **A false in-product sentence is treated as a class, not an instance.** When a
  finding named one client's stale claim in Phase 62, the identical sentence was
  found in another by grepping for the claim rather than trusting the finding's
  scope. Phase 63 applied that prospectively: the read-path warning went to all
  four clients, including the one nobody had reported.

---

## The uncomfortable summary

The fourth full-repo adversarial audit put it best: **the code held up; the
verification layer did not.** Seventeen of eighteen authorization mutations, seven
of nine storage mutations and thirty-three of thirty-eight test-integrity
mutations went red. A full secret hunt across `pg_dump`, every `bytea` column and
the server log found zero hits with a working positive control.

And in the same audit, **two of the three verification blind spots were in
tooling written hours earlier** — including the gate script built to prevent
exactly this.

The lesson worth keeping is not "test more". It is that **a green signal is a
claim, and claims from your own tooling deserve the same scepticism as claims
from anywhere else.**
