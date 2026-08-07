# Sigil docs

**Internal / pre-audit.** These documents describe intended design. They are
kept behind the pre-launch wall and are **not** published publicly until the
independent audit completes and trademark clears (brief, GTM Phase 1).

## If you are here to review the security of this system, start here

This repository exists to be reviewed, so this section is the map rather than a
summary. Read it before the file list below.

**Read in this order.** [`architecture.md`](architecture.md) for the trust
boundary and the life of one record; [`crypto-spec.md`](crypto-spec.md) for the
primitives and the constructions built on them;
[`threat-model.md`](threat-model.md) for the adversary classes and what is
explicitly *not* defended; then [`decisions/`](decisions/README.md), which is
where the reasoning actually lives.

**The load-bearing decisions**, if you read only a few ADRs:
[0035](decisions/0035-device-to-device-vault-sharing.md) (the PQ-hybrid seal
wraps real vault keys — this is the one place the post-quantum work is not a
demo), [0038](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)
(key substitution is refused at a choke point enforced by type in Rust),
[0040](decisions/0040-account-model.md) (no request anywhere names an account —
the structural closure of cross-account IDOR),
[0042](decisions/0042-recovery-kit.md) (a paper kit that recovers keys without
giving the server anything),
[0044](decisions/0044-opt-in-cors-allowlist.md) (why CORS here is *not* a CSRF
control) and
[0046](decisions/0046-passkey-protected-local-containers.md) (a second at-rest
factor whose break-glass is that same paper kit — **AND, never OR** — and which
the server cannot see, disable or weaken) and
[0047](decisions/0047-container-parameter-ceiling-and-no-downgrade-ratchet.md)
(the container header is unauthenticated framing, so its KDF work factors are
bounded **before any allocation** — a zero-knowledge relay cannot filter a
hostile blob, which moves every content-validation duty to the client) and
[0048](decisions/0048-authenticated-vault-key-envelopes.md) (delivering a **key**
with an **anonymous** public-key seal let anyone holding the recipient's
*published* key install a vault key of their choosing — and it explains why the
fix authenticates with the **hybrid** key rather than a signature, and why
confidentiality is hybrid while **authenticity is classical X25519 only**) and
[0049](decisions/0049-entry-identity-and-the-mergeable-vault.md) (a vault synced
as whole snapshots was **last-writer-wins**, so a device that never pulled could
destroy another device's 2FA account and both pushes reported success — the fix is
a **2P-Set** merged over **every** op rather than the tip, which is free on the
wire and therefore **retroactive**, and it is the ADR to read for what a hostile
server can do with a **tombstone**) and
[0050](decisions/0050-confirmations-honest-claims-and-the-clock-diagnostic.md)
(the non-cryptographic defects that still lose a user their accounts — a one-click
delete whose stakes **0049 had just raised**, two clients denying **in the
product** that they could print the recovery kit that prevents permanent account
loss, and a clock diagnostic that is ⛔ **a reading and never a correction**; it is
also the one recent phase where **`sigild` was modified**, by exactly one additive
line, and it says so rather than reaching for the usual *"`sigild` gained
nothing"*) and
[0051](decisions/0051-provisioning-bounds-and-qr-ingest.md) (a provisioning URI
from a stranger could install an entry whose code **never changes**, rendered with
an ordinary countdown — a static secret in a rotating costume — and it is the ADR
to read for the rule this project keeps reusing: ⭐ **refusing to ADD is a
different act from refusing to READ**, so the ceiling is ingest-only, has
deliberately **no floor**, and leaves the vault merge ungated on purpose).

**What is real, and what is not.** The cryptography is real and
**unaudited**. `sigild` is a working dev server whose stateful surface is
**`501` by default** — if you find a route answering, something opted in. Four
client surfaces (CLI, webapp, MV3 extension, native desktop) share one container
format and are cross-verified against each other by the interop suites. The
clients are **not uniform**: at rest the CLI and desktop keep secrets in `0600`
plaintext files, the browsers seal everything into `SIGILcli` containers, and
since Phase 58 the **webapp alone** can add a second at-rest factor — a WebAuthn
PRF output mixed into the sealing secret
([0046](decisions/0046-passkey-protected-local-containers.md)). There
are **no mobile clients**, nothing is deployed, no domain is registered, and no
external audit has been performed.

**Where the sharp edges are, in our own words.** Trust-on-first-write ownership;
first-contact TOFU on a hybrid key unless a human compares a safety number;
a recovery kit that must be printed *in advance*, confers full account
control to whoever holds the paper, and (since Phase 58) also unlocks a
passkey-protected browser profile; passkey protection that exists on **one of
four** clients, defends storage but never execution, and is **not retroactive**;
entitlement that is reported and only
optionally enforced; a per-process replay cache; and no key rotation for device
identities. Since Phase 59, add two more: a **hostile container** parked in an
op-log is refused cheaply by every client but **is never removed**, because the
server cannot know it is there
([0047](decisions/0047-container-parameter-ceiling-and-no-downgrade-ratchet.md));
and the no-downgrade ratchet that stops a browser weakening a vault's KDF **does
not cover the CLI's and the desktop's own vault saves**, so *"strength only goes
up"* is true of the browsers and of re-keys and **not globally true of this
system**. Since Phase 60, add one more that cuts across the post-quantum story:
a shared vault key is now wrapped with an **authenticated** hybrid KEM, but that
authentication is a **classical X25519 static-static DH** — ML-KEM has no
static-static analogue — so **confidentiality is hybrid while authenticity is
not**, and a wrap is **implicit, key-confirmed and non-transferable** rather than
a signature ([0048](decisions/0048-authenticated-vault-key-envelopes.md)). Since
Phase 61, add two that come attached to a fix rather than to a feature: a vault's
**remove-set grows without bound** — every deletion writes a tombstone that must be
carried forever, nothing prunes them, and past `sigild`'s **64 KiB** op cap `push`
becomes a permanent **413** with no supported way to shrink the vault (only a 75 %
warning is built); and the merge is correct **only because entries are immutable**,
so **adding an edit would silently break it** unless the edit is expressed as
delete + add with a fresh id — guarded by a source check that makes that decision
loud rather than impossible
([0049](decisions/0049-entry-identity-and-the-mergeable-vault.md)). Since Phase 62,
add three that are about the **product** rather than the cryptography
([0050](decisions/0050-confirmations-honest-claims-and-the-clock-diagnostic.md)):
a delete is now confirmed on every client, but **a confirmation is not an undo** —
a confirmed delete writes a tombstone that propagates and is protected against
resurrection, so it is still permanent, and an undo was rejected on the merits
rather than deferred; the **clock-skew reading is a diagnostic and never a
correction**, an **offline client gets no reading at all** (which is not a report
that its clock is fine), the reading is an unauthenticated plaintext header a
hostile server can lie about, and the desktop's clock UI is **by-eye only** while
the browsers' clock specs run against a **test double**; and two clients had been
telling users **in the product** that they *"cannot print"* a recovery kit — false
since Phase 56 — which is worth reading as a warning about how this project's
in-product claims drift, not only its documents. Since Phase 63
([0051](decisions/0051-provisioning-bounds-and-qr-ingest.md)), add three about
what a **stranger's provisioning payload** can still do: the new bounds are
**ingest-only and not retroactive**, so a vault poisoned before this release keeps
its non-rotating entry (all four clients now *warn* about it, and ⛔ the warning
**reports and never corrects**); the **vault merge is deliberately not gated**, so
a co-owner of a shared vault can introduce such an entry; and `sigil totp
--period N` is deliberately exempt, so the CLI can still create one on purpose.
Add one more that is about reach rather than about us: **QR scanning depends on
`BarcodeDetector`**, which Firefox, Safari and Linux Chromium lack and which is
**secure-context gated** — so a page served over plain HTTP from a LAN address
gets no scanner, and **no CI runner exercises the supported branch**. Each
ADR ends with its own limits, and they are meant to be read as
findings-in-waiting rather than disclaimers.

⚠️ **Two documents in this folder recently asserted a defense that did not
exist** — `threat-model.md` row V and `crypto-spec.md`'s "cannot mint" paragraph,
both describing the vault-key envelope. Neither was stale: both were written
alongside the code and were wrong on the day they were written, because they
described the *intent* of a flow rather than what the primitive underneath it
does. The corrections are recorded **in place, as corrections**, rather than
edited away. Treat that as the reading instruction for everything here.

**Reproduce our claims.** `./scripts/gate.sh` runs every suite in the repo — Go
with `-race` against a throwaway Postgres, four Rust crates, every
cross-component interop suite in `sigil-wasm/test/` (most of which drive real
binaries against a live server), both browser suites, and the end-to-end shell
proofs. It **fails if any test skipped**, prints which tree and commit it gated,
and checks that every suite on disk is actually run by some workflow — the suites
are **enumerated dynamically**, which is why this paragraph no longer quotes a
count. It also runs both **security scanners** (`govulncheck` against the Go
toolchain we *ship*, and `cargo audit --deny warnings` across all four Rust
lockfiles), and verifies that every workflow which boots a real `sigild` is
actually **triggered** by changes to it. If a claim in these documents is not
backed by something that command runs, treat the claim as unproven and tell us.

⚠️ **And read that sentence sceptically, because it has already been wrong.** On
2026-07-30 this gate printed ALL GREEN on a commit whose `security` workflow was
red on two jobs and whose `interop` workflow had been red for several phases —
its coverage was a strict subset of CI's, and every suite is written on macOS and
run on Linux with nothing checking that the two agreed. Both gaps are closed and
the fixes are mutation-proven, but the general lesson stands:
[`engineering-lessons.md`](engineering-lessons.md) is the honest companion to this
paragraph, and **a green signal from our own tooling is a claim like any other**.

**We would rather hear it.** [`../SECURITY.md`](../SECURITY.md) states the scope;
cryptographic findings are explicitly in scope and wanted. An earlier version of
that file discouraged them, which was wrong and is retracted.

---

- [`architecture.md`](architecture.md) — the system shape: the client-side-crypto
  vs. zero-knowledge-server trust boundary and the life-of-one-record data flow
  (the doc to read first after this index).
- [`sprint-72h.md`](sprint-72h.md) — the 72-hour foundation sprint: definition
  of done, critical path, wall-clock gates, and the defer ledger.
- [`threat-model.md`](threat-model.md) — adversary classes and the defense layer
  for each (condensed from the product brief, §29).
- [`crypto-spec.md`](crypto-spec.md) — primitives, the algorithm-suite registry,
  the crypto-agility envelope, the hybrid construction, and the migration plan
  (condensed from the brief, §11/§20/§21).
- [`api.md`](api.md) — `sigild` HTTP reference: the `/healthz`, `/readyz`,
  `/version` probes, the **dev-only, opt-in** opaque-blob vault op-log (default
  `501`, unauthenticated unless one of two opt-in contracts is configured), the
  multi-device auth model, its opt-in **abuse rate limits**, the **account
  model**, the vault-key relay, what a **recovery kit** looks like on the wire,
  the billing routes and their opt-in **entitlement enforcement** (`402` on
  writes only) — all dev-gated and all `501` by default — plus the opt-in
  **browser-origin allowlist** (`SIGILD_CORS_ORIGINS`), which is off by default
  and is deliberately *not* an authentication control. ⚠️ Its status block was
  **corrected in Phase 57**: `sigild` does no cryptography **on vault content**
  and holds no key that can **decrypt a vault**, but it does verify Ed25519
  request signatures, hash-chain ops with SHA-256 and verify webhook HMACs — the
  unqualified "performs no cryptography" it used to open with was false and would
  have scoped its own cryptography out of a review.
- [`deployment.md`](deployment.md) — the (not-yet-applied) `sigild` deployment
  runbook: topology, secrets posture, PQ-TLS nuance, and an honest
  what-is-not-deployable / validation-status accounting.
- [`decisions/`](decisions/README.md) — Architecture Decision Records (the
  load-bearing *why*), Nygard-style and pre-audit.
- [`engineering-lessons.md`](engineering-lessons.md) — **how this project has
  actually failed**: a consolidated record of the mistakes made building it, what
  each cost, and which controls exist because of them. Worth reading before the
  design documents, because almost every serious defect found here was a *green
  signal that meant nothing* rather than a wrong algorithm — and two of the three
  blind spots in the last audit were in tooling written hours earlier.

Every line here is **subject to change**. Substantial parts of the scaffold now
exist and are tested (the crypto core, the CLI, the dev op-log server, four
client surfaces — webapp, MV3 extension, native desktop and the CLI — device
**enrollment**, real per-vault **authorization**, an **account model**, and,
since Phases 53–55, opt-in **abuse bounds**, a printable **recovery kit** and
opt-in **entitlement enforcement** — with Phase 56 bringing the kit and the
payment warnings to **all four** client surfaces, Phase 58 adding an optional
**passkey second factor to the webapp's at-rest seal**, and Phase 59 bounding the
container header's KDF work factors, making a re-seal unable to weaken a vault,
and making the vault schema changeable without data loss — the last two of which
changed **nothing** on the server). But the system as a whole is
**pre-audit and not production-ready**: nothing here is **audited**, every one of
those server-side pieces is **dev-gated and `501` by default**, and the
product-level layer is still missing — an **identity** system (no email, no
password, no operator break-glass; the only recovery is a **paper kit printed in
advance**, and it **cannot be created after the loss**), session/token issuance,
device-key rotation, and mobile.

A fourth full-repo adversarial audit (six independent lenses, each in its own git
worktree, then a triage pass that re-verified every finding) ran against
`ab37e05`. Its verdict is worth reading before these documents: **the code held
up; the verification layer did not.** One genuine server defect came out of it —
a request the server **rejected** still permanently claimed the vault it named
([ADR 0045](decisions/0045-claim-precondition-rejected-writes-never-claim.md)) —
alongside three blind spots in the tooling that was supposed to notice, and a set
of status lines in these very documents that were false. `journal.md` has the
full account.
