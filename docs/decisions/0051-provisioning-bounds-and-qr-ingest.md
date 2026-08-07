# 0051 — Bounds on an untrusted provisioning payload, and the QR door that made them urgent

- **Status:** Accepted (2026-08)
- **Date:** 2026-08-07
- **Builds on:** [0023](0023-totp-hotp-primitive-and-cli-vault.md) (the HOTP/TOTP
  primitive and the encrypted TOTP vault — the feature these bounds guard),
  [0025](0025-totp-import-export.md) and
  [0026](0026-browser-totp-import-export.md) (the `otpauth://` parser and the
  Google Authenticator migration codec, mirrored in Rust and JS — the two
  existing ingest doors), [0024](0024-wasm-totp-vault-and-cross-client-totp.md)
  (the `TotpVault` / `TotpEntry` schema),
  [0047](0047-container-parameter-ceiling-and-no-downgrade-ratchet.md) (**the
  rule this decision reuses**: a ceiling with deliberately no floor, refusing
  before you pay, and bounding what a stranger may *create* rather than what a
  user already *has*), [0049](0049-entry-identity-and-the-mergeable-vault.md)
  (entries are immutable and vaults merge — which is why the merge is an ingest
  door, and why gating it would be data loss),
  [0050](0050-confirmations-honest-claims-and-the-clock-diagnostic.md) (a single
  action must not silently destroy an account — the same reasoning forbids a
  single glance silently creating one).
- **Changes nothing in:** `sigild`. No route, no header, no canonical message, no
  migration, no table, no metric, no dependency, no schema-version bump. `git
  status --short sigild/` is empty for this phase, the wire protocol is
  byte-for-byte what it was, and `sigild` still has exactly one direct Go
  dependency. **No new dependency anywhere** — the QR path is a shell over the
  platform's own `BarcodeDetector`.

---

## Context

### The defect, reproduced before anything was written

`otpauth://` is a provisioning format defined by a stranger's server and handed
to us as text. Until this phase the only bounds on it were `digits ∈ 6..=10` and
`period != 0`. That left `period` a bare `u32`.

```
otpauth://totp/Evil:victim?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Evil&period=4294967295
```

This was **accepted and stored** by every client. A TOTP counter is
`floor(unix_time / period)`, so with `period = 2³²−1` the counter is `0` until
roughly the year 2106. Measured on the shipped code: the entry produced **755224
at t=59, at t=1.9×10⁹ and at t=4×10⁹** — the same six digits, forever.

⭐ **And this is the part that makes it a security defect rather than a bug.** The
entry did not look broken. It rendered in the list with a label, an issuer and an
**ordinary-looking countdown**, indistinguishable from a real second factor. A
user who scans or pastes that URI believes they have enabled 2FA. What they have
is a **static secret wearing the costume of a rotating one**: a single
observation — a shoulder-surf, a screenshot, one intercepted login — stays valid
indefinitely.

> An obviously-broken entry costs the user a retry. An entry that lies about
> rotating costs them the protection they think they have, silently, for as long
> as the account exists.

This repository already knew the trick worked. `desktop/core/tests/cli_interop.rs`
uses exactly this — a `period` so large the counter never advances — to pin a
clock across two processes, and says so in a comment. We used it deliberately as a
test artifice and never asked what happened when a *stranger* asked for it.

### Why now: the QR scanner removes the last reviewer

⭐⭐ **The sentence this phase turns on:**

> **Every existing door to this defect had a human reading the URI. A QR is
> opaque to humans by construction, so it removes the last reviewer.**

Pasting `otpauth://totp/Evil:victim?secret=…&period=4294967295` puts
`period=4294967295` in front of a person's eyes. Almost nobody would notice it —
but the possibility was the only thing standing between the parser and a hostile
payload, and it is a *possibility*, not a control.

A QR code is a bag of bytes with no human-readable surface at all. Point a camera
at a code on a phishing page, or paste a screenshot someone sent you, and the
payload reaches the parser with **no opportunity for review at any point**. The
same is true of the Google Authenticator migration blob, which is base64
protobuf — but that door at least required the user to already be migrating from
a real app.

So the ordering was deliberate: **the parser was hardened before the scanner
shipped.** Adding a frictionless ingest door on top of a parser with no bounds
would have been adding a delivery mechanism to a known defect.

### The second thing a QR changed: what "one payload" can cost

Nothing in the `otpauth-migration://` wire format bounds how many accounts it
declares. The decode loop was `while there are more bytes: push another account`
— an unbounded allocation driven entirely by attacker-supplied input, on a path a
user reaches by pasting an image.

---

## Decision

### 1. Six bounds, single-sourced in `sigil-core`, mirrored once in JS

`libsigil/core/src/totp.rs` gains `validate_provisioning()`,
`validate_provisioning_count()`, `is_unsafe_display_char()`, a
`ProvisioningError` enum, and four constants. `sigil-wasm/totp-migration.mjs`
carries the mirror (`validateProvisioning`, `validateProvisioningCount`,
`isUnsafeDisplayChar`, the same four constants). The CLI and the desktop reach
the Rust one through `sigil_cli::check_provisioning`; both browsers and the QR
scanner reach the JS one. **There is no fourth literal.**

| Bound | Value | Evidence for the number |
|---|---|---|
| `MAX_PERIOD` | **600 s** | Real issuers use 30 s, occasionally 60 s, very rarely 120 s. 600 s is **5× the largest value observed in the wild** and still rotates 144 times a day, which is what makes "one-time" mean anything. Above it a code stops rotating on any human timescale. |
| `MAX_SECRET_BYTES` | **1024 B** | HMAC accepts a key of any length, so this bounds **storage and sync size, not security**. A 1 KiB shared secret is already ~6× the largest real one. |
| `MAX_LABEL_CHARS` | **256 code points** (label and issuer, separately) | Real labels are account names and email addresses. Without it a hostile multi-kilobyte string is sealed into the vault, pushed through the op-log, and re-rendered on every client forever. |
| unsafe display characters | C0/C1 (`U+0000..=U+001F`, `U+007F..=U+009F`) and bidi overrides/isolates (`U+202A..=U+202E`, `U+2066..=U+2069`) | These reorder **surrounding** text, so a crafted label renders inside our own trusted UI as a different issuer's name. ⭐ **Ordinary right-to-left script is untouched** — Arabic and Hebrew letters carry their own direction and need none of these format characters. The suite pins an Arabic issuer+label and a Hebrew label as **accepted**, next to `U+202E` and `U+2066` as **refused**. |
| `digits` | **6..=10** | Pre-existing (`MIN_DIGITS`/`MAX_DIGITS`); moved inside the one gate so every door gets it. |
| `MAX_PROVISIONING_ENTRIES` | **512 per payload** | ⭐ **Chosen against this system's own limit, not against taste.** A vault syncs as one sealed snapshot in one op and `sigild` caps an op body at 64 KiB. A realistic entry (issuer, an email-shaped label, a 32-char base32 secret, a uuid) serializes to ~182 bytes, so a vault stops being pushable somewhere around **360** entries; even a minimally-sized entry runs out near **560**. 512 sits inside that band and far above any human 2FA collection, so it cannot refuse a real migration — while turning "one URI, unbounded accounts" into a bounded allocation. |

The count check is called **inside the decode loop**, not after it. Checking the
finished list means allocating everything a hostile payload asked for and *then*
deciding not to keep it — which is the allocation the bound exists to prevent.
That is ADR 0047's shape: refuse before you pay.

⚠️ **The refusal messages name a bound and a count, never the offending string.**
Echoing attacker-controlled text into a trusted surface is a free UI-spoofing
primitive, which is the very thing the text rules exist to stop. That discipline
is itself asserted in `provisioning-interop.mjs`.

### 2. ⭐⭐ The ceiling is INGEST-ONLY — refusing to ADD is a different act from refusing to READ

This is the load-bearing rule, taken directly from ADR 0047, and everything else
follows from it:

> **Bound what a stranger may CREATE. Never bound what a user already HAS.**

The gate runs at two construction sites in Rust and four in JS — `parse_otpauth_uri` /
`parseOtpauthUri` and `migration_otp_to_entry` / `migrationOtpToEntry` — i.e.
**wherever an entry is built from untrusted text**. Nothing on the read path
calls it. A vault that already contains an out-of-bounds entry:

- **still opens**, unchanged;
- **still generates that entry's codes**, unchanged;
- is **never rewritten** to remove it (entries are immutable — ADR 0049).

Refusing to render an existing entry would delete a working account to punish the
user for a value we let in. That is a strictly worse outcome than the defect: the
user loses access to a real service, and we caused it.

**And there is deliberately NO FLOOR.** There is no minimum secret length, no
minimum period, no minimum digit count. A short secret is a **weak credential
chosen by the service**, not an attack on us; refusing it would lock a user out of
an account they are required to use. Their defect, their risk, their choice. The
suite pins `secret=AA` — two base32 characters — as **accepted**, so a later
"hardening" that adds a floor goes red and has to argue for itself.

⚠️ **This asymmetry is itself mutation-guarded.** A "fix" that moved the ceiling
onto the read path would pass every other assertion in the suite, so
`provisioning-interop.mjs` asserts it directly: a vault holding a hostile entry
must keep generating its codes.

### 3. The read path REPORTS what the ingest gate can no longer prevent

Because the ceiling is not retroactive and (see §4) does not cover the merge, an
entry whose code never rotates can still be in front of a user. Until this phase
every GUI rendered it with an ordinary countdown — which is the product asserting
that the user's second factor is fine when it is not.

`frozen_period_warning(period)` (Rust, `cli/src/lib.rs`) and
`frozenPeriodWarning(period)` (JS, `sigil-wasm/totp-migration.mjs`) return the
warning for such an entry and `None`/`null` for an ordinary one. Both are keyed
off the **same `MAX_PERIOD`** the ingest gate uses, so the two can never disagree
about what "too long" means. It is rendered by **all four clients**: `sigil totp
list` and `sigil totp code` (on **stderr**, so `sigil totp code x | pbcopy` still
pipes exactly the code), the webapp (`data-testid="frozen-warning"`), the
extension (`.frozen`, `role="alert"`) and the desktop (`EntryView::frozen_warning`
→ `desktop/ui/main.js`).

⛔ **It reports and never corrects.** Nothing changes the code, the period or the
entry; nothing hides or refuses it. The text names the only real remedy — remove
it and re-enrol with the service.

⚠️ The desktop was included **not because a finding named it** but because the
same false-by-omission sentence was in three GUIs and a finding that names one
instance of a class is a finding about the class. That is the Phase 62 lesson
([ADR 0050](0050-confirmations-honest-claims-and-the-clock-diagnostic.md) §3)
applied prospectively.

### 4. ⛔ The Phase 61 vault MERGE is an ingest door and is deliberately NOT gated

`merge_vaults` / `mergeVaults` adopts a peer's entries **unchecked**. A co-owner
of a shared vault can push a snapshot containing `period: 4294967295`, and it
lands. This was considered and left open, for two reasons:

1. **It is inside the stated trust model.** Reaching the merge at all requires
   holding the vault key ([0035](0035-device-to-device-vault-sharing.md) /
   [0038](0038-key-pinning-safety-numbers-and-vault-rotation.md)) — a peer you
   deliberately shared with, whose hybrid key you pinned and whose safety number
   you were shown. A peer who can write entries can already write anything. A
   period ceiling is not what stands between you and them.
2. ⛔ **Gating it would be the worse bug, in the exact direction ADR 0049
   exists to repair: refusing to merge an entry is refusing to READ it.** Drop an
   entry at the merge and the next re-seal writes a vault without it, that vault
   is pushed, and the account is gone from **every** device. Data loss caused by a
   validator is precisely the failure Phase 61 was written to fix.

So the door is **disclosed rather than closed**, and the mitigation lives on the
read path where it cannot destroy anything (§3). ⭐ **The decision is pinned in
both languages so a later "hardening" goes red and has to re-argue it:**
`cli/src/lib.rs`'s unit test
`a_merge_adopts_a_peers_out_of_bounds_entry_and_the_read_path_warns_about_it`
asserts **both halves** — the entry survives the merge unchanged **and** the read
path warns — because either alone is the wrong product. Section 8 of
`provisioning-interop.mjs` does the same on the JS side.

### 5. QR ingest — a new SOURCE for a format we already parse, not a new format

`sigil-wasm/qr-scan.mjs` (framework-free, **zero dependencies**, vendored into the
extension by `build.sh`, re-exported by `@sigil/wasm` in **both** `index.mjs` and
`index.d.ts`) turns an image into a **bounded string** and hands that string to
the already-hardened parsers. It adds **no second parser and no second set of
bounds** — a QR is a delivery mechanism, and the gate is where the text is read.

It is a thin shell over the platform's `BarcodeDetector` rather than a decoder we
own, and that was decided on measurement, not taste:

- **A QR decoder is a superlinear DoS over attacker-chosen images.** Measured on
  `rqrr` 0.10.1 (release; the leading pure-Rust decoder, zero `unsafe`): a
  1.74-megapixel image tiled with QR finder patterns — **smaller than a phone
  screenshot** — took **94 seconds** in `detect_grids()`, while a benign
  1.17-megapixel image took **11 milliseconds**. That is ~8,000×, and all of it
  inside one non-interruptible call. A pixel cap bounds **memory, not time**: at a
  fixed 1.1 Mpx the answer is 11 ms or 19 s depending only on content.
- **`BarcodeDetector` parses the hostile image inside the browser's own
  sandboxed, hardened, continuously-patched decoder**, off our thread, in a
  process we do not share with the vault key.

The zero-dependency choice was also the safer one, which is not usually true and
is why it is written down.

Its own bounds: `MAX_IMAGE_BYTES` 8 MiB, `MAX_IMAGE_PIXELS` 40 Mpx (~3× a
12-megapixel phone photo), `MAX_QR_TEXT_LENGTH` 4096 (a QR maxes out at 2,953
bytes). It **refuses ambiguity** — an image containing more than one QR code is an
error naming the count, because silently taking the first is how a user imports
the account they did not mean to and believes they succeeded. A payload that is
not `otpauth://totp/` or `otpauth-migration://` is **never navigated to, never
rendered as a link, never auto-submitted and never echoed back**; the error names
only the scheme, truncated to 16 characters and stripped to `[a-z0-9+.-]`.

⭐ **`scanProvisioningImage` does not touch the vault.** It returns a payload for
the user to **confirm**. ADR 0050 established that a single click must not destroy
an account; the same reasoning forbids a single glance creating one.

### 6. The import-time size warning, on the ceiling we could not lower

`MAX_PROVISIONING_ENTRIES` (512) permits a payload whose sealed vault exceeds
`MAX_OP_BODY_BYTES` (64 KiB). Rather than silently allow that and let the user
discover it as a `413` at push time — with no supported way to shrink a vault
(tombstones are never pruned and there is no `compact`) — every client now calls
the **existing** `op_body_size_warning` / `opBodySizeWarning` at the moment the
vault grows:

- **webapp** — inside `persist()`, the single place the app seals, so every growth
  path (form add, `otpauth://` paste, migration import, QR scan, merge adoption)
  reaches it without any of them remembering to; plus a recompute on **unlock**,
  so a vault that arrived oversized from another client is not silent.
- **extension** — same shape, `persist()` + the unlock path.
- **CLI** — `warn_vault_size()` after `sigil totp import` and `sigil totp add`, on
  **stderr**.

It is the **same function** the push path uses, so the import-time and push-time
thresholds cannot drift.

---

## Consequences

### Positive

- The live defect is closed at every door that reads a stranger's text, in one
  implementation per language, reached by all four clients.
- The QR on-ramp — the thing that made this urgent — shipped **behind** the fix
  rather than in front of it.
- An out-of-bounds entry that is already in someone's vault is now **visible as
  one** on all four clients, where it previously wore an ordinary countdown.
- A bulk import that would produce an unsyncable vault says so **while the user
  still has a choice**, instead of failing later as a `413`.
- `sigild` changed by zero lines; no new dependency anywhere.

### ⛔ Negative / honest limits — state these as loudly as the feature

1. ⚠️ **`sigil totp add --period N` is deliberately ungated, so a CLI user can
   still create a frozen entry on purpose.** The trust boundary drawn here is *the
   text came from somewhere else* — a URI, a migration blob, a scanned QR — **not**
   *an entry is being created*. A number the operator typed lands in a shell
   history a person can review, and the repository's own cross-process
   clock-pinning artifice depends on it. **The consequence is real and is not
   papered over: `sigil totp add --secret … --period 4294967295` still succeeds.**
   The read-path warning (§3) is what a user sees afterwards. A GUI form is a
   different case — that is where a phishing page's "helpful setup instructions"
   land — so **all three** GUI add-forms — webapp, MV3 extension and native desktop — run the gate.
⚠️ **This sentence was FALSE when first written.**

⭐ **AND THE FIX EXPOSED A DESIGN LINE WORTH NAMING, because the obvious placement was
wrong.** The gate was first put in `VaultSession::add_secret_base32` — the desktop core's
library call — which is where it *looks* like it belongs. That **broke this repo's own
documented clock-pinning artifice**: `cli_interop.rs` uses `PINNED_PERIOD = u32::MAX` and
`server_interop.rs` uses `1_600_000_000` so a TOTP counter stays constant across processes,
and both are **integration** tests, external to the crate, so they cannot reach a private
constructor to work around it. Two suites went red.

So the gate sits on the **Tauri command** (`add_secret` in `desktop/src-tauri/src/main.rs`),
via a testable `VaultSession::check_form_provisioning` helper on the core. That placement is
not a workaround — it is the **same line this ADR already drew for the CLI**: the
programmatic API stays open (`sigil totp add --period N`, `add_secret_base32`), and the
**GUI form** is gated. The desktop is a library plus a shell; the shell is the form.

⛔ **The residual, stated rather than discovered later:** a programmatic caller of
`add_secret_base32` can still create a frozen entry. `add_uri` cannot (it runs
`parse_otpauth_uri`), import cannot, and the form cannot.

⚠️ **The desktop's window is rendered by no test** (ADR 0050 limit 5), so the shell's wiring
is held by a **source-structure check** in `merge-guard.mjs` — it proves the command calls
the gate and **nothing** about whether the window shows the refusal. Both layers are
mutation-proven: removing the shell's call turns the guard red, and neutering the helper's
bound turns a core unit test red, each with the mutated tree confirmed to still COMPILE so
the red is the rule rather than a syntax error. It named two of three: the desktop's
`add_secret_base32` built the entry without consulting the ceiling, so the ADR asserted a
policy it implemented in two of three GUI clients. Found by an independent verifier, not by
the build, and fixed by routing the desktop through `sigil_cli::check_provisioning` — the
same library call, no fourth copy of the bounds.
2. ⚠️ **The merge path is not gated** (§4). A co-owner of a shared vault can
   introduce an out-of-bounds entry, and it will be adopted. This is a
   deliberate, pinned decision inside the stated trust model, mitigated by the
   read-path warning and by nothing else.
3. ⚠️ **512 entries can still produce a vault too large to sync.** The ceiling
   bounds **one payload**; it does **not** promise the resulting vault fits in
   `sigild`'s 64 KiB op body. Lowering it to fit would refuse imports that work
   today. There is still **no `compact`**, tombstones still grow without bound
   ([0049](0049-entry-identity-and-the-mergeable-vault.md)), and past the cap the
   only exit is export → fresh vault id, which **prints secrets in the clear**.
4. ⚠️ **The bounds are NOT retroactive**, by design (§2). A vault poisoned before
   this release keeps its entry. Nothing sweeps, migrates or repairs existing
   vaults, and nothing will — the only remedy is the user removing the entry and
   re-enrolling with the service.
5. ⛔ **`BarcodeDetector` is SECURE-CONTEXT GATED, and that is a product state,
   not just a testing note.** Measured on macOS Chromium 149, one browser, one
   session: `about:blank` and `http://<LAN-IP>:port` report
   `isSecureContext=false` → **undefined**; `http://localhost:port`,
   `http://127.0.0.1:port` and `file:///…` report `isSecureContext=true` →
   **present, `qr_code`**. So **a page served over plain HTTP from anything other
   than localhost gets no scanner** — which is exactly the shape of *pointing a
   phone at a dev laptop*, the obvious way someone would try to scan. `qrSupport()`
   is therefore a **runtime** probe, never a build-time one, and the message the
   user sees names **both** causes (browser support *and* origin) rather than only
   the browser brand.
6. ⛔ **`BarcodeDetector` is also absent by browser.** Firefox and Safari do not
   implement it; Linux Chromium (`mcr.microsoft.com/playwright:v1.56.0-noble`) does
   not either. The unsupported branch is a **real rendered state**, not an error
   path, and it tells the user to paste the `otpauth://` link instead — which does
   the same job.
7. ⛔ **No CI runner exercises the SUPPORTED QR branch.** Every workflow here runs
   `ubuntu-latest`, where the API is absent. What CI *does* exercise is the
   **unsupported** branch — which is the branch its users are in, so that is a real
   assertion rather than a skip. The supported branch is covered only by the macOS
   developer gate (`scripts/gate.sh`). **This is a stated coverage boundary.**
8. ⚠️ **No camera.** This phase reads **images** only — pasted screenshot, dropped
   file, file picker. That is deliberate (most real 2FA enrolment happens on the
   same screen displaying the QR, where there is no second camera to point, and
   `paste` needs no permission and no prompt), but it is a real scope limit.
9. ⚠️ **The pixel cap bounds what WE forward, not what the browser transiently
   allocates.** `createImageBitmap` decodes before we can read dimensions, so a
   tiny PNG declaring enormous dimensions is allocated inside the browser's image
   decoder. That is the hardened component we deliberately chose to rely on; the
   alternative was parsing image headers ourselves, i.e. adding the
   attacker-facing parser this design exists to avoid.
10. ⚠️ **`noValidate` has a UX consequence that was not papered over.** Both
    add-forms disable native constraint validation so that **one** control is
    authoritative (an out-of-range period was otherwise swallowed behind a generic
    browser tooltip and our handler never ran — the user was refused without being
    told why, by the browser rather than by us). The cost: in the extension, an
    empty secret now reports *"base32 secret decoded to zero bytes"* rather than
    the browser's own prompt, and with **both** label and secret empty the secret
    message wins over *"label must not be empty"*. A real ordering wrinkle a
    designer might want reversed.
11. ⚠️ **`frozenPeriodWarning` lives in `totp-migration.mjs`, not
    `totp-vault.mjs`**, which reads oddly for a read-path helper. It is forced:
    `totp-migration.mjs` imports `totp-vault.mjs`, so placing it beside
    `MAX_PERIOD` was the only non-circular option.
12. ⚠️ **The Phase 59 `--skip-unsupported` asymmetry is unchanged and now has a
    sibling.** The browsers and the desktop still fail a `--migration` export
    **wholesale** on one non-30 s entry; only the CLI has the escape hatch.
13. ⚠️ **This is a display and resource control, not a cryptographic one.** None
    of these bounds protects a secret. They stop a stranger installing something
    that *looks* like a second factor, and they bound what one payload can cost.
    Everything else about the entry — the secret, the algorithm — is still
    whatever the issuer said.
14. Pre-audit / **UNAUDITED**. Do not store real 2FA secrets in this build.

### Neutral

- ⚠️ **The gate is a MIRROR, and a drift is invisible.** Rust and JS each
  implement it. A divergence does not fail loudly — it produces entries that look
  completely ordinary on every client, with nothing for a human to notice. The
  guard is `sigil-wasm/test/provisioning-interop.mjs`, which drives the **real
  `sigil` binary** and the JS module over **one shared table** of hostile vectors,
  **and pins `600` / `1024` / `256` against golden literals** — because a
  cross-language *equality* check passes a coordinated retune, which is exactly how
  the `"recovery-kit"` label drifted in Phase 57 with every suite green.
- The `TotpVault` / `TotpEntry` schema is **unchanged**; no version bump, no
  migration, no flag day. A vault written by a Phase 63 client is byte-shape
  identical to one written before it.
- `frozen_period_warning` is the CLI library's, reused by the desktop under
  [ADR 0037](0037-desktop-reuses-cli-library-for-protocol.md)'s
  reuse-do-not-reimplement rule — so the desktop window and `sigil totp code` can
  never disagree about what "does not rotate" means.

---

## Verification

- **`sigil-wasm/test/provisioning-interop.mjs`** (new) — the cross-language
  agreement proof. One shared vector table drives the **real `sigil` binary** and
  the JS parser: 13 hostile URIs that must be **refused by both** (the live
  `period=4294967295` defect, one second over the ceiling, period zero, an
  oversized label, an oversized issuer, `U+202E`, `U+2066`, an embedded newline,
  a secret one byte over, `digits=11`, an `otpauth://hotp/` URI, a non-`otpauth`
  URL, a `javascript:` payload) and vectors that must be **accepted by both** so
  the product is not broken to make it safe (an ordinary 30 s account, 60 s,
  120 s, *exactly* the ceiling, an **Arabic** issuer+label, a **Hebrew** label, and
  a two-character secret proving there is no floor). Plus: the bulk-count ceiling
  in the decode loop, the two `frozen*Warning` implementations at the **same**
  boundary (silent at 600, warning at 601) driven behaviourally through the real
  binary, the **merge decision** (§4), the QR-unsupported message in **both** its
  copies naming the secure-origin cause and `localhost`, and the CLI's
  import-time size warning.
- **`web/apps/webapp/tests/provisioning.spec.ts`** (4) and
  **`extension/tests/provisioning.spec.mjs`** (4) — the gate through the **real
  shipping UI**, not the module: a frozen entry is refused with an error naming
  *"does not rotate"* and *600*, zero rows are added **and the sealed container is
  byte-identical to before** (DOM absence is not the claim); the ceiling itself is
  still accepted and the stored vault, **decrypted in the test process**, carries
  `period: 600`; an already-frozen entry renders its warning; a 512-account import
  warns, and the warning is proven **arithmetically true** by measuring the
  container the app actually wrote.
- **`web/apps/webapp/tests/qr.spec.ts`** (8) and **`extension/tests/qr.spec.mjs`**
  (5) — the QR path in a real browser / a real unpacked extension: the panel tells
  the truth about what this browser can do; a scanned account lands **only after
  confirm** and nothing is written before it; the paste path; a frozen-period QR is
  refused and stores nothing; a label that would render as another issuer is
  refused; a `javascript:`-carrying QR is refused, never opened and never echoed;
  a multi-code image is refused rather than silently picking one; a scanned Google
  Authenticator export imports every account it carries.
- **`cli/src/lib.rs`** unit test
  `a_merge_adopts_a_peers_out_of_bounds_entry_and_the_read_path_warns_about_it`,
  and **`desktop/core/src/lib.rs`**
  `an_entry_whose_code_never_rotates_is_reported_as_such_and_still_generates`.
- **Mutation-proven, eight controls**, each written green → control neutered with
  the mutated line printed and the mutant build/parse-checked → **confirmed red**
  → restored with a zero marker grep and re-run green: the webapp add-form gate,
  the extension add-form gate, the QR unsupported message, both webapp size-warning
  call sites, both extension size-warning call sites, `frozenPeriodWarning`, the
  Rust and JS merge adoption, the CLI's `warn_vault_size`, and the desktop's
  `frozen_warning`.

---

## Alternatives considered

**Refuse an out-of-bounds entry on the READ path too, so existing vaults are
repaired.** Rejected — this is the single most important call in the ADR. It
would delete a user's working account to punish them for a value we let in, and
under Phase 61 the deletion would **propagate**: the next re-seal writes a vault
without the entry and pushes it, removing it from every device. That is the exact
data-loss shape ADR 0049 was written to repair, arriving this time as a security
feature.

**Add a floor as well as a ceiling** (minimum secret length, minimum period).
Rejected — a weak credential is chosen by the *service*, and refusing it locks a
user out of an account they must use. ADR 0047 made the same call for KDF work
factors: a low work factor is a **weak** container, not a **dangerous** one.

**Gate the merge.** Rejected on the merits; see §4 and limitation 2. Pinned in
both languages so it must be re-argued rather than quietly reversed.

**Gate `sigil totp add --period`.** Rejected; see limitation 1. The boundary is
provenance, not the act of creation.

**Own the QR decoder** (`rqrr` in the wasm, or a hand-rolled one). Rejected on a
measurement: 94 s vs 11 ms on images of comparable size, all inside one
non-interruptible call, which would require shipping a Worker with a watchdog to
survive. Delegating to `BarcodeDetector` costs us Firefox, Safari, Linux Chromium
and every non-secure origin — limitations 5–7 — and that price is paid openly in
the UI rather than hidden.

**A camera scanner.** Deferred, not rejected. Image ingest covers the common
motion (the enrolment QR is usually on the same screen) with no permission prompt
and no secure-context camera grant.

**Validate at the UI layer instead of in the parser.** Rejected — that is one
gate per form per client, and the QR door proves why: a new *source* must inherit
the rule automatically. The gate lives where untrusted text becomes an entry, so
there is exactly one place to get right and a new door cannot get a weaker rule by
accident.
