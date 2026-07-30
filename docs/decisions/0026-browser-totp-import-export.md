# 0026 — Browser TOTP import/export (mirror the migration codec in JS)

- **Status:** Accepted — 2026-07.

## Context

The `sigil` CLI can migrate 2FA **in** (Google Authenticator bulk import) and back
**out** ([ADR 0025](0025-totp-import-export.md)), and the browser/wasm client
already holds an encrypted TOTP vault and generates codes cross-client with the CLI
through the opaque op-log ([ADR 0024](0024-wasm-totp-vault-and-cross-client-totp.md)).
But the two clients were not at parity: the browser could add secrets only one at a
time (a base32 secret in the demo) and had **no** import-from-Google-Authenticator
and **no** export path. A user's 2FA overwhelmingly already lives in Google
Authenticator, so a browser client you cannot migrate *into* — or *out of* — is as
much an adoption/trust liability there as it was in the CLI.

The friction is the same as ADR 0025: the Google Authenticator bulk-export URI
(`otpauth-migration://offline?data=<BASE64>`) wraps a **protobuf** `MigrationPayload`,
and the plain single-account form is an `otpauth://totp/…` URI. The CLI solved this
with a **hand-rolled, dependency-free** proto3 codec in
[`cli/src/migration.rs`](../../cli/src/migration.rs) (varint + length-delimited wire
types only, no protobuf crate) plus the `otpauth://` parse/build in
[`cli/src/lib.rs`](../../cli/src/lib.rs). The question was how to give the browser the
**same** import/export without divergence.

Two options: (a) compile the Rust codec to wasm and call it from JS, or (b) mirror
the codec in JS — matching how this repo already handles cross-client formats. The
`SIGILcli` / `SIGILhyb` container constants ([ADR 0020](0020-shared-client-container-format.md),
[ADR 0021](0021-wasm-hybrid-public-key-encryption.md)) and the `TotpVault` /
`TotpEntry` vault JSON ([ADR 0024](0024-wasm-totp-vault-and-cross-client-totp.md)) are
already **mirrored, not shared** — small format/marshalling logic kept in both
`cli/src/lib.rs` and a framework-free `.mjs`, pinned by a Node cross-tool test rather
than a shared crate. The migration codec is more of the same: pure byte-shuffling
with no crypto, exercised by the demo's JS, where a wasm round-trip through the core
would add build surface and marshalling for no crypto benefit.

## Decision

**Mirror the migration + `otpauth://` codec in JavaScript
([`sigil-wasm/totp-migration.mjs`](../../sigil-wasm/totp-migration.mjs)) rather than
sharing the Rust one via wasm, and prove agreement with a Node CLI↔JS cross-tool
test.** This gives the browser client full TOTP import/export at parity with the CLI.

- **JS codec — [`sigil-wasm/totp-migration.mjs`](../../sigil-wasm/totp-migration.mjs).**
  A framework-free, dependency-free ESM module that is a line-for-line mirror of
  `cli/src/migration.rs` (+ the `otpauth://` parse/build in `cli/src/lib.rs`). It
  hand-rolls the same two proto3 wire types (varint = 0, length-delimited = 2) — no
  protobuf library — with the identical schema, the same 10-byte varint cap and
  bounds-checked lengths (so truncated/hostile input throws rather than overruns), and
  the same unknown-field skipping. Its public surface is `decodeMigrationUri` /
  `encodeMigrationUri` (the `otpauth-migration://` bulk form), `parseOtpauthUri` /
  `buildOtpauthUri` (the single-account form), and `base32Encode` (the inverse of
  `totp-vault.mjs`'s `base32Decode`). It emits/consumes the same mirrored vault
  `TotpEntry` shape, so imported accounts drop straight into the existing vault.
- **Demo wiring.** The browser `demo/` (`demo/index.html` + `demo/main.js`) gains
  import (paste an `otpauth-migration://` or `otpauth://` URI) and export (each entry
  as `otpauth://`, or one combined `otpauth-migration://` URI) over those functions,
  matching `sigil totp import` / `sigil totp export`.
- **Cross-tool agreement test —
  [`sigil-wasm/test/migration-interop.mjs`](../../sigil-wasm/test/migration-interop.mjs).**
  A pure codec-agreement proof (no server, no network) that builds the real `sigil`
  CLI and checks the JS and Rust codecs are wire-compatible **both ways**, three ways
  total: **GOLDEN** — the canonical documented Google Authenticator example URI
  decodes in JS to secret base32 `JBSWY3DPEHPK3PXP`, name `Example:alice@google.com`,
  issuer `Example`, sha1, 6 digits (the same golden vector the CLI's own Rust test
  asserts); **RUST→JS** — `sigil totp export --migration` output decodes in JS to the
  accounts the CLI stored (names/algorithms/digits + every secret base32 equal to the
  CLI's own `otpauth://` export); and **JS→RUST** — a JS-`encodeMigrationUri` URI is
  accepted by `sigil totp import` and confirmed by `totp list` + the CLI's `otpauth://`
  export carrying the exact secret bytes.
- **No vault-schema or format change.** Import/export is pure translation at the edge,
  exactly as in ADR 0025; the `TotpVault` / `TotpEntry` JSON and the `SIGILcli`
  container are untouched.

## Consequences

- **Both clients now have full TOTP import/export.** The browser reaches parity with
  the CLI: users can migrate their 2FA **in** from Google Authenticator and back
  **out**, on either client, with no lock-in.
- **The migration codec now lives in TWO places — Rust (`cli/src/migration.rs`) and
  JS (`sigil-wasm/totp-migration.mjs`) — kept in sync by the cross-tool test.** This
  is the deliberate, repo-consistent trade (same as the container and vault mirrors):
  no shared crate / wasm bridge, at the cost of a hand-maintained second copy. The
  `migration-interop.mjs` CLI↔JS agreement test is the guard that keeps them from
  drifting; if one side changes the wire behavior, it fails.
- **Export reveals secrets in the clear — by nature.** As in ADR 0025, an OTP export
  *is* plaintext provisioning material (base32 secrets / raw key bytes); there is no
  way to export usable secrets without exposing them. The demo export path surfaces
  them behind a warning, by design.
- **Still pre-audit / UNAUDITED / dev-only.** This is convenience over the same
  unaudited building blocks; **do not import or export real 2FA secrets in this
  build.** Public copy still obeys
  [`../../web/apps/marketing/MARKETING-CLAIMS.md`](../../web/apps/marketing/MARKETING-CLAIMS.md).

## The JS mirror carried the same two defects — and `decodeMigrationUri` now returns an object (added Phase 59, 2026-07-30)

Per this repo's addendum rule the text above is left untouched; this section
records only what changed.

**The mirror worked exactly as designed, which is the point.** Both defects fixed
in [ADR 0025's addendum](0025-totp-import-export.md) were present here too,
byte-for-byte, because this module is a faithful mirror of `cli/src/migration.rs`.
That is the cost side of the mirror decision: a defect in the original is a defect
in the copy, and the cross-tool test proved they *agreed* — it could not tell that
what they agreed on was wrong.

- **The batch framing** (`batch_size` / `batch_index` / `batch_id`) was consumed
  and discarded here too, so a browser import of the first QR of a three-QR export
  added a third of the accounts and said `Imported N.`
- **`entryToMigrationOtp` dropped the period**, so a 60 s entry was exported as if
  it were 30 s and the receiving app computed different codes from the same secret.

Both now match the Rust side exactly, including the wording of the batch note and
the `is_final_batch` / `finalBatch` distinction that stops a *finished* multi-QR
import being announced as incomplete.

### ⚠️ A breaking change to this module's own API

```js
// before
const entries = decodeMigrationUri(uri);          // Array<TotpEntry>

// after
const batch   = decodeMigrationUri(uri);          // { entries, version, batchSize,
                                                  //   batchIndex, batchId, complete,
                                                  //   finalBatch, batchNote }
```

⭐ **Deliberate, and chosen over an optional out-parameter or a second function.**
A caller that ignores the framing is exactly the bug, so the shape makes ignoring
it *visible* at the call site rather than possible by omission. Every caller in
this repo was updated in the same change: the webapp, the MV3 extension (through
its vendored copy) and the `sigil-wasm/demo/`. There is no published package here,
so no external consumer exists — the change is recorded because the next person to
read `totp-migration.mjs` will find its signature different from every other
decoder in the file.

`migrationBatchIsComplete`, `migrationBatchIsFinal` and `migrationBatchNote` are
also exported for callers that decode a payload themselves.

### ⚠️ Honest limits

- **The mirror is still a mirror.** The batch note text, the one-based rendering of
  the zero-based wire `batch_index`, and the period refusal now exist in **both**
  Rust and JS and **must stay in step**.
  `sigil-wasm/test/schema-interop.mjs` is the guard, and it drives the **real
  `sigil` binary** — but a mirror that drifts still does not fail loudly on its
  own.
- **No `--skip-unsupported` equivalent.** The browser clients call
  `encodeMigrationUri(vault.entries)` over the whole vault, so a single
  unrepresentable entry now makes the migration export throw **wholesale**. Better
  than emitting a wrong one; still a regression in usability that these clients
  have not answered.
- **The browser export still reveals secrets in the clear**, unchanged and by
  design.
