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
</content>
</invoke>
