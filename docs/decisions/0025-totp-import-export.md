# 0025 — TOTP import/export (Google Authenticator migration + `otpauth://`)

- **Status:** Accepted — 2026-07.

## Context

The CLI's encrypted TOTP vault ([ADR 0023](0023-totp-hotp-primitive-and-cli-vault.md))
can generate 2FA codes, but until now the only way to *populate* it was one
account at a time (`totp add --secret <BASE32>` or a single `otpauth://` URI), and
there was **no way to get secrets back out**. Two product realities make that
insufficient:

1. **Adoption needs bulk import.** A new user's 2FA already lives somewhere — most
   commonly **Google Authenticator**, which exports its accounts as a single
   `otpauth-migration://offline?data=<BASE64>` URI (usually shown as a QR code)
   wrapping a **protobuf** `MigrationPayload`. Retyping dozens of base32 secrets by
   hand is a non-starter; an authenticator users cannot migrate *into* will not be
   adopted.
2. **Trust needs export / no lock-in.** A credible authenticator must let users
   take their secrets **out** — to another app, to a backup, or simply to leave.
   An account store you cannot escape is a liability, not a feature.

The friction is the migration format: `otpauth-migration://` is a protobuf message,
and the obvious way to parse protobuf is to pull in a protobuf crate (and usually a
`build.rs` codegen step). That is a meaningful dependency and build-complexity cost
for a *demo* CLI, and it cuts against the same "keep the audit-bound surface small
and dependency-lean" discipline that put every crypto primitive on caller-supplied
entropy and kept the core `getrandom`-free.

## Decision

**Support the Google Authenticator `otpauth-migration://` protobuf format with a
hand-rolled, dependency-free codec — plus plain `otpauth://` — and add matching
`totp import` / `totp export` CLI subcommands, without changing the vault schema.**

- **Hand-rolled protobuf codec — [`cli/src/migration.rs`](../../cli/src/migration.rs).**
  Rather than add a protobuf crate, the module implements just the two proto3 wire
  types the format uses (varint = 0, length-delimited = 2), mirroring how the base32
  codec was hand-rolled elsewhere in this crate. `decode_migration_payload` /
  `encode_migration_payload` parse and render the `MigrationPayload` / `OtpParameters`
  messages into `MigrationOtp` records that hold the **raw** enum integers, and
  `decode_migration_uri` / `encode_migration_uri` wrap the base64 + scheme layer
  (decode tolerates standard/URL-safe alphabets, with or without padding). The
  varint reader is capped at 10 bytes and every length is bounds-checked, so
  truncated or hostile input yields a clear `CliError::Totp`, never a panic; unknown
  fields are skipped by wire type for forward compatibility. The semantic mapping to
  the crate's TOTP model lives in the separate `migration_otp_to_entry` /
  `entry_to_migration_otp` converters, so the codec stays schema-agnostic and
  independently testable.
- **CLI surface — [`cli/src/main.rs`](../../cli/src/main.rs).** `sigil totp import
  <ARG>` accepts an `otpauth-migration://` URI (bulk), a single `otpauth://` URI, or
  a path to a file with one URI per line; duplicate-label entries (already in the
  vault) are skipped, not overwritten, and the vault is re-sealed only if at least
  one entry was actually imported. `sigil totp export [<label>]` prints each selected
  entry as an `otpauth://` URI, or — with `--migration` — one combined
  `otpauth-migration://` URI, to stdout or a `0600` `--out <file>`.
- **The vault schema is NOT changed.** Import/export is pure translation at the
  edges: it reads and writes the existing `TotpVault` / `TotpEntry` JSON sealed in
  the same `SIGILcli` container, so the browser mirror
  ([ADR 0024](0024-wasm-totp-vault-and-cross-client-totp.md)) stays byte-compatible
  and no new at-rest format is introduced.
- **HOTP entries are warned-and-skipped, not errored.** A `MigrationPayload` may
  carry counter-based **HOTP** accounts, but the vault stores period-based **TOTP**
  only (and its schema is deliberately not extended). Such entries map to
  `ImportedOtp::SkippedHotp`, which the importer counts and warns about while
  continuing — a bulk import of many accounts is never aborted by one unsupported
  entry. MD5 / unspecified algorithms and out-of-range digit counts are likewise
  rejected per entry, not fatally.

## Consequences

- **Users can migrate in and out.** The single most common on-ramp (Google
  Authenticator's QR/migration export) works, and users are not locked in — they can
  round-trip their secrets back to `otpauth://` or a combined migration URI.
- **A small, hand-maintained protobuf decoder is now part of the CLI.** It is
  verified two ways: a **golden vector** — the canonical, documented Google
  Authenticator migration example decoding to its known secret / name / issuer /
  algorithm / digits / type — and an **encode → decode round-trip** (and a
  `TotpEntry → MigrationOtp → bytes → back` round-trip), plus truncation and
  unknown-field tests. It adds **no new dependency** and no codegen step, consistent
  with the crate's dependency-lean posture; the cost is that the schema is
  hand-maintained rather than generated.
- **Export reveals secrets in the clear — by nature.** An OTP export *is* the
  plaintext provisioning material (base32 secrets / raw key bytes); there is no way
  to export usable secrets without exposing them. The export path prints a **loud
  stderr warning** first and can write to a `0600` file, but the secrets are in the
  clear by design. This is called out honestly rather than hidden.
- **The vault format and the browser mirror are untouched.** Because import/export
  only translates at the boundary, [ADR 0024](0024-wasm-totp-vault-and-cross-client-totp.md)'s
  mirrored `TotpVault` / `TotpEntry` schema and the cross-client sync story are
  unaffected.
- **Still pre-audit / UNAUDITED / dev-only.** This is a convenience over the same
  unaudited building blocks; **do not import or export real 2FA secrets in this
  build.** Public copy still obeys
  [`../../web/apps/marketing/MARKETING-CLAIMS.md`](../../web/apps/marketing/MARKETING-CLAIMS.md).

## Two things this feature was saying that were not true (added Phase 59, 2026-07-30)

Per this repo's addendum rule the text above is left untouched; this section
records only what changed.

Both defects share one root cause — **a codec that discarded what it did not use**
— and both landed in the one feature whose entire purpose is *not losing
accounts*.

### 1. ⛔ A multi-QR import reported plain success while carrying a fraction of the export

Google Authenticator splits a large export across **several QR codes**. Each is a
complete, independently-decodable `MigrationPayload` carrying `batch_size` /
`batch_index` / `batch_id`, with the accounts **divided between them**. This codec
consumed those three fields and threw them away, so scanning the first QR of a
three-QR export imported **a third of the accounts** and printed `imported N`
with no warning at all. The users it hits hardest are the ones with the most
accounts — the only ones for whom the export is multi-QR in the first place.

`decode_migration_payload` / `decode_migration_uri` now return a
**`MigrationBatch`** carrying the framing, with `is_complete()`, `is_final_batch()`
and a human-readable `batch_note()`. `sigil totp import` prints the note and a
header chosen by whether anything is **actually outstanding**.

⭐ **`is_final_batch()` is not a nicety.** The first cut told a user importing
**batch 2 of 2** that *"0 more QR code(s) must be imported — this import is
PARTIAL"* — i.e. it told someone who had just finished that they had not. **A
warning that cries wolf is one the next user ignores when it is real.** The final
batch is still *named* (this client keeps no cross-invocation state and genuinely
cannot know whether the earlier QRs were imported) but it is not called
incomplete.

### 2. ⛔ A `--migration` export of a non-30-second entry was a silent lie

The migration wire format has **no period field** — Google Authenticator TOTP is
always 30 s. The original text recorded this as *"the entry's `period` is NOT
representable in the format and is dropped"*. In practice that meant a 60 s entry
was exported **as if it were 30 s**, and the receiving app then computed
**different codes from the same secret**: an account that simply stops working,
delivered as a successful export.

`entry_to_migration_otp` now **refuses** such an entry, naming the label, the
period, and the plain `otpauth://` export that carries the field faithfully.

⭐ **Refusal is the default, and a new opt-in makes it survivable.** A silently
partial export of your 2FA is worse than a failed one — but refusing outright made
**one** unusual account cost the user the entire bulk-export path, which is the
anti-lock-in feature. `sigil totp export --migration --skip-unsupported` exports
the rest and names each entry it left out, **individually, with the reason, on
stderr** so it survives a pipe to a file; the summary line then says `PARTIAL` and
how many were skipped. Using it without `--migration` is an error, because the
plain export can represent everything.

### ⚠️ Honest limits

- **`--skip-unsupported` exists only in the CLI.** The webapp, the MV3 extension
  and the desktop call the encoder over the whole vault, so for them one 60 s entry
  now makes the migration export fail **wholesale** where it previously produced a
  wrong one. Right direction; unanswered usability regression.
- **The import is still stateless.** Nothing correlates `batch_id` across
  invocations, so the client cannot tell you that batches 1 and 3 arrived and 2 did
  not. The note says so rather than implying otherwise.
- **`export` still prints secrets in the clear** — unchanged, by design, behind the
  same loud warning.
