# 0024 — Browser TOTP vault and cross-client TOTP through the op-log

- **Status:** Accepted — 2026-07.

## Context

The authenticator function itself landed in
[ADR 0023](0023-totp-hotp-primitive-and-cli-vault.md): a wasm-pure RFC 4226 /
RFC 6238 OTP primitive in `sigil-core` and an encrypted `sigil totp` vault in
the native CLI. But that feature only worked *at the command line*. The client
column (`sigil-wasm`) could seal/open the shared `SIGILcli` container
([ADR 0020](0020-shared-client-container-format.md)), do hybrid public-key
encryption ([ADR 0021](0021-wasm-hybrid-public-key-encryption.md)), and
push/pull opaque containers to the dev op-log
([ADR 0022](0022-wasm-client-server-sync-loop.md)) — but it could **not
generate a 2FA code**. The authenticator, the actual product feature, did not
exist in the browser.

The goal of this phase was to finish that feature in the browser and, more
importantly, to **prove it works cross-client**: a TOTP secret added by one
client and synced through the opaque, zero-knowledge op-log must yield the
*same* code on the other client. That is the first end-to-end product feature
spanning two clients and the server.

Two constraints carried over:

1. **The wasm crate must stay `getrandom`-free** and add no crypto of its own
   ([ADR 0019](0019-wasm-client-bindings.md)). The OTP math already lives in
   the core; the binding must only marshal bytes. TOTP is defined over "current
   Unix time", but neither the core nor the binding may read a clock
   ([ADR 0007](0007-caller-supplied-entropy-in-core.md)).
2. **The vault format is a mirrored, not shared, contract.** The CLI's
   `TotpVault` / `TotpEntry` JSON is a Rust `serde` type in `cli/src/lib.rs`;
   the browser is JavaScript. There is no shared crate for the inner vault JSON,
   exactly as the `SIGILcli` / `SIGILhyb` container constants are mirrored, not
   shared. A drift in the JSON shape silently breaks cross-client interop.

## Decision

**Expose the core OTP primitive through `wasm-bindgen` with JS-supplied time,
and mirror the CLI's vault JSON in a small framework-free ESM module that reuses
the existing sealed container and op-log sync.**

- **Primitive exports — [`sigil-wasm/src/lib.rs`](../../sigil-wasm/src/lib.rs).**
  Add three `#[wasm_bindgen]` functions over `sigil-core`:
  `totp(key, unix_time, period, t0, digits, algorithm)`,
  `hotp(key, counter, digits, algorithm)`, and `format_code(code, digits)`.
  **`unix_time` / `t0` / `counter` arrive as JS Numbers (`f64`)** — JS has no
  native `u64` — validated to non-negative integers before the `u64` cast, so
  the JS caller supplies the clock and the binding reads none. `algorithm` is a
  lowercase string (`"sha1"` default, `"sha256"`, `"sha512"`) mapped by
  `otp_algorithm_from_str`, mirroring the CLI's `totp_algorithm_from_str`, so
  both clients accept the same `algorithm` JSON field. TOTP/HOTP draw no
  entropy, so the crate stays `getrandom`-free. The RFC 4226 App D / RFC 6238
  App B known-answer vectors are asserted **through the `f64`/string wrappers**
  as native `#[cfg(test)]` tests, proving the JS-facing contract independent of
  any clock.
- **Vault module — [`sigil-wasm/totp-vault.mjs`](../../sigil-wasm/totp-vault.mjs).**
  A dependency-free ESM module (runs in Node and the browser) that reads and
  writes the **same sealed `SIGILcli` TOTP vault the CLI uses**: `openVault` →
  `wasm.open_container`, `sealVault` → `wasm.seal_to_container`, `codeForEntry`
  → `wasm.totp` + `wasm.format_code` (with `t0 = 0`, the caller passing
  `Math.floor(Date.now()/1000)`), plus `addEntry` / `newVault` and a
  `base32Decode` for adding a provisioning secret. It performs **no crypto of
  its own** — it hands bytes to the wasm binding. The inner **`TotpVault` /
  `TotpEntry` JSON schema is MIRRORED from `cli/src/lib.rs`** (version `1`;
  `label` / optional `issuer` omitted when absent / `secret` as **standard
  base64 of the raw key bytes** / lowercase `algorithm` / `digits` / `period`),
  with a header comment tying it to that file and demanding it stay in sync.
- **Reuse the sealed vault and the op-log, add nothing to the server.** Because
  a TOTP vault is just another opaque `SIGILcli` container, it rides the
  existing `sync.mjs` push/pull transport ([ADR 0022](0022-wasm-client-server-sync-loop.md))
  unchanged — the secret syncs E2EE through the zero-knowledge op-log with **no
  server change**. The browser `demo/` gains a **TOTP authenticator vault**
  section (add a base32 secret, live per-entry codes, Seal→Push / Pull→Open the
  vault).

## Consequences

- **The authenticator now works in the browser and cross-client.** A secret
  added by `sigil totp add`, synced through the opaque op-log, is decrypted by
  `openVault` and turned into the **same** RFC-correct code by `codeForEntry` in
  the browser (and vice versa). This is the **first end-to-end product feature
  proven working cross-client** (CLI ↔ browser) through the server.
- **The vault JSON schema is now duplicated `cli/src/lib.rs` ↔ `totp-vault.mjs`.**
  Like the container-format constants, it is mirrored, not shared. The guard is
  a header sync note **plus** a live cross-client interop test
  ([`sigil-wasm/test/totp-interop.mjs`](../../sigil-wasm/test/totp-interop.mjs)):
  it builds `sigild` + the real CLI, boots a live sigild
  (`SIGILD_ENABLE_DEV_OPS=1`, in-memory, no auth), asserts the wasm TOTP KAT
  (RFC 6238 App B, T=59, sha1/256/512), then has the CLI add a secret → push →
  the browser pull → `openVault` → `codeForEntry(T=59)` equal **both** the RFC
  vector `94287082` **and** an independent from-scratch Node HMAC-SHA-1 TOTP,
  and checks the server returned the pushed bytes **verbatim** (opaque). Any
  drift in the JSON shape (renamed field, wrong casing, base32-vs-base64 secret)
  fails here.
- **The no-clock / no-RNG invariants hold.** `totp`/`hotp` take time/counter as
  arguments; the binding validates the `f64` and casts, reading no clock and
  drawing no entropy, so both `libsigil/Cargo.lock` and `sigil-wasm/Cargo.lock`
  stay `getrandom`==0 ([ADR 0007](0007-caller-supplied-entropy-in-core.md),
  [ADR 0019](0019-wasm-client-bindings.md)).
- **Still pre-audit / UNAUDITED / dev-only.** The OTP math is RFC-vector-checked
  and the sync is the same opaque dev op-log — but the build is unaudited, the
  transport is dev / localhost / plain-HTTP / no-auth, and the client still only
  *generates* codes (verification, constant-time compare, and zeroization are
  left to callers). **Do not store real 2FA secrets in this build.** This is not
  the product's account / key-management / sync model. Public copy still obeys
  [`../../web/apps/marketing/MARKETING-CLAIMS.md`](../../web/apps/marketing/MARKETING-CLAIMS.md).

## The mirrored schema is now forward-compatible: unknown fields survive, and `min_reader_version` is a separate knob (added Phase 59, 2026-07-30)

Per this repo's addendum rule the text above is left untouched; this section
records only what changed.

**The mirror decision was right; its two rules were not.** This ADR mirrors
`TotpVault` / `TotpEntry` between `cli/src/lib.rs` and
`sigil-wasm/totp-vault.mjs`, and the schema is now read by **four** clients plus a
printed recovery kit. Two rules made it impossible to evolve:

- **`version != 1` was refused outright**, so *any* addition was a flag day —
  every client had to ship before any client could write the new field; and
- **neither side preserved fields it did not know.** `serde` dropped them on the
  next serialize and the JS clients rebuilt `{ version, entries }` by hand. On a
  sync path where **the oldest writer wins**, an old client that merely *opened and
  re-sealed* a vault **deleted a newer client's data** and pushed the stripped copy
  over it.

There was no third option: either the schema could never change, or changing it
meant silent data loss for anyone not yet upgraded.

[ADR 0047](0047-container-parameter-ceiling-and-no-downgrade-ratchet.md) adds,
additively:

1. **`extra` on both structs** (`#[serde(flatten)]` in Rust, an explicit
   rest-spread plus a new `cloneVault()` in JS), so unknown fields round-trip
   verbatim at **vault and entry level**. ⚠️ **This is easy to defeat by
   accident** — any code that rebuilds the object field-by-field throws it away
   again, which is exactly what both browser clients' `withVault` helpers were
   doing.
2. **`min_reader_version`**, separate from `version`. `version` says *what wrote
   this*; `min_reader_version` says *what a reader must understand*. Refuse iff
   `(min_reader_version ?? version) > TOTP_VAULT_READER_VERSION`. An additive
   future vault opens and round-trips losslessly; an incompatible one is refused
   **precisely**, naming the version needed. ⭐ It **fails closed** when the field
   is absent.
3. A stable per-entry **`uuid`** (RFC 4122 v4 from caller-supplied entropy on both
   sides, per [0007](0007-caller-supplied-entropy-in-core.md)). ⚠️ **Nothing keys
   off it yet** — every lookup is still by `label`, deliberately.

**What is unchanged:** the mirror itself (there is still no shared crate for this
schema), the field names and casing, the base64-of-raw-bytes `secret`, the
lowercase algorithm strings, and the rule that a drift between the two sides does
not fail loudly. ⭐ **The guard is stronger, though:** the new
`sigil-wasm/test/schema-interop.mjs` drives the **real `sigil` binary** as the Rust
half, and a Playwright spec in each browser client now proves the property
**through the real UI** — because a verifier reverted the app-level half of this
fix and the whole gate stayed green.

⚠️ **`extra` preserves bytes, not semantics.** An old client can round-trip a field
it does not understand while behaving inconsistently with it.

---

## Addendum (2026-07-31, Phase 61) — the schema gained a remove-set, and `uuid` became load-bearing

Recorded by [0049](0049-entry-identity-and-the-mergeable-vault.md). The mirrored
`TotpVault` / `TotpEntry` JSON changes in two ways, both **purely additive**:

1. **`tombstones`** — a top-level array, the remove-set of the 2P-Set that makes a
   vault mergeable. `Tombstone { uuid, deleted_at?, …unknown }`. ⚠️ **It is
   OMITTED when empty** on both sides, so a client that has never deleted anything
   writes byte-for-byte the shape it always did.
2. **`uuid` stopped being dead weight.** This ADR's previous addendum said
   *"nothing keys off it yet — every lookup is still by `label`, deliberately"*.
   That is now false, and deliberately so: **the merge keys on `uuid`**, and an
   entry that predates the field gets a **deterministic, content-derived** id so
   that two devices holding the same old vault agree without communicating.

⭐ **The mirror did NOT grow a third copy of anything hard.** The id derivation
lives in `sigil-core` (`entry_id.rs`) and the browsers reach the same bytes through
a one-line wasm shell — it is **not** mirrored, because unlike a format constant a
drift in a decision procedure fails *silently*, producing a vault that opens
everywhere and merely duplicates or mis-suppresses entries. What **is** mirrored is
the merge itself (`merge_vaults` ↔ `mergeVaults`), and both sides must sort JSON
keys identically (`serde_json::Value` is a `BTreeMap`; JS uses an explicit
`sortKeysDeep`) or the two clients could pick different winners for the same
conflict and never converge.

⚠️ **`version` is still 1 and `min_reader_version` is still unset**, so a v1 reader
opens a merged vault. With this ADR's `extra` preservation it round-trips
`tombstones` it does not understand; **a client older than
[0047](0047-container-parameter-ceiling-and-no-downgrade-ratchet.md) strips them**,
resurrecting every entry they suppressed. See limitation 4 of
[0049](0049-entry-identity-and-the-mergeable-vault.md).

⛔ **The schema is now correct only while entries are IMMUTABLE.** There is no
revision field and no clock, by design. **An edit must be implemented as delete +
add with a fresh `uuid`** — `sigil-wasm/test/merge-guard.mjs` fails the build if a
shipping client grows one.
