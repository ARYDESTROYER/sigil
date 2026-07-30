# 0047 — A ceiling on container KDF parameters, a no-downgrade ratchet, and a vault schema that can change

- **Status:** Accepted (2026-07)
- **Date:** 2026-07-30
- **Builds on:** [0020](0020-shared-client-container-format.md) (the `SIGILcli`
  container, whose **byte layout is unchanged** — this decision only constrains
  what the existing header fields are allowed to say),
  [0024](0024-wasm-totp-vault-and-cross-client-totp.md) (the `TotpVault` /
  `TotpEntry` JSON mirrored between Rust and JS — it carries a dated addendum
  pointing here), [0003](0003-dev-gated-opaque-op-log.md) (the opaque op-log,
  which is the delivery path for the hostile bytes **and** the reason the server
  cannot filter them), [0035](0035-device-to-device-vault-sharing.md) (the relay
  that carries containers between devices),
  [0007](0007-caller-supplied-entropy-in-core.md) (caller-supplied entropy, which
  is why an entry id can be a v4 UUID formatted from bytes the caller draws).
- **Changes nothing in:** `sigild`. No route, no header, no canonical message, no
  migration, no table, no metric, no dependency, no schema-version bump. The wire
  protocol is byte-for-byte what it was, and `sigild` still has exactly one direct
  Go dependency.

## Context

Three defects, found by reading the container-parsing and re-sealing paths
end-to-end rather than by a failing test. They are one ADR because they are one
sentence: **a `SIGILcli` container is self-describing, and until now every client
believed everything it described.**

### 1. The header's Argon2 parameters were an unbounded instruction from a stranger

A `SIGILcli` container opens with (ADR 0020):

```
"SIGILcli" | version(u8) | m_cost(u32 LE) | t_cost(u32 LE) | p_cost(u32 LE) | salt_len(u8) | salt | envelope
```

Those three `u32`s are **unauthenticated plaintext framing** — they are inputs to
the KDF, so they cannot be inside the AEAD, and they are therefore whatever the
writer of the bytes chose. Every client parsed them and handed them straight to
Argon2id, which **allocates `m_cost` KiB in one block before it does any work**.

Measured on this machine (macOS arm64, 24 GB RAM, `argon2` 0.5.3 — the exact
crate `sigil-core` links), driving the KDF directly:

| header says | what happened |
|---|---|
| `m_cost = 0xFFFF_FFF0` (≈ 4 TiB), `t=1`, `p=1` | ran **12.57 s**, **peak memory footprint 90,364,919,264 bytes (≈ 90 GB)** on a 24 GB machine, then the process was **killed** — no error, no return |
| `t_cost = 0xFFFF_FFF0`, `m = 19456` | allocates nothing and **does not return in any useful sense**: 1 000 passes at that memory cost measured **5.68 s**, so 4 294 967 280 passes extrapolates to **≈ 282 days** for one open attempt |

⛔ **This is a remote denial of service, and the delivery path is the one we are
proudest of.** Containers reach a client through `sigild`'s op-log, which is
**zero-knowledge by design** ([0003](0003-dev-gated-opaque-op-log.md)): it stores
opaque blobs, returns them verbatim, and **cannot inspect or filter what it
relays**. So the property that makes the server safe is exactly the property that
stops it defending anyone here. Anyone who can write to a vault's op-log — a
revoked-but-not-yet-rotated device, a co-tenant of a shared vault
([0035](0035-device-to-device-vault-sharing.md)), a breached server — could put a
container in it that kills every client that pulls, and keeps a user away from
their own 2FA codes on every device at once.

⚠️ **Nobody had noticed because nothing in this repo writes a hostile header.**
The parse was correct for every container we produce, and the tests all produced
containers we produce.

### 2. The browsers silently downgraded a stronger client's work factor

A re-seal is the operation that **chooses** new work factors. The Rust clients
have ratcheted since Phase 58 — `sigil_cli::reseal_container` never writes weaker
parameters than it read. The JavaScript clients had **no equivalent at all**:
every browser re-seal wrote a hardcoded `{ m_cost: 19456, t_cost: 2, p_cost: 1 }`
without ever reading the container's header.

Verified by reading real bytes: the CLI seals at `Argon2Params::RECOMMENDED`
(**65536 / 4 / 2**, confirmed by dumping the header of a `sigil seal` output).
So a vault written on a laptop and edited once in the browser came back at
**19456 / 2 / 1** — a **3.4×** cut in memory cost and **half** the passes.
Silently. With no user action, no prompt and no error. And because a re-seal is
where parameters are chosen, **the weakening was permanent** until something else
raised it.

The same shape is an attack, not just an accident: a container header is
unauthenticated, so an attacker who gets **one** weak container accepted — say
`m_cost = 8` — would otherwise see that weakness survive every subsequent
re-seal, forever.

### 3. The vault schema could not change without a flag day or data loss

The `TotpVault` / `TotpEntry` JSON is **mirrored** across four clients (CLI,
webapp, MV3 extension, native desktop) plus a printed recovery kit
([0024](0024-wasm-totp-vault-and-cross-client-totp.md)), and vaults sync through
an opaque op-log where **the oldest writer wins**. Two rules made that a trap:

- **`version != 1` was refused outright**, so *any* schema addition was a flag day:
  every client had to ship before any client could write the new field; and
- **neither side preserved fields it did not know.** `serde` dropped them on the
  next serialize, and the JS clients rebuilt `{ version, entries }` by hand. So an
  old client that merely **opened and re-sealed** a vault **deleted a newer
  client's data** — and then pushed the stripped version over it.

There was no third option. Either nothing could ever be added, or adding it meant
silent data loss for anyone who had not upgraded yet.

## Decision

### 1. A ceiling on the work factors, enforced at parse time, before any allocation

[`libsigil/core/src/kdf.rs`](../../libsigil/core/src/kdf.rs) gains three constants
and a check:

```rust
Argon2Params::MAX_M_COST = 262_144   // KiB = 256 MiB
Argon2Params::MAX_T_COST = 16        // passes
Argon2Params::MAX_P_COST = 16        // lanes
Argon2Params::validate(&self) -> Result<(), KdfError>   //  KdfError::ParamsTooLarge
```

`derive_master_key` calls `validate()` **first thing**, so every `sigil-core`
caller gets the bound for free. The two container parsers —
`sigil_cli::open_container` and the wasm binding's `open_container_inner` — call
it **earlier still**, before the salt is even sliced, so the failure is reportable
as *"this container is hostile"* (`CliError::ParamsOutOfRange { m_cost, t_cost,
p_cost }`) rather than as a generic KDF error. A user must be able to tell that
apart from a typo'd password.

Measured after the fix, through the **real `sigil` binary** on the same 4 TiB
container: **0.00 s real, 1.18 MB peak memory footprint**, and a typed message
naming what was demanded and the limits.

**Why 256 MiB specifically.** Four constraints, in this order:

- **Nothing that opens today may stop opening.** It is **4×** the strongest thing
  anything in this repo writes (`RECOMMENDED`, 64 MiB) and **≈13×** what the
  browser clients write (19 MiB). Pinned by tests on both the Rust and the wasm
  side.
- **It must leave room to raise the work factor several times over** without a
  format break or a flag day. The bound is **inclusive** — the ceiling value
  itself is accepted.
- **It must not cap us below the state of the practice.** It is comfortably above
  OWASP's highest current Argon2id recommendation (46–64 MiB).
- ⭐ **It must be survivable by the weakest client that has to open the vault, not
  by a developer laptop.** A mobile browser tab or an MV3 extension page that asks
  for a gigabyte is killed by the platform, and a user whose phone cannot open
  their vault is locked out just as surely as by a crash. The bounded worst case
  — 256 MiB × 16 passes × 16 lanes — measured **1.64 s** here.

⭐ **It is a ceiling only. There is deliberately no floor.** A low work factor is
a *weak* container, not a *dangerous* one, and refusing to open it would destroy
data rather than protect it. The anti-downgrade rule belongs at the re-seal step,
where new parameters are chosen — which is §2.

### 2. The no-downgrade ratchet, with exactly ONE implementation

`Argon2Params::no_downgrade(self, requested)` returns the **componentwise
maximum** of what the existing container declares and what the client would write
today, with Argon2's `m_cost >= 8 * p_cost` floor honoured (a componentwise max
can otherwise pair a small `m_cost` with a larger `p_cost` and produce parameters
that will not derive at all). Each factor becomes a ratchet: **up, never down** —
and a client with stronger defaults silently *repairs* a weak container the first
time it re-seals it.

⭐ **The rule lives in `sigil-core` and is not mirrored anywhere.**

| layer | how it reaches the rule |
|---|---|
| `sigil-cli` | `no_downgrade()` **delegates** to `Argon2Params::no_downgrade`; `reseal_container` reads the input header with the new `container_params()` and re-seals at `no_downgrade(existing, params)` — `params` is a **floor**, not an instruction |
| the wasm binding | new exports `container_params` (read a header without a password, no KDF, no allocation) and `reseal_params` (call the core rule) |
| `sigil-wasm/totp-vault.mjs` | `containerParams()` / `ratchetParams()` — thin wrappers, **no JS reimplementation** |
| webapp + extension | a `sealParams(storageKey)` helper at **every** re-seal site |
| `sigil-wasm/sharing.mjs` | `rotateVaultKey` ratchets instead of re-sealing at its hardcoded default |

This matters more than it looks. A mirrored copy of this rule would be free to
drift, and **a drift downward is invisible**: it produces a container that still
opens everywhere, just weaker. There is nothing to notice.

⚠️ **`ratchetParams` is deliberately forgiving.** A stored container that is
corrupt, truncated or from some future format must not block the user from
saving, so it falls back to `requested` — this build's own defaults, never
something weaker than the client would have written anyway. The dangerous
direction (a strong header quietly becoming a weak one) is the one that cannot
happen.

### 3. A vault schema that can change: preserve the unknown, and separate the two version knobs

**Unknown fields are preserved, at both levels.** `TotpVault` and `TotpEntry` each
gain `#[serde(flatten)] extra: BTreeMap<String, serde_json::Value>`; the JS mirror
does the same job with an explicit rest-spread plus a new `cloneVault()`. An old
client can now open, edit and re-seal a vault written by a newer client
**losslessly**.

⚠️ **This is easy to defeat by accident, and that is exactly what happened.** Any
code that rebuilds a vault as `TotpVault { version, entries }` — or, in
JavaScript, `{ version: v.version, entries: [...] }` — throws the preserved data
away again. Both browser clients did precisely that, in their `withVault` helpers,
and both now call `cloneVault`.

**Two version knobs, because they answer two different questions.**

```
version            = what WROTE this vault          (this build writes 1)
min_reader_version = what a READER must understand  (omitted by this build)

refuse  iff  (min_reader_version ?? version)  >  TOTP_VAULT_READER_VERSION
```

A future purely-additive change writes `version: 2, min_reader_version: 1`, and
old clients keep reading it *and* keep its new data intact. A genuinely
incompatible change writes `min_reader_version: 2` and is refused **precisely**,
naming the version required, instead of by an equality check that cannot tell the
two cases apart.

⭐ **It fails closed.** A vault that never states `min_reader_version` is treated
as requiring a reader of its own `version`, so a version-2 writer that forgets the
field gets the old conservative refusal rather than a silent misread.

**A stable per-entry id** (`uuid`, a lowercase RFC 4122 v4 formatted from 16 bytes
of **caller-supplied** entropy — `getrandom` natively, `crypto.getRandomValues` in
the browser, per [0007](0007-caller-supplied-entropy-in-core.md)) is added
alongside. ⚠️ **Nothing keys off it yet.** Every lookup is still by `label`,
deliberately: changing entry identity is a semantics decision, not a
forward-compatibility one. This only makes that change possible later.

**Byte-shape compatibility is asserted, not assumed.** `min_reader_version`,
`extra` and `uuid` are all omitted when empty/absent, and a test pins that
`TotpVault::default()` still serializes to exactly `{"version":1,"entries":[]}`.

### 4. The truthfulness fixes that fell out of the same read

Two things the import/export path was saying that were not true. They are
recorded here because they share the schema's root cause — **a codec that
discarded what it did not use** — but the detail lives in the addenda to
[0025](0025-totp-import-export.md) and [0026](0026-browser-totp-import-export.md):

- **A multi-QR Google Authenticator import reported plain success.** Both codecs
  consumed `batch_size` / `batch_index` / `batch_id` and threw them away, so
  scanning the first QR of a three-QR export imported a third of the accounts and
  said so as if it were all of them — hitting exactly the users with the most to
  lose. The framing is now decoded and surfaced by all four clients. ⭐ And the
  **final** QR of a multi-QR export is reported truthfully rather than as
  "incomplete": a warning that cries wolf is one the next user ignores when it is
  real.
- **A `--migration` export of a non-30-second entry was a silent lie.** The wire
  format has no period field, so a 60 s entry was exported as if it were 30 s and
  the receiving app computed **different codes from the same secret**. It is now
  refused, pointing at the plain `otpauth://` export that carries the period —
  with a new CLI opt-in (`--skip-unsupported`) so that one unrepresentable account
  no longer costs the user the entire bulk-export path.

### 5. A structural guard, because the product was not covered

`sigil-wasm/test/seal-params-guard.mjs` enumerates every call to a sealing
function in the two shipping browser sources and fails unless each one is passed
`sealParams(...)`. It currently checks **6 sealing call sites across 2 product
sources** (4 in `web/apps/webapp/app/authenticator.tsx`, 2 in
`extension/src/popup/popup.js`), and it fails if it finds **zero** — a guard that
checks nothing is worse than no guard.

⛔ **It exists because an independent verifier proved the fix was unguarded.**
Reverting five of the six sites to the bare constant left the whole gate green:
**webapp 50/50 and extension 14/14**. Mutating the *same* logic inside
`totp-vault.mjs` went red. The module was covered; the product was not — entry #9
of [`../engineering-lessons.md`](../engineering-lessons.md) recurring inside the
commit that added that document.

## The sentence an auditor should be able to check

> A `SIGILcli` header's Argon2 work factors are **range-checked before a byte is
> allocated**, by one set of ceilings that lives in `sigil-core` and is reached
> (never copied) by the CLI, the desktop and the wasm binding; a **re-seal** can
> raise those factors and can never lower them, by one `no_downgrade` function in
> the same crate; a vault carries fields this build does not understand **through
> an edit unchanged**, and refuses only the vaults that say they need a newer
> reader; and `sigild` was not modified at all.

## Consequences

### Good

- **A hostile container is a typed refusal in 0.00 s instead of a dead process.**
  Measured, through the real binary, on the real bytes.
- **The bound cannot drift between clients**, because it is not mirrored — the CLI
  and the wasm binding both read `Argon2Params::MAX_*` from the crate they already
  depend on. Only the *format* constants are mirrored (ADR 0020), and those have a
  golden-header test.
- **Raising the work factor later needs no format change**, because the ceiling is
  4× the strongest value anything writes and the bound is inclusive.
- **A weak container is repaired, not merely tolerated**, the first time a client
  with stronger defaults re-seals it.
- **The schema can finally change.** An additive field can ship in one client and
  survive contact with the other three, which is what a four-client mirror plus a
  printed recovery kit actually needs.
- **The import/export path stopped making two claims that were false**, in the one
  feature whose entire purpose is not losing accounts.
- **The product, not just the library, is now guarded** — at three levels: a
  source-structure check on the seal sites, a Rust↔JS interop suite driving the
  real `sigil` binary, and a Playwright spec in each browser client that seeds a
  vault with unknown fields, drives a **real UI edit**, and decrypts what the app
  actually wrote.

### Bad / honest limitations — every one of them real

1. ⛔ **The ceiling is a client-side parse bound, not a server filter, and it
   removes nothing.** `sigild` still relays a hostile container; by design it
   cannot know what it is relaying. There is no delete-op route and no client-side
   quarantine, so the bad blob **stays in the op-log** and every client that pulls
   parses and refuses it **again, every time**. What changed is the cost of that
   refusal — from a killed process to a rejected parse — not the fact of it.
2. ⚠️ **The ratchet turns a bounded cost into a *persistent* one, inside the
   ceiling.** An attacker who gets one container accepted at exactly
   `256 MiB / 16 / 16` (legal, and measured at 1.64 s per open) has that cost
   preserved by the ratchet **forever**, on every device, because the rule is a
   maximum and never a reset. That is the accepted price of choosing "max": there
   is no supported way to lower an already-ratcheted container short of a new
   flow. It is bounded and it is small; it is not zero, and it is not reversible.
3. ⛔ **The ratchet does NOT cover every write. Two real gaps, both named
   deliberately rather than papered over:**
   - `sigil totp <add|import|remove|…>` saves through
     `save_vault(…, Argon2Params::RECOMMENDED)`, and the desktop saves through
     `seal_vault(…, self.params)` (default `RECOMMENDED`). **Neither reads the
     existing container.** They seal from plaintext at their own configured
     parameters.
   - Today this cannot downgrade anything, because `RECOMMENDED` (64 MiB) *is* the
     strongest thing anything here writes — a CLI save can only ever raise a
     browser-written 19 MiB vault. **But the property "strength only goes up" is
     therefore true of the browsers and of re-keys, and not globally true of this
     system.** The day any client writes above 64 MiB, a `sigil totp add` will
     silently lower it.
4. ⚠️ **`ratchetParams` fails open on a container it cannot parse.** Deliberate —
   a corrupt stored value must not stop a user saving — but it means a damaged
   header silently loses the ratchet for that one write.
5. ⚠️ **`min_reader_version` is a promise a *writer* must keep, and nothing
   enforces it.** A careless future client that makes a breaking change while
   leaving the field at 1 will be misread by old clients, silently. The
   fail-closed default only protects the case where the field is **absent
   entirely**.
6. ⚠️ **`extra` preserves fields, not semantics.** An old client can round-trip a
   field it does not understand while behaving inconsistently with it — preserving
   `"archived": true` and still displaying the code. Forward compatibility of the
   *bytes* is not forward compatibility of the *behaviour*.
7. ⚠️ **The entry `uuid` is dead weight today.** It is written, mirrored, tested
   and used by nothing; identity is still the label. Nothing enforces uniqueness,
   and a duplicated vault file yields duplicated ids that no code objects to.
8. ⚠️ **The seal-params guard is a source-structure check.** It proves each call
   site *passes* `sealParams(...)`; it does **not** prove `sealParams` is correct,
   and a call site that shadowed the name would satisfy it. The behavioural proof
   is elsewhere, and neither is a substitute for the other.
9. ⚠️ **The period refusal has an escape hatch in exactly one client.** The CLI
   got `--skip-unsupported`; the **webapp, the MV3 extension and the desktop call
   the encoder over the whole vault**, so for them a single 60 s entry now makes
   the migration export fail **wholesale** where it previously produced a wrong
   one. That is the right direction — a failed export beats a silently corrupt one
   — but it is a usability regression those three clients have not yet answered.
10. ⚠️ **The `otpauth://` and migration formats still carry no entry id**, so a
    round-trip through either one mints a fresh `uuid`. Deliberate (they are
    interop formats, and an imported entry is a different entry in a different
    vault) but it means ids are stable *within* a vault's lifetime and not across
    an export/import.
11. ⚠️ **Everything here is UNAUDITED**, pre-audit and dev-only, like the rest of
    the repo. A bound chosen by measurement on one machine is a bound chosen by
    measurement on one machine.

### Neutral

- The ceilings are **inclusive**, and both `validate()` and `no_downgrade()` are
  `const fn`, so the check costs nothing at runtime and can be used in constant
  contexts.
- `KdfError::ParamsTooLarge` is deliberately **distinct from
  `KdfError::InvalidParams`**. The rejected values may be perfectly legal Argon2
  parameters; they are refused because honouring them would let whoever wrote the
  container dictate an unbounded allocation on the machine opening it. A caller
  has to be able to tell "hostile" from "malformed".
- `container_params()` reads the header **without a password**, which is what the
  ratchet needs and is also exactly why the values are range-checked *there* too —
  so absurd factors can never be fed **back into** a seal by way of the ratchet.

## Alternatives rejected

- **Filter hostile containers at the server.** Impossible without breaking the one
  property the architecture exists for: `sigild` would have to parse a blob it is
  designed to be unable to interpret. Rejected on sight, and worth stating plainly
  because it is the first thing a reader will think of.
- **A floor as well as a ceiling** (refuse to *open* a container whose work factor
  is too low). Rejected: it locks a user out of their own data to protect them from
  a weakness they already have. The ratchet fixes the same problem at the only
  moment where fixing it costs nothing.
- **Pick the ceiling from the machine's RAM at runtime.** Rejected: the bound would
  differ per device, so a container written on a workstation could be
  unopenable on a phone, and a *checked* property would become an
  *environment-dependent* one. A single documented number is auditable; a
  computed one is not.
- **Reimplement `no_downgrade` in JavaScript** rather than adding two wasm exports.
  Rejected — see §2. A drift downward is invisible.
- **Take the requested parameters on re-seal and merely *warn* about a downgrade.**
  Rejected: the browsers had no UI for it, a warning nobody reads is not a control,
  and the correct value is unambiguous.
- **Bump `TOTP_VAULT_VERSION` to 2 and require every client to ship first.** That
  is precisely the flag day this decision exists to abolish, and it does nothing
  about the *data loss* half of the problem.
- **`#[serde(deny_unknown_fields)]`, i.e. fail loudly instead of preserving.**
  Rejected: on a sync path where the oldest writer wins, that converts silent data
  loss into a hard refusal to open your own vault on your own device. Preserving is
  the only option that neither loses data nor bricks a client.
- **Key entries by `uuid` in this change.** Rejected as scope: changing what
  identifies an entry changes de-duplication, import merging and rename semantics
  across four clients. The field is added now precisely so that decision can be
  made later without another schema flag day.

## References

- Code:
  [`../../libsigil/core/src/kdf.rs`](../../libsigil/core/src/kdf.rs)
  (`MAX_M_COST` / `MAX_T_COST` / `MAX_P_COST`, `validate`, `no_downgrade`,
  `KdfError::ParamsTooLarge`);
  [`../../cli/src/lib.rs`](../../cli/src/lib.rs) (`container_params`,
  `no_downgrade`, `reseal_container`, `CliError::ParamsOutOfRange`,
  `check_vault_readable`, `TOTP_VAULT_READER_VERSION`, `format_entry_uuid`,
  `new_totp_entry_with_uuid`, `TotpVault::extra` / `TotpEntry::extra`);
  [`../../cli/src/migration.rs`](../../cli/src/migration.rs) (`MigrationBatch`);
  [`../../sigil-wasm/src/lib.rs`](../../sigil-wasm/src/lib.rs)
  (`container_params`, `reseal_params`, `container_params_inner`);
  [`../../sigil-wasm/totp-vault.mjs`](../../sigil-wasm/totp-vault.mjs)
  (`containerParams`, `ratchetParams`, `cloneVault`, `checkVaultReadable`,
  `formatEntryUuid`, `randomEntryUuid`);
  [`../../web/apps/webapp/app/authenticator.tsx`](../../web/apps/webapp/app/authenticator.tsx)
  and [`../../extension/src/popup/popup.js`](../../extension/src/popup/popup.js)
  (`sealParams`, `cloneVault` at every re-seal / edit site);
  [`../../web/packages/sigil-wasm/index.mjs`](../../web/packages/sigil-wasm/index.mjs)
  + [`index.d.ts`](../../web/packages/sigil-wasm/index.d.ts) (re-export **and**
  types — two separate holes, kept in step).
- Proof:
  [`../../sigil-wasm/test/schema-interop.mjs`](../../sigil-wasm/test/schema-interop.mjs)
  (10 proofs, driving the **real `sigil` binary** as the Rust half);
  [`../../sigil-wasm/test/seal-params-guard.mjs`](../../sigil-wasm/test/seal-params-guard.mjs);
  [`../../web/apps/webapp/tests/schema.spec.ts`](../../web/apps/webapp/tests/schema.spec.ts)
  and
  [`../../extension/tests/schema.spec.mjs`](../../extension/tests/schema.spec.mjs)
  (the property through the **real UI**, decrypting what the app actually wrote);
  plus the Rust unit tests in `kdf.rs`, `cli/src/lib.rs`, `cli/src/migration.rs`
  and `sigil-wasm/src/lib.rs`.
- Format: [`../crypto-spec.md`](../crypto-spec.md) (the ceiling and the ratchet),
  [0020](0020-shared-client-container-format.md) (the header layout, unchanged).
- Adversaries: [`../threat-model.md`](../threat-model.md) — the writer of a
  hostile container, relayed by a server that cannot filter it.
