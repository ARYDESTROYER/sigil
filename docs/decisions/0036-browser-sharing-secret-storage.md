# 0036 — Browser sharing-secret storage (extend the sealed device-identity container to v2)

- **Status:** Accepted — 2026-07.
- **Relates to:** [0033](0033-browser-device-identity-storage.md) (the sealed
  device-identity container this decision extends),
  [0028](0028-webapp-vault-persistence-and-unlock.md) (the sealed-only persistence and
  unlock model), [0035](0035-device-to-device-vault-sharing.md) (the sharing flow whose
  secrets need somewhere to live), and
  [0020](0020-shared-client-container-format.md) (the `SIGILcli` container both use).

## Context

Phase 48 gave the webapp and the MV3 extension the full device-to-device vault-sharing
flow ([ADR 0035](0035-device-to-device-vault-sharing.md)). That puts **two new classes
of bearer secret** on a browser client:

1. the **hybrid secret identity** — an X25519 secret scalar (32 bytes) plus an
   ML-KEM-768 keygen seed (64 bytes). It is the *only* thing that can open an envelope
   addressed to this device;
2. the **vault keyring** — a `vaultId → 32-byte vault key` map covering every shared
   vault this device re-keyed or accepted. Each entry opens a whole vault.

Both must survive a reload, or a shared vault becomes unopenable and a published hybrid
key orphans every envelope already addressed to it. Both are as sensitive as the
Ed25519 device seed already covered by [ADR 0033](0033-browser-device-identity-storage.md).

The `sigil` CLI answers this with two `0600` files (`$HOME/.sigil/device.hybrid` and
`$HOME/.sigil/vault-keys.json`) and leans on filesystem permissions. A browser has no
equivalent: `localStorage` and `chrome.storage.local` are plaintext key-value stores
readable by anything with the origin or the extension profile directory.

Three options were on the table:

1. **A third and fourth store** — new `localStorage` / `chrome.storage.local` keys for
   the hybrid identity and the keyring, each sealed into its own `SIGILcli` container.
   Honest at rest, but it triples the number of containers a client must seal, unseal,
   version, and keep consistent, and every one of them is unsealed by the *same*
   password at the *same* moment anyway.
2. **A field inside the `TotpVault` JSON** — rejected for exactly the reason
   [ADR 0033](0033-browser-device-identity-storage.md) rejected it: that schema is
   **mirrored, not shared**, across `cli/src/lib.rs`, `sigil-wasm/totp-vault.mjs` and
   `desktop/`, and is pinned by cross-client interop tests. A browser-only field would
   break byte-compatibility or force three other surfaces to carry a field they cannot
   use. It is also circular: a **shared** vault is sealed under the very vault key that
   would be stored inside it.
3. **Extend the container that already holds the device seed** — bump its schema and
   put both new secrets beside the seed.

## Decision

**The browser clients store the hybrid secret identity and the vault keyring INSIDE the
existing sealed device-identity container, whose JSON schema is bumped from v1 to v2.
No new store is added.**

The sealed plaintext (`sealDeviceIdentity` / `openDeviceIdentity` in
[`../../sigil-wasm/device-auth.mjs`](../../sigil-wasm/device-auth.mjs),
`DEVICE_IDENTITY_VERSION = 2`) is:

```json
{
  "version": 2,
  "device_id": "dev_…",
  "seed": "<b64 32 bytes>",
  "base_url": "http://127.0.0.1:PORT",
  "hybrid": { "x25519_secret": "<b64 32>", "mlkem_seed": "<b64 64>" },
  "vault_keys": { "<vaultID>": "<b64 32 bytes>" }
}
```

Consequences of that shape, all deliberate:

- **The field names mirror the CLI's on-disk shapes** (`x25519_secret` / `mlkem_seed`
  from its `HybridSecretIdentity`, and the `vaultId → b64` map from its
  `VaultKeyring.keys`), so the two clients describe the same secrets the same way.
- **Both fields are optional and omitted when absent**, so a client that never shares
  writes exactly the shape it always did.
- **v1 containers still open**, yielding `hybrid: null` and an empty keyring. The
  change is backward compatible; there is no migration step and no data loss for an
  already-enrolled browser.
- **Each browser client still persists exactly TWO values, both sealed `SIGILcli`
  containers:** the TOTP vault (`sigil.webapp.vault.v1` / `sigil.extension.vault.v1`)
  and the device identity (`sigil.webapp.device.v1` / `sigil.extension.device.v1`).
  Nothing new is written in the clear.
- **One password, one lock/unlock lifecycle.** Everything in the container is readable
  only while the vault is unlocked; the password and every decrypted secret are
  memory-only and are dropped on Lock / Forget / reload.
- **Unlock gained a fallback, because it had to.** A shared vault is sealed under a
  random vault key, not the password, so the client now opens the **device identity
  first** (with the password), tries the password on the vault, and then tries each
  held vault key in turn. A shared vault therefore re-opens after a reload without the
  user tracking which key belongs to which vault.

## Consequences

### Good

- **No new plaintext surface.** The strongest property of
  [ADR 0028](0028-webapp-vault-persistence-and-unlock.md) and
  [ADR 0033](0033-browser-device-identity-storage.md) — *only sealed containers are
  persisted* — survives a feature that added two more secrets.
- **Offline attackers get ciphertext.** A `localStorage` dump, a copied browser
  profile, or a stolen backup yields containers whose unsealing costs the same Argon2id
  work as the vault itself.
- **Reuses proven machinery.** The container, the Argon2id/AEAD path, and the
  seal/open helpers already existed and are exercised by the cross-client interop
  tests; this decision added a schema version, not a format.
- **The `TotpVault` schema is untouched**, so CLI / desktop / wasm interop is unaffected.
- **Consistency between the two browser clients.** The webapp and the extension use the
  same schema and the same unlock rule, differing only in which storage API they call.

### Bad / accepted costs

- **One container is now a single point of loss.** Losing the vault password loses the
  device identity, the hybrid secret **and** every accepted vault key at once — and a
  shared vault has no other opener, so there is **no recovery path**. This is the price
  of not inventing a second credential; recovery remains unbuilt.
- **Every secret is decrypted together.** Unlocking to read a TOTP code also brings the
  hybrid secret and every vault key into memory, even if the session never shares
  anything. A finer-grained scheme would unseal on demand.
- **No zeroization.** The decrypted material sits in JS `Uint8Array`s for as long as the
  vault is unlocked. JS offers no reliable wipe: Lock / Forget / reload drop the
  references, but nothing scrubs the bytes, and there is no `mlock` and no enclave.
  Anything executing in that origin or extension context while unlocked can read them.
- **The keyring grows without bound and is never pruned.** There is no "forget this
  vault" operation short of Forget-everything.
- **A schema version now has to be honored by two mirrored implementations.** The v2
  shape lives in `device-auth.mjs` and is consumed by both browser clients; a future
  client that writes v3 must keep reading v1 and v2, exactly as this one does.
- **It does not match the CLI's storage.** The CLI keeps these secrets in `0600` files;
  the browser seals them. Neither is wrong, but "where is my hybrid secret?" now has
  two answers, and the CLI's is the weaker one (plaintext at rest).
- **Still dev / pre-audit / UNAUDITED.** Do not store real 2FA secrets.

### Alternatives rejected

- **Separate sealed containers per secret** (option 1) — more moving parts, more
  versioning, and no security gain: they share one password and one unlock moment.
- **A field in the `TotpVault` JSON** (option 2) — breaks a schema mirrored across four
  surfaces, and is circular for a shared vault.
- **Plaintext in web storage** — the same non-starter as in
  [ADR 0033](0033-browser-device-identity-storage.md): it would leave key material
  readable next to a container that is encrypted.
- **A non-extractable WebCrypto key or the Credential Management API** — neither can
  hold an X25519 secret and an ML-KEM seed for use by our wasm, which needs the raw
  bytes to hand to `hybrid_open_container`.

## The sealed-only invariant is now ASSERTED by tests (added Phase 57, 2026-07-28)

This ADR's central claim is that a browser client persists **only** sealed
`SIGILcli` containers. Until Phase 57 **nothing tested it.**

The fourth full-repo audit planted one line in each client's `persistDevice` —

```js
sessionStorage.setItem("sigil.webapp.cache", JSON.stringify(device));
```

— dumping the raw Ed25519 device seed, the hybrid secret identity and every
accepted vault key **in the clear**, and both suites stayed fully green (webapp
19/19, extension 12/12). The existing leak specs were **needle** tests: they swept
the stores into one haystack and asserted the recovery code and one password were
absent from it. The single structural assertion was on localStorage **key names**,
so a value could be anything, and `sessionStorage`, `chrome.storage.session` /
`sync` / `managed`, IndexedDB and Cache Storage were unconstrained.

Both clients now assert the invariant **positively**, over a shared helper
(`sigil-wasm/test/sealed-store-helper.mjs`):

- **every persisted value must base64-decode to bytes beginning with the
  `SIGILcli` magic** — not merely "the key name is one we expect";
- **every other surface must be EMPTY.** Emptiness catches a leak nobody thought
  to write a needle for, which is the whole failure mode above.

⚠️ **The first version of that fix was itself too narrow, and a verifier caught
it.** The webapp is a PWA, so Cache Storage is the one surface allowed to be
non-empty, and the fix exempted it by filtering only **cross-origin** entries —
vacuous against the threat, because every plausible leak (a regression, an
attacker-controlled write, the service worker itself) is **same-origin**. A
same-origin plaintext dump of the whole device identity passed 19/19 while the
extension, which has no such exemption, caught the identical plant. Cache Storage
is now constrained by an **allowlist of what the service worker legitimately
holds** — the shell `/`, `/_next/` build output, and static asset extensions —
and anything else is a finding. Mutation-proven: a dump at `/_leak` now fails with
`Cache Storage holds a NON-SHELL entry`.

Nothing about the storage decision changed. What changed is that the decision is
now **enforced** rather than **remembered**. Every honest limitation above still
stands, including no zeroization and every secret being decrypted together.

## The webapp persists THREE containers when passkey protection is on (added Phase 58, 2026-07-29)

Per this repo's addendum rule the text above is left untouched; this section
records only what changed.

**The body says a browser client "still persists exactly TWO values, both sealed
`SIGILcli` containers".** With [ADR 0046](0046-passkey-protected-local-containers.md)
turned on, the **webapp** persists **three** — and all three are still sealed
`SIGILcli` containers, so the invariant this ADR exists to state is intact:

| `localStorage` key | contents | sealed under |
|---|---|---|
| `sigil.webapp.vault.v1` | the TOTP vault | the **CMK** (was: the password) |
| `sigil.webapp.device.v1` | the v3 device identity — seed, hybrid secret, vault keyring, pin store | the **CMK** (was: the password) |
| `sigil.webapp.hwslot.v1` | **new** — the CMK itself, plus public passkey metadata | `PRF(32) ‖ utf8(password)` |

The third value is a **container and not a JSON marker specifically because of
this ADR**: the leak specs assert that every persisted value decodes to bytes
beginning with the `SIGILcli` magic, and a plaintext `{credential_ids, rp_id}`
marker would have been the first non-container persisted value in this repo's
history. ⛔ Sealing that public metadata under a hardcoded constant just to satisfy
the magic check was rejected as fake crypto.

**What is unchanged:** the sealed-plaintext schema of the device identity (still
v3), the `SIGILcli` format, the one-password/one-unlock lifecycle, the
memory-only handling of every decrypted secret, and every limitation listed above
— including no zeroization, the single-point-of-loss property, and the fact that
the extension and the desktop are untouched (the extension still persists exactly
two containers). The three-container shape applies to the **webapp only**.

⚠️ **One limitation above is now narrower for the webapp and should be read that
way.** *"One container is now a single point of loss … there is no recovery
path"* was written before [ADR 0042](0042-recovery-kit.md). With a kit printed,
the sheet derives the CMK offline and opens both containers — which is the only
reason ADR 0046 could be built at all. Without a kit, the sentence still stands
exactly as written, and ADR 0046 **refuses to enable protection** in that case.
