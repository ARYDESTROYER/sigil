# 0035 — Device-to-device vault sharing (random per-vault key, wrapped with `hybrid_seal`, relayed as an opaque envelope)

- **Status:** Accepted (2026-07)
- **Date:** 2026-07-26
- **Relates to:** [0011](0011-hybrid-kem-combiner.md) (the hybrid KEM),
  [0013](0013-hybrid-public-key-seal.md) (the `hybrid_seal` / `hybrid_open` flow
  this decision finally puts to work), [0020](0020-shared-client-container-format.md)
  (the `SIGILcli` container reused unchanged),
  [0021](0021-wasm-hybrid-public-key-encryption.md) (the `SIGILhyb` container the
  envelope *is*), [0023](0023-totp-hotp-primitive-and-cli-vault.md) (the TOTP vault
  being shared), and [0031](0031-multi-device-auth-model.md) (the device registry,
  grants and revocation reused for authorization).

## Context

Two things had been true at once, and they were in tension.

**First: the product needs key distribution.** [ADR 0031](0031-multi-device-auth-model.md)
gave `sigild` a real (dev-gated) multi-device model — a device registry, enrollment
with proof of possession, per-vault `read`/`write` grants, trust-on-first-write
ownership, and revocation. But a grant only decides **who the server will talk
to**. It says nothing about **who can decrypt**, because the server never holds a
key. Up to Phase 45 a second device could be *authorized* to pull a vault's opaque
containers and still be unable to open a single one, because every vault was sealed
under **one human's password** (`SIGIL_PASSWORD` → Argon2id → the `SIGILcli`
container). The only way to put a second device inside a vault was to tell that
device the password — which is not a key-distribution design, it is a confession.

**Second: the hybrid primitives were built and unused.** `sigil-core` had, in
order: X25519 (`kx.rs`), ML-KEM-768 (`mlkem.rs`), the combined hybrid KEM
(`hybrid.rs`, [ADR 0011](0011-hybrid-kem-combiner.md)), Ed25519 (`sig.rs`),
ML-DSA-65 (`mldsa.rs`), the combined hybrid signature (`hybrid_sig.rs`,
[ADR 0012](0012-hybrid-signature-combiner.md)), and finally the KEM-then-AEAD
`hybrid_seal` / `hybrid_open` (`hybrid_seal.rs`,
[ADR 0013](0013-hybrid-public-key-seal.md)). Every one of those ADRs closed with
the same honest caveat: **standalone, not wired into any product flow.** The CLI's
`hybrid-keygen` / `hybrid-seal` / `hybrid-open` and the wasm client's `SIGILhyb`
interop ([ADR 0021](0021-wasm-hybrid-public-key-encryption.md)) exercised the path,
but only as *demos of encrypting a file*.

So: a feature that needs public-key encryption, and a public-key encryption path
with no feature. This ADR joins them.

The design constraints going in:

- **The human password must never be shared or wrapped.** It is a *user* secret,
  reused across every vault sealed under it; handing it to a recipient device
  would hand over every other vault too, and would make revocation mean "change
  your password everywhere".
- **The server must stay zero-knowledge.** Whatever crosses the boundary must be
  ciphertext the server cannot read, exactly like an op-log blob.
- **Do not invent a second authorization model.** Sharing must ride the grant /
  ownership / revocation model that already exists, or the two will drift and the
  drift will be a security bug.
- **Do not change the container format.** `SIGILcli` is mirrored by hand across
  `cli/src/lib.rs`, `sigil-wasm/src/lib.rs`, the desktop core and the extension
  ([ADR 0020](0020-shared-client-container-format.md)); a format change would have
  to land in all of them simultaneously.

## Decision

Introduce a **vault key** as a distinct layer in the key hierarchy, wrap it
per-recipient with the existing hybrid public-key seal, and relay the wrapped
result through `sigild` as an opaque envelope.

### 1. A shared vault is sealed under a random 32-byte vault key — with no format change

`generate_vault_key()` ([`../../cli/src/lib.rs`](../../cli/src/lib.rs),
`VAULT_KEY_LEN` = 32) draws 32 bytes from the OS CSPRNG. That key is then passed to
the **existing** `seal_vault` / `open_vault` in place of the password bytes.

This works because the `SIGILcli` container takes **arbitrary password bytes** — it
runs Argon2id over whatever it is given. A random 32-byte key drops straight in, so
a shared vault is byte-for-byte the same container shape as a personal one, and the
CLI, the wasm client, the desktop core and the extension all keep reading it with
no change. (The Argon2id pass over an already-uniform 32-byte key is redundant work
rather than a weakness; keeping it is what buys the zero-format-change property.
Replacing it with a direct KDF is a **future** change and would be a format break.)

`sigil vault rekey --vault <id>` is the explicit, one-way door from a
password-sealed vault to a key-sealed one: it opens the file with `SIGIL_PASSWORD`,
draws a fresh key, re-seals the same file under it, and records the key in a local
`0600` keyring. Nothing about an existing password vault changes until an operator
runs it, and every `sigil totp` command keeps its old behaviour unless the new
`--vault-id <id>` flag is passed.

### 2. The vault key is wrapped per recipient with `hybrid_seal` — the first load-bearing use

Each device generates a **hybrid identity** (`sigil device hybrid-publish`): an
X25519 secret scalar + an ML-KEM-768 keygen seed, kept `0600` and never uploaded,
plus a shareable public half (X25519 public key + ML-KEM-768 encapsulation key)
that is published to the registry.

`wrap_vault_key(recipient_public, vault_key)` calls `hybrid_seal_to_container`,
which is the CLI/wasm packaging of `sigil-core`'s `hybrid_seal`
([ADR 0013](0013-hybrid-public-key-seal.md)): hybrid-encapsulate a fresh 32-byte
`ss_combined` to the recipient's `(X25519 public key, ML-KEM-768 encapsulation
key)`, then seal the 32-byte vault key under it with XChaCha20-Poly1305. The result
is a **`SIGILhyb` container** (~1.2 KiB, observed **1226 bytes**), and the
recipient's `unwrap_vault_key` reverses it with its hybrid secret identity.

Fresh ephemeral entropy — the ephemeral X25519 secret, the ML-KEM coin, and the
AEAD nonce — is drawn per call, so two shares of the same key never reuse
randomness (asserted by a unit test).

### 3. `sigild` relays the envelope and cannot read it

Four routes, all dev-gated behind `SIGILD_ENABLE_DEV_OPS` + a configured registry
exactly like the device routes (`501` otherwise), in
[`../../sigild/internal/api/sharing.go`](../../sigild/internal/api/sharing.go):

| Route | Purpose |
|-------|---------|
| `PUT /v1/devices/{deviceID}/hybrid-key` | publish **my own** hybrid public key |
| `GET /v1/devices/{deviceID}/hybrid-key` | fetch a device's hybrid public key |
| `PUT /v1/vaults/{vaultID}/keys/{deviceID}` | deposit an opaque wrapped vault key |
| `GET /v1/vaults/{vaultID}/keys/{deviceID}` | collect the envelope addressed to me |

The storage seam is `store.KeySharing`
([`../../sigild/internal/store/keysharing.go`](../../sigild/internal/store/keysharing.go)),
embedded in `DeviceStore` so both backends implement it, with migration
[`0004_key_sharing.sql`](../../sigild/internal/store/migrations/0004_key_sharing.sql)
adding `sigil_device_hybrid_keys` and `sigil_vault_key_envelopes`
(`sigild_schema_version` → **4**). Both are `bytea`; both are written and read
verbatim.

The server's **only** inspection of key material is a length check —
`ValidateHybridPublicKey` requires 32 and 1184 bytes. It does not decode a curve
point, check for low-order elements, or verify the two halves belong together;
doing so would be the server performing cryptography on user key material. The
envelope is checked for **size only** (non-empty, ≤ `MaxKeyEnvelopeBytes` = 16 KiB).

### 4. Authorization reuses the existing grant model — no new auth path

Every route goes through the **same** contract-v3 choke points as the op-log
(`authenticateDevice` / `authorizeVault` / `authorizeOpsRequest`):

- **publish key** — authenticated, and the path device ID must equal the
  authenticated device's own ID (else `403`). Revoked devices are rejected before
  anything else.
- **fetch key** — any authenticated, active device. These are public keys;
  authentication only stops the registry being world-enumerable.
- **put envelope** — `needWrite` on the vault, so depositing the first envelope for
  an unowned vault **claims** it (trust-on-first-write), the identical rule and the
  identical code path as the first op append. A read-only grantee cannot deposit.
- **get envelope** — the caller must **be the addressee** *and* hold `needRead` on
  the vault. Another device asking for someone else's envelope is `403`
  (authenticated but not permitted), never `401`.

`sigil vault share` deliberately performs both halves in one command — wrap +
deposit the envelope, **then** grant access through the existing
`POST /v1/vaults/{vaultID}/grants` — so authorization and key distribution cannot
drift apart.

### 5. The human password is never shared, never wrapped, never sent

The resulting hierarchy:

```
human password ──Argon2id──▶ seals a PERSONAL vault.  NEVER shared, never wrapped,
                             never leaves the machine.

vault key (32 CSPRNG bytes) ─▶ seals a SHARED vault (same SIGILcli container).
     │
     └── hybrid_seal to each recipient device's hybrid PUBLIC key
         (X25519 + ML-KEM-768 → XChaCha20-Poly1305)  ─▶ opaque SIGILhyb envelope
                                                        relayed by a server that
                                                        cannot read it.
```

Vault keys live in a per-device `0600` keyring (`$HOME/.sigil/vault-keys.json`,
`{"version":1,"keys":{"<vaultID>":"<b64>"}}`) that is **never synced**. No command
ever prints a vault key — `vault rekey` / `share` / `accept` / `list` print only
`vault_key_fingerprint`, the first 16 hex characters of its SHA-256, so two devices
can confirm they hold the same key without revealing it.

## Consequences

### Good

- **The multi-device story is real end to end.** A second device can now be added
  to a vault without ever learning the owner's password. Proven with no mocks by
  [`../../cli/tests/e2e-sharing.sh`](../../cli/tests/e2e-sharing.sh): two devices
  generate the **same** TOTP code (`94287082` at T=59, the RFC 6238 Appendix B
  vector) from the same shared vault, after the key travelled A → wrap → server →
  B → unwrap.
- **Zero-knowledge holds, and is checked rather than asserted.** The bytes the
  server returned are **byte-identical** to the bytes uploaded (`cmp`), the
  envelope is a `SIGILhyb` container, it contains neither the vault key nor the
  2FA seed, and the server's own log contains no envelope content — only
  `vault.key_envelope_put` / `vault.key_envelope_get` audit lines carrying a
  SHA-256 **fingerprint**.
- **No container-format change**, so the CLI, the wasm client, the desktop core and
  the extension are unaffected; migration `0004` is purely additive and touches
  nothing in the op-log, its hash chain, the device registry or the billing tables.
- **One authorization model, not two.** Because sharing reuses grants, ownership
  and revocation, a revoked device loses envelope access on its next request for
  free — no second policy to keep in sync.

### Bad / accepted costs

- **The hybrid primitives are now LOAD-BEARING, and therefore squarely in scope for
  the audit.** Until now `hybrid.rs`, `hybrid_seal.rs`, `kx.rs` and `mlkem.rs` could
  be described as unused building blocks. They now carry vault-key distribution: a
  flaw in the combiner, in the KEM-then-AEAD composition, or in `hybrid_seal_to_container`'s
  framing is a flaw in a real user-facing path. The Cure53 engagement must treat
  the hybrid seal as in-scope product code, not as a lab primitive.
- **It is still a CUSTOM KEM-then-AEAD composition, NOT RFC 9180 HPKE.** It carries
  no HPKE interoperability and no standardized analysis. That was true when it was
  a demo; it is more consequential now that it is load-bearing.
- **The primitives remain UNAUDITED and the SYSTEM is still not "post-quantum
  secure."** The wrap is designed to stay secret if **either** X25519 or ML-KEM-768
  holds, which is a property of the construction — not a claim about the product.
- **The hybrid SIGNATURE (`hybrid_sign` / `hybrid_verify`) is still unused.** All
  request authentication, including every sharing route, is **classical Ed25519
  only**. Wrapping is hybrid; authenticating is not.
- **A device that already unwrapped a vault key keeps it.** Revocation stops
  **future** server access — it cannot make a device forget a key it accepted. The
  e2e script asserts this as an explicit, documented limit rather than hiding it:
  after revocation, device B still generates codes from its local copy. The real
  remediation is `vault rekey` + re-share, which is a **manual, client-driven**
  operation.
- **No automatic re-wrap on revoke, no key rotation schedule, and no forward
  secrecy for the vault key.** Nothing re-keys a vault when a grant is dropped;
  nothing expires an envelope; an envelope already delivered is not recoverable.
  Republishing a hybrid key does **not** re-wrap envelopes already deposited for
  that device — those were sealed to the old key and must be re-shared.
- **Trust in the published hybrid key is trust in the server's registry.** There is
  **no out-of-band verification** of a recipient's hybrid public key (no safety
  numbers, no key-transparency log, no cross-signature). A malicious server that
  substitutes its own hybrid public key for the recipient's would receive a vault
  key wrapped to itself. The fingerprint comparison in `vault list` lets two humans
  detect the *result* after the fact; it does not prevent the substitution. This is
  the single largest gap in the design and is deliberately recorded, not papered
  over.
- **A single mailbox per (vault, recipient).** `PutKeyEnvelope` is an upsert, so
  re-sharing replaces the previous envelope. That is what makes a re-key
  distributable, and it also means a device with `write` access can overwrite an
  envelope another writer deposited.
- **No rate limiting on the sharing routes.** The per-vault op-log limiter covers
  appends only.
- **Still dev-gated, plain HTTP, localhost, and pre-audit.** `501` by default. Do
  not store real 2FA secrets.

### Alternatives rejected

- **Share the password.** Rejected outright: it leaks every other vault sealed
  under it and makes revocation mean a global password change.
- **Derive the vault key from the owner's password** (e.g. HKDF per vault ID).
  Rejected: the recipient would still need the password, and rotation would be
  impossible without re-deriving everything.
- **A new container format that carries wrapped keys inline** (an HPKE-style
  multi-recipient header). Rejected for now: it is the *better* long-term design,
  but it breaks a format hand-mirrored across four client surfaces, and this phase's
  goal was to prove the flow without a coordinated format break. Revisit before the
  format is frozen.
- **Server-side re-encryption / proxy re-encryption.** Rejected: any scheme where
  the server transforms ciphertext puts key material near the server and weakens
  the property the whole architecture exists to protect.
- **A separate authorization model for sharing** (e.g. an ACL on envelopes).
  Rejected: two policies that must agree eventually disagree. Grants already answer
  "who may touch this vault".

## Browser client support (added Phase 48)

This ADR was written when only the `sigil` CLI implemented the flow, and it closed by
recording that as a limit. **That limit is now retired for the browser clients:**
`web/apps/webapp` and the MV3 `extension/` implement the **same** flow, so sharing
works across every client that talks to the server. The **desktop** client still does
not.

- **The protocol, the routes and the byte layouts are unchanged.** Nothing in the
  decisions above was revised. No Rust changed either: the wasm exports the browser
  needs (`hybrid_x25519_public`, `hybrid_mlkem_encaps_key`, `hybrid_seal_to_container`,
  `hybrid_open_container`) already existed from
  [ADR 0021](0021-wasm-hybrid-public-key-encryption.md), and `sigild` was untouched.
- **The client half is [`../../sigil-wasm/sharing.mjs`](../../sigil-wasm/sharing.mjs)** —
  framework-free, dependency-free, Node **and** browser — exporting
  `generateHybridIdentity` / `hybridPublicIdentity`, `publishHybridKey` /
  `fetchHybridKey`, `generateVaultKey` / `vaultKeyFingerprint`, `wrapVaultKey` /
  `unwrapVaultKey`, `putKeyEnvelope` / `getKeyEnvelope`, `shareVault` / `acceptVault`,
  and `explainSharingStatus`. Its semantics are **mirrored, not shared**, from
  `cli/src/lib.rs` and `sigild/internal/api/sharing.go`. It performs **no
  cryptography**: the KEM/AEAD runs in the wasm, request signatures go through
  `device-auth.mjs`, and all entropy is `crypto.getRandomValues`.
- **`shareVault` keeps decision 4 intact in JS**: it wraps, deposits, and *then*
  grants through the existing `grantVaultAccess`, so authorization and key
  distribution cannot drift apart on the browser either. `unwrapVaultKey` mirrors the
  CLI's rule that a recovered plaintext of any length other than 32 bytes is rejected
  rather than used as a key.
- **Where the client keeps the secrets is the one genuinely new decision**, and it is
  recorded separately in [ADR 0036](0036-browser-sharing-secret-storage.md): the
  hybrid secret identity and the vault keyring live **inside the existing sealed
  device-identity container**, whose schema was bumped to **v2**, rather than in a new
  store. A browser therefore still persists only sealed containers.
- **Proof:** [`../../sigil-wasm/test/sharing-interop.mjs`](../../sigil-wasm/test/sharing-interop.mjs)
  boots a real `sigild`, builds the **real `sigil` binary**, and shares **both ways** —
  JS → CLI and CLI → JS — with both ends reaching the same vault-key fingerprint and
  the same RFC 6238 code, plus the `403` negatives, the byte-identical relayed
  envelope, and the check that the human password does **not** open a re-keyed shared
  vault.
- **Every limit above still applies**, unchanged and now on more surfaces: no
  out-of-band verification of a published hybrid key, revocation cannot un-learn an
  accepted key, no rotation / re-wrap / forward secrecy, dev-gated, plain HTTP,
  UNAUDITED. Two are worth restating in browser terms: JS `Uint8Array`s holding key
  material are **not zeroized**, and converting a personal vault into a shared vault
  is a **one-way door** in both UIs.

## Desktop client support (added Phase 49, 2026-07-27)

The Phase 48 section above closed by recording one remaining limit — *"The **desktop**
client still does not."* **That limit is now retired.** The native desktop app
(`desktop/`) implements this flow as well, so **all four client surfaces** — the `sigil`
CLI, `web/apps/webapp`, the MV3 `extension/` and the native desktop app — share vaults
through these routes.

- **Nothing in the decisions above was revised.** The protocol, the four routes, the
  `SIGILhyb` envelope layout, the key hierarchy and the authorization model are
  unchanged, and `sigild/`, `cli/` and `libsigil/` were not edited.
- **The client half is [`../../desktop/core/src/net.rs`](../../desktop/core/src/net.rs)**,
  exposing `DeviceConfig::{publish_hybrid, share_vault, accept_vault}` alongside
  enrollment and sync, plus `VaultSession::{convert_to_shared, unlock_shared}` and
  `pull_and_adopt`, behind eleven new `#[tauri::command]`s.
- **It is not a fourth implementation.** Unlike the browsers, which mirror the flow in
  JS, the desktop **calls the `sigil-cli` library** — `publish_hybrid_key` /
  `fetch_hybrid_key`, `put_key_envelope` / `get_key_envelope`, `wrap_vault_key` /
  `unwrap_vault_key`, `grant_vault_access` — so decision 4 (wrap → deposit → grant
  through the existing grant API) and the 32-byte length check on a recovered plaintext
  hold by construction rather than by mirroring. That choice is recorded in
  [ADR 0037](0037-desktop-reuses-cli-library-for-protocol.md).
- **Where the desktop keeps the secrets is the CLI's answer, not the browsers'**: the
  hybrid secret identity and the vault keyring are the CLI's own `0600` files in a
  `0700` state directory, written by the CLI's own writers — so the two are literally
  interchangeable. No new storage decision was needed, and
  [ADR 0036](0036-browser-sharing-secret-storage.md) remains browser-specific.
- **Proof:** [`../../desktop/core/tests/server_interop.rs`](../../desktop/core/tests/server_interop.rs)
  boots a real `sigild` and builds the **real `sigil` binary**, and shares **both ways** —
  desktop → CLI and CLI → desktop — with both ends reaching the same vault-key
  fingerprint and the same RFC 6238 code, plus the `403` for an unauthorized third
  device, a clear not-enrolled error, and a clear unreachable error with the offline flow
  still generating codes.
- **Every limit above still applies**, and one is worth restating in native terms: the
  desktop's hybrid secret and vault keyring are **`0600` plaintext files**, which is
  **weaker at rest than the browser clients**, whose equivalents are sealed in a
  `SIGILcli` container under the vault password. Nothing is zeroized on either.
