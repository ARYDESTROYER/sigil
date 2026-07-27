# Sigil threat model (condensed)

> **Internal / pre-audit.** Condensed from the product brief §29. Describes the
> *intended* design's defenses; most are not yet implemented. Kept behind the
> pre-launch wall — do not publish until the audit completes.

The cryptographic invariant: the server never holds enough information to
decrypt a vault. Each adversary class below names its capability, the intended
defense, and the layer the defense lives at.

| # | Adversary | Capability | Intended defense | Layer |
| --- | --- | --- | --- | --- |
| 1 | Phishing site | Lookalike domain asks for code/master password | Domain-bound autofill; extension refuses autofill + warns on mismatch | Browser ext + client |
| 2 | Casual snooper | Glances at screen | Auto-lock (5 min default); biometric on reveal; redacted display; no widget/notification preview | Client |
| 3 | Determined attacker w/ device | Has the phone + lock code | Master password is a separate second layer; optional passkey 2nd factor; remote-wipe invalidates device key + re-encrypts on remaining devices | Client + server |
| 4 | Rogue Sigil employee w/ DB access | Reads production DB | Server holds only ciphertext; signed append-only audit log; two-person, time-bound prod access (operational) — architecture is the real defense | Architecture |
| 5 | Compromised sync server | Owns the backend | Client-side decryption; ops signed by device keys (can't forge); replay/drop detected via Lamport clock + Merkle root | Architecture + crypto |
| 6 | State-level wiretap | Captures all traffic | TLS 1.3 hybrid-PQ named group; double-layer (TLS + AEAD); forward secrecy via ephemeral X25519 + ML-KEM | Transport + crypto |
| 7 | Future CRQC | Records now, decrypts ~2035 with Shor's | Hybrid X25519&ML-KEM-768 KEX + Ed25519&ML-DSA-65 sigs; breaking needs Shor's *and* an MLWE break | Crypto |
| 8 | Insider with vault export | Departing family/team member | Re-encrypt on revoke; vault keys rotated, content re-encrypted to remaining members' KEM pubkeys | Server + workflow |
| 9 | Compromised OS reading memory | Reads memory between apps | Master key in mlock'd pages; secure enclave where available; minimal in-memory residence; wipe on lock | OS / hardware |
| 10 | Browser malware | Reads extension state | Extension storage encrypted under master-password-derived key; user-initiated actions only; clipboard cleared after 3s; HTTPS enforced | Extension hardening |
| 11 | Push-notification operator | Reads push payloads | Payloads carry only opaque vault ID + wake hint; approval blobs decryptable only by the user's other devices | Architecture |
| 12 | Lost master password | User locked out | Recovery kit (12-word seed), recovery delegates (delay, default 7d), platform-passkey-bound recovery — none let Sigil decrypt unilaterally | Workflow |

**Server-stores-opaque-blobs property.** Even where `sigild` does hold data, it
holds **only opaque client-encrypted blobs** — never plaintext and never keys.
The server does no cryptography and never decrypts or interprets what it stores,
so vault confidentiality does **not** depend on the server (adversary classes 4
and 5 above). The only stateful surface today is the **dev-only vault op-log**
(see [`api.md`](api.md)): it is **gated off by default** (opt-in via
`SIGILD_ENABLE_DEV_OPS`, otherwise `501`), **in-memory / non-durable** by
default, and **unauthenticated unless one of two opt-in contracts is
configured** — legacy single-static-key **v2** (`SIGILD_OPLOG_PUBKEY`, no
authorization at all) or the **multi-device model v3** (`SIGILD_DEVICE_AUTH`;
see the next section). The same dev gate also opens the **vault-key relay**
(device hybrid **public** keys + opaque wrapped-vault-key envelopes) — which does
not weaken the property above, because the server holds no decapsulation key and
relays the envelope verbatim. It is a local-wiring scaffold only and **must never
be exposed publicly or hold real secrets**.

## Dev op-log request-auth surface (contract v3, opt-in — see [ADR 0031](decisions/0031-multi-device-auth-model.md))

The multi-device model adds a **new attack surface** (enrollment, device
identity, grants, revocation, an operator admin token). Each row names the
capability, what actually defends against it **today**, and where that defense
lives. Everything here is **dev-gated, opt-in, and UNAUDITED**; none of it is a
production security claim.

| # | Adversary | Capability | Defense as implemented | Layer |
| --- | --- | --- | --- | --- |
| A | **Signature forger** | Wants to act as an enrolled device without its private key | Ed25519 verification (Go stdlib) against **that device's registered public key**, resolved from `X-Sigil-Device`; a wrong-length key/signature is a clean reject, not a panic. A device's signature presented under **another** device's ID fails, because the ID is bound *into* the signed message | `sigild` request auth |
| B | **Replayer** | Captured a valid signed request and re-sends it | The signed message carries a **timestamp** (±300 s window) and a **fresh per-request nonce**; a repeated nonce inside the window is rejected. The nonce is recorded **only after** a valid signature, so probes cannot poison or probe the cache | `sigild` request auth |
| C | **Downgrade / cross-protocol attacker** | Replays captured **v2** traffic into the device model, or reuses an enrollment proof as a request signature | **Domain separation**: v3's first line is `sigil-oplog-auth-v3\n` (v2's was `…-v2\n`) *and* a device-ID segment was added, so a v2 signature cannot verify under v3. Enrollment uses a **different domain** (`sigil-device-enroll-v1\n`), so a proof is not a request signature and vice versa. The two contracts are **mutually exclusive** — configuring both makes the server refuse to boot | `sigild` request auth |
| D | **Enrollment-token thief** | Steals an operator-provisioned enrollment token | A token **alone is not enough**: enrollment also requires **proof of possession** — a signature over a challenge that binds the **token's SHA-256 digest**, the timestamp, the nonce, the **submitted public key** and the label, verified against that submitted key. The token is **single-use** and spent atomically (a conditional `UPDATE` in Postgres, a mutex in memory), optionally TTL-bounded, and only its **SHA-256 digest** is ever held or compared (constant-time, no early exit) | `sigild` enrollment |
| E | **Proof interceptor** | Captures a legitimate enrollment proof and tries to substitute its own key or another token | The challenge binds **both** the token digest **and** the exact public-key string, so a captured proof cannot be re-presented with a different token or a swapped key | `sigild` enrollment |
| F | **Malicious enrolled device** | Successfully enrolled; now wants other users' vaults | **Per-vault authorization**: every ops route requires a grant (`write` for append, `read` for list/verify, **ownership** to grant others). A device with no grant gets **`403`**, distinct from `401`. Device IDs are **server-assigned** (128 bits of `crypto/rand`), so an ID cannot be squatted or guessed | `sigild` authorization |
| G | **Revoked device** | Holds a still-valid private key after being revoked | Revocation is checked **before** signature verification, so a revoked device is refused on its **very next request** regardless of how well it signs. The record is retained (not deleted) so the audit trail stays explainable; revocation is idempotent | `sigild` request auth |
| H | **Auth prober / oracle-hunter** | Probes to learn *which* check failed, to enumerate devices or tokens | The response body is deliberately **coarse** — `{"error":"unauthorized"}` or `{"error":"forbidden"}` — for **every** credential failure; the typed reason enum goes **only** to the server-side audit log and the per-reason metric. `/metrics` is count-only and carries **no device or vault ID label** (an ID label would let a scrape enumerate the registry). A registry fault is `500`, so infrastructure trouble is never read as a credential verdict | `sigild` API surface |
| I | **Compromised admin token** | Holds `SIGILD_ADMIN_TOKEN` | **Not defended beyond the token itself.** The holder can list devices and revoke **any** device (denial of service against every device). It is compared in constant time, never logged or exported, and must be ≥ 16 chars; with it **unset**, the operator routes are permanently `401` — there is **no implicit open-admin mode**. But there is **no rotation, no second factor, and no scoping**. It cannot read or decrypt a vault: it grants no read access to op-log contents and the blobs stay opaque either way |  Operational |

**What this surface does NOT defend (be explicit):**

- **Trust-on-first-write ownership is a dev heuristic, not identity.** The first
  device to authenticate a *write* to an **unclaimed** vault becomes its owner.
  An attacker who guesses or learns an unclaimed vault ID and writes to it first
  **becomes the owner** and locks the legitimate owner out with a `403`. This is
  tolerable pre-audit only because vault IDs are client-chosen high-entropy
  identifiers; it is **not** an account model and **not** sufficient for
  production.
- **No ownership transfer — revoking a vault's owner ORPHANS the vault.** After
  the owner is revoked nobody can grant on that vault; existing grantees keep
  only what they already hold. There is no recovery path.
- **No rate limiting on enrollment attempts.** The per-vault op-log rate limiter
  does not cover `POST /v1/devices/enroll`, so token guessing is bounded only by
  the ≥ 16-character minimum and the constant-time digest comparison.
- **The replay cache is per-process and in-memory.** A multi-instance deployment
  needs a shared store (e.g. Redis), or a captured request replayed against a
  *different* instance would pass.
- **A token is single-ATTEMPT, not single-SUCCESS.** It is spent before the
  device row is created, so a failed enrollment burns it (fail-closed by design;
  the operator must issue a new one).
- **No key rotation, re-enrollment, or recovery**, no hardware attestation, no
  account/session/JWT layer, and the in-memory registry is **non-durable** — a
  spent token becomes reusable after a restart (warned loudly at boot), and the
  file backend was not extended.
- **Plain HTTP in dev.** Nothing here substitutes for transport security.

### Browser clients holding a device identity (webapp + MV3 extension)

The webapp and the extension now enroll and sign as devices through
`sigil-wasm/device-auth.mjs` (see
[ADR 0033](decisions/0033-browser-device-identity-storage.md)), which puts a
long-lived Ed25519 **signing key inside a browser profile**. What that does and does
not buy:

- **The device seed is sealed at rest, not plaintext.** The 32-byte seed is sealed
  into a **second `SIGILcli` container under the same vault password** (Argon2id →
  XChaCha20-Poly1305, inside the wasm) and only that container is persisted —
  `localStorage` key `sigil.webapp.device.v1`, `chrome.storage.local` key
  `sigil.extension.device.v1`. So an attacker with **offline** access to the profile
  directory, a stolen backup, or a `localStorage` dump gets ciphertext, not a usable
  signing key; unsealing it costs the same Argon2id work as the vault itself. This is
  the same property the vault already had ([ADR 0028](decisions/0028-webapp-vault-persistence-and-unlock.md)),
  extended to the key.
- **The seed IS exposed in memory while the vault is unlocked.** Signing requires it,
  so between unlock and lock the seed sits in JS heap memory alongside the decrypted
  vault. Lock, reload, and Forget all drop it; Forget also deletes the sealed
  identity container. There is no zeroization, no `mlock`, and no secure enclave.
- **The enrollment token is a bearer secret held in memory only.** It is typed in,
  sent in `X-Sigil-Enroll-Token`, and cleared immediately after use — never persisted
  and never logged by the client. It is single-**attempt**, so a failed enrollment
  burns it.
- **The extension's reach is bounded by the manifest.** MV3 pages cannot `fetch`
  cross-origin without a host permission, and the manifest grants only
  `http://127.0.0.1/*` + `http://localhost/*`, so this build **cannot** talk to a
  remote server even if a URL were pasted in. That is a deployment bound, not a
  cryptographic one.

**What this explicitly does NOT defend against:**

- **A compromised browser or extension host.** Anything that can run code in the
  client's context while the vault is unlocked can read the decrypted seed and the
  vault, sign arbitrary requests as that device, or capture the password as it is
  typed. Sealing at rest defends the *stored* key, not a live process (this is
  adversary classes 9 and 10 in the table above, still unimplemented).
- **A malicious script with access to the same origin.** `localStorage` and the wasm
  bindings are origin-scoped, not script-scoped: XSS in the webapp's origin, a
  malicious dependency in its bundle, or a hostile page sharing the origin defeats
  this entirely. The extension's separate origin and CSP (`script-src 'self'
  'wasm-unsafe-eval'`) narrow but do not eliminate that class.
- **Transport attacks.** The dev sync path is **plain HTTP over loopback with no
  TLS**; request signing proves *who sent it*, not confidentiality of the
  request-response metadata.
- **Key rotation, re-enrollment, or recovery for a browser identity.** Losing the
  vault password destroys the device identity along with the vault; the only recovery
  is an operator revoke plus a fresh enrollment token.

### Browser clients that also SHARE vaults (webapp + MV3 extension)

Both browser clients now run the full sharing flow through `sigil-wasm/sharing.mjs`
(adversary rows R–W below apply to them exactly as to the CLI). What changes on the
client side is **what a browser profile now holds**:

- **Two more classes of bearer secret live on the device.** The **hybrid secret
  identity** (`x25519_secret` + `mlkem_seed`) is the only thing that can open an
  envelope addressed to this device, and the **vault keyring** (`vaultId → 32 bytes`)
  opens every shared vault this device accepted. Either one is as sensitive as the
  device seed.
- **Both are sealed at rest, in the container that already existed.** Rather than
  adding a new store, the sealed device-identity container was extended to **schema
  v2** ([ADR 0036](decisions/0036-browser-sharing-secret-storage.md)): its sealed
  plaintext is now `{version: 2, device_id, seed, base_url, hybrid: {...},
  vault_keys: {...}}`. So each client still persists exactly **two** values, both
  `SIGILcli` containers under the vault password — `sigil.webapp.vault.v1` /
  `sigil.webapp.device.v1`, `sigil.extension.vault.v1` /
  `sigil.extension.device.v1`. An offline attacker with the profile directory, a
  backup, or a `localStorage` dump gets ciphertext, and unsealing costs the same
  Argon2id work as the vault.
- **They are exposed in memory while unlocked, and are NOT zeroized.** Sharing needs
  the hybrid secret and the vault keys in the clear, so between unlock and lock they
  sit in the JS heap as `Uint8Array`s. JS offers no reliable wipe: Lock / Forget /
  reload drop the references, but nothing scrubs the bytes, and there is no `mlock`
  and no enclave. Anything that can run code in the client's context while the vault
  is unlocked can read them.
- **A shared vault is not recoverable from the password.** Once a vault is converted
  to a shared vault it is sealed under the random vault key, so the *only* thing that
  opens it is a key held in the sealed identity container. Unlock therefore opens the
  identity first, tries the password, then falls back to each held vault key. Losing
  the password loses the keyring, and with it every shared vault this device accepted
  — there is no recovery path. Conversion is also a **one-way door** in both UIs.
- **A pasted recipient device ID is trusted as typed.** The UI has no directory and no
  verification step: the sender pastes an ID, and the registry answers with whatever
  hybrid public key it has for it. See the substitution gap below — it is the same gap
  as for the CLI, but a paste-and-click UI makes it easier to walk into.

### The native desktop client (enrolls, syncs and shares — with the CLI's `0600` files)

Since Phase 49 the Tauri desktop app also enrolls, signs contract-v3 requests and shares
vaults, through `desktop/core/src/net.rs`. It introduces **no new protocol surface**: it
drives the `sigil-cli` library, so there is no second HTTP client, no second signing path
and no fourth copy of the canonical message
([ADR 0037](decisions/0037-desktop-reuses-cli-library-for-protocol.md)) — one fewer place
for a signature-verification bug to hide. What it *does* change is where a fourth kind of
host now holds bearer secrets:

- ⚠️ **Its secrets are `0600` plaintext files, not sealed containers.** `device.key`
  (Ed25519 seed + device id), `device.hybrid` (X25519 secret + ML-KEM seed) and
  `vault-keys.json` (a 32-byte key per shared vault) sit in a `0700` state directory
  (`$HOME/.sigil` by default), unencrypted, exactly like the CLI's — **they are the same
  files**, and the modes are asserted in the tests. Only the TOTP vault itself is sealed.
  **The browser clients are STRONGER at rest here**: they seal the device seed, the hybrid
  secret and every vault key inside a `SIGILcli` container under the vault password
  ([ADR 0036](decisions/0036-browser-sharing-secret-storage.md)), so an offline attacker
  with a profile dump or a backup gets ciphertext and must pay Argon2id to get anything.
  Against the desktop, an offline attacker who can read the user's home directory as that
  user — a stolen unencrypted disk, an unsealed backup, a sync-to-cloud folder, another
  process running as the same user — gets the device identity, the hybrid secret and every
  accepted vault key directly. The defense is the OS: file permissions plus full-disk
  encryption. This is the documented native model, not an oversight, but it is a real
  asymmetry and it belongs in an audit's scope.
- **Nothing is zeroized.** Neither the vault password (best-effort zeroed on `Drop`, with
  no `zeroize` crate and no volatile guarantee) nor any key material read off disk is
  scrubbed; there is no `mlock` and no enclave. Same posture as the CLI and the browsers.
- **The enrollment token is handled once and never stored.** It is a password-type field
  in the UI, crosses the IPC for exactly one `enroll` call, is cleared in a `finally` so it
  does not linger in the DOM, and is never persisted or logged. Nothing else secret crosses
  the IPC in either direction: no seed, no hybrid secret, no vault key, no password — only
  opaque device ids and 16-hex SHA-256 fingerprints.
- **The webview is not part of the trust boundary.** It holds no key material, does no
  cryptography, and the Tauri capability file grants `core:default` only (no `fs`, `shell`,
  `http` or `dialog` plugin), so it reaches disk and the network only through the explicit
  commands.
- **Every sharing limit below applies unchanged**, and two are worth naming here: there is
  **no out-of-band verification of a published hybrid public key** (a hostile registry could
  substitute one), and **revocation cannot un-learn a vault key this device already
  accepted**. There is also no key rotation and no re-wrap on revoke.
- **Dev-gated, loopback, plain HTTP, UNAUDITED**, and the GUI itself is build-and-launch
  verified rather than visually verified — all the behaviour above lives in the headless
  core that `desktop/core/tests/server_interop.rs` drives against a real `sigild` and the
  real `sigil` binary.

**Zero-knowledge is unaffected by the auth model — or by sharing.** The registry
stores **auth metadata only** — Ed25519 **public** keys, server-assigned IDs,
labels, permissions, timestamps, and a bearer token's SHA-256 digest. Migrations
`0002_devices.sql` and `0004_key_sharing.sql` touch **nothing** in the op-log
table, so the opaque blob and its tamper-evidence hash chain are byte-for-byte
unchanged, and the server still performs **no cryptography on vault contents**.
Adding authentication did **not** give the server any ability to decrypt, and
neither did adding the key relay: what `0004` stores is **public** key material and
**ciphertext the server has no decapsulation key for** (see the vault-sharing
section below). Adversary classes 4 and 5 above are unchanged. Correspondingly, the audit and metrics surfaces never record a
public key, an enrollment or admin token (or its digest), a signature, a nonce, a
timestamp value, or blob content.

**Audit log preserves zero-knowledge.** The dev op-log emits a **structured
audit log** of every append, list, and **auth denial**, but it records only
**metadata plus a SHA-256 integrity fingerprint of the opaque ciphertext** — the
server **never logs plaintext, keys, blob content, or the request signature /
nonce**. Fingerprinting bytes that are *already* client-encrypted gives an
operator a *who-appended-what-when* trail (a dev-scale down-payment on adversary
#4's "signed append-only audit log") **without weakening the zero-knowledge
property**: the log reveals nothing the server did not already store, and the
server still cannot decrypt a vault. Auth denials are audited with their **reason**
(the fixed enum: missing / invalid / stale / replayed signature, plus the device
model's `unknown_device`, `revoked_device`, `unauthorized_vault`,
`not_vault_owner`, `bad_proof`, `enrollment_token_used`, …) and, under the device
model, the **presented `device_id`** — so failed access attempts against a guarded
op-log are visible **and attributable**, while the reason is never echoed to the
client. This is still the
**dev** op-log (gated off by default); a production audit log would additionally
be signed and tamper-evident.

**Hash chain gives tamper-EVIDENCE for the op-log.** Every stored op now carries
a per-op **SHA-256 hash-chain link** — `hash(seq) = SHA-256("sigil-oplog-chain-v1"
|| len-prefixed vaultID || seq || prev_hash || blob)`, genesis `prev_hash` =
zeros — so each op commits to the previous one across **all three backends**
(see [`api.md`](api.md) and [ADR 0016](decisions/0016-tamper-evident-oplog-hash-chain.md)).
An adversary who **modifies, reorders, inserts, or drops** stored ops changes the
hash of every op from that point on, so the tampering is **detectable by a
verifier** — a dev-scale down-payment on adversary #4's *signed append-only audit
log* and part of adversary #5's *replay/drop detection* (the production goal is
the full signed / Merkle-root audit log; this is not that yet). Because the hash
fingerprints the **already client-encrypted** blob, tamper-evidence is added with
**no plaintext and no key**, so the zero-knowledge property is preserved.
**Honest limits:** this is **tamper-EVIDENT, not tamper-PROOF**. There is a
**single, non-notarized server** and no Byzantine-fault tolerance; the server
exposes a convenience `GET …/ops/verify` but **can lie about it** (it could
recompute a consistent chain over data it has itself doctored). The guarantee
that actually resists a hostile server is **client-side**: a client re-derives
the chain from the per-op hashes it receives and compares against its own
remembered tip. Server-side verification only catches accidental corruption and a
non-adversarial operator's storage faults.

## Device-to-device vault sharing (opt-in, dev-gated — see [ADR 0035](decisions/0035-device-to-device-vault-sharing.md))

Sharing puts **key material in motion** for the first time. A shared vault is
sealed under a random 32-byte **vault key**; that key is wrapped to each recipient
device with the PQ-hybrid `hybrid_seal` path (X25519 + ML-KEM-768 → XChaCha20-
Poly1305) and relayed through `sigild` as an **opaque envelope**. The human
password is **never shared and never wrapped**. The key hierarchy is specified in
[`crypto-spec.md`](crypto-spec.md#key-hierarchy-and-vault-sharing-hybrid_seal--hybrid_open-in-use).

Everything here is **dev-gated (`501` by default), opt-in, plain HTTP in dev, and
UNAUDITED** — and the cryptography it now leans on (the hybrid combiner and the
custom KEM-then-AEAD seal) is **the same unaudited code**, only now load-bearing.

The rows below are **client-agnostic**: the `sigil` CLI, the webapp, the MV3 extension
and the native desktop app all drive the same four routes with the same v3 signatures,
so every defense and every gap applies to all four. The client-specific consequences are
in the subsections above — two more bearer secrets in a browser profile, no zeroization
and no password recovery for a shared vault on the browsers; `0600` plaintext key files
on the desktop.

| # | Adversary | Capability | Defense as implemented | Layer |
| --- | --- | --- | --- | --- |
| R | **Malicious server / rogue operator reading a relayed envelope** | Owns `sigild` and its database; wants the vault key in transit | The envelope is **ciphertext the server has no key for**: it is a `SIGILhyb` container holding the vault key sealed under a shared secret that only the recipient's hybrid **secret** identity can decapsulate, and that identity **never leaves the device**. The server stores and returns the bytes **verbatim**, decodes nothing, and its *only* inspection of key material is a **length check** (32 / 1184 bytes) on a *published public* key. Proven, not asserted: the e2e script byte-compares uploaded vs. returned bytes and greps the envelope for the 2FA seed | Architecture + crypto |
| S | **Unauthorized device requesting an envelope** | Enrolled and authenticated, but has no business with this vault | **Two** independent conditions on `GET …/keys/{deviceID}`: the caller must **be the addressee** *and* hold a **read** grant on the vault. Failing either is **`403`** (`forbidden_device` / `unauthorized_vault`) — never `401` (which would be a lie) and never `404` (which would leak whether an envelope exists). Depositing needs **write**, so a read-only grantee cannot inject one. Verified: a third enrolled device is refused fetching another device's envelope, fetching its own on someone else's vault, reading the op-log, and depositing on a vault it does not own | `sigild` authorization |
| T | **Revoked device** | Was authorized; still holds its Ed25519 key and its hybrid secret identity | Revocation is checked **before** signature verification, so on its very next request the device gets **`401`** on *every* sharing route — collecting an envelope, publishing a hybrid key, and reading the op-log. Depositing an envelope **for** a revoked recipient is refused with `409 device_revoked` rather than silently stored. **This only stops FUTURE access** — see the limits below | `sigild` request auth |
| U | **Device publishing a hybrid key it does not own** | Wants a vault key wrapped to *its* key by impersonating another device in the registry | A device may publish **only into its own slot**: the path `deviceID` must equal the authenticated device's ID, else **`403`** (`forbidden_device`). The registry FK means only an **enrolled** device can have a key on file at all. The `sigild` test `TestHybridKeyCannotPublishForAnotherDevice` pins this by forging the mismatch that the CLI cannot produce | `sigild` authorization |
| V | **Envelope replayer / substituter** | Re-sends a captured envelope deposit, or swaps one envelope for another | The transport is the **v3 signed request contract** (see table above): the body is *inside* the signed message, so a mutated envelope invalidates the signature, and the ±300 s window plus the single-use nonce bound replay. Depositing requires **write** on the vault, so a passive observer cannot deposit anything. A substituted envelope also **fails to open**: `hybrid_open` authenticates, so a wrong or tampered container yields an authentication failure, never plaintext, and `unwrap_vault_key` additionally rejects any recovered plaintext that is not exactly 32 bytes rather than using it as a key | `sigild` request auth + crypto |
| W | **Log / metrics scraper hunting for key material** | Reads `sigild`'s audit log or scrapes `/metrics` | The three sharing audit events carry **metadata plus a SHA-256 fingerprint** only (`vault.key_envelope_put` / `_get`: vault ID, device IDs, size, `blob_sha256`; `device.hybrid_key_published`: a device ID). **No envelope byte, no vault key, and no hybrid public key is ever logged** — the "no key material in logs" rule is kept absolute even for *public* keys, so there is no judgement call to get wrong later. The three `/metrics` counters are counts with **no vault or device label**. Asserted by a test and by the e2e script, which fails if `SIGILhyb` appears in the server log | `sigild` observability |

**What vault sharing does NOT defend (be explicit):**

- **No out-of-band verification of a recipient's hybrid public key.** A sender
  wraps to whatever the registry serves. A **malicious server that substitutes its
  own hybrid public key** for the recipient's would receive a vault key wrapped to
  itself — and the recipient would simply see "no envelope"/a failure to unwrap.
  There are **no safety numbers, no key-transparency log, and no cross-signature**
  binding a hybrid key to the device's already-enrolled Ed25519 identity. Comparing
  the `vault list` key fingerprints out of band detects the *result* after the
  fact; it does not prevent the substitution. **This is the largest gap in the
  design**, and it is why adversary R above is scoped to *reading a relayed
  envelope* rather than to *the server being harmless*.
- **A compromised device keeps its copy of the vault key.** Revocation stops
  **future** server access; it cannot make a device forget a key it already
  unwrapped, and the sealed container it already pulled stays openable offline. The
  e2e script asserts this explicitly rather than hiding it: after revocation,
  device B still generates correct codes locally. The only remediation is a manual
  `vault rekey` + re-share.
- **No re-wrap on revoke, no key rotation, no forward secrecy for the vault key.**
  Nothing re-keys a vault when a grant is dropped, nothing expires an envelope, and
  an envelope already delivered cannot be recalled. Republishing a hybrid key does
  **not** re-wrap envelopes already deposited for that device.
- **Sharing inherits trust-on-first-write.** A first envelope deposit **claims** an
  unowned vault exactly like a first append, so the ownership caveats above apply
  unchanged.
- **A `write` grantee can overwrite another writer's envelope.** There is one
  mailbox per `(vault, recipient)` and a deposit is an upsert — the property that
  makes a re-key distributable also makes it clobberable by any writer.
- **No rate limiting on the sharing routes.** The per-vault op-log limiter covers
  appends only.
- **The wrap is PQ-hybrid; the authentication is not.** Every sharing request is
  signed with **classical Ed25519** (contract v3). The hybrid signature
  (`hybrid_sign` / `hybrid_verify`) exists in `sigil-core` and is used by nothing.
- **The primitives are UNAUDITED and the composition is bespoke.** It is a
  **custom KEM-then-AEAD, NOT RFC 9180 HPKE** — no standardized analysis, no HPKE
  interoperability. The hybrid property (secure if **either** X25519 or ML-KEM-768
  holds) is design intent of unaudited code, and the **SYSTEM is not "post-quantum
  secure."**
- **Local key storage differs per client, and neither model is strong.** In the **CLI
  and the native desktop app** — which share the *same* files — the hybrid secret
  identity (`$HOME/.sigil/device.hybrid`) and the vault keyring
  (`$HOME/.sigil/vault-keys.json`) are mode `0600` plaintext files — **not** sealed
  under the password, not zeroized, not in an enclave; anything that can read the
  user's home directory as that user has the vault keys (adversary class 9 above). In
  the **browser clients** both are sealed under the vault password inside the v2
  device-identity container, which is **stronger at rest** but **not** while unlocked: the
  decrypted key material sits unzeroized in the JS heap, reachable by anything running
  in that origin/extension context (see the browser-sharing subsection above).
- **Plain HTTP in dev.** Signing proves who sent a request; it is not transport
  security.

## Billing / payment surface (opt-in, dev-gated — see [ADR 0034](decisions/0034-billing-provider-seam.md))

The billing layer adds an endpoint that is, by necessity, **authenticated by
something other than a device key**: a payment provider has no enrolled Ed25519
identity, so `POST /v1/billing/webhook/{provider}` is authenticated **only** by
the provider's own signature over the raw request body. That makes it the single
most attacker-interesting route in `sigild`, and the table below is about it.

Everything here is **dev-gated (`501` by default), opt-in, UNAUDITED, and has
never been run against a live provider account.** None of it is a production
security claim, and none of it is a PCI attestation.

| # | Adversary | Capability | Defense as implemented | Layer |
| --- | --- | --- | --- | --- |
| J | **Webhook forger** | Sends a plausible provider-shaped event (e.g. "subscription activated") with no valid signature | **Real HMAC verification over the exact raw body bytes**, computed *before* the JSON is parsed: Stripe `HMAC-SHA256("<t>.<raw body>")` keyed by the endpoint signing secret, Razorpay `HMAC-SHA256(raw body)` keyed by the dashboard webhook secret, Juspay `hmac` scheme likewise (or a constant-time Basic-credential check for the `basic` scheme). Comparison is **constant time** (`hmac.Equal` / `subtle.ConstantTimeCompare`); an undecodable hex signature is simply "not equal", not a distinct error. An **unconfigured** verifier **fails closed** — it accepts nothing. Verdict: `401` with a coarse body | `sigild` webhook auth |
| K | **Replayer** | Captures a genuine, validly-signed webhook and re-sends it | Two independent bounds. **In-scheme (Stripe only):** the signed message includes the timestamp `t` and the delivery is rejected when `abs(now − t) > 5 min`, checked in **both** directions (a far-future timestamp is as suspect as a stale one). **Cross-provider:** the **idempotency ledger** keyed on `(provider, event_id)` makes a replay a **no-op that still answers `200`** — the state change and the ledger claim are one atomic operation (one mutex in memory; one transaction with `INSERT … ON CONFLICT DO NOTHING` + `SELECT … FOR UPDATE` in Postgres), so a replay cannot double-apply even under concurrency. Razorpay and Juspay carry **no timestamp element**, so for them the ledger is the *only* replay bound — and it is why a redelivery *inside* a restart of the **non-durable in-memory** store could still be applied twice | `sigild` webhook auth + store |
| L | **Body tamperer** | Man-in-the-middle mutates the JSON (amount, subject, status) of an otherwise genuine delivery | The MAC is computed over the **exact bytes read off the wire**, never over re-serialized JSON — a re-encode changes key order and whitespace and would either break verification or, if "fixed" by re-signing, let an attacker mutate the body freely. Any mutation therefore fails verification → `401`. Tests assert this explicitly (a semantically-equal re-encode is rejected). **Exception, stated plainly:** Juspay's `basic` scheme authenticates the **connection**, not the body — it does **not** defend against this adversary; use `hmac` where available and require TLS unconditionally | `sigild` webhook auth |
| M | **Unknown-provider prober** | POSTs provider-shaped payloads to `/v1/billing/webhook/anything`, or to a provider path that exists in code but is not enabled here | Only providers named in `SIGILD_BILLING_PROVIDERS` get a live route; anything else is `404 unknown_provider` with the body **drained and discarded**, audited as `unknown_provider` and counted in `sigild_billing_webhook_rejected_total{reason="unknown_provider"}`. The adapter map is fixed at boot, so a request cannot cause an adapter to be constructed, a credential to be read, or an outbound call to be made. With billing off entirely, the route is `501` — never `404`-vs-`501` leakage about *which* providers exist | `sigild` API surface |
| N | **Webhook-secret thief** | Obtains a webhook signing secret (`whsec_…`, the Razorpay webhook secret, the Juspay credentials) | **Not defended beyond the secret itself** — the holder can mint authentic-looking events. What *bounds* the damage: the webhook can only drive the **state machine** (it can make a subject look subscribed; it cannot read a vault, mint a session, enroll a device, or move money), the state machine **rejects illegal transitions**, the staleness guard rejects out-of-order events, and every applied transition is audit-logged with `from`/`to`. What is missing: **no rotation runbook beyond replacing the env var and restarting**, and (Stripe aside) **no timestamp bound**. The webhook secret is a **different secret from the API key**, so leaking one does not leak the other | Operational |
| O | **API-key thief** | Obtains `SIGILD_STRIPE_SECRET_KEY` / `SIGILD_RAZORPAY_KEY_SECRET` / `SIGILD_JUSPAY_API_KEY` | **Not defended.** A live API key is a provider-side credential: the holder can act against the merchant account directly, outside `sigild` entirely, and no server-side control here can stop that — response is provider-side revocation. `sigild` limits only its *own* exposure: keys arrive from the environment (never the repo), live only inside an adapter struct, travel in an `Authorization` header rather than a URL, and are **never logged, never returned in an error, and never exported on `/metrics`** — provider failures surface as a `ProviderError` carrying **only** provider + operation + HTTP status, deliberately never the response body (which can echo customer data) | Operational |
| P | **Subscription-state manipulator** | An authenticated device (or a forged/leaked-secret event) tries to grant itself entitlement, or to regress someone else's | **The subject is server-derived**: a checkout's subject is the **authenticated device ID** taken from the verified v3 signature, never a body field, and `GET /v1/billing/subscription` reports only the caller's own record with no subject parameter — so neither route can act on, or enumerate, another subject. Transitions are checked against an **explicit transition table** (illegal moves are recorded as processed and rejected with no state change), and a **staleness guard** independently drops any event older than the last applied one, so an out-of-order `payment_failed` cannot regress a live subscription. `canceled` can only be left by an event targeting an active state, so a late failure cannot revive a dead subscription into `past_due` | `sigild` billing layer |
| Q | **Log / metrics scraper** | Reads `sigild`'s audit log or scrapes `/metrics` hoping for payment data | The billing audit events (`billing.checkout_created`, `billing.checkout_failed`, `billing.webhook`, `billing.webhook_rejected`, `billing.subscription_transition`) carry **metadata only**: provider name, normalized event type, opaque provider handles, our own subject, and a fixed reason enum — **never** an API key, a webhook secret, a signature header, **one byte of the raw webhook body**, an email/name/phone, or an amount. `/metrics` exposes four counters over **closed label sets materialized at boot** (three provider names, six outcomes, five reject reasons, five statuses) — no event ID, no subject, no amount, so a scrape can neither leak nor enumerate. Both are asserted by tests that plant a marker string in a webhook body and fail if it appears in the logs | `sigild` observability |

**What the billing surface does NOT defend (be explicit):**

- **A compromised provider account or dashboard.** Anyone with the merchant
  account can create, cancel or refund subscriptions and emit real events that we
  will faithfully apply. There is no second opinion, no reconciliation job, and
  no out-of-band verification of a webhook against the provider's API.
- **A stolen API key** (adversary O) — provider-side revocation is the only
  answer, and there is **no key-rotation automation**.
- **Fraud, chargebacks, refunds, disputes, proration, tax, dunning.** None of it
  is modelled. A refund or a chargeback arrives as an event we classify as
  `ignored`, so entitlement does not change.
- **No PCI attestation.** Hosted checkout means **no card data ever reaches this
  process** — there is no field, struct, log line, metric or column that could
  hold a PAN, CVV, expiry, cardholder name or billing address, which keeps scope
  at SAQ-A. That is a scope-minimization property, **not** a certification, and
  nobody has assessed it.
- **Provider scheme correctness has not been confirmed against a live account.**
  No request in this repository has ever reached `api.stripe.com`,
  `api.razorpay.com` or `api.juspay.in`. The **Juspay** adapter in particular is
  explicitly *UNVERIFIED-AGAINST-LIVE-DASHBOARD* — header names, signed message,
  endpoint path and event vocabulary are a best-supported reading. A wrong guess
  fails **closed** (`401`, or an `ignored` event) rather than open, but "fails
  closed" is not "correct".
- **Denial of service against the webhook endpoint.** There is no rate limiting
  on `/v1/billing/webhook/{provider}` (the per-vault op-log limiter does not
  cover it); the only bounds are the 64 KiB body cap and the cost of one HMAC.
- **The in-memory subscription store is non-durable.** Subscriptions *and* the
  processed-event ledger are lost on restart, so a webhook redelivered across a
  restart **can be applied twice**. Only the Postgres backend gives the
  idempotency guarantee across processes and restarts.
- **Transport.** In any real deployment the webhook endpoint **must** be reachable
  only over TLS. The dev server speaks plain HTTP, and Juspay's `basic` scheme in
  particular is a bearer credential with no body binding.

**Status note for this repo:** almost none of the defenses in the **first** table
(adversary classes 1–12, the *intended product* design) is implemented yet — the
one partial exception is class 8 (*insider with vault export*), where the
**mechanism** for re-keying and re-wrapping a vault to remaining members' KEM
public keys now exists in the sharing flow, but the **workflow** does not: nothing
re-keys automatically on revoke, and revocation cannot recall a key already
unwrapped. The current `sigild` skeleton performs no crypto on vault contents and
stores only the opaque blobs and opaque envelopes described above. `libsigil`'s
crypto is still **UNAUDITED**, and it is **no longer all unused**: the hybrid KEM
and the `hybrid_seal` / `hybrid_open` composition are now **load-bearing** (they
wrap vault keys), while the hybrid **signature** and the suite-frame `kem_ct` path
remain wired into nothing. The **second** and **third** tables (the dev op-log
request-auth surface, A–I, and the vault-sharing surface, R–W) *are* implemented —
that code really runs — but they are **dev-gated, off by default, opt-in, and
UNAUDITED**, and they are a request-auth and key-distribution model for a dev
op-log, **not** the product's account, session, or key-management model. Do not represent any of this as live or as a security
guarantee.
