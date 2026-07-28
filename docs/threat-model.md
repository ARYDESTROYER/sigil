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
| 12 | Lost master password / lost every device | User locked out | ⚠️ **What ships is a printed 56-character recovery kit and NOTHING ELSE** ([ADR 0042](decisions/0042-recovery-kit.md), [Recovery kit](#recovery-kit-adversaries-dev-gated--see-adr-0042) below). It confers **IMMEDIATE, un-delayed, un-notified, full account takeover** to whoever holds the paper. There is **no recovery delegate**, **no delay window**, **no notification**, **no veto**, and **no passkey-bound recovery** — do not read this row as if there were. It does keep the property that **Sigil cannot decrypt unilaterally**, because the secret never reaches the server; and it must be **printed in advance** or it does not exist | Workflow + client |

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
| I2 | **Enrollment flood / token-guessing volume** (Phase 53) | Sends unauthenticated enrollment attempts as fast as it can, hoping to guess a token or to exhaust the server | ⚠️ **Bounded only weakly, and only if configured.** With `SIGILD_ENROLL_RATE_LIMIT` set, a **failed** attempt consumes a token from a bucket keyed on the **socket peer address** (IPv4 full address, IPv6 **/64 prefix**) and an empty bucket answers `429` + `Retry-After`. ⚠️ **It is a BACKSTOP, not a defence:** behind the reverse proxy this repo documents it is **one global bucket**, `X-Forwarded-For` is deliberately ignored (it is attacker-supplied text, and keying on it would let one client mint unlimited buckets), and it **fails open** at its 10,000-key cap rather than refusing everyone. It charges **only on the denial path**, so **a valid, unspent credential with a valid proof can never be refused by it** — an earlier revision rejected before the handler and was reproduced **denying a legitimate customer**, i.e. a global account-creation off switch. ⚠️ **It also does not reduce load**: the handler always runs. The real guessing bound remains the ≥ 16-character token minimum, the constant-time digest comparison, and the mandatory proof of possession. **Per-source limiting belongs at the edge and is not configured in `deploy/`** ([ADR 0041](decisions/0041-abuse-bounds-and-the-removed-webhook-limiter.md)) | `sigild` (backstop) + edge |
| I | **Compromised admin token** | Holds `SIGILD_ADMIN_TOKEN` | **Not defended beyond the token itself.** The holder can list devices and revoke **any** device (denial of service against every device). It is compared in constant time, never logged or exported, and must be ≥ 16 chars; with it **unset**, the operator routes are permanently `401` — there is **no implicit open-admin mode**. But there is **no rotation, no second factor, and no scoping**. It cannot read or decrypt a vault: it grants no read access to op-log contents and the blobs stay opaque either way |  Operational |

**What this surface does NOT defend (be explicit):**

- **Trust-on-first-write ownership is a dev heuristic, not identity.** ⚠️ **Phase
  52 moved it up one level — it did not remove it** (see
  [Account boundary](#account-boundary-dev-gated--see-adr-0040) below): the first
  **account** to authenticate a *write* to an **unclaimed** vault becomes its
  owner. An attacker who guesses or learns an unclaimed vault ID and writes to it
  first **becomes the owner** and locks the legitimate owner out with a `403`.
  This is tolerable pre-audit only because vault IDs are client-chosen
  high-entropy identifiers; there is now an account model, but it is **not an
  identity system** and **not** sufficient for production.
- **~~No ownership transfer — revoking a vault's owner ORPHANS the vault.~~**
  ⚠️ **Retired at the device level by Phase 52.** Ownership belongs to an
  **account**, so every sibling device inherits it: revoking the device that
  claimed a vault no longer strands it. **The failure was narrowed twice, not
  eliminated** — lose or revoke *every* device in an account and the account, its
  vaults and its subscription are permanently unreachable **unless a recovery kit
  was printed in advance** ([below](#recovery-kit-adversaries-dev-gated--see-adr-0042));
  a kit **cannot be created after the loss**. Ownership still never transfers
  *between accounts*.
- **~~No rate limiting on enrollment attempts.~~** ⚠️ **Partly addressed by Phase
  53 ([ADR 0041](decisions/0041-abuse-bounds-and-the-removed-webhook-limiter.md)),
  and the caveats matter more than the feature.** `POST /v1/devices/enroll` can be
  bounded by an **opt-in** token bucket keyed on the **socket peer address**
  (`SIGILD_ENROLL_RATE_LIMIT`), returning `429` + `Retry-After`. But it is a
  **BACKSTOP, not a defence**: behind the reverse proxy this repo documents, every
  request arrives from one address and it degrades to a **single global bucket**
  — which is why it charges the bucket **only on the denial path** (so a valid,
  unspent credential with a valid proof can never be refused by it) and **fails
  open** at its key cap. It also **does not reduce load** — the handler always
  runs. Token guessing is still bounded chiefly by the ≥ 16-character minimum and
  the constant-time digest comparison. **Real per-source limiting belongs at the
  edge, and is not configured anywhere in `deploy/`.**
- **The replay cache is per-process and in-memory.** A multi-instance deployment
  needs a shared store (e.g. Redis), or a captured request replayed against a
  *different* instance would pass.
- **A token is single-ATTEMPT, not single-SUCCESS.** It is spent before the
  device row is created, so a failed enrollment burns it (fail-closed by design;
  the operator must issue a new one).
- **No key rotation, no re-enrollment flow**, no hardware attestation, and no
  session/JWT layer. Since Phase 52 there **is** an account layer — auth metadata
  only, with **no identity system** (see
  [Account boundary](#account-boundary-dev-gated--see-adr-0040)) — and since
  Phase 54 there **is** a **recovery kit**, but only as a **paper key printed in
  advance**, not as a reset or a break-glass
  ([below](#recovery-kit-adversaries-dev-gated--see-adr-0042)). Vault **key**
  rotation has existed since Phase 50 (`sigil vault rotate`); what is still
  missing is rotation of a **device identity**. The in-memory
  registry is **non-durable** — a spent token becomes reusable after a restart
  (warned loudly at boot), and the file backend was not extended.
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
- ⚠️ **The webapp's `SIGILD_CORS_ORIGINS` allowlist is NOT a control here.** It
  exists so a browser page can reach `sigild` at all (custom `X-Sigil-*` headers
  make every signed request preflighted, and `sigild` answered every preflight
  `405` until Phase 56). It authenticates nothing: there is **no cookie and no
  ambient credential**, so a hostile cross-origin page could not forge a signed
  request even with CORS wide open, and `Access-Control-Allow-Credentials` is never
  set. Treat it as a reachability and configuration-hygiene setting, not a defence
  ([ADR 0044](decisions/0044-opt-in-cors-allowlist.md)).

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
- **A pasted recipient device ID is still trusted as typed — but the key behind it is
  no longer.** The UI has no directory, so the sender pastes an ID and the registry
  answers for it. Since Phase 50 the browser clients **pin** the hybrid public key
  behind that ID inside their sealed device-identity container (schema **v3**, field
  `pins`) and throw `KeyPinMismatchError` if it ever changes, and both UIs can show
  the **safety number** to compare out of band before the first share. The residual
  risk is unchanged in kind: a paste-and-click UI makes it easy to share to a
  never-verified device on **first** sight, and easy to click through a re-pin. The
  browsers also **fail closed** if a caller forgets to pass its pin store
  (`requirePinStore` throws) rather than silently treating every key as first-sight.

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
- **Every sharing limit below applies unchanged**, including the Phase 50 ones. The
  desktop gets pinning, safety numbers and rotation **by construction** rather than by
  mirroring — it calls the same `sigil-cli` functions (`fetch_hybrid_key_pinned`,
  `rotate_vault_key`, `repin_hybrid_key`) and keeps its pin store in **the same
  `hybrid-pins.json`** in the same state dir, so a desktop pin and a `sigil` pin are
  literally the same record. A mismatch surfaces as `DesktopError::KeyPinMismatch`,
  tagged across the IPC as `"key changed"`. What remains true: **first contact is
  trust-on-first-use unless the user compares the safety number**, and **revocation
  cannot un-learn a vault key this device already accepted** — rotation protects only
  what is written afterwards.
- ⭐ **The alarm is now rendered, not just raised (Phase 51).** Until Phase 51 the
  desktop was the one client where the key-substitution control existed in the core
  but the user could barely see it: `main.rs` tagged the error `"key changed"` and
  `desktop/ui/main.js` had no handler and no re-pin control, so a refused share
  showed as a toast that vanished in seven seconds — while the webapp and the
  extension both blocked and explained. A control the user cannot see is, in
  practice, a control that is not there. IPC errors now cross as a **structured
  value** (`IpcError { kind, message, key_change? }`), where `key_change` is
  populated for exactly the `"key changed"` kind and carries the device id and
  **both safety numbers** — **public material only**, no key bytes and no seed. The
  UI shows a blocking `role="alert"` panel that **disables the share and rotate
  buttons**, prints the pinned and presented numbers side by side, and puts a
  `window.confirm`-guarded re-pin behind them which sends the presented number back
  as `expected` so the native side re-checks it against what the server is serving
  *now*. It is reached from the single central `call()` error path, so every
  command routes through it. **This changes what the user sees, not what the client
  refuses** — the refusal itself was already correct, and is unchanged.
- ⭐ **The path that raises it now has a regression test.** The desktop was also
  the only client whose key-substitution defence had none (the browser side is
  covered by `sigil-wasm/test/pinning-interop.mjs`).
  `desktop/core/tests/server_interop.rs` gained
  `a_substituted_hybrid_key_raises_the_alarm_the_desktop_ui_renders`, which boots a
  real `sigild` and the real `sigil` binary, has the CLI publish key K1, shares
  (which **pins** K1), then runs `sigil device hybrid-publish --regenerate` so the
  **same device id presents a different key** — exactly what a hostile server does,
  and deliberately indistinguishable from a legitimate re-enrolment. It asserts the
  share is refused as `DesktopError::KeyPinMismatch` carrying both numbers in the
  six-groups-of-five-digits shape the UI prints, that **rotation is refused too**,
  that a re-pin to a **wrong** number is refused and leaves the old pin standing,
  and that only a deliberate re-pin to the presented number lets sharing resume.
  The test was **mutation-checked**: with the pin check in `cli/src/lib.rs` neutered
  to fail open it fails with *"SHARED TO A SUBSTITUTED KEY — the pin check did not
  fire"*.
- **Dev-gated, loopback, plain HTTP, UNAUDITED**, and the GUI itself is build-and-launch
  verified rather than visually verified — all the behaviour above lives in the headless
  core that `desktop/core/tests/server_interop.rs` drives against a real `sigild` and the
  real `sigil` binary.

**Zero-knowledge is unaffected by the auth model — or by sharing.** The registry
stores **auth metadata only** — Ed25519 **public** keys, server-assigned IDs,
labels, permissions, timestamps, a bearer token's SHA-256 digest, and (since
Phase 52) account ids, memberships, invite **digests** and vault-owner rows.
Migrations `0002_devices.sql`, `0004_key_sharing.sql` and `0005_accounts.sql`
touch **nothing** in the op-log
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

## Account boundary (dev-gated — see [ADR 0040](decisions/0040-account-model.md))

Phase 52 made an **account** — not a device — the subject of **entitlement** and
the **owner of vaults**. An account is a **server-assigned id on the device row**;
a **single-use invite** minted by a member device is the only way a second device
joins. It is **auth metadata only**: no email, no password, no session, no PII
and no key material. It is **not an identity system**, and the only recovery is a
**paper kit printed in advance**
([below](#recovery-kit-adversaries-dev-gated--see-adr-0042)).

**The invariant that shapes this boundary:** ⭐ **no request anywhere names an
account.** Every handler derives it from `dev.AccountID` on the device row of the
signature it just verified. There is no path segment, no query parameter and no
body field that names an account, so a cross-account request is
**unconstructible**, not merely rejected. That is stronger than a filter, and it
is the whole of the cross-account access-control story.

**The line an auditor should be able to check:** an account is auth metadata
only; the server still never sees a vault key, a password or a plaintext; no
request anywhere names an account; entitlement and vault ownership derive
**solely** from the account on the verified signer's device row; and **membership
grants ciphertext access, never plaintext**.

| # | Adversary | Capability | Defense as implemented | Layer |
| --- | --- | --- | --- | --- |
| Y | **Cross-account prober** | Wants to read or mutate another account's membership, invites or vaults | **Structural:** no request names an account. `GET /v1/account` and the three invite routes all resolve `dev.AccountID` from the verified signature; invite revocation is scoped by `(account_id, invite_id)` in the store, so a **foreign** invite handle and a **missing** one are both `404` — no enumeration oracle. A vault owned by another account answers the same coarse `403` as a vault owned by nobody | `sigild` API surface |
| Z | **Invite interceptor** | Reads an invite in transit, in a chat log, or over the shoulder | ⚠️ **Only partially defended.** An **unpinned** invite is a **bearer secret** for its whole TTL, and the dev transport is **plain HTTP with no TLS**. Defenses that do exist: 256 bits of `crypto/rand`, a short default TTL (15 min), a per-account **open-invite cap**, **single-SUCCESS** redemption (consumption and the device insert are one atomic operation), revocation before use, and an optional **pin** (`invitee_public_key`) binding the invite to exactly one Ed25519 key. **Nothing forces pinning** | `sigild` enrollment + operator practice |
| AA | **Invite-state prober** | Probes to learn whether an invite exists, is used, expired, or revoked | Every invite failure collapses onto an **existing coarse** enrollment reason (`bad_enrollment_token` / `enrollment_token_used` / `enrollment_token_expired` / `bad_proof`) and the **same 401 body**. The fine-grained cause reaches the **audit log only** — never a response, never a `/metrics` label. The one new distinct status, `409 account_full`, is reachable **only after** a credential and a valid proof have been accepted | `sigild` API surface |
| AB | **Compromised member device** | Holds a valid key inside an account | ⚠️ **Largely undefended, by design of a flat model.** It may **invite** new devices, **revoke every other member**, run checkout, and **administer every account-owned vault**. It still **cannot decrypt** a vault it has not been sent an envelope for. What exists is **visibility, not prevention**: `account.device_joined` names the **inviter**, `device.revoked` names the revoker and the account. **Revoking a compromised device does NOT revoke the devices it invited** | Audit / operational |
| AC | **Hostile or compromised server** | Owns the device registry | ⚠️ **It can insert a device into any account** — it writes the registry, so membership is not a client-verified claim. ⭐ **And it still cannot decrypt anything**, because membership confers **AUTHORIZATION, never DECRYPTION**: a joined device reads nothing until an existing member **wraps the vault key to its hybrid public key**, a deliberate client-side act. The follow-on move — serving the attacker's hybrid key when a member goes to wrap — is the key-substitution attack, defended **client-side only** by pinning + safety numbers (adversary **X** below), which **cannot protect first contact** | Architecture + client |
| AD | **Rolled-back binary / stranded rows** | A pre-Phase-52 `sigild` writes to an already-migrated database | Devices enrolled that way carry `account_id NULL`, and vaults claimed that way carry a legacy `is_owner` grant and no owner row. Both **fail CLOSED** — refused everywhere with a coarse `403` (`missing_account` / `vault_owner_unresolved`), and the server **never falls back to the device id**, which would silently resurrect the model accounts replaced. Because the refusal is deliberately indistinguishable from any other, the server **warns at boot** with the counts and the repair command; the repair is the explicit, idempotent **`sigild migrate adopt`**. **Adoption never happens implicitly on the authentication path** — an unauthenticated request must never be able to mint an account | `sigild` boot + operator |

**What this boundary does NOT defend (be explicit):**

- ⚠️ **THIS IS STILL NOT AN IDENTITY SYSTEM, AND RECOVERY EXISTS ONLY IF IT WAS
  PRINTED IN ADVANCE.** No email, no password, no operator break-glass. An account
  is reachable only through a member device's private key — or through a **printed
  recovery kit**, which is itself just such a key on paper
  ([below](#recovery-kit-adversaries-dev-gated--see-adr-0042)). **Lose or revoke
  every device WITHOUT having printed a kit and the account is permanently
  unreachable, its vaults permanently unreadable by the customer AND by us, and
  its subscription stranded** — and **a kit cannot be created after the loss**.
  Compared with the device model this **narrowed** the orphan failure twice (from
  "revoke one device" to "lose every device" to "lose every device having printed
  nothing"); it did **not eliminate** it. *Keep two devices enrolled, and print a
  kit* is guidance, not a guarantee.
- **Trust-on-first-write did not go away; it moved up one level.** The first
  *account* to write an unclaimed, high-entropy vault id owns it, and an attacker
  who gets there first still locks the legitimate owner out with a `403`.
- **Ownership never moves between accounts and membership is immutable** — no
  transfer, merge, split, or account deletion. A device in the wrong account can
  only be revoked and re-enrolled.
- **No account merge across the cutover.** Every device enrolled before migration
  `0005` was adopted into its **own singleton account**, so an existing two-device
  customer has **two accounts and two billing subjects**; the remedy is manual and
  leaves a second subscription row for an operator to reconcile.
- **Entitlement CAN now be enforced, opt-in and on WRITES ONLY**
  ([ADR 0043](decisions/0043-entitlement-enforcement.md)): past a grace period a
  lapsed account's new op-log writes and its cross-account key deposits answer
  `402`. ⭐ **Reads and same-account key recovery are never refused**, so a lapsed
  customer keeps every 2FA code they hold and can still key a replacement device
  or print a recovery kit. With `SIGILD_ENTITLEMENT_ENFORCE` unset (the default)
  nothing is enforced at all. ⚠️ **The billing trust assumption's blast radius grew
  again**: a compromised provider webhook secret now moves an *account's* status,
  and with enforcement on, its **service**.
- **Rate limiting is opt-in and is a BACKSTOP.** `POST /v1/devices/enroll` (per
  source address) and `POST /v1/account/invites` (per account) can be bounded
  ([ADR 0041](decisions/0041-abuse-bounds-and-the-removed-webhook-limiter.md)),
  but behind a reverse proxy the enrollment bucket is **global**, only **failed**
  attempts are charged, the handler still runs, and the invite limiter sits
  **after** authentication so it does not make an unauthenticated flood cheaper.
  The device and invite caps bound stored **state**, not request volume, and there
  is still **no sweep job for expired invites**. `SIGILD_ACCOUNT_MAX_DEVICES` is
  **anti-freeloading, not anti-fraud** — and a **recovery kit consumes a seat**.
- **`/metrics` remains always-on and unauthenticated**, and its per-reason
  counters are a weak correlatable oracle (pre-existing). This surface
  deliberately does **not** widen it.
- **The replay nonce cache is still per-process and in-memory.** Invite
  consumption is DB-atomic and therefore multi-instance safe; **signed requests
  are not**.
- **The in-memory registry is non-durable** — accounts, memberships, invites and
  vault-owner rows all vanish on restart (warned at boot) — and the **file op-log
  backend was still not extended**.
- **Plain HTTP in dev, `501` by default, UNAUDITED.** A real authorization model,
  **not a reviewed one**.

**Zero-knowledge is unchanged.** Migration `0005_accounts.sql` is pure DDL plus a
metadata backfill: **no column it creates can hold a vault key, a password, a
plaintext, a card detail, an email, a phone number, a display name, a bearer
token, a signature or a nonce**; an invite exists only as a lowercase-hex SHA-256
**digest** (the secret is returned exactly once and never stored, logged or
re-served); and `sigil_vault_ops` is not named anywhere in it, so the opaque blob
and its tamper-evidence hash chain are byte-for-byte unchanged and
`GET …/ops/verify` returns the same `tip_hash` before and after. Adversary
classes 4 and 5 are unaffected.

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

⭐ **Phase 50 changed what this section can honestly claim about a hostile
registry** ([ADR 0038](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)).
Until then a client wrapped a vault key to whatever key the server served, and a
server that substituted its own received the vault key — invisibly. Now every
client **pins** a device's hybrid public key on first sight and **hard-refuses**
if it ever changes; a **safety number** lets two humans verify a key out of band
*before* the first share; and `vault rotate` re-keys a vault and re-wraps it to a
chosen set of devices. Read adversary **X** and the limits below together: what
changed is that substitution after first contact is **detected and blocked**, and
that first contact is now **verifiable by a human who chooses to verify it**. What
did **not** change: first contact is otherwise still trust-on-first-use, rotation
protects future content only, and none of it is audited.

The rows below are **client-agnostic**: the `sigil` CLI, the webapp, the MV3 extension
and the native desktop app all drive the same routes with the same v3 signatures,
so every defense and every gap applies to all four. There are exactly **two**
implementations of the pinning and safety-number logic behind them — the Rust
`sigil-cli` library (used by the CLI *and*, via [ADR 0037](decisions/0037-desktop-reuses-cli-library-for-protocol.md),
the desktop) and `sigil-wasm/sharing.mjs` (used by the webapp and the extension) —
mirrored, not shared, and kept byte-identical by a cross-tool test. The
client-specific consequences are in the subsections above — two more bearer secrets
in a browser profile, no zeroization and no password recovery for a shared vault on
the browsers; `0600` plaintext key files on the desktop.

| # | Adversary | Capability | Defense as implemented | Layer |
| --- | --- | --- | --- | --- |
| R | **Malicious server / rogue operator reading a relayed envelope** | Owns `sigild` and its database; wants the vault key in transit | The envelope is **ciphertext the server has no key for**: it is a `SIGILhyb` container holding the vault key sealed under a shared secret that only the recipient's hybrid **secret** identity can decapsulate, and that identity **never leaves the device**. The server stores and returns the bytes **verbatim**, decodes nothing, and its *only* inspection of key material is a **length check** (32 / 1184 bytes) on a *published public* key. Proven, not asserted: the e2e script byte-compares uploaded vs. returned bytes and greps the envelope for the 2FA seed | Architecture + crypto |
| S | **Unauthorized device requesting an envelope** | Enrolled and authenticated, but has no business with this vault | **Two** independent conditions on `GET …/keys/{deviceID}`: the caller must **be the addressee** *and* hold a **read** grant on the vault. Failing either is **`403`** (`forbidden_device` / `unauthorized_vault`) — never `401` (which would be a lie) and never `404` (which would leak whether an envelope exists). Depositing needs **write**, so a read-only grantee cannot inject one. Verified: a third enrolled device is refused fetching another device's envelope, fetching its own on someone else's vault, reading the op-log, and depositing on a vault it does not own | `sigild` authorization |
| T | **Revoked device** | Was authorized; still holds its Ed25519 key and its hybrid secret identity | Revocation is checked **before** signature verification, so on its very next request the device gets **`401`** on *every* sharing route — collecting an envelope, publishing a hybrid key, and reading the op-log. Depositing an envelope **for** a revoked recipient is refused with `409 device_revoked` rather than silently stored. **This only stops FUTURE access** — see the limits below | `sigild` request auth |
| U | **Device publishing a hybrid key it does not own** | Wants a vault key wrapped to *its* key by impersonating another device in the registry | A device may publish **only into its own slot**: the path `deviceID` must equal the authenticated device's ID, else **`403`** (`forbidden_device`). The registry FK means only an **enrolled** device can have a key on file at all. The `sigild` test `TestHybridKeyCannotPublishForAnotherDevice` pins this by forging the mismatch that the CLI cannot produce | `sigild` authorization |
| V | **Envelope replayer / substituter** | Re-sends a captured envelope deposit, or swaps one envelope for another | The transport is the **v3 signed request contract** (see table above): the body is *inside* the signed message, so a mutated envelope invalidates the signature, and the ±300 s window plus the single-use nonce bound replay. Depositing requires **write** on the vault, so a passive observer cannot deposit anything. A substituted envelope also **fails to open**: `hybrid_open` authenticates, so a wrong or tampered container yields an authentication failure, never plaintext, and `unwrap_vault_key` additionally rejects any recovered plaintext that is not exactly 32 bytes rather than using it as a key | `sigild` request auth + crypto |
| W | **Log / metrics scraper hunting for key material** | Reads `sigild`'s audit log or scrapes `/metrics` | The three sharing audit events carry **metadata plus a SHA-256 fingerprint** only (`vault.key_envelope_put` / `_get`: vault ID, device IDs, size, `blob_sha256`; `device.hybrid_key_published`: a device ID). **No envelope byte, no vault key, and no hybrid public key is ever logged** — the "no key material in logs" rule is kept absolute even for *public* keys, so there is no judgement call to get wrong later. The `/metrics` counters are counts with **no vault or device label** (Phase 50's `sigild_key_envelope_deletes_total` included). The two Phase 50 events (`vault.key_envelope_list` / `_delete`) carry device IDs and a count and have **no blob to fingerprint**. Asserted by a test and by the e2e script, which fails if `SIGILhyb` appears in the server log | `sigild` observability |
| X | **Key-substituting server / rogue registry** (Phase 50) | Owns the registry; answers `GET /v1/devices/{B}/hybrid-key` with **its own** hybrid public key so the next share is wrapped to *it* | **Detected and blocked after first contact — not prevented at first contact.** Every client **pins** the first hybrid public key it sees for a device and compares on every later fetch, at the fetch itself (`fetch_hybrid_key_pinned` / `fetchHybridKeyPinned`); a **changed** key is a hard refusal (`CliError::PinMismatch` / `KeyPinMismatchError` / `DesktopError::KeyPinMismatch`) with **nothing wrapped, nothing uploaded, and the pin store not mutated**. There is **no flag, option or default anywhere that accepts a changed key** — only the deliberate `sigil device repin <id> --yes`. For the **first** contact, pinning is worthless by construction, and the answer is the **safety number**: six 5-digit groups over the device id **and both halves** of the hybrid key, compared with the other person over a channel the server does not control. **This defense is only as good as that comparison actually happening.** Proven, not asserted: `pinning-interop.mjs` puts a **rewriting proxy** in front of a real `sigild`, and the client refuses while the stored envelope stays byte-identical to the honest one and does **not** open with the attacker's hybrid secret | Client-side trust store + human verification |

**What vault sharing does NOT defend (be explicit):**

- ⭐ **First contact is still trust-on-first-use unless a human actually compares
  the safety number.** Pinning fixes the *second* and every later fetch; it cannot
  fix the first, because a server that lies the very first time gets its lie
  pinned. `sigil device safety-number` (and the equivalent in the desktop, webapp
  and extension UIs) exists so two people can close that window over a phone call
  or in person — but **nothing forces them to**, nothing detects that they skipped
  it, and a share to a never-before-seen device proceeds with only a warning and a
  `first-sight` pin status. There is still **no key-transparency log and no
  cross-signature** binding a hybrid key to the device's already-enrolled Ed25519
  identity, which would remove the human from the loop; that remains the
  highest-value follow-up.
- **A user who blindly re-pins defeats the whole mechanism.** `device repin`
  requires `--yes`, and refuses outright if the `--safety-number` supplied does not
  match what the server is currently serving — but a user who runs it to make an
  error message go away has handed the attacker exactly what the block prevented.
  Re-pins are counted (`repins`) and shown by `sigil device pins`, so the *evidence*
  survives; the decision is still the human's, and it is unrecoverable.
- **Pinning protects the fetch, not the local machine.** The pin store is a `0600`
  file (native) or a field inside the sealed device-identity container (browsers).
  An attacker who can rewrite it — anything running as that user on a native
  client, anything in the origin/extension context of an *unlocked* browser client
  — can silence the alarm before it fires.
- **Rotation protects FUTURE content only.** `sigil vault rotate` draws a fresh
  vault key, re-seals the vault under it, re-wraps to exactly the named devices and
  deletes every other device's envelope — but a device that **already unwrapped**
  the previous key keeps that key and everything it had already copied.
  Cryptography cannot un-send a secret. The e2e proof states this in both
  directions: after a rotation the removed device cannot read **new** content, and
  it still opens the container it pulled **before**.
- **Revocation still does not re-key anything by itself.** Rotation is a separate,
  **manual, owner-driven** operation. Nothing re-keys a vault when a grant is
  dropped, nothing expires an envelope, nothing schedules a rotation, and there is
  **no forward secrecy** for a vault key already delivered. Republishing a hybrid
  key does **not** re-wrap envelopes already deposited for that device.
- **None of this is audited.** Pinning, the safety-number construction and the
  rotation flow are new, unaudited code in the same dev-gated, plain-HTTP,
  pre-audit posture as everything around them.
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
  user's home directory as that user has the vault keys (adversary class 9 above) — and
  can also rewrite `hybrid-pins.json` to silence the key-substitution alarm. In
  the **browser clients** both are sealed under the vault password inside the v3
  device-identity container (which now also carries the pin store), which is **stronger
  at rest** but **not** while unlocked: the
  decrypted key material sits unzeroized in the JS heap, reachable by anything running
  in that origin/extension context (see the browser-sharing subsection above).
- **Plain HTTP in dev.** Signing proves who sent a request; it is not transport
  security.

## Recovery kit adversaries (dev-gated — see [ADR 0042](decisions/0042-recovery-kit.md))

Phase 54 addressed the **data** half of the account model's worst limitation: a
**recovery kit** is an **ordinary member device** whose Ed25519 and hybrid private
keys are HKDF-SHA256 derivations of 32 bytes of client CSPRNG **printed on paper**
— never transmitted, never stored on a device, never derivable from anything the
server holds.

⭐ **`sigild` gained no concept of "recovery"**: no table, no migration
(`sigild_schema_version` stays **5**), no new auth path. It sees one more device
row, one more hybrid **public** key, and one more opaque ~1226-byte envelope per
covered vault — shapes it already relayed. So **adversary classes 4 and 5 are
unchanged**: the server still cannot decrypt anything, and it holds nothing that
would help someone forge or recover a kit.

**The new capabilities are entirely off-server**, and one of them is severe.

| # | Adversary | Capability | Defense as implemented | Layer |
| --- | --- | --- | --- | --- |
| AE | ⚠️ **Whoever holds the printed sheet** | Has 56 characters on paper — from a drawer, a photo, a filing cabinet, a bin, an estate | ⚠️ **Essentially none, by construction.** The sheet **IS** the credential: it confers **immediate, un-delayed, un-notified, full account control** — read every **covered** vault and **revoke every device**. It is **stronger than a stolen locked phone**: there is no OS lock, no biometric and **no vault password** in front of it, and its nominal `read` grant is **cosmetic** because account ownership authorizes it anyway. What exists is a **checksum** (a mistyped code is refused offline, not silently wrong), **`sigil recovery revoke`** (which bites on the kit's very next request), the fact that it opens **only the vaults it was told to cover**, and **audit visibility** (its use looks like an ordinary device's). The real control is **physical**: treat the sheet as the account | Physical / operational |
| AF | **A server that lies about device labels** | Owns the registry; renames or hides the `"recovery-kit"` label in `GET /v1/account` so a wrap to a kit is not recognised as one | ⚠️ **Partially defended, and this is the phase's stated residual.** Recognising a recipient *as a kit* resolves the **label** from a listing the adversary serves, so a lying server **degrades `vault share` / `vault rotate` to a kit back to ordinary first-sight TOFU (warned and pinned) rather than a refusal**. What it **cannot** do: the caller-**asserted** paths (`sigil recovery cover`, `sigil recovery generate`) do not consult the server at all, and **no path anywhere accepts a CHANGED key or a mismatched safety number** — the pin check and the supplied-safety-number check are independent of the label. The honest claim is therefore **"refuses first-sight kit wraps against a server that does not lie about labels"**, *not* "refuses first-sight kit wraps". A verifier judged this consistent with [ADR 0038](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)'s already-accepted TOFU-on-first-contact limit | Client-side trust store |
| AG | **Key-substituting server, aiming at the kit** | Answers the kit's `GET /v1/devices/{kitID}/hybrid-key` with **its own** key, so the vault key is wrapped to the server instead of to the paper | **Blocked on the paths that matter, by the same choke point as every other wrap** — and hardened in this phase: the pinned fetch is now reached only through `verify_recipient_for_wrap`, which returns a **`VerifiedRecipient`** whose fields are private and which has **no other constructor**, so a wrap **cannot compile** without passing the gate. A **first-sight** wrap to a device known to be a kit is **REFUSED** (`UnverifiedRecoveryKit`) unless the caller supplies the safety number — and ⭐ **the kit's safety number is printed on its own sheet**, so the out-of-band channel is in the same hand as the code. A key **derived** locally from the recovery secret is never fetched at all (`Derived`). ⚠️ Reaching this rule depends on adversary **AF** above | Client-side trust store + printed sheet |
| AH | **Kit prober / enumerator** | Steals or guesses a kit's device id and asks what it can reach | `GET /v1/devices/{deviceID}/keys` is **self-only**, checked **before any store read**: a mismatched id is **`403`**, and an **unknown** device id is the **same coarse `403`, never `404`** — no existence oracle. It returns **metadata only, never a blob** (Postgres selects `octet_length(blob)`), and each row is additionally filtered by the ordinary `read` authorization. Collecting an envelope still requires the kit's **private** key, which exists only on paper | `sigild` authorization |

**What the recovery kit does NOT defend (be explicit):**

- ⚠️ **It recovers KEYS, not DATA.** A vault that was never synced to the server is
  gone; a kit can unwrap a key for ciphertext that exists, not conjure ciphertext
  that does not.
- ⚠️ **It only opens the vaults it was told to COVER**, as of the print date. A
  vault created later needs `sigil recovery cover`, and nothing reminds anyone.
- ⚠️ **A kit cannot be created after the loss.** It is print-it-before-you-need-it,
  with the same failure mode as every backup.
- ⚠️ **A kit consumes a seat** against `SIGILD_ACCOUNT_MAX_DEVICES`, is listed in
  `GET /v1/account`, and **any member may revoke it** — membership is flat.
- ⚠️ **Revoking a kit cannot un-learn** what it already unwrapped; the remediation
  is `vault rotate`, which protects **future content only** and will **refuse** to
  silently drop a kit from a vault's recipient set.
- ⚠️ **No zeroization** of the decoded secret or the derived keys, on any client.
- ⚠️ **`--code` still puts the secret in `argv`** (and shell history). It is warned
  about on stderr, not removed, because scripts need it; the prompt and
  `--code-stdin` paths avoid it.
- **Client coverage is complete across all four surfaces since Phase 56** — the
  `sigil` CLI, the webapp, the MV3 extension and the desktop can each generate,
  cover, check, revoke and **restore** (restore is reachable from the browsers'
  setup/locked screens, because `restore` runs on a **new install**). ⚠️ The
  browser suites drive a **test double** for everything except the webapp's
  `cors.spec.ts`; real-server conformance stays in `cli/tests/e2e-recovery.sh` and
  `sigil-wasm/test/recovery-interop.mjs`. ⚠️ A **browser** client additionally
  needs its origin allowlisted in `SIGILD_CORS_ORIGINS`
  ([ADR 0044](decisions/0044-opt-in-cors-allowlist.md)) or the browser blocks the
  request before it is sent — which is not a defence, only a reachability
  requirement.
- ⚠️ **Dev-gated, plain HTTP in dev, UNAUDITED**, and the codec, derivation and
  gate are all new code.

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
| K | **Replayer** | Captures a genuine, validly-signed webhook and re-sends it | Two independent bounds. **In-scheme (Stripe only):** the signed message includes the timestamp `t` and the delivery is rejected when `abs(now − t) > 5 min`, checked in **both** directions (a far-future timestamp is as suspect as a stale one). **Cross-provider:** the **idempotency ledger** makes a replay a **no-op that still answers `200`** — the state change and the ledger claim are one atomic operation (one mutex in memory; one transaction with `INSERT … ON CONFLICT DO NOTHING` + `SELECT … FOR UPDATE` in Postgres), so a replay cannot double-apply even under concurrency. ⭐ **The ledger key is derived only from bytes the provider's signature covers** ([ADR 0039](decisions/0039-webhook-idempotency-from-signed-bytes.md)) — Stripe's event id sits inside the signed payload; **Razorpay's key is always `SHA-256(raw body)`**, never the `X-Razorpay-Event-Id` header, because Razorpay signs the body and nothing else, so a captured delivery replayed with a fresh header would otherwise have been processed as a **new** event and grown the processed-events ledger on demand; Juspay's comes out of the body too. Razorpay and Juspay carry **no timestamp element**, so for them the ledger is the *only* replay bound — and it is why a redelivery *inside* a restart of the **non-durable in-memory** store could still be applied twice | `sigild` webhook auth + store |
| L | **Body tamperer** | Man-in-the-middle mutates the JSON (amount, subject, status) of an otherwise genuine delivery | The MAC is computed over the **exact bytes read off the wire**, never over re-serialized JSON — a re-encode changes key order and whitespace and would either break verification or, if "fixed" by re-signing, let an attacker mutate the body freely. Any mutation therefore fails verification → `401`. Tests assert this explicitly (a semantically-equal re-encode is rejected). **Exception, stated plainly:** Juspay's `basic` scheme authenticates the **connection**, not the body — it does **not** defend against this adversary. That is why `hmac` is now the **default** and `basic` must be requested by name and is warned about at every boot ([ADR 0039](decisions/0039-webhook-idempotency-from-signed-bytes.md)); where only `basic` is available, TLS is unconditional | `sigild` webhook auth |
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
- ⛔ **Denial of service against the webhook endpoint — and the rate limiter that
  was built for it was REMOVED as HARMFUL.** There is deliberately **no rate
  limiting** on `/v1/billing/webhook/{provider}`; the only bounds are the 64 KiB
  body cap and the cost of one HMAC over a size-capped buffer (no database round
  trip, no state created, before the signature verifies). An early Phase 53
  revision limited the route **before** signature verification, keyed on the
  **provider name** — the only key available at that point, and one **forged
  traffic controls too**. A verifier reproduced the result on a live server: one
  unauthenticated thread at ~137 forged requests/second caused **15 of 15 genuine,
  correctly-signed Stripe deliveries to be shed with `429`**, and a longer flood
  shed roughly **2,000 consecutive genuine retries**; **zero payment events were
  applied**, and the customer was then refused with `402` by entitlement
  enforcement. A provider's retry budget is **finite**, so those events are lost
  **permanently**. ⭐ **The rule this teaches:** you cannot safely shed traffic on
  a route where shedding costs money and the legitimate sender has a finite retry
  budget — limiting *before* verification lets anonymous forged traffic spend the
  honest sender's quota, and limiting *after* verification is no better, because
  an authentic burst is exactly what must never be dropped. **Volume protection
  for this route belongs at the edge**
  ([ADR 0041](decisions/0041-abuse-bounds-and-the-removed-webhook-limiter.md)).
- **Entitlement enforcement changes what a webhook compromise can do.** With
  `SIGILD_ENTITLEMENT_ENFORCE` on, an attacker who can mint authentic-looking
  `subscription_canceled` events can drive an account past its grace period and
  **stop its writes**. ⭐ It still **cannot stop its reads**: a lapsed account can
  always read every op, collect every key envelope, key a **replacement device of
  its own account**, print a recovery kit, revoke a stolen device and pay
  ([ADR 0043](decisions/0043-entitlement-enforcement.md)). Refusal is also never
  destructive — nothing is deleted and nothing expires.
- **The in-memory subscription store is non-durable.** Subscriptions *and* the
  processed-event ledger are lost on restart, so a webhook redelivered across a
  restart **can be applied twice**. Only the Postgres backend gives the
  idempotency guarantee across processes and restarts.
- **Transport.** In any real deployment the webhook endpoint **must** be reachable
  only over TLS. The dev server speaks plain HTTP, and Juspay's `basic` scheme in
  particular is a bearer credential with no body binding.
- ⚠️ **Scope of the "idempotency key comes from signature-covered bytes"
  invariant.** It holds for **Stripe**, **Razorpay**, and **Juspay under
  `scheme=hmac`**. Under **Juspay `scheme=basic` it is vacuous**: that scheme
  authenticates the connection and covers **no bytes at all**, so there is nothing
  for a dedup key to be derived *from*, and adversaries K and L are simply not
  defended against there. No amount of key derivation fixes an authentication
  scheme that signs nothing — which is the reason the default was moved to `hmac`
  ([ADR 0039](decisions/0039-webhook-idempotency-from-signed-bytes.md)) rather than
  the reason it is safe to leave on `basic`.

**Status note for this repo:** almost none of the defenses in the **first** table
(adversary classes 1–12, the *intended product* design) is implemented yet — two
rows are partial and both are worth stating precisely.

Class 8 (*insider with vault export*) has its **mechanism** complete and driveable
end to end: `vault rotate` re-keys a vault and re-wraps it to exactly the remaining
members' hybrid public keys, deleting the departing device's envelope. The
**workflow** around it is still missing — nothing re-keys **automatically** on
revoke, a rotation is a manual owner-driven command, and revocation still cannot
recall a key already unwrapped, so the row's promise holds only for content
written *after* the rotation.

⚠️ **Class 12 (*lost master password / lost every device*) is the row most likely
to be misread, so read its cell again.** What exists is a **printed 56-character
recovery kit** and nothing else: **no recovery delegates, no delay window, no
notification, no veto, and no passkey-bound recovery.** The kit gives its holder
**immediate, un-delayed, un-notified, full account control**, and it must be
printed **before** the loss. What the row's original promise *does* still hold: the
secret never reaches the server, so **Sigil cannot decrypt unilaterally**. See
[Recovery kit adversaries](#recovery-kit-adversaries-dev-gated--see-adr-0042).

The current `sigild` skeleton performs no crypto on vault contents and
stores only the opaque blobs and opaque envelopes described above. `libsigil`'s
crypto is still **UNAUDITED**, and it is **no longer all unused**: the hybrid KEM
and the `hybrid_seal` / `hybrid_open` composition are now **load-bearing** (they
wrap vault keys), while the hybrid **signature** and the suite-frame `kem_ct` path
remain wired into nothing. The later tables (the dev op-log request-auth surface
A–I2, the account boundary Y–AD, the vault-sharing surface R–X, the recovery-kit
surface AE–AH, and the billing surface J–Q) *are* implemented —
that code really runs — but they are **dev-gated, off by default, opt-in, and
UNAUDITED**, and they are a request-auth and key-distribution model for a dev
op-log, **not** the product's account, session, or key-management model. Do not represent any of this as live or as a security
guarantee.
