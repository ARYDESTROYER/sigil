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
| 3 | Determined attacker w/ device | Has the phone + lock code | Master password is a separate second layer; optional passkey 2nd factor; remote-wipe invalidates device key + re-encrypts on remaining devices. ⚠️ **Partially real since Phase 58, and narrower than this row sounds:** the **webapp** can mix a WebAuthn PRF output into the **at-rest seal** of its containers ([ADR 0046](decisions/0046-passkey-protected-local-containers.md), [section below](#browser-profiles-protected-by-a-passkey-webapp-only--see-adr-0046)). That is a second factor on **stored bytes**, not on login and not on a live session; the extension and desktop do not have it, and there is still **no remote wipe** | Client + server |
| 4 | Rogue Sigil employee w/ DB access | Reads production DB | Server holds only ciphertext; signed append-only audit log; two-person, time-bound prod access (operational) — architecture is the real defense | Architecture |
| 5 | Compromised sync server | Owns the backend | Client-side decryption; ops signed by device keys (can't forge); replay/drop detected via Lamport clock + Merkle root | Architecture + crypto |
| 6 | State-level wiretap | Captures all traffic | TLS 1.3 hybrid-PQ named group; double-layer (TLS + AEAD); forward secrecy via ephemeral X25519 + ML-KEM | Transport + crypto |
| 7 | Future CRQC | Records now, decrypts ~2035 with Shor's | Hybrid X25519&ML-KEM-768 KEX + Ed25519&ML-DSA-65 sigs; breaking needs Shor's *and* an MLWE break | Crypto |
| 8 | Insider with vault export | Departing family/team member | Re-encrypt on revoke; vault keys rotated, content re-encrypted to remaining members' KEM pubkeys | Server + workflow |
| 9 | Compromised OS reading memory | Reads memory between apps | Master key in mlock'd pages; secure enclave where available; minimal in-memory residence; wipe on lock | OS / hardware |
| 10 | Browser malware | Reads extension state | Extension storage encrypted under master-password-derived key; user-initiated actions only; clipboard cleared after 3s; HTTPS enforced | Extension hardening |
| 11 | Push-notification operator | Reads push payloads | Payloads carry only opaque vault ID + wake hint; approval blobs decryptable only by the user's other devices | Architecture |
| 12 | Lost master password / lost every device | User locked out | ⚠️ **What ships is a printed 56-character recovery kit and NOTHING ELSE** ([ADR 0042](decisions/0042-recovery-kit.md), [Recovery kit](#recovery-kit-adversaries-dev-gated--see-adr-0042) below). It confers **IMMEDIATE, un-delayed, un-notified, full account takeover** to whoever holds the paper. There is **no recovery delegate**, **no delay window**, **no notification**, **no veto**, and **no passkey-bound recovery** — do not read this row as if there were. (⚠️ Phase 58 runs the dependency the OTHER way: the printed sheet is the break-glass **for** a passkey-protected profile, so a lost passkey costs nothing — but a lost sheet is still unrecoverable, and no passkey can substitute for it. See [ADR 0046](decisions/0046-passkey-protected-local-containers.md).) It does keep the property that **Sigil cannot decrypt unilaterally**, because the secret never reaches the server; and it must be **printed in advance** or it does not exist | Workflow + client |
| 13 | **Writer of a hostile container** (added Phase 59) | Puts **one opaque blob** in a vault's op-log — available to a revoked-but-not-yet-rotated device, a co-tenant of a shared vault, or a breached server | ⚠️ **An availability attack, not a confidentiality one, and the server cannot defend against it by construction** — it stores opaque blobs and filtering would mean parsing what it is designed not to understand. The container header's Argon2id work factors are unauthenticated framing, and Argon2id allocates `m_cost` KiB in one block: measured, a 4 TiB request ran 12.57 s, peaked at ≈ 90 GB and was killed. Defense is a **client-side ceiling checked before any allocation** ([ADR 0047](decisions/0047-container-parameter-ceiling-and-no-downgrade-ratchet.md), [section below](#writer-of-a-hostile-container-client-side-denial-of-service--see-adr-0047)) — which makes the refusal cheap but **does not remove the blob** | Client |

**Server-stores-opaque-blobs property.** Even where `sigild` does hold data, it
holds **only opaque client-encrypted blobs** — never plaintext and never keys.
The server does no cryptography **on what it stores** and never decrypts or
interprets it (it does verify Ed25519 request signatures, hash-chain ops with
SHA-256 and verify webhook HMACs — none of those keys can open a vault),
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
  ⚠️ **Vault IDs are NOT high-entropy** — an earlier version of this bullet said
  they were "client-chosen high-entropy identifiers". They are client-chosen
  strings, frequently human-chosen: the webapp's default is the literal
  `"webapp-demo"`. Guessing is not required. There is now an account model, but it
  is **not an identity system** and **not** sufficient for production.
- **A rejected write NO LONGER claims — but well-formed squatting is still
  unbounded** (Phase 57,
  [ADR 0045](decisions/0045-claim-precondition-rejected-writes-never-claim.md)).
  The claim used to fire inside authorization, ahead of the handler's shape
  checks, so **50 empty-bodied appends across 50 made-up vault ids answered `400`,
  stored nothing, and took all 50 ids permanently** — free, silent, and invisible
  to the per-vault rate limiter, which keys on the id the attacker varies. A cheap
  vault-independent precondition now downgrades a request that is going to be
  refused so it cannot claim (an empty write to an **unowned** vault therefore
  answers `403`, not `400`). ⚠️ **What is still undefended:** an authenticated
  device can squat ids with **genuinely well-formed** writes. Each one is stored,
  entitlement-checked and audited, so it costs something — but **there is no
  per-account claim budget**, and the correct bound must never be keyed on the
  vault id, which the attacker controls.
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
  Argon2id work as the vault. ⚠️ **In the webapp, "under the vault password" is no
  longer the whole story once passkey protection is on** — see
  [the next subsection](#browser-profiles-protected-by-a-passkey-webapp-only--see-adr-0046).
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

### Browser profiles protected by a passkey (webapp only — see [ADR 0046](decisions/0046-passkey-protected-local-containers.md))

Everything above assumes the sealing secret is a **human password**. That is the
weak link in the client story: the PQ-hybrid wrap, the type-enforced wrap gate,
key pinning and the paper kit are all reachable by guessing one password offline,
at whatever rate the attacker's hardware allows against our Argon2id parameters.

**The adversary this addresses: someone who has the browser profile but not the
authenticator.** A copied `localStorage`, a stolen or synced backup, a
disk image, a shared or resold machine, a support-tool export, a malicious sync
extension that exfiltrates web storage — anything that yields the *stored bytes*
without a live session.

With protection on (webapp only), both containers are sealed under a 32-byte
**container master key** rather than the password, and the CMK is wrapped in a
third sealed container under `PRF(32) ‖ utf8(password)` — the PRF output of a
WebAuthn credential, which never leaves the authenticator and is not derivable from
anything on disk. That adversary must now hold **the password AND the
authenticator**.

- ⭐ **AND, never OR.** While protection is on there is **no password-only slot**.
  The two doors are (password AND passkey) and (the printed
  [ADR 0042](decisions/0042-recovery-kit.md) sheet). An OR design would be theatre
  — an offline attacker would simply attack the weaker branch.
- **The break-glass is the sheet already printed**, which derives the same CMK
  offline. Every way a passkey becomes unavailable — lost laptop, cleared profile,
  revoked platform credential, a browser that drops PRF, a cancelled ceremony —
  lands there, with no server and no network. This is why enabling **refuses**
  unless an active kit exists, and why the break-glass form is always reachable on
  the locked screen.
- **`sigild` gained nothing**: no route, header, canonical message, migration,
  table, metric or dependency. A hostile server cannot disable, weaken, detect or
  observe this. Adversary classes 4 and 5 are unchanged.

**What this explicitly does NOT defend against:**

- ⛔ **It defends STORAGE, never EXECUTION.** Anything running in the origin while
  the vault is unlocked (XSS, a malicious extension, a hostile dependency) reads
  the plaintext vault, the Ed25519 seed, the hybrid secret, every vault key, the
  password, the PRF output **and the CMK**. This is unchanged from the rows above.
- ⛔ **It is NOT retroactive.** Only containers re-sealed *after* protection is
  enabled are protected. Earlier copies, backups and forensic images stay
  password-only **forever** — so an attacker who took a snapshot before the switch
  keeps the weaker target.
- ⛔ **An attacker who can DRIVE the authenticator gets `R`.** An unlocked device in
  hand, a coerced user-verification prompt, or malware on the machine at unlock time
  yields the PRF output. What remains between them and the CMK is Argon2id over the
  password — which is why the password is fed to Argon2id **directly** rather than
  through a cheap KDF first.
- ⛔ **User verification is a policy request, not a proof.** We ask for it and read
  a flag. We cannot verify a human was verified, and a lying authenticator is
  undetectable. No attestation is requested, so we make **no claim** about the kind
  of authenticator in use.
- ⛔ **A backup-eligible credential is a new third-party custodian.** It syncs to a
  platform account or password manager, so the second factor becomes as strong as
  that account. The UI says so, derived from the flags of the ceremony that just
  ran; it does not prevent it.
- ⛔ **Whoever holds the printed sheet now also holds local unlock** — without the
  password and without the passkey. The paper was already a full-account credential
  ([ADR 0042](decisions/0042-recovery-kit.md) limitation 1); its reach grew here.
- ⛔ **It is not phishing resistance, not 2FA for login, and not a hardware
  guarantee.** It is a second factor on an **at-rest seal** in one browser profile.
- ⛔ **Only the webapp has it.** The MV3 extension and the native desktop do not, so
  a user can hold a protected profile on one surface and an unprotected one on
  another. That is scope, not a technical block.
- ⛔ **A protected personal vault refuses sync in both directions**, so the local
  copy is the only copy — a device loss is a data loss unless the vault is converted
  to a shared one. The kit recovers **keys, not data**.
- ⛔ **No zeroization**, as everywhere else: the CMK and the PRF output sit in JS
  `Uint8Array`s while the vault is unlocked.

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
  mirroring — it calls the same `sigil-cli` functions (`verify_recipient_for_wrap`,
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
[`crypto-spec.md`](crypto-spec.md#key-hierarchy-and-vault-sharing-hybrid_auth_seal--hybrid_auth_open-in-use).

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
| V | **Envelope forger / replayer / substituter** | Mints an envelope of its own, re-sends a captured deposit, or swaps one envelope for another | ⚠️ **THIS ROW WAS WRONG UNTIL PHASE 60 — see the correction directly below.** The transport is the **v3 signed request contract** (see table above): the body is *inside* the signed message, so a mutated envelope invalidates the signature, and the ±300 s window plus the single-use nonce bound replay. Depositing requires **write** on the vault, so a passive observer cannot deposit anything. And a **forged or re-filed** envelope now fails to open: the wrap is an **authenticated** hybrid KEM ([ADR 0048](decisions/0048-authenticated-vault-key-envelopes.md)) mixing a **static-static X25519 DH between sender and recipient**, so producing an acceptable envelope needs the **sender's** secret and not merely the recipient's published public key; the AAD names the **purpose, vault, recipient and sender**, so an envelope cannot be moved between vaults, recipients, senders or purposes; a **version-1 (anonymous) container is refused outright**; and the unwrap runs only behind the typed `VerifiedSender` gate, which pin-checks the depositing device's hybrid key. ⛔ **First sight of a sender is still TOFU** (adversary **X**), and **authentication is classical X25519 only** — confidentiality is hybrid, authenticity is not | `sigild` request auth + crypto |
| W | **Log / metrics scraper hunting for key material** | Reads `sigild`'s audit log or scrapes `/metrics` | The three sharing audit events carry **metadata plus a SHA-256 fingerprint** only (`vault.key_envelope_put` / `_get`: vault ID, device IDs, size, `blob_sha256`; `device.hybrid_key_published`: a device ID). **No envelope byte, no vault key, and no hybrid public key is ever logged** — the "no key material in logs" rule is kept absolute even for *public* keys, so there is no judgement call to get wrong later. The `/metrics` counters are counts with **no vault or device label** (Phase 50's `sigild_key_envelope_deletes_total` included). The two Phase 50 events (`vault.key_envelope_list` / `_delete`) carry device IDs and a count and have **no blob to fingerprint**. Asserted by a test and by the e2e script, which fails if `SIGILhyb` appears in the server log | `sigild` observability |
| X | **Key-substituting server / rogue registry** (Phase 50) | Owns the registry; answers `GET /v1/devices/{B}/hybrid-key` with **its own** hybrid public key so the next share is wrapped to *it* | **Detected and blocked after first contact — not prevented at first contact.** Every client **pins** the first hybrid public key it sees for a device and compares on every later fetch, at the fetch itself (`verify_recipient_for_wrap` / `verifyRecipientForWrap` — the earlier `fetch_hybrid_key_pinned` / `fetchHybridKeyPinned` were superseded in Phase 54 and **deleted** in Phase 57, because an exported fetch-and-pin sitting next to a stricter gate is a ready-made bypass); a **changed** key is a hard refusal (`CliError::PinMismatch` / `KeyPinMismatchError` / `DesktopError::KeyPinMismatch`) with **nothing wrapped, nothing uploaded, and the pin store not mutated**. There is **no flag, option or default anywhere that accepts a changed key** — only the deliberate `sigil device repin <id> --yes`. For the **first** contact, pinning is worthless by construction, and the answer is the **safety number**: six 5-digit groups over the device id **and both halves** of the hybrid key, compared with the other person over a channel the server does not control. **This defense is only as good as that comparison actually happening.** Proven, not asserted: `pinning-interop.mjs` puts a **rewriting proxy** in front of a real `sigild`, and the client refuses while the stored envelope stays byte-identical to the honest one and does **not** open with the attacker's hybrid secret | Client-side trust store + human verification |

### ⚠️ CORRECTION — row V asserted a defense that did not exist (Phase 60)

**This is recorded rather than quietly rewritten, because the false sentence sat
exactly where a reviewer decides whether to look further.** Until Phase 60, row V
read:

> *"A substituted envelope also **fails to open**: `hybrid_open` authenticates, so
> a wrong or tampered container yields an authentication failure, never plaintext,
> and `unwrap_vault_key` additionally rejects any recovered plaintext that is not
> exactly 32 bytes rather than using it as a key."*

**That was true of a TAMPERED envelope and false of a freshly minted valid one —
which is the actual attack.** The wrap used the **anonymous** `hybrid_seal` (HPKE
`mode_base`), so anyone holding the recipient's **published** hybrid public key —
which `sigild` serves to every authenticated device — could mint a container that
recipient would open, and install a vault key **of their own choosing**. The
second clause was true and irrelevant: **a forged key is exactly 32 bytes**, so
the length check passes. Reproduced with the shipped binary and nothing else:

```
$ sigil hybrid-seal --recipient-pub b.hybrid.pub --in attacker_key.bin --out forged.env
    forged.env: 1226 bytes, magic SIGILhyb   <- byte-shaped IDENTICALLY to a genuine wrap
$ sigil hybrid-open --key b.hybrid --in forged.env --out recovered.bin
    exit=0   recovered = 32 bytes, IDENTICAL to the attacker's chosen key
```

⛔ **And adversary X's pinning did not mitigate it:** `vault accept` fetched no
hybrid key at all, so the pin store was **never consulted** on the unwrap path.
Two attacks were driven against a live `sigild` — a rewriting proxy whose forged
envelope `vault accept` took with **exit 0 and no warning**, and a co-tenant with
`write` but not ownership whose deposit landed because the envelope was **PUT
before the grant was requested**.

Fixed in Phase 60 by an authenticated hybrid KEM, a context-bound AAD, a
container version bump that **refuses v1**, a typed `VerifiedSender` unwrap gate,
open-before-write, and grant-before-deposit — see
[ADR 0048](decisions/0048-authenticated-vault-key-envelopes.md), whose *Honest
limits* section is as load-bearing as its *Decision*.

⚠️ **The generalisable lesson: this was not a stale doc.** It was written
alongside the code and was wrong the day it was written, because it described the
*intent* of the flow rather than what the primitive underneath it does. No drift
check would have caught it, because nothing drifted.

**What vault sharing does NOT defend (be explicit):**

- ⛔ **Sender authentication is CLASSICAL X25519 ONLY** ([ADR 0048](decisions/0048-authenticated-vault-key-envelopes.md)).
  ML-KEM has no static-static analogue, so the guarantees are **asymmetric**:
  breaking **confidentiality** requires breaking **both** X25519 and ML-KEM-768;
  forging **authenticity** requires breaking **X25519 alone**. A quantum
  adversary could forge an envelope it still could not read. The authentication
  is also **implicit and NON-TRANSFERABLE** — it is key confirmation, not a
  signature, so the recipient cannot prove to a third party who sent it, and no
  audit or dispute process can rest on an envelope.
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
row, one more hybrid **public** key, and one more opaque ~1.3 KiB envelope per
covered vault — shapes it already relayed. (⚠️ Since Phase 60 that envelope is
**not a fixed size**: it is `1244 + len(vault_id) + len(recipient_device_id) +
len(sender_device_id)` bytes, because it carries its context AAD —
[ADR 0048](decisions/0048-authenticated-vault-key-envelopes.md). ⛔ A kit covered
**before** Phase 60 must be **re-covered**; its old envelopes are refused.) So **adversary classes 4 and 5 are
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
- ⚠️ **A kit covering more than 500 vaults SILENTLY RECOVERS THE FIRST 500 AND
  REPORTS SUCCESS** (Phase 57). `GET /v1/devices/{deviceID}/keys` caps at 500 rows
  and honestly sets `has_more`, but **no client in this repo reads it** and there
  is **no cursor** to page with. The person hitting this is by definition unable to
  check the result against anything, which is what makes a quiet truncation the
  wrong failure. Treat 500 covered vaults as the real ceiling until a cursor
  exists.
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

## Writer of a hostile container (client-side denial of service — see [ADR 0047](decisions/0047-container-parameter-ceiling-and-no-downgrade-ratchet.md))

**A new adversary class, added in Phase 59 because it was reachable and nothing
addressed it.** It is not a confidentiality attack — it takes nothing — it is an
**availability** attack on the client, and its delivery path is the property this
architecture is built around.

**Capability.** Write one opaque blob to a vault's op-log. That is available to
anyone with write access: a **revoked-but-not-yet-rotated device** (revocation
stops future access, but a blob already deposited stays), a **co-tenant of a
shared vault** ([ADR 0035](decisions/0035-device-to-device-vault-sharing.md)), or
a **breached or hostile server**, which can synthesise blobs freely because it
never had to understand them.

**The attack.** A `SIGILcli` header's Argon2id work factors are **unauthenticated
framing** — they are inputs to the KDF, so they must be readable before any key
exists. Argon2id allocates `m_cost` KiB **in one block before doing any work**.
Measured: `m_cost = 0xFFFF_FFF0` ran **12.57 s**, peaked at a **≈ 90 GB memory
footprint** on a 24 GB machine and was **killed**; `t_cost = 0xFFFF_FFF0`
extrapolates to **≈ 282 days** of CPU for a single open attempt. Every client that
pulls the vault dies, on every device, and the user cannot reach their own 2FA
codes.

⛔ **The server cannot defend against this, by construction.** `sigild` stores
opaque blobs and returns them verbatim; filtering would require parsing a blob it
is designed to be unable to interpret. **The property that makes the server safe
is the property that stops it helping here** — and that is the honest general
lesson: a zero-knowledge relay moves *every* content-validation duty to the
client.

**Defense.** A ceiling on the three work factors
(`MAX_M_COST` = 256 MiB, `MAX_T_COST` = 16, `MAX_P_COST` = 16) enforced in
`sigil-core` **at parse time, before any allocation**, and re-checked earlier
still by both container parsers so the failure is typed
(`CliError::ParamsOutOfRange`) and distinguishable from a wrong password. Measured
after the fix: **0.00 s, 1.18 MB peak footprint**, on the same bytes. Construction
in [`crypto-spec.md`](crypto-spec.md).

**What is NOT defended, and must be read with the row above:**

- ⛔ **The blob is not removed.** There is no delete-op route and no client-side
  quarantine, so it stays in the log and every client re-parses and re-refuses it
  **every time it syncs**. The refusal is cheap; the nuisance is permanent.
- ⛔ **Op-log quota and storage are still consumed.** The per-vault rate limiter
  ([ADR 0017](decisions/0017-oplog-scale-and-observability.md)) is **off by
  default** and bounds append *rate*, not the existence of one bad blob.
- ⚠️ **A container declaring the ceiling exactly (`256 MiB / 16 / 16`, legal, and
  1.64 s per open) is preserved by the no-downgrade ratchet forever** — a small,
  bounded, non-reversible cost an attacker can impose once.
- ⚠️ **Nothing here addresses a client that is fed a *malformed* container by other
  means** (a hostile file handed to `sigil open`, a tampered backup). The same
  parse-time bound applies, but the bound is the whole defense.
- ⚠️ This class was **not previously enumerated in this document**, which is worth
  recording: the model was written around confidentiality, and an availability
  attack delivered through the confidentiality mechanism had no row.

## Writer of a hostile provisioning payload (see [ADR 0051](decisions/0051-provisioning-bounds-and-qr-ingest.md))

**A new adversary class, added in Phase 63 because a live instance of it was
reproduced.** It is not an attack on the vault, on a key, or on the server. It is
an attack on **what the user believes about their own second factor**, and its
entry point is the one surface this product cannot avoid exposing: the text a
stranger's enrolment page hands you.

**Capability.** Get one string in front of a user's authenticator. Anything that
puts an `otpauth://` URI, an `otpauth-migration://` blob or a **QR code** in front
of them qualifies: a phishing "enable 2FA" page, a support email, a forum post, a
QR sticker, a screenshot pasted from a chat. **No account, no device, no vault
key, no server access is required.** This is the widest-reach adversary in this
document and the cheapest to be.

### The attack — a static secret in a rotating costume

A TOTP counter is `floor(unix_time / period)`. `period` was an unbounded `u32`, so
`otpauth://totp/Evil:victim?secret=…&period=4294967295` produced an entry whose
counter is `0` until roughly the year 2106. Measured on the shipped code:
**755224 at t=59, at t=1.9×10⁹ and at t=4×10⁹** — one code, forever.

⛔ **The harm is the disguise, not the freeze.** The entry rendered with a label,
an issuer and an **ordinary countdown**, indistinguishable from a real second
factor. The user believes they enabled 2FA. What they enabled is a static secret:
one shoulder-surf, one screenshot, one intercepted login stays valid indefinitely.
An obviously-broken entry costs a retry; an entry that **lies about rotating**
costs the protection the user thinks they have.

Adjacent capabilities in the same class: a label carrying `U+202E` RIGHT-TO-LEFT
OVERRIDE renders inside our own trusted UI as a *different issuer's name*; a
multi-kilobyte label or secret is sealed into the vault, pushed through the op-log
and re-rendered on every client forever; and a migration payload declaring
unbounded accounts was an allocation driven entirely by attacker input.

### ⭐ Why the QR door changed the risk

> **Every existing door to this defect had a human reading the URI. A QR is opaque
> to humans by construction, so it removes the last reviewer.**

Pasting a URI at least *permits* someone to notice `period=4294967295`. A
possibility is not a control, but it was the only thing there. A QR code has no
human-readable surface at all — point a camera at a phishing page's code, or paste
a screenshot someone sent you, and the payload reaches the parser with **no
opportunity for review at any point**. This is why the parser was hardened
**before** the scanner shipped: adding a frictionless ingest door on top of an
unbounded parser is adding a delivery mechanism to a known defect.

**Defense.** One gate, `sigil_core::validate_provisioning()`, mirrored once in JS,
reached by every ingest door in every client — `period ≤ 600`, `secret ≤ 1024 B`,
label and issuer `≤ 256` code points, no C0/C1 controls and no bidi
overrides/isolates (**ordinary RTL script untouched**), `digits ∈ 6..=10`, and
`≤ 512` accounts per payload checked **inside the decode loop**. Construction and
evidence in [`crypto-spec.md`](crypto-spec.md). The QR path adds **no second
parser and no second set of bounds** — it turns an image into a bounded string and
hands it to the gate — and it **never writes to the vault**, returning a payload
the user must confirm.

**What is NOT defended, and must be read with the section above:**

- ⛔ **The bounds are INGEST-ONLY and deliberately NOT retroactive.** A vault that
  already holds an out-of-bounds entry **still opens and still generates its
  codes**, and nothing sweeps or repairs it. Refusing to *read* would delete a
  working account — and under
  [ADR 0049](decisions/0049-entry-identity-and-the-mergeable-vault.md) the
  deletion would propagate to every device. The mitigation is a **read-path
  warning on all four clients that reports and never corrects**.
- ⛔ **The Phase 61 vault MERGE is an ingest door and is deliberately not gated.**
  A co-owner of a shared vault can push a snapshot containing an out-of-bounds
  entry and it is adopted. That is inside the stated trust model — reaching the
  merge requires the vault key ([0035](decisions/0035-device-to-device-vault-sharing.md)
  / [0038](decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md)), and a
  peer who can write entries can already write anything — and gating it would be
  the worse bug. Pinned by tests in both languages so it must be re-argued.
- ⚠️ **`sigil totp add --period N` is deliberately ungated**, so a CLI user can
  still create a frozen entry on purpose. The boundary is *provenance* — text that
  came from somewhere else — not *creation*.
- ⚠️ **512 accounts per payload can still produce a vault too large to sync**
  (`sigild` caps an op body at 64 KiB). All four clients now warn at import time,
  but the ceiling **bounds one payload, it does not promise the vault fits**, and
  there is still no `compact`.
- ⛔ **`BarcodeDetector` is secure-context gated, which is a product state and not
  only a testing note.** Measured in one browser, one session: `about:blank` and
  `http://<LAN-IP>:port` → **absent**; `http://localhost`, `http://127.0.0.1` and
  `file:///` → **present**. So **a page served over plain HTTP from anything other
  than localhost gets no scanner at all** — exactly the shape of pointing a phone
  at a dev laptop. Firefox and Safari do not implement it, and neither does Linux
  Chromium, so **no CI runner exercises the supported branch**; CI exercises the
  *unsupported* branch, which is a real assertion rather than a skip.
- ⚠️ **These are display and resource controls, not cryptographic ones.** They stop
  a stranger installing something that *looks* like a second factor and bound what
  one payload can cost. They say nothing about the secret itself, and there is
  deliberately **no floor** — a weak credential is the service's choice, and
  refusing it would lock the user out.

## Hostile server against a merging vault — tombstones (see [ADR 0049](decisions/0049-entry-identity-and-the-mergeable-vault.md))

**A new adversary class, added in Phase 61 with the merge itself.** Before it, a
client adopted the newest snapshot wholesale, so a server that wanted to suppress a
2FA account merely had to serve a snapshot without it. The merge is a strict
improvement — but it gives the server a **new object to manipulate**, the
**tombstone**, and a tombstone's whole job is to make an entry disappear. It is an
**integrity and availability** class, not a confidentiality one.

**Capability.** `sigild` stores, orders and serves the ops. It chooses **which**
ops a client sees, **in what order**, and **how many times**. It cannot read them
([ADR 0003](decisions/0003-dev-gated-opaque-op-log.md)) — every op is a sealed
`SIGILcli` container — so everything below is done blind, by position, size and
timing, never by content.

### What a hostile server CAN do

- ⛔ **Withhold ops — the strongest attack, and it is not new.** Serving a client a
  subset of the log hides whatever was in the omitted ops: an added account looks
  like it was never added. **Withholding a snapshot that contains a tombstone
  resurrects a deleted entry** on that client, which is worse than it sounds if the
  deletion was a response to a compromise — the user believes an account is gone
  and their authenticator still shows it. ⚠️ **A withheld op is indistinguishable
  from an op that was never pushed**, which is what makes this hard to detect and
  impossible to fix client-side today.
- ⛔ **Replay ops.** Re-serving an old snapshot is *harmless to convergence* (the
  merge is idempotent, so folding the same op twice changes nothing) but it is
  **not harmless in combination with withholding**: replaying a pre-delete snapshot
  while withholding the post-delete one is exactly the resurrection above.
- ⚠️ **Grow the vault toward the size cap.** Anyone with write access — including
  the server, which can synthesise blobs freely — can append snapshots carrying
  tombstones for ids that never existed. They are cheap, they are **carried
  forever** (nothing prunes a tombstone, ADR 0049 limit 1), and enough of them push
  the sealed vault past `sigild`'s own **64 KiB** op cap, after which the user's
  `push` answers **413** and **there is no supported way to shrink it**. ⚠️ Note the
  shape: the server is the entity enforcing the cap *and* an entity able to fill it.
  The clients warn from 75 % of the cap; that is a warning, not a defence.
- ⚠️ **Learn the coarse shape of the vault.** Op sizes and push timings leak roughly
  how many entries a vault holds and when it changed — **pre-existing**, unchanged
  by this work, and now slightly more informative because a delete produces a push
  that is *larger* than the one before it.

### What a hostile server CANNOT do

- ⭐ **It cannot forge a tombstone for an entry whose id it does not know**, because
  ids live **only inside the sealed vault**. A minted id is 16 random bytes; a
  derived id is a SHA-256 commitment to content the server has never seen. It can
  append tombstones for ids it invents, and they will name nothing.
- ⭐ **It cannot reorder its way to a different result.** The merge is
  **commutative, associative and idempotent on every field, including the unknown
  ones** — so the order the server serves ops in does not change the vault a client
  ends up with. Only the *set* it serves matters, which reduces the entire attack
  surface to withholding. ⚠️ That property was **not** unconditionally true when
  first claimed: tombstone-level unknown fields merged first-seen-wins, and it was
  fixed rather than qualified (ADR 0049 §3).
- ⭐ **It cannot read or modify an entry.** Everything is sealed client-side; the
  server relays ciphertext it cannot open, and a modified blob simply fails to
  decrypt.
- ⭐ **It cannot make a delete "stick" against a device that never saw it.** Delete
  is expressed as data (a tombstone) that must be *delivered*, not as an instruction
  the server executes.

### What is NOT defended

- ⛔ **There is no proof of completeness.** A client cannot tell "you have the whole
  log" from "you have the part I chose to give you". The op-log's hash chain
  ([ADR 0016](decisions/0016-tamper-evident-oplog-hash-chain.md)) is
  tamper-**evident** for ops a client is *shown* — it detects alteration,
  insertion, deletion and reordering **within the served range** — but a server that
  simply serves a **shorter prefix** produces a perfectly valid chain. Truncation is
  the gap, and it is unaddressed.
- ⛔ **There is no compaction, so the growth vector has no bound** other than the
  413 that ends syncing. See ADR 0049 limitation 1.
- ⚠️ **A mixed-version fleet weakens this further.** A client older than
  [ADR 0047](decisions/0047-container-parameter-ceiling-and-no-downgrade-ratchet.md)
  **strips tombstones it does not understand** and pushes the stripped snapshot
  back, resurrecting deletions with no attacker involved at all. A hostile server
  does not need to withhold anything if one device in the account is old enough to
  do the withholding for it.
- ⚠️ **`deleted_at` is attacker-influenced and deliberately inert.** It is written by
  whichever client performed the delete and merged by `min`, so a wrong or hostile
  clock can only make a delete look **earlier**, never postpone it. **Nothing reads
  it today**; a future compaction that keys on it would be trusting a timestamp an
  adversary can lower, and must be designed with that in mind.

## A server that lies about the time (the clock-skew diagnostic — see [ADR 0050](decisions/0050-confirmations-honest-claims-and-the-clock-diagnostic.md))

Every client can compare its own clock against a server's, reading the standard
HTTP **`Date`** header off an unauthenticated `GET /healthz`. This section exists to
bound what that hands an adversary, because the reading is **unauthenticated
plaintext over plain HTTP** and anyone who can see or serve the traffic can change
it.

### What a hostile server (or an on-path attacker) CAN do

- **Return a wrong `Date`.** It can invent skew where there is none, or report *clock
  OK* on a device whose clock is badly wrong. The effect is that the hint is wrong:
  the user is told to fix a clock that is fine, or is not told about one that is not.
- **Withhold the reading**, by refusing the request or omitting the header. The
  client then reports **NO CLOCK READING**, which is deliberately rendered as the
  *absence* of a report and never as "your clock is fine".
- **Correlate a poll.** `GET /healthz` is unauthenticated and carries no device id,
  so it reveals only that some client at that address asked for the time.

### What it CANNOT do

- ⛔ **It cannot change a single generated code.** Every client computes codes from
  its **own** system clock; `sigil-core` reads no clock at all
  ([ADR 0007](decisions/0007-caller-supplied-entropy-in-core.md)) and the instant is
  supplied by the host. No path anywhere feeds a server-supplied time into
  generation — a desktop test takes a reading a **billion seconds** out and the vault
  still prints the RFC 6238 vector `94287082`. **This is the reason a lying server is
  merely annoying rather than dangerous, and it is why "just sync to server time"
  was rejected.**
- ⛔ **No key, signature, envelope, grant or entitlement decision depends on it.** It
  is not an input to the signed-request contract (whose own ±300 s window is a
  separate, server-side mechanism), to the wrap gate, or to anything at rest.
- ⛔ **It learns nothing about a vault.** The route returns no data, and the request
  carries no vault id, device id or signature.

### What is NOT defended

- ⚠️ **The reading is not authenticated and is not meant to be.** Making it
  trustworthy would need a signed time service, which is a new surface, a new
  contract and a new key — for a hint whose worst outcome is being wrong.
- ⚠️ **An offline client gets no reading at all**, which is exactly the situation (a
  laptop with a dead clock battery) where the diagnostic would help most.
- ⚠️ **`deleted_at` and any other client-written timestamp remain attacker-influenced
  in the way described above.** This diagnostic does not, and is not intended to,
  make client clocks trustworthy to anyone else.

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
