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
see the next section). It is a local-wiring scaffold only and **must never be
exposed publicly or hold real secrets**.

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

**Zero-knowledge is unaffected by the auth model.** The registry stores **auth
metadata only** — Ed25519 **public** keys, server-assigned IDs, labels,
permissions, timestamps, and a bearer token's SHA-256 digest. Migration
`0002_devices.sql` touches **nothing** in the op-log table, so the opaque blob
and its tamper-evidence hash chain are byte-for-byte unchanged, and the server
still performs **no cryptography on vault contents**. Adding authentication did
**not** give the server any ability to decrypt: adversary classes 4 and 5 above
are unchanged. Correspondingly, the audit and metrics surfaces never record a
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

**Status note for this repo:** none of the defenses in the **first** table
(adversary classes 1–12, the *intended product* design) is implemented yet. The
current `sigild` skeleton performs no crypto on vault contents and stores only
the opaque blobs described above; `libsigil` has real-but-**unaudited** crypto
building blocks not wired into any product flow. The **second** table (the dev
op-log request-auth surface, A–I) *is* implemented — that code really runs — but
it is **dev-gated, off by default, opt-in, and UNAUDITED**, and it is a
request-auth model for a dev op-log, **not** the product's account, session, or
key-management model. Do not represent any of this as live or as a security
guarantee.
