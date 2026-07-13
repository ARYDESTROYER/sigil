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
`SIGILD_ENABLE_DEV_OPS`, otherwise `501`), **in-memory / non-durable**, and
**UNAUTHENTICATED** — it has no access control whatsoever. It is a local-wiring
scaffold only and **must never be exposed publicly or hold real secrets**; a
production op-log will add device-key auth, per-vault authorization, and durable
storage, while still storing only opaque ciphertext.

**Audit log preserves zero-knowledge.** The dev op-log emits a **structured
audit log** of every append, list, and **auth denial**, but it records only
**metadata plus a SHA-256 integrity fingerprint of the opaque ciphertext** — the
server **never logs plaintext, keys, blob content, or the request signature /
nonce**. Fingerprinting bytes that are *already* client-encrypted gives an
operator a *who-appended-what-when* trail (a dev-scale down-payment on adversary
#4's "signed append-only audit log") **without weakening the zero-knowledge
property**: the log reveals nothing the server did not already store, and the
server still cannot decrypt a vault. Auth denials are audited with their reason
(missing / invalid / stale / replayed signature), so failed access attempts
against a `SIGILD_OPLOG_PUBKEY`-guarded op-log are visible. This is still the
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

**Status note for this repo:** none of the defenses in the table above is
implemented yet. The current `sigild` skeleton performs no crypto, runs no auth,
and stores only the opaque blobs described above; `libsigil` has real-but-
**unaudited** crypto building blocks not wired into any product flow. Do not
represent these defenses as live.
