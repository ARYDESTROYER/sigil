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

**Status note for this repo:** none of the above is implemented yet. The current
`sigild` skeleton stores no vault data and performs no crypto; `libsigil` has no
crypto. Do not represent these defenses as live.
