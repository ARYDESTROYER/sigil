# Architecture Decision Records

> **STATUS: pre-audit.** These ADRs describe the **current pre-launch skeleton**
> (the 72-hour foundation sprint, through the dev-gated op-log, the Ed25519
> sign/verify primitive and device-key request auth (v2, nonce/replay-hardened),
the file-backed and opt-in durable-Postgres dev op-log backends,
> its request-context / readiness / structured-audit-log hardening,
> its per-op tamper-evident hash chain,
> its stdlib op-log scale & observability layer (bounded/paginated reads,
> per-vault rate limiting, a Prometheus-text `/metrics` endpoint, and fail-fast
> config validation),
> its managed, versioned op-log schema migrations with a hash-chain-verified
> backup/restore runbook,
> the first client-side consumer of the wasm-pure core (the `sigil-wasm`
> `wasm-bindgen` binding, with JS-supplied entropy) and its `SIGILcli`-container
> interop with the CLI (seal in one, open in the other), that client's
> `SIGILhyb`-container **hybrid public-key** (X25519 + ML-KEM-768) interop with the
> CLI (the first browser exercise of the PQ-hybrid encryption path),
> that client **closing the client↔server sync loop** by push/pulling opaque
> containers to the dev `sigild` op-log (`sync.mjs`) with live-server + real-CLI
> cross-client interop,
> the RFC 4226/6238 **TOTP/HOTP** primitive and encrypted CLI TOTP vault, and its
> **browser TOTP vault** that makes the authenticator work **cross-client** (a
> secret added on one client and synced through the opaque op-log yields the same
> code on the other), the CLI's **TOTP import/export** (Google Authenticator
> `otpauth-migration://` bulk import via a hand-rolled dependency-free protobuf codec,
> plus `otpauth://`, for migrate-in / no-lock-in) and the **browser client's matching
> TOTP import/export** (the migration codec mirrored in JS and proven wire-compatible
> with the CLI by a Node cross-tool test, so both clients have full import/export),
> the **first real browser webapp** (`web/apps/webapp` over the `@sigil/wasm` loader,
> running libsigil-via-WebAssembly client-side as a real dev authenticator — now an
> **installable, offline-capable (manifest + service worker), accessible** PWA with a
> separate Rust/wasm-pack CI job; dev / no-index / UNAUDITED, kept out of the default
> web CI job),
> the **MV3 browser extension** (`extension/` — a popup TOTP authenticator over the
> vendored wasm + the proven JS helpers, sealing to the same `SIGILcli` vault, sealed-only
> `chrome.storage.local` persistence with an in-memory password; dev / UNAUDITED, loaded
> unpacked and published to no store),
> the dev op-log's **multi-device auth model** (contract v3 — a device registry of
> per-device Ed25519 keys, enrollment via an operator token **plus** proof of
> possession, per-vault grants with trust-on-first-write ownership, and revocation;
> opt-in, dev-gated, mutually exclusive with the legacy single-static-key v2, and
> still UNAUDITED) and the **browser clients speaking that contract** (the wasm gains
> Ed25519 signing, `sigil-wasm/device-auth.mjs` implements the client half for the
> webapp + extension, and each browser keeps its device seed **sealed** in a second
> `SIGILcli` container rather than plaintext in web storage),
> the dev-gated **billing / subscription layer** in `sigild` (a provider-agnostic
> seam with **stdlib-only** Stripe / Razorpay / Juspay adapters — no vendor SDKs —
> hosted checkout only so the server never touches card data, real raw-body HMAC
> webhook verification with constant-time comparison, and idempotency keyed on
> material the provider's signature actually covers; opt-in, `501` by default,
> UNAUDITED, and **never run against a live provider account**),
> **device-to-device vault sharing** (a shared vault sealed under a random 32-byte
> **vault key** — the same `SIGILcli` container, no format change — that key **wrapped
> per recipient device** with the PQ-hybrid `hybrid_seal` path (X25519 + ML-KEM-768) and
> relayed through `sigild` as an **opaque envelope the server cannot read**, authorized
> by the existing v3 grant/ownership/revocation model; the **first load-bearing use of
> the hybrid primitives**, still dev-gated and UNAUDITED, and the human password is
> never shared) **now implemented by the browser clients too** (`sigil-wasm/sharing.mjs`
> gives the webapp and the MV3 extension the same flow as the CLI, with the hybrid
> secret identity and every accepted vault key stored inside the **sealed
> device-identity container**, schema v2 — so a browser still persists only sealed
> containers) **and by the native desktop client, which reaches the network by driving
> the `sigil-cli` library rather than reimplementing enrollment, contract-v3 sync or
> sharing — so all four client surfaces are peers and the canonical signed message still
> exists in only three implementations**,
> and **client-side key verification for that sharing flow** (clients **PIN** a device's
> hybrid public key on first sight and **hard-refuse to wrap** to a changed one, a
> human-comparable **safety number** allows out-of-band verification that pinning cannot
> give at first contact, and a vault key can be **ROTATED and re-wrapped** so revocation
> protects future content — client-side only, mirrored across exactly two
> implementations, with two new dev-gated `sigild` routes reusing the existing write
> authorization; still UNAUDITED, and first contact is still trust-on-first-use unless a
> human actually compares the digits),
> the **account model** (an account is a **server-assigned id on the device row** that
> **entitlement** and **vault ownership** key off instead of the device, so paying on one
> device covers the others and revoking a vault's claimant no longer orphans it; a second
> device joins with a **single-use invite** that rides the **unchanged** enrollment
> challenge — no fourth canonical message — and ⭐ **no request anywhere names an
> account**, which closes cross-account access structurally rather than defensively;
> still dev-gated, `501` by default, UNAUDITED, and explicitly **not an identity system:
> there is no email, no password and NO RECOVERY**),
> **abuse bounds** on the two routes that mint state — opt-in token buckets on device
> enrollment and invite minting, with the honest reading that behind the only topology
> this repo documents they are a **backstop, not a defence** — and the deliberate
> **removal** of a webhook rate limiter that was built, reproduced destroying genuine
> payment deliveries, and deleted rather than tuned,
> the **recovery kit** (a printable 56-character paper key whose device and hybrid
> identities are HKDF derivations of client entropy the server never sees, enrolled as an
> **ordinary member device** so `sigild` gained no concept of recovery at all — with the
> wrap gate that protects it **enforced by type** rather than by a command, and every
> honest limit including that whoever holds the paper holds the account),
> and **entitlement enforcement** (writes may be refused with `402` after a grace period,
> while ⭐ **reads and same-account key recovery are never refused**, because gating a
> second factor on a declined card would be a security failure we caused)
> — both of which then **reached the client surfaces** (the recovery kit and the payment
> warnings are no longer CLI-only), which is also how a **twelve-phase-old hole** surfaced:
> `sigild` answered every browser preflight `405`, so **the webapp could not reach a real
> server at all**, fixed with an **opt-in, allowlisted CORS** that is explicitly ⭐ **not an
> authentication or CSRF control** (there is no cookie — every request is authenticated by
> its own per-request signature),
> and the rule that a **rejected write must never CLAIM a vault** — a fourth
> full-repo adversarial audit found that trust-on-first-write fired during
> authorization, *before* a handler's request-shape checks, so a request the
> server was about to answer `400` still took permanent ownership of the vault id
> it named,
> and **passkey-protected local containers** in the webapp (a WebAuthn PRF output
> mixed into the AT-REST sealing secret as a **second factor**, with the container
> master key derived from the **already-printed recovery sheet** so the break-glass
> needs no new artifact and no server; ⭐ **AND, never OR** — while protection is on
> there is no password-only slot — and ⭐ `sigild` gained **nothing at all**: no
> route, no header, no canonical message, no migration, no table, no metric, no
> dependency),
> and the manual / human-gated deploy & publish posture). They record load-bearing
> decisions that have **actually been made
> and built** — not aspirations, and not a shipping product. Nothing here is
> audited or production-ready; see [`../architecture.md`](../architecture.md) for
> the current system shape and [`../../journal.md`](../../journal.md) for the
> chronological log.

## Why ADRs

[`journal.md`](../../journal.md) is the chronological record of *what happened,
when*. An ADR captures the **why** behind a single load-bearing decision in a
form that survives independent of that timeline: a future reader (or auditor)
can open one file and understand a choice without reconstructing it from the
session log.

We follow the lightweight [Michael Nygard
style](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions):

- Each ADR is a short, **immutable** record. Once **Accepted**, the text is not
  rewritten when the world changes.
- If a decision is reversed or revised, we write a **new** ADR and mark the old
  one **Superseded by NNNN** (and link the replacement). History stays legible.
- **Addenda are the one permitted exception, and only under these rules:** a
  clearly-headed, dated `## … (added Phase NN)` section may be APPENDED when a
  limitation the ADR recorded is later retired, so a reader does not walk away
  believing a stale constraint still holds. An addendum may **only** report what
  changed and point at the ADR that made the change — it must never edit the
  original Status/Context/Decision/Consequences text. If the DECISION itself
  changes, that is a supersession, not an addendum. (Example: ADR 0035 closed by
  noting sharing was CLI-only; Phase 48 retired that, so 0035 carries an
  addendum and the new storage decision got its own ADR 0036.)
- ADRs are numbered sequentially (`NNNN`) and named
  `NNNN-kebab-case-title.md`.
- Each has a fixed shape: **Status**, **Context**, **Decision**,
  **Consequences**. We keep an honest pre-audit framing and cross-link the code
  and docs the decision touches.

## Index

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-record-architecture-decisions.md) | Record architecture decisions | Accepted (2026-06) |
| [0002](0002-standalone-cli-crate-for-getrandom-isolation.md) | Standalone CLI crate for `getrandom` isolation | Accepted (2026-06) |
| [0003](0003-dev-gated-opaque-op-log.md) | Dev-gated, opaque vault op-log in `sigild` | Accepted (2026-06) |
| [0004](0004-crypto-agility-suite-registry.md) | Crypto-agility via an algorithm-suite registry | Accepted (2026-06) |
| [0005](0005-stdlib-only-sigild.md) | `sigild` is Go stdlib-only | Accepted (2026-06); partially superseded by [0014](0014-postgres-durable-oplog-backend.md) |
| [0006](0006-file-backed-dev-op-log-backend.md) | File-backed dev op-log backend (`SIGILD_OPLOG_DIR`) | Accepted (2026-06) |
| [0007](0007-caller-supplied-entropy-in-core.md) | Caller-supplied entropy in `sigil-core` | Accepted (2026-06) |
| [0008](0008-device-key-request-auth.md) | Device-key request auth for the dev op-log (`SIGILD_OPLOG_PUBKEY`) | Accepted (2026-06) |
| [0009](0009-manual-gated-deploy-and-publish.md) | Manual / human-gated deploy and publish | Accepted (2026-06) |
| [0010](0010-op-log-auth-v2-nonce-replay.md) | Op-log request auth v2 — signed per-request nonce + replay cache | Accepted (2026-06) |
| [0011](0011-hybrid-kem-combiner.md) | Hybrid KEM combiner (X25519 & ML-KEM-768 via HKDF) | Accepted (2026-07) |
| [0012](0012-hybrid-signature-combiner.md) | Hybrid signature combiner (Ed25519 then ML-DSA-65) | Accepted (2026-07) |
| [0013](0013-hybrid-public-key-seal.md) | Hybrid public-key seal (KEM-then-AEAD over the hybrid KEM) | Accepted (2026-07); ⚠️ it is **ANONYMOUS** (HPKE `mode_base`) and was **wrongly described as "authenticated"** until Phase 60 — using it to deliver a **key** was a vulnerability, so vault-key wrapping moved to the authenticated construction in [0048](0048-authenticated-vault-key-envelopes.md); this primitive remains correct, and in use, for **file** encryption to a public key |
| [0014](0014-postgres-durable-oplog-backend.md) | Postgres durable op-log backend (`SIGILD_OPLOG_POSTGRES`) | Accepted (2026-07) |
| [0015](0015-oplog-auditability-and-request-context.md) | Op-log auditability and request-context propagation | Accepted (2026-07) |
| [0016](0016-tamper-evident-oplog-hash-chain.md) | Tamper-evident op-log via a per-op hash chain | Accepted (2026-07) |
| [0017](0017-oplog-scale-and-observability.md) | Op-log scale & observability — pagination, per-vault rate limiting, `/metrics`, fail-fast config | Accepted (2026-07) |
| [0018](0018-managed-oplog-migrations-and-backup-integrity.md) | Managed op-log schema migrations and hash-chain-verified backup/restore | Accepted (2026-07) |
| [0019](0019-wasm-client-bindings.md) | WebAssembly client binding (`sigil-wasm`) — separate crate, JS-supplied entropy | Accepted (2026-07) |
| [0020](0020-shared-client-container-format.md) | Shared `SIGILcli` client container format (wasm ↔ CLI interop) | Accepted (2026-07); the header's byte layout is **unchanged**, but its Argon2id work factors are now **bounded at parse time** and a re-seal may never lower them — [0047](0047-container-parameter-ceiling-and-no-downgrade-ratchet.md); see its addendum |
| [0021](0021-wasm-hybrid-public-key-encryption.md) | Hybrid public-key encryption in the wasm client (`SIGILhyb` interop) | Accepted (2026-07) |
| [0022](0022-wasm-client-server-sync-loop.md) | Client↔server sync loop for the wasm client (`sync.mjs` over the dev op-log) | Accepted (2026-07) |
| [0023](0023-totp-hotp-primitive-and-cli-vault.md) | TOTP/HOTP primitive in `sigil-core` + encrypted CLI TOTP vault (first product feature) | Accepted (2026-07) |
| [0024](0024-wasm-totp-vault-and-cross-client-totp.md) | Browser TOTP vault + cross-client TOTP through the op-log (wasm `totp`/`hotp`/`format_code`, mirrored vault JSON) | Accepted (2026-07); the mirrored schema made **forward-compatible** in Phase 59 (unknown fields preserved on both sides, `min_reader_version` separate from `version`, failing closed) — [0047](0047-container-parameter-ceiling-and-no-downgrade-ratchet.md); see its addendum |
| [0025](0025-totp-import-export.md) | TOTP import/export — Google Authenticator `otpauth-migration://` (hand-rolled protobuf) + `otpauth://` | Accepted (2026-07); two **truthfulness** defects fixed in Phase 59 — a multi-QR import reported plain success while carrying a fraction of the accounts, and a `--migration` export of a non-30 s entry silently produced an account that generates the **wrong codes**; see its addendum |
| [0026](0026-browser-totp-import-export.md) | Browser TOTP import/export — mirror the migration codec in JS (`totp-migration.mjs`) + CLI↔JS cross-tool test | Accepted (2026-07); the JS mirror carried the same two defects as [0025](0025-totp-import-export.md) and was fixed with it in Phase 59 — ⚠️ **`decodeMigrationUri` now returns a batch OBJECT, not an array** (a breaking change to this module's own API); see its addendum |
| [0027](0027-webapp-and-wasm-bundling.md) | Real webapp over a `@sigil/wasm` loader (Next.js `asyncWebAssembly` + the `target_features`/`externref` strip) | Accepted (2026-07) |
| [0028](0028-webapp-vault-persistence-and-unlock.md) | Webapp vault persistence + password-unlock model (persist only the `SIGILcli`-sealed container in `localStorage`; in-memory password) | Accepted (2026-07) |
| [0029](0029-webapp-pwa-offline-a11y-and-ci.md) | Webapp as an offline-capable, accessible PWA (hand-rolled service worker + manifest) + a Rust/wasm-pack webapp CI job | Accepted (2026-07) |
| [0030](0030-browser-extension-client.md) | MV3 browser-extension client — popup TOTP authenticator over the vendored wasm + proven helpers (sealed-only `chrome.storage.local`, in-memory password) | Accepted (2026-07) |
| [0031](0031-multi-device-auth-model.md) | Multi-device auth model for the dev op-log (contract v3: device registry, enrollment with proof of possession, per-vault grants, revocation) | Accepted (2026-07); limitations 1 & 4 (device-scoped ownership, orphaned vaults) revised by [0040](0040-account-model.md), and limitation 6's "no rate limiting on enrollment attempts" by [0041](0041-abuse-bounds-and-the-removed-webhook-limiter.md) |
| [0032](0032-native-desktop-client.md) | Native desktop client — Tauri v2 shell over a headless core crate, `sigil-core` linked natively (no wasm), re-using `cli/`'s container/vault/migration logic and sharing the CLI's vault file | Accepted (2026-07) |
| [0033](0033-browser-device-identity-storage.md) | Browser device-identity storage — seal the Ed25519 device seed in a second `SIGILcli` container under the vault password (never plaintext web storage, never a `TotpVault` field) | Accepted (2026-07) |
| [0034](0034-billing-provider-seam.md) | Provider-agnostic billing seam in `sigild` (Stripe / Razorpay / Juspay, stdlib-only adapters with no vendor SDKs, hosted checkout only, raw-body HMAC webhooks, idempotency on the provider event ID) | Accepted (2026-07); §4's idempotency key revised by [0039](0039-webhook-idempotency-from-signed-bytes.md), and its device-scoped subject revised by [0040](0040-account-model.md) |
| [0035](0035-device-to-device-vault-sharing.md) | Device-to-device vault sharing — random per-vault key sealed into the unchanged `SIGILcli` container, wrapped per device with `hybrid_seal` (X25519 + ML-KEM-768), relayed as an opaque envelope, authorized by the existing v3 grants | Accepted (2026-07); ⛔ **the WRAP is superseded by [0048](0048-authenticated-vault-key-envelopes.md)** — `hybrid_seal` is anonymous, so the recipient's published public key was enough to forge an envelope; the wrap is now authenticated + context-bound (`SIGILhyb` **v2**, v1 refused), the envelope is **no longer 1226 bytes**, and every old envelope must be re-issued — see its addendum |
| [0036](0036-browser-sharing-secret-storage.md) | Browser sharing-secret storage — keep the hybrid secret identity and the vault keyring inside the existing sealed device-identity container (schema bumped to v2, v1 still readable) rather than adding a new store | Accepted (2026-07); the sealed-only invariant **asserted by tests** in both browser clients in Phase 57, and the webapp's persisted set widened to **three** sealed containers (still sealed-only) by [0046](0046-passkey-protected-local-containers.md) in Phase 58 — see its addenda |
| [0037](0037-desktop-reuses-cli-library-for-protocol.md) | The desktop client drives the `sigil-cli` library instead of reimplementing the wire protocol — no fourth copy of the canonical contract-v3 message, and the CLI's own state files | Accepted (2026-07) |
| [0038](0038-key-pinning-safety-numbers-and-vault-rotation.md) | Key pinning (pin on first sight, **hard-refuse** on change), a human-comparable safety number as the out-of-band check, and vault key rotation with re-wrap — the client-side answer to a key-substituting server, retiring two limitations recorded in [0035](0035-device-to-device-vault-sharing.md) | Accepted (2026-07); its choke point hardened into a type-enforced gate by [0042](0042-recovery-kit.md), which also records the phase that violated it, and the superseded `fetch_hybrid_key_pinned` / `fetchHybridKeyPinned` **deleted** in Phase 57 — see its addenda |
| [0039](0039-webhook-idempotency-from-signed-bytes.md) | Webhook idempotency keys must be derived from bytes the provider's signature covers (`Event.DedupKey`; Razorpay keys on the signed body, not the `X-Razorpay-Event-Id` header), and Juspay's default webhook scheme becomes `hmac` — revising §4 of [0034](0034-billing-provider-seam.md) | Accepted (2026-07) |
| [0040](0040-account-model.md) | Accounts as the subject of entitlement and the owner of vaults — a server-assigned account id on the device row, single-use invites over the **unchanged** enrollment challenge (no fourth canonical message), and **no request anywhere names an account** — revising limitations 1 & 4 of [0031](0031-multi-device-auth-model.md) and the device-scoped subject of [0034](0034-billing-provider-seam.md) | Accepted (2026-07); limitations 1, 8 and 12 revised by [0042](0042-recovery-kit.md), [0043](0043-entitlement-enforcement.md) and [0041](0041-abuse-bounds-and-the-removed-webhook-limiter.md), limitation 18 (partial client coverage) narrowed in Phase 56, and limitation 11 (the `/metrics` oracle) **narrowed but not closed** in Phase 57 — see its addenda |
| [0041](0041-abuse-bounds-and-the-removed-webhook-limiter.md) | Abuse bounds on enrollment and invite minting (opt-in stdlib token buckets that charge only on the denial path and fail open at their key cap — a **backstop, not a defence**, behind a reverse proxy), and the **removal** of the webhook rate limiter that was proven to shed genuine, correctly-signed payment deliveries — revising limitation 12 of [0040](0040-account-model.md) | Accepted (2026-07) |
| [0042](0042-recovery-kit.md) | The recovery kit — a printable 56-character Crockford paper key whose Ed25519 and hybrid identities are HKDF-SHA256 derivations, enrolled as an **ordinary member device** so `sigild` gained no concept of recovery (no table, no migration), with the wrap gate **enforced by type** (`VerifiedRecipient`) after the first implementation violated [0038](0038-key-pinning-safety-numbers-and-vault-rotation.md)'s choke-point rule — addressing the **data** half of limitation 1 of [0040](0040-account-model.md) | Accepted (2026-07); limitation 9 (partial client coverage) retired in Phase 56, and the kit's device **label** pinned to a golden literal in Phase 57 (which also corrects the *Neutral* section: the construction is **single-sourced**, the label is the mirror), and the printed sheet given a **second job** — deriving the container master key of [0046](0046-passkey-protected-local-containers.md) — in Phase 58 — see its addenda; ⚠️ **two clients were found DENYING this capability in the product** ("this app cannot print one" — true before Phase 56, false ever since) and were corrected in Phase 62, [0050](0050-confirmations-honest-claims-and-the-clock-diagnostic.md) §3 |
| [0043](0043-entitlement-enforcement.md) | Entitlement enforcement — writes refused with **`402 Payment Required`** after an opt-in grace period, while ⭐ **reads and same-account key recovery are never refused** (mechanically pinned by a test that parses the package AST), every uncertainty failing open — retiring limitation 8 of [0040](0040-account-model.md) | Accepted (2026-07); its warning channels gained client readers in Phase 56 — see its addendum |
| [0044](0044-opt-in-cors-allowlist.md) | Opt-in, allowlisted CORS (`SIGILD_CORS_ORIGINS`) so browser clients can reach `sigild` at all — unset means byte-identical, `*` is refused **at boot**, credentials mode is never enabled, and ⭐ it is **not an authentication or CSRF control** because every request is authenticated by its own per-request Ed25519 signature | Accepted (2026-07); the exposed-header list gained **`Date`** in Phase 62 so the browser clock diagnostic can read it cross-origin — [0050](0050-confirmations-honest-claims-and-the-clock-diagnostic.md) §5 |
| [0045](0045-claim-precondition-rejected-writes-never-claim.md) | A **rejected write never claims a vault** — a cheap, vault-independent `claimPrecondition` downgrades `needWrite` to `needWriteNoClaim` so a request the server is about to refuse cannot take trust-on-first-write ownership on its way out; ⚠️ an empty/malformed write to an **unowned** vault therefore answers **`403` instead of `400`**, and a per-account claim budget is still **not** implemented | Accepted (2026-07) |
| [0046](0046-passkey-protected-local-containers.md) | **Passkey-protected local containers** — the webapp's two sealed `SIGILcli` containers are sealed under a **container master key** that is an HKDF derivation of the **printed [0042](0042-recovery-kit.md) sheet**, and the CMK is additionally wrapped in a third container under `PRF(32) ‖ utf8(password)` fed **straight to Argon2id**; ⭐ **AND, never OR** (no password-only slot), ⭐ the **write order is the safety property** (containers first, slot last), and ⭐ **`sigild` gained nothing** — no route, header, canonical message, migration, table, metric or dependency | Accepted (2026-07); **user verification ENFORCED** in Phase 59 after it was found computed-and-ignored (CTAP `hmac-secret` keys two secrets per credential, so a `UV=false` ceremony sealed the slot under the wrong one) — limitation 8 **narrowed, not retired**; see its addendum |
| [0047](0047-container-parameter-ceiling-and-no-downgrade-ratchet.md) | **A ceiling on container KDF parameters, a no-downgrade ratchet, and a vault schema that can change** — the `SIGILcli` header's Argon2id work factors are unauthenticated framing, so they are now range-checked **before any allocation** (an unbounded `m_cost` was a remote DoS relayed by a server that by design cannot filter it); a re-seal may **raise** the work factor and never lower it, by **one** `no_downgrade` in `sigil-core` that the CLI, the desktop and JavaScript all reach rather than copy; and `TotpVault` / `TotpEntry` now **preserve fields they do not understand** with a separate `min_reader_version` that fails closed — retiring the flag-day-or-data-loss choice left by [0024](0024-wasm-totp-vault-and-cross-client-totp.md) | Accepted (2026-07) |
| [0048](0048-authenticated-vault-key-envelopes.md) | **Authenticated, context-bound vault-key envelopes** — the wrap used the **anonymous** `hybrid_seal` (HPKE `mode_base`), so anyone holding a device's **published** hybrid public key could mint an envelope it would accept and install a vault key of their choosing (reproduced with the shipped binary; ⛔ [0038](0038-key-pinning-safety-numbers-and-vault-rotation.md) pinning did **not** help, because `vault accept` fetched no key and never consulted the pin store). Fixed with a **static-static X25519 DH** folded into the KEM, an AAD naming **purpose + vault + recipient + sender**, `SIGILhyb` **v2 with v1 REFUSED and no compatibility flag**, a typed **`VerifiedSender`** unwrap gate, **open-before-write**, and **grant-before-deposit**. ⭐ **`sigild` changed by zero lines.** ⛔ **Authentication is CLASSICAL X25519 ONLY** (ML-KEM has no static-static analogue), implicit and **non-transferable**, first sight is still TOFU, and **every existing envelope must be re-issued**. Corrects two load-bearing documents that asserted the opposite | Accepted (2026-07) |
| [0049](0049-entry-identity-and-the-mergeable-vault.md) | **Entry identity, and a vault that merges instead of overwriting** — a vault synced as whole snapshots was **last-writer-wins**, so a device that never pulled pushed a tip that DESTROYED another device's account (reproduced end to end with the real binary against a real `sigild`; both pushes reported success). Identity becomes the `uuid` [0047](0047-container-parameter-ceiling-and-no-downgrade-ratchet.md) added and left dead — **minted** v4 for new entries, **derived** v8 over content for legacy ones so two devices holding the same old vault agree without communicating — and a vault becomes a **2P-Set** (`entries` ∪ `tombstones`, tombstone wins, safe because a genuine re-add mints a FRESH uuid). ⭐ **Clients now fold EVERY op instead of adopting the tip, which costs nothing on the wire because the op-log already stored every snapshot — so it RETROACTIVELY recovers data already shadowed on real servers.** Import de-dups on a content **fingerprint**, not an identity and no longer on the `label`, so `work@github` and `work@gitlab` both survive. ⭐ **`sigild` changed by zero lines.** ⛔ **Tombstones grow WITHOUT BOUND against the 64 KiB op cap with no compaction** (past it `push` is a permanent 413 — only a 75 % warning is built), and ⛔ **the design is correct ONLY because entries are IMMUTABLE** (an edit must be delete + add with a fresh uuid; a 51-check source guard makes that loud, not impossible — **108 checks** after Phase 62 rewrote its delete gates) | Accepted (2026-07); ⚠️ it **RAISED the stakes of an accidental delete** (the tombstone is protected against exactly the resurrection that used to undo one by accident), which is why [0050](0050-confirmations-honest-claims-and-the-clock-diagnostic.md) gates every single-entry delete behind a confirmation and rejects an undo on the merits |
| [0050](0050-confirmations-honest-claims-and-the-clock-diagnostic.md) | **The product stops harming and lying to its user** — four defects that are not cryptographic and still lose the user their accounts. A **one-click delete** of a 2FA secret, on a row inches from the code and repainting every second, whose stakes [0049](0049-entry-identity-and-the-mergeable-vault.md) had just **RAISED** (the tombstone now propagates and is protected against resurrection, so the accidental safety net is gone by design) — answered with a confirmation that **NAMES the entry** and ⭐ deliberately **NOT an undo** (an undo must either retract a tombstone, unretractable once merged, or hold intent in memory where closing a popup discards it). Two clients telling the user **in the product** that they *"cannot print"* a recovery kit — true before Phase 56, false ever since, with the Generate button on the same screen — the worst kind of documentation defect, because it routes the user **past** the one control ([0042](0042-recovery-kit.md)) that prevents permanent account loss. `vault rekey`'s **one-way door** now requires `--yes` (its aftermath fails **byte-identically to a wrong password**). And a **clock-skew DIAGNOSTIC** on all four clients off the `Date` header every response already carries — ⛔⛔ **a reading, NEVER a correction**, ⭐ offline = **NO READING, which is not "your clock is fine"**, and a confirmation is **not** an undo. ⚠️ **`sigild` WAS modified**: one additive `"Date",` in `corsExposedResponseHeaders`, because `Date` is not CORS-safelisted and a browser reads **null** for it cross-origin (measured with a real Chromium), so without it the browser half is dead — inert unless `SIGILD_CORS_ORIGINS` is set, and disclosing nothing `curl` could not already read | Accepted (2026-07) |
