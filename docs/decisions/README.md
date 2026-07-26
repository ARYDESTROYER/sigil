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
> webhook verification with constant-time comparison, and idempotency keyed on the
> provider event id; opt-in, `501` by default, UNAUDITED, and **never run against a
> live provider account**),
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
| [0013](0013-hybrid-public-key-seal.md) | Hybrid public-key seal (KEM-then-AEAD over the hybrid KEM) | Accepted (2026-07) |
| [0014](0014-postgres-durable-oplog-backend.md) | Postgres durable op-log backend (`SIGILD_OPLOG_POSTGRES`) | Accepted (2026-07) |
| [0015](0015-oplog-auditability-and-request-context.md) | Op-log auditability and request-context propagation | Accepted (2026-07) |
| [0016](0016-tamper-evident-oplog-hash-chain.md) | Tamper-evident op-log via a per-op hash chain | Accepted (2026-07) |
| [0017](0017-oplog-scale-and-observability.md) | Op-log scale & observability — pagination, per-vault rate limiting, `/metrics`, fail-fast config | Accepted (2026-07) |
| [0018](0018-managed-oplog-migrations-and-backup-integrity.md) | Managed op-log schema migrations and hash-chain-verified backup/restore | Accepted (2026-07) |
| [0019](0019-wasm-client-bindings.md) | WebAssembly client binding (`sigil-wasm`) — separate crate, JS-supplied entropy | Accepted (2026-07) |
| [0020](0020-shared-client-container-format.md) | Shared `SIGILcli` client container format (wasm ↔ CLI interop) | Accepted (2026-07) |
| [0021](0021-wasm-hybrid-public-key-encryption.md) | Hybrid public-key encryption in the wasm client (`SIGILhyb` interop) | Accepted (2026-07) |
| [0022](0022-wasm-client-server-sync-loop.md) | Client↔server sync loop for the wasm client (`sync.mjs` over the dev op-log) | Accepted (2026-07) |
| [0023](0023-totp-hotp-primitive-and-cli-vault.md) | TOTP/HOTP primitive in `sigil-core` + encrypted CLI TOTP vault (first product feature) | Accepted (2026-07) |
| [0024](0024-wasm-totp-vault-and-cross-client-totp.md) | Browser TOTP vault + cross-client TOTP through the op-log (wasm `totp`/`hotp`/`format_code`, mirrored vault JSON) | Accepted (2026-07) |
| [0025](0025-totp-import-export.md) | TOTP import/export — Google Authenticator `otpauth-migration://` (hand-rolled protobuf) + `otpauth://` | Accepted (2026-07) |
| [0026](0026-browser-totp-import-export.md) | Browser TOTP import/export — mirror the migration codec in JS (`totp-migration.mjs`) + CLI↔JS cross-tool test | Accepted (2026-07) |
| [0027](0027-webapp-and-wasm-bundling.md) | Real webapp over a `@sigil/wasm` loader (Next.js `asyncWebAssembly` + the `target_features`/`externref` strip) | Accepted (2026-07) |
| [0028](0028-webapp-vault-persistence-and-unlock.md) | Webapp vault persistence + password-unlock model (persist only the `SIGILcli`-sealed container in `localStorage`; in-memory password) | Accepted (2026-07) |
| [0029](0029-webapp-pwa-offline-a11y-and-ci.md) | Webapp as an offline-capable, accessible PWA (hand-rolled service worker + manifest) + a Rust/wasm-pack webapp CI job | Accepted (2026-07) |
| [0030](0030-browser-extension-client.md) | MV3 browser-extension client — popup TOTP authenticator over the vendored wasm + proven helpers (sealed-only `chrome.storage.local`, in-memory password) | Accepted (2026-07) |
| [0031](0031-multi-device-auth-model.md) | Multi-device auth model for the dev op-log (contract v3: device registry, enrollment with proof of possession, per-vault grants, revocation) | Accepted (2026-07) |
| [0032](0032-native-desktop-client.md) | Native desktop client — Tauri v2 shell over a headless core crate, `sigil-core` linked natively (no wasm), re-using `cli/`'s container/vault/migration logic and sharing the CLI's vault file | Accepted (2026-07) |
| [0033](0033-browser-device-identity-storage.md) | Browser device-identity storage — seal the Ed25519 device seed in a second `SIGILcli` container under the vault password (never plaintext web storage, never a `TotpVault` field) | Accepted (2026-07) |
| [0034](0034-billing-provider-seam.md) | Provider-agnostic billing seam in `sigild` (Stripe / Razorpay / Juspay, stdlib-only adapters with no vendor SDKs, hosted checkout only, raw-body HMAC webhooks, idempotency on the provider event ID) | Accepted (2026-07) |
