# Security Policy

**Status: pre-launch, pre-audit.** Nothing here protects real secrets yet.

## Reporting a vulnerability

Email **security@sigilapp.io** (working-name address; provisional pending domain
registration). Please include reproduction steps and your assessment of impact.
A `/.well-known/security.txt` (RFC 9116) is published on the marketing site.

We aim to acknowledge reports within 3 business days. As a tiny pre-launch team
this is best-effort, not a contractual SLA.

## Scope

**Cryptographic findings are IN SCOPE and we want them.** An earlier version of
this file said the core was "not yet implemented" and asked people not to file
crypto findings. That has been false since early in the project and it was
actively harmful advice — it discouraged exactly the reports this project most
needs. It is retracted.

`libsigil` now contains **real but UNAUDITED** cryptography that product flows
actually depend on: an Argon2id KDF, an XChaCha20-Poly1305 + HKDF-SHA256 AEAD and
the sealed-record API, classical Ed25519 and X25519, post-quantum ML-KEM-768 and
ML-DSA-65, and a hybrid KEM/signature/public-key-seal built on them. The hybrid
seal is **load-bearing** — it wraps the vault keys used for device-to-device
sharing. On top of that sit the device-auth request contract, per-vault
authorization, key pinning with safety numbers, and the billing webhook
verification in `sigild`.

All of it is pre-audit and none of it has been reviewed by an independent party,
so **please report anything you find**, including in:

- the crypto core and its composition (`libsigil/`, `docs/crypto-spec.md`)
- the device-auth contract, per-vault authorization and revocation (`sigild/`)
- key pinning, safety numbers and vault-key rotation (`docs/decisions/0038-…`)
- the sealed container / vault formats and the client key handling in `cli/`,
  `sigil-wasm/`, `web/apps/webapp/`, `extension/` and `desktop/`
- webhook signature verification in `sigild/internal/billing/`

Known and already-documented limitations are listed in
[`docs/threat-model.md`](docs/threat-model.md) — a report that one of those is
worse than we think is still welcome. What we cannot act on is a finding that a
deliberately deferred feature is missing; the defer ledger is in
[`docs/sprint-72h.md`](docs/sprint-72h.md).

**Do not test against infrastructure you do not own.** Nothing is deployed, so
please work against a local build.

## What we will publish (later, not now)

- The full threat model and cryptographic specification (currently kept internal
  / behind the pre-launch wall, labeled pre-audit).
- An independent audit report (Cure53 engagement is being scoped — **not yet
  performed**; do not represent Sigil as "audited" until that report exists).

## Coordinated disclosure

We support coordinated disclosure and will credit reporters who wish to be
credited. Please give us a reasonable window to remediate before public
disclosure.
