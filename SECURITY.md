# Security Policy

**Status: pre-launch, pre-audit.** Nothing here protects real secrets yet.

## Reporting a vulnerability

Email **security@sigilapp.io** (working-name address; provisional pending domain
registration). Please include reproduction steps and your assessment of impact.
A `/.well-known/security.txt` (RFC 9116) is published on the marketing site.

We aim to acknowledge reports within 3 business days. As a tiny pre-launch team
this is best-effort, not a contractual SLA.

## Scope

This repository is a skeleton. The cryptographic core (`libsigil`) is not yet
implemented; do not file findings about missing crypto — that work is tracked in
[`docs/sprint-72h.md`](docs/sprint-72h.md) and the product brief.

## What we will publish (later, not now)

- The full threat model and cryptographic specification (currently kept internal
  / behind the pre-launch wall, labeled pre-audit).
- An independent audit report (Cure53 engagement is being scoped — **not yet
  performed**; do not represent Sigil as "audited" until that report exists).

## Coordinated disclosure

We support coordinated disclosure and will credit reporters who wish to be
credited. Please give us a reasonable window to remediate before public
disclosure.
