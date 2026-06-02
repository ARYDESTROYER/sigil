# 72-hour foundation sprint — definition of done & defer ledger

> **Internal.** Pre-launch / stealth posture: defensive, no-index,
> request-beta-access. NOT a public launch. Everything here is reversible and
> over-claim-free. The product itself (real libsigil, full sigild, clients,
> app-store presence, Cure53 results, SOC 2) is **explicitly out of scope** for
> 72 hours.

## Honest scope note

The brief is a 12-month plan. This sprint stands up a credible **foundation**,
not a product. The committed tier below is the deliverable; the stretch tier
(live `sigild` over PQ-TLS) spills to day 4–5 or is honestly deferred. The
draft's hour budget (~58h/founder across 72 wall-clock hours) was not real;
treat the committed tier as the 3-day target.

## Owners

- **Cofounder A** — crypto / backend lean (libsigil, sigild, deploy, CI).
- **Cofounder B** — web / product lean (marketing, DNS/email, legal stubs).

## Committed tier (this = sprint success regardless of stretch)

- [x] Monorepo scaffold, navigable tree, LICENSE split (Apache-2.0 clients/core,
      BSL-1.1 server), CODEOWNERS, version pins.
- [x] `libsigil` builds + `cargo fmt`/`clippy -D warnings`/`test` green + `wasm32` build.
- [x] `sigild` skeleton builds + `gofmt`/`go vet`/`go test` green (`/healthz`,
      `/readyz`, `/v1/vaults/{id}/ops` → 501, no faked crypto).
- [x] Marketing stealth splash: Next.js 15, no-index (robots + meta +
      `X-Robots-Tag`), password-wallable middleware, consented waitlist
      (validated, persistence intentionally stubbed), privacy/terms/imprint
      stubs, `/.well-known/security.txt`, `MARKETING-CLAIMS.md` guardrail.
- [x] Three green CI workflows + Dependabot + gitleaks + inert (`if: false`) release.yml.
- [ ] **Register a domain** (working anchor: `sigilapp.io`) + Cloudflare zone +
      DNSSEC (after NS propagation) + Postmark DKIM/SPF/DMARC `p=none` + Email
      Routing for role mailboxes. *(needs the human to buy the domain)*
- [ ] **Team password manager** provisioned (1Password/Bitwarden), both founders,
      recovery + break-glass documented; registry-of-record + all secrets there,
      never in the repo.
- [ ] **Privacy stub published before the first live waitlist write** (consent
      references it). *(stub written; goes live with the deploy)*
- [ ] **Backups** for the waitlist Postgres: nightly `pg_dump` offsite (R2 /
      Storage Box) + VM snapshots + a proven restore test. *(needed once the
      waitlist persists for real)*
- [ ] `/.well-known/security.txt` + abuse/incident triage note + secret-rotation
      runbook (gitleaks-fired). *(security.txt written; rotation runbook below)*
- [ ] External uptime + cert-expiry monitoring on the walled splash. *(deploy-time)*

## Stretch tier (pass-or-honestly-deferred — never faked)

- [ ] `sigild` on one hardened-systemd Hetzner VM: `https://api.<host>/healthz`
      = 200 over TLS 1.3; `/readyz` pinging PG+Redis; `nmap` confirms only
      22/80/443 reachable.
- [ ] `X25519MLKEM768` hybrid group demonstrably negotiated **against the
      Go-native listener** (not Caddy's classical edge), proven with a Day-0
      validated OpenSSL 3.5+ / Go 1.24.x client. *(local verifier is LibreSSL
      3.3.6, which CANNOT negotiate this — provision the PQ client first.)*
- [ ] First Postgres migration (users/devices/vaults[suite 0x12]/members/
      ops_metadata/billing) with RLS enabled + placeholder policies, documented
      as posture-only.

## Critical path & wall-clock gates

1. Secrets/password manager FIRST — everything descends from it.
2. PQ-TLS client (OpenSSL 3.5+ / Go 1.24.x) proven on the gate machine Day 0.
3. Trademark knockout started; a neutral ACME hostname secured (sslip.io fallback-only).
4. Hetzner identity-check = gate; not cleared ⇒ sigild drops to floor.
5. NS propagation **before** DNSSEC DS and **before** ACME (neither instantaneous).
6. Privacy stub published **before** the first consented write.
7. Postmark **account approval** is a separate manual gate from DNS verification.

## Long-poles kicked off Day 0 (completion out of scope)

Trademark (US/EU/UK/India), legal entity, Apple Developer + Google Play
enrollment, Stripe + Razorpay verification (will **stall** behind the walled,
price-less site — accepted), Postmark approval, Cure53 scoping, Vanta trial.

## Defer ledger (NOT done in 72h, with why)

- libsigil crypto correctness — "correct the first time = weeks"; rushing = walk-back.
- Full sigild business logic, the 3 workers, ClickHouse audit log — months-1-2 roadmap.
- In-browser webapp / admin console / live sign-in / MV3 extension — need libsigil-wasm.
- All native clients — consume a libsigil binary that won't exist for weeks.
- Live payments + Stripe/Razorpay verification — reviewers need a reachable
  pricing/policy page; our site is walled + price-less. Submitted as clock-start only.
- Permanent App Store record + `com.sigil.app` bundle ID — permanent once made;
  needs a D-U-N-S on the unformed entity. Reserve only reversible placeholders.
- Status page — subdomain parked only; no provider stood up (most are public).
- Production shapes (Nomad/K8s/Aurora/multi-region), reproducible Nix builds,
  working cosign/SLSA, Cure53 completion, SOC 2/ISO, lawyer-reviewed legal docs.
- Final brand commitment + GitHub org rename (rename breaks remotes/badges — debt
  documented, not executed).

## Secret-rotation runbook (gitleaks fired / suspected leak)

1. Revoke/rotate the leaked credential at its source (Postmark server token,
   `SITE_PASSWORD`, registrar/DNS API token, etc.) **immediately**.
2. Update the value in the team password manager (the single source of truth).
3. Re-deploy the affected surface with the new value.
4. Purge the secret from git history if it was committed (`git filter-repo`),
   force-push, and rotate anything that history exposed.
5. Note the incident (what leaked, when, blast radius, fix) in the on-call log.

## Zero-over-claims gate (final read-through before tagging `v0.0.1-skeleton`)

No surface may claim a completed audit, SOC 2, "post-quantum secure",
unqualified "end-to-end encrypted", live payments, shipping clients, the
unconfirmed `sigil.app` brand, or a PQ-TLS proof that did not actually run.
