# Sigil docs

**Internal / pre-audit.** These documents describe intended design. They are
kept behind the pre-launch wall and are **not** published publicly until the
independent audit completes and trademark clears (brief, GTM Phase 1).

- [`architecture.md`](architecture.md) — the system shape: the client-side-crypto
  vs. zero-knowledge-server trust boundary and the life-of-one-record data flow
  (the doc to read first after this index).
- [`sprint-72h.md`](sprint-72h.md) — the 72-hour foundation sprint: definition
  of done, critical path, wall-clock gates, and the defer ledger.
- [`threat-model.md`](threat-model.md) — adversary classes and the defense layer
  for each (condensed from the product brief, §29).
- [`crypto-spec.md`](crypto-spec.md) — primitives, the algorithm-suite registry,
  the crypto-agility envelope, the hybrid construction, and the migration plan
  (condensed from the brief, §11/§20/§21).
- [`api.md`](api.md) — `sigild` HTTP reference: the `/healthz`, `/readyz`,
  `/version` probes, the **dev-only, opt-in** opaque-blob vault op-log (default
  `501`, unauthenticated unless one of two opt-in contracts is configured), the
  multi-device auth model, its opt-in **abuse rate limits**, the **account
  model**, the vault-key relay, what a **recovery kit** looks like on the wire,
  the billing routes and their opt-in **entitlement enforcement** (`402` on
  writes only) — all dev-gated and all `501` by default — plus the opt-in
  **browser-origin allowlist** (`SIGILD_CORS_ORIGINS`), which is off by default
  and is deliberately *not* an authentication control.
- [`deployment.md`](deployment.md) — the (not-yet-applied) `sigild` deployment
  runbook: topology, secrets posture, PQ-TLS nuance, and an honest
  what-is-not-deployable / validation-status accounting.
- [`decisions/`](decisions/README.md) — Architecture Decision Records (the
  load-bearing *why*), Nygard-style and pre-audit.

Every line here is **subject to change**. Substantial parts of the scaffold now
exist and are tested (the crypto core, the CLI, the dev op-log server, four
client surfaces — webapp, MV3 extension, native desktop and the CLI — device
**enrollment**, real per-vault **authorization**, an **account model**, and,
since Phases 53–55, opt-in **abuse bounds**, a printable **recovery kit** and
opt-in **entitlement enforcement** — with Phase 56 bringing the kit and the
payment warnings to **all four** client surfaces). But the system as a whole is
**pre-audit and not production-ready**: nothing here is **audited**, every one of
those server-side pieces is **dev-gated and `501` by default**, and the
product-level layer is still missing — an **identity** system (no email, no
password, no operator break-glass; the only recovery is a **paper kit printed in
advance**, and it **cannot be created after the loss**), session/token issuance,
device-key rotation, and mobile.
