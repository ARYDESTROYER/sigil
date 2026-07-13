# Architecture Decision Records

> **STATUS: pre-audit.** These ADRs describe the **current pre-launch skeleton**
> (the 72-hour foundation sprint, through the dev-gated op-log, the Ed25519
> sign/verify primitive and device-key request auth (v2, nonce/replay-hardened),
the file-backed and opt-in durable-Postgres dev op-log backends,
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
