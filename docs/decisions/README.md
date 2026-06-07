# Architecture Decision Records

> **STATUS: pre-audit.** These ADRs describe the **current pre-launch skeleton**
> (the 72-hour foundation sprint, through the dev-gated op-log and incremental
> CLI pull). They record load-bearing decisions that have **actually been made
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
| [0005](0005-stdlib-only-sigild.md) | `sigild` is Go stdlib-only | Accepted (2026-06) |
