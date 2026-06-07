# 0001 — Record architecture decisions

- **Status:** Accepted — 2026-06.

## Context

The repository already carries [`journal.md`](../../journal.md), a detailed
chronological build log, and a set of topic docs under [`docs/`](../README.md)
(architecture, crypto-spec, threat-model, API, deployment). The journal is
excellent for "what happened, when", but the *rationale* for a load-bearing
decision is interleaved across phases and easy to lose: to learn **why** the CLI
is a separate crate, or **why** the op-log defaults to `501`, a reader must scan
the whole timeline.

This is a pre-audit, security-sensitive project where several choices exist
specifically to protect the future audit posture. Those choices need a durable,
greppable home so their reasoning outlives the session that produced them — and
so an independent reviewer can read one file per decision.

## Decision

Adopt lightweight, [Nygard-style](https://cognitect.com/blog/2011/11/15/documenting-architecture-decisions)
Architecture Decision Records under [`docs/decisions/`](README.md):

- One Markdown file per decision, numbered `NNNN-kebab-title.md`.
- Each ADR has **Status / Context / Decision / Consequences**.
- ADRs are **immutable** once Accepted: a changed decision is captured in a
  **new** ADR that **supersedes** the old one (the old one is marked
  *Superseded by NNNN*), never edited in place.
- ADRs record decisions **already made** and accurate to the current code. They
  do not invent decisions or describe unbuilt features; pre-audit framing is
  kept explicit.

The journal remains the chronological source of truth; ADRs are the
decision-indexed companion. See [`docs/decisions/README.md`](README.md) for the
practice and the index.

## Consequences

- A new reader (or auditor) can understand a load-bearing choice from a single
  file, decoupled from the timeline.
- A small ongoing cost: meaningful decisions should be captured as an ADR, and
  reversals require a superseding ADR rather than an edit.
- This first ADR is itself the record of adopting ADRs. ADRs `0002`–`0005`
  back-fill the load-bearing decisions made through the current skeleton.
- ADRs do not replace [`journal.md`](../../journal.md) or the topic docs; they
  cross-link them and avoid duplicating their content.
