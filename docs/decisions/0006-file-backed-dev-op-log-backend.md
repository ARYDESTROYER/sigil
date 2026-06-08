# 0006 — File-backed dev op-log backend (`SIGILD_OPLOG_DIR`)

- **Status:** Accepted — 2026-06.

## Context

[`0003`](0003-dev-gated-opaque-op-log.md) added a **dev-gated, opaque,
in-memory** vault op-log to `sigild` and deliberately stored each operation as
an **opaque `[]byte`** behind a small `VaultLog` seam (the server does no
cryptography and never decodes the bytes). That in-memory map is
**non-durable**: it is lost on every process restart. For the demo path —
`sigil push` a sealed container, restart the server, `sigil pull` it back —
that loss is annoying, and it leaves the `VaultLog` interface with only a single
implementation, so the seam is unproven.

We want **local-dev durability** without weakening any guardrail and without
pretending to be the production store. The project design still puts **all
cryptography on the client** (see [`../crypto-spec.md`](../crypto-spec.md),
[`../threat-model.md`](../threat-model.md)): what `sigild` holds is opaque,
already-sealed ciphertext. Production durability is a separate, much larger
decision (real auth, replicated Postgres/object storage, backups, restore, CRDT
semantics) and is **not** what this ADR is about.

A second concern is that the `vaultID` arrives on the **untrusted HTTP path**.
Any backend that maps a `vaultID` to a filesystem path must not allow a value
like `../../etc/passwd` or `a/b` to escape its directory.

## Decision

Add an **optional, file-backed `VaultLog`** implementation, selected at startup
by the **`SIGILD_OPLOG_DIR`** environment variable, behind the **same
`SIGILD_ENABLE_DEV_OPS` gate** as the in-memory default:

- It implements the **identical `VaultLog` interface** as the in-memory backend,
  so the handlers and the rest of the server are unchanged — this is the whole
  point of validating the seam with a second backend.
- **Selection:** when `SIGILD_ENABLE_DEV_OPS` is unset (the default and only
  production-safe setting), the op-log route is still `501` and **no** backend is
  constructed. When the dev flag is set, the backend is **in-memory by default**;
  if `SIGILD_OPLOG_DIR` is **also** set, the **file-backed** backend is used
  instead and persists each vault's append-and-read journal under that directory.
- **Path-traversal safety:** the untrusted `vaultID` is **encoded to a safe flat
  filename** (`base64.RawURLEncoding` of the raw `vaultID` bytes) before it is
  joined to the base directory. Any input — including `../../etc/passwd` or
  `a/b` — therefore maps to exactly one file **inside** `SIGILD_OPLOG_DIR`; the
  raw `vaultID` is never used as a path component.
- It stays **opaque, dev-gated, and UNAUTHENTICATED**, exactly like
  [`0003`](0003-dev-gated-opaque-op-log.md): the server does **no
  cryptography**, never decodes/parses/orders/merges the bytes, and re-emits them
  unchanged. The 64 KiB per-op cap and `413` still apply.
- It is explicitly **NOT the production store.** Production durability remains
  Postgres / object storage (S3/R2) with auth, replication, backups, restore,
  and real op/CRDT semantics — a separate future decision, not this one.

## Consequences

- The dev op-log is now **durable across restarts** in local dev when
  `SIGILD_OPLOG_DIR` is set, making the push → restart → pull demo work, while
  the default (no dir set) is unchanged in-memory behaviour.
- The **`VaultLog` seam is validated** by a second, behaviourally-equivalent
  backend — the interface is no longer a single-implementation abstraction.
- **Path traversal is structurally prevented:** because the `vaultID` is
  base64url-encoded to a flat filename, no HTTP-supplied value can write or read
  outside `SIGILD_OPLOG_DIR`.
- **Nothing about the security posture changes.** Still no auth, no crypto, no
  signed/ordered ops, no CRDT merge; still opaque ciphertext only; still
  dev-gated-off by default; still **must not be exposed publicly or hold real
  secrets**. This is local-dev durability, not a production storage decision.
- The op-log contract, the dev-only/`501`/`413` caveats, and the
  `SIGILD_OPLOG_DIR` selection are documented in [`../api.md`](../api.md); the
  two dev backends are noted in [`../architecture.md`](../architecture.md) §1.
