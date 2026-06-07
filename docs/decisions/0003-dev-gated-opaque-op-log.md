# 0003 — Dev-gated, opaque vault op-log in `sigild`

- **Status:** Accepted — 2026-06.

## Context

`sigild` ([`../../sigild/`](../../sigild/)) is the sync-server **skeleton**. The
project's design (see [`../crypto-spec.md`](../crypto-spec.md) and
[`../threat-model.md`](../threat-model.md)) puts **all cryptography on the
client**: what crosses the client→server trust boundary is opaque, already-sealed
ciphertext. The server must never see plaintext or keys, which is what the
rogue-employee and compromised-server adversaries lean on.

To demonstrate the first client→server→client path (the CLI pushes a sealed
container and pulls it back), `sigild` needed *somewhere* to put those bytes.
But a real op-log requires authentication, durable storage, and conflict
semantics — none of which exist yet. A project guardrail forbids faking auth or
crypto: stub honestly with `501` rather than ship behaviour that would poison
the future audit.

## Decision

Add a **dev-gated, opaque, in-memory** vault op-log, and keep the production
default at `501`:

- The server stores each operation body as an **opaque `[]byte`** and re-emits
  it unchanged. It does **no cryptography**, never decodes the envelope, and
  never parses, validates, decrypts, orders, or merges the bytes. Defensive
  copies are taken on the way in and out so the server never aliases caller
  memory. (`store/vaultlog.go`, `internal/api/handlers.go`.)
- The op-log is **gated behind the `SIGILD_ENABLE_DEV_OPS` environment
  variable** and **defaults to off**. `Config.DevOpsEnabled` defaults `false`;
  `cmd/server/main.go` only flips it from a truthy `SIGILD_ENABLE_DEV_OPS`.
  When the flag is unset — the default and the only production-safe setting —
  `NewRouter` routes **both** verbs on `/v1/vaults/{vaultID}/ops` to a handler
  that returns **`501 Not Implemented`**. (`internal/api/router.go`.)
- When enabled, the op-log is explicitly **UNAUTHENTICATED, IN-MEMORY,
  NON-DURABLE, DEV-ONLY**, stores opaque blobs only, and is loudly labelled as
  such in code and in [`../api.md`](../api.md). The 64 KiB per-op body cap and
  `413` still apply.

This behaviour is **load-bearing and must not change**: the default-`501`,
do-no-crypto, opaque-blob posture is the whole point.

## Consequences

- An unauthenticated, non-durable, in-memory dev endpoint exists for
  demonstrations, **without** poisoning the audit posture: production runs with
  the flag unset, so the route is `501` and the server still does no crypto and
  holds no plaintext or keys.
- The server's confidentiality property does not depend on the op-log being
  correct — even when enabled, it only stores and returns ciphertext it never
  decoded.
- **Production must add**, before this route is anything more than a dev
  scaffold: real **authentication and per-vault authorization**; **durable,
  replicated storage** (Postgres / object store) with backups and a proven
  restore; and **real operation / CRDT semantics** (signed, ordered ops with
  conflict-free merge) — versus today's naive per-vault append-and-read counter.
  Even then, stored bytes stay opaque client ciphertext.
- Full contract, caveats, and the `501`/`413`/`400` cases are in
  [`../api.md`](../api.md); the system shape is in
  [`../architecture.md`](../architecture.md) §2.
