# 0016 — Tamper-evident op-log via a per-op hash chain

- **Status:** Accepted — 2026-07.

## Context

The dev op-log ([`0003`](0003-dev-gated-opaque-op-log.md)) is an append-and-read
journal of **opaque client-encrypted blobs** behind a `VaultLog` seam with three
backends — in-memory, file-backed ([`0006`](0006-file-backed-dev-op-log-backend.md)),
and durable Postgres ([`0014`](0014-postgres-durable-oplog-backend.md)). The
auditability hardening ([`0015`](0015-oplog-auditability-and-request-context.md))
added a structured audit log that fingerprints each blob with SHA-256, and
explicitly named the remaining gap: *"a production audit log would be **signed and
tamper-evident**."*

Today nothing lets anyone tell whether the **stored sequence** was altered after
the fact. A backend (or an operator, or a corrupted file / row) could modify a
blob, reorder ops, insert a forged op, or silently drop one, and neither the
server nor a client would notice — the per-op `blob_sha256` in the audit log
fingerprints each op in isolation, with nothing binding op *k* to op *k−1*. The
threat model leans on adversary #4's *signed append-only audit log* and adversary
#5's *replay/drop detection*; both want the log's **history** to be verifiable,
not just its confidentiality.

The constraints from [`0003`](0003-dev-gated-opaque-op-log.md) still bind
absolutely: the server stores **opaque blobs** and does **no crypto on the
plaintext**; the op-log stays **dev-gated** (`SIGILD_ENABLE_DEV_OPS`, default
`501`) and **unauthenticated unless `SIGILD_OPLOG_PUBKEY`**. Any integrity
mechanism must preserve zero-knowledge and must not over-claim.

## Decision

Give the op-log **tamper-evidence** with a per-op **SHA-256 hash chain**, stored
in **every** `VaultLog` backend and exposed to clients — a modest, honest
down-payment on the future signed/Merkle audit log:

- **Chain construction (all three backends).** Each op gets a 32-byte hash that
  commits to the previous op's hash:

  ```
  hash(seq) = SHA-256(
        "sigil-oplog-chain-v1"     // ASCII domain-separation label
     || len-prefixed vaultID       // unambiguous field boundary; binds the chain to its vault
     || seq                        // big-endian sequence number
     || prev_hash                  // previous op's 32-byte hash; genesis = 32 zero bytes
     || blob )                     // the opaque client-encrypted bytes, verbatim
  ```

  The genesis `prev_hash` (first op, `seq = 1`) is 32 zero bytes. Because each op
  chains from the one before, altering / inserting / deleting / reordering any op
  changes the hash of that op **and every op after it**.
- **Hashing the OPAQUE ciphertext preserves zero-knowledge.** The chain is
  computed over the **already client-encrypted** blob — it fingerprints
  ciphertext, needs **no key**, and reveals **no plaintext**. The server still
  performs no cryptography on vault contents; this is the same property the audit
  fingerprint relies on ([`0015`](0015-oplog-auditability-and-request-context.md)).
- **Exposed two ways.** `GET …/ops` returns each op's hex `hash` inline, so a
  client can **re-derive and verify the chain itself**; and a new
  **`GET /v1/vaults/{vaultID}/ops/verify`** recomputes the whole chain
  server-side and returns `{vaultID, ok, count, tip_hash, broken_at_seq}`
  (`broken_at_seq` = the first mismatching `seq`, or `null` when intact).
- **Same gate, same auth, same opacity.** `/ops/verify` and the per-op `hash` are
  **dev-gated** (`501` when `SIGILD_ENABLE_DEV_OPS` is unset) and **auth-guarded**
  exactly like the existing ops routes (`401` under `SIGILD_OPLOG_PUBKEY`). The
  64 KiB cap and the opaque contract are unchanged.
- **Storage-format consequences.** The **FileVaultLog on-disk format is bumped to
  v2** (each record now persists its chain hash alongside the length-prefixed
  blob), and the **Postgres table gains a hash column**. The in-memory backend
  carries the hash in-process. Only the `pgx` dependency remains; Mem/File stay
  stdlib.
- **Tamper-EVIDENT, not tamper-PROOF — stated honestly.** A **single,
  non-notarized** server can still **lie** about `/ops/verify`: it can recompute a
  perfectly consistent chain over data it has itself doctored, or just return
  `{"ok": true}`. Server-side verification therefore catches only **accidental**
  corruption and a **non-adversarial** operator's storage faults. The guarantee
  that resists a **hostile** server is **client-side**: the client keeps its own
  tip hash and re-derives the chain from the returned per-op hashes. This is a
  **dev op-log**, not a Byzantine-fault-tolerant or append-only-enforced log.

## Consequences

- **Integrity auditing, two-sided.** An operator can spot-check a vault's chain
  with one request (`/ops/verify`), and — more importantly — a client can verify
  the log's **history** independently of the server, from the per-op hashes,
  detecting modification / insertion / deletion / reordering of stored ops.
- **Zero-knowledge intact.** The chain is over ciphertext only; the server still
  holds no plaintext and no key, and confidentiality still does not depend on the
  server (adversary classes #4 and #5). Tamper-evidence is added with no new
  exposure — see [`../threat-model.md`](../threat-model.md).
- **A durable-format change.** FileVaultLog's format is now **v2** and the
  Postgres schema carries a hash column; the in-memory backend is unaffected on
  restart (non-durable by design). All three implement the identical chain, so a
  blob and its hash are portable in meaning across backends.
- **Security posture unchanged.** Still `SIGILD_ENABLE_DEV_OPS`-gated and `501` by
  default, still unauthenticated unless `SIGILD_OPLOG_PUBKEY`, still opaque blobs
  only, still no crypto on the plaintext. Tamper-evidence is the **only** new
  property.
- **NOT tamper-proof, and production still owes the real thing.** A hostile server
  can lie about `/ops/verify`, so the real guarantee is client-side; and this is
  **not** the production build's **signed / Merkle-root, replay-and-drop-detecting**
  audit log, nor does it add signatures or CRDT merge on the ops themselves. It is
  a dev-scale down-payment on that goal, no more.
- Documented in-sync: the chain construction, the per-op `hash`, and the
  `/ops/verify` route are in [`../api.md`](../api.md); the component change (a hash
  chain across all three backends, client-verifiable per-op hash, tamper-evident
  not tamper-proof) is in [`../architecture.md`](../architecture.md) §1 and §6; and
  the tamper-evidence guarantee and its honest limits are in
  [`../threat-model.md`](../threat-model.md).

Cross-links: builds on [0003](0003-dev-gated-opaque-op-log.md),
[0014](0014-postgres-durable-oplog-backend.md), and
[0015](0015-oplog-auditability-and-request-context.md).
