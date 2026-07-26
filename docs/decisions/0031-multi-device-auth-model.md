# 0031 — Multi-device auth model for the dev op-log (contract v3: device registry, enrollment, per-vault grants, revocation)

- **Status:** Accepted (2026-07)
- **Date:** 2026-07-16
- **Supersedes (as the active contract, when enabled):** the single-static-key
  request auth of [0008](0008-device-key-request-auth.md) /
  [0010](0010-op-log-auth-v2-nonce-replay.md). Those remain **in the code,
  unchanged**, as the legacy v2 mode; v3 is opt-in and mutually exclusive with
  them.

## Context

`sigild`'s dev op-log had exactly two auth postures, both inadequate as a model
of "who may touch which vault":

1. **Unauthenticated** (the default) — anyone who can reach the port can read
   and append to any vault ID.
2. **One static Ed25519 key** (`SIGILD_OPLOG_PUBKEY`, contract v2) — a single
   configured public key authenticated **every** request to **every** vault.

Contract v2 is a real signature check with a real replay defense (a fresh
per-request nonce plus a time-bounded in-memory cache inside a 300 s window),
and it is honest about being a dev key. But structurally it has no notion of
identity or authority:

- **No device identity.** Every request looks the same. The audit log cannot say
  *which* device appended an op, because there is only one key.
- **No authorization.** A holder of the key is authorized on every vault that
  exists or will ever exist. There is no per-vault membership check, so "device
  B must not read device A's vault" is unexpressible.
- **No revocation.** A leaked key can only be dealt with by editing the server's
  environment and restarting it — there is no per-device kill switch, and no way
  to revoke one device while others keep working.
- **No enrollment.** New devices are provisioned by an operator pasting a public
  key into an env var, which does not scale past one device and has no proof
  that the presenter actually holds the corresponding private key.

Meanwhile the client side had moved well past that: three real clients (the
`sigil` CLI, the `web/apps/webapp` browser app, the MV3 extension) all seal to
the same `SIGILcli` container, and two of them can sync opaque containers
through the op-log. The missing piece was a server-side answer to *which device
is this, and is it allowed to touch this vault*.

The guardrail (`CLAUDE.md`: "don't fake crypto/auth") means the alternatives
were to keep stubbing, or to build something **real** — real `crypto/ed25519`
verification against a real registry, with no bypass path, no fallback "trusted"
key, and no hardcoded credential — while staying honestly scoped as a dev,
pre-audit, unaudited model.

## Decision

Build a **multi-device auth model** for the dev op-log — **opt-in**, dev-gated,
and mutually exclusive with the legacy single-key contract.

### 1. A device registry behind a store seam

A new `store.DeviceStore` interface (mirroring the existing `VaultLog` seam:
context-aware, concurrency-safe, interchangeable backends) holds three things,
all **auth metadata only**:

- **Devices** — a raw 32-byte **Ed25519 public key** per device, a
  **server-assigned** ID (`"dev_"` + `base64.RawURLEncoding` of 16 CSPRNG bytes,
  so a client can neither choose nor squat an ID), a label, and a status
  (`active` | `revoked`; a revoked row is retained, never deleted).
- **Enrollment tokens** — operator-provisioned bootstrap secrets recorded
  **only** as a lowercase hex **SHA-256 digest**, with `used_at` as the
  single-use marker.
- **Grants** — `(vaultID, deviceID) -> permission`, where `permission` is
  `read` | `write` and **write implies read**, plus an `is_owner` flag.

Two backends: `MemDeviceStore` (dev/tests, non-durable) and
`PostgresDeviceStore` (durable, sharing the op-log's existing `pgxpool` — **no
second pool and no new dependency**). Storage comes from a new managed migration
**`0002_devices.sql`** (`sigil_devices`, `sigil_enrollment_tokens`,
`sigil_device_grants`) applied by the existing migration machinery from
[ADR 0018](0018-managed-oplog-migrations-and-backup-integrity.md);
`sigild_schema_version` therefore now reports **2**. It touches **nothing** in
`sigil_vault_ops`.

### 2. Enrollment: an operator token **plus** proof of possession

`POST /v1/devices/enroll` requires **two independent factors**, both mandatory:

- an operator-provisioned **enrollment token** in `X-Sigil-Enroll-Token`,
  matched in constant time against the configured digests and then **spent
  atomically** in the registry (a conditional `UPDATE … WHERE used_at IS NULL`
  inside a `FOR UPDATE` transaction in Postgres, a mutex in memory) — a token is
  single-use; and
- **proof of possession**: an Ed25519 signature, in `X-Sigil-Signature`, over a
  canonical enrollment challenge, **verified against the public key being
  submitted**. A bare public-key upload is never accepted.

The challenge uses a **different domain** from the request contract, so an
enrollment proof can never be repurposed as an op-log request signature (or the
reverse):

```
"sigil-device-enroll-v1\n" + TOKEN_SHA256_HEX + "\n" + TIMESTAMP + "\n" +
NONCE + "\n" + PUBLIC_KEY_B64 + "\n" + LABEL
```

Binding the **token digest** means a captured proof cannot be re-presented with
a different token; binding the **public key** means an interceptor cannot swap
in its own key while reusing a victim's token. The same 300 s window and nonce
replay cache apply (enrollment nonces are prefix-namespaced so they cannot
collide with request nonces).

### 3. Contract v3: bind the device ID into the signed message, bump the domain

Every authenticated op-log request now names **which** enrolled device signed
it, via a new `X-Sigil-Device` header, and the signed message gains both a new
domain line and a device segment:

```
MESSAGE = "sigil-oplog-auth-v3\n" + DEVICE_ID + "\n" + METHOD + "\n" + PATH +
          "\n" + QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + BODY
```

The domain bump `…-v2` → `…-v3` **plus** the extra segment is deliberate domain
separation: a captured v2 signature cannot verify under v3, so v2 traffic cannot
be replayed into the device model.

Verification order maps 1:1 to the audited reason: headers present → timestamp
parses → inside the 300 s window → device resolves in the registry → **device
not revoked** → Ed25519 signature verifies under *that device's registered key*
→ nonce not replayed. Two orderings are load-bearing:

- **Revocation is checked BEFORE signature verification**, so a revoked device
  is refused on its very next request regardless of how well it signs.
- **The nonce is recorded ONLY after a valid signature**, so unauthenticated
  probes can neither populate nor probe the replay cache.

### 4. Per-vault authorization with trust-on-first-write ownership

Authentication answers *who*; a second, separate step answers *may they*. Every
ops route declares what it needs — `POST …/ops` needs **write**, `GET …/ops` and
`GET …/ops/verify` need **read**, `POST …/vaults/{id}/grants` needs
**ownership** — and the device must hold a sufficient grant.

Ownership is **trust on first write (TOFU)**: a vault with no owner is claimed
by the **first device that successfully authenticates a write** to it, which
becomes the owner with write permission. The claim is **atomic** in both
backends (a mutex in memory; a partial `UNIQUE INDEX … (vault_id) WHERE
is_owner` in Postgres), so exactly one of N concurrent first-writers wins.
**Reads never claim** — reading an unowned vault is a denial. Only the owner may
grant another enrolled, non-revoked device access.

We chose TOFU because the alternative — a real account model — is a much larger
design (identities, recovery, billing) that this pre-audit skeleton must not
fake, and because vault IDs are already client-chosen high-entropy identifiers.

### 5. 401 vs 403, with no auth oracle

`401` means *unauthenticated*; `403` means *authenticated but not authorized*.
The **client body is coarse** — `{"error":"unauthorized", …}` or
`{"error":"forbidden", …}` — while the **typed reason enum** (`unknown_device`,
`revoked_device`, `unauthorized_vault`, `not_vault_owner`, `bad_proof`,
`enrollment_token_used`, …) goes **only** to the structured audit log and the
per-reason metric. A prober therefore learns the status class and nothing else.
A registry fault is `500` (`store_unavailable`) so infrastructure trouble is
never mistaken for a credential verdict.

### 6. Opt-in, dev-gated, fail-fast, and mutually exclusive with v2

All five new routes are dev-gated exactly like the ops routes: with
`SIGILD_ENABLE_DEV_OPS` unset (or no registry configured) each returns a
deliberate **`501`**, never a `404` and never partial auth behaviour. Four new
env vars (`SIGILD_DEVICE_AUTH`, `SIGILD_ENROLL_TOKENS`,
`SIGILD_ENROLL_TOKEN_TTL`, `SIGILD_ADMIN_TOKEN`) are parsed and validated
**before the listener binds**, and the server **refuses to boot** when
`SIGILD_DEVICE_AUTH` is combined with `SIGILD_OPLOG_PUBKEY` — one auth contract
at a time, so there is never an ambiguous "which model is live" state. With
`SIGILD_DEVICE_AUTH` unset, behaviour is byte-for-byte what it was before.

## Consequences

### Good

- **Real device identity.** The audit log can now say *which* device did what
  (`device_id` on `oplog.append` denials, `device.enrolled`, `device.revoked`,
  `vault.claimed`, `vault.granted`), which the single-key model could not.
- **Real authorization.** "Device B may not read device A's vault" is now
  enforced and returns a *distinct* `403`, not a blanket `401`.
- **Real revocation.** A lost device is killed by one operator call and is
  refused on its next request — before its signature is even checked — without
  disturbing any other device.
- **Enrollment cannot be forged from a stolen token alone**, because the token
  is bound into a proof of possession the thief cannot produce without the
  private key it names; nor from a stolen proof, because the proof is bound to
  the token digest and to the exact public key.
- **Zero-knowledge is untouched.** The migration adds auth metadata only; the
  op-log blob, its hash chain, and the trust boundary are byte-for-byte
  unchanged. The server still performs no cryptography on vault contents (the
  only hashing added is SHA-256 over a bearer token so the plaintext is never
  persisted).
- **No new dependency.** Ed25519 is Go stdlib; the Postgres registry reuses the
  op-log's existing `pgxpool`. `pgx` remains `sigild`'s only direct dependency.
- **Nothing regressed.** The legacy v2 path and the no-auth path are preserved
  verbatim, so the `sigil` CLI's `push`/`pull` and the wasm `sync.mjs` client
  keep working exactly as before.

### Bad / honest limitations (all of these are real; none is papered over)

1. **Trust-on-first-write is a DEV ownership model, not an account model.** It
   assumes the first writer of a high-entropy, client-chosen vault ID is its
   legitimate owner. An attacker who guesses or learns an **unclaimed** vault ID
   and writes to it first becomes its owner, and the real owner is then locked
   out with a `403`. There is no identity behind ownership, no invitation flow,
   and no proof that the claimant *should* own that ID.
2. **An enrollment token is single-ATTEMPT, not single-SUCCESS.** The token is
   spent *before* the device row is created, so an enrollment that then fails on
   a duplicate-key conflict still burns the token. This is deliberately
   fail-closed — the server never silently permits a retry — but it means an
   operator must issue a new token after such a failure.
3. **The replay nonce cache is per-process and in-memory.** A multi-instance
   deployment needs a shared store (e.g. Redis) or a request replayed against a
   *different* instance would pass. Device request nonces share one namespace
   (enrollment nonces are prefix-separated), so a nonce is accepted at most once
   per process per window across all devices.
4. **Revoking a vault's owner ORPHANS the vault.** There is no ownership
   transfer: after the owner is revoked, no device can grant access on that
   vault, and existing grantees keep only what they already hold.
5. **The in-memory registry is non-durable.** With no Postgres backend
   configured, devices, grants and spent-token markers are lost on restart —
   which means a **spent enrollment token becomes reusable after a restart**.
   The server warns loudly at boot. The **file backend was not extended**:
   `SIGILD_OPLOG_DIR` + device auth falls back to the in-memory registry (also
   warned at boot).
6. **Still dev-gated, pre-audit, UNAUDITED.** This is a real auth model, but it
   has not been reviewed by anyone external. There is still **no user/account
   model**, **no session or token issuance** (no JWT — `internal/auth` remains a
   placeholder), **no rate limiting on enrollment attempts** (the per-vault
   op-log limiter does not cover `POST /v1/devices/enroll`), **no key rotation**
   or re-enrollment flow, no recovery, and no hardware attestation. The admin
   token is a single static bearer secret with no rotation story; if it leaks,
   the holder can revoke any device. Transport is still plain HTTP in dev.

### Neutral

- The `VaultLog` seam is unchanged; the registry is a **separate** seam, so a
  backend can implement one without the other (which is exactly why the file
  op-log backend has no device store).
- Auditing and metrics grew a device dimension but stayed *count*-only: no
  metric is labelled by device ID or vault ID (an ID label would let a scrape
  enumerate the registry), and no audit line ever carries a public key,
  signature, nonce, timestamp value, enrollment token, or token digest.
- `GET /metrics` remains always-on and unauthenticated; it exposes the new
  counters and the bumped `sigild_schema_version` and nothing secret.

## References

- Code: [`../../sigild/internal/api/deviceauth.go`](../../sigild/internal/api/deviceauth.go),
  [`devices.go`](../../sigild/internal/api/devices.go),
  [`router.go`](../../sigild/internal/api/router.go),
  [`../../sigild/internal/store/devicestore.go`](../../sigild/internal/store/devicestore.go),
  [`postgresdevicestore.go`](../../sigild/internal/store/postgresdevicestore.go),
  [`migrations/0002_devices.sql`](../../sigild/internal/store/migrations/0002_devices.sql),
  [`../../sigild/cmd/server/main.go`](../../sigild/cmd/server/main.go).
- Contract: [`../api.md`](../api.md) — the authoritative HTTP surface.
- Adversaries/defenses: [`../threat-model.md`](../threat-model.md).
- Prior art in this repo: [ADR 0008](0008-device-key-request-auth.md) (v1
  device-key auth), [ADR 0010](0010-op-log-auth-v2-nonce-replay.md) (v2 nonce +
  replay), [ADR 0018](0018-managed-oplog-migrations-and-backup-integrity.md)
  (the migration machinery `0002_devices.sql` rides on).
