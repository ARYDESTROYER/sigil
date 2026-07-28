# sigild deployment runbook

> **STATUS: pre-audit skeleton / NOT APPLIED.** This is the deployment *story*
> for `sigild`, the Sigil sync server. Nothing here has been provisioned,
> applied, or exposed to the public internet. The artifacts under
> [`../deploy/`](../deploy/) are reference shapes, and `sigild` itself is a
> skeleton that performs **no cryptography on vault content** and **runs no auth
> in its default configuration** (vault ops default to `501`; an opt-in
> `SIGILD_ENABLE_DEV_OPS` dev-only store of opaque client-encrypted blobs —
> in-memory, file-backed, or durable Postgres — exists for local wiring only,
> never expose it). ⚠️ **Both halves of that sentence used to be stated
> unqualified and both were false.** `sigild` verifies Ed25519 request signatures,
> hash-chains the op-log with SHA-256, digests enrollment/admin tokens and
> verifies provider webhook HMACs in constant time — it holds no key that can
> **decrypt a vault**, which is the actual property. And it has had real request
> auth since Phase 41 (contract v3: a device registry, per-vault authorization,
> revocation and, since Phase 52, accounts) — **opt-in and dev-gated**, but
> emphatically built. Treat every "production" word below as
> *future, unbuilt, unaudited*. See [`sprint-72h.md`](sprint-72h.md) for the
> wall-clock gates and the defer ledger this descends from.

This document is intentionally honest about what is and is not deployable today,
and about what could and could not be validated on the build machine (a macOS
arm64 laptop with Docker installed — so the image was built and probed; Caddy,
Terraform, and Nomad were then installed via `brew` and their **native offline
validators** run against the IaC, and a **loopback-only** local compose stack
was brought up as a topology smoke; only `systemd-analyze` remains unavailable on
macOS, so the systemd unit is still by-eye — see the
[validation status table](#8-validation-status)).

---

## 1. Topology & progression

Three shapes, in increasing scale. Each is a strict superset of the last; we do
not skip ahead. The driver is operational burden, not feature need.

```
            Internet
               │  :443 (TLS 1.3, classical groups at the edge)
               ▼
        ┌──────────────┐
        │    Caddy     │   TLS-terminating reverse-proxy edge
        │  (edge/ACME) │   deploy/caddy/Caddyfile
        └──────┬───────┘
               │  127.0.0.1:8080 (plain HTTP, loopback only)
               ▼
        ┌──────────────┐
        │   sigild     │   Go-native HTTP listener (:8080)
        │  (skeleton)  │   /healthz, /readyz, /version
        └──────────────┘   /v1/.../ops → 501 (dev-only opt-in via SIGILD_ENABLE_DEV_OPS)
          (future: Postgres + Redis — NOT wired yet)
```

### Shape 1 — single VM + systemd  (the starting point)

- One hardened Hetzner Cloud VM (`deploy/terraform/`), Ubuntu 24.04.
- `sigild` runs as a hardened **systemd** unit (`deploy/systemd/sigild.service`),
  binary at `/usr/local/bin/sigild`, config from an `EnvironmentFile`.
- **Caddy** on the same box terminates TLS on `:443` and reverse-proxies to
  `sigild` on loopback `127.0.0.1:8080`.
- Firewall: only `22` (founder CIDRs), `80`, `443` inbound; everything else
  denied (`deploy/terraform/main.tf`).
- Intended ceiling per the brief: roughly ≤ ~50k users.

### Shape 2 — orchestrated VMs (Nomad + Docker image)

- Same trust boundary, now orchestrated. `sigild` ships as a **container image**
  built from `sigild/Dockerfile` (added on a parallel track — referenced here by
  path, **not created by this track**).
- A Nomad jobspec (`deploy/nomad/sigild.nomad.hcl`) pulls the published image,
  exposes the `http` port (container `:8080`), and registers an HTTP health
  check against `/healthz`.
- Caddy still fronts the service as the TLS edge.

### Shape 3 — Kubernetes (future, deferred)

- Only past the systemd/Nomad ceiling, and only with a platform engineer. No k8s
  manifests exist in this repo and none are planned for the sprint. Listed for
  completeness; explicitly in the defer ledger (`sprint-72h.md`).

---

## 2. Artifact flow (build → image → run → probe)

```
sigild/Dockerfile ─┐
                   │  .github/workflows/publish-sigild.yml
                   │  (MANUAL — workflow_dispatch only)
                   ▼
        build ──push──▶ PRIVATE GHCR package (ghcr.io/<owner>/sigild:<tag>)
                                                          │
                                                          ▼
                                          deploy/nomad/sigild.nomad.hcl  (image = …)
                                                          │ nomad job run
                                                          ▼
                                                   sigild container :8080
                                                          ▲
                                          deploy/caddy/Caddyfile  (reverse_proxy → :8080)
                                                          ▲
                                              probes: /healthz · /readyz
```

1. **Build → image → push** is the **manual** workflow
   [`.github/workflows/publish-sigild.yml`](../.github/workflows/publish-sigild.yml).
   It is **`workflow_dispatch`-only** — it has **no `push`/`pull_request`
   triggers**, so it never runs on commit; a **human triggers it deliberately**.
   It builds the image from `sigild/Dockerfile`, tags it with the short git SHA
   (matching `sigild`'s build-time `-ldflags` version injection,
   see [§6](#6-versioning--probes)), and pushes it to **GitHub Container Registry
   as a PRIVATE package** `ghcr.io/<owner>/sigild`. While in stealth the package
   **must stay private** (no public image leaks the project). This manual gate is
   recorded in [`decisions/0009-manual-gated-deploy-and-publish.md`](decisions/0009-manual-gated-deploy-and-publish.md).
2. **Repoint the Nomad jobspec.** The jobspec currently points at the placeholder
   `ghcr.io/PLACEHOLDER/sigild:latest`; once a human has published a real image
   via the workflow above, this must be repointed at
   `ghcr.io/<owner>/sigild:<tag>` (do **not** invent a registry path here — the
   owner is filled in only when the package actually exists).
3. **Run**: `nomad job run deploy/nomad/sigild.nomad.hcl` (Shape 2), or
   `systemctl start sigild` against the binary (Shape 1).
4. **Front** it with Caddy as the TLS edge.
5. **Probe** liveness/readiness — see [§6](#6-versioning--probes).

> **Nothing here runs by itself.** The publish workflow never fires
> automatically, and no `nomad job run` / `systemctl start` has been executed.
> Publish and apply both **await an explicit human action** (and a purchased
> domain + provisioned secrets) — see [§9](#9-local-topology-check) and the
> stealth gate at the end of [§7](#7-what-is-not-yet-deployable).

For Shape 1 there is no image at all: CI builds the `sigild` binary, ships it to
`/usr/local/bin/sigild`, and systemd runs it directly. The image step exists only
from Shape 2 onward.

---

## 3. PQ-TLS nuance (read this before claiming a PQ proof)

The sprint's stretch goal is to demonstrate the **`X25519MLKEM768`** hybrid
key-exchange group being negotiated. There is a sharp, easy-to-get-wrong
distinction:

- **Caddy at the edge terminates TLS with its classical groups.** A successful
  `https://api.<host>/` handshake through Caddy proves *classical* TLS 1.3. It
  does **NOT** prove PQ-TLS, even though the connection is encrypted.
- The `X25519MLKEM768` hybrid handshake must be proven **against the Go-native
  `sigild` listener** (Go 1.24.x, which negotiates the hybrid group by default
  when `CurvePreferences` is left `nil`), **not** against the Caddy edge.

So a real PQ proof bypasses Caddy and speaks TLS directly to a `sigild` listener
configured for TLS (the skeleton's `cmd/server` currently serves **plain HTTP**;
a TLS-terminating `sigild` listener is required for this test and is not in the
skeleton). The Caddyfile itself carries this warning inline.

> **Honest restatement:** Do not label a Caddy classical handshake as the PQ
> proof. The proof is: a Day-0-validated **OpenSSL 3.5+ / Go 1.24.x** client
> negotiating `X25519MLKEM768` directly against a Go-native `sigild` TLS
> listener. The build machine's system OpenSSL is **LibreSSL**, which *cannot*
> negotiate this group — a PQ-capable client must be provisioned first. Until
> that client connects to a TLS-enabled `sigild`, the PQ-TLS claim is **unproven**
> and must not appear on any surface (`sprint-72h.md`, zero-over-claims gate).

---

## 4. DNS / ACME wall-clock gate

Caddy obtains a Let's Encrypt certificate via the ACME HTTP-01 (or TLS-ALPN-01)
challenge. That requires the public **A/AAAA record for `api.<host>` to already
resolve to the VM's IP**, because the ACME server connects back to that hostname
to validate control.

Ordering (none of these steps is instantaneous):

1. Provision the VM, obtain its public IPv4/IPv6 (`terraform output sigild_ipv4`).
2. Create the `api.<host>` A/AAAA record pointing at that IP; **wait for DNS to
   propagate**.
3. Only then start Caddy. On first boot before propagation, ACME will fail —
   budget retry/backoff and do not interpret early failures as misconfiguration.

There is a deeper gate from the sprint plan: **NS propagation must complete
before DNSSEC DS and before ACME**, and Hetzner identity-check / domain purchase
are upstream of all of this. None of those are done; this runbook assumes they
will be, when a human clears them. We do **not** register a domain or invent one
here (`example.com` in the Caddyfile is a deliberate placeholder).

---

## 5. Secrets posture

**No secret ever lives in the repo.** Configuration reaches `sigild` only at
runtime:

- **Shape 1 (systemd):** an `EnvironmentFile=/etc/sigild/sigild.env` sourced from
  the team password manager (`SIGILD_ADDR`, future `SIGILD_POSTGRES_ADDR`,
  `SIGILD_REDIS_ADDR`, etc.). The file is created out-of-band on the VM, never
  committed.
- **Shape 2 (Nomad):** env via the jobspec for non-secret values (e.g.
  `SIGILD_ADDR`); real secrets via **Nomad template / Vault** integration,
  **never baked into the image**. The jobspec comment states this.
- **Terraform:** `hcloud_token` and friends come from a gitignored `*.tfvars`
  sourced from the password manager; `variable "hcloud_token"` is marked
  `sensitive = true`.

Backstops:

- [`../.gitleaks.toml`](../.gitleaks.toml) scans for committed secrets (wired into
  CI).
- The **secret-rotation runbook** (revoke → update password manager → redeploy →
  purge history → log) lives in [`sprint-72h.md`](sprint-72h.md#secret-rotation-runbook-gitleaks-fired--suspected-leak).

The team password manager is the single source of truth / registry-of-record for
all credentials. **Payment-provider credentials** (Stripe / Razorpay / Juspay API
keys and webhook signing secrets) are governed by exactly this posture — see
[§13.3](#133-secrets) for the payment-specific notes.

---

## 6. Versioning & probes

`sigild` exposes two probe endpoints (this is the **actual** surface in the
skeleton — there is intentionally no separate `/version` route):

| Probe       | Purpose                       | Skeleton behaviour |
|-------------|-------------------------------|--------------------|
| `GET /healthz` | liveness — process is serving | always `200`; JSON `{"status":"ok","version":<v>}` |
| `GET /readyz`  | readiness — deps reachable    | `200` if configured deps dial OK or are unconfigured; `503` if a *configured* dep is unreachable; JSON includes per-dep `checks` and `version` |

> **Note on `/version`:** the brief sometimes refers to a `/version` probe. The
> skeleton does **not** expose a standalone `/version` endpoint — the build
> version is carried in the `version` field of the `/healthz` and `/readyz` JSON
> responses instead. If a dedicated `/version` route is wanted, it must be added
> to `sigild` (out of scope for the deploy track). Don't document a route that
> doesn't exist.

The `version` value is injected at build time from the git short SHA via
`-ldflags` (default `"dev"`); see `sigild/internal/buildinfo/buildinfo.go`. Tag
the container image with the same SHA so the probe value and the image tag agree.

The Nomad jobspec health-checks `/healthz` (liveness). `/readyz` is the right
probe for load-balancer draining once Postgres/Redis are actually wired, since it
returns `503` when a configured dependency is down.

**Metrics scrape target (`GET /metrics`).** Alongside the probes, `sigild`
exposes an **always-available** `GET /metrics` in **Prometheus text format** for
operational scraping — process counters only (HTTP requests, op-log appends,
verifies, auth denials by reason, rate-limit rejections, and `build_info` with
the build version). It is **stdlib-only** (no metrics client library), holds **no
secrets** — no blob, key, signature, nonce, or vault ID — and does **no crypto**,
so it is safe to scrape from an internal Prometheus without weakening the trust
boundary. It is **not** a health probe (use `/healthz` / `/readyz` for that);
keep it on the loopback / internal side of Caddy rather than exposing it
publicly. Full metric list in [`api.md`](api.md#metrics).

> ⚠️ **The reference Caddyfile CONTRADICTS the previous sentence, and it is worth
> knowing before anyone applies it.** [`../deploy/caddy/Caddyfile`](../deploy/caddy/Caddyfile)
> is a bare catch-all `reverse_proxy 127.0.0.1:8080` with **no path matcher**, so
> in the documented topology `GET /metrics` would be **world-readable** at the
> edge — the endpoint is always-on and never dev-gated. Nothing is deployed, so
> this has never been observed end to end; it is a config that disagrees with its
> own runbook. Before any real edge exists, either block `/metrics` at Caddy (a
> path matcher returning `403`, or an `@internal` remote-IP matcher) or bind the
> scrape to a separate internal listener. Filed here rather than "fixed" quietly
> because the file is a **reference shape**, not an applied config.
>
> It leaks no blob, key, signature, nonce, vault ID or device ID even if exposed —
> but it is still an unauthenticated aggregate view of a private system, and
> [`api.md`](api.md#denial-reasons-audit--metrics-only) records the residual
> correlation oracle its denial labels carry.

**Fail-fast config validation at boot.** `sigild` **validates its configuration
at startup and refuses to boot on a malformed value** (e.g. a bad
`SIGILD_ADDR`, a non-numeric `SIGILD_OPLOG_RATE_LIMIT` / `SIGILD_OPLOG_RATE_BURST`, or
a `SIGILD_OPLOG_PUBKEY` that is not valid base64 of a 32-byte key), exiting
non-zero with a clear message rather than starting misconfigured and failing
later at request time. Under systemd (Shape 1) a bad `EnvironmentFile` therefore
surfaces immediately as a failed unit start, not as silent misbehaviour.

---

## 7. What is NOT yet deployable

To avoid any over-claim, the honest gaps:

- **`sigild` does no cryptography ON VAULT CONTENT, and its DEFAULT
  configuration runs no auth.** ⚠️ Read both clauses precisely — the unqualified
  version of this bullet was **false** and would have scoped the server's
  cryptography out of an external review. `sigild` verifies Ed25519 request
  signatures, hash-chains ops with SHA-256, digests enrollment/admin tokens and
  verifies webhook HMACs in constant time (§§13–14), and it stores devices'
  **public** Ed25519 and hybrid keys plus provider webhook **secrets** in config.
  What it holds is no key that can **decrypt a vault**. Likewise "no auth" means
  *not configured by default*: the multi-device contract v3 and the account model
  are real, tested, opt-in and dev-gated (§14). The vault operation log
  (`/v1/vaults/{id}/ops`) **defaults to `501`** and stays that way in any
  production configuration. It can be turned on **only as a dev scaffold** by
  setting the environment variable **`SIGILD_ENABLE_DEV_OPS`**; when enabled and
  with no auth contract configured it is an **in-memory, non-durable,
  UNAUTHENTICATED** store of **opaque
  client-encrypted blobs** — the server does no crypto on them and never sees
  plaintext or vault keys (POST → `201 {vaultID, seq}`; GET → the stored blobs base64-encoded,
  **paginated** via `?limit` (default 500, max 1000) + a `has_more` flag).
  Oversized bodies are capped at 64 KiB and rejected with **`413`**. Appends can
  optionally be **rate-limited per vault** with **`SIGILD_OPLOG_RATE_LIMIT`**
  (sustained appends/sec/vault) and **`SIGILD_OPLOG_RATE_BURST`** (bucket depth) — a
  stdlib token-bucket that returns `429` + `Retry-After` when exceeded, **off by
  default**; these are **dev-op knobs** that apply only when
  `SIGILD_ENABLE_DEV_OPS` is set and do not change the production `501` default.
  ⚠️ **This bullet used to end "There is still no auth, no durability, no
  Postgres" — three claims that stopped being true at Phases 41, 25 and 24
  respectively.** What is actually true: auth, durability and the Postgres backend
  all exist, are tested, and are **opt-in and dev-gated**; none of them is
  configured by default; and there is still **no real op/CRDT merge semantics**,
  no account/session/identity system and no production change-management around
  any of it.
  **A rejected write no longer claims a vault** ([ADR 0045](decisions/0045-claim-precondition-rejected-writes-never-claim.md)):
  before Phase 57 an empty-bodied append answered `400` while permanently taking
  ownership of the vault id it named, and the per-vault rate limiter could not
  bound it because a squatter varies the vault id. Operationally the thing to know
  is that an empty/malformed write to an **unowned** vault now answers **`403`**,
  and that **no per-account claim budget exists** — an authenticated device can
  still squat ids with well-formed writes.
  **Do NOT set `SIGILD_ENABLE_DEV_OPS` on any exposed instance** — the dev
  op-log must never be reachable from the public internet, and no real secrets
  may be stored in it. This honours the "stub with `501` rather than poison the
  audit" guardrail (brief §14): the production default stays `501`. See
  [`api.md`](api.md) for the full contract.
- **Billing is in the codebase but is not a payment integration you can deploy.**
  The Stripe / Razorpay / Juspay adapters, their webhook signature verification,
  the subscription state machine and the idempotency ledger are **real code that
  really runs** — but they are **opt-in, dev-gated (`501` by default),
  UNAUDITED**, and **have never been run against a live provider account**; the
  Juspay scheme is explicitly **UNVERIFIED-AGAINST-LIVE-DASHBOARD**. A
  subscription now keys off the buying device's **ACCOUNT**
  ([§14](#14-account-model-operator-guide--dev-gated)) rather than the device —
  but an account is **not an identity**: no email, no password, no operator
  break-glass — the only recovery is a **paper kit printed in advance**
  ([§17](#17-recovery-kits-operator-guide--dev-gated)) — and every device enrolled
  before migration `0005` was adopted into its **own** account, so an existing
  two-device customer has **two** billing subjects. Entitlement **can** now be
  enforced ([§16](#16-entitlement-enforcement-operator-guide--opt-in)), but it is
  **off by default**, refuses **writes only**, and **never refuses reads**. There
  is no recurring-subscription creation for the India adapters, no
  fraud/chargeback/refund/proration/tax handling, and **no PCI attestation**
  (hosted checkout keeps card data out of the process entirely, which minimizes
  scope but certifies nothing). Operator guide and the mandatory-TLS requirement:
  [§13](#13-billing--payment-providers-operator-guide--opt-in-dev-gated).
- **No production data store is wired.** The dev op-log can now be pointed at a
  real Postgres via **`SIGILD_OPLOG_POSTGRES`** (a libpq DSN, on the `pgx`
  driver — `sigild`'s first third-party dependency, so the module now carries a
  `go.sum`) for a **durable, concurrent** dev backend
  ([`decisions/0014-postgres-durable-oplog-backend.md`](decisions/0014-postgres-durable-oplog-backend.md)).
  That backend now has **managed, versioned schema migrations**
  ([§11](#11-schema-migrations-postgres-backend)) and a **backup / restore
  runbook whose integrity is provable via the op-log hash chain**
  ([§12](#12-backup--restore-postgres-backend);
  [`decisions/0018-managed-oplog-migrations-and-backup-integrity.md`](decisions/0018-managed-oplog-migrations-and-backup-integrity.md)),
  but production persistence is **still broader and unbuilt** — an **auth /
  enrollment model, CRDT / merge semantics**, and production-grade
  **backup / PITR / replication** (Postgres + object store + Redis) around it —
  none of which exist. Redis / S3(R2) are still only env-var names and
  readiness-probe targets; the first RLS-posture migration is still in the
  stretch tier and **not done**. As with all dev-ops, **do not enable
  `SIGILD_ENABLE_DEV_OPS` (or wire a Postgres DSN) on any exposed instance** — the
  dev op-log must never be reachable from the public internet, and no real
  secrets may be stored in it.
- **No live PQ-TLS proof.** `sigild`'s skeleton listener serves plain HTTP; a
  TLS-enabled Go-native listener and a PQ-capable client are prerequisites that
  do not exist on the build machine (LibreSSL can't negotiate the group). See
  [§3](#3-pq-tls-nuance-read-this-before-claiming-a-pq-proof).
- **Clients are dev-only / NOT deployed.** No admin console consumes this server. The
  demo **`sigil` CLI** does — `push`/`pull` against the dev op-log and, as of Phase 42,
  `sigil device enroll|list|revoke|grant` against a `SIGILD_DEVICE_AUTH` server
  (**contract v3**, so a client exercises the device model end to end) — and so do the
  **webapp and the MV3 extension**, which since Phase 44 enroll and sign under the same
  contract and since Phase 48 also drive the vault-sharing routes, and since Phase 49
  the **native desktop app**, which does all three by calling the CLI's library rather
  than reimplementing the protocol
  ([`decisions/0037-desktop-reuses-cli-library-for-protocol.md`](decisions/0037-desktop-reuses-cli-library-for-protocol.md)).
  All of it is
  **dev / localhost / plain HTTP, nothing deployed**. `libsigil`'s
  real-but-**unaudited** AEAD building block is **not wired into any product flow**.
  A **`web/apps/webapp`** Next.js app now exists — it runs the libsigil core via
  **WebAssembly, entirely client-side** (an **installable, offline-capable, accessible**
  encrypted-TOTP authenticator over the **`@sigil/wasm`** loader;
  [`decisions/0027-webapp-and-wasm-bundling.md`](decisions/0027-webapp-and-wasm-bundling.md),
  [`decisions/0029-webapp-pwa-offline-a11y-and-ci.md`](decisions/0029-webapp-pwa-offline-a11y-and-ci.md)) —
  but it is **dev / no-index / UNAUDITED and NOT deployed** (no build/host target here,
  same stealth `X-Robots-Tag noindex` + `robots.txt Disallow: /` posture as marketing).
  Unlike marketing, **building it requires the Rust + wasm-pack toolchain** (its
  `@sigil/wasm` dependency compiles the repo-root `sigil-wasm` crate to wasm), so it is
  **deliberately kept OUT of the default `web` CI job** — the root `web` scripts still
  filter to marketing only, keeping that job Rust-free — and it must be built/run
  explicitly. A **separate `webapp` CI job** in `.github/workflows/web.yml` now builds
  `@sigil/wasm` (Rust + `wasm-pack`/`wasm-bindgen-cli` on the runner) and runs the
  Playwright suite (including the offline + axe a11y proofs); like **every other CI
  mirror in this repo**, that job has been **validated by-eye / YAML-parsed locally and
  mirrors the known-green local commands — it has NOT been run on real GitHub Actions
  from this machine**. The webapp itself remains dev-only and is not deployed.
- **Nothing is applied or exposed.** No VM exists, no domain is registered, no
  image is published (the publish workflow is **manual-only** and has **not** been
  run — there is no GHCR auth here), no Nomad cluster runs, no public Caddy is
  serving. The image reference is still a placeholder. The IaC is **validated but
  not applied** (no `terraform apply`, no `nomad job run`), and the only thing
  that ran is a **disposable, loopback-only** compose smoke ([§9](#9-local-topology-check)).
  Publish + apply both **await an explicit human action**, a purchased domain, and
  staged secrets — see [`decisions/0009-manual-gated-deploy-and-publish.md`](decisions/0009-manual-gated-deploy-and-publish.md).
- **Posture is stealth / pre-launch.** No public, no-index, request-beta-access.
  No security claims ("audited", "SOC 2", "post-quantum secure", unqualified
  "end-to-end encrypted") may be made until the audit completes and trademark
  clears.

---

## 8. Validation status

The build machine is macOS arm64. **Docker is installed**, and **Caddy,
Terraform, and Nomad were installed via `brew`** so their native **offline**
validators could be run. The container image was **actually built, run, and
probed**; the Caddy / Terraform / Nomad artifacts were **validated with their
native offline validators**; the Caddy → `sigild` edge was brought up as a
**loopback-only compose smoke**. The **only** artifact still reviewed *by eye*
is the systemd unit, because **`systemd-analyze` does not exist on macOS**. This
split is stated plainly so no false confidence is implied. Every tool result
below is an **offline syntax/schema check** (or a local smoke) — none asserts
that any cloud resource, public certificate, or live cluster exists.

| Artifact | How checked | Result / notes |
|----------|-------------|----------------|
| `sigild/Dockerfile` | **Built, run, and probed** — `docker build` (multi-stage → distroless, ~14 MB), `docker run`, then `curl` against the live container. | **Validated locally.** `/healthz` returned the stamped `VERSION` build-arg in its `version` field, `/readyz` reported deps `unconfigured`, and vault ops still `501` (the dev op-log is gated behind `SIGILD_ENABLE_DEV_OPS`, unset in the image — production default). Publish to a PRIVATE GHCR package is the future, **human-triggered** step ([§2](#2-artifact-flow-build--image--run--probe)). |
| `.github/workflows/publish-sigild.yml` | YAML reviewed by eye; **NOT executed here** (no GHCR auth, and it is `workflow_dispatch`-only by design). | **Manual-only:** no `push`/`pull_request` triggers, so it never fires automatically; a human runs it to publish a **PRIVATE** `ghcr.io/<owner>/sigild` package. Intentionally **not run** from this machine. |
| `deploy/local/compose.yaml` | **Brought up on loopback and probed**, then torn down — local Caddy → `sigild` topology smoke ([§9](#9-local-topology-check)). | **Local shape check only.** The stack is **published on `127.0.0.1:8080` (host) → Caddy `:80`**; Caddy then reverse-proxies to `sigild` **over the compose network** (Docker DNS on the service name, *not* loopback). The loopback `127.0.0.1:8080` Caddy→`sigild` hop is the **production** single-VM shape ([§1](#1-topology--progression)), not the local one. Probes answered through the edge. **No real TLS/ACME, no PQ proof, not exposed.** Disposable — not a deployment. |
| `deploy/preflight.sh` | Logic reviewed; gates exercised against the local/unstaged environment ([§10](#10-preflight-go--no-go-gates)). | Encodes the **GO/NO-GO** gates (DNS resolves, `EnvironmentFile` present, image not the placeholder, Docker present). Read-only; **provisions/exposes nothing**. A real target is unstaged, so it correctly reports NO-GO until a human stages DNS + secrets + a published image. |
| `deploy/caddy/Caddyfile` | **`caddy validate`** (Caddy installed via `brew`). | **Tool-validated (offline).** Reverse-proxy target `127.0.0.1:8080` matches `sigild`'s default `:8080`. `api.example.com` is a deliberate placeholder. PQ-TLS caveat present inline. Validates the config **parses**; it does not obtain or test any certificate. |
| `deploy/nomad/sigild.nomad.hcl` | **`nomad job validate`** (Nomad installed via `brew`). | **Tool-validated (offline).** Port `to = 8080` and the `/healthz` check match `sigild`. Image is still the placeholder `ghcr.io/PLACEHOLDER/sigild:latest` — must be repointed at the PRIVATE GHCR image once a human publishes one ([§2](#2-artifact-flow-build--image--run--probe)). Validates the jobspec **schema**; it does not contact a cluster. |
| `deploy/systemd/sigild.service` | **By eye only** — **`systemd-analyze verify` does not exist on macOS**. | `ExecStart=/usr/local/bin/sigild`, `EnvironmentFile` for secrets, hardening directives present. Consistent with Shape 1. No errors spotted; **NOT tool-validated** — run `systemd-analyze verify` on a Linux host. |
| `deploy/terraform/main.tf`, `variables.tf` | **`terraform fmt -check`** + **`terraform validate`** (Terraform installed via `brew`). | **Tool-validated (offline).** Firewall opens only 22/80/443; `hcloud_token` is `sensitive`; outputs the VM IPv4. Validates **syntax + provider schema**; **nothing is applied** (no `terraform apply`), so no VM, IP, or firewall exists. |

> **Honest summary:** the Docker image was **built and smoke-tested locally**
> (all endpoints probed on a running container). Caddy, Terraform, and Nomad were
> installed via `brew` and their **offline validators** run against the IaC
> (`caddy validate`, `terraform fmt -check` + `terraform validate`,
> `nomad job validate`); the four artifacts that have native offline validators
> now pass them. `systemd-analyze` is **not available on macOS**, so the systemd
> unit is still reviewed **by eye only** — run `systemd-analyze verify
> sigild.service` on a Linux host before treating Shape 1 as deployable. The
> validators are **offline syntax/schema checks only**: a green result means the
> file parses and is internally consistent, **not** that any cloud resource,
> certificate, or cluster exists.

---

## 9. Local topology check

[`../deploy/local/compose.yaml`](../deploy/local/compose.yaml) brings up the
**Caddy → `sigild`** edge shape on the **local machine only**, to exercise the
proxy/app wiring before any real host exists. It is a **shape check, NOT a
deployment**:

- **Loopback only.** Ports are published to `127.0.0.1` exclusively; nothing
  binds a public interface and nothing is reachable from the internet.
- **No real TLS / no ACME.** Local Caddy runs with automatic HTTPS off (or `tls
  internal` for a throwaway self-signed cert) — it never contacts Let's Encrypt
  and obtains no publicly-trusted certificate. The DNS/ACME gate in
  [§4](#4-dns--acme-wall-clock-gate) is therefore **not** exercised here.
- **No PQ proof.** This stack does not prove `X25519MLKEM768`; the PQ caveat in
  [§3](#3-pq-tls-nuance-read-this-before-claiming-a-pq-proof) is unchanged. A
  Caddy handshake here is, at most, local classical TLS.
- **Disposable.** It is brought up, probed (`/healthz`, `/readyz`), and **torn
  down** (`docker compose down`); it leaves nothing running and provisions
  nothing.

Its purpose is to confirm the **topology** (Caddy reverse-proxying to `sigild` on
loopback, probes answering through the edge) matches §1, using the same image the
publish workflow would build. It deliberately proves **nothing** about DNS,
public TLS, PQ-TLS, durability, or auth.

---

## 10. Preflight (GO / NO-GO gates)

[`../deploy/preflight.sh`](../deploy/preflight.sh) encodes the **GO / NO-GO
checklist** that must pass **before any real deploy**. It is a read-only gate — it
**provisions nothing and exposes nothing**; it just refuses to let a deploy
proceed against an unready environment. The gates it checks:

- **DNS resolves** — the target `api.<host>` A/AAAA record actually resolves (the
  ACME prerequisite from [§4](#4-dns--acme-wall-clock-gate)).
- **`EnvironmentFile` present** — the out-of-band secrets file
  (`/etc/sigild/sigild.env`, [§5](#5-secrets-posture)) exists on the target; it is
  never committed and must be staged from the password manager first.
- **Image is not the placeholder** — the Nomad jobspec no longer points at
  `ghcr.io/PLACEHOLDER/sigild:latest`; a real published image has been wired in
  ([§2](#2-artifact-flow-build--image--run--probe)).
- **Docker present** — the build/run toolchain is available on the host.

A failing gate is a **NO-GO**: fix the prerequisite, do not override. Passing
preflight is **necessary but not sufficient** — it confirms the environment is
*staged*, but the actual publish + apply still require the explicit human action
described in [§2](#2-artifact-flow-build--image--run--probe) and the stealth gate
in [§7](#7-what-is-not-yet-deployable).

---

## 11. Schema migrations (Postgres backend)

The **durable Postgres op-log backend** (`SIGILD_OPLOG_POSTGRES`) manages its
database schema with **versioned, embedded migrations** rather than the old
ad-hoc `IF NOT EXISTS` DDL that construction used to run inline
([`decisions/0018-managed-oplog-migrations-and-backup-integrity.md`](decisions/0018-managed-oplog-migrations-and-backup-integrity.md)).
This applies **only** to the Postgres backend; the in-memory and file-backed dev
backends have no database and no migrations, and the whole thing is inert unless
`SIGILD_ENABLE_DEV_OPS` is set (vault ops otherwise stay `501`).

- **Embedded + versioned in the binary.** Each migration is an embedded
  `NNNN_description.sql` file (`go:embed`, `sigild/internal/store/migrations/`);
  the zero-padded leading integer is the version and migrations apply in ascending
  order; the current set is **`0001_init.sql`**, **`0002_devices.sql`**,
  **`0003_billing.sql`**, **`0004_key_sharing.sql`** and **`0005_accounts.sql`**
  (version `5`).
  `0001` creates the `sigil_vault_ops` table (opaque `bytea` `blob` + `bytea`
  `hash` + `(vault_id, seq)` primary key). A **`schema_migrations`** tracking
  table (`version`, `name`, `applied_at`) records what has been applied, so a run
  is idempotent and auditable.
- **Auto-applied at boot by default.** When the Postgres backend starts it brings
  the schema up to date automatically (a fresh DB is set up exactly as the old
  inline DDL did — backward compatible; an up-to-date DB is a no-op).
- **Opt out with `SIGILD_OPLOG_AUTO_MIGRATE=0`** (`0` / `false` / `no` / `off`,
  case-insensitive). Then boot applies **nothing**; if the DB is behind the latest
  embedded migration, `sigild` **fails fast at startup** with a clear message
  telling the operator to run `sigild migrate`. This is the recommended posture
  for a controlled deploy where migrations run as a separate, gated step.
- **Operator CLI (not an HTTP endpoint).** `sigild migrate` applies all pending
  migrations; `sigild migrate status` prints each known migration as `[applied]`
  (with its `applied_at`) or `[pending]` and applies nothing; **`sigild migrate
  adopt`** re-runs the account backfill (§11.1). All three read the DSN from
  `SIGILD_OPLOG_POSTGRES` and error clearly if it is unset.
- **Safe concurrent boots.** The whole migration run is serialized across
  instances by a **session-level `pg_advisory_lock`** on a fixed key, and each
  pending migration commits in its **own transaction**, so two `sigild` instances
  booting against the same database cannot double-apply — one migrates, the other
  waits and then sees an up-to-date schema.
- **Observability.** The applied version is exported as the
  **`sigild_schema_version`** gauge on `GET /metrics` (0 for the mem/file
  backends, which have no migrations). See [`api.md`](api.md#metrics).

> **Scope.** These are **pure infrastructure (DDL)** — they create/alter the
> table that holds **opaque client-encrypted blobs**; they never decode, parse, or
> touch blob contents and perform **no cryptography** (zero-knowledge boundary
> intact). This is a real, ordered, tracked migration system for the **dev**
> Postgres backend; it is **not** a production change-management pipeline (no
> down-migrations, no online/zero-downtime rewrites, no managed rollout tooling).

> ⚠️ **Testing caveat — the Postgres store suite has NO per-run schema
> isolation.** `SIGILD_TEST_POSTGRES` points the gated store/integration tests at
> a real database, and they share one schema with no per-run namespace, prefix or
> temporary schema. **Two concurrent `go test ./...` runs against ONE database
> corrupt each other** (and will produce confusing, non-deterministic failures
> rather than a clean error). Give each concurrent run its **own database**, or
> serialize them. The same applies to running the gated suite while
> `cli/tests/e2e-accounts.sh` or `e2e-sharing.sh` is pointed at that DSN.
>
> **Phase 54 added no migration.** The recovery kit needed none — a kit is an
> ordinary device, and its self-only envelope index reuses the
> `sigil_vault_key_envelopes_by_recipient` index created by `0004`. Phase 53,
> Phase 55, Phase 56 and Phase 57 added none either. **`sigild_schema_version` is
> still `5`.**
>
> ⭐ **Run the gated suite. Do not let it skip.** Without `SIGILD_TEST_POSTGRES`
> roughly **30 tests skip silently**, and the fourth audit showed **two real
> regressions survive a DSN-less run** while going red with one: deleting
> `0005`'s ownership backfill, and dropping the active-device filter from the seat
> count (which is the account-bricking defect Phase 52 recorded). `scripts/gate.sh`
> now starts a **throwaway `postgres:16` on a free port** when no DSN is set and
> **FAILS if any test skipped** — the count went from *561 pass / 30 skip* to
> **640 pass / 0 fail / 0 skip**. A green run that skipped a third of the storage
> layer is not a green run.

### 11.1 `sigild migrate adopt` — the account backfill, and when you need it

`0005_accounts.sql` does more than DDL: it **adopts** existing rows into the
account model (see [ADR 0040](decisions/0040-account-model.md)). Inside the
migration's single transaction it

1. mints an `acct_mig_<device_id>` account for every device that has none, active
   **and** revoked, and stamps it onto the device row;
2. records vault ownership for every vault holding a legacy `is_owner` grant; and
3. re-keys any subscription whose `subject` is a **device** id onto that device's
   account.

⚠️ **`sigil_devices.account_id` is deliberately NULLABLE.** A `NOT NULL` column
would stop a **rolled-back** pre-account binary enrolling at all. The cost of
that choice is the whole of this section:

> **A pre-Phase-52 `sigild` running against an already-migrated database enrolls
> devices with `account_id NULL` and claims vaults by writing an `is_owner` grant
> and no owner row.** Roll forward and those rows are **stranded**: the new binary
> refuses them everywhere with a coarse `403` (`missing_account` /
> `vault_owner_unresolved`, deliberately indistinguishable from any other
> refusal), and **`sigild migrate` will NOT fix it** — `0005` is already recorded
> in `schema_migrations`, so it never runs again.

**The accurate rollback story, therefore:** a rollback **is survivable** — an old
binary keeps running and keeps enrolling — **but any device enrolled during the
rollback window needs `sigild migrate adopt` after you roll forward**, and the
**boot warning below is how you know**.

**How an operator finds out.** Because the refusal is deliberately coarse,
traffic tells you nothing. At boot (Postgres registry only) `sigild` counts both
states and, if either is non-zero, logs:

```
WARN ACCOUNT BACKFILL INCOMPLETE: this database holds rows written by a
     PRE-ACCOUNT-MODEL binary after migration 0005 was applied. … `sigild
     migrate` will NOT fix this — 0005 is already recorded as applied. Run
     `sigild migrate adopt` (idempotent) to repair it
     devices_without_account=N  vaults_with_owner_grant_but_no_owner_row=M
```

The check never blocks a boot: a read failure, or a schema older than the account
model, is logged at debug and ignored.

**The repair.** Idempotent, one transaction, and a no-op when there is nothing to
do — ⚠️ **but "one transaction" is asserted, not tested.** The fourth audit
rewrote `adopt` to run its three steps **non-transactionally** and every suite
stayed green, so nothing would catch a partial repair (some devices adopted, no
ownership recorded) if that atomicity were ever lost. The transaction is real in
the code as it stands; the guarantee simply has no test behind it. Treat a failed
`adopt` as *verify before assuming it did nothing*.

```bash
SIGILD_OPLOG_POSTGRES="$DSN" sigild migrate adopt
# nothing to adopt: every device has an account and every owner grant has an owner row
#   — or —
# adopted 3 device(s) into 3 new account(s)
# recorded ownership for 1 vault(s) from existing owner grants
# re-keyed 0 subscription(s) from a device subject to its account
```

**Post-apply verification** (read-only; all three should be `0`):

```sql
-- devices with no account
SELECT count(*) FROM sigil_devices WHERE account_id IS NULL;

-- vaults whose only ownership record is a legacy owner grant
SELECT count(*) FROM sigil_device_grants g
 WHERE g.is_owner
   AND NOT EXISTS (SELECT 1 FROM sigil_vault_owners o WHERE o.vault_id = g.vault_id);

-- subscriptions still keyed to a device id rather than an account
SELECT count(*) FROM sigil_subscriptions s
  JOIN sigil_devices d ON d.device_id = s.subject;
```

And confirm the schema version moved:

```bash
curl -s localhost:8080/metrics | grep sigild_schema_version   # → 5
```

> **Adoption is NEVER implicit.** It does not happen on the authentication path,
> because that would let an **unauthenticated request mint an account**. It is an
> explicit operator command, and that is the only way it runs.

⚠️ **Two consequences to plan around, not work around:**
>
> - **NO ACCOUNT MERGE.** Every pre-0005 device is adopted into its **own
>   singleton account**, so an existing two-device customer ends up with **two
>   accounts and two billing subjects**. The remedy is manual — revoke one device,
>   re-join it by invite, re-share the vault, rotate — and it **leaves a second
>   subscription row for an operator to reconcile**.
> - **`sigil_billing_processed_events.subject` deliberately keeps pre-0005 DEVICE
>   ids.** It is an append-only record of what was processed at the time, read by
>   no logic; rewriting it to look retroactively consistent would falsify history.
>   **Cross-cutover reconciliation needs BOTH ids.**

---

## 12. Backup & restore (Postgres backend)

Because the Postgres op-log stores **opaque, already-client-encrypted blobs**, a
backup is an ordinary database dump — the server holds no key and no plaintext, so
there is nothing extra to protect beyond the database itself. Restore integrity is
validated with the **existing tamper-evidence hash chain**, not a bespoke
mechanism.

**Back up** the op-log database with a standard logical dump:

```bash
# custom-format dump (recommended: parallelizable, selective restore)
pg_dump --format=custom --dbname="$SIGILD_OPLOG_POSTGRES" --file=oplog.dump
# or a plain-SQL dump restorable with psql
pg_dump --dbname="$SIGILD_OPLOG_POSTGRES" > oplog.sql
```

**Restore** into a fresh database:

```bash
pg_restore --dbname="$TARGET_DSN" oplog.dump      # for the custom-format dump
psql       --dbname="$TARGET_DSN" -f oplog.sql    # for the plain-SQL dump
```

Both the `blob` **and** the `hash` columns are `bytea` and are dumped
**byte-for-byte**, and `schema_migrations` is dumped alongside — so a restore
reproduces the op-log rows, their per-op hash-chain links, and the recorded schema
version exactly. Because the hash chain commits each op to the previous one over
the exact stored bytes, **the tamper-evidence chain survives a dump/restore
unchanged**: an intact restore reproduces the same tip hash a live server would
compute.

**Post-restore integrity gate.** For each vault, call the server-side chain
verifier and confirm it reports an intact chain with the **same `tip_hash`** as
before the backup:

```
GET /v1/vaults/{vaultID}/ops/verify   →  { "ok": true, "count": N,
                                           "tip_hash": "<hex>", "broken_at_seq": 0 }
```

(This route is dev-gated and auth-guarded exactly like the other op-log routes;
see [`api.md`](api.md#get-v1vaultsvaultidopsverify--server-side-chain-check).) A
`tip_hash` that matches the pre-backup value is strong evidence the restore is
faithful; an `ok: false` / non-zero `broken_at_seq` means the restored data does
**not** match its chain and must be investigated. **Phase 28 verification
exercised exactly this cycle** — dump → drop → restore of the op-log database,
then `/ops/verify` per vault returned `ok: true` with the **same `tip_hash`** the
live server produced before the drop, confirming the chain is preserved across a
real backup/restore round-trip.

> **Honest scope.** This is a **dev backend** backup runbook: a logical `pg_dump`
> of a single database with chain-verified restore. Production persistence is
> broader and **unbuilt** — Postgres + object store (S3/R2) + Redis, point-in-time
> recovery (WAL archiving / PITR), streaming replication, and periodic
> restore-drills — none of which exist yet
> ([§7](#7-what-is-not-yet-deployable)). The hash-chain check is
> tamper-**evident**, not a cryptographic backup-authentication scheme.

---

## 13. Billing / payment providers (operator guide — opt-in, dev-gated)

> **READ FIRST: nothing in this section has ever been run against a live payment
> provider account.** No request in this repository has been sent to, or received
> from, `api.stripe.com`, `api.razorpay.com` or `api.juspay.in`; every test drives
> a local `httptest` server with fake credentials. The **Juspay** adapter is
> explicitly **UNVERIFIED-AGAINST-LIVE-DASHBOARD** (its header names, signed
> message, endpoint path and event vocabulary are a best-supported reading).
> Treat this as a scaffold you must **verify against each merchant dashboard**
> before any real money moves. It is **UNAUDITED**, and it is **not** a PCI
> attestation. See [`api.md`](api.md#billing--subscriptions-dev-gated-opt-in--phase-45)
> for the wire contract and
> [`decisions/0034-billing-provider-seam.md`](decisions/0034-billing-provider-seam.md)
> for the decision, as revised by
> [`decisions/0039-webhook-idempotency-from-signed-bytes.md`](decisions/0039-webhook-idempotency-from-signed-bytes.md)
> (the idempotency key now comes from signature-covered bytes, and Juspay's
> default webhook scheme is `hmac`).

`sigild` carries a provider-agnostic billing seam with three **stdlib-only**
adapters — **Stripe** (international), **Razorpay** and **Juspay** (India). It
uses each provider's **hosted checkout** flow only: the server asks for a URL and
hands it to the client, so **no card data ever reaches this process** and there is
no field, log line, metric or database column that could hold one. That keeps PCI
scope at SAQ-A; it does not certify anything.

### 13.1 Enabling it (all off by default)

Billing is **doubly gated**. It requires the dev-ops gate **and** the device-auth
model **and** an explicit provider list; with any of them missing all three
`/v1/billing/*` routes serve a deliberate `501`.

```bash
SIGILD_ENABLE_DEV_OPS=1                 # the whole stateful surface is dev-gated
SIGILD_DEVICE_AUTH=1                    # checkout is authenticated as an ENROLLED DEVICE
SIGILD_BILLING_PROVIDERS=stripe,razorpay,juspay
SIGILD_BILLING_DEFAULT_PROVIDER=stripe  # optional; unset => the first listed
SIGILD_BILLING_SUCCESS_URL=https://app.example/billing/ok      # REQUIRED
SIGILD_BILLING_CANCEL_URL=https://app.example/billing/cancel   # REQUIRED
```

Per-provider credentials (each **required when that provider is listed** — see
[`api.md`](api.md#configuration-environment) for the full table):

```bash
# Stripe
SIGILD_STRIPE_SECRET_KEY=sk_live_...          # API key   (bearer token)
SIGILD_STRIPE_WEBHOOK_SECRET=whsec_...        # ENDPOINT SIGNING SECRET — a DIFFERENT secret
SIGILD_STRIPE_PRICE_ID=price_...              # optional default plan
SIGILD_STRIPE_API_BASE_URL=                   # optional host override

# Razorpay
SIGILD_RAZORPAY_KEY_ID=rzp_live_...
SIGILD_RAZORPAY_KEY_SECRET=...
SIGILD_RAZORPAY_WEBHOOK_SECRET=...            # dashboard webhook secret — DIFFERENT from the key secret
SIGILD_RAZORPAY_AMOUNT_MINOR=49900            # optional default, in paise (positive integer)
SIGILD_RAZORPAY_CURRENCY=INR                  # optional
SIGILD_RAZORPAY_DESCRIPTION="Sigil annual"    # optional
SIGILD_RAZORPAY_API_BASE_URL=                 # optional host override

# Juspay
SIGILD_JUSPAY_MERCHANT_ID=...
SIGILD_JUSPAY_API_KEY=...
SIGILD_JUSPAY_CLIENT_ID=...                   # payment-page client id
SIGILD_JUSPAY_WEBHOOK_SCHEME=                 # hmac (DEFAULT when unset) | basic
SIGILD_JUSPAY_WEBHOOK_SECRET=...              # REQUIRED for scheme=hmac, i.e. whenever the scheme is unset
SIGILD_JUSPAY_WEBHOOK_USERNAME=...            # REQUIRED for scheme=basic
SIGILD_JUSPAY_WEBHOOK_PASSWORD=...            # REQUIRED for scheme=basic
SIGILD_JUSPAY_WEBHOOK_SIG_HEADER=             # optional; default X-Juspay-Signature (name UNVERIFIED)
SIGILD_JUSPAY_AMOUNT_MINOR=49900              # optional default, in paise
SIGILD_JUSPAY_CURRENCY=INR                    # optional
SIGILD_JUSPAY_API_BASE_URL=                   # optional host override
```

**Fail-fast, before the listener binds.** All of the above is parsed and
validated at startup: an unknown or duplicate provider name, a missing credential
for an enabled provider, a `SIGILD_BILLING_DEFAULT_PROVIDER` that is not enabled,
a non-absolute success/cancel URL, a non-positive amount, or an unknown Juspay
scheme makes `sigild` **exit non-zero with a clear message**. Validation performs
**no network I/O**, so boot never contacts a payment provider. Under systemd
(Shape 1) a bad `EnvironmentFile` therefore surfaces immediately as a failed unit
start — which is the point: a server that started half-configured would reject
real webhooks it could not authenticate, or offer checkouts it could not create.

**⚠️ The Juspay webhook scheme defaults to `hmac`, and that default is
load-bearing** ([ADR 0039](decisions/0039-webhook-idempotency-from-signed-bytes.md)).
`hmac` binds the **body**; `basic` authenticates only the **connection**, so
anyone holding the credential can post any body and a modified body cannot be
detected. Leaving `SIGILD_JUSPAY_WEBHOOK_SCHEME` unset therefore selects `hmac`
and makes **`SIGILD_JUSPAY_WEBHOOK_SECRET` required** — enabling Juspay without
it is a boot failure, not a silent downgrade. Choosing `basic` is an **explicit
opt-in**: it is still supported, still fails fast without
`SIGILD_JUSPAY_WEBHOOK_USERNAME` / `_PASSWORD` (with an error message that names
what `basic` gives up), and both schemes fail **closed** when their secret is
unset — an unconfigured verifier accepts nothing.

The boot log records **which** providers are enabled and **which** Juspay scheme
is active — a mechanism name, never a credential — plus the loud warnings: that
billing is unaudited and must be verified against live dashboards, (when Postgres
is not configured) that the subscription store is in-memory, and **on every start
under `scheme=basic`, a `WARN` stating that the scheme authenticates the
connection and not the payload**, that anyone holding the credential can post any
body, and that the endpoint must then be TLS-only with the credential treated as
a bearer secret.

### 13.2 Configuring the provider webhook endpoints

Each provider must be pointed at **its own** path:

| Provider | Endpoint to register in the dashboard | Signature header the dashboard configures |
|----------|----------------------------------------|-------------------------------------------|
| Stripe | `https://<host>/v1/billing/webhook/stripe` | `Stripe-Signature` (`t=…,v1=…`), keyed by the **endpoint signing secret** shown when the endpoint is created — copy it into `SIGILD_STRIPE_WEBHOOK_SECRET` |
| Razorpay | `https://<host>/v1/billing/webhook/razorpay` | `X-Razorpay-Signature`, keyed by the **webhook secret** you type into the dashboard — copy the same value into `SIGILD_RAZORPAY_WEBHOOK_SECRET` |
| Juspay | `https://<host>/v1/billing/webhook/juspay` | `Authorization: Basic …` for `scheme=basic`, or the signature header for `scheme=hmac` (**default `X-Juspay-Signature`; the real name is unconfirmed** — override with `SIGILD_JUSPAY_WEBHOOK_SIG_HEADER`) |

A path that names a provider **not** enabled on this instance returns `404`
(body drained, nothing constructed, no credential read); with billing off
entirely every billing path returns `501`.

**Verification checklist before enabling a provider for real money:**

1. Replay a **real** event from the provider's tooling (e.g. `stripe listen
   --forward-to …`, or a dashboard "send test webhook") and confirm a `200` with
   the expected `status` in the JSON body.
2. Confirm the **exact** signature header name and signed message against the
   dashboard's own documentation for that account — especially for **Juspay**.
   Razorpay's **`X-Razorpay-Event-Id`** header no longer affects behaviour beyond
   what appears in the audit log: the idempotency key is derived from the **signed
   body** regardless ([ADR 0039](decisions/0039-webhook-idempotency-from-signed-bytes.md)).
3. Deliver the **same** event twice and confirm the second answers `200` with
   `"status":"duplicate"` and changes nothing. For Razorpay, also redeliver the
   identical body with a **different** `X-Razorpay-Event-Id`: that must also be a
   `duplicate`, because the header is not the key.
4. Confirm the plan/price/amount parameters against the account's real product
   catalogue — the adapters send what you configure and invent nothing.
5. Confirm `sigild_billing_*` counters move as expected on `GET /metrics`.

**Durability matters here.** Without `SIGILD_OPLOG_POSTGRES` the subscription
store is **in-memory and non-durable**: subscriptions *and* the processed-event
ledger are lost on restart, so a webhook redelivered across a restart **would be
applied twice**. Only the Postgres backend enforces the `(provider, dedup key)`
idempotency key in the database, across processes and restarts. Configure
Postgres before pointing any real provider at the endpoint. Billing adds **no
second connection pool and no new dependency** — it reuses the op-log's existing
`pgxpool` and adds migration **`0003_billing.sql`** (`sigil_subscriptions`,
`sigil_billing_processed_events`, plus `0004_key_sharing.sql`), so
`sigild_schema_version` reports **4**
([§11](#11-schema-migrations-postgres-backend) covers how migrations are applied;
[§12](#12-backup--restore-postgres-backend)'s `pg_dump`/`pg_restore` runbook
covers the new tables too, since they are dumped with the rest of the database).

### 13.3 Secrets

**No payment credential ever lives in the repository.** API keys, key secrets,
webhook signing secrets and Juspay's Basic-auth credentials are exactly the
class of secret [§5](#5-secrets-posture) already governs: they live in the **team
password manager** (the single registry-of-record), reach the process only at
runtime through the systemd `EnvironmentFile` or Nomad template/Vault
integration, and are **never baked into the image, the jobspec, or a committed
file**. [`../.gitleaks.toml`](../.gitleaks.toml) scans for leaks and the
[secret-rotation runbook](sprint-72h.md#secret-rotation-runbook-gitleaks-fired--suspected-leak)
applies unchanged — with the payment-specific note that **the API key and the
webhook secret are different secrets** and can be rotated independently, and that
a leaked **API key** must be revoked **at the provider**, because no server-side
control here can contain it.

`sigild` limits its own exposure by construction: credentials are held only
inside an adapter struct, travel in an `Authorization` (or `x-merchantid`) header
rather than a URL, and are **never logged, never returned in an error, and never
exported on `/metrics`** — a failed provider call surfaces as a `ProviderError`
carrying **only** the provider, the operation and the HTTP status, deliberately
never the response body (which can echo customer data).

### 13.4 TLS is mandatory for webhooks in any real deployment

A webhook is an **unauthenticated-by-transport POST from the public internet**
that carries a signature in a header. In any real deployment it **must** reach
`sigild` over **TLS**, terminated at Caddy ([§1](#1-topology--progression)) with
`sigild` bound to loopback behind it:

- Stripe and Razorpay bind the body with an HMAC, so TLS is about
  **confidentiality and endpoint authenticity**, not integrity of the payload.
- **Juspay's `basic` scheme does NOT bind the body** — it is a shared credential
  in an `Authorization` header. Over plain HTTP it is both interceptable and
  replayable with an arbitrary body. This is why `hmac` is the **default** and
  `basic` is an explicit opt-in warned about at every boot; if you must use
  `basic`, the endpoint has to be TLS-only. Note also that the
  "idempotency key comes from signature-covered bytes" property
  ([ADR 0039](decisions/0039-webhook-idempotency-from-signed-bytes.md)) is
  **vacuous under `basic`**: that scheme covers no bytes, so there is nothing for
  it to be derived from.
- The dev server speaks **plain HTTP**, and the local compose topology
  ([§9](#9-local-topology-check)) has **no real TLS** — so the dev configuration
  is for loopback experimentation only. Do not register a provider webhook
  against it.

Keep `GET /metrics` on the internal side of Caddy as before; the billing counters
carry no secret, but the endpoint is still not meant for the public internet.

### 13.5 What an operator does NOT get

- **No live-account verification** of any provider scheme (above), and **no
  Juspay confirmation** at all.
- **No recurring-subscription creation** for the India adapters — Razorpay's
  `/v1/payment_links` and Juspay's `/session` create a **one-time hosted page**.
  Their webhook sides map subscription/mandate events, so a subscription created
  out-of-band in the dashboard drives the state machine correctly.
- **An ACCOUNT is the subject since Phase 52 — but it is not an identity.** A
  subscription keys off the **account** of the device that ran checkout (§14), so
  one human's devices share one subject. There is still no user record, no email,
  no seat model, no transfer and no recovery beyond a **paper kit printed in
  advance** (§17); ⚠️ every device enrolled before migration `0005` was adopted
  into its **own** account, so an existing two-device customer has **two**
  subjects (§11.1).
- **Entitlement enforcement is available but OFF by default** (§16). Turned on, it
  refuses a lapsed account's **writes** with `402` past a grace period and ⭐
  **never refuses reads or same-account key recovery**. Left off, `entitled` is
  reported by `GET /v1/billing/subscription` and consulted by nothing.
- **No fraud, chargeback, refund, proration, tax, dunning or reconciliation
  handling**, and no billing admin surface.
- ⛔ **No rate limiting on the webhook endpoint, deliberately** — only the 64 KiB
  body cap and the cost of one HMAC. `SIGILD_WEBHOOK_RATE_LIMIT` /
  `SIGILD_WEBHOOK_RATE_BURST` **were built in Phase 53 and REMOVED**; setting
  either now logs a boot WARNING and does nothing. See
  [§15.3](#153-why-the-webhook-route-is-not-rate-limited).
- **No PCI attestation** — hosted checkout minimizes scope; it certifies nothing.

---

## 14. Account model (operator guide — dev-gated)

> **Dev-gated and UNAUDITED.** An account is **auth metadata only**: no email, no
> password, no session, no PII, and **NO RECOVERY**. See
> [`api.md` → Account model](api.md#account-model-dev-gated--phase-52) and
> [ADR 0040](decisions/0040-account-model.md).

Since Phase 52 the subject of **entitlement** and the **owner of vaults** is an
**account**, not a device: paying on one device covers the others, and revoking
the device that claimed a vault no longer orphans it. A second device joins with
a **single-use invite** minted by a device already in the account.

### 14.1 Turning it on (there is no switch)

**There is deliberately no `SIGILD_ACCOUNTS` variable.** Accounts are active
exactly when the v3 device model is — a binary that could run either ownership
model would hold **two ownership truths at once**. Setting any `SIGILD_ACCOUNT_*`
value **without `SIGILD_DEVICE_AUTH` is a boot error**, not a silently ignored
knob.

| Variable | Default | Range | Notes |
|----------|---------|-------|-------|
| `SIGILD_ACCOUNT_MAX_DEVICES` | `10` | `[1, 1000]` | **Active** devices only — a revoked device **frees its seat**. Anti-freeloading, **not** anti-fraud |
| `SIGILD_ACCOUNT_MAX_INVITES` | `5` | `[1, 100]` | **Open** invites per account. Bounds stored **state**, not request volume |
| `SIGILD_ACCOUNT_INVITE_TTL` | `15m` | `(0, 24h]` | Go duration. A client may request a **shorter** life, never a longer one |

All three are validated **fail-fast before the listener binds**, and an
out-of-range value is an **error, never a silent clamp**. At boot with device auth
on, `sigild` logs a WARN naming the active model, the caps, and the two
properties an operator must know: **membership is flat** and **there is no
recovery**.

Storage is migration `0005_accounts.sql` (§11), so **`sigild_schema_version`
reports `5`**. With **no Postgres backend** the registry — accounts, memberships,
invites and vault-owner rows included — is **in-memory and non-durable** and is
lost on every restart (warned at boot); the **file op-log backend was not
extended**.

### 14.2 Provisioning a customer

```bash
# 1) the FIRST device of an account uses an OPERATOR token, which always
#    founds a NEW account:
sigil device enroll --token "$SIGILD_ENROLL_TOKEN_VALUE" --label laptop

# 2) every LATER device joins by invite, minted on a device already in it:
sigil account invite --pin-key "<the joining device's Ed25519 public key, b64>"
#    -> prints the invite secret ONCE, on stdout

# 3) the joining device runs the ORDINARY enroll command:
sigil device enroll --token "join_…" --label phone

# 4) inspect / clean up:
sigil account status
sigil account invites
sigil account revoke-invite inv_…
```

An invite rides the **existing** `X-Sigil-Enroll-Token` header under the
**existing** enrollment challenge, so **no client change was needed** — the
webapp and the MV3 extension can join today by pasting an invite into their
enrollment-token field (neither can *mint* one; the CLI and the desktop app can).

### 14.3 Operational cautions

- ⚠️ **An unpinned invite is a BEARER SECRET** for its whole TTL, over a
  **plain-HTTP** dev transport. Use `--pin-key` where you can; **nothing forces
  it**. It is shown **once** and can never be re-served.
- ⚠️ **Membership is FLAT.** Any member may invite, **revoke every other member**,
  run checkout, and administer every account-owned vault. Revoking a compromised
  device does **not** revoke the devices it invited — the audit log names the
  inviter (`account.device_joined`), but nothing prevents it.
- ⚠️ **RECOVERY EXISTS ONLY IF IT WAS PRINTED IN ADVANCE.** Lose or revoke
  **every** device in an account **without having printed a recovery kit** (§17)
  and the account, its vaults and its subscription are permanently unreachable —
  by the customer and by us. **A kit cannot be created after the loss.** Tell
  customers to **keep two devices enrolled AND print a kit**. There is still no
  email, no password and no operator break-glass.
- **Membership is immutable**: no transfer, no merge, no split, no account
  deletion. A device in the wrong account can only be revoked and re-enrolled.
- **Rate limiting on `POST /v1/devices/enroll` and `POST /v1/account/invites` is
  opt-in and is a BACKSTOP** (§15) — behind a reverse proxy the enrollment bucket
  is global, only failures are charged, and the handler still runs. There is still
  **no sweep job** for expired invite rows.
- **Payment enforcement is opt-in** (§16) and refuses **writes only**. Left off,
  entitlement is reported and never enforced.

### 14.4 What to watch

| Signal | Where |
|--------|-------|
| `sigild_accounts_created_total`, `sigild_account_invites_created_total`, `sigild_account_invites_revoked_total`, `sigild_account_joins_total` | `GET /metrics` — counts only, **no id label ever** |
| `sigild_device_enroll_denied_total{reason="account_full"}` | `GET /metrics` — the one new denial label |
| `sigild_oplog_auth_denied_total{reason="missing_account"\|"vault_owner_unresolved"}` | `GET /metrics` — **non-zero means run `sigild migrate adopt`** (§11.1) |
| `account.created` / `account.device_joined` / `account.invite_created` / `account.invite_revoked` | the structured audit log — metadata only, **never** an invite secret or digest |
| `ACCOUNT BACKFILL INCOMPLETE` | a boot WARN — the only signal that stranded rows exist (§11.1) |

---

## 15. Abuse bounds (operator guide — opt-in)

> **Off by default, and stdlib-only** — no new dependency; `sigild` still has
> exactly one direct Go require (`pgx`). See
> [ADR 0041](decisions/0041-abuse-bounds-and-the-removed-webhook-limiter.md) and
> [`api.md` → Abuse rate limiting](api.md#abuse-rate-limiting-enrollment--invite-minting).

> ⚠️ **Read [`deploy/caddy/Caddyfile`](../deploy/caddy/Caddyfile) before you
> enable either limiter.** Behind the reverse proxy this repo documents, every
> request reaches `sigild` from Caddy's address, so the enrollment limiter
> collapses to ONE global bucket and is a **backstop, not a defence**. The
> Caddyfile now carries a ready-to-uncomment per-source `rate_limit` block for
> the enrollment and invite routes, together with the `xcaddy` line that builds a
> Caddy able to run it — rate limiting is a **plugin**, not a stock module, which
> is why the block ships commented out (a live `rate_limit` directive would fail
> `caddy validate` on a stock binary, and this repo validates its IaC offline).
> That file also records why the billing webhook route must **not** get a rate
> zone, only an allowlist.

### 15.1 The two limiters

| Variable | Default | What it bounds |
|----------|---------|----------------|
| `SIGILD_ENROLL_RATE_LIMIT` | unset ⇒ **no limiter installed** | **failed** `POST /v1/devices/enroll` attempts per second, keyed on the **socket peer address** (IPv4 full address, IPv6 **/64 prefix**) |
| `SIGILD_ENROLL_RATE_BURST` | `ceil(rate)`, minimum 1 | bucket depth |
| `SIGILD_INVITE_RATE_LIMIT` | unset ⇒ no limiter installed | `POST /v1/account/invites` per second, keyed **per account** (siblings share one bucket) |
| `SIGILD_INVITE_RATE_BURST` | `ceil(rate)`, minimum 1 | bucket depth |

All four are validated **fail-fast before the listener binds** (a non-numeric,
negative, NaN or infinite rate, or a non-integer/negative burst, exits non-zero
with a message naming both variables of the pair). Over-rate is `429` with a
typed `rate_limited` body and a `Retry-After` header in whole seconds.

Unlike `SIGILD_ACCOUNT_*`, these deliberately **do not require**
`SIGILD_ENABLE_DEV_OPS` / `SIGILD_DEVICE_AUTH`. Setting one without the dev gate
is a **boot WARNING** saying nothing is being limited, not a boot error: a
protective knob that has become moot should not take a server down, while
anything that *changes behaviour* still fails fast.

**Boot output to expect** when any limiter is on:

```
WARN ABUSE RATE LIMITS ENABLED (per-process, in-memory token buckets) — these bound
     REQUEST VOLUME; the SIGILD_ACCOUNT_* caps bound stored STATE. A multi-instance
     deploy divides each budget across instances (there is no shared limiter store)
WARN ABUSE: the enrollment limiter keys on the SOCKET PEER ADDRESS and IGNORES
     X-Forwarded-For … BEHIND A REVERSE PROXY — THE ONLY TOPOLOGY THIS REPO SHIPS —
     ALL ENROLMENTS SHARE ONE BUCKET, so this is a BACKSTOP, not a defence …
```

### 15.2 Read this before you rely on it

- ⚠️ **It is a BACKSTOP, not a defence.** The only topology this repo documents
  (`deploy/caddy/Caddyfile`, `deploy/local/Caddyfile.local`) is a **reverse
  proxy**, so every request reaches `sigild` from **one** address and the
  enrollment limiter degrades to a **single global bucket**. `X-Forwarded-For` is
  deliberately ignored — without a trusted-proxy configuration it is
  attacker-supplied text, and keying on it would let one client mint unlimited
  buckets. Two properties keep the degraded case safe: the bucket is charged
  **only on the denial path** (so **a valid, unspent credential with a valid proof
  can never be refused by it**), and the limiter **fails open** at its 10,000-key
  cap. An earlier revision did neither and was reproduced **refusing a legitimate
  customer** — a global account-creation off switch.
- ⚠️ **It does not reduce load.** The handler always runs, including its database
  work; the limiter replaces only the response.
- ⚠️ **Per-process and in-memory.** A multi-instance deploy divides each budget
  across instances; there is no shared limiter store.
- ⭐ **Real per-source limiting belongs at the EDGE**, which is the component that
  actually knows the peer. **Nothing in `deploy/` configures it today** — no Caddy
  `rate_limit`, no firewall rule, no fail2ban. If you expose anything, that is the
  gap to close first.

### 15.3 Why the webhook route is NOT rate limited

⛔ **`SIGILD_WEBHOOK_RATE_LIMIT` and `SIGILD_WEBHOOK_RATE_BURST` were built in
Phase 53 and REMOVED.** Setting either now logs, at every boot:

```
WARN RETIRED SETTING IGNORED: this variable is set but is no longer read. The webhook
     rate limiter was REMOVED because its only possible key is the provider name, which
     forged traffic also controls, so an anonymous flood spent authentic deliveries'
     quota and destroyed payment events. THE WEBHOOK ROUTE IS NOT RATE LIMITED — bound
     it at the edge, where sources are distinguishable   setting=SIGILD_WEBHOOK_RATE_LIMIT
```

It **warns rather than failing boot** — a protective knob that has become moot
must not take a payments server down — but **remove it from your
`EnvironmentFile`**, because carrying it forward while believing the route is
protected is the most dangerous possible misunderstanding of the removal.

The reason it was removed, stated plainly: limiting
`POST /v1/billing/webhook/{provider}` **before** signature verification keys on
the provider name — the only key available at that point, and one **forged
traffic controls too**. A verifier reproduced the consequence live: one
unauthenticated thread at ~137 forged requests/second caused **15 of 15 genuine,
correctly-signed Stripe deliveries to be shed with `429`**; a longer flood shed
roughly **2,000 consecutive genuine retries**; **zero payment events were
applied**. A provider's retry budget is **finite**, so those events are lost
**permanently**. Limiting *after* verification is no better, because an authentic
burst is exactly what must never be dropped.

What bounds that route instead: the **64 KiB body cap** and the cost of **one
HMAC over a size-capped buffer** — no database round trip, no state created,
before the signature verifies. **Volume protection for it belongs at the edge.**

### 15.4 What to watch

| Signal | Where |
|--------|-------|
| `sigild_abuse_ratelimit_rejected_total{surface="enroll"\|"invite"}` | `GET /metrics` — counts only; **no address, account or key label** |
| `abuse.rate_limited` | the structured audit log (`surface`, `subject`). ⚠️ The **source address is deliberately never logged**, and `subject` is empty on the enroll surface — this server holds no personal data anywhere, and the proxy that would actually block already has the address |
| `RETIRED SETTING IGNORED` | a boot WARN — a retired webhook knob is still set |

---

## 16. Entitlement enforcement (operator guide — opt-in)

> ⚠️ **This is the one setting in this server that can stop serving a paying
> customer.** It is **off by default**, and with it unset **no handler reads the
> subscription store, no header is set, no audit line is written and no metric
> moves**. See [ADR 0043](decisions/0043-entitlement-enforcement.md) and
> [`api.md` → Entitlement enforcement](api.md#entitlement-enforcement-opt-in--phase-55).

### 16.1 Turning it on

| Variable | Default | Bounds | Notes |
|----------|---------|--------|-------|
| `SIGILD_ENTITLEMENT_ENFORCE` | unset ⇒ **OFF** | `1` / `true` | **Requires `SIGILD_ENABLE_DEV_OPS`, `SIGILD_DEVICE_AUTH` and `SIGILD_BILLING_PROVIDERS`** — each missing one is a **boot error** naming why |
| `SIGILD_ENTITLEMENT_GRACE` | **14 days** (`336h`) | `(0, 365d]`, a Go duration | How long after entitlement lapses writes keep working (**warned, not refused**). Setting it **without** the enforce flag is a **boot error** |

Unlike the abuse limiters, these prerequisites are **hard**. A rate limit that is
silently moot is harmless; a payment gate that is silently moot is a business and
support hazard, and an operator who set a grace period believes writes are being
enforced.

The default is deliberately generous. The cost of being too lenient is that
somebody uses the product free for two extra weeks. The cost of being too strict
is that somebody cannot log in to their bank. Those are not comparable.

At boot with enforcement on, `sigild` logs a single **WARN** spelling out exactly
what will and will not be refused, plus the grace value. It is a Warn even on the
happy path, on purpose.

### 16.2 What enforcement means operationally

| Past grace | Behaviour |
|------------|-----------|
| `POST /v1/vaults/{id}/ops` | **`402 payment_required`** |
| `PUT /v1/vaults/{id}/keys/{dev}` | **`402` only when `{dev}` belongs to ANOTHER account** |
| `POST /v1/vaults/{id}/grants` | **`402` only when the grantee belongs to ANOTHER account** |
| **everything else** | **served, unchanged** |

⭐ **What a lapsed customer can always still do:** read every op in every vault
they hold (i.e. generate **every 2FA code they already have**), collect every key
envelope, enumerate which vaults hold a key for them, publish a hybrid key,
**enroll** a device, **revoke** a device, delete a stale envelope, mint an invite,
read their account and subscription, **run checkout to pay** — and ⭐ **deposit a
wrapped vault key (with its grant) to a device of their OWN account**, which is
what makes replacing a dead phone and **printing a recovery kit** (§17) work while
lapsed.

Other things worth knowing before you switch it on:

- **`past_due` is still ENTITLED.** A declined card starts the provider's retry
  window, not a cutoff — so a genuinely failed card buys that window *plus* the
  grace period.
- **Grace runs from the LATER of the subscription's `updated_at` and its
  `current_period_end`**, so a mid-period cancellation keeps working until the
  period already paid for ends.
- ⚠️ **An account that NEVER subscribed is graced from its creation time**, which
  makes the grace period double as the **buy-in window**. There is **no separate
  trial mechanism** in this server.
- **Every uncertainty FAILS OPEN** — a subscription-store fault, an unreadable
  account row, no anchor date, or a device with no account all **serve** the
  request. ⚠️ Watch `entitlement.fail_open` (logged at **error** level): it means
  enforcement is silently **not** happening and free service is going out.
- ⚠️ **The in-memory subscription store is non-durable.** A restart loses every
  subscription, and every account then fails open. Use the Postgres backend.
- **There is no dunning, notification, email, invoice or per-account override.**
  The only warnings are the response headers, the additive `entitlement` block on
  `GET /v1/billing/subscription`, and this server's own audit log.
- **Refusal is never destructive.** Nothing is deleted, nothing expires; a lapsed
  account's data stays exactly where it is.

### 16.3 What to watch

| Signal | Where |
|--------|-------|
| `sigild_entitlement_enforcing` | `GET /metrics` — `1` means it really is on. Check this rather than trusting the config |
| `sigild_entitlement_decisions_total{outcome="entitled"\|"grace"\|"refused"\|"fail_open"}` | `GET /metrics` — counts only, **no account label** |
| `entitlement.grace` | audit log (**warn**) — advance notice that this account will start being refused |
| `entitlement.refused` | audit log (**warn**) — a customer was told to pay, naming which write surface |
| `entitlement.fail_open` | audit log (**error**) — ⚠️ enforcement is not happening; investigate the store |

---

## 17. Recovery kits (operator guide — dev-gated)

> ⭐ **`sigild` has NO concept of "recovery".** There is no recovery table, no
> recovery flag, no recovery configuration, and **no migration** —
> `sigild_schema_version` stays **5**. There is nothing here for an operator to
> turn on, and nothing to back up separately. See
> [ADR 0042](decisions/0042-recovery-kit.md).

A **recovery kit** is a member device whose Ed25519 and hybrid private keys are
HKDF-SHA256 derivations of **32 bytes of client CSPRNG printed on paper** — never
transmitted, and **never derivable from anything this server holds**. On the wire
it enrolls, publishes a hybrid public key, receives opaque envelopes and signs
contract-v3 requests exactly like a phone. It enrolls under the device label
`"recovery-kit"`, which is visible in `GET /v1/account`.

**Customer guidance to give, in this order:**

```bash
# on a device already in the account, after at least one vault exists
sigil recovery generate            # covers every vault in the local keyring
                                   #   -> prints the sheet ONCE, to stdout
sigil recovery verify              # type the code back to confirm the print is readable
sigil recovery check --device-id <kitID>    # what the kit can currently reach

# later, for a vault created after the print
sigil recovery cover --device-id <kitID> --vault <id>

# on a NEW install after losing everything
sigil recovery restore --device-id <kitID>      # prompts for the code; --adopt to keep it
```

### 17.1 Operational cautions

- ⚠️ **WHOEVER HOLDS THE SHEET HOLDS THE ACCOUNT** — read every covered vault and
  **revoke every device**, immediately, with no delay, no notification and no
  veto. It is **stronger than a stolen locked phone**: no OS lock, no biometric
  and **no vault password** stands in front of it, and its nominal `read` grant is
  **cosmetic** because account ownership authorizes it anyway. Treat the sheet as
  the account: safe, envelope, off-site — not a photo on a phone.
- ⚠️ **It recovers KEYS, not DATA.** A vault never synced to this server is gone.
- ⚠️ **It only opens the vaults it was told to COVER**, as of the print date. Tell
  customers to re-run `recovery cover` after creating a vault; **nothing reminds
  them**.
- ⚠️ **A kit cannot be created after the loss.**
- ⚠️ **A kit consumes a seat** against `SIGILD_ACCOUNT_MAX_DEVICES`, and **any
  member may revoke it** (membership is flat).
- ⚠️ **`vault rotate` will refuse** to silently drop a kit from a vault's recipient
  set; dropping one is an explicit `--drop`, and it means the printed sheet no
  longer recovers that vault.
- ⚠️ **`--code` puts the secret in `argv`** (readable via `/proc/<pid>/cmdline`,
  and recorded in shell history). It warns on stderr. Prefer the interactive
  prompt or `--code-stdin`. **There is deliberately no environment variable.**
- **Client coverage (Phase 56): all four surfaces.** The **`sigil` CLI**, the
  **webapp** (a restore panel on the setup **and** locked screens, so a customer
  who lost everything can restore into a fresh browser profile), the **MV3
  extension** and the **desktop** can each generate, cover, check, revoke and
  restore. ⚠️ **A browser restore needs the server reachable from that page's
  origin** — see §18: with `SIGILD_CORS_ORIGINS` unlisted, a browser blocks the
  request before it leaves the page.
- **Entitlement never blocks it.** Printing or extending a kit is a same-account
  key deposit, which §16 exempts, so a lapsed customer can still create one.

### 17.2 What to watch

There is no recovery-specific metric or audit event, by design — a kit is an
ordinary device. What you will see:

| Signal | Where |
|--------|-------|
| `device.enrolled` with a `"recovery-kit"` label | the audit log — a kit joined an account |
| `vault.key_envelope_put` addressed to the kit | the audit log — a vault was covered |
| `sigild_key_envelope_index_total` / `device.key_envelope_index` | `GET /metrics` and the audit log — a device asked which vaults hold a key for it (the restore path uses this) |
| `device.revoked` naming the kit | the audit log — a sheet was retired |

---

## 18. Browser origins / CORS (operator guide — opt-in)

> **The short version: in production you should not set this.** Serve the app and
> the API from the **same origin** behind the reverse proxy that already fronts
> `sigild`, and no origin needs listing. `SIGILD_CORS_ORIGINS` exists for the
> **localhost dev topology**, where the webapp is on one port and `sigild` on
> another. See [ADR 0044](decisions/0044-opt-in-cors-allowlist.md) and
> [`api.md`](api.md#cross-origin-requests-sigild_cors_origins--opt-in-off-by-default).

### 18.1 What it is for

Every signed request carries `X-Sigil-Device` / `-Timestamp` / `-Nonce` /
`-Signature`. Those are not CORS-safelisted request headers, so a **browser
preflights every one of them** with an `OPTIONS` request. `sigild` routes no
`OPTIONS` of its own, so without this setting a preflight is answered `405` and
the browser blocks the real request — which means enrollment, sync, sharing,
restore-from-a-recovery-kit and the entitlement read are all unreachable **from a
browser page on a different origin**. (The MV3 extension is exempt: its
`host_permissions` bypass CORS. The CLI and desktop are not browsers and were
never affected.)

### 18.2 Turning it on

```bash
# Dev only. EXACT origins: scheme + host + optional port, nothing else.
SIGILD_CORS_ORIGINS=http://127.0.0.1:3000,http://localhost:3000
```

- **Unset (the default) installs no CORS middleware at all** — not one response
  header changes, and `OPTIONS` still returns `405`.
- Validated **before the listener binds**. A path, query, fragment, trailing
  slash, embedded credentials or non-`http(s)` scheme is a **startup failure**.
- **`*` is refused at boot** (exit code 1, the listener never binds). There is no
  wildcard mode and no reflect-all mode.
- Changing the list requires a **restart**.

When it is on, the boot log says so:

```
level=WARN msg="CORS ENABLED for an explicit browser origin allowlist — this is
for the LOCALHOST DEV topology; in production serve the app and the API from the
SAME origin behind the reverse proxy. No credentials mode is enabled and no
wildcard is possible; every request is still authenticated by its own per-request
signature" origins=http://127.0.0.1:3000
```

If you see that warning on a production host, the deployment is serving the app
from somewhere other than where you think it is.

### 18.3 What it does and does not do

⚠️ **It is not an authentication control and not a CSRF control.** `sigild` issues
no cookie, no session and no ambient token; every authenticated request is
authenticated by a per-request Ed25519 signature, so a hostile cross-origin page
cannot forge one whatever CORS says. `Access-Control-Allow-Credentials` is
**never** set. Do not treat the allowlist as an access control:

- It constrains **browsers only**. `curl`, the `sigil` CLI, the desktop app and
  anything server-side ignore it entirely.
- It does **not** make the dev transport safe: an allowlisted origin over plain
  `http://` is still cleartext.
- Removing an origin is not instantaneous — `Access-Control-Max-Age: 600` means an
  already-open browser can hold a cached preflight for up to ten minutes.
- No Private Network Access header is sent.

One operational detail worth knowing: the entitlement warning headers (§16) are
**only readable by a browser client when this is configured**, because the
middleware is what sets `Access-Control-Expose-Headers`. A same-origin
deployment gets them for free.

### 18.4 What to watch

There is no CORS metric. A misconfiguration shows up **in the browser**, not in
the server logs: the page reports *"blocked by CORS policy: No
'Access-Control-Allow-Origin' header is present"* while `sigild` records a normal
`405` for the `OPTIONS`. If a customer reports that the web client "cannot reach
the server" while the CLI works fine against the same host, this is the first
thing to check.
