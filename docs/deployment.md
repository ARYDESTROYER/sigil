# sigild deployment runbook

> **STATUS: pre-audit skeleton / NOT APPLIED.** This is the deployment *story*
> for `sigild`, the Sigil sync server. Nothing here has been provisioned,
> applied, or exposed to the public internet. The artifacts under
> [`../deploy/`](../deploy/) are reference shapes, and `sigild` itself is a
> skeleton that performs **no cryptography and runs no auth** (vault ops default
> to `501`; an opt-in `SIGILD_ENABLE_DEV_OPS` dev-only, unauthenticated store of
> opaque client-encrypted blobs — in-memory, file-backed, or durable Postgres —
> exists for local wiring only, never expose it). Treat every "production" word below as
> *future, unbuilt, unaudited*. See [`sprint-72h.md`](sprint-72h.md) for the
> wall-clock gates and the defer ledger this descends from.

This document is intentionally honest about what is and is not deployable today,
and about what could and could not be validated on the build machine (a macOS
arm64 laptop with Docker installed — so the image was built and probed; Caddy,
Terraform, and Nomad were then installed via `brew` and their **native offline
validators** run against the IaC, and a **loopback-only** local compose stack
was brought up as a topology smoke; only `systemd-analyze` remains unavailable on
macOS, so the systemd unit is still by-eye — see the
[validation status table](#validation-status)).

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

- **`sigild` does no cryptography and runs no auth.** The vault operation log
  (`/v1/vaults/{id}/ops`) **defaults to `501`** and stays that way in any
  production configuration. It can be turned on **only as a dev scaffold** by
  setting the environment variable **`SIGILD_ENABLE_DEV_OPS`**; when enabled it
  is an **in-memory, non-durable, UNAUTHENTICATED** store of **opaque
  client-encrypted blobs** — the server does no crypto and never sees plaintext
  or keys (POST → `201 {vaultID, seq}`; GET → the stored blobs base64-encoded,
  **paginated** via `?limit` (default 500, max 1000) + a `has_more` flag).
  Oversized bodies are capped at 64 KiB and rejected with **`413`**. Appends can
  optionally be **rate-limited per vault** with **`SIGILD_OPLOG_RATE_LIMIT`**
  (sustained appends/sec/vault) and **`SIGILD_OPLOG_RATE_BURST`** (bucket depth) — a
  stdlib token-bucket that returns `429` + `Retry-After` when exceeded, **off by
  default**; these are **dev-op knobs** that apply only when
  `SIGILD_ENABLE_DEV_OPS` is set and do not change the production `501` default.
  There is still **no auth, no durability, no Postgres**, and no real op/CRDT
  semantics.
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
  Juspay scheme is explicitly **UNVERIFIED-AGAINST-LIVE-DASHBOARD**. There is no
  account model (a subscription keys off the enrolled device), no entitlement
  enforcement, no recurring-subscription creation for the India adapters, no
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
  contract and since Phase 48 also drive the vault-sharing routes. All of it is
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
  order. The current set is a single baseline, **`0001_init.sql`** (version `1`),
  which creates the `sigil_vault_ops` table (opaque `bytea` `blob` + `bytea`
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
  (with its `applied_at`) or `[pending]` and applies nothing. Both read the DSN
  from `SIGILD_OPLOG_POSTGRES` and error clearly if it is unset.
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
> for the decision.

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
SIGILD_JUSPAY_WEBHOOK_SCHEME=basic            # basic (default) | hmac
SIGILD_JUSPAY_WEBHOOK_USERNAME=...            # REQUIRED for scheme=basic
SIGILD_JUSPAY_WEBHOOK_PASSWORD=...            # REQUIRED for scheme=basic
SIGILD_JUSPAY_WEBHOOK_SECRET=...              # REQUIRED for scheme=hmac
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

The boot log records **which** providers are enabled and **which** Juspay scheme
is active — a mechanism name, never a credential — plus two loud warnings: that
billing is unaudited and must be verified against live dashboards, and (when
Postgres is not configured) that the subscription store is in-memory.

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
   dashboard's own documentation for that account — especially for **Juspay**,
   and for Razorpay's **`X-Razorpay-Event-Id`** header (absent, the adapter falls
   back to a deterministic body hash as the event ID).
3. Deliver the **same** event twice and confirm the second answers `200` with
   `"status":"duplicate"` and changes nothing.
4. Confirm the plan/price/amount parameters against the account's real product
   catalogue — the adapters send what you configure and invent nothing.
5. Confirm `sigild_billing_*` counters move as expected on `GET /metrics`.

**Durability matters here.** Without `SIGILD_OPLOG_POSTGRES` the subscription
store is **in-memory and non-durable**: subscriptions *and* the processed-event
ledger are lost on restart, so a webhook redelivered across a restart **would be
applied twice**. Only the Postgres backend enforces the `(provider, event_id)`
idempotency key in the database, across processes and restarts. Configure
Postgres before pointing any real provider at the endpoint. Billing adds **no
second connection pool and no new dependency** — it reuses the op-log's existing
`pgxpool` and adds migration **`0003_billing.sql`** (`sigil_subscriptions`,
`sigil_billing_processed_events`), so `sigild_schema_version` reports **3**
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
  replayable with an arbitrary body. If you must use `basic`, the endpoint has to
  be TLS-only; prefer `hmac` when the merchant dashboard offers it.
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
- **No account model** — a subscription keys off the **enrolled device** that ran
  checkout, so one human with two devices is two subjects.
- **No entitlement enforcement** — `entitled` is reported by
  `GET /v1/billing/subscription` and consulted by nothing.
- **No fraud, chargeback, refund, proration, tax, dunning or reconciliation
  handling**, no billing admin surface, and no rate limiting on the webhook
  endpoint (only the 64 KiB body cap).
- **No PCI attestation** — hosted checkout minimizes scope; it certifies nothing.
