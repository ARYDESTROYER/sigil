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
all credentials.

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

---

## 7. What is NOT yet deployable

To avoid any over-claim, the honest gaps:

- **`sigild` does no cryptography and runs no auth.** The vault operation log
  (`/v1/vaults/{id}/ops`) **defaults to `501`** and stays that way in any
  production configuration. It can be turned on **only as a dev scaffold** by
  setting the environment variable **`SIGILD_ENABLE_DEV_OPS`**; when enabled it
  is an **in-memory, non-durable, UNAUTHENTICATED** store of **opaque
  client-encrypted blobs** — the server does no crypto and never sees plaintext
  or keys (POST → `201 {vaultID, seq}`; GET → the stored blobs base64-encoded).
  Oversized bodies are capped at 64 KiB and rejected with **`413`**. There is
  still **no auth, no durability, no Postgres**, and no real op/CRDT semantics.
  **Do NOT set `SIGILD_ENABLE_DEV_OPS` on any exposed instance** — the dev
  op-log must never be reachable from the public internet, and no real secrets
  may be stored in it. This honours the "stub with `501` rather than poison the
  audit" guardrail (brief §14): the production default stays `501`. See
  [`api.md`](api.md) for the full contract.
- **No production data store is wired.** The dev op-log can now be pointed at a
  real Postgres via **`SIGILD_OPLOG_POSTGRES`** (a libpq DSN, on the `pgx`
  driver — `sigild`'s first third-party dependency, so the module now carries a
  `go.sum`) for a **durable, concurrent** dev backend
  ([`decisions/0014-postgres-durable-oplog-backend.md`](decisions/0014-postgres-durable-oplog-backend.md)),
  but production still needs an **auth / enrollment model, CRDT / merge
  semantics, managed migrations, and backup / restore / replication** around it —
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
- **Clients are stubbed.** No webapp / admin console / extension / native client
  consumes this server. `libsigil` has a real-but-**unaudited** AEAD building
  block that is **not wired into any product flow**.
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
