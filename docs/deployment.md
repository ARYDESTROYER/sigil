# sigild deployment runbook

> **STATUS: pre-audit skeleton / NOT APPLIED.** This is the deployment *story*
> for `sigild`, the Sigil sync server. Nothing here has been provisioned,
> applied, or exposed to the public internet. The artifacts under
> [`../deploy/`](../deploy/) are reference shapes, and `sigild` itself is a
> skeleton that performs **no cryptography, stores no vault data, and runs no
> auth** (vault ops return `501`). Treat every "production" word below as
> *future, unbuilt, unaudited*. See [`sprint-72h.md`](sprint-72h.md) for the
> wall-clock gates and the defer ledger this descends from.

This document is intentionally honest about what is and is not deployable today,
and about what could and could not be validated on the build machine (a macOS
arm64 laptop with Docker installed — so the image was built and probed — but no
Terraform / Caddy / Nomad / `systemd-analyze` — see the
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
        │  (skeleton)  │   /healthz, /readyz  +  /v1/.../ops → 501
        └──────────────┘
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
sigild/Dockerfile ──build──▶ local image ──push──▶ registry (ghcr.io/<org>/sigild:<tag>)
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

1. **Build** the image from `sigild/Dockerfile` (parallel track; reference by
   path only). Tag it with the short git SHA, matching `sigild`'s build-time
   `-ldflags` version injection (see [§6](#6-versioning--probes)).
2. **Push** to a container registry. The Nomad jobspec currently points at the
   placeholder `ghcr.io/PLACEHOLDER/sigild:latest`; this must be repointed at the
   real published image once one exists (do **not** invent a registry path here).
3. **Run**: `nomad job run deploy/nomad/sigild.nomad.hcl` (Shape 2), or
   `systemctl start sigild` against the binary (Shape 1).
4. **Front** it with Caddy as the TLS edge.
5. **Probe** liveness/readiness — see [§6](#6-versioning--probes).

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

- **`sigild` does no cryptography, stores no vault data, runs no auth.** The
  vault operation log (`/v1/vaults/{id}/ops`) deliberately returns **`501`**
  (oversized bodies are capped at 64 KiB and rejected with **`413`** first). It
  understands no vault format. This is by design (brief §14) and must stay this
  way pre-audit — do not "deploy a backend" and imply it stores secrets.
- **No data stores are wired.** Postgres / Redis / S3(R2) are referenced by env
  var names and by the readiness probe only; there is no schema, no migration, no
  client, no backup/restore. The first Postgres migration (with RLS as
  posture-only) is in the stretch tier and **not done**.
- **No live PQ-TLS proof.** `sigild`'s skeleton listener serves plain HTTP; a
  TLS-enabled Go-native listener and a PQ-capable client are prerequisites that
  do not exist on the build machine (LibreSSL can't negotiate the group). See
  [§3](#3-pq-tls-nuance-read-this-before-claiming-a-pq-proof).
- **Clients are stubbed.** No webapp / admin console / extension / native client
  consumes this server. `libsigil` has a real-but-**unaudited** AEAD building
  block that is **not wired into any product flow**.
- **Nothing is applied.** No VM exists, no domain is registered, no image is
  published, no Nomad cluster runs, no Caddy is serving. The image reference is a
  placeholder.
- **Posture is stealth / pre-launch.** No public, no-index, request-beta-access.
  No security claims ("audited", "SOC 2", "post-quantum secure", unqualified
  "end-to-end encrypted") may be made until the audit completes and trademark
  clears.

---

## 8. Validation status

The build machine is macOS arm64 with **Docker installed** but **Terraform,
Caddy, Nomad, and `systemd-analyze` NOT installed**. The container image was
therefore **actually built, run, and probed**; the four IaC artifacts could only
be **read and syntactically reviewed by eye** — none of them was validated with
its native validator. This split is stated plainly so no false confidence is
implied.

| Artifact | How checked | Result / notes |
|----------|-------------|----------------|
| `sigild/Dockerfile` | **Built, run, and probed** — `docker build` (multi-stage → distroless, ~14 MB), `docker run`, then `curl` against the live container. | **Validated locally.** `/healthz` and `/version` returned the stamped `VERSION` build-arg, `/readyz` reported deps `unconfigured`, and vault ops still `501`. Push to a registry is the future step. |
| `deploy/caddy/Caddyfile` | Syntactic review by eye only — **`caddy validate` NOT installed**. | Reverse-proxy target `127.0.0.1:8080` matches `sigild`'s default `:8080`. `api.example.com` is a deliberate placeholder. PQ-TLS caveat present inline. No errors spotted; **not tool-validated**. |
| `deploy/nomad/sigild.nomad.hcl` | Syntactic review by eye only — **`nomad job validate` NOT installed**. | Port `to = 8080` and `/healthz` check match `sigild`. Image is the placeholder `ghcr.io/PLACEHOLDER/sigild:latest` — must be repointed at the image built from `sigild/Dockerfile` once published (comment added). No errors spotted; **not tool-validated**. |
| `deploy/systemd/sigild.service` | Syntactic review by eye only — **`systemd-analyze verify` NOT installed**. | `ExecStart=/usr/local/bin/sigild`, `EnvironmentFile` for secrets, hardening directives present. Consistent with Shape 1. No errors spotted; **not tool-validated**. |
| `deploy/terraform/main.tf`, `variables.tf` | Syntactic review by eye only — **`terraform validate`/`fmt` NOT installed**. | Firewall opens only 22/80/443; `hcloud_token` is `sensitive`; outputs the VM IPv4. Placeholders not applied. No errors spotted; **not tool-validated**. |

> **Honest summary:** the Docker image was **built and smoke-tested locally**
> (all endpoints probed on a running container). Terraform / Caddy / Nomad /
> `systemd-analyze` validators were **unavailable** on this machine, so those
> four artifacts got only a *manual, by-eye* review for obvious errors (port
> mismatches, the placeholder image, secret handling). Run the native validators
> on a properly tooled host before treating the IaC as deployable.
