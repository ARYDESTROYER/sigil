# 0009 — Manual / human-gated deploy and publish

- **Status:** Accepted — 2026-06.

## Context

The project is in a **stealth, pre-audit** posture: nothing public, no-index,
request-beta-access, and **no security claims** until the audit completes and the
trademark clears (see [`../sprint-72h.md`](../sprint-72h.md) and the brief's
zero-over-claims gate). The deployment *story* exists as reference artifacts under
[`../../deploy/`](../../deploy/) and is documented honestly in
[`../deployment.md`](../deployment.md), but **outward-facing and irreversible
actions** — registering/buying a domain, `terraform apply`, publishing a container
image to a registry, exposing anything to the public internet — are exactly the
moves that would break stealth or cannot be undone.

Two specific risks motivated a single, recorded decision:

- **CI must not leak the project.** A container-publish workflow that ran on
  `push`/`pull_request` would automatically push a `sigild` image to a registry on
  every commit — publishing the project's existence (and a buildable artifact)
  before launch. An auto-deploy pipeline would do the same for infrastructure.
- **Local validation must not become a backdoor to exposure.** We want to *verify
  the deployment is ready* (validated artifacts, a buildable image, a working
  edge→app topology) without provisioning, exposing, or obtaining any
  publicly-trusted certificate in the process.

[`0006`](0006-file-backed-dev-op-log-backend.md) and the other op-log ADRs
([`0003`](0003-dev-gated-opaque-op-log.md), [`0008`](0008-device-key-request-auth.md))
already establish the house pattern for this class of risk: **default to the safe
posture, gate the riskier path behind an explicit opt-in, and never expose it.**
This ADR applies the same pattern to the *deployment surface* itself.

## Decision

Make the **container-publish workflow and all infrastructure
human-gated**, and keep **nothing exposed** while in stealth/pre-audit:

- **Publish is `workflow_dispatch`-only.** The workflow
  [`../../.github/workflows/publish-sigild.yml`](../../.github/workflows/publish-sigild.yml)
  has **no `push` / `pull_request` triggers** — it never runs automatically; it
  builds the image from [`../../sigild/Dockerfile`](../../sigild/Dockerfile) and
  pushes it **only when a human deliberately dispatches it**.
- **The GHCR package is PRIVATE.** It publishes to GitHub Container Registry as a
  **private** package `ghcr.io/<owner>/sigild` (tagged with the git short SHA to
  match `sigild`'s `-ldflags` version). No public image exists while in stealth.
- **No auto-deploy.** No CI step runs `terraform apply` or `nomad job run`. The
  IaC is **validated but never applied** by automation; a human applies it.
- **Local validation is loopback-only and offline.** Readiness is demonstrated
  with (a) the **offline native validators** — `caddy validate`,
  `terraform fmt -check` + `terraform validate`, `nomad job validate` — which are
  syntax/schema checks that contact no cloud or cluster, and (b) a
  **loopback-only** local compose stack
  ([`../../deploy/local/compose.yaml`](../../deploy/local/compose.yaml)) that runs
  Caddy → `sigild` on `127.0.0.1` with **no real TLS/ACME** — a topology shape
  check, brought up, probed, and torn down. `systemd-analyze` is unavailable on
  macOS, so the systemd unit stays by-eye (run `systemd-analyze verify` on Linux).
- **A GO/NO-GO preflight gate.**
  [`../../deploy/preflight.sh`](../../deploy/preflight.sh) encodes the gates that
  must pass before any real deploy (DNS resolves, `EnvironmentFile` present, the
  image is not the `ghcr.io/PLACEHOLDER/...` placeholder, Docker present). It is
  read-only and provisions/exposes nothing.

The full operator-facing detail lives in [`../deployment.md`](../deployment.md)
(§2 artifact flow, §8 validation status, §9 local topology check, §10 preflight).

## Consequences

- Deployment is **verifiably READY** — validated artifacts, a buildable and
  locally-probed image, and a working loopback topology — **without ever
  shipping.** Readiness and exposure are decoupled.
- **CI cannot leak the project.** Because publish is `workflow_dispatch`-only and
  the package is private, no commit or PR publishes a public image or auto-deploys.
- **Publish + apply require explicit human action** plus prerequisites that are
  not present here: a **purchased domain**, **staged secrets** (the
  `EnvironmentFile` / `*.tfvars` from the password manager,
  [`deployment.md` §5](../deployment.md#5-secrets-posture)), and **repointing the
  Nomad jobspec** off its placeholder image onto the published private package.
- The publish workflow is **not run from the build machine** (no GHCR auth here,
  and running it would be an outward-facing action), so its YAML is reviewed by
  eye, not executed — stated honestly in the validation table.
- A small cost: every real publish/deploy is a manual step rather than a
  push-button pipeline. That friction is **intended** while in stealth/pre-audit;
  it can be revisited (with a superseding ADR) once the project is public and
  audited.
- This is a **posture/process** decision: it changes nothing about `sigild`'s
  code, adds no dependency, and makes no security claim. It records *why* nothing
  ships automatically, complementing the dev-gating pattern of
  [`0006`](0006-file-backed-dev-op-log-backend.md) and
  [`0003`](0003-dev-gated-opaque-op-log.md).
