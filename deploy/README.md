# deploy/

Deployment skeletons for `sigild`. **None of these are applied yet** — they are
the reference shapes from the brief, ready to fill in once the Hetzner VM and
domain exist (see [`../docs/sprint-72h.md`](../docs/sprint-72h.md)). The full,
honest runbook lives in [`../docs/deployment.md`](../docs/deployment.md).

- `caddy/Caddyfile` — reverse proxy + automatic TLS for `api.<host>`.
- `systemd/sigild.service` — hardened unit for the single-VM (Nomad-free) shape.
- `terraform/` — Hetzner Cloud VM + firewall skeleton (placeholders, not applied).
- `nomad/sigild.nomad.hcl` — Nomad jobspec for the >0-user managed shape.

Targets, in increasing scale (per the brief):

1. **Single VM + systemd** (≤ ~50k users) — Caddy → `sigild` → local PG/Redis.
2. **Nomad on VMs** — the same, orchestrated.
3. **Kubernetes** — only past ~50k users / with a platform engineer.

## Build → image → nomad flow

From Shape 2 (Nomad) onward, `sigild` ships as a container image:

1. Build the image from [`../sigild/Dockerfile`](../sigild/Dockerfile) (added on
   a parallel track). Tag it with the git short SHA so the tag matches `sigild`'s
   build-time `-ldflags` version.
2. Push it to a container registry.
3. `nomad/sigild.nomad.hcl` pulls that image and health-checks `/healthz`.

The jobspec's `image = "ghcr.io/PLACEHOLDER/sigild:latest"` is a **placeholder**:
repoint it at the image built from `../sigild/Dockerfile` once one is published.
Do not commit a real registry path until it exists. **None of this is applied.**

⚠️ The PQ-TLS (`X25519MLKEM768`) group must be negotiated by the **Go-native
listener**, not by Caddy's classical edge — see notes in the Caddyfile and the
runbook.
