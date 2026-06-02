# deploy/

Deployment skeletons for `sigild`. **None of these are applied yet** — they are
the reference shapes from the brief, ready to fill in once the Hetzner VM and
domain exist (see [`../docs/sprint-72h.md`](../docs/sprint-72h.md)).

- `caddy/Caddyfile` — reverse proxy + automatic TLS for `api.<host>`.
- `systemd/sigild.service` — hardened unit for the single-VM (Nomad-free) shape.
- `terraform/` — Hetzner Cloud VM + firewall skeleton (placeholders, not applied).
- `nomad/sigild.nomad.hcl` — Nomad jobspec for the >0-user managed shape.

Targets, in increasing scale (per the brief):

1. **Single VM + systemd** (≤ ~50k users) — Caddy → `sigild` → local PG/Redis.
2. **Nomad on VMs** — the same, orchestrated.
3. **Kubernetes** — only past ~50k users / with a platform engineer.

⚠️ The PQ-TLS (`X25519MLKEM768`) group must be negotiated by the **Go-native
listener**, not by Caddy's classical edge — see notes in the Caddyfile.
