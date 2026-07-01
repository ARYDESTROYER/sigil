# deploy/local — LOCAL topology smoke (NOT a deployment)

> **LOUD WARNING.** This stack is a **disposable, loopback-only topology check**,
> **not a deployment**. It binds to `127.0.0.1` only, uses **no real TLS and no
> ACME**, obtains **no certificate**, exposes **nothing** to the network or the
> internet, and proves **nothing** about DNS, public TLS, PQ-TLS, durability, or
> auth. It exists solely to confirm the **Caddy → `sigild`** wiring from
> [`../../docs/deployment.md`](../../docs/deployment.md) §1 on the local machine.
> Bring it up, probe it, tear it down.

This is the **local dev** counterpart of the production shapes under
`deploy/{caddy,systemd,nomad,terraform}/`. It is deliberately separate from
them — the production `deploy/caddy/Caddyfile` is **not** modified by this stack.

## What it runs

```
  127.0.0.1:8080  ──▶  caddy (:80, auto_https off)  ──▶  sigild:8080  (plain HTTP)
  (loopback only)        Caddyfile.local                  built from ../../sigild/Dockerfile
```

- **`sigild`** — built from [`../../sigild/Dockerfile`](../../sigild/Dockerfile)
  (image `sigild:local`), serving plain HTTP on `:8080` **inside** the compose
  network. It is **not** published to the host; only Caddy can reach it.
  `SIGILD_ENABLE_DEV_OPS` is left unset, so vault ops stay `501` (production
  default) — this is a probe check, not a data path.
- **`caddy`** — the local TLS edge with **automatic HTTPS disabled**
  ([`Caddyfile.local`](Caddyfile.local), `auto_https off`). Published to
  **`127.0.0.1:8080` → container `:80`** only.

## Run it

From the **repo root**:

```bash
# Bring up (builds the sigild image from ../../sigild/Dockerfile):
docker compose -f deploy/local/compose.yaml up -d --build

# Probe liveness THROUGH Caddy (loopback). Expect HTTP 200 + sigild JSON:
curl -fsS http://127.0.0.1:8080/healthz   # {"status":"ok","version":"dev"}
curl -fsS http://127.0.0.1:8080/readyz    # {"checks":{...},"status":"ok","version":"dev"}

# Tear it DOWN (leaves nothing running, removes the network/volumes):
docker compose -f deploy/local/compose.yaml down -v
```

## Why loopback-only / no TLS

- **`127.0.0.1` binding is load-bearing.** `compose.yaml` publishes
  `127.0.0.1:8080:80`; do **not** change it to `0.0.0.0` or a bare port (both
  bind every interface). Loopback keeps the smoke off the network.
- **`auto_https off`** in `Caddyfile.local` stops Caddy from ever contacting an
  ACME server. No Let's Encrypt, no cert, no DNS/ACME wall-clock gate (that gate
  belongs to the production path — see `docs/deployment.md` §4).
- **No PQ proof.** A handshake here would be, at most, local classical TLS. The
  `X25519MLKEM768` proof must run against the Go-native `sigild` listener, never
  this edge — see `docs/deployment.md` §3.

This stack provisions nothing and exposes nothing. When you are done, run
`docker compose -f deploy/local/compose.yaml down -v`.
