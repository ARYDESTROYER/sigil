# CLAUDE.md — working guide for this repo

> **Read [`journal.md`](journal.md) first, and keep it updated.** `journal.md`
> is the running log of everything done, why, and what's next. Update it
> **frequently and in depth** — at the start and end of every work session, and
> after every meaningful decision, build, test, or scope change. Treat it as the
> source of truth for context that isn't obvious from the code.

## What this is

**Sigil (working name)** — a paid, multi-platform, end-to-end-encrypted,
post-quantum-*ready* authenticator. This repo is the **pre-launch / pre-audit
foundation scaffold** from the 72-hour deployment sprint. It is **not** a
shipping product: the sync server and clients are stubbed, and `libsigil` has
**real but UNAUDITED** crypto building blocks — an Argon2id KDF, an
XChaCha20-Poly1305 + HKDF AEAD, and a C-ABI `seal`/`open` over them — that are
**not wired into any product flow**. Pre-audit — **do not store real
secrets.** See [`docs/sprint-72h.md`](docs/sprint-72h.md).

Posture is **stealth**: defensive, no-index, request-beta-access. Ship nothing
public, make no security claims, until the audit completes and trademark clears.

## Repository map

- `libsigil/` — Rust crypto core (`core` = suite registry + envelope codec +
  real-but-unaudited Argon2id KDF, XChaCha20-Poly1305+HKDF AEAD, and composed
  `seal_record`/`open_record`; `ffi` = C-ABI `seal`/`open`/`buffer_free` + suite
  smoke export, hand-written `sigil.h`).
- `sigild/` — Go sync server skeleton (`/healthz`, `/readyz`, `/version`,
  ops→501/413, request-ID/access-log/recover middleware, in-memory `store`;
  distroless `Dockerfile`). No crypto.
- `web/apps/marketing/` — Next.js 15 stealth splash + waitlist. No-index, wallable.
- `docs/` — threat model, crypto spec, sprint plan, deployment runbook (internal/pre-audit).
- `deploy/` — Terraform / Nomad / Caddy / systemd skeletons (not applied).
- `cli/` — `sigil`, a pre-audit demo CLI that seals/opens a file via the libsigil
  core. **Standalone crate** (own `cli/Cargo.lock`, NOT a libsigil workspace
  member) so it can use `getrandom` without polluting the wasm-pure core.
- `extension/`, `web/apps/{webapp,admin}`, `web/packages/*` — reserved.

## Toolchains (this machine — macOS arm64)

- **Go** 1.26.3 at `/opt/homebrew/bin/go` (go.mod directive: 1.24).
- **Rust** stable (rustc 1.96) via Homebrew `rustup`. ⚠️ The `~/.cargo/bin`
  proxies were **not** created, and `rustup run stable cargo` did not resolve
  subcommands. The reliable invocation is to put the toolchain bin on PATH:
  `export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/opt/homebrew/bin:$PATH"`
- **Node** 20.12 + **pnpm** 9.15 via Corepack (`corepack pnpm …`). CI uses Node 22.
- System `openssl` is **LibreSSL** — it CANNOT negotiate `X25519MLKEM768`. Any
  PQ-TLS verification needs OpenSSL 3.5+ / Go 1.24.x installed explicitly first.

## Build & test (these commands are known-green)

```bash
# Rust core — fmt / clippy / test / wasm
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/opt/homebrew/bin:$PATH"
M=libsigil/Cargo.toml
cargo fmt --manifest-path $M --all -- --check
cargo clippy --manifest-path $M --all-targets -- -D warnings
cargo test --manifest-path $M
cargo build --manifest-path $M -p sigil-core --target wasm32-unknown-unknown

# Rust demo CLI — separate crate; native-only, so getrandom is fine here. After
# building it, confirm it did NOT leak into the wasm-pure core:
cargo fmt   --manifest-path cli/Cargo.toml --all -- --check
cargo clippy --manifest-path cli/Cargo.toml --all-targets -- -D warnings
cargo test  --manifest-path cli/Cargo.toml
grep -c 'name = "getrandom"' libsigil/Cargo.lock   # must STILL be 0

# Go server — fmt / vet / test / build
go=/opt/homebrew/bin/go
gofmt -l sigild            # must print nothing
$go -C sigild vet ./...
$go -C sigild test ./...
$go -C sigild build ./...

# sigild container (multi-stage → distroless, ~14 MB) — needs the Docker daemon
docker build --build-arg VERSION=$(git rev-parse --short HEAD) -t sigild:dev sigild

# Web — typecheck / lint / build (NEXT_TELEMETRY_DISABLED=1)
corepack pnpm -C web typecheck
corepack pnpm -C web lint
corepack pnpm -C web build
```

**Always run the relevant suite after changes and record the result in
`journal.md`.** CI mirrors these in `.github/workflows/`.

## Conventions & guardrails

- **License split:** clients/core/web/CLI = Apache-2.0; `sigild/` = BSL-1.1.
- **No over-claims:** public copy must obey
  [`web/apps/marketing/MARKETING-CLAIMS.md`](web/apps/marketing/MARKETING-CLAIMS.md)
  — never "audited", "SOC 2", "post-quantum secure", or unqualified "E2E
  encrypted" until true.
- **No secrets in the repo.** Secrets live in the team password manager;
  `.gitleaks.toml` scans, and `docs/sprint-72h.md` has the rotation runbook.
- **Don't fake crypto/auth.** Stub with `501` / clear "not implemented" rather
  than implement something that would poison the future audit.
- Rust: `#![forbid(unsafe_code)]` in `core`; clippy `-D warnings` is the bar.
- The brand name and `sigilapp.io` are **provisional** (trademark pending).

## Git / deploy

`main` is committed and pushed to `origin` (genesis → Phase 4); the human has
authorized commits + pushes to `main`. **Still do not register domains or deploy
publicly without explicit human approval** — those are outward-facing/irreversible.
See [`docs/deployment.md`](docs/deployment.md) for the (not-yet-applied) deploy story.
