# Sigil (working name)

A paid, multi-platform, end-to-end-encrypted, post-quantum-ready authenticator.

> **STATUS: pre-launch / pre-audit skeleton.** This repository is the
> foundation scaffold from the 72-hour deployment sprint — _not_ a shipping
> product. The cryptographic core, the sync server, and every client are
> intentionally stubbed. **No real cryptography runs yet. Do not use this to
> store real secrets.** See [`docs/sprint-72h.md`](docs/sprint-72h.md) for the
> exact definition of done and the defer ledger.
>
> The name **Sigil** and any domain are **provisional**, pending trademark
> clearance in the US/EU/UK/India.

## What this repo is (today)

- `libsigil/` — Rust crypto core. **Builds, lints, tests, and compiles to
  `wasm32`** — currently only the algorithm-suite registry + envelope metadata.
- `sigild/` — Go sync server. **Builds, vets, tests.** Serves `/healthz`,
  `/readyz`, and a deliberate `501` on `/v1/vaults/{id}/ops`. Performs no crypto.
- `web/apps/marketing/` — Next.js 15 stealth splash + early-access waitlist +
  privacy/terms/imprint stubs. **No-index, password-wallable.**
- `docs/` — threat model, crypto spec, and the sprint plan (kept internal/pre-audit).
- `deploy/` — Terraform / Nomad / Caddy / systemd skeletons (not yet applied).

## Repository layout

```
libsigil/        Rust crypto core (workspace: core + ffi)
sigild/          Go sync server (cmd/server, cmd/worker-*, internal/*)
web/             Next.js marketing (+ webapp/admin reserved), pnpm workspace
extension/       Browser extension (reserved)
cli/             Rust CLI (reserved)
deploy/          terraform / nomad / helm / caddy / systemd
docs/            threat model, crypto spec, sprint plan
```

Native platform clients (iOS/Android/macOS/Windows/Linux/watchOS/wearOS) live in
**separate repositories** and consume `libsigil` as a versioned binary artifact.

## Toolchains

- Rust stable (rustfmt, clippy, `wasm32-unknown-unknown` target) — pinned in
  [`rust-toolchain.toml`](rust-toolchain.toml).
- Go 1.24+ (the brief targets 1.24.x for the native `X25519MLKEM768` TLS group).
- Node 22 (`.nvmrc`) + pnpm 9 (via Corepack).

## Build & test

```bash
# Rust crypto core
cargo fmt   --manifest-path libsigil/Cargo.toml --all -- --check
cargo clippy --manifest-path libsigil/Cargo.toml --all-targets -- -D warnings
cargo test  --manifest-path libsigil/Cargo.toml
cargo build --manifest-path libsigil/Cargo.toml -p sigil-core --target wasm32-unknown-unknown

# Go sync server
( cd sigild && gofmt -l . && go vet ./... && go test ./... && go build ./... )

# Web (marketing)
( cd web && pnpm install && pnpm lint && pnpm typecheck && pnpm build )
```

## Licensing

Dual model (see [`LICENSE`](LICENSE)):

- **`libsigil/`, clients, CLI, web** → Apache-2.0 ([`LICENSE-APACHE`](LICENSE-APACHE)).
- **`sigild/` (the server)** → intended Business Source License 1.1 (converting
  to Apache-2.0), matching the "open-source clients, source-available server"
  posture in the brief. **Server license text deferred** — not finalized yet.

## Security

Pre-audit. Report issues per [`SECURITY.md`](SECURITY.md). Public marketing copy
must obey [`web/apps/marketing/MARKETING-CLAIMS.md`](web/apps/marketing/MARKETING-CLAIMS.md)
— no "audited" / "SOC 2" / "post-quantum secure" claims until they are true.
