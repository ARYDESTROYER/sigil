# 0027 — Real webapp over a `@sigil/wasm` loader (with the Next.js wasm-bundling strip)

- **Status:** Accepted — 2026-07.

## Context

The client column has, until now, been the standalone **`sigil-wasm`** crate: a
`wasm-bindgen` binding that runs `seal_record` / `open_record`, the `SIGILcli` /
`SIGILhyb` containers, the opaque op-log sync, and the browser TOTP vault + its
import/export — proven in Node and in a hand-served `demo/` page
([ADR 0019](0019-wasm-client-bindings.md), [ADR 0020](0020-shared-client-container-format.md),
[ADR 0021](0021-wasm-hybrid-public-key-encryption.md),
[ADR 0022](0022-wasm-client-server-sync-loop.md),
[ADR 0024](0024-wasm-totp-vault-and-cross-client-totp.md),
[ADR 0026](0026-browser-totp-import-export.md)). That work proved the wasm-pure
core, the mirrored container/vault/migration formats, and the cross-client TOTP
loop all work in a real browser — but only through a throwaway `demo/`. The
`web/apps/webapp` directory had been **reserved** precisely because a real product
webapp was blocked on a real, importable wasm artifact; after Phases 29–36 that
artifact and all its JS helpers exist and are tested. The user chose to turn the
reserved directory into a real Next.js app.

Two frictions had to be resolved to make that a real app rather than a second
`demo/`:

1. **A stable import surface.** A Next.js app should `import` one package, not
   reach into `pkg/` and repo-root `.mjs` files by hand. We wanted the app to
   consume the wasm exports **and** the proven, wasm-agnostic helpers
   (`totp-vault` / `sync` / `totp-migration`) through a single typed module,
   reusing the **same tested source** rather than rewriting it.
2. **Next.js cannot parse the wasm `wasm-pack --target bundler` emits.** rustc
   1.85+ **force-enables** the wasm `reference-types` + `multivalue` target
   features for `wasm32-unknown-unknown` (a `-Ctarget-feature=-…` override is
   ignored). wasm-bindgen sees those in the module's `target_features` custom
   section and emits `externref` in the function type section. Next.js 15's
   bundled webpack uses an **old `@webassemblyjs`** parser (for
   `experiments.asyncWebAssembly`) that cannot decode `externref` and dies with
   `parseVec could not cast the value`. Plain `wasm-pack build --target bundler`
   gives no way to turn this off.

## Decision

**Make `web/apps/webapp` a real Next.js 15 app that consumes a new
`@sigil/wasm` workspace loader package, which wasm-packs the repo-root
`sigil-wasm` crate for a bundler target and re-uses the proven JS helpers — with a
`target_features`/`externref` strip so Next.js's webpack can parse the module.
Keep it OUT of the default `web` CI build so marketing/CI stay Rust-free, and keep
it no-index / UNAUDITED.**

- **`@sigil/wasm` loader package —
  [`../../web/packages/sigil-wasm/`](../../web/packages/sigil-wasm/).** A private,
  `type: module` workspace package (name **`@sigil/wasm`**) whose `build.sh`
  generates **bundler-target** bindings from the **repo-root `sigil-wasm` Rust
  crate** and whose `index.mjs` re-exports the wasm surface (`seal_record` /
  `open_record`, `seal_to_container` / `open_container`, `hybrid_*`, `totp` /
  `hotp` / `format_code`, …) behind an `initWasm()` awaitable and a typed
  `index.d.ts`, **plus re-uses the proven, wasm-agnostic helpers** from the
  repo-root `sigil-wasm/{totp-vault,sync,totp-migration}.mjs` by **relative
  import** — the same tested source the CLI-interop tests exercise, **not a
  rewrite**. The generated `pkg/` is a build artifact (gitignored).
- **The `target_features` / `externref` strip — `build.sh`.** Instead of plain
  `wasm-pack`, `build.sh` runs the same three steps with a strip in the middle:
  (1) `cargo build` the crate to raw wasm; (2) delete the `target_features` custom
  section from that module, so with no such hint wasm-bindgen stays in the MVP
  subset (no `externref`, no multi-value returns) that webpack **can** parse;
  (3) run `wasm-bindgen --target bundler` on the stripped module → `pkg/`. The
  Rust is unchanged and behavior is identical; only the module metadata webpack
  chokes on is removed.
- **Next.js wiring —
  [`../../web/apps/webapp/`](../../web/apps/webapp/).** A real app-router app
  (Next.js 15.1.6 / React 19 / Tailwind 3 / TS-strict). `next.config.mjs` sets
  webpack `experiments.asyncWebAssembly = true` (so the bundler-target import
  instantiates the wasm) and carries the **same no-index stealth headers as
  marketing** (`X-Robots-Tag noindex/nofollow/noarchive`, `X-Content-Type-Options
  nosniff`, `Referrer-Policy no-referrer`, `X-Frame-Options DENY`) plus an
  `app/robots.ts` (`Disallow: /`). The page (`app/page.tsx` + a `"use client"`
  `app/totp-demo.tsx` that **dynamic-imports** `@sigil/wasm` so the wasm loads in
  the browser only, never during SSR) is a **live TOTP demo**: it defaults to the
  **public RFC 6238 test seed** (`GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ` — not a real
  secret) and renders the **wasm-computed** 6-digit code + a per-period countdown
  via the `codeForEntry` / `base32Decode` helpers (the wasm computes the code,
  never JS), with `?secret=<base32>` and `?t=<unix>` test hooks. A loud pre-audit /
  UNAUDITED / no-real-secrets banner sits in the layout and the page.
- **Kept out of the default `web` CI build.** The root `web` scripts still filter
  to **marketing only** (`pnpm --filter marketing …`), so marketing typecheck /
  lint / build and CI are unchanged and **Rust-free**. The webapp builds via its
  own filter (`pnpm --filter @sigil/wasm build`, then `pnpm --filter webapp …`), a
  webapp `prebuild` runs the `@sigil/wasm` build first, and a headless Playwright
  smoke (`tests/wasm.spec.ts`) is the runtime proof.

## Consequences

- **A two-toolchain build for the webapp.** Unlike marketing (Node/pnpm only),
  building the webapp needs the **Rust + wasm-pack toolchain**, because
  `@sigil/wasm` compiles the repo-root `sigil-wasm` crate to wasm. That is exactly
  why it stays out of the default `web` scripts / CI — keeping the always-green web
  CI Node-only — and must be built/run explicitly.
- **Runtime is proven in a real browser, not just asserted.** A headless Chromium
  Playwright smoke loads the page at `?t=59` and asserts the wasm renders the RFC
  6238 SHA-1 6-digit vector, and that a second seed recomputes to a different
  6-digit code — proving the **real** libsigil wasm runs in a real browser, not a
  JS TOTP stand-in. Served pages return the no-index headers.
- **One known-benign build warning.** `next build` emits a single warning — "The
  generated code contains 'async/await' because this module is using
  asyncWebAssembly" — which is expected for `experiments.asyncWebAssembly`, not an
  error.
- **The strip is a maintenance point.** Steps (1)–(3) and the `target_features`
  removal are tied to the current rustc / wasm-bindgen / Next.js (webpack
  `@webassemblyjs`) versions. If a future Next.js parser learns `externref`, or
  wasm-bindgen/rustc change how the target features surface, the strip can be
  revisited; `build.sh` documents exactly why it exists so the workaround is not
  mistaken for arbitrary.
- **No rewrite, no new crypto, formats unchanged.** The webapp reuses the same
  proven `.mjs` helpers and the same mirrored `SIGILcli` / `TotpVault` / migration
  formats; it adds **no** cryptography and changes **no** wire format. All crypto
  stays in `#![forbid(unsafe_code)]` `sigil-core`.
- **Still dev / no-index / UNAUDITED, and not deployed.** This is a demo of the
  same unaudited building blocks — a live TOTP view, **not** a full authenticator
  UI and **not** the product's account / key-management model. A full authenticator
  UI is a later phase. It is not deployed and stores no real secrets. Public copy
  still obeys
  [`../../web/apps/marketing/MARKETING-CLAIMS.md`](../../web/apps/marketing/MARKETING-CLAIMS.md).
