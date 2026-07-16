# @sigil/wasm

Workspace loader for the libsigil `sigil-core` compiled to WebAssembly, consumed
by the webapp. **Pre-audit / UNAUDITED — do not protect real secrets.**

## What it exports

One typed surface (`index.mjs` + hand-written `index.d.ts`):

- the **bundler-target wasm exports** — `totp` / `hotp` / `format_code`,
  `seal_record` / `open_record`, `seal_to_container` / `open_container`, the
  `hybrid_*` public-key path, and `nonce_len` / `recommended_salt_len` /
  `version`;
- an `async initWasm()` returning the ready wasm object; and
- the **proven, wasm-agnostic helpers** re-exported by relative path from the
  repo-root `sigil-wasm/` crate — `totp-vault.mjs`
  (`openVault` / `codeForEntry` / `addEntry` / `sealVault` / `base32Decode` / …),
  `sync.mjs` (`pushContainer` / `pullContainers`), and `totp-migration.mjs`
  (`parseOtpauthUri` / `buildOtpauthUri` / migration URIs). These are the SAME
  tested source the CLI-interop tests exercise — not a rewrite.

## Build

```bash
pnpm --filter @sigil/wasm build   # runs ./build.sh → wasm-pack --target bundler
```

`build.sh` runs `wasm-pack build ../../../sigil-wasm --target bundler --out-dir
./pkg`. The generated `pkg/` is a **build artifact** (gitignored, never
committed). Build does **not** run on install — Rust + wasm-pack are required
only for the explicit `build` script. The webapp consumes the bundler output via
Next.js `experiments.asyncWebAssembly`.
