# 0029 — Webapp as an offline-capable, accessible PWA + a webapp CI job

- **Status:** Accepted — 2026-07.

## Context

[ADR 0027](0027-webapp-and-wasm-bundling.md) stood up `web/apps/webapp` as a real
Next.js app running the libsigil core via WebAssembly, and
[ADR 0028](0028-webapp-vault-persistence-and-unlock.md) made it a real (dev)
authenticator with a `localStorage`-persisted, `SIGILcli`-sealed TOTP vault. Two
gaps remained before it could be called shippable-shaped:

1. **An authenticator must work offline.** People reach for a 2FA app exactly when
   they are mid-login, often on a flaky or absent network; a code generator that
   needs the network to render is unusable. The app already computes every code
   locally in the wasm, but a plain web page still fails to *load* offline — the
   HTML shell, the JS chunks, and the `.wasm` itself are fetched over the network
   on every visit.

2. **Shippable means accessible, and means CI.** A real product surface has to be
   operable by keyboard and assistive technology (labels, focus, live regions),
   and it has to be built and exercised by CI rather than only on one laptop. But
   the webapp is **not** Rust-free — it compiles `sigil-core` to wasm — so it
   cannot simply join the existing Rust-free `web` marketing CI job, and its
   `build.sh` was written for this macOS box (a hard-coded rustup toolchain path)
   rather than a Linux CI runner.

We wanted all of this **without** adding a heavy PWA framework, a service-worker
generator, or any new runtime dependency, and **without** weakening the stealth
no-index posture or the zero-knowledge boundary (the sealed vault must never be
handed to a cache).

## Decision

**Make the webapp an installable, offline-capable, accessible PWA using a
hand-rolled service worker + a web manifest, prove offline and a11y in Playwright,
and add a separate Rust + wasm-pack CI job so the marketing job stays Rust-free —
after making `build.sh` OS-agnostic.**

- **A hand-rolled service worker, not a PWA framework.** `public/sw.js` is a small,
  dependency-free worker registered by `app/register-sw.tsx`. It **precaches the app
  shell** (`"/"`) on install and, on `fetch`, serves **same-origin GET** requests
  **cache-first**, writing every successful response (HTML / JS / CSS / `.wasm` /
  icons) into a single named cache at runtime — so the second visit, and the
  wasm-computed TOTP it powers, works with **no network**. Navigations are
  network-first with a cached-shell fallback. We chose this over Workbox /
  `next-pwa` to keep the exact caching policy legible and add **zero dependencies**.
- **A web manifest for installability.** `app/manifest.ts` (Next's typed
  `MetadataRoute.Manifest`) declares name / icons / `display: standalone` so the app
  is installable. A manifest does **not** make a site crawlable, so the no-index
  posture (robots.ts + `X-Robots-Tag` + layout metadata) is unchanged.
- **Static assets only — never secrets.** The service worker caches **only public
  static assets**. It never caches the sealed vault (that stays in `localStorage`,
  per [ADR 0028](0028-webapp-vault-persistence-and-unlock.md)) and never touches
  **cross-origin** requests, so the dev sync to a localhost sigild op-log is left
  entirely alone. The cache holds ciphertext-free, key-free public code and assets.
- **Accessibility, proven with axe-in-Playwright.** The UI uses labelled
  landmarks/controls, is keyboard-operable, shows visible focus, and announces code
  updates via a live region. `tests/a11y.spec.ts` runs `@axe-core/playwright` on the
  setup and unlocked views and fails on any **serious/critical** violation.
- **Offline, proven with Playwright.** `tests/offline.spec.ts` loads the app online,
  waits for the SW to control the page, reloads once through the SW to populate the
  runtime cache, then goes **offline** and asserts the shell still renders **and the
  cached wasm still computes** the RFC 6238 code.
- **A separate `webapp` CI job; marketing stays Rust-free.** `.github/workflows/web.yml`
  keeps the existing Rust-free `build` job (marketing: install → lint → typecheck →
  build) and adds a **second `webapp` job** that installs a Rust toolchain +
  `wasm-bindgen-cli`/`wasm-pack`, builds `@sigil/wasm`, then runs the webapp's
  typecheck/lint/build and the **Playwright suite** (including the offline + axe
  proofs). The two jobs are isolated so the marketing gate never pulls in Rust.
- **`build.sh` made OS-agnostic.** `web/packages/sigil-wasm/build.sh` now prepends
  only the toolchain dirs that actually exist (the macOS rustup path, `~/.cargo/bin`,
  Homebrew) and discovers `wasm-bindgen` from `PATH` first (falling back to a
  wasm-pack-managed copy under either the macOS or Linux cache dir), so the same
  script builds on this laptop **and** on a Linux CI runner.

## Consequences

- **Codes generate offline after the first load.** Once the app has been opened
  online once (populating the cache), it renders and computes TOTP codes with the
  network fully down — the core property an authenticator needs. Cache versioning is
  a manual `CACHE` bump in `sw.js`; there is no automatic asset-revision pipeline yet.
- **The offline cache holds no secrets.** Only public static assets are cached; the
  sealed vault stays in `localStorage` and cross-origin sync is untouched, so the
  service worker does not widen the trust boundary or touch plaintext/keys.
- **The webapp CI job is by-eye / unrun-on-real-CI, like the repo's other mirrors.**
  The job's YAML has been validated locally and mirrors the known-green local
  commands, but — exactly like the sigild / web / publish workflows — it has **not**
  been executed on real GitHub Actions from this machine; treat a green CI run as
  still-to-be-observed. It is also slower and heavier than the marketing job (it
  provisions Rust + wasm-pack + a headless browser).
- **Still dev / no-index / UNAUDITED and not deployed.** PWA installability and
  offline support do **not** change the posture: there is no host target, no domain,
  and the loud UNAUDITED / no-real-secrets banner stands. This is not the product's
  final client, key-management, or sync model. Public copy still obeys
  [`../../web/apps/marketing/MARKETING-CLAIMS.md`](../../web/apps/marketing/MARKETING-CLAIMS.md).
