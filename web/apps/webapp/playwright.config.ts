import { defineConfig, devices } from "@playwright/test";

// Headless smoke: prove the real libsigil wasm executes in a real browser DOM.
// The webServer runs the PRODUCTION build (`next start`), so a `next build` must
// have run first (the test:e2e npm flow builds beforehand). We pin the clock via
// `?t=` so the wasm-computed code is deterministic.
//
// ⛔ THE ORIGIN MUST BE `localhost`, NOT `127.0.0.1`. Chrome refuses WebAuthn on
// an IP literal — `navigator.credentials.create()` throws
// `SecurityError: This is an invalid domain.` with or without an explicit
// `rp.id`, because an RP ID must be a registrable domain. Both are secure
// contexts, so nothing else in the suite noticed the difference; the passkey
// specs (ADR 0046) would every one of them fail for a reason unrelated to the
// feature. Verified live against the installed Chromium before this was changed.
// The `WEBAPP_ORIGIN` constants in tests/*.spec.ts (which feed the fake sigild's
// CORS allowlist, and the real sigild's SIGILD_CORS_ORIGINS in cors.spec.ts) must
// stay in step with this value.
const PORT = 3210;

export default defineConfig({
  testDir: "./tests",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  // ⛔ STAYS ZERO. A security suite that passes on the second attempt is a suite
  // whose failures get shrugged at; the determinism fix below is `workers`, not
  // a retry.
  retries: 0,
  // ⭐ PINNED, and this is the determinism fix. Playwright's default is half the
  // logical cores (7 on this machine), and these specs are not cheap tests: each
  // one boots a fake sigild, attaches a CDP virtual authenticator, and runs
  // several real Argon2id derivations in a real Chromium. At seven-way
  // contention a full run produced ten failures — a11y, cors, entitlement and
  // leak all timing out on 30 s expectations that finish in a second when the
  // machine is not oversubscribed — and every one of them passed at two workers.
  // A gate that is red for reasons unrelated to the code is a gate people learn
  // to re-run instead of read.
  workers: 2,
  reporter: [["list"]],
  // ⚠️ RAISED FROM THE 30 s DEFAULT for the passkey specs (ADR 0046). One of them
  // runs six or seven real Argon2id derivations (create, protect = re-seal both
  // containers, reload, unlock, break-glass = re-seal both again) plus several
  // WebAuthn ceremonies, which does not fit in 30 s on a laptop. The per-expect
  // timeouts stay tight; this is only the envelope.
  timeout: 180_000,
  use: {
    baseURL: `http://localhost:${PORT}`,
    headless: true,
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `pnpm exec next start -p ${PORT}`,
    url: `http://localhost:${PORT}`,
    timeout: 120_000,
    // ⛔ NEVER REUSE. `reuseExistingServer: !CI` silently binds the suite to
    // whatever `next start` happened to be listening on 3210 — including one
    // serving a build from before the change under test, which is a FALSE GREEN
    // and the exact failure mode this repo's gate script exists to catch. A port
    // that is already occupied now fails loudly instead.
    reuseExistingServer: false,
  },
});
