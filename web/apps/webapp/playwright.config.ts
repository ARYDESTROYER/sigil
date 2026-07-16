import { defineConfig, devices } from "@playwright/test";

// Headless smoke: prove the real libsigil wasm executes in a real browser DOM.
// The webServer runs the PRODUCTION build (`next start`), so a `next build` must
// have run first (the test:e2e npm flow builds beforehand). We pin the clock via
// `?t=` so the wasm-computed code is deterministic.
const PORT = 3210;

export default defineConfig({
  testDir: "./tests",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    headless: true,
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `pnpm exec next start -p ${PORT}`,
    url: `http://127.0.0.1:${PORT}`,
    timeout: 120_000,
    reuseExistingServer: !process.env.CI,
  },
});
