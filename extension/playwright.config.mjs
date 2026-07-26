import { defineConfig } from "@playwright/test";

// Headless proof that the REAL extension runs: the spec launches its own
// persistent context with the unpacked extension loaded (Chrome extensions
// require a persistent context, so there is no `use.browser` project here).
//
// Extensions are unsupported by the headless shell, so the spec launches
// `channel: "chromium"` — the full browser in the new headless mode, which does
// support them. `pnpm test` runs build.sh first (pretest) so vendor/ is fresh.
export default defineConfig({
  testDir: "./tests",
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 120_000,
  reporter: [["list"]],
});
