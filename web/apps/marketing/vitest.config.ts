import { defineConfig } from "vitest/config";

// Unit tests for the marketing app's pure server logic (the waitlist API route
// and the robots policy). These run in a plain Node environment — no jsdom, no
// React rendering — so the test dependency surface stays minimal (vitest only).
export default defineConfig({
  test: {
    environment: "node",
    include: ["app/**/*.test.ts"],
  },
});
