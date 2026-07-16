import { expect, test } from "@playwright/test";

// The RFC 6238 SHA-1 test vector: seed "12345678901234567890", at unix time 59s,
// period 30, 6 digits -> 287082. The page defaults to that seed; `?t=59` pins the
// clock. If this exact code renders, the libsigil wasm engine really ran in the
// browser (JS never computes TOTP here).
const EXPECTED_CODE = "287082";

test("renders a wasm-computed TOTP code in the browser", async ({ page }) => {
  await page.goto("/?t=59");

  // The wasm module must finish loading client-side.
  await expect(page.getByTestId("wasm-status")).toHaveText("ready", {
    timeout: 30_000,
  });

  // The wasm-derived RFC test-vector code must appear in the DOM.
  await expect(page.getByTestId("totp-code")).toHaveText(EXPECTED_CODE, {
    timeout: 30_000,
  });
});

test("recomputes for a different seed via the wasm", async ({ page }) => {
  // A distinct base32 seed ("AAAAAAAAAAAAAAAA" = 10 zero bytes) at t=59 exercises
  // the wasm engine on non-default input; assert it is a fresh 6-digit code that
  // is NOT the default vector's code (proves it truly recomputed).
  await page.goto("/?t=59&secret=AAAAAAAAAAAAAAAA");
  await expect(page.getByTestId("wasm-status")).toHaveText("ready", {
    timeout: 30_000,
  });
  const code = await page.getByTestId("totp-code").textContent();
  expect(code).toMatch(/^\d{6}$/);
  expect(code).not.toBe(EXPECTED_CODE);
});
