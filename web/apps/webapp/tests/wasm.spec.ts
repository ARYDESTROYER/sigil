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

// ── Authenticator feature smokes (the real UI, clock pinned via ?t=) ─────────

// The RFC 6238 SHA-1 seed "12345678901234567890" in base32. Adding it as an
// account and pinning the clock to t=59 must reproduce the same 287082 vector —
// this time through the REAL add-account → in-memory vault → wasm code path.
const RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const T = 30_000;

// Create a fresh vault with the given password, ending in the unlocked view.
async function setupVault(page: import("@playwright/test").Page, password: string) {
  await page.getByTestId("setup-password").fill(password);
  await page.getByTestId("setup-confirm").fill(password);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
}

test("adds an account via the form and shows the wasm-computed RFC code", async ({ page }) => {
  await page.goto("/?t=59");
  await setupVault(page, "correct-horse");

  await page.getByTestId("add-label").fill("rfc-vector");
  await page.getByTestId("add-secret").fill(RFC_SECRET_B32);
  // algorithm sha1 / digits 6 / period 30 are the form defaults.
  await page.getByTestId("add-submit").click();

  await expect(page.getByTestId("account-count")).toHaveText("1", { timeout: T });
  await expect(page.getByTestId("account-code")).toHaveText(EXPECTED_CODE, { timeout: T });
});

test("imports a Google Authenticator otpauth-migration URI", async ({ page }) => {
  // Canonical golden vector: one TOTP account "Example:alice@google.com".
  const MIGRATION_URI =
    "otpauth-migration://offline?data=CjUKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZSABKAEwAhAB";

  await page.goto("/?t=59");
  await setupVault(page, "pw-migration");

  await page.getByTestId("migration-input").fill(MIGRATION_URI);
  await page.getByTestId("migration-submit").click();

  await expect(page.getByTestId("import-result")).toContainText("Imported 1", { timeout: T });
  await expect(page.getByTestId("account-count")).toHaveText("1", { timeout: T });
  await expect(page.getByTestId("account-label")).toContainText("alice@google.com");
});

test("persists the sealed vault across reload (lock/unlock round-trip)", async ({ page }) => {
  const password = "s3cret-persist";

  await page.goto("/?t=59");
  await setupVault(page, password);

  await page.getByTestId("add-label").fill("persisted");
  await page.getByTestId("add-secret").fill(RFC_SECRET_B32);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-label")).toContainText("persisted", { timeout: T });

  // Reload: the plaintext vault + password are gone from memory, only the sealed
  // container survives in localStorage, so the app comes back LOCKED.
  await page.reload();
  await expect(page.getByTestId("unlock-password")).toBeVisible({ timeout: T });

  await page.getByTestId("unlock-password").fill(password);
  await page.getByTestId("unlock-submit").click();

  // Unlock decrypts the persisted vault: the account (and its live code) return.
  await expect(page.getByTestId("account-label")).toContainText("persisted", { timeout: T });
  await expect(page.getByTestId("account-code")).toHaveText(EXPECTED_CODE, { timeout: T });
});
