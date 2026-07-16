import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const T = 30_000;
const RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

// Fail only on genuinely blocking issues; report them readably.
async function expectNoSeriousA11yViolations(page: Page) {
  const results = await new AxeBuilder({ page }).analyze();
  const blocking = results.violations.filter(
    (v) => v.impact === "serious" || v.impact === "critical",
  );
  const summary = blocking
    .map((v) => `${v.id} (${v.impact}): ${v.help} [${v.nodes.length} node(s)]`)
    .join("\n");
  expect(blocking, `axe serious/critical violations:\n${summary}`).toEqual([]);
}

test("landing (setup) page has no serious/critical axe violations", async ({ page }) => {
  await page.goto("/?t=59");
  await expect(page.getByTestId("wasm-status")).toHaveText("ready", { timeout: T });
  await expect(page.getByTestId("setup-submit")).toBeVisible({ timeout: T });
  await expectNoSeriousA11yViolations(page);
});

test("unlocked vault view has no serious/critical axe violations", async ({ page }) => {
  await page.goto("/?t=59");
  await expect(page.getByTestId("setup-submit")).toBeVisible({ timeout: T });

  await page.getByTestId("setup-password").fill("a11y-pass");
  await page.getByTestId("setup-confirm").fill("a11y-pass");
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });

  await page.getByTestId("add-label").fill("rfc-vector");
  await page.getByTestId("add-secret").fill(RFC_SECRET_B32);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-code")).toHaveText("287082", { timeout: T });

  await expectNoSeriousA11yViolations(page);
});
