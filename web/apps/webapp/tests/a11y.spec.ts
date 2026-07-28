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

// The recovery form is the ONE screen a customer who lost every device will
// reach, and they will reach it on a fresh install, possibly under stress. It
// must be as accessible as the rest.
test("the restore-from-a-recovery-kit form has no serious/critical axe violations", async ({
  page,
}) => {
  await page.goto("/?t=59");
  await expect(page.getByTestId("restore-open")).toBeVisible({ timeout: T });
  await page.getByTestId("restore-open").click();
  await expect(page.getByTestId("restore-code")).toBeVisible({ timeout: T });
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

// The passkey panel (ADR 0046) and — more importantly — the break-glass field on
// the LOCKED screen. That field is what a person reaches for when their passkey
// has just stopped working, which is not a calm moment; it must be reachable by
// keyboard, announced, and axe-clean.
test("the passkey panel and the locked-screen break-glass field are axe-clean", async ({
  page,
}) => {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
      hasPrf: true,
    },
  } as never);

  await page.goto("/?t=59");
  await page.getByTestId("setup-password").fill("a11y-passkey");
  await page.getByTestId("setup-confirm").fill("a11y-passkey");
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });

  // The panel in its default (unprotected) state, inside the unlocked vault.
  await expect(page.getByTestId("passkey-state")).toBeVisible();
  await expect(page.getByTestId("passkey-enable")).toBeVisible();
  await expectNoSeriousA11yViolations(page);

  // The locked screen WITH a passkey slot present: the break-glass form is
  // always visible there, never hidden behind a disclosure.
  await page.evaluate(() => {
    // A slot-shaped value is enough to render the locked variant; opening it is
    // covered by passkey.spec.ts.
    window.localStorage.setItem(
      "sigil.webapp.hwslot.v1",
      window.localStorage.getItem("sigil.webapp.vault.v1") ?? "",
    );
  });
  await page.reload();
  await expect(page.getByTestId("unlock-recovery-code")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("unlock-passkey-required")).toBeVisible();
  await expectNoSeriousA11yViolations(page);

  // Keyboard-reachable: focus the code field directly and type into it.
  await page.getByTestId("unlock-recovery-code").focus();
  await page.keyboard.type("ABC");
  await expect(page.getByTestId("unlock-recovery-code")).toHaveValue("ABC");
});
