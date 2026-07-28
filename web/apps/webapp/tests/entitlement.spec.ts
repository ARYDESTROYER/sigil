import { expect, test, type Page } from "@playwright/test";
// See recovery.spec.ts for what this fake is and is not. It returns sigild's
// entitlement SHAPES (the additive block on the subscription route and the
// machine-readable 402) so this spec can assert what the UI SAYS about them.
// @ts-expect-error — plain .mjs test helper shared with the extension suite.
import { startFakeSigild } from "../../../../sigil-wasm/test/fake-sigild.mjs";

const T = 60_000;
const RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_CODE = "287082";
const VAULT_ID = "billing-demo";
/** The origin playwright.config.ts serves the built app on. */
const WEBAPP_ORIGIN = "http://localhost:3210";

type Fake = {
  baseUrl: string;
  close: () => Promise<void>;
  subscription: unknown;
  refuseWrites: boolean;
};

let fake: Fake;

test.beforeAll(async () => {
  // EXPLICIT allowlist, mirroring a real sigild's SIGILD_CORS_ORIGINS — the fake
  // sends no CORS header without one (see recovery.spec.ts).
  fake = (await startFakeSigild({ corsOrigins: [WEBAPP_ORIGIN] })) as Fake;
});

test.afterAll(async () => {
  await fake?.close();
});

async function enrolledVault(page: Page, password: string) {
  await page.goto("/?t=59");
  await page.getByTestId("setup-password").fill(password);
  await page.getByTestId("setup-confirm").fill(password);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });

  await page.getByTestId("add-label").fill("rfc-vector");
  await page.getByTestId("add-secret").fill(RFC_SECRET_B32);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });

  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("sync-vault-id").fill(VAULT_ID);
  await page.getByTestId("device-token").fill("operator-token-0123456789abcdef");
  await page.getByTestId("device-enroll").click();
  await expect(page.getByTestId("sync-status")).toContainText("Enrolled as", { timeout: T });
}

test("inside grace: a visible, non-blocking warning that names what still works", async ({
  page,
}: {
  page: Page;
}) => {
  fake.refuseWrites = false;
  fake.subscription = {
    subject: "acc_fake_1",
    status: "canceled",
    entitled: false,
    entitlement: {
      enforced: true,
      writes: "grace",
      reads: "allowed",
      grace_ends_at: "2026-08-11T00:00:00Z",
    },
  };

  await enrolledVault(page, "grace-password");

  const warning = page.getByTestId("entitlement-grace");
  await expect(warning).toBeVisible({ timeout: T });
  await expect(warning).toContainText("stops");

  // ⭐ THE MESSAGE MUST BE TRUE. Reads and same-account key recovery are never
  // refused, so the warning must say so — and must NOT dress a billing state up
  // as a sign-in problem.
  await expect(warning).toContainText("existing codes are NOT affected");
  await expect(warning).toContainText("offline");
  await expect(warning).toContainText("recovery kit");
  await expect(warning).not.toContainText("unauthorized");
  await expect(warning).not.toContainText("forbidden");

  // Non-blocking: writes still work inside grace.
  await page.getByTestId("sync-push").click();
  await expect(page.getByTestId("sync-status")).toContainText("Pushed sealed container", {
    timeout: T,
  });
  await expect(page.getByTestId("entitlement-402")).toHaveCount(0);
});

test("past grace: a refused write reads as PAYMENT, never as an auth failure — and reads keep working", async ({
  page,
}: {
  page: Page;
}) => {
  fake.refuseWrites = false;
  fake.subscription = {
    subject: "acc_fake_1",
    status: "canceled",
    entitled: false,
    entitlement: {
      enforced: true,
      writes: "grace",
      reads: "allowed",
      grace_ends_at: "2026-08-11T00:00:00Z",
    },
  };

  await enrolledVault(page, "lapsed-password");

  // One successful push while still in grace, so there is something to READ back
  // after the account is refused — the point of the whole asymmetry.
  await page.getByTestId("sync-push").click();
  await expect(page.getByTestId("sync-status")).toContainText("Pushed sealed container", {
    timeout: T,
  });

  // The grace period ends.
  fake.refuseWrites = true;
  fake.subscription = {
    subject: "acc_fake_1",
    status: "canceled",
    entitled: false,
    entitlement: {
      enforced: true,
      writes: "refused",
      reads: "allowed",
      grace_ends_at: "2026-07-01T00:00:00Z",
    },
  };

  await page.getByTestId("entitlement-refresh").click();
  const refused = page.getByTestId("entitlement-refused");
  await expect(refused).toBeVisible({ timeout: T });
  await expect(refused).toContainText("Payment required");
  await expect(refused).not.toContainText("unauthorized");

  // A refused WRITE renders as the 402 it is: its own region, its own words.
  await page.getByTestId("sync-push").click();
  const four02 = page.getByTestId("entitlement-402");
  await expect(four02).toBeVisible({ timeout: T });
  await expect(four02).toContainText("Payment required");
  await expect(four02).toContainText("BILLING state");
  await expect(four02).toContainText("existing codes are NOT affected");
  await expect(four02).not.toContainText("unauthorized");
  await expect(four02).not.toContainText("forbidden");
  await expect(page.getByTestId("sync-status")).not.toContainText("Push failed");

  // ⭐ READS ARE NEVER REFUSED. The pull still works while the account is lapsed…
  await page.getByTestId("sync-pull").click();
  await expect(page.getByTestId("sync-status")).toContainText("Pulled op #", { timeout: T });

  // …and the codes this browser already holds still generate, in the wasm, with
  // no server involved at all. That is the promise the message makes.
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE);
});

test("a server that does not enforce payment says nothing at all", async ({
  page,
}: {
  page: Page;
}) => {
  fake.refuseWrites = false;
  // No `entitlement` block: this is what EVERY sigild that has not opted in
  // returns, and the client must invent no warning from it.
  fake.subscription = { subject: "acc_fake_1", status: "active", entitled: true };

  await enrolledVault(page, "unenforced-password");

  await expect(page.getByTestId("entitlement-status")).toContainText("does not enforce payment", {
    timeout: T,
  });
  await expect(page.getByTestId("entitlement-grace")).toHaveCount(0);
  await expect(page.getByTestId("entitlement-refused")).toHaveCount(0);
});
