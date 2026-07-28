// entitlement.spec.mjs — what the popup SAYS when the account's subscription
// has lapsed (ADR 0043, read side), in the REAL unpacked MV3 extension.
//
// ⭐ THE ASSERTION THAT MATTERS is not that a warning appears — it is that the
// warning is TRUE. sigild refuses WRITES only, only past grace, and never a key
// deposit to a device of the caller's own account. So the popup must never tell
// a user a billing state has cost them their codes, and must never render a 402
// as "unauthorized". Both are asserted negatively, on purpose.
//
// The server is the same FAKE as recovery.spec.mjs: it returns sigild's shapes
// and enforces nothing. What it DOES model faithfully is the asymmetry — only
// the three gated WRITE surfaces answer 402, and reads keep serving.
//
// Pre-audit / UNAUDITED / DEV.

import { test, expect, chromium } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeSigild } from "../../sigil-wasm/test/fake-sigild.mjs";

const EXT_DIR = path.dirname(fileURLToPath(new URL("../package.json", import.meta.url)));
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_CODE_6 = "287082";
const PINNED_T = 59;
const VAULT_ID = "ext-billing-demo";
const LAPSED = {
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

async function extensionId() {
  const manifest = JSON.parse(await readFile(path.join(EXT_DIR, "manifest.json"), "utf8"));
  const der = Buffer.from(manifest.key, "base64");
  const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

let fake;
let id;
let context;
let userDataDir;

test.beforeAll(async () => {
  id = await extensionId();
  fake = await startFakeSigild();
  userDataDir = await mkdtemp(path.join(tmpdir(), "sigil-ext-billing-"));
  context = await chromium.launchPersistentContext(userDataDir, {
    channel: "chromium",
    headless: true,
    args: [`--disable-extensions-except=${EXT_DIR}`, `--load-extension=${EXT_DIR}`],
  });
});

test.afterAll(async () => {
  await context?.close();
  if (userDataDir) await rm(userDataDir, { recursive: true, force: true });
  await fake?.close();
});

/** A popup with a vault, one RFC account, and an enrolled device. */
async function readyPopup(password) {
  const page = await context.newPage();
  const failures = [];
  page.on("pageerror", (e) => failures.push(String(e)));
  await page.goto(`chrome-extension://${id}/src/popup/popup.html?t=${PINNED_T}`);
  await expect(page.locator("body")).toHaveAttribute("data-wasm", /.+/, { timeout: 30_000 });
  // boot() decides setup-vs-locked AFTER an async storage read, so wait for the
  // phase to be settled before branching on it.
  await expect(page.locator("body")).toHaveAttribute("data-phase", /setup|locked/, {
    timeout: 30_000,
  });

  if (await page.getByTestId("view-setup").isVisible()) {
    await page.getByTestId("setup-password").fill(password);
    await page.getByTestId("setup-password-2").fill(password);
    await page.getByTestId("setup-submit").click();
  } else {
    await page.getByTestId("unlock-password").fill(password);
    await page.getByTestId("unlock-submit").click();
  }
  await expect(page.getByTestId("view-unlocked")).toBeVisible({ timeout: 30_000 });

  if ((await page.getByTestId("account").count()) === 0) {
    await page.getByTestId("add-toggle").click();
    await page.getByTestId("add-label").fill("rfc6238");
    await page.getByTestId("add-secret").fill(RFC_SECRET);
    await page.getByTestId("add-submit").click();
  }
  await expect(page.getByTestId("code")).toHaveText(RFC_CODE_6);

  await page.getByTestId("sync-toggle").click();
  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("sync-vault").fill(VAULT_ID);
  if (await page.getByTestId("device-enroll").isVisible()) {
    await page.getByTestId("device-token").fill("operator-token-0123456789abcdef");
    await page.getByTestId("device-enroll").click();
    await expect(page.getByTestId("status")).toContainText("Enrolled as", { timeout: 30_000 });
  }
  return { page, failures };
}

test("inside grace: a visible, non-blocking warning that names what still works", async () => {
  fake.refuseWrites = false;
  fake.subscription = LAPSED;

  const { page, failures } = await readyPopup("billing-password");
  await page.getByTestId("entitlement-refresh").click();

  const note = page.getByTestId("entitlement-state");
  await expect(note).toBeVisible({ timeout: 30_000 });
  await expect(note).toContainText("stops");

  // ⭐ THE MESSAGE MUST BE TRUE. Reads and same-account key recovery are never
  // refused, so it says so — and it does not dress a billing state up as a
  // sign-in problem.
  await expect(note).toContainText("existing codes are NOT affected");
  await expect(note).toContainText("offline");
  await expect(note).toContainText("recovery kit");
  await expect(note).not.toContainText("unauthorized");
  await expect(note).not.toContainText("forbidden");

  // Non-blocking: a write inside grace still succeeds.
  await page.getByTestId("sync-push").click();
  await expect(page.getByTestId("status")).toContainText("Pushed sealed container", {
    timeout: 30_000,
  });
  await expect(page.getByTestId("entitlement-402")).toBeHidden();

  expect(failures).toEqual([]);
  await page.close();
});

test("past grace: a refused write reads as PAYMENT, and reads keep working", async () => {
  fake.refuseWrites = false;
  fake.subscription = LAPSED;

  const { page, failures } = await readyPopup("billing-password");

  // One successful push while still in grace, so there is something to READ
  // back once the account is refused — the whole point of the asymmetry.
  await page.getByTestId("sync-push").click();
  await expect(page.getByTestId("status")).toContainText("Pushed sealed container", {
    timeout: 30_000,
  });

  // The grace period ends.
  fake.refuseWrites = true;
  fake.subscription = {
    ...LAPSED,
    entitlement: { ...LAPSED.entitlement, writes: "refused", grace_ends_at: "2026-07-01T00:00:00Z" },
  };

  await page.getByTestId("entitlement-refresh").click();
  await expect(page.getByTestId("entitlement-state")).toContainText("Payment required", {
    timeout: 30_000,
  });

  // A refused WRITE renders as the 402 it is: its own region, its own words,
  // and never the word "unauthorized".
  await page.getByTestId("sync-push").click();
  const four02 = page.getByTestId("entitlement-402");
  await expect(four02).toBeVisible({ timeout: 30_000 });
  await expect(four02).toContainText("Payment required");
  await expect(four02).toContainText("BILLING state");
  await expect(four02).toContainText("existing codes are NOT affected");
  await expect(four02).not.toContainText("unauthorized");
  await expect(four02).not.toContainText("forbidden");
  await expect(page.getByTestId("status")).not.toContainText("Push failed");

  // ⭐ READS ARE NEVER REFUSED: the pull still works while the account is
  // lapsed, and the codes already held still generate in the wasm, offline.
  await page.getByTestId("sync-pull").click();
  await expect(page.getByTestId("status")).toContainText("Pulled op #", { timeout: 30_000 });
  await expect(page.getByTestId("code")).toHaveText(RFC_CODE_6);

  expect(failures).toEqual([]);
  await page.close();
});

test("a server that does not enforce payment says nothing at all", async () => {
  fake.refuseWrites = false;
  // No `entitlement` block — what EVERY sigild that has not opted in returns.
  fake.subscription = { subject: "acc_fake_1", status: "active", entitled: true };

  const { page, failures } = await readyPopup("billing-password");
  await page.getByTestId("entitlement-refresh").click();
  await expect(page.getByTestId("entitlement-state")).toContainText(
    "does not enforce payment",
    { timeout: 30_000 },
  );

  expect(failures).toEqual([]);
  await page.close();
});
