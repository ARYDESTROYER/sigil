import { expect, test, type Browser, type Page } from "@playwright/test";
// The fake dev server. It verifies no signatures and enforces no authorization —
// it exists so this spec can drive the REAL UI, with the REAL wasm doing every
// cryptographic step, against something that behaves like sigild's shapes.
// Protocol conformance against the real server lives in
// sigil-wasm/test/recovery-interop.mjs and cli/tests/e2e-recovery.sh.
// @ts-expect-error — plain .mjs test helper shared with the extension suite.
import { startFakeSigild } from "../../../../sigil-wasm/test/fake-sigild.mjs";

const T = 60_000;
const RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_CODE = "287082"; // RFC 6238 App B at ?t=59, 6 digits
const VAULT_ID = "webapp-demo";
/** The origin playwright.config.ts serves the built app on. */
const WEBAPP_ORIGIN = "http://127.0.0.1:3210";

type Fake = {
  baseUrl: string;
  close: () => Promise<void>;
  log: string[];
  state: { envelopes: Map<string, unknown>; ops: Map<string, unknown> };
};

let fake: Fake;

test.beforeAll(async () => {
  // ⚠️ The allowlist is EXPLICIT and mirrors a real sigild's SIGILD_CORS_ORIGINS.
  // The fake sends no CORS header without it, exactly as sigild does — a fake
  // that was permissive by default hid a completely dead browser path.
  fake = (await startFakeSigild({ corsOrigins: [WEBAPP_ORIGIN] })) as Fake;
});

test.afterAll(async () => {
  await fake?.close();
});

async function setupVault(page: Page, password: string) {
  await page.getByTestId("setup-password").fill(password);
  await page.getByTestId("setup-confirm").fill(password);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
}

/**
 * ⭐ THE TEST THAT MATTERS: generate a kit on one browser profile, then RESTORE
 * on a genuinely CLEAN one — no localStorage, no device identity, no vault. That
 * is the situation a customer who lost every device is actually in, and it is
 * exactly the situation the previous release could not serve in a browser.
 */
test("generate a kit, cover a vault, then RESTORE on a clean profile", async ({
  page,
  browser,
}: {
  page: Page;
  browser: Browser;
}) => {
  // ── profile 1: an ordinary user with a vault ───────────────────────────────
  await page.goto("/?t=59");
  await setupVault(page, "profile-one-password");

  await page.getByTestId("add-label").fill("rfc-vector");
  await page.getByTestId("add-secret").fill(RFC_SECRET_B32);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });

  // Point at the fake server and enrol this browser as a device.
  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("sync-vault-id").fill(VAULT_ID);
  await page.getByTestId("device-token").fill("operator-token-0123456789abcdef");
  await page.getByTestId("device-enroll").click();
  await expect(page.getByTestId("sync-status")).toContainText("Enrolled as", { timeout: T });

  // A kit can only be given a vault KEY, so the vault has to be a SHARED vault:
  // a personal vault is sealed with the human password, which is never shared,
  // never wrapped and never sent.
  await page.getByTestId("sharing-convert").click();
  await expect(page.getByTestId("sharing-status")).toContainText("random 32-byte vault key", {
    timeout: T,
  });

  // Push, so the server actually holds ciphertext. A kit recovers KEYS, not DATA.
  await page.getByTestId("sync-push").click();
  await expect(page.getByTestId("sync-status")).toContainText("Pushed sealed container", {
    timeout: T,
  });

  // ── generate the kit ──────────────────────────────────────────────────────
  await page.getByTestId("recovery-generate").click();
  await expect(page.getByTestId("recovery-sheet")).toBeVisible({ timeout: T });

  const formatted = ((await page.getByTestId("recovery-code").textContent()) ?? "").trim();
  const kitDeviceId = ((await page.getByTestId("recovery-kit-id").textContent()) ?? "").trim();

  // 56 Crockford characters, printed as 7 groups of 8.
  expect(formatted.split("-")).toHaveLength(7);
  expect(formatted.replace(/-/g, "")).toHaveLength(56);
  expect(kitDeviceId).toMatch(/^dev_/);

  // The sheet carries the safety number, the coverage AS OF TODAY, and the
  // warnings — including the one that says holding it is holding the account.
  await expect(page.getByTestId("recovery-safety-number")).toHaveText(/\d{5}( \d{5}){5}/);
  await expect(page.getByTestId("recovery-covered")).toContainText(VAULT_ID);
  await expect(page.getByTestId("recovery-sheet")).toContainText("FULL CONTROL OF THE ACCOUNT");
  await expect(page.getByTestId("recovery-sheet")).toContainText("NEVER PHOTOGRAPH IT");
  await expect(page.getByTestId("recovery-sheet")).toContainText("RECOVERS KEYS, NOT DATA");
  // It DID cover something, so the "covers nothing" alarm must be absent.
  await expect(page.getByTestId("recovery-covers-nothing")).toHaveCount(0);

  // ⭐ THE CODE IS A CREDENTIAL: it must not be persisted anywhere, and the two
  // storage keys must still be the only two, both sealed containers.
  const stored = await page.evaluate(() => ({
    keys: Object.keys(window.localStorage).sort(),
    blob: JSON.stringify(window.localStorage),
  }));
  expect(stored.keys).toEqual(["sigil.webapp.device.v1", "sigil.webapp.vault.v1"]);
  expect(stored.blob).not.toContain(formatted);
  expect(stored.blob).not.toContain(formatted.replace(/-/g, ""));
  expect(stored.blob).not.toContain("profile-one-password");
  // …and it never went into a URL.
  expect(page.url()).not.toContain(formatted.slice(0, 8));

  // COVER: re-covering from the browser that printed the kit takes the DERIVED
  // path — the key was never fetched, so nothing could have been substituted.
  await page.getByTestId("recovery-cover-kit").fill(kitDeviceId);
  await page.getByTestId("recovery-cover").click();
  await expect(page.getByTestId("recovery-status")).toContainText("derived locally", {
    timeout: T,
  });

  // Confirming clears the code from the DOM; it cannot be shown again.
  await page.getByTestId("recovery-written").check();
  await page.getByTestId("recovery-hide").click();
  await expect(page.getByTestId("recovery-code")).toHaveCount(0);
  await expect(page.getByTestId("recovery-status")).toContainText("cleared from this screen");

  // CHECK reports that recovery is set up and which vaults are covered.
  await page.getByTestId("recovery-check").click();
  await expect(page.getByTestId("recovery-coverage")).toContainText("1 kit(s) enrolled", {
    timeout: T,
  });
  await expect(page.getByTestId("recovery-coverage")).toContainText(`covered by ${kitDeviceId}`);

  // ── profile 2: a FRESH INSTALL. Nothing stored, nothing enrolled. ──────────
  const clean = await browser.newContext();
  const fresh = await clean.newPage();
  await fresh.goto("/?t=59");

  // It really is clean: the app boots into setup, not into a lock screen.
  await expect(fresh.getByTestId("setup-submit")).toBeVisible({ timeout: T });
  expect(await fresh.evaluate(() => Object.keys(window.localStorage))).toEqual([]);

  await fresh.getByTestId("restore-open").click();
  await fresh.getByTestId("restore-url").fill(fake.baseUrl);
  await fresh.getByTestId("restore-device-id").fill(kitDeviceId);

  // A wrong code is refused OFFLINE, before anything is sent, and is named as a
  // typo rather than as an auth failure. ("U" is never part of the alphabet.)
  const requestsBefore = fake.log.length;
  await fresh.getByTestId("restore-code").fill("U".repeat(56));
  await fresh.getByTestId("restore-password").fill("profile-two-password");
  await fresh.getByTestId("restore-confirm").fill("profile-two-password");
  await fresh.getByTestId("restore-submit").click();
  await expect(fresh.getByTestId("restore-error")).toContainText("not a valid recovery code", {
    timeout: T,
  });
  expect(fake.log.length).toBe(requestsBefore); // nothing reached the server

  // The real code, pasted the way a human would: grouped, and in lower case.
  await fresh.getByTestId("restore-code").fill(formatted.toLowerCase());
  await fresh.getByTestId("restore-submit").click();

  // ⭐ Landed in an UNLOCKED vault, with the account back and the wasm computing
  // the RFC vector — on a profile that started completely empty.
  await expect(fresh.getByTestId("vault-view")).toBeVisible({ timeout: T });
  await expect(fresh.getByTestId("account-label")).toContainText("rfc-vector", { timeout: T });
  await expect(fresh.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });

  // The restored profile persists ONLY the two sealed containers, and the code
  // is in neither of them nor in the address bar.
  const restored = await fresh.evaluate(() => ({
    keys: Object.keys(window.localStorage).sort(),
    blob: JSON.stringify(window.localStorage),
  }));
  expect(restored.keys).toEqual(["sigil.webapp.device.v1", "sigil.webapp.vault.v1"]);
  expect(restored.blob).not.toContain(formatted);
  expect(restored.blob).not.toContain(formatted.replace(/-/g, ""));
  expect(fresh.url()).not.toContain(formatted.slice(0, 8));

  // The code field was cleared the moment it worked.
  await expect(fresh.getByTestId("restore-code")).toHaveCount(0);

  await clean.close();
});

/**
 * A kit that covers nothing recovers nothing — the likeliest real-world failure,
 * so the UI has to say so before the user files the sheet away.
 */
test("a kit generated with no vault keys warns that it covers NOTHING", async ({
  page,
}: {
  page: Page;
}) => {
  await page.goto("/?t=59");
  await setupVault(page, "covers-nothing-pw");

  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("sync-vault-id").fill("empty-vault");
  await page.getByTestId("device-token").fill("operator-token-0123456789abcdef");
  await page.getByTestId("device-enroll").click();
  await expect(page.getByTestId("sync-status")).toContainText("Enrolled as", { timeout: T });

  // Before generating, the panel already says a kit would cover nothing.
  await expect(page.getByTestId("recovery-no-vault-keys")).toContainText("covers", {
    timeout: T,
  });

  // Deliberately generate anyway (this vault was never converted to a shared
  // vault, so this browser holds no vault key to wrap).
  await page.getByTestId("recovery-generate").click();
  await expect(page.getByTestId("recovery-covers-nothing")).toContainText(
    "This kit covers NOTHING",
    { timeout: T },
  );
  await expect(page.getByTestId("recovery-covered")).toHaveText("NONE");
});
