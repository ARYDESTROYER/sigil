// extension.spec.mjs — headless proof that the REAL MV3 extension runs.
//
// This does NOT stub chrome.* or serve the popup as a plain page: it launches a
// real Chromium with the unpacked extension loaded and drives
// chrome-extension://<id>/src/popup/popup.html. Everything in the assertions
// therefore went through the actual extension runtime: the MV3 CSP
// ('wasm-unsafe-eval'), the real chrome.storage.local, and the libsigil wasm
// instantiated inside the extension page.
//
// The clock is pinned with the ?t= TEST HOOK so the code is deterministic:
// RFC 6238 Appendix B, T = 59 s, SHA-1, period 30 -> 8-digit 94287082, whose
// 6-digit form (what this UI defaults to) is 287082.
//
// Pre-audit / UNAUDITED / DEV.

import { test, expect, chromium } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const EXT_DIR = path.dirname(fileURLToPath(new URL("../package.json", import.meta.url)));

/** RFC 6238 Appendix B test seed ("12345678901234567890" in base32). PUBLIC. */
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PINNED_T = 59;
const RFC_CODE_6 = "287082"; // low 6 digits of the RFC's 8-digit 94287082
const PASSWORD = "correct horse battery staple";

/**
 * Derive the extension ID from the `key` pinned in manifest.json (Chrome's rule:
 * first 16 bytes of SHA-256 over the DER public key, hex mapped 0-f -> a-p).
 * Without a background service worker there is no target to read the ID from, so
 * pinning it in the manifest is what makes the popup URL addressable.
 */
async function extensionId() {
  const manifest = JSON.parse(await readFile(path.join(EXT_DIR, "manifest.json"), "utf8"));
  const der = Buffer.from(manifest.key, "base64");
  const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

let context;
let id;

test.beforeAll(async () => {
  id = await extensionId();
  const userDataDir = await mkdtemp(path.join(tmpdir(), "sigil-ext-"));
  context = await chromium.launchPersistentContext(userDataDir, {
    // The headless SHELL cannot load extensions; `channel: "chromium"` is the
    // full browser, whose new headless mode can.
    channel: "chromium",
    headless: true,
    args: [`--disable-extensions-except=${EXT_DIR}`, `--load-extension=${EXT_DIR}`],
  });
  context.__userDataDir = userDataDir;
});

test.afterAll(async () => {
  const dir = context?.__userDataDir;
  await context?.close();
  if (dir) await rm(dir, { recursive: true, force: true });
});

/** Open the popup as a real extension page with the clock pinned. */
async function openPopup() {
  const page = await context.newPage();
  const failures = [];
  page.on("pageerror", (e) => failures.push(String(e)));
  await page.goto(`chrome-extension://${id}/src/popup/popup.html?t=${PINNED_T}`);
  return { page, failures };
}

test("the real extension popup runs the wasm and generates the RFC 6238 code", async () => {
  const { page, failures } = await openPopup();

  // The page really is the extension (not a file:// or http:// stand-in).
  expect(page.url().startsWith(`chrome-extension://${id}/`)).toBe(true);

  // The wasm instantiated INSIDE the extension page under the MV3 CSP: boot()
  // stamps the core version on <body> only after init() resolves.
  await expect(page.locator("body")).toHaveAttribute("data-wasm", /.+/, { timeout: 30_000 });

  // The loud pre-audit banner is present.
  await expect(page.getByTestId("banner")).toContainText("UNAUDITED");

  // 1. setup -> create a vault (password stays in memory; only the sealed
  //    container is written to chrome.storage.local).
  await expect(page.getByTestId("view-setup")).toBeVisible();
  await page.getByTestId("setup-password").fill(PASSWORD);
  await page.getByTestId("setup-password-2").fill(PASSWORD);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("view-unlocked")).toBeVisible({ timeout: 30_000 });

  // 2. add the RFC 6238 account from its base32 secret (defaults: SHA-1/6/30).
  await page.getByTestId("add-toggle").click();
  await page.getByTestId("add-label").fill("rfc6238");
  await page.getByTestId("add-issuer").fill("Sigil Test");
  await page.getByTestId("add-secret").fill(RFC_SECRET);
  await page.getByTestId("add-submit").click();

  // 3. THE ASSERTION: the displayed, wasm-computed code equals the RFC vector
  //    for the pinned instant.
  await expect(page.getByTestId("account")).toHaveCount(1);
  await expect(page.getByTestId("code")).toHaveText(RFC_CODE_6);
  await expect(page.getByTestId("countdown")).toHaveText("1s"); // 30 - (59 % 30)

  // Only the SEALED container reached storage: no plaintext secret, no password.
  const stored = await page.evaluate(async () => {
    const all = await chrome.storage.local.get(null);
    return { keys: Object.keys(all), blob: JSON.stringify(all) };
  });
  expect(stored.keys).toEqual(["sigil.extension.vault.v1"]);
  expect(stored.blob).not.toContain(RFC_SECRET);
  expect(stored.blob).not.toContain(PASSWORD);
  expect(stored.blob).not.toContain("rfc6238");

  expect(failures).toEqual([]);
  await page.close();
});

test("a reload re-locks, and unlocking restores the persisted vault", async () => {
  const { page, failures } = await openPopup();
  await expect(page.locator("body")).toHaveAttribute("data-wasm", /.+/, { timeout: 30_000 });

  // A fresh popup finds the sealed container in chrome.storage.local and boots
  // straight into the LOCKED view (the password was never persisted).
  await expect(page.getByTestId("view-locked")).toBeVisible();
  await expect(page.getByTestId("view-unlocked")).toBeHidden();

  // A wrong password must not open it.
  await page.getByTestId("unlock-password").fill("not the password");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("status")).toContainText("Could not unlock", { timeout: 30_000 });
  await expect(page.getByTestId("view-unlocked")).toBeHidden();

  // The right password restores the account, and the code is still the RFC one.
  await page.getByTestId("unlock-password").fill(PASSWORD);
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("view-unlocked")).toBeVisible({ timeout: 30_000 });
  await expect(page.getByTestId("account")).toHaveCount(1);
  await expect(page.getByTestId("account")).toContainText("Sigil Test");
  await expect(page.getByTestId("code")).toHaveText(RFC_CODE_6);

  // Lock returns to the locked view and clears the rendered codes.
  await page.getByTestId("lock").click();
  await expect(page.getByTestId("view-locked")).toBeVisible();
  await expect(page.getByTestId("code")).toHaveCount(0);

  expect(failures).toEqual([]);
  await page.close();
});

test("otpauth:// and Google Authenticator migration imports work in the popup", async () => {
  const { page, failures } = await openPopup();
  await expect(page.locator("body")).toHaveAttribute("data-wasm", /.+/, { timeout: 30_000 });

  await page.getByTestId("unlock-password").fill(PASSWORD);
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("view-unlocked")).toBeVisible({ timeout: 30_000 });

  // otpauth:// import — same RFC seed under a different label, so the code is a
  // second independent check of the vector through the URI path.
  await page.getByTestId("add-toggle").click();
  await page
    .getByTestId("uri-input")
    .fill(`otpauth://totp/Example:alice@example.com?secret=${RFC_SECRET}&issuer=Example`);
  await page.getByTestId("uri-submit").click();
  await expect(page.getByTestId("account")).toHaveCount(2);
  await expect(page.locator('[data-label="alice@example.com"] .code')).toHaveText(RFC_CODE_6);

  // Round-trip the vault OUT as one otpauth-migration:// URI and back IN: the
  // export path and the Google Authenticator import path are the same codec the
  // CLI uses (totp-migration.mjs, vendored verbatim).
  await page.getByTestId("export-toggle").click();
  await page.getByTestId("export-migration").click();
  const migrationUri = await page.getByTestId("export-out").inputValue();
  expect(migrationUri.startsWith("otpauth-migration://offline?data=")).toBe(true);

  // Re-importing is a no-op (duplicate labels are skipped), which proves the
  // encode/decode agree on the labels.
  await page.getByTestId("migration-input").fill(migrationUri);
  await page.getByTestId("migration-submit").click();
  await expect(page.getByTestId("status")).toContainText("Imported 0 of 2");
  await expect(page.getByTestId("account")).toHaveCount(2);

  // Remove one; the vault re-seals and the row disappears.
  await page.locator('[data-label="alice@example.com"] [data-testid="remove"]').click();
  // ⛔ Remove now OPENS A CONFIRMATION rather than deleting: a removal writes a
  // PROPAGATING, resurrection-proof tombstone (ADR 0049 §3), so a mis-click on a
  // button inches from the code is permanent. Confirm it — this spec is about the
  // merge/schema/import, not about the gate.
  await page.locator('[data-label="alice@example.com"] [data-testid="remove-confirm-yes"]').click();
  await expect(page.getByTestId("account")).toHaveCount(1);

  expect(failures).toEqual([]);
  await page.close();
});
