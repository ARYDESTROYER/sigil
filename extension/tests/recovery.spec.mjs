// recovery.spec.mjs — the recovery kit in the REAL unpacked MV3 extension.
//
// ⭐ THE POINT OF THIS FILE is the second half: after a kit is generated on one
// browser profile, it is redeemed on a SECOND, COMPLETELY CLEAN profile — a
// fresh `chrome.storage.local`, no vault, no device identity, no pin store. That
// is the situation a customer who lost every device is actually in, and until
// this phase the extension could not serve it at all (it vendored recovery.mjs
// and exposed nothing).
//
// The server here is a FAKE (sigil-wasm/test/fake-sigild.mjs): it verifies no
// signatures and enforces no authorization, and proves nothing about sigild.
// Everything CRYPTOGRAPHIC is still real and still happens in the extension's
// own wasm: the HKDF derivation from the printed code, the hybrid wrap and
// unwrap, the Argon2id sealing, and the TOTP code. Protocol conformance against
// a live sigild is proven in sigil-wasm/test/recovery-interop.mjs and
// cli/tests/e2e-recovery.sh.
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
const PINNED_T = 59;
const RFC_CODE_6 = "287082";
const VAULT_ID = "ext-recovery-demo";

async function extensionId() {
  const manifest = JSON.parse(await readFile(path.join(EXT_DIR, "manifest.json"), "utf8"));
  const der = Buffer.from(manifest.key, "base64");
  const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

/** Launch a browser profile with the real unpacked extension loaded. */
async function launchProfile() {
  const userDataDir = await mkdtemp(path.join(tmpdir(), "sigil-ext-recovery-"));
  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: "chromium",
    headless: true,
    args: [`--disable-extensions-except=${EXT_DIR}`, `--load-extension=${EXT_DIR}`],
  });
  return { context, userDataDir };
}

let fake;
let id;
let kitCode = "";
let kitDeviceId = "";

test.beforeAll(async () => {
  id = await extensionId();
  fake = await startFakeSigild();
});

test.afterAll(async () => {
  await fake?.close();
});

async function openPopup(context) {
  const page = await context.newPage();
  const failures = [];
  page.on("pageerror", (e) => failures.push(String(e)));
  await page.goto(`chrome-extension://${id}/src/popup/popup.html?t=${PINNED_T}`);
  await expect(page.locator("body")).toHaveAttribute("data-wasm", /.+/, { timeout: 30_000 });
  return { page, failures };
}

test("profile 1: generate a recovery kit that covers a real vault", async () => {
  const { context, userDataDir } = await launchProfile();
  try {
    const { page, failures } = await openPopup(context);

    // A vault with one account whose code is the RFC 6238 vector.
    await expect(page.getByTestId("view-setup")).toBeVisible();
    await page.getByTestId("setup-password").fill("profile-one-password");
    await page.getByTestId("setup-password-2").fill("profile-one-password");
    await page.getByTestId("setup-submit").click();
    await expect(page.getByTestId("view-unlocked")).toBeVisible({ timeout: 30_000 });

    await page.getByTestId("add-toggle").click();
    await page.getByTestId("add-label").fill("rfc6238");
    await page.getByTestId("add-secret").fill(RFC_SECRET);
    await page.getByTestId("add-submit").click();
    await expect(page.getByTestId("code")).toHaveText(RFC_CODE_6);

    // Enrol against the fake dev server.
    await page.getByTestId("sync-toggle").click();
    await page.getByTestId("sync-url").fill(fake.baseUrl);
    await page.getByTestId("sync-vault").fill(VAULT_ID);
    await page.getByTestId("device-token").fill("operator-token-0123456789abcdef");
    await page.getByTestId("device-enroll").click();
    await expect(page.getByTestId("status")).toContainText("Enrolled as", { timeout: 30_000 });

    // A kit can only be handed a vault KEY, so the vault must be a SHARED vault:
    // a personal vault is sealed with the human password, which is never shared,
    // never wrapped and never sent.
    await page.getByTestId("sharing-toggle").click();
    await page.getByTestId("sharing-convert").click();
    await expect(page.getByTestId("status")).toContainText("random 32-byte vault key", {
      timeout: 30_000,
    });

    // Push, so there is ciphertext to come back to. A kit recovers KEYS, not DATA.
    await page.getByTestId("sync-push").click();
    await expect(page.getByTestId("status")).toContainText("Pushed sealed container", {
      timeout: 30_000,
    });

    // ── generate ─────────────────────────────────────────────────────────────
    await page.getByTestId("recovery-toggle").click();
    await page.getByTestId("recovery-generate").click();
    await expect(page.getByTestId("recovery-sheet")).toBeVisible({ timeout: 60_000 });

    kitCode = ((await page.getByTestId("recovery-code").textContent()) ?? "").trim();
    kitDeviceId = ((await page.getByTestId("recovery-kit-id").textContent()) ?? "").trim();
    expect(kitCode.split("-")).toHaveLength(7);
    expect(kitCode.replace(/-/g, "")).toHaveLength(56);
    expect(kitDeviceId).toMatch(/^dev_/);

    // The sheet carries the safety number, the coverage AS OF TODAY, and the
    // warnings — including that holding the paper is holding the account.
    await expect(page.getByTestId("recovery-safety-number")).toHaveText(/\d{5}( \d{5}){5}/);
    await expect(page.getByTestId("recovery-covered")).toContainText(VAULT_ID);
    await expect(page.getByTestId("recovery-sheet")).toContainText("FULL CONTROL OF THE ACCOUNT");
    await expect(page.getByTestId("recovery-sheet")).toContainText("NEVER PHOTOGRAPH IT");
    await expect(page.getByTestId("recovery-sheet")).toContainText("RECOVERS KEYS, NOT DATA");
    await expect(page.getByTestId("recovery-covers-nothing")).toBeHidden();

    // ⭐ THE CODE IS A CREDENTIAL: storage still holds exactly the two sealed
    // containers, and the code is in neither of them.
    const stored = await page.evaluate(async () => {
      const all = await chrome.storage.local.get(null);
      return { keys: Object.keys(all).sort(), blob: JSON.stringify(all) };
    });
    expect(stored.keys).toEqual(["sigil.extension.device.v1", "sigil.extension.vault.v1"]);
    expect(stored.blob).not.toContain(kitCode);
    expect(stored.blob).not.toContain(kitCode.replace(/-/g, ""));
    expect(stored.blob).not.toContain("profile-one-password");
    expect(page.url()).not.toContain(kitCode.slice(0, 8));

    // COVER from the browser that printed the kit takes the DERIVED path: the
    // key was never fetched, so nothing could have been substituted.
    await page.getByTestId("recovery-cover-kit").fill(kitDeviceId);
    await page.getByTestId("recovery-cover").click();
    await expect(page.getByTestId("status")).toContainText("derived locally", { timeout: 30_000 });

    // CHECK reports set-up + coverage.
    await page.getByTestId("recovery-check").click();
    await expect(page.getByTestId("recovery-coverage")).toContainText("1 kit(s) enrolled", {
      timeout: 30_000,
    });
    await expect(page.getByTestId("recovery-coverage")).toContainText(`covered by ${kitDeviceId}`);

    // Confirming clears the code from the DOM; it cannot be shown again.
    await page.getByTestId("recovery-written").check();
    await page.getByTestId("recovery-hide").click();
    await expect(page.getByTestId("recovery-sheet")).toBeHidden();
    expect(await page.getByTestId("recovery-code").textContent()).toBe("");

    expect(failures).toEqual([]);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});

test("profile 2: RESTORE on a completely clean profile", async () => {
  expect(kitCode).not.toBe("");
  const { context, userDataDir } = await launchProfile();
  try {
    const { page, failures } = await openPopup(context);

    // It really is a fresh install: no stored vault, so the popup boots into
    // SETUP — and the restore panel is right there beside it.
    await expect(page.getByTestId("view-setup")).toBeVisible();
    await expect(page.getByTestId("view-restore")).toBeVisible();
    expect(
      await page.evaluate(async () => Object.keys(await chrome.storage.local.get(null))),
    ).toEqual([]);

    await page.getByTestId("restore-toggle").click();
    await page.getByTestId("restore-url").fill(fake.baseUrl);
    await page.getByTestId("restore-device-id").fill(kitDeviceId);
    await page.getByTestId("restore-password").fill("profile-two-password");
    await page.getByTestId("restore-confirm").fill("profile-two-password");

    // A wrong code is refused OFFLINE, before anything is sent, and is named as
    // a mistyped code rather than as an auth failure. ("U" is never used.)
    const before = fake.log.length;
    await page.getByTestId("restore-code").fill("U".repeat(56));
    await page.getByTestId("restore-submit").click();
    await expect(page.getByTestId("restore-error")).toContainText("not a valid recovery code", {
      timeout: 30_000,
    });
    expect(fake.log.length).toBe(before); // nothing reached the server

    // The real code, pasted as a human would: grouped, and in lower case.
    await page.getByTestId("restore-code").fill(kitCode.toLowerCase());
    await page.getByTestId("restore-submit").click();

    // ⭐ Landed in an UNLOCKED vault, with the account back and the wasm
    // computing the RFC vector — on a profile that started completely empty.
    await expect(page.getByTestId("view-unlocked")).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId("account")).toHaveCount(1);
    await expect(page.getByTestId("code")).toHaveText(RFC_CODE_6);
    await expect(page.getByTestId("status")).toContainText("SECOND COPY OF THAT PAPER");

    // Only the two sealed containers were written, and the code is in neither.
    const stored = await page.evaluate(async () => {
      const all = await chrome.storage.local.get(null);
      return { keys: Object.keys(all).sort(), blob: JSON.stringify(all) };
    });
    expect(stored.keys).toEqual(["sigil.extension.device.v1", "sigil.extension.vault.v1"]);
    expect(stored.blob).not.toContain(kitCode);
    expect(stored.blob).not.toContain(kitCode.replace(/-/g, ""));
    expect(stored.blob).not.toContain("profile-two-password");

    // The code field was cleared the moment it worked.
    expect(await page.getByTestId("restore-code").inputValue()).toBe("");

    expect(failures).toEqual([]);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});
