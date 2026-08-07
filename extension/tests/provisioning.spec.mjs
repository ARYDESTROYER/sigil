// provisioning.spec.mjs — ⭐⭐ THE PROVISIONING BOUNDS, PROVEN THROUGH THE REAL
// UNPACKED EXTENSION — not through the module.
//
// ⛔ WHY THIS FILE EXISTS, AND IT IS THE SAME REASON `schema.spec.mjs` EXISTS.
// Phase 63 bounded the `otpauth://`, migration and QR doors and shipped a
// cross-language module test for them — and left the ADD-BY-FORM door in both
// browsers as `type="number" min="1"` with NO max, reproducing the exact defect
// the phase opened with: a period of 4294967295 makes a "one-time" password
// whose code NEVER CHANGES (measured: 755224 at t=59, at t=1.9e9 and at t=4e9),
// shown with an ordinary-looking countdown. `digits` was bounded here (min=6
// max=10); `period` was not. The MODULE was guarded and the PRODUCT was not,
// which is entry #10 of docs/engineering-lessons.md happening again.
//
// ⭐ SO EVERY ASSERTION HERE DRIVES THE SHIPPING POPUP, and the ones about what
// was stored DECRYPT WHAT THE EXTENSION ACTUALLY WROTE rather than reading the
// DOM.
//
// Three separate claims, deliberately not merged:
//
//   1. THE FORM REFUSES an out-of-bounds period, through the same
//      `validateProvisioning` the URI / migration / QR doors use — and still
//      accepts the ceiling itself, so the fix did not break the product.
//   2. THE READ PATH TELLS THE TRUTH about an entry that is ALREADY frozen. The
//      ceiling is deliberately NOT retroactive (ADR 0047's rule), and it
//      deliberately does not cover a Phase 61 vault MERGE, so such an entry can
//      still be in front of a user — and it used to wear a normal countdown.
//   3. THE SIZE WARNING FIRES AT IMPORT, not at the moment sync breaks: the
//      512-account provisioning ceiling permits a vault that does NOT FIT in
//      sigild's 64 KiB op body, and nothing can shrink one afterwards
//      (tombstones are never pruned; there is no `compact`).
//
// Pre-audit / UNAUDITED / DEV. No server is involved; the 413 half is sigild's.

import { test, expect, chromium } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import * as nodeWasm from "../../sigil-wasm/pkg-node/sigil_wasm.js";
import {
  openVault,
  sealVault,
  containerParams,
  bytesToBase64,
  base64ToBytes,
  MAX_OP_BODY_BYTES,
} from "../../sigil-wasm/totp-vault.mjs";
import {
  encodeMigrationUri,
  MAX_PERIOD,
  MAX_PROVISIONING_ENTRIES,
} from "../../sigil-wasm/totp-migration.mjs";

const EXT_DIR = path.dirname(fileURLToPath(new URL("../package.json", import.meta.url)));

// The PUBLIC RFC 6238 SHA-1 test seed. Not a secret; never a real credential.
const RFC_SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PINNED_T = 59;
const RFC_CODE_6 = "287082";
const PASSWORD = "provisioning-spec-password";
const STORAGE_KEY = "sigil.extension.vault.v1";
// The live defect's value: floor(now / 2^32-1) is 0 until roughly the year 2106.
const FROZEN_PERIOD = 4294967295;

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
  const userDataDir = await mkdtemp(path.join(tmpdir(), "sigil-ext-provisioning-"));
  context = await chromium.launchPersistentContext(userDataDir, {
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

// ⭐ Each spec gets its OWN profile-level vault by clearing storage first, so the
// four are independent in either order.
async function openPopup({ fresh = false } = {}) {
  const page = await context.newPage();
  const failures = [];
  page.on("pageerror", (e) => failures.push(String(e)));
  await page.goto(`chrome-extension://${id}/src/popup/popup.html?t=${PINNED_T}`);
  await expect(page.locator("body")).toHaveAttribute("data-wasm", /.+/, { timeout: 30_000 });
  if (fresh) {
    await page.evaluate(async () => {
      await chrome.storage.local.clear();
    });
    await page.reload();
    await expect(page.locator("body")).toHaveAttribute("data-wasm", /.+/, { timeout: 30_000 });
  }
  return { page, failures };
}

async function createVault(page) {
  await expect(page.getByTestId("view-setup")).toBeVisible();
  await page.getByTestId("setup-password").fill(PASSWORD);
  await page.getByTestId("setup-password-2").fill(PASSWORD);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("view-unlocked")).toBeVisible({ timeout: 30_000 });
}

async function unlock(page) {
  await page.getByTestId("unlock-password").fill(PASSWORD);
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("view-unlocked")).toBeVisible({ timeout: 30_000 });
}

async function readStored(page) {
  const b64 = await page.evaluate(
    async (k) => (await chrome.storage.local.get(k))[k] ?? null,
    STORAGE_KEY,
  );
  expect(b64, "the popup must have persisted a sealed vault").toBeTruthy();
  return base64ToBytes(b64);
}

async function writeStored(page, bytes) {
  await page.evaluate(
    async ([k, v]) => {
      await chrome.storage.local.set({ [k]: v });
    },
    [STORAGE_KEY, bytesToBase64(bytes)],
  );
}

function decrypt(container) {
  return openVault(nodeWasm, PASSWORD, container);
}

function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

async function addByForm(page, label, period) {
  await page.getByTestId("add-toggle").click();
  await page.getByTestId("add-label").fill(label);
  await page.getByTestId("add-secret").fill(RFC_SEED);
  await page.getByTestId("add-period").fill(String(period));
  await page.getByTestId("add-submit").click();
}

// ────────────────────────────────────────────────────────────────────────────

test("⛔ the add-by-form period box cannot create a frozen entry", async () => {
  const { page, failures } = await openPopup({ fresh: true });
  await createVault(page);
  const before = await page.evaluate(
    async (k) => (await chrome.storage.local.get(k))[k] ?? null,
    STORAGE_KEY,
  );

  await addByForm(page, "attacked", FROZEN_PERIOD);

  // ⭐ The user is TOLD, and told the real reason — not silently refused behind a
  // native browser tooltip, which is why the form carries `novalidate` and the
  // JS gate is the control.
  const status = page.getByTestId("status");
  await expect(status).toHaveAttribute("data-kind", "error", { timeout: 30_000 });
  await expect(status).toContainText("does not rotate");
  await expect(status).toContainText(String(MAX_PERIOD));

  // ⭐ AND NOTHING WAS WRITTEN. "No row in the list" is not the claim; the sealed
  // container being byte-identical is.
  await expect(page.getByTestId("account")).toHaveCount(0);
  expect(
    await page.evaluate(async (k) => (await chrome.storage.local.get(k))[k] ?? null, STORAGE_KEY),
  ).toBe(before);

  // ⚠️ The affordance must come from the SAME constant — a hand-written `600` in
  // the markup would be a fourth copy nobody guards.
  await expect(page.getByTestId("add-period")).toHaveAttribute("max", String(MAX_PERIOD));
  expect(failures).toEqual([]);
  await page.close();
});

test("...and the ceiling itself is still accepted — the product was not broken to make it safe", async () => {
  const { page, failures } = await openPopup({ fresh: true });
  await createVault(page);
  await addByForm(page, "at-the-ceiling", MAX_PERIOD);
  await expect(page.getByTestId("account")).toHaveCount(1, { timeout: 30_000 });

  const v = decrypt(await readStored(page));
  expect(v.entries).toHaveLength(1);
  expect(v.entries[0].period).toBe(MAX_PERIOD);
  expect(v.entries[0].label).toBe("at-the-ceiling");
  expect(failures).toEqual([]);
  await page.close();
});

test("⛔ an entry that is ALREADY frozen is not rendered with an ordinary countdown", async () => {
  const first = await openPopup({ fresh: true });
  await createVault(first.page);
  await addByForm(first.page, "ordinary", 30);
  await expect(first.page.getByTestId("code")).toHaveText(RFC_CODE_6, { timeout: 30_000 });

  // Seed a frozen entry beside it. This is exactly the state a pre-Phase-63
  // vault is in — and the state a Phase 61 MERGE from a co-owner produces, since
  // the merge deliberately adopts a peer's entries unchecked (gating a merge
  // would mean refusing to READ, the data-loss direction ADR 0049 exists to
  // repair).
  const original = await readStored(first.page);
  const params = containerParams(nodeWasm, original);
  const seeded = decrypt(original);
  seeded.entries.push({
    label: "from-a-peer",
    secret: "AAAAAAAAAAAAAAAA",
    algorithm: "sha1",
    digits: 6,
    period: FROZEN_PERIOD,
    uuid: "11111111-2222-4333-8444-555555555555",
  });
  await writeStored(
    first.page,
    sealVault(
      nodeWasm,
      PASSWORD,
      seeded,
      randomBytes(nodeWasm.recommended_salt_len()),
      randomBytes(nodeWasm.nonce_len()),
      params,
    ),
  );
  expect(first.failures).toEqual([]);
  await first.page.close();

  const { page, failures } = await openPopup();
  await expect(page.getByTestId("view-locked")).toBeVisible();
  await unlock(page);
  await expect(page.getByTestId("account")).toHaveCount(2, { timeout: 30_000 });

  // ⛔ IT REPORTS AND NEVER CORRECTS: the entry is still listed and still
  // generates. Refusing to render it would delete a working account to punish
  // the user for a value we let in.
  const warn = page.getByTestId("frozen-warning");
  await expect(warn).toHaveCount(1, { timeout: 30_000 });
  await expect(warn).toContainText("does not rotate");
  await expect(warn).toContainText("re-enrol");
  expect(failures).toEqual([]);
  await page.close();
});

test("⛔ an import that fills the provisioning ceiling warns that the vault will not sync", async () => {
  const { page, failures } = await openPopup({ fresh: true });
  await createVault(page);
  await expect(page.getByTestId("vault-size-warning")).toBeHidden();

  // ⭐ EXACTLY the number the Phase 63 provisioning ceiling PERMITS. That is the
  // point of this spec: one bound allows a payload the other bound cannot carry,
  // and the user must hear about it while they still have the old app in front
  // of them rather than at the moment `push` starts answering 413.
  const entries = Array.from({ length: MAX_PROVISIONING_ENTRIES }, (_, i) => ({
    label: `user${i}@example.com`,
    issuer: "Example",
    secret: "MFRGGZDFMZTWQ2LK",
    algorithm: "sha1",
    digits: 6,
    period: 30,
  }));

  // The migration form lives inside the same collapsed "Add an account" panel.
  await page.getByTestId("add-toggle").click();
  await page.getByTestId("migration-input").fill(encodeMigrationUri(entries));
  await page.getByTestId("migration-submit").click();
  await expect(page.getByTestId("status")).toContainText(
    `Imported ${MAX_PROVISIONING_ENTRIES}`,
    { timeout: 60_000 },
  );

  const warn = page.getByTestId("vault-size-warning");
  await expect(warn).toBeVisible({ timeout: 30_000 });
  await expect(warn).toContainText(String(MAX_OP_BODY_BYTES));

  // The warning must be TRUE: measure the container the extension actually wrote.
  const sealed = await readStored(page);
  expect(sealed.length).toBeGreaterThan(MAX_OP_BODY_BYTES);
  expect(failures).toEqual([]);
  await page.close();

  // ⭐ AND IT SURVIVES A RELOAD/UNLOCK. A vault imported on another client and
  // pulled here would otherwise stay silent until the user added something.
  const again = await openPopup();
  await unlock(again.page);
  await expect(again.page.getByTestId("vault-size-warning")).toBeVisible({ timeout: 30_000 });
  expect(again.failures).toEqual([]);
  await again.page.close();
});
