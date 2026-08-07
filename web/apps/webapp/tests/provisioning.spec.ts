import { expect, test, type Page } from "@playwright/test";
// @ts-expect-error — the Node-target wasm package (gitignored build output of
// sigil-wasm/build-wasm.sh). The TEST process needs it to seal/open what the app
// stores; the APP uses the bundler-target package instead.
import * as nodeWasm from "../../../../sigil-wasm/pkg-node/sigil_wasm.js";
import {
  openVault,
  sealVault,
  bytesToBase64,
  base64ToBytes,
  MAX_OP_BODY_BYTES,
  // @ts-expect-error — plain .mjs, no bundled types.
} from "../../../../sigil-wasm/totp-vault.mjs";
import {
  encodeMigrationUri,
  MAX_PERIOD,
  MAX_PROVISIONING_ENTRIES,
  // @ts-expect-error — plain .mjs, no bundled types.
} from "../../../../sigil-wasm/totp-migration.mjs";

/**
 * ⭐⭐ THE PROVISIONING BOUNDS, PROVEN THROUGH THE REAL APP — not the module.
 *
 * ⛔ WHY THIS FILE EXISTS, AND IT IS THE SAME REASON `schema.spec.ts` EXISTS.
 * Phase 63 bounded the `otpauth://`, migration and QR doors and shipped a
 * cross-language module test for them — and left the ADD-BY-FORM door in both
 * browsers as `type="number" min="1"` with NO max, reproducing the exact defect
 * the phase opened with: a period of 4294967295 makes a "one-time" password
 * whose code NEVER CHANGES (measured: 755224 at t=59, at t=1.9e9 and at t=4e9),
 * rendered with an ordinary-looking countdown. `digits` was bounded; `period`
 * was not. The module was guarded and the PRODUCT was not — entry #10 of
 * docs/engineering-lessons.md, again.
 *
 * ⭐ SO EVERY ASSERTION HERE DRIVES THE SHIPPING UI, and the ones about what was
 * stored DECRYPT WHAT THE APP ACTUALLY WROTE rather than reading the DOM.
 *
 * Three separate claims, deliberately not merged:
 *
 *   1. THE FORM REFUSES an out-of-bounds period, through the same
 *      `validateProvisioning` the URI / migration / QR doors use — and still
 *      accepts the ceiling itself, so the fix did not break the product to make
 *      it safe.
 *   2. THE READ PATH TELLS THE TRUTH about an entry that is ALREADY frozen. The
 *      ceiling is deliberately NOT retroactive (ADR 0047's rule: bound what a
 *      stranger may CREATE, never what a user already HAS), and it deliberately
 *      does not cover a Phase 61 vault MERGE — so such an entry can still be in
 *      front of a user, and until now it wore a normal countdown ring.
 *   3. THE SIZE WARNING FIRES AT IMPORT, not at the moment sync breaks. The
 *      512-account provisioning ceiling permits a vault that does NOT FIT in
 *      sigild's 64 KiB op body, and there is no way to shrink one afterwards
 *      (tombstones are never pruned; there is no `compact`).
 *
 * ⚠️ These run against no server at all — nothing here needs one. The 413 half
 * is `sigild`'s and is covered by the Rust/Go suites.
 */

const T = 120_000;
const PASSWORD = "provisioning-spec-password";
const STORAGE_KEY = "sigil.webapp.vault.v1";
// The PUBLIC RFC 6238 SHA-1 test seed. Not a secret; never a real credential.
const RFC_SEED_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_CODE = "287082";
// The live defect's value: floor(now / 2^32-1) is 0 until roughly the year 2106.
const FROZEN_PERIOD = 4294967295;

type Vault = { version: number; entries: Record<string, unknown>[]; [k: string]: unknown };

async function createVault(page: Page) {
  await page.goto("/?t=59");
  await page.getByTestId("setup-password").fill(PASSWORD);
  await page.getByTestId("setup-confirm").fill(PASSWORD);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
}

async function storedBytes(page: Page): Promise<Uint8Array> {
  const b64 = await page.evaluate((k) => window.localStorage.getItem(k), STORAGE_KEY);
  expect(b64, "the app must have persisted a sealed vault").toBeTruthy();
  return base64ToBytes(b64!);
}

/** Decrypt what the app actually wrote, in the TEST process. */
async function storedVault(page: Page): Promise<Vault> {
  return openVault(nodeWasm, PASSWORD, await storedBytes(page)) as Vault;
}

/** Overwrite the app's sealed container with `vault`, sealed in THIS process. */
async function seed(page: Page, vault: Vault) {
  const salt = crypto.getRandomValues(new Uint8Array(nodeWasm.recommended_salt_len()));
  const nonce = crypto.getRandomValues(new Uint8Array(nodeWasm.nonce_len()));
  const bytes: Uint8Array = sealVault(nodeWasm, PASSWORD, vault, salt, nonce, {
    m_cost: 19456,
    t_cost: 2,
    p_cost: 1,
  });
  await page.evaluate(
    ([k, v]) => window.localStorage.setItem(k as string, v as string),
    [STORAGE_KEY, bytesToBase64(bytes)],
  );
}

async function reopen(page: Page) {
  await page.reload();
  await expect(page.getByTestId("unlock-password")).toBeVisible({ timeout: T });
  await page.getByTestId("unlock-password").fill(PASSWORD);
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
}

async function fillAddForm(page: Page, label: string, period: number) {
  await page.getByTestId("add-label").fill(label);
  await page.getByTestId("add-secret").fill(RFC_SEED_B32);
  await page.getByTestId("add-period").fill(String(period));
  await page.getByTestId("add-submit").click();
}

// ─────────────────────────────────────────────────────────────────────────────

test("⛔ the add-by-form period box cannot create a frozen entry", async ({ page }) => {
  await createVault(page);
  const before = await page.evaluate((k) => window.localStorage.getItem(k), STORAGE_KEY);

  await fillAddForm(page, "attacked", FROZEN_PERIOD);

  // ⭐ The user is TOLD, and told the real reason — not silently refused behind a
  // native browser tooltip, which is why the form carries `noValidate` and the
  // JS gate is the control.
  const err = page.getByTestId("add-error");
  await expect(err).toBeVisible({ timeout: T });
  await expect(err).toContainText("does not rotate");
  await expect(err).toContainText(String(MAX_PERIOD));

  // ⭐ AND NOTHING WAS WRITTEN. The DOM saying "no account" is not the claim;
  // the sealed container being byte-identical is.
  await expect(page.getByTestId("account-row")).toHaveCount(0);
  expect(await page.evaluate((k) => window.localStorage.getItem(k), STORAGE_KEY)).toBe(before);

  // ⚠️ The affordance must come from the SAME constant, so a fourth hand-written
  // `600` cannot appear in markup and then drift.
  await expect(page.getByTestId("add-period")).toHaveAttribute("max", String(MAX_PERIOD));
});

test("...and the ceiling itself is still accepted — the product was not broken to make it safe", async ({
  page,
}) => {
  await createVault(page);
  await fillAddForm(page, "at-the-ceiling", MAX_PERIOD);
  await expect(page.getByTestId("account-row")).toHaveCount(1, { timeout: T });

  const v = await storedVault(page);
  expect(v.entries).toHaveLength(1);
  expect(v.entries[0].period).toBe(MAX_PERIOD);
  expect(v.entries[0].label).toBe("at-the-ceiling");
});

test("⛔ an entry that is ALREADY frozen is not rendered with an ordinary countdown", async ({
  page,
}) => {
  await createVault(page);
  // An ordinary account first, so the warning can be shown to be SELECTIVE.
  await fillAddForm(page, "ordinary", 30);
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });

  // Seed a frozen entry beside it. This is exactly the state a pre-Phase-63
  // vault is in — and the state a Phase 61 MERGE from a co-owner produces, since
  // the merge deliberately adopts a peer's entries unchecked (gating a merge
  // would mean refusing to READ, which is the data-loss direction ADR 0049 was
  // written to repair).
  const v = await storedVault(page);
  v.entries.push({
    label: "from-a-peer",
    secret: "AAAAAAAAAAAAAAAA",
    algorithm: "sha1",
    digits: 6,
    period: FROZEN_PERIOD,
    uuid: "11111111-2222-4333-8444-555555555555",
  });
  await seed(page, v);
  await reopen(page);

  await expect(page.getByTestId("account-row")).toHaveCount(2, { timeout: T });
  // ⛔ IT REPORTS AND NEVER CORRECTS: the entry is still listed and still
  // generates. Refusing to render it would delete a working account to punish
  // the user for a value we let in.
  const warn = page.getByTestId("frozen-warning");
  await expect(warn).toHaveCount(1, { timeout: T });
  await expect(warn).toContainText("does not rotate");
  await expect(warn).toContainText("re-enrol");
  // The ordinary account is untouched and unwarned.
  await expect(page.getByTestId("account-code").first()).toHaveText(RFC_CODE);
});

test("⛔ an import that fills the provisioning ceiling warns that the vault will not sync", async ({
  page,
}) => {
  await createVault(page);
  await expect(page.getByTestId("vault-size-warning")).toHaveCount(0);

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
  const uri: string = encodeMigrationUri(entries);

  await page.getByTestId("migration-input").fill(uri);
  await page.getByTestId("migration-submit").click();
  await expect(page.getByTestId("import-result")).toContainText(
    `Imported ${MAX_PROVISIONING_ENTRIES}`,
    { timeout: T },
  );

  const warn = page.getByTestId("vault-size-warning");
  await expect(warn).toBeVisible({ timeout: T });
  await expect(warn).toContainText(String(MAX_OP_BODY_BYTES));

  // The warning must be true: measure the container the app actually wrote.
  const sealed = await storedBytes(page);
  expect(sealed.length).toBeGreaterThan(MAX_OP_BODY_BYTES);

  // ⭐ AND IT SURVIVES A RELOAD. A vault imported on another client and pulled
  // here would otherwise stay silent until the user happened to add something.
  await reopen(page);
  await expect(page.getByTestId("vault-size-warning")).toBeVisible({ timeout: T });
});
