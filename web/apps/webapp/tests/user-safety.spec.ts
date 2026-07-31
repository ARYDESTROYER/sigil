// user-safety.spec.ts — ⭐ THE PRODUCT-LEVEL PROOFS for three things this app
// did TO ITS USER, driven through the REAL shipping UI.
//
// ⛔ WHY IT MUST BE AT THIS LEVEL. `docs/engineering-lessons.md` entry 10: two
// Phase 59 fixes were guarded in the shared module and UNGUARDED in the shipping
// app. A verifier reverted `authenticator.tsx` and webapp 50/50 stayed GREEN,
// while mutating the same logic inside the module went red every time. Every
// assertion below therefore goes through the actual buttons in
// `app/authenticator.tsx`, so reverting THAT FILE turns this red.
//
// The three:
//
//  1. ⛔ A ONE-CLICK DELETE OF A 2FA SECRET. `onRemove` went straight to the
//     removal, from a button inches from the code the user came to read, on a
//     row that re-renders every second. And Phase 61 RAISED the stakes: a
//     removal now writes a TOMBSTONE that propagates to every device and is
//     specifically protected against resurrection (ADR 0049 §3), so a stale
//     snapshot that might once have brought the entry back by accident now
//     provably will not. Losing a 2FA secret can mean losing the account.
//
//  2. ⛔ A FALSE CAPABILITY CLAIM. The account panel told the user, in the
//     product, that "this app cannot print one" about a recovery kit — true
//     before Phase 56, false ever since, with the Generate button on the same
//     screen. That is the worst kind of documentation defect: it steers a user
//     AWAY from the single control that prevents permanent account loss.
//
//  3. NO CLOCK-SKEW DIAGNOSTIC. A code rejected because the device clock drifted
//     is indistinguishable, to the user, from a wrong secret. ⛔⛔ And the fix
//     must REPORT, never CORRECT — the codes on screen must still come from the
//     device's own clock.
//
// ⚠️ Runs against `fake-sigild.mjs`, a DOUBLE (see its header for what it is
// laxer about). Everything asserted here is browser behaviour; the server-side
// halves are proven by `sigil-wasm/test/clock-skew-interop.mjs` against a REAL
// sigild.

import { expect, test, type Page } from "@playwright/test";
// @ts-expect-error — plain .mjs test helper shared with the extension suite.
import { startFakeSigild } from "../../../../sigil-wasm/test/fake-sigild.mjs";

const T = 60_000;
/** RFC 6238 App B sha1 key, base32. At t=59 with 6 digits this is 287082. */
const RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_CODE = "287082";
const PASSWORD = "correct horse battery staple";
const WEBAPP_ORIGIN = "http://localhost:3210";

type Fake = { baseUrl: string; close: () => Promise<void> };
let fake: Fake;

test.beforeAll(async () => {
  fake = (await startFakeSigild({ corsOrigins: [WEBAPP_ORIGIN] })) as Fake;
});
test.afterAll(async () => {
  await fake?.close();
});

async function freshVault(page: Page) {
  await page.goto("/?t=59");
  await page.getByTestId("setup-password").fill(PASSWORD);
  await page.getByTestId("setup-confirm").fill(PASSWORD);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
}

async function addAccount(page: Page, label: string, issuer?: string) {
  await page.getByTestId("add-label").fill(label);
  if (issuer) await page.getByTestId("add-issuer").fill(issuer);
  await page.getByTestId("add-secret").fill(RFC_SECRET_B32);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-list")).toContainText(label, { timeout: T });
}

// ───────────────────────────────────────────────────────────────────────────
// 1. THE DELETE CONFIRMATION
// ───────────────────────────────────────────────────────────────────────────

test("⛔ Remove does NOT delete: it opens a confirmation that NAMES the account", async ({
  page,
}) => {
  await freshVault(page);
  await addAccount(page, "alice@example.com", "GitHub");
  await expect(page.getByTestId("account-count")).toHaveText("1", { timeout: T });

  // The one click that used to be the whole deletion.
  await page.getByTestId("account-remove").click();

  // ⭐ THE ACCOUNT IS STILL THERE. This is the assertion that goes red the
  // moment `onClick` is wired back to `onRemove`.
  await expect(page.getByTestId("account-count")).toHaveText("1", { timeout: T });

  const confirm = page.getByTestId("remove-confirm");
  await expect(confirm).toBeVisible({ timeout: T });
  // It must NAME what is about to be destroyed — issuer AND label, because
  // labels stopped being unique in Phase 61 and "Remove work?" cannot tell a
  // user which of two accounts they are about to lose.
  await expect(page.getByTestId("remove-confirm-who")).toHaveText("GitHub, alice@example.com");
  const warning = await page.getByTestId("remove-confirm-warning").textContent();
  expect(warning ?? "").toMatch(/permanent/i);
  // And it must say the removal PROPAGATES — the Phase 61 tombstone is why this
  // is no longer a local edit a later sync might undo.
  expect(warning ?? "").toMatch(/every other device/i);
  // ⛔ …AND IT MUST NOT PROMISE A SYNC THE PRODUCT DOES NOT PERFORM. The first
  // cut of this copy said the deletion "is synced to every other device holding
  // it". Sync here is MANUAL — explicit Push / Pull — and a vault with no server
  // configured never propagates at all, so that sentence was false in the one
  // place precision matters most. The condition must be stated.
  expect(warning ?? "").toMatch(/next time you Push/i);
  expect(warning ?? "").toMatch(/if you never sync/i);
  expect(warning ?? "").not.toMatch(/\bis synced to every other device/i);
});

test("Keep it CANCELS, and the account and its code survive untouched", async ({ page }) => {
  await freshVault(page);
  await addAccount(page, "keepme", "Acme");

  await page.getByTestId("account-remove").click();
  await expect(page.getByTestId("remove-confirm")).toBeVisible({ timeout: T });
  await page.getByTestId("remove-confirm-cancel").click();

  await expect(page.getByTestId("remove-confirm")).toHaveCount(0, { timeout: T });
  await expect(page.getByTestId("account-count")).toHaveText("1", { timeout: T });
  // Still a WORKING account, not just a surviving row.
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
});

test("Delete permanently is the ONLY thing that removes the entry", async ({ page }) => {
  await freshVault(page);
  await addAccount(page, "goodbye", "Acme");
  await addAccount(page, "stays", "Acme");
  await expect(page.getByTestId("account-count")).toHaveText("2", { timeout: T });

  // Click Remove on the row that names "goodbye". ⚠️ The row is REPLACED by the
  // confirmation while it is open, so the "has account-label goodbye" filter no
  // longer matches it — the confirmation is targeted directly, and exactly one
  // can be open at a time.
  await page
    .getByTestId("account-row")
    .filter({ has: page.getByTestId("account-label").filter({ hasText: "goodbye" }) })
    .getByTestId("account-remove")
    .click();
  await expect(page.getByTestId("remove-confirm-who")).toHaveText("Acme, goodbye");
  await page.getByTestId("remove-confirm-yes").click();

  await expect(page.getByTestId("account-count")).toHaveText("1", { timeout: T });
  await expect(page.getByTestId("account-list")).not.toContainText("goodbye", { timeout: T });
  await expect(page.getByTestId("account-list")).toContainText("stays", { timeout: T });
});

test("⭐ the confirmed delete DOES write a tombstone — the gate delays it, never skips it", async ({
  browser,
}) => {
  // ⛔ THE 2P-SET INVARIANT (ADR 0049 §3), asserted BEHAVIOURALLY rather than by
  // counting a JSON field: a removal that writes NO tombstone is the
  // pre-Phase-61 behaviour, and the entry comes straight back the next time this
  // vault meets a snapshot that still holds it. A "confirmation" that quietly
  // dropped the tombstone would pass every assertion above and silently un-fix
  // Phase 61.
  //
  // ⭐ This is also exactly why the fix is a CONFIRM and not an UNDO: an undo
  // would have to write the tombstone and retract it, which is the resurrection
  // this proves must not happen — and unretractable once another device has
  // merged it.
  const ctxA = await browser.newContext();
  const ctxB = await browser.newContext();
  const a = await ctxA.newPage();
  const b = await ctxB.newPage();
  try {
    const vaultId = `safety-tomb-${Date.now()}`;

    await freshVault(a);
    await a.getByTestId("sync-url").fill(fake.baseUrl);
    await a.getByTestId("sync-vault-id").fill(vaultId);
    await addAccount(a, "doomed", "Acme");
    await addAccount(a, "survivor", "Acme");
    // op 1 — a snapshot that STILL HOLDS `doomed`. This is the snapshot that
    // resurrects it if the delete recorded nothing.
    await a.getByTestId("sync-push").click();
    await expect(a.getByTestId("sync-status")).toContainText("Pushed", { timeout: T });

    // Delete through the real confirmation, then push op 2.
    await a
      .getByTestId("account-row")
      .filter({ has: a.getByTestId("account-label").filter({ hasText: "doomed" }) })
      .getByTestId("account-remove")
      .click();
    await a.getByTestId("remove-confirm-yes").click();
    await expect(a.getByTestId("account-count")).toHaveText("1", { timeout: T });
    await a.getByTestId("sync-push").click();
    await expect(a.getByTestId("sync-status")).toContainText("Pushed", { timeout: T });

    // A FRESH device folds BOTH ops. op1 holds `doomed`; op2 must carry a
    // tombstone that suppresses it.
    await freshVault(b);
    await b.getByTestId("sync-url").fill(fake.baseUrl);
    await b.getByTestId("sync-vault-id").fill(vaultId);
    await b.getByTestId("sync-pull").click();
    await expect(b.getByTestId("sync-status")).toContainText("Merged", { timeout: T });

    await expect(b.getByTestId("account-list")).toContainText("survivor", { timeout: T });
    // ⛔ THE ASSERTION. Without a tombstone this reads "doomed" and 2 accounts.
    await expect(b.getByTestId("account-list")).not.toContainText("doomed", { timeout: T });
    await expect(b.getByTestId("account-count")).toHaveText("1", { timeout: T });
  } finally {
    await ctxA.close();
    await ctxB.close();
  }
});

// ───────────────────────────────────────────────────────────────────────────
// 2. THE FALSE RECOVERY CLAIM
// ───────────────────────────────────────────────────────────────────────────

test("⛔ the app does NOT tell the user it cannot print a recovery kit — it can", async ({
  page,
}) => {
  await freshVault(page);

  // Enrol and READ THE ACCOUNT, because that panel is where the false sentence
  // was rendered. A source grep would prove the string changed; this proves the
  // string a user actually SEES changed.
  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("sync-vault-id").fill("safety-recovery-demo");
  await page.getByTestId("device-token").fill("operator-token-0123456789abcdef");
  await page.getByTestId("device-enroll").click();
  await expect(page.getByTestId("sync-status")).toContainText("Enrolled as", { timeout: T });

  await page.getByTestId("account-refresh").click();
  const advice = page.getByTestId("account-recovery-advice");
  await expect(advice).toBeVisible({ timeout: T });
  const text = (await advice.textContent()) ?? "";

  // ⛔ THE FALSE CLAIM IS GONE. This assertion goes red if it comes back.
  expect(text).not.toMatch(/this app cannot print one/i);
  // ⭐ And what replaced it is true in BOTH directions: a kit still cannot be
  // made after the fact, and this client CAN print one — with a pointer to the
  // control rather than to a CLI the user may not have.
  expect(text).toMatch(/CAN print one/);
  expect(text).toMatch(/cannot be created after the fact/i);
  expect(text).toMatch(/Generate a kit/);

  // ...and the control it now points at is really there.
  await expect(page.getByTestId("recovery-generate")).toBeVisible({ timeout: T });
});

// ───────────────────────────────────────────────────────────────────────────
// 3. THE CLOCK DIAGNOSTIC
// ───────────────────────────────────────────────────────────────────────────

test("the clock panel starts UNREAD — it never claims the clock is fine unasked", async ({
  page,
}) => {
  await freshVault(page);
  const status = page.getByTestId("clock-status");
  await expect(status).toHaveAttribute("data-state", "unread", { timeout: T });
  await expect(status).toContainText("Not checked yet");
});

test("⭐ Check clock against a reachable server reports OK", async ({ page }) => {
  await freshVault(page);
  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("clock-check").click();

  const status = page.getByTestId("clock-status");
  await expect(status).toHaveAttribute("data-state", "ok", { timeout: T });
  await expect(status).toContainText("Clock OK", { timeout: T });
});

test("⛔⛔ an unreachable server reads as NO READING, never as 'your clock is fine'", async ({
  page,
}) => {
  await freshVault(page);
  // A port nothing is listening on.
  await page.getByTestId("sync-url").fill("http://127.0.0.1:1");
  await page.getByTestId("clock-check").click();

  const status = page.getByTestId("clock-status");
  await expect(status).toHaveAttribute("data-state", "unavailable", { timeout: T });
  const text = (await status.textContent()) ?? "";
  expect(text).toMatch(/NO CLOCK READING/);
  expect(text).toMatch(/not a report that your clock is fine/i);
  expect(text).not.toMatch(/Clock OK/);
});

test("⛔⛔ the diagnostic NEVER corrects: codes still come from THIS device's clock", async ({
  page,
}) => {
  await freshVault(page);
  await addAccount(page, "rfc-vector", "RFC");
  // `?t=59` pins the page clock to the RFC 6238 instant. Whatever the server
  // says the time is, the rendered code must still be the vector for t=59 — if
  // a reading ever fed the generator, this is where it would show.
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });

  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("clock-check").click();
  await expect(page.getByTestId("clock-status")).not.toHaveAttribute("data-state", "unread", {
    timeout: T,
  });

  // Still the vector. The reading changed the REPORT and nothing else.
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
});
