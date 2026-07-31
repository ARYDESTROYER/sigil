// user-safety.spec.mjs — ⭐ THE PRODUCT-LEVEL PROOFS for three things this
// extension did TO ITS USER, driven through the REAL unpacked MV3 popup.
//
// ⛔ WHY IT MUST BE AT THIS LEVEL. `docs/engineering-lessons.md` entry 10: two
// Phase 59 fixes were guarded in the shared module and UNGUARDED in the shipping
// clients. A verifier reverted the call sites in `popup.js` and extension 14/14
// stayed GREEN. Every assertion below therefore goes through the actual controls
// in `src/popup/popup.{html,js}`, so reverting THOSE turns this red.
//
// The three:
//
//  1. ⛔ A ONE-CLICK DELETE OF A 2FA SECRET, from a button inches from the code
//     the user came to read. Phase 61 RAISED the stakes: a removal writes a
//     TOMBSTONE that propagates to every device and is specifically protected
//     against resurrection (ADR 0049 §3). Losing a 2FA secret can mean losing
//     the account it protects, permanently.
//
//  2. ⛔ A FALSE CAPABILITY CLAIM. The account panel told the user, in the
//     product, that "this extension cannot print one" about a recovery kit —
//     true before Phase 56, false ever since, with the Generate button three
//     sections below. It steers the user AWAY from the single control that
//     prevents permanent account loss.
//
//  3. NO CLOCK-SKEW DIAGNOSTIC. A code rejected because the device clock drifted
//     is indistinguishable, to the user, from a wrong secret. ⛔⛔ And the fix
//     must REPORT, never CORRECT.
//
// ⚠️ The server is `fake-sigild.mjs`, a DOUBLE. Everything here is browser
// behaviour; the server halves are proven by
// `sigil-wasm/test/clock-skew-interop.mjs` against a REAL sigild.
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
/** RFC 6238 App B sha1 key, base32. At t=59 with 6 digits this is 287082. */
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_CODE_6 = "287082";
const PINNED_T = 59;
const PASSWORD = "correct horse battery staple";

async function extensionId() {
  const manifest = JSON.parse(await readFile(path.join(EXT_DIR, "manifest.json"), "utf8"));
  const der = Buffer.from(manifest.key, "base64");
  const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

let fake;
let id;
const profiles = [];

test.beforeAll(async () => {
  id = await extensionId();
  fake = await startFakeSigild();
});

test.afterAll(async () => {
  for (const p of profiles) {
    await p.context?.close();
    if (p.dir) await rm(p.dir, { recursive: true, force: true });
  }
  profiles.length = 0;
  await fake?.close();
});

/**
 * A fresh profile with a vault created through the real setup form.
 *
 * ⚠️ `pinClock` defaults to true (`?t=59`, the deterministic-vector hook). The
 * CLOCK tests must pass `false`, and the reason is the feature working
 * correctly: the diagnostic reads the SAME clock the codes come from, so with
 * the test hook pinning it to 1970 it truthfully reports a ~56-year skew. That
 * is not a bug to route around — a diagnostic that reported on a different clock
 * than the one generating codes would be worse than none.
 */
async function newDevice({ pinClock = true } = {}) {
  const dir = await mkdtemp(path.join(tmpdir(), "sigil-ext-safety-"));
  const context = await chromium.launchPersistentContext(dir, {
    channel: "chromium",
    headless: true,
    args: [`--disable-extensions-except=${EXT_DIR}`, `--load-extension=${EXT_DIR}`],
  });
  profiles.push({ context, dir });

  const page = await context.newPage();
  await page.goto(
    `chrome-extension://${id}/src/popup/popup.html${pinClock ? `?t=${PINNED_T}` : ""}`,
  );
  await expect(page.locator("body")).toHaveAttribute("data-wasm", /.+/, { timeout: 30_000 });
  await expect(page.locator("body")).toHaveAttribute("data-phase", /setup|locked/, {
    timeout: 30_000,
  });
  await page.getByTestId("setup-password").fill(PASSWORD);
  await page.getByTestId("setup-password-2").fill(PASSWORD);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("view-unlocked")).toBeVisible({ timeout: 30_000 });
  return page;
}

// ⚠️ `hasText` matches an element's FULL text content, and every account row
// carries a HIDDEN delete-confirmation paragraph. So a row matches any word that
// appears in the confirmation copy, not only in its own label — a wording change
// that happened to contain "stays" made `filter({hasText:"stays"})` resolve to
// two rows and failed this suite in a place that named neither the copy nor the
// row. If a fixture label below ever appears in the confirmation text, that is
// the cause.
async function addAccount(page, label, secret, issuer) {
  if (!(await page.getByTestId("add-label").isVisible())) {
    await page.getByTestId("add-toggle").click();
  }
  await page.getByTestId("add-label").fill(label);
  if (issuer) await page.getByTestId("add-issuer").fill(issuer);
  await page.getByTestId("add-secret").fill(secret);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account").filter({ hasText: label })).toHaveCount(1, {
    timeout: 30_000,
  });
}

// ───────────────────────────────────────────────────────────────────────────
// 1. THE DELETE CONFIRMATION
// ───────────────────────────────────────────────────────────────────────────

test("⛔ Remove does NOT delete: it opens a confirmation that NAMES the account", async () => {
  const page = await newDevice();
  await addAccount(page, "alice@example.com", RFC_SECRET, "GitHub");
  await expect(page.getByTestId("account")).toHaveCount(1, { timeout: 30_000 });

  await page.getByTestId("remove").click();

  // ⭐ STILL THERE. This assertion goes red the moment the Remove handler is
  // wired back to `removeEntry` directly.
  await expect(page.getByTestId("account")).toHaveCount(1, { timeout: 30_000 });
  const confirm = page.getByTestId("remove-confirm");
  await expect(confirm).toBeVisible({ timeout: 30_000 });

  const warning = await page.getByTestId("remove-confirm-warning").textContent();
  // It must NAME what is about to be destroyed — issuer AND label, because
  // labels stopped being unique in Phase 61.
  expect(warning ?? "").toContain("GitHub, alice@example.com");
  expect(warning ?? "").toMatch(/permanent/i);
  // And say the removal PROPAGATES: the tombstone is why this is not a local
  // edit a later sync might undo.
  expect(warning ?? "").toMatch(/every other device/i);
  // ⛔ …AND IT MUST NOT PROMISE A SYNC THE PRODUCT DOES NOT PERFORM. The first
  // cut said the deletion "is synced to every other device holding it". Sync is
  // MANUAL here — explicit Push / Pull — and a vault with no server configured
  // never propagates at all. The condition must be stated.
  expect(warning ?? "").toMatch(/next time you Push/i);
  expect(warning ?? "").toMatch(/if you never sync/i);
  expect(warning ?? "").not.toMatch(/\bis synced to every other device/i);
});

test("Keep it CANCELS, and the account and its code survive untouched", async () => {
  const page = await newDevice();
  await addAccount(page, "keepme", RFC_SECRET, "Acme");

  await page.getByTestId("remove").click();
  await expect(page.getByTestId("remove-confirm")).toBeVisible({ timeout: 30_000 });
  await page.getByTestId("remove-confirm-cancel").click();

  await expect(page.getByTestId("remove-confirm")).toBeHidden({ timeout: 30_000 });
  await expect(page.getByTestId("account")).toHaveCount(1, { timeout: 30_000 });
  await expect(page.getByTestId("code").first()).toHaveText(RFC_CODE_6, { timeout: 30_000 });
});

test("Delete permanently is the ONLY thing that removes the entry", async () => {
  const page = await newDevice();
  await addAccount(page, "goodbye", RFC_SECRET, "Acme");
  await addAccount(page, "stays", RFC_SECRET, "Acme");
  await expect(page.getByTestId("account")).toHaveCount(2, { timeout: 30_000 });

  const doomed = page.getByTestId("account").filter({ hasText: "goodbye" });
  await doomed.getByTestId("remove").click();
  await expect(doomed.getByTestId("remove-confirm")).toBeVisible({ timeout: 30_000 });
  await doomed.getByTestId("remove-confirm-yes").click();

  await expect(page.getByTestId("account")).toHaveCount(1, { timeout: 30_000 });
  await expect(page.getByTestId("account").first()).toContainText("stays");
});

test("⭐ the confirmed delete DOES tombstone — the gate delays it, never skips it", async () => {
  // ⛔ THE 2P-SET INVARIANT (ADR 0049 §3), asserted BEHAVIOURALLY: a removal that
  // writes NO tombstone is the pre-Phase-61 behaviour, and the entry comes
  // straight back the next time this vault meets a snapshot that still holds it.
  // A "confirmation" that quietly dropped the tombstone would pass every
  // assertion above and silently un-fix Phase 61.
  //
  // ⭐ This is also why the fix is a CONFIRM and not an UNDO: an undo would have
  // to write the tombstone and retract it — the resurrection this proves must
  // not happen, and unretractable once another device has merged it.
  const vaultId = `ext-safety-tomb-${Date.now()}`;

  const a = await newDevice();
  await a.getByTestId("sync-toggle").click();
  await a.getByTestId("sync-url").fill(fake.baseUrl);
  await a.getByTestId("sync-vault").fill(vaultId);
  await addAccount(a, "doomed", RFC_SECRET, "Acme");
  await addAccount(a, "survivor", RFC_SECRET, "Acme");
  // op 1 — a snapshot that STILL HOLDS `doomed`.
  await a.getByTestId("sync-push").click();
  await expect(a.getByTestId("status")).toContainText("Pushed", { timeout: 30_000 });

  const doomed = a.getByTestId("account").filter({ hasText: "doomed" });
  await doomed.getByTestId("remove").click();
  await doomed.getByTestId("remove-confirm-yes").click();
  await expect(a.getByTestId("account")).toHaveCount(1, { timeout: 30_000 });
  await a.getByTestId("sync-push").click();
  await expect(a.getByTestId("status")).toContainText("Pushed", { timeout: 30_000 });

  // A FRESH device folds BOTH ops.
  const b = await newDevice();
  await b.getByTestId("sync-toggle").click();
  await b.getByTestId("sync-url").fill(fake.baseUrl);
  await b.getByTestId("sync-vault").fill(vaultId);
  await b.getByTestId("sync-pull").click();
  await expect(b.getByTestId("status")).toContainText("Merged", { timeout: 30_000 });

  // ⛔ THE ASSERTION. Without a tombstone this is 2 accounts including `doomed`.
  await expect(b.getByTestId("account")).toHaveCount(1, { timeout: 30_000 });
  await expect(b.getByTestId("account").first()).toContainText("survivor");
});

// ───────────────────────────────────────────────────────────────────────────
// 2. THE FALSE RECOVERY CLAIM
// ───────────────────────────────────────────────────────────────────────────

test("⛔ the extension does NOT tell the user it cannot print a recovery kit — it can", async () => {
  const page = await newDevice();

  // Enrol and READ THE ACCOUNT, because that panel is where the false sentence
  // was rendered. A source grep would prove the string changed; this proves the
  // string a user actually SEES changed.
  await page.getByTestId("sync-toggle").click();
  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("sync-vault").fill("safety-demo");
  await page.getByTestId("device-token").fill("operator-token-0123456789abcdef");
  await page.getByTestId("device-enroll").click();
  await expect(page.getByTestId("status")).toContainText("Enrolled as", { timeout: 30_000 });

  await page.getByTestId("account-show").click();
  const state = page.getByTestId("account-state");
  await expect(state).toContainText("Account", { timeout: 30_000 });
  const text = (await state.textContent()) ?? "";

  // ⛔ THE FALSE CLAIM IS GONE. This is the assertion that goes red if the old
  // sentence comes back.
  expect(text).not.toMatch(/this extension cannot print one/i);
  // ⭐ And what replaced it is true in BOTH directions: a kit still cannot be
  // made after the fact, and this client CAN print one — with a pointer to the
  // control rather than to a CLI the user may not have.
  expect(text).toMatch(/CAN print one/);
  expect(text).toMatch(/cannot be created after the fact/i);
  expect(text).toMatch(/Generate a kit/);

  // ...and the control it now points at is really there.
  await page.getByTestId("recovery-toggle").click();
  await expect(page.getByTestId("recovery-generate")).toBeVisible({ timeout: 30_000 });
});

// ───────────────────────────────────────────────────────────────────────────
// 3. THE CLOCK DIAGNOSTIC
// ───────────────────────────────────────────────────────────────────────────

test("the clock panel starts UNREAD — it never claims the clock is fine unasked", async () => {
  const page = await newDevice({ pinClock: false });
  await page.getByTestId("sync-toggle").click();
  const status = page.getByTestId("clock-status");
  await expect(status).toHaveAttribute("data-state", "unread", { timeout: 30_000 });
  await expect(status).toContainText("Not checked yet");
});

test("⭐ Check clock against a reachable server reports OK", async () => {
  const page = await newDevice({ pinClock: false });
  await page.getByTestId("sync-toggle").click();
  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("clock-check").click();

  const status = page.getByTestId("clock-status");
  await expect(status).toHaveAttribute("data-state", "ok", { timeout: 30_000 });
  await expect(status).toContainText("Clock OK", { timeout: 30_000 });
});

test("⛔⛔ an unreachable server reads as NO READING, never as 'your clock is fine'", async () => {
  const page = await newDevice({ pinClock: false });
  await page.getByTestId("sync-toggle").click();
  await page.getByTestId("sync-url").fill("http://127.0.0.1:1");
  await page.getByTestId("clock-check").click();

  const status = page.getByTestId("clock-status");
  await expect(status).toHaveAttribute("data-state", "unavailable", { timeout: 30_000 });
  const text = (await status.textContent()) ?? "";
  expect(text).toMatch(/NO CLOCK READING/);
  expect(text).toMatch(/not a report that your clock is fine/i);
  expect(text).not.toMatch(/Clock OK/);
});

test("⛔⛔ the diagnostic NEVER corrects: codes still come from THIS device's clock", async () => {
  const page = await newDevice();
  await addAccount(page, "rfc-vector", RFC_SECRET, "RFC");
  // `?t=59` pins the popup clock to the RFC 6238 instant.
  await expect(page.getByTestId("code").first()).toHaveText(RFC_CODE_6, { timeout: 30_000 });

  await page.getByTestId("sync-toggle").click();
  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("clock-check").click();
  await expect(page.getByTestId("clock-status")).not.toHaveAttribute("data-state", "unread", {
    timeout: 30_000,
  });

  // Still the vector. The reading changed the REPORT and nothing else.
  await expect(page.getByTestId("code").first()).toHaveText(RFC_CODE_6, { timeout: 30_000 });
});
