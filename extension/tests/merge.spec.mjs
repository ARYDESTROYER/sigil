// merge.spec.mjs — ⭐⭐ THE PRODUCT-LEVEL PROOF that the popup's Pull button
// MERGES instead of adopting the newest op, in the REAL unpacked MV3 extension.
//
// ⛔ WHY THIS EXISTS, and why library coverage would not have done.
// `docs/engineering-lessons.md` entry 10: two Phase 59 fixes were guarded in the
// shared module and UNGUARDED in the shipping clients. A verifier reverted the
// call sites in `popup.js` and `authenticator.tsx` and **extension 14/14 and
// webapp 50/50 stayed green** — the module was covered, so the coverage *looked*
// real while the fix in the shipping app was deletable with no red light.
//
// So: TWO persistent Chromium profiles are TWO DEVICES, with two separate
// `chrome.storage.local` stores. Each adds an account THROUGH THE REAL FORM,
// pushes with the REAL button, and pulls with the REAL button — and both must
// then render BOTH accounts with BOTH correct codes. Reverting `popup.js`'s pull
// to `ops[ops.length - 1]` must turn this RED.
//
// ⚠️ The server is `fake-sigild.mjs`, a DOUBLE: no signature verification, no
// authorization, no entitlement gate. It IS append-only and relays exact bytes,
// which is the only property this spec needs. What a real sigild would allow is
// proven by `sigil-wasm/test/merge-interop.mjs` against a real server.
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
/**
 * A second, DIFFERENT secret so the two devices' accounts differ in content —
 * the RFC seed truncated to its 10-byte form, which yields 263420 at t=59 rather
 * than 287082. ⚠️ Deliberately the SAME published constant family as above: it is
 * already allowlisted in `.gitleaks.toml` BY VALUE, so this suite does not make a
 * secret scanner one line laxer to hold a made-up high-entropy string.
 */
const OTHER_SECRET = "GEZDGNBVGY3TQOJQ";
const PINNED_T = 59;
const PASSWORD = "correct horse battery staple";

// ⚠️ ONE fake sigild is shared by every test here and its op-log is APPEND-ONLY,
// exactly like a real one — so each test needs its OWN vault id or an earlier
// test's ops merge into a later one's.
let vaultSeq = 0;
const nextVaultId = () => `ext-merge-${++vaultSeq}`;

async function extensionId() {
  const manifest = JSON.parse(await readFile(path.join(EXT_DIR, "manifest.json"), "utf8"));
  const der = Buffer.from(manifest.key, "base64");
  const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

let fake;
let id;
/** Every profile opened, so afterAll can close them all. */
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
 * A fresh DEVICE: its own persistent profile (own `chrome.storage.local`), its
 * own vault created through the real setup form, pointed at `vaultId`.
 */
async function newDevice(vaultId) {
  const dir = await mkdtemp(path.join(tmpdir(), "sigil-ext-merge-"));
  const context = await chromium.launchPersistentContext(dir, {
    channel: "chromium",
    headless: true,
    args: [`--disable-extensions-except=${EXT_DIR}`, `--load-extension=${EXT_DIR}`],
  });
  profiles.push({ context, dir });

  const page = await context.newPage();
  const failures = [];
  page.on("pageerror", (e) => failures.push(String(e)));
  await page.goto(`chrome-extension://${id}/src/popup/popup.html?t=${PINNED_T}`);
  await expect(page.locator("body")).toHaveAttribute("data-wasm", /.+/, { timeout: 30_000 });
  await expect(page.locator("body")).toHaveAttribute("data-phase", /setup|locked/, {
    timeout: 30_000,
  });
  await page.getByTestId("setup-password").fill(PASSWORD);
  await page.getByTestId("setup-password-2").fill(PASSWORD);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("view-unlocked")).toBeVisible({ timeout: 30_000 });

  await page.getByTestId("sync-toggle").click();
  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("sync-vault").fill(vaultId);
  return { page, failures };
}

async function addAccount(page, label, secret, issuer) {
  if (!(await page.getByTestId("add-label").isVisible())) {
    await page.getByTestId("add-toggle").click();
  }
  await page.getByTestId("add-label").fill(label);
  if (issuer) await page.getByTestId("add-issuer").fill(issuer);
  await page.getByTestId("add-secret").fill(secret);
  await page.getByTestId("add-submit").click();
}

async function push(page) {
  await page.getByTestId("sync-push").click();
  await expect(page.getByTestId("status")).toContainText("Pushed", { timeout: 30_000 });
}

async function pull(page) {
  await page.getByTestId("sync-pull").click();
  await expect(page.getByTestId("status")).toContainText("Merged", { timeout: 30_000 });
}

/** The rendered account labels, in DOM order. */
async function labels(page) {
  return page.getByTestId("account").locator(".label").allTextContents();
}

test("⭐ two devices each add an account offline; after both sync, BOTH have BOTH", async () => {
  const vaultId = nextVaultId();
  const a = await newDevice(vaultId);
  await addAccount(a.page, "shared-base", RFC_SECRET);
  await expect(a.page.getByTestId("code").first()).toHaveText(RFC_CODE_6, { timeout: 30_000 });
  await push(a.page);

  const b = await newDevice(vaultId);
  await pull(b.page);
  await expect(b.page.getByTestId("account")).toHaveCount(1, { timeout: 30_000 });

  // ⛔ THE PARTITION: each adds a DIFFERENT account, neither pulls first.
  await addAccount(a.page, "only-on-a", RFC_SECRET);
  await expect(a.page.getByTestId("account")).toHaveCount(2, { timeout: 30_000 });
  await push(a.page); // op 2

  await addAccount(b.page, "only-on-b", OTHER_SECRET);
  await expect(b.page.getByTestId("account")).toHaveCount(2, { timeout: 30_000 });
  await push(b.page); // op 3 — THE TIP, which has never seen `only-on-a`.

  // BOTH sync.
  await pull(a.page);
  await pull(b.page);

  for (const [name, dev] of [
    ["A", a],
    ["B", b],
  ]) {
    await expect(dev.page.getByTestId("account"), `${name} did not end with 3`).toHaveCount(3, {
      timeout: 30_000,
    });
    const seen = (await labels(dev.page)).join(" | ");
    expect(seen, `${name} lost an account`).toContain("shared-base");
    expect(seen, `${name} lost the OTHER device's account`).toContain("only-on-a");
    expect(seen, `${name} lost its OWN account`).toContain("only-on-b");
  }

  // ⭐ The SECRETS survived, not merely the labels: two of the three carry the
  // RFC 6238 vector and must read 287082 at the pinned clock.
  for (const dev of [a, b]) {
    const codes = await dev.page.getByTestId("code").allTextContents();
    expect(codes.filter((c) => c === RFC_CODE_6).length).toBe(2);
    expect(codes.filter((c) => c !== RFC_CODE_6).length).toBe(1);
  }

  // Convergence: both render the same accounts in the same order.
  expect(await labels(a.page)).toEqual(await labels(b.page));
  expect(a.failures.concat(b.failures), "page errors").toEqual([]);
});

test("a delete made on one device stays deleted after another device syncs", async () => {
  const vaultId = nextVaultId();
  const a = await newDevice(vaultId);
  await addAccount(a.page, "keep-me", RFC_SECRET);
  await expect(a.page.getByTestId("account")).toHaveCount(1, { timeout: 30_000 });
  await addAccount(a.page, "delete-me", OTHER_SECRET);
  await expect(a.page.getByTestId("account")).toHaveCount(2, { timeout: 30_000 });
  await push(a.page);

  // B pulls, so it HOLDS `delete-me`.
  const b = await newDevice(vaultId);
  await pull(b.page);
  await expect(b.page.getByTestId("account")).toHaveCount(2, { timeout: 30_000 });

  // A removes it through the real button and pushes.
  await a.page
    .getByTestId("account")
    .filter({ hasText: "delete-me" })
    .getByTestId("remove")
    .click();
  await expect(a.page.getByTestId("account")).toHaveCount(1, { timeout: 30_000 });
  await push(a.page);

  // ⛔ Without a tombstone the union brings `delete-me` straight back.
  await pull(b.page);
  await expect(b.page.getByTestId("account")).toHaveCount(1, { timeout: 30_000 });
  expect((await labels(b.page)).join(" | ")).not.toContain("delete-me");

  // B pushes its post-merge snapshot; A merges again. It must STAY gone.
  await push(b.page);
  await pull(a.page);
  await expect(a.page.getByTestId("account")).toHaveCount(1, { timeout: 30_000 });
  expect((await labels(a.page)).join(" | ")).not.toContain("delete-me");
  expect(a.failures.concat(b.failures), "page errors").toEqual([]);
});

test("the same label at two issuers is two accounts, and removing one removes one", async () => {
  const a = await newDevice(nextVaultId());

  await addAccount(a.page, "work", RFC_SECRET, "GitHub");
  await expect(a.page.getByTestId("account")).toHaveCount(1, { timeout: 30_000 });

  // ⛔ Identity used to be the LABEL alone, so this second account — a different
  // service with a different secret — was refused as a duplicate.
  await addAccount(a.page, "work", OTHER_SECRET, "GitLab");
  await expect(a.page.getByTestId("account")).toHaveCount(2, { timeout: 30_000 });

  const codes = await a.page.getByTestId("code").allTextContents();
  expect(new Set(codes).size, "two accounts must have two different codes").toBe(2);
  expect(codes).toContain(RFC_CODE_6);

  // Removing ONE must remove exactly one — a label-keyed filter removed both.
  await a.page.getByTestId("account").filter({ hasText: "GitHub" }).getByTestId("remove").click();
  await expect(a.page.getByTestId("account")).toHaveCount(1, { timeout: 30_000 });
  const left = await a.page.getByTestId("account").first().textContent();
  expect(left).toContain("GitLab");
  expect(a.failures, "page errors").toEqual([]);
});
