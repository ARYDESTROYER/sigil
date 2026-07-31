// merge.spec.ts — ⭐⭐ THE PRODUCT-LEVEL PROOF that the webapp's Pull button
// MERGES instead of adopting the newest op.
//
// ⛔ WHY THIS EXISTS AT ALL, and why library coverage would not have done.
// `docs/engineering-lessons.md` entry 10: two Phase 59 fixes were guarded in the
// shared module and UNGUARDED in the shipping app. A verifier reverted
// `authenticator.tsx` to the pre-fix shape and **webapp 50/50 stayed green**,
// while mutating the same logic inside `totp-vault.mjs` went red every time. The
// module was covered, so the coverage *looked* real — while the fix in the app
// was deletable without a single red light.
//
// So this spec drives the REAL UI: two browser profiles are two devices, each
// ADDS AN ACCOUNT THROUGH THE FORM, each PUSHES with the real button, and then
// each PULLS with the real button and must see BOTH accounts rendered with BOTH
// correct codes. Reverting `authenticator.tsx`'s pull to
// `ops[ops.length - 1]` must turn it RED.
//
// ⚠️ It runs against `fake-sigild.mjs`, a DOUBLE. It verifies no signature and
// enforces no authorization — but it IS append-only and relays exact bytes,
// which is the only property this spec needs. What the browser does is proven
// here; what a real sigild would allow is proven by
// `sigil-wasm/test/merge-interop.mjs`, which drives a real server and the real
// `sigil` binary.

import { expect, test, type Page } from "@playwright/test";
// @ts-expect-error — plain .mjs test helper shared with the extension suite.
import { startFakeSigild } from "../../../../sigil-wasm/test/fake-sigild.mjs";

const T = 60_000;
/** RFC 6238 App B sha1 key, base32. At t=59 with 6 digits this is 287082. */
const RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_CODE = "287082";
/**
 * A second, DIFFERENT secret so the two devices' accounts differ in content —
 * the RFC seed truncated to its 10-byte form, which yields 263420 at t=59 rather
 * than 287082. ⚠️ Deliberately the SAME published constant family as above: it is
 * already allowlisted in `.gitleaks.toml` BY VALUE, so this suite does not make a
 * secret scanner one line laxer to hold a made-up high-entropy string.
 */
const OTHER_SECRET_B32 = "GEZDGNBVGY3TQOJQ";
// ⚠️ ONE fake sigild is shared by every test in this file and its op-log is
// APPEND-ONLY, exactly like a real one. Each test therefore needs its OWN vault
// id, or an earlier test's ops merge into a later one's and the counts are
// nonsense. (This bit once: the delete test saw 5 accounts instead of 2.)
let vaultSeq = 0;
const nextVaultId = () => `merge-demo-${++vaultSeq}`;
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

/** Create a vault through the real setup form and point Sync at the fake. */
async function freshVault(page: Page, vaultId: string) {
  await page.goto("/?t=59");
  await page.getByTestId("setup-password").fill(PASSWORD);
  await page.getByTestId("setup-confirm").fill(PASSWORD);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("sync-vault-id").fill(vaultId);
}

/** Add an account through the real form. */
async function addAccount(page: Page, label: string, secret: string) {
  await page.getByTestId("add-label").fill(label);
  await page.getByTestId("add-secret").fill(secret);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-list")).toContainText(label, { timeout: T });
}

async function push(page: Page) {
  await page.getByTestId("sync-push").click();
  await expect(page.getByTestId("sync-status")).toContainText("Pushed", { timeout: T });
}

async function pull(page: Page) {
  await page.getByTestId("sync-pull").click();
  await expect(page.getByTestId("sync-status")).toContainText("Merged", { timeout: T });
}

/** Every rendered `Issuer · label` string, in DOM order. */
async function renderedLabels(page: Page): Promise<string[]> {
  return page.getByTestId("account-label").allTextContents();
}

test("⭐ two devices each add an account offline; after both sync, BOTH have BOTH", async ({
  browser,
}) => {
  // Two independent browser contexts = two devices with two separate
  // localStorage origins. Neither can see the other's vault except through the
  // op-log.
  const ctxA = await browser.newContext();
  const ctxB = await browser.newContext();
  const a = await ctxA.newPage();
  const b = await ctxB.newPage();

  try {
    // ── SETUP: a common starting point pushed by A, merged by B. ────────────
    const vaultId = nextVaultId();
    await freshVault(a, vaultId);
    await addAccount(a, "shared-base", RFC_SECRET_B32);
    await push(a);

    await freshVault(b, vaultId);
    await pull(b);
    await expect(b.getByTestId("account-list")).toContainText("shared-base", { timeout: T });

    // ── ⛔ THE PARTITION. Each adds a DIFFERENT account, neither pulls. ──────
    await addAccount(a, "only-on-a", RFC_SECRET_B32);
    await push(a); // op 2

    await addAccount(b, "only-on-b", OTHER_SECRET_B32);
    await push(b); // op 3 — THE TIP, and it has never seen `only-on-a`.

    // ── BOTH SYNC. ──────────────────────────────────────────────────────────
    await pull(a);
    await pull(b);

    // ── ⭐ THE ASSERTION. Both devices show all three, RENDERED. ────────────
    for (const [name, page] of [
      ["A", a],
      ["B", b],
    ] as const) {
      const labels = await renderedLabels(page);
      expect(labels.join(" | "), `${name} lost an account`).toContain("shared-base");
      expect(labels.join(" | "), `${name} lost the OTHER device's account`).toContain("only-on-a");
      expect(labels.join(" | "), `${name} lost its OWN account`).toContain("only-on-b");
      await expect(page.getByTestId("account-count")).toHaveText("3", { timeout: T });
    }

    // ── …and the SECRETS survived, not merely the labels. Two of the three
    //    accounts carry the RFC 6238 vector; at ?t=59 they must read 287082.
    for (const page of [a, b]) {
      const codes = await page.getByTestId("account-code").allTextContents();
      expect(codes.filter((c) => c === RFC_CODE).length, "the RFC vector secrets were lost").toBe(
        2,
      );
      // The third is a different secret and must NOT be the same code.
      expect(codes.filter((c) => c !== RFC_CODE).length).toBe(1);
    }

    // ── CONVERGENCE: both devices render the same accounts in the same order.
    expect(await renderedLabels(a)).toEqual(await renderedLabels(b));
  } finally {
    await ctxA.close();
    await ctxB.close();
  }
});

test("a delete made on one device stays deleted after another device syncs", async ({
  browser,
}) => {
  const ctxA = await browser.newContext();
  const ctxB = await browser.newContext();
  const a = await ctxA.newPage();
  const b = await ctxB.newPage();

  try {
    const vaultId = nextVaultId();
    await freshVault(a, vaultId);
    await addAccount(a, "keep-me", RFC_SECRET_B32);
    await addAccount(a, "delete-me", OTHER_SECRET_B32);
    await push(a);

    // B pulls, so it HOLDS `delete-me`.
    await freshVault(b, vaultId);
    await pull(b);
    await expect(b.getByTestId("account-count")).toHaveText("2", { timeout: T });

    // A deletes it through the real Remove button and pushes.
    await a
      .getByTestId("account-row")
      .filter({ hasText: "delete-me" })
      .getByTestId("account-remove")
      .click();
    await expect(a.getByTestId("account-count")).toHaveText("1", { timeout: T });
    await push(a);

    // B merges. ⛔ Without a tombstone the union brings `delete-me` straight back.
    await pull(b);
    await expect(b.getByTestId("account-count")).toHaveText("1", { timeout: T });
    expect((await renderedLabels(b)).join(" | ")).not.toContain("delete-me");

    // B pushes its post-merge snapshot and A merges again: it must STAY gone.
    await push(b);
    await pull(a);
    await expect(a.getByTestId("account-count")).toHaveText("1", { timeout: T });
    expect((await renderedLabels(a)).join(" | ")).not.toContain("delete-me");
  } finally {
    await ctxA.close();
    await ctxB.close();
  }
});

test("the same label at two issuers is two accounts, and both keep their own code", async ({
  page,
}) => {
  await freshVault(page, nextVaultId());

  await page.getByTestId("add-label").fill("work");
  await page.getByTestId("add-issuer").fill("GitHub");
  await page.getByTestId("add-secret").fill(RFC_SECRET_B32);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-count")).toHaveText("1", { timeout: T });

  // ⛔ Identity used to be the LABEL alone, so this second account — a different
  // service, a different secret — was refused as a duplicate.
  await page.getByTestId("add-label").fill("work");
  await page.getByTestId("add-issuer").fill("GitLab");
  await page.getByTestId("add-secret").fill(OTHER_SECRET_B32);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-count")).toHaveText("2", { timeout: T });

  const labels = (await renderedLabels(page)).join(" | ");
  expect(labels).toContain("GitHub");
  expect(labels).toContain("GitLab");

  // …and they are genuinely two accounts, with two different codes.
  const codes = await page.getByTestId("account-code").allTextContents();
  expect(new Set(codes).size).toBe(2);
  expect(codes).toContain(RFC_CODE);

  // Removing ONE must remove exactly one — a label-keyed filter removed both.
  await page
    .getByTestId("account-row")
    .filter({ hasText: "GitHub" })
    .getByTestId("account-remove")
    .click();
  await expect(page.getByTestId("account-count")).toHaveText("1", { timeout: T });
  expect((await renderedLabels(page)).join(" | ")).toContain("GitLab");

  // …and the byte-identical account is still refused.
  await page.getByTestId("add-label").fill("work");
  await page.getByTestId("add-issuer").fill("GitLab");
  await page.getByTestId("add-secret").fill(OTHER_SECRET_B32);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-count")).toHaveText("1", { timeout: T });
});
