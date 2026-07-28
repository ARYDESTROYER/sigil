import { expect, test, type Browser, type Page } from "@playwright/test";
// @ts-expect-error — plain .mjs test helper shared with the extension suite.
import { startFakeSigild } from "../../../../sigil-wasm/test/fake-sigild.mjs";

/**
 * ⭐ THE RECOVERY-KIT WRAP GATE, from the browser.
 *
 * ADR 0042's central control: a client asked to wrap a vault key TO A RECOVERY
 * KIT it has never pinned must REFUSE, because the only thing vouching for that
 * kit's public key is the server — and a server that substituted its own key
 * would be handed the vault key it exists never to see. The refusal is lifted by
 * ONE thing: the safety number PRINTED ON THE SHEET, compared out of band.
 *
 * This spec exists because the control was deletable without any browser test
 * noticing: replacing the gate's condition with `false && (...)` in
 * sigil-wasm/sharing.mjs left every shipped webapp and extension spec green. The
 * derived path (covering from the browser that PRINTED the kit) never reaches the
 * gate at all, so only a SECOND profile — one that never saw the sheet — can
 * exercise it. That is what this does.
 *
 * The server is the fake; everything cryptographic (the wrap, the safety number,
 * the HKDF derivation) is real and happens in the browser's wasm.
 */

const T = 60_000;
const RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_CODE = "287082";
const WEBAPP_ORIGIN = "http://127.0.0.1:3210";

type Fake = {
  baseUrl: string;
  close: () => Promise<void>;
  log: string[];
  state: { envelopes: Map<string, unknown> };
};

let fake: Fake;

test.beforeAll(async () => {
  fake = (await startFakeSigild({ corsOrigins: [WEBAPP_ORIGIN] })) as Fake;
});

test.afterAll(async () => {
  await fake?.close();
});

/** A browser profile with a vault, an enrolled device and a SHARED vault key. */
async function setup(page: Page, password: string, vaultId: string) {
  await page.goto("/?t=59");
  await page.getByTestId("setup-password").fill(password);
  await page.getByTestId("setup-confirm").fill(password);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });

  await page.getByTestId("add-label").fill("rfc-vector");
  await page.getByTestId("add-secret").fill(RFC_SECRET_B32);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });

  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("sync-vault-id").fill(vaultId);
  await page.getByTestId("device-token").fill("operator-token-0123456789abcdef");
  await page.getByTestId("device-enroll").click();
  await expect(page.getByTestId("sync-status")).toContainText("Enrolled as", { timeout: T });

  // A kit can only be handed a vault KEY, so the vault must be a SHARED vault.
  await page.getByTestId("sharing-convert").click();
  await expect(page.getByTestId("sharing-status")).toContainText("random 32-byte vault key", {
    timeout: T,
  });
}

test("a SECOND profile REFUSES to cover a first-sight kit until the printed safety number is supplied", async ({
  page,
  browser,
}: {
  page: Page;
  browser: Browser;
}) => {
  // ── profile 1 prints a kit ────────────────────────────────────────────────
  await setup(page, "wrapgate-one-pw", "wrapgate-vault-a");
  await page.getByTestId("recovery-generate").click();
  await expect(page.getByTestId("recovery-sheet")).toBeVisible({ timeout: T });
  const kitId = ((await page.getByTestId("recovery-kit-id").textContent()) ?? "").trim();
  const printedSafety = ((await page.getByTestId("recovery-safety-number").textContent()) ?? "")
    .trim();
  expect(kitId).toMatch(/^dev_/);
  expect(printedSafety).toMatch(/^\d{5}( \d{5}){5}$/);

  // ── profile 2 never saw that sheet ────────────────────────────────────────
  const ctx = await browser.newContext();
  const p2 = await ctx.newPage();
  const VAULT_B = "wrapgate-vault-b";
  await setup(p2, "wrapgate-two-pw", VAULT_B);
  const envelopeKey = `${VAULT_B}\u0000${kitId}`;
  expect(fake.state.envelopes.has(envelopeKey)).toBe(false);

  // 1) FIRST SIGHT, no safety number → REFUSED, and named as a recovery kit.
  await p2.getByTestId("recovery-cover-kit").fill(kitId);
  await p2.getByTestId("recovery-cover").click();
  await expect(p2.getByTestId("recovery-unverified")).toBeVisible({ timeout: T });
  await expect(p2.getByTestId("recovery-unverified")).toContainText("recovery kit");
  await expect(p2.getByTestId("recovery-status")).toContainText("REFUSED", { timeout: T });
  // ⭐ NOTHING WAS WRAPPED AND NOTHING WAS UPLOADED — the whole point.
  expect(fake.state.envelopes.has(envelopeKey)).toBe(false);

  // 2) A WRONG safety number is refused too, and named as a MISMATCH rather than
  //    as first sight — so the refusal in (1) cannot have silently pinned the
  //    key (a pinned key would make this a "match" and let it through).
  await p2.getByTestId("recovery-cover-safety").fill("11111 22222 33333 44444 55555 66666");
  await p2.getByTestId("recovery-cover").click();
  await expect(p2.getByTestId("recovery-status")).toContainText("does not match", { timeout: T });
  expect(fake.state.envelopes.has(envelopeKey)).toBe(false);

  // 3) The number PRINTED ON THE SHEET, compared out of band → proceeds.
  await p2.getByTestId("recovery-cover-safety").fill(printedSafety);
  await p2.getByTestId("recovery-cover").click();
  await expect(p2.getByTestId("recovery-status")).toContainText("now covered by kit", {
    timeout: T,
  });
  expect(fake.state.envelopes.has(envelopeKey)).toBe(true);

  await ctx.close();
});

/**
 * The same gate, reached from the ORDINARY sharing panel rather than the recovery
 * panel: a recovery kit is an ordinary member device as far as `shareVault` is
 * concerned, so the refusal must hold there too.
 */
test("sharing a vault to a first-sight recovery kit is refused from the sharing panel too", async ({
  page,
  browser,
}: {
  page: Page;
  browser: Browser;
}) => {
  await setup(page, "wrapgate-share-one", "wrapgate-share-a");
  await page.getByTestId("recovery-generate").click();
  await expect(page.getByTestId("recovery-sheet")).toBeVisible({ timeout: T });
  const kitId = ((await page.getByTestId("recovery-kit-id").textContent()) ?? "").trim();

  const ctx = await browser.newContext();
  const p2 = await ctx.newPage();
  const VAULT_B = "wrapgate-share-b";
  await setup(p2, "wrapgate-share-two", VAULT_B);
  const envelopeKey = `${VAULT_B}\u0000${kitId}`;

  // Give profile 2 a pin store of its own. `requirePinStore` FAILS CLOSED — a
  // client with no store is refused outright rather than treated as "everything
  // is first-sight" — so without this the share is blocked one step EARLIER and
  // the recovery-kit gate is never reached. Printing its own kit is the ordinary
  // way a browser acquires a store (it pins its kit's derived key).
  await p2.getByTestId("recovery-generate").click();
  await expect(p2.getByTestId("recovery-sheet")).toBeVisible({ timeout: T });
  await p2.getByTestId("recovery-written").check();
  await p2.getByTestId("recovery-hide").click();

  await p2.getByTestId("sharing-recipient").fill(kitId);
  await p2.getByTestId("sharing-share").click();
  await expect(p2.getByTestId("sharing-status")).toContainText("REFUSING TO WRAP", { timeout: T });
  await expect(p2.getByTestId("sharing-status")).toContainText("RECOVERY KIT");
  expect(fake.state.envelopes.has(envelopeKey)).toBe(false);

  await ctx.close();
});
