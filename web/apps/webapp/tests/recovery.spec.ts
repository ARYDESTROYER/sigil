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
const WEBAPP_ORIGIN = "http://localhost:3210";

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
  // ⭐ AND THE INDEX WAS HEALTHY, so the generate-time truncation warning must be
  // ABSENT. This is the direction that keeps the other one worth reading: a
  // warning that is always on is a warning people learn to skip, and it would
  // send a user off to re-print a sheet that was fine. (The VISIBLE direction is
  // pinned in the truncation spec below, which crowds the index BEFORE printing.)
  await expect(page.getByTestId("recovery-index-truncated")).toHaveCount(0);

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


/**
 * ⭐ A TRUNCATED INDEX MUST REFUSE, NOT UNDER-REPORT.
 *
 * `GET /v1/devices/{id}/keys` caps one page at 500 rows and has NO CURSOR, so a
 * kit covering more than that cannot be fully enumerated. No client read
 * `has_more`, which meant a kit over the cap would have recovered the first 500
 * vaults and reported SUCCESS — a partial recovery presented as a complete one,
 * on the one mechanism whose entire job is answering "did I get everything
 * back?".
 *
 * The cap is shrunk here rather than minting 500 envelopes; the flag and the
 * branch are the real ones.
 */
test("a recovery whose index was TRUNCATED refuses instead of restoring a prefix", async ({
  page,
  browser,
}: {
  page: Page;
  browser: Browser;
}) => {
  await page.goto("/?t=59");
  await setupVault(page, "truncation-profile-one");

  await page.getByTestId("add-label").fill("rfc-vector");
  await page.getByTestId("add-secret").fill(RFC_SECRET_B32);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });

  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("sync-vault-id").fill("truncation-vault");
  await page.getByTestId("device-token").fill("operator-token-0123456789abcdef");
  await page.getByTestId("device-enroll").click();
  await expect(page.getByTestId("sync-status")).toContainText("Enrolled as", { timeout: T });

  await page.getByTestId("sharing-convert").click();
  await expect(page.getByTestId("sharing-status")).toContainText("random 32-byte vault key", {
    timeout: T,
  });
  await page.getByTestId("sync-push").click();
  await expect(page.getByTestId("sync-status")).toContainText("Pushed sealed container", {
    timeout: T,
  });

  // ⭐ CROWD THE INDEX BEFORE PRINTING. Generation is the ONE moment the user can
  // still act on it — re-print, reduce coverage, copy the "covers" line
  // carefully. By restore time the paper is fixed, so a kit whose index is
  // ALREADY crowded has to say so on the sheet.
  //
  // A cap of ZERO makes the very first row overflow, so the flag is reachable
  // without needing to know the kit's device id in advance — which is
  // impossible, since the id does not exist until `generateRecoveryKit` enrols
  // it. (The reachable real-world shape is a race against the grant that
  // discloses the new id; that is driven against a REAL sigild in
  // sigil-wasm/test/recovery-interop.mjs.)
  const tuned = fake as unknown as { indexPageCap: number };
  const previousCap = tuned.indexPageCap;
  tuned.indexPageCap = 0;
  await page.getByTestId("recovery-generate").click();
  await expect(page.getByTestId("recovery-sheet")).toBeVisible({ timeout: T });
  // ⛔ IT STILL PRINTS. Refusing because a stranger crowded a server listing
  // would hand an availability attack the power to stop kits being made at all —
  // a denial of the last line of defence (ADR 0040 limitation 1), strictly worse
  // than the truncation it would be reacting to. It reports, and prints.
  await expect(page.getByTestId("recovery-index-truncated")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("recovery-index-truncated")).toContainText("re-print");
  tuned.indexPageCap = previousCap;

  const formatted = ((await page.getByTestId("recovery-code").textContent()) ?? "").trim();
  const kitDeviceId = ((await page.getByTestId("recovery-kit-id").textContent()) ?? "").trim();
  expect(formatted.replace(/-/g, "")).toHaveLength(56);
  expect(kitDeviceId).toMatch(/^dev_/);

  // Give the kit a SECOND covered vault, then make the server's page hold one row.
  // ⭐ TWO decoys, and the FIRST is deposited by a device that was never enrolled
  // here — exactly the shape ADR 0052 §3 refuses, because the client rule is
  // `accountDevices.has(sender)` and a foreign account's device is simply absent
  // from `GET /v1/account`. ⚠️ The double mints every enrolled device into ONE
  // account (its header says so), so a stranger cannot be expressed by enrolling
  // one; planting the row is the only way to reach that refusal from a browser
  // spec at all. The multi-account form is proven against a REAL sigild in
  // sigil-wasm/test/recovery-interop.mjs.
  const strangerKey = `stranger-vault\u0000${kitDeviceId}`;
  const decoyKey = `overflow-vault\u0000${kitDeviceId}`;
  fake.state.envelopes.set(strangerKey, {
    bytes: Buffer.alloc(1226),
    sender: "dev_not_in_this_account",
    createdAt: new Date().toISOString(),
  });
  fake.state.envelopes.set(decoyKey, {
    bytes: Buffer.alloc(1226),
    sender: "dev_fake_1",
    createdAt: new Date().toISOString(),
  });
  // TWO rows visible (the real vault and the stranger's) and a third beyond the
  // cap — so the listing is BOTH crowded and carrying an untrusted row.
  tuned.indexPageCap = 2;

  try {
    const ctx = await browser.newContext();
    const p2 = await ctx.newPage();
    await p2.goto("/?t=59");
    await p2.getByTestId("restore-open").click();
    await p2.getByTestId("restore-url").fill(fake.baseUrl);
    await p2.getByTestId("restore-device-id").fill(kitDeviceId);
    await p2.getByTestId("restore-password").fill("truncation-profile-two");
    await p2.getByTestId("restore-confirm").fill("truncation-profile-two");
    await p2.getByTestId("restore-code").fill(formatted);
    await p2.getByTestId("restore-submit").click();

    await expect(p2.getByTestId("restore-error")).toContainText("partial recovery", {
      timeout: T,
    });
    // NOTHING was adopted: a half-restored browser is worse than a clean refusal.
    expect(await p2.evaluate(() => Object.keys(window.localStorage))).toEqual([]);

    // ⭐ AND THE WAY OUT. A refusal alone is not a recovery — it just moves the
    // failure. The printed sheet already carries the covered vault ids, so
    // naming them makes the restore ask each VAULT directly instead of asking
    // the server what is waiting for this kit. That listing is what a flood can
    // crowd; a vault addressed by id is not. Same profile, same crowded server,
    // same kit — this time it lands in an unlocked vault with the RFC code.
    await p2.getByTestId("restore-vaults").fill("truncation-vault");
    await p2.getByTestId("restore-submit").click();
    await expect(p2.getByTestId("vault-view")).toBeVisible({ timeout: T });
    await expect(p2.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });

    // ⛔⛔ AND IT MUST SAY SO. This is the scenario the whole fix exists to make
    // honest — a sheet-driven restore off a crowded index — and it SUCCEEDS, so
    // there is no error screen to carry the qualification. `restoreFromKit`
    // computed exactly this warning and the app threw the return value away, so
    // the user landed in an unlocked vault told NOTHING: the index it could not
    // enumerate, the rows it ignored, the vaults it never saw.
    //
    // ⭐ The assertion is on the UNLOCKED screen deliberately. The panel that
    // submitted this is unmounted by the phase flip the success causes, so a
    // message rendered there would be destroyed at the instant it became true —
    // which is why the state is held at the top level.
    const notes = p2.getByTestId("restore-notes");
    await expect(notes).toBeVisible({ timeout: T });
    await expect(notes).toContainText("THIS MAY NOT BE EVERYTHING");
    await expect(notes).toContainText("no way to ask for the rest");
    // ⛔⛔ AND THE OTHER CAVEAT, which had NO test at all: a row the INDEX ALONE
    // introduced, deposited by a device outside this account, is IGNORED — not
    // fetched, not unwrapped, and above all not PINNED into the fresh trust
    // store this restore just built. Deleting this whole note block from the app
    // used to leave every browser test green.
    await expect(notes).toContainText("OUTSIDE your account");
    await expect(notes).toContainText("were ignored");
    // ⭐ ONE SUMMARY, NEVER ONE LINE PER ROW: the ignored vault must not be
    // itemised, because a flood rendered row by row buries the real result —
    // which is exactly what a flood is for.
    await expect(notes).not.toContainText("stranger-vault");
    // ⚠️ NOT A TOAST. It has to still be there after the vault has rendered and
    // any transient status has aged out — "this may not be everything" does not
    // stop being true, and the user cannot act on it from this screen.
    await expect(p2.getByTestId("vault-size-warning")).toHaveCount(0);
    await expect(notes).toBeVisible();
    // Dismissible, and only by the user.
    await p2.getByTestId("restore-notes-dismiss").click();
    await expect(notes).toHaveCount(0);

    // ⚠️ HONEST SCOPE, so a later reader does not over-read this spec: the cap
    // is shrunk rather than 500 envelopes being minted, and the real vault is
    // still ON the single visible page — so `fromSheet` is EMPTY here and the
    // envelope-sender path is NOT exercised in the browser. That path is proven
    // against a REAL sigild in `sigil-wasm/test/recovery-interop.mjs`. What this
    // pins is the truncation flag reaching the user, which is the half that was
    // computed and discarded.
    await ctx.close();
  } finally {
    tuned.indexPageCap = previousCap;
    fake.state.envelopes.delete(decoyKey);
    fake.state.envelopes.delete(strangerKey);
  }
});
