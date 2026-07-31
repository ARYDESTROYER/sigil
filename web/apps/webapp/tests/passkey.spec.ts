import { expect, test, type BrowserContext, type Page } from "@playwright/test";
// @ts-expect-error — plain .mjs test helper shared with the extension suite.
import { startFakeSigild } from "../../../../sigil-wasm/test/fake-sigild.mjs";

/**
 * ⭐ PASSKEY-PROTECTED LOCAL CONTAINERS (ADR 0046), driven through the REAL
 * WebAuthn API with Chrome DevTools Protocol's VIRTUAL AUTHENTICATOR.
 *
 * There is no excuse for an untested WebAuthn path here: every branch of this
 * feature — PRF present, PRF absent, the authenticator removed, a DIFFERENT
 * authenticator, and a backup-eligible credential — is reachable from
 * `WebAuthn.addVirtualAuthenticator`, verified live against the installed
 * Chromium before a line of the feature was written:
 *
 *   * `hasPrf: true`                 -> prf.enabled true, 32 bytes, byte-identical
 *                                      across two assertions
 *   * `hasPrf` OMITTED               -> prf.enabled FALSE, no `results` at all
 *   * `defaultBackupEligibility`     -> the BE/BS flags actually set in authData
 *   * `removeVirtualAuthenticator`   -> the passkey is gone, ceremonies fail
 *
 * ⛔ THE ORIGIN MUST BE `localhost`. Chrome throws
 * `SecurityError: This is an invalid domain.` for WebAuthn on an IP literal, so
 * `playwright.config.ts` serves the app on `http://localhost:3210`. On
 * `127.0.0.1` every spec below fails for a reason unrelated to the feature.
 */

const T = 90_000;

/**
 * ⏱️ THE ENVELOPE FOR THE TWO SPECS THAT WAIT OUT A WEBAUTHN CEREMONY.
 *
 * ⛔ WHY IT IS SEPARATE FROM `playwright.config.ts`'s global 180 s. Two specs
 * here — "2. THE MUTATION THAT MATTERS" and "22. NO LOCKOUT" — drive the
 * NO-USABLE-AUTHENTICATOR path: the virtual authenticator is removed and the app
 * then calls `navigator.credentials.get()`, which (verified live, and documented
 * on `PASSKEY_TIMEOUT_MS` in `sigil-wasm/passkey.mjs`) NEVER SETTLES on its own.
 * The only thing that ends it is the product's own 60 s `timeout`, and that 60 s
 * is WALL CLOCK: it does not shrink on a fast machine and it does not grow on a
 * slow one.
 *
 * MEASURED on an idle machine: spec 2 takes **72 s** and spec 22 **60 s**, while
 * every other spec in the whole webapp suite finishes in **under 2.3 s**. So of
 * the 180 s global envelope these two spend 60 s before any assertion can even be
 * attempted, leaving ~2x headroom for the real work — and under a full
 * `scripts/gate.sh` run (Rust, Go, a Postgres container and a second Chromium all
 * competing) that headroom is what runs out. A security proof that goes red when
 * the machine is busy is a proof people learn to re-run until it passes.
 *
 * ⭐ RAISED HERE, NOT GLOBALLY, ON PURPOSE. Every other spec finishing in ~1 s
 * SHOULD fail at 180 s — that ceiling is a real signal for them, and giving the
 * whole suite five minutes to hide in would throw it away for 55 specs to
 * accommodate 2. The number below is 60 s of unavoidable wait plus a 4x margin on
 * the ~12 s of actual work.
 *
 * ⚠️ IT IS NOT A RETRY. `retries` stays 0 (see `playwright.config.ts`): this
 * changes how long a spec may take, never how many chances it gets.
 */
const NO_AUTHENTICATOR_T = 300_000;

const RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_CODE = "287082";
const WEBAPP_ORIGIN = "http://localhost:3210";
const VAULT_ID = "passkey-vault";
const ENROLL_TOKEN = "operator-token-0123456789abcdef";

type Fake = { baseUrl: string; close: () => Promise<void>; log: string[] };
let fake: Fake;

// ⚠️ ONE FAKE PER TEST, not per worker. These specs each enrol a device and print
// a recovery kit, and the fake models a SINGLE ACCOUNT — so a shared instance
// leaves every spec looking at every other spec's devices and kits. That is not
// the shape of any real account, and it silently broke the relink spec (the
// enable flow saw several active kits and could no longer tell which sheet had
// been typed). Isolation is cheap: it is an in-process HTTP server.
test.beforeEach(async () => {
  fake = (await startFakeSigild({ corsOrigins: [WEBAPP_ORIGIN] })) as Fake;
});
test.afterEach(async () => {
  await fake?.close();
});

// ── virtual authenticator plumbing ───────────────────────────────────────────

type Cdp = Awaited<ReturnType<BrowserContext["newCDPSession"]>>;

/**
 * Attach a virtual authenticator. `hasPrf: false` is the UNSUPPORTED case and is
 * as real as the supported one — Chrome answers `prf.enabled === false` at
 * creation and returns no `results` at assertion.
 */
async function addAuthenticator(
  cdp: Cdp,
  {
    hasPrf = true,
    backupEligible = false,
    // ⭐ "internal" makes Chrome report `authenticatorAttachment: "platform"`;
    // anything else (e.g. "usb", a removable security key) makes it report
    // "cross-platform". That is the knob spec 24 uses to make the REAL
    // attachment differ from an inferred one.
    transport = "internal",
  }: { hasPrf?: boolean; backupEligible?: boolean; transport?: string } = {},
): Promise<string> {
  const options: Record<string, unknown> = {
    protocol: "ctap2",
    ctap2Version: "ctap2_1",
    transport,
    hasResidentKey: true,
    hasUserVerification: true,
    isUserVerified: true,
    automaticPresenceSimulation: true,
  };
  if (hasPrf) options.hasPrf = true;
  if (backupEligible) {
    options.defaultBackupEligibility = true;
    options.defaultBackupState = true;
  }
  const { authenticatorId } = (await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options,
  } as never)) as { authenticatorId: string };
  return authenticatorId;
}

async function enableWebAuthn(page: Page): Promise<Cdp> {
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  return cdp;
}

// ── app-level helpers ────────────────────────────────────────────────────────

async function createVault(page: Page, password: string) {
  await page.getByTestId("setup-password").fill(password);
  await page.getByTestId("setup-confirm").fill(password);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
}

async function addRfcAccount(page: Page) {
  await page.getByTestId("add-label").fill("rfc-vector");
  await page.getByTestId("add-secret").fill(RFC_SECRET_B32);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
}

async function enroll(page: Page) {
  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("sync-vault-id").fill(VAULT_ID);
  await page.getByTestId("device-token").fill(ENROLL_TOKEN);
  await page.getByTestId("device-enroll").click();
  await expect(page.getByTestId("sync-status")).toContainText("Enrolled as", { timeout: T });
}

/** Print a kit and return its 56-character code plus the kit's device id. */
async function generateKit(page: Page): Promise<{ code: string; kitId: string }> {
  await page.getByTestId("recovery-generate").click();
  await expect(page.getByTestId("recovery-sheet")).toBeVisible({ timeout: T });
  const code = ((await page.getByTestId("recovery-code").textContent()) ?? "").trim();
  const kitId = ((await page.getByTestId("recovery-kit-id").textContent()) ?? "").trim();
  expect(code.replace(/-/g, "")).toHaveLength(56);
  await page.getByTestId("recovery-written").check();
  await page.getByTestId("recovery-hide").click();
  return { code, kitId };
}

/** Enrol, print a kit, and turn protection on. */
async function protectProfile(page: Page): Promise<{ code: string; kitId: string }> {
  await enroll(page);
  const kit = await generateKit(page);
  await page.getByTestId("passkey-enable").click();
  await expect(page.getByTestId("passkey-code")).toBeVisible({ timeout: T });
  await page.getByTestId("passkey-code").fill(kit.code);
  await page.getByTestId("passkey-confirm").click();
  await expect(page.getByTestId("passkey-state")).toHaveText("Protected: password + passkey", {
    timeout: T,
  });
  return kit;
}

async function localKeys(page: Page): Promise<string[]> {
  return (await page.evaluate(() => Object.keys(window.localStorage))).sort();
}

const PROTECTED_KEYS = [
  "sigil.webapp.device.v1",
  "sigil.webapp.hwslot.v1",
  "sigil.webapp.vault.v1",
];
const UNPROTECTED_KEYS = ["sigil.webapp.device.v1", "sigil.webapp.vault.v1"];

// ─────────────────────────────────────────────────────────────────────────────

test("1. enable, reload, and unlock with password + passkey", async ({ page }) => {
  const cdp = await enableWebAuthn(page);
  await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-one");
  await addRfcAccount(page);
  await protectProfile(page);

  expect(await localKeys(page)).toEqual(PROTECTED_KEYS);

  await page.reload();
  await expect(page.getByTestId("unlock-submit")).toBeVisible({ timeout: T });
  // The locked screen SAYS a passkey is required — the state and the ciphertext
  // are the same bit.
  await expect(page.getByTestId("unlock-passkey-required")).toBeVisible();

  await page.getByTestId("unlock-password").fill("spec-one");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
  expect(await localKeys(page)).toEqual(PROTECTED_KEYS);
});

test("2. ⭐ THE MUTATION THAT MATTERS: with the authenticator REMOVED, the CORRECT password must FAIL", async ({
  page,
}) => {
  // ⏱️ 60 s of this spec is the product's own WebAuthn ceremony timeout expiring
  // with no authenticator present — wall clock, not work. See NO_AUTHENTICATOR_T.
  test.setTimeout(NO_AUTHENTICATOR_T);
  const cdp = await enableWebAuthn(page);
  const authenticatorId = await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-two");
  await addRfcAccount(page);
  await protectProfile(page);

  // The laptop is stolen / the platform credential is revoked / the profile's
  // passkeys are wiped.
  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });

  await page.reload();
  await expect(page.getByTestId("unlock-submit")).toBeVisible({ timeout: T });
  await page.getByTestId("unlock-password").fill("spec-two"); // CORRECT
  await page.getByTestId("unlock-submit").click();

  // ⛔ It must NOT unlock: the password alone is not a slot.
  await expect(page.getByTestId("unlock-passkey-error")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("vault-view")).toHaveCount(0);

  // ⛔ ...and it must NOT be reported as a wrong password. That is the single
  // worst message for a user whose passkey just died.
  const text = (await page.getByTestId("unlock-passkey-error").textContent()) ?? "";
  expect(text.toLowerCase()).toContain("passkey");
  expect(text.toLowerCase()).not.toContain("wrong password");
  await expect(page.getByTestId("unlock-error")).toHaveCount(0);
});

test("2b. ⭐⭐ THE CIPHERTEXT ACTUALLY CHANGED: the stored containers no longer open with the password ALONE", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-two-b");
  await addRfcAccount(page);
  await protectProfile(page);

  // ⭐⭐ WHY THIS EXISTS, and why spec 2 is not a substitute. Spec 2 proves a
  // ceremony is REQUIRED — it stays green even if the containers are still
  // sealed under the bare password and only a marker file demands the passkey
  // (mutation M3: make `sealingSecret()` fall back to `passwordRef.current`).
  // That would be pure theatre: an attacker who copied `localStorage` discards
  // the marker and attacks the password offline, exactly as before.
  //
  // So model that attacker. Delete the slot, keeping ONLY the two containers,
  // and demand that the correct password does not open them. After a successful
  // enable the password path is dead BY CONSTRUCTION — because the ciphertext
  // changed — not by policy.
  await page.evaluate(() => window.localStorage.removeItem("sigil.webapp.hwslot.v1"));
  await page.reload();
  await expect(page.getByTestId("unlock-submit")).toBeVisible({ timeout: T });
  // No slot: the app does not even ask for a passkey now.
  await expect(page.getByTestId("unlock-passkey-required")).toHaveCount(0);

  await page.getByTestId("unlock-password").fill("spec-two-b"); // CORRECT
  await page.getByTestId("unlock-submit").click();

  await expect(page.getByTestId("unlock-error")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("vault-view")).toHaveCount(0);
});

test("3. ⭐ NO LOCKOUT: the recovery sheet opens it after the passkey is gone, then protection can be re-enabled", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  const first = await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-three");
  await addRfcAccount(page);
  const { code } = await protectProfile(page);

  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: first });
  await page.reload();
  await expect(page.getByTestId("unlock-recovery-code")).toBeVisible({ timeout: T });

  // BREAK-GLASS: the sheet alone, plus a new password for this browser.
  await page.getByTestId("unlock-recovery-code").fill(code);
  await page.getByTestId("unlock-recovery-password").fill("after-the-sheet");
  await page.getByTestId("unlock-recovery-confirm").fill("after-the-sheet");
  await page.getByTestId("unlock-recovery-submit").click();

  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });

  // Protection was DROPPED (the passkey is gone and cannot re-seal a slot), so
  // the profile is back to two containers under the NEW password.
  await expect(page.getByTestId("passkey-state")).toHaveText("Password only");
  expect(await localKeys(page)).toEqual(UNPROTECTED_KEYS);

  // ⭐ And it can be protected again with a BRAND NEW passkey. (The server URL is
  // component state, so the freshly mounted unlocked view is back on its default
  // and has to be pointed at the fake again before the kit lookup can run.)
  await addAuthenticator(cdp);
  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("passkey-enable").click();
  await expect(page.getByTestId("passkey-code")).toBeVisible({ timeout: T });
  await page.getByTestId("passkey-code").fill(code);
  await page.getByTestId("passkey-confirm").click();
  await expect(page.getByTestId("passkey-state")).toHaveText("Protected: password + passkey", {
    timeout: T,
  });

  await page.reload();
  await page.getByTestId("unlock-password").fill("after-the-sheet");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
});

test("4. ⭐ the break-glass is OFFLINE: zero requests leave the page while it runs", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  const authenticatorId = await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-four");
  await addRfcAccount(page);
  const { code } = await protectProfile(page);

  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
  await page.reload();
  await expect(page.getByTestId("unlock-recovery-code")).toBeVisible({ timeout: T });

  // ⭐ Cut the network AND count. `setOffline` alone would not prove the code
  // path has no server dependency — it could simply be failing silently.
  await page.context().setOffline(true);
  const outgoing: string[] = [];
  page.on("request", (r) => outgoing.push(r.url()));

  await page.getByTestId("unlock-recovery-code").fill(code);
  await page.getByTestId("unlock-recovery-password").fill("offline-pass");
  await page.getByTestId("unlock-recovery-confirm").fill("offline-pass");
  await page.getByTestId("unlock-recovery-submit").click();

  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });

  // ⚠️ The two reads below are issued by the UNLOCKED view (AccountBlock and
  // EntitlementBlock refresh on mount) AFTER the break-glass has already
  // completed and the vault is open — they are not part of it, and with the
  // network cut they all fail while the vault stays open. Everything else must be
  // ZERO: the break-glass makes no request of any kind.
  const BACKGROUND_AFTER_UNLOCK = ["/v1/account", "/v1/billing/subscription"];
  const duringBreakGlass = outgoing.filter(
    (u) => !BACKGROUND_AFTER_UNLOCK.some((p) => u.includes(p)),
  );
  expect(duringBreakGlass, "the break-glass must not touch the network at all").toEqual([]);

  await page.context().setOffline(false);
});

test("5. the sheet opens it with the WRONG password (matrix row 5 — strictly better than today)", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  const authenticatorId = await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "the-forgotten-one");
  await addRfcAccount(page);
  const { code } = await protectProfile(page);

  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
  await page.reload();

  // The user does NOT remember the password; the sheet alone is enough.
  await page.getByTestId("unlock-recovery-code").fill(code);
  await page.getByTestId("unlock-recovery-password").fill("a-completely-new-password");
  await page.getByTestId("unlock-recovery-confirm").fill("a-completely-new-password");
  await page.getByTestId("unlock-recovery-submit").click();

  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
});

test("6. enable is REFUSED with no recovery kit — and nothing changes", async ({ page }) => {
  const cdp = await enableWebAuthn(page);
  await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-six");
  await addRfcAccount(page);

  // No enrolment, therefore no account, therefore certainly no kit.
  await page.getByTestId("passkey-enable").click();
  await expect(page.getByTestId("passkey-detail")).toContainText("recovery kit", { timeout: T });

  // Not enrolled, so there is no device-identity container either — the point is
  // that NO hwslot was written and the key set did not change.
  expect(await localKeys(page)).toEqual(["sigil.webapp.vault.v1"]);
  await expect(page.getByTestId("passkey-state")).toHaveText("Password only");

  // The password still opens both containers.
  await page.reload();
  await expect(page.getByTestId("unlock-passkey-required")).toHaveCount(0);
  await page.getByTestId("unlock-password").fill("spec-six");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
});

test("7. enable is REFUSED with a mistyped code — offline, and nothing changes", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-seven");
  await addRfcAccount(page);
  await enroll(page);
  const { code } = await generateKit(page);

  await page.getByTestId("passkey-enable").click();
  await expect(page.getByTestId("passkey-code")).toBeVisible({ timeout: T });

  // Corrupt one character of the body (checksum covers it).
  const raw = code.replace(/-/g, "");
  const bad = (raw[0] === "2" ? "3" : "2") + raw.slice(1);

  const wire: string[] = [];
  page.on("request", (r) => {
    wire.push(r.url());
    const pd = r.postData();
    if (pd) wire.push(pd);
  });

  await page.getByTestId("passkey-code").fill(bad);
  await page.getByTestId("passkey-confirm").click();
  await expect(page.getByTestId("passkey-detail")).toContainText("not a valid recovery code", {
    timeout: T,
  });

  expect(await localKeys(page)).toEqual(UNPROTECTED_KEYS);
  await expect(page.getByTestId("passkey-state")).toHaveText("Password only");
  // ⭐ The code was checksummed on this device: it never reached the wire.
  const haystack = wire.join("\n");
  for (const needle of [bad, bad.toLowerCase(), raw, raw.toLowerCase()]) {
    expect(haystack).not.toContain(needle);
  }

  // The password still opens both containers.
  await page.reload();
  await page.getByTestId("unlock-password").fill("spec-seven");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
});

test("8. PRF unavailable: the control refuses AND the password path is untouched", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  // ⭐ The negative case for free: omitting `hasPrf` makes Chrome report
  // prf.enabled === false at creation and return no results at assertion.
  await addAuthenticator(cdp, { hasPrf: false });

  await page.goto("/?t=59");
  await createVault(page, "spec-eight");
  await addRfcAccount(page);
  await enroll(page);
  await generateKit(page);

  await page.getByTestId("passkey-enable").click();
  await expect(page.getByTestId("passkey-detail")).toContainText("PRF", { timeout: T });
  await expect(page.getByTestId("passkey-state")).toHaveText("Password only");
  expect(await localKeys(page)).toEqual(UNPROTECTED_KEYS);

  // ⭐ A refusal that ALSO broke the password would be a lockout, so assert both.
  await page.reload();
  await page.getByTestId("unlock-password").fill("spec-eight");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
});

test("9. ⭐ THE PRF BYTES ARE LOAD-BEARING: a DIFFERENT passkey whose ceremony SUCCEEDS still cannot unlock it", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  const first = await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-nine");
  await addRfcAccount(page);
  await protectProfile(page);

  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: first });
  await addAuthenticator(cdp); // a fresh device: different PRF key material

  // ⭐⭐ THE POINT OF THIS STEP, and the reason spec 2 is not enough. With an
  // EMPTY new authenticator the ceremony simply fails, which only proves "a
  // ceremony is required" — it stays green even if the PRF output never reaches
  // the KDF at all (mutation M1: stub the PRF contribution to 32 zero bytes).
  // So plant a discoverable credential on the NEW authenticator first: now the
  // ceremony SUCCEEDS and hands back a DIFFERENT 32 bytes, and the only thing
  // that can still refuse the unlock is the PRF output actually being mixed into
  // the sealing secret. Under M1 this unlocks, and this spec goes red.
  await page.evaluate(async () => {
    const enc = new TextEncoder();
    const salt = new Uint8Array(
      await crypto.subtle.digest("SHA-256", enc.encode("sigil-passkey-unlock-v1")),
    );
    await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: "Sigil" },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "other", displayName: "other" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { residentKey: "required", userVerification: "required" },
        extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
      },
    });
  });

  await page.reload();
  await page.getByTestId("unlock-password").fill("spec-nine"); // CORRECT password
  await page.getByTestId("unlock-submit").click();

  await expect(page.getByTestId("unlock-passkey-error")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("vault-view")).toHaveCount(0);

  // The ceremony SUCCEEDED — the refusal came from the slot, so the message must
  // name a different passkey rather than a cancelled prompt.
  const text = (await page.getByTestId("unlock-passkey-error").textContent()) ?? "";
  expect(text).toContain("different passkey");
});

test("10. disable while unlocked returns the profile to password-only", async ({ page }) => {
  const cdp = await enableWebAuthn(page);
  await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-ten");
  await addRfcAccount(page);
  await protectProfile(page);
  expect(await localKeys(page)).toEqual(PROTECTED_KEYS);

  await page.getByTestId("passkey-disable").click();
  await expect(page.getByTestId("passkey-state")).toHaveText("Password only", { timeout: T });
  expect(await localKeys(page)).toEqual(UNPROTECTED_KEYS);

  await page.reload();
  await expect(page.getByTestId("unlock-passkey-required")).toHaveCount(0);
  await page.getByTestId("unlock-password").fill("spec-ten");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
});

test("11. sync refusal: a protected PERSONAL vault cannot be pushed; a SHARED one still can", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-eleven");
  await addRfcAccount(page);
  await protectProfile(page);

  // ⭐ Personal + protected: the container is sealed under a key only this
  // browser holds, so uploading it would deposit ciphertext nobody can read.
  await expect(page.getByTestId("sync-push-blocked")).toBeVisible();
  await expect(page.getByTestId("sync-push")).toBeDisabled();

  // Convert to a SHARED vault: it is sealed under a random 32-byte vault key,
  // which passkey protection deliberately leaves completely alone.
  await page.getByTestId("sharing-convert").click();
  await expect(page.getByTestId("sharing-status")).toContainText("random 32-byte vault key", {
    timeout: T,
  });
  await expect(page.getByTestId("sync-push-blocked")).toHaveCount(0);
  await expect(page.getByTestId("sync-push")).toBeEnabled();

  await page.getByTestId("sync-push").click();
  await expect(page.getByTestId("sync-status")).toContainText("Pushed sealed container", {
    timeout: T,
  });

  // ⭐ PROVE the pushed bytes are NOT CMK-sealed: they are byte-identical to the
  // stored container, which the VAULT KEY opens. (Sharing is untouched.)
  const same = await page.evaluate(async (base) => {
    const stored = window.localStorage.getItem("sigil.webapp.vault.v1") ?? "";
    const res = await fetch(`${base}/v1/vaults/passkey-vault/ops?since=0&limit=10`);
    const json = await res.json();
    const last = json.ops[json.ops.length - 1];
    return last.blob === stored;
  }, fake.baseUrl);
  expect(same, "the pushed container must be the stored one, verbatim").toBe(true);
});

test("12. BE/BS honesty: a BACKUP-ELIGIBLE passkey must not be described as 'this device only'", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  // ⭐ The virtual authenticator really does set the BE/BS flags in
  // authenticatorData — verified live, so this is not a stubbed assertion.
  await addAuthenticator(cdp, { backupEligible: true });

  await page.goto("/?t=59");
  await createVault(page, "spec-twelve");
  await addRfcAccount(page);
  await protectProfile(page);

  const scope = (await page.getByTestId("passkey-scope").textContent()) ?? "";
  expect(scope.toLowerCase()).not.toContain("this device only");
  expect(scope.toLowerCase()).toContain("password manager");

  // And the flags are re-read at EVERY ceremony, not cached from enable time.
  await page.reload();
  await page.getByTestId("unlock-password").fill("spec-twelve");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
  const after = (await page.getByTestId("passkey-scope").textContent()) ?? "";
  expect(after.toLowerCase()).not.toContain("this device only");
});

test("13. ⚠️ RELINK: revoking the linked kit raises the break-glass-is-gone banner", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-thirteen");
  await addRfcAccount(page);
  const { kitId } = await protectProfile(page);

  // Retire the sheet this browser is linked to. NOTHING about the passkey or the
  // containers changes — that is exactly what makes this hazard silent.
  await page.getByTestId("recovery-revoke-kit").fill(kitId);
  await page.getByTestId("recovery-revoke").click();
  // ⚠️ Wait for the SUCCESS wording, not a substring of "Revoking the kit…" — the
  // in-progress message matched, so the reload could race ahead of the revoke.
  await expect(page.getByTestId("recovery-status")).toContainText(`Revoked kit ${kitId}`, {
    timeout: T,
  });

  await page.reload();
  await page.getByTestId("unlock-password").fill("spec-thirteen");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });

  // The server URL is component state and resets to its default on reload, so the
  // check has nowhere to ask until it is pointed back at the server. That is
  // deliberate: unreachable means SAY NOTHING rather than cry wolf.
  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await expect(page.getByTestId("passkey-state")).toHaveText("Protected: password + passkey");

  // The vault still opens — and the UI SAYS the break-glass no longer will.
  await expect(page.getByTestId("passkey-relink")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("passkey-relink")).toContainText("re-link this browser");
});

test("14. ⚠️ REPRINT: generating a NEW kit re-seals the slot in the SAME operation", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  const authenticatorId = await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-fourteen");
  await addRfcAccount(page);
  const { code: oldCode } = await protectProfile(page);

  // ⭐ A NEW sheet means NEW printed bytes and therefore a NEW container master
  // key. If the slot were not re-sealed here, the containers would keep opening
  // with the passkey while the BREAK-GLASS silently died — the worst shape of
  // failure, because nothing would tell anyone.
  await page.getByTestId("recovery-generate").click();
  await expect(page.getByTestId("recovery-sheet")).toBeVisible({ timeout: T });
  const newCode = ((await page.getByTestId("recovery-code").textContent()) ?? "").trim();
  expect(newCode).not.toEqual(oldCode);
  await expect(page.getByTestId("recovery-status")).toContainText("re-linked to the NEW sheet", {
    timeout: T,
  });
  await page.getByTestId("recovery-written").check();
  await page.getByTestId("recovery-hide").click();

  // Lose the passkey, then prove which sheet is the live one.
  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId });
  await page.reload();
  await expect(page.getByTestId("unlock-recovery-code")).toBeVisible({ timeout: T });

  await page.getByTestId("unlock-recovery-code").fill(oldCode);
  await page.getByTestId("unlock-recovery-password").fill("stale-sheet");
  await page.getByTestId("unlock-recovery-confirm").fill("stale-sheet");
  await page.getByTestId("unlock-recovery-submit").click();
  await expect(page.getByTestId("unlock-recovery-error")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("vault-view")).toHaveCount(0);

  await page.getByTestId("unlock-recovery-code").fill(newCode);
  await page.getByTestId("unlock-recovery-password").fill("fresh-sheet");
  await page.getByTestId("unlock-recovery-confirm").fill("fresh-sheet");
  await page.getByTestId("unlock-recovery-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
});

test("15. ⭐⭐ AND, NEVER OR: with the passkey PRESENT and ANSWERING, a WRONG password must not open it", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-fifteen");
  await addRfcAccount(page);
  await protectProfile(page);

  // ⭐⭐ WHY THIS EXISTS. Spec 9 proves the PRF half of `PRF ‖ utf8(password)` is
  // load-bearing; NOTHING proved the password half was. Deleting `utf8(password)`
  // from `hwSlotSecret()` — sealing and opening the slot under the 32 PRF bytes
  // ALONE — left the ENTIRE suite green: 37 passed, every passkey spec, all
  // three leak sweeps, wrap-gate, recovery, a11y, cors and entitlement. Under
  // that mutation the feature silently degrades to passkey-ONLY, so a protected
  // profile opens with ANY password whenever the authenticator answers, which is
  // precisely the attacker the "AND, never OR" argument is written against.
  //
  // The authenticator is deliberately still attached: the ceremony SUCCEEDS and
  // hands back the RIGHT 32 bytes, so the only thing left that can refuse this
  // unlock is the password being mixed into the slot secret.
  await page.reload();
  await expect(page.getByTestId("unlock-submit")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("unlock-passkey-required")).toBeVisible();

  await page.getByTestId("unlock-password").fill("spec-fifteen-WRONG");
  await page.getByTestId("unlock-submit").click();

  await expect(page.getByTestId("unlock-passkey-error")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("vault-view")).toHaveCount(0);
  // The slot refused, not the ceremony — so the wording is the ambiguous one,
  // which is the honest one: a wrong password and a different passkey are
  // cryptographically indistinguishable here.
  const text = (await page.getByTestId("unlock-passkey-error").textContent()) ?? "";
  expect(text).toContain("different passkey");

  // ⭐ And this is not a broken profile: the RIGHT password, same passkey, opens
  // it. Without this the spec would also pass on a profile that never opens.
  await page.getByTestId("unlock-password").fill("spec-fifteen");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
});

test("16. ⛔ NO STALE SLOT: a brand-new vault created beside an orphaned slot must not be bricked", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-sixteen");
  await addRfcAccount(page);
  await protectProfile(page);

  // The two containers are lost while the SLOT survives — a partial clear, a
  // quota eviction, a botched restore. The initial phase is decided from the
  // VAULT key alone, so the app shows SETUP with the old slot still in place.
  await page.evaluate(() => {
    window.localStorage.removeItem("sigil.webapp.vault.v1");
    window.localStorage.removeItem("sigil.webapp.device.v1");
  });
  await page.reload();
  await expect(page.getByTestId("setup-submit")).toBeVisible({ timeout: T });

  await createVault(page, "brand-new");
  await addRfcAccount(page);

  // ⭐ THE FIX: creating a vault clears the slot. Before it, the keys here were
  // ["sigil.webapp.hwslot.v1", "sigil.webapp.vault.v1"] and BOTH doors were shut
  // — the correct new password failed the passkey step, and the sheet reported
  // that the key it derives does not open these containers.
  expect(await localKeys(page)).toEqual(["sigil.webapp.vault.v1"]);

  await page.reload();
  await expect(page.getByTestId("unlock-submit")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("unlock-passkey-required")).toHaveCount(0);
  await page.getByTestId("unlock-password").fill("brand-new");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
});

test("17. ⛔ DELETING the slot must not delete the way out — and the failure must not be called a wrong password", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-seventeen");
  await addRfcAccount(page);
  const { code } = await protectProfile(page);

  // Delete the slot. Both containers stay CMK-sealed, so the CORRECT password
  // does not open them — and the break-glass form used to be gated on the very
  // marker that just vanished, taking the only offline escape out of the DOM.
  await page.evaluate(() => window.localStorage.removeItem("sigil.webapp.hwslot.v1"));
  await page.reload();
  await expect(page.getByTestId("unlock-submit")).toBeVisible({ timeout: T });

  await page.getByTestId("unlock-password").fill("spec-seventeen"); // CORRECT
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("unlock-error")).toBeVisible({ timeout: T });

  const err = (await page.getByTestId("unlock-error").textContent()) ?? "";
  expect(err.toLowerCase()).not.toContain("wrong password or tampered");
  expect(err.toLowerCase()).toContain("recovery sheet");

  // ⭐ THE ESCAPE IS STILL THERE, and it works.
  await expect(page.getByTestId("unlock-recovery-code")).toBeVisible();
  await page.getByTestId("unlock-recovery-code").fill(code);
  await page.getByTestId("unlock-recovery-password").fill("after-the-delete");
  await page.getByTestId("unlock-recovery-confirm").fill("after-the-delete");
  await page.getByTestId("unlock-recovery-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
});

test("18. ...and CORRUPTING the slot behaves identically — the two must never diverge again", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-eighteen");
  await addRfcAccount(page);
  const { code } = await protectProfile(page);

  // ⚠️ Corrupt and delete are the SAME artifact failing in two mundane ways, and
  // before this pair of specs they behaved completely differently: corruption
  // was recoverable while deletion was terminal. Nothing in the design justified
  // that difference, which is exactly why it needs pinning from both sides.
  await page.evaluate(() =>
    window.localStorage.setItem("sigil.webapp.hwslot.v1", "bm90LWEtY29udGFpbmVy"),
  );
  await page.reload();
  await expect(page.getByTestId("unlock-recovery-code")).toBeVisible({ timeout: T });

  await page.getByTestId("unlock-recovery-code").fill(code);
  await page.getByTestId("unlock-recovery-password").fill("after-the-corruption");
  await page.getByTestId("unlock-recovery-confirm").fill("after-the-corruption");
  await page.getByTestId("unlock-recovery-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
  // Recovered profiles are password-only again, and the damaged slot is gone.
  expect(await localKeys(page)).toEqual(UNPROTECTED_KEYS);
});

test("19. ⛔ PULL is refused too: the only copy of a protected personal vault cannot be silently overwritten", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-nineteen");
  await addRfcAccount(page);
  await protectProfile(page);

  // Push is refused because nothing else could read what was uploaded — which is
  // precisely what makes the LOCAL container the only copy. Leaving the adjacent
  // Pull enabled meant one click replaced it with a stale pre-protection
  // container, or (on a mistyped vault id) with bytes nothing in this browser can
  // open. The kit recovers keys, not data, so that loss is permanent.
  await expect(page.getByTestId("sync-push")).toBeDisabled();
  await expect(page.getByTestId("sync-pull")).toBeDisabled();
  const notice = (await page.getByTestId("sync-push-blocked").textContent()) ?? "";
  expect(notice.toLowerCase()).toContain("both directions");
  expect(notice.toLowerCase()).toContain("only");

  // The stored container is untouched, and the escape hatch is the same one Push
  // offers: converting to a SHARED vault restores both directions.
  const before = await page.evaluate(() => window.localStorage.getItem("sigil.webapp.vault.v1"));
  await page.getByTestId("sharing-convert").click();
  await expect(page.getByTestId("sharing-status")).toContainText("random 32-byte vault key", {
    timeout: T,
  });
  await expect(page.getByTestId("sync-pull")).toBeEnabled();
  const after = await page.evaluate(() => window.localStorage.getItem("sigil.webapp.vault.v1"));
  expect(after).not.toEqual(before); // re-sealed under the vault key, not pulled over
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
});

test("20. ⛔ MIXED STATE: the break-glass must not orphan the device identity", async ({ page }) => {
  const cdp = await enableWebAuthn(page);
  await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-twenty");
  await addRfcAccount(page);
  await enroll(page);
  const deviceId = ((await page.getByTestId("device-id").textContent()) ?? "").trim();
  expect(deviceId).not.toEqual("");

  const kit = await generateKit(page);
  // The identity container EXACTLY as it is under the password, captured before
  // protection re-seals it.
  const passwordSealed = await page.evaluate(() =>
    window.localStorage.getItem("sigil.webapp.device.v1"),
  );

  await page.getByTestId("passkey-enable").click();
  await expect(page.getByTestId("passkey-code")).toBeVisible({ timeout: T });
  await page.getByTestId("passkey-code").fill(kit.code);
  await page.getByTestId("passkey-confirm").click();
  await expect(page.getByTestId("passkey-state")).toHaveText("Protected: password + passkey", {
    timeout: T,
  });

  // ⭐ CONSTRUCT THE MIXED STATE the design itself documents as reachable: enable
  // writes hwslot → vault → device and is NOT atomic, so an interruption leaves
  // the identity sealed under the OLD password beside a CMK-sealed vault.
  // Restoring the pre-enable container reproduces that byte for byte.
  await page.evaluate(
    (v: string) => window.localStorage.setItem("sigil.webapp.device.v1", v),
    passwordSealed ?? "",
  );
  await page.reload();
  await expect(page.getByTestId("unlock-recovery-code")).toBeVisible({ timeout: T });

  // The break-glass with a DIFFERENT new password. Before the fix it tried the
  // CMK and nothing else, so the Ed25519 seed, the hybrid secret and every
  // accepted vault key became permanently unreadable — with no message at all.
  await page.getByTestId("unlock-recovery-code").fill(kit.code);
  await page.getByTestId("unlock-recovery-current").fill("spec-twenty"); // the OLD one
  await page.getByTestId("unlock-recovery-password").fill("after-the-interruption");
  await page.getByTestId("unlock-recovery-confirm").fill("after-the-interruption");
  await page.getByTestId("unlock-recovery-submit").click();

  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
  // ⭐ THE IDENTITY SURVIVED — and nothing had to warn about an orphan.
  await expect(page.getByTestId("device-id")).toHaveText(deviceId);
  await expect(page.getByTestId("global-notice")).toHaveCount(0);

  // ...and it was RE-SEALED under the new password, not merely displayed.
  await page.reload();
  await expect(page.getByTestId("unlock-submit")).toBeVisible({ timeout: T });
  await page.getByTestId("unlock-password").fill("after-the-interruption");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("device-id")).toHaveText(deviceId, { timeout: T });
});

test("21. a passkey that lost PRF AFTER protection is pointed at the sheet, not told 'nothing was changed'", async ({
  page,
}) => {
  const cdp = await enableWebAuthn(page);
  const first = await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-twentyone");
  await addRfcAccount(page);
  await protectProfile(page);

  // The credential migrates to an authenticator without PRF — a real outcome of
  // a password-manager or platform-account move. The ceremony still SUCCEEDS;
  // only the derived key is missing.
  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: first });
  await addAuthenticator(cdp, { hasPrf: false });
  await page.evaluate(async () => {
    const enc = new TextEncoder();
    const salt = new Uint8Array(
      await crypto.subtle.digest("SHA-256", enc.encode("sigil-passkey-unlock-v1")),
    );
    await navigator.credentials.create({
      publicKey: {
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        rp: { name: "Sigil" },
        user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "moved", displayName: "moved" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: { residentKey: "required", userVerification: "required" },
        extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
      },
    });
  });

  await page.reload();
  await expect(page.getByTestId("unlock-submit")).toBeVisible({ timeout: T });
  await page.getByTestId("unlock-password").fill("spec-twentyone");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("unlock-passkey-error")).toBeVisible({ timeout: T });

  // ⛔ The ENABLE-flow refusal ("Nothing was changed") is a lie here: the vault is
  // already sealed and the user is locked out of it. This state must route to the
  // recovery wording, exactly as `ceremony_failed` does.
  const text = (await page.getByTestId("unlock-passkey-error").textContent()) ?? "";
  expect(text).not.toContain("Nothing was changed");
  expect(text.toLowerCase()).toContain("recovery sheet");
});

// ─────────────────────────────────────────────────────────────────────────────
// 22. ⭐⭐ THE OTHER INTERRUPTION POINT — and the one where BOTH doors are under
// test at once. Enable writes hwslot → vault → device and is not atomic. Spec 20
// reproduces a crash AFTER the vault re-seal; this reproduces a crash BEFORE it,
// so the slot is on disk while BOTH containers are still PASSWORD-sealed. Then
// the passkey goes away, which is the only scenario the printed sheet exists for.
//
// In that state door 1 (the correct password) is legitimately refused: `unlock()`
// runs the ceremony BEFORE it can try any secret, and the ceremony is what died.
// So the sheet is the ONLY door left, and it has to work with the container it
// actually finds — a password-sealed one — which is exactly why
// `unlockWithRecoverySheet` tries the CMK *and* the supplied current password.
//
// ⚠️ HOW THIS SPEC IS WRITTEN IS PART OF THE POINT. An earlier probe of this
// scenario sampled the result with `locator.isVisible({ timeout })` and reported
// a total lockout. `isVisible()` does NOT wait — Playwright's own typings mark
// that option `@deprecated This option is ignored` — so it read the DOM in the
// same tick as the click, before the break-glass had begun its first Argon2id
// derivation. Raising the number changed nothing because the number was never
// read, which made the artefact look like proof that the number was innocent.
// Every terminal assertion here therefore WAITS: `toBeVisible`, never `isVisible`.
// ─────────────────────────────────────────────────────────────────────────────
test("22. ⛔ NO LOCKOUT: hwslot written, BOTH containers still password-sealed, passkey gone", async ({
  page,
}) => {
  // ⏱️ Same fixed 60 s WebAuthn wait as spec 2. See NO_AUTHENTICATOR_T.
  test.setTimeout(NO_AUTHENTICATOR_T);
  const cdp = await enableWebAuthn(page);
  const auth = await addAuthenticator(cdp);

  await page.goto("/?t=59");
  await createVault(page, "spec-twentytwo");
  await addRfcAccount(page);
  await enroll(page);
  const deviceId = ((await page.getByTestId("device-id").textContent()) ?? "").trim();
  expect(deviceId).not.toEqual("");
  const kit = await generateKit(page);

  // Both containers EXACTLY as they are under the password, captured before
  // protection re-seals either of them.
  const vaultBefore = await page.evaluate(() =>
    window.localStorage.getItem("sigil.webapp.vault.v1"),
  );
  const deviceBefore = await page.evaluate(() =>
    window.localStorage.getItem("sigil.webapp.device.v1"),
  );

  await page.getByTestId("passkey-enable").click();
  await expect(page.getByTestId("passkey-code")).toBeVisible({ timeout: T });
  await page.getByTestId("passkey-code").fill(kit.code);
  await page.getByTestId("passkey-confirm").click();
  await expect(page.getByTestId("passkey-state")).toHaveText("Protected: password + passkey", {
    timeout: T,
  });

  // ⭐ CONSTRUCT the crash-after-hwslot state: put both password-sealed containers
  // back and KEEP the slot. This is the state completePasskeyProtection() names in
  // its own comment as reachable.
  await page.evaluate((v: string) => window.localStorage.setItem("sigil.webapp.vault.v1", v), vaultBefore ?? "");
  await page.evaluate((v: string) => window.localStorage.setItem("sigil.webapp.device.v1", v), deviceBefore ?? "");
  expect(await localKeys(page)).toEqual(PROTECTED_KEYS);

  // ⛔ NOW THE PASSKEY GOES AWAY.
  await cdp.send("WebAuthn.removeVirtualAuthenticator", { authenticatorId: auth });
  await page.reload();
  await expect(page.getByTestId("unlock-submit")).toBeVisible({ timeout: T });

  // DOOR 1 — the CORRECT password. Refused at the ceremony, and it must say so:
  // telling this user "wrong password" sends them to retype a correct password
  // forever while the one thing that works sits on the same screen.
  await page.getByTestId("unlock-password").fill("spec-twentytwo");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("unlock-passkey-error")).toBeVisible({ timeout: T });
  expect((await page.getByTestId("unlock-passkey-error").textContent() ?? "").toLowerCase()).toContain(
    "recovery sheet",
  );
  await expect(page.getByTestId("vault-view")).toHaveCount(0);

  // DOOR 2 — the printed sheet plus the correct current password. THIS MUST OPEN.
  await page.getByTestId("unlock-recovery-code").fill(kit.code);
  await page.getByTestId("unlock-recovery-current").fill("spec-twentytwo");
  await page.getByTestId("unlock-recovery-password").fill("twentytwo-after");
  await page.getByTestId("unlock-recovery-confirm").fill("twentytwo-after");
  await page.getByTestId("unlock-recovery-submit").click();

  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
  // The identity came through too — nothing was orphaned, so nothing warns.
  await expect(page.getByTestId("device-id")).toHaveText(deviceId);
  await expect(page.getByTestId("global-notice")).toHaveCount(0);

  // ...and protection is genuinely OFF: the slot is gone (leaving it would demand
  // a ceremony this profile can no longer perform) and the NEW password alone
  // re-opens both containers after a reload.
  expect(await localKeys(page)).toEqual(UNPROTECTED_KEYS);
  await page.reload();
  await expect(page.getByTestId("unlock-submit")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("unlock-passkey-required")).toHaveCount(0);
  await page.getByTestId("unlock-password").fill("twentytwo-after");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
  await expect(page.getByTestId("device-id")).toHaveText(deviceId);
});

// ─────────────────────────────────────────────────────────────────────────────
// 23. ⛔ A SURVIVING DEVICE IDENTITY MUST NOT BE OVERWRITTEN OR SILENTLY IGNORED.
//
// The initial phase is decided from the VAULT container alone, so a profile whose
// vault is gone while the identity survives (a partial clear, a quota eviction, a
// botched restore) lands on SETUP with the Ed25519 seed, the hybrid secret and
// every accepted vault key still on disk, sealed under the OLD password. Spec 16
// covers the sibling case for the hwslot — which is CLEARED, because a brand-new
// vault has no passkey behind it. The identity is the opposite call: it is the
// only copy of key material, so it is LEFT BYTE-FOR-BYTE IN PLACE and ANNOUNCED.
//
// ⚠️ Spec 20 deletes BOTH containers, so the surviving-identity case was untested;
// nothing would have caught `createVault` growing a `removeItem(DEVICE_KEY)`.
// ─────────────────────────────────────────────────────────────────────────────
test("23. ⛔ clearing ONLY the vault must not silently destroy the device identity", async ({
  page,
}) => {
  await enableWebAuthn(page);

  await page.goto("/?t=59");
  await createVault(page, "spec-twentythree");
  await addRfcAccount(page);
  await enroll(page);
  const deviceId = ((await page.getByTestId("device-id").textContent()) ?? "").trim();
  expect(deviceId).not.toEqual("");
  const identityBefore = await page.evaluate(() =>
    window.localStorage.getItem("sigil.webapp.device.v1"),
  );
  expect(identityBefore).not.toBeNull();

  // ⭐ THE PARTIAL CLEAR: the vault container alone disappears.
  await page.evaluate(() => window.localStorage.removeItem("sigil.webapp.vault.v1"));
  await page.reload();
  await expect(page.getByTestId("setup-submit")).toBeVisible({ timeout: T });

  // The user does the only thing this screen offers: makes a new vault, with a
  // DIFFERENT password — which cannot open the identity sitting beside it.
  await createVault(page, "twentythree-brand-new");

  // ⭐ IT IS ANNOUNCED. A permanent loss a human is told about is recoverable by a
  // human; a silent one is not — and this notice is deliberately top-level, so it
  // outlives the screen that produced it.
  const notice = page.getByTestId("global-notice");
  await expect(notice).toBeVisible({ timeout: T });
  const text = ((await notice.textContent()) ?? "").toLowerCase();
  expect(text).toContain("device identity");
  expect(text).toContain("left in place");
  // It must point at the two things that DO still work, not just report a loss.
  expect(text).toContain("recovery sheet");

  // ⭐⭐ AND IT IS STILL THERE, BYTE FOR BYTE. Never deleted, never overwritten by
  // the new password's identity — this is the only copy of the seed, the hybrid
  // secret and every accepted vault key.
  expect(
    await page.evaluate(() => window.localStorage.getItem("sigil.webapp.device.v1")),
  ).toEqual(identityBefore);
  // The new vault is genuinely a NEW profile: it holds no identity it cannot open.
  await expect(page.getByTestId("device-id")).toHaveCount(0);

  // CONTROL: an ordinary fresh profile — no surviving identity — must NOT warn.
  // A banner that fires when nothing is wrong is a banner people stop reading.
  await page.evaluate(() => window.localStorage.clear());
  await page.reload();
  await expect(page.getByTestId("setup-submit")).toBeVisible({ timeout: T });
  await createVault(page, "twentythree-clean");
  await expect(page.getByTestId("global-notice")).toHaveCount(0);
});

test("24. ⭐⭐ THE ATTACHMENT IS REPORTED, NOT INFERRED: a SECURITY KEY must not be called 'this device only'", async ({
  page,
}) => {
  /**
   * ⛔ WHY THIS SPEC EXISTS, AND WHY IT IS SHAPED LIKE THIS.
   *
   * `authenticatorAttachment` answers the one question a user actually has about
   * a second factor: *what do I have to keep safe?* The app used to INVENT it:
   *
   *     attachment: assertion.backupEligible ? "" : "platform"
   *
   * — so every holder of a non-syncing removable SECURITY KEY was told their
   * passkey lived "on this device only", which is the exact opposite of true and
   * the exact opposite of useful. Phase 59 replaced it with the value the
   * ceremony actually reported (`assertion.authenticatorAttachment`).
   *
   * An independent verifier then reverted that one line in `authenticator.tsx`
   * and the whole suite stayed green — because spec 12 uses a BACKUP-ELIGIBLE
   * authenticator, and `describeProtectionScope` short-circuits on that flag
   * before it ever looks at the attachment. The inference and the truth agreed
   * everywhere the suite looked.
   *
   * ⭐ SO THIS SPEC MAKES THEM DISAGREE. A `usb` virtual authenticator with
   * backup eligibility OFF gives:
   *
   *     REAL       -> "cross-platform"  -> "a removable security key"
   *     FABRICATED -> "platform"        -> "on this device only"
   *
   * There is no way for a fabricated value to coincidentally match, so the
   * mutation cannot survive.
   */
  const cdp = await enableWebAuthn(page);
  await addAuthenticator(cdp, { transport: "usb", backupEligible: false });

  await page.goto("/?t=59");
  await createVault(page, "spec-twentyfour");
  await addRfcAccount(page);
  await protectProfile(page);

  // ⭐ THE MUTATION-SENSITIVE PATH IS UNLOCK, not enable: the reverted line was
  // in `unlock()`, where the assertion's own report becomes `protection`. So
  // reload, unlock, and read the sentence the user is shown afterwards.
  await page.reload();
  await expect(page.getByTestId("unlock-submit")).toBeVisible({ timeout: T });
  await page.getByTestId("unlock-password").fill("spec-twentyfour");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });

  const scope = ((await page.getByTestId("passkey-scope").textContent()) ?? "").toLowerCase();
  expect(scope).toContain("removable security key");
  // ⛔ The sentence the fabrication produced. If this ever comes back, a user is
  // being told to worry about the wrong object.
  expect(scope).not.toContain("this device only");

});

test("24b. CONTROL: a genuine PLATFORM authenticator IS still described as 'this device only'", async ({
  page,
}) => {
  // ⭐ Without this, spec 24's `not.toContain("this device only")` could pass for
  // a boring reason — e.g. the app never says it at all. Same code path, same
  // assertion target, OPPOSITE answer, driven only by the transport.
  //
  // ⚠️ It is a SEPARATE test rather than a second half of 24 on purpose: a
  // ceremony with `allowCredentials: []` matches ANY discoverable credential for
  // the origin, so two virtual authenticators attached to one page make the
  // answer non-deterministic. One authenticator per profile.
  const cdp = await enableWebAuthn(page);
  await addAuthenticator(cdp, { transport: "internal", backupEligible: false });

  await page.goto("/?t=59");
  await createVault(page, "spec-twentyfour-platform");
  await addRfcAccount(page);
  await protectProfile(page);

  await page.reload();
  await expect(page.getByTestId("unlock-submit")).toBeVisible({ timeout: T });
  await page.getByTestId("unlock-password").fill("spec-twentyfour-platform");
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });

  const scope = ((await page.getByTestId("passkey-scope").textContent()) ?? "").toLowerCase();
  expect(scope).toContain("this device only");
  expect(scope).not.toContain("removable security key");
});
