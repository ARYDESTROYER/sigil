import { expect, test, type Page } from "@playwright/test";
// @ts-expect-error — plain .mjs test helper shared with the extension suite.
import { startFakeSigild } from "../../../../sigil-wasm/test/fake-sigild.mjs";

/**
 * ⭐⭐ PHASE 60, THROUGH THE REAL WEBAPP UI.
 *
 * THE VULNERABILITY, reproduced with the shipped `sigil` binary and nothing else:
 *
 *     sigil hybrid-keygen --out b.hybrid        # victim; only b.hybrid.pub is published
 *     sigil hybrid-seal --recipient-pub b.hybrid.pub --in attacker_key.bin --out forged.env
 *     -> 1226 bytes, magic SIGILhyb, byte-shaped IDENTICALLY to a genuine wrap
 *     sigil hybrid-open --key b.hybrid --in forged.env   # exit 0, the attacker's key
 *
 * A wrapped vault key was an ANONYMOUS (ephemeral-static) container under one
 * FIXED AAD, and the only check on the recovered plaintext was `length === 32`.
 * Anyone who could read a device's PUBLISHED hybrid public key — which sigild
 * serves to every authenticated device — could deposit a vault key THEY chose,
 * and everything the victim wrote afterwards was readable by them. ADR 0038
 * pinning did not help: the accept path fetched no hybrid key at all.
 *
 * ⚠️ WHY THIS FILE DRIVES THE UI. Phase 59 shipped product-level fixes that were
 * fully revertible while the whole gate stayed green, because every mutation only
 * went red inside the `.mjs` modules. So this asserts on the WEBAPP's OWN
 * behaviour: `authenticator.tsx`'s `accept()` must go through the sender gate,
 * and its refusal must render in its OWN blocking block
 * (`sharing-envelope-refusal`) — not in the generic status line and not in the
 * pin-mismatch alarm. Revert either and this goes RED.
 *
 * ⚠️ SCOPE, HONESTLY. The forgeries here are built by DOWNGRADING a real
 * envelope's version byte and by withholding the sender, because a page on the
 * webapp origin cannot dynamically import the bundled wasm to mint a genuine
 * anonymous container. That is enough to pin the PRODUCT-level control (the
 * version gate and the sender resolution both run before any decryption). The
 * CRYPTOGRAPHIC proof — a genuinely anonymous container minted from the victim's
 * published public key alone, refused by the real `acceptVault` — lives in
 * `sigil-wasm/test/sharing-interop.mjs`, in the extension's
 * `tests/envelope-auth.spec.mjs` (which CAN import its own vendored wasm), and in
 * the core/CLI unit tests.
 *
 * The server is the fake; every cryptographic step is real and in the wasm.
 */

const T = 60_000;
const RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_CODE = "287082";
const WEBAPP_ORIGIN = "http://localhost:3210";

type Envelope = { bytes: Buffer; sender: string; createdAt: string };
type Fake = {
  baseUrl: string;
  close: () => Promise<void>;
  state: {
    envelopes: Map<string, Envelope>;
    hybridKeys: Map<string, { x25519_public_key: string; mlkem_encaps_key: string }>;
  };
};

let fake: Fake;

test.beforeAll(async () => {
  fake = (await startFakeSigild({ corsOrigins: [WEBAPP_ORIGIN] })) as Fake;
});

test.afterAll(async () => {
  await fake?.close();
});

/** A profile with a vault, an enrolled device, a published hybrid key and a SHARED vault. */
async function setup(page: Page, password: string, vaultId: string): Promise<string> {
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

  // Publishing is what makes this browser a possible RECIPIENT: it is the public
  // key an attacker would mint a forgery to, and the key a real sender wraps to.
  await page.getByTestId("sharing-publish").click();
  await expect(page.getByTestId("sharing-status")).toContainText("Published this device", {
    timeout: T,
  });
  await page.getByTestId("sharing-convert").click();
  await expect(page.getByTestId("sharing-status")).toContainText("random 32-byte vault key", {
    timeout: T,
  });
  return ((await page.getByTestId("sharing-device-id").textContent()) ?? "").trim();
}

/**
 * Make the browser deposit a REAL, authenticated envelope addressed to itself, so
 * the test has genuine bytes to tamper with. Sharing to your own device id is an
 * ordinary, permitted operation — the recipient is just you.
 */
async function depositRealEnvelopeToSelf(page: Page, deviceId: string): Promise<void> {
  await page.getByTestId("sharing-recipient").fill(deviceId);
  await page.getByTestId("sharing-share").click();
  await expect(page.getByTestId("sharing-status")).toContainText("Shared", { timeout: T });
}

test("an UNAUTHENTICATED envelope is refused by the real Accept button, in its own block, and nothing is stored", async ({
  page,
}: {
  page: Page;
}) => {
  const VAULT = "envauth-webapp-a";
  const deviceId = await setup(page, "envauth-webapp-one", VAULT);
  expect(deviceId).toMatch(/^dev_/);

  await depositRealEnvelopeToSelf(page, deviceId);
  const key = `${VAULT}\u0000${deviceId}`;
  const real = fake.state.envelopes.get(key);
  expect(real).toBeTruthy();
  // A genuine wrap is an AUTHENTICATED (version 2) SIGILhyb container.
  expect(real!.bytes.subarray(0, 8).toString("latin1")).toBe("SIGILhyb");
  expect(real!.bytes[8]).toBe(2);

  // ⭐ THE TAMPER. Present the SAME bytes as a version-1 (ANONYMOUS) container —
  // the shape anyone holding only this device's published public key can mint.
  // The client must refuse on the KIND, before any decryption is attempted.
  const downgraded = Buffer.from(real!.bytes);
  downgraded[8] = 1;
  fake.state.envelopes.set(key, { ...real!, bytes: downgraded });

  // ── THE PRODUCT PATH: click Accept, exactly as a user would. ───────────────
  await page.getByTestId("sharing-accept").click();

  // 1. THE REFUSAL RENDERS IN ITS OWN BLOCK — not the status line, not the alarm.
  const refusal = page.getByTestId("sharing-envelope-refusal");
  await expect(refusal).toBeVisible({ timeout: T });
  await expect(refusal).toContainText("NOT AUTHENTICATED");
  await expect(refusal).toContainText("no sender");
  // 2. AND IT IS NAMED AS NEITHER A SIGN-IN NOR A PERMISSION PROBLEM.
  await expect(refusal).toContainText("not a sign-in problem");
  await expect(refusal).toContainText("not a permission problem");
  // The pin-mismatch alarm stays DOWN: no key changed.
  await expect(page.getByTestId("sharing-pin-mismatch")).toHaveCount(0);

  // 3. NOTHING WAS ADOPTED, and localStorage still holds only SEALED containers.
  await expect(page.getByTestId("sharing-status")).toContainText("REFUSED", { timeout: T });
  const values = await page.evaluate(() =>
    Object.keys(window.localStorage).map((k) => window.localStorage.getItem(k) ?? ""),
  );
  expect(values.length).toBeGreaterThan(0);
  for (const v of values) {
    expect(Buffer.from(v, "base64").subarray(0, 8).toString("latin1")).toBe("SIGILcli");
  }
});

test("an envelope the server attributes to NOBODY is refused, and the UI offers the way out it names", async ({
  page,
}: {
  page: Page;
}) => {
  const VAULT = "envauth-webapp-b";
  const deviceId = await setup(page, "envauth-webapp-two", VAULT);

  await depositRealEnvelopeToSelf(page, deviceId);
  const key = `${VAULT}\u0000${deviceId}`;
  const real = fake.state.envelopes.get(key)!;

  // ⚠️ THE SERVER NAMES NOBODY. sigild records the depositing device, but a
  // client must never TRUST that field to be there — a hostile or buggy server
  // can omit it, and "unwrap from whoever" is precisely the anonymous behaviour
  // this phase removed. An empty sender must REFUSE, not fall back.
  fake.state.envelopes.set(key, { ...real, sender: "" });

  await page.getByTestId("sharing-accept").click();

  const refusal = page.getByTestId("sharing-envelope-refusal");
  await expect(refusal).toBeVisible({ timeout: T });
  await expect(refusal).toContainText("which device deposited");
  // ⭐ The UI offers the remedy it just described.
  await expect(page.getByTestId("sharing-accept-from")).toBeVisible();

  // ...and naming the sender by hand lets the SAME envelope through, so the
  // refusal above was about attribution and nothing else.
  await page.getByTestId("sharing-accept-from").fill(deviceId);
  await page.getByTestId("sharing-accept").click();
  await expect(page.getByTestId("sharing-status")).toContainText("AUTHENTICATED as coming from", {
    timeout: T,
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// ⭐⭐ PHASE 60 SYMMETRY — THE TWO STEPS THE BROWSERS DID NOT HAVE.
// ═══════════════════════════════════════════════════════════════════════════
//
// The CLI's `accept_vault_key` has FIVE steps. The browsers had THREE: they went
// from unwrap straight to `vaultKeys: { ...device.vaultKeys, [id]: accepted }`.
// So on two of the four client surfaces —
//
//   * a key that OPENED NOTHING was still sealed into the device identity
//     (step 4, "open before writing"), and
//   * it SILENTLY OVERWROTE whatever key was already there (step 5, "never
//     silently replace") — losing access to everything sealed under the old key,
//     on a device that may hold the last copy of it.
//
// Both checks now live INSIDE `acceptVault`, which is the point: it returns the
// key for the CALLER to persist, so a check at the call site would have been
// duplicated in two clients and forgettable in both. These two tests still drive
// the REAL webapp — click Accept, read the block, tick the box — because a
// module-level test alone is exactly the shape that has twice let a fully
// revertible product fix ship green in this repository.

/** Push the sealed vault, so the fake's newest op is sealed under the CURRENT key. */
async function push(page: Page): Promise<void> {
  await page.getByTestId("sync-push").click();
  await expect(page.getByTestId("sync-status")).toContainText("Pushed sealed container", {
    timeout: T,
  });
}

/**
 * Move the vault on to a FRESH key, the way a user would once it is already
 * shared: rotate it, keeping only this device. (`sharing-convert` is the
 * one-way password→vault-key door and is disabled after the first use.) Rotation
 * re-seals the LOCAL vault under the new key and re-wraps it into this device's
 * own mailbox; it deliberately does NOT push, which is what leaves the server's
 * newest op behind — exactly the state the two refusals below are about.
 */
async function rotateToSelf(page: Page, deviceId: string): Promise<void> {
  await page.getByTestId("sharing-rotate-to").fill(deviceId);
  await page.getByTestId("sharing-rotate").click();
  await expect(page.getByTestId("sharing-status")).toContainText("Rotated", { timeout: T });
}

const SEALED_DEVICE = "sigil.webapp.device.v1";

test("a key that does NOT open the vault is refused — nothing is stored, and the UI says why", async ({
  page,
}: {
  page: Page;
}) => {
  const VAULT = "envauth-webapp-open";
  const deviceId = await setup(page, "envauth-webapp-three", VAULT);
  const mailbox = `${VAULT}\u0000${deviceId}`;

  // K1 seals the vault; push it, so the server's newest op is under K1.
  await push(page);
  // A real, AUTHENTICATED envelope carrying K1, deposited to this device.
  await depositRealEnvelopeToSelf(page, deviceId);
  const envelopeK1 = fake.state.envelopes.get(mailbox);
  expect(envelopeK1).toBeTruthy();

  // ⭐ NOW MOVE THE VAULT ON. Re-keying seals the local vault under a fresh K2,
  // and pushing makes K2 the key the server's newest op needs. The envelope in
  // the mailbox still carries K1 — a stale deposit, byte-for-byte what a replayed
  // or misfiled one looks like. It AUTHENTICATES perfectly; it opens nothing.
  await rotateToSelf(page, deviceId);
  await push(page);
  fake.state.envelopes.set(mailbox, envelopeK1!);

  const before = await page.evaluate((k) => window.localStorage.getItem(k), SEALED_DEVICE);

  await page.getByTestId("sharing-accept").click();

  // 1. REFUSED, in the envelope block, with the reason a human can act on.
  const refusal = page.getByTestId("sharing-envelope-refusal");
  await expect(refusal).toBeVisible({ timeout: T });
  await expect(refusal).toContainText("does NOT open this vault");
  await expect(refusal).toContainText("rotated");
  // Explicitly none of the other three failures.
  await expect(refusal).toContainText("not a permission problem");
  await expect(page.getByTestId("sharing-pin-mismatch")).toHaveCount(0);
  await expect(page.getByTestId("sharing-status")).toContainText("REFUSED", { timeout: T });

  // 2. ⭐ NOTHING WAS STORED. The sealed device identity — the one place a vault
  //    key would land — is byte-for-byte what it was before the click.
  const after = await page.evaluate((k) => window.localStorage.getItem(k), SEALED_DEVICE);
  expect(after).toBe(before);

  // 3. …and localStorage still holds only SEALED containers.
  const values = await page.evaluate(() =>
    Object.keys(window.localStorage).map((k) => window.localStorage.getItem(k) ?? ""),
  );
  expect(values.length).toBeGreaterThan(0);
  for (const v of values) {
    expect(Buffer.from(v, "base64").subarray(0, 8).toString("latin1")).toBe("SIGILcli");
  }
});

test("an accept that would REPLACE a different held key is refused, and replacing needs the explicit tick", async ({
  page,
}: {
  page: Page;
}) => {
  const VAULT = "envauth-webapp-replace";
  const deviceId = await setup(page, "envauth-webapp-four", VAULT);
  const mailbox = `${VAULT}\u0000${deviceId}`;

  // K1 seals the vault AND is pushed, so the server's newest op is under K1 —
  // step 4 therefore PASSES and step 5 is the only thing that can refuse.
  await push(page);
  await depositRealEnvelopeToSelf(page, deviceId);
  const envelopeK1 = fake.state.envelopes.get(mailbox);
  expect(envelopeK1).toBeTruthy();

  // ⭐ The browser moves to K2 LOCALLY and does not push. It now holds a key that
  // is NOT the one in the mailbox, while the mailbox's key still opens the
  // server's newest op. That is the shape of the attack: a deposit nobody asked
  // for, arriving at a device that already has a working key.
  await rotateToSelf(page, deviceId);
  fake.state.envelopes.set(mailbox, envelopeK1!);

  const before = await page.evaluate((k) => window.localStorage.getItem(k), SEALED_DEVICE);

  await page.getByTestId("sharing-accept").click();

  // 1. REFUSED — and it names BOTH fingerprints, never a key.
  const refusal = page.getByTestId("sharing-envelope-refusal");
  await expect(refusal).toBeVisible({ timeout: T });
  await expect(refusal).toContainText("REPLACE a different key");
  await expect(refusal).toContainText("last copy");
  await expect(page.getByTestId("sharing-status")).toContainText("REFUSED", { timeout: T });

  // 2. NOTHING CHANGED at rest.
  expect(await page.evaluate((k) => window.localStorage.getItem(k), SEALED_DEVICE)).toBe(before);

  // 3. ⭐ CLICKING ACCEPT AGAIN, UNTICKED, REFUSES AGAIN. The opt-in is not
  //    "dismiss the warning once" — it must be given for the click it applies to.
  await page.getByTestId("sharing-accept").click();
  await expect(refusal).toBeVisible({ timeout: T });
  await expect(refusal).toContainText("REPLACE a different key");
  expect(await page.evaluate((k) => window.localStorage.getItem(k), SEALED_DEVICE)).toBe(before);

  // 4. THE EXPLICIT TICK IS THE ONLY DOOR — and it reports what it displaced.
  await page.getByTestId("sharing-accept-replace").check();
  await page.getByTestId("sharing-accept").click();
  await expect(page.getByTestId("sharing-status")).toContainText("It REPLACED the key", {
    timeout: T,
  });
  expect(await page.evaluate((k) => window.localStorage.getItem(k), SEALED_DEVICE)).not.toBe(
    before,
  );

  // 5. …and the tick did not stay armed: the block is gone, so nothing is left
  //    ticked out of sight to authorize the NEXT accept.
  await expect(page.getByTestId("sharing-accept-replace")).toHaveCount(0);
});
