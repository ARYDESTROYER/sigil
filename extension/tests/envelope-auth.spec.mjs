// envelope-auth.spec.mjs — ⭐⭐ PHASE 60, THROUGH THE REAL PRODUCT UI.
//
// THE VULNERABILITY, reproduced with the shipped `sigil` binary and nothing else:
//
//     sigil hybrid-keygen --out b.hybrid          # victim; only b.hybrid.pub is published
//     head -c 32 /dev/urandom > attacker_key.bin
//     sigil hybrid-seal --recipient-pub b.hybrid.pub --in attacker_key.bin --out forged.env
//     -> 1226 bytes, magic SIGILhyb, byte-shaped IDENTICALLY to a genuine wrap
//     sigil hybrid-open --key b.hybrid --in forged.env   # exit 0, the attacker's key
//
// A wrapped vault key was an ANONYMOUS (ephemeral-static) container under one
// FIXED AAD, and the only check on the recovered plaintext was `length === 32`.
// So anyone who could read a device's PUBLISHED hybrid public key — which sigild
// serves to every authenticated device — could deposit a vault key THEY chose,
// and everything the victim wrote afterwards was readable by them. ADR 0038
// pinning did not help: the accept path fetched no hybrid key at all, so the pin
// store was never consulted on the receiving side.
//
// ⚠️ WHY THIS FILE EXISTS AND WHY IT DRIVES THE UI. Phase 59 shipped
// product-level fixes that were fully revertible while the whole gate stayed
// green, because every mutation only went red inside the .mjs modules. So this
// spec asserts on the EXTENSION's OWN behaviour:
//
//   * `popup.js`'s accept handler must pass the resolved sender through
//     `acceptVault` (revert it to the old one-argument call and the forgery is
//     accepted -> RED);
//   * `popup.js` + `popup.html` must render the refusal in its OWN alert
//     (`#sharing-envelope-refusal`), not as a generic toast — delete
//     `showEnvelopeRefusal` or the alert element and this goes RED;
//   * NOTHING may be stored: no vault key in `chrome.storage.local`, and the
//     popup must not switch into the shared vault.
//
// THE FORGERY IS REAL, not a hand-built byte string: it is minted IN THE PAGE
// with the extension's OWN vendored wasm, from the victim device's PUBLISHED
// hybrid public key alone — exactly the material an attacker has. An MV3 page can
// dynamic-import its own vendored module, which is what makes that possible here.
//
// The server is the fake (sigil-wasm/test/fake-sigild.mjs). Everything
// cryptographic is real and happens in the extension's wasm.

import { test, expect, chromium } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeSigild } from "../../sigil-wasm/test/fake-sigild.mjs";

const EXT_DIR = path.dirname(fileURLToPath(new URL("../package.json", import.meta.url)));
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PINNED_T = 59;
const RFC_CODE_6 = "287082";
const VAULT = "envauth-vault";

async function extensionId() {
  const manifest = JSON.parse(await readFile(path.join(EXT_DIR, "manifest.json"), "utf8"));
  const der = Buffer.from(manifest.key, "base64");
  const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

async function launchProfile() {
  const userDataDir = await mkdtemp(path.join(tmpdir(), "sigil-ext-envauth-"));
  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: "chromium",
    headless: true,
    args: [`--disable-extensions-except=${EXT_DIR}`, `--load-extension=${EXT_DIR}`],
  });
  return { context, userDataDir };
}

let fake;
let id;

test.beforeAll(async () => {
  id = await extensionId();
  fake = await startFakeSigild();
});

test.afterAll(async () => {
  await fake?.close();
});

async function openPopup(context) {
  const page = await context.newPage();
  const failures = [];
  page.on("pageerror", (e) => failures.push(String(e)));
  await page.goto(`chrome-extension://${id}/src/popup/popup.html?t=${PINNED_T}`);
  await expect(page.locator("body")).toHaveAttribute("data-wasm", /.+/, { timeout: 30_000 });
  return { page, failures };
}

/** A profile with a vault, an enrolled device, a published hybrid key and a SHARED vault. */
async function setup(page, password, vaultId) {
  await expect(page.getByTestId("view-setup")).toBeVisible();
  await page.getByTestId("setup-password").fill(password);
  await page.getByTestId("setup-password-2").fill(password);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("view-unlocked")).toBeVisible({ timeout: 30_000 });

  await page.getByTestId("add-toggle").click();
  await page.getByTestId("add-label").fill("rfc6238");
  await page.getByTestId("add-secret").fill(RFC_SECRET);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("code")).toHaveText(RFC_CODE_6);

  await page.getByTestId("sync-toggle").click();
  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("sync-vault").fill(vaultId);
  await page.getByTestId("device-token").fill("operator-token-0123456789abcdef");
  await page.getByTestId("device-enroll").click();
  await expect(page.getByTestId("status")).toContainText("Enrolled as", { timeout: 30_000 });

  await page.getByTestId("sharing-toggle").click();
  // Publishing is what makes this device a possible RECIPIENT: it is the public
  // key an attacker would mint a forgery to, and the key a real sender wraps to.
  await page.getByTestId("sharing-publish").click();
  await expect(page.getByTestId("status")).toContainText("Published the hybrid public key", {
    timeout: 30_000,
  });
  await page.getByTestId("sharing-convert").click();
  await expect(page.getByTestId("status")).toContainText("random 32-byte vault key", {
    timeout: 30_000,
  });
  const shown = ((await page.getByTestId("sharing-device-id").textContent()) ?? "").trim();
  return shown.replace(/^This device:\s*/, "");
}

/**
 * ⭐ MINT THE REAL FORGERY, in the page, with the extension's own wasm, from
 * PUBLIC material only — the victim's published X25519 public key and ML-KEM
 * encapsulation key, both base64 exactly as the server serves them.
 *
 * This is `sigil hybrid-seal --recipient-pub <victim>.pub`, in a browser.
 */
async function mintForgedEnvelope(page, extId, victimPub, attackerKeyB64) {
  return page.evaluate(
    async ([base, pub, keyB64]) => {
      const wasm = await import(`${base}/vendor/sigil_wasm.js`);
      await wasm.default(`${base}/vendor/sigil_wasm_bg.wasm`);
      const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
      const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
      const forged = wasm.hybrid_seal_to_container(
        b64(pub.x25519_public_key),
        b64(pub.mlkem_encaps_key),
        rnd(32), // ephemeral X25519 secret — the attacker's, and nobody checks it
        rnd(32), // ML-KEM coin
        rnd(wasm.nonce_len()),
        b64(keyB64), // ⚠️ THE KEY THE ATTACKER CHOSE
      );
      return btoa(String.fromCharCode(...new Uint8Array(forged)));
    },
    [`chrome-extension://${extId}`, victimPub, attackerKeyB64],
  );
}

test("a forged ANONYMOUS envelope is REFUSED by the real popup, distinctly, and stores nothing", async () => {
  const { context, userDataDir } = await launchProfile();
  try {
    const { page, failures } = await openPopup(context);
    const victimId = await setup(page, "envauth-pw-one", VAULT);
    expect(victimId).toMatch(/^dev_/);

    // The attacker's whole starting position: the victim's PUBLISHED key.
    const victimPub = fake.state.hybridKeys.get(victimId);
    expect(victimPub).toBeTruthy();

    const attackerKeyB64 = Buffer.from(
      Uint8Array.from({ length: 32 }, (_, i) => (i * 7 + 13) & 0xff),
    ).toString("base64");
    const forgedB64 = await mintForgedEnvelope(page, id, victimPub, attackerKeyB64);
    const forged = Buffer.from(forgedB64, "base64");

    // It IS byte-shaped like a genuine wrap: same magic, same framing.
    expect(forged.subarray(0, 8).toString("latin1")).toBe("SIGILhyb");
    // ...but version 1 — ANONYMOUS. That is the whole defect in one byte.
    expect(forged[8]).toBe(1);

    // Plant it in the victim's own mailbox, as a hostile server or a co-tenant
    // with write access would.
    //
    // NOTE `sender` is a device whose hybrid key the server WILL serve, on
    // purpose. The sender is resolved and fetched BEFORE the envelope is opened,
    // so attributing the deposit to a device that does not exist would be
    // refused one step earlier (an unresolvable sender -- that is the second
    // test) and would prove nothing about the ENVELOPE. Naming a resolvable
    // device is the stronger case: everything about the deposit looks right, and
    // the refusal has to come from the bytes themselves.
    fake.state.envelopes.set(`${VAULT}\u0000${victimId}`, {
      bytes: forged,
      sender: victimId,
      createdAt: new Date().toISOString(),
    });

    // ── THE PRODUCT PATH: click Accept, exactly as a user would. ─────────────
    await page.getByTestId("sharing-accept").click();

    // ⭐ 1. THE REFUSAL IS RENDERED, IN ITS OWN ALERT. Not a toast, not the
    //       generic status line, not the pin-mismatch banner.
    const refusal = page.getByTestId("sharing-envelope-refusal");
    await expect(refusal).toBeVisible({ timeout: 30_000 });
    await expect(refusal).toContainText("NOT AUTHENTICATED");
    await expect(refusal).toContainText("NO SENDER");
    // ⭐ 2. AND IT IS SAID TO BE NEITHER A SIGN-IN NOR A PERMISSION PROBLEM.
    await expect(refusal).toContainText("NOT a sign-in problem");
    await expect(refusal).toContainText("NOT a permission problem");
    // The pin-mismatch alarm must stay DOWN: no key changed.
    await expect(page.getByTestId("sharing-pin-mismatch")).toBeHidden();

    // ⭐ 3. NOTHING WAS STORED. The attacker's key must appear nowhere in
    //       chrome.storage.local, and the popup must not have adopted the vault.
    const stored = await page.evaluate(async () => {
      const all = await chrome.storage.local.get(null);
      return JSON.stringify(all);
    });
    expect(stored).not.toContain(attackerKeyB64);
    // Every persisted value is still a SEALED container (ADR 0036), so the key
    // cannot be hiding in one of them in the clear either.
    const values = await page.evaluate(async () => {
      const all = await chrome.storage.local.get(null);
      return Object.values(all).filter((v) => typeof v === "string");
    });
    for (const v of values) {
      expect(Buffer.from(v, "base64").subarray(0, 8).toString("latin1")).toBe("SIGILcli");
    }

    expect(failures).toEqual([]);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});

test("an envelope the server cannot attribute to any sender is REFUSED, and says so in its own words", async () => {
  const { context, userDataDir } = await launchProfile();
  try {
    const { page, failures } = await openPopup(context);
    const vaultId = "envauth-unknown-sender";
    const victimId = await setup(page, "envauth-pw-two", vaultId);

    const victimPub = fake.state.hybridKeys.get(victimId);
    const forgedB64 = await mintForgedEnvelope(
      page,
      id,
      victimPub,
      Buffer.alloc(32, 0x5a).toString("base64"),
    );

    // ⚠️ THE SERVER NAMES NOBODY. sigild records the depositing device, but the
    // client must not TRUST that field to exist — a hostile or buggy server can
    // omit it, and "unwrap from whoever" is exactly the anonymous behaviour this
    // phase removed. An empty sender must be a REFUSAL, not a fallback.
    fake.state.envelopes.set(`${vaultId}\u0000${victimId}`, {
      bytes: Buffer.from(forgedB64, "base64"),
      sender: "",
      createdAt: new Date().toISOString(),
    });

    await page.getByTestId("sharing-accept").click();

    const refusal = page.getByTestId("sharing-envelope-refusal");
    await expect(refusal).toBeVisible({ timeout: 30_000 });
    await expect(refusal).toContainText("which device deposited");
    await expect(page.getByTestId("sharing-pin-mismatch")).toBeHidden();

    // ⭐ AND THE UI OFFERS THE WAY OUT it just described: naming the sender.
    await expect(page.getByTestId("sharing-accept-from")).toBeVisible();

    expect(failures).toEqual([]);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});

// ═══════════════════════════════════════════════════════════════════════════
// ⭐⭐ PHASE 60 SYMMETRY — THE TWO STEPS THIS POPUP DID NOT HAVE.
// ═══════════════════════════════════════════════════════════════════════════
//
// The CLI's `accept_vault_key` has FIVE steps. This popup had THREE: it went
// from unwrap straight to `vaultKeys: { ...device.vaultKeys, [id]: accepted }`.
// So on this surface (and the webapp's) —
//
//   * a key that OPENED NOTHING was still sealed into the device identity
//     (step 4, "open before writing"), and
//   * it SILENTLY OVERWROTE whatever key was already there (step 5, "never
//     silently replace") — losing access to everything sealed under the old key,
//     on a device that may hold the last copy of it.
//
// Both now live INSIDE `acceptVault`, so the control cannot be lost by editing a
// call site. These tests still drive the REAL popup, because a module-level test
// alone is exactly the shape that has twice let a fully revertible product fix
// ship green in this repository.

/** Push the sealed vault, so the fake's newest op is sealed under the CURRENT key. */
async function push(page) {
  await page.getByTestId("sync-push").click();
  await expect(page.getByTestId("status")).toContainText("Pushed sealed container", {
    timeout: 30_000,
  });
}

/**
 * Move the vault on to a FRESH key the way a user would once it is already
 * shared: rotate it, keeping only this device. (`sharing-convert` is the one-way
 * password→vault-key door and will not run twice.) Rotation re-seals the LOCAL
 * vault under the new key and re-wraps it into this device's own mailbox; it
 * deliberately does NOT push, which is what leaves the server's newest op
 * behind — exactly the state the two refusals below are about.
 */
async function rotateToSelf(page, deviceId) {
  await page.getByTestId("sharing-rotate-to").fill(deviceId);
  await page.getByTestId("sharing-rotate").click();
  await expect(page.getByTestId("status")).toContainText("Rotated", { timeout: 30_000 });
}

/** Deposit a REAL, authenticated envelope carrying the CURRENT vault key, to self. */
async function shareToSelf(page, deviceId) {
  await page.getByTestId("sharing-recipient").fill(deviceId);
  await page.getByTestId("sharing-share").click();
  await expect(page.getByTestId("status")).toContainText("Shared", { timeout: 30_000 });
}

test("a key that does NOT open the vault is REFUSED by the real popup, and nothing is stored", async () => {
  const { context, userDataDir } = await launchProfile();
  try {
    const { page, failures } = await openPopup(context);
    const vaultId = "envauth-ext-open";
    const deviceId = await setup(page, "envauth-pw-three", vaultId);
    const mailbox = `${vaultId}\u0000${deviceId}`;

    // K1 seals the vault; push it, so the server's newest op is under K1, and
    // deposit a real AUTHENTICATED envelope carrying K1.
    await push(page);
    await shareToSelf(page, deviceId);
    const envelopeK1 = fake.state.envelopes.get(mailbox);
    expect(envelopeK1).toBeTruthy();
    expect(envelopeK1.bytes[8]).toBe(2); // genuine = AUTHENTICATED v2

    // ⭐ NOW MOVE THE VAULT ON. Rotating re-seals it under a fresh K2, and
    // pushing makes K2 what the server's newest op needs. The envelope restored
    // below still carries K1 — a stale deposit, byte-for-byte what a replayed or
    // misfiled one looks like. It AUTHENTICATES perfectly; it opens nothing.
    await rotateToSelf(page, deviceId);
    await push(page);
    fake.state.envelopes.set(mailbox, envelopeK1);

    const before = await page.evaluate(() => chrome.storage.local.get(null).then(JSON.stringify));

    await page.getByTestId("sharing-accept").click();

    // 1. REFUSED, in its OWN alert, with the reason a human can act on.
    const refusal = page.getByTestId("sharing-envelope-refusal");
    await expect(refusal).toBeVisible({ timeout: 30_000 });
    await expect(refusal).toContainText("does NOT open this vault");
    await expect(refusal).toContainText("ROTATED");
    await expect(refusal).toContainText("not a permission problem");
    await expect(page.getByTestId("sharing-pin-mismatch")).toBeHidden();

    // 2. ⭐ NOTHING WAS STORED — chrome.storage.local is byte-for-byte unchanged.
    const after = await page.evaluate(() => chrome.storage.local.get(null).then(JSON.stringify));
    expect(after).toBe(before);

    expect(failures).toEqual([]);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});

test("an accept that would REPLACE a different held key is REFUSED, and replacing needs the explicit tick", async () => {
  const { context, userDataDir } = await launchProfile();
  try {
    const { page, failures } = await openPopup(context);
    const vaultId = "envauth-ext-replace";
    const deviceId = await setup(page, "envauth-pw-four", vaultId);
    const mailbox = `${vaultId}\u0000${deviceId}`;

    // K1 seals the vault AND is pushed, so the server's newest op is under K1 —
    // step 4 therefore PASSES and step 5 is the only thing that can refuse.
    await push(page);
    await shareToSelf(page, deviceId);
    const envelopeK1 = fake.state.envelopes.get(mailbox);
    expect(envelopeK1).toBeTruthy();

    // ⭐ The popup moves to K2 LOCALLY and does not push. It now holds a key that
    // is NOT the one in the mailbox, while the mailbox's key still opens the
    // server's newest op. That is the shape of the attack: a deposit nobody asked
    // for, arriving at a device that already has a working key.
    await rotateToSelf(page, deviceId);
    fake.state.envelopes.set(mailbox, envelopeK1);

    const before = await page.evaluate(() => chrome.storage.local.get(null).then(JSON.stringify));

    await page.getByTestId("sharing-accept").click();

    // 1. REFUSED — naming BOTH fingerprints, never a key.
    const refusal = page.getByTestId("sharing-envelope-refusal");
    await expect(refusal).toBeVisible({ timeout: 30_000 });
    await expect(refusal).toContainText("REPLACE a different key");
    await expect(refusal).toContainText("Nothing was replaced");
    await expect(page.getByTestId("sharing-pin-mismatch")).toBeHidden();

    // 2. NOTHING CHANGED at rest.
    expect(await page.evaluate(() => chrome.storage.local.get(null).then(JSON.stringify))).toBe(
      before,
    );

    // 3. ⭐ CLICKING ACCEPT AGAIN, UNTICKED, REFUSES AGAIN. The opt-in is not
    //    "dismiss the warning once" — it must be given for the click it applies
    //    to, which is why hideEnvelopeRefusal un-ticks the box.
    await page.getByTestId("sharing-accept").click();
    await expect(refusal).toBeVisible({ timeout: 30_000 });
    await expect(refusal).toContainText("REPLACE a different key");
    expect(await page.evaluate(() => chrome.storage.local.get(null).then(JSON.stringify))).toBe(
      before,
    );

    // 4. THE EXPLICIT TICK IS THE ONLY DOOR — and it reports what it displaced.
    await page.getByTestId("sharing-accept-replace").check();
    await page.getByTestId("sharing-accept").click();
    await expect(page.getByTestId("status")).toContainText("It REPLACED the key", {
      timeout: 30_000,
    });
    expect(
      await page.evaluate(() => chrome.storage.local.get(null).then(JSON.stringify)),
    ).not.toBe(before);

    // 5. …and the tick did not stay armed for the NEXT accept.
    await expect(page.getByTestId("sharing-accept-replace")).not.toBeChecked();

    expect(failures).toEqual([]);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});
