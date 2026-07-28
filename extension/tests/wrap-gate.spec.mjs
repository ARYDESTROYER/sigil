// wrap-gate.spec.mjs — the RECOVERY-KIT WRAP GATE in the REAL unpacked MV3
// extension.
//
// ⭐ ADR 0042's central control: a client asked to wrap a vault key TO A RECOVERY
// KIT it has never pinned must REFUSE. The only thing vouching for that kit's
// public key is the server, and a server that substituted its own key would be
// handed the vault key it exists never to see. Exactly one thing lifts the
// refusal: the safety number PRINTED ON THE SHEET, compared out of band.
//
// This file exists because the control was deletable without any browser test
// noticing. Replacing the gate's condition with `false && (...)` in
// sigil-wasm/sharing.mjs (and the vendored copy) left every shipped webapp and
// extension spec green. The reason is structural: covering a kit from the
// profile that PRINTED it takes the DERIVED path and never reaches the gate at
// all. Only a SECOND profile — one that never saw the sheet — exercises it.
//
// The server is the fake (see sigil-wasm/test/fake-sigild.mjs); every
// cryptographic step is real and happens in the extension's own wasm.
//
// ⚠️ NOTE the fake is started with NO CORS allowlist here, on purpose: an MV3
// extension page with a host permission is exempt from CORS, so this suite
// proves the no-CORS path that a browser page cannot use.

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

async function extensionId() {
  const manifest = JSON.parse(await readFile(path.join(EXT_DIR, "manifest.json"), "utf8"));
  const der = Buffer.from(manifest.key, "base64");
  const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

async function launchProfile() {
  const userDataDir = await mkdtemp(path.join(tmpdir(), "sigil-ext-wrapgate-"));
  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: "chromium",
    headless: true,
    args: [`--disable-extensions-except=${EXT_DIR}`, `--load-extension=${EXT_DIR}`],
  });
  return { context, userDataDir };
}

let fake;
let id;
let kitDeviceId = "";
let printedSafety = "";

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

/** A profile with a vault, an enrolled device and a SHARED vault key. */
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
  await page.getByTestId("sharing-convert").click();
  await expect(page.getByTestId("status")).toContainText("random 32-byte vault key", {
    timeout: 30_000,
  });
}

test("profile 1: print a kit and note the safety number from the sheet", async () => {
  const { context, userDataDir } = await launchProfile();
  try {
    const { page, failures } = await openPopup(context);
    await setup(page, "wrapgate-one-pw", "ext-wrapgate-a");

    await page.getByTestId("recovery-toggle").click();
    await page.getByTestId("recovery-generate").click();
    await expect(page.getByTestId("recovery-sheet")).toBeVisible({ timeout: 60_000 });

    kitDeviceId = ((await page.getByTestId("recovery-kit-id").textContent()) ?? "").trim();
    printedSafety = ((await page.getByTestId("recovery-safety-number").textContent()) ?? "").trim();
    expect(kitDeviceId).toMatch(/^dev_/);
    expect(printedSafety).toMatch(/^\d{5}( \d{5}){5}$/);

    expect(failures).toEqual([]);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});

test("profile 2: REFUSES to cover a first-sight kit until the PRINTED safety number is typed", async () => {
  expect(kitDeviceId).not.toBe("");
  const VAULT_B = "ext-wrapgate-b";
  const envelopeKey = `${VAULT_B}\u0000${kitDeviceId}`; // the fake keys on vault\0device

  const { context, userDataDir } = await launchProfile();
  try {
    const { page, failures } = await openPopup(context);
    await setup(page, "wrapgate-two-pw", VAULT_B);
    expect(fake.state.envelopes.has(envelopeKey)).toBe(false);

    await page.getByTestId("recovery-toggle").click();

    // 1) FIRST SIGHT, no safety number → REFUSED, and named as a recovery kit.
    await page.getByTestId("recovery-cover-kit").fill(kitDeviceId);
    await page.getByTestId("recovery-cover").click();
    await expect(page.getByTestId("recovery-unverified")).toBeVisible({ timeout: 30_000 });
    await expect(page.getByTestId("recovery-unverified")).toContainText("REFUSED");
    await expect(page.getByTestId("recovery-unverified")).toContainText("recovery kit");
    // ⭐ NOTHING WRAPPED, NOTHING UPLOADED.
    expect(fake.state.envelopes.has(envelopeKey)).toBe(false);

    // 2) A WRONG safety number is refused as a MISMATCH — which also proves (1)
    //    did not silently pin the key (a pinned key would read as a match).
    await page.getByTestId("recovery-cover-safety").fill("11111 22222 33333 44444 55555 66666");
    await page.getByTestId("recovery-cover").click();
    await expect(page.getByTestId("recovery-unverified")).toContainText("does not match", {
      timeout: 30_000,
    });
    expect(fake.state.envelopes.has(envelopeKey)).toBe(false);

    // 3) The number PRINTED ON THE SHEET → proceeds.
    await page.getByTestId("recovery-cover-safety").fill(printedSafety);
    await page.getByTestId("recovery-cover").click();
    await expect(page.getByTestId("status")).toContainText("now covered by kit", {
      timeout: 30_000,
    });
    expect(fake.state.envelopes.has(envelopeKey)).toBe(true);

    expect(failures).toEqual([]);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});
