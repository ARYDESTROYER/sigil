// recovery.spec.mjs — the recovery kit in the REAL unpacked MV3 extension.
//
// ⭐ THE POINT OF THIS FILE is the second half: after a kit is generated on one
// browser profile, it is redeemed on a SECOND, COMPLETELY CLEAN profile — a
// fresh `chrome.storage.local`, no vault, no device identity, no pin store. That
// is the situation a customer who lost every device is actually in, and until
// this phase the extension could not serve it at all (it vendored recovery.mjs
// and exposed nothing).
//
// The server here is a FAKE (sigil-wasm/test/fake-sigild.mjs): it verifies no
// signatures and enforces no authorization, and proves nothing about sigild.
// Everything CRYPTOGRAPHIC is still real and still happens in the extension's
// own wasm: the HKDF derivation from the printed code, the hybrid wrap and
// unwrap, the Argon2id sealing, and the TOTP code. Protocol conformance against
// a live sigild is proven in sigil-wasm/test/recovery-interop.mjs and
// cli/tests/e2e-recovery.sh.
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
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PINNED_T = 59;
const RFC_CODE_6 = "287082";
const VAULT_ID = "ext-recovery-demo";

async function extensionId() {
  const manifest = JSON.parse(await readFile(path.join(EXT_DIR, "manifest.json"), "utf8"));
  const der = Buffer.from(manifest.key, "base64");
  const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

/** Launch a browser profile with the real unpacked extension loaded. */
async function launchProfile() {
  const userDataDir = await mkdtemp(path.join(tmpdir(), "sigil-ext-recovery-"));
  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: "chromium",
    headless: true,
    args: [`--disable-extensions-except=${EXT_DIR}`, `--load-extension=${EXT_DIR}`],
  });
  return { context, userDataDir };
}

let fake;
let id;
let kitCode = "";
let kitDeviceId = "";

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

/** The visible text of `#restore-error`, or "" when it is hidden. */
async function visibleRestoreError(page) {
  const box = page.getByTestId("restore-error");
  if (!(await box.isVisible())) return "";
  return ((await box.textContent()) ?? "").trim().replace(/\s+/g, " ");
}

/**
 * Wait for a restore to land in an UNLOCKED vault, and — if it does not — FAIL
 * WITH THE REASON THE POPUP GAVE.
 *
 * ⛔ THIS EXISTS BECAUSE THE OBVIOUS ASSERTION IS AMBIGUOUS, and that ambiguity
 * cost a reviewer a whole investigation. A bare
 * `expect(view-unlocked).toBeVisible({ timeout: 60_000 })` reports only "hidden
 * after 60 s", so the reviewer reached for `#status` — which said
 * `"Restore failed."`. That reads like proof that the restore threw. It is not:
 * the popup writes exactly that line on ANY failed submit and NEVER clears it,
 * so after profile 3's step 1 (whose refusal is the point of step 1) `#status`
 * ALREADY says "Restore failed." A step 2 that never ran at all, and a step 2
 * that ran and threw, look identical through that field.
 *
 * `priorError` is the visible `#restore-error` text from BEFORE the submit. The
 * popup hides that box on entry to the handler, so:
 *   - a DIFFERENT visible message  => this attempt ran and refused, with reason;
 *   - the SAME message, unchanged  => the submit very likely never ran.
 * Both are named. Neither is a timeout to be raised.
 */
async function expectRestoreUnlocks(page, { priorError = "", timeout = 60_000 } = {}) {
  await expect
    .poll(
      async () => {
        if (await page.getByTestId("view-unlocked").isVisible()) return "unlocked";
        const why = await visibleRestoreError(page);
        if (why === "") return "pending";
        const status = ((await page.getByTestId("status").textContent()) ?? "").trim();
        if (priorError !== "" && why === priorError) {
          return (
            "NO NEW ATTEMPT — #restore-error still shows the PREVIOUS refusal verbatim " +
            `(${why}), so this submit appears never to have run | #status: ${status}`
          );
        }
        return `REFUSED — #restore-error: ${why} | #status: ${status}`;
      },
      { timeout, message: "the restore never reached an unlocked vault" },
    )
    .toBe("unlocked");
}

test("profile 1: generate a recovery kit that covers a real vault", async () => {
  const { context, userDataDir } = await launchProfile();
  try {
    const { page, failures } = await openPopup(context);

    // A vault with one account whose code is the RFC 6238 vector.
    await expect(page.getByTestId("view-setup")).toBeVisible();
    await page.getByTestId("setup-password").fill("profile-one-password");
    await page.getByTestId("setup-password-2").fill("profile-one-password");
    await page.getByTestId("setup-submit").click();
    await expect(page.getByTestId("view-unlocked")).toBeVisible({ timeout: 30_000 });

    await page.getByTestId("add-toggle").click();
    await page.getByTestId("add-label").fill("rfc6238");
    await page.getByTestId("add-secret").fill(RFC_SECRET);
    await page.getByTestId("add-submit").click();
    await expect(page.getByTestId("code")).toHaveText(RFC_CODE_6);

    // Enrol against the fake dev server.
    await page.getByTestId("sync-toggle").click();
    await page.getByTestId("sync-url").fill(fake.baseUrl);
    await page.getByTestId("sync-vault").fill(VAULT_ID);
    await page.getByTestId("device-token").fill("operator-token-0123456789abcdef");
    await page.getByTestId("device-enroll").click();
    await expect(page.getByTestId("status")).toContainText("Enrolled as", { timeout: 30_000 });

    // A kit can only be handed a vault KEY, so the vault must be a SHARED vault:
    // a personal vault is sealed with the human password, which is never shared,
    // never wrapped and never sent.
    await page.getByTestId("sharing-toggle").click();
    await page.getByTestId("sharing-convert").click();
    await expect(page.getByTestId("status")).toContainText("random 32-byte vault key", {
      timeout: 30_000,
    });

    // Push, so there is ciphertext to come back to. A kit recovers KEYS, not DATA.
    await page.getByTestId("sync-push").click();
    await expect(page.getByTestId("status")).toContainText("Pushed sealed container", {
      timeout: 30_000,
    });

    // ── generate ─────────────────────────────────────────────────────────────
    await page.getByTestId("recovery-toggle").click();
    await page.getByTestId("recovery-generate").click();
    await expect(page.getByTestId("recovery-sheet")).toBeVisible({ timeout: 60_000 });

    kitCode = ((await page.getByTestId("recovery-code").textContent()) ?? "").trim();
    kitDeviceId = ((await page.getByTestId("recovery-kit-id").textContent()) ?? "").trim();
    expect(kitCode.split("-")).toHaveLength(7);
    expect(kitCode.replace(/-/g, "")).toHaveLength(56);
    expect(kitDeviceId).toMatch(/^dev_/);

    // The sheet carries the safety number, the coverage AS OF TODAY, and the
    // warnings — including that holding the paper is holding the account.
    await expect(page.getByTestId("recovery-safety-number")).toHaveText(/\d{5}( \d{5}){5}/);
    await expect(page.getByTestId("recovery-covered")).toContainText(VAULT_ID);
    await expect(page.getByTestId("recovery-sheet")).toContainText("FULL CONTROL OF THE ACCOUNT");
    await expect(page.getByTestId("recovery-sheet")).toContainText("NEVER PHOTOGRAPH IT");
    await expect(page.getByTestId("recovery-sheet")).toContainText("RECOVERS KEYS, NOT DATA");
    await expect(page.getByTestId("recovery-covers-nothing")).toBeHidden();
    // ⭐ THE INDEX WAS HEALTHY, so the generate-time truncation warning must be
    // HIDDEN. This direction is what keeps the other one worth reading: a warning
    // that is always on is one people learn to skip, and it would send a user off
    // to re-print a sheet that was fine. The VISIBLE direction is pinned in
    // profile 3, which prints a fresh kit against a crowded index.
    await expect(page.getByTestId("recovery-index-truncated")).toBeHidden();

    // ⭐ THE CODE IS A CREDENTIAL: storage still holds exactly the two sealed
    // containers, and the code is in neither of them.
    const stored = await page.evaluate(async () => {
      const all = await chrome.storage.local.get(null);
      return { keys: Object.keys(all).sort(), blob: JSON.stringify(all) };
    });
    expect(stored.keys).toEqual(["sigil.extension.device.v1", "sigil.extension.vault.v1"]);
    expect(stored.blob).not.toContain(kitCode);
    expect(stored.blob).not.toContain(kitCode.replace(/-/g, ""));
    expect(stored.blob).not.toContain("profile-one-password");
    expect(page.url()).not.toContain(kitCode.slice(0, 8));

    // COVER from the browser that printed the kit takes the DERIVED path: the
    // key was never fetched, so nothing could have been substituted.
    await page.getByTestId("recovery-cover-kit").fill(kitDeviceId);
    await page.getByTestId("recovery-cover").click();
    await expect(page.getByTestId("status")).toContainText("derived locally", { timeout: 30_000 });

    // CHECK reports set-up + coverage.
    await page.getByTestId("recovery-check").click();
    await expect(page.getByTestId("recovery-coverage")).toContainText("1 kit(s) enrolled", {
      timeout: 30_000,
    });
    await expect(page.getByTestId("recovery-coverage")).toContainText(`covered by ${kitDeviceId}`);

    // Confirming clears the code from the DOM; it cannot be shown again.
    await page.getByTestId("recovery-written").check();
    await page.getByTestId("recovery-hide").click();
    await expect(page.getByTestId("recovery-sheet")).toBeHidden();
    expect(await page.getByTestId("recovery-code").textContent()).toBe("");

    expect(failures).toEqual([]);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});

test("profile 2: RESTORE on a completely clean profile", async () => {
  expect(kitCode).not.toBe("");
  const { context, userDataDir } = await launchProfile();
  try {
    const { page, failures } = await openPopup(context);

    // It really is a fresh install: no stored vault, so the popup boots into
    // SETUP — and the restore panel is right there beside it.
    await expect(page.getByTestId("view-setup")).toBeVisible();
    await expect(page.getByTestId("view-restore")).toBeVisible();
    expect(
      await page.evaluate(async () => Object.keys(await chrome.storage.local.get(null))),
    ).toEqual([]);

    await page.getByTestId("restore-toggle").click();
    await page.getByTestId("restore-url").fill(fake.baseUrl);
    await page.getByTestId("restore-device-id").fill(kitDeviceId);
    await page.getByTestId("restore-password").fill("profile-two-password");
    await page.getByTestId("restore-confirm").fill("profile-two-password");

    // A wrong code is refused OFFLINE, before anything is sent, and is named as
    // a mistyped code rather than as an auth failure. ("U" is never used.)
    const before = fake.log.length;
    await page.getByTestId("restore-code").fill("U".repeat(56));
    await page.getByTestId("restore-submit").click();
    await expect(page.getByTestId("restore-error")).toContainText("not a valid recovery code", {
      timeout: 30_000,
    });
    expect(fake.log.length).toBe(before); // nothing reached the server

    // The real code, pasted as a human would: grouped, and in lower case.
    await page.getByTestId("restore-code").fill(kitCode.toLowerCase());
    await page.getByTestId("restore-submit").click();

    // ⭐ Landed in an UNLOCKED vault, with the account back and the wasm
    // computing the RFC vector — on a profile that started completely empty.
    await expectRestoreUnlocks(page);
    await expect(page.getByTestId("account")).toHaveCount(1);
    await expect(page.getByTestId("code")).toHaveText(RFC_CODE_6);
    await expect(page.getByTestId("status")).toContainText("SECOND COPY OF THAT PAPER");

    // Only the two sealed containers were written, and the code is in neither.
    const stored = await page.evaluate(async () => {
      const all = await chrome.storage.local.get(null);
      return { keys: Object.keys(all).sort(), blob: JSON.stringify(all) };
    });
    expect(stored.keys).toEqual(["sigil.extension.device.v1", "sigil.extension.vault.v1"]);
    expect(stored.blob).not.toContain(kitCode);
    expect(stored.blob).not.toContain(kitCode.replace(/-/g, ""));
    expect(stored.blob).not.toContain("profile-two-password");

    // The code field was cleared the moment it worked.
    expect(await page.getByTestId("restore-code").inputValue()).toBe("");

    expect(failures).toEqual([]);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});

/**
 * ⭐ A CROWDED ENVELOPE INDEX MUST REFUSE — AND THE SHEET MUST STILL WORK.
 *
 * `GET /v1/devices/{id}/keys` is how a restored kit finds what it can decrypt.
 * It is ONE page, capped at 500 rows, with NO CURSOR — and any account can put
 * rows in it (deposit an opaque envelope addressed to a device id it knows, then
 * grant that device read on a vault it claimed itself). So:
 *
 *   1. ⛔ a restore that relies on that listing must REFUSE, never restore the
 *      visible prefix and report success;
 *   2. ⭐ naming the vaults printed on the SHEET must recover them anyway,
 *      because that path asks each VAULT directly and cannot be crowded out.
 *
 * The page cap is shrunk rather than minting 500 envelopes; the flag and the
 * branch are the real ones. ⚠️ Against the DOUBLE — this proves what the POPUP
 * does, not what sigild would allow.
 */
test("profile 3: a CROWDED index refuses, and the sheet's vault ids still recover", async () => {
  expect(kitCode).not.toBe("");
  const previousCap = fake.indexPageCap;
  // ⭐ TWO decoys, and the FIRST is deposited by a device that was never enrolled
  // here — exactly the shape ADR 0052 §3 refuses, because the client rule is
  // `accountDevices.has(sender)` and a foreign account's device is simply absent
  // from `GET /v1/account`. ⚠️ The double mints every enrolled device into ONE
  // account (its header says so), so a stranger cannot be expressed by enrolling
  // one; planting the row is the only way to reach that refusal from a browser
  // spec at all. The multi-account form is proven against a REAL sigild in
  // sigil-wasm/test/recovery-interop.mjs.
  const strangerKey = `yy-strangers-vault\u0000${kitDeviceId}`;
  const decoyKey = `zz-crowding-vault\u0000${kitDeviceId}`;
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
  fake.indexPageCap = 2;
  const { context, userDataDir } = await launchProfile();
  try {
    const { page, failures } = await openPopup(context);
    await expect(page.getByTestId("view-restore")).toBeVisible();

    await page.getByTestId("restore-toggle").click();
    await page.getByTestId("restore-url").fill(fake.baseUrl);
    await page.getByTestId("restore-device-id").fill(kitDeviceId);
    await page.getByTestId("restore-password").fill("profile-three-password");
    await page.getByTestId("restore-confirm").fill("profile-three-password");
    await page.getByTestId("restore-code").fill(kitCode.toLowerCase());

    // 1. ⛔ Blind: the listing is crowded, so this cannot know what it is
    //    missing and must say so rather than restore a prefix.
    await page.getByTestId("restore-submit").click();
    await expect(page.getByTestId("restore-error")).toContainText("partial recovery", {
      timeout: 60_000,
    });
    // A half-restored browser is worse than a clean refusal.
    expect(
      await page.evaluate(async () => Object.keys(await chrome.storage.local.get(null))),
    ).toEqual([]);

    // 2. ⭐ The way out: the ids off the sheet's "covers" line.
    //
    // ⚠️ The step-1 refusal above is still on screen. Capture it, so that if this
    // submit fails the report can say WHICH of the two things happened — a real
    // refusal with its reason, or a submit that never ran — instead of leaving a
    // reader with `#status: "Restore failed."`, which step 1 wrote and nothing
    // clears.
    const priorError = await visibleRestoreError(page);
    expect(priorError).toContain("partial recovery");
    await page.getByTestId("restore-vaults").fill(VAULT_ID);
    await page.getByTestId("restore-submit").click();
    await expectRestoreUnlocks(page, { priorError });
    await expect(page.getByTestId("code")).toHaveText(RFC_CODE_6);

    // ⛔⛔ 3. AND IT MUST SAY SO. The restore SUCCEEDED, so there is no error
    //    screen to carry the qualification — and this popup used to fold the
    //    warning into the one-line `#status` under the heading "Not restored:",
    //    which reads as though a NAMED VAULT failed rather than "the result
    //    itself cannot be proven complete". It now has its own persistent alert.
    const notes = page.getByTestId("restore-notes");
    await expect(notes).toBeVisible({ timeout: 60_000 });
    await expect(notes).toContainText("THIS MAY NOT BE EVERYTHING");
    await expect(notes).toContainText("no way to ask for the rest");
    // ⛔⛔ AND THE OTHER CAVEAT, which had NO test at all: a row the INDEX ALONE
    // introduced, deposited by a device outside this account, is IGNORED — not
    // fetched, not unwrapped, and above all not PINNED into the fresh trust
    // store this restore just built. Deleting this whole note block from the
    // popup used to leave every browser test green.
    await expect(notes).toContainText("OUTSIDE your account");
    await expect(notes).toContainText("were ignored");
    // ⭐ ONE SUMMARY, NEVER ONE LINE PER ROW: the ignored vault must not be
    // itemised, because a flood rendered row by row buries the real result —
    // which is exactly what a flood is for.
    await expect(notes).not.toContainText("yy-strangers-vault");
    // ⭐ AND THE HEADLINE CHANGES, the way the desktop's does. A truncated
    // restore that announces a plain "Restored" and buries the qualification in
    // a trailing clause is the under-report this phase exists to remove.
    await expect(page.getByTestId("status")).toContainText("MAY NOT BE ALL OF THEM");
    // ⚠️ It must NOT still be labelled as a per-vault failure.
    await expect(notes).not.toContainText("Not restored");

    // ⚠️ HONEST SCOPE: the cap is shrunk rather than 500 envelopes minted, and
    // the real vault is still ON the single visible page — so `fromSheet` is
    // EMPTY here and the envelope-sender path is NOT exercised in the browser.
    // That path is proven against a REAL sigild in
    // `sigil-wasm/test/recovery-interop.mjs`. What this pins is the truncation
    // flag reaching the user.

    // ── 4. ⭐ AND AT THE MOMENT OF PRINTING, which is the only moment the user
    //    can still act on it. This restored profile holds the kit's identity and
    //    the vault key, so it can print a FRESH sheet — the obvious next thing to
    //    do after a recovery. With the index still crowded, that sheet must carry
    //    the warning, and must still be PRINTED: refusing would let anyone who
    //    can crowd a server listing stop kits being made at all, which is a
    //    denial of the last line of defence (ADR 0040 limitation 1) and strictly
    //    worse than the truncation. A cap of ZERO overflows on the first row,
    //    which is the only way to have the index already crowded for a device id
    //    that does not exist until the enrol inside `generateRecoveryKit`.
    fake.indexPageCap = 0;
    await page.getByTestId("recovery-toggle").click();
    await page.getByTestId("recovery-generate").click();
    await expect(page.getByTestId("recovery-sheet")).toBeVisible({ timeout: 60_000 });
    const truncWarn = page.getByTestId("recovery-index-truncated");
    await expect(truncWarn).toBeVisible();
    await expect(truncWarn).toContainText("re-print");
    // The sheet is real: 56 Crockford characters, printed as 7 groups of 8.
    const reprint = ((await page.getByTestId("recovery-code").textContent()) ?? "").trim();
    expect(reprint.replace(/-/g, "")).toHaveLength(56);

    expect(failures).toEqual([]);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
    fake.indexPageCap = previousCap;
    fake.state.envelopes.delete(decoyKey);
    fake.state.envelopes.delete(strangerKey);
  }
});

