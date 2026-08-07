// qr.spec.mjs — QR scanning in the REAL unpacked MV3 extension (Phase 63).
//
// ⭐ THE PROPERTY, PROVEN THROUGH THE PRODUCT. Every assertion about what was
// added goes through `chrome.storage.local` — i.e. what the popup ACTUALLY
// WROTE — not through the DOM. Library-level coverage of `qr-scan.mjs` says
// nothing about whether the shipping popup still calls it; that is entry #10 of
// docs/engineering-lessons.md, which happened in the commit that documented it.
//
// ⛔⛔ AND THERE IS NO `test.skip()` HERE, DELIBERATELY. `BarcodeDetector` is
// present on macOS Chromium and ABSENT on Linux Chromium — measured directly for
// this phase — and every CI job in this repo runs `ubuntu-latest`. Skipping on
// the unsupported branch would leave the only extension-level proof of this
// feature silently absent in CI while the job stayed green: failure #8 in the
// lessons document, verbatim.
//
// So the first spec asks the PLATFORM and asserts whichever branch it is really
// in — both are real product states. The rest are about OUR logic (the
// provisioning gate, ambiguity, confirm-before-write, what reaches storage),
// none of which is Chromium's business, and they run everywhere: native detector
// where it exists, `installQrStub` where it does not.
//
// ⚠️ `installQrStub` IS A DOUBLE and its limits are its own (lesson #7). It
// returns exactly the payloads the test painted — faithful about CONTENT and
// COUNT, which is all our code branches on — and proves nothing about Chromium's
// pixel decoding. It never shadows a real detector.
//
// ⚠️ NO CAMERA IS TESTED BECAUSE THERE IS NO CAMERA. A permission prompt is
// browser chrome and taking focus destroys an MV3 popup, so a camera control
// here would be a button that closes the window.
//
// Pre-audit / UNAUDITED / DEV.

import { test, expect, chromium } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const EXT_DIR = path.dirname(fileURLToPath(new URL("../package.json", import.meta.url)));
const REPO_ROOT = path.resolve(EXT_DIR, "..");
const PINNED_T = 59;
const PASSWORD = "qr-spec-password";
const STORAGE_KEY = "sigil.extension.vault.v1";
const RFC_CODE_8 = "94287082";

const FIXTURES = JSON.parse(
  await readFile(
    path.join(REPO_ROOT, "sigil-wasm", "test", "fixtures", "qr-matrices.json"),
    "utf8",
  ),
);

async function extensionId() {
  const manifest = JSON.parse(await readFile(path.join(EXT_DIR, "manifest.json"), "utf8"));
  const der = Buffer.from(manifest.key, "base64");
  const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

let id;
test.beforeAll(async () => {
  id = await extensionId();
});

async function launchProfile() {
  const userDataDir = await mkdtemp(path.join(tmpdir(), "sigil-ext-qr-"));
  const context = await chromium.launchPersistentContext(userDataDir, {
    channel: "chromium",
    headless: true,
    args: [`--disable-extensions-except=${EXT_DIR}`, `--load-extension=${EXT_DIR}`],
  });
  return { context, userDataDir };
}

/** See the file header: a faithful-about-content double, installed only if needed. */
async function installQrStub(context) {
  await context.addInitScript(() => {
    if (typeof globalThis.BarcodeDetector === "function") return;
    globalThis.BarcodeDetector = class {
      static async getSupportedFormats() {
        return ["qr_code"];
      }
      async detect() {
        return (globalThis.__qrPayloads ?? []).map((rawValue) => ({
          rawValue,
          format: "qr_code",
        }));
      }
    };
  });
}

async function openPopup(context) {
  const page = await context.newPage();
  await page.goto(`chrome-extension://${id}/src/popup/popup.html?t=${PINNED_T}`);
  await expect(page.locator("body")).toHaveAttribute("data-wasm", /.+/, { timeout: 30_000 });
  return page;
}

async function detectorAvailable(page) {
  return page.evaluate(async () => {
    if (typeof globalThis.BarcodeDetector !== "function") return false;
    try {
      const f = await globalThis.BarcodeDetector.getSupportedFormats();
      return Array.isArray(f) && f.includes("qr_code");
    } catch {
      return false;
    }
  });
}

async function setupVault(page) {
  await expect(page.getByTestId("view-setup")).toBeVisible({ timeout: 30_000 });
  await page.getByTestId("setup-password").fill(PASSWORD);
  await page.getByTestId("setup-password-2").fill(PASSWORD);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("view-unlocked")).toBeVisible({ timeout: 30_000 });
  await page.getByTestId("add-toggle").click();
  await expect(page.getByTestId("qr-probing")).toBeHidden({ timeout: 30_000 });
}

/** Paint a fixture and feed it through the real file input or a real paste. */
async function feedQr(page, key, opts = {}) {
  const fx = FIXTURES[key];
  const via = opts.via ?? "file";
  const repeat = opts.repeat ?? 1;
  const scale = opts.scale ?? 6;
  await page.evaluate(
    async ({ size, modules, via, repeat, scale, encodes }) => {
      globalThis.__qrPayloads = Array.from({ length: repeat }, () => encodes);
      const quiet = 4;
      const unit = (size + quiet * 2) * scale;
      const canvas = document.createElement("canvas");
      canvas.width = unit * repeat;
      canvas.height = unit;
      const ctx = canvas.getContext("2d");
      ctx.fillStyle = "#ffffff";
      ctx.fillRect(0, 0, canvas.width, canvas.height);
      ctx.fillStyle = "#000000";
      for (let r = 0; r < repeat; r++) {
        for (let y = 0; y < size; y++) {
          for (let x = 0; x < size; x++) {
            if (modules[y * size + x] === "1") {
              ctx.fillRect(r * unit + (x + quiet) * scale, (y + quiet) * scale, scale, scale);
            }
          }
        }
      }
      const blob = await new Promise((res) => canvas.toBlob((b) => res(b), "image/png"));
      const dt = new DataTransfer();
      dt.items.add(new File([blob], "qr.png", { type: "image/png" }));
      if (via === "paste") {
        // ⭐ At the FOCUSED element, exactly as a real ⌘V does — see the webapp
        // spec's note: targeting the panel hides a dead shipping path.
        (document.activeElement ?? document.body).dispatchEvent(
          new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true }),
        );
      } else {
        const input = document.querySelector('[data-testid="qr-file-input"]');
        input.files = dt.files;
        input.dispatchEvent(new Event("change", { bubbles: true }));
      }
    },
    { size: fx.size, modules: fx.modules, via, repeat, scale, encodes: fx.encodes },
  );
}

/** The sealed container the popup persisted, as base64 (or null). */
async function storedContainer(page) {
  return page.evaluate(
    (k) => new Promise((res) => chrome.storage.local.get(k, (o) => res(o[k] ?? null))),
    STORAGE_KEY,
  );
}

// ─────────────────────────────────────────────────────────────────────────────

test("the QR panel tells the truth about what this browser can do", async () => {
  const { context, userDataDir } = await launchProfile();
  try {
    const page = await openPopup(context);
    await setupVault(page);
    if (await detectorAvailable(page)) {
      await expect(page.getByTestId("qr-file-input")).toBeVisible();
      await expect(page.getByTestId("qr-unsupported")).toBeHidden();
    } else {
      // ⛔ Not a disabled button — a plain statement plus the alternative.
      await expect(page.getByTestId("qr-unsupported")).toBeVisible();
      await expect(page.getByTestId("qr-unsupported")).toContainText("cannot read QR codes");
      await expect(page.getByTestId("uri-input")).toBeVisible();
    }
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});

test("a scanned account lands in the vault, and nothing is written before confirm", async () => {
  const { context, userDataDir } = await launchProfile();
  try {
    await installQrStub(context);
    const page = await openPopup(context);
    await setupVault(page);

    const before = await storedContainer(page);
    await feedQr(page, "good");
    await expect(page.getByTestId("qr-preview")).toBeVisible({ timeout: 30_000 });
    await expect(page.getByTestId("qr-summary")).toContainText("alice@example.com");

    // ⭐ The stored container must be untouched while a scan is merely offered.
    expect(await storedContainer(page)).toBe(before);

    await page.getByTestId("qr-confirm").click();
    await expect(page.getByTestId("qr-preview")).toBeHidden({ timeout: 30_000 });
    // The account really exists: the popup's own wasm renders the RFC vector.
    await expect(page.getByText(RFC_CODE_8)).toBeVisible({ timeout: 30_000 });
    expect(await storedContainer(page)).not.toBe(before);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});

test("a QR asking for a code that never rotates is REFUSED and stores nothing", async () => {
  const { context, userDataDir } = await launchProfile();
  try {
    await installQrStub(context);
    const page = await openPopup(context);
    await setupVault(page);

    const before = await storedContainer(page);
    await feedQr(page, "frozen");
    await expect(page.getByTestId("qr-error")).toBeVisible({ timeout: 30_000 });
    await expect(page.getByTestId("qr-error")).toContainText("does not rotate");
    await expect(page.getByTestId("qr-preview")).toBeHidden();
    expect(await storedContainer(page)).toBe(before);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});

test("a QR carrying a link is refused and never echoed into the popup", async () => {
  const { context, userDataDir } = await launchProfile();
  try {
    await installQrStub(context);
    const page = await openPopup(context);
    await setupVault(page);

    await feedQr(page, "phish", { via: "paste" });
    await expect(page.getByTestId("qr-error")).toBeVisible({ timeout: 30_000 });

    // ⚠️ Attacker-chosen text must never reach our own trusted surface.
    const html = await page.content();
    expect(html).not.toContain("evil.example");
    expect(html).not.toContain("steal-your-account");
    expect(await page.locator('a[href*="evil.example"]').count()).toBe(0);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});

test("an image holding several QR codes is refused rather than silently picking one", async () => {
  const { context, userDataDir } = await launchProfile();
  try {
    await installQrStub(context);
    const page = await openPopup(context);
    await setupVault(page);

    const before = await storedContainer(page);
    await feedQr(page, "good", { repeat: 2 });
    await expect(page.getByTestId("qr-error")).toBeVisible({ timeout: 30_000 });
    await expect(page.getByTestId("qr-error")).toContainText("QR codes");
    await expect(page.getByTestId("qr-preview")).toBeHidden();
    expect(await storedContainer(page)).toBe(before);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});
