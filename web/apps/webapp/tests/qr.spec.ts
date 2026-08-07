import { expect, test, type Page } from "@playwright/test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
// @ts-expect-error — the Node-target wasm package (gitignored build output of
// sigil-wasm/build-wasm.sh). The TEST process needs it to open what the app
// sealed; the APP uses the bundler-target package instead.
import * as nodeWasm from "../../../../sigil-wasm/pkg-node/sigil_wasm.js";
// @ts-expect-error — plain .mjs, no bundled types.
import { openVault, base64ToBytes } from "../../../../sigil-wasm/totp-vault.mjs";

/**
 * ⭐⭐ QR SCANNING, PROVEN THROUGH THE REAL APP (Phase 63).
 *
 * Two things are being proven here and they are different:
 *
 *   1. A QR code the user WANTS becomes an account — and the account that lands
 *      is verified by DECRYPTING WHAT THE APP ACTUALLY WROTE, in the test
 *      process, not by reading the DOM. Library-level coverage of `qr-scan.mjs`
 *      would say nothing about whether the shipping app still calls it; that is
 *      entry #10 of docs/engineering-lessons.md, which happened in the commit
 *      that documented it.
 *
 *   2. A QR code the user CANNOT READ is refused. This is the half that matters.
 *      Every existing door into the vault — `--uri`, both browsers' paste fields
 *      — had a human looking at the string. ⛔ A QR IS OPAQUE TO HUMANS BY
 *      CONSTRUCTION: it removes the last reviewer. So the provisioning gate is
 *      not an accessory to this feature, it is the precondition for it.
 *
 * ⛔⛔ AND THE THING THIS FILE MUST NOT DO IS SKIP. `BarcodeDetector` is present
 * on macOS Chromium and ABSENT on Linux Chromium — both measured directly for
 * this phase — and every CI job in this repository runs `ubuntu-latest`. A
 * `test.skip()` on the unsupported branch would mean the only browser-level
 * proof of this feature silently evaporates in CI while the job stays green,
 * which is failure #8 in the lessons document, verbatim.
 *
 * ⭐ So instead: BOTH BRANCHES ARE REAL PRODUCT STATES AND EVERY RUNNER ASSERTS
 * THE ONE IT IS ACTUALLY IN. On a runner with the API, the scan path is
 * exercised end to end. On a runner without it, the honest "this browser cannot
 * scan" state is exercised end to end — which is exactly what a Firefox, Safari
 * or Linux user gets, so it is a real assertion about a real user, not a hole.
 *
 * ⭐ AND THERE IS NOT A SINGLE `test.skip()` IN THIS FILE, ON PURPOSE. The first
 * spec asks the PLATFORM and asserts whichever branch it is really in. Every
 * other spec is about OUR logic — the provisioning gate, the ambiguity refusal,
 * confirm-before-write, the no-echo rule, what actually reaches storage — none of
 * which is Chromium's business. Those run EVERYWHERE: with the native detector
 * where it exists, and against `installQrStub()` where it does not.
 *
 * ⚠️ `installQrStub` IS A TEST DOUBLE AND ITS LIMITS ARE ITS OWN (lesson #7: a
 * double must never be more permissive than the thing it stands in for). It
 * returns, for a given painted image, EXACTLY the payload a real decoder would
 * return for it — the fixture's own `encodes` string, once per painted copy — so
 * it is faithful about count and content, which is all our logic consumes. It
 * proves NOTHING about Chromium's pixel decoding. That half is proven by the
 * first spec plus the native runs on macOS.
 *
 * ⚠️ THE RESIDUAL GAP, STATED PLAINLY: no CI runner exercises Chromium's actual
 * QR *decode*. It is covered by the macOS developer gate (`scripts/gate.sh`).
 * That is a stated coverage boundary of choosing the platform's decoder over one
 * we ship — and it is the price paid for not owning a decoder whose measured
 * worst case was 94 seconds on a 1.7-megapixel image.
 */

const T = 90_000;
const PASSWORD = "qr-spec-password";
const STORAGE_KEY = "sigil.webapp.vault.v1";
const RFC_CODE_8 = "94287082";

// Playwright runs with cwd = the config directory (web/apps/webapp), so three
// levels up is the repo root. `import.meta` is unavailable here — this spec is
// transpiled to CommonJS by the Playwright runner.
const FIXTURES = JSON.parse(
  readFileSync(
    join(process.cwd(), "..", "..", "..", "sigil-wasm", "test", "fixtures", "qr-matrices.json"),
    "utf8",
  ),
) as Record<string, { size: number; modules: string; encodes: string }>;

type Vault = { version: number; entries: Record<string, unknown>[]; [k: string]: unknown };

/** Decrypt what the app actually wrote, in the TEST process. */
async function storedVault(page: Page): Promise<Vault> {
  const b64 = await page.evaluate((k) => window.localStorage.getItem(k), STORAGE_KEY);
  expect(b64, "the app must have persisted a sealed vault").toBeTruthy();
  return openVault(nodeWasm, PASSWORD, base64ToBytes(b64!)) as Vault;
}

/** Is `BarcodeDetector` with `qr_code` actually available in THIS browser? */
async function detectorAvailable(page: Page): Promise<boolean> {
  return page.evaluate(async () => {
    if (typeof (globalThis as Record<string, unknown>).BarcodeDetector !== "function") return false;
    try {
      const fmts = await (
        globalThis as unknown as {
          BarcodeDetector: { getSupportedFormats(): Promise<string[]> };
        }
      ).BarcodeDetector.getSupportedFormats();
      return Array.isArray(fmts) && fmts.includes("qr_code");
    } catch {
      return false;
    }
  });
}

/**
 * Install a deterministic `BarcodeDetector` for runners that have none.
 *
 * ⚠️ A DOUBLE, AND HERE IS EXACTLY WHAT IT IS AND IS NOT. It reports the format
 * list a real one reports, and `detect()` returns the payloads the test painted
 * — the fixture's own `encodes` text, once per painted copy — so it is faithful
 * about **content and count**, which is everything our code branches on. It does
 * NOT decode pixels, so it proves nothing about Chromium's decoder. It is
 * installed ONLY when the platform has no detector, and never shadows a real one.
 */
async function installQrStub(page: Page) {
  await page.addInitScript(() => {
    if (typeof (globalThis as Record<string, unknown>).BarcodeDetector === "function") return;
    class StubBarcodeDetector {
      static async getSupportedFormats() {
        return ["qr_code"];
      }
      async detect() {
        const payloads =
          ((globalThis as Record<string, unknown>).__qrPayloads as string[] | undefined) ?? [];
        return payloads.map((rawValue) => ({ rawValue, format: "qr_code" }));
      }
    }
    (globalThis as Record<string, unknown>).BarcodeDetector = StubBarcodeDetector;
    (globalThis as Record<string, unknown>).__qrStubInstalled = true;
  });
}

/**
 * Paint a fixture matrix onto a canvas and feed it to the app.
 *
 * `via: "file"` drives the real `<input type=file>` change handler; `via:
 * "paste"` dispatches a real `paste` ClipboardEvent carrying an image file,
 * which is the primary motion (screenshot -> Cmd-V) and a separate code path.
 *
 * `repeat` paints the same code N times side by side — that is how the
 * "several QR codes in one screenshot" case is produced.
 */
async function feedQr(
  page: Page,
  key: keyof typeof FIXTURES,
  opts: { via?: "file" | "paste"; repeat?: number; scale?: number } = {},
) {
  const fx = FIXTURES[key as string];
  const via = opts.via ?? "file";
  const repeat = opts.repeat ?? 1;
  const scale = opts.scale ?? 6;
  await page.evaluate(
    async ({ size, modules, via, repeat, scale, encodes }) => {
      // Tell the stub (if one is installed) what a real decoder would find in
      // the image about to be painted. Ignored entirely when the platform's own
      // detector is in use — it reads pixels, not this.
      (globalThis as Record<string, unknown>).__qrPayloads = Array.from(
        { length: repeat },
        () => encodes,
      );
      const quiet = 4;
      const unit = (size + quiet * 2) * scale;
      const canvas = document.createElement("canvas");
      canvas.width = unit * repeat;
      canvas.height = unit;
      const ctx = canvas.getContext("2d")!;
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
      const blob: Blob = await new Promise((res) => canvas.toBlob((b) => res(b!), "image/png"));
      const file = new File([blob], "qr.png", { type: "image/png" });
      const dt = new DataTransfer();
      dt.items.add(file);
      if (via === "paste") {
        // ⭐ DISPATCH AT THE FOCUSED ELEMENT, exactly as a real ⌘V does — NOT at
        // the panel. Targeting the panel is what made an earlier revision of
        // this spec pass while the shipping paste path was dead: a paste event
        // bubbles UP from the focused element and never travels DOWN into an
        // unfocused subtree.
        (document.activeElement ?? document.body).dispatchEvent(
          new ClipboardEvent("paste", { clipboardData: dt, bubbles: true, cancelable: true }),
        );
      } else {
        const input = document.querySelector('[data-testid="qr-file-input"]') as HTMLInputElement;
        input.files = dt.files;
        input.dispatchEvent(new Event("change", { bubbles: true }));
      }
    },
    { size: fx.size, modules: fx.modules, via, repeat, scale, encodes: fx.encodes },
  );
}

/**
 * Create a vault, ending unlocked with the QR probe resolved.
 *
 * `mode: "platform"` uses whatever this browser really has — that is how the
 * capability-truth spec measures the product. `mode: "ensure"` additionally
 * installs the stub when the platform has none, so the specs about OUR logic run
 * on every runner instead of skipping (see the file header).
 */
async function setupVault(page: Page, mode: "platform" | "ensure" = "ensure") {
  if (mode === "ensure") await installQrStub(page);
  await page.goto("/?t=59");
  await page.getByTestId("setup-password").fill(PASSWORD);
  await page.getByTestId("setup-confirm").fill(PASSWORD);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
  // The probe must have RESOLVED before a test reads the branch.
  await expect(page.getByTestId("qr-probing")).toHaveCount(0, { timeout: T });
}

// ─────────────────────────────────────────────────────────────────────────────

test("the QR panel tells the truth about what this browser can do", async ({ page }) => {
  await setupVault(page, "platform");
  const available = await detectorAvailable(page);

  if (available) {
    // The control exists because it works.
    await expect(page.getByTestId("qr-file-input")).toBeVisible({ timeout: T });
    await expect(page.getByTestId("qr-unsupported")).toHaveCount(0);
  } else {
    // ⛔ NO DISABLED BUTTON. A control that exists and fails is a claim that is
    // not true, and Phase 62 existed to remove two of those. The user is told
    // plainly, and pointed at the paste field that DOES work.
    await expect(page.getByTestId("qr-unsupported")).toBeVisible({ timeout: T });
    await expect(page.getByTestId("qr-unsupported")).toContainText("cannot read QR codes");
    await expect(page.getByTestId("qr-file-input")).toHaveCount(0);
    // ...and the alternative it names is really there.
    await expect(page.getByTestId("otpauth-input")).toBeVisible();
  }
});

test("a scanned account lands in the vault — and nothing is written before confirm", async ({
  page,
}) => {
  await setupVault(page);

  const before = await page.evaluate((k) => window.localStorage.getItem(k), STORAGE_KEY);

  await feedQr(page, "good");
  await expect(page.getByTestId("qr-preview")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("qr-summary")).toContainText("alice@example.com");

  // ⭐ THE VAULT MUST BE BYTE-IDENTICAL AT THIS POINT. A scanner that wrote on
  // decode would mean pasting a screenshot from a hostile page silently creates
  // an account. This is ADR 0050's confirm-before-destroy, pointed the other way.
  expect(await page.evaluate((k) => window.localStorage.getItem(k), STORAGE_KEY)).toBe(before);

  await page.getByTestId("qr-confirm").click();
  await expect(page.getByTestId("qr-preview")).toHaveCount(0, { timeout: T });

  // Decrypt what the app WROTE — not what it rendered.
  const vault = await storedVault(page);
  const entry = vault.entries.find((e) => e.label === "alice@example.com");
  expect(entry, "the scanned account must be in the sealed vault").toBeTruthy();
  expect(entry!.issuer).toBe("Acme");
  expect(entry!.period).toBe(30);
  expect(entry!.digits).toBe(8);
  // And it is the RFC 6238 seed, so the app's own wasm renders the RFC vector.
  await expect(page.getByText(RFC_CODE_8)).toBeVisible({ timeout: T });
});

test("the paste path works too — a screenshot is the primary motion", async ({ page }) => {
  await setupVault(page);

  await feedQr(page, "good", { via: "paste" });
  await expect(page.getByTestId("qr-preview")).toBeVisible({ timeout: T });
  await page.getByTestId("qr-confirm").click();

  const vault = await storedVault(page);
  expect(vault.entries.some((e) => e.label === "alice@example.com")).toBe(true);
});

test("a QR asking for a code that never rotates is REFUSED and stores nothing", async ({
  page,
}) => {
  await setupVault(page);

  const before = await page.evaluate((k) => window.localStorage.getItem(k), STORAGE_KEY);

  // period=4294967295: the counter stays put until ~2106, so the "one-time"
  // password never changes. This was ACCEPTED by the real CLI before Phase 63.
  await feedQr(page, "frozen");
  await expect(page.getByTestId("qr-error")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("qr-error")).toContainText("does not rotate");

  // Nothing offered, nothing stored.
  await expect(page.getByTestId("qr-preview")).toHaveCount(0);
  expect(await page.evaluate((k) => window.localStorage.getItem(k), STORAGE_KEY)).toBe(before);
  const vault = await storedVault(page);
  expect(vault.entries.some((e) => e.label === "victim")).toBe(false);
});

test("a QR whose label would render as another issuer is REFUSED", async ({ page }) => {
  await setupVault(page);

  await feedQr(page, "spoof");
  await expect(page.getByTestId("qr-error")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("qr-error")).toContainText("display as another");
  await expect(page.getByTestId("qr-preview")).toHaveCount(0);

  const vault = await storedVault(page);
  expect(vault.entries.length).toBe(0);
});

test("a QR carrying a link is refused, never opened, and never echoed into the page", async ({
  page,
}) => {
  await setupVault(page);

  const navigations: string[] = [];
  page.on("framenavigated", (f) => navigations.push(f.url()));

  await feedQr(page, "phish");
  await expect(page.getByTestId("qr-error")).toBeVisible({ timeout: T });

  // ⚠️ The payload is attacker-chosen text. Rendering it inside our own trusted
  // UI is a free spoofing primitive, so only the SCHEME may be named.
  const html = await page.content();
  expect(html).not.toContain("evil.example");
  expect(html).not.toContain("steal-your-account");
  // Nothing was navigated to and no link was created.
  expect(navigations.filter((u) => u.includes("evil.example"))).toEqual([]);
  expect(await page.locator('a[href*="evil.example"]').count()).toBe(0);
});

test("an image holding several QR codes is refused rather than silently picking one", async ({
  page,
}) => {
  await setupVault(page);

  await feedQr(page, "good", { repeat: 3 });
  await expect(page.getByTestId("qr-error")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("qr-error")).toContainText("QR codes");
  await expect(page.getByTestId("qr-preview")).toHaveCount(0);

  const vault = await storedVault(page);
  expect(vault.entries.length).toBe(0);
});

test("a scanned Google Authenticator export imports every account it carries", async ({ page }) => {
  await setupVault(page);

  await feedQr(page, "migration", { scale: 5 });
  await expect(page.getByTestId("qr-preview")).toBeVisible({ timeout: T });
  await expect(page.getByTestId("qr-summary")).toContainText("2 accounts");
  await page.getByTestId("qr-confirm").click();

  const vault = await storedVault(page);
  const labels = vault.entries.map((e) => e.label).sort();
  expect(labels).toEqual(["alice@example.com", "bob@example.com"]);
});
