// leak.spec.mjs — the recovery code must reach NO store, NO log, NO request and
// NO URL, in the REAL unpacked MV3 extension.
//
// ⭐ THE RECOVERY CODE IS A BEARER CREDENTIAL FOR THE WHOLE ACCOUNT (ADR 0042).
// The constraint is absolute: never persisted, never logged.
//
// The shipped specs checked `chrome.storage.local` and the page URL, which is
// narrower than the constraint they claimed — a planted
// `sessionStorage.setItem(...)` plus a `console.log(...)` in the restore flow
// survived them. This sweep enumerates instead of expecting:
//
//   * EVERY chrome.storage area (local, sync, session, managed) in full
//   * EVERY localStorage / sessionStorage key and value
//   * cookies
//   * EVERY IndexedDB database, store and record
//   * EVERY Cache Storage entry
//   * the rendered DOM after the sheet is dismissed
//   * EVERY outgoing request URL and body, for the whole page lifetime
//   * EVERY console message and page error, for the whole page lifetime
//   * the address bar
//
// The server is the fake; the wrap, the unwrap, the HKDF derivation, the Argon2id
// sealing and the TOTP code are all real, in the extension's own wasm.

import { test, expect, chromium } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { startFakeSigild } from "../../sigil-wasm/test/fake-sigild.mjs";
import { sealedOnlyProblems, emptyProblems } from "../../sigil-wasm/test/sealed-store-helper.mjs";

const EXT_DIR = path.dirname(fileURLToPath(new URL("../package.json", import.meta.url)));
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PINNED_T = 59;
const RFC_CODE_6 = "287082";
const VAULT_ID = "ext-leak-vault";

async function extensionId() {
  const manifest = JSON.parse(await readFile(path.join(EXT_DIR, "manifest.json"), "utf8"));
  const der = Buffer.from(manifest.key, "base64");
  const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

async function launchProfile() {
  const userDataDir = await mkdtemp(path.join(tmpdir(), "sigil-ext-leak-"));
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

/** Open the popup with listeners attached BEFORE the first navigation. */
async function openPopup(context) {
  const page = await context.newPage();
  const wire = [];
  const logs = [];
  page.on("request", (r) => {
    wire.push(r.url());
    const pd = r.postData();
    if (pd) wire.push(pd);
  });
  page.on("console", (m) => logs.push(`${m.type()} ${m.text()}`));
  page.on("pageerror", (e) => logs.push(`PAGEERROR ${String(e)}`));
  await page.goto(`chrome-extension://${id}/src/popup/popup.html?t=${PINNED_T}`);
  await expect(page.locator("body")).toHaveAttribute("data-wasm", /.+/, { timeout: 30_000 });
  return { page, wire, logs };
}

/** Dump EVERY client-side store this extension page can reach. */
async function sweepStorage(page) {
  return page.evaluate(async () => {
    const parts = [];
    const localKeys = [];

    for (const area of ["local", "sync", "session", "managed"]) {
      try {
        const all = await chrome.storage[area].get(null);
        if (area === "local") localKeys.push(...Object.keys(all));
        parts.push(`chrome.storage.${area}=${JSON.stringify(all)}`);
      } catch {
        parts.push(`chrome.storage.${area}=unavailable`);
      }
    }

    for (let i = 0; i < window.localStorage.length; i++) {
      const k = window.localStorage.key(i);
      parts.push(`localStorage:${k}=${window.localStorage.getItem(k)}`);
    }
    for (let i = 0; i < window.sessionStorage.length; i++) {
      const k = window.sessionStorage.key(i);
      parts.push(`sessionStorage:${k}=${window.sessionStorage.getItem(k)}`);
    }
    parts.push(`cookie:${document.cookie}`);

    try {
      const dbs = (await indexedDB.databases?.()) ?? [];
      for (const meta of dbs) {
        if (!meta.name) continue;
        const db = await new Promise((resolve) => {
          const req = indexedDB.open(meta.name);
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => resolve(null);
          req.onblocked = () => resolve(null);
        });
        if (!db) continue;
        for (const storeName of Array.from(db.objectStoreNames)) {
          const rows = await new Promise((resolve) => {
            try {
              const req = db.transaction(storeName, "readonly").objectStore(storeName).getAll();
              req.onsuccess = () => resolve(req.result);
              req.onerror = () => resolve([]);
            } catch {
              resolve([]);
            }
          });
          parts.push(`idb:${meta.name}/${storeName}=${JSON.stringify(rows)}`);
        }
        db.close();
      }
    } catch {
      parts.push("idb:unavailable");
    }

    try {
      if (globalThis.caches) {
        for (const name of await caches.keys()) {
          const cache = await caches.open(name);
          for (const req of await cache.keys()) {
            const res = await cache.match(req);
            const body = res ? await res.clone().text().catch(() => "") : "";
            parts.push(`cache:${name}/${req.url}=${body}`);
          }
        }
      }
    } catch {
      parts.push("cache:unavailable");
    }

    // ⭐ The STRUCTURAL view, beside the needle haystack. This used to return
    // only `localKeys` (key NAMES of chrome.storage.local), which is why a
    // plaintext `chrome.storage.session.set({...device})` — the raw Ed25519
    // seed, the hybrid secret and every vault key — sailed through 12/12 green.
    const areas = {};
    for (const area of ["local", "sync", "session", "managed"]) {
      try {
        areas[area] = await chrome.storage[area].get(null);
      } catch {
        areas[area] = "unavailable";
      }
    }
    const localStore = {};
    for (let i = 0; i < window.localStorage.length; i++) {
      const k = window.localStorage.key(i);
      localStore[k] = window.localStorage.getItem(k) ?? "";
    }
    const sessionStore = {};
    for (let i = 0; i < window.sessionStorage.length; i++) {
      const k = window.sessionStorage.key(i);
      sessionStore[k] = window.sessionStorage.getItem(k) ?? "";
    }
    const idbNames = [];
    try {
      for (const meta of (await indexedDB.databases?.()) ?? []) {
        if (meta.name) idbNames.push(meta.name);
      }
    } catch {
      /* enumeration unsupported; the haystack sweep above still ran */
    }
    const cacheNames = globalThis.caches ? await caches.keys().catch(() => []) : [];

    return {
      haystack: parts.join("\n"),
      localKeys: localKeys.sort(),
      areas,
      localStore,
      sessionStore,
      cookie: document.cookie,
      idbNames,
      cacheNames,
    };
  });
}

/**
 * ⭐ ADR 0036, ASSERTED POSITIVELY: `chrome.storage.local` holds EXACTLY the two
 * sealed `SIGILcli` containers (magic bytes checked after base64-decoding), and
 * EVERY other storage surface the popup can reach is EMPTY —
 * chrome.storage.sync/session/managed, the page's own localStorage and
 * sessionStorage, cookies, IndexedDB and Cache Storage.
 *
 * The old spec pinned `chrome.storage.local` KEY NAMES and swept everything else
 * for one needle (the recovery code). A verifier added a single
 * `chrome.storage.session.set({...})` to the extension's persistDevice, dumping
 * the raw 32-byte device seed, the hybrid secret and every vault key in the
 * clear, and the suite stayed 12/12 green. Emptiness catches the leak nobody
 * wrote a needle for.
 */
function expectSealedOnly(where, swept, expectedKeys) {
  const localArea = swept.areas.local === "unavailable" ? {} : swept.areas.local;
  const problems = [
    ...sealedOnlyProblems(localArea, expectedKeys),
    ...emptyProblems("chrome.storage.sync", swept.areas.sync),
    ...emptyProblems("chrome.storage.session", swept.areas.session),
    ...emptyProblems("chrome.storage.managed", swept.areas.managed),
    ...emptyProblems("page localStorage", swept.localStore),
    ...emptyProblems("page sessionStorage", swept.sessionStore),
    ...emptyProblems("cookies", swept.cookie),
    ...emptyProblems("IndexedDB", swept.idbNames),
    ...emptyProblems("Cache Storage", swept.cacheNames),
  ];
  expect(problems, `${where}: ADR 0036 says browsers persist ONLY sealed containers`).toEqual([]);
}

function needles(formatted) {
  const raw = formatted.replace(/-/g, "");
  return [formatted, formatted.toLowerCase(), raw, raw.toLowerCase()];
}

function assertAbsent(where, haystack, formatted) {
  for (const needle of needles(formatted)) {
    expect(haystack, `${where} must not contain the recovery code`).not.toContain(needle);
  }
}

test("profile 1: printing a kit leaks the code into no store, log, request or URL", async () => {
  const { context, userDataDir } = await launchProfile();
  try {
    const { page, wire, logs } = await openPopup(context);

    await page.getByTestId("setup-password").fill("ext-leak-one");
    await page.getByTestId("setup-password-2").fill("ext-leak-one");
    await page.getByTestId("setup-submit").click();
    await expect(page.getByTestId("view-unlocked")).toBeVisible({ timeout: 30_000 });

    await page.getByTestId("add-toggle").click();
    await page.getByTestId("add-label").fill("rfc6238");
    await page.getByTestId("add-secret").fill(RFC_SECRET);
    await page.getByTestId("add-submit").click();
    await expect(page.getByTestId("code")).toHaveText(RFC_CODE_6);

    await page.getByTestId("sync-toggle").click();
    await page.getByTestId("sync-url").fill(fake.baseUrl);
    await page.getByTestId("sync-vault").fill(VAULT_ID);
    await page.getByTestId("device-token").fill("operator-token-0123456789abcdef");
    await page.getByTestId("device-enroll").click();
    await expect(page.getByTestId("status")).toContainText("Enrolled as", { timeout: 30_000 });

    await page.getByTestId("sharing-toggle").click();
    await page.getByTestId("sharing-convert").click();
    await expect(page.getByTestId("status")).toContainText("random 32-byte vault key", {
      timeout: 30_000,
    });
    await page.getByTestId("sync-push").click();
    await expect(page.getByTestId("status")).toContainText("Pushed sealed container", {
      timeout: 30_000,
    });

    await page.getByTestId("recovery-toggle").click();
    await page.getByTestId("recovery-generate").click();
    await expect(page.getByTestId("recovery-sheet")).toBeVisible({ timeout: 60_000 });
    kitCode = ((await page.getByTestId("recovery-code").textContent()) ?? "").trim();
    kitDeviceId = ((await page.getByTestId("recovery-kit-id").textContent()) ?? "").trim();
    expect(kitCode.replace(/-/g, "")).toHaveLength(56);

    // Cover (derived path) and dismiss — the two moments a careless
    // implementation would stash the code.
    await page.getByTestId("recovery-cover-kit").fill(kitDeviceId);
    await page.getByTestId("recovery-cover").click();
    await expect(page.getByTestId("status")).toContainText("derived locally", { timeout: 30_000 });
    await page.getByTestId("recovery-written").check();
    await page.getByTestId("recovery-hide").click();
    await expect(page.getByTestId("recovery-sheet")).toBeHidden();

    const swept = await sweepStorage(page);
    assertAbsent("client storage", swept.haystack, kitCode);
    assertAbsent("DOM after the sheet is hidden", await page.content(), kitCode);
    assertAbsent("network traffic", wire.join("\n"), kitCode);
    assertAbsent("console output", logs.join("\n"), kitCode);
    assertAbsent("address bar", page.url(), kitCode);
    // Only the two sealed containers are at rest — enumerated, not assumed.
    expect(swept.localKeys.sort()).toEqual([
      "sigil.extension.device.v1",
      "sigil.extension.vault.v1",
    ]);
    // ⭐ ...and asserted POSITIVELY: those values ARE sealed containers, and
    // every other storage surface is EMPTY.
    expectSealedOnly("profile 1", swept, [
      "sigil.extension.device.v1",
      "sigil.extension.vault.v1",
    ]);
    expect(swept.haystack).not.toContain("ext-leak-one");
    expect(logs.filter((l) => l.startsWith("PAGEERROR"))).toEqual([]);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});

test("profile 2: RESTORING with the code leaks it into no store, log, request or URL", async () => {
  expect(kitCode).not.toBe("");
  const { context, userDataDir } = await launchProfile();
  try {
    const { page, wire, logs } = await openPopup(context);

    await page.getByTestId("restore-toggle").click();
    await page.getByTestId("restore-url").fill(fake.baseUrl);
    await page.getByTestId("restore-device-id").fill(kitDeviceId);
    await page.getByTestId("restore-password").fill("ext-leak-two");
    await page.getByTestId("restore-confirm").fill("ext-leak-two");
    await page.getByTestId("restore-code").fill(kitCode.toLowerCase());
    await page.getByTestId("restore-submit").click();

    await expect(page.getByTestId("view-unlocked")).toBeVisible({ timeout: 60_000 });
    await expect(page.getByTestId("code")).toHaveText(RFC_CODE_6);

    const swept = await sweepStorage(page);
    assertAbsent("restored client storage", swept.haystack, kitCode);
    assertAbsent("restored DOM", await page.content(), kitCode);
    assertAbsent("restore network traffic", wire.join("\n"), kitCode);
    assertAbsent("restore console output", logs.join("\n"), kitCode);
    assertAbsent("restored address bar", page.url(), kitCode);
    expect(swept.localKeys.sort()).toEqual([
      "sigil.extension.device.v1",
      "sigil.extension.vault.v1",
    ]);
    expectSealedOnly("restored profile", swept, [
      "sigil.extension.device.v1",
      "sigil.extension.vault.v1",
    ]);
    expect(swept.haystack).not.toContain("ext-leak-two");
    expect(logs.filter((l) => l.startsWith("PAGEERROR"))).toEqual([]);

    // ⭐ A RELOAD must not resurrect it: the popup comes back LOCKED and the
    // sweep is still clean.
    await page.reload();
    await expect(page.getByTestId("view-locked")).toBeVisible({ timeout: 30_000 });
    const again = await sweepStorage(page);
    assertAbsent("client storage after reload", again.haystack, kitCode);
    assertAbsent("DOM after reload", await page.content(), kitCode);
    expectSealedOnly("after reload", again, [
      "sigil.extension.device.v1",
      "sigil.extension.vault.v1",
    ]);
  } finally {
    await context.close();
    await rm(userDataDir, { recursive: true, force: true });
  }
});
