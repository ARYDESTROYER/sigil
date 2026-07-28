import { expect, test, type Browser, type Page } from "@playwright/test";
// @ts-expect-error — plain .mjs test helper shared with the extension suite.
import { startFakeSigild } from "../../../../sigil-wasm/test/fake-sigild.mjs";
// @ts-expect-error — plain .mjs test helper shared with the extension suite.
import { sealedOnlyProblems, emptyProblems } from "../../../../sigil-wasm/test/sealed-store-helper.mjs";

/**
 * ⭐ THE RECOVERY CODE IS A BEARER CREDENTIAL FOR THE WHOLE ACCOUNT (ADR 0042).
 * The constraint is absolute: it is NEVER persisted and NEVER logged.
 *
 * The shipped specs checked `localStorage` and `page.url()`, which is narrower
 * than the constraint they claimed. A verifier planted
 * `sessionStorage.setItem("dbg-kit", code)` and `console.log("kit=" + code)`
 * inside the restore flow and the recovery spec stayed green.
 *
 * So this sweep is deliberately BROAD, and it enumerates rather than expecting:
 *   * EVERY localStorage key and value (not the two we expect to see)
 *   * EVERY sessionStorage key and value
 *   * cookies
 *   * EVERY IndexedDB database, store and record
 *   * EVERY Cache Storage entry (this app is a PWA with a service worker)
 *   * the rendered DOM after the sheet is dismissed
 *   * EVERY outgoing request URL and body, for the whole page lifetime
 *   * EVERY console message and page error, for the whole page lifetime
 *   * the address bar
 *
 * A leak anywhere in that set fails, in whichever case and grouping it was
 * written — the raw 56 characters, the grouped form, and both lower-cased.
 */

const T = 60_000;
const RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_CODE = "287082";
const VAULT_ID = "leak-sweep-vault";
const WEBAPP_ORIGIN = "http://127.0.0.1:3210";

type Fake = { baseUrl: string; close: () => Promise<void>; log: string[] };
let fake: Fake;

test.beforeAll(async () => {
  fake = (await startFakeSigild({ corsOrigins: [WEBAPP_ORIGIN] })) as Fake;
});
test.afterAll(async () => {
  await fake?.close();
});

/** Attach BEFORE the first navigation so nothing is missed. */
function watch(page: Page) {
  const wire: string[] = [];
  const logs: string[] = [];
  page.on("request", (r) => {
    wire.push(r.url());
    const pd = r.postData();
    if (pd) wire.push(pd);
  });
  page.on("console", (m) => logs.push(`${m.type()} ${m.text()}`));
  page.on("pageerror", (e) => logs.push(`PAGEERROR ${String(e)}`));
  return { wire, logs };
}

/**
 * Dump EVERY client-side store this origin can reach, as one haystack string
 * plus the localStorage key list (which the spec also pins exactly).
 */
async function sweepStorage(page: Page) {
  return page.evaluate(async () => {
    const parts: string[] = [];
    const localKeys: string[] = [];

    for (let i = 0; i < window.localStorage.length; i++) {
      const k = window.localStorage.key(i)!;
      localKeys.push(k);
      parts.push(`localStorage:${k}=${window.localStorage.getItem(k)}`);
    }
    for (let i = 0; i < window.sessionStorage.length; i++) {
      const k = window.sessionStorage.key(i)!;
      parts.push(`sessionStorage:${k}=${window.sessionStorage.getItem(k)}`);
    }
    parts.push(`cookie:${document.cookie}`);

    // IndexedDB — every database, every store, every record.
    try {
      const dbs = (await (
        indexedDB as IDBFactory & { databases?: () => Promise<{ name?: string }[]> }
      ).databases?.()) ?? [];
      for (const meta of dbs) {
        if (!meta.name) continue;
        const db = await new Promise<IDBDatabase | null>((resolve) => {
          const req = indexedDB.open(meta.name!);
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => resolve(null);
          req.onblocked = () => resolve(null);
        });
        if (!db) continue;
        for (const storeName of Array.from(db.objectStoreNames)) {
          const rows = await new Promise<unknown[]>((resolve) => {
            try {
              const req = db.transaction(storeName, "readonly").objectStore(storeName).getAll();
              req.onsuccess = () => resolve(req.result as unknown[]);
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

    // Cache Storage — this app registers a service worker that precaches assets.
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

    // ⭐ The STRUCTURAL view, beside the needle haystack. sweepStorage used to
    // return only `localKeys` (key NAMES), which is why a plaintext
    // sessionStorage dump of the device seed sailed through 19/19 green specs.
    const local: Record<string, string> = {};
    for (let i = 0; i < window.localStorage.length; i++) {
      const k = window.localStorage.key(i)!;
      local[k] = window.localStorage.getItem(k) ?? "";
    }
    const session: Record<string, string> = {};
    for (let i = 0; i < window.sessionStorage.length; i++) {
      const k = window.sessionStorage.key(i)!;
      session[k] = window.sessionStorage.getItem(k) ?? "";
    }
    const idbNames: string[] = [];
    try {
      const dbs = (await (
        indexedDB as IDBFactory & { databases?: () => Promise<{ name?: string }[]> }
      ).databases?.()) ?? [];
      for (const meta of dbs) if (meta.name) idbNames.push(meta.name);
    } catch {
      /* enumeration unsupported: the haystack sweep above still ran */
    }
    const cacheUrls: string[] = [];
    try {
      if (globalThis.caches) {
        for (const name of await caches.keys()) {
          const cache = await caches.open(name);
          for (const req of await cache.keys()) cacheUrls.push(req.url);
        }
      }
    } catch {
      /* ditto */
    }

    return {
      haystack: parts.join("\n"),
      localKeys: localKeys.sort(),
      local,
      session,
      cookie: document.cookie,
      idbNames,
      cacheUrls,
      origin: window.location.origin,
    };
  });
}

type Swept = Awaited<ReturnType<typeof sweepStorage>>;

/**
 * ⭐ ADR 0036, ASSERTED POSITIVELY: every persisted value is a sealed `SIGILcli`
 * container, and every OTHER client-side store is EMPTY.
 *
 * The old spec pinned localStorage KEY NAMES and nothing else, so a value could
 * be anything and sessionStorage / IndexedDB / Cache Storage were unconstrained.
 * A verifier proved that by adding one plaintext
 * `sessionStorage.setItem("sigil.webapp.cache", JSON.stringify(device))` to
 * persistDevice — dumping the raw device seed, the hybrid secret and every vault
 * key — with the whole suite still green.
 *
 * Cache Storage is the one surface allowed to be non-empty: this app is a PWA
 * whose service worker precaches its own shell. It is constrained STRUCTURALLY
 * instead — every cached entry must be a SAME-ORIGIN asset URL, so a sync
 * response (or anything else cross-origin) can never be sitting in it.
 */
function expectSealedOnly(where: string, s: Swept, expectedKeys: string[]) {
  const problems = [
    ...sealedOnlyProblems(s.local, expectedKeys),
    ...emptyProblems("sessionStorage", s.session),
    ...emptyProblems("cookies", s.cookie),
    ...emptyProblems("IndexedDB", s.idbNames),
    ...s.cacheUrls.filter((u) => !isPrecacheableShellAsset(u, s.origin)).map(
      (u) => `Cache Storage holds a NON-SHELL entry: ${u}`,
    ),
  ];
  expect(problems, `${where}: ADR 0036 says browsers persist ONLY sealed containers`).toEqual([]);
}

/**
 * Is this Cache Storage entry something the service worker is ALLOWED to hold?
 *
 * ⚠️ THIS USED TO BE `!url.startsWith(origin)` — i.e. it only ever flagged
 * CROSS-origin entries, which made it vacuous against the threat it exists to
 * catch: every plausible leak (a regression, an attacker-controlled write, the
 * service worker itself) is SAME-origin. An auditor proved it by writing a full
 * plaintext dump of the device identity — Ed25519 seed, hybrid secret and every
 * vault key — to a same-origin Cache Storage entry, and this suite still passed
 * 19/19 while the extension caught the identical plant.
 *
 * The service worker (public/sw.js) caches only same-origin GET responses, and
 * only the app SHELL plus static assets. So the honest constraint is an
 * ALLOWLIST of what the shell legitimately contains, not an origin check:
 * anything else in that cache is state the app put there, which is exactly what
 * ADR 0036 forbids.
 */
function isPrecacheableShellAsset(rawUrl: string, origin: string): boolean {
  if (!rawUrl.startsWith(origin)) return false; // cross-origin: never legitimate
  let path: string;
  try {
    path = new URL(rawUrl).pathname;
  } catch {
    return false;
  }
  if (path === "/") return true; // the shell itself (SHELL = ["/"] in sw.js)
  if (path.startsWith("/_next/")) return true; // Next.js build output
  return /\.(js|mjs|css|wasm|png|svg|ico|webmanifest|json|woff2?)$/.test(path);
}

/** Every casing/grouping a leak could plausibly take. */
function needles(formatted: string): string[] {
  const raw = formatted.replace(/-/g, "");
  return [formatted, formatted.toLowerCase(), raw, raw.toLowerCase()];
}

function assertAbsent(where: string, haystack: string, formatted: string) {
  for (const needle of needles(formatted)) {
    expect(haystack, `${where} must not contain the recovery code`).not.toContain(needle);
  }
}

test("the recovery code reaches NO store, NO log, NO request and NO URL — on both the printing and the restoring profile", async ({
  page,
  browser,
}: {
  page: Page;
  browser: Browser;
}) => {
  const w1 = watch(page);

  // ── profile 1: print a kit that actually covers a vault ────────────────────
  await page.goto("/?t=59");
  await page.getByTestId("setup-password").fill("leak-sweep-one");
  await page.getByTestId("setup-confirm").fill("leak-sweep-one");
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });

  await page.getByTestId("add-label").fill("rfc-vector");
  await page.getByTestId("add-secret").fill(RFC_SECRET_B32);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });

  await page.getByTestId("sync-url").fill(fake.baseUrl);
  await page.getByTestId("sync-vault-id").fill(VAULT_ID);
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

  await page.getByTestId("recovery-generate").click();
  await expect(page.getByTestId("recovery-sheet")).toBeVisible({ timeout: T });
  const formatted = ((await page.getByTestId("recovery-code").textContent()) ?? "").trim();
  const kitId = ((await page.getByTestId("recovery-kit-id").textContent()) ?? "").trim();
  expect(formatted.replace(/-/g, "")).toHaveLength(56);

  // Cover from the printing browser (the derived path) and then dismiss the
  // sheet — the two moments a careless implementation would stash the code.
  await page.getByTestId("recovery-cover-kit").fill(kitId);
  await page.getByTestId("recovery-cover").click();
  await expect(page.getByTestId("recovery-status")).toContainText("derived locally", { timeout: T });
  await page.getByTestId("recovery-written").check();
  await page.getByTestId("recovery-hide").click();
  await expect(page.getByTestId("recovery-code")).toHaveCount(0);

  const s1 = await sweepStorage(page);
  assertAbsent("profile 1 client storage", s1.haystack, formatted);
  assertAbsent("profile 1 DOM after the sheet is hidden", await page.content(), formatted);
  assertAbsent("profile 1 network traffic", w1.wire.join("\n"), formatted);
  assertAbsent("profile 1 console output", w1.logs.join("\n"), formatted);
  assertAbsent("profile 1 address bar", page.url(), formatted);
  // Only sealed containers are at rest — enumerated, not assumed.
  expect(s1.localKeys).toEqual(["sigil.webapp.device.v1", "sigil.webapp.vault.v1"]);
  // ⭐ ...and asserted POSITIVELY: those values ARE `SIGILcli` containers, and
  // every other store is empty.
  expectSealedOnly("profile 1", s1, ["sigil.webapp.device.v1", "sigil.webapp.vault.v1"]);
  expect(w1.logs.filter((l) => l.startsWith("PAGEERROR"))).toEqual([]);

  // ── profile 2: a clean install RESTORES with the code ──────────────────────
  const ctx = await browser.newContext();
  const p2 = await ctx.newPage();
  const w2 = watch(p2);
  await p2.goto("/?t=59");
  expect(await p2.evaluate(() => Object.keys(window.localStorage))).toEqual([]);

  await p2.getByTestId("restore-open").click();
  await p2.getByTestId("restore-url").fill(fake.baseUrl);
  await p2.getByTestId("restore-device-id").fill(kitId);
  await p2.getByTestId("restore-password").fill("leak-sweep-two");
  await p2.getByTestId("restore-confirm").fill("leak-sweep-two");
  await p2.getByTestId("restore-code").fill(formatted.toLowerCase());
  await p2.getByTestId("restore-submit").click();

  await expect(p2.getByTestId("vault-view")).toBeVisible({ timeout: T });
  await expect(p2.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });

  const s2 = await sweepStorage(p2);
  assertAbsent("restored client storage", s2.haystack, formatted);
  assertAbsent("restored DOM", await p2.content(), formatted);
  assertAbsent("restore network traffic", w2.wire.join("\n"), formatted);
  assertAbsent("restore console output", w2.logs.join("\n"), formatted);
  assertAbsent("restored address bar", p2.url(), formatted);
  expect(s2.localKeys).toEqual(["sigil.webapp.device.v1", "sigil.webapp.vault.v1"]);
  expectSealedOnly("restored profile", s2, [
    "sigil.webapp.device.v1",
    "sigil.webapp.vault.v1",
  ]);
  expect(w2.logs.filter((l) => l.startsWith("PAGEERROR"))).toEqual([]);

  // The new password is memory-only too.
  expect(s2.haystack).not.toContain("leak-sweep-two");

  // ⭐ A RELOAD must not resurrect it from anywhere: the restored profile comes
  // back LOCKED, and the sweep is still clean.
  await p2.reload();
  await expect(p2.getByTestId("unlock-submit")).toBeVisible({ timeout: T });
  const s3 = await sweepStorage(p2);
  assertAbsent("client storage after reload", s3.haystack, formatted);
  assertAbsent("DOM after reload", await p2.content(), formatted);
  expectSealedOnly("after reload", s3, ["sigil.webapp.device.v1", "sigil.webapp.vault.v1"]);

  await ctx.close();
});
