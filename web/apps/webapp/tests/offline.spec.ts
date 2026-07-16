import { expect, test } from "@playwright/test";

// Proves the PWA works with NO network: the service worker (public/sw.js) caches
// the app shell + JS/CSS + the .wasm on first (online) load, so a later OFFLINE
// reload still renders AND still computes a real TOTP code IN THE WASM.
const EXPECTED_CODE = "287082"; // RFC 6238 vector at ?t=59 (default demo seed)
const T = 30_000;

test("works fully offline: cached wasm still computes a TOTP after going offline", async ({
  page,
  context,
}) => {
  // 1. First online load — registers the SW and computes the code via wasm.
  await page.goto("/?t=59");
  await expect(page.getByTestId("wasm-status")).toHaveText("ready", { timeout: T });
  await expect(page.getByTestId("totp-code")).toHaveText(EXPECTED_CODE, { timeout: T });

  // 2. Wait for the SW to be installed + active and controlling the page.
  await page.waitForFunction(
    async () => {
      if (!("serviceWorker" in navigator)) return false;
      await navigator.serviceWorker.ready;
      return navigator.serviceWorker.controller !== null;
    },
    null,
    { timeout: T },
  );

  // 3. One controlled online reload so every asset is fetched THROUGH the SW and
  //    written to the runtime cache (chunks the first load fetched before the SW
  //    took control are otherwise uncached).
  await page.reload();
  await expect(page.getByTestId("wasm-status")).toHaveText("ready", { timeout: T });
  await expect(page.getByTestId("totp-code")).toHaveText(EXPECTED_CODE, { timeout: T });

  // 4. Go OFFLINE and reload — no network at all now.
  await context.setOffline(true);
  await page.reload();

  // 5. The shell still renders and the wasm-computed code still appears.
  await expect(page.getByRole("heading", { name: "Sigil authenticator" })).toBeVisible({
    timeout: T,
  });
  await expect(page.getByTestId("wasm-status")).toHaveText("ready", { timeout: T });
  await expect(page.getByTestId("totp-code")).toHaveText(EXPECTED_CODE, { timeout: T });

  await context.setOffline(false);
});
