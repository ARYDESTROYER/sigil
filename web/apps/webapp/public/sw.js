/*
 * Sigil webapp service worker — offline app shell for the (dev, UNAUDITED)
 * authenticator. A real authenticator must generate codes with NO network.
 *
 * Strategy:
 *   install  — precache the "/" shell, then take over immediately.
 *   activate — delete any older cache versions, claim open clients.
 *   fetch    — SAME-ORIGIN GET only:
 *                • navigations: network-first, fall back to the cached shell;
 *                • assets (JS / CSS / .wasm / icons): cache-first, and cache
 *                  every successful GET at runtime so the second visit — and
 *                  the wasm-computed TOTP it powers — works fully offline.
 *
 * It NEVER touches cross-origin requests (e.g. the dev sigild sync on another
 * port) and NEVER caches or exposes a secret: the vault lives in localStorage,
 * SEALED. Only public static assets are cached. Bump CACHE to invalidate.
 */
const CACHE = "sigil-webapp-v1";
const SHELL = ["/"];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE)
      .then((cache) => cache.addAll(SHELL))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))),
      )
      .then(() => self.clients.claim()),
  );
});

function cacheable(res) {
  return res && res.ok && res.status === 200 && res.type !== "opaque";
}

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // leave cross-origin (sync) alone

  if (req.mode === "navigate") {
    event.respondWith(
      caches.open(CACHE).then(async (cache) => {
        try {
          const net = await fetch(req);
          if (cacheable(net)) cache.put("/", net.clone()); // keep the shell fresh
          return net;
        } catch {
          return (
            (await cache.match("/", { ignoreSearch: true })) ||
            (await cache.match(req)) ||
            Response.error()
          );
        }
      }),
    );
    return;
  }

  event.respondWith(
    caches.open(CACHE).then(async (cache) => {
      const cached = await cache.match(req);
      if (cached) return cached;
      const net = await fetch(req);
      if (cacheable(net)) cache.put(req, net.clone());
      return net;
    }),
  );
});
