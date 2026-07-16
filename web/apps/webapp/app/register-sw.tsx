"use client";

import { useEffect } from "react";

/**
 * Registers the offline service worker (public/sw.js) after load, so the app
 * shell + wasm + JS/CSS chunks get cached and the authenticator works with NO
 * network on the next visit.
 *
 * Registered only in production (the Playwright + real deploy path); in `next
 * dev` a SW would fight HMR. Guarded for browsers without service workers and
 * for insecure contexts (SW requires https or localhost).
 */
export default function RegisterSW() {
  useEffect(() => {
    if (process.env.NODE_ENV !== "production") return;
    if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return;
    const onLoad = () => {
      navigator.serviceWorker.register("/sw.js").catch(() => {
        /* offline shell is a progressive enhancement; ignore failures */
      });
    };
    if (document.readyState === "complete") onLoad();
    else window.addEventListener("load", onLoad, { once: true });
    return () => window.removeEventListener("load", onLoad);
  }, []);
  return null;
}
