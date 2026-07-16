import type { MetadataRoute } from "next";

// PWA manifest so the (dev, UNAUDITED) authenticator is installable and — with
// the service worker (public/sw.js) — works fully OFFLINE. A real authenticator
// must produce codes without a network. This does NOT change the no-index
// posture: robots.ts + the X-Robots-Tag header + layout metadata still forbid
// indexing; a manifest never makes a site crawlable.
export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Sigil authenticator (dev)",
    short_name: "Sigil",
    description:
      "Client-side, end-to-end-encrypted TOTP authenticator. Pre-audit dev build.",
    start_url: "/",
    scope: "/",
    display: "standalone",
    orientation: "portrait",
    background_color: "#0b1220",
    theme_color: "#0b1220",
    icons: [
      { src: "/icons/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" },
      { src: "/icons/icon-512.png", sizes: "512x512", type: "image/png", purpose: "any" },
      {
        src: "/icons/icon-maskable-512.png",
        sizes: "512x512",
        type: "image/png",
        purpose: "maskable",
      },
    ],
  };
}
