import type { Metadata, Viewport } from "next";
import type { ReactNode } from "react";
import "./globals.css";
import RegisterSW from "./register-sw";

// Pre-launch: explicitly tell crawlers to stay away (in addition to the
// X-Robots-Tag header in next.config.mjs and app/robots.ts). This is an internal
// DEV demo, not a deployed product. The PWA manifest below does NOT change that
// posture — a manifest never makes a site indexable.
export const metadata: Metadata = {
  title: "Sigil authenticator (dev)",
  description: "Internal, pre-audit development build. Not public.",
  applicationName: "Sigil",
  manifest: "/manifest.webmanifest",
  robots: {
    index: false,
    follow: false,
    nocache: true,
    googleBot: { index: false, follow: false },
  },
};

export const viewport: Viewport = {
  themeColor: "#0b1220",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-white text-neutral-900 antialiased dark:bg-neutral-950 dark:text-neutral-100">
        <a
          href="#main"
          className="sr-only rounded bg-neutral-900 px-3 py-2 text-sm font-medium text-white focus:not-sr-only focus:absolute focus:left-3 focus:top-3 focus:z-50 dark:bg-neutral-100 dark:text-neutral-900"
        >
          Skip to content
        </a>
        {children}
        <RegisterSW />
      </body>
    </html>
  );
}
