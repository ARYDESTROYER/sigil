import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

// Pre-launch: explicitly tell crawlers to stay away (in addition to the
// X-Robots-Tag header in next.config.mjs and app/robots.ts). This is an internal
// DEV demo, not a deployed product.
export const metadata: Metadata = {
  title: "Sigil webapp (dev)",
  description: "Internal, pre-audit development build. Not public.",
  robots: {
    index: false,
    follow: false,
    nocache: true,
    googleBot: { index: false, follow: false },
  },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen bg-white text-neutral-900 antialiased dark:bg-neutral-950 dark:text-neutral-100">
        {children}
      </body>
    </html>
  );
}
