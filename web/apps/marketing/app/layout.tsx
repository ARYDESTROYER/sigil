import type { Metadata } from "next";
import type { ReactNode } from "react";
import "./globals.css";

// Pre-launch: explicitly tell crawlers to stay away (in addition to the
// X-Robots-Tag header in next.config.mjs and app/robots.ts).
export const metadata: Metadata = {
  title: "Sigil (working name)",
  description: "A paid, encrypted authenticator. In private development.",
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
