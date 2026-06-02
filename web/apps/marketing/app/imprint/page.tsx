import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Imprint — Sigil (working name)",
  robots: { index: false, follow: false },
};

// Imprint / Impressum placeholder (required for EU/DE visitors once an entity
// and address exist). Filled in before any public launch.
export default function Imprint() {
  return (
    <main className="mx-auto max-w-2xl space-y-6 px-6 py-16 text-sm leading-relaxed text-neutral-700 dark:text-neutral-300">
      <h1 className="text-2xl font-bold text-neutral-900 dark:text-neutral-100">
        Imprint
      </h1>
      <p className="text-neutral-500">Pre-launch placeholder, 2 June 2026.</p>
      <p>
        Sigil is operated by its founders. A registered legal entity, business
        address, and responsible-person details will appear here once
        incorporation completes. For any enquiry in the meantime, contact
        hello@sigilapp.io.
      </p>
    </main>
  );
}
