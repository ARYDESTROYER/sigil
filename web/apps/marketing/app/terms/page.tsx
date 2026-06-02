import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Terms — Sigil (working name)",
  robots: { index: false, follow: false },
};

export default function Terms() {
  return (
    <main className="mx-auto max-w-2xl space-y-6 px-6 py-16 text-sm leading-relaxed text-neutral-700 dark:text-neutral-300">
      <h1 className="text-2xl font-bold text-neutral-900 dark:text-neutral-100">
        Terms
      </h1>
      <p className="text-neutral-500">Pre-launch draft, 2 June 2026.</p>
      <p>
        This site advertises an early-access waitlist for a product still in
        development. There is no service, subscription, or payment offered here
        yet, and no commitment is made as to features, pricing, availability, or
        launch timing. Joining the waitlist places you under no obligation. The
        product name and branding are provisional and may change.
      </p>
      <p>
        Full Terms of Service will be published, and reviewed by counsel, before
        any paid product launches.
      </p>
    </main>
  );
}
