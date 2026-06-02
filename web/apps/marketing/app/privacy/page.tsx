import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Privacy Policy — Sigil (working name)",
  robots: { index: false, follow: false },
};

// PRE-LAUNCH DRAFT. Not legal advice; to be reviewed by counsel before launch.
// Published BEFORE any waitlist write so the signup consent ("have read the
// Privacy Policy") references a document that actually exists.
export default function Privacy() {
  return (
    <main className="mx-auto max-w-2xl space-y-6 px-6 py-16 text-sm leading-relaxed text-neutral-700 dark:text-neutral-300">
      <h1 className="text-2xl font-bold text-neutral-900 dark:text-neutral-100">
        Privacy Policy
      </h1>
      <p className="text-neutral-500">
        Pre-launch draft, last updated 2 June 2026. Subject to change before
        public launch.
      </p>

      <section className="space-y-2">
        <h2 className="font-semibold">Who we are</h2>
        <p>
          Sigil is in private development by its founders (a legal entity is
          being formed; this notice will name the controller once incorporated).
          Contact: privacy@sigilapp.io.
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="font-semibold">What we collect at this stage</h2>
        <p>
          Only the email address you submit to the early-access waitlist, the
          timestamp, the exact consent text you agreed to, and a coarse source
          tag (e.g. which link brought you here). Nothing else. We do not run
          third-party analytics that profile you, and we do not use advertising
          cookies.
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="font-semibold">Legal basis</h2>
        <p>
          Your explicit, opt-in consent (GDPR Art. 6(1)(a); India DPDP Act 2023
          notice-and-consent). You may withdraw at any time by emailing
          privacy@sigilapp.io, which deletes your record.
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="font-semibold">Sub-processors</h2>
        <p>
          Email delivery: Postmark. Hosting/CDN: Cloudflare and Hetzner. These
          parties process the waitlist email solely to deliver our messages and
          serve this site.
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="font-semibold">Retention &amp; your rights</h2>
        <p>
          We keep waitlist emails until launch or until you ask us to delete
          them, whichever is first. You can request access, correction or
          deletion at privacy@sigilapp.io. For India DPDP grievances, a
          Grievance Officer will be named here before launch.
        </p>
      </section>
    </main>
  );
}
