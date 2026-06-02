import Link from "next/link";
import { WaitlistForm } from "./waitlist-form";

// Stealth splash. Deliberately minimal: NO security superlatives, no pricing,
// no launch dates, no audit/SOC-2/post-quantum claims. See MARKETING-CLAIMS.md.
export default function Home() {
  return (
    <main className="mx-auto flex min-h-screen max-w-xl flex-col justify-center gap-8 px-6 py-16">
      <div className="flex items-center gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-neutral-900 font-mono text-lg font-bold text-white dark:bg-white dark:text-neutral-900">
          {"//"}
        </div>
        <span className="text-sm uppercase tracking-widest text-neutral-500">
          Working name
        </span>
      </div>

      <div className="space-y-4">
        <h1 className="text-4xl font-bold tracking-tight">Sigil</h1>
        <p className="text-lg text-neutral-600 dark:text-neutral-300">
          A paid, encrypted authenticator for people who already have a real
          digital life. Currently in private development.
        </p>
        <p className="text-sm text-neutral-500">
          Request early access and we&apos;ll reach out when the private beta
          opens. No spam, one email.
        </p>
      </div>

      <WaitlistForm />

      <footer className="border-t border-neutral-200 pt-6 text-xs text-neutral-400 dark:border-neutral-800">
        <p>
          Pre-launch. Name and brand are provisional, pending trademark
          clearance.{" "}
          <Link href="/privacy" className="underline">
            Privacy
          </Link>{" "}
          ·{" "}
          <Link href="/terms" className="underline">
            Terms
          </Link>{" "}
          ·{" "}
          <Link href="/imprint" className="underline">
            Imprint
          </Link>{" "}
          ·{" "}
          <Link href="/security" className="underline">
            Security
          </Link>
        </p>
      </footer>
    </main>
  );
}
