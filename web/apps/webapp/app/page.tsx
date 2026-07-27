import Authenticator from "./authenticator";
import TotpDemo from "./totp-demo";

// Server component shell. Authenticator + TotpDemo are client components that
// load the wasm in the browser only (dynamic import inside an effect), so nothing
// crypto-related evaluates during SSR.
export default function Home() {
  return (
    <div className="mx-auto max-w-2xl px-4 py-8 sm:px-6 sm:py-12">
      <header>
        <div className="mb-8 rounded-md border border-amber-600 bg-amber-50 p-4 text-sm text-amber-900 dark:border-amber-600 dark:bg-amber-950 dark:text-amber-100">
          <strong className="block text-base font-bold uppercase tracking-wide">
            Pre-audit / UNAUDITED dev build
          </strong>
          <p className="mt-1">
            Internal development preview. The cryptography here is real but has{" "}
            <strong>not been audited</strong>. This is not a released product and
            makes no security guarantees.{" "}
            <strong>Do not store real secrets or real 2FA credentials.</strong>
          </p>
        </div>

        <h1 className="mb-2 text-2xl font-bold">Sigil authenticator</h1>
        <p className="mb-8 text-sm text-neutral-600 dark:text-neutral-400">
          A client-side TOTP authenticator, designed end-to-end encrypted (dev). Codes are
          computed by the libsigil core compiled to WebAssembly; your vault is
          sealed with a password and never leaves this browser in the clear. Works
          offline once loaded.
        </p>
      </header>

      <main id="main">
        <Authenticator />

        <details className="mt-10">
          <summary className="cursor-pointer rounded text-sm font-medium text-neutral-600 hover:text-neutral-900 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-neutral-500 dark:text-neutral-400 dark:hover:text-neutral-200">
            wasm self-check (dev)
          </summary>
          <div className="mt-4">
            <TotpDemo />
          </div>
        </details>
      </main>
    </div>
  );
}
