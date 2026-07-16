import TotpDemo from "./totp-demo";

// Server component shell. TotpDemo is a client component that loads the wasm in
// the browser only (dynamic import inside an effect), so nothing crypto-related
// evaluates during SSR.
export default function Home() {
  return (
    <main className="mx-auto max-w-2xl px-6 py-12">
      <div
        role="alert"
        className="mb-8 rounded-md border border-amber-500 bg-amber-50 p-4 text-sm text-amber-900 dark:border-amber-600 dark:bg-amber-950 dark:text-amber-200"
      >
        <strong className="block text-base font-bold uppercase tracking-wide">
          Pre-audit / UNAUDITED dev build
        </strong>
        <p className="mt-1">
          Internal development preview. The cryptography here is real but has{" "}
          <strong>not been audited</strong>. This is not a released product and
          makes no security guarantees. <strong>Do not store real secrets or
          real 2FA credentials.</strong>
        </p>
      </div>

      <h1 className="mb-2 text-2xl font-bold">Sigil webapp</h1>
      <p className="mb-8 text-sm text-neutral-500 dark:text-neutral-400">
        A minimal client-side demo running the libsigil core in the browser via
        WebAssembly. A full authenticator UI comes later.
      </p>

      <TotpDemo />
    </main>
  );
}
