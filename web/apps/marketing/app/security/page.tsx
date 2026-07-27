import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Cryptographic posture — Sigil (working name)",
  robots: { index: false, follow: false },
};

// PRE-LAUNCH / PRE-AUDIT engineering note. Several of these primitives are now
// REALLY IMPLEMENTED in the pre-release codebase, so the old blanket "nothing is
// implemented" line was false — an under-claim, but still false. Correcting it
// must not tip into an over-claim, so every row keeps an explicit UNAUDITED
// qualifier, nothing is described as shipped (no client is released), and the
// page states outright that the system is NOT "post-quantum secure". See
// MARKETING-CLAIMS.md: no "audited", no "SOC 2", no "post-quantum secure", no
// unqualified "end-to-end encrypted" as a present-tense product claim.

type Posture = {
  layer: string;
  primitive: string;
  status: string;
  note: string;
};

// Order mirrors the layered design: secret derivation, data encryption, key
// exchange (classical + PQ), signatures (classical + PQ), then transport.
//
// "Implemented" means exactly one thing here: the code exists in the pre-release
// repository and its own test suite passes. It does NOT mean reviewed, released,
// or certified.
const rows: Posture[] = [
  {
    layer: "KDF",
    primitive: "Argon2id",
    status: "Implemented; unaudited",
    note: "Derives the vault key from a password.",
  },
  {
    layer: "AEAD",
    primitive: "XChaCha20-Poly1305",
    status: "Implemented; unaudited",
    note: "Encrypts the vault. Every stored record is sealed with it.",
  },
  {
    layer: "Classical key exchange",
    primitive: "X25519",
    status: "Implemented; unaudited",
    note: "The classical half of the hybrid KEM below.",
  },
  {
    layer: "Post-quantum KEM",
    primitive: "ML-KEM-768 (FIPS 203)",
    status: "Implemented; unaudited; load-bearing",
    note:
      "Combined with X25519 into a hybrid KEM that wraps a vault key when a vault is shared to another device, so that path is designed to hold if either half survives.",
  },
  {
    layer: "Classical signature",
    primitive: "Ed25519",
    status: "Implemented; unaudited",
    note: "Authenticates a device's requests to the sync server.",
  },
  {
    layer: "Post-quantum signature",
    primitive: "ML-DSA-65 (FIPS 204)",
    status: "Implemented; unaudited; not yet in the authentication path",
    note:
      "Exists and round-trips, including as a hybrid Ed25519 + ML-DSA-65 signature. Device authentication still uses Ed25519 alone.",
  },
  {
    layer: "Transport",
    primitive: "TLS 1.3 (X25519MLKEM768)",
    status: "Designed; planned; unaudited",
    note: "Not deployed — nothing is publicly hosted yet.",
  },
  {
    layer: "Current suite byte",
    primitive: "0x12",
    status: "Implemented; provisional",
    note: "The on-disk suite identifier may still change before launch.",
  },
];

export default function Security() {
  return (
    <main className="mx-auto max-w-2xl space-y-6 px-6 py-16 text-sm leading-relaxed text-neutral-700 dark:text-neutral-300">
      <h1 className="text-2xl font-bold text-neutral-900 dark:text-neutral-100">
        Cryptographic posture
      </h1>
      <p className="text-neutral-500">
        Pre-launch engineering note, updated 27 July 2026. This describes what
        the code does today and what is still design intent.
      </p>

      <p>
        Most of the primitives below are <strong>implemented</strong> in the
        pre-release codebase and covered by its own tests, including the
        post-quantum ones. That is the whole claim. None of it has been{" "}
        <strong>independently reviewed</strong>, and none of it has shipped:
        there is no released client, no public server, and no production data.
        An independent security audit is planned, and until it completes nothing
        here should be relied on. Do not store real two-factor secrets in a
        pre-release build.
      </p>

      <p>
        In particular: implementing ML-KEM-768 and ML-DSA-65 does{" "}
        <em>not</em> make a system &ldquo;post-quantum secure&rdquo;, and we do
        not claim that it does. The post-quantum KEM is used in hybrid with
        X25519 precisely because a hybrid construction is the honest response to
        a young standard — and the surrounding protocol, key management and
        transport are still being built.
      </p>

      <section className="space-y-3">
        <h2 className="font-semibold text-neutral-900 dark:text-neutral-100">
          Primitives and their status
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left">
            <thead>
              <tr className="border-b border-neutral-300 text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-700">
                <th className="py-2 pr-4 font-medium">Layer</th>
                <th className="py-2 pr-4 font-medium">Primitive</th>
                <th className="py-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr
                  key={row.layer}
                  className="border-b border-neutral-200 align-top dark:border-neutral-800"
                >
                  <td className="py-2 pr-4 text-neutral-700 dark:text-neutral-300">
                    {row.layer}
                  </td>
                  <td className="py-2 pr-4 font-mono text-neutral-900 dark:text-neutral-100">
                    {row.primitive}
                  </td>
                  <td className="py-2 text-neutral-500">
                    {row.status}
                    <span className="mt-1 block text-xs text-neutral-400">{row.note}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <p className="text-xs text-neutral-400">
        Status vocabulary:{" "}
        <span className="font-medium">implemented</span> (the code exists in the
        pre-release repository and its own tests pass — not that it is released
        or reviewed), <span className="font-medium">load-bearing</span> (a
        product flow already depends on it),{" "}
        <span className="font-medium">designed</span> (the choice is made on
        paper), <span className="font-medium">planned</span> (not yet started),
        and <span className="font-medium">unaudited</span> (no independent review
        has confirmed any of it). Names like FIPS 203 / FIPS 204 identify the
        standardized algorithm implemented; they are not a claim of
        certification, and no NIST validation has been sought or granted.
      </p>
    </main>
  );
}
