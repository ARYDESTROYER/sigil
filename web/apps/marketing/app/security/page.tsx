import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Cryptographic posture — Sigil (working name)",
  robots: { index: false, follow: false },
};

// PRE-LAUNCH / PRE-AUDIT design note. This page documents the *intended*
// cryptographic design, not a shipped or verified implementation. Every status
// is qualified (designed / in development / pre-audit / unaudited / planned) so
// nothing here reads as a present-tense security guarantee. See
// MARKETING-CLAIMS.md: no "audited", no "SOC 2", no "post-quantum secure", no
// unqualified "end-to-end encrypted".

type Posture = {
  layer: string;
  primitive: string;
  status: string;
};

// Intended design only. Order mirrors the layered design: secret derivation,
// data encryption, key exchange (classical + PQ), signatures (classical + PQ),
// then transport.
const rows: Posture[] = [
  { layer: "KDF", primitive: "Argon2id", status: "Designed; in development; unaudited" },
  {
    layer: "AEAD",
    primitive: "XChaCha20-Poly1305",
    status: "Designed; in development; unaudited",
  },
  {
    layer: "Classical key exchange",
    primitive: "X25519",
    status: "Designed; in development; unaudited",
  },
  {
    layer: "Post-quantum KEM",
    primitive: "ML-KEM-768 (FIPS 203)",
    status: "Designed; in development; unaudited",
  },
  {
    layer: "Hybrid KEM combine",
    primitive: "X-Wing (X25519 + ML-KEM-768, pre-RFC IETF draft)",
    status: "Designed; in development; unaudited",
  },
  {
    layer: "Classical signature",
    primitive: "Ed25519",
    status: "Designed; in development; unaudited",
  },
  {
    layer: "Post-quantum signature",
    primitive: "ML-DSA-65 (FIPS 204)",
    status: "Designed; planned; pre-audit",
  },
  {
    layer: "Transport",
    primitive: "TLS 1.3 (X25519MLKEM768)",
    status: "Designed; planned; unaudited",
  },
  {
    layer: "Current suite byte",
    primitive: "0x12",
    status: "Designed; provisional; pre-audit",
  },
];

export default function Security() {
  return (
    <main className="mx-auto max-w-2xl space-y-6 px-6 py-16 text-sm leading-relaxed text-neutral-700 dark:text-neutral-300">
      <h1 className="text-2xl font-bold text-neutral-900 dark:text-neutral-100">
        Cryptographic posture
      </h1>
      <p className="text-neutral-500">
        Pre-launch design note, 2 June 2026. This describes the cryptographic
        design we are <em>building toward</em>.
      </p>

      <p>
        Nothing below is implemented, shipped, or independently audited yet.
        These are design intentions for a post-quantum-ready authenticator
        (unaudited). Each primitive is listed with its current status; an
        independent security audit is planned. Treat this as a roadmap, not a
        guarantee.
      </p>

      <section className="space-y-3">
        <h2 className="font-semibold text-neutral-900 dark:text-neutral-100">
          Intended primitives and their status
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left">
            <thead>
              <tr className="border-b border-neutral-300 text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-700">
                <th className="py-2 pr-4 font-medium">Layer</th>
                <th className="py-2 pr-4 font-medium">Intended primitive</th>
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
                  <td className="py-2 text-neutral-500">{row.status}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      <p className="text-xs text-neutral-400">
        Status vocabulary: <span className="font-medium">designed</span> (the
        choice is made on paper),{" "}
        <span className="font-medium">in development</span> (code is being
        written), <span className="font-medium">planned</span> (not yet
        started), <span className="font-medium">pre-audit</span> and{" "}
        <span className="font-medium">unaudited</span> (no independent review has
        confirmed any of it). Names like FIPS 203 / FIPS 204 identify the
        standardized algorithm we intend to use; they are not a claim of
        certification.
      </p>
    </main>
  );
}
