// sealed-store-helper.mjs — the POSITIVE form of ADR 0036's browser-persistence
// invariant, shared by the webapp and extension Playwright suites.
//
// ⭐ THE INVARIANT: a browser client persists ONLY sealed `SIGILcli` containers,
// and persists them in exactly ONE place. The Ed25519 device seed, the hybrid
// secret identity, every accepted vault key and the hybrid-key pin store all live
// inside those containers under the vault password; nothing goes to disk in the
// clear.
//
// ⚠️ WHY THIS FILE EXISTS. Nothing enforced that invariant. The leak specs swept
// every store into one haystack and then asserted only `not.toContain(<the
// recovery code>)` plus one password — a NEEDLE test. The single structural pin
// was `expect(localKeys).toEqual([...])`, i.e. localStorage KEY NAMES only:
// nothing said the stored VALUES were containers, and nothing at all constrained
// sessionStorage, chrome.storage.session/sync/managed, IndexedDB or Cache
// Storage. A verifier added one plaintext
// `sessionStorage.setItem("sigil.webapp.cache", JSON.stringify(device))` to the
// webapp's persistDevice and the same to the extension's, dumping the raw 32-byte
// device seed, the hybrid secret and every vault key IN THE CLEAR — and both
// suites stayed fully green (19/19 and 12/12).
//
// So: assert what MUST be there (a container, magic bytes checked), and assert
// that every other surface is EMPTY. Emptiness catches a leak nobody thought to
// write a needle for.
//
// This file is a HELPER, not a suite: `scripts/gate.sh` and the CI-drift check
// both skip `*-helper.mjs`, so it is never executed as a test.

/** The sealed-container magic. Mirrors cli/src/lib.rs::MAGIC and sigil-wasm's CLI_MAGIC. */
export const SIGILCLI_MAGIC = "SIGILcli";

/** The hybrid (public-key) container magic, accepted for completeness. */
export const SIGILHYB_MAGIC = "SIGILhyb";

/**
 * Describe one persisted value: is it a base64-encoded sealed container?
 * Returns `{ ok, magic, reason }` — never throws, so a caller can report the
 * offending key and a readable prefix of what was actually stored.
 */
export function describePersistedValue(value) {
  if (typeof value !== "string") {
    return { ok: false, magic: null, reason: `not a string (${typeof value})` };
  }
  if (!/^[A-Za-z0-9+/]+=*$/.test(value) || value.length < 16) {
    return { ok: false, magic: null, reason: "not standard base64" };
  }
  let bytes;
  try {
    bytes = Buffer.from(value, "base64");
  } catch {
    return { ok: false, magic: null, reason: "base64 decode failed" };
  }
  if (bytes.length < 8) {
    return { ok: false, magic: null, reason: `only ${bytes.length} bytes` };
  }
  const magic = bytes.subarray(0, 8).toString("latin1");
  if (magic !== SIGILCLI_MAGIC && magic !== SIGILHYB_MAGIC) {
    return { ok: false, magic, reason: `magic is ${JSON.stringify(magic)}, not a sealed container` };
  }
  return { ok: true, magic, reason: "" };
}

/** A short, non-secret preview of a value, for a failure message. */
export function preview(value) {
  const s = typeof value === "string" ? value : JSON.stringify(value);
  return s.length > 80 ? `${s.slice(0, 80)}…` : s;
}

/**
 * Check a `{key: value}` map of persisted entries against the invariant.
 *
 * Returns an array of human-readable problems (empty === the invariant holds):
 *   * the key set differs from `expectedKeys`;
 *   * any value is not a base64 sealed container.
 */
export function sealedOnlyProblems(entries, expectedKeys) {
  const problems = [];
  const keys = Object.keys(entries).sort();
  const want = [...expectedKeys].sort();
  if (JSON.stringify(keys) !== JSON.stringify(want)) {
    problems.push(
      `persisted key set is ${JSON.stringify(keys)}, want exactly ${JSON.stringify(want)} — ` +
        `a browser client persists ONLY its sealed containers (ADR 0036)`,
    );
  }
  for (const [key, value] of Object.entries(entries)) {
    const d = describePersistedValue(value);
    if (!d.ok) {
      problems.push(
        `persisted value at ${JSON.stringify(key)} is NOT a sealed SIGILcli container ` +
          `(${d.reason}); stored: ${preview(value)}`,
      );
    }
  }
  return problems;
}

/**
 * Check that a storage surface that must hold NOTHING holds nothing.
 *
 * `contents` is whatever the page dumped for it; anything non-empty is a
 * problem. This is the assertion that catches a leak nobody wrote a needle for.
 */
export function emptyProblems(surfaceName, contents) {
  const problems = [];
  if (contents === null || contents === undefined || contents === "unavailable") return problems;
  if (Array.isArray(contents)) {
    if (contents.length > 0) {
      problems.push(`${surfaceName} must be EMPTY, holds ${JSON.stringify(contents)}`);
    }
    return problems;
  }
  if (typeof contents === "string") {
    if (contents.trim() !== "") {
      problems.push(`${surfaceName} must be EMPTY, holds ${preview(contents)}`);
    }
    return problems;
  }
  const keys = Object.keys(contents);
  if (keys.length > 0) {
    problems.push(`${surfaceName} must be EMPTY, holds keys ${JSON.stringify(keys.sort())}`);
  }
  return problems;
}
