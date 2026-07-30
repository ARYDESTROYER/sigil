// totp-vault.mjs — a framework-free, dependency-free ESM module that reads and
// writes the SAME sealed TOTP vault the `sigil totp` CLI uses, so a browser and
// the CLI are cross-clients over ONE vault file (or one op-log vault).
//
// The vault at rest is a normal CLI-compatible SIGILcli container (the same
// self-describing Argon2id + XChaCha20-Poly1305 file that seal_to_container /
// open_container speak). Its DECRYPTED plaintext is a JSON TotpVault. This module
// performs NO cryptography of its own: it hands bytes to the wasm binding
// (open_container / seal_to_container) and computes codes via the wasm TOTP
// primitive (which itself only marshals to sigil-core). The OTP secret never
// leaves this process; the sigild op-log only ever sees the sealed container.
//
// ── THE VAULT JSON SCHEMA IS MIRRORED FROM cli/src/lib.rs — KEEP IT IN SYNC ──
//
//   TotpVault {
//     version: u8,                 // what WROTE this vault; this build writes 1
//     min_reader_version?: u8,     // OMITTED by this build (see below)
//     entries: TotpEntry[],
//     ...unknown                   // ⭐ preserved verbatim
//   }
//   TotpEntry {
//     label:     string,          // unique within the vault
//     issuer?:   string,          // OMITTED entirely when absent (serde skip)
//     secret:    string,          // STANDARD base64 of the RAW key bytes
//     algorithm: string,          // "sha1" | "sha256" | "sha512"  (lowercase)
//     digits:    number,          // typically 6
//     period:    number,          // seconds, typically 30
//     uuid?:     string,          // ⭐ stable RFC 4122 v4 id; OMITTED when absent
//     ...unknown                  // ⭐ preserved verbatim
//   }
//
// A drift from that shape (an extra/renamed field, wrong casing, base32 instead
// of base64 in `secret`) breaks CLI<->browser interop. The cross-client Node
// test (test/totp-interop.mjs) is the guard: it has the CLI write a vault and
// this module read it (and vice versa) through a live opaque sigild.
//
// ── ⭐ FORWARD COMPATIBILITY (Phase 59) — why the two version knobs differ ────
//
// This schema is mirrored across FOUR clients (CLI, webapp, MV3 extension,
// native desktop) plus a printed recovery kit, and vaults sync through an opaque
// op-log where the OLDEST writer wins. The old rules made that a trap:
//
//   * `version !== 1` was refused outright, so ANY addition was a flag day; and
//   * neither side preserved fields it did not know, so an old client that
//     merely opened and re-sealed a vault DELETED a newer client's data.
//
// Both are fixed, additively:
//
//   1. UNKNOWN FIELDS ARE PRESERVED. This module never rebuilds a vault or an
//      entry field-by-field; it spreads (`{...vault}` / `{...entry}`) so anything
//      it does not understand is written back verbatim. ⚠️ A caller that
//      reconstructs `{ version, entries }` by hand throws that away again — use
//      `cloneVault()` below.
//   2. `min_reader_version` states what a reader must UNDERSTAND, separately from
//      `version`, which states what WROTE the vault. A reader refuses iff
//      `min_reader_version > TOTP_VAULT_READER_VERSION`; when the field is absent
//      the vault's own `version` is used, so an un-annotated future vault still
//      fails closed. Mirrors cli/src/lib.rs::check_vault_readable EXACTLY.
//
// Pre-audit / UNAUDITED / DEV. Do NOT store real 2FA secrets in this build.

// The inner TotpVault plaintext version (cli/src/lib.rs::TOTP_VAULT_VERSION) —
// what this build WRITES into `version`.
export const TOTP_VAULT_VERSION = 1;

// The highest `min_reader_version` this build can satisfy
// (cli/src/lib.rs::TOTP_VAULT_READER_VERSION). MUST stay in step with Rust.
export const TOTP_VAULT_READER_VERSION = 1;

// Works in BOTH Node (v20+) and the browser: base64 is feature-detected (Buffer
// in Node, atob/btoa in the browser), matching sync.mjs.

/** Standard-base64 string -> Uint8Array. */
export function base64ToBytes(b64) {
  if (typeof Buffer !== "undefined") {
    return new Uint8Array(Buffer.from(b64, "base64"));
  }
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** Uint8Array -> standard-base64 string. */
export function bytesToBase64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (typeof Buffer !== "undefined") {
    return Buffer.from(u8).toString("base64");
  }
  let s = "";
  for (const b of u8) s += String.fromCharCode(b);
  return btoa(s);
}

// Coerce a password (string or bytes) to the UTF-8 byte array the wasm expects.
function passwordBytes(password) {
  if (password instanceof Uint8Array) return password;
  if (typeof password === "string") return new TextEncoder().encode(password);
  return new Uint8Array(password);
}

/**
 * Decode an RFC 4648 base32 string into raw bytes. Case-insensitive; ASCII
 * whitespace and `=` padding are ignored (so a secret pasted with spaces from a
 * provisioning screen still decodes). Rejects any other non-alphabet character
 * and an all-empty input. Mirrors cli/src/lib.rs::base32_decode.
 *
 * Base32 is the on-the-wire provisioning form (an `otpauth://` secret); the vault
 * stores the DECODED bytes as base64, so use this only when ADDING a secret.
 */
export function base32Decode(input) {
  let acc = 0;
  let nbits = 0;
  const out = [];
  for (const ch of input) {
    if (ch === "=" || /\s/.test(ch)) continue;
    const up = ch.toUpperCase();
    let val;
    if (up >= "A" && up <= "Z") {
      val = up.charCodeAt(0) - 65; // 'A' -> 0
    } else if (up >= "2" && up <= "7") {
      val = up.charCodeAt(0) - 50 + 26; // '2' -> 26
    } else {
      throw new Error(`invalid base32 character ${JSON.stringify(ch)} in secret`);
    }
    acc = (acc << 5) | val;
    nbits += 5;
    if (nbits >= 8) {
      nbits -= 8;
      out.push((acc >> nbits) & 0xff);
      acc &= (1 << nbits) - 1;
    }
  }
  if (out.length === 0) {
    throw new Error("base32 secret decoded to zero bytes");
  }
  return new Uint8Array(out);
}

/**
 * Open a sealed TOTP vault container and return its TotpVault object.
 *
 *   openVault(wasm, password, containerBytes) -> { version, entries: [...] }
 *
 * `wasm` is the imported binding (must expose `open_container`); `password` may
 * be a string or Uint8Array; `containerBytes` is the raw SIGILcli container (as
 * written by the CLI's `sigil totp` or by sealVault below). Throws on a wrong
 * password / tampered container, or if the decrypted JSON is not a valid vault.
 */
export function openVault(wasm, password, containerBytes) {
  const bytes =
    containerBytes instanceof Uint8Array ? containerBytes : new Uint8Array(containerBytes);
  const plaintext = wasm.open_container(passwordBytes(password), bytes);
  let vault;
  try {
    vault = JSON.parse(new TextDecoder().decode(plaintext));
  } catch (e) {
    throw new Error(`decrypted vault is not valid JSON: ${e.message}`);
  }
  if (
    typeof vault !== "object" ||
    vault === null ||
    typeof vault.version !== "number" ||
    !Array.isArray(vault.entries)
  ) {
    throw new Error("decrypted vault is not a { version, entries: [] } object");
  }
  checkVaultReadable(vault);
  return vault;
}

/**
 * ⭐ The forward-compatibility gate. MIRRORS cli/src/lib.rs::check_vault_readable
 * and MUST stay byte-identical in behaviour — a drift means one client refuses a
 * vault the other happily opens, which on a sync path reads as data loss.
 *
 * A vault is readable when the reader version it DEMANDS is one this build can
 * satisfy. The demand is `min_reader_version` when stated, and otherwise the
 * vault's own `version` — so an un-annotated future vault FAILS CLOSED exactly as
 * the old blanket equality check did, while an explicitly-additive one
 * (`version: 2, min_reader_version: 1`) opens and round-trips losslessly.
 *
 * Throws with the required version named, never a generic "unsupported".
 */
export function checkVaultReadable(vault) {
  const required = vault.min_reader_version ?? vault.version;
  if (typeof required !== "number" || !Number.isInteger(required)) {
    throw new Error("vault version fields must be integers");
  }
  if (required > TOTP_VAULT_READER_VERSION) {
    throw new Error(
      `this vault needs a reader that understands schema version ${required}, and ` +
        `this build understands ${TOTP_VAULT_READER_VERSION} (the vault was written ` +
        `by version ${vault.version}). Upgrade the client that reads it — opening it ` +
        `here could silently discard data it does not understand`,
    );
  }
}

/**
 * ⭐ Clone a vault for editing WITHOUT dropping fields this build does not know.
 *
 * Use this instead of `{ version: v.version, entries: [...v.entries] }`. That
 * shape is the JS twin of rebuilding a serde struct field-by-field: it silently
 * deletes `min_reader_version` and every unknown top-level field, and a client
 * doing it on a shared vault destroys a newer client's data on its next push.
 * The entries array is copied shallowly — entry OBJECTS are shared, which is
 * what keeps their unknown fields intact.
 */
export function cloneVault(vault) {
  return { ...vault, entries: [...vault.entries] };
}

/**
 * Format 16 bytes of CALLER-supplied entropy as a lowercase RFC 4122 v4 UUID.
 * MIRRORS cli/src/lib.rs::format_entry_uuid (same version/variant bit fixing, so
 * both sides produce the same string from the same bytes).
 */
export function formatEntryUuid(random16) {
  const b = Uint8Array.from(random16);
  if (b.length !== 16) throw new Error(`entry uuid needs exactly 16 bytes, got ${b.length}`);
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // RFC 4122 variant
  const h = (from, to) =>
    Array.from(b.slice(from, to), (x) => x.toString(16).padStart(2, "0")).join("");
  return `${h(0, 4)}-${h(4, 6)}-${h(6, 8)}-${h(8, 10)}-${h(10, 16)}`;
}

/**
 * Draw a fresh entry uuid from the platform CSPRNG
 * (`crypto.getRandomValues` — present in Node 20+ and every browser). The
 * entropy is supplied HERE, in JS, never by the wasm (ADR 0007).
 */
export function randomEntryUuid() {
  return formatEntryUuid(globalThis.crypto.getRandomValues(new Uint8Array(16)));
}

/**
 * Compute the current TOTP code for one entry as a zero-padded string.
 *
 *   codeForEntry(wasm, entry, unixTimeSeconds) -> "123456"
 *
 * `unixTimeSeconds` is the caller's clock (e.g. `Math.floor(Date.now()/1000)`) —
 * sigil-core reads no clock, so the time is supplied here. Uses t0 = 0 (the
 * near-universal TOTP epoch offset). Throws on a bad entry (unknown algorithm,
 * out-of-range digits, non-integer time).
 */
export function codeForEntry(wasm, entry, unixTimeSeconds) {
  const secret = base64ToBytes(entry.secret);
  const code = wasm.totp(
    secret,
    unixTimeSeconds,
    entry.period,
    0, // t0
    entry.digits,
    entry.algorithm,
  );
  return wasm.format_code(code, entry.digits);
}

/**
 * Append a TotpEntry to `vault` (mutating and returning it), matching the CLI
 * schema EXACTLY: the raw `secretBytes` are stored as STANDARD base64 in
 * `.secret`, `algorithm` is lowercased, and `issuer` is OMITTED when absent (never
 * written as null) so the JSON is byte-identical to what serde produces.
 *
 *   addEntry(vault, { label, issuer?, secretBytes, algorithm, digits, period, uuid? })
 *
 * Rejects a duplicate label (the CLI treats labels as unique) and out-of-range
 * digits/period up front. A stable `uuid` is drawn from `crypto.getRandomValues`
 * unless the caller supplies one (pass `null` to omit the field entirely, which
 * is what an entry written before the field existed looks like).
 */
export function addEntry(vault, { label, issuer, secretBytes, algorithm, digits, period, uuid }) {
  if (typeof label !== "string" || label.length === 0) {
    throw new Error("label must be a non-empty string");
  }
  if (vault.entries.some((e) => e.label === label)) {
    throw new Error(`an entry labeled ${JSON.stringify(label)} already exists`);
  }
  const algo = String(algorithm ?? "sha1").toLowerCase();
  if (algo !== "sha1" && algo !== "sha256" && algo !== "sha512") {
    throw new Error(`unknown algorithm ${JSON.stringify(algorithm)}: expected sha1/sha256/sha512`);
  }
  if (!Number.isInteger(digits) || digits < 6 || digits > 10) {
    throw new Error(`digits ${digits} out of range 6..=10`);
  }
  if (!Number.isInteger(period) || period <= 0) {
    throw new Error(`period ${period} must be a positive integer`);
  }

  const entry = {
    label,
    // issuer key is added ONLY when present, mirroring serde's skip_serializing_if.
    secret: bytesToBase64(secretBytes),
    algorithm: algo,
    digits,
    period,
  };
  if (issuer !== undefined && issuer !== null && issuer !== "") {
    entry.issuer = issuer;
  }
  // `uuid: null` means "deliberately omit" (an entry as written before the field
  // existed); undefined means "draw one". Mirrors the CLI, where
  // `new_totp_entry` draws and `new_totp_entry_with_uuid(..., None)` omits.
  if (uuid !== null) {
    entry.uuid = uuid ?? randomEntryUuid();
  }
  vault.entries.push(entry);
  return vault;
}

/**
 * Serialize `vault` to JSON and seal it into a CLI-compatible SIGILcli container
 * the `sigil totp` CLI can open back.
 *
 *   sealVault(wasm, password, vault, salt, nonce, params) -> Uint8Array
 *
 * `salt` and `nonce` are caller-supplied entropy (generate with
 * `crypto.getRandomValues`; salt = wasm.recommended_salt_len() bytes, nonce =
 * wasm.nonce_len() bytes). `params` is `{ m_cost, t_cost, p_cost }`. The vault
 * plaintext is UTF-8 JSON with no trailing metadata, matching the CLI's
 * serde_json output shape.
 */
export function sealVault(wasm, password, vault, salt, nonce, params) {
  const json = new TextEncoder().encode(JSON.stringify(vault));
  return wasm.seal_to_container(
    passwordBytes(password),
    salt,
    nonce,
    params.m_cost,
    params.t_cost,
    params.p_cost,
    json,
  );
}

/** Convenience: a fresh empty vault at the current schema version. */
export function newVault() {
  return { version: TOTP_VAULT_VERSION, entries: [] };
}

// ── ⭐ THE NO-DOWNGRADE RATCHET FOR JS RE-SEALS ──────────────────────────────
//
// ⛔ THE BUG THESE CLOSE. A `SIGILcli` container is self-describing: it carries
// the Argon2id work factors it was sealed with. The Rust clients have honoured a
// ratchet since Phase 58 — `sigil_cli::reseal_container` re-seals at
// `no_downgrade(container's params, requested)`, so strength only ever goes up.
// The JS clients had NO equivalent. Every browser re-seal used a hardcoded
// `{ m_cost: 19456, t_cost: 2, p_cost: 1 }`, so a vault the CLI wrote at
// 65536/4/2 came back from ONE browser edit at 19456/2/1 — a 3.4x cut in memory
// cost and half the passes, silently, with no user action and no error. Because
// a re-seal is where new parameters are CHOSEN, that weakening was permanent.
//
// ⭐ The rule is not reimplemented in JS. `wasm.reseal_params` calls
// `sigil-core`'s `Argon2Params::no_downgrade` — literally the function
// `sigil_cli::no_downgrade` delegates to — so the browser and the CLI cannot
// drift. A drifting mirror would be invisible: it produces a container that
// still opens everywhere, just weaker.

/**
 * Read the Argon2id work factors a `SIGILcli` container declares, WITHOUT
 * opening it (no password, no KDF, no allocation).
 *
 *   containerParams(wasm, containerBytes) -> { m_cost, t_cost, p_cost }
 *
 * Throws on anything that is not a valid `SIGILcli` header, including one whose
 * declared factors exceed sigil-core's ceilings.
 */
export function containerParams(wasm, containerBytes) {
  const [m_cost, t_cost, p_cost] = wasm.container_params(containerBytes);
  return { m_cost, t_cost, p_cost };
}

/**
 * ⭐ **Call this at EVERY re-seal.** Returns the work factors to actually write:
 * the componentwise maximum of what `existingContainer` declares and what this
 * client would write today, with Argon2's `m_cost >= 8 * p_cost` floor honoured.
 *
 *   ratchetParams(wasm, existingContainer | null, requested) -> { m_cost, t_cost, p_cost }
 *
 * `existingContainer` is the container about to be REPLACED. `null`/`undefined`/
 * empty means "there is nothing to ratchet from" (a first seal), and `requested`
 * is returned unchanged.
 *
 * ⚠️ It is deliberately FORGIVING of a container it cannot parse: a stored value
 * that is corrupt, truncated or from some future format must not block the user
 * from saving. In that case it falls back to `requested`, which is this build's
 * own defaults — never something weaker than the client would have written
 * anyway. The dangerous direction (a strong header quietly becoming a weak one)
 * is the one that cannot happen.
 */
export function ratchetParams(wasm, existingContainer, requested) {
  if (!existingContainer || existingContainer.length === 0) return requested;
  try {
    const [m_cost, t_cost, p_cost] = wasm.reseal_params(
      existingContainer instanceof Uint8Array ? existingContainer : new Uint8Array(existingContainer),
      requested.m_cost,
      requested.t_cost,
      requested.p_cost,
    );
    return { m_cost, t_cost, p_cost };
  } catch {
    return requested;
  }
}
