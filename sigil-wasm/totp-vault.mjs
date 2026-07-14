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
//   TotpVault { version: u8, entries: TotpEntry[] }              // version == 1
//   TotpEntry {
//     label:     string,          // unique within the vault
//     issuer?:   string,          // OMITTED entirely when absent (serde skip)
//     secret:    string,          // STANDARD base64 of the RAW key bytes
//     algorithm: string,          // "sha1" | "sha256" | "sha512"  (lowercase)
//     digits:    number,          // typically 6
//     period:    number,          // seconds, typically 30
//   }
//
// A drift from that shape (an extra/renamed field, wrong casing, base32 instead
// of base64 in `secret`) breaks CLI<->browser interop. The cross-client Node
// test (test/totp-interop.mjs) is the guard: it has the CLI write a vault and
// this module read it (and vice versa) through a live opaque sigild.
//
// Pre-audit / UNAUDITED / DEV. Do NOT store real 2FA secrets in this build.

// The inner TotpVault plaintext version (cli/src/lib.rs::TOTP_VAULT_VERSION).
export const TOTP_VAULT_VERSION = 1;

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
  if (vault.version !== TOTP_VAULT_VERSION) {
    throw new Error(
      `unsupported vault version ${vault.version}: expected ${TOTP_VAULT_VERSION}`,
    );
  }
  return vault;
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
 *   addEntry(vault, { label, issuer?, secretBytes, algorithm, digits, period })
 *
 * Rejects a duplicate label (the CLI treats labels as unique) and out-of-range
 * digits/period up front.
 */
export function addEntry(vault, { label, issuer, secretBytes, algorithm, digits, period }) {
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
