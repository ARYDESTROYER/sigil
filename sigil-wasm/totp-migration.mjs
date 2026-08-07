// totp-migration.mjs — a framework-free, dependency-free ESM module that gives
// the BROWSER/wasm client the SAME TOTP import/export the `sigil` CLI has:
//
//   * Google Authenticator BULK export/import — the
//     `otpauth-migration://offline?data=<BASE64>` URI, whose payload is a proto3
//     protobuf message wrapping many OTP accounts; and
//   * SINGLE-account provisioning — the standard `otpauth://totp/…` URI.
//
// ── THIS IS A LINE-FOR-LINE MIRROR OF cli/src/migration.rs (+ the otpauth://
//    parse/build in cli/src/lib.rs) — KEEP THE TWO IN SYNC. ──
//
// There is NO protobuf library here: this is a hand-rolled codec for the two
// proto3 wire types the schema uses (varint = wire type 0, length-delimited =
// wire type 2), exactly like the Rust side hand-rolls it. The
// test/migration-interop.mjs Node test is the guard — it proves this JS codec
// and the Rust CLI codec are wire-compatible BOTH ways.
//
// The proto3 schema (identical to migration.rs):
//
//   message MigrationPayload {
//     repeated OtpParameters otp_parameters = 1;
//     int32 version = 2; int32 batch_size = 3;
//     int32 batch_index = 4; int32 batch_id = 5;
//   }
//   message OtpParameters {
//     bytes secret = 1; string name = 2; string issuer = 3;
//     Algorithm algorithm = 4; DigitCount digits = 5;
//     OtpType type = 6; int64 counter = 7;
//   }
//   enum Algorithm  { UNSPECIFIED=0; SHA1=1; SHA256=2; SHA512=3; MD5=4; }
//   enum DigitCount { UNSPECIFIED=0; SIX=1; EIGHT=2; }
//   enum OtpType    { UNSPECIFIED=0; HOTP=1; TOTP=2; }
//
// Every function that yields/takes an account uses the vault TotpEntry shape
// (the SAME shape totp-vault.mjs stores — KEEP IN SYNC):
//
//   TotpEntry {
//     label:     string,        // account label (migration: the raw `name`)
//     issuer?:   string,        // OMITTED when absent (never null/empty)
//     secret:    string,        // STANDARD base64 of the RAW key bytes
//     algorithm: "sha1"|"sha256"|"sha512",
//     digits:    number,        // 6 or 8
//     period:    number,        // seconds (migration carries none → 30)
//   }
//
// STATUS: pre-audit, DEV-ONLY. An otpauth:// / otpauth-migration:// URI carries
// OTP SECRETS IN THE CLEAR (it is the plaintext provisioning form, not an
// encrypted container). The demo export path warns loudly. Do NOT handle real
// 2FA secrets in this build.

import { base64ToBytes, bytesToBase64, base32Decode, randomEntryUuid } from "./totp-vault.mjs";

// ── Constants mirrored from cli/src/migration.rs ─────────────────────────────

/** Proto3 wire type for base-128 varints (int32/int64/enum/bool). */
const WIRE_VARINT = 0;
/** Proto3 wire type for length-delimited fields (bytes/string/embedded msg). */
const WIRE_LEN = 2;

const ALG_SHA1 = 1;
const ALG_SHA256 = 2;
const ALG_SHA512 = 3;
const ALG_MD5 = 4;

const DIGITS_SIX = 1;
const DIGITS_EIGHT = 2;

const OTP_HOTP = 1;
const OTP_TOTP = 2;

/** The version this build writes into an exported MigrationPayload. */
const MIGRATION_PAYLOAD_VERSION = 1;

/** The migration format carries no period; Google Authenticator TOTP is 30 s. */
const TOTP_DEFAULT_PERIOD = 30;

/** The `otpauth-migration://` scheme prefix (matched case-insensitively). */
const MIGRATION_SCHEME = "otpauth-migration://";

// ── base32 (RFC 4648, no padding) — the INVERSE of totp-vault.mjs base32Decode ─

/**
 * Encode raw bytes as an RFC 4648 base32 string with NO `=` padding. Mirrors
 * cli/src/lib.rs::base32_encode. Empty input yields an empty string.
 */
export function base32Encode(bytes) {
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let out = "";
  let acc = 0;
  let nbits = 0;
  for (const b of u8) {
    // Keep acc within 32-bit-safe range: at most 8 leftover bits before this
    // push, +8 = 16 bits, well under 2^31, so plain << is safe.
    acc = (acc << 8) | b;
    nbits += 8;
    while (nbits >= 5) {
      nbits -= 5;
      out += ALPHABET[(acc >> nbits) & 0x1f];
    }
  }
  if (nbits > 0) {
    // Left-align the remaining low bits into a final 5-bit group.
    out += ALPHABET[(acc << (5 - nbits)) & 0x1f];
  }
  return out;
}

// ── Percent-decode (otpauth:// label/issuer fields) — mirrors percent_decode ──

function hexNibble(c) {
  if (c >= 0x30 && c <= 0x39) return c - 0x30; // 0-9
  if (c >= 0x61 && c <= 0x66) return c - 0x61 + 10; // a-f
  if (c >= 0x41 && c <= 0x46) return c - 0x41 + 10; // A-F
  return null;
}

/** Minimal `%XX` percent-decoder; short/invalid escapes pass through. UTF-8. */
function percentDecode(s) {
  const bytes = new TextEncoder().encode(s);
  const out = [];
  let i = 0;
  while (i < bytes.length) {
    if (bytes[i] === 0x25 /* % */ && i + 2 < bytes.length) {
      const h = hexNibble(bytes[i + 1]);
      const l = hexNibble(bytes[i + 2]);
      if (h !== null && l !== null) {
        out.push(h * 16 + l);
        i += 3;
        continue;
      }
    }
    out.push(bytes[i]);
    i += 1;
  }
  return new TextDecoder().decode(new Uint8Array(out));
}

/**
 * Percent-encode for an otpauth:// URI, escaping everything outside the RFC 3986
 * unreserved set (A-Z a-z 0-9 - . _ ~). The inverse of percentDecode; mirrors
 * cli/src/lib.rs::percent_encode.
 */
function percentEncode(s) {
  const bytes = new TextEncoder().encode(s);
  let out = "";
  for (const b of bytes) {
    if (
      (b >= 0x41 && b <= 0x5a) || // A-Z
      (b >= 0x61 && b <= 0x7a) || // a-z
      (b >= 0x30 && b <= 0x39) || // 0-9
      b === 0x2d || // -
      b === 0x2e || // .
      b === 0x5f || // _
      b === 0x7e // ~
    ) {
      out += String.fromCharCode(b);
    } else {
      out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
    }
  }
  return out;
}

// ── Tolerant base64 (standard OR url-safe, with/without padding) ─────────────

/**
 * Base64-decode a migration `data` value, tolerating standard OR url-safe
 * alphabets, with or without padding, and any embedded whitespace. Mirrors
 * cli/src/migration.rs::decode_migration_data (percent-decode → normalize -_ →
 * +/ → strip whitespace/padding → decode).
 */
function decodeMigrationData(data) {
  const decoded = percentDecode(data);
  let normalized = "";
  for (const ch of decoded) {
    if (/\s/.test(ch)) continue;
    if (ch === "-") normalized += "+";
    else if (ch === "_") normalized += "/";
    else normalized += ch;
  }
  const trimmed = normalized.replace(/=+$/, "");
  // base64ToBytes (totp-vault.mjs) accepts unpadded standard base64 in both Node
  // (Buffer) and the browser (atob) — feed it the normalized/unpadded string.
  return base64ToBytes(trimmed);
}

// ── Varint / length-delimited readers (bounds-checked; never overrun) ─────────

// A tiny cursor object { buf, pos } is threaded through the readers so a
// bounds-checked position advances exactly like the Rust `&mut pos`.

/** Read one base-128 varint (LEB128); caps at 10 bytes; throws on overrun. */
function readVarint(cur) {
  let result = 0n;
  let shift = 0n;
  for (let i = 0; i < 10; i++) {
    if (cur.pos >= cur.buf.length) {
      throw new Error("migration payload: varint runs past end of buffer");
    }
    const byte = cur.buf[cur.pos];
    cur.pos += 1;
    result |= BigInt(byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return result;
    shift += 7n;
  }
  throw new Error("migration payload: varint longer than 10 bytes");
}

/** Read a length-delimited body (varint length + that many bytes) as a slice. */
function readLenDelimited(cur) {
  const len = Number(readVarint(cur));
  const end = cur.pos + len;
  if (len < 0 || end > cur.buf.length) {
    throw new Error("migration payload: length-delimited field runs past end");
  }
  const slice = cur.buf.subarray(cur.pos, end);
  cur.pos = end;
  return slice;
}

/** Skip an unknown field of wire type `wire` (varint/len/fixed64/fixed32). */
function skipField(cur, wire) {
  switch (wire) {
    case WIRE_VARINT:
      readVarint(cur);
      break;
    case WIRE_LEN:
      readLenDelimited(cur);
      break;
    case 1: // 64-bit fixed
      if (cur.pos + 8 > cur.buf.length) {
        throw new Error("migration payload: 64-bit field runs past end");
      }
      cur.pos += 8;
      break;
    case 5: // 32-bit fixed
      if (cur.pos + 4 > cur.buf.length) {
        throw new Error("migration payload: 32-bit field runs past end");
      }
      cur.pos += 4;
      break;
    default:
      throw new Error(`migration payload: unknown wire type ${wire}`);
  }
}

// ── Varint / length-delimited writers ────────────────────────────────────────

/** Append `value` (a Number or BigInt ≥ 0) to `out` as a base-128 varint. */
function writeVarint(out, value) {
  let v = BigInt(value);
  for (;;) {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v !== 0n) byte |= 0x80;
    out.push(byte);
    if (v === 0n) break;
  }
}

/** Append a field tag (field_number << 3 | wire_type). */
function writeTag(out, field, wire) {
  writeVarint(out, (BigInt(field) << 3n) | BigInt(wire));
}

/** Append a varint (wire type 0) field. */
function writeVarintField(out, field, value) {
  writeTag(out, field, WIRE_VARINT);
  writeVarint(out, value);
}

/** Append a length-delimited (wire type 2) field. */
function writeLenField(out, field, data) {
  writeTag(out, field, WIRE_LEN);
  writeVarint(out, data.length);
  for (const b of data) out.push(b);
}

// ── Message codec (raw MigrationOtp records, mirroring migration.rs) ──────────

// A decoded OtpParameters, holding the RAW protobuf values (enum ints kept as
// wire integers). Semantic mapping to the vault TotpEntry happens separately in
// migrationOtpToEntry, so this codec stays schema-agnostic.
function emptyOtp() {
  return {
    secret: new Uint8Array(0),
    name: "",
    issuer: "",
    algorithm: 0,
    digits: 0,
    otpType: 0,
    counter: 0n,
  };
}

/** Decode one OtpParameters sub-message from a byte slice. */
function decodeOtpParameters(buf) {
  const otp = emptyOtp();
  const cur = { buf, pos: 0 };
  while (cur.pos < buf.length) {
    const tag = Number(readVarint(cur));
    const field = tag >> 3;
    const wire = tag & 0x07;
    if (field === 1 && wire === WIRE_LEN) {
      otp.secret = new Uint8Array(readLenDelimited(cur));
    } else if (field === 2 && wire === WIRE_LEN) {
      otp.name = new TextDecoder().decode(readLenDelimited(cur));
    } else if (field === 3 && wire === WIRE_LEN) {
      otp.issuer = new TextDecoder().decode(readLenDelimited(cur));
    } else if (field === 4 && wire === WIRE_VARINT) {
      otp.algorithm = Number(readVarint(cur));
    } else if (field === 5 && wire === WIRE_VARINT) {
      otp.digits = Number(readVarint(cur));
    } else if (field === 6 && wire === WIRE_VARINT) {
      otp.otpType = Number(readVarint(cur));
    } else if (field === 7 && wire === WIRE_VARINT) {
      otp.counter = readVarint(cur);
    } else {
      skipField(cur, wire);
    }
  }
  return otp;
}

/**
 * Decode a MigrationPayload into its raw OtpParameters records AND its batch
 * framing. MIRRORS cli/src/migration.rs::decode_migration_payload.
 *
 * ⛔ `batch_size` / `batch_index` / `batch_id` used to be consumed and DISCARDED
 * on both sides. Google Authenticator splits a large export across several QR
 * codes, each a complete payload carrying a SLICE of the accounts, so discarding
 * the framing meant scanning the first QR of a three-QR export imported a third
 * of the accounts and reported success. See `migrationBatchNote`.
 */
function decodeMigrationPayload(buf) {
  const out = { otps: [], version: 0, batchSize: 0, batchIndex: 0, batchId: 0 };
  const cur = { buf, pos: 0 };
  while (cur.pos < buf.length) {
    const tag = Number(readVarint(cur));
    const field = tag >> 3;
    const wire = tag & 0x07;
    if (field === 1 && wire === WIRE_LEN) {
      // ⭐ THE COUNT CEILING, CHECKED BEFORE THE PUSH (Phase 63). MIRRORS the
      // same call in `cli/src/migration.rs`. Nothing in the wire format bounds
      // how many accounts a payload declares, so this loop was an unbounded
      // allocation driven entirely by attacker input. Refusing here means we
      // never build the list we would then throw away.
      validateProvisioningCount(out.otps.length + 1);
      out.otps.push(decodeOtpParameters(readLenDelimited(cur)));
    } else if (field === 2 && wire === WIRE_VARINT) {
      out.version = Number(readVarint(cur));
    } else if (field === 3 && wire === WIRE_VARINT) {
      out.batchSize = Number(readVarint(cur));
    } else if (field === 4 && wire === WIRE_VARINT) {
      out.batchIndex = Number(readVarint(cur));
    } else if (field === 5 && wire === WIRE_VARINT) {
      out.batchId = Number(readVarint(cur));
    } else {
      skipField(cur, wire);
    }
  }
  return out;
}

/**
 * ⭐ Whether a decoded payload is the WHOLE export.
 * MIRRORS cli/src/migration.rs::MigrationBatch::is_complete.
 */
export function migrationBatchIsComplete(batch) {
  return (batch.batchSize ?? 0) <= 1;
}

/**
 * ⭐ A human-readable "batch i of N" note, or `null` for a single-QR export.
 * MIRRORS cli/src/migration.rs::MigrationBatch::batch_note — including the
 * one-based rendering of the zero-based wire `batch_index`, because "batch 0 of
 * 3" reads like nothing was imported.
 *
 * A caller MUST surface this. An import that reports only a count is telling a
 * user with 30 accounts that a transfer succeeded when two thirds of it did not.
 */
export function migrationBatchNote(batch) {
  if (migrationBatchIsComplete(batch)) return null;
  const size = batch.batchSize;
  const index = batch.batchIndex ?? 0;
  const count = (batch.entries ?? batch.otps ?? []).length;
  if (migrationBatchIsFinal(batch)) {
    return (
      `this was batch ${index + 1} of ${size} — the LAST QR code of a MULTI-QR ` +
      `Google Authenticator export (batch id ${batch.batchId ?? 0}), carrying ` +
      `${count} of the accounts. Nothing further needs scanning from this export. ` +
      `Check that the earlier ${Math.max(size - 1, 0)} QR code(s) were imported too ` +
      `before deleting anything from the old app`
    );
  }
  const remaining = Math.max(size - index - 1, 0);
  return (
    `this is batch ${index + 1} of ${size} from a MULTI-QR Google Authenticator ` +
    `export (batch id ${batch.batchId ?? 0}): it carries ${count} of the accounts, ` +
    `and ${remaining} more QR code(s) must be imported before the transfer is ` +
    `complete. This import is PARTIAL`
  );
}

/**
 * ⭐ Whether this payload is the **LAST** QR of a multi-QR export.
 * MIRRORS cli/src/migration.rs::MigrationBatch::is_final_batch.
 *
 * ⛔ Distinct from `migrationBatchIsComplete`, and the distinction is the whole
 * point: batch 2 of 2 is not the whole export, but nothing further needs
 * scanning. Telling a user who has just finished that "0 more QR code(s) must be
 * imported — this import is PARTIAL" is a warning that cries wolf, and a warning
 * that cries wolf is one the next user ignores when it is real.
 *
 * A caller uses this to pick its FRAMING ("incomplete!" vs "that was the last
 * one"); the note text itself already differs.
 */
export function migrationBatchIsFinal(batch) {
  if (migrationBatchIsComplete(batch)) return false;
  return (batch.batchIndex ?? 0) + 1 >= batch.batchSize;
}

/** Encode one raw OtpParameters record; proto3 omits default (zero/empty). */
function encodeOtpParameters(otp) {
  const out = [];
  if (otp.secret.length > 0) writeLenField(out, 1, otp.secret);
  if (otp.name.length > 0) writeLenField(out, 2, new TextEncoder().encode(otp.name));
  if (otp.issuer.length > 0) writeLenField(out, 3, new TextEncoder().encode(otp.issuer));
  if (otp.algorithm !== 0) writeVarintField(out, 4, otp.algorithm);
  if (otp.digits !== 0) writeVarintField(out, 5, otp.digits);
  if (otp.otpType !== 0) writeVarintField(out, 6, otp.otpType);
  if (otp.counter !== 0n) writeVarintField(out, 7, otp.counter);
  return out;
}

/** Encode raw OtpParameters records into a full MigrationPayload blob (bytes). */
function encodeMigrationPayload(params) {
  const out = [];
  for (const otp of params) {
    writeLenField(out, 1, encodeOtpParameters(otp));
  }
  writeVarintField(out, 2, MIGRATION_PAYLOAD_VERSION);
  // A single self-contained batch (batch_size = 1); batch_index/batch_id stay 0.
  writeVarintField(out, 3, 1);
  return new Uint8Array(out);
}

// ── Conversion to/from the vault TotpEntry shape ─────────────────────────────

/**
 * Map a raw decoded OtpParameters to a vault TotpEntry, applying this build's
 * constraints (mirrors migration_otp_to_entry):
 *   - Algorithm SHA1/256/512 → sha1/sha256/sha512; MD5 or unspecified rejected.
 *   - DigitCount SIX→6, EIGHT→8, unspecified→6.
 *   - OtpType TOTP imported; HOTP → null (caller warns + skips); else rejected.
 *   - No period in the format → 30 s. `issuer` omitted when empty.
 * Returns a TotpEntry, or `null` for a HOTP entry the caller should skip.
 */
// ─────────────────── the untrusted-text provisioning gate (Phase 63) ──────────
//
// ⭐ MIRRORED — NOT SHARED — from `libsigil/core/src/totp.rs`
// (`validate_provisioning`, `MAX_PERIOD`, `MAX_SECRET_BYTES`, `MAX_LABEL_CHARS`,
// `is_unsafe_display_char`) and `cli/src/lib.rs` (`check_provisioning`).
// **These MUST stay byte-identical to the Rust rule.** A drift downward is
// INVISIBLE: entries a stranger created would look ordinary on every client.
// The guard is `sigil-wasm/test/provisioning-interop.mjs`, which drives the REAL
// `sigil` binary and this module over ONE shared table of hostile vectors AND
// pins the numbers against GOLDEN LITERALS — because a cross-language *equality*
// check passes a coordinated rename (the Phase 57 `"recovery-kit"` lesson).
//
// ⚠️ INGEST ONLY, and the asymmetry is the point (ADR 0047's rule): this bounds
// what a stranger may CREATE, never what a user already HAS. Nothing on the read
// path calls it — `codeForEntry` still renders an entry with any period, forever
// — because refusing to display an existing entry would delete a working account
// to punish the user for a value we let in.
//
// ⚠️ `addEntry` is deliberately NOT gated. It is also reached by the "add by
// form" UI, where the numbers came from the user's own keyboard. The boundary
// drawn here is *the text came from somewhere else* — a URI, a migration blob, a
// scanned QR — not *an entry is being created*. Same boundary as the CLI's
// `--period` exemption.

/** Largest time step a provisioning URI may request. MIRRORS sigil_core::MAX_PERIOD. */
export const MAX_PERIOD = 600;
/** Largest decoded secret a provisioning URI may carry. MIRRORS sigil_core::MAX_SECRET_BYTES. */
export const MAX_SECRET_BYTES = 1024;
/** Largest label/issuer, in code points. MIRRORS sigil_core::MAX_LABEL_CHARS. */
export const MAX_LABEL_CHARS = 256;
/**
 * Largest number of accounts one bulk-import payload may carry.
 * MIRRORS sigil_core::MAX_PROVISIONING_ENTRIES — see that constant for why 512
 * (it sits just inside the point where the resulting vault stops fitting in
 * sigild's 64 KiB op body, so it cannot refuse an import that would have worked).
 */
export const MAX_PROVISIONING_ENTRIES = 512;

/**
 * Refuse a bulk-import payload carrying more than [`MAX_PROVISIONING_ENTRIES`]
 * accounts. MIRRORS `sigil_core::validate_provisioning_count`.
 *
 * ⭐ Call this INSIDE the decode loop, not after it — checking the finished list
 * means allocating everything a hostile payload asked for and only then deciding
 * not to keep it, which is the allocation this bound exists to prevent.
 *
 * @param {number} count accounts decoded so far, including the one about to be pushed
 */
export function validateProvisioningCount(count) {
  if (count > MAX_PROVISIONING_ENTRIES) {
    throw new Error(
      `import carries more than ${MAX_PROVISIONING_ENTRIES} accounts (reached ${count})`,
    );
  }
}

/**
 * True for a code point that must never appear in a label or issuer: C0/C1
 * controls, and the bidirectional OVERRIDE/ISOLATE format characters that let a
 * label render as a different issuer's name inside our own trusted UI.
 *
 * ⭐ Ordinary right-to-left SCRIPT is untouched — Arabic and Hebrew letters carry
 * their own direction and need none of these. MIRRORS `is_unsafe_display_char`.
 */
export function isUnsafeDisplayChar(cp) {
  return (
    (cp >= 0x00 && cp <= 0x1f) ||
    (cp >= 0x7f && cp <= 0x9f) ||
    (cp >= 0x202a && cp <= 0x202e) ||
    (cp >= 0x2066 && cp <= 0x2069)
  );
}

function hasUnsafeDisplayChar(s) {
  for (const ch of s) {
    if (isUnsafeDisplayChar(ch.codePointAt(0))) return true;
  }
  return false;
}

function countChars(s) {
  let n = 0;
  // eslint-disable-next-line no-unused-vars
  for (const _ of s) n += 1;
  return n;
}

/**
 * Check a provisioning request built from UNTRUSTED TEXT. Throws with the same
 * classification the Rust side reports. MIRRORS `sigil_core::validate_provisioning`.
 *
 * ⚠️ The thrown message names a BOUND and a COUNT, never the offending string —
 * echoing attacker-controlled text into a trusted surface is a free UI-spoofing
 * primitive, which is the very thing the text rules exist to stop.
 *
 * @param {string} label
 * @param {string|null|undefined} issuer
 * @param {number} secretLen decoded secret length in BYTES
 * @param {number} digits
 * @param {number} period
 */
export function validateProvisioning(label, issuer, secretLen, digits, period) {
  if (label.length === 0) throw new Error("label must not be empty");
  const labelChars = countChars(label);
  if (labelChars > MAX_LABEL_CHARS) {
    throw new Error(`label is ${labelChars} characters, over the ${MAX_LABEL_CHARS} maximum`);
  }
  if (issuer !== null && issuer !== undefined) {
    const issuerChars = countChars(issuer);
    if (issuerChars > MAX_LABEL_CHARS) {
      throw new Error(`issuer is ${issuerChars} characters, over the ${MAX_LABEL_CHARS} maximum`);
    }
    if (hasUnsafeDisplayChar(issuer)) {
      throw new Error(
        "label or issuer contains a control or text-direction-override character, " +
          "which can make one account display as another",
      );
    }
  }
  if (hasUnsafeDisplayChar(label)) {
    throw new Error(
      "label or issuer contains a control or text-direction-override character, " +
        "which can make one account display as another",
    );
  }
  if (secretLen > MAX_SECRET_BYTES) {
    throw new Error(`secret is ${secretLen} bytes, over the ${MAX_SECRET_BYTES}-byte maximum`);
  }
  if (!Number.isInteger(digits) || digits < 6 || digits > 10) {
    throw new Error(`digits ${digits} out of range 6..=10`);
  }
  if (period === 0) throw new Error("period must be non-zero");
  if (!Number.isInteger(period) || period < 0) {
    throw new Error(`period ${period} must be a positive integer`);
  }
  if (period > MAX_PERIOD) {
    throw new Error(
      `period ${period}s exceeds the maximum of ${MAX_PERIOD}s: a code that long does not ` +
        "rotate, so it is not a one-time password",
    );
  }
}

/**
 * The warning a user must see for an entry whose time step is so long the code
 * does not meaningfully rotate — or `null` for an ordinary entry.
 *
 * ⭐ MIRRORED — NOT SHARED — from `cli/src/lib.rs::frozen_period_warning`, and
 * keyed off the SAME `MAX_PERIOD` the ingest gate uses so the two can never
 * disagree about what "too long" means. `provisioning-interop.mjs` drives both
 * halves over one table of periods.
 *
 * ⭐⭐ THIS IS THE READ-PATH COUNTERPART TO THE INGEST CEILING, AND IT EXISTS
 * BECAUSE THE CEILING IS DELIBERATELY NOT RETROACTIVE (ADR 0047's rule: bound
 * what a stranger may CREATE, never what a user already HAS). Three routes put
 * an out-of-bounds entry in front of a browser and NONE of them is the ingest
 * gate:
 *
 *   1. a vault sealed before this release, opened now;
 *   2. `sigil totp add --secret … --period N`, which is deliberately exempt
 *      because the operator typed the number themselves;
 *   3. ⚠️ A PHASE 61 VAULT MERGE — a co-owner of a shared vault pushes a
 *      snapshot and `mergeVaults` adopts every entry in it unchecked. See the
 *      block comment on `mergeVaults` in `totp-vault.mjs` for why that door is
 *      deliberately left open rather than gated.
 *
 * Until this existed the product rendered such an entry with an ordinary-looking
 * countdown — i.e. told the user their second factor was fine when it was a
 * static secret in a rotating costume, which is the exact defect Phase 63 opened
 * with. The CLI has warned since Phase 63; this is the browser half.
 *
 * ⛔ IT REPORTS AND NEVER CORRECTS. Nothing here changes the code, the period or
 * the entry — an entry is immutable (ADR 0049) — and nothing here refuses to
 * display it. The only remedy is for the user to remove it and re-enrol with the
 * service, which is what the text says.
 *
 * @param {number} period the entry's time step in seconds
 * @returns {string|null}
 */
export function frozenPeriodWarning(period) {
  if (!Number.isFinite(period) || period <= MAX_PERIOD) return null;
  return (
    `This entry's time step is ${period}s, so its code does not rotate on any human ` +
    `timescale — a single observation of it stays valid. Sigil no longer accepts an entry ` +
    `like this, but it will not delete one you already have. Remove it and re-enrol with ` +
    `the service to get a real rotating code.`
  );
}

function migrationOtpToEntry(otp) {
  if (otp.otpType === OTP_HOTP) return null;
  if (otp.otpType !== OTP_TOTP) {
    throw new Error(`unsupported OTP type ${otp.otpType} (expected TOTP)`);
  }

  let algorithm;
  switch (otp.algorithm) {
    case ALG_SHA1:
      algorithm = "sha1";
      break;
    case ALG_SHA256:
      algorithm = "sha256";
      break;
    case ALG_SHA512:
      algorithm = "sha512";
      break;
    case ALG_MD5:
      throw new Error("MD5 algorithm is not supported");
    default:
      throw new Error(
        `unsupported/unspecified algorithm ${otp.algorithm} (expected SHA1, SHA256, or SHA512)`,
      );
  }

  let digits;
  if (otp.digits === DIGITS_SIX) digits = 6;
  else if (otp.digits === DIGITS_EIGHT) digits = 8;
  else if (otp.digits === 0) digits = 6; // unspecified → default 6
  else throw new Error(`unsupported digit count ${otp.digits} (expected SIX or EIGHT)`);

  if (otp.secret.length === 0) throw new Error("entry has an empty secret");
  if (otp.name.length === 0) throw new Error("entry has an empty name");

  // ⭐ The untrusted-text gate, on the door that carries MANY accounts at once.
  // `period` is not attacker-chosen here (the wire format has no period field),
  // but the name, the issuer and the secret length all are.
  validateProvisioning(
    otp.name,
    otp.issuer.length > 0 ? otp.issuer : null,
    otp.secret.length,
    digits,
    TOTP_DEFAULT_PERIOD,
  );

  const entry = {
    label: otp.name, // migration keeps the full name as the label (no split)
    secret: bytesToBase64(otp.secret),
    algorithm,
    digits,
    period: TOTP_DEFAULT_PERIOD,
    // The migration wire format carries no Sigil entry id, so an imported entry
    // gets a fresh one — the same thing the CLI's new_totp_entry does.
    uuid: randomEntryUuid(),
  };
  if (otp.issuer.length > 0) entry.issuer = otp.issuer;
  return entry;
}

/**
 * Map a vault TotpEntry to a raw OtpParameters for export (mirrors
 * entry_to_migration_otp). The migration format expresses only SHA1/256/512,
 * 6/8 digits, TOTP, and a fixed 30 s period; anything outside that throws rather
 * than being silently corrupted.
 *
 * ⛔ THAT INCLUDES THE PERIOD (Phase 59). The wire format has no period field, so
 * a 60 s entry used to be exported as if it were 30 s — the receiving app would
 * then compute DIFFERENT codes from the same secret, i.e. the export was a
 * silent lie about an account that would simply stop working.
 */
function entryToMigrationOtp(entry) {
  if (entry.period !== TOTP_DEFAULT_PERIOD) {
    throw new Error(
      `cannot export ${JSON.stringify(entry.label)} to the Google Authenticator migration ` +
        `format: its period is ${entry.period} s and that format can only express ` +
        `${TOTP_DEFAULT_PERIOD} s, so the exported account would generate the WRONG codes. ` +
        `Use the plain otpauth:// export instead — it carries the period`,
    );
  }
  const secret = base64ToBytes(entry.secret);
  let algorithm;
  switch (entry.algorithm) {
    case "sha1":
      algorithm = ALG_SHA1;
      break;
    case "sha256":
      algorithm = ALG_SHA256;
      break;
    case "sha512":
      algorithm = ALG_SHA512;
      break;
    default:
      throw new Error(`unsupported algorithm ${entry.algorithm} for migration`);
  }
  let digits;
  if (entry.digits === 6) digits = DIGITS_SIX;
  else if (entry.digits === 8) digits = DIGITS_EIGHT;
  else {
    throw new Error(
      `cannot export ${entry.digits}-digit entry ${JSON.stringify(entry.label)} to migration format (only 6 or 8)`,
    );
  }
  return {
    secret,
    name: entry.label,
    issuer: entry.issuer ?? "",
    algorithm,
    digits,
    otpType: OTP_TOTP,
    counter: 0n,
  };
}

// ── Public URI API ───────────────────────────────────────────────────────────

/**
 * Decode an `otpauth-migration://offline?data=<BASE64>` URI.
 *
 * ⚠️ RETURNS A BATCH OBJECT, NOT AN ARRAY (Phase 59):
 *
 *   { entries, version, batchSize, batchIndex, batchId, complete, finalBatch,
 *     batchNote }
 *
 * because ONE URI is ONE QR CODE, and a large Google Authenticator export spans
 * several. `entries` holds only what THIS payload carried; `complete` is false
 * and `batchNote` is a sentence when there are more QR codes to import. A caller
 * that reports a count without checking `complete` is telling the user a partial
 * transfer succeeded.
 *
 * HOTP accounts are skipped with a console.warn (the vault is TOTP-only),
 * matching the CLI. Mirrors decode_migration_uri.
 *
 * Throws on a wrong scheme, a missing `data=` parameter, bad base64, a malformed
 * payload, or a per-account mapping error (e.g. MD5/unspecified algorithm).
 */
export function decodeMigrationUri(uri) {
  const trimmed = String(uri).trim();
  if (!trimmed.toLowerCase().startsWith(MIGRATION_SCHEME)) {
    throw new Error("not an otpauth-migration:// URI");
  }
  const q = trimmed.indexOf("?");
  const query = q >= 0 ? trimmed.slice(q + 1) : "";
  let data = null;
  for (const pair of query.split("&")) {
    if (pair.startsWith("data=")) {
      data = pair.slice("data=".length);
      break;
    }
  }
  if (data === null) {
    throw new Error("otpauth-migration URI has no data= parameter");
  }
  const bytes = decodeMigrationData(data);
  const payload = decodeMigrationPayload(bytes);
  const entries = [];
  for (const p of payload.otps) {
    const entry = migrationOtpToEntry(p);
    if (entry === null) {
      console.warn(
        `sigil: skipping HOTP entry ${JSON.stringify(p.name)} (the vault stores TOTP only)`,
      );
      continue;
    }
    entries.push(entry);
  }
  const batch = {
    entries,
    version: payload.version,
    batchSize: payload.batchSize,
    batchIndex: payload.batchIndex,
    batchId: payload.batchId,
  };
  batch.complete = migrationBatchIsComplete(batch);
  // ⭐ `finalBatch` is what lets a UI say "that was the last one" instead of
  // "THIS IMPORT IS INCOMPLETE" to someone who has just finished. `batchNote`
  // already reads correctly for both cases; this is for the surrounding framing.
  batch.finalBatch = migrationBatchIsFinal(batch);
  batch.batchNote = migrationBatchNote(batch);
  return batch;
}

/**
 * Encode an array of vault TotpEntry objects into an
 * `otpauth-migration://offline?data=<BASE64>` URI. The output carries the OTP
 * SECRETS IN THE CLEAR — callers must warn before showing it. Mirrors
 * encode_migration_uri.
 */
export function encodeMigrationUri(entries) {
  const otps = entries.map(entryToMigrationOtp);
  const data = bytesToBase64(encodeMigrationPayload(otps));
  return `${MIGRATION_SCHEME}offline?data=${data}`;
}

/**
 * Parse a single `otpauth://totp/LABEL?secret=BASE32&issuer=..&algorithm=..&
 * digits=..&period=..` provisioning URI into a vault TotpEntry. Mirrors
 * cli/src/lib.rs::parse_otpauth_uri: a `Issuer:Account` label seeds the issuer
 * (a `?issuer=` query overrides it); `secret` is required; only `totp` is
 * accepted (not `hotp`).
 *
 * Throws on a bad scheme/type, a missing/invalid secret, an unknown algorithm,
 * non-integer digits/period, or an empty account label.
 */
export function parseOtpauthUri(uri) {
  const raw = String(uri);
  const lower = raw.toLowerCase();
  const prefix = "otpauth://totp/";
  if (!lower.startsWith(prefix)) {
    if (lower.startsWith("otpauth://hotp/")) {
      throw new Error(
        "otpauth hotp:// URIs are not supported (no time step); use a totp:// URI",
      );
    }
    throw new Error("not an otpauth://totp/ URI");
  }
  const rest = raw.slice(prefix.length);
  const qi = rest.indexOf("?");
  const labelPart = qi >= 0 ? rest.slice(0, qi) : rest;
  const query = qi >= 0 ? rest.slice(qi + 1) : "";

  const labelDecoded = percentDecode(labelPart);
  let issuerFromLabel = null;
  let label;
  const colon = labelDecoded.indexOf(":");
  if (colon >= 0) {
    issuerFromLabel = labelDecoded.slice(0, colon).trim();
    label = labelDecoded.slice(colon + 1).trim();
  } else {
    label = labelDecoded.trim();
  }

  let secretB32 = null;
  let issuerFromQuery = null;
  let algorithm = "sha1";
  let digits = 6;
  let period = TOTP_DEFAULT_PERIOD;

  for (const pair of query.split("&")) {
    if (pair.length === 0) continue;
    const eq = pair.indexOf("=");
    const k = (eq >= 0 ? pair.slice(0, eq) : pair).toLowerCase();
    const v = eq >= 0 ? pair.slice(eq + 1) : "";
    if (k === "secret") secretB32 = v;
    else if (k === "issuer") issuerFromQuery = percentDecode(v);
    else if (k === "algorithm") {
      const a = v.toLowerCase();
      if (a !== "sha1" && a !== "sha256" && a !== "sha512") {
        throw new Error(`unknown algorithm ${JSON.stringify(v)} (expected SHA1/SHA256/SHA512)`);
      }
      algorithm = a;
    } else if (k === "digits") {
      if (!/^\d+$/.test(v)) throw new Error(`digits ${JSON.stringify(v)} is not an integer`);
      digits = parseInt(v, 10);
    } else if (k === "period") {
      if (!/^\d+$/.test(v)) throw new Error(`period ${JSON.stringify(v)} is not an integer`);
      period = parseInt(v, 10);
    }
    // ignore unknown params (counter, image, …)
  }

  if (secretB32 === null) throw new Error("otpauth URI has no secret");
  const secretBytes = base32Decode(secretB32);
  // A `?issuer=` query wins over the label prefix.
  let issuer = issuerFromQuery ?? issuerFromLabel;
  if (issuer !== null && issuer.length === 0) issuer = null;
  if (label.length === 0) throw new Error("otpauth URI has an empty account label");
  // ⭐ THE UNTRUSTED-TEXT GATE (Phase 63). Everything above merely *parsed* the
  // URI; this is where we decide whether a stranger may ask for it. A scanned QR
  // reaches this exact line, which is why the gate lives here and not in the UI.
  validateProvisioning(label, issuer, secretBytes.length, digits, period);

  const entry = {
    label,
    secret: bytesToBase64(secretBytes),
    algorithm,
    digits,
    period,
    // `otpauth://` is an INTEROP format with no Sigil entry id, so a parse
    // produces a fresh one — mirroring the CLI's parse_otpauth_uri, which goes
    // through new_totp_entry.
    uuid: randomEntryUuid(),
  };
  if (issuer !== null) entry.issuer = issuer;
  return entry;
}

/**
 * Render a vault TotpEntry as an `otpauth://totp/…` provisioning URI (secret
 * base32-encoded, label/issuer percent-encoded). When an issuer is present the
 * path is `Issuer:Account` AND an `issuer=` query is added (both, per the Key
 * URI convention); `algorithm` is upper-cased. Mirrors entry_to_otpauth_uri.
 *
 * This is an EXPORT: the returned URI contains the secret IN THE CLEAR.
 */
export function buildOtpauthUri(entry) {
  const secretB32 = base32Encode(base64ToBytes(entry.secret));
  const account = percentEncode(entry.label);
  const issuer = entry.issuer && entry.issuer.length > 0 ? entry.issuer : null;

  const labelPath = issuer ? `${percentEncode(issuer)}:${account}` : account;
  let uri = `otpauth://totp/${labelPath}?secret=${secretB32}`;
  if (issuer) uri += `&issuer=${percentEncode(issuer)}`;
  uri += `&algorithm=${entry.algorithm.toUpperCase()}`;
  uri += `&digits=${entry.digits}`;
  uri += `&period=${entry.period}`;
  return uri;
}
