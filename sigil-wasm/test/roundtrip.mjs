// roundtrip.mjs — automated Node round-trip proof for the sigil-wasm binding.
//
// This is the end-to-end proof that the wasm-pure `sigil-core` record API works
// in a JavaScript runtime with CALLER-SUPPLIED ENTROPY: the Argon2id salt and
// the AEAD nonce are generated HERE, in Node, via webcrypto.getRandomValues, and
// passed into the wasm as byte arrays. The wasm module itself has no RNG.
//
// Pre-audit / UNAUDITED demo. Do not protect real secrets.
//
// Usage: build first (./build-wasm.sh), then `node test/roundtrip.mjs`.
// Exits 0 on success (prints a PASS line), non-zero on any assertion failure.

import { webcrypto } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync } from "node:fs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkgPath = join(__dirname, "..", "pkg-node", "sigil_wasm.js");

if (!existsSync(pkgPath)) {
  console.error(
    `FAIL: ${pkgPath} not found. Build first: ./build-wasm.sh`,
  );
  process.exit(1);
}

const wasm = await import(pkgPath);

function assert(cond, msg) {
  if (!cond) {
    console.error(`FAIL: ${msg}`);
    process.exit(1);
  }
}

function bytesContain(haystack, needle) {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

// --- Fast Argon2 params so the test is near-instant (m_cost >= 8 * p_cost). ---
const M_COST = 8;
const T_COST = 1;
const P_COST = 1;

const enc = new TextEncoder();
const dec = new TextDecoder();

const password = enc.encode("correct horse battery staple");
const wrongPassword = enc.encode("incorrect horse battery staple");
const aad = enc.encode("sigil-wasm-roundtrip");
const plaintext = enc.encode("SECRET-MARKER-do-not-leak-42");

// --- Caller-supplied entropy: salt + nonce generated in JS. ---
const salt = new Uint8Array(wasm.recommended_salt_len());
webcrypto.getRandomValues(salt);
assert(salt.length === 16, `recommended_salt_len should be 16, got ${salt.length}`);

const nonce = new Uint8Array(wasm.nonce_len());
webcrypto.getRandomValues(nonce);
assert(nonce.length === 24, `nonce_len should be 24, got ${nonce.length}`);

// --- Seal. ---
const envelope = wasm.seal_record(
  password,
  salt,
  nonce,
  M_COST,
  T_COST,
  P_COST,
  aad,
  plaintext,
);
assert(envelope instanceof Uint8Array, "seal_record must return a Uint8Array");
assert(envelope.length > 0, "envelope must be non-empty");

// The sealed bytes must NOT contain the plaintext marker.
assert(
  !bytesContain(envelope, plaintext),
  "envelope must NOT contain the plaintext",
);

// --- Open with the correct password: must round-trip exactly. ---
const recovered = wasm.open_record(
  password,
  salt,
  M_COST,
  T_COST,
  P_COST,
  envelope,
);
assert(recovered instanceof Uint8Array, "open_record must return a Uint8Array");
assert(
  recovered.length === plaintext.length &&
    recovered.every((b, i) => b === plaintext[i]),
  `recovered plaintext must equal the original (got "${dec.decode(recovered)}")`,
);

// --- Open with the WRONG password: must throw. ---
let threw = false;
try {
  wasm.open_record(wrongPassword, salt, M_COST, T_COST, P_COST, envelope);
} catch (e) {
  threw = true;
}
assert(threw, "open_record with the wrong password MUST throw");

// --- A bad nonce length must be rejected at seal time. ---
let nonceThrew = false;
try {
  wasm.seal_record(
    password,
    salt,
    new Uint8Array(wasm.nonce_len() - 1),
    M_COST,
    T_COST,
    P_COST,
    aad,
    plaintext,
  );
} catch (e) {
  nonceThrew = true;
}
assert(nonceThrew, "seal_record with a short nonce MUST throw");

console.log(`version: ${wasm.version()}`);
console.log(
  "PASS: sigil-wasm Node round-trip (caller-supplied salt+nonce; seal->open equal; " +
    "no-plaintext-leak; wrong-password rejected; bad-nonce rejected)",
);
process.exit(0);
