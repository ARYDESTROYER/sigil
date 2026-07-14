// hybrid-interop.mjs — bidirectional SIGILhyb (hybrid PUBLIC-KEY) interop proof
// between the sigil-wasm binding and the REAL `sigil` CLI binary.
//
// This is the no-password, public-key path: encrypt a file TO another device's
// HYBRID IDENTITY (X25519 + ML-KEM-768). It proves the container the browser/Node
// produces (hybrid_seal_to_container) is byte-compatible with the CLI's on-disk
// SIGILhyb format, and vice-versa, by shelling out to the actual `sigil` binary —
// not by re-implementing its logic here.
//
//   Direction A: wasm.hybrid_seal_to_container -> `sigil hybrid-open`
//                (wasm seals to a CLI-generated identity; CLI opens)
//   Direction B: `sigil hybrid-seal` -> wasm.hybrid_open_container
//                (CLI seals to a wasm-derived identity; wasm opens)
//
// The wasm crate does NOT parse identity files; NODE bridges the CLI identity
// JSON (base64 fields) into raw key bytes and back. The shared format + AAD live
// in BOTH cli/src/lib.rs and sigil-wasm/src/lib.rs (HYBRID_MAGIC="SIGILhyb",
// version=1, eph_x25519_pub[32], mlkem_ct[1088], envelope; AAD =
// "sigil-hybrid-cli/1"; identity JSON fields x25519_public_key / mlkem_encaps_key
// / x25519_secret / mlkem_seed, all standard-base64, identity version=1). If
// either drifts, one of the directions below fails.
//
// Pre-audit / UNAUDITED demo (CUSTOM KEM-then-AEAD, NOT RFC 9180 HPKE; the SYSTEM
// is NOT post-quantum secure). Do not protect real secrets.
//
// ORDERING: pkg-node must exist first. Run ./build-wasm.sh before this test.
// This script builds the CLI itself (cargo build) so it always uses fresh CLI
// bytes. Usage: `node test/hybrid-interop.mjs`. Exits 0 with a PASS line on
// success, non-zero on any mismatch.

import { webcrypto } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync, mkdtempSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");
const pkgPath = join(__dirname, "..", "pkg-node", "sigil_wasm.js");
const cliManifest = join(repoRoot, "cli", "Cargo.toml");
const cliBinary = join(repoRoot, "cli", "target", "debug", "sigil");

function fail(msg) {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
}
function assert(cond, msg) {
  if (!cond) fail(msg);
}

if (!existsSync(pkgPath)) {
  fail(`${pkgPath} not found. Build the wasm first: ./build-wasm.sh`);
}

// Toolchain PATH exactly like the rest of the repo (macOS arm64), so the cargo
// build below resolves the pinned stable toolchain.
const cargoPath = [
  `${process.env.HOME}/.rustup/toolchains/stable-aarch64-apple-darwin/bin`,
  `${process.env.HOME}/.cargo/bin`,
  "/opt/homebrew/bin",
  process.env.PATH ?? "",
].join(":");

// --- Build the real CLI once. ---
console.log("building the sigil CLI (cargo build --bin sigil) ...");
try {
  execFileSync("cargo", ["build", "--manifest-path", cliManifest, "--bin", "sigil"], {
    stdio: "inherit",
    env: { ...process.env, PATH: cargoPath },
  });
} catch (e) {
  fail(`could not build the sigil CLI: ${e.message}`);
}
assert(existsSync(cliBinary), `built CLI binary not found at ${cliBinary}`);

const wasm = await import(pkgPath);

const enc = new TextEncoder();
const dec = new TextDecoder();

// Field sizes fixed by the core/CLI (see cli/src/lib.rs).
const X25519_SECRET_LEN = 32;
const MLKEM_SEED_LEN = 64;
const MLKEM_COIN_LEN = 32;

const plaintextStr = "SIGILhyb-interop-SECRET-MARKER-🔒-42";
const plaintext = enc.encode(plaintextStr);
const marker = enc.encode("SIGILhyb-interop-SECRET-MARKER");

function b64encode(bytes) {
  return Buffer.from(bytes).toString("base64");
}
function b64decode(str) {
  return new Uint8Array(Buffer.from(str, "base64"));
}
function bytesEqual(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}
function bytesContain(h, n) {
  outer: for (let i = 0; i + n.length <= h.length; i++) {
    for (let j = 0; j < n.length; j++) if (h[i + j] !== n[j]) continue outer;
    return true;
  }
  return false;
}

// Isolated temp workspace, cleaned up at the end.
const work = mkdtempSync(join(tmpdir(), "sigil-hybrid-interop-"));

function runCli(args) {
  return execFileSync(cliBinary, args, { env: process.env });
}

try {
  // === Direction A: wasm seals -> CLI opens ==================================
  // The CLI generates the recipient identity (secret + .pub). Node reads the
  // .pub JSON, decodes the public parts, and hands them to the wasm sealer.
  const aSecretId = join(work, "a-recipient.key");
  const aPubId = `${aSecretId}.pub`; // hybrid-keygen writes <out>.pub
  runCli(["hybrid-keygen", "--out", aSecretId]);
  assert(existsSync(aSecretId) && existsSync(aPubId), "Direction A: hybrid-keygen did not write identity files");

  const aPub = JSON.parse(readFileSync(aPubId, "utf8"));
  assert(aPub.version === 1, `Direction A: unexpected .pub identity version ${aPub.version}`);
  const recipientX25519Pub = b64decode(aPub.x25519_public_key);
  const recipientMlkemEncaps = b64decode(aPub.mlkem_encaps_key);
  assert(recipientX25519Pub.length === 32, "Direction A: x25519_public_key must decode to 32 bytes");
  assert(recipientMlkemEncaps.length === 1184, "Direction A: mlkem_encaps_key must decode to 1184 bytes");

  // Caller-supplied entropy generated in JS (the wasm module has no RNG).
  const ephSecret = new Uint8Array(X25519_SECRET_LEN);
  webcrypto.getRandomValues(ephSecret);
  const coin = new Uint8Array(MLKEM_COIN_LEN);
  webcrypto.getRandomValues(coin);
  const nonce = new Uint8Array(wasm.nonce_len());
  webcrypto.getRandomValues(nonce);

  const aContainer = wasm.hybrid_seal_to_container(
    recipientX25519Pub,
    recipientMlkemEncaps,
    ephSecret,
    coin,
    nonce,
    plaintext,
  );
  assert(
    aContainer instanceof Uint8Array && aContainer.length > 0,
    "Direction A: hybrid_seal_to_container must return a non-empty Uint8Array",
  );
  assert(
    dec.decode(aContainer.slice(0, 8)) === "SIGILhyb",
    "Direction A: wasm output is not a SIGILhyb container (bad magic)",
  );
  assert(!bytesContain(aContainer, marker), "Direction A: container must NOT contain the plaintext marker");

  const aContPath = join(work, "a-container.hyb");
  const aOut = join(work, "a-recovered.txt");
  writeFileSync(aContPath, aContainer);

  runCli(["hybrid-open", "--key", aSecretId, "--in", aContPath, "--out", aOut]);
  const aRecovered = new Uint8Array(readFileSync(aOut));
  assert(
    bytesEqual(aRecovered, plaintext),
    `Direction A: CLI-recovered plaintext != original (got "${dec.decode(aRecovered)}")`,
  );
  console.log("  Direction A OK: wasm.hybrid_seal_to_container -> `sigil hybrid-open` round-trips");

  // === Direction B: CLI seals -> wasm opens ==================================
  // Node generates the recipient secret material, derives the public parts via
  // wasm, writes a CLI-format .pub, has the CLI seal to it, then wasm opens.
  const x25519Secret = new Uint8Array(X25519_SECRET_LEN);
  webcrypto.getRandomValues(x25519Secret);
  const mlkemSeed = new Uint8Array(MLKEM_SEED_LEN);
  webcrypto.getRandomValues(mlkemSeed);

  const x25519Public = wasm.hybrid_x25519_public(x25519Secret);
  const mlkemEncaps = wasm.hybrid_mlkem_encaps_key(mlkemSeed);
  assert(x25519Public instanceof Uint8Array && x25519Public.length === 32, "Direction B: hybrid_x25519_public must return 32 bytes");
  assert(mlkemEncaps instanceof Uint8Array && mlkemEncaps.length === 1184, "Direction B: hybrid_mlkem_encaps_key must return 1184 bytes");

  // Write a CLI-format PUBLIC identity JSON (same field names/base64 as the CLI).
  const bPubId = join(work, "b-recipient.key.pub");
  writeFileSync(
    bPubId,
    JSON.stringify({
      version: 1,
      x25519_public_key: b64encode(x25519Public),
      mlkem_encaps_key: b64encode(mlkemEncaps),
    }),
  );

  const bPlain = join(work, "b-plain.txt");
  const bContPath = join(work, "b-container.hyb");
  writeFileSync(bPlain, plaintext);

  runCli(["hybrid-seal", "--recipient-pub", bPubId, "--in", bPlain, "--out", bContPath]);
  const bContainer = new Uint8Array(readFileSync(bContPath));
  assert(
    dec.decode(bContainer.slice(0, 8)) === "SIGILhyb",
    "Direction B: CLI output is not a SIGILhyb container (bad magic)",
  );

  // wasm opens with the raw secret material Node holds (x25519 secret + mlkem seed).
  const bRecovered = wasm.hybrid_open_container(x25519Secret, mlkemSeed, bContainer);
  assert(bRecovered instanceof Uint8Array, "Direction B: hybrid_open_container must return a Uint8Array");
  assert(
    bytesEqual(bRecovered, plaintext),
    `Direction B: wasm-recovered plaintext != original (got "${dec.decode(bRecovered)}")`,
  );
  console.log("  Direction B OK: `sigil hybrid-seal` -> wasm.hybrid_open_container round-trips");
} finally {
  rmSync(work, { recursive: true, force: true });
}

console.log(`version: ${wasm.version()}`);
console.log(
  "PASS: sigil-wasm <-> sigil CLI SIGILhyb hybrid public-key interop " +
    "(A: wasm seals / CLI opens; B: CLI seals / wasm opens)",
);
process.exit(0);
