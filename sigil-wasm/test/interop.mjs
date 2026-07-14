// interop.mjs — bidirectional SIGILcli container interop proof between the
// sigil-wasm binding and the REAL `sigil` CLI binary.
//
// This proves that the container the browser/Node produces (seal_to_container)
// is byte-compatible with the CLI's on-disk format, and vice-versa, by shelling
// out to the actual `sigil` binary — not by re-implementing its logic here.
//
//   Direction A: `sigil seal`  -> wasm.open_container   (CLI seals, wasm opens)
//   Direction B: wasm.seal_to_container -> `sigil open` (wasm seals, CLI opens)
//
// The shared format + AAD live in BOTH cli/src/lib.rs and sigil-wasm/src/lib.rs
// (MAGIC="SIGILcli", version=1, params u32-LE, salt_len:u8, salt, envelope; AAD
// = "sigil-cli/1"). If either drifts, one of the directions below fails.
//
// Pre-audit / UNAUDITED demo. Do not protect real secrets.
//
// ORDERING: pkg-node must exist first. Run ./build-wasm.sh before this test.
// This script builds the CLI itself (cargo build) so it always uses fresh CLI
// bytes. Usage: `node test/interop.mjs`. Exits 0 with a PASS line on success,
// non-zero on any mismatch.

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

const PASSWORD_STR = "correct horse battery staple";
const password = enc.encode(PASSWORD_STR);
const plaintextStr = "SIGILcli-interop-SECRET-MARKER-🔒-42";
const plaintext = enc.encode(plaintextStr);

// Fast Argon2 params for Direction B (wasm seals). Direction A accepts whatever
// params the CLI writes — they are self-describing in the container header.
const M_COST = 8;
const T_COST = 1;
const P_COST = 1;

// Isolated temp workspace, cleaned up at the end.
const work = mkdtempSync(join(tmpdir(), "sigil-interop-"));
const cliEnv = { ...process.env, SIGIL_PASSWORD: PASSWORD_STR };

function runCli(args) {
  return execFileSync(cliBinary, args, { env: cliEnv });
}
function bytesEqual(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

try {
  // === Direction A: CLI seals -> wasm opens ================================
  const aPlain = join(work, "a-plain.txt");
  const aCont = join(work, "a-container.sigil");
  writeFileSync(aPlain, plaintext);

  runCli(["seal", "--in", aPlain, "--out", aCont]);
  const aContainerBytes = new Uint8Array(readFileSync(aCont));

  // Sanity: the CLI really wrote a SIGILcli container.
  assert(
    dec.decode(aContainerBytes.slice(0, 8)) === "SIGILcli",
    "Direction A: CLI output is not a SIGILcli container (bad magic)",
  );

  const aRecovered = wasm.open_container(password, aContainerBytes);
  assert(
    aRecovered instanceof Uint8Array,
    "Direction A: open_container must return a Uint8Array",
  );
  assert(
    bytesEqual(aRecovered, plaintext),
    `Direction A: recovered plaintext != original (got "${dec.decode(aRecovered)}")`,
  );
  console.log("  Direction A OK: `sigil seal` -> wasm.open_container round-trips");

  // === Direction B: wasm seals -> CLI opens ================================
  const salt = new Uint8Array(wasm.recommended_salt_len());
  webcrypto.getRandomValues(salt);
  const nonce = new Uint8Array(wasm.nonce_len());
  webcrypto.getRandomValues(nonce);

  const bContainer = wasm.seal_to_container(
    password,
    salt,
    nonce,
    M_COST,
    T_COST,
    P_COST,
    plaintext,
  );
  assert(
    bContainer instanceof Uint8Array && bContainer.length > 0,
    "Direction B: seal_to_container must return a non-empty Uint8Array",
  );
  // The container must not leak the plaintext marker.
  const marker = enc.encode("SIGILcli-interop-SECRET-MARKER");
  assert(
    !(function contains(h, n) {
      outer: for (let i = 0; i + n.length <= h.length; i++) {
        for (let j = 0; j < n.length; j++) if (h[i + j] !== n[j]) continue outer;
        return true;
      }
      return false;
    })(bContainer, marker),
    "Direction B: container must NOT contain the plaintext marker",
  );

  const bCont = join(work, "b-container.sigil");
  const bOut = join(work, "b-recovered.txt");
  writeFileSync(bCont, bContainer);

  runCli(["open", "--in", bCont, "--out", bOut]);
  const bRecovered = new Uint8Array(readFileSync(bOut));
  assert(
    bytesEqual(bRecovered, plaintext),
    `Direction B: CLI-recovered plaintext != original (got "${dec.decode(bRecovered)}")`,
  );
  console.log("  Direction B OK: wasm.seal_to_container -> `sigil open` round-trips");
} finally {
  rmSync(work, { recursive: true, force: true });
}

console.log(`version: ${wasm.version()}`);
console.log(
  "PASS: sigil-wasm <-> sigil CLI SIGILcli container interop " +
    "(A: CLI seals / wasm opens; B: wasm seals / CLI opens)",
);
process.exit(0);
