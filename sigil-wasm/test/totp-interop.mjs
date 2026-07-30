// totp-interop.mjs — the CROSS-CLIENT TOTP proof: a secret added by the `sigil`
// CLI, synced through the OPAQUE zero-knowledge sigild op-log, and turned back
// into the CORRECT one-time code by the browser/wasm client.
//
// It builds sigild + the CLI, ensures the wasm binding (pkg-node), boots a real
// sigild on a free localhost port (SIGILD_ENABLE_DEV_OPS=1, in-memory, NO auth),
// and proves:
//
//   KAT      DETERMINISTIC wasm TOTP: the wasm binding reproduces the official
//            RFC 6238 Appendix B vectors (T=59, 8 digits) for SHA-1/256/512 —
//            proving the wasm code path is correct independent of any clock.
//   CROSS    CLI writes -> op-log -> browser generates: `sigil totp add` seals a
//            TOTP secret into a SIGILcli vault; pushContainer sends the OPAQUE
//            vault bytes to sigild; pullContainers reads them back; openVault
//            (totp-vault.mjs) decrypts the SAME vault; and codeForEntry(T=59)
//            equals BOTH the RFC vector 94287082 AND an INDEPENDENT Node
//            HMAC-SHA1 TOTP — so the secret survived the round-trip intact and
//            the wasm client agrees with a from-scratch implementation.
//   OPAQUE   the server returned the pushed vault bytes VERBATIM (no crypto on
//            the blob) — the zero-knowledge boundary held.
//
// Pre-audit / UNAUDITED / DEV / LOCALHOST / PLAIN-HTTP demo. Do NOT store real
// 2FA secrets. Usage: `node test/totp-interop.mjs`. Exits 0 with a PASS line,
// non-zero on any mismatch. Always builds fresh sigild + CLI and always kills
// the server + cleans temp.

import { createHmac } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:net";

import { pushContainer, pullContainers } from "../sync.mjs";
import { openVault, codeForEntry, base64ToBytes } from "../totp-vault.mjs";
import { resolveGo } from "./go-helper.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");
const pkgPath = join(__dirname, "..", "pkg-node", "sigil_wasm.js");
const buildWasm = join(__dirname, "..", "build-wasm.sh");
const cliManifest = join(repoRoot, "cli", "Cargo.toml");
const cliBinary = join(repoRoot, "cli", "target", "debug", "sigil");
const sigildDir = join(repoRoot, "sigild");

function fail(msg) {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
}
function assert(cond, msg) {
  if (!cond) fail(msg);
}
function bytesEqual(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

// Toolchain PATH exactly like the rest of the repo (macOS arm64).
const toolPath = [
  `${process.env.HOME}/.rustup/toolchains/stable-aarch64-apple-darwin/bin`,
  `${process.env.HOME}/.cargo/bin`,
  "/opt/homebrew/bin",
  process.env.PATH ?? "",
].join(":");
const toolEnv = { ...process.env, PATH: toolPath };
const goBin = resolveGo();

// Grab a free localhost TCP port by binding :0 and reading it back.
function freePort() {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.on("error", reject);
    srv.listen(0, "127.0.0.1", () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

// Poll {base}/readyz until it returns 200 or we time out.
async function waitReady(base, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const res = await fetch(`${base}/readyz`);
      if (res.status === 200) return;
    } catch {
      // not up yet
    }
    if (Date.now() > deadline) throw new Error(`sigild /readyz not ready within ${timeoutMs}ms`);
    await new Promise((r) => setTimeout(r, 150));
  }
}

// An INDEPENDENT from-scratch RFC 6238 TOTP over RFC 4226 dynamic truncation,
// using ONLY node:crypto's HMAC — deliberately NOT the wasm/sigil-core path, so
// agreement is a real cross-implementation check, not a tautology.
function totpIndependent(keyBytes, unixTime, period, digits, algo = "sha1") {
  const counter = Math.floor(unixTime / period);
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac(algo, Buffer.from(keyBytes)).update(msg).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const bin =
    ((mac[offset] & 0x7f) << 24) |
    (mac[offset + 1] << 16) |
    (mac[offset + 2] << 8) |
    mac[offset + 3];
  const code = (bin >>> 0) % 10 ** digits;
  return String(code).padStart(digits, "0");
}

// --- Ensure the wasm binding exists. ---
if (!existsSync(pkgPath)) {
  console.log("pkg-node missing — building the wasm (./build-wasm.sh) ...");
  try {
    execFileSync("bash", [buildWasm], { stdio: "inherit", env: toolEnv, cwd: join(__dirname, "..") });
  } catch (e) {
    fail(`could not build the wasm binding (./build-wasm.sh): ${e.message}`);
  }
}
assert(existsSync(pkgPath), `${pkgPath} not found even after ./build-wasm.sh. Build the wasm first.`);

// Isolated temp workspace: the built sigild binary + the vault file.
const work = mkdtempSync(join(tmpdir(), "sigil-totp-interop-"));
const sigildBin = join(work, "sigild");
const vaultFile = join(work, "totp-vault.sigil");

// --- Build sigild + the CLI. ---
console.log("building sigild (go build ./cmd/server) ...");
try {
  execFileSync(goBin, ["build", "-o", sigildBin, "./cmd/server"], {
    stdio: "inherit",
    env: toolEnv,
    cwd: sigildDir,
  });
} catch (e) {
  rmSync(work, { recursive: true, force: true });
  fail(`could not build sigild: ${e.message}`);
}
assert(existsSync(sigildBin), `built sigild binary not found at ${sigildBin}`);

console.log("building the sigil CLI (cargo build --bin sigil) ...");
try {
  execFileSync("cargo", ["build", "--manifest-path", cliManifest, "--bin", "sigil"], {
    stdio: "inherit",
    env: toolEnv,
  });
} catch (e) {
  rmSync(work, { recursive: true, force: true });
  fail(`could not build the sigil CLI: ${e.message}`);
}
assert(existsSync(cliBinary), `built CLI binary not found at ${cliBinary}`);

const wasm = await import(pkgPath);
const enc = new TextEncoder();

// RFC 6238 Appendix B keys (distinct ASCII length per hash).
const RFC_KEY_SHA1 = enc.encode("12345678901234567890");
const RFC_KEY_SHA256 = enc.encode("12345678901234567890123456789012");
const RFC_KEY_SHA512 = enc.encode(
  "1234567890123456789012345678901234567890123456789012345678901234",
);
// base32 of RFC_KEY_SHA1 ("12345678901234567890") — what a provisioning string
// carries; the CLI decodes it and stores the raw bytes.
const RFC_SHA1_SECRET_BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

let sigild = null;
try {
  // ===================================================================
  // KAT — DETERMINISTIC wasm TOTP against the RFC 6238 App B vectors.
  //       T=59, 8 digits, period 30, t0 0 — independent of any clock.
  // ===================================================================
  assert(wasm.totp(RFC_KEY_SHA1, 59, 30, 0, 8, "sha1") === 94287082, "KAT sha1 mismatch");
  assert(wasm.totp(RFC_KEY_SHA256, 59, 30, 0, 8, "sha256") === 46119246, "KAT sha256 mismatch");
  assert(wasm.totp(RFC_KEY_SHA512, 59, 30, 0, 8, "sha512") === 90693936, "KAT sha512 mismatch");
  // And the zero-padded rendering is exactly 8 chars.
  assert(wasm.format_code(94287082, 8) === "94287082", "KAT format_code mismatch");
  console.log("  KAT    OK: wasm TOTP reproduces the RFC 6238 App B vectors (sha1/256/512, T=59)");

  // ===================================================================
  // CROSS — CLI writes a TOTP secret -> opaque sigild -> browser reads it.
  // ===================================================================
  const vaultId = "totp-cross-client";
  const PASSWORD_STR = "correct horse battery staple";
  const password = enc.encode(PASSWORD_STR);

  // 1) The CLI adds a TOTP entry (base32 secret) into a SIGILcli vault file.
  const addOut = execFileSync(
    cliBinary,
    [
      "totp", "add", "work",
      "--secret", RFC_SHA1_SECRET_BASE32,
      "--digits", "8",
      "--period", "30",
      "--vault", vaultFile,
    ],
    { env: { ...process.env, SIGIL_PASSWORD: PASSWORD_STR }, encoding: "utf8" },
  );
  assert(/added "work"/.test(addOut), `unexpected CLI totp add output: ${addOut.trim()}`);
  assert(existsSync(vaultFile), "CLI did not write the vault file");
  const vaultBytes = new Uint8Array(readFileSync(vaultFile));
  assert(
    Buffer.from(vaultBytes.slice(0, 8)).toString("latin1") === "SIGILcli",
    "CLI vault file is not a SIGILcli container (bad magic)",
  );

  // 2) Boot a live sigild (dev-ops ON, in-memory, no auth) and push the OPAQUE
  //    vault bytes to it, then pull them back.
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  console.log(`  starting sigild on ${base} (SIGILD_ENABLE_DEV_OPS=1, in-memory, no auth) ...`);
  sigild = spawn(sigildBin, [], {
    env: { ...process.env, SIGILD_ADDR: `127.0.0.1:${port}`, SIGILD_ENABLE_DEV_OPS: "1" },
    stdio: ["ignore", "inherit", "inherit"],
  });
  sigild.on("error", (e) => fail(`sigild failed to spawn: ${e.message}`));
  await waitReady(base);

  const { seq } = await pushContainer(base, vaultId, vaultBytes);
  assert(seq === 1, `first push should be seq 1, got ${seq}`);

  // OPAQUE check: the stored blob must byte-equal the pushed vault (no crypto).
  const rawRes = await fetch(`${base}/v1/vaults/${vaultId}/ops?since=0&limit=1000`);
  assert(rawRes.status === 200, `raw GET should be 200, got ${rawRes.status}`);
  const rawJson = await rawRes.json();
  assert(rawJson.ops.length === 1, `expected 1 stored op, got ${rawJson.ops.length}`);
  const storedBytes = base64ToBytes(rawJson.ops[0].blob);
  assert(
    bytesEqual(storedBytes, vaultBytes),
    "OPAQUE: server-stored blob does not byte-equal the pushed vault (server altered the bytes!)",
  );
  console.log("  OPAQUE OK: sigild returned the pushed vault bytes verbatim (no crypto on the blob)");

  const pulled = await pullContainers(base, vaultId, 0);
  assert(pulled.length === 1, `expected 1 pulled op, got ${pulled.length}`);
  assert(bytesEqual(pulled[0].container, vaultBytes), "pulled vault != pushed vault");

  // 3) The browser/wasm client opens the SAME vault and generates the code.
  const vault = openVault(wasm, password, pulled[0].container);
  assert(vault.version === 1, `vault version should be 1, got ${vault.version}`);
  const work = vault.entries.find((e) => e.label === "work");
  assert(work, "pulled vault has no entry labeled 'work'");
  assert(work.algorithm === "sha1", `entry algorithm should be sha1, got ${work.algorithm}`);
  assert(work.digits === 8 && work.period === 30, "entry digits/period not 8/30");

  // The CLI must have stored the base32-decoded RAW key bytes (as base64).
  assert(
    bytesEqual(base64ToBytes(work.secret), RFC_KEY_SHA1),
    "entry secret does not decode to the RFC SHA-1 key (base32->base64 storage drift)",
  );

  // codeForEntry at T=59 must equal the RFC vector AND an independent Node TOTP.
  const wasmCode = codeForEntry(wasm, work, 59);
  const independent = totpIndependent(RFC_KEY_SHA1, 59, 30, 8, "sha1");
  assert(wasmCode === "94287082", `codeForEntry(T=59) = ${wasmCode}, expected RFC 94287082`);
  assert(
    wasmCode === independent,
    `wasm code ${wasmCode} != independent Node TOTP ${independent}`,
  );
  console.log(
    `  CROSS  OK: CLI-added secret -> opaque sigild -> wasm code ${wasmCode} ` +
      "== RFC 94287082 == independent Node HMAC-SHA1 TOTP",
  );
} finally {
  if (sigild && sigild.exitCode === null) {
    sigild.kill("SIGKILL");
  }
  rmSync(work, { recursive: true, force: true });
}

console.log(`\nversion: ${wasm.version()}`);
console.log(
  "PASS: cross-client TOTP proven — DETERMINISTIC wasm RFC 6238 KAT (sha1/256/512); " +
    "CLI writes a TOTP secret -> OPAQUE zero-knowledge sigild op-log -> browser/wasm " +
    "generates the correct code (== RFC vector == independent Node TOTP)",
);
process.exit(0);
