// pinning-interop.mjs — THE PHASE 50 PROOF, plus PHASE 60's receiving half.
//
// Four claims, proven against a REAL sigild, the REAL `sigil` binary, and the
// REAL wasm. No mocks, no stubs, no hand-waving:
//
//   A. KEY PINNING DETECTS AND BLOCKS A KEY-SUBSTITUTION ATTACK. A MALICIOUS
//      SERVER is simulated honestly — a local intercepting proxy sits in front of
//      sigild and REWRITES the body of `GET /v1/devices/{B}/hybrid-key` to an
//      ATTACKER's hybrid public key. That is exactly what a hostile or
//      compromised registry would do, and until Phase 50 the client would have
//      wrapped the vault key straight to it. We show that device A REFUSES, with
//      the specific error, and — the part that actually matters — that the
//      envelope stored for B is BYTE-IDENTICAL to the honest one and CANNOT be
//      opened with the attacker's hybrid secret. The vault key was never wrapped
//      to the attacker.
//
//   B. THE SAFETY NUMBER IS BYTE-IDENTICAL IN RUST AND JS. The `sigil` binary and
//      this JS module print the SAME digits for the SAME key (and for the
//      order-independent PAIRWISE number, from BOTH sides), and different keys
//      give different digits. Plus the fixed known-answer both implementations
//      hardcode.
//
//   C. ROTATION PROTECTS FUTURE CONTENT. After revoking B and rotating the vault
//      to [A, C], a NEW secret added to the vault is UNREADABLE with B's old key,
//      B's envelope is gone from the server, and still-authorized C reads the new
//      secret fine.
//
//   D. ⭐ PHASE 60 — THE UNWRAP GATE, i.e. the RECEIVING side, which had NO
//      defence at all until that phase: `acceptVault` fetched no hybrid key, so
//      the pin store was never consulted when a vault key ARRIVED. Section 7
//      drives the REAL `acceptVault` against the SAME malicious proxy, now
//      substituting the SENDER's key AND the deposited envelope, and shows that
//      first sight pins-and-proceeds (ADR 0038 TOFU, stated as a limit and
//      demonstrated), a wrong supplied safety number is refused while pinning
//      nothing, and a CHANGED sender key is a hard KeyPinMismatchError.
//      ⚠️ It exists because that gate had NO TEST IN EITHER LANGUAGE: deleting
//      the safety-number comparison and the `checkAndPin` call from
//      `verifySenderForUnwrap` left every suite in the repo green while a
//      hostile key was installed in a victim's keyring. Both mutations were run
//      against this section; both go RED.
//
// And the deliberate escape hatch: a LEGITIMATE re-enrolment also trips the alarm
// (it is indistinguishable from an attack), a re-pin with the WRONG safety number
// is refused, and only an explicit `repin --yes` with the RIGHT number restores
// sharing.
//
// Pre-audit / UNAUDITED / DEV / LOCALHOST / PLAIN-HTTP. Usage:
//   node test/pinning-interop.mjs
// Exits 0 with a PASS line, non-zero on any failure. Always kills the server and
// the proxy and removes the temp workspace in a finally block.

import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:net";
import { resolveGo } from "./go-helper.mjs";

import { generateDeviceSeed, enrollDevice, pullContainersAuthed } from "../device-auth.mjs";
import {
  acceptVault,
  wrapVaultKey,
  SafetyNumberMismatchError,
  TRUST_UNVERIFIED_FIRST_SIGHT,
  generateHybridIdentity,
  hybridPublicIdentity,
  publishHybridKey,
  fetchHybridKey,
  verifyRecipientForWrap,
  shareVault,
  safetyNumber,
  pairwiseSafetyNumber,
  renderSafetyNumber,
  hybridSafetyDigest,
  newPinStore,
  requirePinStore,
  checkAndPin,
  repinHybridKey,
  KeyPinMismatchError,
  generateVaultKey,
  vaultKeyFingerprint,
  SAFETY_NUMBER_GROUPS,
  // ⭐ PHASE 60 SYMMETRY — steps 4 and 5 of the CLI's five-step accept, which the
  // browser clients did not have until this phase. Section 7 drives both.
  verifySenderForUnwrap,
  unwrapVaultKey,
  VaultKeyDoesNotOpenError,
  VaultKeyReplacementError,
} from "../sharing.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");
const pkgPath = join(__dirname, "..", "pkg-node", "sigil_wasm.js");
const buildWasm = join(__dirname, "..", "build-wasm.sh");
const sigildDir = join(repoRoot, "sigild");
const cliManifest = join(repoRoot, "cli", "Cargo.toml");
const sigilBin = join(repoRoot, "cli", "target", "debug", "sigil");

// THROW rather than process.exit: exiting here would skip the finally block and
// leave a sigild and a proxy running with a temp workspace on disk.
function fail(msg) {
  throw new Error(`FAIL: ${msg}`);
}
function assert(cond, msg) {
  if (!cond) fail(msg);
}
function bytesEqual(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

const toolPath = [
  `${process.env.HOME}/.rustup/toolchains/stable-aarch64-apple-darwin/bin`,
  `${process.env.HOME}/.cargo/bin`,
  "/opt/homebrew/bin",
  process.env.PATH ?? "",
].join(":");
const toolEnv = { ...process.env, PATH: toolPath };
const goBin = resolveGo();

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

async function waitReady(base, timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      const res = await fetch(`${base}/readyz`);
      if (res.status === 200) return;
    } catch {
      /* not up yet */
    }
    if (Date.now() > deadline) throw new Error(`sigild /readyz not ready within ${timeoutMs}ms`);
    await new Promise((r) => setTimeout(r, 150));
  }
}

// --- Ensure the wasm binding exists. ---
if (!existsSync(pkgPath)) {
  console.log("pkg-node missing — building the wasm (./build-wasm.sh) ...");
  try {
    execFileSync("bash", [buildWasm], {
      stdio: "inherit",
      env: toolEnv,
      cwd: join(__dirname, ".."),
    });
  } catch (e) {
    fail(`could not build the wasm binding (./build-wasm.sh): ${e.message}`);
  }
}
assert(existsSync(pkgPath), `${pkgPath} not found even after ./build-wasm.sh.`);

const work = mkdtempSync(join(tmpdir(), "sigil-pinning-"));
const sigildBin = join(work, "sigild");
const logPath = join(work, "sigild.log");

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

console.log("building the REAL sigil CLI (cargo build --bin sigil) ...");
try {
  execFileSync("cargo", ["build", "--manifest-path", cliManifest, "--bin", "sigil", "--quiet"], {
    stdio: "inherit",
    env: toolEnv,
  });
} catch (e) {
  rmSync(work, { recursive: true, force: true });
  fail(`could not build the sigil CLI: ${e.message}`);
}
assert(existsSync(sigilBin), `built sigil binary not found at ${sigilBin}`);

const wasm = await import(pkgPath);

const TOKEN_A = "enroll-token-A-0123456789";
const TOKEN_B = "enroll-token-B-0123456789";
const TOKEN_C = "enroll-token-C-0123456789";
const TOKEN_JS = "enroll-token-JS-0123456789";
const ADMIN_TOKEN = "admin-token-0123456789";
const PASSWORD = "correct horse battery staple";

// The PUBLIC RFC 6238 test seed. NOT a real secret — that is the whole point.
const RFC_SEED_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const VAULT = "pinvault";

// ⭐ The fixed known answer BOTH implementations hardcode. Rust asserts it in
// cli/src/lib.rs::safety_number_known_answer; JS asserts it here. If the two ever
// disagree, two people comparing digits across clients would wrongly conclude
// they were under attack.
const SAFETY_NUMBER_KAT = "83791 28129 67801 50284 55242 77845";

let sigild = null;
let proxy = null;
try {
  // =====================================================================
  // 0. A REAL sigild, and in front of it a MALICIOUS-SERVER PROXY.
  // =====================================================================
  const port = await freePort();
  const proxyPort = await freePort();
  const direct = `http://127.0.0.1:${port}`;
  const base = `http://127.0.0.1:${proxyPort}`; // what the CLIENTS talk to
  console.log(`starting sigild on ${direct} (dev-ops + DEVICE AUTH v3, in-memory) ...`);
  const logFd = (await import("node:fs")).openSync(logPath, "w");
  sigild = spawn(sigildBin, [], {
    env: {
      ...process.env,
      SIGILD_ADDR: `127.0.0.1:${port}`,
      SIGILD_ENABLE_DEV_OPS: "1",
      SIGILD_DEVICE_AUTH: "1",
      SIGILD_ENROLL_TOKENS: `${TOKEN_A},${TOKEN_B},${TOKEN_C},${TOKEN_JS}`,
      SIGILD_ADMIN_TOKEN: ADMIN_TOKEN,
    },
    stdio: ["ignore", logFd, logFd],
  });
  sigild.on("error", (e) => fail(`sigild failed to spawn: ${e.message}`));
  await waitReady(direct);

  // ⭐ THE MALICIOUS SERVER. A transparent forwarding proxy that, when armed,
  // rewrites the RESPONSE BODY of `GET /v1/devices/{victim}/hybrid-key` to an
  // ATTACKER's hybrid public key. Requests are forwarded verbatim, so the
  // clients' contract-v3 signatures still verify — which is exactly the point:
  // the request is authenticated, the RESPONSE is not, and nothing in the
  // protocol binds a published hybrid key to the device that owns it. This is a
  // faithful stand-in for a hostile or compromised registry.
  //
  // It runs as its OWN PROCESS on purpose: this test drives the real `sigil`
  // binary with execFileSync, which BLOCKS the Node event loop, so an in-process
  // proxy could never answer the CLI's requests. It reads its attack config from
  // a file on every request, so the parent arms and disarms it by writing JSON.
  const attackConfig = join(work, "attack.json");
  const proxyScript = join(work, "malicious-proxy.mjs");
  writeFileSync(attackConfig, JSON.stringify({ on: false }));
  writeFileSync(
    proxyScript,
    `import http from "node:http";
import { readFileSync } from "node:fs";
const [upstreamPort, listenPort, cfgPath] = process.argv.slice(2);
function cfg() {
  try {
    return JSON.parse(readFileSync(cfgPath, "utf8"));
  } catch {
    return { on: false };
  }
}
http
  .createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const up = http.request(
        {
          hostname: "127.0.0.1",
          port: Number(upstreamPort),
          path: req.url,
          method: req.method,
          headers: { ...req.headers, host: "127.0.0.1:" + upstreamPort, connection: "close" },
        },
        (upRes) => {
          const out = [];
          upRes.on("data", (c) => out.push(c));
          upRes.on("end", () => {
            let payload = Buffer.concat(out);
            const headers = { ...upRes.headers };
            const a = cfg();
            if (
              a.on &&
              req.method === "GET" &&
              req.url === "/v1/devices/" + a.victim + "/hybrid-key" &&
              upRes.statusCode === 200
            ) {
              payload = Buffer.from(
                JSON.stringify({
                  device_id: a.victim,
                  x25519_public_key: a.x25519,
                  mlkem_encaps_key: a.mlkem,
                  updated_at: new Date().toISOString(),
                }),
              );
              headers["content-length"] = String(payload.length);
              delete headers["transfer-encoding"];
            }
            // ⭐ PHASE 60. A key-substituting server that ONLY swaps the hybrid
            // key achieves nothing now: the envelope still authenticates to the
            // REAL sender, so the AEAD refuses it. The attack that actually
            // works is to swap the key AND deposit an envelope minted under it —
            // so the proxy must be able to rewrite the envelope body too, or the
            // unwrap-gate test would "pass" for the wrong reason.
            if (
              a.on &&
              a.envelopePath &&
              req.method === "GET" &&
              req.url === a.envelopePath &&
              upRes.statusCode === 200
            ) {
              payload = Buffer.from(a.envelopeB64, "base64");
              headers["content-type"] = "application/octet-stream";
              headers["content-length"] = String(payload.length);
              delete headers["transfer-encoding"];
            }
            // No keep-alive through the proxy: this test blocks the Node event
            // loop for seconds at a time running the real CLI (execFileSync), so
            // a pooled idle socket would go stale and the next fetch would fail
            // for reasons that have nothing to do with what is being proven.
            delete headers["keep-alive"];
            headers["connection"] = "close";
            res.writeHead(upRes.statusCode, headers);
            res.end(payload);
          });
        },
      );
      up.on("error", () => {
        res.writeHead(502);
        res.end("proxy upstream error");
      });
      up.end(Buffer.concat(chunks));
    });
  })
  .listen(Number(listenPort), "127.0.0.1");
`,
  );
  proxy = spawn(process.execPath, [proxyScript, String(port), String(proxyPort), attackConfig], {
    stdio: ["ignore", "inherit", "inherit"],
  });
  /** Arm or disarm the malicious server. */
  function setAttack(next) {
    writeFileSync(attackConfig, JSON.stringify(next));
  }
  await waitReady(base);
  console.log(`malicious-server proxy listening on ${base} -> ${direct} (attack DISARMED)\n`);

  // Each CLI device gets its OWN HOME: a separate machine, in effect, with its
  // own identity, hybrid identity, keyring AND pin store.
  const homes = {};
  for (const name of ["A", "B", "C"]) {
    homes[name] = join(work, `device-${name}`);
    mkdirSync(homes[name], { recursive: true });
  }
  /** Run the REAL sigil binary as one of the CLI devices; returns stdout. */
  function sigil(who, args, extraEnv = {}) {
    return execFileSync(sigilBin, args, {
      encoding: "utf8",
      env: {
        ...toolEnv,
        HOME: homes[who],
        SIGIL_SERVER: base,
        SIGIL_DEVICE_KEY: join(homes[who], ".sigil", "device.key"),
        SIGIL_PASSWORD: PASSWORD,
        ...extraEnv,
      },
    });
  }
  /** Run the CLI expecting FAILURE; returns the combined stderr+stdout. */
  function sigilFails(who, args, what, extraEnv = {}) {
    try {
      sigil(who, args, extraEnv);
    } catch (e) {
      return `${e.stderr ?? ""}${e.stdout ?? ""}`;
    }
    fail(`${what}: the command SUCCEEDED but must have failed`);
    return "";
  }

  // =====================================================================
  // 1. Enroll A, B, C (CLI) and one JS device; publish hybrid keys.
  // =====================================================================
  const ids = {};
  for (const [who, token] of [
    ["A", TOKEN_A],
    ["B", TOKEN_B],
    ["C", TOKEN_C],
  ]) {
    const out = sigil(who, ["device", "enroll", "--token", token, "--label", who]);
    ids[who] = (out.match(/dev_[A-Za-z0-9_-]+/) ?? [])[0];
    assert(ids[who], `could not parse device id for ${who} from: ${out}`);
    sigil(who, ["device", "hybrid-publish"]);
  }
  const seedJs = generateDeviceSeed();
  const devJs = await enrollDevice(wasm, {
    baseUrl: direct,
    token: TOKEN_JS,
    label: "browser-js",
    seed: seedJs,
  });
  const hybridJs = generateHybridIdentity();
  const authJs = {
    baseUrl: direct,
    deviceId: devJs.deviceId,
    seed: seedJs,
    hybrid: hybridJs,
    pins: newPinStore(),
    // ⭐ PHASE 60 SYMMETRY: `acceptVault`'s never-silently-replace check reads the
    // keys this client already holds, and FAILS CLOSED like `pins`. Section 7
    // overrides it per call.
    vaultKeys: {},
  };
  await publishHybridKey(wasm, authJs, hybridJs);
  console.log(`  (1) OK: enrolled A=${ids.A} B=${ids.B} C=${ids.C} JS=${devJs.deviceId}`);

  // =====================================================================
  // 2. CLAIM B — the SAFETY NUMBER is byte-identical in Rust and JS.
  // =====================================================================

  // 2a. The fixed KAT both implementations hardcode. Build the same fixture the
  //     Rust test builds: x25519[i] = i, mlkem[i] = (7i + 11) mod 256.
  const katX = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) katX[i] = i;
  const katM = new Uint8Array(1184);
  for (let i = 0; i < 1184; i += 1) katM[i] = (i * 7 + 11) % 256;
  const katJs = await safetyNumber("dev_KAT", {
    x25519PublicKey: katX,
    mlkemEncapsKey: katM,
  });
  assert(
    katJs === SAFETY_NUMBER_KAT,
    `JS safety-number KAT = "${katJs}", want "${SAFETY_NUMBER_KAT}" (Rust asserts the same string)`,
  );
  const katGroups = katJs.split(" ");
  assert(
    katGroups.length === SAFETY_NUMBER_GROUPS && katGroups.every((g) => /^\d{5}$/.test(g)),
    `safety number shape wrong: "${katJs}"`,
  );

  // 2b. ⭐ LIVE AGREEMENT: the real `sigil` binary and this JS module compute the
  //     SAME number for the SAME published key.
  const bOwn = sigil("B", ["device", "safety-number"]);
  // Six space-separated 5-digit groups, wherever they appear in the output.
  const grabNumber = (text) => (text.match(/\d{5}(?: \d{5}){5}/) ?? [])[0];
  const bNumberRust = grabNumber(bOwn);
  assert(bNumberRust, `could not parse B's own safety number from:\n${bOwn}`);
  const bKey = await fetchHybridKey(wasm, authJs, ids.B);
  const bNumberJs = await safetyNumber(ids.B, bKey);
  assert(
    bNumberRust === bNumberJs,
    `RUST vs JS safety number DISAGREE for ${ids.B}: rust="${bNumberRust}" js="${bNumberJs}"`,
  );

  // 2c. A DIFFERENT key gives a DIFFERENT number.
  const aKey = await fetchHybridKey(wasm, authJs, ids.A);
  const aNumberJs = await safetyNumber(ids.A, aKey);
  assert(aNumberJs !== bNumberJs, "two different devices produced the SAME safety number");

  // 2d. The PAIRWISE number is order-independent — and both clients agree.
  const pairFromA = sigil("A", ["device", "safety-number", "--pair", ids.B]);
  const pairFromB = sigil("B", ["device", "safety-number", "--pair", ids.A]);
  const pairA = grabNumber(pairFromA);
  const pairB = grabNumber(pairFromB);
  assert(pairA && pairB, "could not parse the pairwise safety numbers");
  assert(pairA === pairB, `pairwise number is NOT order-independent: A saw ${pairA}, B saw ${pairB}`);
  const pairJs = await pairwiseSafetyNumber(
    { deviceId: ids.A, identity: aKey },
    { deviceId: ids.B, identity: bKey },
  );
  const pairJsSwapped = await pairwiseSafetyNumber(
    { deviceId: ids.B, identity: bKey },
    { deviceId: ids.A, identity: aKey },
  );
  assert(pairJs === pairJsSwapped, "JS pairwise number is not order-independent");
  assert(pairJs === pairA, `RUST vs JS pairwise DISAGREE: rust="${pairA}" js="${pairJs}"`);
  console.log(
    `  (2) OK: safety numbers AGREE across Rust and JS\n` +
      `        B    = ${bNumberJs}   (rust == js)\n` +
      `        A    = ${aNumberJs}   (different key -> different number)\n` +
      `        A<->B pairwise = ${pairJs}   (identical from both sides, rust == js)`,
  );

  // =====================================================================
  // 3. A creates a SHARED vault and shares it to B and C. First sight pins.
  // =====================================================================
  const vaultFile = join(homes.A, "vault.sigil");
  sigil("A", ["totp", "add", "work", "--secret", RFC_SEED_B32, "--vault", vaultFile]);
  sigil("A", ["vault", "rekey", "--vault", VAULT, "--file", vaultFile, "--publish"]);
  sigil("A", ["push", "--vault", VAULT, "--in", vaultFile]);

  const envHonest = join(work, "envelope-B-honest.bin");
  const shareOut = sigil("A", [
    "vault",
    "share",
    "--vault",
    VAULT,
    "--to",
    ids.B,
    "--permission",
    "read",
  ]);
  assert(
    // The CLI now reports the WRAP GATE's verdict rather than the raw pin
    // status, so the wording changed with the gate (RecipientTrust::label).
    shareOut.includes("FIRST SIGHT — NOT verified out of band (pinned now)"),
    `the first share should PIN B's key on first sight; got:\n${shareOut}`,
  );
  sigil("A", ["vault", "share", "--vault", VAULT, "--to", ids.C, "--permission", "read"]);
  // A second share to B must report a MATCH, not another first sight.
  const shareAgain = sigil("A", ["vault", "share", "--vault", VAULT, "--to", ids.B]);
  assert(
    shareAgain.includes("matches the key this client pinned earlier"),
    `an unchanged key must proceed as a MATCH; got:\n${shareAgain}`,
  );

  // B and C accept and read the shared secret.
  const inboxB = join(homes.B, "inbox");
  const inboxC = join(homes.C, "inbox");
  // Capture the HONEST envelope exactly as the server is storing it right now —
  // AFTER the last legitimate share, so the later byte-comparison is meaningful
  // (each share re-wraps with fresh ephemeral entropy, so the bytes change on
  // every legitimate share too).
  sigil("B", ["vault", "accept", "--vault", VAULT, "--envelope-out", envHonest]);
  sigil("C", ["vault", "accept", "--vault", VAULT]);
  sigil("B", ["pull", "--vault", VAULT, "--out-dir", inboxB]);
  sigil("C", ["pull", "--vault", VAULT, "--out-dir", inboxC]);
  const pulledB = join(inboxB, VAULT, "op-1.sigil");
  const pulledC = join(inboxC, VAULT, "op-1.sigil");
  const listB = sigil("B", ["totp", "list", "--vault", pulledB, "--vault-id", VAULT]);
  assert(listB.includes("work"), `B could not read the shared vault:\n${listB}`);
  const listC = sigil("C", ["totp", "list", "--vault", pulledC, "--vault-id", VAULT]);
  assert(listC.includes("work"), `C could not read the shared vault:\n${listC}`);
  console.log(`  (3) OK: A shared ${VAULT} to B and C (keys pinned on first sight); both read it`);

  // =====================================================================
  // 4. ⭐ CLAIM A — THE ATTACK. The server substitutes a key for B.
  // =====================================================================
  const attackerHybrid = generateHybridIdentity();
  const attackerPublic = hybridPublicIdentity(wasm, attackerHybrid);
  const b64 = (u8) => Buffer.from(u8).toString("base64");
  setAttack({
    on: true,
    victim: ids.B,
    x25519: b64(attackerPublic.x25519PublicKey),
    mlkem: b64(attackerPublic.mlkemEncapsKey),
  });

  // 4a. Sanity: an AUTHENTICATED fetch through the malicious server now returns
  //     the ATTACKER's key, not B's. This is the substitution, observed.
  const authViaProxy = { ...authJs, baseUrl: base };
  const servedUnderAttack = await fetchHybridKey(wasm, authViaProxy, ids.B);
  const servedNumber = await safetyNumber(ids.B, servedUnderAttack);
  assert(
    servedNumber !== bNumberJs,
    "the malicious proxy is NOT actually substituting — the test would prove nothing",
  );

  // 4b. ⭐ THE CLI REFUSES. `sigil vault share --to B` must fail loudly.
  const refusal = sigilFails(
    "A",
    ["vault", "share", "--vault", VAULT, "--to", ids.B],
    "the substituted-key share",
  );
  assert(
    refusal.includes("REFUSING TO SHARE"),
    `the refusal must be loud and specific; got:\n${refusal}`,
  );
  assert(refusal.includes(ids.B), `the refusal must NAME the device ${ids.B}; got:\n${refusal}`);
  assert(
    refusal.includes("KEY-SUBSTITUTION ATTACK"),
    `the refusal must say what this might be; got:\n${refusal}`,
  );
  assert(
    refusal.includes("LEGITIMATE") && refusal.includes("RE-ENROLMENT"),
    `the refusal must also admit the benign explanation; got:\n${refusal}`,
  );
  assert(refusal.includes("repin"), `the refusal must say how to proceed deliberately`);
  assert(
    refusal.includes(bNumberJs),
    `the refusal must show the PINNED safety number so a human can compare`,
  );

  // 4c. ⭐ THE PART THAT MATTERS: the vault key was NOT wrapped to the attacker.
  //     The envelope sitting in B's mailbox is byte-identical to the honest one,
  //     and the attacker's hybrid secret cannot open it.
  const envAfter = join(work, "envelope-B-after-attack.bin");
  sigil("B", ["vault", "accept", "--vault", VAULT, "--envelope-out", envAfter]);
  const honestBytes = new Uint8Array(readFileSync(envHonest));
  const afterBytes = new Uint8Array(readFileSync(envAfter));
  assert(
    bytesEqual(honestBytes, afterBytes),
    "the stored envelope CHANGED during the refused share — something was uploaded!",
  );
  let attackerOpened = false;
  try {
    wasm.hybrid_open_container(
      attackerHybrid.x25519Secret,
      attackerHybrid.mlkemSeed,
      afterBytes,
    );
    attackerOpened = true;
  } catch {
    /* expected: the envelope was never sealed to the attacker */
  }
  assert(!attackerOpened, "⚠️ THE ATTACKER OPENED THE ENVELOPE — the vault key leaked");

  // 4d. ⭐ THE BROWSER CLIENT REFUSES TOO, with the catchable typed error.
  //     The JS device pins B's real key against the honest server, then tries to
  //     share through the lying proxy.
  //
  //     ⭐ The pin is established through THE REAL WRAP GATE
  //     (verifyRecipientForWrap), not through a convenience wrapper that no
  //     product path uses — the superseded fetchHybridKeyPinned was deleted in
  //     Phase 57 precisely because a test-only choke point proves nothing about
  //     the choke point the product actually goes through.
  const authJsPinned = { ...authJs, baseUrl: direct, pins: newPinStore() };
  const firstSight = await verifyRecipientForWrap(wasm, authJsPinned, ids.B);
  assert(
    firstSight.safetyNumber === bNumberJs,
    "the wrap gate must pin the HONEST key on first sight",
  );
  const authJsProxied = { ...authJsPinned, baseUrl: base };
  let jsRefused = null;
  try {
    await shareVault(wasm, authJsProxied, {
      vaultId: `js-${VAULT}`,
      recipientDeviceId: ids.B,
      vaultKey: generateVaultKey(),
    });
  } catch (e) {
    jsRefused = e;
  }
  assert(
    jsRefused instanceof KeyPinMismatchError,
    `the JS client must throw KeyPinMismatchError; got ${jsRefused && jsRefused.name}`,
  );
  assert(jsRefused.deviceId === ids.B, "KeyPinMismatchError must carry the device id");
  assert(
    jsRefused.pinnedSafetyNumber === bNumberJs,
    "KeyPinMismatchError must carry the PINNED safety number",
  );
  assert(
    jsRefused.presentedSafetyNumber !== bNumberJs,
    "KeyPinMismatchError must carry the PRESENTED (different) safety number",
  );
  // And the attacker's key was NOT pinned by the failed attempt.
  const stillPinned = authJsPinned.pins.pins[ids.B].safety_number;
  assert(stillPinned === bNumberJs, "a failed check must NOT re-pin — the store was mutated");

  // 4e. ⭐ requirePinStore FAILS CLOSED — with an assertion, not a comment.
  //     This control has already degraded into a no-op once: it used to return
  //     a fresh empty store for null/undefined, so a caller that forgot its pins
  //     silently got "every key is first-sight" and pinning stopped protecting
  //     anything. Nothing in the tree asserted the throw, and an auditor reverted
  //     it to the fail-OPEN version with every suite still green. So: assert it
  //     directly, AND assert that a real WRAP PATH refuses rather than proceeds.
  for (const absent of [null, undefined]) {
    let threw = null;
    try {
      requirePinStore(absent);
    } catch (e) {
      threw = e;
    }
    assert(
      threw !== null,
      `requirePinStore(${absent}) MUST THROW — a missing pin store must never ` +
        `default to empty, which silently turns every key into a first sight`,
    );
    assert(
      /pin store is required/i.test(threw.message),
      `requirePinStore(${absent}) threw the wrong error: ${threw.message}`,
    );
  }
  // The wrap path itself must refuse, not proceed to an unpinned first sight.
  for (const [what, brokenAuth] of [
    ["no pins at all", { ...authJs, baseUrl: direct, pins: null }],
    ["undefined pins", { ...authJs, baseUrl: direct, pins: undefined }],
  ]) {
    let wrapThrew = null;
    try {
      await shareVault(wasm, brokenAuth, {
        vaultId: `js-nopins-${VAULT}`,
        recipientDeviceId: ids.B,
        vaultKey: generateVaultKey(),
      });
    } catch (e) {
      wrapThrew = e;
    }
    assert(
      wrapThrew !== null && /pin store is required/i.test(wrapThrew.message),
      `shareVault with ${what} MUST REFUSE (got ${wrapThrew && wrapThrew.message}) — ` +
        `a wrap with no pin store is an unpinned first sight, i.e. the control is off`,
    );
  }
  // ...and verifyRecipientForWrap, the gate every wrap goes through, refuses too.
  {
    let gateThrew = null;
    try {
      await verifyRecipientForWrap(wasm, { ...authJs, baseUrl: direct, pins: null }, ids.B);
    } catch (e) {
      gateThrew = e;
    }
    assert(
      gateThrew !== null && /pin store is required/i.test(gateThrew.message),
      `verifyRecipientForWrap with no pin store MUST REFUSE; got ${gateThrew && gateThrew.message}`,
    );
  }
  console.log(
    "  (4e) OK: requirePinStore FAILS CLOSED — null/undefined throw, and shareVault +\n" +
      "        verifyRecipientForWrap refuse rather than falling back to an empty store",
  );

  setAttack({ on: false });
  console.log(
    `  (4) OK: ⭐ KEY-SUBSTITUTION ATTACK DETECTED AND BLOCKED\n` +
      `        malicious server served ${jsRefused.presentedSafetyNumber} for ${ids.B}\n` +
      `        clients had pinned    ${bNumberJs}\n` +
      `        CLI refused, browser threw KeyPinMismatchError, the stored envelope is\n` +
      `        BYTE-IDENTICAL to the honest one, and the attacker's hybrid secret CANNOT open it`,
  );

  // =====================================================================
  // 5. ⭐ CLAIM C — ROTATION. Revoke B, rotate to [A, C], prove the split.
  // =====================================================================
  // Keep a copy of the vault B could read BEFORE the rotation, and B's old key
  // stays in B's keyring untouched — that is the honest adversary model.
  const preRotationList = sigil("B", ["totp", "list", "--vault", pulledB, "--vault-id", VAULT]);
  assert(preRotationList.includes("work"), "B should read the pre-rotation vault");

  sigil("A", ["device", "revoke", ids.B, "--admin-token", ADMIN_TOKEN]);

  // Phase 54: a rotation that would silently delete a current holder's envelope
  // is REFUSED. B is the device being rotated away from, so dropping it has to
  // be stated — that is the whole point of the guard.
  let refusedRotate = "";
  try {
    sigil("A", ["vault", "rotate", "--vault", VAULT, "--to", ids.A, "--to", ids.C, "--file", vaultFile]);
  } catch (err) {
    refusedRotate = `${err.stdout ?? ""}${err.stderr ?? ""}${err.message ?? ""}`;
  }
  assert(
    refusedRotate.includes("REFUSING TO ROTATE") && refusedRotate.includes(ids.B),
    `a rotation that would silently drop ${ids.B} must be refused; got:\n${refusedRotate}`,
  );

  const rotateOut = sigil("A", [
    "vault",
    "rotate",
    "--vault",
    VAULT,
    "--to",
    ids.A,
    "--to",
    ids.C,
    "--drop",
    ids.B,
    "--file",
    vaultFile,
  ]);
  assert(rotateOut.includes("rotated vault"), `rotate failed:\n${rotateOut}`);
  assert(
    rotateOut.includes(`removed:     ${ids.B}`),
    `rotation must DELETE B's stale envelope; got:\n${rotateOut}`,
  );
  assert(
    rotateOut.includes(`re-wrapped:  ${ids.C}`) && rotateOut.includes(`re-wrapped:  ${ids.A}`),
    `rotation must re-wrap to A and C; got:\n${rotateOut}`,
  );
  const [, oldFp, newFp] = rotateOut.match(/old key:\s+sha256 ([0-9a-f]+)[\s\S]*?new key:\s+sha256 ([0-9a-f]+)/);
  assert(oldFp !== newFp, "rotation did not actually change the vault key");

  // A adds a NEW secret AFTER the rotation and pushes it.
  sigil("A", [
    "totp",
    "add",
    "post-rotation",
    "--secret",
    RFC_SEED_B32,
    "--vault",
    vaultFile,
    "--vault-id",
    VAULT,
  ]);
  sigil("A", ["push", "--vault", VAULT, "--in", vaultFile]);

  // C — still authorized — re-accepts the NEW key, pulls, and reads the new secret.
  // ⭐ `--replace` is REQUIRED from Phase 60 on: C already holds the PRE-rotation
  // key, and accepting a DIFFERENT one for a vault you already hold is exactly
  // how a hostile deposit would take a vault away from a device that had it. The
  // refusal is the default; overwriting must be stated.
  sigil("C", ["vault", "accept", "--vault", VAULT, "--replace"]);
  sigil("C", ["pull", "--vault", VAULT, "--out-dir", inboxC]);
  // The pull is INCREMENTAL, so take the highest op-N C has ever pulled rather
  // than assuming a sequence number.
  const opsDir = join(inboxC, VAULT);
  const latestOp = readdirSync(opsDir)
    .filter((f) => /^op-\d+\.sigil$/.test(f))
    .sort((a, b) => Number(a.match(/\d+/)[0]) - Number(b.match(/\d+/)[0]))
    .pop();
  assert(latestOp, `expected C to have pulled a post-rotation op into ${opsDir}`);
  const rotatedForC = join(opsDir, latestOp);
  const listCafter = sigil("C", ["totp", "list", "--vault", rotatedForC, "--vault-id", VAULT]);
  assert(
    listCafter.includes("post-rotation"),
    `still-authorized C must read the NEW secret; got:\n${listCafter}`,
  );

  // ⭐ B — revoked and rotated away — CANNOT read it, even holding the ciphertext
  //    and its OLD vault key.
  const rotatedForB = join(homes.B, "rotated.sigil");
  copyFileSync(rotatedForC, rotatedForB);
  const bDenied = sigilFails(
    "B",
    ["totp", "list", "--vault", rotatedForB, "--vault-id", VAULT],
    "B reading the rotated vault with its OLD key",
  );
  assert(
    !bDenied.includes("post-rotation"),
    "⚠️ B READ THE POST-ROTATION CONTENT with its old key",
  );

  // B's envelope really is gone from the server (checked from A, the owner).
  const envelopesAfter = sigil("A", ["vault", "list"]);
  void envelopesAfter;
  const listAfter = await (async () => {
    // Use the JS transport as an independent reader of the server's own view.
    const { listKeyEnvelopes } = await import("../sharing.mjs");
    // A's identity is a CLI file; read the seed to sign as A.
    const idFile = JSON.parse(readFileSync(join(homes.A, ".sigil", "device.key"), "utf8"));
    const authA = {
      baseUrl: direct,
      deviceId: idFile.device_id,
      seed: new Uint8Array(Buffer.from(idFile.seed, "base64")),
      pins: newPinStore(),
    };
    return listKeyEnvelopes(wasm, authA, VAULT);
  })();
  const holders = listAfter.map((r) => r.deviceId).sort();
  assert(
    !holders.includes(ids.B),
    `B still holds an envelope after the rotation: ${holders.join(", ")}`,
  );
  assert(
    holders.includes(ids.A) && holders.includes(ids.C),
    `A and C must still hold envelopes; got ${holders.join(", ")}`,
  );
  console.log(
    `  (5) OK: ⭐ ROTATION — vault key ${oldFp} -> ${newFp}\n` +
      `        C (authorized) READ the post-rotation secret; B (revoked) could NOT,\n` +
      `        and B's envelope was deleted (holders now: ${holders.join(", ")})\n` +
      `        HONEST LIMIT: B still has everything it read BEFORE the rotation`,
  );

  // =====================================================================
  // 6. The deliberate escape hatch: a LEGITIMATE re-enrolment also alarms,
  //    and only an explicit, verified re-pin clears it.
  // =====================================================================
  sigil("C", ["device", "hybrid-publish", "--regenerate"]);
  const benignRefusal = sigilFails(
    "A",
    ["vault", "share", "--vault", VAULT, "--to", ids.C],
    "sharing to a legitimately re-enrolled device",
  );
  assert(
    benignRefusal.includes("REFUSING TO SHARE"),
    "a legitimate key change must ALSO be refused — the client cannot tell them apart",
  );

  // A re-pin without --yes is refused outright.
  const noYes = sigilFails("A", ["device", "repin", ids.C], "repin without --yes");
  assert(noYes.includes("--yes"), `repin must require an explicit acknowledgement:\n${noYes}`);

  // A re-pin with the WRONG safety number is refused.
  const wrongNumber = sigilFails(
    "A",
    ["device", "repin", ids.C, "--yes", "--safety-number", "00000 00000 00000 00000 00000 00000"],
    "repin with a wrong safety number",
  );
  assert(
    wrongNumber.includes("does not match"),
    `a mistyped safety number must refuse:\n${wrongNumber}`,
  );

  // The RIGHT number — read out of band, here computed independently in JS.
  const cKeyNew = await fetchHybridKey(wasm, authJs, ids.C);
  const cNumberNew = await safetyNumber(ids.C, cKeyNew);
  const repinOut = sigil("A", [
    "device",
    "repin",
    ids.C,
    "--yes",
    "--safety-number",
    cNumberNew,
  ]);
  assert(repinOut.includes("RE-PINNED"), `the deliberate re-pin should succeed:\n${repinOut}`);
  const shareAfterRepin = sigil("A", ["vault", "share", "--vault", VAULT, "--to", ids.C]);
  assert(
    shareAfterRepin.includes("matches the key this client pinned earlier"),
    `after a deliberate re-pin the share must proceed:\n${shareAfterRepin}`,
  );
  const pinsOut = sigil("A", ["device", "pins"]);
  assert(
    pinsOut.includes("re-pinned 1 time(s)"),
    `the pin store must record that a human accepted a key change:\n${pinsOut}`,
  );

  // The pure-JS pin store behaves identically.
  const store = newPinStore();
  assert((await checkAndPin(store, ids.C, cKeyNew)).status === "first-sight", "JS first sight");
  assert((await checkAndPin(store, ids.C, cKeyNew)).status === "match", "JS unchanged -> match");
  let jsThrew = false;
  try {
    await checkAndPin(store, ids.C, aKey);
  } catch (e) {
    jsThrew = e instanceof KeyPinMismatchError;
  }
  assert(jsThrew, "JS checkAndPin must throw KeyPinMismatchError on a changed key");
  assert(
    store.pins[ids.C].safety_number === cNumberNew,
    "a failed JS check must not mutate the pin store",
  );
  const repinned = await repinHybridKey(store, ids.C, aKey);
  assert(repinned.repins === 1 && repinned.previousSafetyNumber === cNumberNew, "JS repin bookkeeping");
  console.log(
    `  (6) OK: a LEGITIMATE re-enrolment alarms too; repin needs --yes AND the right\n` +
      `        safety number; the pin store records the re-pin (Rust and JS agree)`,
  );

  // =====================================================================
  // 7. ⭐⭐ PHASE 60 — THE UNWRAP GATE, i.e. the RECEIVING side.
  // =====================================================================
  //
  // Sections 1-6 prove the WRAP side: this client will not hand a vault key to
  // a substituted recipient key. That is only half the problem, and until Phase
  // 60 the other half was undefended — `acceptVault` fetched NO hybrid key at
  // all, so the pin store was never consulted when a key ARRIVED. Anyone
  // holding the recipient's PUBLISHED public key could mint an envelope and
  // install a vault key of their choosing.
  //
  // ⚠️ AND THE FIX HAD NO TEST. Deleting the safety-number comparison and the
  // `checkAndPin` call from `verifySenderForUnwrap` left every suite in this
  // repository green, while a rewriting proxy installed a hostile key in the
  // victim's keyring. So this section drives the REAL `acceptVault` — the
  // function the webapp and the extension call — against the SAME malicious
  // proxy, and it must go RED if either half of that gate is removed.
  //
  // The attack modelled here is the strong one: the server swaps the SENDER's
  // published hybrid key AND replaces the deposited envelope with one minted
  // under it. Swapping only the key achieves nothing (the AEAD refuses), which
  // is why the proxy learned to rewrite envelope bodies above.
  {
    const jsRecipientPub = hybridPublicIdentity(wasm, hybridJs);
    const authJsDirect = { ...authJs, baseUrl: direct };

    // A shares the (post-rotation) vault to the JS device, so there is a real
    // envelope, deposited by a real sender, sitting in a real mailbox.
    sigil("A", [
      "vault",
      "share",
      "--vault",
      VAULT,
      "--to",
      devJs.deviceId,
      "--permission",
      "read",
    ]);

    // --- 7a. FIRST SIGHT: pinned, reported as unverified, and ACCEPTED. -----
    // ⚠️ THE RESIDUAL LIMIT, ASSERTED SO IT CANNOT SILENTLY INVERT. ADR 0038's
    // accepted trust-on-first-use applies to the unwrap side too: a sender this
    // client has never seen is PINNED and the accept PROCEEDS, with the trust
    // level saying plainly that nothing was verified out of band. A build that
    // refused first contact and waved changes through would be worse than
    // useless, and neither half alone would notice the swap.
    const pinsAfterFirstSight = newPinStore();
    const firstAccept = await acceptVault(
      wasm,
      { ...authJsDirect, pins: pinsAfterFirstSight },
      { vaultId: VAULT, senderDeviceId: ids.A },
    );
    assert(
      firstAccept.senderTrust === TRUST_UNVERIFIED_FIRST_SIGHT,
      `first sight of a SENDER must be reported as unverified first sight, got ` +
        `${firstAccept.senderTrust}`,
    );
    assert(
      firstAccept.senderSafetyNumber === aNumberJs,
      "the accept must report the SENDER's safety number so a human can compare it",
    );
    assert(firstAccept.vaultKey.length === 32, "the recovered vault key must be 32 bytes");
    assert(
      pinsAfterFirstSight.pins[ids.A]?.safety_number === aNumberJs,
      "⚠️ FIRST SIGHT DID NOT PIN THE SENDER — every later key change would then be " +
        "a first sight too, and the unwrap gate could never fire",
    );

    // POSITIVE CONTROL: the key an honest accept produced really opens the
    // vault. Without this, "everything is refused" would read as a pass.
    const pulled = await pullContainersAuthed(
      wasm,
      { deviceId: devJs.deviceId, seed: seedJs },
      direct,
      VAULT,
      0,
    );
    assert(pulled.length > 0, "expected the shared vault to have at least one op");
    const openedByJs = Buffer.from(
      wasm.open_container(firstAccept.vaultKey, pulled[pulled.length - 1].container),
    ).toString("utf8");
    assert(
      openedByJs.includes("post-rotation"),
      "the accepted key must actually OPEN the vault — otherwise the refusals below " +
        "prove nothing",
    );

    // --- 7b. A WRONG SUPPLIED SAFETY NUMBER IS A HARD STOP, pinning nothing. -
    const pinsUnused = newPinStore();
    let numberRefusal = null;
    try {
      await acceptVault(
        wasm,
        { ...authJsDirect, pins: pinsUnused },
        {
          vaultId: VAULT,
          senderDeviceId: ids.A,
          expectedSafetyNumber: "00000 00000 00000 00000 00000 00000",
        },
      );
    } catch (e) {
      numberRefusal = e;
    }
    assert(
      numberRefusal instanceof SafetyNumberMismatchError,
      `⚠️ THE SAFETY-NUMBER CHECK DID NOT FIRE on the unwrap side; got ` +
        `${numberRefusal && numberRefusal.name}`,
    );
    assert(
      Object.keys(pinsUnused.pins).length === 0,
      "a REFUSED key must not be pinned — pinning it would let the retry report a " +
        "Match and the alarm would never fire again",
    );

    // --- 7c. ⭐⭐ THE ATTACK. Substituted sender key + forged envelope. ------
    const impostorHybrid = generateHybridIdentity();
    const impostorPublic = hybridPublicIdentity(wasm, impostorHybrid);
    const attackerChosenKey = generateVaultKey();
    // The attacker mints an envelope AS device A, under ITS OWN keys, with the
    // CORRECT context — so the only lie is the key the server serves.
    const forgedEnvelope = wrapVaultKey(
      wasm,
      { deviceId: ids.A, hybrid: impostorHybrid },
      jsRecipientPub,
      { vaultId: VAULT, recipientDeviceId: devJs.deviceId, senderDeviceId: ids.A },
      attackerChosenKey,
    );
    setAttack({
      on: true,
      victim: ids.A, // whose PUBLISHED key gets swapped
      x25519: b64(impostorPublic.x25519PublicKey),
      mlkem: b64(impostorPublic.mlkemEncapsKey),
      envelopePath: `/v1/vaults/${VAULT}/keys/${devJs.deviceId}`,
      envelopeB64: Buffer.from(forgedEnvelope).toString("base64"),
    });

    const authJsProxy = { ...authJs, baseUrl: base };
    // Sanity: the substitution is actually happening.
    const servedA = await fetchHybridKey(wasm, authJsProxy, ids.A);
    assert(
      (await safetyNumber(ids.A, servedA)) !== aNumberJs,
      "the malicious proxy is NOT substituting the sender's key — the test would " +
        "prove nothing",
    );

    // ⚠️ THE HONEST CONTROL, and the residual limit in one assertion: at the
    // CRYPTOGRAPHIC layer, with an EMPTY pin store, the attack SUCCEEDS. First
    // contact cannot be protected by pinning alone (ADR 0038), and stating it
    // here proves the refusals below are the gates doing the work rather than
    // some unrelated failure.
    const virginPins = newPinStore();
    const swappedSender = await verifySenderForUnwrap(wasm, authJsProxy, ids.A, {
      pins: virginPins,
    });
    const tofuKey = unwrapVaultKey(
      wasm,
      hybridJs,
      swappedSender,
      { vaultId: VAULT, recipientDeviceId: devJs.deviceId, senderDeviceId: ids.A },
      forgedEnvelope,
    );
    assert(
      bytesEqual(tofuKey, attackerChosenKey),
      "the attack is not actually live — an unwrap with NO pin should have yielded the " +
        "attacker's key, so the refusals below would prove nothing",
    );

    // --- 7d. ⭐⭐ STEP 4: OPEN BEFORE RETURNING — DEFENCE IN DEPTH. -----------
    // The attacker's key is a valid 32-byte key that AUTHENTICATES perfectly
    // (the sender's key was swapped, so the AEAD is happy) and that a virgin pin
    // store has no reason to doubt. What it cannot do is OPEN THE VAULT. Until
    // Phase 60's symmetry fix, the browsers had no such check — `acceptVault`
    // went straight from unwrap to return, and the webapp and the extension
    // sealed the attacker's key into their device identity, DISPLACING the real
    // one. This is the first-contact case pinning provably cannot catch, so the
    // fact that step 4 catches it is the whole point of mirroring the CLI.
    let openRefusal = null;
    try {
      await acceptVault(
        wasm,
        { ...authJsProxy, pins: newPinStore() },
        { vaultId: VAULT, senderDeviceId: ids.A, heldKeys: {} },
      );
    } catch (e) {
      openRefusal = e;
    }
    assert(
      openRefusal instanceof VaultKeyDoesNotOpenError,
      `⚠️ STEP 4 DID NOT FIRE — a key that opens NOTHING was returned to be persisted, ` +
        `on the exact first-contact path pinning cannot protect. Got ` +
        `${openRefusal && openRefusal.name}`,
    );
    assert(
      openRefusal.vaultId === VAULT,
      "VaultKeyDoesNotOpenError must name the vault so a UI can say which one",
    );

    // ⭐ AND WITH THE SENDER PINNED, IT IS A HARD STOP.
    let unwrapRefusal = null;
    try {
      await acceptVault(
        wasm,
        { ...authJsProxy, pins: pinsAfterFirstSight },
        { vaultId: VAULT, senderDeviceId: ids.A },
      );
    } catch (e) {
      unwrapRefusal = e;
    }
    assert(
      unwrapRefusal instanceof KeyPinMismatchError,
      `⚠️ THE UNWRAP GATE DID NOT FIRE — a substituted sender key installed an ` +
        `attacker-chosen vault key. Got ${unwrapRefusal && unwrapRefusal.name}`,
    );
    assert(
      unwrapRefusal.deviceId === ids.A &&
        unwrapRefusal.pinnedSafetyNumber === aNumberJs &&
        unwrapRefusal.presentedSafetyNumber !== aNumberJs,
      "KeyPinMismatchError must carry the device and BOTH safety numbers so the UI " +
        "can show a human what changed",
    );
    assert(
      pinsAfterFirstSight.pins[ids.A].safety_number === aNumberJs,
      "a refused unwrap must NOT re-pin — a retry would then see a Match",
    );

    setAttack({ on: false });

    // --- 7e. ⭐⭐ STEP 5: NEVER SILENTLY REPLACE. -----------------------------
    // With the attack off, the genuine envelope unwraps to the genuine key. The
    // question this step answers is what happens when the client ALREADY HOLDS a
    // key for that vault. Until Phase 60's symmetry fix the browsers overwrote
    // it unconditionally (`vaultKeys: { ...device.vaultKeys, [id]: accepted }`),
    // so a deposit nobody asked for could take a vault away from the only device
    // that could still open it — the old key is the only thing that opens
    // everything sealed under it, and this client may hold the last copy.
    const realKey = firstAccept.vaultKey;
    const strandedKey = generateVaultKey();

    // (i) A DIFFERENT held key is a HARD STOP, and it names both fingerprints.
    let replaceRefusal = null;
    try {
      await acceptVault(
        wasm,
        { ...authJsDirect, pins: pinsAfterFirstSight },
        { vaultId: VAULT, senderDeviceId: ids.A, heldKeys: { [VAULT]: strandedKey } },
      );
    } catch (e) {
      replaceRefusal = e;
    }
    assert(
      replaceRefusal instanceof VaultKeyReplacementError,
      `⚠️ STEP 5 DID NOT FIRE — an accept silently REPLACED a different key this client ` +
        `already held. Got ${replaceRefusal && replaceRefusal.name}`,
    );
    assert(
      replaceRefusal.vaultId === VAULT &&
        replaceRefusal.heldFingerprint === (await vaultKeyFingerprint(strandedKey)) &&
        replaceRefusal.offeredFingerprint === (await vaultKeyFingerprint(realKey)),
      "VaultKeyReplacementError must carry the vault and BOTH fingerprints so a human can " +
        "see what would be swapped — without either key being printed",
    );

    // (ii) The SAME key is not a replacement at all — a re-accept is idempotent.
    const reAccept = await acceptVault(
      wasm,
      { ...authJsDirect, pins: pinsAfterFirstSight },
      { vaultId: VAULT, senderDeviceId: ids.A, heldKeys: { [VAULT]: realKey } },
    );
    assert(
      reAccept.replaced === null && bytesEqual(reAccept.vaultKey, realKey),
      "re-accepting the SAME key must not be reported as a replacement",
    );

    // (iii) The EXPLICIT opt-in is the only door, and it REPORTS what it did.
    const replaced = await acceptVault(
      wasm,
      { ...authJsDirect, pins: pinsAfterFirstSight },
      {
        vaultId: VAULT,
        senderDeviceId: ids.A,
        heldKeys: { [VAULT]: strandedKey },
        replace: true,
      },
    );
    assert(
      replaced.replaced === (await vaultKeyFingerprint(strandedKey)),
      "an opted-in replacement must report the fingerprint of the key it displaced, so a " +
        "user is told what they just lost access to",
    );

    // (iv) …and the keyring FAILS CLOSED, like the pin store. A caller that
    //      forgets it must be a loud error, never "this client holds nothing" —
    //      that silent default is precisely how a security check becomes a no-op.
    let closedRefusal = null;
    try {
      await acceptVault(
        wasm,
        { baseUrl: direct, deviceId: devJs.deviceId, seed: seedJs, hybrid: hybridJs },
        { vaultId: VAULT, senderDeviceId: ids.A, pins: pinsAfterFirstSight },
      );
    } catch (e) {
      closedRefusal = e;
    }
    assert(
      closedRefusal && /already holds/.test(closedRefusal.message),
      `⚠️ heldKeys DID NOT FAIL CLOSED — an absent keyring silently disabled step 5. ` +
        `Got ${closedRefusal && closedRefusal.message}`,
    );

    // (v) POSITIVE CONTROL: step 4 also PASSES on an honest accept, so "everything
    //     is refused" cannot read as a pass.
    assert(
      firstAccept.verifiedAgainstTip === true && firstAccept.tipContainer !== null,
      "an honest accept must report that the key was PROVED against the vault's newest op, " +
        "and hand those exact bytes back so the caller does not pull again",
    );

    console.log(
      "  (7) OK: ⭐ THE UNWRAP GATE — first sight of a SENDER pins, warns and proceeds\n" +
        "        (ADR 0038 TOFU, and at the crypto layer the substituted key IS taken);\n" +
        "        a wrong supplied safety number is refused and pins nothing; a CHANGED\n" +
        `        sender key is KeyPinMismatchError — ${unwrapRefusal.presentedSafetyNumber}\n` +
        `        served for ${ids.A}, ${aNumberJs} pinned — with the pin store unmutated;\n` +
        "        ⭐ STEP 4 refuses a key that OPENS NOTHING (the first-contact case pinning\n" +
        "        cannot catch) and STEP 5 refuses to REPLACE a different held key without an\n" +
        "        explicit opt-in, with the keyring failing CLOSED when absent",
    );
  }

  // A last belt-and-braces check that the digest itself is stable.
  const digest = await hybridSafetyDigest("dev_KAT", {
    x25519PublicKey: katX,
    mlkemEncapsKey: katM,
  });
  assert(renderSafetyNumber(digest) === SAFETY_NUMBER_KAT, "digest -> render round trip");

  console.log(
    "\nPASS — Phase 50 + Phase 60:\n" +
      "  * a MALICIOUS SERVER substituting a hybrid public key is DETECTED and BLOCKED in\n" +
      "    both the CLI and the browser client, and the vault key was never wrapped to it;\n" +
      "  * SAFETY NUMBERS are byte-identical in Rust and JS (single + order-independent\n" +
      "    pairwise), and different keys give different numbers;\n" +
      "  * ROTATION makes post-rotation content unreadable to a revoked device while a\n" +
      "    still-authorized device reads it — FUTURE content only, by design;\n" +
      "  * ⭐ THE UNWRAP GATE holds on the RECEIVING side: the real acceptVault refuses a\n" +
      "    CHANGED sender key and a wrong safety number without mutating the pin store,\n" +
      "    while first sight is honestly reported as unverified TOFU;\n" +
      "  * ⭐ AND THE JS ACCEPT IS SYMMETRIC WITH THE CLI'S FIVE STEPS: a recovered key that\n" +
      "    OPENS NOTHING is refused (VaultKeyDoesNotOpenError) — which is what catches the\n" +
      "    first-contact substitution pinning provably cannot — and one that would REPLACE a\n" +
      "    different held key needs an explicit opt-in (VaultKeyReplacementError), with the\n" +
      "    keyring failing CLOSED when a caller forgets to pass it.",
  );
} catch (e) {
  console.error(e && e.stack ? e.stack : String(e));
  if (existsSync(logPath)) {
    console.error("--- sigild log ---\n" + readFileSync(logPath, "utf8"));
  }
  process.exitCode = 1;
} finally {
  if (proxy) proxy.kill("SIGTERM");
  if (sigild) {
    sigild.kill("SIGTERM");
    await new Promise((r) => setTimeout(r, 200));
    if (!sigild.killed) sigild.kill("SIGKILL");
  }
  rmSync(work, { recursive: true, force: true });
}
