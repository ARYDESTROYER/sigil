// sync-interop.mjs — end-to-end proof that the sigil-wasm client CLOSES THE
// E2EE SYNC LOOP against a LIVE dev sigild AND the real `sigil` CLI, entirely
// through the opaque, zero-knowledge op-log.
//
// It builds sigild + the CLI, boots a real sigild on a free localhost port with
// SIGILD_ENABLE_DEV_OPS=1 (in-memory backend, NO auth), and then proves:
//
//   PROOF 1  client self-loop: wasm seal_to_container -> pushContainer -> sigild
//            -> pullContainers -> wasm open_container == original plaintext.
//   PROOF 2  CLI writes / browser reads: `sigil seal` + `sigil push` a SIGILcli
//            container into a vault, then pullContainers (JS) + wasm
//            open_container == original plaintext.
//   PROOF 3  browser writes / CLI reads: wasm seal_to_container + pushContainer
//            into a vault, then `sigil pull` + `sigil open` == original plaintext.
//   OPAQUE   after a push, GET the raw op back and confirm the stored blob
//            base64-decodes to EXACTLY the pushed bytes — the server returned
//            them verbatim and did NO crypto.
//
// The two ends use DIFFERENT crypto material per proof yet interoperate because
// the SIGILcli container is self-describing (salt + Argon2 params in the header)
// and the password is shared out-of-band. The server never sees any of it.
//
// Pre-audit / UNAUDITED / DEV / LOCALHOST / PLAIN-HTTP demo. Do not protect real
// secrets. Usage: `node test/sync-interop.mjs`. Exits 0 with a PASS line, non-zero
// on any failure. Always builds fresh sigild + CLI and always kills the server.

import { webcrypto } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import {
  existsSync,
  mkdtempSync,
  writeFileSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:net";

import { pushContainer, pullContainers } from "../sync.mjs";
import { resolveGo } from "./go-helper.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");
const pkgPath = join(__dirname, "..", "pkg-node", "sigil_wasm.js");
const buildWasm = join(__dirname, "..", "build-wasm.sh");
const cliManifest = join(repoRoot, "cli", "Cargo.toml");
const cliBinary = join(repoRoot, "cli", "target", "debug", "sigil");
const sigildDir = join(repoRoot, "sigild");

// ⚠️ THROW, NEVER process.exit(). `process.exit()` terminates immediately and
// SKIPS the `finally` block below that kills the spawned sigild — which is how
// twelve orphaned servers, the oldest ~46 hours old, accumulated on the dev
// machine. Throwing unwinds properly, the finally runs, the server dies, and the
// non-zero exit still comes from the uncaught error. `pinning-interop.mjs` has
// carried this note for several phases; the other suites had not adopted it.
function fail(msg) {
  throw new Error(`FAIL: ${msg}`);
}
function assert(cond, msg) {
  if (!cond) fail(msg);
}
function bytesEqual(a, b) {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

// Toolchain PATH exactly like the rest of the repo (macOS arm64), so cargo/go
// resolve the pinned stable toolchain.
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

// Isolated temp workspace: the built sigild binary + all scratch files.
const work = mkdtempSync(join(tmpdir(), "sigil-sync-interop-"));
const sigildBin = join(work, "sigild");

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
const dec = new TextDecoder();

// Fast Argon2 params so the wasm seals are instant (m_cost >= 8 * p_cost).
const M_COST = 8;
const T_COST = 1;
const P_COST = 1;

let sigild = null;
try {
  // --- Boot a live sigild on a free port: dev-ops ON, in-memory, no auth. ---
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  console.log(`starting sigild on ${base} (SIGILD_ENABLE_DEV_OPS=1, in-memory, no auth) ...`);
  sigild = spawn(sigildBin, [], {
    env: {
      ...process.env,
      SIGILD_ADDR: `127.0.0.1:${port}`,
      SIGILD_ENABLE_DEV_OPS: "1",
    },
    stdio: ["ignore", "inherit", "inherit"],
  });
  sigild.on("error", (e) => fail(`sigild failed to spawn: ${e.message}`));
  await waitReady(base);
  console.log("sigild is ready.\n");

  // ===================================================================
  // PROOF 1 — client self-loop: wasm seals -> push -> pull -> wasm opens
  // ===================================================================
  {
    const vault = "wasm-selfloop";
    const password = enc.encode("correct horse battery staple");
    const plaintextStr = "PROOF1-wasm-selfloop-SECRET-🔒-42";
    const plaintext = enc.encode(plaintextStr);

    const salt = new Uint8Array(wasm.recommended_salt_len());
    webcrypto.getRandomValues(salt);
    const nonce = new Uint8Array(wasm.nonce_len());
    webcrypto.getRandomValues(nonce);

    const container = wasm.seal_to_container(password, salt, nonce, M_COST, T_COST, P_COST, plaintext);
    assert(container instanceof Uint8Array && container.length > 0, "PROOF 1: seal produced empty container");

    const { seq } = await pushContainer(base, vault, container);
    assert(seq === 1, `PROOF 1: first push should be seq 1, got ${seq}`);

    // --- OPAQUE check: GET the raw op back; the stored blob must decode to the
    //     EXACT pushed bytes (server returned them verbatim, did no crypto). ---
    const rawRes = await fetch(`${base}/v1/vaults/${vault}/ops?since=0&limit=1000`);
    assert(rawRes.status === 200, `OPAQUE: raw GET should be 200, got ${rawRes.status}`);
    const rawJson = await rawRes.json();
    assert(rawJson.ops.length === 1, `OPAQUE: expected 1 op, got ${rawJson.ops.length}`);
    const storedBytes = new Uint8Array(Buffer.from(rawJson.ops[0].blob, "base64"));
    assert(
      bytesEqual(storedBytes, container),
      "OPAQUE: server-stored blob does not byte-equal the pushed container (server altered the bytes!)",
    );

    const pulled = await pullContainers(base, vault, 0);
    assert(pulled.length === 1, `PROOF 1: expected 1 pulled op, got ${pulled.length}`);
    assert(bytesEqual(pulled[0].container, container), "PROOF 1: pulled container != pushed container");

    const recovered = wasm.open_container(password, pulled[0].container);
    assert(
      bytesEqual(recovered, plaintext),
      `PROOF 1: recovered plaintext != original (got "${dec.decode(recovered)}")`,
    );
    console.log(`  PROOF 1 OK: wasm seal -> push(seq ${seq}) -> pull -> wasm open round-trips`);
    console.log("  OPAQUE  OK: server returned the pushed bytes verbatim (no crypto on the blob)");
  }

  // ===================================================================
  // PROOF 2 — CLI writes / browser reads (cross-client, opaque server)
  //   `sigil seal` + `sigil push`  ->  pullContainers (JS) + wasm.open_container
  // ===================================================================
  {
    const vault = "cli-writes-wasm-reads";
    const PASSWORD_STR = "cli-to-wasm horse staple";
    const password = enc.encode(PASSWORD_STR);
    const plaintextStr = "PROOF2-CLI-writes-browser-reads-🔒-42";
    const plaintext = enc.encode(plaintextStr);

    const plainPath = join(work, "p2-plain.txt");
    const contPath = join(work, "p2-container.sigil");
    writeFileSync(plainPath, plaintext);

    // CLI seals a SIGILcli container (password via SIGIL_PASSWORD env).
    execFileSync(cliBinary, ["seal", "--in", plainPath, "--out", contPath], {
      env: { ...process.env, SIGIL_PASSWORD: PASSWORD_STR },
    });
    // CLI pushes the opaque container to the live sigild (--server = our base).
    const pushOut = execFileSync(
      cliBinary,
      ["push", "--vault", vault, "--in", contPath, "--server", base],
      { encoding: "utf8" },
    );
    assert(/pushed vault .* seq 1/.test(pushOut), `PROOF 2: unexpected CLI push output: ${pushOut.trim()}`);

    // Browser side: pull via the JS module and open with the wasm.
    const pulled = await pullContainers(base, vault, 0);
    assert(pulled.length === 1, `PROOF 2: expected 1 pulled op, got ${pulled.length}`);
    // Sanity: it really is a CLI SIGILcli container.
    assert(
      dec.decode(pulled[0].container.slice(0, 8)) === "SIGILcli",
      "PROOF 2: pulled container is not a SIGILcli container (bad magic)",
    );
    const recovered = wasm.open_container(password, pulled[0].container);
    assert(
      bytesEqual(recovered, plaintext),
      `PROOF 2: wasm-recovered plaintext != original (got "${dec.decode(recovered)}")`,
    );
    console.log("  PROOF 2 OK: `sigil seal`+`sigil push` -> JS pull -> wasm.open_container round-trips");
  }

  // ===================================================================
  // PROOF 3 — browser writes / CLI reads (cross-client, opaque server)
  //   wasm.seal_to_container + pushContainer  ->  `sigil pull` + `sigil open`
  // ===================================================================
  {
    const vault = "wasm-writes-cli-reads";
    const PASSWORD_STR = "wasm-to-cli horse staple";
    const password = enc.encode(PASSWORD_STR);
    const plaintextStr = "PROOF3-browser-writes-CLI-reads-🔒-42";
    const plaintext = enc.encode(plaintextStr);

    const salt = new Uint8Array(wasm.recommended_salt_len());
    webcrypto.getRandomValues(salt);
    const nonce = new Uint8Array(wasm.nonce_len());
    webcrypto.getRandomValues(nonce);

    const container = wasm.seal_to_container(password, salt, nonce, M_COST, T_COST, P_COST, plaintext);
    const { seq } = await pushContainer(base, vault, container);
    assert(seq === 1, `PROOF 3: first push should be seq 1, got ${seq}`);

    // CLI pulls the vault into an out-dir, then opens the pulled op-1.sigil.
    const outDir = join(work, "p3-inbox");
    execFileSync(cliBinary, ["pull", "--vault", vault, "--out-dir", outDir, "--server", base], {
      env: { ...process.env },
    });
    const pulledContainer = join(outDir, vault, "op-1.sigil");
    assert(existsSync(pulledContainer), `PROOF 3: CLI did not write ${pulledContainer}`);

    const recoveredPath = join(work, "p3-recovered.txt");
    execFileSync(cliBinary, ["open", "--in", pulledContainer, "--out", recoveredPath], {
      env: { ...process.env, SIGIL_PASSWORD: PASSWORD_STR },
    });
    const recovered = new Uint8Array(readFileSync(recoveredPath));
    assert(
      bytesEqual(recovered, plaintext),
      `PROOF 3: CLI-recovered plaintext != original (got "${dec.decode(recovered)}")`,
    );
    console.log("  PROOF 3 OK: wasm seal + JS push -> `sigil pull` -> `sigil open` round-trips");
  }
} finally {
  if (sigild && sigild.exitCode === null) {
    sigild.kill("SIGKILL");
  }
  rmSync(work, { recursive: true, force: true });
}

console.log(`\nversion: ${wasm.version()}`);
console.log(
  "PASS: sigil-wasm E2EE sync loop over a LIVE sigild op-log " +
    "(PROOF 1 client self-loop; PROOF 2 CLI writes / browser reads; " +
    "PROOF 3 browser writes / CLI reads; OPAQUE server returns bytes verbatim)",
);
process.exit(0);
