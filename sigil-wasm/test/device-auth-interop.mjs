// device-auth-interop.mjs — end-to-end proof that a BROWSER-STYLE JS client can
// authenticate against sigild's REAL multi-device auth model (op-log request
// contract v3 + device enrollment), using only the wasm for cryptography.
//
// It builds sigild, boots it on a free localhost port with the device model ON
// (SIGILD_ENABLE_DEV_OPS=1, SIGILD_DEVICE_AUTH=1, two single-use enrollment
// tokens, an admin token), and then proves, against the LIVE server:
//
//   (a) ENROLL A       — JS draws a 32-byte seed, derives its Ed25519 public key
//                        in the wasm, signs the proof-of-possession challenge and
//                        gets a server-assigned device id.
//   (b) A OWNS A VAULT — A pushes a wasm-sealed container (claiming the vault by
//                        trust-on-first-write), pulls it back, and the wasm opens
//                        it to the exact original plaintext.
//   (c) B IS REFUSED   — a second enrolled device B gets 403 on A's vault (it is
//                        authenticated but holds no grant).
//   (d) GRANT B READ   — A (the owner) grants B read; B can then pull and open.
//   (e) REVOKE B       — the operator revokes B; B's very next request is 401.
//   (f) TAMPER / STALE — a request whose body was swapped after signing, and one
//                        signed with a 10-minute-old timestamp, are both 401.
//   (g) TOKEN REUSE    — re-presenting an already-spent enrollment token fails.
//
// Plus two invariants: an UNSIGNED request is 401 (the server really is
// enforcing), and the pushed blob comes back byte-identical (the server did no
// crypto — zero-knowledge intact).
//
// Pre-audit / UNAUDITED / DEV / LOCALHOST / PLAIN-HTTP. Usage:
//   node test/device-auth-interop.mjs
// Exits 0 with a PASS line, non-zero on any failure. Always kills the server and
// removes its temp workspace in a finally block.

import { webcrypto } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:net";

import {
  generateDeviceSeed,
  devicePublicKey,
  enrollDevice,
  signedFetch,
  pushContainerAuthed,
  pullContainersAuthed,
  grantVaultAccess,
  revokeDeviceAdmin,
  listDevices,
  canonicalV3Message,
  sealDeviceIdentity,
  openDeviceIdentity,
  DeviceAuthError,
} from "../device-auth.mjs";
import { bytesToBase64 } from "../totp-vault.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");
const pkgPath = join(__dirname, "..", "pkg-node", "sigil_wasm.js");
const buildWasm = join(__dirname, "..", "build-wasm.sh");
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

// Run `fn` and assert it threw with the expected HTTP status.
async function expectStatus(want, fn, what) {
  try {
    await fn();
  } catch (e) {
    const got = e && typeof e.status === "number" ? e.status : 0;
    assert(got === want, `${what}: expected HTTP ${want}, got ${got} (${e.message})`);
    return e;
  }
  fail(`${what}: expected HTTP ${want}, but the call SUCCEEDED`);
}

const toolPath = [
  `${process.env.HOME}/.rustup/toolchains/stable-aarch64-apple-darwin/bin`,
  `${process.env.HOME}/.cargo/bin`,
  "/opt/homebrew/bin",
  process.env.PATH ?? "",
].join(":");
const toolEnv = { ...process.env, PATH: toolPath };
const goBin = "/opt/homebrew/bin/go";

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

const work = mkdtempSync(join(tmpdir(), "sigil-device-auth-"));
const sigildBin = join(work, "sigild");

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

const wasm = await import(pkgPath);
const enc = new TextEncoder();
const dec = new TextDecoder();

// Fast Argon2 params so the wasm seals are instant (m_cost >= 8 * p_cost).
const M_COST = 8;
const T_COST = 1;
const P_COST = 1;

// Operator-provisioned secrets for this run (dev-only, >= 16 chars each).
const TOKEN_A = "enroll-token-A-0123456789";
const TOKEN_B = "enroll-token-B-0123456789";
const ADMIN_TOKEN = "admin-token-0123456789";

let sigild = null;
try {
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  console.log(`starting sigild on ${base} (dev-ops + DEVICE AUTH v3, in-memory registry) ...`);
  sigild = spawn(sigildBin, [], {
    env: {
      ...process.env,
      SIGILD_ADDR: `127.0.0.1:${port}`,
      SIGILD_ENABLE_DEV_OPS: "1",
      SIGILD_DEVICE_AUTH: "1",
      SIGILD_ENROLL_TOKENS: `${TOKEN_A},${TOKEN_B}`,
      SIGILD_ADMIN_TOKEN: ADMIN_TOKEN,
    },
    stdio: ["ignore", "inherit", "inherit"],
  });
  sigild.on("error", (e) => fail(`sigild failed to spawn: ${e.message}`));
  await waitReady(base);
  console.log("sigild is ready.\n");

  const vault = "browser-device-vault";
  const password = enc.encode("correct horse battery staple");
  const plaintextStr = "PHASE44-browser-device-auth-🔒-42";
  const plaintext = enc.encode(plaintextStr);

  // A sealed SIGILcli container — the OPAQUE payload the server never decodes.
  const salt = new Uint8Array(wasm.recommended_salt_len());
  webcrypto.getRandomValues(salt);
  const nonce = new Uint8Array(wasm.nonce_len());
  webcrypto.getRandomValues(nonce);
  const container = wasm.seal_to_container(
    password,
    salt,
    nonce,
    M_COST,
    T_COST,
    P_COST,
    plaintext,
  );

  // --- INVARIANT: the server really is enforcing (unsigned request -> 401). ---
  {
    const res = await fetch(`${base}/v1/vaults/${vault}/ops`, {
      method: "POST",
      headers: { "Content-Type": "application/octet-stream" },
      body: container,
    });
    assert(res.status === 401, `unsigned push should be 401, got ${res.status}`);
    console.log("  GUARD  OK: an UNSIGNED op-log request is refused 401");
  }

  // ===================================================================
  // (a) ENROLL device A — seed in JS, signature in the wasm.
  // ===================================================================
  const seedA = generateDeviceSeed();
  assert(seedA instanceof Uint8Array && seedA.length === 32, "(a) seed must be 32 bytes");
  const pubA = devicePublicKey(wasm, seedA);
  assert(pubA.length === 32, "(a) derived public key must be 32 bytes");

  const devA = await enrollDevice(wasm, {
    baseUrl: base,
    token: TOKEN_A,
    label: "browser-A",
    seed: seedA,
  });
  assert(typeof devA.deviceId === "string" && devA.deviceId.length > 0, "(a) no device id returned");
  assert(bytesEqual(devA.publicKey, pubA), "(a) enrolled public key != derived public key");
  const idA = { deviceId: devA.deviceId, seed: seedA };
  console.log(`  (a) OK: device A enrolled as ${devA.deviceId} (label ${devA.label})`);

  // --- STORAGE MODEL: the clients persist the identity SEALED, never in the
  //     clear. Prove the round-trip and that the seed bytes do not appear in
  //     what gets written to localStorage / chrome.storage.local. ---
  {
    const s = new Uint8Array(wasm.recommended_salt_len());
    webcrypto.getRandomValues(s);
    const n = new Uint8Array(wasm.nonce_len());
    webcrypto.getRandomValues(n);
    const sealedId = sealDeviceIdentity(wasm, "vault-password", { ...idA, baseUrl: base }, s, n, {
      m_cost: M_COST,
      t_cost: T_COST,
      p_cost: P_COST,
    });
    const stored = bytesToBase64(sealedId); // exactly what a client writes
    assert(!stored.includes(bytesToBase64(seedA)), "SEALED: the seed leaked into the stored blob!");
    assert(
      !Buffer.from(sealedId).includes(Buffer.from(seedA)),
      "SEALED: raw seed bytes found inside the sealed container!",
    );
    const reopened = openDeviceIdentity(wasm, "vault-password", sealedId);
    assert(reopened.deviceId === idA.deviceId, "SEALED: device id did not survive the round-trip");
    assert(bytesEqual(reopened.seed, seedA), "SEALED: seed did not survive the round-trip");
    let wrongPwThrew = false;
    try {
      openDeviceIdentity(wasm, "wrong password", sealedId);
    } catch {
      wrongPwThrew = true;
    }
    assert(wrongPwThrew, "SEALED: a wrong password must not open the identity container");
    console.log(
      "  SEAL   OK: the device identity round-trips through a password-SEALED SIGILcli container (no plaintext seed at rest)",
    );
  }

  // ===================================================================
  // (b) A pushes (claiming the vault), pulls it back, and the wasm opens it.
  // ===================================================================
  {
    const { seq } = await pushContainerAuthed(wasm, idA, base, vault, container);
    assert(seq === 1, `(b) first authenticated push should be seq 1, got ${seq}`);

    const pulled = await pullContainersAuthed(wasm, idA, base, vault, 0);
    assert(pulled.length === 1, `(b) expected 1 pulled op, got ${pulled.length}`);
    assert(
      bytesEqual(pulled[0].container, container),
      "(b) server did NOT return the pushed bytes verbatim (zero-knowledge violated!)",
    );
    const recovered = wasm.open_container(password, pulled[0].container);
    assert(
      bytesEqual(recovered, plaintext),
      `(b) recovered plaintext != original (got "${dec.decode(recovered)}")`,
    );
    console.log(
      `  (b) OK: A pushed (seq ${seq}), claimed the vault, pulled it back and the wasm opened it (bytes verbatim)`,
    );
  }

  // ===================================================================
  // (c) Enroll device B; it is authenticated but NOT authorized -> 403.
  // ===================================================================
  const seedB = generateDeviceSeed();
  const devB = await enrollDevice(wasm, {
    baseUrl: base,
    token: TOKEN_B,
    label: "browser-B",
    seed: seedB,
  });
  const idB = { deviceId: devB.deviceId, seed: seedB };
  assert(devB.deviceId !== devA.deviceId, "(c) B got the same device id as A");
  {
    const e = await expectStatus(
      403,
      () => pullContainersAuthed(wasm, idB, base, vault, 0),
      "(c) B pulling A's vault",
    );
    assert(e instanceof DeviceAuthError, "(c) expected a DeviceAuthError");
    assert(/forbidden/i.test(e.message), `(c) message should explain 403, got: ${e.message}`);
    console.log(`  (c) OK: device B (${devB.deviceId}) is enrolled but refused 403 on A's vault`);
  }

  // ===================================================================
  // (d) A (the owner) grants B read -> B can pull and open.
  // ===================================================================
  {
    const grant = await grantVaultAccess(wasm, idA, base, vault, devB.deviceId, "read");
    assert(grant.device_id === devB.deviceId, `(d) unexpected grant response: ${JSON.stringify(grant)}`);

    const pulled = await pullContainersAuthed(wasm, idB, base, vault, 0);
    assert(pulled.length === 1, `(d) B expected 1 op after the grant, got ${pulled.length}`);
    const recovered = wasm.open_container(password, pulled[0].container);
    assert(bytesEqual(recovered, plaintext), "(d) B could not open the pulled container");

    // The grant is READ-only, so B still cannot write.
    await expectStatus(
      403,
      () => pushContainerAuthed(wasm, idB, base, vault, container),
      "(d) B pushing with a read-only grant",
    );
    console.log("  (d) OK: after A granted read, B pulls + opens the vault — and is still 403 on write");
  }

  // ===================================================================
  // (e) The operator revokes B -> B's very next request is 401.
  // ===================================================================
  {
    const revoked = await revokeDeviceAdmin({
      baseUrl: base,
      adminToken: ADMIN_TOKEN,
      deviceId: devB.deviceId,
    });
    assert(revoked.status === "revoked", `(e) unexpected revoke response: ${JSON.stringify(revoked)}`);

    await expectStatus(
      401,
      () => pullContainersAuthed(wasm, idB, base, vault, 0),
      "(e) revoked B pulling",
    );

    // A is untouched by B's revocation.
    const stillOk = await pullContainersAuthed(wasm, idA, base, vault, 0);
    assert(stillOk.length === 1, "(e) A should still be able to pull after B was revoked");

    // Operator listing sees both devices with the right statuses (no key material).
    const { devices } = await listDevices({ baseUrl: base, adminToken: ADMIN_TOKEN });
    const byId = Object.fromEntries(devices.map((d) => [d.device_id, d]));
    assert(byId[devA.deviceId]?.status === "active", "(e) A should still be active");
    assert(byId[devB.deviceId]?.status === "revoked", "(e) B should be revoked");
    assert(
      !JSON.stringify(devices).includes(bytesToBase64(pubA)),
      "(e) the device listing must NOT echo public key material",
    );
    console.log("  (e) OK: admin revoked B — B is 401 on its next request, A is unaffected");
  }

  // ===================================================================
  // (f) A TAMPERED body and a STALE timestamp are both refused 401.
  // ===================================================================
  {
    // Tampered body: sign over the real container, then send different bytes.
    const path = `/v1/vaults/${vault}/ops`;
    const timestamp = String(Math.floor(Date.now() / 1000));
    const nonceB64 = bytesToBase64(webcrypto.getRandomValues(new Uint8Array(16)));
    const msg = canonicalV3Message(idA.deviceId, "POST", path, "", timestamp, nonceB64, container);
    const sig = bytesToBase64(wasm.ed25519_sign(idA.seed, msg));
    const tampered = Uint8Array.from(container);
    tampered[tampered.length - 1] ^= 0x01;

    const res = await fetch(`${base}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-Sigil-Device": idA.deviceId,
        "X-Sigil-Timestamp": timestamp,
        "X-Sigil-Nonce": nonceB64,
        "X-Sigil-Signature": sig,
      },
      body: tampered,
    });
    assert(res.status === 401, `(f) tampered body should be 401, got ${res.status}`);

    // Stale timestamp: correctly signed, but 10 minutes old (window is 300 s).
    const staleTs = String(Math.floor(Date.now() / 1000) - 600);
    const staleNonce = bytesToBase64(webcrypto.getRandomValues(new Uint8Array(16)));
    const staleMsg = canonicalV3Message(
      idA.deviceId,
      "POST",
      path,
      "",
      staleTs,
      staleNonce,
      container,
    );
    const staleSig = bytesToBase64(wasm.ed25519_sign(idA.seed, staleMsg));
    const staleRes = await fetch(`${base}${path}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/octet-stream",
        "X-Sigil-Device": idA.deviceId,
        "X-Sigil-Timestamp": staleTs,
        "X-Sigil-Nonce": staleNonce,
        "X-Sigil-Signature": staleSig,
      },
      body: container,
    });
    assert(staleRes.status === 401, `(f) stale timestamp should be 401, got ${staleRes.status}`);

    // And the honest, freshly signed equivalent still works — so (f) is proving
    // the tamper/staleness checks, not a broken client.
    const okRes = await signedFetch(wasm, { ...idA, baseUrl: base }, "POST", path, "", container, {
      "Content-Type": "application/octet-stream",
    });
    assert(okRes.status === 201, `(f) the honest control push should be 201, got ${okRes.status}`);
    console.log("  (f) OK: a tampered body and a 10-minute-stale timestamp are both 401 (honest control: 201)");
  }

  // ===================================================================
  // (g) An enrollment token is SINGLE-USE: re-presenting it fails.
  // ===================================================================
  {
    const seedC = generateDeviceSeed();
    const e = await expectStatus(
      401,
      () =>
        enrollDevice(wasm, {
          baseUrl: base,
          token: TOKEN_A, // already spent by device A
          label: "browser-C-should-fail",
          seed: seedC,
        }),
      "(g) reusing a spent enrollment token",
    );
    assert(e instanceof DeviceAuthError, "(g) expected a DeviceAuthError");
    console.log("  (g) OK: reusing an already-spent enrollment token is refused 401");
  }
} finally {
  if (sigild && sigild.exitCode === null) {
    sigild.kill("SIGKILL");
  }
  rmSync(work, { recursive: true, force: true });
}

console.log(`\nversion: ${wasm.version()}`);
console.log(
  "PASS: browser-style JS client authenticates against a LIVE sigild multi-device model " +
    "(a enroll; b own+round-trip; c 403 unauthorized; d grant->read; e revoke->401; " +
    "f tamper/stale->401; g enrollment token single-use)",
);
process.exit(0);
