// sharing-interop.mjs — THE PHASE 48 PROOF: device-to-device vault sharing works
// ACROSS CLIENTS, in BOTH directions, between a browser-style JS client and the
// REAL `sigil` CLI, through a REAL sigild.
//
// No mocks anywhere. It builds sigild and the sigil binary, boots sigild on a
// free loopback port with dev-ops + multi-device auth (contract v3), and then:
//
//   (a) BROWSER -> CLI : the JS client enrolls, publishes a hybrid public key,
//                        seals a TOTP vault holding the PUBLIC RFC 6238 seed
//                        under a RANDOM 32-byte VAULT KEY, pushes it, and shares
//                        it to an enrolled CLI device. The REAL `sigil` binary
//                        accepts the share, pulls the vault, and prints the SAME
//                        TOTP code for a pinned instant — which is also the
//                        published RFC 6238 vector.
//   (b) CLI -> BROWSER : the CLI re-keys its own vault, pushes, and shares it to
//                        the JS device. The JS client accepts, unwraps, pulls,
//                        and computes the SAME code in the wasm.
//
// Plus the negative half, which is what makes the positive half mean anything:
//
//   * an enrolled but UNAUTHORIZED third identity is 403 fetching someone else's
//     envelope, 403 fetching one addressed to itself on a vault it has no grant
//     on, and 403 trying to deposit one;
//   * the envelope the server stored is BYTE-IDENTICAL to what was uploaded and
//     contains NEITHER the plaintext vault key NOR the 2FA seed;
//   * the server's own log holds no key material at all.
//
// And the STORAGE invariant this phase turns on: the hybrid SECRET identity and
// every accepted vault key round-trip through the SEALED device-identity
// container, and none of those bytes appear in what a browser would persist.
//
// Pre-audit / UNAUDITED / DEV / LOCALHOST / PLAIN-HTTP. Usage:
//   node test/sharing-interop.mjs
// Exits 0 with a PASS line, non-zero on any failure. Always kills the server and
// removes its temp workspace in a finally block.

import { webcrypto } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:net";

import {
  generateDeviceSeed,
  enrollDevice,
  pushContainerAuthed,
  pullContainersAuthed,
  sealDeviceIdentity,
  openDeviceIdentity,
  DeviceAuthError,
} from "../device-auth.mjs";
import {
  generateHybridIdentity,
  hybridPublicIdentity,
  publishHybridKey,
  fetchHybridKey,
  generateVaultKey,
  wrapVaultKey,
  unwrapVaultKey,
  putKeyEnvelope,
  getKeyEnvelope,
  shareVault,
  acceptVault,
  vaultKeyFingerprint,
  KEY_ENVELOPE_MAGIC,
  WRAPPED_VAULT_KEY_LEN,
} from "../sharing.mjs";
import {
  newVault,
  addEntry,
  openVault,
  sealVault,
  codeForEntry,
  base32Decode,
  bytesToBase64,
} from "../totp-vault.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");
const pkgPath = join(__dirname, "..", "pkg-node", "sigil_wasm.js");
const buildWasm = join(__dirname, "..", "build-wasm.sh");
const sigildDir = join(repoRoot, "sigild");
const cliManifest = join(repoRoot, "cli", "Cargo.toml");
const sigilBin = join(repoRoot, "cli", "target", "debug", "sigil");

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

/** Run `fn` and assert it threw with the expected HTTP status. */
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

const work = mkdtempSync(join(tmpdir(), "sigil-sharing-"));
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
const enc = new TextEncoder();

// Fast Argon2 params so the wasm seals are instant (m_cost >= 8 * p_cost). The
// container is SELF-DESCRIBING, so the CLI opens it with these regardless.
const ARGON2 = { m_cost: 8, t_cost: 1, p_cost: 1 };

// Operator-provisioned secrets for this run (dev-only, >= 16 chars each).
const TOKEN_JS = "enroll-token-JS-0123456789";
const TOKEN_CLI = "enroll-token-CLI-0123456789";
const TOKEN_C = "enroll-token-C-0123456789";
const ADMIN_TOKEN = "admin-token-0123456789";

// The PUBLIC RFC 6238 test seed (ASCII "12345678901234567890" in base32). NOT a
// real secret — it is the published test vector, which is the entire point.
const RFC_SEED_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_RAW_SECRET = "12345678901234567890";
const RFC_T = 59; // RFC 6238 Appendix B, T = 59
const RFC_CODE = "94287082"; // ...the published SHA-1 / 8-digit code at that instant

let sigild = null;
try {
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  console.log(`starting sigild on ${base} (dev-ops + DEVICE AUTH v3, in-memory) ...`);
  const logFd = (await import("node:fs")).openSync(logPath, "w");
  sigild = spawn(sigildBin, [], {
    env: {
      ...process.env,
      SIGILD_ADDR: `127.0.0.1:${port}`,
      SIGILD_ENABLE_DEV_OPS: "1",
      SIGILD_DEVICE_AUTH: "1",
      SIGILD_ENROLL_TOKENS: `${TOKEN_JS},${TOKEN_CLI},${TOKEN_C}`,
      SIGILD_ADMIN_TOKEN: ADMIN_TOKEN,
    },
    stdio: ["ignore", logFd, logFd],
  });
  sigild.on("error", (e) => fail(`sigild failed to spawn: ${e.message}`));
  await waitReady(base);
  console.log("sigild is ready.\n");

  // Each CLI device gets its OWN HOME, so it gets its own identity file, hybrid
  // identity and vault keyring — a separate machine, in effect.
  const cliHome = join(work, "cli-device");
  mkdirSync(cliHome, { recursive: true });

  /** Run the REAL sigil binary as the CLI device; returns stdout. */
  function sigil(args, extraEnv = {}) {
    return execFileSync(sigilBin, args, {
      encoding: "utf8",
      env: {
        ...toolEnv,
        HOME: cliHome,
        SIGIL_SERVER: base,
        SIGIL_DEVICE_KEY: join(cliHome, ".sigil", "device.key"),
        ...extraEnv,
      },
    });
  }

  // ===================================================================
  // 0. Enroll three identities: the JS "browser", the real CLI, and an
  //    unauthorized third JS identity.
  // ===================================================================
  const seedJs = generateDeviceSeed();
  const devJs = await enrollDevice(wasm, {
    baseUrl: base,
    token: TOKEN_JS,
    label: "browser-js",
    seed: seedJs,
  });
  const hybridJs = generateHybridIdentity();
  // `auth` is exactly the object openDeviceIdentity returns, so an unlocked
  // browser client passes its device identity straight in.
  const authJs = { baseUrl: base, deviceId: devJs.deviceId, seed: seedJs, hybrid: hybridJs };
  await publishHybridKey(wasm, authJs);

  const cliEnroll = sigil(["device", "enroll", "--token", TOKEN_CLI, "--label", "cli-device"]);
  const cliDeviceId = (cliEnroll.match(/dev_[A-Za-z0-9_-]+/) ?? [])[0];
  assert(cliDeviceId, `could not parse the CLI device id from:\n${cliEnroll}`);
  sigil(["device", "hybrid-publish"]);

  const seedC = generateDeviceSeed();
  const devC = await enrollDevice(wasm, {
    baseUrl: base,
    token: TOKEN_C,
    label: "browser-c",
    seed: seedC,
  });
  const hybridC = generateHybridIdentity();
  const authC = { baseUrl: base, deviceId: devC.deviceId, seed: seedC, hybrid: hybridC };
  await publishHybridKey(wasm, authC);

  assert(devJs.deviceId !== cliDeviceId && cliDeviceId !== devC.deviceId, "device ids collided");
  console.log(
    `  (0) OK: enrolled JS=${devJs.deviceId}  CLI=${cliDeviceId}  C=${devC.deviceId}; all three published hybrid public keys`,
  );

  // The JS client's published key is what the CLI would wrap to: prove the
  // registry round-trips the exact public halves we derived locally.
  {
    const mine = hybridPublicIdentity(wasm, hybridJs);
    const served = await fetchHybridKey(wasm, authJs, devJs.deviceId);
    assert(
      bytesEqual(served.x25519PublicKey, mine.x25519PublicKey) &&
        bytesEqual(served.mlkemEncapsKey, mine.mlkemEncapsKey),
      "(0) the registry did not serve back the exact published hybrid public key",
    );
    assert(served.x25519PublicKey.length === 32, "(0) X25519 public key must be 32 bytes");
    assert(served.mlkemEncapsKey.length === 1184, "(0) ML-KEM encaps key must be 1184 bytes");
    console.log("  (0) OK: the registry serves back the exact 32 / 1184-byte public halves");
  }

  // ===================================================================
  // SEALED STORAGE: the hybrid SECRET identity and every accepted vault key
  // live INSIDE the password-sealed device-identity container. Nothing new is
  // ever persisted in the clear.
  // ===================================================================
  {
    const probeKey = generateVaultKey();
    const s = webcrypto.getRandomValues(new Uint8Array(wasm.recommended_salt_len()));
    const n = webcrypto.getRandomValues(new Uint8Array(wasm.nonce_len()));
    const sealed = sealDeviceIdentity(
      wasm,
      "vault-password",
      {
        deviceId: devJs.deviceId,
        seed: seedJs,
        baseUrl: base,
        hybrid: hybridJs,
        vaultKeys: { "probe-vault": probeKey },
      },
      s,
      n,
      ARGON2,
    );
    const stored = bytesToBase64(sealed); // EXACTLY what a browser writes to storage
    const sealedBuf = Buffer.from(sealed);
    for (const [what, secret] of [
      ["device seed", seedJs],
      ["hybrid X25519 secret", hybridJs.x25519Secret],
      ["hybrid ML-KEM seed", hybridJs.mlkemSeed],
      ["vault key", probeKey],
    ]) {
      assert(!stored.includes(bytesToBase64(secret)), `SEALED: the ${what} leaked into the stored blob!`);
      assert(!sealedBuf.includes(Buffer.from(secret)), `SEALED: raw ${what} bytes found in the container!`);
    }
    const reopened = openDeviceIdentity(wasm, "vault-password", sealed);
    assert(bytesEqual(reopened.seed, seedJs), "SEALED: seed did not survive the round-trip");
    assert(
      reopened.hybrid && bytesEqual(reopened.hybrid.x25519Secret, hybridJs.x25519Secret),
      "SEALED: hybrid X25519 secret did not survive the round-trip",
    );
    assert(
      bytesEqual(reopened.hybrid.mlkemSeed, hybridJs.mlkemSeed),
      "SEALED: hybrid ML-KEM seed did not survive the round-trip",
    );
    assert(
      bytesEqual(reopened.vaultKeys["probe-vault"], probeKey),
      "SEALED: vault key did not survive the round-trip",
    );
    let threw = false;
    try {
      openDeviceIdentity(wasm, "wrong password", sealed);
    } catch {
      threw = true;
    }
    assert(threw, "SEALED: a wrong password must not open the identity container");

    // BACKWARD COMPATIBILITY: a v1 container (no sharing fields) still opens.
    const legacy = wasm.seal_to_container(
      enc.encode("vault-password"),
      webcrypto.getRandomValues(new Uint8Array(wasm.recommended_salt_len())),
      webcrypto.getRandomValues(new Uint8Array(wasm.nonce_len())),
      ARGON2.m_cost,
      ARGON2.t_cost,
      ARGON2.p_cost,
      enc.encode(
        JSON.stringify({ version: 1, device_id: "dev_legacy", seed: bytesToBase64(seedJs), base_url: base }),
      ),
    );
    const old = openDeviceIdentity(wasm, "vault-password", new Uint8Array(legacy));
    assert(old.deviceId === "dev_legacy" && old.hybrid === null, "SEALED: a v1 container must still open");
    assert(Object.keys(old.vaultKeys).length === 0, "SEALED: a v1 container must yield an empty keyring");
    console.log(
      "  SEAL   OK: hybrid secret + vault keys round-trip through the password-SEALED container (nothing in the clear); v1 containers still open",
    );
  }

  // ===================================================================
  // (a) BROWSER -> CLI. The JS client owns a vault sealed under a RANDOM
  //     32-byte vault key and shares it to the real CLI device.
  // ===================================================================
  const VAULT_A = "browser-shared";
  const vaultKeyA = generateVaultKey();
  const fingerprintA = await vaultKeyFingerprint(vaultKeyA);
  let uploadedEnvelope;
  {
    // Build a TOTP vault holding the PUBLIC RFC 6238 seed and seal it under the
    // VAULT KEY (not a password): a SIGILcli container takes arbitrary password
    // BYTES, so a random 32-byte key drops straight in.
    const v = newVault();
    addEntry(v, {
      label: "rfc",
      issuer: "RFC6238",
      secretBytes: base32Decode(RFC_SEED_B32),
      algorithm: "sha1",
      digits: 8,
      period: 30,
    });
    const salt = webcrypto.getRandomValues(new Uint8Array(wasm.recommended_salt_len()));
    const nonce = webcrypto.getRandomValues(new Uint8Array(wasm.nonce_len()));
    const container = sealVault(wasm, vaultKeyA, v, salt, nonce, ARGON2);

    // The browser's own code, before anything is shared.
    const jsCode = codeForEntry(wasm, v.entries[0], RFC_T);
    assert(jsCode === RFC_CODE, `(a) the JS code at T=${RFC_T} is ${jsCode}, want ${RFC_CODE}`);

    // Push (claims the vault by trust-on-first-write), then share to the CLI.
    const { seq } = await pushContainerAuthed(wasm, authJs, base, VAULT_A, container);
    assert(seq === 1, `(a) first push should be seq 1, got ${seq}`);

    const shared = await shareVault(wasm, authJs, {
      vaultId: VAULT_A,
      recipientDeviceId: cliDeviceId,
      vaultKey: vaultKeyA,
      permission: "read",
    });
    uploadedEnvelope = shared.envelope;
    assert(
      shared.envelopeBytes === WRAPPED_VAULT_KEY_LEN,
      `(a) a wrapped 32-byte vault key should be ${WRAPPED_VAULT_KEY_LEN} bytes, got ${shared.envelopeBytes}`,
    );
    assert(shared.fingerprint === fingerprintA, "(a) shareVault reported a different fingerprint");
    console.log(
      `  (a) OK: JS sealed a vault under a random vault key (fp ${fingerprintA}), pushed it, and shared a ${shared.envelopeBytes}-byte envelope to the CLI`,
    );
  }

  // The REAL `sigil` binary accepts, pulls and prints the code.
  {
    const fetchedPath = join(work, "cli-fetched.env");
    sigil(["vault", "accept", "--vault", VAULT_A, "--envelope-out", fetchedPath]);

    // ZERO-KNOWLEDGE: the relay returned EXACTLY the bytes that were uploaded.
    const fetched = new Uint8Array(readFileSync(fetchedPath));
    assert(
      bytesEqual(fetched, uploadedEnvelope),
      "(a) the bytes the server served back differ from the bytes uploaded (zero-knowledge violated!)",
    );

    // The CLI recovered the SAME key: compare fingerprints, never keys.
    const listed = sigil(["vault", "list"]);
    const cliFp = (listed.match(new RegExp(`${VAULT_A}\\s+key_sha256=([0-9a-f]+)`)) ?? [])[1];
    assert(
      cliFp === fingerprintA,
      `(a) the CLI recovered fingerprint ${cliFp}, the JS client holds ${fingerprintA}`,
    );

    const inbox = join(cliHome, "inbox-a");
    sigil(["pull", "--vault", VAULT_A, "--out-dir", inbox]);
    const pulledDir = join(inbox, VAULT_A);
    const pulled = readdirSync(pulledDir).filter((f) => f.endsWith(".sigil"));
    assert(pulled.length >= 1, `(a) the CLI pulled no container into ${pulledDir}`);

    const out = sigil([
      "totp",
      "code",
      "rfc",
      "--vault",
      join(pulledDir, pulled[0]),
      "--vault-id",
      VAULT_A,
      "--at",
      String(RFC_T),
    ]);
    const cliCode = out.trim().split(/\s+/)[0];
    assert(
      cliCode === RFC_CODE,
      `(a) the CLI's code from the browser-shared vault is ${cliCode}, want ${RFC_CODE}`,
    );
    console.log(
      `  (a) OK: the REAL sigil binary accepted, unwrapped (fp ${cliFp}), pulled and printed ${cliCode} at T=${RFC_T} — the RFC 6238 vector`,
    );
  }

  // ===================================================================
  // (b) CLI -> BROWSER. The CLI re-keys its own vault and shares it to the JS
  //     device, which accepts and computes the SAME code in the wasm.
  // ===================================================================
  const VAULT_B = "cli-shared";
  {
    const cliPassword = "cli-human-password-never-shared";
    sigil(
      [
        "totp",
        "add",
        "rfcb",
        "--secret",
        RFC_SEED_B32,
        "--issuer",
        "RFC6238",
        "--algorithm",
        "sha1",
        "--digits",
        "8",
        "--period",
        "30",
      ],
      { SIGIL_PASSWORD: cliPassword },
    );
    // Re-key: the password vault becomes a SHARED vault under a random key.
    sigil(["vault", "rekey", "--vault", VAULT_B], { SIGIL_PASSWORD: cliPassword });
    sigil(["push", "--vault", VAULT_B, "--in", join(cliHome, ".sigil", "totp-vault.sigil")]);

    const cliUploaded = join(work, "cli-uploaded.env");
    sigil([
      "vault",
      "share",
      "--vault",
      VAULT_B,
      "--to",
      devJs.deviceId,
      "--permission",
      "read",
      "--envelope-out",
      cliUploaded,
    ]);

    // The JS client accepts: collect, unwrap, and hold the recovered vault key.
    const accepted = await acceptVault(wasm, authJs, { vaultId: VAULT_B });
    assert(accepted.vaultKey.length === 32, "(b) the recovered vault key must be 32 bytes");
    assert(
      bytesEqual(accepted.envelope, new Uint8Array(readFileSync(cliUploaded))),
      "(b) the envelope the JS client collected differs from what the CLI uploaded",
    );

    const cliListed = sigil(["vault", "list"]);
    const cliFpB = (cliListed.match(new RegExp(`${VAULT_B}\\s+key_sha256=([0-9a-f]+)`)) ?? [])[1];
    assert(
      cliFpB === accepted.fingerprint,
      `(b) the JS client recovered fingerprint ${accepted.fingerprint}, the CLI holds ${cliFpB}`,
    );

    // Pull the sealed vault and open it with the recovered key, in the wasm.
    const ops = await pullContainersAuthed(wasm, authJs, base, VAULT_B, 0);
    assert(ops.length >= 1, "(b) the JS client pulled no container");
    const opened = openVault(wasm, accepted.vaultKey, ops[ops.length - 1].container);
    const entry = opened.entries.find((e) => e.label === "rfcb");
    assert(entry, "(b) the shared vault has no 'rfcb' entry");
    const jsCode = codeForEntry(wasm, entry, RFC_T);

    const cliOut = sigil(["totp", "code", "rfcb", "--vault-id", VAULT_B, "--at", String(RFC_T)]);
    const cliCode = cliOut.trim().split(/\s+/)[0];
    assert(jsCode === cliCode, `(b) JS code ${jsCode} != CLI code ${cliCode}`);
    assert(jsCode === RFC_CODE, `(b) the shared code is ${jsCode}, want the RFC vector ${RFC_CODE}`);

    // The CLI's HUMAN PASSWORD was never shared, wrapped or sent — and it no
    // longer opens the re-keyed vault.
    let pwStillWorks = true;
    try {
      openVault(wasm, cliPassword, ops[ops.length - 1].container);
    } catch {
      pwStillWorks = false;
    }
    assert(!pwStillWorks, "(b) the CLI's human password still opens the re-keyed shared vault!");
    console.log(
      `  (b) OK: the CLI shared to the browser — JS=${jsCode}  CLI=${cliCode}  RFC 6238 vector=${RFC_CODE} (fp ${accepted.fingerprint}); the human password does NOT open it`,
    );
  }

  // ===================================================================
  // NEGATIVE: an enrolled but UNAUTHORIZED third identity gets nothing.
  // ===================================================================
  {
    const e1 = await expectStatus(
      403,
      () => getKeyEnvelope(wasm, authC, VAULT_A, cliDeviceId),
      "C fetching the CLI device's envelope",
    );
    assert(e1 instanceof DeviceAuthError, "expected a DeviceAuthError");
    assert(/forbidden/i.test(e1.message), `the 403 message should explain forbidden: ${e1.message}`);

    await expectStatus(
      403,
      () => getKeyEnvelope(wasm, authC, VAULT_A, devC.deviceId),
      "C fetching an envelope addressed to itself on a vault it has no grant on",
    );

    const junk = wrapVaultKey(wasm, hybridPublicIdentity(wasm, hybridC), generateVaultKey());
    await expectStatus(
      403,
      () => putKeyEnvelope(wasm, authC, VAULT_A, devC.deviceId, junk),
      "C depositing an envelope on a vault it does not own",
    );

    // Even holding the ciphertext, C cannot open an envelope addressed elsewhere.
    let opened = true;
    try {
      unwrapVaultKey(wasm, hybridC, uploadedEnvelope);
    } catch {
      opened = false;
    }
    assert(!opened, "C opened an envelope that was not addressed to it!");
    console.log(
      "  NEG    OK: the unauthorized third identity is 403 fetching another device's envelope, 403 fetching its own, 403 depositing — and cannot open the ciphertext",
    );
  }

  // ===================================================================
  // OPAQUE: the envelope is ciphertext, and the server logged none of it.
  // ===================================================================
  {
    const envBuf = Buffer.from(uploadedEnvelope);
    assert(
      envBuf.subarray(0, 8).toString("latin1") === KEY_ENVELOPE_MAGIC,
      `the envelope must start with ${KEY_ENVELOPE_MAGIC}`,
    );
    assert(!envBuf.includes(Buffer.from(vaultKeyA)), "the envelope contains the plaintext vault key!");
    assert(!envBuf.includes(Buffer.from(RFC_RAW_SECRET, "utf8")), "the envelope contains the raw 2FA secret!");
    assert(!envBuf.includes(Buffer.from(RFC_SEED_B32, "utf8")), "the envelope contains the base32 seed!");

    // Two wraps of the SAME key must differ (fresh ephemeral entropy per call).
    const again = wrapVaultKey(wasm, await fetchHybridKey(wasm, authJs, cliDeviceId), vaultKeyA);
    assert(!bytesEqual(again, uploadedEnvelope), "two wraps of the same key were identical (entropy reuse!)");

    const log = readFileSync(logPath, "utf8");
    assert(!log.includes(KEY_ENVELOPE_MAGIC), "sigild logged envelope content!");
    assert(!log.includes(bytesToBase64(vaultKeyA)), "sigild logged the vault key!");
    assert(!log.includes(bytesToBase64(hybridJs.x25519Secret)), "sigild logged a hybrid secret!");
    assert(!log.includes(bytesToBase64(hybridJs.mlkemSeed)), "sigild logged a hybrid seed!");
    assert(!log.includes(RFC_RAW_SECRET), "sigild logged the raw 2FA secret!");
    assert(log.includes("vault.key_envelope_put"), "no key_envelope_put audit line");
    assert(log.includes("vault.key_envelope_get"), "no key_envelope_get audit line");
    assert(log.includes("blob_sha256"), "no blob fingerprint in the audit trail");
    console.log(
      "  ZK     OK: the envelope is a SIGILhyb container holding no plaintext key or seed, two wraps differ, and the server logged fingerprints only",
    );
  }
} finally {
  if (sigild && sigild.exitCode === null) {
    sigild.kill("SIGKILL");
  }
  rmSync(work, { recursive: true, force: true });
}

console.log(`\nversion: ${wasm.version()}`);
console.log(
  "PASS: cross-client vault sharing works BOTH ways against a LIVE sigild — " +
    "(a) browser -> real sigil CLI and (b) real sigil CLI -> browser both yield the RFC 6238 vector " +
    `${RFC_CODE} at T=${RFC_T}; an unauthorized device is 403 everywhere; the relayed envelope is ` +
    "byte-identical ciphertext and the server logged no key material.",
);
process.exit(0);
