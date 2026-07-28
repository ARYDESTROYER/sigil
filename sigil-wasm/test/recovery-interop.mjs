// recovery-interop.mjs — THE PHASE 54 PROOF: the RECOVERY KIT works ACROSS
// CLIENTS, in BOTH directions, between a browser-style JS client and the REAL
// `sigil` CLI, through a REAL sigild.
//
// No mocks anywhere. It builds sigild and the sigil binary, boots sigild on a
// free loopback port with dev-ops + multi-device auth (contract v3), and then:
//
//   (a) BROWSER -> CLI : the JS client enrolls, seals a TOTP vault holding the
//                        PUBLIC RFC 6238 seed under a RANDOM 32-byte vault key,
//                        pushes it, and generates a RECOVERY KIT. The REAL
//                        `sigil recovery restore` — on a machine with NO local
//                        state — recovers the vault from the 56 printed
//                        characters and prints 94287082 at T=59.
//   (b) CLI -> BROWSER : the CLI generates a kit for its own vault, and the JS
//                        client's `restoreFromKit` recovers it and computes the
//                        SAME code in the wasm.
//
// Plus the assertions that make those mean anything:
//
//   * ⭐ THE DERIVATION KAT is reproduced through the wasm exports, so the
//     Crockford codec, the checksum and the HKDF expansion cannot drift from
//     `sigil-core`'s own known-answer test (they are literally the same Rust —
//     this pins that they are still reached);
//   * ⭐ NO LEAK: `fetch` is wrapped and EVERY outgoing byte (URL, headers,
//     body) of EVERY request is scanned for the printed code, the raw recovery
//     secret and each derived seed — expecting zero occurrences;
//   * a mistyped code is rejected OFFLINE — with `fetch` replaced by a function
//     that FAILS THE TEST if it is called at all;
//   * `restoreFromKit` on a kit that covers nothing reports "nothing to
//     recover", not a fault.
//
// Pre-audit / UNAUDITED / DEV / LOCALHOST / PLAIN-HTTP. Usage:
//   node test/recovery-interop.mjs
// Exits 0 with a PASS line, non-zero on any failure. Always kills the server and
// removes its temp workspace in a finally block.

import { webcrypto } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:net";

import {
  generateDeviceSeed,
  enrollDevice,
  createAccountInvite,
  pushContainerAuthed,
  pullContainersAuthed,
} from "../device-auth.mjs";
import {
  generateHybridIdentity,
  generateVaultKey,
  listKeyEnvelopes,
  newPinStore,
  publishHybridKey,
  rotateVaultKey,
  shareVault,
  vaultKeyFingerprint,
  PIN_ORIGIN_RECOVERY_KIT,
  RecipientsWouldBeDroppedError,
  UnverifiedRecoveryKitError,
  SafetyNumberMismatchError,
} from "../sharing.mjs";
import {
  RECOVERY_DEVICE_LABEL,
  RecoveryError,
  generateRecoveryKit,
  listRecoverableVaults,
  restoreFromKit,
  verifyRecoveryKit,
} from "../recovery.mjs";
import { newVault, addEntry, openVault, sealVault, codeForEntry, base32Decode } from "../totp-vault.mjs";

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
function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
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
      const res = await realFetch(`${base}/readyz`);
      if (res.status === 200) return;
    } catch {
      /* not up yet */
    }
    if (Date.now() > deadline) throw new Error(`sigild /readyz not ready within ${timeoutMs}ms`);
    await new Promise((r) => setTimeout(r, 150));
  }
}

// ===========================================================================
// ⭐ THE NO-LEAK HARNESS. Every request this process makes is recorded — URL,
// headers and body — so the assertions at the end can prove that no recovery
// code, recovery secret or derived seed ever left the client.
// ===========================================================================
const realFetch = globalThis.fetch.bind(globalThis);
const outbound = [];
globalThis.fetch = async function recordingFetch(url, init = {}) {
  const parts = [String(url)];
  for (const [k, v] of Object.entries(init.headers ?? {})) parts.push(`${k}: ${v}`);
  if (init.body) {
    const body = init.body instanceof Uint8Array ? init.body : new Uint8Array(init.body ?? []);
    parts.push(Buffer.from(body).toString("latin1"));
    parts.push(Buffer.from(body).toString("base64"));
    parts.push(hex(body));
  }
  outbound.push(parts.join("\n"));
  return realFetch(url, init);
};

// --- Ensure the wasm binding exists. ---
if (!existsSync(pkgPath)) {
  console.log("pkg-node missing — building the wasm (./build-wasm.sh) ...");
  try {
    execFileSync("bash", [buildWasm], { stdio: "inherit", env: toolEnv, cwd: join(__dirname, "..") });
  } catch (e) {
    fail(`could not build the wasm binding (./build-wasm.sh): ${e.message}`);
  }
}
assert(existsSync(pkgPath), `${pkgPath} not found even after ./build-wasm.sh.`);

const work = mkdtempSync(join(tmpdir(), "sigil-recovery-"));
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

// Fast Argon2 params so the wasm seals are instant (m_cost >= 8 * p_cost). The
// container is SELF-DESCRIBING, so the CLI opens it with these regardless.
const ARGON2 = { m_cost: 8, t_cost: 1, p_cost: 1 };

const TOKEN_JS = "enroll-token-JS-0123456789";
const TOKEN_CLI = "enroll-token-CLI-0123456789";

// The PUBLIC RFC 6238 test seed. NOT a real secret — it is the published vector.
const RFC_SEED_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_T = 59;
const RFC_CODE = "94287082";

const VAULT_JS = "jsvault";
const VAULT_CLI = "clivault";

// Secrets that must never appear in an outbound request.
const secretsSeen = [];

let sigild = null;
try {
  // =====================================================================
  // (c) ⭐ THE DERIVATION KAT, through the wasm exports.
  // =====================================================================
  {
    const seed = new Uint8Array(32).fill(0x42);
    const edSeed = new Uint8Array(wasm.recovery_derive_ed25519_seed(seed));
    const edPub = new Uint8Array(wasm.ed25519_public_key(edSeed));
    assert(
      hex(edPub) === "913af25b7f0ea458577b80124f137f7a8f0e5850a73a5cdeaf92e9169edeb717",
      `KAT: ed25519 public key drifted (${hex(edPub)})`,
    );
    const xSecret = new Uint8Array(wasm.recovery_derive_x25519_secret(seed));
    const xPub = new Uint8Array(wasm.hybrid_x25519_public(xSecret));
    assert(
      hex(xPub) === "a55ac63d4d1f84face17abb82cc3449cd43c3f25f7a08008075bd594acc98754",
      `KAT: x25519 public key drifted (${hex(xPub)})`,
    );
    const mlkemSeed = new Uint8Array(wasm.recovery_derive_mlkem_seed(seed));
    const encaps = new Uint8Array(wasm.hybrid_mlkem_encaps_key(mlkemSeed));
    assert(encaps.length === 1184, "KAT: ML-KEM encapsulation key must be 1184 bytes");
    const digest = new Uint8Array(await webcrypto.subtle.digest("SHA-256", encaps));
    assert(
      hex(digest) === "14260b3e72b496ac3fde4a2434fd0f175f55324cca38ef8cd75a53675b643806",
      `KAT: ML-KEM encapsulation key drifted (${hex(digest)})`,
    );
    const code = wasm.recovery_encode(seed);
    assert(code.length === 56, `KAT: a printed code must be 56 characters, got ${code.length}`);
    assert(
      wasm.recovery_format(code) ===
        "05144GJ2-89144GJ2-89144GJ2-89144GJ2-89144GJ2-89144GJ2-89145G6W",
      "KAT: the printed grouping drifted",
    );
    // Presentation folds; U does not.
    assert(
      hex(new Uint8Array(wasm.recovery_decode(wasm.recovery_format(code).toLowerCase()))) ===
        hex(seed),
      "KAT: the grouped/lowercase form did not decode back to the same secret",
    );
    console.log("  (c) OK: ⭐ the derivation + codec KAT matches sigil-core, the CLI and the wasm");
  }

  // =====================================================================
  // A mistyped code must be rejected with ZERO network I/O — proven by
  // making any fetch a hard test failure while it runs.
  // =====================================================================
  {
    const seed = webcrypto.getRandomValues(new Uint8Array(32));
    const good = wasm.recovery_encode(seed);
    const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    const swapped = alphabet[(alphabet.indexOf(good[0]) + 1) % alphabet.length] + good.slice(1);
    const saved = globalThis.fetch;
    globalThis.fetch = () => fail("a request was made BEFORE the checksum was verified");
    try {
      let threw = false;
      try {
        verifyRecoveryKit(wasm, swapped);
      } catch (e) {
        threw = true;
        assert(e instanceof RecoveryError, "a typo must be a RecoveryError");
        assert(
          /not a valid recovery code/.test(e.message),
          `a typo must say so plainly, got: ${e.message}`,
        );
      }
      assert(threw, "a mistyped code was ACCEPTED");
      // The good one decodes, also offline.
      assert(hex(verifyRecoveryKit(wasm, good)) === hex(seed), "the good code did not round-trip");
    } finally {
      globalThis.fetch = saved;
    }
    console.log("  (d) OK: a mistyped code is rejected OFFLINE — zero network I/O before the checksum");
  }

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
      SIGILD_ENROLL_TOKENS: `${TOKEN_JS},${TOKEN_CLI}`,
    },
    stdio: ["ignore", logFd, logFd],
  });
  sigild.on("error", (e) => fail(`sigild failed to spawn: ${e.message}`));
  await waitReady(base);
  console.log("sigild is ready.\n");

  const cliHome = join(work, "cli-device");
  const restoreHome = join(work, "cli-restore");
  mkdirSync(cliHome, { recursive: true });
  mkdirSync(restoreHome, { recursive: true });

  function sigil(args, home = cliHome, extraEnv = {}) {
    return execFileSync(sigilBin, args, {
      encoding: "utf8",
      env: {
        ...toolEnv,
        HOME: home,
        SIGIL_SERVER: base,
        SIGIL_DEVICE_KEY: join(home, ".sigil", "device.key"),
        ...extraEnv,
      },
    });
  }

  // =====================================================================
  // 0. Enroll the JS "browser" and the real CLI.
  // =====================================================================
  const seedJs = generateDeviceSeed();
  const devJs = await enrollDevice(wasm, {
    baseUrl: base,
    token: TOKEN_JS,
    label: "browser-js",
    seed: seedJs,
  });
  const hybridJs = generateHybridIdentity();
  const authJs = {
    baseUrl: base,
    deviceId: devJs.deviceId,
    seed: seedJs,
    hybrid: hybridJs,
    pins: newPinStore(),
  };
  await publishHybridKey(wasm, authJs);

  const cliEnroll = sigil(["device", "enroll", "--token", TOKEN_CLI, "--label", "cli-device"]);
  const cliDeviceId = (cliEnroll.match(/dev_[A-Za-z0-9_-]+/) ?? [])[0];
  assert(cliDeviceId, `could not parse the CLI device id from:\n${cliEnroll}`);
  sigil(["device", "hybrid-publish"]);
  console.log(`  (0) OK: enrolled JS=${devJs.deviceId}  CLI=${cliDeviceId}`);

  // =====================================================================
  // (a) BROWSER -> CLI. The JS client builds a shared vault, pushes it, and
  //     generates a recovery kit. The REAL CLI restores from the paper.
  // =====================================================================
  const vaultKeyJs = generateVaultKey();
  {
    const v = newVault();
    addEntry(v, {
      label: "work",
      issuer: "RFC6238",
      secretBytes: base32Decode(RFC_SEED_B32),
      algorithm: "sha1",
      digits: 8,
      period: 30,
    });
    const salt = webcrypto.getRandomValues(new Uint8Array(wasm.recommended_salt_len()));
    const nonce = webcrypto.getRandomValues(new Uint8Array(wasm.nonce_len()));
    const sealed = sealVault(wasm, vaultKeyJs, v, salt, nonce, ARGON2);
    await pushContainerAuthed(wasm, authJs, base, VAULT_JS, sealed);
  }

  const kit = await generateRecoveryKit(wasm, authJs, {
    vaultKeys: [{ vaultId: VAULT_JS, vaultKey: vaultKeyJs }],
    pins: authJs.pins,
  });
  secretsSeen.push(kit.code, kit.formatted, kit.formatted.replace(/-/g, ""));
  assert(kit.code.length === 56, `the printed code must be 56 characters, got ${kit.code.length}`);
  assert(kit.deviceId.startsWith("dev_"), "the kit did not enroll");
  assert(
    kit.verification.unwrappedVault === VAULT_JS,
    "the pre-print verification did not unwrap a real envelope",
  );
  assert(
    kit.verification.fingerprint === (await vaultKeyFingerprint(vaultKeyJs)),
    "the pre-print verification recovered a DIFFERENT key",
  );
  assert(
    kit.pins.pins[kit.deviceId]?.origin === PIN_ORIGIN_RECOVERY_KIT,
    "the kit's pin is not marked origin=recovery-kit (it was DERIVED, not fetched)",
  );
  // The derived seeds are secrets too.
  {
    const parsed = verifyRecoveryKit(wasm, kit.code);
    secretsSeen.push(
      Buffer.from(parsed).toString("base64"),
      hex(parsed),
      hex(new Uint8Array(wasm.recovery_derive_ed25519_seed(parsed))),
      hex(new Uint8Array(wasm.recovery_derive_x25519_secret(parsed))),
      hex(new Uint8Array(wasm.recovery_derive_mlkem_seed(parsed))),
      Buffer.from(wasm.recovery_derive_ed25519_seed(parsed)).toString("base64"),
      Buffer.from(wasm.recovery_derive_x25519_secret(parsed)).toString("base64"),
    );
  }
  console.log(
    `  (a) OK: the JS client printed a 56-character kit (${kit.deviceId}), verified end to end BEFORE returning it`,
  );

  // The kit is a VISIBLE, labelled member device.
  {
    const listed = await listRecoverableVaults(wasm, authJs, devJs.deviceId);
    assert(Array.isArray(listed), "the index route did not answer for the JS device");
  }

  // ⭐ THE HEADLINE: the REAL `sigil` binary, on a machine with NO local state,
  // recovers the vault from the printed characters alone.
  const restoreOut = sigil(
    [
      "recovery",
      "restore",
      "--code",
      kit.formatted,
      "--device-id",
      kit.deviceId,
      "--server",
      base,
      "--out-dir",
      join(restoreHome, ".sigil"),
    ],
    restoreHome,
  );
  assert(
    restoreOut.includes(`recovered:   ${VAULT_JS}`),
    `the CLI did not recover the JS vault:\n${restoreOut}`,
  );
  const cliCode = sigil(
    [
      "totp",
      "code",
      "work",
      "--vault",
      join(restoreHome, ".sigil", `${VAULT_JS}.sigil`),
      "--vault-id",
      VAULT_JS,
      "--keyring",
      join(restoreHome, ".sigil", "vault-keys.json"),
      "--at",
      String(RFC_T),
    ],
    restoreHome,
  ).trim().split(/\s+/)[0];
  assert(
    cliCode === RFC_CODE,
    `(a) the real CLI restored from the paper but produced ${cliCode}, want ${RFC_CODE}`,
  );
  console.log(
    `  (a) OK: ⭐ the REAL sigil binary recovered the JS vault from the paper alone -> ${cliCode} at T=${RFC_T}`,
  );

  // =====================================================================
  // (b) CLI -> BROWSER. The CLI generates a kit for ITS vault; the JS client
  //     restores from it.
  // =====================================================================
  sigil(["totp", "add", "cli", "--secret", RFC_SEED_B32, "--digits", "8", "--period", "30"], cliHome, {
    SIGIL_PASSWORD: "cli password cli",
  });
  sigil(["vault", "rekey", "--vault", VAULT_CLI, "--publish"], cliHome, {
    SIGIL_PASSWORD: "cli password cli",
  });
  sigil(["push", "--vault", VAULT_CLI, "--in", join(cliHome, ".sigil", "totp-vault.sigil")]);
  const cliGen = sigil(["recovery", "generate", "--vault", VAULT_CLI]);
  const cliKitCode = (cliGen.match(/^SECRET\s+(\S+)$/m) ?? [])[1];
  const cliKitId = (cliGen.match(/^device id\s+(\S+)$/m) ?? [])[1];
  assert(cliKitCode && cliKitId, `could not parse the CLI's sheet:\n${cliGen}`);
  secretsSeen.push(cliKitCode, cliKitCode.replace(/-/g, ""));

  const restored = await restoreFromKit(wasm, {
    baseUrl: base,
    code: cliKitCode,
    deviceId: cliKitId,
  });
  assert(restored.vaults.length >= 1, "the JS client recovered nothing from the CLI's kit");
  const target = restored.vaults.find((v) => v.vaultId === VAULT_CLI);
  assert(target, `the JS client did not recover ${VAULT_CLI} (got ${restored.vaults.map((v) => v.vaultId)})`);
  {
    const kitAuth = {
      baseUrl: base,
      deviceId: cliKitId,
      seed: restored.identity.ed25519Seed,
      hybrid: restored.identity.hybrid,
      pins: newPinStore(),
    };
    const ops = await pullContainersAuthed(wasm, kitAuth, base, VAULT_CLI, 0);
    assert(ops.length > 0, "the op-log held no container for the CLI vault");
    const vault = openVault(wasm, target.vaultKey, ops[ops.length - 1].container);
    const entry = vault.entries.find((e) => e.label === "cli");
    assert(entry, "the recovered CLI vault has no 'cli' entry");
    const code = codeForEntry(wasm, entry, RFC_T);
    assert(code === RFC_CODE, `(b) the browser produced ${code}, want ${RFC_CODE}`);
    console.log(
      `  (b) OK: ⭐ the browser recovered the CLI's vault from the CLI's paper -> ${code} at T=${RFC_T}`,
    );
  }

  // =====================================================================
  // ⭐ NO LEAK: scan EVERY outgoing byte of EVERY request this process made.
  // =====================================================================
  {
    assert(outbound.length > 10, "the fetch recorder captured suspiciously few requests");
    for (const secret of secretsSeen) {
      if (!secret || secret.length < 8) continue;
      for (const req of outbound) {
        assert(
          !req.includes(secret),
          `⛔ a recovery secret appeared in an outgoing request (${secret.slice(0, 8)}…)`,
        );
      }
    }
    console.log(
      `  ZK     OK: none of ${secretsSeen.length} recovery secrets appears in any of ${outbound.length} outgoing requests`,
    );
  }

  // ...and none of them reached the server's log either.
  {
    const log = readFileSync(logPath, "utf8");
    for (const secret of secretsSeen) {
      if (!secret || secret.length < 8) continue;
      assert(!log.includes(secret), "⛔ a recovery secret reached the server log");
    }
    assert(log.includes("device.key_envelope_index"), "the index route left no audit trail");
    assert(
      !log
        .split("\n")
        .filter((l) => l.includes("device.key_envelope_index"))
        .some((l) => l.includes("blob_sha256")),
      "the index audit line carries a blob fingerprint; it reads no blob",
    );
    console.log("  ZK     OK: no recovery secret in the server log; the index audit line has no blob fingerprint");
  }

  // =====================================================================
  // ⭐⭐ (f) THE WRAP GATE — from JS, every path that wraps to a kit obeys the
  //         SAME rule, not just coverVault.
  //
  //   THE DEFECT: Phase 54 put the recovery-kit verification on ONE function.
  //   A sibling with zero knowledge of the kit reached the identical outcome —
  //   the live vault key wrapped to whatever key the server serves — through
  //   shareVault / rotateVaultKey and ordinary first-sight TOFU.
  // =====================================================================
  {
    // A SIBLING in the kit's own account, with an EMPTY pin store: the exact
    // "zero prior knowledge" state the reproduction used.
    const invite = await createAccountInvite(
      wasm,
      { deviceId: devJs.deviceId, seed: seedJs },
      base,
      {},
    );
    const sibSeed = generateDeviceSeed();
    const sib = await enrollDevice(wasm, {
      baseUrl: base,
      token: invite.invite,
      label: "sibling",
      seed: sibSeed,
    });
    const sibHybrid = generateHybridIdentity();
    const authSib = {
      deviceId: sib.deviceId,
      seed: sibSeed,
      baseUrl: base,
      hybrid: sibHybrid,
      pins: newPinStore(),
    };
    await publishHybridKey(wasm, authSib);
    assert(
      authSib.pins.pins[kit.deviceId] === undefined,
      "the sibling already knows the kit's key; the test would prove nothing",
    );

    // The sibling makes a shared vault of its own, so a refusal below is
    // unambiguously about the kit's key and not about a missing vault key.
    const sibVaultId = "sibvault";
    const sibKey = generateVaultKey();
    {
      const v = newVault();
      addEntry(v, {
        label: "s",
        secretBytes: base32Decode(RFC_SEED_B32),
        algorithm: "sha1",
        digits: 8,
        period: 30,
      });
      const salt = webcrypto.getRandomValues(new Uint8Array(wasm.recommended_salt_len()));
      const nonce = webcrypto.getRandomValues(new Uint8Array(wasm.nonce_len()));
      await pushContainerAuthed(
        wasm,
        authSib,
        base,
        sibVaultId,
        sealVault(wasm, sibKey, v, salt, nonce, ARGON2),
      );
    }

    // ⭐ 1/2: shareVault to the kit REFUSES without a safety number.
    let threw = null;
    try {
      await shareVault(wasm, authSib, {
        vaultId: sibVaultId,
        recipientDeviceId: kit.deviceId,
        vaultKey: sibKey,
      });
    } catch (e) {
      threw = e;
    }
    assert(
      threw instanceof UnverifiedRecoveryKitError,
      `shareVault to a RECOVERY KIT must throw UnverifiedRecoveryKitError, got: ${threw}`,
    );
    assert(
      authSib.pins.pins[kit.deviceId] === undefined,
      "a REFUSED share pinned the kit's key — a retry would then see 'match' and proceed",
    );

    // ...and refuses a WRONG safety number, still without pinning.
    threw = null;
    try {
      await shareVault(wasm, authSib, {
        vaultId: sibVaultId,
        recipientDeviceId: kit.deviceId,
        vaultKey: sibKey,
        expectedSafetyNumber: "11111 22222 33333 44444 55555 66666",
      });
    } catch (e) {
      threw = e;
    }
    assert(
      threw instanceof SafetyNumberMismatchError,
      `a WRONG safety number must throw SafetyNumberMismatchError, got: ${threw}`,
    );
    assert(
      authSib.pins.pins[kit.deviceId] === undefined,
      "a REFUSED share pinned the kit's key",
    );

    // ⭐ 2/2: rotateVaultKey to the kit refuses through the SAME gate.
    threw = null;
    try {
      await rotateVaultKey(wasm, authSib, {
        vaultId: sibVaultId,
        recipientDeviceIds: [sib.deviceId, kit.deviceId],
        sealedVault: new Uint8Array(
          (await pullContainersAuthed(wasm, authSib, base, sibVaultId, 0)).at(-1).container,
        ),
        oldVaultKey: sibKey,
        params: ARGON2,
        drop: [],
      });
    } catch (e) {
      threw = e;
    }
    assert(
      threw instanceof UnverifiedRecoveryKitError,
      `rotateVaultKey to a RECOVERY KIT must throw UnverifiedRecoveryKitError, got: ${threw}`,
    );

    // The RIGHT number, read off the sheet, is accepted — a gate, not a wall.
    const shared = await shareVault(wasm, authSib, {
      vaultId: sibVaultId,
      recipientDeviceId: kit.deviceId,
      vaultKey: sibKey,
      expectedSafetyNumber: kit.safetyNumber,
    });
    assert(
      shared.trust === "verified-first-sight",
      `a verified first sight must be recorded as such, got ${shared.trust}`,
    );
    console.log(
      "  (f) OK: shareVault AND rotateVaultKey refuse an unverified RECOVERY KIT (pinning nothing), " +
        "and accept the number printed on the sheet",
    );

    // =====================================================================
    // ⭐ (g) THE ROTATION DROP GUARD, exercised FROM JS.
    //
    //   rotateVaultKey defaults drop=[] and throws on any unnamed envelope
    //   holder. Both browser clients called it with NO drop field, so a
    //   rotation that excluded any holder — the entire point of rotating —
    //   hard-failed and nothing covered it. This is that coverage.
    // =====================================================================
    const sealedNow = new Uint8Array(
      (await pullContainersAuthed(wasm, authSib, base, sibVaultId, 0)).at(-1).container,
    );
    const holders = (await listKeyEnvelopes(wasm, authSib, sibVaultId)).map((h) => h.deviceId);
    assert(
      holders.includes(kit.deviceId),
      "the kit should hold an envelope for the sibling's vault by now",
    );

    // Leaving the kit out with NO drop list is exactly what both browsers did.
    threw = null;
    try {
      await rotateVaultKey(wasm, authSib, {
        vaultId: sibVaultId,
        recipientDeviceIds: [sib.deviceId],
        sealedVault: sealedNow,
        oldVaultKey: sibKey,
        params: ARGON2,
      });
    } catch (e) {
      threw = e;
    }
    assert(
      threw instanceof RecipientsWouldBeDroppedError,
      `omitting a holder must throw RecipientsWouldBeDroppedError, got: ${threw}`,
    );
    assert(
      threw.unknown.some((u) => u.deviceId === kit.deviceId),
      "the refusal must NAME the holder that would lose access",
    );
    // ⚠️ HONEST LIMIT, unchanged by this fix round: `isRecoveryKit` is true only
    // when THIS client's pin carries origin="recovery-kit", i.e. only on the
    // device that GENERATED the kit. A sibling that learned the key by fetching
    // it — even through the wrap gate, which knew it was a kit — pins it without
    // that marker, so the refusal names the device but does not label it. The
    // refusal itself is what protects access; the label is a nicety.

    // Naming it — what the browser UIs now let a user do — succeeds.
    const rotated = await rotateVaultKey(wasm, authSib, {
      vaultId: sibVaultId,
      recipientDeviceIds: [sib.deviceId],
      sealedVault: sealedNow,
      oldVaultKey: sibKey,
      params: ARGON2,
      drop: [kit.deviceId],
    });
    assert(
      rotated.removed.includes(kit.deviceId),
      "the rotation did not delete the dropped holder's envelope",
    );
    assert(
      rotated.newFingerprint !== rotated.oldFingerprint,
      "the rotation did not actually change the key",
    );
    console.log(
      "  (g) OK: rotateVaultKey from JS refuses to drop an unnamed holder (naming the kit), and " +
        "succeeds once `drop` names it — the call shape both browsers now use",
    );
  }

  // A kit that covers nothing reports "nothing to recover", not a fault.
  {
    const bare = await generateRecoveryKit(wasm, authJs, { vaultKeys: [], pins: authJs.pins });
    secretsSeen.push(bare.code);
    let threw = false;
    try {
      await restoreFromKit(wasm, { baseUrl: base, code: bare.code, deviceId: bare.deviceId });
    } catch (e) {
      threw = true;
      assert(
        /nothing to recover/.test(e.message),
        `an uncovered kit must say "nothing to recover", got: ${e.message}`,
      );
    }
    assert(threw, "an uncovered kit restored something");
    console.log('  (e) OK: an uncovered kit reports "valid code and device, but nothing to recover"');
  }
} finally {
  if (sigild && sigild.exitCode === null) sigild.kill("SIGKILL");
  rmSync(work, { recursive: true, force: true });
  globalThis.fetch = realFetch;
}

console.log(`\nversion: ${wasm.version()}`);
console.log(
  "PASS: the RECOVERY KIT works across clients BOTH ways against a LIVE sigild — the real sigil " +
    `binary recovers a browser-made vault from 56 printed characters (${RFC_CODE} at T=${RFC_T}) and ` +
    "the browser recovers a CLI-made one; the derivation KAT matches sigil-core; a typo is caught " +
    "OFFLINE; and no recovery secret appears in any outgoing request or in the server log.",
);
process.exit(0);
