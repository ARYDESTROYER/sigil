// accounts-interop.mjs — end-to-end proof that a BROWSER-STYLE JS client speaks
// sigild's ACCOUNT model (Phase 52), and that it is the SAME account the real
// `sigil` CLI joins.
//
// WHY THIS TEST EXISTS. Before accounts, a subscription belonged to a DEVICE and
// a vault was owned by a DEVICE. So paying on your phone did not entitle your
// laptop, and revoking the device that first wrote a vault ORPHANED that vault
// forever. An account is a server-assigned id on the device row that entitlement
// and vault ownership key off instead. This file proves the client half of that,
// twice over — once in JS, once by handing a JS-minted invite to the real Rust
// binary — because an account model that only one client can speak is not one.
//
// It builds sigild AND the real `sigil` CLI, boots the server on a free
// localhost port with the device model ON, and then proves against the LIVE
// server:
//
//   (a) FOUND      — a JS device enrolls with an OPERATOR token and founds an
//                    account; GET /v1/account reports it with one member.
//   (b) INVITE     — that device mints a single-use invite. The secret appears in
//                    exactly ONE response and NEVER in the listing.
//   (c) ★ CROSS    — the REAL `sigil` CLI redeems that JS-minted invite with the
//                    ORDINARY `sigil device enroll --token <invite>`, and lands in
//                    the SAME account. No new command, no new wire format.
//   (d) JS JOINS   — a second JS device joins by invite too, and both JS devices
//                    and the CLI device appear in ONE account listing.
//   (e) ★ SIBLING  — device A claims a vault and is REVOKED; sibling B, which was
//                    granted NOTHING, still reads and writes it. That is the
//                    orphaned-vault defect, fixed.
//   (f) ISOLATION  — a device enrolled with its own OPERATOR token lands in a
//                    DIFFERENT account, is 403 on the first account's vault, and
//                    sees only itself in GET /v1/account.
//   (g) NEGATIVES  — a redeemed invite is 401; a foreign invite handle is 404
//                    (indistinguishable from a missing one); the open-invite
//                    quota is 409; an unsigned account call is 401.
//
// Plus the invariant that shapes the whole design: NO REQUEST NAMES AN ACCOUNT.
// A mint body carrying `account_id` / `subject` is ignored — the invite lands in
// the caller's own account, because the server reads it off the signature.
//
// Pre-audit / UNAUDITED / DEV / LOCALHOST / PLAIN-HTTP. Usage:
//   node test/accounts-interop.mjs
// Exits 0 with a PASS line, non-zero on any failure. Always kills the server and
// removes its temp workspace in a finally block.

import { webcrypto } from "node:crypto";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync, mkdtempSync, mkdirSync, rmSync } from "node:fs";
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
  revokeDeviceAdmin,
  getAccount,
  createAccountInvite,
  listAccountInvites,
  revokeAccountInvite,
  DeviceAuthError,
} from "../device-auth.mjs";

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
const goBin = existsSync("/opt/homebrew/bin/go") ? "/opt/homebrew/bin/go" : "go";

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

const work = mkdtempSync(join(tmpdir(), "sigil-accounts-"));
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

console.log("building the real sigil CLI (cargo build --bin sigil) ...");
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

const M_COST = 8;
const T_COST = 1;
const P_COST = 1;

const TOKEN_A = "enroll-token-A-0123456789";
const TOKEN_X = "enroll-token-X-0123456789";
const ADMIN_TOKEN = "admin-token-0123456789";

/** Run the REAL sigil binary as one device (its own HOME = its own identity). */
function sigil(home, base, args) {
  return execFileSync(sigilBin, args, {
    env: {
      ...toolEnv,
      HOME: home,
      SIGIL_SERVER: base,
      SIGIL_DEVICE_KEY: join(home, ".sigil", "device.key"),
    },
    encoding: "utf8",
  });
}

let sigild = null;
try {
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  console.log(`starting sigild on ${base} (dev-ops + device auth v3 + accounts) ...`);
  sigild = spawn(sigildBin, [], {
    env: {
      ...process.env,
      SIGILD_ADDR: `127.0.0.1:${port}`,
      SIGILD_ENABLE_DEV_OPS: "1",
      SIGILD_DEVICE_AUTH: "1",
      SIGILD_ENROLL_TOKENS: `${TOKEN_A},${TOKEN_X}`,
      SIGILD_ADMIN_TOKEN: ADMIN_TOKEN,
      SIGILD_ACCOUNT_MAX_DEVICES: "4",
      SIGILD_ACCOUNT_MAX_INVITES: "2",
      SIGILD_ACCOUNT_INVITE_TTL: "10m",
    },
    stdio: ["ignore", "inherit", "inherit"],
  });
  sigild.on("error", (e) => fail(`sigild failed to spawn: ${e.message}`));
  await waitReady(base);
  console.log("sigild is ready.\n");

  // --- GUARD: an UNSIGNED account call is refused. ---
  {
    const res = await fetch(`${base}/v1/account`);
    assert(res.status === 401, `unsigned GET /v1/account should be 401, got ${res.status}`);
    console.log("  GUARD  OK: an UNSIGNED account request is refused 401");
  }

  // ===================================================================
  // (a) A JS device enrolls with an OPERATOR token and FOUNDS an account.
  // ===================================================================
  const seedA = generateDeviceSeed();
  const devA = await enrollDevice(wasm, {
    baseUrl: base,
    token: TOKEN_A,
    label: "browser-A",
    seed: seedA,
  });
  const idA = { deviceId: devA.deviceId, seed: seedA };
  assert(
    typeof devA.accountId === "string" && devA.accountId.startsWith("acct_"),
    `(a) enrollment did not report an account id: ${JSON.stringify(devA.accountId)}`,
  );

  const acctA = await getAccount(wasm, idA, base);
  assert(acctA.account_id === devA.accountId, "(a) GET /v1/account disagrees with the enroll response");
  assert(acctA.device_count === 1, `(a) expected 1 member, got ${acctA.device_count}`);
  assert(acctA.device_limit === 4, `(a) expected the configured device limit 4, got ${acctA.device_limit}`);
  assert(acctA.devices.length === 1 && acctA.devices[0].device_id === devA.deviceId, "(a) wrong member list");
  console.log(`  (a) OK: browser device ${devA.deviceId} founded account ${acctA.account_id} (1/4 devices)`);

  // ===================================================================
  // (b) It mints a single-use invite. The secret is served exactly once.
  // ===================================================================
  const invite1 = await createAccountInvite(wasm, idA, base, { ttlSeconds: 300 });
  assert(typeof invite1.invite === "string" && invite1.invite.startsWith("join_"), "(b) no join_ secret");
  assert(invite1.invite_id.startsWith("inv_"), "(b) no public invite handle");
  assert(invite1.account_id === acctA.account_id, "(b) the invite is for another account");
  assert(invite1.pinned === false, "(b) an unpinned invite should report pinned:false");

  const open1 = await listAccountInvites(wasm, idA, base);
  assert(open1.invites.length === 1, `(b) expected 1 open invite, got ${open1.invites.length}`);
  assert(open1.invites[0].invite_id === invite1.invite_id, "(b) the listing lost the handle");
  const listingText = JSON.stringify(open1);
  assert(!listingText.includes(invite1.invite), "(b) THE LISTING ECHOED THE INVITE SECRET");
  assert(!listingText.includes("invite_hash"), "(b) the listing leaked the redemption digest");
  console.log("  (b) OK: the invite secret appears in exactly ONE response; the listing is metadata only");

  // The structural rule: a body naming an account is IGNORED.
  {
    const body = enc.encode(
      JSON.stringify({ account_id: "acct_SOMEONE_ELSE", subject: "acct_SOMEONE_ELSE" }),
    );
    const res = await signedFetch(
      wasm,
      { ...idA, baseUrl: base },
      "POST",
      "/v1/account/invites",
      "",
      body,
      { "Content-Type": "application/json" },
    );
    assert(res.status === 201, `(b) mint with a hostile body should still be 201, got ${res.status}`);
    const hostile = await res.json();
    assert(
      hostile.account_id === acctA.account_id,
      `(b) a BODY FIELD STEERED THE ACCOUNT: ${hostile.account_id}`,
    );
    // Clean it up so it does not eat the quota.
    await revokeAccountInvite(wasm, idA, base, hostile.invite_id);
    console.log("  (b) OK: a mint body naming another account is ignored — no request names an account");
  }

  // ===================================================================
  // (c) ★ THE REAL sigil CLI redeems the JS-minted invite.
  // ===================================================================
  const homeCli = join(work, "cli-device");
  mkdirSync(homeCli, { recursive: true });
  const enrollOut = sigil(homeCli, base, [
    "device",
    "enroll",
    "--token",
    invite1.invite,
    "--label",
    "rust-cli",
  ]);
  const cliDeviceId = (enrollOut.match(/dev_[A-Za-z0-9_-]+/) ?? [])[0];
  assert(cliDeviceId, `(c) the CLI did not report a device id: ${enrollOut}`);

  const cliStatus = sigil(homeCli, base, ["account", "status"]);
  assert(
    cliStatus.includes(acctA.account_id),
    `(c) the CLI landed in a different account:\n${cliStatus}`,
  );
  assert(cliStatus.includes("devices: 2/4"), `(c) the CLI does not see 2 members:\n${cliStatus}`);
  console.log(
    `  (c) OK: the REAL sigil CLI joined account ${acctA.account_id} with a JS-minted invite ` +
      `(device ${cliDeviceId}) — unchanged enroll command, unchanged wire format`,
  );

  // ===================================================================
  // (d) A second JS device joins; all three appear in ONE account.
  // ===================================================================
  const seedB = generateDeviceSeed();
  const pubB = devicePublicKey(wasm, seedB);
  // PINNED to B's public key: an intercepted invite is then useless to anyone else.
  const invite2 = await createAccountInvite(wasm, idA, base, { inviteePublicKey: pubB });
  assert(invite2.pinned === true, "(d) a key-pinned invite must report pinned:true");

  const devB = await enrollDevice(wasm, {
    baseUrl: base,
    token: invite2.invite,
    label: "browser-B",
    seed: seedB,
  });
  const idB = { deviceId: devB.deviceId, seed: seedB };
  assert(devB.accountId === acctA.account_id, `(d) B joined ${devB.accountId}, not ${acctA.account_id}`);

  const acctFromB = await getAccount(wasm, idB, base);
  assert(acctFromB.account_id === acctA.account_id, "(d) B reports a different account");
  assert(acctFromB.device_count === 3, `(d) expected 3 members, got ${acctFromB.device_count}`);
  const members = acctFromB.devices.map((d) => d.device_id).sort();
  assert(
    members.includes(devA.deviceId) && members.includes(devB.deviceId) && members.includes(cliDeviceId),
    `(d) the member list is missing someone: ${members.join(", ")}`,
  );
  console.log(`  (d) OK: one account, three members (2 browser + 1 CLI), via a KEY-PINNED invite`);

  // ===================================================================
  // (e) ★ THE ORPHANED-VAULT DEFECT: revoke the claimant, the sibling lives.
  // ===================================================================
  const vault = "account-owned-vault";
  const password = enc.encode("correct horse battery staple");
  const plaintext = enc.encode("PHASE52-account-owned-🔑");
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

  {
    // A's first WRITE claims the vault — for the ACCOUNT, not the device.
    const { seq } = await pushContainerAuthed(wasm, idA, base, vault, container);
    assert(seq === 1, `(e) first push should be seq 1, got ${seq}`);

    // The operator revokes A. Before Phase 52 this orphaned the vault forever.
    await revokeDeviceAdmin({ baseUrl: base, adminToken: ADMIN_TOKEN, deviceId: devA.deviceId });
    await expectStatus(401, () => getAccount(wasm, idA, base), "(e) the revoked device");

    // B holds NO grant. Its authorization comes from the account owning the vault.
    const pulled = await pullContainersAuthed(wasm, idB, base, vault, 0);
    assert(pulled.length === 1, `(e) sibling B pulled ${pulled.length} ops, expected 1`);
    assert(
      bytesEqual(pulled[0].container, container),
      "(e) the server did not return the pushed bytes verbatim (zero-knowledge violated)",
    );
    const recovered = wasm.open_container(password, pulled[0].container);
    assert(bytesEqual(recovered, plaintext), "(e) the sibling could not open the container");

    const { seq: seq2 } = await pushContainerAuthed(wasm, idB, base, vault, container);
    assert(seq2 === 2, `(e) sibling B's write should be seq 2, got ${seq2}`);
    console.log(
      "  (e) OK: the vault's CLAIMANT was revoked and its sibling — with NO grant row — still read AND wrote it",
    );
  }

  // ===================================================================
  // (f) A device with its OWN operator token is a DIFFERENT account, 403.
  // ===================================================================
  const seedX = generateDeviceSeed();
  const devX = await enrollDevice(wasm, {
    baseUrl: base,
    token: TOKEN_X,
    label: "browser-X",
    seed: seedX,
  });
  const idX = { deviceId: devX.deviceId, seed: seedX };
  assert(
    devX.accountId !== acctA.account_id,
    "(f) an OPERATOR token must always found a NEW account, never join one",
  );

  const acctX = await getAccount(wasm, idX, base);
  assert(acctX.device_count === 1, `(f) X's account should hold only X, got ${acctX.device_count}`);
  const xMembers = JSON.stringify(acctX.devices);
  assert(
    !xMembers.includes(devB.deviceId) && !xMembers.includes(cliDeviceId),
    "(f) X's account listing LEAKED another account's members",
  );
  await expectStatus(403, () => pullContainersAuthed(wasm, idX, base, vault, 0), "(f) foreign read");
  await expectStatus(
    403,
    () => pushContainerAuthed(wasm, idX, base, vault, container),
    "(f) foreign write",
  );
  console.log(
    `  (f) OK: an operator token founded a SEPARATE account (${acctX.account_id}); it is 403 on the first account's vault and sees only itself`,
  );

  // ===================================================================
  // (g) The negatives.
  // ===================================================================
  {
    // A redeemed invite cannot be redeemed twice.
    const seedDup = generateDeviceSeed();
    const e1 = await expectStatus(
      401,
      () =>
        enrollDevice(wasm, {
          baseUrl: base,
          token: invite1.invite,
          label: "should-fail",
          seed: seedDup,
        }),
      "(g) reusing a redeemed invite",
    );
    assert(e1 instanceof DeviceAuthError, "(g) expected a DeviceAuthError");

    // A FOREIGN invite handle is 404 — exactly like one that never existed.
    const foreign = await createAccountInvite(wasm, idX, base, {});
    await expectStatus(
      404,
      () => revokeAccountInvite(wasm, idB, base, foreign.invite_id),
      "(g) revoking another account's invite",
    );
    await expectStatus(
      404,
      () => revokeAccountInvite(wasm, idB, base, "inv_doesNotExistAtAll"),
      "(g) revoking a nonexistent invite",
    );

    // The OPEN-invite quota (SIGILD_ACCOUNT_MAX_INVITES=2) is enforced.
    await createAccountInvite(wasm, idB, base, {});
    await createAccountInvite(wasm, idB, base, {});
    await expectStatus(409, () => createAccountInvite(wasm, idB, base, {}), "(g) the invite quota");
    console.log(
      "  (g) OK: a redeemed invite is 401; a FOREIGN handle and a MISSING one are both 404; the open-invite quota is 409",
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
  "PASS: a browser-style JS client speaks the ACCOUNT model against a LIVE sigild, and it is the " +
    "SAME account the real sigil CLI joins (a found; b invite served once; c ★ CLI redeems a " +
    "JS-minted invite; d 3 members via a pinned invite; e ★ revoked claimant, sibling still reads " +
    "AND writes; f separate account is 403; g reuse/foreign-handle/quota negatives)",
);
process.exit(0);
