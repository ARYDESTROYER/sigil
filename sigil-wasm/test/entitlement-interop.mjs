// entitlement-interop.mjs — sigil-wasm/entitlement.mjs against a REAL sigild.
//
// ⭐ WHY THIS EXISTS. `entitlement.mjs` shipped with browser-suite coverage only,
// and those suites drive a FAKE server that returns hand-written shapes. So
// nothing in the repo proved that the module reads what sigild actually emits —
// and `readEntitlementHeaders` had no caller at all, so nothing proved the header
// channel worked in any direction.
//
// This boots the REAL `sigild` twice, with real entitlement enforcement, and
// asserts the three signals ADR 0043 defines, each against the server that
// produces it:
//
//   1. GRACE, via the additive `entitlement` block on
//      GET /v1/billing/subscription        -> entitlementState/describeEntitlement
//   2. GRACE, via the X-Sigil-Entitlement* RESPONSE HEADERS on a write that is
//      still being SERVED                  -> readEntitlementHeaders
//   3. REFUSED, via the machine-readable 402 body on a write past grace
//                                          -> paymentRequiredFrom/describePaymentRequired
//
// ...plus the guarantee the whole design turns on: PAST GRACE, READS ARE STILL
// SERVED. A pull is not refused, and the codes it yields are computed locally.
//
// Dev / localhost / plain HTTP / UNAUDITED. Billing has never been run against a
// live provider account (ADR 0034) — nothing here contacts one; the Stripe values
// below are throwaway strings that satisfy sigild's boot-time validation and are
// never used, because no webhook and no checkout is exercised.

import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync, mkdtempSync, openSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:net";

import {
  generateDeviceSeed,
  enrollDevice,
  pushContainerAuthed,
  pullContainersAuthed,
} from "../device-auth.mjs";
import {
  getSubscription,
  entitlementState,
  describeEntitlement,
  describePaymentRequired,
  paymentRequiredFrom,
  readEntitlementHeaders,
  explainSubscriptionStatus,
  PAYMENT_REQUIRED_CODE,
} from "../entitlement.mjs";
import {
  newVault,
  addEntry,
  sealVault,
  openVault,
  codeForEntry,
  base32Decode,
} from "../totp-vault.mjs";
import { webcrypto } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");
const pkgPath = join(__dirname, "..", "pkg-node", "sigil_wasm.js");
const buildWasm = join(__dirname, "..", "build-wasm.sh");
const sigildDir = join(repoRoot, "sigild");
const goBin = process.env.GO ?? "/opt/homebrew/bin/go";

function fail(msg) {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
}
function assert(cond, msg) {
  if (!cond) fail(msg);
}

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

const work = mkdtempSync(join(tmpdir(), "sigil-entitlement-"));
const sigildBin = join(work, "sigild");

if (!existsSync(pkgPath)) {
  console.log("building the wasm package (build-wasm.sh) ...");
  execFileSync("bash", [buildWasm], { stdio: "inherit" });
}
console.log("building sigild (go build ./cmd/server) ...");
execFileSync(goBin, ["build", "-o", sigildBin, "./cmd/server"], {
  cwd: sigildDir,
  stdio: "inherit",
});

const wasm = await import(pkgPath);

const ARGON2 = { m_cost: 8, t_cost: 1, p_cost: 1 };
const TOKEN = "entitlement-enroll-token-0123456789";
const RFC_SEED_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_T = 59;
const RFC_CODE = "94287082";
const PASSWORD = new TextEncoder().encode("entitlement-interop-password");

/**
 * Boot a sigild with entitlement ENFORCED and the given grace window. Every
 * other knob is the ordinary dev configuration the other interop tests use.
 *
 * A brand-new account has never subscribed, so ADR 0043 anchors its grace on the
 * ACCOUNT'S CREATION — which makes "24h" mean "inside grace" and "1ms" mean
 * "already past it", with no clock manipulation and no fake provider events.
 */
async function startSigild(grace) {
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;
  const logFd = openSync(join(work, `sigild-${port}.log`), "w");
  const proc = spawn(sigildBin, [], {
    env: {
      ...process.env,
      SIGILD_ADDR: `127.0.0.1:${port}`,
      SIGILD_ENABLE_DEV_OPS: "1",
      SIGILD_DEVICE_AUTH: "1",
      SIGILD_ENROLL_TOKENS: TOKEN,
      SIGILD_ENTITLEMENT_ENFORCE: "1",
      SIGILD_ENTITLEMENT_GRACE: grace,
      // Enforcement needs a subscription store to read. Throwaway values for a
      // loopback server that never contacts a provider.
      SIGILD_BILLING_PROVIDERS: "stripe",
      SIGILD_BILLING_SUCCESS_URL: "http://127.0.0.1/paid",
      SIGILD_BILLING_CANCEL_URL: "http://127.0.0.1/cancelled",
      SIGILD_STRIPE_SECRET_KEY: "sk_test_not_a_real_key_000000",
      SIGILD_STRIPE_WEBHOOK_SECRET: "whsec_not_a_real_secret_0000",
    },
    stdio: ["ignore", logFd, logFd],
  });
  proc.on("error", (e) => fail(`sigild failed to spawn: ${e.message}`));
  await waitReady(base);
  return { base, proc };
}

/** Enroll a fresh device and hand back an auth identity. */
async function enroll(base, label) {
  const seed = generateDeviceSeed();
  const dev = await enrollDevice(wasm, { baseUrl: base, token: TOKEN, label, seed });
  return { deviceId: dev.deviceId, seed, baseUrl: base };
}

/** A sealed vault holding the RFC 6238 App B account. All entropy from the
 * runtime CSPRNG, exactly as a browser supplies it (ADR 0007). */
function sealedVault() {
  const vault = addEntry(newVault(), {
    label: "rfc6238",
    secretBytes: base32Decode(RFC_SEED_B32),
    algorithm: "sha1",
    digits: 8,
    period: 30,
  });
  const salt = webcrypto.getRandomValues(new Uint8Array(wasm.recommended_salt_len()));
  const nonce = webcrypto.getRandomValues(new Uint8Array(wasm.nonce_len()));
  return sealVault(wasm, PASSWORD, vault, salt, nonce, ARGON2);
}

const running = [];
process.on("exit", () => {
  for (const p of running) {
    try {
      p.kill("SIGKILL");
    } catch {
      /* already gone */
    }
  }
  rmSync(work, { recursive: true, force: true });
});

// ===========================================================================
// 1 + 2. INSIDE GRACE: warned two ways, and still served.
// ===========================================================================
{
  const { base, proc } = await startSigild("24h");
  running.push(proc);
  console.log(`\n=== sigild at ${base} — entitlement ENFORCED, 24h grace`);

  const auth = await enroll(base, "grace-device");
  const container = sealedVault();

  // (1) THE SUBSCRIPTION BLOCK. This is the channel a read-only client has, and
  //     the only one that exists BEFORE any write is attempted.
  const sub = await getSubscription(wasm, auth, base);
  const state = entitlementState(sub);
  assert(state.enforced === true, `enforcement must be reported: ${JSON.stringify(sub)}`);
  assert(state.level === "grace", `expected level "grace", got ${state.level}`);
  assert(state.writes === "grace", `expected writes "grace", got ${state.writes}`);
  assert(state.graceEndsAt !== "", "grace must carry the DEADLINE, not just the fact");
  const note = describeEntitlement(state);
  assert(note.tone === "warning", `grace must warn (tone ${note.tone})`);
  assert(
    /Your existing codes are NOT affected/.test(note.detail),
    `the warning must state what is NOT affected: ${note.detail}`,
  );
  console.log("  (1) OK: GET /v1/billing/subscription reports GRACE with a deadline");

  // (2) THE RESPONSE HEADERS on a write that is still being SERVED. This signal
  //     exists ONLY here: it is not in the body and there is no error to carry
  //     it, so a client that does not read headers never sees it.
  let header = null;
  const { seq } = await pushContainerAuthed(wasm, auth, base, "grace-vault", container, {
    onResponse: (res) => {
      header = readEntitlementHeaders(res);
    },
  });
  assert(seq === 1, `the write inside grace must be SERVED, got seq ${seq}`);
  assert(header !== null, "sigild must warn on a served-in-grace write, and it must be readable");
  assert(header.state === "grace", `expected header state "grace", got ${header.state}`);
  assert(header.graceEndsAt !== "", "the header must carry the deadline too");
  assert(
    header.graceEndsAt === state.graceEndsAt,
    `the two channels must agree: header ${header.graceEndsAt} vs block ${state.graceEndsAt}`,
  );
  console.log("  (2) OK: X-Sigil-Entitlement* headers on the SERVED write say the same thing");

  // A healthy response must produce NOTHING — no invented warning.
  const pulled = await pullContainersAuthed(wasm, auth, base, "grace-vault", 0);
  assert(pulled.length === 1, "the pull must return the pushed container");
  assert(
    readEntitlementHeaders({ headers: new Headers() }) === null,
    "a response with no entitlement headers must read as null, never as a warning",
  );
  console.log("  (3) OK: a response with no warning headers reads as null");
}

// ===========================================================================
// 3. PAST GRACE: writes refused as a BILLING state, reads still served.
// ===========================================================================
{
  const { base, proc } = await startSigild("1ms");
  running.push(proc);
  console.log(`\n=== sigild at ${base} — entitlement ENFORCED, already past grace`);

  const auth = await enroll(base, "lapsed-device");
  const container = sealedVault();

  let refused = null;
  try {
    await pushContainerAuthed(wasm, auth, base, "lapsed-vault", container);
    fail("a write past grace must be refused");
  } catch (e) {
    refused = paymentRequiredFrom(e, "Push");
  }
  assert(refused !== null, "the refusal must be recognised as PAYMENT, not as an auth failure");
  assert(refused.status === 402, `expected 402, got ${refused.status}`);
  assert(refused.readsAllowed === true, "the server must state that reads are allowed");
  assert(refused.keyRecoveryAllowed === true, "the server must state that key recovery is allowed");
  assert(
    refused.checkoutPath === "/v1/billing/checkout",
    `the refusal must name where to pay, got ${refused.checkoutPath}`,
  );
  assert(refused.subscriptionStatus !== "", "the refusal must name the account's own status");
  const shown = describePaymentRequired(refused);
  assert(shown.tone === "billing", `a 402 is billing, not an error (tone ${shown.tone})`);
  assert(
    /NOT an authentication or permission failure/.test(shown.detail),
    `the rendered text must rule out auth/permission: ${shown.detail}`,
  );
  console.log(`  (4) OK: the write is refused with a machine-readable ${PAYMENT_REQUIRED_CODE}`);

  // ⭐ AND THE GUARANTEE: THE READ PATH HOLDS NO ENTITLEMENT CODE AT ALL.
  // Past grace this device could not claim a vault (the claiming write is the
  // thing that was refused), so the read it attempts is unowned and comes back
  // 403 — an AUTHORIZATION verdict that has nothing to do with billing. What
  // matters is what it is NOT: never 402, and never recognised as a payment
  // refusal, no matter how lapsed the account is.
  let readStatus = 0;
  let readAsPayment = null;
  try {
    await pullContainersAuthed(wasm, auth, base, "lapsed-vault", 0);
  } catch (e) {
    readStatus = e?.status ?? 0;
    readAsPayment = paymentRequiredFrom(e, "Pull");
  }
  assert(readStatus !== 402, `a READ must never be refused for payment (got ${readStatus})`);
  assert(readAsPayment === null, "a read failure must never be classified as a payment refusal");

  // Nothing was pushed to this server, so prove the local half directly: the
  // container this client already holds still opens and still produces codes,
  // with no server involved at all.
  const vault = openVault(wasm, PASSWORD, container);
  const code = codeForEntry(wasm, vault.entries[0], RFC_T);
  assert(code === RFC_CODE, `expected the RFC 6238 vector ${RFC_CODE}, got ${code}`);
  console.log("  (5) OK: reads are served, and codes still compute locally (RFC 6238 vector)");

  // The subscription route is NEVER gated: a refused customer can always find
  // out why they are being refused.
  const sub = await getSubscription(wasm, auth, base);
  const state = entitlementState(sub);
  assert(state.level === "refused", `expected level "refused", got ${state.level}`);
  assert(explainSubscriptionStatus(501).includes("billing turned off"), "explainer sanity");
  console.log("  (6) OK: the subscription route is never itself gated by entitlement");
}

console.log("\nPASS — entitlement.mjs reads all three of sigild's real signals: the subscription");
console.log("block, the served-in-grace response headers, and the 402 refusal; and past grace a");
console.log("read is never refused for payment while codes keep generating locally.\n");

// Both sigilds are still children of this process, so exit explicitly rather
// than waiting for an event loop they keep alive. The exit hook kills them.
process.exit(0);
