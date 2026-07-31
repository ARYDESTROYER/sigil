// merge-interop.mjs — ⭐⭐ THE HEADLINE PROOF for Phase 61: two devices each add
// a different account while offline, and after both sync BOTH accounts exist on
// BOTH devices and both still generate correct codes.
//
// ⛔ THE DEFECT IT EXISTS FOR. A vault syncs as whole sealed SNAPSHOTS through an
// append-only op-log, and every client ADOPTED THE NEWEST ONE WHOLESALE
// (`ops[ops.length - 1]` in the browsers, `pull_and_adopt` on the desktop). So:
// device A adds `alpha` and pushes; device B, which never pulled, adds `bravo`
// and pushes; B's snapshot is now the tip, it has never seen `alpha`, and the
// moment any client adopts the tip that account is GONE — with both devices
// reporting success. For an authenticator a lost 2FA secret can mean a
// permanently lost account. It was reproduced end to end against a real sigild
// before a line of the fix was written.
//
// ⭐ WHAT THIS PROVES, against a REAL sigild and the REAL `sigil` binary — no
// mocks, no double, two independent implementations of the merge (Rust and JS)
// meeting on one op-log:
//
//   HEADLINE  A (the real CLI) and B (the JS client) each add an account without
//             pulling first. Both sync. BOTH have BOTH, and the RFC 6238 vector
//             secret still yields 94287082 at T=59 — the SECRET survived, not
//             merely the label.
//   CONVERGE  A's and B's merged plaintext are BYTE-IDENTICAL. Convergence as an
//             equality, not a vibe: this is what a drifted Rust/JS mirror fails.
//   IDEMPOTENT A second sync round on a converged vault appends NO op. That is
//             what stops two devices pushing at each other forever.
//   DELETE    A removes an account and pushes. B — still holding it — merges and
//             it is GONE. B then pushes its (post-merge) snapshot and A merges
//             again: it STAYS gone. Without a tombstone a union resurrects it.
//   RE-ADD    A tombstone does not poison a genuine re-add: adding the account
//             back draws a FRESH id, so it survives the merge.
//   LEGACY    ONE pre-Phase-61 vault (no `uuid` anywhere) copied to two devices,
//             each normalising independently, merges to N entries and NOT 2N.
//             A RANDOM migration id would double every account in every existing
//             multi-device vault on first sync.
//   IMPORT    `work` at GitHub and `work` at GitLab BOTH import (they differ in
//             issuer and secret), and re-importing the same export imports NONE.
//   KAT       The content-derived entry id agrees byte for byte between
//             `sigil_core::entry_id` (via the wasm) and the shared known-answer
//             vector asserted in the Rust unit tests.
//   PROPERTY  600 GENERATED vault pairs merge order-independently, associatively
//             and idempotently — compared on the SERIALIZED BYTES. The
//             unqualified "commutative" claim had two real exceptions:
//             tombstone-level unknown fields merged FIRST-SEEN-WINS, and even
//             after that was fixed the VALUES converged while the BYTES did not.
//             ⚠️ This property compared through a key-sorting `canonJson` and so
//             passed 600/600 while the second one was true.
//   TOMB-XTRA Rust and JS pick the SAME winner for a conflicting unknown field
//             on a shared tombstone (the second cross-language ordering rule).
//   BYTES     ⭐ The REAL `sigil` binary and this JS module serialize the SAME
//             merged vault to BYTE-IDENTICAL plaintext — no parse, no
//             canonicalisation. `serde` writes declaration order with its
//             flattened `extra` sorted; JavaScript objects are insertion-ordered
//             and had to be taught to match. Two clients writing different bytes
//             for identical content makes every push a fresh op.
//   THREE-DEV ⭐ A THIRD device joining LATE — with offline work of its own, and
//             after the other two have already diverged AND merged — converges
//             byte-identically with both, and its delete propagates to both.
//             Two devices cannot distinguish a join from "the second one wins".
//   SIZE      ⛔ The TOMBSTONE GROWTH LIMIT is WARNED about before it becomes a
//             413. The remove-set never shrinks, nothing prunes it and there is
//             no compaction command, so a user who meets the cap without notice
//             has already lost the ability to sync.
//   OPAQUE    The server returned the pushed bytes verbatim — zero-knowledge
//             intact; it never learns an entry, an id or a tombstone exists.
//
// Pre-audit / UNAUDITED / DEV / LOCALHOST / PLAIN-HTTP. Do NOT store real 2FA
// secrets. Usage: `node test/merge-interop.mjs`. Exits 0 with a PASS line.

import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createServer, connect as tcpConnect } from "node:net";
import { request as httpRequest } from "node:http";

import { pushContainer, pullContainers } from "../sync.mjs";
import {
  openVault,
  sealVault,
  newVault,
  addEntry,
  addEntryChecked,
  codeForEntry,
  entryIdentity,
  entryFingerprint,
  mergeVaults,
  mergeOpsInto,
  normalizeVault,
  removeEntry,
  vaultToJson,
  base64ToBytes,
  bytesToBase64,
  // ⛔ The tombstone growth limit (Phase 61 follow-up).
  opBodySizeWarning,
  MAX_OP_BODY_BYTES,
  OP_BODY_WARN_BYTES,
} from "../totp-vault.mjs";
import { resolveGo } from "./go-helper.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");
const pkgPath = join(__dirname, "..", "pkg-node", "sigil_wasm.js");
const buildWasm = join(__dirname, "..", "build-wasm.sh");
const cliManifest = join(repoRoot, "cli", "Cargo.toml");
const cliBinary = join(repoRoot, "cli", "target", "debug", "sigil");
const sigildDir = join(repoRoot, "sigild");

// ⚠️ THROW, NEVER process.exit(): `process.exit()` skips the `finally` that kills
// the spawned sigild, which is how orphaned servers accumulate on the dev box.
function fail(msg) {
  throw new Error(`FAIL: ${msg}`);
}
function assert(cond, msg) {
  if (!cond) fail(msg);
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

// ═══════════════════════════════════════════════════════════════════════════
// ⛔⛔ THE TRANSPORT — why this suite does NOT use Node's global `fetch`.
//
// This is one of the longer suites (measured five times standalone at
// 200-201 s, i.e. ~3.3 minutes — an earlier version of this comment said
// "~9-11 minutes", which was ~3x off and is exactly the kind of live claim
// nothing checks) and it was FLAKY: about
// 3 failures in 11 runs, in two modes.
//
// MODE 1 — `TypeError: fetch failed … cause: Error: read ECONNRESET` inside
// `pullContainers`. THE BEST-SUPPORTED EXPLANATION is keep-alive socket reuse
// racing sigild's idle reaper, and this suite is unusually exposed to it:
//
//   * sigild sets `IdleTimeout: 60 * time.Second` (sigild/cmd/server/main.go),
//     after which it closes an idle keep-alive connection. VERIFIED by reading
//     the server.
//   * Node's `fetch` (undici) POOLS connections and would normally retire an
//     idle socket first — but its keep-alive timer is a TIMER, and this suite
//     spends minutes at a stretch with the EVENT LOOP FULLY BLOCKED: every
//     `sigil` invocation is `execFileSync`, and the PROPERTY section runs 600
//     synchronous merge rounds. A timer that cannot fire does not retire
//     anything. VERIFIED by reading this file.
//   * The pool then hands out a socket the server has already closed, the write
//     lands on a dead connection, and the read comes back RST. ⚠️ THIS LAST STEP
//     IS INFERENCE, NOT OBSERVATION — no packet capture was taken, and the
//     failure was never reproduced on demand. It is a mechanism consistent with
//     every fact available, not a proven chain.
//
// ⭐ THE FIX DOES NOT DEPEND ON THAT INFERENCE BEING EXACTLY RIGHT: removing the
// SHARED POOL removes the whole class. `agent: false` gives every request its own
// connection, which Node closes when the response ends, so no idle socket exists
// to go stale under ANY of the pooling variants. (`Connection: close` cannot be
// set through `fetch` — it is a forbidden header name and is silently dropped,
// which is why this is a `node:http` client and not a header on the global one.)
//
// MODE 2 — `sigild /readyz not ready within 15000ms`. ⚠️ THE CAUSE OF THIS ONE IS
// NOT ESTABLISHED, and it would be dishonest to write as if it were. What IS
// known: it was hit ONCE while this file was being fixed, and in that occurrence
// the child was **ALIVE**, had printed **NOTHING** — not even its startup WARN —
// and never accepted a TCP connection for 45 s. It did not reproduce in 12
// consecutive fresh boots under 10-way CPU load (102-612 ms each), so simple CPU
// contention is RULED OUT.
//
// What that message WAS, definitely, is a misdiagnosis machine: `waitReady`
// polled a port and never looked at the child, so "the process died", "it never
// bound", "it bound and wedged" and "it is merely slow" all printed the same
// sentence. That is fixed — the child's exit status is checked, a raw TCP probe
// separates "nothing is listening" from "listening but not answering", and the
// deadline is 60 s because a generous deadline only costs a slower FAILURE. A
// single boot retry follows, scoped and justified at its call site.
//
// ⚠️ NO BLANKET RETRY ANYWHERE. A retry that hides a genuine failure is worse
// than a flake, because it converts "this is broken" into "run it again". The
// only retry below is on a TRANSPORT errno, on GET only (a retried POST would
// append a duplicate op and change the seq assertions), and it PRINTS.
// ═══════════════════════════════════════════════════════════════════════════

/** Transport errors that mean "the bytes did not get through", never "the server said no". */
const TRANSPORT_ERRNOS = new Set(["ECONNRESET", "EPIPE", "ETIMEDOUT"]);

function errnoOf(err) {
  for (let e = err; e; e = e.cause) if (typeof e.code === "string") return e.code;
  return null;
}

/** One request, one connection, no pool. A minimal `fetch`-shaped wrapper. */
function rawRequest(url, init = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const body = init.body === undefined || init.body === null ? null : Buffer.from(init.body);
    const headers = { ...(init.headers ?? {}) };
    if (body) headers["content-length"] = String(body.length);
    const req = httpRequest(
      {
        hostname: u.hostname,
        port: u.port,
        path: `${u.pathname}${u.search}`,
        method: init.method ?? "GET",
        headers,
        // ⭐ THE WHOLE POINT: no shared agent, so no pooled idle socket exists to
        // be reaped by sigild's 60 s IdleTimeout while the event loop is blocked.
        agent: false,
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("error", reject);
        res.on("end", () => {
          const buf = Buffer.concat(chunks);
          const text = buf.toString("utf8");
          resolve({
            status: res.statusCode,
            statusText: res.statusMessage ?? "",
            ok: res.statusCode >= 200 && res.statusCode < 300,
            headers: { get: (k) => res.headers[String(k).toLowerCase()] ?? null },
            text: async () => text,
            json: async () => JSON.parse(text),
            arrayBuffer: async () => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.length),
          });
        });
      },
    );
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

let transportRetries = 0;

/**
 * The `fetch` this suite installs globally (so `sync.mjs`'s default path uses it
 * too, without changing its signature at 20-odd call sites).
 */
async function poollessFetch(url, init = {}) {
  const method = (init.method ?? "GET").toUpperCase();
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await rawRequest(url, init);
    } catch (err) {
      const code = errnoOf(err);
      // ⚠️ NARROW: GET only (a retried POST would append a duplicate op),
      // transport errnos only (never a refusal the server actually sent), at
      // most two extra attempts — and it SHOUTS, so a flake can never be
      // mistaken for a clean run.
      if (method !== "GET" || attempt >= 2 || !TRANSPORT_ERRNOS.has(code)) throw err;
      transportRetries += 1;
      console.error(
        `  ⚠️  TRANSPORT RETRY ${attempt + 1}/2: GET ${url} failed with ${code}. ` +
          `This should not happen now that every request gets its own connection — ` +
          `if you are reading this, the pooling diagnosis was incomplete.`,
      );
      await new Promise((r) => setTimeout(r, 200 * (attempt + 1)));
    }
  }
}

globalThis.fetch = poollessFetch;

/** Can anything at all connect to this TCP port? Distinguishes "not listening" from "not answering". */
function tcpReachable(port) {
  return new Promise((resolve) => {
    const sock = tcpConnect({ host: "127.0.0.1", port }, () => {
      sock.destroy();
      resolve(true);
    });
    sock.on("error", () => resolve(false));
    sock.setTimeout(1000, () => {
      sock.destroy();
      resolve(false);
    });
  });
}

/**
 * Wait for sigild to answer /readyz — while WATCHING THE CHILD, so a failure is
 * DIAGNOSED rather than reported as an anonymous timeout.
 *
 * ⚠️ The old message was `sigild /readyz not ready within 15000ms` and nothing
 * else, which is a symptom, not a cause. It could equally mean the process died,
 * the port was stolen, the server bound but wedged, or the client transport was
 * broken — four different bugs behind one sentence. This distinguishes them:
 * the child's exit status, and a raw TCP connect to tell "nothing is listening"
 * apart from "listening but not answering HTTP".
 *
 * The deadline is 60 s rather than 15 s because the only cost of a generous
 * deadline is a slower FAILURE, while the cost of a tight one is a false red on
 * a busy machine. A boot that is merely slow is reported as a ⚠️ on success, so
 * a creeping regression stays visible instead of being absorbed by the slack.
 */
async function waitReady(base, child, timeoutMs = 60000) {
  const port = Number(new URL(base).port);
  const started = Date.now();
  const deadline = started + timeoutMs;
  for (;;) {
    if (child.exitCode !== null || child.signalCode !== null) {
      throw new Error(
        `sigild EXITED before becoming ready (code=${child.exitCode}, signal=${child.signalCode}) ` +
          `after ${Date.now() - started}ms. This is NOT a slow start — it died. One candidate to ` +
          `check first: freePort() picks a port and CLOSES it, so anything else on the box can ` +
          `take it before sigild binds. sigild's own stderr is above this line and will say so ` +
          `if that is what happened.`,
      );
    }
    try {
      const res = await fetch(`${base}/readyz`);
      if (res.status === 200) {
        const ms = Date.now() - started;
        if (ms > 5000) {
          console.error(
            `  ⚠️  SLOW BOOT: sigild took ${ms}ms to answer /readyz. Not a failure, but this is ` +
              `the number that used to blow a 15 s deadline — if it keeps rising, find out why.`,
          );
        }
        return;
      }
    } catch {
      /* not up yet */
    }
    if (Date.now() > deadline) {
      const listening = await tcpReachable(port);
      throw new Error(
        `sigild /readyz did not answer within ${timeoutMs}ms.\n` +
          `  child:  ALIVE (pid=${child.pid}) — it did not crash\n` +
          `  socket: ${
            listening
              ? "ACCEPTING TCP connections but not answering HTTP — the server is WEDGED, which " +
                "is a real sigild bug, not a harness race"
              : "REFUSING TCP connections — sigild is running but never bound the port. Look for a " +
                "bind error in its stderr above; if there is none, it never reached its listener."
          }\n` +
          `  ⚠️ sigild printed nothing above? Then it had not reached its startup log at all.`,
      );
    }
    await new Promise((r) => setTimeout(r, 150));
  }
}

if (!existsSync(pkgPath)) {
  console.log("pkg-node missing — building the wasm (./build-wasm.sh) ...");
  execFileSync("bash", [buildWasm], {
    stdio: "inherit",
    env: toolEnv,
    cwd: join(__dirname, ".."),
  });
}
assert(existsSync(pkgPath), `${pkgPath} not found even after ./build-wasm.sh.`);

const work = mkdtempSync(join(tmpdir(), "sigil-merge-interop-"));
const sigildBin = join(work, "sigild");
// Device A is the REAL `sigil` binary driving its own vault file.
const vaultA = join(work, "a-vault.sigil");

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

const wasm = await import(pkgPath);
const enc = new TextEncoder();

// RFC 6238 App B sha1 key and its base32 provisioning form.
const RFC_KEY = enc.encode("12345678901234567890");
const RFC_BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PASSWORD = "correct horse battery staple";
const ARGON2 = { m_cost: 19456, t_cost: 2, p_cost: 1 };

// The SHARED known-answer vector, asserted identically in
// libsigil/core/src/entry_id.rs, sigil-wasm/src/lib.rs and cli/src/lib.rs.
const KAT_ID = "41828256-7397-80c1-bf67-e6b85ff84173";

function sealB(vault) {
  return sealVault(
    wasm,
    PASSWORD,
    vault,
    crypto.getRandomValues(new Uint8Array(wasm.recommended_salt_len())),
    crypto.getRandomValues(new Uint8Array(wasm.nonce_len())),
    ARGON2,
  );
}

function sigil(args, extraEnv = {}) {
  return execFileSync(cliBinary, args, {
    env: { ...process.env, SIGIL_PASSWORD: PASSWORD, ...extraEnv },
    encoding: "utf8",
  });
}

function labelsOf(vault) {
  return vault.entries.map((e) => e.label).sort();
}

/**
 * Canonical form: every object's keys sorted, at every depth.
 *
 * ⚠️⚠️ THIS IS NOT THE CONVERGENCE ORACLE, AND USING IT AS ONE WAS A REAL DEFECT.
 * It NORMALISES KEY ORDER AWAY, so it cannot see a merge that produces identical
 * content in a different byte order — which is precisely what `mergeVaults`
 * claimed could not happen and what it did. An earlier revision of the PROPERTY
 * section below compared through this function, and byte equality was therefore
 * asserted NOWHERE. The property now compares `vaultToJson` output directly, and
 * the BYTES section compares raw plaintext against the real `sigil` binary's.
 *
 * What it is still good for: a STRUCTURAL, key-order-insensitive comparison when
 * the question is "did these two hold the same content", and the failure
 * messages it prints are stable and readable. Every ordering claim is checked in
 * bytes elsewhere.
 *
 * ⭐ It is also exactly the canonicalisation the merge's own conflict tiebreak
 * uses (`sortKeysDeep` in JS, `serde_json::to_value`'s sorted map in Rust), so if
 * the two sides disagreed here they would also pick different winners for the
 * same conflict and never converge.
 */
function canon(value) {
  if (Array.isArray(value)) return value.map(canon);
  if (value && typeof value === "object") {
    const out = {};
    for (const k of Object.keys(value).sort()) out[k] = canon(value[k]);
    return out;
  }
  return value;
}
function canonJson(vault) {
  return JSON.stringify(canon(JSON.parse(vaultToJson(vault))));
}

/** Read the vault the CLI holds on disk, through the JS opener. */
function readA() {
  return openVault(wasm, PASSWORD, new Uint8Array(readFileSync(vaultA)));
}

let sigild = null;
try {
  // =====================================================================
  // KAT — the identity derivation is SINGLE-SOURCED in sigil-core and both
  //       languages reach the same bytes.
  // =====================================================================
  assert(
    wasm.entry_id("GitHub", "alice@example.com", RFC_KEY, "sha1", 6, 30, 0) === KAT_ID,
    "the wasm entry_id export does not reproduce the shared KAT",
  );
  const katEntry = {
    label: "alice@example.com",
    issuer: "GitHub",
    secret: bytesToBase64(RFC_KEY),
    algorithm: "sha1",
    digits: 6,
    period: 30,
  };
  assert(
    entryFingerprint(wasm, katEntry) === KAT_ID,
    "entryFingerprint must reach the same derivation as wasm.entry_id",
  );
  console.log("  KAT       OK: sigil-core entry_id, reached from JS, matches the shared vector");

  // =====================================================================
  // Boot a real sigild (dev ops on, in-memory, no auth).
  // =====================================================================
  // ⚠️ `freePort()` asks the kernel for a port and then CLOSES it, so there is a
  // window in which anything else on the box — including the other suites
  // `scripts/gate.sh` runs — can take it before sigild binds. That is a bind
  // race, not a slow start, and it used to surface as a bare "not ready within
  // 15000ms". `waitReady` now tells the two apart; this retries ONCE, only for
  // the case where the child actually DIED, and says so.
  let base = null;
  for (let boot = 0; ; boot += 1) {
    const port = await freePort();
    base = `http://127.0.0.1:${port}`;
    console.log(`  starting sigild on ${base} (SIGILD_ENABLE_DEV_OPS=1, in-memory, no auth) ...`);
    sigild = spawn(sigildBin, [], {
      env: { ...process.env, SIGILD_ADDR: `127.0.0.1:${port}`, SIGILD_ENABLE_DEV_OPS: "1" },
      stdio: ["ignore", "inherit", "inherit"],
    });
    sigild.on("error", (e) => fail(`sigild failed to spawn: ${e.message}`));
    try {
      await waitReady(base, sigild);
      break;
    } catch (e) {
      // ⭐ ONE retry, and ONLY here. This is the one place in the suite where a
      // retry cannot hide a product defect: not a single request has been made,
      // so nothing under test has behaved yet — the only thing being retried is
      // "did an OS-level server process come up on a port". It is capped at one
      // attempt and it SHOUTS, so a machine that cannot start sigild reliably is
      // still visible rather than quietly papered over.
      if (boot >= 1) throw e;
      console.error(`  ⚠️  SIGILD DID NOT BECOME READY:\n${e.message}`);
      console.error(
        `  ⚠️  RETRYING THE BOOT ONCE on a fresh port. A second failure is a REAL failure and ` +
          `will NOT be retried. If you are reading this, note it — the boot is not supposed to ` +
          `need a retry, and a run that needed one is evidence, not noise.`,
      );
      sigild.kill("SIGKILL");
      sigild = null;
    }
  }

  const vaultId = "merge-headline";

  // =====================================================================
  // SETUP — a shared starting point: A creates the vault with `base` and
  //         pushes it; B pulls and merges, so both hold the same one op.
  // =====================================================================
  sigil(["totp", "add", "base", "--secret", RFC_BASE32, "--vault", vaultA]);
  sigil(["totp", "sync", vaultId, "--server", base, "--vault", vaultA]);

  let vaultB = newVault();
  {
    const ops = await pullContainers(base, vaultId, 0);
    const res = mergeOpsInto(wasm, PASSWORD, vaultB, ops);
    assert(res.applied === 1, `B should have merged 1 op, applied=${res.applied}`);
    vaultB = res.vault;
  }
  assert(labelsOf(vaultB).join() === "base", `B setup: ${labelsOf(vaultB)}`);

  // =====================================================================
  // ⭐⭐ HEADLINE — both devices add OFFLINE, neither pulls first.
  // =====================================================================
  // A adds `alpha` (carrying the RFC vector secret) and pushes -> op 2.
  sigil([
    "totp", "add", "alpha",
    "--secret", RFC_BASE32,
    "--digits", "8",
    "--vault", vaultA,
  ]);
  sigil(["totp", "sync", vaultId, "--server", base, "--vault", vaultA]);

  // B adds `bravo` WITHOUT pulling, and pushes -> op 3, THE TIP.
  addEntry(vaultB, {
    label: "bravo",
    issuer: "GitLab",
    secretBytes: enc.encode("bravo-secret-key-0000"),
    algorithm: "sha1",
    digits: 6,
    period: 30,
  });
  const bravoTip = sealB(vaultB);
  await pushContainer(base, vaultId, bravoTip);

  // ⛔ THE OLD BEHAVIOUR, asserted so the setup is not silently wrong: the TIP
  // — what every client used to adopt — does NOT contain `alpha`.
  {
    const ops = await pullContainers(base, vaultId, 0);
    const tip = openVault(wasm, PASSWORD, ops[ops.length - 1].container);
    assert(
      !tip.entries.some((e) => e.label === "alpha"),
      "setup is wrong: the tip already contains alpha, so nothing is being proven",
    );
    console.log(
      `  SETUP     OK: the tip (op #${ops[ops.length - 1].seq}) holds [${labelsOf(tip)}] — ` +
        "adopting it wholesale is what destroyed alpha",
    );
  }

  // Now BOTH sync.
  sigil(["totp", "sync", vaultId, "--server", base, "--vault", vaultA]);
  {
    const ops = await pullContainers(base, vaultId, 0);
    const res = mergeOpsInto(wasm, PASSWORD, vaultB, ops);
    vaultB = res.vault;
  }

  const afterA = readA();
  assert(
    labelsOf(afterA).join() === "alpha,base,bravo",
    `A must hold all three, got [${labelsOf(afterA)}]`,
  );
  assert(
    labelsOf(vaultB).join() === "alpha,base,bravo",
    `B must hold all three, got [${labelsOf(vaultB)}]`,
  );

  // ⭐ The SECRET survived, not merely the label: the RFC 6238 App B vector.
  const alphaA = afterA.entries.find((e) => e.label === "alpha");
  const alphaB = vaultB.entries.find((e) => e.label === "alpha");
  assert(codeForEntry(wasm, alphaA, 59) === "94287082", "A: alpha lost its secret");
  assert(codeForEntry(wasm, alphaB, 59) === "94287082", "B: alpha lost its secret");
  // …and B's own account still works too.
  const bravoA = afterA.entries.find((e) => e.label === "bravo");
  assert(
    codeForEntry(wasm, bravoA, 59) === codeForEntry(wasm, vaultB.entries.find((e) => e.label === "bravo"), 59),
    "A and B disagree about bravo's code",
  );
  console.log(
    "  HEADLINE  OK: two devices added offline, both synced, BOTH hold all three — " +
      "and alpha still prints the RFC 6238 vector 94287082 on BOTH",
  );

  // =====================================================================
  // CONVERGE — byte-identical merged plaintext. This is what a drifted
  //            Rust/JS mirror fails, and a "nothing was lost" assertion
  //            cannot see.
  // =====================================================================
  assert(
    canonJson(afterA) === canonJson(vaultB),
    `A and B did not converge:\n  A=${canonJson(afterA)}\n  B=${canonJson(vaultB)}`,
  );
  // ⭐ And the ENTRY ORDER agrees too, not just the set — that is the part a
  // drifted `canonicalizeVault` would break while every "nothing was lost"
  // assertion stayed green.
  assert(
    afterA.entries.map((e) => e.uuid).join() === vaultB.entries.map((e) => e.uuid).join(),
    "A and B agree on the CONTENT but not the ORDER — canonicalizeVault has drifted",
  );
  console.log(
    "  CONVERGE  OK: the Rust and JS merges produce identical content AND identical entry order",
  );

  // =====================================================================
  // IDEMPOTENT — a second round appends no op, so devices do not ping-pong.
  // =====================================================================
  const opsBefore = (await pullContainers(base, vaultId, 0)).length;
  const syncOut = sigil([
    "totp", "sync", vaultId, "--server", base, "--vault", vaultA,
  ]);
  const opsAfter = (await pullContainers(base, vaultId, 0)).length;
  assert(
    opsAfter === opsBefore,
    `a converged sync must append NO op: ${opsBefore} -> ${opsAfter}\n${syncOut}`,
  );
  console.log(`  IDEMPOTENT OK: a converged sync appended no op (still ${opsAfter})`);

  // =====================================================================
  // DELETE — a removal must survive meeting a snapshot that still holds it.
  // =====================================================================
  sigil(["totp", "remove", "alpha", "--vault", vaultA]);
  sigil(["totp", "sync", vaultId, "--server", base, "--vault", vaultA]);
  {
    // B still holds `alpha` and has not pulled.
    assert(vaultB.entries.some((e) => e.label === "alpha"), "B should still hold alpha here");
    const ops = await pullContainers(base, vaultId, 0);
    vaultB = mergeOpsInto(wasm, PASSWORD, vaultB, ops).vault;
    assert(
      !vaultB.entries.some((e) => e.label === "alpha"),
      "the delete did not propagate to B — a tombstone must beat a stale snapshot",
    );
    assert(
      Array.isArray(vaultB.tombstones) && vaultB.tombstones.length === 1,
      `B should carry exactly 1 tombstone, got ${JSON.stringify(vaultB.tombstones)}`,
    );
    // B pushes its post-merge snapshot; A merges again. It must STAY gone.
    await pushContainer(base, vaultId, sealB(vaultB));
    sigil(["totp", "sync", vaultId, "--server", base, "--vault", vaultA]);
    assert(
      !readA().entries.some((e) => e.label === "alpha"),
      "alpha was RESURRECTED on A — the tombstone did not survive the round trip",
    );
  }
  console.log("  DELETE    OK: a removal survives a stale snapshot AND a round trip back");

  // =====================================================================
  // RE-ADD — a tombstone must not poison a genuine re-add (a fresh id).
  // =====================================================================
  sigil(["totp", "add", "alpha", "--secret", RFC_BASE32, "--digits", "8", "--vault", vaultA]);
  sigil(["totp", "sync", vaultId, "--server", base, "--vault", vaultA]);
  {
    const ops = await pullContainers(base, vaultId, 0);
    vaultB = mergeOpsInto(wasm, PASSWORD, vaultB, ops).vault;
    const re = vaultB.entries.find((e) => e.label === "alpha");
    assert(re, "a genuine re-add was eaten by its own tombstone");
    assert(codeForEntry(wasm, re, 59) === "94287082", "the re-added alpha lost its secret");
  }
  console.log("  RE-ADD    OK: re-adding draws a fresh id, so delete-wins cannot eat it");

  // =====================================================================
  // LEGACY — ONE pre-Phase-61 vault (no uuid anywhere), normalised
  //          independently on two devices, must merge to N and not 2N.
  // =====================================================================
  {
    const legacy = {
      version: 1,
      entries: [
        {
          label: "old-one",
          issuer: "Legacy",
          secret: bytesToBase64(enc.encode("legacy-secret-aaaa00")),
          algorithm: "sha1",
          digits: 6,
          period: 30,
        },
        {
          label: "old-two",
          secret: bytesToBase64(enc.encode("legacy-secret-bbbb00")),
          algorithm: "sha1",
          digits: 6,
          period: 30,
        },
      ],
    };
    assert(
      !JSON.stringify(legacy).includes("uuid"),
      "the legacy fixture must genuinely carry no uuid",
    );
    const legacyId = "merge-legacy";
    // The SAME bytes reach both devices. The CLI gets the file; JS gets a copy.
    const legacyFile = join(work, "legacy.sigil");
    writeFileSync(legacyFile, sealB(legacy));
    const legacyJs = JSON.parse(JSON.stringify(legacy));

    // Each device normalises on its own and pushes.
    sigil(["totp", "sync", legacyId, "--server", base, "--vault", legacyFile]);
    await pushContainer(base, legacyId, sealB(normalizeVault(wasm, legacyJs)));

    const ops = await pullContainers(base, legacyId, 0);
    const merged = mergeOpsInto(wasm, PASSWORD, newVault(), ops).vault;
    assert(
      merged.entries.length === 2,
      `a legacy vault normalised on two devices must merge to 2 entries, got ${merged.entries.length}: ` +
        `${merged.entries.map((e) => `${e.label}/${entryIdentity(wasm, e)}`).join(", ")}`,
    );
    console.log("  LEGACY    OK: independent normalisation of one legacy vault gives 2, not 4");
  }

  // =====================================================================
  // IMPORT — `work` at two issuers is two accounts (CRITICAL 2), and a
  //          re-import is a no-op.
  // =====================================================================
  {
    const importFile = join(work, "import.txt");
    const gh = "otpauth://totp/GitHub:work?secret=GEZDGNBVGY3TQOJQ&issuer=GitHub";
    const gl = "otpauth://totp/GitLab:work?secret=MFRGGZDFMZTWQ2LK&issuer=GitLab";
    writeFileSync(importFile, `${gh}\n${gl}\n`);
    const importVault = join(work, "import-vault.sigil");
    const out1 = sigil(["totp", "import", importFile, "--vault", importVault]);
    assert(/imported 2/.test(out1), `both same-labelled accounts must import: ${out1.trim()}`);

    // A re-import of the SAME file must import NOTHING and NAME both skips.
    const out2 = sigil(["totp", "import", importFile, "--vault", importVault]);
    assert(/imported 0/.test(out2), `a re-import must be a no-op: ${out2.trim()}`);

    const imported = openVault(wasm, PASSWORD, new Uint8Array(readFileSync(importVault)));
    assert(imported.entries.length === 2, `expected 2 entries, got ${imported.entries.length}`);
    const issuers = imported.entries.map((e) => e.issuer).sort();
    assert(
      issuers.join() === "GitHub,GitLab",
      `both issuers must be present, got [${issuers}]`,
    );

    // …and the JS side agrees, through addEntryChecked.
    const jsVault = newVault();
    const input = {
      label: "work",
      issuer: "GitHub",
      secretBytes: enc.encode("12345678901234567890"),
      algorithm: "sha1",
      digits: 6,
      period: 30,
    };
    assert(addEntryChecked(wasm, jsVault, input) === true, "first add should land");
    assert(
      addEntryChecked(wasm, jsVault, input) === false,
      "⛔ a re-import must be refused — comparing IDENTITIES instead of fingerprints " +
        "silently duplicates every account in a re-imported export",
    );
    assert(
      addEntryChecked(wasm, jsVault, { ...input, issuer: "GitLab", secretBytes: enc.encode("x".repeat(20)) }) === true,
      "the same label at a different issuer is a DIFFERENT account and must land",
    );
    assert(jsVault.entries.length === 2, `JS: expected 2, got ${jsVault.entries.length}`);
    console.log(
      "  IMPORT    OK: work@GitHub and work@GitLab both import; a re-import imports none (Rust AND JS)",
    );
  }

  // =====================================================================
  // COMMUTATIVE — the algebra, checked directly on the JS side against the
  //               same inputs in both orders.
  // =====================================================================
  {
    const x = newVault();
    addEntry(x, { label: "x", secretBytes: enc.encode("x".repeat(20)), algorithm: "sha1", digits: 6, period: 30 });
    const y = newVault();
    addEntry(y, { label: "y", secretBytes: enc.encode("y".repeat(20)), algorithm: "sha1", digits: 6, period: 30 });
    const xy = mergeVaults(wasm, x, y).vault;
    const yx = mergeVaults(wasm, y, x).vault;
    assert(vaultToJson(xy) === vaultToJson(yx), "merge is not commutative");
    const again = mergeVaults(wasm, xy, xy).vault;
    assert(vaultToJson(again) === vaultToJson(xy), "merge is not idempotent");
    // …and a delete recorded on one side beats the other's copy either way.
    const del = mergeVaults(wasm, x, x).vault;
    removeEntry(wasm, del, { label: "x" }, 1_700_000_000);
    assert(vaultToJson(mergeVaults(wasm, del, x).vault) === vaultToJson(mergeVaults(wasm, x, del).vault),
      "delete-wins is order-dependent");
    assert(mergeVaults(wasm, x, del).vault.entries.length === 0, "the tombstone did not win");
    console.log("  ALGEBRA   OK: commutative, idempotent, and delete-wins in both orders");
  }

  // =====================================================================
  // ⭐ TIEBREAK — the ONE place where Rust and JS could silently disagree.
  //
  // When two snapshots claim the same id with DIFFERENT content, the winner is
  // the lexicographically greater CANONICAL JSON. Rust computes that through
  // `serde_json::to_value` (whose `Map` is a BTreeMap, i.e. SORTED keys) and JS
  // through `sortKeysDeep`. If those two ever ordered keys differently the two
  // clients would pick DIFFERENT winners for the same conflict and never
  // converge — while every "nothing was lost" assertion stayed green, because
  // nothing IS lost; they just disagree forever.
  //
  // ⚠️ It is not hypothetical: turning on serde_json's `preserve_order` feature
  // (which pulls `indexmap` and makes the map INSERTION-ordered) would break it
  // with no compile error and no test failure anywhere else.
  // =====================================================================
  {
    const tieId = "44444444-4444-4444-8444-444444444444";
    const tieVault = "merge-tiebreak";
    // ⚠️ THIS FIXTURE IS CONSTRUCTED, NOT ARBITRARY, and the first attempt at it
    // was USELESS: a mutation that made JS stop sorting keys left this suite
    // GREEN, because with those particular field orders BOTH canonicalisations
    // happened to pick the same entry. A conflict test that cannot distinguish
    // the two orderings proves nothing about them.
    //
    // These two are chosen so the answers genuinely DIVERGE:
    //   * SORTED keys   -> the first differing field is `secret`, and LEFT's
    //                      ("bbb…") sorts above RIGHT's ("aaa…")  => LEFT wins.
    //   * INSERTION ord -> LEFT starts `{"algorithm"…` and RIGHT `{"uuid"…`,
    //                      and "u" > "a"                          => RIGHT wins.
    // Rust always sorts (serde_json's Map is a BTreeMap), so if JS ever stopped
    // sorting, the two clients would pick different winners — and this assertion
    // is the only thing that would notice.
    const left = {
      version: 1,
      entries: [
        {
          algorithm: "sha1",
          digits: 6,
          label: "conflict",
          period: 30,
          secret: bytesToBase64(enc.encode("bbbbbbbbbbbbbbbbbbbb")),
          uuid: tieId,
        },
      ],
    };
    const right = {
      version: 1,
      entries: [
        {
          uuid: tieId,
          period: 30,
          digits: 6,
          algorithm: "sha1",
          secret: bytesToBase64(enc.encode("aaaaaaaaaaaaaaaaaaaa")),
          label: "conflict",
        },
      ],
    };
    await pushContainer(base, tieVault, sealB(left));
    await pushContainer(base, tieVault, sealB(right));

    // The REAL CLI merges them…
    const tieFile = join(work, "tie.sigil");
    sigil(["totp", "sync", tieVault, "--server", base, "--vault", tieFile]);
    const rustWinner = openVault(wasm, PASSWORD, new Uint8Array(readFileSync(tieFile)))
      .entries.find((e) => e.uuid === tieId);

    // …and so does JS, from the same ops.
    const ops = await pullContainers(base, tieVault, 0);
    const jsWinner = mergeOpsInto(wasm, PASSWORD, newVault(), ops).vault.entries.find(
      (e) => e.uuid === tieId,
    );

    assert(rustWinner && jsWinner, "both sides must keep exactly one of the two");
    assert(
      rustWinner.secret === jsWinner.secret,
      `⛔ Rust and JS chose DIFFERENT winners for the same conflict — the canonical ` +
        `JSON orderings have drifted, so these two clients can never converge.\n` +
        `  rust=${rustWinner.secret}\n  js  =${jsWinner.secret}`,
    );
    // …and merging in the other order picks the same one, on the JS side.
    const flipped = mergeVaults(wasm, right, left).vault.entries.find((e) => e.uuid === tieId);
    assert(
      flipped.secret === jsWinner.secret,
      "the tiebreak is order-dependent — merge is not commutative under conflict",
    );
    console.log(
      "  TIEBREAK  OK: Rust and JS pick the SAME winner for a same-id conflict, in either order",
    );
  }

  // =====================================================================
  // ⭐⭐ PROPERTY — the algebra over GENERATED inputs, in both orders.
  //
  // ⛔ WHY. `mergeVaults`'s comment claims "commutative, associative and
  // idempotent" WITHOUT QUALIFICATION, and that claim had a real, reproduced
  // exception: tombstone-level unknown fields merged FIRST-SEEN-WINS
  // (`{ ...t, ...prev }`), so two vaults whose tombstones shared a uuid but
  // disagreed about an unknown key gave `merge(a,b) != merge(b,a)` forever.
  // Every hand-written example above stayed GREEN, because none of them put an
  // unknown field on a tombstone — which is exactly what a FUTURE version of
  // this client will do (ADR 0047 forward compatibility) and what this one has
  // to carry through untouched.
  //
  // The fix made the claim TRUE (the same lexicographic-max rule the vault level
  // already used); this keeps it true, on the JS side, over the field kinds a
  // hand-written example forgets. It mirrors
  // `cli/src/lib.rs::merge_is_order_independent_over_generated_vaults`.
  // =====================================================================
  {
    // A tiny deterministic PRNG — no dependency, and this is a fixture
    // generator, not cryptography.
    let seed = 0x1234abcd;
    const rnd = () => {
      seed ^= seed << 13;
      seed ^= seed >>> 17;
      seed ^= seed << 5;
      seed >>>= 0;
      return seed;
    };
    const below = (n) => rnd() % n;
    const pick = (xs) => xs[below(xs.length)];

    // ⚠️ A TINY id pool ON PURPOSE: with unique ids everywhere the union is
    // trivially commutative and this would prove nothing.
    const IDS = [
      "11111111-1111-4111-8111-111111111111",
      "22222222-2222-4222-8222-222222222222",
      "33333333-3333-4333-8333-333333333333",
      "44444444-4444-4444-8444-444444444444",
    ];
    const SECRETS = ["aaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbb", "cc"];
    const LABELS = ["alpha", "bravo", "charlie"];
    const ISSUERS = [undefined, "GitHub", "GitLab"];
    // Two DIFFERENT values under the SAME unknown key is the whole point.
    const UNKNOWN = ["left", "right", { z: 1, a: 2 }, [1, 2, 3], 7];

    const arbitraryVault = () => {
      const v = { version: 1, entries: [] };
      for (const id of IDS) {
        if (below(3) === 0) continue;
        const entry = {
          label: pick(LABELS),
          secret: bytesToBase64(enc.encode(pick(SECRETS))),
          algorithm: "sha1",
          digits: 6,
          period: 30,
        };
        const iss = pick(ISSUERS);
        if (iss !== undefined) entry.issuer = iss;
        // Some entries carry NO uuid (a pre-Phase-61 row), so the derived
        // identity path is in the property too.
        if (below(5) !== 0) entry.uuid = id;
        if (below(3) === 0) entry.future_entry_field = pick(UNKNOWN);
        v.entries.push(entry);
      }
      const tombstones = [];
      for (const id of IDS) {
        if (below(3) !== 0) continue;
        const t = { uuid: id };
        if (below(4) !== 0) t.deleted_at = 1700000000 + below(1000);
        // ⭐ THE FIELD KIND THE REGRESSION LIVED IN.
        if (below(2) === 0) t.future_tombstone_field = pick(UNKNOWN);
        if (below(4) === 0) t.reason = pick(UNKNOWN);
        tombstones.push(t);
      }
      if (tombstones.length > 0) v.tombstones = tombstones;
      if (below(2) === 0) v.future_vault_field = pick(UNKNOWN);
      if (below(4) === 0) v.min_reader_version = 1;
      return v;
    };

    const tombExtras = (t) => {
      const { uuid, deleted_at: _d, ...rest } = t;
      void uuid;
      return JSON.stringify(canon(rest));
    };

    let sawTombstoneExtraConflict = 0;
    for (let round = 0; round < 600; round += 1) {
      const a = arbitraryVault();
      const b = arbitraryVault();

      // Did this round actually contain the input the regression needs? A
      // property test that never generates the interesting case is a no-op, so
      // it is COUNTED and asserted below.
      for (const ta of a.tombstones ?? []) {
        for (const tb of b.tombstones ?? []) {
          if (ta.uuid === tb.uuid && tombExtras(ta) !== tombExtras(tb)) {
            sawTombstoneExtraConflict += 1;
          }
        }
      }

      const ab = mergeVaults(wasm, a, b).vault;
      const ba = mergeVaults(wasm, b, a).vault;
      // ⚠️⚠️ `vaultToJson`, NOT `canonJson`. `canonJson` sorts every key at every
      // depth, so it CANNOT SEE the defect this property exists to exclude: two
      // tombstones sharing a uuid with disjoint unknown fields converged in
      // VALUE and diverged in BYTES, and this property passed 600/600 rounds
      // while that was true. `vaultToJson` is the exact serialization every
      // client seals and pushes, so this compares what is actually stored.
      assert(
        vaultToJson(ab) === vaultToJson(ba),
        `round ${round}: merge is NOT commutative BYTE FOR BYTE\n  a=${JSON.stringify(a)}\n  b=${JSON.stringify(b)}\n` +
          `  ab=${vaultToJson(ab)}\n  ba=${vaultToJson(ba)}`,
      );
      assert(
        vaultToJson(mergeVaults(wasm, ab, ab).vault) === vaultToJson(ab),
        `round ${round}: merge is NOT idempotent`,
      );
      // Associativity is what makes a THIRD device joining late converge no
      // matter which pair merged first.
      const c = arbitraryVault();
      const abc = mergeVaults(wasm, ab, c).vault;
      const aBc = mergeVaults(wasm, a, mergeVaults(wasm, b, c).vault).vault;
      assert(
        vaultToJson(abc) === vaultToJson(aBc),
        `round ${round}: merge is NOT associative BYTE FOR BYTE\n  abc=${vaultToJson(abc)}\n  aBc=${vaultToJson(aBc)}`,
      );
    }
    assert(
      sawTombstoneExtraConflict >= 20,
      `the generator never produced two tombstones sharing a uuid with DIFFERENT unknown fields ` +
        `(${sawTombstoneExtraConflict} times) — this property would then pass without exercising ` +
        `the case it exists for`,
    );
    console.log(
      `  PROPERTY  OK: 600 generated pairs merge order-independently, associatively and ` +
        `idempotently (${sawTombstoneExtraConflict} same-uuid tombstone/unknown-field conflicts hit)`,
    );
  }

  // =====================================================================
  // ⭐ TOMBSTONE-EXTRA — and Rust and JS must pick the SAME winner for it.
  //
  // The commutativity fix introduced a NEW cross-language rule (unknown
  // tombstone fields combine by lexicographic max of CANONICAL JSON). Like the
  // entry tiebreak above, a drift here converges within each client and never
  // between them.
  // =====================================================================
  {
    const tombId = "55555555-5555-4555-8555-555555555555";
    const tombVault = "merge-tombstone-extra";
    const withExtra = (value) => ({
      version: 1,
      entries: [],
      tombstones: [{ uuid: tombId, deleted_at: 1700000000, future_tombstone_field: value }],
    });
    await pushContainer(base, tombVault, sealB(withExtra("aaa")));
    await pushContainer(base, tombVault, sealB(withExtra("zzz")));

    const tombFile = join(work, "tomb.sigil");
    sigil(["totp", "sync", tombVault, "--server", base, "--vault", tombFile]);
    const rustTomb = openVault(wasm, PASSWORD, new Uint8Array(readFileSync(tombFile))).tombstones.find(
      (t) => t.uuid === tombId,
    );
    const ops = await pullContainers(base, tombVault, 0);
    const jsTomb = mergeOpsInto(wasm, PASSWORD, newVault(), ops).vault.tombstones.find(
      (t) => t.uuid === tombId,
    );
    assert(rustTomb && jsTomb, "both sides must keep the tombstone");
    assert(
      rustTomb.future_tombstone_field === jsTomb.future_tombstone_field,
      `⛔ Rust and JS kept DIFFERENT values for the same unknown tombstone field — the two ` +
        `clients can never converge.\n  rust=${JSON.stringify(rustTomb)}\n  js  =${JSON.stringify(jsTomb)}`,
    );
    assert(
      jsTomb.future_tombstone_field === "zzz",
      `the surviving value must be the deterministic MAX, not whichever arrived first: ` +
        `${JSON.stringify(jsTomb)}`,
    );
    // …and merging the two the other way round agrees.
    const flipped = mergeVaults(wasm, withExtra("zzz"), withExtra("aaa")).vault.tombstones[0];
    assert(
      flipped.future_tombstone_field === "zzz",
      "⛔ tombstone `extra` is order-dependent — merge is not commutative",
    );
    console.log(
      "  TOMB-XTRA OK: an unknown tombstone field merges commutatively, and Rust and JS agree",
    );
  }

  // =====================================================================
  // ⭐⭐ BYTES — the REAL `sigil` binary and this JS module serialize the SAME
  //     merged vault to the SAME BYTES.
  //
  // ⛔ WHY THIS EXISTS, and why nothing above it could have caught the bug.
  // Every convergence assertion in this suite compared through `canonJson`,
  // which sorts every object's keys at every depth — i.e. it NORMALISES AWAY
  // exactly the property being claimed. `mergeVaults`'s own docstring said
  // `merge(a,b)` and `merge(b,a)` agree "byte for byte with no exception", and
  // BYTE EQUALITY WAS ASSERTED NOWHERE. It was false on two counts:
  //
  //   1. `mergeVaults` spread one side and appended the other's keys, so two
  //      tombstones sharing a uuid with DISJOINT unknown fields (or two vaults
  //      with disjoint unknown TOP-LEVEL fields) came out as
  //        …,"alpha":1,"beta":2   one way round
  //        …,"beta":2,"alpha":1   the other.
  //   2. CROSS-LANGUAGE: `serde` writes struct fields in DECLARATION order and
  //      its flattened `extra` is a `BTreeMap` (sorted), while JS wrote
  //      insertion order — so `addEntry`'s `issuer` landed LAST and unknown
  //      fields landed wherever `JSON.parse` had put them. Two clients holding
  //      IDENTICAL content wrote DIFFERENT BYTES.
  //
  // Neither is visible to a parser, which is why every other suite stayed green.
  // It matters because a sealed vault is pushed as an OPAQUE op: different bytes
  // for identical content means every push is a fresh op, growing the log toward
  // the 64 KiB cap the SIZE section warns about, and any "unchanged, skip the
  // push" or content-addressing added later is silently wrong. The merge
  // report's own `changed` flag is computed by exactly this comparison.
  //
  // ⚠️ THE COMPARISON IS ON RAW PLAINTEXT BYTES — no parse, no canonicalisation,
  // no `canonJson`. That is the whole point.
  // =====================================================================
  {
    const bytesVault = "merge-bytes";
    const bytesFile = join(work, "bytes.sigil");
    const tombId = "33333333-3333-4333-8333-333333333333";

    // A deliberately AWKWARD pair — every shape whose ordering the two languages
    // could disagree about, in one fixture:
    //   * an entry WITH `issuer` (serde writes it 2nd; JS used to append it last)
    //   * an entry WITHOUT `issuer` (the `skip_serializing_if` path)
    //   * an entry with NO uuid at all (the derived-identity path)
    //   * unknown fields on an ENTRY, deliberately out of alphabetical order,
    //     one of them a nested object with out-of-order keys
    //   * ONE shared tombstone whose unknown fields are DISJOINT across the two
    //     sides — the exact input the byte-commutativity defect lived in
    //   * disjoint unknown TOP-LEVEL fields, again out of alphabetical order
    //   * `min_reader_version` present on ONE side only
    const left = {
      version: 1,
      min_reader_version: 1,
      entries: [
        {
          label: "alice",
          issuer: "GitHub",
          secret: bytesToBase64(RFC_KEY),
          algorithm: "sha1",
          digits: 6,
          period: 30,
          uuid: "11111111-1111-4111-8111-111111111111",
          zeta_entry_field: 1,
          alpha_entry_field: { y: 1, x: 2 },
        },
      ],
      tombstones: [{ zulu_left: 1, deleted_at: 1_700_000_009, uuid: tombId }],
      zulu_vault_field: "L",
    };
    const right = {
      version: 1,
      entries: [
        {
          label: "bob",
          secret: bytesToBase64(enc.encode("bbbbbbbbbbbbbbbbbbbb")),
          algorithm: "sha1",
          digits: 6,
          period: 30,
          uuid: "22222222-2222-4222-8222-222222222222",
        },
        {
          // NO uuid: both sides must DERIVE the same one, and it must land in
          // the same place in the sorted entry list.
          label: "carol",
          issuer: "GitLab",
          secret: bytesToBase64(enc.encode("cccccccccccccccccccc")),
          algorithm: "sha256",
          digits: 8,
          period: 60,
        },
      ],
      tombstones: [{ uuid: tombId, deleted_at: 1_700_000_001, alpha_right: [1, { q: 1, p: 2 }] }],
      alpha_vault_field: "R",
    };

    // ⚠️ Seal BEFORE merging: `mergeVaults` normalises in place, so merging first
    // would fill in `carol`'s uuid and the CLI would be handed a DIFFERENT vault
    // than the JS side started from.
    writeFileSync(bytesFile, sealB(structuredClone(left)));
    await pushContainer(base, bytesVault, sealB(structuredClone(right)));

    // The REAL binary folds the pushed op into its local vault and re-seals it.
    sigil(["totp", "sync", bytesVault, "--server", base, "--vault", bytesFile]);
    const rustBytes = wasm.open_container(
      enc.encode(PASSWORD),
      new Uint8Array(readFileSync(bytesFile)),
    );

    const jsMerged = mergeVaults(wasm, structuredClone(left), structuredClone(right)).vault;
    const jsBytes = enc.encode(vaultToJson(jsMerged));

    const asText = (u8) => new TextDecoder().decode(u8);
    assert(
      asText(rustBytes) === asText(jsBytes),
      "⛔ Rust and JS serialize the SAME merged vault to DIFFERENT BYTES — two clients " +
        "holding identical content write different ciphertext, so every push is a fresh op " +
        "and no content-addressing or skip-if-unchanged rule can ever be correct.\n" +
        `  rust=${asText(rustBytes)}\n  js  =${asText(jsBytes)}`,
    );
    assert(
      rustBytes.length === jsBytes.length && rustBytes.every((b, i) => b === jsBytes[i]),
      "the two encodings differ at the BYTE level despite comparing equal as text",
    );

    // …and the JS merge is byte-commutative on this same awkward fixture, which
    // is what `mergeVaults`'s docstring claims and what `canonJson` cannot see.
    const flip = enc.encode(
      vaultToJson(mergeVaults(wasm, structuredClone(right), structuredClone(left)).vault),
    );
    assert(
      asText(flip) === asText(jsBytes),
      "⛔ mergeVaults is not BYTE-commutative on disjoint unknown fields:\n" +
        `  a,b=${asText(jsBytes)}\n  b,a=${asText(flip)}`,
    );

    // Guard the fixture itself: a pair that never produced the interesting shape
    // would let this section pass while proving nothing.
    const merged = JSON.parse(asText(jsBytes));
    const mergedTomb = merged.tombstones.find((t) => t.uuid === tombId);
    assert(
      mergedTomb && "alpha_right" in mergedTomb && "zulu_left" in mergedTomb,
      "the fixture did not actually JOIN two disjoint unknown tombstone fields",
    );
    assert(
      "alpha_vault_field" in merged && "zulu_vault_field" in merged,
      "the fixture did not actually JOIN two disjoint unknown top-level fields",
    );
    assert(
      merged.entries.length === 3 && merged.entries.some((e) => e.issuer === undefined),
      "the fixture must carry an entry WITHOUT an issuer (the skip_serializing_if path)",
    );
    console.log(
      "  BYTES     OK: the real `sigil` binary and this JS module serialize the same merged " +
        "vault to byte-identical plaintext, and the JS merge is byte-commutative",
    );
  }

  // =====================================================================
  // ⭐⭐ THREE-DEVICE — a device joining LATE, after the other two have
  //     already diverged AND merged, converges with both.
  //
  // ⛔ WHY IT IS SEPARATE FROM THE HEADLINE. Every suite in this repo covered
  // TWO devices (and a merge into a fresh empty vault). Two devices cannot
  // distinguish a genuine join from "the second one wins" — associativity only
  // has content once a third value exists, and a late joiner is the case where
  // a client folds ops it has never seen INTERLEAVED with its own offline work.
  // The three-device case was verified by hand and asserted NOWHERE.
  //
  // C is deliberately the WORST joiner: it adds an account BEFORE it has ever
  // pulled, and pushes — so the tip, for a moment, contains only C's account.
  // That is the exact shape that used to destroy data.
  // =====================================================================
  {
    const threeId = "merge-three-device";
    const vaultA3 = join(work, "a3-vault.sigil");

    // 1) A (the REAL CLI) creates the vault. `--digits 8` so the account carries
    //    the RFC 6238 App B vector exactly, and the late joiner's copy of the
    //    SECRET (not merely the label) is checkable against 94287082.
    sigil(["totp", "add", "a-only", "--secret", RFC_BASE32, "--digits", "8", "--vault", vaultA3]);
    sigil(["totp", "sync", threeId, "--server", base, "--vault", vaultA3]);

    // 2) B (JS) joins, then adds OFFLINE and pushes.
    let b3 = newVault();
    b3 = mergeOpsInto(wasm, PASSWORD, b3, await pullContainers(base, threeId, 0)).vault;
    addEntry(b3, {
      label: "b-only",
      issuer: "GitLab",
      secretBytes: enc.encode("b-only-secret-000000"),
      algorithm: "sha1",
      digits: 6,
      period: 30,
    });
    await pushContainer(base, threeId, sealB(b3));

    // 3) A adds its OWN second account without pulling, then syncs — so A and B
    //    have genuinely DIVERGED and then MERGED before C ever appears.
    sigil(["totp", "add", "a-two", "--secret", RFC_BASE32, "--vault", vaultA3]);
    sigil(["totp", "sync", threeId, "--server", base, "--vault", vaultA3]);
    b3 = mergeOpsInto(wasm, PASSWORD, b3, await pullContainers(base, threeId, 0)).vault;
    assert(
      labelsOf(b3).join() === "a-only,a-two,b-only",
      `A and B must have converged BEFORE C joins, B has [${labelsOf(b3)}]`,
    );

    // 4) ⭐ C JOINS LATE — and adds its own account BEFORE pulling anything.
    let c3 = newVault();
    addEntry(c3, {
      label: "c-only",
      issuer: "Okta",
      secretBytes: enc.encode("c-only-secret-000000"),
      algorithm: "sha1",
      digits: 6,
      period: 30,
    });
    await pushContainer(base, threeId, sealB(c3));
    {
      // ⛔ Assert the trap is real: the TIP now holds ONLY c-only, so adopting
      // it wholesale — the pre-Phase-61 behaviour — destroys three accounts.
      const ops = await pullContainers(base, threeId, 0);
      const tip = openVault(wasm, PASSWORD, ops[ops.length - 1].container);
      assert(
        labelsOf(tip).join() === "c-only",
        `setup is wrong: the tip should hold only c-only, it holds [${labelsOf(tip)}]`,
      );
    }

    // 5) ⭐⭐ C ALSO CARRIES UNPUSHED LOCAL WORK ACROSS THE FOLD, and that is the
    //    assertion NOTHING ELSE in this suite makes. Everywhere above, a device
    //    pushes before it merges, so its own state is already IN the op-log and
    //    a merge that started from a FRESH vault instead of `local` would still
    //    look correct. A late joiner is exactly the client with local additions
    //    the server has never seen — folding a log full of three other branches
    //    must not drop them.
    addEntry(c3, {
      label: "c-unpushed",
      issuer: "Okta",
      secretBytes: enc.encode("c-unpushed-secret-00"),
      algorithm: "sha1",
      digits: 6,
      period: 30,
    });

    // All three sync. C merges FIRST, while `c-unpushed` exists nowhere else.
    sigil(["totp", "sync", threeId, "--server", base, "--vault", vaultA3]);
    b3 = mergeOpsInto(wasm, PASSWORD, b3, await pullContainers(base, threeId, 0)).vault;
    await pushContainer(base, threeId, sealB(b3));
    c3 = mergeOpsInto(wasm, PASSWORD, c3, await pullContainers(base, threeId, 0)).vault;
    assert(
      c3.entries.some((e) => e.label === "c-unpushed"),
      "⛔ the late joiner's UNPUSHED local account was destroyed by the fold — a merge must " +
        "start from `local`, not from the server's state",
    );
    // Now C publishes its merged view, and A and B pick `c-unpushed` up.
    await pushContainer(base, threeId, sealB(c3));
    sigil(["totp", "sync", threeId, "--server", base, "--vault", vaultA3]);
    b3 = mergeOpsInto(wasm, PASSWORD, b3, await pullContainers(base, threeId, 0)).vault;

    const a3 = openVault(wasm, PASSWORD, new Uint8Array(readFileSync(vaultA3)));
    const want = "a-only,a-two,b-only,c-only,c-unpushed";
    assert(labelsOf(a3).join() === want, `A holds [${labelsOf(a3)}]`);
    assert(labelsOf(b3).join() === want, `B holds [${labelsOf(b3)}]`);
    assert(labelsOf(c3).join() === want, `C holds [${labelsOf(c3)}]`);
    assert(
      canonJson(a3) === canonJson(b3) && canonJson(b3) === canonJson(c3),
      `the three devices did not converge:\n  A=${canonJson(a3)}\n  B=${canonJson(b3)}\n  C=${canonJson(c3)}`,
    );
    // …and the secret survived on the LATE joiner, not just the label.
    assert(
      codeForEntry(wasm, c3.entries.find((e) => e.label === "a-only"), 59) === "94287082",
      "the late joiner got a-only's label but not its secret",
    );

    // 6) ⭐ And a delete raised by the LATE joiner reaches both incumbents and
    //    does not resurrect — a tombstone from a device the others have only
    //    just met is the case a "newest wins" merge silently drops.
    removeEntry(wasm, c3, { label: "a-only" }, 1_700_000_000);
    await pushContainer(base, threeId, sealB(c3));
    sigil(["totp", "sync", threeId, "--server", base, "--vault", vaultA3]);
    b3 = mergeOpsInto(wasm, PASSWORD, b3, await pullContainers(base, threeId, 0)).vault;
    await pushContainer(base, threeId, sealB(b3));
    c3 = mergeOpsInto(wasm, PASSWORD, c3, await pullContainers(base, threeId, 0)).vault;
    const a3b = openVault(wasm, PASSWORD, new Uint8Array(readFileSync(vaultA3)));
    const want2 = "a-two,b-only,c-only,c-unpushed";
    assert(labelsOf(a3b).join() === want2, `A after C's delete: [${labelsOf(a3b)}]`);
    assert(labelsOf(b3).join() === want2, `B after C's delete: [${labelsOf(b3)}]`);
    assert(labelsOf(c3).join() === want2, `C after C's delete: [${labelsOf(c3)}]`);
    assert(
      canonJson(a3b) === canonJson(b3) && canonJson(b3) === canonJson(c3),
      `the three devices diverged after the late joiner's delete:\n  A=${canonJson(a3b)}\n` +
        `  B=${canonJson(b3)}\n  C=${canonJson(c3)}`,
    );
    console.log(
      "  THREE-DEV OK: a device joining LATE (with offline work of its own) converges with two " +
        "devices that had already diverged and merged — byte-identical, and its delete propagates",
    );
  }

  // =====================================================================
  // ⛔ SIZE — the TOMBSTONE GROWTH LIMIT must be WARNED ABOUT, in both
  //    languages, BEFORE it becomes a 413 that ends syncing permanently.
  //
  // A vault is a 2P-Set: the remove-set never shrinks, nothing prunes a
  // tombstone, and there is no compaction command. sigild caps ONE op body at
  // 64 KiB. A user who first meets that at the 413 has already lost the ability
  // to sync, with no supported way back.
  // =====================================================================
  {
    assert(
      opBodySizeWarning(1024) === null,
      "a small vault must not be warned about — a warning that is always on is noise",
    );
    assert(
      typeof opBodySizeWarning(OP_BODY_WARN_BYTES) === "string",
      `no warning at the 75% threshold (${OP_BODY_WARN_BYTES} of ${MAX_OP_BODY_BYTES})`,
    );
    const over = opBodySizeWarning(MAX_OP_BODY_BYTES + 1);
    assert(/413/.test(over ?? ""), `the over-limit warning must name the 413: ${over}`);

    // ⭐ …and the REAL CLI prints it, from a vault genuinely fat with
    // tombstones. Built in JS and pushed, because 800 `sigil totp remove`
    // invocations would take minutes; what is under test is the CLI's warning,
    // not how the tombstones got there.
    const fatId = "merge-fat";
    const fat = newVault();
    fat.tombstones = [];
    // ⚠️ 750, not 900: at ~72 bytes per tombstone 900 seals to ~64.9 KiB, which
    // is inside the 64 KiB WARN band by only ~600 bytes — a fixture one JSON
    // tweak away from tripping the push cap and failing for the wrong reason.
    for (let i = 0; i < 750; i += 1) {
      const hex = i.toString(16).padStart(8, "0");
      fat.tombstones.push({ uuid: `${hex}-0000-4000-8000-000000000000`, deleted_at: 1700000000 + i });
    }
    const fatContainer = sealB(fat);
    assert(
      fatContainer.length >= OP_BODY_WARN_BYTES && fatContainer.length < MAX_OP_BODY_BYTES,
      `the fixture must land in the WARN band, it is ${fatContainer.length} bytes`,
    );
    await pushContainer(base, fatId, fatContainer);

    const fatFile = join(work, "fat.sigil");
    const run = spawnSync(
      cliBinary,
      ["totp", "sync", fatId, "--server", base, "--vault", fatFile],
      { env: { ...process.env, SIGIL_PASSWORD: PASSWORD }, encoding: "utf8" },
    );
    // ⭐ A WARNING IS NOT A GATE: the sync must still SUCCEED. A size warning
    // that failed the operation would be worse than the silence it replaces.
    assert(
      run.status === 0,
      `the fat sync must still succeed — a warning is not a gate.\n${run.stdout}\n${run.stderr}`,
    );
    assert(
      /op limit/.test(run.stderr) && /413/.test(run.stderr),
      `⛔ the CLI synced a ${fatContainer.length}-byte vault (over ${OP_BODY_WARN_BYTES} of the ` +
        `${MAX_OP_BODY_BYTES}-byte cap) and said NOTHING. The remove-set never shrinks and there ` +
        `is no compaction command, so the next thing this user hears is a 413 that ends syncing ` +
        `permanently.\nstderr was:\n${run.stderr}`,
    );
    assert(
      /tombstone/.test(run.stderr),
      `the warning must name TOMBSTONES as the thing that grows, else the user cannot act on it:` +
        `\n${run.stderr}`,
    );
    console.log(
      `  SIZE      OK: JS warns at ${OP_BODY_WARN_BYTES}/${MAX_OP_BODY_BYTES} bytes, and the real ` +
        `CLI warned (without failing) on a ${fatContainer.length}-byte vault`,
    );
  }

  // =====================================================================
  // OPAQUE — the server returned exactly what was pushed, and learned
  //          nothing about entries, ids or tombstones.
  // =====================================================================
  {
    const probeId = "merge-opaque";
    const probe = newVault();
    addEntry(probe, {
      label: "probe",
      secretBytes: enc.encode("probe-secret-0000000"),
      algorithm: "sha1",
      digits: 6,
      period: 30,
    });
    const bytes = sealB(probe);
    await pushContainer(base, probeId, bytes);
    const res = await fetch(`${base}/v1/vaults/${probeId}/ops?since=0&limit=10`);
    const body = await res.json();
    const back = base64ToBytes(body.ops[0].blob);
    assert(
      back.length === bytes.length && back.every((b, i) => b === bytes[i]),
      "the server did not return the pushed bytes verbatim",
    );
    const text = Buffer.from(back).toString("latin1");
    for (const needle of ["probe", "tombstone", "uuid", "entries"]) {
      assert(!text.includes(needle), `the sealed container leaked ${needle} in the clear`);
    }
    console.log("  OPAQUE    OK: bytes returned verbatim; no entry, id or tombstone is visible");
  }

  // ⚠️ Report the flake budget explicitly. `transportRetries` should be 0 now
  // that every request has its own connection; a non-zero count here means the
  // pooling diagnosis was incomplete and must be revisited, not tolerated.
  console.log(
    transportRetries === 0
      ? "  TRANSPORT OK: 0 retries — no request hit a transport error"
      : `  ⚠️  TRANSPORT: ${transportRetries} retry/retries were needed. The run PASSED, but the ` +
          `connection-per-request fix was supposed to make this impossible. Investigate.`,
  );

  console.log(
    "\nPASS: multi-device merge proven — two devices each added an account OFFLINE, both " +
      "synced, and BOTH hold BOTH with correct codes; deletes converge and do not resurrect; " +
      "a legacy vault does not duplicate; and `work` at two issuers is two accounts.",
  );
} finally {
  if (sigild) {
    sigild.kill("SIGKILL");
  }
  rmSync(work, { recursive: true, force: true });
}
