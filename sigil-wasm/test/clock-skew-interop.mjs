// clock-skew-interop.mjs — the CLOCK DIAGNOSTIC against a REAL sigild, in both
// languages, plus the Rust <-> JS agreement that makes them one feature.
//
// ---------------------------------------------------------------------------
// ⛔ WHAT THIS PROTECTS
// ---------------------------------------------------------------------------
//
// A TOTP code is a function of a shared secret and THE CURRENT TIME. When a
// device's clock drifts past half a step, the codes it produces start falling
// outside the window a verifier will accept (RFC 6238 §5.2 permits one step
// either side, so it is LIKELY and increasingly certain, never immediate and
// total) — and to the user a rejected code is INDISTINGUISHABLE from a wrong
// secret. It is the most common real-world authenticator failure there is, and
// no Sigil client reported it anywhere until now.
//
// The reading comes from the HTTP `Date` header every Go response already
// carries. There is no new route, no new endpoint and no new dependency.
//
// ---------------------------------------------------------------------------
// WHAT IS ASSERTED, AND WHY EACH ONE IS HERE
// ---------------------------------------------------------------------------
//
//  1. A REAL sigild's `Date` header parses in JS and yields a near-zero skew
//     against this machine's clock. (Nothing else in the repo parses a real
//     server's Date header — the browser suites use a DOUBLE.)
//  2. ⭐ The REAL `sigil` binary reads the SAME server and agrees. `sigil clock`
//     is driven as a subprocess; its exit status and its wording are checked.
//  3. ⭐⭐ RUST AND JS AGREE ON THE THRESHOLD AND THE DIRECTION. The constant is
//     MIRRORED (`CLOCK_SKEW_WARN_SECONDS` in cli/src/lib.rs and clock-skew.mjs),
//     so a drift would have one client calling a machine healthy while another
//     calls it broken. ⛔ THIS USED TO BE A HEADING WITH NOTHING BEHIND IT: only
//     the JS constant was checked, a verifier mutated the RUST one, and this
//     suite exited 0 while printing the sentence above. It now (3a) reads the
//     Rust literal out of `cli/src/lib.rs` and compares it numerically, and (3b)
//     drives the REAL `sigil clock` against a server whose `Date` header this
//     test CONTROLS, comparing its verdict against the JS verdict on the very
//     (server, local) pair Rust printed — which is what proves the constant is
//     wired and not merely spelled the same in two files.
//  4. ⭐⭐⭐ OFFLINE IS "NO READING", NEVER "FINE". Both implementations are
//     pointed at a dead port and must say so. Reporting a healthy clock when you
//     could not ask is the same class of lie this phase removed from the
//     recovery copy.
//  5. A MIS-PARSE IS `null`, NEVER A WRONG NUMBER. A silently wrong reading
//     would tell a user with a perfect clock to change it — worse than silence,
//     because the whole point is to stop people debugging the wrong thing.
//  6. ⛔ IT IS A DIAGNOSTIC, NEVER A CORRECTION: with the server's clock far from
//     ours, the code the vault produces is still computed from the LOCAL time we
//     passed in — the RFC 6238 vector, unchanged.
//  7. ⭐ The BROWSER can actually READ the header cross-origin. `Date` is NOT
//     CORS-safelisted, so this is not free: it needs sigild's
//     Access-Control-Expose-Headers to name it. Asserted against a real sigild
//     booted with SIGILD_CORS_ORIGINS.
//
// Dev / localhost / plain HTTP / UNAUDITED.

import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync, spawn, spawnSync } from "node:child_process";
import { createServer } from "node:net";
// ⭐ Section 3b needs a server whose `Date` header it CONTROLS, so the real
// `sigil` binary and the JS reader can be compared on a chosen skew rather than
// on whatever this machine happens to agree with.
import { createServer as createHttpServer } from "node:http";

import {
  CLOCK_SKEW_WARN_SECONDS,
  parseHttpDate,
  skewFromDateHeader,
  readClockSkew,
  fetchClockSkew,
  describeClockSkew,
} from "../clock-skew.mjs";
import { resolveGo } from "./go-helper.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");
const pkgPath = join(__dirname, "..", "pkg-node", "sigil_wasm.js");
const buildWasm = join(__dirname, "..", "build-wasm.sh");
const sigildDir = join(repoRoot, "sigild");
const cliDir = join(repoRoot, "cli");
const goBin = resolveGo();

let failures = 0;
function fail(msg) {
  failures += 1;
  console.error(`FAIL: ${msg}`);
}
function assert(cond, msg) {
  if (!cond) fail(msg);
  else console.log(`  ok  ${msg}`);
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

async function waitReady(base, timeoutMs = 20000) {
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

const work = mkdtempSync(join(tmpdir(), "sigil-clock-"));
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
console.log("building the real sigil CLI (cargo build --bin sigil) ...");
execFileSync("cargo", ["build", "--bin", "sigil"], { cwd: cliDir, stdio: "inherit" });
const sigilBin = join(cliDir, "target", "debug", "sigil");

const wasm = await import(pkgPath);

const port = await freePort();
const base = `http://127.0.0.1:${port}`;
// A page origin that is DIFFERENT from the API origin, so the CORS assertion is
// a real cross-origin one rather than a same-origin freebie.
const pageOrigin = "http://127.0.0.1:65123";
const srv = spawn(sigildBin, [], {
  env: {
    ...process.env,
    SIGILD_ADDR: `127.0.0.1:${port}`,
    SIGILD_ENABLE_DEV_OPS: "1",
    SIGILD_CORS_ORIGINS: pageOrigin,
  },
  stdio: ["ignore", "ignore", "pipe"],
});
srv.stderr.on("data", () => {});

let rc = 1;
try {
  await waitReady(base);

  // ── 1. a REAL sigild's Date header, read by the JS module ────────────────
  console.log("\n=== 1. a real sigild's Date header, read in JS ===");
  const local = Math.floor(Date.now() / 1000);
  const live = await fetchClockSkew({ baseUrl: base }, local);
  assert(live.state === "ok" || live.state === "skewed", `got a reading (${live.state})`);
  assert(
    typeof live.serverUnix === "number" && live.serverUnix > 1_600_000_000,
    `server time parsed as a plausible unix instant (${live.serverUnix})`,
  );
  assert(
    Math.abs(live.skewSeconds) <= 5,
    `this machine agrees with the server it is talking to (skew ${live.skewSeconds}s)`,
  );
  // The same reading, taken off a response the client ALREADY made — the
  // zero-extra-request path the browser sync uses.
  const anyRes = await fetch(`${base}/healthz`);
  const piggy = readClockSkew(anyRes, local);
  assert(piggy.state !== "unavailable", "readClockSkew works off an existing response");

  // ── 2. the REAL sigil binary reads the same server and agrees ────────────
  console.log("\n=== 2. the real `sigil clock` against the same server ===");
  const cli = spawnSync(sigilBin, ["clock", "--server", base], { encoding: "utf8" });
  const cliOut = `${cli.stdout}${cli.stderr}`;
  assert(cli.status === 0, `\`sigil clock\` exited 0 against a healthy pair (got ${cli.status})`);
  assert(cliOut.includes("clock OK"), "`sigil clock` reports the clock as OK");
  assert(
    cliOut.includes("server time:") && cliOut.includes("local time:"),
    "`sigil clock` prints BOTH readings, not just a verdict",
  );
  // Rust's server_unix and JS's must be the same instant (same server, seconds apart).
  const m = cliOut.match(/server time:\s+(\d+)/);
  assert(m !== null, "`sigil clock` printed a parsable server instant");
  if (m) {
    const rustServer = Number(m[1]);
    assert(
      Math.abs(rustServer - live.serverUnix) <= 5,
      `Rust and JS parsed the SAME server clock (rust ${rustServer}, js ${live.serverUnix})`,
    );
  }

  // ── 3. the MIRRORED threshold and direction ──────────────────────────────
  console.log("\n=== 3. Rust and JS agree on the threshold and the direction ===");
  assert(CLOCK_SKEW_WARN_SECONDS === 15, "JS threshold is half a 30s step");

  // ⛔⛔ THIS SECTION USED TO CLAIM AN AGREEMENT IT NEVER CHECKED. It asserted
  // the JS constant against a golden 15, printed the header above, and left the
  // Rust half entirely to `cli/src/lib.rs`'s own unit test. A verifier mutated
  // ONLY the Rust constant and this suite exited 0 — under a heading that said
  // "Rust and JS agree on the threshold". A mirror with a guard on one side is
  // not a guarded mirror, and a section header is not a check.
  //
  // It is now checked TWO ways, because each catches what the other cannot:
  //
  //   3a. THE LITERAL. The Rust constant is read out of `cli/src/lib.rs` and
  //       compared numerically to the JS one. Exact for ANY change to either
  //       literal, including 15 -> 16.
  //   3b. THE BEHAVIOUR. The real `sigil` binary is pointed at a server whose
  //       `Date` header is offset by a chosen amount, so its verdict can be
  //       compared against the JS verdict on THE SAME (server, local) pair that
  //       Rust itself printed. This is what proves the constant is actually
  //       WIRED — a matching pair of literals that nothing reads would still
  //       pass 3a.

  // ── 3a. the literal, read from the Rust source ───────────────────────────
  const rustLib = readFileSync(join(cliDir, "src", "lib.rs"), "utf8");
  const rustConst = rustLib.match(/pub const CLOCK_SKEW_WARN_SECONDS:\s*i64\s*=\s*(\d+)\s*;/);
  assert(rustConst !== null, "found `pub const CLOCK_SKEW_WARN_SECONDS` in cli/src/lib.rs");
  const rustThreshold = rustConst ? Number(rustConst[1]) : NaN;
  assert(
    rustThreshold === CLOCK_SKEW_WARN_SECONDS,
    `Rust and JS carry the SAME threshold (rust ${rustThreshold}, js ${CLOCK_SKEW_WARN_SECONDS})`,
  );
  // Pinned against a GOLDEN LITERAL as well as against each other: a COORDINATED
  // rename or retune passes a cross-language equality check while changing what
  // every client tells a user about their machine.
  assert(rustThreshold === 15, "and it is 15 — half a 30s TOTP step");

  // ── 3b. the behaviour, on the SAME reading, from the REAL binary ──────────
  // A server whose Date header is offset by a chosen number of seconds. Node's
  // `toUTCString()` emits exactly the RFC 9110 IMF-fixdate both parsers require.
  const imf = (unixSeconds) => new Date(unixSeconds * 1000).toUTCString();
  // ⚠️ ASYNC, and it must stay that way. The Date server below runs IN THIS
  // PROCESS, and `spawnSync` blocks Node's single event loop — so a synchronous
  // CLI call here deadlocks: the child waits for a response the parent cannot
  // send until the child exits. (Observed live as a hang with section 3a green
  // and 3b producing nothing.) Sections 2, 4 and 5 may keep using `spawnSync`
  // because they talk to `sigild`, a separate OS process.
  const runCli = (args) =>
    new Promise((done) => {
      const p = spawn(sigilBin, args, { stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      p.stdout.on("data", (d) => {
        out += d;
      });
      p.stderr.on("data", (d) => {
        out += d;
      });
      p.on("close", (status) => done({ status, text: out }));
    });
  let dateOffset = 0;
  const skewSrv = createHttpServer((_req, res) => {
    res.setHeader("Date", imf(Math.floor(Date.now() / 1000) + dateOffset));
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
  });
  const skewPort = await freePort();
  await new Promise((r) => skewSrv.listen(skewPort, "127.0.0.1", r));
  const skewBase = `http://127.0.0.1:${skewPort}`;
  try {
    // Straddle the boundary in both directions, and sit ON it.
    for (const offset of [0, -14, -15, -16, -17, -60, 14, 15, 16, 17, 60]) {
      dateOffset = offset;
      const run = await runCli(["clock", "--server", skewBase]);
      const { text } = run;
      const sm = text.match(/server time:\s+(\d+)/);
      const lm = text.match(/local time:\s+(\d+)/);
      if (sm === null || lm === null) {
        fail(`\`sigil clock\` printed no readable pair at offset ${offset}s:\n${text}`);
        continue;
      }
      // ⭐ The SAME two instants Rust just used, handed to the JS half. Any
      // jitter between the two clocks is therefore irrelevant: both halves are
      // judging one identical reading.
      const serverUnix = Number(sm[1]);
      const localUnix = Number(lm[1]);
      const rustSkewed = /CLOCK SKEW/.test(text);
      const js = skewFromDateHeader(imf(serverUnix), localUnix);
      assert(
        js.skewSeconds === localUnix - serverUnix,
        `offset ${offset}s: JS reproduces Rust's skew (${js.skewSeconds}s)`,
      );
      assert(
        (js.state === "skewed") === rustSkewed,
        `offset ${offset}s: same verdict from both (skew ${js.skewSeconds}s, ` +
          `rust ${rustSkewed ? "SKEWED" : "OK"}, js ${js.state})`,
      );
      // The exit status is part of the contract a script sees, so it must agree
      // with the words too.
      assert(
        (run.status !== 0) === rustSkewed,
        `offset ${offset}s: \`sigil clock\` exit status matches its own verdict`,
      );
      if (rustSkewed) {
        const dir = js.skewSeconds > 0 ? "AHEAD OF" : "BEHIND";
        assert(
          text.includes(dir) && describeClockSkew(js).includes(dir),
          `offset ${offset}s: both name the same direction (${dir})`,
        );
      }
    }
  } finally {
    await new Promise((r) => skewSrv.close(r));
  }

  const HEADER = "Sun, 06 Nov 1994 08:49:37 GMT";
  const AT = 784111777;
  assert(parseHttpDate(HEADER) === AT, "JS parses the RFC 9110 example date");
  for (const [delta, want, dir] of [
    [0, "ok", null],
    [15, "ok", null],
    [-15, "ok", null],
    [16, "skewed", "AHEAD OF"],
    [-16, "skewed", "BEHIND"],
    [300, "skewed", "AHEAD OF"],
  ]) {
    const s = skewFromDateHeader(HEADER, AT + delta);
    assert(s.state === want, `local ${delta >= 0 ? "+" : ""}${delta}s => ${want}`);
    if (dir) {
      assert(
        describeClockSkew(s).includes(`${Math.abs(delta)}s ${dir}`),
        `and the sentence names the direction (${dir})`,
      );
    }
  }

  // ── 4. OFFLINE IS "NO READING", NOT "FINE" ───────────────────────────────
  console.log("\n=== 4. offline is NO READING, never 'your clock is fine' ===");
  const deadPort = await freePort(); // closed again immediately: nothing listens
  const dead = `http://127.0.0.1:${deadPort}`;
  const jsOffline = await fetchClockSkew({ baseUrl: dead }, local);
  assert(jsOffline.state === "unavailable", "JS reports UNAVAILABLE against a dead port");
  const jsText = describeClockSkew(jsOffline);
  assert(jsText.includes("NO CLOCK READING"), "and says NO CLOCK READING");
  assert(
    /not a report that your clock is fine/i.test(jsText),
    "and explicitly denies that this means the clock is fine",
  );
  assert(!/Clock OK/i.test(jsText), "and never says 'Clock OK' with no reading");

  const cliOffline = spawnSync(sigilBin, ["clock", "--server", dead], { encoding: "utf8" });
  const offText = `${cliOffline.stdout}${cliOffline.stderr}`;
  assert(cliOffline.status !== 0, "`sigil clock` exits non-zero when it could not ask");
  assert(offText.includes("NO READING"), "`sigil clock` says NO READING");
  assert(
    /NOT a report that your clock is fine/i.test(offText),
    "and explicitly denies that this means the clock is fine",
  );
  assert(!/clock OK/i.test(offText), "and never says 'clock OK' with no reading");

  // ── 5. a mis-parse is null, NEVER a wrong number ─────────────────────────
  console.log("\n=== 5. a mis-parse is null, never a wrong number ===");
  // ⛔ "12345" is the one that mattered: `Date.parse` accepts it as the YEAR
  // 12345, so a lenient implementation turns a nonsense header into a confident
  // ~10,000-year skew and screams at a user whose clock is perfect. Both halves
  // must refuse it. The others are the ordinary shapes RFC 9110 lists as
  // obsolete or that a proxy might mangle.
  for (const bad of [
    "",
    "   ",
    "not a date",
    "12345",
    "1785468384",
    "2026-07-31T12:00:00Z", // ISO, not IMF-fixdate
    "Sun, 06 Nov 1994 08:49:37 PST", // wrong zone
    "Sunday, 06-Nov-94 08:49:37 GMT", // obsolete RFC 850
    "Sun Nov  6 08:49:37 1994", // obsolete asctime
    "Sun, 06 Nov 1994 08:49:37 GMT extra", // trailing junk
    "Sun, 06 Xxx 1994 08:49:37 GMT", // bad month
  ]) {
    assert(parseHttpDate(bad) === null, `refuses ${JSON.stringify(bad)}`);
  }
  // And the one it must ACCEPT, so the guard above cannot be "fixed" into a
  // blanket refusal that would silently disable the whole diagnostic.
  assert(parseHttpDate(HEADER) === AT, "still accepts a genuine IMF-fixdate");
  const noHeader = skewFromDateHeader(null, local);
  assert(noHeader.state === "unavailable", "a missing Date header is UNAVAILABLE, not zero skew");
  assert(
    describeClockSkew(noHeader).includes("Access-Control-Expose-Headers"),
    "and the reason names the browser cause a developer would need",
  );

  // ── 6. ⛔ A DIAGNOSTIC, NEVER A CORRECTION ───────────────────────────────
  console.log("\n=== 6. it reports; it never corrects the clock codes come from ===");
  // Point the reading at a server whose clock is (as far as this test is
  // concerned) irrelevant, then generate a code at the RFC 6238 instant. The
  // code must be the RFC vector — i.e. the CALLER's time, untouched.
  const skewedReading = skewFromDateHeader(HEADER, AT + 100_000);
  assert(skewedReading.state === "skewed", "a 100000s drift is reported as skewed");
  const key = Buffer.from("12345678901234567890", "utf8");
  const code = wasm.format_code(wasm.totp(key, 59, 30, 0, 8, "sha1"), 8);
  assert(
    code === "94287082",
    `the RFC 6238 vector is unchanged by a skew reading (got ${code})`,
  );

  // ── 7. ⭐ the BROWSER can read Date cross-origin ─────────────────────────
  console.log("\n=== 7. Date is READABLE cross-origin (it is not CORS-safelisted) ===");
  const cors = await fetch(`${base}/healthz`, { headers: { Origin: pageOrigin } });
  const exposed = cors.headers.get("access-control-expose-headers") ?? "";
  assert(
    /(^|[\s,])Date([\s,]|$)/i.test(exposed),
    `sigild exposes Date to JS (Access-Control-Expose-Headers: ${exposed || "<none>"})`,
  );
  assert(
    cors.headers.get("access-control-allow-origin") === pageOrigin,
    "and echoes the allowlisted origin",
  );
  // Without the expose header a browser would read null here and the whole
  // browser-side diagnostic would be dead — the exact shape of the CORS defect
  // that hid for twelve phases (ADR 0044).

  rc = failures === 0 ? 0 : 1;
  console.log(failures === 0 ? "\nPASS" : `\n${failures} FAILURE(S)`);
} catch (e) {
  console.error(`FAIL: ${e?.stack ?? e}`);
  rc = 1;
} finally {
  srv.kill("SIGKILL");
  rmSync(work, { recursive: true, force: true });
}
process.exit(rc);
