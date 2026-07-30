// portability-guard — the tests must run on Linux, not just on this Mac.
//
// WHY THIS EXISTS. Every gate in this repo runs on macOS arm64, and every CI
// workflow runs on ubuntu-latest. Nothing checked that the two agreed, so three
// jobs were RED for several phases while `scripts/gate.sh` printed ALL GREEN:
//
//   * six `*-interop.mjs` suites hardcoded `const goBin = "/opt/homebrew/bin/go"`,
//     giving `spawnSync /opt/homebrew/bin/go ENOENT` on every Linux runner. Only
//     accounts-interop.mjs had a fallback — which is exactly why the accounts job
//     was the one that passed while its neighbours failed;
//   * `e2e-sharing.sh` and `e2e-recovery.sh` used
//     `stat -f '%Lp' p 2>/dev/null || stat -c '%a' p`, which reads as "try BSD,
//     fall back to GNU" and is not, because GNU `stat -f` means --file-system and
//     does NOT fail. The mode comparison received a filesystem dump concatenated
//     with the real answer and reported a permissions violation that did not
//     exist.
//
// This is the THIRD appearance of the hardcoded-Go defect — `cors.spec.ts` had it
// too, and there it was worse, because that spec `test.skip`ped itself and stayed
// green while proving nothing. Written-down patterns did not stop it; a check
// does.
//
// ⚠️ WHAT THIS GUARD CANNOT DO. It is a source check, not a Linux run. It catches
// the two idioms that have actually bitten, and it will NOT catch a new
// macOS-only assumption of a different shape. The only real answer is running the
// suites on Linux — see the Docker recipe in journal.md. Treat this as a
// regression guard for known defects, not as portability assurance.
//
// Run: node sigil-wasm/test/portability-guard.mjs

import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");

let failures = 0;
const fail = (m) => {
  failures += 1;
  console.error(`FAIL: ${m}`);
};

console.log("portability-guard: the suites must run on Linux, not just on this Mac\n");

// ── 1. Node interop suites resolve Go, never hardcode it ─────────────────────
const testDir = join(ROOT, "sigil-wasm", "test");
// `*-guard.mjs` is excluded from the Go scan and only from it: a source guard
// necessarily QUOTES the patterns it hunts for, so scanning itself is a
// guaranteed false positive (this file flagged itself on first run). Guards do
// not spawn subprocesses, so nothing real is lost — but the exclusion is
// deliberately narrow, and every guard is still enumerated by `suites` below and
// by gate.sh's runner, drift check and inventory.
const suites = readdirSync(testDir).filter(
  (f) => f.endsWith(".mjs") && !f.startsWith("fake-") && !f.endsWith("-helper.mjs"),
);
if (suites.length === 0) fail("found NO node suites — this guard's paths are stale");

let goUsers = 0;
for (const f of suites) {
  if (f.endsWith("-guard.mjs")) continue; // see the note on `suites` above
  const src = readFileSync(join(testDir, f), "utf8");
  const usesGo = /\bgoBin\b/.test(src) || /resolveGo\s*\(/.test(src);
  if (!usesGo) continue;
  goUsers += 1;

  if (!/from\s+"\.\/go-helper\.mjs"/.test(src)) {
    fail(
      `${f} spawns a Go toolchain but does not import resolveGo from ` +
        `"./go-helper.mjs". Hand-rolling the lookup is how six suites ended up ` +
        `hardcoding /opt/homebrew/bin/go and failing on every Linux runner.`,
    );
  }
  if (src.includes("/opt/homebrew/bin/go")) {
    fail(
      `${f} still contains a literal "/opt/homebrew/bin/go". That path does not ` +
        `exist on a Linux runner; go-helper.mjs is the only place it belongs.`,
    );
  }
}
if (goUsers === 0) {
  fail("no suite appears to use Go at all — several do, so this guard's detection is broken");
} else {
  console.log(`  ok  ${goUsers} node suite(s) resolve Go through go-helper.mjs`);
}

// ── 2. Shell e2e proofs read file modes portably ─────────────────────────────
const shDir = join(ROOT, "cli", "tests");
const scripts = readdirSync(shDir).filter((f) => f.endsWith(".sh") && !f.startsWith("_"));
if (scripts.length === 0) fail("found NO shell e2e scripts — this guard's paths are stale");

for (const f of scripts) {
  const src = readFileSync(join(shDir, f), "utf8");
  // A bare `stat -X` call outside the shared library. `filemode` is the only
  // sanctioned way to read permission bits.
  const m = src.match(/^.*\bstat\s+-[a-zA-Z].*$/m);
  if (m) {
    fail(
      `${f} calls \`stat\` directly:\n        ${m[0].trim()}\n` +
        `      Use filemode() from _e2e-lib.sh. BSD and GNU stat disagree, and ` +
        `the obvious "try one, fall back to the other" idiom is BROKEN because ` +
        `GNU \`stat -f\` succeeds rather than failing.`,
    );
  }
  if (/if \[\[ -x \/opt\/homebrew\/bin\/go \]\]/.test(src)) {
    fail(`${f} hand-rolls Go resolution — call resolve_go from _e2e-lib.sh instead.`);
  }
}
console.log(`  ok  ${scripts.length} shell e2e script(s) use the shared portability helpers`);

// ── 3. The browser spec that already learned this lesson keeps its PATH lookup ─
// cors.spec.ts silently test.skip()ped itself in CI because it resolved Go as
// `process.env.GO ?? "/opt/homebrew/bin/go"` with no PATH lookup. actions/setup-go
// puts `go` on PATH and NEVER sets $GO, which is why adding setup-go alone did
// not fix it.
const cors = join(ROOT, "web", "apps", "webapp", "tests", "cors.spec.ts");
try {
  const src = readFileSync(cors, "utf8");
  if (src.includes("/opt/homebrew/bin/go") && !/for \(const candidate of \[/.test(src)) {
    fail(
      "cors.spec.ts references the Homebrew Go path without a PATH candidate " +
        "list. Without one it resolves nothing on CI and skips itself — a green " +
        "job proving nothing about CORS.",
    );
  } else {
    console.log("  ok  cors.spec.ts keeps its PATH lookup");
  }
} catch {
  console.log("  --  cors.spec.ts not found (moved? this guard should move with it)");
}

if (failures > 0) {
  console.error(`\nFAILED: ${failures} portability problem(s)`);
  process.exit(1);
}
console.log("\nPASS: no known macOS-only idiom in the suites");
