// docs-claims-guard — the COUNTABLE claims in the documentation must match the code.
//
// ─────────────────────────────────────────────────────────────────────────────
// WHY THIS EXISTS
//
// This project's documentation has been wrong, repeatedly, in ways that mattered:
//
//   * status blocks said `sigild` "performs no cryptography" and "holds no keys"
//     while 15 non-test files imported crypto — which would have scoped its own
//     cryptography out of an external review;
//   * `docs/threat-model.md` row V asserted a substituted key envelope "fails to
//     open", describing a defence that did not exist;
//   * `docs/api.md` gave a fixed 1226-byte layout for a route whose envelope had
//     become variable-length;
//   * CLAUDE.md's Tauri command count has drifted THREE times (21 -> 31 -> 40 -> 41);
//   * four items in journal.md's "still open" list had already been fixed — and a
//     stale OPEN item is worse than a stale status line, because it aims the next
//     person's work at finished work.
//
// ⚠️ WHAT THIS GUARD CAN AND CANNOT DO — read this before trusting it.
//
// It checks **countable** claims: numbers that can be derived from the tree by a
// command. It CANNOT check prose. The threat-model row V failure — a sentence
// asserting a security property that the primitive underneath did not provide —
// is invisible here, and that was the most dangerous one. This guard buys the
// cheap class so that human review can spend itself on the expensive class. It
// is not a substitute for reading.
//
// Each check names its ground-truth command so a failure tells you which side is
// wrong, rather than only that they disagree.
//
// Run: node sigil-wasm/test/docs-claims-guard.mjs

import { execSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const sh = (cmd) => execSync(cmd, { cwd: ROOT, encoding: "utf8" }).trim();
const read = (p) => readFileSync(join(ROOT, p), "utf8");

let failures = 0;
const fail = (m) => {
  failures += 1;
  console.error(`FAIL: ${m}`);
};

/** Number words this repo actually writes out, so "forty" is comparable to 40. */
const WORDS = {
  one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8,
  nine: 9, ten: 10, eleven: 11, twelve: 12, thirteen: 13, fourteen: 14,
  fifteen: 15, sixteen: 16, seventeen: 17, eighteen: 18, nineteen: 19,
  twenty: 20, thirty: 30, forty: 40, fifty: 50, sixty: 60,
};
const wordsAlt = Object.keys(WORDS).join("|");

/**
 * Assert that every number the docs state for `label` equals `truth`.
 *
 * `patterns` are regexes with ONE capture group holding the number (digits or a
 * word). A doc that never states the claim is not a failure — this guard exists
 * to catch DISAGREEMENT, not to mandate that every fact be written down.
 */
function claim({ label, truth, how, patterns }) {
  // ⛔ ADRs ARE EXCLUDED FROM COUNT CHECKS, BY CATEGORY — not by a hand-list.
  //
  // An ADR is a DATED, ACCEPTED RECORD of a decision. ADR 0032 says the desktop
  // has "ten `#[tauri::command]`s" and then NAMES those ten; that was true at
  // Phase 32 and "correcting" it to today's 41 would falsify the record. The
  // same reasoning as the removed schema-version check: history is not drift.
  //
  // ⚠️ The cost, stated rather than hidden: a genuinely wrong count written into
  // a NEW ADR is not caught here. ADRs still take part in the dangling-link
  // check below, because a dead link is a defect whenever it was written.
  const files = allDocs().filter((f) => !f.startsWith("docs/decisions/"));
  let checked = 0;
  for (const f of files) {
    let src;
    try {
      src = read(f);
    } catch {
      continue; // a doc that moved is the drift check's job, not this one
    }
    for (const re of patterns) {
      for (const m of src.matchAll(re)) {
        const raw = m[1].toLowerCase();
        const stated = /^\d+$/.test(raw) ? Number(raw) : WORDS[raw];
        if (stated === undefined) continue;
        checked += 1;
        if (stated !== truth) {
          fail(
            `${f}: claims ${label} = ${m[1]}, but the tree says ${truth}.\n` +
              `      ground truth: ${how}\n` +
              `      context: ${JSON.stringify(m[0].slice(0, 110))}`,
          );
        }
      }
    }
  }
  console.log(`  ok  ${label} = ${truth}  (${checked} doc claim(s) agree)`);
}


/**
 * EVERY prose document in the repo. ⚠️ NOT a hand-listed set, deliberately.
 *
 * The first version of this guard took a `files:` allowlist per check, and a
 * planted false claim ("sigild has exactly three direct dependencies") dropped
 * into docs/README.md went UNDETECTED simply because that file was not on that
 * check's list. An allowlist turns "we check the docs" into "we check the four
 * docs someone remembered", which is the same shape as a suite that runs in no
 * workflow. Scan them all; a doc nobody listed is exactly where drift hides.
 */
function allDocs() {
  const out = ["CLAUDE.md", "README.md"];
  const walk = (rel) => {
    for (const e of readdirSync(join(ROOT, rel), { withFileTypes: true })) {
      if (e.isDirectory()) walk(`${rel}/${e.name}`);
      else if (e.name.endsWith(".md")) out.push(`${rel}/${e.name}`);
    }
  };
  walk("docs");
  return out.filter((f) => {
    try { readFileSync(join(ROOT, f)); return true; } catch { return false; }
  });
}

console.log("docs-claims-guard: countable documentation claims must match the code\n");

// ── 1. Tauri commands — drifted three times ─────────────────────────────────
claim({
  label: "desktop Tauri commands",
  truth: Number(
    sh(`grep -n '#\\[tauri::command\\]' desktop/src-tauri/src/main.rs | grep -v '://' | wc -l`),
  ),
  how: "grep '#[tauri::command]' desktop/src-tauri/src/main.rs, excluding comment lines",
  // ⚠️ ONLY the attribute form. A TOTAL is written "forty `#[tauri::command]`s";
  // the bare phrase "eleven Tauri commands" is used for a SUBSET (the eleven
  // that ADR 0037 added), and matching it reported a false failure.
  // ⚠️ WIDENED after a verifier found "added no commands** (still **forty**)"
  // slipping through: the first pattern required the attribute form to follow
  // the number, and that sentence has no attribute form at all. A guard whose
  // pattern is narrower than the prose it audits reports a clean bill it has
  // not earned.
  patterns: [
    new RegExp(`(\\d+|${wordsAlt})\\s+\\*{0,2}\`?#\\[tauri::command\\]`, "gi"),
    new RegExp(`still \\*{0,2}(\\d+|${wordsAlt})\\*{0,2}\\)?:?\\s*\`?ImportSummary`, "gi"),
    new RegExp(`commands\\*{0,2} \\(still \\*{0,2}(\\d+|${wordsAlt})`, "gi"),
  ],
});

// ── 2. sigild's direct dependency count — a load-bearing invariant ───────────
claim({
  label: "sigild direct Go dependencies",
  truth: Number(
    sh(`/opt/homebrew/bin/go -C sigild list -m -f '{{if not .Indirect}}{{.Path}}{{end}}' all 2>/dev/null | grep -v 'sigild$' | grep -c .`),
  ),
  how: "go list -m, non-indirect, excluding the module itself",
  patterns: [new RegExp(`exactly (\\d+|${wordsAlt}) direct`, "gi")],
});

// ── 3. Node interop suites — the count gate.sh's inventory prints ────────────
claim({
  label: "node interop suites",
  truth: readdirSync(join(ROOT, "sigil-wasm/test")).filter(
    (f) => f.endsWith(".mjs") && !f.startsWith("fake-") && !f.endsWith("-helper.mjs"),
  ).length,
  how: "sigil-wasm/test/*.mjs excluding fake-* and *-helper.mjs (gate.sh's own expression)",
  // ⚠️ CAPTURE THE DENOMINATOR. CLAUDE.md numbers its build block "1/16",
  // "2/16", … — `N/M` where M is the total. My first pattern captured N and
  // then reported that the docs "claim 1 suite", which is a guard inventing a
  // finding. Anchor on the last step line and take M.
  patterns: [
    /\d+\/(\d+) (?:seal\/open|wasm<->CLI)/g,
    /ALL (\w+) Node interop tests/gi,
    // ⚠️ "then the SIXTEEN Node suites below must all PASS" — another phrasing
    // the first version missed.
    new RegExp(`the \\*{0,2}(\\d+|${wordsAlt})\\*{0,2} Node (?:interop )?suites`, "gi"),
  ],
});

// ── 4. Shell e2e scripts ────────────────────────────────────────────────────
claim({
  label: "shell e2e scripts",
  truth: readdirSync(join(ROOT, "cli/tests")).filter(
    (f) => f.endsWith(".sh") && !f.startsWith("_"),
  ).length,
  how: "cli/tests/*.sh excluding _* (gate.sh's own exclusion)",
  patterns: [new RegExp(`the (\\d+|${wordsAlt}) shell e2e`, "gi")],
});

// ── 5. The newest ADR, which the reviewer entry point points at ─────────────
{
  const adrs = readdirSync(join(ROOT, "docs/decisions"))
    .filter((f) => /^\d{4}-/.test(f))
    .map((f) => Number(f.slice(0, 4)))
    .sort((a, b) => a - b);
  const newest = adrs[adrs.length - 1];
  // Every ADR number must exist as a file — a dangling reference is a dead link
  // in the one folder a reviewer is told to read.
  const referenced = new Set();
  for (const f of allDocs()) {
    let src;
    try {
      src = read(f);
    } catch {
      continue;
    }
    for (const m of src.matchAll(/decisions\/(\d{4})-[a-z0-9-]+\.md/g)) {
      referenced.add(Number(m[1]));
    }
  }
  const dangling = [...referenced].filter((n) => !adrs.includes(n)).sort();
  if (dangling.length) {
    fail(`ADR references with no such file: ${dangling.join(", ")}`);
  } else {
    console.log(`  ok  ADRs 0001..${String(newest).padStart(4, "0")} — ${referenced.size} referenced, none dangling`);
  }
  // A contiguous run: a gap means an ADR was deleted or misnumbered.
  const gaps = [];
  for (let i = 1; i <= newest; i += 1) if (!adrs.includes(i)) gaps.push(i);
  if (gaps.length) fail(`ADR numbering has gaps: ${gaps.join(", ")}`);
  else console.log(`  ok  ADR numbering is contiguous 1..${newest}`);
}

// ── 6. The getrandom invariant, as stated in prose ──────────────────────────
for (const lock of ["libsigil/Cargo.lock", "sigil-wasm/Cargo.lock"]) {
  const n = Number(sh(`grep -c 'name = "getrandom"' ${lock} || true`));
  if (n !== 0) {
    fail(`${lock} contains ${n} getrandom entries — every doc asserting "getrandom-free" is now false`);
  }
}
console.log("  ok  both wasm-pure lockfiles are getrandom-free, as the docs claim");

// ── 7. (REMOVED) sigild's applied schema version ───────────────────────────
// ⛔ DELIBERATELY NOT CHECKED, and the reason is the point of this whole file.
// CLAUDE.md records `sigild_schema_version` now reports N` once per phase that
// added a migration — 2, then 3, then 4, then 5 — and every one of those
// sentences was TRUE WHEN WRITTEN. A guard comparing each against today's count
// reports three false failures out of four. That is a guard inventing findings,
// which is exactly how the always-red cargo-audit job trained people to skip the
// security workflow. Historical prose is not mechanically checkable; a human
// reading for staleness is the only control that works on it, and pretending
// otherwise would make this file untrustworthy for the claims it CAN check.


// ── 8. Playwright spec FILE counts ──────────────────────────────────────────
// ⚠️ These drifted in FOUR places at once when Phase 61 added merge.spec.ts and
// merge.spec.mjs. Counting FILES is cheap and stable; counting TESTS needs a
// built app and a `--list` run, so it is deliberately not attempted here —
// stated so nobody assumes this covers it.
for (const [label, dir, ext] of [
  ["webapp Playwright spec files", "web/apps/webapp/tests", ".spec.ts"],
  ["extension Playwright spec files", "extension/tests", ".spec.mjs"],
]) {
  const truth = readdirSync(join(ROOT, dir)).filter((f) => f.endsWith(ext)).length;
  const which = ext === ".spec.ts" ? "webapp" : "extension";
  claim({
    label,
    truth,
    how: `count of ${dir}/*${ext}`,
    patterns: [
      new RegExp(`${which}[^\\n]{0,80}?\\d+ tests in (\\d+) spec files`, "gi"),
      new RegExp(`(\\d+) tests in (?:\\d+) spec files[^\\n]{0,40}${which}`, "gi"),
    ],
  });
}

// ── 9. The entry-id golden vector must be asserted where the docs say ───────
{
  const VECTOR = "41828256-7397-80c1-bf67-e6b85ff84173";
  let truth = 0;
  try {
    // ⚠️ EXCLUDE *-guard.mjs — THIS FILE CONTAINS THE VECTOR AS A STRING LITERAL,
    // so an unfiltered grep counts the guard as an assertion site and reports
    // that a doc claiming "four" agrees when reality is three. A source guard
    // necessarily quotes what it hunts for; portability-guard.mjs hit the same
    // trap and carries the same exclusion.
    truth = Number(sh(`grep -rl '${VECTOR}' --include='*.rs' --include='*.mjs' . 2>/dev/null | grep -v target | grep -v -- '-guard\\.mjs' | wc -l`));
  } catch {
    truth = 0;
  }
  if (truth > 0) {
    claim({
      label: "entry-id golden-vector assertion sites",
      truth,
      how: `grep -rl '${VECTOR}' over *.rs and *.mjs, excluding target/`,
      patterns: [new RegExp(`asserted in \\*{0,2}(\\d+|${wordsAlt})\\*{0,2} places`, "gi")],
    });
  }
}

if (failures > 0) {
  console.error(`\nFAILED: ${failures} documentation claim(s) disagree with the code`);
  process.exit(1);
}
console.log("\nPASS: every countable documentation claim matches the tree");
