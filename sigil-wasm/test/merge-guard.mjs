// merge-guard — a SOURCE-STRUCTURE guard over the merge's PREMISES: no shipping
// client may ADOPT the newest op-log snapshot, every removal must record a
// tombstone, imports must de-dup by CONTENT, entries must stay IMMUTABLE, and
// the tombstone growth limit must be warned about before it becomes a 413.
//
// ⛔ WHY THIS EXISTS, and why it is a source check rather than a behavioural one.
//
// Phase 61 fixed last-writer-wins: every client took `ops[ops.length - 1]` (or,
// on the desktop, `pull_vault`'s `max_by_key(|op| op.seq)`) and wrote it over the
// local vault, so an account added on a device that had not pulled first was
// silently destroyed. The fix routes every adoption through a merge.
//
// `docs/engineering-lessons.md` entry 10 is why a library test is not enough:
// two Phase 59 fixes were guarded in the shared module and UNGUARDED in the
// shipping app, and reverting the app's call sites left webapp 50/50 and
// extension 14/14 GREEN. The behavioural proofs for this phase
// (`merge-interop.mjs`, `web/apps/webapp/tests/merge.spec.ts`,
// `extension/tests/merge.spec.mjs`, `desktop/core/tests/server_interop.rs`) each
// cover the sites that exist TODAY. This guard covers the failure that actually
// recurs: a NEW adoption site written later that forgets.
//
// ⚠️ WHAT IT DOES NOT PROVE. It proves the shipping call sites CALL the merge and
// that removals CALL a tombstoning remove. It proves nothing at all about whether
// the merge is correct — that is what the behavioural suites are for, and neither
// substitutes for the other.
//
// ⚠️ IT MUST FAIL WHEN IT FINDS NOTHING. A rename that made every pattern miss
// would otherwise turn this into a silent no-op, which is exactly how guard #8 in
// the lessons document died.
//
// Run: node sigil-wasm/test/merge-guard.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");

let failures = 0;
const fail = (m) => {
  failures += 1;
  console.error(`FAIL: ${m}`);
};

const lineOf = (src, index) => src.slice(0, index).split("\n").length;

/** Every index at which `re` matches, with its line number. */
function hits(src, re) {
  const out = [];
  const rx = new RegExp(re.source, re.flags.includes("g") ? re.flags : `${re.flags}g`);
  let m;
  while ((m = rx.exec(src)) !== null) {
    out.push({ index: m.index, line: lineOf(src, m.index), text: m[0], groups: m.slice(1) });
  }
  return out;
}

function read(rel) {
  try {
    return readFileSync(resolve(ROOT, rel), "utf8");
  } catch {
    fail(`${rel}: cannot read — if this file moved, this guard must move with it`);
    return null;
  }
}

/**
 * Blank out line comments so a COMMENT explaining the defect is not counted as
 * the defect. ⚠️ Blanked, not deleted, so line numbers in failure messages stay
 * true — a guard that reports the wrong line sends the next reader to the wrong
 * place, which is its own small version of the problem this file exists for.
 *
 * ⛔⛔ THE `*` RULE IS LOAD-BEARING AND IT USED TO BE WRONG. The pattern was
 * `/^\s*(\/\/|\*|\/\*)/` — blank ANY line whose first character is `*`, meant for
 * block-comment continuation lines. But that is ALSO the shape of a Rust deref
 * assignment:
 *
 *     *e = TotpEntry { label: new_label.into(), ..e.clone() };
 *
 * …which is precisely the whole-struct-replace edit section 6b exists to catch.
 * The stripper BLANKED IT, so the guard read a planted bypass as a clean tree and
 * reported PASS. A `*` is only treated as a comment when it is followed by
 * whitespace, a `/` (the block-comment terminator) or the end of the line;
 * `*e`, `*self` and `*(` are CODE.
 */
function stripComments(src) {
  // ⚠️ TRACK BLOCK-COMMENT STATE — DO NOT PATTERN-MATCH A LEADING `*`.
  //
  // This used to blank any line matching /^\s*(\/\/|\/\*|\*(\s|\/|$))/, where the
  // last branch was meant for the `*` continuation lines of a /* … */ block.
  // But that is ALSO the shape of a Rust deref assignment, so the stripper
  // DELETED THE BYPASS BEFORE ANY PATTERN COULD SEE IT:
  //
  //     *e = TotpEntry { label: x, ..e.clone() };     // caught only after a fix
  //     * e = TotpEntry { label: x, ..e.clone() };    // STILL survived it
  //
  // I confirmed the spaced form live: merge-guard exit 0, zero FAILs, while
  // `cargo fmt --check` exit 1. Relying on rustfmt to reformat a bypass into a
  // shape the guard happens to catch is not a control — it is a coincidence
  // that holds until someone runs the guard on unformatted code.
  //
  // Tracking `/* … */` properly removes the whole class. `//` is still matched
  // only at line start, deliberately: blanking from any `//` would eat the
  // `https://` in a URL and silently shrink what every check below inspects.
  const out = [];
  let inBlock = false;
  for (const line of src.split("\n")) {
    if (inBlock) {
      if (line.includes("*/")) inBlock = false;
      out.push("");
      continue;
    }
    const t = line.trimStart();
    if (t.startsWith("//")) {
      out.push("");
    } else if (t.startsWith("/*")) {
      if (!line.includes("*/")) inBlock = true;
      out.push("");
    } else {
      out.push(line);
    }
  }
  return out.join("\n");
}

// ───────────────────────────────────────────────────────────────────────────
// ⭐ LENGTH-PRESERVING VIEWS + BRACE MATCHING.
//
// `stripComments` above blanks whole COMMENT LINES, which is enough to keep a
// comment from being read as code but destroys character offsets (it replaces a
// line's text with ""). Section 3b needs offsets: it asks "does the confirmation
// run BEFORE the destructive call, inside the same handler?", and that is a
// question about POSITIONS, not about whether two patterns both appear somewhere
// in a 1,200-line file.
//
// So there are two views, both EXACTLY as long as the original and therefore
// index-compatible with it and with each other:
//
//   blank(src, { strings: true })  — comments AND string/template/regex literals
//                                    blanked. Braces here are structure only, so
//                                    it is what brace matching walks.
//   blank(src, { strings: false }) — only comments blanked. String CONTENTS
//                                    survive, so `data-testid="…"` and prompt
//                                    wording can be matched.
//
// ⚠️ Why not a real parser: adding one would be a new dependency in a repo whose
// whole posture is "don't", for a guard. The self-test at the end of section 3b
// pins this machinery against the exact mutations it exists to catch, so a
// botched scanner reads as RED rather than as a clean tree.
// ───────────────────────────────────────────────────────────────────────────

/** Can a `/` at this point start a regex literal? Standard prev-token rule. */
const REGEX_MAY_FOLLOW = /[({[,;:=!&|?+\-*%~^<>]/;

/**
 * Blank comments (and optionally literals), preserving length and newlines.
 *
 * @param {string} src
 * @param {{strings:boolean}} opts
 * @returns {string} the same length as `src`
 */
function blank(src, { strings }) {
  const out = src.split("");
  const n = src.length;
  const wipe = (from, to) => {
    for (let k = from; k < to && k < n; k += 1) if (out[k] !== "\n") out[k] = " ";
  };
  let i = 0;
  let lastSig = "";
  while (i < n) {
    const c = src[i];
    const d = src[i + 1];
    if (c === "/" && d === "/") {
      let j = i;
      while (j < n && src[j] !== "\n") j += 1;
      wipe(i, j);
      i = j;
      continue;
    }
    if (c === "/" && d === "*") {
      const k = src.indexOf("*/", i + 2);
      const j = k === -1 ? n : k + 2;
      wipe(i, j);
      i = j;
      continue;
    }
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n) {
        if (src[j] === "\\") {
          j += 2;
          continue;
        }
        if (src[j] === c || src[j] === "\n") break;
        j += 1;
      }
      const end = Math.min(j + 1, n);
      if (strings) wipe(i, end);
      i = end;
      lastSig = "x";
      continue;
    }
    if (c === "`") {
      // Blank the WHOLE template, `${…}` included. Blanking a matched pair
      // removes one `{` and one `}`, so brace balance is preserved either way.
      let j = i + 1;
      let depth = 0;
      while (j < n) {
        if (src[j] === "\\") {
          j += 2;
          continue;
        }
        if (depth === 0 && src[j] === "`") break;
        if (src[j] === "$" && src[j + 1] === "{") {
          depth += 1;
          j += 2;
          continue;
        }
        if (depth > 0 && src[j] === "{") depth += 1;
        else if (depth > 0 && src[j] === "}") depth -= 1;
        j += 1;
      }
      const end = Math.min(j + 1, n);
      if (strings) wipe(i, end);
      i = end;
      lastSig = "x";
      continue;
    }
    if (c === "/" && (lastSig === "" || REGEX_MAY_FOLLOW.test(lastSig))) {
      let j = i + 1;
      let cls = false;
      let closed = false;
      while (j < n) {
        const e = src[j];
        if (e === "\\") {
          j += 2;
          continue;
        }
        if (e === "\n") break;
        if (e === "[") cls = true;
        else if (e === "]") cls = false;
        else if (e === "/" && !cls) {
          closed = true;
          break;
        }
        j += 1;
      }
      if (closed) {
        const end = Math.min(j + 1, n);
        if (strings) wipe(i, end);
        i = end;
        lastSig = "x";
        continue;
      }
    }
    if (!/\s/.test(c)) lastSig = c;
    i += 1;
  }
  return out.join("");
}

/**
 * The `{` of every block enclosing `index`, INNERMOST FIRST.
 *
 * `code.slice(open, index)` is therefore exactly the source that provably runs
 * before `index` within that block — not code after it, and not code in a
 * sibling block. That distinction is the whole point: the old desktop check
 * asked only whether `window.confirm(` appeared ANYWHERE in the file, and the
 * file has six of them for unrelated things.
 *
 * @param {string} code a `blank(src, {strings:true})` view
 */
function enclosingOpens(code, index, levels = 8) {
  const out = [];
  let depth = 0;
  for (let i = index - 1; i >= 0 && out.length < levels; i -= 1) {
    const c = code[i];
    if (c === "}") depth += 1;
    else if (c === "{") {
      if (depth === 0) out.push(i);
      else depth -= 1;
    }
  }
  return out;
}

/** The index of the `}` closing the `{` at `open`, or -1. */
function matchBrace(code, open) {
  let depth = 0;
  for (let i = open; i < code.length; i += 1) {
    if (code[i] === "{") depth += 1;
    else if (code[i] === "}") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/**
 * The receiver of the INNERMOST `<recv>.addEventListener("click", …)` whose
 * handler body contains `index`, or null.
 *
 * Exact rather than proximity-based: for each candidate listener the handler's
 * opening brace is found and matched, and the candidate only counts when
 * `index` falls inside it.
 */
function enclosingClickListener(code, text, index) {
  let best = null;
  for (const m of hits(text, /(\w+)\s*\.addEventListener\s*\(\s*["']click["']/)) {
    if (m.index >= index) continue;
    const open = code.indexOf("{", m.index);
    if (open === -1 || open > index) continue;
    const close = matchBrace(code, open);
    if (close === -1 || close < index) continue;
    if (best === null || m.index > best.index) best = { index: m.index, recv: m.groups[0] };
  }
  return best;
}

console.log("merge-guard: no shipping client may adopt the tip, and no removal may skip a tombstone\n");

let checks = 0;

// ───────────────────────────────────────────────────────────────────────────
// 1. THE ADOPTION SITES. Each shipping client must reach the merge helper.
// ───────────────────────────────────────────────────────────────────────────
const ADOPTERS = [
  {
    rel: "web/apps/webapp/app/authenticator.tsx",
    // The parent's merge entry point, plus the two places that consume op lists.
    requires: [/mergeOpsInto\s*\(/, /onMergeOps\s*\(/],
    what: "the webapp's Pull and restore-from-kit paths",
  },
  {
    rel: "extension/src/popup/popup.js",
    requires: [/mergeOpsInto\s*\(/],
    what: "the extension popup's Pull and restore-from-kit paths",
  },
  {
    rel: "desktop/core/src/net.rs",
    requires: [/merge_ops_into\s*\(/, /pull_vault_ops\s*\(/],
    what: "the desktop's pull_and_adopt",
  },
  {
    rel: "cli/src/main.rs",
    requires: [/merge_ops_into\s*\(/],
    what: "`sigil totp sync`",
  },
];

for (const { rel, requires, what } of ADOPTERS) {
  const src = read(rel);
  if (src === null) continue;
  for (const re of requires) {
    checks += 1;
    if (re.test(src)) {
      console.log(`  ok  ${rel}: ${what} reaches ${re.source}`);
    } else {
      fail(
        `${rel}: ${what} does NOT reach ${re.source}. An adoption that does not merge ` +
          `DESTROYS every account the newest snapshot has not seen.`,
      );
    }
  }
}

// ───────────────────────────────────────────────────────────────────────────
// 2. THE BANNED SHAPE. A bare tip-read must not appear on an adoption path.
//
// ⚠️ Deliberately narrow: `ops[ops.length - 1]` is legitimate in a few places
// that are NOT adoptions (reading the tip's HEADER to ratchet Argon2 params, or
// probing that a freshly unwrapped key opens something). Those are allowed by an
// explicit allowlist so the guard stays honest instead of being weakened
// wholesale — and an allowlist entry that stops matching is itself a failure.
// ───────────────────────────────────────────────────────────────────────────
const TIP_READ = /ops\[ops\.length\s*-\s*1\]/;
const ALLOWED_TIP_READS = [
  {
    rel: "web/apps/webapp/app/authenticator.tsx",
    count: 1,
    why: "ratchetParams reads the tip's Argon2 HEADER on the restore path; the vault content itself comes from mergeOpsInto",
  },
  {
    rel: "extension/src/popup/popup.js",
    count: 1,
    why: "same as the webapp: a header read for the ratchet, not an adoption",
  },
  {
    rel: "sigil-wasm/sharing.mjs",
    count: 1,
    why: "acceptVault PROBES that the unwrapped key opens the tip; it adopts nothing",
  },
];

for (const { rel, count, why } of ALLOWED_TIP_READS) {
  const src = read(rel);
  if (src === null) continue;
  checks += 1;
  const found = hits(stripComments(src), TIP_READ);
  if (found.length === count) {
    console.log(`  ok  ${rel}: ${found.length} allowed tip read(s) — ${why}`);
  } else {
    fail(
      `${rel}: expected exactly ${count} tip read(s) (${why}), found ${found.length} ` +
        `at line(s) ${found.map((f) => f.line).join(", ") || "none"}. ` +
        `A NEW one is almost certainly an adoption that skips the merge; ` +
        `a MISSING one means this allowlist entry is stale and must be re-justified.`,
    );
  }
}

// Anywhere else, a tip read is banned outright.
const BANNED_IN = [
  "web/packages/sigil-wasm/index.mjs",
  "sigil-wasm/totp-vault.mjs",
  "sigil-wasm/sync.mjs",
  "sigil-wasm/recovery.mjs",
];
for (const rel of BANNED_IN) {
  const src = read(rel);
  if (src === null) continue;
  checks += 1;
  // Comments explaining the defect are fine; code is not. Strip line comments.
  const found = hits(stripComments(src), TIP_READ);
  if (found.length === 0) {
    console.log(`  ok  ${rel}: no tip read`);
  } else {
    fail(`${rel}: a tip read appeared at line(s) ${found.map((f) => f.line).join(", ")}`);
  }
}

// ⭐ And the desktop's tip-read helper must not be what `pull_and_adopt` uses.
{
  const rel = "desktop/core/src/net.rs";
  const src = read(rel);
  if (src !== null) {
    checks += 1;
    const fnStart = src.indexOf("pub fn pull_and_adopt");
    if (fnStart === -1) {
      fail(`${rel}: pull_and_adopt is gone — this guard must move with it`);
    } else {
      // The function body up to the next top-level `pub fn`/`fn ` at column 0.
      const rest = src.slice(fnStart);
      const end = rest.slice(1).search(/\n(pub )?fn /);
      const body = end === -1 ? rest : rest.slice(0, end + 1);
      if (/\bself\.pull_vault\s*\(|config\.pull_vault\s*\(/.test(body)) {
        fail(
          `${rel}: pull_and_adopt calls pull_vault (a TIP READ). It must call ` +
            `pull_vault_ops and fold them through merge_ops_into.`,
        );
      } else {
        console.log(`  ok  ${rel}: pull_and_adopt does not read the tip`);
      }
    }
  }
}

// ───────────────────────────────────────────────────────────────────────────
// 3. REMOVALS MUST TOMBSTONE. A removal that only filters `entries` is exactly
//    the pre-Phase-61 behaviour: the entry comes back on the next merge.
// ───────────────────────────────────────────────────────────────────────────
const REMOVERS = [
  {
    rel: "web/apps/webapp/app/authenticator.tsx",
    requires: /wasm\.removeEntry\s*\(/,
    banned: /entries\s*=\s*[a-zA-Z_$.]*entries\.filter\s*\(/,
  },
  {
    rel: "extension/src/popup/popup.js",
    requires: /removeEntry\s*\(\s*wasm\s*,/,
    banned: /entries\s*=\s*[a-zA-Z_$.]*entries\.filter\s*\(/,
  },
];

for (const { rel, requires, banned } of REMOVERS) {
  const src = read(rel);
  if (src === null) continue;
  checks += 1;
  if (!requires.test(src)) {
    fail(
      `${rel}: no tombstoning removeEntry(...) call. A removal that writes no ` +
        `tombstone is undone by the next merge with a device that still holds it.`,
    );
  } else {
    console.log(`  ok  ${rel}: removal goes through the tombstoning helper`);
  }
  checks += 1;
  const found = hits(stripComments(src), banned);
  if (found.length === 0) {
    console.log(`  ok  ${rel}: no bare entries.filter removal`);
  } else {
    fail(
      `${rel}: a bare \`entries = entries.filter(...)\` removal at line(s) ` +
        `${found.map((f) => f.line).join(", ")} — it writes no tombstone.`,
    );
  }
}

// The desktop's removal goes through the CLI library, which tombstones; what the
// UI must not do is remove by a LABEL it cannot disambiguate.
{
  const rel = "desktop/ui/main.js";
  const src = read(rel);
  if (src !== null) {
    checks += 1;
    if (/call\(\s*"remove_by_id"/.test(src)) {
      console.log(`  ok  ${rel}: removes by identity`);
    } else {
      fail(`${rel}: does not call remove_by_id — removing by label is ambiguous`);
    }
  }
}

// ───────────────────────────────────────────────────────────────────────────
// 3b. ⛔ EVERY GUI REMOVAL MUST BE CONFIRMED FIRST.
//
// The tombstone is what makes this a source-structure concern and not a taste
// one. A removal is now PERMANENT AND PROPAGATING by design: it writes a
// tombstone that every other device merges and that is specifically protected
// against resurrection (ADR 0049 §3 — delete wins, and a stale snapshot re-adding
// the id LOSES). Before Phase 61 a mis-click might have been undone by accident
// on the next sync; now it provably will not be. And losing a 2FA secret can mean
// losing the account it protects.
//
// In every GUI the Remove control sits inches from the code the user came to
// read, on a row that re-renders once a second — so a bare one-click delete is
// not an edge case, it is the expected mis-click.
//
// ⚠️ THE CLI IS DELIBERATELY EXEMPT: `sigil totp remove <label>` is already a
// typed, deliberate statement of intent, and a prompt would break every script.
// It prints the consequence instead, which is checked separately below.
//
// ⚠️ WHAT THIS PROVES AND DOES NOT. It proves a confirmation EXISTS on the path,
// not that it is correct or unbypassable — the behavioural proofs are
// `web/apps/webapp/tests/user-safety.spec.ts` and
// `extension/tests/user-safety.spec.mjs`, which click the real buttons.
//
// ⛔⛔ THIS CHECK WAS REWRITTEN AFTER IT FAILED ON ITS OWN SUBJECT MATTER — the
// FIFTH guard in this repo to do so (`docs/engineering-lessons.md`). The first
// version asserted two things that were true whether or not the confirmation
// existed:
//
//   (a) DESKTOP. It required `/window\.confirm\(/` to appear ANYWHERE in
//       `desktop/ui/main.js`. That file has SIX `window.confirm(` calls, for
//       re-pinning a changed key, rekeying, forgetting the vault and so on. A
//       verifier deleted the delete confirmation OUTRIGHT and the guard still
//       printed a green line. It was matching the wrong five calls.
//   (b) EXTENSION. It banned the single spelling
//       `/rm\.addEventListener\(\s*"click"\s*,\s*async/`. A verifier replaced it
//       with a NON-async handler that still performed the removal
//       (`rm.addEventListener("click", () => { void withVault(...) })`) and the
//       guard passed. Banning one spelling of a bypass bans that spelling, not
//       the bypass.
//
// ⭐ THE RULE THIS NOW FOLLOWS: assert the PRESENCE of the confirmation ON THE
// PATH TO THE DESTRUCTIVE CALL, never the ABSENCE of some spelling of its
// bypass. There are infinitely many spellings of a bypass and exactly one
// question worth asking — "can this call be reached without the gate?" — so each
// client is checked by locating the destructive call and walking OUT from it.
//
// Each check is a pure `src -> {ok, why}` predicate so the SELF-TEST below can
// run it against specimens that ARE the two mutations above. That is what stops
// this from regressing a sixth time: the mutations are now encoded in the guard.
// ───────────────────────────────────────────────────────────────────────────

/**
 * DESKTOP — `desktop/ui/main.js` calls `call("remove_by_id", …)`. Every such
 * call must be DOMINATED, inside one of its own enclosing blocks, by a
 * `window.confirm(` whose result is acted on (`return`) and whose prompt both
 * names the account (a `Delete ${…}` template) and states the consequence.
 */
function desktopDeleteGate(src) {
  const code = blank(src, { strings: true });
  const text = blank(src, { strings: false });
  // Found in the STRING-PRESERVING view — the command name is a string literal,
  // so the structure view has blanked it. The two views are the same length, so
  // the index carries straight over to the brace walk below.
  const sites = hits(text, /call\(\s*"remove_by_id"/);
  if (sites.length === 0) {
    return {
      ok: false,
      why:
        "no `call(\"remove_by_id\", …)` site found at all. Either the removal moved (this guard " +
        "must move with it) or the desktop removes by LABEL again, which cannot disambiguate " +
        "two accounts sharing one.",
    };
  }
  for (const site of sites) {
    const opens = enclosingOpens(code, site.index);
    // ⛔ THE ANSWER MUST BE CONSUMED, NOT MERELY ASKED FOR.
    //
    // This used to accept any enclosing block containing BOTH `window.confirm(`
    // and a `return`. A verifier defeated it by keeping the full confirmation
    // text and DISCARDING its result:
    //
    //     window.confirm(`Delete ${who}? …`);   // <- Cancel deletes anyway
    //     await call("remove_by_id", { uuid });
    //
    // The dialog appears, the user clicks Cancel, and the secret is destroyed —
    // the single worst outcome this whole phase exists to prevent, passing a
    // guard whose failure message promised "(and acts on its answer)". It
    // promised a property it did not check.
    //
    // A call whose value is used is never at STATEMENT POSITION: it is preceded
    // by `if (`, `!`, `=`, `return`, `&&`, `||`, `? `, and so on. A call whose
    // value is thrown away sits directly after `;`, `{`, `}` or the start of the
    // block. That distinction is the whole check.
    const gated = opens.some((o) => {
      const before = code.slice(o, site.index);
      const m = [...before.matchAll(/window\.confirm\s*\(/g)].pop();
      if (!m) return false;
      const prefix = before.slice(0, m.index).replace(/\s+$/, "");
      const last = prefix.slice(-1);
      const consumed = last !== "" && last !== ";" && last !== "{" && last !== "}";
      return consumed && /\breturn\b/.test(before.slice(m.index));
    });
    if (!gated) {
      return {
        ok: false,
        why:
          `the removal at line ${site.line} is reachable without a confirmation: no enclosing ` +
          `block runs \`window.confirm(\` (and acts on its answer) before it`,
      };
    }
    // ⛔ …AND IT MUST NOT PROMISE A SYNC THE PRODUCT DOES NOT PERFORM. The
    // desktop is the ONE client whose delete confirmation has no behavioural
    // spec (its UI is by-eye), so this is the only thing standing between it and
    // a repeat of the copy that said the deletion "is synced to every other
    // device holding it". Sync here is MANUAL — explicit Push / Pull — and a
    // vault with no server configured never propagates at all.
    const overclaims = opens.some((o) =>
      /is synced to every other device/.test(text.slice(o, site.index)),
    );
    if (overclaims) {
      return {
        ok: false,
        why:
          `the confirmation before line ${site.line} claims the deletion "is synced to every ` +
          `other device", which is FALSE: sync is MANUAL (Push / Pull) and a vault with no ` +
          `server configured never propagates at all`,
      };
    }
    const named = opens.some((o) => /Delete \$\{/.test(text.slice(o, site.index)));
    const explained = opens.some((o) => /permanently deletes/.test(text.slice(o, site.index)));
    if (!named || !explained) {
      return {
        ok: false,
        why:
          `the confirmation before line ${site.line} does not ${!named ? "NAME the account" : "state that the deletion is permanent"}` +
          ` — labels stopped being unique in Phase 61, so a prompt that cannot say WHICH account ` +
          `is about to be destroyed is not a confirmation`,
      };
    }
  }
  return { ok: true, why: `${sites.length} removal site(s), each gated by a naming confirmation` };
}

/**
 * EXTENSION — `extension/src/popup/popup.js` gates with a two-button confirm
 * strip rather than a blocking `confirm()`, so the property is STRUCTURAL: every
 * `removeEntry(` call must sit inside the click handler of the button that
 * carries `data-testid = "remove-confirm-yes"`, and not the row's Remove button.
 *
 * ⭐ The handler's SHAPE is never inspected. async or not, arrow or function,
 * wrapped in `void` or awaited — all that is asked is which button it hangs off.
 */
function extensionDeleteGate(src) {
  const code = blank(src, { strings: true });
  const text = blank(src, { strings: false });
  const yes = text.match(/(\w+)\.dataset\.testid\s*=\s*"remove-confirm-yes"/);
  if (!yes) {
    return {
      ok: false,
      why:
        'no element is tagged `dataset.testid = "remove-confirm-yes"`, so there is no confirm ' +
        "button to hang the removal off (and `user-safety.spec.mjs` cannot address one either)",
    };
  }
  const yesVar = yes[1];
  const sites = hits(code, /\bremoveEntry\s*\(/);
  if (sites.length === 0) {
    return {
      ok: false,
      why:
        "no `removeEntry(` site found at all — either the removal moved (this guard must move " +
        "with it) or the popup removes without writing a tombstone",
    };
  }
  for (const site of sites) {
    const listener = enclosingClickListener(code, text, site.index);
    if (listener === null) {
      return {
        ok: false,
        why: `the removal at line ${site.line} is not inside any click handler — it cannot be told whether it is gated`,
      };
    }
    if (listener.recv !== yesVar) {
      return {
        ok: false,
        why:
          `the removal at line ${site.line} runs from \`${listener.recv}\`'s click handler, not ` +
          `\`${yesVar}\`'s (the "remove-confirm-yes" button) — one click on the row destroys a ` +
          `2FA secret`,
      };
    }
  }
  return {
    ok: true,
    why: `${sites.length} removal site(s), all inside \`${yesVar}\` (the confirm button) — handler shape irrelevant`,
  };
}

/**
 * WEBAPP — `AccountRow` in `authenticator.tsx`. The destructive prop
 * `onRemove()` may only be INVOKED from inside the element carrying
 * `data-testid="remove-confirm-yes"`, and the row's own Remove button element
 * must not mention it at all.
 *
 * Scoped to `AccountRow`, because the parent components legitimately PASS
 * `onRemove` down; what is banned is CALLING it outside the gate.
 */
function webappDeleteGate(src) {
  const text = blank(src, { strings: false });
  const start = text.indexOf("function AccountRow(");
  if (start === -1) {
    return { ok: false, why: "no `function AccountRow(` — the row component moved; move this guard with it" };
  }
  const rest = text.indexOf("\nfunction ", start + 1);
  const body = text.slice(start, rest === -1 ? text.length : rest);
  const at = (i) => lineOf(text, start + i);
  if (!/data-testid="remove-confirm-yes"/.test(body)) {
    return { ok: false, why: 'AccountRow has no `data-testid="remove-confirm-yes"` element to confirm with' };
  }
  if (!/setConfirming\s*\(\s*true\s*\)/.test(body)) {
    return { ok: false, why: "AccountRow never opens a confirmation (`setConfirming(true)`)" };
  }
  // ⚠️ ANY invocation, not just the zero-arg one: `onRemove(id)` destroys just
  // as much, and a guard that only knows one call shape is the bug this whole
  // section was rewritten to remove.
  const calls = hits(body, /\bonRemove\s*\(/);
  if (calls.length === 0) {
    return { ok: false, why: "AccountRow never invokes `onRemove()` — the removal moved; move this guard with it" };
  }
  for (const c of calls) {
    const tag = body.lastIndexOf("<button", c.index);
    const region = tag === -1 ? "" : body.slice(tag, c.index);
    if (!/data-testid="remove-confirm-yes"/.test(region)) {
      return {
        ok: false,
        why:
          `\`onRemove()\` is invoked at line ${at(c.index)} from an element that is NOT the ` +
          `"remove-confirm-yes" button — one click destroys a 2FA secret`,
      };
    }
  }
  const openIdx = body.indexOf('data-testid="account-remove"');
  if (openIdx === -1) {
    return { ok: false, why: 'the row has no `data-testid="account-remove"` button' };
  }
  const tagStart = body.lastIndexOf("<button", openIdx);
  const tagEnd = body.indexOf("</button>", openIdx);
  const el = body.slice(tagStart === -1 ? openIdx : tagStart, tagEnd === -1 ? body.length : tagEnd);
  if (/onRemove/.test(el)) {
    return {
      ok: false,
      why:
        `the row's Remove button (line ${at(openIdx)}) references \`onRemove\` itself — it must ` +
        `only open the confirmation`,
    };
  }
  return { ok: true, why: `${calls.length} \`onRemove()\` call(s), all inside the confirm button` };
}

// ── The desktop's GUI add-form must run the ADR 0051 ingest ceiling ─────────
//
// ⛔ WHY: the desktop's add-form shipped UNGATED while ADR 0051 asserted that
// GUI forms are gated — the phase's own stated policy, false about two of three
// GUI clients, found by an independent verifier rather than by the build. The
// webapp and the extension are covered by product-level Playwright specs; the
// desktop's window is rendered by no test (ADR 0050 limit 5), so this is the
// only thing standing between that door and a silent regression.
//
// ⚠️ It is a SOURCE check. It proves the Tauri command calls the gate; it proves
// NOTHING about whether the window shows the refusal.
{
  const rel = "desktop/src-tauri/src/main.rs";
  const src = read(rel);
  if (src === null) {
    fail(`${rel}: cannot read — if the Tauri shell moved, this guard must move with it`);
  } else {
    checks += 1;
    const body = fnBody(src, "fn add_secret(");
    if (body === null) {
      fail(
        `${rel}: no \`fn add_secret(\` found. Either the GUI add-form command was renamed ` +
          `(this guard must be renamed with it) or it is gone — do not assume the latter.`,
      );
    } else if (!/check_form_provisioning\s*\(/.test(body)) {
      fail(
        `${rel}: the \`add_secret\` command does NOT call \`check_form_provisioning(\`. ` +
          `⛔ That is the desktop's GUI add-form, and without the gate it can create an ` +
          `entry whose code NEVER ROTATES (ADR 0051) — a second factor that looks fine and ` +
          `stays valid forever. The library call \`add_secret_base32\` is deliberately ` +
          `ungated (the clock-pinning artifice depends on it), so this command is the ONLY ` +
          `place the form is bounded.`,
      );
    } else {
      console.log(`  ok  ${rel}: the GUI add-form runs the ADR 0051 ingest ceiling`);
    }
  }
}

/** Body of a Rust/JS function whose signature starts with `sig`, brace-matched. */
function fnBody(src, sig) {
  const i = src.indexOf(sig);
  if (i === -1) return null;
  const open = src.indexOf("{", i);
  if (open === -1) return null;
  const close = matchBrace(blank(src, { strings: true }), open);
  return close === -1 ? null : src.slice(open, close + 1);
}

const DELETE_GATES = [
  { rel: "web/apps/webapp/app/authenticator.tsx", gate: webappDeleteGate, what: "the webapp's account row" },
  { rel: "extension/src/popup/popup.js", gate: extensionDeleteGate, what: "the extension popup's account row" },
  { rel: "desktop/ui/main.js", gate: desktopDeleteGate, what: "the desktop's account row" },
];

for (const { rel, gate, what } of DELETE_GATES) {
  const src = read(rel);
  if (src === null) continue;
  checks += 1;
  const r = gate(src);
  if (r.ok) {
    console.log(`  ok  ${rel}: ${what} cannot delete without confirming — ${r.why}`);
  } else {
    fail(
      `${rel}: ${what} — ${r.why}. A removal writes a PROPAGATING, resurrection-proof tombstone ` +
        `(ADR 0049 §3): a mis-click is permanent, and losing a 2FA secret can mean losing the ` +
        `account it protects.`,
    );
  }
}

// ⛔⛔ THE SELF-TEST — the two mutations that got past the first version of this
// check, encoded so they can never get past it silently again, plus the good
// shapes so a "fix" that just returns false forever is caught too.
//
// ⚠️ The specimens are deliberately MINIMAL rather than copies of the real
// files: a specimen that tracked the real source would have to be updated
// whenever the UI moved, and would then be updated to whatever the source
// happened to say — including a broken version.
{
  const DESKTOP_OK = `
    del.addEventListener("click", async () => {
      const who = row.issuer ? \`\${row.issuer}, \${row.label}\` : row.label;
      if (!window.confirm(\`Delete \${who}?\\n\\nThis permanently deletes the secret.\`)) return;
      await call("remove_by_id", { uuid: row.uuid });
    });
    forget.addEventListener("click", () => { if (!window.confirm("Forget the vault?")) return; });
  `;
  // ⛔ MUTATION (a), verbatim in shape: the confirmation is gone, but the file
  // still has other window.confirm() calls for unrelated controls.
  const DESKTOP_MUTATED = `
    del.addEventListener("click", async () => {
      // confirmation removed
      await call("remove_by_id", { uuid: row.uuid });
    });
    forget.addEventListener("click", () => { if (!window.confirm("Forget the vault?")) return; });
  `;
  // ⛔ The copy defect this phase introduced and then had to remove: a prompt
  // that promises a sync the product does not perform.
  const DESKTOP_OVERCLAIM = `
    del.addEventListener("click", async () => {
      const who = row.issuer ? \`\${row.issuer}, \${row.label}\` : row.label;
      if (!window.confirm(\`Delete \${who}?\\n\\nThis permanently deletes the secret, and the deletion is synced to every other device holding it.\`)) return;
      await call("remove_by_id", { uuid: row.uuid });
    });
  `;
  const EXT_OK = `
    yes.dataset.testid = "remove-confirm-yes";
    rm.addEventListener("click", () => { confirmBox.hidden = false; });
    no.addEventListener("click", closeConfirm);
    yes.addEventListener("click", async () => {
      await withVault((d) => { removeEntry(wasm, d, { uuid: li.dataset.uuid }, t); });
    });
  `;
  // ⛔ MUTATION (b), verbatim in shape: a NON-async handler on the row's own
  // Remove button that still performs the removal.
  const EXT_MUTATED = `
    yes.dataset.testid = "remove-confirm-yes";
    rm.addEventListener("click", () => {
      void withVault((d) => { removeEntry(wasm, d, { uuid: li.dataset.uuid }, t); });
    });
    no.addEventListener("click", closeConfirm);
  `;
  const WEBAPP_OK = `
function AccountRow({ onRemove }) {
  const [confirming, setConfirming] = useState(false);
  if (confirming) {
    return (<button data-testid="remove-confirm-yes" onClick={() => { setConfirming(false); onRemove(); }}>Delete permanently</button>);
  }
  return (<button data-testid="account-remove" onClick={() => setConfirming(true)}>Remove</button>);
}
function Next() {}
`;
  // ⛔ The webapp's equivalent evasion: not the banned literal `onClick={onRemove}`,
  // but an arrow that calls it — which the old banned-spelling check missed.
  //
  // ⚠️ The confirmation UI is left FULLY INTACT here, `setConfirming(true)`
  // included, so this specimen can only fail on the rule that matters: WHICH
  // element invokes `onRemove()`. A specimen that also deleted the confirm
  // would pass for the wrong reason and prove nothing about the bypass.
  const WEBAPP_MUTATED = `
function AccountRow({ onRemove }) {
  const [confirming, setConfirming] = useState(false);
  if (confirming) {
    return (<button data-testid="remove-confirm-yes" onClick={() => { setConfirming(false); onRemove(); }}>Delete permanently</button>);
  }
  return (<><button data-testid="account-review" onClick={() => setConfirming(true)}>Review</button><button data-testid="account-remove" onClick={() => onRemove()}>Remove</button></>);
}
function Next() {}
`;
  const SPECIMENS = [
    [desktopDeleteGate, DESKTOP_OK, true, "desktop: gated removal passes"],
    [desktopDeleteGate, DESKTOP_MUTATED, false, "desktop: DELETING the confirmation is caught (other confirms present)"],
    [desktopDeleteGate, DESKTOP_OVERCLAIM, false, "desktop: a prompt promising an automatic sync is caught"],
    [extensionDeleteGate, EXT_OK, true, "extension: removal on the confirm button passes"],
    [extensionDeleteGate, EXT_MUTATED, false, "extension: a NON-async handler on the row button is caught"],
    [webappDeleteGate, WEBAPP_OK, true, "webapp: onRemove() only inside the confirm button passes"],
    [webappDeleteGate, WEBAPP_MUTATED, false, "webapp: `onClick={() => onRemove()}` on the row button is caught"],
  ];
  for (const [gate, specimen, want, what] of SPECIMENS) {
    checks += 1;
    const got = gate(specimen).ok;
    if (got === want) {
      console.log(`  ok  self-test: ${what}`);
    } else {
      fail(
        `SELF-TEST FAILED: ${what} — the gate returned ok=${got}, expected ${want}. ` +
          (want
            ? `A guard that rejects the CORRECT shape gets deleted, which is the same as never ` +
              `having written it.`
            : `This specimen IS a mutation a verifier already got past this check once. Fix the ` +
              `gate, do not weaken the specimen.`),
      );
    }
  }

  // The literal/brace machinery the gates stand on, pinned directly: a scanner
  // that silently mis-handles a string or a template makes every gate above
  // meaningless without failing anything.
  const B = blank(`const a = "}{"; /* } */ const b = \`x\${ {y:1} }z\`; // }\nconst c = 1;`, {
    strings: true,
  });
  checks += 1;
  if ((B.match(/[{}]/g) ?? []).length === 0) {
    console.log("  ok  self-test: braces inside strings, templates and comments are not structure");
  } else {
    fail(
      `SELF-TEST FAILED: blank() left ${JSON.stringify(B)} — braces in literals or comments are ` +
        `being counted as structure, so enclosingOpens() walks to the wrong block.`,
    );
  }
  checks += 1;
  const withStrings = blank('const a = "keep me"; // drop me\n', { strings: false });
  if (withStrings.includes("keep me") && !withStrings.includes("drop me")) {
    console.log("  ok  self-test: the string-preserving view keeps strings and drops comments");
  } else {
    fail(`SELF-TEST FAILED: blank(src,{strings:false}) produced ${JSON.stringify(withStrings)}`);
  }
  checks += 1;
  if (blank("x", { strings: true }).length === 1 && B.length === B.length) {
    const sample = 'a\n"b}c"\n`d`\n';
    if (blank(sample, { strings: true }).length === sample.length) {
      console.log("  ok  self-test: blank() preserves length, so offsets stay comparable");
    } else {
      fail("SELF-TEST FAILED: blank() changed the source length — every offset above is wrong.");
    }
  }
}

// The CLI's exemption is conditional on it SAYING what it just did.
{
  const rel = "cli/src/main.rs";
  const src = read(rel);
  if (src !== null) {
    checks += 1;
    if (/PERMANENT: the second-factor secret is gone/.test(src)) {
      console.log(`  ok  ${rel}: \`totp remove\` states the consequence`);
    } else {
      fail(
        `${rel}: \`sigil totp remove\` no longer states that the removal is PERMANENT and ` +
          `propagates. It is exempt from a confirmation PROMPT only because it says this.`,
      );
    }
  }
}

// ───────────────────────────────────────────────────────────────────────────
// 4. IMPORT/ADD MUST DE-DUP BY CONTENT, NOT BY LABEL.
// ───────────────────────────────────────────────────────────────────────────
const DEDUPERS = [
  { rel: "web/apps/webapp/app/authenticator.tsx", requires: /addEntryChecked\s*\(/ },
  { rel: "extension/src/popup/popup.js", requires: /addEntryChecked\s*\(/ },
  { rel: "cli/src/main.rs", requires: /entry_fingerprint\s*\(/ },
  { rel: "desktop/core/src/lib.rs", requires: /entry_fingerprint\s*\(/ },
];
for (const { rel, requires } of DEDUPERS) {
  const src = read(rel);
  if (src === null) continue;
  checks += 1;
  if (requires.test(src)) {
    console.log(`  ok  ${rel}: de-dups by content fingerprint`);
  } else {
    fail(
      `${rel}: does not de-dup by content fingerprint. Keying on the LABEL silently ` +
        `drops \`work\` at a second issuer — the Google Authenticator import defect.`,
    );
  }
}

// ───────────────────────────────────────────────────────────────────────────
// 5. THE IDENTITY DERIVATION MUST NOT BE REIMPLEMENTED IN JS.
//    It is single-sourced in sigil-core precisely because a drift there would be
//    invisible: a vault that opens fine everywhere and silently duplicates.
// ───────────────────────────────────────────────────────────────────────────
{
  const rel = "sigil-wasm/totp-vault.mjs";
  const src = read(rel);
  if (src !== null) {
    checks += 1;
    if (/wasm\.entry_id\s*\(/.test(src)) {
      console.log(`  ok  ${rel}: identity comes from sigil-core through the wasm`);
    } else {
      fail(`${rel}: does not call wasm.entry_id — the derivation has been reimplemented in JS`);
    }
    checks += 1;
    // A JS SHA-256 in this module would mean the transcript was rebuilt here.
    if (/crypto\.subtle\.digest|createHash\s*\(/.test(src)) {
      fail(`${rel}: hashes in JS — the entry-id transcript must live only in sigil-core`);
    } else {
      console.log(`  ok  ${rel}: no JS-side hashing`);
    }
  }
}

// ───────────────────────────────────────────────────────────────────────────
// 6. ⭐⭐ ENTRIES ARE IMMUTABLE — THE PREMISE THE WHOLE MERGE RESTS ON.
//
// ⛔ WHY THIS SECTION EXISTS. `merge_vaults` has NO clock, NO Lamport counter,
// NO vector clock, NO per-entry revision and NO timestamp tiebreak. That is
// correct ONLY because a uuid names one fixed (label, issuer, secret, algorithm,
// digits, period) forever — "which version of entry U wins" is a question that
// cannot be asked. Add an EDIT and the merge silently keeps whichever copy sorts
// higher in canonical JSON: a rename could revert itself, a corrected period
// could un-correct, and nothing anywhere would fail. Every suite in this repo
// would stay green, because they all test a design that no longer holds.
//
// Until now the sole guard was a code COMMENT in two mirrors. A comment does not
// fail a build.
//
// ⭐ WHY A GUARD AND NOT A STRUCTURAL FIX. Structural immutability was
// considered and rejected, for a specific reason rather than for effort:
//
//   * In Rust it would mean private fields on `TotpEntry` with accessors. That
//     is real enforcement — but `TotpEntry` is a MIRRORED wire schema, and the
//     JS half is a plain object literal in `totp-vault.mjs` that no language
//     feature can seal. `Object.freeze` is not it either: a would-be editor
//     simply clones, mutates the clone and pushes THAT, which is the identical
//     defect with an extra line. So a structural fix would cover ONE of the two
//     implementations and TWO of the four shipping clients, while reading as if
//     it covered all of them — the worst outcome available.
//   * The failure mode this must catch is a NEW code path written months from
//     now by someone who has not read the merge. What stops that is a check that
//     goes red in CI naming the rule, in the language they are writing in.
//
// So: a source guard, over BOTH languages, with an exact allowlist — the same
// idiom section 2 uses for tip reads, and for the same reason.
//
// ⚠️ WHAT IT DOES NOT PROVE. It cannot catch an edit routed through a helper it
// does not know about, or an entry rebuilt field-by-field into a new literal
// under the SAME uuid. It raises the cost of adding an edit accidentally; it
// does not make one impossible.
// ───────────────────────────────────────────────────────────────────────────

// The CONTENT fields — the ones a uuid promises are fixed. ⚠️ `uuid` is
// deliberately NOT here: `normalize_vault`/`normalizeVault` filling in a MISSING
// id, and `add` minting a fresh one, are exactly how identity is established.
// Writing an entry's uuid does not edit an account; writing its `secret` does.
const CONTENT_WRITE = /(?<!dataset)\.(label|secret|issuer|algorithm|digits|period)\s*=(?!=)/;

const IMMUTABLE_SURFACES = [
  {
    rel: "cli/src/lib.rs",
    count: 0,
    why: "the vault library builds entries with struct literals and never edits one in place",
  },
  {
    rel: "cli/src/main.rs",
    count: 0,
    why: "`sigil totp` add/import/remove construct or drop entries; nothing edits one",
  },
  {
    rel: "cli/src/migration.rs",
    count: 4,
    why: "decoding the Google Authenticator protobuf (secret/issuer/algorithm/digits) into a fresh `MigrationOtp` WIRE struct — not a vault entry",
  },
  {
    rel: "desktop/core/src/lib.rs",
    count: 0,
    why: "the desktop reuses the CLI library's constructors (ADR 0037)",
  },
  { rel: "desktop/core/src/net.rs", count: 0, why: "moves bytes; never touches an entry's fields" },
  {
    rel: "desktop/src-tauri/src/main.rs",
    count: 0,
    why: "a thin IPC shell; every vault operation is a call into sigil-desktop-core",
  },
  {
    rel: "sigil-wasm/totp-vault.mjs",
    count: 2,
    why: "`addEntry` sets `issuer` on the object literal it is BUILDING, and `addEntryChecked` on the throwaway candidate it fingerprints",
  },
  {
    rel: "sigil-wasm/totp-migration.mjs",
    count: 6,
    why: "4 decode a fresh `MigrationOtp` wire struct; 2 set `issuer` on a fresh entry being CONSTRUCTED from a decoded OTP / an otpauth:// URI",
  },
  {
    rel: "web/apps/webapp/app/authenticator.tsx",
    count: 0,
    why: "the webapp adds and removes; it has no edit control",
  },
  {
    rel: "extension/src/popup/popup.js",
    count: 0,
    why: "the popup adds and removes; it has no edit control (`li.dataset.label` is DOM, excluded by the pattern)",
  },
  { rel: "desktop/ui/main.js", count: 0, why: "the desktop UI adds and removes; it has no edit control" },
];

for (const { rel, count, why } of IMMUTABLE_SURFACES) {
  const src = read(rel);
  if (src === null) continue;
  checks += 1;
  const found = hits(stripComments(src), CONTENT_WRITE);
  if (found.length === count) {
    console.log(
      `  ok  ${rel}: ${found.length} in-place content write(s)` + (count > 0 ? ` — ${why}` : ""),
    );
  } else {
    fail(
      `${rel}: expected exactly ${count} in-place write(s) to an entry CONTENT field ` +
        `(${why}), found ${found.length} at line(s) ` +
        `${found.map((f) => `${f.line} (${f.text.trim()})`).join(", ") || "none"}.\n` +
        `      ⛔ A NEW one is very likely an EDIT. The merge has no clock, no revision and no ` +
        `timestamp tiebreak, and that is correct ONLY because a uuid names one fixed ` +
        `(label, issuer, secret, algorithm, digits, period) forever. An edit must be ` +
        `implemented as DELETE + ADD WITH A FRESH UUID, or this merge silently keeps ` +
        `whichever copy sorts higher.\n` +
        `      A MISSING one means this allowlist entry is stale and must be re-justified.`,
    );
  }
}

// ───────────────────────────────────────────────────────────────────────────
// 6b. ⛔⛔ THE WHOLE-VALUE REPLACE — the bypass the field scan above CANNOT see.
//
// The scan in 6 looks for `.label =` / `.secret =` etc. An independent verifier
// walked straight past it with ORDINARY, IDIOMATIC RUST:
//
//     for e in &mut vault.entries {
//         if e.uuid.as_deref() == Some(uuid) {
//             *e = TotpEntry { label: new_label.into(), ..e.clone() };
//         }
//     }
//
// Not one `.label =` anywhere — and it is an EDIT, under the same uuid, which
// silently degrades the merge exactly as section 6 describes. The JS twin is as
// short: `vault.entries[i] = { ...e, label: x }`.
//
// ⚠️ WHY THESE ARE SEPARATE CHECKS RATHER THAN A WIDER REGEX IN 6. Section 6
// counts writes to a NAMED FIELD; that is what makes its allowlist countable and
// its message specific. "Replace the whole struct" is a different shape with
// different legitimate uses (building a fresh entry IS a struct literal), so it
// needs its own predicate: what is banned is a struct literal that is written
// THROUGH a reference/index to an entry that already exists, or one that carries
// the surviving fields of an existing entry over via `..`.
//
// ⚠️ WHAT IT STILL DOES NOT CATCH: an edit routed through a helper that takes and
// returns an owned entry, or one performed on a clone that is then pushed. As
// section 6 says, this raises the cost of adding an edit by accident; it does not
// make one impossible.
// ───────────────────────────────────────────────────────────────────────────

/**
 * Every `Name { … }` struct-literal body in `src`, brace-MATCHED rather than
 * regex-guessed — a `[^}]*` would stop at the first nested `}` and miss exactly
 * the multi-line literal an edit is written as.
 */
function structLiteralBodies(src, name) {
  const out = [];
  const rx = new RegExp(`\\b${name}\\s*\\{`, "g");
  let m;
  while ((m = rx.exec(src)) !== null) {
    const open = m.index + m[0].length - 1;
    let depth = 0;
    let i = open;
    for (; i < src.length; i += 1) {
      if (src[i] === "{") depth += 1;
      else if (src[i] === "}") {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    out.push({ line: lineOf(src, m.index), body: src.slice(open + 1, i) });
  }
  return out;
}

// A struct literal assigned THROUGH a deref or an index — i.e. over something
// that already exists. `*e = TotpEntry {` / `vault.entries[i] = TotpEntry {`.
const RS_REPLACE_IN_PLACE =
  /(?:\*\s*[A-Za-z_][A-Za-z0-9_.]*|[A-Za-z_][A-Za-z0-9_.]*\s*\[[^\]]*\])\s*=\s*TotpEntry\s*\{/;

// `..` in a TotpEntry literal carries an EXISTING entry's remaining fields over.
// `..Default::default()` is exempt: it fills from a fresh default, not from a
// live entry, so it constructs rather than edits.
const RS_STRUCT_UPDATE = /\.\.\s*(?!Default::default|TotpEntry::default|Self::default)[A-Za-z_*&]/;

// JS: replacing a whole entry in the array, or spreading an existing entry and
// overriding a CONTENT field.
const JS_REPLACE_IN_PLACE = /entries\s*\[[^\]]*\]\s*=\s*\{/;
const JS_SPREAD_OVERRIDE =
  /\{\s*\.\.\.\s*[A-Za-z0-9_$.[\]]*(?:[eE]ntry|\be\b)[A-Za-z0-9_$.[\]]*\s*,\s*(?:label|secret|issuer|algorithm|digits|period)\s*:/;
// A wholesale rewrite of the entry list — the map-shaped cousin of the
// `entries.filter` removal section 3 already bans.
const JS_ENTRIES_MAP_ASSIGN = /entries\s*=\s*[A-Za-z0-9_$.]*entries\.map\s*\(/;
// Mutating an entry object in place without ever naming a field.
const JS_OBJECT_ASSIGN =
  /Object\.assign\s*\(\s*(?:[A-Za-z0-9_$.[\]]*[eE]ntry[A-Za-z0-9_$.[\]]*|e|entries\s*\[[^\]]*\])\s*,/;

const RUST_SURFACES = [
  "cli/src/lib.rs",
  "cli/src/main.rs",
  "desktop/core/src/lib.rs",
  "desktop/core/src/net.rs",
  "desktop/src-tauri/src/main.rs",
];
const JS_SURFACES = [
  "sigil-wasm/totp-vault.mjs",
  "sigil-wasm/totp-migration.mjs",
  "web/apps/webapp/app/authenticator.tsx",
  "extension/src/popup/popup.js",
  "desktop/ui/main.js",
];

const EDIT_EXPLANATION =
  "⛔ THIS REPLACES AN ENTRY THAT ALREADY EXISTS, i.e. it is an EDIT. `merge_vaults` " +
  "has no clock, no revision and no timestamp tiebreak, and that is correct ONLY " +
  "because a uuid names one fixed (label, issuer, secret, algorithm, digits, period) " +
  "forever. An edit must be DELETE + ADD WITH A FRESH UUID.";

for (const rel of RUST_SURFACES) {
  const src = read(rel);
  if (src === null) continue;
  const clean = stripComments(src);

  checks += 1;
  const replaced = hits(clean, RS_REPLACE_IN_PLACE);
  if (replaced.length === 0) {
    console.log(`  ok  ${rel}: no whole-entry replace through a reference or index`);
  } else {
    fail(
      `${rel}: a whole \`TotpEntry\` is written over an existing one at line(s) ` +
        `${replaced.map((f) => `${f.line} (${f.text.trim()})`).join(", ")}. ${EDIT_EXPLANATION}`,
    );
  }

  checks += 1;
  const carried = structLiteralBodies(clean, "TotpEntry").filter((s) => RS_STRUCT_UPDATE.test(s.body));
  if (carried.length === 0) {
    console.log(`  ok  ${rel}: no \`TotpEntry { …, ..existing }\` struct update`);
  } else {
    fail(
      `${rel}: a \`TotpEntry\` literal carries an EXISTING entry's fields over with \`..\` at ` +
        `line(s) ${carried.map((s) => s.line).join(", ")}. ${EDIT_EXPLANATION} ` +
        `(\`..Default::default()\` is exempt — it builds a fresh entry.)`,
    );
  }
}

for (const rel of JS_SURFACES) {
  const src = read(rel);
  if (src === null) continue;
  const clean = stripComments(src);
  for (const [re, what] of [
    [JS_REPLACE_IN_PLACE, "an entry slot is overwritten with a fresh object literal"],
    [JS_SPREAD_OVERRIDE, "an existing entry is spread with a CONTENT field overridden"],
    [JS_ENTRIES_MAP_ASSIGN, "the whole entry list is rewritten through `.map(...)`"],
    [JS_OBJECT_ASSIGN, "an entry object is mutated in place via Object.assign"],
  ]) {
    checks += 1;
    const found = hits(clean, re);
    if (found.length === 0) {
      console.log(`  ok  ${rel}: ${what} — not present`);
    } else {
      fail(
        `${rel}: ${what} at line(s) ${found.map((f) => `${f.line} (${f.text.trim()})`).join(", ")}. ` +
          EDIT_EXPLANATION,
      );
    }
  }
}

// ⚠️ The patterns above must actually MATCH something when the banned shape is
// present, or this whole section is decoration. A self-test on literal source
// text keeps a botched regex from reading as a clean tree — this repo has
// shipped a guard whose pattern silently matched nothing FOUR times.
{
  const SPECIMENS = [
    [RS_REPLACE_IN_PLACE, "        *e = TotpEntry { label: new_label.into(), ..e.clone() };"],
    [RS_REPLACE_IN_PLACE, "    vault.entries[i] = TotpEntry { label: l, ..old };"],
    [JS_REPLACE_IN_PLACE, "  vault.entries[i] = { ...e, label: next };"],
    [JS_SPREAD_OVERRIDE, "  const renamed = { ...entry, label: next };"],
    [JS_SPREAD_OVERRIDE, "  out.push({ ...e, secret: fresh });"],
    [JS_ENTRIES_MAP_ASSIGN, "  vault.entries = vault.entries.map((e) => e);"],
    [JS_OBJECT_ASSIGN, "  Object.assign(entry, { label: next });"],
  ];
  for (const [re, specimen] of SPECIMENS) {
    checks += 1;
    if (re.test(specimen)) {
      console.log(`  ok  self-test: /${re.source.slice(0, 34)}…/ matches its specimen`);
    } else {
      fail(
        `SELF-TEST FAILED: the pattern /${re.source}/ does NOT match the banned shape it exists ` +
          `for:\n      ${specimen}\n      A guard whose regex matches nothing reads exactly like a ` +
          `clean tree. Fix the pattern, do not delete the specimen.`,
      );
    }
  }
  // …and it must not fire on the LEGITIMATE construction shapes.
  const ALLOWED = [
    [RS_STRUCT_UPDATE, "TotpEntry { label, ..Default::default() }", false],
    [JS_SPREAD_OVERRIDE, "const out = { ...vault, entries: [...vault.entries] };", false],
    [JS_SPREAD_OVERRIDE, "tombs.set(t.uuid, { ...t });", false],
  ];
  for (const [re, specimen, want] of ALLOWED) {
    checks += 1;
    if (re.test(specimen) === want) {
      console.log(`  ok  self-test: legitimate construction not flagged (${specimen.slice(0, 40)}…)`);
    } else {
      fail(
        `SELF-TEST FAILED: /${re.source}/ FLAGS a legitimate construction:\n      ${specimen}\n` +
          `      A guard that cries wolf on ordinary code gets deleted, which is the same as ` +
          `never having written it.`,
      );
    }
  }
}

// ───────────────────────────────────────────────────────────────────────────
// 6c. ⭐⭐ THE SERIALIZED FIELD ORDER — Rust's struct declaration IS the wire
//     order, and the JS mirror hard-codes a COPY of it.
//
// ⛔ WHY. `serde` writes a struct's fields in DECLARATION order and its
// `#[serde(flatten)] extra` map is a `BTreeMap` (sorted). JavaScript objects are
// INSERTION-ordered, so `sigil-wasm/totp-vault.mjs`'s `vaultToJson` reproduces
// that order from three hand-written arrays. Before it did, Rust and JS wrote
// DIFFERENT BYTES for identical vault content — invisible to every parser, and
// therefore invisible to every suite that compared parsed structures.
//
// ⚠️ THE DRIFT IS SILENT AND ONE-SIDED. Adding a field to `TotpEntry` in Rust
// takes one line and nothing anywhere fails: the JS writer simply emits the new
// field with the UNKNOWN ones, sorted, at the end — which parses fine, generates
// correct codes, and quietly makes the two clients disagree byte for byte again.
// `merge-interop.mjs`'s BYTES section only catches it if its fixture happens to
// carry that field. This catches it from the declaration itself.
// ───────────────────────────────────────────────────────────────────────────
{
  /** Field names of `pub struct NAME { … }` in DECLARATION order. */
  const rustStructFields = (src, name) => {
    const m = new RegExp(`pub struct ${name}\\s*\\{`).exec(src);
    if (!m) return null;
    const open = m.index + m[0].length - 1;
    let depth = 0;
    let i = open;
    for (; i < src.length; i += 1) {
      if (src[i] === "{") depth += 1;
      else if (src[i] === "}") {
        depth -= 1;
        if (depth === 0) break;
      }
    }
    const body = src.slice(open + 1, i);
    // ⚠️ The flattened catch-all is NOT part of the fixed order — it is the
    // sorted map that comes after. Drop it, but only if it really is flattened.
    const flattened = new Set();
    for (const fm of body.matchAll(/#\[serde\(flatten\)\]\s*\n\s*pub\s+([a-z_0-9]+)\s*:/g)) {
      flattened.add(fm[1]);
    }
    return {
      fields: [...body.matchAll(/^\s*pub\s+([a-z_0-9]+)\s*:/gm)]
        .map((f) => f[1])
        .filter((f) => !flattened.has(f)),
      flattened: [...flattened],
    };
  };

  /** The `const NAME = ["a", "b"]` array from the JS mirror. */
  const jsOrder = (src, name) => {
    const m = new RegExp(`const ${name}\\s*=\\s*\\[([^\\]]*)\\]`).exec(src);
    if (!m) return null;
    return [...m[1].matchAll(/"([^"]+)"/g)].map((x) => x[1]);
  };

  const rustSrc = read("cli/src/lib.rs");
  const jsSrc = read("sigil-wasm/totp-vault.mjs");
  if (rustSrc !== null && jsSrc !== null) {
    for (const [struct, arrayName] of [
      ["TotpVault", "VAULT_FIELD_ORDER"],
      ["TotpEntry", "ENTRY_FIELD_ORDER"],
      ["Tombstone", "TOMBSTONE_FIELD_ORDER"],
    ]) {
      checks += 1;
      const rust = rustStructFields(rustSrc, struct);
      const js = jsOrder(jsSrc, arrayName);
      if (rust === null || js === null) {
        fail(
          `could not read the field order for ${struct}: rust=${rust ? "ok" : "NOT FOUND"}, ` +
            `js ${arrayName}=${js ? "ok" : "NOT FOUND"}. If either was renamed this check must ` +
            `move with it — a guard that cannot find its subject proves nothing.`,
        );
        continue;
      }
      if (rust.flattened.length !== 1) {
        fail(
          `${struct}: expected exactly ONE #[serde(flatten)] field (the unknown-field catch-all), ` +
            `found ${rust.flattened.length} [${rust.flattened}]. The JS writer assumes one sorted ` +
            `map at the end.`,
        );
        continue;
      }
      if (rust.fields.join() === js.join()) {
        console.log(`  ok  ${struct}: serde order [${rust.fields}] matches ${arrayName}`);
      } else {
        fail(
          `⛔ SERIALIZED FIELD ORDER HAS DRIFTED for ${struct}:\n` +
            `        Rust (cli/src/lib.rs, declaration order): [${rust.fields}]\n` +
            `        JS   (sigil-wasm/totp-vault.mjs ${arrayName}): [${js}]\n` +
            `      serde writes DECLARATION order; the JS mirror reproduces it from that array. ` +
            `While they differ, the CLI and every browser client write DIFFERENT BYTES for ` +
            `IDENTICAL vault content — every push becomes a fresh op, and no skip-if-unchanged ` +
            `or content-addressing rule can be correct. Nothing else fails when this drifts.`,
        );
      }
    }
  }
}

// ⭐ And no edit-shaped OPERATION may be declared. This catches the shape that
// would not trip the field scan: an edit routed through a helper, a new CLI
// subcommand, a new tauri command, a new exported mutator.
const EDIT_SHAPED =
  /\b(?:fn|function|const|let)\s+(rename\w*|edit_?[Ee]ntry\w*|update_?[Ee]ntry\w*|modify_?[Ee]ntry\w*|set_?(?:Label|Secret|Issuer|Period|Digits|label|secret|issuer|period|digits)\w*)\s*[({=<]/;
const NO_EDIT_OPS = [
  "cli/src/lib.rs",
  "cli/src/main.rs",
  "desktop/core/src/lib.rs",
  "desktop/src-tauri/src/main.rs",
  "sigil-wasm/totp-vault.mjs",
  "web/apps/webapp/app/authenticator.tsx",
  "extension/src/popup/popup.js",
];
for (const rel of NO_EDIT_OPS) {
  const src = read(rel);
  if (src === null) continue;
  checks += 1;
  const found = hits(stripComments(src), EDIT_SHAPED);
  if (found.length === 0) {
    console.log(`  ok  ${rel}: declares no edit-shaped operation`);
  } else {
    fail(
      `${rel}: declares an edit-shaped operation at line(s) ` +
        `${found.map((f) => `${f.line} (${f.text.trim()})`).join(", ")}. ` +
        `⛔ Entries are IMMUTABLE — an edit must be DELETE + ADD WITH A FRESH UUID. ` +
        `If this really is not an edit, rename it; if it IS, the merge needs a revision ` +
        `rule before it can exist.`,
    );
  }
}

// ⭐ The `sigil totp` mutation surface must stay CLOSED. The CLI is the reference
// client — an edit reaches the product through a subcommand here first.
{
  const rel = "cli/src/main.rs";
  const src = read(rel);
  if (src !== null) {
    checks += 1;
    const start = src.indexOf("fn cmd_totp(");
    const body = start === -1 ? "" : src.slice(start, start + 1400);
    const subs = [...body.matchAll(/^\s*"([a-z-]+)" => cmd_totp_/gm)].map((m) => m[1]).sort();
    const want = ["add", "code", "export", "import", "list", "remove", "sync"];
    if (subs.length === 0) {
      fail(`${rel}: could not find the \`sigil totp\` dispatch — this check must move with it`);
    } else if (subs.join() === want.join()) {
      console.log(`  ok  ${rel}: the totp mutation surface is closed (${subs.join(" | ")})`);
    } else {
      fail(
        `${rel}: the \`sigil totp\` subcommands changed: [${subs}] != [${want}]. ` +
          `⛔ If a new one MUTATES an entry rather than adding or removing whole entries, ` +
          `the merge's no-clock design is broken by it. Justify and update this list.`,
      );
    }
  }
}

// ⭐ …and the warning itself must not be quietly deleted from either mirror. It
// is the only thing that tells the next reader WHY there is no revision field.
const IMMUTABILITY_NOTE = /delete \+ add with a fresh uuid, or this merge is wrong/i;
for (const rel of ["cli/src/lib.rs", "sigil-wasm/totp-vault.mjs"]) {
  const src = read(rel);
  if (src === null) continue;
  checks += 1;
  if (IMMUTABILITY_NOTE.test(src)) {
    console.log(`  ok  ${rel}: carries the "an edit must be delete + add" warning`);
  } else {
    fail(
      `${rel}: the immutability warning is GONE. It is the only in-code explanation of why ` +
        `the merge has no clock and no revision field; deleting it is how the next author ` +
        `adds an edit in good faith.`,
    );
  }
}

// ───────────────────────────────────────────────────────────────────────────
// 7. ⛔ THE TOMBSTONE GROWTH LIMIT MUST BE WARNED ABOUT, AND THE THREE COPIES
//    OF THE CAP MUST AGREE.
//
// A vault is a 2P-Set whose remove-set never shrinks; nothing prunes a tombstone
// and there is no compaction command. sigild answers 413 above 64 KiB, and past
// that there is no supported way to shrink the vault — a user who first meets
// this AT the 413 has already lost the ability to sync. The number lives in
// THREE hand-written places (Go, Rust, JS) and a drift is silent: the warning
// simply fires at the wrong size, or after the wall.
// ───────────────────────────────────────────────────────────────────────────
{
  const capOf = (rel, re) => {
    const src = read(rel);
    if (src === null) return null;
    const m = re.exec(src);
    return m ? m[1] : null;
  };
  checks += 1;
  const go = capOf("sigild/internal/api/middleware.go", /maxOpsBodyBytes\s*=\s*64\s*<<\s*(10)/);
  const rust = capOf("cli/src/lib.rs", /MAX_OP_BODY_BYTES:\s*usize\s*=\s*64\s*<<\s*(10)/);
  const js = capOf("sigil-wasm/totp-vault.mjs", /MAX_OP_BODY_BYTES\s*=\s*64\s*\*\s*(1024)/);
  if (go && rust && js) {
    console.log("  ok  the 64 KiB op cap agrees across sigild, the CLI and the JS mirror");
  } else {
    fail(
      `the 64 KiB op-body cap could not be found identically in all three places ` +
        `(go=${go}, rust=${rust}, js=${js}). A drift makes the client warn at the wrong ` +
        `size — or after the wall it exists to warn about.`,
    );
  }

  // Every client that PUSHES must consult the warning. A limit nobody surfaces
  // is a limit the user discovers as a 413 with no way back.
  const WARNERS = [
    { rel: "cli/src/main.rs", re: /op_body_size_warning\s*\(/, what: "`sigil totp sync`" },
    {
      rel: "desktop/src-tauri/src/main.rs",
      re: /op_body_size_warning_for\s*\(/,
      what: "the desktop push command",
    },
    {
      rel: "web/apps/webapp/app/authenticator.tsx",
      re: /opBodySizeWarning\s*\(/,
      what: "the webapp Sync panel",
    },
    {
      rel: "extension/src/popup/popup.js",
      re: /opBodySizeWarning\s*\(/,
      what: "the extension popup's push",
    },
  ];
  for (const { rel, re, what } of WARNERS) {
    const src = read(rel);
    if (src === null) continue;
    checks += 1;
    if (re.test(stripComments(src))) {
      console.log(`  ok  ${rel}: ${what} warns before the op cap becomes a 413`);
    } else {
      fail(
        `${rel}: ${what} pushes without checking ${re.source}. Tombstones are never pruned and ` +
          `there is no compaction command, so this client walks its user into a 413 that ends ` +
          `syncing, silently.`,
      );
    }
  }
}

// ───────────────────────────────────────────────────────────────────────────
// 8. ⛔⛔ THE DESKTOP'S IPC HOP FOR THE SHEET'S VAULT IDS.
//
// `GET /v1/devices/{id}/keys` — how a restored recovery kit finds what it can
// decrypt — is ONE page capped at 500 rows with NO CURSOR, and ANY account can
// put rows in it (deposit an opaque envelope addressed to a device id it knows,
// then grant that device read on a vault it claimed itself; there is no cap on
// claiming). Measured: 520 vaults flooded in 0.6 s pushed the genuine row off
// the page. The answer is the ids printed on the sheet's `covers` line, which
// make a restore ask each VAULT directly — addressed BY VAULT ID, so a flood
// cannot crowd them out.
//
// ⚠️ THIS IS THE ONE PRODUCT LAYER IN THE REPO WITH NO BEHAVIOURAL COVERAGE.
// Both browsers drive the equivalent hop end to end in Playwright (their
// recovery specs fill the vault-ids field and assert the vault opens). The
// desktop cannot: `desktop/core/tests/server_interop.rs` calls
// `DeviceConfig::recovery_restore` DIRECTLY — it pins the LIBRARY — and no test
// anywhere renders `desktop/ui/`. So the hop
//
//     desktop/ui/main.js        call("recovery_restore", { …, vaultIds })
//         ↓ Tauri IPC (camelCase JS key → snake_case Rust arg)
//     desktop/src-tauri/…       vault_ids: Option<Vec<String>>
//         ↓ unwrap_or_default()
//     sigil-desktop-core        recovery_restore(…, &vaults)
//
// is deletable with the whole gate green. ⛔ AND ITS FAILURE IS INVISIBLE: a
// dropped or mis-named argument deserializes to `None` SILENTLY, and its only
// observable consequence is a refusal BYTE-IDENTICAL to the refusal a genuinely
// truncated index produces. The user is told "this server's list is crowded" —
// which is true — and never that the ids they typed off the paper were thrown
// away in transit.
//
// ⛔⛔ AND THE FIRST VERSION OF THIS SECTION WAS BYPASSABLE BY THE EXACT FAILURE
// IT EXISTS TO CATCH — the same lesson as section 3b, one phase later. It asked
// whether the TOKEN appeared and was not a literal `null`/`undefined`/`[]`; it
// never related the value PASSED to the value BOUND. Both of these printed
// `ok  … 1 restore call site(s)` and exited 0 while sending an EMPTY list:
//
//     call("recovery_restore", { …, vaultIds: vaultIds.slice(0, 0) })   // ui
//     .recovery_restore(&code, …, &vaults[..0])                          // cmd, and it COMPILES
//
// So the checks below demand the BARE identifier — no call, index, slice or
// literal on either side — and both bypasses are encoded as self-test specimens,
// because the old specimen set only ever mutated the BINDING and never a correct
// binding passed through a truncating expression.
//
// ⚠️ A SOURCE CHECK, NOT A PROOF, exactly like the delete gates above: it shows
// the ids are PASSED and ACCEPTED, not that the restore they drive is correct
// (that is the library's tests). A refactor that hoists the field read into a
// helper will false-alarm here by design — the alternative is a guard that
// accepts any spelling, which is the no-op this file exists to avoid.
// ───────────────────────────────────────────────────────────────────────────

/** Index of the `)` matching the `(` at `open`, or -1. Braces have `matchBrace`. */
function matchParen(code, open) {
  let depth = 0;
  for (let i = open; i < code.length; i += 1) {
    if (code[i] === "(") depth += 1;
    else if (code[i] === ")") {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

/**
 * Split `(a, b(c, d), e)` into `["a", "b(c, d)", "e"]` — commas at NESTING DEPTH
 * ZERO only, so an argument that is itself a call keeps its own commas.
 *
 * ⛔ THIS EXISTS BECAUSE THE FIRST VERSION OF SECTION 8 ASKED "does the name
 * APPEAR in the argument list?", and `&vaults[..0]` contains `vaults`. Relating
 * the value PASSED to the value BOUND needs the argument as a whole token, which
 * needs a splitter.
 *
 * @param {string} withParens the slice INCLUDING the surrounding parentheses
 */
function splitTopLevelArgs(withParens) {
  const inner = withParens.slice(1, -1);
  const out = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < inner.length; i += 1) {
    const c = inner[i];
    if (c === "(" || c === "[" || c === "{") depth += 1;
    else if (c === ")" || c === "]" || c === "}") depth -= 1;
    else if (c === "," && depth === 0) {
      out.push(inner.slice(start, i));
      start = i + 1;
    }
  }
  out.push(inner.slice(start));
  return out.map((a) => a.trim()).filter((a) => a !== "");
}

/**
 * The value an object literal binds to `key`, as SOURCE TEXT, or:
 *   - `{ shorthand: true }` for `{ …, vaultIds, … }`;
 *   - `null` when the key is not present at all.
 *
 * Only a key in KEY POSITION counts (immediately after `{` or `,`), so a
 * mention of the name inside some other value is not mistaken for the property.
 */
function objectLiteralValue(args, key) {
  const rx = new RegExp(`[{,]\\s*${key}\\s*(:)?`, "g");
  let m;
  while ((m = rx.exec(args)) !== null) {
    if (m[1] === undefined) return { shorthand: true, text: key };
    // Read to the matching top-level `,` or the closing `}`.
    let depth = 0;
    const from = m.index + m[0].length;
    for (let i = from; i < args.length; i += 1) {
      const c = args[i];
      if (c === "(" || c === "[" || c === "{") depth += 1;
      else if (c === ")" || c === "]") depth -= 1;
      else if (c === "}") {
        if (depth === 0) return { shorthand: false, text: args.slice(from, i).trim() };
        depth -= 1;
      } else if (c === "," && depth === 0) {
        return { shorthand: false, text: args.slice(from, i).trim() };
      }
    }
    return { shorthand: false, text: args.slice(from).trim() };
  }
  return null;
}

/** A bare JS/Rust identifier and nothing else — no call, index, slice or literal. */
const BARE_IDENTIFIER = /^[A-Za-z_$][A-Za-z0-9_$]*$/;

/**
 * DESKTOP UI — every `call("recovery_restore", { … })` must pass `vaultIds`,
 * that value must not be a hardcoded absence, and it must be derived from the
 * sheet's `recovery-restore-vaults` field rather than invented.
 */
function desktopRestoreVaultIdsUi(src) {
  const code = blank(src, { strings: true });
  const text = blank(src, { strings: false });
  const sites = hits(text, /call\(\s*["']recovery_restore["']/);
  // ⭐ ZERO IS A FAILURE. A rename would otherwise turn this whole section into
  // a check of nothing that still prints green.
  if (sites.length === 0) {
    return {
      ok: false,
      why:
        'no `call("recovery_restore", …)` site found at all. Either the restore moved (this ' +
        "guard must move with it) or the desktop no longer restores from a kit",
    };
  }
  for (const site of sites) {
    const open = code.indexOf("{", site.index);
    const close = open === -1 ? -1 : matchBrace(code, open);
    if (open === -1 || close === -1 || open > matchParen(code, code.indexOf("(", site.index))) {
      return { ok: false, why: `the call at line ${site.line} has no argument object to inspect` };
    }
    const args = text.slice(open, close + 1);
    const passed = objectLiteralValue(args, "vaultIds");
    if (passed === null) {
      return {
        ok: false,
        why:
          `the call at line ${site.line} does not pass \`vaultIds\`. The Tauri command takes ` +
          "`vault_ids: Option<Vec<String>>`, so a missing key deserializes to `None` SILENTLY " +
          "and the sheet's ids never reach the library — indistinguishable, to the user, from " +
          "a genuinely truncated index",
      };
    }
    // ⛔⛔ THE VALUE PASSED MUST BE THE VALUE BOUND — the BARE identifier, with
    // no call, index or slice wrapped round it. Asking only "is the token there,
    // and is it not literally null/undefined/[]?" was the hole an auditor walked
    // straight through: `vaultIds: vaultIds.slice(0, 0)` printed `ok` while
    // sending an EMPTY list, so the library took the blind path and the user got
    // a refusal BYTE-IDENTICAL to a genuine truncation. Any expression at all is
    // refused here, because there is no expression this call site needs.
    if (!passed.shorthand && !BARE_IDENTIFIER.test(passed.text)) {
      return {
        ok: false,
        why:
          `the call at line ${site.line} passes \`vaultIds: ${passed.text}\` — an EXPRESSION, not ` +
          "the bound value. Anything that can narrow, empty or invent the list (a slice, an " +
          "index, a call, a literal) is the same defect wearing the argument's name: the restore " +
          "silently falls back to the crowdable per-device index and refuses with a message the " +
          "user cannot tell from a real truncation",
      };
    }
    if (!passed.shorthand && passed.text !== "vaultIds") {
      return {
        ok: false,
        why:
          `the call at line ${site.line} passes \`vaultIds: ${passed.text}\`, which is not the ` +
          "`vaultIds` bound from the sheet field. This guard can only follow one name; rename the " +
          "local back, or move this guard with it",
      };
    }
  }
  // The value must come FROM THE SHEET. A `vaultIds` computed from anything else
  // passes the checks above and still cannot survive a flood.
  const bind = /(?:const|let|var)\s+vaultIds\s*=/.exec(code);
  if (bind === null) {
    return {
      ok: false,
      why: "`vaultIds` is passed but never bound — this guard cannot see where the ids come from",
    };
  }
  const stmtEnd = code.indexOf(";", bind.index);
  const rhs = text.slice(bind.index, stmtEnd === -1 ? text.length : stmtEnd);
  if (!/recovery-restore-vaults/.test(rhs)) {
    return {
      ok: false,
      why:
        "`vaultIds` is not read from the `recovery-restore-vaults` field. The ids have to be the " +
        "ones the user copied off the paper; anything else is a value that looks right and " +
        "cannot survive a flooded index",
    };
  }
  return {
    ok: true,
    why: `${sites.length} restore call site(s), each passing ids read from the sheet's covers field`,
  };
}

/**
 * DESKTOP TAURI SHELL — the `recovery_restore` command must ACCEPT the ids and
 * FORWARD them to the core. Tauri v2 camelCases command arguments, so the JS key
 * `vaultIds` binds to the Rust parameter `vault_ids`; both spellings are checked
 * here because that conversion is exactly where a rename goes silent.
 */
function desktopRestoreVaultIdsCommand(src) {
  const sites = hits(src, /#\[tauri::command\]\s*(?:pub\s+)?fn\s+recovery_restore\s*\(/);
  if (sites.length !== 1) {
    return {
      ok: false,
      why:
        `expected exactly ONE \`#[tauri::command] fn recovery_restore(\`, found ${sites.length}. ` +
        "A rename or a second copy makes this guard meaningless",
    };
  }
  const site = sites[0];
  const parenOpen = src.indexOf("(", site.index + site.text.length - 1);
  const parenClose = matchParen(src, parenOpen);
  const bodyOpen = src.indexOf("{", parenClose);
  const bodyClose = bodyOpen === -1 ? -1 : matchBrace(blank(src, { strings: true }), bodyOpen);
  if (parenClose === -1 || bodyClose === -1) {
    return { ok: false, why: "could not brace-match the command's signature and body" };
  }
  const sig = src.slice(parenOpen, parenClose + 1);
  const body = src.slice(bodyOpen, bodyClose + 1);
  if (!/vault_ids\s*:\s*(?:Option\s*<\s*)?Vec\s*<\s*String\s*>/.test(sig)) {
    return {
      ok: false,
      why:
        "the command does not accept `vault_ids: Option<Vec<String>>` (the snake_case binding of " +
        "the UI's `vaultIds`). Without the parameter the ids are dropped at the IPC boundary " +
        "with no error anywhere",
    };
  }
  // Accepting is not forwarding. Follow whatever local the parameter is bound to
  // into the core call, so a parameter that is accepted and then ignored fails.
  //
  // ⛔ THE BINDING'S RIGHT-HAND SIDE IS CHECKED TOO. `let vaults = vault_ids` —
  // optionally with the `Option` unwrapped — is the ONLY shape allowed, because
  // anything else (`…into_iter().take(0).collect()`, `…[..0].to_vec()`) narrows
  // the list here instead of at the call and reads exactly as innocent.
  const bound = /let\s+(\w+)\s*(?::[^=;]*)?=\s*([^;]*);/.exec(body);
  let forwarded = "vault_ids";
  if (bound && /\bvault_ids\b/.test(bound[2])) {
    forwarded = bound[1];
    const rhs = bound[2].replace(/\s+/g, "");
    const WHOLE_VALUE = /^vault_ids(?:\.unwrap_or_default\(\)|\.unwrap_or\([^;]*\))?$/;
    if (!WHOLE_VALUE.test(rhs)) {
      return {
        ok: false,
        why:
          `\`vault_ids\` is bound as \`${bound[2].trim()}\`, which is not the whole value. A ` +
          "binding that narrows the list makes every later check pass while the sheet's ids are " +
          "already gone",
      };
    }
  }
  const callAt = body.search(/\.\s*recovery_restore\s*\(/);
  if (callAt === -1) {
    return { ok: false, why: "the command never calls the core's `recovery_restore`" };
  }
  const argsOpen = body.indexOf("(", callAt);
  const argsClose = matchParen(body, argsOpen);
  const args = argsClose === -1 ? "" : body.slice(argsOpen, argsClose + 1);
  // ⛔⛔ THE ARGUMENT MUST BE THE BARE BINDING, borrowed and nothing else.
  // Asking `\bforwarded\b` against the whole argument list accepted
  // `&vaults[..0]` — an EMPTY slice that `cargo check` is perfectly happy with,
  // that this guard printed `ok` for, and whose only symptom is a refusal the
  // user cannot distinguish from a genuinely crowded index.
  const passes = splitTopLevelArgs(args).some((a) => {
    const m = /^&?\s*([A-Za-z_]\w*)$/.exec(a);
    return m !== null && m[1] === forwarded;
  });
  if (!passes) {
    return {
      ok: false,
      why:
        `\`${forwarded}\` does not reach the core call as itself — the argument list is ` +
        `\`${args.replace(/\s+/g, " ").trim()}\`. An argument that is parsed and then discarded, ` +
        "narrowed or sliced is the SAME defect as one that was never sent, and it type-checks",
    };
  }
  return { ok: true, why: `\`vault_ids\` accepted and forwarded to the core as \`${forwarded}\`` };
}

{
  const RESTORE_GATES = [
    {
      rel: "desktop/ui/main.js",
      gate: desktopRestoreVaultIdsUi,
      what: "the desktop UI's restore form",
    },
    {
      rel: "desktop/src-tauri/src/main.rs",
      gate: desktopRestoreVaultIdsCommand,
      what: "the desktop's `recovery_restore` IPC command",
    },
  ];
  for (const { rel, gate, what } of RESTORE_GATES) {
    const src = read(rel);
    if (src === null) continue;
    checks += 1;
    const r = gate(src);
    if (r.ok) {
      console.log(`  ok  ${rel}: ${what} carries the sheet's vault ids — ${r.why}`);
    } else {
      fail(
        `${rel}: ${what} — ${r.why}. The kit's per-device envelope index is ONE uncursored page ` +
          `any account can crowd rows off, so the sheet's ids are the ONLY flood-proof route to ` +
          `a restore (ADR 0042; ADR 0040 limitation 1). This hop has no behavioural coverage — ` +
          `the browsers' Playwright specs cover theirs, and nothing renders desktop/ui/.`,
      );
    }
  }

  // ⛔ THE SELF-TEST. Same posture as section 3b: the mutations this guard exists
  // to catch are encoded here, so a "fix" that returns true forever — or one that
  // returns false forever — is caught. Specimens are MINIMAL on purpose; one that
  // tracked the real sources would be updated to whatever they happened to say.
  const UI_OK = `
    const vaultIds = $("recovery-restore-vaults").value.split(/[\\s,]+/).filter(Boolean);
    r = await call("recovery_restore", { code, deviceId, adopt, vaultIds });
  `;
  const UI_DROPPED = `
    const vaultIds = $("recovery-restore-vaults").value.split(/[\\s,]+/).filter(Boolean);
    r = await call("recovery_restore", { code, deviceId, adopt });
  `;
  const UI_NULLED = `
    const vaultIds = $("recovery-restore-vaults").value.split(/[\\s,]+/).filter(Boolean);
    r = await call("recovery_restore", { code, deviceId, adopt, vaultIds: null });
  `;
  const UI_INVENTED = `
    const vaultIds = [];
    r = await call("recovery_restore", { code, deviceId, adopt, vaultIds });
  `;
  const UI_RENAMED = `
    const vaultIds = $("recovery-restore-vaults").value.split(/[\\s,]+/).filter(Boolean);
    r = await call("recovery_restore_v2", { code, deviceId, adopt, vaultIds });
  `;
  // ⛔⛔ THE TWO BYPASSES AN AUDITOR ACTUALLY WALKED THROUGH. Both were planted
  // in the REAL sources; both left this section printing `ok` and exit 0, and
  // the Rust one compiled. They are the reason the checks above relate the value
  // PASSED to the value BOUND instead of asking whether a token appears.
  const UI_EXPLICIT_OK = `
    const vaultIds = $("recovery-restore-vaults").value.split(/[\\s,]+/).filter(Boolean);
    r = await call("recovery_restore", { code, deviceId, adopt, vaultIds: vaultIds });
  `;
  const UI_SLICED = `
    const vaultIds = $("recovery-restore-vaults").value.split(/[\\s,]+/).filter(Boolean);
    r = await call("recovery_restore", { code, deviceId, adopt, vaultIds: vaultIds.slice(0, 0) });
  `;
  const UI_FILTERED = `
    const vaultIds = $("recovery-restore-vaults").value.split(/[\\s,]+/).filter(Boolean);
    r = await call("recovery_restore", { code, deviceId, adopt, vaultIds: vaultIds.filter(() => false) });
  `;
  const CMD_OK = `
#[tauri::command]
fn recovery_restore(code: String, vault_ids: Option<Vec<String>>) -> CmdResult<RestoreOutcome> {
    let vaults = vault_ids.unwrap_or_default();
    let r = sync_config(&state)?.recovery_restore(&code, None, false, &vaults).map_err(ipc)?;
    Ok(r)
}`;
  const CMD_NO_PARAM = `
#[tauri::command]
fn recovery_restore(code: String) -> CmdResult<RestoreOutcome> {
    let vaults = Vec::new();
    let r = sync_config(&state)?.recovery_restore(&code, None, false, &vaults).map_err(ipc)?;
    Ok(r)
}`;
  const CMD_IGNORED = `
#[tauri::command]
fn recovery_restore(code: String, vault_ids: Option<Vec<String>>) -> CmdResult<RestoreOutcome> {
    let vaults = vault_ids.unwrap_or_default();
    let r = sync_config(&state)?.recovery_restore(&code, None, false, &[]).map_err(ipc)?;
    Ok(r)
}`;
  const CMD_SLICED = `
#[tauri::command]
fn recovery_restore(code: String, vault_ids: Option<Vec<String>>) -> CmdResult<RestoreOutcome> {
    let vaults = vault_ids.unwrap_or_default();
    let r = sync_config(&state)?.recovery_restore(&code, None, false, &vaults[..0]).map_err(ipc)?;
    Ok(r)
}`;
  const CMD_TRUNCATING_BINDING = `
#[tauri::command]
fn recovery_restore(code: String, vault_ids: Option<Vec<String>>) -> CmdResult<RestoreOutcome> {
    let vaults: Vec<String> = vault_ids.unwrap_or_default().into_iter().take(0).collect();
    let r = sync_config(&state)?.recovery_restore(&code, None, false, &vaults).map_err(ipc)?;
    Ok(r)
}`;

  const SPECIMENS = [
    [desktopRestoreVaultIdsUi, UI_OK, true, "ui: ids read from the sheet field and passed"],
    [desktopRestoreVaultIdsUi, UI_EXPLICIT_OK, true, "ui: the explicit `vaultIds: vaultIds` form is accepted"],
    [desktopRestoreVaultIdsUi, UI_DROPPED, false, "ui: the argument DROPPED from the call is caught"],
    [desktopRestoreVaultIdsUi, UI_NULLED, false, "ui: `vaultIds: null` is caught"],
    [desktopRestoreVaultIdsUi, UI_INVENTED, false, "ui: ids not read from the sheet field are caught"],
    [desktopRestoreVaultIdsUi, UI_RENAMED, false, "ui: a renamed command leaves ZERO sites, which fails"],
    [desktopRestoreVaultIdsUi, UI_SLICED, false, "ui: ⛔ a correct binding passed through `.slice(0, 0)` is caught"],
    [desktopRestoreVaultIdsUi, UI_FILTERED, false, "ui: ⛔ a correct binding passed through a filter is caught"],
    [desktopRestoreVaultIdsCommand, CMD_OK, true, "cmd: the parameter is accepted and forwarded"],
    [desktopRestoreVaultIdsCommand, CMD_NO_PARAM, false, "cmd: a command that does not accept it is caught"],
    [desktopRestoreVaultIdsCommand, CMD_IGNORED, false, "cmd: accepted-then-discarded is caught"],
    [desktopRestoreVaultIdsCommand, CMD_SLICED, false, "cmd: ⛔ forwarding `&vaults[..0]` is caught"],
    [
      desktopRestoreVaultIdsCommand,
      CMD_TRUNCATING_BINDING,
      false,
      "cmd: ⛔ a binding that narrows before the call is caught",
    ],
  ];
  for (const [gate, specimen, want, what] of SPECIMENS) {
    checks += 1;
    const got = gate(specimen).ok;
    if (got === want) {
      console.log(`  ok  self-test: ${what}`);
    } else {
      fail(`self-test: ${what} — expected ok=${want}, got ok=${got}`);
    }
  }
}

// ⭐ It must fail when it finds nothing, or a rename turns it into a no-op.
if (checks === 0) {
  fail(
    "performed NO checks at all — either every shipping source moved (they did not) " +
      "or this guard's paths are stale. A guard that checks nothing is worse than none.",
  );
}

console.log(`\nperformed ${checks} structural check(s) across the shipping clients`);
if (failures > 0) {
  console.error(`\nFAILED: ${failures} problem(s)`);
  process.exit(1);
}
console.log(
  "PASS: every shipping adoption path merges, every removal tombstones, every import " +
    "de-dups by content, and the identity derivation is not reimplemented in JS",
);
