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
    out.push({ index: m.index, line: lineOf(src, m.index), text: m[0] });
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
