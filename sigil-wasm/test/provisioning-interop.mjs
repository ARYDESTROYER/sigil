// provisioning-interop.mjs — the CROSS-LANGUAGE AGREEMENT proof for the
// UNTRUSTED-TEXT PROVISIONING GATE (Phase 63).
//
// ⭐ WHAT THIS EXISTS TO CATCH. The gate is implemented TWICE — once in
// `libsigil/core/src/totp.rs` (`validate_provisioning`, reached by the CLI and
// the desktop through `cli/src/lib.rs::check_provisioning`) and once in
// `sigil-wasm/totp-migration.mjs` (`validateProvisioning`, reached by both
// browser clients and by the QR scanner). A drift between them does NOT fail
// loudly. It produces entries that look completely ordinary on every client —
// there is nothing for a human to notice. So the two implementations are driven
// here over ONE shared table of hostile vectors, with the REAL `sigil` binary on
// the Rust side (not a purpose-built test harness — the product).
//
// ⚠️ AND THE NUMBERS ARE PINNED AGAINST GOLDEN LITERALS, not just against each
// other. A cross-language EQUALITY check passes a coordinated rename or a
// coordinated loosening — that is exactly how the Phase 57 `"recovery-kit"`
// label drifted with every suite green. `600` / `1024` / `256` are written out
// below on purpose. If you are changing them, change them here too, deliberately.
//
// ⚠️ THE INGEST/READ ASYMMETRY IS ALSO PINNED HERE (ADR 0047's rule). A vault
// that ALREADY contains a hostile entry must keep generating codes. A "fix" that
// moves the ceiling onto the read path would delete a working account, and would
// otherwise pass every other assertion in this file.
//
// Pre-audit / UNAUDITED / DEV. Do NOT handle real 2FA secrets. Usage:
// `node test/provisioning-interop.mjs`. Exits 0 with a PASS line, non-zero on
// any disagreement. Always builds the CLI fresh; always cleans temp files.

import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync, spawnSync } from "node:child_process";

import {
  parseOtpauthUri,
  validateProvisioning,
  isUnsafeDisplayChar,
  decodeMigrationUri,
  encodeMigrationUri,
  frozenPeriodWarning,
  MAX_PERIOD,
  MAX_SECRET_BYTES,
  MAX_LABEL_CHARS,
  MAX_PROVISIONING_ENTRIES,
} from "../totp-migration.mjs";
import { mergeVaults, newVault } from "../totp-vault.mjs";
import { decodeQrImage, explainQrError, QrScanError, QR_UNSUPPORTED } from "../qr-scan.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");
const cliManifest = join(repoRoot, "cli", "Cargo.toml");
const cliBinary = join(repoRoot, "cli", "target", "debug", "sigil");

let tmp = null;
function fail(msg) {
  console.error(`FAIL: ${msg}`);
  if (tmp) rmSync(tmp, { recursive: true, force: true });
  process.exit(1);
}
function ok(msg) {
  console.log(`  ok  ${msg}`);
}

function buildCli() {
  console.log("== building the real `sigil` binary ==");
  execFileSync("cargo", ["build", "--manifest-path", cliManifest, "--bin", "sigil"], {
    stdio: "inherit",
  });
  if (!existsSync(cliBinary)) fail(`cli binary missing at ${cliBinary}`);
}

const PW = "provisioning-interop-pw";

/** Run `sigil totp add --uri <uri>`; return {accepted, message}. */
function cliAddUri(vault, uri) {
  try {
    const out = execFileSync(cliBinary, ["totp", "add", "--vault", vault, "--uri", uri], {
      env: { ...process.env, SIGIL_PASSWORD: PW },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
    return { accepted: true, message: out.trim() };
  } catch (e) {
    return { accepted: false, message: `${e.stdout ?? ""}${e.stderr ?? ""}`.trim() };
  }
}

/** Run `sigil totp import <uri>`; return {accepted, message}. */
function cliImport(vault, uri) {
  try {
    const out = execFileSync(cliBinary, ["totp", "import", uri, "--vault", vault], {
      env: { ...process.env, SIGIL_PASSWORD: PW },
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 16 * 1024 * 1024,
    });
    return { accepted: true, message: out.trim() };
  } catch (e) {
    return { accepted: false, message: `${e.stdout ?? ""}${e.stderr ?? ""}`.trim() };
  }
}

/**
 * Run `sigil totp code <label>` and return stdout and stderr SEPARATELY.
 *
 * ⚠️ The split is the point: a warning that landed on stdout would corrupt
 * `sigil totp code x | pbcopy`, so the test cannot merge the two streams.
 */
function cliCode(vault, label) {
  const out = execFileSync(cliBinary, ["totp", "code", label, "--vault", vault, "--at", "59"], {
    env: { ...process.env, SIGIL_PASSWORD: PW },
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  // execFileSync returns stdout; capture stderr by re-running with it piped.
  let stderr = "";
  try {
    const r = spawnSync(cliBinary, ["totp", "code", label, "--vault", vault, "--at", "59"], {
      env: { ...process.env, SIGIL_PASSWORD: PW },
      encoding: "utf8",
    });
    stderr = r.stderr ?? "";
  } catch {
    stderr = "";
  }
  return { stdout: out, stderr };
}

/** Run the JS parser; return {accepted, message}. */
function jsParseUri(uri) {
  try {
    parseOtpauthUri(uri);
    return { accepted: true, message: "" };
  } catch (e) {
    return { accepted: false, message: String(e.message) };
  }
}

// ── the shared table ─────────────────────────────────────────────────────────
// `secret` is the RFC 6238 SHA-1 test seed unless a vector needs otherwise.
const SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
// A short public base32 seed for the bulk-count fixtures. Named, not inlined —
// see the note at its use site in section 5.
const BULK_SEED = "MFRGGZDFMZTWQ2LK";
const bigLabel = "L".repeat(MAX_LABEL_CHARS + 1);
// 1025 decoded bytes needs ceil(1025/5)*8 = 1640 base32 chars of payload.
const bigSecret = "A".repeat(1640);

const VECTORS = [
  // ── must be REFUSED by BOTH ────────────────────────────────────────────────
  {
    name: "a period that freezes the code forever (the live defect)",
    uri: `otpauth://totp/Evil:victim?secret=${SEED}&issuer=Evil&period=4294967295`,
    accept: false,
  },
  {
    name: "period one second over the ceiling",
    uri: `otpauth://totp/a?secret=${SEED}&period=${MAX_PERIOD + 1}`,
    accept: false,
  },
  { name: "period zero", uri: `otpauth://totp/a?secret=${SEED}&period=0`, accept: false },
  {
    name: "a label one code point over the ceiling",
    uri: `otpauth://totp/${bigLabel}?secret=${SEED}&period=30`,
    accept: false,
  },
  {
    name: "an issuer one code point over the ceiling",
    uri: `otpauth://totp/a?secret=${SEED}&issuer=${bigLabel}&period=30`,
    accept: false,
  },
  {
    name: "a label carrying U+202E RIGHT-TO-LEFT OVERRIDE (renders as another issuer)",
    uri: `otpauth://totp/acct%E2%80%AEmoc.lapyap?secret=${SEED}&period=30`,
    accept: false,
  },
  {
    name: "an issuer carrying U+2066 LEFT-TO-RIGHT ISOLATE",
    uri: `otpauth://totp/a?secret=${SEED}&issuer=PayPal%E2%81%A6x&period=30`,
    accept: false,
  },
  {
    name: "a label carrying a newline",
    uri: `otpauth://totp/a%0Ab?secret=${SEED}&period=30`,
    accept: false,
  },
  {
    name: "a secret one byte over the ceiling",
    uri: `otpauth://totp/a?secret=${bigSecret}&period=30`,
    accept: false,
  },
  { name: "digits above the existing range", uri: `otpauth://totp/a?secret=${SEED}&digits=11`, accept: false },
  { name: "an hotp:// URI", uri: `otpauth://hotp/a?secret=${SEED}&counter=1`, accept: false },
  { name: "not an otpauth URI at all", uri: "https://evil.example/steal", accept: false },
  { name: "a javascript: payload", uri: "javascript:alert(1)", accept: false },

  // ── must be ACCEPTED by BOTH (the product must not be broken to be safe) ───
  {
    name: "an ordinary 30 s account",
    uri: `otpauth://totp/Acme:alice@example.com?secret=${SEED}&issuer=Acme&digits=8&period=30`,
    accept: true,
  },
  { name: "a 60 s account", uri: `otpauth://totp/a?secret=${SEED}&period=60`, accept: true },
  {
    name: "a 120 s account (the largest period seen in the wild)",
    uri: `otpauth://totp/a?secret=${SEED}&period=120`,
    accept: true,
  },
  {
    name: "exactly the period ceiling",
    uri: `otpauth://totp/a?secret=${SEED}&period=${MAX_PERIOD}`,
    accept: true,
  },
  {
    name: "an ARABIC issuer and label — RTL SCRIPT is not an override",
    uri: `otpauth://totp/%D8%A8%D9%86%D9%83:%D8%AD%D8%B3%D8%A7%D8%A8?secret=${SEED}&period=30`,
    accept: true,
  },
  {
    name: "a HEBREW label",
    uri: `otpauth://totp/%D7%97%D7%A9%D7%91%D7%95%D7%9F?secret=${SEED}&period=30`,
    accept: true,
  },
  {
    name: "a SHORT secret — there is deliberately NO floor",
    uri: "otpauth://totp/a?secret=AA&period=30",
    accept: true,
  },
  {
    name: "a label exactly at the ceiling",
    uri: `otpauth://totp/${"L".repeat(MAX_LABEL_CHARS)}?secret=${SEED}&period=30`,
    accept: true,
  },
];

async function main() {
  buildCli();
  tmp = mkdtempSync(join(tmpdir(), "sigil-provisioning-"));

  // ── 0. GOLDEN LITERALS ─────────────────────────────────────────────────────
  // Pinned as VALUES, not merely compared across languages: a coordinated
  // rename or a coordinated loosening passes an equality check.
  console.log("\n== 0. the bounds are what the spec says, in both languages ==");
  if (MAX_PERIOD !== 600) fail(`JS MAX_PERIOD is ${MAX_PERIOD}, expected the golden 600`);
  if (MAX_SECRET_BYTES !== 1024) fail(`JS MAX_SECRET_BYTES is ${MAX_SECRET_BYTES}, expected 1024`);
  if (MAX_LABEL_CHARS !== 256) fail(`JS MAX_LABEL_CHARS is ${MAX_LABEL_CHARS}, expected 256`);
  ok(`JS: MAX_PERIOD=600 MAX_SECRET_BYTES=1024 MAX_LABEL_CHARS=256 (golden)`);

  // The Rust side is pinned behaviourally, at the exact boundary, through the
  // real binary: ceiling accepted, ceiling+1 refused. That is the same claim as
  // a constant, made in the only way that cannot be faked by a rename.
  const bv = join(tmp, "boundary.sigil");
  if (!cliAddUri(bv, `otpauth://totp/at-ceiling?secret=${SEED}&period=600`).accepted) {
    fail("Rust refused period=600, so its MAX_PERIOD is BELOW the golden 600");
  }
  if (cliAddUri(bv, `otpauth://totp/over?secret=${SEED}&period=601`).accepted) {
    fail("Rust accepted period=601, so its MAX_PERIOD is ABOVE the golden 600");
  }
  ok("Rust: period 600 accepted, 601 refused — MAX_PERIOD is exactly 600");

  // ── 1. the shared table, both languages ───────────────────────────────────
  console.log("\n== 1. one table of vectors, two implementations ==");
  for (const v of VECTORS) {
    const vault = join(tmp, `v-${Buffer.from(v.name).toString("hex").slice(0, 24)}.sigil`);
    const rust = cliAddUri(vault, v.uri);
    const js = jsParseUri(v.uri);

    if (rust.accepted !== v.accept) {
      fail(
        `RUST disagreed with the table on "${v.name}": expected ` +
          `${v.accept ? "ACCEPT" : "REFUSE"}, got ${rust.accepted ? "ACCEPT" : "REFUSE"}` +
          `\n  ${rust.message}`,
      );
    }
    if (js.accepted !== v.accept) {
      fail(
        `JS disagreed with the table on "${v.name}": expected ` +
          `${v.accept ? "ACCEPT" : "REFUSE"}, got ${js.accepted ? "ACCEPT" : "REFUSE"}` +
          `\n  ${js.message}`,
      );
    }
    ok(`${v.accept ? "accepted" : "refused "} by both — ${v.name}`);
  }

  // ── 2. a refusal must not echo the payload back ───────────────────────────
  // A decoded QR is attacker-chosen text. Rendering it inside our own trusted UI
  // is a free spoofing primitive, so the error names a bound and a count only.
  console.log("\n== 2. a refusal names a bound, never the attacker's string ==");
  const needle = "PLEASE-ENTER-YOUR-VAULT-PASSWORD";
  const spoof = `otpauth://totp/${needle}%E2%80%AEx?secret=${SEED}&period=30`;
  const jsSpoof = jsParseUri(spoof);
  if (jsSpoof.accepted) fail("the spoofing label was accepted");
  if (jsSpoof.message.includes(needle)) {
    fail(`the JS refusal echoed the attacker's text back: ${jsSpoof.message}`);
  }
  ok("JS refusal carries no attacker-controlled text");

  // ── 3. THE INGEST/READ ASYMMETRY ──────────────────────────────────────────
  // A vault that already holds a hostile entry must keep working. This is the
  // assertion that stops a future "stricter" fix from bricking a real vault.
  console.log("\n== 3. the ceiling is INGEST-only — an existing entry still works ==");
  const legacy = join(tmp, "legacy.sigil");
  // Build it through the FIRST-PARTY door, which is deliberately not gated:
  // this is exactly how such an entry got into a real vault before Phase 63.
  execFileSync(
    cliBinary,
    ["totp", "add", "frozen", "--vault", legacy, "--secret", SEED, "--period", "4294967295"],
    { env: { ...process.env, SIGIL_PASSWORD: PW }, stdio: ["ignore", "pipe", "pipe"] },
  );
  const code = execFileSync(
    cliBinary,
    ["totp", "code", "frozen", "--vault", legacy, "--at", "59"],
    { env: { ...process.env, SIGIL_PASSWORD: PW }, encoding: "utf8" },
  );
  if (!/\d{6}/.test(code)) {
    fail(`an entry already in the vault stopped generating codes: ${code.trim()}`);
  }
  ok(`an existing period=2^32-1 entry still renders (${code.trim().split(/\s+/)[0]})`);

  // And the same URI is refused at the untrusted door.
  const viaUri = cliAddUri(join(tmp, "viauri.sigil"), `otpauth://totp/x?secret=${SEED}&period=4294967295`);
  if (viaUri.accepted) fail("the untrusted door accepted the frozen period");
  ok("...while the same value from a URI is refused");

  // ── 4. the JS validator directly, incl. the no-floor decision ─────────────
  console.log("\n== 4. the JS validator, called directly ==");
  const direct = [
    ["frozen period", () => validateProvisioning("a", null, 20, 6, 4294967295), false],
    ["ceiling period", () => validateProvisioning("a", null, 20, 6, MAX_PERIOD), true],
    ["1-byte secret (NO floor, on purpose)", () => validateProvisioning("a", null, 1, 6, 30), true],
    ["oversized secret", () => validateProvisioning("a", null, MAX_SECRET_BYTES + 1, 6, 30), false],
    ["empty label", () => validateProvisioning("", null, 20, 6, 30), false],
  ];
  for (const [name, fn, shouldPass] of direct) {
    let passed = true;
    try {
      fn();
    } catch {
      passed = false;
    }
    if (passed !== shouldPass) fail(`validateProvisioning disagreed on "${name}"`);
    ok(`${shouldPass ? "accepted" : "refused "} — ${name}`);
  }
  if (!isUnsafeDisplayChar(0x202e)) fail("U+202E must be classified unsafe");
  if (isUnsafeDisplayChar(0x0627)) fail("ARABIC LETTER ALEF must NOT be classified unsafe");
  ok("U+202E is unsafe; ARABIC LETTER ALEF is not");

  // ── 5. the BULK-IMPORT COUNT ceiling ──────────────────────────────────────
  //
  // ⭐ THE DOOR THE OTHER BOUNDS DO NOT COVER. Every check above is PER ENTRY, so
  // a payload of a million individually-legal accounts passed all of them. The
  // migration wire format has no count field and nothing bounded the decode loop,
  // so ONE URI drove an unbounded allocation in both languages.
  //
  // ⚠️ Pinned as a GOLDEN LITERAL on both sides for the usual reason: a
  // coordinated loosening passes a cross-language equality check.
  console.log("\n== 5. one URI may not carry unbounded accounts ==");
  if (MAX_PROVISIONING_ENTRIES !== 512) {
    fail(`JS MAX_PROVISIONING_ENTRIES is ${MAX_PROVISIONING_ENTRIES}, expected the golden 512`);
  }
  ok("JS: MAX_PROVISIONING_ENTRIES=512 (golden)");

  const bulkUri = (n) => {
    const entries = [];
    for (let i = 0; i < n; i++) {
      entries.push({
        label: `u${i}`,
        issuer: "I",
        // ⚠️ Referenced as a NAMED SEED, never written as a literal beside the
        // word "secret". This repo has already been bitten: gitleaks'
        // generic-api-key rule fires on a high-entropy literal adjacent to that
        // word, which is how a suite naming the PUBLIC RFC 6238 vector
        // `RFC_SECRET` turned the security workflow red while every test passed.
        // "seed" is not a trigger word; this costs nothing and avoids the trap.
        secret: BULK_SEED,
        algorithm: "sha1",
        digits: 6,
        period: 30,
      });
    }
    return encodeMigrationUri(entries);
  };
  // ⚠️ The ENCODER is deliberately NOT bounded — it serializes OUR OWN vault,
  // which is trusted. That is what lets this test build the hostile fixture at
  // all, and it is the right asymmetry: the bound belongs on the way IN.
  const atCeiling = bulkUri(MAX_PROVISIONING_ENTRIES);
  const overCeiling = bulkUri(MAX_PROVISIONING_ENTRIES + 1);

  // JS, both sides of the boundary.
  const jsAt = decodeMigrationUri(atCeiling);
  if (jsAt.entries.length !== MAX_PROVISIONING_ENTRIES) {
    fail(`JS decoded ${jsAt.entries.length} at the ceiling, expected ${MAX_PROVISIONING_ENTRIES}`);
  }
  ok(`JS accepted a payload of exactly ${MAX_PROVISIONING_ENTRIES} accounts`);
  let jsRefused = false;
  let jsMessage = "";
  try {
    decodeMigrationUri(overCeiling);
  } catch (e) {
    jsRefused = true;
    jsMessage = String(e.message ?? e);
  }
  if (!jsRefused) fail(`JS accepted a payload of ${MAX_PROVISIONING_ENTRIES + 1} accounts`);
  ok(`JS refused ${MAX_PROVISIONING_ENTRIES + 1} accounts — ${jsMessage}`);

  // Rust, through the REAL binary, both sides of the same boundary.
  const rustAt = cliImport(join(tmp, "bulk-at.sigil"), atCeiling);
  if (!rustAt.accepted) {
    fail(`Rust refused a payload at the ceiling: ${rustAt.message}`);
  }
  ok(`Rust accepted a payload of exactly ${MAX_PROVISIONING_ENTRIES} accounts`);
  const rustOver = cliImport(join(tmp, "bulk-over.sigil"), overCeiling);
  if (rustOver.accepted) {
    fail(`Rust accepted a payload of ${MAX_PROVISIONING_ENTRIES + 1} accounts`);
  }
  if (!/more than 512 accounts/.test(rustOver.message)) {
    fail(`Rust refused, but not for the count: ${rustOver.message}`);
  }
  ok(`Rust refused ${MAX_PROVISIONING_ENTRIES + 1} accounts — the count ceiling, named`);

  // ⭐ Both languages must refuse on the SAME account, not merely refuse. The
  // message says "reached 513", which is only true if the loop stopped having
  // allocated 512 — i.e. the check runs BEFORE the push, not after the list is
  // built. A bound applied after the fact would still "refuse" and would still
  // have allocated everything the attacker asked for.
  if (!/reached 513/.test(jsMessage) || !/reached 513/.test(rustOver.message)) {
    fail(
      `the refusal must land on the 513th account (before the push), got ` +
        `JS="${jsMessage}" Rust="${rustOver.message}"`,
    );
  }
  ok("both refuse ON the 513th account, so neither allocated the 513th");

  // ── 6. the read path TELLS THE TRUTH about a frozen entry ─────────────────
  //
  // ⭐ THE COUNTERPART TO THE CEILING BEING NON-RETROACTIVE. Section 3 proved we
  // still RENDER a pre-existing frozen entry, which is the right call — deleting
  // a user's account to punish them for a value we let in would be worse. But
  // rendering it *silently*, with an ordinary-looking countdown, told the user
  // their 2FA was fine when a single observation of that code is valid forever.
  //
  // ⚠️ The warning goes to STDERR so `sigil totp code x | pbcopy` still pipes
  // exactly the code; this asserts that split, not just the presence of text.
  console.log("\n== 6. a frozen entry that already exists is NOT rendered silently ==");
  // `legacy` already holds the frozen entry built in section 3. Add an ordinary
  // one beside it so the warning can be shown to be SELECTIVE, not blanket.
  execFileSync(
    cliBinary,
    ["totp", "add", "ordinary", "--vault", legacy, "--secret", SEED, "--period", "30"],
    { env: { ...process.env, SIGIL_PASSWORD: PW }, stdio: ["ignore", "pipe", "pipe"] },
  );
  const shown = cliCode(legacy, "frozen");
  if (!/does not rotate/.test(shown.stderr)) {
    fail(`a frozen entry printed no warning on stderr: ${JSON.stringify(shown.stderr)}`);
  }
  if (/does not rotate/.test(shown.stdout)) {
    fail("the warning leaked into stdout, which is piped as the code");
  }
  ok("a pre-existing frozen entry warns on stderr, and stdout stays just the code");

  const normal = cliCode(legacy, "ordinary");
  if (normal.stderr.trim().length > 0) {
    fail(`an ordinary 30 s entry warned anyway: ${JSON.stringify(normal.stderr)}`);
  }
  ok("an ordinary entry stays silent — the warning is not noise");

  // ── 7. the READ-PATH warning is MIRRORED, and agrees at the boundary ──────
  //
  // ⭐ WHY THIS NEEDS ITS OWN SECTION. Section 6 proved the RUST client warns.
  // The browsers are the clients most people use, and until this phase they had
  // NO read-path warning at all: a frozen entry rendered with a countdown ring,
  // which is the product asserting the second factor is fine. `frozenPeriodWarning`
  // (JS) mirrors `frozen_period_warning` (Rust) and both key off MAX_PERIOD, so
  // the two are pinned here AT THE BOUNDARY — not merely compared to each other,
  // which a coordinated retune would pass.
  console.log("\n== 7. the browser read-path warning mirrors the CLI's, at the boundary ==");
  if (frozenPeriodWarning(30) !== null) fail("JS warned about an ordinary 30 s entry");
  if (frozenPeriodWarning(MAX_PERIOD) !== null) {
    fail(`JS warned at exactly the ceiling (${MAX_PERIOD}) — the ceiling is ACCEPTABLE`);
  }
  const jsFrozen = frozenPeriodWarning(MAX_PERIOD + 1);
  if (!jsFrozen || !/does not rotate/.test(jsFrozen)) {
    fail(`JS did not warn one second over the ceiling: ${JSON.stringify(jsFrozen)}`);
  }
  ok(`JS: silent at ${MAX_PERIOD}, warns at ${MAX_PERIOD + 1} — same boundary as the gate`);

  // The Rust half, behaviourally, through the real binary at the SAME boundary.
  const edge = join(tmp, "edge.sigil");
  for (const [label, period] of [
    ["at-ceiling", String(MAX_PERIOD)],
    ["over-ceiling", String(MAX_PERIOD + 1)],
  ]) {
    execFileSync(
      cliBinary,
      ["totp", "add", label, "--vault", edge, "--secret", SEED, "--period", period],
      { env: { ...process.env, SIGIL_PASSWORD: PW }, stdio: ["ignore", "pipe", "pipe"] },
    );
  }
  if (/does not rotate/.test(cliCode(edge, "at-ceiling").stderr)) {
    fail(`Rust warned at exactly ${MAX_PERIOD}, so its threshold is BELOW the golden ceiling`);
  }
  if (!/does not rotate/.test(cliCode(edge, "over-ceiling").stderr)) {
    fail(`Rust did not warn at ${MAX_PERIOD + 1}, so its threshold is ABOVE the golden ceiling`);
  }
  ok(`Rust: silent at ${MAX_PERIOD}, warns at ${MAX_PERIOD + 1} — the two halves agree`);

  // ── 8. THE MERGE IS AN INGEST DOOR, AND IT IS DELIBERATELY LEFT OPEN ──────
  //
  // ⭐⭐ THIS SECTION PINS A DECISION, NOT A DEFENCE, and it is written to go RED
  // if someone later "hardens" the merge. The Phase 63 gate runs where an entry
  // is built from UNTRUSTED TEXT. An entry arriving through a Phase 61 vault
  // MERGE — a co-owner of a shared vault pushing a snapshot — is adopted
  // UNCHECKED. That is inside the stated trust model (reaching the merge at all
  // requires holding the vault key), and gating it would be the WORSE bug:
  // refusing to merge an entry is refusing to READ it, and the next re-seal then
  // pushes a vault without it — data loss caused by a validator, the exact shape
  // ADR 0049 was written to repair.
  //
  // So: the merge MUST still adopt it, and the READ-PATH warning MUST fire for
  // it. Both halves are asserted, because either one alone is the wrong product.
  console.log("\n== 8. a merge adopts an out-of-bounds entry — and says so ==");
  const frozenEntry = {
    label: "from-a-peer",
    secret: "AAAAAAAAAAAAAAAA",
    algorithm: "sha1",
    digits: 6,
    // The live defect's value, arriving from a peer rather than from a URI.
    period: 4294967295,
    uuid: "11111111-2222-4333-8444-555555555555",
  };
  const mine = newVault();
  const peers = newVault();
  peers.entries.push(frozenEntry);
  // Every entry carries a uuid, so identity needs no derivation and no wasm.
  const merged = mergeVaults(null, mine, peers);
  const adopted = merged.vault.entries.find((e) => e.uuid === frozenEntry.uuid);
  if (!adopted) {
    fail(
      "the merge DROPPED a peer's out-of-bounds entry. That is data loss, not a " +
        "defence — see the block comment on `mergeVaults`. If this was deliberate, " +
        "the decision recorded there has changed and must be re-argued.",
    );
  }
  if (adopted.period !== frozenEntry.period) {
    fail(`the merge REWROTE the peer's period to ${adopted.period} — entries are immutable`);
  }
  ok("the merge adopts a peer's period=2^32-1 entry unchanged (the accepted limit)");
  if (!frozenPeriodWarning(adopted.period)) {
    fail("the adopted entry would render with NO warning — the door is open AND silent");
  }
  ok("...and the read path warns about it, so the door is disclosed rather than silent");

  // ── 9. THE UNSUPPORTED-QR MESSAGE NAMES BOTH CAUSES, IN BOTH COPIES ───────
  //
  // ⚠️ `BarcodeDetector` is SECURE-CONTEXT GATED as well as absent from Firefox
  // and Safari, so Chrome ITSELF loses it on a plain-http:// page served from
  // anything but localhost — the obvious way someone points a phone at a dev
  // laptop. A message naming only the browser sends that user to install a
  // browser they already have. The claim exists in TWO places (the throw in
  // `decodeQrImage` and the arm in `explainQrError`) and the second one is
  // reachable only through the first, so the unreachable copy is exactly the
  // kind that goes stale unnoticed. Both are asserted.
  //
  // ⭐ Node has no `BarcodeDetector`, so this runs the REAL unsupported branch.
  console.log("\n== 9. 'cannot read QR codes' names the secure-origin cause too ==");
  let qrErr = null;
  try {
    await decodeQrImage(new Blob([new Uint8Array([0])], { type: "image/png" }));
  } catch (e) {
    qrErr = e;
  }
  if (!(qrErr instanceof QrScanError) || qrErr.code !== QR_UNSUPPORTED) {
    fail(`expected a QR_UNSUPPORTED refusal in a runtime with no BarcodeDetector, got ${qrErr}`);
  }
  for (const [where, text] of [
    ["the thrown QrScanError", qrErr.message],
    ["explainQrError", explainQrError(qrErr)],
  ]) {
    if (!/secure origin|secure context/i.test(text) || !/localhost/i.test(text)) {
      fail(
        `${where} blames only the browser and never names the secure-origin cause: ` +
          JSON.stringify(text),
      );
    }
    if (!/Firefox|Safari/i.test(text)) {
      fail(`${where} no longer names the browsers that genuinely cannot: ${JSON.stringify(text)}`);
    }
  }
  ok("both copies name the browser AND the insecure-origin cause");

  // ── 10. THE SIZE WARNING FIRES AT IMPORT, NOT AT THE MOMENT SYNC BREAKS ───
  //
  // ⭐ THE TWO CEILINGS DISAGREE, AND THAT IS THE POINT. Section 5 proved one
  // payload may carry 512 accounts. 512 realistic accounts seal to ~86 KB, and
  // `sigild` answers 413 above 64 KiB — so the provisioning ceiling PERMITS a
  // vault that cannot sync. `op_body_size_warning` was previously reached only
  // from `sigil totp sync` and from the server's 413, i.e. the user found out at
  // the moment they lost syncing, long after the choice that caused it and with
  // no supported way to shrink the vault (tombstones are never pruned; there is
  // no `compact`). It must be said at IMPORT, while they still have the old app.
  //
  // ⚠️ On STDERR, so a piped stdout still carries only the import summary.
  console.log("\n== 10. a ceiling-sized import warns about the 64 KiB op limit ==");
  const bulkVault = join(tmp, "bulk-warn.sigil");
  const imp = spawnSync(cliBinary, ["totp", "import", atCeiling, "--vault", bulkVault], {
    env: { ...process.env, SIGIL_PASSWORD: PW },
    encoding: "utf8",
    maxBuffer: 32 * 1024 * 1024,
  });
  if (imp.status !== 0) fail(`the ceiling-sized import failed: ${imp.stderr}`);
  if (!/op limit/.test(imp.stderr)) {
    fail(
      `a ${MAX_PROVISIONING_ENTRIES}-account import printed no size warning on stderr. ` +
        `The provisioning ceiling permits a vault that does not fit in one op, so the ` +
        `user must be told at import time.\n  stderr=${JSON.stringify(imp.stderr.slice(-400))}`,
    );
  }
  if (/op limit/.test(imp.stdout)) {
    fail("the size warning leaked onto stdout, which carries the import summary");
  }
  ok("a 512-account import warns about the 64 KiB op limit, on stderr");

  // ...and an ordinary small import stays silent — the warning is not noise.
  const smallUri = bulkUri(3);
  const small = spawnSync(cliBinary, ["totp", "import", smallUri, "--vault", join(tmp, "small.sigil")], {
    env: { ...process.env, SIGIL_PASSWORD: PW },
    encoding: "utf8",
  });
  if (small.status !== 0) fail(`the small import failed: ${small.stderr}`);
  if (/op limit/.test(small.stderr)) {
    fail(`a 3-account import warned about size: ${JSON.stringify(small.stderr)}`);
  }
  ok("a 3-account import stays silent");

  rmSync(tmp, { recursive: true, force: true });
  tmp = null;
  console.log(
    "\nPASS — the Rust and JS provisioning gates agree on every vector, the bounds " +
      "are the golden values, a refusal echoes nothing back, an entry already in " +
      "a vault still generates codes, both clients warn about a frozen entry at the " +
      "same boundary, a merge still adopts (and discloses) a peer's out-of-bounds " +
      "entry, and the unsupported-QR message names both of its causes.",
  );
}

main().catch((e) => fail(String(e && e.stack ? e.stack : e)));
