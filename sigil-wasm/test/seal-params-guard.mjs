// seal-params-guard — a SOURCE-STRUCTURE guard: every product re-seal site must
// ratchet its Argon2 parameters, and none may pass the bare defaults constant.
//
// WHY THIS EXISTS, and why it is a source check rather than a behavioural one.
//
// Phase 59 fixed a real downgrade: the browser clients re-sealed at a hardcoded
// `{ m_cost: 19456, t_cost: 2, p_cost: 1 }` without reading the container header,
// so a vault the CLI wrote at 65536/4/2 came back at 19456/2/1 after ONE browser
// edit — a 3.4x memory and 2x time downgrade, silently, on a cross-client vault.
// The fix routes every site through a `sealParams(...)` helper that reads the
// existing header and takes the componentwise MAX.
//
// An independent verifier then found that only ONE of the six sites was actually
// guarded: mutating the other five back to the bare constant left webapp 50/50
// and extension 14/14 GREEN. The code was correct; nothing would have noticed it
// becoming incorrect. That is entry #9 of docs/engineering-lessons.md — "the
// suites check one needle, not the property" — recurring inside the very phase
// that added the document.
//
// Behavioural coverage for all six would mean driving an enrolled device and a
// passkey ceremony through two browsers for each one. This check buys the
// regression guard those tests would buy, for the failure that actually happens:
// a NEW re-seal call site written later that forgets to ratchet. It is the same
// shape as the AST guard already pinning the entitlement call sites in sigild.
//
// It is deliberately NOT a grep for a magic number. It locates every call to a
// sealing function in the shipping product sources and asserts each one is passed
// a ratcheted parameter expression.
//
// Run: node sigil-wasm/test/seal-params-guard.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "../..");

/** The shipping product sources that persist a sealed container. */
const PRODUCTS = [
  "web/apps/webapp/app/authenticator.tsx",
  "extension/src/popup/popup.js",
];

/** Functions that write a `SIGILcli` container and therefore take Argon2 params. */
const SEALERS = ["sealVault", "sealDeviceIdentity", "sealHwSlot"];

/** The helper that reads the existing header and ratchets. */
const RATCHET = "sealParams";

let failures = 0;
const fail = (m) => {
  failures += 1;
  console.error(`FAIL: ${m}`);
};

/**
 * Return the argument text of each call to `name` in `src`, by scanning forward
 * from the call and balancing parentheses. Crude but exact enough for a guard,
 * and it does not depend on formatting the way a line-based grep would.
 */
function callArguments(src, name) {
  const out = [];
  const needle = `${name}(`;
  let i = src.indexOf(needle);
  while (i !== -1) {
    // Skip a definition (`function sealVault(`) rather than a call.
    const before = src.slice(Math.max(0, i - 20), i);
    if (!/\b(function|async function)\s*$/.test(before)) {
      let depth = 0;
      let j = i + needle.length - 1;
      for (; j < src.length; j += 1) {
        if (src[j] === "(") depth += 1;
        else if (src[j] === ")") {
          depth -= 1;
          if (depth === 0) break;
        }
      }
      out.push({ index: i, args: src.slice(i + needle.length, j) });
    }
    i = src.indexOf(needle, i + needle.length);
  }
  return out;
}

const lineOf = (src, index) => src.slice(0, index).split("\n").length;

console.log("seal-params-guard: every product re-seal must ratchet its Argon2 parameters\n");

let checked = 0;
for (const rel of PRODUCTS) {
  const path = resolve(ROOT, rel);
  let src;
  try {
    src = readFileSync(path, "utf8");
  } catch {
    fail(`${rel}: cannot read — if this file moved, this guard must move with it`);
    continue;
  }

  // The ratchet helper itself must exist; without it every call below is
  // trivially unratcheted and the guard would be reporting on nothing.
  if (!src.includes(`${RATCHET}(`)) {
    fail(`${rel}: no ${RATCHET}(...) helper — the ratchet is gone entirely`);
    continue;
  }

  for (const sealer of SEALERS) {
    for (const call of callArguments(src, sealer)) {
      checked += 1;
      const line = lineOf(src, call.index);
      if (!call.args.includes(`${RATCHET}(`)) {
        fail(
          `${rel}:${line} — ${sealer}(...) does not pass ${RATCHET}(...). ` +
            `A re-seal that ignores the stored header silently DOWNGRADES the ` +
            `work factor of a vault written by a stronger client.`,
        );
      } else {
        console.log(`  ok  ${rel}:${line} ${sealer} ratchets`);
      }
    }
  }
}

if (checked === 0) {
  fail(
    "found NO sealing call sites at all — either the products stopped sealing " +
      "(they did not) or this guard's function names are stale. A guard that " +
      "checks nothing is worse than no guard.",
  );
}

console.log(`\nchecked ${checked} sealing call site(s) across ${PRODUCTS.length} product source(s)`);

if (failures > 0) {
  console.error(`\nFAILED: ${failures} problem(s)`);
  process.exit(1);
}
console.log("PASS: every product sealing call site ratchets its Argon2 parameters");
