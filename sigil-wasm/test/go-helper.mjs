// go-helper — resolve a Go toolchain the same way everywhere.
//
// ⚠️ WHY THIS EXISTS. Six of these interop suites hardcoded
// `const goBin = "/opt/homebrew/bin/go"` — the macOS Homebrew path — with no
// lookup of any kind. That works on the dev machine and is an instant ENOENT on
// a Linux runner, so the `interop` workflow had been RED for several phases:
//
//     FAIL: could not build sigild: spawnSync /opt/homebrew/bin/go ENOENT
//
// Only `accounts-interop.mjs` had a fallback, which is exactly why the accounts
// job was the one that passed while its neighbours failed.
//
// This is the third appearance of the same defect. `desktop/core/tests/
// server_interop.rs` solved it properly with `resolve_go()` ($GO → PATH →
// Homebrew, PANICKING rather than skipping) and CLAUDE.md calls that "the
// pattern"; `web/apps/webapp/tests/cors.spec.ts` was missing the PATH lookup and
// silently `test.skip`ped itself in CI (worse — a green job proving nothing).
// The pattern was written down but never made reusable, so every new suite
// re-derived it and some got it wrong. Now there is one implementation.
//
// ⭐ IT THROWS, IT NEVER SKIPS. A suite that quietly stops running looks exactly
// like a suite that passes, which is this repository's single recurring defect
// class (see docs/engineering-lessons.md).
//
// Named `*-helper.mjs` deliberately: scripts/gate.sh's runner loop, its CI-drift
// check and its inventory count all skip that suffix, so this file is not
// mistaken for a test.

import { existsSync } from "node:fs";
import { delimiter, join } from "node:path";

/**
 * Candidate Go binaries, in the order the rest of the repo uses:
 *   1. $GO             — explicit override; what interop.yml sets (`GO: go`).
 *   2. PATH            — what actions/setup-go provides. `setup-go` puts `go` on
 *                        PATH and NEVER sets $GO, which is why an earlier "fix"
 *                        that only added setup-go to a job did not work.
 *   3. /usr/local/go   — the stock Linux tarball location.
 *   4. /opt/homebrew   — this macOS dev machine.
 */
function* candidates() {
  if (process.env.GO) yield process.env.GO;
  for (const dir of (process.env.PATH ?? "").split(delimiter)) {
    if (dir) yield join(dir, "go");
  }
  yield "/usr/local/go/bin/go";
  yield "/opt/homebrew/bin/go";
}

/**
 * Absolute path to a usable Go binary.
 *
 * @throws if no Go toolchain exists. Callers must NOT catch this into a skip.
 */
export function resolveGo() {
  for (const c of candidates()) {
    if (existsSync(c)) return c;
  }
  throw new Error(
    "no Go toolchain found. Set $GO, or put `go` on PATH.\n" +
      "  This suite builds a REAL sigild and cannot be run without one — and it\n" +
      "  deliberately fails rather than skipping, because a skipped suite reads\n" +
      "  green while proving nothing.",
  );
}

/**
 * The toolchain PATH these suites run subprocesses with. Prepends the dev
 * machine's rustup/cargo/Homebrew directories, then keeps the inherited PATH —
 * so a Linux runner still finds everything actions/setup-* installed.
 */
export function toolPath() {
  return [
    `${process.env.HOME}/.rustup/toolchains/stable-aarch64-apple-darwin/bin`,
    `${process.env.HOME}/.cargo/bin`,
    "/opt/homebrew/bin",
    process.env.PATH ?? "",
  ]
    .filter(Boolean)
    .join(delimiter);
}

/** `process.env` with {@link toolPath} applied. */
export function toolEnv() {
  return { ...process.env, PATH: toolPath() };
}
