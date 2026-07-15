// migration-interop.mjs — the CROSS-TOOL AGREEMENT proof for TOTP import/export:
// the browser/JS codec (totp-migration.mjs) and the Rust CLI codec
// (cli/src/migration.rs) speak the SAME Google Authenticator
// `otpauth-migration://` wire format, proven BOTH ways.
//
// No sigild / network here — this is a pure codec-agreement test between the two
// hand-rolled protobuf implementations. It builds the `sigil` CLI, then proves:
//
//   GOLDEN   the canonical Google Authenticator example URI decodes in JS to the
//            documented account (secret JBSWY3DPEHPK3PXP, name
//            "Example:alice@google.com", issuer "Example", sha1, 6 digits) — the
//            SAME golden vector the CLI's own Rust test asserts.
//   RUST->JS the CLI seals a couple of accounts and `totp export --migration`s
//            them; the JS codec decodes that URI and the accounts match what the
//            CLI stored (names/algorithms/digits + each secret base32 equals the
//            CLI's own otpauth export).
//   JS->RUST the JS codec encodes accounts into a migration URI; `sigil totp
//            import` accepts it into a fresh vault and `totp list` + the CLI's
//            otpauth export confirm the accounts + secrets arrived intact.
//
// Pre-audit / UNAUDITED / DEV. Do NOT handle real 2FA secrets. Usage:
// `node test/migration-interop.mjs`. Exits 0 with a PASS line, non-zero on any
// mismatch. Always builds the CLI fresh; always cleans temp files.

import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { execFileSync } from "node:child_process";

import {
  decodeMigrationUri,
  encodeMigrationUri,
  parseOtpauthUri,
  base32Encode,
} from "../totp-migration.mjs";
import { base64ToBytes } from "../totp-vault.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(__dirname, "..", "..");
const cliManifest = join(repoRoot, "cli", "Cargo.toml");
const cliBinary = join(repoRoot, "cli", "target", "debug", "sigil");

function fail(msg) {
  console.error(`FAIL: ${msg}`);
  process.exit(1);
}
function assert(cond, msg) {
  if (!cond) fail(msg);
}

// Toolchain PATH exactly like the rest of the repo (macOS arm64).
const toolPath = [
  `${process.env.HOME}/.rustup/toolchains/stable-aarch64-apple-darwin/bin`,
  `${process.env.HOME}/.cargo/bin`,
  "/opt/homebrew/bin",
  process.env.PATH ?? "",
].join(":");
const toolEnv = { ...process.env, PATH: toolPath };

const PASSWORD = "correct horse battery staple";

// Run the CLI with SIGIL_PASSWORD set; return stdout (warnings go to stderr).
function sigil(args) {
  return execFileSync(cliBinary, args, {
    env: { ...process.env, SIGIL_PASSWORD: PASSWORD },
    encoding: "utf8",
  });
}

// --- Build the CLI. ---
console.log("building the sigil CLI (cargo build --bin sigil) ...");
try {
  execFileSync("cargo", ["build", "--manifest-path", cliManifest, "--bin", "sigil"], {
    stdio: "inherit",
    env: toolEnv,
  });
} catch (e) {
  fail(`could not build the sigil CLI: ${e.message}`);
}
assert(existsSync(cliBinary), `built CLI binary not found at ${cliBinary}`);

const work = mkdtempSync(join(tmpdir(), "sigil-migration-interop-"));

try {
  // =====================================================================
  // GOLDEN — the canonical Google Authenticator example decodes in JS.
  // =====================================================================
  const GOLDEN =
    "otpauth-migration://offline?data=CjUKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZSABKAEwAhAB";
  const golden = decodeMigrationUri(GOLDEN);
  assert(golden.length === 1, `golden should decode to 1 account, got ${golden.length}`);
  const g = golden[0];
  assert(
    base32Encode(base64ToBytes(g.secret)) === "JBSWY3DPEHPK3PXP",
    `golden secret base32 mismatch: ${base32Encode(base64ToBytes(g.secret))}`,
  );
  assert(g.label === "Example:alice@google.com", `golden name mismatch: ${g.label}`);
  assert(g.issuer === "Example", `golden issuer mismatch: ${g.issuer}`);
  assert(g.algorithm === "sha1", `golden algorithm mismatch: ${g.algorithm}`);
  assert(g.digits === 6, `golden digits mismatch: ${g.digits}`);
  console.log(
    "  GOLDEN   OK: JS decodes the canonical GA example -> JBSWY3DPEHPK3PXP / " +
      '"Example:alice@google.com" / issuer Example / sha1 / 6 digits',
  );

  // =====================================================================
  // RUST -> JS — CLI seals accounts, exports migration URI, JS decodes it.
  // =====================================================================
  const rustVault = join(work, "rust.sigil");
  // acc-one: base32 GEZDGNBVGY3TQOJQ = raw "1234567890", sha1, 6 digits.
  // acc-two: base32 JBSWY3DPEHPK3PXP = raw "Hello!"+deadbeef, sha256, 8 digits.
  sigil(["totp", "add", "acc-one", "--secret", "GEZDGNBVGY3TQOJQ", "--vault", rustVault]);
  sigil([
    "totp", "add", "acc-two",
    "--secret", "JBSWY3DPEHPK3PXP",
    "--algorithm", "sha256",
    "--digits", "8",
    "--vault", rustVault,
  ]);

  const migrationUri = sigil(["totp", "export", "--migration", "--vault", rustVault]).trim();
  assert(
    migrationUri.startsWith("otpauth-migration://offline?data="),
    `CLI --migration export is not a migration URI: ${migrationUri.slice(0, 40)}`,
  );
  const decoded = decodeMigrationUri(migrationUri);
  assert(decoded.length === 2, `expected 2 decoded accounts, got ${decoded.length}`);

  const byLabel = Object.fromEntries(decoded.map((e) => [e.label, e]));
  assert(byLabel["acc-one"], "decoded migration is missing acc-one");
  assert(byLabel["acc-two"], "decoded migration is missing acc-two");
  assert(byLabel["acc-one"].algorithm === "sha1", "acc-one algorithm != sha1");
  assert(byLabel["acc-one"].digits === 6, "acc-one digits != 6");
  assert(byLabel["acc-two"].algorithm === "sha256", "acc-two algorithm != sha256");
  assert(byLabel["acc-two"].digits === 8, "acc-two digits != 8");

  // The decoded secrets must equal the SAME secrets the CLI's own otpauth export
  // emits (cross-checking the two Rust export paths against the JS decode).
  const otpauthLines = sigil(["totp", "export", "--vault", rustVault])
    .trim()
    .split("\n")
    .filter((l) => l.startsWith("otpauth://"));
  assert(otpauthLines.length === 2, `expected 2 otpauth lines, got ${otpauthLines.length}`);
  for (const line of otpauthLines) {
    const parsed = parseOtpauthUri(line);
    const fromMigration = byLabel[parsed.label];
    assert(fromMigration, `otpauth export has a label not in migration decode: ${parsed.label}`);
    const migB32 = base32Encode(base64ToBytes(fromMigration.secret));
    const otpB32 = base32Encode(base64ToBytes(parsed.secret));
    assert(
      migB32 === otpB32,
      `secret base32 mismatch for ${parsed.label}: migration ${migB32} vs otpauth ${otpB32}`,
    );
  }
  // And they are the exact base32 secrets we provisioned.
  assert(
    base32Encode(base64ToBytes(byLabel["acc-one"].secret)) === "GEZDGNBVGY3TQOJQ",
    "acc-one secret drifted from GEZDGNBVGY3TQOJQ",
  );
  assert(
    base32Encode(base64ToBytes(byLabel["acc-two"].secret)) === "JBSWY3DPEHPK3PXP",
    "acc-two secret drifted from JBSWY3DPEHPK3PXP",
  );
  console.log(
    "  RUST->JS OK: `sigil totp export --migration` -> JS decode matches all " +
      "names/algorithms/digits and every secret base32 (== the CLI otpauth export)",
  );

  // =====================================================================
  // JS -> RUST — JS encodes a migration URI, the CLI imports + confirms it.
  // =====================================================================
  // A JS-built account: raw RFC key "12345678901234567890" (base32
  // GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ), sha1, 8 digits, with an issuer.
  const rfcRaw = new TextEncoder().encode("12345678901234567890");
  const rfcB32 = base32Encode(rfcRaw); // GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
  const jsEntries = [
    {
      label: "js-imported",
      issuer: "JSTool",
      secret: Buffer.from(rfcRaw).toString("base64"),
      algorithm: "sha1",
      digits: 8,
      period: 30,
    },
    {
      label: "js-second",
      secret: Buffer.from(new TextEncoder().encode("Hello!")).toString("base64"),
      algorithm: "sha512",
      digits: 6,
      period: 30,
    },
  ];
  const jsMigrationUri = encodeMigrationUri(jsEntries);
  assert(
    jsMigrationUri.startsWith("otpauth-migration://offline?data="),
    "JS-built migration URI has the wrong scheme",
  );

  const jsVault = join(work, "js.sigil");
  const importOut = sigil(["totp", "import", jsMigrationUri, "--vault", jsVault]);
  assert(/imported 2 into/.test(importOut), `CLI did not import 2 accounts: ${importOut.trim()}`);

  const listOut = sigil(["totp", "list", "--vault", jsVault]);
  assert(/js-imported/.test(listOut), "CLI list is missing js-imported");
  assert(/js-second/.test(listOut), "CLI list is missing js-second");
  assert(
    /js-imported\s+issuer=JSTool\s+algorithm=sha1\s+digits=8/.test(listOut),
    `js-imported row wrong in CLI list:\n${listOut}`,
  );
  assert(
    /js-second\s+issuer=-\s+algorithm=sha512\s+digits=6/.test(listOut),
    `js-second row wrong in CLI list:\n${listOut}`,
  );

  // The CLI must have stored the EXACT secret bytes: its otpauth export of
  // js-imported must carry the RFC base32 secret.
  const jsOtpauth = sigil(["totp", "export", "js-imported", "--vault", jsVault])
    .trim()
    .split("\n")
    .find((l) => l.startsWith("otpauth://"));
  assert(jsOtpauth, "CLI otpauth export of js-imported produced no URI");
  const jsParsed = parseOtpauthUri(jsOtpauth);
  const jsStoredB32 = base32Encode(base64ToBytes(jsParsed.secret));
  assert(
    jsStoredB32 === rfcB32,
    `JS->CLI secret drifted: CLI stored ${jsStoredB32}, expected ${rfcB32}`,
  );
  console.log(
    "  JS->RUST OK: JS `encodeMigrationUri` -> `sigil totp import` -> `totp list` " +
      "shows both accounts and the CLI's stored secret base32 matches the JS input",
  );
} finally {
  rmSync(work, { recursive: true, force: true });
}

console.log(
  "\nPASS: cross-tool TOTP migration agreement proven THREE ways — GOLDEN GA " +
    "vector via JS; RUST->JS (`sigil totp export --migration` decodes in JS); and " +
    "JS->RUST (JS-encoded migration URI imports into the CLI) — the JS codec " +
    "(totp-migration.mjs) and the Rust codec (cli/src/migration.rs) are wire-compatible",
);
process.exit(0);
