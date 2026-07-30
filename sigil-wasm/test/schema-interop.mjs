// schema-interop.mjs — Phase 59. The ONLY automated guard on TWO Rust <-> JS
// mirrors that were, until now, silently lossy:
//
//   1. THE VAULT SCHEMA (cli/src/lib.rs::TotpVault/TotpEntry  <->
//      sigil-wasm/totp-vault.mjs). Neither side used to preserve fields it did
//      not know: serde DROPPED them, and the JS clients rebuilt `{version,
//      entries}` by hand. So an OLD client that merely opened and re-sealed a
//      vault DELETED a newer client's data — on a sync path where the oldest
//      writer wins. And `version !== 1` was refused outright, which made every
//      future addition a four-client flag day.
//
//   2. THE MIGRATION BATCH FRAMING (cli/src/migration.rs <->
//      sigil-wasm/totp-migration.mjs). Google Authenticator splits a large
//      export across several QR codes; both codecs consumed `batch_size` /
//      `batch_index` / `batch_id` and threw them away, so importing the first QR
//      of a three-QR export imported a THIRD of the accounts and reported plain
//      success.
//
// A mirror that drifts does NOT fail loudly — it just quietly loses data. This
// test is the tripwire, and it uses the REAL `sigil` binary as the Rust half, so
// nothing here can be true of a re-implementation and false of the product.
//
// It needs NO server: everything is local containers and local URIs.
//
// Usage:  node sigil-wasm/test/schema-interop.mjs      (prints PASS, exits 0)

import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import * as wasm from "../pkg-node/sigil_wasm.js";
import {
  openVault,
  sealVault,
  addEntry,
  cloneVault,
  checkVaultReadable,
  formatEntryUuid,
  bytesToBase64,
  base64ToBytes,
  containerParams,
  ratchetParams,
  TOTP_VAULT_READER_VERSION,
} from "../totp-vault.mjs";
import { decodeMigrationUri, encodeMigrationUri } from "../totp-migration.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = join(HERE, "..", "..");
const PASSWORD = "correct horse battery staple";
// Fast Argon2 params so the seals are instant (m_cost >= 8 * p_cost). Well
// inside the Phase 59 ceilings, which is itself part of the point.
const ARGON2 = { m_cost: 8, t_cost: 1, p_cost: 1 };

function assert(cond, msg) {
  if (!cond) throw new Error(`ASSERTION FAILED: ${msg}`);
}

const work = mkdtempSync(join(tmpdir(), "sigil-schema-interop-"));
let sigilBin;

function sigil(args, opts = {}) {
  return execFileSync(sigilBin, args, {
    encoding: "utf8",
    env: { ...process.env, SIGIL_PASSWORD: PASSWORD },
    ...opts,
  });
}

/** Run the CLI expecting FAILURE; return its combined output. */
function sigilFails(args) {
  try {
    execFileSync(sigilBin, args, {
      encoding: "utf8",
      stdio: "pipe",
      env: { ...process.env, SIGIL_PASSWORD: PASSWORD },
    });
  } catch (e) {
    return `${e.stdout ?? ""}${e.stderr ?? ""}`;
  }
  throw new Error(`expected \`sigil ${args.join(" ")}\` to fail, but it succeeded`);
}

/** Seal arbitrary bytes into a SIGILcli container using the REAL CLI. */
function cliSeal(plaintextPath, outPath) {
  sigil(["seal", "--in", plaintextPath, "--out", outPath]);
}

// A minimal, INDEPENDENT proto3 writer — deliberately NOT the module under test,
// so a bug in the codec cannot also produce the fixture that hides it.
function varint(n) {
  const out = [];
  let v = BigInt(n);
  do {
    let b = Number(v & 0x7fn);
    v >>= 7n;
    if (v > 0n) b |= 0x80;
    out.push(b);
  } while (v > 0n);
  return out;
}
function lenField(field, bytes) {
  return [...varint((field << 3) | 2), ...varint(bytes.length), ...bytes];
}
function varintField(field, n) {
  return [...varint(field << 3), ...varint(n)];
}
/** One QR of a multi-QR Google Authenticator export. */
function multiQrUri(accounts, { size, index, id }) {
  const body = [];
  for (const a of accounts) {
    const otp = [
      ...lenField(1, [...new TextEncoder().encode(a.secret)]),
      ...lenField(2, [...new TextEncoder().encode(a.name)]),
      ...lenField(3, [...new TextEncoder().encode("Svc")]),
      ...varintField(4, 1), // SHA1
      ...varintField(5, 1), // SIX
      ...varintField(6, 2), // TOTP
    ];
    body.push(...lenField(1, otp));
  }
  body.push(...varintField(2, 1)); // version
  body.push(...varintField(3, size)); // batch_size
  body.push(...varintField(4, index)); // batch_index
  body.push(...varintField(5, id)); // batch_id
  const b64 = Buffer.from(Uint8Array.from(body)).toString("base64");
  return `otpauth-migration://offline?data=${encodeURIComponent(b64)}`;
}

try {
  console.log("building the sigil CLI (cargo build --bin sigil) ...");
  execFileSync(
    "cargo",
    ["build", "--manifest-path", join(REPO, "cli", "Cargo.toml"), "--bin", "sigil"],
    { stdio: "inherit" },
  );
  sigilBin = join(REPO, "cli", "target", "debug", "sigil");

  // =====================================================================
  // PROOF 1 — RUST WRITES AN UNKNOWN FIELD, JS PRESERVES IT
  //
  // Stand in for a FUTURE client by sealing a vault JSON that carries fields
  // neither side knows, using the REAL CLI's own container writer. Then have JS
  // open it, EDIT it (the operation that used to destroy the data), and re-seal.
  // =====================================================================
  const futureJson = {
    version: 1,
    entries: [
      {
        label: "acct",
        issuer: "Svc",
        secret: bytesToBase64(new TextEncoder().encode("1234567890")),
        algorithm: "sha1",
        digits: 6,
        period: 30,
        uuid: "11111111-2222-4333-8444-555555555555",
        // Fields a FUTURE Sigil writes and today's build knows nothing about:
        icon: "github",
        tags: ["work", "critical"],
      },
    ],
    vault_name: "work",
    future_object: { nested: [1, 2, 3] },
  };
  const plain = join(work, "future.json");
  const container = join(work, "future.sigil");
  writeFileSync(plain, JSON.stringify(futureJson));
  cliSeal(plain, container);

  // JS opens it, adds an account, and re-seals.
  let v = openVault(wasm, PASSWORD, new Uint8Array(readFileSync(container)));
  assert(v.vault_name === "work", "JS lost the unknown top-level field on open");
  assert(v.entries[0].icon === "github", "JS lost the unknown ENTRY field on open");

  const draft = cloneVault(v);
  addEntry(draft, {
    label: "added-by-js",
    secretBytes: new TextEncoder().encode("0123456789"),
    algorithm: "sha1",
    digits: 6,
    period: 30,
  });
  const salt = crypto.getRandomValues(new Uint8Array(wasm.recommended_salt_len()));
  const nonce = crypto.getRandomValues(new Uint8Array(wasm.nonce_len()));
  const afterJs = sealVault(wasm, PASSWORD, draft, salt, nonce, ARGON2);
  const jsSealed = join(work, "after-js.sigil");
  writeFileSync(jsSealed, Buffer.from(afterJs));

  // The REAL CLI must read that vault…
  const listed = sigil(["totp", "list", "--vault", jsSealed]);
  assert(listed.includes("acct"), `CLI cannot see the original entry: ${listed}`);
  assert(listed.includes("added-by-js"), `CLI cannot see the JS-added entry: ${listed}`);
  console.log("  PROOF 1a OK: JS opened a vault with unknown fields, edited it, CLI reads it");

  // =====================================================================
  // PROOF 2 — RUST EDITS IT TOO, AND STILL PRESERVES THE UNKNOWN FIELDS
  //
  // This is the half serde used to destroy: `sigil totp add` deserializes into
  // TotpVault, mutates, and re-serializes. Without #[serde(flatten)] every
  // unknown field is gone at this point.
  // =====================================================================
  sigil([
    "totp", "add", "added-by-cli",
    "--secret", "GEZDGNBVGY3TQOJQ",
    "--vault", jsSealed,
  ]);

  v = openVault(wasm, PASSWORD, new Uint8Array(readFileSync(jsSealed)));
  assert(v.vault_name === "work", "RUST dropped the unknown top-level field on re-seal");
  assert(
    JSON.stringify(v.future_object) === JSON.stringify({ nested: [1, 2, 3] }),
    "RUST mangled a nested unknown top-level field",
  );
  const acct = v.entries.find((e) => e.label === "acct");
  assert(acct, "the original entry disappeared");
  assert(acct.icon === "github", "RUST dropped the unknown ENTRY field on re-seal");
  assert(
    JSON.stringify(acct.tags) === JSON.stringify(["work", "critical"]),
    "RUST mangled the unknown ENTRY array field",
  );
  assert(
    acct.uuid === "11111111-2222-4333-8444-555555555555",
    "RUST did not keep the stable entry uuid",
  );
  console.log(
    "  PROOF 2  OK: `sigil totp add` round-tripped a vault written by a NEWER client " +
      "without losing one unknown field, at vault OR entry level",
  );

  // =====================================================================
  // PROOF 3 — THE STABLE ENTRY UUID EXISTS ON BOTH SIDES AND AGREES
  // =====================================================================
  const cliAdded = v.entries.find((e) => e.label === "added-by-cli");
  const jsAdded = v.entries.find((e) => e.label === "added-by-js");
  const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  assert(UUID_RE.test(cliAdded.uuid), `CLI-added entry has no v4 uuid: ${cliAdded.uuid}`);
  assert(UUID_RE.test(jsAdded.uuid), `JS-added entry has no v4 uuid: ${jsAdded.uuid}`);
  assert(cliAdded.uuid !== jsAdded.uuid, "two entries must not share an id");
  // The FORMATTER is a pure function of caller-supplied bytes on both sides, so
  // it has one shared vector. (Rust: cli/src/lib.rs::format_entry_uuid.)
  assert(
    formatEntryUuid(new Uint8Array(16).fill(0xff)) === "ffffffff-ffff-4fff-bfff-ffffffffffff",
    "the JS uuid formatter drifted from the Rust one",
  );
  console.log("  PROOF 3  OK: both sides mint RFC 4122 v4 entry ids, and the formatter agrees");

  // =====================================================================
  // PROOF 4 — min_reader_version REFUSES PRECISELY, ON BOTH SIDES
  //
  // Purely-additive future vault (version 2, min_reader_version 1) must OPEN;
  // an incompatible one (min_reader_version 2) must be REFUSED by both.
  // =====================================================================
  const additive = { ...futureJson, version: 2, min_reader_version: 1 };
  const addPlain = join(work, "additive.json");
  const addCont = join(work, "additive.sigil");
  writeFileSync(addPlain, JSON.stringify(additive));
  cliSeal(addPlain, addCont);
  const addOpened = openVault(wasm, PASSWORD, new Uint8Array(readFileSync(addCont)));
  assert(addOpened.version === 2, "additive vault should report version 2");
  const addList = sigil(["totp", "list", "--vault", addCont]);
  assert(addList.includes("acct"), `CLI refused a purely-additive v2 vault: ${addList}`);

  const breaking = { ...futureJson, version: 2, min_reader_version: 2 };
  const brkPlain = join(work, "breaking.json");
  const brkCont = join(work, "breaking.sigil");
  writeFileSync(brkPlain, JSON.stringify(breaking));
  cliSeal(brkPlain, brkCont);
  let jsRefused = null;
  try {
    openVault(wasm, PASSWORD, new Uint8Array(readFileSync(brkCont)));
  } catch (e) {
    jsRefused = e.message;
  }
  assert(jsRefused !== null, "JS opened a vault demanding a reader it does not have");
  assert(jsRefused.includes("version 2"), `JS refusal must NAME the version: ${jsRefused}`);
  const cliRefusal = sigilFails(["totp", "list", "--vault", brkCont]);
  assert(
    cliRefusal.includes("schema version 2"),
    `CLI refusal must NAME the version: ${cliRefusal}`,
  );
  // FAIL CLOSED: a future vault that never states min_reader_version is refused
  // by both, exactly as the old blanket equality check did.
  const silent = { ...futureJson, version: 2 };
  const silPlain = join(work, "silent.json");
  const silCont = join(work, "silent.sigil");
  writeFileSync(silPlain, JSON.stringify(silent));
  cliSeal(silPlain, silCont);
  let silentRefused = false;
  try {
    openVault(wasm, PASSWORD, new Uint8Array(readFileSync(silCont)));
  } catch {
    silentRefused = true;
  }
  assert(silentRefused, "an un-annotated future vault must FAIL CLOSED in JS");
  sigilFails(["totp", "list", "--vault", silCont]);
  assert(TOTP_VAULT_READER_VERSION === 1, "reader version constant drifted");
  checkVaultReadable({ version: 1, entries: [] }); // today's vault still opens
  console.log(
    "  PROOF 4  OK: min_reader_version lets an ADDITIVE v2 vault open on both sides, " +
      "refuses an incompatible one precisely on both sides, and fails CLOSED when unstated",
  );

  // =====================================================================
  // PROOF 5 — A MULTI-QR EXPORT IS NEVER REPORTED AS A WHOLE IMPORT
  // =====================================================================
  const qr1 = multiQrUri([{ secret: "1234567890", name: "batched-a" }], {
    size: 3,
    index: 0,
    id: 77,
  });

  // JS side.
  const batch = decodeMigrationUri(qr1);
  assert(batch.entries.length === 1, "batch 1 should carry its one account");
  assert(batch.batchSize === 3, `batch_size must be decoded, got ${batch.batchSize}`);
  assert(batch.batchIndex === 0, `batch_index must be decoded, got ${batch.batchIndex}`);
  assert(batch.batchId === 77, `batch_id must be decoded, got ${batch.batchId}`);
  assert(batch.complete === false, "a 1-of-3 batch must NOT read as complete");
  assert(batch.batchNote.includes("batch 1 of 3"), `JS note: ${batch.batchNote}`);
  assert(batch.batchNote.includes("PARTIAL"), `JS note: ${batch.batchNote}`);

  // Rust side — the REAL CLI, importing the SAME URI.
  const batchVault = join(work, "batched.sigil");
  const importOut = sigil(["totp", "import", qr1, "--vault", batchVault], {
    stdio: "pipe",
  });
  assert(importOut.includes("imported 1"), `CLI should still import: ${importOut}`);
  assert(
    importOut.includes("INCOMPLETE"),
    `CLI must not report a partial import as whole: ${importOut}`,
  );
  assert(importOut.includes("batch 1 of 3"), `CLI must say which batch: ${importOut}`);

  // …and a SINGLE-batch export stays quiet on both sides.
  const single = multiQrUri([{ secret: "1234567890", name: "single-a" }], {
    size: 1,
    index: 0,
    id: 5,
  });
  const singleBatch = decodeMigrationUri(single);
  assert(singleBatch.complete === true, "a 1-of-1 export must read as complete");
  assert(singleBatch.batchNote === null, "a single-QR export must not warn");
  const singleVault = join(work, "single.sigil");
  const singleOut = sigil(["totp", "import", single, "--vault", singleVault], { stdio: "pipe" });
  assert(!singleOut.includes("INCOMPLETE"), `single-QR import must stay quiet: ${singleOut}`);
  console.log(
    "  PROOF 5  OK: a 1-of-3 Google Authenticator batch is reported as PARTIAL by BOTH the " +
      "CLI and the JS codec (and a single-QR export is not)",
  );

  // =====================================================================
  // PROOF 6 — A MIGRATION EXPORT REFUSES TO LIE ABOUT THE PERIOD
  //
  // The wire format has no period field. Exporting a 60 s account as if it were
  // 30 s produces an entry that generates the WRONG codes in the receiving app.
  // =====================================================================
  const oddVault = join(work, "odd-period.sigil");
  sigil([
    "totp", "add", "sixty",
    "--secret", "GEZDGNBVGY3TQOJQ",
    "--period", "60",
    "--vault", oddVault,
  ]);
  const exportFail = sigilFails(["totp", "export", "--migration", "--vault", oddVault]);
  assert(exportFail.includes("60 s"), `CLI must name the period: ${exportFail}`);
  assert(exportFail.includes("WRONG codes"), `CLI must say why: ${exportFail}`);
  // …and the plain otpauth:// export, which CAN carry the period, still works.
  const plainExport = sigil(["totp", "export", "--vault", oddVault], { stdio: "pipe" });
  assert(plainExport.includes("period=60"), `otpauth export must carry it: ${plainExport}`);

  // JS side.
  let jsExportRefused = null;
  try {
    encodeMigrationUri([
      {
        label: "sixty",
        secret: bytesToBase64(new TextEncoder().encode("1234567890")),
        algorithm: "sha1",
        digits: 6,
        period: 60,
      },
    ]);
  } catch (e) {
    jsExportRefused = e.message;
  }
  assert(jsExportRefused !== null, "JS silently exported a non-30 s period");
  assert(jsExportRefused.includes("60 s"), `JS must name the period: ${jsExportRefused}`);
  // The standard 30 s period still exports on both sides.
  const ok30 = encodeMigrationUri([
    {
      label: "thirty",
      secret: bytesToBase64(new TextEncoder().encode("1234567890")),
      algorithm: "sha1",
      digits: 6,
      period: 30,
    },
  ]);
  assert(decodeMigrationUri(ok30).entries.length === 1, "a 30 s entry must still export");
  console.log(
    "  PROOF 6  OK: both the CLI and the JS codec REFUSE a migration export whose period " +
      "the format cannot carry, and point at the otpauth:// export that can",
  );

  // =====================================================================
  // PROOF 7 — A HOSTILE ARGON2 HEADER IS REFUSED, NOT ALLOCATED
  //
  // Same container, same ceilings, both sides. `m_cost = 0xFFFF_FFF0` is ~4 TiB;
  // the header is unauthenticated, and containers arrive through sigild's
  // zero-knowledge relay, which cannot filter them.
  // =====================================================================
  const good = new Uint8Array(readFileSync(jsSealed));
  const hostile = Uint8Array.from(good);
  new DataView(hostile.buffer, hostile.byteOffset).setUint32(9, 0xfffffff0, true);
  let jsHostile = null;
  try {
    wasm.open_container(new TextEncoder().encode(PASSWORD), hostile);
  } catch (e) {
    jsHostile = e.message;
  }
  assert(jsHostile !== null, "the wasm accepted a 4 TiB Argon2 header");
  assert(jsHostile.includes("Nothing was allocated"), `wasm message: ${jsHostile}`);
  const hostilePath = join(work, "hostile.sigil");
  writeFileSync(hostilePath, Buffer.from(hostile));
  const cliHostile = sigilFails(["totp", "list", "--vault", hostilePath]);
  assert(
    cliHostile.includes("Nothing was allocated"),
    `CLI must refuse the hostile header: ${cliHostile}`,
  );
  // …and the untouched container still opens on both sides.
  assert(
    openVault(wasm, PASSWORD, good).entries.length >= 2,
    "a normal container must still open",
  );
  assert(base64ToBytes(bytesToBase64(good)).length === good.length, "base64 helpers intact");
  console.log(
    "  PROOF 7  OK: a container demanding ~4 TiB of Argon2 memory is refused at PARSE time " +
      "by BOTH the CLI and the wasm, with nothing allocated, while a normal one still opens",
  );

  // =====================================================================
  // PROOF 8 — THE LAST QR OF A MULTI-QR EXPORT DOES NOT CRY WOLF
  //
  // Importing batch 2 of 2 used to print "and 0 more QR code(s) must be
  // imported … This import is PARTIAL", then "THIS IMPORT IS INCOMPLETE" — to a
  // user who had just finished. A false alarm is how a real one gets ignored.
  // The note must still SAY which batch it was (no client keeps cross-run
  // state), but must not claim anything is outstanding.
  // =====================================================================
  const lastQr = multiQrUri([{ secret: "1234567890", name: "batched-last" }], {
    size: 2,
    index: 1,
    id: 88,
  });
  const lastBatch = decodeMigrationUri(lastQr);
  assert(lastBatch.finalBatch === true, "batch 2 of 2 must read as the FINAL batch");
  assert(lastBatch.complete === false, "…but it is still not the whole export on its own");
  assert(lastBatch.batchNote.includes("batch 2 of 2"), `JS note: ${lastBatch.batchNote}`);
  assert(lastBatch.batchNote.includes("LAST QR code"), `JS note: ${lastBatch.batchNote}`);
  assert(!lastBatch.batchNote.includes("PARTIAL"), `JS still cries wolf: ${lastBatch.batchNote}`);
  assert(!lastBatch.batchNote.includes("0 more QR"), `JS still cries wolf: ${lastBatch.batchNote}`);
  // …and the FIRST batch of the same export is STILL loud.
  const firstQr = multiQrUri([{ secret: "1234567890", name: "batched-first" }], {
    size: 2,
    index: 0,
    id: 88,
  });
  const firstBatch = decodeMigrationUri(firstQr);
  assert(firstBatch.finalBatch === false, "batch 1 of 2 is not final");
  assert(firstBatch.batchNote.includes("PARTIAL"), `JS note: ${firstBatch.batchNote}`);

  // Rust side — the REAL CLI, same two URIs.
  const lastVault = join(work, "batched-last.sigil");
  const lastOut = sigil(["totp", "import", lastQr, "--vault", lastVault], { stdio: "pipe" });
  assert(lastOut.includes("imported 1"), `CLI should import: ${lastOut}`);
  assert(lastOut.includes("batch 2 of 2"), `CLI must still name the batch: ${lastOut}`);
  assert(
    !lastOut.includes("INCOMPLETE"),
    `CLI told a finished user their import was incomplete: ${lastOut}`,
  );
  assert(!lastOut.includes("PARTIAL"), `CLI still cries wolf: ${lastOut}`);
  const firstVault = join(work, "batched-first.sigil");
  const firstOut = sigil(["totp", "import", firstQr, "--vault", firstVault], { stdio: "pipe" });
  assert(
    firstOut.includes("INCOMPLETE"),
    `a genuinely partial import must STAY loud: ${firstOut}`,
  );
  console.log(
    "  PROOF 8  OK: the FINAL QR of a multi-QR export is reported truthfully (named, but not " +
      "called incomplete) by both the CLI and the JS codec, while a genuinely outstanding " +
      "batch is still loud on both",
  );

  // =====================================================================
  // PROOF 9 — ONE UNSUPPORTED ACCOUNT DOES NOT COST THE WHOLE BULK EXPORT
  //
  // Refusal stays the DEFAULT (a silently partial 2FA export is worse than a
  // failed one), but `--skip-unsupported` is an explicit, itemised opt-in.
  // =====================================================================
  const mixedVault = join(work, "mixed-export.sigil");
  sigil(["totp", "add", "normal", "--secret", "GEZDGNBVGY3TQOJQ", "--vault", mixedVault]);
  sigil([
    "totp", "add", "oddball",
    "--secret", "GEZDGNBVGY3TQOJQ",
    "--period", "60",
    "--vault", mixedVault,
  ]);
  // DEFAULT: refuse, and NAME the offender rather than making the user hunt.
  const refused = sigilFails(["totp", "export", "--migration", "--vault", mixedVault]);
  assert(refused.includes("REFUSED"), `default must refuse: ${refused}`);
  assert(refused.includes("oddball"), `it must name the entry: ${refused}`);
  assert(refused.includes("--skip-unsupported"), `it must offer the way out: ${refused}`);
  // OPT-IN: the rest exports, and what was dropped is named LOUDLY on stderr.
  const skipOut = execFileSync(
    sigilBin,
    ["totp", "export", "--migration", "--skip-unsupported", "--vault", mixedVault],
    { encoding: "utf8", env: { ...process.env, SIGIL_PASSWORD: PASSWORD } },
  );
  const skipUri = skipOut.trim().split("\n").filter((l) => l.startsWith("otpauth-migration://"));
  assert(skipUri.length === 1, `expected one migration URI, got: ${skipOut}`);
  const skipped = decodeMigrationUri(skipUri[0]);
  assert(skipped.entries.length === 1, `only the exportable entry should be in it`);
  assert(skipped.entries[0].label.includes("normal"), `wrong entry: ${skipped.entries[0].label}`);
  // The warning goes to STDERR (so it survives `> backup.txt`), not stdout.
  let skipErr = "";
  try {
    execFileSync(
      sigilBin,
      ["totp", "export", "--migration", "--skip-unsupported", "--vault", mixedVault],
      { encoding: "utf8", stdio: ["pipe", "pipe", "pipe"], env: { ...process.env, SIGIL_PASSWORD: PASSWORD } },
    );
  } catch {
    /* unreachable: it succeeds */
  }
  skipErr = execFileSync(
    "/bin/sh",
    ["-c", `${JSON.stringify(sigilBin)} totp export --migration --skip-unsupported --vault ${JSON.stringify(mixedVault)} 2>&1 >/dev/null`],
    { encoding: "utf8", env: { ...process.env, SIGIL_PASSWORD: PASSWORD } },
  );
  assert(skipErr.includes("oddball"), `stderr must name what was skipped: ${skipErr}`);
  assert(skipErr.includes("THIS EXPORT IS PARTIAL"), `stderr must be loud: ${skipErr}`);
  // …and the flag is refused where it would be meaningless.
  const misuse = sigilFails(["totp", "export", "--skip-unsupported", "--vault", mixedVault]);
  assert(misuse.includes("only applies"), `misuse must be caught: ${misuse}`);
  console.log(
    "  PROOF 9  OK: `--migration` still REFUSES by default and names the offending entry, " +
      "and `--skip-unsupported` exports the rest while itemising what it left out on stderr",
  );

  // =====================================================================
  // PROOF 10 — THE NO-DOWNGRADE RATCHET IS THE SAME RULE IN RUST AND JS
  //
  // Every JS re-seal used to write a hardcoded 19456/2/1, so ONE browser edit of
  // a CLI-written 65536/4/2 vault cut its memory cost by 3.4x, silently. The
  // rule now lives in sigil-core and is reached from JS through the wasm, so the
  // two cannot drift.
  // =====================================================================
  const strongPlain = join(work, "strong.json");
  const strongCont = join(work, "strong.sigil");
  writeFileSync(strongPlain, JSON.stringify({ version: 1, entries: [] }));
  // The CLI seals at its own RECOMMENDED parameters (65536/4/2).
  cliSeal(strongPlain, strongCont);
  const strongBytes = new Uint8Array(readFileSync(strongCont));
  const declared = containerParams(wasm, strongBytes);
  assert(declared.m_cost === 65536, `CLI should write 65536, got ${declared.m_cost}`);
  // A browser whose defaults are WEAKER must re-seal at the STRONGER header.
  const browserDefaults = { m_cost: 19456, t_cost: 2, p_cost: 1 };
  const ratcheted = ratchetParams(wasm, strongBytes, browserDefaults);
  assert(
    ratcheted.m_cost === 65536 && ratcheted.t_cost === 4 && ratcheted.p_cost === 2,
    `a browser edit downgraded a CLI vault: ${JSON.stringify(ratcheted)}`,
  );
  // …and the other direction: a deliberately WEAK container is RAISED.
  const weakCont = join(work, "weak.sigil");
  writeFileSync(
    weakCont,
    Buffer.from(
      sealVault(wasm, PASSWORD, { version: 1, entries: [] },
        new Uint8Array(wasm.recommended_salt_len()),
        new Uint8Array(wasm.nonce_len()),
        { m_cost: 8, t_cost: 1, p_cost: 1 }),
    ),
  );
  const raised = ratchetParams(wasm, new Uint8Array(readFileSync(weakCont)), browserDefaults);
  assert(
    raised.m_cost === 19456 && raised.t_cost === 2 && raised.p_cost === 1,
    `a weak container must be RAISED, not preserved: ${JSON.stringify(raised)}`,
  );
  // No existing container (a first seal) -> the client's own defaults, unchanged.
  assert(
    JSON.stringify(ratchetParams(wasm, null, browserDefaults)) === JSON.stringify(browserDefaults),
    "a first seal must use the client's own params",
  );
  // ⭐ The RUST side agrees, proven against the REAL binary: `sigil vault rekey`
  // re-seals the vault and must not weaken it either.
  const rekeyVault = join(work, "rekey.sigil");
  sigil(["totp", "add", "ratchet", "--secret", "GEZDGNBVGY3TQOJQ", "--vault", rekeyVault]);
  const beforeRekey = containerParams(wasm, new Uint8Array(readFileSync(rekeyVault)));
  const keyring = join(work, "rekey-keys.json");
  sigil(["vault", "rekey", "--vault", "ratchet-vault", "--file", rekeyVault, "--keyring", keyring]);
  const afterRekey = containerParams(wasm, new Uint8Array(readFileSync(rekeyVault)));
  assert(
    afterRekey.m_cost >= beforeRekey.m_cost &&
      afterRekey.t_cost >= beforeRekey.t_cost &&
      afterRekey.p_cost >= beforeRekey.p_cost,
    `the CLI weakened a container on rekey: ${JSON.stringify(beforeRekey)} -> ${JSON.stringify(afterRekey)}`,
  );
  console.log(
    "  PROOF 10 OK: the JS ratchet keeps a CLI-written 65536/4/2 header intact through a " +
      "browser-strength re-seal, RAISES a weak one, and agrees with the real CLI's own rekey",
  );

  console.log(
    "\nPASS: the vault schema and the migration batch framing agree across Rust and JS — " +
      "unknown fields survive an edit on BOTH sides, min_reader_version refuses precisely " +
      "and fails closed, entry uuids are minted and stable, a multi-QR import is reported " +
      "as PARTIAL, an unrepresentable period is refused rather than exported as a lie, and " +
      "a hostile Argon2 header is refused before any allocation, the FINAL QR of a multi-QR " +
      "export is not called incomplete, one unsupported account no longer costs the whole " +
      "bulk export, and no JS re-seal can write a weaker Argon2 header than it read",
  );
} finally {
  rmSync(work, { recursive: true, force: true });
}
