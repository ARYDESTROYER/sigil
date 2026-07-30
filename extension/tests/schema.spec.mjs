// schema.spec.mjs — ⭐⭐ THE PROPERTY, PROVEN THROUGH THE REAL EXTENSION.
//
// ⛔ WHY THIS FILE EXISTS. Phase 59 taught four clients to preserve vault fields
// they do not understand, because the TotpVault schema is mirrored across the
// CLI, the webapp, this extension and the desktop app, and vaults sync through
// an op-log where the OLDEST writer wins: a client that rebuilt
// `{ version, entries }` by hand DELETED a newer client's data on its next push.
//
// The fix landed in two places — `totp-vault.mjs` (the library) and
// `src/popup/popup.js` (the product, which had to stop hand-rebuilding the
// object and call `cloneVault`). An independent verifier then REVERTED the
// product half:
//
//     const draft = { version: vault.version, entries: [...vault.entries] };
//
// ...verbatim the pre-Phase-59 shape, and the whole gate stayed green — 12
// extension specs, 46 webapp specs and the Rust<->JS schema interop all passed.
// Mutating the SAME logic inside `totp-vault.mjs` went red. So the MODULE was
// guarded and the PRODUCT was not, which is this repo's oldest failure mode
// wearing a new costume (docs/engineering-lessons.md).
//
// This spec closes that hole at the only level that can: it seeds a vault whose
// stored JSON carries fields no Sigil build has heard of, drives a REAL EDIT
// through the REAL popup, and then decrypts what the extension actually wrote.
//
// ⚠️ The seeding and the verification both happen in the TEST process, using the
// Node-target wasm (`sigil-wasm/pkg-node`, built by `build.sh` -> the repo-root
// `build-wasm.sh`, the same run that vendors the popup's own copy). The popup is
// a black box here: password in, sealed bytes out.
//
// Pre-audit / UNAUDITED / DEV.

import { test, expect, chromium } from "@playwright/test";
import { createHash } from "node:crypto";
import { mkdtemp, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import * as nodeWasm from "../../sigil-wasm/pkg-node/sigil_wasm.js";
import {
  openVault,
  sealVault,
  containerParams,
  bytesToBase64,
  base64ToBytes,
} from "../../sigil-wasm/totp-vault.mjs";

const EXT_DIR = path.dirname(fileURLToPath(new URL("../package.json", import.meta.url)));

const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PINNED_T = 59;
const RFC_CODE_6 = "287082";
const PASSWORD = "schema-spec-password";
const STORAGE_KEY = "sigil.extension.vault.v1";

// Fields NO Sigil build understands. They stand in for whatever a future client
// writes, and `min_reader_version` is a real Phase 59 field that must also ride
// through untouched.
const UNKNOWN_VAULT_FIELDS = {
  min_reader_version: 1,
  future_policy: { require_uv: true, max_age_days: 90 },
  written_by: "sigil-future/9.9.9",
};
const UNKNOWN_ENTRY_FIELDS = {
  notes_ref: "note-7f3a-not-a-secret",
  future_flags: ["alpha", "beta"],
};

async function extensionId() {
  const manifest = JSON.parse(await readFile(path.join(EXT_DIR, "manifest.json"), "utf8"));
  const der = Buffer.from(manifest.key, "base64");
  const hex = createHash("sha256").update(der).digest("hex").slice(0, 32);
  return [...hex].map((c) => String.fromCharCode(97 + parseInt(c, 16))).join("");
}

let context;
let id;

test.beforeAll(async () => {
  id = await extensionId();
  const userDataDir = await mkdtemp(path.join(tmpdir(), "sigil-ext-schema-"));
  context = await chromium.launchPersistentContext(userDataDir, {
    channel: "chromium",
    headless: true,
    args: [`--disable-extensions-except=${EXT_DIR}`, `--load-extension=${EXT_DIR}`],
  });
  context.__userDataDir = userDataDir;
});

test.afterAll(async () => {
  const dir = context?.__userDataDir;
  await context?.close();
  if (dir) await rm(dir, { recursive: true, force: true });
});

async function openPopup() {
  const page = await context.newPage();
  const failures = [];
  page.on("pageerror", (e) => failures.push(String(e)));
  await page.goto(`chrome-extension://${id}/src/popup/popup.html?t=${PINNED_T}`);
  await expect(page.locator("body")).toHaveAttribute("data-wasm", /.+/, { timeout: 30_000 });
  return { page, failures };
}

/** The exact bytes the extension has in chrome.storage.local. */
async function readStored(page) {
  const b64 = await page.evaluate(async (k) => (await chrome.storage.local.get(k))[k] ?? null, STORAGE_KEY);
  expect(b64, "the popup must have persisted a sealed vault").toBeTruthy();
  return base64ToBytes(b64);
}

async function writeStored(page, bytes) {
  await page.evaluate(
    async ([k, v]) => {
      await chrome.storage.local.set({ [k]: v });
    },
    [STORAGE_KEY, bytesToBase64(bytes)],
  );
}

/** Decrypt what the extension actually wrote, in the TEST process. */
function decrypt(container) {
  return openVault(nodeWasm, PASSWORD, container);
}

function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

async function unlock(page) {
  await page.getByTestId("unlock-password").fill(PASSWORD);
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("view-unlocked")).toBeVisible({ timeout: 30_000 });
}

test("⭐ an edit made through the REAL popup preserves vault fields this build does not understand", async () => {
  // ── a vault created by the real popup ────────────────────────────────────
  const first = await openPopup();
  await expect(first.page.getByTestId("view-setup")).toBeVisible();
  await first.page.getByTestId("setup-password").fill(PASSWORD);
  await first.page.getByTestId("setup-password-2").fill(PASSWORD);
  await first.page.getByTestId("setup-submit").click();
  await expect(first.page.getByTestId("view-unlocked")).toBeVisible({ timeout: 30_000 });

  await first.page.getByTestId("add-toggle").click();
  await first.page.getByTestId("add-label").fill("seeded");
  await first.page.getByTestId("add-secret").fill(RFC_SECRET);
  await first.page.getByTestId("add-submit").click();
  await expect(first.page.getByTestId("account")).toHaveCount(1);
  await expect(first.page.getByTestId("code")).toHaveText(RFC_CODE_6);

  // ── seed: graft unknown fields onto the popup's OWN sealed container ─────
  const original = await readStored(first.page);
  // Re-seal at the SAME work factors the popup chose, so this step cannot itself
  // move the header and muddy the ratchet assertions in the second spec.
  const params = containerParams(nodeWasm, original);
  const seeded = decrypt(original);
  expect(seeded.entries).toHaveLength(1);
  Object.assign(seeded, UNKNOWN_VAULT_FIELDS);
  Object.assign(seeded.entries[0], UNKNOWN_ENTRY_FIELDS);
  await writeStored(
    first.page,
    sealVault(
      nodeWasm,
      PASSWORD,
      seeded,
      randomBytes(nodeWasm.recommended_salt_len()),
      randomBytes(nodeWasm.nonce_len()),
      params,
    ),
  );
  expect(first.failures).toEqual([]);
  await first.page.close();

  // ── drive a REAL edit through the REAL popup ────────────────────────────
  const { page, failures } = await openPopup();
  await expect(page.getByTestId("view-locked")).toBeVisible();
  await unlock(page);
  // The popup must have OPENED the seeded vault (min_reader_version 1 is fine).
  await expect(page.getByTestId("account")).toHaveCount(1);

  await page.getByTestId("add-toggle").click();
  await page.getByTestId("add-label").fill("added-after-seeding");
  await page.getByTestId("add-secret").fill(RFC_SECRET);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account")).toHaveCount(2);

  // ── verify: decrypt what the POPUP wrote ────────────────────────────────
  const afterAdd = decrypt(await readStored(page));
  expect(afterAdd.entries).toHaveLength(2);

  // ⛔ THE MUTATION TARGET. Reverting `cloneVault(vault)` to
  // `{ version: vault.version, entries: [...vault.entries] }` in popup.js
  // deletes every one of these, and these expectations are what notice.
  expect(afterAdd.min_reader_version).toBe(UNKNOWN_VAULT_FIELDS.min_reader_version);
  expect(afterAdd.future_policy).toEqual(UNKNOWN_VAULT_FIELDS.future_policy);
  expect(afterAdd.written_by).toBe(UNKNOWN_VAULT_FIELDS.written_by);

  const seededEntry = afterAdd.entries.find((e) => e.label === "seeded");
  expect(seededEntry, "the seeded entry must still be there").toBeTruthy();
  expect(seededEntry.notes_ref).toBe(UNKNOWN_ENTRY_FIELDS.notes_ref);
  expect(seededEntry.future_flags).toEqual(UNKNOWN_ENTRY_FIELDS.future_flags);

  // ── and again through a REMOVAL, the other edit the popup offers ────────
  await page.locator('[data-label="added-after-seeding"] [data-testid="remove"]').click();
  await expect(page.getByTestId("account")).toHaveCount(1);
  const afterRemove = decrypt(await readStored(page));
  expect(afterRemove.min_reader_version).toBe(UNKNOWN_VAULT_FIELDS.min_reader_version);
  expect(afterRemove.future_policy).toEqual(UNKNOWN_VAULT_FIELDS.future_policy);
  expect(afterRemove.written_by).toBe(UNKNOWN_VAULT_FIELDS.written_by);
  expect(afterRemove.entries.find((e) => e.label === "seeded").notes_ref).toBe(
    UNKNOWN_ENTRY_FIELDS.notes_ref,
  );

  expect(failures).toEqual([]);
  await page.close();
});

test("⭐ a re-seal by the REAL popup never writes WEAKER Argon2 parameters than it read", async () => {
  // ⛔ THE OBSERVED BUG. `sigil_cli::reseal_container` has ratcheted the work
  // factors since Phase 58 — never write a container weaker than the one you
  // read — and the JS clients had no equivalent at all. Every popup re-seal used
  // a hardcoded 19456/2/1, so a vault the CLI wrote at 65536/4/2 came back from
  // ONE edit here at a 3.4x lower memory cost and half the passes, silently, and
  // permanently (a re-seal is where new parameters get chosen).
  // ⚠️ SELF-CONTAINED. The extension suite shares ONE persistent context across
  // the whole file, so this spec wipes storage and builds its own vault rather
  // than inheriting whatever the spec above left behind — otherwise a failure
  // there cascades into a meaningless failure here, and a mutation report cannot
  // tell the two apart.
  const seedPage = await openPopup();
  await seedPage.page.evaluate(async () => {
    await chrome.storage.local.clear();
  });
  await seedPage.page.reload();
  await expect(seedPage.page.locator("body")).toHaveAttribute("data-wasm", /.+/, {
    timeout: 30_000,
  });
  await expect(seedPage.page.getByTestId("view-setup")).toBeVisible();
  await seedPage.page.getByTestId("setup-password").fill(PASSWORD);
  await seedPage.page.getByTestId("setup-password-2").fill(PASSWORD);
  await seedPage.page.getByTestId("setup-submit").click();
  await expect(seedPage.page.getByTestId("view-unlocked")).toBeVisible({ timeout: 30_000 });
  await seedPage.page.getByTestId("add-toggle").click();
  await seedPage.page.getByTestId("add-label").fill("ratchet-seed");
  await seedPage.page.getByTestId("add-secret").fill(RFC_SECRET);
  await seedPage.page.getByTestId("add-submit").click();
  await expect(seedPage.page.getByTestId("account")).toHaveCount(1);
  const current = decrypt(await readStored(seedPage.page));

  // Exactly what this popup would find if the vault had been created on the
  // user's laptop with the CLI and synced here.
  const STRONG = { m_cost: 65536, t_cost: 4, p_cost: 2 };
  const strongBytes = sealVault(
    nodeWasm,
    PASSWORD,
    current,
    randomBytes(nodeWasm.recommended_salt_len()),
    randomBytes(nodeWasm.nonce_len()),
    STRONG,
  );
  expect(containerParams(nodeWasm, strongBytes)).toEqual(STRONG);
  await writeStored(seedPage.page, strongBytes);
  await seedPage.page.close();

  const { page, failures } = await openPopup();
  await unlock(page);
  await page.getByTestId("add-toggle").click();
  await page.getByTestId("add-label").fill("after-strong");
  await page.getByTestId("add-secret").fill(RFC_SECRET);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account")).toHaveCount(2);

  // ⛔ The popup has re-sealed. The header must still be the STRONG one.
  expect(containerParams(nodeWasm, await readStored(page))).toEqual(STRONG);

  // ...and the other direction: a deliberately WEAK container must be RAISED to
  // this build's own floor, not merely preserved.
  const WEAK = { m_cost: 8, t_cost: 1, p_cost: 1 };
  await writeStored(
    page,
    sealVault(
      nodeWasm,
      PASSWORD,
      current,
      randomBytes(nodeWasm.recommended_salt_len()),
      randomBytes(nodeWasm.nonce_len()),
      WEAK,
    ),
  );
  await page.close();

  const weakRun = await openPopup();
  await unlock(weakRun.page);
  await weakRun.page.getByTestId("add-toggle").click();
  await weakRun.page.getByTestId("add-label").fill("after-weak");
  await weakRun.page.getByTestId("add-secret").fill(RFC_SECRET);
  await weakRun.page.getByTestId("add-submit").click();
  await expect(weakRun.page.getByTestId("account")).toHaveCount(2);

  const raised = containerParams(nodeWasm, await readStored(weakRun.page));
  expect(raised.m_cost).toBeGreaterThan(WEAK.m_cost);
  expect(raised).toEqual({ m_cost: 19456, t_cost: 2, p_cost: 1 });

  expect(failures).toEqual([]);
  expect(weakRun.failures).toEqual([]);
  await weakRun.page.close();
});
