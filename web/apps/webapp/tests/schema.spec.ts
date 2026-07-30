import { expect, test, type Page } from "@playwright/test";
// @ts-expect-error — the Node-target wasm package (gitignored build output of
// sigil-wasm/build-wasm.sh). The TEST process needs it to open the app's sealed
// container; the APP uses the bundler-target package instead.
import * as nodeWasm from "../../../../sigil-wasm/pkg-node/sigil_wasm.js";
// @ts-expect-error — the same proven vault helpers the app itself ships.
import {
  openVault,
  sealVault,
  containerParams,
  bytesToBase64,
  base64ToBytes,
  // @ts-expect-error — plain .mjs, no bundled types.
} from "../../../../sigil-wasm/totp-vault.mjs";

/**
 * ⭐⭐ THE PROPERTY, PROVEN THROUGH THE REAL APP — not through the library.
 *
 * ⛔ WHY THIS FILE EXISTS. Phase 59 taught four clients to preserve vault fields
 * they do not understand, because the TotpVault schema is mirrored across the
 * CLI, this webapp, the MV3 extension and the desktop app, and vaults sync
 * through an op-log where the OLDEST writer wins: a client that rebuilt
 * `{ version, entries }` by hand DELETED a newer client's data on its next push.
 *
 * The fix landed in two places — `totp-vault.mjs` (the library) and
 * `authenticator.tsx` (the app, which had to stop hand-rebuilding the object and
 * call `cloneVault`). An independent verifier then REVERTED the app half:
 *
 *     const draft = { version: vault.version, entries: [...vault.entries] };
 *
 * ...verbatim the pre-Phase-59 shape, and the whole gate stayed green — 46
 * webapp specs, 12 extension specs and the Rust<->JS schema interop all passed.
 * Mutating the SAME logic inside `totp-vault.mjs` went red. So the MODULE was
 * guarded and the PRODUCT was not, which is this repo's oldest failure mode
 * wearing a new costume (docs/engineering-lessons.md).
 *
 * This spec closes that hole at the only level that can: it seeds a vault whose
 * stored JSON carries fields this build has never heard of, drives a REAL EDIT
 * through the REAL UI, and then decrypts what the app actually wrote.
 *
 * ⚠️ The seeding and the verification both happen in the TEST process, using the
 * Node-target wasm — deliberately, so that nothing the app does can affect the
 * measurement. The app is a black box here: password in, sealed bytes out.
 */

const T = 90_000;
const RFC_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_CODE = "287082";
const STORAGE_KEY = "sigil.webapp.vault.v1";
const PASSWORD = "schema-spec-password";

// Fields NO Sigil build understands. They stand in for whatever a future client
// writes — a per-entry note reference, a policy block, a provenance stamp — and
// `min_reader_version` is a real Phase 59 field the app must also carry through.
const UNKNOWN_VAULT_FIELDS = {
  min_reader_version: 1,
  future_policy: { require_uv: true, max_age_days: 90 },
  written_by: "sigil-future/9.9.9",
};
const UNKNOWN_ENTRY_FIELDS = {
  notes_ref: "note-7f3a-not-a-secret",
  future_flags: ["alpha", "beta"],
};

type Vault = {
  version: number;
  entries: Record<string, unknown>[];
  [k: string]: unknown;
};

async function readStoredVault(page: Page): Promise<Uint8Array> {
  const b64 = await page.evaluate((k) => window.localStorage.getItem(k), STORAGE_KEY);
  expect(b64, "the app must have persisted a sealed vault").toBeTruthy();
  return base64ToBytes(b64!);
}

/** Decrypt what the app actually wrote, in the TEST process. */
function decrypt(container: Uint8Array): Vault {
  return openVault(nodeWasm, PASSWORD, container) as Vault;
}

async function createVaultWithAccount(page: Page) {
  await page.goto("/?t=59");
  await page.getByTestId("setup-password").fill(PASSWORD);
  await page.getByTestId("setup-confirm").fill(PASSWORD);
  await page.getByTestId("setup-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });

  await page.getByTestId("add-label").fill("seeded");
  await page.getByTestId("add-secret").fill(RFC_SECRET_B32);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-code")).toHaveText(RFC_CODE, { timeout: T });
}

test("⭐ an edit made through the REAL UI preserves vault fields this build does not understand", async ({
  page,
}) => {
  await createVaultWithAccount(page);

  // ── seed: graft unknown fields onto the app's own sealed container ────────
  const original = await readStoredVault(page);
  // Re-seal at the SAME work factors the app chose, so this step cannot itself
  // change the header and confuse the no-downgrade assertions below.
  const params = containerParams(nodeWasm, original);
  const seeded = decrypt(original);
  expect(seeded.entries).toHaveLength(1);
  Object.assign(seeded, UNKNOWN_VAULT_FIELDS);
  Object.assign(seeded.entries[0], UNKNOWN_ENTRY_FIELDS);

  const salt = crypto.getRandomValues(new Uint8Array(nodeWasm.recommended_salt_len()));
  const nonce = crypto.getRandomValues(new Uint8Array(nodeWasm.nonce_len()));
  const seededBytes: Uint8Array = sealVault(nodeWasm, PASSWORD, seeded, salt, nonce, params);
  await page.evaluate(
    ([k, v]) => window.localStorage.setItem(k as string, v as string),
    [STORAGE_KEY, bytesToBase64(seededBytes)],
  );

  // ── drive a REAL edit through the REAL UI ────────────────────────────────
  await page.reload();
  await expect(page.getByTestId("unlock-password")).toBeVisible({ timeout: T });
  await page.getByTestId("unlock-password").fill(PASSWORD);
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
  // The app must have OPENED the seeded vault (min_reader_version 1 is readable).
  await expect(page.getByTestId("account-count")).toHaveText("1", { timeout: T });

  // Adding an account is a re-seal: withVault -> cloneVault -> persist.
  await page.getByTestId("add-label").fill("added-after-seeding");
  await page.getByTestId("add-secret").fill(RFC_SECRET_B32);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-count")).toHaveText("2", { timeout: T });

  // ── verify: decrypt what the APP wrote ───────────────────────────────────
  const afterAdd = decrypt(await readStoredVault(page));
  expect(afterAdd.entries).toHaveLength(2);

  // ⛔ THE MUTATION TARGET. Reverting `wasm.cloneVault(vault)` to
  // `{ version: vault.version, entries: [...vault.entries] }` in
  // authenticator.tsx deletes every one of these, and this expectation is what
  // notices.
  expect(afterAdd.min_reader_version).toBe(UNKNOWN_VAULT_FIELDS.min_reader_version);
  expect(afterAdd.future_policy).toEqual(UNKNOWN_VAULT_FIELDS.future_policy);
  expect(afterAdd.written_by).toBe(UNKNOWN_VAULT_FIELDS.written_by);

  // Entry-level unknowns survive too (the seeded entry, found by label).
  const seededEntry = afterAdd.entries.find((e) => e.label === "seeded");
  expect(seededEntry, "the seeded entry must still be there").toBeTruthy();
  expect(seededEntry!.notes_ref).toBe(UNKNOWN_ENTRY_FIELDS.notes_ref);
  expect(seededEntry!.future_flags).toEqual(UNKNOWN_ENTRY_FIELDS.future_flags);

  // ── the same property through a REMOVAL, the other edit the app offers ───
  await page
    .getByTestId("account-row")
    .filter({ hasText: "added-after-seeding" })
    .getByTestId("account-remove")
    .click();
  await expect(page.getByTestId("account-count")).toHaveText("1", { timeout: T });
  const afterRemove = decrypt(await readStoredVault(page));
  expect(afterRemove.min_reader_version).toBe(UNKNOWN_VAULT_FIELDS.min_reader_version);
  expect(afterRemove.future_policy).toEqual(UNKNOWN_VAULT_FIELDS.future_policy);
  expect(afterRemove.written_by).toBe(UNKNOWN_VAULT_FIELDS.written_by);
  const stillThere = afterRemove.entries.find((e) => e.label === "seeded");
  expect(stillThere!.notes_ref).toBe(UNKNOWN_ENTRY_FIELDS.notes_ref);
});

test("⭐ a re-seal by the REAL UI never writes WEAKER Argon2 parameters than it read", async ({
  page,
}) => {
  // ⛔ THE OBSERVED BUG. `sigil_cli::reseal_container` has ratcheted the work
  // factors since Phase 58 — never write a container weaker than the one you
  // read — and the JS clients had no equivalent at all. Every browser re-seal
  // used a hardcoded 19456/2/1, so a vault the CLI wrote at 65536/4/2 came back
  // from ONE edit here at a 3.4x lower memory cost and half the passes, silently,
  // and permanently (a re-seal is where new parameters get chosen).
  await createVaultWithAccount(page);

  const original = await readStoredVault(page);
  const seeded = decrypt(original);

  // Re-seal the app's own vault at the CLI's RECOMMENDED parameters, i.e. exactly
  // what this browser would find if the user had created the vault on their
  // laptop and synced it here.
  const STRONG = { m_cost: 65536, t_cost: 4, p_cost: 2 };
  const salt = crypto.getRandomValues(new Uint8Array(nodeWasm.recommended_salt_len()));
  const nonce = crypto.getRandomValues(new Uint8Array(nodeWasm.nonce_len()));
  const strongBytes: Uint8Array = sealVault(nodeWasm, PASSWORD, seeded, salt, nonce, STRONG);
  expect(containerParams(nodeWasm, strongBytes)).toEqual(STRONG);
  await page.evaluate(
    ([k, v]) => window.localStorage.setItem(k as string, v as string),
    [STORAGE_KEY, bytesToBase64(strongBytes)],
  );

  await page.reload();
  await expect(page.getByTestId("unlock-password")).toBeVisible({ timeout: T });
  await page.getByTestId("unlock-password").fill(PASSWORD);
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });

  await page.getByTestId("add-label").fill("after-strong");
  await page.getByTestId("add-secret").fill(RFC_SECRET_B32);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-count")).toHaveText("2", { timeout: T });

  // ⛔ The app has now re-sealed. The header must still be the STRONG one.
  expect(containerParams(nodeWasm, await readStoredVault(page))).toEqual(STRONG);

  // ...and the other direction: a deliberately WEAK container must be RAISED to
  // this build's own floor, not merely preserved.
  const WEAK = { m_cost: 8, t_cost: 1, p_cost: 1 };
  const weakBytes: Uint8Array = sealVault(
    nodeWasm,
    PASSWORD,
    seeded,
    crypto.getRandomValues(new Uint8Array(nodeWasm.recommended_salt_len())),
    crypto.getRandomValues(new Uint8Array(nodeWasm.nonce_len())),
    WEAK,
  );
  await page.evaluate(
    ([k, v]) => window.localStorage.setItem(k as string, v as string),
    [STORAGE_KEY, bytesToBase64(weakBytes)],
  );
  await page.reload();
  await expect(page.getByTestId("unlock-password")).toBeVisible({ timeout: T });
  await page.getByTestId("unlock-password").fill(PASSWORD);
  await page.getByTestId("unlock-submit").click();
  await expect(page.getByTestId("vault-view")).toBeVisible({ timeout: T });
  await page.getByTestId("add-label").fill("after-weak");
  await page.getByTestId("add-secret").fill(RFC_SECRET_B32);
  await page.getByTestId("add-submit").click();
  await expect(page.getByTestId("account-count")).toHaveText("2", { timeout: T });

  const raised = containerParams(nodeWasm, await readStoredVault(page));
  expect(raised.m_cost).toBeGreaterThan(WEAK.m_cost);
  expect(raised).toEqual({ m_cost: 19456, t_cost: 2, p_cost: 1 });
});
