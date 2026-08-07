// popup.js — the Sigil (dev) browser-action popup: an encrypted TOTP vault.
//
// WHAT THIS FILE DOES *NOT* DO: cryptography. Every cryptographic operation is
// performed by the libsigil WebAssembly core (sealing, opening, and the TOTP
// codes themselves), and every vault/migration transformation is performed by
// the PROVEN, framework-free helpers vendored from the repo-root sigil-wasm/
// (totp-vault.mjs, totp-migration.mjs). This file is UI glue + storage.
//
// STORAGE MODEL (mirrors the webapp, ADR 0028-era model):
//   * chrome.storage.local holds ONLY the sealed SIGILcli container (base64).
//   * The password lives ONLY in memory while unlocked; it is never persisted.
//   * Closing the popup drops the in-memory state, so the vault re-locks.
//   * The container format is the SAME one the `sigil` CLI and the webapp use,
//     so a vault stays cross-client interoperable. Do not invent a new one.
//
// ENTROPY: the salt and nonce are drawn in JS via crypto.getRandomValues and
// passed INTO the wasm (the core draws no entropy and reads no clock).
//
// TEST HOOK: `popup.html?t=<unix-seconds>` PINS the clock to that instant (no
// ticking), so a headless test can assert an exact RFC 6238 vector. Without it
// the clock ticks live once per second. See README.md.
//
// Pre-audit / UNAUDITED / DEV. Do NOT store real 2FA secrets.

import init, * as wasm from "../../vendor/sigil_wasm.js";
import {
  newVault,
  openVault,
  sealVault,
  addEntry,
  // ⭐ Phase 61: identity, the 2P-Set merge, and a remove that TOMBSTONES.
  addEntryChecked,
  entryIdentity,
  mergeOpsInto,
  removeEntry,
  cloneVault,
  codeForEntry,
  base32Decode,
  base64ToBytes,
  bytesToBase64,
  ratchetParams,
  // ⛔ The tombstone growth limit: warn BEFORE the 64 KiB cap becomes a 413.
  opBodySizeWarning,
} from "../../vendor/totp-vault.mjs";
import {
  parseOtpauthUri,
  buildOtpauthUri,
  decodeMigrationUri,
  encodeMigrationUri,
  // ⭐ Phase 63: the untrusted-text gate and its constants. `validateProvisioning`
  // is what the add-by-form door now runs (see the `add-form` handler);
  // `MAX_PERIOD` sets the input's `max` attribute so no fourth literal exists.
  // `frozenPeriodWarning` is the READ-path counterpart — an entry that got in
  // before the gate, or through a vault MERGE, must not wear a normal countdown.
  validateProvisioning,
  frozenPeriodWarning,
  MAX_PERIOD,
} from "../../vendor/totp-migration.mjs";
import { pushContainer, pullContainers } from "../../vendor/sync.mjs";
import {
  generateDeviceSeed,
  enrollDevice,
  pushContainerAuthed,
  pullContainersAuthed,
  sealDeviceIdentity,
  openDeviceIdentity,
  explainAuthStatus,
  getAccount,
} from "../../vendor/device-auth.mjs";
import {
  generateHybridIdentity,
  hybridPublicIdentity,
  publishHybridKey,
  fetchHybridKey,
  generateVaultKey,
  vaultKeyFingerprint,
  shareVault,
  acceptVault,
  explainSharingStatus,
  // Phase 50 — key verification + rotation. Same module the webapp uses; there is
  // no extension-specific copy of any of this.
  safetyNumber,
  repinHybridKey,
  rotateVaultKey,
  listKeyEnvelopes,
  newPinStore,
  KeyPinMismatchError,
  UnverifiedRecoveryKitError,
  SafetyNumberMismatchError,
  // Phase 60 — the AUTHENTICATED vault-key envelope. Both are REFUSALS with
  // their own meaning: neither is a 401, a 403, or a changed key.
  UnauthenticatedEnvelopeError,
  UnknownSenderError,
  // …and the other two halves of the CLI's five-step accept, which this popup
  // was missing entirely: a key that opens NOTHING, and one that would silently
  // REPLACE a key this browser already depends on.
  VaultKeyDoesNotOpenError,
  VaultKeyReplacementError,
} from "../../vendor/sharing.mjs";
// THE RECOVERY KIT (ADR 0042). Same vendored module the webapp imports; this
// file adds no cryptography and no codec of its own.
import {
  generateRecoveryKit,
  coverVault,
  restoreFromKit,
  revokeRecoveryKit,
  pinDerivedKey,
  explainRecoveryStatus,
  RECOVERY_DEVICE_LABEL,
} from "../../vendor/recovery.mjs";
// ENTITLEMENT (ADR 0043, read side): what the server already says about payment.
import {
  getSubscription,
  entitlementState,
  describeEntitlement,
  describePaymentRequired,
  explainSubscriptionStatus,
  paymentRequiredFrom,
  readEntitlementHeaders,
  formatInstant,
  NEVER_REFUSED,
} from "../../vendor/entitlement.mjs";
// ⛔ CLOCK SKEW — a DIAGNOSTIC, never a correction. Nothing here feeds the clock
// `nowSeconds()` gives the wasm to generate codes.
import { fetchClockSkew, describeClockSkew } from "../../vendor/clock-skew.mjs";
// QR scanning (Phase 63) — the platform's own BarcodeDetector, no dependency.
// It produces a bounded STRING and hands it to the parsers above, which is where
// the provisioning gate lives; it adds no crypto and no second parser.
import {
  qrSupport,
  scanProvisioningImage,
  imageFromEvent,
  explainQrError,
} from "../../vendor/qr-scan.mjs";

/** chrome.storage.local key holding ONLY the sealed container, base64. */
const STORAGE_KEY = "sigil.extension.vault.v1";

/**
 * chrome.storage.local key holding the SEALED device identity — a SECOND
 * SIGILcli container, sealed with the SAME vault password, whose plaintext is
 * {device_id, seed, base_url, hybrid?, vault_keys?}.
 *
 * The Ed25519 device SEED, the hybrid SECRET identity (X25519 secret + ML-KEM
 * seed) and every accepted 32-byte VAULT KEY are secret key material, so NONE of
 * them is ever stored in plaintext: they are only recoverable while the vault is
 * unlocked (the password is memory-only). They live in their own container rather
 * than inside the vault JSON so the CLI-mirrored TotpVault schema stays
 * byte-compatible.
 */
const DEVICE_KEY = "sigil.extension.device.v1";

/**
 * Argon2id parameters used when (re)sealing. The container is self-describing
 * (it carries these), so opening needs none and a vault sealed here still opens
 * in the CLI and the webapp. Interactive-grade parameters for a dev build.
 */
const ARGON2 = { m_cost: 19456, t_cost: 2, p_cost: 1 };

// ── in-memory session state (never persisted) ────────────────────────────────

/** @type {string} the vault password, memory-only, cleared on lock. */
let password = "";
/** @type {{version:number,entries:object[]}|null} */
let vault = null;
/** @type {{deviceId:string,seed:Uint8Array,baseUrl:string,hybrid:object|null,vaultKeys:object}|null} memory-only. */
let device = null;
/**
 * What SEALS the TOTP vault container: the human password for a PERSONAL vault,
 * or the 32-byte VAULT KEY for a SHARED one. A SIGILcli container takes arbitrary
 * password BYTES, so a random key drops straight in where a password goes —
 * exactly as `sigil vault rekey` does it. Memory-only, cleared on lock.
 * @type {string|Uint8Array}
 */
let sealSecret = "";
/** @type {string|null} the vault id this vault is shared under, else null. */
let activeVaultId = null;
/** @type {number|null} pinned unix time from the ?t= TEST HOOK, else null. */
let pinnedTime = null;
/** @type {number|undefined} setInterval handle for the 1 s tick. */
let ticker;

const $ = (id) => document.getElementById(id);
const err = (e) => (e instanceof Error ? e.message : String(e));

/**
 * ⭐ THE ONE SENTENCE ABOUT RECOVERY, SO IT CANNOT DRIFT INTO A LIE AGAIN.
 *
 * The account panel used to state, in the product, that "this extension cannot
 * print one" — advice that was correct until Phase 56 and has been false ever
 * since. A stale capability claim is worse than no claim when the capability in
 * question is the only thing standing between the user and permanent loss of
 * every account in the vault: it does not merely fail to help, it actively
 * routes them past the fix.
 *
 * What is still TRUE, and must stay in this string: a kit cannot be created
 * AFTER access is lost. That is a property of the design (ADR 0042), not a
 * limitation of this client.
 */
const RECOVERY_ADVICE =
  "A kit cannot be created after the fact — but this extension CAN print one " +
  "right now: open “Recovery kit (dev)” below and choose “Generate a kit”.";

/** Current unix seconds — the pinned test clock if set, else the wall clock. */
function nowSeconds() {
  return pinnedTime !== null ? pinnedTime : Math.floor(Date.now() / 1000);
}

function say(text, kind = "info") {
  const el = $("status");
  el.textContent = text;
  el.dataset.kind = kind;
}

/** Show exactly one of the setup / locked / unlocked views. */
function show(view) {
  for (const name of ["setup", "locked", "unlocked"]) {
    $(`view-${name}`).hidden = name !== view;
  }
  // ⭐ RESTORE IS VISIBLE WHENEVER THE VAULT IS NOT OPEN — including on a
  // completely fresh install, which is precisely the state a customer who lost
  // every device is in. It is not a sub-feature of an unlocked vault.
  $("view-restore").hidden = view === "unlocked";
  $("lock").hidden = view !== "unlocked";
  document.body.dataset.phase = view;
}

// ── persistence (sealed container only) ──────────────────────────────────────

async function readSealed() {
  const got = await chrome.storage.local.get(STORAGE_KEY);
  return got[STORAGE_KEY] ?? null;
}

/**
 * Seal `v` under the CURRENT seal secret (password or vault key) with fresh
 * entropy and store ONLY the resulting container. Throws before writing if
 * sealing fails, so a failed save can never leave a corrupt container behind.
 */
async function persist(v, secret = null) {
  const salt = crypto.getRandomValues(new Uint8Array(wasm.recommended_salt_len()));
  const nonce = crypto.getRandomValues(new Uint8Array(wasm.nonce_len()));
  const container = sealVault(wasm, secret ?? sealSecret, v, salt, nonce, await sealParams(STORAGE_KEY));
  await chrome.storage.local.set({ [STORAGE_KEY]: bytesToBase64(container) });
  // ⭐ WARN AT THE MOMENT THE VAULT GROWS, not at the moment sync breaks.
  // `opBodySizeWarning` was previously wired only to Push and to the server's
  // 413, so a user who imported a large Google Authenticator export learned
  // their vault no longer syncs long after the choice that caused it — and there
  // is no supported way to shrink it (tombstones are never pruned, and there is
  // no `compact`). Keyed off the SAME `MAX_OP_BODY_BYTES` as the push path and
  // the CLI, because it is the same function. Measured motivation: a 512-entry
  // import (the provisioning ceiling) seals to ~86 KB against a 64 KiB cap.
  showSizeWarning(opBodySizeWarning(container.length));
}

/** Render (or clear) the persistent vault-size alert. */
function showSizeWarning(text) {
  const el = $("size-warning");
  if (!el) return;
  el.textContent = text ?? "";
  el.hidden = !text;
}

/**
 * ⭐⭐ THE NO-DOWNGRADE RATCHET, applied at every re-seal this popup performs.
 *
 * ⛔ A `SIGILcli` container carries the Argon2id work factors it was sealed with,
 * and a re-seal is where new factors get CHOSEN. This popup used to write
 * `ARGON2` verbatim, so a vault the CLI wrote at 65536/4/2 came back from ONE
 * edit here at 19456/2/1 — 3.4x less memory and half the passes, silently, on a
 * vault the user shares with their laptop. The Rust clients have ratcheted since
 * Phase 58 (`sigil_cli::reseal_container`); this is the JS half.
 *
 * `ARGON2` is a FLOOR, not an instruction: what gets written is the componentwise
 * max of the stored container's factors and this build's. The rule lives in
 * sigil-core (`Argon2Params::no_downgrade`, reached through the wasm), so it
 * cannot drift from the CLI's.
 */
async function sealParams(storageKey) {
  const got = await chrome.storage.local.get(storageKey);
  const stored = got[storageKey];
  return ratchetParams(wasm, stored ? base64ToBytes(stored) : null, ARGON2);
}

// ── device identity (sealed at rest, exactly like the vault) ─────────────────

/**
 * Seal the device identity under the CURRENT vault password and store ONLY the
 * container. `null` forgets the identity.
 */
async function persistDevice(d) {
  if (!d) {
    await chrome.storage.local.remove(DEVICE_KEY);
    device = null;
    renderDevice();
    return;
  }
  const salt = crypto.getRandomValues(new Uint8Array(wasm.recommended_salt_len()));
  const nonce = crypto.getRandomValues(new Uint8Array(wasm.nonce_len()));
  const container = sealDeviceIdentity(wasm, password, d, salt, nonce, await sealParams(DEVICE_KEY));
  await chrome.storage.local.set({ [DEVICE_KEY]: bytesToBase64(container) });
  device = d;
  renderDevice();
}

/**
 * Decrypt the stored device identity with the just-accepted password. A
 * container that will not open (e.g. sealed under an older password) is treated
 * as "no device" rather than blocking the unlock.
 */
async function loadDevice(pw) {
  const got = await chrome.storage.local.get(DEVICE_KEY);
  const sealed = got[DEVICE_KEY];
  device = null;
  if (sealed) {
    try {
      device = openDeviceIdentity(wasm, pw, base64ToBytes(sealed));
    } catch {
      device = null;
    }
  }
  renderDevice();
}

/** Show either the enrollment form or the enrolled-device summary. */
function renderDevice() {
  const state = $("device-state");
  const fields = $("device-enroll-fields");
  const forget = $("device-forget");
  if (!state || !fields || !forget) return;
  if (device) {
    state.textContent = `Enrolled as ${device.deviceId} — sync requests are signed by this device.`;
    fields.hidden = true;
    forget.hidden = false;
  } else {
    state.textContent = "Not enrolled — sync requests are unauthenticated.";
    fields.hidden = false;
    forget.hidden = true;
    account = null;
  }
  const showBtn = $("account-show");
  if (showBtn) showBtn.hidden = !device;
  const entBtn = $("entitlement-check");
  if (entBtn) entBtn.hidden = !device;
  renderAccount();
  renderSharing();
  renderRecovery();
}

/** Reflect whether a kit generated right now would cover anything. */
function renderRecovery() {
  const warn = $("recovery-no-keys");
  if (!warn) return;
  const holds = Object.keys(device?.vaultKeys ?? {}).length;
  warn.hidden = !device || holds > 0 || !$("recovery-sheet").hidden;
}

// ── account membership (Phase 52) ────────────────────────────────────────────
//
// THE STATE THIS EXISTS TO SHOW. An account invite pastes straight into the
// enrollment-token field, so this browser can JOIN an account with no wire
// change at all. Joining confers AUTHORIZATION, never DECRYPTION: the joined
// device authenticates and can see the account and its entitlement, and can
// decrypt NOTHING until an existing member wraps a vault key to its hybrid
// public key (Sharing → Share to this device id, then Accept here).
//
// The CLI and the desktop app surface that step. Until now the browsers did not,
// so a freshly joined extension showed an account beside an empty vault with no
// explanation — which reads as a bug rather than as work still outstanding.

/** The last /v1/account response, or null. Never persisted. */
let account = null;

/** Render the account summary and, when it applies, the waiting-for-a-key state. */
function renderAccount() {
  const state = $("account-state");
  const waiting = $("account-awaiting-key");
  if (!state || !waiting) return;
  if (!device || !account) {
    if (!device) state.textContent = "";
    waiting.hidden = true;
    return;
  }
  const revoked = account.revoked_device_count
    ? ` (${account.revoked_device_count} revoked — revoked devices do not use a seat)`
    : "";
  // ⛔ THIS SENTENCE USED TO BE FALSE, AND FALSE IN THE MOST DAMAGING DIRECTION.
  // It read "…and this extension cannot print one", which was true before Phase
  // 56 and has been wrong ever since: `recovery-generate` is right there in the
  // Recovery kit panel below, calling `generateRecoveryKit`. Telling a user that
  // the ONE control which prevents permanent, unrecoverable account loss does
  // not exist — inside the product, three sections above the button — steers
  // them away from it. See RECOVERY_ADVICE in this file: one string, used
  // everywhere the subject comes up, so the two cannot drift again.
  state.textContent =
    `Account ${account.account_id} — ${account.device_count} of ${account.device_limit} ` +
    `devices in use${revoked}. An account is reachable only through a member ` +
    `device's private key, so losing every device is unrecoverable UNLESS a ` +
    `recovery kit was printed in advance. ${RECOVERY_ADVICE} Membership ` +
    `is flat (any member may invite, and may revoke any other member).`;

  const id = $("sync-vault").value.trim();
  const holdsKey = Boolean(device.vaultKeys?.[id]);
  // Only meaningful once there IS another member who could send a key.
  const hasSiblings = (account.device_count ?? 0) > 1;
  if (hasSiblings && !holdsKey) {
    waiting.textContent =
      `Joined — waiting for a key from another device. This device is a member of ` +
      `the account and its requests are authorized, but membership does not hand over ` +
      `any encryption key. It cannot decrypt vault "${id || "(none)"}" until an ` +
      `existing member shares it here (on that device: Sharing → Share to ` +
      `${device.deviceId}). Then use Accept below.`;
    waiting.hidden = false;
  } else {
    waiting.hidden = true;
  }
}

/** Reflect the device / hybrid / shared-vault state in the Sharing panel. */
function renderSharing() {
  const who = $("sharing-device");
  const hyb = $("sharing-hybrid-state");
  const vlt = $("sharing-vault-state");
  if (!who || !hyb || !vlt) return;
  if (!device) {
    who.textContent = "Enroll this browser as a device first (Sync above).";
    hyb.textContent = "";
    vlt.textContent = "";
    return;
  }
  who.textContent = `This device: ${device.deviceId}`;
  hyb.textContent = device.hybrid
    ? "Hybrid key: this device has a hybrid identity — publish it so others can share to you."
    : "Hybrid key: not created yet — publish to create and register one.";
  const id = $("sync-vault").value.trim();
  const shared = activeVaultId === id && Boolean(device.vaultKeys?.[id]);
  vlt.textContent = shared
    ? `Vault "${id}": SHARED — sealed under a random 32-byte vault key.`
    : `Vault "${id}": personal — sealed with your password.`;
}

/**
 * Turn a failure into a message. A device-auth failure carries the HTTP status,
 * so 401 (not authenticated) and 403 (not authorized for this vault) are spelled
 * out instead of shown as a generic error.
 */
function authErr(e) {
  const status = e && typeof e.status === "number" ? e.status : 0;
  // 402 is included deliberately: it is a BILLING state, and rendering it as a
  // bare "HTTP 402" (the old default arm) told the user nothing. It is still NOT
  // 401/403 — explainAuthStatus spells out that the device authenticated and was
  // authorized, and that reading is never refused.
  if (status === 401 || status === 402 || status === 403 || status === 501) {
    return explainAuthStatus(status);
  }
  return err(e);
}

/**
 * Same, for the SHARING endpoints: 401 (not authenticated) vs 403 (authenticated
 * but not permitted — not the addressee, or no write access) vs 404 (nothing has
 * been shared / no hybrid key published) mean completely different things.
 */
function sharingErr(e) {
  const status = e && typeof e.status === "number" ? e.status : 0;
  return status >= 400 ? explainSharingStatus(status) : err(e);
}

/**
 * ⭐ PHASE 60 — THE ENVELOPE-AUTHENTICITY REFUSALS, rendered DISTINCTLY.
 *
 * An unauthenticated vault-key envelope is NOT a 401 (the request authenticated
 * fine), NOT a 403 (nothing was forbidden) and NOT a pin mismatch (no key
 * changed). It means the BYTES prove nothing about who produced them — anyone
 * who could read this device's PUBLISHED hybrid public key could have minted
 * them — so accepting one could install a vault key an attacker chose.
 *
 * Returns true when it handled the error (and told the user), like
 * {@link showPinMismatch}.
 */
function showEnvelopeRefusal(e) {
  const box = $("sharing-envelope-refusal");
  const text = $("sharing-envelope-refusal-text");
  if (e instanceof UnauthenticatedEnvelopeError) {
    if (text) {
      text.textContent =
        `REFUSED — that vault-key envelope is NOT AUTHENTICATED (SIGILhyb version ` +
        `${e.foundVersion}; a vault key must be version ${e.expectedVersion}). Nothing was opened ` +
        `and no key was stored. This is NOT a sign-in problem and NOT a permission problem, and ` +
        `no device's key changed: the envelope carries NO SENDER, so anyone who can read this ` +
        `device's published hybrid public key could have minted it. Ask the owner to re-share.`;
    }
    if (box) box.hidden = false;
    say("Accept REFUSED: that envelope is not authenticated. Nothing was opened.", "error");
    return true;
  }
  if (e instanceof UnknownSenderError) {
    if (text) {
      text.textContent =
        `REFUSED — nothing says which device deposited that vault key, so there is nothing to ` +
        `authenticate it against. Nothing was opened and no key was stored. Type the sharing ` +
        `device's id into "Accept from device id" and try again.`;
    }
    if (box) box.hidden = false;
    say("Accept REFUSED: the depositing device is unknown. Nothing was opened.", "error");
    return true;
  }
  // ⭐ STEP 4 of the CLI's accept_vault_key, which this popup did not have: the
  // envelope authenticated fine, but the key inside opens NOTHING. Storing it
  // would have been useless at best and would have DISPLACED the real key at
  // worst (see the replacement branch below).
  if (e instanceof VaultKeyDoesNotOpenError) {
    if (text) {
      text.textContent =
        `REFUSED — that key does NOT open this vault. Nothing was opened and no key was stored. ` +
        `The envelope WAS properly authenticated, so this is not a forgery the sender check can ` +
        `name and not a permission problem: the key that came out simply does not decrypt this ` +
        `vault's newest contents. Either it was deposited for a different vault, or the sender ` +
        `ROTATED the key and has not pushed the re-sealed vault yet — ask them to push, then ` +
        `accept again.`;
    }
    if (box) box.hidden = false;
    say("Accept REFUSED: that key does not open this vault. Nothing was stored.", "error");
    return true;
  }
  // ⭐ STEP 5. Everything checked out; what is refused is the OVERWRITE. Silently
  // replacing is how a hostile deposit takes a vault away from a device that
  // already had it — this browser may hold the last copy of the old key.
  if (e instanceof VaultKeyReplacementError) {
    if (text) {
      text.textContent =
        `REFUSED — that would REPLACE a different key this browser already holds for "${e.vaultId}" ` +
        `(sha256 ${e.heldFingerprint}); the key offered is sha256 ${e.offeredFingerprint}. Nothing ` +
        `was replaced. Overwriting would lose access to everything sealed under the key you have. ` +
        `If the sender ROTATED the vault key that is exactly what you want: tick "Replace the key ` +
        `I hold" and accept again. If they did not, someone deposited a key you did not ask for.`;
    }
    if (box) box.hidden = false;
    const wrap = $("sharing-accept-replace-row");
    if (wrap) wrap.hidden = false;
    say("Accept REFUSED: it would replace a DIFFERENT key this browser holds.", "error");
    return true;
  }
  return false;
}

function hideEnvelopeRefusal() {
  const box = $("sharing-envelope-refusal");
  if (box) box.hidden = true;
  // ⭐ AND RE-ARM THE GUARD. A `--replace` opt-in that stayed ticked out of sight
  // would silently authorize the NEXT accept — of a different vault, from a
  // different sender — which is precisely the silent overwrite step 5 exists to
  // stop. The caller reads the box BEFORE calling this.
  const row = $("sharing-accept-replace-row");
  if (row) row.hidden = true;
  const box2 = $("sharing-accept-replace");
  if (box2) box2.checked = false;
}

/**
 * Apply `mutate` to a copy of the vault, re-seal + persist it, then swap it in
 * and re-render. A mutator that throws (duplicate label, bad secret, …) aborts
 * BEFORE anything is written.
 */
/**
 * Adopt an ALREADY-BUILT vault object: persist it, then swap it in.
 *
 * ⭐ Used by the merge, whose output is a whole vault rather than a mutation of
 * the current one. It persists FIRST (that can throw), so a failed seal never
 * leaves the UI showing accounts that are not on disk.
 */
async function replaceVault(next) {
  await persist(next);
  vault = next;
  render();
}

async function withVault(mutate) {
  if (!vault) throw new Error("vault is locked");
  // ⭐ `cloneVault`, NOT `{ version, entries }`. Rebuilding the object
  // field-by-field silently deletes `min_reader_version` and every field a newer
  // client wrote, and this popup would then push the stripped vault over the
  // newer one — the oldest writer wins on the op-log.
  const draft = cloneVault(vault);
  await mutate(draft);
  await persist(draft);
  vault = draft;
  render();
}

// ── rendering ────────────────────────────────────────────────────────────────

function render() {
  const list = $("accounts");
  const entries = vault ? vault.entries : [];
  $("empty").hidden = entries.length > 0;

  // Rebuild the rows only when the set of accounts changed; otherwise just update
  // the code + countdown so the DOM (and any focus) stays stable across ticks.
  // ⭐ Phase 61: keyed on IDENTITY, not label. Labels are no longer unique
  // (`work` at two issuers is two accounts), so a label-keyed row set would
  // collapse two accounts into one row and remove the wrong one.
  const want = entries.map((e) => entryIdentity(wasm, e)).join("\u0000");
  if (list.dataset.labels !== want) {
    list.dataset.labels = want;
    list.replaceChildren(...entries.map(row));
  }
  tick();
}

function row(entry) {
  const li = document.createElement("li");
  li.dataset.testid = "account";
  li.dataset.label = entry.label;
  // ⭐ Phase 61: the STABLE handle. `dataset.label` is retained for the existing
  // specs' selectors but is no longer what anything is looked up by.
  li.dataset.uuid = entryIdentity(wasm, entry);

  const who = document.createElement("div");
  who.className = "who";
  const label = document.createElement("span");
  label.className = "label";
  label.textContent = entry.label;
  who.append(label);
  if (entry.issuer) {
    const issuer = document.createElement("span");
    issuer.className = "issuer";
    issuer.textContent = entry.issuer;
    who.append(issuer);
  }

  const code = document.createElement("button");
  code.type = "button";
  code.className = "code";
  code.dataset.testid = "code";
  code.title = "Copy code";
  code.addEventListener("click", () => copy(code.textContent ?? ""));

  const left = document.createElement("span");
  left.className = "left";
  left.dataset.testid = "countdown";

  const rm = document.createElement("button");
  rm.type = "button";
  rm.className = "rm";
  rm.dataset.testid = "remove";
  rm.textContent = "Remove";
  rm.setAttribute("aria-label", `Remove ${who_(entry)}`);

  // ⛔⛔ THE DELETE CONFIRMATION — the mirror of the webapp's (authenticator.tsx,
  // AccountRow). It is not politeness; it is the only thing between a misclick
  // and permanent, unrecoverable loss of a second factor, and losing a second
  // factor can mean losing the account it protects.
  //
  //  1. The button sits inches from the CODE the user came to read, in a popup
  //     whose rows re-render every second. Misclicks are the expected case.
  //  2. ⭐ Phase 61 RAISED the stakes: a removal writes a TOMBSTONE that
  //     propagates to every device and is specifically protected against
  //     resurrection (ADR 0049 §3 — delete wins). It used to be that a stale
  //     snapshot might bring the entry back by accident; now it provably will
  //     not.
  //
  // ⭐ A CONFIRM, NOT AN UNDO, and the reason is the merge: an undo would have to
  // write the tombstone and retract it — the exact resurrection ADR 0049 exists
  // to prevent, and unretractable the moment another device merges it — or hold
  // the delete pending in memory, where CLOSING THE POPUP (which happens
  // constantly, that is what popups do) silently discards the user's intent. The
  // tombstone is written at commit and never before.
  const confirmBox = document.createElement("div");
  confirmBox.className = "rmconfirm";
  confirmBox.dataset.testid = "remove-confirm";
  confirmBox.setAttribute("role", "alert");
  confirmBox.hidden = true;

  const confirmText = document.createElement("p");
  confirmText.dataset.testid = "remove-confirm-warning";
  // ⚠️ IT MUST NOT PROMISE A SYNC IT DOES NOT PERFORM. An earlier revision said
  // "the deletion is synced to every other device holding it", which is FALSE
  // here: sync in this product is MANUAL (explicit Push / Pull) and a vault with
  // no server configured never propagates at all. This is the sentence a user
  // reads while deciding whether to destroy a second factor, so it says exactly
  // what happens and exactly what it is conditional on.
  confirmText.textContent =
    `Delete ${who_(entry)}? This permanently deletes the second-factor secret ` +
    `from this vault. Sigil syncs only when you ask it to, so the deletion ` +
    `reaches every other device holding this vault the next time you Push and ` +
    `they Pull; until you do — and forever, if you never sync — it applies to ` +
    `this device alone. It cannot be undone from here — if you no longer have ` +
    `this secret anywhere else, you may lose access to the account it protects.`;

  const yes = document.createElement("button");
  yes.type = "button";
  yes.className = "rm danger";
  yes.dataset.testid = "remove-confirm-yes";
  yes.textContent = "Delete permanently";

  const no = document.createElement("button");
  no.type = "button";
  no.className = "rm";
  no.dataset.testid = "remove-confirm-cancel";
  no.textContent = "Keep it";

  const closeConfirm = () => {
    confirmBox.hidden = true;
    rm.hidden = false;
  };

  // ⛔ This opens the gate. It MUST NOT remove: `removeEntry` writes the
  // propagating tombstone described above.
  rm.addEventListener("click", () => {
    confirmBox.hidden = false;
    rm.hidden = true;
    yes.focus();
  });
  no.addEventListener("click", closeConfirm);
  yes.addEventListener("click", async () => {
    closeConfirm();
    try {
      // ⭐ Phase 61: remove by IDENTITY and RECORD A TOMBSTONE. Filtering by
      // label removed every account sharing that label, and — worse — wrote no
      // tombstone, so the entry came straight back the next time this vault met
      // a snapshot that still held it.
      await withVault((d) => {
        removeEntry(wasm, d, { uuid: li.dataset.uuid }, Math.floor(Date.now() / 1000));
      });
      say(`Removed ${entry.label}.`);
    } catch (e) {
      say(err(e), "error");
    }
  });

  confirmBox.append(confirmText, yes, no);
  li.append(who, code, left, rm, confirmBox);

  // ⛔⛔ THE READ-PATH FROZEN-ENTRY WARNING (Phase 63). The ingest ceiling is
  // deliberately NOT retroactive and deliberately does not cover a Phase 61
  // vault MERGE (see `mergeVaults` in totp-vault.mjs), so an entry whose code
  // never rotates can still be sitting in this list — and until now it wore an
  // ordinary countdown, which is the product telling the user their second
  // factor is fine when it is a static secret in a rotating costume.
  //
  // ⛔ IT REPORTS AND NEVER CORRECTS: nothing here alters or hides the entry.
  const frozen = frozenPeriodWarning(entry.period);
  if (frozen) {
    const warn = document.createElement("p");
    warn.className = "frozen";
    warn.dataset.testid = "frozen-warning";
    warn.setAttribute("role", "alert");
    warn.textContent = frozen;
    li.append(warn);
  }
  return li;
}

/** "issuer, label" when there is an issuer, else just the label. */
function who_(entry) {
  return entry.issuer ? `${entry.issuer}, ${entry.label}` : entry.label;
}

/** Recompute every visible code + countdown from the current clock. */
function tick() {
  if (!vault) return;
  const t = nowSeconds();
  for (const li of $("accounts").children) {
    const entry = vault.entries.find((e) => entryIdentity(wasm, e) === li.dataset.uuid);
    if (!entry) continue;
    const code = li.querySelector(".code");
    const left = li.querySelector(".left");
    try {
      code.textContent = codeForEntry(wasm, entry, t);
      code.classList.remove("bad");
    } catch (e) {
      code.textContent = `error: ${err(e)}`;
      code.classList.add("bad");
    }
    const remaining = entry.period - (t % entry.period);
    left.textContent = `${remaining}s`;
    left.dataset.low = remaining <= 5 ? "1" : "0";
  }
}

async function copy(text) {
  const value = String(text).trim();
  if (!value) return;
  try {
    // Preferred path; falls back below when the clipboard API is unavailable
    // (this extension deliberately requests no clipboard permission).
    await navigator.clipboard.writeText(value);
    say("Code copied.");
  } catch {
    const ta = document.createElement("textarea");
    ta.value = value;
    document.body.append(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    say(ok ? "Code copied." : "Could not copy.", ok ? "info" : "error");
  }
}

// ── lock / unlock lifecycle ──────────────────────────────────────────────────

function lock() {
  password = "";
  sealSecret = "";
  activeVaultId = null;
  vault = null;
  device = null; // the seed, hybrid secret and vault keys leave memory too
  renderDevice();
  $("accounts").replaceChildren();
  $("accounts").dataset.labels = "";
  $("export-out").hidden = true;
  $("export-out").value = "";
  // A recovery code on screen is a credential on screen: locking removes it.
  $("recovery-code").textContent = "";
  $("recovery-sheet").hidden = true;
  $("recovery-written").checked = false;
  $("recovery-hide").disabled = true;
  $("recovery-coverage").hidden = true;
  $("recovery-unverified").hidden = true;
  $("entitlement-state").hidden = true;
  $("entitlement-402").hidden = true;
  $("unlock-pw").value = "";
  show("locked");
  say("Locked.");
}

function unlocked() {
  show("unlocked");
  render();
  say(`Unlocked — ${vault.entries.length} account(s).`);
}

// ── boot ─────────────────────────────────────────────────────────────────────

async function boot() {
  // TEST HOOK: ?t=<unix> pins the clock so codes are deterministic.
  const t = new URLSearchParams(location.search).get("t");
  if (t !== null && Number.isFinite(Number(t))) pinnedTime = Math.floor(Number(t));

  try {
    // MV3 popups are extension pages, so the .wasm is same-origin; hand the
    // loader an explicit extension URL rather than relying on import.meta
    // resolution.
    await init({ module_or_path: chrome.runtime.getURL("vendor/sigil_wasm_bg.wasm") });
  } catch (e) {
    say(`Could not load the WebAssembly core: ${err(e)}`, "error");
    document.body.dataset.phase = "error";
    return;
  }

  document.body.dataset.wasm = wasm.version();

  const sealed = await readSealed();
  if (sealed) {
    show("locked");
    say("A sealed vault is stored. Enter your password.");
  } else {
    show("setup");
    say("No vault yet — create one to begin.");
  }

  // Live clock (skipped when pinned, so a test sees a frozen instant).
  if (pinnedTime === null) ticker = setInterval(tick, 1000);
}

// ── event wiring ─────────────────────────────────────────────────────────────

$("setup-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pw = $("setup-pw").value;
  if (pw.length < 8) return say("Use a password of at least 8 characters.", "error");
  if (pw !== $("setup-pw2").value) return say("Passwords do not match.", "error");
  try {
    say("Deriving the key…");
    password = pw;
    sealSecret = pw;
    activeVaultId = null;
    vault = newVault();
    await persist(vault);
    await loadDevice(pw);
    $("setup-pw").value = "";
    $("setup-pw2").value = "";
    unlocked();
  } catch (e) {
    password = "";
    sealSecret = "";
    vault = null;
    say(err(e), "error");
  }
});

$("unlock-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const pw = $("unlock-pw").value;
  try {
    say("Deriving the key…");
    const sealed = await readSealed();
    if (!sealed) throw new Error("no sealed vault is stored");
    const container = base64ToBytes(sealed);

    // The device identity opens with the PASSWORD; it is what carries any vault
    // keys, so it must be read first.
    await loadDevice(pw);

    // A PERSONAL vault opens with the password. A SHARED vault is sealed under a
    // random 32-byte vault key instead, so fall back to the keys this device
    // holds — the CLI's `--vault-id` rule, just chosen automatically.
    let opened = null;
    let secret = pw;
    let vid = null;
    try {
      opened = openVault(wasm, pw, container);
    } catch (passwordError) {
      for (const [id, key] of Object.entries(device?.vaultKeys ?? {})) {
        try {
          opened = openVault(wasm, key, container);
          secret = key;
          vid = id;
          break;
        } catch {
          // not this vault's key — try the next one
        }
      }
      if (!opened) throw passwordError; // report the password failure
    }

    vault = opened;
    password = pw;
    sealSecret = secret;
    activeVaultId = vid;
    // ⭐ Also on OPEN, not only on write: a vault that was already oversized
    // (imported on another client and pulled here) would otherwise stay silent
    // until the user happened to add something.
    showSizeWarning(opBodySizeWarning(container.length));
    renderSharing();
    $("unlock-pw").value = "";
    unlocked();
    if (device) void refreshEntitlement();
  } catch (e) {
    vault = null;
    password = "";
    sealSecret = "";
    activeVaultId = null;
    say(`Could not unlock: ${err(e)}`, "error");
  }
});

$("lock").addEventListener("click", lock);

$("destroy").addEventListener("click", async () => {
  await chrome.storage.local.remove([STORAGE_KEY, DEVICE_KEY]);
  password = "";
  sealSecret = "";
  activeVaultId = null;
  vault = null;
  device = null;
  renderDevice();
  show("setup");
  say("Sealed vault deleted.");
});

// ⭐ The `max` affordance comes from the SAME constant the gate uses. Written in
// JS rather than in the markup so `600` exists in exactly one place.
$("add-period").max = String(MAX_PERIOD);

$("add-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const label = $("add-label").value.trim();
    const issuer = $("add-issuer").value.trim();
    // ⭐⭐ THE PROVISIONING GATE, ON THE ADD-BY-FORM DOOR TOO (Phase 63 fix).
    //
    // ⛔ This form reproduced the exact defect the phase exists to close: the
    // period box was `type=number min="1"` with NO max, so 4294967295 created a
    // "one-time" password whose code never changes, shown with an ordinary
    // countdown.
    //
    // ⭐ WHY THIS DOES NOT CONTRADICT THE CLI'S DELIBERATE `--period` EXEMPTION:
    // that exemption is for a flag an operator typed into a shell, where the
    // value sits in their history. A GUI form is a different trust surface — it
    // is where a phishing page's "helpful setup instructions" land, nobody
    // reviews it afterwards, and nothing here needs an unbounded period.
    //
    // ⭐ Routed through the SAME `validateProvisioning` as the URI / migration /
    // QR doors, so there is no fourth copy of the bounds. The `max` attribute
    // above is UX; THIS is the control.
    validateProvisioning(
      label,
      issuer || null,
      base32Decode($("add-secret").value).length,
      Number($("add-digits").value),
      Number($("add-period").value),
    );
    await withVault((d) => {
      // ⭐ Phase 61: refuses an account already in the vault by CONTENT, not by
      // label — so `work` at two different issuers is two accounts.
      addEntryCheckedOrThrow(d, {
        label,
        issuer: issuer || undefined,
        secretBytes: base32Decode($("add-secret").value),
        algorithm: $("add-alg").value,
        digits: Number($("add-digits").value),
        period: Number($("add-period").value),
      });
    });
    $("add-form").reset();
    $("add-digits").value = "6";
    $("add-period").value = "30";
    say(`Added ${label}.`);
  } catch (e) {
    say(err(e), "error");
  }
});

// ── Scan a QR code (Phase 63) ───────────────────────────────────────────────
//
// ⭐ NOTHING IS WRITTEN UNTIL THE USER CONFIRMS. A scanner that added on decode
// would mean pasting a screenshot from a hostile page silently creates an
// account. ADR 0050 established that one click must not destroy an account; the
// same reasoning forbids one glance creating one.
//
// ⛔ The unsupported branch is a REAL RENDERED STATE, not a disabled button: a
// control that exists and fails is a claim that is not true.
let qrPending = null;

function qrSay(message) {
  const el = $("qr-error");
  el.textContent = message;
  el.hidden = !message;
}

function qrShowPending(pending) {
  qrPending = pending;
  $("qr-summary").textContent = pending ? pending.summary : "";
  $("qr-preview").hidden = !pending;
}

async function qrScanBlob(blob) {
  qrSay("");
  qrShowPending(null);
  if (!blob) return;
  try {
    const found = await scanProvisioningImage(blob);
    // Parsing here runs the SAME provisioning gate the paste field runs, so a
    // hostile QR is refused before anything is even offered as addable.
    let summary;
    if (found.kind === "otpauth") {
      const e = parseOtpauthUri(found.text);
      summary =
        `${e.issuer ? e.issuer + ": " : ""}${e.label} — ` +
        `${e.algorithm.toUpperCase()}, ${e.digits} digits, every ${e.period}s`;
    } else {
      const batch = decodeMigrationUri(found.text);
      const n = batch.entries.length;
      summary = `a Google Authenticator export carrying ${n} account${n === 1 ? "" : "s"}`;
    }
    qrShowPending({ kind: found.kind, text: found.text, summary });
  } catch (e) {
    qrSay(explainQrError(e));
  }
}

$("qr-file-input").addEventListener("change", async (ev) => {
  const file = ev.target.files && ev.target.files[0];
  ev.target.value = "";
  await qrScanBlob(file || null);
});

// ⭐ ON `document`, NOT ON THE SECTION — a paste event is dispatched at the
// FOCUSED element and BUBBLES UP; it never travels down into an unfocused
// subtree. A listener on the panel receives nothing when the user just presses
// ⌘V, which is the whole motion. (Measured: panel listener 0 hits, document
// listener every time.) Safe to listen this widely only because
// `imageFromEvent` returns null for a TEXT paste, so pasting an otpauth:// URI
// into the field below is untouched.
document.addEventListener("paste", async (ev) => {
  const blob = imageFromEvent(ev);
  if (!blob) return;
  ev.preventDefault();
  await qrScanBlob(blob);
});

$("qr-cancel").addEventListener("click", () => {
  qrSay("");
  qrShowPending(null);
});

$("qr-confirm").addEventListener("click", async () => {
  if (!qrPending) return;
  const pending = qrPending;
  try {
    if (pending.kind === "otpauth") {
      const entry = parseOtpauthUri(pending.text);
      let res;
      await withVault((d) => {
        res = mergeEntries(d, [entry]);
        if (res.added === 0) throw new Error("this exact account is already in the vault");
      });
      qrShowPending(null);
      say(`Added ${entry.label}.`);
    } else {
      const batch = decodeMigrationUri(pending.text);
      let added = 0;
      await withVault((d) => {
        added = mergeEntries(d, batch.entries).added;
      });
      qrShowPending(null);
      const base = `Imported ${added} of ${batch.entries.length} account(s).`;
      if (batch.batchNote && !batch.finalBatch) {
        say(
          `${base} ⚠️ THIS IMPORT IS INCOMPLETE — ${batch.batchNote}. Import the remaining ` +
            `QR code(s) before deleting anything from the old app.`,
          "error",
        );
      } else {
        say(batch.batchNote ? `${base} ${batch.batchNote}.` : base);
      }
    }
  } catch (e) {
    qrSay(err(e));
  }
});

// The probe is a RUNTIME question — BarcodeDetector is absent in Firefox, in
// Safari and on Linux Chromium, and it is secure-context gated.
qrSupport()
  .then((supported) => {
    $("qr-probing").hidden = true;
    $("qr-supported").hidden = !supported;
    $("qr-unsupported").hidden = supported;
  })
  .catch(() => {
    $("qr-probing").hidden = true;
    $("qr-unsupported").hidden = false;
  });

$("uri-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const entry = parseOtpauthUri($("uri-input").value.trim());
    let res;
    await withVault((d) => {
      res = mergeEntries(d, [entry]);
      if (res.added === 0) throw new Error("this exact account is already in the vault");
    });
    $("uri-form").reset();
    say(`Added ${entry.label}.`);
  } catch (e) {
    say(err(e), "error");
  }
});

$("migration-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    // ⛔ ONE URI IS ONE QR CODE. A large Google Authenticator export spans
    // several; `batchNote` is non-null when more remain, and must be shown or a
    // user deletes the old app with most of their accounts still only there.
    const batch = decodeMigrationUri($("migration-input").value.trim());
    const entries = batch.entries;
    let added = 0;
    let skippedNames = [];
    await withVault((d) => {
      const res = mergeEntries(d, entries);
      added = res.added;
      skippedNames = res.skippedNames;
    });
    $("migration-form").reset();
    // ⭐ NAME the skips. "duplicates skipped" is exactly the message a user saw
    // when the label-keyed de-dup silently dropped their second `work` account.
    const base =
      `Imported ${added} of ${entries.length} account(s)` +
      (skippedNames.length
        ? `; already in this vault: ${skippedNames.join("; ")}.`
        : ".");
    if (batch.batchNote && !batch.finalBatch) {
      say(
        `${base} ⚠️ THIS IMPORT IS INCOMPLETE — ${batch.batchNote}. Import the remaining ` +
          `QR code(s) before deleting anything from the old app.`,
        "error",
      );
    } else if (batch.batchNote) {
      // ⭐ The FINAL QR of a multi-QR export. Still say which batch it was —
      // this popup keeps no record of earlier runs — but do NOT call a finished
      // import incomplete. A warning that cries wolf is one the next user
      // ignores when it is real.
      say(`${base} ${batch.batchNote}.`);
    } else {
      say(base);
    }
  } catch (e) {
    say(err(e), "error");
  }
});

/**
 * Append already-parsed TotpEntry objects to a draft vault, skipping accounts
 * ALREADY IN IT. Goes through addEntryChecked so the stored shape is exactly the
 * CLI's (base64 secret, lowercase algorithm, issuer omitted when absent).
 *
 * ⭐⭐ Phase 61 (CRITICAL 2): the skip test is the CONTENT FINGERPRINT, not the
 * label. It used to be `draft.entries.some((x) => x.label === e.label)`, so a
 * Google Authenticator export holding `work` at GitHub AND `work` at GitLab
 * imported ONE of them and silently dropped the other — two different accounts,
 * in the feature whose entire purpose is not losing accounts.
 *
 * Returns `{ added, skippedNames }`. ⭐ It NAMES the skips: a bare count is what
 * let that defect hide, because a user saw "skipped 1" and could not learn which.
 */
/** `addEntryChecked` that throws instead of returning false, for form handlers. */
function addEntryCheckedOrThrow(draft, input) {
  if (!addEntryChecked(wasm, draft, input)) {
    throw new Error("this exact account is already in the vault");
  }
  return draft;
}

function mergeEntries(draft, entries) {
  let added = 0;
  const skippedNames = [];
  for (const e of entries) {
    const ok = addEntryChecked(wasm, draft, {
      label: e.label,
      issuer: e.issuer,
      secretBytes: base64ToBytes(e.secret),
      algorithm: e.algorithm,
      digits: e.digits,
      period: e.period,
    });
    if (ok) added++;
    else skippedNames.push(e.issuer ? `${e.issuer}: ${e.label}` : e.label);
  }
  return { added, skippedNames };
}

$("export-uris").addEventListener("click", () => {
  try {
    showExport(vault.entries.map(buildOtpauthUri).join("\n"));
  } catch (e) {
    say(err(e), "error");
  }
});

$("export-migration").addEventListener("click", () => {
  try {
    showExport(encodeMigrationUri(vault.entries));
  } catch (e) {
    say(err(e), "error");
  }
});

function showExport(text) {
  const out = $("export-out");
  out.value = text;
  out.hidden = false;
  say("Export shown below — it contains your secrets in the clear.", "error");
}

// ── sync (dev): sealed container to/from a local sigild op-log ───────────────
//
// Two modes, chosen automatically: with NO device identity the requests are
// unauthenticated (exactly as the sigil-wasm sync transport always behaved);
// with one enrolled they are signed under sigild's multi-device contract v3
// (the Ed25519 signature is computed IN THE WASM).

$("device-enroll").addEventListener("click", async () => {
  const token = $("device-token").value.trim();
  const label = $("device-label").value.trim();
  if (!token) return say("Paste the single-use enrollment token first.", "error");
  try {
    say("Enrolling this browser as a device…");
    // The seed is drawn here (CSPRNG) and passed INTO the wasm; the wasm draws none.
    const seed = generateDeviceSeed();
    const baseUrl = $("sync-url").value.trim();
    const enrolled = await enrollDevice(wasm, { baseUrl, token, label, seed });
    // Persist SEALED under the vault password — never the raw seed.
    await persistDevice({ deviceId: enrolled.deviceId, seed, baseUrl });
    $("device-token").value = ""; // single-use: drop it immediately
    // A client that only ever READS is never refused and never sees a warning
    // header, so the subscription route is its only warning channel. Read it.
    void refreshEntitlement();
    say(`Enrolled as ${enrolled.deviceId}.`);
  } catch (e) {
    say(`Enrollment failed: ${authErr(e)}`, "error");
  }
});

$("device-forget").addEventListener("click", async () => {
  await persistDevice(null);
  say("Device identity deleted. Sync is unauthenticated again.");
});

$("account-show").addEventListener("click", async () => {
  if (!device) return;
  try {
    say("Reading account…");
    const baseUrl = $("sync-url").value.trim();
    account = await getAccount(wasm, { ...device, baseUrl }, baseUrl);
    renderAccount();
    say(`Account ${account.account_id}.`);
  } catch (e) {
    account = null;
    renderAccount();
    // A 403 here is the server refusing a device whose account row is missing —
    // a real, repairable data state (`sigild migrate adopt`), not a crash.
    $("account-state").textContent = `Account unavailable: ${authErr(e)}`;
    say(`Account unavailable: ${authErr(e)}`, "error");
  }
});

$("sync-push").addEventListener("click", async () => {
  // ⚠️ Declared OUTSIDE the try so the size warning survives the FAILURE path
  // too — a 413 is exactly where it matters, and "Push failed" alone tells the
  // user nothing about why or what to do.
  let sizeWarn = null;
  try {
    say("Pushing…");
    $("entitlement-402").hidden = true;
    const got = await chrome.storage.local.get(STORAGE_KEY);
    const sealed = got[STORAGE_KEY];
    if (!sealed) throw new Error("no sealed vault to push");
    const container = base64ToBytes(sealed);
    const baseUrl = $("sync-url").value.trim();
    const vaultId = $("sync-vault").value.trim();
    // ⛔ THE TOMBSTONE GROWTH LIMIT. A vault is a 2P-Set: its remove-set never
    // shrinks, nothing prunes a tombstone, and past sigild's 64 KiB op cap the
    // push is a 413 with no supported way to shrink. Warn while there is still
    // room to act — meeting this first AT the 413 means sync is already gone.
    sizeWarn = opBodySizeWarning(container.length);
    // ⭐ THE GRACE CHANNEL. sigild sets X-Sigil-Entitlement* on a write it is
    // still SERVING inside the grace period — a 2xx — so that warning lives ONLY
    // in the response headers and never in a body or an error. Reading it here is
    // what turns a lapse into notice the user can act on, instead of a refusal
    // that arrives with none.
    let warn = null;
    const { seq } = device
      ? await pushContainerAuthed(wasm, device, baseUrl, vaultId, container, {
          onResponse: (res) => {
            warn = readEntitlementHeaders(res);
          },
        })
      : await pushContainer(baseUrl, vaultId, container);
    if (warn) {
      $("entitlement-402").textContent =
        `Subscription ${warn.status || "lapsed"} — uploading new changes stops` +
        `${warn.graceEndsAt ? ` on ${formatInstant(warn.graceEndsAt)}` : " soon"}. ` +
        `${NEVER_REFUSED}`;
      $("entitlement-402").hidden = false;
    }
    say(
      `Pushed sealed container as op #${seq}${device ? " (signed)" : ""}.` +
        (sizeWarn ? ` ⚠️ ${sizeWarn}` : ""),
    );
    // A successful sync means a reachable server, i.e. a free clock reference.
    // Take the reading here so a broken clock is found while doing something
    // else, long before the user is staring at a rejected login.
    void refreshClock();
  } catch (e) {
    // ⭐ A 402 is a BILLING state, not an auth failure and not a bug: the server
    // authenticated AND authorized this device and then asked for payment.
    // Rendering it as "unauthorized" would send the user to debug a key that is
    // working perfectly, and would imply a loss of access that has not happened.
    const pay = paymentRequiredFrom(e, "Push");
    if (pay) {
      const note = describePaymentRequired(pay);
      $("entitlement-402").textContent = `${note.headline} ${note.detail}`;
      $("entitlement-402").hidden = false;
      say("Push was refused pending payment. Nothing else changed.");
      return;
    }
    say(`Push failed: ${authErr(e)}${sizeWarn ? ` ⚠️ ${sizeWarn}` : ""}`, "error");
  }
});

$("sync-pull").addEventListener("click", async () => {
  try {
    say("Pulling…");
    const baseUrl = $("sync-url").value.trim();
    const vaultId = $("sync-vault").value.trim();
    const ops = device
      ? await pullContainersAuthed(wasm, device, baseUrl, vaultId, 0)
      : await pullContainers(baseUrl, vaultId, 0);
    if (ops.length === 0) return say("No ops on the server for that vault id.");
    // ⭐⭐ MERGE EVERY OP — do NOT adopt `ops[ops.length - 1]`.
    //
    // ⛔ This used to take the newest op and write it over the stored container.
    // If a laptop that had never pulled pushed after this browser did, the
    // laptop's snapshot was the tip, it had never seen this browser's accounts,
    // and one click destroyed them — with both devices reporting success.
    if (!vault) return say("Unlock the vault first — a merge needs to open it.", "error");
    const res = mergeOpsInto(wasm, sealSecret, vault, ops);
    // ⚠️ REPLACE the vault wholesale — do NOT copy `entries`/`tombstones` onto a
    // clone of the old one. `mergeVaults` already carried every unknown top-level
    // field forward (ADR 0047), and a field-by-field copy would throw away
    // exactly what a NEWER client wrote — the same defect `cloneVault` exists to
    // prevent, one level up.
    await replaceVault(res.vault);
    const skipNote = res.skipped.length
      ? ` ⚠️ ${res.skipped.length} op(s) could not be opened with this vault's secret and were NOT merged (${res.skipped
          .map((x) => `#${x.seq}`)
          .join(", ")}) — they are still on the server.`
      : "";
    say(
      `Merged ${res.applied} op(s) through #${res.tip}. ${res.added} account(s) added, ` +
        `${res.removed} removed by a delete from another device. ` +
        `${res.vault.entries.length} account(s) now.${skipNote}`,
    );
    void refreshClock();
  } catch (e) {
    say(`Pull failed: ${authErr(e)}`, "error");
  }
});

// ── clock skew (the DIAGNOSTIC) ─────────────────────────────────────────────
//
// ⛔ A TOTP code rejected because this device's clock drifted is
// INDISTINGUISHABLE, to the user, from a wrong secret — so they re-scan the QR,
// re-import the export, delete and re-add the account, and none of it helps.
// Nothing in this product reported it until now.
//
// ⛔⛔ IT REPORTS. IT NEVER CORRECTS. `nowSeconds()` still drives every code from
// this device's own system clock. A code generated against a server-supplied
// time is one the user cannot reproduce, cannot compare against any other
// authenticator, and cannot reason about when the server is wrong or hostile.
//
// ⭐ "unavailable" is rendered as NO READING, never as "your clock is fine".
async function refreshClock() {
  const el = $("clock-status");
  if (!el) return;
  let reading;
  try {
    reading = await fetchClockSkew({ baseUrl: $("sync-url").value.trim() }, nowSeconds());
  } catch (e) {
    reading = { state: "unavailable", reason: err(e) };
  }
  el.dataset.state = reading.state;
  el.textContent = describeClockSkew(reading);
  el.className = reading.state === "skewed" ? "warn" : "hint";
}

$("clock-check").addEventListener("click", () => {
  void refreshClock();
});

// ── sharing (dev): device-to-device vault sharing ───────────────────────────
//
// The key model, mirrored exactly from the `sigil vault ...` CLI:
//
//   * a PERSONAL vault stays sealed under the human password. The password is
//     NEVER shared, NEVER wrapped, and never leaves this browser.
//   * a SHARED vault is sealed under a RANDOM 32-byte VAULT KEY. "Convert to
//     shared" is the one-way door between the two (the CLI's `vault rekey`).
//   * that vault key is WRAPPED to each recipient device's published HYBRID
//     public key (X25519 + ML-KEM-768) into an opaque SIGILhyb envelope the
//     server relays and cannot read.
//
// STORAGE: the hybrid SECRET identity and every vault key live INSIDE the
// password-sealed device-identity container (DEVICE_KEY), exactly like the device
// seed. Nothing new is ever written to chrome.storage.local in the clear.
//
// The construction is a CUSTOM KEM-then-AEAD, NOT RFC 9180 HPKE; the system is
// NOT "post-quantum secure". Pre-audit / UNAUDITED / DEV.

/** The auth context every sharing call takes: this device plus its server. */
function sharingAuth() {
  if (!device) throw new Error("enroll this browser as a device first (Sync above)");
  return { ...device, baseUrl: $("sync-url").value.trim() };
}

/**
 * ⭐ PHASE 60. A vault-key envelope is now AUTHENTICATED with the SENDING device's
 * long-term hybrid secret, and the recipient checks it against the PUBLISHED
 * public half — so wrapping a key requires this browser to have a hybrid identity
 * AND to have published it. Before Phase 60 a wrap needed only the recipient's
 * public key, which is exactly why anybody else could mint one. Create + publish
 * on demand rather than failing with "publish first": the user did not choose to
 * care about this.
 *
 * Returns the hybrid SECRET identity (never logged, never persisted in the clear
 * — `persistDevice` re-seals it into the device-identity container).
 */
async function ensurePublishedHybrid() {
  if (device.hybrid) return device.hybrid;
  const hybrid = generateHybridIdentity();
  await persistDevice({ ...device, hybrid });
  await publishHybridKey(wasm, { ...sharingAuth(), hybrid });
  return hybrid;
}

/** The vault id the Sharing panel operates on (shared with the Sync panel). */
function sharingVaultId() {
  const id = $("sync-vault").value.trim();
  if (!id) throw new Error("set a vault id first (Sync → Vault id)");
  return id;
}

$("sharing-publish").addEventListener("click", async () => {
  try {
    say("Publishing this device's hybrid key…");
    const auth = sharingAuth();
    // Create the hybrid identity on first use and SEAL it under the password.
    const hybrid = device.hybrid ?? generateHybridIdentity();
    await persistDevice({ ...device, hybrid });
    await publishHybridKey(wasm, { ...sharingAuth(), hybrid });
    say(`Published the hybrid public key for ${auth.deviceId}. Others can now share vaults to it.`);
  } catch (e) {
    say(`Publish failed: ${sharingErr(e)}`, "error");
  }
});

$("sharing-convert").addEventListener("click", async () => {
  try {
    if (!vault) throw new Error("vault is locked");
    if (!device) throw new Error("enroll this browser as a device first (Sync above)");
    const id = sharingVaultId();
    say("Re-sealing under a fresh random vault key…");
    const key = generateVaultKey();
    // Seal the key FIRST (inside the device container), then re-seal the vault.
    await persistDevice({ ...device, vaultKeys: { ...(device.vaultKeys ?? {}), [id]: key } });
    await persist(vault, key);
    sealSecret = key;
    activeVaultId = id;
    renderSharing();
    const fp = await vaultKeyFingerprint(key);
    say(
      `Vault "${id}" is now sealed under a random 32-byte vault key (sha256 ${fp}). ` +
        "Your password no longer opens it and was never shared. Push it, then share it.",
    );
  } catch (e) {
    say(`Convert failed: ${sharingErr(e)}`, "error");
  }
});

$("sharing-share").addEventListener("click", async () => {
  try {
    const auth = sharingAuth();
    const id = sharingVaultId();
    const to = $("sharing-recipient").value.trim();
    if (!to) throw new Error("paste the recipient's device id");
    const key = device.vaultKeys?.[id];
    if (!key) throw new Error(`vault "${id}" is not shared yet — convert it to a shared vault first`);
    say("Wrapping the vault key and sharing…");
    hidePinMismatch();
    hideEnvelopeRefusal();
    // shareVault goes through the PIN CHOKE POINT: an unchanged key proceeds, a
    // CHANGED key throws KeyPinMismatchError and nothing is wrapped or uploaded.
    const hybrid = await ensurePublishedHybrid();
    const res = await shareVault(wasm, { ...auth, hybrid }, {
      vaultId: id,
      recipientDeviceId: to,
      vaultKey: key,
      // ⚠️ EXPLICIT, and it was MISSING. `requirePinStore` FAILS CLOSED, and a
      // popup that has never pinned anything has no store — so the FIRST share
      // from a fresh profile died with "a pin store is required" instead of
      // pinning the recipient on first sight. Passing the empty store is the
      // documented way to say "no pins yet"; it starts the check, not skips it.
      pins: device.pins ?? newPinStore(),
      permission: $("sharing-permission").value === "write" ? "write" : "read",
      // Checked BEFORE anything is wrapped. Blank = not supplied; the wrap gate
      // still REFUSES a first-sight recovery kit without it.
      expectedSafetyNumber: $("sharing-share-safety").value.trim() || null,
    });
    // Persist the (possibly newly-pinned) store INSIDE the sealed container.
    await persistDevice({ ...device, pins: res.pins });
    $("sharing-safety-number").textContent = `Safety number for ${to}: ${res.safetyNumber}`;
    say(
      `Shared "${id}" with ${to} (${res.permission}): a ${res.envelopeBytes}-byte envelope the ` +
        `server relays but cannot read. Key sha256 ${res.fingerprint}. ` +
        (res.pinStatus === "first-sight"
          ? "FIRST CONTACT — the key was just pinned but NOT verified by a human. Read the safety " +
            "number to its owner over a trusted channel and check it matches."
          : "That device's key matches the one pinned earlier."),
    );
  } catch (e) {
    if (showPinMismatch(e)) return;
    say(`Share failed: ${sharingErr(e)}`, "error");
  }
});

// ── Phase 50: safety numbers, the pin alarm, and rotation ───────────────────

/** Hide the key-change alarm and re-enable sharing. */
function hidePinMismatch() {
  const box = $("sharing-pin-mismatch");
  if (box) box.hidden = true;
  pendingRepin = null;
}

/** The device whose key changed, awaiting a DELIBERATE re-pin. */
let pendingRepin = null;

/**
 * ⭐ THE ALARM. A changed hybrid key is not a generic failure: it is either a
 * key-substitution attack or a legitimate re-enrolment, and only a human can tell
 * which. Show both numbers and BLOCK until they act.
 */
function showPinMismatch(e) {
  if (!(e instanceof KeyPinMismatchError)) return false;
  pendingRepin = e.deviceId;
  const box = $("sharing-pin-mismatch");
  $("sharing-pin-mismatch-text").textContent =
    `REFUSED — the hybrid public key for ${e.deviceId} has CHANGED. Nothing was shared and no ` +
    `key was wrapped. This is either a KEY-SUBSTITUTION ATTACK (a hostile or compromised server ` +
    `swapping in a key it can decrypt with) or a LEGITIMATE RE-ENROLMENT of that device. ` +
    `pinned: ${e.pinnedSafetyNumber} — presented: ${e.presentedSafetyNumber}. ` +
    `Read the presented digits to its owner over a channel the server does not control.`;
  box.hidden = false;
  say(`Share REFUSED: ${e.deviceId}'s key changed. Nothing was shared.`, "error");
  return true;
}

$("sharing-my-safety").addEventListener("click", async () => {
  try {
    if (!device) throw new Error("enroll this browser as a device first (Sync above)");
    if (!device.hybrid) throw new Error("publish this device's hybrid key first");
    const pub = hybridPublicIdentity(wasm, device.hybrid);
    const sn = await safetyNumber(device.deviceId, pub);
    $("sharing-safety-number").textContent = `This device (${device.deviceId}): ${sn}`;
    say(
      "Read these digits to anyone about to share a vault with you, over a channel the server " +
        "does not control. Nothing was sent — this is derived from local key material.",
    );
  } catch (e) {
    say(`Safety number failed: ${sharingErr(e)}`, "error");
  }
});

$("sharing-their-safety").addEventListener("click", async () => {
  try {
    const auth = sharingAuth();
    const to = $("sharing-recipient").value.trim();
    if (!to) throw new Error("paste the recipient's device id");
    const identity = await fetchHybridKey(wasm, auth, to);
    const sn = await safetyNumber(to, identity);
    $("sharing-safety-number").textContent = `${to}: ${sn}`;
    const pinned = device.pins?.pins?.[to]?.safety_number;
    say(
      pinned
        ? pinned === sn
          ? `This matches the key already pinned for ${to}.`
          : `This does NOT match the key pinned for ${to} (${pinned}). Sharing will be REFUSED.`
        : `${to} is not pinned yet. Confirm these digits with its owner over a trusted channel ` +
            "BEFORE the first share.",
      pinned && pinned !== sn ? "error" : undefined,
    );
  } catch (e) {
    say(`Safety number failed: ${sharingErr(e)}`, "error");
  }
});

// ⚠️ The deliberate escape hatch. Only reachable after a mismatch BLOCKED a
// share, and only by an explicit click on a button that says what it means.
$("sharing-repin").addEventListener("click", async () => {
  try {
    if (!pendingRepin) throw new Error("nothing to re-pin");
    const auth = sharingAuth();
    const identity = await fetchHybridKey(wasm, auth, pendingRepin);
    const pins = device.pins ?? newPinStore();
    const res = await repinHybridKey(pins, pendingRepin, identity);
    await persistDevice({ ...device, pins });
    const who = pendingRepin;
    hidePinMismatch();
    say(
      `Re-pinned ${who}. This client now trusts ${res.safetyNumber} for that device. If you did ` +
        "not verify those digits with its owner out of band, that was a mistake.",
    );
  } catch (e) {
    say(`Re-pin failed: ${sharingErr(e)}`, "error");
  }
});

$("sharing-rotate").addEventListener("click", async () => {
  try {
    const auth = sharingAuth();
    const id = sharingVaultId();
    const key = device.vaultKeys?.[id];
    if (!key) throw new Error(`vault "${id}" is not a shared vault`);
    const recipients = $("sharing-rotate-to")
      .value.split(/[\s,]+/)
      .map((x) => x.trim())
      .filter(Boolean);
    if (recipients.length === 0) {
      throw new Error("list every device id that KEEPS access (comma or space separated)");
    }
    // ⭐ THE DROP LIST. rotateVaultKey REFUSES to delete an envelope its caller
    // did not name, and this popup used to pass none — so any rotation that
    // actually excluded somebody, which is the whole point of rotating, threw
    // with no way through. "Remove every other device" resolves the list from
    // the server so the destruction is still stated, just not retyped.
    const drop = $("sharing-rotate-drop")
      .value.split(/[\s,]+/)
      .map((x) => x.trim())
      .filter(Boolean);
    if ($("sharing-rotate-drop-all").checked) {
      for (const holder of await listKeyEnvelopes(wasm, auth, id)) {
        if (!recipients.includes(holder.deviceId) && !drop.includes(holder.deviceId)) {
          drop.push(holder.deviceId);
        }
      }
    }
    // "dev_x=12345 …" pairs, so a recovery kit among the recipients can be
    // verified against its printed sheet before anything is wrapped.
    const safetyNumbers = {};
    for (const entry of $("sharing-rotate-safety").value.split(",")) {
      const at = entry.indexOf("=");
      if (at > 0) safetyNumbers[entry.slice(0, at).trim()] = entry.slice(at + 1).trim();
    }
    const stored = (await chrome.storage.local.get(STORAGE_KEY))[STORAGE_KEY];
    if (!stored) throw new Error("no sealed vault in this browser to rotate");
    say("Rotating the vault key and re-wrapping…");
    const hybrid = await ensurePublishedHybrid();
    const res = await rotateVaultKey(wasm, { ...auth, hybrid }, {
      vaultId: id,
      // ⚠️ EXPLICIT for the same reason as the share above.
      pins: device.pins ?? newPinStore(),
      recipientDeviceIds: recipients,
      sealedVault: base64ToBytes(stored),
      oldVaultKey: key,
      params: ARGON2,
      drop,
      safetyNumbers,
    });
    await persistDevice({
      ...device,
      pins: res.pins,
      vaultKeys: { ...(device.vaultKeys ?? {}), [id]: res.vaultKey },
    });
    await chrome.storage.local.set({ [STORAGE_KEY]: bytesToBase64(res.sealedVault) });
    sealSecret = res.vaultKey;
    say(
      `Rotated "${id}": ${res.oldFingerprint} -> ${res.newFingerprint}. Re-wrapped to ` +
        `${res.rewrapped.map((r) => r.deviceId).join(", ")}` +
        (res.removed.length > 0 ? `; deleted the envelope of ${res.removed.join(", ")}` : "") +
        ". Push the vault so the remaining devices get the new content. This protects FUTURE " +
        "content only — a device that already unwrapped the old key keeps what it copied.",
    );
  } catch (e) {
    if (showPinMismatch(e)) return;
    say(`Rotate failed: ${sharingErr(e)}`, "error");
  }
});

$("sharing-accept").addEventListener("click", async () => {
  try {
    const auth = sharingAuth();
    const id = sharingVaultId();
    say("Collecting and unwrapping the shared vault key…");
    // ⚠️ READ THE OPT-IN BEFORE clearing the refusal — hideEnvelopeRefusal
    // deliberately un-ticks the box so it can never authorize a LATER accept.
    const replace = $("sharing-accept-replace").checked;
    hideEnvelopeRefusal();
    // ⭐ PHASE 60. This used to unwrap ANYTHING that decrypted to 32 bytes, from
    // anybody — it fetched no hybrid key, so the pin store was never consulted
    // on the accept path at all. It now resolves the DEPOSITING device (named
    // here, else from this device's self-only envelope index), pin-checks that
    // device's key, and refuses anything that is not an AUTHENTICATED version-2
    // envelope bound to (this vault, this device, that sender).
    const from = $("sharing-accept-from").value.trim();
    const accepted = await acceptVault(wasm, auth, {
      vaultId: id,
      senderDeviceId: from || null,
      expectedSafetyNumber: $("sharing-share-safety").value.trim() || null,
      // ⚠️ EXPLICIT, because `requirePinStore` FAILS CLOSED. A browser that has
      // only ever RECEIVED has never pinned anything, and an absent store is a
      // caller bug rather than "everything is first-sight" — so the empty store
      // has to be stated. Empty means the sender is first sight: honest TOFU,
      // exactly like the CLI's empty pin file. It does not skip the check.
      pins: device.pins ?? newPinStore(),
      // ⭐ PHASE 60 SYMMETRY, steps 4 and 5 of the CLI's `accept_vault_key`.
      // `heldKeys` FAILS CLOSED exactly like `pins`, and it is what stops an
      // accept silently REPLACING a key this browser depends on; `replace` is
      // the deliberate opt-in the refusal alert below offers. Both checks run
      // INSIDE acceptVault — this call site only supplies the facts it alone
      // knows, so the control cannot be lost by forgetting it here.
      heldKeys: device.vaultKeys ?? {},
      replace,
    });
    // Seal the recovered key immediately, so a failed pull cannot lose it — and
    // the newly-pinned SENDER with it, or the next accept treats that device as
    // first sight all over again. By this point acceptVault has already PROVED
    // the key opens the vault (or that there is nothing to open) and that it is
    // not quietly displacing another.
    await persistDevice({
      ...device,
      vaultKeys: { ...(device.vaultKeys ?? {}), [id]: accepted.vaultKey },
      pins: accepted.pins,
    });
    $("sharing-safety-number").textContent =
      `Sender ${accepted.senderDeviceId} (${accepted.senderTrust}): ${accepted.senderSafetyNumber}`;

    const replacedNote = accepted.replaced
      ? ` It REPLACED the key sha256 ${accepted.replaced} this browser held — anything sealed ` +
        `under that key and not re-sealed under this one is no longer readable here.`
      : "";
    // ⭐ No second pull. `acceptVault` already fetched the newest op to prove the
    // key opens it, and hands those exact bytes back — so the vault is adopted
    // from the container the check ran against, not from a later one.
    if (!accepted.verifiedAgainstTip || !accepted.tipContainer) {
      say(
        `Accepted the vault key for "${id}" (sha256 ${accepted.fingerprint}) and sealed it locally, ` +
          "but the server holds no vault yet — ask the owner to push." +
          replacedNote,
      );
      return;
    }
    const container = accepted.tipContainer;
    const opened = openVault(wasm, accepted.vaultKey, container); // throws before storing
    await chrome.storage.local.set({ [STORAGE_KEY]: bytesToBase64(container) });
    vault = opened;
    sealSecret = accepted.vaultKey;
    activeVaultId = id;
    renderSharing();
    render();
    say(
      `Accepted and opened the shared vault "${id}" — ${opened.entries.length} account(s). ` +
        `Key sha256 ${accepted.fingerprint}: compare it with the sender out of band. ` +
        `AUTHENTICATED as coming from ${accepted.senderDeviceId} (${accepted.senderTrust}).` +
        replacedNote,
    );
  } catch (e) {
    if (showEnvelopeRefusal(e)) return;
    if (showPinMismatch(e)) return;
    say(`Accept failed: ${sharingErr(e)}`, "error");
  }
});

// ── recovery kit (dev) ───────────────────────────────────────────────────────
//
// ⚠️⚠️ THE KIT IS A CREDENTIAL, stronger than a stolen locked phone: whoever
// holds the 56 characters has full control of the account. It is put into the
// DOM ONCE, is never written to chrome.storage.local, never logged, never placed
// in a URL, and is cleared the moment the user confirms they have written it
// down. Everything cryptographic happens in the vendored, proven recovery.mjs
// (which itself only calls the wasm); this file is UI glue.

/** Classify a recovery failure into the things a user can actually act on. */
function recoveryErr(e) {
  const status = e && typeof e.status === "number" ? e.status : 0;
  if (status >= 400) return explainRecoveryStatus(status);
  // ⭐ PHASE 60, said in its own words on the recovery path too: an envelope
  // that proves nothing about who produced it is neither a 401 nor a 403 nor a
  // changed key, and it must never be collapsed into a generic failure.
  if (e instanceof UnauthenticatedEnvelopeError) {
    return (
      `That vault-key envelope is NOT AUTHENTICATED (SIGILhyb version ${e.foundVersion}; a vault ` +
      `key must be version ${e.expectedVersion}). It carries no sender, so anyone who could read ` +
      "this kit's published hybrid public key could have minted it — accepting it would install a " +
      "vault key an attacker chose. Nothing was opened and nothing was stored. Ask the vault's " +
      "owner to re-issue the kit's envelopes (sigil recovery cover, or Cover in the app)."
    );
  }
  if (e instanceof UnknownSenderError) {
    return (
      "Nothing says which device deposited that vault key, so there is nothing to authenticate it " +
      "against. Nothing was opened and nothing was stored."
    );
  }
  const text = err(e);
  if (/unsupported recovery kit version/i.test(text)) {
    return (
      "This kit was printed by a NEWER version of Sigil: the code itself is intact (its checksum " +
      "is correct) but this build does not understand its format version. Update this extension; " +
      "do not retype the code."
    );
  }
  if (/not a valid recovery code/i.test(text)) {
    return (
      "That is not a valid recovery code — check for a mistyped character. Nothing was sent " +
      "anywhere: the code is checked on this device before any request. Hyphens, spaces and case " +
      "do not matter; the letters I, L and O are never used (read them as 1, 1 and 0) and U is " +
      "never used at all."
    );
  }
  if (/nothing to recover/i.test(text)) {
    return (
      "Valid kit, but it covers NOTHING on this server: the code and device id are correct and " +
      "the server knows this kit, it just holds no vault key for it. The kit was enrolled but " +
      "never covered a vault, or a rotation dropped it."
    );
  }
  return text;
}

/** The wrap gate refused, or a supplied number did not match. Say which. */
function wrapGateErr(e) {
  if (e instanceof UnverifiedRecoveryKitError) {
    $("recovery-unverified").textContent =
      `REFUSED — ${e.deviceId} is a recovery kit this browser has never seen. Nothing was ` +
      `wrapped and nothing was uploaded. The only thing vouching for that kit's key is the ` +
      `server, and a hostile server that substituted its own key would be handed this vault's ` +
      `key. THE SAFETY NUMBER IS PRINTED ON THE RECOVERY SHEET — compare it with these digits ` +
      `out of band, then type it in and try again. From server: ${e.presentedSafetyNumber}`;
    $("recovery-unverified").hidden = false;
    return true;
  }
  if (e instanceof SafetyNumberMismatchError) {
    $("recovery-unverified").textContent =
      `REFUSED — the safety number you typed does not match the key this server is serving for ` +
      `${e.deviceId}. You typed ${e.expectedSafetyNumber}; the server presented ` +
      `${e.presentedSafetyNumber}. Either it was mistyped, or the server substituted a key it can ` +
      `decrypt with. Nothing was wrapped, nothing uploaded, no key pinned.`;
    $("recovery-unverified").hidden = false;
    return true;
  }
  return false;
}

$("recovery-generate").addEventListener("click", async () => {
  try {
    const auth = sharingAuth();
    say("Generating a recovery kit…");
    $("recovery-unverified").hidden = true;
    const vaultKeys = Object.entries(device.vaultKeys ?? {}).map(([vaultId, vaultKey]) => ({
      vaultId,
      vaultKey,
    }));
    const pins = device.pins ?? newPinStore();
    const hybrid = await ensurePublishedHybrid();
    const res = await generateRecoveryKit(wasm, { ...auth, hybrid }, { vaultKeys, pins });
    // Persist the DERIVED pin (and nothing else) inside the sealed container.
    await persistDevice({ ...device, pins: res.pins });

    $("recovery-code").textContent = res.formatted;
    $("recovery-kit-id").textContent = res.deviceId;
    $("recovery-account").textContent = res.accountId;
    $("recovery-server").textContent = res.baseUrl;
    $("recovery-safety").textContent = res.safetyNumber;
    $("recovery-covered").textContent = res.covered.length
      ? res.covered.map((c) => c.vaultId).join(", ")
      : "NONE";
    $("recovery-covers-nothing").hidden = res.covered.length > 0;
    $("recovery-written").checked = false;
    $("recovery-hide").disabled = true;
    $("recovery-sheet").hidden = false;
    renderRecovery();
    say(
      `Kit ${res.deviceId} created in account ${res.accountId} and verified end to end — it ` +
        `re-derived its own identity from the printed code, authenticated, and unwrapped ` +
        `${res.verification.unwrappedVault || "no vault"}. Write the code down NOW.`,
    );
  } catch (e) {
    say(`Generating a recovery kit failed: ${recoveryErr(e)}`, "error");
  }
});

$("recovery-written").addEventListener("change", () => {
  $("recovery-hide").disabled = !$("recovery-written").checked;
});

$("recovery-hide").addEventListener("click", () => {
  // ⭐ USED — clear it from the DOM. Nothing about it was ever persisted.
  $("recovery-code").textContent = "";
  $("recovery-sheet").hidden = true;
  $("recovery-written").checked = false;
  $("recovery-hide").disabled = true;
  renderRecovery();
  say(
    "The recovery code has been cleared from this screen and was never stored. If you did not " +
      "write it down, generate a new kit and revoke the old one.",
  );
});

$("recovery-print").addEventListener("click", () => window.print());

$("recovery-copy").addEventListener("click", async () => {
  await copy($("recovery-code").textContent ?? "");
  say(
    "Copied to the clipboard — which other applications can read. Paste it into whatever will " +
      "hold it, then clear your clipboard.",
    "error",
  );
});

$("recovery-cover").addEventListener("click", async () => {
  try {
    const auth = sharingAuth();
    const id = sharingVaultId();
    const to = $("recovery-kit").value.trim();
    if (!to) throw new Error("paste the kit's device id (it is printed on the sheet)");
    const key = device.vaultKeys?.[id];
    if (!key) {
      throw new Error(
        `vault "${id}" is still a PERSONAL vault sealed with your password. A recovery kit can ` +
          "only be given a vault KEY, so convert it to a shared vault first (Sharing above).",
      );
    }
    $("recovery-unverified").hidden = true;
    say("Wrapping this vault's key to the kit…");
    const hybrid = await ensurePublishedHybrid();
    const res = await coverVault(wasm, { ...auth, hybrid }, {
      kitDeviceId: to,
      vaultId: id,
      vaultKey: key,
      pins: device.pins ?? newPinStore(),
      expectedSafetyNumber: $("recovery-cover-safety").value.trim() || null,
    });
    await persistDevice({ ...device, pins: res.pins });
    say(
      `Vault "${id}" is now covered by kit ${to} — a ${res.envelopeBytes}-byte envelope the ` +
        `server relays but cannot read (key sha256 ${res.fingerprint}). ` +
        (res.derived
          ? "The kit's key was derived locally by this browser, so nothing was fetched and " +
            "nothing could have been substituted."
          : "The kit's key came from the server and matched the safety number you supplied."),
    );
  } catch (e) {
    if (wrapGateErr(e)) {
      say("Cover REFUSED: that kit's key is not verified. Nothing was wrapped.", "error");
      return;
    }
    say(`Cover failed: ${recoveryErr(e)}`, "error");
  }
});

$("recovery-check").addEventListener("click", async () => {
  try {
    const auth = sharingAuth();
    say("Checking recovery…");
    const acct = await getAccount(wasm, device, auth.baseUrl);
    const kits = (acct.devices ?? []).filter((d) => d.label === RECOVERY_DEVICE_LABEL);
    const lines = [];
    let covered = 0;
    const vaultIds = Object.keys(device.vaultKeys ?? {});
    for (const v of vaultIds) {
      let holders = [];
      try {
        holders = (await listKeyEnvelopes(wasm, auth, v))
          .map((h) => h.deviceId)
          .filter((d) => kits.some((k) => k.device_id === d));
      } catch (e) {
        lines.push(`${v}: could not be checked (${sharingErr(e)})`);
        continue;
      }
      if (holders.length) covered++;
      lines.push(holders.length ? `${v}: covered by ${holders.join(", ")}` : `${v}: NOT covered`);
    }
    const el = $("recovery-coverage");
    el.textContent =
      (kits.length === 0
        ? "Recovery: NOT SET UP — this account has no recovery kit. If every device is lost, the " +
          "account and its vaults are unreachable, by you and by us, and a kit cannot be created " +
          "after the fact. "
        : `Recovery: ${kits.length} kit(s) enrolled (${kits
            .map((k) => `${k.device_id} ${k.status ?? "active"}`)
            .join("; ")}). `) +
      (vaultIds.length
        ? `${covered} of ${vaultIds.length} vault(s) this browser holds a key for are covered. ` +
          lines.join(" · ")
        : "This browser holds no vault keys, so there is nothing to cover yet.");
    el.hidden = false;
    say(kits.length ? `${kits.length} recovery kit(s) enrolled.` : "Recovery is NOT set up.");
  } catch (e) {
    say(`Check failed: ${recoveryErr(e)}`, "error");
  }
});

$("recovery-revoke").addEventListener("click", async () => {
  try {
    const auth = sharingAuth();
    const to = $("recovery-revoke-kit").value.trim();
    if (!to) throw new Error("paste the kit's device id");
    say("Revoking the kit…");
    const res = await revokeRecoveryKit(wasm, auth, {
      kitDeviceId: to,
      vaultIds: Object.keys(device.vaultKeys ?? {}),
    });
    say(
      `Revoked kit ${to}; removed its envelope for ${
        res.removed.length ? res.removed.join(", ") : "no vault"
      }. ${res.rotateReminder}`,
      "error",
    );
  } catch (e) {
    say(`Revoke failed: ${recoveryErr(e)}`, "error");
  }
});

// ── restore from a printed kit, on a client with NO local state ─────────────
//
// ⭐ THE FLOW THAT MATTERS. It runs from the setup / locked screens because a
// user who lost every device is looking at a FRESH INSTALL: no vault, no device
// identity, no pin store, no keyring — only a sheet of paper.
//
// The code is decoded and checksummed OFFLINE before any network I/O, so a
// mistyped code never reaches a server. It is cleared from the form the moment
// it works, and NOTHING derived from it is stored except inside the SEALED
// device-identity container, under the new password.

$("restore-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const errBox = $("restore-error");
  errBox.hidden = true;
  const pw = $("restore-pw").value;
  if (pw.length < 8) {
    errBox.textContent = "Choose a password of at least 8 characters for this browser.";
    errBox.hidden = false;
    return;
  }
  if (pw !== $("restore-pw2").value) {
    errBox.textContent = "Those passwords do not match.";
    errBox.hidden = false;
    return;
  }
  try {
    const baseUrl = $("restore-url").value.trim();
    say("Checking the code on this device, then asking the server…");
    const res = await restoreFromKit(wasm, {
      baseUrl,
      code: $("restore-code").value,
      deviceId: $("restore-device").value.trim(),
    });

    const kitAuth = {
      deviceId: res.deviceId,
      seed: res.identity.ed25519Seed,
      baseUrl,
      hybrid: res.identity.hybrid,
    };

    // A kit recovers KEYS. The ciphertext still has to exist, so try each
    // recovered vault until one has content this key opens.
    const notes = res.skipped.map((s) => `${s.vaultId}: ${s.reason}`);
    let opened = null;
    let openedId = "";
    let openedKey = null;
    let openedContainer = null;
    for (const v of res.vaults) {
      try {
        const ops = await pullContainersAuthed(wasm, kitAuth, baseUrl, v.vaultId, 0);
        if (ops.length === 0) {
          notes.push(`${v.vaultId}: key recovered, but the server holds no vault content for it`);
          continue;
        }
        // ⭐ Phase 61: MERGE every op, do not adopt the tip. A restore is the one
        // path where the user cannot check the result against anything, so
        // reconstructing the UNION of every snapshot matters most here.
        const merged = mergeOpsInto(wasm, v.vaultKey, newVault(), ops);
        if (merged.applied === 0) {
          notes.push(
            `${v.vaultId}: ${merged.skipped.length} op(s) present but none opened with the recovered key`,
          );
          continue;
        }
        for (const sk of merged.skipped) {
          notes.push(`${v.vaultId}: op #${sk.seq} was not merged (${sk.reason})`);
        }
        const salt = crypto.getRandomValues(new Uint8Array(wasm.recommended_salt_len()));
        const nonce = crypto.getRandomValues(new Uint8Array(wasm.nonce_len()));
        const container = sealVault(
          wasm,
          v.vaultKey,
          merged.vault,
          salt,
          nonce,
          ratchetParams(wasm, ops[ops.length - 1].container, ARGON2),
        );
        opened = merged.vault;
        openedId = v.vaultId;
        openedKey = v.vaultKey;
        openedContainer = container;
        break;
      } catch (e) {
        notes.push(`${v.vaultId}: ${err(e)}`);
      }
    }
    if (!opened) {
      // Persist NOTHING: a half-restored profile is worse than a clean refusal,
      // and this is the documented limit — a kit recovers keys, not data.
      throw new Error(
        `the code and device id are valid and ${res.vaults.length} vault key(s) were recovered, ` +
          "but no vault content could be opened. A recovery kit recovers KEYS, not DATA: a vault " +
          "whose sealed container was never pushed to this server cannot come back." +
          (notes.length ? ` Details: ${notes.join("; ")}.` : ""),
      );
    }

    // ADOPT the kit. Keep every recovered vault key, and PIN the kit's own
    // hybrid key as DERIVED so a later cover from here wraps to a locally
    // derived key and never asks the server for one.
    const vaultKeys = {};
    for (const v of res.vaults) vaultKeys[v.vaultId] = v.vaultKey;
    // ⭐ PHASE 60: start from the store the restore itself built. Every envelope
    // it opened was AUTHENTICATED against its depositing device's key, and that
    // key was pinned in the process — dropping it here would make each of those
    // senders first-sight all over again on the next accept.
    const pins = res.pins ?? newPinStore();
    await pinDerivedKey(pins, res.deviceId, hybridPublicIdentity(wasm, res.identity.hybrid));

    password = pw;
    sealSecret = openedKey;
    activeVaultId = openedId;
    vault = opened;
    await persistDevice({
      deviceId: res.deviceId,
      seed: res.identity.ed25519Seed,
      baseUrl,
      hybrid: res.identity.hybrid,
      vaultKeys,
      pins,
    });
    await chrome.storage.local.set({ [STORAGE_KEY]: bytesToBase64(openedContainer) });

    // ⭐ USED — clear it from the form immediately.
    $("restore-code").value = "";
    $("restore-pw").value = "";
    $("restore-pw2").value = "";
    $("sync-url").value = baseUrl;
    $("sync-vault").value = openedId;
    renderSharing();
    unlocked();
    say(
      `Restored vault "${openedId}" — ${opened.entries.length} account(s) — from the printed kit. ` +
        "⚠️ THIS BROWSER IS NOW A SECOND COPY OF THAT PAPER: it holds the kit's keys. Keep the " +
        "sheet itself somewhere else." +
        (notes.length ? ` Not restored: ${notes.join("; ")}.` : ""),
      "error",
    );
  } catch (e) {
    errBox.textContent = recoveryErr(e);
    errBox.hidden = false;
    say("Restore failed.", "error");
  }
});

// ── entitlement (dev): read what the server says about payment ──────────────
//
// ⭐ THE MESSAGE MUST BE TRUE. sigild refuses WRITES only, only past grace, and
// never a key deposit to a device of the caller's OWN account. So this never says
// a billing state has cost the user their codes — it has not: codes are computed
// here, in the wasm, offline, from a vault this browser already holds.

async function refreshEntitlement() {
  const el = $("entitlement-state");
  if (!device) {
    el.hidden = true;
    return;
  }
  const baseUrl = $("sync-url").value.trim();
  try {
    const sub = await getSubscription(wasm, { ...device, baseUrl }, baseUrl);
    const state = entitlementState(sub);
    const note = describeEntitlement(state);
    if (note.tone === "none") {
      // A server that does not enforce payment says NOTHING. Inventing a warning
      // here would be inventing a state the server never reported.
      el.textContent = "This server does not enforce payment, so nothing here is gated.";
    } else {
      el.textContent = `${note.headline} ${note.detail}`;
    }
    el.dataset.tone = note.tone;
    el.hidden = false;
  } catch (e) {
    const status = e && typeof e.status === "number" ? e.status : 0;
    el.textContent = `Subscription unavailable: ${
      status ? explainSubscriptionStatus(status) : err(e)
    }`;
    el.dataset.tone = "none";
    el.hidden = false;
  }
}

$("entitlement-check").addEventListener("click", refreshEntitlement);

$("sync-vault").addEventListener("input", renderSharing);

window.addEventListener("unload", () => {
  if (ticker) clearInterval(ticker);
  password = "";
  sealSecret = "";
  activeVaultId = null;
  vault = null;
  device = null;
});

boot();
