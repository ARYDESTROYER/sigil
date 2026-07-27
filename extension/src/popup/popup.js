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
  codeForEntry,
  base32Decode,
  base64ToBytes,
  bytesToBase64,
} from "../../vendor/totp-vault.mjs";
import {
  parseOtpauthUri,
  buildOtpauthUri,
  decodeMigrationUri,
  encodeMigrationUri,
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
  newPinStore,
  KeyPinMismatchError,
} from "../../vendor/sharing.mjs";

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
  const container = sealVault(wasm, secret ?? sealSecret, v, salt, nonce, ARGON2);
  await chrome.storage.local.set({ [STORAGE_KEY]: bytesToBase64(container) });
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
  const container = sealDeviceIdentity(wasm, password, d, salt, nonce, ARGON2);
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
  }
  renderSharing();
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
  if (status === 401 || status === 403 || status === 501) return explainAuthStatus(status);
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
 * Apply `mutate` to a copy of the vault, re-seal + persist it, then swap it in
 * and re-render. A mutator that throws (duplicate label, bad secret, …) aborts
 * BEFORE anything is written.
 */
async function withVault(mutate) {
  if (!vault) throw new Error("vault is locked");
  const draft = { version: vault.version, entries: [...vault.entries] };
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

  // Rebuild the rows only when the set of labels changed; otherwise just update
  // the code + countdown so the DOM (and any focus) stays stable across ticks.
  const want = entries.map((e) => e.label).join("\u0000");
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
  rm.setAttribute("aria-label", `Remove ${entry.label}`);
  rm.addEventListener("click", async () => {
    try {
      await withVault((d) => {
        d.entries = d.entries.filter((e) => e.label !== entry.label);
      });
      say(`Removed ${entry.label}.`);
    } catch (e) {
      say(err(e), "error");
    }
  });

  li.append(who, code, left, rm);
  return li;
}

/** Recompute every visible code + countdown from the current clock. */
function tick() {
  if (!vault) return;
  const t = nowSeconds();
  for (const li of $("accounts").children) {
    const entry = vault.entries.find((e) => e.label === li.dataset.label);
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
    renderSharing();
    $("unlock-pw").value = "";
    unlocked();
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

$("add-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const label = $("add-label").value.trim();
    const issuer = $("add-issuer").value.trim();
    await withVault((d) => {
      addEntry(d, {
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

$("uri-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const entry = parseOtpauthUri($("uri-input").value.trim());
    await withVault((d) => mergeEntries(d, [entry]));
    $("uri-form").reset();
    say(`Added ${entry.label}.`);
  } catch (e) {
    say(err(e), "error");
  }
});

$("migration-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const entries = decodeMigrationUri($("migration-input").value.trim());
    let added = 0;
    await withVault((d) => {
      added = mergeEntries(d, entries);
    });
    $("migration-form").reset();
    say(`Imported ${added} of ${entries.length} account(s); duplicates skipped.`);
  } catch (e) {
    say(err(e), "error");
  }
});

/**
 * Append already-parsed TotpEntry objects to a draft vault, skipping labels that
 * already exist. Goes through addEntry so the stored shape is exactly the CLI's
 * (base64 secret, lowercase algorithm, issuer omitted when absent).
 */
function mergeEntries(draft, entries) {
  let added = 0;
  for (const e of entries) {
    if (draft.entries.some((x) => x.label === e.label)) continue;
    addEntry(draft, {
      label: e.label,
      issuer: e.issuer,
      secretBytes: base64ToBytes(e.secret),
      algorithm: e.algorithm,
      digits: e.digits,
      period: e.period,
    });
    added++;
  }
  return added;
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
    say(`Enrolled as ${enrolled.deviceId}.`);
  } catch (e) {
    say(`Enrollment failed: ${authErr(e)}`, "error");
  }
});

$("device-forget").addEventListener("click", async () => {
  await persistDevice(null);
  say("Device identity deleted. Sync is unauthenticated again.");
});

$("sync-push").addEventListener("click", async () => {
  try {
    say("Pushing…");
    const got = await chrome.storage.local.get(STORAGE_KEY);
    const sealed = got[STORAGE_KEY];
    if (!sealed) throw new Error("no sealed vault to push");
    const container = base64ToBytes(sealed);
    const baseUrl = $("sync-url").value.trim();
    const vaultId = $("sync-vault").value.trim();
    const { seq } = device
      ? await pushContainerAuthed(wasm, device, baseUrl, vaultId, container)
      : await pushContainer(baseUrl, vaultId, container);
    say(`Pushed sealed container as op #${seq}${device ? " (signed)" : ""}.`);
  } catch (e) {
    say(`Push failed: ${authErr(e)}`, "error");
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
    const latest = ops[ops.length - 1];
    // Store the SEALED bytes only; lock + unlock to decrypt with your password.
    await chrome.storage.local.set({ [STORAGE_KEY]: bytesToBase64(latest.container) });
    say(`Pulled op #${latest.seq}. Lock and unlock to decrypt the pulled vault.`);
  } catch (e) {
    say(`Pull failed: ${authErr(e)}`, "error");
  }
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
    // shareVault goes through the PIN CHOKE POINT: an unchanged key proceeds, a
    // CHANGED key throws KeyPinMismatchError and nothing is wrapped or uploaded.
    const res = await shareVault(wasm, auth, {
      vaultId: id,
      recipientDeviceId: to,
      vaultKey: key,
      permission: $("sharing-permission").value === "write" ? "write" : "read",
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
    const stored = (await chrome.storage.local.get(STORAGE_KEY))[STORAGE_KEY];
    if (!stored) throw new Error("no sealed vault in this browser to rotate");
    say("Rotating the vault key and re-wrapping…");
    const res = await rotateVaultKey(wasm, auth, {
      vaultId: id,
      recipientDeviceIds: recipients,
      sealedVault: base64ToBytes(stored),
      oldVaultKey: key,
      params: ARGON2,
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
    const accepted = await acceptVault(wasm, auth, { vaultId: id });
    // Seal the recovered key immediately, so a failed pull cannot lose it.
    await persistDevice({
      ...device,
      vaultKeys: { ...(device.vaultKeys ?? {}), [id]: accepted.vaultKey },
    });

    const ops = await pullContainersAuthed(wasm, device, auth.baseUrl, id, 0);
    if (ops.length === 0) {
      say(
        `Accepted the vault key for "${id}" (sha256 ${accepted.fingerprint}) and sealed it locally, ` +
          "but the server holds no vault yet — ask the owner to push.",
      );
      return;
    }
    const container = ops[ops.length - 1].container;
    const opened = openVault(wasm, accepted.vaultKey, container); // throws before storing
    await chrome.storage.local.set({ [STORAGE_KEY]: bytesToBase64(container) });
    vault = opened;
    sealSecret = accepted.vaultKey;
    activeVaultId = id;
    renderSharing();
    render();
    say(
      `Accepted and opened the shared vault "${id}" — ${opened.entries.length} account(s). ` +
        `Key sha256 ${accepted.fingerprint}: compare it with the sender out of band.`,
    );
  } catch (e) {
    say(`Accept failed: ${sharingErr(e)}`, "error");
  }
});

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
