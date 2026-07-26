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

/** chrome.storage.local key holding ONLY the sealed container, base64. */
const STORAGE_KEY = "sigil.extension.vault.v1";

/**
 * chrome.storage.local key holding the SEALED device identity — a SECOND
 * SIGILcli container, sealed with the SAME vault password, whose plaintext is
 * {device_id, seed, base_url}.
 *
 * The Ed25519 device SEED is secret signing key material, so it is NEVER stored
 * in plaintext: it is only recoverable while the vault is unlocked (the password
 * is memory-only). It lives in its own container rather than inside the vault
 * JSON so the CLI-mirrored TotpVault schema stays byte-compatible.
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
/** @type {{deviceId:string,seed:Uint8Array,baseUrl:string}|null} memory-only. */
let device = null;
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
 * Seal `v` under `password` with fresh entropy and store ONLY the resulting
 * container. Throws before writing if sealing fails, so a failed save can never
 * leave a corrupt container behind.
 */
async function persist(v) {
  const salt = crypto.getRandomValues(new Uint8Array(wasm.recommended_salt_len()));
  const nonce = crypto.getRandomValues(new Uint8Array(wasm.nonce_len()));
  const container = sealVault(wasm, password, v, salt, nonce, ARGON2);
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
  vault = null;
  device = null; // the device seed leaves memory with the password
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
    vault = newVault();
    await persist(vault);
    await loadDevice(pw);
    $("setup-pw").value = "";
    $("setup-pw2").value = "";
    unlocked();
  } catch (e) {
    password = "";
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
    vault = openVault(wasm, pw, base64ToBytes(sealed));
    password = pw;
    await loadDevice(pw);
    $("unlock-pw").value = "";
    unlocked();
  } catch (e) {
    vault = null;
    password = "";
    say(`Could not unlock: ${err(e)}`, "error");
  }
});

$("lock").addEventListener("click", lock);

$("destroy").addEventListener("click", async () => {
  await chrome.storage.local.remove([STORAGE_KEY, DEVICE_KEY]);
  password = "";
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

window.addEventListener("unload", () => {
  if (ticker) clearInterval(ticker);
  password = "";
  vault = null;
  device = null;
});

boot();
