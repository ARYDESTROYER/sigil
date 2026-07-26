// Sigil Desktop — PRE-AUDIT / UNAUDITED demonstration UI.
//
// This file is deliberately dumb. It holds no key material, does no
// cryptography, parses no container, and never sees a stored secret except when
// the user explicitly asks for an export. Everything real happens across the
// Tauri IPC in `sigil-desktop-core` (native Rust, linked against sigil-core --
// no WebAssembly anywhere in this column).

"use strict";

const invoke = window.__TAURI__.core.invoke;

const $ = (id) => document.getElementById(id);

/** Transient status line at the bottom of the window. */
let toastTimer = null;
function toast(message, isError = false) {
  const el = $("toast");
  el.textContent = message;
  el.classList.toggle("err", Boolean(isError));
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    el.hidden = true;
  }, isError ? 7000 : 3500);
}

/** Call a command, surfacing any Rust-side error as a toast. */
async function call(cmd, args = {}) {
  try {
    return await invoke(cmd, args);
  } catch (err) {
    toast(String(err), true);
    throw err;
  }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

let tick = null;

function applyStatus(status) {
  $("banner-title").textContent = status.banner_title;
  $("banner-body").textContent = status.banner_body;
  $("vault-path").textContent = status.path;
  $("lock-btn").hidden = !status.unlocked;
  $("lock-screen").hidden = status.unlocked;
  $("app").hidden = !status.unlocked;

  $("lock-heading").textContent = status.exists ? "Unlock vault" : "Create vault";
  $("lock-hint").textContent = status.exists
    ? "A sealed vault exists at the path above. Enter its password to unlock it — the same password the sigil CLI uses."
    : "No vault yet. The password you choose seals a new SIGILcli container at the path above.";

  if (status.unlocked) {
    startTicking();
  } else {
    stopTicking();
    $("export-out").hidden = true;
    $("export-out").textContent = "";
  }
}

function startTicking() {
  if (tick !== null) return;
  refresh();
  tick = setInterval(refresh, 1000);
}

function stopTicking() {
  if (tick === null) return;
  clearInterval(tick);
  tick = null;
}

/** Redraw the account list with codes freshly computed by the native core. */
async function refresh() {
  let rows;
  try {
    rows = await invoke("list");
  } catch (err) {
    // Most likely the vault was locked out from under us; stop the timer.
    stopTicking();
    return;
  }

  $("count").textContent = rows.length === 1 ? "1 account" : `${rows.length} accounts`;
  $("empty").hidden = rows.length > 0;

  const ul = $("accounts");
  ul.textContent = "";
  for (const row of rows) {
    const li = document.createElement("li");

    const name = document.createElement("div");
    const title = document.createElement("div");
    title.className = "acct-name";
    title.textContent = row.issuer ? `${row.issuer} · ${row.label}` : row.label;
    const meta = document.createElement("div");
    meta.className = "acct-meta";
    meta.textContent = `${row.algorithm} · ${row.digits} digits · ${row.period}s`;
    name.append(title, meta);

    const codeWrap = document.createElement("div");
    const code = document.createElement("div");
    code.className = "code";
    // Group as XXX XXX / XXXX XXXX for legibility without touching the value.
    const half = Math.ceil(row.code.length / 2);
    code.textContent = `${row.code.slice(0, half)} ${row.code.slice(half)}`;
    const ring = document.createElement("div");
    ring.className = "ring";
    const bar = document.createElement("progress");
    bar.max = row.period;
    bar.value = row.seconds_remaining;
    const secs = document.createElement("span");
    secs.textContent = `${row.seconds_remaining}s`;
    ring.append(bar, secs);
    codeWrap.append(code, ring);

    const del = document.createElement("button");
    del.className = "link";
    del.textContent = "Remove";
    del.addEventListener("click", async () => {
      if (!window.confirm(`Remove "${row.label}" from the vault?`)) return;
      await call("remove", { label: row.label });
      toast(`removed ${row.label}`);
      refresh();
    });

    li.append(name, codeWrap, del);
    ul.append(li);
  }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

$("unlock-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const field = $("password");
  const password = field.value;
  if (!password) return;
  const status = await call("unlock", { password });
  field.value = ""; // never keep it in the DOM
  applyStatus(status);
  toast(status.count === 0 ? "vault ready" : `unlocked · ${status.count} accounts`);
});

$("lock-btn").addEventListener("click", async () => {
  applyStatus(await call("lock"));
  toast("locked");
});

$("add-secret-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  await call("add_secret", {
    label: $("label").value,
    issuer: $("issuer").value || null,
    secret: $("secret").value,
    algorithm: $("algorithm").value,
    digits: Number($("digits").value),
    period: Number($("period").value),
  });
  $("label").value = "";
  $("issuer").value = "";
  $("secret").value = "";
  toast("account added");
  refresh();
});

$("import-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = $("import-text").value.trim();
  if (!text) return;
  // A single otpauth:// line is an "add"; anything else goes through the
  // migration-aware importer. Both paths live in the Rust core.
  const r = await call("import", { text });
  $("import-text").value = "";
  toast(
    `imported ${r.imported} (skipped: ${r.skipped_duplicate} duplicate, ` +
      `${r.skipped_hotp} HOTP, ${r.skipped_invalid} invalid)`
  );
  refresh();
});

async function reveal(cmd) {
  const out = await call(cmd, { label: null });
  const pre = $("export-out");
  pre.textContent = out.lines.join("\n");
  pre.hidden = false;
  toast("secrets revealed on screen — clear them when you are done", true);
}

$("export-uris-btn").addEventListener("click", () => reveal("export_uris"));
$("export-migration-btn").addEventListener("click", () => reveal("export_migration"));

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

(async function boot() {
  const status = await call("status");
  $("export-warning").textContent =
    "WARNING: an export reveals your TOTP SECRETS IN THE CLEAR. Anyone who can " +
    "read the screen can generate your codes.";
  applyStatus(status);
})();
