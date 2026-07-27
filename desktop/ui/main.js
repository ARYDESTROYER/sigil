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
// Sync & sharing
//
// Still dumb: this panel names a server, a vault id and a device id, and shows
// FINGERPRINTS the native side computed. It never sees a seed, a vault key or a
// wrapped envelope, and the enrollment token it collects is passed straight
// across the IPC once and then cleared from the DOM -- it is never stored here.
// ---------------------------------------------------------------------------

/** Read the vault id the sync/share actions operate on. */
function vaultId() {
  const id = $("sync-vault-id").value.trim();
  if (!id) toast("enter a vault id first", true);
  return id;
}

/** Render the device facts table. Values are fingerprints and ids, never keys. */
function applySync(sync) {
  $("sync-state").textContent = !sync.configured
    ? "off"
    : sync.enrolled
      ? "enrolled"
      : "not enrolled";
  if (sync.configured && $("server-url").value.trim() === "") {
    $("server-url").value = sync.server;
  }
  $("enroll-block").hidden = !sync.configured;
  $("vault-block").hidden = !sync.configured;
  $("share-block").hidden = !sync.configured;

  const dl = $("device-facts");
  dl.textContent = "";
  const put = (key, value, dim = false) => {
    const dt = document.createElement("dt");
    dt.textContent = key;
    const dd = document.createElement("dd");
    dd.textContent = value;
    if (dim) dd.className = "off";
    dl.append(dt, dd);
  };

  if (!sync.configured) {
    put("server", "none — this app is offline and stays offline", true);
    return;
  }
  put("server", sync.server);
  put("state", sync.state_dir);
  put("device id", sync.device_id ?? "not enrolled yet");
  if (sync.device_fingerprint) put("device key", `sha256 ${sync.device_fingerprint}`);
  put(
    "hybrid key",
    sync.hybrid_identity_present
      ? `sha256 ${sync.hybrid_fingerprint ?? "?"}`
      : "not created yet",
    !sync.hybrid_identity_present
  );
  put(
    "shared vaults",
    sync.vaults.length === 0
      ? "none"
      : sync.vaults.map((v) => `${v.vault_id} (sha256 ${v.key_fingerprint})`).join("\n"),
    sync.vaults.length === 0
  );
}

async function refreshSync() {
  applySync(await call("sync_status"));
}

$("server-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const sync = await call("set_server", { server: $("server-url").value });
  applySync(sync);
  toast(sync.configured ? `server set to ${sync.server}` : "server cleared — offline");
});

$("check-server-btn").addEventListener("click", async () => {
  const probe = await call("check_server");
  toast(probe.detail, !probe.reachable);
});

$("enroll-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const field = $("enroll-token");
  const token = field.value;
  if (!token) return;
  try {
    const deviceId = await call("enroll", { token, label: $("enroll-label").value });
    toast(`enrolled as ${deviceId}`);
  } finally {
    field.value = ""; // never keep the token in the DOM
  }
  await refreshSync();
});

$("publish-hybrid-btn").addEventListener("click", async () => {
  const fp = await call("publish_hybrid");
  toast(`hybrid public key published (sha256 ${fp}) — the secret half never left this machine`);
  await refreshSync();
});

$("convert-btn").addEventListener("click", async () => {
  const id = vaultId();
  if (!id) return;
  if (
    !window.confirm(
      `Re-seal this vault under a random vault key for "${id}"?\n\n` +
        "This is one-way: afterwards the vault opens with that key, not your " +
        "password. Your password is never shared or uploaded."
    )
  )
    return;
  const fp = await call("convert_to_shared", { vaultId: id });
  toast(`shared vault ready (key sha256 ${fp}) — the key itself is never shown`);
  await refreshSync();
});

$("push-btn").addEventListener("click", async () => {
  const id = vaultId();
  if (!id) return;
  const seq = await call("push", { vaultId: id });
  toast(`pushed the sealed container as seq ${seq} (the server cannot read it)`);
});

$("pull-btn").addEventListener("click", async () => {
  const id = vaultId();
  if (!id) return;
  const r = await call("pull", { vaultId: id });
  toast(
    r.adopted
      ? `pulled seq ${r.seq} — ${r.count} accounts`
      : "nothing new on the server"
  );
  if (r.adopted) refresh();
});

$("share-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const id = vaultId();
  if (!id) return;
  const fp = await call("share", {
    vaultId: id,
    deviceId: $("share-device").value,
    permission: $("share-permission").value,
  });
  toast(`shared ${id} (key sha256 ${fp}) — wrapped to that device, opaque to the server`);
});

// ── Phase 50: safety numbers, the pin alarm, and rotation ──────────────────

/** Show a safety number (or a pin verdict) in the dedicated line. */
function showSafety(text) {
  $("safety-number").textContent = text;
}

$("my-safety-btn").addEventListener("click", async () => {
  const sn = await call("my_safety_number");
  showSafety(`This device: ${sn}`);
  toast(
    "Read these digits to whoever is about to share a vault with you, over a channel the " +
      "server does not control. Nothing was sent anywhere."
  );
});

$("peer-safety-btn").addEventListener("click", async () => {
  const to = $("share-device").value.trim();
  if (!to) return toast("enter the recipient device id first");
  const [sn, state] = await call("peer_safety_number", { deviceId: to });
  showSafety(`${to}: ${sn}`);
  toast(`Pin state: ${state}. Confirm the digits with that device's owner out of band.`);
});

$("pairwise-safety-btn").addEventListener("click", async () => {
  const to = $("share-device").value.trim();
  if (!to) return toast("enter the recipient device id first");
  const sn = await call("pairwise_safety_number", { deviceId: to });
  showSafety(`Pairwise with ${to}: ${sn}`);
  toast(
    "This number is ORDER-INDEPENDENT: the other device sees exactly the same digits. " +
      "If they differ, do NOT share."
  );
});

$("pins-btn").addEventListener("click", async () => {
  const rows = await call("pins");
  if (rows.length === 0) {
    showSafety("No keys pinned yet — the first share pins the key it sees.");
    return;
  }
  showSafety(
    rows
      .map(
        (p) =>
          `${p.device_id}: ${p.safety_number}` +
          (p.repins > 0 ? ` (re-pinned ${p.repins}x by explicit request)` : "")
      )
      .join("  |  ")
  );
});

$("rotate-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const id = vaultId();
  if (!id) return;
  const deviceIds = $("rotate-devices")
    .value.split(/[\s,]+/)
    .map((x) => x.trim())
    .filter(Boolean);
  const r = await call("rotate", { vaultId: id, deviceIds });
  toast(
    `rotated ${id}: ${r.old_fingerprint} -> ${r.new_fingerprint}; re-wrapped to ` +
      `${r.rewrapped.join(", ")}` +
      (r.removed.length > 0 ? `; deleted the envelope of ${r.removed.join(", ")}` : "") +
      ". The vault is now locked — unlock it with the shared vault id. This protects " +
      "FUTURE content only."
  );
  refresh();
});

$("accept-btn").addEventListener("click", async () => {
  const id = vaultId();
  if (!id) return;
  const fp = await call("accept", { vaultId: id });
  toast(`accepted ${id} (key sha256 ${fp}) — now Pull to fetch the vault`);
  await refreshSync();
});

$("unlock-shared-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  const status = await call("unlock_shared", { vaultId: $("unlock-vault-id").value });
  applyStatus(status);
  await refreshSync();
  toast(`unlocked with the vault key · ${status.count} accounts`);
});

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

(async function boot() {
  const status = await call("status");
  $("export-warning").textContent =
    "WARNING: an export reveals your TOTP SECRETS IN THE CLEAR. Anyone who can " +
    "read the screen can generate your codes.";
  applyStatus(status);
  // The Sync panel is visible whether or not the vault is unlocked: a recipient
  // device has to enroll and accept a share BEFORE it can open anything.
  await refreshSync();
})();
