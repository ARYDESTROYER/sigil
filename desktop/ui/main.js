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

/**
 * The text of a Rust-side error. Errors cross the IPC as {kind, message,
 * key_change?}; older/unexpected shapes still stringify sensibly.
 */
function errText(err) {
  if (err && typeof err === "object" && typeof err.message === "string") return err.message;
  return String(err);
}

/**
 * Call a command, surfacing any Rust-side error as a toast — EXCEPT a changed
 * hybrid key, which gets the loud, blocking alarm instead of a toast that
 * disappears in seven seconds.
 */
async function call(cmd, args = {}) {
  try {
    return await invoke(cmd, args);
  } catch (err) {
    // A changed hybrid key gets the blocking alarm; a payment refusal gets the
    // entitlement banner (which says what still works). Everything else toasts.
    if (err && typeof err === "object" && err.entitlement) applyEntitlement(err.entitlement);
    if (!showKeyAlarm(err)) toast(errText(err), true);
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
    // Locking wipes anything secret that was on screen — including a recovery
    // code that was still waiting to be written down.
    clearRecoveryCode();
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
  const base =
    `imported ${r.imported} (skipped: ${r.skipped_duplicate} duplicate, ` +
    `${r.skipped_hotp} HOTP, ${r.skipped_invalid} invalid)`;
  // ⛔ A multi-QR Google Authenticator export arrives one QR at a time. Saying
  // "imported 12" and nothing else is how a user deletes the old app with two
  // thirds of their accounts still only there.
  const partial = r.partial_batches ?? [];
  // ⭐ The alarm keys off batches_outstanding, not "was this multi-QR at all".
  // Batch 2 of 2 still gets its note (this app keeps no record of earlier runs)
  // but must not be called incomplete — a false alarm is how a real one gets
  // ignored.
  toast(
    partial.length === 0
      ? base
      : r.batches_outstanding
        ? `${base} — ⚠️ INCOMPLETE: ${partial.join(" ")} Import the remaining QR ` +
            `code(s) before deleting anything from the old app.`
        : `${base} — ${partial.join(" ")}`
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
  // Recovery needs a server but NOT an unlocked vault and NOT an enrolled
  // device: `restore` runs on a new install, which is the whole point.
  $("recovery-block").hidden = !sync.configured;
  // The account panel needs an ENROLLED identity: the server reads the account
  // off the signature, so an un-enrolled device has nothing to ask about.
  $("account-block").hidden = !sync.configured || !sync.enrolled;
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

// --- Account (which devices are yours) --------------------------------------
//
// Nothing here names an account: the server derives it from this device's
// signature, so there is no account field to get wrong or to abuse.

/** Fill the account facts table. Ids and counts only — never a key or a secret. */
function putAccountFacts(pairs) {
  const dl = $("account-facts");
  dl.textContent = "";
  for (const [key, value, dim] of pairs) {
    const dt = document.createElement("dt");
    dt.textContent = key;
    const dd = document.createElement("dd");
    dd.textContent = value;
    if (dim) dd.className = "off";
    dl.append(dt, dd);
  }
}

/** Hide the one-time invite secret again (on any other account action). */
function clearInviteOutput() {
  $("account-invite-out").hidden = true;
  $("account-invite-out").textContent = "";
  $("account-invite-warning").hidden = true;
}

$("account-status-btn").addEventListener("click", async () => {
  clearInviteOutput();
  const a = await call("account_status");
  const rows = [
    ["account", a.account_id],
    [
      "devices",
      `${a.device_count} of ${a.device_limit} active` +
        (a.revoked_device_count
          ? ` · ${a.revoked_device_count} revoked (a revoked device does not use a seat)`
          : ""),
    ],
  ];
  for (const m of a.members) {
    rows.push([
      m.is_this_device ? "this device" : "member",
      `${m.device_id} · ${m.status}${m.label ? ` · ${m.label}` : ""}`,
      m.status !== "active",
    ]);
  }
  if (a.device_count < 2) {
    rows.push([
      "warning",
      "only one device in this account. There is NO RECOVERY — enroll a second one.",
    ]);
  }
  putAccountFacts(rows);
});

$("account-invite-btn").addEventListener("click", async () => {
  clearInviteOutput();
  const inv = await call("account_invite", { ttlSeconds: null });
  // Shown ONCE, in the DOM only, never persisted. It is cleared by the next
  // account action or by locking the vault.
  $("account-invite-warning").hidden = false;
  const out = $("account-invite-out");
  out.textContent =
    `${inv.invite}\n\n` +
    `handle:  ${inv.invite_id}  (use this to revoke it)\n` +
    `expires: ${inv.expires_at}\n` +
    `pinned:  ${inv.pinned ? "yes" : "no — anyone who reads it can use it"}`;
  out.hidden = false;
  toast("invite minted — shown once, not stored anywhere");
});

$("account-invites-btn").addEventListener("click", async () => {
  clearInviteOutput();
  const invites = await call("account_invites");
  if (invites.length === 0) {
    putAccountFacts([["open invites", "none"]]);
    return;
  }
  putAccountFacts(
    invites.map((i) => [
      "open invite",
      `${i.invite_id} · by ${i.created_by_device_id} · expires ${i.expires_at}` +
        (i.pinned ? " · pinned" : ""),
    ])
  );
});

$("account-revoke-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  clearInviteOutput();
  const field = $("account-invite-id");
  const id = field.value.trim();
  if (!id) return;
  await call("account_revoke_invite", { inviteId: id });
  field.value = "";
  toast(`invite ${id} revoked`);
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
  // A served write clears a stale refusal banner (and a refused one raises it,
  // from `call`'s error path). ⭐ Then ASK: a write served INSIDE GRACE looks
  // identical to a healthy one from here, so only the subscription read can
  // surface the deadline.
  await refreshEntitlement();
  await pullEntitlementFromServer();
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
  const safety = $("share-safety").value.trim();
  const r = await call("share", {
    vaultId: id,
    deviceId: $("share-device").value,
    permission: $("share-permission").value,
    // Optional for an ordinary device; the wrap gate REQUIRES it for a recovery
    // kit this device has never pinned, and refuses before anything is wrapped.
    safetyNumber: safety === "" ? null : safety,
  });
  showSafety(`${$("share-device").value.trim()}: ${r.safety_number}`);
  toast(
    r.needs_out_of_band_check
      ? `shared ${id} (key sha256 ${r.fingerprint}) — but this was a FIRST SIGHT of that ` +
          `device's key and nothing out of band confirmed it. Read the digits above back to ` +
          `its owner over a channel the server does not control.`
      : `shared ${id} (key sha256 ${r.fingerprint}) — ${r.trust}`,
    r.needs_out_of_band_check
  );
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
  // A number that DIFFERS from the pin is the same fact the alarm reports, just
  // reached read-only — so it is an error-level message, not a note.
  const differs = state.startsWith("DIFFERS");
  toast(
    differs
      ? `Pin state: ${state}. Sharing with ${to} will be REFUSED. Do NOT re-pin unless its ` +
          "owner reads you the presented digits over a channel the server does not control."
      : `Pin state: ${state}. Confirm the digits with that device's owner out of band.`,
    differs
  );
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

// ── THE KEY-SUBSTITUTION ALARM ──────────────────────────────────────────────
//
// A share or a rotation refused because a device's hybrid PUBLIC key changed is
// the one error in this app that must not scroll past as a toast. The native
// side tags it `kind: "key changed"` and hands over BOTH safety numbers; this is
// where the user sees them side by side and decides. Nothing re-pins by itself.

/** The device whose key changed, awaiting a DELIBERATE re-pin. */
let pendingRepin = null;

/** The actions the alarm BLOCKS while it is up. */
function blockedButtons() {
  return [
    $("share-form").querySelector('button[type="submit"]'),
    $("rotate-form").querySelector('button[type="submit"]'),
  ];
}

/**
 * ⭐ Show the alarm for a `key changed` IPC error. Returns true when it handled
 * the error (so the caller does not also toast it), false for anything else.
 */
function showKeyAlarm(err) {
  const kc = err && typeof err === "object" ? err.key_change : null;
  if (!kc) return false;
  pendingRepin = kc;

  $("pin-mismatch-title").textContent =
    `REFUSED — the hybrid public key for ${kc.device_id} has CHANGED.`;
  $("pin-mismatch-text").textContent =
    "Nothing was shared and no key was wrapped. This is either a KEY-SUBSTITUTION " +
    "ATTACK (a hostile or compromised server swapping in a key it can decrypt with, " +
    "so it would receive this vault's key) or a LEGITIMATE RE-ENROLMENT of that " +
    "device. Only you can tell, by reading the new digits to its owner over a " +
    "channel the server does not control.";
  $("pin-mismatch-numbers").textContent =
    `pinned:    ${kc.pinned_safety_number}\npresented: ${kc.presented_safety_number}`;
  $("pin-mismatch").hidden = false;
  for (const b of blockedButtons()) if (b) b.disabled = true;
  $("pin-mismatch").scrollIntoView({ block: "nearest" });
  toast(`REFUSED: ${kc.device_id}'s key changed. Nothing was shared.`, true);
  return true;
}

/** Take the alarm down. Sharing stays refused until this happens. */
function hideKeyAlarm() {
  pendingRepin = null;
  $("pin-mismatch").hidden = true;
  for (const b of blockedButtons()) if (b) b.disabled = false;
}

$("pin-mismatch-dismiss").addEventListener("click", () => {
  hideKeyAlarm();
  toast(
    "Alarm cleared WITHOUT re-pinning: this device still refuses that key, which is the " +
      "safe outcome. Verify the safety number out of band before sharing again."
  );
});

// ⚠️ The deliberate escape hatch. Only reachable after a mismatch BLOCKED a
// share, only by an explicit click, and only after a confirmation that names the
// risk. `expected` is sent so the native side re-checks that the number the user
// says they verified is still the one the server presents.
$("repin-btn").addEventListener("click", async () => {
  if (!pendingRepin) return;
  const { device_id: deviceId, presented_safety_number: presented } = pendingRepin;
  if (
    !window.confirm(
      `DANGEROUS — re-pin ${deviceId}?\n\n` +
        `Only continue if that device's owner read you EXACTLY:\n\n  ${presented}\n\n` +
        "over a channel the server does not control (a phone call, in person). If you " +
        "have not done that, a hostile server may be substituting a key it can decrypt " +
        "with, and re-pinning would hand it this vault's key."
    )
  )
    return;
  const [previous, current] = await call("repin", { deviceId, expected: presented });
  hideKeyAlarm();
  showSafety(`${deviceId}: ${current}`);
  toast(
    `Re-pinned ${deviceId}: ${previous ?? "(nothing pinned)"} -> ${current}. This device now ` +
      "trusts that key. If you did not verify those digits with its owner out of band, that " +
      "was a mistake — re-enroll to undo it."
  );
  await refreshSync();
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
// ⭐ ENTITLEMENT (ADR 0043)
//
// The server may refuse WRITES from an account whose subscription lapsed past
// its grace period. It never refuses reads, and it never refuses giving another
// device of your own account a vault key -- including printing a recovery kit.
// This panel exists so a refusal reads as "pay to continue", never as "your
// codes are gone", and so the guarantees are stated every single time.
// ---------------------------------------------------------------------------

function applyEntitlement(e) {
  const banner = $("entitlement-banner");
  if (!e || !e.needs_attention) {
    banner.hidden = true;
    return;
  }
  const refused = e.writes === "refused";
  banner.classList.toggle("notice", !refused);
  $("entitlement-title").textContent = refused
    ? "New writes are refused — this account's subscription has lapsed."
    : "This account's subscription has lapsed. Writes still work, for now.";
  $("entitlement-detail").textContent =
    e.detail +
    (e.grace_ends_at ? ` (${refused ? "writes stopped" : "writes stop"} ${e.grace_ends_at})` : "") +
    (e.subscription_status ? ` Status: ${e.subscription_status}.` : "") +
    (e.checkout_path ? ` Pay at ${e.checkout_path}.` : "");
  banner.hidden = false;
}

$("entitlement-dismiss").addEventListener("click", () => {
  // Dismiss hides the banner; it does NOT change anything on the server, and
  // the next refused write brings it straight back.
  $("entitlement-banner").hidden = true;
});

async function refreshEntitlement() {
  // A purely cached, local read: it cannot fail because a server is down.
  try {
    applyEntitlement(await invoke("entitlement_status"));
  } catch {
    /* nothing observed yet */
  }
}

// ⭐ ASK THE SERVER. This is the ONLY way this client can learn it is inside its
// GRACE period -- lapsed, still served, with a deadline. A 402 can only ever say
// "already too late", and the header sigild sets on a served-in-grace write is
// dropped by the transport. Without this the "Writes still work, for now."
// branch above was unreachable.
//
// Best-effort by design: it is called after a server is configured and after
// each sync, and a failure (offline, billing off, not enrolled) leaves the
// cached view alone rather than inventing a warning.
async function pullEntitlementFromServer({ loud = false } = {}) {
  try {
    const e = await invoke("entitlement_refresh");
    applyEntitlement(e);
    if (loud) {
      toast(
        e.needs_attention
          ? "Subscription checked — see the banner above."
          : `Subscription checked: ${e.detail}`,
      );
    }
  } catch (err) {
    // Offline, billing switched off, or this device is not enrolled. Leave the
    // cached view ALONE rather than inventing (or clearing) a warning.
    if (loud) toast(errText(err), true);
  }
}

$("check-subscription-btn").addEventListener("click", () => {
  void pullEntitlementFromServer({ loud: true });
});

// ---------------------------------------------------------------------------
// ⭐ THE RECOVERY KIT (ADR 0042)
//
// ⚠️ The 56-character code is THE WHOLE CREDENTIAL -- whoever holds it controls
// the account. This file therefore: shows it exactly once, in one DOM node,
// wipes that node on demand / on lock / on any other recovery action, never
// stores it anywhere, never puts it in a URL, and clears the restore input in a
// `finally` so a failed attempt does not leave it sitting in the window.
// ---------------------------------------------------------------------------

/** Wipe the printed code from the screen. The only copy is the paper. */
function clearRecoveryCode() {
  const sheet = $("recovery-sheet");
  if (!sheet) return;
  $("recovery-code").textContent = "";
  $("recovery-sheet-facts").textContent = "";
  sheet.hidden = true;
}

/** Fill the recovery facts table. Ids, counts and public digits only. */
function putRecoveryFacts(pairs) {
  const dl = $("recovery-facts");
  dl.textContent = "";
  for (const [key, value, dim] of pairs) {
    const dt = document.createElement("dt");
    dt.textContent = key;
    const dd = document.createElement("dd");
    dd.textContent = value;
    if (dim) dd.className = "off";
    dl.append(dt, dd);
  }
}

$("recovery-kits-btn").addEventListener("click", async () => {
  clearRecoveryCode();
  const kits = await call("recovery_kits");
  if (kits.length === 0) {
    putRecoveryFacts([
      [
        "recovery",
        "NOT SET UP. If you lose every device in this account, its vaults are " +
          "gone — unreadable by you and by us.",
      ],
    ]);
    return;
  }
  putRecoveryFacts(
    kits.map((k) => [
      k.status === "active" ? "kit" : "revoked kit",
      `${k.device_id} · printed ${k.created_at}`,
      k.status !== "active",
    ])
  );
});

$("recovery-generate-btn").addEventListener("click", async () => {
  clearRecoveryCode();
  if (
    !window.confirm(
      "Print a recovery kit?\n\n" +
        "You will be shown 56 characters ONCE. Write them on paper.\n\n" +
        "⚠️ Whoever holds that paper has FULL CONTROL of this account: they can " +
        "read every covered vault and revoke every device. There is no password " +
        "and no lock in front of it.\n\n" +
        "It covers the shared vaults this device holds keys for, as of now, and " +
        "it recovers KEYS, not DATA — a vault that was never pushed cannot come back."
    )
  )
    return;

  const kit = await call("recovery_generate", { vaultIds: null });
  // Shown ONCE, in the DOM only. Nothing writes it anywhere.
  $("recovery-code").textContent = kit.code;
  $("recovery-sheet-facts").textContent =
    `kit device id: ${kit.device_id}   (you need this to restore)\n` +
    `account:       ${kit.account_id}\n` +
    `server:        ${kit.server}\n` +
    `safety number: ${kit.safety_number}\n` +
    `covers:        ${
      kit.covered.length === 0
        ? "(nothing yet — cover a vault below)"
        : kit.covered.map((c) => `${c.vault_id} (key sha256 ${c.key_fingerprint})`).join("\n               ")
    }\n` +
    `verified:      unwrapped ${kit.verified_vault || "(nothing to unwrap)"} as ` +
    `${kit.verified_account_id} before printing\n` +
    `seats:         ${kit.seats_used} of ${kit.seat_limit} devices (the kit uses one)`;
  $("recovery-sheet").hidden = false;
  $("recovery-sheet").scrollIntoView({ block: "nearest" });
  // Pre-fill the ids the next actions need. These are PUBLIC, not the code.
  $("recovery-device").value = kit.device_id;
  $("recovery-safety").value = kit.safety_number;
  toast("recovery kit printed — shown once, stored nowhere. Write it down now.", true);
  await refreshSync();
});

$("recovery-code-clear").addEventListener("click", () => {
  clearRecoveryCode();
  toast("cleared from the screen. The paper is now the only copy.");
});

$("recovery-cover-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  clearRecoveryCode();
  const id = vaultId();
  if (!id) return;
  const safety = $("recovery-safety").value.trim();
  const [fingerprint, derived] = await call("recovery_cover", {
    deviceId: $("recovery-device").value,
    vaultId: id,
    // ⭐ Required on any device that did not print the kit. The native wrap gate
    // refuses a first sight of a kit's key without it, before anything is
    // wrapped or uploaded — so leaving it blank there is an error, not a risk.
    safetyNumber: safety === "" ? null : safety,
  });
  toast(
    `${id} is now covered by the kit (key sha256 ${fingerprint})` +
      (derived
        ? " — this device derived the kit's key itself, so nothing was fetched."
        : " — the kit's key was fetched and checked against the safety number you gave.")
  );
});

$("recovery-check-btn").addEventListener("click", async () => {
  clearRecoveryCode();
  const rows = await call("recovery_check", { deviceId: $("recovery-device").value });
  if (rows.length === 0) {
    putRecoveryFacts([["coverage", "this device holds no shared vaults to check"]]);
    return;
  }
  putRecoveryFacts([
    ["checked from", "THIS device only — a vault created elsewhere is invisible here"],
    ...rows.map((r) => [
      r.vault_id,
      r.covered
        ? r.synced
          ? `covered ${r.covered_at} · pushed — recoverable`
          : `covered ${r.covered_at} · ⚠️ NEVER PUSHED — the key would come back, the data would not`
        : "NOT covered — the kit cannot open this vault",
      !r.covered || !r.synced,
    ]),
  ]);
});

$("recovery-revoke-btn").addEventListener("click", async () => {
  clearRecoveryCode();
  const deviceId = $("recovery-device").value.trim();
  if (!deviceId) return toast("enter the kit device id first", true);
  if (
    !window.confirm(
      `Revoke recovery kit ${deviceId}?\n\n` +
        "The printed sheet stops working and its wrapped keys are deleted.\n\n" +
        "⚠️ This CANNOT un-learn a key the kit already unwrapped. If you think the " +
        "paper was seen, rotate each vault afterwards — and that protects future " +
        "content only.\n\n" +
        "If this was your only kit, you are back to: lose every device, lose the vaults."
    )
  )
    return;
  const r = await call("recovery_revoke", { deviceId, vaultIds: null });
  putRecoveryFacts([
    ["revoked", r.device_id],
    ["envelopes deleted", r.envelopes_removed.join(", ") || "none"],
    ["already clear", r.already_clear.join(", ") || "none"],
    ["still to do", "rotate each vault above — revocation cannot un-learn a key"],
  ]);
  toast(`kit ${r.device_id} revoked`, true);
});

$("recovery-verify-btn").addEventListener("click", async () => {
  const code = $("recovery-code-in").value;
  if (!code) return;
  // OFFLINE: decode + checksum only. The code is not sent anywhere by this.
  await call("recovery_verify", { code });
  toast("that code is well-formed (checked offline — nothing was sent anywhere)");
});

$("recovery-restore-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  clearRecoveryCode();
  const field = $("recovery-code-in");
  const code = field.value;
  const deviceId = $("recovery-restore-device").value.trim();
  if (!code || !deviceId) return;
  const adopt = $("recovery-adopt").checked;
  if (
    adopt &&
    !window.confirm(
      "Keep the kit's identity on this machine?\n\n" +
        "⚠️ This machine becomes a SECOND COPY OF THE PAPER: anyone with access " +
        "to it gains full control of the account, with no password in front of it.\n\n" +
        "Leave it unticked to recover the vaults and nothing else."
    )
  )
    return;

  let r;
  try {
    r = await call("recovery_restore", { code, deviceId, adopt });
  } finally {
    // ⚠️ Whatever happened, the credential does not stay in the window.
    field.value = "";
  }
  const out = $("recovery-restore-out");
  out.textContent =
    `restored as ${r.device_id} in account ${r.account_id}\n\n` +
    r.vaults
      .map(
        (v) =>
          `${v.vault_id}: ${v.entries} account(s) -> ${v.path}  (key sha256 ${v.key_fingerprint})`
      )
      .join("\n") +
    (r.skipped.length
      ? `\n\nnot recovered:\n${r.skipped.map(([v, why]) => `${v}: ${why}`).join("\n")}`
      : "") +
    (r.adopted
      ? "\n\n⚠️ This machine now holds the kit's own keys — it is a second copy of the paper."
      : "\n\nThe kit's identity was NOT kept on this machine.");
  out.hidden = false;
  toast(
    r.vaults.length === 0
      ? "nothing was recovered — the kit holds no vault this server can serve"
      : `recovered ${r.vaults.length} vault(s). Open one with its vault id above.`,
    r.vaults.length === 0
  );
  await refreshSync();
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
  // device has to enroll and accept a share BEFORE it can open anything — and a
  // RESTORE runs on a machine that has no vault at all.
  await refreshSync();
  await refreshEntitlement();
  // ⭐ Ask the server at startup too, so a customer inside their grace period is
  // told BEFORE they try to write — which is the entire point of a grace period.
  // Silent on failure: offline, billing off and not-enrolled are all ordinary.
  await pullEntitlementFromServer();
})();
