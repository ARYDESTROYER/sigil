// main.js — framework-free driver for the sigil-wasm browser demo.
//
// Pre-audit / UNAUDITED demo of the wasm-pure sigil-core. Do NOT enter real
// secrets. Requires ./build-wasm.sh to have produced ../pkg-web first.
//
// Two paths are shown:
//   * the raw record API (seal_record / open_record) — envelope-as-base64, with
//     (salt, params) kept in memory for Open; and
//   * the CLI-compatible SIGILcli CONTAINER path (seal_to_container /
//     open_container) — the container is a self-describing file you can DOWNLOAD
//     and open on the command line with `sigil open`, and a container written by
//     `sigil seal` can be UPLOADED here and opened. That is the browser<->CLI
//     interop the Node test (test/interop.mjs) proves headlessly.

import init, {
  seal_record,
  open_record,
  seal_to_container,
  open_container,
  hybrid_x25519_public,
  hybrid_mlkem_encaps_key,
  hybrid_seal_to_container,
  hybrid_open_container,
  totp,
  format_code,
  nonce_len,
  recommended_salt_len,
  version,
} from "../pkg-web/sigil_wasm.js";
import { pushContainer, pullContainers } from "../sync.mjs";
import {
  newVault,
  addEntry,
  openVault,
  sealVault,
  codeForEntry,
  base32Decode,
  base64ToBytes,
} from "../totp-vault.mjs";
import {
  parseOtpauthUri,
  buildOtpauthUri,
  decodeMigrationUri,
  encodeMigrationUri,
} from "../totp-migration.mjs";

// totp-vault.mjs takes the wasm binding as an injected `wasm` object; adapt the
// named ESM imports into the shape it expects (the same functions the CLI uses).
const wasmForVault = { open_container, seal_to_container, totp, format_code };

// Fast Argon2 params so the demo is instant (m_cost >= 8 * p_cost). Production
// uses far higher costs — see sigil_core::Argon2Params::RECOMMENDED. The CLI
// (`sigil seal`) uses RECOMMENDED, but the container is self-describing, so
// open_container reads whichever params the file carries.
const PARAMS = { m_cost: 8, t_cost: 1, p_cost: 1 };
const AAD = new TextEncoder().encode("sigil-wasm-demo");

const $ = (id) => document.getElementById(id);
const enc = new TextEncoder();
const dec = new TextDecoder();

function toB64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}
function fromB64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// In-memory state carried from the last Seal to the next Open: the caller MUST
// persist (salt, params) alongside the envelope — they are not inside it.
let lastSalt = null;

async function main() {
  await init();
  $("version").textContent = version();

  // --- Raw record API: Seal / Open (envelope-as-base64) ------------------
  $("seal").addEventListener("click", () => {
    try {
      const password = enc.encode($("password").value);
      const plaintext = enc.encode($("plaintext").value);

      // Caller-supplied entropy: fresh salt + nonce from the browser CSPRNG.
      const salt = new Uint8Array(recommended_salt_len());
      crypto.getRandomValues(salt);
      const nonce = new Uint8Array(nonce_len());
      crypto.getRandomValues(nonce);

      const envelope = seal_record(
        password,
        salt,
        nonce,
        PARAMS.m_cost,
        PARAMS.t_cost,
        PARAMS.p_cost,
        AAD,
        plaintext,
      );

      lastSalt = salt; // remember for Open
      $("envelope").textContent = toB64(envelope);
      $("recovered").textContent = "";
    } catch (e) {
      $("envelope").textContent = "Seal error: " + e;
    }
  });

  $("open").addEventListener("click", () => {
    try {
      if (!lastSalt) {
        $("recovered").textContent = "Seal something first (need the salt).";
        return;
      }
      const password = enc.encode($("password").value);
      const envelope = fromB64($("envelope").textContent.trim());

      const recovered = open_record(
        password,
        lastSalt,
        PARAMS.m_cost,
        PARAMS.t_cost,
        PARAMS.p_cost,
        envelope,
      );
      $("recovered").textContent = dec.decode(recovered);
    } catch (e) {
      $("recovered").textContent = "Open error (wrong password / tampered?): " + e;
    }
  });

  // --- CLI-compatible SIGILcli container: download / upload --------------
  // Seal into a self-describing container and offer it as a .sigil download the
  // user can open with `sigil open` (SIGIL_PASSWORD=... sigil open --in file).
  $("download").addEventListener("click", () => {
    try {
      const password = enc.encode($("password").value);
      const plaintext = enc.encode($("plaintext").value);

      // Caller-supplied entropy: fresh salt + nonce from the browser CSPRNG.
      const salt = new Uint8Array(recommended_salt_len());
      crypto.getRandomValues(salt);
      const nonce = new Uint8Array(nonce_len());
      crypto.getRandomValues(nonce);

      const container = seal_to_container(
        password,
        salt,
        nonce,
        PARAMS.m_cost,
        PARAMS.t_cost,
        PARAMS.p_cost,
        plaintext,
      );

      const blob = new Blob([container], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "note.sigil";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      $("containerStatus").textContent =
        `Downloaded note.sigil (${container.length} bytes). Open it with: ` +
        `SIGIL_PASSWORD='…' sigil open --in note.sigil --out note.txt`;
    } catch (e) {
      $("containerStatus").textContent = "Download error: " + e;
    }
  });

  // Open an uploaded container (from this demo OR from `sigil seal`).
  $("containerFile").addEventListener("change", async (ev) => {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    try {
      const password = enc.encode($("password").value);
      const bytes = new Uint8Array(await file.arrayBuffer());
      const recovered = open_container(password, bytes);
      $("uploadRecovered").textContent = dec.decode(recovered);
      $("containerStatus").textContent =
        `Opened ${file.name} (${bytes.length} bytes) — a SIGILcli container.`;
    } catch (e) {
      $("uploadRecovered").textContent =
        "Open error (wrong password / not a SIGILcli container / tampered?): " + e;
    } finally {
      ev.target.value = ""; // allow re-selecting the same file
    }
  });

  // --- Hybrid PUBLIC-KEY (SIGILhyb) path ---------------------------------
  // The no-password path. JS holds the secret material (x25519 secret + mlkem
  // keypair-seed) in memory for this page; the wasm derives the public parts
  // and does the KEM-then-AEAD seal/open. All entropy is generated here.
  //
  // Field sizes are fixed by sigil-core (X25519 secret 32, ML-KEM keygen seed
  // 64, ML-KEM coin 32). The identity JSON mirrors the CLI's `.pub` format.
  const X25519_SECRET_LEN = 32;
  const MLKEM_SEED_LEN = 64;
  const MLKEM_COIN_LEN = 32;

  // In-memory secret identity for this page (never downloaded).
  let hybSecret = null; // { x25519_secret: Uint8Array, mlkem_seed: Uint8Array }
  let hybOwnPub = null; // { x25519_public_key: Uint8Array, mlkem_encaps_key: Uint8Array }
  // The recipient .pub a sender loaded (or null → seal to our own identity).
  let hybLoadedRecipient = null; // { x25519_public_key, mlkem_encaps_key } (Uint8Arrays)

  $("hybGen").addEventListener("click", () => {
    try {
      const x25519_secret = new Uint8Array(X25519_SECRET_LEN);
      crypto.getRandomValues(x25519_secret);
      const mlkem_seed = new Uint8Array(MLKEM_SEED_LEN);
      crypto.getRandomValues(mlkem_seed);

      const x25519_public_key = hybrid_x25519_public(x25519_secret);
      const mlkem_encaps_key = hybrid_mlkem_encaps_key(mlkem_seed);

      hybSecret = { x25519_secret, mlkem_seed };
      hybOwnPub = { x25519_public_key, mlkem_encaps_key };

      // Show the shareable PUBLIC identity in the CLI's .pub JSON shape.
      $("hybPub").textContent = JSON.stringify(
        {
          version: 1,
          x25519_public_key: toB64(x25519_public_key),
          mlkem_encaps_key: toB64(mlkem_encaps_key),
        },
        null,
        2,
      );
      $("hybStatus").textContent =
        "Generated a fresh hybrid identity (secret held in memory only).";
      $("hybRecovered").textContent = "";
    } catch (e) {
      $("hybStatus").textContent = "Keygen error: " + e;
    }
  });

  // Download the shareable PUBLIC identity as a CLI-compatible .pub JSON file.
  $("hybPubDownload").addEventListener("click", () => {
    if (!hybOwnPub) {
      $("hybStatus").textContent = "Generate a hybrid identity first.";
      return;
    }
    const json = JSON.stringify(
      {
        version: 1,
        x25519_public_key: toB64(hybOwnPub.x25519_public_key),
        mlkem_encaps_key: toB64(hybOwnPub.mlkem_encaps_key),
      },
      null,
      2,
    );
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "identity.key.pub";
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    $("hybStatus").textContent = "Downloaded identity.key.pub (share it with senders).";
  });

  // Load an optional recipient .pub (a CLI or demo identity JSON).
  $("hybRecipientPub").addEventListener("change", async (ev) => {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    try {
      const obj = JSON.parse(new TextDecoder().decode(await file.arrayBuffer()));
      const x = fromB64(obj.x25519_public_key);
      const ek = fromB64(obj.mlkem_encaps_key);
      if (x.length !== 32 || ek.length !== 1184) {
        throw new Error("bad key lengths in .pub (expected 32 / 1184 bytes)");
      }
      hybLoadedRecipient = { x25519_public_key: x, mlkem_encaps_key: ek };
      $("hybStatus").textContent = `Loaded recipient .pub ${file.name}; seal will encrypt TO it.`;
    } catch (e) {
      hybLoadedRecipient = null;
      $("hybStatus").textContent = "Could not read recipient .pub: " + e;
    }
  });

  // Hybrid-seal the plaintext to the loaded recipient (or our own identity) and
  // download the SIGILhyb container.
  $("hybSeal").addEventListener("click", () => {
    try {
      const recipient = hybLoadedRecipient ?? hybOwnPub;
      if (!recipient) {
        $("hybStatus").textContent = "Generate an identity or load a recipient .pub first.";
        return;
      }
      const plaintext = enc.encode($("hybPlaintext").value);

      // Caller-supplied entropy: ephemeral X25519 secret, ML-KEM coin, nonce.
      const ephSecret = new Uint8Array(X25519_SECRET_LEN);
      crypto.getRandomValues(ephSecret);
      const coin = new Uint8Array(MLKEM_COIN_LEN);
      crypto.getRandomValues(coin);
      const nonce = new Uint8Array(nonce_len());
      crypto.getRandomValues(nonce);

      const container = hybrid_seal_to_container(
        recipient.x25519_public_key,
        recipient.mlkem_encaps_key,
        ephSecret,
        coin,
        nonce,
        plaintext,
      );

      const blob = new Blob([container], { type: "application/octet-stream" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "note.hyb";
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      const to = hybLoadedRecipient ? "the loaded recipient .pub" : "your own identity";
      $("hybStatus").textContent =
        `Sealed ${container.length} bytes to ${to}; downloaded note.hyb. ` +
        `Open with: sigil hybrid-open --key your.key --in note.hyb --out note.txt`;
    } catch (e) {
      $("hybStatus").textContent = "Hybrid-seal error: " + e;
    }
  });

  // Open an uploaded SIGILhyb container with our in-memory secret identity.
  $("hybContainerFile").addEventListener("change", async (ev) => {
    const file = ev.target.files && ev.target.files[0];
    if (!file) return;
    try {
      if (!hybSecret) {
        $("hybRecovered").textContent = "Generate a hybrid identity first (need the secret).";
        return;
      }
      const bytes = new Uint8Array(await file.arrayBuffer());
      const recovered = hybrid_open_container(
        hybSecret.x25519_secret,
        hybSecret.mlkem_seed,
        bytes,
      );
      $("hybRecovered").textContent = dec.decode(recovered);
      $("hybStatus").textContent = `Opened ${file.name} (${bytes.length} bytes) — a SIGILhyb container.`;
    } catch (e) {
      $("hybRecovered").textContent =
        "Hybrid-open error (wrong identity / not a SIGILhyb container / tampered?): " + e;
    } finally {
      ev.target.value = ""; // allow re-selecting the same file
    }
  });

  // --- Sync over the dev sigild op-log (SIGILcli) ------------------------
  // Closes the E2EE loop from the browser using the shared, framework-free
  // sync.mjs transport: seal here, PUSH the OPAQUE bytes to the op-log, later
  // PULL them back and open with the same password. The server is zero-knowledge
  // (opaque bytes, no crypto); this interoperates with `sigil push`/`sigil pull`.
  $("syncPush").addEventListener("click", async () => {
    try {
      const base = $("syncServer").value.trim();
      const vault = $("syncVault").value.trim();
      if (!base || !vault) {
        $("syncStatus").textContent = "Enter a server URL and a vault ID first.";
        return;
      }
      const password = enc.encode($("password").value);
      const plaintext = enc.encode($("plaintext").value);

      // Caller-supplied entropy: fresh salt + nonce from the browser CSPRNG.
      const salt = new Uint8Array(recommended_salt_len());
      crypto.getRandomValues(salt);
      const nonce = new Uint8Array(nonce_len());
      crypto.getRandomValues(nonce);

      const container = seal_to_container(
        password,
        salt,
        nonce,
        PARAMS.m_cost,
        PARAMS.t_cost,
        PARAMS.p_cost,
        plaintext,
      );

      const { seq } = await pushContainer(base, vault, container);
      $("syncStatus").textContent =
        `Pushed ${container.length} opaque bytes to vault "${vault}" as seq ${seq}. ` +
        `Pull it back below, or with: sigil pull --vault ${vault} --out-dir ./inbox --server ${base}`;
      $("syncRecovered").textContent = "";
    } catch (e) {
      $("syncStatus").textContent =
        "Push error (is a dev sigild running with SIGILD_ENABLE_DEV_OPS=1?): " + e;
    }
  });

  $("syncPull").addEventListener("click", async () => {
    try {
      const base = $("syncServer").value.trim();
      const vault = $("syncVault").value.trim();
      if (!base || !vault) {
        $("syncStatus").textContent = "Enter a server URL and a vault ID first.";
        return;
      }
      const password = enc.encode($("password").value);

      // Drain the vault; open the LATEST container (highest seq).
      const ops = await pullContainers(base, vault, 0);
      if (ops.length === 0) {
        $("syncStatus").textContent = `Vault "${vault}" is empty — push something first.`;
        $("syncRecovered").textContent = "";
        return;
      }
      const latest = ops[ops.length - 1];
      const recovered = open_container(password, latest.container);
      $("syncStatus").textContent =
        `Pulled ${ops.length} op(s) from vault "${vault}"; opened the latest (seq ${latest.seq}).`;
      $("syncRecovered").textContent = dec.decode(recovered);
    } catch (e) {
      $("syncRecovered").textContent = "";
      $("syncStatus").textContent =
        "Pull/open error (wrong password / no dev sigild / empty vault?): " + e;
    }
  });

  // --- TOTP authenticator vault (SIGILcli) -------------------------------
  // An in-page vault of TOTP entries, showing the LIVE code for each (the browser
  // clock supplies the time; sigil-core reads none). The vault seals into the
  // SAME SIGILcli container the `sigil totp` CLI uses, and rides the same opaque
  // op-log via sync.mjs — so a secret added here can be read by `sigil totp`, and
  // vice versa. Vault logic lives in the shared, framework-free totp-vault.mjs.
  let totpVault = newVault();

  const escapeHtml = (s) =>
    String(s).replace(
      /[&<>"']/g,
      (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
    );

  // Repaint the vault list with each entry's CURRENT code + a countdown to the
  // next period. Called on every add/pull and once a second by the interval.
  function renderTotp() {
    const list = $("totpList");
    if (totpVault.entries.length === 0) {
      list.innerHTML = '<span class="muted">(empty — add a secret above)</span>';
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    list.innerHTML = "";
    for (const entry of totpVault.entries) {
      let code, remaining;
      try {
        code = codeForEntry(wasmForVault, entry, now);
        remaining = entry.period - (now % entry.period);
      } catch (e) {
        code = "error";
        remaining = 0;
      }
      const row = document.createElement("div");
      row.className = "totp-entry";
      const issuer = entry.issuer ? `${escapeHtml(entry.issuer)} · ` : "";
      row.innerHTML =
        `<span class="totp-code">${escapeHtml(code)}</span>` +
        `<strong>${escapeHtml(entry.label)}</strong>` +
        `<span class="totp-meta">${issuer}${escapeHtml(entry.algorithm)} · ` +
        `${entry.digits} digits · ${entry.period}s · next in ${remaining}s</span>`;
      list.appendChild(row);
    }
  }

  $("totpAdd").addEventListener("click", () => {
    try {
      const label = $("totpLabel").value.trim();
      const secretB32 = $("totpSecret").value.trim();
      const digits = parseInt($("totpDigits").value, 10);
      const period = parseInt($("totpPeriod").value, 10);
      const algorithm = $("totpAlgo").value;
      const secretBytes = base32Decode(secretB32);
      addEntry(totpVault, { label, secretBytes, algorithm, digits, period });
      $("totpStatus").textContent =
        `Added "${label}" to the in-page vault (${totpVault.entries.length} entr${
          totpVault.entries.length === 1 ? "y" : "ies"
        }). Seal + Push it to sync with the CLI.`;
      renderTotp();
    } catch (e) {
      $("totpStatus").textContent = "Add error: " + e;
    }
  });

  // Add a parsed TotpEntry (the vault shape, secret = base64) into the in-page
  // vault via addEntry (which takes RAW secret bytes), skipping a duplicate
  // label. Returns "added" | "duplicate".
  function addParsedEntry(entry) {
    if (totpVault.entries.some((e) => e.label === entry.label)) return "duplicate";
    addEntry(totpVault, {
      label: entry.label,
      issuer: entry.issuer,
      secretBytes: base64ToBytes(entry.secret),
      algorithm: entry.algorithm,
      digits: entry.digits,
      period: entry.period,
    });
    return "added";
  }

  // Import an otpauth:// (single) or otpauth-migration:// (bulk) URI.
  $("totpImport").addEventListener("click", () => {
    try {
      const uri = $("totpImportUri").value.trim();
      if (!uri) {
        $("totpStatus").textContent = "Paste an otpauth:// or otpauth-migration:// URI first.";
        return;
      }
      let entries;
      if (uri.toLowerCase().startsWith("otpauth-migration://")) {
        entries = decodeMigrationUri(uri); // may warn+skip HOTP entries
      } else if (uri.toLowerCase().startsWith("otpauth://")) {
        entries = [parseOtpauthUri(uri)];
      } else {
        throw new Error("not an otpauth:// or otpauth-migration:// URI");
      }
      let imported = 0;
      let duplicate = 0;
      for (const entry of entries) {
        if (addParsedEntry(entry) === "added") imported++;
        else duplicate++;
      }
      $("totpStatus").textContent =
        `Imported ${imported} entr${imported === 1 ? "y" : "ies"}` +
        (duplicate > 0 ? `, skipped ${duplicate} duplicate` : "") +
        `. Vault now has ${totpVault.entries.length}.`;
      renderTotp();
    } catch (e) {
      $("totpStatus").textContent = "Import error: " + e;
    }
  });

  // Export the vault as one otpauth:// URI per entry.
  $("totpExportOtpauth").addEventListener("click", () => {
    try {
      if (totpVault.entries.length === 0) {
        $("totpExportOut").textContent = "(vault is empty — add or import an entry first)";
        return;
      }
      $("totpExportOut").textContent = totpVault.entries.map(buildOtpauthUri).join("\n");
    } catch (e) {
      $("totpExportOut").textContent = "Export error: " + e;
    }
  });

  // Export the WHOLE vault as one Google Authenticator otpauth-migration:// URI.
  $("totpExportMigration").addEventListener("click", () => {
    try {
      if (totpVault.entries.length === 0) {
        $("totpExportOut").textContent = "(vault is empty — add or import an entry first)";
        return;
      }
      $("totpExportOut").textContent = encodeMigrationUri(totpVault.entries);
    } catch (e) {
      $("totpExportOut").textContent = "Export error: " + e;
    }
  });

  $("totpPush").addEventListener("click", async () => {
    try {
      const base = $("syncServer").value.trim();
      const vaultId = $("totpVaultId").value.trim();
      if (!base || !vaultId) {
        $("totpStatus").textContent = "Enter the Server URL (above) and a vault ID first.";
        return;
      }
      if (totpVault.entries.length === 0) {
        $("totpStatus").textContent = "Add an entry first — the vault is empty.";
        return;
      }
      const password = enc.encode($("password").value);

      // Caller-supplied entropy: fresh salt + nonce from the browser CSPRNG.
      const salt = new Uint8Array(recommended_salt_len());
      crypto.getRandomValues(salt);
      const nonce = new Uint8Array(nonce_len());
      crypto.getRandomValues(nonce);

      const container = sealVault(wasmForVault, password, totpVault, salt, nonce, PARAMS);
      const { seq } = await pushContainer(base, vaultId, container);
      $("totpStatus").textContent =
        `Sealed the vault (${container.length} opaque bytes) and pushed it to "${vaultId}" as seq ${seq}. ` +
        `Read it on the CLI with: SIGIL_PASSWORD='…' sigil pull --vault ${vaultId} --out-dir ./inbox --server ${base}`;
    } catch (e) {
      $("totpStatus").textContent =
        "Push error (is a dev sigild running with SIGILD_ENABLE_DEV_OPS=1?): " + e;
    }
  });

  $("totpPull").addEventListener("click", async () => {
    try {
      const base = $("syncServer").value.trim();
      const vaultId = $("totpVaultId").value.trim();
      if (!base || !vaultId) {
        $("totpStatus").textContent = "Enter the Server URL (above) and a vault ID first.";
        return;
      }
      const password = enc.encode($("password").value);

      const ops = await pullContainers(base, vaultId, 0);
      if (ops.length === 0) {
        $("totpStatus").textContent = `Vault "${vaultId}" is empty — push something first.`;
        return;
      }
      // Open the LATEST vault snapshot (highest seq) and replace the in-page vault.
      const latest = ops[ops.length - 1];
      totpVault = openVault(wasmForVault, password, latest.container);
      $("totpStatus").textContent =
        `Pulled + opened vault "${vaultId}" (seq ${latest.seq}) — ${totpVault.entries.length} ` +
        `entr${totpVault.entries.length === 1 ? "y" : "ies"}. Live codes below.`;
      renderTotp();
    } catch (e) {
      $("totpStatus").textContent =
        "Pull/open error (wrong password / no dev sigild / empty vault?): " + e;
    }
  });

  // Repaint the live codes + countdown once a second.
  renderTotp();
  setInterval(renderTotp, 1000);
}

main();
