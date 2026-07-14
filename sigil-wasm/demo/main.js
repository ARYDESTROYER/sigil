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
  nonce_len,
  recommended_salt_len,
  version,
} from "../pkg-web/sigil_wasm.js";

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
}

main();
