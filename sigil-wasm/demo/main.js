// main.js — framework-free driver for the sigil-wasm browser demo.
//
// Pre-audit / UNAUDITED demo of the wasm-pure sigil-core. Do NOT enter real
// secrets. Requires ./build-wasm.sh to have produced ../pkg-web first.

import init, {
  seal_record,
  open_record,
  nonce_len,
  recommended_salt_len,
  version,
} from "../pkg-web/sigil_wasm.js";

// Fast Argon2 params so the demo is instant (m_cost >= 8 * p_cost). Production
// uses far higher costs — see sigil_core::Argon2Params::RECOMMENDED.
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
}

main();
