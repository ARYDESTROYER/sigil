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
}

main();
