// device-auth.mjs — the CLIENT half of sigild's multi-device auth model
// (op-log request-auth CONTRACT v3 + device enrollment), for JavaScript.
//
// This is the browser twin of the `sigil` CLI's device identity: it lets a
// browser client (the webapp, the MV3 extension, or Node) enroll as a real
// DEVICE and then sign every op-log request, so the same sigild that the CLI
// authenticates against accepts the browser too.
//
// ┌─ MIRRORED BYTE LAYOUT — KEEP IN SYNC ──────────────────────────────────────┐
// │ The canonical signed messages below are MIRRORED, not shared, from:        │
// │   * sigild/internal/api/deviceauth.go — canonicalV3Message /               │
// │     canonicalEnrollMessage / hashEnrollToken (the SERVER, source of truth); │
// │   * cli/src/lib.rs — canonical_v3_message / canonical_enroll_message /      │
// │     enroll_token_hash (the reference CLIENT).                              │
// │ All three MUST stay byte-for-byte identical. A one-byte drift here does not │
// │ fail loudly — it just yields 401 on every request.                          │
// └────────────────────────────────────────────────────────────────────────────┘
//
// WHAT THIS FILE DOES NOT DO: cryptography. Every signature is produced by the
// libsigil WebAssembly core (`ed25519_sign`, i.e. sigil-core's real Ed25519);
// SHA-256 of the enrollment token comes from Web Crypto (`crypto.subtle`). There
// is no hand-rolled signing here, and no placeholder.
//
// ENTROPY stays JS-supplied, matching the crate's caller-supplied-entropy
// invariant: the 32-byte device SEED and every per-request nonce are drawn with
// `crypto.getRandomValues` and passed INTO the wasm. The wasm draws none.
//
// SECRETS: the device seed and the enrollment token are secret bearer material.
// Nothing in this module logs them, and nothing here persists anything at all —
// storage is the caller's decision (the webapp and the extension keep the seed
// inside a SEALED container, never in plaintext).
//
// Works in BOTH Node (v20+: global fetch, webcrypto, Buffer) and the browser
// (fetch, crypto.subtle, btoa/atob). The only environment-specific bit is base64,
// which is feature-detected.
//
// ACCOUNTS (Phase 52) live at the bottom of this file: getAccount /
// createAccountInvite / listAccountInvites / revokeAccountInvite. They add NO
// canonical message and NO header — an account invite is redeemed by the
// UNCHANGED enrollDevice, and every account call is an ordinary v3 request.
//
// Pre-audit / UNAUDITED / DEV / LOCALHOST / PLAIN-HTTP. This is a real
// authorization model, not a reviewed one, and an account is AUTH METADATA ONLY:
// no email, no password, no session, no recovery. Do NOT point it at a remote
// host.

import { pushContainer, pullContainers } from "./sync.mjs";

// ── contract constants (mirrored from deviceauth.go / cli/src/lib.rs) ─────────

/** First line of the contract v3 signed message. sigild: `opsAuthDomainV3`. */
export const OPLOG_AUTH_V3_PREFIX = "sigil-oplog-auth-v3\n";

/** First line of the enrollment proof-of-possession challenge. sigild: `enrollDomain`. */
export const DEVICE_ENROLL_PREFIX = "sigil-device-enroll-v1\n";

/** Header carrying the enrolled device ID on a v3 request. */
export const HEADER_DEVICE = "X-Sigil-Device";
/** Header carrying the unix-seconds timestamp (v3 + enrollment). */
export const HEADER_TIMESTAMP = "X-Sigil-Timestamp";
/** Header carrying the fresh per-request nonce (v3 + enrollment). */
export const HEADER_NONCE = "X-Sigil-Nonce";
/** Header carrying the standard-base64 Ed25519 signature (v3 + enrollment). */
export const HEADER_SIGNATURE = "X-Sigil-Signature";
/** Header carrying the single-use enrollment token. SECRET — never log it. */
export const HEADER_ENROLL_TOKEN = "X-Sigil-Enroll-Token";
/** Header carrying the operator admin token. SECRET — never log it. */
export const HEADER_ADMIN_TOKEN = "X-Sigil-Admin-Token";

/** Ed25519 seed length in bytes. Mirrors sigil-core's SIG_SEED_LEN. */
export const DEVICE_SEED_LEN = 32;

/** Per-request nonce length in bytes. Mirrors the CLI's OPLOG_NONCE_LEN (>= 16). */
const NONCE_BYTES = 16;

// ── tiny environment-agnostic helpers ────────────────────────────────────────

const TEXT_ENCODER = new TextEncoder();

// NOTE: these two are deliberately NOT exported. `totp-vault.mjs` already
// exports `bytesToBase64`/`base64ToBytes`, and the `@sigil/wasm` loader
// star-re-exports both modules — duplicate star exports would make the name
// ambiguous and unimportable. Callers should use the totp-vault ones.

/** Encode bytes as STANDARD base64 (Node Buffer or browser btoa). */
function bytesToBase64(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  if (typeof Buffer !== "undefined") return Buffer.from(u8).toString("base64");
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}

/** Decode a STANDARD base64 string to bytes (Node Buffer or browser atob). */
function base64ToBytes(b64) {
  if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(b64, "base64"));
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/** The runtime's Web Crypto object (Node 20 exposes it globally, as do browsers). */
function webcrypto() {
  const c = globalThis.crypto;
  if (!c || !c.getRandomValues || !c.subtle) {
    throw new Error(
      "device-auth: Web Crypto (crypto.getRandomValues + crypto.subtle) is unavailable; " +
        "a secure context (https or localhost) is required",
    );
  }
  return c;
}

/**
 * Lowercase-hex SHA-256 of the enrollment token, exactly as sigild's
 * `hashEnrollToken` and the CLI's `enroll_token_hash` compute it. Only this
 * DIGEST is bound into the signed challenge; the plaintext token is never
 * stored or logged by this module.
 */
export async function enrollTokenHash(token) {
  const digest = await webcrypto().subtle.digest("SHA-256", TEXT_ENCODER.encode(token));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Concatenate strings/Uint8Arrays into one Uint8Array (strings as UTF-8). */
function concatBytes(parts) {
  const chunks = parts.map((p) => (typeof p === "string" ? TEXT_ENCODER.encode(p) : p));
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

/** Join a base URL and an absolute path without doubling or dropping the slash. */
function joinUrl(baseUrl, path) {
  return `${String(baseUrl).replace(/\/+$/, "")}${path}`;
}

// ── the canonical signed messages (MIRRORED — see the banner above) ───────────

/**
 * Build the byte-for-byte contract v3 signed message:
 *
 *   "sigil-oplog-auth-v3\n" + DEVICE_ID + "\n" + METHOD + "\n" + PATH + "\n" +
 *   QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + BODY
 *
 * METHOD is the uppercase HTTP method, PATH the DECODED URL path with no query
 * (Go's `r.URL.Path`), QUERY the RAW query string with no leading "?" ("" when
 * absent, Go's `r.URL.RawQuery`), TIMESTAMP decimal-ASCII unix seconds, NONCE the
 * EXACT `X-Sigil-Nonce` text, and BODY the raw request body bytes (empty for GET).
 */
export function canonicalV3Message(deviceId, method, path, query, timestamp, nonce, body) {
  return concatBytes([
    OPLOG_AUTH_V3_PREFIX,
    deviceId,
    "\n",
    method,
    "\n",
    path,
    "\n",
    query,
    "\n",
    timestamp,
    "\n",
    nonce,
    "\n",
    body ?? new Uint8Array(0),
  ]);
}

/**
 * Build the byte-for-byte device-enrollment proof-of-possession challenge:
 *
 *   "sigil-device-enroll-v1\n" + TOKEN_SHA256_HEX + "\n" + TIMESTAMP + "\n" +
 *   NONCE + "\n" + PUBLIC_KEY_B64 + "\n" + LABEL
 *
 * There is NO trailing newline after the label. PUBLIC_KEY_B64 and LABEL are the
 * EXACT strings placed in the JSON body, so both sides sign the same bytes.
 */
export function canonicalEnrollMessage(tokenHashHex, timestamp, nonce, publicKeyB64, label) {
  return concatBytes([
    DEVICE_ENROLL_PREFIX,
    tokenHashHex,
    "\n",
    timestamp,
    "\n",
    nonce,
    "\n",
    publicKeyB64,
    "\n",
    label ?? "",
  ]);
}

// ── device identity ──────────────────────────────────────────────────────────

/**
 * Draw a fresh 32-byte Ed25519 device seed from the CSPRNG.
 *
 * SECRET. Hand it to the wasm to sign; never log it, and never persist it in
 * plaintext (the clients keep it inside a sealed container).
 */
export function generateDeviceSeed() {
  return webcrypto().getRandomValues(new Uint8Array(DEVICE_SEED_LEN));
}

/** Fresh per-request nonce: 16 CSPRNG bytes, standard base64 (the TEXT is signed). */
function freshNonce() {
  return bytesToBase64(webcrypto().getRandomValues(new Uint8Array(NONCE_BYTES)));
}

/** Current unix seconds as the decimal-ASCII string that is signed AND sent. */
function unixSeconds() {
  return String(Math.floor(Date.now() / 1000));
}

/** Derive the 32-byte Ed25519 public key for a seed, via the wasm (real crypto). */
export function devicePublicKey(wasm, seed) {
  return new Uint8Array(wasm.ed25519_public_key(seed));
}

/** Reject device IDs that cannot sit verbatim in a URL path segment (CLI rule). */
function checkDeviceId(deviceId) {
  if (!deviceId || deviceId.includes("/") || /\s/.test(deviceId)) {
    throw new Error(
      `device-auth: invalid device id ${JSON.stringify(deviceId)}: must be non-empty with no "/" or whitespace`,
    );
  }
}

/** Same rule for vault IDs — mirrors the CLI's `check_vault`. */
function checkVaultId(vaultId) {
  if (!vaultId || vaultId.includes("/") || /\s/.test(vaultId)) {
    throw new Error(
      `device-auth: invalid vault id ${JSON.stringify(vaultId)}: must be non-empty with no "/" or whitespace`,
    );
  }
}

// ── sealed device-identity storage (the seed is NEVER stored in plaintext) ────
//
// A device identity is `{ deviceId, seed }` — and the seed is SECRET signing key
// material, so a client must not park it in localStorage / chrome.storage.local
// as plaintext bytes. These two helpers let a client keep it exactly the way it
// already keeps the TOTP vault: sealed into a `SIGILcli` container under the
// user's vault password (Argon2id -> XChaCha20-Poly1305, in the wasm). It is a
// SEPARATE container from the TOTP vault, so the CLI-mirrored `TotpVault` JSON
// schema is untouched, and it is only readable while the vault is unlocked.
//
// ── v2 (Phase 48): the container ALSO carries the SHARING secrets ────────────
//
// Device-to-device vault sharing (sharing.mjs) introduces two more pieces of
// bearer key material on a client:
//
//   * the HYBRID SECRET IDENTITY — {x25519Secret(32), mlkemSeed(64)} — the ONLY
//     thing that can open an envelope addressed to this device; and
//   * the VAULT KEYRING — `vaultId -> 32-byte vault key` for every shared vault
//     this device has re-keyed or accepted.
//
// The `sigil` CLI keeps those in 0600 files ($HOME/.sigil/device.hybrid and
// $HOME/.sigil/vault-keys.json) because a POSIX filesystem is what it has. A
// browser has no such thing, so they ride INSIDE this same sealed container:
// one password, one lock/unlock lifecycle, and NOTHING new persisted in the
// clear. Both are readable only while the vault is unlocked.
//
// The JSON field names deliberately mirror the CLI's on-disk shapes
// (`x25519_secret` / `mlkem_seed` from HybridSecretIdentity, and the
// `vaultId -> b64` map from VaultKeyring.keys).
//
// BACKWARD COMPATIBLE: v1 containers (no `hybrid`, no `vault_keys`) still open —
// they simply yield `hybrid: null` and an empty keyring. Both fields are omitted
// from the JSON entirely when absent, so a client that never shares writes the
// same shape it always did.

/** Schema version this build WRITES for the sealed device-identity JSON. */
export const DEVICE_IDENTITY_VERSION = 3;

/**
 * Schema versions this build can READ. v1 predates the sharing fields; v2
 * predates the Phase 50 hybrid-key PIN STORE.
 *
 * ⭐ WHY THE PIN STORE LIVES IN HERE. The browser clients persist ONLY sealed
 * containers — that is a load-bearing property and Phase 50 does not regress it.
 * A native client keeps its pin store as a 0600 file in its 0700 state dir; a
 * browser has no such thing, so the pins ride INSIDE this same sealed container,
 * under the same one password and the same lock/unlock lifecycle. Nothing new is
 * written to localStorage / chrome.storage in the clear.
 *
 * The pins are PUBLIC key material, but they are security-critical LOCAL state:
 * an attacker who can rewrite them can silence the key-substitution alarm.
 * Sealing them is exactly the right treatment.
 */
const SUPPORTED_DEVICE_IDENTITY_VERSIONS = [1, 2, 3];

/** X25519 secret scalar length in the sealed hybrid identity. */
const HYBRID_X25519_SECRET_LEN = 32;
/** ML-KEM-768 keygen seed length in the sealed hybrid identity. */
const HYBRID_MLKEM_SEED_LEN = 64;
/** Vault key length (mirrors cli/src/lib.rs::VAULT_KEY_LEN). */
const VAULT_KEY_LEN = 32;

/**
 * Seal a device identity into a `SIGILcli` container under `password`.
 *
 *   sealDeviceIdentity(wasm, password, identity, salt, nonce, params)
 *     -> Uint8Array (the sealed container; store THIS, never the secrets)
 *
 * `identity` is `{ deviceId, seed, baseUrl?, hybrid?, vaultKeys?, pins? }` where
 * `hybrid` is `{ x25519Secret: Uint8Array(32), mlkemSeed: Uint8Array(64) }`,
 * `vaultKeys` is `{ [vaultId]: Uint8Array(32) }`, and `pins` is the Phase 50
 * hybrid-key pin store `{ version, pins: { [deviceId]: {...} } }`. All three
 * sharing fields are OPTIONAL and are omitted from the JSON when absent.
 *
 * `salt` and `nonce` are caller-supplied CSPRNG bytes (`crypto.getRandomValues`),
 * exactly as for the TOTP vault. All crypto happens inside the wasm.
 */
export function sealDeviceIdentity(wasm, password, identity, salt, nonce, params) {
  const obj = {
    version: DEVICE_IDENTITY_VERSION,
    device_id: identity.deviceId,
    seed: bytesToBase64(identity.seed),
    base_url: identity.baseUrl ?? "",
  };
  if (identity.hybrid) {
    const h = identity.hybrid;
    if (
      !(h.x25519Secret instanceof Uint8Array) ||
      h.x25519Secret.length !== HYBRID_X25519_SECRET_LEN ||
      !(h.mlkemSeed instanceof Uint8Array) ||
      h.mlkemSeed.length !== HYBRID_MLKEM_SEED_LEN
    ) {
      throw new Error(
        `device-auth: hybrid must be { x25519Secret: Uint8Array(${HYBRID_X25519_SECRET_LEN}), ` +
          `mlkemSeed: Uint8Array(${HYBRID_MLKEM_SEED_LEN}) }`,
      );
    }
    obj.hybrid = {
      x25519_secret: bytesToBase64(h.x25519Secret),
      mlkem_seed: bytesToBase64(h.mlkemSeed),
    };
  }
  if (identity.vaultKeys && Object.keys(identity.vaultKeys).length > 0) {
    const keys = {};
    for (const [vaultId, key] of Object.entries(identity.vaultKeys)) {
      if (!(key instanceof Uint8Array) || key.length !== VAULT_KEY_LEN) {
        throw new Error(
          `device-auth: vault key for ${JSON.stringify(vaultId)} must be a ${VAULT_KEY_LEN}-byte Uint8Array`,
        );
      }
      keys[vaultId] = bytesToBase64(key);
    }
    obj.vault_keys = keys;
  }
  // Phase 50: the hybrid-key PIN STORE. Stored as-is (it is already plain JSON of
  // base64 strings, mirroring cli/src/lib.rs::HybridPinStore) and omitted when
  // empty, so a client that has never shared writes exactly the shape it always
  // did.
  if (identity.pins && Object.keys(identity.pins.pins ?? {}).length > 0) {
    obj.pins = { version: identity.pins.version ?? 1, pins: identity.pins.pins };
  }
  const pw = typeof password === "string" ? TEXT_ENCODER.encode(password) : password;
  return new Uint8Array(
    wasm.seal_to_container(
      pw,
      salt,
      nonce,
      params.m_cost,
      params.t_cost,
      params.p_cost,
      TEXT_ENCODER.encode(JSON.stringify(obj)),
    ),
  );
}

/**
 * Open a sealed device-identity container. Throws on a wrong password or a
 * tampered container (the AEAD tag fails), and on an unknown schema version.
 *
 *   -> { deviceId, seed: Uint8Array(32), baseUrl,
 *        hybrid: { x25519Secret, mlkemSeed } | null,
 *        vaultKeys: { [vaultId]: Uint8Array(32) },
 *        pins: { version, pins: { [deviceId]: {...} } } }
 *
 * A v1 container (written before sharing existed) opens fine and yields
 * `hybrid: null` with an empty `vaultKeys`; a v2 container yields an EMPTY pin
 * store, so an existing client keeps working and simply pins on next use.
 */
export function openDeviceIdentity(wasm, password, containerBytes) {
  const pw = typeof password === "string" ? TEXT_ENCODER.encode(password) : password;
  const plain = wasm.open_container(pw, containerBytes);
  const obj = JSON.parse(new TextDecoder().decode(plain));
  if (!SUPPORTED_DEVICE_IDENTITY_VERSIONS.includes(obj.version)) {
    throw new Error(`device-auth: unsupported device identity version ${obj.version}`);
  }
  const seed = base64ToBytes(obj.seed);
  if (seed.length !== DEVICE_SEED_LEN) {
    throw new Error(`device-auth: stored seed is ${seed.length} bytes, expected ${DEVICE_SEED_LEN}`);
  }

  let hybrid = null;
  if (obj.hybrid) {
    const x25519Secret = base64ToBytes(obj.hybrid.x25519_secret ?? "");
    const mlkemSeed = base64ToBytes(obj.hybrid.mlkem_seed ?? "");
    if (
      x25519Secret.length !== HYBRID_X25519_SECRET_LEN ||
      mlkemSeed.length !== HYBRID_MLKEM_SEED_LEN
    ) {
      throw new Error(
        `device-auth: stored hybrid identity is ${x25519Secret.length}/${mlkemSeed.length} bytes, ` +
          `expected ${HYBRID_X25519_SECRET_LEN}/${HYBRID_MLKEM_SEED_LEN}`,
      );
    }
    hybrid = { x25519Secret, mlkemSeed };
  }

  const vaultKeys = {};
  for (const [vaultId, encoded] of Object.entries(obj.vault_keys ?? {})) {
    const key = base64ToBytes(encoded);
    if (key.length !== VAULT_KEY_LEN) {
      throw new Error(
        `device-auth: stored vault key for ${JSON.stringify(vaultId)} is ${key.length} bytes, expected ${VAULT_KEY_LEN}`,
      );
    }
    vaultKeys[vaultId] = key;
  }

  // Phase 50 pin store. Absent (v1/v2) => empty, i.e. everything is first-sight.
  const pins =
    obj.pins && typeof obj.pins === "object" && typeof obj.pins.pins === "object"
      ? { version: obj.pins.version ?? 1, pins: obj.pins.pins }
      : { version: 1, pins: {} };

  return { deviceId: obj.device_id, seed, baseUrl: obj.base_url ?? "", hybrid, vaultKeys, pins };
}

// ── errors ───────────────────────────────────────────────────────────────────

/**
 * An HTTP failure from a device-auth call, carrying the STATUS so a caller can
 * tell 401 (not authenticated) from 403 (authenticated but not authorized for
 * this vault) without string-matching.
 */
export class DeviceAuthError extends Error {
  constructor(status, message, body) {
    super(message);
    this.name = "DeviceAuthError";
    /** @type {number} HTTP status code. */
    this.status = status;
    /** @type {string} the raw response body (coarse server text, no secrets). */
    this.body = body ?? "";
  }
}

/**
 * A human-readable explanation for a device-auth status. The server deliberately
 * returns COARSE reasons (it never says which check tripped), so this explains
 * the CLASS of failure and what to do about it.
 */
export function explainAuthStatus(status) {
  switch (status) {
    case 401:
      return "401 unauthorized — this device is not authenticated (unknown, revoked, bad signature, clock skew over 300s, or a replayed request).";
    case 403:
      return "403 forbidden — this device IS authenticated but is not permitted. Either it is not authorized for that vault (ask a device in the owning account to grant it access), or it carries NO ACCOUNT at all — which happens only when a pre-account-model server enrolled it against an already-migrated database, and which an operator repairs with `sigild migrate adopt`. The two are deliberately indistinguishable from here.";
    // ⭐ A 402 is a BILLING state, and it must never read as an auth failure.
    // This arm exists so that EVERY surface that can receive one explains it:
    // explainSharingStatus falls through to here, and the extension's popup
    // rendered a lapsed-account cross-account share as an anonymous "HTTP 402".
    // The wording matches the webapp's billing region and entitlement.mjs.
    case 402:
      return "402 payment required — this is a BILLING state, not a sign-in problem and not a bug. The server authenticated and authorized this device and THEN asked for payment. Reading is never refused: existing codes, pulls and already-shared keys keep working. Renew the subscription to resume uploading new changes.";
    case 404:
      return "404 not found — no such open invite in YOUR account. An invite belonging to another account is deliberately indistinguishable from one that never existed.";
    case 409:
      return "409 conflict — that public key is already enrolled, or the account is at its device / open-invite limit.";
    case 500:
      return "500 server error — a server-side fault (the device registry could not be read or written). It is NOT a verdict on this device: retry.";
    case 501:
      return "501 not implemented — the server does not have the device model enabled (SIGILD_ENABLE_DEV_OPS + SIGILD_DEVICE_AUTH).";
    default:
      return `HTTP ${status}`;
  }
}

/**
 * Await a transport promise and, if it rejects with an auth-class status (the
 * transport attaches `.status`), rethrow it as a {@link DeviceAuthError} carrying
 * the plain-language 401-vs-403 explanation. Any other failure passes through
 * untouched.
 */
async function asAuthError(promise, what) {
  try {
    return await promise;
  } catch (e) {
    const status = e && typeof e.status === "number" ? e.status : 0;
    if (status === 401 || status === 403 || status === 501) {
      throw new DeviceAuthError(status, `${what}: ${explainAuthStatus(status)}`, e.message);
    }
    throw e;
  }
}

async function failResponse(res, what) {
  const body = await res.text().catch(() => "");
  throw new DeviceAuthError(
    res.status,
    `${what}: ${explainAuthStatus(res.status)}${body ? ` — ${body.trim()}` : ""}`,
    body,
  );
}

// ── enrollment ───────────────────────────────────────────────────────────────

/**
 * ENROLL this client's Ed25519 public key with sigild and return the assigned
 * device ID.
 *
 *   enrollDevice(wasm, { baseUrl, token, label, seed })
 *     -> { deviceId, publicKey: Uint8Array, publicKeyB64, label, status, createdAt }
 *
 * Two independent factors are sent, both mandatory server-side:
 *   1. the operator-provisioned, SINGLE-USE enrollment token (a bearer secret,
 *      sent in `X-Sigil-Enroll-Token`, never logged here);
 *   2. PROOF OF POSSESSION — an Ed25519 signature by `seed` (produced IN THE
 *      WASM) over {@link canonicalEnrollMessage}, which binds the token digest,
 *      the timestamp, a fresh nonce, the submitted public key and the label.
 *
 * An OPERATOR enrollment token is single-use and a FAILED attempt burns it too,
 * exactly as the server documents.
 *
 * ⭐ JOINING AN ACCOUNT USES THIS SAME CALL (Phase 52). An account INVITE minted
 * by a device already in an account (see {@link createAccountInvite}) is passed
 * as `token` here, verbatim — the enrollment challenge already binds the token
 * DIGEST, so an invite needs no new header, no new signed-message domain and no
 * client change. An operator token founds a NEW account; an invite JOINS the
 * inviter's. The returned `accountId` says which, and is `""` against a server
 * without the account model.
 *
 * Throws {@link DeviceAuthError} on any non-201.
 */
export async function enrollDevice(wasm, { baseUrl, token, label = "", seed }) {
  if (!token) throw new Error("device-auth: an enrollment token is required");
  if (!(seed instanceof Uint8Array) || seed.length !== DEVICE_SEED_LEN) {
    throw new Error(`device-auth: seed must be a ${DEVICE_SEED_LEN}-byte Uint8Array`);
  }

  const publicKey = devicePublicKey(wasm, seed);
  const publicKeyB64 = bytesToBase64(publicKey);

  // Serialize the body FIRST, then sign the EXACT strings it carries — the
  // server verifies over the DECODED JSON strings, so escaping cannot diverge.
  const bodyText = JSON.stringify({ public_key: publicKeyB64, label });
  const bodyBytes = TEXT_ENCODER.encode(bodyText);

  const timestamp = unixSeconds();
  const nonce = freshNonce();
  const tokenHash = await enrollTokenHash(token);
  const message = canonicalEnrollMessage(tokenHash, timestamp, nonce, publicKeyB64, label);
  const signature = bytesToBase64(wasm.ed25519_sign(seed, message));

  const res = await globalThis.fetch(joinUrl(baseUrl, "/v1/devices/enroll"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      [HEADER_ENROLL_TOKEN]: token,
      [HEADER_TIMESTAMP]: timestamp,
      [HEADER_NONCE]: nonce,
      [HEADER_SIGNATURE]: signature,
    },
    body: bodyBytes,
  });
  if (res.status !== 201) await failResponse(res, "enrollDevice");

  const json = await res.json();
  if (typeof json.device_id !== "string" || json.device_id === "") {
    throw new Error(`device-auth: enrollment 201 had no device_id: ${JSON.stringify(json)}`);
  }
  return {
    deviceId: json.device_id,
    publicKey,
    publicKeyB64,
    label: json.label ?? label,
    status: json.status ?? "active",
    createdAt: json.created_at ?? "",
    // ADDITIVE (Phase 52): a server without the account model omits it.
    accountId: json.account_id ?? "",
  };
}

// ── signed requests (contract v3) ─────────────────────────────────────────────

/**
 * Perform ONE contract-v3-signed request.
 *
 *   signedFetch(wasm, { baseUrl, deviceId, seed }, method, path, query, bodyBytes, headers?)
 *     -> Response
 *
 * `path` is the absolute URL path (e.g. `/v1/vaults/demo/ops`) and `query` the
 * RAW query string with no leading "?" (`""` when absent) — the two are signed
 * EXACTLY as they go on the wire. A FRESH nonce and the CURRENT unix seconds are
 * used on every call, so a captured request cannot be replayed inside the
 * server's 300 s window.
 *
 * Returns the raw `Response` (it does NOT throw on 401/403) so callers can map
 * the status themselves; the wrappers below throw {@link DeviceAuthError}.
 */
export async function signedFetch(
  wasm,
  { baseUrl, deviceId, seed },
  method,
  path,
  query = "",
  bodyBytes = null,
  headers = {},
) {
  checkDeviceId(deviceId);
  if (!(seed instanceof Uint8Array) || seed.length !== DEVICE_SEED_LEN) {
    throw new Error(`device-auth: seed must be a ${DEVICE_SEED_LEN}-byte Uint8Array`);
  }
  const upper = String(method).toUpperCase();
  const body = bodyBytes ? (bodyBytes instanceof Uint8Array ? bodyBytes : new Uint8Array(bodyBytes)) : null;

  const timestamp = unixSeconds();
  const nonce = freshNonce();
  const message = canonicalV3Message(
    deviceId,
    upper,
    path,
    query,
    timestamp,
    nonce,
    body ?? new Uint8Array(0),
  );
  const signature = bytesToBase64(wasm.ed25519_sign(seed, message));

  const url = joinUrl(baseUrl, query ? `${path}?${query}` : path);
  const init = {
    method: upper,
    headers: {
      ...headers,
      [HEADER_DEVICE]: deviceId,
      [HEADER_TIMESTAMP]: timestamp,
      [HEADER_NONCE]: nonce,
      [HEADER_SIGNATURE]: signature,
    },
  };
  if (body) init.body = body;
  return globalThis.fetch(url, init);
}

/**
 * Build a `fetch`-shaped function that signs every call under contract v3.
 *
 * This is what lets the UNCHANGED, already-proven `sync.mjs` transport speak the
 * authenticated contract: it takes an optional `fetch` implementation, so the
 * unauthenticated path stays byte-identical while the authenticated path just
 * swaps in this signer.
 *
 * It reconstructs the signed `(method, path, query, body)` from the URL the
 * transport built: `path` is the DECODED pathname (Go's `r.URL.Path`) and
 * `query` the raw search string minus the leading "?" (Go's `r.URL.RawQuery`).
 */
export function makeSignedFetch(wasm, identity) {
  return async function signingFetch(url, init = {}) {
    const u = new URL(url);
    let path = u.pathname;
    try {
      path = decodeURIComponent(u.pathname);
    } catch {
      // A malformed percent-escape: sign the raw pathname rather than throwing.
    }
    const query = u.search.startsWith("?") ? u.search.slice(1) : u.search;
    const body = init.body ?? null;
    return signedFetch(
      wasm,
      { ...identity, baseUrl: u.origin },
      init.method ?? "GET",
      path,
      query,
      body,
      init.headers ?? {},
    );
  };
}

// ── authenticated sync (thin wrappers over the proven sync.mjs transport) ─────

/**
 * PUSH a sealed container to the op-log as an authenticated DEVICE.
 *
 *   pushContainerAuthed(wasm, identity, baseUrl, vaultId, containerBytes) -> { seq }
 *
 * `identity` is `{ deviceId, seed }`. Under contract v3 a WRITE to an unclaimed
 * vault CLAIMS it for this device (trust-on-first-write); a write to a vault
 * owned by another device is 403.
 *
 * Like the unauthenticated path, this moves OPAQUE bytes and does no crypto on
 * the container — it only signs the REQUEST.
 *
 * `opts.onResponse(res)` is OPTIONAL and additive: it receives the raw Response
 * before the body is read, which is the ONLY way to see sigild's
 * `X-Sigil-Entitlement*` headers — they ride on a write that is still being
 * SERVED inside the grace period, so they never appear in an error. Pass
 * `entitlement.mjs`'s `readEntitlementHeaders` here to surface that warning. An
 * observer that throws is ignored; it cannot break a push.
 */
export async function pushContainerAuthed(
  wasm,
  identity,
  baseUrl,
  vaultId,
  containerBytes,
  opts = {},
) {
  checkVaultId(vaultId);
  return asAuthError(
    pushContainer(baseUrl, vaultId, containerBytes, {
      fetch: makeSignedFetch(wasm, identity),
      onResponse: opts.onResponse,
    }),
    "pushContainerAuthed",
  );
}

/**
 * PULL (and drain) a vault's sealed containers as an authenticated DEVICE.
 *
 *   pullContainersAuthed(wasm, identity, baseUrl, vaultId, since?) -> [{seq, container, hash}]
 *
 * A READ never claims a vault: reading an unowned vault, or one owned by another
 * device with no grant, is 403.
 */
export async function pullContainersAuthed(wasm, identity, baseUrl, vaultId, sinceOpt = 0) {
  checkVaultId(vaultId);
  return asAuthError(
    pullContainers(baseUrl, vaultId, sinceOpt, {
      fetch: makeSignedFetch(wasm, identity),
    }),
    "pullContainersAuthed",
  );
}

// ── vault grants + revocation (device administration) ─────────────────────────

/**
 * GRANT another enrolled device access to a vault. OWNER-ONLY: `identity` must
 * be the device that claimed the vault on first write.
 *
 * `permission` is `"read"` or `"write"`.
 */
export async function grantVaultAccess(
  wasm,
  identity,
  baseUrl,
  vaultId,
  granteeDeviceId,
  permission = "read",
) {
  if (permission !== "read" && permission !== "write") {
    throw new Error(`device-auth: permission must be "read" or "write", got ${permission}`);
  }
  checkVaultId(vaultId);
  checkDeviceId(granteeDeviceId);
  // The path is signed and sent VERBATIM (like the CLI's grant call); checkVaultId
  // keeps it a single, escape-free URL segment so both sides see the same bytes.
  const path = `/v1/vaults/${vaultId}/grants`;
  const body = TEXT_ENCODER.encode(JSON.stringify({ device_id: granteeDeviceId, permission }));
  const res = await signedFetch(wasm, { ...identity, baseUrl }, "POST", path, "", body, {
    "Content-Type": "application/json",
  });
  if (res.status !== 201) await failResponse(res, "grantVaultAccess");
  return res.json();
}

/** LIST a vault's grants. Any device with READ access may see them. */
export async function listVaultGrants(wasm, identity, baseUrl, vaultId) {
  checkVaultId(vaultId);
  const path = `/v1/vaults/${vaultId}/grants`;
  const res = await signedFetch(wasm, { ...identity, baseUrl }, "GET", path, "", null);
  if (res.status !== 200) await failResponse(res, "listVaultGrants");
  return res.json();
}

/**
 * SELF-REVOKE this device: a v3-signed POST to its own revoke route. A device may
 * retire itself; it may NOT revoke another device (the server answers 403).
 */
export async function revokeSelf(wasm, identity, baseUrl) {
  const path = `/v1/devices/${identity.deviceId}/revoke`;
  const res = await signedFetch(wasm, { ...identity, baseUrl }, "POST", path, "", new Uint8Array(0), {
    "Content-Type": "application/json",
  });
  if (res.status !== 200) await failResponse(res, "revokeSelf");
  return res.json();
}

/**
 * OPERATOR revoke of ANY device, using the admin token (a bearer secret, never
 * logged here). This is the break-glass path for a lost device.
 */
export async function revokeDeviceAdmin({ baseUrl, adminToken, deviceId }) {
  checkDeviceId(deviceId);
  const res = await globalThis.fetch(
    joinUrl(baseUrl, `/v1/devices/${encodeURIComponent(deviceId)}/revoke`),
    {
      method: "POST",
      headers: { "Content-Type": "application/json", [HEADER_ADMIN_TOKEN]: adminToken },
    },
  );
  if (res.status !== 200) await failResponse(res, "revokeDeviceAdmin");
  return res.json();
}

/** OPERATOR list of every registered device (admin token; no keys are returned). */
export async function listDevices({ baseUrl, adminToken }) {
  const res = await globalThis.fetch(joinUrl(baseUrl, "/v1/devices"), {
    headers: { [HEADER_ADMIN_TOKEN]: adminToken },
  });
  if (res.status !== 200) await failResponse(res, "listDevices");
  return res.json();
}

// ── the ACCOUNT model (Phase 52) ─────────────────────────────────────────────
//
// An ACCOUNT is a group of one person's own devices. It is what a SUBSCRIPTION
// and a VAULT'S OWNERSHIP belong to — so paying on one device entitles the
// others, and revoking one device no longer orphans the vaults it claimed.
//
// THE STRUCTURAL RULE, MIRRORED HERE: nothing below puts an account id in a
// path, a query string or a body. The server always reads the account off the
// device row of the signature it just verified, which is what makes a
// cross-account request unconstructible rather than merely rejected. If you ever
// find yourself wanting to add an `accountId` parameter to one of these, the
// design has failed.
//
// NO NEW CRYPTO AND NO NEW WIRE FORMAT: every call rides the EXISTING
// {@link signedFetch} contract-v3 path, and JOINING rides the EXISTING
// {@link enrollDevice} path with the invite as its `token`. The three canonical
// message implementations (Go server, Rust CLI, this module) are untouched.
//
// HONEST SCOPE — surface these in any UI built on this module:
//   * NO RECOVERY. An account is reachable only through a member device's
//     private key. Lose or revoke every device and the account, its vaults and
//     its subscription are permanently unreachable.
//   * Joining grants AUTHORIZATION, never DECRYPTION. A joined device reads
//     nothing until a member wraps the vault key to its hybrid public key
//     (sharing.mjs). "Device joined — waiting for a key from another device" is
//     the honest state to render.
//   * Membership is FLAT: any member may invite, revoke every other member, and
//     run checkout. Revoking a compromised device does NOT revoke the devices it
//     invited.
//   * An UNPINNED invite is a BEARER SECRET for its whole TTL, over a plain-HTTP
//     dev transport.

/** Reject invite handles that cannot sit verbatim in a URL path segment. */
function checkInviteId(inviteId) {
  if (typeof inviteId !== "string" || inviteId === "" || /[\/\s]/.test(inviteId)) {
    throw new Error(`device-auth: invalid invite id ${JSON.stringify(inviteId)}`);
  }
}

/**
 * READ the signing device's own account.
 *
 *   getAccount(wasm, identity, baseUrl)
 *     -> { account_id, created_at, device_count, device_limit, devices: [...] }
 *
 * There is no route that reads another account and none that enumerates them, so
 * this is always "mine". A 403 can mean the device carries no account — the
 * server fails CLOSED there rather than falling back to the device id, and does
 * it with the SAME coarse body as any other refusal so no oracle appears. That
 * state is only produced by a pre-account-model server writing to an
 * already-migrated database; the operator repairs it with `sigild migrate adopt`.
 */
export async function getAccount(wasm, identity, baseUrl) {
  const res = await signedFetch(wasm, { ...identity, baseUrl }, "GET", "/v1/account", "", null);
  if (res.status !== 200) await failResponse(res, "getAccount");
  return res.json();
}

/**
 * MINT a single-use invite that lets ONE more device join this account.
 *
 *   createAccountInvite(wasm, identity, baseUrl, { ttlSeconds?, inviteePublicKey? })
 *     -> { invite_id, invite, account_id, expires_at, pinned }
 *
 * ⚠️ `invite` is a BEARER SECRET returned exactly ONCE: it is never re-served,
 * never logged and stored only as a digest. Show it once, do not persist it, and
 * clear it from memory after use — the same handling this module already gives
 * an enrollment token.
 *
 * `ttlSeconds` may only SHORTEN the invite's life (the server clamps to its own
 * ceiling). `inviteePublicKey` (a 32-byte Uint8Array, the joining device's
 * Ed25519 public key from {@link devicePublicKey}) PINS the invite to that one
 * key, so an intercepted invite is useless to anyone else. Nothing forces
 * pinning; prefer it whenever the UI can carry the public key back.
 *
 * The joining device redeems it through the UNCHANGED {@link enrollDevice}.
 */
export async function createAccountInvite(
  wasm,
  identity,
  baseUrl,
  { ttlSeconds = 0, inviteePublicKey = null } = {},
) {
  // NOTE WHAT IS NOT HERE: no account id and no subject. The invite always lands
  // in the CALLER's account, resolved server-side from the signature.
  const payload = {};
  if (ttlSeconds > 0) payload.ttl_seconds = Math.floor(ttlSeconds);
  if (inviteePublicKey) {
    if (!(inviteePublicKey instanceof Uint8Array) || inviteePublicKey.length !== DEVICE_SEED_LEN) {
      throw new Error(
        `device-auth: inviteePublicKey must be a ${DEVICE_SEED_LEN}-byte Uint8Array (an Ed25519 public key)`,
      );
    }
    payload.invitee_public_key = bytesToBase64(inviteePublicKey);
  }
  const body = TEXT_ENCODER.encode(JSON.stringify(payload));

  const res = await signedFetch(
    wasm,
    { ...identity, baseUrl },
    "POST",
    "/v1/account/invites",
    "",
    body,
    { "Content-Type": "application/json" },
  );
  if (res.status !== 201) await failResponse(res, "createAccountInvite");
  return res.json();
}

/**
 * LIST this account's OPEN invites. METADATA ONLY — the secret and its digest are
 * never served, so a minted invite can never be recovered from the server.
 */
export async function listAccountInvites(wasm, identity, baseUrl) {
  const res = await signedFetch(
    wasm,
    { ...identity, baseUrl },
    "GET",
    "/v1/account/invites",
    "",
    null,
  );
  if (res.status !== 200) await failResponse(res, "listAccountInvites");
  return res.json();
}

/**
 * REVOKE an unredeemed invite of this account, by its PUBLIC handle.
 *
 * The server scopes the lookup by (account, invite id), so a FOREIGN handle and a
 * MISSING one both answer 404 — there is no enumeration oracle, which is why this
 * cannot tell you which it was.
 */
export async function revokeAccountInvite(wasm, identity, baseUrl, inviteId) {
  checkInviteId(inviteId);
  const path = `/v1/account/invites/${inviteId}/revoke`;
  const res = await signedFetch(
    wasm,
    { ...identity, baseUrl },
    "POST",
    path,
    "",
    new Uint8Array(0),
    { "Content-Type": "application/json" },
  );
  if (res.status !== 200) await failResponse(res, "revokeAccountInvite");
  return res.json();
}
