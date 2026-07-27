// sharing.mjs — the CLIENT half of DEVICE-TO-DEVICE VAULT SHARING, for
// JavaScript. This is the browser twin of the `sigil vault ...` /
// `sigil device hybrid-publish` commands: it lets the webapp, the MV3 extension
// or Node publish a hybrid public key, wrap a vault key to another enrolled
// device, relay the opaque envelope through sigild, and accept a vault shared to
// this device.
//
// ┌─ MIRRORED SEMANTICS + BYTE LAYOUTS — KEEP IN SYNC ─────────────────────────┐
// │ Everything here is MIRRORED, not shared, from:                             │
// │   * cli/src/lib.rs — generate_hybrid_identity / wrap_vault_key /            │
// │     unwrap_vault_key / publish_hybrid_key / fetch_hybrid_key /              │
// │     put_key_envelope / get_key_envelope / vault_key_fingerprint /           │
// │     VAULT_KEY_LEN, and cli/src/main.rs's `vault rekey|share|accept`         │
// │     (the REFERENCE client);                                                 │
// │   * sigild/internal/api/sharing.go — the four routes, their request and     │
// │     response shapes, and the 401-vs-403 rules (the SERVER, source of truth);│
// │   * sigil-wasm/src/lib.rs — the `SIGILhyb` container layout produced by     │
// │     hybrid_seal_to_container (magic 8 ‖ version 1 ‖ eph_x25519_pub 32 ‖     │
// │     mlkem_ct 1088 ‖ envelope). A 32-byte vault key wraps to 1226 bytes.     │
// │ A drift here does not fail loudly — it yields a 400/403 or an envelope the  │
// │ CLI cannot open. The cross-client Node test (test/sharing-interop.mjs) is   │
// │ the guard: it shares BOTH ways against a live sigild and the real CLI.      │
// └────────────────────────────────────────────────────────────────────────────┘
//
// THE KEY MODEL (identical to the CLI's — deviating breaks interop AND security):
//
//   human password ──Argon2id──> seals a PERSONAL vault. NEVER shared, NEVER
//                                wrapped, never leaves this device.
//   vault key = 32 CSPRNG bytes ──> seals a SHARED vault. The `SIGILcli`
//                                container takes arbitrary password BYTES, so a
//                                random 32-byte key drops in exactly where a
//                                password goes — no format change at all.
//        │
//        └── wrapped per recipient with `hybrid_seal_to_container`
//            (X25519 + ML-KEM-768 -> XChaCha20-Poly1305) into an OPAQUE
//            `SIGILhyb` envelope that sigild relays and cannot read.
//
// WHAT THIS FILE DOES NOT DO: cryptography. Every KEM/AEAD operation happens
// inside the libsigil WebAssembly core; every request signature is produced by
// device-auth.mjs (which itself only calls the wasm). There is nothing
// hand-rolled here.
//
// ENTROPY is JS-supplied, matching the crate's caller-supplied-entropy invariant
// (ADR 0007): the hybrid identity (X25519 secret + ML-KEM seed), every vault key,
// and the per-wrap ephemeral X25519 secret / ML-KEM coin / AEAD nonce are all
// drawn with `crypto.getRandomValues` and passed INTO the wasm. The wasm draws
// none, so both Cargo.lock files stay `getrandom`-free.
//
// SECRETS: a hybrid SECRET identity and a vault key are bearer key material.
// Nothing here logs them and nothing here persists anything — storage is the
// caller's decision, and the browser clients keep both inside the SEALED
// device-identity container (see device-auth.mjs `sealDeviceIdentity`), never in
// plaintext localStorage / chrome.storage.local. A vault key is never rendered:
// {@link vaultKeyFingerprint} exists so two devices can prove they hold the same
// key without either printing it (mirrors the CLI's `vault_key_fingerprint`).
//
// Works in BOTH Node (v20+: global fetch, webcrypto, Buffer) and the browser.
//
// HONEST SCOPE: pre-audit, UNAUDITED, DEV / LOCALHOST / PLAIN-HTTP. The hybrid
// construction is a CUSTOM KEM-then-AEAD, NOT RFC 9180 HPKE; the SYSTEM is NOT
// "post-quantum secure". There is NO out-of-band verification of a published
// hybrid public key (a hostile registry could substitute its own — compare
// fingerprints out of band). Revoking a device stops FUTURE server access; it
// cannot make a device forget a vault key it already accepted.

import { signedFetch, grantVaultAccess, DeviceAuthError, explainAuthStatus } from "./device-auth.mjs";
import { bytesToBase64, base64ToBytes } from "./totp-vault.mjs";

// ── sizes (mirrored from cli/src/lib.rs + sigil-core) ────────────────────────

/** A vault key is 32 CSPRNG bytes. cli/src/lib.rs::VAULT_KEY_LEN. */
export const VAULT_KEY_LEN = 32;
/** X25519 secret scalar length. */
export const HYBRID_X25519_SECRET_LEN = 32;
/** X25519 public key length (the server length-checks this). */
export const HYBRID_X25519_PUBLIC_LEN = 32;
/** ML-KEM-768 keygen seed (`d‖z`) length. */
export const HYBRID_MLKEM_SEED_LEN = 64;
/** ML-KEM-768 encapsulation key length (the server length-checks this). */
export const HYBRID_MLKEM_ENCAPS_LEN = 1184;
/** The 8-byte magic every wrapped-key envelope starts with. */
export const KEY_ENVELOPE_MAGIC = "SIGILhyb";
/** Byte length of a wrapped 32-byte vault key: 8+1+32+1088+(24+32+16). */
export const WRAPPED_VAULT_KEY_LEN = 1226;

const TEXT_ENCODER = new TextEncoder();

// ── tiny helpers ─────────────────────────────────────────────────────────────

/** The runtime's Web Crypto object (Node 20 exposes it globally, as do browsers). */
function webcrypto() {
  const c = globalThis.crypto;
  if (!c || !c.getRandomValues || !c.subtle) {
    throw new Error(
      "sharing: Web Crypto (crypto.getRandomValues + crypto.subtle) is unavailable; " +
        "a secure context (https or localhost) is required",
    );
  }
  return c;
}

/** Reject ids that cannot sit verbatim in a URL path segment (the CLI's rule). */
function checkId(kind, id) {
  if (!id || typeof id !== "string" || id.includes("/") || /\s/.test(id)) {
    throw new Error(
      `sharing: invalid ${kind} ${JSON.stringify(id)}: must be non-empty with no "/" or whitespace`,
    );
  }
  return id;
}

/** Turn a non-2xx into a DeviceAuthError carrying the status and an explanation. */
async function failResponse(res, what) {
  const body = await res.text().catch(() => "");
  throw new DeviceAuthError(
    res.status,
    `${what}: ${explainSharingStatus(res.status)}${body ? ` — ${body.trim()}` : ""}`,
    body,
  );
}

/**
 * Plain-language explanation of a sharing-endpoint status. Extends
 * {@link explainAuthStatus} with the statuses only these routes produce, so a UI
 * can tell "you are not signed in" (401) from "that envelope is not yours" (403)
 * from "nothing has been shared yet" (404).
 */
export function explainSharingStatus(status) {
  switch (status) {
    case 403:
      return (
        "403 forbidden — this device authenticated fine but is not permitted. Only a device with " +
        "WRITE access may deposit a key envelope, only the ADDRESSEE may collect one, and a device " +
        "may publish only its OWN hybrid key."
      );
    case 404:
      return (
        "404 not found — nothing is there. The other device may not have published a hybrid key " +
        "yet, or no vault has been shared to this device."
      );
    case 409:
      return "409 conflict — that recipient device has been revoked.";
    case 413:
      return "413 payload too large — the envelope exceeds the server's size limit.";
    default:
      return explainAuthStatus(status);
  }
}

/** The URL PATH of a device's hybrid-key endpoint (mirrors `hybrid_key_path`). */
function hybridKeyPath(deviceId) {
  return `/v1/devices/${deviceId}/hybrid-key`;
}

/** The URL PATH of a (vault, device) envelope mailbox (`key_envelope_path`). */
function keyEnvelopePath(vaultId, deviceId) {
  return `/v1/vaults/${vaultId}/keys/${deviceId}`;
}

/**
 * Normalize an `auth` argument: `{ baseUrl, deviceId, seed, hybrid? }` — exactly
 * the object {@link openDeviceIdentity} returns, so an unlocked client can pass
 * its device identity straight in.
 */
function checkAuth(auth) {
  if (!auth || typeof auth !== "object") throw new Error("sharing: auth is required");
  checkId("device id", auth.deviceId);
  if (!auth.baseUrl) throw new Error("sharing: auth.baseUrl is required");
  return auth;
}

// ── hybrid identity (the device's long-term KEM key pair) ────────────────────

/**
 * Draw a fresh hybrid SECRET identity from the CSPRNG.
 *
 *   -> { x25519Secret: Uint8Array(32), mlkemSeed: Uint8Array(64) }
 *
 * Mirrors the CLI's `generate_hybrid_identity` (whose secret file holds exactly
 * these two fields, `x25519_secret` / `mlkem_seed`). BOTH halves are SECRET: they
 * are the only thing that can open an envelope addressed to this device.
 * Persist them ONLY inside a sealed container — never as plaintext bytes.
 */
export function generateHybridIdentity() {
  const c = webcrypto();
  return {
    x25519Secret: c.getRandomValues(new Uint8Array(HYBRID_X25519_SECRET_LEN)),
    mlkemSeed: c.getRandomValues(new Uint8Array(HYBRID_MLKEM_SEED_LEN)),
  };
}

/**
 * Derive the shareable PUBLIC half of a hybrid identity, in the wasm.
 *
 *   hybridPublicIdentity(wasm, { x25519Secret, mlkemSeed })
 *     -> { x25519PublicKey: Uint8Array(32), mlkemEncapsKey: Uint8Array(1184) }
 *
 * These are the two fields the CLI writes into `<identity>.pub`
 * (`x25519_public_key` / `mlkem_encaps_key`) and the two the server stores.
 */
export function hybridPublicIdentity(wasm, secretIdentity) {
  const s = requireSecretIdentity(secretIdentity);
  return {
    x25519PublicKey: new Uint8Array(wasm.hybrid_x25519_public(s.x25519Secret)),
    mlkemEncapsKey: new Uint8Array(wasm.hybrid_mlkem_encaps_key(s.mlkemSeed)),
  };
}

function requireSecretIdentity(identity) {
  if (
    !identity ||
    !(identity.x25519Secret instanceof Uint8Array) ||
    identity.x25519Secret.length !== HYBRID_X25519_SECRET_LEN ||
    !(identity.mlkemSeed instanceof Uint8Array) ||
    identity.mlkemSeed.length !== HYBRID_MLKEM_SEED_LEN
  ) {
    throw new Error(
      `sharing: a hybrid secret identity must be { x25519Secret: Uint8Array(${HYBRID_X25519_SECRET_LEN}), ` +
        `mlkemSeed: Uint8Array(${HYBRID_MLKEM_SEED_LEN}) }`,
    );
  }
  return identity;
}

function requirePublicIdentity(identity) {
  if (
    !identity ||
    !(identity.x25519PublicKey instanceof Uint8Array) ||
    identity.x25519PublicKey.length !== HYBRID_X25519_PUBLIC_LEN ||
    !(identity.mlkemEncapsKey instanceof Uint8Array) ||
    identity.mlkemEncapsKey.length !== HYBRID_MLKEM_ENCAPS_LEN
  ) {
    throw new Error(
      `sharing: a hybrid public identity must be { x25519PublicKey: Uint8Array(${HYBRID_X25519_PUBLIC_LEN}), ` +
        `mlkemEncapsKey: Uint8Array(${HYBRID_MLKEM_ENCAPS_LEN}) }`,
    );
  }
  return identity;
}

/**
 * PUBLISH this device's hybrid PUBLIC key so other devices can wrap a vault key
 * to it. Only the PUBLIC half is ever sent.
 *
 *   publishHybridKey(wasm, auth, secretIdentity?) -> { deviceId, updatedAt }
 *
 * `auth` is `{ baseUrl, deviceId, seed, hybrid? }`; `secretIdentity` defaults to
 * `auth.hybrid`. SELF-ONLY: the server 403s if the path device id is not the
 * authenticated one, so this always publishes into `auth.deviceId`'s slot.
 * Publishing is an UPSERT — re-publishing after regenerating the local identity
 * replaces the stored key, but does NOT re-wrap envelopes already deposited for
 * this device (those were sealed to the old key and must be re-shared).
 */
export async function publishHybridKey(wasm, auth, secretIdentity = null) {
  checkAuth(auth);
  const secret = requireSecretIdentity(secretIdentity ?? auth.hybrid);
  const pub = hybridPublicIdentity(wasm, secret);

  // Serialize FIRST, then sign the exact bytes that go on the wire.
  const bodyText = JSON.stringify({
    x25519_public_key: bytesToBase64(pub.x25519PublicKey),
    mlkem_encaps_key: bytesToBase64(pub.mlkemEncapsKey),
  });
  const path = hybridKeyPath(auth.deviceId);
  const res = await signedFetch(wasm, auth, "PUT", path, "", TEXT_ENCODER.encode(bodyText), {
    "Content-Type": "application/json",
  });
  if (res.status !== 200) await failResponse(res, "publishHybridKey");
  const json = await res.json();
  return { deviceId: json.device_id, updatedAt: json.updated_at ?? "" };
}

/**
 * FETCH another device's published hybrid PUBLIC key, so this device can wrap a
 * vault key to it. Any authenticated, active device may fetch any device's key.
 *
 *   fetchHybridKey(wasm, auth, deviceId)
 *     -> { deviceId, x25519PublicKey, mlkemEncapsKey, updatedAt }
 *
 * The lengths are validated HERE (32 / 1184): the server deliberately does only
 * a length check and no cryptography on key material, so correctness of a
 * published key is the client's business.
 *
 * ⚠️ There is NO out-of-band verification that this key really belongs to that
 * device — a hostile registry could substitute its own and receive the vault key
 * wrapped to itself. Compare {@link vaultKeyFingerprint} out of band to detect it.
 */
export async function fetchHybridKey(wasm, auth, deviceId) {
  checkAuth(auth);
  checkId("device id", deviceId);
  const path = hybridKeyPath(deviceId);
  const res = await signedFetch(wasm, auth, "GET", path, "", null);
  if (res.status !== 200) await failResponse(res, `fetchHybridKey(${deviceId})`);
  const json = await res.json();
  const identity = {
    deviceId: json.device_id ?? deviceId,
    x25519PublicKey: base64ToBytes(json.x25519_public_key ?? ""),
    mlkemEncapsKey: base64ToBytes(json.mlkem_encaps_key ?? ""),
    updatedAt: json.updated_at ?? "",
  };
  requirePublicIdentity(identity);
  return identity;
}

// ── vault keys ───────────────────────────────────────────────────────────────

/**
 * Draw a fresh 32-byte VAULT KEY from the CSPRNG. Mirrors the CLI's
 * `generate_vault_key`.
 *
 * This is what seals a SHARED vault: it goes exactly where a password goes in
 * `sealVault` / `openVault`, because a `SIGILcli` container takes arbitrary
 * password BYTES. The human password is never shared and never wrapped.
 */
export function generateVaultKey() {
  return webcrypto().getRandomValues(new Uint8Array(VAULT_KEY_LEN));
}

/**
 * A short, NON-REVERSIBLE fingerprint of a vault key: the first 16 hex
 * characters of its SHA-256. Mirrors the CLI's `vault_key_fingerprint`, so two
 * clients can prove they hold the SAME key without either revealing it.
 *
 * Async because it uses Web Crypto's SHA-256.
 */
export async function vaultKeyFingerprint(key) {
  requireVaultKey(key);
  const digest = new Uint8Array(await webcrypto().subtle.digest("SHA-256", key));
  return [...digest.slice(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function requireVaultKey(key) {
  if (!(key instanceof Uint8Array) || key.length !== VAULT_KEY_LEN) {
    throw new Error(`sharing: a vault key must be a ${VAULT_KEY_LEN}-byte Uint8Array`);
  }
  return key;
}

/**
 * WRAP a vault key to a recipient's hybrid public identity, producing the OPAQUE
 * `SIGILhyb` envelope the server relays. Mirrors the CLI's `wrap_vault_key`.
 *
 *   wrapVaultKey(wasm, { x25519PublicKey, mlkemEncapsKey }, vaultKey) -> Uint8Array
 *
 * FRESH ephemeral entropy is drawn on EVERY call — an ephemeral X25519 secret, an
 * ML-KEM-768 encapsulation coin, and an AEAD nonce — so no two shares of the same
 * key ever reuse randomness. All three come from `crypto.getRandomValues`; the
 * wasm draws none.
 */
export function wrapVaultKey(wasm, recipientPublic, vaultKey) {
  const pub = requirePublicIdentity(recipientPublic);
  requireVaultKey(vaultKey);
  const c = webcrypto();
  const ephemeralX25519Secret = c.getRandomValues(new Uint8Array(HYBRID_X25519_SECRET_LEN));
  const mlkemCoin = c.getRandomValues(new Uint8Array(32));
  const aeadNonce = c.getRandomValues(new Uint8Array(wasm.nonce_len()));
  return new Uint8Array(
    wasm.hybrid_seal_to_container(
      pub.x25519PublicKey,
      pub.mlkemEncapsKey,
      ephemeralX25519Secret,
      mlkemCoin,
      aeadNonce,
      vaultKey,
    ),
  );
}

/**
 * UNWRAP an envelope with this device's hybrid SECRET identity, recovering the
 * 32-byte vault key. Mirrors the CLI's `unwrap_vault_key`.
 *
 * The recovered plaintext MUST be exactly {@link VAULT_KEY_LEN} bytes — anything
 * else is REJECTED rather than silently used as a key. A wrong identity or a
 * tampered envelope throws (the AEAD tag fails) and leaks no plaintext.
 */
export function unwrapVaultKey(wasm, mySecretIdentity, envelopeBytes) {
  const secret = requireSecretIdentity(mySecretIdentity);
  const envelope =
    envelopeBytes instanceof Uint8Array ? envelopeBytes : new Uint8Array(envelopeBytes);
  const plaintext = new Uint8Array(
    wasm.hybrid_open_container(secret.x25519Secret, secret.mlkemSeed, envelope),
  );
  if (plaintext.length !== VAULT_KEY_LEN) {
    throw new Error(
      `sharing: envelope opened but held ${plaintext.length} bytes, expected a ${VAULT_KEY_LEN}-byte vault key`,
    );
  }
  return plaintext;
}

// ── the opaque envelope relay ────────────────────────────────────────────────

/**
 * DEPOSIT an opaque wrapped vault key addressed to `recipientDeviceId`.
 *
 *   putKeyEnvelope(wasm, auth, vaultId, recipientDeviceId, envelopeBytes)
 *     -> { vaultId, deviceId, sizeBytes, createdAt }
 *
 * This performs NO cryptography — it only moves already-sealed bytes, exactly
 * like a push. The signing device must hold WRITE on the vault; depositing into
 * an UNCLAIMED vault claims it (trust-on-first-write, the same rule as the first
 * op append). 404 = unknown recipient, 409 = revoked recipient, 413 = oversized.
 */
export async function putKeyEnvelope(wasm, auth, vaultId, recipientDeviceId, envelopeBytes) {
  checkAuth(auth);
  checkId("vault id", vaultId);
  checkId("device id", recipientDeviceId);
  const body =
    envelopeBytes instanceof Uint8Array ? envelopeBytes : new Uint8Array(envelopeBytes);
  if (body.length === 0) throw new Error("sharing: refusing to deposit an empty envelope");
  const path = keyEnvelopePath(vaultId, recipientDeviceId);
  const res = await signedFetch(wasm, auth, "PUT", path, "", body, {
    "Content-Type": "application/octet-stream",
  });
  if (res.status !== 201) await failResponse(res, "putKeyEnvelope");
  const json = await res.json();
  return {
    vaultId: json.vaultID ?? vaultId,
    deviceId: json.device_id ?? recipientDeviceId,
    sizeBytes: json.size_bytes ?? body.length,
    createdAt: json.created_at ?? "",
  };
}

/**
 * COLLECT the opaque envelope addressed to a device, returning the bytes EXACTLY
 * as the sender uploaded them (the server re-encodes nothing).
 *
 *   getKeyEnvelope(wasm, auth, vaultId, deviceId = auth.deviceId) -> Uint8Array
 *
 * ONLY the addressee may collect: asking for another device's envelope is 403,
 * never 401 and never 404 (a 404 would leak whether an envelope exists). The
 * caller must ALSO hold read on the vault. Performs no cryptography — the caller
 * unwraps with {@link unwrapVaultKey}.
 */
export async function getKeyEnvelope(wasm, auth, vaultId, deviceId = null) {
  checkAuth(auth);
  checkId("vault id", vaultId);
  const target = checkId("device id", deviceId ?? auth.deviceId);
  const path = keyEnvelopePath(vaultId, target);
  const res = await signedFetch(wasm, auth, "GET", path, "", null);
  if (res.status !== 200) await failResponse(res, "getKeyEnvelope");
  return new Uint8Array(await res.arrayBuffer());
}

// ── the two composed operations ──────────────────────────────────────────────

/**
 * SHARE a vault with another enrolled device, in one call.
 *
 *   shareVault(wasm, auth, { vaultId, recipientDeviceId, vaultKey, permission })
 *     -> { recipientDeviceId, envelope, envelopeBytes, permission, fingerprint }
 *
 * Deliberately does BOTH halves together — wrap + deposit, THEN grant through the
 * EXISTING `grantVaultAccess` route — so authorization and key distribution can
 * never drift apart (mirrors `sigil vault share`). The steps:
 *
 *   1. fetch the recipient's published hybrid PUBLIC key;
 *   2. WRAP this vault's key to it with fresh ephemeral entropy;
 *   3. DEPOSIT the opaque envelope (needs WRITE on the vault);
 *   4. GRANT the recipient `permission` ("read" | "write", default "read").
 *
 * The vault key never leaves this device unwrapped and is never returned in a
 * loggable form — only its `fingerprint`.
 */
export async function shareVault(
  wasm,
  auth,
  { vaultId, recipientDeviceId, vaultKey, permission = "read" },
) {
  checkAuth(auth);
  checkId("vault id", vaultId);
  checkId("device id", recipientDeviceId);
  requireVaultKey(vaultKey);
  if (permission !== "read" && permission !== "write") {
    throw new Error(`sharing: permission must be "read" or "write", got ${permission}`);
  }

  // 1) the recipient's PUBLIC hybrid key, straight from the registry.
  const recipient = await fetchHybridKey(wasm, auth, recipientDeviceId);
  // 2) WRAP: fresh ephemeral X25519 secret + ML-KEM coin + AEAD nonce per call.
  const envelope = wrapVaultKey(wasm, recipient, vaultKey);
  // 3) DEPOSIT the OPAQUE envelope; the server cannot read it.
  await putKeyEnvelope(wasm, auth, vaultId, recipientDeviceId, envelope);
  // 4) AUTHORIZE through the EXISTING grant API, so access and keys agree.
  await grantVaultAccess(
    wasm,
    { deviceId: auth.deviceId, seed: auth.seed },
    auth.baseUrl,
    vaultId,
    recipientDeviceId,
    permission,
  );

  return {
    recipientDeviceId,
    envelope,
    envelopeBytes: envelope.length,
    permission,
    fingerprint: await vaultKeyFingerprint(vaultKey),
  };
}

/**
 * ACCEPT a vault shared TO this device: collect the envelope addressed to
 * `auth.deviceId`, unwrap it with this device's hybrid SECRET identity, and
 * return the recovered 32-byte vault key (mirrors `sigil vault accept`).
 *
 *   acceptVault(wasm, auth, { vaultId, secretIdentity? })
 *     -> { vaultId, vaultKey, envelope, fingerprint }
 *
 * `secretIdentity` defaults to `auth.hybrid`. The CALLER decides what to do with
 * the returned key — the browser clients store it inside the SEALED
 * device-identity container, never in the clear.
 */
export async function acceptVault(wasm, auth, { vaultId, secretIdentity = null }) {
  checkAuth(auth);
  checkId("vault id", vaultId);
  const secret = requireSecretIdentity(secretIdentity ?? auth.hybrid);
  const envelope = await getKeyEnvelope(wasm, auth, vaultId, auth.deviceId);
  const vaultKey = unwrapVaultKey(wasm, secret, envelope);
  return {
    vaultId,
    vaultKey,
    envelope,
    fingerprint: await vaultKeyFingerprint(vaultKey),
  };
}
