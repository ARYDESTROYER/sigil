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
// │     hybrid_auth_seal_to_container (magic 8 ‖ version 2 ‖ eph_x25519_pub 32  │
// │     ‖ mlkem_ct 1088 ‖ envelope). ⚠️ The length is NO LONGER FIXED at 1226:   │
// │     the envelope carries its context AAD, so see wrappedVaultKeyLen().      │
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
//        └── wrapped per recipient with `hybrid_auth_seal_to_container`
//            (X25519 + ML-KEM-768 -> XChaCha20-Poly1305) into an OPAQUE
//            `SIGILhyb` VERSION 2 envelope that sigild relays and cannot read.
//
// ⭐⭐ PHASE 60 — THE ENVELOPE IS NOW AUTHENTICATED AND CONTEXT-BOUND.
//
// THE HOLE, reproduced with the shipped binary and nothing else:
//
//     sigil hybrid-keygen --out b.hybrid          # victim; only b.hybrid.pub is published
//     sigil hybrid-seal --recipient-pub b.hybrid.pub --in attacker_key.bin --out forged.env
//     -> 1226 bytes, magic SIGILhyb, byte-shaped IDENTICALLY to a genuine wrap
//     sigil hybrid-open --key b.hybrid --in forged.env   # the attacker's key, cleanly
//
// `hybrid_seal_to_container` is an ANONYMOUS (ephemeral-static) KEM, so holding
// the recipient's PUBLISHED hybrid public key — which sigild serves to every
// authenticated device — was enough to mint an envelope any client accepted;
// the AAD was one FIXED tag binding no vault, no recipient, no sender and no
// PURPOSE; and the only check on the recovered plaintext was `length === 32`.
// A hostile server, or any co-tenant with WRITE, could install a vault key IT
// chose and read everything the victim wrote afterwards. ADR 0038 pinning did
// not help: `acceptVault` fetched no hybrid key at all, so the pin store was
// never consulted on the receiving side.
//
// THE FIX, three parts, all of which must hold:
//
//   * the KEM is AUTHENTICATED — `hybrid_auth_seal_to_container` mixes a
//     static-static X25519 DH from the SENDER's long-term secret into the KDF,
//     so a forger needs the sender's SECRET, not just public material;
//   * the AAD is CONTEXT-BOUND — {@link vaultKeyWrapAad} over (purpose, vault
//     id, recipient device id, sender device id), so an envelope cannot be
//     re-filed under another vault/recipient/sender or replayed as a file;
//   * the container VERSION is 2, and a version-1 container is REFUSED wherever
//     a vault key is expected ({@link UnauthenticatedEnvelopeError}). There is
//     deliberately NO compatibility flag — accepting v1 is accepting the bug.
//
// ⭐ AND THE RECEIVING SIDE NOW HAS A GATE. {@link verifySenderForUnwrap} is the
// mirror of {@link verifyRecipientForWrap}: it resolves the DEPOSITING device's
// hybrid public key, pin-checks it, honours a supplied safety number, and is the
// only thing that can construct the {@link VerifiedSender} that
// {@link unwrapVaultKey} demands — enforced by the type, not by convention.
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
// "post-quantum secure". Revoking a device stops FUTURE server access; it cannot
// make a device forget a vault key it already accepted — for that, ROTATE (see
// `rotateVaultKey` below), which protects FUTURE content only.
//
// KEY SUBSTITUTION (Phase 50): a published hybrid public key is now PINNED on
// first sight and a CHANGED key is a hard refusal (`KeyPinMismatchError`), and a
// human-comparable SAFETY NUMBER closes the first-contact window pinning cannot.
// See the Phase 50 section at the bottom of this file.

import {
  signedFetch,
  grantVaultAccess,
  // ⭐ PHASE 60 SYMMETRY. `acceptVault` needs to OPEN the vault's newest op with
  // the recovered key BEFORE that key is handed back to be persisted — the same
  // step 4 the CLI's `accept_vault_key` performs with `pull_ops_auth`. Without
  // it a key that opens NOTHING still reaches local state.
  pullContainersAuthed,
  getAccount,
  DeviceAuthError,
  explainAuthStatus,
} from "./device-auth.mjs";
import { bytesToBase64, base64ToBytes, ratchetParams } from "./totp-vault.mjs";
// ⭐ ONE recovery-kit label per language. This module used to redefine the string
// locally; see the note above recipientIsRecoveryKit for why that was dangerous.
// (recovery.mjs imports this module too — an ESM cycle that is safe because
// neither file touches the other's bindings at module-evaluation time.)
import { RECOVERY_DEVICE_LABEL as RECOVERY_KIT_DEVICE_LABEL } from "./recovery.mjs";

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

/**
 * `SIGILhyb` container version 1 — the ANONYMOUS, ephemeral-static form.
 *
 * ⛔ NEVER a vault-key envelope. Its only sender-side key is a per-message
 * ephemeral, so anybody holding the recipient's PUBLISHED public key can mint
 * one. Mirrors `cli/src/lib.rs::HYBRID_FORMAT_VERSION`.
 */
export const KEY_ENVELOPE_VERSION_ANONYMOUS = 1;

/**
 * `SIGILhyb` container version 2 — the AUTHENTICATED form, and the ONLY version
 * a vault-key unwrap accepts. Mirrors `cli/src/lib.rs::HYBRID_AUTH_FORMAT_VERSION`.
 */
export const KEY_ENVELOPE_VERSION_AUTHENTICATED = 2;

/**
 * Fixed byte overhead of a wrapped 32-byte vault key, EXCLUDING the AAD:
 * magic(8) + version(1) + eph_x25519_pub(32) + mlkem_ct(1088) + the envelope's
 * nonce/framing/ciphertext(79) = 1208.
 *
 * ⚠️ REPLACES the old flat `WRAPPED_VAULT_KEY_LEN = 1226`. That constant was true
 * only while every hybrid container shared ONE fixed 18-byte AAD — which is
 * precisely the defect Phase 60 closed. The AAD now names the vault and both
 * devices, so the envelope length depends on those identifiers. Use
 * {@link wrappedVaultKeyLen}.
 */
export const WRAPPED_VAULT_KEY_OVERHEAD = 1208;

/** Exact byte length a wrapped 32-byte vault key will have for a given context. */
export function wrappedVaultKeyLen(vaultId, recipientDeviceId, senderDeviceId) {
  return (
    WRAPPED_VAULT_KEY_OVERHEAD +
    VAULT_KEY_WRAP_AAD_PREFIX_LEN +
    12 +
    TEXT_ENCODER.encode(vaultId).length +
    TEXT_ENCODER.encode(recipientDeviceId).length +
    TEXT_ENCODER.encode(senderDeviceId).length
  );
}

/**
 * Byte length of the vault-key-wrap AAD's domain-separation prefix — the string
 * `sigil` + `-vault-key-wrap-v1` + a trailing newline, 24 bytes, defined once in
 * `sigil_core::VAULT_KEY_WRAP_AAD_PREFIX`.
 *
 * ⭐ Deliberately a LENGTH and not a copy of the literal. The AAD itself is
 * SINGLE-SOURCED through {@link vaultKeyWrapAad} -> the wasm -> `sigil-core`, so
 * a JS copy of the domain string would be a mirror with nothing to keep it in
 * sync — a drift surface for no benefit. The only thing JS needs it for is
 * predicting an envelope's size in {@link wrappedVaultKeyLen}.
 */
export const VAULT_KEY_WRAP_AAD_PREFIX_LEN = 24;

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
 * ⚠️ THIS IS THE RAW FETCH AND IT ENFORCES NOTHING. It returns whatever the
 * server says. A hostile registry could substitute its own key here and receive
 * the vault key wrapped to itself. Prefer {@link verifyRecipientForWrap}, which
 * pins on first sight, REFUSES a changed key and REFUSES an unverified recovery
 * kit — every share/rotate path in this module goes through that one, and it is
 * the only thing that produces a value a wrap will accept. Use this bare version
 * only for DISPLAY (e.g.
 * computing a {@link safetyNumber} to read aloud), never to wrap a key.
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

// ── the wrap context + the sender identity ───────────────────────────────────

/**
 * ⭐ THE CONTEXT a vault-key envelope is bound to. Both sides MUST build the
 * identical value or the AEAD refuses to open — which IS the point.
 *
 *   vaultKeyWrapAad(wasm, vaultId, recipientDeviceId, senderDeviceId) -> Uint8Array
 *
 * ⭐ SINGLE-SOURCED, NOT MIRRORED. This is a one-line call into the wasm, which
 * is a one-line shell over `sigil_core::vault_key_wrap_aad` — the very function
 * the `sigil` CLI calls. The Rust and JS clients therefore compute the same bytes
 * BY CONSTRUCTION rather than by two hand-written implementations agreeing.
 * (`sigil-wasm/test/sharing-interop.mjs` still pins the golden vector, because a
 * drift alarm costs nothing.)
 *
 * Layout, for the record:
 *
 *   "sigil-vault-key-wrap-v1\n"
 *   ‖ u32_be(len(vaultId))            ‖ vaultId
 *   ‖ u32_be(len(recipientDeviceId))  ‖ recipientDeviceId
 *   ‖ u32_be(len(senderDeviceId))     ‖ senderDeviceId
 *
 * Every field is length-prefixed, so ("ab","c","d") cannot collide with
 * ("a","bc","d").
 */
export function vaultKeyWrapAad(wasm, vaultId, recipientDeviceId, senderDeviceId) {
  checkId("vault id", vaultId);
  checkId("recipient device id", recipientDeviceId);
  checkId("sender device id", senderDeviceId);
  return new Uint8Array(wasm.vault_key_wrap_aad(vaultId, recipientDeviceId, senderDeviceId));
}

/**
 * Normalize a wrap CONTEXT: `{ vaultId, recipientDeviceId, senderDeviceId }`.
 * Mirrors the CLI's `VaultKeyWrapContext::new`.
 */
function requireWrapContext(ctx) {
  if (!ctx || typeof ctx !== "object") {
    throw new Error(
      "sharing: a wrap context { vaultId, recipientDeviceId, senderDeviceId } is required — " +
        "a vault-key envelope is bound to all three",
    );
  }
  checkId("vault id", ctx.vaultId);
  checkId("recipient device id", ctx.recipientDeviceId);
  checkId("sender device id", ctx.senderDeviceId);
  return ctx;
}

/**
 * The SENDING half of a wrap: which device we are, and the hybrid SECRET
 * identity that proves it — `{ deviceId, hybrid: { x25519Secret, mlkemSeed } }`.
 *
 * Bundled so a call site cannot pass one device's id with another's secret.
 * Mirrors the CLI's `SenderIdentity`.
 */
export function senderIdentity(deviceId, hybridSecret) {
  checkId("sender device id", deviceId);
  return { deviceId, hybrid: requireSecretIdentity(hybridSecret) };
}

/**
 * The sender identity implied by an unlocked client's `auth`
 * (`{ deviceId, hybrid }`). This is what every client passes.
 */
export function senderFromAuth(auth) {
  checkAuth(auth);
  if (!auth.hybrid) {
    // ⚠️ A REAL BEHAVIOUR CHANGE, said plainly rather than surfaced as a shape
    // error. Before Phase 60 a wrap needed only the RECIPIENT's public key, so a
    // device with no hybrid identity of its own could still hand out vault keys
    // — which is exactly why anybody else could too. Authenticating the envelope
    // means the sender must hold a long-term secret, and the recipient must be
    // able to FETCH the matching public half, so it has to be published.
    throw new Error(
      "sharing: this device has no hybrid identity, so it cannot AUTHENTICATE a vault-key " +
        "envelope. Publish this device's hybrid key first (Sharing → Publish this device's " +
        "hybrid key); the recipient needs the public half to check who the envelope came from.",
    );
  }
  return senderIdentity(auth.deviceId, auth.hybrid);
}

function requireSenderIdentity(sender) {
  if (!sender || typeof sender !== "object") {
    throw new Error(
      "sharing: a sender identity { deviceId, hybrid } is required — a vault-key envelope is " +
        "AUTHENTICATED to the device that produced it, so the wrap needs that device's secret",
    );
  }
  checkId("sender device id", sender.deviceId);
  requireSecretIdentity(sender.hybrid);
  return sender;
}

/**
 * ⛔ Thrown when a vault-key slot is handed a container that is NOT an
 * AUTHENTICATED (version 2) envelope — in practice, a version-1 anonymous one.
 *
 * ⭐ THIS IS ITS OWN CLASS ON PURPOSE. It is NOT a 401 (the request authenticated
 * fine), NOT a 403 (nothing was forbidden) and NOT a
 * {@link KeyPinMismatchError} (no key changed). It means the BYTES prove nothing
 * about who produced them, and every client renders it distinctly.
 */
export class UnauthenticatedEnvelopeError extends Error {
  constructor(foundVersion) {
    super(
      `REFUSING TO UNWRAP: this is a version ${foundVersion} SIGILhyb container, and a vault-key ` +
        `envelope must be version ${KEY_ENVELOPE_VERSION_AUTHENTICATED} (AUTHENTICATED).\n  ` +
        `A version ${KEY_ENVELOPE_VERSION_ANONYMOUS} container carries NO SENDER: anyone who can ` +
        `read this device's published hybrid PUBLIC key can mint one, so accepting it would let ` +
        `an attacker install a vault key of their own choosing and read everything written ` +
        `afterwards.\n  There is deliberately no compatibility flag. Ask the sender to re-issue ` +
        `it (sigil vault share / vault rotate / recovery cover, or the Share panel).`,
    );
    this.name = "UnauthenticatedEnvelopeError";
    /** @type {number} the container version actually found. */
    this.foundVersion = foundVersion;
    /** @type {number} the version a vault-key envelope must be. */
    this.expectedVersion = KEY_ENVELOPE_VERSION_AUTHENTICATED;
  }
}

/**
 * ⛔ Thrown when an envelope cannot be attributed to an EXPECTED SENDER: the
 * caller could not work out which device deposited it, so there was nothing to
 * authenticate against and nothing was unwrapped.
 *
 * A REFUSAL, not a fallback — unwrapping "from whoever" is exactly the anonymous
 * behaviour that made a forgery indistinguishable from a real envelope.
 */
export class UnknownSenderError extends Error {
  constructor(detail) {
    super(
      `REFUSING TO UNWRAP: ${detail}\n  A vault-key envelope is authenticated to the device that ` +
        `deposited it, so there is nothing to check it against until that device is known. Name ` +
        `it explicitly (senderDeviceId).`,
    );
    this.name = "UnknownSenderError";
  }
}

/**
 * ⛔ Thrown when the key recovered from an envelope does NOT open the vault it
 * claims to be for — step 4 of {@link acceptVault}, mirroring the CLI's
 * `accept_vault_key` ("the recovered key does NOT open vault …'s newest op").
 *
 * ⭐ WHY IT IS A REFUSAL AND NOT A WARNING. A key that decrypts nothing is
 * useless at best and hostile at worst: it is exactly what a forged or misfiled
 * deposit produces, and once it is in local state it can DISPLACE the real key
 * (see {@link VaultKeyReplacementError}). So nothing is returned to be persisted.
 *
 * ⚠️ It can also be honest and benign: a sender who ROTATED the vault key but has
 * not yet PUSHED the re-sealed vault leaves the server's newest op sealed under
 * the OLD key. The remedy is for them to push, then accept again.
 */
export class VaultKeyDoesNotOpenError extends Error {
  constructor(vaultId, detail) {
    super(
      `REFUSING TO ACCEPT: the recovered key does NOT open vault ${JSON.stringify(vaultId)}'s ` +
        `newest op (${detail}); nothing was stored.\n  ` +
        `A vault key that opens nothing is either a forged or misfiled deposit, or a sender who ` +
        `rotated the key and has not pushed the re-sealed vault yet. Ask them to push and try ` +
        `again.`,
    );
    this.name = "VaultKeyDoesNotOpenError";
    /** @type {string} the vault the key failed to open. */
    this.vaultId = vaultId;
  }
}

/**
 * ⛔ Thrown when accepting would REPLACE a DIFFERENT key this client already
 * holds for the vault — step 5 of {@link acceptVault}, mirroring the CLI's
 * `accept_vault_key` ("this client already holds a DIFFERENT key for vault …").
 *
 * ⭐ WHY. Silently overwriting is how a hostile deposit TAKES A VAULT AWAY from a
 * device that already had it: the old key is the only thing that opens everything
 * sealed under it, and this client may hold the last copy. Replacing is
 * legitimate (a rotation the sender pushed), so it is allowed — but only as an
 * explicit `replace: true`, never by default.
 *
 * Both fingerprints are SHA-256 prefixes, never key bytes, so a UI can show a
 * human what would be swapped without printing key material.
 */
export class VaultKeyReplacementError extends Error {
  constructor(vaultId, heldFingerprint, offeredFingerprint) {
    super(
      `REFUSING TO ACCEPT: this client already holds a DIFFERENT key for vault ` +
        `${JSON.stringify(vaultId)} (sha256 ${heldFingerprint}); accepting would replace it with ` +
        `sha256 ${offeredFingerprint} and lose access to everything sealed under it.\n  ` +
        `If the sender ROTATED the key that is exactly what you want — accept again with ` +
        `replace: true (the CLI spells this --replace). If they did not, someone deposited a key ` +
        `you did not ask for.`,
    );
    this.name = "VaultKeyReplacementError";
    /** @type {string} the vault whose key would be replaced. */
    this.vaultId = vaultId;
    /** @type {string} SHA-256 fingerprint (16 hex) of the key already held. */
    this.heldFingerprint = heldFingerprint;
    /** @type {string} SHA-256 fingerprint (16 hex) of the key offered. */
    this.offeredFingerprint = offeredFingerprint;
  }
}

/**
 * Normalize/validate the map of vault keys this client ALREADY HOLDS.
 *
 * FAIL CLOSED, for exactly the reason {@link requirePinStore} does: a caller that
 * forgot to pass its keyring would silently get "this client holds nothing", the
 * never-silently-replace check would degrade into a no-op, and a hostile deposit
 * would overwrite a good key with no refusal at all. `{}` is a valid, explicit
 * statement that nothing is held; `null`/`undefined` is a programming error.
 */
export function requireHeldVaultKeys(keys) {
  if (keys === null || keys === undefined) {
    throw new Error(
      "sharing: the vault keys this client already holds are required (they are what stops an " +
        "accept silently REPLACING a key you depend on). Pass the keyring from the unlocked " +
        "device identity (device.vaultKeys), or {} if you deliberately hold none.",
    );
  }
  if (typeof keys !== "object" || Array.isArray(keys)) {
    throw new Error("sharing: held vault keys must be { [vaultId]: Uint8Array(32) }");
  }
  // ⚠️ AND EVERY VALUE MUST BE RAW BYTES. A caller that handed base64 strings
  // (the shape they are SEALED in) would compare unequal to every recovered key,
  // so every accept would refuse — fail-closed, but as an unexplainable wall.
  // Say so here instead.
  for (const [vaultId, key] of Object.entries(keys)) {
    if (!(key instanceof Uint8Array) || key.length !== VAULT_KEY_LEN) {
      throw new Error(
        `sharing: the held key for ${JSON.stringify(vaultId)} must be a ${VAULT_KEY_LEN}-byte ` +
          `Uint8Array (raw bytes, not base64)`,
      );
    }
  }
  return keys;
}

/** The `SIGILhyb` container version byte, or `null` if the bytes are not one. */
export function keyEnvelopeVersion(envelopeBytes) {
  const bytes =
    envelopeBytes instanceof Uint8Array ? envelopeBytes : new Uint8Array(envelopeBytes ?? []);
  if (bytes.length < 9) return null;
  for (let i = 0; i < 8; i += 1) {
    if (bytes[i] !== KEY_ENVELOPE_MAGIC.charCodeAt(i)) return null;
  }
  return bytes[8];
}

/**
 * ⭐ WRAP a vault key to a recipient's hybrid public identity, AUTHENTICATED as
 * `sender` and BOUND to `ctx`. Mirrors the CLI's `wrap_vault_key`.
 *
 *   wrapVaultKey(wasm, sender, recipientPublic, ctx, vaultKey) -> Uint8Array
 *
 * `sender` is `{ deviceId, hybrid: { x25519Secret, mlkemSeed } }` — this device's
 * LONG-TERM hybrid secret is what authenticates the envelope. `ctx` is
 * `{ vaultId, recipientDeviceId, senderDeviceId }`.
 *
 * FRESH ephemeral entropy is drawn on EVERY call — an ephemeral X25519 secret, an
 * ML-KEM-768 encapsulation coin, and an AEAD nonce — so no two wraps of the same
 * key ever reuse randomness. All three come from `crypto.getRandomValues`; the
 * wasm draws none.
 *
 * ⚠️ `ctx.senderDeviceId` MUST equal `sender.deviceId`: the caller says who it is
 * twice — once for the AAD (which the recipient checks) and once for the key
 * material (which the AEAD checks). They are compared here, so a mismatch is a
 * local error rather than an envelope nobody can open.
 */
export function wrapVaultKey(wasm, sender, recipientPublic, ctx, vaultKey) {
  const s = requireSenderIdentity(sender);
  const pub = requirePublicIdentity(recipientPublic);
  const c2 = requireWrapContext(ctx);
  requireVaultKey(vaultKey);
  if (c2.senderDeviceId !== s.deviceId) {
    throw new Error(
      `sharing: wrap context names sender ${JSON.stringify(c2.senderDeviceId)} but the signing ` +
        `identity is ${JSON.stringify(s.deviceId)}`,
    );
  }
  const aad = vaultKeyWrapAad(wasm, c2.vaultId, c2.recipientDeviceId, c2.senderDeviceId);
  const c = webcrypto();
  const ephemeralX25519Secret = c.getRandomValues(new Uint8Array(HYBRID_X25519_SECRET_LEN));
  const mlkemCoin = c.getRandomValues(new Uint8Array(32));
  const aeadNonce = c.getRandomValues(new Uint8Array(wasm.nonce_len()));
  return new Uint8Array(
    wasm.hybrid_auth_seal_to_container(
      s.hybrid.x25519Secret,
      pub.x25519PublicKey,
      pub.mlkemEncapsKey,
      ephemeralX25519Secret,
      mlkemCoin,
      aeadNonce,
      aad,
      vaultKey,
    ),
  );
}

/**
 * ⭐ UNWRAP an envelope with this device's hybrid SECRET identity — but ONLY as a
 * record from `sender`, and ONLY under `ctx`. Mirrors the CLI's
 * `unwrap_vault_key`.
 *
 *   unwrapVaultKey(wasm, mySecretIdentity, verifiedSender, ctx, envelopeBytes)
 *     -> Uint8Array(32)
 *
 * Three checks, in this order, every one load-bearing:
 *
 *   1. the container must be AUTHENTICATED (version 2). A version-1 container is
 *      {@link UnauthenticatedEnvelopeError} — it carries no sender at all;
 *   2. the AEAD must authenticate under the secret derived with `sender`'s STATIC
 *      X25519 public key. A forger holding only public material cannot produce
 *      one, so a wrong or forged sender fails HERE, at the AEAD, not at a string
 *      comparison that could be bypassed;
 *   3. the recovered plaintext must be exactly {@link VAULT_KEY_LEN} bytes.
 *
 * ⭐ `sender` must be a {@link VerifiedSender}, which only
 * {@link verifySenderForUnwrap} and {@link verifiedSenderFromLocal} can build —
 * the receiving-side twin of the {@link verifyRecipientForWrap} gate. A caller
 * cannot reach this function with a key it pulled straight off the wire.
 */
export function unwrapVaultKey(wasm, mySecretIdentity, sender, ctx, envelopeBytes) {
  const secret = requireSecretIdentity(mySecretIdentity);
  if (!(sender instanceof VerifiedSender)) {
    throw new Error(
      "sharing: unwrapVaultKey needs a VerifiedSender — obtain one from verifySenderForUnwrap() " +
        "(which pin-checks the depositing device's key) or verifiedSenderFromLocal() (when this " +
        "process holds the sender's own secret). An unverified key off the wire is exactly what " +
        "this gate exists to refuse.",
    );
  }
  const c2 = requireWrapContext(ctx);
  if (c2.senderDeviceId !== sender.deviceId) {
    throw new Error(
      `sharing: unwrap context names sender ${JSON.stringify(c2.senderDeviceId)} but the ` +
        `verified sender is ${JSON.stringify(sender.deviceId)}`,
    );
  }
  const envelope =
    envelopeBytes instanceof Uint8Array ? envelopeBytes : new Uint8Array(envelopeBytes);

  // 1) ⛔ THE VERSION REFUSAL, before any cryptography, so the caller gets a
  //    typed error rather than an opaque AEAD failure. (The wasm re-checks; this
  //    is what makes the refusal renderable.)
  const version = keyEnvelopeVersion(envelope);
  if (version !== KEY_ENVELOPE_VERSION_AUTHENTICATED) {
    throw new UnauthenticatedEnvelopeError(version ?? -1);
  }

  const aad = vaultKeyWrapAad(wasm, c2.vaultId, c2.recipientDeviceId, c2.senderDeviceId);
  const plaintext = new Uint8Array(
    wasm.hybrid_auth_open_container(
      secret.x25519Secret,
      secret.mlkemSeed,
      sender.x25519PublicKey,
      aad,
      envelope,
    ),
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
 * Deliberately does every half together — gate + wrap, THEN grant, THEN deposit,
 * all through the EXISTING `grantVaultAccess` route — so authorization and key
 * distribution can never drift apart (mirrors `sigil vault share`). The steps:
 *
 *   1. GATE: resolve + pin-check the recipient's published hybrid PUBLIC key;
 *   2. WRAP this vault's key to it, AUTHENTICATED as this device and BOUND to
 *      (vault, recipient, sender), with fresh ephemeral entropy;
 *   3. GRANT the recipient `permission` ("read" | "write", default "read");
 *   4. DEPOSIT the opaque envelope (needs WRITE on the vault).
 *
 * ⭐ **THE ORDER IS AUTHORIZE-THEN-DEPOSIT, AND IT USED TO BE THE OTHER WAY
 * ROUND** (this file, like the CLI, deposited first). A device with WRITE but no
 * ownership therefore got its envelope STORED and only THEN met the grant
 * route's 403 — so a caller who could not legitimately share still landed a key
 * envelope of its choosing in the recipient's mailbox. A failed grant now means
 * nothing was deposited. The reverse failure (grant succeeds, deposit fails) is
 * the safe one: the recipient can read ciphertext it has no key for, which is
 * exactly the state every recipient is in before a share anyway.
 *
 * The vault key never leaves this device unwrapped and is never returned in a
 * loggable form — only its `fingerprint`.
 */
export async function shareVault(
  wasm,
  auth,
  {
    vaultId,
    recipientDeviceId,
    vaultKey,
    permission = "read",
    pins = null,
    expectedSafetyNumber = null,
    sender = null,
  },
) {
  checkAuth(auth);
  checkId("vault id", vaultId);
  checkId("device id", recipientDeviceId);
  requireVaultKey(vaultKey);
  if (permission !== "read" && permission !== "write") {
    throw new Error(`sharing: permission must be "read" or "write", got ${permission}`);
  }
  // The AUTHENTICATING identity. Defaults to this unlocked client's own, which
  // is what every shipping caller wants; a caller with no hybrid identity gets a
  // loud local error instead of an envelope nobody can trust.
  const from = requireSenderIdentity(sender ?? senderFromAuth(auth));

  // 1) ⭐ THE WRAP GATE. Resolve the recipient's PUBLIC hybrid key AND settle
  //    trust in it in ONE call, before anything can be wrapped. A changed key
  //    (KeyPinMismatchError), a wrong expectedSafetyNumber
  //    (SafetyNumberMismatchError), or an unpinned RECOVERY KIT
  //    (UnverifiedRecoveryKitError) all stop HERE: nothing is wrapped, nothing
  //    is uploaded, and the pin store is not mutated. `pins` defaults to
  //    auth.pins (the store that came out of the sealed device-identity
  //    container), so an unlocked client enforces with no extra wiring.
  const pinStore = requirePinStore(pins ?? auth.pins);
  const {
    identity: recipient,
    trust,
    safetyNumber: recipientSafetyNumber,
  } = await verifyRecipientForWrap(wasm, auth, recipientDeviceId, {
    pins: pinStore,
    expectedSafetyNumber,
  });
  const pinStatus = trust === TRUST_PINNED || trust === TRUST_DERIVED ? "match" : "first-sight";
  // 2) WRAP: AUTHENTICATED as this device, BOUND to (vault, recipient, sender);
  //    fresh ephemeral X25519 secret + ML-KEM coin + AEAD nonce per call.
  const ctx = {
    vaultId,
    recipientDeviceId,
    senderDeviceId: from.deviceId,
  };
  const envelope = wrapVaultKey(wasm, from, recipient, ctx, vaultKey);
  // 3) AUTHORIZE FIRST through the EXISTING grant API, so a caller that may not
  //    share cannot leave an envelope behind.
  await grantVaultAccess(
    wasm,
    { deviceId: auth.deviceId, seed: auth.seed },
    auth.baseUrl,
    vaultId,
    recipientDeviceId,
    permission,
  );
  // 4) DEPOSIT the OPAQUE envelope; the server cannot read it.
  await putKeyEnvelope(wasm, auth, vaultId, recipientDeviceId, envelope);

  return {
    recipientDeviceId,
    envelope,
    envelopeBytes: envelope.length,
    permission,
    fingerprint: await vaultKeyFingerprint(vaultKey),
    // ⭐ What the wrap gate concluded, and the number the user should confirm
    // out of band. `trust === "unverified-first-sight"` means this key has NOT
    // been verified by a human yet — a UI should say so. `pinStatus` is kept for
    // callers written against the Phase 50 shape.
    trust,
    pinStatus,
    safetyNumber: recipientSafetyNumber,
    pins: pinStore,
  };
}

/**
 * ⭐ ACCEPT a vault shared TO this device — the receiving half of
 * {@link shareVault}, and **where the forgery used to land**.
 *
 *   acceptVault(wasm, auth, {
 *     vaultId, secretIdentity?, senderDeviceId?, expectedSafetyNumber?, pins?,
 *     heldKeys?, replace?
 *   }) -> { vaultId, vaultKey, envelope, fingerprint, senderDeviceId,
 *           senderTrust, senderSafetyNumber, verifiedAgainstTip, tipContainer,
 *           replaced }
 *
 * What it now does, in order, all of it load-bearing (mirrors the CLI's
 * `accept_vault_key`, ALL FIVE STEPS):
 *
 *   1. **work out WHO deposited the envelope** — explicitly (`senderDeviceId`),
 *      else from this device's OWN envelope index (`GET /v1/devices/{id}/keys`,
 *      self-only). No sender ⇒ {@link UnknownSenderError}, a REFUSAL. The id is
 *      server-supplied and therefore untrusted; naming the wrong device just
 *      makes step 3 fail, because the sender's static key is an INPUT to the
 *      derivation, not a string that gets compared;
 *   2. **establish that sender's hybrid key** through
 *      {@link verifySenderForUnwrap} — the pin store, at last, on the accept
 *      path. Before Phase 60 this function fetched no hybrid key at all, so ADR
 *      0038's pin store was never consulted here;
 *   3. **unwrap AUTHENTICATED and CONTEXT-BOUND** — a version-1 (anonymous)
 *      envelope is refused outright ({@link UnauthenticatedEnvelopeError}); a
 *      forged or re-filed one fails at the AEAD;
 *   4. ⭐ **OPEN BEFORE RETURNING.** The recovered key must actually open this
 *      vault's newest op, or nothing comes back to be persisted
 *      ({@link VaultKeyDoesNotOpenError}). A vault the server holds nothing for
 *      yet is the one exception, reported as `verifiedAgainstTip: false`;
 *   5. **never silently REPLACE.** A DIFFERENT key already held for this vault
 *      needs an explicit `replace: true`, else {@link VaultKeyReplacementError}.
 *      Overwriting is how a hostile deposit takes a vault away from a device
 *      that already had it.
 *
 * ⭐⭐ STEPS 4 AND 5 LIVE **HERE**, NOT AT THE CALL SITES, AND THAT IS THE POINT.
 * `acceptVault` returns the key for the caller to persist (the CLI writes its own
 * keyring), so putting these checks in the webapp and the extension would have
 * left them duplicated, forgettable, and — as this repository has shipped twice
 * before — revertible with every suite still green. Enforcing them at the ONE
 * place the key is produced means a client physically cannot store a key that
 * opens nothing, and cannot overwrite a key it depends on without saying so. The
 * `replace` opt-in is the only door, and it is explicit in both browsers' UI.
 *
 * `secretIdentity` defaults to `auth.hybrid`; `pins` to `auth.pins`; `heldKeys`
 * to `auth.vaultKeys`. `heldKeys` FAILS CLOSED (see
 * {@link requireHeldVaultKeys}) for the same reason `pins` does. The CALLER
 * decides what to do with the returned key — the browser clients store it inside
 * the SEALED device-identity container, never in the clear, and must ALSO
 * persist the returned `pins` so the sender stays pinned.
 *
 * `tipContainer` is the newest op as pulled by step 4, handed back so a caller
 * can adopt the vault WITHOUT a second round trip (and without the window in
 * which a different op could arrive between the check and the open).
 */
export async function acceptVault(
  wasm,
  auth,
  {
    vaultId,
    secretIdentity = null,
    senderDeviceId = null,
    expectedSafetyNumber = null,
    pins = null,
    heldKeys = null,
    replace = false,
  },
) {
  checkAuth(auth);
  checkId("vault id", vaultId);
  const secret = requireSecretIdentity(secretIdentity ?? auth.hybrid);
  const pinStore = requirePinStore(pins ?? auth.pins);
  const held = requireHeldVaultKeys(heldKeys ?? auth.vaultKeys);

  // 0) ⭐ COLLECT THE ENVELOPE FIRST — before anything else is asked of the
  //    server, and mirroring the CLI's `accept_vault_key`. A device that may NOT
  //    read this vault would otherwise be told "I cannot work out who deposited
  //    the key" (its own index is empty) when the true and far more useful answer
  //    is the mailbox's own 403. The fetch grants nothing — the envelope is
  //    opaque ciphertext and is not unwrapped until step 3 — so surfacing the
  //    authorization failure first costs no security.
  const envelope = await getKeyEnvelope(wasm, auth, vaultId, auth.deviceId);

  // 1) WHO SENT IT.
  let from = senderDeviceId;
  if (from) {
    checkId("sender device id", from);
  } else {
    const index = await listKeyEnvelopesForSelf(wasm, auth);
    from = index.find((e) => e.vaultId === vaultId)?.senderDeviceId || "";
    if (!from) {
      throw new UnknownSenderError(
        `this device's envelope index does not say which device deposited the key for vault ` +
          `${JSON.stringify(vaultId)}`,
      );
    }
  }

  // 2) ESTABLISH THE SENDER'S KEY (the pin store, on the accept path at last).
  const sender = await verifySenderForUnwrap(wasm, auth, from, {
    pins: pinStore,
    expectedSafetyNumber,
  });

  // 3) UNWRAP, authenticated and context-bound.
  const vaultKey = unwrapVaultKey(
    wasm,
    secret,
    sender,
    { vaultId, recipientDeviceId: auth.deviceId, senderDeviceId: from },
    envelope,
  );

  // 4) ⭐ OPEN BEFORE RETURNING. Steps 1-3 prove WHO produced the envelope; they
  //    say nothing about whether what came out is the key to THIS vault. The CLI
  //    has always pulled the newest op and opened it before touching its keyring
  //    — the browser clients did not, so a key that opened nothing was sealed
  //    into the device identity and, worse, DISPLACED whatever was there (step
  //    5). Pull once, open once, refuse loudly.
  const ops = await pullContainersAuthed(wasm, auth, auth.baseUrl, vaultId, 0);
  const tipContainer = ops.length > 0 ? ops[ops.length - 1].container : null;
  if (tipContainer) {
    try {
      wasm.open_container(vaultKey, tipContainer);
    } catch (e) {
      throw new VaultKeyDoesNotOpenError(vaultId, (e && e.message) || String(e));
    }
  }

  // 5) NEVER SILENTLY REPLACE. An identical key is a harmless re-accept; a
  //    DIFFERENT one is either a rotation the user should confirm or a hostile
  //    deposit that would cost them everything sealed under the key they hold.
  // `sameBytes` is the module's existing comparison, declared with the pin store
  // below and hoisted; there is deliberately no second copy of it here.
  const heldKey = held[vaultId] ?? null;
  let replaced = null;
  if (heldKey && !sameBytes(heldKey, vaultKey)) {
    const heldFingerprint = await vaultKeyFingerprint(heldKey);
    if (!replace) {
      throw new VaultKeyReplacementError(
        vaultId,
        heldFingerprint,
        await vaultKeyFingerprint(vaultKey),
      );
    }
    replaced = heldFingerprint;
  }

  return {
    vaultId,
    vaultKey,
    envelope,
    fingerprint: await vaultKeyFingerprint(vaultKey),
    senderDeviceId: from,
    senderTrust: sender.trust,
    senderSafetyNumber: sender.safetyNumber,
    pins: pinStore,
    // ⭐ Step 4's verdict. `false` ONLY when the server holds no vault yet, so
    // there was nothing to open — never when an open was attempted and failed.
    verifiedAgainstTip: tipContainer !== null,
    // The newest op, already fetched and already proven to open. A caller adopts
    // the vault from THIS rather than pulling again.
    tipContainer,
    // Step 5's verdict: the fingerprint of the key this one replaced, or null.
    replaced,
  };
}

/**
 * This device's OWN envelope index — which vaults hold a wrapped key for it, and
 * WHICH DEVICE DEPOSITED EACH ONE. SELF-ONLY server-side (`GET
 * /v1/devices/{id}/keys`; asking about another device is 403).
 *
 * Kept here rather than imported from recovery.mjs so the accept path has no
 * dependency on the recovery module; it is METADATA ONLY, never a blob.
 */
async function listKeyEnvelopesForSelf(wasm, auth) {
  const res = await signedFetch(wasm, auth, "GET", `/v1/devices/${auth.deviceId}/keys`, "", null);
  if (res.status !== 200) await failResponse(res, "listKeyEnvelopesForSelf");
  const json = await res.json();
  return (json.vaults ?? []).map((v) => ({
    vaultId: v.vaultID ?? "",
    senderDeviceId: v.sender_device_id ?? "",
  }));
}

// ===========================================================================
// PHASE 50 — KEY VERIFICATION: SAFETY NUMBERS, KEY PINNING, VAULT ROTATION
// ===========================================================================
//
// ┌─ MIRRORED — NOT SHARED. KEEP BYTE-IDENTICAL WITH cli/src/lib.rs ──────────┐
// │ Every construction below is duplicated in the sigil-cli LIBRARY (which the │
// │ `sigil` CLI *and* the native desktop app both call). The safety-number      │
// │ digest in particular MUST agree byte for byte between Rust and JS, or two   │
// │ people comparing digits across clients would see different numbers and      │
// │ conclude they were under attack. Both sides carry the SAME known-answer     │
// │ test, and sigil-wasm/test/pinning-interop.mjs proves the agreement by       │
// │ running the real `sigil` binary against this module.                        │
// └────────────────────────────────────────────────────────────────────────────┘
//
// THE HOLE THIS CLOSES. `fetchHybridKey` used to return whatever the server
// said, and `shareVault` wrapped the vault key to it. A hostile or compromised
// server could substitute its OWN hybrid public key for the recipient's, receive
// the vault key wrapped to itself, and read the vault — invisibly.
//
//   1. PINNING — zero user effort, works from the SECOND contact onward. The
//      first key seen for a device is PINNED; every later fetch compares. Changed
//      => KeyPinMismatchError, a hard stop. Never silently accepted, never
//      auto-re-pinned.
//   2. SAFETY NUMBER — closes the FIRST-contact window that pinning cannot. Six
//      5-digit groups derived from the full hybrid public key + device id, read
//      aloud over a channel the server does not control. The pairwise variant is
//      ORDER-INDEPENDENT so both people see the same string.
//   3. ROTATION — a fresh vault key, the vault re-sealed under it, re-wrapped to
//      a chosen set of devices, every other envelope deleted. ⚠️ Protects FUTURE
//      content ONLY: a device that already unwrapped the old key keeps whatever
//      it copied.
//
// WHERE THE PIN STORE LIVES IN A BROWSER. The browser clients persist ONLY
// sealed containers, and Phase 50 does not regress that: the pin store rides
// INSIDE the existing sealed device-identity container (device-auth.mjs, schema
// v3, field `pins`). Nothing new is written to localStorage / chrome.storage in
// the clear.

// ── safety numbers ───────────────────────────────────────────────────────────

/** Domain separation for a SINGLE device's digest. cli/src/lib.rs::SAFETY_NUMBER_PREFIX. */
export const SAFETY_NUMBER_PREFIX = "sigil-safety-number-v1\n";
/** Domain separation for the pairwise digest. cli/src/lib.rs::SAFETY_NUMBER_PAIR_PREFIX. */
export const SAFETY_NUMBER_PAIR_PREFIX = "sigil-safety-number-pair-v1\n";
/** Six 5-digit groups = 30 decimal digits ~= 99.6 bits. */
export const SAFETY_NUMBER_GROUPS = 6;
/** Digest bytes consumed per rendered group. */
export const SAFETY_NUMBER_BYTES_PER_GROUP = 5;

/** Concatenate byte chunks into one Uint8Array. */
function concat(parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const out = new Uint8Array(n);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** Big-endian u32 length prefix, so no two different inputs share a byte stream. */
function u32be(n) {
  return new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
}

/** A length-prefixed transcript field (mirrors the Rust `absorb_field`). */
function field(bytes) {
  return [u32be(bytes.length), bytes];
}

/**
 * The raw 32-byte SAFETY DIGEST binding a device id to the FULL hybrid public
 * key material. MUST match cli/src/lib.rs::hybrid_safety_digest byte for byte:
 *
 *   SHA-256( "sigil-safety-number-v1\n"
 *          ‖ u32_be(len(deviceId)) ‖ deviceId
 *          ‖ u32_be(32)            ‖ x25519PublicKey
 *          ‖ u32_be(1184)          ‖ mlkemEncapsKey )
 *
 * BOTH halves of the hybrid key are covered, and the device id is bound in, so a
 * genuine key relayed under a different device's id does not verify.
 */
export async function hybridSafetyDigest(deviceId, publicIdentity) {
  checkId("device id", deviceId);
  const pub = requirePublicIdentity(publicIdentity);
  const message = concat([
    TEXT_ENCODER.encode(SAFETY_NUMBER_PREFIX),
    ...field(TEXT_ENCODER.encode(deviceId)),
    ...field(pub.x25519PublicKey),
    ...field(pub.mlkemEncapsKey),
  ]);
  return new Uint8Array(await webcrypto().subtle.digest("SHA-256", message));
}

/**
 * Render a 32-byte digest as `"12345 67890 13579 24680 11223 44556"`.
 *
 * Each group is 5 digest bytes read BIG-ENDIAN, reduced mod 100000 and
 * zero-padded. Mirrors cli/src/lib.rs::render_safety_number.
 */
export function renderSafetyNumber(digest) {
  if (!(digest instanceof Uint8Array) || digest.length < SAFETY_NUMBER_GROUPS * SAFETY_NUMBER_BYTES_PER_GROUP) {
    throw new Error("sharing: renderSafetyNumber needs at least 30 digest bytes");
  }
  const groups = [];
  for (let g = 0; g < SAFETY_NUMBER_GROUPS; g += 1) {
    let acc = 0;
    for (let i = 0; i < SAFETY_NUMBER_BYTES_PER_GROUP; i += 1) {
      // 5 bytes max out at 2^40, well inside a JS double's exact integer range.
      acc = acc * 256 + digest[g * SAFETY_NUMBER_BYTES_PER_GROUP + i];
    }
    groups.push(String(acc % 100000).padStart(5, "0"));
  }
  return groups.join(" ");
}

/**
 * ⭐ THE NUMBER A USER READS ALOUD. The safety number of ONE device's hybrid
 * public key.
 *
 *   await safetyNumber(deviceId, { x25519PublicKey, mlkemEncapsKey }) -> "..."
 *
 * Compare it with the other person over a channel the SERVER DOES NOT CONTROL
 * (a phone call, in person) BEFORE the first share. Pinning cannot protect first
 * contact; this is the only thing that can.
 */
export async function safetyNumber(deviceId, publicIdentity) {
  return renderSafetyNumber(await hybridSafetyDigest(deviceId, publicIdentity));
}

/**
 * The PAIRWISE safety number for two devices — ORDER-INDEPENDENT, so both sides
 * see the SAME digits no matter who runs it:
 *
 *   (lo, hi) = the two per-device digests sorted BYTEWISE ascending
 *   SHA-256( "sigil-safety-number-pair-v1\n" ‖ lo ‖ hi )  -> rendered
 *
 *   await pairwiseSafetyNumber({ deviceId, identity }, { deviceId, identity })
 */
export async function pairwiseSafetyNumber(a, b) {
  const da = await hybridSafetyDigest(a.deviceId, a.identity);
  const db = await hybridSafetyDigest(b.deviceId, b.identity);
  let lo = da;
  let hi = db;
  for (let i = 0; i < da.length; i += 1) {
    if (da[i] !== db[i]) {
      if (da[i] > db[i]) {
        lo = db;
        hi = da;
      }
      break;
    }
  }
  const message = concat([TEXT_ENCODER.encode(SAFETY_NUMBER_PAIR_PREFIX), lo, hi]);
  return renderSafetyNumber(new Uint8Array(await webcrypto().subtle.digest("SHA-256", message)));
}

// ── the pin store ────────────────────────────────────────────────────────────

/** Schema version of the pin store. Mirrors cli/src/lib.rs::HYBRID_PIN_STORE_VERSION. */
export const HYBRID_PIN_STORE_VERSION = 1;

/**
 * The `origin` marker a pin carries when its key was DERIVED locally (from a
 * recovery secret) rather than fetched from a server — the one pin in the system
 * established without asking anybody, so there was nothing to substitute.
 *
 * MIRRORS `cli/src/lib.rs::PIN_ORIGIN_RECOVERY_KIT`. The pin-store VERSION is
 * deliberately NOT bumped: `origin` is additive and omitted when absent, so an
 * older client reads a newer store unchanged.
 */
export const PIN_ORIGIN_RECOVERY_KIT = "recovery-kit";

/**
 * ⚠️ Thrown by {@link rotateVaultKey} when a device currently holding an
 * envelope was named by NEITHER the new recipient set NOR `drop`.
 *
 * Rotating would delete its envelope and silently end its access — including,
 * most damagingly, a RECOVERY KIT's. `unknown` is `[{ deviceId, isRecoveryKit }]`
 * and carries no key material. Nothing was changed when this throws.
 */
export class RecipientsWouldBeDroppedError extends Error {
  constructor(vaultId, unknown) {
    const names = unknown
      .map((u) => (u.isRecoveryKit ? `${u.deviceId} (YOUR RECOVERY KIT)` : u.deviceId))
      .join(", ");
    super(
      `refusing to rotate ${vaultId}: ${unknown.length} device(s) hold a wrapped key but were ` +
        `named by neither the recipient list nor drop — rotating would silently end their ` +
        `access: ${names}. Nothing was changed.`,
    );
    this.name = "RecipientsWouldBeDroppedError";
    this.vaultId = vaultId;
    this.unknown = unknown;
  }
}

/**
 * ⚠️ THE KEY-SUBSTITUTION ALARM. Thrown when a device's published hybrid public
 * key differs from the one this client pinned.
 *
 * It is a distinct, CATCHABLE class (not a string match) carrying the device id
 * and BOTH safety numbers, so a UI can render exactly what the human needs to
 * decide: "here is what we trusted, here is what the server just said, go call
 * them".
 *
 * Reaching this means the caller MUST NOT proceed — and nothing that throws it
 * has wrapped or uploaded anything.
 */
export class KeyPinMismatchError extends Error {
  constructor(deviceId, pinnedSafetyNumber, presentedSafetyNumber) {
    super(
      `REFUSING TO SHARE: the hybrid public key published for device ${deviceId} has CHANGED ` +
        `since this client pinned it.\n  pinned    safety number: ${pinnedSafetyNumber}\n  ` +
        `presented safety number: ${presentedSafetyNumber}\n  ` +
        `This is either a KEY-SUBSTITUTION ATTACK (a hostile or compromised server swapped in a ` +
        `key it can decrypt with, so it would receive this vault's key) or a LEGITIMATE ` +
        `RE-ENROLMENT of that device. No vault key was wrapped and nothing was uploaded. ` +
        `Confirm the presented safety number with the other device's owner over a TRUSTED ` +
        `out-of-band channel, then re-pin deliberately with repinHybridKey().`,
    );
    this.name = "KeyPinMismatchError";
    /** @type {string} the device whose key changed. */
    this.deviceId = deviceId;
    /** @type {string} the safety number we trusted. */
    this.pinnedSafetyNumber = pinnedSafetyNumber;
    /** @type {string} the safety number the server just presented. */
    this.presentedSafetyNumber = presentedSafetyNumber;
  }
}

/** A fresh, empty pin store. */
export function newPinStore() {
  return { version: HYBRID_PIN_STORE_VERSION, pins: {} };
}

/** Normalize/validate a pin store, accepting `null`/`undefined` as empty. */
export function requirePinStore(store) {
  // FAIL CLOSED. An earlier version returned a fresh empty store for
  // null/undefined, which is the wrong failure mode for a security control: a
  // caller that forgot to pass its pins would silently get "every key is
  // first-sight", i.e. pinning would quietly stop protecting anything and the
  // key-substitution attack this module exists to block would succeed. No
  // shipping caller relies on that fallback — the webapp, the extension and the
  // tests all call newPinStore() explicitly when they genuinely want an empty
  // store — so an absent store is treated as a programming error, loudly.
  if (store === null || store === undefined) {
    throw new Error(
      "sharing: a pin store is required (pinning is what blocks key substitution). " +
        "Pass the store from the unlocked device identity, or newPinStore() if you " +
        "deliberately want to start with no pinned keys.",
    );
  }
  if (typeof store !== "object" || typeof store.pins !== "object" || store.pins === null) {
    throw new Error("sharing: a pin store must be { version, pins: { [deviceId]: pin } }");
  }
  if (store.version !== HYBRID_PIN_STORE_VERSION) {
    throw new Error(
      `sharing: unsupported pin store version ${store.version}: expected ${HYBRID_PIN_STORE_VERSION}`,
    );
  }
  return store;
}

/** Build the pin record for a key as it stands right now (mirrors `make_pin`). */
async function makePin(deviceId, identity, repins) {
  const pub = requirePublicIdentity(identity);
  return {
    device_id: deviceId,
    x25519_public_key: bytesToBase64(pub.x25519PublicKey),
    mlkem_encaps_key: bytesToBase64(pub.mlkemEncapsKey),
    safety_number: await safetyNumber(deviceId, pub),
    pinned_at: Math.floor(Date.now() / 1000),
    repins,
  };
}

/** Constant-shape byte comparison (these are PUBLIC keys; no timing concern). */
function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * ⭐ THE CHOKE POINT. Compare a fetched hybrid public key against the pin store
 * and pin it on first sight.
 *
 *   await checkAndPin(pins, deviceId, identity)
 *     -> { status: "first-sight" | "match", safetyNumber, changed: false }
 *
 *   * device not in the store -> PINS it (mutating `pins` in place) and returns
 *     `"first-sight"`;
 *   * pinned key byte-identical -> `"match"`, store untouched;
 *   * pinned key DIFFERS -> throws {@link KeyPinMismatchError} and changes
 *     NOTHING.
 *
 * There is deliberately NO option on this function that accepts a changed key.
 * Re-pinning is a separate, explicit operation ({@link repinHybridKey}).
 *
 * The comparison is over DECODED raw bytes, so a server re-encoding the same key
 * cannot raise a false alarm. The CALLER is responsible for PERSISTING `pins`
 * afterwards (the browser clients re-seal the device-identity container).
 */
export async function checkAndPin(pins, deviceId, identity) {
  const store = requirePinStore(pins);
  checkId("device id", deviceId);
  const pub = requirePublicIdentity(identity);

  const existing = store.pins[deviceId];
  if (existing) {
    const pinnedX = base64ToBytes(existing.x25519_public_key ?? "");
    const pinnedM = base64ToBytes(existing.mlkem_encaps_key ?? "");
    if (sameBytes(pinnedX, pub.x25519PublicKey) && sameBytes(pinnedM, pub.mlkemEncapsKey)) {
      return { status: "match", safetyNumber: existing.safety_number, changed: false };
    }
    throw new KeyPinMismatchError(
      deviceId,
      existing.safety_number,
      await safetyNumber(deviceId, pub),
    );
  }

  const pin = await makePin(deviceId, pub, 0);
  store.version = HYBRID_PIN_STORE_VERSION;
  store.pins[deviceId] = pin;
  return { status: "first-sight", safetyNumber: pin.safety_number, changed: false };
}

/**
 * ⚠️ EXPLICIT, DELIBERATE re-pin — the ONLY way a changed key is ever accepted.
 *
 *   await repinHybridKey(pins, deviceId, identity)
 *     -> { previousSafetyNumber: string | null, safetyNumber, repins }
 *
 * NOTHING calls this automatically. A UI must make the user act on purpose, and
 * must tell them WHY it is dangerous: a changed key is either a legitimate
 * re-enrolment or a key-substitution attack, and only a human comparing the new
 * safety number out of band can tell those apart.
 */
export async function repinHybridKey(pins, deviceId, identity) {
  const store = requirePinStore(pins);
  checkId("device id", deviceId);
  const previous = store.pins[deviceId] ?? null;
  const repins = previous ? (previous.repins ?? 0) + 1 : 0;
  const pin = await makePin(deviceId, requirePublicIdentity(identity), repins);
  store.version = HYBRID_PIN_STORE_VERSION;
  store.pins[deviceId] = pin;
  return {
    previousSafetyNumber: previous ? previous.safety_number : null,
    safetyNumber: pin.safety_number,
    repins,
  };
}

// ⚠️ `fetchHybridKeyPinned` USED TO LIVE HERE and is DELETED ON PURPOSE
// (Phase 57), mirroring the deletion of `fetch_hybrid_key_pinned` in
// cli/src/lib.rs. It was ADR 0038's choke point — fetch a hybrid public key and
// pin-check it in one call — and Phase 54 SUPERSEDED it with
// {@link verifyRecipientForWrap}, which additionally refuses an unverified
// recovery kit and honours a caller-supplied safety number. It then survived
// with exactly ONE caller (a test) while the docs still recommended it by name:
// an exported fetch-and-pin WITHOUT the recovery-kit refusal is a ready-made
// bypass of the wrap gate for whoever reaches for the familiar name next.
//
// Need a key for a wrap? `verifyRecipientForWrap` — every wrap path goes through
// it, and it is what shareVault / rotateVaultKey / coverVault call. Need a key
// for DISPLAY only (a safety number, a deliberate re-pin)? The bare
// {@link fetchHybridKey}, which wraps nothing.

// ===========================================================================
// ⭐⭐ THE WRAP GATE — MIRRORS cli/src/lib.rs::verify_recipient_for_wrap
// ===========================================================================
//
// ADR 0038: "the enforcement rides on the fetch itself … EVERY wrap path goes
// through it. A trust store that some code path forgets to consult is
// worthless."
//
// Phase 54 broke that rule on the Rust side by putting the recovery-kit
// verification on ONE COMMAND (`recovery cover`) instead of on the choke point,
// so `vault share --to <kitID>` and `vault rotate --to <kitID>` reached the same
// outcome through ordinary first-sight TOFU. The same shape existed here:
// coverVault checked, shareVault and rotateVaultKey did not. Both sides now
// funnel every wrap through ONE function.

// The device label a recovery kit enrols under. ⭐ IMPORTED, NOT REDEFINED
// (Phase 57): this file used to carry its own `RECOVERY_KIT_DEVICE_LABEL =
// "recovery-kit"` beside recovery.mjs's `RECOVERY_DEVICE_LABEL`, so ONE label
// existed as THREE independent string literals (here, recovery.mjs,
// cli/src/lib.rs) with nothing tying them together. That label is the ONLY signal
// driving `recipientIsRecoveryKit`, i.e. the arm that makes a wrap to a kit obey
// ADR 0042's mandatory-safety-number rule instead of ordinary TOFU — so a rename
// in one place silently downgrades the kit to first-sight TOFU.
//
// There are now TWO literals, one per language, and `recovery-interop.mjs` asserts
// them equal END TO END by driving the REAL `sigil` binary against a kit this
// client enrolled (and vice versa). It is NOT re-exported here: the `@sigil/wasm`
// barrel star-exports both modules, and two star-exports of one name make it
// ambiguous and silently drop it. (The import itself is at the top of the file.)

/** How trust in a recipient's key was established. Mirrors `RecipientTrust`. */
export const TRUST_DERIVED = "derived";
export const TRUST_PINNED = "pinned";
export const TRUST_VERIFIED_FIRST_SIGHT = "verified-first-sight";
export const TRUST_UNVERIFIED_FIRST_SIGHT = "unverified-first-sight";

/**
 * ⛔ Thrown when a wrap targets a RECOVERY KIT this client has never pinned and
 * no safety number was supplied to check the server's answer against.
 *
 * Stricter than an ordinary first sight ON PURPOSE: a kit's safety number is
 * printed on the sheet, so the out-of-band channel is guaranteed to exist — and
 * a kit is the one credential that reconstructs a whole account. Nothing was
 * wrapped, nothing uploaded, and no key pinned.
 */
export class UnverifiedRecoveryKitError extends Error {
  constructor(deviceId, presentedSafetyNumber) {
    super(
      `REFUSING TO WRAP: device ${deviceId} is a RECOVERY KIT this client has never pinned, so ` +
        `the only thing vouching for its key is the server — and a hostile server that ` +
        `substituted its own key would be handed this vault's key.\n  from server: ` +
        `${presentedSafetyNumber}\n  The safety number is PRINTED ON THE RECOVERY SHEET. Compare ` +
        `it, then retry supplying expectedSafetyNumber. Nothing was wrapped, nothing was ` +
        `uploaded, and no key was pinned.`,
    );
    this.name = "UnverifiedRecoveryKitError";
    this.deviceId = deviceId;
    this.presentedSafetyNumber = presentedSafetyNumber;
  }
}

/** ⛔ Thrown when a supplied safety number does not match the served key. */
export class SafetyNumberMismatchError extends Error {
  constructor(deviceId, expected, presented) {
    super(
      `REFUSING TO WRAP: the safety number supplied does not match the key this server is ` +
        `serving for ${deviceId}.\n  you supplied: ${expected}\n  from server:  ${presented}\n  ` +
        `Either it was mistyped, or the server substituted a key it can decrypt with. Nothing was ` +
        `wrapped, nothing was uploaded, and no key was pinned.`,
    );
    this.name = "SafetyNumberMismatchError";
    this.deviceId = deviceId;
    this.expectedSafetyNumber = expected;
    this.presentedSafetyNumber = presented;
  }
}

/** Compare safety numbers ignoring spacing/presentation. */
function sameSafetyNumber(a, b) {
  return String(a).replace(/\D/g, "") === String(b).replace(/\D/g, "");
}

/** The DERIVED pin for a device, if this client holds one (mirrors `derived_pin`). */
function derivedPinIdentity(store, deviceId) {
  const pin = store?.pins?.[deviceId];
  if (!pin || pin.origin !== PIN_ORIGIN_RECOVERY_KIT) return null;
  return {
    x25519PublicKey: base64ToBytes(pin.x25519_public_key ?? ""),
    mlkemEncapsKey: base64ToBytes(pin.mlkem_encaps_key ?? ""),
  };
}

/**
 * Is `deviceId` a RECOVERY KIT, as far as this client can tell?
 *
 * The signal is the kit's deliberately-visible device label on the CALLER'S OWN
 * account listing (`GET /v1/account`, which names no account and returns only
 * "mine"). FAIL-CLOSED: an error other than 501 (no account model on this
 * server at all) propagates, so a wrap is refused rather than proceeding on a
 * signal we could not read.
 *
 * ⚠️ HONEST LIMIT, identical to the Rust side: the label comes from the server,
 * which is the adversary. A hostile server can HIDE it and degrade a kit wrap to
 * ordinary first-sight TOFU with a warning — no worse than any other first
 * contact. What it cannot do is make the wrap accept a CHANGED key or a
 * mismatched safety number.
 */
async function recipientIsRecoveryKit(wasm, auth, deviceId) {
  try {
    const account = await getAccount(wasm, { deviceId: auth.deviceId, seed: auth.seed }, auth.baseUrl);
    return (account.devices ?? []).some(
      (d) => d.device_id === deviceId && d.label === RECOVERY_KIT_DEVICE_LABEL,
    );
  } catch (err) {
    if (err && err.status === 501) return false;
    throw err;
  }
}

/**
 * ⭐⭐ THE GATE. Resolve a recipient's hybrid public key AND establish trust in
 * it, in ONE call, before anything can be wrapped to it.
 *
 *   await verifyRecipientForWrap(wasm, auth, deviceId, {
 *     pins, expectedSafetyNumber, knownRecoveryKit
 *   }) -> { deviceId, identity, trust, safetyNumber, pins }
 *
 * | situation | outcome | pin store |
 * |---|---|---|
 * | key DERIVED locally (`origin: "recovery-kit"`) | `derived`, NO fetch | untouched |
 * | pinned key, byte-identical | `pinned` | untouched |
 * | pinned key, **different** | ⛔ {@link KeyPinMismatchError} | **untouched** |
 * | first sight + matching safety number | `verified-first-sight` | pinned |
 * | first sight + **wrong** safety number | ⛔ {@link SafetyNumberMismatchError} | **untouched** |
 * | first sight, **RECOVERY KIT**, no safety number | ⛔ {@link UnverifiedRecoveryKitError} | **untouched** |
 * | first sight, ordinary device, no safety number | `unverified-first-sight` (ADR 0038 TOFU) | pinned |
 *
 * Every refusal happens BEFORE the key is pinned. Pinning a key we then refused
 * would mean a retry sees "match" and proceeds — the alarm silencing itself.
 */
export async function verifyRecipientForWrap(
  wasm,
  auth,
  deviceId,
  { pins = null, expectedSafetyNumber = null, knownRecoveryKit = false } = {},
) {
  checkAuth(auth);
  checkId("device id", deviceId);
  const store = requirePinStore(pins ?? auth.pins);

  // 1) A LOCALLY DERIVED key. Nothing was fetched, so nothing could be swapped.
  const derived = derivedPinIdentity(store, deviceId);
  if (derived) {
    return {
      deviceId,
      identity: derived,
      trust: TRUST_DERIVED,
      safetyNumber: await safetyNumber(deviceId, derived),
      pins: store,
    };
  }

  // 2) Ask the server, then decide. Nothing below writes to the pin store until
  //    every check has passed.
  const identity = await fetchHybridKey(wasm, auth, deviceId);
  const presented = await safetyNumber(deviceId, identity);

  if (expectedSafetyNumber && !sameSafetyNumber(expectedSafetyNumber, presented)) {
    throw new SafetyNumberMismatchError(deviceId, expectedSafetyNumber, presented);
  }

  if (store.pins[deviceId]) {
    // Throws KeyPinMismatchError on a changed key; mutates nothing either way.
    await checkAndPin(store, deviceId, identity);
    return { deviceId, identity, trust: TRUST_PINNED, safetyNumber: presented, pins: store };
  }

  // 3) FIRST SIGHT.
  let trust = TRUST_VERIFIED_FIRST_SIGHT;
  if (!expectedSafetyNumber) {
    if (knownRecoveryKit || (await recipientIsRecoveryKit(wasm, auth, deviceId))) {
      throw new UnverifiedRecoveryKitError(deviceId, presented);
    }
    trust = TRUST_UNVERIFIED_FIRST_SIGHT;
  }
  await checkAndPin(store, deviceId, identity);
  return { deviceId, identity, trust, safetyNumber: presented, pins: store };
}

// ===========================================================================
// ⭐⭐ THE UNWRAP GATE — MIRRORS cli/src/lib.rs::verify_sender_for_unwrap
// ===========================================================================
//
// ADR 0038 put a gate on the FETCH so no wrap could reach an unverified key. The
// RECEIVING side had no gate at all: `acceptVault` fetched nothing, opened
// anything, and checked only that the plaintext was 32 bytes long. That is what
// made a forged envelope indistinguishable from a real one.
//
// ⚠️ THE HONEST LIMIT, stated plainly because it is the same one ADR 0038
// accepted: on FIRST SIGHT of a sender, a hostile server can serve its own key
// as "the sender's" AND forge an envelope under it. Pinning cannot protect first
// contact in either direction. What authentication buys UNCONDITIONALLY is the
// other attacker in the threat model — a co-tenant with write access, or any
// party that is not the server — who can no longer mint an acceptable envelope
// at all. Against the server itself the defence is the same as for a wrap: a
// pinned sender is a hard stop on change, and `expectedSafetyNumber` closes
// first contact if a human uses it.

/** Module-private construction token: the JS equivalent of private fields. */
const VERIFIED_SENDER_GATE = Symbol("sigil.VerifiedSender");

/**
 * A sender whose hybrid public key has passed {@link verifySenderForUnwrap} (or
 * is held locally in full).
 *
 * ⭐ It CANNOT be constructed from outside this module — `new VerifiedSender(...)`
 * throws — so {@link unwrapVaultKey}'s signature is a proof rather than a
 * convention. Mirrors the CLI's `VerifiedSender`, whose fields are private and
 * which has no public literal.
 */
export class VerifiedSender {
  constructor(gate, deviceId, identity, trust, safetyNumberText) {
    if (gate !== VERIFIED_SENDER_GATE) {
      throw new Error(
        "sharing: VerifiedSender cannot be constructed directly — use verifySenderForUnwrap() " +
          "(which pin-checks the depositing device's published key) or verifiedSenderFromLocal().",
      );
    }
    /** @type {string} the device this key belongs to. */
    this.deviceId = deviceId;
    /** @type {{x25519PublicKey: Uint8Array, mlkemEncapsKey: Uint8Array}} */
    this.identity = identity;
    /** @type {string} how trust was established (one of the TRUST_* constants). */
    this.trust = trust;
    /** @type {string} the safety number of the key about to authenticate an envelope. */
    this.safetyNumber = safetyNumberText;
    Object.freeze(this);
  }

  /** The sender's static X25519 public key — the authentication input. */
  get x25519PublicKey() {
    return this.identity.x25519PublicKey;
  }
}

/**
 * ⭐ The sender is an identity THIS PROCESS HOLDS THE SECRET HALF OF.
 *
 * Nothing is fetched, so there is nothing for a server to substitute — the
 * strongest trust outcome, stronger than a pin. It is NOT a bypass: constructing
 * it requires the sender's SECRET identity, and anyone holding that already *is*
 * the sender. Used when a device unwraps an envelope it wrapped itself (a
 * recovery kit's mandatory pre-print round trip). Mirrors
 * `VerifiedSender::from_local`.
 */
export async function verifiedSenderFromLocal(wasm, sender) {
  const s = requireSenderIdentity(sender);
  const identity = hybridPublicIdentity(wasm, s.hybrid);
  return new VerifiedSender(
    VERIFIED_SENDER_GATE,
    s.deviceId,
    identity,
    TRUST_DERIVED,
    await safetyNumber(s.deviceId, identity),
  );
}

/**
 * ⭐⭐ THE UNWRAP GATE. Resolve the hybrid public key of the device that
 * DEPOSITED an envelope, and establish trust in it, before anything is opened.
 *
 *   await verifySenderForUnwrap(wasm, auth, deviceId, { pins, expectedSafetyNumber })
 *     -> VerifiedSender
 *
 * | situation | outcome | pin store |
 * |---|---|---|
 * | key DERIVED locally (`origin: "recovery-kit"`) | `derived`, NO fetch | untouched |
 * | pinned key, byte-identical | `pinned` | untouched |
 * | pinned key, **different** | ⛔ {@link KeyPinMismatchError} | **untouched** |
 * | first sight + matching safety number | `verified-first-sight` | pinned |
 * | first sight + **wrong** safety number | ⛔ {@link SafetyNumberMismatchError} | **untouched** |
 * | first sight, no safety number | `unverified-first-sight` (ADR 0038 TOFU) | pinned |
 *
 * Deliberately the SAME table as {@link verifyRecipientForWrap} minus the
 * recovery-kit row: a kit is a RECIPIENT of wraps, and the one place a kit acts
 * as a sender (its own pre-print verification) holds the secret and uses
 * {@link verifiedSenderFromLocal}.
 *
 * As on the wrap side, every refusal happens BEFORE the key is pinned, so a
 * retry cannot silence the alarm by pinning what was just refused.
 */
export async function verifySenderForUnwrap(
  wasm,
  auth,
  deviceId,
  { pins = null, expectedSafetyNumber = null } = {},
) {
  checkAuth(auth);
  checkId("sender device id", deviceId);
  const store = requirePinStore(pins ?? auth.pins);

  // 1) A LOCALLY DERIVED key. Nothing was fetched, so nothing could be swapped.
  const derived = derivedPinIdentity(store, deviceId);
  if (derived) {
    return new VerifiedSender(
      VERIFIED_SENDER_GATE,
      deviceId,
      derived,
      TRUST_DERIVED,
      await safetyNumber(deviceId, derived),
    );
  }

  // 2) Ask the server, then decide. Nothing below writes to the pin store until
  //    every check has passed.
  const identity = await fetchHybridKey(wasm, auth, deviceId);
  const presented = await safetyNumber(deviceId, identity);

  if (expectedSafetyNumber && !sameSafetyNumber(expectedSafetyNumber, presented)) {
    throw new SafetyNumberMismatchError(deviceId, expectedSafetyNumber, presented);
  }

  const alreadyPinned = Boolean(store.pins[deviceId]);
  // Throws KeyPinMismatchError on a changed key; mutates nothing in that case.
  await checkAndPin(store, deviceId, identity);
  const trust = alreadyPinned
    ? TRUST_PINNED
    : expectedSafetyNumber
      ? TRUST_VERIFIED_FIRST_SIGHT
      : TRUST_UNVERIFIED_FIRST_SIGHT;
  return new VerifiedSender(VERIFIED_SENDER_GATE, deviceId, identity, trust, presented);
}

// ── rotation transport: list + delete envelopes ──────────────────────────────

/** The URL PATH of a vault's envelope COLLECTION (mirrors `key_envelopes_path`). */
function keyEnvelopesPath(vaultId) {
  return `/v1/vaults/${vaultId}/keys`;
}

/**
 * LIST which devices currently hold a key envelope for a vault.
 *
 *   listKeyEnvelopes(wasm, auth, vaultId) -> [{ deviceId, senderDeviceId, sizeBytes, createdAt }]
 *
 * Requires WRITE on the vault (an owner-side operation, same choke point as
 * depositing). METADATA ONLY — the server never returns a blob here.
 */
export async function listKeyEnvelopes(wasm, auth, vaultId) {
  checkAuth(auth);
  checkId("vault id", vaultId);
  const path = keyEnvelopesPath(vaultId);
  const res = await signedFetch(wasm, auth, "GET", path, "", null);
  if (res.status !== 200) await failResponse(res, "listKeyEnvelopes");
  const json = await res.json();
  return (json.recipients ?? []).map((r) => ({
    deviceId: r.device_id,
    senderDeviceId: r.sender_device_id ?? "",
    sizeBytes: r.size_bytes ?? 0,
    createdAt: r.created_at ?? "",
  }));
}

/**
 * DELETE the envelope addressed to one device, so a device rotated away from a
 * vault cannot collect the NEW key.
 *
 *   deleteKeyEnvelope(wasm, auth, vaultId, deviceId) -> boolean (false = nothing there)
 *
 * Requires WRITE on the vault. A 404 is NOT an error for a rotation: the desired
 * end state ("no envelope") already holds.
 *
 * ⚠️ This does not un-learn a key the device already unwrapped. It only stops it
 * collecting anything new.
 */
export async function deleteKeyEnvelope(wasm, auth, vaultId, deviceId) {
  checkAuth(auth);
  checkId("vault id", vaultId);
  checkId("device id", deviceId);
  const path = keyEnvelopePath(vaultId, deviceId);
  const res = await signedFetch(wasm, auth, "DELETE", path, "", null);
  if (res.status === 404) return false;
  if (res.status !== 200) await failResponse(res, "deleteKeyEnvelope");
  return true;
}

// ── rotation ─────────────────────────────────────────────────────────────────

/**
 * ⭐ ROTATE a vault key and RE-WRAP it to a chosen set of devices.
 *
 *   await rotateVaultKey(wasm, auth, {
 *     vaultId, recipientDeviceIds, sealedVault, oldVaultKey, params, salt?, nonce?, pins?
 *   }) -> { vaultKey, sealedVault, oldFingerprint, newFingerprint, rewrapped, removed }
 *
 * The owner-side remediation that revocation was missing:
 *
 *   1. fetch + PIN-CHECK **every** recipient FIRST, so a {@link KeyPinMismatchError}
 *      aborts the whole rotation before anything is re-sealed or uploaded;
 *   2. draw a FRESH 32-byte vault key;
 *   3. re-seal the sealed container under it (open with the old key, seal with
 *      the new one — container-agnostic, it never inspects the plaintext);
 *   4. wrap the new key to each recipient and UPSERT the envelope;
 *   5. DELETE the envelope of every device holding one that is NOT a recipient.
 *
 * The CALLER persists the returned `sealedVault` (and pushes it) and the returned
 * `vaultKey` — this module stores nothing.
 *
 * ⭐ **THE FAIL-CLOSED DROP GUARD (Phase 54).** Step 5 DESTROYS access, so it
 * may not happen by omission. Before anything is mutated, the current envelope
 * holders are listed and any device in neither `recipientDeviceIds` nor `drop`
 * throws {@link RecipientsWouldBeDroppedError}, naming each one and flagging any
 * that this client's pin store marks as a RECOVERY KIT (`origin:
 * "recovery-kit"`). `recipientDeviceIds` keeps its exact meaning — the complete
 * new recipient set — so excluding a compromised device is still one call; what
 * changed is that destroying access is now stated rather than implied.
 *
 * MIRRORS `cli/src/lib.rs::rotate_vault_key`'s guard exactly.
 *
 * ⚠️ WHAT THIS DOES NOT DO. It protects FUTURE content ONLY. A device that
 * already unwrapped the PREVIOUS key still holds that key and whatever it had
 * already copied; cryptography cannot un-send a secret. What it DOES guarantee is
 * that anything sealed AFTER the rotation is unreadable to a device left out of
 * `recipientDeviceIds`.
 */
export async function rotateVaultKey(
  wasm,
  auth,
  {
    vaultId,
    recipientDeviceIds,
    sealedVault,
    oldVaultKey,
    params,
    salt = null,
    nonce = null,
    pins = null,
    drop = [],
    safetyNumbers = {},
    sender = null,
  },
) {
  checkAuth(auth);
  checkId("vault id", vaultId);
  // The AUTHENTICATING identity for every re-wrap (defaults to this client's).
  const from = requireSenderIdentity(sender ?? senderFromAuth(auth));
  if (!Array.isArray(recipientDeviceIds) || recipientDeviceIds.length === 0) {
    throw new Error(
      "sharing: rotateVaultKey needs recipientDeviceIds — name EVERY device that keeps access " +
        "(usually including this one, so the owner can still recover its own key)",
    );
  }
  for (const id of recipientDeviceIds) checkId("device id", id);
  requireVaultKey(oldVaultKey);
  const container = sealedVault instanceof Uint8Array ? sealedVault : new Uint8Array(sealedVault);
  const store = requirePinStore(pins ?? auth.pins);

  // 0) ⭐ THE DROP GUARD (Phase 54). Enumerate who holds an envelope RIGHT NOW
  //    and refuse if the caller did not account for every one of them. This runs
  //    FIRST — before the pin checks, before the re-seal, before any request
  //    that changes state — so a refusal leaves everything exactly as it was.
  const existingHolders = await listKeyEnvelopes(wasm, auth, vaultId);
  const keepSet = new Set(recipientDeviceIds);
  const dropSet = new Set(Array.isArray(drop) ? drop : []);
  const unnamed = existingHolders
    .map((h) => h.deviceId)
    .filter((d) => !keepSet.has(d) && !dropSet.has(d));
  if (unnamed.length > 0) {
    // Consult the LOCAL pin store so a recovery kit is NAMED as such. A device
    // that never heard of the kit has no such pin and will only see "unknown
    // recipient" — an honest limit, not a bug.
    throw new RecipientsWouldBeDroppedError(
      vaultId,
      unnamed.map((deviceId) => ({
        deviceId,
        isRecoveryKit: store?.pins?.[deviceId]?.origin === PIN_ORIGIN_RECOVERY_KIT,
      })),
    );
  }

  // 1) ⭐ GATE EVERYONE BEFORE MUTATING ANYTHING, through the SAME
  //    verifyRecipientForWrap that shareVault uses. A substituted key — or an
  //    unverified RECOVERY KIT recipient — aborts the rotation with the vault
  //    untouched, far better than a half-rotated vault whose key leaked.
  //    `safetyNumbers` is `{ [deviceId]: "the printed digits" }` for any
  //    recipient the user verified out of band; it is REQUIRED for a
  //    first-sight recovery kit.
  const resolved = [];
  for (const deviceId of recipientDeviceIds) {
    const { identity, trust } = await verifyRecipientForWrap(wasm, auth, deviceId, {
      pins: store,
      expectedSafetyNumber: safetyNumbers?.[deviceId] ?? null,
    });
    resolved.push({ deviceId, identity, trust });
  }

  // 2-3) Fresh key, re-seal the container under it.
  const c = webcrypto();
  const vaultKey = generateVaultKey();
  const plaintext = wasm.open_container(oldVaultKey, container);
  // ⭐ NO-DOWNGRADE. This is the direct JS twin of `sigil_cli::reseal_container`,
  // and it used to re-seal at a hardcoded 19456/2/1 no matter what the input
  // declared — so rotating a vault the CLI had written at 65536/4/2 quietly cut
  // its memory cost by 3.4x. `params` is a FLOOR, not a verbatim instruction.
  const p = ratchetParams(wasm, container, params ?? { m_cost: 19456, t_cost: 2, p_cost: 1 });
  const resealed = new Uint8Array(
    wasm.seal_to_container(
      vaultKey,
      salt ?? c.getRandomValues(new Uint8Array(wasm.recommended_salt_len())),
      nonce ?? c.getRandomValues(new Uint8Array(wasm.nonce_len())),
      p.m_cost,
      p.t_cost,
      p.p_cost,
      plaintext,
    ),
  );

  // 4) Re-wrap to every chosen recipient (an UPSERT — the old envelope is
  //    replaced, not appended to).
  const rewrapped = [];
  for (const { deviceId, identity, trust } of resolved) {
    const envelope = wrapVaultKey(
      wasm,
      from,
      identity,
      { vaultId, recipientDeviceId: deviceId, senderDeviceId: from.deviceId },
      vaultKey,
    );
    await putKeyEnvelope(wasm, auth, vaultId, deviceId, envelope);
    rewrapped.push({ deviceId, trust, pinStatus: trust });
  }

  // 5) Remove the stale envelopes of everyone left out. Re-listed rather than
  //    reusing step 0's snapshot, so a device that deposited an envelope
  //    mid-rotation is still caught — and every removal is one the caller named
  //    in `drop`, because step 0 refused otherwise.
  const removed = [];
  for (const existing of await listKeyEnvelopes(wasm, auth, vaultId)) {
    if (keepSet.has(existing.deviceId)) continue;
    if (await deleteKeyEnvelope(wasm, auth, vaultId, existing.deviceId)) {
      removed.push(existing.deviceId);
    }
  }

  return {
    vaultKey,
    sealedVault: resealed,
    oldFingerprint: await vaultKeyFingerprint(oldVaultKey),
    newFingerprint: await vaultKeyFingerprint(vaultKey),
    rewrapped,
    removed,
    pins: store,
  };
}
