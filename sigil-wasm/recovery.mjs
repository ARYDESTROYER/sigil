// sigil-wasm/recovery.mjs — THE RECOVERY KIT, for JavaScript (Phase 54).
//
// Framework-free, dependency-free ESM. Runs in Node and the browser.
//
// THE MODEL, IN ONE SENTENCE. A recovery kit is an ORDINARY MEMBER DEVICE whose
// Ed25519 and hybrid private keys are derived from 32 bytes of client CSPRNG that
// are printed on paper, never transmitted, never stored on any device, and never
// derivable from anything the server holds. `sigild` gains NO concept of
// "recovery": it sees one more device row, one more hybrid PUBLIC key and one
// more opaque ~1226-byte `SIGILhyb` envelope per covered vault — byte-for-byte
// the shapes it already relays for device-to-device sharing (ADR 0035).
//
// ⭐ THERE IS NO NEW MIRROR TO KEEP IN SYNC HERE, AND THAT IS DELIBERATE. The
// Crockford codec, the 16-bit checksum, the version byte and the HKDF-SHA256
// derivation all live in `sigil-core` (`recovery.rs`) and reach this module
// THROUGH THE WASM — `wasm.recovery_encode` / `recovery_decode` /
// `recovery_derive_*` / `recovery_format`. The CLI calls the same Rust. So a kit
// printed by the browser and a kit printed by `sigil recovery generate` are the
// same bytes BY CONSTRUCTION, not by two implementations agreeing. Contrast the
// `SIGILcli` / `SIGILhyb` / TOTP-vault / canonical-v3 layouts, which ARE
// hand-mirrored and need interop tests to catch drift.
//
// What this module mirrors is the FLOW (mint invite -> enroll as the kit ->
// publish -> pin the derived key -> cover -> verify before printing), which
// mirrors `cli/src/lib.rs`'s `recovery_generate` and friends. A divergence there
// yields a 400/403 or a kit the CLI cannot redeem, which
// `sigil-wasm/test/recovery-interop.mjs` is the guard against.
//
// IT DOES NO CRYPTOGRAPHY ITSELF. The codec and derivation happen in the wasm,
// the KEM/AEAD happens in the wasm, every signature goes through
// `device-auth.mjs`, and all entropy is `crypto.getRandomValues` — so both
// `Cargo.lock`s stay `getrandom`-free.
//
// ⚠️ THE PRINTED CODE AND EVERY DERIVED SEED ARE SECRETS. This module returns
// them to the caller ONCE and never persists, logs, or transmits them. The only
// outbound bytes derived from a kit are PUBLIC keys and signatures. A caller
// MUST NOT put a code in localStorage, a URL, an analytics event or a log line.
//
// ⚠️ THE CENTRAL COMPROMISE, recorded as a compromise: the envelope is not on the
// paper and retrieving it requires authentication, which is what forces the paper
// to ALSO be an identity. A stolen kit is FULL ACCOUNT TAKEOVER (membership is
// flat, ADR 0040) — strictly more powerful than a stolen locked phone.
//
// ⚠️ THE KIT RECOVERS KEYS, NOT DATA. A vault whose sealed container was never
// pushed to the op-log is gone with or without a kit.
//
// STATUS: dev-gated, plain HTTP, pre-audit, UNAUDITED. The wrap is a CUSTOM
// KEM-then-AEAD, NOT RFC 9180 HPKE, and the system is not "post-quantum secure".

import {
  DeviceAuthError,
  createAccountInvite,
  enrollDevice,
  getAccount,
  revokeSelf,
  signedFetch,
} from "./device-auth.mjs";
import {
  PIN_ORIGIN_RECOVERY_KIT,
  TRUST_DERIVED,
  deleteKeyEnvelope,
  getKeyEnvelope,
  hybridPublicIdentity,
  publishHybridKey,
  safetyNumber,
  unwrapVaultKey,
  vaultKeyFingerprint,
  verifyRecipientForWrap,
  wrapVaultKey,
} from "./sharing.mjs";
import { putKeyEnvelope } from "./sharing.mjs";
import { grantVaultAccess } from "./device-auth.mjs";

/** Length of the raw recovery secret, in bytes. `sigil-core::RECOVERY_SEED_LEN`. */
export const RECOVERY_SEED_LEN = 32;

/** Characters in a printed (ungrouped) recovery code. */
export const RECOVERY_KIT_CHARS = 56;

/**
 * The device label a recovery kit enrolls under.
 *
 * DELIBERATELY VISIBLE, and identical to `cli/src/lib.rs::RECOVERY_DEVICE_LABEL`.
 * Hiding it would buy only protection against targeted denial (a hostile server
 * can deny everything anyway) and targeted substitution (already covered by
 * pinning), and it would cost every client the ability to render
 * "Recovery: not set up".
 */
export const RECOVERY_DEVICE_LABEL = "recovery-kit";

/** A recovery-kit failure that is not an HTTP failure. Carries no secret. */
export class RecoveryError extends Error {
  constructor(message) {
    super(message);
    this.name = "RecoveryError";
  }
}

/**
 * Turn an HTTP status into the THREE distinct things a user can act on. They
 * mean different things and a client must not guess between them.
 *
 * (The fourth message — "that is not a valid recovery code" — never reaches here:
 * it is decided OFFLINE by {@link verifyRecoveryKit} before any request.)
 */
export function explainRecoveryStatus(status) {
  switch (status) {
    case 401:
      return (
        "valid code, but this server has no such device — the kit may belong to a different " +
        "server, or it has been revoked. The server deliberately will not say which."
      );
    case 403:
      return (
        "authenticated, but not permitted: a kit may read only its OWN envelope index and only " +
        "the envelopes addressed to it."
      );
    case 402:
      // A kit GENERATION wraps and deposits, i.e. it is a gated write. A 402 is
      // BILLING and must never be read as "your code is wrong" or "not permitted".
      return (
        "payment required: this is a BILLING state, not a bad code and not a permission problem. " +
        "The server authenticated and authorized this device and THEN asked for payment. " +
        "RESTORING from an existing kit is never refused — only creating new material is."
      );
    case 404:
      return "nothing there: no envelope is waiting for this kit for that vault.";
    case 501:
      return "this server has the device model turned off, so the recovery routes are not serving.";
    default:
      return `unexpected HTTP ${status}`;
  }
}

/** The Web Crypto object, in Node or the browser. */
function webcrypto() {
  const c = globalThis.crypto;
  if (!c || typeof c.getRandomValues !== "function") {
    throw new RecoveryError("recovery: no Web Crypto available (need crypto.getRandomValues)");
  }
  return c;
}

/** std-base64 of raw bytes (Node + browser), for pin-store records. */
function bytesToBase64(bytes) {
  if (typeof globalThis.Buffer !== "undefined") {
    return globalThis.Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return globalThis.btoa(binary);
}

/** Raw bytes from std-base64 (Node + browser). */
function base64ToBytes(text) {
  if (typeof globalThis.Buffer !== "undefined") {
    return new Uint8Array(globalThis.Buffer.from(text, "base64"));
  }
  const binary = globalThis.atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

function checkId(what, value) {
  if (typeof value !== "string" || value.length === 0 || /[\s/]/.test(value)) {
    throw new RecoveryError(`recovery: ${what} must be a non-empty string with no "/" or whitespace`);
  }
  return value;
}

function requireSeed(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== RECOVERY_SEED_LEN) {
    throw new RecoveryError(`recovery: the recovery secret must be a ${RECOVERY_SEED_LEN}-byte Uint8Array`);
  }
  return seed;
}

/**
 * Render a code for the printed sheet: 7 groups of 8 joined by `-`.
 *
 * ONE renderer everywhere — it is `sigil-core`'s own, reached through the wasm,
 * so the grouping cannot drift between the CLI, the browser and the extension.
 */
export function formatRecoveryCode(wasm, code) {
  return wasm.recovery_format(code);
}

/**
 * VERIFY a printed recovery code OFFLINE — decode + checksum only, returning the
 * 32-byte secret.
 *
 * ⭐ Makes NO network request whatsoever. That is what lets a client say
 * "that is not a valid recovery code — check for a mistyped character" WITHOUT
 * having first leaked the code to a possibly-wrong server.
 *
 * Forgiving about presentation (hyphens, spaces, case, and Crockford's
 * `O`->`0`, `I`/`L`->`1` folding) and strict about content (`U` is rejected, not
 * folded; a bad checksum is a typo; a flipped version byte reads as a typo too,
 * because the checksum covers it).
 */
export function verifyRecoveryKit(wasm, code) {
  if (typeof code !== "string" || code.length === 0) {
    throw new RecoveryError("recovery: a recovery code is required");
  }
  try {
    return new Uint8Array(wasm.recovery_decode(code));
  } catch (err) {
    throw new RecoveryError(String(err?.message ?? err));
  }
}

/**
 * Derive a kit's full identity from its 32-byte recovery secret.
 *
 *   -> { ed25519Seed, publicKeyUnavailable?, hybrid: { x25519Secret, mlkemSeed } }
 *
 * Deterministic and RNG-free — the paper IS the key. The derivation is
 * `sigil-core`'s, reached through the wasm, so it is the same function the CLI
 * and the desktop app call.
 *
 * ⚠️ Everything returned is SECRET.
 */
export function deriveRecoveryIdentity(wasm, seed) {
  requireSeed(seed);
  return {
    ed25519Seed: new Uint8Array(wasm.recovery_derive_ed25519_seed(seed)),
    hybrid: {
      x25519Secret: new Uint8Array(wasm.recovery_derive_x25519_secret(seed)),
      mlkemSeed: new Uint8Array(wasm.recovery_derive_mlkem_seed(seed)),
    },
  };
}

/**
 * ASK THE SERVER which vaults hold a wrapped key for a device.
 *
 *   listRecoverableVaults(wasm, auth, deviceId = auth.deviceId)
 *     -> [{ vaultId, senderDeviceId, sizeBytes, createdAt }]
 *
 * SELF-ONLY server-side: asking about another device is 403. A restored kit has
 * no local state at all and therefore knows NO vault ids — this is the only way
 * it can find out what it is able to decrypt. It grants nothing new: the server
 * already holds every one of these ids, and the caller could already fetch each
 * envelope by naming its vault.
 *
 * ⭐ METADATA ONLY. The route never returns a blob.
 */
export async function listRecoverableVaults(wasm, auth, deviceId = null) {
  const target = checkId("device id", deviceId ?? auth?.deviceId);
  const res = await signedFetch(wasm, auth, "GET", `/v1/devices/${target}/keys`, "", null);
  if (res.status !== 200) {
    throw new DeviceAuthError(
      `listRecoverableVaults: ${explainRecoveryStatus(res.status)}`,
      res.status,
    );
  }
  const json = await res.json();
  return (json.vaults ?? []).map((v) => ({
    vaultId: v.vaultID ?? "",
    senderDeviceId: v.sender_device_id ?? "",
    sizeBytes: v.size_bytes ?? 0,
    createdAt: v.created_at ?? "",
  }));
}

/**
 * PIN a hybrid public key this client DERIVED itself, without ever asking the
 * server.
 *
 * ⭐ The one pin in the system established with no fetch, so there is nothing to
 * poison: from here on, covering a vault from THIS client wraps to the derived
 * identity and never calls `fetchHybridKey`. It does not weaken ADR 0038, whose
 * invariant is "every key OBTAINED FROM THE SERVER is pin-checked before a wrap"
 * — here none is obtained.
 *
 * Re-pinning the SAME key is a no-op; a DIFFERENT existing pin THROWS. This
 * function never silently replaces a pin. Mirrors `cli/src/lib.rs::pin_derived_key`.
 */
export async function pinDerivedKey(pins, deviceId, publicIdentity) {
  checkId("device id", deviceId);
  if (!pins || typeof pins !== "object" || typeof pins.pins !== "object") {
    throw new RecoveryError("recovery: a pin store is required (pinDerivedKey fails closed)");
  }
  const existing = pins.pins[deviceId];
  const number = await safetyNumber(deviceId, publicIdentity);
  const x25519B64 = bytesToBase64(publicIdentity.x25519PublicKey);
  const mlkemB64 = bytesToBase64(publicIdentity.mlkemEncapsKey);
  if (existing) {
    if (existing.x25519_public_key === x25519B64 && existing.mlkem_encaps_key === mlkemB64) {
      return pins;
    }
    throw new RecoveryError(
      `recovery: a DIFFERENT hybrid key is already pinned for ${deviceId} — refusing to replace ` +
        `it (pinned ${existing.safety_number}, derived ${number})`,
    );
  }
  pins.pins[deviceId] = {
    device_id: deviceId,
    x25519_public_key: x25519B64,
    mlkem_encaps_key: mlkemB64,
    safety_number: number,
    pinned_at: Math.floor(Date.now() / 1000),
    repins: 0,
    origin: PIN_ORIGIN_RECOVERY_KIT,
  };
  return pins;
}

/** The DERIVED pin for a device, if this client holds one. */
export function derivedPin(pins, deviceId) {
  const pin = pins?.pins?.[deviceId];
  if (!pin || pin.origin !== PIN_ORIGIN_RECOVERY_KIT) return null;
  // The pin store holds base64 text; wrapping needs raw bytes.
  return {
    x25519PublicKey: base64ToBytes(pin.x25519_public_key),
    mlkemEncapsKey: base64ToBytes(pin.mlkem_encaps_key),
  };
}

/**
 * GENERATE a recovery kit and cover a set of vaults with it.
 *
 *   generateRecoveryKit(wasm, auth, { vaultKeys, pins, inviteTtlSeconds? })
 *     -> { code, deviceId, accountId, baseUrl, safetyNumber, covered,
 *          verification, pins }
 *
 * `vaultKeys` is `[{ vaultId, vaultKey }]` — the caller supplies the keys it
 * already holds; this module never reads a keyring.
 *
 * The flow, in order (mirrors `cli/src/lib.rs::recovery_generate`):
 *
 *   1. 32 CSPRNG bytes -> the kit's Ed25519 + hybrid identity;
 *   2. mint a PINNED, single-use invite for the kit's Ed25519 public key
 *      (an intercepted invite is then useless to anyone else);
 *   3. redeem it AS THE KIT over the UNCHANGED enrollment challenge, under the
 *      visible label `recovery-kit`;
 *   4. publish the kit's hybrid PUBLIC key, signed as the kit (that route is
 *      self-only, so it must happen here);
 *   5. ⭐ PIN the DERIVED key with `origin: "recovery-kit"`;
 *   6. wrap each vault key to the kit and grant it `read`;
 *   7. ⭐ VERIFY BEFORE RETURNING — re-parse the code, re-derive from the PARSED
 *      value, authenticate as the kit, assert the account it resolves to is the
 *      generating device's own (this is the only thing that catches a server
 *      enrolling the kit into a DIFFERENT account), collect one envelope, unwrap
 *      it and compare fingerprints. Any failure revokes the partial kit and
 *      throws: a kit that was generated but never worked is impossible.
 *
 * ⚠️ `code` is THE SECRET. Render it once, let the user write it down, and drop
 * it. Do NOT persist it.
 */
export async function generateRecoveryKit(
  wasm,
  auth,
  { vaultKeys = [], pins = null, inviteTtlSeconds = null } = {},
) {
  if (!auth || !auth.baseUrl || !auth.deviceId || !auth.seed) {
    throw new RecoveryError("recovery: an enrolled, unlocked identity is required");
  }
  const pinStore = pins ?? auth.pins;
  if (!pinStore || typeof pinStore.pins !== "object") {
    throw new RecoveryError("recovery: a pin store is required (this client fails closed)");
  }

  // The generating device's own account, so step 7 has something to compare to.
  const mine = await getAccount(wasm, auth, auth.baseUrl);
  const myAccountId = mine.account_id ?? "";

  // 1) Entropy and derivation. The entropy is the CALLER's, always.
  const seed = webcrypto().getRandomValues(new Uint8Array(RECOVERY_SEED_LEN));
  const identity = deriveRecoveryIdentity(wasm, seed);
  const code = wasm.recovery_encode(seed);
  const publicIdentity = hybridPublicIdentity(wasm, {
    x25519Secret: identity.hybrid.x25519Secret,
    mlkemSeed: identity.hybrid.mlkemSeed,
  });
  const kitPublicKey = wasm.ed25519_public_key(identity.ed25519Seed);

  // 2) A PINNED, single-use invite for exactly this public key.
  const invite = await createAccountInvite(wasm, auth, auth.baseUrl, {
    ttlSeconds: inviteTtlSeconds ?? 0,
    inviteePublicKey: kitPublicKey,
  });

  // 3) Redeem it AS THE KIT, over the unchanged enrollment challenge.
  const enrolled = await enrollDevice(wasm, {
    baseUrl: auth.baseUrl,
    token: invite.invite,
    label: RECOVERY_DEVICE_LABEL,
    seed: identity.ed25519Seed,
  });
  const kitId = enrolled.deviceId;
  const kitAuth = {
    baseUrl: auth.baseUrl,
    deviceId: kitId,
    seed: identity.ed25519Seed,
    hybrid: { x25519Secret: identity.hybrid.x25519Secret, mlkemSeed: identity.hybrid.mlkemSeed },
  };

  // From here a failure leaves a live kit on the server, so every path out
  // revokes it and re-throws the ORIGINAL error.
  const abort = async (err) => {
    try {
      await revokeSelf(wasm, kitAuth, auth.baseUrl);
    } catch {
      /* best effort: the original failure is what matters */
    }
    throw err;
  };

  try {
    // 4) Publish the kit's hybrid PUBLIC key (self-only route).
    await publishHybridKey(wasm, kitAuth, {
      x25519Secret: identity.hybrid.x25519Secret,
      mlkemSeed: identity.hybrid.mlkemSeed,
    });

    // 5) ⭐ PIN THE DERIVED KEY. Nothing was fetched, so nothing could be
    //    substituted — and step 6 therefore never asks the server for a key.
    await pinDerivedKey(pinStore, kitId, publicIdentity);

    // 6) Cover each vault by wrapping OUR copy of the key to the DERIVED
    //    identity, then granting through the EXISTING grant route.
    const covered = [];
    for (const { vaultId, vaultKey } of vaultKeys) {
      checkId("vault id", vaultId);
      const envelope = wrapVaultKey(wasm, publicIdentity, vaultKey);
      await putKeyEnvelope(wasm, auth, vaultId, kitId, envelope);
      await grantVaultAccess(
        wasm,
        { deviceId: auth.deviceId, seed: auth.seed },
        auth.baseUrl,
        vaultId,
        kitId,
        "read",
      );
      covered.push({ vaultId, fingerprint: await vaultKeyFingerprint(vaultKey) });
    }

    // 7) ⭐ THE MANDATORY VERIFICATION ROUND-TRIP. Deliberately re-parses the
    //    printed form and re-derives from THAT, so a codec bug cannot hand a
    //    user a sheet that decodes to a different identity.
    const parsed = verifyRecoveryKit(wasm, code);
    const reborn = deriveRecoveryIdentity(wasm, parsed);
    const rebornAuth = {
      baseUrl: auth.baseUrl,
      deviceId: kitId,
      seed: reborn.ed25519Seed,
      hybrid: { x25519Secret: reborn.hybrid.x25519Secret, mlkemSeed: reborn.hybrid.mlkemSeed },
    };
    const kitAccount = await getAccount(wasm, rebornAuth, auth.baseUrl);
    const kitAccountId = kitAccount.account_id ?? "";
    if (kitAccountId !== myAccountId) {
      throw new RecoveryError(
        `the kit enrolled into account ${kitAccountId} but this device is in ${myAccountId}; ` +
          "the server did not put the kit in your account, so it is being revoked and NOT " +
          "returned",
      );
    }
    const indexed = await listRecoverableVaults(wasm, rebornAuth, kitId);
    let verification = {
      accountId: kitAccountId,
      indexedVaults: indexed.length,
      unwrappedVault: "",
      fingerprint: "",
    };
    if (vaultKeys.length > 0) {
      const first = vaultKeys[0];
      if (!indexed.some((v) => v.vaultId === first.vaultId)) {
        throw new RecoveryError(
          `the kit's own envelope index does not list ${first.vaultId}; it is being revoked and ` +
            "NOT returned",
        );
      }
      const envelope = await getKeyEnvelope(wasm, rebornAuth, first.vaultId, kitId);
      const recovered = unwrapVaultKey(wasm, rebornAuth.hybrid, envelope);
      const fingerprint = await vaultKeyFingerprint(recovered);
      if (fingerprint !== (await vaultKeyFingerprint(first.vaultKey))) {
        throw new RecoveryError(
          `the kit unwrapped a DIFFERENT key for ${first.vaultId}; it is being revoked and NOT ` +
            "returned",
        );
      }
      verification = {
        accountId: kitAccountId,
        indexedVaults: indexed.length,
        unwrappedVault: first.vaultId,
        fingerprint,
      };
    }

    return {
      // ⚠️ THE SECRET. Render once; never persist.
      code,
      formatted: wasm.recovery_format(code),
      deviceId: kitId,
      accountId: myAccountId,
      baseUrl: auth.baseUrl,
      safetyNumber: await safetyNumber(kitId, publicIdentity),
      covered,
      verification,
      // The caller re-seals this into the device-identity container so the
      // derived pin survives a reload.
      pins: pinStore,
    };
  } catch (err) {
    return abort(err);
  }
}

/**
 * COVER one more vault with an existing kit.
 *
 * TWO PATHS, and the difference is the whole point:
 *
 *  * where this client holds the DERIVED pin (`origin: "recovery-kit"`), the
 *    derived identity is used directly and NOTHING is fetched — no substitution
 *    window exists at all;
 *  * from any OTHER client the key comes from the server, which on a first sight
 *    would be plain trust-on-first-use. This design is STRICTER than ADR 0038
 *    here because the out-of-band channel is guaranteed present — the safety
 *    number is printed on the sheet in the user's own hand. `expectedSafetyNumber`
 *    is therefore REQUIRED on that path, and a mismatch is refused. A warning is
 *    not good enough when the verification channel is in the user's pocket.
 */
export async function coverVault(
  wasm,
  auth,
  { kitDeviceId, vaultId, vaultKey, pins = null, expectedSafetyNumber = null },
) {
  checkId("kit device id", kitDeviceId);
  checkId("vault id", vaultId);
  const pinStore = pins ?? auth?.pins;
  if (!pinStore || typeof pinStore.pins !== "object") {
    throw new RecoveryError("recovery: a pin store is required (this client fails closed)");
  }

  // ⭐ THE TRUST DECISION COMES FIRST, through the SHARED WRAP GATE. This used
  // to be bespoke logic living here, which is exactly the defect the fix round
  // closed: `shareVault` and `rotateVaultKey` reached the same outcome without
  // it. `knownRecoveryKit: true` is the caller ASSERTING what this command is —
  // so the gate does not have to discover it, and a server that hides the
  // recovery-kit label cannot evade the check on this path.
  const verified = await verifyRecipientForWrap(wasm, auth, kitDeviceId, {
    pins: pinStore,
    expectedSafetyNumber,
    knownRecoveryKit: true,
  });
  const derived = verified.trust === TRUST_DERIVED;
  const identity = verified.identity;

  const envelope = wrapVaultKey(wasm, identity, vaultKey);
  await putKeyEnvelope(wasm, auth, vaultId, kitDeviceId, envelope);
  await grantVaultAccess(
    wasm,
    { deviceId: auth.deviceId, seed: auth.seed },
    auth.baseUrl,
    vaultId,
    kitDeviceId,
    "read",
  );
  return {
    vaultId,
    kitDeviceId,
    derived: Boolean(derived),
    fingerprint: await vaultKeyFingerprint(vaultKey),
    envelopeBytes: envelope.length,
    pins: pinStore,
  };
}

/**
 * RESTORE from a printed recovery kit, on a client with NO local state.
 *
 *   restoreFromKit(wasm, { baseUrl, code, deviceId }) ->
 *     { deviceId, accountId, vaults: [{ vaultId, vaultKey, container, fingerprint }],
 *       skipped: [{ vaultId, reason }], identity }
 *
 * The code is decoded and checksummed **OFFLINE, before any network I/O**, so a
 * mistyped code never reaches a server.
 *
 * `deviceId` is REQUIRED and is printed on the sheet. It is NOT a secret — the
 * server assigns it, nothing about the printed secret determines it, and there is
 * deliberately no route that looks a device up by public key.
 *
 * ⭐ NOTHING IS PERSISTED HERE. The caller decides what to keep, and the browser
 * clients keep everything inside the SEALED device-identity container. In
 * particular, `identity` (the kit's own derived secrets) is returned so a caller
 * can deliberately "adopt" the kit — which makes that client a second copy of the
 * paper and must be presented that way.
 */
export async function restoreFromKit(wasm, { baseUrl, code, deviceId }) {
  if (!baseUrl) throw new RecoveryError("recovery: baseUrl is required");
  // ⭐ OFFLINE FIRST. Zero network I/O happens before this succeeds.
  const seed = verifyRecoveryKit(wasm, code);
  checkId("device id", deviceId);
  const identity = deriveRecoveryIdentity(wasm, seed);
  const auth = {
    baseUrl,
    deviceId,
    seed: identity.ed25519Seed,
    hybrid: { x25519Secret: identity.hybrid.x25519Secret, mlkemSeed: identity.hybrid.mlkemSeed },
  };

  const account = await getAccount(wasm, auth, baseUrl);
  const indexed = await listRecoverableVaults(wasm, auth, deviceId);
  if (indexed.length === 0) {
    throw new RecoveryError(
      "valid code and device, but there is nothing to recover: this kit holds no vault key on " +
        "this server. It was enrolled but never covered a vault, or a rotation dropped it.",
    );
  }

  const vaults = [];
  const skipped = [];
  for (const entry of indexed) {
    let envelope;
    try {
      envelope = await getKeyEnvelope(wasm, auth, entry.vaultId, deviceId);
    } catch (err) {
      skipped.push({ vaultId: entry.vaultId, reason: String(err?.message ?? err) });
      continue;
    }
    // Rejects any recovered plaintext that is not exactly 32 bytes.
    const vaultKey = unwrapVaultKey(wasm, auth.hybrid, envelope);
    vaults.push({
      vaultId: entry.vaultId,
      vaultKey,
      fingerprint: await vaultKeyFingerprint(vaultKey),
    });
  }

  return { deviceId, accountId: account.account_id ?? "", vaults, skipped, identity };
}

/**
 * REVOKE a recovery kit: refuse it at the door and take back its envelopes.
 *
 * It deliberately does NOT auto-rotate. Rotation re-seals user data and must stay
 * an explicit act — and revocation cannot un-learn a vault key the kit already
 * unwrapped, so the caller is told to rotate each vault.
 *
 * Envelopes are removed FIRST, while the caller's own access is certainly intact.
 */
export async function revokeRecoveryKit(wasm, auth, { kitDeviceId, vaultIds = [] }) {
  checkId("kit device id", kitDeviceId);
  const removed = [];
  const alreadyClear = [];
  for (const vaultId of vaultIds) {
    checkId("vault id", vaultId);
    if (await deleteKeyEnvelope(wasm, auth, vaultId, kitDeviceId)) removed.push(vaultId);
    else alreadyClear.push(vaultId);
  }
  const res = await signedFetch(
    wasm,
    auth,
    "POST",
    `/v1/devices/${kitDeviceId}/revoke`,
    "",
    new Uint8Array(0),
    { "Content-Type": "application/json" },
  );
  if (res.status !== 200) {
    throw new DeviceAuthError(
      `revokeRecoveryKit: ${explainRecoveryStatus(res.status)}`,
      res.status,
    );
  }
  return {
    kitDeviceId,
    removed,
    alreadyClear,
    // Rotation is the caller's explicit next step; this module will not do it.
    rotateReminder:
      "revocation stops the kit talking to the server — it CANNOT un-learn a vault key the kit " +
      "already unwrapped. Rotate each vault (dropping this kit) so future content is unreadable " +
      "to it.",
  };
}
