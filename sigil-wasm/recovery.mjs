// sigil-wasm/recovery.mjs — THE RECOVERY KIT, for JavaScript (Phase 54).
//
// Framework-free, dependency-free ESM. Runs in Node and the browser.
//
// THE MODEL, IN ONE SENTENCE. A recovery kit is an ORDINARY MEMBER DEVICE whose
// Ed25519 and hybrid private keys are derived from 32 bytes of client CSPRNG that
// are printed on paper, never transmitted, never stored on any device, and never
// derivable from anything the server holds. `sigild` gains NO concept of
// "recovery": it sees one more device row, one more hybrid PUBLIC key and one
// more opaque ~1.3 KiB `SIGILhyb` envelope per covered vault — byte-for-byte
// the shapes it already relays for device-to-device sharing (ADR 0035).
// ⚠️ NOT the flat 1226 bytes this comment used to claim: from Phase 60 a
// vault-key envelope carries its context AAD, so its length depends on the
// vault id and both device ids (see `wrappedVaultKeyLen` in sharing.mjs).
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
  listKeyEnvelopes,
  hybridPublicIdentity,
  newPinStore,
  publishHybridKey,
  safetyNumber,
  senderFromAuth,
  unwrapVaultKey,
  vaultKeyFingerprint,
  verifiedSenderFromLocal,
  verifyRecipientForWrap,
  verifySenderForUnwrap,
  wrapVaultKey,
  UnknownSenderError,
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
 *
 * ⚠️ THE RESULT CARRIES A `truncated` FLAG AND CALLERS MUST HONOUR IT. The route
 * caps one page at `maxRecipientIndexRows` (500 in sigild) and reports the
 * overflow as `has_more: true`; there is NO CURSOR, so the rest is unreachable.
 * Every client ignored the flag, which meant a kit covering more than 500 vaults
 * would have recovered the first 500 and REPORTED SUCCESS — a partial recovery
 * presented as a complete one, which is the worst possible failure for a
 * mechanism whose entire job is "did I get everything back?".
 *
 * ⚠️ **THIS ROUTE IS DENIABLE BY A THIRD PARTY, and that is the other half of
 * why `truncated` exists.** Any account may deposit an envelope addressed to
 * this device and grant it `read` on a vault it owns, so a party that knows this
 * device's id can push genuine rows off the single uncursored page. It cannot
 * read anything and it cannot forge an envelope — but it can make discovery
 * return `has_more: true` and hide what matters. Measured against a real sigild:
 * 520 planted vaults in 0.6 s pushed the one genuine row out. Recovery therefore
 * must not DEPEND on this route: `restoreFromKit` takes vault ids straight from
 * the printed sheet, which no later act can touch. Mirrors the Rust twin
 * `cli/src/lib.rs::list_recoverable_vaults`; ADR 0052.
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
  const vaults = (json.vaults ?? []).map((v) => ({
    vaultId: v.vaultID ?? "",
    senderDeviceId: v.sender_device_id ?? "",
    sizeBytes: v.size_bytes ?? 0,
    createdAt: v.created_at ?? "",
  }));
  // Additive and non-enumerable so the array still behaves exactly as before for
  // every existing caller (length, iteration, JSON) — but a caller that CARES can
  // see it, and `restoreFromKit` below refuses to claim completeness without it.
  Object.defineProperty(vaults, "truncated", {
    value: json.has_more === true,
    enumerable: false,
  });
  return vaults;
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
    // ⭐ AUTHENTICATED as the GENERATING device (Phase 60): the kit's envelopes
    // carry a sender, so a restore can check who deposited them. Grant BEFORE
    // deposit, matching shareVault and the CLI.
    const from = senderFromAuth(auth);
    const covered = [];
    for (const { vaultId, vaultKey } of vaultKeys) {
      checkId("vault id", vaultId);
      const envelope = wrapVaultKey(
        wasm,
        from,
        publicIdentity,
        { vaultId, recipientDeviceId: kitId, senderDeviceId: from.deviceId },
        vaultKey,
      );
      await grantVaultAccess(
        wasm,
        { deviceId: auth.deviceId, seed: auth.seed },
        auth.baseUrl,
        vaultId,
        kitId,
        "read",
      );
      await putKeyEnvelope(wasm, auth, vaultId, kitId, envelope);
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
    // ⭐ GENERATION IS THE ONE MOMENT THE USER CAN STILL ACT — re-print, reduce
    // coverage, copy the `covers` line carefully. By restore time the paper is
    // fixed. So a kit whose index is ALREADY truncated must say so here, on
    // every client, not on one of four.
    let verification = {
      accountId: kitAccountId,
      indexedVaults: indexed.length,
      indexTruncated: indexed.truncated === true,
      unwrappedVault: "",
      fingerprint: "",
    };
    if (vaultKeys.length > 0) {
      const first = vaultKeys[0];
      // ⚠️ A TRUNCATED index is NOT grounds to refuse to print. The sheet carries
      // the covered vault ids, so a restore does not need this route — and
      // destroying a working kit because a stranger crowded a listing would hand
      // an availability attack the ability to stop kits being made at all. It is
      // reported instead, and the envelope is still unwrapped end to end below.
      // Mirrors `cli/src/lib.rs::recovery_verify_kit`; without this the SAME
      // flood, performed BEFORE generate, lets any current or former
      // collaborator stop this client ever printing a kit — a denial of the last
      // line of defence (ADR 0040 limitation 1), strictly worse than the
      // truncation it would be reacting to.
      if (!indexed.truncated && !indexed.some((v) => v.vaultId === first.vaultId)) {
        throw new RecoveryError(
          `the kit's own envelope index does not list ${first.vaultId}; it is being revoked and ` +
            "NOT returned",
        );
      }
      const envelope = await getKeyEnvelope(wasm, rebornAuth, first.vaultId, kitId);
      // ⭐ The SENDER here is THIS device, whose secret half we hold — so the
      // gate is satisfied with NO fetch and nothing a server could substitute.
      const recovered = unwrapVaultKey(
        wasm,
        rebornAuth.hybrid,
        await verifiedSenderFromLocal(wasm, from),
        { vaultId: first.vaultId, recipientDeviceId: kitId, senderDeviceId: from.deviceId },
        envelope,
      );
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
        indexTruncated: indexed.truncated === true,
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

  // ⭐ AUTHENTICATED as THIS device, BOUND to (vault, kit, this device).
  const from = senderFromAuth(auth);
  const envelope = wrapVaultKey(
    wasm,
    from,
    identity,
    { vaultId, recipientDeviceId: kitDeviceId, senderDeviceId: from.deviceId },
    vaultKey,
  );
  // AUTHORIZE FIRST, then deposit (mirrors shareVault and the CLI).
  await grantVaultAccess(
    wasm,
    { deviceId: auth.deviceId, seed: auth.seed },
    auth.baseUrl,
    vaultId,
    kitDeviceId,
    "read",
  );
  await putKeyEnvelope(wasm, auth, vaultId, kitDeviceId, envelope);
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
 * Work out WHICH DEVICE deposited the envelope addressed to `recipient` for
 * `vaultId`, WITHOUT going through the per-device index.
 *
 * ⭐ The discovery path that cannot be denied: `GET /v1/vaults/{id}/keys` is
 * addressed BY VAULT ID, so it returns this vault's recipients however many
 * unrelated vaults exist. Mirrors `envelope_sender_for` in `cli/src/lib.rs`.
 *
 * Requires WRITE, which for a kit is satisfied by its ACCOUNT owning the vault
 * (ADR 0040). A cross-account share is a per-DEVICE read grant, so this
 * legitimately 403s there and the caller falls back to "unknown sender".
 */
async function envelopeSenderFor(wasm, auth, vaultId, recipient) {
  try {
    const holders = await listKeyEnvelopes(wasm, auth, vaultId);
    const row = holders.find((h) => h.deviceId === recipient);
    return row && row.senderDeviceId ? row.senderDeviceId : null;
  } catch {
    return null;
  }
}

/**
 * RESTORE from a printed recovery kit, on a client with NO local state.
 *
 *   restoreFromKit(wasm, { baseUrl, code, deviceId, vaultIds }) ->
 *     { deviceId, accountId, vaults: [{ vaultId, vaultKey, container, fingerprint }],
 *       skipped: [{ vaultId, reason }], identity, indexTruncated, fromSheet }
 *
 * ⭐ `vaultIds` COMES OFF THE PRINTED SHEET (its `covers` line), and it is what
 * makes a flooded index survivable rather than fatal. Supplying them makes this
 * ask each VAULT which device deposited its envelope instead of asking the
 * server what is waiting for this kit — and the per-device index is a single
 * page capped at 500 rows with NO CURSOR that any other account can push rows
 * onto (deposit an opaque envelope addressed to a device id it knows, then grant
 * that device read on a vault it claimed itself). With no ids and a truncated
 * index this REFUSES, because it cannot know what it is missing.
 *
 * ⚠️ A vault covered AFTER the sheet was printed is on no sheet, and the index
 * is the only way to find it. `indexTruncated` says when that gap is live, and a
 * UI must not round it up to "everything".
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
export async function restoreFromKit(wasm, { baseUrl, code, deviceId, vaultIds = [] }) {
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

  const sheetVaults = (Array.isArray(vaultIds) ? vaultIds : [])
    .map((v) => String(v ?? "").trim())
    .filter(Boolean);

  const account = await getAccount(wasm, auth, baseUrl);

  // ⭐ THE SHEET PATH MUST NOT BE GATED BEHIND THE ROUTE IT EXISTS TO BYPASS.
  // `vaultIds` exists precisely because the per-device index is deniable, so a
  // restore that names its vaults has to survive that route being UNAVAILABLE —
  // not merely crowded. A server that 500s or hangs on this ONE endpoint would
  // otherwise kill the sheet path too, which touches it for nothing but a sender
  // hint and the truncation flag. With sheet ids an index failure DEGRADES to
  // "empty, and completeness unknown"; with none it still throws, because there
  // is nothing left to fall back to. It degrades LOUDLY: `indexError` is
  // reported, never swallowed. Mirrors `cli/src/lib.rs::recovery_restore`.
  let indexError = null;
  let indexed;
  try {
    indexed = await listRecoverableVaults(wasm, auth, deviceId);
  } catch (err) {
    if (sheetVaults.length === 0) throw err;
    indexError = String(err?.message ?? err);
    indexed = [];
    // An index that never answered is the strongest possible statement that
    // this client cannot enumerate its own coverage.
    Object.defineProperty(indexed, "truncated", { value: true, enumerable: false });
  }
  // ⛔ REFUSE RATHER THAN UNDER-REPORT. The index route has a hard page cap and no
  // cursor, so a truncated answer means this client CANNOT know what it is
  // missing. Restoring the visible prefix and calling it a recovery would tell a
  // customer their vaults are back while some are silently absent — so this fails
  // loudly instead, and names the way out: the printed sheet already carries the
  // covered vault ids, and nothing that happened after it was printed can change
  // what it says.
  if (indexed.truncated && sheetVaults.length === 0) {
    throw new RecoveryError(
      "this server lists MORE vaults for this kit than it will return in one page, and that " +
        "route has no cursor — so this client cannot see all of them and REFUSES to report a " +
        "partial recovery as a complete one. Nothing was restored. Restore by naming the vaults " +
        "printed on the sheet's `covers` line: that path asks each vault directly and cannot be " +
        "crowded out. A vault covered AFTER the sheet was printed is not on it and stays " +
        "invisible until the listing clears.",
    );
  }

  // ⭐ WHO IS ALLOWED TO INTRODUCE A VAULT TO THIS RESTORE.
  //
  // An authenticated envelope (ADR 0048) proves WHO deposited it. It proves
  // NOTHING about whether that sender is trusted — and every input to the wrap
  // is public: any enrolled device on ANY account may fetch this kit's published
  // hybrid key, and the AAD is (purpose, vault id, recipient id, sender id). So
  // a stranger can mint a GENUINE, correctly-authenticated envelope addressed to
  // this kit for a vault they own, grant the kit read, and push a container
  // sealed under a key of their choosing. This runs on a machine with an EMPTY
  // pin store, so `verifySenderForUnwrap` returns first-sight TOFU, PINS the
  // stranger's key, unwraps, and hands their vault back as a RECOVERED one — to
  // the one person who by definition has nothing left to check it against.
  //
  //   * a vault NAMED ON THE SHEET is vouched for BY THE USER and is processed
  //     whatever the sender says — the sheet is the channel nothing on the
  //     network can touch, and that is the entire point of it;
  //   * a vault the INDEX alone introduced is processed only if its sender is a
  //     device in this kit's OWN ACCOUNT (active or revoked — the covering
  //     device may since have been revoked, and its envelopes stay valid).
  //
  // ⭐ Decided from the index row alone, BEFORE any network call for that row,
  // so a flood costs nothing: no fetch, no unwrap, and above all no PIN.
  //
  // ⚠️ HONEST LIMIT: this defends against a THIRD PARTY, not against the SERVER.
  // The account device list is served by the same server, so a hostile one could
  // omit a genuine sender and cause a legitimate index-only row to be ignored.
  // That is reported, not silent — and a server that wanted to deny recovery can
  // already withhold the envelope outright.
  const accountDevices = new Set(
    (account?.devices ?? []).map((d) => d?.device_id).filter(Boolean),
  );

  // What to try, in a stable order. Sheet ids first: they are the ones the user
  // can vouch for. Each carries whatever the index managed to say about it.
  const targets = [];
  const fromSheet = [];
  const seen = new Set();
  let ignoredUntrusted = 0;
  for (const vaultId of sheetVaults) {
    if (seen.has(vaultId)) continue;
    seen.add(vaultId);
    const row = indexed.find((v) => v.vaultId === vaultId);
    const senderDeviceId = row && row.senderDeviceId ? row.senderDeviceId : null;
    if (!senderDeviceId) fromSheet.push(vaultId);
    targets.push({ vaultId, senderDeviceId });
  }
  for (const entry of indexed) {
    if (seen.has(entry.vaultId)) continue;
    seen.add(entry.vaultId);
    // Index-only: the sender must be one of OUR devices. An unnamed sender names
    // no device in this account and so fails this test too — there is nothing to
    // authenticate such an envelope against in any case.
    if (!accountDevices.has(entry.senderDeviceId)) {
      ignoredUntrusted += 1;
      continue;
    }
    targets.push({
      vaultId: entry.vaultId,
      senderDeviceId: entry.senderDeviceId || null,
    });
  }

  if (targets.length === 0) {
    throw new RecoveryError(
      "valid code and device, but there is nothing to recover: this kit holds no vault key on " +
        "this server. It was enrolled but never covered a vault, or a rotation dropped it.",
    );
  }

  // ⭐ PHASE 60. A restore runs on a machine with NO local state, so it starts
  // with an EMPTY pin store — every sender is first sight, which is honest TOFU
  // and exactly what ADR 0038 accepts. What it will NOT do is unwrap
  // anonymously: a vault whose depositing device the index does not name is
  // SKIPPED with a reason rather than opened from "whoever". A forged envelope
  // therefore fails at the AEAD instead of installing an attacker's key.
  const pins = newPinStore();
  const vaults = [];
  const skipped = [];
  for (const entry of targets) {
    // TWO SOURCES for the sender, and the second is the one that survives a
    // flood: the per-device index when it listed this vault, otherwise the
    // VAULT's own recipient list, addressed by an id taken off the sheet.
    const senderDeviceId =
      entry.senderDeviceId ?? (await envelopeSenderFor(wasm, auth, entry.vaultId, deviceId));
    if (!senderDeviceId) {
      skipped.push({
        vaultId: entry.vaultId,
        reason: new UnknownSenderError(
          `the server did not name the device that deposited the key for ` +
            `vault ${JSON.stringify(entry.vaultId)}`,
        ).message,
      });
      continue;
    }
    let envelope;
    let sender;
    try {
      sender = await verifySenderForUnwrap(wasm, auth, senderDeviceId, { pins });
      envelope = await getKeyEnvelope(wasm, auth, entry.vaultId, deviceId);
    } catch (err) {
      skipped.push({ vaultId: entry.vaultId, reason: String(err?.message ?? err) });
      continue;
    }
    let vaultKey;
    try {
      // AUTHENTICATED + CONTEXT-BOUND, and rejects any recovered plaintext that
      // is not exactly 32 bytes.
      vaultKey = unwrapVaultKey(
        wasm,
        auth.hybrid,
        sender,
        {
          vaultId: entry.vaultId,
          recipientDeviceId: deviceId,
          senderDeviceId,
        },
        envelope,
      );
    } catch (err) {
      skipped.push({ vaultId: entry.vaultId, reason: String(err?.message ?? err) });
      continue;
    }
    vaults.push({
      vaultId: entry.vaultId,
      vaultKey,
      senderDeviceId,
      senderTrust: sender.trust,
      senderSafetyNumber: sender.safetyNumber,
      fingerprint: await vaultKeyFingerprint(vaultKey),
    });
  }

  return {
    deviceId,
    accountId: account.account_id ?? "",
    vaults,
    skipped,
    identity,
    pins,
    // ⛔ NEVER PRESENT A TRUNCATED RESTORE AS COMPLETE. Reaching here with this
    // true means vault ids WERE supplied, so what came back is what the caller
    // named plus one page — a floor, not a total.
    indexTruncated: indexed.truncated === true,
    // Vault ids the caller supplied that the index did not list, recovered by
    // asking each vault directly.
    fromSheet,
    // ⚠️ The index route could not be read AT ALL and this restore carried on
    // with only the named vaults. Set only when vault ids WERE supplied. A
    // caller MUST surface it: "listed nothing" and "never answered" are
    // different facts, and the second is how a vault covered after the sheet was
    // printed goes missing.
    indexError,
    // How many listed rows were deposited by devices OUTSIDE this account and
    // were ignored without being fetched, unwrapped or pinned. A COUNT, never
    // one entry per row — a flood is bounded noise, and reporting it row by row
    // would bury the real result, which is exactly what the flood is for.
    ignoredUntrusted,
  };
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
