// passkey.mjs — PASSKEY-PROTECTED LOCAL CONTAINERS (ADR 0046).
//
// Framework-free, dependency-free ESM. Runs in a browser only: it needs
// `navigator.credentials` (WebAuthn) and `crypto.subtle`.
//
// ⭐ WHAT THIS IS FOR, IN ONE SENTENCE. Every browser client seals its two
// `SIGILcli` containers (the TOTP vault, the device identity) with Argon2id under
// a HUMAN PASSWORD, and that password is the only factor standing between an
// attacker who copied `localStorage` and everything inside. This module adds a
// SECOND factor to the AT-REST seal: a WebAuthn credential's PRF output is mixed
// into the sealing secret, so a stolen copy of the storage is useless without the
// authenticator too.
//
// ⛔ WHAT THIS IS NOT.
//   * It is NOT request authentication. The wire protocol is untouched: every
//     signed request is still a classical Ed25519 contract-v3 signature, and
//     `sigild` knows nothing about any of this — no route, no header, no
//     canonical message, no column. A hostile server cannot disable, weaken,
//     detect or even observe it.
//   * It defends STORAGE, never EXECUTION. Anything running in this origin while
//     the vault is unlocked (XSS, a malicious extension) reads the plaintext
//     vault, the Ed25519 seed, the hybrid secret, every vault key, the password,
//     the PRF output and the CMK — exactly as before.
//   * It is NOT retroactive. Only containers re-sealed after protection is
//     enabled are protected; earlier copies, backups and forensic images stay
//     password-only forever.
//
// ⭐ THE CONSTRUCTION (and both choices are load-bearing):
//
//   CMK  = HKDF-SHA256(salt = "sigil-recovery-kit-v1",
//                      ikm  = kit_seed(32),                     // ADR 0042's printed sheet
//                      info = "sigil-recovery-kit-v1/container-master-key",
//                      L    = 32)
//
//   PRF_SALT = SHA-256("sigil-passkey-unlock-v1")                // 32 B constant, NOT secret
//   R        = prf.results.first from a WebAuthn assertion       // 32 B
//   hwslot   = seal_to_container(R ‖ utf8(password), {cmk, …})   // ⭐ PRF BYTES FIRST
//
//   1. `R ‖ utf8(password)` is fed STRAIGHT to the container's own Argon2id —
//      there is deliberately no cheap HKDF over the password. An attacker who can
//      drive the authenticator (an unlocked device, a coerced UV prompt) recovers
//      `R` and then still faces Argon2id over the password. Putting the password
//      through a cheap KDF instead would hand that attacker an unstretched guess.
//   2. PRF bytes FIRST. A fixed-length 32-byte prefix makes the parse
//      unambiguous; password-first would let ("abc", P) and ("abcX", P′) collide.
//
// ⭐ AND, NEVER OR. While protection is on there is NO password-only slot. The
// two ways in are (password AND passkey) and (the printed ADR 0042 sheet). An OR
// design — either factor opens the container — is theatre: an offline attacker
// simply attacks the weaker branch and the passkey buys exactly zero.
//
// ⭐ NO LOCKOUT. Every way a passkey can become unavailable — a lost laptop, a
// cleared profile, a revoked platform credential, a browser that drops PRF, a
// cancelled ceremony, PRF returning different bytes — lands on the recovery
// sheet, which derives the CMK OFFLINE with no server and no network. That is why
// enabling protection REFUSES unless a kit already exists and the code is typed
// back first.
//
// This module does NO cryptography of its own: SHA-256 and HKDF come from
// `crypto.subtle`, and the AEAD + Argon2id happen inside the wasm.
//
// Pre-audit / UNAUDITED / dev-gated, like everything around it.

import { base64ToBytes, bytesToBase64 } from "./totp-vault.mjs";

/** The PRF salt's domain string. Hashed, never used raw. NOT a secret. */
export const PASSKEY_PRF_DOMAIN = "sigil-passkey-unlock-v1";

/** Schema version of the sealed hardware slot's plaintext JSON. */
export const HW_SLOT_VERSION = 1;

/** Expected length of a WebAuthn PRF output (bytes). */
export const PRF_OUTPUT_LEN = 32;

/** Container master key length (bytes). Same shape as a vault key. */
export const CONTAINER_MASTER_KEY_LEN = 32;

/**
 * How long a ceremony may stay outstanding, in milliseconds.
 *
 * ⚠️ NOT COSMETIC. WebAuthn's `timeout` is the only thing that bounds a ceremony
 * with NO usable authenticator: verified live, `navigator.credentials.get()` in
 * a browser profile whose passkeys are gone NEVER SETTLES on its own. Without
 * this the unlock screen would sit on "Unlocking…" forever instead of telling
 * the user their passkey is unavailable and pointing at the recovery sheet — i.e.
 * the exact no-lockout guarantee would be invisible to the person who needs it.
 */
export const PASSKEY_TIMEOUT_MS = 60_000;

/**
 * HKDF salt for the CMK. ⭐ Deliberately the SAME salt ADR 0042 already extracts
 * the kit's three device secrets under — one `HKDF-Extract` domain for the sheet,
 * with the INFO label doing the separating. Mirrors
 * `libsigil/core/src/recovery.rs`'s salt (no trailing newline).
 */
export const CMK_HKDF_SALT = "sigil-recovery-kit-v1";

/** HKDF info label for the CMK. Distinct from every ADR 0042 label. */
export const CMK_HKDF_INFO = "sigil-recovery-kit-v1/container-master-key";

const TEXT_ENCODER = new TextEncoder();

/** A passkey ceremony or PRF failure. `code` is a stable, testable discriminator. */
export class PasskeyError extends Error {
  constructor(message, code = "passkey_error") {
    super(message);
    this.name = "PasskeyError";
    this.code = code;
  }
}

/**
 * The authenticator or the browser cannot do WebAuthn PRF at all.
 *
 * ⚠️ This is "unsupported", never "retry". A PRF that is missing, short, or
 * NON-DETERMINISTIC is indistinguishable from a dead passkey, and enabling
 * protection on top of one would build a lockout.
 */
export class PrfUnavailableError extends PasskeyError {
  constructor(message, code = "prf_unavailable") {
    super(message, code);
    this.name = "PrfUnavailableError";
  }
}

function creds() {
  const c = globalThis.navigator?.credentials;
  if (!c || typeof c.create !== "function" || typeof c.get !== "function") {
    throw new PasskeyError("passkey: this browser has no WebAuthn support", "no_webauthn");
  }
  return c;
}

function subtle() {
  const s = globalThis.crypto?.subtle;
  if (!s) {
    throw new PasskeyError(
      "passkey: crypto.subtle is unavailable (a secure context is required)",
      "no_subtle",
    );
  }
  return s;
}

/**
 * Can this page even attempt a passkey ceremony?
 *
 *   -> { available: boolean, reason: string }
 *
 * ⚠️ Capability is only ever reported from a probe that JUST RAN — see
 * `probePrf`. This function answers the cheaper question "is the API here at
 * all", and a `true` from it is NOT a claim that PRF works.
 */
export function passkeySupport() {
  if (!globalThis.isSecureContext) {
    return {
      available: false,
      reason:
        "this page is not a secure context, so the browser will not run a passkey ceremony " +
        "(use https, or http://localhost)",
    };
  }
  const c = globalThis.navigator?.credentials;
  if (!c || typeof c.create !== "function" || typeof c.get !== "function") {
    return { available: false, reason: "this browser has no WebAuthn support" };
  }
  if (!globalThis.crypto?.subtle) {
    return { available: false, reason: "crypto.subtle is unavailable in this context" };
  }
  return { available: true, reason: "" };
}

/**
 * `SHA-256("sigil-passkey-unlock-v1")` — the 32-byte PRF evaluation point.
 *
 * A CONSTANT, and deliberately not a secret: it is an input to a keyed function
 * whose key never leaves the authenticator. Making it per-profile would buy
 * per-profile CMK separation only at the price of a NON-container persisted
 * artifact, which ADR 0036 forbids.
 */
export async function prfSalt() {
  const digest = await subtle().digest("SHA-256", TEXT_ENCODER.encode(PASSKEY_PRF_DOMAIN));
  return new Uint8Array(digest);
}

/** Flags byte of a WebAuthn authenticatorData blob (offset 32). */
function authDataFlags(buffer) {
  const bytes = new Uint8Array(buffer ?? new ArrayBuffer(0));
  return bytes.length > 32 ? bytes[32] : 0;
}

/**
 * Read the BE (backup eligible) and BS (backup state) flags of an authenticator
 * data blob.
 *
 * ⭐ THIS IS WHAT KEEPS THE STATUS LINE HONEST. A backup-eligible credential
 * syncs to a cloud keychain, so the factor is only as strong as that provider
 * account — a NEW third-party custodian. Claiming "this device only" for such a
 * credential would be false, so the claim is derived from the flags read at the
 * LAST ceremony rather than from what happened to be true when protection was
 * switched on.
 */
export function backupFlags(authenticatorData) {
  const flags = authDataFlags(authenticatorData);
  return {
    userPresent: (flags & 0x01) !== 0,
    userVerified: (flags & 0x04) !== 0,
    backupEligible: (flags & 0x08) !== 0,
    backupState: (flags & 0x10) !== 0,
  };
}

/**
 * The one sentence the UI is allowed to say about scope, derived from the flags
 * of the ceremony that just happened.
 *
 * ⚠️ Capped by MARKETING-CLAIMS.md: no "hardware-backed", no "phishing-resistant",
 * no "2FA", no "unbreakable". "Passkey" is not "hardware".
 */
export function describeProtectionScope({ backupEligible, attachment } = {}) {
  if (backupEligible) {
    return (
      "protected by a passkey in your password manager or platform account — that provider can " +
      "sync it to your other devices, so the protection is as strong as that account"
    );
  }
  if (attachment === "platform") {
    return (
      "protected by a passkey on this device only — it cannot sync, so losing this device means " +
      "using your recovery sheet"
    );
  }
  return (
    "protected by a passkey on a removable security key — keep it, and your recovery sheet, " +
    "somewhere you can reach"
  );
}

function randomBytes(n) {
  const rng = globalThis.crypto;
  if (!rng?.getRandomValues) {
    throw new PasskeyError("passkey: no CSPRNG available", "no_csprng");
  }
  return rng.getRandomValues(new Uint8Array(n));
}

function toBytes(value) {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  return null;
}

function hex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * CREATE a discoverable passkey for this origin, asking for the PRF extension.
 *
 *   -> { credentialId, rpId, attachment, prfEnabled, backupEligible, backupState }
 *
 * `residentKey: "required"` makes the credential DISCOVERABLE, which is what lets
 * the unlock screen call `get()` with an EMPTY `allowCredentials` — the client
 * therefore needs no plaintext marker file naming credential ids, and the only
 * persisted artifact stays a sealed container.
 *
 * `userVerification: "required"` asks the authenticator to verify a human.
 * ⚠️ UV is a POLICY REQUEST, not a proof: we read a flag, we cannot verify that a
 * human was verified, and a lying authenticator is undetectable.
 *
 * No attestation is requested, deliberately: it costs privacy and CBOR parsing
 * and buys nothing here.
 */
export async function createPasskey({
  rpName = "Sigil",
  userName = "sigil-local-vault",
  userDisplayName = "Sigil vault",
  userId = null,
  timeoutMs = PASSKEY_TIMEOUT_MS,
} = {}) {
  const salt = await prfSalt();
  let cred;
  try {
    cred = await creds().create({
      publicKey: {
        challenge: randomBytes(32),
        rp: { name: rpName },
        user: {
          id: userId ?? randomBytes(16),
          name: userName,
          displayName: userDisplayName,
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 }, // ES256
          { type: "public-key", alg: -257 }, // RS256
        ],
        authenticatorSelection: {
          residentKey: "required",
          requireResidentKey: true,
          userVerification: "required",
        },
        attestation: "none",
        timeout: timeoutMs,
        extensions: { prf: { eval: { first: salt } } },
      },
    });
  } catch (err) {
    throw new PasskeyError(
      `passkey: creating a passkey failed (${err?.name ?? "Error"}: ${err?.message ?? err})`,
      "create_failed",
    );
  }
  if (!cred) throw new PasskeyError("passkey: the browser returned no credential", "create_failed");

  const ext = typeof cred.getClientExtensionResults === "function"
    ? cred.getClientExtensionResults()
    : {};
  const prfEnabled = ext?.prf?.enabled === true;
  let authenticatorData = null;
  try {
    authenticatorData = cred.response?.getAuthenticatorData?.() ?? null;
  } catch {
    authenticatorData = null;
  }
  const flags = backupFlags(authenticatorData);

  return {
    credentialId: bytesToBase64(toBytes(cred.rawId) ?? new Uint8Array(0)),
    rpId: globalThis.location?.hostname ?? "",
    attachment: cred.authenticatorAttachment ?? "",
    prfEnabled,
    backupEligible: flags.backupEligible,
    backupState: flags.backupState,
  };
}

/**
 * Run ONE assertion and return its PRF output.
 *
 *   -> { prfOutput: Uint8Array(32), backupEligible, backupState, userVerified,
 *        credentialId, attachment }
 *
 * `allowCredentials: []` means "any discoverable credential for this origin",
 * which is how the LOCKED screen can run a ceremony before it has opened
 * anything — the credential id lives INSIDE the sealed slot it is trying to open.
 *
 * ⛔ **USER VERIFICATION IS ENFORCED HERE, AND THAT IS A CORRECTNESS REQUIREMENT,
 * NOT A POLICY PREFERENCE (Phase 59).** CTAP 2.1's `hmac-secret` keys **TWO
 * INDEPENDENT SECRETS** per credential — `CredRandomWithUV` and
 * `CredRandomWithoutUV` — and which one the authenticator uses is decided by
 * whether the ceremony verified a user. A ceremony that completes with `UV=false`
 * therefore returns a *different, equally valid-looking* 32 bytes.
 *
 * We ask for `userVerification: "required"`, but that is a REQUEST; the flag is
 * the only evidence, and nothing used to read it. The failure it caused is
 * precisely the lockout ADR 0046 exists to prevent: at enable, the slot gets
 * sealed under the wrong secret (and the two-assertion determinism probe does NOT
 * catch it, because both probe assertions share one UV state and so agree with
 * each other); at unlock, the slot then refuses, and a user holding a working
 * passkey and the correct password is told "wrong password or a different
 * passkey" and pushed onto the recovery sheet.
 *
 * So a UV-less assertion is refused with its OWN code (`uv_missing`) rather than
 * being silently used. ⚠️ This remains a flag we are trusting: we cannot verify
 * that a human was verified, and a lying authenticator is undetectable (ADR 0046,
 * limitation 8). What it does guarantee is that we never seal under, or try to
 * open with, a secret from the wrong hmac-secret slot.
 */
export async function evaluatePrf({ allowCredentials = [], timeoutMs = PASSKEY_TIMEOUT_MS } = {}) {
  const salt = await prfSalt();
  let assertion;
  try {
    assertion = await creds().get({
      publicKey: {
        challenge: randomBytes(32),
        userVerification: "required",
        allowCredentials,
        timeout: timeoutMs,
        extensions: { prf: { eval: { first: salt } } },
      },
    });
  } catch (err) {
    throw new PasskeyError(
      `passkey: the passkey ceremony did not complete (${err?.name ?? "Error"}: ` +
        `${err?.message ?? err})`,
      "ceremony_failed",
    );
  }
  if (!assertion) {
    throw new PasskeyError("passkey: the ceremony returned no assertion", "ceremony_failed");
  }

  // ⛔ UV FIRST, BEFORE THE PRF BYTES ARE EVEN LOOKED AT. See the doc comment:
  // UV=false means the authenticator used its OTHER hmac-secret key, so the 32
  // bytes below are the wrong secret — usable, plausible, and silently fatal.
  // Checking here makes this the single choke point for enable AND unlock.
  const flags = backupFlags(assertion.response?.authenticatorData);
  if (!flags.userVerified) {
    throw new PasskeyError(
      "passkey: this ceremony completed WITHOUT user verification, and an authenticator derives " +
        "a DIFFERENT key in that case (CTAP hmac-secret keys one secret with UV and another " +
        "without). Refusing to use it rather than sealing — or trying to open — a vault with the " +
        "wrong key",
      "uv_missing",
    );
  }

  const ext = typeof assertion.getClientExtensionResults === "function"
    ? assertion.getClientExtensionResults()
    : {};
  const first = ext?.prf?.results?.first;
  const prfOutput = toBytes(first);
  if (!prfOutput) {
    throw new PrfUnavailableError(
      "passkey: this authenticator returned no PRF output, so it cannot protect a vault",
      "prf_missing",
    );
  }
  if (prfOutput.length !== PRF_OUTPUT_LEN) {
    throw new PrfUnavailableError(
      `passkey: the PRF output is ${prfOutput.length} bytes, expected ${PRF_OUTPUT_LEN}`,
      "prf_length",
    );
  }
  return {
    prfOutput,
    credentialId: bytesToBase64(toBytes(assertion.rawId) ?? new Uint8Array(0)),
    backupEligible: flags.backupEligible,
    backupState: flags.backupState,
    userVerified: flags.userVerified,
    // ⭐ THE REAL ATTACHMENT, reported by the ceremony that just ran — not
    // inferred. `describeProtectionScope` turns this into the sentence a user
    // reads about where their second factor lives, and inferring it from the
    // backup-eligible flag (as a caller once did) says "on this device only"
    // for every non-syncing SECURITY KEY, which is the opposite of true and the
    // opposite of useful when the question is "what do I have to keep safe".
    // "" when the browser does not report it — callers must not invent one.
    attachment: assertion.authenticatorAttachment ?? "",
  };
}

/**
 * ⭐ THE PROBE. Create a passkey, then assert TWICE, and require 32 bytes that
 * are BYTE-IDENTICAL across both assertions.
 *
 *   -> { credentialId, rpId, attachment, prfOutput, backupEligible, backupState }
 *
 * The second assertion is not ceremony: a PRF that returns different bytes each
 * time would seal a container nothing could ever open again, and it is
 * INDISTINGUISHABLE from a working one after a single call. Non-determinism is
 * reported as "unsupported", never as "try again".
 *
 * `prf.enabled === false` at creation is a sufficient hard refusal on its own.
 */
export async function probePrf(options = {}) {
  const support = passkeySupport();
  if (!support.available) throw new PrfUnavailableError(`passkey: ${support.reason}`, "unsupported");

  const created = await createPasskey(options);
  if (!created.prfEnabled) {
    throw new PrfUnavailableError(
      "passkey: this authenticator created a passkey but does not support the PRF extension, so " +
        "it cannot derive a key to protect your vault with",
      "prf_disabled",
    );
  }

  const first = await evaluatePrf();
  const second = await evaluatePrf();
  if (hex(first.prfOutput) !== hex(second.prfOutput)) {
    throw new PrfUnavailableError(
      "passkey: this authenticator returned DIFFERENT PRF bytes for the same input, so a vault " +
        "sealed with it could stop opening at any moment — refusing to use it",
      "prf_nondeterministic",
    );
  }

  return {
    credentialId: second.credentialId || created.credentialId,
    rpId: created.rpId,
    // Prefer the attachment the ASSERTION reported; fall back to creation's.
    // Both are the browser's own answer — neither is inferred.
    attachment: second.attachment || created.attachment,
    prfOutput: second.prfOutput,
    backupEligible: second.backupEligible,
    backupState: second.backupState,
  };
}

/**
 * ⭐ THE SLOT SECRET: `R ‖ utf8(password)`, handed straight to the container's
 * Argon2id.
 *
 * There is no HKDF here ON PURPOSE (see the header). PRF bytes come FIRST so the
 * fixed-length prefix makes the concatenation unambiguous.
 */
export function hwSlotSecret(prfOutput, password) {
  const r = toBytes(prfOutput);
  if (!r || r.length !== PRF_OUTPUT_LEN) {
    throw new PasskeyError(
      `passkey: the PRF output must be a ${PRF_OUTPUT_LEN}-byte Uint8Array`,
      "bad_prf",
    );
  }
  const pw = typeof password === "string" ? TEXT_ENCODER.encode(password) : toBytes(password);
  if (!pw) throw new PasskeyError("passkey: a password is required", "bad_password");
  const out = new Uint8Array(r.length + pw.length);
  out.set(r, 0);
  out.set(pw, r.length);
  return out;
}

/**
 * Derive the CONTAINER MASTER KEY from an ADR 0042 recovery-kit seed.
 *
 *   deriveContainerMasterKey(kitSeed(32)) -> Uint8Array(32)
 *
 * ⭐ ONE `crypto.subtle.deriveBits` call, in JS, and deliberately NOT a new label
 * in `libsigil/core/src/recovery.rs`: it has no Rust consumer, so a Rust copy
 * would be a mirror that can only drift, and a new wasm export would mean editing
 * `index.mjs` AND `index.d.ts` — the two-hole trap Phase 56 fell into. If the CLI
 * or desktop ever want offline local unlock, it moves into `recovery.rs` then.
 *
 * ⭐ This is what makes the break-glass need NO new artifact and NO server: the
 * same 56 characters that already rebuild a lost account also open a protected
 * local profile.
 */
export async function deriveContainerMasterKey(kitSeed) {
  const ikm = toBytes(kitSeed);
  if (!ikm || ikm.length !== 32) {
    throw new PasskeyError("passkey: the recovery seed must be 32 bytes", "bad_seed");
  }
  const s = subtle();
  const key = await s.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await s.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: TEXT_ENCODER.encode(CMK_HKDF_SALT),
      info: TEXT_ENCODER.encode(CMK_HKDF_INFO),
    },
    key,
    CONTAINER_MASTER_KEY_LEN * 8,
  );
  return new Uint8Array(bits);
}

/**
 * SEAL the hardware slot: a THIRD `SIGILcli` container holding the CMK, sealed
 * under `R ‖ utf8(password)`.
 *
 * ⭐ It is a container, not a JSON marker, precisely so the browser's persisted
 * key set stays "sealed containers only" (ADR 0036) — the leak specs check every
 * stored value's magic bytes, and a plaintext `{credential_ids, rp_id}` marker
 * would be the first non-container persisted value in this repo's history.
 * ⛔ Sealing that public metadata under a HARDCODED constant just to satisfy the
 * magic check would be fake crypto, which CLAUDE.md forbids by name.
 */
export function sealHwSlot(
  wasm,
  { prfOutput, password, cmk, kitDeviceId = "", credentialId = "", rpId = "", backupEligible = false, backupState = false },
  salt,
  nonce,
  params,
) {
  const key = toBytes(cmk);
  if (!key || key.length !== CONTAINER_MASTER_KEY_LEN) {
    throw new PasskeyError(
      `passkey: the container master key must be ${CONTAINER_MASTER_KEY_LEN} bytes`,
      "bad_cmk",
    );
  }
  const plaintext = {
    version: HW_SLOT_VERSION,
    cmk: bytesToBase64(key),
    kit_device_id: kitDeviceId,
    credential_id: credentialId,
    rp_id: rpId,
    backup_eligible: !!backupEligible,
    backup_state: !!backupState,
    created_at: new Date().toISOString(),
  };
  return new Uint8Array(
    wasm.seal_to_container(
      hwSlotSecret(prfOutput, password),
      salt,
      nonce,
      params.m_cost,
      params.t_cost,
      params.p_cost,
      TEXT_ENCODER.encode(JSON.stringify(plaintext)),
    ),
  );
}

/**
 * OPEN the hardware slot.
 *
 * Throws when the AEAD tag fails — which happens for a wrong password AND for a
 * different passkey, and those two are cryptographically indistinguishable here.
 * ⛔ A caller must therefore NOT render this as "wrong password": that is the
 * worst possible message for someone whose passkey just died.
 */
export function openHwSlot(wasm, prfOutput, password, containerBytes) {
  let obj;
  try {
    const plain = wasm.open_container(hwSlotSecret(prfOutput, password), containerBytes);
    obj = JSON.parse(new TextDecoder().decode(plain));
  } catch (err) {
    throw new PasskeyError(
      "passkey: the passkey slot did not open — either the password is wrong, or this is not the " +
        `passkey the vault was protected with (${err?.message ?? err})`,
      "slot_open_failed",
    );
  }
  if (obj.version !== HW_SLOT_VERSION) {
    throw new PasskeyError(
      `passkey: unsupported passkey slot version ${obj.version}`,
      "slot_version",
    );
  }
  const cmk = base64ToBytes(obj.cmk ?? "");
  if (cmk.length !== CONTAINER_MASTER_KEY_LEN) {
    throw new PasskeyError(
      `passkey: the stored container master key is ${cmk.length} bytes, expected ` +
        `${CONTAINER_MASTER_KEY_LEN}`,
      "slot_cmk_length",
    );
  }
  return {
    version: obj.version,
    cmk,
    kitDeviceId: obj.kit_device_id ?? "",
    credentialId: obj.credential_id ?? "",
    rpId: obj.rp_id ?? "",
    backupEligible: !!obj.backup_eligible,
    backupState: !!obj.backup_state,
    createdAt: obj.created_at ?? "",
  };
}

/**
 * Turn a passkey failure into something a person can act on.
 *
 * ⛔ Every branch names the PASSKEY. None of them may collapse into "wrong
 * password": a user whose authenticator was wiped needs to be pointed at the
 * recovery sheet, not sent to retype a password that is perfectly correct.
 *
 * ⭐ `atUnlock` IS NOT COSMETIC, and it exists because the same `code` means two
 * OPPOSITE things at the two call sites. During ENABLE, a PRF failure means the
 * control refused and *nothing was written* — "Nothing was changed" is the
 * reassurance the user needs. At UNLOCK the containers are ALREADY sealed under
 * a key that authenticator can no longer derive, so the very same sentence tells
 * a LOCKED-OUT person that everything is fine and never mentions the one thing
 * that would get them back in. A credential migrated to a non-PRF authenticator
 * after protection was switched on lands exactly there.
 */
export function explainPasskeyStatus(err, { atUnlock = false } = {}) {
  const code = err?.code ?? "";
  switch (code) {
    case "no_webauthn":
    case "unsupported":
    case "no_subtle":
      return (
        "This browser cannot run a passkey ceremony here. Your vault is unaffected — unlock it " +
        "with your recovery sheet, or open it in a browser that supports passkeys."
      );
    case "prf_disabled":
    case "prf_missing":
      return atUnlock
        ? "This passkey answered, but it cannot derive a key (it does not support the PRF " +
            "extension), so it cannot open this vault — the credential has most likely moved to " +
            "a different authenticator. Your vault is NOT lost: unlock it with your recovery " +
            "sheet below, which needs no passkey and no network."
        : "This passkey works, but it cannot derive a key (it does not support the PRF " +
            "extension), so it cannot protect a vault. Nothing was changed.";
    case "prf_length":
    case "prf_nondeterministic":
      return atUnlock
        ? "This authenticator's derived key changed, so it can no longer open this vault. Your " +
            "vault is NOT lost: unlock it with your recovery sheet below, which needs no passkey " +
            "and no network."
        : "This authenticator's derived key is not stable, so a vault sealed with it could stop " +
            "opening at any moment. Refusing to use it. Nothing was changed.";
    // ⛔ DISTINCT FROM "wrong password" AND FROM "PRF unsupported". The passkey
    // is fine and the password may be fine; what happened is that the ceremony
    // did not verify a user, and the authenticator therefore derives a different
    // key. The fix is a real action the user can take (use the PIN/biometric
    // prompt), which is why this must never be folded into slot_open_failed.
    case "uv_missing":
      return atUnlock
        ? "Your passkey answered without verifying you (no PIN, biometric or device unlock), and " +
            "authenticators derive a DIFFERENT key in that case — so it cannot open this vault. " +
            "Try again and complete the PIN or biometric prompt. If your authenticator cannot " +
            "verify you at all, unlock with your recovery sheet below."
        : "Your passkey answered without verifying you (no PIN, biometric or device unlock). " +
            "Authenticators derive a different key when they skip verification, so protecting " +
            "the vault now would seal it with a key that later fails to open it. Nothing was " +
            "changed — set up a PIN or biometric for this passkey and try again.";
    case "create_failed":
      return "Creating a passkey did not complete — it may have been dismissed or blocked.";
    case "ceremony_failed":
      return (
        "The passkey ceremony did not complete: it was cancelled, timed out, or the passkey is " +
        "no longer on this device. Your vault is NOT lost — unlock it with your recovery sheet " +
        "below, which needs no passkey and no network."
      );
    case "slot_open_failed":
      return (
        "The passkey answered, but the slot did not open. That means EITHER the password is " +
        "wrong OR this is a different passkey from the one the vault was protected with. If the " +
        "passkey is gone, use your recovery sheet below."
      );
    case "slot_version":
    case "slot_cmk_length":
      return "This passkey slot was written by a different version of Sigil and cannot be read here.";
    default:
      return err?.message ? String(err.message) : "The passkey step failed.";
  }
}
