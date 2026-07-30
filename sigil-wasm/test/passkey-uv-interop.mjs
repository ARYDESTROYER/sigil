// passkey-uv-interop.mjs — Phase 59. The guard on the ONE passkey check that,
// when missing, causes the exact lockout ADR 0046 exists to prevent.
//
// ⛔ THE DEFECT. CTAP 2.1's `hmac-secret` keys TWO INDEPENDENT SECRETS per
// credential — `CredRandomWithUV` and `CredRandomWithoutUV` — and the
// authenticator picks between them based on whether the ceremony verified a
// user. `evaluatePrf` computed `userVerified` from the authenticator-data flags
// and then NOTHING enforced it. So a ceremony completing with UV=false yielded
// the OTHER 32 bytes: at enable, the hardware slot got sealed under the wrong
// secret; at unlock, that slot then refused, and a user holding a WORKING passkey
// and the CORRECT password was told "wrong password or a different passkey" and
// sent to the recovery sheet.
//
// The two-assertion determinism probe does NOT catch this: both probe assertions
// share one UV state, so they agree with each other and look perfectly healthy.
//
// ⚠️ WHY THIS IS A NODE TEST AND NOT A PLAYWRIGHT ONE. Chrome's CDP virtual
// authenticator cannot produce the failure: with `userVerification: "required"`
// it either verifies (UV=1) or the ceremony fails outright, so the "completed
// but unverified" case — a nonconforming or lying authenticator, or a browser
// that silently downgrades — is unreachable through the real API. Driving the
// REAL `evaluatePrf` over a stubbed `navigator.credentials` is the only way to
// exercise the branch at all, and an unexercised branch of a lockout-adjacent
// control is exactly what this repo keeps shipping.
//
// This drives the SHIPPED function — no re-implementation of the check.
//
// Usage:  node sigil-wasm/test/passkey-uv-interop.mjs   (prints PASS, exits 0)

function assert(cond, msg) {
  if (!cond) throw new Error(`ASSERTION FAILED: ${msg}`);
}

// ── a minimal WebAuthn double ────────────────────────────────────────────────
//
// ⚠️ THIS DOUBLE IS DELIBERATELY MORE PERMISSIVE THAN A REAL AUTHENTICATOR: it
// returns an assertion with whatever flags the test asks for, including
// combinations Chrome would refuse. That is the entire point — it reaches the
// branch a real authenticator will not let us reach — but it means a PASS here
// is evidence about OUR check, not about any browser's behaviour.

const PRF_BYTES_WITH_UV = new Uint8Array(32).fill(0xa1);
const PRF_BYTES_WITHOUT_UV = new Uint8Array(32).fill(0xb2); // the OTHER secret

/**
 * Build an authenticatorData blob whose flags byte (offset 32) is `flags`.
 * UP = 0x01, UV = 0x04, BE = 0x08, BS = 0x10 — the layout `backupFlags` reads.
 */
function authData(flags) {
  const buf = new Uint8Array(37); // 32 rpIdHash + 1 flags + 4 signCount
  buf[32] = flags;
  return buf.buffer;
}

/**
 * Install `globalThis.navigator`.
 *
 * ⚠️ PLAIN ASSIGNMENT DOES NOT WORK ON NODE >= 21. Node 21 shipped the
 * `navigator` global, and it is an ACCESSOR with a getter and NO setter, so
 * `globalThis.navigator = {...}` throws in an ES module (strict mode):
 *
 *     TypeError: Cannot set property navigator of #<Object> which has only a getter
 *
 * The dev machine runs Node 20.12, where `navigator` is undefined and the
 * assignment is fine — so this passed locally and was an instant, total failure
 * on Linux CI, which pins Node 22 (`interop.yml`). Same shape as the
 * `/opt/homebrew/bin/go` hardcode: a host-only assumption that the only gate
 * anyone ran could not see.
 *
 * The property IS configurable on every Node that defines it, so
 * `defineProperty` works on both, and is repeatable across the several calls
 * this suite makes.
 */
function setNavigator(value) {
  Object.defineProperty(globalThis, "navigator", {
    value,
    configurable: true,
    writable: true,
    enumerable: true,
  });
}

function installCredentials({ userVerified, attachment = "cross-platform" }) {
  const prf = userVerified ? PRF_BYTES_WITH_UV : PRF_BYTES_WITHOUT_UV;
  const flags = 0x01 | (userVerified ? 0x04 : 0x00);
  globalThis.isSecureContext = true;
  setNavigator({
    credentials: {
      async get() {
        return {
          rawId: new Uint8Array([1, 2, 3, 4]).buffer,
          authenticatorAttachment: attachment,
          response: { authenticatorData: authData(flags) },
          getClientExtensionResults: () => ({ prf: { results: { first: prf } } }),
        };
      },
      async create() {
        throw new Error("create() is not part of this test");
      },
    },
  });
}

// passkey.mjs reads `globalThis.navigator` at CALL time, so the stub can be
// installed after the import.
const { evaluatePrf, backupFlags, explainPasskeyStatus, describeProtectionScope } = await import(
  "../passkey.mjs"
);

// =====================================================================
// PROOF 1 — A UV-LESS CEREMONY IS REFUSED, AND ITS BYTES NEVER ESCAPE
// =====================================================================
installCredentials({ userVerified: false });
let refused = null;
try {
  await evaluatePrf();
} catch (e) {
  refused = e;
}
assert(refused !== null, "a ceremony completing WITHOUT user verification must be refused");
assert(
  refused.code === "uv_missing",
  `the refusal must carry its OWN code, got ${JSON.stringify(refused.code)}`,
);
// The wrong-slot bytes must not appear anywhere in what the caller sees —
// including the error, which a UI renders.
assert(
  !JSON.stringify(refused.message).includes("b2b2"),
  "the refusal must not leak the PRF bytes",
);
console.log("  PROOF 1  OK: evaluatePrf REFUSES a UV=false assertion with code `uv_missing`");

// =====================================================================
// PROOF 2 — THE REFUSAL IS DISTINCT FROM "WRONG PASSWORD" AND FROM "NO PRF"
//
// The whole failure was that this state was indistinguishable from a wrong
// password. Both the enable-time and the unlock-time wordings must name the real
// problem and give the user something to DO.
// =====================================================================
const atUnlock = explainPasskeyStatus(refused, { atUnlock: true });
const atEnable = explainPasskeyStatus(refused, { atUnlock: false });
for (const [where, text] of [
  ["unlock", atUnlock],
  ["enable", atEnable],
]) {
  assert(
    !/wrong password/i.test(text),
    `the ${where} message must NOT read as "wrong password": ${text}`,
  );
  assert(
    /verif/i.test(text),
    `the ${where} message must name user verification: ${text}`,
  );
  assert(
    /PIN|biometric/i.test(text),
    `the ${where} message must tell the user what to do: ${text}`,
  );
}
assert(atUnlock !== atEnable, "unlock and enable must not say the same thing");
assert(
  /Nothing was changed/i.test(atEnable),
  `at ENABLE the user must be told nothing was written: ${atEnable}`,
);
assert(
  /recovery sheet/i.test(atUnlock),
  `at UNLOCK the user must still be pointed at the sheet: ${atUnlock}`,
);
// …and it is NOT the same message as the PRF-unsupported branch.
const prfMissing = explainPasskeyStatus({ code: "prf_missing" }, { atUnlock: true });
assert(atUnlock !== prfMissing, "uv_missing must not be folded into prf_missing");
console.log(
  "  PROOF 2  OK: the refusal is worded distinctly at enable and at unlock, names verification, " +
    "and is never rendered as a wrong password",
);

// =====================================================================
// PROOF 3 — A VERIFIED CEREMONY STILL WORKS, AND REPORTS THE REAL ATTACHMENT
//
// The fix must not break the normal path, and the attachment must be the value
// the ceremony reported — it used to be inferred from the backup-eligible flag,
// which told every holder of a non-syncing SECURITY KEY that their factor lived
// "on this device only".
// =====================================================================
installCredentials({ userVerified: true, attachment: "cross-platform" });
const ok = await evaluatePrf();
assert(ok.userVerified === true, "a verified ceremony must report userVerified");
assert(ok.prfOutput.length === 32, "a verified ceremony must return 32 PRF bytes");
assert(ok.prfOutput[0] === 0xa1, "a verified ceremony must return the WITH-UV secret");
assert(
  ok.attachment === "cross-platform",
  `attachment must be the ceremony's own value, got ${JSON.stringify(ok.attachment)}`,
);

installCredentials({ userVerified: true, attachment: "platform" });
const plat = await evaluatePrf();
assert(plat.attachment === "platform", "a platform authenticator must report `platform`");

// The two attachments must produce DIFFERENT user-facing scope sentences, which
// is what the fabricated value destroyed: a security key was described as
// "on this device only".
const keyScope = describeProtectionScope({ backupEligible: false, attachment: "cross-platform" });
const platScope = describeProtectionScope({ backupEligible: false, attachment: "platform" });
assert(keyScope !== platScope, "a security key and a platform passkey must not be described alike");
assert(/security key/i.test(keyScope), `a cross-platform authenticator is a security key: ${keyScope}`);
assert(/this device only/i.test(platScope), `a platform authenticator is device-bound: ${platScope}`);
console.log(
  "  PROOF 3  OK: a verified ceremony returns the WITH-UV secret and the REAL attachment, and " +
    "a security key is no longer described as 'this device only'",
);

// =====================================================================
// PROOF 4 — THE FLAG READER ITSELF (the input the check depends on)
// =====================================================================
assert(backupFlags(authData(0x00)).userVerified === false, "UV clear must read as false");
assert(backupFlags(authData(0x04)).userVerified === true, "UV set must read as true");
assert(backupFlags(authData(0x05)).userPresent === true, "UP is bit 0");
assert(backupFlags(authData(0x0c)).backupEligible === true, "BE is bit 3");
assert(backupFlags(authData(0x14)).backupState === true, "BS is bit 4");
console.log("  PROOF 4  OK: the authenticator-data flag reader is correct bit by bit");

console.log(
  "\nPASS: a passkey ceremony that completes WITHOUT user verification is refused with a " +
    "distinct, honest error instead of silently deriving CTAP's other hmac-secret key — the " +
    "failure that sealed a slot nothing could reopen and told the user their password was wrong",
);
