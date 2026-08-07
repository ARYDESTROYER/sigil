// qr-scan.mjs — reading an `otpauth://` provisioning code out of a QR IMAGE, in
// a browser, with no dependency of any kind.
//
// ⭐ WHY THIS EXISTS. Until Phase 63 the only way to add an account to Sigil was
// to paste an `otpauth://` URI or retype a base32 secret by hand. Every real 2FA
// enrolment screen shows a QR code. That made the on-ramp the weakest part of the
// product — closer to a missing product than a missing feature.
//
// ⭐⭐ AND WHY IT IS A THIN SHELL OVER `BarcodeDetector` RATHER THAN A DECODER WE
// OWN. This was the decision the phase turned on, and it was made on two
// measurements rather than on taste:
//
//   1. A QR decoder is a SUPERLINEAR DoS over attacker-chosen images. Measured on
//      `rqrr` 0.10.1 (release, the leading pure-Rust decoder, zero `unsafe`): a
//      1.74-megapixel image tiled with QR finder patterns — SMALLER than a phone
//      screenshot — took **94 seconds** in `detect_grids()`, while a benign
//      1.17-megapixel image took **11 milliseconds**. That is ~8,000x, and 100%
//      of it is inside one non-interruptible call. A pixel cap bounds MEMORY, not
//      TIME: at a fixed 1.1 Mpx the answer is either 11 ms or 19 s depending only
//      on content. Owning that decoder means owning that hang, and means shipping
//      a Worker with a watchdog to survive it.
//   2. `BarcodeDetector` is the platform's, so the hostile image is parsed inside
//      the browser's own sandboxed, hardened, continuously-patched decoder, off
//      our thread, in a process we do not share with the vault key.
//
//   So the zero-dependency choice is also the safer one. That is not usually true
//   and it is why it is written down here.
//
// ⛔⛔ THE PRICE, STATED AS LOUDLY AS THE FEATURE. `BarcodeDetector` DOES NOT
// EXIST EVERYWHERE. Measured directly for this phase, on a secure context:
//
//   macOS Chromium (bundled + Chrome channel, headless and headed) → PRESENT, qr_code
//   Linux Chromium (mcr.microsoft.com/playwright:v1.56.0-noble)    → ABSENT
//
// Firefox and Safari do not implement it at all. So on those browsers Sigil
// CANNOT scan, and the product says exactly that instead of showing a button that
// fails — `qrSupport()` is what the UI asks, and the unsupported branch is a real
// rendered state, not an error path.
//
// ⭐⭐ AND THERE IS A SECOND AXIS, WHICH THE TABLE ABOVE ORIGINALLY OMITTED AND
// WHICH COST A REVIEWER A WRONG CONCLUSION. `BarcodeDetector` is SECURE-CONTEXT
// GATED, so the SAME browser answers differently depending only on where the page
// came from. Measured on macOS Chromium 149, one browser, one session:
//
//   about:blank                     isSecureContext=false → undefined
//   http://<LAN-IP>:port            isSecureContext=false → undefined
//   http://localhost:port           isSecureContext=true  → PRESENT, qr_code
//   http://127.0.0.1:port           isSecureContext=true  → PRESENT, qr_code
//   file:///…                       isSecureContext=true  → PRESENT, qr_code
//
// ⚠️ A capability probe run on `about:blank` therefore reports "this browser
// cannot scan" about a browser that scans perfectly. That is not hypothetical:
// it is how this phase was briefed, and it nearly deleted a working feature.
// ⭐ IT IS ALSO A REAL PRODUCT STATE, not just a testing trap — serving this app
// from a plain-HTTP LAN address (a phone pointed at a dev laptop, the obvious way
// someone would try to scan) silently loses the API. That is why `qrSupport()` is
// a RUNTIME probe and why the message the user sees names the page's origin as a
// cause, not only the browser brand.
//
// ⛔ AND THE CONSEQUENCE FOR OUR OWN TESTING, WHICH IS THE UNCOMFORTABLE PART:
// every CI job in this repository runs `ubuntu-latest`, where the API is absent.
// So NO CI RUNNER EXERCISES THE SUPPORTED BRANCH. What CI does exercise is the
// unsupported branch — which is the branch its users are actually in, so that is
// a real assertion and not a skip. The supported branch is covered by the macOS
// developer gate (`scripts/gate.sh`). This is a stated coverage boundary, not an
// oversight; see the ADR.
//
// ── WHAT THIS MODULE DOES AND DOES NOT DO ────────────────────────────────────
// It does NO cryptography, holds NO state, and never touches a key, a password
// or a vault. It turns an image into a bounded STRING and hands that string to
// the ALREADY-HARDENED text parsers (`parseOtpauthUri` / `decodeMigrationUri` in
// totp-migration.mjs), which is where the Phase 63 provisioning gate lives. A QR
// is not a new format — it is a new SOURCE for a format we already parse — so
// this file adds no second parser and no second set of bounds.
//
// ⚠️ NO CAMERA. This phase reads IMAGES only: a pasted screenshot, a dropped
// file, a file picker. That is deliberate, and it is not a lesser path — most
// real 2FA enrolment happens on the same screen that is displaying the QR, where
// there is no second camera to point. `paste` in particular needs no permission,
// no prompt and no secure-context camera grant, and it is the exact motion of
// Cmd-Shift-4 / Win-Shift-S.
//
// Pre-audit / UNAUDITED / DEV. Do NOT scan a real 2FA QR into this build.

/** Largest image we will even look at, in bytes. Bounds the cheap case cheaply. */
export const MAX_IMAGE_BYTES = 8 * 1024 * 1024;

/**
 * Largest image we will hand to the detector, in pixels.
 *
 * ⚠️ HONEST LIMIT: a decoded image is allocated by `createImageBitmap` BEFORE we
 * can read its dimensions, so this bounds what WE forward to the detector, not
 * what the browser transiently allocates. A tiny PNG can declare enormous
 * dimensions. That allocation happens inside the browser's image decoder, which
 * is the hardened component we deliberately chose to rely on; the alternative was
 * to parse image headers ourselves, i.e. to add the attacker-facing parser this
 * design exists to avoid. 40 Mpx is ~3x a 12-megapixel phone photo.
 */
export const MAX_IMAGE_PIXELS = 40_000_000;

/** Longest decoded payload we will accept. A QR maxes out at 2,953 bytes. */
export const MAX_QR_TEXT_LENGTH = 4096;

/** A QR was read, but what it contained is not something Sigil will act on. */
export class QrScanError extends Error {
  /**
   * @param {string} message human-readable, and NEVER containing scanned text
   * @param {string} code machine-readable: one of the `QR_*` codes below
   */
  constructor(message, code) {
    super(message);
    this.name = "QrScanError";
    this.code = code;
  }
}

export const QR_UNSUPPORTED = "qr_unsupported";
export const QR_TOO_LARGE = "qr_too_large";
export const QR_NOT_FOUND = "qr_not_found";
export const QR_AMBIGUOUS = "qr_ambiguous";
export const QR_NOT_PROVISIONING = "qr_not_provisioning";
export const QR_TOO_LONG = "qr_too_long";

/**
 * Can this browser read a QR code at all?
 *
 * ⚠️ TWO-PART AND ASYNC, ON PURPOSE. `'BarcodeDetector' in globalThis` is NOT
 * sufficient: a browser may expose the constructor and support no formats, or
 * not `qr_code` specifically. The one-part probe is the mutation this is written
 * to survive.
 *
 * ⚠️ It must also stay a RUNTIME probe, never a build-time one: the API is
 * secure-context gated, so the same binary served from a plain-HTTP LAN origin
 * silently loses it.
 *
 * @returns {Promise<boolean>}
 */
export async function qrSupport() {
  if (typeof globalThis.BarcodeDetector !== "function") return false;
  try {
    const formats = await globalThis.BarcodeDetector.getSupportedFormats();
    return Array.isArray(formats) && formats.includes("qr_code");
  } catch {
    return false;
  }
}

/**
 * Decode exactly one QR code out of an image blob and return its raw text.
 *
 * ⚠️ REFUSES AMBIGUITY. A desktop screenshot can easily contain more than one QR
 * code. Silently taking the first is how a user imports the account they did not
 * mean to and believes they succeeded, so a count other than one is an error that
 * says how many were found.
 *
 * ⚠️ The returned string is UNTRUSTED and is a SECRET. Callers must not render
 * it, log it, put it in a URL, or store it — hand it straight to the provisioning
 * parsers.
 *
 * @param {Blob} blob
 * @returns {Promise<string>} the single decoded payload
 */
export async function decodeQrImage(blob) {
  if (!(await qrSupport())) {
    // ⚠️⚠️ TWO CAUSES, AND NAMING ONLY THE BROWSER IS A FALSE DIAGNOSIS.
    // `BarcodeDetector` is ALSO secure-context gated, so Chrome ITSELF reports
    // "unsupported" on a plain-http:// page served from anything other than
    // localhost — which is exactly how someone reaches a dev laptop from their
    // phone to scan a code. This message used to say only "Chrome and Edge can;
    // Firefox and Safari cannot", which sends that user to install a browser
    // they already have. It is kept in sync with `explainQrError`'s
    // QR_UNSUPPORTED arm ON PURPOSE — the two are the same claim, and this
    // repository has been bitten four times by a false sentence surviving in the
    // one copy nobody grepped for. `provisioning-interop.mjs` asserts both.
    throw new QrScanError(
      "this page cannot read QR codes: either the browser does not support it " +
        "(Chrome and Edge do; Firefox and Safari do not), or the page was not loaded " +
        "over a secure origin — the API is unavailable on a plain-http:// address " +
        "other than localhost",
      QR_UNSUPPORTED,
    );
  }
  if (typeof blob?.size === "number" && blob.size > MAX_IMAGE_BYTES) {
    throw new QrScanError(
      `image is ${blob.size} bytes, over the ${MAX_IMAGE_BYTES}-byte maximum`,
      QR_TOO_LARGE,
    );
  }

  let bitmap;
  try {
    bitmap = await createImageBitmap(blob);
  } catch {
    throw new QrScanError("that file could not be read as an image", QR_NOT_FOUND);
  }

  try {
    const pixels = bitmap.width * bitmap.height;
    if (pixels > MAX_IMAGE_PIXELS) {
      throw new QrScanError(
        `image is ${bitmap.width}x${bitmap.height} pixels, over the ` +
          `${MAX_IMAGE_PIXELS}-pixel maximum`,
        QR_TOO_LARGE,
      );
    }

    const detector = new globalThis.BarcodeDetector({ formats: ["qr_code"] });
    let codes;
    try {
      codes = await detector.detect(bitmap);
    } catch {
      throw new QrScanError("that image could not be scanned", QR_NOT_FOUND);
    }
    const values = (codes ?? [])
      .map((c) => (typeof c?.rawValue === "string" ? c.rawValue : ""))
      .filter((s) => s.length > 0);

    if (values.length === 0) {
      throw new QrScanError("no QR code was found in that image", QR_NOT_FOUND);
    }
    if (values.length > 1) {
      throw new QrScanError(
        `that image contains ${values.length} QR codes — crop it to just the one you want`,
        QR_AMBIGUOUS,
      );
    }
    const text = values[0];
    if (text.length > MAX_QR_TEXT_LENGTH) {
      throw new QrScanError(
        `the QR code carries ${text.length} characters, over the ` +
          `${MAX_QR_TEXT_LENGTH}-character maximum`,
        QR_TOO_LONG,
      );
    }
    return text;
  } finally {
    // Release the decoded pixels promptly; a frame of someone's desktop is not
    // something to leave alive on the heap.
    if (typeof bitmap.close === "function") bitmap.close();
  }
}

/**
 * Classify a decoded QR payload as something Sigil will act on.
 *
 * ⚠️ A QR CAN ENCODE ANYTHING — `javascript:`, `https://phishing.example`, or a
 * paragraph of prose crafted to read as a message from Sigil. So the payload is
 * NEVER navigated to, never rendered as a link, never auto-submitted, and never
 * echoed back into the UI. The error below names ONLY the scheme, truncated, and
 * only after stripping anything that is not an ASCII letter/digit/`+`/`-`/`.` —
 * so it cannot smuggle text into a trusted surface.
 *
 * @param {string} text
 * @returns {{kind: "otpauth"|"migration", text: string}}
 */
export function classifyQrPayload(text) {
  const s = String(text);
  const lower = s.toLowerCase();
  if (lower.startsWith("otpauth://totp/")) return { kind: "otpauth", text: s };
  if (lower.startsWith("otpauth-migration://")) return { kind: "migration", text: s };
  if (lower.startsWith("otpauth://hotp/")) {
    throw new QrScanError(
      "that is a counter-based (HOTP) code, which Sigil does not support",
      QR_NOT_PROVISIONING,
    );
  }
  const scheme = (lower.split(":", 1)[0] ?? "").replace(/[^a-z0-9+.-]/g, "").slice(0, 16);
  throw new QrScanError(
    scheme.length > 0
      ? `that QR code is a "${scheme}" link, not a 2FA setup code — Sigil will not open it`
      : "that QR code is not a 2FA setup code",
    QR_NOT_PROVISIONING,
  );
}

/**
 * The whole image path, composed: blob in, classified provisioning payload out.
 *
 * ⭐ THIS FUNCTION DOES NOT TOUCH THE VAULT, BY DESIGN. It returns a payload for
 * the caller to show the user and have them CONFIRM. A scanner that writes on
 * decode means pointing a camera — or pasting a screenshot from a page that put
 * one there — silently mutates the vault. ADR 0050 established that a single
 * click must not destroy an account; the same reasoning forbids a single glance
 * creating one.
 *
 * @param {Blob} blob
 * @returns {Promise<{kind: "otpauth"|"migration", text: string}>}
 */
export async function scanProvisioningImage(blob) {
  return classifyQrPayload(await decodeQrImage(blob));
}

/**
 * Pull the first image out of a `paste` or `drop` event, or null if there is none.
 *
 * ⭐ Uses the EVENT's own data, never `navigator.clipboard.read()`. The event
 * carries the image with no permission and no prompt, and works in every browser;
 * the clipboard API prompts and reads whatever happens to be there.
 *
 * @param {ClipboardEvent|DragEvent} event
 * @returns {Blob|null}
 */
export function imageFromEvent(event) {
  const dt = event?.clipboardData ?? event?.dataTransfer;
  if (!dt) return null;
  for (const item of dt.items ?? []) {
    if (item.kind === "file" && String(item.type).startsWith("image/")) {
      const file = item.getAsFile();
      if (file) return file;
    }
  }
  for (const file of dt.files ?? []) {
    if (String(file.type).startsWith("image/")) return file;
  }
  return null;
}

/**
 * Render a scan failure as something a user can act on.
 *
 * ⚠️ It must never include the scanned payload — see `classifyQrPayload`.
 *
 * @param {unknown} err
 * @returns {string}
 */
export function explainQrError(err) {
  if (err instanceof QrScanError) {
    if (err.code === QR_UNSUPPORTED) {
      // ⚠️ TWO CAUSES, AND NAMING ONLY THE FIRST IS A FALSE DIAGNOSIS. Chrome
      // and Edge support this; Firefox and Safari do not. But the API is also
      // secure-context gated, so Chrome ITSELF loses it on a plain-HTTP page
      // served from anything other than localhost — which is exactly how someone
      // would reach a dev laptop from their phone to scan a code. Telling that
      // user "your browser cannot do this" sends them to install a browser they
      // already have.
      return (
        "This page cannot read QR codes. Either the browser does not support it " +
        "(Chrome and Edge do; Firefox and Safari do not), or the page was not " +
        "loaded over a secure origin — the API is unavailable on a plain-http:// " +
        "address other than localhost. Paste the otpauth:// setup link instead — " +
        "it does the same job."
      );
    }
    return err.message;
  }
  // ⭐ A REFUSAL FROM THE PROVISIONING GATE MUST REACH THE USER INTACT. The gate
  // throws ordinary `Error`s ("period 4294967295s exceeds the maximum of 600s: a
  // code that long does not rotate…"), and collapsing those into a generic
  // "could not be scanned" would tell the user the image was unreadable when in
  // fact it was read perfectly and REFUSED — a false statement about our own
  // behaviour, of exactly the kind Phase 62 existed to delete. A spec caught this
  // being wrong.
  //
  // ⚠️ Safe to pass through ONLY because the gate is disciplined about never
  // putting attacker-controlled text in its messages — it names a bound and a
  // count. That discipline is itself asserted, in
  // `sigil-wasm/test/provisioning-interop.mjs`.
  if (err instanceof Error && typeof err.message === "string" && err.message.length > 0) {
    return err.message;
  }
  return "That image could not be scanned.";
}
