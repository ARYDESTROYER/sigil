// sigil-wasm/clock-skew.mjs — is this device's clock right? (client half)
//
// Framework-free, dependency-free ESM. Runs in Node and the browser. It does NO
// cryptography, holds NO state, and reads nothing but one HTTP response header.
//
// ---------------------------------------------------------------------------
// ⛔ THE FAILURE THIS EXISTS FOR
// ---------------------------------------------------------------------------
//
// A TOTP code is a function of a shared secret and THE CURRENT TIME. When a
// device's clock drifts past half a time step, the codes it produces start
// falling outside the window a verifier will accept — and to the user a rejected
// code is INDISTINGUISHABLE from having the wrong secret. (RFC 6238 §5.2 lets a
// verifier accept one step either side, so a drift just over half a step often
// still validates; the further it drifts the more certainly it does not. The
// honest claim is LIKELY, and increasingly certain — never "every code".)
//
// So they re-scan the QR, re-import the export, delete the account and add it
// again, and none of it helps, because nothing was ever wrong with the secret.
// It is the most common real-world authenticator failure there is, and no Sigil
// client reported it anywhere.
//
// ---------------------------------------------------------------------------
// ⭐ THE SOURCE OF TRUTH IS ALREADY ON THE WIRE
// ---------------------------------------------------------------------------
//
// Every HTTP response Go's net/http produces carries a `Date` header (RFC 9110
// §6.6.1), so any sigild a client already talks to is a clock reference. No new
// route, no new endpoint, no new dependency.
//
// ⚠️ ONE BROWSER-SPECIFIC CATCH, MEASURED RATHER THAN ASSUMED: `Date` is NOT a
// CORS-safelisted response header, so `response.headers.get("Date")` returns
// null cross-origin unless the server names it in `Access-Control-Expose-Headers`.
// Probed against a real sigild from a real Chromium on a different origin, the
// only readable headers were content-length, content-type and x-request-id.
// sigild's exposed list therefore gained "Date" (one additive line in
// internal/api/cors.go, inside a middleware that is not even installed unless
// SIGILD_CORS_ORIGINS is set). `readClockSkew` reports the null case as
// UNAVAILABLE with a reason a developer can act on, rather than as "fine".
//
// ---------------------------------------------------------------------------
// ⛔⛔ IT IS A DIAGNOSTIC AND NEVER A CORRECTION
// ---------------------------------------------------------------------------
//
// Nothing here feeds the clock used to GENERATE codes. The wasm core reads no
// clock at all (ADR 0007) and the instant is always supplied by the caller from
// the system clock — that stays true. A client that silently generated codes
// against a server-supplied time would produce codes the user cannot reproduce,
// cannot compare against any other authenticator, and cannot reason about when
// the server is wrong or hostile. A wrong code the user can EXPLAIN beats a
// right code they cannot TRUST.
//
// ⚠️ AND IT IS NOT A SECURITY CONTROL. The reading is an unauthenticated
// plaintext header over plain HTTP; anyone who can see the traffic can change
// it. Its only job is to turn "my codes don't work" into "your clock is 4m12s
// fast". A hostile answer can at worst make that hint wrong, and no key,
// signature or generated code depends on it.
//
// ⭐ OFFLINE MEANS NO READING, NOT "FINE". `state: "unavailable"` is a distinct
// outcome from `state: "ok"`, and every caller in this repo renders it as such.
// Saying "your clock is fine" when we could not ask is the same class of lie as
// the stale capability claims this phase also removed.
//
// STATUS: dev-gated, plain HTTP, pre-audit, UNAUDITED.

/**
 * Warn when the local clock differs from the server's by more than this.
 *
 * Half of the default 30-second TOTP step: at exactly half a period a code sits
 * on the edge of the window a verifier will accept, so this is where drift
 * starts costing the user codes rather than merely being untidy.
 *
 * ⚠️ MIRRORED — not shared — with `CLOCK_SKEW_WARN_SECONDS` in `cli/src/lib.rs`.
 * They must agree, or two clients disagree about whether the same machine has a
 * problem. `clock-skew-interop.mjs` is the guard.
 */
export const CLOCK_SKEW_WARN_SECONDS = 15;

/** The response header carrying the server's clock. */
export const HEADER_DATE = "Date";

/**
 * The exact IMF-fixdate shape RFC 9110 §5.6.7 requires:
 * `Sun, 06 Nov 1994 08:49:37 GMT`.
 *
 * ⛔⛔ THIS GUARD IS LOAD-BEARING AND IT WAS ADDED BECAUSE A TEST CAUGHT ITS
 * ABSENCE. `Date.parse` is permissive by design and its non-ISO behaviour is
 * implementation-defined: `Date.parse("12345")` returns a finite number (the
 * year 12345), so the first version of this function turned an obviously
 * nonsensical header into a confident reading roughly 10,000 years out — and
 * therefore into a screaming CLOCK SKEW warning aimed at a user whose clock was
 * perfect. A mis-parse must be `null`, never a wrong number: telling someone to
 * fix a clock that is already right is worse than saying nothing, because the
 * entire purpose of this feature is to stop people debugging the wrong thing.
 *
 * The Rust half (`parse_http_date` in cli/src/lib.rs) hand-rolls the whole parse
 * and so never had this exposure; matching it here is what keeps the two halves
 * saying the same thing about the same bytes.
 */
const IMF_FIXDATE =
  /^[A-Z][a-z]{2}, \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \d{4} \d{2}:\d{2}:\d{2} GMT$/;

/**
 * Parse an HTTP `Date` header (RFC 9110 IMF-fixdate) into unix SECONDS.
 *
 * The shape is checked FIRST (see `IMF_FIXDATE`); only then is `Date.parse`
 * trusted with the arithmetic, which it does correctly for this one format in
 * every runtime this ships to.
 *
 * @param {string|null|undefined} raw
 * @returns {number|null} unix seconds, or null when it is not parsable.
 */
export function parseHttpDate(raw) {
  if (typeof raw !== "string") return null;
  const s = raw.trim();
  if (!IMF_FIXDATE.test(s)) return null;
  const ms = Date.parse(s);
  if (!Number.isFinite(ms)) return null;
  return Math.floor(ms / 1000);
}

/**
 * Compare a local instant against a server `Date` header.
 *
 * @param {string|null|undefined} dateHeader raw `Date` header value, or null.
 * @param {number} localUnix local clock, unix seconds (CALLER-supplied, the same
 *   discipline the core uses — ADR 0007 — so this is testable without a clock).
 * @returns {{state:"ok"|"skewed", serverUnix:number, localUnix:number, skewSeconds:number}
 *          |{state:"unavailable", reason:string}}
 */
export function skewFromDateHeader(dateHeader, localUnix) {
  if (dateHeader === null || dateHeader === undefined) {
    return {
      state: "unavailable",
      // Named precisely, because in the browser this is the ROUTINE case when a
      // server has not exposed the header, and "no Date header" would send a
      // developer looking at the wrong layer.
      reason:
        "the response carried no readable Date header (cross-origin, a browser can only read " +
        "it when the server lists Date in Access-Control-Expose-Headers)",
    };
  }
  const serverUnix = parseHttpDate(dateHeader);
  if (serverUnix === null) {
    return { state: "unavailable", reason: `unparsable Date header ${JSON.stringify(dateHeader)}` };
  }
  const skewSeconds = Math.floor(localUnix) - serverUnix;
  return {
    state: Math.abs(skewSeconds) > CLOCK_SKEW_WARN_SECONDS ? "skewed" : "ok",
    serverUnix,
    localUnix: Math.floor(localUnix),
    skewSeconds,
  };
}

/**
 * Read the clock off a response a client ALREADY made — zero extra requests.
 *
 * @param {Response} response any fetch Response from a sigild.
 * @param {number} localUnix local clock, unix seconds.
 */
export function readClockSkew(response, localUnix) {
  let raw = null;
  try {
    raw = response?.headers?.get?.(HEADER_DATE) ?? null;
  } catch {
    raw = null;
  }
  return skewFromDateHeader(raw, localUnix);
}

/**
 * Ask a server for the time, explicitly.
 *
 * Sends ONE unauthenticated `GET /healthz` — a route that exists on every
 * sigild, is never dev-gated and returns no data.
 *
 * ⭐ Deliberately its OWN request rather than a value threaded out of push/pull:
 * the reading must still be available when the sync itself FAILED, which is
 * exactly the moment a user is trying to work out what is wrong.
 *
 * @param {{baseUrl:string, fetch?:typeof fetch}} opts
 * @param {number} localUnix local clock, unix seconds.
 */
export async function fetchClockSkew(opts, localUnix) {
  const doFetch = opts?.fetch ?? globalThis.fetch;
  const base = String(opts?.baseUrl ?? "").replace(/\/+$/, "");
  let res;
  try {
    res = await doFetch(`${base}/healthz`, { method: "GET" });
  } catch (e) {
    return {
      state: "unavailable",
      reason: `could not reach ${base} (${e instanceof Error ? e.message : String(e)})`,
    };
  }
  // ⭐ A non-2xx response STILL carries a Date header, and a clock reading is
  // useful precisely when the server is unhappy with us.
  return readClockSkew(res, localUnix);
}

/**
 * The sentence to show a human. Names the DIRECTION explicitly — "ahead" and
 * "behind" are what a person can act on; a signed integer is not.
 *
 * ⚠️ MIRRORED — not shared — with `ClockSkew::describe` in `cli/src/lib.rs`.
 *
 * @param {ReturnType<typeof skewFromDateHeader>} skew
 * @returns {string}
 */
export function describeClockSkew(skew) {
  if (!skew || skew.state === "unavailable") {
    return (
      "NO CLOCK READING — this is not a report that your clock is fine, it is the absence of a " +
      `report (${skew?.reason ?? "no reason given"}). Codes are generated entirely on this ` +
      "device from its system clock, so if codes are being rejected, check the clock by hand " +
      "against any phone with automatic time sync."
    );
  }
  const d = skew.skewSeconds;
  if (skew.state === "ok") {
    return (
      `Clock OK: this device is within ${Math.abs(d)}s of the server ` +
      `(local ${skew.localUnix}, server ${skew.serverUnix}); TOTP codes will line up.`
    );
  }
  const dir = d > 0 ? "AHEAD OF" : "BEHIND";
  const verb = d > 0 ? "back" : "forward";
  return (
    `⚠️ CLOCK SKEW: this device is ${Math.abs(d)}s ${dir} the server ` +
    `(local ${skew.localUnix}, server ${skew.serverUnix}). That is more than half a 30s TOTP ` +
    "step, so codes generated here are likely to be REJECTED even though the secret is correct " +
    "— the two failures look identical. Fix the system clock (turn automatic time sync on, or " +
    `move it ${verb} ${Math.abs(d)}s). Nothing is wrong with your vault, and no code or key has ` +
    "been changed."
  );
}
