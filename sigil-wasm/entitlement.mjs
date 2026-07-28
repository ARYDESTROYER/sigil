// sigil-wasm/entitlement.mjs — READ what sigild already says about payment, and
// say it back to the user TRUTHFULLY (Phase 55 / ADR 0043, client half).
//
// Framework-free, dependency-free ESM. Runs in Node and the browser. It does NO
// cryptography and holds NO state: every request goes through the existing
// contract-v3 `signedFetch` in `device-auth.mjs`.
//
// ⭐ THE ONE THING THIS MODULE EXISTS TO GET RIGHT: the message must be TRUE.
//
// sigild's entitlement gate (ADR 0043 §2/§3) is called from EXACTLY THREE WRITE
// handlers — `opsAppend`, `keyEnvelopePut`, `vaultGrantCreate` — and from no read
// handler at all, a shape a test enforces by parsing the server package's AST.
// And a key-envelope deposit (plus the grant that accompanies it) to a device of
// the CALLER'S OWN ACCOUNT is exempt even after grace. So the honest statement,
// which every string in this file sticks to, is:
//
//   REFUSED after grace ......... appending NEW ops to the op-log (pushing
//                                 changed vault content), and depositing a
//                                 wrapped vault key / granting access to a
//                                 device of a DIFFERENT account.
//   NEVER REFUSED ............... reading every op of every vault you hold, i.e.
//                                 GENERATING EVERY CODE YOU ALREADY HAVE (which
//                                 on these clients happens offline, in the wasm,
//                                 with no server involved at all); collecting
//                                 your key envelopes; enumerating which vaults
//                                 hold a key for you; publishing a hybrid key;
//                                 enrolling a device; REVOKING a device; deleting
//                                 a stale envelope; minting an invite; reading
//                                 your account; running checkout to pay; and
//                                 giving another device OF YOUR OWN ACCOUNT the
//                                 key to a vault — which is what makes replacing
//                                 a dead device, and PRINTING A RECOVERY KIT,
//                                 work while lapsed.
//
// ⚠️ NEVER tell a user a billing state has cost them their codes. It has not.
// ⚠️ A `402` is a BILLING state. It is not `401` (not authenticated) and not
//    `403` (not authorized), and rendering it as either is a lie that sends the
//    user to debug the wrong thing.
//
// It is also entirely possible that a server has enforcement OFF (the default):
// then no header is ever set and the `entitlement` block is ABSENT from
// `GET /v1/billing/subscription`. `entitlementState` reports that as `off`, and
// a client must show nothing rather than inventing a warning.
//
// STATUS: dev-gated, plain HTTP, pre-audit, UNAUDITED. Billing has never been
// run against a live provider account (ADR 0034).

import { DeviceAuthError, signedFetch } from "./device-auth.mjs";

/** `grace` or `lapsed`, set by sigild only on a gated write. */
export const HEADER_ENTITLEMENT = "X-Sigil-Entitlement";
/** The account's billing status, from sigild's closed enum. */
export const HEADER_ENTITLEMENT_STATUS = "X-Sigil-Entitlement-Status";
/** RFC3339 instant at which writes stop (or stopped). */
export const HEADER_ENTITLEMENT_GRACE_ENDS = "X-Sigil-Entitlement-Grace-Ends";

/** The stable error code in sigild's machine-readable 402 body. */
export const PAYMENT_REQUIRED_CODE = "payment_required";

/**
 * ⭐ The sentence that must never be softened OR overstated, in one place so all
 * four clients say the same thing. Reads and same-account key recovery are never
 * refused; that is the whole point of ADR 0043's asymmetry.
 */
export const NEVER_REFUSED =
  "Your existing codes are NOT affected: they are generated on this device, in the " +
  "WebAssembly core, from a vault you already hold — offline, with no server involved. " +
  "Reading anything already stored is never refused, and neither is giving another device " +
  "of YOUR OWN account the key to a vault, so you can still replace a lost device and " +
  "still create or extend a recovery kit. Nothing is deleted and nothing expires.";

/** What a lapsed account actually loses. Refused = new writes, and only those. */
export const WHAT_IS_REFUSED =
  "What stops is uploading NEW changes: pushing changed vault content to the server, and " +
  "sharing a vault to a device belonging to a DIFFERENT account.";

/**
 * A refusal for PAYMENT, carrying sigild's machine-readable 402 body.
 *
 * ⚠️ Distinct from {@link DeviceAuthError} ON PURPOSE. A caller that collapses
 * this into "unauthorized" is telling the user their key or their permissions are
 * wrong, when in fact the server authenticated AND authorized them and then asked
 * for money.
 */
export class PaymentRequiredError extends Error {
  constructor(body, what = "request") {
    const detail = body?.detail ?? "this account's subscription has lapsed and its grace period has ended";
    super(`${what}: 402 payment required — ${detail}`);
    this.name = "PaymentRequiredError";
    /** @type {number} always 402. */
    this.status = 402;
    /** @type {string} the account's own billing status, e.g. "canceled". */
    this.subscriptionStatus = body?.subscription_status ?? "";
    /** @type {string} RFC3339 instant at which writes stopped. */
    this.graceEndedAt = body?.grace_ended_at ?? "";
    /** @type {boolean} ALWAYS true — reads are never refused. */
    this.readsAllowed = body?.reads_allowed !== false;
    /** @type {boolean} ALWAYS true — same-account key deposit is exempt. */
    this.keyRecoveryAllowed = body?.key_recovery_allowed !== false;
    /** @type {string} where to go to fix it. */
    this.checkoutPath = body?.checkout_path ?? "/v1/billing/checkout";
    /** @type {string} the server's own prose. */
    this.detail = detail;
  }
}

/** Best-effort JSON parse; a non-JSON body is simply "no structured body". */
function parseJson(text) {
  if (typeof text !== "string" || text.trim() === "") return null;
  try {
    return JSON.parse(text);
  } catch {
    // A body that is not JSON tells us nothing; the status already did.
    return null;
  }
}

/**
 * Pull the structured 402 out of ANY thrown transport error, or return null.
 *
 *   const pay = paymentRequiredFrom(err, "Push");
 *   if (pay) { renderBillingState(pay); return; }
 *   renderAuthOrOtherFailure(err);
 *
 * Works for every error shape this repo throws: `DeviceAuthError` (which carries
 * `.status` + `.body`), and the plain `Error` from `sync.mjs` (which carries
 * `.status`, and `.body` since Phase 56). When the body cannot be parsed the
 * status alone is still enough to classify it correctly — a 402 is a 402.
 */
export function paymentRequiredFrom(err, what = "request") {
  const status = err && typeof err.status === "number" ? err.status : 0;
  if (status !== 402) return null;
  if (err instanceof PaymentRequiredError) return err;
  const body = parseJson(err?.body) ?? parseJson(err?.message?.split(" — ").slice(1).join(" — "));
  return new PaymentRequiredError(body, what);
}

/**
 * Read the three warning headers off a response that was SERVED.
 *
 *   readEntitlementHeaders(res) -> { state: "grace"|"lapsed", status, graceEndsAt } | null
 *
 * sigild sets them only when an account is in grace or past it, so `null` is the
 * ordinary, healthy answer and MUST NOT be rendered as anything.
 */
export function readEntitlementHeaders(res) {
  const h = res?.headers;
  if (!h || typeof h.get !== "function") return null;
  const state = h.get(HEADER_ENTITLEMENT);
  if (state !== "grace" && state !== "lapsed") return null;
  return {
    state,
    status: h.get(HEADER_ENTITLEMENT_STATUS) ?? "",
    graceEndsAt: h.get(HEADER_ENTITLEMENT_GRACE_ENDS) ?? "",
  };
}

/**
 * READ this device's ACCOUNT's subscription, including the additive
 * `entitlement` block (ADR 0043 §4).
 *
 *   getSubscription(wasm, auth, baseUrl)
 *     -> { subject, provider, status, entitled, current_period_end, updated_at,
 *          entitlement?: { enforced, writes, reads, grace_ends_at } }
 *
 * ⭐ THE WARNING CHANNEL FOR A READ-ONLY CLIENT. A client that only ever reads is
 * never refused and never sees a warning header, so without this it would learn
 * about a lapse only the first time it tried to write. This route is itself never
 * gated by entitlement.
 *
 * NO REQUEST NAMES AN ACCOUNT: the subject is the account behind the verified
 * signature (ADR 0040), so there is nothing here to enumerate with.
 */
export async function getSubscription(wasm, auth, baseUrl = null) {
  const base = baseUrl ?? auth?.baseUrl;
  const res = await signedFetch(
    wasm,
    { ...auth, baseUrl: base },
    "GET",
    "/v1/billing/subscription",
    "",
    null,
  );
  if (res.status !== 200) {
    const body = await res.text().catch(() => "");
    throw new DeviceAuthError(
      res.status,
      `getSubscription: ${explainSubscriptionStatus(res.status)}${body ? ` — ${body.trim()}` : ""}`,
      body,
    );
  }
  return res.json();
}

/** Plain-language explanation of a subscription-route status. */
export function explainSubscriptionStatus(status) {
  switch (status) {
    case 401:
      return "401 unauthorized — this device is not authenticated (unknown, revoked, bad signature or clock skew).";
    case 403:
      return "403 forbidden — this device is authenticated but carries no account the server will report on.";
    case 501:
      return "501 not implemented — this server has billing turned off, so there is no subscription to report. Nothing is being enforced.";
    default:
      return `HTTP ${status}`;
  }
}

/**
 * Reduce a subscription response (or a header reading) to ONE state a UI can
 * switch on, without ever inventing a warning that the server did not make.
 *
 *   entitlementState(subscription) ->
 *     { level: "off" | "ok" | "grace" | "refused",
 *       enforced, status, writes, graceEndsAt, entitled }
 *
 *  * `off`     — this server does not enforce payment (the block is ABSENT).
 *                Show NOTHING. This is the default for every sigild.
 *  * `ok`      — enforcement is on and writes are allowed.
 *  * `grace`   — lapsed, writes still work, and they stop at `graceEndsAt`.
 *                A visible, NON-BLOCKING warning.
 *  * `refused` — past grace: new writes are refused. Reads are not.
 */
export function entitlementState(subscription) {
  const block = subscription?.entitlement;
  if (!block || block.enforced !== true) {
    return {
      level: "off",
      enforced: false,
      status: subscription?.status ?? "",
      writes: "allowed",
      graceEndsAt: "",
      entitled: subscription?.entitled ?? true,
    };
  }
  const writes = block.writes === "grace" || block.writes === "refused" ? block.writes : "allowed";
  return {
    level: writes === "allowed" ? "ok" : writes === "grace" ? "grace" : "refused",
    enforced: true,
    status: subscription?.status ?? "",
    writes,
    graceEndsAt: block.grace_ends_at ?? "",
    entitled: subscription?.entitled ?? false,
  };
}

/** Render an RFC3339 instant for humans, falling back to the raw string. */
export function formatInstant(iso) {
  if (!iso) return "";
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return String(iso);
  return at.toLocaleString();
}

/**
 * The user-facing text for a state, as `{ tone, headline, detail }`.
 *
 * `tone` is `"none" | "info" | "warning" | "billing"`; `"billing"` is deliberately
 * NOT `"error"`, because a 402 is not a fault of the user's device, their key or
 * their permissions.
 */
export function describeEntitlement(state) {
  switch (state?.level) {
    case "grace":
      return {
        tone: "warning",
        headline: state.graceEndsAt
          ? `Subscription lapsed — uploading new changes stops on ${formatInstant(state.graceEndsAt)}.`
          : "Subscription lapsed — uploading new changes will stop soon.",
        detail:
          `Billing status: ${state.status || "unknown"}. Everything still works right now. ` +
          `${WHAT_IS_REFUSED} ${NEVER_REFUSED}`,
      };
    case "refused":
      return {
        tone: "billing",
        headline: "Payment required — the server is refusing new uploads for this account.",
        detail:
          `Billing status: ${state.status || "unknown"}${
            state.graceEndsAt ? `; the grace period ended ${formatInstant(state.graceEndsAt)}` : ""
          }. This is a BILLING state, not a sign-in problem and not a bug — the server ` +
          `authenticated and authorized this device and then asked for payment. ` +
          `${WHAT_IS_REFUSED} ${NEVER_REFUSED}`,
      };
    case "ok":
      return {
        tone: "info",
        headline: "Subscription active.",
        detail: `Billing status: ${state.status || "unknown"}. Writes are allowed.`,
      };
    default:
      return { tone: "none", headline: "", detail: "" };
  }
}

/**
 * The user-facing text for an actual `402` refusal, from the server's OWN body.
 *
 * Uses the server's `detail` verbatim (it is written to be shown) and adds the
 * never-refused sentence, so a client cannot accidentally render a refusal
 * without also rendering what still works.
 */
export function describePaymentRequired(err) {
  return {
    tone: "billing",
    headline: "Payment required — that upload was refused because the subscription lapsed.",
    detail:
      `${err.detail} ` +
      `Billing status: ${err.subscriptionStatus || "unknown"}${
        err.graceEndedAt ? `; the grace period ended ${formatInstant(err.graceEndedAt)}` : ""
      }. This is a BILLING state, NOT an authentication or permission failure. ` +
      `${NEVER_REFUSED}`,
  };
}
