// fake-sigild.mjs — a tiny in-memory stand-in for sigild's dev routes, for the
// BROWSER client test suites (web/apps/webapp and extension/).
//
// ⚠️ WHAT THIS IS NOT. It is NOT sigild and it proves NOTHING about sigild. It
// does not verify a single signature, does not enforce ownership or grants, and
// does not implement the entitlement gate — it just returns the shapes. Protocol
// conformance against the REAL server is proven elsewhere and stays there:
//   * sigil-wasm/test/device-auth-interop.mjs   (contract v3 against a live sigild)
//   * sigil-wasm/test/sharing-interop.mjs       (vault sharing, both directions)
//   * sigil-wasm/test/recovery-interop.mjs      (the recovery kit, both directions)
//   * cli/tests/e2e-recovery.sh                 (twelve steps, real sigild + real CLI)
//
// WHAT IT IS FOR: driving a BROWSER UI end to end in Playwright without a Go
// toolchain, so a spec can assert what the UI does — including restoring on a
// genuinely CLEAN PROFILE while the server still holds the account, the device
// registry, the wrapped envelopes and the sealed vault.
//
// ⭐ EVERYTHING CRYPTOGRAPHIC IN THOSE SPECS IS STILL REAL. This server never
// decodes a container, never decodes an envelope and holds no key: it relays the
// exact bytes it was given, exactly as sigild does. The wrap, the unwrap, the
// Argon2id sealing, the HKDF derivation of a recovery kit and every TOTP code all
// happen for real in the browser's wasm.
//
// ⚠️ CORS IS OFF BY DEFAULT HERE, EXACTLY AS IT IS IN sigild. An earlier version
// of this file always sent `Access-Control-Allow-Origin: *`, which made six
// browser specs pass green while the real path — a page on one origin talking to
// a sigild on another — was blocked by the browser and completely dead. A test
// double that is more permissive than the thing it doubles hides precisely the
// failures it exists to catch.
//
// A caller that needs cross-origin access must pass an EXPLICIT allowlist, which
// is what a real sigild needs too (SIGILD_CORS_ORIGINS):
//
//   startFakeSigild({ corsOrigins: ["http://127.0.0.1:3210"] })
//
// The MV3 extension passes nothing: an extension page with a host permission is
// exempt from CORS, so its specs prove the no-CORS path.
//
// ⚠️⚠️ THE RULE THIS FILE LIVES UNDER: A DOUBLE MUST NEVER BE MORE PERMISSIVE
// THAN THE THING IT DOUBLES. That is not a style preference — the CORS default
// above is the scar: an always-`*` fake made six browser specs green while the
// real path was completely dead. An audit found four MORE axes where this file
// was laxer than sigild and said so nowhere, so each is now ENFORCED here rather
// than merely disclaimed:
//   1. the CATCH-ALL answers 501 for unimplemented /v1/ routes (sigild's
//      dev-gated routes are "501 by default, NEVER 404"); a 404 inside the double
//      inverted that invariant, so a client that mistook 501 for 404 — or vice
//      versa — would look correct here;
//   2. key-envelope PUT enforces the 16 KiB cap (`MAX_KEY_ENVELOPE_BYTES`) -> 413;
//   3. hybrid-key PUT validates BOTH halves' LENGTHS (32 / 1184) -> 400, which is
//      the only look sigild ever takes at key material;
//   4. key-envelope PUT checks the RECIPIENT EXISTS and is NOT REVOKED
//      -> 404 device_not_found / 409 device_revoked.
//
// ⚠️ WHAT IS STILL LAXER, STATED EXPLICITLY SO NOBODY INFERS OTHERWISE. It
// verifies NO SIGNATURE, enforces NO ownership/grant/authorization, applies NO
// entitlement gate beyond the `refuseWrites` switch, has NO rate limiting, NO
// nonce/replay window, NO account seat cap, NO hash chain and NO self-only check
// on the per-device envelope index. A spec here can therefore prove what the
// BROWSER does, and NOTHING about what sigild would allow. Every one of those
// lives in the real-server suites listed above.

import { createServer } from "node:http";
import { createHash } from "node:crypto";

// Mirrors sigild: store.MaxKeyEnvelopeBytes, api.maxHybridKeyBodyBytes,
// store.X25519PublicKeyLen, store.MLKEM768EncapsKeyLen, api.maxRecipientIndexRows.
const MAX_KEY_ENVELOPE_BYTES = 16 * 1024;
const MAX_HYBRID_KEY_BODY_BYTES = 8 * 1024;
const X25519_PUBLIC_KEY_LEN = 32;
const MLKEM768_ENCAPS_KEY_LEN = 1184;
const MAX_RECIPIENT_INDEX_ROWS = 500;

/** Decoded byte length of a std-base64 string, or -1 when it is not one. */
function b64len(value) {
  if (typeof value !== "string" || value === "") return -1;
  try {
    return Buffer.from(value, "base64").length;
  } catch {
    return -1;
  }
}

const SIGIL_HEADERS = [
  "content-type",
  "x-sigil-device",
  "x-sigil-timestamp",
  "x-sigil-nonce",
  "x-sigil-signature",
  "x-sigil-enroll-token",
  "x-sigil-admin-token",
].join(", ");

/**
 * Mirror sigild's allowlist semantics: echo the presented origin ONLY when it is
 * on the list, never `*`, never with credentials mode, always with Vary: Origin.
 * With an empty list this sets NOTHING — the default, matching a default sigild.
 */
function makeCors(allowed) {
  const list = new Set(allowed.map((o) => String(o).toLowerCase()));
  return function cors(req, res) {
    if (list.size === 0) return false;
    res.setHeader("Vary", "Origin");
    const origin = req.headers.origin ?? "";
    if (!origin || !list.has(origin.toLowerCase())) return false;
    res.setHeader("Access-Control-Allow-Origin", origin);
    // ⚠️ MUST MATCH `corsExposedResponseHeaders` in sigild/internal/api/cors.go.
    // "Date" is on that list because it is NOT one of the seven CORS-safelisted
    // response headers, so a browser reads null for it cross-origin — which is
    // what the clock-skew diagnostic depends on. This double omitting it made
    // the webapp's "Check clock" spec report NO READING against a server whose
    // real counterpart answers fine: a double that is more RESTRICTIVE than the
    // thing it stands in for fails an honest test, which is the benign
    // direction, but it is still a divergence and it still cost a debug cycle.
    res.setHeader(
      "Access-Control-Expose-Headers",
      "X-Request-ID, Date, X-Sigil-Entitlement, X-Sigil-Entitlement-Status, X-Sigil-Entitlement-Grace-Ends",
    );
    return true;
  };
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

/**
 * Start the fake on a free loopback port.
 *
 *   const server = await startFakeSigild();
 *   server.baseUrl                       // http://127.0.0.1:<port>
 *   server.subscription = {...}          // what GET /v1/billing/subscription says
 *   server.refuseWrites = true           // make gated WRITES answer sigild's 402
 *   await server.close();
 *
 * `refuseWrites` deliberately gates ONLY the three write surfaces sigild's own
 * gate is called from (op append, key-envelope deposit, grant) and leaves every
 * read serving — mirroring ADR 0043's asymmetry, so a spec that asserted a read
 * still worked would go red if a client started refusing reads by itself.
 *
 * `corsOrigins` is an EXPLICIT allowlist and defaults to EMPTY, so by default
 * this fake is as CORS-hostile as a default sigild.
 */
export async function startFakeSigild({ accountId = "acc_fake_1", corsOrigins = [] } = {}) {
  const cors = makeCors(corsOrigins);
  const state = {
    accountId,
    devices: new Map(), // deviceId -> { device_id, label, status, account_id, public_key }
    hybridKeys: new Map(), // deviceId -> { x25519_public_key, mlkem_encaps_key, updated_at }
    envelopes: new Map(), // `${vaultId}\0${deviceId}` -> { bytes, sender, createdAt }
    ops: new Map(), // vaultId -> [Buffer]
    invites: [],
    nextDevice: 1,
    nextInvite: 1,
  };

  const api = {
    state,
    /** GET /v1/billing/subscription answers with this verbatim. */
    subscription: { subject: accountId, status: "active", entitled: true },
    /** When true, the three GATED WRITE surfaces answer sigild's 402 body. */
    refuseWrites: false,
    /** Recorded request lines, for assertions like "the code never hit the wire". */
    log: [],
    /** Page cap of the per-device envelope index. Shrinkable so a spec can reach
     *  the has_more branch without creating 500 envelopes. */
    indexPageCap: MAX_RECIPIENT_INDEX_ROWS,
  };

  const json = (res, status, body, extraHeaders = {}) => {
    cors(res.req, res);
    for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  };

  const paymentRequired = (res) =>
    json(res, 402, {
      error: "payment_required",
      detail:
        "this account's subscription has lapsed and its grace period has ended, so new writes " +
        "are refused; reading your existing vault contents, collecting your key envelopes, and " +
        "giving another device of THIS account the key to a vault (including creating a recovery " +
        "kit) are NOT affected",
      subscription_status: "canceled",
      grace_ended_at: "2026-07-01T00:00:00Z",
      reads_allowed: true,
      key_recovery_allowed: true,
      checkout_path: "/v1/billing/checkout",
    });

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    const path = url.pathname;
    const method = req.method ?? "GET";
    api.log.push(`${method} ${req.url}`);

    if (method === "OPTIONS") {
      // A preflight is answered ONLY for an allowlisted origin. With no
      // allowlist this replies with NO CORS header at all, which the browser
      // rejects — exactly what a default sigild does.
      if (cors(res.req, res)) {
        res.setHeader("Access-Control-Allow-Methods", "GET, HEAD, POST, PUT, DELETE, OPTIONS");
        res.setHeader("Access-Control-Allow-Headers", SIGIL_HEADERS);
        res.setHeader("Access-Control-Max-Age", "600");
      }
      res.writeHead(204);
      res.end();
      return;
    }

    const body = await readBody(req);
    const seg = path.split("/").filter(Boolean); // e.g. ["v1","vaults","x","keys","dev_1"]

    // ── account ──────────────────────────────────────────────────────────────
    if (path === "/v1/account" && method === "GET") {
      const devices = [...state.devices.values()];
      return json(res, 200, {
        account_id: state.accountId,
        created_at: "2026-01-01T00:00:00Z",
        device_count: devices.filter((d) => d.status === "active").length,
        revoked_device_count: devices.filter((d) => d.status !== "active").length,
        device_limit: 10,
        devices,
      });
    }

    if (path === "/v1/account/invites" && method === "POST") {
      const id = `inv_${state.nextInvite++}`;
      const secret = `invite-secret-${id}-0123456789abcdef`;
      state.invites.push({ invite_id: id, secret });
      return json(res, 201, {
        invite_id: id,
        invite: secret,
        account_id: state.accountId,
        expires_at: "2099-01-01T00:00:00Z",
        pinned: true,
      });
    }

    // ── devices ──────────────────────────────────────────────────────────────
    if (path === "/v1/devices/enroll" && method === "POST") {
      let parsed = {};
      try {
        parsed = JSON.parse(body.toString("utf8"));
      } catch {
        return json(res, 400, { error: "bad_request" });
      }
      const id = `dev_fake_${state.nextDevice++}`;
      const device = {
        device_id: id,
        label: parsed.label ?? "",
        status: "active",
        created_at: new Date().toISOString(),
        account_id: state.accountId,
        public_key: parsed.public_key ?? "",
      };
      state.devices.set(id, device);
      return json(res, 201, device);
    }

    if (seg[0] === "v1" && seg[1] === "devices" && seg[3] === "revoke" && method === "POST") {
      const device = state.devices.get(seg[2]);
      if (!device) return json(res, 401, { error: "unauthorized" });
      device.status = "revoked";
      return json(res, 200, { device_id: device.device_id, revoked: true });
    }

    if (seg[0] === "v1" && seg[1] === "devices" && seg[3] === "hybrid-key") {
      if (method === "PUT") {
        if (body.length > MAX_HYBRID_KEY_BODY_BYTES) {
          return json(res, 413, { error: "too_large" });
        }
        let parsed = {};
        try {
          parsed = JSON.parse(body.toString("utf8"));
        } catch {
          return json(res, 400, { error: "bad_request" });
        }
        // ⭐ THE ONLY LOOK SIGILD EVER TAKES AT KEY MATERIAL: a LENGTH CHECK on
        // both halves. Never a curve-point parse — it holds no decapsulation key
        // and decodes nothing.
        if (
          b64len(parsed.x25519_public_key) !== X25519_PUBLIC_KEY_LEN ||
          b64len(parsed.mlkem_encaps_key) !== MLKEM768_ENCAPS_KEY_LEN
        ) {
          return json(res, 400, { error: "bad_hybrid_key" });
        }
        state.hybridKeys.set(seg[2], {
          x25519_public_key: parsed.x25519_public_key,
          mlkem_encaps_key: parsed.mlkem_encaps_key,
          updated_at: new Date().toISOString(),
        });
        return json(res, 200, { device_id: seg[2], updated_at: new Date().toISOString() });
      }
      if (method === "GET") {
        const key = state.hybridKeys.get(seg[2]);
        if (!key) return json(res, 404, { error: "hybrid_key_not_found" });
        return json(res, 200, { device_id: seg[2], ...key });
      }
    }

    // Self-only envelope INDEX — how a restored kit learns what it can decrypt.
    if (seg[0] === "v1" && seg[1] === "devices" && seg[3] === "keys" && method === "GET") {
      const vaults = [];
      let hasMore = false;
      for (const [k, v] of state.envelopes) {
        const [vaultId, deviceId] = k.split("\0");
        if (deviceId !== seg[2]) continue;
        // Same hard page cap as sigild's maxRecipientIndexRows, and the same
        // absence of a cursor. `api.indexPageCap` lets a spec shrink it so the
        // TRUNCATION branch is reachable without minting 500 envelopes.
        if (vaults.length >= api.indexPageCap) {
          hasMore = true;
          break;
        }
        vaults.push({
          vaultID: vaultId,
          sender_device_id: v.sender,
          size_bytes: v.bytes.length,
          created_at: v.createdAt,
        });
      }
      return json(res, 200, { device_id: seg[2], vaults, has_more: hasMore });
    }

    // ── vault key envelopes ──────────────────────────────────────────────────
    if (seg[0] === "v1" && seg[1] === "vaults" && seg[3] === "keys" && seg.length === 5) {
      const key = `${seg[2]}\0${seg[4]}`;
      if (method === "PUT") {
        // GATED WRITE #2 in sigild.
        if (api.refuseWrites) return paymentRequired(res);
        // The opaque envelope has a hard size cap; over it is 413, never a store.
        if (body.length > MAX_KEY_ENVELOPE_BYTES) {
          return json(res, 413, { error: "too_large" });
        }
        // The recipient must be an ENROLLED, NON-REVOKED device. A double that
        // accepted a deposit addressed to nobody would hide a whole class of
        // client bug behind a cheerful 201.
        const recipient = state.devices.get(seg[4]);
        if (!recipient) return json(res, 404, { error: "device_not_found" });
        if (recipient.status !== "active") return json(res, 409, { error: "device_revoked" });
        const createdAt = new Date().toISOString();
        state.envelopes.set(key, {
          bytes: Buffer.from(body),
          sender: req.headers["x-sigil-device"] ?? "",
          createdAt,
        });
        return json(res, 201, {
          vaultID: seg[2],
          device_id: seg[4],
          size_bytes: body.length,
          created_at: createdAt,
        });
      }
      if (method === "GET") {
        const env = state.envelopes.get(key);
        if (!env) return json(res, 404, { error: "not_found" });
        cors(res.req, res);
        res.writeHead(200, { "Content-Type": "application/octet-stream" });
        return res.end(env.bytes);
      }
      if (method === "DELETE") {
        if (!state.envelopes.delete(key)) return json(res, 404, { error: "envelope_not_found" });
        return json(res, 200, { vaultID: seg[2], device_id: seg[4], deleted: true });
      }
    }

    if (seg[0] === "v1" && seg[1] === "vaults" && seg[3] === "keys" && seg.length === 4) {
      if (method === "GET") {
        const recipients = [];
        for (const [k, v] of state.envelopes) {
          const [vaultId, deviceId] = k.split("\0");
          if (vaultId !== seg[2]) continue;
          recipients.push({
            device_id: deviceId,
            sender_device_id: v.sender,
            size_bytes: v.bytes.length,
            created_at: v.createdAt,
          });
        }
        recipients.sort((a, b) => a.device_id.localeCompare(b.device_id));
        return json(res, 200, { vaultID: seg[2], recipients });
      }
    }

    // ── grants ───────────────────────────────────────────────────────────────
    if (seg[0] === "v1" && seg[1] === "vaults" && seg[3] === "grants") {
      if (method === "POST") {
        // GATED WRITE #3 in sigild.
        if (api.refuseWrites) return paymentRequired(res);
        let parsed = {};
        try {
          parsed = JSON.parse(body.toString("utf8"));
        } catch {
          return json(res, 400, { error: "bad_request" });
        }
        return json(res, 201, {
          vaultID: seg[2],
          device_id: parsed.device_id,
          permission: parsed.permission,
        });
      }
      if (method === "GET") return json(res, 200, { vaultID: seg[2], grants: [] });
    }

    // ── the op-log ───────────────────────────────────────────────────────────
    if (seg[0] === "v1" && seg[1] === "vaults" && seg[3] === "ops" && seg.length === 4) {
      const vaultId = decodeURIComponent(seg[2]);
      if (method === "POST") {
        // GATED WRITE #1 in sigild.
        if (api.refuseWrites) return paymentRequired(res);
        const list = state.ops.get(vaultId) ?? [];
        list.push(Buffer.from(body));
        state.ops.set(vaultId, list);
        return json(res, 201, { vaultID: vaultId, seq: list.length });
      }
      if (method === "GET") {
        // ⭐ NEVER gated, even when refuseWrites is on. Reads are never refused.
        const since = Number(url.searchParams.get("since") ?? 0) || 0;
        const list = state.ops.get(vaultId) ?? [];
        const ops = list
          .map((blob, i) => ({ seq: i + 1, blob }))
          .filter((op) => op.seq > since)
          .map((op) => ({
            seq: op.seq,
            blob: op.blob.toString("base64"),
            hash: createHash("sha256").update(op.blob).digest("base64"),
          }));
        return json(res, 200, {
          vaultID: vaultId,
          ops,
          next: list.length,
          has_more: false,
        });
      }
    }

    // ── billing ──────────────────────────────────────────────────────────────
    if (path === "/v1/billing/subscription" && method === "GET") {
      // ⭐ Never gated by entitlement: refusing to tell a customer why they are
      // being refused, because they are being refused, would be absurd.
      return json(res, 200, api.subscription);
    }

    // ⭐ CATCH-ALL. sigild's dev-gated surface answers 501 — never 404 — when the
    // dev flag is off, so an UNIMPLEMENTED /v1/ route here answers 501 too. A 404
    // would have inverted that invariant inside the double.
    if (seg[0] === "v1") {
      return json(res, 501, { error: "not_implemented" });
    }
    return json(res, 404, { error: "not_found" });
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  api.baseUrl = `http://127.0.0.1:${port}`;
  // ⚠️ DROP KEEP-ALIVE SOCKETS FIRST, or close() can outlive the test hook.
  //
  // `server.close()` stops accepting NEW connections and then waits for every
  // in-flight one to end. A browser holds its HTTP/1.1 connections open for
  // reuse, so with a real Chromium driving this double there is usually at least
  // one idle keep-alive socket and `close()` waits on it — under parallel load,
  // past Playwright's hook timeout. That surfaced as
  //   `1 failed … passkey.spec.ts:46:6  await fake?.close()`
  // during a full gate run, while the same spec passed in 1.6 s on its own: a
  // TEARDOWN race reported as a product failure, in a security suite, which is
  // exactly the kind of noise that gets a red result waved through.
  //
  // `closeAllConnections()` (Node >= 18.2) severs them immediately. It is
  // optional-chained so an older runtime degrades to the previous behaviour
  // rather than throwing, and the callback's error is ignored deliberately —
  // "the server was already closed" is not a test failure.
  api.close = () =>
    new Promise((resolve) => {
      server.closeAllConnections?.();
      server.close(() => resolve());
    });
  return api;
}
