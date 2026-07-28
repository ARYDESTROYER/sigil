// sync.mjs — a tiny, framework-free, dependency-free ESM transport that moves
// OPAQUE sealed containers to/from a dev sigild op-log over plain HTTP.
//
// It is the JS twin of the `sigil` CLI's push/pull: it shuttles already-sealed
// bytes and NEVER inspects or interprets a container's contents. It performs NO
// cryptography — confidentiality comes entirely from the caller sealing the
// bytes (via the wasm seal_to_container / hybrid_seal_to_container) BEFORE push.
// The sigild server is zero-knowledge: it stores and returns the exact bytes.
//
// Works in BOTH Node (v20+, global fetch) and the browser (fetch + atob): the
// only environment-specific bit is base64 decoding, which is feature-detected
// (Buffer in Node, atob in the browser).
//
// AUTHENTICATION is OPTIONAL and injected, never built in: both functions take
// an optional `opts.fetch` — any `fetch`-shaped function. With it omitted they
// use `globalThis.fetch` and behave EXACTLY as they always have (the
// unauthenticated dev path, byte-identical). `device-auth.mjs` supplies a
// signing fetch (`makeSignedFetch`) to speak sigild's multi-device contract v3,
// so the transport itself stays auth-agnostic and does no cryptography.
//
// The sigild op-log HTTP contract this speaks (dev-only, unauthenticated when
// SIGILD_OPLOG_PUBKEY is unset):
//   PUSH  POST {base}/v1/vaults/{vaultId}/ops   body = RAW container bytes
//         -> 201 JSON { vaultID, seq }
//   PULL  GET  {base}/v1/vaults/{vaultId}/ops?since={n}&limit={m}
//         -> 200 JSON { vaultID, ops:[{seq, blob, hash}], next, has_more }
//         where blob and hash are STANDARD-base64 strings.
//
// Pre-audit / UNAUDITED / DEV / LOCALHOST / PLAIN-HTTP demo. No TLS, no auth on
// this path. Do NOT point it at a remote host or use it for real secrets.

// How many ops to request per page when draining. The server clamps ?limit to
// [1, 1000]; 500 is its default and a comfortable page size for small containers.
const PULL_PAGE_LIMIT = 500;

// Decode a standard-base64 string into a Uint8Array, working in Node (Buffer)
// and the browser (atob). This is the only runtime-specific primitive here.
function base64ToBytes(b64) {
  if (typeof Buffer !== "undefined") {
    // Node: Buffer handles standard base64 directly.
    return new Uint8Array(Buffer.from(b64, "base64"));
  }
  // Browser: atob -> binary string -> bytes.
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Join a base URL and a path without doubling or dropping the slash.
function joinUrl(baseUrl, path) {
  return `${baseUrl.replace(/\/+$/, "")}${path}`;
}

// pushContainer — POST the raw container bytes to the op-log and return the
// server-assigned sequence number.
//
//   baseUrl        e.g. "http://127.0.0.1:8080"
//   vaultId        the vault to append to (opaque id; a single path segment)
//   containerBytes Uint8Array | ArrayBuffer | Buffer — the RAW sealed container
//   opts.fetch     OPTIONAL fetch-shaped function (default globalThis.fetch);
//                  device-auth.mjs passes a contract-v3 signing fetch here
//   -> { seq }     the monotonic sequence assigned by the server
//
// Throws a clear Error on any non-201 response.
export async function pushContainer(baseUrl, vaultId, containerBytes, opts = {}) {
  const body =
    containerBytes instanceof Uint8Array
      ? containerBytes
      : new Uint8Array(containerBytes);

  // `.bind` matters: browsers reject a WebIDL `fetch` invoked with a `this` that
  // is not the global (Illegal invocation).
  const doFetch = opts.fetch ?? globalThis.fetch.bind(globalThis);
  const url = joinUrl(baseUrl, `/v1/vaults/${encodeURIComponent(vaultId)}/ops`);
  const res = await doFetch(url, {
    method: "POST",
    // Opaque bytes — an octet-stream, never decoded by the server.
    headers: { "Content-Type": "application/octet-stream" },
    body,
  });

  // Additive (Phase 56): hand the RAW Response to an optional observer before it
  // is consumed, so a caller can read RESPONSE HEADERS. sigild sets its
  // X-Sigil-Entitlement* warning headers on a write it is still SERVING inside
  // the grace period — a 2xx — so that warning is unreachable from the parsed
  // body. A throwing observer must never break sync: this moves bytes, it does
  // not render UI.
  //
  // ⚠️ Cross-origin, those headers are only readable if the server lists them in
  // Access-Control-Expose-Headers (sigild's CORS middleware does).
  if (typeof opts.onResponse === "function") {
    try {
      opts.onResponse(res);
    } catch {
      /* an observer's failure is not a transport failure */
    }
  }

  if (res.status !== 201) {
    const text = await res.text().catch(() => "");
    const err = new Error(
      `pushContainer: expected 201 from ${url}, got ${res.status} ${res.statusText}${
        text ? ` — ${text.trim()}` : ""
      }`,
    );
    // Additive: carry the status so an auth-aware caller can tell 401 from 403
    // without parsing the message. The message text itself is unchanged.
    err.status = res.status;
    // Additive (Phase 56): carry the RAW body too, so a caller can read a
    // MACHINE-READABLE refusal — notably sigild's 402 payment-required body,
    // which names the billing status and what is still allowed — without
    // re-parsing prose out of `message`.
    err.body = text;
    throw err;
  }

  const json = await res.json();
  if (typeof json.seq !== "number") {
    throw new Error(`pushContainer: 201 response missing numeric seq: ${JSON.stringify(json)}`);
  }
  return { seq: json.seq };
}

// pullContainers — drain a vault from `sinceOpt` (default 0) and return every op
// newer than it, in ascending seq order, with each container base64-DECODED back
// to the exact bytes that were pushed.
//
//   baseUrl   e.g. "http://127.0.0.1:8080"
//   vaultId   the vault to read
//   sinceOpt  fetch ops with seq > sinceOpt (default 0 = from the start)
//   opts.fetch OPTIONAL fetch-shaped function (default globalThis.fetch)
//   -> [{ seq, container: Uint8Array, hash }]
//
// The server pages: it returns up to `limit` ops plus { next, has_more }. This
// loops since=next until has_more is false, accumulating every op, so the caller
// gets the whole vault in one call regardless of size.
export async function pullContainers(baseUrl, vaultId, sinceOpt = 0, opts = {}) {
  let since = Number(sinceOpt) || 0;
  const out = [];
  const doFetch = opts.fetch ?? globalThis.fetch.bind(globalThis);

  for (;;) {
    const url = joinUrl(
      baseUrl,
      `/v1/vaults/${encodeURIComponent(vaultId)}/ops?since=${since}&limit=${PULL_PAGE_LIMIT}`,
    );
    const res = await doFetch(url, { method: "GET" });
    if (res.status !== 200) {
      const text = await res.text().catch(() => "");
      const err = new Error(
        `pullContainers: expected 200 from ${url}, got ${res.status} ${res.statusText}${
          text ? ` — ${text.trim()}` : ""
        }`,
      );
      // Additive: see pushContainer — the status (and, since Phase 56, the raw
      // body) ride along for auth-aware callers.
      err.status = res.status;
      err.body = text;
      throw err;
    }

    const json = await res.json();
    const ops = Array.isArray(json.ops) ? json.ops : [];
    for (const op of ops) {
      out.push({
        seq: op.seq,
        // base64 -> raw container bytes (the server returned them verbatim).
        container: base64ToBytes(op.blob),
        // The server's hex/std-base64 chain hash, passed through untouched.
        hash: op.hash,
      });
    }

    // Advance to the server's cursor and stop when the vault is drained.
    if (!json.has_more) break;
    // Defensive: if next didn't advance, stop rather than loop forever.
    if (typeof json.next !== "number" || json.next <= since) break;
    since = json.next;
  }

  // Already ascending by seq (the server returns them in order), but sort to be
  // safe across pages.
  out.sort((a, b) => a.seq - b.seq);
  return out;
}
