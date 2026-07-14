# 0022 — Client↔server sync loop for the wasm client (`sync.mjs` over the dev op-log)

- **Status:** Accepted — 2026-07.

## Context

The client column of the architecture has been climbing toward parity with the
native CLI. `sigil-wasm` ([ADR 0019](0019-wasm-client-bindings.md)) first ran the
core's `seal_record` / `open_record` in a JS runtime; then it gained `SIGILcli`
container interop with the CLI on the password path
([ADR 0020](0020-shared-client-container-format.md)); then the `SIGILhyb`
hybrid public-key path ([ADR 0021](0021-wasm-hybrid-public-key-encryption.md)).
All of that is **crypto that runs entirely on one client** — it seals and opens
bytes, but it never crosses the trust boundary to a server.

The `sigild` op-log already exists as the server half of the sync story: a
dev-gated ([ADR 0003](0003-dev-gated-opaque-op-log.md)), **opaque**, append-and-read
byte journal that the `sigil` CLI already push/pulls to over plain HTTP. The whole
point of the architecture is that what crosses the boundary is an **already-sealed,
opaque** container, so the server can store and re-emit it without ever holding a
key or plaintext. To **demonstrate the full end-to-end E2EE sync architecture** —
not just client-side crypto — the wasm client should reach that server too, and it
should **interoperate with the CLI through it** (browser writes / CLI reads and
vice-versa), which is the concrete proof that both clients speak the same container
**and** the same op-log contract.

The constraints that shaped every prior wasm decision still hold: keep all
cryptography in `#![forbid(unsafe_code)]` `sigil-core`, keep the wasm crate
`getrandom`-free and standalone, and don't invent a new server contract or a new
container format for a pre-audit demo.

## Decision

**Add a small, framework-free, dependency-free JS `fetch` module
([`../../sigil-wasm/sync.mjs`](../../sigil-wasm/sync.mjs)) that moves opaque sealed
containers to/from the existing dev `sigild` op-log, keep all cryptography in the
wasm, reuse the op-log contract unchanged, and prove the loop against a *live*
sigild and the *real* CLI rather than a mock.** Four subordinate choices:

- **The transport is plain JS `fetch`; the crypto stays in wasm.** `sync.mjs`
  exports two functions — `pushContainer(baseUrl, vaultId, containerBytes)` and
  `pullContainers(baseUrl, vaultId, since)`. It performs **no cryptography** and
  never inspects a container: the caller seals with the wasm
  (`seal_to_container` / `hybrid_seal_to_container`) *before* pushing, and opens
  with the wasm *after* pulling. The JS only shuttles bytes. This keeps the
  crypto/transport split the rest of the repo depends on and adds **no** crypto to
  a non-`forbid(unsafe_code)` surface.
- **Reuse the existing dev op-log contract verbatim — no new server surface.**
  `pushContainer` POSTs the **raw container bytes** to `POST /v1/vaults/{id}/ops`
  (→ `201 {vaultID, seq}`); `pullContainers` drains
  `GET /v1/vaults/{id}/ops?since=&limit=` (→
  `{vaultID, ops:[{seq, blob, hash}], next, has_more}`, `blob`/`hash`
  standard-base64), looping `since=next` until `has_more` is false and
  base64-decoding each `blob` back to the exact bytes. This is byte-for-byte the
  same contract `sigil push` / `sigil pull` already speak
  ([ADR 0017](0017-oplog-scale-and-observability.md) for the pagination shape), so
  `sigild` is **unchanged**.
- **Run in both Node and the browser with zero deps.** The only
  environment-specific primitive is base64 decoding; it is feature-detected
  (`Buffer` in Node, `atob` in the browser). `fetch` is global in both. So the same
  module backs the Node integration test and the browser demo's Sync section.
- **Prove it with a live server + the real CLI, not a mock.** A Node integration
  test ([`../../sigil-wasm/test/sync-interop.mjs`](../../sigil-wasm/test/sync-interop.mjs))
  builds `sigild` (`go build ./cmd/server`) and the real `sigil` CLI
  (`cargo build --bin sigil`), boots a live sigild on a free localhost port
  (`SIGILD_ENABLE_DEV_OPS=1`, in-memory backend, no auth), polls `/readyz`, and
  always kills the server in a `finally`. It asserts: a **client self-loop** (wasm
  seal → push → pull → wasm open); **CLI writes / browser reads** (`sigil seal` +
  `sigil push` → JS pull → `wasm.open_container`); **browser writes / CLI reads**
  (wasm seal + JS push → `sigil pull` + `sigil open`); and an **OPAQUE** check that
  a raw `GET …/ops` blob base64-decodes to **exactly** the pushed bytes — the
  server returned them verbatim and did no crypto.

## Consequences

- **The full E2EE sync architecture is demonstrable end-to-end for the client
  column.** A browser/Node client can now seal a container, push it to the server,
  pull it back, and open it — and interoperate with the CLI through the same vault.
  This is the first time the wasm client crosses the trust boundary to a server.
- **Cross-client interop is proven against the real CLI, both directions.** Because
  the browser and `sigil` share the `SIGILcli` container **and** the op-log
  contract, `sigil seal`+`push` → wasm open and wasm seal+push → `sigil pull`+`open`
  both round-trip, checked against the **actual** built CLI binary — not a
  re-implementation. If either the container format or the contract drifts, a proof
  fails.
- **The server stays zero-knowledge.** The transport ships opaque bytes and the
  OPAQUE assertion pins that the server returns them verbatim; the container is
  sealed client-side before it ever leaves. `sigild` holds no key and no plaintext,
  exactly as the threat model requires.
- **It is dev / localhost / plain-HTTP / no-auth, and not the product sync model.**
  The test boots sigild with no `SIGILD_OPLOG_PUBKEY` (unauthenticated) over plain
  HTTP on loopback. `sync.mjs` must not be pointed at a remote host or used for real
  secrets. It is a **demonstration** of the sync loop — there is still **no** real
  auth / device enrollment / per-vault authorization, and **no** CRDT / conflict-free
  merge / operation semantics (the op-log stays a plain append-and-read byte journal;
  cf. [ADR 0016](0016-tamper-evident-oplog-hash-chain.md) on tamper-evidence, not
  merge). A real product sync/auth model is a future, separate decision.
- **The integration test needs four toolchains.** `sync-interop.mjs` is heavier than
  the pure-JS round-trip tests: it requires Go (to build sigild), Rust/cargo (to
  build the CLI), Node (to run), and the wasm `pkg-node/` artifact (built by
  `build-wasm.sh`). It builds sigild and the CLI itself and always tears the server
  down, so it is self-contained but slower — an accepted cost for a real end-to-end
  proof over a mock.
