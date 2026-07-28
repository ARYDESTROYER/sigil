# 0044 — Opt-in, allowlisted CORS on a signature-authenticated API — and why it is not a CSRF control

- **Status:** Accepted (2026-07)
- **Date:** 2026-07-28
- **Builds on:** [0031](0031-multi-device-auth-model.md) (contract v3 — the
  per-request Ed25519 signature that is the *only* thing authenticating a
  request, and the `X-Sigil-*` headers that are the reason a preflight happens at
  all), [0033](0033-browser-device-identity-storage.md) (the browser clients that
  hold a device key), [0005](0005-stdlib-only-sigild.md) (why this is 170 lines of
  `net/http` and not a CORS library), [0009](0009-manual-gated-deploy-and-publish.md)
  (the reverse-proxy topology this defers to in production).

## Context

Since [ADR 0031](0031-multi-device-auth-model.md), every authenticated request a
client makes to `sigild` carries `X-Sigil-Device`, `X-Sigil-Timestamp`,
`X-Sigil-Nonce` and `X-Sigil-Signature`. None of those is a CORS-safelisted
request header, so a **browser preflights every one of them** with an `OPTIONS`
request before the real request leaves the page.

`sigild` routed no `OPTIONS` method and emitted no `Access-Control-*` header
anywhere. `grep -rin access-control sigild/` returned **nothing**, and a real
preflight was answered **`405 Method Not Allowed`**. In a real Chromium, against
a real `sigild`, the result was:

```
Access to fetch at 'http://127.0.0.1:8080/v1/devices/enroll' from origin
'http://127.0.0.1:3210' has been blocked by CORS policy: Response to preflight
request doesn't pass access control check: No 'Access-Control-Allow-Origin'
header is present on the requested resource.
```

So **from the webapp, enrollment, sync, sharing, restore-from-a-recovery-kit and
the entitlement read were all dead** — not slow, not degraded: blocked by the
browser before a byte was sent. The **MV3 extension was unaffected**, because an
extension page with a matching `host_permissions` entry is exempt from CORS, and
its suite therefore stayed honest throughout.

Two things about how this was found belong in the record.

**It is pre-existing.** The gap dates from Phase 44, when the browser clients
first learned to sign requests. It went unnoticed for twelve phases because
nothing browser-level ever talked to a real `sigild`: the Node interop suites use
a real server but are not a browser, and the browser suites were not talking to a
real server.

**And the phase that found it had just made it harder to see.** Phase 56's own
new test double, `sigil-wasm/test/fake-sigild.mjs`, sent
`Access-Control-Allow-Origin: *` unconditionally. Six new webapp specs passed
green — including the specs for the flagship deliverable, browser restore — while
the real path was dead. **A test double that is more permissive than the thing it
doubles hides exactly the failures it exists to catch.**

## Decision

### 1. An opt-in, exact-match origin allowlist — `SIGILD_CORS_ORIGINS`

`SIGILD_CORS_ORIGINS` is a comma-separated list of **exact** origins (scheme +
host + optional port, nothing else):

```
SIGILD_CORS_ORIGINS=http://127.0.0.1:3000,http://localhost:3000
```

It is parsed and normalized by `validateCORSOrigins` in `cmd/server`, **before
the listener binds**, like every other configuration value in this server. A
malformed entry — a path, a query, a trailing slash, embedded credentials, a
non-`http(s)` scheme, a stray comma leaving no origins at all — is a **startup
failure**, never a silent fallback to something permissive.

### 2. ⭐ UNSET means byte-identical, structurally

With no allowlist configured, `NewRouter` **does not install the middleware at
all**. It is not a middleware that checks a flag on every request; it is absent
from the chain. No response carries an `Access-Control-*` header, no response
carries `Vary: Origin`, and `OPTIONS` still falls through to the mux and is still
answered `405`.

A verifier swept **45 responses across 9 paths × 5 methods** with an `Origin`
header present against a default server and found **zero `Access-Control-*`
lines**, with `OPTIONS` still `405` — the pre-CORS behaviour, reproduced.

### 3. `*` is refused at boot, not accepted and narrowed

```
SIGILD_CORS_ORIGINS=*   ⇒  rc=1, the listener never binds
```

with a message that says why: *"a wildcard is REFUSED: this API carries
per-request signed credentials, so every origin allowed to reach it must be named
explicitly. In production serve the app and the API from the SAME origin behind
the reverse proxy and set nothing here."*

Accepting `*` and then quietly treating it as "the origins I would have allowed
anyway" is the kind of helpfulness that makes a configuration file mean something
other than what it says. A wildcard here is either a mistake or a decision nobody
wrote down, and both should stop a boot rather than survive one.

### 4. What the middleware does, exactly

| | |
|---|---|
| `Vary: Origin` | added on **every** response the middleware touches, allowed or not — no cache may serve one origin the header computed for another |
| `Access-Control-Allow-Origin` | the **echoed** request origin, and **only** when it is on the list. Never `*`, never a stored value the request did not present |
| `Access-Control-Allow-Credentials` | ⛔ **never set** (§5) |
| `Access-Control-Expose-Headers` | `X-Request-ID` plus the three `X-Sigil-Entitlement*` headers |
| preflight (`OPTIONS` + `Access-Control-Request-Method`, allowed origin) | **`204`**, with `Access-Control-Allow-Methods`, an explicit `Access-Control-Allow-Headers` naming exactly the `X-Sigil-*` set the four clients send, and `Access-Control-Max-Age: 600` |
| preflight from an **unknown** origin | falls through to the mux and is answered `405`, exactly as before — so there is no probe that distinguishes *"this route exists"* from *"your origin is allowed"* |
| a preflight the middleware answers | reaches **no handler**: it never touches the op-log, the device registry, a rate limiter or the database |

`Access-Control-Expose-Headers` is not incidental. The entitlement warning
headers ([ADR 0043](0043-entitlement-enforcement.md)) are not on the CORS-safelist,
so without exposing them a browser client cannot read its own grace warning — and
telling a customer *before* their writes stop is the entire point of that
channel.

The middleware sits **innermost** in the chain, closest to the mux, so a
preflight it answers is still counted, still assigned a request ID and still
appears in the access log.

**No new dependency.** It is `net/http` and `strings`. `sigild/go.mod` still has
**exactly one** direct require (`pgx`).

### 5. ⭐ THIS IS NOT AN AUTHENTICATION CONTROL, AND IT IS NOT A CSRF CONTROL

This is the part that decides everything above, and the part most likely to be
misread by someone who has configured CORS on an ordinary cookie-session API.

`sigild` issues **no cookie, no session and no bearer token that a browser
attaches ambiently**. Every authenticated request is authenticated by a
**per-request Ed25519 signature over a canonical message**
(`canonicalV3Message`, [ADR 0031](0031-multi-device-auth-model.md)), computed
from a private key the requesting page holds and binding the method, the path,
the query, a timestamp, a fresh nonce and the body.

A hostile cross-origin page has no such key. It cannot forge a signature, so it
cannot make an authenticated request **whatever CORS says**. Therefore:

- **`Access-Control-Allow-Credentials` is never set**, and there is nothing for
  it to enable.
- **CORS here provides no CSRF protection that the signature did not already
  provide.** The classic CSRF shape — a hostile page causing the browser to
  attach *your* ambient credential to *its* request — has no analogue here,
  because there is no ambient credential.
- The allowlist is consequently **not a security boundary**, and this ADR
  deliberately does not claim it as one.

What it *is* for: (a) the browser half of the product works at all; (b) the set
of origins permitted to reach a given server is a **deliberate, written-down
operator decision** rather than an accident of whichever page happened to load;
and (c) a browser-side failure becomes an honest configuration error instead of
an unexplained network error.

### 6. Production should not need this

**A production deployment should serve the app and the API from the same origin
behind the reverse proxy.** Caddy already fronts `sigild` in every topology this
repo documents ([`deployment.md`](../deployment.md)), so a same-origin path
prefix needs **no origin listed at all** and leaves this file inert.

`SIGILD_CORS_ORIGINS` exists for the **localhost dev topology**, where the webapp
is on `:3000` and `sigild` on `:8080` and the two are necessarily different
origins. That is why it is opt-in, why it is off by default, and why the boot log
says so out loud when it is on:

> `CORS ENABLED for an explicit browser origin allowlist — this is for the
> LOCALHOST DEV topology; in production serve the app and the API from the SAME
> origin behind the reverse proxy. No credentials mode is enabled and no wildcard
> is possible; every request is still authenticated by its own per-request
> signature`

### 7. The test double was corrected to match

`fake-sigild.mjs` now sends **no** CORS header unless a test passes an explicit
`corsOrigins` allowlist — the same shape a real `sigild` requires. The MV3
extension suite passes nothing, so it proves the no-CORS path that its
`host_permissions` actually take.

The browser-level proof of the fix is `web/apps/webapp/tests/cors.spec.ts`, which
builds and boots the **real** `sigild` and asserts **both** directions: with
`SIGILD_CORS_ORIGINS` set the browser enrols, and **without** it the browser is
blocked — the pre-fix behaviour, reproduced on demand, so the spec cannot pass
vacuously. It needs the Go toolchain and **skips** without it, which is why
`actions/setup-go` was added to the `webapp` CI job: without it the only
browser-level proof of this decision would silently skip while the job stayed
green.

## The sentence an auditor should be able to check

> With `SIGILD_CORS_ORIGINS` unset — the default — no middleware is installed and
> no response differs by one byte from a pre-CORS server; with it set, the server
> echoes **only** an allowlisted origin, never `*`, refuses a wildcard **at
> boot**, and **never** sets `Access-Control-Allow-Credentials` — and none of
> that authenticates anything, because every authenticated request is
> authenticated by its own per-request Ed25519 signature and a cross-origin page
> holds no key with which to forge one.

## Consequences

### Good

- **The webapp can reach a real server.** Enrollment, sync, sharing,
  restore-from-kit and the entitlement read work from a browser page for the
  first time since Phase 44.
- **Off is genuinely off** — structurally, not conditionally: the middleware is
  absent from the chain, proven by a 45-response sweep.
- **A wildcard is unreachable by typo.** The most common CORS mistake is a boot
  failure here.
- **The failure mode of the four clients is now visible.** A browser client
  pointed at a server that has not listed it fails with a CORS error the operator
  can act on, rather than a mystery.
- **No new dependency, no new auth path, no new route, no migration.**
  `sigild_schema_version` stays **5** and there is still exactly one direct Go
  dependency.
- **The test double is now weaker than the real server, not stronger** — the only
  safe direction for a double to differ.

### Bad / honest limitations

1. ⚠️ **CORS constrains browsers and nothing else.** `curl`, the `sigil` CLI, the
   desktop app and any hostile script outside a browser ignore it completely. It
   is **not an access control**, and must never be read as one; authorization is
   still the signature plus the grant model.
2. ⚠️ **It does not make the dev transport safe.** An allowlisted origin over
   plain `http://` is still cleartext on the wire, still dev-gated, still
   pre-audit, still **UNAUDITED**.
3. **Exact match only.** No wildcards, no subdomain patterns, no regex, no
   `null` origin. Adding or removing an origin is an env change and a restart —
   deliberate, and inconvenient by design.
4. **`Access-Control-Max-Age: 600` means removal is not instant.** An origin
   dropped from the allowlist can still have up to ten minutes of cached
   preflight in an already-open browser. Ten minutes is the chosen trade against
   re-preflighting every signed request.
5. **No Private Network Access handling.** The middleware sends no
   `Access-Control-Allow-Private-Network`. If a browser enforces PNA for a page
   reaching `localhost`, this would need revisiting; it is not handled today.
6. **The browser-level proof is skippable.** `cors.spec.ts` requires Go and skips
   without it. CI now carries Go for that job, but a developer running the webapp
   suite on a machine without Go gets a green run that proved nothing about CORS.
   The skip is visible in the Playwright output; it is not silent, but it is easy
   to miss.
7. **This was a twelve-phase-old hole found by accident.** Nothing in the repo
   structurally prevents the next browser-only defect: the browser suites still
   run against a double for everything except this one spec.

### Neutral

- The allowed-request-header list is written out (`Content-Type`, `X-Request-ID`,
  and the six `X-Sigil-*` headers) rather than wildcarded, so an operator reading
  `cors.go` can see the entire cross-origin request surface in one place. A new
  client header must be added there — a small, deliberate cost.
- `Vary: Origin` is added even for origins that are refused, which is slightly
  more conservative than strictly necessary and keeps every cache-correctness
  argument to one sentence.

## Alternatives rejected

- **Do nothing; tell developers to run a proxy.** Rejected: the repo's own
  documented dev topology is two ports, four client surfaces are supposed to be
  peers, and "the browser client silently cannot reach the server" is exactly the
  class of defect this phase existed to fix.
- **`Access-Control-Allow-Origin: *`, unconditionally.** Rejected. It is *not*
  the disaster it would be on a cookie API — there is no ambient credential to
  abuse — but it makes the reachable surface undocumented and unbounded, and it
  removes the operator's ability to say which pages this server is for. It is
  refused loudly rather than quietly discouraged.
- **Echo any `Origin` presented (reflect-all).** Rejected for the same reason,
  plus it looks like an allowlist while being none.
- **A CORS library.** Rejected under [ADR 0005](0005-stdlib-only-sigild.md): the
  behaviour is ~40 lines of header setting, and a dependency here would be an
  opaque answer to a question an auditor should be able to read.
- **Enable credentials mode.** Rejected: there is no cookie and no session, so it
  would grant nothing and would tell a future reader that ambient authority
  exists.
- **Treat CORS as the CSRF defence and relax the signature.** Rejected outright.
  The signature is the authentication; CORS is a browser convention layered on
  top of it, and it constrains only browsers.
- **Leave the test double permissive "because it is only a double".** Rejected —
  it is the reason six specs were green over dead code. A double may be *less*
  capable than the real thing; it must never be **more permissive**.
- **Add CORS to the ordinary `web.yml` marketing job.** Not applicable, and worth
  saying: the marketing build stays toolchain-free. Only the `webapp` job carries
  Rust + wasm-pack, and now Go.

## References

- Code: [`../../sigild/internal/api/cors.go`](../../sigild/internal/api/cors.go)
  (the middleware and the reasoning in full),
  [`../../sigild/cmd/server/corsconfig.go`](../../sigild/cmd/server/corsconfig.go)
  (`validateCORSOrigins`, `normalizeCORSOrigin`),
  [`../../sigild/internal/api/router.go`](../../sigild/internal/api/router.go)
  (`Config.CORSOrigins`, installed innermost and only when non-empty),
  [`../../sigild/cmd/server/main.go`](../../sigild/cmd/server/main.go) (fail-fast
  validation before the bind, and the boot warning).
- Tests: [`../../sigild/internal/api/cors_test.go`](../../sigild/internal/api/cors_test.go),
  [`../../sigild/cmd/server/corsconfig_test.go`](../../sigild/cmd/server/corsconfig_test.go),
  and the browser-level proof
  [`../../web/apps/webapp/tests/cors.spec.ts`](../../web/apps/webapp/tests/cors.spec.ts)
  (real Chromium, real `sigild`, both directions).
- The corrected double:
  [`../../sigil-wasm/test/fake-sigild.mjs`](../../sigil-wasm/test/fake-sigild.mjs).
- Contract: [`../api.md`](../api.md) — the `SIGILD_CORS_ORIGINS` section.
- Operator runbook: [`../deployment.md`](../deployment.md) §18.
- What is actually authenticating the request:
  [ADR 0031](0031-multi-device-auth-model.md) and [`../api.md`](../api.md)
  (signed request contract v3).
