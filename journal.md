# Sigil — build journal

Running log of everything done, why, and what's next. **Update frequently and in
depth** (start/end of each session, after every decision/build/test/scope change).
Newest entries at the bottom of each day. Dates are absolute.

Conventions: ✅ done & verified · 🟡 in progress · ⛔ deferred (out of 72h scope) ·
⚠️ risk/gotcha · ➡️ next.

---

## ⭐ RESUME ANCHOR — state of play (keep current; read this first)

**Where we are (through Phase 37, `main` @ origin, clean tree).** Phase 37 turned the
reserved `web/apps/webapp` into a **real Next.js 15 app that runs libsigil via
WebAssembly, entirely client-side** — a live TOTP demo over a new **`@sigil/wasm`**
workspace loader package (which wasm-packs the repo-root `sigil-wasm` crate for a
bundler target and reuses the proven `totp-vault`/`sync`/`totp-migration` JS helpers).
The first real browser product surface; dev / no-index / UNAUDITED, kept out of the
default web CI build (needs the Rust + wasm-pack toolchain), marketing/CI unchanged.
Proven GREEN in a real browser by a headless Playwright smoke (the wasm renders the
RFC 6238 vector `287082` at t=59). ADR 0027; details in the Phase 37 entry below.
Phase 36 brought the
**browser client to TOTP import/export parity with the CLI**, so **both clients now
have full 2FA import/export**. A framework-free, dependency-free ESM module
**`sigil-wasm/totp-migration.mjs`** gives the browser the same Google Authenticator
bulk import (`otpauth-migration://offline?data=<BASE64>`) + single-account `otpauth://`
import/export as the CLI (`decodeMigrationUri` / `encodeMigrationUri` / `parseOtpauthUri`
/ `buildOtpauthUri` + `base32Encode`), wired into the demo (`demo/index.html` +
`demo/main.js`). It is a **hand-rolled, dependency-free proto3 codec that MIRRORS
`cli/src/migration.rs`** (+ the `otpauth://` parse/build in `cli/src/lib.rs`) — no
protobuf library, no wasm bridge — so the migration codec now lives in BOTH Rust (cli)
and JS (sigil-wasm) and MUST stay in sync, exactly like the `SIGILcli`/`SIGILhyb`
container constants and the `TotpVault`/`TotpEntry` vault JSON. VERIFIED GREEN by a Node
CLI↔JS cross-tool agreement test **`sigil-wasm/test/migration-interop.mjs`** (no server;
builds the real `sigil` CLI) proving both codecs wire-compatible THREE ways: **GOLDEN**
— the canonical documented Google Authenticator example URI decodes in JS to secret
base32 `JBSWY3DPEHPK3PXP`, name `Example:alice@google.com`, issuer `Example`, sha1, 6
digits (the same golden vector the CLI's own Rust test asserts); **RUST→JS** — `sigil
totp export --migration` decodes in JS to the CLI's accounts (names/algorithms/digits +
every secret base32 == the CLI's own `otpauth://` export); and **JS→RUST** — a
JS-`encodeMigrationUri` URI is accepted by `sigil totp import` and confirmed by `totp
list` + the CLI's `otpauth://` export carrying the exact secret bytes. No vault-schema /
container change (pure edge translation). `export` reveals the 2FA secrets IN THE CLEAR
by design (an export IS plaintext provisioning material). Dev/UNAUDITED — do NOT
import/export real 2FA secrets yet. ADR 0026. Phase 35 gave the
CLI **TOTP import/export** so users can migrate 2FA **in** (adoption) and back **out**
(no lock-in). `sigil totp import <ARG>` ingests a **Google Authenticator** bulk-export
`otpauth-migration://offline?data=<BASE64>` URI, a single `otpauth://` URI, or a file
of URIs (one per line, `#` comments skipped); `sigil totp export [<label>]` prints
entries as `otpauth://` URIs or (with `--migration`) ONE combined
`otpauth-migration://` URI, to stdout or `--out <file>` (0600). The migration format
is a **protobuf** `MigrationPayload`, decoded/encoded by a **hand-rolled, dependency-free
protobuf codec** (`cli/src/migration.rs`: proto3 varint + length-delimited wire types
only — NO protobuf crate, mirroring the hand-rolled base32) with `decode_migration_uri`/
`encode_migration_uri` + the `MigrationOtp`↔`TotpEntry` converters. VERIFIED GREEN by a
**golden vector** (the canonical documented Google Authenticator export decodes to
secret `JBSWY3DPEHPK3PXP` = `b"Hello!" ‖ DE AD BE EF`, name `Example:alice@google.com`,
issuer `Example`, SHA1/SIX/TOTP) and **encode→decode + `TotpEntry`→migration→back
round-trips** (plus truncation + unknown-field-skip tests). HOTP entries in a payload
are **warned-and-skipped** (vault is TOTP-only); the vault's `TotpVault` JSON schema is
**UNCHANGED** (browser mirror intact); duplicate labels are skipped, not overwritten.
`export` prints **SECRETS IN THE CLEAR** by design (an export IS plaintext provisioning
material) behind a loud stderr warning. No new dep; Dev/UNAUDITED — do NOT import/export
real 2FA secrets yet. ADR 0025. Phase 34 made the
authenticator work **CROSS-CLIENT (CLI ↔ browser) through the opaque server** — the
**first end-to-end product feature spanning two clients and the op-log**. `sigil-wasm`
gained three `#[wasm_bindgen]` OTP exports over the core primitive (ADR 0023) — `totp`
/ `hotp` / `format_code` — with **JS supplying the time** (`unix_time`/`t0`/`counter`
arrive as `f64`, validated to non-negative integers before the `u64` cast; `algorithm`
string map mirrors the CLI's), so the crate stays `getrandom`-free. A framework-free ESM
module **`sigil-wasm/totp-vault.mjs`** (`openVault`/`sealVault`/`addEntry`/`codeForEntry`/
`newVault`) reads/writes the **same sealed `SIGILcli` TOTP vault the `sigil totp` CLI
uses**; the **`TotpVault`/`TotpEntry` JSON schema is MIRRORED — not shared — between
`cli/src/lib.rs` and `totp-vault.mjs`** (version 1; `label`, optional `issuer`, `secret`
= STANDARD base64 of raw key bytes, lowercase `algorithm`, `digits`, `period`) and must
stay in sync. Because the vault is just another opaque container it rides the existing
`sync.mjs` op-log transport unchanged, so a secret added on ONE client and synced through
the zero-knowledge op-log yields the SAME code on the other. VERIFIED GREEN by
**`sigil-wasm/test/totp-interop.mjs`**: wasm TOTP KAT (RFC 6238 App B, T=59, sha1/256/512)
+ CLI `totp add` → push → browser pull → `openVault` → `codeForEntry(T=59)` == RFC
`94287082` == an independent Node HMAC-SHA-1 TOTP, with the server returning the pushed
bytes verbatim (opaque). The browser `demo/` gained a **TOTP authenticator vault** section
(add a base32 secret, live codes, Seal→Push / Pull→Open). UNAUDITED, dev/localhost, GENERATE
only; do NOT store real 2FA secrets. ADR 0024. Phase 33 shipped
the **FIRST REAL PRODUCT FEATURE** — the authenticator function itself. libsigil-core
gained an **HOTP/TOTP** one-time-password primitive (`hotp`/`totp`/`format_code` over
an `OtpAlgorithm` enum — SHA-1 (default)/SHA-256/SHA-512; `totp.rs`): **RFC 4226 HOTP**
(dynamic truncation) + **RFC 6238 TOTP**, the FIRST primitive that implements an actual
product FEATURE rather than a building block. It is verified GREEN against the **RFC
4226 App D** and **RFC 6238 App B** known-answer vectors (`rfc4226_appendix_d_hotp_sha1`,
`rfc6238_appendix_b_totp_all_hashes`, both PASS). `totp` takes the current Unix time as
a CALLER-SUPPLIED `u64` — the core reads NO clock and NO RNG, so the wasm-pure/no-RNG
contract (ADR 0007) is intact; two new deps `hmac` (keyed MAC; already transitive via
`hkdf`, now direct) + the NEW `sha1` (HMAC-SHA-1 is the near-universal `otpauth://`
default → interop requires it), both `default-features = false` so `getrandom`==0 in
`libsigil/Cargo.lock` still holds. The demo CLI wired it into an **encrypted TOTP vault**
— `sigil totp add|list|code|remove` (base32 + `otpauth://` import) — with the 2FA secrets
sealed at rest in the SAME `SIGILcli` password container as `seal`/`open` (so a vault is
just another opaque sealed container, E2EE at rest, op-log-syncable later). Live demo
VERIFIED: `totp add work --secret <b32> --issuer Acme` + `totp add --uri
"otpauth://totp/Acme:bob?..."` → `list` (2 entries, secret never printed) → `code work`
→ `620863 (valid for 9s)`; the on-disk vault begins with magic `SIGILcli` (sealed-at-rest
check); a WRONG password fails with `Aead(Authentication)` (no plaintext leak); `remove
work` drops it. Core totp tests 8/8 PASS, CLI tests 40/40 PASS, core `getrandom`==0. Real
but UNAUDITED (only GENERATES codes — verification left to callers); do NOT store real 2FA
secrets yet. ADR 0023. Phase 32 **CLOSED
THE CLIENT↔SERVER E2EE SYNC LOOP** for the client column: **`sigil-wasm/sync.mjs`**
— a tiny, framework-free, dependency-free ESM transport (`pushContainer` /
`pullContainers`, the JS twin of `sigil push` / `sigil pull`) — push/pulls **OPAQUE**
sealed containers to/from the dev `sigild` op-log over `fetch`. It does **no crypto**
(the wasm seals before push) and reuses the existing op-log contract verbatim:
`pushContainer` POSTs raw bytes to `POST /v1/vaults/{id}/ops` (→ 201 `{vaultID, seq}`),
`pullContainers` drains `GET …/ops?since=&limit=` (→ `{vaultID, ops:[{seq, blob,
hash}], next, has_more}`, base64 blobs, loops `since=next` until `has_more=false`).
Runs in **both Node** (`fetch`+`Buffer`) **and the browser** (`fetch`+`atob`,
feature-detected); the `demo/` gained a **Sync** section. Proven GREEN by
**`test/sync-interop.mjs`**, which builds `sigild` + the **real** CLI, boots a LIVE
sigild on a free port (`SIGILD_ENABLE_DEV_OPS=1`, in-memory, no auth) and asserts
PROOF 1 client self-loop, PROOF 2 **CLI writes / browser reads**, PROOF 3 **browser
writes / CLI reads**, and OPAQUE (a raw `GET …/ops` blob base64-decodes to EXACTLY
the pushed bytes → **server did no crypto, zero-knowledge intact**). Dev / localhost
/ plain-HTTP / no-auth, UNAUDITED; NOT the product sync model (no real auth /
enrollment / CRDT). ADR 0022. Phase 31 brought
**HYBRID public-key (no-password) encryption to `sigil-wasm`**: four new
`#[wasm_bindgen]` exports — `hybrid_x25519_public` / `hybrid_mlkem_encaps_key` /
`hybrid_seal_to_container` / `hybrid_open_container` — encrypt a file **to** a
device's hybrid identity (**X25519 + ML-KEM-768**) into the same **`SIGILhyb`**
container the CLI uses (`HYBRID_MAGIC` `SIGILhyb`, version 1, `eph_x25519_pub[32]`,
`mlkem_ct[1088]`, envelope; AEAD `sigil-hybrid-cli/1`), the **FIRST browser
exercise of the PQ-hybrid encryption path**. Entropy stays JS-supplied (X25519
secret / ML-KEM seed / ephemeral secret / coin / nonce via `getRandomValues`) and
Node bridges the CLI identity JSON (the wasm crate never parses identity files).
`HYBRID_*` format consts are MIRRORED — not shared — in `cli/src/lib.rs` +
`sigil-wasm/src/lib.rs` (MUST stay in sync), guarded by a native golden
fixed-prefix test + a Node interop test (`test/hybrid-interop.mjs`) that shells to
the REAL built CLI both directions (A: wasm seals / `sigil hybrid-open`; B: `sigil
hybrid-seal` / wasm opens) — **bidirectional interop PASS**, both `Cargo.lock`s
still **getrandom==0**. A custom KEM-then-AEAD (NOT RFC 9180 HPKE), UNAUDITED demo,
NOT the product key model; the SYSTEM is NOT "post-quantum secure" (ADR 0021).
Phase 30 made
`sigil-wasm` **INTEROPERABLE with the `sigil` CLI**: new `seal_to_container`/
`open_container` exports read+write the exact same `SIGILcli` container (magic
`SIGILcli`, version 1, Argon2 params `u32`-LE, `u8`-len salt, envelope; AEAD
`sigil-cli/1`), so **seal-in-browser ↔ `sigil open`** works both ways. Format
constants are MIRRORED (not shared) in `cli/src/lib.rs` + `sigil-wasm/src/lib.rs`
with a sync comment, guarded by a native golden-header test + a Node interop test
(`test/interop.mjs`) that shells to the REAL built CLI both directions — VERIFIED
GREEN, both `Cargo.lock`s still getrandom==0. A pre-audit CLI/demo container, NOT a
frozen product wire format (ADR 0020). Phase 29 opened
the **CLIENT COLUMN** (reserved until now): **`sigil-wasm`**, a standalone
`wasm-bindgen` binding that runs the core's `seal_record`/`open_record` in the
**browser + Node** — the FIRST thing to actually consume the wasm-pure core in a
JS runtime. It is deliberately **`getrandom`-free**: JS supplies the Argon2id salt
+ AEAD nonce via `crypto.getRandomValues`, so the caller-supplied-entropy
invariant is now proven end-to-end into a JS host (both `libsigil/Cargo.lock` AND
`sigil-wasm/Cargo.lock` are getrandom==0). Own `Cargo.lock` like `cli/` (not a
libsigil workspace member); build via `sigil-wasm/build-wasm.sh` → gitignored
`pkg-web/`+`pkg-node/`; proven by a Node round-trip test (PASS) + native `*_inner`
unit tests + a browser `demo/`. A DEMO of the UNAUDITED building block, NOT the
product account/key-management model (ADR 0019). Phase 28 gave
the durable Postgres op-log **managed, versioned embedded migrations**
(`schema_migrations`, applied under a session `pg_advisory_lock`; auto at boot or
via the `sigild migrate` / `sigild migrate status` operator CLI; opt out with
`SIGILD_OPLOG_AUTO_MIGRATE=0` → fail-fast), a **`sigild_schema_version`** gauge on
`/metrics`, and a **`pg_dump`/`pg_restore` backup runbook** whose restore
integrity is proved by the existing hash chain (`/ops/verify` re-yields the same
`tip_hash`) — pure stdlib+`pgx`+`go:embed`, opaque/zero-knowledge intact, dev
backend only (ADR 0018). libsigil-core
now has a COMPLETE but **UNAUDITED** hybrid crypto suite, all `no_std`,
wasm-pure, `getrandom`-free, caller-supplied-entropy (no in-core RNG):
- symmetric: Argon2id KDF, XChaCha20-Poly1305+HKDF AEAD, envelope codec,
  `seal_record`/`open_record`.
- signatures: Ed25519 (`sig.rs`) + ML-DSA-65 (`mldsa.rs`) + hybrid
  `hybrid_sign`/`hybrid_verify` (`hybrid_sig.rs`, verify needs both).
- KEM/KEX: X25519 (`kx.rs`) + ML-KEM-768 (`mlkem.rs`) + hybrid
  `hybrid_encapsulate`/`hybrid_decapsulate` (`hybrid.rs`, HKDF combiner).
- public-key encryption: `hybrid_seal`/`hybrid_open` (`hybrid_seal.rs`) — the
  hybrid KEM wired into a KEM-then-AEAD flow, encrypt a record TO a recipient's
  hybrid pubkey (custom composition, NOT RFC 9180 HPKE). FIRST hybrid primitive
  wired into an encryption flow; still standalone + unaudited (Phase 21).
- FFI (`libsigil/ffi`): seal/open/buffer_free + Ed25519 sign/verify/pubkey + the
  **hybrid encryption path** (`sigil_x25519_public_key`, `sigil_ml_kem768_keygen`,
  `sigil_hybrid_encapsulate`/`decapsulate`/`seal`/`open`; `SIGIL_ERR_HYBRID`) — a
  native client can generate a hybrid identity + encrypt-to-a-pubkey through the
  C-ABI (custom KEM-then-AEAD, NOT HPKE; UNAUDITED, not wired into a flow) (Phase 22).
- `sigild` (Go, ONE dep — `pgx`): probes + dev-gated (`SIGILD_ENABLE_DEV_OPS`) opaque
  op-log; **three `VaultLog` backends** — in-memory, file-backed (`SIGILD_OPLOG_DIR`),
  or **durable/concurrent Postgres** (`SIGILD_OPLOG_POSTGRES`; precedence PG > file >
  mem); optional Ed25519 **v2** request auth (`SIGILD_OPLOG_PUBKEY`, signed nonce +
  replay cache). Default 501. **Hardened for reliability + auditability (Phase 25):**
  `VaultLog` is request-context-aware (client-disconnect/timeout cancels in-flight
  storage work), `/readyz` pings the **live** backend (Postgres pool → `503` if down),
  `http.Server` read/write/idle timeouts + `pgxpool` limits, and a **structured audit
  log** (`oplog.append`/`list`/`auth_denied` metadata + a blob **SHA-256 fingerprint** —
  NEVER the blob content or any secret; zero-knowledge boundary intact). **Tamper-evident
  (Phase 26):** a per-op **SHA-256 hash chain** across all three backends via one
  canonical `chainHash` (each op commits to the previous), a per-op `hash` in the GET
  response, and `GET …/ops/verify` (`VerifyChain{ok,count,tip_hash,broken_at_seq}`); File
  format bumped v1→v2 + Postgres gains a hash column. The chain fingerprints the OPAQUE
  ciphertext (zero-knowledge intact) and is tamper-**EVIDENT not tamper-proof** — a
  hostile server can lie, so real verification is **client-side**. **Scaled + observable
  (Phase 27, all stdlib):** `GET …/ops` is **paginated** (`?limit`, default 500 / max
  1000, `has_more` + `next`; bad limit → `400 bad_limit`; `Since` cap pushed into every
  backend incl. a Postgres `LIMIT`); optional **per-vault stdlib token-bucket rate limit**
  (`SIGILD_OPLOG_RATE_LIMIT` + `SIGILD_OPLOG_RATE_BURST` → `429 rate_limited` +
  `Retry-After`, off by default, bounded/evicting map); an **always-on** stdlib
  **`GET /metrics`** Prometheus-text endpoint (counters only — appends/verify/ratelimit/
  auth-denied-by-reason/http-by-class/build_info; NO blob, key, or vault ID; never
  dev-gated); and **fail-fast config validation** (bad `SIGILD_ADDR`/rate/burst/pubkey →
  exit 1 BEFORE binding). ADR 0017. **Managed migrations (Phase 28, Postgres backend only):**
  versioned embedded migrations (`go:embed` `internal/store/migrations/NNNN_*.sql`, baseline
  `0001_init.sql`) tracked in a **`schema_migrations`** table, run under a session-level
  **`pg_advisory_lock`** (each in its own tx → safe concurrent boots), replacing the old
  inline DDL. Auto-applied at boot unless **`SIGILD_OPLOG_AUTO_MIGRATE=0`** (then fail-fast);
  operator CLI **`sigild migrate`** / **`sigild migrate status`**. Applied version exported as
  the **`sigild_schema_version`** gauge on `/metrics`. **Backup:** `pg_dump`/`pg_restore` dumps
  `blob`+`hash` byte-for-byte → hash chain survives; post-restore gate is `GET …/ops/verify`
  (`ok:true`, same `tip_hash`). ADR 0018.
- `cli` (`sigil`): seal/open/push/pull(incremental)/keygen + v2 request signing;
  plus **hybrid-keygen/hybrid-seal/hybrid-open** — public-key encrypt a file TO a
  device's hybrid identity (X25519 + ML-KEM-768) via the core's `hybrid_seal`/
  `hybrid_open` (Phase 23; FIRST user-facing use of the hybrid encryption path).
- `sigil-wasm` (Phase 29): standalone `wasm-bindgen` crate (own `Cargo.lock`, NOT
  a workspace member), thin binding over the core record API —
  `seal_record`/`open_record`/`nonce_len`/`recommended_salt_len`/`version` to JS.
  No crypto of its own; `getrandom`-free (JS supplies salt+nonce). `build-wasm.sh`
  (wasm-pack 0.13.1 / wasm-bindgen 0.2.100) → gitignored `pkg-web/`+`pkg-node/`;
  Node round-trip test + native `*_inner` tests + browser `demo/`. FIRST consumer
  of the wasm-pure core; UNAUDITED demo, not the product key model. ADR 0019.
  **Phase 30: now CLI-interoperable** — `seal_to_container`/`open_container` read+
  write the CLI's `SIGILcli` container (AAD `sigil-cli/1`), format mirrored in both
  `cli/src/lib.rs` + `sigil-wasm/src/lib.rs` (MUST stay in sync), proven by a Node
  interop test shelling to the real CLI both directions. ADR 0020.
  **Phase 31: now also HYBRID public-key** — `hybrid_x25519_public`/
  `hybrid_mlkem_encaps_key`/`hybrid_seal_to_container`/`hybrid_open_container`
  encrypt a file TO a device hybrid identity (X25519 + ML-KEM-768) into the CLI's
  `SIGILhyb` container (AAD `sigil-hybrid-cli/1`); `HYBRID_*` consts mirrored in
  `cli/src/lib.rs` + `sigil-wasm/src/lib.rs` (MUST stay in sync), proven by a Node
  interop test (`test/hybrid-interop.mjs`) shelling to the real CLI both directions.
  FIRST browser exercise of the PQ-hybrid path; custom KEM-then-AEAD not HPKE;
  getrandom==0 preserved. ADR 0021.
  **Phase 32: now CLOSES THE CLIENT↔SERVER SYNC LOOP** — `sync.mjs`
  (`pushContainer`/`pullContainers`) push/pulls the OPAQUE container to/from the dev
  `sigild` op-log over `fetch` (raw-bytes POST → `{vaultID, seq}`; paginated base64
  GET), no crypto in JS, reusing the existing op-log contract. `test/sync-interop.mjs`
  builds sigild + the real CLI, boots a LIVE sigild (dev-ops/in-mem/no-auth) and proves
  client self-loop + cross-client CLI↔wasm (both directions) + OPAQUE server (bytes
  verbatim, zero-knowledge). Dev/localhost/plain-HTTP/no-auth; NOT the product sync
  model. ADR 0022.
- web marketing splash; deploy = validated skeletons + manual GHCR publish +
  loopback stack (**nothing deployed/exposed; no domain**). ADRs 0001–0022.

**HARD INVARIANTS (never break; the commit gate checks them every phase):**
- `grep -c 'name = "getrandom"' libsigil/Cargo.lock` MUST be **0** (core is
  wasm-pure; the wasm32 build must pass). CLI is a SEPARATE crate (own lock) so
  it may use getrandom. `sigil-wasm` is ALSO a separate crate but is deliberately
  getrandom-FREE too (JS supplies entropy), so
  `grep -c 'name = "getrandom"' sigil-wasm/Cargo.lock` MUST **also** be **0**.
- `#![forbid(unsafe_code)]` in core; `#![deny(unsafe_op_in_unsafe_fn)]` in ffi.
- sigild now has **ONE dependency — `pgx`** — for the opt-in Postgres op-log backend
  (the module gained a `go.sum`; ADR 0014 relaxes ADR 0005 for exactly this backend).
  The **core server + the in-memory / file-backed backends stay stdlib-only**; `pgx`
  is dormant unless `SIGILD_OPLOG_POSTGRES` is set. No over-claims anywhere (never
  "audited"/"secure"/"post-quantum secure"/"SOC 2"/unqualified "E2E"); the SYSTEM
  is NOT post-quantum secure — honest UNAUDITED building blocks only.
- Core MSRV is **1.85** (ml-dsa forced it; machine rustc is 1.96; CI pins stable).
- Rust invocation: `export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/opt/homebrew/bin:$PATH"`.
- Deploy/publish/domain = **human-gated** (outward-facing/irreversible). Do NOT
  publish/apply/expose without explicit human approval.
- Working method: opus-4.8 sub-agent workflows (build ‖ verify ‖ document); I
  re-run the full gate MYSELF before every commit; keep `docs/` in sync in the
  SAME change; commit + push to `main` per phase.

**➡️ NEXT:** Phase 27 made the dev op-log **bounded, throttleable, and observable**
without touching its security posture (**ADR 0017**) — four **pure-stdlib** features, no
new dep (`pgx` stays the only one). (1) **Pagination:** `GET …/ops` takes `?limit`
(default 500, clamped to `[1,1000]`; non-integer → `400 bad_limit`) and returns
`has_more` beside `next`; the limit is a signature change on `VaultLog.Since(ctx, vaultID,
since, limit)` pushed into every backend, so Postgres applies it as a SQL `LIMIT` (not a
fetch-all-then-slice). A client drains a vault by looping `since = next` until
`has_more=false`. (2) **Rate limiting:** when `SIGILD_OPLOG_RATE_LIMIT` (+ optional
`SIGILD_OPLOG_RATE_BURST`) is set, each **vault ID** gets an independent stdlib
token-bucket (`ratelimit.go`, `sync.Mutex`+map+`time`); an append over the refill rate →
`429 rate_limited` + `Retry-After`; GET is never throttled; the map is bounded
(`rateLimiterMaxVaults=10000` + idle eviction). **Off by default** — unset ⇒ no wrapper,
behaviour unchanged. (3) **`/metrics`:** an **always-on** (NOT dev-gated), unauthenticated
`GET /metrics` renders a hand-written Prometheus-text exposition of process counters
(`sigild_oplog_appends_total`, `_verify_total`, `_ratelimit_rejected_total`,
`_auth_denied_total{reason}`, `sigild_http_requests_total{class}`,
`sigild_build_info{version}`) — counters + build version only, **never** a blob / key /
signature / nonce / vault ID (proven: a posted secret blob is absent from `/metrics`).
Counters are **per-router** (atomic, test-isolatable, not process-global). (4) **Fail-fast
config validation:** the startup path parses/validates `SIGILD_ADDR`, `SIGILD_OPLOG_RATE_
LIMIT`, `SIGILD_OPLOG_RATE_BURST`, and `SIGILD_OPLOG_PUBKEY` **before binding** and exits
non-zero with a clear message on any malformed value (proven: bad rate/burst/pubkey/addr
each → rc 1, port never bound). All proven live incl. real Postgres pagination
(`LIMIT` honored in SQL) and **all prior features intact** — default (no dev-ops) still
**501** on every ops verb, tamper-evidence still fires (`broken_at_seq=2` on a live PG
`UPDATE`), audit log still leaks no blob. ✅ **Doc drift reconciled at the commit gate:**
api.md / architecture.md / deployment.md / ADR 0017 had named the burst env
`SIGILD_OPLOG_BURST`, and api.md's metric table had `sigild_oplog_{verifies,auth_denials,
rate_limited}_total`; the code is authoritative (`SIGILD_OPLOG_RATE_BURST`;
`sigild_oplog_{verify,auth_denied,ratelimit_rejected}_total`) and the docs were corrected
in this same commit. Still a **dev op-log**
(dev-gated, default 501, unauthenticated unless `SIGILD_OPLOG_PUBKEY`), opaque blobs only,
no crypto on the plaintext; these are **dev-scale operability primitives** (in-process
limiter, process-local counters, boot-time validation), NOT production SLOs / a distributed
quota / a durable TSDB. It still owes the real data layer — auth / enrollment, per-vault
authorization, CRDT / merge, managed migrations, backups-with-restore, replication, and a
signed / Merkle-root production audit log. Next: **build that layer around the adapter**
(start with a real device-enrollment / per-vault authorization model), OR resume the
crypto wiring — a real device-enrollment / session / key-management flow behind the hybrid
primitives (Phase 21–23: how identities are minted, published, trusted, rotated). ⚠️
Wiring the hybrid **signature** into op-log auth is **still blocked**: Go's stdlib has no
ML-DSA, so op-log auth stays classical Ed25519 (v2) until we take a PQ-sig dependency or
move the check off the Go server. No account/session model uses `hybrid_seal` yet. The
full product is still early (~6% — see the completeness note); the mountain (7 native
clients, real backend/auth, payments, Cure53 audit, SOC2) is mostly untouched —
Phase 27 made one adapter bounded + observable, not the store.

---

## 2026-06-02 — Day 0/1: greenfield foundation scaffold

### Context & mandate
- Input: the Sigil v2 product/design/tech brief (61pp, a 12-month plan).
- Ask: a realistic 2–3 day deployment plan + domain availability, then **build it
  all from scratch and test everything**. Posture: pre-launch / stealth.
- Ground truth at start: repo was an empty `git init` (0 commits, 0 files, remote
  `github.com/ARYDESTROYER/sigil.git`). So this is pure greenfield scaffolding.

### Planning (done via a 9-agent workflow + adversarial critique)
- Committed 72h target: walled+no-index waitlist splash + committed monorepo with
  green CI + DNS/email foundation + backed-up Postgres. Stretch: live `sigild`
  over PQ-TLS; floor: healthz-only. Full plan recorded in `docs/sprint-72h.md`.
- The critique caught: fantasy hour budget, missing backups, privacy-policy
  sequencing, and that the local OpenSSL is LibreSSL (can't do PQ-TLS). All folded
  into `docs/sprint-72h.md`.

### Domain availability (live, via Vercel registrar)
- ⚠️ The bare **"Sigil" brand is taken on every credible TLD** (`sigil.app/.com/
  .io/.dev/.co/.net/.org/.xyz/.me/...`) and all common compounds (`get/use/try/
  join-sigil`, `sigilauth`, `sigilhq.com`, `sigilapp.com`). Shortlist fallbacks
  (`tessera/keepsake/witness/veil`) also taken on `.app`.
- Registrable: `sigilapp.io` ($38), `sigilhq.io` ($38), `sigilkeep.com` ($11),
  `vaultsigil.com` ($11), `heysigil.com` ($11), `sigil2fa.com` ($11).
- **Decision (user):** anchor working name on **`sigilapp.io`**. Used as a
  placeholder only; trademark knockout still runs before brand commitment.
  Domain not yet purchased (human action; outward-facing).

### Toolchains (macOS 14.8.2, arm64)
- Present at start: git, Homebrew, Node 20.12, Corepack, Docker. Missing: go, rust,
  pnpm, gh, cosign.
- Installed: **Go 1.26.3** (brew), **Rust stable rustc 1.96** (brew `rustup`),
  **pnpm 9.15** (corepack). 
- ⚠️ Homebrew `rustup` did **not** create `~/.cargo/bin` proxies and
  `rustup run stable cargo <subcmd>` failed to resolve subcommands. Fix:
  put `~/.rustup/toolchains/stable-aarch64-apple-darwin/bin` directly on PATH.
  Documented in `CLAUDE.md`.
- ⚠️ System `openssl` is LibreSSL → cannot negotiate `X25519MLKEM768`. The PQ-TLS
  proof (stretch) needs OpenSSL 3.5+/Go 1.24.x provisioned first.

### Built & verified

**libsigil (Rust workspace: `core` + `ffi`)** ✅
- `core` = `#![forbid(unsafe_code)]`, `no_std`; `AlgorithmSuite` registry (bytes
  0x10–0x15, current 0x12), `ENVELOPE_VERSION`, `from_byte`/`as_byte`/
  `is_post_quantum`, 6 unit tests. `ffi` = `cdylib`+`rlib` exporting
  `sigil_current_suite()` smoke test. No real crypto (intentional).
- Verified: `cargo fmt --check` OK · `cargo clippy --all-targets -D warnings`
  clean · `cargo test` 6 pass (5 core + 1 ffi) · `cargo build -p sigil-core
  --target wasm32-unknown-unknown` OK.

**sigild (Go, stdlib only — hermetic, no external deps)** ✅
- `cmd/server` (graceful shutdown, slog, env config); `internal/api` router using
  Go 1.22+ method+pattern mux: `GET /healthz`, `GET /readyz` (TCP-dial reachability
  of configured PG/Redis, 503 if a configured dep is unreachable, "unconfigured"
  otherwise), `GET|POST /v1/vaults/{vaultID}/ops` → 501 (no faked crypto).
  `internal/buildinfo` version var; stub packages `internal/{auth,vault,push,admin,
  store}`; `cmd/worker-{rehash,audit,breach}` stubs.
- Tests (`internal/api/handlers_test.go`): healthz 200, readyz-unconfigured 200,
  readyz-unreachable 503, ops 501 (GET+POST, body shape). 
- Decision: readyz uses plain `net.DialTimeout` (not pgx/redis) so the skeleton is
  dependency-free and tests run offline; documented to be swapped for real pings.
- Verified: `gofmt -l` clean · `go vet ./...` OK · `go test ./...` pass ·
  `go build ./...` OK.

**web/apps/marketing (Next.js 15 + React 19 + Tailwind 3, pnpm workspace)** ✅
- Stealth splash (minimal copy, zero security superlatives — see
  MARKETING-CLAIMS.md), client `WaitlistForm` (email + honeypot + unchecked-default
  consent), `POST /api/waitlist` (validates; **persistence intentionally stubbed**,
  returns 202 — no un-backed-up PII, no consent referencing an unpublished policy),
  `privacy`/`terms`/`imprint` stub pages, `robots.ts` Disallow /, layout robots
  noindex, `next.config.mjs` `X-Robots-Tag`+security headers, `middleware.ts`
  Basic-Auth wall (no-op when `SITE_PASSWORD` unset), `public/.well-known/
  security.txt`.
- Fix applied: literal `//` logo text tripped `react/jsx-no-comment-textnodes` →
  wrapped as `{"//"}`.
- Verified: `pnpm typecheck` OK · `pnpm lint` clean · `pnpm build` OK (9 routes +
  middleware generated).

**CI / security** ✅
- `.github/workflows/{libsigil,sigild,web}.yml` (path-filtered, mirror the local
  commands), inert `release.yml` (`if: false` — cosign/SLSA deferred),
  `.github/dependabot.yml` (cargo/gomod/npm/actions), `.gitleaks.toml`.

**Docs / meta** ✅
- `README.md`, `LICENSE` (split explainer), `LICENSE-APACHE` (canonical, curl'd),
  `.gitignore`/`.editorconfig`/`.nvmrc`/`CODEOWNERS`/`SECURITY.md`.
- `docs/{crypto-spec,threat-model,sprint-72h,README}.md` (internal/pre-audit).
- `CLAUDE.md` (this guide) + `journal.md` (this file).

### Decisions & justifications
- **Stdlib-only sigild** for the skeleton → hermetic builds/tests, no network in
  CI, no `go.sum`. Real pgx/redis come with the real endpoints.
- **Hand-rolled Next app** (not create-next-app) → exact control of no-index +
  Basic-Auth + claims discipline; pinned Next 15.1.6 / React 19.0.0 / Tailwind 3.
- **No faked crypto/persistence anywhere** → protects the future Cure53 story and
  the "have read the privacy policy" consent validity.
- **Anchor `sigilapp.io` as placeholder**, brand/trademark unresolved.

### ⛔ Deferred (out of 72h scope — see docs/sprint-72h.md defer ledger)
- libsigil crypto correctness; full sigild API + workers + ClickHouse; webapp/
  admin/extension/native clients; live payments + Stripe/Razorpay verification;
  permanent App Store bundle ID; status page; Nomad/K8s/multi-region; reproducible
  Nix builds + working cosign/SLSA; Cure53 completion; SOC 2/ISO.

### ➡️ Next (this session)
1. `sigild/LICENSE` (BSL-1.1); `deploy/` stubs (Caddy, systemd, Terraform, Nomad);
   leaf READMEs for reserved dirs.
2. Full test sweep across all three toolchains again + validate CI YAML parses.
3. Summarize; **hold** commit/push/domain-purchase/deploy for explicit human OK.

### ⚠️ Operational note
- Output is being intermittently blocked by an upstream content filter (false
  positives on security/crypto language + secret-looking strings). Mitigation:
  smaller chunks, no verbatim secret-like strings. Files already written are intact.

### Session close — final verification sweep ✅ (all green)
- **Rust:** `cargo fmt --check` OK · `clippy --all-targets -D warnings` clean ·
  `cargo test` 4 suites green · `wasm32-unknown-unknown` build OK.
- **Go:** `gofmt -l` clean · `go vet ./...` OK · `go test ./...` pass ·
  `go build ./...` OK.
- **Runtime smoke (real binary):** built with version ldflags; `/healthz`→200
  (`version: v0.0.1-skeleton`), `/readyz`→200 (deps unconfigured), ops GET/POST
  →501, unknown→404, graceful SIGTERM shutdown logged. ✅
- **Web:** `pnpm typecheck` OK · `pnpm lint` clean · `pnpm build` OK (9 routes +
  middleware). Fixed `react/jsx-no-comment-textnodes` (`{"//"}`).
- **CI YAML:** all 5 files parse (validated via Ruby YAML). Fixed `release.yml`
  (`TODO:` colon-space in an unquoted `run:` scalar broke YAML).
- **Tree:** 83 source files tracked; `target/`, `node_modules/`, `.next/`,
  `*.tsbuildinfo` confirmed git-ignored.
- **Decision:** licenses — kept `LICENSE`/`LICENSE-APACHE`; server BSL text
  **skipped per user**; dangling refs softened to "deferred".
- **Held (need explicit human OK):** git commit + push, domain purchase
  (`sigilapp.io`), any public deploy. Repo still has 0 commits by design.

### ➡️ Next (when human returns)
1. Approve the first signed commit + push, OR keep iterating locally.
2. Buy `sigilapp.io` (or chosen name) → Cloudflare zone → Postmark DKIM/SPF/DMARC.
3. Provision PQ-TLS client (OpenSSL 3.5+) before attempting the stretch sigild VM.

### Commit `0edd579` — genesis scaffold ✅
- 83 files, working tree clean. Local commit on `main`, unsigned (no signing key
  configured), **not pushed** (user buying the domain; push not requested).

### Dev increment #1 — libsigil crypto-agility envelope codec ✅
- Added `libsigil/core/src/envelope.rs`: `Envelope { suite, aad, nonce,
  ciphertext, tag, kem_ct }` with `encode()`/`decode()`. Concrete self-describing
  format `0x01` — per-field unsigned-LEB128 varint length prefixes + a `flags`
  byte for the optional `kem_ct`. **Serialization only; no encryption** (does not
  fake crypto). `core` now `extern crate alloc`.
- Rationale: lands the crypto-AGILITY property (suite byte travels inside the
  frame → migrate suites without flag-day re-encryption) without touching real
  crypto, which stays weeks out per the brief.
- Design note: the brief's prose layout left nonce/ct/tag boundaries
  implicit-by-suite; chose explicit length prefixes so the frame parses
  unambiguously and is testable. Documented in `docs/crypto-spec.md`.
- Tests (8 new): round-trip with/without kem_ct, header bytes, empty fields,
  multibyte varint length (5000-byte field), reject bad version / unknown suite /
  truncated / trailing bytes. Verified: fmt --check ✓ · clippy -D warnings ✓ ·
  `cargo test` 14 core + 1 ffi ✓ · wasm32 build ✓.
- Committed `bbf496f`.

### Dev increment #2 — sigild HTTP middleware ✅
- Added `sigild/internal/api/middleware.go`: `requestID` (assign/propagate
  `X-Request-ID`, stash in ctx), `accessLog` (one structured slog line per
  request — method/path/status/bytes/dur; **never logs bodies**, so no vault
  material reaches logs), `recoverer` (panic → 500), `statusRecorder`, and a
  `chain()` helper. Wired into `NewRouter` (recoverer → requestID → accessLog →
  mux).
- Tests (4): ID generated, inbound ID propagated, recoverer → 500, `newRequestID`
  unique + 16-hex. Live check: `X-Request-Id` emitted (`55ee765f…`) and an
  inbound `my-trace-123` propagated.
- Verified: gofmt ✓ · vet ✓ · test ✓ · build ✓.
- Committed `0a9a13c`; pushed `main` → `origin/main` (user authorized push;
  domain purchase still in progress on their side).

## 2026-06-02 — Phase 2 (3 parallel agents via workflow `wu9u3qp47`)

Ran a workflow with 3 agents over disjoint subtrees (libsigil / sigild / web).
Each was constrained to its directory, forbidden from touching shared files or
committing. **I re-verified everything myself** (did not trust agent self-reports)
before committing.

### libsigil — real (unaudited) AEAD layer ✅
- New `core/src/aead.rs`: `seal()`/`open()` over the Envelope using
  XChaCha20-Poly1305 (chacha20poly1305 0.10) keyed by HKDF-SHA256 (hkdf 0.12 +
  sha2 0.10). Per-record key = HKDF(info = `sigil-record-v1` || suite_byte), so
  keys are bound to the suite. Nonces passed in (no RNG in core). Fail-closed:
  tamper/wrong-key/wrong-suite → `AeadError::Authentication`, no plaintext leak.
- wasm SAFETY: all three crates added with `default-features = false` to keep
  `getrandom` out of the tree — I confirmed **0 getrandom entries in Cargo.lock**
  and the wasm32 build stays green.
- Honest pre-audit caveats in the module docs (suite bound via key not AAD; no
  zeroization; no KEM/rotation yet). 14 new tests.

### sigild — hardening ✅
- Typed JSON error envelope (`internal/api/errors.go`, `writeError`); refactored
  the 501 ops + 500 recoverer to use it.
- 64 KiB per-op body limit (`limitBody` middleware + MaxBytesReader): oversized →
  413 `payload_too_large`; small body still → 501. (Brief §14: 64 KiB cap.)
- New `internal/store`: `KV` interface + concurrency-safe in-memory `MemKV`
  (RWMutex, defensive copies, sorted List). No crypto/DB. Tests incl. concurrency.

### web — `/security` page ✅
- `app/security/page.tsx`: no-index "Cryptographic posture" PQC table; every row
  qualified (designed/in-development/planned/pre-audit/unaudited); intro is an
  explicit negation; status-vocabulary key; clarifies FIPS names ≠ certification.
  Footer link added. No forbidden claims (claims-grep clean).

### My independent verification (the real gate) ✅
- Rust: fmt --check ✓ · clippy -D warnings ✓ · **27 tests** ✓ · wasm32 ✓ ·
  getrandom absent ✓.
- Go: gofmt ✓ · vet ✓ · test (api + store) ✓ · build ✓.
- Web: typecheck ✓ · lint ✓ · build ✓ (`/security` route present).
- Updated README.md + CLAUDE.md crypto-status lines (the "no real crypto" line
  was now stale).

## 2026-06-02 — Phase 3 (workflow `w00itf376`, all opus 4.8 agents)

Goal: finish the symmetric key chain (add the Argon2id front end), expose the
AEAD across the FFI boundary, and harden CI. Per the user's standing directive
("use sub agents for everything, always opus 4.8"), all build work ran through
opus workflow agents; **I re-ran the full gate myself before committing.**

Recovery note: an earlier Phase-3 run (`wkpeg2g7k`) was interrupted by a
`/compact` and left a **half-applied** tree — `kdf.rs` existed but `lib.rs` had
no `mod kdf;`, and `Cargo.lock` listed `argon2` while `Cargo.toml` did not
declare it. This run rebuilt to a consistent state from that partial work.

### libsigil/core — Argon2id KDF, wired in ✅
- `core/src/kdf.rs`: `derive_master_key(password, salt, Argon2Params)` →
  `[u8; 32]`, real Argon2id (argon2 0.5.3, `Version::V0x13`) via
  `hash_password_into`. `Argon2Params::RECOMMENDED` = brief's m=65536 KiB
  (64 MiB) / t=4 / p=2. **No RNG**: the salt is the caller's responsibility
  (keeps the crate wasm-clean). `KdfError` maps Argon2 errors to
  Invalid{Params,Salt}/Hash. 7 tests (determinism, salt/password sensitivity,
  short-salt + bad-params rejection) use tiny FAST params so they're instant.
- Wired into `lib.rs` (`mod kdf;` + re-exports `derive_master_key`,
  `Argon2Params`, `KdfError`, `MASTER_KEY_LEN`); crate doc now shows the full
  key chain (password → Argon2id → master key → HKDF → per-record key →
  XChaCha20-Poly1305), all labelled pre-audit / building-block.
- **wasm guardrail held:** `argon2` added with `default-features = false,
  features = ["alloc"]` so the `rand`/`password-hash`→`rand_core`→`getrandom`
  edge stays inactive. Confirmed **0 getrandom in Cargo.lock** and wasm32 green.
  (argon2 pulls base64ct/blake2/cpufeatures/password-hash/rand_core into the
  lockfile, but none activate getrandom.)

### libsigil/ffi — real (unaudited) C-ABI seal/open ✅
- `ffi/src/lib.rs`: `sigil_seal` / `sigil_open` / `sigil_buffer_free` over an
  `#[repr(C)] SigilBuffer { *mut u8, usize }`, plus the existing
  `sigil_current_suite`. Status codes: `SIGIL_OK`=0, `_ERR_NULL_ARG`=-1,
  `_ERR_OPEN`=-2 (decode + auth failures collapse to one code → no structure
  leak, never writes `*out`), `_ERR_BAD_INPUT`=-3.
- Memory contract: library owns the heap slice until `sigil_buffer_free`; empty
  outputs normalise to `{null,0}` to dodge the dangling-empty-Vec free trap.
- `#![deny(unsafe_op_in_unsafe_fn)]` kept; every `unsafe` block has a `// SAFETY:`
  note; `# Safety` doc sections on all exports. Hand-written `ffi/include/sigil.h`
  (no cbindgen dependency — offline) mirrors the structs/codes/prototypes.
- 7 ffi tests: round-trip, tamper→`_ERR_OPEN`, garbage/truncated→error-not-crash,
  null-arg, empty-plaintext round-trip, free-empty no-op.
- core's `#![forbid(unsafe_code)]` is untouched; all the unsafe lives in ffi.

### CI — security scanning ✅
- `.github/workflows/security.yml`: gitleaks (full history) + govulncheck
  (sigild, Go 1.24.x) + cargo-audit (libsigil), on push/PR + weekly Monday cron.

### My independent verification (the real gate) ✅
- Rust: fmt --check ✓ · clippy -D warnings ✓ · **34 core + 7 ffi tests** ✓ ·
  wasm32 ✓ · `grep -c getrandom Cargo.lock` = **0** ✓.
- Go: gofmt ✓ · vet ✓ · test (api + store) ✓ · build ✓.
- Web: typecheck ✓ · lint ✓ · build ✓ (10 routes).
- YAML: all 5 workflow files parse (ruby `YAML.load_file`).
- Over-claim scan: every "audited"/"secure" hit is a negation/caveat; no
  "SOC 2" / "post-quantum secure" / unqualified "end-to-end encrypted".
- Reviewed the ffi `unsafe` line-by-line (null checks, slice bounds, Box
  reconstruction) myself before committing.
- Tightened now-stale core crate-doc wording ("pure, dependency-free" →
  "cryptographic"; "pulls in only core" → "core + alloc, not std") and refreshed
  README/CLAUDE crypto-status + repo-map lines to name the KDF and the FFI API.

## 2026-06-04 — Phase 4 (workflow `wnwct8sms`, 3 parallel opus tracks + verify)

Theme: deployment readiness + the composed encryption API. Three disjoint
subtrees ran in parallel (libsigil/core · sigild · deploy+docs), then one
independent verifier; **I re-ran the gate and the container smoke myself.**

### libsigil/core — composed record API ✅
- New `core/src/record.rs`: `seal_record(password, salt, params, nonce, aad,
  plaintext) -> Vec<u8>` and `open_record(password, salt, params, bytes)`,
  composing Argon2id → AEAD → envelope codec into the single call a client makes.
  `RecordError { Kdf, Aead, Envelope }` with `From` impls (`?`). **No new
  crypto** — it only wires existing blocks. `open_record` decodes *before*
  deriving the key so garbage is rejected without paying the Argon2id cost.
- Wired into `lib.rs` (`mod record;` + re-exports); crate doc names it the
  end-to-end entry point. 8 tests (round-trip, wrong-password→Aead-auth-fail,
  tamper, key-path determinism, empty, garbage/truncated/empty→Envelope).
- Honest caveats: `(salt, params)` are NOT in the envelope — caller must persist
  them; nonce-reuse is the caller's job; no zeroization; not an account/rotation
  system.

### sigild — container + `/version` ✅
- `GET /version` → `{"name":"sigild","version":<buildinfo>}` (no secrets, no
  crypto) + `TestVersion`. Multi-stage `Dockerfile` (golang:1.24-alpine builder,
  `CGO_ENABLED=0 -trimpath -ldflags …Version=$VERSION` → `gcr.io/distroless/
  static-debian12:nonroot`, USER nonroot, EXPOSE 8080) + `.dockerignore`. No
  Docker HEALTHCHECK by design (distroless has no shell; orchestrator probes
  `/healthz`). sigild still does NO crypto / NO storage; ops still `501`.

### deploy + docs — runbook ✅
- New `docs/deployment.md`: topology (systemd VM → Nomad+image → k8s), artifact
  flow, the PQ-TLS-must-be-proven-on-the-Go-listener caveat, DNS/ACME wall-clock
  gate, secrets posture, a "what is NOT yet deployable" section, and a validation
  status table. `deploy/README.md` + nomad image comment point at `sigild/
  Dockerfile`.

### My independent gate (the real commit gate) ✅
- Rust: fmt ✓ · clippy -D warnings ✓ · **42 core + 7 ffi tests** ✓ · wasm32 ✓ ·
  getrandom **0** ✓ · `#![forbid(unsafe_code)]` intact.
- Go: gofmt ✓ · vet ✓ · test (api + store, incl. `/version`) ✓ · build ✓.
- Web: unchanged this phase (no `web/` edits) — prior green build still holds.
- **Docker smoke (first-hand):** built the image (**13.9 MB** distroless), ran
  it, and probed the live container — `/healthz` + `/version` carried the stamped
  `VERSION` build-arg, `/readyz` → deps `unconfigured`, ops → `501`. Cleaned up.
- **Caught a cross-track inaccuracy:** Track C wrote deployment.md §8 saying the
  Docker daemon was stopped and the image was "NOT built", but Track B had
  brought the daemon up and built+probed it. Corrected §8 (and the intro) to the
  truth — image built/validated locally; only terraform/caddy/nomad/systemd
  validators remain uninstalled. (Accuracy is the whole point here.)
- Refreshed CLAUDE repo-map/build-commands (added the docker build) and the
  Git/deploy note (no longer "no commits yet").

## 2026-06-05 — Phase 5 (workflow `w8y9u2ofg`, 2 parallel opus tracks + verify)

Theme: the first **runnable** end-to-end demonstration of the crypto core — a
small CLI that seals/opens a file with a password. Two disjoint tracks (the
`cli/` crate · its CI workflow), then an independent verifier; **I re-ran the
gate and a real binary round-trip myself.**

### cli/ — the `sigil` demo CLI ✅
- New **standalone** crate `sigil-cli` (binary `sigil`), path-depending on
  `../libsigil/core`. Composes `seal_record`/`open_record` into a self-describing
  on-disk **container**: `magic "SIGILcli" | version u8 | m_cost/t_cost/p_cost
  u32 LE | salt_len u8 | salt | envelope`. The salt+params live in the header
  because they are NOT in the envelope (the nonce is); the AEAD nonce stays
  inside the envelope. Fixed `aad = b"sigil-cli/1"`.
- `cli/src/lib.rs` (testable, `#![forbid(unsafe_code)]`): `seal_to_container` /
  `open_container` + `CliError`. The container **parser is bounds-checked** — a
  `len < FIXED_HEADER_LEN(22)` gate makes every later index provably in-range,
  and the declared `salt_len` is checked before `split_at`, so untrusted bytes
  never panic. Errors surface `RecordError` via Debug — **never** plaintext.
- `cli/src/main.rs`: hand-rolled `std::env` arg parser (no clap), password from
  `SIGIL_PASSWORD` (unset/empty → hard error, never hangs), loud
  **PRE-AUDIT / UNAUDITED / not-for-real-secrets** banner in `--help`.
- 13 tests (11 lib unit incl. tamper/bad-magic/version/salt-overrun/truncation;
  2 integration that drive the real binary via `CARGO_BIN_EXE_sigil`).

### getrandom isolation (the key guardrail) ✅
- The CLI uses `getrandom` for salt+nonce — **fine**, it is native-only and never
  compiled to wasm. It is a **standalone crate with its own `cli/Cargo.lock`**,
  NOT a libsigil workspace member (`libsigil/Cargo.toml` members stay
  `["core","ffi"]`). Verified `libsigil/Cargo.lock` getrandom count = **0** and
  its **mtime was byte-identical before/after** the CLI build (`1780397378`);
  `cli/Cargo.lock` getrandom = 1 (expected).

### CI ✅
- `.github/workflows/cli.yml` mirrors `libsigil.yml` (paths `cli/**`, fmt/clippy/
  test/build, `workspaces: cli`, no wasm job — native-only).

### My independent gate (the real commit gate) ✅
- CLI: fmt ✓ · clippy -D warnings ✓ · **11 unit + 2 integration tests** ✓ ·
  build ✓.
- **First-hand binary round-trip:** sealed a file → opaque 131-byte container
  (plaintext absent) → opened with the right password → **byte-identical**;
  wrong password → exit 1, `Aead(Authentication)`, **no output written**; unset
  `SIGIL_PASSWORD` → fail-fast exit 1.
- Regression: libsigil fmt/clippy/**42+7** tests/wasm/getrandom 0 ✓; Go
  fmt/vet/test/build ✓; all 6 workflow YAMLs parse ✓. Web untouched.
- Refreshed README + CLAUDE (repo map: `cli/` no longer "reserved"; known-green
  CLI commands + the getrandom-stays-0 check).

## 2026-06-06 — Phase 6 (dev-gated opaque vault op-log in sigild + verify)

Theme: the first **client→server→client** path — give `sigild` a place to put
the CLI's sealed container and hand it back unchanged, **without the server ever
touching crypto or plaintext**. Built behind a dev flag, then independently
verified incl. a live round-trip; **I re-ran the gate and the demo myself.**

### sigild — opaque, dev-gated, in-memory op-log ✅
- New `internal/store/vaultlog.go`: `MemVaultLog` with `Append(vaultID, blob)
  -> seq` and `Since(vaultID, sinceSeq) -> []Op`. **1-based, per-vault**
  monotonic sequence; **defensive copies** of the blob on the way in AND on the
  way out (server never aliases caller memory). Stdlib-only (`sync` mutex). The
  blob is an **opaque `[]byte`** — the server does **no crypto**, never decodes,
  never interprets it; it is exactly the bytes the client sent.
- New handlers (`internal/api/handlers.go` + wiring in `router.go`):
  `POST /v1/vaults/{vaultID}/ops` (read body → `Append` → `201 {"vaultID","seq"}`)
  and `GET …/ops?since=N` (→ `200 {"ops":[{seq,blob}],"next"}`, `blob`
  base64). Empty POST body → `400`; bad `since` → `400`; the **64 KiB
  `limitBody` cap still wraps POST**, so oversized → `413` even when enabled.
- **DEV-GATED, default OFF.** `cfg.DevOpsEnabled` defaults `false` in `Config`;
  `main.go` only flips it from a truthy `SIGILD_ENABLE_DEV_OPS`. When the flag is
  **unset, `NewRouter`'s else-branch routes BOTH verbs to `opsNotImplemented` →
  `501 not_implemented`** — production default is unchanged, honoring the
  "stub with 501 rather than poison the audit" guardrail.
- ⚠️ Loudly labeled, in code + `docs/api.md`: this op-log is **UNAUTHENTICATED,
  IN-MEMORY, NON-DURABLE, DEV-ONLY**, stores **opaque blobs only**, and is **not**
  a real op-log. `api.md` leads with a bold "READ THIS FIRST. This endpoint is a
  development scaffold, not a product." block. No fake auth was added.

### docs — `docs/api.md` ✅
- New endpoint reference for the dev op-log: the `SIGILD_ENABLE_DEV_OPS` gate
  (default → `501`), request/response shapes, the `400`/`413` cases, and the
  honest caveats (opaque/unauthenticated/in-memory/non-durable, server never
  decrypts). No over-claims (the only "audited" hit is the negation "Nothing here
  is audited or production-ready").

### My independent gate (the real commit gate) ✅
- Go: gofmt ✓ · vet ✓ · build ✓ · test ✓ — **7 new store tests** (SeqIncrements,
  SeqIsPerVault, SinceZeroReturnsAll, SinceFilters, SinceUnknownVault,
  DefensiveCopy, ConcurrentAppends) + **5 new api tests** (AppendAndList,
  EmptyBodyIs400, BadSinceIs400, OversizedStill413WhenEnabled, **and
  DefaultStill501**), plus the pre-existing 501/413 tests still pass.
- **stdlib-only held:** `vaultlog.go` imports only `sync`; handlers use
  `encoding/json`/`io`/`strconv` etc. `go.mod` unchanged (no `require` block).
- **Live round-trip (real binaries, real localhost sockets):** sealed a known
  plaintext (sha256 `92bbc8a6…`) with the CLI → 165-byte `secret.sigil`
  (sha256 `05780ac6…`); started `sigild` with `SIGILD_ENABLE_DEV_OPS=1`;
  `POST --data-binary @container` → **`201 {"vaultID":"demo","seq":1}`**;
  `GET ?since=0` → **`200`**, `ops[0].seq=1`, `next=1`; base64-decoded
  `ops[0].blob` = 165 bytes, sha256 `05780ac6…` — **byte-identical** to the
  container (server stored the ciphertext opaquely, unchanged); ran `sigil open`
  on the decoded bytes with the same password → recovered plaintext sha256
  `92bbc8a6…` = original. **Full client→server→client round-trip: YES.**
- **Default-501 confirmed three ways:** code (else-branch), httptest
  (`TestVaultOpsDefaultStill501`), and **live** — a second server started
  WITHOUT the flag (`:18091`) returned `501 not_implemented` on BOTH POST and
  GET. Both background servers were killed; no leftover procs/listeners.
- Regression: libsigil fmt/clippy/**7** tests/wasm/**getrandom 0** ✓; cli
  fmt/clippy/**2** tests ✓; all 6 workflow YAMLs parse ✓. Web untouched.
- Over-claim scan CLEAN — every "audited"/"unaudited" hit across the changed
  `sigild/*.go` + `docs/*` is a negation/caveat or the guardrail line itself; no
  unqualified "secure"/"post-quantum secure"/"SOC 2"/"E2E".

### ⛔ Still NOT production (honest)
- The op-log is a **dev scaffold**. Production needs: real **auth** (this is
  explicitly unauthenticated), a **durable** store (this is in-memory and lost on
  restart), and **CRDT / conflict-resolution semantics** (this is a naive
  append-only log with a per-vault counter, not a real sync protocol). The prod
  default stays `501` until those land.

## 2026-06-06 — Phase 7 (CLI push/pull two-device sync demo + architecture.md + verify)

Theme: close the loop the Phase-6 server opened — teach the `sigil` CLI to
**push** a sealed container to sigild's dev op-log and **pull** it back on a
second device, then write the missing top-level **`docs/architecture.md`**. The
client never decrypts on the server's behalf and the server still never touches
crypto; the only thing that crosses the wire is the opaque container. Built,
then independently verified incl. a **live two-device round-trip**; **I re-ran
the gate and the demo myself.**

### cli/ — `sigil push` / `sigil pull` ✅
- Added to `cli/src/lib.rs`: `push_op(server, vault, blob) -> seq` (`POST
  {server}/v1/vaults/{vault}/ops` with the raw container as the body, parses
  `{"seq"}` from the `201`) and `pull_ops(server, vault, since) -> Vec<(seq,
  blob)>` (`GET …/ops?since=N`, base64-decodes each `ops[].blob`). Wired into
  `main.rs` as two new subcommands; vault id is validated **before any request**
  (rejects empty / path-y ids). HTTP errors surface as `CliError` with the
  server's status + body — e.g. a non-dev server's `501` becomes
  `dev op-log returned HTTP 501: …` and a non-zero exit.
- New deps (cli crate only): **`ureq`** with `default-features = false` (so it
  speaks **plain HTTP**, no TLS stack pulled in — these talk to **localhost dev
  sigild only**), `serde` + `serde_json` (parse the op-log JSON), `base64`
  (decode the returned blobs). Server URL comes from `--server` or the
  **`SIGIL_SERVER`** env var (default `http://127.0.0.1:8080`).
- ⚠️ **Loudly labeled dev/localhost/plain-HTTP/unauthenticated/opaque** in the
  `--help` banner, the `lib.rs` push/pull doc comments, and `cli/README.md` ("dev /
  localhost / plain HTTP only", "no TLS and no auth"). The op-log they hit is
  itself dev-gated + unauthenticated. The CLI keeps its loud **PRE-AUDIT /
  UNAUDITED / not-for-real-secrets** banner. No over-claims.
- Tests: **4 new mock-server unit tests** stand up a real `TcpListener` on a
  loopback port and assert wire behavior without sigild —
  `push_op_posts_body_to_right_path_and_returns_seq`,
  `pull_ops_sends_since_and_decodes_base64_blobs`,
  `server_500_becomes_cli_error_server`, and
  `bad_vault_is_rejected_before_any_request` (no request is even sent).

### getrandom isolation (the key guardrail) — re-proven ✅
- The new deps land in **`cli/Cargo.lock` only**. `libsigil/Cargo.lock` is
  **byte-for-byte unchanged** (`git diff --quiet libsigil/Cargo.lock` →
  UNCHANGED) and its **getrandom count is still `0`** (getrandom remains present
  only in `cli/Cargo.lock`, count `1`). `libsigil/Cargo.toml` members stay
  `["core","ffi"]` — the CLI is still **not** a workspace member.

### docs — `docs/architecture.md` ✅
- New 269-line top-level architecture doc: §1 **Component map** with an ASCII
  component diagram and the **trust boundary** (client-side crypto vs. the
  zero-knowledge server); §2 **Data flow — the life of one record** with a full
  diagram (password → Argon2id → HKDF → XChaCha20-Poly1305 AEAD → envelope →
  CLI container → `push` → sigild op-log → `pull` → `open`). Cross-links
  `crypto-spec.md`, `api.md`, `threat-model.md`, `deployment.md`,
  `sprint-72h.md`, `CLAUDE.md`, and `README.md`. Honest throughout — leads with
  the negation list (nothing here is audited / "secure" / "post-quantum secure" /
  SOC 2 / unqualified "end-to-end encrypted"); the lone "audited core" phrase
  names the core as the *audit target* (intent), not a claim of having been
  audited.

### My independent gate (the real commit gate) ✅
- CLI: fmt ✓ · clippy -D warnings ✓ · **15 lib + 2 integration = 17 tests** ✓ ·
  build ✓ (`sigil` binary).
- **Live two-device round-trip (real binaries, real localhost sockets):** built
  sigild fresh; ran it **with `SIGILD_ENABLE_DEV_OPS=1` on :18094** (and a second
  instance **without** the flag on :18095 for the negative case), both green on
  `/healthz`. **Device A:** wrote `pt.txt` (sha256 `0581f73e…`) → `sigil seal` →
  `op.bin` (145 bytes) → `sigil push --vault demo --in op.bin --server
  http://127.0.0.1:18094` → **"pushed vault demo seq 1"**. **Device B** (separate
  dir): `sigil pull --vault demo --since 0 --out-dir pulled …` → wrote
  `pulled/op-1.sigil`. **BYTE-IDENTICAL:** `op.bin` and `pulled/op-1.sigil` are
  both sha256 `0e5ed487…` — the server stored/returned the ciphertext opaquely.
  Device B `sigil open --in pulled/op-1.sigil --out got.txt` → `got.txt` sha256
  `0581f73e…` == the original plaintext. **Full seal→push→pull→open across two
  devices: YES.**
- **Flag-off 501 confirmed live:** pushing to the non-dev server (:18095)
  surfaced `dev op-log returned HTTP 501: {"error":"not_implemented",…,
  "vaultID":"demo"}` and exited non-zero (`1`). Both servers killed; no lingering
  processes.
- Regression: libsigil fmt/clippy/**42+7** tests/wasm/**getrandom 0** ✓; Go
  fmt/vet/test/build ✓; all 6 workflow YAMLs parse ✓. Web untouched.
- Over-claim scan CLEAN across `cli/src/*.rs`, `cli/README.md`, `cli/Cargo.toml`,
  `docs/architecture.md` — every "audited"/"secure"/"post-quantum"/"SOC 2"/"E2E"
  hit is a negation, an explicit caveat, the "post-quantum-*ready*" qualified
  form, or a legitimate technical descriptor ("cryptographically-secure random
  bytes from the OS"). `#![forbid(unsafe_code)]` intact in both `cli/src/main.rs`
  and `cli/src/lib.rs`.

### ⛔ Still NOT production (honest)
- push/pull is a **dev/localhost demo over plain HTTP**. Still missing, same as
  Phase 6 plus the client side: real **auth** (both the CLI and the op-log are
  unauthenticated), **TLS for the client** (the CLI speaks plain HTTP — it never
  pulls in a TLS stack, intentionally, and is localhost-only), a **durable
  store** (the op-log is in-memory, lost on restart), and **CRDT /
  conflict-resolution** (still a naive per-vault append counter, not a sync
  protocol). The prod ops default stays `501`.

## 2026-06-07 — Phase 8 (incremental pull cursor + multi-vault)

Theme: make `sigil pull` **incremental** so a second device only fetches ops it
hasn't seen yet, instead of re-pulling the whole op-log every time. No server
change (sigild already exposes `?since=N`); the work is entirely a thin client
cursor layer + wiring it through `cmd_pull`. Built, then **independently
verified** incl. a **live incremental + multi-vault demo**; **I re-ran the gate
and the demo myself.**

### cli/ — per-(server,vault) pull cursor ✅
- New cursor layer in `cli/src/lib.rs`: `read_cursor` / `write_cursor` over a
  JSON **state file** that lives **inside `--out-dir`** as
  `.sigil-pull-state.json`. The map key is **`"{server}|{vault}"`**, so each
  `(server, vault)` pair tracks its own high-water seq independently. Missing
  file or missing key reads **0** (first pull → fetch from the beginning); a
  malformed/unparseable state file surfaces a `CliError` (state error), it does
  not silently reset. The stored cursor is **local, non-secret bookkeeping** — it
  holds only seq numbers and the server/vault label, never plaintext or key
  material.
- `cmd_pull` now takes `since: Option<u64>`: an explicit **`--since N` overrides**
  the cursor for a one-off pull; otherwise it reads the persisted cursor, asks
  the op-log for everything **after** it, writes the new `op-<seq>.sigil` files,
  and **advances + persists the cursor** to the highest seq pulled (monotonic —
  it only ever moves forward). When there are no new ops it prints
  `no new ops since <cursor>` and writes nothing.
- 7 new unit tests: `cursor_write_then_read_round_trip`,
  `cursor_missing_file_reads_zero`, `cursor_missing_key_reads_zero`,
  `cursor_two_keys_are_independent`, `cursor_malformed_state_is_state_error`,
  `cursor_write_overwrites_same_key`, `cursor_key_combines_server_and_vault`.
- ⚠️ Still **loudly labeled dev/localhost/plain-HTTP/unauthenticated/opaque** in
  the `--help` banner — a new **INCREMENTAL PULL** section documents the
  per-(server,vault) cursor, the `.sigil-pull-state.json` location inside
  `--out-dir`, monotonic advancement, the `--since` override, and that the state
  is local/non-secret. The loud **PRE-AUDIT / UNAUDITED / not-for-real-secrets**
  banner is intact. No over-claims.

### getrandom isolation + no new deps (the key guardrail) — re-proven ✅
- **No new deps this phase** — the cursor uses `serde_json` + `std::fs`, both
  already in the cli crate. `cli/Cargo.toml` is **unchanged** (`git diff --quiet
  cli/Cargo.toml` → unchanged), and no `Cargo.lock`/`Cargo.toml` changed anywhere
  in the repo. `libsigil/Cargo.lock` is **byte-for-byte unchanged**
  (`git diff --quiet` → unchanged) and its **getrandom count is still `0`**
  (getrandom present, count `1`, only in `cli/Cargo.lock`, as expected). The CLI
  is still **not** a libsigil workspace member.

### My independent gate (the real commit gate) ✅
- CLI: fmt ✓ · clippy -D warnings ✓ · **22 lib + 2 integration = 24 tests** ✓
  (incl. the 7 new cursor tests) · build ✓ (`sigil` binary, 3.7 MB).
- **Live incremental + multi-vault demo (real binaries, real localhost
  sockets):** ran `sigild` with `SIGILD_ENABLE_DEV_OPS=1` on `:18097` (server
  logged the loud `DEV op-log enabled: UNAUTHENTICATED, in-memory, non-durable`
  WARN); sealed real containers with `SIGIL_PASSWORD=pw` from 3 distinct
  plaintexts. **Vault A:** pushed op1→seq 1, op2→seq 2; first pull into out-dir D
  wrote `op-1.sigil`+`op-2.sigil` and **`cursor for A now at 2`** (state =
  `{"http://127.0.0.1:18097|A":2}`); a second pull with no new ops printed
  **`no new ops since 2`** and wrote nothing (D unchanged); sealing+pushing
  op3→seq 3 then pulling wrote **only** `op-3.sigil` (`pulled seq 3`,
  `cursor for A now at 3`). **Multi-vault:** pushed one op to vault B→seq 1;
  pulling `--vault B` into the **same** out-dir D used B's **independent** cursor
  (started at 0, pulled seq 1, `cursor for B now at 1`) and **left A's cursor
  untouched at 3** — final state `{"…|A":3,"…|B":1}`. Cursor
  independence/monotonicity all correct. **Open:** A's `op-2.sigil` opened to
  exactly `PLAINTEXT-TWO` and A's `op-3.sigil` to its original; wrong password
  failed with `could not open record: Aead(Authentication)` and wrote no
  plaintext.
- ⚠️ **One honest behavioral note (found here, FIXED in Phase 8b below):** at the
  time of this demo, pulled files were named `op-<seq>.sigil` with **no vault
  namespacing**, so pulling vault B (seq 1) into the **same** out-dir as vault A
  **overwrote A's `op-1.sigil`** on disk (a filename collision — opening
  `op-1.sigil` after the B pull yielded B's plaintext). The per-vault **cursors**
  stayed correct and independent; the collision was purely a filesystem naming
  clash when two vaults shared one out-dir (the demo deliberately used one dir).
  A's uncollided containers (op-2, op-3) round-tripped correctly. ➡️ Fixed by
  namespacing pulled filenames per vault — see **Phase 8b** below.
- Regression: libsigil fmt/clippy/**42+7** tests/wasm/**getrandom 0** ✓; Go
  (sigild) fmt/vet/test/build ✓ (untouched this phase); all 6 workflow YAMLs
  parse ✓. Web untouched.
- Over-claim scan CLEAN across `cli/src/*.rs` + `cli/README.md` — every
  "audited"/"unaudited" hit is a negation/disclaimer, the lone "secure" is the
  legitimate technical descriptor (OS CSPRNG, "cryptographically-secure random
  bytes"), and there is no "post-quantum secure" / "SOC 2" / unqualified
  "end-to-end encrypted". `#![forbid(unsafe_code)]` intact in the cli.

### docs — CLAUDE.md onboarding pointer ✅
- Expanded the top `CLAUDE.md` blockquote into a **required onboarding path** for
  any new (cold-start) session: read `journal.md` first, then the `docs/` folder
  **in full** — `docs/README.md` (index) → `docs/architecture.md` (system shape /
  data flow / trust boundary) → `api.md` / `crypto-spec.md` / `threat-model.md` /
  `deployment.md` / `sprint-72h.md` — before making changes. Kept the
  "keep `journal.md` updated frequently and in depth" mandate. Also refreshed the
  `cli/` repo-map bullet (CLAUDE.md + README.md) to note incremental pull.

### ⛔ Still NOT production (honest)
- Incremental pull only changes **which ops the client re-fetches**; the
  underlying sync is still a **dev/localhost demo over plain HTTP**. Same gaps as
  Phase 7: real **auth** (CLI and op-log are both unauthenticated), **TLS for the
  client** (plain HTTP, localhost-only), a **durable store** (the op-log is
  in-memory, lost on restart), and **CRDT / conflict-resolution** (still a naive
  per-vault append counter — the cursor is a high-water mark, not merge
  semantics). The prod ops default stays `501`.

## 2026-06-08 — Phase 8b (per-vault pulled-file namespacing — fix the collision)

Theme: close the one honest behavioral note from Phase 8 — multiple vaults pulled
into a **shared `--out-dir`** could overwrite each other because pulled ops were
named `op-<seq>.sigil` flat, with no vault namespacing.

### cli/ — pulled ops now go to `<out_dir>/<vault>/op-<seq>.sigil` ✅
- Fixed: `cmd_pull` now writes each pulled op into a **per-vault subdir** —
  `<out_dir>/<vault>/op-<seq>.sigil` instead of `<out_dir>/op-<seq>.sigil`. Two
  (or more) vaults can now safely share one `--out-dir`: their files land under
  distinct `<vault>/` subdirs and never collide. The shared cursor **state file
  stays at the out-dir ROOT** (`<out_dir>/.sigil-pull-state.json`), unchanged — it
  still keys on `"{server}|{vault}"`, so the per-vault high-water cursors keep
  working exactly as before.
- `--help` + `cli/README.md` updated to document the `<out-dir>/<vault>/op-<seq>.sigil`
  per-vault layout and that the state file lives at the out-dir root, keeping the
  loud **DEV / LOCALHOST / PLAIN-HTTP / UNAUTHENTICATED / PRE-AUDIT / UNAUDITED**
  caveats. No over-claims. `#![forbid(unsafe_code)]` intact in the cli.

### My independent gate (the real commit gate) ✅
- CLI: fmt ✓ · clippy -D warnings ✓ · **22 lib + 2 integration = 24 tests** ✓ ·
  build ✓ (`sigil` binary).
- **Live same-out-dir multi-vault no-collision demo (real binaries, real localhost
  sockets):** ran dev `sigild` (`SIGILD_ENABLE_DEV_OPS=1` on `:18098`), sealed 3
  containers with distinct plaintexts under one password. Pushed 2 ops to vault A
  (seq 1, seq 2) and 1 to vault B (seq 1) — A/op-1 and B/op-1 deliberately share
  the `op-1.sigil` filename, exactly the Phase-8 collision. Pulled both into ONE
  shared out-dir D (`pull --vault A --out-dir D`, then `pull --vault B --out-dir
  D`). Result: `D/A/op-1.sigil`, `D/A/op-2.sigil`, and `D/B/op-1.sigil` all exist
  (per-vault subdirs); the state file is at `D/.sigil-pull-state.json` (out-dir
  root, not inside a subdir). **`D/A/op-1.sigil` was byte-identical (`cmp`) to the
  original A container — NOT overwritten by the B pull — and opened to A's first
  plaintext, NOT B's.** A/op-2 and B/op-1 also opened to their correct plaintexts.
  State file held BOTH cursors:
  `{"http://127.0.0.1:18098|A":2,"http://127.0.0.1:18098|B":1}`. Server killed and
  confirmed down; temp dirs cleaned.
- getrandom isolation re-proven: `libsigil/Cargo.lock` **unchanged** and its
  **getrandom count still `0`**; `cli/Cargo.toml` **unchanged** (no new deps —
  dependency set still `sigil-core`, `getrandom`, `ureq`, `serde`, `serde_json`,
  `base64`). The CLI is still **not** a libsigil workspace member.
- Regression: libsigil fmt/clippy/**42+7** tests/wasm/**getrandom 0** ✓; Go
  (sigild) fmt/vet/test/build ✓ (untouched this phase). Web untouched.
- Over-claim scan CLEAN across the updated `--help` + `cli/README.md` — every
  "audited" hit is a negation (`UNAUDITED` / "has not been audited"); no "SOC 2" /
  "post-quantum secure" / "production-ready" / unqualified "end-to-end encrypted".

### ⛔ Still NOT production (honest)
- This is a **filesystem-layout fix only** — it changes where pulled files land,
  nothing else. The underlying sync is still the same **dev/localhost demo over
  plain HTTP** with the same gaps as Phase 7/8: real **auth** (CLI + op-log both
  unauthenticated), **TLS for the client** (plain HTTP, localhost-only), a
  **durable store** (op-log in-memory, lost on restart), and **CRDT /
  conflict-resolution** (still a naive per-vault append counter). The prod ops
  default stays `501`.

## 2026-06-08 — Phase 9 (sigild op-log integration test + ADRs)

Theme: pin down the dev op-log's *wire* behavior with a real-socket Go
integration test (the existing api tests drive an `httptest.ResponseRecorder`,
not an actual client over TCP), and start the **`docs/decisions/`** ADR set so
load-bearing choices are recorded once and cross-linked instead of re-derived
from the code. Built, then **independently verified** green (race-clean, ADRs
accurate); production behavior is **unchanged** (default ops still `501`).

### sigild — real-socket op-log integration test ✅
- New `sigild/internal/api/oplog_integration_test.go` — **TEST-ONLY** (untracked;
  no tracked non-`_test.go` sigild file modified, so production behavior is
  unchanged and the default ops route still returns `501`). It stands up a real
  `httptest.NewServer` over an **actual TCP socket** and drives it with a real
  `net/http` client (stdlib only — `httptest`/`net/http`/`encoding/json`/
  `encoding/base64`).
- 6 new top-level integration tests (23 top-level tests in `internal/api/` total,
  all pass): `TestOplogIntegrationAppendListLifecycle`,
  `TestOplogIntegrationSinceCursor` (3 subtests),
  `TestOplogIntegrationOpaqueBinaryIntegrity`,
  `TestOplogIntegrationMultiVaultIndependence`,
  `TestOplogIntegrationProbes` (3 subtests),
  `TestOplogIntegrationGatingDisabled` (3 subtests — incl. POST+GET ops `== 501`
  when `DevOpsEnabled=false`), `TestOplogIntegrationErrorShapes` (3 subtests:
  empty_op `400`, bad_since `400`, oversized `413`).
- What it adds over the recorder unit tests: a **real client + real socket**
  (not an in-process recorder), end-to-end **multi-vault independence**, round-trip
  **opaque binary integrity** (the server hands back the exact client bytes,
  unchanged — no decode), **since-cursor** paging behavior, and the **dev gating**
  proven over the wire (flag off → both verbs `501`).

### docs — first ADRs under `docs/decisions/` ✅
- New `docs/decisions/` with a `README.md` index + `0001`–`0005`, all Nygard-style
  (Status / Context / Decision / Consequences), all **Accepted — 2026-06**, framed
  **pre-audit** in the README. Siblings are cross-linked; no invented decisions.
  - **0001** — record architecture decisions (the ADR practice itself).
  - **0002** — standalone CLI crate for getrandom isolation (CI-checkable invariant:
    `getrandom` count in `libsigil/Cargo.lock` = `0`; `cli/Cargo.lock` = `1`; cli is
    not a libsigil workspace member).
  - **0003** — dev-gated opaque op-log (default `501`; opaque blobs only; server
    never decodes).
  - **0004** — crypto-agility suite registry (`#[non_exhaustive]` `AlgorithmSuite`,
    `HybridPq = 0x12`, `CURRENT = HybridPq`, reserved `kem_ct` envelope field; the
    KEM/signature halves honestly labeled *specified-and-reserved, not implemented,
    unaudited*).
  - **0005** — stdlib-only sigild (no `go.sum`, hermetic builds/tests).
- This realizes the "lightweight ADRs under `docs/decisions/`" intent noted at the
  end of Phase 8 — now a standing practice (see CLAUDE.md onboarding + guardrails).

### Verification (independently verified — the real gate) ✅
- Go: `gofmt -l sigild` clean · `go -C sigild vet ./...` clean · `go -C sigild
  build ./...` clean · `go -C sigild test ./...` — **23 top-level api tests pass**
  (incl. all 6 new oplog integration tests), `internal/store` ok, 0 failures ·
  `go -C sigild test -race -count=1 ./internal/api/` → **ok in 1.281s,
  fully race-clean** (no DATA RACE output).
- **Production unchanged:** `router.go` still routes BOTH verbs to
  `opsNotImplemented` (`501`) when `DevOpsEnabled` is false; `main.go` only flips it
  from a truthy `SIGILD_ENABLE_DEV_OPS`; the new file is the only sigild change and
  it is test-only.
- ADRs accurate — spot-checked mechanically against code: `getrandom` count in
  `libsigil/Cargo.lock` = **0** (cli = 1; cli not a member); `router.go` default
  `501` matches 0003; `core/src/lib.rs` non_exhaustive suite enum + `HybridPq=0x12`
  + `CURRENT` + `envelope.rs` `kem_ct` field match 0004.
- Regression: libsigil fmt/clippy/**42+7** tests/wasm/**getrandom 0** ✓; cli
  fmt/clippy/**22+2** tests ✓; all 6 workflow YAMLs parse ✓. Web untouched.
- Over-claim scan CLEAN across the new test + `docs/decisions/*.md` — no
  "audited"/"secure"/"post-quantum secure"/"SOC 2"/unqualified "end-to-end
  encrypted"; the only "audited"/"unaudited" hits are explicit negations/caveats
  (e.g. 0004 "This is **unaudited**", README "Nothing here is audited or
  production-ready"). The ADRs call the core **audit-bound** / **pre-audit**
  throughout; the lone loose "audited core" shorthand in 0002 is a guardrail
  framing, not a product security claim.

### ⛔ Held — outward-facing, awaits explicit human approval (NOT done)
- **GHCR (container registry) publish** of the `sigild` image is outward-facing and
  irreversible-ish, so it is **not** done — it awaits explicit human approval, same
  posture as domain purchase / public deploy. The image still only builds + is
  smoke-tested **locally** (Phase 4); nothing was published.
  - ➡️ **Update (Phase 13):** the publish **mechanism** now exists as a manual,
    `workflow_dispatch`-**only** workflow (`.github/workflows/publish-sigild.yml`,
    private GHCR) — still intentionally **un-run**; no image has been published.

## 2026-06-08 — Phase 10 (file-backed durable dev op-log)

Theme: give the dev op-log an **optional durable backend** so a sealed container
survives a `sigild` restart, without changing the default and without the server
ever touching crypto or plaintext. The new backend sits behind the **same
`VaultLog` interface** as the in-memory default and is selected purely by an env
var. Built behind the existing dev flag, then **independently verified** incl. a
**real over-HTTP restart-durability demo + path-safety**; production behavior is
**unchanged** (default still in-memory; ops still default `501`).

### sigild — `FileVaultLog`, a file-backed durable backend ✅
- New `internal/store/filevaultlog.go`: a `FileVaultLog` implementing the same
  `Append(vaultID, blob) -> seq` / `Since(vaultID, sinceSeq) -> []Op` contract as
  `MemVaultLog`. Each vault is a **per-vault append-only file** of **4-byte
  big-endian length-prefixed records** (`encoding/binary`); `Append` writes the
  length prefix + the raw blob and **`fsync`s** before returning. The **1-based,
  per-vault `seq` is re-derived from disk** by counting records in the file (no
  separate counter file), so a fresh process over the same dir continues at the
  right next seq. **Defensive copies** of the blob on the way out (the server
  never aliases caller memory); a **truncated trailing record** (partial final
  write, e.g. an `fsync` that didn't complete) is **tolerated** — the reader stops
  at the last whole record rather than erroring. Stdlib-only (`bufio`,
  `encoding/base64`, `encoding/binary`, `errors`, `io`, `os`, `path/filepath`,
  `sync`). The blob stays an **opaque `[]byte`** — the server does **no crypto**,
  never decodes/parses it; **IT IS NOT THE PRODUCTION STORE**.
- **Path-traversal-proof filename scheme.** The `vaultID` comes from the
  **untrusted HTTP path**, so `pathFor` does NOT use it directly: it
  **`base64.RawURLEncoding`-encodes** the raw vaultID bytes (alphabet has no `/`,
  `+`, or `=`), appends `.log`, then `filepath.Join`s onto the base dir. No input
  can therefore contain a path separator or `..`, so **any** vaultID maps to **one
  flat file inside the dir** — `"../../etc/passwd"`, `"a/b"`, `".."` all become
  safe flat filenames and never write outside the base dir.
- **Selected via `SIGILD_OPLOG_DIR`; default unchanged.** `main.go` wires the file
  backend **only when `SIGILD_OPLOG_DIR` is set** (and the dev flag is on);
  otherwise the op-log stays the in-memory `MemVaultLog`. The op-log itself is
  **still dev-gated** (`SIGILD_ENABLE_DEV_OPS`) and **still defaults to `501`** —
  no flag, no op-log, durable or not. On startup with the dir set, the server logs
  a loud WARN: **"FILE-BACKED durable backend active — UNAUTHENTICATED, dev-only,
  NOT the production store — do NOT expose publicly."** No fake auth was added.
- ⚠️ Loudly labeled in code + ADR 0006: this durable backend is a **LOCAL-DEV
  convenience**, **UNAUTHENTICATED / dev-only**, stores **opaque blobs only**, and
  is **explicitly NOT the production store** (production = Postgres/S3 per the
  brief). It is durability **only** — still **no auth, no crypto, no CRDT**.

### docs — api.md / architecture.md / ADR 0006 ✅
- `docs/api.md`, `docs/architecture.md`, and the new **ADR 0006** (file-backed
  durable dev op-log backend) were updated by the docs track to document the
  `SIGILD_OPLOG_DIR` selector, the durable-vs-in-memory choice, the
  base64url-safe-filename / path-traversal property, and the "NOT the production
  store" framing. This entry finalizes the remaining living docs (this file,
  `CLAUDE.md`, `README.md`).

### Verification (independently verified — the real gate) ✅
- Go: `gofmt -l sigild` clean · `go vet ./...` clean · `go build ./...` clean ·
  `go test ./...` — all packages ok, **store 25 PASS** (incl. **11 new
  `FileVaultLog` tests**: SeqIncrements, SeqIsPerVault, SinceZeroReturnsAll,
  SinceFilters, SinceUnknownVault, DurabilityAcrossRestart, PathTraversalSafety,
  OpaqueBinaryIntegrity, ConcurrentAppends, DefensiveCopy,
  TruncatedTrailingRecordIgnored), **api 23 PASS**. `go test -race -count=1
  ./internal/store/ ./internal/api/` → both ok, **race-clean** (incl. a 16×50
  concurrent-append test).
- **Real over-HTTP restart durability (first-hand, byte-checked):** built
  `/tmp/sigild_p10` from `cmd/server`; started it with
  `SIGILD_ENABLE_DEV_OPS=1 SIGILD_OPLOG_DIR=… SIGILD_ADDR=:18100` (startup logged
  the loud FILE-BACKED-durable WARN). POSTed a raw opaque binary blob
  (`00 01 de ad be ef ff 10 "sigil-opaque"`, sha256 `43f60cfc…4642`) to
  `/v1/vaults/dur/ops` → `{"vaultID":"dur","seq":1}`; `GET ?since=0` returned the
  blob base64 `AAHerb7v/xBzaWdpbC1vcGFxdWU=` (matches). **On disk:** `ZHVy.log`
  (`ZHVy` = base64url(`"dur"`)) contained exactly `00 00 00 14` (len=20 BE) + the
  20 raw blob bytes. **`kill -9`** the server, **restart on the SAME port + SAME
  OPLOG dir**: `GET ?since=0` returned seq 1 with a **byte-identical** blob (sha256
  `43f60cfc…4642`, `cmp` byte-identical). The server stored/returned the exact
  client bytes across a crash — **durability: YES.**
- **Negative control A (in-memory non-durable):** dev flag set but **no
  `SIGILD_OPLOG_DIR`** — op present before restart, **empty `ops` (`[]`)** after
  `kill -9` + restart on the same port → non-durable confirmed (the default
  behavior is unchanged).
- **Negative control B (gating, no dev flag):** **no `SIGILD_ENABLE_DEV_OPS`** —
  both GET and POST `/v1/vaults/x/ops` return **`501`** with the pre-audit-skeleton
  body (`{"error":"not_implemented","detail":"vault operation log is not
  implemented in the pre-audit skeleton"}`). Default stays `501`, durable or not.
- **Path traversal SAFE, verified two ways.** UNIT: `TestFileVaultLogPathTraversalSafety`
  appends hostile ids (`"../escape"`, `"a/b/c"`, `".."`, `"../../etc/passwd"`),
  walks the **parent** of the oplog dir, and asserts every file is **flat and
  directly under the dir**, then re-reads each id and gets its exact blob back.
  REAL HTTP: POSTing to `/v1/vaults/..%2F..%2Fevil/ops`,
  `/v1/vaults/..%2F..%2F..%2Ftmp%2Fetc%2Fpasswd/ops`, and `/v1/vaults/a%2Fb/ops`
  produced **three flat files directly under the dir** (`Li4vLi4vZXZpbA.log` =
  `../../evil`, `Li4vLi4vLi4vdG1wL2V0Yy9wYXNzd2Q.log` = `../../../tmp/etc/passwd`,
  `YS9i.log` = `a/b`); `find` showed **no subdirectories** and nothing outside the
  base dir, and sentinel checks confirmed **no `/tmp/etc`, `/tmp/evil`, or `/evil`**
  were created. The hostile blobs were still **retrievable by id** over HTTP. The
  untrusted vaultID cannot escape the dir.
- **Same-dir restart at the unit level:** `TestFileVaultLogDurabilityAcrossRestart`
  builds a new instance over the same dir, re-derives seqs, returns prior blobs,
  and continues at the next seq (4).
- Regression: libsigil fmt/clippy/**42+7** tests/wasm/**getrandom 0** ✓; cli
  fmt/clippy/**22+2** tests ✓; all 6 workflow YAMLs parse ✓. Web untouched.
- **stdlib-only held:** `filevaultlog.go` imports only `bufio`,
  `encoding/base64`, `encoding/binary`, `errors`, `io`, `os`, `path/filepath`,
  `sync` — no third-party deps; `go.mod` unchanged (no `go.sum`).
- Over-claim scan CLEAN: the new Go files and ADR 0006 have **zero** hits for
  "audited"/"secure"/"post-quantum secure"/"SOC 2"/unqualified "end-to-end
  encrypted"; the backend is labeled "NOT the production store",
  "UNAUTHENTICATED / dev-only", "OPAQUE … never decrypted/parsed", "performs no
  cryptography" throughout. The only "audited"/"unaudited" hits in the edited docs
  are pre-existing negations/caveats, not added diff lines.

### ⛔ Still NOT production (honest)
- `FileVaultLog` adds **durability only**. It is a **LOCAL-DEV** backend, **NOT**
  the production Postgres/S3 store named in the brief. Same gaps as Phase 6/7
  otherwise: real **auth** (the op-log is still unauthenticated), **crypto** (the
  server still does none — opaque blobs only), and **CRDT / conflict-resolution**
  (still a naive per-vault append counter, now persisted to a flat file, not a
  sync protocol). The prod ops default stays `501`.

## 2026-06-09 — Phase 11 (Ed25519 signature primitive in libsigil-core)

### Context & mandate
- Goal: add the **classical Ed25519** signature half of the planned hybrid
  signature suite (Ed25519&ML-DSA-65) to `libsigil-core` as a standalone, real
  cryptographic primitive — sign and verify — without touching any existing
  KDF/AEAD code and without breaking the wasm-pure / no-RNG invariants.
- ⚠️ This is the **signature PRIMITIVE only**. It is **not** yet wired into any
  product flow (no device-key auth). The **ML-DSA-65 post-quantum half stays
  FUTURE/unimplemented** — there is still **no post-quantum signature** in this
  repo. Real but **UNAUDITED**.

### core — `core/src/sig.rs` ✅
- New module exposing a **raw-bytes** Ed25519 API, re-exported from `lib.rs`:
  `public_key_from_seed(&[u8; 32]) -> [u8; 32]`, `sign(seed, msg) -> [u8; 64]`,
  and `verify(public_key, msg, signature) -> Result<(), SigError>`, plus the
  length constants `SIG_SEED_LEN`/`SIG_PUBLIC_KEY_LEN` (32) and `SIGNATURE_LEN`
  (64) and the `SigError` enum (malformed key / bad signature).
- **Caller-supplied entropy:** the API takes a **32-byte secret SEED** from the
  caller — exactly like the KDF takes the salt and the AEAD takes the nonce.
  **core still generates NO randomness** (no RNG, no key-gen). The seed must come
  from a cryptographically secure source on the caller's side.
- **Deterministic.** Ed25519 signatures are deterministic per RFC 8032, so a
  given (seed, message) always yields the same signature — asserted by a
  `signing_is_deterministic` test. `verify` uses dalek `verify_strict` (rejects
  non-canonical / small-order points).
- ⚠️ **classical only** — this is the Ed25519 half. The PQ ML-DSA-65 half is
  documented as future/unimplemented in the module docs, `lib.rs`, the crypto
  spec, the architecture map, and ADR 0007. Labeled **UNAUDITED** throughout.

### Dependency & the WASM/GETRANDOM gate
- Chose **`ed25519-dalek = { version = "2", default-features = false }`** — the
  `default-features = false` is load-bearing: it drops the `rand_core`/`getrandom`
  path (we use only `from_bytes`/`sign`/`verify_strict`, never key-gen RNG).
- ✅ **The gate held.** `grep -c 'name = "getrandom"' libsigil/Cargo.lock` =
  **0** (before and after the change), and `cargo build -p sigil-core --target
  wasm32-unknown-unknown` **succeeds** — the wasm-pure invariant is preserved.
  `#![forbid(unsafe_code)]` and `no_std` (`core` + `alloc`) are intact.

### Tests ✅
- **RFC 8032 known-answer vector:** `sig::tests::rfc8032_test1_known_answer_vector`
  asserts **RFC 8032 §7.1 Ed25519 "TEST 1"** (the empty-message vector): seed
  `9d61b19deffd5a60…`, expected public key `d75a980182b10ab7…`, expected signature
  `e5564300c360ac72…`. It checks `public_key_from_seed(seed) == expected_pk` **and**
  `sign(seed, "") == expected_sig` **and** `verify(expected_pk, "", expected_sig) ==
  Ok(())` — a real interop vector, not just an internal round-trip.
- Plus the behavioural suite: `round_trip_verifies`, `wrong_message_fails`,
  `wrong_public_key_fails`, `malformed_public_key_is_rejected`,
  `flipped_signature_byte_fails`, `all_zero_signature_fails`,
  `signing_is_deterministic`, `constants_have_expected_lengths`.
- ✅ `cargo fmt --check` clean · `cargo clippy --all-targets -D warnings` clean ·
  `cargo test` — **sigil-core 51 PASS**, sigil-ffi 7 PASS · wasm build OK ·
  getrandom count **0**. Regression: cli fmt/clippy/**22** tests ✓; sigild
  gofmt/vet/test/build ✓; all 6 workflow YAMLs parse ✓. Web untouched.

### docs — crypto-spec.md / architecture.md / ADR 0007 ✅
- `docs/crypto-spec.md`, `docs/architecture.md`, and the new **ADR 0007**
  (Ed25519 signature primitive — **caller-supplied entropy / 32-byte seed**, no
  in-core RNG, classical half only) were updated by the docs track. The spec marks
  the Ed25519 half "real but NOT YET AUDITED" and the ML-DSA-65 half
  "specified-but-not-implemented". This entry finalizes the remaining living docs
  (this file, `CLAUDE.md`, `README.md`).

### ➡️ Still NOT wired in — planned NEXT phase (honest)
- This phase adds the **primitive only**. It is **not** yet connected to
  device-key authentication. The planned next phase is to **use** it: have the CLI
  **sign** Ed25519 op-log requests with a per-device key, and have **sigild**
  **verify** those signatures before accepting an op-log append (replacing today's
  unauthenticated dev op-log). The hybrid Ed25519&ML-DSA-65 signature does **not
  yet exist** — only the classical half, and it is unaudited.

## 2026-06-09 — Phase 12 (Ed25519 device-key auth for the op-log)

Theme: **use** the Phase-11 Ed25519 primitive — close the "still unauthenticated"
gap on the dev op-log by signing op-log *requests* on the CLI and verifying them
in `sigild`, with the **exact same canonical message constructed byte-for-byte in
both languages** (Go stdlib `crypto/ed25519` on the server, `sigil_core::sign` on
the client). The whole point of this phase is the **cross-language contract**, so
it was independently verified with a **LIVE Rust-signed / Go-verified round-trip**.
Built behind a new env gate, then **I re-ran the gate and the live interop myself.**

### The cross-language request-auth contract (`sigil-oplog-auth-v1`)
- The signed **MESSAGE** (raw bytes) is a 5-line ASCII prefix immediately followed
  by the raw request **body** bytes:

      MESSAGE = b"sigil-oplog-auth-v1\n"
              + METHOD    + b"\n"   (uppercase: "POST" or "GET")
              + PATH      + b"\n"   (URL path, NO query — e.g. /v1/vaults/demo/ops)
              + QUERY     + b"\n"   (raw query string, or "" if none — e.g. since=0)
              + TIMESTAMP + b"\n"   (current unix SECONDS, decimal ASCII)
              + BODY                (raw request body bytes; EMPTY for GET)

  The client signs MESSAGE with Ed25519 (its 32-byte secret seed via
  `sigil_core::sign`) and sends two headers: **`X-Sigil-Timestamp`** (the same
  decimal value used in MESSAGE) and **`X-Sigil-Signature`** (standard-base64 of
  the 64-byte signature). Go (`opsauth.go`) and Rust (`cli/src/lib.rs`) build the
  same domain prefix + same append order, so the messages agree byte-for-byte.

### sigild — `authorizeOps`, dev-gated Ed25519 verification ✅
- New `internal/api/opsauth.go` (**stdlib-only**: `crypto/ed25519`,
  `encoding/base64`, `errors`, `net/http`, `strconv`, `time`). Enabled **only**
  when `sigild` is configured with **`SIGILD_OPLOG_PUBKEY`** = standard-base64 of a
  32-byte Ed25519 **public** key (and the dev op-log flag is on). When
  `SIGILD_OPLOG_PUBKEY` is **unset there is NO auth** — current behavior is
  unchanged and the existing op-log tests still pass.
- On **both GET and POST** `/v1/vaults/{vaultID}/ops`, when configured:
  (1) read `X-Sigil-Timestamp` + `X-Sigil-Signature` — missing/blank → **401**;
  (2) parse the timestamp as int64, reject non-int or `abs(now - ts) > 300s`
  (stale/skew) → **401**; (3) reconstruct MESSAGE from `r.Method`, `r.URL.Path`,
  `r.URL.RawQuery`, the timestamp header, and the (already 64-KiB-size-limited)
  body; (4) base64-decode the signature and `ed25519.Verify(pubkey, MESSAGE, sig)`
  — false → **401**; (5) on success, fall through to the normal append/list
  handler. Every 401 uses the existing typed envelope
  `{"error":"unauthorized","detail":"…"}` via the existing `writeError` path.
- On startup with the pubkey configured, `main.go` emits a loud WARN: **"DEV op-log
  request AUTH ENABLED: Ed25519, SINGLE configured DEV device key,
  replay-window-bounded (not replay-proof) — dev-only, do NOT expose publicly."**

### cli/ — `sigil keygen` + `--key` request signing ✅
- New `sigil keygen --out device.key` generates a 32-byte seed (OS CSPRNG via the
  already-present `getrandom`), derives the public key with
  `sigil_core::public_key_from_seed`, and writes the **key file** as JSON
  `{"version":1,"seed":"<std-b64 32B>","public_key":"<std-b64 32B>"}` with mode
  **0600**; it prints the public key to paste into `SIGILD_OPLOG_PUBKEY`.
- `sigil push` / `sigil pull` gained **`--key <file>`** (or the **`SIGIL_DEVICE_KEY`**
  env var): when supplied they construct the same canonical MESSAGE and attach the
  `X-Sigil-Timestamp` / `X-Sigil-Signature` headers (signing via `sigil_core::sign`).
  With no key the requests are sent unsigned exactly as before — so they succeed
  against a no-pubkey server and get a **401** against a pubkey-configured one.
- ⚠️ Loudly labeled in `--help`, the lib doc comments, and `cli/README.md`. The
  CLI keeps its **PRE-AUDIT / UNAUDITED / not-for-real-secrets** banner.

### libsigil/core — untouched (lock unchanged) ✅
- This phase only **uses** the existing `sigil_core::{sign, public_key_from_seed}`
  from Phase 11. **No core change:** `git diff --quiet libsigil/Cargo.lock` →
  unchanged, `getrandom` count still **0**, `#![forbid(unsafe_code)]` + wasm-pure
  intact. The CLI's `getrandom` did not leak into the wasm-pure core.

### Tests ✅
- sigild: `opsauth_test.go` covers signed POST/GET accepted, missing headers → 401,
  garbage signature → 401, stale/future skew → 401, wrong key → 401, tampered body
  → 401, and the **disabled-unchanged regression** (no pubkey → existing behavior).
  `go test -race ./internal/api/` race-clean.
- cli: 26 lib + 2 integration tests, incl. `push_with_key`/`pull_with_key` asserting
  the signature verifies over the contract message, and keygen 0600 / round-trip.

### Verification — LIVE cross-language interop (the real gate) ✅
Built `sigild` (`/tmp/sigild_p12` from `./cmd/server`) + the CLI
(`cli/target/debug/sigil`). `sigil keygen --out device.key` → file mode 0600,
printed pubkey `UQKTPgGDkRSyDQ57tRKH8Nj2n/6DaYOW6xUOEQexZpw=`. Started the server
with `SIGILD_ENABLE_DEV_OPS=1 SIGILD_OPLOG_PUBKEY=<that> SIGILD_ADDR=:18103` (the
loud AUTH-ENABLED WARN fired). Sealed a real container with `SIGIL_PASSWORD=pw`
(`op.bin`, 177 bytes). **The point — Rust-signed, Go-verified:**
1. `sigil push --vault demo --in op.bin --key device.key --server :18103` →
   **"pushed vault demo seq 1"**, exit 0; access log **POST … status 201**. The
   **Rust Ed25519 signature was ACCEPTED by Go `crypto/ed25519.Verify`** — the
   canonical messages agree byte-for-byte.
2. Same `sigil push` **without `--key`** → **HTTP 401**
   `{"error":"unauthorized","detail":"missing or invalid op-log request signature"}`,
   exit 1.
3. `sigil pull --vault demo --out-dir inbox --key device.key` →
   **"pulled seq 1 → …/inbox/demo/op-1.sigil"**, cursor at 1, exit 0; signed
   **GET status 200**.
4. `sigil pull` **without `--key`** → **HTTP 401**, exit 1 (signed GET 200 vs
   unsigned GET 401 both in the access log).
5. Raw `curl` POST with a bogus `X-Sigil-Signature` + `X-Sigil-Timestamp` → **401**;
   raw `curl` GET with bogus sig → **401**; a structurally-valid-but-wrong 64-byte
   sig (base64 of 64 zero bytes) → **401**.
6. **END-TO-END:** `sigil open` the **pulled** `op-1.sigil` with `pw` → recovered
   plaintext **== original** (`diff` match). Encryption survives the full
   push → auth → pull round trip.
7. **No-pubkey server** (`SIGILD_ENABLE_DEV_OPS=1`, **no** `SIGILD_OPLOG_PUBKEY`,
   `:18104`) → an **UNSIGNED** push succeeded ("pushed vault demo seq 1", exit 0).
   **Auth is off by default; existing behavior is unchanged.**

Server access log corroborates: signed POST 201, unsigned POST 401, signed GET 200,
unsigned GET 401, two bogus-curl 401s, wrong-64B-sig 401 — **zero ERROR lines**.
Servers killed cleanly; temp dir + binaries removed.

- Gate: sigild `gofmt -l` clean · `go vet ./...` clean · `go test ./...` pass
  (api + store, all `opsauth_test` cases) · `go test -race ./internal/api/`
  race-clean · `go build ./...` OK. cli `cargo fmt --check` · `clippy -D warnings`
  · **26 lib + 2 integration** tests · build OK. Regression: libsigil
  fmt/clippy/**51+7** tests/wasm/**getrandom 0** ✓; `libsigil/Cargo.lock`
  unchanged. All 6 workflow YAMLs parse ✓. Web untouched.
- Over-claim scan CLEAN across `opsauth.go`, `opsauth_test.go`, `cli/src/{lib,main}.rs`,
  `cli/README.md`, `main.go`, `handlers.go`, `router.go`, and the docs — every
  "audited"/"secure" hit is a negation or a qualified/technical term (OS CSPRNG
  "cryptographically-secure random bytes"); no "post-quantum secure" / "SOC 2" /
  unqualified "end-to-end encrypted". The auth is explicitly labeled **SINGLE
  configured DEV device key**, **replay-window-bounded (not replay-proof)**,
  **dev-only**, **plain-HTTP**.

### ⛔ Still NOT production (honest scope)
- This is a **single, static, configured DEV device key** — one `SIGILD_OPLOG_PUBKEY`,
  not a registry. The **300-second timestamp window bounds replay but does NOT
  fully prevent it** — there is **no nonce/jti store**, so a captured signed request
  can be replayed inside the window; production needs nonce tracking. **Full device
  enrollment, a multi-device key registry, and JWT bearer tokens** (see
  `sigild/internal/auth`) remain **FUTURE**. The transport is still **plain HTTP,
  dev/localhost only**. Auth stays **off by default** (no pubkey configured → the
  op-log is unauthenticated exactly as before), and the prod ops default is still
  `501`. ADR 0008 + `docs/{api,architecture}.md` were updated by the docs track;
  this entry finalizes the remaining living docs (this file, `CLAUDE.md`,
  `README.md`).

## 2026-06-22 — Phase 13 (deployment readiness — manual publish, local stack, IaC validation)

Theme: make the deployment **verifiably READY without shipping anything** — a
human-triggered container publish, a loopback-only edge→app topology smoke, and
the offline IaC validators all green — while keeping the stealth/pre-audit posture
intact (**nothing applied, nothing exposed, no domain**). The whole surface landed
in commit **c493055**; this entry back-fills the journal for it. Readiness and
exposure are deliberately **decoupled** — captured in the new **ADR 0009**.

### The manual GHCR publish workflow — `.github/workflows/publish-sigild.yml` ✅
- A `workflow_dispatch`-**ONLY** GitHub Actions workflow. There is intentionally
  **NO `push` / `pull_request` / `schedule`** trigger — nothing builds or
  publishes automatically; a human runs it by hand from the Actions tab. (The only
  `push` token in the file is `push: true` inside the docker build-push step — a
  step arg, **not** a workflow trigger.) Confirmed `workflow_dispatch`-only this
  pass (`on:` has exactly one key).
- It builds `sigild` from `sigild/Dockerfile` and pushes to
  **`ghcr.io/${{ github.repository_owner }}/sigild`** (= `ghcr.io/<owner>/sigild`),
  tagged with the git **short SHA** (+ an optional dispatch `tag` input), passing
  `VERSION=<short_sha>` as a build-arg to match sigild's `-ldflags` version
  injection. `permissions: packages: write`; logs into GHCR via `GITHUB_TOKEN`; a
  final step **reminds the operator to set the GHCR package PRIVATE**.
- ⚠️ **Not run here** — there is no GHCR auth on this machine and running it would
  be an outward-facing action, so the YAML is reviewed by eye, not executed.
  Because publish is manual-only + the package is private, **CI cannot leak the
  project**.

### deploy/local/ — loopback-only Caddy → sigild topology smoke ✅
- New `deploy/local/{compose.yaml,Caddyfile.local,README.md}`: a compose stack
  that stands up the production **Caddy → sigild** edge shape on the local box —
  **NOT a deployment**. Hard guarantees baked into the artifacts: **loopback-only**
  (Caddy publishes `127.0.0.1:8080→80`, never `0.0.0.0`; sigild is `expose`d on the
  compose network only, never host-published), **no real TLS/ACME**
  (`auto_https off` — never contacts Let's Encrypt, obtains no publicly-trusted
  cert), **no PQ proof**, **disposable** (`down -v`).
- Verified end-to-end this pass, then torn down:
  `docker compose -f deploy/local/compose.yaml up -d --build` built `sigild:local`
  from the distroless `Dockerfile` (~14 MB; VERSION defaults to `dev` — compose
  passes no build-arg). `curl http://127.0.0.1:8080/healthz` **through Caddy** →
  **HTTP 200** `{"status":"ok","version":"dev"}`, with `Via: 1.1 Caddy` and the
  Caddyfile.local hardening headers (`X-Content-Type-Options: nosniff`, `Server`
  stripped) + sigild's `X-Request-Id`, proving it traversed the proxy. `/readyz` →
  **200** `{"checks":{"postgres":"unconfigured","redis":"unconfigured"},"version":"dev"}`
  (no `status` field on readyz). `/v1/vaults/abc/ops` → **501** (dev op-log off =
  production default; `SIGILD_ENABLE_DEV_OPS` unset). Caddy reverse-proxies to
  `sigild:8080` over the compose **bridge network** (Docker DNS on the service
  name); the `127.0.0.1:8080` is only the host→Caddy:80 hop — the loopback
  Caddy→sigild hop is the *production* single-VM shape, not the local one.
  `docker compose down -v` removed both containers + the network; re-curling
  `127.0.0.1:8080` → connection-refused, `docker ps -a` shows no `local-*`.

### Offline IaC validation — caddy / terraform / nomad all green ✅
- Caddy, Terraform, and Nomad were **brew-installed** and their **offline**
  validators run cleanly (all exit 0) — syntax/schema checks that contact no cloud
  or cluster:
  - **caddy v2.11.4** `caddy validate --adapter caddyfile`: `deploy/caddy/Caddyfile`
    → "Valid configuration" (benign INFO only — auto_https adds a :443 TLS policy +
    HTTP→HTTPS redirect); `deploy/local/Caddyfile.local` → "Valid configuration"
    (auto_https fully off, as intended).
  - **terraform v1.15.6**: `fmt -check -recursive` clean; `init -backend=false` OK
    (reused hcloud provider 1.66.0 from the committed
    `deploy/terraform/.terraform.lock.hcl` — added in c493055 so `validate` runs
    offline); `validate` → "Success! The configuration is valid."
  - **nomad v2.0.3**: `fmt -check` clean; `nomad job validate
    deploy/nomad/sigild.nomad.hcl` → "Job validation successful" (with the expected
    offline note that the driver config isn't validated without an agent; **no**
    shutdown_delay warning — the jobspec's `shutdown_delay="5s"` silences it). The
    jobspec still points at the `ghcr.io/PLACEHOLDER/sigild:latest` placeholder.
- ⚠️ `systemd-analyze` is **N/A on macOS**, so `deploy/systemd/sigild.service`
  stays **by-eye only** (run `systemd-analyze verify` on a Linux host).

### deploy/preflight.sh — read-only GO/NO-GO gate ✅
- New POSIX-sh `deploy/preflight.sh`: a **read-only** checklist that provisions /
  exposes / mutates **nothing**. Four gates from `docs/deployment.md`
  (§4 DNS/ACME, §5 secrets, §2 image flow, §8 toolchain): the target
  `SIGIL_DEPLOY_HOST` A/AAAA **resolves**; the systemd `EnvironmentFile`
  (`/etc/sigild/sigild.env`) is **present**; the Nomad jobspec image is **not the
  `ghcr.io/PLACEHOLDER` placeholder**; **Docker present**. Exit 0 = GO; non-zero =
  NO-GO (= count of failed gates).
- Verified: with all prereqs unset → **3 FAIL** (DNS / secrets / placeholder image)
  + 1 PASS (docker), verdict **"NO-GO — 3 gate(s) FAILED"**, exit 3; faking a
  resolvable `SIGIL_DEPLOY_HOST=example.com` flips DNS to PASS → **2 FAIL**, exit 2.
  It **correctly reports NO-GO** until a human stages DNS + secrets + a published
  image.

### ADR 0009 — manual / human-gated deploy and publish ✅
- New `docs/decisions/0009-manual-gated-deploy-and-publish.md` (Accepted —
  2026-06): records *why* nothing ships automatically — publish is
  `workflow_dispatch`-only to a **private** GHCR package, no CI `terraform apply` /
  `nomad job run`, local validation is **loopback-only + offline**, and a preflight
  gate stands between "ready" and "deploy". Same house pattern as the op-log ADRs
  (0003 / 0006 / 0008): default safe, gate the risky path behind an explicit human
  opt-in, never expose it. The ADR set is now **0001–0009**.

### ⛔ Still NOT deployed — nothing applied / published / exposed (LOUD + honest)
- **Nothing outward-facing happened.** No image was pushed to GHCR (the workflow is
  manual-only and was **not run** — no GHCR auth here); **no `terraform apply`, no
  `nomad job run`**; **no domain** registered; the local compose stack was
  **loopback-only and has been torn down**. The IaC is **validated but never
  applied**; the Nomad jobspec still points at `ghcr.io/PLACEHOLDER/sigild` and
  preflight still says **NO-GO**. Publish + apply await an **explicit human
  trigger** with the prerequisites (purchased domain, staged secrets, a published
  private image) that are **not present here** — exactly the stealth gate in
  `docs/sprint-72h.md` / `deployment.md` §7 and ADR 0009.
- Living docs finalized in this same change: `journal.md` (this entry), `CLAUDE.md`,
  and `README.md`; `docs/deployment.md` + ADR 0009 carry the operator detail.

## 2026-06-22 — Phase 15 (op-log auth v2: signed nonce + replay cache; Ed25519 across the FFI)

Theme: close the one honest gap ADR 0008 left open — the op-log's device-key auth
(Phase 12) *bounded* replay by a 300 s window but did **not prevent** it (no nonce
store, so a captured signed request could be resubmitted inside the window) — and,
in parallel, finish exposing the Phase-11 Ed25519 primitive across the **C-ABI** so
a client in any language can sign/verify. Two disjoint tracks (sigild+cli auth · the
ffi sig exports), then an independent verifier; the gate plus a **live cross-language
v2 interop + a live replay rejection + the RFC 8032 vector re-proven through the
C-ABI** were all re-run first-hand. Production behaviour is unchanged (default ops
still `501`; auth still off unless `SIGILD_OPLOG_PUBKEY` is set). ADR 0010 and
`docs/{api,architecture,crypto-spec}.md` were updated by the docs track; this entry
finalizes the remaining living docs (this file, `CLAUDE.md`, `README.md`).

### The contract — op-log auth v2 (signed nonce + replay cache), a CLEAN break from v1 ✅
- The signed MESSAGE gains a per-request **nonce** line and a new domain prefix, so
  the exact bytes both sides now build are:
  `"sigil-oplog-auth-v2\n" + METHOD + "\n" + PATH + "\n" + QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + BODY`
  — METHOD uppercase, PATH = `r.URL.Path` (no query), QUERY = raw query (`""` if
  none), TIMESTAMP = decimal unix seconds, NONCE = the **exact `X-Sigil-Nonce`
  header text used verbatim** (so both sides agree byte-for-byte), BODY = raw body
  (`""` for GET). Three headers now required: `X-Sigil-Timestamp`,
  **`X-Sigil-Nonce`**, `X-Sigil-Signature`.
- **v2 supersedes v1 outright** — a clean break, not a negotiated version: there are
  **no external clients** (only the in-repo Go server + Rust CLI), so the domain
  prefix simply moved `…-v1` → `…-v2` and a stale v1 signature (which lacks the
  nonce line) now fails closed. A request with no `X-Sigil-Nonce` is rejected.
- **Gate unchanged:** all of this is active **only** when `SIGILD_OPLOG_PUBKEY` is
  set; unset → no auth, existing no-auth tests unchanged, prod default still `501`.

### sigild — the time-bounded seen-nonce replay cache ✅
- `internal/api/opsauth.go` (stdlib-only; adds `sync`) bumps `opsAuthDomain` to
  `"sigil-oplog-auth-v2\n"` and, in `authorizeOps`, enforces the check in strict
  order: (1) all three headers present/non-blank → else 401; (2) parse timestamp,
  `abs(now-ts) > 300s` → 401; (3) reconstruct the v2 MESSAGE (with the **raw nonce
  header**) and `ed25519.Verify` false → 401; (4) **only after a valid signature** —
  so an unauthenticated probe never touches the cache — the nonce is
  checked/recorded.
- New `nonceCache`: an in-memory, **concurrency-safe** (`sync.Mutex`),
  **time-bounded** `map[nonce]ts`. `checkAndRecord` first **evicts** every entry with
  `ts < now-300` (a nonce is remembered exactly as long as its request could still
  pass the timestamp window), then treats a still-present nonce as a **replay** (401),
  else records it. A hard **size cap** (`nonceCacheMaxEntries = 50_000`) is a backstop
  so the map cannot grow without bound under abuse (once at the cap, fresh nonces are
  refused). Replay 401s keep the typed envelope with a **distinct detail** —
  `{"error":"unauthorized","detail":"replayed request"}` — while generic signature
  failures stay `"missing or invalid op-log request signature"`.

### cli/ — v2 request signing (fresh CSPRNG nonce per request) ✅
- `sigil push` / `sigil pull` (with `--key` / `SIGIL_DEVICE_KEY`) now generate a
  **fresh ≥16-byte nonce from `getrandom`** per request, std-base64-encode it to the
  `X-Sigil-Nonce` header, build the identical v2 MESSAGE, and sign with
  `sigil_core::sign`. Every request carries a distinct nonce, so two otherwise-identical
  pushes never collide in the server's cache. The loud DEV / plain-HTTP / PRE-AUDIT /
  UNAUDITED banners are intact.

### libsigil/ffi — Ed25519 across the C-ABI ✅
- `ffi/src/lib.rs` now exports the Phase-11 primitive over the C-ABI:
  `sigil_public_key_from_seed(seed → out_public_key)`,
  `sigil_sign(seed, message, message_len, out_signature)`, and
  `sigil_verify(public_key, message, message_len, signature)`, plus a new status code
  **`SIGIL_ERR_VERIFY = -4`** (invalid point / malformed sig / well-formed-but-not-
  verifying all collapse to it → no structure leak). `#![deny(unsafe_op_in_unsafe_fn)]`
  intact; every `unsafe` block carries a `// SAFETY:` note. Hand-written
  `ffi/include/sigil.h` mirrors the prototypes + the length `#define`s
  (`SIGIL_SIG_SEED_LEN 32`, `SIGIL_SIG_PUBLIC_KEY_LEN 32`, `SIGIL_SIGNATURE_LEN 64`).
  **core untouched this phase** — the ffi only *uses* existing core fns.

### Verification — LIVE v2 interop + REPLAY rejected + RFC 8032 through the C-ABI (the real gate) ✅
- **Live cross-language v2 interop (Rust signs → Go verifies).** Built
  `/tmp/sigild_p15` + `cli/target/debug/sigil`; `sigil keygen --out device.key`
  printed pubkey `90uYnRcWKVzlq3TCg9oXLFcnI6qcAFPJHLO59ruGFDg=`; started
  `SIGILD_ENABLE_DEV_OPS=1 SIGILD_OPLOG_PUBKEY=<pubkey> SIGILD_ADDR=:18120` (health
  200). Sealed a real 164-byte container. Results: (1) `sigil push --key` →
  **"pushed vault demo seq 1"**, exit 0 (ACCEPTED); (2) push **without `--key`** →
  **HTTP 401** `{"error":"unauthorized","detail":"missing or invalid op-log request
  signature"}`, exit 1; (3) `sigil pull --key --since 0` → **"pulled seq 1"**, exit 0;
  (4) pull **without `--key`** → **401**; (5) bogus `curl` ts/nonce/sig → **401**;
  (6) **TAMPERED** (valid Ed25519 sig but changed body) → **401**; (7) **STALE** (valid
  sig over ts = now-400s) → **401**; (8) `sigil open` the pulled `op-1.sigil` →
  **ROUNDTRIP_EQUAL=YES** (decrypted `cmp`-equal to the original plaintext). A
  **second** server on `:18121` with **no** `SIGILD_OPLOG_PUBKEY` accepted an
  **unsigned** push (seq 1) — the unauthenticated path is unchanged.
- **Replay REJECTED — unit + live.** Unit: `opsauth_test.go`'s
  `TestOpsAuthReplayRejected` builds ONE signed request and submits it twice — the
  POST subtest asserts rec1==201 then rec2 is a 401 with detail `"replayed request"`;
  the GET subtest asserts rec1==200 then the same 401. Companions confirm the cache
  semantics: `TestOpsAuthFreshNonceSucceedsTwice` (two requests differing only by
  nonce both 201), `TestOpsAuthNonceOutsideWindowRejectedByTimestamp` (a stale ts is
  rejected BEFORE the nonce is recorded), `TestNonceCacheEvictsExpired`,
  `TestNonceCacheHardCap` — all PASS under `go test -race -count=1 ./internal/api/`
  (ok, 1.309s, race-clean). Live: a small Go signer (asserting its derived pubkey ==
  `device.key`'s `public_key`) signed a v2 message with a **FIXED nonce**, then the
  identical request was curled TWICE at `:18120 /v1/vaults/replaytest/ops` → attempt
  #1 **HTTP 201** `{"vaultID":"replaytest","seq":1}`, attempt #2 **HTTP 401**
  `{"error":"unauthorized","detail":"replayed request"}` (access log shows 201 then
  401 on the same path). **The Phase-12 / ADR-0008 replay caveat is closed.**
- **RFC 8032 through the FFI.** `ffi/src/lib.rs`'s `rfc8032_test1_through_ffi` drives
  RFC 8032 Ed25519 TEST 1 (empty message) entirely through the C-ABI:
  `sigil_public_key_from_seed` → pubkey `d75a9801…511a`, `sigil_sign(NULL, 0)` → sig
  `e5564300…100b`, `sigil_verify(pk, NULL, 0, sig)` → `SIGIL_OK`. All three assert in
  `cargo test` (sigil-ffi **13 passed, 0 failed**). **C smoke (best-effort):** built
  the staticlib (`libsigil_ffi.a`), compiled a C file that `#include "sigil.h"`,
  derived the pubkey, signed the empty message, and verified — output "C SMOKE PASS:
  pk+sig match RFC8032 TEST1, good verify=SIGIL_OK, tampered verify=SIGIL_ERR_VERIFY",
  exit 0 (a one-byte-tampered sig returns `SIGIL_ERR_VERIFY` = -4).

### Gate + isolation ✅
- sigild: `gofmt -l` clean · `go vet ./...` clean · `go test ./...` pass ·
  `go test -race -count=1 ./internal/api/` race-clean · `go build ./...` OK.
- cli: `cargo fmt --check` · `clippy -D warnings` clean · **26 lib + 2 integration**
  tests (incl. `push_with_key`/`pull_with_key` asserting a ≥16-byte fresh-per-request
  nonce + the signature verifying over the reconstructed v2 message) · build OK.
- libsigil: fmt · clippy -D warnings · **51 core + 13 ffi** tests · wasm32 build OK.
  **core untouched:** `libsigil/Cargo.lock` unchanged, `getrandom` count still **0**,
  `#![forbid(unsafe_code)]` + wasm-pure intact; `ffi` keeps
  `#![deny(unsafe_op_in_unsafe_fn)]`. All 7 workflow YAMLs parse. Web untouched.
- Over-claim scan CLEAN — every "audited"/"secure" hit across `opsauth.go`,
  `ffi/src/lib.rs`, `sigil.h`, and the docs is a negation or an honest caveat
  (pre-audit / UNAUDITED / "classical Ed25519" / RFC 8032 / "ML-DSA-65 PQ half is
  future work"); no "post-quantum secure" / "SOC 2" / unqualified "end-to-end
  encrypted". The auth is labeled **SINGLE configured DEV device key**, the cache
  **per-process/in-memory**, **dev-only**, **plain-HTTP**.

### ADR 0010 — op-log auth v2 (signed nonce + replay cache) ✅
- New `docs/decisions/0010-op-log-auth-v2-nonce-replay.md` (Accepted — 2026-06)
  records *why* v2 replaces v1 outright (no external clients → clean break, no
  version negotiation) and closes the ADR-0008 replay caveat, with the honest
  consequences below. The ADR set is now **0001–0010**.

### ⛔ Still NOT production (honest scope)
- Still a **SINGLE configured DEV device key** (`SIGILD_OPLOG_PUBKEY`), not a
  registry. The replay cache is **per-process / in-memory** — it stops a replay
  against **this** sigild instance only; a multi-instance production deploy needs a
  **shared store** (e.g. Redis) so a request replayed against a *different* instance
  is also caught, and would want it to survive restarts. **Device enrollment, a
  multi-device key registry, key rotation, and JWT bearer tokens** (see
  `sigild/internal/auth`) remain **FUTURE**. Transport is still **plain HTTP,
  dev/localhost only**; auth stays **off by default** (no pubkey → the op-log is
  unauthenticated exactly as before); the op-log is still opaque + dev-gated and the
  prod ops default is `501`. The FFI sig exports are a **raw, classical, UNAUDITED
  Ed25519** building block — the ML-DSA-65 PQ half of the planned hybrid stays
  unimplemented and none of it is wired into an auth/enrollment flow.

## Documentation strategy

Recording the decision so the doc set stays coherent as the repo grows:

- **`CLAUDE.md`** = the working guide (toolchains, known-green commands,
  guardrails) — read first by anyone (human or agent) doing work.
- **`journal.md`** = this chronological log (what/why/next, per session/phase) —
  the source of truth for non-obvious context. **~1.2k lines now** (13 phases) —
  past the point where a single file is comfortable. ➡️ **Rotate per-month**
  (e.g. `journal/2026-06.md`) at the next natural break rather than let it sprawl
  further; the trigger has effectively been reached.
- **`README.md`** = the front door (what the repo is, layout, build/test) for a
  first-time reader.
- **`docs/`** = topic docs: `crypto-spec.md`, `threat-model.md`, `sprint-72h.md`,
  `deployment.md`, `api.md`, and now **`architecture.md`** (the map that ties the
  pieces together).
- **`docs/decisions/`** = lightweight **ADRs** (Nygard-style) for load-bearing
  choices — started in **Phase 9** with an index + `0001`–`0005` (ADR practice,
  getrandom isolation, dev-gated op-log, crypto-agility suite registry, stdlib-only
  sigild). ➡️ Add a new ADR in the **same change** as any future load-bearing
  decision (e.g. "why the salt+params live in the CLI container header, not the
  envelope", "why the client speaks plain HTTP only" remain good candidates to
  capture).

## 2026-07-13 — Phase 16 (X25519 classical key-agreement in libsigil-core)

### Context & mandate
- Goal: add the **classical X25519** key-agreement half of the planned hybrid
  KEX (X25519&ML-KEM-768) to `libsigil-core` as a standalone, real cryptographic
  primitive — derive a public key and compute a shared secret — without touching
  any existing KDF/AEAD/Ed25519 code and without breaking the wasm-pure / no-RNG
  invariants.
- ⚠️ This is the **key-agreement PRIMITIVE only**. It is **not** wired into any
  product flow (no key exchange / session establishment). The **ML-KEM-768
  post-quantum KEM half stays FUTURE/unimplemented** — there is still **no
  post-quantum KEM** in this repo, and the hybrid (X25519 & ML-KEM-768 combined
  via HKDF) does **not yet exist**. Real but **UNAUDITED**.

### core — `core/src/kx.rs` ✅
- New module exposing a **raw-bytes** X25519 API, re-exported from `lib.rs`
  (`mod kx;` line 45; `pub use kx::{x25519_public_key, x25519_shared_secret,
  KxError, X25519_PUBLIC_KEY_LEN, X25519_SECRET_KEY_LEN, X25519_SHARED_SECRET_LEN}`
  lines 51–54): `x25519_public_key(&[u8; 32]) -> [u8; 32]` (scalar-mult of the
  caller's secret against the RFC 7748 basepoint) and
  `x25519_shared_secret(&[u8; 32] secret, &[u8; 32] their_public) ->
  Result<[u8; 32], KxError>`, plus the length constants
  `X25519_SECRET_KEY_LEN`/`X25519_PUBLIC_KEY_LEN`/`X25519_SHARED_SECRET_LEN`
  (all 32) and the `KxError` enum.
- **Caller-supplied entropy:** the API takes a **32-byte secret SCALAR** from the
  caller — exactly like the KDF takes the salt, the AEAD takes the nonce, and the
  Ed25519 primitive takes the seed. **core still generates NO randomness** (no
  RNG, no key-gen); `x25519_public_key` uses the `X25519_BASEPOINT_BYTES` const
  and both functions call `x25519(scalar, point)` on caller-supplied bytes. The
  secret scalar must come from a cryptographically secure source on the caller's
  side.
- **Non-contributory rejection.** `x25519_shared_secret` **rejects an all-zero /
  low-order shared secret** — after the scalar-mult it checks `shared == [0u8; 32]`
  (kx.rs lines 122–124) and returns `Err(KxError::NonContributory)` if so, so a
  low-order/identity peer public key can't force a known all-zero shared secret.
- ⚠️ **Raw DH output, not a key.** The 32-byte shared secret is the raw X25519
  result and **must be run through a KDF** (e.g. the existing HKDF-SHA256 layer)
  before use as a symmetric key — documented in the module docs and the crypto
  spec. **classical only** — this is the X25519 half; the PQ ML-KEM-768 half is
  documented as future/unimplemented in the module docs, `lib.rs`, the crypto
  spec, the architecture map, and ADR 0007. Labeled **UNAUDITED** throughout.
- **Deterministic.** X25519 is deterministic per RFC 7748, so a given
  (secret, public) always yields the same shared secret — asserted by
  `agreement_is_deterministic`. No per-exchange RNG is needed.

### Dependency & the WASM/GETRANDOM gate
- Chose **`x25519-dalek = { version = "2", default-features = false }`** — the
  `default-features = false` is load-bearing: it drops the `rand_core`/`getrandom`
  path (we use only the raw `x25519`/basepoint scalar-mult, never key-gen RNG).
  As anticipated, x25519-dalek 2.0.1 **shares `curve25519-dalek`** with the
  existing `ed25519-dalek`, so it added little and pulled in **no getrandom edge**.
- ✅ **The gate held.** `grep -c 'name = "getrandom"' libsigil/Cargo.lock` =
  **0** (before and after the change; `grep -c 'getrandom'` for any occurrence is
  also **0**), and `cargo build -p sigil-core --target wasm32-unknown-unknown`
  **succeeds** — the wasm-pure invariant is preserved. `#![forbid(unsafe_code)]`
  (lib.rs line 37) and `no_std` (`core` + `alloc`) are intact.

### Tests ✅
- **RFC 7748 §6.1 Diffie–Hellman known-answer vector**
  (`kx::tests::rfc7748_section_6_1_dh_known_answer_vector`): alice_priv
  `77076d0a…`, alice_pub `8520f009…`, bob_priv `5dab087e…`, bob_pub `de9edb7d…`,
  shared **K = `4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742`**.
  It re-derives **both** public keys AND asserts **both DH directions**
  (`alice_secret × bob_pub` and `bob_secret × alice_pub`) equal K — a real interop
  vector plus the agreement symmetry, not just an internal round-trip.
- **RFC 7748 §5.2 scalar-mult vector 1**
  (`kx::tests::rfc7748_section_5_2_scalarmult_vector_1`): k = `a546e36b…`,
  u = `e6db6867…`, out =
  **`c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552`**.
- **Non-contributory rejection asserted:** `all_zero_public_key_is_non_contributory`
  (`x25519_shared_secret(secret, [0u8; 32])` → `Err(KxError::NonContributory)`) and
  `known_order_eight_point_is_non_contributory` (a low-order order-8 point → the
  same `Err`) both PASS.
- Plus `agreement_is_deterministic` and a constants/lengths check — **6 kx tests**
  in all.
- ✅ `cargo fmt --check` clean · `cargo clippy --all-targets -D warnings` clean ·
  `cargo test` — **sigil-core 57 PASS**, sigil-ffi 13 PASS · wasm build OK ·
  getrandom count **0**. Regression: cli fmt/clippy/**26 + 2** tests ✓
  (`cli/Cargo.lock` unchanged — only `libsigil/Cargo.lock` moved); sigild
  gofmt/vet/test/build ✓; all 7 workflow YAMLs parse ✓. Web untouched.

### docs — crypto-spec.md / architecture.md / ADR 0007 ✅
- `docs/crypto-spec.md`, `docs/architecture.md`, and **ADR 0007**
  (`0007-caller-supplied-entropy-in-core.md`) were updated by the docs track —
  ADR 0007 now lists the **X25519 secret scalar** alongside the salt / nonce /
  Ed25519 seed as caller-supplied entropy, notes the deterministic DH (no
  per-exchange RNG), and names the ML-KEM-768 PQ KEM half as still unimplemented.
  This entry finalizes the remaining living docs (this file, `CLAUDE.md`,
  `README.md`).

### ➡️ Still NOT wired in — future (honest)
- This phase adds the **primitive only**. It is **not** connected to any key
  exchange / session-establishment flow, and the raw shared secret still needs a
  KDF pass before use. The hybrid X25519 & ML-KEM-768 KEM does **not yet exist** —
  only the classical X25519 half, and it is unaudited; the ML-KEM-768 PQ half
  stays future/unimplemented.

## 2026-07-13 — Phase 17 (ML-KEM-768 post-quantum KEM in libsigil-core)

### Context & mandate
- Goal: add the **post-quantum ML-KEM-768** (NIST FIPS 203 Module-Lattice KEM)
  half of the planned hybrid KEX (X25519&ML-KEM-768) to `libsigil-core` as a
  standalone, real cryptographic primitive — deterministic key generation,
  encapsulation, and decapsulation — without touching the existing
  KDF/AEAD/Ed25519/X25519 code and without breaking the wasm-pure / no-RNG
  invariants. This is the **FIRST post-quantum primitive in the repo.**
- ⚠️ **KEM PRIMITIVE only.** It is **not** combined with the Phase-16 classical
  X25519 half into the hybrid `ss_combined`, and **not** wired into any key
  exchange / session establishment / enrollment flow. Real but **UNAUDITED**.

### core — `core/src/mlkem.rs` ✅
- New module exposing a **raw-bytes** ML-KEM-768 API, re-exported from `lib.rs`
  (`mod mlkem;` + `pub use` of the three functions, the six length constants, and
  `MlKemError`): `ml_kem768_keygen(&[u8; 64]) -> (ek[1184], dk[2400])`,
  `ml_kem768_encapsulate(&ek, &coin[32]) -> Result<(ct[1088], ss[32]), MlKemError>`,
  and `ml_kem768_decapsulate(&dk, &ct) -> Result<ss[32], MlKemError>`. The
  FIPS 203 sizes are pinned as consts (`ML_KEM768_ENCAPS_KEY_LEN` 1184,
  `_DECAPS_KEY_LEN` 2400, `_CIPHERTEXT_LEN` 1088, `_SHARED_SECRET_LEN` 32,
  `_KEYGEN_SEED_LEN` 64, `_ENCAPS_COIN_LEN` 32). The fixed-size raw-bytes shape is
  deliberately FFI-friendly for a later `sigil-ffi` C-ABI export.
- **Caller-supplied entropy — core still generates NO randomness.** keygen takes a
  64-byte `d‖z` seed and drives the FIPS 203 `generate_deterministic(d, z)`; encaps
  takes a 32-byte coin `m` and drives `encapsulate_deterministic(m)`; decaps needs
  no entropy. Exactly like the KDF salt, the AEAD nonce, the Ed25519 seed, and the
  X25519 scalar — the caller MUST draw the seed and coin from a cryptographically
  secure source (a predictable coin breaks encapsulation secrecy). No keygen or
  encapsulation RNG runs inside core (ADR 0007).
- **Decapsulation is total (FIPS 203 §6.3 implicit rejection).**
  `ml_kem768_decapsulate` returns `Ok` for any well-formed ciphertext: a tampered
  ciphertext yields a deterministic *pseudo-random* secret that differs from the
  sender's rather than an error. `MlKemError`'s arms
  (`BadEncapsKey`/`BadDecapsKey`/`BadCiphertext`) cover only structurally
  unparseable inputs — unreachable for the fixed-size array inputs here, present so
  the raw-bytes contract stays honest at the eventual FFI boundary. The core stays
  panic-free (the crate's total ops have a `()` error that never fires; surfaced as
  a parse error rather than an unwrap).
- ⚠️ **Raw shared secret, NOT a key.** The 32-byte output is the raw ML-KEM secret
  and **must be run through the hybrid HKDF combiner** (together with the X25519
  shared secret, so breaking either scheme alone doesn't compromise the session
  key) before use — the same rule the X25519 raw DH output already carries.
  **post-quantum only** — standalone, providing no classical protection on its own
  if ML-KEM were broken. Labeled UNAUDITED and NOT-yet-hybrid throughout the module
  docs, `lib.rs`, and the docs set.

### Dependency & the WASM/GETRANDOM gate — the make-or-break PQ milestone ✅
- Chose **`ml-kem = { version = "0.2.3", default-features = false, features =
  ["deterministic"] }`** (RustCrypto). The `deterministic` feature is what exposes
  the caller-entropy `generate_deterministic` / `encapsulate_deterministic` entry
  points; `default-features = false` keeps the RNG-driven convenience API out of
  the tree.
- ✅ **The gate HELD for a post-quantum lattice crate.** This was the
  make-or-break question of the phase: `grep -c 'name = "getrandom"'
  libsigil/Cargo.lock` = **0** (ml-kem pulls `rand_core` **without** its
  `getrandom` feature), and `cargo build -p sigil-core --target
  wasm32-unknown-unknown` **succeeds** — a full ML-KEM-768 implementation compiles
  wasm-pure with no system entropy backend. A notable milestone: the
  wasm-purity + getrandom-0 invariants survive the repo's **first PQ crate**.
  `#![forbid(unsafe_code)]` (lib.rs) and `no_std` (`core` + `alloc`) intact.

### Tests ✅
- **6 mlkem tests, all PASS.** `round_trip_shared_secret_matches` does the real
  KEM round-trip — keygen(SEED) → encapsulate(ek, COIN) → decapsulate(dk, ct) and
  asserts `ss_sender == ss_receiver` (32-byte agreement). Determinism:
  `keygen_is_deterministic` (same seed → byte-identical ek+dk; flipped seed →
  different) and `encapsulate_is_deterministic` (same ek,coin → identical ct+ss;
  different coin → different). Implicit rejection:
  `tampered_ciphertext_is_implicitly_rejected` (flip `ct[0]`, decaps returns `Ok`
  with a secret DIFFERENT from the sender's) and
  `wrong_decaps_key_yields_different_secret` (a valid ct under the wrong dk also
  returns `Ok`, different secret). `constants_have_expected_lengths` pins the
  FIPS 203 sizes.
- ⚠️ **No official FIPS 203 / NIST ACVP KAT is embedded**, and this is disclosed
  honestly in a source NOTE: reproducing one needs the exact
  (`d, z, m -> ek, dk, ct, K`) bytes, which we will **not fabricate**. Correctness
  rests on the round-trip + determinism + implicit-rejection tests above plus the
  upstream `ml-kem` crate's own ACVP vetting. An honest gap, not a faked vector.
- ✅ `cargo fmt --check` clean · `cargo clippy --all-targets -D warnings` clean ·
  `cargo test` — **sigil-core 63 PASS** (incl. the 6 mlkem tests), sigil-ffi 13
  PASS · wasm32 build OK · getrandom count **0**. Regression: cli
  fmt/clippy/**26 + 2** tests ✓ (the shared `ml-kem` edge now appears in
  `cli/Cargo.lock` — expected, a separate crate that may use getrandom;
  `libsigil/Cargo.lock` is the one that must stay at 0, and does); sigild
  gofmt/vet/test/build ✓; all 7 workflow YAMLs parse ✓. Web untouched.

### docs — crypto-spec.md / architecture.md / ADR 0007 ✅
- `docs/crypto-spec.md`, `docs/architecture.md`, and **ADR 0007**
  (`0007-caller-supplied-entropy-in-core.md`) were updated by the docs track —
  ADR 0007 now lists the **ML-KEM-768 keygen seed (`d‖z`, 64 bytes) and
  encapsulation coin (`m`, 32 bytes)** alongside the salt / AEAD nonce / Ed25519
  seed / X25519 scalar as caller-supplied entropy, notes the deterministic FIPS 203
  variants (decapsulation needs no entropy), and records that both hybrid-KEM halves
  now exist standalone but no combiner assembles `ss_combined` yet. This entry
  finalizes the remaining living docs (this file, `CLAUDE.md`, `README.md`).

### ➡️ Still NOT wired in — future (honest)
- This is the **primitive only**. **Both** classical (X25519, Phase 16) and
  post-quantum (ML-KEM-768, this phase) hybrid-KEM halves now exist **standalone**,
  but the **hybrid combiner does NOT yet exist** — nothing runs both KEXes and folds
  their shared secrets through HKDF into `ss_combined`, so there is still no hybrid
  KEM in the repo, only its two separate pieces. The raw ML-KEM secret still needs a
  KDF pass before use. It is unaudited and not connected to any key exchange /
  session / enrollment flow; the **ML-DSA-65 post-quantum signature** half of the
  *other* planned hybrid stays unimplemented. No over-claims: "post-quantum"
  describes the ML-KEM-768 algorithm family — the **system is NOT "post-quantum
  secure".**

## 2026-07-13 — Phase 18 (hybrid KEM assembled: X25519 + ML-KEM-768 via HKDF)

### Context & mandate
- Goal: **combine** the two standalone KEM halves that Phases 16–17 left sitting
  side by side — the classical X25519 DH agreement (`kx.rs`) and the post-quantum
  ML-KEM-768 KEM (`mlkem.rs`) — into **one** hybrid KEM producing a single 32-byte
  combined shared secret, without touching the existing KDF/AEAD/Ed25519/X25519/
  ML-KEM code and without breaking the wasm-pure / no-RNG invariants. This is the
  piece that was explicitly missing at the end of Phase 17: "nothing runs both
  KEXes and folds their shared secrets through HKDF into `ss_combined`."
- ⚠️ This assembles the **hybrid KEM PRIMITIVE only**. It is real but **UNAUDITED**
  and **standalone** — it is **not** wired into any key exchange / session /
  account / vault flow. The **ML-DSA-65 post-quantum signature** half of the
  *other* planned hybrid stays unimplemented.

### core — `core/src/hybrid.rs` ✅
- New module that performs **no new low-level cryptography of its own** — it
  *composes* the two existing building blocks. `hybrid_encapsulate` and
  `hybrid_decapsulate` are the two sides, re-exported from `lib.rs` (`mod hybrid;`
  line 53; `pub use hybrid::{hybrid_decapsulate, hybrid_encapsulate,
  HybridEncapsulation, HybridError, HYBRID_SHARED_SECRET_LEN}` lines 61–64):
  - `hybrid_encapsulate(recipient_x25519_pub, recipient_mlkem_encaps_key,
    ephemeral_x25519_secret, mlkem_coin) -> Result<(eph_x25519_pub[32],
    mlkem_ct[1088], combined[32]), HybridError>` — runs the X25519 DH against the
    recipient's public key, derives the ephemeral public key, ML-KEM-encapsulates
    to the recipient's encaps key, then `combine`s.
  - `hybrid_decapsulate(recipient_x25519_secret, recipient_mlkem_decaps_key,
    sender_eph_x25519_pub, mlkem_ct) -> Result<combined[32], HybridError>` — the
    matching recover side.
  - The raw-bytes fixed-size-array shape is deliberately FFI-friendly for a later
    `sigil-ffi` C-ABI export.
- **The combiner — `combine()` is real HKDF-SHA256, not XOR or a plain concat.**
  `ss_combined = HKDF-SHA256(ikm = ss_x ‖ ss_kem ‖ transcript_hash, salt = None,
  info = "sigil-hybrid-v1") → 32 bytes`, where `transcript_hash =
  SHA256(eph_x25519_pub ‖ mlkem_ct)`. Both raw component secrets feed the HKDF
  input keying material (the 96-byte `ikm`), so the combined key needs **both**
  halves; the transcript hash binds the exact ciphertext material (ephemeral
  public key + ML-KEM ciphertext) so the halves cannot be mixed-and-matched or
  substituted across sessions; the fixed `"sigil-hybrid-v1"` `info` label is the
  domain separation. `salt = None` because the concatenated raw secrets are
  already high-entropy — HKDF is used purely as the combiner/labelling step. This
  matches the RFC 9794 / NIST SP 800-56C Rev. 2-style concatenation-KDF combiner
  documented in `docs/crypto-spec.md`.
- **The hybrid property (honest design intent of an UNAUDITED primitive).**
  Because both `ss_x` and `ss_kem` are concatenated into the HKDF input, the
  combined secret is *designed* to stay secret if **either** the X25519 **or** the
  ML-KEM-768 component remains secure — the standard hybrid-combiner property
  (recovering the combined key requires breaking **both**). Stated as design
  intent, not a proven or audited guarantee. Nothing here makes the system — or
  even this primitive — "post-quantum secure"; "post-quantum" names the ML-KEM-768
  component algorithm.
- **Caller-supplied entropy — core still generates NO randomness.** The module
  never generates the sender's ephemeral X25519 secret or the ML-KEM
  encapsulation coin; the caller supplies both, exactly as it supplies the
  Argon2id salt, the AEAD nonce, the X25519 scalar, and the Ed25519 seed elsewhere
  (ADR 0007). A fresh ephemeral secret + coin per encapsulation is required; reuse
  breaks ephemeral secrecy.
- **`HybridError`** wraps the failure of either half so callers can tell which
  primitive rejected the inputs: `Kx(KxError)` — reachable, a non-contributory /
  low-order X25519 public key (RFC 7748 §6.1) — and `MlKem(MlKemError)` —
  unreachable for the fixed-size arrays here, present so the raw-bytes contract
  stays honest at the eventual FFI boundary. Both `From` impls are provided so the
  `?` operator threads component errors up.

### Dependency & the WASM/GETRANDOM gate — no new deps ✅
- **No new dependencies.** `git diff libsigil/core/Cargo.toml` is empty; `hybrid.rs`
  reuses `kx` (X25519), `mlkem` (ML-KEM-768), and the `hkdf` + `sha2` crates the
  AEAD layer already depends on. The combiner is the same vetted HKDF-SHA256 used
  elsewhere in the crate.
- ✅ **The gate held.** `grep -c 'name = "getrandom"' libsigil/Cargo.lock` = **0**
  (rechecked after the wasm build), and `cargo build -p sigil-core --target
  wasm32-unknown-unknown` **succeeds** — the hybrid assembly stays wasm-pure with
  no system entropy backend. `#![forbid(unsafe_code)]` (lib.rs) and `no_std`
  (`core` + `alloc`) intact.

### Tests ✅ — the round-trip capstone plus the four required properties
- **8 hybrid tests, all PASS**, covering the four load-bearing properties:
  - **(a) End-to-end round-trip agreement** — `round_trip_hybrid_kem_agrees` is
    the capstone: the sender `hybrid_encapsulate`s to the recipient's
    `(x25519_pub, ml_kem_encaps_key)`, the recipient `hybrid_decapsulate`s with its
    `(x25519_secret, ml_kem_decaps_key)`, and **`k_sender == k_receiver`** — the two
    halves compose into one agreed key.
  - **(b) Transcript binding** — `tampered_ciphertext_yields_different_combined_secret`
    (`ct[0] ^= 1`; ML-KEM decaps is total so it still returns `Ok` via implicit
    rejection, but `assert_ne!` vs the sender's key) and
    `tampered_ephemeral_pubkey_yields_different_combined_secret` (`eph_pub[0] ^= 1`
    → `assert_ne!`). A flipped ciphertext or ephemeral public key changes the
    combined key regardless.
  - **(c) Both halves feed the output** — `both_halves_feed_the_combined_secret`
    flips ONLY the ML-KEM half (holding X25519 + transcript fixed), then ONLY the
    X25519 half — each changes the combined key, so neither half alone can
    reproduce it.
  - **(d) Non-contributory propagation** — `low_order_recipient_pub_is_non_contributory`:
    an all-zero recipient public key makes `hybrid_encapsulate` return
    `Err(HybridError::Kx(KxError::NonContributory))` rather than folding a known
    shared secret into the combiner.
  - Plus `encapsulate_is_deterministic`, `combine_is_deterministic`, and a
    constants/length check.
- ✅ `cargo fmt --check` clean · `cargo clippy --all-targets -D warnings` clean ·
  `cargo test` — **sigil-core 71 PASS** (incl. the 8 hybrid tests), sigil-ffi 13
  PASS · wasm32 build OK · getrandom count **0** · `#![forbid(unsafe_code)]`
  present. Regression: cli fmt/clippy/**26 + 2** tests ✓; sigild
  gofmt/vet/test/build ✓; all 7 workflow YAMLs parse ✓. Web untouched.

### docs — crypto-spec.md / architecture.md / ADR 0011 ✅
- `docs/crypto-spec.md`, `docs/architecture.md`, and **ADR 0011** were already
  updated by the docs track — ADR 0011 records the hybrid-KEM combiner decision
  (concatenation-KDF via HKDF-SHA256 with the `"sigil-hybrid-v1"` label and the
  transcript binding). This entry finalizes the remaining living docs (this file,
  `CLAUDE.md`, `README.md`).

### ➡️ What this closes, and what's still open (honest)
- This **closes the hybrid KEM**: both KEX halves — classical X25519 (Phase 16)
  and post-quantum ML-KEM-768 (Phase 17) — now **combine into one 32-byte secret**
  via HKDF-SHA256, designed to stay secret if either component holds. The gap
  called out at the end of Phase 17 ("the hybrid combiner does NOT yet exist") is
  filled.
- Still open: (1) it is the **primitive only** — **UNAUDITED** and **standalone**,
  not wired into any key exchange / session / account / vault flow; (2) the
  **ML-DSA-65 post-quantum signature** half of the *other* planned hybrid
  (Ed25519 & ML-DSA-65) stays unimplemented — the Ed25519 classical half exists,
  the PQ half does not; (3) no over-claims: the **system is NOT "post-quantum
  secure"** — "post-quantum" describes the ML-KEM-768 component algorithm and the
  hybrid's *design intent*, on an unaudited building block.

## 2026-07-13 — Phase 19 (ML-DSA-65 post-quantum signature in libsigil-core)

### Context & mandate
- Goal: add the **post-quantum ML-DSA-65** (NIST FIPS 204 Module-Lattice Digital
  Signature Algorithm, security category 3) half of the planned hybrid signature
  (Ed25519&ML-DSA-65) to `libsigil-core` as a standalone, real cryptographic
  primitive — deterministic key generation, signing, and verification — without
  touching the existing KDF/AEAD/Ed25519/X25519/ML-KEM/hybrid code and without
  breaking the wasm-pure / no-RNG invariants. This is the **second post-quantum
  primitive** in the repo (ML-KEM-768 was the first, Phase 17) and the PQ
  counterpart to the classical Ed25519 signer (Phase 11).
- ⚠️ **SIGNATURE PRIMITIVE only.** It is **not** combined with the Phase-11
  classical Ed25519 half into a hybrid signature, and **not** wired into any
  identity / enrollment / device-key / auth flow. Real but **UNAUDITED**.

### core — `core/src/mldsa.rs` ✅
- New module exposing a **raw-bytes** ML-DSA-65 API, re-exported from `lib.rs`
  (`mod mldsa;` line 61; `pub use` of the three functions, the four length
  constants, and `MlDsaError`, lines 76–79): `ml_dsa65_keygen(&[u8; 32]) ->
  (pk[1952], sk[4032])`, `ml_dsa65_sign(&sk, message) -> Result<sig[3309],
  MlDsaError>`, and `ml_dsa65_verify(&pk, message, &sig) -> Result<(), MlDsaError>`.
  FIPS 204 sizes are pinned as consts (`ML_DSA65_PUBLIC_KEY_LEN` 1952,
  `_SECRET_KEY_LEN` 4032 — the standard `skEncode` form, `_SIGNATURE_LEN` 3309,
  `_KEYGEN_SEED_LEN` 32). The fixed-size raw-bytes shape is deliberately
  FFI-friendly for a later `sigil-ffi` C-ABI export, matching mlkem/kx/sig.
- **Caller-supplied entropy — core still generates NO randomness, for a SIGNING
  scheme this time.** keygen takes the 32-byte FIPS 204 keygen seed `xi` and drives
  `ExpandedSigningKey::from_seed` (= `ML-DSA.KeyGen_internal`); signing uses the
  FIPS 204 **deterministic** variant (`sign_deterministic(msg, &[])`, empty context,
  randomizer `rnd` fixed to zero), so a signature is a pure function of
  `(secret_key, message)` and NO per-signature entropy is drawn — the crate needs no
  RNG for signing either. Exactly like the Argon2id salt, the AEAD nonce, the
  Ed25519 seed, the X25519 scalar, and the ML-KEM seed/coin (ADR 0007). The caller
  MUST draw `xi` from a CSPRNG and safeguard it and the secret key it produces;
  whoever holds either can forge.
- **`MlDsaError`** (`#[non_exhaustive]`): `BadPublicKey` / `BadSecretKey` — parse
  guards, unreachable for the fixed-size arrays here (present so the raw-bytes
  contract stays honest at the eventual FFI boundary); `BadSignature` — reachable,
  `sigDecode`/`z`-norm/hint check rejected a structurally invalid signature;
  `Verification` — reachable, a well-formed signature that did not verify (wrong
  message, wrong key, tampered). keygen cannot fail so it returns a plain tuple, no
  `Result`.
- Honest caveat recorded in-module: the secret key crosses the API as the 4032-byte
  `skEncode` (the crate marks the expanded encode/decode deprecated in favour of the
  32-byte seed; we `#[allow(deprecated)]` it because our raw-bytes contract fixes the
  standard form). `skDecode` is **structural** (no FIPS 204 validation), so a
  *maliciously malformed* secret key is not gracefully rejected; every key from
  `ml_dsa65_keygen` is well-formed, so signing one back is total and panic-free.
- ⚠️ **post-quantum SIGNATURE only — standalone, NOT the hybrid.** A signature from
  this module stands on its own and provides no classical protection if ML-DSA were
  broken; a complete hybrid signer will produce BOTH an Ed25519 and an ML-DSA-65
  signature and a verifier will require both. Labeled UNAUDITED / NOT-yet-hybrid
  throughout the module docs, `lib.rs`, and the docs set. "post-quantum" names the
  ML-DSA-65 algorithm family — it does **not** mean the module, let alone the
  system, is "post-quantum secure".

### Dependency, MSRV bump & the WASM/GETRANDOM gate — the second PQ crate ✅
- Chose **`ml-dsa = { version = "0.1.1", default-features = false, features =
  ["alloc"] }`** (RustCrypto). `default-features = false` keeps `getrandom` out —
  ml-dsa's randomness enters only through its optional RNG-driven convenience API,
  which we do not enable; we use the deterministic `from_seed` / `sign_deterministic`
  entry points instead.
- **MSRV bump (load-bearing, reported):** ml-dsa 0.1.1 is `edition = "2024"` /
  `rust-version = "1.85"`, and **no 1.74-compatible release exists**, so
  `libsigil/core/Cargo.toml`'s `rust-version` was raised **1.74 → 1.85** — the
  minimum ml-dsa requires, documented in a Cargo.toml comment. This is the only dep
  that forced it: **ml-kem stayed at 0.2.3** (its 1.74 pin), every other dep still
  builds on 1.74. The machine toolchain is **rustc 1.96.0**, well above 1.85, so
  fmt/clippy/test/wasm all pass. (Contrast Phase 17, where ml-kem was deliberately
  pinned to 0.2.3 to *hold* 1.74; ml-dsa 0.1.x offered no such escape.)
- ✅ **The gate HELD for the repo's SECOND post-quantum lattice crate.** `grep -c
  'name = "getrandom"' libsigil/Cargo.lock` = **0** (ml-dsa pulls `rand_core`
  without its `getrandom` feature), and `cargo build -p sigil-core --target
  wasm32-unknown-unknown` **succeeds** — a full ML-DSA-65 signer compiles wasm-pure
  with no system entropy backend. `#![forbid(unsafe_code)]` (lib.rs) and `no_std`
  (`core` + `alloc`) intact. Note: ml-dsa 0.1.x pulls its own major versions of
  `hybrid-array` (0.4), `signature` (3), and `crypto-common` (0.2), distinct from
  ml-kem's 0.2.x lineage — both coexist in the lock without a getrandom edge.

### Tests ✅
- **8 mldsa tests, all PASS.** `round_trip_verifies` — keygen(SEED) → sign(sk, MSG)
  → verify(pk, MSG, sig) = `Ok(())` (and pins the returned buffer sizes).
  Determinism: `keygen_is_deterministic` (same seed → byte-identical (pk,sk); flipped
  seed → different) and `signing_is_deterministic` (same (sk,msg) → byte-identical
  sig — the FIPS 204 deterministic/`rnd=0` variant; different message → different
  sig). Rejection: `wrong_message_fails` → `Verification`, `tampered_signature_fails`
  (flip `sig[0]`) → `Verification | BadSignature`, `wrong_key_fails` (pk from a
  different seed) → `Verification`. `empty_message_round_trips` (empty message
  signs+verifies, and correctly rejects a non-empty one).
  `constants_have_expected_lengths` pins pk=1952/sk=4032/sig=3309/seed=32.
- ⚠️ **No official FIPS 204 / NIST ACVP KAT is embedded**, disclosed honestly in a
  source NOTE (lines 335–339): reproducing one needs the exact (`xi -> pk, sk`) and
  deterministic (`sk, M -> sig`) bytes, which we will **not fabricate**. Correctness
  rests on the round-trip + determinism + rejection tests plus the upstream `ml-dsa`
  crate's own ACVP vetting. An honest gap, not a faked vector — same posture as the
  ML-KEM-768 module.
- ✅ `cargo fmt --check` clean · `cargo clippy --all-targets -D warnings` clean ·
  `cargo test` — **sigil-core 79 PASS** (incl. the 8 mldsa tests), sigil-ffi 13
  PASS · wasm32 build OK · getrandom count **0**. Regression: cli fmt/clippy/**26 +
  2** tests ✓ (`cli/Cargo.lock` getrandom = 1 as ever — a separate native crate
  outside the wasm gate; `libsigil/Cargo.lock` is the one that must stay 0, and
  does); sigild gofmt/vet/test/build ✓; all 7 workflow YAMLs parse ✓. Web untouched.

### docs — crypto-spec.md / architecture.md / ADR 0007 ✅
- `docs/crypto-spec.md`, `docs/architecture.md`, and **ADR 0007**
  (`0007-caller-supplied-entropy-in-core.md`) were updated by the docs track —
  ADR 0007 now lists the **ML-DSA-65 keygen seed `xi` (32 bytes)** alongside the
  salt / AEAD nonce / Ed25519 seed / X25519 scalar / ML-KEM seed+coin as
  caller-supplied entropy, and records that deterministic FIPS 204 signing (`rnd=0`)
  keeps signing RNG-free too. This entry finalizes the remaining living docs (this
  file, `CLAUDE.md`, `README.md`), and notes the MSRV 1.74→1.85 bump.

### ➡️ What this adds, and what's still open (honest)
- This adds the **signature primitive only**. With it, **both halves of the planned
  hybrid signature now exist standalone** — classical Ed25519 (Phase 11) and
  post-quantum ML-DSA-65 (this phase) — but the **hybrid *signature* combiner does
  NOT yet exist**: nothing produces both signatures and requires both to verify. That
  mirrors where the KEM stood after Phase 17, except the KEM has since been assembled
  (the hybrid KEM combiner, Phase 18). So the crypto ledger now reads: **hybrid KEM =
  assembled** (X25519 + ML-KEM-768 via HKDF, Phase 18); **hybrid signature = both
  halves present, combiner still future**; and **none of it is wired into an actual
  key-exchange / session / identity / vault flow**. The remaining crypto work is the
  **hybrid signature combiner** and then **wiring the hybrid primitives into a real
  flow**.
- No over-claims: "post-quantum" describes the ML-DSA-65 algorithm family — the
  **system is NOT "post-quantum secure".**

## 2026-07-13 — Phase 20 (hybrid signature assembled: Ed25519 || ML-DSA-65)

### Context & mandate
- Goal: **assemble the hybrid signature** — compose the two existing signature
  primitives, the classical Ed25519 (Phase 11) and the post-quantum ML-DSA-65
  (Phase 19), into ONE signature that a verifier accepts **only if both halves
  validate**. This is the signature counterpart to the hybrid KEM combiner
  (Phase 18), and it **completes the hybrid crypto suite**: with it, **both**
  planned hybrid constructions — the hybrid KEM (X25519 & ML-KEM-768) and the
  hybrid signature (Ed25519 & ML-DSA-65) — now exist as standalone primitives.
- ⚠️ Composition only — **no new low-level cryptography**. `hybrid_sig.rs` calls
  the crate's existing `sign`/`verify` (sig.rs) and `ml_dsa65_*` (mldsa.rs); it
  adds no new dep and mints no keys. Real but **UNAUDITED** and **standalone** —
  NOT wired into any flow.

### core — `core/src/hybrid_sig.rs` ✅
- New module, re-exported from `lib.rs` (`mod hybrid_sig;` + `pub use
  hybrid_sig::{hybrid_sign, hybrid_verify, HybridSigError, HYBRID_SIGNATURE_LEN}`):
  `hybrid_sign(ed25519_seed[32], mldsa_keygen_seed[32], message) ->
  Result<[u8; 3373], HybridSigError>` and `hybrid_verify(ed25519_public_key[32],
  mldsa_public_key[1952], message, hybrid_signature[3373]) -> Result<(),
  HybridSigError>`. The raw-bytes, fixed-size-array shape is deliberately
  FFI-friendly for a later `sigil-ffi` export, matching sig/mldsa/kx/mlkem/hybrid.
- **Layout — plain concatenation, `ed25519_sig(64) ‖ ml_dsa65_sig(3309)` = 3373
  bytes.** `hybrid_sign` writes the Ed25519 signature to `out[..SIGNATURE_LEN]`
  (bytes `0..64`) then the ML-DSA-65 signature to `out[SIGNATURE_LEN..]` (bytes
  `64..3373`); `HYBRID_SIGNATURE_LEN = SIGNATURE_LEN(64) + ML_DSA65_SIGNATURE_LEN(3309)
  = 3373` (pinned by the `constant_has_expected_length` test). **Unlike the hybrid
  KEM there is NO KDF and NO transcript binding** — a signature is public and already
  commits to the message, and both component signatures cover the SAME message
  bytes, so the combiner is a plain concatenation plus an **AND over the two
  verifications**. `hybrid_verify` splits the 3373 bytes back into the two
  fixed-size halves and calls **both** `verify(ed25519_public_key, message,
  &ed_sig)?` **and** `ml_dsa65_verify(mldsa_public_key, message, &mldsa_sig)?`
  (Ed25519 checked first), returning `Ok(())` only if BOTH pass.
- **The hybrid identity is two caller-supplied seeds; signing is deterministic —
  core still generates NO randomness.** The signer holds a 32-byte Ed25519 seed AND
  a 32-byte ML-DSA-65 keygen seed (`xi`); `hybrid_sign` recomputes the ML-DSA-65 key
  pair from its seed on each call (via `ml_dsa65_keygen`) to recover the secret key
  it signs with, discarding the public key. Both component signatures are
  deterministic — Ed25519 per RFC 8032, ML-DSA-65 in its FIPS 204 deterministic
  variant (`rnd = 0`) — so the **hybrid signature is a pure function of `(seed_ed,
  seed_mldsa, message)`**: no per-signature entropy is drawn, and the crate needs no
  RNG for signing. Same caller-supplied-entropy contract as the salt / AEAD nonce /
  Ed25519 seed / X25519 scalar / ML-KEM seed+coin (ADR 0007). Whoever holds a seed
  can forge that half.
- **`HybridSigError`** (`#[non_exhaustive]`) wraps whichever half rejected the
  inputs so a caller can tell which scheme failed: `Ed25519(SigError)` — reachable,
  the classical half did not verify — and `MlDsa(MlDsaError)` — reachable on verify
  (ML-DSA half did not verify), unreachable-in-practice on sign (guards the derived
  secret-key length at the eventual FFI boundary). Both `From` impls are provided so
  `?` threads component errors up. `hybrid_verify` checks Ed25519 first, so an input
  that fails both halves surfaces as `Ed25519`.
- **The hybrid property (honest design intent of an UNAUDITED primitive):** because
  `hybrid_verify` returns `Ok(())` only when BOTH halves verify, a forgery over a
  message requires forging **both** an Ed25519 signature **and** an ML-DSA-65
  signature — the classical half still stands if ML-DSA-65 is broken, and the
  post-quantum half still stands if Ed25519 is broken (e.g. by a
  cryptographically-relevant quantum computer). Stated as design intent, not a
  proven or audited guarantee. Nothing here makes the module — let alone the
  **system** — "post-quantum secure" or "secure"; "post-quantum" names the ML-DSA-65
  component algorithm.
- Pre-audit caveats recorded in-module: `hybrid_sign` recomputes the 4032-byte
  ML-DSA-65 secret key from the seed on every call (deterministic, keeps the API a
  clean two-seed hybrid identity, but not free — a hot signer can cache the derived
  secret key and call `ml_dsa65_sign` directly); no zeroization of seeds / derived
  secret key / intermediates; unaudited; not wired into any product identity flow.

### Dependency & the WASM/GETRANDOM gate — no new deps ✅
- **No new dependencies.** `git diff libsigil/core/Cargo.toml` is empty; `hybrid_sig.rs`
  reuses `sig` (Ed25519) and `mldsa` (ML-DSA-65) — both already in the crate. The
  changed tree is only `lib.rs` (the `mod` + re-exports) plus the new `hybrid_sig.rs`
  and ADR 0012.
- ✅ **The gate held.** `grep -c 'name = "getrandom"' libsigil/Cargo.lock` = **0**
  (rechecked after the wasm build), and `cargo build -p sigil-core --target
  wasm32-unknown-unknown` **succeeds** — the hybrid signature stays wasm-pure with no
  system entropy backend. `#![forbid(unsafe_code)]` (lib.rs) and `no_std` (`core` +
  `alloc`) intact. MSRV unchanged (still 1.85 from the ml-dsa dep in Phase 19; the
  machine is rustc 1.96).

### Tests ✅ — the round-trip capstone plus the both-halves-required proofs
- **9 hybrid_sig tests, all PASS**, covering the load-bearing properties:
  - **Round-trip (capstone)** — `round_trip_hybrid_signature_verifies`:
    `hybrid_sign(&ED_SEED, &MLDSA_SEED, MSG)` → `hybrid_verify(&ed_pub, &mldsa_pub,
    MSG, &sig)` = **`Ok(())`** (and pins `sig.len() == HYBRID_SIGNATURE_LEN`). The two
    halves compose into one signature a joint verifier accepts.
  - **Both halves required — tamper the Ed25519 half** —
    `tampered_ed25519_half_fails_even_with_valid_mldsa`: `sig[0] ^= 0x01` (Ed25519
    half only; the ML-DSA-65 half at `64..` is intact and still valid) → verify
    returns `Err(HybridSigError::Ed25519(_))`.
  - **Both halves required — tamper the ML-DSA-65 half** —
    `tampered_mldsa_half_fails_even_with_valid_ed25519`: `sig[SIGNATURE_LEN] ^= 0x01`
    (i.e. `sig[64]`, ML-DSA-65 half only; the Ed25519 half at `0..64` is intact and
    still valid) → verify returns `Err(HybridSigError::MlDsa(_))`. Tampering EITHER
    half alone breaks the whole signature.
  - **Determinism** — `signing_is_deterministic`: `hybrid_sign` twice over the same
    `(seeds, message)` yields byte-identical 3373-byte output (`assert_eq!(a, b)`).
  - Plus `constant_has_expected_length` (3373 = 64 + 3309), `wrong_message_fails`,
    `wrong_ed25519_public_key_fails`, `wrong_mldsa_public_key_fails`, and
    `empty_message_round_trips`.
- ✅ `cargo fmt --check` clean · `cargo clippy --all-targets -D warnings` clean ·
  `cargo test` — **sigil-core 88 PASS** (incl. the 9 hybrid_sig tests), sigil-ffi
  **13 PASS** · wasm32 build OK · getrandom count **0** · `#![forbid(unsafe_code)]`
  present. Regression: cli fmt/clippy/**26 + 2** tests ✓ (`cli/Cargo.lock` getrandom
  = 1 as ever — separate native crate outside the wasm gate; `libsigil/Cargo.lock`
  is the one that must stay 0, and does); sigild gofmt/vet/test/build ✓; all 7
  workflow YAMLs parse ✓. Web untouched.

### docs — crypto-spec.md / architecture.md / ADR 0012 ✅
- `docs/crypto-spec.md`, `docs/architecture.md`, and **ADR 0012**
  (`0012-hybrid-signature-combiner.md`) were already updated by the docs track — ADR
  0012 records the combiner decision (plain concatenation `Ed25519.Sign(m) ‖
  ML-DSA-65.Sign(m)` with verification requiring both halves; no KDF / no transcript
  binding because a signature already commits to the message; both halves
  deterministic so the combined signature is RNG-free). This entry finalizes the
  remaining living docs (this file, `CLAUDE.md`, `README.md`).

### ➡️ What this closes, and what's still open (honest)
- This **assembles the hybrid signature** and thereby **COMPLETES the hybrid crypto
  suite**: both planned hybrids now exist as standalone primitives — the hybrid KEM
  (X25519 & ML-KEM-768 via HKDF, Phase 18) and the hybrid signature (Ed25519 &
  ML-DSA-65 by concatenation + AND-verify, this phase). The "combiner still future"
  gap called out at the end of Phase 19 is filled.
- Still open — the SAME gap for both hybrids: they are **primitives only**, **UNAUDITED**
  and **standalone**, **NOT wired into any flow**. The sigild op-log request auth
  still uses the **classical Ed25519 signature only** (not the hybrid); the
  record/account/vault path still uses the password-KDF → AEAD → envelope flow (no
  KEM, no signature). The remaining crypto work is **wiring the hybrid primitives
  into an actual account / session / record flow**, and then the eventual **audit**.
- No over-claims: "post-quantum" describes the ML-DSA-65 (and ML-KEM-768) component
  algorithms and the hybrids' *design intent* on unaudited building blocks — the
  **system is NOT "post-quantum secure".**

## 2026-07-13 — Phase 21 (hybrid public-key seal/open: encrypt a record to a recipient hybrid pubkey)

### Context & mandate
- Goal: **wire the hybrid KEM into an actual encryption flow** — the primitives
  were all assembled by Phase 20 but nothing *used* them. This phase composes the
  hybrid KEM (`hybrid.rs`, Phase 18) with the existing AEAD seal/open (`aead.rs`)
  and envelope codec (`envelope.rs`) into **hybrid public-key authenticated
  encryption**: `hybrid_seal` encrypts a record TO a recipient's **hybrid public
  key**, and `hybrid_open` recovers it with the recipient's **hybrid secret**. This
  is the FIRST time a hybrid primitive is put into a genuine flow.
- ⚠️ Composition only — **no new low-level cryptography and no new deps.**
  `hybrid_seal.rs` calls the crate's existing `hybrid_encapsulate`/`hybrid_decapsulate`,
  `seal`/`open`, and `Envelope::encode`/`decode`; it mints no keys and draws no
  entropy. A **CUSTOM** KEM-then-AEAD construction — **NOT RFC 9180 HPKE** — real
  but **UNAUDITED** and **standalone** (a crypto-level flow, still NOT the product's
  account / key-management / vault-storage model, and not used by sigild/CLI).

### core — `core/src/hybrid_seal.rs` ✅
- New module, re-exported from `lib.rs` (`mod hybrid_seal;` + `pub use
  hybrid_seal::{hybrid_open, hybrid_seal, HybridSealError, HybridSealed}`).
- **KEM-then-AEAD composition.** `hybrid_seal(recipient_hybrid_pub, ephemeral_x25519_secret,
  mlkem_coin, aead_nonce, aad, plaintext)` (hybrid_seal.rs lines 139–148): calls
  `hybrid_encapsulate(recipient pubkey, eph_secret, coin) -> (eph_pub, mlkem_ct,
  combined)` to derive a fresh 32-byte combined KEM secret to the recipient, then
  `seal(&combined, nonce, aad, plaintext).encode()` to AEAD-encrypt the record under
  it. It returns `(eph_pub, mlkem_ct, envelope)` — the ephemeral X25519 public key,
  the ML-KEM-768 ciphertext, and the encoded AEAD envelope — everything the recipient
  needs and nothing secret. `hybrid_open(recipient_hybrid_secret, eph_pub, mlkem_ct,
  aad, envelope)` (lines 176–184) is the inverse: `hybrid_decapsulate(recipient secret,
  eph_pub, mlkem_ct) -> combined` re-derives the same 32-byte secret, then
  `Envelope::decode` + `open(&combined, &env)` authenticates and decrypts. **No crypto
  is invented here** — it is a wiring of two audited-shape primitives.
- **Entropy stays caller-supplied — core generates NO randomness (ADR 0007).** The
  ephemeral X25519 secret, the ML-KEM encapsulation coin, and the AEAD nonce are all
  **parameters** to `hybrid_seal`; the module draws none itself. `getrandom` count
  stays 0 and the wasm32 build holds.
- **`HybridSealError`** (`#[non_exhaustive]`) distinguishes the two failure domains:
  `Hybrid(HybridError)` — the KEM step rejected an input (e.g. a non-contributory
  recipient X25519 public key) — and `Aead(AeadError)` — the envelope failed to
  decode or authenticate. `From` impls thread `?` through. `HybridSealed` names the
  `(eph_pub, mlkem_ct, envelope)` output shape.
- **Design intent (honest, of an UNAUDITED primitive):** confidentiality/integrity
  of the record to the recipient rests on the AEAD under a key that the hybrid KEM
  binds to BOTH the X25519 and ML-KEM-768 shares (transcript-bound HKDF combiner),
  so the combined key is designed to stay secret if EITHER KEM half holds. Stated as
  design intent, not a proven or audited guarantee; nothing here makes the module —
  let alone the **system** — "post-quantum secure" or "secure".

### Dependency & the WASM/GETRANDOM gate — no new deps ✅
- **No new dependencies.** `git diff libsigil/core/Cargo.toml` empty; `git diff
  libsigil/Cargo.lock` empty. `hybrid_seal.rs` composes `hybrid` + `aead` + `envelope`,
  all already in the crate. Changed tree is only `lib.rs` (mod + re-exports), the new
  `hybrid_seal.rs`, and the docs (crypto-spec / architecture / ADR 0013).
- ✅ **The gate held.** `grep -c 'name = "getrandom"' libsigil/Cargo.lock` = **0**
  (rechecked after the wasm build); `cargo build -p sigil-core --target
  wasm32-unknown-unknown` **succeeds**. `#![forbid(unsafe_code)]` (lib.rs) and
  `no_std` (`core` + `alloc`) intact. MSRV unchanged (still 1.85; machine rustc 1.96).

### Tests ✅ — the encrypt-to-pubkey round-trip plus wrong-recipient / tamper proofs
- **9 hybrid_seal tests, all PASS**, covering the load-bearing properties:
  - **Round-trip (capstone)** — `encrypt_to_pubkey_round_trip`: a sender seals TO the
    recipient's hybrid pubkey `(r_x_pub, ek)`; the recipient opens with the hybrid
    secret `(r_x_secret, dk)`; recovered == plaintext. It also scans the encoded
    envelope and asserts it does **not** contain the plaintext bytes.
  - **Wrong recipient** — `wrong_recipient_fails_with_aead_error`: opening with an
    unrelated recipient's `(x25519_secret, ml-kem decaps key)` derives a different
    combined key → `Err(HybridSealError::Aead(_))`; no plaintext leaks.
  - **Tamper (three)** — `tampered_envelope_is_rejected` (flip a tag byte) →
    `Err(Aead(Authentication))`; `tampered_mlkem_ct_is_rejected` (flip `ct[0]`) →
    `Err(Aead(Authentication))`; `tampered_ephemeral_pubkey_is_rejected` (flip
    `eph_pub[0]`) → `is_err`. Plus `aad_is_authenticated`: forging the AAD at open →
    `Err(Aead(Authentication))`.
  - **Non-contributory guard** — `non_contributory_recipient_pub_is_rejected`: an
    all-zero recipient X25519 public key →
    `Err(HybridSealError::Hybrid(HybridError::Kx(KxError::NonContributory)))`, so a
    degenerate recipient key is refused before any AEAD work.
  - Plus determinism (same inputs → byte-identical envelope) and an empty-plaintext
    round-trip.
- ✅ `cargo fmt --check` clean · `cargo clippy --all-targets -D warnings` clean ·
  `cargo test` — **sigil-core 97 PASS** (incl. the 9 hybrid_seal tests), sigil-ffi
  **13 PASS** · wasm32 build OK · getrandom count **0** · `#![forbid(unsafe_code)]`
  present. Regression: cli `cargo test` (2 integration tests) ✓ (`cli/Cargo.lock`
  getrandom = 1 as ever — separate native crate outside the wasm gate;
  `libsigil/Cargo.lock` is the one that must stay 0, and does); sigild
  gofmt/vet/test/build ✓; all 7 workflow YAMLs parse ✓. Web untouched.

### docs — crypto-spec.md / architecture.md / ADR 0013 ✅
- `docs/crypto-spec.md`, `docs/architecture.md`, and **ADR 0013**
  (`0013-hybrid-public-key-seal.md`) were already updated by the docs track — ADR
  0013 records the KEM-then-AEAD composition decision (hybrid_encapsulate → seal, a
  custom construction explicitly NOT RFC 9180 HPKE; caller-supplied ephemeral secret /
  coin / nonce; the `(eph_pub, mlkem_ct, envelope)` wire shape). This entry finalizes
  the remaining living docs (this file, `CLAUDE.md`, `README.md`).

### ➡️ What this opens, and what's still open (honest)
- This is the **first wiring of a hybrid primitive into an encryption flow**: the
  hybrid KEM now drives an actual encrypt-to-a-recipient-pubkey operation instead of
  standing alone. It is a **crypto-level flow / primitive**, not a product feature —
  a CUSTOM KEM-then-AEAD composition (NOT RFC 9180 HPKE), real but **UNAUDITED** and
  **standalone**.
- Still open — `hybrid_seal`/`hybrid_open` are **not exported over FFI** and **not
  used by sigild or the CLI**; there is still no account / key-management /
  vault-storage model behind them, and the sigild op-log auth still uses the
  classical Ed25519 signature only. Next: **FFI-export the hybrid primitives**, then
  integrate into a product path; then the eventual **audit**.
- No over-claims: "post-quantum" names the ML-KEM-768 component algorithm and the
  construction's *design intent* on unaudited building blocks — the **system is NOT
  "post-quantum secure".**

## 2026-07-13 — Phase 22 (FFI: hybrid encryption path over the C-ABI)

### Context & mandate
- Goal: **expose the hybrid encryption path (Phase 21) across the `sigil-ffi`
  C-ABI** so native clients can call it. Phase 21 wired the hybrid KEM into
  `hybrid_seal`/`hybrid_open` but that flow lived only in Rust — no client could
  reach it. This phase adds the thin extern-`"C"` surface (and its `sigil.h`
  declarations) over the core's already-existing hybrid primitives.
- ⚠️ FFI-only — **no new low-level cryptography, no new deps, and `libsigil/core`
  is untouched** (`git diff --stat libsigil/core` is EMPTY — not even a doc
  change). The core already re-exports `x25519_public_key`, `ml_kem768_keygen`,
  and `hybrid_encapsulate`/`decapsulate`/`seal`/`open` plus every length constant
  the FFI needs; this phase only wraps them. These are **UNAUDITED** primitives
  and the encryption path is a **CUSTOM KEM-then-AEAD** composition — **NOT RFC
  9180 HPKE**; the system is **NOT "post-quantum secure"**.

### ffi — `libsigil/ffi/src/lib.rs` + `include/sigil.h` ✅
- **Six new extern `"C"` exports** wrapping the hybrid encryption path:
  - `sigil_x25519_public_key` — derive the 32-byte X25519 public key from a
    32-byte secret scalar (a hybrid identity's classical public half).
  - `sigil_ml_kem768_keygen` — generate an ML-KEM-768 `(encaps, decaps)` key pair
    from a 64-byte `d‖z` seed (the PQ public half + secret half).
  - `sigil_hybrid_encapsulate` / `sigil_hybrid_decapsulate` — the two sides of the
    hybrid KEM (X25519 + ML-KEM-768 combined via HKDF into one 32-byte secret).
  - `sigil_hybrid_seal` — encrypt a record **to** a recipient's hybrid public key,
    outputting `(eph_pub, mlkem_ct, envelope)` in a heap `SigilBuffer`.
  - `sigil_hybrid_open` — decrypt with the recipient's hybrid secret key,
    outputting the recovered plaintext.
- **New status code `SIGIL_ERR_HYBRID` (-5)** for a hybrid-KEM rejection (notably
  a non-contributory / low-order X25519 public key) on
  encapsulate/decapsulate/seal, writing no output. `sigil_hybrid_open` instead
  mirrors `sigil_open`: **every** failure — hybrid-KEM rejection, envelope decode,
  or authentication — collapses to `SIGIL_ERR_OPEN`, and no plaintext is written,
  so the boundary never leaks structure or plaintext on a bad recipient / tamper.
- **`sigil.h`** gains the six prototypes, `#define SIGIL_ERR_HYBRID (-5)`, and the
  fixed-size length `#define`s the caller allocates against:
  `SIGIL_X25519_PUBLIC_KEY_LEN`/`SECRET_KEY_LEN` = 32, `SIGIL_MLKEM768_ENCAPS_KEY_LEN`
  = 1184, `DECAPS_KEY_LEN` = 2400, `CIPHERTEXT_LEN` = 1088, `KEYGEN_SEED_LEN` = 64,
  `ENCAPS_COIN_LEN` = 32, `SIGIL_HYBRID_SHARED_SECRET_LEN` = 32, `SIGIL_AEAD_NONCE_LEN`
  = 24. Fixed-size outputs (pubkeys, key pairs, KEM secret) go into caller-provided
  buffers with nothing to free; the seal envelope + the open plaintext come back in
  heap `SigilBuffer`s the caller MUST release with `sigil_buffer_free`. Hand-written,
  kept in sync with `lib.rs` by hand; `ffi/README.md` updated to match.
- **Caller-supplied entropy stays the caller's job (ADR 0007).** This layer draws
  NO randomness — the ephemeral X25519 secret, the ML-KEM coin, the keygen seed,
  and the AEAD nonce are all parameters and MUST come fresh per call from a CSPRNG.

### Unsafe discipline — ffi contract intact ✅
- `#![deny(unsafe_op_in_unsafe_fn)]` present (ffi `lib.rs:65`); `core` keeps
  `#![forbid(unsafe_code)]` (`core/lib.rs:68`). Every exported extern fn carries a
  `/// # Safety` section (12 exported fns total), and every `unsafe { … }` block
  carries a `// SAFETY` comment (46 production blocks; the few that looked bare
  sit under a shared multi-line SAFETY comment over consecutive `copy_fixed` /
  `optional_slice` statements). `nm` on the built `libsigil_ffi.dylib` shows all
  six new symbols (`_sigil_hybrid_*`, `_sigil_x25519_public_key`,
  `_sigil_ml_kem768_keygen`) as public `T` symbols.

### Dependency & the WASM/GETRANDOM gate — no new deps, core untouched ✅
- **No new dependencies, no `Cargo.toml`/`Cargo.lock` change.** The diff touches
  only `ffi/src/lib.rs`, `ffi/include/sigil.h`, `ffi/README.md`, and the two docs
  (`docs/architecture.md`, `docs/crypto-spec.md`) already updated by the docs
  track. `git diff --stat libsigil/core` is EMPTY.
- ✅ **The gate held.** `grep -c 'name = "getrandom"' libsigil/Cargo.lock` = **0**
  (rechecked twice, incl. after the wasm build); `cargo build -p sigil-core
  --target wasm32-unknown-unknown` **succeeds** — FFI work does not touch the
  wasm-pure core, and the invariant is intact. (FFI is a separate crate that MAY
  use unsafe; only `core` forbids it.)

### Tests ✅ — both hybrid C-ABI round-trips proven, plus a standalone C smoke
- **`cargo test --manifest-path libsigil/Cargo.toml`: sigil-core 97 PASS,
  sigil-ffi 19 PASS, 0 failed** (the ffi suite grew from 13 → 19 with six hybrid
  C-ABI tests). The load-bearing ones exercise the actual extern `"C"` fns:
  - **KEM round-trip** — `hybrid_kem_round_trip_through_ffi`:
    `sigil_hybrid_encapsulate` then `sigil_hybrid_decapsulate` recover the **same
    32-byte combined secret**.
  - **Seal/open round-trip (capstone)** — `hybrid_seal_then_open_round_trip`:
    `sigil_hybrid_seal` then `sigil_hybrid_open` recover the **exact plaintext**.
  - Plus `hybrid_empty_plaintext_round_trips`, `hybrid_wrong_recipient_open_fails`
    (collapses to `SIGIL_ERR_OPEN`, no leak), `hybrid_non_contributory_recipient_pub_errors`
    (→ `SIGIL_ERR_HYBRID`), and `hybrid_null_args_return_null_arg`.
- **Standalone C smoke (link + round-trip through the real header).** Compiled a
  C file (`#include "sigil.h"`) with `cc -std=c11 -Wall -Wextra` against the built
  `libsigil_ffi.dylib` + include dir — **linked cleanly, rc=0, no warnings**. It
  builds a recipient hybrid identity (`sigil_ml_kem768_keygen` from a fixed 64-byte
  seed + `sigil_x25519_public_key` from a fixed secret), runs `sigil_hybrid_seal`
  on a 35-byte message with AAD, then `sigil_hybrid_open`. Output:
  > `seal ok: envelope 88 bytes / open ok: recovered 35 bytes, EXACT MATCH /
  > wrong-recipient open rc=-2 (expect SIGIL_ERR_OPEN=-2) / ALL C-ABI SMOKE CHECKS
  > PASSED`
  process exit 0, buffers freed via `sigil_buffer_free`. Confirms the link, the
  hybrid seal→open round-trip, and that a wrong recipient secret returns
  `SIGIL_ERR_OPEN` **without leaking plaintext**.
- ✅ `cargo fmt --check` clean · `cargo clippy --all-targets -D warnings` clean ·
  wasm32 build OK · getrandom count **0**. Regression: cli fmt/clippy/**26 + 2**
  tests ✓ (`cli/Cargo.lock` getrandom = 1 as ever — separate native crate outside
  the wasm gate); sigild gofmt/vet/test/build ✓; all 7 workflow YAMLs parse ✓.
  Web untouched.

### docs — architecture.md / crypto-spec.md ✅
- `docs/architecture.md` and `docs/crypto-spec.md` were already updated by the docs
  track to describe the hybrid encryption path across the C-ABI. This entry
  finalizes the remaining living docs (this file, `CLAUDE.md`, `README.md`, and the
  `ffi/README.md` export table). **No new ADR** — Phase 22 is a mechanical FFI
  wrapping of primitives whose design decisions are already captured (the hybrid KEM
  combiner in ADR 0011 and the KEM-then-AEAD composition in ADR 0013); ADRs
  remain 0001–0013.

### ➡️ What this opens, and what's still open (honest)
- A **native client can now, over the C-ABI, generate a hybrid identity
  (X25519 + ML-KEM-768) and encrypt a record TO another party's hybrid public key**,
  then decrypt it — the Phase 21 flow is reachable from C. Both C-ABI round-trips
  (KEM and seal/open) are proven in-tree and via a standalone C smoke.
- Still open — it is a **crypto-level flow over the FFI, not a product feature**: a
  CUSTOM KEM-then-AEAD composition (NOT RFC 9180 HPKE), real but **UNAUDITED** and
  **standalone**. There is still no account / key-management / enrollment /
  vault-storage model behind it, and neither sigild nor the CLI calls it; the sigild
  op-log auth still uses the classical Ed25519 signature only. Next: **wire the
  hybrid path into an actual account / session / record flow.** ⚠️ Wiring the hybrid
  **signature** into sigild's op-log auth is **blocked** — Go's stdlib has no ML-DSA,
  so sigild stays stdlib-only Ed25519 until we take a PQ-sig dependency (breaks the
  no-go.sum invariant) or move the check off the Go server.
- No over-claims: "post-quantum" names the ML-KEM-768 component algorithm and the
  path's *design intent* on unaudited building blocks — the **system is NOT
  "post-quantum secure".**

## 2026-07-13 — Phase 23 (CLI hybrid public-key encryption: encrypt a file to a device hybrid identity)

### Context & mandate
- Goal: give the hybrid encryption path (Phase 21 core `hybrid_seal`/`hybrid_open`,
  Phase 22 FFI) its **FIRST user-facing exercise, end-to-end**. Everything hybrid so
  far lived in the Rust core or behind the C-ABI — no human-drivable command touched
  it. This phase adds three `sigil` subcommands that let one device encrypt a file
  **TO** another device's hybrid public identity and let that device decrypt it,
  with **no shared password** (public-key, not password, encryption).
- ⚠️ Wiring only — **no new low-level cryptography and no new deps.** The CLI
  composes the core's already-existing `hybrid_seal`/`hybrid_open` (+ `x25519_public_key`,
  `ml_kem768_keygen`) into on-disk identity + container formats. A **CUSTOM**
  KEM-then-AEAD construction — **NOT RFC 9180 HPKE** — real but **UNAUDITED**, and a
  **demo of the hybrid encryption path, NOT the product's account / key-management
  model**. Keeps the loud PRE-AUDIT / not-for-real-secrets posture.

### cli — `cli/src/lib.rs` + `cli/src/main.rs` ✅
- **Two on-disk identity files (JSON, std-base64 fields).**
  - **Secret** `<file>` (`HybridSecretIdentity`): `{"version":1,"x25519_secret":"<b64
    32>","mlkem_seed":"<b64 64>"}` — the private half a device keeps to itself. The
    ML-KEM-768 decaps key is re-derived from `mlkem_seed` on load (`ml_kem768_keygen`),
    so the seed alone reconstitutes the PQ secret. Written **mode 0600**.
  - **Public** `<file>.pub` (`HybridPublicIdentity`): `{"version":1,"x25519_public_key":
    "<b64 32>","mlkem_encaps_key":"<b64 1184>"}` — the shareable half a device hands to
    senders. Carries only public material (no `x25519_secret` / `mlkem_seed`). Written
    0644.
- **The `SIGILhyb` container** (`hybrid_seal_to_container` / `hybrid_open_container`):
  `magic b"SIGILhyb"(8)` + `version(1)` + `eph_x25519_pub(32)` + `mlkem_ct(1088)` +
  `envelope(..)` — a self-describing prefix (`HYBRID_FIXED_PREFIX_LEN` = 1129) followed
  by the `hybrid_seal` AEAD envelope tail (the nonce lives inside the envelope). A fixed
  `HYBRID_AAD = b"sigil-hybrid-cli/1"` namespaces this tool's records and is bound into
  the AEAD. No password anywhere — the KEM secret comes from encapsulating to the
  recipient's hybrid pubkey.
- **Three subcommands** (`main.rs`):
  - `sigil hybrid-keygen --out <file>` — draw a fresh 32-byte X25519 secret + 64-byte
    ML-KEM seed from the CSPRNG, write the 0600 secret `<file>` and shareable
    `<file>.pub`, and print the pubkey path for senders.
  - `sigil hybrid-seal --recipient-pub <pubfile> --in <file> --out <file>` — encrypt
    `--in` TO the recipient public identity, writing the `SIGILhyb` container.
  - `sigil hybrid-open --key <file> --in <file> --out <file>` — decrypt the container
    with the recipient's secret identity, writing the recovered plaintext.
- Decode is **defensive**: identity fields are length-checked per field
  (`decode_identity_field::<N>` rejects wrong-length base64), and the container decode
  rejects short/garbage/bad-magic/bad-version/truncated input **without panicking**
  (every split is length-gated first). Open failures collapse to
  `CliError::HybridSeal(HybridSealError)` — a wrong identity or a tampered container
  surfaces as `Aead(Authentication)` and writes **no** output file.

### Dependency & isolation gate — no new deps, libsigil lock untouched ✅
- **No new dependencies.** `cli/Cargo.toml` unchanged (`git diff --quiet` exit 0) —
  deps stay `sigil-core` + `getrandom` + `ureq` + `serde`/`serde_json` + `base64`;
  `cli/Cargo.lock` also unchanged. The hybrid commands reuse `sigil_core::hybrid_seal`/
  `hybrid_open` + `getrandom` (for the fresh secrets/seed) that were already present.
- ✅ **The wasm gate held.** `grep -c 'name = "getrandom"' libsigil/Cargo.lock` = **0**
  and `git diff --quiet libsigil/Cargo.lock` exit 0 — the CLI is a SEPARATE crate (own
  lock; its own getrandom = 1, outside the wasm gate) and did not leak into the
  wasm-pure core. `#![forbid(unsafe_code)]` retained in both `cli/src/main.rs` and
  `cli/src/lib.rs`.

### Tests ✅ — the encrypt-to-identity round-trip plus wrong-identity / tamper / hygiene
- **`cargo test --manifest-path cli/Cargo.toml`: 36 PASS, 0 failed** — `lib.rs` **33**
  (incl. **7 NEW** hybrid tests: identity derivation + save/load 0600 round-trip,
  decode rejects wrong-length field, seal/open round-trip, empty-plaintext round-trip,
  wrong-identity fails without leaking plaintext, tampered container rejected, and
  short/garbage/bad-magic/bad-version/truncated rejected without panic) and
  `tests/cli.rs` **3** (incl. **NEW** `hybrid_keygen_seal_open_round_trips_via_binary`
  driving the real `sigil` binary).
- ✅ `cargo fmt --all --check` clean · `cargo clippy --all-targets -D warnings` clean ·
  `cargo build` → `cli/target/debug/sigil` (4.8 MB).

### LIVE two-device proof (real binary, temp dirs)
- **Positive round-trip.** (B) `sigil hybrid-keygen --out B/id.key` → exit 0; wrote
  `B/id.key` (**mode 0600**) + shareable `B/id.key.pub` (0644). (A) wrote a known
  plaintext, then `sigil hybrid-seal --recipient-pub B/id.key.pub --in pt.txt --out
  msg.hyb` → exit 0, a **1242-byte `SIGILhyb` container** with the plaintext **absent
  in the clear**. (B) `sigil hybrid-open --key B/id.key --in msg.hyb --out got.txt` →
  exit 0; `cmp pt.txt got.txt` == **MATCH** (recovered == original).
- **Negative (wrong identity).** A DIFFERENT identity `B2` (`hybrid-keygen --out
  B2/id.key`) running `hybrid-open` on A's `msg.hyb` →
  > `sigil: error: could not hybrid-open record: Aead(Authentication)`
  exit 1, and **no output file was written** — no plaintext leaked.
- **Secret-file hygiene.** The secret `id.key` is mode **0600**; its `x25519_secret` /
  `mlkem_seed` base64 values do **NOT** appear anywhere in `id.key.pub` (the public
  file carries only `version` + `x25519_public_key` + `mlkem_encaps_key`).

### Regression — everything else still green ✅
- libsigil fmt/clippy clean; `cargo test` **97 + 19** PASS; wasm32 `sigil-core` build
  OK; getrandom count **0**. sigild gofmt/vet/test/build ✓. All 7 workflow YAMLs
  parse ✓. Web untouched.

### docs — architecture.md (docs track) + this finalizer ✅
- `docs/architecture.md` was already updated by the docs track to describe the CLI
  hybrid public-key commands. This entry finalizes the remaining living docs (this
  file, `CLAUDE.md`, `README.md`). **No new ADR** — Phase 23 is a CLI wiring of
  primitives whose design decisions are already captured (the hybrid KEM combiner in
  ADR 0011, the KEM-then-AEAD composition in ADR 0013); ADRs remain 0001–0013.

### ➡️ What this opens, and what's still open (honest)
- This is the **FIRST user-facing exercise of the hybrid stack end-to-end**: a person
  can run three commands to generate a device hybrid identity and public-key encrypt a
  file to another device — the Phase 21/22 flow is now reachable from a human-drivable
  CLI, and the two-device round-trip is proven live.
- Still open — it is a **demo / dev tool, NOT a product feature**: a CUSTOM
  KEM-then-AEAD construction (NOT RFC 9180 HPKE), real but **UNAUDITED**. There is
  still no account / device-enrollment / key-publication / trust / rotation model —
  identities are loose files a human copies by hand — and nothing in a real product
  path or in sigild uses it. Next: **a bigger wiring step — a real enrollment /
  session / key-management flow** behind the primitives, or the non-crypto product
  surface.
- No over-claims: "post-quantum" names the ML-KEM-768 component algorithm and the
  path's *design intent* on unaudited building blocks — the **system is NOT
  "post-quantum secure".**

## 2026-07-13 — Phase 24 (durable Postgres op-log backend)

### Context & mandate
- Goal: give the dev op-log its **first real, durable, concurrent store adapter**.
  Everything behind the `VaultLog` seam so far was process-local — the in-memory
  `MemVaultLog` is lost on restart, and the file-backed `FileVaultLog`
  (`SIGILD_OPLOG_DIR`) is a single-node convenience with no concurrency story beyond
  per-file locking. So the demo path (`sigil push` → `sigil pull`) could not survive a
  realistic multi-writer or restart-heavy dev setup, and the interface had never been
  exercised by a networked database.
- ⚠️ **Deliberate architectural shift.** This adds `sigild`'s **first third-party
  dependency (`pgx`)**, so the module gains a `go.sum` and the long-standing
  "sigild is stdlib-only" invariant is **relaxed** — honestly, for exactly this one
  backend. Recorded as **ADR 0014**, which *partially supersedes* **ADR 0005**
  (stdlib-only): the core server + the Mem/File backends stay stdlib-only; only the
  Postgres adapter links `pgx`, and it is dormant unless a DSN is configured.
- HARD RULES held: the server still stores **opaque client-encrypted blobs** and does
  **no crypto** (Postgres column is `bytea`; never decoded/parsed/ordered/merged); the
  op-log stays **dev-gated** (`SIGILD_ENABLE_DEV_OPS`, default **501**) and
  **unauthenticated unless `SIGILD_OPLOG_PUBKEY`** (unchanged). Postgres only adds a
  durable/concurrent backend — no new security properties, no auth model.

### sigild — `internal/store/postgresvaultlog.go` ✅
- **`PostgresVaultLog` (pgx/v5 `pgxpool`)** implements the identical `VaultLog` seam as
  the Mem/File backends. `NewPostgresVaultLog(ctx, dsn)` opens a `pgxpool` and ensures
  the schema `sigil_vault_ops (vault_id text, seq bigint, blob bytea, …)` keyed on
  `(vault_id, seq)`; `Close()` drains the pool.
- **Opaque `bytea`, defensive copies.** `Append` stores the exact client bytes as
  `bytea` and `Since` re-emits them unchanged; both sides copy the slice so a caller can
  never mutate stored/returned buffers. The 64 KiB per-op cap + `413` still live at the
  handler, unchanged.
- **Concurrency-safe per-vault `seq`.** Each append runs in a **transaction** that first
  takes a per-vault `pg_advisory_xact_lock(hashtext(vaultID))`, then inserts
  `seq = (SELECT COALESCE(MAX(seq),0)+1 FROM sigil_vault_ops WHERE vault_id = $1)`, so
  concurrent appenders to the **same** vault get gap-free, strictly increasing sequence
  numbers with no races. Reads (`since > N`) come off the indexed `(vault_id, seq)`
  ordering.
- **Selection precedence (`cmd/server/main.go`):** with dev-ops ON, backend =
  `SIGILD_OPLOG_POSTGRES` (a DSN) **>** `SIGILD_OPLOG_DIR` (file) **>** in-memory
  `MemVaultLog`. With dev-ops OFF (the default, only production-safe setting) **no
  backend is constructed** and both verbs of `/v1/vaults/{id}/ops` return **501**.

### Tests — 9 integration tests, gated on a DSN ✅
- New `internal/store/postgresvaultlog_test.go` **skips cleanly** when
  `SIGILD_TEST_POSTGRES` is unset (`t.Skip("set SIGILD_TEST_POSTGRES …")`), so the
  offline suite stays green with **no** database. Seven behavioral tests cover
  seq-increments, per-vault seq isolation, `since=0` returns all, `since` filtering,
  unknown-vault, defensive copy, and opaque-binary integrity; two showpiece tests cover
  concurrency and durability (below).
- **Verified LIVE against a real Docker Postgres 16** (host port 5544,
  `SIGILD_TEST_POSTGRES` set, `go test ./internal/store/ -run Postgres -race -v`) — all
  **9 RAN (not skipped) and PASSED under `-race`**; package result `ok, 2.189s`. Quoting
  the two showpieces:
  > `TestPostgresVaultLogConcurrentAppends` — 16 goroutines × 25 = **400 appends to ONE
  > vault** via `pg_advisory_xact_lock` + `MAX(seq)+1` inside a tx; asserted 400 ops with
  > a **unique, contiguous 1..400 seq set** — PASS 0.42s.
  > `TestPostgresVaultLogDurabilityAcrossReconnect` — wrote 3 ops, `Close()`d the pool,
  > opened a **SECOND fresh pool** on the same DSN, read all 3 back **byte-identically**,
  > and a 4th append **continued at seq 4** from the durable `MAX(seq)` — PASS 0.03s.
- Confirmed the same tests **SKIP** when `SIGILD_TEST_POSTGRES` is unset, and the
  container was removed afterward (`docker rm -f sigil_pg_v` → GONE).

### Dependency / stdlib-only shift ✅
- `sigild/go.mod` now `go 1.25.0` (pgx requires ≥1.25) and
  `require github.com/jackc/pgx/v5 v5.10.0`; the module gained a **`go.sum`**.
  `go mod verify` = all modules verified (pgx + transitive
  `pgpassfile`/`pgservicefile`/`puddle`, `golang.org/x/sync`, `golang.org/x/text`).
- Honest framing (per ADR 0014): sigild is now "**stdlib-only *except* the opt-in
  Postgres backend**," not "stdlib-only." Core server + Mem/File backends remain
  stdlib; `pgx` is dormant without a DSN.
- **libsigil wasm/getrandom invariant UNAFFECTED and re-confirmed:**
  `grep -c 'name = "getrandom"' libsigil/Cargo.lock` = **0** (unchanged); `cli/Cargo.lock`
  = 1 as ever (separate native crate). This phase is sigild + docs + CI only — core/CLI
  untouched.

### CI — `.github/workflows/sigild.yml` gained a Postgres service ✅
- The `sigild` workflow now stands up a **Postgres service container**, sets
  `SIGILD_TEST_POSTGRES` for the test step, and pins Go **1.25.x** (+ module cache) so
  the 9 integration tests **run in CI** (not just skip). All 7 workflow YAMLs still
  parse. `Dockerfile` bumped to `golang:1.25-alpine` and now `COPY go.mod go.sum` +
  `go mod download` before build.

### Regression — everything else still green ✅
- `gofmt -l sigild` empty · `go vet ./...` clean · `go test ./...` offline (no DSN) all
  packages **ok** (the 9 Postgres tests SKIP with a clear message; FileVaultLog 6 /
  MemKV 7 / MemVaultLog 7 PASS; api package ok) · `go build ./...` OK · `go mod verify`
  OK. Default op-log **unchanged**: dev-ops OFF ⇒ **501** for both verbs
  (`TestVaultOpsReturns501`, `TestVaultOpsDefaultStill501`,
  `TestOplogIntegrationGatingDisabled`); dev-ops ON with no env var ⇒ non-durable
  `MemVaultLog`. libsigil fmt/clippy/test + wasm32 build + getrandom 0; cli tests pass.
  Web untouched.

### docs — api.md / deployment.md / architecture.md / ADR 0014 (docs track) + this finalizer ✅
- `docs/api.md`, `docs/deployment.md`, `docs/architecture.md`, and **ADR 0014** were
  already written by the docs track (three backends + `SIGILD_OPLOG_POSTGRES`
  selection/precedence, the storage note, and the stdlib-only relaxation);
  `deploy/.../sigild.yml` (compose) gained a Postgres service. This entry finalizes the
  remaining living docs (this file, `CLAUDE.md`, `README.md`) and updates the RESUME
  ANCHOR's stdlib-only invariant.

### ➡️ What this opens, and what's still open (honest)
- The dev op-log now has a **durable, concurrent** home when a DSN is set, and the
  `VaultLog` seam is validated against a real networked database — the **first
  production-store adapter**, exercised live under `-race` for both concurrency and
  durability-across-reconnect.
- Still open — it is **one adapter, NOT the production data layer**: still dev-gated
  (default 501), still opaque `bytea`, still unauthenticated unless
  `SIGILD_OPLOG_PUBKEY`, and it owes auth / enrollment, per-vault authorization, CRDT /
  merge, managed migrations, backups-with-proven-restore, and replication (+ an object
  store for large blobs). It **must not be exposed publicly or hold real secrets.**
- No over-claims: durability + concurrency are the **only** new properties; the security
  posture is unchanged and the **system is NOT "post-quantum secure".**

## 2026-07-13 — Phase 25 (sigild reliability + auditability hardening)

### Context & mandate
- Goal: make the dev op-log **reliable to operate and auditable** — without touching
  its security posture. Two gaps stood out after Phase 24 gave it a networked Postgres
  backend: (i) the `VaultLog` seam (`Append`/`Since`) took **no `context.Context`**, so
  a client disconnect or slow request could not cancel in-flight storage work — against
  Postgres a dropped client could pin a pooled connection until the query returned on
  its own, and body reads were unbounded by the request lifetime; and (ii) there was
  **no visibility** (no record of *who appended what, when*; auth denials left no trail)
  and `/readyz` only TCP-dialled the future `postgres`/`redis` addresses, so it reported
  ready even when the **backend actually serving traffic** was unreachable.
- HARD RULES held absolutely: the server still stores **opaque client-encrypted blobs**
  and does **no crypto**; the op-log stays **dev-gated** (`SIGILD_ENABLE_DEV_OPS`,
  default **501**) and **unauthenticated unless `SIGILD_OPLOG_PUBKEY`** (unchanged).
  Observability must put **no** plaintext, key, blob content, or auth secret into a log
  — that would puncture the zero-knowledge boundary the whole design rests on. Recorded
  as **ADR 0015**.

### (a) Request-context propagation through `VaultLog` ✅
- `Append`/`Since` now take a `context.Context` threaded from the HTTP request
  (`r.Context()`), and request bodies are read under it. A cancelled/slow request
  (client disconnect, `http.Server` timeouts, or `pgxpool` acquire limits) cancels the
  in-flight append/read instead of leaking a goroutine or pinning a connection. Mem/File
  honor cancellation cheaply; Postgres passes the ctx straight to `pgx`.
- Proven live by **`TestPostgresVaultLogContextCancelled`**: a cancelled ctx cancels the
  DB work and returns a non-nil error with **nothing persisted**.

### (b) `/readyz` pings the live op-log backend ✅
- Readiness now performs a **real** health check of the **active** backend: when
  Postgres is configured it **pings the `pgxpool`** (via a `store.Pinger` seam bounded by
  a 2 s `readyzPingTimeout`) and returns **503** if the DB is down; the in-memory / file
  backends have no remote dependency and report healthy. The future
  `SIGILD_POSTGRES_ADDR`/`SIGILD_REDIS_ADDR` probes stay plain TCP dials.
- Verified live against Docker Postgres 16:
  > `GET /readyz` ⇒ **HTTP 200** `{"checks":{"oplog":"ok",…}}` while PG up; after
  > `docker stop`, `GET /readyz` ⇒ **HTTP 503** `{"checks":{"oplog":"unreachable",…}}`
  > (backend-down detected via `store.Pinger.Ping`, bounded by the 2 s timeout).

### (c) Timeouts + pool limits ✅
- `http.Server` gained read/write/idle timeouts (15 / 15 / 60 s) and the `pgxpool`
  gained connection limits (`MaxConns` 10, `MaxConnLifetime` 1 h), so no single request
  or connection runs unbounded.

### (d) Structured audit log — metadata + a fingerprint, NEVER the content ✅
- New `internal/api/audit.go` emits three structured `slog` events on the op-log path:
  - `oplog.append` — `event, request_id, vault_id, seq, size_bytes, blob_sha256, auth`
    (`auth` ∈ `ed25519`|`none`); `blob_sha256` is a hex **SHA-256 fingerprint** of the
    opaque stored bytes, computed once, for integrity/traceability only.
  - `oplog.list` — `event, request_id, vault_id, since, returned_count`.
  - `oplog.auth_denied` — `event, request_id, vault_id, reason`, where `reason` is a
    fixed enum (`missing_headers|bad_timestamp|stale_timestamp|bad_signature|replayed`)
    — **never** any secret.
- Wired in `handlers.go`: `auditAppend` after a successful `Append`, `auditList` after
  `Since`, `auditAuthDenied` before every `401` denial.
- **KEY guarantee — the zero-knowledge boundary is preserved.** The audit trail proves
  *who appended what, when* while the server NEVER logs the blob content, any signature,
  nonce, timestamp, or key. Because the fingerprint is taken over bytes that are
  **already client-encrypted**, the log reveals nothing the server did not already hold,
  and the server still performs no crypto and cannot decrypt a vault.
- **Proven by a no-blob-in-logs test** (ran + PASSED under `-race`):
  > `TestAuditAppendAndListNoBlobInLogs` posts a recognizable blob
  > (`TOPSECRET-opaque-blob-DO-NOT-LOG-9f3a2b7c`), verifies the append/list metadata
  > (incl. `blob_sha256 == sha256(blob)`), then asserts the raw blob **never** appears in
  > the ENTIRE captured JSON log. `TestAuditAuthDeniedReasonsNoBlobInLogs` drives all four
  > denial paths (`missing_headers`/`bad_signature`/`stale_timestamp`/`replayed`), asserts
  > the precise reason each time, asserts the accepted request records `auth="ed25519"`,
  > and re-asserts the blob never appears on any path.

### Regression — everything else still green ✅
- `gofmt -l sigild` empty · `go vet ./...` clean · `go test ./...` offline all packages
  **ok** (the 10 Postgres tests SKIP cleanly with a `set SIGILD_TEST_POSTGRES` message) ·
  `go test -race ./internal/api/ ./internal/store/` clean (api ok 1.327s, store ok
  4.159s, no data races) · `go build ./...` OK · `go mod verify` OK. **Live Postgres:
  all 10 `PostgresVaultLog` integration tests RAN and PASSED under `-race`** (seq /
  isolation / since / defensive-copy / opaque integrity + `ConcurrentAppends` 400
  contiguous + `DurabilityAcrossReconnect` + the new `ContextCancelled`); ok 1.935s.
- **Default op-log unchanged:** dev-ops OFF ⇒ **501** both verbs
  (`TestVaultOpsReturns501`, `TestVaultOpsDefaultStill501`,
  `TestOplogIntegrationGatingDisabled`); op-log stays UNAUTHENTICATED unless
  `SIGILD_OPLOG_PUBKEY` (`authorizeOps` returns OK when the key is nil;
  `TestOpsAuthDisabledUnchangedNoHeaders`).
- **libsigil wasm/getrandom invariant UNAFFECTED and re-confirmed:**
  `grep -c 'name = "getrandom"' libsigil/Cargo.lock` = **0**; `cli` = 1 (untouched).
  This phase is sigild + docs only — core/CLI untouched.

### docs — api.md / architecture.md / deployment.md / threat-model.md / ADR 0015 + this finalizer ✅
- `docs/api.md`, `docs/architecture.md`, `docs/deployment.md`, `docs/threat-model.md`,
  and **ADR 0015** were already written by the docs track (request-context propagation,
  the real `/readyz` backend ping, `http.Server`/`pgxpool` timeouts, and the audit-event
  schema + the never-log-a-secret guarantee). This entry finalizes the remaining living
  docs (this file, `CLAUDE.md`, `README.md`) and updates the RESUME ANCHOR. ⚠️ Minor
  known drift: `docs/api.md`'s audit table names the field `size` while the code emits
  `size_bytes` — flagged for the docs track to reconcile (outside this finalizer's edit
  scope).

### ➡️ What this opens, and what's still open (honest)
- The dev op-log is now **more reliable** (cancellation/timeout-bounded work, no
  goroutine/connection leaks on client disconnect), **auditable** (a structured,
  correlatable trail of appends / lists / auth-denials), and `/readyz` **tells the
  truth** about the store actually serving traffic — all with the zero-knowledge
  boundary intact (audit records only metadata + a fingerprint of already-encrypted
  bytes).
- Still open — this is **dev-op-log hardening, NOT a production sync server**: still
  dev-gated (default 501), still opaque, still unauthenticated unless
  `SIGILD_OPLOG_PUBKEY`, and it still owes the real data layer — auth / enrollment,
  per-vault authorization, CRDT / merge, managed migrations, backups-with-proven-restore,
  replication. No over-claims: reliability + auditability are the **only** new
  properties; the security posture is unchanged and the **system is NOT
  "post-quantum secure".**

---

## 2026-07-13 — Phase 26 (tamper-evident hash-chained op-log)

### Context & mandate
- Phase 25 (ADR 0015) added a structured audit log that fingerprints each op with
  SHA-256, and named the gap outright: a production audit log would be *signed and
  tamper-evident*. But the per-op `blob_sha256` fingerprints each op in **isolation** —
  nothing bound op *k* to op *k−1*, so a backend / operator / corrupted file or row could
  modify, reorder, insert, or drop a stored op and **neither the server nor a client would
  notice**. Threat-model adversaries #4 (signed append-only audit log) and #5 (replay/drop
  detection) want the log's **history** verifiable, not just its confidentiality.
- Mandate: make the op-log **tamper-evident** WITHOUT touching the security posture or the
  zero-knowledge boundary. HARD RULES held absolutely: the server stores **opaque blobs**
  and does **no crypto on the plaintext**; the op-log stays **dev-gated** (default **501**)
  and **unauthenticated unless `SIGILD_OPLOG_PUBKEY`**; `sigild` keeps its ONE dep (`pgx`),
  Mem/File stay stdlib; `libsigil`/`cli` untouched. Recorded as **ADR 0016**.

### The chain — one canonical `chainHash` (`store/oplogchain.go`) ✅
- Each op gets a 32-byte hash that commits to the previous op's hash:
  > `hash(seq) = SHA-256( "sigil-oplog-chain-v1"  ‖  uint32_be(len(vaultID)) ‖ vaultID
  >   ‖  uint64_be(seq)  ‖  prev_hash[32]  ‖  blob )`

  with `prev_hash = 32 zero bytes` for the **genesis** op (`seq = 1`). The ASCII domain
  label separates this hash from any other SHA-256 use; the **uint32 length-prefix** on
  `vaultID` makes the field boundary unambiguous (so `("ab","c") ≠ ("a","bc")`) and binds
  the chain to its vault; `blob` is the opaque client-encrypted bytes verbatim.
- Because each op chains from the one before, altering / inserting / deleting / reordering
  ANY op changes that op's hash **and every hash after it**.
- **Hashing the OPAQUE ciphertext preserves zero-knowledge**: the chain is computed over
  already-client-encrypted bytes — it needs **no key** and reveals **no plaintext** (the
  same property the Phase 25 audit fingerprint relies on). The server still performs no
  cryptography on vault contents.

### All three backends store + continue the identical chain ✅
- `Op` gained a `Hash []byte` field. Every backend's `Append` computes the next op's hash
  from the stored tip via the shared `chainHash`, and `verifyChain` recomputes the whole
  chain the same way — ONE function, so the three backends are provably hash-compatible.
- **MemVaultLog** — carries each op's hash in-process (non-durable by design).
- **FileVaultLog** — on-disk format **bumped v1 → v2**: a version header + per-record
  `[4-byte BE len][blob][32-byte hash]`; a fresh instance re-reads the persisted hashes,
  so verification survives restart.
- **PostgresVaultLog** — the `sigil_vault_ops` table gains a **hash column**; the next hash
  is computed and inserted inside the **same `pg_advisory_xact_lock` tx** that assigns
  `seq`, so concurrent same-vault appends stay chain-consistent.

### `/ops/verify` + `VerifyChain`, exposed two ways ✅
- `GET …/ops` now returns each op's hex `hash` inline, so a client can **re-derive and
  verify the chain itself** from the returned hashes.
- New **`GET /v1/vaults/{vaultID}/ops/verify`** recomputes the chain server-side and
  returns `{vaultID, ok, count, tip_hash, broken_at_seq}` (`VerifyChain{OK, Count, TipHash,
  BrokenAtSeq}`) — `broken_at_seq` is the first mismatching `seq` (or `null` when intact);
  an empty vault verifies `ok=true, count=0` with the genesis tip.
- **Same gate, same auth, same opacity**: `/ops/verify` and the per-op `hash` are
  **dev-gated** (the router registers `opsNotImplemented` → **501** when dev-ops is off)
  and **auth-guarded** by `authorizeOps` exactly like the existing ops routes. The 64 KiB
  cap and the opaque contract are unchanged.

### Verified — live Postgres tamper detection + cross-backend hash equality ✅
- **Live Postgres, end-to-end** (real `postgres:16-alpine`, server on :8099,
  `SIGILD_ENABLE_DEV_OPS=1` + `SIGILD_OPLOG_POSTGRES`):
  > appended 3 ops → `GET /ops/verify` ⇒ `{ok:true, count:3, tip_hash:…}`. Then
  > `psql … UPDATE sigil_vault_ops SET blob = blob || '\x00' WHERE …seq=2` ⇒
  > `GET /ops/verify` ⇒ `{ok:false, count:3, broken_at_seq:2, tip_hash: all-zero}`.
  > Separately forcing 32 zero bytes into the **hash column at seq=3** ⇒
  > `{ok:false, broken_at_seq:3}` while an untampered control vault stayed `ok=true` —
  > proving `broken_at_seq` tracks the tampered position (not hardcoded).
- **Gated store tests under `-race`**: `TestPostgresVaultLogVerifyChainOK`,
  `TestPostgresVaultLogVerifyChainDetectsTamper` (corrupts the hash column →
  `broken_at_seq=2`), `TestPostgresVaultLogChainMatchesMem` all PASS; the full PG suite
  (13 tests, incl. concurrent appends + durability-across-reconnect) PASS under `-race`.
- **File + Mem tamper tests** PASS: `TestFileVaultLogVerifyChainDetectsTamper` (flips an
  on-disk blob byte, a fresh instance re-reads → `broken_at_seq=2`),
  `TestMemVaultLogVerifyChainDetectsTamper` (white-box blob byte flip → `broken_at_seq=2`).
- **Cross-backend hash equality — both pairs PASS**:
  > `TestVaultLogChainCrossBackendConsistency` appends identical `(vaultID, blobs incl. an
  > empty blob)` to **Mem vs File** and asserts identical per-op `Seq`, identical per-op
  > `Hash`, and identical `VerifyChain` `TipHash`; `TestPostgresVaultLogChainMatchesMem`
  > (ran live) asserts an identical per-op hash sequence and tip for **Postgres vs Mem**.

  `TestChainHashDeterministicAndSensitive` proves `chainHash` is a pure function that
  changes when ANY of vaultID / seq / prev_hash / blob changes.

### Regression — everything else still green ✅
- `gofmt -l sigild` empty · `go vet ./...` clean · `go build ./...` OK · `go mod verify`
  OK (sigild's only dep is still `pgx`; Mem/File stdlib) · `go test ./...` offline all
  packages ok (PG tests SKIP without `SIGILD_TEST_POSTGRES`) · `go test -race -count=1
  ./internal/api/ ./internal/store/` clean (api ok ~1.6s, store ok ~5.0s, no data races).
- **Default op-log UNCHANGED** — proven live on a plain server (no dev-ops): `GET`/`POST`
  `…/ops` **and** `GET …/ops/verify` all ⇒ **501** `{"error":"not_implemented",…}` (a
  deliberate 501, not a 404); `TestVaultOpsVerifyDefaultStill501` confirms it. Op-log stays
  unauthenticated unless `SIGILD_OPLOG_PUBKEY`.
- **libsigil / CLI untouched**: `grep -c 'name = "getrandom"' libsigil/Cargo.lock` = **0**;
  `git status --porcelain cli/ libsigil/` empty — this phase is sigild + docs only.

### docs — api.md / architecture.md / threat-model.md / ADR 0016 + this finalizer ✅
- The docs track already updated `docs/api.md` (the per-op `hash` field + the `/ops/verify`
  endpoint + the chain formula), `docs/architecture.md`, and `docs/threat-model.md`, and
  wrote **ADR 0016**. This entry finalizes the remaining living docs (this file,
  `CLAUDE.md`, `README.md`) and updates the RESUME ANCHOR.

### ➡️ What this opens, and what's still open (honest)
- The op-log is now **tamper-evident**: modification / insertion / deletion / reordering of
  any stored op is detectable from the per-op hashes, and an operator can spot-check a vault
  with one `/ops/verify` request — all with the zero-knowledge boundary intact (the chain
  fingerprints ciphertext only).
- **Tamper-EVIDENT, NOT tamper-proof — no over-claim.** A single, non-notarized server can
  still **lie** about `/ops/verify` (recompute a perfectly consistent chain over data it
  has itself doctored, or just return `{"ok":true}`). Server-side verify catches only
  **accidental** corruption / a non-adversarial operator's storage faults; the guarantee
  that resists a **hostile** server is **client-side** — the client keeps its own tip and
  re-derives the chain from the returned per-op hashes. Still a **dev op-log**, NOT a
  Byzantine-fault-tolerant / append-only-enforced / notarized log, and NOT the production
  build's signed / Merkle-root store.
- Still owed by the real data layer (unchanged from Phase 25): auth / enrollment, per-vault
  authorization, CRDT / merge, managed migrations, backups-with-proven-restore, replication
  — and a signed / Merkle-root, replay-and-drop-detecting production audit log. Tamper-
  evidence is the **only** new property; the security posture is unchanged and the **system
  is NOT "post-quantum secure".**

---

## 2026-07-13 — Phase 27 (op-log pagination, rate limiting, /metrics, config validation)

### Context & mandate
- Phase 26 (ADR 0016) made the dev op-log tamper-evident and durable, but three
  **operational** gaps + one **hardening** gap remained: reads were unbounded
  (`GET …/ops?since=N` returned EVERY op after `N` in one response — a memory/latency
  footgun as a vault grows, with no way to page), appends had no throttle (a single busy
  or hostile vault could hammer the durable Postgres backend), there was no way to see
  request/append/verify/denial volume without scraping logs, and a malformed env var was
  ignored or blew up at first request instead of at boot.
- Mandate: close all four **WITHOUT** touching the security posture — four **pure Go
  stdlib** features, **no new dependency** (`pgx` stays the only third-party import), none
  changing the dev-gated / opaque / unauthenticated-by-default posture. HARD RULES held:
  the server stores **opaque blobs** and does **no crypto on the plaintext**; the op-log
  stays **dev-gated** (default **501**) and **unauthenticated unless `SIGILD_OPLOG_PUBKEY`**;
  Mem/File stay stdlib; `libsigil`/`cli` untouched. Recorded as **ADR 0017**.

### (1) Bounded, paginated reads — `?limit` + `has_more` ✅
- `VaultLog.Since` gained a **limit** parameter (`Since(ctx, vaultID, since, limit)`), a
  signature change pushed into **all three backends** so the cap is applied where the data
  lives — Postgres uses it as a SQL `LIMIT` (not fetch-all-then-slice), Mem/File truncate.
- `GET …/ops` takes an optional **`?limit`** (default **500**, clamped to `[1,1000]`;
  `limit=0` → 1) and returns **`has_more`** beside `next`; `has_more = (len(ops)==limit)`.
  A non-integer `limit` → **`400 {"error":"bad_limit"}`**. A client drains a vault by
  looping `since = next` until `has_more=false`.
- Proven live (in-memory, :18101, 5 ops appended):
  > `GET /ops?limit=2` ⇒ `seq[1,2]`, `has_more=true`, `next=2`; `GET /ops?since=2&limit=2`
  > ⇒ `seq[3,4]`, `has_more=true`, `next=4`; `GET /ops?since=4&limit=2` ⇒ `seq[5]`,
  > `has_more=false`, `next=5` (short last page ends the walk); `GET /ops?limit=abc` ⇒
  > `400 {"error":"bad_limit"}`. Blobs round-trip opaquely (b64 decodes to the exact
  > posted bytes) with the per-op hash present.

  Gated PG test **`TestPostgresVaultLogSinceRespectsLimit`** PASSED against live Postgres
  (the `LIMIT` is honored in SQL); `limit=0` clamps to 1 (unit test).

### (2) Per-vault stdlib token-bucket rate limit → `429` ✅
- New `internal/api/ratelimit.go`: a **per-vault** token bucket, pure stdlib
  (`sync.Mutex` + `map` + `time`). When **`SIGILD_OPLOG_RATE_LIMIT`** (sustained
  appends/sec/vault) is set — with optional **`SIGILD_OPLOG_RATE_BURST`** bucket depth —
  an append over the vault's refill rate gets **`429 rate_limited`** + a **`Retry-After`**
  header. Per-vault isolation means one busy vault cannot starve others. The limiter is
  **bounded** (`rateLimiterMaxVaults=10000` + idle-bucket eviction) so a flood of distinct
  vault IDs cannot grow the map without limit. It shapes append *rate* only and **never
  inspects the opaque blob**. GET is **never** rate-limited.
- Proven live (rate=2 burst=2, :18102):
  > 10 rapid `POST`s to `vaultA` ⇒ first **2 = 201**, remaining **8 = 429** each with
  > `Retry-After: 1`; a second vault `vaultB` still got **201** (independent bucket).
  > Rate unset/0 (:18103): 20 rapid `POST`s ⇒ **20× 201, zero 429** (no wrapper installed,
  > behaviour unchanged). Startup emits a dev-only warn line when the limiter is active.

  `TestRateLimiterConcurrent` (+ others) **-race clean** on `internal/api`; a unit test
  confirms GET routes are never throttled.

### (3) A stdlib `/metrics` Prometheus-text endpoint ✅
- New `internal/api/metrics.go` renders a **hand-written Prometheus exposition** (no client
  library — stdlib only). **`GET /metrics`** is **always available** (registered OUTSIDE
  the dev gate) and unauthenticated, exposing process counters:
  `sigild_oplog_appends_total`, `_verify_total`, `_ratelimit_rejected_total`,
  `_auth_denied_total{reason=…}` (5 reasons), `sigild_http_requests_total{class}`, and
  `sigild_build_info{version}`. Counters are **per-router** (atomic, test-isolatable — NOT
  process-global), so tests observe a clean delta.
- **NO secrets exposed — the zero-knowledge boundary holds.** `/metrics` exports only
  aggregate counts + the build version — **never** a blob, key, signature, nonce, vault
  content, or vault ID (no per-vault cardinality either). Proven live:
  > `GET /metrics` ⇒ **200**, `text/plain`, `version=0.0.4`. `appends_total` 0→1 after an
  > append, `verify_total`→1 after a verify. With `SIGILD_OPLOG_PUBKEY` set, an unsigned
  > `POST`+`GET` (each **401**) drove `sigild_oplog_auth_denied_total{reason="missing_
  > headers"}` to **2**. A posted blob `"SECRETSAUCE-BLOB-9911"` is **absent** from
  > `/metrics` (raw AND base64 = 0 hits); the configured pubkey is **absent** (0 hits).

### (4) Fail-fast config validation ✅
- The startup path (`cmd/server`) extracts `parseRateLimit` / `parseRateBurst` /
  `effectiveBurst` / `parseOpLogPubKey` / `validateListenAddr` and **validates the config
  BEFORE binding the listener**, exiting non-zero with a clear message on any malformed
  value instead of starting misconfigured and failing later at request time.
- Proven live:
  > `SIGILD_OPLOG_RATE_LIMIT=notanumber` ⇒ **exit rc 1**, port **NOT bound** (connection
  > refused), log `invalid SIGILD_OPLOG_RATE_LIMIT: must be a number`. Same fail-fast for
  > `RATE_LIMIT=-5` (non-negative), `RATE_BURST=xyz` (integer), `OPLOG_PUBKEY` garbage
  > (base64/length), and `SIGILD_ADDR=8080` bare-port (invalid TCP addr) — all **exit 1,
  > none bind**. A good config (`rate=2.5`) binds and serves `/healthz` **200**.

  `TestParseRateLimit` / `TestParseRateBurst` / `TestEffectiveBurst` / `TestParseOpLogPubKey`
  / `TestValidateListenAddr` all PASS.

### Regression — all prior features intact ✅
- **Default op-log UNCHANGED** — no `SIGILD_ENABLE_DEV_OPS`: `GET`/`POST` `…/ops` **and**
  `GET …/ops/verify` all ⇒ **501** `{"error":"not_implemented",…}` (POST body confirmed);
  `/metrics` still **200** (it is always-on, never dev-gated). dev-ops in-memory:
  append/list (3 ops, each a 32-byte hash as a 44-char b64) / verify `ok=true count=3` OK.
- **Tamper-evidence still fires** (live Postgres, :18114): 3 durable appends, verify
  `ok=true`; `UPDATE sigil_vault_ops … WHERE seq=2` ⇒ verify `ok=false, broken_at_seq=2`.
  **Audit still leaks no blob**: `oplog.append ×3` / `.list` / `.verify` carry
  `blob_sha256` + `size_bytes` only — the raw blob AND its base64 are **0 hits** in the log.
  `/readyz` **200** `{oplog:ok,postgres:ok}` with PG up; **503** `{oplog:unreachable}` when
  PG stopped. All 14 live `PostgresVaultLog` tests PASS incl. `SinceRespectsLimit`,
  `VerifyChainDetectsTamper`, `DurabilityAcrossReconnect`, `ChainMatchesMem`.
- `gofmt -l sigild` empty · `go vet ./...` clean · `go mod verify` OK · `go build ./...`
  OK · `go test ./...` offline all packages ok (PG SKIP on the `SIGILD_TEST_POSTGRES` gate)
  · `go test -race ./internal/api ./internal/store` clean (concurrent limiter / nonce /
  metrics, no data races).
- **No new deps:** `go.mod` direct require is still only `github.com/jackc/pgx/v5 v5.10.0`
  (indirect all pgx-transitive); the new files import **stdlib only**
  (`math`/`net/http`/`strconv`/`sync`/`sync/atomic`/`time`/`io`/`strings`).
- **libsigil / CLI untouched:** `grep -c 'name = "getrandom"' libsigil/Cargo.lock` = **0**
  (re-confirmed twice); `git status` shows no `libsigil/` or `cli/` changes — this phase is
  sigild + docs only.

### docs — api.md / architecture.md / deployment.md / ADR 0017 + this finalizer ✅
- The docs track already updated `docs/api.md` (the `?limit` / `has_more` pagination, the
  `429 rate_limited` + `Retry-After`, and the `/metrics` endpoint), `docs/architecture.md`
  (§1 + §4), and `docs/deployment.md` (§6–§7 — the scrape target, the rate-limit knobs, and
  fail-fast config validation), and wrote **ADR 0017**. This entry finalizes the remaining
  living docs (this file, `CLAUDE.md`, `README.md`) and updates the RESUME ANCHOR.
- ✅ **Drift reconciled at the commit gate (same commit):** api.md / architecture.md /
  deployment.md / ADR 0017 had named the burst env `SIGILD_OPLOG_BURST`, but the code reads
  **`SIGILD_OPLOG_RATE_BURST`** (`os.Getenv` in `cmd/server/main.go`); additionally api.md's
  `/metrics` table had listed `sigild_oplog_{verifies,auth_denials,rate_limited}_total`
  where the code emits `sigild_oplog_{verify,auth_denied,ratelimit_rejected}_total`. The
  **code is authoritative** — I corrected all four docs (env name + the three metric names)
  in the Phase 27 commit itself, verified by grepping the doc tokens against
  `metrics.go` / `cmd/server/main.go`.

### ➡️ What this opens, and what's still open (honest)
- The dev op-log is now **bounded** (paginated reads, optional per-vault append throttle),
  **observable** (a stdlib `/metrics` scrape target), and **fail-fast** (a bad env var is a
  failed boot, not a silently-wrong running instance) — all **pure stdlib**, no new dep,
  with the zero-knowledge boundary intact (`/metrics` is counters + version only; the rate
  limiter keys on the vault ID but never reads the blob).
- **Not production SLOs — no over-claim.** These are **dev-scale operability primitives**:
  an **in-process** rate limiter (per-process, not a distributed quota), **process-local**
  counters (reset on restart, not a durable TSDB), and **boot-time** validation — not the
  production build's rate-limit tier, metrics pipeline, or config management. The security
  posture is unchanged: still `SIGILD_ENABLE_DEV_OPS`-gated + **501** by default, still
  unauthenticated unless `SIGILD_OPLOG_PUBKEY`, still opaque blobs only, still no crypto on
  the plaintext; `/metrics` is the only always-on addition, and it is counters-only.
- Still owed by the real data layer (unchanged): auth / enrollment, per-vault authorization,
  CRDT / merge, managed migrations, backups-with-proven-restore, replication — and a signed
  / Merkle-root production audit log. Scale + observability are the **only** new properties;
  the **system is NOT "post-quantum secure".**

---

## 2026-07-14 — Phase 28 (managed op-log schema migrations + hash-chain-verified backup/restore)

### Context & mandate
- The durable Postgres op-log backend (Phase 24 / ADR 0014) created its schema with **ad-hoc
  inline DDL** at construction (`CREATE TABLE IF NOT EXISTS` + an `ALTER … ADD COLUMN IF NOT
  EXISTS` for the Phase 26 hash column). That worked for one evolving dev table but had no
  notion of *version*, no record of *what was applied when*, no safe concurrent-apply story,
  no operator control, and no documented/provable backup path.
- Mandate: replace the inline DDL with a **managed, versioned migration system** for the
  Postgres backend and document a **backup/restore runbook whose integrity is proved by the
  EXISTING hash chain** — **no new dependency** (`pgx` stays the only third-party import;
  new code is pure stdlib + `pgx` + `go:embed`), **opaque blobs / no crypto on plaintext**
  preserved, and the **dev-gated / 501-by-default** posture unchanged (migrations only matter
  when `SIGILD_OPLOG_POSTGRES` is set).

### What shipped (code — implemented + verified GREEN before this doc pass)
- **`internal/store/migrate.go` + `internal/store/migrations/0001_init.sql`:** `go:embed`'d
  `NNNN_description.sql` migrations, ascending by the zero-padded version; baseline
  `0001_init.sql` = version **1** (creates `sigil_vault_ops`: `vault_id`/`seq`/`blob bytea`/
  `hash bytea`/`created_at`, PK `(vault_id, seq)`; cleanly adopts a legacy table). A
  **`schema_migrations`** tracking table (`version`, `name`, `applied_at`). `Migrate` runs
  under a **session-level `pg_advisory_lock`** (key `0x5347494C5F4D4752` = "SGIL_MGR") with
  each pending migration in its **own transaction**; `Status` reports applied/pending;
  `AppliedVersion` treats a missing table (SQLSTATE 42P01) as version 0.
- **`internal/store/postgresvaultlog.go`:** `NewPostgresVaultLog` now calls `Migrate` at
  construction when **auto-migrate is enabled** (the default). `autoMigrateEnabled()` reads
  **`SIGILD_OPLOG_AUTO_MIGRATE`** — `0`/`false`/`no`/`off` (case-insensitive) ⇒ OFF, in
  which case construction applies NOTHING and **fails fast** if `AppliedVersion < latest`
  (message: "run `sigild migrate`"). New `SchemaVersion(ctx)` reads the applied version for
  the metric.
- **`cmd/server/main.go`:** subcommand dispatch — **`sigild migrate`** applies pending,
  **`sigild migrate status`** reports (both require `SIGILD_OPLOG_POSTGRES`; arg-parse +
  missing-DSN checks are unit-testable without a DB). On server start the applied version is
  read via `pgLog.SchemaVersion` and threaded into the metrics config.
- **`internal/api/metrics.go`:** new **`sigild_schema_version`** gauge — help "Applied op-log
  DB migration version (0 when the backend is not Postgres)."; a config-time value fixed at
  construction (0 for mem/file), rendered in the Prometheus text output.

### How verified
- `gofmt -l sigild` clean; `go -C sigild vet ./...`; **`go -C sigild test ./... -race`** green
  (migration parse/sort/dup-version unit tests, fresh-DB apply, status, legacy-table adopt,
  auto-migrate-off fail-fast, and **`TestMigrateConcurrentNoDoubleApply`** — concurrent
  `Migrate` calls serialize on the advisory lock and apply each migration exactly once, no
  data race). Postgres-backed tests gated on `SIGILD_TEST_POSTGRES`.
- **Backup/restore integrity proof:** the verifier ran a **`pg_dump` → drop → `pg_restore`**
  cycle against the op-log database and then hit **`GET /v1/vaults/{id}/ops/verify`** per
  vault — it returned **`ok: true`** with the **same `tip_hash`** the live server produced
  before the drop, confirming the per-op SHA-256 hash chain survives a real dump/restore
  byte-for-byte (both `blob` and `hash` are `bytea`, dumped literally). So backup integrity
  reuses the existing tamper-evidence chain rather than any bespoke mechanism.
- **No new dep / core untouched:** `sigild/go.mod` direct require still only
  `github.com/jackc/pgx/v5`; the migration runner/CLI import stdlib + `pgx` + `embed`.
  `grep -c 'name = "getrandom"' libsigil/Cargo.lock` = **0**; no `libsigil/` or `cli/`
  changes (sigild + docs only).

### Docs (this pass)
- `docs/deployment.md`: new **§11 Schema migrations** (embedded/versioned, auto-apply +
  `SIGILD_OPLOG_AUTO_MIGRATE=0` opt-out + fail-fast, `sigild migrate`/`migrate status`,
  advisory-lock-safe concurrent boots, `sigild_schema_version`) and **§12 Backup & restore**
  (`pg_dump`/`pg_restore`, byte-for-byte `blob`+`hash`, `/ops/verify` post-restore gate citing
  the tip_hash-survives-restore proof); §7 gap bullet updated to reference them.
- `docs/architecture.md`: sigild component note + the "No production storage" limitation now
  mention managed embedded migrations (`schema_migrations`), `sigild_schema_version` on
  `/metrics`, and the chain-verified backup runbook.
- `docs/api.md`: added `sigild_schema_version` (gauge) to the `/metrics` table; noted the
  `sigild migrate` operator CLI (framed as CLI, not an HTTP endpoint).
- `docs/decisions/0018-managed-oplog-migrations-and-backup-integrity.md` written
  (Nygard-style) + indexed in `docs/decisions/README.md` (Accepted, 2026-07); ADR banner
  extended. `CLAUDE.md` + `README.md` sigild sections extended; RESUME ANCHOR moved to
  Phase 28.

### ➡️ Still open (honest)
- This is a **dev** backend migration + backup story: real, ordered, tracked migrations and a
  chain-verified logical dump — **not** down-migrations, online/zero-downtime rewrites,
  managed rollout tooling, PITR (WAL archiving), streaming replication, an object store, or
  restore-drill automation. Production persistence (Postgres + S3/R2 + Redis) is still
  broader and unbuilt. Posture unchanged: dev-gated / **501** by default, opaque blobs only,
  no crypto on the plaintext; the **system is NOT "post-quantum secure".**

---

## 2026-07-14 — Phase 29 (wasm client column: `sigil-wasm` seal/open in the browser)

### What & why
Opened the **client column** — reserved and empty until now. Added **`sigil-wasm`**, a
standalone `wasm-bindgen` binding over `sigil-core`'s record API, exposing
`seal_record` / `open_record` (plus `nonce_len` / `recommended_salt_len` / `version`) to
JavaScript so a **browser or Node** process can seal/open a record entirely client-side.
It is the **FIRST thing to actually consume the wasm-pure core in a JS runtime** — until
now the `wasm32-unknown-unknown` build only proved the core stays *linkable*; nothing
exercised it from JS.

The point of the phase is to prove **caller-supplied entropy end to end into a JS host**.
`sigil-core` has no in-core RNG ([ADR 0007](docs/decisions/0007-caller-supplied-entropy-in-core.md));
`sigil-wasm` carries that all the way out — the Argon2id salt + the AEAD nonce are
generated in JS with `crypto.getRandomValues` and passed IN as byte arrays — so the crate
is deliberately **`getrandom`-free**, unlike `cli/`.

### How (design decisions → ADR 0019)
- **Separate crate, own lockfile.** Not a `libsigil` workspace member (mirrors `cli/`,
  [ADR 0002](docs/decisions/0002-standalone-cli-crate-for-getrandom-isolation.md)):
  path-deps `../libsigil/core`, resolves into its own `sigil-wasm/Cargo.lock`, so
  `wasm-bindgen` (pinned `= "0.2.100"`) never touches `libsigil/Cargo.lock`.
- **Entropy from JS, not `getrandom`.** Deliberately no `getrandom` dep — the whole point
  is to keep the guard mechanical across a *second* lockfile.
- **No crypto of its own.** `#[wasm_bindgen]` entry points are a paper-thin shell over
  `*_inner` helpers (returning `Result<Vec<u8>, String>`, natively testable) that only
  marshal bytes into `sigil-core`. Crate cannot `#![forbid(unsafe_code)]` (the
  `#[wasm_bindgen]` macro emits `unsafe` glue); all security-relevant code stays in the
  `forbid(unsafe_code)` core. Lib is `crate-type = ["cdylib","rlib"]`.
- Build via `sigil-wasm/build-wasm.sh` (wasm-pack 0.13.1, which bundles wasm-bindgen-cli
  0.2.100 matching the pin) → **two** packages from one crate: `pkg-web/` (browser ESM,
  `--target web`) + `pkg-node/` (Node CJS, `--target nodejs`). Both are **build artifacts,
  gitignored** (root `.gitignore`: `sigil-wasm/pkg-web/`, `sigil-wasm/pkg-node/`,
  `sigil-wasm/target/`) — NOT committed. Committed: crate source, `Cargo.lock`,
  `build-wasm.sh`, `test/roundtrip.mjs`, `demo/`, `README.md`.

### How verified
- **Node round-trip PASS:** `node sigil-wasm/test/roundtrip.mjs` (after `build-wasm.sh`)
  generates a 16-byte salt + 24-byte nonce with `webcrypto.getRandomValues`, seals a known
  marker under fast Argon2 params, asserts the sealed bytes do NOT contain the plaintext,
  opens back and asserts equality, and asserts wrong-password + short-nonce both throw —
  prints the `PASS: sigil-wasm Node round-trip (…)` line and exits 0.
- Native `*_inner` unit tests (`cargo test --manifest-path sigil-wasm/Cargo.toml`):
  round-trip, wrong-password-fails, wrong-nonce-len-rejected, constants-are-faithful.
- Browser `demo/` (`demo/index.html` + `demo/main.js`) serves an in-browser seal/open page
  with a loud pre-audit banner (salt+nonce from `window.crypto.getRandomValues`).
- **Both getrandom guards == 0:** `grep -c 'name = "getrandom"' libsigil/Cargo.lock` = **0**
  (unchanged) AND `grep -c 'name = "getrandom"' sigil-wasm/Cargo.lock` = **0**. `libsigil/`
  and `cli/` untouched (new crate + docs only).

### Docs (this pass — docs only, no code touched)
- `docs/architecture.md`: `sigil-wasm` added to the §1 component map as the first
  client-side consumer of the wasm-pure core; §4 now lists **four** Rust build surfaces
  (added the `sigil-wasm` crate + its second getrandom-guarded lockfile); §6 "No clients"
  note updated — the client column has started (still a demo, not a product client).
- `README.md`: new `sigil-wasm/` bullet + layout line + build/test snippet (honest
  pre-audit tone; a demo of an UNAUDITED building block, not the product key model).
- `CLAUDE.md`: `sigil-wasm` repo-map bullet, build/test commands (+ the
  `sigil-wasm/Cargo.lock` getrandom==0 check), license-split note (Apache-2.0, client side).
- `docs/decisions/0019-wasm-client-bindings.md` written (Nygard) + indexed in
  `docs/decisions/README.md` (Accepted, 2026-07); ADR banner extended. RESUME ANCHOR moved
  to Phase 29.

### ➡️ Still open (honest)
- `sigil-wasm` wraps **only** the symmetric password-derived `seal_record`/`open_record`
  path — it does NOT touch the hybrid public-key flow, and it is **not** the product's
  account / key-management / session model. A building-block demo, UNAUDITED, not for real
  secrets. `pkg-*` require a `wasm-pack` build step (artifacts gitignored). No real web app,
  admin console, or extension yet (still reserved dirs). Posture unchanged; the **system is
  NOT "post-quantum secure".**

---

## 2026-07-14 — Phase 30 (wasm ↔ CLI `SIGILcli` container interop)

### What & why
Made `sigil-wasm` **interoperable with the `sigil` CLI**: a file sealed in the browser now
opens with `sigil open`, and a file sealed with `sigil seal` opens in the browser. Until
now the wasm binding only exposed the bare `seal_record`/`open_record` envelope (salt +
Argon2 params carried out-of-band), so it shared the *crypto* with the CLI but not the
*packaging* — the two clients could not read each other's files. The CLI already defines a
small self-describing on-disk **`SIGILcli` container** (`cli/src/lib.rs`): the raw envelope
prefixed with the salt + the three Argon2 cost params (which the envelope itself does not
carry). This phase teaches the wasm binding to read+write that exact container.

Added two `#[wasm_bindgen]` exports in `sigil-wasm/src/lib.rs`:
- `seal_to_container(password, salt, nonce, m_cost, t_cost, p_cost, plaintext) -> Uint8Array`
  — seals under the CLI's fixed AAD `sigil-cli/1` and packs the self-describing header
  `magic "SIGILcli" ‖ version=1 ‖ m_cost/t_cost/p_cost (u32 LE) ‖ salt_len(u8) ‖ salt` in
  front of the envelope, byte-mirroring `cli/src/lib.rs`.
- `open_container(password, container) -> Uint8Array` — validates magic + version, reads the
  params + salt back out of the header, slices the envelope tail, re-derives the key and
  authenticates+decrypts. Rejects (throws) on bad magic, unsupported version, a declared
  salt that overruns the buffer, a truncated header, wrong password, or tampered ciphertext.

### How (format is MIRRORED, not shared)
Decided **against a shared crate** for the container format and **mirrored** the constants
into `sigil-wasm/src/lib.rs` instead — `CLI_MAGIC`/`CLI_FORMAT_VERSION`/`CLI_AAD`/
`CLI_FIXED_HEADER_LEN` mirror `cli/src/lib.rs`'s `MAGIC`/`FORMAT_VERSION`/`AAD`/
`FIXED_HEADER_LEN`, each carrying a comment naming the CLI value it must equal. Rationale
(ADR 0020): this is a **pre-audit demo container, not a product wire format**; a shared
crate is real structural weight (a fourth Cargo unit, wasm-purity + lockfile isolation to
re-litigate) for a format we expect to replace. The duplication is small and mechanically
guarded — the two copies **MUST stay byte-for-byte in sync**, enforced by tests below.

### How verified
- **Bidirectional interop PASS:** `node sigil-wasm/test/interop.mjs` (after `build-wasm.sh`)
  **builds and shells to the REAL `sigil` binary** (`cargo build --bin sigil`, no stale
  binary) and drives both directions against a random 16-byte salt + 24-byte nonce from
  `webcrypto.getRandomValues`:
  - **Direction A** — `sigil seal` writes a container → Node reads the bytes → `open_container`
    recovers the plaintext (asserts equality + that the CLI wrote a `SIGILcli` magic).
  - **Direction B** — `seal_to_container` writes a container → asserts it does NOT leak the
    plaintext marker → `sigil open` decrypts it (asserts equality).
  Prints the `PASS: sigil-wasm <-> sigil CLI SIGILcli container interop (A: … ; B: …)` line
  and exits 0.
- **Native golden-header + container tests** (`cargo test --manifest-path sigil-wasm/Cargo.toml`):
  `container_round_trip`, `container_wrong_password_fails`, `container_bad_magic_rejected`,
  `container_truncated_header_rejected`, `container_declared_salt_overrun_rejected`, and
  `container_header_is_golden` (asserts the emitted 38-byte header byte-for-byte against a
  hand-built expected header — any drift from `cli/src/lib.rs`'s layout fails here).
- **Both getrandom guards still == 0:** `grep -c 'name = "getrandom"' libsigil/Cargo.lock` =
  **0** AND `grep -c 'name = "getrandom"' sigil-wasm/Cargo.lock` = **0** — the interop path
  keeps the caller-supplied-entropy contract (JS supplies salt+nonce).

### Docs (this pass — docs only, no code touched)
- `docs/architecture.md`: §1 `sigil-wasm` bullet extended with the CLI interop
  (`seal_to_container`/`open_container`, the `SIGILcli` byte layout + AAD, mirrored-not-shared
  constants, golden + Node-interop tests); the client-container diagram box relabeled
  "SIGILcli container (cli + sigil-wasm)".
- `README.md`: `sigil-wasm/` bullet notes the shared container (seal in one, open in the
  other) + the interop test; MARKETING-CLAIMS discipline reiterated.
- `CLAUDE.md`: `sigil-wasm` repo-map bullet records the interop + `seal_to_container`/
  `open_container` exports + the mirrored (must-stay-in-sync) constants in both
  `cli/src/lib.rs` and `sigil-wasm/src/lib.rs` + the `test/interop.mjs` build-and-test line.
- `docs/decisions/0020-shared-client-container-format.md` written (Nygard) + indexed in
  `docs/decisions/README.md` (Accepted, 2026-07); ADR banner extended. RESUME ANCHOR moved
  to Phase 30.

### ➡️ Still open (honest)
- The `SIGILcli` container is a **pre-audit CLI/demo container, NOT a frozen product wire
  format**, over the **UNAUDITED** symmetric `seal_record`/`open_record` building block. It
  is **not** the product's account / key-management / session model and must not protect real
  secrets. The format is **duplicated** in two crates — a real, bounded maintenance cost
  (change one, change the other; the golden + interop tests are the tripwire). A future real,
  versioned container/wire format belongs in `sigil-core` or a purpose-built shared crate (at
  which point ADR 0020 would be superseded). Posture unchanged; the **system is NOT
  "post-quantum secure".**

---

## 2026-07-14 — Phase 31 (wasm HYBRID public-key encryption + `SIGILhyb` CLI interop)

### What & why
Brought **HYBRID public-key (no-password) encryption to `sigil-wasm`** — the wasm client
column now reaches the **PQ-hybrid encryption path** for the first time. Until now the wasm
binding only did the symmetric password path (`SIGILcli`, Phases 29/30). `sigil-core` has had
a full hybrid public-key path since Phase 21 (`hybrid_seal`/`hybrid_open`, ADR 0013 — encrypt
a record TO a recipient's **X25519 + ML-KEM-768** identity via a custom KEM-then-AEAD), and
the CLI exposed it in Phase 23 (`hybrid-keygen`/`hybrid-seal`/`hybrid-open`, `SIGILhyb`
container). This phase teaches the browser/Node binding to do the same, byte-compatible with
the CLI both directions.

Added four `#[wasm_bindgen]` exports in `sigil-wasm/src/lib.rs`:
- `hybrid_x25519_public(secret) -> Uint8Array` (32-byte secret → 32-byte X25519 public key)
  and `hybrid_mlkem_encaps_key(seed) -> Uint8Array` (64-byte seed → 1184-byte ML-KEM-768
  encapsulation key) — the two raw derivations needed to build a recipient `.pub` identity.
- `hybrid_seal_to_container(recipient_x25519_pub, recipient_mlkem_encaps_key, ephemeral_x25519_secret,
  mlkem_coin, aead_nonce, plaintext) -> Uint8Array` — hybrid-encapsulates to the recipient,
  seals under the fixed hybrid AAD `sigil-hybrid-cli/1`, and packs the self-describing prefix
  `magic "SIGILhyb" ‖ version=1 ‖ eph_x25519_pub[32] ‖ mlkem_ct[1088]` in front of the
  envelope, byte-mirroring `cli/src/lib.rs`.
- `hybrid_open_container(recipient_x25519_secret, recipient_mlkem_seed, container) -> Uint8Array`
  — validates the `SIGILhyb` magic + version, slices `eph_pub` + `mlkem_ct` + envelope, and
  hybrid-decapsulates+opens. Rejects (throws) on bad magic, unsupported version, truncation,
  or a wrong recipient / tampered ciphertext.

### How (entropy JS-supplied; identity JSON bridged by Node)
Two invariant-preserving choices (ADR 0021):
- **All entropy stays JS-supplied** — the recipient X25519 secret + ML-KEM keygen seed and the
  per-message ephemeral X25519 secret + ML-KEM coin + AEAD nonce are all generated in JS with
  `crypto.getRandomValues` and passed in, so `sigil-wasm` stays **`getrandom`-free** (like the
  core; both lockfiles keep `getrandom`-count 0).
- **The wasm crate does NOT parse identity files** — Node bridges the CLI's identity JSON
  (fields `x25519_public_key` / `mlkem_encaps_key` / `x25519_secret` / `mlkem_seed`,
  standard-base64) into raw key bytes. The crate exposes just the two derivations it needs.

The `SIGILhyb` format constants are **MIRRORED — not shared** — `HYBRID_MAGIC` (`b"SIGILhyb"`),
`HYBRID_FORMAT_VERSION` (1), `HYBRID_AAD` (`b"sigil-hybrid-cli/1"`) in `sigil-wasm/src/lib.rs`
mirror `cli/src/lib.rs`'s `HYBRID_MAGIC` / `HYBRID_AAD`, each with a comment tying it to the
other file. Same rationale as ADR 0020: a pre-audit demo format is not worth a shared crate;
the two copies **MUST stay byte-for-byte in sync**, enforced by the tests below.

### How verified
- **Bidirectional interop PASS:** `node sigil-wasm/test/hybrid-interop.mjs` (after
  `build-wasm.sh`) **builds and shells to the REAL `sigil` binary** (`cargo build --bin sigil`,
  no stale binary) and drives both directions with JS-generated entropy; Node bridges the CLI
  identity JSON:
  - **Direction A** — `sigil hybrid-keygen` writes a recipient identity → Node reads the
    `.pub`, decodes the public parts → `hybrid_seal_to_container` writes the container (asserts
    `SIGILhyb` magic + that it does NOT leak the plaintext marker) → `sigil hybrid-open`
    recovers the plaintext (asserts equality).
  - **Direction B** — Node generates recipient secret material → derives the publics via
    `hybrid_x25519_public` / `hybrid_mlkem_encaps_key` → writes a CLI-format `.pub` → `sigil
    hybrid-seal` writes the container → `hybrid_open_container` recovers the plaintext (asserts
    equality).
  Prints the `PASS: sigil-wasm <-> sigil CLI SIGILhyb hybrid public-key interop (A: … ; B: …)`
  line and exits 0.
- **Native golden + hybrid container tests** (`cargo test --manifest-path sigil-wasm/Cargo.toml`):
  derive-publics → seal → open round-trip, wrong-recipient failure, bad-magic / truncated /
  bad-length rejection, and a `SIGILhyb` golden fixed-prefix check.
- **Both getrandom guards still == 0:** `grep -c 'name = "getrandom"' libsigil/Cargo.lock` = **0**
  AND `grep -c 'name = "getrandom"' sigil-wasm/Cargo.lock` = **0** — the hybrid path keeps the
  caller-supplied-entropy contract.

### Docs (this pass — docs only, no code touched)
- `docs/architecture.md`: §1 `sigil-wasm` bullet extended with the hybrid public-key path
  (the four exports, the `SIGILhyb` byte layout + AAD, JS-supplied entropy, Node-bridged
  identity JSON, mirrored-not-shared constants, golden + `hybrid-interop.mjs` tests, honest
  framing).
- `README.md`: `sigil-wasm/` bullet notes password-less hybrid public-key encryption in the
  browser interoperable with the CLI; UNAUDITED; MARKETING-CLAIMS discipline (not
  "post-quantum secure").
- `CLAUDE.md`: `sigil-wasm` repo-map bullet records the hybrid exports + `SIGILhyb` interop +
  the mirrored (must-stay-in-sync) `HYBRID_*` consts in both `cli/src/lib.rs` and
  `sigil-wasm/src/lib.rs`; the build & test block gains the `hybrid-interop.mjs` line.
- `docs/decisions/0021-wasm-hybrid-public-key-encryption.md` written (Nygard) + indexed in
  `docs/decisions/README.md` (Accepted, 2026-07); ADR banner extended. RESUME ANCHOR moved to
  Phase 31.

### ➡️ Still open (honest)
- `hybrid_seal`/`hybrid_open` are a **CUSTOM KEM-then-AEAD composition, NOT RFC 9180 HPKE**,
  over the **UNAUDITED** hybrid building blocks; `SIGILhyb` is a **CLI/demo container, not a
  frozen product wire format**, and is **duplicated** in two crates (change one, change the
  other; the golden + interop tests are the tripwire). It is **not** the product's account /
  key-management model and must not protect real secrets. That the browser can now run the
  hybrid path does **not** make the **system** post-quantum secure. A future real, versioned
  container/wire format belongs in `sigil-core` or a purpose-built shared crate (at which point
  ADRs 0020/0021 would be superseded). Posture unchanged; the **system is NOT "post-quantum
  secure".**

---

## 2026-07-14 — Phase 32 (wasm client↔server sync loop over the dev op-log)

### What & why
**CLOSED THE CLIENT↔SERVER E2EE SYNC LOOP** for the client column. Through Phase 31 the wasm
client only did **on-device** crypto (`seal`/`open`, `SIGILcli`, `SIGILhyb`) — it never
crossed the trust boundary to a server. `sigild`'s dev-gated, opaque op-log is the server half
of the sync story and the `sigil` CLI already push/pulls to it. This phase teaches the
browser/Node client to reach the **same** op-log and interoperate with the CLI through it —
demonstrating the full E2EE sync architecture, not just client-side crypto.

Added **`sigil-wasm/sync.mjs`** — a tiny, framework-free, dependency-free ESM transport, the
JS twin of `sigil push` / `sigil pull`. Two exports:
- `pushContainer(baseUrl, vaultId, containerBytes)` → POSTs the **raw** container bytes to
  `POST /v1/vaults/{id}/ops` (Content-Type `application/octet-stream`), asserts `201`, returns
  `{ seq }` from the `{vaultID, seq}` response.
- `pullContainers(baseUrl, vaultId, since=0)` → drains
  `GET /v1/vaults/{id}/ops?since=&limit=500`, reading `{vaultID, ops:[{seq, blob, hash}], next,
  has_more}` (std-base64 `blob`/`hash`), loops `since=next` until `has_more=false`, and
  base64-decodes each `blob` back to the exact bytes → `[{seq, container: Uint8Array, hash}]`.

Key design: **the JS does NO cryptography** — it only shuttles bytes; the wasm seals BEFORE
push and opens AFTER pull. It **reuses the existing op-log contract verbatim** (no new server
surface). It runs in **both Node** (global `fetch` + `Buffer`) **and the browser** (`fetch` +
`atob`) — the only env-specific bit (base64 decode) is feature-detected. The browser `demo/`
gained a **Sync** section (server-URL + vault-ID fields, Seal→Push / Pull→Open buttons) over
`sync.mjs`, with a loud pre-audit banner.

### How verified
- **Live-server sync-loop interop PASS:** `node sigil-wasm/test/sync-interop.mjs` (after
  `build-wasm.sh`) **builds `sigild`** (`go build ./cmd/server`) **and the REAL `sigil` CLI**
  (`cargo build --bin sigil`), boots a LIVE sigild on a free localhost port
  (`SIGILD_ENABLE_DEV_OPS=1`, in-memory backend, no auth), polls `/readyz`, and always kills
  the server in a `finally`. It proves:
  - **PROOF 1** — client self-loop: `wasm.seal_to_container` → `pushContainer` (seq 1) →
    `pullContainers` → `wasm.open_container` == original plaintext.
  - **PROOF 2** — **CLI writes / browser reads**: `sigil seal` + `sigil push` a `SIGILcli`
    container → `pullContainers` (JS) + `wasm.open_container` == original (asserts the pulled
    bytes really carry `SIGILcli` magic).
  - **PROOF 3** — **browser writes / CLI reads**: `wasm.seal_to_container` + `pushContainer`
    → `sigil pull` (writes `op-1.sigil`) + `sigil open` == original.
  - **OPAQUE** — after a push, a raw `GET …/ops` blob base64-decodes to **EXACTLY** the pushed
    container bytes → the server returned them verbatim and did **no crypto** (zero-knowledge
    intact). The two ends use different crypto material per proof yet interoperate because the
    `SIGILcli` container is self-describing (salt + Argon2 params in the header) and the
    password is shared out-of-band; the server never sees any of it.
  Prints the `PASS: sigil-wasm E2EE sync loop over a LIVE sigild op-log …` line, exits 0.
- The op-log contract in `sync.mjs` was checked against the actual server code
  (`sigild/internal/api/handlers.go`: `POST` → `{vaultID, seq}` 201; `GET` →
  `{vaultID, ops:[{seq, blob, hash}], next, has_more}`, `blob` a `[]byte` → std-base64) — no
  name drift.

### Docs (this pass — docs only, no code touched)
- `docs/architecture.md`: §1 `sigil-wasm` bullet extended with the closed client↔server sync
  loop (`sync.mjs`, `pushContainer`/`pullContainers`, the reused op-log contract, opaque →
  zero-knowledge, cross-client CLI interop, the `sync-interop.mjs` live-server proof, honest
  dev/localhost/no-auth framing); §6 "no clients" gap notes the loop is now closed but dev-only.
- `README.md`: `sigil-wasm/` bullet notes browser sync of opaque containers to the dev op-log
  interoperating with the CLI; dev-only; UNAUDITED; MARKETING-CLAIMS discipline.
- `CLAUDE.md`: `sigil-wasm` repo-map bullet records `sync.mjs` (push/pull over the op-log),
  `test/sync-interop.mjs` (live sigild + real CLI cross-client proof), the demo Sync UI, and
  the dev/localhost/plain-HTTP/no-auth + zero-knowledge framing.
- `docs/decisions/0022-wasm-client-server-sync-loop.md` written (Nygard) + indexed in
  `docs/decisions/README.md` (Accepted, 2026-07); ADR banner extended. RESUME ANCHOR moved to
  Phase 32.

### ➡️ Still open (honest)
- **Dev / localhost / plain-HTTP / no-auth only.** The proof boots sigild with no
  `SIGILD_OPLOG_PUBKEY` over plain HTTP on loopback. `sync.mjs` must not be pointed at a remote
  host or used for real secrets. It is a **demonstration** of the sync loop — **not** the
  product sync model: no real auth / device enrollment / per-vault authorization, and no CRDT /
  conflict-free merge / operation semantics (the op-log stays a plain append-and-read byte
  journal with a tamper-evident hash chain, not a mergeable log). A real product sync/auth
  model is a future, separate decision. Posture unchanged; the **system is NOT "post-quantum
  secure".**

## 2026-07-14 — Phase 33 (FIRST product feature: HOTP/TOTP primitive + encrypted CLI TOTP vault)

### What & why
Sigil is an **authenticator**, but until now the repo had **no authenticator function** —
every primitive was a general building block, none was the thing a user actually wants: a
valid 2FA code. Phase 33 closes that: the **first primitive that implements an actual product
FEATURE**. It lands in two layers, split along the no-clock/no-RNG boundary (ADR 0007):
- **Core primitive** — `libsigil/core/src/totp.rs`: `hotp(key, counter, digits, algorithm)`
  (RFC 4226 §5.3 dynamic truncation), `totp(key, unix_time, period, t0, digits, algorithm)`
  (RFC 6238 §4, counter `T=(unix_time-t0)/period`), `format_code(code, digits)` (zero-padded),
  over `OtpAlgorithm` (`Sha1` default / `Sha256` / `Sha512`) + `OtpError`
  (InvalidDigits/InvalidPeriod/TimeBeforeT0). Digits bounded 6..=10 (`MIN_DIGITS`/`MAX_DIGITS`).
- **CLI encrypted vault** — `sigil totp add|list|code|remove` (`cli/src/{lib,main}.rs`): a
  `TotpVault` (versioned `TotpEntry` list) serialized to JSON and **sealed with the SAME
  `SIGILcli` password container as `seal`/`open`** (`seal_vault`/`open_vault` wrap
  `seal_to_container`/`open_container`) — so a TOTP vault is just another opaque sealed
  container (E2EE at rest, op-log-syncable later, no new format). `add` takes `--secret <BASE32>`
  or `--uri "otpauth://totp/..."`; `list` never prints the secret; `code` uses the system clock.

### How (design decisions → ADR 0023)
- **Caller-supplied time keeps the core pure.** `totp` takes `unix_time: u64` as an argument;
  the core reads NO clock and NO RNG, so `no_std`/`wasm32-unknown-unknown`/`getrandom`-free holds
  (ADR 0007). The CLI supplies the wall clock (`SystemTime::now`) and the entropy (Argon2 salt /
  AEAD nonce, as it already did).
- **Two new getrandom-free deps.** `hmac` (keyed MAC — already transitive via `hkdf`, now a
  DIRECT dep) + the NEW `sha1` (HMAC-SHA-1 is the near-universal `otpauth://` default → interop
  REQUIRES it; `sha2` already present). Both `default-features = false` → no `getrandom`/`rand`.
- **Vault reuses the minimal-audit-surface `SIGILcli` sealing** — no new at-rest format, no new
  crypto; inherits wrong-password/tamper → authentication failure, never plaintext.

### How verified (GREEN)
- **RFC known-answer vectors PASS**: `totp::tests::rfc4226_appendix_d_hotp_sha1` (ten 6-digit
  SHA-1 HOTP values, counters 0..=9) and `rfc6238_appendix_b_totp_all_hashes` (8-digit codes at
  six reference times × SHA-1/256/512). Core totp suite **8/8 ok**; core `getrandom`==0.
- **CLI tests 40/40 ok.**
- **Live `sigil totp` demo**: `totp add work --secret <b32> --issuer Acme --digits 6` +
  `totp add --uri "otpauth://totp/Acme:bob?secret=...&period=30"` → `list` shows 2 entries
  (secret never printed) → `code work` → `620863 (valid for 9s)` → on-disk vault begins with
  magic **`SIGILcli`** (sealed-at-rest check) → WRONG password → `Aead(Authentication)` (no
  plaintext leak) → `remove work` drops it.

### Docs (this pass — docs only, no code touched)
- `docs/crypto-spec.md` — new **HOTP/TOTP** section (signatures, RFC-vector verification,
  caller-supplied-time invariant, `hmac`/`sha1` getrandom-free deps, honest UNAUDITED framing).
- `docs/architecture.md` — added `totp` to the `libsigil/core` component list (first product
  *feature*) + the CLI TOTP-vault note + diagram lines.
- `docs/decisions/0023-totp-hotp-primitive-and-cli-vault.md` — new ADR; indexed in
  `docs/decisions/README.md` (Accepted, 2026-07).
- `CLAUDE.md` — libsigil bullet (totp primitive + `hmac`/`sha1` deps) + cli bullet (`sigil totp`
  vault subcommands). `README.md` — TOTP vault as the first authenticator feature (UNAUDITED,
  MARKETING-CLAIMS discipline).

### ➡️ Still open (honest)
- **Generate-only, UNAUDITED, dev-only.** The module only GENERATES codes — verification
  (constant-time compare + validity window) is left to callers; no key zeroization. The OTP math
  is RFC-vector-checked but the build is unaudited. **Do NOT store real 2FA secrets yet.**
- **Not yet the product account/sync model.** The vault is a local CLI file; multi-device sync,
  enrollment, and recovery are future. It *could* ride the op-log unchanged (opaque container),
  but that path isn't wired. The **system is still NOT "post-quantum secure".**

---

## 2026-07-14 — Phase 34 (browser TOTP vault: authenticator works CROSS-CLIENT CLI ↔ browser through the opaque op-log)

### What & why
Phase 33 gave us the authenticator function, but only at the command line. Phase 34 finishes
it **in the browser** and — the real point — proves it works **cross-client**: a TOTP secret
added on one client and synced through the **opaque, zero-knowledge** op-log yields the **same
RFC-correct code** on the other. This is the **first end-to-end product feature spanning two
clients (CLI ↔ browser) and the server**. Docs-only pass here (code + tests already GREEN):
- **wasm OTP exports** — `sigil-wasm/src/lib.rs`: three `#[wasm_bindgen]` fns over the core
  primitive (ADR 0023) — `totp(key, unix_time, period, t0, digits, algorithm)`,
  `hotp(key, counter, digits, algorithm)`, `format_code(code, digits)`. Per the no-clock
  invariant **JS supplies the time**: `unix_time`/`t0`/`counter` arrive as `f64`, validated to
  non-negative integers before the `u64` cast (`u64_from_f64`); `algorithm` is a lowercase
  string mapped by `otp_algorithm_from_str` (mirrors the CLI's `totp_algorithm_from_str`).
  TOTP/HOTP draw no entropy → `sigil-wasm/Cargo.lock` stays `getrandom`==0.
- **shared vault module** — `sigil-wasm/totp-vault.mjs` (framework-free ESM, Node + browser):
  `openVault`/`sealVault`/`addEntry`/`codeForEntry`/`newVault` (+ `base32Decode`,
  `base64ToBytes`/`bytesToBase64`) over `open_container`/`seal_to_container`/`totp`/`format_code`.
  It does NO crypto itself — it reads/writes the **same sealed `SIGILcli` TOTP vault the
  `sigil totp` CLI uses**. Demo UI: `demo/index.html` + `demo/main.js` gain a **TOTP
  authenticator vault** section (add a base32 secret, live per-entry codes, Seal→Push /
  Pull→Open the vault over `sync.mjs`).

### The mirrored schema (KEEP IN SYNC)
The inner **`TotpVault` / `TotpEntry` JSON schema is MIRRORED — not shared — between
`cli/src/lib.rs` (`TotpVault`/`TotpEntry`/`TOTP_VAULT_VERSION`) and `sigil-wasm/totp-vault.mjs`**,
exactly as the `SIGILcli`/`SIGILhyb` container consts are mirrored. Shape (version 1):
`TotpEntry { label, issuer? (OMITTED when absent — serde `skip_serializing_if`), secret
(STANDARD base64 of the RAW key bytes, not base32), algorithm (lowercase sha1/sha256/sha512),
digits, period }`. Any drift (renamed field, wrong casing, base32-vs-base64 secret) breaks
CLI ↔ browser interop; the cross-client test is the guard.

### How verified (GREEN)
- **`node sigil-wasm/test/totp-interop.mjs`** (builds `sigild` + the real CLI, boots a live
  sigild on a free port, `SIGILD_ENABLE_DEV_OPS=1`, in-memory, no auth):
  - **KAT** — the wasm binding reproduces the RFC 6238 App B vectors (T=59, 8 digits):
    sha1 → `94287082`, sha256 → `46119246`, sha512 → `90693936` (clock-independent).
  - **CROSS** — `sigil totp add work --secret GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ --digits 8
    --period 30` → `pushContainer` sends the OPAQUE vault bytes → `pullContainers` reads them
    back → `openVault` decrypts the SAME vault → `codeForEntry(work, 59)` == RFC `94287082`
    == an INDEPENDENT from-scratch Node HMAC-SHA-1 TOTP (`totpIndependent`), and the stored
    `secret` base64-decodes to the RFC SHA-1 key (no base32↔base64 storage drift).
  - **OPAQUE** — a raw `GET …/ops` blob byte-equals the pushed vault (server did no crypto →
    zero-knowledge boundary held).
- Native wasm `*_inner` tests carry the SAME RFC vectors through the `f64`/string wrappers
  (`totp_rfc6238_vectors_through_wrapper`, `hotp_rfc4226_vectors_through_wrapper`,
  `format_code_wrapper_pads`, plus rejection tests for bad algorithm / non-integer / out-of-range).
- `sigil-wasm/Cargo.lock` `getrandom`==0 preserved (JS supplies the time; no entropy drawn).

### Docs (this pass — docs only, no code touched)
- `docs/architecture.md` — sigil-wasm bullet extended: browser TOTP generation, JS-supplied
  time, `totp-vault.mjs` sharing the sealed `SIGILcli` vault, mirrored `TotpVault`/`TotpEntry`
  schema, cross-client-through-op-log proof, demo TOTP UI, honest UNAUDITED/dev framing.
- `docs/decisions/0024-wasm-totp-vault-and-cross-client-totp.md` — new Nygard ADR (context /
  decision / consequences); indexed in `docs/decisions/README.md` (Accepted, 2026-07) and noted
  in its status preamble.
- `CLAUDE.md` — sigil-wasm bullet extended (wasm `totp`/`hotp`/`format_code` exports,
  `totp-vault.mjs`, mirrored-schema sync note, demo UI) + `totp-interop.mjs` (and
  `sync-interop.mjs`) added to the wasm test list.
- `README.md` — short note that the browser can hold an encrypted TOTP vault and generate 2FA
  codes cross-client with the CLI via the op-log; UNAUDITED, do not store real 2FA secrets.
- `journal.md` — this entry + RESUME ANCHOR bumped to through Phase 34.

### ➡️ Still open (honest)
- **Generate-only, UNAUDITED, dev-only.** Still only GENERATES codes (no verification /
  constant-time compare / validity window, no key zeroization); transport is dev / localhost /
  plain-HTTP / no-auth. **Do NOT store real 2FA secrets.**
- **Not the product account / key-management / sync model.** No real auth / enrollment / CRDT;
  the mirrored vault JSON is a pre-audit demo shape, not a frozen wire format. The **system is
  still NOT "post-quantum secure".** Public copy still obeys `web/apps/marketing/MARKETING-CLAIMS.md`.

---

## 2026-07-15 — Phase 35 (CLI TOTP import/export: Google Authenticator `otpauth-migration://` + `otpauth://`)

### What & why
The vault could generate codes but the only way to populate it was one account at a time, and
there was **no way out**. Phase 35 adds **import** (adoption: migrate existing 2FA in — above
all from **Google Authenticator**, whose bulk export is an `otpauth-migration://offline?data=`
protobuf QR) and **export** (trust / no-lock-in: take secrets back out). Code + tests already
GREEN; this pass is docs-only.

- **Hand-rolled protobuf codec** — `cli/src/migration.rs`. NO protobuf crate and no codegen:
  just the two proto3 wire types the format uses (varint = 0, length-delimited = 2), mirroring
  the hand-rolled base32 elsewhere in the crate. `decode_migration_payload` /
  `encode_migration_payload` parse/render `MigrationPayload` + `OtpParameters` into `MigrationOtp`
  records (raw enum ints); `decode_migration_uri` / `encode_migration_uri` wrap the base64 + scheme
  layer (decode tolerates standard/URL-safe, padded or not). Varint capped at 10 bytes, every
  length bounds-checked (truncated/hostile input → `CliError::Totp`, never a panic); unknown
  fields skipped by wire type. Semantic mapping isolated in `migration_otp_to_entry` /
  `entry_to_migration_otp` so the codec stays schema-agnostic + independently testable.
- **CLI** — `cli/src/main.rs`. `sigil totp import <ARG>` = an `otpauth-migration://` URI (bulk),
  a single `otpauth://` URI, or a file of URIs (one/line, blank + `#` skipped); duplicate labels
  skipped (not overwritten), vault re-sealed only if ≥1 imported. `sigil totp export [<label>]`
  = each entry as an `otpauth://` URI, or (with `--migration`) ONE combined
  `otpauth-migration://` URI, to stdout or a 0600 `--out <file>`, behind a LOUD stderr warning.
- **Vault schema UNCHANGED** — import/export translates only at the edges over the existing
  `TotpVault`/`TotpEntry` JSON in the same `SIGILcli` container, so the browser mirror
  (ADR 0024) stays byte-compatible; no new at-rest format.
- **HOTP warned-and-skipped** — a migration payload may carry counter-based HOTP; the vault is
  TOTP-only (schema deliberately not extended) → `ImportedOtp::SkippedHotp`, counted + warned,
  never fatal. MD5/unspecified algorithm + out-of-range digits rejected per entry, not fatally.

### Verified GREEN
- **Golden vector** (`golden_google_authenticator_example_decodes_to_documented_values`): the
  canonical documented Google Authenticator export decodes to raw secret `b"Hello!" ‖ DE AD BE EF`
  (base32 `JBSWY3DPEHPK3PXP`), name `Example:alice@google.com`, issuer `Example`, SHA1 / SIX /
  TOTP — and maps to a well-formed `TotpEntry` (period defaults to 30).
- **Round-trips**: `encode_migration_payload`→`decode_migration_payload` is the identity across
  varied algorithm/digits/type/issuer + a 200-byte secret (2-byte varint length) and survives the
  full URI wrapper; `TotpEntry`→`entry_to_migration_otp`→encode→decode→`migration_otp_to_entry`
  returns the same entry.
- Plus HOTP-skipped, MD5/unspecified-rejected, unspecified-digits-defaults-to-6, truncated-payload
  -rejected-without-panic, unknown-fields-skipped. No new dependency (uses the CLI's existing
  `base64`).

### Docs (this pass — docs only, no code touched)
- `docs/architecture.md` — CLI bullet extended: `totp import`/`export`, Google Authenticator
  `otpauth-migration://` via the hand-rolled `cli/src/migration.rs` protobuf decoder + `otpauth://`,
  vault schema unchanged / browser mirror intact, HOTP warned-and-skipped, export-reveals-secrets
  honest framing.
- `docs/decisions/0025-totp-import-export.md` — new Nygard ADR (context: adoption needs import /
  trust needs export; decision: hand-rolled dependency-free protobuf codec over a crate, keep the
  vault schema, warn+skip HOTP; consequences: hand-maintained decoder verified by golden vector +
  round-trip, export reveals secrets by nature, still UNAUDITED/dev). Indexed in
  `docs/decisions/README.md` (Accepted, 2026-07) + noted in its status preamble.
- `CLAUDE.md` — cli bullet extended with `sigil totp import/export`, the hand-rolled migration
  protobuf codec (dependency-free), and the vault-schema-unchanged / browser-mirror-intact note.
- `README.md` — short note that `totp import`/`export` support Google Authenticator migration +
  `otpauth://`; UNAUDITED, do not use for real secrets yet, MARKETING-CLAIMS discipline.
- `journal.md` — this entry + RESUME ANCHOR bumped to through Phase 35.

### ➡️ Still open (honest)
- **Dev-only / UNAUDITED.** Do NOT import or export real 2FA secrets in this build. `export`
  reveals secrets in the clear **by design** (an export IS plaintext provisioning material).
- **Hand-maintained schema.** The protobuf schema is hand-written, not generated — kept honest
  by the golden vector + round-trip tests. Vault stays TOTP-only (HOTP skipped). Public copy still
  obeys `web/apps/marketing/MARKETING-CLAIMS.md`.

---

## 2026-07-15 — Phase 36 (browser TOTP import/export: parity with the CLI; migration codec MIRRORED cli ↔ sigil-wasm)

### What & why
- Phase 35 gave the **CLI** TOTP import/export; the **browser/wasm** client still had none —
  it could add only one base32 secret at a time and had no way to migrate 2FA in or out. This
  phase brings the browser to **parity**, so **BOTH clients now have full 2FA import/export**.
  A user's 2FA overwhelmingly already lives in Google Authenticator, so a browser client you
  cannot migrate into — or out of — is the same adoption/trust liability it was for the CLI.

### How (design decisions → ADR 0026)
- **Mirror the codec in JS, don't share the Rust one via wasm.** New framework-free,
  dependency-free ESM module **`sigil-wasm/totp-migration.mjs`** is a line-for-line mirror of
  `cli/src/migration.rs` (+ the `otpauth://` parse/build in `cli/src/lib.rs`) — the same
  hand-rolled proto3 codec (varint = 0, length-delimited = 2; NO protobuf library; 10-byte varint
  cap + bounds-checked lengths → throws, never overruns; unknown fields skipped). Public surface:
  `decodeMigrationUri` / `encodeMigrationUri` (the `otpauth-migration://offline?data=…` bulk form),
  `parseOtpauthUri` / `buildOtpauthUri` (single-account `otpauth://`), and `base32Encode` (inverse
  of `totp-vault.mjs`'s `base32Decode`). Consistent with the existing `SIGILcli`/`SIGILhyb`
  container + `TotpVault`/`TotpEntry` vault mirrors — small no-crypto marshalling kept in both
  places, pinned by a cross-tool test, no shared crate / wasm bridge.
- **The codec now lives in TWO places (Rust cli + JS sigil-wasm) and MUST stay in sync.** The
  guard is the cross-tool test below; if either side changes the wire behavior it fails.
- **Demo wiring** — `demo/index.html` + `demo/main.js` import (paste an `otpauth-migration://` or
  `otpauth://` URI) + export (each entry as `otpauth://`, or one combined `otpauth-migration://`),
  matching `sigil totp import` / `sigil totp export`.
- **No vault-schema / container change** — pure edge translation over the existing
  `TotpVault`/`TotpEntry` JSON in the `SIGILcli` container.

### Verified GREEN
- **`sigil-wasm/test/migration-interop.mjs`** — a pure codec-agreement proof (no server/network;
  builds the real `sigil` CLI) proving the JS and Rust codecs wire-compatible THREE ways:
  - **GOLDEN** — the canonical documented Google Authenticator example URI decodes in JS to secret
    base32 `JBSWY3DPEHPK3PXP`, name `Example:alice@google.com`, issuer `Example`, sha1, 6 digits —
    the SAME golden vector the CLI's own Rust test asserts.
  - **RUST→JS** — `sigil totp export --migration` decodes in JS to the CLI's stored accounts (all
    names/algorithms/digits + every secret base32 == the CLI's own `otpauth://` export).
  - **JS→RUST** — a JS-`encodeMigrationUri` URI is accepted by `sigil totp import` and confirmed by
    `totp list` + the CLI's `otpauth://` export carrying the exact secret bytes.

### Docs (this pass — docs only, no code touched)
- `docs/architecture.md` — sigil-wasm bullet extended: the browser now imports/exports TOTP
  (Google Authenticator `otpauth-migration://` + `otpauth://`) at CLI parity, codec MIRRORED
  Rust (cli) ↔ JS (sigil-wasm) with the Node cross-tool agreement test; honest dev/UNAUDITED +
  export-reveals-secrets framing.
- `docs/decisions/0026-browser-totp-import-export.md` — new Nygard ADR (context: client parity /
  browser should import from Google Authenticator too; decision: mirror the migration protobuf
  codec in JS rather than sharing the Rust one via wasm, consistent with the container/vault
  mirrors, and prove agreement with a Node CLI↔JS cross-tool test on the golden vector +
  round-trips; consequences: codec now in two places kept in sync by the test, still UNAUDITED/dev,
  export reveals secrets). Indexed in `docs/decisions/README.md` (Accepted, 2026-07) + noted in
  its status preamble.
- `CLAUDE.md` — sigil-wasm bullet extended with `totp-migration.mjs` (JS otpauth + migration codec
  mirroring `cli/src/migration.rs`), the demo import/export, and the `migration-interop.mjs`
  cross-tool test; the codec-mirrored-and-must-stay-in-sync note; test added to the build-test list.
- `README.md` — short note that the browser can import from Google Authenticator + export at CLI
  parity; codec mirrored + cross-tool test; export in the clear; UNAUDITED, MARKETING-CLAIMS.
- `journal.md` — this entry + RESUME ANCHOR bumped to through Phase 36 (TOTP import/export now on
  BOTH clients).

### ➡️ Still open (honest)
- **Dev-only / UNAUDITED.** Do NOT import or export real 2FA secrets in this build. `export`
  reveals secrets in the clear **by design** (an export IS plaintext provisioning material).
- **Hand-maintained schema in two languages now.** The proto3 codec is hand-written on both the
  Rust and JS sides — kept honest only by `migration-interop.mjs`; a change to one side must
  update the other or the test fails. Vault stays TOTP-only (HOTP warned-and-skipped). Public copy
  still obeys `web/apps/marketing/MARKETING-CLAIMS.md`.

---

## 2026-07-16 — Phase 37 (real webapp: `web/apps/webapp` runs libsigil via WebAssembly client-side, over a `@sigil/wasm` loader)

### What & why
- The client column had reached a real browser only through the throwaway `sigil-wasm/demo/`
  page. The reserved `web/apps/webapp` was blocked on a real, importable wasm artifact + JS
  helpers — which Phases 29–36 built and proved. Phase 37 turns the reserved directory into a
  **real Next.js 15 app that runs the libsigil core via WebAssembly, entirely client-side** —
  the **first real browser product surface**. It is a **live TOTP demo**, not yet a full
  authenticator UI. Dev / no-index / UNAUDITED; **not deployed**.

### How (design decisions → ADR 0027)
- **New `@sigil/wasm` workspace loader package (`web/packages/sigil-wasm`).** Private,
  `type: module` (name **`@sigil/wasm`**). Its `build.sh` generates **bundler-target** wasm
  bindings from the **repo-root `sigil-wasm` Rust crate** and `index.mjs` re-exports the wasm
  surface (`seal_record`/`open_record`, `seal_to_container`/`open_container`, `hybrid_*`,
  `totp`/`hotp`/`format_code`) behind an `initWasm()` awaitable + a typed `index.d.ts`, **plus
  re-uses the proven, wasm-agnostic helpers** from the repo-root
  `sigil-wasm/{totp-vault,sync,totp-migration}.mjs` by RELATIVE import — the same tested source
  the interop tests exercise, NOT a rewrite, NO new crypto.
- **The `target_features`/`externref` strip (the load-bearing wasm-bundling detail).** rustc
  1.85+ force-enables the wasm `reference-types`+`multivalue` target features, so wasm-bindgen
  emits `externref`, which Next.js 15's bundled (old `@webassemblyjs`) webpack parser cannot
  decode (`parseVec could not cast the value`). `build.sh` works around it with a **3-step
  strip**: (1) `cargo build` the crate to raw wasm; (2) delete the `target_features` custom
  section so wasm-bindgen stays in the MVP subset (no `externref`); (3) `wasm-bindgen --target
  bundler` → gitignored `pkg/`. The app sets webpack `experiments.asyncWebAssembly = true`.
- **The app (`web/apps/webapp`).** Next.js 15.1.6 / React 19 / Tailwind 3 / TS-strict app-router.
  `next.config.mjs` carries the SAME no-index stealth headers as marketing (`X-Robots-Tag
  noindex/nofollow/noarchive`, nosniff, `no-referrer`, `X-Frame-Options DENY`) + `app/robots.ts`
  (`Disallow: /`). `app/page.tsx` + a `"use client"` `app/totp-demo.tsx` (dynamic-imports
  `@sigil/wasm` so wasm loads in the browser only) is a **live TOTP demo**: default PUBLIC RFC
  6238 seed `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ` (not a real secret), **wasm-computed** 6-digit code
  + countdown via `codeForEntry`/`base32Decode` (wasm computes the code, never JS), `?secret=` /
  `?t=` test hooks. Loud UNAUDITED / no-real-secrets banner in layout + page.
- **Kept OUT of the default web CI build.** Root `web` scripts still filter to **marketing only**
  (`pnpm --filter marketing …`), so marketing CI stays Rust-free. The webapp builds via its own
  filter and needs the Rust + wasm-pack toolchain; a webapp `prebuild` runs the `@sigil/wasm`
  build first.

### Verified GREEN (gated first-hand)
- **Marketing UNCHANGED** — typecheck / lint / build still green; root web scripts still filter
  marketing only, so CI stays Rust-free. `libsigil/core`, `cli/`, `sigild/`, and the repo-root
  `sigil-wasm` Rust crate are byte-for-byte untouched; `getrandom` count stays 0.
- **`@sigil/wasm` build** succeeds (wasm-bindgen 0.2.100; the 3-step strip produces a
  webpack-parseable module).
- **webapp** typecheck + lint clean; `next build` succeeds with **ONE KNOWN-BENIGN warning** —
  "The generated code contains 'async/await' because this module is using asyncWebAssembly"
  (expected for `experiments.asyncWebAssembly`, not an error).
- **Headless Playwright smoke PASSES 2/2** (`tests/wasm.spec.ts`, chromium): loads the page at
  `?t=59` and asserts the **wasm-rendered** TOTP code is **`287082`** (the RFC 6238 SHA-1 6-digit
  vector at unix 59), and a second seed recomputes to a different 6-digit code — **proving the
  real libsigil wasm runs in a real browser**. Served pages return the no-index headers.
- **Generated artifacts gitignored** (`.next`, `pkg`, `node_modules`, `test-results`, tsbuildinfo).
- ⚠️ **Process note:** the Phase-37 build agent completed the actual build + gate but its workflow
  failed at the final structured-output report step (not the build). The result was **salvaged and
  re-gated first-hand**, so the GREEN above is confirmed, not assumed.

### Docs (this pass)
- `docs/architecture.md` — new `web/apps/webapp` + `@sigil/wasm` component in the map (first real
  product client surface; the 3-step `target_features`/`externref` strip; dev/no-index/UNAUDITED;
  marketing/CI unchanged); diagram footer + the "no clients / extension" gap updated to note the
  browser app now exists (still a demo, not deployed).
- `docs/deployment.md` — the "clients are stubbed" gap now notes the webapp exists but is
  dev-only / NOT deployed, and that building it needs the Rust + wasm-pack toolchain, so it is
  deliberately kept out of the default web CI build.
- `CLAUDE.md` — repository map: `web/apps/webapp` + `web/packages/sigil-wasm` no longer reserved;
  Build & test section gained the webapp/@sigil/wasm commands (with the marketing-only note + the
  benign async-wasm warning).
- `README.md` — short note that an in-browser webapp now exists (dev, UNAUDITED) running libsigil
  via WebAssembly; layout line updated.
- `docs/decisions/0027-webapp-and-wasm-bundling.md` — new Nygard ADR (context: demo proved the
  client; reserved webapp was blocked on a real wasm artifact, now built; decision: real Next.js
  app over a `@sigil/wasm` loader that wasm-packs the crate for a bundler target + asyncWebAssembly,
  with the `target_features`/`externref` strip, reusing the proven JS helpers, kept out of default
  web CI, no-index/UNAUDITED; consequences: two-toolchain build, headless-Playwright RFC-vector
  proof, full authenticator UI is next, not deployed, the strip is a version-tied maintenance
  point). Indexed in `docs/decisions/README.md` (Accepted, 2026-07) + noted in its status preamble.
- `journal.md` — this entry + RESUME ANCHOR bumped to through Phase 37.

### ➡️ Still open (honest)
- **Dev / no-index / UNAUDITED, NOT deployed.** A live TOTP *view*, not a full authenticator UI
  and not the product's account / key-management model. No real secrets. Full authenticator UI is
  a later phase.
- **The externref strip is a maintenance point.** It is tied to the current rustc / wasm-bindgen /
  Next.js (webpack `@webassemblyjs`) versions; `build.sh` documents exactly why it exists so a
  future reader doesn't mistake it for arbitrary. If a future Next.js parser learns `externref`,
  the strip can be dropped.
- **Two-toolchain build.** The webapp needs Rust + wasm-pack (unlike marketing), which is why it
  stays out of the default web CI build; marketing/CI remain Node-only and Rust-free. Public copy
  still obeys `web/apps/marketing/MARKETING-CLAIMS.md`.
