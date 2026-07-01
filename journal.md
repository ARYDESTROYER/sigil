# Sigil — build journal

Running log of everything done, why, and what's next. **Update frequently and in
depth** (start/end of each session, after every decision/build/test/scope change).
Newest entries at the bottom of each day. Dates are absolute.

Conventions: ✅ done & verified · 🟡 in progress · ⛔ deferred (out of 72h scope) ·
⚠️ risk/gotcha · ➡️ next.

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

## 2026-07-01 — Phase 13 (X25519 key-agreement primitive in libsigil-core)

### Context & mandate
- Goal: add the **classical X25519** (RFC 7748) key-agreement half of the planned
  hybrid KEM (X25519 & ML-KEM-768, suite `0x12`) to `libsigil-core` as a real,
  standalone cryptographic primitive — public-key derivation and Diffie-Hellman —
  mirroring the Phase-11 Ed25519 primitive, without touching the existing
  KDF/AEAD/sig code and without breaking the wasm-pure / no-RNG / getrandom-0
  invariants.
- ⚠️ This is the **KEX PRIMITIVE only**. The **ML-KEM-768 post-quantum half stays
  FUTURE/unimplemented**, and the two shared secrets are **not** combined — there
  is still **no post-quantum KEM** and **no hybrid** in this repo. Not wired into
  any product/KEM flow. Real but **UNAUDITED**.
- Method: research fan-out (43 opus agents over disjoint design questions) →
  synthesized brief; I implemented; adversarial-review fan-out; **I re-ran the
  full gate myself before committing.**

### core — `core/src/kex.rs` ✅
- New module, re-exported from `lib.rs`:
  `x25519_public_key(&[u8;32]) -> [u8;32]` (= `x25519(secret, BASEPOINT)`),
  `x25519_shared_secret(&[u8;32], &[u8;32]) -> [u8;32]` (raw DH scalar-mult), and
  a constant-time `is_contributory(&[u8;32]) -> bool` all-zero/low-order check,
  plus the length constants `KEX_SECRET_LEN`/`KEX_PUBLIC_KEY_LEN`/
  `KEX_SHARED_SECRET_LEN` (all 32).
- **Caller-supplied entropy:** takes a 32-byte secret scalar from the caller —
  exactly like the KDF salt, the AEAD nonce, and the Ed25519 seed. **core still
  generates NO randomness.** X25519 clamps the scalar internally.
- **Raw primitive, caller owns policy.** `x25519_shared_secret` returns the raw
  result and is total (never panics for any 32-byte input); the contributory
  (all-zero) policy is surfaced via `is_contributory`, not decided for the caller
  (RFC 7748 §6.1 stance, matching `sig.rs`). `is_contributory` uses `subtle`'s
  constant-time `ct_eq` so it does not leak which bytes are zero.
- ⚠️ **classical only** — documented as future/unimplemented for ML-KEM-768 in the
  module docs, `lib.rs`, crypto-spec, architecture, and ADR 0010. **UNAUDITED**
  throughout. Cross-primitive caveat added: do NOT reuse the same 32 bytes as both
  an Ed25519 seed and an X25519 secret.

### Dependency & the WASM/GETRANDOM gate ✅
- Added **`x25519-dalek = { version = "2", default-features = false }`** (+
  `subtle` declared directly, `default-features = false`, already transitive via
  `curve25519-dalek`). `default-features = false` is load-bearing: it drops the
  `getrandom`/`rand_core`, `zeroize`, and `static_secrets` paths — we use only the
  RNG-free free function `x25519()` and the `X25519_BASEPOINT_BYTES` constant.
- ✅ **The gate held.** `grep -c 'name = "getrandom"' libsigil/Cargo.lock` = **0**
  (before and after), `cargo build -p sigil-core --target wasm32-unknown-unknown`
  **succeeds**, and there is still exactly **1** `curve25519-dalek` in the lock
  (shared with `ed25519-dalek`, no duplicate). `#![forbid(unsafe_code)]` and
  `no_std` intact.

### Tests ✅
- **RFC 7748 §6.1 KAT** (Alice/Bob): derive both public keys from the given
  secrets and compute the shared secret both directions — a real interop vector.
- **RFC 7748 §5.2 KAT**: single scalar·u-coordinate multiplication — an
  independent vector for the raw path.
- Plus: symmetric agreement for self-derived keys, distinct-peer secrets differ,
  determinism, `u=0` and `u=1` low-order points → all-zero + non-contributory, and
  a direct `is_contributory` all-zero/non-zero test, and constant lengths.
- ✅ `cargo fmt --check` clean · `cargo clippy --all-targets -D warnings` clean ·
  `cargo test` — **sigil-core 60 PASS** (9 new kex), sigil-ffi 7 PASS · wasm build
  OK · getrandom count **0**.

### docs — crypto-spec.md / architecture.md / ADR 0010 ✅
- New **ADR 0010** (X25519 key-agreement primitive — classical KEM half,
  caller-supplied secret, raw primitive + `is_contributory` policy hook,
  cross-linked 0004/0007). `crypto-spec.md` hybrid-construction status now names
  the classical X25519 half implemented (ML-KEM-768 half + combine still not);
  `architecture.md` §1 lists the primitive and §6 splits the KEM/signature
  half-built status. `README.md` + `CLAUDE.md` repo-map lines name the X25519 KEX
  primitive. Decisions index updated.

### ➡️ Still NOT done (honest)
- **No PQ, no hybrid, not wired in.** ML-KEM-768 remains unimplemented; the two
  shared secrets are not combined; the primitive is a standalone building block,
  not part of any KEM/record/product flow. No zeroization. Real but UNAUDITED.

## 2026-07-01 — Phase 14 (FFI expansion: Ed25519 sign/verify + X25519 over the C-ABI)

### Context & mandate
- Goal: expose the Phase-11 Ed25519 and Phase-13 X25519 primitives across the
  `sigil-ffi` C-ABI so the native clients (separate repos) can call them, without
  touching the existing `seal`/`open`/`buffer_free` surface and without adding any
  dependency or RNG to the FFI.
- Method: 35-agent research fan-out → synthesized FFI design brief (the first
  synthesis run returned placeholder junk; re-ran just the synthesis from the
  cached research with a strengthened prompt) → I implemented → gate re-run myself.

### ffi — six new fixed-size exports ✅
- **New calling convention** (ADR 0011): because every output is a **fixed size**
  (32/64 bytes), these write into a **caller-allocated** out buffer and return an
  `int32_t` status — **no heap `SigilBuffer`, nothing to `sigil_buffer_free`**.
  `seal`/`open`/`buffer_free` are unchanged. New exports:
  `sigil_ed25519_public_key`, `sigil_ed25519_sign`, `sigil_ed25519_verify`,
  `sigil_x25519_public_key`, `sigil_x25519_shared_secret`,
  `sigil_x25519_is_contributory`.
- **One new status code `SIGIL_ERR_VERIFY = -4`.** `sigil_ed25519_verify` returns
  `SIGIL_OK` (0) for a valid signature and collapses **all** `SigError` variants
  (BadPublicKey/BadSignature/Verification) into `SIGIL_ERR_VERIFY` — no
  structure leak, same stance as `sigil_open`→`SIGIL_ERR_OPEN`, but a distinct
  code. `0 == valid` is documented loudly (opposite of a C bool).
- **Guard-first, copy-first, alias-safe.** All required pointers null-checked
  before any write; each fixed input copied into a local array before the output
  is written, so out buffers may overlap inputs; `msg` reuses `optional_slice`
  (null iff `len == 0`). `sigil_x25519_shared_secret` returns the **raw** DH result
  (all-zero for a low-order peer → still `SIGIL_OK`); contributory policy is the
  separate `sigil_x25519_is_contributory` **predicate** (1/0/-1, not a status code).
- Algorithm-qualified names leave room for future `sigil_mldsa65_*` /
  `sigil_mlkem768_*`. `#![deny(unsafe_op_in_unsafe_fn)]`, per-block `// SAFETY:`
  notes, and `# Safety` doc sections on every export, matching the crate style.

### hand-written header + docs ✅
- `sigil.h` kept in sync **by hand**: new `#define SIGIL_ERR_VERIFY (-4)`, a new
  banner section + the six prototypes (C99 sized-array params `uint8_t x[32]`),
  broadened top/status-code comments. **Symbol parity verified**: the 10
  `extern "C" fn` names in `lib.rs` == the 10 prototype names in `sigil.h`, and the
  `SIGIL_*` codes match. New **ADR 0011** (fixed-size out-buffer convention);
  `architecture.md` (ffi bullet + ASCII diagram), README, CLAUDE, decisions index,
  and this journal updated in the same change.

### Tests + gate (independently re-run) ✅
- 15 new `#[test]`s (total **sigil-ffi 22**, sigil-core 60): Ed25519 round-trip,
  tamper-sig/tamper-msg/wrong-key → `SIGIL_ERR_VERIFY`, malformed-pubkey collapses
  (no crash), empty-message sign+verify, null-arg matrix, **RFC 8032 TEST 1 driven
  through the C-ABI**; X25519 agreement, pubkey-matches-core, **RFC 7748 §6.1
  through the C-ABI**, null-arg matrix, low-order peer → all-zero + `SIGIL_OK` +
  non-contributory, `is_contributory` predicate, and a `status_code_values_are_stable`
  regression pin (0,-1,-2,-3,-4).
- `cargo fmt --check` clean · `clippy --all-targets -D warnings` clean · `cargo
  test` 60 + 22 pass · wasm build OK · **getrandom count 0** (no new dep — ffi's
  only dep stays `sigil-core`; `libsigil/Cargo.lock` unchanged by this phase).

### ➡️ Still NOT done (honest)
- **Classical-only, UNAUDITED, no keygen in FFI.** The PQ halves (ML-DSA-65 /
  ML-KEM-768) are unimplemented, so nothing here is post-quantum; the host supplies
  seeds/secrets (no RNG in the FFI, per ADR 0007); none of it is wired into an
  account/key-management flow. Optional `panic = "abort"` hardening left as a noted
  future option (the wrapped core fns are already panic-free for fixed inputs).

## 2026-07-01 — Phases 13 & 14 adversarial review follow-ups

Both phases went through large multi-agent adversarial review passes after commit;
**must-fix was empty in both** (no code defects, UB, or invariant violations —
the code was verified sound, KATs pass, constant-time check confirmed, alias-safety
confirmed genuinely sound). The surviving items were doc-accuracy and test-coverage
gaps, applied as follow-up commits:

- **Phase 13 review** (35 reviewers) → commit `2999c76`: corrected ADR 0010's
  `default-features` description (matches the Cargo.toml comment now); documented +
  tested two X25519 properties — non-canonical public-key encoding (bit-255 mask /
  mod-p) and the argument-order footgun; added `clamping_equivalence` and a
  non-trivial order-8 low-order-point test (sigil-core → 63 tests).
- **Phase 14 review** (22 dimensions × 3 independent voters = 66) → this commit:
  the loudly-documented FFI alias-safety guarantee (out may overlap in) was tested
  by zero tests; added three in-place aliasing regression tests
  (`ed25519_public_key_in_place_alias`, `ed25519_sign_out_overlaps_seed`,
  `x25519_shared_secret_in_place_alias`) that pin the copy-before-write ordering
  against a known-answer vector (sigil-ffi → 25 tests). The review explicitly
  discarded two suggested "missing" tests as non-issues (a wrong-length verify is
  structurally impossible for fixed-size array params; is_contributory-on-real-DH is
  already covered).

Gate after both follow-ups: fmt/clippy clean; **sigil-core 63 + sigil-ffi 25** pass;
wasm green; getrandom 0.

## 2026-07-01 — Phase 15 (op-log replay protection: per-request nonce, contract v2)

### Context & mandate
- Goal: close the replay gap the docs/code explicitly flagged on the dev op-log's
  optional Ed25519 auth ("the 300 s window bounds replay but does NOT prevent it —
  there is no nonce/jti store"). Add a per-request **nonce** and a bounded
  server-side nonce store so a captured signed request cannot be replayed within
  the window. Cross-language (sigild Go + CLI Rust), byte-exact contract.
- Method: 34-agent research fan-out → synthesized design brief (the first
  schema-constrained synthesis failed the retry cap; re-ran the synthesis as
  free-text from the cached research). I implemented; **I re-ran the gate and a
  LIVE cross-language interop + replay test myself.**

### The v2 contract (`sigil-oplog-auth-v2`)
- Bumped the domain `v1`→`v2` and inserted a `NONCE` line **between TIMESTAMP and
  BODY**: `MESSAGE = "sigil-oplog-auth-v2\n" + METHOD + "\n" + PATH + "\n" + QUERY
  + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + BODY`. A **hard cutover** — v1 and v2
  are mutually unverifiable (domain + framing both differ). New required header
  **`X-Sigil-Nonce`**; the CLI sends standard-base64 of 16 CSPRNG bytes.

### sigild — nonce store + v2 verify ✅
- New `internal/api/noncestore.go`: a bounded, TTL-evicting, in-memory
  `nonceStore` (Go stdlib `sync.Mutex` + map). `checkAndRecord(nonce, now)` is an
  atomic read-modify-write. **TTL = 2× the skew window (600 s), not 1×** — the
  skew check is two-sided (a request may be signed up to 300 s in the future), so
  a captured request stays replayable until `ts+300` = up to `now+600`; a 1× TTL
  would evict the guard a window too early. Expiry anchors to the **server's**
  receipt time (never the attacker-controlled client ts). Hard cap
  (`nonceStoreMaxEntries = 65536`); at capacity, after sweeping expired entries,
  it **fails closed**.
- `opsauth.go` (v2): read all three headers; **validate the nonce BEFORE folding
  it into the message** (`validNonce`: non-empty, ≤128 bytes, printable ASCII
  `0x21`–`0x7E` so it can't contain `\n` and shift framing); fold nonce into the
  message; `ed25519.Verify`; then — **only after a valid signature** — consult the
  nonce store (so unauthenticated traffic can't populate/flood it). Nonce store
  wired onto `handlers` and created in `NewRouter` only when auth is on.
- Unchanged when auth is off (no pubkey → no nonce required, byte-for-byte the
  same). `main.go` WARN updated. Still Go stdlib-only (no `go.sum`).

### cli/ — v2 signing ✅
- `sign_oplog_request` now generates a `fresh_nonce()` (16 CSPRNG bytes via the
  already-present `getrandom`, standard-base64), folds it into the v2 message, and
  returns `(timestamp, nonce, signature)`; `push`/`pull` attach `X-Sigil-Nonce`.
  Unsigned path (no `--key`) unchanged. `libsigil/Cargo.lock` unchanged, getrandom
  **0**; `cli/Cargo.lock` gained `x25519-dalek`/`subtle` transitively from Phase
  13's `sigil-core` (expected; cli getrandom stays 1, `cli/Cargo.toml` unchanged).

### Tests + gate (independently re-run) ✅
- Go: `noncestore_test.go` (fresh/replay/expiry/cap-fail-closed/cap-reclaim/
  concurrent, `-race`) + `opsauth_test.go` extended to v2 (replay→401, missing/
  malformed nonce→401, v1-message→401, distinct-nonces→both accepted, plus all
  existing cases updated). `gofmt`/`vet`/`build` clean; `go test -race ./internal/
  api/` green.
- Rust: `fresh_nonce` distinctness/framing test; `push/pull_with_key` updated to
  verify over the v2 message + assert the nonce header. cli fmt/clippy clean, 27
  lib + 2 integration tests. libsigil 63+25 unaffected.

### Verification — LIVE cross-language interop + replay (the real gate) ✅
Built `sigild` + the CLI. `keygen` → device.key (0600) + pubkey. Started sigild
with `SIGILD_ENABLE_DEV_OPS=1 SIGILD_OPLOG_PUBKEY=<pub> :18111`.
1. **Rust-signed v2 push → Go verify:** `sigil push --key` → "pushed vault demo
   seq 1" (the byte-exact cross-language contract works over a real socket).
2. Second signed push → **seq 2** (fresh nonce accepted).
3. Unsigned push → **HTTP 401** `{"error":"unauthorized",…}`.
4. **Replay (the point):** captured a real CLI-signed request (via a one-shot
   capture server), then `curl`-replayed it twice to the live sigild — **first →
   201, identical resend (same nonce, same still-fresh timestamp) → 401.** Because
   the *same timestamp* succeeded on the first replay, the 401 is the **nonce
   store** catching the replay, not staleness.
5. Tampered nonce → **401**. Server killed; no leftover processes.

### docs ✅
- New **ADR 0012** (nonce replay protection, v2); `api.md` auth section rewritten
  to v2 (3 headers, 6-line message, replay step, honest in-memory caveat);
  `architecture.md` §1/§2/§6, `README.md`, `CLAUDE.md`, `cli/README.md`, and the
  decisions index updated; the stale "not nonce-tracked" phrasing replaced (ADR
  0008 and journal history left immutable).

### ⛔ Still NOT production (honest)
- The nonce store is **in-memory / per-process**: lost on restart (a captured
  request could be replayed after a restart within its remaining window) and not
  shared across instances (replicas don't dedupe). Production needs a
  shared/persistent store (e.g. Redis `SET NX EX`). Still a SINGLE static dev key,
  plain-HTTP, dev-gated-off by default. Enrollment / multi-device / JWT remain
  future.

## Documentation strategy

Recording the decision so the doc set stays coherent as the repo grows:

- **`CLAUDE.md`** = the working guide (toolchains, known-green commands,
  guardrails) — read first by anyone (human or agent) doing work.
- **`journal.md`** = this chronological log (what/why/next, per session/phase) —
  the source of truth for non-obvious context. ~510 lines now; **fine for now**.
  ➡️ If it keeps growing we will **rotate it per-month** (e.g. `journal/2026-06.md`)
  rather than let one file sprawl.
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
