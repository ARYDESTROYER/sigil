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
