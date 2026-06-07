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
