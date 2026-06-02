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
