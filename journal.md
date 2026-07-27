# Sigil — build journal

Running log of everything done, why, and what's next. **Update frequently and in
depth** (start/end of each session, after every decision/build/test/scope change).
Newest entries at the bottom of each day. Dates are absolute.

Conventions: ✅ done & verified · 🟡 in progress · ⛔ deferred (out of 72h scope) ·
⚠️ risk/gotcha · ➡️ next.

---

## ⭐ RESUME ANCHOR — state of play (keep current; read this first)

**Where we are (through Phase 51; Phase 51 is complete and gated but UNCOMMITTED in the
working tree — `main` @ origin is at Phase 50 + two fix commits).**

**Phase 51 closed the third full-repo audit's findings.** No new feature; two of the
findings shared one shape — ⭐ **a control that exists in the code but does not reach the
place it has to act is not a control.** (1) ⭐ **The desktop's key-substitution ALARM is
now VISIBLE.** It always *refused* correctly, but `desktop/ui/main.js` had no handler and
no re-pin control, so a refused share showed as a **7-second toast** (the webapp and
extension both blocked and explained). IPC errors now cross as a **STRUCTURED** value —
`CmdResult<T> = Result<T, IpcError>`, `IpcError { kind, message, key_change? }` — with
`key_change` populated for **exactly one kind** (`"key changed"`) carrying `device_id` +
both safety numbers, **PUBLIC material only, no key bytes and no seed**;
`From<String> for IpcError` left every `?` site unchanged. The UI gained a `#pin-mismatch`
`role="alert"` block that **BLOCKS share + rotate**, prints both numbers, and puts a
`window.confirm`-guarded re-pin behind them sending `expected` = the presented number so
the native side re-checks it — reached from the single central `call()` error path.
⚠️ **The REFUSAL did not change, only its visibility.** ⚠️ **Premise correction: the
finding also claimed the desktop lacked safety-number / pinned-key views — WRONG, they
already existed.** **NEW TEST** (`desktop/core/tests/server_interop.rs`
`a_substituted_hybrid_key_raises_the_alarm_the_desktop_ui_renders`): the desktop was the
ONLY client whose key-substitution defence had no regression test. Real sigild + real CLI;
CLI publishes K1, a share PINS it, then `sigil device hybrid-publish --regenerate` makes
the SAME device id present a DIFFERENT key — what a hostile server does, and deliberately
indistinguishable from a legitimate re-enrolment. Asserts `DesktopError::KeyPinMismatch`
with both numbers in the 6×5-digit shape, **rotation refused too**, a WRONG-number re-pin
refused **leaving the old pin standing**, and only a deliberate re-pin resuming sharing.
✅ **MUTATION-TESTED**: with the pin check in `cli/src/lib.rs` failing open it fails with
*"SHARED TO A SUBSTITUTED KEY — the pin check did not fire"*. ⚠️ It also exposed a LATENT
harness bug — `Harness::start()` keyed its temp dir on pid + `now_unix()` in **SECONDS**,
and cargo runs a file's tests in **parallel threads of ONE process**, so two harnesses in
the same second shared a path and one `remove_dir_all`'d the other's state (surfacing in
the OTHER test); fixed with an `AtomicUsize`. (2) ⭐ **WEBHOOK DEDUP MOVED INSIDE THE
SIGNATURE (ADR 0039, revising §4 of ADR 0034).** Razorpay signs the **BODY ONLY**, but the
dedup id came from the **`X-Razorpay-Event-Id` HEADER**, which a replayer picks freely — so
a captured valid delivery replayed with a fresh header verified and counted as a **NEW
event** (attacker-driven unbounded growth of the processed-events ledger; the state machine
bounded the rest). The invariant now: **an idempotency key MUST be a function of bytes the
provider's SIGNATURE COVERS.** `billing.Event` gained `DedupKey` + `Event.IdempotencyKey()`;
Razorpay **always** uses `"body-" + hex(SHA-256(rawBody))` and the header is demoted to a
correlation LABEL on `Event.ID`; Stripe uses `env.ID` (inside the signed payload); Juspay
derives from the body. ✅ **MUTATION-TESTED**: reverting to `ev.ID` makes the replay return
`"accepted"` and `TestWebhookRazorpayReplayWithFreshHeaderIDIsOneEvent` catches it; live
forgery set is 401/401/401 (wrong secret / tampered body / missing header). ⚠️ **VACUOUS
under Juspay `scheme=basic`** — it authenticates the connection, not any bytes. (3)
**Juspay's default webhook scheme is now `hmac`** (`NewJuspay`'s switch inverted; `default`
= HMAC, so an unset scheme fails CLOSED rather than degrading to connection-only auth):
`SIGILD_JUSPAY_WEBHOOK_SECRET` required when unset, `basic` is a boot failure without its
credentials and logs a **WARN naming the limitation every start**. Both schemes still work.
(4) **The marketing security page stopped under-claiming** — it said nothing was
implemented and called ML-KEM-768 / ML-DSA-65 "planned", which was **false in the safe
direction**. Now Argon2id / XChaCha20-Poly1305 / X25519 / Ed25519 / ML-KEM-768 / ML-DSA-65
are **"Implemented; unaudited"**, ML-KEM-768 additionally **load-bearing**, ML-DSA-65
**"not yet in the authentication path"**, TLS X25519MLKEM768 still "Designed; planned",
with a defined vocabulary (**"implemented" = the code exists in the pre-release repo and
its own tests pass — NOT released, NOT reviewed**) and a paragraph stating that
implementing ML-KEM/ML-DSA does **NOT** make a system "post-quantum secure". ⚠️ **PREMISE
CORRECTION + STANDING INVARIANT: the finding claimed these are "tested against FIPS
vectors" — FALSE HERE.** `mlkem.rs:332` / `mldsa.rs:335` state that **NO official FIPS 203
/ FIPS 204 / NIST ACVP known-answer vector is embedded**; the **UPSTREAM RustCrypto crates**
are ACVP-validated. **Never write that we verify against FIPS/ACVP vectors.** (5) **CI:**
`sigild.yml` now runs **`go test -race ./...`** (the local gate always did — CI was the
weaker one), `security.yml`'s cargo-audit covers **all four Rust workspaces** (it audited
only `libsigil`, the smallest lockfile; `desktop/` carries the whole Tauri tree), and
`cli/tests/e2e-sharing.sh` **finally runs in a workflow** (a second job in `interop.yml`;
it also stopped hardcoding the macOS Homebrew Go). ⚠️ Two doc corrections found while
writing the CI list out file-by-file: the "desktop CI cannot find Go" warning described a
gap **already closed inside Phase 49**; and CLAUDE.md wrongly claimed `libsigil.yml` /
`cli.yml` run the **`getrandom`==0 guard** — they do NOT (only `desktop.yml` and
`interop.yml` do; coverage survives because `interop.yml` triggers on `cli/**` and
`libsigil/**`, but do not assume the crate's own job checks it).
**NEW ADR 0039**; docs synced in the same change. Details in the Phase 51 entry below.

**Phase 50** **CLOSED THE
HOLE THIS REPO HAD BEEN DOCUMENTING AS OPEN** — the one the threat model called *"the
single largest gap in the design"* and ADR 0035 recorded verbatim: **no out-of-band
verification of a published hybrid public key**, so a hostile/compromised server could
substitute its OWN key, receive the vault key wrapped to itself, and read the vault
INVISIBLY. The request was authenticated; the RESPONSE never was. ⭐ **THREE MECHANISMS,
ALL CLIENT-SIDE** (ADR 0038): **(1) PINNING** — the first hybrid public key seen for a
device is PINNED, every later fetch compares RAW bytes of BOTH halves, and a **CHANGED
key BLOCKS** (`CliError::PinMismatch` / `KeyPinMismatchError` / `DesktopError::KeyPinMismatch`,
IPC-tagged `"key changed"`): **nothing wrapped, nothing uploaded, the pin store NOT
mutated**, and there is **NO flag/option/default ANYWHERE that accepts a changed key**;
an UNCHANGED key proceeds silently; **FIRST SIGHT pins, proceeds and WARNS** — the honest
limit of TOFU. ⭐ **THE CHOKE POINT IS THE FETCH ITSELF** — `fetch_hybrid_key_pinned` /
`fetchHybridKeyPinned` fetch + pin-check in ONE call and **EVERY wrap path (share AND
rotate, both implementations) goes through it**; the bare `fetch_hybrid_key` /
`fetchHybridKey` survive ONLY on non-wrapping paths (safety-number display, the
deliberate re-pin, desktop `check_server`). **(2) SAFETY NUMBER** — `SHA-256("sigil-
safety-number-v1\n" ‖ u32_be(len(deviceId)) ‖ deviceId ‖ u32_be(32) ‖ x25519_public_key ‖
u32_be(1184) ‖ mlkem_encaps_key)`, rendered as **6 groups × 5 digits** (each = 5 digest
bytes big-endian mod 100000, zero-padded) ≈ **99.6 bits**; the **PAIRWISE** form sorts the
two digests **BYTEWISE** then hashes under `"sigil-safety-number-pair-v1\n"` so **both
sides see the SAME string regardless of order**. It **binds the device id** and covers
**BOTH key halves**, so a genuine key replayed under another device id does NOT verify.
**(3) ROTATION** — `rotate_vault_key`/`rotateVaultKey`: **pin-check EVERY recipient FIRST**
(a mismatch aborts before ANY local or remote mutation), fresh 32-byte key,
`reseal_container` (open old → seal new, **never inspecting the plaintext**), 0600 via
temp-file+rename, `keyring_put` **AFTER** the file lands, wrap+upsert per recipient, then
list + **DELETE every envelope not in the recipient set**. **RE-PIN is deliberate and
never automatic:** `sigil device repin <id> --yes [--safety-number "<digits>"]` refuses
without `--yes` and refuses if the supplied number ≠ what the server serves NOW; re-pins
are **counted** and shown by `sigil device pins`. **NEW CLI:** `device safety-number
[<id>] [--pair <id>]` / `device pins` / `device repin` / `vault rotate --vault <id> --to
<dev>…`. **PIN STORE:** natively `hybrid-pins.json` **0600 in the 0700 state dir** (the
CLI **and** desktop share the SAME file ⇒ one record); in the browsers **INSIDE the
existing sealed device-identity container**, schema **v2→v3** (`pins` field, v1/v2 still
open yielding an EMPTY store) — so the browser clients **STILL persist ONLY sealed
containers**. **EXACTLY TWO IMPLEMENTATIONS** (Rust `sigil-cli` for CLI+desktop via ADR
0037; `sigil-wasm/sharing.mjs` for webapp+extension), **MIRRORED — MUST stay
byte-identical**, same KAT on both sides. **sigild gained TWO minimal dev-gated routes**
reusing the **EXISTING** `authorizeOpsRequest` + `needWrite` (the same check that
authorizes depositing an envelope): **`GET /v1/vaults/{vaultID}/keys`** (**METADATA ONLY**
— device id, sender, size, created_at, **never a blob**) and **`DELETE
/v1/vaults/{vaultID}/keys/{deviceID}`**; **sigild stores/serves/validates NO pin and NO
safety number**, still **501 by default**, still **exactly ONE direct dependency**.
✅ **VERIFIED FIRST-HAND:** all **NINE** node tests pass; **cli 77 tests**; desktop **15
unit + its integration tests**; **sigild `go test -race` green across 4 packages**;
webapp build + **Playwright 8/8**; **extension 3/3**; `libsigil` `getrandom` still **0**.
⭐ **THE ATTACK IS BLOCKED, PROVEN LIVE** (`sigil-wasm/test/pinning-interop.mjs`): a
**rewriting proxy** in front of a real `sigild` swaps B's hybrid public key for an
ATTACKER's — exactly what a hostile registry does — and the CLI **REFUSES** with an error
NAMING BOTH safety numbers, explaining it is either a key-substitution attack or a
legitimate re-enrolment, stating **no vault key was wrapped and nothing was uploaded**,
and telling the user to confirm out-of-band then re-pin deliberately; the stored envelope
stays **BYTE-IDENTICAL to the honest one** and does **NOT open with the attacker's hybrid
secret**; the browser threw `KeyPinMismatchError`; and **Rust and JS safety numbers
agreed** (per-device, pairwise-from-both-sides, and the shared KAT). ⚠️ **HONEST LIMITS,
DO NOT SOFTEN:** pinning **CANNOT protect FIRST contact** — the safety number can, but
**only if a human actually compares it**, and nothing forces or detects that; a user who
**blindly re-pins defeats it**; **rotation protects FUTURE content ONLY** (a device that
already unwrapped a key keeps what it copied); anyone who can rewrite the pin store can
silence the alarm; there is still **no key-transparency log and no cross-signature**
binding a hybrid key to the enrolled Ed25519 identity (**the highest-value follow-up**);
and **ALL OF IT IS UNAUDITED**, dev-gated, plain HTTP. **This is NOT "secure now"** — it
closes one documented hole and narrows another. ADR 0038 (new) + a dated addendum on ADR
0035 retiring its two stale limitations; details in the Phase 50 entry below.
Phase 49 put the
**NATIVE DESKTOP client on the network**: device **enrollment**, **contract-v3 signed
sync**, and **vault sharing** — so **all four client surfaces (CLI, webapp, MV3
extension, native desktop) are peers**, and the desktop is no longer offline-only.
⭐ **THE HEADLINE IS REUSE, NOT REIMPLEMENTATION, AT THE PROTOCOL LAYER:**
`desktop/core/src/net.rs` imports **30 symbols from the `sigil-cli` LIBRARY**
(`enroll_device`, `push_op_auth`/`pull_ops_auth`, `publish_hybrid_key`/`fetch_hybrid_key`,
`put_key_envelope`/`get_key_envelope`, `wrap_vault_key`/`unwrap_vault_key`,
`grant_vault_access`, the `generate_*`/`load_*`/`save_*`/`keyring_*` helpers,
`vault_key_fingerprint`, `RequestAuth`, `DeviceIdentity`, `VaultKeyring`, `CliError`,
`VAULT_KEYRING_FILE`, `VAULT_KEY_LEN`) — **grep-verified: ZERO copies of the canonical v3
message domain, ZERO copies of the enrollment-challenge domain, ZERO direct
`ureq`/`reqwest`, ZERO direct Ed25519 signing anywhere under `desktop/`.** The canonical
signed bytes exist in **THREE** implementations (Go server / Rust CLI / JS browser), kept
in sync only by interop tests; **a fourth copy was explicitly avoided** (ADR 0037). The
only new code is app config/UI wording — the CLI's path-resolution + error-explanation
helpers live in `cli/src/main.rs`, i.e. the **BINARY**, so they are not importable;
`DeviceConfig` re-derives the same file names and `net_error` maps `CliError` → typed
`DesktopError`. **`cli/` was NOT edited.** Because the CLI's own writers and file names
are used, the state files are **INTERCHANGEABLE**: point `sigil --key` (or `HOME`) at the
desktop state dir and it is literally the same device. **New operations:** `DeviceConfig`
+ `enroll`, `publish_hybrid`, `push_vault`/`push_vault_file`, `pull_vault`, `share_vault`,
`accept_vault`, `status`, `check_server`, plus `VaultSession::convert_to_shared`/
`unlock_shared` and `pull_and_adopt` (v3 when enrolled, legacy v2 when the identity has no
device id, unsigned with no identity). ⭐ **`status()` is purely LOCAL** (no network,
cannot fail because a server is down; fingerprints only) while **`check_server` reports
reachability as DATA, not an error**; **`pull_and_adopt` OPENS the pulled container BEFORE
writing** (temp file + rename, 0600) so an unreadable container can never clobber a good
vault. **11 new `#[tauri::command]`s** (→ 21 total) over `AppState { session, sync }`, with
the config **cloned out before any network call** so no lock is held across I/O; errors
reach the UI tagged distinctly: unauthenticated (401) / not authorized (403) / route
disabled (501) / nothing there (404) / server unreachable / not enrolled / already enrolled
/ not a shared vault. **SECRETS:** the native model, identical to the CLI's, inside a
**0700** state dir (`$HOME/.sigil`) — `device.key` **0600**, `device.hybrid` **0600**,
`device.hybrid.pub` (public), `vault-keys.json` **0600**, `totp-vault.sigil` 0600 via
temp-file + rename; modes asserted in tests. **NEVER printed, logged or returned across the
IPC:** the Ed25519 seed, the hybrid secret, the vault key, the human password, the
enrollment token — only device ids + SHA-256 fingerprints (the only prints are the
pre-audit banner). The enrollment token is a **password-type field, used for ONE call,
cleared in a `finally`, never stored**. ✅ **VERIFIED FIRST-HAND:** `cargo fmt --check` and
`clippy --all-targets -D warnings` clean; the **full desktop suite passes** (15 unit tests +
the pre-existing `cli_interop` + the new `server_interop`); `cargo build --release`
succeeds; `libsigil/Cargo.lock` `getrandom` still **0**; changes confined to `desktop/`; the
other clients unaffected (sigil-wasm `sharing-interop` + `sync-interop` still pass).
⭐ **THE PROOF** (`desktop/core/tests/server_interop.rs` — boots a **REAL sigild** with
dev-ops + device auth and builds the **REAL `sigil` binary**; the clock is pinned via
**`period = 1_600_000_000`** so the TOTP counter equals RFC 6238 App B's `T=59` counter from
2020 to 2071): `status` reads with **no state at all** and contract-v3 ops report
**NotEnrolled**; the desktop enrolls (identity 0600 in a 0700 dir); publishes its hybrid
public key (secret 0600, **never uploaded**); re-seals the vault under a random 32-byte
vault key so **the password no longer opens it**; pushes it as **seq 1, contract-v3
signed**; **(a) DESKTOP → op-log → CLI:** the real `sigil totp code` printed **94287082**
(the RFC 6238 App B vector) from a vault the desktop sealed, pushed and shared; **(b) CLI →
op-log → DESKTOP:** the desktop unwrapped the **same key** and computed **94287082** from
the CLI's vault; an enrolled but unauthorized third device is **403** on read and on accept;
an unenrolled desktop gets a **clear NotEnrolled error rather than a panic**; and with the
server unreachable there is a clear **Unreachable** error **AND the offline flow still
generates codes**. ⚠️ **HONEST LIMITS:** the desktop stores its secrets as **0600 PLAINTEXT
files** (the documented native model) — **weaker at rest than the browser clients, which
seal everything** (ADR 0036); that asymmetry is now stated in the threat model. **No
zeroization.** The **inherited sharing limits are unchanged**: ⭐ **no out-of-band
verification of a published hybrid public key** (a hostile registry could substitute one),
revocation **cannot un-learn** an accepted vault key, **no key rotation, no
re-wrap-on-revoke**. The server side is still **dev-gated, plain HTTP on loopback,
UNAUDITED**, and the **GUI remains build-and-launch verified rather than visually verified**
here — all behaviour lives in the headless core the tests drive. ADR 0035 (desktop-support
addendum) + **NEW ADR 0037** (reuse the CLI library, don't duplicate the protocol); details
in the Phase 49 entry below.
Phase 48 took **vault
sharing to the BROWSER clients** — the webapp and the MV3 extension — so sharing now works
across **every client that talks to the server**, not just the CLI (desktop still does not).
⭐ **NO protocol, route, byte layout or Rust source changed:** every wasm export the browsers
need (`hybrid_x25519_public`, `hybrid_mlkem_encaps_key`, `hybrid_seal_to_container`,
`hybrid_open_container`) already existed from Phase 31, and `sigild` was untouched. The client
half is a NEW framework-free, dependency-free ESM module **`sigil-wasm/sharing.mjs`** (Node +
browser) — `generateHybridIdentity` / `hybridPublicIdentity`, `publishHybridKey` /
`fetchHybridKey`, `generateVaultKey` / `vaultKeyFingerprint`, `wrapVaultKey` /
`unwrapVaultKey` (rejects a recovered plaintext that is not exactly 32 bytes),
`putKeyEnvelope` / `getKeyEnvelope`, `shareVault` (fetch key → wrap → PUT envelope → grant
through the **EXISTING** `grantVaultAccess`, so authorization and key distribution cannot
drift), `acceptVault`, `explainSharingStatus` — **MIRRORED** from `cli/src/lib.rs` +
`sigild/internal/api/sharing.go`. It does **no crypto itself** (KEM/AEAD in the wasm,
signatures through `device-auth.mjs`) and every byte of entropy is `crypto.getRandomValues`.
⭐ **THE STORAGE DECISION (ADR 0036): nothing new is persisted in the clear.** Instead of a
new store, the EXISTING sealed device-identity container was bumped **v1→v2**, so each browser
client persists exactly **TWO** keys, both sealed `SIGILcli` containers: the TOTP vault
(`sigil.webapp.vault.v1` / `sigil.extension.vault.v1`) and the device identity
(`sigil.webapp.device.v1` / `sigil.extension.device.v1`) whose plaintext is now
`{version:2, device_id, seed, base_url, hybrid:{x25519_secret, mlkem_seed},
vault_keys:{vaultId: b64 32 bytes}}` — Ed25519 seed + hybrid SECRET identity + every accepted
vault key in ONE container under the vault password; **v1 still opens** (hybrid null, empty
keyring). Password + all decrypted secrets are memory-only, cleared on lock/forget/unload.
**Unlock now opens the device identity FIRST, tries the password, then falls back to each held
vault key**, so a shared vault re-opens after reload. BOTH clients got the **FULL** flow (show/
copy device id · publish hybrid key · convert to a shared vault under a fresh random 32-byte
key · share to a pasted recipient device id with read/write · accept), with 401/403/404
surfaced distinctly; `extension/build.sh` vendors `sharing.mjs` alongside the other helpers.
✅ **VERIFIED FIRST-HAND:** cargo fmt/clippy `-D warnings` clean, **26** wasm tests, **ALL
EIGHT** node tests PASS (roundtrip, interop, hybrid-interop, sync-interop, totp-interop,
migration-interop, device-auth-interop, **sharing-interop**); webapp typecheck/lint/build green
with **Playwright 8/8**; **extension 3/3**; marketing build green; **both `Cargo.lock`s
`getrandom`==0**; nothing changed under `sigild/`, `cli/`, `libsigil/` or `desktop/`.
⭐ **THE CROSS-CLIENT PROOF** (`sharing-interop.mjs`, live sigild + the REAL `sigil` binary,
both ways): JS sealed a vault under a random vault key, pushed, and shared a **1226-byte**
envelope → the real CLI accepted, unwrapped to the **SAME fingerprint**, pulled and printed
**94287082** at T=59 (the RFC 6238 vector); CLI → browser also produced **94287082**, and the
human password does **NOT** open that vault; an unauthorized third identity is **403** three
ways; the relayed envelope is byte-identical ciphertext with no key or seed in it; two wraps
of the same key differ; the server logged only fingerprints. ⚠️ **HONEST LIMITS (inherited
from Phase 46, unchanged):** ⭐ **NO out-of-band verification of a published hybrid public
key** — a hostile/compromised registry could substitute its own and intercept a share (the
recipient device id and key are trusted as served) — **the biggest gap**; JS `Uint8Array`s
holding secrets are **not zeroized**; revocation **cannot un-learn** a vault key a device
already accepted; **no rotation, no re-wrap-on-revoke**; converting a personal vault to a
shared one is a **ONE-WAY DOOR** in the UI; dev-gated, plain HTTP on loopback, **UNAUDITED**.
ADR 0035 (browser-support section) + **NEW ADR 0036** (the v2 container decision); details in
the Phase 48 entry below.
Phase 46 delivered **device-to-device VAULT SHARING** — the answer to "a grant says who the
server will talk to, but the server holds no key, so how does a SECOND device actually decrypt?".
⭐ **The key hierarchy:** the **human password seals a PERSONAL vault and is NEVER shared, never
wrapped, never sent**; a SHARED vault is sealed under a **random 32-byte VAULT KEY**; that key is
**wrapped per recipient** with the PQ-hybrid `hybrid_seal` path (X25519 + ML-KEM-768 → AEAD) into an
**opaque `SIGILhyb` envelope** (~1.2 KiB) that `sigild` **relays and cannot read**. ⭐ **NO CONTAINER
FORMAT CHANGE** — the `SIGILcli` container takes arbitrary password BYTES, so a random key drops in
and all four client surfaces keep reading it unchanged. **`sigild` gained four routes** behind the
SAME dev gate and the SAME v3 choke points (**no new auth path**): `PUT|GET
/v1/devices/{deviceID}/hybrid-key` (publish is **self-only** ⇒ 403 otherwise) and `PUT|GET
/v1/vaults/{vaultID}/keys/{deviceID}` (PUT needs **write** and CLAIMS an unowned vault; GET requires
the caller to **BE the addressee AND hold read** ⇒ otherwise **403, never 401/404**, returning the
**exact bytes** as octet-stream); caps 8 KiB / 16 KiB; migration **`0004_key_sharing.sql`** ⇒
**`sigild_schema_version` now 4**. The server's ONLY look at key material is a **LENGTH CHECK** (32 /
1184) — never a curve-point parse. **CLI:** `sigil device hybrid-publish` + `sigil vault
rekey|share|accept|list`, keys in a 0600 keyring, **never printed** (only a 16-hex SHA-256
fingerprint); `sigil totp … --vault-id <id>` is purely additive so existing invocations are
unchanged. ✅ **VERIFIED FIRST-HAND:** `go test ./...` green; `cargo test` (cli) green;
**`./cli/tests/e2e-sharing.sh` PASS** — two devices generate **94287082 at T=59 (the RFC 6238
vector)** from the same shared vault; the server's returned bytes are **byte-identical** to the
uploaded envelope, which contains **no seed** and never appears in the logs; device C is **403**
everywhere and a revoked B is **401** everywhere. ⚠️ **THE FRAMING THAT CHANGED: the hybrid KEM /
`hybrid_seal` are NO LONGER "standalone, not wired into any flow" — they are LOAD-BEARING and IN
SCOPE for the audit.** The hybrid **SIGNATURE is still used by nothing** (all request auth is
classical Ed25519). ⚠️ **HONEST LIMITS:** UNAUDITED; custom KEM-then-AEAD, **NOT RFC 9180 HPKE**;
the **SYSTEM is NOT "post-quantum secure"**; ⭐ **NO out-of-band verification of a published hybrid
key** (a hostile registry could substitute its own — the biggest gap); a revoked/compromised device
**keeps a key it already unwrapped**; **no rotation, no re-wrap-on-revoke, no forward secrecy, no
recovery**; one mailbox per (vault, recipient) so any writer can overwrite; no rate limiting; local
keys are 0600 plaintext files; only the CLI implements sharing. ADR 0035; details in the Phase 46
entry below.
Phase 45 gave `sigild` a **billing /
subscription layer**, because Sigil is a **paid** product and the payment story was an unwritten
assumption. A **provider-agnostic seam** (`sigild/internal/billing/`): one `billing.Provider`
interface (`Name`/`CreateCheckout`/`VerifyWebhook`) with **three adapters** — **Stripe**
(international), **Razorpay** + **Juspay** (India) — a normalized event vocabulary
(`checkout_completed`/`subscription_activated`/`subscription_renewed`/`subscription_canceled`/
`payment_failed`/`ignored`) and an explicit **state machine** (`none`/`trialing`/`active`/
`past_due`/`canceled` as a transition TABLE; `past_due` is still entitled — a declined card opens a
retry window, it is not a cutoff). ⚠️ **THE RULE THAT SHAPED THE WHOLE PHASE: NO VENDOR SDKs** —
every adapter is `net/http` + `crypto/hmac` + `crypto/subtle` + `encoding/json` + `net/url`, so
**`sigild/go.mod` still has EXACTLY ONE direct require (`pgx`)** and the security-critical code is
~30 readable lines per provider instead of an opaque library call. **HOSTED CHECKOUT ONLY** ⇒ **no
card data ever enters the process** (no struct field, log line, metric or column could hold a
PAN/CVV/expiry — PCI scope SAQ-A, **not** an attestation). **Three routes, TWO auths, deliberately:**
`POST /v1/billing/checkout` + `GET /v1/billing/subscription` reuse the **device-auth v3** choke
point and the **subject is the AUTHENTICATED DEVICE ID, never a body field**;
`POST /v1/billing/webhook/{provider}` is authenticated **ONLY by the provider's own signature over
the RAW body** (a provider has no device key) — verified over the exact wire bytes **before** the
JSON is parsed, constant-time, every failure a coarse 401. **Idempotency** is keyed on
`(provider, event_id)` and **fused with the state change into ONE atomic operation** (mutex in mem;
one tx with `ON CONFLICT DO NOTHING` + `SELECT … FOR UPDATE` in Postgres), so a **duplicate delivery
is a no-op that still answers 200** — as are `ignored`/`stale`/`illegal`/`unresolved`, because a
non-2xx puts a provider into retry/backoff. New migration **`0003_billing.sql`**
(`sigil_subscriptions`, `sigil_billing_processed_events`) ⇒ **`sigild_schema_version` now 3**;
Postgres **shares the op-log's existing `pgxpool`** (no second pool, no new dep). Default is the
deliberate **501** (needs `SIGILD_ENABLE_DEV_OPS` **and** `SIGILD_DEVICE_AUTH` **and**
`SIGILD_BILLING_PROVIDERS`). **VERIFIED FIRST-HAND:** `go test ./...` green across `sigild`
(billing, api, store, cmd/server), including forged / wrong-secret / tampered-body / stale-timestamp
webhooks all rejected `401`, the same event delivered twice → `accepted` then `duplicate` with ONE
state change, a re-encoded-but-equivalent JSON body rejected (proving raw-byte verification), the
`501`-by-default posture, and no secret/subject/body-marker in `/metrics` or the audit log. ⚠️
**HONEST LIMITS — do not paper over:** **nothing has EVER been run against a live provider account**
(every test drives a local `httptest` server with fake credentials); the **Juspay** adapter is
explicitly **UNVERIFIED-AGAINST-LIVE-DASHBOARD** (header names, signed message, endpoint path,
event vocabulary) and Razorpay's surrounding details are MEDIUM confidence; **no account model** (a
subscription keys off the enrolled DEVICE); recurring *subscription creation* is unimplemented for
the India adapters; no entitlement enforcement, no fraud/chargeback/refund/proration/tax/dunning;
**no PCI attestation**; the in-memory store is non-durable (a redelivery across a restart could
double-apply); no rate limit on the webhook route; and **billing living inside `sigild` is
PROVISIONAL** — a scaffold placement, not a final topology. ADR 0034; details in the Phase 45 entry
below.
Phase 44 finished the **auth story across the CLI + browser clients**: the webapp and
the MV3 extension can now **enroll and authenticate as real devices** against `sigild`'s
multi-device model (**contract v3**, ADR 0031) — previously only the `sigil` CLI could. Three
thin `#[wasm_bindgen]` shells over `sigil-core`'s Ed25519 — **`ed25519_public_key(seed)`**,
**`ed25519_sign(seed, message)`**, **`ed25519_verify(public_key, message, signature)`** — give a
browser real signing; the seed is a **CALLER argument** (JS `crypto.getRandomValues`) and Ed25519
is deterministic, so **both `libsigil/Cargo.lock` and `sigil-wasm/Cargo.lock` are still
`getrandom`==0** (re-confirmed) and Rust tests are now **26** incl. an **RFC 8032 KAT**. NEW
**`sigil-wasm/device-auth.mjs`** (framework-free, dependency-free, Node + browser) is the CLIENT
half: `generateDeviceSeed`/`devicePublicKey`, `enrollDevice`, `signedFetch`/`makeSignedFetch`,
`pushContainerAuthed`/`pullContainersAuthed`, `grantVaultAccess`/`listVaultGrants`,
`revokeSelf`/`revokeDeviceAdmin`/`listDevices`, `sealDeviceIdentity`/`openDeviceIdentity`,
`DeviceAuthError`+`explainAuthStatus` — **ALL signing is `wasm.ed25519_sign`; there is NO JS-side
signing**. ⚠️ The canonical layout (`canonicalV3Message`/`canonicalEnrollMessage`/
`enrollTokenHash`) is **MIRRORED from `sigild/internal/api/deviceauth.go` + `cli/src/lib.rs` and
now lives in THREE implementations that MUST stay byte-identical** — drift does not fail loudly,
it silently 401s. `sync.mjs` gained **ONE optional `opts.fetch`** (+ additive `err.status`), so
the unauthenticated path is behaviourally identical (why the older interop tests still pass).
**SECRETS (ADR 0033): the 32-byte device seed is NEVER stored in plaintext** — it is sealed into
a **SECOND `SIGILcli` container under the SAME vault password** (in the wasm) and only that is
persisted (`localStorage` `sigil.webapp.device.v1`, `chrome.storage.local`
`sigil.extension.device.v1`; sealed plaintext `{version, device_id, seed, base_url}`), a separate
container **deliberately** so the CLI-mirrored `TotpVault` schema stays byte-compatible; the
decrypted seed is **memory-only while unlocked** (lock/reload/forget drop it; forget deletes the
sealed identity), and the enrollment token is an in-memory bearer secret cleared after use. ⚠️
**`extension/manifest.json` gained `host_permissions ["http://127.0.0.1/*",
"http://localhost/*"]`** — MV3 pages cannot fetch cross-origin without one; deliberately
**LOOPBACK-ONLY** so the build cannot reach a remote server (`permissions` is still `["storage"]`).
**VERIFIED FIRST-HAND:** fmt clean, clippy `-D warnings` clean, 26 Rust tests; **ALL SEVEN Node
tests pass** (roundtrip, interop, hybrid-interop, sync-interop, totp-interop, migration-interop,
device-auth-interop); webapp typecheck/lint/build green + **Playwright 8/8**; **extension 3/3**
(real unpacked extension in chromium); marketing still green and Rust-free; **nothing changed
under `sigild/`, `cli/`, `libsigil/` or `desktop/`**. The device-auth interop test boots a **REAL
`sigild` with `SIGILD_DEVICE_AUTH=1`** and proves: unsigned → 401; A enrolls; identity round-trips
the sealed container with **no plaintext seed at rest**; A pushes/claims/pulls/opens byte-verbatim;
B enrolled but **403** on A's vault; after a read grant B pulls yet is still 403 on write; an admin
revoke makes B **401** while A is unaffected; tampered body + stale timestamp both 401; a spent
enrollment token 401. Honest: **the enrollment UI is NOT Playwright-covered** (protocol proven in
Node; UI suites still pass), still the **DEV op-log over plain HTTP, no TLS, loopback only**, the
server model is **dev-gated + UNAUDITED** with **trust-on-first-write** ownership and **no account
model / session issuance / key rotation / enrollment rate limiting**, and the **native `desktop/`
client still has no sync or enrollment**. ADR 0033 (+ a browser-client note appended to ADR 0031);
details in the Phase 44 entry below.
Phase 43 opened the
**NATIVE client column**: a new top-level **`desktop/`** —
a **Tauri v2 desktop authenticator** whose Rust backend links libsigil **NATIVELY**. That is
the whole point: `web/apps/webapp` and `extension/` both run the core as **WebAssembly**, so
a third browser-shaped client would have proved nothing; **there is no wasm, `wasm-bindgen` or
`wasm-pack` anywhere under `desktop/`** (grepped and confirmed). `sigil-core` still reads **no
clock and no RNG**, so the native app supplies both — **entropy** through `sigil-cli`'s
`getrandom` seal path, the **clock** via `std::time` passed **into** `sigil_core` as a `u64`.
**Two crates:** **`sigil-desktop-core`** (`desktop/core`) holds **ALL** the authenticator logic
**headless** and is `#![forbid(unsafe_code)]`; **`sigil-desktop`** (`desktop/src-tauri`) is a
thin Tauri shell — a `Mutex`-held `VaultSession` and **ten `#[tauri::command]`s**; `desktop/ui`
is framework-free HTML/CSS/JS (**no npm, no bundler, no CDN**). **ZERO crypto/format
reimplementation**: the `SIGILcli` container, the `TotpVault`/`TotpEntry` schema,
`TotpEntry::code_at`, `base32_decode`, the `otpauth://` parse/build and the Google
Authenticator migration codec are all **re-used from `cli/` by path dependency** (no hand-rolled
hmac/sha1 anywhere; **nothing under `cli/` was edited**). So the vault is
**`$HOME/.sigil/totp-vault.sigil` — byte-for-byte the CLI's default: the desktop app and the CLI
literally share ONE vault file** (dir 0700, file 0600, temp-file+rename so an interrupted save
can't truncate a good vault); **only the sealed container is persisted**, the password is
memory-only and **best-effort** zeroed on `Drop`. **Trust boundary:** the webview holds no key
material and does no crypto, and the Tauri capability grants **`core:default` ONLY** (no
fs/shell/http/dialog plugin), so the frontend reaches disk only through the explicit commands;
export commands return the secrets-in-the-clear warning **together with** the payload. It is
its **OWN cargo workspace with its own `desktop/Cargo.lock`, deliberately outside `libsigil`**
(like `cli/` and `sigil-wasm/`) — **`libsigil/Cargo.lock` `getrandom` is still 0**. **VERIFIED
FIRST-HAND:** fmt clean, clippy `-D warnings` zero, **11 unit + 1 integration test pass**,
release build → **~8.6 MB native binary** that launches and keeps its event loop alive while
printing the pre-audit banner; the **RFC 6238 App B KAT** (`T=59` → `94287082`/`287082`) was
**independently reproduced with a from-scratch Python HMAC-SHA-1**; and **THE INTEROP PROOF**
(`desktop/core/tests/cli_interop.rs`) builds the **REAL `sigil` binary** and drives it as a
subprocess against **ONE shared vault file BOTH ways** — desktop-created vault →
`sigil totp list`/`code`/`export` agree byte-for-byte; `sigil totp add` → the desktop reopens
the same file and reproduces the CLI's code/issuer/algorithm/digits; and a desktop-generated
migration URI imports via `sigil totp import` (temp dirs, never the real user vault). Honest:
the **GUI is build-and-launch verified but NOT visually verified** (screencapture denied here →
no screenshot proof, which is exactly why all behaviour lives in the headless lib), **`tauri
build` / the `.app` bundler was NOT run** (the applicable build is `cargo build --release`;
**unsigned, unnotarized, undistributed**), the interop test's exact cross-process equality uses
**`period = u32::MAX`** to pin the counter at 0 until ~2106 — a **deliberate test artifice, not
product behaviour** (an ordinary 30 s account is also checked with a bounded retry), the
password zeroing is **best-effort**, it is still **pre-audit / UNAUDITED (do not store real 2FA
secrets)**, and this is **one** native surface — the other native platforms, **mobile in
particular, remain unbuilt**. ADR 0032; details in the Phase 43 entry below.
Phase 42 taught the **`sigil` CLI to
speak the server's multi-device auth contract v3** — the CLIENT half of ADR 0031, so a real
client now exercises the device model end to end (**no new ADR**; a "client support" note was
appended to ADR 0031 instead). Four new subcommands — **`sigil device enroll --token <t>
[--label <name>] [--key <file>] [--server <url>] [--reuse-key]`**, **`device list
--admin-token <t>`**, **`device revoke <deviceID> [--admin-token <t>] [--key <file>]`**,
**`device grant <deviceID> --vault <id> --permission read|write [--key <file>]`** — plus
env vars **`SIGIL_ENROLL_TOKEN`/`SIGIL_ADMIN_TOKEN`/`SIGIL_DEVICE_ID`** (flags win) beside the
unchanged `SIGIL_SERVER`/`SIGIL_DEVICE_KEY`. The **EXISTING key file was EXTENDED**, not
replaced: an OPTIONAL `device_id` (serde `default` + `skip_serializing_if`) means an old key
file parses unchanged and still signs v2. **Contract selection is additive and driven by the
identity**: **no key ⇒ unsigned** (byte-identical legacy path) · **identity WITHOUT
`device_id` ⇒ v2** · **identity WITH `device_id` ⇒ v3** (+ `X-Sigil-Device`), so `push`/`pull`
sign v3 automatically once their key is enrolled; `SIGIL_DEVICE_ID` forces v3 on an older key
file. **VERIFIED FIRST-HAND against a live sigild:** enroll A → 0600 identity, no seed on
stdout; **reusing that enrollment token failed (single-use)**; `sigil push --vault demo`
succeeded at **seq 1** and **claimed** the vault (trust-on-first-write); pull + open
round-tripped byte-identical plaintext; device B enrolled and **B pulling A's vault before a
grant → 403**; `device grant <B> --vault demo --permission read` → B pulled fine; **B WRITING
with a read-only grant → 403** (the lattice is enforced); after an admin **revoke** B got
**401** while A kept working; an **UNSIGNED push → 401**; and the server log contained
**neither the enrollment token nor the admin token**. Static green (fmt, clippy `-D warnings`,
64 lib + 3 integration tests) and the **legacy paths are untouched** — `sigil-wasm`
`sync-interop.mjs` + `totp-interop.mjs` still PASS against an UNAUTHENTICATED dev sigild, all
changes are confined to `cli/`, and `libsigil` `getrandom` is still **0**. Honest: still the
**DEV op-log over PLAIN HTTP (no TLS)**, server model dev-gated + **UNAUDITED**, ownership is
trust-on-first-write, enrollment tokens are single-ATTEMPT, and there is still no account
model, no session issuance, no key rotation, and a per-process replay cache. Details in the
Phase 42 entry below.
Phase 41 gave **`sigild` a REAL
multi-device auth model** — the first time the server can answer *which device is this,
and may it touch this vault*. **Op-log auth contract v3**, opt-in via **`SIGILD_DEVICE_AUTH`**
(requires `SIGILD_ENABLE_DEV_OPS`; **mutually exclusive** with the legacy single-key
`SIGILD_OPLOG_PUBKEY` — the server **refuses to boot**, rc=1, if both are set), replaces
one static key with a **device registry** (one Ed25519 key per device, server-assigned
`dev_…` IDs), **enrollment** requiring an operator token (`SIGILD_ENROLL_TOKENS`, held only
as SHA-256 digests, single-use, optional `SIGILD_ENROLL_TOKEN_TTL`) **PLUS proof of
possession** on a separate domain, **per-vault grants** (read/write, write implies read)
with **trust-on-first-write ownership**, and **revocation** checked *before* signature
verification. Five new dev-gated routes (`POST /v1/devices/enroll`, `GET /v1/devices`,
`POST /v1/devices/{deviceID}/revoke`, `POST|GET /v1/vaults/{vaultID}/grants`), a new
`X-Sigil-Device` header, `401` vs `403` now distinct with **no auth oracle** (coarse body;
typed reason only to audit + metrics), and a new migration **`0002_devices.sql`**
(`sigild_schema_version` → **2**) that adds **AUTH METADATA ONLY** — the opaque blob, its
hash chain and the zero-knowledge boundary are untouched, and `pgx` is still the only Go
dependency. **VERIFIED FIRST-HAND: 24/24 adversarial checks passed** with an independently
written client (forged/wrong-key/wrong-token/tampered/stale/corrupted/v2-domain/replayed →
401; cross-device vault access → **403 not 401**; admin revoke → 200 then the revoked
device 401 while device A stays 200; wrong admin token 401), **default posture is all ops
AND all device routes `501`** with `/metrics` still 200, gofmt/vet clean, `go test -race
./...` all ok, and the **cross-component regression is green** (sigil-wasm sync-interop
3 proofs + opaque check; totp-interop cross-client RFC vector) so the CLI push/pull and
wasm sync are unaffected. Honest: **dev-gated, pre-audit, UNAUDITED**, TOFU is a dev
ownership model not an account model, a token is single-*attempt*, the replay cache is
per-process, revoking a vault's owner **orphans** it, the in-memory registry is
non-durable, and there is no session/JWT, key rotation, or enrollment rate limiting.
ADR 0031; details in the Phase 41 entry below.
Phase 40 opened a **NEW client
surface**: `extension/` is **no longer reserved** — it is a real **Manifest V3 browser
extension** whose **popup is a wasm-powered authenticator** (a multi-account **encrypted
TOTP vault**), so **a SECOND real product client now exists** beside `web/apps/webapp`
(third over the core counting the demo `cli/`). It **adds no crypto and no vault/migration
logic of its own**: `extension/build.sh` runs the repo-root `sigil-wasm/build-wasm.sh` and
**vendors** the wasm bindings + **verbatim copies** of the proven `totp-vault.mjs` /
`totp-migration.mjs` into a gitignored `extension/vendor/`; `src/popup/popup.js` is UI glue
+ storage. It seals to the **SAME `SIGILcli` container** as the CLI and the webapp (vaults
stay **cross-client interoperable** — no third at-rest format) and persists **ONLY the
sealed container** in `chrome.storage.local` (`sigil.extension.vault.v1`) with the
**password in memory only** (closing the popup re-locks) → setup / locked / unlocked.
Add by form / `otpauth://` / **Google Authenticator migration import**, export back out,
codes + countdowns **computed in the wasm**. Deliberately small surface:
`"permissions": ["storage"]` and nothing else, **no background worker / content script /
options page**, MV3 CSP widened by exactly one keyword (`'wasm-unsafe-eval'`). **VERIFIED
GREEN headlessly** — `extension/tests/extension.spec.mjs` loads the **REAL unpacked
extension** in a full Chromium and the wasm renders the RFC 6238 vector **`287082`** at the
pinned `?t=59` in the actual popup, storage holds **only** the sealed container, and
reload→lock→unlock restores it (3/3 pass). Honest: **dev / UNAUDITED / loaded unpacked /
published to NO store**, **no sync** (never talks to `sigild`), generate-only, none of the
originally reserved ambitions (phishing protection, passkey provider, content scripts), and
**not wired into CI**. ADR 0030; details in the Phase 40 entry below.
Phase 39 hardened the
`web/apps/webapp` authenticator toward shippable: it is now an **installable PWA that
works fully OFFLINE** — a web **manifest** (`app/manifest.ts`) + a hand-rolled **service
worker** (`public/sw.js`, registered by `app/register-sw.tsx`) that precaches the app
shell and runtime-caches JS/CSS/`.wasm` **cache-first**, so after the first online load
codes still **generate with no network** in the wasm. The SW caches **only static
assets** (the sealed vault stays in `localStorage`; cross-origin sync untouched → the
zero-knowledge boundary is intact). It is also **accessible** (ARIA/keyboard/focus/
live-region, **axe-clean**). A **separate `webapp` CI job** (`.github/workflows/web.yml`)
builds `@sigil/wasm` with a Rust + wasm-pack toolchain and runs the Playwright suite;
the marketing `build` job stays Rust-free, and `web/packages/sigil-wasm/build.sh` was made
**cross-platform** for the Linux runner. Proven GREEN by headless Playwright:
`tests/offline.spec.ts` (offline reload still computes the TOTP in cached wasm) +
`tests/a11y.spec.ts` (`@axe-core/playwright`, no serious/critical) + the Phase 38
`tests/wasm.spec.ts` still green; marketing still green. Honest: the `webapp` CI job is
by-eye / YAML-parse-only locally like the repo's other CI mirrors — not run on real
GitHub Actions from here; still dev / no-index / UNAUDITED, **not deployed**. ADR 0029;
details in the Phase 39 entry below.
Phase 38 built the
`web/apps/webapp` page from a single-code TOTP *view* into a **real (dev) authenticator
UI** — a **multi-account encrypted TOTP vault** (`app/authenticator.tsx`) over the same
`@sigil/wasm` loader. Accounts **seal into a `SIGILcli` container** (same sealed format
as the CLI / browser vault, cross-client-interoperable) and **only the sealed container
is persisted** in `localStorage` (`sigil.webapp.vault.v1`); the **password lives only in
memory** and unlocks by opening the container, so the app boots setup / locked /
unlocked. Add by form / `otpauth://` / **Google Authenticator `otpauth-migration://`
import**, **export** back out, live **codes + countdown rings computed in the wasm**;
entropy via `crypto.getRandomValues`; optional dev Sync of the sealed container to a
localhost op-log. Proven GREEN by headless Playwright feature smokes (add-account ==
RFC vector `287082`; GA migration import; lock/reload/unlock persistence) with marketing
still green. ADR 0028 (persistence + unlock model); details in the Phase 38 entry below.
Phase 37 turned the
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

---

## 2026-07-16 — Phase 38 (real authenticator UI: `web/apps/webapp` multi-account encrypted TOTP vault + password unlock + sealed-container persistence)

### What & why
- Phase 37 shipped the webapp as a **live TOTP view** of one hard-coded RFC seed — stateless,
  single-account, nothing persisted. Phase 38 turns that page into a **real (dev) authenticator
  UI**: a **multi-account encrypted TOTP vault** that survives reloads. A 2FA app that forgets
  every account on refresh is useless, so persistence was the gating gap. No new crypto, no new
  format — it reuses the proven `SIGILcli` sealed vault + `TotpVault` schema + the wasm-computed
  codes from Phases 33–36. Still dev / no-index / UNAUDITED; **not deployed**.

### How (design decisions → ADR 0028)
- **New `app/authenticator.tsx` (`"use client"`).** Dynamic-imports `@sigil/wasm` (browser-only,
  no SSR crypto). Three phases decided purely by whether the `localStorage` key exists —
  **setup** (create vault + password), **locked** (prompt for password), **unlocked** (vault open
  in memory): `page.tsx` now renders `<Authenticator/>` with the old `totp-demo.tsx` demoted to a
  collapsed "wasm self-check" `<details>`.
- **Persist ONLY the sealed container.** Single `localStorage` key `sigil.webapp.vault.v1` holds
  the base64 of the `SIGILcli`-sealed `TotpVault` — the **plaintext vault and the password are
  never written to disk**. Every mutation (`withVault`) clones → mutates → **re-seals with a fresh
  salt+nonce** (`crypto.getRandomValues`) → rewrites that one key; a rejected mutation (duplicate
  label) throws BEFORE any persist, so the stored container is never corrupted.
- **Password in memory only.** Held in a ref, cleared on **Lock** (and gone on reload / tab
  close). **Unlock = open the container**; wrong password fails the AEAD → "wrong password or
  tampered vault". Argon2id params are OWASP-interactive-ish (m=19456,t=2,p=1); the container is
  self-describing so open needs none → stays CLI-interoperable.
- **Add / import / export / sync.** Add by form (label/issuer/base32 secret/algorithm/digits/
  period, with a local base32 pre-validate for a clear error), by `otpauth://` paste, or by
  **Google Authenticator `otpauth-migration://` import** (duplicates skipped, reports
  imported/skipped). **Export** reveals `otpauth://` URIs or one combined migration URI behind a
  loud secrets-in-the-clear warning. Live **codes + SVG countdown rings computed in the wasm**
  (`codeForEntry`; wasm computes every code, never JS). An optional **Sync (dev)** panel push/
  pulls the **sealed** container to a localhost sigild op-log (opaque bytes; no TLS/auth).
- **Forget vault** escape hatch on the locked screen (confirmed) — the only way out of a vault
  whose password is lost (a lost password is unrecoverable by design).

### Verified GREEN (gated first-hand)
- **Headless Playwright feature smokes PASS** (`web/apps/webapp/tests/wasm.spec.ts`, chromium,
  clock pinned via `?t=`): (1) **add-account** — creating a vault, adding the RFC 6238 base32 seed
  as an account, and reading the code reproduces the vector **`287082`** through the REAL
  add-account → in-memory vault → wasm path (not the demo seed); (2) **GA import** — the canonical
  golden `otpauth-migration://` URI imports as `Example:alice@google.com` (Imported 1, count 1);
  (3) **persistence** — add account → **reload** comes back LOCKED (plaintext+password gone, only
  the sealed container survived) → **unlock** restores the account and its live code. The two
  original wasm-render smokes still pass.
- **Marketing still green + CI unchanged** — root `web` scripts still filter marketing only, so
  marketing typecheck/lint/build and CI stay Rust-free. `libsigil/core`, `cli/`, `sigild/`, and
  the repo-root `sigil-wasm` crate are untouched; `getrandom` count stays 0.

### Docs (this pass)
- `docs/architecture.md` — the `web/apps/webapp` component now describes the full authenticator
  UI (multi-account encrypted TOTP vault, seals to `SIGILcli`, persists sealed-only in
  localStorage with an in-memory password unlock, add/import/export, codes in wasm); diagram
  footer + the "no clients" gap updated to say the browser app is now a real authenticator UI
  (still dev/no-index/UNAUDITED, not the product key-management model).
- `CLAUDE.md` — repository map gained a `web/apps/webapp` entry reflecting the authenticator UI
  (vault, add/import/export, password unlock + localStorage persistence of the sealed container,
  live codes); build/test commands unchanged.
- `README.md` — the webapp bullet now says it is a working (dev, UNAUDITED) authenticator with an
  encrypted multi-account TOTP vault + import/export + password unlock; layout line updated.
- `docs/decisions/0028-webapp-vault-persistence-and-unlock.md` — new Nygard ADR (context: a real
  authenticator needs to persist accounts across reloads with no backend; decision: persist ONLY
  the `SIGILcli`-sealed container in localStorage, password in memory, unlock by opening it, reuse
  the shared sealed vault format, entropy via `crypto.getRandomValues`; consequences: lost password
  = unrecoverable by design, localStorage is not hardened → dev only, no account/device/sync-auth
  model yet, cross-client-interoperable for free, still UNAUDITED). Indexed in
  `docs/decisions/README.md` (Accepted, 2026-07).
- `journal.md` — this entry + RESUME ANCHOR bumped to through Phase 38.

### ➡️ Still open (honest)
- **Dev / no-index / UNAUDITED, NOT deployed.** A real authenticator UI, but of the same unaudited
  building blocks and **not** the product's account / device / key-management model. No real 2FA
  secrets.
- **A lost password = an unrecoverable local vault, by design.** No backend, no recovery key, no
  escrow — only the password opens the vault; "Forget vault" is the only way out.
- **`localStorage` is not a hardened secret store.** We persist only the sealed container (never
  plaintext / never the password), but this stays a dev build; a production client wants a stronger
  store + per-device keys.
- **Local, single-browser persistence only.** The dev Sync panel round-trips the sealed container
  through the opaque op-log, but that is dev / localhost / plain-HTTP / no-auth — not multi-device
  or enrollment.

---

## 2026-07-16 — Phase 39 (webapp toward shippable: installable OFFLINE PWA + accessibility + a webapp CI job)

### What & why
- Phase 38 made the webapp a real (dev) authenticator with a persisted, sealed TOTP vault, but two
  gaps remained before it could be called shippable-shaped: (1) **an authenticator must work
  offline** — you reach for 2FA mid-login on a flaky/absent network, and a plain web page still
  fails to *load* offline even though it computes codes locally; (2) **shippable means accessible +
  under CI** — but the webapp is NOT Rust-free (it compiles `sigil-core` to wasm), so it can't join
  the Rust-free marketing CI job, and its `build.sh` was hard-coded to this macOS box. Phase 39
  closes all three with **no new runtime dependency** and **no posture change** (still dev /
  no-index / UNAUDITED, not deployed).

### How (design decisions → ADR 0029)
- **Hand-rolled service worker, not a PWA framework.** `public/sw.js` (registered by
  `app/register-sw.tsx`) precaches the app shell (`"/"`) on install and serves **same-origin GET**
  **cache-first**, writing every successful HTML/JS/CSS/`.wasm`/icon response into one named cache
  at runtime; navigations are network-first with a cached-shell fallback. Chosen over Workbox /
  `next-pwa` to keep the caching policy legible and add zero deps.
- **Web manifest** (`app/manifest.ts`, Next's typed `MetadataRoute.Manifest`) → installable
  (name/icons/`display: standalone`). A manifest never makes a site crawlable, so robots.ts +
  `X-Robots-Tag` + layout metadata keep the no-index posture unchanged.
- **Static assets only — never secrets.** The SW caches only public static assets; it never caches
  the sealed vault (stays in `localStorage`) and never touches cross-origin requests (the dev sync
  to localhost sigild is left alone) → zero-knowledge boundary intact.
- **Accessibility.** Labelled landmarks/controls, keyboard-operable, visible focus, code updates
  announced via a live region.
- **Separate `webapp` CI job.** `.github/workflows/web.yml` keeps the Rust-free `build` job
  (marketing) and adds a second `webapp` job that installs a Rust toolchain +
  `wasm-bindgen-cli`/`wasm-pack`, builds `@sigil/wasm`, then runs webapp typecheck/lint/build + the
  Playwright suite (incl. offline + axe). The two jobs are isolated so marketing stays Rust-free.
- **`build.sh` made OS-agnostic.** `web/packages/sigil-wasm/build.sh` now prepends only
  toolchain dirs that exist (macOS rustup path, `~/.cargo/bin`, Homebrew) and discovers
  `wasm-bindgen` from PATH first (falling back to a wasm-pack cache under either the macOS or Linux
  cache dir), so the same script builds on this laptop and on a Linux CI runner.

### Verified GREEN (gated first-hand)
- **Headless Playwright PASS** (chromium): `tests/offline.spec.ts` — first online load registers the
  SW and computes the code, one controlled reload populates the runtime cache, then going **offline**
  and reloading still renders the shell AND still computes the RFC 6238 code **`287082`** in the
  cached wasm (proving codes generate with no network). `tests/a11y.spec.ts` — `@axe-core/playwright`
  on the setup and unlocked views reports **no serious/critical** violations. The Phase 38
  `tests/wasm.spec.ts` feature smokes (add-account == RFC vector, GA import, lock/reload/unlock
  persistence) still pass.
- **Marketing still green + its CI job stays Rust-free** — the root `web` scripts still filter to
  marketing only. `libsigil/core`, `cli/`, `sigild/`, and the repo-root `sigil-wasm` crate are
  untouched; `getrandom` count stays 0.

### Docs (this pass)
- `docs/architecture.md` — the `web/apps/webapp` component + diagram footer now note it is an
  installable offline PWA (manifest + service worker; static assets cached, sealed vault stays in
  localStorage), accessible/axe-clean, with a separate Rust+wasm-pack `webapp` CI job (marketing
  stays Rust-free); the Playwright proofs (`offline.spec.ts`, `a11y.spec.ts`) cited.
- `docs/deployment.md` — the stubbed-clients bullet now records the separate `webapp` CI job
  (Rust + wasm-pack + Playwright), honestly flagged as by-eye / YAML-parse-only locally and NOT run
  on real GitHub Actions from here (like the other CI mirrors); webapp still dev-only / not deployed.
- `CLAUDE.md` — the `web/apps/webapp` map entry updated (installable offline PWA + accessible), plus
  the new `webapp` CI job alongside the Rust-free marketing job and the cross-platform `build.sh`.
- `README.md` — the webapp bullet now says installable / offline-capable / accessible (dev,
  UNAUDITED) authenticator PWA.
- `docs/decisions/0029-webapp-pwa-offline-a11y-and-ci.md` — new Nygard ADR (context: an
  authenticator must work offline, and shippable needs a11y + CI; decision: hand-rolled service
  worker with runtime cache-first + app-shell precache rather than a PWA framework dep, a web
  manifest, axe-in-Playwright, a separate Rust+wasm-pack CI job, OS-agnostic `build.sh`;
  consequences: SW caches static assets only — never secrets, offline works after first load, the
  CI job is by-eye/unrun-on-real-CI, still dev/UNAUDITED/not-deployed). Indexed in
  `docs/decisions/README.md` (Accepted, 2026-07).
- `journal.md` — this entry + RESUME ANCHOR bumped to through Phase 39.

### ➡️ Still open (honest)
- **Dev / no-index / UNAUDITED, NOT deployed.** PWA installability + offline do not change posture;
  no host target, no domain. Not the product's final client / key-management / sync model.
- **The `webapp` CI job is by-eye / unrun-on-real-CI** — YAML validated + mirrors the known-green
  local commands, but not executed on real GitHub Actions from this machine (like every other CI
  mirror in this repo). It is also heavier/slower than marketing (Rust + wasm-pack + a browser).
- **Manual cache versioning.** `sw.js` invalidates on a manual `CACHE` bump; no automatic
  asset-revision pipeline yet.

---

## 2026-07-26 — Phase 40 (NEW client surface: MV3 browser extension — a wasm-powered popup authenticator)

### What & why
- `extension/` had been a **reserved directory** since the sprint, and its README named the exact
  blocker: it "depends on `libsigil-wasm`, not yet available". That blocker is **gone** — the
  repo-root `sigil-wasm` crate builds a browser wasm package (ADR 0019), reads/writes the shared
  `SIGILcli` container (ADR 0020), computes TOTP (ADR 0024) and does Google Authenticator
  import/export (ADR 0026), all behind framework-free ESM helpers that already have Node interop
  tests against the real CLI. So the directory was finally spendable.
- **Why now, beyond "we can":** one browser client cannot prove the shared-vault architecture
  *generalizes* — with a sample size of one, accidental coupling to Next.js, to `localStorage`, or
  to a bundler is invisible. A **second real client on a different runtime** (an MV3 extension page:
  different storage API, stricter CSP, **no bundler at all**) is the cheapest way to find that
  coupling or show there is none. And a popup one click from the login form is the shape the product
  actually takes.
- Constraint for the whole phase: change **nothing** under `libsigil/`, `cli/`, `sigild/`, or the
  repo-root `sigil-wasm/` — and add **no cryptography**.

### How (design decisions → ADR 0030)
- **Vendor, don't reimplement.** `extension/build.sh` is the ONLY build step (no bundler — the popup
  is plain ESM). It runs the repo-root `sigil-wasm/build-wasm.sh` (single source of truth for the
  wasm build: wasm-pack 0.13.1 against the `wasm-bindgen = "=0.2.100"` pin, `--target web`) and
  copies into a **gitignored `extension/vendor/`**: `sigil_wasm.js` + `sigil_wasm_bg.wasm` (+`.d.ts`)
  and **verbatim** copies of `totp-vault.mjs` + `totp-migration.mjs`, plus a `BUILD-INFO.txt`
  provenance stamp so a stale `vendor/` is obvious. `src/popup/popup.js` therefore contains **no
  crypto and no vault/migration logic** — a THIRD copy of that logic is exactly what we refused to
  write. `.gitignore` gained `extension/{vendor,test-results,playwright-report}/`.
- **Same `SIGILcli` vault → vaults stay cross-client.** The same mirrored `TotpVault` JSON sealed
  into the same Argon2id → XChaCha20-Poly1305 container the CLI and webapp use. No new at-rest
  format was invented for the extension; the container is self-describing, so a vault sealed in the
  popup opens in `sigil` and in the webapp.
- **Sealed-only persistence + in-memory password** (mirrors the webapp, ADR 0028).
  `chrome.storage.local` holds **ONLY** the sealed container (base64) under
  `sigil.extension.vault.v1`; the plaintext vault and the password are **never** written; the
  password is a module-local that dies with the popup, so closing it re-locks and a fresh open boots
  setup / locked / unlocked. Salt + nonce from `crypto.getRandomValues` (core still draws no entropy,
  reads no clock — ADR 0007).
- **Minimal MV3 surface.** `"permissions": ["storage"]` and **nothing else** — no host permissions,
  no `tabs`, no `clipboardWrite` (copy uses the in-page clipboard API with a `document.execCommand`
  fallback). **No background service worker, no content script, no options page** — the MVP does not
  need them, so they are not declared. CSP widened by exactly one keyword:
  `script-src 'self' 'wasm-unsafe-eval'; object-src 'self'` (the minimum to instantiate the core).
  A pinned **PUBLIC** manifest `key` fixes the unpacked extension ID (no private half exists in this
  repo; it is not a signing key) so a headless test can address `chrome-extension://<id>/…` without
  a background worker to read the ID from.
- **Dependency-light:** exactly one devDependency (`@playwright/test`) — no UI framework, no
  bundler, no crypto/protobuf/PWA library. It is a **standalone pnpm project**, not part of the
  `web/` workspace.
- **TEST HOOK:** `popup.html?t=<unix-seconds>` pins the clock and stops the 1 s tick so an exact RFC
  6238 vector is assertable. It changes the displayed time only — never the vault.

### ✅ Verified GREEN (gated first-hand)
- **`corepack pnpm -C extension test` → 3 passed** (`tests/extension.spec.mjs`). Nothing is stubbed:
  the spec launches a **real Chromium with the unpacked extension loaded**
  (`chromium.launchPersistentContext(…, { channel: "chromium", headless: true,
  args: ["--disable-extensions-except=…","--load-extension=…"] })` — the headless *shell* cannot
  load extensions, the full browser in the new headless mode can) and drives
  `chrome-extension://<pinned-id>/src/popup/popup.html?t=59`, so the **real MV3 CSP**, the **real
  `chrome.storage.local`** and the **real wasm** are exercised. It asserts:
  1. the wasm instantiates **inside the extension page** and the UNAUDITED banner shows;
  2. creating a vault then adding the PUBLIC RFC 6238 seed `GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ` at the
     pinned `t=59` displays exactly **`287082`** — the wasm-computed 6-digit form of the RFC's
     `94287082` — with a `1s` countdown, **in the real popup**;
  3. `chrome.storage.local` contains **ONLY the sealed container** — no plaintext secret, label, or
     password (the sealed-only persistence property, checked in real storage);
  4. a fresh popup boots **locked**, a wrong password is rejected, the right one restores the
     persisted account and the same code;
  5. the `otpauth://` + Google Authenticator `otpauth-migration://` import paths and the export
     round-trip work, and removal re-seals the vault.
- ⚠️ An intermediate run during the phase failed all three with `Could not load the WebAssembly
  core: Failed to fetch`; the re-run after the vendored build settled is clean (3/3). Stale
  `test-results/` from that run are gitignored artifacts, not state.
- **Nothing else moved.** `libsigil/`, `cli/`, `sigild/`, the repo-root `sigil-wasm/`, and `web/` are
  untouched by this phase; both `Cargo.lock`s still have `getrandom` == 0.

### Docs (this pass)
- `docs/architecture.md` — new `extension` component in §1 (MV3 popup authenticator over the
  **vendored** wasm + proven helpers; same `SIGILcli` vault → cross-client; sealed-only
  `chrome.storage.local` + in-memory password; `["storage"]` only, no background worker, one CSP
  keyword; the headless proof) + a diagram-footer line; §6 reworded — the extension is no longer a
  "reserved directory", but is honestly logged as dev / UNAUDITED / unpublished / no-sync / none of
  the reserved ambitions.
- `CLAUDE.md` — `extension/` promoted from "reserved" to a real repository-map entry, and its
  build/test commands added to the Build & test section (`pnpm -C extension install`,
  `./extension/build.sh`, `pnpm -C extension test`, plus the load-unpacked note and the "not in CI"
  caveat).
- `README.md` — a short `extension/` bullet (browser extension client, encrypted TOTP vault, dev /
  UNAUDITED / unpublished) + the repository-layout line updated.
- `docs/decisions/0030-browser-extension-client.md` — new Nygard ADR (context: the reserved
  extension was blocked on a wasm artifact that now exists, and a second real client is the honest
  test of the shared-vault architecture; decision: MV3 with a minimal permission/CSP surface, vendor
  the wasm + reuse the proven helpers rather than reimplement, persist ONLY the sealed `SIGILcli`
  container with an in-memory password, stay dependency-light and store-unpublished; consequences:
  vault stays cross-client, a build step now stands between clone and loadable extension, MV3
  CSP/popup-lifetime constraints, still dev/UNAUDITED, no CI job). Indexed in
  `docs/decisions/README.md` (Accepted, 2026-07).
- `journal.md` — this entry + RESUME ANCHOR bumped to through Phase 40.

### ➡️ Still open (honest)
- **Dev / UNAUDITED / published to NO store.** Loaded unpacked by hand, not signed, not listed. Same
  unaudited building blocks; no security claim. **Do NOT store real 2FA secrets.**
- **No sync.** The extension never talks to `sigild`; the vault is local to one browser profile —
  no multi-device, enrollment, or recovery. A lost password is an unrecoverable local vault by
  design, and `chrome.storage.local` is **not** a hardened secret store.
- **Generate-only.** No verification, no constant-time comparison, no zeroization.
- **A build step is now load-bearing.** `vendor/` is generated and gitignored, so the extension needs
  the **Rust + wasm-pack toolchain** before it can be loaded or tested; a stale `vendor/` is a real
  failure mode (hence `BUILD-INFO.txt`).
- **Not in CI.** The Playwright proof runs locally only (needs a full Chromium + the Rust/wasm
  toolchain); no `.github/workflows/` job exercises the extension yet.
- **None of the reserved ambitions.** Phishing protection, passkey provider, and content scripts are
  explicitly NOT implemented by this phase — a background service worker would be required first.

---

## 2026-07-16 — Phase 41 (`sigild` gets a REAL multi-device auth model: contract v3 — device registry, enrollment with proof of possession, per-vault grants, revocation)

### What & why
- Until now `sigild` had exactly two auth postures, and **neither was a model of authority**:
  wide open (the default), or **ONE static Ed25519 key** (`SIGILD_OPLOG_PUBKEY`, contract v2)
  that authenticated **every** request to **every** vault. That meant **no device identity**
  (the audit log could not say *which* device appended an op — there was only one key), **no
  authorization** ("device B must not read device A's vault" was unexpressible), **no
  revocation** (a leaked key could only be handled by editing the env and restarting), and
  **no enrollment** (an operator pasted a public key into a variable, with no proof the
  presenter held the private half).
- Meanwhile the client column had run well ahead: three real clients (`cli/`,
  `web/apps/webapp`, `extension/`) all seal to the same `SIGILcli` container and two of them
  sync opaque containers through the op-log. The missing piece was **server-side**.
- The `CLAUDE.md` guardrail is "don't fake crypto/auth" — so the choice was to keep stubbing
  or build something **real**. Phase 41 built the real thing, honestly scoped: real
  `crypto/ed25519` verification against a real registry, **no bypass path, no fallback
  "trusted" key, no hardcoded credential** — and still **dev-gated, opt-in, UNAUDITED**.

### How (design decisions → ADR 0031)
- **Device registry behind a store seam.** New `store.DeviceStore` interface
  (`internal/store/devicestore.go`), mirroring the existing `VaultLog` seam: context-aware,
  concurrency-safe, interchangeable backends. It holds **auth metadata only** — devices (a
  raw 32-byte Ed25519 **public** key, a **server-assigned** ID = `"dev_"` + raw-URL-base64
  of 16 `crypto/rand` bytes so a client can neither choose nor squat an ID, a label, an
  `active`/`revoked` status), enrollment tokens (recorded **only** as a lowercase hex
  SHA-256 digest, with `used_at` as the single-use marker), and grants
  (`(vaultID, deviceID) -> read|write`, write implies read, plus an `is_owner` flag).
  Backends: `MemDeviceStore` (dev/tests, non-durable) and `PostgresDeviceStore`
  (`postgresdevicestore.go`) that **shares the op-log's existing `pgxpool`** — **no second
  pool and NO new dependency**.
- **Contract v3 binds the device into the signed message** (`canonicalV3Message`,
  `internal/api/deviceauth.go`):
  `"sigil-oplog-auth-v3\n" + DEVICE_ID + "\n" + METHOD + "\n" + PATH + "\n" + QUERY + "\n" +
  TIMESTAMP + "\n" + NONCE + "\n" + BODY`, with a new **`X-Sigil-Device`** header alongside
  the v2 trio. The domain bump `…-v2` → `…-v3` **plus** the extra segment is deliberate
  **domain separation**: a captured v2 signature cannot verify under v3, so v2 traffic
  cannot be replayed into the device model.
- **Enrollment = two independent, both-mandatory factors** (`internal/api/devices.go`):
  (1) an operator-provisioned **enrollment token** (`X-Sigil-Enroll-Token`), matched in
  **constant time** against the configured digests (no early exit) and then **spent
  atomically** — a conditional `UPDATE … WHERE used_at IS NULL` inside a `FOR UPDATE` tx in
  Postgres, a mutex in memory; and (2) **proof of possession** over a **DIFFERENT domain**
  (`canonicalEnrollMessage`):
  `"sigil-device-enroll-v1\n" + TOKEN_SHA256_HEX + "\n" + TIMESTAMP + "\n" + NONCE + "\n" +
  PUBLIC_KEY_B64 + "\n" + LABEL`, signed by the enrolling private key and verified against
  the **SUBMITTED** public key. A bare public-key upload is never accepted. Binding the
  token digest means a captured proof cannot be re-presented with a *different* token;
  binding the public key means an interceptor cannot swap in its own key while reusing a
  victim's token; the separate domain means a proof is never a request signature.
- **Verification order is 1:1 with the audited reason**, and two orderings are load-bearing:
  headers present → timestamp parses → inside the **300 s** window → device resolves →
  **device NOT revoked (checked BEFORE signature verification**, so revocation bites on the
  device's very next request no matter how well it signs) → Ed25519 verifies under **that
  device's registered key** → **nonce not replayed (recorded ONLY after a valid signature**,
  so unauthenticated probes can neither populate nor probe the cache) → per-vault
  authorization.
- **Authorization + TRUST-ON-FIRST-WRITE ownership** (`authorizeVault`): each route declares
  what it needs (`POST …/ops` ⇒ **write**, `GET …/ops` and `…/ops/verify` ⇒ **read**,
  `POST …/grants` ⇒ **owner**). A vault with no owner is claimed by the **first device that
  successfully authenticates a WRITE** to it; the claim is **atomic** in both backends (a
  mutex in memory; a **partial `UNIQUE INDEX … (vault_id) WHERE is_owner`** in Postgres), so
  exactly one of N concurrent first-writers wins. **Reads never claim** (403 on an unowned
  vault); only the owner may grant, and only to an enrolled, non-revoked device.
- **401 vs 403 with NO auth oracle.** `401` = unauthenticated, `403` = authenticated but not
  permitted, `500` = registry fault (`store_unavailable`, deliberately *not* a credential
  verdict). The **client body stays coarse** — `{"error":"unauthorized"}` /
  `{"error":"forbidden"}` — while the typed reason enum (`unknown_device`, `revoked_device`,
  `unauthorized_vault`, `not_vault_owner`, `forbidden_device`, `bad_admin_token`,
  `bad_proof`, `enrollment_token_used`, `enrollment_token_expired`, `bad_enrollment_token`,
  `malformed_key`, `device_exists`, `store_unavailable`) goes **ONLY** to the audit log and
  the per-reason metric.
- **Five new routes, all dev-gated** (`internal/api/router.go`): `POST /v1/devices/enroll`,
  `GET /v1/devices`, `POST /v1/devices/{deviceID}/revoke`, `POST /v1/vaults/{vaultID}/grants`,
  `GET /v1/vaults/{vaultID}/grants`. With dev-ops off (or no registry) each returns a
  deliberate **`501`** — never `404`, never partial auth behaviour. Revocation has **two**
  authorized paths, neither a bypass: the operator admin token (may revoke **any** device —
  the break-glass path) or **self-revocation** (a valid v3-signed request whose signing
  device *is* the target; revoking someone else is `403 forbidden_device`).
- **Config, fail-fast before the listener binds** (`cmd/server/main.go`,
  `validateDeviceAuthConfig`): `SIGILD_DEVICE_AUTH` (requires `SIGILD_ENABLE_DEV_OPS`,
  **mutually exclusive** with `SIGILD_OPLOG_PUBKEY`), `SIGILD_ENROLL_TOKENS` (comma-separated,
  each ≥ 16 chars, no duplicates, **required** when device auth is on — only digests reach
  `api.Config`), `SIGILD_ENROLL_TOKEN_TTL` (optional positive Go duration; unset ⇒ no expiry
  but still single-use), `SIGILD_ADMIN_TOKEN` (optional, ≥ 16 chars; **unset ⇒ the operator
  routes are permanently 401 — there is NO implicit open-admin mode**).
- **Storage: migration `0002_devices.sql`** on the existing managed-migration machinery
  (ADR 0018), `0001_init` untouched: `sigil_devices`, `sigil_enrollment_tokens`,
  `sigil_device_grants` (+ `sigil_device_grants_one_owner`, `sigil_device_grants_by_device`).
  `sigild_schema_version` now reports **2**. It is **pure DDL over auth metadata** and
  touches **NOTHING** in `sigil_vault_ops` — **the opaque blob, its tamper-evidence hash
  chain, and the zero-knowledge boundary are byte-for-byte unaffected**, and the server still
  does no cryptography on vault contents (the only hashing added is SHA-256 over a bearer
  token so the plaintext is never persisted).
- **Observability, count-only:** `sigild_device_enrollments_total`,
  `sigild_device_revocations_total`, `sigild_vault_grants_total`, `sigild_vault_claims_total`,
  `sigild_oplog_authz_denied_total`, `sigild_device_enroll_denied_total{reason}`, plus the new
  reasons on `sigild_oplog_auth_denied_total{reason}`. **No metric is labelled by device or
  vault ID** (an ID label would let a scrape enumerate the registry). New audit events
  `device.enrolled` / `device.enroll_denied` / `device.revoked` / `vault.claimed` /
  `vault.granted` carry `device_id`, `label`, `permission`, `revoked_by`, `reason` — and
  **never** a public key, token (or digest), signature, nonce, timestamp value, or blob.

### ✅ Verified GREEN (gated first-hand)
- `gofmt` / `go vet` clean; **`go test -race ./...` all ok**; `go build ./...` + `go mod
  verify` ok; still **exactly ONE direct Go dependency (`pgx`)**.
- **24/24 adversarial checks passed** against live servers with an **independently written**
  client: valid enrollment **201**; reused token **401**; unprovisioned token **401**; proof
  signed by the **wrong key 401**; proof bound to a **different token 401**; tampered
  body/path **401**; corrupted signature **401**; stale timestamp **401**; a **v2-domain
  signature under v3 401**; an unenrolled key signing as an enrolled device **401**; device
  A's signature sent under device B's ID **401**; unknown device **401**; replay of an
  identical signed request **401**; device B reading/writing device A's vault **403 (not
  401)**; admin revoke **200**; the revoked device then **401**; device A unaffected **200**;
  wrong admin token **401**.
- **Mutual exclusion is enforced at boot:** `SIGILD_DEVICE_AUTH` + `SIGILD_OPLOG_PUBKEY`
  together ⇒ the server **refuses to boot**, rc=1, `"invalid device-auth configuration"`.
- **Default posture confirmed:** with `SIGILD_ENABLE_DEV_OPS` unset, **all ops AND all five
  device routes return `501`**, while `GET /metrics` still returns **200** (it is never
  dev-gated).
- **Cross-component regression green:** `sigil-wasm/test/sync-interop.mjs` (3 proofs +
  the opaque check) and `sigil-wasm/test/totp-interop.mjs` (cross-client RFC vector) still
  pass — **the CLI's `push`/`pull` and the wasm `sync.mjs` client are unaffected** by the new
  contract, because the legacy v2 and no-auth paths are preserved verbatim.

### Docs (this pass)
- `docs/api.md` (the HTTP contract authority) — a new **"Multi-device auth model (contract
  v3) — DEV"** section: the four config variables, the storage tables, the exact v3 canonical
  message + header table + the 7-step verification order, the grant/TOFU model with the
  per-route permission table, the `401`/`403`/`500` split and the "no auth oracle" property,
  the full denial-reason enum, and per-endpoint request/response/error tables for all five
  routes plus the default-`501` posture. The legacy v2 section is retitled **LEGACY** with
  the mutual-exclusion note; the metrics table, the audit-event table, the op-log
  "unauthenticated" warning, and the "what production will add" bullet were all updated.
  ⚠️ Also fixed a **pre-existing** inaccuracy unrelated to this phase: `api.md` described the
  per-op `hash` and `tip_hash` as **hex**, but `opsList`/`opsVerify` emit them as
  **standard base64** (`base64.StdEncoding`) — corrected in four places.
- `docs/architecture.md` — the device-auth model added to the `sigild` component (registry +
  enrollment + grants + revocation over the store seam, mem + Postgres via migration 0002,
  `schema_version` 2), with the explicit note that it changes **nothing** about the opaque
  blob / zero-knowledge boundary; the §6 "No real auth or authorization" bullet rewritten to
  say what now exists versus what is still missing (account model, sessions/JWT, rotation,
  recovery, enrollment rate limiting, shared replay store); the trust-boundary paragraph and
  the "no production storage" bullet de-staled.
- `docs/threat-model.md` — a new adversary table for the auth surface (**A–I**: signature
  forger, replayer, downgrade/cross-protocol, enrollment-token thief, proof interceptor,
  malicious enrolled device, revoked device, auth prober/oracle-hunter, compromised admin
  token) with the defense **as implemented**, followed by an explicit **"what this does NOT
  defend"** list (TOFU, orphaned vaults, no enrollment rate limiting, per-process replay
  cache, single-attempt tokens, no rotation/recovery/attestation, non-durable mem registry,
  plain HTTP) and a paragraph on why zero-knowledge is unaffected. The closing status note
  now distinguishes the *intended* product defenses (unimplemented) from this
  *implemented-but-dev-gated-and-unaudited* surface.
- `CLAUDE.md` — the `sigild` bullet gained the full v3 model (routes, env vars, both canonical
  messages, verify order, grants/TOFU, revocation, migration 0002, `schema_version` 2, new
  metrics/audit events) with its honest limits; the v2 paragraph relabelled LEGACY. **Also
  fixed a repo-map gap** found by an audit: the map omitted **seven committed sigild
  packages** — `cmd/worker-audit`, `cmd/worker-breach`, `cmd/worker-rehash` (~15-line stubs)
  and `internal/admin`, `internal/auth`, `internal/push`, `internal/vault` (6–7-line `doc.go`
  placeholders) — now listed as inert scaffold, with a pointed note that `internal/auth` is
  **NOT** where the real auth lives (`internal/api/deviceauth.go` +
  `internal/store/devicestore.go` are).
- `README.md` — a brief honest note on the opt-in multi-device auth model (enrollment,
  per-vault authorization, revocation; dev-gated, `501` by default, UNAUDITED, not an account
  model); the stale "no auth / enrollment / per-vault authorization" clause corrected.
- `docs/decisions/0031-multi-device-auth-model.md` — new Nygard ADR (context: one static key
  authenticated everything, with no device identity, authorization or revocation; decision:
  a device registry with an Ed25519 key per device, enrollment via an operator token **plus**
  proof of possession, contract v3 binding the device ID into the signed message with a
  bumped domain, per-vault grants with TOFU ownership, revocation checked before signature
  verification, opt-in and mutually exclusive with v2; consequences: **every** honest
  limitation below). Indexed in `docs/decisions/README.md` (Accepted, 2026-07).
- `journal.md` — this entry + RESUME ANCHOR bumped to **through Phase 41**.

### ➡️ Still open (honest)
- **Dev-gated, pre-audit, UNAUDITED.** This is a real auth model, but nobody external has
  reviewed it. It is off by default (`501`), plain HTTP in dev, and **not** a security claim.
- **TOFU is a dev ownership model, not an account model.** It assumes the first writer of a
  high-entropy, client-chosen vault ID is legitimate; an attacker who writes to an unclaimed
  ID first **becomes its owner** and locks the real owner out with a `403`.
- **An enrollment token is single-ATTEMPT, not single-SUCCESS.** It is spent *before* the
  device row is created, so a duplicate-key enrollment **burns** it — fail-closed by design;
  an operator must issue a new token.
- **The replay nonce cache is per-process / in-memory.** A multi-instance deployment needs a
  shared store (e.g. Redis). Device request nonces share one namespace (enrollment nonces are
  prefix-separated).
- **Revoking a vault's owner ORPHANS the vault.** There is **no ownership transfer**, so
  nobody can grant on it afterwards; existing grantees keep only what they already hold.
- **The in-memory registry is non-durable** — devices, grants and spent-token markers are
  lost on restart, so a **spent token becomes reusable** after one (warned at boot). The
  **file backend was NOT extended**: device auth with `SIGILD_OPLOG_DIR` falls back to the
  in-memory registry (also warned at boot).
- **No user/account model, no session or token issuance (no JWT — `internal/auth` is still a
  placeholder), no key rotation or re-enrollment, no recovery, no hardware attestation, and
  NO rate limiting on enrollment attempts.** The admin token is a single static bearer secret
  with no rotation story: if it leaks, the holder can revoke any device (a DoS — it still
  cannot decrypt anything).

---

## 2026-07-16 — Phase 42 (the `sigil` CLI speaks contract v3: device enrollment, v3-signed push/pull, grants, revocation)

### What & why
- Phase 41 built the server half of the multi-device auth model (ADR 0031) but **no client
  spoke it** — v3 could only be exercised by a throwaway test client. Phase 42 is the
  **client half**: the `sigil` CLI now enrolls as a device, signs its op-log requests under
  contract v3, grants other devices access to its vaults, and revokes devices.
- **No new ADR.** This is the other half of ADR 0031, not a new decision — it introduces no
  design choice of its own, only mirrors the server's canonical messages. A **"Client
  support (added Phase 42)"** section was appended to
  `docs/decisions/0031-multi-device-auth-model.md` instead.

### How (all changes confined to `cli/`)
- **Four subcommands** under a `device` dispatch (`cli/src/main.rs`: `cmd_device`,
  `parse_device_flags`, `cmd_device_enroll`/`_list`/`_revoke`/`_grant`):
  - `sigil device enroll --token <t> [--label <name>] [--key <file>] [--server <url>] [--reuse-key]`
    → `POST /v1/devices/enroll`. Generates a fresh key (or reuses the existing one with
    `--reuse-key`), signs the proof-of-possession challenge, and writes the server-assigned
    device ID back into the identity file. It **refuses to overwrite** an existing identity
    file without `--reuse-key` — overwriting would destroy a device's only credential.
  - `sigil device list --admin-token <t> [--server <url>]` → `GET /v1/devices` (operator-only).
  - `sigil device revoke <deviceID> [--admin-token <t>] [--key <file>] [--server <url>]` →
    `POST /v1/devices/{deviceID}/revoke`; self-revocation via `--key` (the CLI checks locally
    that the identity IS the target before sending), operator revocation via `--admin-token`.
  - `sigil device grant <deviceID> --vault <id> --permission read|write [--key <file>] [--server <url>]`
    → `POST /v1/vaults/{vaultID}/grants` (owner-only). `GET …/grants` has **no subcommand yet**.
- **Identity model: the EXISTING key file was EXTENDED, not replaced.** `KeyFile`
  (`cli/src/lib.rs`) gained an **optional `device_id`** (`#[serde(default,
  skip_serializing_if = "Option::is_none")]`), so a key file written by an older build parses
  unchanged, omits the field on write, and keeps signing v2. `DeviceIdentity` +
  `RequestAuth::{None,V2,V3}` make **contract selection additive and driven by the identity**:
  **no key ⇒ unsigned** (byte-identical legacy path) · **identity WITHOUT `device_id` ⇒ legacy
  v2** · **identity WITH `device_id` ⇒ v3** (adds the `X-Sigil-Device` header). `push`/`pull`
  therefore sign v3 automatically once their key is enrolled, with **zero flag changes**;
  `SIGIL_DEVICE_ID` forces v3 with that ID even on an older key file.
- **Canonical bytes are rebuilt client-side and MUST stay byte-identical to sigild's**:
  `canonical_v3_message` (`"sigil-oplog-auth-v3\n" + DEVICE_ID + "\n" + METHOD + "\n" + PATH +
  "\n" + QUERY + "\n" + TIMESTAMP + "\n" + NONCE + "\n" + BODY`) mirrors `canonicalV3Message`,
  and `canonical_enroll_message` (`"sigil-device-enroll-v1\n" + TOKEN_SHA256_HEX + "\n" +
  TIMESTAMP + "\n" + NONCE + "\n" + PUBLIC_KEY_B64 + "\n" + LABEL`, **no trailing newline**)
  mirrors `canonicalEnrollMessage`. A fresh CSPRNG nonce + the current unix seconds are drawn
  per request; signing is `sigil_core::sign`. The enrollment body is serialized FIRST and the
  exact strings it carries are what get signed, so escaping cannot diverge from the server.
- **New env vars** `SIGIL_ENROLL_TOKEN` / `SIGIL_ADMIN_TOKEN` / `SIGIL_DEVICE_ID` (flags win,
  empty treated as unset) beside the unchanged `SIGIL_SERVER` / `SIGIL_DEVICE_KEY` /
  `SIGIL_PASSWORD`. The default identity path `$HOME/.sigil/device.key` applies **only** to the
  `device` subcommands; `push`/`pull` keep their old rule (no key ⇒ unsigned).
- **Secret hygiene:** identity files are written `0600` (parent dir `0700`), and the seed, the
  enrollment token and the admin token are **never printed** — only device IDs, labels and
  statuses. `explain_device_error` / `explain_sync_error` translate `401` vs `403` into
  actionable operator text (including the exact `sigil device grant …` line to ask an owner
  for) **without echoing any credential**.
- **Dependencies:** one new dependency **EDGE** only — `sha2` (`default-features = false`) for
  the enrollment-token digest. The crate was already in `cli/Cargo.lock` transitively via
  `sigil-core`, so **no new package** entered the lockfile.

### ✅ Verified GREEN (first-hand, against a live `sigild`)
- **Enroll A** succeeded and wrote a `0600` identity — **no seed on stdout**.
- **Reusing the same enrollment token failed** — tokens really are single-use.
- `sigil push --vault demo --in <file> --key A.key` succeeded at **seq 1** and **claimed** the
  vault (trust-on-first-write); `sigil pull` + `sigil open` round-tripped **byte-identical**
  plaintext.
- **Device B enrolled**, and **B pulling A's vault BEFORE a grant → `403`**.
- `sigil device grant <B> --vault demo --permission read` succeeded → **B then pulled fine**.
- **B WRITING with a read-only grant → `403`** — the permission lattice is enforced.
- After an **admin revoke**, **B → `401`** while **A kept working**.
- An **UNSIGNED push** against a device-auth server → **`401`**.
- The **server log contained neither the enrollment token nor the admin token**.
- Static: `cargo fmt --check` clean, `cargo clippy --all-targets -D warnings` clean,
  **64 lib + 3 integration tests pass**.
- **Regression green:** `sigil-wasm/test/sync-interop.mjs` and `totp-interop.mjs` both still
  **PASS** (they drive the real CLI against an **UNAUTHENTICATED** dev sigild), proving the
  legacy unsigned/v2 paths are untouched. All changes are confined to `cli/`, and
  **`libsigil/Cargo.lock` `getrandom` is still 0**.

### Docs (this pass)
- `docs/api.md` — a new **"Client support (the `sigil` CLI)"** subsection in the v3 section
  (command→route table, the contract-selection table, the env vars, the note that
  `GET …/grants` has no subcommand yet); the legacy-v2 key-file paragraph now mentions the
  optional `device_id`, and its "multi-device enrollment / registry … is future" clause was
  corrected to point at contract v3 (JWT/session issuance is what is still future).
- `CLAUDE.md` — the `cli/` bullet gained the four subcommands, the extended-key-file /
  backward-compatibility note, the unsigned/v2/v3 selection rule, the new env vars, the
  canonical-message sync requirement, and the `sha2` dep-edge note, with the honest scope kept.
- `README.md` — a brief honest note that the CLI can enroll as a device and sync under
  per-vault authorization against the dev server (dev / plain HTTP / UNAUDITED).
- `docs/deployment.md` — the stale "no … native client consumes this server" clause corrected:
  the `sigil` CLI does, now including the device model, still dev/localhost/plain HTTP.
- `docs/decisions/0031-multi-device-auth-model.md` — a **"Client support (added Phase 42)"**
  section (no new ADR).
- `journal.md` — this entry + RESUME ANCHOR bumped to **through Phase 42**.

### ➡️ Still open (honest)
- **Dev op-log over PLAIN HTTP — no TLS.** Do not point it at a remote host.
- **The server-side model is dev-gated and UNAUDITED**; this is not a security claim.
- **Ownership is trust-on-first-write** — a dev heuristic, not an account model.
- **Enrollment tokens are single-ATTEMPT** (a failed attempt burns one).
- **No account model, no session issuance (no JWT), no key rotation / re-enrollment**, and the
  server's **replay cache is per-process**.
- Client gaps: **no `device grants` listing subcommand** (`GET /v1/vaults/{vaultID}/grants` is
  unused), and the CLI is still the **only** client that speaks v3 — the wasm `sync.mjs`,
  webapp, and extension all remain on the unsigned dev path.

---

## 2026-07-16 — Phase 43 (the NATIVE client column opens: `desktop/`, a Tauri v2 authenticator over libsigil linked natively)

### What & why
- Three client surfaces existed and **every one was a terminal or a browser**: `cli/`
  (native, but a terminal tool), `web/apps/webapp` (core as **wasm**), `extension/` (core as
  **wasm**). The **native GUI column was empty**, and `README.md` said native clients "live in
  separate repositories" — none existed.
- Phase 43 fills it with a new top-level **`desktop/`**: a **Tauri v2** desktop authenticator
  whose Rust backend links **`sigil-core` as a plain NATIVE Rust dependency**. **There is no
  wasm, `wasm-bindgen` or `wasm-pack` anywhere under `desktop/`** — grepped and confirmed. That
  is what makes this a genuinely new column instead of a re-skin of the browser clients: it is a
  **second, non-wasm consumer** of the core's caller-supplies-entropy-and-time contract
  (ADR 0007), which is the cheapest available test of whether that contract is a real interface
  or an accident of the wasm path. Routing a native app through wasm would have carried the
  whole wasm-pack / `target_features`-strip apparatus for zero benefit on a platform that links
  Rust directly.
- **ADR 0032** records the decision.

### How
- **Own cargo workspace.** `desktop/Cargo.toml` (`members = ["core", "src-tauri"]`) with its
  **own `desktop/Cargo.lock`**, **deliberately OUTSIDE the `libsigil` workspace** exactly like
  `cli/` and `sigil-wasm/` (ADR 0002), so Tauri's platform stack and the transitively-pulled
  native `getrandom` can never perturb the wasm-pure, audit-bound core lockfile.
  `rust-version = "1.85"` (transitive `ml-dsa` 0.1.1 is edition 2024).
- **Two crates, logic split from shell.**
  - **`sigil-desktop-core`** (`desktop/core`) — **ALL** the authenticator logic, **headless**,
    `#![forbid(unsafe_code)]` + `#![deny(missing_docs)]`: `VaultSession`
    (`create`/`unlock`/`open_or_create`, `with_params`, `entries_at`/`entries_now`,
    `add_secret_base32`, `add_uri`, `import_text`/`import_file`, `remove`, `export_uris`,
    `export_migration_uri`, `save`), the `EntryView`/`ImportSummary` view models,
    `DesktopError`, `now_unix`, `default_vault_path`, and the `BANNER_TITLE`/`BANNER_BODY`/
    `EXPORT_WARNING` constants.
  - **`sigil-desktop`** (`desktop/src-tauri`) — a **thin** shell: one window, a
    `Mutex<Option<VaultSession>>` app state, and **ten `#[tauri::command]`s** (`status`,
    `unlock`, `lock`, `list`, `add_secret`, `add_uri`, `import`, `remove`, `export_uris`,
    `export_migration`) that only marshal arguments.
  - `desktop/ui` — framework-free HTML/CSS/JS. **No npm, no bundler, no CDN.**
  - The split is deliberate: **a GUI cannot be clicked by a test runner**, so everything that
    could be wrong lives in `core/` where tests drive it.
- **The two things the core refuses to do.** `sigil-core` reads **no clock and no RNG**, so the
  native app supplies both: **entropy** (Argon2id salt, AEAD nonce) through `sigil-cli`'s
  native `getrandom` path inside `seal_to_container`, and the **clock** via
  `std::time::SystemTime` in `now_unix`, passed **into** the core's `totp` as a `u64`.
- **REUSE, NOT REIMPLEMENT — zero crypto/format code in this directory.**
  `sigil-desktop-core` path-depends on `sigil-core` **and on the `sigil-cli` LIBRARY target**,
  taking the `SIGILcli` container (`seal_vault`/`open_vault`), the `TotpVault`/`TotpEntry`
  schema and `TotpEntry::code_at`, `base32_decode`, `new_totp_entry`,
  `totp_algorithm_from_str`, `parse_otpauth_uri`/`entry_to_otpauth_uri`, and the Google
  Authenticator migration codec (`decode_migration_uri`/`encode_migration_uri`/
  `entry_to_migration_otp`/`migration_otp_to_entry`). Grepped `desktop/core` for hand-rolled
  hmac/sha1 — **none**. **Nothing under `cli/` was edited.** Consequence: **no fourth at-rest
  format and NO mirrored schema to keep in sync** (unlike the deliberate Rust↔JS mirrors of
  ADRs 0020/0026) — this column consumes the Rust definitions directly.
- **One shared vault file.** Default path **`$HOME/.sigil/totp-vault.sigil`** (fallback
  `./totp-vault.sigil` when `$HOME` is unset) — **byte-for-byte the CLI's default**, so the
  desktop app and `sigil totp` drive **the same file** with no configuration. Dir `0700`, file
  `0600`; `save()` writes a temp file and **renames** it into place so an interrupted save
  cannot truncate a good vault. **Only the sealed container is ever persisted**; the password
  is memory-only for the life of a `VaultSession` and **best-effort** zeroed on `Drop` (no
  `zeroize`, no volatile guarantee — documented, not claimed).
- **Trust boundary.** The webview holds **no** key material and does **no** crypto — the
  password crosses the IPC once at unlock, codes arrive already computed — and
  `desktop/src-tauri/capabilities/default.json` grants **`core:default` and nothing else** (no
  `fs`/`shell`/`http`/`dialog` plugin), so the frontend reaches disk only through the explicit
  commands. The export commands return `EXPORT_WARNING` **together with** the payload, so a UI
  cannot render the secrets without the warning.
- **Features.** Create / unlock / lock an encrypted vault; live list (issuer/label + code +
  seconds remaining, recomputed ~1/s); add by base32 secret with algorithm/digits/period; add
  by `otpauth://` URI; import Google Authenticator `otpauth-migration://`; remove; export
  `otpauth://` URIs and one combined migration URI behind the loud warning. A loud **UNAUDITED**
  banner is rendered in the window **and** printed to stderr at startup from the same Rust
  constants, so no surface can quietly soften it.

### ✅ Verified GREEN (first-hand)
- `cargo fmt --manifest-path desktop/Cargo.toml --all -- --check` — **clean**.
- `cargo clippy --manifest-path desktop/Cargo.toml --all-targets -- -D warnings` — **zero
  warnings**.
- `cargo test --manifest-path desktop/Cargo.toml` — **11 unit tests + 1 integration test, all
  pass**.
- `cargo build --manifest-path desktop/Cargo.toml --release` — **succeeds**, producing an
  **~8.6 MB native binary**; **launching it keeps the process alive with the event loop
  running** and prints the pre-audit banner.
- **The TOTP KAT** (`totp_kat_rfc6238_t59` in `desktop/core/src/lib.rs`) asserts the **native**
  path reproduces **RFC 6238 App B at `T=59`** — `94287082` (8 digits) and `287082` (6) — and
  both were **independently reproduced with a from-scratch Python HMAC-SHA-1 implementation**.
- **THE INTEROP PROOF** (`desktop/core/tests/cli_interop.rs`) builds the **REAL `sigil`
  binary** and drives it as a **subprocess** against **ONE SHARED vault file, both directions**:
  a desktop-created vault is read by `sigil totp list` / `totp code` / `totp export` with
  **byte-for-byte agreement**; `sigil totp add` appends to that same file and the desktop
  **reopens it and reproduces the CLI's code, issuer, algorithm and digits**; and a
  desktop-generated migration URI **imports via `sigil totp import`**. Tests use **temp dirs,
  never the real user vault**.
- **Lockfile invariant intact:** `grep -c 'name = "getrandom"' libsigil/Cargo.lock` is still
  **0**, and `desktop/` is **not** a `libsigil` workspace member.

### ⚠️ Honest caveats (documented, not hidden)
1. **The GUI is build-and-launch verified, NOT visually verified.** Screencapture is denied in
   this environment, so there is **no screenshot proof** of the rendered window. This is exactly
   why all behaviour lives in a **headless** lib that tests drive — but the pixels are unproven
   here.
2. **`tauri build` (the `.app` bundler) was NOT run.** The applicable build is
   `cargo build --release`. The app is **not signed, not notarized, not distributed**.
3. **The interop test pins the clock with a deliberate artifice.** `sigil totp code` reads the
   host clock and has no `--at` flag, so the exact cross-process equality assertions use
   **`period = u32::MAX`** — the TOTP counter is `floor(now/period) = 0` until ~2106, making the
   code a constant both processes must agree on. **A test artifice, not product behaviour.** An
   ordinary 30 s account is also checked, with a bounded retry that tolerates a step boundary
   landing between the two processes.
4. **Still pre-audit / UNAUDITED — do not store real 2FA secrets.**
5. **Password zeroing is best-effort** (no `zeroize`, no volatile guarantee, the OS may have
   paged the buffer).
6. **This is ONE native surface.** macOS is where it was built and launched; Windows/Linux are
   untried from here, and the other native platforms — **mobile in particular — remain
   unbuilt**. No sync (`push`/`pull`), no device enrollment, no QR scanning, no code
   verification, no hardened zeroization in this column.

### Docs (this pass)
- `docs/architecture.md` — `desktop` added to the component map as the **fourth client surface
  and the first NATIVE one** (both crates, the native linkage, reuse-not-reimplement, the shared
  vault file, sealed-only persistence + in-memory password, the `core:default`-only trust
  boundary, its own workspace/lockfile); §4 "Build & dependency isolation" grew from **four to
  five Rust build surfaces**; the §1 diagram legend gained a `desktop` block; and §6's "No
  native clients" bullet was corrected to "one native GUI client now exists" with every caveat.
- `CLAUDE.md` — a `desktop/` repository-map entry (both crates, the native linkage, the
  reuse-not-reimplement rule, the shared vault path, its own workspace/`Cargo.lock`, the
  `u32::MAX` test artifice, dev/UNAUDITED/unsigned) and a **desktop block in Build & test**
  (`fmt`/`clippy`/`test`, the interop test, `cargo build --release`, and the
  `getrandom`==0 re-check), plus the `web/apps/admin` "reserved" note updated.
- `README.md` — a short honest `desktop/` note (native, shares the CLI's vault, dev / UNAUDITED
  / unsigned / undistributed), a repository-layout row, a Build & test line, and the "native
  clients live in separate repositories" sentence corrected.
- `docs/decisions/0032-native-desktop-client.md` — **NEW ADR 0032**, plus its index row in
  `docs/decisions/README.md`.
- `journal.md` — this entry + RESUME ANCHOR bumped to **through Phase 43**.

### ➡️ Still open (honest)
- **No `.app`/`.msi`/`.deb` bundle, no code signing, no notarization, no distribution channel.**
- **No visual/GUI regression proof** in this environment; the headless crate is the only gate.
- **No sync in the desktop column** — it never talks to `sigild`, so the multi-device work of
  Phases 41–42 (contract v3, grants, revocation) is unused here.
- **No mobile client.** The native column is open, not finished.
- **Not wired into CI** (like `extension/`); the gates above are local only.

---

## 2026-07-16 — Phase 44 (the browser clients authenticate: `device-auth.mjs`, wasm Ed25519, and a sealed device identity)

### What & why
- Phases 41–42 built the server's **multi-device auth model (contract v3)** and taught the
  **`sigil` CLI** to speak it. Every other client was still an **anonymous writer**: the webapp
  and the extension could only sync against a wide-open dev op-log, so the whole device model —
  enrollment, per-vault grants, revocation — was unreachable from the two surfaces a real user
  would actually touch.
- Phase 44 closes that: the **browser clients now enroll and sign as real devices**, so the auth
  story is complete across the CLI + browser column. Nothing on the server changed — the client
  half was the entire missing piece.
- **No new protocol ADR** (that is ADR 0031; a "Browser client support" note was appended to it).
  The one genuinely new decision — **how a browser stores its device identity** — is recorded as
  **ADR 0033**.

### How
- **Three wasm exports over `sigil-core`'s Ed25519.** `sigil-wasm/src/lib.rs` gains
  `ed25519_public_key(seed)`, `ed25519_sign(seed, message)` and
  `ed25519_verify(public_key, message, signature)` — thin `#[wasm_bindgen]` shells over the
  existing core primitive, no new crypto. The 32-byte seed is a **CALLER argument** (JS draws it
  with `crypto.getRandomValues`) and Ed25519 signing is deterministic, so the crate draws **no**
  entropy and the caller-supplied-entropy invariant (ADR 0007) holds unchanged. The `@sigil/wasm`
  loader re-exports all three.
- **NEW `sigil-wasm/device-auth.mjs`** — framework-free, dependency-free ESM that runs in **Node
  and the browser**, implementing the CLIENT half of contract v3: `generateDeviceSeed` /
  `devicePublicKey`, `enrollDevice`, `signedFetch` / `makeSignedFetch`, `pushContainerAuthed` /
  `pullContainersAuthed`, `grantVaultAccess` / `listVaultGrants`, `revokeSelf` /
  `revokeDeviceAdmin` / `listDevices`, `sealDeviceIdentity` / `openDeviceIdentity`, plus
  `DeviceAuthError` and `explainAuthStatus` (which renders the server's deliberately coarse
  401-vs-403 without inventing an oracle). **ALL signing is `wasm.ed25519_sign` — there is NO
  JS-side signing**; `enrollTokenHash` is lowercase-hex SHA-256 via `crypto.subtle`.
- **The canonical layout now lives in THREE implementations.** `canonicalV3Message` /
  `canonicalEnrollMessage` / `enrollTokenHash` are **MIRRORED — not shared — from
  `sigild/internal/api/deviceauth.go` (the source of truth) and `cli/src/lib.rs`**. ⚠️ Go, Rust
  and JS **must stay byte-identical**: drift does **not** fail loudly, it silently 401s every
  request. The interop tests are the only guard.
- **`sync.mjs` extended ADDITIVELY.** One optional `opts.fetch` (default `globalThis.fetch`) plus
  an additive `err.status`. The **unauthenticated path is behaviourally identical** — which is
  exactly why the five older Node interop tests still pass untouched — and the authenticated path
  just injects `makeSignedFetch`. The transport still does **no** crypto and never inspects a
  container.
- **SECRET HANDLING — the device seed is NEVER stored in plaintext (ADR 0033).** It is sealed
  into a **SECOND `SIGILcli` container under the SAME vault password** (Argon2id →
  XChaCha20-Poly1305, sealed and opened **inside the wasm**), and only that container is
  persisted: `localStorage` key **`sigil.webapp.device.v1`**, `chrome.storage.local` key
  **`sigil.extension.device.v1`**. The sealed plaintext is `{version, device_id, seed, base_url}`.
  It is a **separate container rather than a field in the vault JSON deliberately**, so the
  CLI-mirrored `TotpVault` schema stays byte-compatible (the CLI, the desktop app and the
  migration codec are untouched). The decrypted seed lives **only in memory while the vault is
  unlocked** — lock, reload and forget all drop it, and **forget deletes the sealed identity
  too**. The enrollment token is a bearer secret held in memory only, cleared after use, never
  stored or logged.
- **Webapp** (`web/apps/webapp/app/authenticator.tsx`): the Sync panel grows a **Device identity**
  section — enroll with a single-use token + label, or Forget; `push`/`pull` route through
  `pushContainerAuthed` / `pullContainersAuthed` when enrolled and stay unauthenticated when not.
- **Extension** (`extension/src/popup/popup.{html,js}`, `extension/build.sh`): the popup gains the
  same Sync + enrollment panel over the newly-vendored `sync.mjs` + `device-auth.mjs` (copied
  **verbatim**, as always — no reimplementation).
- ⚠️ **`extension/manifest.json` gained `"host_permissions": ["http://127.0.0.1/*",
  "http://localhost/*"]`** — MV3 extension pages **cannot** fetch cross-origin without an explicit
  host permission. It is deliberately **LOOPBACK-ONLY**, with an explanatory comment in the
  manifest, so this build **cannot reach a remote server**. `"permissions"` is still `["storage"]`
  and nothing else. Documented honestly rather than glossed: this is a real expansion of a
  previously host-permission-free extension.

### ✅ Verified GREEN (first-hand)
- **Rust:** `cargo fmt … --check` clean; `cargo clippy --all-targets -- -D warnings` clean;
  **26 tests** in `sigil-wasm`, including an **RFC 8032 known-answer vector** for the new Ed25519
  shells.
- **ALL SEVEN Node tests PASS:** `roundtrip.mjs`, `interop.mjs`, `hybrid-interop.mjs`,
  `sync-interop.mjs`, `totp-interop.mjs`, `migration-interop.mjs`, and the new
  **`device-auth-interop.mjs`**.
- **The live device-auth proof** (`device-auth-interop.mjs` boots a **REAL `sigild`** with
  `SIGILD_ENABLE_DEV_OPS=1` + `SIGILD_DEVICE_AUTH=1`) asserts, in order: an **unsigned request is
  refused 401**; **device A enrolls**; the identity **round-trips through the password-sealed
  container with NO plaintext seed at rest** (and a wrong password cannot open it); **A pushes,
  claims the vault (trust-on-first-write), pulls and opens it byte-verbatim**; **device B is
  enrolled but 403 on A's vault**; **after a read grant B can pull but is still 403 on write**;
  **an admin revoke makes B 401 while A is unaffected**; **a tampered body and a stale timestamp
  are both 401**; and **reusing a spent enrollment token is 401**.
- **Webapp:** typecheck / lint / build green; **Playwright 8/8**.
- **Extension:** `corepack pnpm -C extension test` → **3/3**, driving the **real unpacked
  extension** in chromium.
- **Marketing** build still green and **Rust-free**.
- **Lockfile invariant intact:** `grep -c 'name = "getrandom"'` is **0** in **both**
  `libsigil/Cargo.lock` and `sigil-wasm/Cargo.lock` — the seed is JS-supplied, so nothing pulled
  an RNG into the wasm-pure crates.
- **Blast radius:** nothing under `sigild/`, `cli/`, `libsigil/` or `desktop/` changed.

### ⚠️ Honest caveats (documented, not hidden)
1. **The enrollment UI is NOT covered by a Playwright test** in either browser client. The auth
   protocol itself is proven **live in Node**; the existing UI suites still pass and assert no
   page errors — but nobody has clicked the enroll button in a headless browser.
2. **Still the DEV op-log over PLAIN HTTP — no TLS, loopback only.** Request signing proves who
   sent a request; it is not transport security.
3. **The server-side model is still dev-gated and UNAUDITED.** Ownership is
   **trust-on-first-write**, and there is still **no account model, no session issuance, no key
   rotation, and no rate limiting on enrollment attempts**.
4. **The canonical message layout now lives in THREE implementations** (sigild Go, cli Rust,
   sigil-wasm JS) that **must stay byte-identical** — the interop tests are what guard that, and
   a drift fails silently as a 401 rather than loudly.
5. **The seed is exposed in memory while the vault is unlocked** (signing needs it): no
   zeroization, no `mlock`, no enclave. Sealing defends the **stored** key, not a live process,
   and neither client defends against a compromised browser/extension host or a malicious script
   with access to the same origin.
6. **The native `desktop/` client still has no sync and no device enrollment** — the auth story
   is complete for the CLI + browser column only.

### Docs (this pass)
- `docs/api.md` — the CLI client-support section now points onward, and a new **"Client support
  (the browser + Node clients)"** subsection maps the `device-auth.mjs` surface onto all five
  device routes, notes that all signing happens in the wasm, that `sync.mjs` changed additively,
  and that the canonical layout lives in three implementations kept in sync by the interop tests.
- `docs/architecture.md` — the `sigil-wasm` bullet records the three Ed25519 exports +
  `device-auth.mjs` + the live interop proof; the webapp and extension bullets record enrollment,
  signed sync, the **sealed** device identity and (extension) the **loopback-only** host
  permission; the stale "the extension has no sync" claim is corrected in both the component map
  and §6.
- `CLAUDE.md` — `sigil-wasm/`, webapp and `extension/` repository-map bullets updated; the Build
  & test block now **names all seven** Node tests (and the webapp's 8 Playwright specs).
- `README.md` — one honest sentence that all four clients that talk to the dev server can now
  enroll and authenticate as devices (with the `desktop/` exception stated).
- `docs/threat-model.md` — a new **"Browser clients holding a device identity"** subsection: the
  seed is sealed at rest under the vault password, it **is** exposed in memory while unlocked, the
  enrollment token is a bearer secret, the extension's reach is bounded by a loopback-only host
  permission — and an explicit statement that none of this defends against a compromised
  browser/extension host or same-origin script access.
- `docs/decisions/0031-multi-device-auth-model.md` — a **"Browser client support (added Phase
  44)"** note appended (no new protocol ADR).
- `docs/decisions/0033-browser-device-identity-storage.md` — **NEW ADR 0033** (sealed second
  `SIGILcli` container vs. plaintext web storage vs. a `TotpVault` field), plus its index row and
  a banner line in `docs/decisions/README.md`.
- `journal.md` — this entry + RESUME ANCHOR bumped to **through Phase 44**.

### ➡️ Still open (honest)
- **No browser test for enrollment** — the highest-value next gate for this column.
- **No TLS anywhere in the sync path**, and no shared (multi-instance) replay store.
- **No account model, session issuance, key rotation, re-enrollment or recovery** — a lost vault
  password still destroys the device identity along with the vault.
- **`desktop/` remains sync-less**, so contract v3 is still unused in the native column.

---

## 2026-07-26 — Phase 45 (`sigild` learns to take money: a provider-agnostic billing / subscription layer — Stripe + Razorpay + Juspay, stdlib-only, hosted checkout, idempotent webhooks)

### What & why
- **Sigil is a paid product and nothing in the repository could take a payment.** That made
  the payment story an *unwritten assumption* — the worst place for it, because payment
  decisions (which providers, how webhooks are authenticated, where subscription state
  lives, whether a vendor SDK enters the process) are hard to reverse and are exactly what
  an auditor asks about first.
- **Two markets, two payment worlds.** India's rails (UPI, netbanking, card mandates) are
  served by **Razorpay** and **Juspay**; the rest of the world by **Stripe**. There is no
  single processor covering both well, so "pick one" was never available — the design had
  to assume **at least three** providers, each with its own webhook scheme, event
  vocabulary and checkout API. Designing for three from the start cost exactly one
  interface; retrofitting a second provider into a Stripe-shaped codebase is how a
  provider dialect leaks into the state machine and the database.
- **The constraint that shaped everything: NO VENDOR SDKs.** Every provider ships an
  official Go SDK. Using three would put large, opaque, **network-capable** dependencies
  in the same process as an E2EE sync server whose entire value proposition is that it
  holds nothing worth stealing — and would bury the security-critical code (signature
  verification) inside a vendor library where a reviewer cannot read it. ADR 0005 /
  ADR 0014 made `sigild` a **one-direct-dependency** module; that posture is worth more
  than SDK convenience.
- **And the `CLAUDE.md` guardrail: don't fake crypto/auth.** A billing layer with a
  "TODO: verify signature" or a `==` on an HMAC would poison a future audit. Either the
  verification is real, or the routes stay `501`. They are real.
- **ADR 0034** records the decision, the alternatives, and the honest limits.

### How
- **The seam** — `sigild/internal/billing/billing.go`: one `billing.Provider` interface
  (`Name` / `CreateCheckout` / `VerifyWebhook`), a normalized `Event` (provider, event ID,
  `EventType`, subject, customer/subscription refs, trial flag, timestamps — and
  **deliberately no email / name / phone / card field**), `CheckoutRequest` /
  `CheckoutSession`, and coarse sentinel errors (`ErrBadSignature`, `ErrMalformedWebhook`,
  `ErrNotConfigured`). `ProviderError` carries **only** provider + operation + HTTP status
  — never the provider's response body, which can echo customer data into a log line.
- **Three adapters**, `net/http` + `crypto/hmac` + `crypto/sha256` + `crypto/subtle` +
  `encoding/json` + `net/url` only, each with an **injectable base URL and HTTP client** so
  the whole suite points at a local `httptest` server and nothing reaches the internet:
  - **`stripe.go`** — `POST /v1/checkout/sessions` (form-encoded; `mode=subscription`, a
    price-ID line item, `client_reference_id` + `subscription_data[metadata][sigil_subject]`
    carrying our subject, `Idempotency-Key` = the server-generated per-attempt reference).
    Webhook: `Stripe-Signature: t=…,v1=…`; signed message `"<t>.<RAW BODY>"`,
    HMAC-SHA256 under the endpoint signing secret, **5-minute tolerance checked in BOTH
    directions**, **every** `v1` element compared with **no early exit** (Stripe sends
    several during secret rotation), legacy `v0` **ignored, never accepted** (a downgrade
    path).
  - **`razorpay.go`** — `POST /v1/payment_links` (JSON, Basic auth, `notes.sigil_subject`,
    `notify` all-false so we hand over no customer contact detail). Webhook:
    `X-Razorpay-Signature`, HMAC-SHA256 over the **bare raw body** (no timestamp, so **no
    in-scheme replay bound** — the ledger is the bound); event ID from
    `X-Razorpay-Event-Id`, else a **deterministic** `"body-" + hex(SHA-256(raw body))` so a
    byte-identical redelivery still dedupes.
  - **`juspay.go`** — `POST /session` (`action=paymentPage`, `x-merchantid`, API key as the
    Basic-auth username, subject in `udf1` + `metadata`; the minor→major amount is rendered
    by **integer arithmetic only**, no float rounding). Webhook auth is behind a swappable
    **`juspayWebhookVerifier`** seam with two real implementations — `basic` (constant-time
    `Authorization: Basic`, both halves, no short circuit) and `hmac` (hex HMAC-SHA256 over
    the raw body, **configurable header name**, default `X-Juspay-Signature`) — precisely
    **because the provider contract is uncertain**; the uncertainty is quarantined to one
    type in one file.
- **State machine** — `state.go`: an explicit transition **table**, not scattered `if`s,
  because money-adjacent state that drifts is how a customer either pays for nothing or
  gets the product free. `past_due` is deliberately **entitled** (a declined card starts a
  provider retry window; cutting a paying customer off instantly is hostile and usually
  wrong); `canceled` is **not** a dead end (a re-purchase must work) but can only be left
  by an event targeting an active state, so a late `payment_failed` cannot revive it.
- **Store** — `store/subscriptionstore.go` + `postgressubscriptionstore.go`, mirroring the
  `VaultLog`/`DeviceStore` seams. `ApplyWebhookEvent` is one atomic
  **dedupe → resolve subject → staleness guard → legality → apply**: one mutex in memory,
  one transaction in Postgres with `INSERT … ON CONFLICT (provider,event_id) DO NOTHING`
  (zero rows affected *means* duplicate) and `SELECT … FOR UPDATE` on the subscription row.
  Fusing the ledger claim with the state change is the whole point — split into two calls,
  a crash in between double-applies or loses an event. An **unresolved** event is
  deliberately **not** recorded as processed, so a later event can establish the binding.
- **Migration `0003_billing.sql`** — `sigil_subscriptions` (+ a partial index for
  `(provider, subscription_ref)` subject resolution) and `sigil_billing_processed_events`
  (PK `(provider, event_id)` — idempotency enforced by the **database**, not by application
  timing) (+ a `processed_at` index). Pure DDL, **no column that could hold a PAN/CVV/
  expiry/name/address/email/phone**, the raw payload never persisted, `sigil_vault_ops`
  untouched ⇒ `sigild_schema_version` → **3**, zero-knowledge intact.
- **HTTP** — `api/billing.go` + three routes in `router.go`, dev-gated exactly like the ops
  and device routes (`501`, never `404`). Checkout reads the body **first** (the v3
  signature covers it) then authenticates through the **existing** `authenticateDevice`
  choke point; the subject is `dev.ID`, **server-derived**; `StartCheckout` binds
  subject→provider **before** the outbound call so a racing webhook has a row to resolve
  against; the per-attempt reference is server-generated (`"sigil-" + 12 random bytes`).
  The webhook reads the body **once** and keeps the exact bytes.
- **Observability** — four counters over **closed label sets materialized at boot**
  (`sigild_billing_checkouts_total{provider}`,
  `sigild_billing_webhooks_total{provider,outcome}`,
  `sigild_billing_webhook_rejected_total{reason}`,
  `sigild_billing_subscription_transitions_total{status}`) and five audit events
  (`billing.checkout_created` / `checkout_failed` / `webhook` / `webhook_rejected` /
  `subscription_transition`) carrying metadata only.
- **Config** — `cmd/server/billingconfig.go`: ~25 env vars parsed and validated **before
  the listener binds**, with **no network I/O**, and two loud boot warnings (unaudited /
  verify against live dashboards; in-memory store is non-durable).

### ✅ Verified (first-hand, this machine)
- `gofmt -l sigild` clean; `go -C sigild vet ./...` clean; **`go -C sigild test ./...`
  green** across `cmd/server`, `internal/api`, `internal/billing`, `internal/store`.
- **Forgery attempts are rejected.** Per provider: a **wrong secret**, a **tampered body**,
  a **missing/malformed signature header**, and (Stripe) a **stale timestamp** each produce
  `ErrBadSignature` → a coarse `401` at the HTTP layer, with the reason only in the audit
  log and the per-reason metric. `TestStripeWrongSecretRejected`,
  `TestStripeTamperedBodyRejected`, `TestStripeStaleTimestampRejected`,
  `TestRazorpayTamperedBodyRejected`, `TestJuspayHMACTamperedAndWrongSecretRejected`,
  `TestJuspayBasicWrongCredentialsRejected`, `TestWebhookRejectsBadSignature`,
  `TestWebhookRejectsTamperedBody`.
- **Raw-byte verification is proven, not assumed.** `Test{Stripe,Razorpay,Juspay}Verifies
  RawBytesNotReencodedJSON` re-serialize a semantically identical payload and confirm it
  **fails** — the MAC is over the wire bytes, not over re-encoded JSON.
- **Fails closed.** `TestUnconfiguredWebhookVerificationFailsClosed` — an adapter with no
  secret accepts nothing; `TestConstructionAndMisconfigurationMakeNoNetworkCall` — building
  an adapter performs no I/O.
- **The idempotency proof.** `TestWebhookIdempotency`: the **same** Stripe event delivered
  twice returns `200 accepted` then `200 duplicate`, and the subscription ends at exactly
  one `active` — one state change, two `200`s. Plus `TestWebhookStaleEventDoesNotRegress`
  and `TestWebhookIllegalTransitionIs200NoChange` (both `200`, neither moves state).
- **The one-dependency check.** `sigild/go.mod` still has **exactly one direct require**
  (`github.com/jackc/pgx/v5`); the billing package imports only Go stdlib. Re-confirmed by
  reading the module file after the phase.
- **Dev-gated `501` default.** `TestBillingRoutes501WhenDevOpsOff` and
  `TestBillingRoutes501WhenNotConfigured` — all three routes return
  `{"error":"not_implemented"}` with `501` (never `404`) when dev-ops is off or billing is
  unconfigured; `TestBillingConfigEnabled` pins the both-halves-required rule.
- **Subject cannot be spoofed.** `TestCheckoutSubjectCannotBeSpoofed`,
  `TestSubscriptionIsPerDevice`, `TestCheckoutRequiresDeviceAuth`,
  `TestSubscriptionRequiresDeviceAuth`, and `TestWebhookNeedsNoDeviceAuth` (the webhook is
  the one route outside the device model, on purpose).
- **No leakage.** `TestBillingMetricsExposeNoSecrets` asserts the four counters move and
  that no API key, webhook secret, device/subject ID, event ID or session ID appears in the
  exposition; `TestBillingAuditLogsNoSecretsOrBodies` plants a marker string **inside** a
  webhook body and fails if it reaches the logs. `TestProviderErrorCarriesOnlyAStatusCode`
  and `TestEventAndCheckoutShapesCarryNoCardDataOrPII` / `TestPersistedShapeCarriesNoCard
  DataOrPII` pin the no-PII shape of the error, the event and the persisted row.
- **Fail-fast config.** `TestBillingRequiresDevOpsAndDeviceAuth`,
  `TestEnablingProviderWithoutSecretsIsBootError`, `TestRazorpayRequiresAllThreeSecrets`,
  `TestJuspaySchemeSelection`, `TestProviderListValidation`,
  `TestDefaultProviderMustBeEnabled`, `TestReturnURLsAreRequiredAndAbsolute`,
  `TestAmountValidation`, `TestBaseURLOverrideValidation`.
- Postgres-backed store tests are gated on `SIGILD_TEST_POSTGRES` and **skipped** here, as
  with the other Postgres suites — so the **durable** idempotency path is proven by code
  review and the in-memory twin's semantics, **not** by a live database run on this machine.

### ⚠️ Honest limits (recorded, not softened)
- **Nothing has ever been run against a live provider account.** No request in this
  repository has reached `api.stripe.com`, `api.razorpay.com` or `api.juspay.in`. Every
  test drives a local `httptest` server with fake credentials.
- **The Juspay adapter is explicitly UNVERIFIED-AGAINST-LIVE-DASHBOARD** — header names,
  the exact signed message, the endpoint path, the response envelope and the event
  vocabulary are a best-supported reading. Both schemes are *real* (a real constant-time
  HMAC; a real constant-time credential comparison), but which one a merchant account uses,
  and under what header, must be confirmed first. Its `basic` scheme authenticates the
  **connection, not the body** — it does not defend a tampered payload, so it demands TLS
  unconditionally.
- **Razorpay's surrounding details are MEDIUM confidence** — the `X-Razorpay-Event-Id`
  header name (hence the deterministic fallback) and the exact subscription event names.
  The webhook signing scheme itself is high confidence.
- **No account model**: a subscription keys off the **enrolled device**, so one human with
  two devices is two subjects. It will have to be migrated when accounts exist.
- **Recurring subscription CREATION is unimplemented for the India adapters** (both create
  a one-time hosted page; their webhook sides do map subscription/mandate events, so an
  out-of-band subscription drives the state machine correctly).
- **No entitlement enforcement** — `entitled` is reported and consulted by nothing.
- **No fraud, chargeback, refund, dispute, proration, tax, dunning, invoicing or
  reconciliation**, no billing admin surface, **no rate limit on the webhook route** (only
  the 64 KiB body cap), and **no PCI attestation** (hosted checkout minimizes scope; it
  certifies nothing).
- **The in-memory subscription store is non-durable** — subscriptions *and* the
  processed-event ledger are lost on restart, so a webhook redelivered across a restart can
  be applied twice. Only Postgres gives the guarantee across processes and restarts.
- **Billing living inside `sigild` is PROVISIONAL** — placed where the identity, config,
  storage and observability plumbing already existed, not a claim that money-adjacent state
  belongs in a zero-knowledge sync server. Reversible by a later ADR.

### Docs updated in the same change
- `docs/api.md` — a full **Billing / subscriptions** section: every route with
  method/auth/request/response/status codes, the **per-provider webhook contract** (which
  header carries the signature and exactly what is signed), the normalized event-type
  mapping table, the state machine, the **idempotency guarantee** (duplicate delivery is a
  no-op `200`), configuration, storage, the audit events, and the honest limits; plus the
  four new metric rows and `sigild_schema_version` → **3**.
- `docs/architecture.md` — where billing sits, the provider seam, the no-SDK/one-dependency
  rule, no card data / SAQ-A, and the **honest architectural caveat** that billing inside
  the sync server is a scaffold decision rather than a final topology; a matching §6 gap
  entry.
- `docs/threat-model.md` — a new **billing / payment surface** adversary table (J–Q: webhook
  forger, replayer, body tamperer, unknown-provider prober, webhook-secret thief, API-key
  thief, subscription-state manipulator, log/metrics scraper) with the defenses **and** an
  explicit "what this does NOT defend" list (compromised provider account, stolen API key,
  no fraud/chargeback handling, no PCI attestation, unverified schemes, no webhook rate
  limit, non-durable in-memory store, TLS required).
- `docs/deployment.md` — **§13**, an operator guide: the env vars, how to register each
  provider's webhook endpoint (and a pre-production verification checklist), secrets living
  in the team password manager and never in the repo, the **mandatory TLS** requirement for
  webhooks in any real deployment, and a closing "what an operator does NOT get".
- `CLAUDE.md` — the `sigild/` bullet now records the billing layer, the three adapters, the
  stdlib-only/no-SDK rule, the new env vars, migration `0003`, and the dev-gated default.
- `README.md` — an honest paragraph: payment/subscription support exists in code
  (Stripe/Razorpay/Juspay), is unaudited and dev-gated, and **has never been run against a
  live provider account**.
- `docs/decisions/0034-billing-provider-seam.md` — **NEW ADR 0034**, plus its index row
  (Accepted, 2026-07) and a banner line in `docs/decisions/README.md`.
- `journal.md` — this entry + RESUME ANCHOR bumped to **through Phase 45**.

### ➡️ Still open (honest)
- **Verify every provider scheme against a live merchant dashboard** — Juspay first, then
  Razorpay's event-ID header and subscription event names, then a Stripe CLI replay. This
  is the gate before any real money.
- **Wire recurring subscription creation** for Razorpay (`/v1/subscriptions`) and Juspay
  (mandates); today only the webhook side models them.
- **Enforce entitlement** somewhere (the op-log routes are the obvious consumer), which
  needs the account model first.
- **Decide whether billing stays in `sigild`** — the ADR deliberately leaves it open.
- (Committed after this entry was written: Phase 45 is `9d87eb5` on `main`.)

---

## 2026-07-26 — Phase 46 (device-to-device VAULT SHARING: a random per-vault key, wrapped with the PQ-hybrid seal, relayed as an opaque envelope)

### Why this phase, and what it fixes
Two facts had been sitting next to each other, unresolved.

1. **Phase 41/42 gave us authorization, not key distribution.** A grant decides *who the
   server will talk to*. It says nothing about *who can decrypt*, because the server holds
   no key. So a second device could be perfectly authorized to `pull` a vault's containers
   and still open **none** of them — every vault was sealed under **one human's password**.
   The only way in was to tell the other device the password, which is not a design, it is
   a confession.
2. **Every hybrid primitive we built was unused.** X25519, ML-KEM-768, the hybrid KEM
   combiner (ADR 0011), Ed25519, ML-DSA-65, the hybrid signature (ADR 0012), and the
   KEM-then-AEAD `hybrid_seal`/`hybrid_open` (ADR 0013) — each ADR closed with the same
   caveat: **standalone, not wired into any flow**. The CLI and wasm client only *demoed*
   the seal by encrypting a file.

Phase 46 joins them: a feature that needs public-key encryption, meet the public-key
encryption path with no feature.

### The key hierarchy (the whole design in five lines)
```
human password ─Argon2id─▶ seals a PERSONAL vault.  NEVER shared, NEVER wrapped, never sent.
vault key = 32 CSPRNG bytes ─▶ seals a SHARED vault, through the SAME SIGILcli container
     └─ hybrid_seal to each recipient device's hybrid PUBLIC key (X25519 + ML-KEM-768)
        ─▶ an OPAQUE SIGILhyb envelope that sigild relays and cannot read.
```
⭐ **The trick that made this cheap: NO CONTAINER FORMAT CHANGE.** The `SIGILcli` container
takes arbitrary password **BYTES** — it runs Argon2id over whatever it is handed — so a
random 32-byte key drops straight in. A shared vault is byte-for-byte the same shape as a
personal one, and the CLI, the wasm client, the desktop core and the extension all keep
reading it **unchanged**. (The Argon2id pass over an already-uniform key is redundant work,
kept deliberately: it is what buys the zero-format-change property. Replacing it with a
direct KDF is a future, format-breaking change.) That mattered because `SIGILcli` is
hand-mirrored across four client surfaces — changing it means changing all of them at once.

### What was built
**`sigild` — a key relay, deliberately the dullest component in the repo** (`internal/api/sharing.go`,
`internal/store/keysharing.go`, `internal/store/postgreskeysharing.go`). Four routes, all
behind the **same** dev gate and the **same** v3 choke points (`authenticateDevice` /
`authorizeVault` / `authorizeOpsRequest`) — ⚠️ **there is NO new auth path**:
- `PUT|GET /v1/devices/{deviceID}/hybrid-key` — publish/fetch a device's hybrid **PUBLIC**
  key. Publish is **self-only** (path ID ≠ authenticated ID ⇒ **403**); body ≤ 8 KiB; fetch
  is open to any authenticated active device (they are public keys — auth only stops the
  registry being world-enumerable) and 404s `hybrid_key_not_found`.
- `PUT|GET /v1/vaults/{vaultID}/keys/{deviceID}` — deposit/collect the **opaque wrapped
  vault key**. PUT needs **write** (a first deposit CLAIMS an unowned vault, trust-on-first-
  write, same rule and same code path as a first append) → **201**; `404 device_not_found`
  / `409 device_revoked` / `413` over `MaxKeyEnvelopeBytes` = 16 KiB. GET requires the
  caller to **BE the addressee AND hold read** — otherwise **403, never 401 and never 404**
  (a 401 would be a lie; a 404 would leak whether an envelope exists) — and returns the
  **exact stored bytes** as `application/octet-stream`.

⭐ **The server's ONLY inspection of key material is a LENGTH CHECK** (`ValidateHybridPublicKey`:
32 / 1184 bytes). No curve-point parse, no low-order screen, no "do these two halves belong
together" — doing any of that would be the server performing cryptography on user key
material. Correctness of a published key is the **client's** business.

Migration **`0004_key_sharing.sql`** (`sigil_device_hybrid_keys`, `sigil_vault_key_envelopes`,
+ a by-recipient index) is purely additive — `sigil_vault_ops`, its hash chain, the registry,
the grants table and the billing tables are byte-for-byte untouched ⇒ **`sigild_schema_version`
now 4**. Both are UPSERTs, so re-sharing after a re-key replaces the envelope. Audit events
`device.hybrid_key_published` / `vault.key_envelope_put` / `vault.key_envelope_get` carry
metadata + a **`blob_sha256` fingerprint** and never the bytes; three count-only metrics with
no vault/device label.

**`sigil` CLI — the client half.** `device hybrid-publish` (creates the hybrid identity if
absent, publishes only the public half; refuses to silently overwrite a secret whose `.pub`
is missing, because that would orphan every envelope already addressed to it), and
`vault rekey | share | accept | list`. `share` deliberately does **both halves in one
command** — wrap + deposit, **then grant through the EXISTING grant route** — so
authorization and key distribution cannot drift apart. `wrap_vault_key` /
`unwrap_vault_key` are thin, explicit wrappers over `hybrid_seal_to_container` with **fresh
ephemeral entropy per call**, and unwrap **rejects any recovered plaintext that is not
exactly 32 bytes** rather than using it as a key. Local state (never uploaded): the hybrid
secret at `$HOME/.sigil/device.hybrid` (0600) + `.pub`, and the keyring
`$HOME/.sigil/vault-keys.json` (0600). ⭐ **A vault key is NEVER printed** — only
`vault_key_fingerprint`, the first 16 hex chars of its SHA-256, so two devices can prove
they hold the same key without revealing it. `sigil totp …` gained **`--vault-id <id>`**
(open with the vault key instead of `SIGIL_PASSWORD`) — purely additive, `--vault <file>`
keeps its meaning, so **every existing invocation behaves exactly as before**; `totp code`
gained `--at <unix>` so a code is reproducible across two machines in a proof.

### ✅ VERIFIED FIRST-HAND (this session, no mocks anywhere)
- `go test ./...` across `sigild` — **green** (`api`, `store`, `billing`, `cmd/server`),
  including the new `sharing_test.go` (18 cases: verbatim+addressed relay, third-device
  403, read-only grantee cannot deposit, revoked refused, publish-for-another-device 403,
  malformed key rejected, oversized 413, dev-gated 501, **and a no-envelope-bytes-in-logs
  test**) and the backend-agnostic `keysharing_test.go` conformance suite.
- `cargo test --manifest-path cli/Cargo.toml` — **green**, incl. the new unit tests: a vault
  key is 32 bytes and differs per call; the keyring round-trips and is **0600**; **a vault
  key seals a vault exactly like a password** (still a `SIGILcli` container); wrap/unwrap
  round-trips, the envelope does **not** contain the key in the clear, a different device
  cannot open it, and two wraps of the same key differ; a non-32-byte payload is rejected;
  the fingerprint is stable, short, hex, and is not the key.
- ⭐ **`./cli/tests/e2e-sharing.sh` — PASS.** Builds the REAL `sigild` + the REAL `sigil`,
  boots sigild on a free loopback port (`SIGILD_ENABLE_DEV_OPS=1`, `SIGILD_DEVICE_AUTH=1`),
  enrolls **three** devices with **separate `HOME`s** (so separate identities, hybrid
  identities and keyrings — three machines in effect), and asserts:
  - **THE HEADLINE — two devices, the same code.** A puts the public RFC 6238 seed in a
    vault, re-keys it, pushes, shares to B; B accepts, pulls, and generates
    **`A=94287082  B=94287082  RFC 6238 vector=94287082` at T=59 — all equal.**
    Fingerprints matched (`4c1a3e03b354a7a7` on both), so B recovered *the same key*.
    The uploaded envelope was **1226 bytes**.
  - **THE ZERO-KNOWLEDGE CHECK.** `cmp` of uploaded vs. server-returned bytes:
    **byte-identical**. The envelope starts `SIGILhyb`. It contains **neither** the base32
    seed **nor** the raw `12345678901234567890` secret. And the server's own log contains
    **no** `SIGILhyb` — only `vault.key_envelope_put` / `_get` lines with `blob_sha256`.
  - **THE AUTHORIZATION RESULTS.** Device C (enrolled, unauthorized) is **403** fetching
    B's envelope, **403** fetching one for itself, **403** reading the op-log, and **403**
    depositing on a vault it does not own — and after fabricating its own key for the same
    vault ID, C's fingerprint (`b9134efac5db48d7`) ≠ A's, and C **cannot open** the shared
    container at all. A **revoked** device B is **401** on accept, on hybrid-publish and on
    pull. ⚠️ And the script asserts the honest limit as a *test*: B still generates correct
    codes **locally** after revocation.
- Also re-confirmed: `SIGIL_PASSWORD` **no longer opens** the re-keyed vault — the password
  was never shared, wrapped, or sent.

### ⚠️ HONEST LIMITS — do not paper over
- ⭐ **The hybrid primitives are now LOAD-BEARING, so they are squarely IN SCOPE for the
  audit.** "Standalone building block" is no longer an available excuse for `hybrid.rs`,
  `hybrid_seal.rs`, `kx.rs` or `mlkem.rs`. A flaw there is a flaw in a user-facing path.
- **Still a CUSTOM KEM-then-AEAD, NOT RFC 9180 HPKE**; still **UNAUDITED**; the **SYSTEM is
  still NOT "post-quantum secure"**.
- **The hybrid SIGNATURE remains unused.** All request auth — including every sharing route
  — is **classical Ed25519** (contract v3). The wrap is hybrid; the authentication is not.
- ⭐ **THE BIGGEST GAP: no out-of-band verification of a published hybrid public key.** A
  sender wraps to whatever the registry serves. A malicious server that substitutes its own
  hybrid key would receive a vault key wrapped **to itself**. No safety numbers, no key
  transparency, no cross-signature binding the hybrid key to the device's enrolled Ed25519
  identity. Comparing `vault list` fingerprints out of band detects the result *after the
  fact*; it does not prevent the substitution.
- **A compromised or revoked device KEEPS any vault key it already unwrapped.** Revocation
  stops FUTURE server access only; the container it already pulled stays openable offline.
  Remediation is a **manual** `vault rekey` + re-share.
- **NOT implemented: key rotation schedule, automatic re-wrap on revoke, forward secrecy for
  a delivered vault key, envelope expiry, recovery.** Republishing a hybrid key does **not**
  re-wrap envelopes already deposited for that device.
- **One mailbox per (vault, recipient)** and a deposit is an upsert, so any device with
  `write` can overwrite another writer's envelope. Sharing also inherits **trust-on-first-write**.
- **No rate limiting** on the sharing routes (the per-vault limiter covers appends only).
- **Local key storage is filesystem permissions, nothing more** — the hybrid secret and the
  keyring are 0600 plaintext files: not sealed under the password, not zeroized, no enclave.
- **Only the CLI implements sharing.** The webapp, extension and desktop clients do not.
- Dev-gated (`501` by default), localhost, plain HTTP. **Do not store real 2FA secrets.**

### Docs updated in the same change
- `docs/crypto-spec.md` — ⭐ **the load-bearing correction**: every "standalone / not wired
  into any flow" statement about the hybrid **KEM** and `hybrid_seal`/`hybrid_open` was
  corrected to say they now carry **vault-key wrapping**, while the caveats were *sharpened*
  rather than deleted (custom KEM-then-AEAD ≠ HPKE, UNAUDITED, system not PQ-secure) and the
  hybrid **signature** was explicitly re-stated as **still unused**. Plus a new
  **Key hierarchy and vault sharing** section: the three layers, exactly what the server sees
  vs. cannot do (as a table), and the honest limits.
- `docs/api.md` — a full **Device-to-device vault sharing** section: all four routes with
  auth/request/response/status codes, the 401-vs-403 rules, every size cap, the storage and
  migration `0004`, the audit events, CLI client support, and honest limits; plus the three
  new metric rows, `sigild_schema_version` → **4**, the route/permission table, and the
  `501` default posture (now nine routes, with the new detail string).
- `docs/architecture.md` — the same standalone/not-wired corrections in the component map
  and §3/§6, the sharing relay in the `sigild` bullet, the sharing commands in the `cli`
  bullet, and a new **§2b data-flow diagram** for sharing + the zero-knowledge boundary.
- `docs/threat-model.md` — a new **vault-sharing** adversary table (R–W: malicious server
  reading a relayed envelope, unauthorized device, revoked device, device publishing a key
  it does not own, envelope replay/substitution, log/metrics scraper) with an explicit
  "what this does NOT defend" list; the closing status note corrected (the crypto is no
  longer all unused).
- `CLAUDE.md` — the sharing routes/migration/caps in a new `sigild/` bullet, the CLI
  commands and key hierarchy in the `cli/` bullet, the e2e script added to the known-green
  commands, and the hybrid-primitive framing corrected to match reality.
- `README.md` — an honest note that vaults can be shared between enrolled devices with
  post-quantum-hybrid key wrapping, still dev-gated and unaudited; the top banner's
  "not wired into any product flow" corrected.
- `docs/decisions/0035-device-to-device-vault-sharing.md` — **NEW ADR 0035**, plus its index
  row (Accepted, 2026-07) and a banner line in `docs/decisions/README.md`.
- `journal.md` — this entry + RESUME ANCHOR bumped to **through Phase 46**.

### ➡️ Still open (honest)
- ⭐ **Bind a hybrid public key to the device's enrolled Ed25519 identity** (self-sign the
  hybrid key with the device key at publish time, and verify it at wrap time). That closes
  the registry-substitution gap and is the single highest-value follow-up.
- **Rotation + re-wrap on revoke**: make `vault rekey` re-share automatically to every
  remaining grantee, so revocation has a real remediation path.
- **Teach the other clients to share** — the browser/extension/desktop surfaces have the
  wasm `hybrid_*` exports already; they need the keyring + the four routes.
- **Wire the hybrid SIGNATURE into something** — it is now the only hybrid construction
  still used by nothing.
- (Committed after this entry was written: Phase 46 is `ab50783` on `main`.)

---

## 2026-07-27 — Phase 48 (vault sharing reaches the BROWSER clients: webapp + MV3 extension)

### Why this phase, and what it fixes
Phase 46 shipped device-to-device vault sharing and closed with an explicit limit:
**"Only the CLI implements sharing. The webapp, extension and desktop clients do not."**
That is a real hole, not a cosmetic one — a sharing feature that exists in exactly one
client is a demo, and the two browser surfaces were already the ones a user would
actually reach for. Phase 48 closes it for the browsers. Desktop still does not share.

The pleasing part: **nothing new had to be built underneath.** The wasm exports the
browsers need (`hybrid_x25519_public`, `hybrid_mlkem_encaps_key`,
`hybrid_seal_to_container`, `hybrid_open_container`) have existed since Phase 31, and
`sigild` already served the four routes. **No Rust source changed and `sigild/`, `cli/`,
`libsigil/` and `desktop/` were untouched.** What was missing was a client half in
JavaScript and an answer to "where does a browser keep a hybrid secret".

### What was built

**`sigil-wasm/sharing.mjs` — NEW.** Framework-free, dependency-free ESM, Node **and**
browser, mirroring `cli/src/lib.rs` and `sigild/internal/api/sharing.go`. Exports:
`generateHybridIdentity` / `hybridPublicIdentity`, `publishHybridKey` /
`fetchHybridKey`, `generateVaultKey` / `vaultKeyFingerprint`, `wrapVaultKey` /
`unwrapVaultKey`, `putKeyEnvelope` / `getKeyEnvelope`, the two composed operations
`shareVault` / `acceptVault`, and `explainSharingStatus`.

- ⭐ **It does NO cryptography.** The KEM/AEAD happens in the wasm; every request
  signature goes through `device-auth.mjs`. Nothing is hand-rolled.
- ⭐ **Every byte of entropy is `crypto.getRandomValues`** — the hybrid identity, each
  vault key, and the per-wrap ephemeral X25519 secret / ML-KEM coin / AEAD nonce. Both
  `Cargo.lock`s stay `getrandom`==0.
- `shareVault` deliberately does **wrap + deposit and THEN the grant through the
  EXISTING `grantVaultAccess`** — the same composition as `sigil vault share`, so
  authorization and key distribution cannot drift apart.
- `unwrapVaultKey` **rejects any recovered plaintext that is not exactly 32 bytes**
  rather than using it as a key (the CLI's rule, mirrored).
- `explainSharingStatus` extends `explainAuthStatus` with the statuses only these
  routes produce, so a UI can say "not signed in" (401) vs "that envelope is not
  yours" (403) vs "nothing shared yet" (404) instead of one generic error.

**The storage decision — the important part (ADR 0036).** ⭐ **Nothing new is persisted
in the clear.** Sharing puts two more classes of bearer secret on a browser: the
**hybrid SECRET identity** (the only thing that can open an envelope addressed to this
device) and the **vault keyring** (a 32-byte key per shared vault). The CLI keeps those
in `0600` files; a browser has no equivalent. Rather than adding a store, the **EXISTING
sealed device-identity container was extended v1→v2**:

```
{ version: 2, device_id, seed, base_url,
  hybrid: { x25519_secret, mlkem_seed },
  vault_keys: { "<vaultID>": "<b64 32 bytes>" } }
```

So the Ed25519 device seed, the hybrid secret and every accepted vault key sit inside
**one** container sealed under the vault password, and each client persists exactly
**TWO** values, both sealed `SIGILcli` containers: `sigil.webapp.vault.v1` +
`sigil.webapp.device.v1`, `sigil.extension.vault.v1` + `sigil.extension.device.v1`.
Verified by grep that **all eight persistence writes across the two clients are
`bytesToBase64(container)`**. `DEVICE_IDENTITY_VERSION = 2`; **v1 containers still open**
(→ `hybrid: null`, empty keyring), so it is backward compatible with no migration step.
The password and every decrypted secret are memory-only and are dropped on lock / forget
/ unload.

**Both clients got the FULL flow, not a reduced one** — webapp `SharingPanel` in
`app/authenticator.tsx`, extension Sharing section in `popup.html` + `popup.js`:
show/copy this device id · publish this device's hybrid key · convert a password vault
into a shared vault sealed under a fresh random 32-byte key · share to a pasted
recipient device id with read/write · accept a vault shared to this device. **Unlock
changed in both:** it opens the device identity FIRST (with the password), tries the
password on the vault, then **falls back to each held vault key**, so a shared vault
re-opens after a reload. `extension/build.sh` now vendors `sharing.mjs` alongside
`totp-vault.mjs` / `totp-migration.mjs` / `sync.mjs` / `device-auth.mjs` (it imports two
of them, so all five must stay siblings), and `@sigil/wasm` re-exports it for the webapp.

### ✅ VERIFIED FIRST-HAND (this session)
- `cargo fmt` / `clippy -D warnings` clean; **26** wasm tests.
- ⭐ **ALL EIGHT Node tests PASS** — `roundtrip`, `interop`, `hybrid-interop`,
  `sync-interop`, `totp-interop`, `migration-interop`, `device-auth-interop`, and the
  new **`sharing-interop`**.
- **webapp** typecheck / lint / build green, **Playwright 8/8**; **extension 3/3**;
  marketing build green.
- **Both `Cargo.lock`s still `getrandom`==0**; nothing changed under `sigild/`, `cli/`,
  `libsigil/` or `desktop/`.
- ⭐ **THE CROSS-CLIENT PROOF — `sigil-wasm/test/sharing-interop.mjs`**, which boots a
  real `sigild` and builds the **REAL `sigil` binary** (no mocks):
  - **(a) browser → CLI.** The JS client sealed a vault under a random vault key, pushed
    it, and shared a **1226-byte** envelope to the CLI device. The **real `sigil`
    binary** accepted it, unwrapped it to the **SAME key fingerprint**, pulled the vault
    and printed **`94287082`** at T=59 — the published RFC 6238 vector.
  - **(b) CLI → browser.** The CLI shared to the JS device; both produced **`94287082`**.
    And the human password does **NOT** open that vault — proving it is sealed under the
    random vault key, not the password.
  - **Negatives.** An unauthorized third identity is **403** fetching another device's
    envelope, **403** fetching its own, and **403** depositing.
  - **Zero-knowledge.** The relayed envelope is **byte-identical** ciphertext containing
    no plaintext key and no seed; two wraps of the same key differ (no entropy reuse);
    the server logged only fingerprints.

### ⚠️ HONEST LIMITS — inherited from Phase 46 and unchanged
- ⭐ **NO out-of-band verification of a published hybrid public key.** A hostile or
  compromised registry could substitute its own key and intercept a share — the
  recipient device id and the key served for it are simply **trusted as served**. This
  remains the single largest gap, and a paste-a-device-id UI makes it easier to walk
  into than a CLI flag did.
- **JS `Uint8Array`s holding secrets are not zeroized.** While the vault is unlocked the
  hybrid secret and every vault key sit in the JS heap; lock/forget/reload drop the
  references but nothing scrubs the bytes. No `mlock`, no enclave.
- **Revocation cannot un-learn a vault key a device already accepted.** It stops FUTURE
  server access only.
- **No key rotation and no re-wrap-on-revoke.**
- **Converting a personal vault to a shared vault is a ONE-WAY DOOR in the UI**, and a
  shared vault has no password fallback — losing the password loses the keyring with it,
  and there is no recovery path.
- **Dev-gated, plain HTTP on loopback, UNAUDITED.** Do NOT store real 2FA secrets.

### Docs updated in the same change
- `docs/architecture.md` — `sharing.mjs` added to the `sigil-wasm` bullet; the sharing
  panel + the v2 sealed device container + the unlock fallback in the **webapp** and
  **extension** bullets; §2b now states the flow is **not CLI-only** (either end may be a
  browser) and its honest limits gained the one-way door + no-zeroization notes.
- `docs/api.md` — a new **Client support (the browser + Node clients)** subsection in the
  sharing section (the module→route table, `auth` shape, supporting surface, and the
  interop guard), the stale "the browser, extension and desktop clients do not implement
  sharing yet" corrected to desktop-only, and one honest-limits bullet on client-side key
  storage.
- `docs/crypto-spec.md` — a new **"The same hierarchy, exercised from the browser"**
  subsection (wrap/unwrap still happen in the wasm; entropy is `crypto.getRandomValues`),
  and a no-zeroization limit.
- `docs/threat-model.md` — a new **"Browser clients that also SHARE vaults"** subsection
  (two more bearer secrets, sealed at rest in the v2 container, exposed unzeroized in
  memory, no password recovery for a shared vault, a pasted device id is trusted as
  typed); the R–W table marked client-agnostic; the local-key-storage limit rewritten to
  cover both clients.
- `docs/deployment.md` — corrected the stale "the only client that consumes this server
  is the CLI".
- `docs/decisions/0035-device-to-device-vault-sharing.md` — a **"Browser client support
  (added Phase 48)"** section recording that the webapp and extension implement the flow
  and that the protocol is unchanged.
- `docs/decisions/0036-browser-sharing-secret-storage.md` — **NEW ADR 0036** for the
  narrow storage decision (extend the sealed device container to v2 rather than add a
  store), plus its index row and a banner line in `docs/decisions/README.md`.
- `CLAUDE.md` — the `sigil-wasm` bullet (`sharing.mjs` + the v2 container), the webapp
  and extension bullets (sharing panel, v2 container, unlock fallback), and the
  known-green command list now naming **all EIGHT** Node tests.
- `README.md` — one honest sentence that every client which talks to the server can now
  share (CLI, webapp, extension), still dev-gated and unaudited.
- `journal.md` — this entry + RESUME ANCHOR bumped to **through Phase 48**.

### ➡️ Still open (honest)
- ⭐ **Bind a hybrid public key to the device's enrolled Ed25519 identity** (self-sign at
  publish, verify at wrap). Still the highest-value follow-up, and now it protects three
  clients instead of one.
- **Rotation + re-wrap on revoke**, so revocation has a real remediation path.
- **Teach the DESKTOP client to share** — the last client surface without it.
- **Wire the hybrid SIGNATURE into something** — still the only hybrid construction used
  by nothing.
- **Playwright coverage for the sharing UI** — the protocol is proven live in Node, but
  nobody has driven the publish/convert/share/accept buttons in a headless browser (the
  same honest gap the enrollment UI has).

---

## 2026-07-27 — Phase 49 (the NATIVE DESKTOP client joins the network: enrollment, contract-v3 sync, sharing)

### Why this phase, and what it fixes
Phase 48 closed with an explicit item: **"Teach the DESKTOP client to share — the last
client surface without it."** It was worse than that, actually: the desktop had no
network at all — no enrollment, no sync, no sharing. It opened the same vault *file* as
the CLI and stopped there. Phase 49 closes it. **All four client surfaces (CLI, webapp,
MV3 extension, native desktop) are now peers on the network.**

### The engineering decision that shaped the phase
⭐ **Reuse the `sigil-cli` LIBRARY; do not reimplement the protocol.** The canonical
contract-v3 signed message already exists in **three** implementations —
`sigild/internal/api/deviceauth.go` (Go, the source of truth), `cli/src/lib.rs` (Rust),
`sigil-wasm/device-auth.mjs` (JS) — kept byte-identical **only** by interop tests, and
drift there does not fail loudly: it produces a `401` on every request, which looks
exactly like a bad key or a skewed clock. Writing a fourth copy in `desktop/core` was the
obvious way to do this phase. It was rejected.

`desktop/core/src/net.rs` therefore imports **30 symbols** from `sigil_cli` in one `use`:
`enroll_device`, `fetch_hybrid_key`, `generate_hybrid_identity`, `generate_key`,
`generate_vault_key`, `get_key_envelope`, `grant_vault_access`, `keyring_get`,
`keyring_put`, `load_hybrid_public`, `load_hybrid_secret`, `load_identity`,
`load_key_file`, `load_keyring`, `publish_hybrid_key`, `pull_ops_auth`, `push_op_auth`,
`put_key_envelope`, `save_hybrid_public`, `save_hybrid_secret`, `save_key`,
`unwrap_vault_key`, `vault_key_fingerprint`, `wrap_vault_key`, `CliError`,
`DeviceIdentity`, `RequestAuth`, `VaultKeyring`, `VAULT_KEYRING_FILE`, `VAULT_KEY_LEN`
(plus `sigil_cli::open_vault` by path).

✅ **Verified by grep, not by assertion:** `desktop/` contains **ZERO** copies of the
canonical v3 message domain, **ZERO** copies of the enrollment-challenge domain, **ZERO**
direct `ureq`/`reqwest` calls, and **ZERO** direct Ed25519 signing. The canonical bytes
stay at three implementations.

**What could NOT be reused** — and is therefore the only new code — is app config and UI
wording, with no protocol and no crypto in it: the CLI's path-resolution and
error-explanation helpers live in `cli/src/main.rs`, i.e. the **binary**, so they are not
importable. `DeviceConfig` re-derives the same file names, and `net_error` maps `CliError`
onto typed `DesktopError` variants. **`cli/` was not edited.**

⭐ **The consequence worth remembering:** because the CLI's own writers and file names are
used, the desktop state files are **interchangeable with the CLI's**. Point `sigil --key`
(or `HOME`) at a desktop state directory and it is *literally the same device*.

### What was built

**`desktop/core/src/net.rs` — NEW.** `DeviceConfig` (`new` / `for_server`, state dir
defaulting to `$HOME/.sigil`) with `enroll`, `publish_hybrid`, `push_vault` /
`push_vault_file`, `pull_vault`, `share_vault`, `accept_vault`, `status`, `check_server`;
plus `VaultSession::convert_to_shared` / `unlock_shared` and the free `pull_and_adopt`.
Contract selection is the CLI's rule, unchanged: **v3 when enrolled**, legacy **v2** when
an identity has no device id, **unsigned** when there is no identity.

Three shapes were deliberate:

- ⭐ **`status()` is purely LOCAL.** It reads disk only, never opens a socket — so it
  works offline, renders with no server configured, and **cannot fail because a server is
  down**. It reports fingerprints only, never a key.
- ⭐ **`check_server` reports reachability as DATA, not an error** (`ServerCheck {
  reachable, hybrid_published, detail }`). Offline is a normal state for this app, not an
  exception.
- ⭐ **`pull_and_adopt` opens the pulled container BEFORE writing it** (then temp-file +
  rename, `0600`), so a container this device cannot read — or one a server mangled — can
  **never clobber a good vault**.

**11 new `#[tauri::command]`s** (10 → 21) over `AppState { session:
Mutex<Option<VaultSession>>, sync: Mutex<Option<DeviceConfig>> }`: `unlock_shared`,
`set_server`, `sync_status`, `enroll`, `publish_hybrid`, `check_server`,
`convert_to_shared`, `push`, `pull`, `share`, `accept`. Each **clones the config out of
the mutex before any network call**, so no lock is held across I/O. Errors reach the UI
**tagged distinctly** — `unauthenticated` (401), `not authorized` (403), `route disabled`
(501), `nothing there` (404), `server unreachable`, `not enrolled`, `already enrolled`,
`not a shared vault` — because those are genuinely different situations for a user.

**Secrets — the native model, identical to the CLI's**, all inside a **`0700`** state
directory (`$HOME/.sigil` by default): `device.key` (Ed25519 seed + device id) **0600**,
`device.hybrid` (X25519 secret + ML-KEM seed) **0600**, `device.hybrid.pub` (public only),
`vault-keys.json` (vault id → 32-byte key) **0600**, `totp-vault.sigil` **0600** via
temp-file + rename. Modes are asserted in the tests. ⭐ **Never printed, logged or returned
across the IPC:** the Ed25519 seed, the hybrid secret, the vault key, the human password,
the enrollment token — only device ids and SHA-256 fingerprints. Verified there are **no
prints outside the pre-audit banner**. The enrollment token is a **password-type field**,
used for one call, cleared in a `finally`, never stored.

### ✅ Verified first-hand (the gate)
- `cargo fmt --check` clean; `cargo clippy --all-targets -- -D warnings` clean.
- **The full desktop suite passes: 15 unit tests + the pre-existing `cli_interop` + the
  new `server_interop`.**
- `cargo build --release` succeeds.
- `grep -c 'name = "getrandom"' libsigil/Cargo.lock` still **0**.
- Changes **confined to `desktop/`**; the other clients are unaffected (sigil-wasm
  `sharing-interop` and `sync-interop` still pass).

### ⭐ THE PROOF — `desktop/core/tests/server_interop.rs`
Boots a **REAL `sigild`** (dev ops + device auth, contract v3) on a free loopback port and
builds the **REAL `sigil` binary**. No mocks, no stubs, no fake HTTP. The clock is pinned
via **`period = 1_600_000_000`**, so the TOTP counter equals RFC 6238 Appendix B's `T=59`
counter for every instant from **2020 to 2071** — which is why two independently-clocked
processes must both print the published vector.

1. `status` reads with **no state at all**, and contract-v3 ops report **NotEnrolled**.
2. The desktop **enrolls** (identity `0600` inside a `0700` dir; a second enroll is
   `AlreadyEnrolled`, never a silent overwrite of the device's only credential).
3. It **publishes its hybrid public key** (secret `0600`, **never uploaded**).
4. It **re-seals the vault under a random 32-byte vault key**, so **the password no longer
   opens it** — the human password is never shared, wrapped or uploaded.
5. It **pushes** the opaque container as **seq 1, contract-v3 signed**.
6. **(a) DESKTOP → op-log → CLI:** the real `sigil totp code` printed **94287082** (RFC
   6238 App B) from a vault the desktop sealed, pushed and shared. The pulled bytes are
   **byte-identical** to the pushed bytes and contain neither the seed nor the label.
7. **(b) CLI → op-log → DESKTOP:** the desktop **unwrapped the same key** (same
   fingerprint) and computed **94287082** from the CLI's vault.
8. **Negatives:** an enrolled but **unauthorized third device is 403** on read and on
   accept; an **unenrolled desktop gets a clear `NotEnrolled` error rather than a panic**
   (and a failed op creates no state); with the server unreachable there is a clear
   **`Unreachable`** error **and the offline flow still generates codes**.

### ⚠️ Honest limits (carry these)
- ⭐ **The desktop stores its secrets as `0600` PLAINTEXT files** — the documented native
  model, and **weaker at rest than the browser clients**, which seal everything into a
  `SIGILcli` container under the vault password (ADR 0036). The asymmetry is worth stating
  plainly and is now in the threat model: an offline attacker who can read `$HOME` as that
  user gets the device identity, the hybrid secret and every accepted vault key. The
  defense is the OS (file modes + full-disk encryption).
- **No zeroization.** The password is best-effort zeroed on `Drop`; nothing else is
  scrubbed, and there is no `mlock` and no enclave.
- **The inherited sharing limits apply unchanged:** ⭐ **no out-of-band verification of a
  published hybrid public key** (a hostile registry could substitute one — still the
  biggest gap in the design); **revocation cannot un-learn** a vault key a device already
  accepted; **no key rotation and no re-wrap-on-revoke**.
- **The server side is still dev-gated, plain HTTP on loopback, and UNAUDITED.**
- **The GUI remains build-and-launch verified, not visually verified** in this
  environment — which is tolerable only because **all behaviour lives in the headless core
  that the tests drive**.
- ⚠️ **CI gap not closed here:** `.github/workflows/desktop.yml` runs a bare `cargo test`,
  which now also picks up `server_interop` — and that test builds `sigild` with the Go at
  `/opt/homebrew/bin/go` unless `GO=` is set, a path that does not exist on a GitHub
  runner. The workflow was **not** edited (this was a docs pass); either set `GO` or scope
  the CI test step before relying on that job.
- **Do NOT store real 2FA secrets.**

### Docs updated in the same change
- `docs/architecture.md` — the `desktop` bullet now records the network half (the
  operations, contract selection, the 30 reused `sigil-cli` symbols and the avoided fourth
  canonical-message copy, the interchangeable state files, local-only `status()` vs
  `check_server`-as-data, open-before-write, the tagged errors, the at-rest asymmetry, and
  the `server_interop` proof), 21 Tauri commands in the client diagram, §2b's sharing flow
  is now "all four clients", and §6's stale "no sync, no device enrollment" is retired.
- `docs/api.md` — the contract-v3 CLI section and the canonical-message note now say the
  desktop added **no fourth copy**; a new **Client support (the native desktop app)**
  subsection under sharing; the client-side key-storage limit covers the desktop.
- `docs/threat-model.md` — a new **native desktop client** subsection (0600 plaintext
  secrets in a 0700 dir, no zeroization, the enrollment token handled once and never
  stored, the webview outside the trust boundary, the inherited sharing limits), explicit
  that the **browser clients are stronger at rest** and why; the sharing table is now
  client-agnostic across four clients; the local-key-storage bullet updated.
- `docs/crypto-spec.md` — the desktop runs the same wrap/unwrap by calling the CLI's
  library, and stores the keyring in the CLI's `0600` files.
- `docs/deployment.md` — the client list now includes the desktop.
- `docs/decisions/0035-device-to-device-vault-sharing.md` — a **"Desktop client support
  (added Phase 49, 2026-07-27)"** addendum retiring the "the desktop still does not" limit,
  reporting only what changed (per the addendum rule in `docs/decisions/README.md`).
- `docs/decisions/0037-desktop-reuses-cli-library-for-protocol.md` — **NEW ADR 0037** for
  the narrow decision (drive the `sigil-cli` library rather than duplicate the wire
  protocol; the alternatives rejected, including extracting a shared `sigil-client` crate,
  which is the likely successor), plus its index row and a banner clause in
  `docs/decisions/README.md`.
- `CLAUDE.md` — the `desktop/` bullet (net.rs operations, the 21 commands, the reuse rule
  and the grep evidence, the state files and modes, the at-rest asymmetry, the
  `server_interop` proof) and the Build & test block (`--test server_interop`, 15 unit
  tests + 2 integration tests), plus the CI-gap note.
- `README.md` — one honest sentence that the desktop now syncs and shares like the others,
  still dev-gated and unaudited.
- `journal.md` — this entry + RESUME ANCHOR bumped to **through Phase 49**.

### ➡️ Still open (honest)
- ⭐ **Bind a hybrid public key to the device's enrolled Ed25519 identity** (self-sign at
  publish, verify at wrap). Unchanged as the highest-value follow-up, and it now protects
  four clients.
- **Rotation + re-wrap on revoke**, so revocation has a real remediation path.
- **Extract a `sigil-client` crate** that both `cli/` and `desktop/` consume, so a GUI does
  not depend on a demo CLI's library target (ADR 0037 names this as its likely successor).
- **Fix `desktop.yml`** so the new `server_interop` test can find a Go toolchain on a
  GitHub runner.
- **Wire the hybrid SIGNATURE into something** — still the only hybrid construction used by
  nothing.
- **Visual / UI-driven coverage for the desktop and browser sharing UIs** — every protocol
  claim is proven headlessly; no test clicks the buttons.

---

## 2026-07-27 — Phase 50 (KEY VERIFICATION: pin device keys, safety numbers, and vault key ROTATION — the documented hole closes)

### Why this phase, and what it fixes
This repo has been carrying a hole **in writing** for four phases. `docs/threat-model.md`
called it *"the single largest gap in the design"*; ADR 0035 recorded it in its own
Consequences; the Phase 48 and Phase 49 journal entries both restate it as an inherited
limit. Stated exactly as it stood:

> **Trust in the published hybrid key is trust in the server's registry.** There is **no
> out-of-band verification** of a recipient's hybrid public key. A malicious server that
> substitutes its own hybrid public key for the recipient's would receive a vault key
> wrapped to itself.

The asymmetry underneath it: **contract v3 authenticates the REQUEST; nothing
authenticates the RESPONSE.** Device A asks the server for B's hybrid public key and
wraps the vault key to whatever comes back. Every other defense in the sharing design is
downstream of that answer being honest — the envelope is unreadable to the server *only*
because it was sealed to a key the server does not hold. Substitute the key and the whole
property collapses, **invisibly**: A sees a successful share, B sees an envelope it cannot
open, which looks exactly like a bug.

The second recorded limit compounded it — **no rotation, no re-wrap on revoke** — so even
after *detecting* a compromise there was no remediation.

### The three decisions (ADR 0038), and why each is shaped the way it is
⭐ **1. PIN, and BLOCK on change — never warn.** The first hybrid public key seen for a
device is pinned; every later fetch compares **decoded RAW bytes of BOTH halves** (so a
server re-encoding the same key cannot raise a false alarm). Unseen ⇒ `FirstSight` (pin,
proceed, **warn**). Identical ⇒ `Match` (proceed silently). **Different ⇒ HARD STOP**:
`CliError::PinMismatch` / `KeyPinMismatchError` / `DesktopError::KeyPinMismatch` — with
**nothing wrapped, nothing uploaded, and the pin store NOT mutated**.

**Blocking rather than warning is the load-bearing choice.** A warning on a key change is
a warning users click through, and the cost of clicking through is total compromise of the
vault being shared. So: **there is no flag, option, env var or default anywhere that makes
a wrap accept a changed key.** The only escape hatch is a separate, deliberate command.

⭐ **The choke point is the FETCH ITSELF.** `fetch_hybrid_key_pinned` (Rust) /
`fetchHybridKeyPinned` (JS) fetch the key **and** check the pin in ONE call, and **every**
wrap path — `vault share` *and* `vault rotate`, in both implementations — goes through it.
A trust store some code path forgets to consult is worthless, so the check is not a step a
caller can skip. The bare `fetch_hybrid_key` / `fetchHybridKey` survive **only** where
nothing is wrapped: safety-number display, the deliberate re-pin, and desktop
`check_server`.

⭐ **2. SAFETY NUMBER for what pinning structurally cannot do.** Pinning is worthless on
the *first* fetch — if the server lies then, the lie is what gets pinned. So:

```
digest = SHA-256( "sigil-safety-number-v1\n"
                ‖ u32_be(len(device_id)) ‖ device_id
                ‖ u32_be(32)             ‖ x25519_public_key
                ‖ u32_be(1184)           ‖ mlkem_encaps_key )
rendered = 6 groups × 5 digits; group[g] = u40_be(digest[5g..5g+5]) mod 100000
```

Each choice is deliberate: a **domain-separated prefix**; **length-prefixed fields** so
`"ab"+"c"` cannot collide with `"a"+"bc"`; **BOTH key halves covered** (a swap of only the
ML-KEM half still changes the number); **the device id bound in** (a genuine key replayed
under a different device's id does not verify); **raw bytes, not base64**; and **30 digits
≈ 99.6 bits** — readable aloud, and not searchable for a collision. The **PAIRWISE** form
sorts the two per-device digests **BYTEWISE** before hashing under a separate prefix, and
that sort is the entire trick: it makes the input, and so the output, identical whichever
side computes it, so both people see the SAME digits and cannot compare the wrong pair.

⭐ **3. ROTATION as the remediation revocation never had.** `rotate_vault_key` /
`rotateVaultKey`: load the current key → **PIN-CHECK EVERY RECIPIENT FIRST** → fresh
32-byte key → `reseal_container` (open with old, seal with new, **never inspecting the
plaintext**, so it re-keys a TOTP vault or any `SIGILcli` container identically, no format
change) → write **0600 via temp-file + rename** → `keyring_put` **AFTER** the file is in
place → wrap + upsert per recipient → list + **DELETE every envelope not in the recipient
set**.

Two orderings were chosen for the **failure** case, not the happy path: pin-checking
everyone *before* any mutation means a substituted key aborts the whole rotation with the
vault untouched (a half-rotated vault whose new key had already been wrapped to an
attacker is worse than no rotation); and writing the keyring *after* the file means a
crash between them cannot leave the keyring naming a key that opens nothing.

### Where the pin store lives — each client's existing rule, not a new one
- **Native (`sigil` CLI + desktop, sharing the same file):** `hybrid-pins.json`, **0600 in
  the 0700 state dir**, through the same `write_secret_file` helper as other sensitive
  state (created `0600` up front so it is never briefly world-readable, `fsync`'d,
  re-`chmod`'d). A CLI pin and a desktop pin are literally **one record**.
- **Browsers:** a `pins` field **inside the existing sealed device-identity container**,
  schema **v2 → v3**; v1 and v2 still open and yield an **EMPTY** store, and `pins` is
  omitted when empty so a client that never shared writes the shape it always did.

⭐ The browser choice is the one worth defending: a JSON blob in `localStorage` would have
been trivial and would have **broken the invariant** from ADR 0028 / ADR 0033 that a
browser persists **nothing in the clear**. The pins are *public* key material — but they
are **security-critical LOCAL state**, because anyone who can rewrite them can silence the
alarm. Sealing them is the right treatment.

### `sigild`: two routes, and deliberately no knowledge
`GET /v1/vaults/{vaultID}/keys` (**METADATA ONLY** — device id, sender, size,
`created_at`; **never a blob**, and Postgres selects `octet_length(blob)` so ciphertext
never leaves the DB) and `DELETE /v1/vaults/{vaultID}/keys/{deviceID}`. Both **dev-gated**
with everything else and both reusing the **EXISTING `authorizeOpsRequest` with
`needWrite`** — the same check that authorizes depositing an envelope. That is the correct
bar rather than a stricter one: **a device that can deposit an envelope can already
REPLACE any envelope in the vault**, so enumerate + delete grants it no new power.
`sigild` **stores, serves and validates NO pin and NO safety number** — the trust
mechanism is entirely client-side, which is the only place it can live when the adversary
*is* the server. Still **501 by default**; still **exactly ONE direct dependency**.

### ⚠️ The fix I made beyond the phase — `requirePinStore` now FAILS CLOSED
`requirePinStore(store)` previously returned a **fresh empty store** for `null`/`undefined`.
That is the wrong failure mode for a security control: a caller that forgot to pass its
pins would silently get **"every key is first-sight"** — pinning would quietly stop
protecting anything, with **no error anywhere**, and the exact attack this module exists to
block would succeed. It now **throws**.

Flipping it immediately **surfaced a genuine stale caller**: the Phase-48
`sharing-interop.mjs` predates pinning and was relying on the fallback. It now supplies a
pin store explicitly. Worth recording because it is precisely the class of
**silent-degradation** bug this project has been bitten by before — a control that still
"passes" while protecting nothing.

### ✅ VERIFIED FIRST-HAND (the gate)
- **ALL NINE node tests pass** (roundtrip, interop, hybrid-interop, sync-interop,
  totp-interop, migration-interop, device-auth-interop, sharing-interop, **pinning-interop**).
- **cli: 77 tests.** **desktop: 15 unit + its integration tests.** **sigild: `go test -race`
  green across 4 packages**, one direct dependency. **webapp build + Playwright 8/8.**
  **extension 3/3.** **`libsigil` `getrandom` still 0.**

⭐ **THE ATTACK IS BLOCKED — proven live, no mocks** (`sigil-wasm/test/pinning-interop.mjs`).
A **transparent rewriting proxy** sits in front of a REAL `sigild` and, when armed,
rewrites the response body of `GET /v1/devices/{B}/hybrid-key` to an **ATTACKER's** hybrid
public key. Requests are forwarded verbatim, so the clients' contract-v3 signatures still
verify — **which is exactly the point: the request is authenticated, the RESPONSE is not.**
Results:

- the CLI **REFUSES**, with an error that **NAMES BOTH SAFETY NUMBERS**, explains it is
  either a **KEY-SUBSTITUTION ATTACK** or a **LEGITIMATE RE-ENROLMENT**, states that **no
  vault key was wrapped and nothing was uploaded**, and tells the user to confirm the
  number out-of-band and then re-pin deliberately;
- ⭐ the part that actually matters: the envelope stored for B is **BYTE-IDENTICAL to the
  honest one** and **CANNOT be opened with the attacker's hybrid secret** — the vault key
  was never wrapped to the attacker;
- the **browser threw `KeyPinMismatchError`**, and a failed check **did NOT mutate the pin
  store**;
- **Rust and JS safety numbers AGREED** — per-device, the order-independent pairwise number
  computed from **both** sides, and the fixed KAT both implementations hardcode
  (`83791 28129 67801 50284 55242 77845`); different keys give different digits. The
  construction was also **independently reimplemented from the spec text alone, with no
  project code, reproducing both the per-device and the pairwise KAT** — so
  `docs/crypto-spec.md` is exact enough to build from;
- **ROTATION works and its limit holds:** after revoking B and rotating to `[A, C]`, a NEW
  secret is **unreadable with B's old key**, B's envelope is **gone from the server**, and
  still-authorized **C reads the new secret fine**;
- the deliberate escape hatch behaves: a **legitimate re-enrolment also trips the alarm**
  (it is indistinguishable from an attack), a re-pin with the **WRONG** safety number is
  **refused**, and only an explicit `repin --yes` with the RIGHT number restores sharing.

### ⚠️ HONEST LIMITS — do not let this become "secure now"
- ⭐ **Pinning CANNOT protect FIRST contact.** If the server lies the very first time, the
  lie is what gets pinned. The **safety number** closes that window **only if a human
  actually compares it** — nothing forces the comparison and nothing detects that it was
  skipped; a first-sight share proceeds with a warning.
- ⭐ **A user who blindly re-pins defeats the whole mechanism.** `--yes` plus the optional
  safety-number check raise the cost; they cannot stop someone re-pinning to make an error
  go away. The `repins` counter preserves the *evidence*, not the safety.
- ⭐ **Rotation protects FUTURE content ONLY.** A device that already unwrapped the previous
  key keeps that key and everything it copied — cryptography cannot un-send a secret.
  Deleting an envelope stops it collecting anything **new**; it does not reach into that
  device. Rotation is also **manual**: nothing re-keys on revoke, no schedule, no forward
  secrecy.
- **The pin store is only as safe as its host** — anything that can rewrite it silences the
  alarm before it fires.
- **Still no key-transparency log and no cross-signature** binding a hybrid public key to
  the device's enrolled Ed25519 identity. That would remove the human from the loop and is
  **the highest-value follow-up**; it was deferred, not dismissed, because it changes the
  publish payload and registry schema across four clients and the server, whereas this
  phase could ship complete and proven client-side.
- **A third mirrored construction to keep in sync**, and its drift mode is nasty: divergence
  would be **misdiagnosed as an attack by users**. Hence the KAT on both sides and the
  cross-tool test.
- **UNAUDITED**, dev-gated (`501` by default), plain HTTP on loopback. **Do NOT store real
  2FA secrets.** Nothing here makes the system "secure" — it closes one documented hole and
  narrows another.

### 📄 Docs updated in the same change
- `docs/threat-model.md` — the **most important edit**: the stale *"no out-of-band
  verification"* and *"no rotation / no re-wrap on revoke"* statements corrected; a **new
  adversary row X (key-substituting server / rogue registry)**; the *"what sharing does NOT
  defend"* list rewritten around the real residual risks (first contact, blind re-pin, the
  pin store's host, rotation's future-only scope, unaudited); the desktop and browser
  subsections and the class-8 status note updated.
- `docs/api.md` — both new routes documented in full (auth, request/response, status codes,
  the **metadata-only** guarantee, the `501`-by-default posture), plus the authorization
  table, the metrics table, the two new audit events, "all **eleven** routes", and the CLI /
  JS / desktop client-support tables.
- `docs/crypto-spec.md` — the exact safety-number transcript, rendering, and the
  pairwise ordering rule **and why it is order-independent**; the pin-check outcome table;
  and the full **rotation key lifecycle** with its ordering rationale.
- `docs/architecture.md` — new **§2c**: the pin store as a **client-side trust store the
  server can neither read nor write** (native `0600` file vs sealed container), where it is
  enforced, and rotation; stale claims in §1, §2b and §6 corrected.
- `CLAUDE.md` — the new CLI subcommands, the two sigild routes, pin-store locations/modes,
  the container **v3** bump, the desktop/webapp/extension wiring, and the test list
  renumbered to **NINE** node tests.
- `README.md` — an honest short paragraph: clients pin device keys, a safety number lets
  you verify one by hand, vault keys can be rotated — with the first-contact and
  future-content-only caveats stated in the same breath.
- `docs/decisions/0038-key-pinning-safety-numbers-and-vault-rotation.md` — **NEW ADR 0038**
  covering all three decisions together, with alternatives rejected (warn-instead-of-block,
  cross-signature, key transparency, after-the-fact fingerprint comparison, auto-re-pin,
  hex fingerprints, deriving the new key from the old, server-side revocation, and the
  fail-open pin store) and every residual risk; indexed in `docs/decisions/README.md`.
- `docs/decisions/0035-device-to-device-vault-sharing.md` — a dated **"Key verification and
  rotation (added Phase 50, 2026-07-27)"** addendum under the addendum rule in
  `docs/decisions/README.md`: it reports **only** what changed and points at 0038, edits no
  original text, and is explicit about which halves of each limitation are **not** retired.

### ➡️ Still open (honest)
- ⭐ **Cross-sign the hybrid public key with the device's enrolled Ed25519 identity** (sign
  at publish, verify at wrap) — the one change that would protect **first contact** without
  a human. Now the clear top of the list.
- **Key transparency / gossip**, so a pin can be checked against something other than one
  device's memory.
- **Automatic re-wrap on revoke** and some rotation policy, so remediation is not purely
  manual.
- **Zeroization** of key material on every client — still nothing, anywhere.
- **Wire the hybrid SIGNATURE into something** — still the only hybrid construction used by
  nothing; all request auth, including these routes, is classical Ed25519.
- **UI-driven coverage** for the new key-trust surfaces: the protocol claims are proven
  headlessly, but no test clicks the safety-number, re-pin or rotate buttons.

---

## 2026-07-27 — Phase 51 (closing the third full-repo audit: the desktop's key-substitution ALARM becomes visible, webhook dedup moves inside the signature, and the security page stops lying in the safe direction)

### Why this phase
This was not a feature phase. A third full-repo audit produced a short list of open
findings, and this phase closed them. The two that mattered share a shape worth naming,
because it is a recurring failure mode here rather than two unrelated bugs:

> **A control that exists in the code but does not reach the place it has to act is not a
> control.** The desktop's key-substitution defence *refused* correctly and then told the
> user about it in a toast that vanished in seven seconds. The billing idempotency ledger
> *deduplicated* correctly and then keyed itself on a value the attacker picks.

Both were real code, both passed their own tests, and both were documented as working.

---

### 1. ⭐ THE DESKTOP KEY-SUBSTITUTION ALARM — raised for four phases, barely shown

**Before.** `desktop/src-tauri/src/main.rs` already tagged a pin mismatch `"key changed"`
(Phase 50, ADR 0038). But `desktop/ui/main.js` had **no handler for it and no re-pin
control**, so the single most important refusal in the product — *a hostile server tried
to substitute a key and we did not wrap to it* — rendered as a **7-second toast**,
identical in weight to "enter the recipient device id first". The webapp and the MV3
extension both did this properly: block, explain, offer a deliberate re-pin. The desktop
was the odd one out.

**What changed — structure across the IPC.** Errors used to cross as plain strings, which
is precisely why the UI could not do better than print one. Now:

```rust
type CmdResult<T> = Result<T, IpcError>;

struct IpcError { kind: &'static str, message: String, key_change: Option<KeyChange> }
struct KeyChange { device_id, pinned_safety_number, presented_safety_number }
```

`key_change` is populated for **exactly one `kind`** (`"key changed"`) and carries
**PUBLIC material only** — a device id and two safety numbers. **No key bytes, no seed,
nothing secret gained a route across the trust boundary**; that was the constraint the
shape had to satisfy before anything else. `From<String> for IpcError` keeps **every
existing `?` site unchanged**, so this is additive rather than a 21-command rewrite.

**The UI half.** `desktop/ui/{index.html,styles.css,main.js}` gained a `#pin-mismatch`
`role="alert"` block that:

- **BLOCKS the share and rotate submit buttons** while it is up;
- prints the **pinned** and **presented** safety numbers side by side in a monospace
  block, with instructions to read the *presented* digits to that device's owner **over a
  channel the server does not control**;
- offers a `window.confirm`-guarded re-pin that sends **`expected` = the presented
  number**, so the native side re-checks that what the user says they verified is still
  what the server is serving *right now*;
- offers "Keep refusing" as the other exit, which says plainly that refusing is the safe
  outcome.

Wording matches the webapp and the extension deliberately — three clients describing the
same event three different ways is its own problem. It is reached from the **single
central `call()` error path**, so every command's errors route through it and no command
can bypass it; non-key-change errors still toast exactly as before. The read-only
`peer_safety_number` button also now reports a `DIFFERS` pin state at **error** level
rather than as a note, because that is the same fact reached read-only.

⚠️ **What did NOT change: the refusal itself.** The client refused before and refuses now.
This phase changed **visibility**, not behaviour — worth stating precisely so nobody reads
it as a security fix to the wrap path.

⚠️ **PREMISE CORRECTION.** The audit finding also claimed the desktop did not surface
safety-number / pinned-key views. **That clause was wrong** — `device safety-number`,
the pairwise form and `device pins` all already had buttons and commands there since
Phase 50. They were not added, and nothing in the docs should say they were.

---

### 2. A REGRESSION TEST FOR THE PATH THAT RAISES IT (added by me, not the build agent)

The desktop was the **only** client whose key-substitution defence had no test at all —
the browser side has had `sigil-wasm/test/pinning-interop.mjs` since Phase 50. Given that
the whole point of this phase was "an unexercised control is not a control", shipping the
UI without one would have been the same mistake in a new place.

`desktop/core/tests/server_interop.rs` gained
**`a_substituted_hybrid_key_raises_the_alarm_the_desktop_ui_renders`**. It boots a real
`sigild` and builds the real `sigil` binary (no mocks), has the CLI publish key **K1**,
performs a share — **which is what PINS K1** and must succeed — and then runs:

```
sigil device hybrid-publish --regenerate
```

so the **SAME device id now presents a DIFFERENT hybrid public key**. ⭐ That trigger is
chosen for faithfulness, not convenience: it is byte-for-byte what a hostile server does
when it substitutes a key it can decrypt with, and it is **deliberately indistinguishable
from a legitimate re-enrolment** — which is the entire reason the decision has to reach a
human instead of being resolved in code.

It asserts:

- the share is refused as **`DesktopError::KeyPinMismatch`** — not a generic error, which
  is what the UI branches on;
- the alarm carries **both** safety numbers, the pinned one equals what was actually
  pinned, they differ, and both are in the **6 groups × 5 digits** shape the UI prints
  (the test parses the shape, so a rendering change that broke the panel would fail here);
- **rotation is refused too** — the other wrap path;
- a re-pin to a **WRONG** number is refused **and leaves the old pin standing** (checked by
  re-attempting the share and still getting the alarm);
- only a **deliberate** re-pin to the presented number lets sharing resume, and the
  returned `(previous, current)` pair matches.

✅ **MUTATION-TESTED.** With the pin check in `cli/src/lib.rs` neutered to fail open, the
test fails with **`SHARED TO A SUBSTITUTED KEY — the pin check did not fire`**. Restored,
it passes. A test that has never been observed failing is a hypothesis.

---

### 3. ⚠️ A LATENT TEST-HARNESS BUG the new test exposed

`Harness::start()` built its temp directory from **pid + `now_unix()` in SECONDS**. That
was fine while the file held one test. `cargo` runs the tests in a file in **parallel
threads of ONE process**, so pid is shared — and two harnesses starting in the same second
produced the **same path**, where the second one's `remove_dir_all` deleted the first
one's state out from under it. It surfaced as a baffling **"No such file or directory" in
the OTHER test**, which had done nothing wrong.

Fixed with an `AtomicUsize` counter in the directory name. Recording it because the
symptom pointed at entirely the wrong test, and because it had been latent since Phase 49
waiting for a second test to exist.

---

### 4. ⭐ RAZORPAY WEBHOOK DEDUP MOVED INSIDE THE SIGNATURE (ADR 0039)

**The defect.** Razorpay signs the **body and nothing else** — no timestamp, no headers.
The adapter nevertheless took its event id from the **`X-Razorpay-Event-Id` header**, and
that id was the idempotency key. A captured, genuinely-signed delivery replayed with **any
headers the attacker likes** still verifies, so changing one header changed the key and
the delivery was processed as a **NEW event**.

The blast radius was bounded but the guarantee was false. The state machine is idempotent,
legality-checked and `OccurredAt`-ordered, so a replay could not walk a subscription
anywhere it had not already been — but the **processed-events ledger could be grown
without limit on demand**, from an endpoint with no rate limiting. And the documented
promise ("a duplicate delivery is a no-op") held only for duplicates the attacker chose
not to relabel.

**The fix, stated as an invariant rather than a patch:**

> **An idempotency key MUST be a function of bytes the provider's signature covers.**

`billing.Event` gained **`DedupKey`** plus **`Event.IdempotencyKey()`** (falls back to
`ID`), and `sigild/internal/api/billing.go` now passes `EventID: ev.IdempotencyKey()` —
one place where the ledger key is chosen, so it cannot silently drift back to the header.

- **Razorpay** always sets `DedupKey = "body-" + hex(SHA-256(rawBody))`. A byte-identical
  body is exactly **one** event whatever the headers say. The header id is **demoted to a
  correlation LABEL** on `Event.ID`, for the dashboard and the audit log, documented as
  not a security value. (The body hash already existed — as a *fallback* used only when
  the header was missing. The fix is that it is now the **only** thing that keys the
  ledger.)
- **Stripe** sets `DedupKey = env.ID`: its event id is **inside** the signed payload
  (`"<t>.<body>"`), so it is already covered. Set explicitly rather than left to the `ID`
  fallback, so the guarantee is visible at the call site.
- **Juspay** uses a body-derived id.

✅ **VERIFIED FIRST-HAND, BY MUTATION.** Reverting to `EventID: ev.ID` makes the replay
return **`"accepted"`** — i.e. the attack works — and
**`TestWebhookRazorpayReplayWithFreshHeaderIDIsOneEvent`** catches it. Restored, the
`sigild` suite is green under `go test -race`. Against a live local server the forgery set
behaves: **wrong secret → 401, tampered body → 401, missing signature header → 401**.

⚠️ **SCOPE NOTE, now recorded in the threat model.** The invariant holds for **Stripe**,
**Razorpay**, and **Juspay under `scheme=hmac`**. Under **Juspay `scheme=basic` it is
VACUOUS** — basic authenticates the *connection*, not any bytes, so there is nothing for a
dedup key to be derived from and adversaries K/L are simply not defended there. No key
derivation fixes an authentication scheme that signs nothing.

---

### 5. JUSPAY'S DEFAULT WEBHOOK SCHEME IS NOW `hmac`

`NewJuspay`'s switch was **inverted**: `case JuspaySchemeBasic` selects connection auth,
and **`default` selects HMAC** — so an empty or unrecognized scheme lands on the
body-binding verifier with no secret configured, which **accepts nothing**. It fails
closed instead of silently degrading to connection-only authentication.

The rationale is recorded in the file, and it is the whole argument in one line:
**uncertainty about a header name is a configuration problem; getting connection-only
authentication by accident is a security problem.** The old default traded the second away
to avoid the first.

`cmd/server/billingconfig.go` follows: `SIGILD_JUSPAY_WEBHOOK_SECRET` is **required when
the scheme is unset**; choosing `basic` without its credentials is a **boot failure** whose
message names what was opted into; and a `basic` boot logs a **WARN every start** stating
that the scheme authenticates the connection and not the payload, that anyone holding the
credential can post any body, and that the endpoint must then be TLS-only. **Both schemes
still work; both still fail closed on an unset secret.** `basic` is still available —
reportedly some merchant accounts only offer it — it just has to be **asked for by name**.

⚠️ This is a **breaking configuration change** for anyone relying on the old default.
There is nobody: **nothing here has ever run against a live provider account.** Called out
anyway, rather than discovered at boot.

---

### 6. THE MARKETING SECURITY PAGE WAS UNDER-CLAIMING — AND THEREFORE STILL FALSE

`web/apps/marketing/app/security/page.tsx` said *"nothing below is implemented, shipped,
or independently audited yet"* and listed **ML-KEM-768** and **ML-DSA-65** as *"planned"*.
Every one of those primitives is real code in this repo with passing tests. This is an
unusual correction to have to make — the page erred **toward** modesty — but a false
statement about our own cryptography is a false statement, and an auditor reading it
against the code would rightly ask which other claims are unreliable.

Corrected, without tipping into the opposite error:

- Argon2id, XChaCha20-Poly1305, X25519, Ed25519, **ML-KEM-768** and **ML-DSA-65** now read
  **"Implemented; unaudited"**, each with a one-line note saying what it actually does.
- **ML-KEM-768** is additionally marked **load-bearing** — it is combined with X25519 into
  the hybrid KEM that wraps a vault key when a vault is shared, which is real product code.
- **ML-DSA-65** reads **"implemented; not yet in the authentication path"**: it exists and
  round-trips, including as a hybrid Ed25519 + ML-DSA-65 signature, and **device
  authentication is still Ed25519 alone**.
- **TLS `X25519MLKEM768`** stays **"Designed; planned"** — nothing is deployed.
- A **defined status vocabulary** pins the words down: **"implemented" means the code
  exists in the pre-release repository and its own tests pass — not released, not
  reviewed**; "load-bearing" means a product flow already depends on it.
- A dedicated paragraph states outright that **implementing ML-KEM/ML-DSA does NOT make a
  system "post-quantum secure", and we do not claim that it does** — the hybrid
  construction is the honest response to a young standard, and the surrounding protocol,
  key management and transport are still being built.

`MARKETING-CLAIMS.md` still holds: no "audited", no "SOC 2", no "post-quantum secure", no
unqualified present-tense "end-to-end encrypted", and nothing described as shipped.

⚠️ **PREMISE CORRECTION — and an invariant for anyone writing about the PQ primitives.**
The audit finding said these are *"tested against FIPS vectors"*. **THAT IS FALSE IN THIS
REPO, and the page does not say it.** `libsigil/core/src/mlkem.rs:332` and
`mldsa.rs:335` state plainly that **no official FIPS 203 / FIPS 204 / NIST ACVP
known-answer vector is embedded** — reproducing one needs exact byte tuples, and
fabricating them would be worse than not having them. The **upstream RustCrypto `ml-kem` /
`ml-dsa` crates** are the ACVP-validated ones; our correctness rests on round-trip,
determinism, implicit-rejection and negative tests **plus** that upstream vetting. The
page therefore says the primitives are **"covered by their own tests"**. I also added an
explicit note to `docs/crypto-spec.md` so the accurate version is written down somewhere
authoritative, contrasting it with the classical/OTP primitives, which **do** carry
official RFC vectors (RFC 7748, RFC 8032, RFC 4226/6238). **Never write that we verify
against FIPS/ACVP vectors.**

---

### 7. CI COVERAGE

- **`sigild.yml` now runs `go test -race ./...`.** The local gate has always run `-race`,
  so CI was the **weaker** of the two on a concurrent server whose op-log, nonce cache,
  rate limiter and subscription store are all shared mutable state with concurrency tests
  aimed straight at them. Without the detector those tests pass while the race they exist
  to catch is still there.
- **`security.yml`'s cargo-audit now covers all four Rust workspaces** (`libsigil`, `cli`,
  `sigil-wasm`, `desktop`) via a `fail-fast: false` matrix. It audited `libsigil` only —
  the **smallest and most conservative** lockfile, which says nothing about the other
  three. `desktop/` pulls the entire Tauri tree, by far the largest dependency surface in
  the repository and the one most likely to be the subject of an advisory.
- **`cli/tests/e2e-sharing.sh` now runs in a workflow** — a second `e2e-sharing` job in
  `interop.yml`. It is the tenth cross-component proof and the only shell one, and it was
  in exactly the position the nine Node tests were in before commit `5735f80`: **run by
  nothing**. The script also stopped hardcoding the macOS Homebrew Go: it resolves
  **`$GO` → `/opt/homebrew/bin/go` → `go` on PATH** and errors clearly if none exists.
- All workflows still parse.

---

### 📄 Docs updated in the same change (the docs-stay-in-sync rule)

- **`docs/decisions/0039-webhook-idempotency-from-signed-bytes.md` — NEW ADR 0039**, for
  the load-bearing rule: *webhook idempotency keys MUST be derived from bytes the
  provider's signature covers*. It carries the per-provider table, the Juspay-`basic`
  vacuity caveat, the mutation-test verification, the accepted costs (a body-derived key
  is not human-recognizable; a provider that redelivers a semantically-identical event
  with a different body would count as two), and the alternatives rejected (rate-limit
  instead, uniform body hashing, drop `basic` entirely, police the header). It **revises
  §4 of ADR 0034** rather than superseding it — 0034's body is untouched, per the ADR
  immutability rule; the index row for 0034 now says so, exactly as 0005 already flags its
  partial supersession by 0014.
- **`docs/decisions/README.md`** — the 0039 index row, the 0034 revision note, and the
  banner's stale "idempotency keyed on the provider event id" clause.
- **`docs/api.md`** — the idempotency section now leads with the signature-coverage rule
  and a per-provider key table; the webhook contract table puts **Juspay `hmac` first as
  the default** and marks `basic` explicit-opt-in; the Razorpay bullet is rewritten around
  the header being a correlation label; the env table marks `SIGILD_JUSPAY_WEBHOOK_SECRET`
  required when the scheme is unset; the `billing.webhook` audit row notes `event_id` is
  **not** the idempotency key. ⚠️ Also fixed a stale count left from Phase 50: *"the three
  vault-sharing counters"* — there are **FOUR** (`..._hybrid_keys_published_total`,
  `..._vault_key_envelopes_total`, `..._vault_key_envelope_fetches_total`,
  `..._key_envelope_deletes_total`), verified against `internal/api/metrics.go`; they are
  now named rather than counted.
- **`docs/threat-model.md`** — the desktop subsection gains the "the alarm is now
  rendered, not just raised" entry (with the explicit note that the *refusal* did not
  change) and the new regression test; adversary **K** (replayer) is rewritten around the
  signature-covered dedup key; adversary **L**'s Juspay exception notes the default flip;
  and the billing "does NOT defend" list gains the **scope note** that the invariant is
  **vacuous under `scheme=basic`**.
- **`docs/architecture.md`** — the `desktop` component description now documents the
  structured `IpcError` (and that `key_change` carries public material only); §2c gains a
  paragraph that **all four client surfaces now SHOW the alarm**, not just raise it; the
  billing paragraph carries the dedup-key rule and the Juspay default.
- **`docs/deployment.md`** — §13.1 gains the ⚠️ block explaining that the Juspay scheme
  defaults to `hmac`, that `SIGILD_JUSPAY_WEBHOOK_SECRET` is therefore required when
  unset, that `basic` fails fast without its credentials and logs a WARN every start; the
  env sample reordered to match; §13.2's verification checklist adds "redeliver the
  identical body with a *different* `X-Razorpay-Event-Id` and confirm `duplicate`"; §13.4
  notes the invariant is vacuous under `basic`.
- **`docs/crypto-spec.md`** — the explicit, accurate note on what "tested" means for
  ML-KEM-768 / ML-DSA-65 (no embedded FIPS/ACVP KAT here; upstream RustCrypto is the
  ACVP-validated part), contrasted with the RFC-vectored classical and OTP primitives.
- **`CLAUDE.md`** — the billing paragraph (the `DedupKey` invariant, the Razorpay replay
  reasoning, the Juspay default + boot behaviour), the `desktop/` bullet (the structured
  `IpcError`, the UI alarm, the new test and its mutation check, the harness bug, and the
  premise correction about safety-number views), the marketing bullet (the security-page
  correction **and** the never-claim-FIPS-vectors invariant), the Go gate now `-race`, the
  desktop test count (**15 unit + 3 integration across 2 files**), and the **CI job list
  rewritten** — it claimed "every surface now has a CI job" while omitting `interop.yml`,
  `security.yml` and `release.yml` entirely.
- **`README.md`** — reviewed and **left unchanged**: nothing in it was made inaccurate by
  this phase (its billing paragraph says only "duplicate deliveries are idempotent", which
  is now more true than before; its pinning paragraph is client-agnostic).

### ⚠️ Two stale/wrong doc items found beyond the audit list, and corrected

**(a) `CLAUDE.md` claimed `libsigil.yml` and `cli.yml` run the `getrandom`==0 guard. They
do not.** Writing the CI list out file-by-file — rather than repeating the old summary
sentence — is what surfaced it. The guard exists in **`desktop.yml`** and **`interop.yml`**
only. The invariant is still covered in practice, because a `cli/**` or `libsigil/**`
change triggers `interop.yml`, which asserts `getrandom`==0 for **both**
`libsigil/Cargo.lock` and `sigil-wasm/Cargo.lock` — but the crate's *own* job does not
check it, which is exactly the sort of thing you would assume wrongly under time pressure.
`CLAUDE.md` now says so explicitly and points back at the local `grep -c` command. **The
workflows were not edited** (this phase's brief was documentation only); adding the guard
to `libsigil.yml` / `cli.yml` is a one-line follow-up.

**(b)** `CLAUDE.md` carried a **"Known CI gap after Phase 49"** warning saying `desktop.yml` would
fail on a GitHub runner because `server_interop` looks for Go at `/opt/homebrew/bin/go`.
**That gap was already closed inside Phase 49 itself**, after the journal entry that
flagged it: `desktop.yml` installs Go with `actions/setup-go@v5`, and `resolve_go()`
resolves **`$GO` → `go` on PATH → Homebrew**, and **panics rather than skipping** when Go
is genuinely absent. The warning had simply never been retired. Now corrected to record
that it is closed — and to point out that the Phase 51 Go-resolver work was in
`cli/tests/e2e-sharing.sh`, a different file with the same old hardcoded path.

### ➡️ Still open (honest, and mostly unchanged — this phase closed findings, not gaps)
- ⭐ **Cross-sign the hybrid public key with the device's enrolled Ed25519 identity** (sign
  at publish, verify at wrap) — still the one change that would protect **first contact**
  without a human in the loop, and still the highest-value follow-up.
- **Key transparency / gossip**, so a pin can be checked against something other than one
  device's memory.
- **Automatic re-wrap on revoke** and some rotation policy — remediation is still manual.
- **Zeroization** of key material on every client — still nothing, anywhere.
- **Wire the hybrid SIGNATURE into something** — still the only hybrid construction used
  by nothing; all request auth, including the sharing routes, is classical Ed25519.
- **UI-driven coverage.** Phase 51 tested the path that *raises* the desktop alarm, in the
  headless core. **No test clicks the alarm's re-pin button, or the safety-number and
  rotate buttons, on any client.** The gap narrowed; it did not close.
- **No rate limiting on `/v1/billing/webhook/{provider}`.** ADR 0039 closed the
  unbounded-ledger-growth path that ran *through* the idempotency key; it does not bound
  request volume.
- **Add the `getrandom`==0 guard to `libsigil.yml` and `cli.yml`** — see the finding
  above. One step each; not done here because this phase's brief was documentation only.
- **Billing has still never been run against a live provider account**, Juspay remains
  UNVERIFIED-AGAINST-LIVE-DASHBOARD, and the whole repo remains **pre-audit and
  UNAUDITED**. Do not store real secrets.
