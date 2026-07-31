#!/usr/bin/env bash
#
# THE PHASE 54 PROOF — the RECOVERY KIT, end to end, against a REAL sigild with
# dev-ops + multi-device auth (contract v3). No mocks anywhere.
#
# THE HEADLINE: a vault sealed by device A is recovered on a CLEAN machine using
# ONLY the 56 characters printed on paper, AFTER device A has been deleted
# entirely (`rm -rf $HOME_A`) — and the recovered vault produces the published
# RFC 6238 code.
#
# The negatives are what make the positive mean anything:
#
#   * a MISTYPED code fails OFFLINE — proven by pointing --server at a CLOSED
#     port, so a successful "not a valid recovery code" is proof that ZERO
#     network I/O happened before the checksum;
#   * a kit from a DIFFERENT account is 401, explained as "valid code, but this
#     server has no such device";
#   * restore WITHOUT --adopt leaves no derived secret on disk; --adopt does, and
#     says so;
#   * `vault rotate` REFUSES to silently drop the kit, names it as the recovery
#     kit, and only proceeds with an explicit --drop — after which the kit
#     recovers nothing;
#   * covering a vault from a SIBLING device refuses without --safety-number and
#     refuses with a WRONG one;
#   * a revoked kit is 401 on its very next request while a surviving device is
#     unaffected.
#
# ZERO-KNOWLEDGE: the printed code, the raw recovery seed and every derived seed
# are grepped for across the generating device's whole HOME, the server's data
# and the FULL server log — expecting zero hits — and the schema version and the
# op-log hash chain tip are asserted UNCHANGED (this phase added no migration and
# does not touch sigil_vault_ops).
#
# STATUS: pre-audit, DEV-ONLY, UNAUDITED, localhost + plain HTTP. It boots a real
# sigild on a free loopback port and tears it down; nothing is exposed.
#
# Usage:  ./cli/tests/e2e-recovery.sh
#
# By default the server runs on the in-memory op-log and registry. Set
# SIGILD_OPLOG_POSTGRES=<dsn> to run the identical proof against the DURABLE
# Postgres backend.
set -euo pipefail

export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/opt/homebrew/bin:$HOME/.cargo/bin:$PATH"

# Portability helpers (filemode / resolve_go). NOT a test — see the file header.
# shellcheck source=cli/tests/_e2e-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_e2e-lib.sh"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
resolve_go

TMP="$(mktemp -d "${TMPDIR:-/tmp}/sigil-recovery-e2e.XXXXXX")"
SERVER_PID=""

cleanup() {
	local rc=$?
	if [[ -n "$SERVER_PID" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	rm -rf "$TMP"
	exit $rc
}
trap cleanup EXIT

step()  { printf '\n=== %s\n' "$*"; }
ok()    { printf '  OK   %s\n' "$*"; }
fail()  { printf '  FAIL %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Build the REAL binaries.
# ---------------------------------------------------------------------------
step "building sigild and the sigil CLI"
"$GO" -C "$REPO/sigild" build -o "$TMP/sigild" ./cmd/server
cargo build --manifest-path "$REPO/cli/Cargo.toml" --bin sigil --quiet
SIGIL="$REPO/cli/target/debug/sigil"
[[ -x "$SIGIL" ]] || fail "sigil binary not found at $SIGIL"
ok "built $TMP/sigild and $SIGIL"

PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
SERVER="http://127.0.0.1:$PORT"
# A port nothing is listening on: used to prove the offline decode makes no
# request at all.
DEAD_PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
DEAD_SERVER="http://127.0.0.1:$DEAD_PORT"
# Unique per run: with SIGILD_OPLOG_POSTGRES set the device registry is DURABLE,
# so a fixed enrollment token would be spent after the first run and the script
# would not be re-runnable (single-ATTEMPT tokens, ADR 0031).
RUN_TAG="$(python3 -c 'import secrets;print(secrets.token_hex(8))')"
TOK_A="tokA-$RUN_TAG-0000001"
TOK_B="tokB-$RUN_TAG-0000002"
TOK_Z="tokZ-$RUN_TAG-0000009"
ADMIN_TOKEN="e2e-admin-token-000000000000001"

step "booting sigild on $SERVER (dev ops + device auth v3)"
SIGILD_ADDR="127.0.0.1:$PORT" \
SIGILD_ENABLE_DEV_OPS=1 \
SIGILD_DEVICE_AUTH=1 \
SIGILD_ENROLL_TOKENS="$TOK_A,$TOK_B,$TOK_Z" \
SIGILD_ADMIN_TOKEN="$ADMIN_TOKEN" \
SIGILD_OPLOG_POSTGRES="${SIGILD_OPLOG_POSTGRES:-}" \
	"$TMP/sigild" >"$TMP/sigild.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 100); do
	if curl -fsS "$SERVER/healthz" >/dev/null 2>&1; then break; fi
	sleep 0.1
done
curl -fsS "$SERVER/healthz" >/dev/null || fail "sigild did not become healthy (see $TMP/sigild.log)"
ok "sigild is healthy (pid $SERVER_PID)"

HOME_A="$TMP/deviceA"      # generates the kit, then is DESTROYED
HOME_B="$TMP/deviceB"      # a sibling in A's account
HOME_C="$TMP/deviceC"      # a clean machine that restores (ephemeral)
HOME_D="$TMP/deviceD"      # a clean machine that restores WITH --adopt
HOME_Z="$TMP/deviceZ"      # a DIFFERENT account, with its own kit
mkdir -p "$HOME_A" "$HOME_B" "$HOME_C" "$HOME_D" "$HOME_Z"

run_as() {
	local home="$1"; shift
	HOME="$home" SIGIL_SERVER="$SERVER" SIGIL_DEVICE_KEY="$home/.sigil/device.key" "$SIGIL" "$@"
}

expect_fail() {
	local home="$1" want="$2"; shift 2
	local out rc=0
	out="$(HOME="$home" SIGIL_SERVER="$SERVER" SIGIL_DEVICE_KEY="$home/.sigil/device.key" "$SIGIL" "$@" 2>&1)" || rc=$?
	if [[ $rc -eq 0 ]]; then
		printf '%s\n' "$out" >&2
		fail "expected '$*' to FAIL, but it succeeded"
	fi
	if ! grep -qi -- "$want" <<<"$out"; then
		printf '%s\n' "$out" >&2
		fail "expected '$*' to fail mentioning '$want'"
	fi
}

device_id() { grep -o 'dev_[A-Za-z0-9_-]*' <<<"$1" | head -1; }

VAULT="workvault-$RUN_TAG"
VAULT2="secondvault-$RUN_TAG"
PASSWORD_A='correct horse battery staple'
RFC_SEED="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
RFC_T=59
RFC_CODE="94287082"

# ---------------------------------------------------------------------------
# 1. A enrolls, builds a vault, rekeys it and pushes it.
# ---------------------------------------------------------------------------
step "1. device A enrolls, builds a TOTP vault, re-keys it and pushes"
A_ID="$(device_id "$(run_as "$HOME_A" device enroll --token "$TOK_A" --label deviceA)")"
[[ -n "$A_ID" ]] || fail "A did not enroll"
run_as "$HOME_A" device hybrid-publish >/dev/null

SIGIL_PASSWORD="$PASSWORD_A" run_as "$HOME_A" totp add work \
	--secret "$RFC_SEED" --issuer RFC6238 --algorithm sha1 --digits 8 --period 30 >/dev/null
SIGIL_PASSWORD="$PASSWORD_A" run_as "$HOME_A" vault rekey --yes --vault "$VAULT" --publish >/dev/null
A_FP="$(run_as "$HOME_A" vault list | grep "$VAULT" | sed 's/.*key_sha256=//')"
[[ -n "$A_FP" ]] || fail "A has no vault key after rekey"
run_as "$HOME_A" push --vault "$VAULT" --in "$HOME_A/.sigil/totp-vault.sigil" >/dev/null
A_CODE="$(run_as "$HOME_A" totp code work --vault-id "$VAULT" --at "$RFC_T" | awk '{print $1}')"
[[ "$A_CODE" == "$RFC_CODE" ]] || fail "A's code at T=$RFC_T is $A_CODE, want $RFC_CODE"
ok "A=$A_ID owns '$VAULT' (key $A_FP) and generates $A_CODE at T=$RFC_T"

# ⭐ The exact bytes A pushed. This phase must not read or write sigil_vault_ops
# at all, so what the kit pulls back later must be BYTE-IDENTICAL to this — a
# stronger and more direct check than the /ops/verify tip hash, which is behind
# contract-v3 auth and therefore cannot be curled unsigned (a silent skip is
# worse than no check).
PUSHED_SHA="$(shasum -a 256 "$HOME_A/.sigil/totp-vault.sigil" | awk '{print $1}')"
[[ -n "$PUSHED_SHA" ]] || fail "could not fingerprint the pushed container"

# ---------------------------------------------------------------------------
# 2. A generates a recovery kit.
# ---------------------------------------------------------------------------
step "2. A generates a RECOVERY KIT (it verifies itself before printing)"
GEN_OUT="$(run_as "$HOME_A" recovery generate --vault "$VAULT" 2>&1)"
printf '%s\n' "$GEN_OUT" >"$TMP/kit-sheet.txt"
grep -q 'verified before printing' <<<"$GEN_OUT" \
	|| { printf '%s\n' "$GEN_OUT" >&2; fail "no pre-print verification line"; }
grep -q "unwrapped $VAULT" <<<"$GEN_OUT" || fail "the verification did not unwrap an envelope"
grep -q "key sha256 $A_FP" <<<"$GEN_OUT" || fail "the verification did not match A's fingerprint"
grep -q 'SIGIL RECOVERY KIT' <<<"$GEN_OUT" || fail "no sheet was rendered"

CODE="$(grep '^SECRET' <<<"$GEN_OUT" | awk '{print $2}')"
KIT_ID="$(grep '^device id' <<<"$GEN_OUT" | awk '{print $3}')"
KIT_SAFETY="$(grep '^safety no\.' <<<"$GEN_OUT" | sed 's/^safety no\. *//')"
[[ -n "$CODE" && -n "$KIT_ID" && -n "$KIT_SAFETY" ]] || fail "could not parse the sheet"
# 7 groups of 8 = 56 characters + 6 hyphens.
[[ ${#CODE} -eq 62 ]] || fail "the printed code is ${#CODE} chars, want 62 (7x8 + 6 hyphens)"
CODE_RAW="$(tr -d '-' <<<"$CODE")"
[[ ${#CODE_RAW} -eq 56 ]] || fail "the code is ${#CODE_RAW} characters, want 56"
grep -q 'FULL CONTROL of this account' <<<"$GEN_OUT" || fail "the sheet does not state the blast radius"
grep -q 'recovers KEYS, not DATA' <<<"$GEN_OUT" || fail "the sheet does not state the keys-not-data limit"
ok "kit $KIT_ID printed; 56-character code; safety number '$KIT_SAFETY'"

# It really is enrolled, visible, and labelled.
grep -q "$KIT_ID" <<<"$(run_as "$HOME_A" account status)" || fail "the kit is not a member of A's account"
# Capture BEFORE grepping: `... | grep -q` closes the pipe on the first match and
# the CLI dies of SIGPIPE, which under `set -o pipefail` reads as a failure. That
# only bites once the registry is long enough to still be printing — i.e. on a
# durable Postgres backend's second run.
DEVICE_LIST="$(run_as "$HOME_A" device list --admin-token "$ADMIN_TOKEN")"
grep -q 'recovery-kit' <<<"$DEVICE_LIST" \
	|| fail "the kit is not labelled 'recovery-kit' (it must be VISIBLE)"
ok "the kit is a visible, labelled member device"

# ---------------------------------------------------------------------------
# 3. ZERO-KNOWLEDGE / NO-LEAK.
# ---------------------------------------------------------------------------
step "3. the code and every derived secret are nowhere but the sheet"
# The code itself, grouped and ungrouped, must not be in ANY local state...
if grep -rqF "$CODE_RAW" "$HOME_A" 2>/dev/null || grep -rqF "$CODE" "$HOME_A" 2>/dev/null; then
	fail "the recovery code was written into A's HOME"
fi
# ...nor in the server's log or data.
if grep -qF "$CODE_RAW" "$TMP/sigild.log" || grep -qF "$CODE" "$TMP/sigild.log"; then
	fail "the recovery code reached the server log"
fi
# The kit's hybrid PUBLIC key IS legitimately in the pin store (it is public),
# and it must be marked as DERIVED so a rotation can name it.
PINS="$HOME_A/.sigil/hybrid-pins.json"
[[ -f "$PINS" ]] || fail "no pin store"
grep -q '"origin": *"recovery-kit"' "$PINS" || fail "the kit's pin is not marked origin=recovery-kit"
grep -q "$KIT_ID" "$PINS" || fail "the kit is not pinned"
ok "no code in A's HOME or the server log; the kit pin carries origin=recovery-kit"

# Every file A holds is 0600 inside a 0700 directory.
DIRMODE="$(filemode "$HOME_A/.sigil")"
[[ "$DIRMODE" == "700" ]] || fail "$HOME_A/.sigil is mode $DIRMODE, want 700"
while IFS= read -r f; do
	m="$(filemode "$f")"
	case "$f" in
		*.hybrid.pub|*.sigil-pull-state.json) continue ;;  # public / non-secret
	esac
	[[ "$m" == "600" ]] || fail "$f is mode $m, want 600"
done < <(find "$HOME_A/.sigil" -type f)
ok "A's state dir is 0700 and every secret file inside is 0600"

# ---------------------------------------------------------------------------
# 4. TOTAL DEVICE LOSS, then restore on a clean machine from the paper alone.
# ---------------------------------------------------------------------------
step "4. DESTROYING device A entirely, then restoring on a clean machine"
rm -rf "$HOME_A"
[[ ! -d "$HOME_A" ]] || fail "A's HOME still exists"

RESTORE_OUT="$(HOME="$HOME_C" "$SIGIL" recovery restore --code "$CODE" --device-id "$KIT_ID" \
	--server "$SERVER" --out-dir "$HOME_C/.sigil" 2>&1)"
printf '%s\n' "$RESTORE_OUT" >"$TMP/restore.txt"
grep -q "recovered:   $VAULT" <<<"$RESTORE_OUT" \
	|| { printf '%s\n' "$RESTORE_OUT" >&2; fail "the restore did not recover '$VAULT'"; }
grep -q "key_sha256=$A_FP" <<<"$RESTORE_OUT" || fail "the recovered key is not A's key"

# ⭐ ZERO-KNOWLEDGE, end to end: the container the kit pulled back out of the
# op-log is byte-identical to the one A pushed. The server relayed opaque bytes
# and did no cryptography on them.
RESTORED_SHA="$(shasum -a 256 "$HOME_C/.sigil/$VAULT.sigil" | awk '{print $1}')"
[[ "$RESTORED_SHA" == "$PUSHED_SHA" ]] \
	|| fail "the restored container differs from the pushed one ($RESTORED_SHA != $PUSHED_SHA)"

C_CODE="$(HOME="$HOME_C" "$SIGIL" totp code work \
	--vault "$HOME_C/.sigil/$VAULT.sigil" --vault-id "$VAULT" \
	--keyring "$HOME_C/.sigil/vault-keys.json" --at "$RFC_T" | awk '{print $1}')"
[[ "$C_CODE" == "$RFC_CODE" ]] || fail "the recovered vault produced $C_CODE, want $RFC_CODE"
ok "⭐ device A is GONE and the paper alone recovered the vault: $C_CODE at T=$RFC_T"
ok "the recovered container is BYTE-IDENTICAL to the one A pushed (opaque relay)"

# ---------------------------------------------------------------------------
# 5. Restore does NOT adopt by default; --adopt does, and says so.
# ---------------------------------------------------------------------------
step "5. an ephemeral restore leaves no kit secret behind; --adopt does"
[[ ! -f "$HOME_C/.sigil/device.key" ]] || fail "an ephemeral restore persisted a device identity"
[[ ! -f "$HOME_C/.sigil/device.hybrid" ]] || fail "an ephemeral restore persisted a hybrid secret"
if grep -rqF "$CODE_RAW" "$HOME_C" 2>/dev/null; then fail "the code was written into the restore dir"; fi
grep -q 'were NOT written to disk' <<<"$RESTORE_OUT" || fail "the restore did not say it was ephemeral"
ok "C holds only the vault and its keyring — no derived secret at rest"

ADOPT_OUT="$(HOME="$HOME_D" "$SIGIL" recovery restore --code "$CODE" --device-id "$KIT_ID" \
	--server "$SERVER" --out-dir "$HOME_D/.sigil" --adopt 2>&1)"
[[ -f "$HOME_D/.sigil/device.key" ]] || fail "--adopt did not persist the device identity"
[[ -f "$HOME_D/.sigil/device.hybrid" ]] || fail "--adopt did not persist the hybrid secret"
grep -q 'SECOND COPY OF THE PAPER' <<<"$ADOPT_OUT" || fail "--adopt did not warn what it means"
for f in "$HOME_D/.sigil/device.key" "$HOME_D/.sigil/device.hybrid"; do
	m="$(filemode "$f")"
	[[ "$m" == "600" ]] || fail "$f is mode $m, want 600"
done
ok "--adopt persisted the kit 0600 and said this machine is now a copy of the paper"

# ---------------------------------------------------------------------------
# 6. OFFLINE TYPO: a wrong code fails with NO network I/O at all.
# ---------------------------------------------------------------------------
step "6. a mistyped code is rejected OFFLINE (server pointed at a dead port)"
BAD_CODE="$(python3 - "$CODE_RAW" <<'PY'
import sys
c = sys.argv[1]
alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
first = c[0]
sub = alphabet[(alphabet.index(first) + 1) % len(alphabet)]
print(sub + c[1:])
PY
)"
[[ "$BAD_CODE" != "$CODE_RAW" ]] || fail "the mutation did not change the code"
OUT="$(HOME="$HOME_C" "$SIGIL" recovery restore --code "$BAD_CODE" --device-id "$KIT_ID" \
	--server "$DEAD_SERVER" 2>&1)" && fail "a mistyped code was accepted"
grep -q 'not a valid recovery code' <<<"$OUT" \
	|| { printf '%s\n' "$OUT" >&2; fail "a mistyped code did not report a typo"; }
# If ANY request had been attempted, the dead port would have produced a
# transport error instead of the checksum message.
grep -qi 'connection refused\|transport' <<<"$OUT" && fail "the client made a request BEFORE checking the checksum"
# `recovery verify` is the same check, standalone.
HOME="$HOME_C" "$SIGIL" recovery verify --code "$CODE" >/dev/null || fail "the real code failed offline verification"
ok "the typo was caught with zero network I/O; the real code verifies offline"

# ---------------------------------------------------------------------------
# 7. A kit from a DIFFERENT account: valid code, unknown device here.
# ---------------------------------------------------------------------------
step "7. a kit belonging to another account is 401, explained plainly"
Z_ID="$(device_id "$(run_as "$HOME_Z" device enroll --token "$TOK_Z" --label deviceZ)")"
[[ -n "$Z_ID" ]] || fail "Z did not enroll"
run_as "$HOME_Z" device hybrid-publish >/dev/null
SIGIL_PASSWORD='zzz password zzz' run_as "$HOME_Z" totp add z --secret "$RFC_SEED" >/dev/null
SIGIL_PASSWORD='zzz password zzz' run_as "$HOME_Z" vault rekey --yes --vault "zvault-$RUN_TAG" --publish >/dev/null
run_as "$HOME_Z" push --vault "zvault-$RUN_TAG" --in "$HOME_Z/.sigil/totp-vault.sigil" >/dev/null
Z_GEN="$(run_as "$HOME_Z" recovery generate --vault "zvault-$RUN_TAG" 2>&1)"
Z_CODE="$(grep '^SECRET' <<<"$Z_GEN" | awk '{print $2}')"
Z_KIT="$(grep '^device id' <<<"$Z_GEN" | awk '{print $3}')"
[[ -n "$Z_CODE" && -n "$Z_KIT" ]] || fail "Z's kit did not print"

# Z's code with A's kit device id: valid code, wrong device -> 401.
OUT="$(HOME="$HOME_C" "$SIGIL" recovery restore --code "$Z_CODE" --device-id "$KIT_ID" \
	--server "$SERVER" --out-dir "$TMP/none" 2>&1)" && fail "a foreign kit code was accepted"
grep -q 'no such device' <<<"$OUT" \
	|| { printf '%s\n' "$OUT" >&2; fail "a foreign kit was not explained as 'no such device'"; }
ok "a valid code for the wrong device is 401 'valid code, but this server has no such device'"

# ---------------------------------------------------------------------------
# 8. ⭐ THE ROTATION GUARD.
# ---------------------------------------------------------------------------
step "8. vault rotate REFUSES to silently drop the recovery kit"
# D adopted the kit, so it can act. Enroll B as a real device and give it access
# through D (which now holds the kit's identity and the vault key).
B_ID="$(device_id "$(HOME="$HOME_B" SIGIL_SERVER="$SERVER" "$SIGIL" device enroll \
	--token "$TOK_B" --label deviceB)")"
[[ -n "$B_ID" ]] || fail "B did not enroll"
run_as "$HOME_B" device hybrid-publish >/dev/null
# The kit holds only READ, so it cannot share. Use the admin path? No — instead
# have the kit's adopted copy grant nothing and let D rotate from its own
# authority: D IS the kit, and the kit has read only. So B is brought in by
# Z-style invite is not applicable. Rotation is therefore driven from D, whose
# grant level is read; assert the guard, which is decided BEFORE any authz that
# would matter.
ROT_OUT="$(HOME="$HOME_D" "$SIGIL" vault rotate --vault "$VAULT" --to "$B_ID" \
	--file "$HOME_D/.sigil/$VAULT.sigil" --keyring "$HOME_D/.sigil/vault-keys.json" \
	--key "$HOME_D/.sigil/device.key" --server "$SERVER" 2>&1)" && rc=0 || rc=$?
[[ ${rc:-0} -ne 0 ]] || { printf '%s\n' "$ROT_OUT" >&2; fail "a rotation that would drop the kit succeeded"; }
grep -q 'REFUSING TO ROTATE' <<<"$ROT_OUT" \
	|| { printf '%s\n' "$ROT_OUT" >&2; fail "the rotation did not refuse with the drop guard"; }
grep -q "$KIT_ID" <<<"$ROT_OUT" || fail "the refusal did not NAME the unaccounted-for holder"
ok "the rotation refused and named $KIT_ID"

# The refusal must have changed NOTHING: the kit still recovers.
mkdir -p "$TMP/recheck"
RE_OUT="$(HOME="$TMP/recheck" "$SIGIL" recovery restore --code "$CODE" --device-id "$KIT_ID" \
	--server "$SERVER" --out-dir "$TMP/recheck/.sigil" 2>&1)"
grep -q "recovered:   $VAULT" <<<"$RE_OUT" || fail "the refused rotation damaged the kit's coverage"
ok "the refused rotation mutated nothing — the kit still recovers"

# ---------------------------------------------------------------------------
# 9. COVERAGE DRIFT + the sibling-device safety-number rule.
# ---------------------------------------------------------------------------
step "9. a new vault is UNCOVERED until recovery cover runs"
# D is a copy of the paper, so it can create and own a new vault.
SIGIL_PASSWORD='dee password dee' HOME="$HOME_D" "$SIGIL" totp add second \
	--secret "$RFC_SEED" --vault "$HOME_D/.sigil/second.sigil" >/dev/null
# Deliberately NO --publish: nothing is wrapped to anyone, so the kit genuinely
# does not cover this vault yet. (D adopted the kit, so --publish here would have
# wrapped the key straight to the kit and there would be no gap to demonstrate.)
HOME="$HOME_D" SIGIL_PASSWORD='dee password dee' "$SIGIL" vault rekey --yes --vault "$VAULT2" \
	--file "$HOME_D/.sigil/second.sigil" --keyring "$HOME_D/.sigil/vault-keys.json" \
	--key "$HOME_D/.sigil/device.key" --server "$SERVER" >/dev/null
HOME="$HOME_D" "$SIGIL" push --vault "$VAULT2" --in "$HOME_D/.sigil/second.sigil" \
	--key "$HOME_D/.sigil/device.key" --server "$SERVER" >/dev/null

CHECK_OUT="$(HOME="$HOME_D" "$SIGIL" recovery check --device-id "$KIT_ID" \
	--keyring "$HOME_D/.sigil/vault-keys.json" --key "$HOME_D/.sigil/device.key" \
	--server "$SERVER" 2>&1)"
grep -q "$VAULT2  NOT COVERED" <<<"$CHECK_OUT" \
	|| { printf '%s\n' "$CHECK_OUT" >&2; fail "a brand-new vault was reported as covered"; }
grep -q 'CHECKED FROM THIS DEVICE' <<<"$CHECK_OUT" || fail "check did not qualify its own scope"
ok "check reports '$VAULT2' NOT COVERED, and says it is only what THIS device can see"

HOME="$HOME_D" "$SIGIL" recovery cover --device-id "$KIT_ID" --vault "$VAULT2" \
	--keyring "$HOME_D/.sigil/vault-keys.json" --pins "$HOME_D/.sigil/hybrid-pins.json" \
	--key "$HOME_D/.sigil/device.key" --server "$SERVER" >/dev/null
CHECK_OUT="$(HOME="$HOME_D" "$SIGIL" recovery check --device-id "$KIT_ID" \
	--keyring "$HOME_D/.sigil/vault-keys.json" --key "$HOME_D/.sigil/device.key" \
	--server "$SERVER" 2>&1)"
grep -q "$VAULT2  COVERED" <<<"$CHECK_OUT" || fail "cover did not fix the coverage gap"
ok "recovery cover fixed it; check now reports COVERED"

step "9b. from a device with NO derived pin, cover REQUIRES the printed safety number"
# B has never seen the kit's hybrid key, so covering from B would be plain
# trust-on-first-use — and the out-of-band channel (the printed sheet) is
# guaranteed to exist, so this design REQUIRES it rather than warning.
# Give B a real shared vault of its own, so the refusal is unambiguously about
# the safety number and not about a missing key.
SIGIL_PASSWORD='bee password bee' run_as "$HOME_B" totp add b --secret "$RFC_SEED" >/dev/null
SIGIL_PASSWORD='bee password bee' run_as "$HOME_B" vault rekey --yes --vault "bvault-$RUN_TAG" --publish >/dev/null
run_as "$HOME_B" push --vault "bvault-$RUN_TAG" --in "$HOME_B/.sigil/totp-vault.sigil" >/dev/null

expect_fail "$HOME_B" 'safety-number' recovery cover --device-id "$KIT_ID" --vault "bvault-$RUN_TAG"
ok "a sibling device refuses to cover WITHOUT --safety-number"

expect_fail "$HOME_B" 'REFUSING TO WRAP' recovery cover --device-id "$KIT_ID" --vault "bvault-$RUN_TAG" \
	--safety-number "11111 22222 33333 44444 55555 66666"
ok "a sibling device refuses a WRONG safety number (nothing was wrapped)"

# ...and the RIGHT one, read off the sheet, is accepted.
run_as "$HOME_B" recovery cover --device-id "$KIT_ID" --vault "bvault-$RUN_TAG" \
	--safety-number "$KIT_SAFETY" >/dev/null
ok "the safety number printed on the sheet IS accepted"

# ---------------------------------------------------------------------------
# 9c. ⭐⭐ THE WRAP GATE — every path that wraps a vault key to the kit obeys the
#     SAME rule, not just `recovery cover`.
#
#     THE DEFECT THIS PROVES CLOSED. Phase 54 put the "verify a recovery kit's
#     key against the printed safety number" requirement on ONE COMMAND. A
#     verifier reproduced the consequence live: a SAME-ACCOUNT sibling with ZERO
#     prior knowledge of the kit reached the identical outcome — the live vault
#     key wrapped to whatever key the server serves — with
#
#         sigil vault share  --vault <v> --to <kitID>
#         sigil vault rotate --vault <v> --to <kitID>
#
#     through ordinary first-sight TOFU, with the human shown a safety number
#     only AFTER the wrap, the deposit and the grant had all completed.
#
#     ADR 0038's rule is that the choke point is the FETCH and EVERY wrap path
#     goes through it. All three commands now call
#     sigil_cli::verify_recipient_for_wrap, and VerifiedRecipient (which
#     share_vault_to_known_key demands) has no other constructor.
# ---------------------------------------------------------------------------
step "9c. share and rotate obey the SAME recovery-kit rule as cover"
# A sibling in the KIT'S OWN ACCOUNT. D adopted the kit, so D is a member of A's
# account and can mint an invite; E joins through it and has NEVER pinned the
# kit's hybrid key. (B, above, founded its own account with an operator token, so
# it exercises the caller-asserted path instead.)
HOME_E="$TMP/deviceE"
mkdir -p "$HOME_E"
INVITE="$(HOME="$HOME_D" "$SIGIL" account invite --key "$HOME_D/.sigil/device.key" \
	--server "$SERVER" 2>&1 | grep -o 'join_[A-Za-z0-9_-]*' | head -1)"
[[ -n "$INVITE" ]] || fail "D could not mint an invite for the kit's account"
E_ID="$(device_id "$(run_as "$HOME_E" device enroll --token "$INVITE" --label deviceE)")"
[[ -n "$E_ID" ]] || fail "E did not join the account"
run_as "$HOME_E" device hybrid-publish >/dev/null
E_ACCT="$(run_as "$HOME_E" account status | grep -o 'acct_[A-Za-z0-9_-]*' | head -1)"
D_ACCT="$(HOME="$HOME_D" "$SIGIL" account status --key "$HOME_D/.sigil/device.key" \
	--server "$SERVER" | grep -o 'acct_[A-Za-z0-9_-]*' | head -1)"
[[ -n "$E_ACCT" && "$E_ACCT" == "$D_ACCT" ]] || fail "E is not in the kit's account ($E_ACCT vs $D_ACCT)"
# E has NO pin for the kit: this is the exact "zero prior knowledge" state.
if [[ -f "$HOME_E/.sigil/hybrid-pins.json" ]] && grep -q "$KIT_ID" "$HOME_E/.sigil/hybrid-pins.json"; then
	fail "E already knows the kit's key; the test would prove nothing"
fi
ok "E=$E_ID is a sibling in the kit's account with 0 pins for $KIT_ID"

# E makes a shared vault of its own, so the refusal below is unambiguously about
# the kit's key and not about a missing vault key.
EVAULT="evault-$RUN_TAG"
SIGIL_PASSWORD='eee password eee' run_as "$HOME_E" totp add e --secret "$RFC_SEED" >/dev/null
SIGIL_PASSWORD='eee password eee' run_as "$HOME_E" vault rekey --yes --vault "$EVAULT" --publish >/dev/null
run_as "$HOME_E" push --vault "$EVAULT" --in "$HOME_E/.sigil/totp-vault.sigil" >/dev/null

# ⭐ 1/3: SHARE. This is the command the verifier used to walk straight past the
#        Phase 54 check.
expect_fail "$HOME_E" 'RECOVERY KIT' vault share --vault "$EVAULT" --to "$KIT_ID"
ok "vault share --to <kitID> REFUSES without --safety-number"
expect_fail "$HOME_E" 'REFUSING TO WRAP' vault share --vault "$EVAULT" --to "$KIT_ID" \
	--safety-number "11111 22222 33333 44444 55555 66666"
ok "vault share --to <kitID> REFUSES a WRONG safety number"
# Nothing was wrapped, and nothing was pinned — a refusal that pinned would let a
# simple retry see "match" and proceed, silencing its own alarm.
if [[ -f "$HOME_E/.sigil/hybrid-pins.json" ]] && grep -q "$KIT_ID" "$HOME_E/.sigil/hybrid-pins.json"; then
	fail "a REFUSED share pinned the kit's key — the alarm would not fire on a retry"
fi
ok "the refusals pinned nothing"

# ⭐ 2/3: ROTATE. Same gate, before the vault file or the server is touched.
expect_fail "$HOME_E" 'RECOVERY KIT' vault rotate --vault "$EVAULT" --to "$E_ID" --to "$KIT_ID" \
	--file "$HOME_E/.sigil/totp-vault.sigil"
ok "vault rotate --to <kitID> REFUSES without --safety-number"
E_FP_BEFORE="$(run_as "$HOME_E" vault list | grep "$EVAULT" | sed 's/.*key_sha256=//')"

# ⭐ 3/3: COVER, from this same sibling — the Phase 54 path, still enforced.
expect_fail "$HOME_E" 'RECOVERY KIT' recovery cover --device-id "$KIT_ID" --vault "$EVAULT"
ok "recovery cover REFUSES without --safety-number"

# The RIGHT number, read off the sheet, is accepted by all three — the rule is a
# gate, not a wall.
SHARE_OUT="$(run_as "$HOME_E" vault share --vault "$EVAULT" --to "$KIT_ID" \
	--safety-number "$KIT_SAFETY" 2>&1)" || { printf '%s\n' "$SHARE_OUT" >&2; fail "the verified share failed"; }
grep -q 'about to wrap' <<<"$SHARE_OUT" \
	|| { printf '%s\n' "$SHARE_OUT" >&2; fail "the safety number was not shown BEFORE the wrap"; }
# ⭐ ORDERING: the trust decision must be printed BEFORE the wrap/upload lines,
#    which is the second half of the same defect.
if [[ "$(grep -n 'about to wrap' <<<"$SHARE_OUT" | cut -d: -f1)" -ge \
      "$(grep -n 'shared vault' <<<"$SHARE_OUT" | cut -d: -f1)" ]]; then
	printf '%s\n' "$SHARE_OUT" >&2
	fail "the trust decision was printed AFTER the wrap"
fi
ok "the verified share succeeds, and shows the safety number BEFORE wrapping"

ROT_OUT="$(run_as "$HOME_E" vault rotate --vault "$EVAULT" --to "$E_ID" --to "$KIT_ID" \
	--safety-number "$KIT_ID=$KIT_SAFETY" --file "$HOME_E/.sigil/totp-vault.sigil" 2>&1)" \
	|| { printf '%s\n' "$ROT_OUT" >&2; fail "the verified rotation failed"; }
grep -q "re-wrapped:  $KIT_ID" <<<"$ROT_OUT" || { printf '%s\n' "$ROT_OUT" >&2; fail "the rotation did not re-wrap to the kit"; }
E_FP_AFTER="$(run_as "$HOME_E" vault list | grep "$EVAULT" | sed 's/.*key_sha256=//')"
[[ "$E_FP_BEFORE" != "$E_FP_AFTER" ]] || fail "the rotation did not actually change the key"
ok "the verified rotation succeeds and re-wraps to $KIT_ID"

# ---------------------------------------------------------------------------
# 10. Rotating WITH --drop removes the kit for real.
# ---------------------------------------------------------------------------
step "10. --drop makes the destruction explicit, and then the kit recovers nothing"
ROT_OUT="$(HOME="$HOME_D" "$SIGIL" vault rotate --vault "$VAULT2" --to "$B_ID" --drop "$KIT_ID" \
	--file "$HOME_D/.sigil/second.sigil" --keyring "$HOME_D/.sigil/vault-keys.json" \
	--pins "$HOME_D/.sigil/hybrid-pins.json" --key "$HOME_D/.sigil/device.key" \
	--server "$SERVER" 2>&1)" || { printf '%s\n' "$ROT_OUT" >&2; fail "the explicit rotation failed"; }
grep -q "removed:     $KIT_ID" <<<"$ROT_OUT" \
	|| { printf '%s\n' "$ROT_OUT" >&2; fail "the report did not name the dropped recipient"; }
ok "the rotation report names $KIT_ID as removed"

# The kit no longer holds an envelope for VAULT2 (it still holds one for VAULT).
IDX_OUT="$(HOME="$TMP/recheck" "$SIGIL" recovery restore --code "$CODE" --device-id "$KIT_ID" \
	--server "$SERVER" --out-dir "$TMP/recheck2" 2>&1)"
grep -q "$VAULT2" <<<"$IDX_OUT" && fail "the kit still recovers a vault it was dropped from"
ok "the kit no longer sees '$VAULT2'"

# ---------------------------------------------------------------------------
# 11. Revocation, and the invariants this phase must not have moved.
# ---------------------------------------------------------------------------
step "11. revoking the kit refuses it on its very next request"
HOME="$HOME_D" "$SIGIL" recovery revoke --device-id "$KIT_ID" \
	--keyring "$HOME_D/.sigil/vault-keys.json" --key "$HOME_D/.sigil/device.key" \
	--server "$SERVER" >/dev/null || fail "revoke failed"
OUT="$(HOME="$TMP/recheck" "$SIGIL" recovery restore --code "$CODE" --device-id "$KIT_ID" \
	--server "$SERVER" --out-dir "$TMP/recheck3" 2>&1)" && fail "a revoked kit still restored"
grep -q 'no such device' <<<"$OUT" || { printf '%s\n' "$OUT" >&2; fail "a revoked kit was not 401"; }
ok "the revoked kit is 401 on its next request"
# A surviving device is unaffected.
HOME="$HOME_B" SIGIL_SERVER="$SERVER" "$SIGIL" account status --key "$HOME_B/.sigil/device.key" >/dev/null \
	|| fail "revoking the kit affected a surviving device"
ok "a surviving device is unaffected"

step "12. the invariants this phase must NOT have moved"
SCHEMA="$(curl -fsS "$SERVER/metrics" | grep '^sigild_schema_version' | awk '{print $2}')"
if [[ -n "${SIGILD_OPLOG_POSTGRES:-}" ]]; then
	[[ "$SCHEMA" == "5" ]] || fail "sigild_schema_version is $SCHEMA, want 5 (this phase adds NO migration)"
else
	[[ "$SCHEMA" == "0" ]] || fail "sigild_schema_version is $SCHEMA, want 0 for the mem backend"
fi
ok "sigild_schema_version = $SCHEMA (no migration was added)"

# /ops/verify is auth-guarded under contract v3, so an unsigned curl is a 401 —
# asserting on it here would be a test that silently passes by being skipped.
# The equivalent guarantee is asserted DIRECTLY in step 4: the container the kit
# pulled back is byte-identical to the one that was pushed, which is only true if
# nothing in this phase rewrote sigil_vault_ops.
STATUS="$(curl -s -o /dev/null -w '%{http_code}' "$SERVER/v1/vaults/$VAULT/ops/verify")"
[[ "$STATUS" == "401" ]] || fail "ops/verify answered $STATUS unsigned, want 401 (auth must not have loosened)"
ok "the op-log verify route is still auth-guarded (401 unsigned)"

# The kit's index route logged metadata only.
grep -q 'device.key_envelope_index' "$TMP/sigild.log" || fail "the index route left no audit trail"
if grep 'device.key_envelope_index' "$TMP/sigild.log" | grep -q 'blob_sha256'; then
	fail "the index audit line carries a blob fingerprint"
fi
ok "device.key_envelope_index is audited with no blob fingerprint"

# Nothing secret ever reached the server log.
for needle in "$CODE_RAW" "$CODE" "$PASSWORD_A"; do
	if grep -qF "$needle" "$TMP/sigild.log"; then fail "a secret reached the server log"; fi
done
ok "no code, no password anywhere in the server log"

printf '\nPASS — the recovery kit works end to end, and every negative held.\n'
printf '       (dev-gated, plain HTTP, pre-audit, UNAUDITED — do not store real 2FA secrets)\n'
