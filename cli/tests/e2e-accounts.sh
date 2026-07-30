#!/usr/bin/env bash
#
# THE PHASE 52 PROOF — ACCOUNTS, end to end, against a REAL sigild with dev-ops +
# multi-device auth (contract v3). No mocks anywhere: real server, real CLI, four
# devices with four separate HOMEs.
#
# It proves the two defects the account model exists to fix:
#
#   DEFECT 1 (entitlement) — a subscription used to belong to a DEVICE, so paying
#     on your phone did not entitle your laptop. Now a second device that JOINS by
#     invite lands in the SAME account, which is the billing subject. This script
#     proves the membership half (billing itself needs a provider, so it is
#     covered by the server's Go tests).
#
#   DEFECT 2 (orphaned vaults) — a vault used to be owned by the DEVICE that first
#     wrote it, so revoking that device orphaned the vault forever. Here device A
#     claims a vault, A is REVOKED, and its sibling B — which was never granted
#     anything — still reads it, writes it, GRANTS access to it and ROTATES its
#     key. Before this phase every one of those was a 403.
#
# Plus the boundary, which is what makes the above mean anything:
#
#   * an invite is SINGLE-USE — a second redemption is refused;
#   * device C, enrolled with its own OPERATOR token, lands in a DIFFERENT account
#     and is 403 on A's vault three ways;
#   * a member may revoke a SIBLING (200) but not a foreign device (403);
#   * no request ever names an account, and no invite secret is ever re-served —
#     `account invites` returns metadata only, and the server never logs one.
#
# STATUS: pre-audit, DEV-ONLY, UNAUDITED, localhost + plain HTTP. It boots a real
# sigild on a free loopback port and tears it down; nothing is exposed.
#
# Usage:  ./cli/tests/e2e-accounts.sh
#
# By default the server runs on the in-memory op-log and registry. Set
# SIGILD_OPLOG_POSTGRES=<dsn> to run the identical proof against the DURABLE
# Postgres backend (which also exercises migration 0005).
set -euo pipefail

export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/opt/homebrew/bin:$HOME/.cargo/bin:$PATH"

# Portability helpers (filemode / resolve_go). NOT a test — see the file header.
# shellcheck source=cli/tests/_e2e-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_e2e-lib.sh"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
resolve_go

TMP="$(mktemp -d "${TMPDIR:-/tmp}/sigil-acct-e2e.XXXXXX")"
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

# ---------------------------------------------------------------------------
# Boot sigild: dev-ops ON, multi-device auth ON. TWO operator enrollment tokens
# only — every OTHER device in this script joins by INVITE, which is the point.
# ---------------------------------------------------------------------------
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
SERVER="http://127.0.0.1:$PORT"
ADMIN_TOKEN="e2e-admin-token-000000000000001"

step "booting sigild on $SERVER (dev ops + device auth v3 + accounts)"
SIGILD_ADDR="127.0.0.1:$PORT" \
SIGILD_ENABLE_DEV_OPS=1 \
SIGILD_DEVICE_AUTH=1 \
SIGILD_ENROLL_TOKENS="tokA-000000000000000000000001,tokC-000000000000000000000003" \
SIGILD_ADMIN_TOKEN="$ADMIN_TOKEN" \
SIGILD_ACCOUNT_MAX_DEVICES=4 \
SIGILD_ACCOUNT_MAX_INVITES=3 \
SIGILD_ACCOUNT_INVITE_TTL=10m \
SIGILD_OPLOG_POSTGRES="${SIGILD_OPLOG_POSTGRES:-}" \
	"$TMP/sigild" >"$TMP/sigild.log" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 100); do
	if curl -fsS "$SERVER/healthz" >/dev/null 2>&1; then break; fi
	sleep 0.1
done
curl -fsS "$SERVER/healthz" >/dev/null || fail "sigild did not become healthy (see $TMP/sigild.log)"
ok "sigild is healthy (pid $SERVER_PID)"

HOME_A="$TMP/deviceA"; HOME_B="$TMP/deviceB"; HOME_C="$TMP/deviceC"; HOME_D="$TMP/deviceD"
mkdir -p "$HOME_A" "$HOME_B" "$HOME_C" "$HOME_D"

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
	if ! grep -q -- "$want" <<<"$out"; then
		printf '%s\n' "$out" >&2
		fail "expected '$*' to fail with $want"
	fi
}

device_id()  { grep -o 'dev_[A-Za-z0-9_-]*'  <<<"$1" | head -1; }
account_id() { grep -o 'acct_[A-Za-z0-9_-]*' <<<"$1" | head -1; }

VAULT="acctvault"
PASSWORD_A='correct horse battery staple'
RFC_SEED="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
RFC_T=59
RFC_CODE="94287082"

# ---------------------------------------------------------------------------
# 1. A enrolls with an OPERATOR token and founds an account.
# ---------------------------------------------------------------------------
step "A enrolls with an operator token (founds a NEW account)"
A_ID="$(device_id "$(run_as "$HOME_A" device enroll --token tokA-000000000000000000000001 --label deviceA)")"
[[ -n "$A_ID" ]] || fail "A did not enroll"

A_STATUS="$(run_as "$HOME_A" account status)"
ACCT_A="$(account_id "$A_STATUS")"
[[ -n "$ACCT_A" ]] || fail "A has no account: $A_STATUS"
grep -q 'devices: 1/4 active' <<<"$A_STATUS" || fail "A's account should hold 1/4 devices: $A_STATUS"
grep -q 'NO RECOVERY' <<<"$A_STATUS" || fail "a single-device account must warn that there is no recovery"
ok "A=$A_ID is alone in account $ACCT_A (and is told there is NO RECOVERY)"

# ---------------------------------------------------------------------------
# 2. A mints an invite; B JOINS with it through the ORDINARY enroll command.
# ---------------------------------------------------------------------------
step "A mints a single-use invite"
INVITE="$(run_as "$HOME_A" account invite 2>/dev/null | head -1)"
[[ "$INVITE" == join_* ]] || fail "expected a join_ invite secret, got ${INVITE:0:8}…"
ok "minted an invite (secret withheld from this log)"

INV_LIST="$(run_as "$HOME_A" account invites)"
grep -q 'inv_' <<<"$INV_LIST" || fail "the open invite is not listed: $INV_LIST"
if grep -qF "$INVITE" <<<"$INV_LIST"; then
	fail "the invite LISTING echoed the secret"
fi
INVITE_ID="$(grep -o 'inv_[A-Za-z0-9_-]*' <<<"$INV_LIST" | head -1)"
ok "the listing shows the public handle $INVITE_ID and NOT the secret"

step "B joins A's account with 'sigil device enroll --token <invite>'"
B_ID="$(device_id "$(run_as "$HOME_B" device enroll --token "$INVITE" --label deviceB)")"
[[ -n "$B_ID" && "$B_ID" != "$A_ID" ]] || fail "B did not enroll as a distinct device"
ok "B=$B_ID enrolled — no new command, no new wire format, the enroll path is unchanged"

step "A and B report ONE account with TWO devices"
A_STATUS="$(run_as "$HOME_A" account status)"
B_STATUS="$(run_as "$HOME_B" account status)"
ACCT_B="$(account_id "$B_STATUS")"
[[ "$ACCT_A" == "$ACCT_B" ]] || fail "B landed in $ACCT_B, not A's account $ACCT_A"
grep -q 'devices: 2/4 active' <<<"$A_STATUS" || fail "A should now see 2/4 devices: $A_STATUS"
grep -q 'devices: 2/4 active' <<<"$B_STATUS" || fail "B should see 2/4 devices: $B_STATUS"
grep -q "$B_ID" <<<"$A_STATUS" || fail "A does not list B as a member"
grep -q "$A_ID" <<<"$B_STATUS" || fail "B does not list A as a member"
grep -q 'this device' <<<"$B_STATUS" || fail "B's own row is not marked"
ok "both devices see account $ACCT_A with members $A_ID and $B_ID"

step "the invite was SINGLE-USE"
[[ "$(run_as "$HOME_A" account invites)" == "no open invites" ]] || fail "the redeemed invite is still open"
expect_fail "$HOME_D" "401" device enroll --token "$INVITE" --label deviceD-replay
ok "a redeemed invite is refused (401) and no longer listed"

# ---------------------------------------------------------------------------
# 3. A builds a shared vault, claims it, and shares the key to B.
# ---------------------------------------------------------------------------
step "A and B publish hybrid PUBLIC keys"
run_as "$HOME_A" device hybrid-publish >/dev/null
run_as "$HOME_B" device hybrid-publish >/dev/null
ok "published (secret halves stay local, 0600)"

step "A seals the RFC 6238 seed, re-keys the vault, and pushes it (claiming '$VAULT')"
SIGIL_PASSWORD="$PASSWORD_A" run_as "$HOME_A" totp add rfc \
	--secret "$RFC_SEED" --issuer RFC6238 --algorithm sha1 --digits 8 --period 30 >/dev/null
SIGIL_PASSWORD="$PASSWORD_A" run_as "$HOME_A" vault rekey --vault "$VAULT" --publish >/dev/null
run_as "$HOME_A" push --vault "$VAULT" --in "$HOME_A/.sigil/totp-vault.sigil" >/dev/null
A_FP="$(run_as "$HOME_A" vault list | grep "$VAULT" | sed 's/.*key_sha256=//')"
[[ -n "$A_FP" ]] || fail "A holds no vault key"
ok "vault '$VAULT' is now owned by ACCOUNT $ACCT_A (claimed on A's first write)"

step "A shares the vault key to its sibling B"
run_as "$HOME_A" vault share --vault "$VAULT" --to "$B_ID" --permission read >/dev/null
run_as "$HOME_B" vault accept --vault "$VAULT" >/dev/null
B_FP="$(run_as "$HOME_B" vault list | grep "$VAULT" | sed 's/.*key_sha256=//')"
[[ "$A_FP" == "$B_FP" ]] || fail "B recovered a different vault key"
ok "B holds the same vault key ($B_FP) — membership authorized it, the WRAP is what gave it plaintext"

# ---------------------------------------------------------------------------
# 4. C enrolls with its OWN operator token: a DIFFERENT account, 403 everywhere.
# ---------------------------------------------------------------------------
step "C enrolls with a second OPERATOR token -> a DIFFERENT account"
C_ID="$(device_id "$(run_as "$HOME_C" device enroll --token tokC-000000000000000000000003 --label deviceC)")"
ACCT_C="$(account_id "$(run_as "$HOME_C" account status)")"
[[ -n "$ACCT_C" && "$ACCT_C" != "$ACCT_A" ]] || fail "C landed in A's account ($ACCT_C)"
ok "C=$C_ID is in account $ACCT_C, which is NOT $ACCT_A"

step "C is refused on A's account's vault, three ways"
expect_fail "$HOME_C" "403" pull --vault "$VAULT" --out-dir "$HOME_C/inbox"
ok "C cannot read the op-log (403)"
run_as "$HOME_C" device hybrid-publish >/dev/null
expect_fail "$HOME_C" "403" vault accept --vault "$VAULT"
ok "C cannot collect a key envelope (403)"
SIGIL_PASSWORD='c-password' run_as "$HOME_C" totp add junk --secret "$RFC_SEED" >/dev/null
expect_fail "$HOME_C" "403" push --vault "$VAULT" --in "$HOME_C/.sigil/totp-vault.sigil"
ok "C cannot write the vault (403)"

step "C cannot see or touch A's account"
C_STATUS="$(run_as "$HOME_C" account status)"
if grep -q "$A_ID" <<<"$C_STATUS" || grep -q "$B_ID" <<<"$C_STATUS"; then
	fail "C's account listing leaked A's members"
fi
ok "C's account listing shows only C (no route names an account, so none can be asked for)"
expect_fail "$HOME_C" "404" account revoke-invite "$INVITE_ID"
ok "a foreign invite handle is 404 — indistinguishable from one that never existed"

# ---------------------------------------------------------------------------
# 5. ★ THE HEADLINE: revoke the vault's original claimant. Its SIBLING keeps
#    full control — read, write, GRANT and ROTATE — with no grant row anywhere.
# ---------------------------------------------------------------------------
step "the operator revokes A (the device that claimed the vault)"
run_as "$HOME_A" device revoke "$A_ID" --admin-token "$ADMIN_TOKEN" >/dev/null
expect_fail "$HOME_A" "401" pull --vault "$VAULT" --out-dir "$HOME_A/inbox"
ok "A is revoked and refused (401). Before Phase 52 this ORPHANED the vault."

step "sibling B still READS the vault"
run_as "$HOME_B" pull --vault "$VAULT" --out-dir "$HOME_B/inbox" >/dev/null
B_VAULT_FILE="$(ls "$HOME_B/inbox/$VAULT"/op-*.sigil | head -1)"
[[ -f "$B_VAULT_FILE" ]] || fail "B pulled nothing"
B_CODE="$(run_as "$HOME_B" totp code rfc --vault "$B_VAULT_FILE" --vault-id "$VAULT" --at "$RFC_T" | awk '{print $1}')"
[[ "$B_CODE" == "$RFC_CODE" ]] || fail "B's code is $B_CODE, want $RFC_CODE"
ok "B generates $B_CODE at T=$RFC_T (the RFC 6238 vector)"

step "sibling B still WRITES the vault — with NO grant row of its own"
run_as "$HOME_B" push --vault "$VAULT" --in "$B_VAULT_FILE" >/dev/null
ok "B appended an op (authorized by ACCOUNT ownership, not by a grant)"

step "★ sibling B still GRANTS access — the owner-only route, after the owner died"
run_as "$HOME_B" device grant "$C_ID" --vault "$VAULT" --permission read >/dev/null
ok "B granted $C_ID read access. This is the defect: before Phase 52 it was a 403."
run_as "$HOME_C" pull --vault "$VAULT" --out-dir "$HOME_C/inbox2" >/dev/null
ok "C (a foreign account) now reads the vault BECAUSE it was granted, one device at a time"

step "★ sibling B still ROTATES the vault key"
# Phase 54: a rotation that would silently delete a current holder's envelope is
# REFUSED. A (the revoked device that claimed the vault) still holds one, so
# dropping it has to be stated — that is the guard, not a regression.
if run_as "$HOME_B" vault rotate --vault "$VAULT" --to "$B_ID" --file "$B_VAULT_FILE" >/dev/null 2>&1; then
	fail "a rotation that would silently drop $A_ID's envelope must be refused"
fi
ok "an unnamed current holder aborts the rotation (Phase 54 drop guard)"
run_as "$HOME_B" vault rotate --vault "$VAULT" --to "$B_ID" --drop-all-others --file "$B_VAULT_FILE" >/dev/null
B_FP2="$(run_as "$HOME_B" vault list | grep "$VAULT" | sed 's/.*key_sha256=//')"
[[ -n "$B_FP2" && "$B_FP2" != "$B_FP" ]] || fail "rotation did not change the vault key"
run_as "$HOME_B" push --vault "$VAULT" --in "$B_VAULT_FILE" >/dev/null
B_CODE2="$(run_as "$HOME_B" totp code rfc --vault "$B_VAULT_FILE" --vault-id "$VAULT" --at "$RFC_T" | awk '{print $1}')"
[[ "$B_CODE2" == "$RFC_CODE" ]] || fail "B lost the vault across the rotation"
ok "rotated $B_FP -> $B_FP2 and B still generates $B_CODE2"

# ---------------------------------------------------------------------------
# 6. SIBLING REVOCATION: a member may retire a member, and only a member.
# ---------------------------------------------------------------------------
step "B invites D into the account, then revokes it as a SIBLING"
INVITE_D="$(run_as "$HOME_B" account invite --ttl 300 2>/dev/null | head -1)"
D_ID="$(device_id "$(run_as "$HOME_D" device enroll --token "$INVITE_D" --label deviceD)")"
[[ -n "$D_ID" ]] || fail "D did not join"
# The cap counts ACTIVE devices, not lifetime enrolments. A was revoked in step 5,
# so it is still LISTED but no longer holds a seat: B + D = 2 active of 4.
D_STATUS="$(run_as "$HOME_B" account status)"
grep -q 'devices: 2/4 active' <<<"$D_STATUS" || fail "the account should hold 2/4 active: $D_STATUS"
grep -q '1 revoked' <<<"$D_STATUS" || fail "the revoked claimant should be reported separately: $D_STATUS"
ok "D=$D_ID joined via B's invite (any member may invite — membership is FLAT)"
ok "revoked A is LISTED but does not hold a seat — the cap is on CONCURRENT devices"

run_as "$HOME_B" device revoke "$D_ID" >/dev/null
expect_fail "$HOME_D" "401" account status
ok "B revoked its sibling D with no admin token (200), and D is now 401"

# ★ THE SEAT COMES BACK. Two of the account's four enrolments are now revoked; if
# revoked rows kept their seats this account would be permanently stuck, because
# every remedy the model prescribes ("revoke and re-enroll") would burn one.
E_STATUS="$(run_as "$HOME_B" account status)"
grep -q 'devices: 1/4 active' <<<"$E_STATUS" || fail "revoking D should free its seat: $E_STATUS"
grep -q '2 revoked' <<<"$E_STATUS" || fail "both revoked devices should be reported: $E_STATUS"
INVITE_E="$(run_as "$HOME_B" account invite --ttl 300 2>/dev/null | head -1)"
[[ -n "$INVITE_E" ]] || fail "B could not mint an invite after two revocations — the seats were never freed"
# Revoke it again so the open-invite quota section below starts from a clean slate.
INVITE_E_ID="$(run_as "$HOME_B" account invites | awk '/^  inv_/ {print $1; exit}')"
[[ -n "$INVITE_E_ID" ]] || fail "could not read back the invite handle"
run_as "$HOME_B" account revoke-invite "$INVITE_E_ID" >/dev/null
ok "★ after two revocations the account is 1/4 active and can still invite — a revoked device FREES its seat"

expect_fail "$HOME_B" "403" device revoke "$C_ID"
ok "B canNOT revoke C, which is in another account (403)"
expect_fail "$HOME_B" "403" device revoke "dev_doesnotexist"
ok "an UNKNOWN device is also 403 to a non-admin — never 404, so there is no existence oracle"

# ---------------------------------------------------------------------------
# 7. The invite quota, and what the server did NOT log.
# ---------------------------------------------------------------------------
step "the OPEN-invite quota is enforced"
run_as "$HOME_B" account invite >/dev/null 2>&1
run_as "$HOME_B" account invite >/dev/null 2>&1
run_as "$HOME_B" account invite >/dev/null 2>&1
expect_fail "$HOME_B" "409" account invite
ok "a fourth open invite is refused (409) at SIGILD_ACCOUNT_MAX_INVITES=3"

step "the server never logged an invite secret"
if grep -q 'join_' "$TMP/sigild.log"; then
	fail "sigild logged an invite secret"
fi
grep -q 'account.invite_created' "$TMP/sigild.log" || fail "no invite_created audit line"
grep -q 'account.device_joined' "$TMP/sigild.log" || fail "no device_joined audit line"
grep -q 'inv_' "$TMP/sigild.log" || fail "the audit trail should carry the PUBLIC invite handle"
ok "the audit trail records public handles and metadata only"

if curl -fsS "$SERVER/metrics" | grep -qE 'acct_|inv_|join_|dev_'; then
	fail "/metrics leaked an identifier"
fi
ok "/metrics carries counts only — no account, device or invite identifier"

printf '\n=== PASS — accounts are the subject of entitlement and the owner of vaults.\n'
printf '    Account %s = {A %s (revoked), B %s}; D joined and was sibling-revoked.\n' "$ACCT_A" "$A_ID" "$B_ID"
printf '    A claimed the vault and was revoked; B read, wrote, GRANTED and ROTATED it anyway.\n'
printf '    Account %s (device C) was 403 on all of it until B granted that ONE device.\n' "$ACCT_C"
printf '    No request named an account; no invite secret was ever re-served or logged.\n'
