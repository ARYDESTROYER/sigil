#!/usr/bin/env bash
#
# THE PHASE 46 PROOF — device-to-device vault sharing, end to end, against a REAL
# sigild with dev-ops + multi-device auth (contract v3).
#
# It proves the whole chain, with no mocks anywhere:
#
#   1. Two devices A and B enroll with SEPARATE identity files and SEPARATE
#      hybrid identities, and publish only their hybrid PUBLIC keys.
#   2. A puts the RFC 6238 test seed in a TOTP vault, RE-KEYS that vault under a
#      random 32-byte VAULT KEY (the human password is never shared), pushes the
#      sealed vault, and SHARES the vault key to B — wrapped with the PQ-hybrid
#      (X25519 + ML-KEM-768) public-key path.
#   3. B ACCEPTS: it collects the opaque envelope, unwraps it with its hybrid
#      SECRET identity, and recovers the SAME vault key.
#   4. B generates the SAME TOTP CODE as A for the same pinned instant — and both
#      equal the published RFC 6238 vector.
#
# Plus the negative half, which is what makes the positive half mean anything:
#
#   * a THIRD device cannot fetch B's envelope (403), cannot fetch one for itself
#     (403), and cannot read the vault (403);
#   * a REVOKED device is refused (401);
#   * the bytes the server stored are BYTE-IDENTICAL to the opaque envelope that
#     was uploaded, and contain neither the vault key nor the 2FA seed — the
#     server relayed ciphertext it cannot read.
#
# STATUS: pre-audit, DEV-ONLY, UNAUDITED, localhost + plain HTTP. It boots a real
# sigild on a free loopback port and tears it down; nothing is exposed.
#
# Usage:  ./cli/tests/e2e-sharing.sh
#
# By default the server runs on the in-memory op-log and registry. Set
# SIGILD_OPLOG_POSTGRES=<dsn> to run the identical proof against the DURABLE
# Postgres backend (which also exercises migration 0004).
set -euo pipefail

export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/opt/homebrew/bin:$HOME/.cargo/bin:$PATH"

# Portability helpers (filemode / resolve_go). NOT a test — see the file header.
# shellcheck source=cli/tests/_e2e-lib.sh
. "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/_e2e-lib.sh"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
resolve_go

TMP="$(mktemp -d "${TMPDIR:-/tmp}/sigil-share-e2e.XXXXXX")"
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
# Build the REAL binaries. No stubs, no mocks.
# ---------------------------------------------------------------------------
step "building sigild and the sigil CLI"
"$GO" -C "$REPO/sigild" build -o "$TMP/sigild" ./cmd/server
cargo build --manifest-path "$REPO/cli/Cargo.toml" --bin sigil --quiet
SIGIL="$REPO/cli/target/debug/sigil"
[[ -x "$SIGIL" ]] || fail "sigil binary not found at $SIGIL"
ok "built $TMP/sigild and $SIGIL"

# ---------------------------------------------------------------------------
# Boot sigild: dev-ops ON, multi-device auth ON, three single-use enrollment
# tokens, an operator admin token. In-memory registry and op-log — this is a
# throwaway server on a free loopback port.
# ---------------------------------------------------------------------------
PORT="$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')"
SERVER="http://127.0.0.1:$PORT"
ADMIN_TOKEN="e2e-admin-token-000000000000001"

step "booting sigild on $SERVER (dev ops + device auth v3)"
SIGILD_ADDR="127.0.0.1:$PORT" \
SIGILD_ENABLE_DEV_OPS=1 \
SIGILD_DEVICE_AUTH=1 \
SIGILD_ENROLL_TOKENS="tokA-000000000000000000000001,tokB-000000000000000000000002,tokC-000000000000000000000003" \
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

# Each device gets its OWN HOME, so it gets its own identity file, its own hybrid
# identity, and its own vault keyring — exactly like three separate machines.
HOME_A="$TMP/deviceA"; HOME_B="$TMP/deviceB"; HOME_C="$TMP/deviceC"
mkdir -p "$HOME_A" "$HOME_B" "$HOME_C"

# run_as <home> <args...> — invoke the CLI as one device. SIGIL_DEVICE_KEY is
# what makes push/pull sign under contract v3 (their legacy rule is unchanged:
# with no --key and no SIGIL_DEVICE_KEY they send UNSIGNED), and it resolves to
# the same identity file the device/vault subcommands default to.
run_as() {
	local home="$1"; shift
	HOME="$home" SIGIL_SERVER="$SERVER" SIGIL_DEVICE_KEY="$home/.sigil/device.key" "$SIGIL" "$@"
}

# expect_fail <home> <expected-substring> <args...> — the command MUST fail and
# its output MUST mention the expected status.
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

# device_id <output> — pull the dev_ id out of a CLI message.
device_id() { grep -o 'dev_[A-Za-z0-9_-]*' <<<"$1" | head -1; }

VAULT="sharedvault"
PASSWORD_A='correct horse battery staple'
# The PUBLIC RFC 6238 test seed (ASCII "12345678901234567890" in base32). NOT a
# real secret — it is the published test vector, which is the whole point.
RFC_SEED="GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
RFC_T=59            # RFC 6238 Appendix B, T = 59
RFC_CODE="94287082" # ...the published SHA-1 / 8-digit code at that instant

# ---------------------------------------------------------------------------
# 1. Enroll three devices, each with its own identity and hybrid identity.
# ---------------------------------------------------------------------------
step "enrolling devices A, B and C (separate identities)"
A_ID="$(device_id "$(run_as "$HOME_A" device enroll --token tokA-000000000000000000000001 --label deviceA)")"
B_ID="$(device_id "$(run_as "$HOME_B" device enroll --token tokB-000000000000000000000002 --label deviceB)")"
C_ID="$(device_id "$(run_as "$HOME_C" device enroll --token tokC-000000000000000000000003 --label deviceC)")"
[[ -n "$A_ID" && -n "$B_ID" && -n "$C_ID" ]] || fail "enrollment did not yield three device IDs"
[[ "$A_ID" != "$B_ID" && "$B_ID" != "$C_ID" ]] || fail "device IDs collided"
ok "A=$A_ID  B=$B_ID  C=$C_ID"

step "publishing hybrid PUBLIC keys (secret halves stay local, 0600)"
run_as "$HOME_A" device hybrid-publish >/dev/null
run_as "$HOME_B" device hybrid-publish >/dev/null
run_as "$HOME_C" device hybrid-publish >/dev/null
for h in "$HOME_A" "$HOME_B" "$HOME_C"; do
	[[ -f "$h/.sigil/device.hybrid" ]] || fail "no hybrid secret identity in $h"
	mode="$(filemode "$h/.sigil/device.hybrid")"
	[[ "$mode" == "600" ]] || fail "hybrid secret in $h is mode $mode, want 600"
done
ok "three hybrid identities published; every secret half is mode 0600"
# (A device can only ever publish its OWN key — the CLI signs as itself and the
#  server 403s a mismatched path device ID; that rule is pinned by the Go test
#  TestHybridKeyCannotPublishForAnotherDevice, which can forge the mismatch.)

# ---------------------------------------------------------------------------
# 2. A builds a TOTP vault (password-sealed), then RE-KEYS it for sharing.
# ---------------------------------------------------------------------------
step "A adds the RFC 6238 seed to a password-sealed vault"
SIGIL_PASSWORD="$PASSWORD_A" run_as "$HOME_A" totp add rfc \
	--secret "$RFC_SEED" --issuer RFC6238 --algorithm sha1 --digits 8 --period 30 >/dev/null
A_CODE_PW="$(SIGIL_PASSWORD="$PASSWORD_A" run_as "$HOME_A" totp code rfc --at "$RFC_T" | awk '{print $1}')"
[[ "$A_CODE_PW" == "$RFC_CODE" ]] || fail "A's password-vault code at T=$RFC_T is $A_CODE_PW, want $RFC_CODE"
ok "A generates $A_CODE_PW at T=$RFC_T (matches the RFC 6238 vector)"

step "A re-keys the vault under a fresh random 32-byte VAULT KEY"
SIGIL_PASSWORD="$PASSWORD_A" run_as "$HOME_A" vault rekey --vault "$VAULT" --publish >/dev/null
A_FP="$(run_as "$HOME_A" vault list | grep "$VAULT" | sed 's/.*key_sha256=//')"
[[ -n "$A_FP" ]] || fail "A has no vault key after rekey"
ok "vault key fingerprint (A) = $A_FP"

# The password must NO LONGER open the re-keyed vault: it is sealed under the
# vault key now, and the password was never shared or wrapped.
if SIGIL_PASSWORD="$PASSWORD_A" run_as "$HOME_A" totp list >/dev/null 2>&1; then
	fail "the human password still opens the re-keyed vault"
fi
ok "the human password no longer opens the shared vault (it was never shared)"

step "A pushes the sealed vault to the op-log"
run_as "$HOME_A" push --vault "$VAULT" --in "$HOME_A/.sigil/totp-vault.sigil" >/dev/null
ok "pushed (A owns vault '$VAULT' by trust-on-first-write)"

A_CODE="$(run_as "$HOME_A" totp code rfc --vault-id "$VAULT" --at "$RFC_T" | awk '{print $1}')"
[[ "$A_CODE" == "$RFC_CODE" ]] || fail "A's key-sealed vault code is $A_CODE, want $RFC_CODE"
ok "A still generates $A_CODE from the key-sealed vault"

# ---------------------------------------------------------------------------
# 3. A shares to B; B accepts.
# ---------------------------------------------------------------------------
step "A shares vault '$VAULT' to device B (wrap + relay + grant)"
run_as "$HOME_A" vault share --vault "$VAULT" --to "$B_ID" --permission read \
	--envelope-out "$TMP/uploaded.env" >/dev/null
[[ -s "$TMP/uploaded.env" ]] || fail "no envelope was written"
ok "uploaded a $(wc -c <"$TMP/uploaded.env" | tr -d ' ')-byte opaque envelope"

step "B accepts the share"
run_as "$HOME_B" vault accept --vault "$VAULT" --envelope-out "$TMP/fetched.env" >/dev/null
B_FP="$(run_as "$HOME_B" vault list | grep "$VAULT" | sed 's/.*key_sha256=//')"
[[ "$A_FP" == "$B_FP" ]] || fail "B recovered a different vault key ($B_FP) than A holds ($A_FP)"
ok "B recovered the SAME vault key (fingerprint $B_FP)"

# ---------------------------------------------------------------------------
# 4. ZERO-KNOWLEDGE: the relay returned exactly the ciphertext it was given.
# ---------------------------------------------------------------------------
step "the server relayed the envelope VERBATIM and cannot read it"
cmp -s "$TMP/uploaded.env" "$TMP/fetched.env" \
	|| fail "the bytes the server returned differ from the bytes uploaded"
ok "uploaded bytes == bytes the server stored and served back (byte-identical)"

head -c 8 "$TMP/uploaded.env" | grep -q 'SIGILhyb' \
	|| fail "the envelope is not a hybrid (SIGILhyb) container"
ok "the envelope is a SIGILhyb container: X25519 + ML-KEM-768 KEM-then-AEAD"

if grep -q "$RFC_SEED" "$TMP/uploaded.env" 2>/dev/null; then
	fail "the envelope contains the 2FA seed in the clear"
fi
if strings "$TMP/uploaded.env" 2>/dev/null | grep -q "12345678901234567890"; then
	fail "the envelope contains the raw 2FA secret"
fi
ok "the envelope contains no plaintext seed — it is ciphertext to the server"

# ---------------------------------------------------------------------------
# 5. THE HEADLINE: B generates the SAME code as A at the same pinned instant.
# ---------------------------------------------------------------------------
step "B pulls the shared vault and generates a code"
run_as "$HOME_B" pull --vault "$VAULT" --out-dir "$HOME_B/inbox" >/dev/null
B_VAULT_FILE="$(ls "$HOME_B/inbox/$VAULT"/op-*.sigil | head -1)"
[[ -f "$B_VAULT_FILE" ]] || fail "B pulled no vault container"

B_CODE="$(run_as "$HOME_B" totp code rfc --vault "$B_VAULT_FILE" --vault-id "$VAULT" --at "$RFC_T" | awk '{print $1}')"
[[ "$B_CODE" == "$A_CODE" ]] || fail "B's code ($B_CODE) differs from A's ($A_CODE)"
[[ "$B_CODE" == "$RFC_CODE" ]] || fail "B's code ($B_CODE) is not the RFC 6238 vector ($RFC_CODE)"
ok "A=$A_CODE  B=$B_CODE  RFC 6238 vector=$RFC_CODE  -> ALL EQUAL at T=$RFC_T"

# ---------------------------------------------------------------------------
# 6. NEGATIVE: an unauthorized third device gets nothing.
# ---------------------------------------------------------------------------
step "device C (enrolled, unauthorized) is refused everywhere"
expect_fail "$HOME_C" "403" vault accept --vault "$VAULT" --for "$B_ID"
ok "C cannot fetch B's envelope (403 forbidden, not 401)"

expect_fail "$HOME_C" "403" vault accept --vault "$VAULT"
ok "C cannot fetch an envelope for itself on A's vault (403)"

expect_fail "$HOME_C" "403" pull --vault "$VAULT" --out-dir "$HOME_C/inbox"
ok "C cannot read the vault op-log (403)"

# C fabricates its OWN vault key for the SAME vault id and tries to inject an
# envelope into A's vault — the closest thing to a real attack this model allows.
SIGIL_PASSWORD='c-password-not-shared' run_as "$HOME_C" totp add junk --secret "$RFC_SEED" >/dev/null
SIGIL_PASSWORD='c-password-not-shared' run_as "$HOME_C" vault rekey --vault "$VAULT" >/dev/null
expect_fail "$HOME_C" "403" vault share --vault "$VAULT" --to "$C_ID"
ok "C cannot deposit an envelope on a vault it does not own (403)"

C_FP="$(run_as "$HOME_C" vault list | grep "$VAULT" | sed 's/.*key_sha256=//')"
[[ -n "$C_FP" && "$C_FP" != "$A_FP" ]] || fail "C ended up holding A's vault key"
ok "C's fabricated key ($C_FP) is NOT A's key ($A_FP) — C never learned it"

if run_as "$HOME_C" totp code rfc --vault "$B_VAULT_FILE" --vault-id "$VAULT" --at "$RFC_T" >/dev/null 2>&1; then
	fail "C opened the shared vault container with its own key"
fi
ok "C cannot open the shared vault container at all"

# ---------------------------------------------------------------------------
# 7. NEGATIVE: a REVOKED device is refused.
# ---------------------------------------------------------------------------
step "revoking device B"
run_as "$HOME_A" device revoke "$B_ID" --admin-token "$ADMIN_TOKEN" >/dev/null
ok "operator revoked $B_ID"

expect_fail "$HOME_B" "401" vault accept --vault "$VAULT"
ok "the revoked device cannot collect an envelope (401)"

expect_fail "$HOME_B" "401" device hybrid-publish
ok "the revoked device cannot publish a hybrid key (401)"

expect_fail "$HOME_B" "401" pull --vault "$VAULT" --out-dir "$HOME_B/inbox2"
ok "the revoked device cannot read the vault (401)"

# Honest scope, stated as an assertion rather than a comment: revocation stops
# FUTURE access. B already accepted, so it still holds the key locally — that is
# why re-keying and re-sharing is the real remediation.
STILL="$(run_as "$HOME_B" totp code rfc --vault "$B_VAULT_FILE" --vault-id "$VAULT" --at "$RFC_T" | awk '{print $1}')"
[[ "$STILL" == "$RFC_CODE" ]] || fail "unexpected local state on the revoked device"
ok "revocation stops FUTURE server access; it cannot un-learn an already-accepted key (documented limit)"

# ---------------------------------------------------------------------------
# 8. The server's own logs never contain the envelope.
# ---------------------------------------------------------------------------
step "the server never logged the envelope bytes"
if grep -q 'SIGILhyb' "$TMP/sigild.log"; then
	fail "sigild logged envelope content"
fi
grep -q 'vault.key_envelope_put' "$TMP/sigild.log" || fail "no key_envelope_put audit line"
grep -q 'vault.key_envelope_get' "$TMP/sigild.log" || fail "no key_envelope_get audit line"
grep -q 'blob_sha256' "$TMP/sigild.log" || fail "no blob fingerprint in the audit trail"
ok "audit trail records fingerprints and metadata only"

printf '\n=== PASS — device-to-device vault sharing works end to end.\n'
printf '    A(%s) -> hybrid-wrapped vault key -> opaque relay -> B(%s)\n' "$A_ID" "$B_ID"
printf '    Both devices generate %s at T=%s (RFC 6238 vector).\n' "$RFC_CODE" "$RFC_T"
printf '    The server relayed ciphertext byte-for-byte and could not read it.\n'
