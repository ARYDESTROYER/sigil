#!/bin/sh
# deploy/preflight.sh — GO / NO-GO preflight gate for a sigild deploy.
#
# Encodes the wall-clock prerequisites from docs/deployment.md (§4 DNS/ACME,
# §5 secrets, §2 image flow, §8 toolchain) as a checklist. It is a READ-ONLY
# gate: it provisions NOTHING, exposes NOTHING, mutates NOTHING — it only
# inspects the environment and refuses (non-zero exit) if any gate is unmet.
#
# Passing preflight is NECESSARY but NOT SUFFICIENT: it confirms the target is
# *staged*, but the actual publish + apply still require the explicit human
# action described in docs/deployment.md §2 and the stealth gate in §7. This
# script never deploys.
#
# Usage:
#   SIGIL_DEPLOY_HOST=api.example.com ./deploy/preflight.sh
#
# Environment (all optional; unset inputs cause the corresponding gate to FAIL):
#   SIGIL_DEPLOY_HOST   target FQDN whose A/AAAA must already resolve (§4).
#   SIGIL_ENV_FILE      systemd EnvironmentFile path; default /etc/sigild/sigild.env (§5).
#   SIGIL_NOMAD_JOB     Nomad jobspec to check the image line in;
#                       default <repo>/deploy/nomad/sigild.nomad.hcl (§2).
#   SIGIL_SKIP_ENVFILE  set to 1 to skip the EnvironmentFile gate (Shape 2/Nomad,
#                       where secrets come from Vault, not a systemd file).
#
# Exit status: 0 = GO (all gates PASS); non-zero = NO-GO (count of failed gates).

# Intentionally NOT `set -e`: we want to run EVERY gate and report the full
# checklist, then exit non-zero on the tally. `set -u` catches typos in vars.
set -u

# ---- presentation ----------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	C_PASS='\033[32m'
	C_FAIL='\033[31m'
	C_DIM='\033[2m'
	C_OFF='\033[0m'
else
	C_PASS='' C_FAIL='' C_DIM='' C_OFF=''
fi

FAILS=0

pass() { printf "  ${C_PASS}PASS${C_OFF}  %s\n" "$1"; }
fail() {
	printf "  ${C_FAIL}FAIL${C_OFF}  %s\n" "$1"
	[ -n "${2:-}" ] && printf "        ${C_DIM}%s${C_OFF}\n" "$2"
	FAILS=$((FAILS + 1))
}

# Resolve repo root from this script's location (no `cd`, read-only).
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

NOMAD_JOB="${SIGIL_NOMAD_JOB:-$REPO_ROOT/deploy/nomad/sigild.nomad.hcl}"
ENV_FILE="${SIGIL_ENV_FILE:-/etc/sigild/sigild.env}"

printf "%s\n" "sigild deploy preflight — GO / NO-GO gates (read-only)"
printf "${C_DIM}%s${C_OFF}\n\n" "docs/deployment.md §2/§4/§5/§8 · provisions nothing · exposes nothing"

# ---- gate: DNS resolves (§4 DNS/ACME wall-clock gate) -----------------------
# ACME requires the public A/AAAA record for the target host to ALREADY resolve.
resolves() {
	host="$1"
	# Try the common resolvers in order; success if any returns an address.
	if command -v getent >/dev/null 2>&1; then
		# getent ahosts covers both A and AAAA; works on Linux deploy hosts.
		getent ahosts "$host" 2>/dev/null | grep -q . && return 0
	fi
	if command -v dig >/dev/null 2>&1; then
		out=$(dig +short A "$host" 2>/dev/null; dig +short AAAA "$host" 2>/dev/null)
		[ -n "$out" ] && return 0
	fi
	if command -v host >/dev/null 2>&1; then
		host "$host" 2>/dev/null | grep -Eqi 'has( IPv6)? address' && return 0
	fi
	if command -v nslookup >/dev/null 2>&1; then
		nslookup "$host" 2>/dev/null | awk '/^Address: /{print}' | grep -q . && return 0
	fi
	return 1
}

if [ -z "${SIGIL_DEPLOY_HOST:-}" ]; then
	fail "DNS: target host resolves" \
		"SIGIL_DEPLOY_HOST is unset — set it to the api.<host> FQDN that must already resolve (§4)."
elif resolves "$SIGIL_DEPLOY_HOST"; then
	pass "DNS: $SIGIL_DEPLOY_HOST resolves (A/AAAA present — ACME prerequisite met)"
else
	fail "DNS: $SIGIL_DEPLOY_HOST resolves" \
		"no A/AAAA record yet — create it and wait for propagation before Caddy/ACME (§4)."
fi

# ---- gate: systemd EnvironmentFile present (§5 secrets, Shape 1) ------------
if [ "${SIGIL_SKIP_ENVFILE:-0}" = "1" ]; then
	pass "Secrets: EnvironmentFile gate SKIPPED (Shape 2/Nomad — secrets via Vault, §5)"
elif [ -f "$ENV_FILE" ]; then
	pass "Secrets: EnvironmentFile $ENV_FILE present (staged out-of-band, never committed)"
else
	fail "Secrets: EnvironmentFile $ENV_FILE present" \
		"stage it from the password manager on the target host first (§5); or set SIGIL_SKIP_ENVFILE=1 for the Nomad shape."
fi

# ---- gate: Nomad image is not the PLACEHOLDER (§2 artifact flow) ------------
if [ ! -f "$NOMAD_JOB" ]; then
	fail "Image: jobspec readable" "Nomad jobspec not found at $NOMAD_JOB."
elif grep -q 'ghcr.io/PLACEHOLDER' "$NOMAD_JOB"; then
	fail "Image: jobspec no longer the placeholder" \
		"$NOMAD_JOB still points at ghcr.io/PLACEHOLDER — repoint at the published PRIVATE GHCR image (§2)."
else
	pass "Image: $NOMAD_JOB image is not the PLACEHOLDER (real image wired in)"
fi

# ---- gate: Docker present (§8 toolchain) -----------------------------------
if command -v docker >/dev/null 2>&1; then
	pass "Toolchain: docker present ($(command -v docker))"
else
	fail "Toolchain: docker present" "install Docker on the build/run host (§8)."
fi

# ---- verdict ---------------------------------------------------------------
printf "\n"
if [ "$FAILS" -eq 0 ]; then
	printf "${C_PASS}%s${C_OFF}\n" "GO — all preflight gates PASS."
	printf "${C_DIM}%s${C_OFF}\n" "Necessary, not sufficient: publish + apply still need explicit human action (deployment.md §2/§7)."
	exit 0
fi
printf "${C_FAIL}%s${C_OFF}\n" "NO-GO — $FAILS gate(s) FAILED. Fix the prerequisite(s); do not override."
exit "$FAILS"
