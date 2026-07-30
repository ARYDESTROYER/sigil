# shellcheck shell=bash
# _e2e-lib.sh — portability helpers shared by the end-to-end shell proofs.
#
# NOT A TEST. The leading underscore is load-bearing: scripts/gate.sh's runner
# loop, its CI-drift check and its inventory count all skip `cli/tests/_*.sh`, so
# this file is never mistaken for a suite (the same reason the node helpers are
# named `*-helper.mjs`).
#
# ─────────────────────────────────────────────────────────────────────────────
# WHY: these scripts are written on macOS and run on Linux in CI, and BOTH of the
# things below differ between the two. `e2e-sharing.sh` and `e2e-recovery.sh` had
# been failing on every CI run for several phases because of the first one.

# filemode <path> — the permission bits as plain octal digits, e.g. `600`.
#
# ⚠️ THE BUG THIS REPLACES, because the naive fix looks identical and is wrong:
#
#     mode="$(stat -f '%Lp' "$p" 2>/dev/null || stat -c '%a' "$p")"
#
# That reads as "try BSD, fall back to GNU". It is not, because **GNU `stat -f`
# does not fail** — in GNU coreutils `-f` means `--file-system`, so the format
# string is consumed as a FILE ARGUMENT and the real path is reported as
# filesystem status, on stdout, with exit status 0-ish. Observed on ubuntu:24.04:
#
#     mode=[  File: "/tmp/x"
#         ID: 1e0af95adc552b5b Namelen: 255     Type: overlayfs
#     Block size: 4096       Fundamental block size: 4096
#     Blocks: Total: 238733024  Free: 229665120  Available: 217519805
#     Inodes: Total: 60710912   Free: 59225470
#     700]
#
# — the GNU filesystem dump AND the fallback's answer, concatenated, so
# `[[ "$mode" == "700" ]]` fails and the proof reports a permissions violation
# that does not exist. On macOS it worked perfectly, which is why it survived.
#
# ⭐ SO PROBE GNU FIRST. BSD `stat` has no `-c` and fails cleanly, which makes the
# GNU→BSD direction unambiguous; the BSD→GNU direction is not.
if stat -c '%a' . >/dev/null 2>&1; then
	filemode() { stat -c '%a' "$1"; } # GNU coreutils (Linux)
else
	filemode() { stat -f '%Lp' "$1"; } # BSD stat (macOS)
fi

# resolve_go — set $GO to a usable Go toolchain, or exit 1.
#
# $GO wins (interop.yml sets `GO: go`); then whatever `go` is on PATH, which is
# what actions/setup-go provides — note setup-go puts `go` on PATH and NEVER sets
# $GO, so a PATH lookup is required, not optional; then the stock Linux tarball
# location; then this macOS dev machine's Homebrew.
#
# It EXITS rather than skipping. A proof that quietly does not run reads exactly
# like a proof that passed — see docs/engineering-lessons.md.
resolve_go() {
	if [[ -n "${GO:-}" ]] && command -v "$GO" >/dev/null 2>&1; then
		return 0
	fi
	local c
	for c in go /usr/local/go/bin/go /opt/homebrew/bin/go; do
		if command -v "$c" >/dev/null 2>&1; then
			GO="$c"
			return 0
		fi
	done
	echo "no Go toolchain found (set \$GO, or put \`go\` on PATH)" >&2
	exit 1
}
