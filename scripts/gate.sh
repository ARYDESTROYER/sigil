#!/usr/bin/env bash
# Sigil full gate. Enumerates every test entry point DYNAMICALLY so a newly added
# suite cannot be silently missed — that has happened twice (a 10th and then an
# 11th interop test), and this repo's recurring defect is work that quietly does
# not run looking identical to work that passes.
#
# Usage:  ./gate.sh [--quick]     (--quick skips ONLY the shell e2e scripts)
#
# ⚠️ --quick does NOT skip Postgres, deliberately. An earlier version of this line
# claimed it did, which was both wrong and the wrong idea: a DSN-less run silently
# skips ~30 tests, and two real regressions (deleting migration 0005's ownership
# backfill, and dropping the active-device filter from the seat count) have been
# shown to survive one. The gated suite is not optional.
#
# It COUNTS results rather than trusting exit codes, and it prints a final
# inventory so a missing suite is visible.

set -uo pipefail
# ⚠️ RESOLVE THE REPO FROM THIS SCRIPT'S OWN LOCATION. An earlier version hardcoded
# an absolute path to one checkout, so running the gate from a git WORKTREE built and
# tested a DIFFERENT tree — it reported "getrandom==0" while the worktree's lockfile
# contained a planted getrandom stanza. A gate that reports green about a tree it is
# not looking at is worse than no gate.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1
echo "gating: $(pwd)  ($(git rev-parse --short HEAD 2>/dev/null || echo 'no git'))"
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/opt/homebrew/bin:$PATH"
export NEXT_TELEMETRY_DISABLED=1
GO=/opt/homebrew/bin/go
QUICK=${1:-}
fail=0
note() { printf '%s\n' "$*"; }
bad()  { fail=1; printf '  ✗ %s\n' "$*"; }
ok()   { printf '  ✓ %s\n' "$*"; }

note "=== INVARIANTS ==="
for l in libsigil/Cargo.lock sigil-wasm/Cargo.lock; do
  c=$(grep -c 'name = "getrandom"' "$l")
  [ "$c" -eq 0 ] && ok "$l getrandom==0" || bad "$l getrandom=$c"
done
deps=$($GO -C sigild list -m -f '{{if not .Indirect}}{{.Path}}{{end}}' all 2>/dev/null | grep -v 'sigild$' | grep -c .)
[ "$deps" -eq 1 ] && ok "sigild has exactly 1 direct dep" || bad "sigild direct deps = $deps"

note "=== WORKFLOWS PARSE ==="
python3 -c "
import yaml,glob,sys
bad=0
for f in sorted(glob.glob('.github/workflows/*.yml')):
    try: yaml.safe_load(open(f))
    except Exception as e: print('  ✗',f,e); bad=1
print('  ✓ all workflows parse' if not bad else '')
sys.exit(bad)" || fail=1

note "=== GO (sigild) ==="
[ -z "$(gofmt -l sigild)" ] && ok "gofmt clean" || bad "gofmt: $(gofmt -l sigild)"
$GO -C sigild vet ./... 2>/dev/null && ok "vet clean" || bad "vet"
# ⚠️ SKIPS ARE THE POINT. Without a DSN ~30 Postgres tests skip, and counting only
# PASS/FAIL hides that entirely — two real regressions (deleting migration 0005's
# ownership backfill, and dropping the active-device filter from the seat count)
# have been shown to survive a DSN-less run while going red with one. So: run the
# gated suite for real when we can, and REPORT the skips either way.
if [ -z "${SIGILD_TEST_POSTGRES:-}" ] && command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  PGPORT=$(python3 -c "import socket;s=socket.socket();s.bind(('127.0.0.1',0));print(s.getsockname()[1]);s.close()")
  PGNAME="sigil-gate-pg-$$"
  if docker run -d --rm --name "$PGNAME" -e POSTGRES_PASSWORD=pg -p "$PGPORT":5432 postgres:16 >/dev/null 2>&1; then
    for _ in $(seq 1 40); do docker exec "$PGNAME" pg_isready -U postgres >/dev/null 2>&1 && break; sleep 0.5; done
    export SIGILD_TEST_POSTGRES="postgres://postgres:pg@127.0.0.1:$PGPORT/postgres"
    trap 'docker rm -f "$PGNAME" >/dev/null 2>&1' EXIT
    ok "started a throwaway postgres:16 for the gated suite"
  fi
fi
o=$($GO -C sigild test -race -count=1 ./... -v 2>&1)
p=$(printf '%s' "$o" | grep -cE '^(    )*--- PASS'); f=$(printf '%s' "$o" | grep -cE '^(    )*--- FAIL')
sk=$(printf '%s' "$o" | grep -cE '^(    )*--- SKIP')
[ "$f" -eq 0 ] && ok "go -race: $p pass, 0 fail, $sk skip" || bad "go -race: $f FAILED"
if [ -n "${SIGILD_TEST_POSTGRES:-}" ]; then
  [ "$sk" -eq 0 ] && ok "Postgres-gated suite RAN (0 skips)" || bad "$sk tests SKIPPED even with a DSN set"
else
  bad "NO SIGILD_TEST_POSTGRES and no usable docker: $sk tests skipped — migrations, the account store and the seat cap were NOT exercised"
fi

note "=== RUST (every crate, discovered) ==="
for m in libsigil cli sigil-wasm desktop; do
  cargo fmt --manifest-path $m/Cargo.toml --all -- --check >/dev/null 2>&1 && ok "$m fmt" || bad "$m fmt"
  cargo clippy --manifest-path $m/Cargo.toml --all-targets -- -D warnings >/dev/null 2>&1 && ok "$m clippy" || bad "$m clippy"
  t=$(cargo test --manifest-path $m/Cargo.toml 2>&1 | grep -E 'test result:' )
  printf '%s' "$t" | grep -q FAILED && bad "$m tests" || ok "$m tests ($(printf '%s' "$t" | grep -oE '[0-9]+ passed' | awk -F' ' '{s+=$1} END {print s}') passed)"
done

note "=== WASM + NODE INTEROP (dynamically enumerated) ==="
./sigil-wasm/build-wasm.sh >/dev/null 2>&1 && ok "build-wasm" || bad "build-wasm"
cargo build --manifest-path cli/Cargo.toml --bin sigil >/dev/null 2>&1
# Helpers are NOT tests. fake-sigild.mjs is a server double and would hang here.
for t in sigil-wasm/test/*.mjs; do
  case "$(basename "$t")" in fake-*|*-helper.mjs) continue;; esac
  if node "$t" >/dev/null 2>&1; then ok "$(basename "$t")"; else bad "$(basename "$t")"; fi
done

note "=== BROWSER CLIENTS (rebuild FIRST — the local gate lies otherwise) ==="
corepack pnpm --filter @sigil/wasm build >/dev/null 2>&1
corepack pnpm --filter webapp build >/dev/null 2>&1 && ok "webapp build" || bad "webapp build"
r=$(corepack pnpm --filter webapp exec playwright test 2>&1 | tail -3)
printf '%s' "$r" | grep -q "failed" && bad "webapp playwright: $r" || ok "webapp playwright: $(printf '%s' "$r" | grep -oE '[0-9]+ passed')"
./extension/build.sh >/dev/null 2>&1 && ok "extension vendor" || bad "extension build.sh"
# `pnpm test` (not `exec playwright test`) — only it runs the pretest vendor hook.
r=$(cd extension && corepack pnpm test 2>&1 | tail -3)
printf '%s' "$r" | grep -q "failed" && bad "extension: $r" || ok "extension: $(printf '%s' "$r" | grep -oE '[0-9]+ passed')"
corepack pnpm -C web build >/dev/null 2>&1 && ok "marketing build" || bad "marketing build"

if [ "$QUICK" != "--quick" ]; then
  note "=== SHELL E2E (dynamically enumerated) ==="
  for s in cli/tests/*.sh; do
    if ./"$s" >/dev/null 2>&1; then ok "$(basename "$s")"; else bad "$(basename "$s")"; fi
  done
fi


note "=== CI DRIFT (does a workflow actually RUN every suite on disk?) ==="
# This repo has THREE TIMES shipped a suite that no workflow ran: the nine node
# interop tests for ~20 phases, then accounts+recovery, then entitlement. The
# tests were green locally every time. Detect the drift instead of rediscovering it.
missing=0
for t in sigil-wasm/test/*.mjs; do
  b=$(basename "$t")
  case "$b" in fake-*|*-helper.mjs) continue;; esac
  grep -qF "$b" .github/workflows/*.yml || { bad "no workflow runs $b"; missing=1; }
done
for s in cli/tests/*.sh; do
  b=$(basename "$s")
  grep -qF "$b" .github/workflows/*.yml || { bad "no workflow runs $b"; missing=1; }
done
[ "$missing" -eq 0 ] && ok "every node interop suite and shell e2e script is named in a workflow"

note "=== INVENTORY (a suite missing from this list is a suite nobody runs) ==="
printf '  rust crates:      %s\n' "$(ls -d libsigil cli sigil-wasm desktop | tr '\n' ' ')"
printf '  go test pkgs:     %s\n' "$(find sigild -name '*_test.go' | sed 's|/[^/]*_test.go||' | sort -u | wc -l | tr -d ' ')"
# Must use the SAME exclusion as the runner loop and the drift check, or the one
# number whose job is to make a MISSING suite visible is itself wrong.
printf '  node interop:     %s\n' "$(ls sigil-wasm/test/*.mjs | grep -vE '/(fake-|[^/]*-helper\.mjs)' | grep -c .)"
printf '  shell e2e:        %s\n' "$(ls cli/tests/*.sh | wc -l | tr -d ' ')"
printf '  playwright specs: %s\n' "$(find web extension -name '*.spec.ts' -o -name '*.spec.mjs' | grep -vc node_modules)"

[ "$fail" -eq 0 ] && note "
GATE: ALL GREEN" || note "
GATE: FAILURES ABOVE"
exit $fail
