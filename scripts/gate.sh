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
# ⚠️ `$HOME/.cargo/bin` is APPENDED, not prepended: cargo-installed helper
# binaries (cargo-audit) live there, but the rustup toolchain bin must keep
# winning for `cargo`/`rustc` itself. Leaving it off entirely made the new
# cargo-audit check report "not installed" on a machine where it was.
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:/opt/homebrew/bin:$PATH:$HOME/.cargo/bin"
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

note "=== SECURITY SCANNERS (all three of security.yml, plus the working tree) ==="
# ⚠️ WHY THIS BLOCK EXISTS, and it is the same lesson as everything else here.
# On 2026-07-30 the `security` workflow was RED on two jobs — govulncheck and
# cargo-audit(desktop) — while this gate reported ALL GREEN on the very commit
# that broke them. It did not disagree with CI; it never asked the question.
# A gate whose coverage is a strict subset of CI's cannot tell you CI will pass,
# which is the one thing a pre-push gate exists to tell you.

# --- govulncheck ------------------------------------------------------------
# It must scan the toolchain we SHIP (go.mod says `go 1.25.0`; the Dockerfile
# builds `FROM golang:1.25-alpine`; CI pins setup-go `1.25.x`) — NOT whatever
# the dev machine happens to have. Those differ here: this machine's Go is
# 1.26.3, which carries three stdlib advisories the shipped 1.25 line does not.
# Scanning the dev toolchain would report vulnerabilities that are not in the
# artifact, and a scanner that cries wolf gets muted — which is precisely how
# the always-red cargo-audit job stopped being read.
SCANGO=""
if [ -n "${SIGIL_SCAN_GO:-}" ] && [ -x "${SIGIL_SCAN_GO}" ]; then
  SCANGO="$SIGIL_SCAN_GO"
else
  # Newest locally-installed go1.25.x from `golang.org/dl` (version-sorted).
  for c in $(ls "$HOME"/go/bin/go1.25.* 2>/dev/null | sort -V -r); do
    [ -x "$c" ] && SCANGO="$c" && break
  done
fi
if [ -z "$SCANGO" ]; then
  bad "no go1.25.x toolchain to scan with — govulncheck NOT RUN.
      Install the line we actually ship, then re-run:
        $GO install golang.org/dl/go1.25.12@latest && \$HOME/go/bin/go1.25.12 download
      (or set SIGIL_SCAN_GO=/path/to/go). Scanning with the dev toolchain
      instead would report stdlib findings that are not in the shipped binary.)"
else
  gv=$(cd sigild 2>/dev/null && GOTOOLCHAIN=local "$SCANGO" run golang.org/x/vuln/cmd/govulncheck@latest ./... 2>&1)
  if [ -z "$gv" ]; then
    # The scanner produced NOTHING. That is never a pass — it means the `cd`
    # failed or govulncheck could not start, and reporting a vulnerability count
    # from an empty string would be a green-shaped signal for a check that did
    # not run. (Observed while testing this block: a failed `cd` printed
    # "0 vulnerability(ies)".)
    bad "govulncheck produced NO OUTPUT — it did not run. Check that sigild/ exists and \"$SCANGO\" works."
  elif printf '%s' "$gv" | grep -q 'No vulnerabilities found'; then
    ok "govulncheck clean ($("$SCANGO" version | awk '{print $3}'), the shipped line)"
  else
    n=$(printf '%s' "$gv" | grep -c '^Vulnerability #')
    if [ "$n" -gt 0 ]; then
      bad "govulncheck ($("$SCANGO" version | awk '{print $3}')): $n vulnerability(ies)
$(printf '%s' "$gv" | grep -E '^Vulnerability #|^    Found in:|^    Fixed in:' | sed 's/^/      /')"
    else
      # ⚠️ OUTPUT THAT IS NEITHER "clean" NOR A FINDING MEANS THE SCAN DID NOT
      # COMPLETE — a module download failure, a proxy timeout, a toolchain
      # hiccup. The first version reported this as
      #     ✗ govulncheck (go1.25.12): 0 vulnerability(ies)
      # which reads like a contradiction and cost a verifier a debug cycle: zero
      # findings presented as a failure. Same family as the cargo-audit flake
      # that printed an EMPTY reason. Say which it is.
      bad "govulncheck COULD NOT COMPLETE — this is NOT a finding, the scan failed to run:
$(printf '%s' "$gv" | tail -5 | sed 's/^/      /')"
    fi
  fi
fi

# --- gitleaks ---------------------------------------------------------------
# ⚠️ ADDED AFTER THE SECOND MISS. The first version of this block ran govulncheck
# and cargo-audit — TWO of `security.yml`'s THREE jobs — and the very next push
# went red on the third. Closing "the gate is a subset of CI" by adding *some* of
# the missing checks is not closing it. Run the whole workflow's worth.
#
# Uses the same Docker image concept as CI's action, so no host install is
# required; skipping when Docker is unavailable would recreate the exact blind
# spot this block exists to remove, so it FAILS instead.
if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  bad "docker unavailable — gitleaks did NOT run. This is the third CI check;
      a gate missing it is a gate that can be green while \`security\` is red."
else
  glimg=zricethezav/gitleaks:latest
  # (a) HISTORY — byte-for-byte what CI scans.
  gl=$(docker run --rm -v "$PWD:/repo:ro" -w /repo "$glimg" \
         detect --source=/repo --config=/repo/.gitleaks.toml --no-banner --redact 2>&1)
  if printf '%s' "$gl" | grep -q 'no leaks found'; then
    ok "gitleaks clean (full history)"
  else
    bad "gitleaks (history): $(printf '%s' "$gl" | grep -oE 'leaks found: [0-9]+' | tail -1)
$(printf '%s' "$gl" | grep -E '^(File|Line|RuleID):' | head -12 | sed 's/^/      /')"
  fi

  # (b) ⭐ WHAT IS ABOUT TO BE COMMITTED — which the history scan CANNOT see.
  # Verified: an uncommitted file holding a random 40-char credential beside
  # `api_secret_key` is reported as "no leaks found" by the history scan. A
  # pre-push gate that only inspects what is already committed cannot stop you
  # committing a secret; it can only tell you afterwards.
  #
  # `--no-git` over the repo root is the wrong tool — it walked node_modules and
  # build output and reported 39 findings here. So scan exactly the set git would
  # take: tracked + untracked-but-not-ignored, copied into a scratch tree.
  glsrc=$(mktemp -d)
  git ls-files -co --exclude-standard -z | while IFS= read -r -d '' f; do
    [ -f "$f" ] || continue
    mkdir -p "$glsrc/$(dirname "$f")" && cp "$f" "$glsrc/$f"
  done
  cp .gitleaks.toml .gitleaksignore "$glsrc/" 2>/dev/null
  gw=$(docker run --rm -v "$glsrc:/scan:ro" -w /scan "$glimg" \
         detect --source=. --config=.gitleaks.toml --no-git --no-banner --redact 2>&1)
  rm -rf "$glsrc"
  if printf '%s' "$gw" | grep -q 'no leaks found'; then
    ok "gitleaks clean (working tree — everything git would commit)"
  else
    bad "gitleaks (working tree): $(printf '%s' "$gw" | grep -oE 'leaks found: [0-9]+' | tail -1)
$(printf '%s' "$gw" | grep -E '^(File|Line|RuleID):' | head -12 | sed 's/^/      /')"
  fi
fi

# --- cargo audit ------------------------------------------------------------
# `--deny warnings` across EVERY lockfile. Vulnerabilities fail, and so does any
# unmaintained/unsound advisory that is not written down in that workspace's
# .cargo/audit.toml with a reason and a removal condition. Only desktop/ has
# such a file; the other three must stay warning-free outright.
if ! command -v cargo-audit >/dev/null 2>&1; then
  bad "cargo-audit not installed — the Rust advisory scan did NOT run.
      Install it (this is the same check CI runs on all four lockfiles):
        cargo install cargo-audit --locked"
else
  # ⚠️ RUN THE SCAN ONCE, AND TELL "found something" APART FROM "could not run".
  # The first version of this loop ran `cargo audit` a SECOND time just to build
  # the failure message, doubling the number of advisory-database fetches and so
  # doubling the chance of a transient. Worse, its message grepped only for
  # `^(Crate|ID|Warning|Title|error):`, which a git fetch error does not match —
  # so a network blip printed `✗ cargo audit sigil-wasm:` with an EMPTY reason,
  # indistinguishable from a real advisory. Observed three times in one session;
  # a full gate needed three attempts to go green. A gate that intermittently
  # invents a security finding gets ignored exactly like the always-red
  # cargo-audit job this block was written to replace.
  for m in libsigil cli sigil-wasm desktop; do
    out=$(cd "$m" && cargo audit --deny warnings 2>&1)
    if [ $? -eq 0 ]; then
      ok "cargo audit $m (0 vulns, 0 unacknowledged warnings)"
    elif printf '%s' "$out" | grep -qE '^(Crate|ID):'; then
      # Real finding rows are present — this is a genuine result.
      bad "cargo audit $m:
$(printf '%s' "$out" | grep -E '^(Crate|ID|Warning|Title|error):' | sed 's/^/      /')"
    else
      # Non-zero with no finding rows means the scan never completed. Retry once
      # against the CACHED database (-n skips the git fetch, the flaky part).
      out=$(cd "$m" && cargo audit --deny warnings -n 2>&1)
      if [ $? -eq 0 ]; then
        ok "cargo audit $m (cached advisory DB — the fetch failed, the scan did not)"
      else
        bad "cargo audit $m COULD NOT RUN — this is not a finding, the scan failed to complete:
$(printf '%s' "$out" | tail -4 | sed 's/^/      /')"
      fi
    fi
  done
fi

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
# ⚠️ SKIPS COUNT AS FAILURES HERE, for the same reason they do in the Go block
# above: a spec that quietly stops running looks exactly like a spec that passes.
# Playwright prints "N skipped"/"N did not run" only when there ARE any, so this
# is silent on a healthy run. (`retries: 0` in playwright.config.ts means there is
# no "flaky" line to worry about — a suite that needs a second attempt is a suite
# whose failures get ignored.)
pw() { # $1 = label, $2 = captured tail of the playwright run
  if printf '%s' "$2" | grep -qE "failed|did not run"; then bad "$1: $2"
  elif printf '%s' "$2" | grep -q "skipped"; then bad "$1 SKIPPED tests: $2"
  else
    # ⚠️ REQUIRE A PARSEABLE COUNT. This used to print `ok` with whatever
    # `grep -oE '[0-9]+ passed'` returned — including NOTHING, when the summary
    # line fell outside the captured tail. That rendered as
    # `✓ webapp playwright: ` / `undefined`: a PASS reported with no measurement
    # behind it, which is the exact failure this whole script exists to catch.
    # If the result cannot be read, that is a failure to measure, not a success.
    n=$(printf '%s' "$2" | grep -oE '[0-9]+ passed' | tail -1)
    if [ -n "$n" ]; then ok "$1: $n"
    else bad "$1: could NOT read a pass count from the output — the run may not have
      completed. Not treating an unreadable result as a pass. Tail was:
$(printf '%s' "$2" | tail -6 | sed 's/^/      /')"; fi
  fi
}
r=$(corepack pnpm --filter webapp exec playwright test 2>&1 | tail -15)
pw "webapp playwright" "$r"
./extension/build.sh >/dev/null 2>&1 && ok "extension vendor" || bad "extension build.sh"
# `pnpm test` (not `exec playwright test`) — only it runs the pretest vendor hook.
r=$(cd extension && corepack pnpm test 2>&1 | tail -15)
pw "extension" "$r"
corepack pnpm -C web build >/dev/null 2>&1 && ok "marketing build" || bad "marketing build"

if [ "$QUICK" != "--quick" ]; then
  note "=== SHELL E2E (dynamically enumerated) ==="
  # `_*.sh` is a sourced library, not a suite — the shell twin of the node
  # `*-helper.mjs` rule. This exclusion is repeated in the drift check and the
  # inventory below and MUST stay identical in all three: an inventory that
  # counts differently from the runner is the one number whose job is to make a
  # missing suite visible, being wrong.
  for s in cli/tests/*.sh; do
    case "$(basename "$s")" in _*) continue;; esac
    ./"$s" >/dev/null 2>&1
    rc=$?
    case "$rc" in
      0) ok "$(basename "$s")" ;;
      # 137 = SIGKILL, 143 = SIGTERM. The script did not FAIL — it was KILLED, by
      # an OOM killer, a sandbox, or a CI step timeout, usually with no output
      # because stdout was still block-buffered. Reporting that as a test failure
      # sends the next person hunting a bug in code that is fine: it happened here
      # on 2026-07-30 and cost a real detour before `exit=0 in 21s` outside the
      # sandbox settled it. ⚠️ It still FAILS the gate — "could not be run" is not
      # "passed", and auto-retrying would just hide the flakiness.
      137|143) bad "$(basename "$s") was KILLED (signal $((rc-128))), not failed — no result.
      Nothing is proven either way. Usual causes: memory pressure, a sandbox, or a
      step timeout. Re-run it alone before believing it is broken." ;;
      *) bad "$(basename "$s") (exit $rc)" ;;
    esac
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
  case "$b" in _*) continue;; esac
  grep -qF "$b" .github/workflows/*.yml || { bad "no workflow runs $b"; missing=1; }
done
[ "$missing" -eq 0 ] && ok "every node interop suite and shell e2e script is named in a workflow"

# ⚠️ NAMING A SUITE IS NOT ENOUGH — THE WORKFLOW MUST ALSO BE TRIGGERED.
# Every workflow here has `paths:` filters, so a workflow can name a suite and
# still never run it for the change that breaks it. Found on 2026-07-30:
# `desktop.yml` and `web.yml` each boot a REAL sigild (server_interop.rs,
# cors.spec.ts) while neither triggered on `sigild/**`, so a server change that
# broke a client contract would have run neither suite.
trigger_ok=1
python3 - <<'PY' || trigger_ok=0
import glob, os, re, sys, yaml

def suite_files(wf_text):
    """Test entry points a workflow runs, resolved to files on disk."""
    out = set()
    for m in re.finditer(r'(sigil-wasm/test/[\w.-]+\.mjs|cli/tests/[\w.-]+\.sh)', wf_text):
        out.add(m.group(1))
    # `cargo test --manifest-path X/Cargo.toml` exercises every integration test
    # under that workspace, which is how desktop reaches server_interop.rs.
    for m in re.finditer(r'--manifest-path\s+(\S+)/Cargo\.toml', wf_text):
        out.update(glob.glob(os.path.join(m.group(1), '**', 'tests', '*.rs'), recursive=True))
    # A bare `cargo test` in a workflow that checks out one workspace dir.
    for m in re.finditer(r'working-directory:\s*(\S+)', wf_text):
        out.update(glob.glob(os.path.join(m.group(1), '**', 'tests', '*.rs'), recursive=True))
    # Playwright specs are named by their project dir, not individually.
    for m in re.finditer(r'--filter\s+(webapp|@sigil/\S+)', wf_text):
        out.update(glob.glob('web/apps/webapp/tests/*.ts'))
    if 'extension/build.sh' in wf_text or '-C extension' in wf_text:
        out.update(glob.glob('extension/tests/*.mjs'))
    # normpath: the same file can arrive as both "x/y.rs" and "./x/y.rs" from
    # different patterns, which would report every finding twice.
    return {os.path.normpath(f) for f in out if os.path.isfile(f)}

bad = 0
for wf in sorted(glob.glob('.github/workflows/*.yml')):
    text = open(wf).read()
    doc = yaml.safe_load(text)
    on = doc.get('on') or doc.get(True) or {}
    if not isinstance(on, dict):
        continue
    push = on.get('push')
    if not isinstance(push, dict) or 'paths' not in push:
        continue  # triggers on everything; nothing to check
    paths = set(push['paths'])
    for f in suite_files(text):
        # Which component does this suite actually need built?
        src = open(f, encoding='utf-8', errors='replace').read()
        if 'cmd/server' in src and 'sigild/**' not in paths:
            print(f"  ✗ {wf} runs {f}, which builds a real sigild, "
                  f"but does not trigger on sigild/**")
            bad = 1
sys.exit(bad)
PY
if [ "$trigger_ok" -eq 1 ]; then
  ok "every workflow that boots a real sigild triggers on sigild/**"
else
  bad "a workflow runs a real-sigild suite it is not triggered for (see above)"
fi

note "=== INVENTORY (a suite missing from this list is a suite nobody runs) ==="
printf '  rust crates:      %s\n' "$(ls -d libsigil cli sigil-wasm desktop | tr '\n' ' ')"
printf '  go test pkgs:     %s\n' "$(find sigild -name '*_test.go' | sed 's|/[^/]*_test.go||' | sort -u | wc -l | tr -d ' ')"
# Must use the SAME exclusion as the runner loop and the drift check, or the one
# number whose job is to make a MISSING suite visible is itself wrong.
printf '  node interop:     %s\n' "$(ls sigil-wasm/test/*.mjs | grep -vE '/(fake-|[^/]*-helper\.mjs)' | grep -c .)"
printf '  shell e2e:        %s\n' "$(ls cli/tests/*.sh | grep -vc '/_')"
printf '  playwright specs: %s\n' "$(find web extension -name '*.spec.ts' -o -name '*.spec.mjs' | grep -vc node_modules)"

[ "$fail" -eq 0 ] && note "
GATE: ALL GREEN" || note "
GATE: FAILURES ABOVE"
exit $fail
