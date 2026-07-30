set -u
echo "== copying the repo (excluding build artifacts) =="
mkdir -p /work
tar -C /src --exclude=./target --exclude='*/target' --exclude=node_modules \
    --exclude=.git --exclude=.next --exclude=pkg-web --exclude=vendor \
    -cf - . 2>/dev/null | tar -C /work -xf -
cd /work
echo "repo at $(pwd), $(find . -type f | wc -l) files"

echo; echo "== building the real sigil CLI (Linux) =="
cargo build --manifest-path cli/Cargo.toml --bin sigil --quiet 2>&1 | tail -5
ls -l cli/target/debug/sigil && file cli/target/debug/sigil | cut -c1-80

pass=0; fail=0
run() { # $1 label, rest = command
  local label="$1"; shift
  if "$@" > "/tmp/$label.log" 2>&1; then echo "  ✓ $label"; pass=$((pass+1))
  else echo "  ✗ $label"; tail -12 "/tmp/$label.log" | sed 's/^/       /'; fail=$((fail+1)); fi
}

echo; echo "== SHELL E2E on Linux =="
for s in cli/tests/e2e-sharing.sh cli/tests/e2e-accounts.sh cli/tests/e2e-recovery.sh; do
  run "$(basename "$s" .sh)" bash "$s"
done

echo; echo "== NODE INTEROP on Linux (pkg-node copied from the macOS build; wasm is platform-independent) =="
if [ -f sigil-wasm/pkg-node/sigil_wasm.js ]; then
  for t in sync totp device-auth sharing pinning accounts recovery entitlement; do
    run "$t-interop" node "sigil-wasm/test/$t-interop.mjs"
  done
  run "portability-guard" node sigil-wasm/test/portability-guard.mjs
  run "seal-params-guard" node sigil-wasm/test/seal-params-guard.mjs
  run "schema-interop" node sigil-wasm/test/schema-interop.mjs
  run "passkey-uv-interop" node sigil-wasm/test/passkey-uv-interop.mjs
else
  echo "  !! pkg-node missing — node suites NOT RUN"
fi

echo; echo "== LINUX RESULT: $pass passed, $fail failed =="
exit $fail
