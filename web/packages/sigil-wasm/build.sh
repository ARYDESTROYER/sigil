#!/usr/bin/env bash
# build.sh — generate BUNDLER-target wasm bindings for this workspace package
# from the repo-root `sigil-wasm` Rust crate, in a shape Next.js 15's webpack can
# parse.
#
# WHY NOT PLAIN `wasm-pack build --target bundler`?
#   rustc 1.85+ force-enables the `reference-types` + `multivalue` wasm target
#   features for wasm32-unknown-unknown (a `-Ctarget-feature=-…` override is
#   ignored). wasm-bindgen then sees those in the module's `target_features`
#   custom section and emits `externref` in the function type section. Next.js's
#   bundled webpack uses an OLD `@webassemblyjs` parser (for
#   `experiments.asyncWebAssembly`) that cannot decode `externref` and dies with
#   `parseVec could not cast the value`. wasm-pack gives no way to turn this off.
#
# WHAT WE DO INSTEAD — the same three steps wasm-pack runs, but with a strip in
# the middle:
#   1. cargo build the crate to raw wasm (unchanged Rust; behavior identical);
#   2. delete the `target_features` custom section from that raw module — with no
#      such hint, wasm-bindgen stays in the MVP subset (no externref, no
#      multi-value returns) that webpack CAN parse;
#   3. run wasm-bindgen `--target bundler` on the stripped module -> ./pkg.
#
# Output lands in ./pkg (a BUILD ARTIFACT, gitignored; never committed). This
# does NOT run on install — only on an explicit build.
#
# Pre-audit / UNAUDITED demo of the wasm-pure sigil-core. Do NOT protect real
# secrets. See README.md.
set -euo pipefail

# Put common Rust toolchain locations on PATH, OS-agnostically. On this macOS
# arm64 box cargo lives under the rustup toolchain dir (no ~/.cargo/bin proxies);
# on Linux CI cargo + a `cargo install`-ed wasm-bindgen-cli live in ~/.cargo/bin.
# Only existing dirs are prepended, so a missing path on either OS is harmless.
for _d in \
  "$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin" \
  "$HOME/.cargo/bin" \
  "/opt/homebrew/bin"; do
  [ -d "$_d" ] && case ":$PATH:" in *":$_d:"*) ;; *) PATH="$_d:$PATH" ;; esac
done
export PATH

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CRATE="$(cd "$HERE/../../../sigil-wasm" && pwd)"
OUT="$HERE/pkg"
RAW="$CRATE/target/wasm32-unknown-unknown/release/sigil_wasm.wasm"

# --- locate the wasm-bindgen CLI (version-matched to Cargo.toml's =0.2.100) ----
# Prefer one on PATH; else the copy wasm-pack cached. If neither exists, bootstrap
# the cache by running wasm-pack once (it downloads the pinned wasm-bindgen).
find_bindgen() {
  if command -v wasm-bindgen >/dev/null 2>&1; then command -v wasm-bindgen; return 0; fi
  # Fall back to a wasm-pack-managed copy — macOS ($HOME/Library/Caches) or
  # Linux ($HOME/.cache) cache locations.
  local c
  c="$(ls -1 \
        "$HOME/Library/Caches/.wasm-pack"/wasm-bindgen-cargo-install-*/wasm-bindgen \
        "$HOME/.cache/.wasm-pack"/wasm-bindgen-cargo-install-*/wasm-bindgen \
        2>/dev/null | sort | tail -1 || true)"
  if [ -n "$c" ] && [ -x "$c" ]; then echo "$c"; return 0; fi
  return 1
}

if ! WASM_BINDGEN="$(find_bindgen)"; then
  echo "== wasm-bindgen not found; bootstrapping via wasm-pack (downloads it) =="
  command -v wasm-pack >/dev/null 2>&1 || { echo "error: neither wasm-bindgen nor wasm-pack found on PATH" >&2; exit 1; }
  wasm-pack build "$CRATE" --release --target bundler --out-dir "$(mktemp -d)" >/dev/null 2>&1 || true
  WASM_BINDGEN="$(find_bindgen)" || { echo "error: could not obtain wasm-bindgen" >&2; exit 1; }
fi

echo "== wasm-bindgen: $WASM_BINDGEN ($("$WASM_BINDGEN" --version)) =="

# --- 1. cargo build -> raw wasm --------------------------------------------------
echo "== [1/3] cargo build (release, wasm32-unknown-unknown) =="
( cd "$CRATE" && cargo build --release --target wasm32-unknown-unknown -p sigil-wasm )

# --- 2. strip the target_features custom section ---------------------------------
echo "== [2/3] strip target_features custom section (externref-free for webpack) =="
STRIPPED="$(mktemp -t sigil_wasm_stripped.XXXXXX).wasm"
python3 - "$RAW" "$STRIPPED" <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
def leb(d, i):
    r = s = 0
    while True:
        b = d[i]; i += 1; r |= (b & 0x7f) << s
        if not b & 0x80: break
        s += 7
    return r, i
out = bytearray(data[:8])  # magic + version
i = 8
while i < len(data):
    start = i
    sid = data[i]; i += 1
    size, i = leb(data, i)
    body = data[i:i+size]; i += size
    drop = False
    if sid == 0:  # custom section: read its name
        nlen, j = leb(body, 0)
        if body[j:j+nlen].decode("latin1") == "target_features":
            drop = True
    if not drop:
        out += data[start:i]
open(sys.argv[2], "wb").write(out)
PY

# --- 3. wasm-bindgen --target bundler -> ./pkg -----------------------------------
echo "== [3/3] wasm-bindgen --target bundler -> $OUT =="
rm -rf "$OUT"
"$WASM_BINDGEN" --target bundler --out-dir "$OUT" --out-name sigil_wasm "$STRIPPED"
rm -f "$STRIPPED"

# Keep pkg self-ignoring so it never gets committed even if the parent rule moves.
printf '*\n' > "$OUT/.gitignore"

echo "Done. Generated $OUT (gitignored)."
