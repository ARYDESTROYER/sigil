#!/usr/bin/env bash
# build-wasm.sh — build the sigil-wasm browser + Node artifacts from the one
# crate, using wasm-pack (which bundles a matching wasm-bindgen, avoiding
# version-mismatch pain).
#
# Outputs (BUILD ARTIFACTS — gitignored, do NOT commit):
#   pkg-web/   ESM package for the browser demo   (wasm-pack --target web)
#   pkg-node/  CommonJS package for the Node test  (wasm-pack --target nodejs)
#
# Pre-audit / UNAUDITED demo of the wasm-pure sigil-core. Do not protect real
# secrets. See README.md.
set -euo pipefail

# Pin the toolchain path exactly like the rest of the repo (macOS arm64).
# `~/.cargo/bin` is where `cargo install wasm-pack` drops the binary.
export PATH="$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$HOME/.cargo/bin:/opt/homebrew/bin:$PATH"

# Pinned for reproducibility. wasm-pack bundles its own wasm-bindgen CLI that
# matches the `wasm-bindgen = "=0.2.100"` pin in Cargo.toml.
WASM_PACK_VERSION="0.13.1"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

if ! command -v wasm-pack >/dev/null 2>&1; then
  echo "wasm-pack not found; installing v${WASM_PACK_VERSION} via cargo install ..."
  cargo install wasm-pack --version "${WASM_PACK_VERSION}" --locked
fi

echo "== wasm-pack version =="
wasm-pack --version

echo "== building pkg-web (browser, ESM) =="
wasm-pack build --release --target web --out-dir pkg-web

echo "== building pkg-node (Node, CommonJS) =="
wasm-pack build --release --target nodejs --out-dir pkg-node

echo
echo "Build complete."
echo "  Browser ESM package: $HERE/pkg-web"
echo "  Node package:        $HERE/pkg-node"
echo
echo "Run the automated Node round-trip test with:"
echo "  node \"$HERE/test/roundtrip.mjs\""
echo
echo "Serve the browser demo (from this dir) with any static server, e.g.:"
echo "  python3 -m http.server 8000   # then open http://localhost:8000/demo/"
