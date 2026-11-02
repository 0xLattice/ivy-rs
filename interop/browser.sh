#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q -p ivy-wasm --target wasm32-unknown-unknown --release
npm --prefix interop/browser-oracle ci --ignore-scripts --no-audit --no-fund >/dev/null
npm --prefix interop/browser-oracle run build >/dev/null
node interop/browser-oracle/smoke.mjs
cargo build -q -p ivy-websocket --example browser_peer
node interop/browser-oracle/websocket.mjs
