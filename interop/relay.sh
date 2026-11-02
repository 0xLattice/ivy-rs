#!/bin/bash
# Real TCP triangles: each runtime is tested as endpoint and as carrier.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q --example relay_node -p ivy
swift build --package-path interop --product relay-node >/dev/null
rust=target/debug/examples/relay_node
swift=interop/.build/debug/relay-node
port=${IVY_RELAY_INTEROP_PORT:-48600}
logs=$(mktemp -d)
pids=()
cleanup(){ for pid in "${pids[@]:-}"; do [[ -n "$pid" ]] || continue; kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done; rm -rf "$logs"; }
trap cleanup EXIT
ready(){
  local log=$1
  for _ in $(seq 1 100); do if grep -q '^READY$' "$log"; then return; fi; sleep 0.1; done
  cat "$log" >&2; return 1
}
triangle(){
  local carrier=$1 target=$2 dial=$3 label=$4
  port=$((port+3))
  "$carrier" carrier 1 "$port" >"$logs/carrier" 2>&1 & pids+=("$!")
  ready "$logs/carrier"
  "$target" serve 2 "$((port+1))" "$port" >"$logs/target" 2>&1 & pids+=("$!")
  ready "$logs/target"
  echo "== $label"
  if ! "$dial" dial 3 "$((port+2))" "$port" >"$logs/dial" 2>&1; then cat "$logs/carrier" "$logs/target" "$logs/dial"; return 1; fi
  cat "$logs/dial"
  grep -q '^PASS$' "$logs/dial"
  for pid in "${pids[@]:-}"; do [[ -n "$pid" ]] || continue; kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; done
  pids=()
}
triangle "$rust" "$swift" "$rust" 'Rust carrier, Swift target, Rust initiator'
triangle "$swift" "$rust" "$swift" 'Swift carrier, Rust target, Swift initiator'
triangle "$rust" "$rust" "$swift" 'Rust carrier and target, Swift initiator'
triangle "$swift" "$swift" "$rust" 'Swift carrier and target, Rust initiator'
echo 'relay interop: all triangles passed'
