#!/bin/bash
# Runs this port and Swift Ivy (interop/Package.swift pins the release)
# against each other over real TCP, each side listening and each dialing,
# then checks that dialing for the wrong key fails. Exits nonzero on the
# first unexpected result.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q --example interop -p ivy
# Not -q: that hides the compiler errors too.
(cd interop && swift build 2>&1 | { grep -vE '^\[[0-9]+/[0-9]+\] ' || true; })
rust=target/debug/examples/interop
swift=interop/.build/debug/node
port=${IVY_INTEROP_PORT:-47500}

# pair <listener> <dialer> <name> <dialed key byte> <want: pass|fail>
pair() {
  local listener=$1 dialer=$2 name=$3 dialed=$4 want=$5
  port=$((port + 1))
  local log status=0
  log=$(mktemp)
  "$listener" listen 1 "$port" >"$log" 2>&1 &
  local pid=$!
  for _ in $(seq 1 100); do
    grep -q listening "$log" && break
    sleep 0.1
  done
  echo "== $name"
  "$dialer" dial 2 "$port" "$dialed" || status=$?
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  rm -f "$log"
  if [[ $want == pass && $status -ne 0 ]] || [[ $want == fail && $status -eq 0 ]]; then
    echo "interop: $name: want $want, dialer exited $status" >&2
    exit 1
  fi
}

pair "$swift" "$rust" "Swift listens, Rust dials" 1 pass
pair "$rust" "$swift" "Rust listens, Swift dials" 1 pass
pair "$rust" "$rust" "Rust listens, Rust dials" 1 pass
pair "$swift" "$rust" "Rust dials Swift for the wrong key" 3 fail
pair "$rust" "$swift" "Swift dials Rust for the wrong key" 3 fail
echo "interop: all pairings passed"
