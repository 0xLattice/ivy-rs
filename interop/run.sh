#!/bin/bash
# Runs this port and Swift Ivy (interop/Package.swift pins the release)
# against each other over real TCP, each side listening and each dialing,
# and checks that dialing for the wrong key fails in the handshake. Also
# compares key work bits with Tally's for 256 keys. Exits nonzero on the
# first unexpected result.
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q --example interop -p ivy
# Not -q: that hides the compiler errors too.
(cd interop && swift build 2>&1 | { grep -vE '^\[[0-9]+/[0-9]+\] ' || true; })
rust=target/debug/examples/interop
swift=interop/.build/debug/node
port=${IVY_INTEROP_PORT:-47500}

# Captured first: a failure inside <(...) would escape set -e.
rust_bits=$("$rust" keybits)
swift_bits=$("$swift" keybits)
if [[ $(wc -l <<<"$rust_bits") -ne 256 || $rust_bits != "$swift_bits" ]]; then
  echo "interop: key work bits differ from Tally's" >&2
  exit 1
fi
echo "== key work bits match Tally for 256 keys"

# pair <listener> <dialer> <name> <dialed key byte> <want: pass|fail>
pair() {
  local listener=$1 dialer=$2 name=$3 dialed=$4 want=$5
  port=$((port + 1))
  local log out status=0
  log=$(mktemp)
  out=$(mktemp)
  "$listener" listen 1 "$port" >"$log" 2>&1 &
  local pid=$!
  for _ in $(seq 1 100); do
    grep -q listening "$log" && break
    sleep 0.1
  done
  if ! grep -q listening "$log"; then
    echo "interop: $name: listener never started" >&2
    cat "$log" >&2
    exit 1
  fi
  echo "== $name"
  "$dialer" dial 2 "$port" "$dialed" >"$out" 2>&1 || status=$?
  cat "$out"
  sleep 0.5
  kill "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  if [[ $want == pass ]]; then
    [[ $status -eq 0 ]] && grep -q '^PASS$' "$out" || {
      echo "interop: $name: dialer exited $status" >&2
      exit 1
    }
  else
    # The dialer reached the listener and the handshake, not the
    # connection, is what failed.
    [[ $status -ne 0 ]] && grep -q '^FAIL session' "$out" || {
      echo "interop: $name: want a handshake failure, dialer exited $status" >&2
      exit 1
    }
    if [[ $listener == "$rust" ]] && ! grep -q '^REFUSED' "$log"; then
      echo "interop: $name: the Rust listener did not refuse the hello" >&2
      cat "$log" >&2
      exit 1
    fi
  fi
  rm -f "$log" "$out"
}

pair "$swift" "$rust" "Swift listens, Rust dials" 1 pass
pair "$rust" "$swift" "Rust listens, Swift dials" 1 pass
pair "$rust" "$rust" "Rust listens, Rust dials" 1 pass
pair "$swift" "$rust" "Rust dials Swift for the wrong key" 3 fail
pair "$rust" "$swift" "Swift dials Rust for the wrong key" 3 fail
pair "$rust" "$rust" "Rust dials Rust for the wrong key" 3 fail
echo "interop: all pairings passed"
