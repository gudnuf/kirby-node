#!/usr/bin/env bash
# Kirby "nerve" slice-1 deterministic test (the spec "Done" steps 2-6): stand up a
# local nostr-rs-relay, run 3 presence-only nodes (distinct identities), and prove
#   - all 3 show ALIVE (3 distinct npubs), no central registry;
#   - kill one -> it goes STALE past the threshold, the other two stay ALIVE, and
#     the survivors' logs report the peer went STALE;
#   - restart the killed node -> it returns ALIVE with the SAME npub (identity
#     persisted on disk).
#
# This needs NO Firecracker/KVM: presence is host-side and VM-independent, so the
# nodes run with `run --presence-only`.
#
# Run it INSIDE the dev shell so cargo + the relay binary are available:
#   nix develop --command bash scripts/nerve-presence-test.sh
# (or from an already-entered `nix develop`: bash scripts/nerve-presence-test.sh)
#
# Tunables via env: INTERVAL (re-publish secs), STALE (stale threshold secs),
# PORT (relay port), KEEP (1 = keep the work dir on exit for inspection).
set -euo pipefail

INTERVAL="${INTERVAL:-3}"
STALE="${STALE:-8}"
PORT="${PORT:-7787}"
RELAY_URL="ws://127.0.0.1:${PORT}"
KEEP="${KEEP:-0}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d -t kirby-nerve-XXXXXX)"
RELAY_DATA="$WORK/relay-db"
mkdir -p "$RELAY_DATA"

# PIDs we start, torn down on exit.
RELAY_PID=""
declare -A NODE_PID=()

cleanup() {
  set +e
  for n in "${!NODE_PID[@]}"; do
    [ -n "${NODE_PID[$n]}" ] && kill "${NODE_PID[$n]}" 2>/dev/null
  done
  [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null
  wait 2>/dev/null
  if [ "$KEEP" = "1" ]; then
    echo "[test] work dir kept: $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# --- locate the relay binary -------------------------------------------------
# Prefer nostr-rs-relay on PATH (dev shell / nix profile); else build it from the
# flake. The relay accepts arbitrary kinds and has NIP-42 off (see nix/relay.nix).
RELAY_BIN="$(command -v nostr-rs-relay || true)"
if [ -z "$RELAY_BIN" ]; then
  echo "[test] nostr-rs-relay not on PATH; building it from the flake (nix build .#relay-bin)..."
  RELAY_OUT="$(nix build --no-link --print-out-paths "$ROOT#relay-bin")"
  RELAY_BIN="$RELAY_OUT/bin/nostr-rs-relay"
fi
echo "[test] relay binary: $RELAY_BIN"

# A minimal relay config: bind localhost:$PORT, SQLite in $RELAY_DATA, arbitrary
# kinds (no allowlist), NIP-42 off.
cat > "$WORK/relay.toml" <<EOF
[info]
name = "kirby-nerve-test-relay"

[database]
data_directory = "$RELAY_DATA"

[network]
address = "127.0.0.1"
port = $PORT

[authorization]
nip42_auth = false

[limits]
messages_per_sec = 0
EOF

# --- build the daemon --------------------------------------------------------
echo "[test] building kirby-node (cargo build -p kirby-node)..."
( cd "$ROOT" && cargo build -p kirby-node >/dev/null 2>"$WORK/build.log" ) \
  || { cat "$WORK/build.log" >&2; fail "cargo build failed"; }
BIN="$ROOT/target/debug/kirby-node"
[ -x "$BIN" ] || fail "daemon binary not found at $BIN"

# --- start the relay ---------------------------------------------------------
echo "[test] starting relay on $RELAY_URL ..."
RUST_LOG=warn "$RELAY_BIN" --config "$WORK/relay.toml" >"$WORK/relay.log" 2>&1 &
RELAY_PID=$!

# Wait for the relay TCP port to accept connections.
for i in $(seq 1 50); do
  if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then exec 3>&- 3<&-; break; fi
  kill -0 "$RELAY_PID" 2>/dev/null || { cat "$WORK/relay.log" >&2; fail "relay exited early"; }
  sleep 0.2
  [ "$i" = 50 ] && { cat "$WORK/relay.log" >&2; fail "relay did not open port $PORT"; }
done
echo "[test] relay is up."

# --- helpers: read the fleet JSON (machine artifact, parsed with jq) ---------
command -v jq >/dev/null || fail "jq is required (run inside nix develop)"

# Prints the JSON array from `kirby-node presence --json` (JSON only, no human
# lines), so jq can parse stdout directly.
fleet_json() {
  "$BIN" presence --relay-url "$RELAY_URL" --stale-after "$STALE" --timeout-secs 4 --json 2>/dev/null
}

# count nodes with a given alive value (true/false) in the fleet JSON
count_alive() {
  local want="$1"
  fleet_json | jq "[.[] | select(.alive == $want)] | length"
}

# the npub of a given node_id from the fleet JSON (empty if absent)
npub_of() {
  local node="$1"
  fleet_json | jq -r --arg n "$node" '.[] | select(.node_id == $n) | .npub' | head -1
}

# the number of DISTINCT npubs in the fleet
distinct_npubs() {
  fleet_json | jq '[.[].npub] | unique | length'
}

# is a given node_id present with alive==want (true/false)? exit 0 if so.
node_is() {
  local node="$1" want="$2"
  local got
  got="$(fleet_json | jq -r --arg n "$node" '.[] | select(.node_id == $n) | .alive' | head -1)"
  [ "$got" = "$want" ]
}

# --- start a presence-only node ----------------------------------------------
start_node() {
  local node="$1"
  local dir="$WORK/state-$node"
  mkdir -p "$dir"
  RUST_LOG=info "$BIN" run \
    --presence-only \
    --node-id "$node" \
    --treasury-path "$dir" \
    --relay-url "$RELAY_URL" \
    --presence-interval "$INTERVAL" \
    --presence-stale-after "$STALE" \
    >"$WORK/$node.log" 2>&1 &
  NODE_PID[$node]=$!
  echo "[test] started $node (pid ${NODE_PID[$node]}, state $dir)"
}

echo "[test] === Step: start 3 presence-only nodes ==="
start_node node-1
start_node node-2
start_node node-3

# Let them publish and discover (a couple of intervals).
sleep "$((INTERVAL * 2 + 2))"

echo "[test] === Step: assert 3 distinct npubs ALIVE ==="
echo "---- fleet ----"
"$BIN" presence --relay-url "$RELAY_URL" --stale-after "$STALE" --timeout-secs 4
echo "---------------"
ALIVE="$(count_alive true)"
[ "$ALIVE" = "3" ] || fail "expected 3 ALIVE, got $ALIVE"
DISTINCT="$(distinct_npubs)"
[ "$DISTINCT" = "3" ] || fail "expected 3 distinct npubs, got $DISTINCT"
echo "[test] OK: 3 distinct npubs ALIVE."

# Record node-1's npub for the persistence check.
NPUB1_BEFORE="$(npub_of node-1)"
[ -n "$NPUB1_BEFORE" ] || fail "could not read node-1 npub"
echo "[test] node-1 npub = $NPUB1_BEFORE"

echo "[test] === Step: kill node-1, expect STALE past threshold ==="
kill "${NODE_PID[node-1]}" 2>/dev/null
wait "${NODE_PID[node-1]}" 2>/dev/null || true
NODE_PID[node-1]=""
# Wait past the stale threshold (plus a sweep margin).
sleep "$((STALE + INTERVAL + 2))"

echo "---- fleet after kill ----"
"$BIN" presence --relay-url "$RELAY_URL" --stale-after "$STALE" --timeout-secs 4
echo "--------------------------"
# node-1 must be STALE (alive==false), the other two ALIVE.
node_is node-1 false || fail "node-1 should be STALE after kill"
node_is node-2 true  || fail "node-2 should still be ALIVE"
node_is node-3 true  || fail "node-3 should still be ALIVE"
echo "[test] OK: node-1 STALE, node-2 + node-3 ALIVE."

# The survivors' logs must report the peer went STALE.
sleep 1
grep -q "went STALE" "$WORK/node-2.log" || grep -q "went STALE" "$WORK/node-3.log" \
  || fail "no survivor logged the peer going STALE"
echo "[test] OK: a survivor logged 'went STALE'."

echo "[test] === Step: restart node-1, expect ALIVE with the SAME npub ==="
start_node node-1
sleep "$((INTERVAL * 2 + 2))"
echo "---- fleet after restart ----"
"$BIN" presence --relay-url "$RELAY_URL" --stale-after "$STALE" --timeout-secs 4
echo "-----------------------------"
node_is node-1 true || fail "node-1 should be ALIVE again after restart"
NPUB1_AFTER="$(npub_of node-1)"
[ "$NPUB1_AFTER" = "$NPUB1_BEFORE" ] \
  || fail "node-1 npub changed across restart: $NPUB1_BEFORE -> $NPUB1_AFTER (identity not persisted)"
echo "[test] OK: node-1 ALIVE with the SAME npub ($NPUB1_AFTER) -> identity persisted."

echo
echo "PASS: nerve slice-1 presence test (3 ALIVE -> kill -> STALE -> restart -> same npub)."
