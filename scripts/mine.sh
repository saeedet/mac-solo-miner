#!/usr/bin/env bash
#
# mine.sh — run the whole stack: node check, pool, miner.
#
# Usage:
#   ./scripts/mine.sh [network] [--threads N|half|max] [--address ADDR]
#
# `network` defaults to mainnet.
#
# The payout address is read, in order of preference, from:
#   1. --address
#   2. $SOLO_PAYOUT_ADDRESS
#   3. ~/.solo-mac-miner/payout.<network>
#
# The file is the convenient option: an address in a shell command ends up in
# your history, and one committed to a public repo permanently links your
# identity to every block that address ever receives.
#
# Ctrl-C stops the miner and the pool together. Nothing is lost by stopping:
# mining is memoryless, so an hour today and an hour next month are worth
# exactly what two hours now would be.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

NETWORK="mainnet"
THREADS=""
ADDRESS="${SOLO_PAYOUT_ADDRESS:-}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --threads) THREADS="$2"; shift 2 ;;
    --address) ADDRESS="$2"; shift 2 ;;
    --help|-h) sed -n '3,22p' "${BASH_SOURCE[0]}"; exit 0 ;;
    --*)       echo "unknown option $1" >&2; exit 1 ;;
    *)         NETWORK="$1"; shift ;;
  esac
done

die() { echo "error: $*" >&2; exit 1; }

# --- The payout address --------------------------------------------------
ADDRESS_FILE="$HOME/.solo-mac-miner/payout.$NETWORK"
if [[ -z "$ADDRESS" && -f "$ADDRESS_FILE" ]]; then
  ADDRESS="$(tr -d '[:space:]' < "$ADDRESS_FILE")"
  echo "payout address from $ADDRESS_FILE"
fi
[[ -n "$ADDRESS" ]] || die "no payout address. Pass --address, set SOLO_PAYOUT_ADDRESS, or write one to $ADDRESS_FILE"

# --- Refuse to mine on a node that is not ready --------------------------
#
# Mining on a stale tip is not merely wasteful, it is certain to be wasted:
# the block would build on a parent the network has already moved past, and
# every hash spent on it is spent on something that cannot be accepted.
echo "checking the $NETWORK node..."
STATUS="$(./scripts/node.sh cli "$NETWORK" getblockchaininfo 2>&1)" \
  || die "no $NETWORK node responding. Start one with: ./scripts/node.sh start $NETWORK"

python3 - "$STATUS" <<'PY' || exit 1
import json, sys
info = json.loads(sys.argv[1])
behind = info["headers"] - info["blocks"]
if info["initialblockdownload"] or behind > 0:
    print(f"error: node is still syncing — {info['blocks']:,} of {info['headers']:,} "
          f"({behind:,} behind). Mining now would build on a stale tip.", file=sys.stderr)
    sys.exit(1)
print(f"node ready: {info['chain']} at height {info['blocks']:,}")
PY

# --- Run -----------------------------------------------------------------
POOL_LOG="$(mktemp -t solo-pool)"
cleanup() {
  echo
  echo "stopping..."
  [[ -n "${POOL_PID:-}" ]] && kill "$POOL_PID" 2>/dev/null
  wait "${POOL_PID:-}" 2>/dev/null
  echo "pool log kept at $POOL_LOG"
}
trap cleanup EXIT INT TERM

./target/release/solo-pool --network "$NETWORK" --address "$ADDRESS" > "$POOL_LOG" 2>&1 &
POOL_PID=$!

# Give the pool time to validate the address and bind, then make sure it is
# actually alive before pointing a miner at it.
sleep 3
kill -0 "$POOL_PID" 2>/dev/null || { echo "pool failed to start:"; cat "$POOL_LOG"; exit 1; }
sed -n '1,6p' "$POOL_LOG"

# Blocks found are announced by the pool, so surface its output alongside the
# miner's rather than burying it in a file.
tail -f "$POOL_LOG" | grep --line-buffered -E "BLOCK FOUND|accepted|REJECTED|new tip" &

MINER_ARGS=(--pool 127.0.0.1:3333 --worker "mac.$NETWORK")
[[ -n "$THREADS" ]] && MINER_ARGS+=(--threads "$THREADS")

exec ./target/release/mac-miner "${MINER_ARGS[@]}"
