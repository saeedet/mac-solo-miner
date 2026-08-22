#!/usr/bin/env bash
#
# sync-status.sh — how far along is the node?
#
# Usage:
#   ./scripts/sync-status.sh [network] [--watch]
#
# `network` defaults to mainnet. `--watch` refreshes every 30s.
#
# Getting a node to the tip has up to three phases, and only the first is
# chatty, so a quiet log does not mean it has finished:
#
#   1. reindex - read and index every blk*.dat        (prints per file)
#   2. connect - replay blocks, rebuild the UTXO set  (prints per block)
#   3. sync    - download the remaining blocks        (prints per block)
#
# Phases 2 and 3 look identical in the log; what separates them is whether the
# node still has local blocks to replay or is fetching them from peers.

set -uo pipefail

NETWORK="mainnet"
WATCH=false
for arg in "$@"; do
  case "$arg" in
    --watch) WATCH=true ;;
    --*)     ;;
    *)       NETWORK="$arg" ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATADIR="${SOLO_DATADIR:-$HOME/.bitcoin-solo}"
CONF="$REPO_ROOT/config/bitcoin.$NETWORK.conf"
CLI="$(command -v bitcoin-cli || echo /opt/homebrew/opt/bitcoin/bin/bitcoin-cli)"

report() {
  if ! pgrep -f "bitcoind.*$DATADIR" > /dev/null; then
    echo "bitcoind is NOT running"
    return 1
  fi

  local info
  if ! info="$("$CLI" -datadir="$DATADIR" -conf="$CONF" getblockchaininfo 2>/dev/null)"; then
    # Normal for a few minutes after start, while the block index loads.
    local files
    files=$(grep -c 'Reindexing block file' "$DATADIR/debug.log" 2>/dev/null || true)
    echo "RPC not up yet (phase 1: ${files:-0} / 5324 block files indexed)"
    return 0
  fi

  local peers
  peers="$("$CLI" -datadir="$DATADIR" -conf="$CONF" getconnectioncount 2>/dev/null || echo '?')"

  python3 - "$info" "$DATADIR/debug.log" "$peers" <<'PY'
import datetime, json, re, sys

info, log_path, peers = json.loads(sys.argv[1]), sys.argv[2], sys.argv[3]

behind = info["headers"] - info["blocks"]
progress = info["verificationprogress"]

# Bitcoin Core's own estimate, weighted by transaction count rather than block
# count. It is the honest percentage, but it saturates near the end: at 99.6%
# there can still be hours left, because recent blocks carry far more
# transactions than early ones. The blocks-behind figure is the useful one at
# the tail of a sync.
width = 40
filled = min(width, int(progress * width))
bar = "#" * filled + "-" * (width - filled)

print(f"network   : {info['chain']}")
print(f"progress  : [{bar}] {progress * 100:.4f}%")
print(f"height    : {info['blocks']:,} / {info['headers']:,}")
print(f"behind    : {behind:,} blocks")
print(f"syncing   : {info['initialblockdownload']}")
if info.get("pruned"):
    print(f"pruned    : yes, keeping from height {info.get('pruneheight', 0):,}")
print(f"disk      : {info['size_on_disk'] / 1e9:.1f} GB")
print(f"peers     : {peers}")
if info.get("warnings"):
    print(f"WARNINGS  : {info['warnings']}")

# Rate from the recent log only. A lifetime average is useless here: early
# blocks connect hundreds of times faster than recent ones.
try:
    lines = open(log_path, errors="ignore").read().splitlines()
except OSError:
    sys.exit(0)

tips = [line for line in lines if "UpdateTip" in line][-500:]
if len(tips) < 2:
    sys.exit(0)

def parse(line):
    return (datetime.datetime.strptime(line[:20], "%Y-%m-%dT%H:%M:%SZ"),
            int(re.search(r"height=(\d+)", line).group(1)))

(start_time, start_height) = parse(tips[0])
(end_time, end_height) = parse(tips[-1])
seconds = max((end_time - start_time).total_seconds(), 1)
rate = (end_height - start_height) / seconds

print(f"rate      : {rate:.1f} blocks/s (last {len(tips)} blocks)")
if behind <= 0:
    print("eta       : caught up")
elif rate > 0:
    eta = behind / rate
    print(f"eta       : ~{eta / 3600:.1f} h" if eta > 3600 else f"eta       : ~{eta / 60:.0f} min")
PY
}

if $WATCH; then
  while true; do
    clear
    date "+%H:%M:%S"
    report || exit 1
    sleep 30
  done
else
  report
fi
