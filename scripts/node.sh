#!/usr/bin/env bash
#
# node.sh — control the bitcoind instance this project uses.
#
# We deliberately use a DEDICATED data directory (~/.bitcoin-solo) instead of
# Bitcoin Core's default (~/Library/Application Support/Bitcoin), so nothing
# this project does can ever touch another node or wallet on this machine.
#
# Bitcoin Core namespaces networks inside the datadir automatically:
#   ~/.bitcoin-solo/regtest/    ~/.bitcoin-solo/testnet4/    ~/.bitcoin-solo/
#
# Usage:
#   ./scripts/node.sh start  [network]
#   ./scripts/node.sh stop   [network]
#   ./scripts/node.sh status [network]
#   ./scripts/node.sh cli    [network] <bitcoin-cli args...>
#
# `network` is regtest (default), testnet4, or mainnet.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMMAND="${1:-}"
NETWORK="${2:-regtest}"

DATADIR="${SOLO_DATADIR:-$HOME/.bitcoin-solo}"
CONF="$REPO_ROOT/config/bitcoin.$NETWORK.conf"

# Prefer whatever is on PATH; fall back to the Homebrew location.
BITCOIND="$(command -v bitcoind || echo /opt/homebrew/opt/bitcoin/bin/bitcoind)"
BITCOIN_CLI="$(command -v bitcoin-cli || echo /opt/homebrew/opt/bitcoin/bin/bitcoin-cli)"

# Both binaries read the same config file, so bitcoin-cli picks up the network
# (regtest=1 etc.) automatically and we never pass -regtest by hand.
ARGS=(-datadir="$DATADIR" -conf="$CONF")

die() { echo "error: $*" >&2; exit 1; }

[[ -f "$CONF" ]] || die "no config for network '$NETWORK' (expected $CONF)"

case "$COMMAND" in
  start)
    mkdir -p "$DATADIR"
    echo "starting bitcoind  network=$NETWORK  datadir=$DATADIR"
    "$BITCOIND" "${ARGS[@]}" -daemon

    # bitcoind forks immediately but the RPC server is not up until it has
    # loaded the block index, so poll until it answers before returning.
    for _ in $(seq 1 60); do
      if "$BITCOIN_CLI" "${ARGS[@]}" getblockchaininfo >/dev/null 2>&1; then
        echo "RPC is up."
        exec "$BITCOIN_CLI" "${ARGS[@]}" getblockchaininfo
      fi
      sleep 1
    done
    die "bitcoind did not answer RPC within 60s — check $DATADIR/$NETWORK/debug.log"
    ;;

  stop)
    "$BITCOIN_CLI" "${ARGS[@]}" stop
    ;;

  status)
    "$BITCOIN_CLI" "${ARGS[@]}" getblockchaininfo
    ;;

  cli)
    # Everything from the 3rd argument on is passed straight to bitcoin-cli.
    "$BITCOIN_CLI" "${ARGS[@]}" "${@:3}"
    ;;

  *)
    sed -n '3,20p' "${BASH_SOURCE[0]}"   # print the usage block above
    exit 1
    ;;
esac
