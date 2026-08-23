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

# --- Build, so the binaries match the source -----------------------------
#
# The whole point of this project is editing the code, and running a stale
# binary after a change is a confusing way to lose an hour. cargo is a no-op
# when nothing changed, so this costs nothing on a normal start.
export PATH="/opt/homebrew/opt/rustup/bin:$PATH"
command -v cargo > /dev/null || die "cargo not found. Install Rust, or build manually and edit this script."
echo "building..."
cargo build --release -q -p solo-pool -p mac-miner || die "build failed"

# --- Refuse to mine on a node that is not ready --------------------------
#
# Mining on a stale tip is not merely wasteful, it is certain to be wasted:
# the block would build on a parent the network has already moved past, and
# every hash spent on it is spent on something that cannot be accepted.
# The pool owns this decision — it checks the chain, the sync state, the peer
# count and the tip's age in one place (see crates/solo-pool/src/readiness.rs).
# Repeating a weaker version here would only give two answers that can drift
# apart. This just fails fast, with a friendlier message, when there is plainly
# no node at all.
./scripts/node.sh cli "$NETWORK" getblockcount > /dev/null 2>&1 \
  || die "no $NETWORK node responding. Start one with: ./scripts/node.sh start $NETWORK"

# --- Clear the way -------------------------------------------------------
#
# A pool left over from a previous run holds port 3333 and the next start fails
# with a bare "Address already in use". Since anything listening there under our
# own binary is definitionally ours and stale, clear it; anything else is
# somebody's business and we stop instead.
STALE="$(lsof -nP -iTCP:3333 -sTCP:LISTEN -t 2>/dev/null || true)"
if [[ -n "$STALE" ]]; then
  if ps -p "$STALE" -o command= | grep -q solo-pool; then
    echo "clearing a stale solo-pool (pid $STALE) still holding port 3333"
    kill "$STALE" 2>/dev/null
    sleep 1
  else
    die "port 3333 is in use by pid $STALE ($(ps -p "$STALE" -o comm=)), which is not ours"
  fi
fi

# --- Run -----------------------------------------------------------------
POOL_LOG="$(mktemp -t solo-pool)"

# Everything started here must die with the script. Note the miner below is NOT
# exec'd: exec would replace this shell, taking the trap with it, and the pool
# would outlive Ctrl-C and hold the port against the next run.
# Set by cleanup so the exit path below can tell a shutdown we asked for from
# one that happened to us.
STOPPING=false

cleanup() {
  STOPPING=true
  echo
  echo "stopping..."

  # Kill every child rather than named PIDs. In `a | b &`, `$!` is the PID of
  # `b` only, so killing it leaves `a` alive — and a surviving `tail -f` holds
  # this script's stdout open, so whatever is reading it never sees EOF and
  # hangs forever. Killing by parent gets the whole pipeline.
  pkill -P $$ 2>/dev/null
  wait 2>/dev/null

  echo "pool log kept at $POOL_LOG"
}
# A signal handler that does not exit would let bash resume after the
# interrupted command, so Ctrl-C is made explicit. 130 is the conventional
# status for SIGINT.
trap 'cleanup; exit 130' INT TERM
trap cleanup EXIT

./target/release/solo-pool --network "$NETWORK" --address "$ADDRESS" > "$POOL_LOG" 2>&1 &
POOL_PID=$!

# Wait for the pool to announce that it has *built a job*, not merely that its
# process exists. A pool whose node is unreachable can bind the port and look
# perfectly healthy while never producing work, and a miner pointed at it would
# hash nothing while reporting a fine hashrate.
echo "waiting for the pool to get work..."
for _ in $(seq 1 60); do
  grep -q "POOL READY" "$POOL_LOG" 2>/dev/null && READY=1 && break
  kill -0 "$POOL_PID" 2>/dev/null || break
  sleep 1
done

if [[ -z "${READY:-}" ]]; then
  echo
  echo "the pool never produced a job. Its output:"
  echo "---"
  cat "$POOL_LOG"
  exit 1
fi

sed -n '1,8p' "$POOL_LOG"

# Blocks found are announced by the pool, so surface its output alongside the
# miner's rather than burying it in a file.
# Anything that is a block, a rejection, or a failure. The earlier filter listed
# only good news, which meant "cannot fetch a template" and "cannot build a job"
# — the latter being how a witness-commitment mismatch surfaces — never reached
# the terminal.
tail -f "$POOL_LOG" \
  | grep --line-buffered -iE "BLOCK FOUND|accepted|REJECTED|not adopted|new tip|FATAL|error|cannot|warn|disagree" &

MINER_ARGS=(--pool 127.0.0.1:3333 --worker "mac.$NETWORK")
[[ -n "$THREADS" ]] && MINER_ARGS+=(--threads "$THREADS")

# Backgrounded and waited on, deliberately — and deliberately not exec'd.
#
# `exec` would replace this shell and take the traps with it. But a plain
# foreground child is not much better: bash defers signal handling until the
# running command finishes, so a SIGTERM aimed at this script alone would sit
# pending while the miner ran on, and nothing would ever stop. `wait` is
# interruptible, so the trap fires immediately either way.
./target/release/mac-miner "${MINER_ARGS[@]}" &
MINER_PID=$!
wait "$MINER_PID"
MINER_STATUS=$?

# The miner exits 0 when the pool closes the connection — which is what a clean
# Ctrl-C looks like, and also what a pool that died of its own accord looks
# like. Reporting both as success would let a supervisor read a fatal mining
# failure as a completed run, so they are told apart here, where the reason is
# known.
if [[ "$STOPPING" == false ]] && ! kill -0 "$POOL_PID" 2>/dev/null; then
  echo
  echo "the pool exited on its own — this was not a clean shutdown."
  echo "--- its last output ---"
  tail -8 "$POOL_LOG"
  exit 1
fi

exit "$MINER_STATUS"
