#!/usr/bin/env bash
set -u

# NET_4 skew proof: nodes 0, 2, and 3 start first; node 1 joins 30 seconds
# later, then node 2 is stopped for 20 seconds. The shared harness performs
# the identical-tip, panic, stale-sync, and clean-exit checks.
: "${NODE_BIN:?set NODE_BIN to the release indra-node binary}"
: "${GENESIS_BIN:?set GENESIS_BIN to the release indra-genesis binary}"
: "${KEYGEN_BIN:?set KEYGEN_BIN to the release indra-keygen binary}"
export START_NODE1_DELAY_SECONDS=30
export STOP_NODE2_SECONDS=20
exec "$(dirname "$0")/line_topology_live.sh" "$@"
