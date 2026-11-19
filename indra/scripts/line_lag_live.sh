#!/usr/bin/env bash
set -u

# Four-validator line topology with node 1 paused after height 3, then resumed
# and checked for recovery without an identity ban. The shared harness records
# the pause/resume timeline and distinguishes recovery from total run time.
LAG_SECONDS=${LAG_SECONDS:-360}
TARGET_HEIGHT=${TARGET_HEIGHT:-10}
EXPECT_PEER_COUNTS=${EXPECT_PEER_COUNTS:-1,2,2,1}
STOP_NODE_INDEX=${STOP_NODE_INDEX:-1}
STOP_AFTER_HEIGHT=${STOP_AFTER_HEIGHT:-3}
export STOP_SECONDS="$LAG_SECONDS" STOP_NODE_INDEX STOP_AFTER_HEIGHT TARGET_HEIGHT EXPECT_PEER_COUNTS

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$SCRIPT_DIR/line_topology_live.sh" "$@"
