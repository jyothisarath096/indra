#!/usr/bin/env bash
set -u

# Four-validator line topology with validator 2 paused long enough to fall
# behind by roughly ten heights, then resumed and checked for catch-up without
# an identity ban. The shared harness performs the SIGSTOP/SIGCONT and all
# process, tip, panic, and stale-sync checks.
LAG_SECONDS=${LAG_SECONDS:-360}
TARGET_HEIGHT=${TARGET_HEIGHT:-10}
EXPECT_PEER_COUNTS=${EXPECT_PEER_COUNTS:-1,2,2,1}
export STOP_NODE2_SECONDS="$LAG_SECONDS" TARGET_HEIGHT EXPECT_PEER_COUNTS

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$SCRIPT_DIR/line_topology_live.sh" "$@"
