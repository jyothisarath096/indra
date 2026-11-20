#!/usr/bin/env bash
set -u

: "${NODE_BIN:?set NODE_BIN}"
: "${GENESIS_BIN:?set GENESIS_BIN}"
: "${KEYGEN_BIN:?set KEYGEN_BIN}"

for tool in awk mkdir printf tail sed grep; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf '%s\n' "pause_threshold.sh: missing required tool: $tool" >&2
        exit 2
    }
done

TARGET_HEIGHT=${TARGET_HEIGHT:-8}
CAP_SECONDS=${CAP_SECONDS:-2400}
STOP_NODE_INDEX=${STOP_NODE_INDEX:-1}
EXPECT_PEER_COUNTS=${EXPECT_PEER_COUNTS:-1,2,2,1}
ROOT=${1:-"$(mktemp -d /tmp/indra-pause-threshold.XXXXXX)"}

mkdir -p "$ROOT"
printf 'stop_seconds\tstatus\trecovery_seconds\tevents\tdirectory\n'
failed=0

for stop_seconds in 300 420 540 660 780; do
    run_dir="$ROOT/stop-$stop_seconds"
    mkdir -p "$run_dir"
    output="$run_dir/harness.out"
    if NODE_BIN="$NODE_BIN" \
        GENESIS_BIN="$GENESIS_BIN" \
        KEYGEN_BIN="$KEYGEN_BIN" \
        STOP_SECONDS="$stop_seconds" \
        TARGET_HEIGHT="$TARGET_HEIGHT" \
        CAP_SECONDS="$CAP_SECONDS" \
        STOP_NODE_INDEX="$STOP_NODE_INDEX" \
        EXPECT_PEER_COUNTS="$EXPECT_PEER_COUNTS" \
        scripts/line_topology_live.sh "$run_dir" >"$output" 2>&1; then
        status=PASS
    else
        status=FAIL
        failed=1
    fi
    result=$(grep '^target_height=' "$output" | tail -1 || true)
    recovery=$(printf '%s\n' "$result" | sed -n 's/.*recovery_seconds=\([^ ]*\).*/\1/p')
    events=$(grep -E '^\| [0-3] \|' "$output" | awk -F'|' '{gsub(/[[:space:]]/, "", $7); total += $7} END {if (NR > 0) print total}' || true)
    if [ -z "$result" ] || [ -z "$recovery" ] || [ -z "$events" ]; then
        status=FAIL
        failed=1
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$stop_seconds" "$status" "${recovery:-MISSING}" "${events:-MISSING}" "$run_dir"
done

exit "$failed"
