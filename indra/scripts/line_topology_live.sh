#!/usr/bin/env bash
set -u

: "${NODE_BIN:?set NODE_BIN}"
: "${GENESIS_BIN:?set GENESIS_BIN}"
: "${KEYGEN_BIN:?set KEYGEN_BIN}"
TARGET_HEIGHT=${TARGET_HEIGHT:-10}
CAP_SECONDS=${CAP_SECONDS:-2400}
START_NODE1_DELAY_SECONDS=${START_NODE1_DELAY_SECONDS:-0}
STOP_NODE_INDEX=${STOP_NODE_INDEX:-1}
STOP_AFTER_HEIGHT=${STOP_AFTER_HEIGHT:-3}
STOP_SECONDS=${STOP_SECONDS:-0}
RESTART_MODE=${RESTART_MODE:-0}
DOWN_SECONDS=${DOWN_SECONDS:-900}
EXPECT_PEER_COUNTS=${EXPECT_PEER_COUNTS:-}
BASE_P2P_PORT=${BASE_P2P_PORT:-32700}
BASE_RPC_PORT=${BASE_RPC_PORT:-19700}
ROOT=${1:-"$(mktemp -d /tmp/indra-line-topology.XXXXXX)"}
mkdir -p "$ROOT"
command -v curl >/dev/null || { echo 'curl is required' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'python3 is required' >&2; exit 2; }
for tool in awk cat date grep kill mkdir mktemp printf sleep tail tee tr; do
    command -v "$tool" >/dev/null 2>&1 || {
        printf '%s\n' "line_topology_live.sh: missing required tool: $tool" >&2
        exit 2
    }
done

PIDS=()
timestamp_ms() { python3 -c 'import time; print(int(time.time() * 1000))'; }
timeline() { printf '%s %s\n' "$(timestamp_ms)" "$*" >>"$ROOT/timeline.log"; }
log_events_after() {
    awk -v start="$1" '
        /\[p2p\] t=[0-9]+ms (authenticated peer connected|peer disconnected)/ {
            t=$0; sub(/^.* t=/, "", t); sub(/ms.*$/, "", t);
            if ((t + 0) >= (start + 0)) count++
        }
        END { print count + 0 }
    ' "$2"
}
rounds_between() {
    awk -v start="$1" -v end="$2" '
        /\[timing\] t=[0-9]+ms ROUND ADVANCED/ {
            t=$0; sub(/^.* t=/, "", t); sub(/ms.*$/, "", t);
            if ((t + 0) >= (start + 0) && (t + 0) <= (end + 0)) count++
        }
        END { print count + 0 }
    ' "$3"
}
cleanup() {
    local pid
    for pid in "${PIDS[@]-}"; do [ -n "$pid" ] && kill -TERM "$pid" 2>/dev/null || true; done
    for pid in "${PIDS[@]-}"; do [ -n "$pid" ] && wait "$pid" 2>/dev/null || true; done
}
trap cleanup EXIT INT TERM

rpc() {
    local port=$1 method=$2
    curl --silent --show-error --max-time 3 -H 'Content-Type: application/json' \
        -H 'X-Rpc-Token: local' \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":[],\"id\":1}" \
        "http://127.0.0.1:$port/" || true
}
admin_rpc() {
    local port=$1 method=$2
    curl --silent --show-error --max-time 3 -H 'Content-Type: application/json' \
        -H 'X-Rpc-Token: local' -H 'X-Admin-Token: local-admin' \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":[],\"id\":1}" \
        "http://127.0.0.1:$port/" || true
}
field() {
    python3 -c 'import json,sys
try:
 v=json.load(sys.stdin).get("result",{})
 for p in sys.argv[1].split("."): v=v.get(p,"")
 print(v)
except Exception: print("")' "$1"
}
metric() { awk -v n="$2" '$1 == n { print $2; found=1 } END { if (!found) print 0 }' "$1" | tail -1; }

make_genesis() {
    local d chain now i
    d=$1
    chain="net3-$(basename "$d")"
    now=$(date +%s)
    mkdir -p "$d/keys" "$d"/data-{0,1,2,3}
    for i in 0 1 2 3; do
        printf 'net3-hot-%s\n' "$i" >"$d/keys/hot-$i.pass"
        printf 'net3-cold-%s\n' "$i" >"$d/keys/cold-$i.pass"
        chmod 600 "$d/keys/"*.pass
        printf 'net3-passphrase-%s\nnet3-passphrase-%s\n' "$i" "$i" |
            "$KEYGEN_BIN" --output "$d/keys/hot-$i.json" --name "net3-validator-$i" \
            --chain-id "$chain" --passphrase --keys-password-file "$d/keys/hot-$i.pass" \
            >"$d/keygen-$i.log" 2>&1 || return 1
        "$KEYGEN_BIN" cold --output "$d/keys/cold-$i.json" \
            --keys-password-file "$d/keys/cold-$i.pass" >>"$d/cold-$i.log" 2>&1 || return 1
        "$KEYGEN_BIN" export-public --keys "$d/keys/hot-$i.json" --chain-id "$chain" \
            --output "$d/keys/hot-$i-public.json" >>"$d/keygen-$i.log" 2>&1 || return 1
        "$KEYGEN_BIN" export-public --keys "$d/keys/cold-$i.json" --chain-id "$chain" \
            --output "$d/keys/cold-$i-public.json" --keys-password-file "$d/keys/cold-$i.pass" \
            --hot-export "$d/keys/hot-$i-public.json" >>"$d/cold-$i.log" 2>&1 || return 1
        "$GENESIS_BIN" create-vrf-proof --chain-id "$chain" --hot-keys "$d/keys/hot-$i.json" \
            --keys-password-file "$d/keys/hot-$i.pass" --output "$d/keys/vrf-$i.json" \
            >>"$d/genesis.log" 2>&1 || return 1
        "$GENESIS_BIN" validator-entry --name "net3-validator-$i" --stake 1000000000000 \
            --chain-id "$chain" --hot-export "$d/keys/hot-$i-public.json" \
            --cold-export "$d/keys/cold-$i-public.json" --vrf-proof "$d/keys/vrf-$i.json" \
            --output "$d/keys/entry-$i.json" >>"$d/genesis.log" 2>&1 || return 1
    done
    "$GENESIS_BIN" build --chain-id "$chain" --genesis-timestamp "$now" \
        --validator-entry "$d/keys/entry-0.json" --validator-entry "$d/keys/entry-1.json" \
        --validator-entry "$d/keys/entry-2.json" --validator-entry "$d/keys/entry-3.json" \
        --output "$d/genesis.toml" >>"$d/genesis.log" 2>&1 || return 1
    "$GENESIS_BIN" validate --genesis "$d/genesis.toml" >>"$d/genesis.log" 2>&1
}

write_config() {
    local d=$1 i=$2 peers
    case "$i" in
        0) peers="\"127.0.0.1:$((BASE_P2P_PORT+10))\"" ;;
        1) peers="\"127.0.0.1:$BASE_P2P_PORT\", \"127.0.0.1:$((BASE_P2P_PORT+20))\"" ;;
        2) peers="\"127.0.0.1:$((BASE_P2P_PORT+10))\", \"127.0.0.1:$((BASE_P2P_PORT+30))\"" ;;
        3) peers="\"127.0.0.1:$((BASE_P2P_PORT+20))\"" ;;
    esac
    cat >"$d/config-$i.toml" <<EOF
[node]
mode = "validator"
data_dir = "$d/data-$i"
genesis = "$d/genesis.toml"
[keys]
path = "$d/keys/hot-$i.json"
password_file = "$d/keys/hot-$i.pass"
[network]
p2p_addr = "127.0.0.1:$((BASE_P2P_PORT+i*10))"
observer_addr = ""
bootstrap_peers = [$peers]
dns_discovery_enabled = false
[rpc]
addr = "127.0.0.1:$((BASE_RPC_PORT+i*10))"
enabled = true
access_token = "local"
admin_token = "local-admin"
[metrics]
addr = "127.0.0.1:$((BASE_RPC_PORT+600+i*10))"
enabled = true
EOF
}

start_one_node() {
    local d=$1 i=$2
    printf 'COMMAND node-%s: %q --config %q\n' "$i" "$NODE_BIN" "$d/config-$i.toml" >>"$d/commands.log"
    "$NODE_BIN" --config "$d/config-$i.toml" >>"$d/node-$i.stdout" 2>>"$d/node-$i.stderr" &
    PIDS[$i]=$!
}

start_nodes() {
    local d=$1 i
    for i in 0 2 3; do
        start_one_node "$d" "$i"
    done
    if [ "$START_NODE1_DELAY_SECONDS" -gt 0 ]; then
        sleep "$START_NODE1_DELAY_SECONDS"
    fi
    i=1
    start_one_node "$d" "$i"
}

snapshot() {
    local d=$1 i
    for i in 0 1 2 3; do
        rpc $((BASE_RPC_PORT+i*10)) indra_getTip >"$d/tip-$i.json"
        rpc $((BASE_RPC_PORT+i*10)) indra_getChainInfo >"$d/info-$i.json"
        admin_rpc $((BASE_RPC_PORT+i*10)) indra_getPeerTopology >"$d/topology-$i.json"
        curl --silent --max-time 3 "http://127.0.0.1:$((BASE_RPC_PORT+600+i*10))/metrics" \
            >"$d/metrics-$i" || true
    done
}

make_genesis "$ROOT" || { echo "genesis failed; see $ROOT/genesis.log" >&2; exit 1; }
for i in 0 1 2 3; do write_config "$ROOT" "$i"; done
timeline t_start
started_at_ms=$(timestamp_ms)
start_nodes "$ROOT"
started=$SECONDS
if [ "$STOP_SECONDS" -gt 0 ] || [ "$RESTART_MODE" -eq 1 ]; then
    stop_started=$SECONDS
    while [ "$SECONDS" -lt "$((stop_started+CAP_SECONDS))" ]; do
        stop_height=0
        for i in 0 1 2 3; do
            height=$(rpc $((BASE_RPC_PORT+i*10)) indra_getTip | field height)
            [ -n "$height" ] || height=0
            [ "$height" -gt "$stop_height" ] 2>/dev/null && stop_height=$height
        done
        if [ "$stop_height" -ge "$STOP_AFTER_HEIGHT" ] 2>/dev/null; then break; fi
        sleep 2
    done
    if [ "$stop_height" -lt "$STOP_AFTER_HEIGHT" ] 2>/dev/null; then
        echo "failed to reach STOP_AFTER_HEIGHT=$STOP_AFTER_HEIGHT before interruption" >&2
        exit 1
    fi
    height_at_stop=$stop_height
    t_stop_ms=$(timestamp_ms)
    timeline "t_stop t_ms=$t_stop_ms height=$height_at_stop node=$STOP_NODE_INDEX"
    if [ "$RESTART_MODE" -eq 1 ]; then
        kill -KILL "${PIDS[$STOP_NODE_INDEX]}" 2>/dev/null || true
        timeline "t_down t_ms=$t_stop_ms height_at_stop=$height_at_stop"
        sleep "$DOWN_SECONDS"
    else
        kill -STOP "${PIDS[$STOP_NODE_INDEX]}" 2>/dev/null || true
        sleep "$STOP_SECONDS"
    fi
    t_cont_ms=$(timestamp_ms)
    if [ "$RESTART_MODE" -eq 1 ]; then
        timeline "t_restart t_ms=$t_cont_ms height_at_stop=$height_at_stop"
        start_one_node "$ROOT" "$STOP_NODE_INDEX"
    else
        timeline "t_cont t_ms=$t_cont_ms height_at_stop=$height_at_stop"
        kill -CONT "${PIDS[$STOP_NODE_INDEX]}" 2>/dev/null || true
    fi
    timeline "resume_observed height_at_stop=$height_at_stop"
else
    height_at_stop=0
    t_cont_ms=0
fi
reached=0
mesh_formed_ms=
t_first_block_after_cont_ms=
t_all_nodes_at_tip_ms=
paused_both_neighbours_ms=
while [ "$SECONDS" -lt "$((started+CAP_SECONDS))" ]; do
    min_height=999999
    max_height=0
    tips=()
    for i in 0 1 2 3; do
        height=$(rpc $((BASE_RPC_PORT+i*10)) indra_getTip | field height)
        [ -n "$height" ] || height=0
        [ "$height" -lt "$min_height" ] 2>/dev/null && min_height=$height
        [ "$height" -gt "$max_height" ] 2>/dev/null && max_height=$height
        tips[$i]=$(rpc $((BASE_RPC_PORT+i*10)) indra_getTip | field tip_hash)
    done
    now_ms=$(timestamp_ms)
    if [ -z "$mesh_formed_ms" ]; then
        mesh_formed=1
        if [ -n "$EXPECT_PEER_COUNTS" ]; then
            IFS=, read -r -a expected_peers <<<"$EXPECT_PEER_COUNTS"
            for i in 0 1 2 3; do
                peer_count=$(admin_rpc $((BASE_RPC_PORT+i*10)) indra_getPeerTopology | field peer_count)
                [ "${expected_peers[$i]:-}" = "$peer_count" ] || mesh_formed=0
            done
        else
            mesh_formed=0
        fi
        if [ "$mesh_formed" -eq 1 ]; then
            mesh_formed_ms=$now_ms
            timeline "mesh_formed t_ms=$mesh_formed_ms"
        fi
    fi
    if { [ "$STOP_SECONDS" -gt 0 ] || [ "$RESTART_MODE" -eq 1 ]; } && [ -z "$t_first_block_after_cont_ms" ] && \
        [ "$max_height" -gt "$height_at_stop" ] 2>/dev/null; then
        t_first_block_after_cont_ms=$now_ms
        timeline "t_first_block_after_cont height=$max_height"
    fi
    if { [ "$STOP_SECONDS" -gt 0 ] || [ "$RESTART_MODE" -eq 1 ]; } && [ -z "$paused_both_neighbours_ms" ]; then
        peer_count=$(admin_rpc $((BASE_RPC_PORT+STOP_NODE_INDEX*10)) indra_getPeerTopology | field peer_count)
        if [ "$peer_count" -ge 2 ] 2>/dev/null; then
            paused_both_neighbours_ms=$now_ms
            timeline "paused_node_both_neighbours_connected peer_count=$peer_count"
        fi
    fi
    target_after_pause=$((height_at_stop+5))
    if { [ "$STOP_SECONDS" -gt 0 ] || [ "$RESTART_MODE" -eq 1 ]; } && [ "$min_height" -ge "$target_after_pause" ] 2>/dev/null; then
        same_current_tip=1
        first_current_tip=${tips[0]}
        for i in 1 2 3; do [ "${tips[$i]}" = "$first_current_tip" ] || same_current_tip=0; done
        if [ "$same_current_tip" -eq 1 ]; then
            t_all_nodes_at_tip_ms=$now_ms
            timeline "t_all_nodes_at_tip height=$min_height tip=$first_current_tip"
            reached=1
            break
        fi
    fi
    if [ "$min_height" -ge "$TARGET_HEIGHT" ] 2>/dev/null; then reached=1; break; fi
    sleep 2
done
snapshot "$ROOT"

for pid in "${PIDS[@]-}"; do kill -TERM "$pid" 2>/dev/null || true; done
for i in 0 1 2 3; do
    wait "${PIDS[$i]}" 2>/dev/null; printf '%s\n' "$?" >"$ROOT/exit-$i"
done

same_tip=1; first_tip=""
for i in 0 1 2 3; do
    tip=$(test -f "$ROOT/tip-$i.json" && field tip_hash <"$ROOT/tip-$i.json" || printf '')
    [ -n "$first_tip" ] || first_tip=$tip
    [ "$tip" = "$first_tip" ] || same_tip=0
done
panics=$(grep -hEc 'panicked at|handler panic' "$ROOT"/node-*.stderr 2>/dev/null | awk '{s+=$1} END{print s+0}')
stale=$(grep -hE 'indra_stale_sync_responses_total' "$ROOT"/metrics-* 2>/dev/null | awk '{s+=$2} END{print s+0}')
exits_ok=1
for i in 0 1 2 3; do [ "$(cat "$ROOT/exit-$i")" = 0 ] || exits_ok=0; done
peer_counts_ok=1
if [ -n "$EXPECT_PEER_COUNTS" ]; then
    IFS=, read -r -a expected_peers <<<"$EXPECT_PEER_COUNTS"
    for i in 0 1 2 3; do
        [ "${expected_peers[$i]:-}" = "$(field peers <"$ROOT/info-$i.json")" ] || peer_counts_ok=0
    done
fi

{
    printf '# line topology live run\n\n'
    rounds_during_pause=0
    connection_events_after_resume=()
    event_reference_ms=${t_cont_ms:-0}
    if [ "$STOP_SECONDS" -eq 0 ] && [ "$RESTART_MODE" -eq 0 ]; then
        event_reference_ms=${mesh_formed_ms:-$started_at_ms}
    fi
    for i in 0 1 2 3; do
        connection_events_after_resume[$i]=$(log_events_after "$event_reference_ms" "$ROOT/node-$i.stderr")
        rounds_during_pause=$((rounds_during_pause+$(rounds_between "${t_stop_ms:-0}" "${t_cont_ms:-0}" "$ROOT/node-$i.stderr")))
    done
    recovery_seconds=
    if [ -n "$t_first_block_after_cont_ms" ]; then
        recovery_ms=$((t_first_block_after_cont_ms-t_cont_ms))
        recovery_seconds=$(awk -v ms="$recovery_ms" 'BEGIN { printf "%.3f", ms / 1000 }')
    fi
    printf 'target_height=%s reached=%s same_tip=%s panics=%s stale_sync=%s exits_zero=%s peer_counts_ok=%s elapsed_seconds_after_start=%s pause_seconds=%s down_seconds=%s rounds_reached_during_pause=%s recovery_seconds=%s mesh_formed_ms=%s event_reference_ms=%s t_all_nodes_at_tip_ms=%s paused_node_both_neighbours_ms=%s\n\n' \
        "$TARGET_HEIGHT" "$reached" "$same_tip" "$panics" "${stale:-0}" "$exits_ok" "$peer_counts_ok" "$((SECONDS-started))" "$STOP_SECONDS" "$([ "$RESTART_MODE" -eq 1 ] && printf '%s' "$DOWN_SECONDS" || printf '0')" "$rounds_during_pause" "${recovery_seconds:-}" "${mesh_formed_ms:-}" "$event_reference_ms" "${t_all_nodes_at_tip_ms:-}" "${paused_both_neighbours_ms:-}"
    printf '| node | height | tip | peers | exit | post-resume connection events | topology |\n|---:|---:|---|---:|---:|---:|---|\n'
    for i in 0 1 2 3; do
        printf '| %s | %s | %s | %s | %s | %s | %s |\n' "$i" \
            "$(field height <"$ROOT/tip-$i.json")" \
            "$(field tip_hash <"$ROOT/tip-$i.json")" \
            "$(field peers <"$ROOT/info-$i.json")" \
            "$(cat "$ROOT/exit-$i")" \
            "${connection_events_after_resume[$i]:-0}" \
            "$(tr '\n' ' ' <"$ROOT/topology-$i.json")"
    done
} | tee "$ROOT/summary.md"

summary_line=$(grep '^target_height=' "$ROOT/summary.md" | tail -1 || true)
result_valid=1
[ -n "$summary_line" ] || result_valid=0
if [ "$STOP_SECONDS" -gt 0 ] || [ "$RESTART_MODE" -eq 1 ]; then
    printf '%s\n' "$summary_line" | grep -Eq 'recovery_seconds=[^ ]+' || result_valid=0
fi

if [ "$result_valid" -eq 1 ] && [ "$reached" -eq 1 ] && [ "$same_tip" -eq 1 ] && [ "$panics" -eq 0 ] && \
    [ "${stale:-0}" -eq 0 ] && [ "$exits_ok" -eq 1 ] && [ "$peer_counts_ok" -eq 1 ]; then
    printf 'PASS\n'
    exit 0
fi
printf 'FAIL\n' >&2
exit 1
