#!/usr/bin/env bash
set -u

: "${NODE_BIN:?set NODE_BIN}"
: "${GENESIS_BIN:?set GENESIS_BIN}"
: "${KEYGEN_BIN:?set KEYGEN_BIN}"
TARGET_HEIGHT=${TARGET_HEIGHT:-10}
CAP_SECONDS=${CAP_SECONDS:-2400}
START_NODE1_DELAY_SECONDS=${START_NODE1_DELAY_SECONDS:-0}
STOP_NODE2_SECONDS=${STOP_NODE2_SECONDS:-0}
EXPECT_PEER_COUNTS=${EXPECT_PEER_COUNTS:-}
BASE_P2P_PORT=${BASE_P2P_PORT:-32700}
BASE_RPC_PORT=${BASE_RPC_PORT:-19700}
ROOT=${1:-"$(mktemp -d /tmp/indra-line-topology.XXXXXX)"}
mkdir -p "$ROOT"
command -v curl >/dev/null || { echo 'curl is required' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'python3 is required' >&2; exit 2; }

PIDS=()
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

start_nodes() {
    local d=$1 i
    for i in 0 2 3; do
        printf 'COMMAND node-%s: %q --config %q\n' "$i" "$NODE_BIN" "$d/config-$i.toml" >>"$d/commands.log"
        "$NODE_BIN" --config "$d/config-$i.toml" >"$d/node-$i.stdout" 2>"$d/node-$i.stderr" &
        PIDS+=($!)
    done
    if [ "$START_NODE1_DELAY_SECONDS" -gt 0 ]; then
        sleep "$START_NODE1_DELAY_SECONDS"
    fi
    i=1
    printf 'COMMAND node-%s: %q --config %q\n' "$i" "$NODE_BIN" "$d/config-$i.toml" >>"$d/commands.log"
    "$NODE_BIN" --config "$d/config-$i.toml" >"$d/node-$i.stdout" 2>"$d/node-$i.stderr" &
    PIDS+=($!)
    if [ "$STOP_NODE2_SECONDS" -gt 0 ]; then
        sleep 2
        kill -STOP "${PIDS[1]}" 2>/dev/null || true
        sleep "$STOP_NODE2_SECONDS"
        kill -CONT "${PIDS[1]}" 2>/dev/null || true
    fi
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
start_nodes "$ROOT"
started=$SECONDS
reached=0
while [ "$SECONDS" -lt "$((started+CAP_SECONDS))" ]; do
    min_height=999999
    for i in 0 1 2 3; do
        height=$(rpc $((BASE_RPC_PORT+i*10)) indra_getTip | field height)
        [ -n "$height" ] || height=0
        [ "$height" -lt "$min_height" ] 2>/dev/null && min_height=$height
    done
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
    printf 'target_height=%s reached=%s same_tip=%s panics=%s stale_sync=%s exits_zero=%s peer_counts_ok=%s elapsed_seconds=%s\n\n' \
        "$TARGET_HEIGHT" "$reached" "$same_tip" "$panics" "${stale:-0}" "$exits_ok" "$peer_counts_ok" "$((SECONDS-started))"
    printf '| node | height | tip | peers | exit | topology |\n|---:|---:|---|---:|---:|---|\n'
    for i in 0 1 2 3; do
        printf '| %s | %s | %s | %s | %s | %s |\n' "$i" \
            "$(field height <"$ROOT/tip-$i.json")" \
            "$(field tip_hash <"$ROOT/tip-$i.json")" \
            "$(field peers <"$ROOT/info-$i.json")" \
            "$(cat "$ROOT/exit-$i")" \
            "$(tr '\n' ' ' <"$ROOT/topology-$i.json")"
    done
} | tee "$ROOT/summary.md"

if [ "$reached" -eq 1 ] && [ "$same_tip" -eq 1 ] && [ "$panics" -eq 0 ] && \
    [ "${stale:-0}" -eq 0 ] && [ "$exits_ok" -eq 1 ] && [ "$peer_counts_ok" -eq 1 ]; then
    printf 'PASS\n'
    exit 0
fi
printf 'FAIL\n' >&2
exit 1
