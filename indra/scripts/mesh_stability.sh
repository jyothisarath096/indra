#!/usr/bin/env bash
set -u

: "${NODE_BIN:?set NODE_BIN}"
: "${GENESIS_BIN:?set GENESIS_BIN}"
: "${KEYGEN_BIN:?set KEYGEN_BIN}"
RUNS=${RUNS:-20}
WAIT_SECONDS=${WAIT_SECONDS:-60}
PEER_GATE_SECONDS=${PEER_GATE_SECONDS:-60}
BASE_P2P_PORT=${BASE_P2P_PORT:-32600}
BASE_RPC_PORT=${BASE_RPC_PORT:-19600}
ROOT=${1:-"$(mktemp -d /tmp/indra-mesh-stability.XXXXXX)"}
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
    curl --silent --show-error --max-time 3 -H 'Content-Type: application/json' -H 'X-Rpc-Token: local' \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":[],\"id\":1}" \
        "http://127.0.0.1:$port/" || true
}
admin_rpc() {
    local port=$1 method=$2
    curl --silent --show-error --max-time 3 -H 'Content-Type: application/json' -H 'X-Rpc-Token: local' -H 'X-Admin-Token: local-admin' \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":[],\"id\":1}" \
        "http://127.0.0.1:$port/" || true
}
field() { python3 -c 'import json,sys
try:
 v=json.load(sys.stdin).get("result",{})
 for p in sys.argv[1].split("."): v=v.get(p,"")
 print(v)
except Exception: print("")' "$1"; }

make_genesis() {
    local d=$1 chain="net1-$(basename "$d")" now i
    now=$(date +%s); mkdir -p "$d/keys" "$d"/data-{0,1,2,3}
    for i in 0 1 2 3; do
        printf 'net1-hot-%s\n' "$i" >"$d/keys/hot-$i.pass"
        printf 'net1-cold-%s\n' "$i" >"$d/keys/cold-$i.pass"
        chmod 600 "$d/keys/"*.pass
        printf 'net1-passphrase-%s\nnet1-passphrase-%s\n' "$i" "$i" | "$KEYGEN_BIN" --output "$d/keys/hot-$i.json" --name "net1-validator-$i" --chain-id "$chain" --passphrase --keys-password-file "$d/keys/hot-$i.pass" >"$d/keygen-$i.log" 2>&1
        "$KEYGEN_BIN" cold --output "$d/keys/cold-$i.json" --keys-password-file "$d/keys/cold-$i.pass" >"$d/cold-$i.log" 2>&1
        "$KEYGEN_BIN" export-public --keys "$d/keys/hot-$i.json" --chain-id "$chain" --output "$d/keys/hot-$i-public.json" >>"$d/keygen-$i.log" 2>&1
        "$KEYGEN_BIN" export-public --keys "$d/keys/cold-$i.json" --chain-id "$chain" --output "$d/keys/cold-$i-public.json" --keys-password-file "$d/keys/cold-$i.pass" --hot-export "$d/keys/hot-$i-public.json" >>"$d/cold-$i.log" 2>&1
        "$GENESIS_BIN" create-vrf-proof --chain-id "$chain" --hot-keys "$d/keys/hot-$i.json" --keys-password-file "$d/keys/hot-$i.pass" --output "$d/keys/vrf-$i.json" >>"$d/genesis.log" 2>&1
        "$GENESIS_BIN" validator-entry --name "net1-validator-$i" --stake 1000000000000 --chain-id "$chain" --hot-export "$d/keys/hot-$i-public.json" --cold-export "$d/keys/cold-$i-public.json" --vrf-proof "$d/keys/vrf-$i.json" --output "$d/keys/entry-$i.json" >>"$d/genesis.log" 2>&1
    done
    "$GENESIS_BIN" build --chain-id "$chain" --genesis-timestamp "$now" \
        --validator-entry "$d/keys/entry-0.json" --validator-entry "$d/keys/entry-1.json" \
        --validator-entry "$d/keys/entry-2.json" --validator-entry "$d/keys/entry-3.json" \
        --output "$d/genesis.toml" >>"$d/genesis.log" 2>&1
    "$GENESIS_BIN" validate --genesis "$d/genesis.toml" >>"$d/genesis.log" 2>&1
}

write_config() {
    local d=$1 i=$2 peers="" j
    for j in 0 1 2 3; do [ "$j" = "$i" ] || peers="$peers\"127.0.0.1:$((BASE_P2P_PORT+j*10))\", "; done
    peers=${peers%, }
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
    PIDS=()
    for i in 0 1 2 3; do
        printf 'COMMAND node-%s: %q --config %q\n' "$i" "$NODE_BIN" "$d/config-$i.toml" >>"$d/commands.log"
        "$NODE_BIN" --config "$d/config-$i.toml" >"$d/node-$i.stdout" 2>"$d/node-$i.stderr" & PIDS+=("$!")
    done
}

stop_nodes() {
    local pid
    for pid in "${PIDS[@]-}"; do kill -TERM "$pid" 2>/dev/null || true; done
    for pid in "${PIDS[@]-}"; do wait "$pid" 2>/dev/null || true; done
    PIDS=()
}

peer_gate() {
    local d=$1 until=$((SECONDS+PEER_GATE_SECONDS)) i peers
    while [ "$SECONDS" -lt "$until" ]; do
        for i in 0 1 2 3; do
            peers=$(rpc $((BASE_RPC_PORT+i*10)) indra_getChainInfo | field peers)
            [ "${peers:-0}" -ge 3 ] 2>/dev/null || break
            [ "$i" = 3 ] && return 0
        done
        sleep 1
    done
    for i in 0 1 2 3; do
        admin_rpc $((BASE_RPC_PORT+i*10)) indra_getPeerTopology >"$d/topology-$i.json"
        printf 'node-%s peers=%s topology=%s\n' "$i" \
            "$(rpc $((BASE_RPC_PORT+i*10)) indra_getChainInfo | field peers)" \
            "$(tr '\n' ' ' <"$d/topology-$i.json")" >>"$d/missing-edges.log"
    done
    return 1
}

printf '# NET_1 mesh stability\n\n' >"$ROOT/summary.md"
printf '| start | result | elapsed_seconds | missing edges |\n|---:|---|---:|---|\n' >>"$ROOT/summary.md"
for run in $(seq 1 "$RUNS"); do
    d="$ROOT/start-$run"; mkdir -p "$d"; started=$SECONDS
    if ! make_genesis "$d"; then
        printf '| %s | FAIL genesis | %s | genesis failure |\n' "$run" "$((SECONDS-started))" >>"$ROOT/summary.md"
        continue
    fi
    for i in 0 1 2 3; do write_config "$d" "$i"; done
    start_nodes "$d"
    sleep "$WAIT_SECONDS"
    if peer_gate "$d"; then
        result=PASS; missing=none
    else
        result=FAIL; missing=$(tr '\n' ';' <"$d/missing-edges.log")
    fi
    printf '| %s | %s | %s | %s |\n' "$run" "$result" "$((SECONDS-started))" "$missing" >>"$ROOT/summary.md"
    stop_nodes
done
printf '\nPASS=%s FAIL=%s\n' "$(grep -c '| PASS |' "$ROOT/summary.md" || true)" "$(grep -c '| FAIL' "$ROOT/summary.md" || true)" >>"$ROOT/summary.md"
printf 'Summary: %s\n' "$ROOT/summary.md"
