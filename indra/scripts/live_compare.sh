#!/usr/bin/env bash
set -u

: "${OLD_NODE_BIN:?set OLD_NODE_BIN}"
: "${NEW_NODE_BIN:?set NEW_NODE_BIN}"
: "${OLD_GENESIS_BIN:?set OLD_GENESIS_BIN}"
: "${NEW_GENESIS_BIN:?set NEW_GENESIS_BIN}"
: "${OLD_KEYGEN_BIN:?set OLD_KEYGEN_BIN}"
: "${NEW_KEYGEN_BIN:?set NEW_KEYGEN_BIN}"
RUNS=${RUNS:-3}; TARGET_HEIGHT=${TARGET_HEIGHT:-50}; CAP_SECONDS=${CAP_SECONDS:-1200}; PEER_GATE_SECONDS=${PEER_GATE_SECONDS:-120}
ROOT=${1:-"$(mktemp -d /tmp/indra-live-compare.XXXXXX)"}; mkdir -p "$ROOT"
command -v curl >/dev/null || { echo 'curl is required' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'python3 is required' >&2; exit 2; }

PIDS=()
cleanup() { local pid; for pid in "${PIDS[@]-}"; do [ -n "$pid" ] || continue; kill -TERM "$pid" 2>/dev/null || true; done; for pid in "${PIDS[@]-}"; do [ -n "$pid" ] || continue; wait "$pid" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

rpc() {
    local port=$1 method=$2
    curl --silent --show-error --max-time 3 -H 'Content-Type: application/json' -H 'X-Rpc-Token: local' \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":[],\"id\":1}" "http://127.0.0.1:$port/" || true
}
field() { python3 -c 'import json,sys
try:
 v=json.load(sys.stdin).get("result",{})
 for p in sys.argv[1].split("."): v=v.get(p,"")
 print(v)
except Exception: print("")' "$1"; }
metric() { awk -v n="$2" '$1 == n { print $2; found=1 } END { if (!found) print 0 }' "$1" | tail -1; }

make_genesis() {
    local kg=$1 gb=$2 d=$3 chain="index7-$(basename "$d")" now i
    now=$(date +%s); mkdir -p "$d/keys" "$d"/data-{0,1,2,3}
    for i in 0 1 2 3; do
        printf 'index7-password-%s\n' "$i" >"$d/keys/hot-$i.pass"; printf 'index7-cold-password-%s\n' "$i" >"$d/keys/cold-$i.pass"; chmod 600 "$d/keys/"*.pass
        printf 'unique-index7-passphrase-%s\nunique-index7-passphrase-%s\n' "$i" "$i" | "$kg" --output "$d/keys/hot-$i.json" --name "index7-validator-$i" --chain-id "$chain" --passphrase --keys-password-file "$d/keys/hot-$i.pass" >"$d/keygen-$i.log" 2>&1
        "$kg" cold --output "$d/keys/cold-$i.json" --keys-password-file "$d/keys/cold-$i.pass" >"$d/cold-$i.log" 2>&1
        "$kg" export-public --keys "$d/keys/hot-$i.json" --chain-id "$chain" --output "$d/keys/hot-$i-public.json" >>"$d/keygen-$i.log" 2>&1
        "$kg" export-public --keys "$d/keys/cold-$i.json" --chain-id "$chain" --output "$d/keys/cold-$i-public.json" --keys-password-file "$d/keys/cold-$i.pass" --hot-export "$d/keys/hot-$i-public.json" >>"$d/cold-$i.log" 2>&1
        "$gb" create-vrf-proof --chain-id "$chain" --hot-keys "$d/keys/hot-$i.json" --keys-password-file "$d/keys/hot-$i.pass" --output "$d/keys/vrf-$i.json" >>"$d/genesis.log" 2>&1
        "$gb" validator-entry --name "index7-validator-$i" --stake 1000000000000 --chain-id "$chain" --hot-export "$d/keys/hot-$i-public.json" --cold-export "$d/keys/cold-$i-public.json" --vrf-proof "$d/keys/vrf-$i.json" --output "$d/keys/entry-$i.json" >>"$d/genesis.log" 2>&1
    done
    "$gb" build --chain-id "$chain" --genesis-timestamp "$now" --validator-entry "$d/keys/entry-0.json" --validator-entry "$d/keys/entry-1.json" --validator-entry "$d/keys/entry-2.json" --validator-entry "$d/keys/entry-3.json" --output "$d/genesis.toml" >>"$d/genesis.log" 2>&1
    "$gb" validate --genesis "$d/genesis.toml" >>"$d/genesis.log" 2>&1
}

write_config() {
    local d=$1 i=$2 peers="" j
    for j in 0 1 2 3; do [ "$j" = "$i" ] || peers="$peers\"127.0.0.1:$((32600+j*10))\", "; done; peers=${peers%, }
    cat >"$d/config-$i.toml" <<EOF
[node]
mode = "validator"
data_dir = "$d/data-$i"
genesis = "$d/genesis.toml"
[keys]
path = "$d/keys/hot-$i.json"
password_file = "$d/keys/hot-$i.pass"
[network]
p2p_addr = "127.0.0.1:$((32600+i*10))"
observer_addr = ""
bootstrap_peers = [$peers]
dns_discovery_enabled = false
[rpc]
addr = "127.0.0.1:$((19600+i*10))"
enabled = true
access_token = "local"
[metrics]
addr = "127.0.0.1:$((20600+i*10))"
enabled = true
EOF
}
start_all() { local d=$1 bin=$2 late=$3 i; PIDS=(); for i in 0 1 2 3; do [ "$i" = "$late" ] && continue; printf 'COMMAND node-%s: %q --config %q\n' "$i" "$bin" "$d/config-$i.toml" | tee -a "$d/commands.log"; "$bin" --config "$d/config-$i.toml" >"$d/node-$i.stdout" 2>"$d/node-$i.stderr" & PIDS+=("$!"); done; }
stop_all() { local d=$1 pid n=0; for pid in "${PIDS[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done; for pid in "${PIDS[@]}"; do wait "$pid" 2>/dev/null; printf '%s\n' "$?" >"$d/exit-$n"; n=$((n+1)); done; PIDS=(); }
peer_gate() { local d=$1 until=$((SECONDS+PEER_GATE_SECONDS)) i p; while [ "$SECONDS" -lt "$until" ]; do for i in 0 1 2 3; do [ -f "$d/node-$i.stdout" ] || continue; p=$(rpc $((19600+i*10)) indra_getChainInfo | field peers); [ "${p:-0}" -ge 3 ] 2>/dev/null || break; [ "$i" = 3 ] && return 0; done; sleep 1; done; for i in 0 1 2 3; do printf 'peer gate failed node=%s\n' "$i" >>"$d/invalid.log"; tail -20 "$d/node-$i.stderr" 2>/dev/null || true; done; return 1; }
snapshot() { local d=$1 i; for i in 0 1 2 3; do rpc $((19600+i*10)) indra_getTip >"$d/tip-$i.json"; rpc $((19600+i*10)) indra_getChainInfo >"$d/info-$i.json"; curl --silent --max-time 3 "http://127.0.0.1:$((20600+i*10))/metrics" >"$d/metrics-$i" || true; done; }
record() { local d=$1 label=$2 valid=$3 seconds=$4 i height tip peers panic stale exit; printf '| %s | %s | %s | %.2f | %.2f |' "$label" "$valid" "$TARGET_HEIGHT" "$seconds" "$(awk -v s="$seconds" -v h="$TARGET_HEIGHT" 'BEGIN{if (s > 0) print h/s*60; else print 0}')" >>"$ROOT/live_compare_summary.md"; for i in 0 1 2 3; do height=$(test -f "$d/tip-$i.json" && field height <"$d/tip-$i.json" || printf '?'); tip=$(test -f "$d/tip-$i.json" && field tip_hash <"$d/tip-$i.json" || printf '?'); peers=$(test -f "$d/info-$i.json" && field peers <"$d/info-$i.json" || printf '?'); panic=$(test -f "$d/metrics-$i" && metric "$d/metrics-$i" 'indra_handler_panics_total{component="none"}' || printf '?'); stale=$(test -f "$d/metrics-$i" && awk '/indra_stale_sync_responses_total/ {s+=$2} END{print s+0}' "$d/metrics-$i" || printf '?'); exit=$(cat "$d/exit-$i" 2>/dev/null || printf '?'); printf ' node%s:h=%s tip=%s peers=%s panic=%s stale=%s exit=%s |' "$i" "$height" "$tip" "$peers" "$panic" "$stale" "$exit" >>"$ROOT/live_compare_summary.md"; done; printf '\n' >>"$ROOT/live_compare_summary.md"; }
scenario_s1() { local d=$1 bin=$2; mkdir -p "$d"; make_genesis "$NEW_KEYGEN_BIN" "$NEW_GENESIS_BIN" "$d" || return 1; for i in 0 1 2 3; do write_config "$d" "$i"; done; start_all "$d" "$bin" -; peer_gate "$d" || { stop_all "$d"; return 1; }; sleep 10; kill -KILL "${PIDS[0]}" 2>/dev/null || true; wait "${PIDS[0]}" 2>/dev/null || true; printf 'S1 killed node0 and restarting same data dir\n' >"$d/scenario.log"; "$bin" --config "$d/config-0.toml" >"$d/node-0-restart.stdout" 2>"$d/node-0-restart.stderr" & PIDS[0]=$!; deadline=$((SECONDS+120)); recovered=0; while [ "$SECONDS" -lt "$deadline" ]; do a=$(rpc 19600 indra_getTip | field tip_hash); b=$(rpc 19610 indra_getTip | field tip_hash); [ -n "$a" ] && [ "$a" = "$b" ] && { recovered=1; break; }; sleep 2; done; printf 'S1 recovered_to_common_tip=%s\n' "$recovered" >>"$d/scenario.log"; snapshot "$d"; stop_all "$d"; }
scenario_s2() { local d=$1 bin=$2; mkdir -p "$d"; make_genesis "$NEW_KEYGEN_BIN" "$NEW_GENESIS_BIN" "$d" || return 1; for i in 0 1 2 3; do write_config "$d" "$i"; done; start_all "$d" "$bin" 3; sleep 60; printf 'COMMAND late node-3: %q --config %q\n' "$bin" "$d/config-3.toml" | tee -a "$d/commands.log"; "$bin" --config "$d/config-3.toml" >"$d/node-3.stdout" 2>"$d/node-3.stderr" & PIDS+=("$!"); peer_gate "$d" || { stop_all "$d"; return 1; }; deadline=$((SECONDS+CAP_SECONDS)); synced=0; while [ "$SECONDS" -lt "$deadline" ]; do a=$(rpc 19600 indra_getTip | field tip_hash); b=$(rpc 19630 indra_getTip | field tip_hash); [ -n "$a" ] && [ "$a" = "$b" ] && { synced=1; break; }; sleep 2; done; printf 'S2 late_node_synced=%s\n' "$synced" >"$d/scenario.log"; snapshot "$d"; stop_all "$d"; }

printf '# INDEX_7 live comparison\n\n| binary | validity | target | seconds | blocks/min | per-node details |\n|---|---|---:|---:|---:|---|\n' >"$ROOT/live_compare_summary.md"
for label in old new; do
    if [ "$label" = old ]; then
        bin=$OLD_NODE_BIN; gb=$OLD_GENESIS_BIN; kg=$OLD_KEYGEN_BIN
    else
        bin=$NEW_NODE_BIN; gb=$NEW_GENESIS_BIN; kg=$NEW_KEYGEN_BIN
    fi
    for run in $(seq 1 "$RUNS"); do
        d="$ROOT/$label-run-$run"; mkdir -p "$d"; make_genesis "$kg" "$gb" "$d" || { printf '%s genesis failed\n' "$label" >"$d/invalid.log"; continue; }; for i in 0 1 2 3; do write_config "$d" "$i"; done; start_all "$d" "$bin" -; started=$SECONDS
        attempt=0; while ! peer_gate "$d"; do stop_all "$d"; attempt=$((attempt+1)); [ "$attempt" -ge 3 ] && break; start_all "$d" "$bin" -; done
        if [ "$attempt" -ge 3 ]; then record "$d" "$label" INVALID "$((SECONDS-started))"; continue; fi
        reached=0; deadline=$((SECONDS+CAP_SECONDS)); while [ "$SECONDS" -lt "$deadline" ]; do h=$(rpc 19600 indra_getTip | field height); if [ "${h:-0}" -ge "$TARGET_HEIGHT" ] 2>/dev/null; then reached=1; break; fi; sleep 2; done
        seconds=$((SECONDS-started)); [ "$reached" -eq 1 ] && validity=VALID || validity=INVALID; snapshot "$d"; stop_all "$d"; record "$d" "$label" "$validity" "$seconds"
    done
done
scenario_s1 "$ROOT/new-s1" "$NEW_NODE_BIN" || printf 'S1 FAILED\n' >>"$ROOT/live_compare_summary.md"
scenario_s2 "$ROOT/new-s2" "$NEW_NODE_BIN" || printf 'S2 FAILED\n' >>"$ROOT/live_compare_summary.md"
if awk -F'|' -v expected="$((2*RUNS))" '
    /^\| (old|new) / {
        rows++
        if ($3 !~ /VALID/) bad=1
        target=$4; gsub(/^[[:space:]]+|[[:space:]]+$/, "", target)
        tip=""
        for (i=7; i<=NF; i++) {
            if ($i !~ /node[0-3]:/) continue
            detail=$i
            h=detail; sub(/^.*h=/, "", h); sub(/[[:space:]].*$/, "", h)
            node_tip=detail; sub(/^.*tip=/, "", node_tip); sub(/[[:space:]].*$/, "", node_tip)
            if ((h+0) < (target+0) || detail !~ /panic=0/ || detail !~ /stale=0/ || detail !~ /exit=0/) bad=1
            if (tip == "") tip=node_tip; else if (tip != node_tip) bad=1
        }
    }
    /FAILED/ { bad=1 }
    END { if (rows != expected) bad=1; exit bad }
' "$ROOT/live_compare_summary.md"; then result=PASS; else result=FAIL; fi
printf '\nPASS/FAIL: %s (PASS requires every run to reach the target with identical tips, zero panics/stale-sync, and exit 0.)\n' "$result" >>"$ROOT/live_compare_summary.md"
printf 'Summary: %s\n' "$ROOT/live_compare_summary.md"
