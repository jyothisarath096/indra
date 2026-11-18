#!/usr/bin/env bash
set -euo pipefail

# Reviewed exceptions are kept at file granularity because generated/test-only
# attributes are intentionally local to their target and this guard is meant to
# catch newly introduced suppressions, not replace code review.
allowed_files=(
  indra-cli/src/bin/genesis.rs
  indra-cli/src/bin/governance.rs
  indra-cli/src/bin/keygen.rs
  indra-cli/src/bin/send.rs
  indra-cli/src/bin/stake.rs
  indra-cli/src/bin/tx.rs
  indra-cli/src/bin/wallet_scan.rs
  indra-core/src/types/authorization.rs
  indra-core/src/types/block.rs
  indra-core/src/types/consensus_snapshot.rs
  indra-node/src/bin/audit_block_log.rs
  indra-node/src/bin/dns_seed_sign.rs
  indra-node/src/bin/indra-sync-recover.rs
  indra-node/src/bin/node.rs
  indra-node/src/bin/observer.rs
  indra-node/src/hardened_read_rpc.rs
  indra-rpc/src/handlers.rs
  indra-state/src/chain.rs
  indra-state/src/effects.rs
  indra-state/src/txn.rs
)

is_allowed() {
  local candidate=$1
  for allowed in "${allowed_files[@]}"; do
    [[ "$candidate" == "indra/$allowed" ]] && return 0
  done
  return 1
}

violations=0
while IFS=: read -r file line _; do
  [[ -z "$file" ]] && continue
  if ! is_allowed "$file"; then
    printf 'unreviewed lint suppression: %s:%s\n' "$file" "$line"
    violations=$((violations + 1))
  fi
done < <(rg -n '#!?\[(allow|expect|cfg_attr\([^]]*allow)' --glob '*.rs' indra --glob '!indra/audit_evidence/**' || true)

if ((violations != 0)); then
  exit 1
fi
