#!/usr/bin/env bash
set -euo pipefail

source_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$source_root"

# This guard intentionally checks source locations rather than maintaining a
# file allowlist. Macros can synthesize attributes and are a documented blind
# spot; ordinary source attributes must remain in test-only code.
if command -v rg >/dev/null 2>&1; then
    matches=$(rg -n '#!?(\[allow|\[expect|\[cfg_attr\([^]]*allow)' \
        --glob '*.rs' . --glob '!audit_evidence/**' || true)
else
    matches=$(grep -RInE '#!?\[(allow|expect|cfg_attr\([^]]*allow)' . \
        --include='*.rs' --exclude-dir=audit_evidence || true)
fi

violations=0
while IFS= read -r match; do
    [[ -z "$match" ]] && continue
    file=${match%%:*}
    rest=${match#*:}
    line=${rest%%:*}
    text=${rest#*:}
    if [[ "$file" == *"/tests/"* || "$file" == *"/benches/"* ]]; then
        continue
    fi
    if [[ "$text" == *'#![cfg_attr(test, allow('* ]]; then
        continue
    fi
    printf 'unreviewed lint suppression: %s:%s:%s\n' "$file" "$line" "$text"
    violations=$((violations + 1))
done <<< "$matches"

if ((violations != 0)); then
    exit 1
fi
