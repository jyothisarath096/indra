#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
required=(
  'unused_must_use'
  'clippy::unwrap_used'
  'clippy::expect_used'
  'clippy::panic'
  'clippy::indexing_slicing'
  'clippy::unreachable'
  'clippy::todo'
  'clippy::unimplemented'
)

status=0
while IFS= read -r file; do
  for lint in "${required[@]}"; do
    if ! grep -Fq "$lint" "$file" || ! grep -Eq '#!\[.*deny|#!\[cfg_attr' "$file"; then
      printf 'missing canonical deny %s: %s\n' "$lint" "$file"
      status=1
    fi
  done
done < <(
  find "$root" -path '*/target' -prune -o -path '*/audit_evidence' -prune -o -path "$root/fuzz" -prune -o \
    \( -path '*/src/lib.rs' -o -path '*/src/bin/*.rs' -o -path '*/benches/*.rs' \) -type f -print | sort
)
exit "$status"
