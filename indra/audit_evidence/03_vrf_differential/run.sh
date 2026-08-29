#!/bin/sh
set -eu

REFERENCE_REPOSITORY=https://github.com/reyzin/ecvrf.git
REFERENCE_COMMIT=917883bc5fa4dfb069bc40ed7cf8ba5d988bedf1
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORK_DIR=${TMPDIR:-/tmp}/indra-vrf-differential-$REFERENCE_COMMIT
REFERENCE_DIR=$WORK_DIR/ecvrf
REFERENCE_CLI=$WORK_DIR/reference_cli

mkdir -p "$WORK_DIR"
if [ ! -d "$REFERENCE_DIR/.git" ]; then
    git clone "$REFERENCE_REPOSITORY" "$REFERENCE_DIR"
fi
git -C "$REFERENCE_DIR" fetch --quiet origin "$REFERENCE_COMMIT"
git -C "$REFERENCE_DIR" checkout --quiet --detach "$REFERENCE_COMMIT"
test "$(git -C "$REFERENCE_DIR" rev-parse HEAD)" = "$REFERENCE_COMMIT"

CXX=${CXX:-c++}
HOMEBREW_PREFIX=${HOMEBREW_PREFIX:-/opt/homebrew}
"$CXX" -std=c++11 -O2 \
    -I"$REFERENCE_DIR" -I"$HOMEBREW_PREFIX/include" \
    "$SCRIPT_DIR/reference_cli.cpp" "$REFERENCE_DIR/sha512.c" \
    -L"$HOMEBREW_PREFIX/lib" -lntl -lgmp \
    -o "$REFERENCE_CLI"

printf 'reference_repository=%s\n' "$REFERENCE_REPOSITORY"
printf 'reference_commit=%s\n' "$(git -C "$REFERENCE_DIR" rev-parse HEAD)"
printf 'indra_commit=%s\n' "$(git -C "$SCRIPT_DIR/../.." rev-parse HEAD)"
printf 'indra_vrf_source_sha256=%s\n' "$(shasum -a 256 "$SCRIPT_DIR/../../indra-crypto/src/vrf.rs" | awk '{print $1}')"
cargo run --release --manifest-path "$SCRIPT_DIR/harness/Cargo.toml" -- "$REFERENCE_CLI"
