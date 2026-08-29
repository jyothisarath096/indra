#!/bin/sh
set -eu
cd "$(dirname "$0")/../.."
python3 scripts/check_consensus_build_policy.py
cargo run --release --locked --manifest-path audit_evidence/11_cross_platform_determinism/Cargo.toml -- generate audit_evidence/11_cross_platform_determinism/corpus.json
cargo run --release --locked --manifest-path audit_evidence/11_cross_platform_determinism/Cargo.toml -- run audit_evidence/11_cross_platform_determinism/corpus.json audit_evidence/11_cross_platform_determinism/results-$(rustc -vV | awk '/^host:/ {print $2}').json

# On each Linux target, build locally with the pinned toolchain and then run:
# ./indra-q768-determinism run corpus.json results-<target>.json
# Copy the result back and compare all three only after actual execution:
# python3 compare.py results-aarch64-apple-darwin.json results-x86_64-unknown-linux-musl.json results-aarch64-unknown-linux-musl.json
