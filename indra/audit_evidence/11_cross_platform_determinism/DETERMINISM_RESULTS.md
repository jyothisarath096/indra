# Q768 cross-platform determinism audit

## Classification: OPEN

The qualified `aarch64-apple-darwin` binary executed natively on a physical Apple M4. The two Linux matrix binaries were cross-compiled successfully, but neither executed in a native Linux environment. No Docker container, VM, cloud runner, or QEMU user-mode execution environment was available. QEMU system binaries were present, but no bootable qualified Linux guest was available and **no emulated run was performed or represented as native**. Under the required classification rule, the overall result is `OPEN`, not `PASS`.

## Corpus and output format

`corpus.json` is canonical compact JSON, schema `indra-q768-determinism-corpus`, version 1. It contains 10,202 cases: 10,000 deterministic xorshift64 cases using seed `494e4452412d5137`, 196 legal endpoint/threshold cases, and six invalid-domain/certificate cases. Legal coverage includes all required F endpoints, `w=1`, `w=W`, `w=W-1`, `W=1`, `200`, and `u64::MAX`, and exact outputs `T-1`, `T`, and `T+1` where representable.

Every successful result records fixed-width big-endian hex for the 96-byte Q768 log endpoints, 96-byte Q768 phi endpoints, four-byte interval width, 64-byte threshold, and 64-byte supplied output. Decimal strings encode the three u64 inputs. Errors use stable categories rather than platform-dependent display text.

Production `evaluate()` is authoritative. Its public API does not expose private phi endpoints, so the harness includes an audit-only exact arithmetic mirror of the private `phi` path. For every successful case it refuses to emit a record unless the mirror-derived threshold and width exactly equal production. This obtains the requested private endpoint evidence without modifying consensus code, but it is weaker than direct production instrumentation and is recorded as a residual audit assumption.

## Executed results

| Target | Execution | Cases | Result SHA-256 | Status |
|---|---:|---:|---|---|
| `aarch64-apple-darwin` | physical/native Apple M4 | 10,202 | `1c34146a3434d151bcfb5832ea3946da184259954adf228b05c69b9645cc2d37` | PASS for this target |
| `x86_64-unknown-linux-musl` | not executed | — | unavailable | OPEN |
| `aarch64-unknown-linux-musl` | not executed | — | unavailable | OPEN |

The macOS run returned the expected categories: `invalid_f` (2), `invalid_stake_domain` (3), and `inverted_interval` (1). All 10,196 legal evaluations succeeded. Maximum observed certificate width was 642 at `(F=1,w=18446744073709551614,W=18446744073709551615)`, below `2^24`.

The Linux binaries are retained as build evidence only through their hashes in the metadata files. They do not establish execution determinism.

## Toolchain and lock enforcement

`python3 scripts/check_consensus_build_policy.py` passed before the builds. Qualified builds used Rust/Cargo 1.93.1, LLVM 21.1.8, release mode, default features, empty `RUSTFLAGS`, target-default CPU/features, and `--locked`. The normative root lock hash is `5479dc079feaa81055de2a26ef585c9778b5257ace77d5e805229bc2679ab7b7`.

The standalone audit crate necessarily has a subset lockfile (`2fa5f97878d92192b5ec33344f07de90cc7906acb2dbc382f55afa09c9cb17bb`) because it is intentionally outside the shipping workspace. Both hashes are recorded. Its production path dependency points at the same checked-out `indra-core`; this audit does not qualify the standalone crate as a release binary.

Source revision was `b6404ccacc508d92a022f50ad1af3da4d4e31a02` with a pre-existing dirty worktree. The corpus hash is `065490d479dfc62cd310217c43814abe976c13d5a14ce2b925b68f11cb17d873`.

## NON-NORMATIVE CONTROL

Rust 1.96.0 / LLVM 22.1.2 executed the same corpus natively on the Apple M4. Its result SHA-256 was also `1c34146a3434d151bcfb5832ea3946da184259954adf228b05c69b9645cc2d37`; byte comparison passed. This does not expand the qualified matrix.

## Optimized no-FP inspection

Optimized `indra_core::sortition::{certified_log,mul,phi,evaluate}` assembly was emitted for all three target triples. The requested AArch64 and x86 floating-point arithmetic/conversion mnemonic searches returned zero matches. Exact assembly hashes and source are retained in `no-fp-*`; `no-fp-summary.txt` records the search.

The Q768 call path uses `num-bigint` integer operations only and contains no Q768-specific runtime dispatch. `cpufeatures` exists elsewhere in the dependency graph for cryptographic primitives, but the inspected sortition symbols do not call it. Therefore there was no second CPU-feature profile relevant to Q768 arithmetic.

## What remains to close OPEN

Run the already-built corpus with pinned, locally built release binaries on actual x86-64 Linux and AArch64 Linux hosts, record host metadata and binary hashes, and compare the three canonical result files with `compare.py`. Emulated results may be added as explicitly non-qualifying evidence but cannot close this item.
