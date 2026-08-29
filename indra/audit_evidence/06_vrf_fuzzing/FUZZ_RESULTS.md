# INDRA VRF primitive fuzzing

Date: 2026-08-18

INDRA base commit: `b6404ccacc508d92a022f50ad1af3da4d4e31a02`

Toolchain:

- `cargo-fuzz 0.13.2`
- `rustc 1.100.0-nightly (67854e511 2026-08-15)`
- libFuzzer with AddressSanitizer, aarch64-apple-darwin

## Targets and invariants

| Target | Invariant |
|---|---|
| `vrf_verify_arbitrary` | Arbitrary public keys, alpha, beta, and proof bytes never panic; malformed values fail closed. Alpha is capped at 4,096 bytes and the total input at 8,192 bytes. |
| `vrf_valid_proof_mutation` | A generated proof verifies; a guaranteed bit mutation of the public key, alpha, beta, Gamma, challenge, or scalar is rejected. |
| `vrf_public_key_validation` | Arbitrary 32-byte encodings never panic; accepted points decompress, re-encode byte-identically, are nonidentity, and are torsion-free. |
| `vrf_prove_verify_roundtrip` | Deterministic seed/alpha proving never panics, verifies, and is byte-identical on repetition. Alpha is capped at 4,096 bytes. |
| `vrf_proof_framing` | Every proof whose length is not exactly the RFC 9381 ELL2 length of 80 bytes is rejected without panic. |

## Deterministic seed corpus

`cargo run --manifest-path fuzz/Cargo.toml --bin seed_corpora` regenerates the corpus. It includes all three RFC 9381 ELL2 seeds and alphas, locally generated valid proofs and outputs, mutations of each bound proof component, proof lengths 79 and 81, a noncanonical scalar equal to the group order, identity and all eight Dalek torsion points, and a noncanonical identity encoding. Initial deterministic seed counts were 12 verification, 18 mutation, 13 public-key, 3 round-trip, and 12 framing inputs. libFuzzer retained additional coverage-increasing inputs during the campaigns.

## Campaign results

All commands were run from the workspace root.

| Target | Executions | Time | Average exec/s | Peak RSS | Result |
|---|---:|---:|---:|---:|---|
| `vrf_verify_arbitrary` | 100,000 | 16 s | 6,250 | 79 MB | PASS — no crash or panic |
| `vrf_valid_proof_mutation` | 100,000 | 166 s | 602 | 86 MB | PASS — no crash, panic, or invariant failure |
| `vrf_public_key_validation` | 100,000 | 4 s | 25,000 | 45 MB | PASS — no crash, panic, or invariant failure |
| `vrf_prove_verify_roundtrip` | 100,000 | 175 s | 571 | 81 MB | PASS — no crash, panic, or invariant failure |
| `vrf_proof_framing` | 100,000 | 92 s | 1,086 | 89 MB | PASS — no crash, panic, or unexpected acceptance |

Commands:

```sh
cargo +nightly fuzz run vrf_verify_arbitrary fuzz/corpus/vrf_verify_arbitrary -- -runs=100000 -max_len=8192 -timeout=10 -print_final_stats=1
cargo +nightly fuzz run vrf_valid_proof_mutation fuzz/corpus/vrf_valid_proof_mutation -- -runs=100000 -max_len=4129 -timeout=10 -print_final_stats=1
cargo +nightly fuzz run vrf_public_key_validation fuzz/corpus/vrf_public_key_validation -- -runs=100000 -max_len=32 -timeout=10 -print_final_stats=1
cargo +nightly fuzz run vrf_prove_verify_roundtrip fuzz/corpus/vrf_prove_verify_roundtrip -- -runs=100000 -max_len=4128 -timeout=10 -print_final_stats=1
cargo +nightly fuzz run vrf_proof_framing fuzz/corpus/vrf_proof_framing -- -runs=100000 -max_len=8192 -timeout=10 -print_final_stats=1
```

No crash artifacts were produced. No production VRF defect was discovered, and production VRF code was not changed by this work.
