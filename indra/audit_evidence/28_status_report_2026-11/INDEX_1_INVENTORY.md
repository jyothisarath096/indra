# INDEX_1 inventory

This inventory was produced from `/Users/bonkai/Desktop/indra/project_indra/indra`. The per-crate command was:

```text
cargo clippy -p <crate> --lib --bins --no-deps -- -D clippy::indexing_slicing
```

The logs remain outside the repository under `/tmp/index1_final_<crate>.log`.

## Production-target counts

| crate | indexing/slicing diagnostics after this pass | highest-count files still needing the next pass |
|---|---:|---|
| indra-crypto | 0 | none |
| indra-keystore | 0 | none |
| indra-storage | 0 | none |
| indra-network | 21 | `indra-network/src/handshake.rs` (8), `policy.rs` (7), `message.rs` (2), `dandelion.rs` (2), `transport.rs` (1) |
| indra-rpc | 11 | `indra-rpc/src/handlers.rs` (11) |
| indra-node | 7 | `indra-node/src/sync.rs` (3), `config_file.rs` (2), `metrics.rs` (1), `hardened_read_rpc.rs` (1) |
| indra-cli | 2 | `indra-cli/src/rpc_client.rs` (2) |
| indra-ffi | 8 | `indra-ffi/src/lib.rs` (6), `staking.rs` (2) |
| indra-bench | 0 | none |

The command was run for production libraries and binaries, not test targets. A zero count means that command exited successfully; a nonzero count is the number of `indexing may panic` or `slicing may panic` diagnostics in the corresponding `/tmp` log.

## Completed boundary fixes

The old `indra-crypto` sites were on externally reachable parsing surfaces: `PaymentAddressV1::decode` consumes address bytes and `vrf_verify` consumes a transmitted proof. The old code had length checks, so this pass did not reproduce a panic, but the static analyzer could not prove all bounds. The sites are now represented by checked ranges, iterators, or fixed-size conversions. The new malformed-input tests are `payment_address::tests::malformed_short_and_long_binary_addresses_return_errors` and `vrf::tests::truncated_vrf_proof_returns_typed_error`; both are in the touched source files.

| current file and line | indexed value | bound or replacement | classification |
|---|---|---|---|
| `indra/indra-crypto/src/payment_address.rs:70-159` | address version, chain length, chain ID, PQ length, checksum, classical/PQ key ranges | `first`, `get`, exact-length checks, and fixed-array conversion | external address bytes; fixed |
| `indra/indra-crypto/src/payment_address.rs:270-328` | base64 chunks and alphabet values | chunk iterators and checked alphabet lookup | internal encoder/decoder state; fixed |
| `indra/indra-crypto/src/vrf.rs:37-43,166-187` | SHA-512 halves and 80-byte proof components | split/checked ranges and exact proof length | external proof bytes at verification; fixed |
| `indra/indra-keystore/src/cold_shamir.rs:268-305` | secret/share limbs | exact chunks and iterator zips | decoded keystore/share bytes already length-validated; fixed |
| `indra/indra-keystore/src/cold_shamir.rs:350-378` | commitment, value, and blinding limbs | length check plus iterator zips | validated share structure; fixed |
| `indra/indra-keystore/src/cold_shamir.rs:390-479` | polynomial and generated-share limbs | iterator zips | internally constructed arrays/vectors; fixed |
| `indra/indra-keystore/src/cold_shamir.rs:550-595` | share-index bitmap, threshold basis, scalar limbs | checked bitmap access, checked basis range, chunks, split | share files are external but structural validation now returns errors; fixed |
| `indra/indra-storage/src/manifest.rs:145-184` | persistent manifest header and chain bytes | checked ranges after minimum-length validation | disk bytes; fixed |
| `indra/indra-storage/src/state_store.rs:145-201` | snapshot header and payload | checked ranges and typed corruption errors | disk bytes; fixed |
| `indra/indra-storage/src/state_store.rs:410-476` | snapshot metadata fields | checked ranges and exact-length validation | disk bytes; fixed |
| `indra/indra-storage/src/vote_safety.rs:165-184` | CRC and payload | checked suffix/payload ranges | disk bytes; fixed |

The keystore and storage diagnostic counts were 27 and 32 before their fixes (the attachment’s threshold therefore required full classification rather than the <=25 shortcut); all of their reported sites are covered by the rows above and their final production scans are zero.

## Remaining sites for the next ordered pass

The remaining network, RPC, node, CLI, and FFI sites are classified as follows from the diagnostic locations in the `/tmp` logs. They are not silently suppressed or changed in this pass.

| subsystem | locations | classification |
|---|---|---|
| network | `dandelion.rs:325,330`; `handshake.rs:184,189,209,211,213,225,227,229`; `message.rs:349,738`; `policy.rs:647,653,661,672,674,676`; `transport.rs:88,147` | peer/message bytes and transport framing; external or disk/peer inputs, next pass |
| RPC | `handlers.rs:802,806,809,823,898,899,1096,1097,1132,1133,2846` | RPC parameters and response/state collections; external request or serialized state paths, next pass |
| node | `config_file.rs:591,594`; `hardened_read_rpc.rs:563`; `metrics.rs:879`; `sync.rs:432,494` | config, observer/RPC and sync/network data; external or disk/peer inputs, next pass |
| CLI | `rpc_client.rs:240-241` | RPC response bytes; external network input, next pass |
| FFI | `staking.rs:109-110`; `lib.rs:314-315,610-611,639,669` | caller-provided C buffers and lengths; externally supplied FFI input, next pass |

## Lint-suppression inventory

The initial search command was:

```text
rg -n '#!?\[(allow|expect|cfg_attr\([^]]*allow)' --glob '*.rs' indra
```

Removed in this pass: `indra-cli/src/genesis_cmd.rs` and `indra-bench/src/lib.rs` module-level `missing_docs`, `indra-cli/src/rpc_client.rs:89` `unused_mut`, and the dead marker/allow in `indra-node/src/audit_harness.rs`. The remaining attributes are in a reviewed file allowlist enforced by `indra/scripts/check_no_lint_allows.sh`; they are test-only panic/unwrap allowances, test-only dead-code helpers, or argument-shape allowances whose signatures preserve existing APIs. The script’s blind spots are that it is file-granular, does not judge whether a listed exception is still justified, and does not inspect non-Rust lint configuration beyond the source search.
