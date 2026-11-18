# INDEX_2 inventory

This inventory covers the implementation pass run from `/Users/bonkai/Desktop/indra/project_indra/indra` on 18 November 2026. Existing unrelated dirty files and audit artifacts were preserved.

## Indexing diagnostics

| crate | command result | remaining production diagnostics | log |
|---|---|---:|---|
| `indra-network` | PASS | 0 | `/tmp/index2_network_after.log` |
| `indra-rpc` | PASS | 0 | `/tmp/index2_rpc_after.log` |
| `indra-node` | measured only | 7 | `/tmp/index2_count_indra-node.log` |
| `indra-cli` | measured only | 2 | `/tmp/index2_count_indra-cli.log` |
| `indra-ffi` | measured only | 8 | `/tmp/index2_count_indra-ffi.log` |

Network fixes cover `dandelion.rs`, `handshake.rs`, `message.rs`, `policy.rs`, and `transport.rs`. RPC fixes cover `handlers.rs`. The crate roots now deny `clippy::indexing_slicing` for non-test builds.

## Remaining indexing locations

- `indra-node`: `src/sync.rs` (3), `src/config_file.rs` (2), `src/metrics.rs` (1), `src/hardened_read_rpc.rs` (1).
- `indra-cli`: `src/rpc_client.rs` (2).
- `indra-ffi`: `src/lib.rs` (6), `src/staking.rs` (2).

These were measured and deliberately not changed because INDEX_2 scoped the implementation pass to network and RPC.

## Suppression inventory after the pass

The source search was:

```text
rg -n '#!?[[:space:]]*\\[(allow|expect|cfg_attr\\([^]]*allow)' --glob '*.rs' . --glob '!audit_evidence/**'
```

The only remaining matches are crate-root `cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))` in the CLI and node test binaries. No production `#[allow]` or `#[expect]` attributes remain. The former `too_many_arguments` attributes in authorization, block hashing, snapshot-root computation, observer RPC, RPC state construction, and staking confirmation paths were removed by grouping inputs into named structs. State dead-code attributes were removed.

The new `scripts/check_no_lint_allows.sh` has no per-file allowlist. It accepts only test/bench paths and the explicit crate-root test `cfg_attr` form. Its blind spot is attributes synthesized by macros.

## Configuration/lint search

The requested repository search covered `Cargo.toml`, `.cargo/config*`, `clippy.toml`, `rust-toolchain*`, and CI files for lowered lint levels and `cap-lints`. No new lowering or `cap-lints` setting was found during this pass.
