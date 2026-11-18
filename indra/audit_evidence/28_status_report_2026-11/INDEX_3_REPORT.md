# Index 3 implementation report

Difference found: the Index 3 token boundary was previously represented by two interchangeable `String` values; the current tree now uses distinct `AdminToken` and `AccessToken` types with constant-time byte comparison in `indra-node/src/bin/node.rs:4959-4983`. The current tree also has a real listener test and a supervisor report-count seam. The earlier Index 2 network/RPC indexing hardening is present in HEAD; its old/new behavior was checked below. The actual `fc1d3e02..HEAD` source diff contains 20 network slice-index replacements and 11 RPC argument/nibble sites; it does not contain 21 network replacements, so that contextual count is not reproduced as a fact.

Unfinished at report time: the replay-filtered node command was still running the long `startup_fails_on_snapshot_replay_gap` test when this report was assembled. No process was interrupted. A full byte-for-byte harness covering every complex network message variant was not added; the repository's all-variant round-trip test was run at both revisions instead.

## 1. Old/new A: crypto, VRF, Shamir, and storage

The comparison used detached worktree `fc1d3e02` and current HEAD, with separate temporary harnesses and fixed inputs. The commands and result files were:

| Area | Command/result | Result |
|---|---|---|
| Payment address and VRF | current and `fc1d3e02` harnesses, then `diff -u /tmp/indra-index3-old-crypto.out /tmp/indra-index3-current-crypto.out` | Empty diff; address encode/decode, malformed address classes, VRF proof/output/verification, and malformed VRF cases matched. |
| Shamir/cold-key ceremony | current and `fc1d3e02` harnesses, then `diff -u /tmp/indra-index3-old-shamir.out /tmp/indra-index3-current-shamir.out` | Empty diff for fixed-RNG generation, recovery, manifest/share serialization, and malformed cases. |
| Storage | current and `fc1d3e02` harnesses, then `diff -u /tmp/indra-index3-old-storage.out /tmp/indra-index3-current-storage.out` | Empty diff for manifest, vote-safety, and snapshot serialization/error behavior. Both revisions returned the same post-gate snapshot error for the intentionally invalid fixture. |

The harness outputs are preserved at `/tmp/indra-index3-current-crypto.out`, `/tmp/indra-index3-old-crypto.out`, `/tmp/indra-index3-current-shamir.out`, `/tmp/indra-index3-old-shamir.out`, `/tmp/indra-index3-current-storage.out`, and `/tmp/indra-index3-old-storage.out`.

## 2. Old/new B: network and RPC

The network wire enum in `indra-network/src/message.rs:82-141` contains Block, Vote, Tx, TxStem, StakingOp, GovernanceOp, PeerList, Ping, Pong, RequestBlocks, BlockResponse, Status, RequestProposal, RequestQC, and QCResponse. The repository test `message_encode_decode_all_types` in `indra-network/tests/network.rs` was run at both revisions. The old detached worktree result is `/tmp/index3_old_b_network.log`; the current result is `/tmp/index3_network_integration.log`. Both ended with `4 passed; 0 failed; 0 ignored` and the all-variant test passed.

The RPC adversarial aggregate test `all_public_rpc_methods_reject_adversarial_parameter_corpus_without_panicking_or_leaking` in `indra-rpc/src/handlers.rs` was run at `c996c775` (`/tmp/index3_old_b_rpc.log`) and current HEAD (`/tmp/index3_current_b_rpc.log`). Both ended with `1 passed; 0 failed; 0 ignored`.

The Index 2 changes checked below replace former unchecked indexing with checked extraction and typed errors. The current tests cover truncated input, trailing bytes, declared-length mismatch, oversized peer-list counts, malformed handshake fields, and RPC adversarial parameters. The tests do not prove that every possible semantic input is accepted identically; they prove the listed malformed-input classes fail without a panic.

## 3. Former indexing sites and crafted external-input coverage

The source comparison command was:

```text
git diff --unified=0 fc1d3e02..HEAD -- indra-network/src indra-rpc/src/handlers.rs
```

The former production indexing sites are grouped by function and current location. The actual diff has 20 network sites:

| Current file:line | Function/site | External input or internal invariant |
|---|---|---|
| `indra-network/src/dandelion.rs:325` | `eligible.get(...)` | Internal eligible relay list; checked selection. |
| `indra-network/src/dandelion.rs:330` | `eligible.get(...)` | Internal eligible relay list; checked fallback selection. |
| `indra-network/src/handshake.rs:184` | `parse_common_prefix` | Peer handshake magic. |
| `indra-network/src/handshake.rs:189` | `parse_common_prefix` | Peer handshake version bytes. |
| `indra-network/src/handshake.rs:212` | `parse_step1` | Peer X25519 public-key field. |
| `indra-network/src/handshake.rs:216` | `parse_step1` | Peer ML-KEM encapsulation key. |
| `indra-network/src/handshake.rs:222` | `parse_step1` | Peer validator ID. |
| `indra-network/src/handshake.rs:238` | `parse_step2` | Peer X25519 public-key field. |
| `indra-network/src/handshake.rs:242` | `parse_step2` | Peer ML-KEM ciphertext. |
| `indra-network/src/handshake.rs:248` | `parse_step2` | Peer validator ID. |
| `indra-network/src/message.rs:349` | `Message::decode` | Network message payload after declared length. |
| `indra-network/src/message.rs:740` | status-message decoder | Network status round field. |
| `indra-network/src/policy.rs:647` | `decode_bans` | Persistent ban-store magic. |
| `indra-network/src/policy.rs:653` | `decode_bans` | Persistent ban-store version. |
| `indra-network/src/policy.rs:667` | `decode_bans` | Persistent ban-store count. |
| `indra-network/src/policy.rs:680` | `decode_bans` | Persistent ban-store entry region. |
| `indra-network/src/policy.rs:686` | `decode_bans` | Persistent ban-store validator ID. |
| `indra-network/src/policy.rs:690` | `decode_bans` | Persistent ban-store expiry. |
| `indra-network/src/transport.rs:88` | `Connection::read_frame` | Async read buffer length. |
| `indra-network/src/transport.rs:151` | `Connection::decode_frame` | Peer frame payload bounds. |

The remaining 11 RPC sites are:

| Current file:line | Function/site | External input |
|---|---|---|
| `indra-rpc/src/handlers.rs:821` | `get_canonical_blocks` | Optional scan authorization slice. |
| `indra-rpc/src/handlers.rs:830` | `get_canonical_blocks` | `from_height`. |
| `indra-rpc/src/handlers.rs:835` | `get_canonical_blocks` | `limit`. |
| `indra-rpc/src/handlers.rs:851` | `get_canonical_blocks` | `expected_parent_hash`. |
| `indra-rpc/src/handlers.rs:932` | `get_transaction` | height. |
| `indra-rpc/src/handlers.rs:935` | `get_transaction` | transaction index. |
| `indra-rpc/src/handlers.rs:1134` | `authorized_payment_address` | payment address. |
| `indra-rpc/src/handlers.rs:1138` | `authorized_payment_address` | scan authorization proof. |
| `indra-rpc/src/handlers.rs:1175` | `explain_utxo_provenance_authorized` | authorization parameter slice. |
| `indra-rpc/src/handlers.rs:1179` | `explain_utxo_provenance_authorized` | UTXO ID. |
| `indra-rpc/src/handlers.rs:2898` | `encode_nibble_path` | Compressed-proof nibble conversion. |

The RPC compressed-proof callers at `indra-rpc/src/handlers.rs:2826-2879` now propagate the `Result` from the nibble encoder. The RPC crafted-input aggregate named above exercises the public dispatch surface; the network malformed-input tests named in Section 2 exercise the peer-facing decoders. No source indexing change was made in this turn to the network or RPC crates; those changes are already in HEAD.

## 4. Token separation and real listener behavior

`AdminToken` and `AccessToken` are private, distinct tuple structs at `indra-node/src/bin/node.rs:4959-4973`. Their `matches` methods compare their byte slices using `subtle::ConstantTimeEq` at `indra-node/src/bin/node.rs:4967-4969` and `4980-4982`. `RpcListenerConfig` stores the two roles separately at `indra-node/src/bin/node.rs:4985-4993`; `RpcHandlerAuth` carries typed references at `indra-node/src/bin/node.rs:5575-5580`; the production configuration mapping constructs them separately at `indra-node/src/bin/node.rs:4162-4170`.

A temporary Rust type-check proof attempted to pass `AdminToken` to a function requiring `AccessToken`. `rustc /tmp/indra-index3-token-swap.rs` produced `error[E0308]: mismatched types ... expected AccessToken, found AdminToken`; the raw output is `/tmp/indra-index3-token-swap.err`. This is a temporary compiler proof, not a repository compile-fail test.

The unit wiring test is `rpc_token_wiring_keeps_admin_and_access_roles_distinct` at `indra-node/src/bin/node.rs:8058-8103`. The real HTTP listener test is `real_rpc_listener_keeps_admin_and_access_tokens_separate` at `indra-node/src/bin/node.rs:8105-8188`. It starts `spawn_rpc_listener` at `8137`, configures `admin-A` and `access-B` at `8144-8145`, rejects `access-B` in the admin header at `8178-8179`, accepts `admin-A` at `8180-8181`, rejects missing full-RPC access at `8182-8183`, and accepts a read-only height request with `access-B` at `8184-8185`. This is an in-process listener bound to an ephemeral loopback socket, not a multi-machine deployment test.

## 5. Supervisor report seam

`report_unexpected` increments the process-local counter at `indra-node/src/supervisor.rs:140-148`; `reset_report_count` and `report_count` are at `150-158`. The test `rpc_transaction_relay_cache_poison_returns_typed_internal_error` resets the count and asserts exactly one report at `indra-node/src/bin/node.rs:8190-8205`. This seam is a production API addition solely to make the report count observable; it does not alter consensus or RPC behavior.

## 6. Verification

The following commands were run from `/Users/bonkai/Desktop/indra/project_indra/indra`.

| Check | Result and raw-output location |
|---|---|
| `cargo check --workspace --all-targets` | PASS; final line `Finished dev profile [unoptimized + debuginfo] target(s) in 9.97s`; `/tmp/index3_workspace_check.log`. |
| strict debug clippy | PASS; `DEBUG_CLIPPY_EXIT=0`; `/tmp/index3_clippy_debug.log`. |
| strict release clippy | PASS; `RELEASE_CLIPPY_EXIT=0`; `/tmp/index3_clippy_release.log`. |
| lint script | PASS; `SCRIPT_EXIT=0`; `/tmp/index3_lint_guard_script.log`. |
| `cargo test -p indra-core --test lint_guard` | PASS, `1 passed; 0 failed; 0 ignored`; `/tmp/index3_lint_guard_test.log`. |
| affected debug tests | PASS: crypto `40/0/0`, keystore `22/0/0`, storage `48/0/1`, network `158/0/1`, RPC `69/0/0`, node binary `96/0/0`; logs `/tmp/index3_crypto_debug.log`, `/tmp/index3_keystore_debug.log`, `/tmp/index3_storage_debug.log`, `/tmp/index3_network_debug.log`, `/tmp/index3_rpc_debug.log`, `/tmp/index3_node_bin_debug.log`. |
| release workspace tests | PASS; all targets completed with zero failures; node library `344 passed; 0 failed; 5 ignored`, network `158 passed; 0 failed; 1 ignored`, state `342 passed; 0 failed; 3 ignored`, storage `48 passed; 0 failed; 1 ignored`; `/tmp/index3_workspace_release.log`. |
| `cargo audit` | PASS, `advisories ok`; `/tmp/index3_audit.log`. |
| `cargo deny check` | PASS, final categories `advisories ok, bans ok, licenses ok, sources ok`; duplicate-package messages are warnings in `/tmp/index3_deny.log`. |
| golden vector | PASS, `1 passed; 0 failed`; `/tmp/index3_golden.log`. |
| core vector filter | Command completed with `0 passed; 0 failed; 0 ignored; 154 filtered out`; `/tmp/index3_core_vector.log`. No matching test name existed for that filter, so this is not evidence that an RFC vector test ran. |
| network integration | PASS, `4 passed; 0 failed; 0 ignored`; `/tmp/index3_network_integration.log`. |
| replay-filtered node tests | RUNNING when report assembly began; `/tmp/index3_replay.log`. The command was not interrupted and no final result is claimed here. |

The current node binary test command, including the new real listener test, completed with `96 passed; 0 failed; 0 ignored` in `/tmp/index3_node_bin_debug.log`. The current and old B network/RPC comparison logs are listed in Section 2.

## 7. Diff and resource state

The intentional source diff for this Index 3 turn is grouped by crate:

```text
indra-node/src/bin/node.rs   169 lines changed
indra-node/src/supervisor.rs 14 lines changed
```

The report itself is a new untracked file. Existing untracked audit reports and existing user changes were not modified. No network or RPC source file was changed by this turn.

The final filesystem check captured during this task was:

```text
Filesystem      Size  Used Avail Capacity iused ifree %iused  Mounted on
/dev/disk3s5    228Gi 189Gi 15Gi 93%      2.0M 152M 1%      /System/Volumes/Data
```

The source changes are limited to typed RPC token wiring and the supervisor counting seam. They do not change consensus rules, wire encodings, storage formats, or token values. The long replay-filtered test remains an explicitly unfinished verification item until its log receives a terminal result.
