# PQ VRF Residual Risk — Classical VRF Blast Radius

## 1. Status Statement

INDRA's proposer-election VRF is a classical ECVRF over Ristretto255/Curve25519, implemented in `indra-crypto/src/vrf.rs`. This is deliberate: there is currently no NIST-standardized post-quantum VRF construction. Replacing this with an unaudited bespoke PQ-VRF would create a larger cryptographic risk than using a well-understood classical primitive with a bounded and monitored failure mode.

This document is not a closure note. It is a standing risk-acceptance record for a known classical component inside an otherwise post-quantum-oriented stack.

## 2. Complete VRF/BLS Touchpoint Table

Scope searched: `indra-core`, `indra-crypto`, `indra-state`, `indra-consensus`, `indra-node`, `indra-rpc`, `indra-ffi`, `indra-cli`, `indra-storage`, `indra-network`, and `indra-bench`.

Search terms: `VrfKeypair`, `vrf_pk`, `VrfOutput`, `VrfProof`, `VrfElectionResult`, `vrf_verify`, `vrf_prove`, `vrf_sign`, `compute_proposer_vrf`, `derive_all_seeds`, `ed25519_seed`, `ml_dsa_seed`, `vrf_seed`, `bls_seed`, `BlsKeypair`, `BlsPublicKey`, `BlsSignature`, `bls_pk`, and `bls_`.

Result: 525 live-crate occurrences across 49 files. The table groups contiguous line hits by file while preserving every hit location.

Classification key:

- A: proposer-election core or crypto primitive implementation used for proposer election
- B: identity/registration/config/test/serialization metadata pass-through
- C: fund/custody/signature-critical use
- D: other / unclear

| File | Lines | Count | Class | Justification |
|---|---:|---:|---|---|
| `indra-bench/benches/full_bench.rs` | 19-21 | 3 | B | Benchmark wiring only. |
| `indra-bench/src/crypto_bench.rs` | 6, 9, 13, 81-82, 85, 93-94, 96, 98, 121-122, 127, 130-131, 157-158, 162-164 | 20 | A/B | Benchmarks VRF/BLS primitives; not live consensus or custody logic. |
| `indra-bench/src/fixtures.rs` | 16, 18, 94-95, 99-100 | 6 | B | Fixture seed/key material for benchmarks. |
| `indra-bench/src/lib.rs` | 12-13 | 2 | B | Benchmark module exports. |
| `indra-cli/src/bin/send.rs` | 68, 78, 111 | 3 | B | CLI loads key/config material; no VRF crypto decision. |
| `indra-cli/src/bin/stake.rs` | 70 | 1 | B | CLI staking key/config handling. |
| `indra-cli/src/bin/tx.rs` | 75, 105 | 2 | B | CLI transaction key/config handling; not VRF-based authorization. |
| `indra-cli/src/bin/wallet_scan.rs` | 42, 46, 121, 169, 195, 198 | 6 | B | Wallet/key handling; no VRF verification or funds authorization via VRF. |
| `indra-cli/src/genesis_cmd.rs` | 21-22, 40, 42, 84-85, 158-159, 230 | 9 | B | Genesis/config generation includes public VRF/BLS metadata. |
| `indra-cli/src/keygen.rs` | 23-24, 27-29, 35-36, 38, 56, 58, 69, 71, 73, 90-91, 94-96, 105-109, 123-127, 136-137, 139-141, 284-286, 288-289, 294, 296, 299-300, 310-311, 313-315, 331-334, 341, 344-346, 354, 357-359, 378-379, 403-404, 493-494, 516-518 | 68 | B | Key generation, display, file serialization, and tests. |
| `indra-cli/src/staking.rs` | 21 | 1 | B | Staking CLI type import / metadata. |
| `indra-cli/src/tx_builder.rs` | 54, 119, 121, 222, 287, 296, 557, 580, 599, 677, 679 | 11 | B | Transaction builder carries key/config material; no VRF unlock path. |
| `indra-cli/tests/cli.rs` | 47-48, 98-100 | 5 | B | CLI tests. |
| `indra-consensus/src/producer.rs` | 28, 30, 36, 42, 78, 92, 100, 216, 223, 226, 241-242, 249, 256, 274, 299, 329, 353 | 18 | A | Block proposal path computes proposer VRF proof/output and election hash. |
| `indra-consensus/src/proposer.rs` | 8-9, 21, 32, 34, 89, 103, 107, 125, 132, 195, 197, 214, 235, 247, 259, 261, 267, 283, 397, 408-409, 421, 442 | 24 | A | Proposer-election VRF selection and commit-reveal scoring. |
| `indra-consensus/tests/consensus.rs` | 19, 183, 197, 204 | 4 | A/B | Consensus tests for proposer/VRF behavior. |
| `indra-core/src/error.rs` | 162 | 1 | B | Error variant only. |
| `indra-core/src/lib.rs` | 38 | 1 | B | Module export. |
| `indra-core/src/types/staking.rs` | 124, 280, 287, 393, 524, 564, 590, 608 | 8 | B | Staking registration wire metadata includes VRF public key. |
| `indra-core/src/types/vrf_election.rs` | 151, 164, 262, 269 | 4 | A/B | Election-result structure and hash domain. |
| `indra-crypto/src/bls.rs` | 22, 26, 33, 38, 49-50, 54, 56, 64, 92, 127-128 | 12 | B/D | BLS primitive exists and is tested; no live consensus/custody use found. Reserved/dead surface, see section 4. |
| `indra-crypto/src/error.rs` | 55 | 1 | B | Error variant only. |
| `indra-crypto/src/lib.rs` | 19-20, 33, 37 | 4 | A/B | Exports VRF/BLS modules and types. |
| `indra-crypto/src/mnemonic.rs` | 26, 28, 30, 55-58, 61-63, 112-116, 152, 155-158, 165-166 | 22 | B | Domain-separated seed derivation for hybrid, VRF, and BLS keys. |
| `indra-crypto/src/vrf.rs` | 42, 46, 50, 56, 149, 185, 192, 195-196, 199, 224, 236, 245, 257-259, 265-267, 272-274, 279-281, 286-289, 294-295, 301-303, 309-311 | 37 | A | Classical ECVRF implementation and tests. |
| `indra-crypto/tests/audit_phase1.rs` | 8, 11, 15, 53 | 4 | A/B | Crypto audit regression tests. |
| `indra-ffi/include/indra.h` | 48-49, 137 | 3 | B | FFI key structure/header declarations. |
| `indra-ffi/src/keygen.rs` | 2, 11, 15-17, 50, 52-53 | 8 | B | FFI key generation/export metadata. |
| `indra-ffi/src/lib.rs` | 82-83, 95-96, 672-674, 676, 680, 684, 695-696, 709-710, 717-718 | 16 | B | FFI key material handling and tests. |
| `indra-ffi/src/staking.rs` | 149, 161, 167, 185, 625, 634 | 6 | B | FFI staking registration carries VRF public key. |
| `indra-ffi/src/tx.rs` | 31, 39, 44 | 3 | B | FFI transaction/key handling; no VRF authorization. |
| `indra-node/src/bin/node.rs` | 1342-1344, 1841, 1844, 1963, 1966, 2687-2689 | 10 | A/B | Node startup/config and VRF consensus message routing. |
| `indra-node/src/config.rs` | 30, 34, 85-86, 108-109, 134-135 | 8 | B | Validator config carries VRF/BLS seeds. |
| `indra-node/src/config_file.rs` | 20, 22, 24, 208, 214-216, 233-234, 317-319 | 12 | B | Config-file parsing/serialization. |
| `indra-node/src/driver.rs` | 15, 34, 39, 119, 768, 838, 843, 887, 953, 959-960, 963, 1109, 1271, 2454, 2731, 2841, 2853, 2880, 2885, 2894, 2912, 2919, 2923, 2972, 2979-2980, 3046, 3048, 3061, 3068, 3075, 3115-3116, 3118, 3136, 3558-3559, 3561, 3625-3626, 3628, 3676-3677, 3679, 5121, 5179, 5449-5450, 5452 | 50 | A | Live consensus VRF commit/reveal, election result storage, and tests. |
| `indra-node/src/engine.rs` | 20, 35, 39, 86, 174, 185, 192, 197, 467, 475, 566, 576, 728, 1007, 1018, 1040, 1044, 1208, 1210, 1223, 1230, 1237, 1365, 1368, 1693, 1697, 1731, 1759, 1787-1788, 1797, 1828, 1845, 1847 | 34 | A/B | Engine stores VRF keypair for local proposer election; config/tests. |
| `indra-node/src/genesis.rs` | 187 | 1 | B | Genesis validation/metadata. |
| `indra-node/src/sync.rs` | 24, 26, 320, 322, 353-354, 358, 390, 398, 562, 577, 603, 613, 638, 640, 659, 676, 683, 690, 1179, 1181 | 21 | A | Sync/replay verifies proposer-election VRF and election-result consistency only. |
| `indra-node/tests/node.rs` | 23, 63, 65, 78-79, 83, 86, 93, 147, 159, 182, 192, 214, 218, 273 | 15 | A/B | Node tests and fixtures. |
| `indra-rpc/src/handlers.rs` | 1520, 1542 | 2 | B | RPC tests/fixtures; no VRF-sensitive public method found. |
| `indra-state/src/apply.rs` | 52, 57-58, 420, 428, 453-454, 459-460, 1078, 1130, 1160, 2061, 2075, 2118 | 15 | A/B | Block proposer verification plus fixed slash-reporter candidate-search tests. Legacy pre-commit-reveal fallback is unreachable with current height-0 activation. |
| `indra-state/src/delegation.rs` | 133, 140, 255, 290, 292, 343, 973, 1289, 2001, 2007, 2017-2018, 2044, 2056, 2081, 2111, 2142, 2157, 2181, 2193, 2205, 2233, 2245, 2285, 2297, 2337, 2349 | 27 | B | Validator registration stores/checks VRF public key uniqueness; no funds unlocked by VRF. |
| `indra-state/src/epoch.rs` | 924 | 1 | B | Test/metadata fixture. |
| `indra-state/src/governance_apply.rs` | 698 | 1 | B | Test/metadata fixture. |
| `indra-state/src/state_root.rs` | 89-90 | 2 | B | State root includes validator metadata including VRF key. |
| `indra-state/src/validator.rs` | 89, 136-137, 178, 301, 342, 589, 620-621 | 9 | B | Validator metadata storage/indexing. |
| `indra-state/tests/monetary_invariants.rs` | 100 | 1 | B | Test fixture. |
| `indra-state/tests/state_machine.rs` | 92, 263 | 2 | B | Test fixture. |
| `indra-storage/src/state_store.rs` | 735 | 1 | B | Snapshot/load test fixture. |

Additional non-live artifacts also contain VRF/BLS strings: prior audit/design docs, `genesis.toml`, `genesis.toml.example`, `releases/genesis.toml`, `keys_new.json`, and historical `setup_indra_phase*.sh` scaffolding. These are configuration/documentation/setup artifacts, not live state-transition code. They do not introduce a separate cryptographic use.

Category C result after this task: zero live commit-reveal-active VRF uses remain in fund/custody/reward-routing decisions.

The stopped audit originally found one Category C-adjacent path:

- `indra-state/src/apply.rs::slash_reporter_validator_id_for_block` used `proposer_id_from_vrf_proof`, which called `vrf_verify`, to recover proposer identity for slash-reporter reward routing.

That dependency has now been removed for the commit-reveal-active path. The function recovers the proposer by bounded candidate search against `block.header.election_result_hash`, which is included in the finalized block hash and therefore attested by the block QC's ML-DSA-87 signatures.

## 3. Key-Derivation Independence

Verified at construction level in `indra-crypto/src/mnemonic.rs`.

`derive_all_seeds(master_seed)` derives:

- `ed25519_seed = derive_seed(master_seed, b"indra-ed25519-v1")`
- `ml_dsa_seed = derive_seed(master_seed, b"indra-ml-dsa-v1")`
- `vrf_seed = derive_seed(master_seed, b"indra-vrf-v1")`
- `bls_seed = derive_seed(master_seed, b"indra-bls-v1")`

`derive_seed` uses HMAC-SHA256 keyed by the 32-byte master seed, with the role-specific byte string as the HMAC message/domain separator. The three outputs are therefore domain-separated derivations from the common master seed. The existing tests additionally confirm deterministic output and pairwise inequality for tested vectors, but the primary conclusion here comes from the construction: separate HMAC domains prevent direct key reuse between hybrid signing, VRF, and BLS material.

Conclusion: compromise or future cryptanalytic break of the VRF secret key does not imply compromise of the hybrid signing key or BLS seed by key-derivation reuse.

## 4. BLS Seed Finding

`derive_all_seeds` produces a `bls_seed`, and the workspace contains a BLS module plus key/config serialization paths. The audit found no live consensus, transaction, staking, governance, sync, or reward path that depends on a BLS signature for safety or custody.

Observed BLS locations are:

- `indra-crypto/src/bls.rs`: BLS primitive implementation and tests.
- `indra-cli/src/keygen.rs`, `indra-ffi/src/*`, `indra-node/src/config*.rs`, `genesis*.toml`: key generation/config plumbing.
- `indra-bench/*`: benchmarks and fixtures.

Status: BLS is currently reserved/dead key material, not a live attack surface. It should remain documented because key files/configs may carry this seed even though active protocol safety does not depend on it.

## 5. Concrete Classical-VRF Blast Radius

If a future cryptographically relevant quantum computer breaks Curve25519/Ristretto255 discrete log, the attacker may be able to:

1. Recover or forge VRF secret-key behavior for a validator VRF public key.
2. Predict that validator's future VRF outputs/proofs for proposer-election inputs.
3. Forge valid-looking VRF proofs for proposer-election verification where the verifier only checks the classical VRF relation.
4. Bias or manipulate live proposer-election participation for compromised/forged VRF identities, subject to the rest of the consensus protocol accepting the surrounding block/vote signatures.

The attacker cannot, from this VRF break alone:

1. Forge ML-DSA-87 hybrid block, vote, transaction, staking, or governance signatures.
2. Unlock UTXOs.
3. Authorize staking bonds, unbonding, delegations, or governance operations.
4. Redirect slash-reporter rewards in the commit-reveal-active path, because reward routing now recovers proposer identity from the QC-attested `election_result_hash` instead of live VRF verification.
5. Derive the hybrid signing seed from the VRF seed via key-schedule reuse, because seed derivation is domain-separated.

Worst-case bounded impact: live proposer-election manipulation and liveness/censorship pressure. A VRF break can help an attacker predict or forge proposer-election proofs, which may let them target winning proposers earlier, bias proposer selection for identities they can otherwise operate, or create invalid proposer-election material that honest nodes must reject. It does not by itself move funds or bypass the post-quantum signature checks that authorize blocks, votes, transactions, staking, governance, or finalized reward routing.

## 6. Sync and Replay Confirmation

`indra-node/src/sync.rs` uses VRF verification for proposer-election validity during block intake/replay and verifies commit-reveal election-result consistency. No sync or restart-replay path was found that uses VRF material to authorize funds, mutate custody state, release staking bonds, compute rewards, or bypass hybrid signatures.

The sync/replay blast radius is therefore the same as live consensus: classical VRF affects proposer-election validity checks, not custody or signature authorization.

## 7. Slash-Reporter Reward Routing Fix

Before this task, slash-reporter reward routing had a reward-adjacent dependency on live classical VRF verification:

1. `slash_reporter_pubkey_for_block`
2. `slash_reporter_validator_id_for_block`
3. `proposer_id_from_vrf_proof`
4. `vrf_verify`

The active commit-reveal path now uses:

1. `block.header.election_result_hash`
2. all active validator IDs as a bounded candidate set
3. `VrfElectionResult::hash()` recomputed for normal and fallback candidates
4. uniqueness requirement: exactly one candidate must match

This is behavior-preserving for valid blocks but removes live VRF verification from the reward-routing decision. The authoritative value is now the already-finalized, QC-attested election result hash.

Fallback branch reachability:

- `VRF_COMMIT_REVEAL_ELECTION_HEIGHT = 0`
- `vrf_commit_reveal_election_active(height)` returns `height >= VRF_COMMIT_REVEAL_ELECTION_HEIGHT`

Therefore the non-commit-reveal fallback branch is dead code for the current chain configuration. It is retained only for alternate/future configurations where pre-commit-reveal blocks might exist. If such a configuration is ever used, that narrow legacy branch would still rely on live VRF proof verification for slash-reporter proposer recovery and must be reviewed as a residual item before launch.

## 8. Migration Trigger and Standing Review Item

This accepted risk must be revisited when either condition becomes true:

1. A NIST-standardized or broadly peer-reviewed and adopted post-quantum VRF construction becomes available.
2. Credible cryptanalytic timeline estimates for cryptographically relevant quantum computers materially shorten.

This is a standing item for every future security audit phase. It is not a one-time note.

## 9. Explicit Risk Status

This is not resolved or closed. INDRA still uses a classical VRF for live proposer election because no standardized PQ replacement exists today.

The risk is accepted, bounded, and monitored. After this task, the confirmed live blast radius is limited to proposer-election behavior and sync/replay proposer-election verification. A previously discovered reward-routing dependency on live VRF verification was removed for the active commit-reveal path.
