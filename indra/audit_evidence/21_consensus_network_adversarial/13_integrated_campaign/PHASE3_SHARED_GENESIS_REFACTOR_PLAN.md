# Shared-genesis fixture refactor plan (design only)

## Source map

- `local_driver`: `indra-node/src/driver.rs:2668-2778`.
- `seal_test_genesis_fixture`: `indra-node/src/genesis.rs:324-350`.
- `NodeConfig`: `indra-node/src/config.rs:16-158`; `NodeConfig::local_test`:
  `indra-node/src/config.rs:162-230`.
- `NodeEngine::init`: invoked by `local_driver` at
  `indra-node/src/driver.rs:2731` and again after entropy sealing at
  `indra-node/src/driver.rs:2770`.
- `VoteSafetyStore::open`: `indra-node/src/driver.rs:2732` and `2771`.
- `ConsensusDriver::new`: `indra-node/src/driver.rs:2733` and `2772`.

## Ownership

Shared across nodes: sealed genesis bytes, genesis precommit hash, validator
records, chain configuration, derived authority and consensus snapshot roots.
Node-local: hot/PQ/VRF/cold secret material, selected validator identity,
`NodeConfig`, data directory, `NodeEngine`, `ConsensusDriver`, and
`VoteSafetyStore` path.

## Coupling

`local_driver` generates one hot/PQ/VRF/cold key set, derives one hybrid
identity, renders one `[[validators]]` record, seals that manifest, and binds the
same seed into `NodeConfig`. This couples genesis authority membership to the
local node identity.

## NodeConfig findings

Two `NodeConfig` values can reference the same `genesis_path`; local secret
selection is independent through `validator_seed`, `vrf_seed`, `pq_seed`, and
`pq_pk`. `NodeEngine` derives authority from the manifest and validates local
key material against the selected validator record. Secret keys are not embedded
in the sealed manifest.

## Minimum implementation plan (not applied)

1. Extract deterministic key/proof generation into `TestValidatorMaterial`.
2. Extract rendering of a validator TOML record.
3. Add `SharedGenesisFixture` that renders all records, calls
   `seal_test_genesis_fixture`, and stores the sealed path/metadata.
4. Add a per-node constructor that clones `NodeConfig::local_test`, points it at
   the shared manifest, sets that validator's seeds/public key, and assigns a
   unique data directory.
5. Keep `local_driver(seed, suffix)` unchanged initially; migrate it only after
   one-validator byte-for-byte regression tests prove equivalence.
6. Add assertions for distinct IDs, shared authority/snapshot roots, equal
   genesis identity, and distinct durable/vote-safety paths.

Risks and corresponding checks: manifest-byte drift (one-validator golden
fixture), mismatched IDs (derive-and-compare assertion), invalid VRF proofs
(NodeEngine initialization), divergent roots (cross-node root equality), and
shared storage (canonicalized path inequality).
