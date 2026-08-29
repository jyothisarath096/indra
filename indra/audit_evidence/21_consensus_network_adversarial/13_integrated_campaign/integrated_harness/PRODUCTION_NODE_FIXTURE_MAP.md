# Production node fixture map (Step 3)

| Dependency | Actual helper/type | Source | Harness status |
|---|---|---|---|
| consensus driver | `ConsensusDriver::new(NodeEngine, VoteSafetyStore)` | `indra-node/src/driver.rs:272` | blocked by crate-private integration |
| canonical genesis | `canonical_test_genesis`, `build_finalized_genesis_state` | `indra-node/src/genesis.rs:709,855` | helpers are crate-private/public split |
| engine | `NodeEngine::new` and test initialization fixtures | `indra-node/src/engine.rs` tests | requires node crate test context and durable directory |
| safety persistence | `VoteSafetyStore` used by driver fixtures | `indra-node/src/driver.rs` tests | must be constructed in owning crate |
| local signing | `sign_and_record_local_vote` | `indra-node/src/driver.rs:1256` | private; no external safe call |
| QC | `indra_consensus::qc::build_qc`, `verify_qc` | `indra-consensus/src/qc.rs` | directly callable once production votes exist |
| restart | reconstruct engine + safety store from same directories | driver restart tests | not cloneable from external crate |

The audit harness currently cannot construct a faithful fixture externally
without reproducing the private `local_driver` setup inside an owning-crate
feature module. Step 4's adapter intentionally does not expose raw keys or
arbitrary state mutation. A complete fixture remains blocked pending that
narrow, reviewed implementation.

Step 6 confirmed `local_driver` is defined inside `driver.rs`'s `#[cfg(test)]
mod tests` (around line 2660), returning `(ConsensusDriver, PathBuf)`. It
constructs `NodeConfig::local_test`, deterministic PQ/classical/VRF/cold keys,
sealed genesis TOML, `NodeEngine::init`, and `VoteSafetyStore::open`. Because
the whole builder is test-module private, the feature-gated audit module cannot
reuse it without relocating the common builder out of the test module. That
relocation was not performed in this evidence step.
