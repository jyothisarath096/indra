# Production adapter map (Step 2 inventory)

| Harness operation | Production type/function | Source | Directly callable | Limitation |
|---|---|---|---|---|
| construct node | `ConsensusDriver::new(NodeEngine, VoteSafetyStore)` | `indra-node/src/driver.rs:272` | yes in crate tests | requires fully initialized engine and durable safety store |
| current height | `ConsensusDriver::height` | `driver.rs:2376` | yes | none |
| current round | `ConsensusDriver::current_round` | `driver.rs:686` | yes | none |
| process event | `ConsensusDriver::process(DriverEvent)` | `driver.rs:736` | yes | event/action types must be wired |
| propose/prevote/precommit timeout | `on_propose_timeout`, `on_prevote_timeout`, `on_precommit_timeout` | `driver.rs:2326-2360` | yes | tick adapter required |
| local vote signing | `sign_and_record_local_vote` | `driver.rs:1256` | no (private) | exposed only through production event/timeout paths |
| proposal/vote validation | driver event handlers | `driver.rs` | indirect | production fixtures required |
| QC construction/verification | `build_qc`, `verify_qc` | `indra-consensus/src/qc.rs` | yes | snapshot and signer context required |
| lock/PoLC/commit | driver and engine event paths | `driver.rs`, `engine.rs` | indirect | durable state transaction required |
| restart | engine + `VoteSafetyStore` load | driver tests | fixture-only | cannot clone pre-crash driver |

No production adapter was added: external access to private vote paths or
uninitialized engine fixtures would violate the required production fidelity.
