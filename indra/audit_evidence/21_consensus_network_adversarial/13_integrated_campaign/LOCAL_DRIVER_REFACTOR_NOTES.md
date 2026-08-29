# local_driver refactor notes

Captured source: `indra-node/src/driver.rs`, `#[cfg(test)] mod tests`,
`local_driver` beginning near line 2660. Signature:

```text
fn local_driver(seed: [u8; 32], suffix: &str) -> (ConsensusDriver, PathBuf)
```

The body creates `NodeConfig::local_test(temp_dir(suffix))`, deterministic
PQ/classical/VRF/cold keys, VRF possession material, sealed genesis TOML,
`NodeEngine::init`, `VoteSafetyStore::open(engine.config.vote_safety_path())`,
and `ConsensusDriver::new`. It then builds the canonical test state used by
the driver tests.

The implementation depends on neighboring private test helpers (`temp_dir`,
key/fixture utilities, and test-only imports). A behavior-preserving shared
builder therefore requires moving that dependency cluster together, then keeping
the existing wrapper as a thin call. No copy or rewrite was made in this audit
step, and no consensus or persistence semantics were changed.

Current status: refactor pending; external `audit_harness` remains unable to
construct a canonical fixture until the shared builder is moved inside the
owning crate under `cfg(any(test, feature = "audit-harness"))`.

Step 8 implementation review: the dependency cluster is not limited to
`local_driver` and `temp_dir`; it includes neighboring private key/genesis
helpers and test imports. A partial extraction would either duplicate setup or
alter test compilation semantics. No partial module was added.

Step 9 authorized the complete atomic move. It was not committed in this pass;
the canonical `local_driver` remains unchanged and the audit feature cannot yet
construct a production fixture.
