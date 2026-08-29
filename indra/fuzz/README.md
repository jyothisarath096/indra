# Permanent fuzzing targets

These libFuzzer targets exercise INDRA's externally controlled parsing and
dispatch boundaries. They are deliberately kept in-tree; crashes and minimized
reproducers under `artifacts/` must be reviewed as security findings rather than
silently deleted.

Install the runner and a nightly toolchain once:

```sh
cargo install cargo-fuzz
rustup toolchain install nightly --profile minimal
```

Run a local one-minute campaign per target:

```sh
cargo +nightly fuzz run transaction_deserialization -- -max_total_time=60
cargo +nightly fuzz run public_json_rpc -- -max_total_time=60
cargo +nightly fuzz run governance_parsing -- -max_total_time=60
cargo +nightly fuzz run p2p_gossip_parsing -- -max_total_time=60
cargo +nightly fuzz run vrf_verify_arbitrary -- -max_total_time=60 -max_len=8192
cargo +nightly fuzz run vrf_valid_proof_mutation -- -max_total_time=60 -max_len=4129
cargo +nightly fuzz run vrf_public_key_validation -- -max_total_time=60 -max_len=32
cargo +nightly fuzz run vrf_prove_verify_roundtrip -- -max_total_time=60 -max_len=4128
cargo +nightly fuzz run vrf_proof_framing -- -max_total_time=60 -max_len=8192
```

For CI smoke coverage, use `-max_total_time=30 -timeout=10` for each target.
Nightly/security jobs should retain each corpus directory between runs and use a
longer budget. Seed files are generated from canonical current wire structures
by `cargo run --manifest-path fuzz/Cargo.toml --bin seed_corpora`; rerun that
command whenever a wire format changes and review the resulting corpus diff.
