# Q768 oracle harness

Run from the INDRA workspace root:

```sh
cargo run --release --manifest-path audit_evidence/08_q768_oracle/Cargo.toml
```

The standalone crate uses MPFR through `rug` and calls the production
`indra_core::sortition` API. It is not a workspace member or shipping dependency.
On the first contract failure it exits without modifying production code and prints
the exact tuple, thresholds, certificate endpoints, and width.
