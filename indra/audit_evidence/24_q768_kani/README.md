# Q768 Kani harness

This standalone verification-only crate calls INDRA's production sortition API.
It is deliberately not a workspace member and changes no production source.

List harnesses:

```sh
cargo kani list --manifest-path audit_evidence/24_q768_kani/Cargo.toml
```

Attempt one harness:

```sh
cargo kani --manifest-path audit_evidence/24_q768_kani/Cargo.toml \
  --harness certified_log_interval_is_ordered
```

See `KANI_RESULTS.md` before interpreting or extending these runs. In particular,
do not reduce the symbolic domain or disable unwinding checks and describe the
result as full-domain verification.
