# L3-NET-09 Remediation

## Root cause

`PostAuthCooldowns` retained empty validator namespaces after inner address
metadata expired. Namespace creation checked only `by_validator.len()`, so 200
historical IDs could prevent a current validator from receiving cooldown tracking.

## Fix

`BoundedCooldownTracker::is_empty` is now an explicit policy API. On insertion of
a previously unseen validator at the 200-namespace boundary, `PostAuthCooldowns`
uses the supplied `Instant` to prune every inner tracker and removes only trackers
that are empty after pruning. It then rechecks the cap and either creates the new
namespace or preserves the hard cap when all namespaces still contain retained
metadata. No scan occurs on ordinary blocked lookups or existing-validator writes.

The outer cap remains 200; each namespace remains capped at 16 live IP entries and
32 bookkeeping records; totals remain 3,200 and 6,400. Reclamation is deterministic
in map iteration only for eligibility; no live namespace is evicted. Exact reset,
cross-validator isolation, authentication, wire, and consensus semantics are
unchanged.

## Regressions and harnesses

Added node tests for expired-namespace admission, non-expired saturation, partial
rotation, existing exact reset/isolation, 200,000-address churn, and global bounds.
The rotation harness now proves historical namespaces are reclaimed and a new
validator is admitted; the churn harness still reports 16/15 entries and 32
bookkeeping records.

Observed harness output:

```text
ROTATION: historical_namespaces=200 expired_live_entries=0 new_validator_tracker_inserted=true namespaces_after=1
REMEDIATED: validator_id=42..42 unique_authenticated_source_ips=200000 retained_before_reset=16 retained_after_exact_current_key_reset=15 per_validator_cap=16 bookkeeping_cap=32
```

The rotation harness then fills the remaining 199 current-authority namespaces,
ending at the hard cap of 200. Non-expired saturation declines the 201st namespace
without evicting any live validator state.

## Scope and residual risk

Production files changed: `indra-network/src/policy.rs` and
`indra-node/src/bin/node.rs`. Evidence harness changes are under the identity/rate
limit audit directory. L3-NET-07 and L3-NET-08 bounds remain intact. No consensus,
crypto, handshake, wire, limiter, or remaining Phase 2C behavior was changed.

L3-NET-09 remains **OPEN PENDING INDEPENDENT REVIEW**.

## Validation

Passed: `cargo test -p indra-network`, `cargo test -p indra-core`,
`cargo test -p indra-consensus`, `cargo test -p indra-node`,
`cargo test --workspace`, `cargo test --workspace --no-run`,
`cargo fmt --all -- --check`, and `git diff --check`.
