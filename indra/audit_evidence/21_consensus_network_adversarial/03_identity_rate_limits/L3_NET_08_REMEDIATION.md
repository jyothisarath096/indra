# L3-NET-08 Remediation

## Disposition

L3-NET-08 remains **OPEN pending independent review**. This focused change bounds authenticated post-authentication cooldown state; it does not resume the unfinished Phase 2C audit branches.

## Root cause

`indra-node/src/bin/node.rs` previously stored post-authentication cooldowns in a single generic `CooldownTracker<PostAuthInboundKey>`, keyed by `(validator_id, source_ip)`. The validator cap bounded only the first key dimension. A valid validator could therefore churn source addresses and retain one entry per address indefinitely (the preserved reproducer retained 200,000 entries).

## Policy implemented

Post-auth state is now `PostAuthCooldowns`: an outer map of validator identity to an inner `BoundedCooldownTracker<IpAddr>`. Each validator namespace has a strict 16-address live-entry cap, 60-second retention, two-second failure cooldown, and an auxiliary order cap of 32. The outer namespace is capped at `MAX_ACTIVE_VALIDATORS` (200), so total bounds are 3,200 live address entries and 6,400 order entries. Saturation declines to retain another key and applies the normal cooldown duration; it never evicts or resets another validator's state.

Successful authentication still resets only the exact `(validator, source_ip)` key. Disconnect/reconnect behavior and validator identity semantics are unchanged. Pre-auth tracking remains the separate 4,096-entry policy from L3-NET-07.

## Evidence

The deterministic 200,000-address harness now reports 16 retained entries before exact-current-key reset and 15 after reset. The node regressions prove per-validator isolation, exact reset, and the outer validator namespace bound. No production wire format, authentication proof, consensus behavior, or validator limiter was changed.

## Validation

Focused tests passed for the node post-auth regressions, the existing bounded cooldown tests, and the standalone churn harness. Full workspace validation is recorded below after execution. `git diff --check` and formatting checks are required before handoff.

## Scope

Production change: `indra-node/src/bin/node.rs`. Evidence harness: `audit_evidence/21_consensus_network_adversarial/03_identity_rate_limits/harness/src/bin/post_auth_growth.rs`. L3-NET-07 pre-auth policy is reused only as a bounded primitive, not as a shared cache; L3-NET-04 and all remaining Phase 2C branches are untouched.
