# L3-NET-09 Reproducer

- **Title:** Historical post-auth validator namespaces are not reclaimed.
- **Preliminary severity:** MEDIUM.
- **Production reachable:** Yes, after authenticated historical validators populate the post-auth map and authority rotates.
- **Prerequisite:** valid credentials for 200 historical validator IDs and an authority transition to a new validator ID.
- **Identity domain:** `PostAuthCooldowns.by_validator` outer namespace.

## Exact reproducer

Run:

```sh
cargo run --manifest-path audit_evidence/21_consensus_network_adversarial/03_identity_rate_limits/harness/Cargo.toml --bin post_auth_rotation
```

Observed:

```text
ROTATION: historical_namespaces=200 expired_live_entries=0 new_validator_tracker_inserted=false namespaces_after=200
```

The harness models the production `PostAuthCooldowns` policy: one inner bounded
tracker per validator, 60-second retention, lazy expiry, and outer admission only
while `by_validator.len() < MAX_ACTIVE_VALIDATORS` (200). At `now + 61s`, all inner
address entries are expired, but no exact-key reset occurs, so the outer entries
remain. A new validator receives the fallback cooldown and no retained tracker.

## Consequence

The process remains memory-bounded, and no consensus safety mutation was observed.
However, current-authority validators can lose remembered post-auth cooldown state
until historical namespaces are removed by exact-key reset or process restart. This
can increase reconnect/handshake work and weakens the intended post-auth cooldown
policy after repeated authority rotations.

## Recommended next action

Design a post-auth-specific namespace reclamation policy that removes empty expired
inner trackers without allowing one validator to evict or reset another validator's
live state. Do not reuse the pre-auth tracker wholesale. No remediation was made in
this audit.
