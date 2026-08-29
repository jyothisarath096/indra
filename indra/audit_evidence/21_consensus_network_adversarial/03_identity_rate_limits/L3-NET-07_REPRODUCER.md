# L3-NET-07 Reproducer — Unbounded pre-authentication cooldown state

## Identity setup

No validator credential is required. The production inbound listener constructs a
`PreAuthInboundKey` from the remote source IP and its network group before the
validator handshake. A failed handshake calls
`inbound_cooldowns.pre_auth.record_failure_at(pre_auth_key, Instant::now())`.

## Production path

`indra-node/src/bin/node.rs` inbound TCP accept -> per-IP/global live-connection
reservation -> handshake semaphore -> `perform_handshake_responder` -> handshake
failure -> `CooldownTracker::record_failure_at`.

`CooldownTracker` in `indra-network/src/policy.rs` owns an ordinary `HashMap`.
`record_failure_at` inserts every new key. It has no capacity, LRU, idle sweep, or
expiry removal. `blocked_at` reads but does not delete expired entries. `reset`
removes only the exact key after a successful connection.

## Deterministic constructor

Run:

```sh
cargo run --manifest-path audit_evidence/21_consensus_network_adversarial/03_identity_rate_limits/harness/Cargo.toml --release
```

The harness uses the production `indra_network::policy::CooldownTracker` with the
production 2-second/60-second cooldown parameters. It records failures for 200,000
distinct IPv6 source identities at one deterministic `Instant`, then proves all
200,000 remain addressable as blocked entries. The two 100,000-key waves establish
continued linear growth rather than a hidden 100,000-entry cap.

## Expected result

Pre-authentication attacker-created state must have an explicit global bound and
eviction/cleanup behavior.

## Actual result

All distinct keys remain retained. No capacity or eviction is present.

## Reachability and prerequisites

Production reachable: yes. An attacker needs TCP reachability and many distinct
observable source IPs over time; no validator authentication is required. The
64-live-inbound, 3-per-IP, 50-handshake, and 10-second timeout bounds limit
simultaneous work but do not bound cumulative cooldown-map cardinality. Entries
survive connection close and expiry of the cooldown deadline, and last until an
exact-key successful connection or process restart.

## Consequence

Sybil source churn can grow resident process memory without a protocol maximum.
This satisfies critical stop condition 4: attacker-unbounded authentication-policy
state. Preliminary severity: HIGH pending independent review and operational
measurement.

