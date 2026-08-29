# L3-NET-08 Reproducer — Authenticated address churn creates unbounded post-auth cooldown state

## Identity and connection setup

- Validator identities: one active validator V.
- Validator credentials: valid current ML-DSA-87 transport credential for V.
- Connections: sequential authenticated inbound connections for V from distinct
  observable source IPs. Parallel connections are unnecessary.
- Message class/limiter state: no consensus message is required. The state is created
  by authenticated connection disconnect handling.

## Exact production path

1. `perform_handshake_responder` verifies V against the current authority and returns
   `HandshakeResult { peer_validator_id: V, ... }`.
2. `PeerManagerActor::register_peer` retains at most one live connection for V.
3. A disconnect produces `NetworkEvent::PeerDisconnected { validator_id: V, addr }`.
4. The node network-event bridge calls:

   ```text
   inbound_cooldowns.post_auth.record_failure_at(
       PostAuthInboundKey { validator_id: V, ip: addr.ip() }, now)
   )
   ```

5. `post_auth` is the original generic `CooldownTracker<PostAuthInboundKey>` backed by
   an uncapped `HashMap` without expiry reclamation or capacity eviction.
6. A later successful connection resets only `(V, current_source_ip)`. Entries for V's
   previous source IPs remain.

The 200-active-validator authority cap does not bound the Cartesian namespace
`validator_id × source_IP`. One credential holder can change source addresses
sequentially and create arbitrarily many keys.

## Deterministic production-type constructor

Run:

```sh
cargo run --manifest-path audit_evidence/21_consensus_network_adversarial/03_identity_rate_limits/harness/Cargo.toml --release --bin post_auth_growth
```

The harness uses the production `indra_network::policy::CooldownTracker` and a key
with the exact production fields `(validator_id, IpAddr)`. One fixed validator ID is
combined with 200,000 IPv6 addresses in one `/32`. It records the production 2/60
second policy at one deterministic `Instant`, proves all keys remain, resets only the
current exact key, and proves the other 199,999 remain.

## Expected boundary

Authenticated address churn must have a finite production cardinality bound or an
authority-scoped key that cannot grow with attacker-selected transport addresses.

## Actual result

```text
unique authenticated source IPs: 200,000
retained before exact reset:      200,000
retained after exact reset:       199,999
capacity/eviction/expiry:         none
```

## Reachability and prerequisites

- Production reachable: yes.
- Authentication prerequisite: one valid active validator credential.
- Reconnect prerequisite: sequential authenticated reconnect/address churn.
- Parallel-connection prerequisite: no.
- Budget before/after: no fresh consensus-message bucket is created; the affected
  resource is post-auth identity/cooldown state.
- Attacker prerequisite: ability to make V's authenticated connections appear from
  many source IPs over the node process lifetime (particularly inexpensive within a
  controlled IPv6 prefix).

## Consequence and classification

Resident memory grows linearly with historical authenticated source addresses until
process restart. This satisfies continuation critical stop condition 6:
post-auth attacker-controlled cooldown state is unbounded.

- Preliminary severity: HIGH.
- Safety impact: none reproduced.
- Liveness impact: memory pressure can degrade or terminate a node.
- Resource impact: attacker-linear persistent in-memory `HashMap` growth.
- Recommended next action: independent reproduction and a design-only review that
  preserves validator/reconnect semantics before focused remediation.

