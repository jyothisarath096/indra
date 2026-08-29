# Project Indra Layer 3 Phase 2C — Identity and Rate-Limit Boundary Audit

## Continuation final disposition

**CRITICAL STOP**

The original audit stopped after L3-NET-07; that finding was subsequently remediated,
reviewed, and closed. On continuation, the separately scoped post-auth cooldown branch
reproduced L3-NET-08 and triggered mandatory critical stop condition 6. No production
code was modified and no remediation was attempted. Remaining continuation branches
are explicitly incomplete rather than inferred.

## Continuation finding

### L3-NET-08 — Authenticated address churn creates unbounded post-auth cooldown state

- Preliminary severity: HIGH
- Production reachable: yes
- Identity domain: authenticated `(validator_id, source IP)` reconnect/disconnect state
- Budget multiplication factor: not a message-budget multiplication; state cardinality
  grows linearly without a maximum
- Authentication prerequisite: one valid active validator credential
- Reconnect prerequisite: yes, sequential address churn
- Parallel-connection prerequisite: no
- Safety impact: none reproduced
- Liveness impact: attacker-driven memory pressure can degrade or terminate a node
- Resource impact: unbounded retained `HashMap` entries until process restart
- Reproducer: `L3-NET-08_REPRODUCER.md`
- Recommended action: independent reproduction and remediation design review

The active-validator cap does not bound this map because its key is the Cartesian
combination of validator ID and full source IP. The production disconnect path records
each authenticated address. Successful reconnect removes only the current exact key.
The deterministic harness retained 200,000 keys for one validator and retained 199,999
after resetting the current address.

Continuation reproducer command:

```sh
cargo run --manifest-path audit_evidence/21_consensus_network_adversarial/03_identity_rate_limits/harness/Cargo.toml --release --bin post_auth_growth
```

Observed:

```text
REPRODUCED: validator_id=42..42 unique_authenticated_source_ips=200000 retained_before_reset=200000 retained_after_exact_current_key_reset=199999 capacity_or_eviction=none
```

The updated Phase 2C harness, repeated connection-race suite, and full package/workspace
validation were not run after this reproduction because the continuation requires an
immediate critical stop. This is not reported as a validation pass.

## Production identity model traced before stop

Inbound TCP connections are first identified by socket address and source IP. The
listener reserves one of 64 inbound slots, enforces three simultaneous inbound
connections per IP, and acquires one of 50 handshake permits. The handshake has a
10-second timeout. Matching chain/genesis prefaces precede ML-KEM/X25519 exchange.
The claimed validator ID is looked up in the current governing network authority,
and possession of that validator's ML-DSA-87 key is verified over the complete
handshake transcript and claimed ID.

Only a successful `HandshakeResult` supplies `peer_validator_id` to the peer-manager
actor. The actor keys live connections and message limiters by that authenticated
validator ID. A live identity cannot change or downgrade. A deterministic
initiator/responder tie-break permits only one retained connection per validator.

## Authentication state machine

1. Accept TCP source and construct pre-auth key `(network group, source IP)`.
2. Reject if that key is in cooldown.
3. Reserve global/per-IP live connection capacity.
4. Acquire bounded handshake permit or reject.
5. Enforce chain ID and finalized-genesis fingerprint.
6. Parse claimed validator ID and require it in current network authority.
7. Perform ML-KEM-1024/X25519 key agreement.
8. Verify ML-DSA-87 possession over transcript plus claimed validator ID.
9. On failure, retain/update pre-auth cooldown state.
10. On success, apply post-auth cooldown and register one connection for the
    authenticated validator identity.

Valid authentication, unknown-validator rejection, invalid-signature rejection,
chain mismatch, timeout, reconnect persistence, and same-validator tie-break tests
already exist in the production test tree. The remaining requested handshake matrix
was not executed after the stop condition.

## Limiter ownership model

`PeerManagerActor::limiters_by_validator` is node-wide and keyed by the authenticated
transport validator ID. It is not removed on disconnect or connection replacement.
All mutation occurs in the actor's serialized `InboundMessage` handler. Per-message
count charging occurs before global byte charging; applicable byte charging uses the
actual decrypted framed plaintext length, not a re-encoded size.

The vote bucket is configured for 80 burst and 20 votes/second. Existing deterministic
tests directly manipulate the bucket's `Instant` and establish no refill at 49 ms and
one full token at 50 ms. Existing peer-manager tests establish 80 accepted near-
duplicate votes, rejection of the 81st with a frozen bucket, independent validator
budgets, and persistence across disconnect.

## Historical critical finding (closed before continuation)

### L3-NET-07 — Sybil source churn created unbounded pre-authentication cooldown state

- Preliminary severity: HIGH
- Production reachable: yes
- Affected identity domain: unauthenticated source IP/network group
- Budget multiplication factor: unbounded cumulative key cardinality; simultaneous
  work remains bounded
- Reconnect prerequisite: no
- Parallel-connection prerequisite: no; distinct sources may be used sequentially
- Authentication prerequisite: none
- Safety impact: none reproduced
- Liveness impact: increasing memory pressure can degrade or terminate the node;
  no concrete consensus safety mutation was tested
- Resource impact: attacker-linear retained `HashMap` memory until restart or exact-
  key successful authentication
- Reproducer: `L3-NET-07_REPRODUCER.md`
- Recommended next action: independent reproduction and focused remediation review
  of a strictly bounded/expiring pre-auth policy map

This section preserves original finding history. L3-NET-07 is now CLOSED: production
pre-auth state uses the reviewed 4,096-live/8,192-bookkeeping bounded tracker and the
200,000-key regression passed during remediation validation.

Before remediation, the production `CooldownTracker<K>` contained an uncapped `HashMap`. New failure keys
are inserted by `record_failure_at`; `blocked_at` never expires/removes them. The only
removal method is `reset(&exact_key)`. Inbound authentication failure calls this API
with attacker-controlled source identity. Global live-connection, per-IP, semaphore,
and timeout limits cap concurrency but do not cap cumulative distinct keys over the
process lifetime.

The deterministic harness retained and resolved 200,000 distinct keys in two waves.
This directly meets Phase 2C critical stop condition 4.

## Validation performed before stop

The standalone production-type reproducer completed successfully:

```text
REPRODUCED: unique_keys=200000 retained_and_blocked=200000 capacity_or_eviction=none
```

Command:

```sh
cargo run --manifest-path audit_evidence/21_consensus_network_adversarial/03_identity_rate_limits/harness/Cargo.toml --release
```

The required package/workspace suite, formatting check, and broader concurrency
repetitions were intentionally not started after reproduction because the audit's
critical-stop rule requires immediate return. This is not reported as a validation
pass.

## Partial results preserved

- Same-validator connection multiplication: the peer actor retains at most one live
  connection per authenticated validator and keeps one validator-keyed limiter across
  replacement/disconnect.
- Different validators: limiter keys are independent authenticated validator IDs.
- Vote boundaries: 80 burst, 20/sec, 49/50 ms boundary tests exist deterministically.
- Byte accounting: actual plaintext frame length is charged for configured large
  classes; not every message class has a byte bucket.
- Relay attribution: inbound rate charging uses authenticated transport sender identity;
  signed-origin attribution analysis was in progress and is not classified because the
  critical stop precluded completing its reproducer.
- Restart: all rate-limit and cooldown maps are in-memory and reset on process restart;
  no persistence change was considered.

## Continuation open assumptions and intentionally incomplete work

The continuation completed the post-auth cardinality branch only far enough to
reproduce L3-NET-08. Relay-origin multiplication, request-family completion,
outbound/sync cardinality proof, stale-credential rotation, and repeated connection
race tests remain incomplete because critical stop condition 6 required immediate
return. No conclusions are claimed for those branches.

## Production changes

None. All new files are audit evidence or the standalone deterministic reproducer.

## Part 3 continuation after L3-NET-08 remediation

This section supersedes the historical CRITICAL STOP disposition above for the
already-remediated L3-NET-08 state. The historical finding and original reproducer
remain preserved verbatim for independent review.

The L3-NET-07/L3-NET-08 regression gates passed (4,096/8,192 pre-auth; 16/32 per-validator post-auth; 200 namespaces and 3,200/6,400 global post-auth bounds).

### L3-NET-09 — historical post-auth validator namespaces are not reclaimed

`PostAuthCooldowns` removes an outer validator namespace only during exact-key
`reset`. Inner address expiry is lazy and does not remove the empty outer map entry.
The deterministic `post_auth_rotation` harness filled 200 validator namespaces,
advanced 61 seconds, forced inner expiry (zero live address entries), then attempted
to insert a new authority validator. Insertion was refused and no cooldown tracker
was created; the outer namespace count remained 200. This is production reachable
after authority rotation when historical validators have authenticated. It requires
valid credentials for the historical validators and an authority transition. No
consensus safety mutation was observed. Preliminary severity: MEDIUM (bounded
resource state but current-validator cooldown tracking can be disabled); preserve for
focused remediation review. This is not a HIGH/CRITICAL stop under the observed
policy.

Relay-origin attribution, request-family limits, outbound/sync cardinality, stale
credential behavior, connection races, and multi-validator budget modeling remain
incomplete and were not remediated.

## Part 3 disposition

**PASS WITH NON-CRITICAL FINDINGS** — for the branches exercised in this
continuation. L3-NET-09 requires focused remediation review; the remaining Phase 2C
branches are incomplete and must not be treated as audited or cleared.
