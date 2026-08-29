# L3-NET-07 Remediation Design

Status: design for independent review. L3-NET-07 remains **OPEN**. No production
code, production test, or patch was created by this task.

## 1. Root-cause recap

`CooldownTracker<K>` owns `HashMap<K, CooldownEntry>` without a capacity or
reclamation policy. `record_failure_at` inserts a caller-supplied key,
`blocked_at` only compares `now` with `retry_at`, and `reset` removes only the
exact key. The inbound listener records every failed validator handshake under:

```text
PreAuthInboundKey {
    group: NetworkGroup::from_ip(source_ip),
    ip: source_ip,
}
```

Distinct observable source IPs therefore create distinct retained entries. The
64-inbound, three-per-IP, 50-handshake, and ten-second-timeout controls bound live
work, not cumulative keys. The confirmed reproducer retained 200,000 keys.

## 2. Current production policy and call sites

The generic tracker implements exponential delays of 2, 4, 8, 16, 32, then 60
seconds. A further failure refreshes `retry_at` and retains a 60-second next delay.
There is no failure counter separate from `next_delay`, no decay, no expiration
sweep, and no read-side mutation. State is process-local.

Production instantiations are distinct even though they share the generic type:

| Instance | Key | Trust domain | Gate/update behavior |
|---|---|---|---|
| inbound `pre_auth` | `(NetworkGroup, source IpAddr)` | attacker-controlled before authentication | checked before capacity reservation; failed handshake records; successful inbound connection resets exact source key |
| inbound `post_auth` | `(validator_id, source IpAddr)` | authenticated validator plus transport address | checked after successful cryptographic handshake; disconnect records; successful connection resets exact key |
| outbound peer cooldown | address string before known identity, otherwise validator ID | locally selected address or authenticated validator | dial/handshake failure records; successful connection and peer eviction reset relevant key |
| sync source cooldown | validator ID | authenticated validator | sync timeout/invalid-response paths record; request selection checks it |

The current unit test `cooldown_doubles_and_resets` proves 2-second initial delay,
4-second second delay, active blocking, and exact-key reset. Node tests cover
pre-auth exponential cooldown, outbound peer removal/reset, and successful
connection behavior. The Phase 2C reproducer proves uncapped growth. No current
test establishes cardinality, expiration reclamation, or saturation semantics.

## 3. Trust-domain separation

The remediation should not change generic `CooldownTracker` globally.

- **Pre-authentication:** keys are attacker-created, cardinality must be strictly
  bounded, and eviction is necessarily attacker-influenceable. Its purpose is a
  best-effort temporary backoff inside a hard resource envelope.
- **Post-authentication/outbound/sync:** keys are authority-derived or locally
  selected and have different persistence requirements. Evicting them under
  unauthenticated churn could mint reconnect or sync budgets. Their semantics must
  remain unchanged in the L3-NET-07 implementation.

Recommended scope: introduce a dedicated bounded pre-auth cooldown type or a
bounded mode instantiated only for `InboundCooldowns::pre_auth`. Leave
`post_auth`, outbound, sync, validator message limiters, and the 80/20 vote bucket
untouched.

## 4. Capacity derivation

Relevant production facts are:

- 64 maximum simultaneously reserved inbound connections;
- three simultaneous inbound connections per exact IP;
- 50 shared handshake permits (inbound and outbound);
- ten-second full validator-handshake timeout;
- 2-to-60-second exponential pre-auth cooldown;
- at most 200 active validators, although pre-auth sources need not be validators;
- an authenticated peer table of 80 and an outbound target of eight;
- IPv4 `/16` and IPv6 `/32` network groups, but the full IP is also in the key.

The live limit implies at most 64 sources are simultaneously consuming inbound
slots. A legitimate 200-validator authority undergoing widespread endpoint churn
still fits far below 1,000 distinct recent source IPs. A capacity should cover many
complete waves of legitimate concurrency while making attacker cost and memory
explicit.

| Candidate | Entries | Multiple of live inbound cap | Approximate memory | Abuse resistance | Legitimate false-eviction risk | Saturation behavior |
|---|---:|---:|---:|---|---|---|
| 1,024 | 1,024 | 16x | 0.14–0.20 MiB | attacker needs about 1,024 newer failed-source keys to target the oldest entry | low in ordinary operation, but concentrated NAT/cloud churn could evict recent history | frequent eviction under moderate distributed scanning |
| **4,096** | **4,096** | **64x** | **0.56–0.81 MiB** | approximately 4,096 newer failures are required to target the oldest entry from a full map | very low relative to 200 active validators and 64 live inbound slots | bounded degradation under large Sybil scans without material memory cost |
| 16,384 | 16,384 | 256x | 2.25–3.25 MiB | highest churn cost before targeted eviction | negligible | retains substantially more attacker history, but gives little added protection without a global attempt rate |

Recommendation: **4,096 live pre-auth entries**. It covers 64 complete rotations of
the inbound live cap and over 20 distinct recent endpoints per maximum active
validator. Compared with 16,384 it avoids retaining four times as much purely
attacker-controlled history; compared with 1,024 it gives materially more room for
distributed operational churn. The number is a policy constant that should be
documented next to the live inbound and handshake limits.

This capacity is not a claim that 4,096 sources are trusted. It is the maximum
amount of temporary abuse history worth retaining without a separate global
handshake-attempt policy.

## 5. Memory sizing

A local `size_of` measurement on the target Rust toolchain/architecture produced:

| Type | Size | Alignment |
|---|---:|---:|
| `IpAddr` | 17 B | 1 |
| `NetworkGroup` | 5 B | 1 |
| `PreAuthInboundKey` | 22 B | 1 |
| `Instant` | 16 B | 8 |
| `Duration` | 16 B | 8 |
| current `CooldownEntry` | 32 B | 8 |
| `(PreAuthInboundKey, CooldownEntry)` | 56 B | 8 |

The tuple size is not the allocation cost. At an approximate 87.5% hash-table load,
56 bytes becomes about 64 bytes per live entry before hash-table control bytes and
allocator slack. Deterministic eviction also needs bounded order metadata. A
`TimedEntry<PreAuthInboundKey>` containing key, generation and deadline is roughly
48 bytes; when capped at at most twice the live capacity, it can add up to roughly
96 bytes/live entry at the compaction threshold. In practice the combined design is
expected around **144–208 bytes per live entry**, including control bytes, capacity
rounding, and allocator overhead.

Operational estimates:

| Live entries | Estimated memory range |
|---:|---:|
| 1,000 | 141–203 KiB |
| 4,000 | 563–813 KiB |
| 4,096 recommended cap | 576–832 KiB |
| 16,000 | 2.20–3.17 MiB |

These are sizing estimates, not byte-perfect allocator guarantees. The implementation
test should additionally measure retained capacity in the target allocator if an
operational RSS bound is required.

## 6. Expiration and reclamation

There are two different notions of expiry:

1. `retry_at`: the source is no longer blocked after this time.
2. metadata retention: how long the next exponential delay remains remembered.

Deleting at `retry_at` would silently reduce the policy to repeated two-second
cooldowns for any source that waits out each block, destroying exponential backoff.
The recommended design therefore uses a **60-second idle metadata TTL after the
most recent recorded failure**. A blocked check does not refresh this TTL. After 60
seconds without another recorded failure, the history becomes reclaimable and a
future failure starts again at two seconds. This changes indefinite failure-memory
into an explicit decay policy while preserving escalation during active abuse.

Alternatives:

| Strategy | CPU/locking | Recovery latency | Attacker influence | Assessment |
|---|---|---|---|---|
| removal in `is_blocked` | O(1) for queried key | only when exact key returns | attacker chooses which keys are visited | useful exact-key cleanup but insufficient alone |
| prune in `record_failure` | amortized O(1) with ordered deadlines | next failed attempt | cleanup tied to relevant traffic | recommended |
| periodic full sweep | O(N) mutex hold | bounded by timer | attacker fills scan set | reject as primary mechanism |
| prune only at capacity | low normal cost | memory stays full | predictable saturation | acceptable fallback, not sufficient lifecycle policy |
| ordered opportunistic expiry plus pressure eviction | amortized O(1); occasional bounded compaction | next check/failure and always before insertion | bounded by cap | **recommended** |

Both `is_blocked(key, now)` and `record_failure(key, now)` should first pop expired
entries from the front of a deadline/recency queue while holding the existing mutex.
No background task is required. `is_blocked` may remove the queried entry if its
metadata TTL is expired, but must not refresh recency or retention merely because a
connection checked it.

## 7. Eviction and saturation policy

When inserting an unseen key:

1. reclaim all expired metadata reachable at the front of the ordered queue;
2. if still at capacity, evict exactly one least-recently-failed live entry;
3. insert the new key with initial two-second block, next delay four seconds, and a
   60-second metadata-retention deadline;
4. never let the live map exceed 4,096 entries.

For an existing key, update its delay and deadlines without increasing live
cardinality. Successful authentication removes only its exact pre-auth key.

Policy comparison:

| Policy | Targeted eviction | CPU | Predictability | Decision |
|---|---|---|---|---|
| plain LRU on every lookup | blocked probes can protect attacker entries forever | O(1) average | predictable | reject |
| oldest cooldown deadline | short first-offense entries are evicted first even when recently abusive | heap/logarithmic or ordered queue | predictable | reject |
| expired-first, oldest failure | attacker can force eviction, but only by newer recorded failures; preserves active failure relevance | amortized O(1) | deterministic | **recommend** |
| FIFO | refreshes do not protect repeatedly failing sources | O(1) | deterministic | weaker abuse memory |
| random | makes tests and operational diagnosis harder | O(1) | intentionally unpredictable | unnecessary with randomized hashing |
| refuse new tracking | lets all new Sybil identities bypass source cooldown at saturation | O(1) | deterministic | reject |
| global fail-closed | attacker can fill map and deny all legitimate new sources | O(1) | deterministic | reject |

The new source is admitted to the normal handshake path on its first attempt, just
as today; after its failure it is tracked and blocked for two seconds. At saturation
one old source may regain access, but the node remains available to legitimate new
sources and memory remains bounded. Eviction work must never perform a full-map scan.

## 8. Eviction-bypass attack

Assume source A has just failed and is the oldest live entry in a full 4,096-entry
map. To deliberately evict A, the attacker must cause approximately 4,096 distinct
new source keys to reach a recorded handshake failure after A. A then reconnects and
receives a normal first attempt instead of remaining blocked.

The attacker encounters:

- at most 64 reserved inbound connections globally;
- at most three simultaneous connections per exact IP;
- at most 50 simultaneous handshakes;
- a ten-second timeout for slow/incomplete attempts;
- actual TCP setup and one failed-handshake exchange per new key.

Fast malformed prefaces can fail well before ten seconds, so source cardinality—not
the timeout—is the controlling attacker cost. There is currently no global attempt-
per-second limiter; 4,096 failures could therefore be generated substantially faster
than 60 seconds on a sufficiently distributed, high-rate source. Exact time cannot be
honestly fixed without network and crypto benchmarks.

This means bounded eviction can turn A's cooldown into no cooldown after sufficient
Sybil churn. That is an unavoidable bounded-cache degradation. It is acceptable for
this narrow state-bounding remediation because each regained attempt costs roughly
one full cache worth of newer failed identities, memory stays bounded, and no
authenticated validator budget is reset. It must be documented and measured in the
later cryptographic/connection-DoS phase. If those measurements show unacceptable
CPU load, an independent global pre-auth attempt bucket should be designed; it should
not be smuggled into L3-NET-07.

## 9. Source IP and network-group semantics

`NetworkGroup::from_ip` uses IPv4 `/16` and IPv6 `/32`. `PreAuthInboundKey` includes
both that group and the complete `IpAddr`. Because the full IP uniquely determines
the group, the group field currently adds classification data but **does not aggregate
cooldown identity**. IPv4 sources in one `/16` remain independent. IPv6 addresses in
one `/32` also remain independent, so an attacker controlling a single routed IPv6
prefix can cheaply generate enormous key diversity. This materially amplifies the
confirmed finding.

Changing the key to group-only would collapse many unrelated IPv4 users, cloud
tenants, carrier NAT users, or IPv6 networks into one penalty domain. It could let
one abusive host deny an entire `/16` or `/32`. That semantic change is outside this
remediation design.

Recommendation: retain the exact current key for L3-NET-07 and bound its state.
Evaluate a separate, low-capacity per-group/global attempt control only during the
cryptographic-DoS phase, with NAT and IPv6 deployment data.

## 10. Is an additional global pre-auth budget required?

| Architecture | Memory bound | CPU/crypto bound | Source backoff | Assessment |
|---|---|---|---|---|
| bounded map only | yes | only existing concurrency/timeout bounds | yes until eviction | fixes confirmed state defect but ignores existing concurrency controls |
| bounded map plus existing 64/3/50/10s controls | yes | bounds simultaneous work, not attempt rate | yes until eviction | **minimum recommended architecture for L3-NET-07** |
| above plus global attempt token bucket | yes | also bounds aggregate attempt rate | yes | potentially valuable, but policy and liveness tradeoffs belong to later crypto-DoS audit |
| above plus per-group limiter | yes if separately bounded | bounds a prefix | may penalize large shared groups | defer pending deployment/NAT evidence |

The finding is unbounded state, not a reproduced unbounded ML-DSA verification path.
The minimum remediation should bound the pre-auth map and preserve existing live-work
controls. Add metrics for occupancy, eviction, and failure rate if operational
instrumentation is already in scope; metrics must not create per-source labels.

## 11. HashMap collision considerations

`std::collections::HashMap` without an explicit builder uses `RandomState`, seeded per
map/process and designed to resist attacker-chosen collision sets. No practical
collision amplification was reproduced. Capacity bounding additionally caps the
number of live buckets and worst-case structure size. No custom fast/non-random
hasher should be introduced for these attacker-controlled keys.

## 12. Concurrency and serialization

Both inbound trackers are inside `Arc<std::sync::Mutex<InboundCooldowns>>`. Listener
checks, failed-handshake updates, successful-auth resets, and post-auth disconnect
updates acquire this mutex. The handshake itself occurs without holding it.

The bounded pre-auth implementation must perform expiry, eviction, and insertion
under that same mutex. Therefore:

- simultaneous inserts cannot transiently exceed capacity;
- checks see either the old or new complete entry;
- reset removes only the exact key;
- a cleanup cannot remove a newly refreshed entry if queue records carry a generation
  and deletion verifies that generation against the live map;
- race outcome follows event order: a later failure after a success records a new
  cooldown, while a later success after a failure clears it.

No additional lock or actor is recommended. A queue compaction may be O(cap), but it
must be infrequent (for example only when bookkeeping exceeds `2 * HARD_CAP`), making
updates amortized O(1) and the worst work strictly bounded by 4,096—not attacker-total
history. Never scan O(N) on every handshake.

## 13. Proposed API and data structure

Recommended conceptual type:

```text
BoundedCooldownTracker<K> {
    values: HashMap<K, (CooldownEntry, generation, retention_deadline)>,
    order: VecDeque<(K, generation, retention_deadline)>,
    capacity: usize,
    minimum: Duration,
    maximum: Duration,
    retention_ttl: Duration,
    next_generation: u64,
    evictions: u64,
}

new(capacity, minimum, maximum, retention_ttl)
is_blocked(&mut self, key, now) -> bool
record_failure_at(&mut self, key, now) -> Duration
reset(&mut self, key)
prune_expired(now)
len() -> usize
capacity() -> usize
evictions() -> u64
bookkeeping_len() -> usize     // test/metrics
```

Target complexities:

- lookup/reset: O(1) average;
- insert/update: amortized O(1);
- expired pruning: O(number expired from ordered front);
- capacity eviction: amortized O(1);
- occasional queue compaction: O(HARD_CAP), never O(total historical keys);
- map live entries `<= HARD_CAP`; queue entries `<= 2 * HARD_CAP` after every public
  operation.

Recency means **most recent recorded failure**, not most recent lookup. Each failure
gets a monotonically wrapping generation. Stale queue records are ignored unless
their generation matches the live map. On generation wrap, either rebuild generations
under the cap or use a correctness-safe comparison; do not permit an ancient stale
record to delete a refreshed entry.

The repository already contains `BoundedTtlMap` with a bounded-generation queue,
expired-first behavior, deterministic least-recently-touched eviction, and bounded
bookkeeping. Implementation may carefully extend/reuse that primitive, but its
current access-refresh semantics do not exactly match cooldown policy: blocked checks
must not refresh TTL or recency. A small specialized wrapper/type is easier to audit
than forcing inappropriate semantics. No new dependency is needed.

## 14. Required invariants

- **I1:** pre-auth live cooldown cardinality is always `<= 4,096` after construction
  and after every operation.
- **I2:** all pre-auth memory, including order/generation metadata, is O(4,096) and
  independent of total historical source identities.
- **I3:** entries with no recorded failure for 60 seconds become reclaimable and are
  opportunistically removed.
- **I4:** no unauthenticated input can allocate cooldown state beyond the live-map and
  bounded-bookkeeping caps.
- **I5:** post-authenticated validator, outbound, sync, score, ban, and message-limiter
  semantics are unchanged.
- **I6:** reconnect/replacement cannot create duplicate post-auth validator budgets;
  the existing validator-keyed peer-manager limiter remains authoritative.
- **I7:** successful authentication resets only the exact `(group, IP)` pre-auth key
  that produced that connection.
- **I8:** expiry/eviction removes an entry only when its key and generation match the
  live map; stale queue records cannot delete refreshed entries.
- **I9:** the order queue, generation records, metrics, and any heap are themselves
  strictly bounded; no auxiliary history grows with attacker attempts.
- **I10:** routine operations are average/amortized O(1); no handshake performs an
  unbounded scan. Any compaction is capped by `HARD_CAP` and occurs at a bounded
  amortized frequency.

## 15. Implementation-phase adversarial test plan

All time tests use injected `Instant` values, never sleeps.

1. Insert exactly 4,096 unique keys; assert `len == capacity == 4,096` and bounded
   bookkeeping.
2. Insert key 4,097; assert `len == 4,096`, exactly one deterministic eviction, and
   the new key's initial two-second cooldown.
3. Insert 200,000 distinct keys; assert live length never exceeds 4,096 and auxiliary
   bookkeeping never exceeds its documented cap.
4. Advance 59,999 ms after a failure; assert metadata remains and active cooldown
   behavior is correct. Advance to 60 seconds idle; trigger pruning and assert removal.
5. Exercise 2/4/8/16/32/60-second escalation; assert non-expired active cooldown blocks.
6. Reset one exact key among neighbors; assert only it is removed and other delays are
   unchanged.
7. Fill with deterministic insertion order, refresh one key by recording another
   failure, saturate, and prove the oldest *failure* entry—not the refreshed key—is
   evicted.
8. Put attacker A in cooldown, add 4,096 newer Sybil keys, prove A can be evicted and
   document this as the accepted bounded-degradation behavior; prove no memory growth.
9. Keep a legitimate key recently failed while churning older keys; prove it remains
   tracked until it becomes the deterministic oldest or idle-expires.
10. Repeat churn with distinct IPv4 addresses across and within `/16` groups; prove
    current exact-IP semantics and cap.
11. Repeat with 200,000 IPv6 addresses within one `/32`; prove exact-IP diversity does
    not exceed memory cap.
12. Spawn concurrent operations through the same production mutex; after every join,
    assert live and bookkeeping caps, no panic, and exact-key consistency. Repeat at
    least 100 times under a fixed seeded schedule where possible.
13. Refresh a key, leave its stale queue record at the front, prune/evict, and prove
    generation checking preserves the refreshed entry.
14. Race modeled event orders: failure then success removes; success then failure
    records. Assert deterministic last-event semantics.
15. Run all existing `CooldownTracker`, handshake, inbound connection-cap, and
    semaphore tests unchanged.
16. Re-run the original 200,000-key L3-NET-07 reproducer with the production pre-auth
    type and change only the expected cardinality to `<= 4,096`.
17. Re-run validator limiter tests: 80 immediate votes accepted, 81st rejected, 49 ms
    no refill, 50 ms one token.
18. Re-run same-validator disconnect/reconnect and replacement tests; prove message
    budget remains validator-scoped and persistent.
19. Prove post-auth cooldown entries are unaffected by pre-auth saturation.
20. Run Miri or sanitizer-compatible targeted tests if available to stress queue/map
    bookkeeping; this is supplementary, not a substitute for deterministic assertions.

## 16. Rejected alternatives

- **Make generic `CooldownTracker` globally bounded:** rejected because post-auth,
  outbound, and sync trust domains have different identity and persistence semantics.
- **Delete immediately at `retry_at`:** rejected because a source that waits out each
  block would never escalate beyond two seconds.
- **Unbounded expiry heap:** rejected because it merely moves the original defect to
  auxiliary metadata.
- **Full-map sweep per connection:** rejected due mutex-held O(cap) work on attacker-
  driven input.
- **Refuse new entries at capacity:** rejected because all new identities become
  unthrottled while attackers pin the table.
- **Global fail-closed saturation:** rejected because filling the map would let an
  unauthenticated attacker deny every legitimate new inbound source.
- **Group-only key:** rejected for this scope because `/16` IPv4 and `/32` IPv6
  collateral blocking requires separate operational justification.
- **Persistent pre-auth state:** rejected because ephemeral abuse history is not a
  consensus/security identity record and disk I/O would add a new attacker-controlled
  resource boundary.
- **New cache crate:** rejected; existing standard-library and repository primitives
  are sufficient and easier to audit.
- **Add global handshake token bucket now:** deferred because L3-NET-07 establishes
  unbounded state, not a measured aggregate cryptographic-DoS defect.

## 17. Restart policy

Pre-auth cooldown state should remain ephemeral. Restart is already a transport and
rate-policy reset boundary, and an unauthenticated source history is neither consensus
state nor an authorization decision. Persistence would add attacker-driven disk state,
format migration, corruption handling, and write amplification without addressing an
attacker capable of inducing restarts. Restart inducibility belongs to a separate
operational/DoS audit.

## 18. Recommended design and implementation scope

Implement a dedicated `BoundedCooldownTracker<PreAuthInboundKey>` with:

- hard live capacity 4,096;
- 2-second minimum and 60-second maximum exponential delay;
- 60-second idle metadata retention after the last recorded failure;
- expired-first, then least-recently-failed deterministic eviction;
- bounded generation queue (`<= 2 * capacity` after each operation);
- average/amortized O(1) operations under the existing inbound cooldown mutex;
- standard randomized `HashMap` hashing;
- no persistence and no new dependency.

At saturation, evict one oldest-failure entry and track the new failed source. Do not
globally reject new sources and do not silently leave them untracked. Preserve all
post-auth, outbound, sync, validator limiter, authentication, and connection policies.

Expected implementation files, subject to independent design approval:

- `indra-network/src/policy.rs`: bounded pre-auth-capable cooldown structure and unit
  tests, or the smallest reusable primitive extension with non-refreshing lookup;
- `indra-network/src/lib.rs`: export only if the dedicated type must cross the crate
  boundary;
- `indra-node/src/bin/node.rs`: instantiate only `InboundCooldowns::pre_auth` with the
  4,096 cap and add integration/concurrency regressions;
- existing L3-NET-07 evidence harness: update remediation expectation while preserving
  the original finding report/reproducer.

No wire format, handshake transcript, validator identity, rate-limit budget, peer
tie-break, network-group rule, or consensus semantic change is required.

## 19. Severity and residual risk

HIGH remains appropriate before remediation because unauthenticated sequential source
churn creates process-lifetime attacker-linear state and can eventually exhaust node
memory.

After the proposed bound, the original memory-exhaustion vector becomes impossible
through this structure. Residual attacks are:

- bounded cache churn and roughly 0.6–0.8 MiB retained policy memory;
- an attacker with about one cap of newer Sybil failures can evict an older cooldown;
- existing bounded handshake concurrency can still be saturated;
- no global attempt-per-second bound exists.

For L3-NET-07 these are bounded nuisance/operational risks, preliminarily LOW if the
implementation satisfies I1–I10. Aggregate handshake CPU and inbound-slot starvation
must be evaluated in the later cryptographic/peer-churn DoS phases. This design does
not mark the finding closed.
