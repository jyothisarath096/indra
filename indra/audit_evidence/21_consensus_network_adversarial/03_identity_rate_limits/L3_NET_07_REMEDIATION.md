# L3-NET-07 Focused Remediation

Status: remediation implemented and returned for independent review. **L3-NET-07
remains OPEN**; this report does not close the finding.

## Confirmed root cause

The generic production `CooldownTracker<K>` stored failure state in an uncapped
`HashMap`. Inbound handshake failures supplied attacker-controlled
`PreAuthInboundKey { NetworkGroup, source IpAddr }` values. Neither elapsed retry
deadlines nor disconnects reclaimed entries, so sequential unique-source churn grew
process-lifetime memory. The original deterministic harness retained all 200,000
attempted identities.

The approved design is documented in `L3_NET_07_REMEDIATION_DESIGN.md`.

## Production files changed

- `indra-network/src/policy.rs`
- `indra-network/src/lib.rs`
- `indra-node/src/bin/node.rs`

Only inbound pre-authentication cooldown ownership changed. Audit harness/evidence
files changed under this evidence directory. No other production module was touched
for L3-NET-07.

## Dedicated bounded pre-auth type

`BoundedCooldownTracker<K>` contains:

- a `HashMap<K, BoundedCooldownValue>` for live identities;
- a `VecDeque<BoundedCooldownOrderEntry<K>>` for deterministic expiry/recency;
- explicit capacity, minimum/maximum cooldown, and idle-retention policy;
- monotonically assigned generations with bounded reindexing before `u64` wrap;
- an aggregate capacity-eviction counter.

The API is:

- `new(capacity, minimum, maximum, retention_ttl)`
- `record_failure_at(key, now)`
- `blocked_at(key, now)`
- `reset(key)`
- `prune_expired(now)`
- `len`, `capacity`, `evictions`, and `bookkeeping_len`

The existing generic `CooldownTracker` remains the type used by inbound post-auth,
outbound, and sync-source cooldowns.

## Reviewed hard bound

`PRE_AUTH_COOLDOWN_CAPACITY` is 4,096. This is a reviewed operational/security
resource bound, not a consensus parameter or unique mathematical constant. It is 64
times the 64-live-inbound cap and more than twenty recent endpoints per maximum
active validator while keeping attacker-controlled policy memory below approximately
0.6–0.8 MiB under the approved sizing model.

Permanent tests and the updated harness observed:

```text
live maximum:        4,096
bookkeeping maximum: 4,096
required ceilings:   4,096 live / 8,192 bookkeeping
```

## Cooldown and retention semantics

Recorded failures apply 2, 4, 8, 16, 32, 60, then 60 seconds. `retry_at` controls
blocking. `retention_deadline` is independently set to 60 seconds after the most
recent recorded failure. A lookup never refreshes recency, generation, cooldown, or
retention. Thus an attacker may wait past a retry deadline without losing escalation
history; 60 seconds with no newly recorded failure resets that history.

## Expiry, eviction, and stale-record safety

Every lookup/failure prunes idle-expired order records reachable from the ordered
front. A live value is deleted only when queued key and generation match and the live
retention deadline is expired. At capacity, expired records are reclaimed first;
otherwise exactly one least-recently-failed live identity is evicted before insertion.

Updates append a new generation record. Stale records cannot delete a refreshed live
entry. Before `u64` generation wrap, the tracker performs a bounded live-entry
reindex. Queue compaction occurs only after bookkeeping would exceed twice capacity;
it rebuilds from at most 4,096 live entries. After every public operation the live
map is at most 4,096 and order bookkeeping at most 8,192. There is no unbounded heap,
metrics label map, persistence, background sweep, or attacker-history-sized scan.

## Concurrency model

Production retains the existing `Arc<Mutex<InboundCooldowns>>`. Pre-auth lookup,
failure insertion, expiry, eviction, and exact-key reset execute while holding that
mutex. No second lock, task, actor, or sweeper was introduced. The permanent test
runs concurrent updates through the mutex for 100 repetitions and asserts both bounds
after every insertion; no transient over-capacity or corruption occurred.

## Attack regressions

### Original 200,000-source attack

Before: 200,000 attempted, 200,000 retained.

After, updated standalone harness:

```text
REMEDIATED: unique_keys=200000 live=4096 maximum_live=4096 bookkeeping=4096 maximum_bookkeeping=4096 hard_cap=4096 bookkeeping_cap=8192
```

### IPv4 churn

100,000 distinct exact IPv4 identities were recorded through the production
`InboundCooldowns::pre_auth` type. Live state never exceeded 4,096 and bookkeeping
never exceeded 8,192.

### IPv6 `/32` churn

200,000 exact IPv6 identities within `2001:db8::/32` were recorded. Every key retained
the existing `/32` group plus exact-address semantics. Maximum live/bookkeeping were
4,096/4,096.

### Approved self-eviction residual

Source A was placed in cooldown, followed by one cache worth of newer failed IPv6
identities. A was deterministically evicted, then received a fresh two-second initial
failure cooldown. State remained at or below both bounds. This is the reviewed
bounded degradation; no global bucket, group-only key, or fail-closed policy was
added.

### Recent legitimate identity and event ordering

A recently refreshed legitimate source survived eviction of older churn entries.
Failure then successful-auth reset removed only its exact key. Successful reset then
a later failure created a new cooldown, proving serialized last-event behavior.

## Post-auth and validator isolation

The post-auth field remains `CooldownTracker<PostAuthInboundKey>`. Outbound and sync
cooldowns also remain generic `CooldownTracker` instances. No pre-auth path references
or mutates `PeerManagerActor::limiters_by_validator`.

Unchanged regressions passed for:

- one authenticated validator sharing one 80-vote budget;
- the 81st frozen-bucket vote being rejected;
- different validators retaining independent budgets;
- disconnect/reconnect not resetting validator budget;
- 20 votes/second refill with 49 ms rejection and 50 ms acceptance;
- same-validator connection tie-break and stale-disconnect replacement safety;
- inbound live/per-IP caps, handshake semaphore, timeout, unknown/invalid auth, and
  successful handshake behavior.

## Wire, authentication, and consensus scope

- Canonical/wire semantics changed: **no**.
- Handshake transcript or validator authentication semantics changed: **no**.
- Validator identity or network-group key semantics changed: **no**.
- Consensus semantics changed: **no**.
- Validator message/rate-limit semantics changed: **no**.
- Persistence/disk state added: **no**.

## Memory and complexity bound

Total pre-auth cooldown state is O(4,096), including a live map capped at 4,096 and
ordering records capped at 8,192. Lookup/reset are average O(1). Insert, expiry, and
capacity eviction are amortized O(1). Occasional compaction/reindex is O(4,096), never
O(total historical attacker keys).

## Residual risk

A sufficiently distributed attacker can churn about one cache worth of newer failed
identities to evict an older cooldown. Existing 64-inbound, three-per-IP, 50-handshake,
and ten-second timeout controls still govern simultaneous work. Aggregate handshake
attempt rate and cryptographic DoS remain explicitly deferred; L3-NET-07 removes the
unbounded state vector only.

## Validation results

- `cargo test -p indra-network`: PASS — 148 passed, 1 ignored; integration 4 passed.
- `cargo test -p indra-core`: PASS — 148 passed; integration 21 passed.
- `cargo test -p indra-consensus`: PASS — 59 passed; integration 5 passed.
- `cargo test -p indra-node`: PASS — library 280 passed, 5 ignored; node binary 85
  passed; integration 15 passed.
- `cargo test --workspace`: PASS, including all non-ignored workspace and doc tests.
- `cargo test --workspace --no-run`: PASS.
- `cargo fmt --all -- --check`: PASS.
- `git diff --check`: PASS.
- Updated L3-NET-07 release harness: PASS, 200,000 inputs -> 4,096 live and 4,096
  bookkeeping maximum.
- Bounded cooldown focused unit tests: PASS (8).
- Production pre-auth attack/concurrency tests: PASS (6), including 100 concurrency
  repetitions.
- Focused diff reverse-application check: PASS.

Ignored tests are pre-existing explicit hardware/performance benchmarks and were not
silently treated as executed.

## Focused diff review notes

The focused diff includes only the dedicated bounded tracker/export, the pre-auth
instantiation and regressions, and the updated audit harness/report. It intentionally
excludes unrelated pre-existing dirty-tree changes. Independent review should verify
I1–I12 and preserve the accepted self-eviction residual rather than broadening this
patch into global handshake or group policy.
