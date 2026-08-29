# Quorum boundary and finality evidence

Production uses exactly (`indra-core/src/types/primitives.rs:381-393`):

```text
total != 0 && (signed as u128) * 3 > (total as u128) * 2
```

There is no division, rounded-BPS decision, equality acceptance, validator-count
fallback or overflowing `u64` product. Snapshot construction rejects a weight
sum exceeding `u64` (`indra-core/src/types/consensus_snapshot.rs:300-307`).

| total | rejected through | minimum accepted |
|---:|---:|---:|
| 3 | 2 | 3 |
| 4 | 2 | 3 |
| 10,001 | 6,667 | 6,668 |
| 18,446,744,073,709,551,615 | 12,297,829,382,473,034,410 | 12,297,829,382,473,034,411 |

For strict quorums A and B, `|A∩B| >= |A|+|B|-W > W/3`. The exact audit
harness enumerates all signer subsets for 4-equal and 7-unequal sets and checks
the theorem for 200 validators and `u64::MAX` total. Production tests independently
cover totals 1..=100,000 and the 10,001-stake floor-rounding trap
(`indra-consensus/src/qc.rs:927-1035`).

Classification: **PASS**.
