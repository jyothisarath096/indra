# Layer 2 Phase 8 — Validator topology and infrastructure concentration

## Executive result

No critical-stop condition was met. The exact strict-quorum predicate preserves
finalized safety for Byzantine stake below one third, and no modeled outage
below one third deterministically prevents QC formation. The material gap is
operational: consensus cannot identify common operators, providers, regions, or
ASNs, and it imposes no per-operator or per-validator voting-weight ceiling.

| Area | Classification | Result |
|---|---|---|
| Protocol quorum safety under correlated failures | **PASS** | Correlation does not change the strict stake-intersection proof; `<1/3` Byzantine stake cannot form conflicting strict-`>2/3` QCs. |
| Proposer liveness under correlated failures | **PASS** | With any online honest stake proposer probability remains positive; with `>2/3` online stake both proposer and QC progress remain possible. At `>=1/3` unavailable stake, QC liveness deterministically stops as designed. |
| Validator/operator concentration risk | **FINDING** | Common control is not represented or bounded. One operator can control multiple identities or one validator approaching/exceeding one third stake. |
| Cloud/region/ASN concentration risk | **OPEN** | These dimensions are absent from chain state and the repository does not provide a verified mainnet deployment map. |
| Launch-time topology readiness | **OPEN** | No mainnet validator/operator/provider/region allocation exists to test against an acceptance policy. A launch-time review is required. |

## 1. What the protocol knows

### Consensus-visible

The live validator record contains the hybrid identity-derived validator ID,
vote/VRF keys, self-stake, lifecycle status, VRF activation timing, a display
name, and an optional advertised `network_addr`
(`indra-state/src/validator.rs:67-121`). Validator records, including the
address, are encoded into state (`indra-state/src/validator.rs:124-185`). The
address can be changed at most once per epoch by an Active or Registered
validator and is committed back to state (`indra-state/src/delegation.rs:1556-1588`).

The immutable consensus snapshot is narrower: each member contains validator
ID, **self-stake consensus weight**, vote keys, VRF key/suite, and key activation
epoch; it contains no name or address (`indra-core/src/types/consensus_snapshot.rs:22-80`).
Snapshot validation caps membership at 200, rejects zero weights, recomputes the
total, and commits the canonical list/root
(`indra-core/src/types/consensus_snapshot.rs:206-245`). Snapshot construction
copies `validator.stake_spark`, not delegation, and sorts by validator ID
(`indra-state/src/chain.rs:629-701`).

### Locally visible

Nodes join current live `network_addr` metadata onto snapshot-authoritative
membership and keys for authenticated transport/discovery; the address is
explicitly not frozen in the snapshot (`indra-node/src/engine.rs:140-158`,
`indra-node/src/engine.rs:1444-1471`). Peer tables and observed socket addresses
therefore reveal IP-level topology locally, but this is observation, not a
consensus assertion of operator/provider ownership. On-chain addresses are fed
into discovery after address validation (`indra-node/src/bin/node.rs:908-954`).

### Not represented

No production structure or mutation path records a canonical operator ID,
beneficial owner, cloud/VPS provider, region, country, or ASN. The human-readable
genesis `name` is described only as an operator label and is not included in the
consensus snapshot (`indra-node/src/genesis.rs:154-181`). An IP address can be
externally mapped to infrastructure data, but the protocol neither commits nor
verifies that mapping.

Consequently INDRA cannot distinguish, from consensus state:

```text
20 validators / 20 operators
20 validators / 1 operator
20 validators / 1 cloud region
```

Distinct keys and identities prove distinct cryptographic principals, not
distinct organizations or failure domains.

## 2. Validator selection and concentration mechanics

The full registry is capped at 1,500 and the mature active set at 200; earlier
stake phases cap it at 20, 50, or 100 (`indra-core/src/types/primitives.rs:20-26`,
`indra-core/src/types/primitives.rs:250-293`). Active-set selection ranks
eligible validators by descending self-stake, with validator ID as tie-breaker.
The code explicitly excludes delegation from consensus/selection weight
(`indra-state/src/validator.rs:778-814`).

Registration requires only a minimum self-bond; the deposited UTXO's complete
value becomes `stake_spark` (`indra-state/src/delegation.rs:797-857`). Later
self-stake is checked-added without a protocol concentration ceiling
(`indra-state/src/delegation.rs:1176-1243`). Thus the practical maximum is
bounded by available issued value and `u64`, not by a per-validator fraction.
One validator can approach or exceed one third of total snapshot weight.

Delegation cannot create consensus-weight concentration in the current design:
delegated positions are economically associated with a validator, but snapshot
weight remains self-stake only. This audit found no weighting bug. Conversely,
monitoring only delegated stake would miss the relevant concentration risk.
Multiple validators under common control remain indistinguishable.

## 3. Exact model

The reproducible model is `topology_model.py`; it generated 363 result rows in
`topology_results.csv` using 100-digit Decimal arithmetic and no Monte Carlo.
Assumptions are machine-readable in `assumptions.json`.

At fixed mainnet `f=3/8`, an online stake fraction `h` has:

```text
P(at least one online proposer) = 1 - (5/8)^h
P(no online proposer for N rounds) = ((5/8)^h)^N
E(rounds to an online proposer) = 1 / (1 - (5/8)^h)
QC without failed/withholding stake iff 3h > 2
```

The split-invariant Praos probability makes these aggregate outage results
independent of how the online stake is divided among validator identities,
subject to the separately audited negligible finite threshold grid error.

### Deterministic correlated outages

| Failed stake | Honest online | QC possible? | P(online proposer) | Expected rounds | P(no proposer 5r) | 10r | 20r |
|---:|---:|:---:|---:|---:|---:|---:|---:|
| 5% | 95% | yes | 0.360138 | 2.7767 | 0.107258 | 0.011504 | 0.000132 |
| 10% | 90% | yes | 0.344924 | 2.8992 | 0.120631 | 0.014552 | 0.000212 |
| 20% | 80% | yes | 0.313400 | 3.1908 | 0.152588 | 0.023283 | 0.000542 |
| 25% | 75% | yes | 0.297073 | 3.3662 | 0.171613 | 0.029451 | 0.000867 |
| 30% | 70% | yes | 0.280359 | 3.5669 | 0.193010 | 0.037253 | 0.001388 |
| 1/3 | 2/3 | **no** | 0.268996 | 3.7175 | 0.208737 | 0.043571 | 0.001898 |
| 40% | 60% | **no** | 0.245728 | 4.0695 | 0.244141 | 0.059605 | 0.003553 |
| 50% | 50% | **no** | 0.209431 | 4.7749 | 0.308816 | 0.095367 | 0.009095 |

Proposer availability degrades smoothly; QC liveness has the hard boundary.
Exactly one-third failure leaves exactly two-thirds online, which fails the
strict predicate. Production uses the exact `signed*3 > total*2` comparison
with `u128` cross-products (`indra-core/src/types/primitives.rs:369-387`), and
both vote collection and QC verification call that predicate
(`indra-consensus/src/vote.rs:176-180`, `indra-consensus/src/qc.rs:229-274`).

The same table applies to an offline operator, provider, region, or ASN holding
the named stake fraction. Identity count does not repair a shared failure
domain.

## 4. Operator and correlated Byzantine control

For Byzantine fraction `beta`, the model separately computes coalition
eligibility, absence of an honest proposer, Byzantine-only proposer rounds, QC
blocking, and the accepted GR-01 publish/withhold upper-bound strategy.

| Byzantine stake | P(coalition eligible) | P(no honest proposer) | P(only Byzantine proposer) | Expected rounds to honest proposer | Can block QC? | GR-01 absolute next-height bias |
|---:|---:|---:|---:|---:|:---:|---:|
| 20% | 0.089718 | 0.686600 | 0.061600 | 3.1908 | no | 0.015774 |
| 25% | 0.110860 | 0.702927 | 0.077927 | 3.3662 | no | 0.025126 |
| 30% | 0.131512 | 0.719641 | 0.094641 | 3.5669 | no | 0.036917 |
| 32% | 0.139637 | 0.726438 | 0.101438 | 3.6555 | no | 0.042355 |

Below one third, withholding cannot deterministically block honest QC formation,
though it increases latency, creates proposer-only censorship opportunities,
and exercises the already accepted bounded GR-01 bias. At one third, withholding
becomes a deterministic QC veto. Safety requires Byzantine stake strictly below
one third; correlation does not weaken the mathematical intersection, but it can
make the assumed common-control fraction much larger than identity counts imply.

Splitting common-control stake conserves `P(any coalition proposer)` exactly in
the ideal model but creates multiple candidate outputs. For example, at 20%
stake `P(any)=0.089718` for 1, 5, 20, 100, or 200 identities, while
`P(multiple)` rises from zero for one identity to approximately 0.004131 for 200.
This is the operational-choice surface already bounded and accepted as GR-01;
topology metadata cannot detect the common controller.

## 5. Provider, region, ASN, and identity count

The provider/region/ASN scenarios in the CSV use the same exact outage model at
10–50% stake. A 20% shared-provider failure leaves QC possible but raises
expected online-proposer discovery to 3.19 rounds. A 30% failure leaves QC
possible at 70% online and 3.57 expected proposer rounds. Any shared domain at
one third or more deterministically prevents QC formation while nodes can still
elect proposals and advance only through stalled rounds.

The model explicitly compares 10 versus 100 identities sharing 35% provider
stake. Both have identical aggregate proposer probability and both halt QC if
that provider disappears. Therefore:

```text
many validator identities != infrastructure decentralization
```

A comparison such as “100 validators, one provider, 35% stake” versus “10
validators, independent providers, 35% stake” differs only in the correlation
assignment; validator count alone supplies no resilience evidence.

## 6. Network partitions

| Partition | Larger side QC? | Smaller side QC? | Outcome |
|---|:---:|:---:|---|
| 70/30 | yes | no | 70% side can finalize; 30% side can elect but cannot finalize. |
| 67/33 | yes | no | 67% is strictly above two thirds; 33% cannot finalize. |
| 66/34 | no | no | both sides can elect proposals; neither can finalize. |
| 60/40 | no | no | both sides stall without QCs. |
| 50/50 | no | no | both sides stall without QCs. |

No partition can give both sides strictly more than two thirds, so the strict
predicate prevents dual finalization assuming honest validators do not
double-sign. Proposer election alone does not imply progress: minority and
sub-quorum partitions continue to find eligible proposers probabilistically but
cannot certify their blocks.

## 7. Deployment evidence

The repository contains historical testnet evidence, not a mainnet topology.
`DEPLOYMENT_MANIFEST.md` records four equal-stake testnet-3 validators and four
public server IPs (`docs/DEPLOYMENT_MANIFEST.md:9-15`,
`docs/DEPLOYMENT_MANIFEST.md:47-54`). The Phase-6 signoff says those four nodes
formed a 3/3 full mesh and exposed live on-chain addresses
(`docs/PHASE6_FINAL_SIGNOFF.md:35-42`). It does not record verified operator
grouping, provider, region, country, or ASN. The checked-in release genesis is
explicitly called obsolete by the deployment document
(`docs/DEPLOYMENT_MANIFEST.md:3-7`).

Accordingly, current real-world infrastructure concentration is **OPEN**. IP
ownership or hosting geography could be researched externally, but such a
point-in-time lookup would remain operational evidence and would not establish
future mainnet diversity.

## 8. Mainnet operational controls

| Control | Classification | Reason |
|---|---|---|
| Launch-time stake/common-control concentration review | **REQUIRED BEFORE GENESIS** | The protocol cannot detect common control; any operator/failure domain at `>=1/3` can halt QC formation. |
| Operator disclosure of common control across validator IDs | **REQUIRED BEFORE GENESIS** | Identity count otherwise materially overstates decentralization. Disclosure is not cryptographically enforceable and must be reviewed as an assumption. |
| Genesis provider/region/ASN inventory | **REQUIRED BEFORE GENESIS** | Required to rule out a single known infrastructure outage controlling `>=1/3` stake. |
| Published validator diversity guidelines | **REQUIRED BEFORE GENESIS** | Converts the implicit correlated-failure assumption into an explicit launch criterion. |
| Continuous provider/region/ASN concentration monitoring | **RECOMMENDED OPERATIONAL CONTROL** | Addresses post-genesis moves and address changes; external enrichment is required. |
| Self-stake concentration alerts at 20%, 25%, 30%, and 1/3 | **RECOMMENDED OPERATIONAL CONTROL** | Provides warning before the deterministic QC-veto boundary. |
| Delegation concentration alert for consensus safety | **NOT REQUIRED** | Delegated stake is not consensus weight in this protocol; economic/reward concentration may still merit separate monitoring. |
| Consensus-enforced provider/operator caps | **NOT REQUIRED in this phase** | Provider identity is not objectively self-authenticating; arbitrary caps require separate governance/Sybil-resistance design. |

The existing validator requirements specify bandwidth and on-chain address
operation, but not provider/operator concentration limits
(`docs/MAINNET_VALIDATOR_REQUIREMENTS.md:1-18`,
`docs/MAINNET_VALIDATOR_REQUIREMENTS.md:55-82`). The four required-before-genesis
items above close an evidence/readiness gap; they do not claim consensus-level
enforcement.

## 9. Critical-stop review

* No `<1/3` correlated Byzantine coalition violated finalized safety.
* No outage leaving strictly more than two-thirds honest stake caused
  deterministic persistent liveness failure; proposer absence remains a
  geometric tail and QC remains possible.
* Consensus snapshot construction consistently uses self-stake, matching active
  selection; no delegation-weighting protocol defect was found.

The finding is therefore concentration observability and launch policy, not a
consensus arithmetic or weighting bug. No production remediation was attempted.
