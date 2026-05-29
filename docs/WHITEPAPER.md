# INDRA Protocol
## A Post-Quantum Monetary Settlement Network

**Version 1.8 — Pre-release draft**
**Bonkai and team**

---

## Abstract

INDRA is a pre-mainnet Layer 1 blockchain protocol implementing a
conservative monetary settlement network designed around post-quantum
cryptographic assumptions. It addresses a specific vulnerability present
in all major blockchain systems currently in production: the eventual
susceptibility of elliptic-curve digital signatures to Shor's algorithm
running on a cryptographically relevant quantum computer.

INDRA implements NIST FIPS 204 (ML-DSA, parameter set Dilithium2)
alongside classical Ed25519 in a hybrid signature scheme for all
transactions, ensuring security under both classical and quantum threat
models simultaneously. Consensus finality uses Dilithium2-only Quorum
Certificates — fully post-quantum. Transaction amounts are confidential,
secured by Pedersen commitments and Bulletproof range proofs.

**Important scope note:** INDRA transaction *ownership* and consensus
*finality* are post-quantum secure. Transaction *amount confidentiality*
uses classical Ristretto255 elliptic-curve cryptography — a known and
acknowledged limitation documented in Section 7.3. A quantum adversary
cannot steal funds or forge consensus, but could potentially determine
hidden transaction amounts from historical data. This distinction is
stated clearly here and not buried.

The monetary policy is simple and immutable: one billion INDRA,
all pre-minted at genesis and locked in a protocol reward reserve,
released deterministically to validators through block rewards over
approximately one hundred years. No new supply is ever created after
genesis. No coins were pre-allocated to any person or entity. Every
INDRA is earned by securing the network.

INDRA is written entirely in Rust. All code is open source. The
implementation has undergone preliminary internal review. A professional
third-party security audit is required and planned before mainnet launch.
This document is a pre-release technical specification, not a production
deployment announcement.

---

## 1. Problem Statement

### 1.1 Long-lived digital value and the quantum migration problem

Digital monetary assets are increasingly held as long-term stores of
value. Bitcoin, created in 2009, is now held by sovereign wealth funds,
publicly listed corporations, and hundreds of millions of individuals
who intend to retain their holdings for years or decades. Records
created on blockchains today — property transfers, procurement
commitments, identity attestations — may need to remain cryptographically
verifiable for thirty to fifty years.

All major blockchains in production use elliptic-curve cryptographic
signatures. Bitcoin uses ECDSA on secp256k1. Ethereum uses the same.
Most proof-of-stake networks use Ed25519 or BLS12-381. The security of
these schemes depends on the computational hardness of the elliptic-curve
discrete logarithm problem.

In 1994, Peter Shor published an algorithm demonstrating that a
sufficiently capable quantum computer can solve the discrete logarithm
problem in polynomial time. A quantum computer executing Shor's algorithm
can derive a private key from an observed public key. For any blockchain
whose addresses or public keys are visible on-chain, this means funds
could be spent by an adversary without knowledge of the private key.

### 1.2 Uncertain but material timeline

The timing of cryptographically relevant quantum computers remains
genuinely uncertain. Current systems operate at 1,000 to 2,000 physical
qubits with high error rates. Breaking ECDSA-256 is estimated to require
thousands of stable logical qubits, accounting for error correction
overhead — a threshold meaningfully beyond current hardware.

IBM's published roadmap describes a path toward fault-tolerant quantum
computing with progress expected through the 2030s, but exact capability
timelines involve substantial technical uncertainty. Independent academic
estimates vary considerably.

What matters for infrastructure design is not predicting the exact date
of the threat but recognising that monetary infrastructure has long
migration timelines. A blockchain launched today will have users,
institutional holders, and on-chain records in 2040. The prudent
engineering response is to design for post-quantum security now, not to
schedule a migration for when the threat becomes acute. Migrations of
core cryptographic assumptions in widely deployed systems are slow,
contentious, and frequently incomplete.

### 1.3 The NIST response

The United States National Institute of Standards and Technology
concluded its post-quantum cryptography standardisation process in
August 2024 with the publication of three final standards: FIPS 203
(ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA). These are the
first government-standardised post-quantum algorithms intended for
general deployment.

FIPS 204 (ML-DSA, based on CRYSTALS-Dilithium) specifies a digital
signature algorithm whose security rests on the hardness of the
Module Learning With Errors problem. This problem is believed to resist
attack by both classical and quantum computers. The Dilithium2 parameter
set provides 128-bit post-quantum security.

INDRA implements FIPS 204 at the Dilithium2 parameter set for all
transaction signatures. This is not a custom or experimental
cryptographic construction — it is an implementation of a published
government standard.

### 1.4 Why existing blockchains face migration difficulty

Upgrading an existing blockchain's signature scheme requires changing
the core cryptographic assumptions that every participant, smart
contract, exchange integration, and institutional custody system was
built around. For Bitcoin specifically, this would require a hard fork —
a protocol change requiring genuine adoption by miners, node operators,
economic participants, and the broader ecosystem. Bitcoin's history
with hard forks (Bitcoin Cash, Bitcoin SV) illustrates the political
and technical difficulty of such changes.

Additionally, Bitcoin has a specific structural vulnerability: coins
held at pay-to-public-key (P2PK) addresses, including a substantial
portion of early mining rewards, have their public keys directly exposed
on-chain. These are vulnerable to quantum key derivation without any
further transaction occurring.

INDRA does not face a migration problem. Post-quantum signatures are
the only signature scheme for transactions. The protocol was designed
with this assumption from the beginning.

### 1.5 Design goals

INDRA was designed to satisfy the following properties:

1. **Post-quantum security for transaction ownership.** All transaction
   signatures must remain secure against quantum adversaries.

2. **Amount confidentiality.** Transaction amounts must not be visible
   to observers of the public blockchain under classical adversaries.
   Post-quantum amount confidentiality is a known limitation and
   future goal — see Section 7.3.

3. **Monetary simplicity.** The supply schedule must be simple,
   deterministic, and immutable — not subject to governance votes.

4. **Absolute finality.** Transactions must reach irreversible
   settlement without probabilistic confirmation delays.

5. **Open validator participation.** Anyone meeting the stake
   requirement can secure the network, without permission or
   identity verification.

6. **Mobile accessibility.** Delegation of stake must be possible
   from low-cost smartphone hardware.

---

## 2. Technical Architecture

### 2.1 Overview

INDRA is implemented in Rust. The workspace consists of:

```
indra-crypto        Post-quantum and classical cryptography
indra-bulletproofs  Zero-knowledge range proof implementation
indra-core          Protocol types, serialisation, primitives
indra-state         State machine, UTXO set, epoch logic
indra-consensus     BFT consensus, mempool, proposer election
indra-network       P2P networking and gossip protocol
indra-storage       Persistent block store and state snapshots
indra-node          Node binary and JSON-RPC server
indra-cli           Command-line wallet and validator tools
indra-ffi           C-compatible FFI bridge for mobile wallets
```

### 2.2 Transaction signature scheme

Every INDRA transaction carries two signatures:

**Ed25519 (classical):** 32-byte public key, 64-byte signature,
128-bit classical security. Implemented via ed25519-dalek 2.x.

**Dilithium2 / ML-DSA (post-quantum):** 1,312-byte public key,
approximately 2,420-byte signature, 128-bit post-quantum security,
NIST FIPS 204. Implemented via pqcrypto-dilithium 0.5.

Both signatures must verify for a transaction to be accepted. Under
a classical adversary, Ed25519 provides the primary security guarantee.
Under a quantum adversary capable of breaking Ed25519, Dilithium2
provides the security guarantee. An adversary must break both
simultaneously to forge a transaction.

**Transaction size:** A typical INDRA confidential transaction carries
approximately 5-6 KB of data, including both signatures (~3.8 KB),
Bulletproof range proof (~674 bytes), UTXO commitments, and nullifiers.
INDRA is a settlement network, not a high-frequency payment processor.
Transaction sizes are acceptable for this use case. Mobile wallets do
not sync full block history — they query their own UTXOs via RPC, so
the signature size does not affect mobile user experience.

### 2.3 Consensus signatures — Dilithium2-only QCs

INDRA's consensus layer uses Dilithium2 (NIST FIPS 204) exclusively
for Quorum Certificate verification. A QC is the cryptographic
evidence that a supermajority of validators agreed on a block.

Each QC contains one Dilithium2 signature per signing validator.
Verification is O(n) in validator count. Benchmarked on Apple
M-series hardware (single-threaded, release build):

```
Validators   QC verify time   Per signature
10           ~1ms             ~89µs
50           ~4ms             ~98µs
100          ~9ms             ~94µs
150          ~13ms            ~88µs
200          ~12ms            ~63µs

Block time:             6,000ms
QC overhead (150v):     ~13ms
QC as % of block time:  0.13%
```

QC verification consumes less than 0.15% of block time at the
target validator set size. It is not a performance bottleneck.
Production nodes may parallelise verification across cores for
further reduction.

BLS12-381 aggregate signatures were considered during development
for their O(1) verification efficiency. They were deliberately
removed because BLS12-381 is an elliptic-curve pairing, broken by
Shor's algorithm. Dilithium2-only QCs make consensus finality fully
post-quantum at the cost of linear verification time — the correct
tradeoff for a conservative settlement network.

**Quantum security properties:**

| Component | Scheme | Quantum-safe |
|-----------|--------|-------------|
| Transaction signatures | Ed25519 + Dilithium2 | Yes (hybrid) |
| QC finality proofs | Dilithium2 only | Yes |
| Block hashing | SHA-256 | Partial (Grover, 2x) |
| Pedersen commitments | Ristretto255 | No (classical EC) |

Transaction ownership and consensus finality are fully post-quantum.
Amount confidentiality uses classical cryptography — this is an
acknowledged limitation described in Section 7.3.

### 2.4 Confidential transactions

INDRA transaction amounts are hidden using Pedersen commitments on
the Ristretto255 group:

```
C = v·G + r·H
```

where G and H are independent generators, v is the amount, and r
is a randomly chosen blinding factor known only to the sender and
receiver. The commitment perfectly hides v and is computationally
binding against classical adversaries.

Bulletproof range proofs alongside each output prove that the
committed value lies in [0, 2^64) without revealing the value.
Proof size is approximately 674 bytes. Proof generation on server
hardware takes approximately 300-500ms.

**Mobile performance note:** Bulletproof generation on mobile
devices has not yet been systematically benchmarked across
representative hardware. For use cases where proof generation
time is unacceptable, INDRA supports public (non-confidential)
transactions that omit the Bulletproof entirely. Benchmarks
across representative Android and iOS hardware will be published
before mainnet.

### 2.5 UTXO model

INDRA uses an Unspent Transaction Output model. Each UTXO represents
a unit of value owned by a specific public key. Spending a UTXO
produces a nullifier recorded permanently on-chain. Double-spending
is cryptographically impossible: once a nullifier exists, any
transaction attempting to spend the same UTXO is rejected.

### 2.6 BFT consensus

INDRA uses Tendermint-style Byzantine Fault Tolerant consensus.

**Absolute finality:** Once a block is committed, it is final. No
forks, no reorganisations.

**Safety threshold:** The network tolerates up to one-third of
total validator stake being Byzantine. Consensus requires 66.67%
of total stake to agree on a block.

**Block time:** 6 seconds. Transactions reach irreversible
settlement within one block period.

**VRF proposer election:** Block proposers are selected via a
Verifiable Random Function keyed on the previous block hash,
providing unpredictable but publicly verifiable leader election.

**Block pruning:** Validators run in pruned mode by default,
retaining the last 50,000 blocks (~300 MB). The full state
database (UTXO set, validator set) is always retained. Archive
nodes (block explorers) retain all blocks. Validator history
is recorded on all nodes, not only on the validator's own device.

---

## 3. Token Economics

### 3.1 Supply model

All one billion INDRA are created at the genesis block. No new
supply is ever created after this point. The total supply can only
decrease over time through transaction fee burn.

```
Hard cap:            1,000,000,000 INDRA
Decimals:            8 (1 INDRA = 100,000,000 Spark)
Post-genesis supply: Zero new INDRA ever created
Supply direction:    Decreasing (fee burn)
```

The hard cap is enforced as a constitutional invariant in the
protocol. Every block application asserts that total supply does
not exceed one billion INDRA. This cannot be disabled by governance.

### 3.2 Genesis allocation and the locked reserve mechanism

```
Validator Rewards Pool   1,000,000,000 INDRA   100%
  All INDRA pre-minted at genesis, locked in protocol.
  Released deterministically via block rewards over ~100 years.
  Earned by whoever secures the network.
  No pre-allocation to any person or entity.
```

**How the locked reserve works:** The validator rewards pool is
not held by any private key or multisig. All 1,000,000,000 INDRA
exist in the protocol state from the genesis block. Block rewards
are distributed automatically by the protocol code according to
the immutable schedule: `block_reward_at_height(h)` returns the
exact reward for each block, credited to the block proposer by the
state machine. No human intervention is required or possible.

This is identical in principle to Bitcoin's block subsidy, with
the distinction that INDRA pre-mints all coins at genesis rather
than creating new coins at each block. The economic effect is
identical. No entity holds the private key to this reserve — it
is distributed by code, not by custodians.

Every INDRA must be earned by running infrastructure that secures
the network. There is no foundation pre-mine, no team allocation,
no investor reserve, and no operational bootstrap. The founders
hold no pre-mined INDRA. Like all participants, they earn block
rewards by running validator nodes.

**Ecosystem sustainability:** The absence of a foundation pre-mine
raises a legitimate question: how are audits, legal costs, and
infrastructure funded? Honestly, these are funded by the founders
from personal resources during the bootstrap phase, supplemented
by voluntary ecosystem contributions and grants as the network
matures. This is the same model Bitcoin followed. It is a real
constraint and not a solved problem. The founding team's incentive
alignment is direct: INDRA succeeds or they earn nothing. This
is intentional.

### 3.3 Block reward schedule

Rewards are distributed from the locked reserve — not newly
created supply. The reward per block follows a schedule of flat
periods and halvings:

```
Era 1  Year 1-4    ~11.89 INDRA/block    250,000,000 INDRA
Era 2  Year 4-8    ~5.94 INDRA/block     125,000,000 INDRA
Era 3  Year 8-16   ~2.97 INDRA/block     125,000,000 INDRA
Era 4  Year 16-24  ~1.49 INDRA/block      62,500,000 INDRA
Era 5+ Halves every 8 years thereafter
```

Era 1 releases approximately 25% of the validator rewards pool
over four years. This front-loading is deliberate: high early
rewards attract validators during the critical bootstrap period.

**Early validator concentration:** With a small initial validator
set, Era 1 rewards accrue to a small number of operators. This
mirrors Bitcoin's early mining concentration — Satoshi mined a
substantial fraction of early blocks before others joined. The
design is intentional: early participants take the highest risk
(unaudited software, no price, no liquidity) and earn the highest
rewards. The schedule is fully public from genesis. Anyone can
join from block 0 on equal terms.

Early-stage block rewards are intentionally high to incentivise
bootstrap participation. As the validator set grows, per-validator
rewards normalise. Specific yield projections are not published
as they depend on adoption variables outside the protocol's control.

### 3.4 Fee model

All transaction fees are split at the protocol level:

```
50% burned permanently
50% distributed to validators proportional to stake
```

No treasury share. No governance share. As transaction volume
grows, fee revenue supplements block rewards and net supply
decreases.

**Monetary dynamics:** In the early phase, circulating supply
grows as the locked reserve releases block rewards. Total supply
is hard-capped and can only decrease via fee burn. In a mature
high-transaction phase, fee burn may exceed new circulation,
making circulating supply net-deflationary. INDRA is positioned
as a store of value, not a medium of exchange — deflationary
pressure is an intentional design choice consistent with this
positioning, not a flaw. Validators earn from both block rewards
(fixed in INDRA terms) and fee revenue (grows with adoption).
This two-component reward structure reduces reliance on either
component alone.

### 3.5 Anti-concentration

**Saturation is disabled below 20 active validators.**
During the bootstrap phase, all validators receive full
proportional rewards. This ensures the network can start
correctly before saturation mechanics become meaningful.

Above 20 validators, the saturation point is:

```
saturation_point = total_active_stake / active_validator_count
```

Validators above the saturation point receive diminishing
marginal rewards. This makes visible concentration economically
inefficient.

This mechanism does not prevent hidden coordination among
operators who split stake across multiple validators. No protocol
mechanism can fully prevent this without becoming identity-governed.
The saturation curve reduces visible concentration and is
complemented by transparency tooling in the wallet.

### 3.6 No monetary governance

INDRA has no on-chain governance for monetary parameters.
Protocol changes occur through INDRA Improvement Proposals —
public proposals, open debate, validator signalling, and genuine
ecosystem consensus via software upgrade adoption. No single
group can impose monetary changes.

---

## 4. Privacy Model and Compliance

### 4.1 Amount confidentiality

INDRA hides transaction amounts. The sender, recipient, and
transaction graph are visible on-chain (public keys are public).
What is hidden is the specific amount transferred.

This provides meaningful privacy for legitimate financial
activity under a classical adversary. It does not provide full
anonymity — transaction graph analysis can still reveal
relationships between addresses.

### 4.2 What confidential transactions do not hide

- Sender and recipient public keys are public
- Transaction existence is public
- Transaction timing is public
- The fact that a specific UTXO was spent is public

### 4.3 Compliance and disclosure

INDRA supports optional view keys for selective disclosure to
auditors, regulators, or exchanges. A public (non-confidential)
transaction mode omits Bulletproof range proofs and reveals
amounts in plaintext — for use with regulated intermediaries.

Sanctions screening and anti-money-laundering obligations are
handled at the application layer, as with Bitcoin and Ethereum.

---

## 5. Validator Network

### 5.1 Open participation

Any entity can register as a validator. There is no permission
process, no identity verification, no KYC, and no hard minimum
stake requirement. Admission to the active consensus set is
determined purely by stake ranking — the top N validators by
total backing (own stake plus delegations) are active at any
given epoch.

**No hard minimum stake.** The only floor is the dust limit
(0.001 INDRA) to prevent spam registrations. The effective
minimum to enter the active set is the stake of the lowest
currently active validator — a market-determined number that
adjusts automatically as the network grows.

**Active set size grows with the network.** As more INDRA is
staked, more validator slots open. This ties decentralisation
directly to economic security: more stake = more security =
safely support more validators.

```
Total staked    Max active validators
< 1M INDRA      20 validators
< 10M INDRA     50 validators
< 50M INDRA     100 validators
< 200M INDRA    200 validators
< 500M INDRA    350 validators
≥ 500M INDRA    500 validators
```

**How to join as a validator:**
1. Register by staking any amount above the dust limit
2. Attract delegation from INDRA holders to boost total backing
3. At the next epoch boundary (~30 minutes): if your total
   backing ranks in the top N, you enter the active set
4. No application, no approval, no waiting list beyond stake ranking

**Displacement:** If another validator accumulates more total
backing than you, they may displace you from the active set at
the next epoch reselection. You remain registered (waiting) —
your stake is not returned or slashed. You can re-enter by
gaining more delegation. This is stake competition, not
punishment.

**Genesis validators** are pre-registered in the genesis block
and form the initial active set regardless of stake amount.
They are the founding operators who bootstrap the chain.

### 5.2 Validator lifecycle

```
REGISTERED → ACTIVE → UNBONDING → EXITED
                    ↘ SLASHED (equivocation only)
```

**Registered:** Staked minimum, submitted registration. Enters
active set at next epoch boundary.

**Active:** Participates in consensus, proposes blocks when elected
by VRF, earns block rewards and fee rewards.

**Unbonding:** 30-hour lock after undelegation. Cannot participate
in consensus. Earned rewards remain claimable.

**Exited:** Stake returned. May re-register anytime.

**Slashed:** Double-signed (equivocation). 10% of stake burned.
Forced exit from active set.

### 5.3 Block proposer election

```
proposer_seed = VRF_prove(previous_block_hash, validator_vrf_key)
proposer       = weighted_selection(active_validators, proposer_seed)
```

Selection weighted by stake. VRF output is publicly verifiable
but unpredictable in advance.

### 5.4 Reward calculation

**Block rewards** distributed at each epoch boundary (~30 min):

```
epoch_block_reward = 300 × block_reward_at_current_era

validator_share = epoch_block_reward
                × (validator_stake / total_active_stake)
                × saturation_adjustment(...)
```

**Commission split:**
```
if no delegators:
    validator_keeps = total_reward

if delegators present:
    commission    = total_reward × commission_rate
    delegator_pool = total_reward - commission
    each_delegator = delegator_pool × (delegator_stake / total_delegated)
```

All reward distribution is automatic. Validators cannot
intercept, delay, or redirect delegator rewards.

### 5.5 Slashing

INDRA's slashing model is deliberately minimal. Only intentional
equivocation results in stake being burned.

```
Offence                  Penalty           Notes
────────────────────────────────────────────────────────────────
Miss block as proposer   Lost reward only  Not punished.
Offline (any duration)   No rewards        Stake never burned.
                         while offline     Come back → earn again.
Double-signing a block   10% of stake      Intentional malicious
(equivocation)           burned            act. Forced exit.
```

**Philosophy:** Earn when you work, nothing when you don't.
No stake is burned for being offline — ever. A validator who
runs four hours per day earns proportionally to those hours.
Infrastructure failures are not punished. Only deliberate
betrayal of consensus is slashed.

This follows Bitcoin's model and explicitly rejects the
centralisation pressure of punitive downtime slashing.

**Validator portability:** A validator's identity is derived
deterministically from their 24-word recovery phrase. Moving
to new hardware requires only entering the phrase — same
validator ID, same stake, same history. No registration process.
No downtime penalty for hardware transitions.

**Key architecture (v1):** Consensus signing key and wallet key
are derived from the same phrase using domain-separated derivation.
Key separation (hot consensus key vs cold withdrawal key,
following the Ethereum model) is planned for a future version
before mainnet stake reaches significant value.

**Delegator slashing:** Delegators share in slashing proportional
to their delegation. Choose validators with no equivocation history.

### 5.6 Anti-concentration

**Saturation mechanism (soft nudge, not enforcement):**
Above 20 active validators, rewards are subject to a saturation
curve:

```
saturation_point = total_active_stake / active_validator_count
Below saturation: 100% reward efficiency
Above saturation: efficiency = saturation_point / validator_stake
```

This makes visible stake concentration economically inefficient.
It does not prevent Sybil splitting — a sophisticated actor can
operate multiple validators under different identities and bypass
the curve. This is acknowledged. No on-chain mechanism can solve
Sybil without becoming identity-governed, which INDRA rejects.
The saturation curve deters lazy concentration; transparency
tooling in the wallet complements it for sophisticated actors.

**Dynamic active set as the primary anti-concentration mechanism:**
The more meaningful protection is the stake-ranked active set
itself. As the network grows, more validator slots open (up to
500 at full maturity). Delegation allows community participants
to collectively boost smaller validators into the active set,
providing an organic check on concentration that no fixed
mechanism can replicate.

**QC size limits:**
Maximum QC signers: 500 validators
Maximum QC size: ~1.2 MB (500 × ~2,420 bytes)
Within the 2 MB protocol limit.
Verification time at 500 validators: ~50ms (0.8% of block time).

### 5.7 Delegation — earning yield from any device

```
Minimum delegation:     Dust limit (0.001 INDRA protocol floor)
                        Each validator sets their own minimum above this
                        Default: no minimum (accept any amount)
Maximum delegation:     No limit
Unbonding period:       30 hours
Commission range:       0-20% (set by each validator)
Reward frequency:       Each epoch (~30 minutes)
Key custody:            Delegator retains full custody always
```

**Delegation boosts validators into the active set.**
A small validator with many delegators can have higher total
backing than a large self-staking operator. The community can
collectively vote validators in and out of the active set
simply by choosing where to delegate. This is the most
powerful decentralisation mechanism in the protocol — no
governance vote, no permission, just economic signal.

**Delegation is non-custodial.** The validator cannot spend,
redirect, or access delegated funds. Delegation is a cryptographic
instruction to the protocol — not a transfer of custody.

**Rewards are automatic.** Protocol distributes at each epoch.
Validators cannot intercept or redirect delegator rewards.
Commission is deducted by the protocol automatically.

**Split delegation supported.** Delegators can split across
multiple validators to spread risk and support decentralisation.

**Commission changes prospective.** Changes apply from next
epoch only. Current epoch uses previously advertised rate.

**Undelegation:** 30-hour unbonding. No rewards during unbonding.
Funds return automatically after unbonding completes.

INDRA is designed so that, if adoption and liquidity emerge,
delegation can be accessible from low-cost mobile devices.
Whether this becomes practically meaningful depends on factors
outside the protocol's control: token price, validator reliability,
wallet availability, and local regulatory treatment of staking.

---

## 6. Target Context

### 6.1 Store of value

INDRA's primary purpose is a quantum-safe store of value:
fixed supply (decreasing via fee burn), post-quantum durability,
global portability (6-second settlement), 8 decimal places.

For holders considering a long-term digital asset, the quantum
vulnerability of classical blockchain signatures is a real,
uncertain-timeline risk. INDRA is designed to address this risk
for transaction ownership. Amount confidentiality under quantum
adversaries is not yet addressed — see Section 7.3.

### 6.2 Settlement and remittances

6-second irreversible settlement with confidential amounts and
low fees. India receives approximately $125 billion in remittances
annually through services charging 2-5% with 1-3 day settlement.
INDRA's settlement economics are more favourable on both dimensions
if an adoption ecosystem emerges — which is not guaranteed.

Financial privacy for remittances reflects a legitimate interest
in personal financial privacy, not regulatory evasion.

### 6.3 South Asia and mobile access

India, Pakistan, Bangladesh, and Sri Lanka together have over
one billion smartphone users, many without access to traditional
yield-bearing financial instruments. INDRA's delegation model
is designed to be accessible from mobile hardware.

The practical realisation depends on exchange liquidity, wallet
availability, regulatory clarity, and ecosystem maturity —
conditions that do not currently exist and cannot be promised.
The protocol architecture supports mobile delegation. The
ecosystem required to make it practically useful is the work
of the phases below.

### 6.4 Government records (future stage)

INDRA's UTXO model and nullifier mechanism make double-selling
cryptographically impossible. This has application to land
registry and procurement records. This requires substantial
policy design work and is a future stage, not a current
capability. The technical foundation is in place.

---

## 7. Current Status and Limitations

### 7.1 Development status

INDRA is a pre-mainnet protocol. Implementation is complete:
35 test suites, zero failures, zero compiler warnings, zero
lint errors. Running on a private four-node testnet. Not yet
subjected to public adversarial conditions.

### 7.2 Security review status

The implementation has undergone preliminary internal review.
An independent security review was conducted prior to this
publication. A professional third-party audit by an independent
security firm is required and planned before mainnet launch.
The audit report will be published in full.

Unit tests catch implementation bugs. They are not a substitute
for fuzzing, adversarial testnet conditions, formal verification,
or professional cryptographic review. None of these have yet
occurred.

### 7.3 Known limitations

**Amount confidentiality is not post-quantum.** This is stated
in the Abstract and repeated here for clarity. INDRA protects
fund *ownership* and consensus *finality* against quantum
adversaries. It does not protect transaction *amounts* against
a quantum adversary. Ristretto255 Pedersen commitments are
quantum-vulnerable. A sufficiently capable quantum computer
could determine historical transaction amounts. This does not
enable theft of funds. Post-quantum commitment schemes exist
but are not yet standardised for deployment. This limitation
will be addressed in a future protocol version as the field
matures.

**Bulletproof generation on mobile is unbenchmarked.** Proof
generation on server hardware takes 300-500ms. Performance on
low-end Android devices common in target markets (Moto G,
Redmi, etc.) has not been measured. Preliminary estimates
suggest 2-5 seconds on mid-range hardware. For users where
this is unacceptable, public (non-confidential) transactions
are available. Systematic mobile benchmarks will be published
before mainnet.

**Early validator concentration.** Era 1 releases 250 million
INDRA over four years. With a small initial validator set,
rewards concentrate among early participants. This is
intentional and mirrors Bitcoin's early mining concentration.
Early validators take the highest risk and earn the highest
rewards. The schedule is public from genesis — anyone can
join from block 0.

**Economic security model (structural):**
An attack on INDRA requires controlling more than one-third of
total staked supply. At any given token price P:

```
Attack cost = 34% × total_staked_INDRA × P
Attacker's stake slashed: 10% of their stake if detected

Example (illustrative, no price assumed):
  10M INDRA staked → attack requires 3.4M INDRA
  100M INDRA staked → attack requires 34M INDRA
  500M INDRA staked → attack requires 170M INDRA
```

The cost of attack scales directly with total staked supply and
token price. A formal economic security analysis with attack
cost vs. maximum extractable value will be published with the
security audit before mainnet.

**No smart contracts.** INDRA is a settlement layer. This
is a deliberate design choice, not a roadmap item.

**Public testnet not yet launched.** Consensus bugs often
emerge at scale under adversarial conditions. A four-node
private testnet cannot surface them. A minimum three-month
public testnet with open validator participation is required
before mainnet.

**Key separation not yet implemented.** v1 uses a unified
key derived from the 24-word phrase. Hot/cold key separation
is planned before mainnet stake reaches significant value.

---

## 7b. Minimum System Requirements

```
CPU:      2 cores (any modern processor, 2015 or newer)
RAM:      4 GB minimum / 8 GB recommended
Storage:  10 GB free minimum (pruned mode, default)
          500 GB+ for archive nodes (block explorers)
Network:  10 Mbps stable upload and download
          Port 30303 open for P2P
          Static IP recommended but not required
Uptime:   No minimum — validators earn proportional to uptime
          No penalty for being offline
OS:       macOS 12+, Ubuntu 20.04+, Windows 10+ (64-bit)
```

Default (pruned) mode retains the last 50,000 blocks (~300 MB)
plus the state database (~200 MB). Validator history is stored
on all network nodes — not only on the validator's own device.
A validator can move to new hardware, re-enter their 24-word
phrase, resync from the network, and resume with the same
identity and full history intact.

---

## 8. Roadmap

Milestones, not dates. Each milestone completes before the next.

**Phase 1 — Protocol implementation (current)**
Core protocol in Rust, post-quantum hybrid signatures,
Dilithium2-only QC consensus, confidential transactions,
BFT consensus, v7.1 economics, block pruning, CLI tooling,
iOS wallet with Rust FFI bridge, 35 test suites passing.

**Phase 2 — Public testnet**
Private testnet stable with four validators. Public bootstrap
nodes in at least three geographic regions. Public testnet
open to all validators. Testnet faucet. Public block explorer.
Android wallet. Node setup application. Minimum three months
sustained public testnet before proceeding.

**Phase 3 — Audit and hardening**
Professional security audit by independent firm. All findings
resolved and published. Fuzz testing of codec, state machine,
and cryptographic operations. Network stress testing. Mobile
Bulletproof benchmarks published. Economic security analysis
published. Hot/cold key separation implemented.

**Phase 4 — Mainnet**
Reproducible genesis ceremony with publicly verifiable genesis
hash. Bootstrap nodes operational. Wallets available on App
Store and Play Store. Block explorer live. IIP process open.

**Phase 5 — Ecosystem**
Exchange integrations as demand warrants. TypeScript SDK.
Government record pilot design. Academic partnerships.

---

## 9. Team

INDRA Protocol was designed and built by Bonkai and a small
team of engineers. The code is public and the design has been
examined independently.

The founders hold no pre-mined INDRA. There is no team
allocation, no foundation reserve, and no operational bootstrap.
The founders earn INDRA the same way as every other participant:
by running validator nodes. This is encoded in the protocol —
the genesis block contains no pre-mine.

A protocol's security derives from its mathematical properties
and open-source implementation, not from the credentials of
its creators.

Contact: indraprotocol@protonmail.com
Repository: github.com/jyothisarath096/indra

---

## 10. Technical Appendix

### A. Cryptographic primitives

| Primitive | Use | Security | Quantum-safe | Library |
|-----------|-----|----------|-------------|---------|
| Ed25519 | Tx classical sig | 128-bit | No | ed25519-dalek 2.x |
| Dilithium2/ML-DSA | Tx PQ sig | 128-bit PQ | Yes | pqcrypto-dilithium 0.5 |
| Dilithium2/ML-DSA | QC finality sigs | 128-bit PQ | Yes | pqcrypto-dilithium 0.5 |
| Pedersen/Ristretto255 | Amount hiding | Classical only | No (acknowledged) | curve25519-dalek 4.x |
| Bulletproofs | Range proofs | Classical only | No (acknowledged) | indra-bulletproofs |
| SHA-256 | Hashing | 128-bit* | Partial | sha2 |
| VRF/Ed25519 | Proposer election | 128-bit | No | custom |
| BLS12-381 | (removed from consensus) | — | — | — |

*Grover's algorithm reduces SHA-256 effective security to ~64-bit
under a quantum adversary. Considered acceptable at this parameter size.

### B. Protocol constants (v7.1)

```
Hard cap:                   1,000,000,000 INDRA
Spark per INDRA:            100,000,000 (8 decimals)
Block time:                 6 seconds
Blocks per year:            5,256,000
Epoch duration:             300 blocks (~30 minutes)
Consensus quorum:           66.67% of total stake
BFT safety threshold:       <33.33% Byzantine stake
Min validator stake:        None (dust limit only: 0.001 INDRA)
                            Active set admission by stake ranking
Effective min stake:        Lowest active validator's total backing
                            (market-determined, updates each epoch)
Max active validators:      20 → 50 → 100 → 200 → 350 → 500
                            (grows with total staked supply)
Min delegation:             Dust limit (validator sets own floor)
Unbonding period:           30 hours
Default prune window:       50,000 blocks (~300 MB)
Era 1 block reward:         ~11.89 INDRA/block
Era 1 duration:             4 years (21,024,000 blocks)
Era 2 duration:             4 years
Era 3+ duration:            8 years per era
Fee burn:                   50% of all fees
Fee to validators:          50% of all fees
Slash — double sign:        10% of stake
Slash — offline:            No penalty (lost rewards only)
Saturation threshold:       Active when validators > 20
                            saturation_point = total_stake / active_count
```

### C. QC verification benchmark

Measured on Apple M-series hardware, single-threaded, release build:

```
Validators   Total time   Per signature
10           ~1ms         ~89µs
50           ~4ms         ~98µs
100          ~9ms         ~94µs
150          ~13ms        ~88µs
200          ~12ms        ~63µs

Block time: 6,000ms
QC overhead at 150 validators: ~13ms (0.13% of block time)
```

QC verification is not a performance bottleneck.

### D. Quantum threat model

| Attack vector | Threat | INDRA response |
|---------------|--------|----------------|
| Break Ed25519 tx sig | Forge transactions | Dilithium2 still protects |
| Break Dilithium2 tx sig | Forge transactions | Ed25519 still protects |
| Quantum attack on QC | Forge consensus | Dilithium2-only QC — fully PQ |
| Break Pedersen commitment | Reveal hidden amounts | Does not enable theft |
| Grover on SHA-256 | Weaken hashing | 2x speedup only, acceptable |

### E. Security review

Preliminary internal review completed. Independent review conducted
prior to publication. Professional third-party audit required before
mainnet. Audit report will be published in full.

---

## References

1. Shor, P.W. (1994). Algorithms for quantum computation. FOCS 1994.
2. NIST (2024). FIPS 204 — ML-DSA. https://csrc.nist.gov/pubs/fips/204/final
3. NIST (2024). Post-Quantum Cryptography Standardization. https://csrc.nist.gov/pqcrypto
4. Nakamoto, S. (2008). Bitcoin: A Peer-to-Peer Electronic Cash System. https://bitcoin.org/bitcoin.pdf
5. Bunz, B. et al. (2018). Bulletproofs. IEEE S&P 2018.
6. Buchman, E. (2016). Tendermint. University of Guelph.
7. Government of India (2023). National Quantum Mission. https://dst.gov.in/nqm
8. IBM (2023). IBM Quantum Roadmap. https://www.ibm.com/quantum/blog/large-scale-ftqc
9. World Bank (2024). Migration and Development Brief: Remittances.
10. CRYSTALS-Dilithium Team (2021). Algorithm Specifications. https://pq-crystals.org/dilithium/

---

*INDRA Protocol — Pre-release working draft v1.8*
*This is a technical specification, not a financial instrument prospectus.*
*Protocol parameters may change before mainnet.*
*This document does not constitute investment advice.*