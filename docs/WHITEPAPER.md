# INDRA Protocol
## A Post-Quantum Monetary Settlement Network

**Version 1.5 — Pre-release draft**
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
models simultaneously. Transaction amounts are confidential, secured by
Pedersen commitments and Bulletproof range proofs. Consensus is achieved
via a Tendermint-style Byzantine Fault Tolerant protocol with six-second
absolute finality.

The monetary policy is simple and immutable: one billion INDRA, all pre-minted at genesis and locked in a
protocol reward reserve, released deterministically to validators
through block rewards over approximately one hundred years. No new
supply is ever created after genesis. No coins were pre-allocated
to any person or entity. Every INDRA is earned by securing the network.

INDRA is written entirely in Rust. All code is open source. The
implementation has undergone preliminary internal and AI-assisted review.
A professional third-party security audit is required and planned before
mainnet launch. This document is a pre-release technical specification,
not a production deployment announcement.

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

1. **Post-quantum security for transactions.** All transaction
   signatures must remain secure against quantum adversaries.

2. **Amount confidentiality.** Transaction amounts must not be
   visible to observers of the public blockchain.

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
simultaneously to forge a transaction — a significantly stronger
property than either scheme alone.

The larger signature sizes (Dilithium2 public key: 1,312 bytes vs
Ed25519: 32 bytes) are acceptable for a settlement network where
security takes precedence over bandwidth optimisation. Transaction
throughput requirements for a monetary settlement layer are orders
of magnitude lower than those of a high-frequency payment processor.

### 2.3 Consensus signatures — Dilithium2-only QCs

INDRA's consensus layer uses Dilithium2 (NIST FIPS 204) exclusively
for Quorum Certificate verification. A QC is the cryptographic
evidence that a supermajority of validators agreed on a block.

Each QC contains one Dilithium2 signature per signing validator.
Verification iterates all signatures — O(n) in validator count.
At the target validator set of 50-150 validators, QC
verification adds a small overhead per block. Internal benchmarks
on Apple M-series hardware indicate this overhead is well within
acceptable bounds for a 6-second block time. Formal benchmark
results will be published before mainnet alongside the security
audit report.

BLS12-381 aggregate signatures were considered during development
for their O(1) verification efficiency. They were deliberately
removed because BLS12-381 is an elliptic-curve pairing, broken by
Shor's algorithm. Using BLS for consensus finality would introduce
a classical cryptographic dependency in the critical path — 
inconsistent with INDRA's post-quantum design goals.

The Dilithium2-only approach makes QC verification fully
post-quantum at the cost of linear verification time. This is the
correct tradeoff for a conservative settlement network.

**Quantum security properties:**

| Component | Scheme | Quantum-safe |
|-----------|--------|-------------|
| Transaction signatures | Ed25519 + Dilithium2 | Yes (hybrid) |
| QC finality proofs | Dilithium2 only | Yes |
| Block hashing | SHA-256 | Partial (Grover, 2x) |
| Pedersen commitments | Ristretto255 | No (classical EC) |

Transaction ownership and consensus finality are fully
post-quantum. Amount confidentiality uses classical cryptography
and is not yet post-quantum — this is the one acknowledged
limitation, described in Section 7.3.

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
This prevents creation of outputs with negative values, which would
allow counterfeiting.

INDRA implements Bulletproofs natively in the indra-bulletproofs
crate, built on curve25519-dalek 4.x. Proof size is approximately
674 bytes. Proof generation on server hardware takes approximately
300-500ms. Proof generation on mobile devices has not yet been
systematically benchmarked across representative hardware — this
will be documented before mainnet.

### 2.5 UTXO model

INDRA uses an Unspent Transaction Output model. Each UTXO represents
a unit of value owned by a specific public key. Spending a UTXO
produces a nullifier recorded permanently on-chain. Double-spending
is cryptographically impossible: once a nullifier exists, any
transaction attempting to spend the same UTXO is rejected.

### 2.6 BFT consensus

INDRA uses Tendermint-style Byzantine Fault Tolerant consensus.

**Absolute finality:** Once a block is committed, it is final. No
forks, no reorganisations. This differs fundamentally from Bitcoin's
probabilistic finality, where a transaction requires multiple
subsequent blocks to be considered practically irreversible.

**Safety threshold:** The network tolerates up to one-third of
total validator stake being Byzantine (malicious or faulty).
Consensus requires 66.67% of total stake to agree on a block.

**Block time:** 6 seconds. Transactions reach irreversible
settlement within one block period.

**VRF proposer election:** Block proposers are selected via a
Verifiable Random Function keyed on the previous block hash,
providing unpredictable but publicly verifiable leader election.

**Current validator set:** Four validators on the private testnet.
The public testnet will be open to any validator meeting the
minimum stake requirement.

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
not exceed one billion INDRA. This assertion cannot be disabled by
governance. Changing it requires a hard fork — a software change
requiring genuine adoption across the ecosystem.

### 3.2 Genesis allocation

```
Validator Rewards Pool   1,000,000,000 INDRA   100%
  Locked in protocol at genesis.
  Released deterministically via block rewards over ~100 years.
  Earned by whoever secures the network.
  No pre-allocation to any person or entity.
  Founders earn INDRA the same way as everyone else: by validating.
```

Every INDRA must be earned by running infrastructure that
secures the network. There is no foundation pre-mine, no team
allocation, no investor reserve, and no operational bootstrap.
This follows Bitcoin's distribution model exactly: the network's
first participants earn the most, and the schedule is public and
fixed so that anyone can participate from genesis on equal terms.

The founders hold no pre-mined INDRA. Like all participants,
they earn block rewards by running validator nodes. This is the
strongest possible alignment between builders and network: the
protocol succeeds or it does not, and the builders succeed or
they do not, together.

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
rewards attract validators during the critical bootstrap period
when network security is most fragile and transaction volume is
lowest. As the network matures and fee revenue grows, block
reward dependence decreases.

### 3.4 Fee model

All transaction fees are split at the protocol level:

```
50% burned permanently
50% distributed to validators proportional to stake
```

No treasury share. No governance share. As transaction volume
grows, fee revenue supplements block rewards, and net supply
decreases. At sufficient scale, fee burn may exceed block reward
distribution, making INDRA net deflationary in circulating terms.

### 3.5 Anti-concentration

Validator rewards are subject to a saturation mechanism. The
saturation point is total active stake divided by a target
validator count. Validators with stake below the saturation
point receive full rewards. Validators above the saturation
point receive diminishing marginal rewards.

**Saturation is disabled below 20 active validators.**
During early bootstrap when validator count is small, all
validators receive full proportional rewards. This ensures
the network can bootstrap correctly before saturation
mechanics become meaningful.

Above 20 validators, the saturation point is:

```
saturation_point = total_active_stake / active_validator_count
```

Validators above the saturation point receive diminishing
marginal rewards. This makes visible concentration economically
inefficient without penalising the bootstrap phase.

This mechanism does not prevent hidden coordination among
operators who split stake across multiple validators. No protocol
mechanism can fully prevent this without becoming identity-governed.
Transparency tooling in the wallet complements the saturation curve.

### 3.6 No monetary governance

INDRA has no on-chain governance for monetary parameters.
There is no mechanism by which token holders can vote to change
the supply schedule, inflation, or fee split. These are encoded
as protocol constants. Protocol changes occur through INDRA
Improvement Proposals — public proposals, open debate, validator
signalling, and genuine ecosystem consensus via software upgrade
adoption. No single group can impose monetary changes.

---

## 4. Privacy Model and Compliance

### 4.1 Amount confidentiality

INDRA hides transaction amounts. The sender, recipient, and
transaction graph are visible on-chain (public keys are public).
What is hidden is the specific amount transferred.

This provides meaningful privacy for legitimate financial
activity: a business's treasury movements are not visible to
competitors; an individual's savings transfers are not visible
to surveillance systems. It does not provide full anonymity —
transaction graph analysis can still reveal relationships
between addresses.

### 4.2 What confidential transactions do not hide

- Sender and recipient public keys are public
- Transaction existence is public
- Transaction timing is public
- The fact that a specific UTXO was spent is public

Users seeking stronger anonymity properties would need to
combine INDRA with additional privacy techniques (address
rotation, timing variation, mixing). INDRA does not natively
provide these.

### 4.3 Compliance and disclosure

INDRA supports optional view keys. A sender can generate a
view key for a specific transaction or address that allows
a third party — an auditor, regulator, or exchange — to
verify the transaction amount without access to the spending
key. This enables selective disclosure for compliance purposes
without compromising amount privacy for the general public.

Exchanges and institutions operating in regulated jurisdictions
may use a public (non-confidential) transaction mode, which
omits Bulletproof range proofs and reveals amounts in plaintext.
Users transacting through regulated onramps may be required
to use this mode by the relevant intermediary.

Sanctions screening and anti-money-laundering obligations are
handled at the application layer (exchanges, wallets, payment
services) rather than at the base protocol layer. This is the
same architecture as Bitcoin and Ethereum, where base-layer
protocols do not enforce compliance — intermediaries do.

The base protocol does not guarantee anonymity and does not
prevent lawful disclosure by parties who hold the relevant keys.

---

## 5. Validator Network

### 5.1 Open participation

Any entity that stakes sufficient INDRA can operate a validator
node. There is no permission process, no identity verification,
no KYC requirement. The only requirement is economic: stake the
minimum amount and run the node software correctly.

```
Minimum validator stake:    100,000 INDRA
Adjustable range:           50,000 to 500,000 INDRA
Adjustment mechanism:       IIP process (not governance vote)
Adjustment timelock:        90 days minimum
```

The minimum stake is not a barrier to participation — it is an
alignment mechanism. Validators with skin in the game have a
financial incentive to behave correctly. Slashing penalises
misbehaviour by reducing the validator's own stake.

### 5.2 Validator lifecycle

A validator passes through the following states:

```
REGISTERED → ACTIVE → UNBONDING → EXITED
                    ↘ SLASHED (malicious behaviour)
```

**Registered:** Validator has staked the minimum amount and
submitted a registration transaction. Not yet producing blocks.
Enters the active set at the next epoch boundary.

**Active:** Validator participates in consensus, proposes blocks
when elected by VRF, signs precommit votes, and earns block
rewards and fee rewards proportional to stake.

**Unbonding:** Validator has submitted an undelegate transaction.
Stake is locked for the unbonding period (60 epochs, approximately
30 hours). Cannot participate in consensus during unbonding.
Rewards earned before unbonding remain claimable.

**Exited:** Unbonding period complete. Stake returned to validator's
wallet. Validator may re-register at any time by staking again.

**Slashed:** Validator committed a slashable offence (see 5.5).
A portion of stake is burned. Severe slashing (double-sign)
results in forced exit from the active set.

### 5.3 Block proposer election

At each block height, one validator is elected as proposer using
a Verifiable Random Function (VRF):

```
proposer_seed = VRF_prove(previous_block_hash, validator_vrf_key)
proposer       = weighted_selection(active_validators, proposer_seed)
```

Selection is weighted by stake: a validator with 2% of total stake
is elected as proposer approximately 2% of the time. The VRF
output is publicly verifiable — anyone can confirm the correct
validator was elected — but unpredictable in advance, preventing
targeted attacks on known future proposers.

### 5.4 Reward calculation

**Block rewards** are distributed at each epoch boundary
(every 300 blocks, approximately 30 minutes):

```
epoch_block_reward = blocks_per_epoch × block_reward_at_current_era
                   = 300 × current_era_reward

validator_share    = epoch_block_reward × (validator_stake / total_active_stake)
                   × saturation_adjustment(validator_stake, total_active_stake)
```

**Fee rewards** accumulate throughout the epoch:
Each transaction contributes 50% of its fee to the fee_reward_pool.
At epoch boundary, the pool is distributed proportionally by stake.

**Commission split:**
```
total_validator_reward = block_reward_share + fee_reward_share

if no delegators:
    validator_keeps = total_validator_reward

if delegators present:
    commission_amount  = total_validator_reward × commission_rate
    delegator_pool     = total_validator_reward - commission_amount
    validator_keeps    = commission_amount
    each_delegator_gets = delegator_pool × (delegator_stake / total_delegated)
```

Early-stage block rewards are intentionally high to incentivise
bootstrap participation when the validator set is small. As the
validator set grows and fee revenue matures, per-validator rewards
normalise. The exact yield depends on total staked supply, validator
count, and transaction volume — all of which evolve organically
as the network grows. Specific yield projections are not published
in this document as they depend on adoption variables outside the
protocol's control.

### 5.5 Slashing

INDRA's slashing model is deliberately minimal. Only one
category of behaviour results in stake being burned:
intentional equivocation (double-signing).

```
Offence                  Penalty           Notes
────────────────────────────────────────────────────────────────
Miss block as proposer   Lost reward only  No stake burned.
                                           Normal — not punished.

Offline (any duration)   No rewards        Stake never burned for
                         while offline     being offline. Come back
                                           online → earn again.

Double-signing a block   10% of stake      Intentional malicious act.
(equivocation)           burned            Requires deliberately
                                           signing two conflicting
                                           blocks. No honest validator
                                           ever triggers this.
                                           Forced exit from active set.
```

**The philosophy: earn when you work, nothing when you don't.**

INDRA does not slash validators for being offline. A validator
who can only run their node four hours per day earns
proportionally to those four hours. Their stake is never
touched for the time they are offline.

This follows Bitcoin's model. Miners who stop mining earn
nothing — they are not penalised for stopping. The economic
incentive to earn rewards is sufficient without the threat
of stake destruction for honest failures.

Punitive downtime slashing would centralise validation toward
only large professional operators with redundant infrastructure.
Individuals, researchers, and community members running nodes
on personal hardware would be systematically penalised for
normal infrastructure failures: power outages, ISP downtime,
hardware maintenance. INDRA explicitly rejects this design.

**Validator portability:**
A validator's identity is derived deterministically from their
24-word recovery phrase. The same phrase always produces the
same validator ID and signing keys. A validator can stop their
node, move to new hardware, enter their recovery phrase, and
resume with the same identity and accumulated stake. There is
no registration process and no downtime penalty for the
transition.

**Key architecture (v1):**
In the current implementation, the validator signing key and
wallet key are derived from the same 24-word phrase using
domain-separated derivation. This simplifies the user experience
at the cost of operational key separation.

A future protocol version will separate consensus signing keys
(hot keys, used for block signing) from withdrawal keys (cold
keys, controlling stake). This follows the Ethereum validator
model and reduces risk if a consensus key is exposed — an
attacker who obtains the signing key could trigger a double-sign
slash but could not steal the underlying stake. This separation
is planned before mainnet stake reaches significant value.

**Delegator slashing:**
Delegators share in slashing events proportional to their
delegation. If a validator double-signs and loses 10% of stake,
delegators lose 10% of their delegated portion. This creates
a meaningful selection incentive — choose validators with
no history of equivocation.

### 5.6 Saturation and anti-concentration

Validator rewards are subject to a saturation mechanism that
makes visible stake concentration economically inefficient:

```
saturation_point = total_active_stake / TARGET_VALIDATOR_COUNT
                 = total_active_stake / 200

reward_efficiency:
  validator_stake ≤ saturation_point:  100% efficiency
  validator_stake > saturation_point:  efficiency = saturation_point / validator_stake
```

**Example:**
```
Total active stake: 10,000,000 INDRA
Saturation point:   10,000,000 / 200 = 50,000 INDRA

Validator A (40,000 INDRA stake):
  Below saturation → 100% efficiency → full reward share

Validator B (100,000 INDRA stake):
  Above saturation → efficiency = 50,000/100,000 = 50%
  Earns half of what proportional stake would suggest
  
  This means B would earn more by splitting into two validators
  of 50,000 INDRA each — which is the intended incentive.
```

The saturation mechanism does not prevent hidden coordination
among colluding operators who split stake across multiple
validators under different identities. No protocol mechanism
can achieve this without becoming identity-governed.
The saturation curve reduces visible concentration and is
complemented by transparency tooling in the wallet interface.

**Validator set size limit:**
The protocol enforces MAX_QC_SIGNERS = 200. QCs with more than
200 signers are rejected. This keeps QC sizes manageable
(200 × ~2,420 bytes = ~484 KB maximum) and is consistent
with the target validator set size.

### 5.7 Delegation — earning yield from any device

Any INDRA holder can delegate to a validator without running
infrastructure.

```
Minimum delegation:     100 INDRA
Maximum delegation:     No limit
Unbonding period:       60 epochs (~30 hours)
Commission range:       0-20% (set by each validator)
Reward frequency:       Each epoch (~30 minutes)
Key custody:            Delegator retains full custody
                        Validator cannot access delegated funds
```

**The delegation flow on mobile:**
1. Open INDRA wallet on smartphone
2. Tap "Stake" tab
3. View validator list sorted by decentralisation score
   (uptime, stake share, commission, slash history)
4. Tap a validator → tap "Delegate"
5. Enter amount (minimum 100 INDRA)
6. Confirm with Face ID / fingerprint
7. Delegation active at next epoch boundary
8. Rewards accumulate and are claimable each epoch

**Delegation is non-custodial.**
The validator never holds the delegator's INDRA. Delegation
is a cryptographic instruction to the protocol. The validator
cannot spend, redirect, or access delegated funds. Private
keys remain in the delegator's device at all times.

**Rewards are automatic and validator-proof.**
The protocol calculates and distributes rewards at each epoch
boundary without validator intervention. Commission is deducted
by the protocol automatically. Validators cannot intercept,
delay, or redirect delegator rewards.

**Split delegation is supported.**
A delegator can split stake across multiple validators to
spread slashing risk and support decentralisation. For example,
500 INDRA to one validator and 500 to another in a different
geographic region.

**Commission changes apply prospectively.**
Rate changes take effect from the next epoch only. The current
epoch always uses the previously advertised rate. Delegators
can undelegate before a new rate takes effect.

**Undelegation:**
Undelegation is not instant. The 30-hour unbonding period
exists to prevent validators from being immediately abandoned
after a slash event. This gives the network time to process
the slash before delegators can exit.

During unbonding, delegated INDRA earns no rewards and cannot
be transferred. After unbonding completes, funds return to
the delegator's wallet automatically.

**Risk:**
Delegators share in validator slashing. Choose validators with
good uptime records and no slash history. The wallet surfaces
this information. A validator slashed for double-signing loses
10% of stake — including delegated stake.

INDRA is designed so that, if adoption and liquidity emerge,
delegation can be accessible from low-cost mobile devices
across South Asia and other regions with high smartphone
penetration but limited access to traditional yield-bearing
instruments. Whether this becomes practically meaningful
depends on factors outside the protocol's control: token
price, validator reliability, wallet availability, and
local regulatory treatment of staking income.

---

## 6. Target Context

### 6.1 Store of value

INDRA's primary purpose is a quantum-safe store of value. The
monetary policy is designed around four properties: scarcity
(fixed supply, decreasing over time), durability (post-quantum
signature scheme designed to remain secure across the quantum
transition), portability (global settlement in under 10
seconds), and divisibility (eight decimal places).

For holders considering a digital asset as a long-term store
of value, the quantum vulnerability of classical blockchain
signatures is a real, if uncertain-timeline, risk. INDRA
is designed to remove this risk.

### 6.2 Settlement and remittances

INDRA's absolute finality (6-second irreversible settlement)
makes it suitable for monetary settlement use cases. Cross-border
value transfer with confidential amounts and low fees may be
useful for remittance corridors where amount privacy is valued.

India receives approximately $125 billion in remittances
annually. Current transfer services charge 2-5% in fees with
1-3 day settlement times. INDRA's economics are more favourable
on both dimensions if an adoption ecosystem emerges.

Financial privacy for remittances reflects a legitimate
interest in conducting personal financial transactions without
exposing amounts to surveillance or targeted crime — not a
mechanism for regulatory evasion.

### 6.3 South Asia and mobile access

India, Pakistan, Bangladesh, and Sri Lanka together have over
one billion smartphone users, many without access to
traditional yield-bearing financial instruments. INDRA's
delegation model is designed to be accessible from mobile
hardware.

The practical realisation of this depends on exchange
liquidity, wallet availability, regulatory clarity, and
ecosystem maturity — conditions that do not yet exist and
cannot be promised. The protocol architecture supports
mobile delegation. The ecosystem required to make it
practically useful is the work of the phases described
in the roadmap below.

### 6.4 Government records (future stage)

Land registration fraud, tampered records, and double-selling
are persistent problems in South Asian property markets.
INDRA's UTXO model and nullifier mechanism make double-spending
(including double-selling of property) cryptographically
impossible. Post-quantum signatures ensure records remain
cryptographically verifiable over decades.

This application requires substantial policy design work:
identity handling, multi-party transaction structures, court
order interaction, stamp duty integration, and regulatory
framework. It is a future stage, not a current capability.
The protocol's technical foundation is in place. The policy
and institutional framework is not yet developed.

---

## 7. Current Status and Limitations

### 7.1 Development status

INDRA is a pre-mainnet protocol. The implementation is complete
and the test suite passes (35 test suites, zero failures, zero
compiler warnings, zero lint errors at time of writing). The
protocol is running on a private four-node testnet. It has not
yet been subjected to public adversarial conditions.

### 7.2 Security review status

The implementation has undergone preliminary internal review
and systematic AI-assisted security analysis. Twelve findings
were identified across consensus, cryptography, economics,
state machine, and serialisation categories. All twelve were
resolved before this publication.

**AI-assisted review is not equivalent to a professional
security audit.** It identifies design issues and common
vulnerability patterns but cannot substitute for manual
code review by experienced cryptographic engineers, fuzz
testing, adversarial testnet conditions, or formal verification.

A professional third-party security audit is required and
planned before mainnet launch. The audit report will be
published in full.

### 7.3 Known limitations

**Pedersen commitment scheme is not post-quantum.** Amount
hiding uses Ristretto255, which is quantum-vulnerable. A
quantum adversary could potentially determine hidden amounts.
This affects amount privacy, not transaction security. Post-quantum
commitment schemes exist but are not yet deployed in INDRA.

**Bulletproof generation time on mobile is not yet benchmarked.**
Preliminary estimates suggest 1-3 seconds on mid-range
smartphone hardware. Systematic benchmarking across
representative devices is required before production claims
can be made.

**Early validator concentration.** Era 1 releases 250 million
INDRA over four years. With a small initial validator set,
these rewards accrue to a small number of operators. This
mirrors Bitcoin's early mining concentration and resolves
through organic validator set growth. With a small initial validator set,
these rewards accrue to a small number of operators. This
mirrors Bitcoin's early mining concentration. Resolution
comes through organic validator set growth as rewards remain
attractive and the network develops.

**No smart contracts.** INDRA is a settlement layer. It does
not support arbitrary programmable computation. DeFi applications,
NFT protocols, and general-purpose computation are outside
its scope by design.

**Public testnet not yet launched.** The four-node private
testnet has demonstrated basic block production. Public testnet
with open validator participation, adversarial conditions, and
sustained operation has not yet occurred.

---

## 7b. Minimum System Requirements

To run an INDRA validator node:

```
CPU:      2 cores (any modern processor, 2015 or newer)
RAM:      4 GB minimum / 8 GB recommended
Storage:  50 GB SSD (chain grows over time)
          HDD is not recommended (too slow for state reads)
Network:  10 Mbps stable upload and download
          Port 30303 open for P2P (configurable)
          Static IP recommended but not required
Uptime:   No minimum requirement
          Validators earn proportional to time online
          No penalty for being offline
OS:       macOS 12+
          Ubuntu 20.04+ / Debian 11+
          Windows 10+ (64-bit)
```

A validator can run on a personal laptop, a home server,
a cloud VPS, or a university research machine. The minimum
hardware is modest by design — INDRA's consensus is not
computationally intensive. The primary requirement is a
stable internet connection when the node is running.

## 8. Roadmap

Milestones, not dates. Each milestone completes before the next begins.

**Phase 1 — Protocol implementation (current)**
Core protocol in Rust, post-quantum hybrid signatures,
confidential transactions, BFT consensus, v7.1 economics,
CLI tooling, iOS wallet with Rust FFI bridge, 35 test suites
passing with zero failures.

**Phase 2 — Public testnet**
Private testnet stable with four validators producing blocks.
Public bootstrap nodes in at least three geographic regions.
Public testnet open to all validators. Testnet faucet.
Public block explorer. Android wallet. Node setup wizard.
Minimum three months of sustained public testnet operation
before proceeding.

**Phase 3 — Audit and hardening**
Professional security audit by independent firm. All findings
resolved and published. Fuzz testing of codec, state machine,
and cryptographic operations. Network stress testing under
simulated adversarial conditions. Complete documentation.

**Phase 4 — Mainnet**
Reproducible genesis ceremony with publicly verifiable genesis
hash. Bootstrap nodes operational. Wallets available. Block
explorer live. IIP process open. Community governance of
protocol improvements through open proposals.

**Phase 5 — Ecosystem development**
Exchange integrations as demand warrants. TypeScript SDK for
developer ecosystem. Government record pilot design.
Academic partnerships on post-quantum cryptography.

---

## 9. Team

INDRA Protocol was designed and built by Bonkai and a small
team of engineers. The code is public and the design has been
examined independently.

The founders hold no pre-mined INDRA. There is no team
allocation, no foundation reserve, and no operational
bootstrap. The founders earn INDRA the same way as every
other participant: by running validator nodes that secure
the network. This is not a rhetorical position — it is
encoded in the protocol. The genesis block contains no
pre-mine. Every INDRA that exists was earned.

A protocol's security derives from its mathematical properties
and open-source implementation, not from the credentials of
its creators. The cryptographic guarantees of INDRA do not
depend on trusting any individual. They depend on published
mathematical constructions, open source code, and the
adversarial conditions of a public network over time.

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
| Pedersen/Ristretto255 | Amount hiding | Perfect hiding | No (acknowledged) | curve25519-dalek 4.x |
| Bulletproofs | Range proofs | 128-bit | No (acknowledged) | indra-bulletproofs |
| SHA-256 | Hashing | 128-bit* | Partial | sha2 |
| VRF/Ed25519 | Proposer election | 128-bit | No | custom |
| BLS12-381 | (removed from consensus) | — | — | — |

*Grover's algorithm provides quadratic speedup against SHA-256,
reducing effective security to 64-bit under a quantum adversary.
This is considered acceptable for hash functions at this parameter size.

### B. Protocol constants (v7.1)

```
Hard cap:                   1,000,000,000 INDRA
Spark per INDRA:            100,000,000
Block time:                 6 seconds
Blocks per year:            5,256,000
Epoch duration:             300 blocks
Consensus quorum:           66.67% of total stake
BFT safety threshold:       <33.33% Byzantine stake
Min validator stake:        100,000 INDRA
Min delegation:             100 INDRA
Unbonding period:           30 hours
Era 1 block reward:         ~11.89 INDRA/block
Era 1 duration:             4 years (21,024,000 blocks)
Era 2 duration:             4 years
Era 3+ duration:            8 years per era
Fee burn:                   50% of all fees
Fee to validators:          50% of all fees
Slash — double sign:        10% of stake
Offline (any duration):     No penalty — lost rewards only
```

### C. Security review summary

| Category | Findings | Resolved |
|----------|----------|----------|
| Consensus safety | 3 | 3 |
| Cryptographic correctness | 2 | 2 |
| Economic attacks | 3 | 3 |
| State machine | 2 | 2 |
| Serialisation safety | 1 | 1 |
| Operational | 1 | 1 |
| **Total** | **12** | **12** |

Full findings and resolutions: github.com/jyothisarath096/indra/docs/

A professional audit is planned before mainnet. The report will
be published in full.

### D. Quantum threat model summary

| Attack vector | Threat | INDRA response |
|---------------|--------|----------------|
| Break Ed25519 tx sig | Forge transactions | Dilithium2 still protects |
| Break Dilithium2 tx sig | Forge transactions | Ed25519 still protects |
| Quantum attack on QC | Forge consensus finality | No classical crypto in QC — Dilithium2 only |
| Break Pedersen commitment | Reveal hidden amounts | Does not enable theft |
| Grover on SHA-256 | Weaken hashing | 2x speedup only, acceptable |

---

## References

1. Shor, P.W. (1994). Algorithms for quantum computation: discrete
   logarithms and factoring. FOCS 1994.

2. NIST (2024). Module-Lattice-Based Digital Signature Standard.
   FIPS 204. https://csrc.nist.gov/pubs/fips/204/final

3. NIST (2024). Post-Quantum Cryptography Standardization.
   https://csrc.nist.gov/pqcrypto

4. Nakamoto, S. (2008). Bitcoin: A Peer-to-Peer Electronic Cash
   System. https://bitcoin.org/bitcoin.pdf

5. Bunz, B. et al. (2018). Bulletproofs: Short Proofs for
   Confidential Transactions and More. IEEE S&P 2018.

6. Buchman, E. (2016). Tendermint: Byzantine Fault Tolerance in
   the Age of Blockchains. University of Guelph.

7. Government of India (2023). National Quantum Mission.
   https://dst.gov.in/nqm

8. IBM (2023). IBM Quantum Development Roadmap.
   https://www.ibm.com/quantum/blog/large-scale-ftqc

9. World Bank (2024). Migration and Development Brief: Remittances.

10. CRYSTALS-Dilithium Team (2021). CRYSTALS-Dilithium Algorithm
    Specifications. https://pq-crystals.org/dilithium/

---

*INDRA Protocol — Pre-release working draft v1.5*
*This is a technical specification, not a financial instrument prospectus.*
*Protocol parameters may change before mainnet.*
*This document does not constitute investment advice.*