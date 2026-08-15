# INDRA Protocol
## A Post-Quantum Blockchain for Monetary Settlement

**Version 2.0 — Pre-mainnet technical specification**

---

## Abstract

INDRA is a pre-mainnet Layer 1 blockchain protocol implementing a
conservative monetary settlement network designed around post-quantum
cryptographic assumptions. It addresses a specific vulnerability present
in all major blockchain systems currently in production: the eventual
susceptibility of elliptic-curve digital signatures to Shor's algorithm
running on a cryptographically relevant quantum computer.

INDRA implements NIST FIPS 204 (ML-DSA-87, the highest security parameter
set of CRYSTALS-Dilithium) alongside classical Ed25519 in a hybrid
signature scheme for all transactions, ensuring security under both
classical and quantum threat models simultaneously. Consensus finality
uses ML-DSA-87-only Quorum Certificates — fully post-quantum. Validator
transport is encrypted with hybrid X25519 + ML-KEM-1024 (NIST FIPS 203)
key encapsulation. The current OutputV1 transaction format stores authoritative
amounts and full hybrid owner keys publicly; checked-`u64` conservation and
dust validation are the sole monetary-validity rules.

**Important scope note:** INDRA transaction ownership requires exact
full-hybrid-key custody plus dual Ed25519 + ML-DSA-87 verification, and
consensus finality uses ML-DSA-87. These paths retain post-quantum security
through their PQ components. The current chain format does not
provide node-level owner or amount privacy: full nodes and raw block-data
observers can see OutputV1 owner/value metadata. Future transaction
privacy work is documented as planned, not implemented. This distinction
is stated clearly here and not buried.

The monetary policy is simple and immutable: one billion INDRA, all
pre-minted at genesis and locked in a protocol reward reserve, released
deterministically to validators through block rewards over approximately
one hundred years. No new supply is ever created after genesis. No coins
were pre-allocated to any person or entity. Every INDRA is earned by
securing the network.

INDRA is written entirely in Rust. All code is open source. The
implementation has undergone preliminary internal review. A professional
third-party security audit is required and planned before mainnet
launch. This document is a pre-release technical specification, not
a production deployment announcement.

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
Most proof-of-stake networks use Ed25519 or BLS12-381. The security
of these schemes depends on the computational hardness of the
elliptic-curve discrete logarithm problem.

In 1994, Peter Shor published an algorithm demonstrating that a
sufficiently capable quantum computer can solve the discrete logarithm
problem in polynomial time. A quantum computer executing Shor's algorithm
can derive a private key from an observed public key. For any blockchain
whose addresses or public keys are visible on-chain, this means funds
could be spent by an adversary without knowledge of the private key.

### 1.2 Uncertain but material timeline

The timing of cryptographically relevant quantum computers remains
genuinely uncertain. Current systems operate with high error rates and
limited logical qubits. Breaking ECDSA-256 is estimated to require
thousands of stable logical qubits with error correction — a threshold
meaningfully beyond current hardware.

What matters for infrastructure design is not predicting the exact date
of the threat but recognising that monetary infrastructure has long
migration timelines. A blockchain launched today will have users,
institutional holders, and on-chain records in 2040 and beyond. The
prudent engineering response is to design for post-quantum security now,
not to schedule a migration for when the threat becomes acute. Migrations
of core cryptographic assumptions in widely deployed systems are slow,
contentious, and frequently incomplete.

### 1.3 The NIST response

The United States National Institute of Standards and Technology
concluded its post-quantum cryptography standardisation process in
August 2024 with the publication of three final standards:

- **FIPS 203** (ML-KEM) — key encapsulation
- **FIPS 204** (ML-DSA) — digital signatures
- **FIPS 205** (SLH-DSA) — hash-based signatures

FIPS 204 (ML-DSA, based on CRYSTALS-Dilithium) specifies a digital
signature algorithm whose security rests on the hardness of the Module
Learning With Errors problem. This problem is believed to resist attack
by both classical and quantum computers. INDRA implements ML-DSA at the
highest security parameter set, ML-DSA-87, providing NIST security level
5 — equivalent to 256-bit post-quantum security.

FIPS 203 (ML-KEM) specifies a key encapsulation mechanism for hybrid
encryption. INDRA uses ML-KEM-1024 for validator-to-validator transport
encryption, combined with classical X25519.

INDRA's cryptographic choices are implementations of published government
standards, not custom or experimental constructions.

### 1.4 Why existing blockchains face migration difficulty

Upgrading an existing blockchain's signature scheme requires changing
the core cryptographic assumptions that every participant, exchange
integration, and institutional custody system was built around. For
Bitcoin, this would require a hard fork requiring genuine adoption by
all economic participants. Bitcoin's history illustrates the political
and technical difficulty of such changes.

INDRA does not face a migration problem. Post-quantum signatures are
the only signature scheme from genesis. The protocol was designed with
this assumption from the beginning.

### 1.5 Design goals

1. **Post-quantum security for transaction ownership.** All transaction
   signatures must remain secure against quantum adversaries.

2. **Post-quantum consensus finality.** All consensus signatures use
   ML-DSA-87. Quorum certificates are fully post-quantum.

3. **Post-quantum transport.** Validator-to-validator communication
   uses ML-KEM-1024 for key encapsulation.

4. **Future transaction privacy.** The current OutputV1 format exposes
   owner/value metadata to raw-chain observers. A future OutputV2 design
   must provide owner and amount privacy without compromising INDRA's
   post-quantum security posture — see Section 7.3.

5. **Monetary simplicity.** The supply schedule must be simple,
   deterministic, and immutable — not subject to governance votes.

6. **Absolute finality.** Transactions must reach irreversible
   settlement without probabilistic confirmation delays.

7. **Open validator participation.** Anyone meeting the stake
   requirement can secure the network.

8. **On-chain governance.** Protocol parameters adjustable by
   validator supermajority through a cryptographically sound
   commit-reveal mechanism.

---

## 2. Technical Architecture

### 2.1 Codebase overview

INDRA is implemented in Rust. The workspace:

```
indra-crypto        Post-quantum and classical cryptography
indra-core          Protocol types, serialisation, primitives
indra-state         State machine, UTXO set, epoch logic, governance
indra-consensus     BFT consensus, mempool, proposer election
indra-network       P2P networking and authenticated gossip
indra-storage       Block store, state snapshots, epoch history
indra-node          Node binary and JSON-RPC server
indra-rpc           RPC handler and dispatch
indra-cli           CLI wallet, stake manager, governance CLI
indra-keystore      Encrypted validator/wallet key-file support
indra-ffi           C-compatible FFI bridge for mobile wallets
indra-bench         Benchmarks and scale experiments
```

### 2.2 Transaction signature scheme

Every INDRA transaction carries two signatures:

**Ed25519 (classical):** 32-byte public key, 64-byte signature,
128-bit classical security. Implemented via ed25519-dalek 2.x.

**ML-DSA-87 (post-quantum):** NIST FIPS 204, security level 5,
approximately 256-bit post-quantum security. Public key: 2,592 bytes.
Signature: approximately 4,627 bytes.

Both signatures must verify for a transaction to be accepted. Under a
classical adversary, Ed25519 provides the primary security guarantee.
Under a quantum adversary capable of breaking Ed25519, ML-DSA-87
provides the security guarantee. An adversary must break both
simultaneously to forge a transaction.

The upgrade from the earlier Dilithium2 parameter set to ML-DSA-87
(security level 5) was made during development to align with NIST's
final FIPS 204 specification and achieve maximum post-quantum security.

### 2.3 Consensus signatures — ML-DSA-87 Quorum Certificates

INDRA's consensus layer uses ML-DSA-87 exclusively for Quorum
Certificate verification. A QC is the cryptographic evidence that a
supermajority of validators agreed on a block.

Each QC contains one ML-DSA-87 signature per signing validator.
Verification is O(n) in validator count. BLS12-381 aggregate signatures
were considered for their O(1) verification efficiency. They were
deliberately removed because BLS12-381 is an elliptic-curve pairing,
broken by Shor's algorithm. ML-DSA-87-only QCs make consensus finality
fully post-quantum at the cost of linear verification time — the
correct tradeoff for a conservative settlement network.

### 2.4 Transport layer cryptography

Validator-to-validator P2P connections use a hybrid key encapsulation:

```
Session key = X25519(ephemeral) + ML-KEM-1024(ephemeral)
Encryption  = ChaCha20-Poly1305(session_key)
Auth        = ML-DSA-87(validator_identity_key)
```

Unknown peers are rejected at handshake. The transport provides
forward secrecy under both classical and quantum adversaries.

### 2.5 Quantum security summary

| Component | Scheme | Quantum-safe |
|-----------|--------|-------------|
| Transaction signatures | Ed25519 + ML-DSA-87 | Yes (hybrid) |
| QC finality proofs | ML-DSA-87 only | Yes |
| Validator transport | X25519 + ML-KEM-1024 | Yes (hybrid) |
| Block hashing | SHA-256 | Partial (Grover, 2x) |
| Transparent value conservation | Checked `u64` arithmetic | Information-theoretic arithmetic invariant |

Transaction ownership, consensus finality, and validator transport are
post-quantum secure. OutputV1 owner/value metadata is not hidden from raw-chain
observers. INDRA is transparent-amount and pseudonymous; value correlation can
deanonymize flows even without key reuse.

### 2.6 Transparent value validation

`OutputV1.value_spark` is authoritative public consensus data. Validators sum
inputs and outputs with checked `u64` arithmetic and require inputs to equal
outputs plus the public fee; any overflow fails consensus validation. Dust
rules reject uneconomic outputs. No transaction-value commitment, opening, or
range-proof system exists in the current protocol.

### 2.7 UTXO model

INDRA uses an Unspent Transaction Output model. Each UTXO represents
a unit of value owned by a specific public key. Spending a UTXO
atomically removes the referenced UTXO from the live set. Double-spending
is rejected because an already-consumed UTXO no longer exists, and any
transaction attempting to spend the same UTXO is rejected.

UTXO entries use one canonical genesis-native encoding. Nodes reject unknown
schema and storage formats rather than attempting compatibility conversion.

### 2.8 BFT consensus

INDRA uses Tendermint-style Byzantine Fault Tolerant consensus with
several enhancements:

**Absolute finality:** Once a block is committed, it is final. No
forks, no reorganisations.

**Safety threshold:** The network tolerates up to one-third of total
validator stake being Byzantine. Consensus requires 66.67% of total
stake to agree on a block.

**Block time:** 6 seconds. Transactions reach irreversible settlement
within one block period.

**VRF proposer election:** Block proposers are selected via a
Verifiable Random Function keyed on the previous block hash, providing
unpredictable but publicly verifiable leader election.

**Consensus stability fixes:** Three specific stability improvements
were implemented during testnet operation:

1. *Round synchronisation* — validators broadcast their current
   consensus round in Status messages; validators that fall behind
   due to restart or network disruption advance to match peers.

2. *Vote safety persistence* — the highest round and step voted is
   persisted to disk (`vote_safety.dat`) before each vote. On restart,
   the validator skips past rounds it already voted in, preventing
   equivocating votes that would cause peers to reject its participation.

3. *Proposal-driven round advancement* — when a validator receives a
   valid VRF-verified proposal for a higher round than its current
   round, it advances immediately to process the proposal, preventing
   round divergence from compounding over multiple restarts.

These fixes were identified and resolved during testnet operation.

**Block pruning:** Validators run in pruned mode by default, retaining
the last 50,000 blocks. The full state database (UTXO set, validator
set, governance state) is always retained via periodic snapshots.
Archive nodes retain all blocks.

### 2.9 Canonical state and storage format

INDRA persists one canonical mainnet state schema and one segmented block-store
format. Genesis, snapshots, epoch records, staking positions/tranches, and
governance state are produced directly in their current representations.
Unknown formats fail closed; the runtime contains no historical decoder,
converter, or migration ladder.

### 2.10 Discovery and operator trust boundaries

Peer discovery is layered rather than DNS-only. Nodes can use static
bootstrap peers, persisted peers, peer exchange, on-chain validator
network addresses, DNS seed A records with DNSSEC validation, and INDRA's
signed DNS discovery format.

Signed DNS discovery is INDRA's post-quantum analogue to Ethereum's
EIP-1459 idea: DNS transports a chunked node list, but the list itself is
signed with an independent ML-DSA-87 discovery key whose public key is
configured outside DNS. DNSSEC protects the transport path; the INDRA
signature protects against a compromised DNS operator publishing a forged
node list. Plain DNS A records remain a rollout fallback.

Operator keys are stored in encrypted `keys.json` files by default using
Argon2id password derivation and ChaCha20-Poly1305 authenticated
encryption. Plaintext keystores are not accepted. For mobile/FFI consumers,
production APIs use opaque in-process key handles so raw private keys do not
cross the C ABI boundary; no raw-key compatibility exports exist.

---

## 3. Token Economics

### 3.1 Supply model

All one billion INDRA are created at the genesis block. No new supply
is ever created after this point. The total supply can only decrease
over time through transaction fee burn.

```
Hard cap:            1,000,000,000 INDRA
Decimals:            8 (1 INDRA = 100,000,000 Spark)
Post-genesis supply: Zero new INDRA ever created
Supply direction:    Decreasing (fee burn only)
```

The hard cap is enforced as a constitutional invariant in the protocol.
Every block application asserts that total supply does not exceed one
billion INDRA. This cannot be overridden by governance.

### 3.2 Genesis allocation

```
Validator Rewards Pool   1,000,000,000 INDRA   100%
```

All 1,000,000,000 INDRA exist in protocol state from the genesis block,
locked in a reward reserve not controlled by any private key. Block
rewards are distributed automatically by the state machine according
to the immutable schedule. No human intervention is required or possible.

Every INDRA must be earned by running infrastructure that secures the
network. There is no foundation pre-mine, no team allocation, no investor
reserve. The founders hold no pre-mined INDRA. Like all participants,
they earn block rewards by running validator nodes.

### 3.3 Block reward schedule

Rewards are distributed from the locked reserve — not newly created
supply. The reward per block follows a flat-then-halving schedule:

```
Era    Period          Reward / block         Total released
─────────────────────────────────────────────────────────────
1      Year 1–4        11.892 INDRA           ~250,000,000 INDRA
2      Year 4–8         5.946 INDRA           ~125,000,000 INDRA
3      Year 8–16        2.973 INDRA           ~125,000,000 INDRA
4      Year 16–24       1.486 INDRA            ~62,500,000 INDRA
5+     Halves every 8 years thereafter
```

Era 1 releases approximately 25% of the total supply over four years.
High early rewards attract validators during the bootstrap period.
The reward schedule is immutable and cannot be changed by governance.

**Epoch rewards:** 300 blocks × 11.892 INDRA/block = 3,567.6 INDRA
distributed per epoch (~30 minutes) during Era 1.

### 3.4 Fee model

All transaction fees are split at the protocol level:

```
50%  burned permanently (reduces total supply)
50%  distributed to active validators proportional to stake
```

No treasury share. No governance allocation. As transaction volume
grows, fee revenue supplements block rewards and net supply decreases.

### 3.5 Validator set expansion

The maximum active validator count grows automatically with total
staked supply — not through governance votes:

```
Total staked          Max active validators
< 1,000,000 INDRA     20 validators
< 10,000,000 INDRA    50 validators
< 50,000,000 INDRA    100 validators
≥ 50,000,000 INDRA    200 validators
```

This ties decentralisation directly to economic security: more stake
means more security, which safely supports more validators. The maximum
is 200 validators, constrained by QC size requirements.

---

## 4. Privacy Model

### 4.1 Current owner/value privacy

INDRA's current OutputV1 format does not hide transaction owners or
amounts from raw-chain observers. Sender/recipient public keys,
transaction graph metadata, and `value_spark` output metadata are visible
to full nodes and anyone reading block/state data directly.

The existing RPC hardening prevents casual remote address surveillance
through public RPC endpoints, but that is not the same as protocol-level
transaction privacy.

### 4.2 What current RPC hardening does not hide

- Sender and recipient public keys are public
- Output value metadata is public in OutputV1
- Transaction existence is public
- Transaction timing is public
- The fact that a specific UTXO was spent is public

### 4.3 Current privacy boundary and future view-key work

INDRA exposes recipient hybrid public keys and authoritative value metadata to
anyone reading raw chain data directly. It is a transparent-amount,
pseudonymous model, not a full transaction-privacy model; amount correlation
can deanonymize flows.

Remote RPC-based legacy address scanning requires authorization: a caller
must prove ownership of the address before using the legacy UTXO/balance
scan methods. This closes casual remote surveillance through public RPC
endpoints, but it does not hide OutputV1 owner/value metadata from a full
node or anyone with raw block data.

Full owner-level transaction privacy against node-level observers
requires a future protocol upgrade using stealth destinations, encrypted
recipient notes, and real view keys. That upgrade must use a reviewed,
genuinely post-quantum-appropriate construction before INDRA makes any
full view-key or stealth-address privacy claim. It is planned, but not
implemented.

---

## 5. Validator Network

### 5.1 Open participation

Any entity can register as a validator. There is no permission process or
external identity verification, but registration requires at least
1,000,000,000 Spark of validator-owned self-stake. Admission to the active
consensus set is determined by validator self-stake only; delegated stake
does not increase consensus authority or active-set rank.

**Active set admission:**
1. Register with at least 1,000,000,000 Spark of validator-owned self-stake
2. At the next epoch boundary (~30 minutes): if self-stake ranks
   in the top N, the validator enters the active set

**Displacement:** If another validator accumulates more self-stake,
they may displace an incumbent at the next epoch reselection. The
displaced validator remains registered — stake is not burned. They
can re-enter by gaining more delegation.

**Registered-validator cap:** The validator registry itself is bounded
at 1,500 total registered validators. On the current testnet this
replacement rule activates at block height 97,000. Before activation,
a full registry rejects additional registrations. At or after activation,
a new registration is accepted into a full registry only if its self-bond
exceeds the lowest-ranked registered validator's self-stake; in that
case the lowest-ranked registered validator is synchronously evicted
from the live registry. Its retained stake positions exit through the
ordinary immutable tranche lifecycle and become UTXOs only at maturity.
This prevents unbounded permanent validator-state growth without turning
registration into a first-come-first-served race.

### 5.2 Validator lifecycle

```
REGISTERED ↔ ACTIVE
      ↘       ↙
       SLASHED
```

**Unbonding period:** 1,008 epochs (~21 days). Each exit becomes an immutable
height-precise tranche; stake cannot be redirected during unbonding.

### 5.3 Auto-delegation for validators outside the active set

Validators that run 24/7 but fall outside the active set at an epoch
boundary earn no rewards for that epoch. To offset this, validators
can designate a preferred `auto_delegate_to` target:

```
indra-stake auto-delegate --validator <id> --target <id>
```

When a validator is not selected for the active set, their stake is
soft-delegated to the target validator for that epoch's reward routing.
The stake remains self-bonded — no UTXO movement or unbonding period is
required. This is a pure reward routing mechanism, invisible to
consensus, that allows 24/7 operators to earn delegator rewards even
when outside the active set.

### 5.4 Slashing

INDRA's explicit-evidence slashing model is deliberate and minimal.

```
Offence                      Penalty            Notes
──────────────────────────────────────────────────────────
Miss block as proposer       Lost reward only   Not slashed
Brief offline period         No rewards         No evidence-based slash
Liveness failure (3+ epochs  0.10% per epoch    Stake reduced; amount burned
  without participation)
Double-precommit             5.00% of stake     Slashed and exited
Reporter reward              5.00% of slash     Paid to reporter
```

**Liveness:** After 3 consecutive epochs without participation, a
validator incurs a 0.10% per-epoch penalty. This is the only ongoing
penalty for offline behaviour: it reduces validator stake and burns the
same amount from total supply at each penalised epoch transition.

**Double-signing:** Only intentional equivocation (signing two different
blocks at the same height and round) results in meaningful stake burn.
The 5% double-precommit slash applies immediately upon detection.
Evidence must be included in a block by another validator.

**Philosophy:** Brief downtime loses rewards but does not enter the
explicit malicious-equivocation slashing path. Persistent downtime is
different: after the liveness threshold, the protocol applies a small,
compounding stake penalty so inactive validators cannot remain active
with no economic consequence.

### 5.5 Delegation

```
Minimum delegation:    Dust limit (0.001 INDRA protocol floor)
                       Each validator sets their own minimum above this
Unbonding period:      1,008 epochs (~21 days)
Commission range:      0–20% (maximum governable, can only decrease)
Reward frequency:      Each epoch (~30 minutes)
Key custody:           Delegator retains full custody always
```

Delegation is non-custodial. The validator cannot spend, redirect,
or access delegated funds. Commission is deducted automatically by
the protocol. Rewards accumulate in each stake position's
`pending_rewards_spark` each epoch
and are claimable at any time.

**Delegator reward query:** The `indra_getDelegatorPositions` and
`indra_getDelegatorRewards` RPC methods allow any delegator to query
their positions and pending rewards across all validators in a single
call, without knowing which validators they have delegated to in advance.

---

## 6. On-Chain Governance

### 6.1 Overview

INDRA implements a five-phase commit-reveal governance mechanism with
two-snapshot vote weight accounting. Governance allows the validator
community to adjust protocol parameters within defined bounds.
Monetary parameters (hard cap, era reward schedule) and safety
parameters (consensus quorum) are permanently immutable.

### 6.2 Five-phase governance lifecycle

```
Phase 1  DELIBERATION   30 epochs  (~15 hours)
  Proposal published on-chain. Community discusses.
  SNAPSHOT 1 taken at end of Phase 1.
  Captures eligible validators and their stake.

Phase 2  COMMIT         20 epochs  (~10 hours)
  All Snapshot 1 eligible validators MUST submit:
    H("INDRA-gov-commit-v1:" || proposal_id || validator_id
      || vote_byte || nonce_32_bytes)
  Their vote is hidden. Missing commit = abstain.

Phase 3  REVEAL         10 epochs  (~5 hours)
  All who committed MUST reveal (vote_byte, nonce).
  Votes become public. Non-reveal = abstain.
  Validator non-reveal does not directly affect the proposer's deposit.
  Delegators who disagree may governance-redelegate their
  vote weight to a different validator.
  SNAPSHOT 2 taken at end of Phase 3.

Phase 4  TALLY          1 epoch    (automatic)
  Final count: Snapshot 1 votes × Snapshot 2 stake weights.
  Non-committed validators count as abstain in denominator.
  Non-revealed validators count as abstain.
  Deposit is returned if the proposal passes, or if it fails with
  >=10% support; it is burned only if the proposal fails below that
  support threshold or the proposer cancels during deliberation.

Phase 5  EXEC DELAY     100 epochs (~50 hours, governable)
  If passed: parameter change queued.
  Executes automatically at next epoch boundary.
```

**Total governance cycle:** ~160 epochs (~80 hours) from proposal to
execution under default parameters.

Governance phase boundaries are inclusive for the phase being closed.
Operations included in the exact block that reaches a transition epoch
are processed under the old phase first, then the epoch transition takes
effect. For example, a reveal included in the block that reaches the
tally epoch is still accepted before the proposal moves to tally.

### 6.3 Two-snapshot mechanism

**Snapshot 1** (end of Phase 1): Captures which validators are eligible
to vote and their stake at that point. Prevents late stake manipulation
to influence validator eligibility.

The proposal also freezes the applicable standard or critical YES-stake
threshold when it is created. A later governance change cannot retroactively
change the decision rule for a proposal already in its lifecycle.

**Snapshot 2** (end of Phase 3): After governance redelegation, captures
the final stake weight applied to each validator's vote. Delegators who
disagree with their validator's revealed vote can shift their weight to
a different validator during Phase 3.

**Vote count:** `yes_stake / snapshot1_total_stake > quorum_bps / 10000`

Despite the historical field name, `quorum_bps` is a YES-stake threshold
over total Snapshot 1 stake, not a participation quorum. Snapshot 1 total
stake is the denominator, including abstains and non-participation. A
proposal passes only if YES stake alone exceeds the configured threshold;
YES beating NO among participants is not sufficient. See
`docs/GOVERNANCE_THRESHOLD_DESIGN.md`.

### 6.4 Governance redelegation

During Phase 3, after validator votes are revealed, delegators may
submit a `GovernanceRedelegate` operation to shift their vote weight
to a different validator for this proposal only:

- Moves vote WEIGHT only — no UTXO movement, no unbonding period
- Only delegators (not self-staking validators) may redelegate
- One redelegation per delegator per proposal
- Only to a validator who has already revealed their vote
- Weight capped by actual delegated stake
- Evaporates after proposal resolves — real delegation unchanged

This gives delegators a genuine voice in governance outcomes without
requiring the unbonding period that would make delegation-based voting
impractical.

### 6.5 Proposal tiers

**Tier 1 — Standard** (YES stake must exceed 50% of Snapshot 1 stake):
- `slash_liveness_threshold_epochs` — consecutive epochs before liveness penalty
- `min_delegation_spark` — global delegation dust floor
- `proposal_deposit_spark` — governance proposal deposit amount

**Tier 2 — Critical** (YES stake must exceed 67% of Snapshot 1 stake):
- `slash_liveness_bps` — liveness penalty rate (floor: 1 BPS)
- `slash_double_precommit_bps` — double-precommit slash rate
- `max_commission_bps` — maximum validator commission (monotonic decrease only)
- `governance_delay_epochs` — execution delay (monotonic increase only)
- `governance_quorum_bps` — standard YES-stake threshold over total snapshot stake (monotonic increase only)
- `governance_critical_quorum_bps` — critical YES-stake threshold over total snapshot stake (monotonic increase only)

### 6.6 Permanently immutable parameters

The following are enforced immutable in code and cannot be changed by
any governance action regardless of support level:

- `HARD_CAP_SPARK` — 1,000,000,000 INDRA maximum supply
- Era block reward schedule — halving schedule
- Exact strict BFT quorum predicate — `signed_stake * 3 > total_stake * 2`,
  evaluated with checked `u128` intermediates; it is not a rounded BPS parameter
- `active_slot_coefficient_numerator` (`F`) — immutable genesis-selected
  numerator for proposer sortition, constrained to `1..=2^63`
- `max_active_validators` — automatic per stake phases
- Cryptographic algorithms (ML-DSA-87, ML-KEM-1024)

### 6.7 Monotonic constraints

- `max_commission_bps` — can only **decrease** (protects existing delegators)
- `governance_delay_epochs` — can only **increase** (protects community reaction time)
- `governance_quorum_bps` — can only **increase** (higher YES-stake threshold = safer)
- `governance_critical_quorum_bps` — can only **increase**

These constraints are enforced at proposal validation time. A proposal
that violates a monotonic constraint is rejected at submission.

### 6.8 Spam protection

```
Proposal deposit:           1,000 INDRA
Deposit return:             If proposal passes, or if failed proposal has ≥10% support
Deposit burned:             If failed proposal has <10% support, or proposer cancels
Burn accounting:            Checked subtraction from total supply and epoch audit record
Max active proposals:       3 globally
Per-proposer limit:         1 active proposal at any time
Cooldown:                   1 new proposal per proposer per 10 epochs
```

### 6.9 Default governance parameters

```
Standard YES threshold:     >50.00% of Snapshot 1 stake
Critical YES threshold:     >67.00% of Snapshot 1 stake
Execution delay:            100 epochs (~50 hours)
Proposal deposit:           1,000 INDRA
Max commission:             20% (may only decrease via governance)
Liveness threshold:         3 epochs
Liveness penalty:           0.10% per epoch
Double-precommit slash:     5.00%
```

### 6.10 Proposal history retention

Active proposals are retained unconditionally. Terminal proposal records
(`Failed`, `Cancelled`, and `Executed`) are consensus-retained only for
the 1,024 most recent terminal proposals, ordered deterministically by
proposal epoch and ID. Older terminal records may be absent from ordinary
node RPC responses; deep historical governance lookup is an archive-node
or indexer responsibility. This pruning rule is height-gated and is
scheduled for activation on the current testnet at block height 97,000.

---

## 7. Current Status and Limitations

### 7.1 Development status

INDRA is a pre-mainnet protocol. A four-validator testnet has been
running continuously producing blocks with full consensus, epoch
transitions, governance state, and epoch history recording. The
protocol has not yet been subjected to public adversarial conditions.

The repository contains a large unit and integration test suite across
the workspace. Exact test counts change as hardening work continues and
should be taken from the current CI run, not from this document.

### 7.2 Security review status

The implementation has undergone preliminary internal review. A
professional third-party security audit by an independent firm is
required and planned before mainnet launch. The audit report will
be published in full.

Unit tests catch implementation bugs. They are not a substitute for
fuzzing, adversarial testnet conditions, formal verification, or
professional cryptographic review. None of these have yet occurred.

### 7.3 Known limitations

**Full transaction privacy is not implemented.** INDRA protects fund
ownership and consensus finality against quantum adversaries, but the
current OutputV1 format exposes owner and value metadata to raw-chain
observers. Full owner/amount privacy requires a future OutputV2 protocol
upgrade with stealth destinations, encrypted recipient notes, and reviewed
post-quantum-appropriate view-key machinery.

**No smart contracts.** INDRA is a settlement layer. This is a
deliberate design choice.

**Open public testnet period not yet complete.** A four-validator
testnet is running, but a minimum three-month public testnet with open
validator participation is still required before mainnet.

**Key separation not yet implemented.** The current implementation
uses a unified key derived from a 24-word recovery phrase. Hot/cold
key separation (hot consensus key, cold withdrawal key) is planned
before mainnet stake reaches significant value.

**StateCommitmentV2 and compressed authenticated trees are not active.**
Incremental validator/delegation/staking commitments and compressed
authenticated UTXO trees have been implemented behind hard-fork
height gates, but both activation constants remain deliberately
unscheduled (`u64::MAX`) pending further review. Live testnet state roots
therefore still use the currently-active commitment rules.

---

## 7b. Minimum System Requirements

```
CPU:      2 cores (any modern processor, 2015 or newer)
RAM:      4 GB minimum / 8 GB recommended
Storage:  10 GB free minimum (pruned mode, default)
          1 TB+ for archive nodes
Network:  10 Mbps stable upload and download
          Ports 30303 (P2P) and 30304 (observer) open
          Static IP recommended but not required
Uptime:   No minimum — validators earn proportional to uptime
          Brief downtime loses rewards; persistent inactivity triggers
          liveness penalties after the configured threshold
OS:       macOS 12+, Ubuntu 20.04+, Windows 10+ (64-bit)
```

Default (pruned) mode retains the last 50,000 blocks (~300 MB) plus
the state database (UTXO set, validator set, governance state,
epoch history). A validator can move to new hardware, re-enter their
24-word phrase, resync from the network, and resume with the same
identity and full history intact.

---

## 8. JSON-RPC Interface

INDRA nodes expose a JSON-RPC 2.0 endpoint. Key methods:

```
Chain queries
  indra_getChainInfo         Chain height, supply, validators, fees
  indra_getBlock             Full block by height
  indra_getTip               Current tip hash and height
  indra_getMempoolSize       Pending transaction count

Validator queries
  indra_getValidatorSet      All active validators
  indra_getValidator         Single validator by ID
  indra_getValidatorSelfStake   Self-stake bonds
  indra_getValidatorAutoDelegate Auto-delegation target
  indra_getValidatorDelegators  All delegators to a validator

Delegator queries
  indra_getDelegatorPositions   All positions across all validators
  indra_getDelegatorRewards     Pending rewards across all validators
  indra_getDelegations          Delegations to a specific validator

Epoch history
  indra_getEpochRecord       Full record for one epoch
  indra_getEpochHistory      Paginated epoch summaries
  indra_getLatestEpoch       Most recently completed epoch

Governance
  indra_getGovernanceParams  Current governable parameters
  indra_getProposals         Active and consensus-retained recent proposals
  indra_getProposal          Full detail for a retained proposal
  indra_getProposalVotes     Per-validator vote breakdown for a retained proposal
  indra_getGovernanceNonce   Governance replay-protection nonce
  indra_submitGovernanceOp   Submit a governance operation

Completed governance proposals older than the consensus retention window may
be pruned from ordinary node state; deep historical governance lookup is an
archive-node or indexer responsibility, matching block-pruning behavior.
`indra_getProposals.total_count` therefore means retained count, not lifetime
count. `NotFound` cannot distinguish a never-existing proposal from one that
has already been pruned.

Submission
  indra_sendTransaction      Submit a transaction
  indra_submitStakingOp      Submit a staking operation
  indra_getLegacyScanChallenge        Ownership challenge for protocol-output provenance
  indra_getStakingNonce      Replay-protection nonce for staking ops
  indra_getPeers             Connected validator and observer peers
  indra_getRpcPolicy         Listener mode and admin-token policy, no token value

Admin-only operator diagnostics
  indra_getPeerTopology      Full peer topology, protected by X-Admin-Token
```

---

## 9. Roadmap

Milestones, not dates. Each milestone completes before the next.

**Phase 1 — Protocol implementation (complete)**
Core protocol in Rust, ML-DSA-87 hybrid signatures, ML-DSA-87-only
QC consensus, hybrid PQ transport (X25519 + ML-KEM-1024), OutputV1 value
commitment/range-proof machinery, BFT consensus with stability fixes, UTXO delegation,
auto-delegation, five-phase commit-reveal governance, epoch history,
canonical genesis-native state/storage formats, encrypted key storage, CLI tooling (stake +
governance), JSON-RPC, and a four-validator testnet.

**Phase 2 — Public testnet**
Public bootstrap nodes in multiple geographic regions. Public testnet
open to all validators. Testnet faucet. Public block explorer. iOS
TestFlight release. Android wallet. Minimum three months sustained
public testnet before proceeding.

**Phase 3 — Audit and hardening**
Professional security audit by independent firm. All findings resolved
and published. Fuzz testing. Network stress testing. Economic security
analysis published. Hot/cold
key separation implemented.

**Phase 4 — Mainnet**
Reproducible genesis ceremony with publicly verifiable genesis hash.
Bootstrap nodes operational. DNS seeds live with DNSSEC and INDRA signed
discovery. Wallets available on App Store and Play Store. Block explorer
live.

**Phase 5 — Ecosystem**
Exchange integrations as demand warrants. SDK releases.
Government record pilot design. Academic partnerships.

---

## 10. Team

INDRA Protocol was designed and built by Jyothi Sarath Kolaparthi
(Buddhi) and a small team of engineers. The code is public and the
design has been examined internally.

The founders hold no pre-mined INDRA. There is no team allocation,
no foundation reserve, and no operational bootstrap. The founders
earn INDRA the same way as every other participant: by running
validator nodes. This is encoded in the protocol — the genesis block
contains no pre-mine.

A protocol's security derives from its mathematical properties and
open-source implementation, not from the credentials of its creators.

Contact: indraprotocol@protonmail.com
Repository: github.com/jyothisarath096/indra

---

## 11. Technical Appendix

### A. Cryptographic primitives

| Primitive | Use | Security | Quantum-safe | Standard |
|-----------|-----|----------|-------------|---------|
| Ed25519 | Transaction classical sig | 128-bit | No | RFC 8032 |
| ML-DSA-87 | Transaction PQ sig | Level 5 (~256-bit PQ) | Yes | NIST FIPS 204 |
| ML-DSA-87 | QC finality sigs | Level 5 | Yes | NIST FIPS 204 |
| ML-DSA-87 | Staking op sigs | Level 5 | Yes | NIST FIPS 204 |
| ML-DSA-87 | Governance op sigs | Level 5 | Yes | NIST FIPS 204 |
| ML-KEM-1024 | Transport key encap | Level 5 | Yes | NIST FIPS 203 |
| X25519 | Transport classical ECDH | 128-bit | No | RFC 7748 |
| ChaCha20-Poly1305 | Transport encryption | 256-bit | Partial | RFC 8439 |
| Checked `u64` | Public monetary conservation | Exact arithmetic invariant | Yes | Rust checked arithmetic |
| SHA-256 | Hashing | 128-bit* | Partial | FIPS 180-4 |
| VRF/Ed25519 | Proposer election | 128-bit | No | draft-irtf-cfrg-vrf |

*Grover's algorithm reduces SHA-256 effective security to ~64-bit under
a quantum adversary. Considered acceptable at current parameter sizes.

### B. Protocol constants

```
Hard cap:                    1,000,000,000 INDRA
Spark per INDRA:             100,000,000 (8 decimal places)
Dust limit:                  0.001 INDRA (100,000 Spark)
Block time:                  6 seconds
Blocks per year:             5,256,000
Epoch duration:              300 blocks (~30 minutes)
Consensus quorum:            66.67% of total stake
BFT safety threshold:        <33.33% Byzantine stake
Unbonding period:            1,008 epochs (~21 days)
Default prune window:        50,000 blocks
Snapshot interval:           300 blocks (each epoch)

Validator set phases:
  Phase 1 (<1M INDRA staked):   20 validators
  Phase 2 (<10M INDRA staked):  50 validators
  Phase 3 (<50M INDRA staked):  100 validators
  Phase 4 (≥50M INDRA staked):  200 validators

Era 1 block reward:          11.892 INDRA (1,189,200,000 Spark)
Era 1 duration:              4 years (21,024,000 blocks)
Era 2 duration:              4 years
Era 3+ duration:             8 years per era
Fee burn:                    50% of all transaction fees
Fee to validators:           50% of all transaction fees

Slashing (default, governable within bounds):
  Liveness threshold:        3 consecutive epochs
  Liveness penalty:          0.10% per epoch (1 BPS minimum)
  Double-precommit:          5.00% of stake (500 BPS)
  Reporter reward:           5.00% of slash amount (500 BPS)

Commission:
  Maximum:                   20% (2,000 BPS, governable)
  Range:                     0–max_commission_bps

Governance (default):
  Standard YES threshold:    >50% of Snapshot 1 stake (5,000 BPS)
  Critical YES threshold:    >67% of Snapshot 1 stake (6,700 BPS)
  Execution delay:           100 epochs (~50 hours)
  Proposal deposit:          1,000 INDRA
  Active proposals max:      3 globally
  Per-proposer max:          1 active at a time
  Cooldown:                  10 epochs between proposals

Schema version:              4 (as of v2.0 specification)
```

### C. Reward mathematics

**Era 1 total:**
```
300 blocks/epoch × 1,189,200,000 Spark/block = 356,760,000,000 Spark/epoch
356,760,000,000 Spark × (5,256,000/300) epochs/year = 6,258,960,000,000,000 Spark/year
6,258,960,000,000,000 / 100,000,000 = 62,589,600 INDRA/year
62,589,600 × 4 = 250,358,400 INDRA over Era 1 (~25% of supply)
```

**Validator epoch share (equal stake, no delegation):**
```
validator_share = 356,760,000,000 / active_validator_count Spark/epoch
At 4 validators:   89,190,000,000 Spark/epoch = 891.9 INDRA/epoch
At 20 validators:  17,838,000,000 Spark/epoch = 178.38 INDRA/epoch
```

### D. Quantum threat model

| Attack vector | Threat | INDRA response |
|---------------|--------|----------------|
| Break Ed25519 tx sig | Forge transactions | ML-DSA-87 still protects |
| Break ML-DSA-87 tx sig | Forge transactions | Ed25519 still protects |
| Break both simultaneously | Forge transactions | Both must fail together |
| Quantum attack on QC | Forge consensus | ML-DSA-87-only QC — fully PQ |
| Break X25519 transport | Intercept P2P | ML-KEM-1024 still protects |
| Break ML-KEM-1024 | Intercept P2P | X25519 still protects |
| Grover on SHA-256 | Weaken hashing | 2x speedup only, acceptable |

The hybrid construction at every layer ensures that breaking one
classical scheme is insufficient. An adversary must break both the
classical and post-quantum scheme simultaneously to compromise any
security property. This is the strongest achievable hybrid guarantee.

### E. Governance lifecycle example

```
Block 300 (epoch 1 boundary) — Proposal submitted:
  Action: SetSlashLivenessBps { value: 8 }  (Tier 2: Critical)
  Deposit: 1,000 INDRA escrowed from proposer UTXO
  Phase 1 start: epoch 1
  Phase 2 start: epoch 31 (Snapshot 1 taken)
  Phase 3 start: epoch 61 (reveals begin)
  Tally:         epoch 71
  Exec after:    epoch 171

Epoch 31 — Phase 2 (Commit):
  buddhi:  submits H(domain || proposal || buddhi || YES || nonce_A)
  bonkai:  submits H(domain || proposal || bonkai || NO  || nonce_B)
  siddhi:  submits H(domain || proposal || siddhi || YES || nonce_C)
  kushal:  submits H(domain || proposal || kushal || NO  || nonce_D)

Epoch 61 — Phase 3 (Reveal):
  All four validators reveal (YES/NO, nonce)
  Votes become public.
  A delegator to bonkai (voted NO) sees the result and
  governance-redelegates 50,000 INDRA weight to siddhi (YES).

Epoch 71 — Tally:
  Snapshot 2 weights: buddhi 100k + siddhi 150k (received redeleg)
    + bonkai 50k (lost redeleg) + kushal 100k = 400k total
  YES: buddhi 100k + siddhi 150k = 250k
  NO:  bonkai 50k + kushal 100k = 150k
  YES% = 250k/400k = 62.5% < 67% critical YES threshold
  → Proposal FAILS. Deposit returned (>10% support).

Alternative: if YES = 270k (>67%), proposal passes → executes at epoch 171.
```

---

## References

1. Shor, P.W. (1994). Algorithms for quantum computation. FOCS 1994.
2. NIST (2024). FIPS 204 — ML-DSA. https://csrc.nist.gov/pubs/fips/204/final
3. NIST (2024). FIPS 203 — ML-KEM. https://csrc.nist.gov/pubs/fips/203/final
4. NIST (2024). Post-Quantum Cryptography Standardization. https://csrc.nist.gov/pqcrypto
5. Nakamoto, S. (2008). Bitcoin: A Peer-to-Peer Electronic Cash System. https://bitcoin.org/bitcoin.pdf
7. Buchman, E. (2016). Tendermint: Byzantine Fault Tolerance in the Age of Blockchains. University of Guelph.
8. CRYSTALS-Dilithium Team (2021). Algorithm Specifications and Supporting Documentation. https://pq-crystals.org/dilithium/
9. Bernstein, D.J. & Lange, T. (2017). Post-quantum cryptography. Nature 549, 188–194.

---

*INDRA Protocol — Technical specification v2.0*
*This is a technical specification, not a financial instrument prospectus.*
*Protocol parameters may change before mainnet.*
*This document does not constitute investment advice.*
