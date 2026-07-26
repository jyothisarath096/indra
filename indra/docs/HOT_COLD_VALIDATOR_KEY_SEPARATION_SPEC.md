# INDRA Validator Hot/Cold Key Separation Specification

Status: specification only; no implementation or activation is authorized by this document.

Version: 1.0

## Security scope and terminology

This specification separates a validator's continuously online consensus authority
from its custody and governance authority.

- **Hot key** means the validator's existing full hybrid key pair:
  Ed25519 plus ML-DSA-87. The existing `validator_id =
  SHA256(hot_ed25519_public_key)` remains unchanged.
- **Cold key** means a second, independently generated full hybrid key pair:
  Ed25519 plus ML-DSA-87. It is registered as the validator's custody and
  governance authority.
- **Full hybrid signature** means one Ed25519 signature and one ML-DSA-87
  signature over exactly the same canonical message, verified against the two
  public components stored together in one registered `HybridPubKey`. Both
  verifications MUST succeed.
- **Dual-required** means two complete hybrid signatures over exactly the same
  canonical message: one under the registered hot pair and one under the
  registered cold pair. It never means one component from each pair.
- **Delegator custody key** means an ordinary delegator's existing full hybrid
  identity key. Delegators do not acquire a validator hot key under this
  specification.
- **Custody output** means an output containing validator stake, validator
  rewards, governance deposits or refunds, or funds otherwise designated as
  validator-owned value. Such an output is owned by the validator's cold key.
- **Operational output** means an ordinary UTXO deliberately created for the
  hot key. It is not stake, a staking return, or a validator protocol reward.

The security objective is precise: compromise of the hot key alone MUST NOT
authorize withdrawal, redirection, claiming, rotation, or spending of validator
custody value. Valid protocol slashing remains outside that protection.

## 1. Complete authority matrix

All authorities below are definitive. "Cold-only" for an ordinary delegator
means the delegator's existing full hybrid custody identity key.

| Operation | Authority | Reason and required effect |
|---|---|---|
| `RegisterValidator` | **Dual-required** | The hot signature proves control of the consensus identity from which `validator_id` is derived. The cold signature proves possession of the custody key. The registration bond MUST already be owned by the cold key. Neither signature alone may register the validator. |
| Existing-validator cold-key enrollment | **Dual-required** | The registered hot key proves authority over the existing validator record; the proposed cold key proves possession of both of its components. This is the one-time migration binding. |
| `SelfStake` | **Cold-only** | It spends a cold-owned UTXO into slashable validator principal. Hot compromise must not be able to increase or rearrange custody exposure. |
| `SelfUnstake` | **Cold-only** | It initiates release of validator principal and can change validator status. |
| Validator `ClaimRewards` | **Cold-only** | It converts validator reward accounting into a spendable cold-owned UTXO. |
| Delegator `ClaimRewards` | **Cold-only** | It converts delegation reward accounting into a UTXO owned by the delegator custody key. |
| `SetCommission` | **Cold-only** | It changes the validator's future economic entitlement and affects delegators. It is not required for consensus liveness and therefore does not justify hot exposure. |
| `SetAutoDelegate` | **Cold-only** | It controls economic deployment of registered-validator stake and resulting reward allocation. It is not required continuously. |
| `UpdateNetworkAddress` | **Hot-only** | It is an operational availability setting needed by the online validator. It cannot select a reward recipient, release a bond, rotate a custody key, or spend value. |
| Validator `RegisterPaymentKey` | **Cold-only** | It controls where future blinded payments to the validator can be recovered. A hot compromise must not redirect future validator receipts. |
| Delegator `RegisterPaymentKey` | **Cold-only** | It is authorized by the delegator's existing custody identity key. |
| `Delegate` | **Cold-only** | It spends a delegator-owned UTXO into a delegation bond. |
| `Undelegate` | **Cold-only** | It initiates release of delegated principal. |
| Governance `Propose` | **Cold-only** | It spends a proposal-deposit UTXO and exercises constitutional authority. The deposit MUST be cold-owned. |
| Governance `Commit` | **Cold-only** | Governance voting is not a continuously required consensus duty. Keeping it cold prevents a hot consensus compromise from also controlling governance votes. |
| Governance `Reveal` | **Cold-only** | It completes the cold-authorized governance vote. Operational inconvenience is accepted in favor of isolation. |
| Governance `Redelegate` | **Cold-only** | It changes a delegator's governance weight. It is authorized by the delegator custody key. |
| Governance `Execute` | **Hot-only** | Execution is a mechanical trigger for an already-approved, delayed and revalidated action. The signer receives no discretion to change the action or move personal funds. Any active or registered validator hot key may trigger it. |
| Governance `Cancel` | **Cold-only** | Only the proposer may cancel, and cancellation burns the proposal deposit. It is a custody/governance decision. |
| Cold-key rotation | **Dual-required: current cold plus proposed new cold** | The current cold signature authorizes replacement; the new cold signature proves full possession. The hot key has no role. |
| Ordinary UTXO spending | **Owner-only** | A cold-owned input requires the cold key; a hot-owned operational input requires the hot key; a delegator-owned input requires that delegator's custody key. A transaction may not mix inputs with different owners. No single UTXO is spendable by either key. |
| Authorized read RPCs | **Either, strictly by requested owner** | A proof by the hot key may read only hot-owned addresses; a proof by the cold key may read only cold-owned addresses. This grants no write authority and does not make the same address readable under two keys. |

The authorized read RPC rule applies to
`indra_getLegacyBalanceAuthorized`, `indra_getLegacyUtxosAuthorized`, and
`indra_explainUtxoProvenanceAuthorized`. The current address-to-classical-key
check remains, followed by full hybrid signature verification. Operators who
require the cold key to remain physically offline must scan cold-owned outputs
by exporting signed, short-lived scan proofs from the offline signer. This
specification does not introduce a view key.

Consensus prevotes, precommits, VRF commit messages, VRF reveal messages,
validator transport authentication, relay authentication, and the separate VRF
proof remain hot responsibilities. Block headers remain unsigned directly, as
in the current protocol.

## 2. Concrete key and registry structures

### 2.1 Cold-key generation and storage

A cold key consists of:

```text
ColdHybridKeypair {
    ed25519_secret_seed: 32 uniformly random bytes,
    ml_dsa_87_secret_seed: 32 independently uniformly random bytes
}

ColdHybridPubKey {
    ed25519_public_key: 32 bytes,
    ml_dsa_87_public_key: 2592 bytes
}
```

The two cold seeds MUST be generated by a cryptographically secure random
number generator on the offline signing device. They MUST NOT be derived from:

- either hot secret;
- the VRF secret;
- the payment secret;
- a validator ID;
- a common hot/cold seed;
- the same 32-byte entropy value as each other; or
- a deterministic path rooted in any secret present on the validator host.

The cold-key generator MUST request independent random bytes for the Ed25519 and
ML-DSA-87 seeds. It MUST derive both public keys locally and perform
sign/verify self-tests before producing enrollment material.

Cold secrets MUST be stored only in an encrypted offline keystore or hardware
signer. The keystore encryption and backup format are operational controls and
do not replace protocol authentication. At least two geographically separated,
encrypted backups are recommended. Backup media MUST never contain the hot
secret. The online node stores only the cold public key, version and status.

The CLI/FFI signer interface MUST support an offline workflow:

1. An online watch-only tool constructs canonical unsigned operation bytes.
2. The offline cold signer displays the chain ID, operation type, validator ID,
   nonce, cold-key version and all custody-relevant fields.
3. The offline signer returns a complete hybrid signature.
4. The online tool attaches and submits it without receiving either cold
   secret.

### 2.2 Validator registry fields

`ValidatorEntry` gains the following consensus-committed fields:

```text
cold_hybrid_classical_pk: Option<[u8; 32]>
cold_hybrid_pq_pk: Option<[u8; 2592]>
cold_key_version: u64
cold_key_status: Unenrolled | Active
cold_nonce: u64
```

`cold_key_version` is zero while unenrolled. Initial enrollment installs
version 1. Each successful rotation increments the version by exactly one.

The full cold pair, version, status and cold nonce MUST be included in:

- canonical `ValidatorEntry` encoding;
- validator state-commitment leaves;
- snapshot persistence and restoration;
- state-root projection;
- RPC validator responses; and
- genesis configuration for validators created at or after enforcement.

The registry MUST reject:

- malformed Ed25519 or ML-DSA-87 public keys;
- an ML-DSA-87 key of any length other than 2592 bytes;
- reuse of either cold public component by another validator;
- equality between any cold component and any registered hot component;
- equality between a validator's cold and hot pair;
- reuse of the same cold pair by multiple validator IDs; and
- a zero or skipped cold-key version.

Global uniqueness is enforced separately for each public component. This
prevents a pair formed from a component already assigned to another role or
validator.

### 2.3 Canonical authorization envelopes

Every role-authorized message includes:

```text
domain
chain_id
operation_tag
validator_id or delegator_id
authority_role = HOT | COLD
authority_key_version
role_nonce
complete operation payload
```

Hot and cold domains are distinct. A cold signature is invalid in a hot
envelope and vice versa.

For a dual-required operation, both signatures cover one byte-identical
canonical message containing both complete public keys, the intended new
version, and the full payload. Verification is:

```text
verify_hybrid(message, hot_signature, registered_hot_pair)
AND
verify_hybrid(message, cold_signature, registered_or_proposed_cold_pair)
```

Four independent primitive verifications therefore succeed: hot Ed25519, hot
ML-DSA-87, cold Ed25519 and cold ML-DSA-87.

No verifier may construct a `HybridPubKey` by taking components from separate
records or from the submitted signature envelope.

Hot and cold operations use separate nonce namespaces. Cold operations carry
`cold_key_version` and the next `cold_nonce`. Hot operations retain a hot
operation nonce. A rotation consumes the current cold nonce and atomically
resets the new version's nonce to zero. The first ordinary operation under the
new version uses nonce 1.

### 2.4 Initial validator registration

The registration payload contains:

- commission;
- registration bond UTXO ID and opening proof;
- full hot public pair;
- VRF public key;
- full cold public pair;
- initial cold-key version 1;
- chain ID; and
- the complete registration payload domain.

The registration UTXO MUST be owned by the proposed cold pair. The state
transition verifies:

1. the existing UTXO and its commitment opening;
2. UTXO ownership by the proposed cold pair;
3. full hybrid proof of possession by the proposed hot pair;
4. full hybrid proof of possession by the proposed cold pair;
5. uniqueness of hot, cold and VRF keys;
6. canonical `validator_id = SHA256(hot_ed25519_public_key)`; and
7. both signatures over the same registration message.

Only after all checks pass is the UTXO spent and the validator plus self-bond
inserted atomically.

### 2.5 Existing-validator enrollment

An `EnrollValidatorColdKey` transition contains the validator ID, proposed full
cold public pair, target version 1, current migration nonce, chain ID, and a
statement that all unresolved validator self-bonds and validator reward
accounting become cold-controlled.

It requires:

- one full hybrid signature by the currently registered hot pair; and
- one full hybrid signature by the proposed cold pair;

over identical bytes.

Enrollment is permitted only when status is `Unenrolled` and version is zero.
It is atomic with installing the cold pair, updating state commitments, and
making all unresolved validator custody records resolve through version 1.

This enrollment cannot retroactively protect a validator whose hot key was
already compromised. Before legitimate enrollment, an attacker controlling the
hot key can co-sign enrollment with an attacker-generated cold key. This is an
unavoidable migration exposure because the pre-upgrade chain has no independent
credential with which to distinguish the legitimate operator. Activation MUST
therefore occur only after operators verify and complete enrollment through an
authenticated operational process.

### 2.6 Identity derivation decision

This specification does **not** change `validator_id` or `delegator_id`
derivation.

- A validator ID remains `SHA256(hot_ed25519_public_key)`.
- A delegator ID remains `SHA256(delegator_ed25519_public_key)`.

Changing those IDs would break registry references, bond records, governance
snapshots, nonces and historical proofs without adding cryptographic strength.
Instead, the validator registry supplies an explicit consensus-committed
binding:

```text
validator_id
  -> complete registered hot hybrid pair
  -> complete registered cold hybrid pair and version
  -> VRF key
```

The ID is only an index. It is never accepted as proof that a PQ key is bound.
Every authorization resolves the full role-specific pair from committed state
and verifies both components.

Delegator identity derivation is unchanged because ordinary delegators have no
forced-online validator role. Their identity registry continues to pin the full
hybrid pair.

## 3. UTXO ownership model

### 3.1 Outputs created after enforcement

The following outputs MUST be owned by the validator's currently active full
cold public key at the state transition that creates the output:

- validator self-bond release outputs, normal or slashed;
- validator reward-claim outputs;
- validator self-bond refunds caused by registry eviction;
- validator pending-reward payouts caused by registry eviction;
- validator governance-deposit change;
- validator governance-deposit refund;
- any future protocol-generated payout whose economic source is validator
  principal, commission or validator rewards.

The following remain owned by their existing non-validator custody owner:

- delegator bond releases;
- delegator reward claims;
- delegator eviction refunds; and
- delegator governance-related outputs.

An ordinary hot-owned operational UTXO remains hot-owned. The protocol never
silently changes an already-created ordinary UTXO's owner.

### 3.2 Bond records and owner resolution

`StakeBondEntry` gains an explicit custody-owner discriminator:

```text
custody_owner:
    DelegatorIdentity(delegator_id)
  | ValidatorColdIdentity(validator_id)
```

It does not store a classical-only address. For
`ValidatorColdIdentity`, release logic resolves the validator's complete,
currently active cold pair from `ValidatorEntry`. For
`DelegatorIdentity`, it resolves the complete pair from
`delegator_identities`, preserving the existing delegator behavior.

New `RegisterValidator` and `SelfStake` bonds MUST use
`ValidatorColdIdentity`. `Delegate` bonds MUST use `DelegatorIdentity`.

The owner resolution in `epoch.rs::released_bond_output` and
`regenerated_bond_output` MUST stop treating `delegator_id == validator_id` as
sufficient owner selection. It MUST dispatch on `custody_owner`, require a
complete registry pair, and fail atomically if resolution is impossible.

### 3.3 Reward claims

Validator reward claims do not accept a payout key from the request. The
operation names the validator ID and cold-key version, and the state transition:

1. resolves the currently active cold pair from `ValidatorEntry`;
2. verifies the cold signature;
3. clears pending validator rewards; and
4. creates the reward UTXO to that resolved cold pair.

The submitted operation cannot substitute a different payout public key.

Delegator reward claims continue to resolve the delegator's full registered
identity pair. Their submitted key, when required for legacy compatibility,
must exactly equal the registered full pair.

### 3.4 Eviction and governance outputs

Validator eviction resolves the current cold pair for both self-bond refunds
and validator pending rewards. Eviction cannot fall back to the hot pair. If
the validator is unenrolled after enforcement, its custody values remain in
consensus state and are not paid until valid enrollment; they are never burned
or redirected solely because enrollment is missing.

Validator governance proposals require a cold-owned deposit UTXO. Change and
later refunds are recreated to the current cold pair. Cancellation still burns
the deposit according to existing governance rules.

### 3.5 Existing bonds and outputs

#### Existing unresolved self-bonds

At successful existing-validator enrollment, every unresolved self-bond for
that validator is logically migrated to
`ValidatorColdIdentity(validator_id)`. The transition MUST update the canonical
bond records and corresponding state-commitment leaves atomically.

This migration changes only the eventual release owner. It does not alter:

- bond amount;
- commitment;
- bonded epoch;
- unbonding end epoch;
- slashability; or
- validator stake accounting.

The enrollment signatures explicitly commit to this migration.

Enrollment migration is always atomic. There is no `Migrating` status,
continuation operation or batch protocol. A validator may enroll only when it
has at most 4,096 unresolved self-bonds. The implementation constant is
`MAX_ATOMIC_COLD_KEY_MIGRATION_SELF_BONDS`.

Migrating one self-bond changes only its fixed-size custody-owner
discriminator, replaces the persistent-map entry, re-encodes and hashes the
bond leaf, and updates one incremental sparse-Merkle commitment leaf. It
performs no per-bond signature verification, commitment opening, range-proof
generation, UTXO creation or storage growth. The applicable optimized
maximum-block guard is four seconds against the six-second target block time;
the existing maximum ordinary block measured approximately 1.3 seconds on the
development Mac. An optimized benchmark of the exact mutation and commitment
path migrated 4,096 bonds in 40.501 milliseconds on that machine. The cap
therefore consumes approximately one percent of the four-second guard and
retains over sixty times the measured migration-cost headroom while allowing
thousands of independent self-stake top-ups.

If a validator has more than 4,096 unresolved self-bonds, enrollment fails
without changing state and reports the count, cap and remedy. During the
enrollment interval the validator must cold-enrollment-consolidate by using the
existing legacy-authorized `SelfUnstake` operation for every self-bond, waiting
for all releases to mature, combining the resulting spendable UTXOs into one
validator-owned UTXO with an ordinary transaction, and using `SelfStake` once
to create one consolidated self-bond. It may then retry enrollment. Released
UTXOs are not rekeyed by this process; the ordinary consolidation transaction
is required and remains authorized by their existing owner.

#### Existing unclaimed validator rewards

They remain accounting entries during enrollment and become claimable only by
the enrolled cold key. Enrollment does not mint or move them.

#### Existing ordinary hot-owned UTXOs

They remain hot-owned. They are not rekeyed by consensus. Before enforcement,
an operator may spend them in an ordinary transaction to a newly created
cold-owned output. This includes any already-matured bond release or already
claimed reward that became an ordinary UTXO before enrollment.

This is deliberate: changing an existing spendable UTXO's owner without the
current owner's transaction signature would violate UTXO authorization and
invalidate historical wallet assumptions.

#### Unenrolled validators at enforcement

There is no hot-key fallback. An unenrolled validator:

- is deterministically demoted from `Active` to `Registered`;
- cannot `SelfStake`, `SelfUnstake`, claim validator rewards, set commission,
  set auto-delegation, register a validator payment key, propose, vote in
  governance, cancel, or receive custody payouts;
- retains bonded value in state;
- remains slashable for evidence generated while active; and
- may complete dual-signed enrollment later.

Its existing self-bonds and rewards remain frozen until enrollment completes.

## 4. Lifecycle

### 4.1 New-validator registration

1. Generate the hot hybrid key on the validator signing system.
2. Generate the VRF key independently.
3. Generate the cold Ed25519 and ML-DSA-87 seeds independently on an offline
   signer.
4. Fund a UTXO owned by the cold pair.
5. Construct the canonical registration payload, including both public pairs,
   VRF key, bond proof, chain ID and initial version.
6. Sign the exact payload with the complete cold pair offline.
7. Sign the same payload with the complete hot pair.
8. Submit both signatures.
9. State validation verifies the two complete pairs, ownership, uniqueness,
   bond proof and ID binding before committing all records atomically.

### 4.2 Existing-validator enrollment

1. Generate and back up the independent cold pair offline.
2. Construct the canonical enrollment payload from the current chain state.
3. Verify on the offline device the validator ID, hot public key fingerprint,
   cold public key fingerprint, chain ID and migration statement.
4. Add the full cold signature.
5. Add the full registered-hot signature over the same bytes.
6. Submit before the enforcement height.
7. Verify through multiple independent nodes that the committed cold
   fingerprint and migration status match the offline record.
8. Sweep already-spendable hot-owned custody UTXOs to cold-owned UTXOs before
   enforcement.

### 4.3 Normal cold-authorized operation

For `SelfUnstake`:

1. The watch-only online tool queries the current cold version, cold nonce,
   target bond and chain ID.
2. It creates canonical bytes containing the exact bond ID, validator ID,
   version and next nonce.
3. The offline signer displays and verifies those fields.
4. Both cold components sign exactly those bytes.
5. The online tool submits the complete signature.
6. Admission and block application resolve the registered cold pair for that
   version and require both signature components.
7. The bond enters unbonding. At maturity, its output is created to the
   then-current active cold pair.

The same offline flow applies to all cold-only operations.

### 4.4 Cold-key loss

There is **no protocol recovery path** for a lost cold key.

Neither the hot key, governance, a social committee, a classical-only recovery
key, nor an administrator can replace it. This is deliberate:

- a hot recovery path would recreate the original custody vulnerability;
- a governance or administrator recovery path would introduce confiscation
  authority;
- a precommitted recovery key would add a third custody credential and an
  additional compromise path; and
- classical-only recovery would be a direct PQ downgrade.

Loss therefore permanently locks cold-owned ordinary UTXOs and prevents future
cold-authorized actions. Bonded principal remains slashable and locked unless
the cold key is recovered. This severe consequence must be disclosed in tooling
and validator requirements.

### 4.5 Rotation and compromise response

Rotation is proactive key replacement, not loss recovery.

`RotateValidatorColdKey` contains:

- validator ID;
- current cold version;
- next cold version, exactly current plus one;
- full proposed new cold pair;
- current cold nonce;
- chain ID; and
- the rotation domain.

It requires two complete hybrid signatures over identical bytes:

1. the current registered cold pair authorizes replacement; and
2. the proposed new cold pair proves possession.

Rotation has **no delay**. It becomes effective atomically in the block that
commits it. A delay without an independent recovery authority would merely
extend exposure and would not stop an attacker controlling the current cold
key.

The hot key cannot authorize, cancel, veto or accelerate rotation.

After rotation:

- all unresolved validator self-bonds resolve to the new current cold pair at
  release;
- all subsequently claimed rewards and protocol refunds use the new pair;
- already-created UTXOs remain owned by the old pair and must be swept with an
  ordinary transaction before the old key is destroyed;
- mempool operations signed under the old version become invalid;
- an already committed `SelfUnstake` remains in force, but its future release
  resolves the new current pair;
- an already committed governance vote remains historically valid;
- an uncommitted old-version governance reveal becomes invalid and MUST be
  re-signed under the new version; the reveal remains valid because the
  governance commitment binds the stable validator ID, proposal, vote and
  reveal nonce rather than a cold-key version; tooling MUST warn against
  rotating between governance commit and reveal;
- the old key can no longer authorize new protocol operations.

A compromised current cold key can race the legitimate operator and rotate to
an attacker key. No cryptographic protocol can distinguish two valid commands
from the same compromised key. Canonical block order and the cold nonce ensure
that only the first committed rotation succeeds; all competing rotations and
old-version operations then fail. Rotation is therefore effective only if the
legitimate rotation commits before the attacker acts.

There is no cancellation transaction. This removes cancellation races and
prevents the hot key from regaining custody influence.

Within one block, role-authorized operations are evaluated in canonical block
order. An old-version operation placed before a valid rotation may execute; the
rotation then advances the version. An old-version operation placed after that
rotation fails and invalidates the containing block under the normal atomic
block-validation rules. Proposers and mempools MUST therefore order a rotation
after any intentionally retained old-version operations and purge all remaining
old-version operations once it commits.

### 4.6 Full exit

A validator exits by cold-signing `SelfUnstake` for every active self-bond.
Each bond follows the normal unbonding and slashing window. The validator is
demoted according to existing minimum-stake rules and ceases consensus duties.
At maturity, releases are cold-owned. The validator cold-signs reward claims
and later ordinary transactions spending those outputs.

An ordinary delegator exits by signing `Undelegate` for every delegation bond
with the delegator custody key, waiting for maturity, claiming rewards, and
spending the resulting delegator-owned UTXOs as desired.

There is no hot-only emergency exit.

### 4.7 Slashing

Cold custody does not shield principal from valid slashing.

Slash evidence continues to verify historical hot consensus signatures against
the hot pair. Valid slashing reduces the validator's bonded amount irrespective
of cold consent. A later release creates only the post-slash remainder to the
current cold pair. Neither cold-key loss nor rotation blocks evidence
application, changes evidence windows, or restores burned value.

### 4.8 Migration and activation

Two distinct hard-fork heights are used:

1. `VALIDATOR_COLD_KEY_ENROLLMENT_HEIGHT`
2. `VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT`

Both are explicit chain parameters set to inert maximum values until reviewed
and scheduled. Enforcement MUST be later than enrollment.

At enrollment height:

- new wire types and validator fields become valid;
- existing validators may enroll;
- new validator registrations MUST use the dual-signature, cold-bond format;
- cold-key uniqueness and state commitments become consensus-enforced;
- migrated validators immediately use cold authority for all cold-designated
  operations; and
- an enrolled validator has no hot fallback.

During the enrollment interval, an unenrolled legacy validator retains legacy
authorization only so it can continue operating while migrating. This
temporary compatibility ends absolutely at enforcement.

Before scheduling enforcement, release operators MUST verify from canonical
state that **every active validator** has completed enrollment and confirmed
its cold fingerprint out of band. A mere two-thirds quorum is insufficient:
demoting the remainder would change the active-set denominator and could
increase an adversary's stake fraction. The height remains a deterministic
hard fork; this unanimous-active-set readiness check determines when it is safe
to schedule, not whether individual nodes enforce it.

At enforcement height:

- all cold-designated operations use only the authority matrix in this
  document;
- all legacy encodings for those operations are rejected;
- unenrolled active validators are deterministically demoted;
- their custody state freezes as specified above;
- no hot fallback, compatibility flag or emergency override remains; and
- state roots commit the same deterministic transition on every node.

Historical blocks and signatures remain verifiable under their historical
rules. Mempools purge operations invalid under the new height. Nodes MUST refuse
to start across enforcement if their software does not support the new schema.

A public testnet rehearsal MUST cover enrollment, partial enrollment,
enforcement demotion, bond migration, rotation, unbonding across both heights,
governance commit/reveal boundaries, snapshot restore and state-root agreement.
Mainnet activation is prohibited until external review is complete.

## 5. Downgrade and fallback prohibitions

### 5.1 No classical-only path

This design contains no classical-only identity, authorization, rotation,
enrollment or recovery path. Every hot or cold authorization invokes the full
hybrid verifier. Loss has no recovery exception.

### 5.2 No component mixing

Each registry entry stores a complete role-specific pair. Verification accepts
one complete signature object against exactly one stored pair. Dual-required
operations perform two complete hybrid verifications. They never combine the
hot Ed25519 component with cold ML-DSA-87, or the reverse.

Component-level global uniqueness checks additionally reject reuse across hot
and cold roles.

### 5.3 No post-enforcement legacy fallback

After `VALIDATOR_COLD_KEY_ENFORCEMENT_HEIGHT`, a cold-designated operation has
one valid authority: the current registered cold pair. Unenrolled validators
freeze; they do not fall back to hot authorization. Legacy wire encodings are
rejected.

### 5.4 Full-pair identity and ownership binding

`validator_id` remains a stable index derived from the hot classical key, but
it is never an ownership proof. Cold authority and custody output creation
always resolve the complete cold pair from consensus-committed state and verify
both components. Enrollment proves possession of both proposed cold
components. UTXO owner fields contain the complete hybrid public key.

### 5.5 Independent entropy

The cold Ed25519 and ML-DSA-87 seeds are independently randomly generated
offline and are not derived from hot, VRF, payment or shared validator entropy.
The protocol and tooling reject any workflow that imports a hot seed as cold
seed material.

The protocol cannot inspect entropy provenance from public keys. Operational
conformance therefore requires audited key-generation tooling and ceremony.
This limitation is explicit and is part of external review.

### 5.6 Rotation cannot downgrade or bypass

Rotation requires the current full cold signature and the proposed new full
cold signature over the same role-separated message. The new pair is subject to
the same size, uniqueness and cross-role checks as initial enrollment. Version
and nonce advance atomically. There is no hot approval, hot cancellation,
classical recovery, delayed mixed-version window, old-key fallback or
administrator override.

## 6. Post-quantum security certification for this design

### 6.1 Specification-level conclusion

**This concrete specification does not reduce or weaken INDRA's existing
hybrid-signature post-quantum security invariant.**

That conclusion follows specifically from these rules:

1. Every cold authority is Ed25519 plus ML-DSA-87.
2. Both components sign the same canonical, chain-bound, role-bound message.
3. Both components must verify against one complete consensus-registered pair.
4. Dual-required operations require two complete hybrid verifications, not a
   split or aggregated signature.
5. Hot and cold secrets use independent entropy and distinct domains.
6. The stable classical-derived validator ID is only an index; authorization
   always resolves and verifies the full pair.
7. No cold operation has a hot, classical-only, legacy or recovery fallback
   after enforcement.
8. Rotation preserves exactly the same full-hybrid checks and advances
   atomically.
9. Cold output ownership is a full `HybridPubKey`, and later spending again
   requires both signature components.
10. Existing consensus voting and QC hybrid verification are unchanged.

Under this specification, breaking ML-DSA-87 alone is insufficient to forge a
cold authorization because Ed25519 must also verify. Breaking Ed25519 alone is
insufficient because ML-DSA-87 must also verify. The addition of a second
independent pair creates no signature-combination rule by which one component
of either pair can substitute for another.

The specification also does not weaken consensus safety rules. Hot voting, QC
verification, VRF verification, slash-evidence verification, quorum thresholds
and stake accounting are unchanged. Cold custody cannot veto valid slashing.
Governance authority moves from hot to cold rather than becoming weaker or
permissionless. The enforcement transition can harm liveness if it is scheduled
with any unenrolled active validator and can alter the active-set trust
distribution, which is why scheduling requires verified enrollment of the
entire active set; it does not create an alternate signature or quorum rule.
Incorrect scheduling is an operational activation risk, not a cryptographic
downgrade, and must be reviewed independently.

### 6.2 What cannot be absolutely certified at this phase

**I cannot certify with absolute certainty that an implementation which does
not yet exist cannot compromise chain security or PQ security.**

That stronger claim requires evidence that is unavailable in a document-only
phase:

- implementation review proving every verifier follows this specification;
- tests proving there is no legacy fallback or component-mixing path;
- serialization and state-root compatibility evidence;
- audited entropy generation and offline-signing tooling;
- migration rehearsal with real historical state;
- cryptanalysis of the libraries and primitives outside this design; and
- independent external protocol and cryptographic review.

There are also two irreducible limitations which are not PQ downgrades:

1. Public keys cannot prove that operators actually used independent entropy.
   Audited tooling and ceremony must enforce that operational requirement.
2. A valid current cold key, once compromised, is indistinguishable from its
   legitimate holder. It can authorize rotation or custody actions until a
   legitimate rotation wins the on-chain nonce race.

Therefore the unambiguous certification is:

- **At the specification level: no PQ weakening or downgrade is introduced.**
- **At the system/implementation level: absolute security is not yet
  certifiable, and mainnet activation is prohibited until implementation
  evidence and external review exist.**

Any implementation that deviates from Sections 1 through 5 fails this
certification.

## 7. External review checklist

### Cryptographic construction

- [ ] Confirm every hot and cold path uses Ed25519 **and** ML-DSA-87 verification.
- [ ] Confirm both components sign byte-identical canonical messages.
- [ ] Confirm hot, cold, governance, staking, enrollment and rotation domains
      cannot collide.
- [ ] Confirm chain ID, role, operation tag, validator ID, version, nonce and
      full payload are covered by every relevant signature.
- [ ] Confirm dual-required verification means two complete hybrid
      verifications.
- [ ] Confirm no aggregation, threshold, OR-composition or cross-pair mixing is
      present.
- [ ] Confirm exact public-key and signature lengths fail closed.
- [ ] Confirm malformed and noncanonical Ed25519 and ML-DSA-87 values fail
      closed.

### Key generation and custody

- [ ] Audit that cold Ed25519 and ML-DSA-87 seeds use independent CSPRNG calls.
- [ ] Confirm no hot, VRF, payment or common-root derivation exists.
- [ ] Review offline signer display and human-verification fields.
- [ ] Verify cold secrets never cross online CLI/FFI/RPC boundaries.
- [ ] Verify encrypted backup guidance and key-loss warnings.
- [ ] Confirm tooling detects accidental public-component reuse.

### Registry and identity binding

- [ ] Confirm `validator_id` is treated only as an index.
- [ ] Confirm every authority lookup resolves the full role-specific pair.
- [ ] Confirm cold pair, version, status and nonce are consensus committed.
- [ ] Confirm global component uniqueness across validators and hot/cold roles.
- [ ] Confirm registration proves possession of both complete pairs.
- [ ] Confirm existing enrollment binds hot and proposed cold signatures to
      identical migration bytes.
- [ ] Confirm snapshot encode/decode and state-root projection preserve all new
      fields.

### Authority matrix

- [ ] Trace every operation in Section 1 from RPC/relay admission through block
      application and confirm the assigned authority.
- [ ] Confirm `UpdateNetworkAddress` cannot affect custody.
- [ ] Confirm governance `Execute` cannot change approved payloads or move
      signer funds.
- [ ] Confirm cold governance commit/reveal flows remain usable through
      rotation and nonce changes.
- [ ] Confirm authorized reads grant no write or payout capability.

### UTXO and staking flows

- [ ] Trace new registration bonds, self-stakes, unstakes, slashed releases,
      claims, evictions and governance refunds to the correct cold owner.
- [ ] Confirm delegator outputs remain assigned to the delegator's full pair.
- [ ] Confirm no output recipient can be substituted in a signed request.
- [ ] Confirm ordinary transactions require the exact input owner pair.
- [ ] Confirm a transaction cannot mix hot and cold inputs.
- [ ] Confirm fully compact bond owner resolution uses the explicit custody
      discriminator and complete registry pair.
- [ ] Confirm missing cold identity fails atomically without burn or hot
      fallback.

### Rotation, loss and races

- [ ] Confirm rotation requires current-cold and new-cold complete signatures.
- [ ] Confirm version increments by exactly one and nonce handling is atomic.
- [ ] Confirm the first committed conflicting rotation wins deterministically.
- [ ] Confirm old-version mempool operations are purged.
- [ ] Confirm unresolved bonds follow the new key while existing UTXOs remain
      old-key-owned.
- [ ] Confirm the hot key cannot rotate, veto, cancel or recover the cold key.
- [ ] Confirm no administrator, governance or classical-only recovery exists.
- [ ] Test rotation around `SelfUnstake`, claim, eviction and governance
      commit/reveal boundaries.

### Migration and activation

- [ ] Confirm both activation heights are inert until explicitly scheduled.
- [ ] Confirm new registrations are dual-required from enrollment height.
- [ ] Confirm enrolled validators lose hot fallback immediately.
- [ ] Confirm all fallback ends at enforcement height.
- [ ] Confirm unenrolled active validators are deterministically demoted.
- [ ] Confirm frozen custody remains accounted, slashable and not burned.
- [ ] Confirm deterministic batched bond migration is bounded and resumable.
- [ ] Confirm enrollment cannot change the chosen cold pair mid-migration.
- [ ] Confirm historical blocks remain verifiable under historical rules.
- [ ] Rehearse mixed old/new nodes and prove unsupported nodes fail visibly.
- [ ] Rehearse snapshot restore before, during and after both heights.
- [ ] Compare state roots across independent implementations or test harnesses.
- [ ] Verify enrollment and out-of-band fingerprint confirmation for every
      active validator before scheduling enforcement; do not accept quorum-only
      readiness.

### Adversarial tests

- [ ] Hot signature plus cold PQ signature is rejected.
- [ ] Cold signature plus hot PQ signature is rejected.
- [ ] Classical-only, PQ-only and either-component signatures are rejected.
- [ ] Wrong role, chain, version, nonce, validator ID or operation tag is
      rejected.
- [ ] Legacy hot `SelfUnstake`, claim, commission, auto-delegation, payment-key
      and governance operations are rejected after enforcement.
- [ ] A hot-compromised validator cannot enroll after a legitimate enrollment.
- [ ] A hot-compromised validator cannot rotate or spend cold custody.
- [ ] A cold-compromised validator cannot vote in consensus or authenticate as
      the hot role.
- [ ] Missing-key and malformed-state cases fail atomically.
- [ ] Reorganizations across enrollment, rotation and enforcement preserve one
      deterministic authority state.

### Review outcome

- [ ] Record every assumption and residual risk.
- [ ] Require remediation and re-review for any deviation from Sections 1–5.
- [ ] Issue separate conclusions for specification correctness,
      implementation conformance, migration safety and operational key
      generation.
- [ ] Do not approve mainnet activation on specification review alone.

## Resolution of the investigation's previously open questions

Every previously listed uncertainty is resolved as follows:

1. **Validator governance authority:** propose, commit, reveal and cancel are
   cold-only; execute is hot-only and mechanical.
2. **Commission and auto-delegation:** cold-only.
3. **Loss recovery:** none.
4. **Rotation effect on bonds:** all unresolved self-bonds resolve the current
   cold key; already-created UTXOs retain their recorded owner.
5. **Validator ID:** remains the hot-classical-derived stable ID; the full cold
   pair is layered onto the committed validator registry.
6. **Legacy hot-owned bonds:** unresolved self-bonds migrate during dual-signed
   enrollment; already-created ordinary UTXOs require an ordinary sweep.
7. **Output authority model:** protocol custody outputs are directly owned by
   the registered full cold pair; no separate third custody key is introduced.
8. **Activation and rollback:** two explicit height gates, deterministic
   demotion/freeze at enforcement, historical-rule verification, no
   post-enforcement fallback, and no mainnet scheduling before review and
   rehearsal.
