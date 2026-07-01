# CS-05 Proposer Uniqueness Diagnostic

## Root Cause (code evidence)

`elect_proposer` currently computes a total-order winner from a mixed data set: the claiming validator's real VRF output, when available, and synthetic public fallback outputs for everyone else.

Code trace:

- `indra-consensus/src/proposer.rs:10-18` defines `ProposerCandidate::verified_vrf_output: Option<VrfOutput>`.
- `indra-consensus/src/proposer.rs:98-102` defines `candidate_output(vrf_pubkey, vrf_input)` as `SHA256(vrf_pubkey || vrf_input)`.
- `indra-consensus/src/proposer.rs:121-128` uses `candidate.verified_vrf_output` when present, otherwise falls back to `candidate_output`.
- `indra-consensus/src/proposer.rs:132-138` picks the lowest stake-weighted score, then ties by output bytes and validator ID.
- `indra-node/src/engine.rs:381-400` computes the local node's actual VRF output in `is_proposer`, injects only that local output into the candidate list, and calls `elect_proposer`.
- `indra-node/src/engine.rs:483-504` repeats the same one-real-output election for reproposals.
- `indra-consensus/src/producer.rs:75-104` repeats the same check during block construction: find the local VRF public key, compute its actual output, inject only that output, then require `elect_proposer` to return that local validator.
- `indra-node/src/sync.rs:314-343` verifies an incoming proposal by finding the one validator whose VRF proof matches the header output, injecting only that proposer output, and calling `elect_proposer`.
- `indra-node/src/bin/node.rs:1438-1468` and `indra-node/src/bin/node.rs:1522-1545` build proposal-loop elections with every `verified_vrf_output` set to `None`; only `is_proposer`, `propose`, `repropose`, or `verify_proposer_vrf` fills in one output later.

That means the election result is perspective-dependent:

- When A evaluates its own slot, the candidate set is `{A_actual, B_fallback, C_fallback, D_fallback}`.
- When B evaluates its own slot, the candidate set is `{A_fallback, B_actual, C_fallback, D_fallback}`.
- When a verifier checks A's proposal, it reconstructs the same `{A_actual, others_fallback}` view.
- When a verifier checks B's proposal, it reconstructs `{B_actual, others_fallback}`.

Both A and B can therefore pass proposer verification for the same `(height, round)`. This does not violate safety after full-hash voting, because votes/QCs certify specific `block_hash()` values, but it can split votes and force extra rounds.

The local first-arrival staging rule contains the damage on each node, but does not make the network agree on one proposal:

- `indra-node/src/driver.rs:892-899` rejects a second different block for the same `(height, round)` once a node has staged one.
- `indra-node/src/bin/node.rs:215-231` suppresses local fresh proposal production if the node already has a staged proposal for that slot.

Those rules are useful containment. They do not eliminate multi-winner election because different validators can see different valid proposals first.

## Frequency Estimate

No live validator journals are present in the workspace. A search of local logs found only `indra-data/blocks.log` plus diagnostic markdown references, not the raw multi-node `[proposer] producing block` streams needed to prove an observed same-round multi-proposer event from logs.

Mathematically, for 4 equal-stake validators, the current scheme makes multi-winner slots common, not rare.

Model:

- Let each validator's actual VRF score be an independent uniform value `T_i`.
- Let each validator's public fallback score be an independent uniform-looking deterministic value `F_i`.
- Validator `i` believes it is proposer if `T_i < min(F_j for j != i)`.

For four equal validators, the expected number of apparent proposers is approximately 1 per slot, but the distribution is wide:

| Apparent proposers in a slot | Approximate probability |
|---:|---:|
| 0 | 37.5% |
| 1 | 35.7% |
| 2 | 17.9% |
| 3 | 7.2% |
| 4 | 1.8% |

So `P(two or more apparent proposers) ≈ 26.8%`, and `P(no apparent proposer) ≈ 37.5%`.

This estimate assumes equal stake and uniform-looking hash/VRF outputs. Unequal stake changes the thresholds, but the core problem remains: each candidate is comparing their private true output against other candidates' public fallback values, so the election is not a single shared function.

Operationally, this explains avoidable proposer churn:

- Multi-winner slots split prevotes by full block hash.
- Zero-winner slots produce no proposal until timeout.
- The protocol then relies on later rounds/reproposals to recover.

## candidate_output Analysis

`candidate_output` is defined in `indra-consensus/src/proposer.rs:98-102`:

```rust
pub fn candidate_output(vrf_pubkey: &[u8; 32], vrf_input: &[u8; 32]) -> VrfOutput {
    let mut data = Vec::with_capacity(vrf_pubkey.len() + vrf_input.len());
    data.extend_from_slice(vrf_pubkey);
    data.extend_from_slice(vrf_input);
    VrfOutput(sha256(&data))
}
```

Inputs:

- the validator's public VRF key;
- the election input computed from epoch seed, height, and round.

Properties:

- Deterministic for a given `(vrf_pubkey, epoch_seed, height, round)`.
- Publicly computable by every node.
- Not a verified VRF output.
- Not equal to the non-claiming validator's actual VRF output except with negligible probability.

The actual VRF output is produced by `compute_proposer_vrf` at `indra-consensus/src/proposer.rs:146-161`, which calls `vrf_prove(keypair, vrf_input)`. That output depends on the validator's secret VRF key. The fallback is only `SHA256(public_key || input)`. It is therefore a deterministic public placeholder, not a substitute for the hidden actual output.

This is the central contradiction: `elect_proposer` acts as if it has comparable outputs for all candidates, but in reality it has one secret-derived output and several public placeholders.

## Fix Options Evaluation

### Option A — Round-robin with VRF tiebreak

Use deterministic validator order as the primary proposer selection rule, e.g. active validator index by `(height + round) mod validator_count`, optionally weighted by stake. VRF could remain in the header as extra entropy or as a tiebreak only when the deterministic rule produces equal candidates.

1. **Eliminates multi-winner?** Yes, if the primary rule is fully public and deterministic. Every validator computes the same winner.
2. **Grinding/predictability risk?** High predictability. A validator can know its proposer slots far in advance. VRF tiebreak does not help unless it is actually needed; with a total round-robin order, it usually is not.
3. **Code size?** Small to medium. Mostly `proposer.rs`, `engine.rs`, `producer.rs`, `sync.rs`, and tests. Existing VRF header fields can remain for compatibility.
4. **Wire/protocol/genesis impact?** Consensus-rule change, but not necessarily a wire-format change if existing VRF fields stay populated. No key regeneration required. Fresh testnet wipe or hard-fork height required.

Assessment: excellent for liveness simplicity, mediocre for anti-targeting and unpredictability.

### Option B — VRF threshold eligibility

Instead of choosing one lowest score, a validator is eligible if its own verified VRF output is below a public threshold. Proposals are valid from any eligible validator.

1. **Eliminates multi-winner?** No. It changes the rule from “one winner” to “zero, one, or many eligible proposers.” Multi-proposer slots still exist by design.
2. **Grinding/predictability risk?** Lower than public deterministic election because eligibility uses secret VRF output. Still vulnerable to validator key grinding if keys can be generated after future inputs are known.
3. **Code size?** Medium. `verify_proposer_vrf` would check threshold eligibility instead of total-order winner. Driver logic must accept that multiple proposals are valid.
4. **Wire/protocol/genesis impact?** Consensus-rule change, no obvious wire-format change if existing VRF proof/output fields stay. No key regeneration required.

Assessment: viable for protocols designed around eligibility, but INDRA currently assumes a single elected proposer. This option does not solve CS-05 as stated; it formalizes a bounded multi-proposer model.

### Option C — VRF commit-reveal

Validators first commit to their VRF output/proof, then reveal. Once enough reveals are available, everyone computes the same lowest-score winner over actual VRF outputs.

1. **Eliminates multi-winner?** Yes, after the reveal set is fixed by protocol rules. Everyone compares the same real outputs.
2. **Grinding/predictability risk?** Best of the listed options if commits bind outputs before reveal and validator registration/epoch seed rules prevent key grinding. Withholding attacks remain: a validator can refuse to reveal if its output is bad, so the design must specify reveal deadlines and penalties/skip rules.
3. **Code size?** Large. Requires new message types or vote fields, new per-round state, timeout rules, slash/penalty or exclusion semantics for non-reveal, and new tests.
4. **Wire/protocol/genesis impact?** Yes. This is a real protocol change and likely wire-format change. No key regeneration required, but simultaneous upgrade/fresh testnet reset would be prudent.

Assessment: strongest mainnet-grade direction, but too invasive for a quick liveness hardening patch.

### Option D — Public-key deterministic election

Use a deterministic public function of the active validator set, epoch seed, parent/tip entropy, height, round, validator ID, VRF public key, and stake to select one proposer. VRF can be retained for epoch-seed generation or future entropy, but not used as a hidden per-round total-order input.

Example score:

```text
score_i = H(
  "INDRA-PROPOSER-PUBLIC-v1" ||
  epoch_seed ||
  height ||
  round ||
  validator_id_i ||
  vrf_pubkey_i
) / stake_i
winner = lowest(score_i), tie by validator_id
```

This is conceptually close to the old all-public `candidate_output` election, but should be made explicit and domain-separated as a public deterministic election rather than mixed with verified private VRF outputs.

1. **Eliminates multi-winner?** Yes. Every validator has all inputs and computes the same winner.
2. **Grinding/predictability risk?** Medium. The proposer sequence is predictable once the seed and active set are known. Key grinding is possible if validators can choose keys after knowing future seeds. Mitigations: registration delay, epoch-level validator-set freeze, using a seed finalized after the registration cutoff, and not allowing cheap key rotation.
3. **Code size?** Medium and clean. `elect_proposer` becomes all-public again; `is_proposer`, `produce_block`, and `verify_proposer_vrf` stop injecting one candidate's actual output for winner selection. Existing VRF proof fields can either be retained and verified only as key-ownership/entropy evidence, or ignored behind a hard-fork height.
4. **Wire/protocol/genesis impact?** Consensus-rule change. No wire-format change is required if the block header keeps existing VRF output/proof fields. No crypto derivation, key regeneration, or state schema change required. Fresh testnet reset or hard-fork height recommended because proposer validity changes.

Assessment: best near-term testnet fix. It restores a single globally determined proposer with moderate implementation cost.

### Option E — First-arrival cap (current behavior + bounded liveness cost)

Keep the current mixed election but rely on each node accepting only the first valid proposal for a slot.

1. **Eliminates multi-winner?** No. It only limits each node to one staged proposal. Different nodes can stage different first arrivals.
2. **Grinding/predictability risk?** Same as the current scheme, plus the existing one-sided VRF comparison problem remains.
3. **Code size?** Minimal, and mostly already implemented. `driver.rs:892-899` rejects a second different block for the same slot; `node.rs:215-231` suppresses local production when a proposal is already staged.
4. **Wire/protocol/genesis impact?** None if left as-is.

Assessment: acceptable safety containment, not a CS-05 fix. It bounds some local duplicate work but still permits repeated vote splitting and timeouts.

## Recommendation

For INDRA testnet, choose **Option D — Public-key deterministic election** as the immediate fix.

Reasoning:

- It completely eliminates the multi-winner problem.
- It is much simpler and safer to implement than commit-reveal.
- It does not require changing cryptographic derivation, genesis key material, state schema, or block wire format if existing VRF fields are retained.
- It matches the current operational priority: correctness and liveness before mainnet, with protocol changes still acceptable.
- It avoids pretending that one proposal can reveal all validators' private VRF outputs. A single proposal cannot support a total-order VRF election unless the other outputs have already been revealed.

For mainnet, keep **Option C — commit-reveal** as the long-term design if INDRA requires private/unpredictable per-round proposer selection with strong anti-grinding properties. That should be a separate protocol design task because reveal withholding, penalties, latency, and wire messages need careful treatment.

Do **not** choose Option B as a direct fix for CS-05; it makes multiple valid proposers an explicit protocol feature. Do **not** choose Option E as the root fix; it is already mostly present and does not prevent vote splitting.

## Proposed Fix Sketch

### Goal

Make proposer election a single public deterministic function evaluated identically by every validator.

### Function-level changes

1. Replace mixed-output winner selection in `indra-consensus/src/proposer.rs::elect_proposer`.

Current shape:

```rust
let output = candidate.verified_vrf_output
    .clone()
    .unwrap_or_else(|| candidate_output(&candidate.vrf_pubkey, &vrf_input));
let score = election_score(&output, candidate.stake, total_stake);
```

Recommended shape:

```rust
let output = public_proposer_output(
    &election.epoch_seed,
    election.height,
    election.round,
    &candidate.validator_id,
    &candidate.vrf_pubkey,
);
let score = election_score(&output, candidate.stake, total_stake);
```

Use a domain-separated hash:

```rust
pub fn public_proposer_output(
    epoch_seed: &Bytes32,
    height: u64,
    round: u32,
    validator_id: &Bytes32,
    vrf_pubkey: &[u8; 32],
) -> VrfOutput {
    let mut data = b"INDRA-PROPOSER-PUBLIC-v1".to_vec();
    data.extend_from_slice(&epoch_seed.0);
    data.extend_from_slice(&height.to_le_bytes());
    data.extend_from_slice(&round.to_le_bytes());
    data.extend_from_slice(&validator_id.0);
    data.extend_from_slice(vrf_pubkey);
    VrfOutput(sha256(&data))
}
```

2. Keep `verified_vrf_output` out of winner selection.

Options:

- leave the field in `ProposerCandidate` temporarily but ignore it in `elect_proposer`;
- or remove it in a larger cleanup once tests are updated.

3. Update `NodeEngine::is_proposer`.

It should:

- verify the local validator ID is active;
- verify local VRF public key matches the registered VRF public key;
- call the public deterministic `elect_proposer`;
- return true only if the elected ID equals the local validator ID.

It should not compute local actual VRF output to decide eligibility.

4. Update `produce_block`.

It should:

- still find the validator candidate matching the local VRF key;
- call public deterministic `elect_proposer`;
- reject if the elected validator ID is not local;
- optionally still compute and include a VRF proof/output for telemetry/future entropy, but not use it as the election score.

5. Update `verify_proposer_vrf`.

Better renamed later to `verify_proposer`.

It should:

- build candidates from the active validator set;
- compute public deterministic winner;
- identify the block proposer either by verifying the included VRF proof against exactly one active validator or by adding an explicit proposer ID field in a future wire-format cleanup;
- require the matched proposer ID equals the public deterministic winner.

For a no-wire-change version, keep requiring the existing VRF proof to identify the proposer key, but do not inject the proof output into `elect_proposer`.

6. Add tests.

Minimum tests:

- Two different validators with valid VRF proofs for the same `(height, round)` cannot both pass proposer verification; only the public deterministic winner passes.
- `is_proposer` returns true for exactly one active validator per `(height, round)` in a 4-validator set.
- `elect_proposer` returns the same winner regardless of any `verified_vrf_output` values present in candidates.
- Weighted selection remains deterministic and stake-sensitive.

### Compatibility notes

- This is a consensus-rule change, not a cryptographic key-derivation change.
- It does not require genesis/key regeneration if the existing active validator set and VRF public keys remain unchanged.
- It does not require a wire-format change if existing VRF proof/output header fields remain.
- It should be gated behind a hard-fork height or activated from genesis on a fresh testnet reset.

