# INDRA Security Audit — Phase 2: Transaction and UTXO Security

## Summary Table

| ID | Component | Finding | Severity | Status |
|----|-----------|---------|----------|--------|
| T-01 | UTXO ownership | Spend authorization requires the owner hybrid signature for all inputs | SAFE | Checked |
| T-02 | Nullifier | Same-block duplicate-UTXO spends with distinct nullifiers are rejected | CRITICAL | FIXED — regression tests added |
| T-03 | Nullifier | Cross-block replay protection works for normal spends because UTXOs are removed and nullifiers persist | SAFE | Checked |
| T-04 | apply.rs | `verify_balance` is called after duplicate input UTXO IDs are rejected | CRITICAL | FIXED via T-02 |
| T-05 | apply.rs / fee.rs | Transaction value sums and required-fee multiplication fail closed on overflow | LOW | FIXED — checked arithmetic regression test added |
| T-06 | apply.rs | Zero-value / dust outputs are rejected in structure and state validation | SAFE | Checked |
| T-07 | fee.rs | Base-fee and per-transaction fee enforcement are deterministic and enforced at block state | SAFE | Checked |
| T-08 | apply.rs / staking | Range proofs verify stored commitments; staking bonds now require explicit commitment opening | SAFE / LOW | FIXED for staking |
| T-09 | transaction.rs | Transaction/block input/output/resource limits exist | SAFE | Checked |
| T-10 | transaction.rs | Transaction signatures cover canonical fields; tx hash includes signatures | SAFE | Checked |
| T-11 | mempool admission | RPC/P2P mempool admission now runs full state validation before insert/gossip | MEDIUM | FIXED — invalid-signature/nonexistent-UTXO tests added |
| T-12 | apply_block | Transactions are applied in deterministic block order; producer canonicalizes selected tx order | SAFE | Checked |

Severity key: CRITICAL / HIGH / MEDIUM / LOW / INFO / SAFE.

## Detailed Findings

### T-01 — UTXO ownership requires a valid owner hybrid signature

**Description:** For each transaction, `validate_transaction` looks up every referenced input UTXO, requires all inputs to share the same `owner_pubkey`, converts that owner key to a crypto public key, and verifies the transaction signature over `tx.signing_bytes(chain_id)`.

**Attack scenario checked:** An attacker observes a UTXO ID, commitment, owner public key, and public value, then attempts to spend it without the owner's hybrid private key.

**Code location:** `indra-state/src/apply.rs:553-597`; `indra-core/src/types/transaction.rs:187-203`.

**Proof-of-concept / reasoning:** Without a valid Ed25519 + ML-DSA hybrid signature under the UTXO owner's public key, `verify_hybrid` returns an error and `apply_block` rejects the block. Existing tests in `apply.rs` include `wrong_signature_rejected`, `zeroed_signature_rejected`, and `wrong_chain_id_rejected`.

**Recommended fix:** None for basic owner authorization. The follow-up fix for T-02 must not weaken this invariant.

**Status:** SAFE.

### T-02 — Same-block duplicate-UTXO spends with distinct nullifiers are rejected

**Description:** The transaction pre-validation pass previously tracked `block_nullifiers`, but did not track input UTXO IDs. A block could contain two transactions that both referenced the same UTXO with different arbitrary nullifiers. Both validated against the same start-of-block UTXO. During mutation, `apply_transaction` called `state.utxos.spend(&input.utxo_id)` but ignored `None`; the second transaction still inserted its nullifier and created outputs.

This is exploitable by a legitimate UTXO owner. They can create two valid signed transactions spending the same UTXO, choose two distinct nullifiers, and create two sets of outputs whose commitments each balance against the same input commitment. The result is two unspent outputs from one original UTXO.

**Attack scenario:**

1. Attacker owns one UTXO with value `V` and knows its blinding.
2. They construct `tx_a` spending `utxo_id` with nullifier `N_a`, output value `V - fee`, and a valid fee/output commitment balance.
3. They construct `tx_b` spending the same `utxo_id` with nullifier `N_b != N_a`, again outputting `V - fee`.
4. `apply_block` pre-validates both transactions before mutating state.
5. `block_nullifiers` sees `N_a` and `N_b` as distinct, so no duplicate is detected.
6. Both transactions load the same still-unspent UTXO during validation and pass signature, fee, range-proof, and balance checks.
7. Mutation spends the UTXO for `tx_a`; mutation for `tx_b` ignores that the UTXO is already gone and still creates `tx_b`'s output.

**Code location:** `indra-state/src/apply.rs:316-329`, `indra-state/src/apply.rs:542-582`, `indra-state/src/apply.rs:665-675`.

**Proof-of-concept:** Added `indra-state/tests/audit_phase2.rs::audit_t01_same_utxo_can_be_spent_twice_in_one_block_with_distinct_nullifiers`. It is ignored by default and can be run explicitly:

```bash
cargo test -p indra-state --test audit_phase2 -- --ignored --nocapture
```

The PoC builds real range-proved, hybrid-signed transactions and confirms the vulnerable behavior: one starting UTXO becomes two unspent outputs and two nullifiers.

**Fix:** `apply_block` now tracks `block_input_utxos: HashSet<Bytes32>` alongside `block_nullifiers` during pre-validation and rejects repeated `input.utxo_id` values both within one transaction and across multiple transactions in the same block. `apply_transaction` now treats `state.utxos.spend(&input.utxo_id) == None` as an invariant violation instead of silently continuing. Longer term, consider binding nullifiers to `(owner secret, utxo_id)` with a verifiable spend proof if the protocol intends nullifiers to be more than replay tags.

**Status:** FIXED. This remediation does not change cryptographic derivation, key material, genesis data, wire encoding, or transaction format. It is a state-validation hardening fix.

### T-03 — Cross-block replay protection works for normal spends

**Description:** `NullifierSet` is append-only, encoded deterministically, and restored from snapshots. `apply_transaction` inserts each input nullifier, and `validate_transaction` rejects nullifiers already in state. UTXOs are removed from `UtxoSet` on spend.

**Attack scenario checked:** Replay the same transaction in a later block, or construct a second transaction reusing the same nullifier.

**Code location:** `indra-state/src/nullifier.rs:44-122`; `indra-state/src/apply.rs:548-550`, `indra-state/src/apply.rs:665-668`.

**Proof-of-concept / reasoning:** A later replay finds either the nullifier already present or the UTXO missing. Existing tests cover `double_spend_same_block_rejected` for duplicate nullifiers and `replay_tx_rejected_by_nullifier`.

**Recommended fix:** Fix T-02. After that, cross-block replay protection remains sound.

**Status:** SAFE.

### T-04 — `verify_balance` is called after duplicate input commitments are rejected

**Description:** `verify_balance` is called for every transaction, using the exact input commitments from referenced UTXOs, output commitments from transaction outputs, and the fee commitment. This re-verifies the Phase 1 C-15 finding. The former T-02 bug allowed the same input commitment to appear twice in one block, either across two transactions or twice in one transaction with distinct nullifiers. That duplicate input path is now rejected before `verify_balance` is trusted.

**Attack scenario:** The T-02 exploit passes `verify_balance` because each transaction independently balances against the same input commitment observed during start-of-block validation.

**Code location:** `indra-state/src/apply.rs:558-562`, `indra-state/src/apply.rs:632-651`.

**Proof-of-concept:** Same PoC as T-02, now inverted into regression tests.

**Fix:** Input UTXO uniqueness is enforced during block-level transaction pre-validation. Regression tests cover duplicate UTXO spends both across two transactions and within one transaction.

**Status:** FIXED via T-02.

### T-05 — Value arithmetic uses saturating operations

**Description:** Consensus-critical transaction arithmetic now fails closed instead of saturating silently. `validate_transaction` uses checked arithmetic for input public-value totals, output public-value totals, output-plus-fee totals, and required-fee multiplication.

**Attack scenario checked:** Carefully choose values/fees/output sums to overflow and wrap into an apparently valid balance.

**Code location:** `indra-state/src/apply.rs` transaction validation; `indra-state/src/error.rs::StateError::ValueOverflow`; `indra-state/src/fee.rs:38-70`.

**Proof-of-concept / reasoning:** `indra-state/tests/audit_phase2.rs::transaction_with_overflowing_input_sum_is_rejected` constructs a malformed state whose transaction inputs sum above `u64::MAX`; validation now returns `StateError::ValueOverflow` before signature/range-proof work or state mutation.

**Fix:** Replaced transaction value sums and required-fee multiplication with `checked_add`/`checked_mul`. The EIP-1559-style base-fee controller in `fee.rs` intentionally remains saturating/clamping and now has a comment explaining why that is not a balance equation.

**Status:** FIXED.

### T-06 — Dust outputs are rejected

**Description:** Output dust is checked in both `TransactionV1::validate_structure` and `validate_transaction`. Zero-output transactions are rejected, and zero-value outputs are below `DUST_LIMIT_SPARK`.

**Attack scenario checked:** Create many zero/dust outputs to bloat the UTXO set.

**Code location:** `indra-core/src/types/transaction.rs:130-166`; `indra-state/src/apply.rs:521-525`, `indra-state/src/apply.rs:632-638`.

**Proof-of-concept / reasoning:** Decode caps outputs at `MAX_OUTPUTS`, structure validation rejects output values below `DUST_LIMIT_SPARK`, and block validation caps transactions per block.

**Recommended fix:** None for consensus. CLI builder should align its change-output behavior with the chain dust rule; see T-11 notes.

**Status:** SAFE.

### T-07 — Fee and base-fee checks are enforced at the current block state

**Description:** `validate_block_header` requires `block.header.base_fee == state.base_fee`. Each transaction must pay `state.base_fee * tx_weight_kb`. The next base fee is computed after applying the block from the number of transactions in that block.

**Attack scenario checked:** Include a transaction below current base fee, or propose a block using stale/future base fee to make low-fee transactions pass.

**Code location:** `indra-state/src/apply.rs:498-504`, `indra-state/src/apply.rs:608-619`, `indra-state/src/apply.rs:398-400`; `indra-state/src/fee.rs:38-70`.

**Proof-of-concept / reasoning:** A wrong header base fee is rejected before state mutation. A low-fee transaction is rejected during validation. Existing tests include `wrong_base_fee_rejected` and `fee_too_low_rejected`.

**Recommended fix:** None for consensus.

**Status:** SAFE.

### T-08 — Range proofs verify against stored commitments; aggregate binding is enforced

**Description:** For each output, `verify_range` is called with `output.commitment.compressed_point.0`, which is the same commitment later cloned into the `UtxoSet`. The aggregate commitment equation is then checked with `verify_balance`.

**Attack scenario checked:** Provide a valid range proof for commitment `C1` but store a different commitment `C2` in the UTXO.

**Code location:** `indra-state/src/apply.rs:632-651`; `indra-state/src/apply.rs:670-675`; `indra-state/src/utxo.rs:226-241`.

**Proof-of-concept / reasoning:** No alternate commitment is introduced between validation and storage; the output object is cloned directly into the UTXO set.

**Caveat:** For ordinary transaction outputs, the public `OutputV1.value_spark` field remains public accounting metadata; the transaction-level public sum and aggregate commitment equation prevent simple inflation in normal UTXO spends. Staking/delegation is different because it consumes an individual output as economic collateral, so that path now requires the spender to reveal a staking-specific opening proof for the bond UTXO.

**Fix / hardening:** `RegisterValidator`, `SelfStake`, and `Delegate` now carry `StakingBondProof { committed_value_spark, blinding_factor }`. At activation height, state validation requires this proof and verifies that it opens the exact stored output commitment and that the opened value equals `output.value_spark` before the UTXO is spent. This closes the staking-specific T-08/ST-03 risk while preserving the existing aggregate balance model for ordinary transaction outputs.

**Status:** FIXED for staking; SAFE for direct transaction inflation.

### T-09 — Transaction size and resource limits exist

**Description:** Transactions are bounded by `MAX_INPUTS`, `MAX_OUTPUTS`, and `MAX_RANGE_PROOF_BYTES`; blocks are bounded by `MAX_TX_PER_BLOCK` and `MAX_BLOCK_SIZE_BYTES`. Decoding uses these limits for on-wire transactions inside blocks.

**Attack scenario checked:** Submit a single transaction with excessive inputs/outputs/range proofs to consume CPU or memory.

**Code location:** `indra-core/src/types/primitives.rs:94-103`, `indra-core/src/types/primitives.rs:147`; `indra-core/src/types/transaction.rs:234-245`; `indra-core/src/types/block.rs:185-195`; `indra-state/src/apply.rs:483-494`.

**Proof-of-concept / reasoning:** Decoding enforces list and variable-byte limits. Applying a block also checks encoded block size and transaction count.

**Recommended fix:** Keep the limits. Consider adding transaction-level encoded-size checks in mempool admission for clearer errors before gossip.

**Status:** SAFE.

### T-10 — Transaction hash malleability was not found

**Description:** Transaction signing bytes include a literal `TX_SIGN` domain, chain ID, version, signature module, inputs, outputs, fee amount, fee blinding, and fee commitment. The transaction hash is SHA-256 of the full canonical encoding including signatures.

**Attack scenario checked:** Change a transaction ID/hash without invalidating signatures, or replay across chains.

**Code location:** `indra-core/src/types/transaction.rs:187-208`, `indra-core/src/types/transaction.rs:212-245`.

**Proof-of-concept / reasoning:** Any change to signed fields invalidates the hybrid signature. Any change to signatures changes `tx_hash`. Chain ID is included in the signed bytes.

**Recommended fix:** None for current encoding. If future optional/legacy decode fields are added, ensure they are either signed or excluded from transaction identity by design.

**Status:** SAFE.

### T-11 — Mempool admission is weaker than block application

**Description:** RPC and P2P mempool admission now run full state-machine transaction validation before insertion or gossip. `Mempool::submit` remains the lightweight internal insertion primitive, while `Mempool::submit_validated` is the admission path for external transactions.

**Attack scenario:**

1. Attacker submits many structurally valid but signature-invalid or UTXO-invalid transactions with sufficient fee fields.
2. Admission calls `validate_transaction` against current state with fresh per-admission duplicate-nullifier and duplicate-UTXO tracking.
3. Signature-invalid, unknown-UTXO, locked-output, double-spend, or balance-invalid transactions are rejected before mempool insertion and before gossip.
4. Final `apply_block` validation remains authoritative in case state changes between admission and inclusion.

**Code location:** `indra-consensus/src/mempool.rs::submit_validated`; `indra-node/src/driver.rs::process_tx`; `indra-node/src/bin/node.rs` transaction RPC path; `indra-node/src/lib.rs::rpc_submit_transaction`.

**Proof-of-concept / reasoning:** Regression tests in `indra-consensus/src/mempool.rs` cover invalid signatures, nonexistent UTXOs, and successful admission of a fully valid transaction.

**Lock-contention note:** The node already holds the consensus/engine lock while processing inbound transaction events and RPC submission. The new validation uses a current state snapshot and does not acquire an additional nested lock, so it does not introduce a new deadlock pattern. The tradeoff is extra snapshot/validation work at admission; invalid transactions are rejected before network gossip, which is the intended DoS reduction.

**Status:** FIXED.

### T-12 — Transaction order is deterministic

**Description:** `apply_block` validates and applies transactions in the exact order in `block.transactions`. The producer selects from mempool deterministically and then sorts selected transactions by `tx_hash`. The block's full hash now commits to the exact block, and every validator applies the same ordered transaction vector.

**Attack scenario checked:** Two validators apply the same block's transactions in different orders and reach different states.

**Code location:** `indra-state/src/apply.rs:321-329`, `indra-state/src/apply.rs:360-363`; `indra-consensus/src/producer.rs:107-115`.

**Proof-of-concept / reasoning:** There is no map iteration in transaction application; ordering is the block vector order. The earlier consensus fix to vote over full `block_hash()` means the transaction order is certified as part of the full block identity.

**Recommended fix:** None for current transaction ordering. Add a regression test that selected mempool transactions are sorted by `tx_hash` before production.

**Status:** SAFE.

## Proof-of-Concept Tests

Added/updated:

- `indra-state/tests/audit_phase2.rs::t02_duplicate_utxo_spend_across_two_transactions_in_one_block_is_rejected`
- `indra-state/tests/audit_phase2.rs::t02_duplicate_utxo_spend_within_single_transaction_inputs_is_rejected`
- `indra-state/tests/audit_phase2.rs::legitimate_single_spend_still_works_after_duplicate_utxo_fix`
- `indra-state/tests/audit_phase2.rs::transaction_with_overflowing_input_sum_is_rejected`
- `indra-state/src/apply.rs::apply_transaction_fails_loudly_if_utxo_already_spent`
- `indra-state/src/delegation.rs` staking bond proof tests covering accepted openings, missing proofs, wrong blindings, value mismatches, and rollback/no-spend behavior on failure
- `indra-consensus/src/mempool.rs::mempool_rejects_transaction_with_invalid_signature`
- `indra-consensus/src/mempool.rs::mempool_rejects_transaction_spending_nonexistent_utxo`
- `indra-consensus/src/mempool.rs::mempool_accepts_valid_transaction`

The original exploit PoC was inverted: the duplicate-UTXO block now fails with `StateError::DuplicateUtxoSpend`, the original UTXO remains unspent, nullifiers are unchanged, and height does not advance.

## Findings NOT Present

- Non-owner UTXO theft was not found: spends require a valid hybrid signature from the input UTXO owner.
- Cross-chain transaction replay was not found: transaction signing bytes include `chain_id`.
- Base-fee bypass was not found: block header base fee must match state, and each transaction must pay at least current `base_fee * weight_kb`.
- Range proof substitution was not found: proofs are verified against the same commitment stored in the UTXO output.
- Commitment balance omission was not found: `verify_balance` is called for every validated transaction.
- Zero/dust UTXO spam was not found in consensus: dust outputs and zero-output transactions are rejected, and inputs/outputs are capped.
- Transaction application order non-determinism was not found: application follows the block vector order, and production canonicalizes selected mempool transactions by transaction hash.

## Recommended Fix Order

1. **Strengthen nullifier semantics:** if nullifiers are intended to prove ownership-secret derivation, add a verifiable spend/nullifier proof or redesign the input authorization model so arbitrary nullifiers cannot be chosen freely.
2. **Fix CLI dust-change construction:** when positive change is below or equal to dust and omitted, either add it to `fee_amount` and fee commitment or reject construction before signing.

## Phase 2 Hardening Change Scope

The original T-05/T-08/T-11 hardening pass did **not** change cryptographic derivation, wire format, state schema, genesis data, or validator/key material. The later ST-03/T-08 follow-up intentionally adds a staking-op wire-format change for `RegisterValidator`, `SelfStake`, and `Delegate` by carrying `StakingBondProof`; on testnet this requires a fresh wipe or coordinated hard-fork activation. It does **not** change cryptographic derivation, key material, genesis validator keys, or the block/QC wire format.
