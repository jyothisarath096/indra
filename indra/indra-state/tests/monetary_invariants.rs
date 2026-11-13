//! Consensus monetary invariants for the transparent-value transaction format.

use indra_core::types::primitives::TEST_CHAIN_ID;

use indra_core::types::{
    block::{BlockHeaderVNext, BlockVNext},
    crypto::{HybridPubKey, HybridSignature},
    primitives::{
        Bytes32, ProtocolVersion, VariableBytes, LIFETIME_SUPPLY_CAP_SPARK, MAX_QC_SIZE_BYTES,
        TRANSACTION_PROTOCOL_VERSION,
    },
    transaction::{InputV1, OutputV1, TransactionV1},
};
use indra_crypto::{ClassicalKeypair, HybridKeypair, PqKeypair, VrfKeypair};
use indra_state::{
    apply_block_for_test as apply_block, ChainState, StateError, ValidatorEntry, ValidatorStatus,
};
use indra_state::{apply_epoch_transition, EpochTransitionContext};

fn keypair(seed: [u8; 32]) -> (HybridPubKey, HybridKeypair) {
    let pair = HybridKeypair::new(
        ClassicalKeypair::from_seed(&seed),
        PqKeypair::from_seed(&seed).unwrap(),
    );
    let public = pair.public_key();
    (
        HybridPubKey {
            classical_pk: Bytes32::from(public.classical.0),
            pq_pk: VariableBytes::from_slice(&public.pq.0).unwrap(),
        },
        pair,
    )
}

fn dummy_sig() -> HybridSignature {
    HybridSignature {
        classical_sig: VariableBytes::from_slice(&[0; 64]).unwrap(),
        pq_sig: VariableBytes::from_slice(&[0; 4627]).unwrap(),
    }
}

fn output(value_spark: u64, owner_pubkey: HybridPubKey) -> OutputV1 {
    OutputV1 {
        value_spark,
        owner_pubkey,
        lock_height: 0,
    }
}

fn validator(owner: &HybridPubKey) -> ValidatorEntry {
    ValidatorEntry {
        validator_id: owner.identity_id(),
        name: "money".into(),
        hybrid_classical_pk: Some(owner.classical_pk.0),
        hybrid_pq_pk: Some(owner.pq_pk.as_slice().to_vec()),
        vrf_pk: Some(VrfKeypair::from_seed(&[7; 32]).public_key()),
        vrf_key_activation_epoch: 0,
        pending_vrf_pk: None,
        pending_vrf_activation_epoch: None,
        stake_spark: 1_000_000,
        status: ValidatorStatus::Active,
        registered_epoch: 0,
        last_active_epoch: 0,
        slashed_offense_id: None,
        commission_bps: 0,
        pending_commission_bps: None,
        pending_commission_effective_epoch: None,
        min_delegation_spark: 1,
        auto_delegate_to: None,
        network_addr: None,
        network_addr_last_updated_epoch: None,
        cold_hybrid_classical_pk: Some(owner.classical_pk.0),
        cold_hybrid_pq_pk: Some(owner.pq_pk.as_slice().try_into().unwrap()),
        cold_key_version: 1,
        cold_nonce: 0,
    }
}

fn state() -> (ChainState, HybridPubKey, HybridKeypair) {
    let (owner, pair) = keypair([9; 32]);
    let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
    state.active_slot_coefficient_numerator =
        indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR;
    state.validators.upsert(validator(&owner)).unwrap();
    state.finalize_genesis().unwrap();
    // Isolate value conservation and dust from fee-market policy.
    state.base_fee = 0;
    (state, owner, pair)
}

fn account_fixture_claims(state: &mut ChainState) {
    state.monetary_aggregates = state.recompute_monetary_aggregates().unwrap();
    let issued = state.monetary_aggregates.total_claims_spark().unwrap();
    state.total_supply = issued;
    state.monetary_ledger.genesis_issued_spark = issued;
    state.monetary_ledger.reward_budget_spark = LIFETIME_SUPPLY_CAP_SPARK - issued;
    state.monetary_ledger.validate(issued).unwrap();
}

fn signed_tx(
    state: &ChainState,
    pair: &HybridKeypair,
    inputs: Vec<Bytes32>,
    outputs: Vec<OutputV1>,
    fee_amount: u64,
) -> TransactionV1 {
    let mut tx = TransactionV1 {
        version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
        signature_module_id: 1,
        inputs: inputs
            .into_iter()
            .enumerate()
            .map(|(_, utxo_id)| InputV1 { utxo_id })
            .collect(),
        outputs,
        fee_amount,
        signature: dummy_sig(),
    };
    let sig = pair
        .sign(&tx.signing_bytes(&state.chain_id).unwrap())
        .unwrap();
    tx.signature = HybridSignature {
        classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
        pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
    };
    tx
}

fn block(state: &ChainState, tx: TransactionV1) -> BlockVNext {
    BlockVNext {
        header: BlockHeaderVNext {
            protocol_version: ProtocolVersion::CURRENT,
            height: state.height + 1,
            prev_hash: state.tip_hash,
            timestamp: 1_700_000_001,
            state_root: Bytes32::ZERO,
            validator_set_root: Bytes32::ZERO,
            mempool_set_root: Bytes32::ZERO,
            value_hash: Bytes32::ZERO,
            base_fee: state.base_fee,
            proposer_round: 0,
            polc_round: None,
            proposer_id: Bytes32::from([0x83; 32]),
            vrf_suite: indra_core::types::block::VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
            election_seed: state.election_seed,
            proposer_vrf_output: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            proposer_vrf_proof: VariableBytes::from_slice(&[0u8; 80]).unwrap(),
            value_entropy: indra_core::types::block::ProposalEntropyV1 {
                origin_proposer_id: Bytes32::from([0x83; 32]),
                origin_round: 0,
                vrf_output: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                vrf_proof: VariableBytes::from_slice(&[0u8; 80]).unwrap(),
            },
            sortition_claim: indra_core::types::block::SortitionClaimV1::PraosThreshold,
            proposer_priority: indra_core::types::primitives::Bytes64([0; 64]),
            quorum_certificate: VariableBytes::<MAX_QC_SIZE_BYTES>::from_slice(&[]).unwrap(),
        },
        transactions: vec![tx],
        slashing_evidence: vec![],
        governance_ops: vec![],
        staking_ops: vec![],
    }
}

fn apply_values(inputs: &[u64], outputs: &[u64], fee: u64) -> Result<(), StateError> {
    let (mut state, owner, pair) = state();
    let ids = inputs
        .iter()
        .enumerate()
        .map(|(i, value)| {
            state
                .utxos
                .insert(output(*value, owner.clone()), 0, i as u32, 0)
                .unwrap()
        })
        .collect();
    if inputs
        .iter()
        .try_fold(0u64, |sum, value| sum.checked_add(*value))
        .is_some_and(|input_total| {
            state
                .total_supply
                .checked_add(input_total)
                .is_some_and(|total| total <= LIFETIME_SUPPLY_CAP_SPARK)
        })
    {
        account_fixture_claims(&mut state);
    }
    let tx = signed_tx(
        &state,
        &pair,
        ids,
        outputs.iter().map(|v| output(*v, owner.clone())).collect(),
        fee,
    );
    let block = block(&state, tx);
    apply_block(&mut state, &block, 0).map(|_| ())
}

#[test]
fn outputs_plus_fee_greater_than_inputs_is_rejected() {
    assert!(apply_values(&[1_000_000], &[900_001], 100_000).is_err());
}

#[test]
fn output_plus_fee_overflow_is_rejected() {
    assert!(matches!(
        apply_values(&[u64::MAX], &[u64::MAX], 1),
        Err(StateError::ValueOverflow)
    ));
}

#[test]
fn multi_input_sum_overflow_is_rejected() {
    assert!(matches!(
        apply_values(&[u64::MAX, 1], &[u64::MAX], 1),
        Err(StateError::ValueOverflow)
    ));
}

#[test]
fn output_accumulation_overflow_is_rejected() {
    assert!(matches!(
        apply_values(&[u64::MAX], &[u64::MAX, 1], 0),
        Err(StateError::ValueOverflow)
    ));
}

#[test]
fn exact_public_conservation_succeeds_without_commitment_fields() {
    assert!(apply_values(&[1_000_000, 2_000_000], &[2_900_000], 100_000).is_ok());
}

#[test]
fn dust_boundaries_are_consensus_enforced() {
    let dust = indra_core::types::primitives::DUST_LIMIT_SPARK;
    assert!(apply_values(&[dust], &[0], dust).is_err());
    assert!(apply_values(&[dust], &[dust - 1], 1).is_err());
    let exact_dust = apply_values(&[dust], &[dust], 0);
    assert!(exact_dust.is_ok(), "exact dust failed: {exact_dust:?}");
    assert!(apply_values(&[1_000_000_000], &[999_900_000], 100_000).is_ok());
}

#[test]
fn epoch_reward_does_not_increase_total_supply() {
    let (mut state, _, _) = state();
    let supply_before = state.total_supply;
    let height = indra_core::types::primitives::EPOCH_DURATION_BLOCKS;
    apply_epoch_transition(
        &mut state,
        &EpochTransitionContext::new(height, height - 1).unwrap(),
        0,
        None,
    )
    .unwrap();
    assert_eq!(state.total_supply, supply_before);
}

#[test]
fn fee_burn_reduces_total_supply() {
    let (mut state, owner, pair) = state();
    let input_value = 1_000_000;
    let fee = 100_000;
    let utxo = state
        .utxos
        .insert(output(input_value, owner.clone()), 0, 0, 0)
        .unwrap();
    account_fixture_claims(&mut state);
    let tx = signed_tx(
        &state,
        &pair,
        vec![utxo],
        vec![output(input_value - fee, owner)],
        fee,
    );
    let supply_before = state.total_supply;
    let expected_reward = indra_state::monetary::block_reward_for_budget(
        state.monetary_ledger.reward_budget_spark,
        1,
    )
    .unwrap();
    let block = block(&state, tx);
    apply_block(&mut state, &block, 0).unwrap();
    assert_eq!(
        state.total_supply,
        supply_before + expected_reward - fee / 2
    );
}

#[test]
fn liveness_penalty_burn_reduces_total_supply_if_active() {
    let (mut state, _, _) = state();
    let supply_before = state.total_supply;
    let height = 4 * indra_core::types::primitives::EPOCH_DURATION_BLOCKS;
    apply_epoch_transition(
        &mut state,
        &EpochTransitionContext::new(height, height - 1).unwrap(),
        0,
        None,
    )
    .unwrap();
    assert!(state.total_supply < supply_before);
    assert_eq!(supply_before - state.total_supply, 1_000);
}

#[test]
fn total_supply_invariant_across_full_epoch_cycle() {
    let (mut state, owner, pair) = state();
    let input_value = 1_000_000;
    let fee = 100_000;
    let utxo = state
        .utxos
        .insert(output(input_value, owner.clone()), 0, 0, 0)
        .unwrap();
    account_fixture_claims(&mut state);
    let tx = signed_tx(
        &state,
        &pair,
        vec![utxo],
        vec![output(input_value - fee, owner)],
        fee,
    );
    let supply_before = state.total_supply;
    let expected_reward = indra_state::monetary::block_reward_for_budget(
        state.monetary_ledger.reward_budget_spark,
        1,
    )
    .unwrap();
    let block = block(&state, tx);
    apply_block(&mut state, &block, 0).unwrap();
    let after_block = state.total_supply;
    let height = indra_core::types::primitives::EPOCH_DURATION_BLOCKS;
    apply_epoch_transition(
        &mut state,
        &EpochTransitionContext::new(height, height - 1).unwrap(),
        0,
        None,
    )
    .unwrap();
    assert_eq!(after_block, supply_before + expected_reward - fee / 2);
    assert_eq!(state.total_supply, after_block);
}
