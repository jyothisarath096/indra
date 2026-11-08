//! Phase 2 security-audit proof-of-concept tests.
//!
//! These tests intentionally document vulnerabilities found by the audit.
//! They are ignored so normal CI is not trained to accept an exploit as
//! correct behaviour. Run explicitly with:
//!
//!   cargo test -p indra-state --test audit_phase2 -- --ignored

use indra_core::types::primitives::TEST_CHAIN_ID;

use indra_core::types::{
    block::{BlockHeaderVNext, BlockVNext},
    crypto::{HybridPubKey, HybridSignature},
    primitives::{
        Bytes32, ProtocolVersion, VariableBytes, INITIAL_BASE_FEE_SPARK_PER_KB,
        LIFETIME_SUPPLY_CAP_SPARK, MAX_QC_SIZE_BYTES, MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
        TRANSACTION_PROTOCOL_VERSION,
    },
    transaction::{InputV1, OutputV1, TransactionV1},
};
use indra_crypto::{ClassicalKeypair, HybridKeypair, PqKeypair, VrfKeypair};
use indra_state::{
    apply_block_for_test as apply_block, ChainState, StateError, ValidatorEntry, ValidatorStatus,
};

fn keypair(seed: [u8; 32]) -> (HybridPubKey, HybridKeypair) {
    let classical = ClassicalKeypair::from_seed(&seed);
    let pq = PqKeypair::from_seed(&seed).unwrap();
    let keypair = HybridKeypair::new(classical, pq);
    let public = keypair.public_key();
    (
        HybridPubKey {
            classical_pk: Bytes32::from(public.classical.0),
            pq_pk: VariableBytes::from_slice(&public.pq.0).unwrap(),
        },
        keypair,
    )
}

fn finalized_genesis() -> ChainState {
    let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
    state.active_slot_coefficient_numerator =
        indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR;
    let seed = [0xF0; 32];
    let (public, _) = keypair(seed);
    let validator_id = public.identity_id();
    state
        .validators
        .upsert(ValidatorEntry {
            validator_id,
            name: "audit-fixture-validator".into(),
            hybrid_classical_pk: Some(public.classical_pk.0),
            hybrid_pq_pk: Some(public.pq_pk.as_slice().to_vec()),
            vrf_pk: Some(VrfKeypair::from_seed(&seed).public_key()),
            vrf_key_activation_epoch: 0,
            pending_vrf_pk: None,
            pending_vrf_activation_epoch: None,
            stake_spark: MINIMUM_VALIDATOR_SELF_STAKE_SPARK,
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
            cold_hybrid_classical_pk: Some(public.classical_pk.0),
            cold_hybrid_pq_pk: Some(public.pq_pk.as_slice().try_into().unwrap()),
            cold_key_version: 1,
            cold_nonce: 0,
        })
        .unwrap();
    state.finalize_genesis().unwrap();
    state
}

fn insert_genesis_fixture_utxo(
    state: &mut ChainState,
    output: OutputV1,
    output_index: u32,
) -> Bytes32 {
    let id = state.utxos.insert(output, 0, 0, output_index).unwrap();
    state.monetary_aggregates = state.recompute_monetary_aggregates().unwrap();
    let issued = state.monetary_aggregates.total_claims_spark().unwrap();
    state.total_supply = issued;
    state.monetary_ledger.genesis_issued_spark = issued;
    state.monetary_ledger.reward_budget_spark = LIFETIME_SUPPLY_CAP_SPARK - issued;
    state.monetary_ledger.validate(state.total_supply).unwrap();
    id
}

fn sign_tx(tx: &TransactionV1, keypair: &HybridKeypair, chain_id: &str) -> HybridSignature {
    let sig = keypair.sign(&tx.signing_bytes(chain_id).unwrap()).unwrap();
    HybridSignature {
        classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
        pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
    }
}

fn output(
    value: u64,
    _blinding: [u8; 32],
    owner_pubkey: HybridPubKey,
    _proof_seed: [u8; 32],
) -> OutputV1 {
    OutputV1 {
        value_spark: value,
        owner_pubkey,
        lock_height: 0,
    }
}

fn tx_spending(
    utxo_id: Bytes32,
    value_in: u64,
    _input_blinding: [u8; 32],
    owner_pubkey: HybridPubKey,
    keypair: &HybridKeypair,
    output_blinding: [u8; 32],
    proof_seed: [u8; 32],
) -> TransactionV1 {
    let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
    let value_out = value_in - fee;

    let mut tx = TransactionV1 {
        version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
        signature_module_id: 1,
        inputs: vec![InputV1 { utxo_id }],
        outputs: vec![output(
            value_out,
            output_blinding,
            owner_pubkey.clone(),
            proof_seed,
        )],
        fee_amount: fee,
        signature: HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        },
    };
    tx.signature = sign_tx(&tx, keypair, TEST_CHAIN_ID);
    tx
}

fn tx_spending_same_utxo_twice(
    utxo_id: Bytes32,
    value_in: u64,
    _input_blinding: [u8; 32],
    owner_pubkey: HybridPubKey,
    keypair: &HybridKeypair,
) -> TransactionV1 {
    let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
    let value_out = value_in
        .checked_mul(2)
        .and_then(|v| v.checked_sub(fee))
        .unwrap();
    let output_blinding = [0x31; 32];

    let mut tx = TransactionV1 {
        version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
        signature_module_id: 1,
        inputs: vec![InputV1 { utxo_id }, InputV1 { utxo_id }],
        outputs: vec![output(
            value_out,
            output_blinding,
            owner_pubkey.clone(),
            [0x71; 32],
        )],
        fee_amount: fee,
        signature: HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        },
    };
    tx.signature = sign_tx(&tx, keypair, TEST_CHAIN_ID);
    tx
}

fn block_with_transactions(state: &ChainState, transactions: Vec<TransactionV1>) -> BlockVNext {
    BlockVNext {
        header: BlockHeaderVNext {
            protocol_version: ProtocolVersion::CURRENT,
            height: state.height + 1,
            prev_hash: state.tip_hash,
            timestamp: 1_700_000_000,
            state_root: Bytes32::ZERO,
            validator_set_root: Bytes32::ZERO,
            mempool_set_root: Bytes32::ZERO,
            value_hash: Bytes32::ZERO,
            base_fee: state.base_fee,
            proposer_round: 0,
            polc_round: None,
            proposer_id: Bytes32::from([0x81; 32]),
            vrf_suite: indra_core::types::block::VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
            election_seed: state.election_seed,
            proposer_vrf_output: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            proposer_vrf_proof: VariableBytes::from_slice(&[0u8; 80]).unwrap(),
            value_entropy: indra_core::types::block::ProposalEntropyV1 {
                origin_proposer_id: Bytes32::from([0x81; 32]),
                origin_round: 0,
                vrf_output: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                vrf_proof: VariableBytes::from_slice(&[0u8; 80]).unwrap(),
            },
            sortition_claim: indra_core::types::block::SortitionClaimV1::PraosThreshold,
            proposer_priority: indra_core::types::primitives::Bytes64([0; 64]),
            quorum_certificate: VariableBytes::<MAX_QC_SIZE_BYTES>::from_slice(&[]).unwrap(),
        },
        transactions,
        slashing_evidence: vec![],
        governance_ops: vec![],
        staking_ops: vec![],
    }
}

#[test]
fn transaction_with_overflowing_input_sum_is_rejected() {
    let mut state = finalized_genesis();
    let (owner_pubkey, _owner_keypair) = keypair([0x45; 32]);
    let huge_output_a = OutputV1 {
        value_spark: u64::MAX,
        owner_pubkey: owner_pubkey.clone(),
        lock_height: 0,
    };
    let huge_output_b = OutputV1 {
        value_spark: 1,
        owner_pubkey,
        lock_height: 0,
    };
    let utxo_a = state.utxos.insert(huge_output_a, 0, 0, 0).unwrap();
    let utxo_b = state.utxos.insert(huge_output_b, 0, 0, 1).unwrap();

    let overflow_owner = keypair([0x46; 32]).0;
    let tx = TransactionV1 {
        version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
        signature_module_id: 1,
        inputs: vec![InputV1 { utxo_id: utxo_a }, InputV1 { utxo_id: utxo_b }],
        outputs: vec![OutputV1 {
            value_spark: INITIAL_BASE_FEE_SPARK_PER_KB,
            owner_pubkey: overflow_owner.clone(),
            lock_height: 0,
        }],
        fee_amount: INITIAL_BASE_FEE_SPARK_PER_KB,
        signature: HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        },
    };
    let block = block_with_transactions(&state, vec![tx]);

    assert_eq!(
        apply_block(&mut state, &block, 0),
        Err(StateError::ValueOverflow)
    );
    assert_eq!(state.height, 0);
    assert!(state.utxos.contains(&utxo_a));
    assert!(state.utxos.contains(&utxo_b));
}

#[test]
fn t02_duplicate_utxo_spend_across_two_transactions_in_one_block_is_rejected() {
    let mut state = finalized_genesis();
    let (owner_pubkey, owner_keypair) = keypair([0x42; 32]);
    let input_value = 10_000_000_000u64;
    let input_blinding = [0x11; 32];
    let original_output = output(
        input_value,
        input_blinding,
        owner_pubkey.clone(),
        [0x51; 32],
    );
    let utxo_id = insert_genesis_fixture_utxo(&mut state, original_output, 0);

    let tx_a = tx_spending(
        utxo_id,
        input_value,
        input_blinding,
        owner_pubkey.clone(),
        &owner_keypair,
        [0x21; 32],
        [0x61; 32],
    );
    let mut tx_b = tx_spending(
        utxo_id,
        input_value,
        input_blinding,
        owner_pubkey,
        &owner_keypair,
        [0x22; 32],
        [0x62; 32],
    );
    tx_b.outputs[0].lock_height = 1;
    tx_b.signature = sign_tx(&tx_b, &owner_keypair, TEST_CHAIN_ID);

    let block = block_with_transactions(&state, vec![tx_a, tx_b]);

    assert_eq!(
        apply_block(&mut state, &block, 0),
        Err(StateError::DuplicateUtxoSpend { utxo_id })
    );
    assert!(state.utxos.contains(&utxo_id));
    assert_eq!(state.utxos.len(), 1);
    assert_eq!(state.height, 0);
}

#[test]
fn t02_duplicate_utxo_spend_within_single_transaction_inputs_is_rejected() {
    let mut state = finalized_genesis();
    let (owner_pubkey, owner_keypair) = keypair([0x43; 32]);
    let input_value = 10_000_000_000u64;
    let input_blinding = [0x12; 32];
    let original_output = output(
        input_value,
        input_blinding,
        owner_pubkey.clone(),
        [0x52; 32],
    );
    let utxo_id = insert_genesis_fixture_utxo(&mut state, original_output, 0);
    let tx = tx_spending_same_utxo_twice(
        utxo_id,
        input_value,
        input_blinding,
        owner_pubkey,
        &owner_keypair,
    );
    let block = block_with_transactions(&state, vec![tx]);

    assert_eq!(
        apply_block(&mut state, &block, 0),
        Err(StateError::DuplicateUtxoSpend { utxo_id })
    );
    assert!(state.utxos.contains(&utxo_id));
    assert_eq!(state.utxos.len(), 1);
    assert_eq!(state.height, 0);
}

#[test]
fn legitimate_single_spend_still_works_after_duplicate_utxo_fix() {
    let mut state = finalized_genesis();
    let (owner_pubkey, owner_keypair) = keypair([0x44; 32]);
    let input_value = 10_000_000_000u64;
    let input_blinding = [0x13; 32];
    let original_output = output(
        input_value,
        input_blinding,
        owner_pubkey.clone(),
        [0x53; 32],
    );
    let utxo_id = insert_genesis_fixture_utxo(&mut state, original_output, 0);
    let tx = tx_spending(
        utxo_id,
        input_value,
        input_blinding,
        owner_pubkey,
        &owner_keypair,
        [0x23; 32],
        [0x63; 32],
    );
    let block = block_with_transactions(&state, vec![tx]);

    apply_block(&mut state, &block, 0).unwrap();

    assert!(!state.utxos.contains(&utxo_id));
    assert_eq!(state.utxos.len(), 1);
    assert_eq!(state.height, 1);
}
