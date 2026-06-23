//! Integration tests for the complete state machine.
//!
//! These tests verify multi-block scenarios, epoch transitions,
//! and fee evolution over sequences of blocks.

use curve25519_dalek::scalar::Scalar;
use indra_core::{
    codec::Encode,
    types::{
        block::{BlockHeaderV1, BlockV1},
        primitives::{
            DUST_LIMIT_SPARK, EPOCH_DURATION_BLOCKS, GENESIS_SUPPLY_SPARK,
            INITIAL_BASE_FEE_SPARK_PER_KB, UNBONDING_PERIOD_EPOCHS,
        },
        slashing::SlashEvidenceV1,
        staking::{StakingOp, StakingOpBody},
        transaction::{InputV1, OutputV1, TransactionV1},
        vote::{VoteStep, VoteV1},
    },
    Bytes32, CommitmentV1, HybridPubKey, HybridSignature, ProtocolVersion, VariableBytes,
};
use indra_crypto::{commit, prove_range, ClassicalKeypair, HybridKeypair, PqKeypair};
use indra_state::{
    apply::apply_slash, apply_block, epoch::apply_epoch_transition, utxo::UtxoSet, ChainState,
    ValidatorEntry, ValidatorStatus,
};
use rand::{rngs::StdRng, SeedableRng};

const TEST_INPUT_VALUE: u64 = 1_000_000;

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_test_keypair(seed: [u8; 32]) -> (HybridPubKey, HybridKeypair) {
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

fn dummy_sig() -> HybridSignature {
    HybridSignature {
        classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
        pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
    }
}

fn signed_staking_op(
    body: StakingOpBody,
    nonce: u64,
    keypair: &HybridKeypair,
    chain_id: &str,
) -> StakingOp {
    let mut op = StakingOp {
        body,
        nonce,
        signature: dummy_sig(),
    };
    let sig = keypair.sign(&op.signing_bytes(chain_id)).unwrap();
    op.signature = HybridSignature {
        classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
        pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
    };
    op
}

fn pubkey_to_id(pubkey: &HybridPubKey) -> Bytes32 {
    Bytes32::from(indra_crypto::sha256(&pubkey.encode_to_vec()))
}

fn install_validator(
    state: &mut ChainState,
    seed: [u8; 32],
) -> (Bytes32, HybridPubKey, HybridKeypair) {
    let (pubkey, keypair) = make_test_keypair(seed);
    let validator_id = pubkey_to_id(&pubkey);
    state
        .validators
        .upsert(ValidatorEntry {
            validator_id,
            name: format!("validator-{}", seed[0]),
            hybrid_classical_pk: Some(pubkey.classical_pk.0),
            hybrid_pq_pk: Some(pubkey.pq_pk.as_slice().to_vec()),
            vrf_pk: Some(seed),
            stake_spark: 0,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
            self_report_count: 0,
            commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
            min_delegation_spark: DUST_LIMIT_SPARK,
            auto_delegate_to: None,
        })
        .unwrap();
    (validator_id, pubkey, keypair)
}

fn sign_transaction(
    keypair: &HybridKeypair,
    chain_id: &str,
    tx: &TransactionV1,
) -> HybridSignature {
    let sig = keypair.sign(&tx.signing_bytes(chain_id)).unwrap();
    HybridSignature {
        classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
        pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
    }
}

fn signed_vote(
    keypair: &HybridKeypair,
    validator_id: Bytes32,
    step: VoteStep,
    block_hash: Bytes32,
) -> VoteV1 {
    let signing_bytes =
        indra_core::types::vote_signing::vote_signing_bytes(7, 0, step, &block_hash, &validator_id);
    let sig = keypair.sign(&signing_bytes).unwrap();
    VoteV1 {
        height: 7,
        round: 0,
        step,
        block_hash,
        validator_id,
        signature: HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        },
    }
}

fn derive_fee_blinding(input_blindings: &[[u8; 32]], output_blindings: &[[u8; 32]]) -> [u8; 32] {
    let input_sum = input_blindings.iter().fold(Scalar::ZERO, |acc, blinding| {
        acc + Scalar::from_bytes_mod_order(*blinding)
    });
    let output_sum = output_blindings.iter().fold(Scalar::ZERO, |acc, blinding| {
        acc + Scalar::from_bytes_mod_order(*blinding)
    });
    (input_sum - output_sum).to_bytes()
}

fn make_output(byte: u8, owner_pubkey: HybridPubKey) -> OutputV1 {
    let value = TEST_INPUT_VALUE + byte as u64;
    let blinding = [byte; 32];
    let commitment = commit(value, &blinding);
    let mut rng = StdRng::from_seed([byte; 32]);
    let proof = prove_range(value, &blinding, &mut rng).unwrap();

    OutputV1 {
        value_spark: value,
        commitment: CommitmentV1 {
            compressed_point: Bytes32::from(commitment.0),
        },
        owner_pubkey,
        range_proof: VariableBytes::from_slice(&proof).unwrap(),
        lock_height: 0,
    }
}

fn make_tx(
    state: &ChainState,
    keypair: &HybridKeypair,
    owner_pubkey: HybridPubKey,
    utxo_id: Bytes32,
    input_value: u64,
    input_blinding: [u8; 32],
    nullifier_byte: u8,
    out_byte: u8,
) -> TransactionV1 {
    let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
    let output_value = input_value - fee;
    let blinding = [out_byte; 32];
    let fee_blinding = derive_fee_blinding(&[input_blinding], &[blinding]);
    let commitment = commit(output_value, &blinding);
    let fee_commitment = commit(fee, &fee_blinding);
    let mut rng = StdRng::from_seed([out_byte; 32]);
    let proof = prove_range(output_value, &blinding, &mut rng).unwrap();
    let mut tx = TransactionV1 {
        version: ProtocolVersion::CURRENT,
        signature_module_id: 1,
        inputs: vec![InputV1 {
            utxo_id,
            nullifier: Bytes32::from([nullifier_byte; 32]),
        }],
        outputs: vec![OutputV1 {
            value_spark: output_value,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from(commitment.0),
            },
            owner_pubkey,
            range_proof: VariableBytes::from_slice(&proof).unwrap(),
            lock_height: 0,
        }],
        fee_amount: fee,
        fee_blinding: Bytes32::from(fee_blinding),
        fee_commitment: CommitmentV1 {
            compressed_point: Bytes32::from(fee_commitment.0),
        },
        signature: dummy_sig(),
    };
    tx.signature = sign_transaction(keypair, &state.chain_id, &tx);
    tx
}

fn make_block(state: &ChainState, txs: Vec<TransactionV1>) -> BlockV1 {
    let height = state.height + 1;
    BlockV1 {
        header: BlockHeaderV1 {
            protocol_version: ProtocolVersion::CURRENT,
            height,
            prev_hash: state.tip_hash,
            timestamp: 1_700_000_000 + height,
            state_root: Bytes32::ZERO,
            validator_set_root: Bytes32::ZERO,
            mempool_set_root: Bytes32::ZERO,
            value_hash: Bytes32::ZERO,
            base_fee: state.base_fee,
            proposer_round: 0,
            polc_round: indra_core::types::block::NO_POLC_ROUND,
            proposer_vrf_output: Bytes32::ZERO,
            proposer_vrf_proof: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            quorum_certificate: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
        },
        transactions: txs,
        slashing_evidence: vec![],
        governance_ops: vec![],
        staking_ops: vec![],
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn genesis_state_constants() {
    let state = ChainState::new_genesis();
    assert_eq!(state.total_supply, GENESIS_SUPPLY_SPARK);
    assert_eq!(state.height, 0);
    assert_eq!(state.base_fee, INITIAL_BASE_FEE_SPARK_PER_KB);
}

#[test]
fn one_hundred_empty_blocks() {
    let mut state = ChainState::new_genesis();
    for _ in 0..100 {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block, 0).unwrap();
    }
    assert_eq!(state.height, 100);
}

#[test]
fn utxo_lifecycle_across_blocks() {
    let mut state = ChainState::new_genesis();
    let (owner_pubkey, keypair) = make_test_keypair([0x11; 32]);

    // Create a UTXO by inserting it at genesis
    let output = make_output(0x01, owner_pubkey.clone());
    let utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();

    // Block 1: spend that UTXO, create a new one
    let block1_output_value = (TEST_INPUT_VALUE + 0x01u64) - (INITIAL_BASE_FEE_SPARK_PER_KB * 10);
    let tx = make_tx(
        &state,
        &keypair,
        owner_pubkey.clone(),
        utxo_id,
        TEST_INPUT_VALUE + 0x01u64,
        [0x01; 32],
        0xAA,
        0x02,
    );
    let block1 = make_block(&state, vec![tx]);
    apply_block(&mut state, &block1, 0).unwrap();

    assert!(!state.utxos.contains(&utxo_id), "old UTXO should be spent");
    assert_eq!(state.utxos.len(), 1, "one new UTXO created");
    assert!(state.nullifiers.contains(&Bytes32::from([0xAAu8; 32])));

    // Block 2: spend the new UTXO
    // Find the new UTXO id — it was inserted at height 1, tx 0, output 0
    let blinding = [0x02u8; 32];
    let commitment = commit(block1_output_value, &blinding);
    let mut rng = StdRng::from_seed([0x02u8; 32]);
    let proof = prove_range(block1_output_value, &blinding, &mut rng).unwrap();
    let new_utxo_id = UtxoSet::compute_utxo_id(
        &OutputV1 {
            value_spark: block1_output_value,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from(commitment.0),
            },
            owner_pubkey: owner_pubkey.clone(),
            range_proof: VariableBytes::from_slice(&proof).unwrap(),
            lock_height: 0,
        },
        1,
        0,
        0,
    );
    let tx2 = make_tx(
        &state,
        &keypair,
        owner_pubkey,
        new_utxo_id,
        block1_output_value,
        [0x02; 32],
        0xBB,
        0x03,
    );
    let block2 = make_block(&state, vec![tx2]);
    apply_block(&mut state, &block2, 0).unwrap();

    assert_eq!(state.height, 2);
    assert_eq!(state.utxos.len(), 1);
    assert!(state.nullifiers.contains(&Bytes32::from([0xBBu8; 32])));
}

#[test]
fn fee_evolves_over_blocks() {
    let mut state = ChainState::new_genesis();
    let fee_at_genesis = state.base_fee;

    // Apply 10 empty blocks — fee should decrease (below target utilisation)
    for _ in 0..10 {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block, 0).unwrap();
    }
    // Fee should have decreased from initial
    assert!(state.base_fee <= fee_at_genesis);
    // But never below minimum
    assert!(state.base_fee >= indra_core::types::primitives::MIN_BASE_FEE_SPARK_PER_KB);
}

#[test]
fn epoch_transition_fires_at_boundary() {
    let mut state = ChainState::new_genesis();
    let supply_before = state.total_supply;
    let treasury_before = state.treasury_balance;

    // Apply exactly one epoch worth of blocks
    for _ in 0..EPOCH_DURATION_BLOCKS {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block, 0).unwrap();
    }

    assert_eq!(state.height, EPOCH_DURATION_BLOCKS);
    assert_eq!(state.current_epoch(), 1);
    assert_eq!(state.total_supply, supply_before);
    assert_eq!(state.treasury_balance, treasury_before);
}

#[test]
fn two_epochs_preserve_supply() {
    let mut state = ChainState::new_genesis();

    // First epoch
    for _ in 0..EPOCH_DURATION_BLOCKS {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block, 0).unwrap();
    }
    let supply_after_epoch1 = state.total_supply;

    // Second epoch
    for _ in 0..EPOCH_DURATION_BLOCKS {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block, 0).unwrap();
    }

    assert_eq!(state.total_supply, supply_after_epoch1);
    assert_eq!(state.current_epoch(), 2);
}

#[test]
fn fees_are_burned() {
    let mut state = ChainState::new_genesis();
    let (owner_pubkey, keypair) = make_test_keypair([0x11; 32]);

    // Insert a spendable UTXO
    let output = make_output(0x01, owner_pubkey.clone());
    let utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();
    let supply_before = state.total_supply;

    let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
    let tx = make_tx(
        &state,
        &keypair,
        owner_pubkey,
        utxo_id,
        TEST_INPUT_VALUE + 0x01u64,
        [0x01; 32],
        0xCC,
        0x02,
    );
    assert_eq!(tx.fee_amount, fee);

    let block = make_block(&state, vec![tx]);
    apply_block(&mut state, &block, 0).unwrap();

    assert_eq!(state.total_supply, supply_before - (fee / 2));
    assert_eq!(state.fee_reward_pool, fee - (fee / 2));
}

#[test]
fn chain_is_deterministic() {
    // Two independent nodes starting from genesis and applying the same blocks
    // must arrive at identical state
    let mut state_a = ChainState::new_genesis();
    let mut state_b = ChainState::new_genesis();

    for i in 0..50u64 {
        let block_a = make_block(&state_a, vec![]);
        let block_b = make_block(&state_b, vec![]);
        // Blocks are identical because states are identical
        assert_eq!(
            block_a.header.block_hash(),
            block_b.header.block_hash(),
            "block hashes must match at height {}",
            i + 1
        );
        apply_block(&mut state_a, &block_a, 0).unwrap();
        apply_block(&mut state_b, &block_b, 0).unwrap();
        assert_eq!(state_a.height, state_b.height);
        assert_eq!(state_a.tip_hash, state_b.tip_hash);
        assert_eq!(state_a.total_supply, state_b.total_supply);
        assert_eq!(state_a.base_fee, state_b.base_fee);
    }
}

#[test]
fn test_self_stake_full_lifecycle() {
    let mut state = ChainState::new_genesis();
    let (validator_id, validator_pubkey, validator_keypair) =
        install_validator(&mut state, [0x41; 32]);
    let output = make_output(0x40, validator_pubkey.clone());
    let bond_value = output.value_spark;
    let bond_utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();

    let stake_op = signed_staking_op(
        StakingOpBody::SelfStake {
            bond_utxo_id,
            validator_pubkey: validator_pubkey.clone(),
        },
        1,
        &validator_keypair,
        &state.chain_id,
    );
    let mut stake_block = make_block(&state, vec![]);
    stake_block.staking_ops = vec![stake_op];
    apply_block(&mut state, &stake_block, 0).unwrap();

    assert!(!state.utxos.contains(&bond_utxo_id));
    assert_eq!(
        state.validators.get(&validator_id).unwrap().stake_spark,
        bond_value
    );
    assert_eq!(
        state.staked_bonds.get(&bond_utxo_id).unwrap().delegator_id,
        validator_id
    );

    let unstake_op = signed_staking_op(
        StakingOpBody::SelfUnstake {
            bond_utxo_id,
            validator_pubkey,
        },
        2,
        &validator_keypair,
        &state.chain_id,
    );
    let mut unstake_block = make_block(&state, vec![]);
    unstake_block.staking_ops = vec![unstake_op];
    apply_block(&mut state, &unstake_block, 0).unwrap();

    assert_eq!(state.validators.get(&validator_id).unwrap().stake_spark, 0);
    assert_eq!(
        state
            .staked_bonds
            .get(&bond_utxo_id)
            .unwrap()
            .unbonding_end_epoch,
        Some(UNBONDING_PERIOD_EPOCHS)
    );

    apply_epoch_transition(&mut state, UNBONDING_PERIOD_EPOCHS, 0).unwrap();
    assert!(!state.staked_bonds.contains_key(&bond_utxo_id));
    assert_eq!(state.utxos.len(), 1);
    assert!(state
        .utxos
        .all_entries()
        .any(|entry| entry.output.value_spark == bond_value));
}

#[test]
fn test_auto_delegate_full_lifecycle() {
    let mut state = ChainState::new_genesis();
    let mut validators = Vec::new();
    for i in 1..=21u8 {
        let (id, pubkey, keypair) = install_validator(&mut state, [i; 32]);
        let stake = (22u64 - i as u64) * DUST_LIMIT_SPARK * 100;
        state.validators.get_mut(&id).unwrap().stake_spark = stake;
        validators.push((id, pubkey, keypair));
    }

    let target_id = validators[0].0;
    let inactive_id = validators[20].0;
    let inactive_pubkey = validators[20].1.clone();
    let inactive_keypair = &validators[20].2;
    let chain_id = state.chain_id.clone();
    let set_auto_delegate = signed_staking_op(
        StakingOpBody::SetAutoDelegate {
            validator_id: inactive_id,
            target_validator_id: target_id,
        },
        1,
        &inactive_keypair,
        &chain_id,
    );
    let mut set_block = make_block(&state, vec![]);
    set_block.staking_ops = vec![set_auto_delegate];
    apply_block(&mut state, &set_block, 0).unwrap();

    let mut previous_rewards = 0;
    for epoch in 1..=3 {
        apply_epoch_transition(&mut state, epoch, 0).unwrap();
        let rewards = state.validators.get(&inactive_id).unwrap().pending_rewards;
        assert!(rewards > previous_rewards);
        previous_rewards = rewards;
    }

    let claimed = state.validators.get(&inactive_id).unwrap().pending_rewards;
    assert!(claimed >= DUST_LIMIT_SPARK);
    let utxos_before = state.utxos.len();
    let chain_id = state.chain_id.clone();
    let claim_rewards = signed_staking_op(
        StakingOpBody::ClaimRewards {
            validator_id: inactive_id,
            delegator_pubkey: inactive_pubkey,
        },
        2,
        &inactive_keypair,
        &chain_id,
    );
    let mut claim_block = make_block(&state, vec![]);
    claim_block.staking_ops = vec![claim_rewards];
    apply_block(&mut state, &claim_block, 0).unwrap();

    assert_eq!(
        state.validators.get(&inactive_id).unwrap().pending_rewards,
        0
    );
    assert_eq!(state.utxos.len(), utxos_before + 1);
    assert!(state
        .utxos
        .all_entries()
        .any(|entry| entry.output.value_spark == claimed));
}

#[test]
fn test_self_stake_slash_reduces_bond_amount() {
    let mut state = ChainState::new_genesis();
    let (validator_id, validator_pubkey, validator_keypair) =
        install_validator(&mut state, [0x42; 32]);
    let output = make_output(0x50, validator_pubkey.clone());
    let bond_value = output.value_spark;
    let bond_utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();

    let stake_op = signed_staking_op(
        StakingOpBody::SelfStake {
            bond_utxo_id,
            validator_pubkey,
        },
        1,
        &validator_keypair,
        &state.chain_id,
    );
    let mut block = make_block(&state, vec![]);
    block.staking_ops = vec![stake_op];
    apply_block(&mut state, &block, 0).unwrap();

    let evidence = SlashEvidenceV1 {
        validator_id,
        vote_1: signed_vote(
            &validator_keypair,
            validator_id,
            VoteStep::Precommit,
            Bytes32::from([0xA1; 32]),
        ),
        vote_2: signed_vote(
            &validator_keypair,
            validator_id,
            VoteStep::Precommit,
            Bytes32::from([0xA2; 32]),
        ),
    };
    let chain_id = state.chain_id.clone();
    apply_slash(&mut state, &evidence, &chain_id).unwrap();

    assert_eq!(
        state.staked_bonds.get(&bond_utxo_id).unwrap().amount_spark,
        bond_value - (bond_value * 500 / 10_000)
    );
    assert!(matches!(
        state.validators.get(&validator_id).unwrap().status,
        ValidatorStatus::Slashed
    ));
}
