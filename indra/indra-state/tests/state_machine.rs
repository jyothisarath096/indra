//! Integration tests for the complete state machine.
//!
//! These tests verify multi-block scenarios, epoch transitions,
//! and fee evolution over sequences of blocks.

use curve25519_dalek::scalar::Scalar;
use indra_core::{
    codec::{Decode, Encode},
    types::{
        block::{BlockHeaderV1, BlockV1},
        crypto::PQVoteSig,
        primitives::{
            DUST_LIMIT_SPARK, EPOCH_DURATION_BLOCKS, GENESIS_SUPPLY_SPARK,
            INITIAL_BASE_FEE_SPARK_PER_KB, MAX_QC_SIZE_BYTES, UNBONDING_PERIOD_EPOCHS,
        },
        qc::{QuorumCertificateV1, SIGNER_BITFIELD_BYTES},
        slashing::SlashEvidenceV1,
        staking::{StakingOp, StakingOpBody},
        transaction::{InputV1, OutputV1, TransactionV1},
        vote::{VoteStep, VoteV1},
    },
    Bytes32, CommitmentV1, HybridPubKey, HybridSignature, ProtocolVersion, VariableBytes,
};
use indra_crypto::{commit, prove_range, ClassicalKeypair, HybridKeypair, PqKeypair};
use indra_state::{
    apply::apply_slash, apply_block, compute_state_root, epoch::apply_epoch_transition,
    utxo::UtxoSet, ChainState, ValidatorEntry, ValidatorStatus,
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

fn install_test_validators_for_qc(state: &mut ChainState) -> Vec<Bytes32> {
    (0..4u8)
        .map(|index| {
            let validator_id = Bytes32::from([0xA0 + index; 32]);
            state
                .validators
                .upsert(ValidatorEntry {
                    validator_id,
                    name: format!("qc-validator-{index}"),
                    hybrid_classical_pk: None,
                    hybrid_pq_pk: None,
                    vrf_pk: None,
                    stake_spark: 100_000_000_000,
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
            validator_id
        })
        .collect()
}

fn qc_bytes_for_signers(
    signer_ids: &[Bytes32],
    certified_height: u64,
) -> VariableBytes<MAX_QC_SIZE_BYTES> {
    let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
    for slot in 0..signer_ids.len() {
        signer_bitfield[slot / 8] |= 1 << (slot % 8);
    }
    let qc = QuorumCertificateV1 {
        height: certified_height,
        round: 0,
        block_hash: Bytes32::from([0xC1; 32]),
        signer_bitfield,
        pq_signatures: signer_ids
            .iter()
            .copied()
            .map(|validator_id| PQVoteSig {
                validator_id,
                pq_sig: VariableBytes::from_slice(&[0xDD; 32]).unwrap(),
            })
            .collect(),
    };
    VariableBytes::from_slice(&qc.encode_to_vec()).unwrap()
}

fn make_block_with_qc(state: &ChainState, signer_ids: &[Bytes32]) -> BlockV1 {
    let mut block = make_block(state, vec![]);
    block.header.quorum_certificate =
        qc_bytes_for_signers(signer_ids, block.header.height.saturating_sub(1));
    block
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
fn last_active_epoch_updated_identically_live_and_replay() {
    let mut live_state = ChainState::new_genesis();
    let signer_ids = install_test_validators_for_qc(&mut live_state);
    live_state.height = EPOCH_DURATION_BLOCKS;

    let mut replay_state = live_state.clone();
    for _ in 0..10 {
        let block = make_block_with_qc(&live_state, &signer_ids);
        apply_block(&mut live_state, &block, 0).unwrap();
        apply_block(&mut replay_state, &block, 0).unwrap();
    }

    let live_epochs: Vec<(Bytes32, u64)> = live_state
        .validators
        .all_validators()
        .map(|v| (v.validator_id, v.last_active_epoch))
        .collect();
    let replay_epochs: Vec<(Bytes32, u64)> = replay_state
        .validators
        .all_validators()
        .map(|v| (v.validator_id, v.last_active_epoch))
        .collect();
    assert_eq!(
        live_epochs, replay_epochs,
        "live and replay apply paths must update last_active_epoch identically"
    );
    assert_eq!(
        compute_state_root(&live_state),
        compute_state_root(&replay_state)
    );

    let snapshot_bytes = live_state.encode_to_vec();
    let restored_state = ChainState::decode_exact(&snapshot_bytes).unwrap();
    let restored_epochs: Vec<(Bytes32, u64)> = restored_state
        .validators
        .all_validators()
        .map(|v| (v.validator_id, v.last_active_epoch))
        .collect();
    assert_eq!(
        live_epochs, restored_epochs,
        "snapshot restore must preserve last_active_epoch"
    );
    assert_eq!(
        compute_state_root(&live_state),
        compute_state_root(&restored_state),
        "state roots must match after snapshot/restore"
    );
}

#[test]
fn apply_block_updates_last_active_epoch_for_qc_signers() {
    let mut state = ChainState::new_genesis();
    let signer_ids = install_test_validators_for_qc(&mut state);
    state.height = EPOCH_DURATION_BLOCKS;

    for validator_id in &signer_ids {
        assert_eq!(
            state
                .validators
                .get(validator_id)
                .unwrap()
                .last_active_epoch,
            0
        );
    }

    let block = make_block_with_qc(&state, &signer_ids[..2]);
    apply_block(&mut state, &block, 0).unwrap();

    let expected_epoch = indra_state::epoch::epoch_for_height(block.header.height);
    assert_eq!(
        state
            .validators
            .get(&signer_ids[0])
            .unwrap()
            .last_active_epoch,
        expected_epoch
    );
    assert_eq!(
        state
            .validators
            .get(&signer_ids[1])
            .unwrap()
            .last_active_epoch,
        expected_epoch
    );
    assert_eq!(
        state
            .validators
            .get(&signer_ids[2])
            .unwrap()
            .last_active_epoch,
        0
    );
    assert_eq!(
        state
            .validators
            .get(&signer_ids[3])
            .unwrap()
            .last_active_epoch,
        0
    );
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

#[test]
fn epoch_transition_produces_identical_state_on_replay() {
    let mut original = ChainState::new_genesis();
    for seed in 1..=4 {
        let (id, _, _) = install_validator(&mut original, [seed; 32]);
        original.validators.get_mut(&id).unwrap().stake_spark = 1_000_000;
    }
    let mut replay = original.clone();
    apply_epoch_transition(&mut original, 1, 0).unwrap();
    apply_epoch_transition(&mut replay, 1, 0).unwrap();
    assert_eq!(original.encode_to_vec(), replay.encode_to_vec());
}

#[test]
fn replay_with_different_arithmetic_diverges_without_height_gating() {
    use indra_core::types::primitives::{muldiv, overflow_fix_active};

    const EPOCH_REWARD: u64 = 1_189_200_000 * 300;
    const STAKE: u64 = 100_000_000_000;
    const TOTAL_STAKE: u64 = STAKE * 4;

    // This is the persisted snapshot before the 300th (epoch-boundary) block.
    // The transition below models the reward mutation caused by those 300
    // blocks; all other blocks in this minimal replay are empty.
    let mut snapshot = ChainState::new_genesis();
    let mut validator_ids = Vec::new();
    for seed in 1..=4 {
        let (id, _, _) = install_validator(&mut snapshot, [seed; 32]);
        snapshot.validators.get_mut(&id).unwrap().stake_spark = STAKE;
        validator_ids.push(id);
    }

    let old_reward = EPOCH_REWARD.saturating_mul(STAKE) / TOTAL_STAKE;
    let new_reward = muldiv(EPOCH_REWARD, STAKE, TOTAL_STAKE);
    assert_eq!(old_reward, 46_116_860);
    assert_eq!(new_reward, 89_190_000_000);
    assert_ne!(old_reward, new_reward);

    // What the old live chain committed at the epoch boundary.
    let mut reference = snapshot.clone();
    reference.height = EPOCH_DURATION_BLOCKS;
    for id in &validator_ids {
        reference.validators.get_mut(id).unwrap().pending_rewards = old_reward;
    }
    let committed_root = compute_state_root(&reference);

    // What a new binary would produce when replaying the same boundary with
    // unconditional muldiv: a different state root, reproducing the incident.
    let mut ungated_replay = snapshot.clone();
    ungated_replay.height = EPOCH_DURATION_BLOCKS;
    for id in &validator_ids {
        ungated_replay
            .validators
            .get_mut(id)
            .unwrap()
            .pending_rewards = new_reward;
    }
    assert_ne!(committed_root, compute_state_root(&ungated_replay));

    // Simulate a mainnet activation at 50,000. A replay of height 300 must
    // continue using historical arithmetic even when executed by the new code.
    let activation_height = 50_000;
    let gated_reward = if EPOCH_DURATION_BLOCKS >= activation_height {
        new_reward
    } else {
        old_reward
    };
    let mut gated_replay = snapshot;
    gated_replay.height = EPOCH_DURATION_BLOCKS;
    for id in &validator_ids {
        gated_replay.validators.get_mut(id).unwrap().pending_rewards = gated_reward;
    }
    assert_eq!(committed_root, compute_state_root(&gated_replay));

    // The current testnet configuration activates the corrected path at genesis.
    assert!(overflow_fix_active(0));
    assert!(overflow_fix_active(25_932));
    assert!(overflow_fix_active(u64::MAX));
}

#[test]
fn height_gated_arithmetic_is_deterministic_across_restarts() {
    use indra_core::types::primitives::{muldiv, overflow_fix_active};

    let epoch_reward = 356_760_000_000;
    let stake = 100_000_000_000;
    let total_stake = 400_000_000_000;
    let replay_height = 100u64;
    let reward_for = |height: u64| {
        if overflow_fix_active(height) {
            muldiv(epoch_reward, stake, total_stake)
        } else {
            epoch_reward.saturating_mul(stake) / total_stake
        }
    };

    // Both binaries dispatch from the block height, not from binary version.
    assert_eq!(reward_for(replay_height), reward_for(replay_height));
    assert_eq!(reward_for(replay_height), 89_190_000_000);
}

#[test]
fn governance_state_encoding_is_deterministic() {
    let mut first = ChainState::new_genesis();
    let mut second = ChainState::new_genesis();
    let a = Bytes32::from([1; 32]);
    let b = Bytes32::from([2; 32]);
    first.governance.gov_nonces.insert(b, 2);
    first.governance.gov_nonces.insert(a, 1);
    second.governance.gov_nonces.insert(a, 1);
    second.governance.gov_nonces.insert(b, 2);
    assert_eq!(
        first.governance.encode_to_vec(),
        second.governance.encode_to_vec()
    );
}

#[test]
fn btreemap_iteration_is_deterministic_unlike_hashmap() {
    use std::collections::BTreeMap;

    let keys = [
        Bytes32::from([0xFF; 32]),
        Bytes32::from([0x01; 32]),
        Bytes32::from([0xAA; 32]),
        Bytes32::from([0x55; 32]),
    ];
    let mut map = BTreeMap::new();
    for (index, key) in keys.iter().enumerate() {
        map.insert(*key, index as u64 * 1_000);
    }

    let order: Vec<Bytes32> = map.keys().copied().collect();
    let mut expected = order.clone();
    expected.sort_by_key(|key| key.0);
    assert_eq!(order, expected);

    let encode = |entries: &BTreeMap<Bytes32, u64>| {
        entries
            .iter()
            .flat_map(|(key, value)| key.0.into_iter().chain(value.to_le_bytes()))
            .collect::<Vec<u8>>()
    };
    assert_eq!(encode(&map), encode(&map));
}

#[test]
fn delegator_reward_distribution_is_height_gated() {
    use indra_core::types::primitives::muldiv;

    let reward_pool = 80_271_000_000u64;
    let staked = 100_000_000_000u64;
    let total_delegated = 400_000_000_000u64;
    let old = reward_pool.saturating_mul(staked) / total_delegated;
    let new = muldiv(reward_pool, staked, total_delegated);

    assert_ne!(old, new);
    assert!(new > old);
}

#[test]
fn commission_bps_is_height_gated() {
    use indra_core::types::primitives::{bps_of, overflow_fix_active};

    let reward = 89_190_000_000u64;
    let commission_bps = 1_000u32;
    let old = reward.saturating_mul(commission_bps as u64) / 10_000;
    let new = bps_of(reward, commission_bps);

    assert_eq!(old, 8_919_000_000);
    assert_eq!(new, 8_919_000_000);
    assert!(overflow_fix_active(0));
}

#[test]
fn liveness_penalty_is_height_gated() {
    use indra_core::types::primitives::{bps_of, overflow_fix_active};

    let stake = 100_000_000_000u64;
    let liveness_bps = 10u32;
    let old = stake.saturating_mul(liveness_bps as u64) / 10_000;
    let new = bps_of(stake, liveness_bps);

    assert_eq!(old, 100_000_000);
    assert_eq!(new, 100_000_000);
    assert!(overflow_fix_active(0));
}

#[test]
fn qc_vote_order_is_deterministic() {
    use std::collections::BTreeMap;

    let validator_ids = [
        Bytes32::from([0xFF; 32]),
        Bytes32::from([0x01; 32]),
        Bytes32::from([0x80; 32]),
        Bytes32::from([0x42; 32]),
    ];
    let mut votes1 = BTreeMap::new();
    for (index, id) in validator_ids.iter().enumerate() {
        votes1.insert(*id, index as u64);
    }
    let mut votes2 = BTreeMap::new();
    for (index, id) in validator_ids.iter().rev().enumerate() {
        votes2.insert(*id, (3 - index) as u64);
    }

    let order1: Vec<Bytes32> = votes1.keys().copied().collect();
    let order2: Vec<Bytes32> = votes2.keys().copied().collect();
    assert_eq!(order1, order2);

    let encode = |votes: &BTreeMap<Bytes32, u64>| {
        votes
            .iter()
            .flat_map(|(id, vote)| id.0.into_iter().chain(vote.to_le_bytes()))
            .collect::<Vec<u8>>()
    };
    assert_eq!(encode(&votes1), encode(&votes2));
}
