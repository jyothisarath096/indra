//! Monetary-policy invariant tests for staking, slashing, rewards and fees.

use curve25519_dalek::scalar::Scalar;
use indra_core::types::{
    block::{BlockHeaderV1, BlockV1, NO_POLC_ROUND},
    crypto::{CommitmentV1, HybridPubKey, HybridSignature},
    primitives::{
        Bytes32, ProtocolVersion, VariableBytes, DEFAULT_CHAIN_ID, INITIAL_BASE_FEE_SPARK_PER_KB,
        MAX_QC_SIZE_BYTES, MAX_RANGE_PROOF_BYTES, MAX_VRF_PROOF_BYTES, UNBONDING_PERIOD_EPOCHS,
    },
    slashing::SlashEvidenceV1,
    staking::{StakingOp, StakingOpBody},
    transaction::{InputV1, OutputV1, TransactionV1},
    vote::{VoteStep, VoteV1},
};
use indra_crypto::{commit, prove_range, ClassicalKeypair, HybridKeypair, PqKeypair};
use indra_state::{
    apply::apply_slash_at_height, apply_block, apply_epoch_transition, apply_staking_op,
    ChainState, ValidatorEntry, ValidatorStatus,
};
use rand::{rngs::StdRng, SeedableRng};

const INPUT_VALUE: u64 = 1_000_000;

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

fn pubkey_to_id(pubkey: &HybridPubKey) -> Bytes32 {
    Bytes32::from(indra_crypto::sha256(&pubkey.classical_pk.0))
}

fn dummy_sig() -> HybridSignature {
    HybridSignature {
        classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
        pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
    }
}

fn sign_staking_op(keypair: &HybridKeypair, chain_id: &str, op: &mut StakingOp) {
    let sig = keypair.sign(&op.signing_bytes(chain_id)).unwrap();
    op.signature = HybridSignature {
        classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
        pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
    };
}

fn sign_transaction(
    tx: &TransactionV1,
    keypair: &HybridKeypair,
    chain_id: &str,
) -> HybridSignature {
    let sig = keypair.sign(&tx.signing_bytes(chain_id)).unwrap();
    HybridSignature {
        classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
        pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
    }
}

fn output(
    value: u64,
    blinding: [u8; 32],
    owner_pubkey: HybridPubKey,
    proof_seed: [u8; 32],
) -> OutputV1 {
    let commitment = commit(value, &blinding);
    let mut rng = StdRng::from_seed(proof_seed);
    let proof = prove_range(value, &blinding, &mut rng).unwrap();
    OutputV1 {
        value_spark: value,
        commitment: CommitmentV1 {
            compressed_point: Bytes32::from(commitment.0),
        },
        owner_pubkey,
        range_proof: VariableBytes::<MAX_RANGE_PROOF_BYTES>::from_slice(&proof).unwrap(),
        lock_height: 0,
    }
}

fn make_validator(pubkey: &HybridPubKey, seed: [u8; 32], stake: u64) -> ValidatorEntry {
    ValidatorEntry {
        validator_id: pubkey_to_id(pubkey),
        name: "monetary-test-validator".into(),
        hybrid_classical_pk: Some(pubkey.classical_pk.0),
        hybrid_pq_pk: Some(pubkey.pq_pk.as_slice().to_vec()),
        vrf_pk: Some(seed),
        stake_spark: stake,
        status: ValidatorStatus::Active,
        registered_epoch: 0,
        last_active_epoch: 0,
        pending_rewards: 0,
        rewards_last_epoch: 0,
        self_report_count: 0,
        commission_bps: 1_000,
        pending_commission_bps: None,
        pending_commission_effective_epoch: None,
        min_delegation_spark: 1,
        auto_delegate_to: None,
        network_addr: None,
        network_addr_last_updated_epoch: None,
        cold_hybrid_classical_pk: None,
        cold_hybrid_pq_pk: None,
        cold_key_version: 0,
        cold_key_status: indra_state::ColdKeyStatus::Unenrolled,
        cold_nonce: 0,
    }
}

fn self_stake_op(
    state: &ChainState,
    bond_utxo_id: Bytes32,
    validator_pubkey: HybridPubKey,
    validator_keypair: &HybridKeypair,
    nonce: u64,
) -> StakingOp {
    let bond_proof = state.utxos.get(&bond_utxo_id).and_then(|entry| {
        (0u8..=u8::MAX).find_map(|seed| {
            let candidate = commit(entry.output.value_spark, &[seed; 32]);
            (candidate.0 == entry.output.commitment.compressed_point.0).then(|| {
                indra_core::types::staking::StakingBondProof {
                    committed_value_spark: entry.output.value_spark,
                    blinding_factor: Bytes32::from([seed; 32]),
                }
            })
        })
    });
    let mut op = StakingOp {
        body: StakingOpBody::SelfStake {
            bond_utxo_id,
            validator_pubkey,
            bond_proof,
            cold_authorization: None,
        },
        nonce,
        signature: dummy_sig(),
    };
    sign_staking_op(validator_keypair, &state.chain_id, &mut op);
    op
}

fn self_unstake_op(
    state: &ChainState,
    bond_utxo_id: Bytes32,
    validator_pubkey: HybridPubKey,
    validator_keypair: &HybridKeypair,
    nonce: u64,
) -> StakingOp {
    let mut op = StakingOp {
        body: StakingOpBody::SelfUnstake {
            bond_utxo_id,
            validator_pubkey,
            cold_authorization: None,
        },
        nonce,
        signature: dummy_sig(),
    };
    sign_staking_op(validator_keypair, &state.chain_id, &mut op);
    op
}

fn fee_tx(
    state: &ChainState,
    utxo_id: Bytes32,
    keypair: &HybridKeypair,
    owner_pubkey: HybridPubKey,
    input_blinding: [u8; 32],
) -> TransactionV1 {
    let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
    let output_value = INPUT_VALUE - fee;
    let output_blinding = [0x42; 32];
    let fee_blinding = (Scalar::from_bytes_mod_order(input_blinding)
        - Scalar::from_bytes_mod_order(output_blinding))
    .to_bytes();
    let fee_commitment = commit(fee, &fee_blinding);
    let mut tx = TransactionV1 {
        version: ProtocolVersion::CURRENT,
        signature_module_id: 1,
        inputs: vec![InputV1 {
            utxo_id,
            nullifier: Bytes32::from([0x99; 32]),
        }],
        outputs: vec![output(
            output_value,
            output_blinding,
            owner_pubkey,
            [0x43; 32],
        )],
        payment_notes: Vec::new(),
        fee_amount: fee,
        fee_blinding: Bytes32::from(fee_blinding),
        fee_commitment: CommitmentV1 {
            compressed_point: Bytes32::from(fee_commitment.0),
        },
        signature: dummy_sig(),
    };
    tx.signature = sign_transaction(&tx, keypair, &state.chain_id);
    tx
}

fn block_with_transactions(state: &ChainState, transactions: Vec<TransactionV1>) -> BlockV1 {
    BlockV1 {
        header: BlockHeaderV1 {
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
            polc_round: NO_POLC_ROUND,
            proposer_vrf_output: Bytes32::ZERO,
            proposer_vrf_proof: VariableBytes::<MAX_VRF_PROOF_BYTES>::from_slice(&[]).unwrap(),
            quorum_certificate: VariableBytes::<MAX_QC_SIZE_BYTES>::from_slice(&[]).unwrap(),
            election_result_hash: None,
        },
        transactions,
        slashing_evidence: vec![],
        governance_ops: vec![],
        staking_ops: vec![],
        vrf_reveals: vec![],
    }
}

fn signed_vote(keypair: &HybridKeypair, validator_id: Bytes32, block_hash: Bytes32) -> VoteV1 {
    let signing_bytes = indra_core::types::vote_signing::vote_signing_bytes(
        7,
        0,
        VoteStep::Precommit,
        &block_hash,
        &validator_id,
        None,
        DEFAULT_CHAIN_ID,
    );
    let sig = keypair.sign(&signing_bytes).unwrap();
    VoteV1 {
        height: 7,
        round: 0,
        step: VoteStep::Precommit,
        block_hash,
        validator_id,
        election_result_hash: None,
        signature: HybridSignature {
            classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
        },
    }
}

fn slash_evidence(keypair: &HybridKeypair, validator_id: Bytes32) -> SlashEvidenceV1 {
    SlashEvidenceV1 {
        validator_id,
        vote_1: signed_vote(keypair, validator_id, Bytes32::from([0xAA; 32])),
        vote_2: signed_vote(keypair, validator_id, Bytes32::from([0xBB; 32])),
    }
}

#[test]
fn bond_and_unbond_do_not_change_total_supply() {
    let mut state = ChainState::new_genesis();
    let (validator_pubkey, validator_keypair) = keypair([0x10; 32]);
    let validator_id = pubkey_to_id(&validator_pubkey);
    state
        .validators
        .upsert(make_validator(&validator_pubkey, [0x10; 32], 0))
        .unwrap();
    let bond_output = output(
        INPUT_VALUE,
        [0x11; 32],
        validator_pubkey.clone(),
        [0x12; 32],
    );
    let bond_utxo_id = state.utxos.insert(bond_output, 0, 0, 0).unwrap();
    let supply_before = state.total_supply;
    let chain_id = state.chain_id.clone();

    let stake = self_stake_op(
        &state,
        bond_utxo_id,
        validator_pubkey.clone(),
        &validator_keypair,
        1,
    );
    apply_staking_op(&mut state, &stake, &chain_id, 1).unwrap();
    assert_eq!(state.total_supply, supply_before);
    assert_eq!(
        state.validators.get(&validator_id).unwrap().stake_spark,
        INPUT_VALUE
    );

    let unstake = self_unstake_op(
        &state,
        bond_utxo_id,
        validator_pubkey,
        &validator_keypair,
        2,
    );
    apply_staking_op(&mut state, &unstake, &chain_id, 1).unwrap();
    assert_eq!(state.total_supply, supply_before);

    apply_epoch_transition(&mut state, UNBONDING_PERIOD_EPOCHS, 0).unwrap();
    assert_eq!(state.total_supply, supply_before);
}

#[test]
fn slash_reduces_total_supply_by_burn_amount() {
    let mut state = ChainState::new_genesis();
    let (validator_pubkey, validator_keypair) = keypair([0x20; 32]);
    let validator_id = pubkey_to_id(&validator_pubkey);
    state
        .validators
        .upsert(make_validator(&validator_pubkey, [0x20; 32], INPUT_VALUE))
        .unwrap();
    let evidence = slash_evidence(&validator_keypair, validator_id);
    let supply_before = state.total_supply;
    let treasury_before = state.treasury_balance;
    let slash_bps = state.governance.params.slash_double_precommit_bps;
    let slash_amount = INPUT_VALUE.saturating_mul(slash_bps as u64) / 10_000;
    let chain_id = state.chain_id.clone();

    apply_slash_at_height(&mut state, &evidence, &chain_id, 7, None).unwrap();

    assert_eq!(state.total_supply, supply_before - slash_amount);
    assert_eq!(state.treasury_balance, treasury_before);
}

#[test]
fn epoch_reward_does_not_increase_total_supply() {
    let mut state = ChainState::new_genesis();
    let (validator_pubkey, _) = keypair([0x30; 32]);
    state
        .validators
        .upsert(make_validator(&validator_pubkey, [0x30; 32], INPUT_VALUE))
        .unwrap();
    let supply_before = state.total_supply;

    apply_epoch_transition(&mut state, 1, 0).unwrap();

    assert_eq!(state.total_supply, supply_before);
}

#[test]
fn fee_burn_reduces_total_supply() {
    let mut state = ChainState::new_genesis();
    let (owner_pubkey, owner_keypair) = keypair([0x40; 32]);
    let input_blinding = [0x41; 32];
    let utxo_id = state
        .utxos
        .insert(
            output(
                INPUT_VALUE,
                input_blinding,
                owner_pubkey.clone(),
                [0x44; 32],
            ),
            0,
            0,
            0,
        )
        .unwrap();
    let tx = fee_tx(
        &state,
        utxo_id,
        &owner_keypair,
        owner_pubkey,
        input_blinding,
    );
    let burned = tx.fee_amount / 2;
    let supply_before = state.total_supply;

    let block = block_with_transactions(&state, vec![tx]);
    apply_block(&mut state, &block, 0).unwrap();

    assert_eq!(state.total_supply, supply_before - burned);
}

#[test]
fn liveness_penalty_burn_reduces_total_supply_if_active() {
    let mut state = ChainState::new_genesis();
    let (validator_pubkey, _) = keypair([0x50; 32]);
    state
        .validators
        .upsert(make_validator(&validator_pubkey, [0x50; 32], INPUT_VALUE))
        .unwrap();
    let supply_before = state.total_supply;

    apply_epoch_transition(&mut state, 3, 0).unwrap();

    assert!(state.total_supply < supply_before);
    assert_eq!(supply_before - state.total_supply, INPUT_VALUE / 1_000);
}

#[test]
fn total_supply_invariant_across_full_epoch_cycle() {
    let mut state = ChainState::new_genesis();
    let (validator_pubkey, _) = keypair([0x60; 32]);
    state
        .validators
        .upsert(make_validator(&validator_pubkey, [0x60; 32], INPUT_VALUE))
        .unwrap();
    let (owner_pubkey, owner_keypair) = keypair([0x61; 32]);
    let input_blinding = [0x62; 32];
    let utxo_id = state
        .utxos
        .insert(
            output(
                INPUT_VALUE,
                input_blinding,
                owner_pubkey.clone(),
                [0x63; 32],
            ),
            0,
            0,
            0,
        )
        .unwrap();
    let tx = fee_tx(
        &state,
        utxo_id,
        &owner_keypair,
        owner_pubkey,
        input_blinding,
    );
    let expected_burn = tx.fee_amount / 2;
    let supply_before = state.total_supply;

    let block = block_with_transactions(&state, vec![tx]);
    apply_block(&mut state, &block, 0).unwrap();
    let after_block_supply = state.total_supply;
    apply_epoch_transition(&mut state, 1, 0).unwrap();

    assert_eq!(after_block_supply, supply_before - expected_burn);
    assert_eq!(
        state.total_supply, after_block_supply,
        "epoch rewards are preminted/accounted and must not mint supply"
    );
}
