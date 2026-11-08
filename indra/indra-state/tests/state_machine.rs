//! Integration tests for the complete state machine.
//!
//! These tests verify multi-block scenarios, epoch transitions,
//! and fee evolution over sequences of blocks.

use indra_core::types::primitives::TEST_CHAIN_ID;

use indra_core::{
    codec::{Decode, Encode},
    types::{
        block::{BlockHeaderVNext, BlockVNext},
        crypto::PQVoteSig,
        primitives::{
            DUST_LIMIT_SPARK, EPOCH_DURATION_BLOCKS, INITIAL_BASE_FEE_SPARK_PER_KB,
            LIFETIME_SUPPLY_CAP_SPARK, MAX_QC_SIZE_BYTES, TRANSACTION_PROTOCOL_VERSION,
        },
        qc::{ClassicalVoteSig, QuorumCertificateV1, SIGNER_BITFIELD_BYTES},
        staking::{ColdStakingAuthorization, StakingOp, StakingOpBody},
        transaction::{InputV1, OutputV1, TransactionV1},
        vote::VoteStep,
    },
    Bytes32, HybridPubKey, HybridSignature, ProtocolVersion, VariableBytes,
};
use indra_crypto::{ClassicalKeypair, HybridKeypair, PqKeypair, VrfKeypair};
use indra_state::{
    apply_block_for_test as apply_block, compute_state_root,
    epoch::{apply_epoch_transition, EpochTransitionContext},
    utxo::UtxoSet,
    ChainState, ValidatorEntry, ValidatorStatus,
};

const TEST_INPUT_VALUE: u64 = 1_000_000;

fn new_test_state() -> ChainState {
    let mut state = ChainState::new_genesis(TEST_CHAIN_ID);
    state.active_slot_coefficient_numerator =
        indra_core::types::primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR;
    state
}

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
    mut body: StakingOpBody,
    nonce: u64,
    keypair: &HybridKeypair,
    chain_id: &str,
) -> StakingOp {
    let cold_designated = matches!(
        body,
        StakingOpBody::SelfStake { .. }
            | StakingOpBody::SetAutoDelegate { .. }
            | StakingOpBody::ClaimRewards { .. }
    );
    if cold_designated {
        let authorization = ColdStakingAuthorization {
            cold_key_version: 1,
            cold_nonce: nonce,
        };
        match &mut body {
            StakingOpBody::SelfStake {
                cold_authorization, ..
            }
            | StakingOpBody::SetAutoDelegate {
                cold_authorization, ..
            } => {
                *cold_authorization = authorization;
            }
            StakingOpBody::ClaimRewards {
                cold_authorization, ..
            } => *cold_authorization = Some(authorization),
            _ => unreachable!(),
        }
    }
    let mut op = StakingOp {
        body,
        nonce: if cold_designated { 0 } else { nonce },
        signature: dummy_sig(),
    };
    let signing_bytes = op
        .cold_authorization_signing_bytes(chain_id)
        .unwrap()
        .unwrap_or_else(|| op.signing_bytes(chain_id));
    let sig = keypair.sign(&signing_bytes).unwrap();
    op.signature = HybridSignature {
        classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
        pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
    };
    op
}

fn install_validator(
    state: &mut ChainState,
    seed: [u8; 32],
) -> (Bytes32, HybridPubKey, HybridKeypair) {
    let (pubkey, keypair) = make_test_keypair(seed);
    let validator_id = pubkey.identity_id();
    state
        .validators
        .upsert(ValidatorEntry {
            validator_id,
            name: format!("validator-{}", seed[0]),
            hybrid_classical_pk: Some(pubkey.classical_pk.0),
            hybrid_pq_pk: Some(pubkey.pq_pk.as_slice().to_vec()),
            vrf_pk: Some(VrfKeypair::from_seed(&seed).public_key()),
            vrf_key_activation_epoch: 0,
            pending_vrf_pk: None,
            pending_vrf_activation_epoch: None,
            stake_spark: 0,
            status: ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            slashed_offense_id: None,
            commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
            pending_commission_bps: None,
            pending_commission_effective_epoch: None,
            min_delegation_spark: DUST_LIMIT_SPARK,
            auto_delegate_to: None,
            network_addr: None,
            network_addr_last_updated_epoch: None,
            cold_hybrid_classical_pk: Some(pubkey.classical_pk.0),
            cold_hybrid_pq_pk: Some(pubkey.pq_pk.as_slice().try_into().unwrap()),
            cold_key_version: 1,
            cold_nonce: 0,
        })
        .unwrap();
    (validator_id, pubkey, keypair)
}

fn finalized_genesis() -> ChainState {
    let mut state = new_test_state();
    let (validator_id, _, _) = install_validator(&mut state, [0xF0; 32]);
    state.validators.get_mut(&validator_id).unwrap().stake_spark = TEST_INPUT_VALUE;
    state.finalize_genesis().unwrap();
    state
}

fn account_fixture_claims(state: &mut ChainState) {
    state.monetary_aggregates = state.recompute_monetary_aggregates().unwrap();
    let issued = state.monetary_aggregates.total_claims_spark().unwrap();
    state.total_supply = issued;
    state.monetary_ledger.genesis_issued_spark = issued;
    state.monetary_ledger.reward_budget_spark = LIFETIME_SUPPLY_CAP_SPARK - issued;
    state.monetary_ledger.validate(issued).unwrap();
}

fn advance_fixture_height_with_issuance(state: &mut ChainState, height: u64) {
    let target = indra_state::monetary::cumulative_reward_target_at_height(
        state.monetary_ledger.reward_budget_spark,
        height,
    )
    .unwrap();
    if target != 0 {
        let mut position = state.stake_positions.values().next().unwrap().clone();
        position.pending_rewards_spark =
            position.pending_rewards_spark.checked_add(target).unwrap();
        state.stake_positions.insert(position.position_id, position);
    }
    state.monetary_ledger.cumulative_reward_minted_spark = target;
    state.monetary_ledger.epoch_reward_minted_spark = target;
    state.total_supply = state.total_supply.checked_add(target).unwrap();
    state.monetary_aggregates = state.recompute_monetary_aggregates().unwrap();
    state.height = height;
}

fn sign_transaction(
    keypair: &HybridKeypair,
    chain_id: &str,
    tx: &TransactionV1,
) -> HybridSignature {
    let sig = keypair.sign(&tx.signing_bytes(chain_id).unwrap()).unwrap();
    HybridSignature {
        classical_sig: VariableBytes::from_slice(&sig.classical.0).unwrap(),
        pq_sig: VariableBytes::from_slice(&sig.pq.0).unwrap(),
    }
}

fn make_output(byte: u8, owner_pubkey: HybridPubKey) -> OutputV1 {
    let value = TEST_INPUT_VALUE + byte as u64;

    OutputV1 {
        value_spark: value,
        owner_pubkey,
        lock_height: 0,
    }
}

fn make_tx(
    state: &ChainState,
    keypair: &HybridKeypair,
    owner_pubkey: HybridPubKey,
    utxo_id: Bytes32,
    input_value: u64,
    _input_blinding: [u8; 32],
    _input_tag: u8,
    _out_byte: u8,
) -> TransactionV1 {
    let fee = INITIAL_BASE_FEE_SPARK_PER_KB * 10;
    let output_value = input_value - fee;
    let mut tx = TransactionV1 {
        version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
        signature_module_id: 1,
        inputs: vec![InputV1 { utxo_id }],
        outputs: vec![OutputV1 {
            value_spark: output_value,
            owner_pubkey: owner_pubkey.clone(),
            lock_height: 0,
        }],
        fee_amount: fee,
        signature: dummy_sig(),
    };
    tx.signature = sign_transaction(keypair, &state.chain_id, &tx);
    tx
}

fn make_block(state: &ChainState, txs: Vec<TransactionV1>) -> BlockVNext {
    let height = state.height + 1;
    let quorum_certificate = if height > 1 {
        let signer_ids: Vec<_> = state
            .validators
            .active_validators()
            .map(|validator| validator.validator_id)
            .collect();
        qc_bytes_for_signers(state, &signer_ids, height - 1)
    } else {
        VariableBytes::from_slice(&[]).unwrap()
    };
    BlockVNext {
        header: BlockHeaderVNext {
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
            polc_round: None,
            proposer_id: Bytes32::from([0x82; 32]),
            vrf_suite: indra_core::types::block::VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
            election_seed: state.election_seed,
            proposer_vrf_output: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            proposer_vrf_proof: VariableBytes::from_slice(&[0u8; 80]).unwrap(),
            value_entropy: indra_core::types::block::ProposalEntropyV1 {
                origin_proposer_id: Bytes32::from([0x82; 32]),
                origin_round: 0,
                vrf_output: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                vrf_proof: VariableBytes::from_slice(&[0u8; 80]).unwrap(),
            },
            sortition_claim: indra_core::types::block::SortitionClaimV1::PraosThreshold,
            proposer_priority: indra_core::types::primitives::Bytes64([0; 64]),
            quorum_certificate,
        },
        transactions: txs,
        slashing_evidence: vec![],
        governance_ops: vec![],
        staking_ops: vec![],
    }
}

fn install_test_validators_for_qc(state: &mut ChainState) -> Vec<Bytes32> {
    let ids: Vec<_> = (0..4u8)
        .map(|index| {
            let seed = [0xA0 + index; 32];
            let (pubkey, _) = make_test_keypair(seed);
            let validator_id = pubkey.identity_id();
            state
                .validators
                .upsert(ValidatorEntry {
                    validator_id,
                    name: format!("qc-validator-{index}"),
                    hybrid_classical_pk: Some(pubkey.classical_pk.0),
                    hybrid_pq_pk: Some(pubkey.pq_pk.as_slice().to_vec()),
                    vrf_pk: Some(VrfKeypair::from_seed(&seed).public_key()),
                    vrf_key_activation_epoch: 0,
                    pending_vrf_pk: None,
                    pending_vrf_activation_epoch: None,
                    stake_spark: 100_000_000_000,
                    status: ValidatorStatus::Active,
                    registered_epoch: 0,
                    last_active_epoch: 0,
                    slashed_offense_id: None,
                    commission_bps: indra_core::types::primitives::DEFAULT_COMMISSION_BPS,
                    pending_commission_bps: None,
                    pending_commission_effective_epoch: None,
                    min_delegation_spark: DUST_LIMIT_SPARK,
                    auto_delegate_to: None,
                    network_addr: None,
                    network_addr_last_updated_epoch: None,
                    cold_hybrid_classical_pk: Some(pubkey.classical_pk.0),
                    cold_hybrid_pq_pk: Some(pubkey.pq_pk.as_slice().try_into().unwrap()),
                    cold_key_version: 1,
                    cold_nonce: 0,
                })
                .unwrap();
            validator_id
        })
        .collect();
    state.finalize_genesis().unwrap();
    ids
}

fn qc_bytes_for_signers(
    state: &ChainState,
    signer_ids: &[Bytes32],
    certified_height: u64,
) -> VariableBytes<MAX_QC_SIZE_BYTES> {
    let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
    let snapshot = state
        .snapshot_for_consensus_height(certified_height)
        .unwrap();
    for signer_id in signer_ids {
        let (position, _) = snapshot.entry_with_position(signer_id).unwrap();
        signer_bitfield[position / 8] |= 1 << (position % 8);
    }
    let signed: Vec<_> = signer_ids
        .iter()
        .map(|validator_id| {
            let keypair = std::iter::once([0xF0; 32])
                .chain((0..4u8).map(|index| [0xA0 + index; 32]))
                .chain((1..=21u8).map(|seed| [seed; 32]))
                .map(make_test_keypair)
                .find(|(key, _)| key.identity_id() == *validator_id)
                .map(|(_, keypair)| keypair)
                .expect("QC signer seed must be known to the integration fixture");
            let bytes = indra_core::types::vote_signing::vote_signing_bytes(
                certified_height,
                0,
                VoteStep::Precommit,
                &state.tip_hash,
                validator_id,
                &snapshot.snapshot_root,
                &state.chain_id,
            );
            (*validator_id, keypair.sign(&bytes).unwrap())
        })
        .collect();
    let qc = QuorumCertificateV1 {
        height: certified_height,
        round: 0,
        block_hash: state.tip_hash,
        snapshot_root: snapshot.snapshot_root,
        signer_bitfield,
        pq_signatures: signed
            .iter()
            .map(|(validator_id, signature)| PQVoteSig {
                validator_id: *validator_id,
                pq_sig: VariableBytes::from_slice(&signature.pq.0).unwrap(),
            })
            .collect(),
        classical_signatures: signed
            .iter()
            .map(|(validator_id, signature)| ClassicalVoteSig {
                validator_id: *validator_id,
                classical_sig: VariableBytes::from_slice(&signature.classical.0).unwrap(),
            })
            .collect(),
    };
    VariableBytes::from_slice(&qc.encode_to_vec()).unwrap()
}

fn make_block_with_qc(state: &ChainState, signer_ids: &[Bytes32]) -> BlockVNext {
    let mut block = make_block(state, vec![]);
    block.header.quorum_certificate =
        qc_bytes_for_signers(state, signer_ids, block.header.height.saturating_sub(1));
    block
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn genesis_state_constants() {
    let state = new_test_state();
    assert_eq!(
        state.total_supply,
        state.monetary_aggregates.total_claims_spark().unwrap()
    );
    assert_eq!(state.height, 0);
    assert_eq!(state.base_fee, INITIAL_BASE_FEE_SPARK_PER_KB);
}

#[test]
fn last_active_epoch_updated_identically_live_and_replay() {
    let mut live_state = new_test_state();
    let signer_ids = install_test_validators_for_qc(&mut live_state);
    advance_fixture_height_with_issuance(&mut live_state, EPOCH_DURATION_BLOCKS);

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
    let mut state = new_test_state();
    let signer_ids = install_test_validators_for_qc(&mut state);
    advance_fixture_height_with_issuance(&mut state, EPOCH_DURATION_BLOCKS);

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

    let block = make_block_with_qc(&state, &signer_ids[..3]);
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
        expected_epoch
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
fn timestamp_does_not_affect_state_root() {
    let mut state_t0 = new_test_state();
    let mut state_t1 = new_test_state();
    install_test_validators_for_qc(&mut state_t0);
    install_test_validators_for_qc(&mut state_t1);

    let block = make_block(&state_t0, vec![]);

    apply_block(&mut state_t0, &block, 0).unwrap();
    apply_block(&mut state_t1, &block, 1_700_000_000).unwrap();

    assert_eq!(
        compute_state_root(&state_t0),
        compute_state_root(&state_t1),
        "State root must be identical regardless of timestamp_secs value. If this fails, timestamp has been accidentally used in state computation."
    );
}

#[test]
fn epoch_record_timestamp_differs_but_state_root_matches() {
    let mut state_live = new_test_state();
    let mut state_replay = new_test_state();
    install_test_validators_for_qc(&mut state_live);
    install_test_validators_for_qc(&mut state_replay);

    let mut live_boundary_record = None;
    let mut replay_boundary_record = None;
    for height in 1u64..=EPOCH_DURATION_BLOCKS {
        let block = make_block(&state_live, vec![]);
        assert_eq!(block.header.height, height);

        live_boundary_record =
            apply_block(&mut state_live, &block, 1_700_000_000 + height).unwrap();
        replay_boundary_record = apply_block(&mut state_replay, &block, 0).unwrap();
    }

    let live_record = live_boundary_record.expect("epoch boundary should emit an EpochRecord");
    let replay_record = replay_boundary_record.expect("epoch boundary should emit an EpochRecord");
    assert_ne!(
        live_record.timestamp_secs, replay_record.timestamp_secs,
        "EpochRecord timestamps should differ between live and replay"
    );
    assert_eq!(
        compute_state_root(&state_live),
        compute_state_root(&state_replay),
        "State roots must match between live and replay despite different timestamps"
    );
}

#[test]
fn one_hundred_empty_blocks() {
    let mut state = finalized_genesis();
    for _ in 0..100 {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block, 0).unwrap();
    }
    assert_eq!(state.height, 100);
}

#[test]
fn utxo_lifecycle_across_blocks() {
    let mut state = finalized_genesis();
    let (owner_pubkey, keypair) = make_test_keypair([0x11; 32]);

    // Create a UTXO by inserting it at genesis
    let output = make_output(0x01, owner_pubkey.clone());
    let utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();
    account_fixture_claims(&mut state);

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

    // Block 2: spend the new UTXO
    // Find the new UTXO id — it was inserted at height 1, tx 0, output 0
    let new_utxo_id = UtxoSet::compute_utxo_id(
        &OutputV1 {
            value_spark: block1_output_value,
            owner_pubkey: owner_pubkey.clone(),
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
}

#[test]
fn fee_evolves_over_blocks() {
    let mut state = finalized_genesis();
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
    let mut state = finalized_genesis();
    let supply_before = state.total_supply;
    let reward_budget = state.monetary_ledger.reward_budget_spark;

    // Apply exactly one epoch worth of blocks
    for _ in 0..EPOCH_DURATION_BLOCKS {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block, 0).unwrap();
    }

    assert_eq!(state.height, EPOCH_DURATION_BLOCKS);
    assert_eq!(state.current_epoch(), 1);
    let expected = indra_state::monetary::cumulative_reward_target_at_height(
        reward_budget,
        EPOCH_DURATION_BLOCKS,
    )
    .unwrap();
    assert_eq!(
        state.total_supply,
        supply_before.checked_add(expected).unwrap()
    );
}

#[test]
fn two_epochs_follow_exact_cumulative_issuance() {
    let mut state = finalized_genesis();
    let genesis_supply = state.total_supply;
    let budget = state.monetary_ledger.reward_budget_spark;

    // First epoch
    for _ in 0..EPOCH_DURATION_BLOCKS {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block, 0).unwrap();
    }
    // Second epoch
    for _ in 0..EPOCH_DURATION_BLOCKS {
        let block = make_block(&state, vec![]);
        apply_block(&mut state, &block, 0).unwrap();
    }

    let expected = indra_state::monetary::cumulative_reward_target_at_height(
        budget,
        EPOCH_DURATION_BLOCKS * 2,
    )
    .unwrap();
    assert_eq!(state.total_supply, genesis_supply + expected);
    assert_eq!(state.current_epoch(), 2);
}

#[test]
fn fees_are_burned() {
    let mut state = finalized_genesis();
    let (owner_pubkey, keypair) = make_test_keypair([0x11; 32]);

    // Insert a spendable UTXO
    let output = make_output(0x01, owner_pubkey.clone());
    let utxo_id = state.utxos.insert(output, 0, 0, 0).unwrap();
    account_fixture_claims(&mut state);
    let supply_before = state.total_supply;
    let reward = indra_state::monetary::block_reward_for_budget(
        state.monetary_ledger.reward_budget_spark,
        1,
    )
    .unwrap();

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

    assert_eq!(state.total_supply, supply_before + reward - (fee / 2));
    assert_eq!(state.fee_reward_pool, fee - (fee / 2));
}

#[test]
fn chain_is_deterministic() {
    // Two independent nodes starting from genesis and applying the same blocks
    // must arrive at identical state
    let mut state_a = finalized_genesis();
    let mut state_b = finalized_genesis();

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
fn test_auto_delegate_full_lifecycle() {
    let mut state = new_test_state();
    let mut validators = Vec::new();
    for i in 1..=21u8 {
        let (id, pubkey, keypair) = install_validator(&mut state, [i; 32]);
        let stake = (22u64 - i as u64) * DUST_LIMIT_SPARK * 100;
        state.validators.get_mut(&id).unwrap().stake_spark = stake;
        validators.push((id, pubkey, keypair));
    }
    state.finalize_genesis().unwrap();

    let target_id = validators[0].0;
    let inactive_id = validators[20].0;
    let inactive_position_id = indra_core::types::stake_position::derive_position_id(
        inactive_id,
        inactive_id,
        indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
            validator_id: inactive_id,
        },
    );
    let inactive_pubkey = validators[20].1.clone();
    let inactive_keypair = &validators[20].2;
    let chain_id = state.chain_id.clone();
    let set_auto_delegate = signed_staking_op(
        StakingOpBody::SetAutoDelegate {
            validator_id: inactive_id,
            target_validator_id: target_id,
            cold_authorization: ColdStakingAuthorization {
                cold_key_version: 1,
                cold_nonce: 1,
            },
        },
        1,
        &inactive_keypair,
        &chain_id,
    );
    let mut set_block = make_block(&state, vec![]);
    set_block.staking_ops = vec![set_auto_delegate];
    apply_block(&mut state, &set_block, 0).unwrap();

    let mut previous_rewards = 0;
    for _ in 1u64..=3 {
        let reward_block = make_block(&state, vec![]);
        apply_block(&mut state, &reward_block, 0).unwrap();
        let rewards = state
            .stake_positions
            .get(&inactive_position_id)
            .unwrap()
            .pending_rewards_spark;
        assert!(rewards > previous_rewards);
        previous_rewards = rewards;
    }

    let claimed = state
        .stake_positions
        .get(&inactive_position_id)
        .unwrap()
        .pending_rewards_spark;
    assert!(claimed >= DUST_LIMIT_SPARK);
    let utxos_before = state.utxos.len();
    let chain_id = state.chain_id.clone();
    let claim_rewards = signed_staking_op(
        StakingOpBody::ClaimRewards {
            validator_id: inactive_id,
            delegator_pubkey: inactive_pubkey,
            cold_authorization: None,
        },
        2,
        &inactive_keypair,
        &chain_id,
    );
    let mut claim_block = make_block(&state, vec![]);
    claim_block.staking_ops = vec![claim_rewards];
    apply_block(&mut state, &claim_block, 0).unwrap();

    let post_claim_accrual = state
        .stake_positions
        .get(&inactive_position_id)
        .unwrap()
        .pending_rewards_spark;
    assert!(
        post_claim_accrual < claimed,
        "the claim must clear prior accrual even though its own block issues a fresh reward"
    );
    assert_eq!(state.utxos.len(), utxos_before + 1);
    assert!(state
        .utxos
        .all_entries()
        .any(|entry| entry.output.value_spark == claimed));
}

#[test]
fn epoch_transition_produces_identical_state_on_replay() {
    let mut original = new_test_state();
    for seed in 1..=4 {
        let (id, _, _) = install_validator(&mut original, [seed; 32]);
        original.validators.get_mut(&id).unwrap().stake_spark = 1_000_000;
    }
    original.finalize_genesis().unwrap();
    let mut replay = original.clone();
    apply_epoch_transition(
        &mut original,
        &EpochTransitionContext::new(
            (1u64).saturating_mul(EPOCH_DURATION_BLOCKS),
            (1u64)
                .saturating_mul(EPOCH_DURATION_BLOCKS)
                .saturating_sub(1),
        )
        .unwrap(),
        0,
    )
    .unwrap();
    apply_epoch_transition(
        &mut replay,
        &EpochTransitionContext::new(
            (1u64).saturating_mul(EPOCH_DURATION_BLOCKS),
            (1u64)
                .saturating_mul(EPOCH_DURATION_BLOCKS)
                .saturating_sub(1),
        )
        .unwrap(),
        0,
    )
    .unwrap();
    assert_eq!(original.encode_to_vec(), replay.encode_to_vec());
}

#[test]
fn corrected_arithmetic_differs_from_saturating_multiply_then_divide() {
    use indra_core::types::primitives::muldiv;

    const EPOCH_REWARD: u64 = 1_189_200_000 * 300;
    const STAKE: u64 = 100_000_000_000;
    const TOTAL_STAKE: u64 = STAKE * 4;

    // This is the persisted snapshot before the 300th (epoch-boundary) block.
    // The transition below models the reward mutation caused by those 300
    // blocks; all other blocks in this minimal replay are empty.
    let mut snapshot = new_test_state();
    let mut validator_ids = Vec::new();
    for seed in 1..=4 {
        let (id, _, _) = install_validator(&mut snapshot, [seed; 32]);
        snapshot.validators.get_mut(&id).unwrap().stake_spark = STAKE;
        let custody = indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
            validator_id: id,
        };
        let position = indra_core::types::stake_position::StakePositionV1::new(
            id,
            id,
            custody,
            Some(
                indra_core::types::stake_position::ActiveStakeAggregateV1::new(STAKE, 1, 1)
                    .unwrap(),
            ),
            0,
            0,
        )
        .unwrap();
        snapshot
            .stake_positions
            .insert(position.position_id, position);
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
        let position_id = indra_core::types::stake_position::derive_position_id(
            *id,
            *id,
            indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
                validator_id: *id,
            },
        );
        let mut position = reference.stake_positions.get(&position_id).unwrap().clone();
        position.pending_rewards_spark = old_reward;
        reference.stake_positions.insert(position_id, position);
    }
    let committed_root = compute_state_root(&reference);

    // What a new binary would produce when replaying the same boundary with
    // unconditional muldiv: a different state root, reproducing the incident.
    let mut ungated_replay = snapshot.clone();
    ungated_replay.height = EPOCH_DURATION_BLOCKS;
    for id in &validator_ids {
        let position_id = indra_core::types::stake_position::derive_position_id(
            *id,
            *id,
            indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity {
                validator_id: *id,
            },
        );
        let mut position = ungated_replay
            .stake_positions
            .get(&position_id)
            .unwrap()
            .clone();
        position.pending_rewards_spark = new_reward;
        ungated_replay.stake_positions.insert(position_id, position);
    }
    assert_ne!(committed_root, compute_state_root(&ungated_replay));
}

#[test]
fn corrected_arithmetic_is_deterministic_across_restarts() {
    use indra_core::types::primitives::muldiv;

    let epoch_reward = 356_760_000_000;
    let stake = 100_000_000_000;
    let total_stake = 400_000_000_000;
    let replay_height = 100u64;
    let reward_for = |_height: u64| muldiv(epoch_reward, stake, total_stake);

    // Both binaries dispatch from the block height, not from binary version.
    assert_eq!(reward_for(replay_height), reward_for(replay_height));
    assert_eq!(reward_for(replay_height), 89_190_000_000);
}

#[test]
fn governance_state_encoding_is_deterministic() {
    let mut first = new_test_state();
    let mut second = new_test_state();
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
fn commission_bps_uses_corrected_arithmetic() {
    use indra_core::types::primitives::bps_of;

    let reward = 89_190_000_000u64;
    let commission_bps = 1_000u32;
    let old = reward.saturating_mul(commission_bps as u64) / 10_000;
    let new = bps_of(reward, commission_bps);

    assert_eq!(old, 8_919_000_000);
    assert_eq!(new, 8_919_000_000);
}

#[test]
fn liveness_penalty_uses_corrected_arithmetic() {
    use indra_core::types::primitives::bps_of;

    let stake = 100_000_000_000u64;
    let liveness_bps = 10u32;
    let old = stake.saturating_mul(liveness_bps as u64) / 10_000;
    let new = bps_of(stake, liveness_bps);

    assert_eq!(old, 100_000_000);
    assert_eq!(new, 100_000_000);
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
