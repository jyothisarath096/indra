use indra_core::types::primitives::TEST_CHAIN_ID;
    use super::*;
    use crate::NodeConfig;
    use indra_consensus::{
        producer::{produce_block, BlockTemplate},
        vote::VoteCollector,
    };
    use indra_core::{
        types::block::{BlockHeaderVNext, BlockVNext},
        types::primitives::{DEFAULT_COMMISSION_BPS, DUST_LIMIT_SPARK},
        Bytes32, Bytes64, ProtocolVersion, VariableBytes,
    };
    use indra_crypto::{
        hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair},
        VrfKeypair,
    };

    use indra_state::{apply_block, ChainState, ValidatorEntry, ValidatorStatus};
    use std::{path::PathBuf, time::Instant};

    fn temp_dir(suffix: &str) -> PathBuf {
        tempfile::Builder::new()
            .prefix(&format!("indra_driver_test_{suffix}_"))
            .tempdir()
            .unwrap()
            .keep()
    }

    fn make_block(state: &ChainState) -> indra_core::types::block::BlockProposalVNext {
        let mut block = BlockVNext {
            header: BlockHeaderVNext {
                protocol_version: ProtocolVersion::CURRENT,
                height: state.height + 1,
                prev_hash: state.tip_hash,
                timestamp: 1_700_000_000 + state.height + 1,
                state_root: Bytes32::ZERO,
                validator_set_root: Bytes32::ZERO,
                mempool_set_root: Bytes32::ZERO,
                value_hash: Bytes32::ZERO,
                base_fee: state.base_fee,
                proposer_round: 0,
                polc_round: None,
                proposer_id: Bytes32::ZERO,
                vrf_suite: indra_core::types::block::VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
                election_seed: state.election_seed,
                proposer_vrf_output: VariableBytes::from_slice(&[0; 64]).unwrap(),
                proposer_vrf_proof: VariableBytes::from_slice(&[0; 80]).unwrap(),
                value_entropy: indra_core::types::block::ProposalEntropyV1 {
                    origin_proposer_id: Bytes32::ZERO,
                    origin_round: 0,
                    vrf_output: VariableBytes::from_slice(&[0; 64]).unwrap(),
                    vrf_proof: VariableBytes::from_slice(&[0; 80]).unwrap(),
                },
                sortition_claim: indra_core::types::block::SortitionClaimV1::PraosThreshold,
                proposer_priority: indra_core::types::primitives::Bytes64::ZERO,
                quorum_certificate: indra_core::VariableBytes::from_slice(&[]).unwrap(),
            },
            transactions: vec![],
            slashing_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        };

        let mut projection_state = state.clone();
        let projected =
            indra_state::project_block_for_roots(&mut projection_state, &block, 0).unwrap();
        block.header.state_root = projected.state_root;
        block.header.validator_set_root = projected.validator_set_root;
        block.header.value_hash = projected.value_hash;
        indra_core::types::block::BlockProposalVNext {
            block,
            proposer_authorization: indra_core::types::crypto::HybridSignature {
                classical_sig: VariableBytes::from_slice(&[]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[]).unwrap(),
            },
        }
    }

    fn test_hash(i: usize) -> Bytes32 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&((i as u64).saturating_add(1)).to_le_bytes());
        Bytes32::from(bytes)
    }

    fn governing_snapshot_root(driver: &ConsensusDriver, height: u64) -> Bytes32 {
        driver
            .engine
            .state
            .snapshot_for_consensus_height(height)
            .expect("test fixture must have the governing snapshot")
            .snapshot_root
    }

    fn dummy_vote(
        height: u64,
        round: u32,
        step: VoteStep,
        block_hash: Bytes32,
        snapshot_root: Bytes32,
    ) -> VoteV1 {
        VoteV1 {
            height,
            round,
            step,
            block_hash,
            validator_id: test_hash(round as usize),
            snapshot_root,
            signature: indra_core::types::crypto::HybridSignature {
                classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[0u8; 32]).unwrap(),
            },
        }
    }

    fn single_validator_qc_bytes(
        driver: &ConsensusDriver,
        signer: &HybridKeypair,
        height: u64,
        block_hash: Bytes32,
    ) -> Vec<u8> {
        let snapshot_root = driver
            .engine
            .state
            .snapshot_for_consensus_height(height)
            .unwrap()
            .snapshot_root;
        let validator_id = indra_core::types::crypto::hybrid_identity_id(
            &signer.public_key().classical.0,
            &signer.public_key().pq.0,
        );
        let vote = indra_consensus::vote::produce_vote(
            height,
            0,
            VoteStep::Precommit,
            block_hash,
            validator_id,
            snapshot_root,
            TEST_CHAIN_ID,
            signer,
        )
        .unwrap();
        build_qc(
            height,
            0,
            block_hash,
            TEST_CHAIN_ID,
            snapshot_root,
            &driver.engine.qc_validators(),
            vec![&vote],
        )
        .unwrap()
        .encode_to_vec()
    }

    fn qc_bytes_from_signers(
        driver: &ConsensusDriver,
        signers: &[&HybridKeypair],
        height: u64,
        round: u32,
        block_hash: Bytes32,
    ) -> Vec<u8> {
        let snapshot_root = driver
            .engine
            .state
            .snapshot_for_consensus_height(height)
            .unwrap()
            .snapshot_root;
        let votes: Vec<_> = signers
            .iter()
            .map(|signer| {
                let validator_id = indra_core::types::crypto::hybrid_identity_id(
                    &signer.public_key().classical.0,
                    &signer.public_key().pq.0,
                );
                indra_consensus::vote::produce_vote(
                    height,
                    round,
                    VoteStep::Precommit,
                    block_hash,
                    validator_id,
                    snapshot_root,
                    TEST_CHAIN_ID,
                    signer,
                )
                .unwrap()
            })
            .collect();
        let vote_refs: Vec<_> = votes.iter().collect();
        build_qc(
            height,
            round,
            block_hash,
            TEST_CHAIN_ID,
            snapshot_root,
            &driver.engine.qc_validators(),
            vote_refs,
        )
        .unwrap()
        .encode_to_vec()
    }

    fn install_active_validator(
        driver: &mut ConsensusDriver,
        seed: [u8; 32],
        name: &str,
    ) -> HybridKeypair {
        let classical = ClassicalKeypair::from_seed(&seed);
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let hybrid = HybridKeypair::new(classical, pq);
        let public = hybrid.public_key();
        let vrf_pk = VrfKeypair::from_seed(&seed).public_key();
        let cold = indra_crypto::ColdHybridKeypair::from_independent_seeds(
            [seed[0] ^ 0xA5; 32],
            [seed[0] ^ 0x5A; 32],
        )
        .unwrap();
        let cold_public = cold.public_key();
        let cold_public = cold_public.as_complete_hybrid();
        let validator_id =
            indra_core::types::crypto::hybrid_identity_id(&public.classical.0, &public.pq.0);

        if driver.engine.state.validators.get(&validator_id).is_none() {
            driver
                .engine
                .state
                .validators
                .upsert(ValidatorEntry {
                    validator_id,
                    name: name.to_string(),
                    hybrid_classical_pk: Some(public.classical.0),
                    hybrid_pq_pk: Some(public.pq.0.to_vec()),
                    vrf_pk: Some(vrf_pk),
                    vrf_key_activation_epoch: 0,
                    pending_vrf_pk: None,
                    pending_vrf_activation_epoch: None,
                    stake_spark: 1_000_000,
                    status: ValidatorStatus::Active,
                    registered_epoch: 0,
                    last_active_epoch: 0,
                    slashed_offense_id: None,
                    commission_bps: DEFAULT_COMMISSION_BPS,
                    pending_commission_bps: None,
                    pending_commission_effective_epoch: None,
                    min_delegation_spark: DUST_LIMIT_SPARK,
                    auto_delegate_to: None,
                    network_addr: None,
                    network_addr_last_updated_epoch: None,
                    cold_hybrid_classical_pk: Some(cold_public.classical.0),
                    cold_hybrid_pq_pk: Some(cold_public.pq.0),
                    cold_key_version: 1,
                    cold_nonce: 0,
                })
                .unwrap();
            if driver.engine.state.height == 0 {
                crate::genesis::finalize_test_genesis(&mut driver.engine.state);
            }
        }
        hybrid
    }

    fn validator_id_for(signer: &HybridKeypair) -> Bytes32 {
        indra_core::types::crypto::hybrid_identity_id(
            &signer.public_key().classical.0,
            &signer.public_key().pq.0,
        )
    }

    fn local_driver(seed: [u8; 32], suffix: &str) -> (ConsensusDriver, PathBuf) {
        local_driver_at_dir(seed, temp_dir(suffix))
    }

    fn local_driver_at_dir(seed: [u8; 32], dir: PathBuf) -> (ConsensusDriver, PathBuf) {
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let genesis_path = dir.join("genesis.toml");
        std::fs::create_dir_all(&dir).unwrap();
        for counter in 0u64..4_096 {
            let extra = |tag: u8| {
                let mut value = [tag; 32];
                value[..8].copy_from_slice(&counter.to_le_bytes());
                value
            };
            let seeds = [seed, extra(0xE1), extra(0xE2), extra(0xE3)];
            let genesis = crate::genesis::test_genesis_toml_single_authority(
                "indra-testnet-1",
                &seeds.map(|value| (value, value, value)),
            );
            std::fs::write(&genesis_path, &genesis).unwrap();
            let mut config = NodeConfig::local_test(dir.clone());
            config.genesis_path = Some(genesis_path.to_string_lossy().to_string());
            config.validator_seed = Some(seed);
            config.vrf_seed = Some(seed);
            config.pq_pk = Some(pq.public_key().0.to_vec());
            config.pq_seed = Some(pq.secret_key_bytes());
            let engine = NodeEngine::init(config).unwrap();
            let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
            let driver = ConsensusDriver::new(engine, vote_safety);
            let vrf = VrfKeypair::from_seed(&seed);
            let eligible = (0..MAX_ROUNDS_PER_HEIGHT).any(|round| {
                let election = driver.proposer_election_for_height(1, round).unwrap();
                election
                    .candidates
                    .iter()
                    .find(|candidate| candidate.vrf_pubkey == vrf.public_key())
                    .map(|candidate| {
                        indra_consensus::proposer::compute_proposer_vrf(
                            candidate.validator_id,
                            &vrf,
                            &election,
                        )
                        .unwrap()
                        .eligible
                    })
                    .unwrap_or(false)
            });
            if eligible {
                return (driver, dir);
            }
            drop(driver);
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
        }
        panic!("test genesis could not find an eligible deterministic validator")
    }

    struct TestValidatorMaterial {
        seed: [u8; 32],
        classical: ClassicalKeypair,
        pq: PqKeypair,
        vrf: VrfKeypair,
        cold: indra_crypto::ColdHybridKeypair,
        validator_id: [u8; 32],
        vrf_output: Vec<u8>,
        vrf_proof: Vec<u8>,
    }

    fn test_validator_material(seed: [u8; 32]) -> TestValidatorMaterial {
        let classical = ClassicalKeypair::from_seed(&seed);
        let pq = PqKeypair::from_seed(&seed).unwrap();
        let vrf = VrfKeypair::from_seed(&seed);
        let mut cold_classical_seed = seed;
        cold_classical_seed[0] ^= 0xA5;
        let mut cold_pq_seed = seed;
        cold_pq_seed[0] ^= 0x5A;
        let cold = indra_crypto::ColdHybridKeypair::from_independent_seeds(
            cold_classical_seed,
            cold_pq_seed,
        ).unwrap();
        let validator_id = indra_core::types::crypto::hybrid_identity_id(
            &classical.public_key().0, &pq.public_key().0,
        ).0;
        let challenge = indra_core::types::staking::StakingOp::vrf_possession_challenge(
            "indra-testnet-1", &Bytes32::from(validator_id),
            &Bytes32::from(vrf.public_key()), 0,
        ).unwrap();
        let (vrf_output, vrf_proof) = indra_crypto::vrf_prove(&vrf, &challenge);
        TestValidatorMaterial { seed, classical, pq, vrf, cold, validator_id,
            vrf_output: vrf_output.0.to_vec(), vrf_proof: vrf_proof.0 }
    }

    fn render_test_validator_record(name: &str, m: &TestValidatorMaterial, stake: u64) -> String {
        let cold_public = m.cold.public_key();
        let cold = cold_public.as_complete_hybrid();
        format!("\n[[validators]]\nname = \"{name}\"\nvalidator_id = \"{}\"\nstake = {stake}\nhybrid_classical_pk = \"{}\"\nhybrid_pq_pk = \"{}\"\nvrf_pk = \"{}\"\nvrf_possession_output = \"{}\"\nvrf_possession_proof = \"{}\"\ncold_hybrid_classical_pk = \"{}\"\ncold_hybrid_pq_pk = \"{}\"\ncold_key_version = 1\ncold_nonce = 0\n", hex::encode(m.validator_id), hex::encode(m.classical.public_key().0), hex::encode(m.pq.public_key().0), hex::encode(m.vrf.public_key()), hex::encode(&m.vrf_output), hex::encode(&m.vrf_proof), hex::encode(cold.classical.0), hex::encode(cold.pq.0))
    }

    fn make_strict_block(
        driver: &ConsensusDriver,
        proposer_seed: [u8; 32],
        round: u32,
        prev_qc_bytes: Vec<u8>,
    ) -> indra_core::types::block::BlockProposalVNext {
        let vrf = VrfKeypair::from_seed(&proposer_seed);
        let election = (round..MAX_ROUNDS_PER_HEIGHT)
            .find_map(|candidate_round| {
                let election = driver
                    .proposer_election_for_height(driver.height() + 1, candidate_round)
                    .ok()?;
                let candidate = election
                    .candidates
                    .iter()
                    .find(|candidate| candidate.vrf_pubkey == vrf.public_key())?;
                indra_consensus::proposer::compute_proposer_vrf(
                    candidate.validator_id,
                    &vrf,
                    &election,
                )
                .ok()?
                .eligible
                .then_some(election)
            })
            .expect("test proposer must become eligible within the bounded round search");
        let template = BlockTemplate {
            proposer_vrf_keypair: vrf,
            prev_qc_bytes,
            timestamp: 1_700_000_000 + driver.height() + 1,
            polc_round: None,
            transactions: vec![],
            slash_evidence: vec![],
            governance_ops: vec![],
            staking_ops: vec![],
        };
        let mut projected = driver.engine.state.clone();
        let block = produce_block(&template, &mut projected, &election).unwrap();
        let signer = HybridKeypair::new(
            ClassicalKeypair::from_seed(&proposer_seed),
            PqKeypair::from_seed(&proposer_seed).unwrap(),
        );
        let empty = indra_core::types::crypto::HybridSignature {
            classical_sig: VariableBytes::from_slice(&[]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[]).unwrap(),
        };
        let mut proposal = indra_core::types::block::BlockProposalVNext {
            block,
            proposer_authorization: empty,
        };
        let transcript = proposal.signing_bytes(TEST_CHAIN_ID.as_bytes()).unwrap();
        let signature = signer.sign(&transcript).unwrap();
        proposal.proposer_authorization = indra_core::types::crypto::HybridSignature {
            classical_sig: VariableBytes::from_slice(&signature.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&signature.pq.0).unwrap(),
        };
        proposal
    }

    fn verify_live_proposal(
        driver: &ConsensusDriver,
        proposal: &indra_core::types::block::BlockProposalVNext,
    ) -> Result<(), String> {
        let snapshot = driver
            .engine
            .state
            .snapshot_for_consensus_height(proposal.header.height)
            .map_err(|error| error.to_string())?;
        indra_core::types::proposal::verify_proposal(
            proposal,
            driver.engine.state.chain_id.as_bytes(),
            &driver.engine.state.election_seed,
            snapshot,
        )
        .map(|_| ())
        .map_err(|error| error.to_string())
    }

    fn process_single_validator_proposal(
        driver: &mut ConsensusDriver,
        proposal: indra_core::types::block::BlockProposalVNext,
    ) -> Vec<DriverAction> {
        // Deterministic test elections can require a later round. Model the
        // completed round-change that precedes delivery of that proposal; the
        // round-evidence protocol itself has dedicated adversarial tests.
        if proposal.header.proposer_round > driver.current_round() {
            driver
                .start_round(proposal.header.proposer_round)
                .expect("test proposal round must be legal");
        }
        let mut actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal,
        });
        actions.extend(driver.on_propose_timeout());
        actions
    }

    fn reauthorize_test_proposal(
        proposal: &mut indra_core::types::block::BlockProposalVNext,
        seed: [u8; 32],
        chain_id: &[u8],
    ) {
        let signer = HybridKeypair::new(
            ClassicalKeypair::from_seed(&seed),
            PqKeypair::from_seed(&seed).unwrap(),
        );
        let signature = signer
            .sign(&proposal.signing_bytes(chain_id).unwrap())
            .unwrap();
        proposal.proposer_authorization = indra_core::types::crypto::HybridSignature {
            classical_sig: VariableBytes::from_slice(&signature.classical.0).unwrap(),
            pq_sig: VariableBytes::from_slice(&signature.pq.0).unwrap(),
        };
    }

    fn election_for_round(driver: &ConsensusDriver, height: u64, round: u32) -> ProposerElection {
        driver.proposer_election_for_height(height, round).unwrap()
    }

    #[test]
    fn live_proposal_guard_uses_snapshot_when_live_active_set_is_empty() {
        let seed = [0xA3u8; 32];
        let (mut driver, dir) = local_driver(seed, "snapshot_live_proposer_guard");
        let valid = make_strict_block(&driver, seed, 0, vec![]);

        assert!(verify_live_proposal(&driver, &valid).is_ok());

        for validator_id in driver
            .engine
            .state
            .validators
            .active_validators()
            .map(|validator| validator.validator_id)
            .collect::<Vec<_>>()
        {
            driver
                .engine
                .state
                .validators
                .get_mut(&validator_id)
                .unwrap()
                .status = ValidatorStatus::Registered;
        }
        assert_eq!(driver.engine.state.validators.active_count(), 0);
        assert!(
            verify_live_proposal(&driver, &valid).is_ok(),
            "snapshot-authorized proposer must still verify after live demotion"
        );

        let mut invalid = valid;
        invalid.block.header.proposer_vrf_proof = VariableBytes::from_slice(&[0xA5; 32]).unwrap();
        assert!(
            verify_live_proposal(&driver, &invalid).is_err(),
            "invalid proposer proof must be checked, not skipped, when S(height) is nonempty"
        );

        driver.engine.state.consensus_snapshots.clear();
        assert!(verify_live_proposal(&driver, &invalid).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposal_verification_rejects_mismatched_transaction_set_root() {
        let seed = [0xA4u8; 32];
        let (driver, dir) = local_driver(seed, "mismatched_transaction_set_root");
        let mut proposal = make_strict_block(&driver, seed, 0, vec![]);
        proposal.block.header.mempool_set_root = Bytes32::from([0xFF; 32]);

        let error = verify_live_proposal(&driver, &proposal).unwrap_err();
        assert!(error.contains("transaction-set root mismatch"), "{error}");
        drop(driver);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn proposal_requires_both_hybrid_components_and_independent_vrf_validity() {
        let seed = [0xA4u8; 32];
        let (driver, dir) = local_driver(seed, "proposal_hybrid_and_vrf_independence");
        let valid = make_strict_block(&driver, seed, 0, vec![]);
        assert!(verify_live_proposal(&driver, &valid).is_ok());

        let mut bad_classical = valid.clone();
        let mut classical_bytes = bad_classical
            .proposer_authorization
            .classical_sig
            .as_slice()
            .to_vec();
        classical_bytes[0] ^= 1;
        bad_classical.proposer_authorization.classical_sig =
            VariableBytes::from_slice(&classical_bytes).unwrap();
        assert!(verify_live_proposal(&driver, &bad_classical).is_err());

        let mut bad_pq = valid.clone();
        let mut pq_bytes = bad_pq.proposer_authorization.pq_sig.as_slice().to_vec();
        pq_bytes[0] ^= 1;
        bad_pq.proposer_authorization.pq_sig = VariableBytes::from_slice(&pq_bytes).unwrap();
        assert!(verify_live_proposal(&driver, &bad_pq).is_err());

        let attacker = HybridKeypair::new(
            ClassicalKeypair::from_seed(&[0xF1; 32]),
            PqKeypair::from_seed(&[0xF2; 32]).unwrap(),
        );
        let attacker_signature = attacker
            .sign(
                &valid
                    .signing_bytes(driver.engine.state.chain_id.as_bytes())
                    .unwrap(),
            )
            .unwrap();
        let mut mixed = valid.clone();
        mixed.proposer_authorization.pq_sig =
            VariableBytes::from_slice(&attacker_signature.pq.0).unwrap();
        assert!(verify_live_proposal(&driver, &mixed).is_err());

        let mut forged_eligibility = valid.clone();
        let mut output_bytes = forged_eligibility
            .block
            .header
            .proposer_vrf_output
            .as_slice()
            .to_vec();
        output_bytes[63] ^= 1;
        forged_eligibility.block.header.proposer_vrf_output =
            VariableBytes::from_slice(&output_bytes).unwrap();
        assert!(verify_live_proposal(&driver, &forged_eligibility).is_err());

        let mut forged_entropy = valid.clone();
        let mut entropy_bytes = forged_entropy
            .block
            .header
            .value_entropy
            .vrf_output
            .as_slice()
            .to_vec();
        entropy_bytes[0] ^= 1;
        forged_entropy.block.header.value_entropy.vrf_output =
            VariableBytes::from_slice(&entropy_bytes).unwrap();
        reauthorize_test_proposal(
            &mut forged_entropy,
            seed,
            driver.engine.state.chain_id.as_bytes(),
        );
        assert!(verify_live_proposal(&driver, &forged_entropy).is_err());

        let mut tampered_content = valid.clone();
        tampered_content.block.header.timestamp ^= 1;
        assert!(verify_live_proposal(&driver, &tampered_content).is_err());

        let snapshot = driver
            .engine
            .state
            .snapshot_for_consensus_height(1)
            .unwrap();
        assert!(indra_core::types::proposal::verify_proposal(
            &valid,
            b"different-chain",
            &driver.engine.state.election_seed,
            snapshot,
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn local_vote_authorization_uses_snapshot_membership_after_registry_demotion() {
        let seed = [0xA5u8; 32];
        let (mut driver, dir) = local_driver(seed, "snapshot_local_vote_authority");
        let local_id = driver.engine.validator_id().unwrap();
        let snapshot = driver.engine.state.consensus_snapshots[0].clone();
        assert!(snapshot
            .entries()
            .iter()
            .any(|entry| entry.validator_id == local_id));
        driver
            .engine
            .state
            .validators
            .get_mut(&local_id)
            .unwrap()
            .status = ValidatorStatus::Registered;

        assert!(driver
            .engine
            .voter_authorized_for_height(u64::MAX, local_id)
            .unwrap());
        let actions = driver.sign_and_record_local_vote(1, 0, VoteStep::Prevote, Bytes32::ZERO);
        assert!(actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastVote(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_fixture_production_prevote_persists_vote_safety_record() {
        let (mut driver, dir) = local_driver([0xA7u8; 32], "audit_fixture_prevote_persistence");
        let safety_path = driver.engine.config.vote_safety_path();
        assert!(safety_path.parent().is_some_and(|parent| parent.exists()));
        let validator_id = driver.engine.validator_id().unwrap();
        let actions = driver.sign_and_record_local_vote(
            1,
            0,
            VoteStep::Prevote,
            Bytes32::ZERO,
        );
        assert!(actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastVote(_))));
        let store = VoteSafetyStore::open(&safety_path);
        assert!(matches!(store.load(), VoteSafetyLoadResult::Record(record) if record.height == 1 && record.round == 0 && record.step == VoteStep::Prevote as u8));
        assert_eq!(validator_id, driver.engine.validator_id().unwrap());
        drop(store);
        drop(driver);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_restart_conflicting_vote_reproducer_ordinary_height() {
        let seed = [0xA9u8; 32];
        let (mut driver, dir) = local_driver(seed, "audit_restart_conflict_ordinary");
        let config = driver.engine.config.clone();
        let first = driver.sign_and_record_local_vote(1, 0, VoteStep::Prevote, Bytes32::ZERO);
        assert!(first.iter().any(|action| matches!(action, DriverAction::BroadcastVote(_))));
        drop(driver);
        let engine = NodeEngine::init(config).unwrap();
        let store = VoteSafetyStore::open(engine.config.vote_safety_path());
        assert!(matches!(store.load(), VoteSafetyLoadResult::Record(record) if record.height == 1 && record.round == 0 && record.step == 0));
        let mut reopened = ConsensusDriver::new(engine, store);
        let second = reopened.sign_and_record_local_vote(1, 0, VoteStep::Prevote, Bytes32::from([1; 32]));
        assert!(!second.iter().any(|action| matches!(action, DriverAction::BroadcastVote(_))));
        drop(reopened);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_signing_boundary_rejects_future_round_before_persistence() {
        let (mut driver, dir) = local_driver([0xAAu8; 32], "audit_signing_boundary_round");
        let safety_path = driver.engine.config.vote_safety_path();
        let before = VoteSafetyStore::open(&safety_path).load();
        let actions = driver.sign_and_record_local_vote(1, 1, VoteStep::Prevote, Bytes32::ZERO);
        assert!(!actions.iter().any(|action| matches!(action, DriverAction::BroadcastVote(_))));
        assert_eq!(VoteSafetyStore::open(&safety_path).load(), before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn audit_harness_two_production_nodes_exchange_real_vote() {
        // Two independently opened production drivers exchange the exact
        // signed vote through a deterministic in-test scheduler queue.
        let (mut a, dir_a) = local_driver([0xC1; 32], "bridge_a");
        let (mut b, dir_b) = local_driver([0xC1; 32], "bridge_b");
        let source: SocketAddr = "127.0.0.1:10001".parse().unwrap();
        let actions = a.sign_and_record_local_vote(1, 0, VoteStep::Prevote, Bytes32::ZERO);
        let vote = actions
            .into_iter()
            .find_map(|action| match action {
                DriverAction::BroadcastVote(vote) => Some(vote),
                _ => None,
            })
            .expect("production signer must emit a vote");
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(vote);
        let delivered = queue.pop_front().expect("scheduler must deliver vote");
        let _ = b.process(DriverEvent::InboundVote {
            from: source,
            vote: delivered,
        });
        let _ = std::fs::remove_dir_all(dir_a);
        let _ = std::fs::remove_dir_all(dir_b);
    }

    struct TwoValidatorFixture {
        driver_a: ConsensusDriver,
        driver_b: ConsensusDriver,
        material_a: TestValidatorMaterial,
        material_b: TestValidatorMaterial,
        dir_a: PathBuf,
        dir_b: PathBuf,
    }

    fn shared_two_validator_fixture() -> TwoValidatorFixture {
        let a = test_validator_material([0xA1; 32]);
        let b = test_validator_material([0xB2; 32]);
        let (driver_a, dir_a) = local_driver(a.seed, "shared_a_seed");
        let original = std::fs::read_to_string(dir_a.join("genesis.toml")).unwrap();
        let original = original;
        drop(driver_a);
        let sealed = original + &render_test_validator_record("b", &b, 1_000_000)
            + &render_test_validator_record("c", &test_validator_material([0xC3; 32]), 1_000_000)
            + &render_test_validator_record("d", &test_validator_material([0xD4; 32]), 1_000_000);
        std::fs::write(dir_a.join("genesis.toml"), &sealed).unwrap();
        let dir_b = temp_dir("shared_b_seed");
        std::fs::create_dir_all(&dir_b).unwrap();
        std::fs::write(dir_b.join("genesis.toml"), &sealed).unwrap();
        let mut ca = NodeConfig::local_test(dir_a.clone());
        ca.genesis_path = Some(dir_a.join("genesis.toml").to_string_lossy().into());
        ca.validator_seed = Some(a.seed); ca.vrf_seed = Some(a.seed);
        ca.pq_seed = Some(a.pq.secret_key_bytes()); ca.pq_pk = Some(a.pq.public_key().0.to_vec());
        let mut cb = NodeConfig::local_test(dir_b.clone());
        cb.genesis_path = Some(dir_b.join("genesis.toml").to_string_lossy().into());
        cb.validator_seed = Some(b.seed); cb.vrf_seed = Some(b.seed);
        cb.pq_seed = Some(b.pq.secret_key_bytes()); cb.pq_pk = Some(b.pq.public_key().0.to_vec());
        let ea = NodeEngine::init(ca).unwrap(); let eb = NodeEngine::init(cb).unwrap();
        let vote_safety_path_a = ea.config.vote_safety_path();
        let vote_safety_path_b = eb.config.vote_safety_path();
        TwoValidatorFixture { driver_a: ConsensusDriver::new(ea, VoteSafetyStore::open(&vote_safety_path_a)), driver_b: ConsensusDriver::new(eb, VoteSafetyStore::open(&vote_safety_path_b)), material_a: a, material_b: b, dir_a, dir_b }
    }

    #[test]
    fn audit_fixture_shared_genesis_two_distinct_validators() {
        let a = test_validator_material([0xA1; 32]);
        let b = test_validator_material([0xB2; 32]);
        let manifest = crate::genesis::test_genesis_toml(
            "indra-testnet-1",
            &[(a.seed, a.seed, a.seed), (b.seed, b.seed, b.seed)],
        );
        assert!(crate::genesis::parse_genesis_manifest_str(&manifest).is_err());
    }

    struct FourValidatorFixture { drivers: Vec<ConsensusDriver>, materials: Vec<TestValidatorMaterial>, sealed_genesis: Vec<u8>, dirs: Vec<PathBuf>, vote_safety_paths: Vec<PathBuf> }

    fn shared_four_validator_fixture() -> FourValidatorFixture {
        let seeds = [[0x01; 32], [0x02; 32], [0x03; 32], [0x04; 32]];
        let materials: Vec<_> = seeds.into_iter().map(test_validator_material).collect();
        for i in 0..4 { for j in (i + 1)..4 { assert_ne!(materials[i].validator_id, materials[j].validator_id); } }
        let sealed = crate::genesis::test_genesis_toml(
            "indra-testnet-1",
            &seeds.map(|seed| (seed, seed, seed)),
        )
        .into_bytes();
        let mut drivers = Vec::new(); let mut dirs = Vec::new(); let mut safety = Vec::new();
        for (i, m) in materials.iter().enumerate() {
            let dir = temp_dir(&format!("shared_four_{i}")); std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("genesis.toml"), &sealed).unwrap();
            let mut cfg = NodeConfig::local_test(dir.clone()); cfg.genesis_path = Some(dir.join("genesis.toml").to_string_lossy().into()); cfg.validator_seed = Some(m.seed); cfg.vrf_seed = Some(m.seed); cfg.pq_seed = Some(m.pq.secret_key_bytes()); cfg.pq_pk = Some(m.pq.public_key().0.to_vec());
            let engine = NodeEngine::init(cfg).unwrap(); let path = engine.config.vote_safety_path(); safety.push(path.clone()); drivers.push(ConsensusDriver::new(engine, VoteSafetyStore::open(&path))); dirs.push(dir);
        }
        for i in 0..4 { assert_eq!(drivers[i].engine.validator_id(), Some(Bytes32::from(materials[i].validator_id))); assert_eq!(drivers[i].engine.state.genesis_fingerprint, drivers[0].engine.state.genesis_fingerprint); for m in &materials { assert!(drivers[i].engine.state.validators.get(&Bytes32::from(m.validator_id)).is_some()); } }
        for i in 0..4 { assert_eq!(std::fs::read(dirs[i].join("genesis.toml")).unwrap(), sealed); for j in (i + 1)..4 { assert_ne!(dirs[i], dirs[j]); assert_ne!(safety[i], safety[j]); } }
        let roots: Vec<_> = drivers.iter().map(|d| d.engine.state.snapshot_for_consensus_height(1).unwrap().snapshot_root).collect(); assert!(roots.iter().all(|r| *r == roots[0]));
        FourValidatorFixture { drivers, materials, sealed_genesis: sealed, dirs, vote_safety_paths: safety }
    }

    #[test]
    fn audit_fixture_shared_genesis_four_distinct_validators() {
        let fixture = shared_four_validator_fixture();
        for i in 0..4 { assert_eq!(fixture.drivers[i].engine.validator_id(), Some(Bytes32::from(fixture.materials[i].validator_id))); assert_eq!(fixture.drivers[i].engine.state.height, fixture.drivers[0].engine.state.height); assert_eq!(fixture.drivers[i].engine.state.tip_hash, fixture.drivers[0].engine.state.tip_hash); }
        let snapshot = fixture.drivers[0].engine.state.snapshot_for_consensus_height(1).unwrap();
        assert_eq!(snapshot.entries().len(), 4);
        let weights: Vec<_> = fixture.materials.iter().map(|m| snapshot.entry_with_position(&Bytes32::from(m.validator_id)).unwrap().1.consensus_weight_spark).collect();
        assert!(weights.iter().all(|w| *w == weights[0]));
        for i in 0..4 { for j in (i + 1)..4 { assert_ne!(fixture.dirs[i], fixture.dirs[j]); assert_ne!(fixture.vote_safety_paths[i], fixture.vote_safety_paths[j]); } assert_eq!(std::fs::read(fixture.dirs[i].join("genesis.toml")).unwrap(), fixture.sealed_genesis); }
        let dirs = fixture.dirs; drop(fixture.drivers); for dir in dirs { let _ = std::fs::remove_dir_all(dir); }
    }

    #[test]
    fn audit_harness_four_validators_accept_one_production_proposal() {
        let mut fixture = shared_four_validator_fixture();
        for d in &mut fixture.drivers { d.sync.mark_caught_up(d.height()); }
        let mut partition_round_1 = fixture.drivers[0].current_round();
        loop { let election = fixture.drivers[0].proposer_election_for_height(1, partition_round_1).unwrap(); if (0..4).any(|i| fixture.drivers[i].engine.is_proposer(&election)) { break; } for d in &mut fixture.drivers { let _=d.on_propose_timeout(); let _=d.on_prevote_timeout(); d.on_precommit_timeout().unwrap(); } partition_round_1 += 1; }
        let election = fixture.drivers[0].proposer_election_for_height(1, partition_round_1).unwrap();
        let eligible: Vec<_> = (0..4).filter(|i| fixture.drivers[*i].engine.is_proposer(&election)).collect();
        assert!(!eligible.is_empty());
        let proposer = *eligible.iter().min().unwrap();
        let proposal = fixture.drivers[proposer].engine.propose(&election, 1_700_000_000, vec![], None).unwrap();
        let hash = proposal.block.header.block_hash();
        let value_hash = proposal.block.header.value_hash;
        let proposer_id = proposal.block.header.proposer_id;
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(proposal.clone());
        let local = queue.pop_front().unwrap();
        fixture.drivers[proposer].process(DriverEvent::InboundBlock { from: None, proposal: local });
        assert!(fixture.drivers[proposer].pending_proposal(&hash).is_some());
        for i in 0..4 { if i != proposer { queue.push_back(proposal.clone()); let p = queue.pop_front().unwrap(); fixture.drivers[i].process(DriverEvent::InboundBlock { from: Some("127.0.0.1:12000".parse().unwrap()), proposal: p }); assert!(fixture.drivers[i].pending_proposal(&hash).is_some()); } assert_eq!(fixture.drivers[i].engine.state.height, 0); }
        assert_eq!(proposal.block.header.value_hash, value_hash); assert_eq!(proposal.block.header.proposer_id, proposer_id);
        let before = fixture.drivers[(proposer + 1) % 4].proposal_admission_metrics;
        fixture.drivers[(proposer + 1) % 4].process(DriverEvent::InboundBlock { from: Some("127.0.0.1:12000".parse().unwrap()), proposal: proposal.clone() });
        assert_eq!(fixture.drivers[(proposer + 1) % 4].proposal_admission_metrics, before);
        let dirs = fixture.dirs; drop(fixture.drivers); for dir in dirs { let _ = std::fs::remove_dir_all(dir); }
    }

    #[test]
    fn audit_harness_four_validator_strict_prevote_quorum_boundary() {
        let mut fixture = shared_four_validator_fixture();
        for d in &mut fixture.drivers { d.sync.mark_caught_up(d.height()); }
        let mut partition_round_1 = fixture.drivers[0].current_round();
        loop { let election = fixture.drivers[0].proposer_election_for_height(1, partition_round_1).unwrap(); if (0..4).any(|i| fixture.drivers[i].engine.is_proposer(&election)) { break; } for d in &mut fixture.drivers { let _=d.on_propose_timeout(); let _=d.on_prevote_timeout(); d.on_precommit_timeout().unwrap(); } partition_round_1 += 1; }
        let election = fixture.drivers[0].proposer_election_for_height(1, partition_round_1).unwrap();
        let proposer = (0..4).find(|i| fixture.drivers[*i].engine.is_proposer(&election)).unwrap();
        let proposal = fixture.drivers[proposer].engine.propose(&election, 1_700_000_000, vec![], None).unwrap();
        let hash = proposal.block.header.block_hash();
        for i in 0..4 { fixture.drivers[i].process(DriverEvent::InboundBlock { from: None, proposal: proposal.clone() }); }
        let mut votes = Vec::new();
        let ids: Vec<_> = fixture.drivers.iter().map(|d| d.engine.validator_id().unwrap()).collect();
        assert_eq!(ids.len(), 4); assert!(ids.iter().enumerate().all(|(i,id)| ids.iter().skip(i+1).all(|other| id != other)));
        for i in 0..3 { let actions = fixture.drivers[i].on_propose_timeout(); let vote = actions.into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a {Some(v)} else {None}).unwrap(); assert_eq!(vote.validator_id, ids[i]); assert_eq!((vote.height,vote.round,vote.step,vote.block_hash),(1,0,VoteStep::Prevote,hash)); votes.push(vote); }
        assert!(fixture.drivers[0].collector_has_vote_from(1,0,VoteStep::Prevote,ids[0]));
        assert_eq!(fixture.drivers[0].current_phase(), RoundPhase::Prevote);
        assert!(fixture.drivers[0].valid_round.is_none() && fixture.drivers[0].valid_value.is_none());
        assert!(fixture.drivers[0].locked_round.is_none() && fixture.drivers[0].locked_value.is_none());
        assert_eq!(fixture.drivers[0].last_qc_height(), None);
        assert!(fixture.drivers[0].locked_round.is_none());
        let b_actions = fixture.drivers[0].process(DriverEvent::InboundVote { from: "127.0.0.1:13001".parse().unwrap(), vote: votes[1].clone() });
        assert!(!matches!(fixture.drivers[0].vote_decision(1,0,VoteStep::Prevote), Some(VoteDecision::QuorumReached { .. })));
        assert!(b_actions.iter().all(|a| !matches!(a, DriverAction::BroadcastVote(v) if v.step == VoteStep::Precommit)));
        assert!(fixture.drivers[0].collector_has_vote_from(1,0,VoteStep::Prevote,ids[1]));
        assert!(!fixture.drivers[0].collector_has_vote_from(1,0,VoteStep::Prevote,ids[2]));
        assert!(!fixture.drivers[0].collector_has_vote_from(1,0,VoteStep::Prevote,ids[3]));
        assert!(fixture.drivers[0].valid_round.is_none() && fixture.drivers[0].valid_value.is_none());
        assert!(fixture.drivers[0].locked_round.is_none() && fixture.drivers[0].locked_value.is_none());
        assert_eq!(fixture.drivers[0].current_phase(), RoundPhase::Prevote);
        assert_eq!(fixture.drivers[0].engine.state.height, 0);
        let actions = fixture.drivers[0].process(DriverEvent::InboundVote { from: "127.0.0.1:13002".parse().unwrap(), vote: votes[2].clone() });
        match fixture.drivers[0].vote_decision(1,0,VoteStep::Prevote) { Some(VoteDecision::QuorumReached { block_hash, .. }) => assert_eq!(block_hash, hash), other => panic!("expected quorum, got {other:?}") }
        let precommits: Vec<_> = actions.iter().filter_map(|a| if let DriverAction::BroadcastVote(v)=a { if v.step == VoteStep::Precommit {Some(v)} else {None} } else {None}).collect();
        assert_eq!(precommits.len(), 1);
        assert_eq!((precommits[0].validator_id, precommits[0].height, precommits[0].round, precommits[0].step, precommits[0].block_hash), (ids[0],1,0,VoteStep::Precommit,hash));
        assert_eq!(fixture.drivers[0].current_phase(), RoundPhase::Precommit);
        assert_eq!(fixture.drivers[0].valid_round, Some(0));
        assert_eq!(fixture.drivers[0].valid_value, Some(hash));
        assert_eq!(fixture.drivers[0].locked_round, Some(0));
        assert_eq!(fixture.drivers[0].locked_value, Some(hash));
        assert_eq!(fixture.drivers[0].engine.state.height, 0);
        assert_eq!(fixture.drivers[0].last_qc_height(), None);
        let governing_root = governing_snapshot_root(&fixture.drivers[0], 1);
        let polc_ids: std::collections::HashSet<_> = fixture.drivers[0].locked_polc_votes.iter().map(|v| v.validator_id).collect();
        assert!(polc_ids.contains(&ids[0]) && polc_ids.contains(&ids[1]) && polc_ids.contains(&ids[2]) && !polc_ids.contains(&ids[3]));
        assert_eq!(polc_ids.len(), 3);
        for vote in &fixture.drivers[0].locked_polc_votes {
            assert_eq!(vote.height, 1);
            assert_eq!(vote.round, 0);
            assert_eq!(vote.step, VoteStep::Prevote);
            assert_eq!(vote.block_hash, hash);
            assert_eq!(vote.snapshot_root, governing_root);
        }
        let phase_before = fixture.drivers[0].current_phase(); let valid_before = fixture.drivers[0].valid_round; let value_before = fixture.drivers[0].valid_value; let lock_before = fixture.drivers[0].locked_round; let locked_value_before = fixture.drivers[0].locked_value; let polc_before = fixture.drivers[0].locked_polc_votes.clone(); let height_before = fixture.drivers[0].engine.state.height; let qc_before = fixture.drivers[0].last_qc_height(); let metrics_before = fixture.drivers[0].vote_admission_metrics;
        let replay = fixture.drivers[0].process(DriverEvent::InboundVote { from: "127.0.0.1:13002".parse().unwrap(), vote: votes[2].clone() });
        assert_eq!(fixture.drivers[0].current_phase(), phase_before);
        assert_eq!(fixture.drivers[0].valid_round, valid_before); assert_eq!(fixture.drivers[0].valid_value, value_before); assert_eq!(fixture.drivers[0].locked_round, lock_before); assert_eq!(fixture.drivers[0].locked_value, locked_value_before); assert_eq!(fixture.drivers[0].locked_polc_votes, polc_before); assert_eq!(fixture.drivers[0].engine.state.height, height_before); assert_eq!(fixture.drivers[0].last_qc_height(), qc_before); assert_eq!(fixture.drivers[0].vote_admission_metrics, metrics_before);
        assert!(replay.iter().all(|a| !matches!(a, DriverAction::BroadcastVote(v) if v.step == VoteStep::Precommit)));
        assert_eq!(fixture.drivers[0].engine.state.height, 0);
        let dirs = fixture.dirs; drop(fixture.drivers); for dir in dirs { let _ = std::fs::remove_dir_all(dir); }
    }

    #[test]
    fn audit_harness_four_validator_strict_precommit_quorum_finalizes() {
        let mut fixture = shared_four_validator_fixture();
        for d in &mut fixture.drivers { d.sync.mark_caught_up(d.height()); }
        let election = fixture.drivers[0].proposer_election_for_height(1, 0).unwrap();
        let proposer = (0..4).find(|i| fixture.drivers[*i].engine.is_proposer(&election)).unwrap();
        let proposal = fixture.drivers[proposer].engine.propose(&election, 1_700_000_000, vec![], None).unwrap();
        let hash = proposal.block.header.block_hash();
        for d in &mut fixture.drivers { d.process(DriverEvent::InboundBlock { from: None, proposal: proposal.clone() }); }
        let ids: Vec<_> = fixture.drivers.iter().map(|d| d.engine.validator_id().unwrap()).collect();
        let mut prevotes = Vec::new();
        for i in 0..3 {
            let actions = fixture.drivers[i].on_propose_timeout();
            prevotes.push(actions.into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a {Some(v)} else {None}).unwrap());
        }
        let mut precommits = Vec::new();
        for i in 0..3 {
            for j in 0..3 {
                if i != j {
                    let actions = fixture.drivers[i].process(DriverEvent::InboundVote { from: format!("127.0.0.1:{}", 14000+j).parse().unwrap(), vote: prevotes[j].clone() });
                    if let Some(v) = actions.into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a { (v.step == VoteStep::Precommit).then_some(v) } else {None}) { precommits.push((i, v)); }
                }
            }
        }
        precommits.sort_by_key(|(i, _)| *i);
        assert_eq!(precommits.len(), 3);
        for (i, v) in &precommits { assert_eq!(fixture.drivers[*i].current_phase(), RoundPhase::Precommit); assert_eq!((v.validator_id,v.height,v.round,v.step,v.block_hash),(ids[*i],1,0,VoteStep::Precommit,hash)); }
        let original_tip_hash = fixture.drivers[0].engine.state.tip_hash;
        let before = fixture.drivers[0].vote_admission_metrics.qc_formations;
        assert_eq!(fixture.drivers[0].engine.state.height, 0);
        fixture.drivers[0].process(DriverEvent::InboundVote { from: "127.0.0.1:14001".parse().unwrap(), vote: precommits[1].1.clone() });
        assert_eq!(fixture.drivers[0].engine.state.height, 0);
        assert_eq!(fixture.drivers[0].engine.state.tip_hash, original_tip_hash);
        assert_eq!(fixture.drivers[0].last_qc_height(), None);
        assert!(fixture.drivers[0].last_qc_bytes().is_empty());
        assert_eq!(fixture.drivers[0].vote_admission_metrics.qc_formations, before);
        assert!(fixture.drivers[0].collector_has_vote_from(1,0,VoteStep::Precommit,ids[0]));
        assert!(fixture.drivers[0].collector_has_vote_from(1,0,VoteStep::Precommit,ids[1]));
        assert!(!fixture.drivers[0].collector_has_vote_from(1,0,VoteStep::Precommit,ids[2]));
        assert!(!fixture.drivers[0].collector_has_vote_from(1,0,VoteStep::Precommit,ids[3]));
        assert!(!matches!(fixture.drivers[0].vote_decision(1,0,VoteStep::Precommit), Some(VoteDecision::QuorumReached { .. })));
        fixture.drivers[0].process(DriverEvent::InboundVote { from: "127.0.0.1:14002".parse().unwrap(), vote: precommits[2].1.clone() });
        assert_eq!(fixture.drivers[0].engine.state.height, 1);
        assert_eq!(fixture.drivers[0].engine.state.tip_hash, hash);
        assert_eq!(fixture.drivers[0].last_qc_height(), Some(1));
        assert!(!fixture.drivers[0].last_qc_bytes().is_empty());
        assert_eq!(fixture.drivers[0].vote_admission_metrics.qc_formations, before + 1);
        let qc = QuorumCertificateV1::decode_exact(&fixture.drivers[0].last_qc_bytes()).unwrap();
        assert_eq!((qc.height,qc.round,qc.block_hash),(1,0,hash));
        let snapshot = fixture.drivers[0].engine.state.snapshot_for_consensus_height(1).unwrap().clone();
        indra_core::types::qc::verify_qc_against_snapshot(&qc, &snapshot, TEST_CHAIN_ID).unwrap();
        let qc_signers: Vec<_> = snapshot.entries().iter().enumerate()
            .filter(|(i, _)| (qc.signer_bitfield[*i / 8] & (1u8 << (*i % 8))) != 0)
            .map(|(_, entry)| entry.validator_id)
            .collect();
        assert!(qc_signers.contains(&ids[0]));
        assert!(qc_signers.contains(&ids[1]));
        assert!(qc_signers.contains(&ids[2]));
        assert!(!qc_signers.contains(&ids[3]));
        let signer_weight: u64 = snapshot.entries().iter().enumerate()
            .filter(|(i, _)| (qc.signer_bitfield[*i / 8] & (1u8 << (*i % 8))) != 0)
            .map(|(_, entry)| entry.consensus_weight_spark).sum();
        let total_weight: u64 = snapshot.entries().iter().map(|entry| entry.consensus_weight_spark).sum();
        assert!(has_strict_two_thirds_quorum(signer_weight, total_weight));
        assert_eq!(fixture.drivers[0].current_round(), 0);
        assert_eq!(fixture.drivers[0].current_phase(), RoundPhase::Propose);
        assert!(fixture.drivers[0].locked_round.is_none() && fixture.drivers[0].locked_value.is_none() && fixture.drivers[0].locked_value_hash.is_none());
        assert!(fixture.drivers[0].locked_polc_votes.is_empty());
        assert!(fixture.drivers[0].valid_round.is_none() && fixture.drivers[0].valid_value.is_none() && fixture.drivers[0].valid_proposal.is_none());
        assert!(fixture.drivers[0].pending_proposal(&hash).is_none());
        let state_dir = fixture.drivers[0].engine.config.state_dir();
        assert_eq!(indra_storage::load_last_qc(&state_dir).unwrap(), Some(fixture.drivers[0].last_qc_bytes()));
        assert_eq!(indra_storage::load_pending_last_qc(&state_dir).unwrap(), None);
        assert!(matches!(fixture.drivers[0].vote_safety.load(), VoteSafetyLoadResult::NoRecord));
        let replay_height = fixture.drivers[0].engine.state.height;
        let replay_tip = fixture.drivers[0].engine.state.tip_hash;
        let replay_qc = fixture.drivers[0].last_qc_bytes();
        let replay_qch = fixture.drivers[0].last_qc_height();
        let replay_round = fixture.drivers[0].current_round();
        let replay_phase = fixture.drivers[0].current_phase();
        let replay_formations = fixture.drivers[0].vote_admission_metrics.qc_formations;
        fixture.drivers[0].process(DriverEvent::InboundVote { from: "127.0.0.1:14002".parse().unwrap(), vote: precommits[2].1.clone() });
        assert_eq!(fixture.drivers[0].engine.state.height, replay_height);
        assert_eq!(fixture.drivers[0].engine.state.tip_hash, replay_tip);
        assert_eq!(fixture.drivers[0].last_qc_bytes(), replay_qc);
        assert_eq!(fixture.drivers[0].last_qc_height(), replay_qch);
        assert_eq!(fixture.drivers[0].current_round(), replay_round);
        assert_eq!(fixture.drivers[0].current_phase(), replay_phase);
        assert_eq!(fixture.drivers[0].vote_admission_metrics.qc_formations, replay_formations);
        let dirs = fixture.dirs; drop(fixture.drivers); for dir in dirs { let _ = std::fs::remove_dir_all(dir); }
    }

    #[test]
    fn audit_harness_post_finalization_stale_and_conflicting_traffic_is_safe() {
        let mut fixture = shared_four_validator_fixture();
        for d in &mut fixture.drivers { d.sync.mark_caught_up(d.height()); }
        let election = fixture.drivers[0].proposer_election_for_height(1, 0).unwrap();
        let proposer = (0..4).find(|i| fixture.drivers[*i].engine.is_proposer(&election)).unwrap();
        let proposal = fixture.drivers[proposer].engine.propose(&election, 1_700_000_000, vec![], None).unwrap();
        let hash = proposal.block.header.block_hash();
        let alternate = fixture.drivers[proposer].engine.propose(&election, 1_700_000_001, vec![], None).unwrap();
        let alternate_hash = alternate.block.header.block_hash();
        assert_ne!(alternate_hash, hash);
        for d in &mut fixture.drivers { d.process(DriverEvent::InboundBlock { from: None, proposal: proposal.clone() }); }
        let ids: Vec<_> = fixture.drivers.iter().map(|d| d.engine.validator_id().unwrap()).collect();
        let mut prevotes = Vec::new();
        for i in 0..3 { prevotes.push(fixture.drivers[i].on_propose_timeout().into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a {Some(v)} else {None}).unwrap()); }
        let mut precommits = Vec::new();
        for i in 0..3 { for j in 0..3 { if i != j { let actions = fixture.drivers[i].process(DriverEvent::InboundVote { from: format!("127.0.0.1:{}",15000+j).parse().unwrap(), vote: prevotes[j].clone() }); if let Some(v)=actions.into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a {(v.step==VoteStep::Precommit).then_some(v)} else {None}) { precommits.push((i,v)); } } } }
        precommits.sort_by_key(|(i,_)|*i);
        fixture.drivers[0].process(DriverEvent::InboundVote { from: "127.0.0.1:15001".parse().unwrap(), vote: precommits[1].1.clone() });
        fixture.drivers[0].process(DriverEvent::InboundVote { from: "127.0.0.1:15002".parse().unwrap(), vote: precommits[2].1.clone() });
        let baseline = (fixture.drivers[0].engine.state.height, fixture.drivers[0].engine.state.tip_hash, fixture.drivers[0].last_qc_bytes(), fixture.drivers[0].last_qc_height(), fixture.drivers[0].current_round(), fixture.drivers[0].current_phase(), fixture.drivers[0].vote_admission_metrics.qc_formations);
        fixture.drivers[0].process(DriverEvent::InboundBlock { from: None, proposal: proposal.clone() });
        fixture.drivers[0].process(DriverEvent::InboundBlock { from: None, proposal: alternate });
        fixture.drivers[0].process(DriverEvent::InboundVote { from: "127.0.0.1:15000".parse().unwrap(), vote: prevotes[0].clone() });
        fixture.drivers[0].process(DriverEvent::InboundVote { from: "127.0.0.1:15002".parse().unwrap(), vote: precommits[2].1.clone() });
        let signer = HybridKeypair::new(ClassicalKeypair::from_seed(&fixture.materials[3].seed), fixture.materials[3].pq.clone());
        let conflicting = indra_consensus::vote::produce_vote(1, 0, VoteStep::Precommit, Bytes32([9u8;32]), ids[3], governing_snapshot_root(&fixture.drivers[0], 1), TEST_CHAIN_ID, &signer).unwrap();
        fixture.drivers[0].process(DriverEvent::InboundVote { from: "127.0.0.1:15003".parse().unwrap(), vote: conflicting });
        let after = (fixture.drivers[0].engine.state.height, fixture.drivers[0].engine.state.tip_hash, fixture.drivers[0].last_qc_bytes(), fixture.drivers[0].last_qc_height(), fixture.drivers[0].current_round(), fixture.drivers[0].current_phase(), fixture.drivers[0].vote_admission_metrics.qc_formations);
        assert_eq!(after, baseline);
        assert!(fixture.drivers[0].pending_proposal(&hash).is_none());
        assert!(fixture.drivers[0].pending_proposal(&alternate_hash).is_none());
        let dirs = fixture.dirs; drop(fixture.drivers); for dir in dirs { let _ = std::fs::remove_dir_all(dir); }
    }

    #[test]
    fn audit_harness_four_validators_converge_across_two_heights() {
        let mut fixture = shared_four_validator_fixture();
        for d in &mut fixture.drivers { d.sync.mark_caught_up(d.height()); }
        let ids: Vec<_> = fixture.drivers.iter().map(|d| d.engine.validator_id().unwrap()).collect();
        let mut height1_proposal = None;
        let mut height1_prevote = None;
        let mut height1_precommit = None;
        let mut height2_round = 0;
        let mut height1_hash = Bytes32::ZERO;
        for height in 1..=2 {
            loop {
                let round = fixture.drivers[0].current_round();
                let election = fixture.drivers[0].proposer_election_for_height(height, round).unwrap();
                if (0..4).any(|i| fixture.drivers[i].engine.is_proposer(&election)) { break; }
                assert!(round < MAX_ROUNDS_PER_HEIGHT - 1);
                let old_height = fixture.drivers[0].engine.state.height;
                let old_tip = fixture.drivers[0].engine.state.tip_hash;
                for d in &mut fixture.drivers {
                    let pv = d.on_propose_timeout().into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a {Some(v)} else {None}).unwrap();
                    assert_eq!((pv.height,pv.round,pv.step,pv.block_hash),(height,round,VoteStep::Prevote,Bytes32::ZERO));
                    let pc = d.on_prevote_timeout().into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a {Some(v)} else {None}).unwrap();
                    assert_eq!((pc.height,pc.round,pc.step,pc.block_hash),(height,round,VoteStep::Precommit,Bytes32::ZERO));
                    d.on_precommit_timeout().unwrap();
                }
                assert!(fixture.drivers.iter().all(|d| d.current_round() == round + 1 && d.current_phase() == RoundPhase::Propose));
                assert!(fixture.drivers.iter().all(|d| d.engine.state.height == old_height && d.engine.state.tip_hash == old_tip));
            }
            let election = fixture.drivers[0].proposer_election_for_height(height, fixture.drivers[0].current_round()).unwrap();
            if height == 2 {
                height2_round = fixture.drivers[0].current_round();
                assert!(height2_round < MAX_ROUNDS_PER_HEIGHT);
            }
            let proposer = (0..4).find(|i| fixture.drivers[*i].engine.is_proposer(&election)).unwrap_or_else(|| {
                panic!("no fixture validator eligible for height {height} round 0; ids={ids:?}")
            });
            let parent_qc = if height == 1 { vec![] } else { fixture.drivers[proposer].last_qc_bytes() };
            let proposal = fixture.drivers[proposer].engine.propose(&election, 1_700_000_000 + height, parent_qc, None).unwrap();
            let hash = proposal.block.header.block_hash();
            assert_eq!(proposal.block.header.height, height);
            assert_eq!(proposal.block.header.proposer_round, fixture.drivers[0].current_round());
            if height == 1 { height1_hash = hash; height1_proposal = Some(proposal.clone()); }
            if height == 2 { assert_eq!(proposal.block.header.prev_hash, fixture.drivers[0].engine.state.tip_hash); }
            if height == 2 {
                let qc = QuorumCertificateV1::decode_exact(proposal.block.header.quorum_certificate.as_slice()).unwrap();
                assert_eq!((qc.height, qc.block_hash), (1, height1_hash));
                let snap = fixture.drivers[0].engine.state.snapshot_for_consensus_height(1).unwrap().clone();
                indra_core::types::qc::verify_qc_against_snapshot(&qc, &snap, TEST_CHAIN_ID).unwrap();
            }
            for d in &mut fixture.drivers { d.process(DriverEvent::InboundBlock { from: None, proposal: proposal.clone() }); }
            let mut prevotes = Vec::new();
            for i in 0..4 { prevotes.push(fixture.drivers[i].on_propose_timeout().into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a {Some(v)} else {None}).unwrap()); }
            for v in &prevotes { assert_eq!((v.height,v.round,v.step,v.block_hash),(height,fixture.drivers[0].current_round(),VoteStep::Prevote,hash)); }
            if height == 1 { height1_prevote = Some(prevotes[0].clone()); }
            let mut precommits = Vec::new();
            for i in 0..4 { for j in 0..4 { if i != j { let actions = fixture.drivers[i].process(DriverEvent::InboundVote { from: format!("127.0.0.1:{}",16000+j).parse().unwrap(), vote: prevotes[j].clone() }); if let Some(v)=actions.into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a {(v.step==VoteStep::Precommit).then_some(v)} else {None}) { precommits.push((i,v)); } } } }
            precommits.sort_by_key(|(i,_)|*i);
            for (_, v) in &precommits { assert_eq!((v.height,v.round,v.step,v.block_hash),(height,fixture.drivers[0].current_round(),VoteStep::Precommit,hash)); }
            if height == 1 { height1_precommit = precommits.first().map(|(_,v)| v.clone()); }
            for i in 0..4 { for (j,v) in &precommits { if *j != i { fixture.drivers[i].process(DriverEvent::InboundVote { from: format!("127.0.0.1:{}",17000+j).parse().unwrap(), vote: v.clone() }); } } }
            for d in &fixture.drivers { assert_eq!(d.engine.state.height, height); assert_eq!(d.engine.state.tip_hash, hash); assert_eq!(d.last_qc_height(), Some(height)); }
        }
        let final_tip = fixture.drivers[0].engine.state.tip_hash;
        let height2_hash = final_tip;
        let canonical_roots = indra_state::compute_state_roots(&fixture.drivers[0].engine.state);
        for d in &fixture.drivers {
            assert_eq!(d.engine.state.height, 2); assert_eq!(d.engine.state.tip_hash, final_tip); assert_eq!(d.current_round(), 0); assert_eq!(d.current_phase(), RoundPhase::Propose); assert_eq!(d.last_qc_height(), Some(2));
            let roots = indra_state::compute_state_roots(&d.engine.state);
            assert_eq!(roots.state_root, canonical_roots.state_root);
            assert_eq!(roots.validator_set_root, canonical_roots.validator_set_root);
            assert!(d.locked_round.is_none() && d.locked_value.is_none() && d.locked_value_hash.is_none() && d.locked_polc_votes.is_empty() && d.valid_round.is_none() && d.valid_value.is_none() && d.valid_proposal.is_none());
            assert!(matches!(d.vote_safety.load(), VoteSafetyLoadResult::NoRecord));
            assert!(d.pending_proposal(&height1_hash).is_none() && d.pending_proposal(&height2_hash).is_none());
            let qc = QuorumCertificateV1::decode_exact(&d.last_qc_bytes()).unwrap();
            assert_eq!((qc.height, qc.round, qc.block_hash), (2, height2_round, height2_hash));
            let snap = d.engine.state.snapshot_for_consensus_height(2).unwrap().clone();
            indra_core::types::qc::verify_qc_against_snapshot(&qc, &snap, TEST_CHAIN_ID).unwrap();
        }
        let d0 = &mut fixture.drivers[0];
        let before_roots = indra_state::compute_state_roots(&d0.engine.state);
        let before = (d0.engine.state.height, d0.engine.state.tip_hash, before_roots.state_root, before_roots.validator_set_root, d0.last_qc_bytes(), d0.last_qc_height(), d0.current_round(), d0.current_phase(), d0.vote_admission_metrics.qc_formations);
        d0.process(DriverEvent::InboundBlock { from: None, proposal: height1_proposal.unwrap() });
        d0.process(DriverEvent::InboundVote { from: "127.0.0.1:18000".parse().unwrap(), vote: height1_prevote.unwrap() });
        d0.process(DriverEvent::InboundVote { from: "127.0.0.1:18001".parse().unwrap(), vote: height1_precommit.unwrap() });
        let after_roots = indra_state::compute_state_roots(&d0.engine.state);
        let after = (d0.engine.state.height, d0.engine.state.tip_hash, after_roots.state_root, after_roots.validator_set_root, d0.last_qc_bytes(), d0.last_qc_height(), d0.current_round(), d0.current_phase(), d0.vote_admission_metrics.qc_formations);
        assert_eq!(before, after);
        assert!(d0.pending_proposal(&height1_hash).is_none() && d0.pending_proposal(&height2_hash).is_none());
        let dirs = fixture.dirs; drop(fixture.drivers); for dir in dirs { let _ = std::fs::remove_dir_all(dir); }
        let _ = ids;
    }

    #[test]
    fn audit_harness_four_validator_partition_heal_converges() {
        let mut fixture = shared_four_validator_fixture();
        for d in &mut fixture.drivers { d.sync.mark_caught_up(d.height()); }
        let mut initial_round = fixture.drivers[0].current_round();
        loop { let e=fixture.drivers[0].proposer_election_for_height(1, initial_round).unwrap(); if (0..4).any(|i| fixture.drivers[i].engine.is_proposer(&e)) { break; } let h=fixture.drivers[0].engine.state.height; let t=fixture.drivers[0].engine.state.tip_hash; for d in &mut fixture.drivers { let _=d.on_propose_timeout(); let _=d.on_prevote_timeout(); d.on_precommit_timeout().unwrap(); } assert!(fixture.drivers.iter().all(|d| d.engine.state.height==h && d.engine.state.tip_hash==t && d.current_round()==initial_round+1 && d.current_phase()==RoundPhase::Propose)); initial_round+=1; }
        let election = fixture.drivers[0].proposer_election_for_height(1, initial_round).unwrap();
        let proposer = (0..4).find(|i| fixture.drivers[*i].engine.is_proposer(&election)).unwrap();
        let proposal = fixture.drivers[proposer].engine.propose(&election, 1_700_000_000, vec![], None).unwrap();
        let hash = proposal.block.header.block_hash();
        let partition_round_1 = proposal.block.header.proposer_round;
        for d in &mut fixture.drivers { d.process(DriverEvent::InboundBlock { from: None, proposal: proposal.clone() }); }
        let mut votes = Vec::new();
        for i in 0..4 { let v=fixture.drivers[i].on_propose_timeout().into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a {Some(v)} else {None}).unwrap(); assert_eq!((v.height,v.round,v.step,v.block_hash),(1,partition_round_1,VoteStep::Prevote,hash)); votes.push(v); }
        let partition = |a: usize, b: usize| (a < 2) == (b < 2);
        for to in 0..4 { for from in 0..4 { if from != to && partition(from,to) { fixture.drivers[to].process(DriverEvent::InboundVote { from: format!("127.0.0.1:{}",19000+from).parse().unwrap(), vote: votes[from].clone() }); } } }
        for d in &fixture.drivers { assert_eq!(d.engine.state.height,0); assert_eq!(d.last_qc_height(),None); assert!(d.valid_round.is_none() && d.locked_round.is_none()); }
        let mut partition_nil_precommit = None;
        for d in &mut fixture.drivers { let acts = d.on_prevote_timeout(); if partition_nil_precommit.is_none() { partition_nil_precommit = acts.into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a {Some(v)} else {None}); } d.on_precommit_timeout().unwrap(); }
        let nil = partition_nil_precommit.as_ref().unwrap(); assert_eq!((nil.height,nil.round,nil.step,nil.block_hash),(1,partition_round_1,VoteStep::Precommit,Bytes32::ZERO));
        assert!(fixture.drivers.iter().all(|d| d.engine.state.height == 0));
        // Keep the partition active for a second complete round, checking eligibility first.
        let partition_round_2 = fixture.drivers[0].current_round();
        let election2 = fixture.drivers[0].proposer_election_for_height(1, partition_round_2).unwrap();
        if let Some(p2) = (0..4).find(|i| fixture.drivers[*i].engine.is_proposer(&election2)) {
            let p = fixture.drivers[p2].engine.propose(&election2, 1_700_000_050, vec![], None).unwrap();
            let second_hash = p.block.header.block_hash();
            let side = p2 < 2;
            for i in 0..4 { if (i < 2) == side { fixture.drivers[i].process(DriverEvent::InboundBlock { from: None, proposal: p.clone() }); } }
            let members: Vec<_> = (0..4).filter(|i| (*i < 2) == side).collect();
            let mut side_votes = Vec::new();
            for i in &members { let v=fixture.drivers[*i].on_propose_timeout().into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a {Some(v)} else {None}).unwrap(); assert_eq!((v.height,v.round,v.step,v.block_hash),(1,partition_round_2,VoteStep::Prevote,second_hash)); side_votes.push((*i,v)); }
            for (to,_) in &side_votes { for (from,v) in &side_votes { if to != from { fixture.drivers[*to].process(DriverEvent::InboundVote { from: format!("127.0.0.1:{}",19500+from).parse().unwrap(), vote: v.clone() }); } } }
            for i in &members { assert!(!matches!(fixture.drivers[*i].vote_decision(1,partition_round_2,VoteStep::Prevote), Some(VoteDecision::QuorumReached { .. }))); }
        }
        for d in &mut fixture.drivers { let _=d.on_propose_timeout(); let _=d.on_prevote_timeout(); d.on_precommit_timeout().unwrap(); }
        assert!(fixture.drivers.iter().all(|d| d.engine.state.height == 0 && d.last_qc_height().is_none()));
        let mut round = fixture.drivers[0].current_round();
        loop { let election = fixture.drivers[0].proposer_election_for_height(1, round).unwrap(); if (0..4).any(|i| fixture.drivers[i].engine.is_proposer(&election)) { break; } for d in &mut fixture.drivers { let _=d.on_propose_timeout(); let _=d.on_prevote_timeout(); d.on_precommit_timeout().unwrap(); } round += 1; }
        let election = fixture.drivers[0].proposer_election_for_height(1, round).unwrap();
        let proposer = (0..4).find(|i| fixture.drivers[*i].engine.is_proposer(&election)).unwrap();
        let proposal = fixture.drivers[proposer].engine.propose(&election, 1_700_000_100 + round as u64, vec![], None).unwrap();
        let recovered_hash = proposal.block.header.block_hash();
        for d in &mut fixture.drivers { d.process(DriverEvent::InboundBlock { from: None, proposal: proposal.clone() }); }
        let mut pvs = Vec::new();
        for i in 0..4 { pvs.push(fixture.drivers[i].on_propose_timeout().into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a {Some(v)} else {None}).unwrap()); }
        let mut pcs = Vec::new();
        for i in 0..4 { for j in 0..4 { if i != j { let acts = fixture.drivers[i].process(DriverEvent::InboundVote { from: format!("127.0.0.1:{}",20000+j).parse().unwrap(), vote: pvs[j].clone() }); if let Some(v)=acts.into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a {(v.step==VoteStep::Precommit).then_some(v)} else {None}) { pcs.push((i,v)); } } } }
        pcs.sort_by_key(|(i,_)|*i);
        for i in 0..4 { for (j,v) in &pcs { if *j != i { fixture.drivers[i].process(DriverEvent::InboundVote { from: format!("127.0.0.1:{}",21000+j).parse().unwrap(), vote: v.clone() }); } } }
        let roots = indra_state::compute_state_roots(&fixture.drivers[0].engine.state);
        for d in &fixture.drivers { assert_eq!(d.engine.state.height,1); assert_eq!(d.engine.state.tip_hash,recovered_hash); assert_eq!(d.current_round(), 0); assert_eq!(d.current_phase(), RoundPhase::Propose); assert_eq!(d.last_qc_height(),Some(1)); let r=indra_state::compute_state_roots(&d.engine.state); assert_eq!(r.state_root,roots.state_root); assert_eq!(r.validator_set_root,roots.validator_set_root); let qc=QuorumCertificateV1::decode_exact(&d.last_qc_bytes()).unwrap(); assert_eq!((qc.height,qc.block_hash),(1,recovered_hash)); let snap=d.engine.state.snapshot_for_consensus_height(1).unwrap().clone(); indra_core::types::qc::verify_qc_against_snapshot(&qc,&snap,TEST_CHAIN_ID).unwrap(); }
        let a = &mut fixture.drivers[0]; let before_roots=indra_state::compute_state_roots(&a.engine.state); let before=(a.engine.state.height,a.engine.state.tip_hash,before_roots.state_root,before_roots.validator_set_root,a.last_qc_bytes(),a.last_qc_height(),a.current_round(),a.current_phase(),a.vote_admission_metrics.qc_formations); a.process(DriverEvent::InboundVote{from:"127.0.0.1:19000".parse().unwrap(),vote:votes[0].clone()}); a.process(DriverEvent::InboundVote{from:"127.0.0.1:19001".parse().unwrap(),vote:partition_nil_precommit.clone().unwrap()}); let after_roots=indra_state::compute_state_roots(&a.engine.state); let after=(a.engine.state.height,a.engine.state.tip_hash,after_roots.state_root,after_roots.validator_set_root,a.last_qc_bytes(),a.last_qc_height(),a.current_round(),a.current_phase(),a.vote_admission_metrics.qc_formations); assert_eq!(before,after);
        let dirs = fixture.dirs; drop(fixture.drivers); for dir in dirs { let _ = std::fs::remove_dir_all(dir); }
        let _ = (hash, partition, partition_nil_precommit.clone());
    }

    #[test]
    fn audit_harness_four_validator_gst_delayed_delivery_recovers() {
        let mut fixture = shared_four_validator_fixture();
        for d in &mut fixture.drivers { d.sync.mark_caught_up(d.height()); }
        let genesis_tip = fixture.drivers[0].engine.state.tip_hash;
        const MAX_POST_GST_DELIVERY_STEPS: u64 = 2;
        let mut post_gst = false;
        let mut round = 0;
        loop { let e=fixture.drivers[0].proposer_election_for_height(1,round).unwrap(); if (0..4).any(|i| fixture.drivers[i].engine.is_proposer(&e)) { break; } for d in &mut fixture.drivers { let _=d.on_propose_timeout(); let _=d.on_prevote_timeout(); d.on_precommit_timeout().unwrap(); } round+=1; }
        let election=fixture.drivers[0].proposer_election_for_height(1,round).unwrap(); let proposer=(0..4).find(|i| fixture.drivers[*i].engine.is_proposer(&election)).unwrap(); let proposal=fixture.drivers[proposer].engine.propose(&election,1_700_000_000,vec![],None).unwrap(); let _initial_hash=proposal.block.header.block_hash();
        assert!(!post_gst);
        let delayed_proposal = proposal.clone();
        for i in 0..2 { fixture.drivers[i].process(DriverEvent::InboundBlock{from:None,proposal:proposal.clone()}); }
        let mut old_prevote=None; let mut old_precommit=None;
        for i in 0..4 { let p=fixture.drivers[i].on_propose_timeout().into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a{Some(v)}else{None}); if old_prevote.is_none(){old_prevote=p;} let pc=fixture.drivers[i].on_prevote_timeout().into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a{Some(v)}else{None}); if old_precommit.is_none(){old_precommit=pc;} fixture.drivers[i].on_precommit_timeout().unwrap(); }
        assert!(fixture.drivers.iter().all(|d| d.engine.state.height==0 && d.engine.state.tip_hash==genesis_tip && d.last_qc_height().is_none()));
        let round2=fixture.drivers[0].current_round(); let e2=fixture.drivers[0].proposer_election_for_height(1,round2).unwrap();
        if let Some(p2)=(0..4).find(|i| fixture.drivers[*i].engine.is_proposer(&e2)){ let p=fixture.drivers[p2].engine.propose(&e2,1_700_000_050,vec![],None).unwrap(); let h=p.block.header.block_hash(); for i in 0..2{fixture.drivers[i].process(DriverEvent::InboundBlock{from:None,proposal:p.clone()}); let v=fixture.drivers[i].on_propose_timeout().into_iter().find_map(|a|if let DriverAction::BroadcastVote(v)=a{Some(v)}else{None}).unwrap(); assert_eq!((v.height,v.round,v.step,v.block_hash),(1,round2,VoteStep::Prevote,h));} }
        for i in 0..4 { let _=fixture.drivers[i].on_propose_timeout(); let _=fixture.drivers[i].on_prevote_timeout(); fixture.drivers[i].on_precommit_timeout().unwrap(); }
        assert!(fixture.drivers.iter().all(|d| d.engine.state.height==0 && d.engine.state.tip_hash==genesis_tip && d.last_qc_height().is_none()));
        let stale_before=(fixture.drivers[3].engine.state.height,fixture.drivers[3].engine.state.tip_hash,fixture.drivers[3].current_round(),fixture.drivers[3].last_qc_height(),fixture.drivers[3].locked_round,fixture.drivers[3].locked_value,fixture.drivers[3].valid_round,fixture.drivers[3].valid_value);
        fixture.drivers[3].process(DriverEvent::InboundBlock{from:None,proposal:delayed_proposal.clone()});
        let stale_after=(fixture.drivers[3].engine.state.height,fixture.drivers[3].engine.state.tip_hash,fixture.drivers[3].current_round(),fixture.drivers[3].last_qc_height(),fixture.drivers[3].locked_round,fixture.drivers[3].locked_value,fixture.drivers[3].valid_round,fixture.drivers[3].valid_value); assert_eq!(stale_before,stale_after);
        assert!(!post_gst); post_gst=true; assert!(post_gst); let mut delivery_step=0u64; let mut post_gst_emitted_messages=0usize; let mut post_gst_delivered_broadcasts=0usize;
        round = fixture.drivers[0].current_round();
        loop {
            let e=fixture.drivers[0].proposer_election_for_height(1,round).unwrap(); if (0..4).any(|i| fixture.drivers[i].engine.is_proposer(&e)) { break; }
            let mut nil_prevotes=Vec::new(); for i in 0..4 { let v=fixture.drivers[i].on_propose_timeout().into_iter().find_map(|a|if let DriverAction::BroadcastVote(v)=a{Some(v)}else{None}).unwrap(); let emitted=delivery_step; post_gst_emitted_messages+=1; nil_prevotes.push((i,v,emitted)); }
            let delivered=delivery_step+1; let mut nil_precommits=Vec::new(); for (j,v,emitted) in &nil_prevotes { assert!(delivered-*emitted<=MAX_POST_GST_DELIVERY_STEPS); for i in 0..4 { if i!=*j { let acts=fixture.drivers[i].process(DriverEvent::InboundVote{from:format!("127.0.0.1:{}",22100+j).parse().unwrap(),vote:v.clone()}); if let Some(pc)=acts.into_iter().find_map(|a|if let DriverAction::BroadcastVote(v)=a{Some(v)}else{None}) { post_gst_emitted_messages+=1; nil_precommits.push((i,pc,delivered)); } } } post_gst_delivered_broadcasts+=1; } delivery_step=delivered;
            let delivered=delivery_step+1; for (j,v,emitted) in &nil_precommits { assert!(delivered-*emitted<=MAX_POST_GST_DELIVERY_STEPS); for i in 0..4 { if i!=*j { fixture.drivers[i].process(DriverEvent::InboundVote{from:format!("127.0.0.1:{}",22200+j).parse().unwrap(),vote:v.clone()}); } } post_gst_delivered_broadcasts+=1; } delivery_step=delivered;
            for d in &mut fixture.drivers { let _=d.on_prevote_timeout(); d.on_precommit_timeout().unwrap(); } round+=1;
        }
        let recovery_election = fixture.drivers[0].proposer_election_for_height(1, round).unwrap();
        let recovery_proposer=(0..4).find(|i| fixture.drivers[*i].engine.is_proposer(&recovery_election)).unwrap();
        let recovery_proposal=fixture.drivers[recovery_proposer].engine.propose(&recovery_election,1_700_000_100,vec![],None).unwrap();
        let hash=recovery_proposal.block.header.block_hash();
        let emitted_step=delivery_step; post_gst_emitted_messages+=1; delivery_step+=1; assert!(delivery_step-emitted_step<=MAX_POST_GST_DELIVERY_STEPS); for d in &mut fixture.drivers { d.process(DriverEvent::InboundBlock{from:None,proposal:recovery_proposal.clone()}); } post_gst_delivered_broadcasts+=1;
        let mut votes=Vec::new(); for i in 0..4 { let v=fixture.drivers[i].on_propose_timeout().into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a{Some(v)}else{None}).unwrap(); post_gst_emitted_messages+=1; votes.push((i,v,delivery_step)); }
        let mut pcs=Vec::new(); let delivered_step=delivery_step+1; for (j,v,emitted) in &votes { assert!(delivered_step-*emitted<=MAX_POST_GST_DELIVERY_STEPS); for i in 0..4 { if i!=*j { let acts=fixture.drivers[i].process(DriverEvent::InboundVote{from:format!("127.0.0.1:{}",22000+j).parse().unwrap(),vote:v.clone()}); if let Some(pc)=acts.into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a {(v.step==VoteStep::Precommit).then_some(v)}else{None}){post_gst_emitted_messages+=1; pcs.push((i,pc,delivered_step));} } } post_gst_delivered_broadcasts+=1; } delivery_step=delivered_step;
        pcs.sort_by_key(|(i,_,_)|*i); let delivered_step=delivery_step+1; for (j,v,emitted) in &pcs { assert!(delivered_step-*emitted<=MAX_POST_GST_DELIVERY_STEPS); for i in 0..4 { if *j!=i { fixture.drivers[i].process(DriverEvent::InboundVote{from:format!("127.0.0.1:{}",23000+j).parse().unwrap(),vote:v.clone()}); } } post_gst_delivered_broadcasts+=1; } delivery_step=delivered_step; assert!(delivery_step > 0); assert_eq!(post_gst_emitted_messages,post_gst_delivered_broadcasts);
        let roots=indra_state::compute_state_roots(&fixture.drivers[0].engine.state); for d in &fixture.drivers { assert_eq!(d.engine.state.height,1); assert_eq!(d.engine.state.tip_hash,hash); assert_eq!(d.current_round(),0); assert_eq!(d.current_phase(),RoundPhase::Propose); assert_eq!(d.last_qc_height(),Some(1)); let r=indra_state::compute_state_roots(&d.engine.state); assert_eq!(r.state_root,roots.state_root); assert_eq!(r.validator_set_root,roots.validator_set_root); let qc=QuorumCertificateV1::decode_exact(&d.last_qc_bytes()).unwrap(); assert_eq!((qc.height,qc.round,qc.block_hash),(1,round,hash)); let s=d.engine.state.snapshot_for_consensus_height(1).unwrap().clone(); indra_core::types::qc::verify_qc_against_snapshot(&qc,&s,TEST_CHAIN_ID).unwrap(); }
        let a=&mut fixture.drivers[0]; let rb=indra_state::compute_state_roots(&a.engine.state); let before=(a.engine.state.height,a.engine.state.tip_hash,rb.state_root,rb.validator_set_root,a.last_qc_bytes(),a.last_qc_height(),a.current_round(),a.current_phase(),a.vote_admission_metrics.qc_formations); a.process(DriverEvent::InboundBlock{from:None,proposal:delayed_proposal}); a.process(DriverEvent::InboundVote{from:"127.0.0.1:24000".parse().unwrap(),vote:old_prevote.unwrap()}); a.process(DriverEvent::InboundVote{from:"127.0.0.1:24001".parse().unwrap(),vote:old_precommit.unwrap()}); let ra=indra_state::compute_state_roots(&a.engine.state); let after=(a.engine.state.height,a.engine.state.tip_hash,ra.state_root,ra.validator_set_root,a.last_qc_bytes(),a.last_qc_height(),a.current_round(),a.current_phase(),a.vote_admission_metrics.qc_formations); assert_eq!(before,after); assert!(a.pending_proposal(&_initial_hash).is_none()); assert!(a.locked_round.is_none()&&a.locked_value.is_none()&&a.valid_round.is_none()&&a.valid_value.is_none());
        let dirs=fixture.dirs; drop(fixture.drivers); for dir in dirs { let _=std::fs::remove_dir_all(dir); }
    }

    #[test]
    fn audit_harness_four_validator_restart_storm_recovers_safely() {
        let mut fixture = shared_four_validator_fixture();
        for driver in &mut fixture.drivers {
            driver.sync.mark_caught_up(driver.height());
        }
        let genesis_tip = fixture.drivers[0].engine.state.tip_hash;
        let ids: Vec<_> = fixture
            .materials
            .iter()
            .map(|material| Bytes32::from(material.validator_id))
            .collect();

        let (initial_round, election, proposer) = loop {
            let round = fixture.drivers[0].current_round();
            assert!(fixture
                .drivers
                .iter()
                .all(|driver| driver.current_round() == round
                    && driver.current_phase() == RoundPhase::Propose));
            let election = fixture.drivers[0]
                .proposer_election_for_height(1, round)
                .unwrap();
            if let Some(proposer) = (0..4)
                .find(|index| fixture.drivers[*index].engine.is_proposer(&election))
            {
                break (round, election, proposer);
            }
            for driver in &mut fixture.drivers {
                let _ = driver.on_propose_timeout();
                let _ = driver.on_prevote_timeout();
                driver.on_precommit_timeout().unwrap();
                assert_eq!(driver.engine.state.height, 0);
                assert_eq!(driver.engine.state.tip_hash, genesis_tip);
                assert_eq!(driver.last_qc_height(), None);
            }
        };
        assert!(fixture.drivers[proposer].engine.is_proposer(&election));
        let proposal = fixture.drivers[proposer]
            .engine
            .propose(
                &election,
                1_700_000_000 + u64::from(initial_round),
                vec![],
                None,
            )
            .unwrap();
        let original_hash = proposal.block.header.block_hash();
        let original_value_hash = proposal.block.header.value_hash;
        let snapshot = fixture.drivers[0]
            .engine
            .state
            .snapshot_for_consensus_height(1)
            .unwrap()
            .clone();
        for driver in &mut fixture.drivers {
            driver.process(DriverEvent::InboundBlock {
                from: None,
                proposal: proposal.clone(),
            });
            assert!(driver.pending_proposal(&original_hash).is_some());
        }

        let mut original_prevotes = Vec::new();
        for (index, driver) in fixture.drivers.iter_mut().enumerate() {
            let vote = driver
                .on_propose_timeout()
                .into_iter()
                .find_map(|action| match action {
                    DriverAction::BroadcastVote(vote) => Some(vote),
                    _ => None,
                })
                .unwrap();
            assert_eq!(
                (
                    vote.validator_id,
                    vote.height,
                    vote.round,
                    vote.step,
                    vote.block_hash,
                    vote.snapshot_root,
                ),
                (
                    ids[index],
                    1,
                    initial_round,
                    VoteStep::Prevote,
                    original_hash,
                    snapshot.snapshot_root,
                )
            );
            original_prevotes.push(vote);
        }

        let restart = |drivers: &mut Vec<ConsensusDriver>, index: usize| {
            let old = drivers.remove(index);
            let config = old.engine.config.clone();
            drop(old);
            let engine = NodeEngine::init(config).unwrap();
            let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
            let mut restarted = ConsensusDriver::new(engine, vote_safety);
            restarted.sync.mark_caught_up(restarted.height());
            drivers.insert(index, restarted);
        };
        let no_broadcast_vote = |actions: &[DriverAction]| {
            !actions
                .iter()
                .any(|action| matches!(action, DriverAction::BroadcastVote(_)))
        };
        let conflicting_hash = Bytes32::from([0xEE; 32]);
        assert_ne!(conflicting_hash, original_hash);

        // A crashes after its prevote but before receiving a PoLC, and then
        // crashes a second time at the same height. Both reopenings must skip
        // the persisted signing slot without inventing a lock.
        restart(&mut fixture.drivers, 0);
        assert_eq!(fixture.drivers[0].engine.state.height, 0);
        assert_eq!(fixture.drivers[0].current_round(), initial_round + 1);
        assert_eq!(fixture.drivers[0].current_phase(), RoundPhase::Propose);
        assert!(fixture.drivers[0].locked_round.is_none());
        assert!(fixture.drivers[0].locked_value.is_none());
        assert!(fixture.drivers[0].locked_value_hash.is_none());
        assert!(fixture.drivers[0].locked_polc_votes.is_empty());
        assert!(fixture.drivers[0].valid_round.is_none());
        assert!(fixture.drivers[0].valid_value.is_none());
        let VoteSafetyLoadResult::Record(a_record) = fixture.drivers[0].vote_safety.load() else {
            panic!("A's prevote safety record did not survive restart")
        };
        assert_eq!((a_record.height, a_record.round, a_record.step), (1, initial_round, 0));
        assert!(a_record.consensus_lock.is_none());
        assert!(no_broadcast_vote(&fixture.drivers[0].sign_and_record_local_vote(
            1,
            initial_round,
            VoteStep::Prevote,
            conflicting_hash,
        )));
        restart(&mut fixture.drivers, 0);
        assert_eq!(fixture.drivers[0].engine.state.height, 0);
        assert_eq!(fixture.drivers[0].current_round(), initial_round + 1);
        assert_eq!(fixture.drivers[0].current_phase(), RoundPhase::Propose);
        assert!(fixture.drivers[0].locked_round.is_none());
        assert!(fixture.drivers[0].locked_value.is_none());
        assert!(fixture.drivers[0].locked_value_hash.is_none());
        assert!(fixture.drivers[0].locked_polc_votes.is_empty());
        assert!(fixture.drivers[0].valid_round.is_none());
        assert!(fixture.drivers[0].valid_value.is_none());
        let VoteSafetyLoadResult::Record(a_record_again) =
            fixture.drivers[0].vote_safety.load()
        else {
            panic!("A's prevote safety record did not survive its second restart")
        };
        assert_eq!(
            (a_record_again.height, a_record_again.round, a_record_again.step),
            (1, initial_round, 0)
        );
        assert!(a_record_again.consensus_lock.is_none());
        assert!(no_broadcast_vote(&fixture.drivers[0].sign_and_record_local_vote(
            1,
            initial_round,
            VoteStep::Precommit,
            conflicting_hash,
        )));

        // B, C, and D remain in the original round. Give each exactly the two
        // remote prevotes needed in addition to its own vote for a real 3/4
        // PoLC. This produces their normal non-nil production precommits but
        // deliberately does not distribute any precommit yet.
        let quorum_sources = [[0usize, 2usize], [0, 1], [0, 1]];
        let mut original_precommits: Vec<Option<VoteV1>> = vec![None; 4];
        for (offset, receiver) in (1usize..4).enumerate() {
            for source in quorum_sources[offset] {
                let actions = fixture.drivers[receiver].process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 25000 + source)
                        .parse()
                        .unwrap(),
                    vote: original_prevotes[source].clone(),
                });
                if let Some(precommit) = actions.into_iter().find_map(|action| match action {
                    DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Precommit => {
                        Some(vote)
                    }
                    _ => None,
                }) {
                    original_precommits[receiver] = Some(precommit);
                }
            }
            let driver = &fixture.drivers[receiver];
            assert_eq!(driver.current_phase(), RoundPhase::Precommit);
            assert_eq!(driver.locked_round, Some(initial_round));
            assert_eq!(driver.locked_value, Some(original_hash));
            assert_eq!(driver.locked_value_hash, Some(original_value_hash));
            assert_eq!(driver.valid_round, Some(initial_round));
            assert_eq!(driver.valid_value, Some(original_hash));
            assert!(driver.locked_polc_votes.len() >= 3);
            assert!(original_precommits[receiver].is_some());
            assert_eq!(driver.engine.state.height, 0);
            assert_eq!(driver.last_qc_height(), None);
        }
        let old_precommit = original_precommits[2].clone().unwrap();

        // B restarts with a lock; C restarts after its precommit. The fresh
        // production drivers must independently verify and restore the same
        // durable proposal and PoLC before participating again.
        for index in [1usize, 2] {
            restart(&mut fixture.drivers, index);
            let driver = &fixture.drivers[index];
            assert_eq!(driver.engine.state.height, 0);
            assert_eq!(driver.current_round(), initial_round + 1);
            assert_eq!(driver.current_phase(), RoundPhase::Propose);
            assert_eq!(driver.locked_round, Some(initial_round));
            assert_eq!(driver.locked_value, Some(original_hash));
            assert_eq!(driver.locked_value_hash, Some(original_value_hash));
            assert_eq!(driver.valid_round, Some(initial_round));
            assert_eq!(driver.valid_value, Some(original_hash));
            assert_eq!(driver.locked_polc_votes.len(), 3);
            let VoteSafetyLoadResult::Record(record) = driver.vote_safety.load() else {
                panic!("locked vote-safety record did not survive restart")
            };
            assert_eq!((record.height, record.round, record.step), (1, initial_round, 1));
            let lock = record.consensus_lock.unwrap();
            assert_eq!(
                (lock.height, lock.round, lock.block_hash, lock.value_hash),
                (1, initial_round, original_hash, original_value_hash)
            );
            assert_eq!(lock.proposal.block.header.block_hash(), original_hash);
            assert_eq!(lock.polc_votes, driver.locked_polc_votes);
            let mut collector = VoteCollector::new(
                1,
                initial_round,
                VoteStep::Prevote,
                driver.engine.state.chain_id.clone(),
                snapshot.snapshot_root,
                driver.registered_voters.clone(),
            );
            for vote in &lock.polc_votes {
                assert_eq!(
                    (vote.height, vote.round, vote.step, vote.block_hash, vote.snapshot_root),
                    (
                        1,
                        initial_round,
                        VoteStep::Prevote,
                        original_hash,
                        snapshot.snapshot_root,
                    )
                );
                collector.add_vote(vote.clone()).unwrap();
            }
            assert!(matches!(
                collector.current_decision(),
                VoteDecision::QuorumReached { block_hash, .. } if block_hash == original_hash
            ));
        }
        for index in [1usize, 2] {
            assert!(no_broadcast_vote(&fixture.drivers[index].sign_and_record_local_vote(
                1,
                initial_round,
                VoteStep::Prevote,
                conflicting_hash,
            )));
            assert!(no_broadcast_vote(&fixture.drivers[index].sign_and_record_local_vote(
                1,
                initial_round,
                VoteStep::Precommit,
                conflicting_hash,
            )));
            assert!(no_broadcast_vote(&fixture.drivers[index].sign_and_record_local_vote(
                1,
                initial_round.saturating_sub(1),
                VoteStep::Prevote,
                conflicting_hash,
            )));
        }

        // D did not restart and is still in Precommit at the original round.
        // Its normal timeout brings it to the same safe round as A/B/C.
        fixture.drivers[3].on_precommit_timeout().unwrap();
        assert!(fixture.drivers.iter().all(|driver| {
            driver.current_round() == initial_round + 1
                && driver.current_phase() == RoundPhase::Propose
                && driver.engine.state.height == 0
        }));

        // Re-deliver the genuine original proposal and PoLC through normal
        // inbound paths. This reconstructs old-round evidence in volatile
        // collectors without changing the lock directly.
        for driver in &mut fixture.drivers {
            driver.process(DriverEvent::InboundBlock {
                from: None,
                proposal: proposal.clone(),
            });
            for (source, vote) in original_prevotes.iter().take(3).enumerate() {
                driver.process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 25200 + source)
                        .parse()
                        .unwrap(),
                    vote: vote.clone(),
                });
            }
            assert_eq!(driver.valid_round, Some(initial_round));
            assert_eq!(driver.valid_value, Some(original_hash));
            assert!(driver.take_valid_block_for_reproposal().is_some());
        }

        // Advance only through production timeouts until an actual fixture
        // validator is eligible, then re-propose the locked value with its
        // verified PoLC round.
        let (recovery_round, recovery_election, recovery_proposer) = loop {
            let round = fixture.drivers[0].current_round();
            assert!(fixture
                .drivers
                .iter()
                .all(|driver| driver.current_round() == round
                    && driver.current_phase() == RoundPhase::Propose));
            let election = fixture.drivers[0]
                .proposer_election_for_height(1, round)
                .unwrap();
            if let Some(proposer) = (0..4)
                .find(|index| fixture.drivers[*index].engine.is_proposer(&election))
            {
                break (round, election, proposer);
            }
            for driver in &mut fixture.drivers {
                let _ = driver.on_propose_timeout();
                let _ = driver.on_prevote_timeout();
                driver.on_precommit_timeout().unwrap();
                assert_eq!(driver.engine.state.height, 0);
                assert_eq!(driver.engine.state.tip_hash, genesis_tip);
                assert_eq!(driver.last_qc_height(), None);
            }
        };
        let (valid_block, valid_round) = fixture.drivers[recovery_proposer]
            .take_valid_block_for_reproposal()
            .unwrap();
        assert_eq!(valid_round, initial_round);
        assert_eq!(valid_block.header.value_hash, original_value_hash);
        let last_qc = fixture.drivers[recovery_proposer].last_qc_bytes();
        let recovery_proposal = fixture.drivers[recovery_proposer]
            .engine
            .repropose(
                &valid_block,
                recovery_round,
                Some(valid_round),
                &recovery_election,
                valid_block.header.timestamp,
                last_qc,
            )
            .unwrap();
        let committed_hash = recovery_proposal.block.header.block_hash();
        assert_eq!(recovery_proposal.block.header.polc_round, Some(initial_round));
        for driver in &mut fixture.drivers {
            driver.process(DriverEvent::InboundBlock {
                from: None,
                proposal: recovery_proposal.clone(),
            });
            assert!(driver.pending_proposal(&committed_hash).is_some());
        }

        let mut recovery_prevotes = Vec::new();
        for (index, driver) in fixture.drivers.iter_mut().enumerate() {
            let vote = driver
                .on_propose_timeout()
                .into_iter()
                .find_map(|action| match action {
                    DriverAction::BroadcastVote(vote) => Some(vote),
                    _ => None,
                })
                .unwrap();
            assert_eq!(
                (vote.validator_id, vote.height, vote.round, vote.step, vote.block_hash),
                (ids[index], 1, recovery_round, VoteStep::Prevote, committed_hash)
            );
            recovery_prevotes.push(vote);
        }
        let mut recovery_precommits: Vec<Option<VoteV1>> = vec![None; 4];
        for receiver in 0..4 {
            for source in 0..4 {
                if source == receiver {
                    continue;
                }
                let actions = fixture.drivers[receiver].process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 25300 + source)
                        .parse()
                        .unwrap(),
                    vote: recovery_prevotes[source].clone(),
                });
                if let Some(precommit) = actions.into_iter().find_map(|action| match action {
                    DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Precommit => {
                        Some(vote)
                    }
                    _ => None,
                }) {
                    recovery_precommits[receiver] = Some(precommit);
                }
            }
            let vote = recovery_precommits[receiver]
                .as_ref()
                .expect("recovery prevote quorum must produce a precommit");
            assert_eq!(
                (vote.validator_id, vote.height, vote.round, vote.step, vote.block_hash),
                (ids[receiver], 1, recovery_round, VoteStep::Precommit, committed_hash)
            );
        }

        // At local+one-remote precommit each observer has exactly 2/4 and must
        // remain at genesis. A second distinct remote vote crosses 3/4 and
        // independently finalizes on every production driver.
        for receiver in 0..4 {
            let source = (receiver + 1) % 4;
            fixture.drivers[receiver].process(DriverEvent::InboundVote {
                from: format!("127.0.0.1:{}", 25400 + source)
                    .parse()
                    .unwrap(),
                vote: recovery_precommits[source].clone().unwrap(),
            });
            assert_eq!(fixture.drivers[receiver].engine.state.height, 0);
            assert_eq!(fixture.drivers[receiver].engine.state.tip_hash, genesis_tip);
            assert_eq!(fixture.drivers[receiver].last_qc_height(), None);
            assert!(!matches!(
                fixture.drivers[receiver].vote_decision(
                    1,
                    recovery_round,
                    VoteStep::Precommit,
                ),
                Some(VoteDecision::QuorumReached { .. })
            ));
        }
        for receiver in 0..4 {
            let source = (receiver + 2) % 4;
            fixture.drivers[receiver].process(DriverEvent::InboundVote {
                from: format!("127.0.0.1:{}", 25500 + source)
                    .parse()
                    .unwrap(),
                vote: recovery_precommits[source].clone().unwrap(),
            });
        }

        let roots = indra_state::compute_state_roots(&fixture.drivers[0].engine.state);
        for driver in &fixture.drivers {
            assert_eq!(driver.engine.state.height, 1);
            assert_eq!(driver.engine.state.tip_hash, committed_hash);
            assert_eq!(driver.current_round(), 0);
            assert_eq!(driver.current_phase(), RoundPhase::Propose);
            assert_eq!(driver.last_qc_height(), Some(1));
            let driver_roots = indra_state::compute_state_roots(&driver.engine.state);
            assert_eq!(driver_roots.state_root, roots.state_root);
            assert_eq!(driver_roots.validator_set_root, roots.validator_set_root);
            let qc = QuorumCertificateV1::decode_exact(&driver.last_qc_bytes()).unwrap();
            assert_eq!((qc.height, qc.round, qc.block_hash), (1, recovery_round, committed_hash));
            indra_core::types::qc::verify_qc_against_snapshot(
                &qc,
                &snapshot,
                TEST_CHAIN_ID,
            )
            .unwrap();
        }

        // Two more real process restarts must recover the committed chain and
        // promoted current-tip QC, with committed-height safety state cleared.
        for index in [0usize, 2] {
            let persisted_qc_before_restart = fixture.drivers[index].last_qc_bytes();
            restart(&mut fixture.drivers, index);
            let driver = &mut fixture.drivers[index];
            assert_eq!(driver.engine.state.height, 1);
            assert_eq!(driver.engine.state.tip_hash, committed_hash);
            assert_eq!(driver.next_height(), 2);
            assert_eq!(driver.current_round(), 0);
            assert_eq!(driver.current_phase(), RoundPhase::Propose);
            assert_eq!(driver.last_qc_height(), Some(1));
            assert_eq!(driver.last_qc_bytes(), persisted_qc_before_restart);
            assert!(driver.locked_round.is_none());
            assert!(driver.locked_value.is_none());
            assert!(driver.locked_value_hash.is_none());
            assert!(driver.locked_polc_votes.is_empty());
            assert!(driver.valid_round.is_none());
            assert!(driver.valid_value.is_none());
            assert!(matches!(driver.vote_safety.load(), VoteSafetyLoadResult::NoRecord));
            let qc = QuorumCertificateV1::decode_exact(&driver.last_qc_bytes()).unwrap();
            indra_core::types::qc::verify_qc_against_snapshot(
                &qc,
                &snapshot,
                TEST_CHAIN_ID,
            )
            .unwrap();
            assert!(no_broadcast_vote(&driver.sign_and_record_local_vote(
                1,
                initial_round,
                VoteStep::Prevote,
                conflicting_hash,
            )));
        }

        let driver = &mut fixture.drivers[0];
        let before_roots = indra_state::compute_state_roots(&driver.engine.state);
        let before = (
            driver.engine.state.height,
            driver.engine.state.tip_hash,
            before_roots.state_root,
            before_roots.validator_set_root,
            driver.last_qc_bytes(),
            driver.last_qc_height(),
            driver.current_round(),
            driver.current_phase(),
            driver.vote_admission_metrics.qc_formations,
        );
        driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal,
        });
        driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:25600".parse().unwrap(),
            vote: original_prevotes[0].clone(),
        });
        driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:25601".parse().unwrap(),
            vote: old_precommit,
        });
        let after_roots = indra_state::compute_state_roots(&driver.engine.state);
        let after = (
            driver.engine.state.height,
            driver.engine.state.tip_hash,
            after_roots.state_root,
            after_roots.validator_set_root,
            driver.last_qc_bytes(),
            driver.last_qc_height(),
            driver.current_round(),
            driver.current_phase(),
            driver.vote_admission_metrics.qc_formations,
        );
        assert_eq!(before, after);
        assert!(driver.pending_proposal(&original_hash).is_none());

        let dirs = fixture.dirs;
        drop(fixture.drivers);
        for dir in dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn audit_harness_four_validator_byzantine_equivocation_preserves_safety() {
        let mut fixture = shared_four_validator_fixture();
        for driver in &mut fixture.drivers {
            driver.sync.mark_caught_up(driver.height());
        }
        let ids: Vec<_> = fixture
            .drivers
            .iter()
            .map(|driver| driver.engine.validator_id().unwrap())
            .collect();
        let genesis_tip = fixture.drivers[0].engine.state.tip_hash;

        let (round, election, proposer) = loop {
            let round = fixture.drivers[0].current_round();
            assert!(fixture
                .drivers
                .iter()
                .all(|driver| driver.current_round() == round
                    && driver.current_phase() == RoundPhase::Propose));
            let election = fixture.drivers[0]
                .proposer_election_for_height(1, round)
                .unwrap();
            if let Some(proposer) = (0..4)
                .find(|index| fixture.drivers[*index].engine.is_proposer(&election))
            {
                break (round, election, proposer);
            }
            for driver in &mut fixture.drivers {
                let _ = driver.on_propose_timeout();
                let _ = driver.on_prevote_timeout();
                driver.on_precommit_timeout().unwrap();
                assert_eq!(driver.engine.state.height, 0);
                assert_eq!(driver.engine.state.tip_hash, genesis_tip);
                assert_eq!(driver.last_qc_height(), None);
            }
        };
        assert!(fixture.drivers[proposer].engine.is_proposer(&election));
        let proposal = fixture.drivers[proposer]
            .engine
            .propose(
                &election,
                1_700_010_000 + u64::from(round),
                vec![],
                None,
            )
            .unwrap();
        let proposal_hash = proposal.block.header.block_hash();
        let conflicting_hash = Bytes32::from([0xD5; 32]);
        assert_ne!(proposal_hash, conflicting_hash);
        let snapshot = fixture.drivers[0]
            .engine
            .state
            .snapshot_for_consensus_height(1)
            .unwrap()
            .clone();
        for driver in fixture.drivers.iter_mut().take(3) {
            driver.process(DriverEvent::InboundBlock {
                from: None,
                proposal: proposal.clone(),
            });
            assert!(driver.pending_proposal(&proposal_hash).is_some());
        }

        let mut honest_prevotes = Vec::new();
        for index in 0..3 {
            let vote = fixture.drivers[index]
                .on_propose_timeout()
                .into_iter()
                .find_map(|action| match action {
                    DriverAction::BroadcastVote(vote) => Some(vote),
                    _ => None,
                })
                .unwrap();
            assert_eq!(
                (vote.validator_id, vote.height, vote.round, vote.step, vote.block_hash),
                (ids[index], 1, round, VoteStep::Prevote, proposal_hash)
            );
            honest_prevotes.push(vote);
        }

        let byzantine_signer = HybridKeypair::new(
            ClassicalKeypair::from_seed(&fixture.materials[3].seed),
            fixture.materials[3].pq.clone(),
        );
        let d_prevote_proposal = indra_consensus::vote::produce_vote(
            1,
            round,
            VoteStep::Prevote,
            proposal_hash,
            ids[3],
            snapshot.snapshot_root,
            TEST_CHAIN_ID,
            &byzantine_signer,
        )
        .unwrap();
        let d_prevote_conflict = indra_consensus::vote::produce_vote(
            1,
            round,
            VoteStep::Prevote,
            conflicting_hash,
            ids[3],
            snapshot.snapshot_root,
            TEST_CHAIN_ID,
            &byzantine_signer,
        )
        .unwrap();
        assert_ne!(d_prevote_proposal.block_hash, d_prevote_conflict.block_hash);

        // A and C see D's proposal vote first; B sees the conflicting vote
        // first. The second same-slot vote is authenticated for evidence but
        // cannot enter a collector or add D's stake again.
        let a_first = fixture.drivers[0].process(DriverEvent::InboundVote {
            from: "127.0.0.1:26003".parse().unwrap(),
            vote: d_prevote_proposal.clone(),
        });
        let a_second = fixture.drivers[0].process(DriverEvent::InboundVote {
            from: "127.0.0.1:26013".parse().unwrap(),
            vote: d_prevote_conflict.clone(),
        });
        assert!(a_first
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastVote(vote) if vote.validator_id == ids[3])));
        assert!(!a_second
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastVote(_))));
        fixture.drivers[1].process(DriverEvent::InboundVote {
            from: "127.0.0.1:26023".parse().unwrap(),
            vote: d_prevote_conflict.clone(),
        });
        let b_second = fixture.drivers[1].process(DriverEvent::InboundVote {
            from: "127.0.0.1:26033".parse().unwrap(),
            vote: d_prevote_proposal.clone(),
        });
        assert!(!b_second
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastVote(_))));
        fixture.drivers[2].process(DriverEvent::InboundVote {
            from: "127.0.0.1:26043".parse().unwrap(),
            vote: d_prevote_proposal.clone(),
        });

        for index in 0..3 {
            let key = ConsensusDriver::collector_key(1, round, VoteStep::Prevote);
            let d_votes = fixture.drivers[index]
                .vote_collectors
                .get(&key)
                .map(|collector| {
                    collector
                        .accepted_votes()
                        .into_iter()
                        .filter(|vote| vote.validator_id == ids[3])
                        .count()
                })
                .unwrap_or(0);
            assert!(d_votes <= 1, "D was counted more than once at observer {index}");
            assert!(!matches!(
                fixture.drivers[index].vote_decision(1, round, VoteStep::Prevote),
                Some(VoteDecision::QuorumReached { .. })
            ));
            assert_eq!(fixture.drivers[index].valid_round, None);
            assert_eq!(fixture.drivers[index].valid_value, None);
            assert_eq!(fixture.drivers[index].locked_round, None);
            assert_eq!(fixture.drivers[index].locked_value, None);
            assert_eq!(fixture.drivers[index].engine.state.height, 0);
            assert_eq!(fixture.drivers[index].last_qc_height(), None);
        }

        // Asymmetric honest delivery now gives each honest observer a genuine
        // three-distinct-identity PoLC for P. No conflicting proposal/PoLC is
        // available, so all honest locks must be identical.
        let mut honest_precommits: Vec<Option<VoteV1>> = vec![None; 3];
        for (receiver, sources) in [(0usize, vec![1usize]), (1, vec![0, 2]), (2, vec![0, 1])] {
            for source in sources {
                let actions = fixture.drivers[receiver].process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 26100 + source)
                        .parse()
                        .unwrap(),
                    vote: honest_prevotes[source].clone(),
                });
                if let Some(precommit) = actions.into_iter().find_map(|action| match action {
                    DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Precommit => {
                        Some(vote)
                    }
                    _ => None,
                }) {
                    honest_precommits[receiver] = Some(precommit);
                }
            }
            let driver = &fixture.drivers[receiver];
            assert_eq!(driver.current_phase(), RoundPhase::Precommit);
            assert_eq!(driver.valid_round, Some(round));
            assert_eq!(driver.valid_value, Some(proposal_hash));
            assert_eq!(driver.locked_round, Some(round));
            assert_eq!(driver.locked_value, Some(proposal_hash));
            assert!(!driver.locked_polc_votes.is_empty());
            assert_eq!(driver.engine.state.height, 0);
            assert_eq!(driver.last_qc_height(), None);
            let precommit = honest_precommits[receiver]
                .as_ref()
                .expect("honest PoLC must produce a local precommit");
            assert_eq!(
                (
                    precommit.validator_id,
                    precommit.height,
                    precommit.round,
                    precommit.step,
                    precommit.block_hash,
                ),
                (ids[receiver], 1, round, VoteStep::Precommit, proposal_hash)
            );
        }
        let locks_before_conflict: Vec<_> = fixture
            .drivers
            .iter()
            .take(3)
            .map(|driver| {
                (
                    driver.current_round(),
                    driver.locked_round,
                    driver.locked_value,
                    driver.valid_round,
                    driver.valid_value,
                )
            })
            .collect();
        fixture.drivers[2].process(DriverEvent::InboundVote {
            from: "127.0.0.1:26113".parse().unwrap(),
            vote: d_prevote_conflict.clone(),
        });
        fixture.drivers[2].process(DriverEvent::InboundVote {
            from: "127.0.0.1:26110".parse().unwrap(),
            vote: honest_prevotes[0].clone(),
        });
        let d_later_round_conflict = indra_consensus::vote::produce_vote(
            1,
            round + 1,
            VoteStep::Prevote,
            conflicting_hash,
            ids[3],
            snapshot.snapshot_root,
            TEST_CHAIN_ID,
            &byzantine_signer,
        )
        .unwrap();
        fixture.drivers[2].process(DriverEvent::InboundVote {
            from: "127.0.0.1:26123".parse().unwrap(),
            vote: d_later_round_conflict,
        });
        let locks_after_conflict: Vec<_> = fixture
            .drivers
            .iter()
            .take(3)
            .map(|driver| {
                (
                    driver.current_round(),
                    driver.locked_round,
                    driver.locked_value,
                    driver.valid_round,
                    driver.valid_value,
                )
            })
            .collect();
        assert_eq!(locks_before_conflict, locks_after_conflict);

        let d_precommit_proposal = indra_consensus::vote::produce_vote(
            1,
            round,
            VoteStep::Precommit,
            proposal_hash,
            ids[3],
            snapshot.snapshot_root,
            TEST_CHAIN_ID,
            &byzantine_signer,
        )
        .unwrap();
        let d_precommit_conflict = indra_consensus::vote::produce_vote(
            1,
            round,
            VoteStep::Precommit,
            conflicting_hash,
            ids[3],
            snapshot.snapshot_root,
            TEST_CHAIN_ID,
            &byzantine_signer,
        )
        .unwrap();

        // Deliver conflict first so D cannot contribute to P at A. The second
        // cryptographically valid precommit must produce slash evidence, while
        // the collector retains only A's local P precommit.
        fixture.drivers[0].process(DriverEvent::InboundVote {
            from: "127.0.0.1:26203".parse().unwrap(),
            vote: d_precommit_conflict.clone(),
        });
        let slash_actions = fixture.drivers[0].process(DriverEvent::InboundVote {
            from: "127.0.0.1:26213".parse().unwrap(),
            vote: d_precommit_proposal.clone(),
        });
        assert!(slash_actions.iter().any(|action| matches!(
            action,
            DriverAction::SlashDetected(evidence) if evidence.validator_id == ids[3]
        )));
        assert!(!fixture.drivers[0].collector_has_vote_from(
            1,
            round,
            VoteStep::Precommit,
            ids[3],
        ));
        assert_eq!(fixture.drivers[0].engine.state.height, 0);
        assert_eq!(fixture.drivers[0].last_qc_height(), None);

        // A production-built conflicting QC with D duplicated still resolves
        // to only one authorized signer and must fail governing-snapshot QC
        // verification.
        let (qc_validators, _) = fixture.drivers[0]
            .engine
            .qc_authority_for_height(1)
            .unwrap();
        let conflicting_qc = indra_consensus::qc::build_qc(
            1,
            round,
            conflicting_hash,
            TEST_CHAIN_ID,
            snapshot.snapshot_root,
            &qc_validators,
            vec![
                &d_precommit_conflict,
                &d_precommit_conflict,
                honest_precommits[0].as_ref().unwrap(),
            ],
        )
        .unwrap();
        assert!(indra_core::types::qc::verify_qc_against_snapshot(
            &conflicting_qc,
            &snapshot,
            TEST_CHAIN_ID,
        )
        .is_err());

        // Exactly local+one remote P precommit is 2/4 and cannot finalize.
        // The next distinct honest identity crosses strict >2/3. D is absent
        // from every finalizing signer set.
        let second_and_third = [(1usize, 2usize), (0, 2), (0, 1)];
        for receiver in 0..3 {
            let (second, third) = second_and_third[receiver];
            fixture.drivers[receiver].process(DriverEvent::InboundVote {
                from: format!("127.0.0.1:{}", 26300 + second)
                    .parse()
                    .unwrap(),
                vote: honest_precommits[second].clone().unwrap(),
            });
            assert_eq!(fixture.drivers[receiver].engine.state.height, 0);
            assert_eq!(fixture.drivers[receiver].engine.state.tip_hash, genesis_tip);
            assert_eq!(fixture.drivers[receiver].last_qc_height(), None);
            assert!(!matches!(
                fixture.drivers[receiver].vote_decision(1, round, VoteStep::Precommit),
                Some(VoteDecision::QuorumReached { .. })
            ));
            fixture.drivers[receiver].process(DriverEvent::InboundVote {
                from: format!("127.0.0.1:{}", 26400 + third)
                    .parse()
                    .unwrap(),
                vote: honest_precommits[third].clone().unwrap(),
            });
        }

        let canonical_roots = indra_state::compute_state_roots(&fixture.drivers[0].engine.state);
        for driver in fixture.drivers.iter().take(3) {
            assert_eq!(driver.engine.state.height, 1);
            assert_eq!(driver.engine.state.tip_hash, proposal_hash);
            assert_eq!(driver.current_round(), 0);
            assert_eq!(driver.current_phase(), RoundPhase::Propose);
            assert_eq!(driver.last_qc_height(), Some(1));
            let roots = indra_state::compute_state_roots(&driver.engine.state);
            assert_eq!(roots.state_root, canonical_roots.state_root);
            assert_eq!(roots.validator_set_root, canonical_roots.validator_set_root);
            let qc = QuorumCertificateV1::decode_exact(&driver.last_qc_bytes()).unwrap();
            assert_eq!((qc.height, qc.round, qc.block_hash), (1, round, proposal_hash));
            indra_core::types::qc::verify_qc_against_snapshot(
                &qc,
                &snapshot,
                TEST_CHAIN_ID,
            )
            .unwrap();
        }

        let driver = &mut fixture.drivers[0];
        let roots_before = indra_state::compute_state_roots(&driver.engine.state);
        let before = (
            driver.engine.state.height,
            driver.engine.state.tip_hash,
            roots_before.state_root,
            roots_before.validator_set_root,
            driver.last_qc_bytes(),
            driver.last_qc_height(),
            driver.current_round(),
            driver.current_phase(),
            driver.vote_admission_metrics.qc_formations,
        );
        driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:26503".parse().unwrap(),
            vote: d_prevote_conflict,
        });
        driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:26513".parse().unwrap(),
            vote: d_prevote_proposal,
        });
        driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:26520".parse().unwrap(),
            vote: honest_prevotes[0].clone(),
        });
        driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:26521".parse().unwrap(),
            vote: honest_precommits[1].clone().unwrap(),
        });
        driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal,
        });
        let roots_after = indra_state::compute_state_roots(&driver.engine.state);
        let after = (
            driver.engine.state.height,
            driver.engine.state.tip_hash,
            roots_after.state_root,
            roots_after.validator_set_root,
            driver.last_qc_bytes(),
            driver.last_qc_height(),
            driver.current_round(),
            driver.current_phase(),
            driver.vote_admission_metrics.qc_formations,
        );
        assert_eq!(before, after);
        assert!(driver.pending_proposal(&proposal_hash).is_none());

        let dirs = fixture.dirs;
        drop(fixture.drivers);
        for dir in dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn audit_harness_four_validator_topology_churn_recovers() {
        #[derive(Clone)]
        enum TopologyMessage {
            Proposal(BlockProposalVNext),
            Vote(VoteV1),
        }

        let mut fixture = shared_four_validator_fixture();
        for driver in &mut fixture.drivers {
            driver.sync.mark_caught_up(driver.height());
        }
        let ids: Vec<_> = fixture
            .drivers
            .iter()
            .map(|driver| driver.engine.validator_id().unwrap())
            .collect();
        let genesis_tip = fixture.drivers[0].engine.state.tip_hash;
        let t1 = [
            [false, true, false, false],
            [true, false, true, false],
            [false, true, false, true],
            [false, false, true, false],
        ];
        let t2 = [
            [false, false, true, true],
            [false, false, false, true],
            [true, false, false, false],
            [true, true, false, false],
        ];
        let isolate_d = [
            [false, true, true, false],
            [true, false, true, false],
            [true, true, false, false],
            [false, false, false, false],
        ];
        let healed = [
            [false, true, true, true],
            [true, false, true, true],
            [true, true, false, true],
            [true, true, true, false],
        ];

        let (round, election, proposer) = loop {
            let round = fixture.drivers[0].current_round();
            assert!(fixture
                .drivers
                .iter()
                .all(|driver| driver.current_round() == round
                    && driver.current_phase() == RoundPhase::Propose));
            let election = fixture.drivers[0]
                .proposer_election_for_height(1, round)
                .unwrap();
            if let Some(proposer) = (0..4)
                .find(|index| fixture.drivers[*index].engine.is_proposer(&election))
            {
                break (round, election, proposer);
            }
            for driver in &mut fixture.drivers {
                let _ = driver.on_propose_timeout();
                let _ = driver.on_prevote_timeout();
                driver.on_precommit_timeout().unwrap();
                assert_eq!(driver.engine.state.height, 0);
                assert_eq!(driver.engine.state.tip_hash, genesis_tip);
                assert_eq!(driver.last_qc_height(), None);
            }
        };
        let proposal = fixture.drivers[proposer]
            .engine
            .propose(
                &election,
                1_700_020_000 + u64::from(round),
                vec![],
                None,
            )
            .unwrap();
        let proposal_hash = proposal.block.header.block_hash();
        let snapshot = fixture.drivers[0]
            .engine
            .state
            .snapshot_for_consensus_height(1)
            .unwrap()
            .clone();

        // Relay the exact proposal hop-by-hop over T1's line. The proposer is
        // the only local injection point; every remote admission below has a
        // currently permitted edge.
        fixture.drivers[proposer].process(DriverEvent::InboundBlock {
            from: None,
            proposal: proposal.clone(),
        });
        let mut proposal_visible = [false; 4];
        proposal_visible[proposer] = true;
        while proposal_visible.iter().any(|visible| !visible) {
            let (from, to) = (0..4)
                .find_map(|from| {
                    proposal_visible[from].then_some(from).and_then(|from| {
                        (0..4).find_map(|to| {
                            (t1[from][to] && !proposal_visible[to]).then_some((from, to))
                        })
                    })
                })
                .expect("connected T1 line must relay the proposal to every validator");
            assert!(t1[from][to]);
            fixture.drivers[to].process(DriverEvent::InboundBlock {
                from: Some(
                    format!("127.0.0.1:{}", 27000 + from)
                        .parse()
                        .unwrap(),
                ),
                proposal: proposal.clone(),
            });
            proposal_visible[to] = true;
        }
        for driver in &fixture.drivers {
            assert!(driver.pending_proposal(&proposal_hash).is_some());
        }

        let mut prevotes = Vec::new();
        for (index, driver) in fixture.drivers.iter_mut().enumerate() {
            let vote = driver
                .on_propose_timeout()
                .into_iter()
                .find_map(|action| match action {
                    DriverAction::BroadcastVote(vote) => Some(vote),
                    _ => None,
                })
                .unwrap();
            assert_eq!(
                (vote.validator_id, vote.height, vote.round, vote.step, vote.block_hash),
                (ids[index], 1, round, VoteStep::Prevote, proposal_hash)
            );
            prevotes.push(vote);
        }

        // Under T1, B sees A and C sees D. Relaying A's exact signed vote
        // through B gives C three distinct identities and a genuine lock,
        // while A/B/D retain different visibility and nobody can commit.
        for (from, to) in [(0usize, 1usize), (3, 2)] {
            assert!(t1[from][to]);
            fixture.drivers[to].process(DriverEvent::InboundVote {
                from: format!("127.0.0.1:{}", 27100 + from)
                    .parse()
                    .unwrap(),
                vote: prevotes[from].clone(),
            });
        }
        assert!(t1[1][2]);
        let c_lock_actions = fixture.drivers[2].process(DriverEvent::InboundVote {
            from: "127.0.0.1:27101".parse().unwrap(),
            vote: prevotes[0].clone(),
        });
        let precommit_c = c_lock_actions
            .into_iter()
            .find_map(|action| match action {
                DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Precommit => Some(vote),
                _ => None,
            })
            .expect("C must lock after receiving three distinct T1 prevotes");
        assert_eq!(fixture.drivers[2].locked_value, Some(proposal_hash));
        assert_eq!(fixture.drivers[2].locked_round, Some(round));
        assert_eq!(fixture.drivers[0].locked_value, None);
        assert_eq!(fixture.drivers[1].locked_value, None);
        assert_eq!(fixture.drivers[3].locked_value, None);
        assert!(fixture
            .drivers
            .iter()
            .all(|driver| driver.engine.state.height == 0
                && driver.engine.state.tip_hash == genesis_tip
                && driver.last_qc_height().is_none()));

        // A duplicate relay of A's immutable signed vote still represents one
        // validator identity and one stake contribution at C.
        assert!(t1[1][2]);
        fixture.drivers[2].process(DriverEvent::InboundVote {
            from: "127.0.0.1:27111".parse().unwrap(),
            vote: prevotes[0].clone(),
        });
        let prevote_key = ConsensusDriver::collector_key(1, round, VoteStep::Prevote);
        let a_votes_at_c = fixture.drivers[2]
            .vote_collectors
            .get(&prevote_key)
            .unwrap()
            .accepted_votes()
            .into_iter()
            .filter(|vote| vote.validator_id == ids[0])
            .count();
        assert_eq!(a_votes_at_c, 1);

        // Queue traffic emitted under T1 and release it only after switching
        // to T2. Every queued hop is validated against T2 at delivery time.
        let mut delayed = std::collections::VecDeque::new();
        delayed.push_back((0usize, 2usize, TopologyMessage::Proposal(proposal.clone())));
        delayed.push_back((0, 2, TopologyMessage::Vote(prevotes[0].clone())));
        delayed.push_back((2, 0, TopologyMessage::Vote(precommit_c.clone())));
        while let Some((from, to, message)) = delayed.pop_front() {
            assert!(t2[from][to]);
            match message {
                TopologyMessage::Proposal(proposal) => {
                    fixture.drivers[to].process(DriverEvent::InboundBlock {
                        from: Some(
                            format!("127.0.0.1:{}", 27200 + from)
                                .parse()
                                .unwrap(),
                        ),
                        proposal,
                    });
                }
                TopologyMessage::Vote(vote) => {
                    fixture.drivers[to].process(DriverEvent::InboundVote {
                        from: format!("127.0.0.1:{}", 27200 + from)
                            .parse()
                            .unwrap(),
                        vote,
                    });
                }
            }
        }
        let a_votes_at_c_after_t2 = fixture.drivers[2]
            .vote_collectors
            .get(&prevote_key)
            .unwrap()
            .accepted_votes()
            .into_iter()
            .filter(|vote| vote.validator_id == ids[0])
            .count();
        assert_eq!(a_votes_at_c_after_t2, 1);

        // T2 permits C/D -> A and A/B -> D. These asymmetric deliveries lock
        // A and D on the same value without using any removed T1 edge.
        let mut precommits: Vec<Option<VoteV1>> = vec![None; 4];
        precommits[2] = Some(precommit_c.clone());
        for (receiver, sources) in [(0usize, vec![2usize, 3usize]), (3, vec![0, 1])] {
            for source in sources {
                assert!(t2[source][receiver]);
                let actions = fixture.drivers[receiver].process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 27300 + source)
                        .parse()
                        .unwrap(),
                    vote: prevotes[source].clone(),
                });
                if let Some(precommit) = actions.into_iter().find_map(|action| match action {
                    DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Precommit => {
                        Some(vote)
                    }
                    _ => None,
                }) {
                    precommits[receiver] = Some(precommit);
                }
            }
            assert_eq!(fixture.drivers[receiver].locked_value, Some(proposal_hash));
            assert_eq!(fixture.drivers[receiver].engine.state.height, 0);
            assert_eq!(fixture.drivers[receiver].last_qc_height(), None);
            assert!(precommits[receiver].is_some());
        }
        assert_eq!(fixture.drivers[1].locked_value, None);

        // The delayed C precommit plus A's local precommit is exactly 2/4 at
        // A. Likewise D's local plus A is 2/4. Neither topology can turn these
        // two identities into a QC or commit.
        assert!(fixture.drivers[0].collector_has_vote_from(
            1,
            round,
            VoteStep::Precommit,
            ids[2],
        ));
        assert_eq!(fixture.drivers[0].engine.state.height, 0);
        assert_eq!(fixture.drivers[0].last_qc_height(), None);
        assert!(t2[0][3]);
        fixture.drivers[3].process(DriverEvent::InboundVote {
            from: "127.0.0.1:27310".parse().unwrap(),
            vote: precommits[0].clone().unwrap(),
        });
        assert_eq!(fixture.drivers[3].engine.state.height, 0);
        assert_eq!(fixture.drivers[3].last_qc_height(), None);

        // Isolate D and connect A/B/C. B receives the already-signed A vote
        // from T1 plus C's vote over the new isolation topology and locks P.
        assert!(isolate_d[2][1]);
        let b_lock_actions = fixture.drivers[1].process(DriverEvent::InboundVote {
            from: "127.0.0.1:27402".parse().unwrap(),
            vote: prevotes[2].clone(),
        });
        let precommit_b = b_lock_actions
            .into_iter()
            .find_map(|action| match action {
                DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Precommit => Some(vote),
                _ => None,
            })
            .expect("B must lock using the three distinct honest prevotes");
        precommits[1] = Some(precommit_b);
        assert_eq!(fixture.drivers[1].locked_value, Some(proposal_hash));

        // A/B/C each demonstrate an exact two-precommit no-commit checkpoint,
        // then receive the third distinct honest identity and finalize while D
        // remains isolated at genesis.
        assert!(isolate_d[1][0]);
        fixture.drivers[0].process(DriverEvent::InboundVote {
            from: "127.0.0.1:27411".parse().unwrap(),
            vote: precommits[1].clone().unwrap(),
        });
        assert_eq!(fixture.drivers[0].engine.state.height, 1);

        assert!(isolate_d[0][1]);
        fixture.drivers[1].process(DriverEvent::InboundVote {
            from: "127.0.0.1:27420".parse().unwrap(),
            vote: precommits[0].clone().unwrap(),
        });
        assert_eq!(fixture.drivers[1].engine.state.height, 0);
        assert_eq!(fixture.drivers[1].last_qc_height(), None);
        assert!(isolate_d[2][1]);
        fixture.drivers[1].process(DriverEvent::InboundVote {
            from: "127.0.0.1:27422".parse().unwrap(),
            vote: precommits[2].clone().unwrap(),
        });
        assert_eq!(fixture.drivers[1].engine.state.height, 1);

        assert!(isolate_d[0][2]);
        fixture.drivers[2].process(DriverEvent::InboundVote {
            from: "127.0.0.1:27430".parse().unwrap(),
            vote: precommits[0].clone().unwrap(),
        });
        assert_eq!(fixture.drivers[2].engine.state.height, 0);
        assert_eq!(fixture.drivers[2].last_qc_height(), None);
        assert!(isolate_d[1][2]);
        fixture.drivers[2].process(DriverEvent::InboundVote {
            from: "127.0.0.1:27431".parse().unwrap(),
            vote: precommits[1].clone().unwrap(),
        });
        assert_eq!(fixture.drivers[2].engine.state.height, 1);
        assert_eq!(fixture.drivers[3].engine.state.height, 0);
        assert_eq!(fixture.drivers[3].engine.state.tip_hash, genesis_tip);
        assert_eq!(fixture.drivers[3].last_qc_height(), None);

        // Full healing changes delivery only. Replay A's precommit through a
        // second valid relay path and prove its identity appears once at D;
        // B's distinct precommit then provides D's real third signer.
        assert!(healed[0][2] && healed[2][3]);
        fixture.drivers[3].process(DriverEvent::InboundVote {
            from: "127.0.0.1:27502".parse().unwrap(),
            vote: precommits[0].clone().unwrap(),
        });
        let precommit_key = ConsensusDriver::collector_key(1, round, VoteStep::Precommit);
        let a_precommits_at_d = fixture.drivers[3]
            .vote_collectors
            .get(&precommit_key)
            .unwrap()
            .accepted_votes()
            .into_iter()
            .filter(|vote| vote.validator_id == ids[0])
            .count();
        assert_eq!(a_precommits_at_d, 1);
        assert_eq!(fixture.drivers[3].engine.state.height, 0);
        assert!(healed[1][3]);
        fixture.drivers[3].process(DriverEvent::InboundVote {
            from: "127.0.0.1:27511".parse().unwrap(),
            vote: precommits[1].clone().unwrap(),
        });

        let canonical_roots = indra_state::compute_state_roots(&fixture.drivers[0].engine.state);
        for driver in &fixture.drivers {
            assert_eq!(driver.engine.state.height, 1);
            assert_eq!(driver.engine.state.tip_hash, proposal_hash);
            assert_eq!(driver.current_round(), 0);
            assert_eq!(driver.current_phase(), RoundPhase::Propose);
            assert_eq!(driver.last_qc_height(), Some(1));
            let roots = indra_state::compute_state_roots(&driver.engine.state);
            assert_eq!(roots.state_root, canonical_roots.state_root);
            assert_eq!(roots.validator_set_root, canonical_roots.validator_set_root);
            let qc = QuorumCertificateV1::decode_exact(&driver.last_qc_bytes()).unwrap();
            assert_eq!((qc.height, qc.block_hash), (1, proposal_hash));
            indra_core::types::qc::verify_qc_against_snapshot(
                &qc,
                &snapshot,
                TEST_CHAIN_ID,
            )
            .unwrap();
        }

        let driver = &mut fixture.drivers[0];
        let roots_before = indra_state::compute_state_roots(&driver.engine.state);
        let before = (
            driver.engine.state.height,
            driver.engine.state.tip_hash,
            roots_before.state_root,
            roots_before.validator_set_root,
            driver.last_qc_bytes(),
            driver.last_qc_height(),
            driver.current_round(),
            driver.current_phase(),
            driver.vote_admission_metrics.qc_formations,
        );
        driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal,
        });
        driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:27600".parse().unwrap(),
            vote: prevotes[0].clone(),
        });
        driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:27602".parse().unwrap(),
            vote: precommit_c,
        });
        let roots_after = indra_state::compute_state_roots(&driver.engine.state);
        let after = (
            driver.engine.state.height,
            driver.engine.state.tip_hash,
            roots_after.state_root,
            roots_after.validator_set_root,
            driver.last_qc_bytes(),
            driver.last_qc_height(),
            driver.current_round(),
            driver.current_phase(),
            driver.vote_admission_metrics.qc_formations,
        );
        assert_eq!(before, after);
        assert!(driver.pending_proposal(&proposal_hash).is_none());

        let dirs = fixture.dirs;
        drop(fixture.drivers);
        for dir in dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn audit_harness_four_validator_valid_traffic_pressure_recovers() {
        const REPLAY_COUNT: usize = 32;

        let mut fixture = shared_four_validator_fixture();
        for driver in &mut fixture.drivers {
            driver.sync.mark_caught_up(driver.height());
        }
        let ids: Vec<_> = fixture
            .drivers
            .iter()
            .map(|driver| driver.engine.validator_id().unwrap())
            .collect();
        let genesis_tip = fixture.drivers[0].engine.state.tip_hash;

        let (initial_round, initial_election, initial_proposer) = loop {
            let round = fixture.drivers[0].current_round();
            let election = fixture.drivers[0]
                .proposer_election_for_height(1, round)
                .unwrap();
            if let Some(proposer) = (0..4)
                .find(|index| fixture.drivers[*index].engine.is_proposer(&election))
            {
                break (round, election, proposer);
            }
            for driver in &mut fixture.drivers {
                let _ = driver.on_propose_timeout();
                let _ = driver.on_prevote_timeout();
                driver.on_precommit_timeout().unwrap();
                assert_eq!(driver.engine.state.height, 0);
                assert_eq!(driver.engine.state.tip_hash, genesis_tip);
                assert_eq!(driver.last_qc_height(), None);
            }
        };
        let initial_proposal = fixture.drivers[initial_proposer]
            .engine
            .propose(
                &initial_election,
                1_700_030_000 + u64::from(initial_round),
                vec![],
                None,
            )
            .unwrap();
        let initial_hash = initial_proposal.block.header.block_hash();
        let snapshot = fixture.drivers[0]
            .engine
            .state
            .snapshot_for_consensus_height(1)
            .unwrap()
            .clone();

        // Admit one real proposal per node, then pressure the trusted replay
        // path from many synthetic peer addresses. Exact accepted replays must
        // not repeat proposal verification or detached state projection.
        for (index, driver) in fixture.drivers.iter_mut().enumerate() {
            driver.process(DriverEvent::InboundBlock {
                from: None,
                proposal: initial_proposal.clone(),
            });
            assert!(driver.pending_proposal(&initial_hash).is_some());
            let metrics_after_accept = driver.proposal_admission_metrics;
            for replay in 0..REPLAY_COUNT {
                driver.process(DriverEvent::InboundBlock {
                    from: Some(
                        format!("127.0.0.1:{}", 28000 + index * REPLAY_COUNT + replay)
                            .parse()
                            .unwrap(),
                    ),
                    proposal: initial_proposal.clone(),
                });
            }
            assert_eq!(driver.proposal_admission_metrics, metrics_after_accept);
            assert_eq!(
                driver
                    .pending_blocks
                    .values()
                    .filter(|proposal| proposal.block.header.block_hash() == initial_hash)
                    .count(),
                1
            );
        }

        let mut initial_prevotes = Vec::new();
        for (index, driver) in fixture.drivers.iter_mut().enumerate() {
            let vote = driver
                .on_propose_timeout()
                .into_iter()
                .find_map(|action| match action {
                    DriverAction::BroadcastVote(vote) => Some(vote),
                    _ => None,
                })
                .unwrap();
            assert_eq!(
                (vote.validator_id, vote.height, vote.round, vote.step, vote.block_hash),
                (ids[index], 1, initial_round, VoteStep::Prevote, initial_hash)
            );
            initial_prevotes.push(vote);
        }

        // Each observer receives only one remote identity, repeated 32 times.
        // Local+remote is exactly 2/4, so replay pressure cannot form a lock.
        for source in 0..4 {
            let receiver = (source + 1) % 4;
            fixture.drivers[receiver].process(DriverEvent::InboundVote {
                from: format!("127.0.0.1:{}", 28200 + source)
                    .parse()
                    .unwrap(),
                vote: initial_prevotes[source].clone(),
            });
            let metrics_after_accept = fixture.drivers[receiver].vote_admission_metrics;
            for replay in 0..REPLAY_COUNT {
                fixture.drivers[receiver].process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 28300 + source * REPLAY_COUNT + replay)
                        .parse()
                        .unwrap(),
                    vote: initial_prevotes[source].clone(),
                });
            }
            assert_eq!(
                fixture.drivers[receiver].vote_admission_metrics,
                metrics_after_accept
            );
            let key = ConsensusDriver::collector_key(1, initial_round, VoteStep::Prevote);
            let source_votes = fixture.drivers[receiver]
                .vote_collectors
                .get(&key)
                .unwrap()
                .accepted_votes()
                .into_iter()
                .filter(|vote| vote.validator_id == ids[source])
                .count();
            assert_eq!(source_votes, 1);
            assert!(!matches!(
                fixture.drivers[receiver].vote_decision(
                    1,
                    initial_round,
                    VoteStep::Prevote,
                ),
                Some(VoteDecision::QuorumReached { .. })
            ));
            assert_eq!(fixture.drivers[receiver].locked_value, None);
            assert_eq!(fixture.drivers[receiver].engine.state.height, 0);
        }

        // Add several distinct, production-authorized same-slot proposals only
        // after every validator has already cast its initial prevote. This
        // stresses pending proposal retention without changing that vote.
        for variant in 1..=12u64 {
            let proposal = fixture.drivers[initial_proposer]
                .engine
                .propose(
                    &initial_election,
                    initial_proposal.block.header.timestamp + variant,
                    vec![],
                    None,
                )
                .unwrap();
            fixture.drivers[0].process(DriverEvent::InboundBlock {
                from: Some("127.0.0.1:28400".parse().unwrap()),
                proposal,
            });
        }
        assert!(fixture.drivers[0].pending_blocks.len() >= 12);
        assert!(fixture.drivers[0].pending_blocks.len() <= MAX_STALLED_HEIGHT_ENTRIES);

        // Finish the initial round without a value quorum. Each timeout emits
        // a genuine nil precommit, which remains valid old-round traffic for
        // later pressure and post-commit replay.
        let mut old_precommits = Vec::new();
        for driver in &mut fixture.drivers {
            let precommit = driver
                .on_prevote_timeout()
                .into_iter()
                .find_map(|action| match action {
                    DriverAction::BroadcastVote(vote) => Some(vote),
                    _ => None,
                })
                .unwrap();
            assert_eq!(
                (precommit.height, precommit.round, precommit.step, precommit.block_hash),
                (1, initial_round, VoteStep::Precommit, Bytes32::ZERO)
            );
            old_precommits.push(precommit);
            driver.on_precommit_timeout().unwrap();
        }

        // Continue through legal timeout rounds until the deterministic fixture
        // has experienced at least two genuinely proposer-less rounds. Replay
        // authenticated round-zero traffic throughout and prove no regression.
        let mut proposerless_rounds = 0usize;
        let mut old_nil_prevote = None;
        while proposerless_rounds < 2 {
            let pressure_round = fixture.drivers[0].current_round();
            assert!(fixture
                .drivers
                .iter()
                .all(|driver| driver.current_round() == pressure_round
                    && driver.current_phase() == RoundPhase::Propose));
            let pressure_election = fixture.drivers[0]
                .proposer_election_for_height(1, pressure_round)
                .unwrap();
            let has_fixture_proposer = (0..4)
                .any(|index| fixture.drivers[index].engine.is_proposer(&pressure_election));
            if !has_fixture_proposer {
                proposerless_rounds += 1;
            }
            let rounds_before: Vec<_> = fixture
                .drivers
                .iter()
                .map(|driver| driver.current_round())
                .collect();
            let mut round_nil_prevotes = Vec::new();
            for driver in &mut fixture.drivers {
                let vote = driver
                    .on_propose_timeout()
                    .into_iter()
                    .find_map(|action| match action {
                        DriverAction::BroadcastVote(vote) => Some(vote),
                        _ => None,
                    })
                    .unwrap();
                assert_eq!(
                    (vote.height, vote.round, vote.step, vote.block_hash),
                    (1, pressure_round, VoteStep::Prevote, Bytes32::ZERO)
                );
                round_nil_prevotes.push(vote);
            }
            // Retain a remote validator's genuine nil prevote so later-round
            // pressure traverses authoritative inbound admission rather than
            // the local-vote replay shortcut.
            old_nil_prevote.get_or_insert_with(|| round_nil_prevotes[1].clone());

            let stale_before = (
                fixture.drivers[0].engine.state.height,
                fixture.drivers[0].engine.state.tip_hash,
                fixture.drivers[0].current_round(),
                fixture.drivers[0].locked_round,
                fixture.drivers[0].locked_value,
                fixture.drivers[0].last_qc_height(),
                fixture.drivers[0].vote_admission_metrics.qc_formations,
            );
            for replay in 0..REPLAY_COUNT {
                fixture.drivers[0].process(DriverEvent::InboundBlock {
                    from: Some(
                        format!("127.0.0.1:{}", 28600 + replay)
                            .parse()
                            .unwrap(),
                    ),
                    proposal: initial_proposal.clone(),
                });
                fixture.drivers[0].process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 28700 + replay)
                        .parse()
                        .unwrap(),
                    vote: initial_prevotes[1].clone(),
                });
                fixture.drivers[0].process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 28740 + replay)
                        .parse()
                        .unwrap(),
                    vote: old_nil_prevote.clone().unwrap(),
                });
                fixture.drivers[0].process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 28780 + replay)
                        .parse()
                        .unwrap(),
                    vote: old_precommits[1].clone(),
                });
            }
            let stale_after = (
                fixture.drivers[0].engine.state.height,
                fixture.drivers[0].engine.state.tip_hash,
                fixture.drivers[0].current_round(),
                fixture.drivers[0].locked_round,
                fixture.drivers[0].locked_value,
                fixture.drivers[0].last_qc_height(),
                fixture.drivers[0].vote_admission_metrics.qc_formations,
            );
            assert_eq!(stale_before, stale_after);

            for driver in &mut fixture.drivers {
                let precommit = driver
                    .on_prevote_timeout()
                    .into_iter()
                    .find_map(|action| match action {
                        DriverAction::BroadcastVote(vote) => Some(vote),
                        _ => None,
                    })
                    .unwrap();
                assert_eq!(
                    (precommit.height, precommit.round, precommit.step, precommit.block_hash),
                    (1, pressure_round, VoteStep::Precommit, Bytes32::ZERO)
                );
                driver.on_precommit_timeout().unwrap();
                assert_eq!(driver.engine.state.height, 0);
                assert_eq!(driver.engine.state.tip_hash, genesis_tip);
                assert_eq!(driver.last_qc_height(), None);
            }
            assert!(fixture.drivers.iter().enumerate().all(|(index, driver)| {
                driver.current_round() == rounds_before[index] + 1
                    && driver.current_phase() == RoundPhase::Propose
            }));
        }

        let (recovery_round, recovery_election, recovery_proposer) = loop {
            let round = fixture.drivers[0].current_round();
            let election = fixture.drivers[0]
                .proposer_election_for_height(1, round)
                .unwrap();
            if let Some(proposer) = (0..4)
                .find(|index| fixture.drivers[*index].engine.is_proposer(&election))
            {
                break (round, election, proposer);
            }
            for driver in &mut fixture.drivers {
                let _ = driver.on_propose_timeout();
                let _ = driver.on_prevote_timeout();
                driver.on_precommit_timeout().unwrap();
                assert_eq!(driver.engine.state.height, 0);
                assert_eq!(driver.last_qc_height(), None);
            }
        };
        let recovery_proposal = fixture.drivers[recovery_proposer]
            .engine
            .propose(
                &recovery_election,
                1_700_031_000 + u64::from(recovery_round),
                vec![],
                None,
            )
            .unwrap();
        let recovery_hash = recovery_proposal.block.header.block_hash();

        // A/B/C accept Q and create genuine production prevotes. D receives
        // A/B votes first, so production buffers one identity each under the
        // missing proposal hash and requests Q only once.
        for driver in fixture.drivers.iter_mut().take(3) {
            driver.process(DriverEvent::InboundBlock {
                from: None,
                proposal: recovery_proposal.clone(),
            });
        }
        let mut recovery_prevotes: Vec<Option<VoteV1>> = vec![None; 4];
        for index in 0..3 {
            let vote = fixture.drivers[index]
                .on_propose_timeout()
                .into_iter()
                .find_map(|action| match action {
                    DriverAction::BroadcastVote(vote) => Some(vote),
                    _ => None,
                })
                .unwrap();
            assert_eq!(
                (vote.validator_id, vote.height, vote.round, vote.step, vote.block_hash),
                (ids[index], 1, recovery_round, VoteStep::Prevote, recovery_hash)
            );
            recovery_prevotes[index] = Some(vote);
        }
        for source in [0usize, 1] {
            let vote = recovery_prevotes[source].clone().unwrap();
            fixture.drivers[3].process(DriverEvent::InboundVote {
                from: format!("127.0.0.1:{}", 28800 + source)
                    .parse()
                    .unwrap(),
                vote: vote.clone(),
            });
            let metrics_after_buffer = fixture.drivers[3].vote_admission_metrics;
            for replay in 0..REPLAY_COUNT {
                fixture.drivers[3].process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 28900 + source * REPLAY_COUNT + replay)
                        .parse()
                        .unwrap(),
                    vote: vote.clone(),
                });
            }
            assert_eq!(fixture.drivers[3].vote_admission_metrics, metrics_after_buffer);
        }
        assert_eq!(
            fixture.drivers[3]
                .buffered_votes
                .get(&(1, recovery_round, recovery_hash))
                .unwrap()
                .len(),
            2
        );
        assert!(fixture.drivers[3]
            .requested_proposals
            .contains(&(1, recovery_round, recovery_hash)));
        assert_eq!(fixture.drivers[3].requested_proposals.len(), 1);
        let proposal_actions = fixture.drivers[3].process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:29000".parse().unwrap()),
            proposal: recovery_proposal.clone(),
        });
        assert!(proposal_actions
            .iter()
            .all(|action| !matches!(action, DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Precommit)));
        assert!(!fixture.drivers[3]
            .buffered_votes
            .contains_key(&(1, recovery_round, recovery_hash)));
        assert!(!fixture.drivers[3]
            .requested_proposals
            .contains(&(1, recovery_round, recovery_hash)));
        let d_actions = fixture.drivers[3].on_propose_timeout();
        let mut d_precommit = None;
        for action in d_actions {
            if let DriverAction::BroadcastVote(vote) = action {
                if vote.step == VoteStep::Prevote {
                    assert_eq!(vote.block_hash, recovery_hash);
                    recovery_prevotes[3] = Some(vote);
                } else if vote.step == VoteStep::Precommit {
                    assert!(d_precommit.replace(vote).is_none());
                }
            }
        }
        assert!(recovery_prevotes[3].is_some());
        assert!(d_precommit.is_some());
        let recovery_prevote_key =
            ConsensusDriver::collector_key(1, recovery_round, VoteStep::Prevote);
        for source in [0usize, 1] {
            let accepted_for_source = fixture.drivers[3]
                .vote_collectors
                .get(&recovery_prevote_key)
                .unwrap()
                .accepted_votes()
                .into_iter()
                .filter(|vote| vote.validator_id == ids[source])
                .count();
            assert_eq!(accepted_for_source, 1);
        }
        for replay in 0..REPLAY_COUNT {
            let actions = fixture.drivers[3].process(DriverEvent::InboundVote {
                from: format!("127.0.0.1:{}", 29100 + replay)
                    .parse()
                    .unwrap(),
                vote: recovery_prevotes[0].clone().unwrap(),
            });
            assert!(actions
                .iter()
                .all(|action| !matches!(action, DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Precommit)));
        }

        // Deliver each real recovery prevote to every observer and capture one
        // production precommit per validator. Replay/load history must not
        // suppress the eventual valid quorum transition.
        let mut recovery_precommits: Vec<Option<VoteV1>> = vec![None; 4];
        recovery_precommits[3] = d_precommit;
        for receiver in 0..4 {
            for source in 0..4 {
                if source == receiver {
                    continue;
                }
                let actions = fixture.drivers[receiver].process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 29200 + source)
                        .parse()
                        .unwrap(),
                    vote: recovery_prevotes[source].clone().unwrap(),
                });
                if let Some(precommit) = actions.into_iter().find_map(|action| match action {
                    DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Precommit => {
                        Some(vote)
                    }
                    _ => None,
                }) {
                    assert!(recovery_precommits[receiver].replace(precommit).is_none());
                }
            }
            assert!(recovery_precommits[receiver].is_some());
            assert_eq!(fixture.drivers[receiver].locked_value, Some(recovery_hash));
        }

        // These are production-path bounds, with no test-side pruning. Replay
        // identity limits one accepted vote per validator/H/R/step; missing
        // non-nil proposal votes are buffered before collector/quorum handling,
        // so `pending_precommit_quorum` cannot accumulate while the proposal is
        // absent. Proposal admission, missing-proposal buffering/requesting,
        // collector creation, and seen-vote admission each run their own bound
        // enforcement. The dedicated L3-NET-12 regression above supplies the
        // direct >256 authenticated proof for `round_advance_evidence`.
        for driver in &fixture.drivers {
            assert!(driver.vote_collectors.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(driver.round_advance_evidence.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(driver.pending_blocks.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(driver.buffered_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(driver.requested_proposals.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(driver.seen_round_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(driver.pending_precommit_quorum.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(driver.pending_precommit_quorum.is_empty());
            assert_eq!(driver.engine.state.height, 0);
            assert_eq!(driver.last_qc_height(), None);
        }

        // Exactly two distinct precommits are insufficient; the third distinct
        // signer independently commits Q on all four drivers.
        for receiver in 0..4 {
            let second = (receiver + 1) % 4;
            fixture.drivers[receiver].process(DriverEvent::InboundVote {
                from: format!("127.0.0.1:{}", 29300 + second)
                    .parse()
                    .unwrap(),
                vote: recovery_precommits[second].clone().unwrap(),
            });
            assert_eq!(fixture.drivers[receiver].engine.state.height, 0);
            assert_eq!(fixture.drivers[receiver].engine.state.tip_hash, genesis_tip);
            assert_eq!(fixture.drivers[receiver].last_qc_height(), None);
            assert!(!matches!(
                fixture.drivers[receiver].vote_decision(
                    1,
                    recovery_round,
                    VoteStep::Precommit,
                ),
                Some(VoteDecision::QuorumReached { .. })
            ));
        }
        for receiver in 0..4 {
            let third = (receiver + 2) % 4;
            fixture.drivers[receiver].process(DriverEvent::InboundVote {
                from: format!("127.0.0.1:{}", 29400 + third)
                    .parse()
                    .unwrap(),
                vote: recovery_precommits[third].clone().unwrap(),
            });
        }

        let canonical_roots = indra_state::compute_state_roots(&fixture.drivers[0].engine.state);
        for driver in &fixture.drivers {
            assert_eq!(driver.engine.state.height, 1);
            assert_eq!(driver.engine.state.tip_hash, recovery_hash);
            assert_eq!(driver.current_round(), 0);
            assert_eq!(driver.current_phase(), RoundPhase::Propose);
            assert_eq!(driver.last_qc_height(), Some(1));
            let roots = indra_state::compute_state_roots(&driver.engine.state);
            assert_eq!(roots.state_root, canonical_roots.state_root);
            assert_eq!(roots.validator_set_root, canonical_roots.validator_set_root);
            let qc = QuorumCertificateV1::decode_exact(&driver.last_qc_bytes()).unwrap();
            assert_eq!((qc.height, qc.round, qc.block_hash), (1, recovery_round, recovery_hash));
            indra_core::types::qc::verify_qc_against_snapshot(
                &qc,
                &snapshot,
                TEST_CHAIN_ID,
            )
            .unwrap();
        }

        let driver = &mut fixture.drivers[0];
        let roots_before = indra_state::compute_state_roots(&driver.engine.state);
        let before = (
            driver.engine.state.height,
            driver.engine.state.tip_hash,
            roots_before.state_root,
            roots_before.validator_set_root,
            driver.last_qc_bytes(),
            driver.last_qc_height(),
            driver.current_round(),
            driver.current_phase(),
            driver.vote_admission_metrics.qc_formations,
        );
        for replay in 0..REPLAY_COUNT {
            driver.process(DriverEvent::InboundBlock {
                from: Some(
                    format!("127.0.0.1:{}", 29500 + replay)
                        .parse()
                        .unwrap(),
                ),
                proposal: initial_proposal.clone(),
            });
            for vote in &initial_prevotes {
                driver.process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 29600 + replay)
                        .parse()
                        .unwrap(),
                    vote: vote.clone(),
                });
            }
            driver.process(DriverEvent::InboundVote {
                from: format!("127.0.0.1:{}", 29700 + replay)
                    .parse()
                    .unwrap(),
                vote: old_precommits[1].clone(),
            });
            driver.process(DriverEvent::InboundVote {
                from: format!("127.0.0.1:{}", 29800 + replay)
                    .parse()
                    .unwrap(),
                vote: old_nil_prevote.clone().unwrap(),
            });
            driver.process(DriverEvent::InboundVote {
                from: format!("127.0.0.1:{}", 29900 + replay)
                    .parse()
                    .unwrap(),
                vote: recovery_precommits[1].clone().unwrap(),
            });
        }
        let roots_after = indra_state::compute_state_roots(&driver.engine.state);
        let after = (
            driver.engine.state.height,
            driver.engine.state.tip_hash,
            roots_after.state_root,
            roots_after.validator_set_root,
            driver.last_qc_bytes(),
            driver.last_qc_height(),
            driver.current_round(),
            driver.current_phase(),
            driver.vote_admission_metrics.qc_formations,
        );
        assert_eq!(before, after);
        assert!(driver.pending_proposal(&initial_hash).is_none());
        assert!(driver.pending_proposal(&recovery_hash).is_none());

        let dirs = fixture.dirs;
        drop(fixture.drivers);
        for dir in dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct MultiSeedChaosDigest {
        seed: u64,
        events: Vec<String>,
        committed_hashes: Vec<Bytes32>,
    }

    fn assert_multiseed_chaos_safety(drivers: &[ConsensusDriver]) {
        let minimum_height = drivers
            .iter()
            .map(|driver| driver.engine.state.height)
            .min()
            .unwrap();
        let maximum_height = drivers
            .iter()
            .map(|driver| driver.engine.state.height)
            .max()
            .unwrap();
        assert!(maximum_height <= minimum_height + 1);

        for left in 0..drivers.len() {
            for right in (left + 1)..drivers.len() {
                if drivers[left].engine.state.height == drivers[right].engine.state.height {
                    assert_eq!(
                        drivers[left].engine.state.tip_hash,
                        drivers[right].engine.state.tip_hash,
                        "honest drivers at the same committed height diverged",
                    );
                }
            }
        }

        let mut locks = BTreeMap::new();
        let mut certified = BTreeMap::new();
        for driver in drivers {
            if let (Some(round), Some(value)) = (driver.locked_round, driver.locked_value) {
                let key = (driver.next_height(), round);
                if let Some(previous) = locks.insert(key, value) {
                    assert_eq!(previous, value, "conflicting honest non-nil locks");
                }
            }
            if !driver.last_qc_bytes().is_empty() {
                let qc = QuorumCertificateV1::decode_exact(&driver.last_qc_bytes()).unwrap();
                if let Some(previous) = certified.insert(qc.height, qc.block_hash) {
                    assert_eq!(previous, qc.block_hash, "conflicting valid QC identities");
                }
            }
            assert!(driver.vote_collectors.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(driver.round_advance_evidence.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(driver.pending_blocks.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(driver.buffered_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(driver.requested_proposals.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(driver.seen_round_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(driver.pending_precommit_quorum.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        }
    }

    fn restart_multiseed_chaos_driver(drivers: &mut Vec<ConsensusDriver>, index: usize) {
        let old = drivers.remove(index);
        let config = old.engine.config.clone();
        drop(old);
        let engine = NodeEngine::init(config).unwrap();
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let mut restarted = ConsensusDriver::new(engine, vote_safety);
        restarted.sync.mark_caught_up(restarted.height());
        drivers.insert(index, restarted);
    }

    fn multiseed_chaos_next(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state
    }

    fn run_four_validator_multiseed_chaos(seed: u64) -> MultiSeedChaosDigest {
        const DUPLICATE_DELIVERIES: usize = 8;
        const MAX_POST_GST_DELIVERY_STEPS: u64 = 2;

        let mut fixture = shared_four_validator_fixture();
        for driver in &mut fixture.drivers {
            driver.sync.mark_caught_up(driver.height());
        }
        let ids: Vec<_> = fixture
            .drivers
            .iter()
            .map(|driver| driver.engine.validator_id().unwrap())
            .collect();
        let mut schedule_state = seed ^ 0xD1B5_4A32_D192_ED03;
        let mut events = vec![format!("seed={seed}:genesis")];
        let mut committed_hashes = Vec::new();
        let mut historical_traffic: Vec<(BlockProposalVNext, VoteV1, VoteV1)> = Vec::new();
        let mut restarted_after_prevote = false;
        let mut restarted_after_lock = false;
        let mut restarted_after_finality = false;

        for height in 1u64..=3 {
            let parent_tip = fixture.drivers[0].engine.state.tip_hash;
            let parent_height = height - 1;
            assert!(fixture.drivers.iter().all(|driver| {
                driver.engine.state.height == parent_height
                    && driver.engine.state.tip_hash == parent_tip
                    && driver.current_round() == 0
                    && driver.current_phase() == RoundPhase::Propose
            }));

            // Every seed exercises a real asynchronous round. Even-numbered
            // schedules keep a deterministic 2+2 partition for two complete
            // rounds; odd schedules model a changing 3+1 isolation and relay
            // topology for one round. No side receives three value identities.
            let disturbed_rounds = if seed % 2 == 0 && height == 1 { 2 } else { 1 };
            for disturbance in 0..disturbed_rounds {
                let round = fixture.drivers[0].current_round();
                assert!(fixture.drivers.iter().all(|driver| {
                    driver.current_round() == round
                        && driver.current_phase() == RoundPhase::Propose
                }));
                let election = fixture.drivers[0]
                    .proposer_election_for_height(height, round)
                    .unwrap();
                let proposer = (0..4)
                    .find(|index| fixture.drivers[*index].engine.is_proposer(&election));
                let isolated = (multiseed_chaos_next(&mut schedule_state) as usize) % 4;
                let first = (isolated + 1) % 4;
                let second = (isolated + 2) % 4;
                let proposal_side = [first, second];
                events.push(format!(
                    "h{height}:r{round}:topology={} isolated={isolated}",
                    if disturbed_rounds == 2 { "2+2" } else { "3+1" },
                ));

                let mut disturbed_proposal = None;
                let mut disturbed_hash = Bytes32::ZERO;
                if let Some(proposer) = proposer {
                    let parent_qc = if height == 1 {
                        vec![]
                    } else {
                        fixture.drivers[proposer].last_qc_bytes()
                    };
                    let proposal = fixture.drivers[proposer]
                        .engine
                        .propose(
                            &election,
                            1_700_100_000
                                + seed * 10_000
                                + height * 100
                                + u64::from(round),
                            parent_qc,
                            None,
                        )
                        .unwrap();
                    disturbed_hash = proposal.block.header.block_hash();
                    for receiver in proposal_side {
                        fixture.drivers[receiver].process(DriverEvent::InboundBlock {
                            from: Some(
                                format!("127.0.0.1:{}", 30_000 + proposer * 10 + receiver)
                                    .parse()
                                    .unwrap(),
                            ),
                            proposal: proposal.clone(),
                        });
                        assert_multiseed_chaos_safety(&fixture.drivers);
                    }
                    events.push(format!(
                        "h{height}:r{round}:proposal-delay:{}",
                        hex::encode(&disturbed_hash.0[..6]),
                    ));
                    disturbed_proposal = Some(proposal);
                } else {
                    events.push(format!("h{height}:r{round}:proposerless-timeout"));
                }

                let mut prevotes = Vec::new();
                for index in 0..4 {
                    let vote = fixture.drivers[index]
                        .on_propose_timeout()
                        .into_iter()
                        .find_map(|action| match action {
                            DriverAction::BroadcastVote(vote) => Some(vote),
                            _ => None,
                        })
                        .unwrap();
                    assert_eq!((vote.height, vote.round, vote.step), (height, round, VoteStep::Prevote));
                    if disturbed_proposal.is_some() && proposal_side.contains(&index) {
                        assert_eq!(vote.block_hash, disturbed_hash);
                    } else {
                        assert_eq!(vote.block_hash, Bytes32::ZERO);
                    }
                    prevotes.push(vote);
                    assert_multiseed_chaos_safety(&fixture.drivers);
                }

                // Deterministic 2+2 routing: the exact same signed vote may be
                // duplicated on a relay edge, but only the opposite member of
                // each pair receives it. No collector can obtain three voter
                // identities and duplicates cannot manufacture stake.
                let pair_offset = (multiseed_chaos_next(&mut schedule_state) as usize) & 1;
                let routes: Vec<(usize, usize)> = if disturbed_rounds == 2 {
                    let pairs = if pair_offset == 0 {
                        [[0usize, 1usize], [2usize, 3usize]]
                    } else {
                        [[0usize, 2usize], [1usize, 3usize]]
                    };
                    pairs
                        .into_iter()
                        .flat_map(|pair| [(pair[0], pair[1]), (pair[1], pair[0])])
                        .collect()
                } else {
                    // The isolated validator has no route. The connected trio
                    // is rewired as a directed relay chain for this delivery
                    // epoch; only two value identities are visible anywhere.
                    vec![(first, second), (second, (isolated + 3) % 4)]
                };
                for (source, receiver) in routes.iter().copied() {
                    fixture.drivers[receiver].process(DriverEvent::InboundVote {
                        from: format!("127.0.0.1:{}", 30_100 + source * 10 + receiver)
                            .parse()
                            .unwrap(),
                        vote: prevotes[source].clone(),
                    });
                    if (seed + height + disturbance) % 2 == 0 {
                        for duplicate in 0..2 {
                            fixture.drivers[receiver].process(DriverEvent::InboundVote {
                                from: format!(
                                    "127.0.0.1:{}",
                                    30_200 + duplicate + source * 10 + receiver
                                )
                                .parse()
                                .unwrap(),
                                vote: prevotes[source].clone(),
                            });
                        }
                    }
                    assert_multiseed_chaos_safety(&fixture.drivers);
                }
                for driver in &fixture.drivers {
                    assert_eq!(driver.engine.state.height, parent_height);
                    assert_eq!(driver.engine.state.tip_hash, parent_tip);
                    assert_eq!(driver.last_qc_height(), height.checked_sub(1).filter(|h| *h > 0));
                    assert!(driver.locked_round.is_none());
                    assert!(driver.locked_value.is_none());
                }

                // Seed zero supplies the campaign's restart-after-prevote
                // boundary. Reopening from the same durable directory advances
                // only that driver to the next safe round; its peers reach the
                // same round through their ordinary timeout path.
                let restart_after_prevote = seed == 0 && height == 1 && disturbance == 0;
                let restart_index = isolated;
                if restart_after_prevote {
                    restart_multiseed_chaos_driver(&mut fixture.drivers, restart_index);
                    restarted_after_prevote = true;
                    events.push(format!("h{height}:r{round}:restart-after-prevote:{restart_index}"));
                    assert_eq!(fixture.drivers[restart_index].current_round(), round + 1);
                    assert_multiseed_chaos_safety(&fixture.drivers);
                }

                let mut nil_precommits = Vec::new();
                for index in 0..4 {
                    if restart_after_prevote && index == restart_index {
                        continue;
                    }
                    let vote = fixture.drivers[index]
                        .on_prevote_timeout()
                        .into_iter()
                        .find_map(|action| match action {
                            DriverAction::BroadcastVote(vote) => Some(vote),
                            _ => None,
                        })
                        .unwrap();
                    assert_eq!(
                        (vote.height, vote.round, vote.step, vote.block_hash),
                        (height, round, VoteStep::Precommit, Bytes32::ZERO),
                    );
                    nil_precommits.push((index, vote));
                    assert_multiseed_chaos_safety(&fixture.drivers);
                }
                for (source, receiver) in routes.iter().copied() {
                    if restart_after_prevote && source == restart_index {
                        continue;
                    }
                    let vote = nil_precommits
                        .iter()
                        .find(|(index, _)| *index == source)
                        .unwrap()
                        .1
                        .clone();
                    fixture.drivers[receiver].process(DriverEvent::InboundVote {
                        from: format!("127.0.0.1:{}", 30_300 + source * 10 + receiver)
                            .parse()
                            .unwrap(),
                        vote,
                    });
                    assert_multiseed_chaos_safety(&fixture.drivers);
                }
                for index in 0..4 {
                    if restart_after_prevote && index == restart_index {
                        continue;
                    }
                    fixture.drivers[index].on_precommit_timeout().unwrap();
                    assert_multiseed_chaos_safety(&fixture.drivers);
                }
                assert!(fixture.drivers.iter().all(|driver| {
                    driver.engine.state.height == parent_height
                        && driver.engine.state.tip_hash == parent_tip
                        && driver.last_qc_height()
                            == height.checked_sub(1).filter(|previous| *previous > 0)
                        && driver.current_round() == round + 1
                        && driver.current_phase() == RoundPhase::Propose
                }));

                if let (Some(proposal), Some((_, nil_precommit))) =
                    (disturbed_proposal, nil_precommits.first())
                {
                    historical_traffic.push((proposal, prevotes[0].clone(), nil_precommit.clone()));
                }
                events.push(format!("h{height}:r{round}:no-commit"));
            }

            // Seed one exercises restart after a genuine non-nil lock and
            // precommit. All four first obtain a production PoLC, the selected
            // driver is reopened from its durable lock, and the other three
            // enter the same next round via on_precommit_timeout().
            let lock_restart_mode = seed == 1 && height == 2;
            let mut reproposal_source = None;
            if lock_restart_mode {
                let (round, election, proposer) = loop {
                    let round = fixture.drivers[0].current_round();
                    let election = fixture.drivers[0]
                        .proposer_election_for_height(height, round)
                        .unwrap();
                    if let Some(proposer) =
                        (0..4).find(|index| fixture.drivers[*index].engine.is_proposer(&election))
                    {
                        break (round, election, proposer);
                    }
                    for driver in &mut fixture.drivers {
                        let _ = driver.on_propose_timeout();
                        let _ = driver.on_prevote_timeout();
                        driver.on_precommit_timeout().unwrap();
                    }
                    assert_multiseed_chaos_safety(&fixture.drivers);
                };
                let parent_qc = fixture.drivers[proposer].last_qc_bytes();
                let proposal = fixture.drivers[proposer]
                    .engine
                    .propose(
                        &election,
                        1_700_150_000 + seed * 1_000 + height * 100 + u64::from(round),
                        parent_qc,
                        None,
                    )
                    .unwrap();
                let hash = proposal.block.header.block_hash();
                for driver in &mut fixture.drivers {
                    driver.process(DriverEvent::InboundBlock {
                        from: None,
                        proposal: proposal.clone(),
                    });
                }
                let prevotes: Vec<_> = fixture
                    .drivers
                    .iter_mut()
                    .map(|driver| {
                        driver
                            .on_propose_timeout()
                            .into_iter()
                            .find_map(|action| match action {
                                DriverAction::BroadcastVote(vote) => Some(vote),
                                _ => None,
                            })
                            .unwrap()
                    })
                    .collect();
                let mut precommits: Vec<Option<VoteV1>> = vec![None; 4];
                for receiver in 0..4 {
                    for source in 0..4 {
                        if source == receiver {
                            continue;
                        }
                        let actions = fixture.drivers[receiver].process(DriverEvent::InboundVote {
                            from: format!("127.0.0.1:{}", 30_400 + source * 10 + receiver)
                                .parse()
                                .unwrap(),
                            vote: prevotes[source].clone(),
                        });
                        if let Some(vote) = actions.into_iter().find_map(|action| match action {
                            DriverAction::BroadcastVote(vote)
                                if vote.step == VoteStep::Precommit => Some(vote),
                            _ => None,
                        }) {
                            precommits[receiver] = Some(vote);
                        }
                    }
                    assert_eq!(fixture.drivers[receiver].locked_value, Some(hash));
                    assert!(precommits[receiver].is_some());
                }
                let restart_index =
                    (multiseed_chaos_next(&mut schedule_state) as usize) % fixture.drivers.len();
                restart_multiseed_chaos_driver(&mut fixture.drivers, restart_index);
                restarted_after_lock = true;
                events.push(format!("h{height}:r{round}:restart-after-lock:{restart_index}"));
                assert_eq!(fixture.drivers[restart_index].locked_value, Some(hash));
                assert_eq!(fixture.drivers[restart_index].current_round(), round + 1);
                for index in 0..4 {
                    if index != restart_index {
                        fixture.drivers[index].on_precommit_timeout().unwrap();
                    }
                }
                assert!(fixture.drivers.iter().all(|driver| {
                    driver.current_round() == round + 1
                        && driver.current_phase() == RoundPhase::Propose
                        && driver.locked_value == Some(hash)
                }));
                for driver in &mut fixture.drivers {
                    driver.process(DriverEvent::InboundBlock {
                        from: None,
                        proposal: proposal.clone(),
                    });
                    for (source, vote) in prevotes.iter().take(3).enumerate() {
                        driver.process(DriverEvent::InboundVote {
                            from: format!("127.0.0.1:{}", 30_500 + source)
                                .parse()
                                .unwrap(),
                            vote: vote.clone(),
                        });
                    }
                    assert_eq!(driver.valid_value, Some(hash));
                }
                historical_traffic.push((
                    proposal,
                    prevotes[0].clone(),
                    precommits[0].clone().unwrap(),
                ));
                reproposal_source = Some((hash, round));
                assert_multiseed_chaos_safety(&fixture.drivers);
            }

            // The post-disturbance network is a deterministic bounded-delivery
            // model. Proposer-less rounds still broadcast and deliver every
            // production nil vote before advancing; no traffic is discarded.
            let (recovery_round, election, proposer) = loop {
                let round = fixture.drivers[0].current_round();
                assert!(fixture.drivers.iter().all(|driver| {
                    driver.current_round() == round
                        && driver.current_phase() == RoundPhase::Propose
                }));
                let election = fixture.drivers[0]
                    .proposer_election_for_height(height, round)
                    .unwrap();
                if let Some(proposer) =
                    (0..4).find(|index| fixture.drivers[*index].engine.is_proposer(&election))
                {
                    break (round, election, proposer);
                }
                let nil_prevotes: Vec<_> = fixture
                    .drivers
                    .iter_mut()
                    .map(|driver| {
                        driver
                            .on_propose_timeout()
                            .into_iter()
                            .find_map(|action| match action {
                                DriverAction::BroadcastVote(vote) => Some(vote),
                                _ => None,
                            })
                            .unwrap()
                    })
                    .collect();
                let mut nil_precommits: Vec<Option<VoteV1>> = vec![None; 4];
                for receiver in 0..4 {
                    for source in 0..4 {
                        if source != receiver {
                            let actions = fixture.drivers[receiver].process(DriverEvent::InboundVote {
                                from: format!("127.0.0.1:{}", 30_600 + source * 10 + receiver)
                                    .parse()
                                    .unwrap(),
                                vote: nil_prevotes[source].clone(),
                            });
                            if let Some(vote) = actions.into_iter().find_map(|action| match action {
                                DriverAction::BroadcastVote(vote)
                                    if vote.step == VoteStep::Precommit => Some(vote),
                                _ => None,
                            }) {
                                nil_precommits[receiver] = Some(vote);
                            }
                        }
                    }
                }
                for (index, driver) in fixture.drivers.iter_mut().enumerate() {
                    if nil_precommits[index].is_none() {
                        nil_precommits[index] = driver
                            .on_prevote_timeout()
                            .into_iter()
                            .find_map(|action| match action {
                                DriverAction::BroadcastVote(vote) => Some(vote),
                                _ => None,
                            });
                    }
                    assert!(nil_precommits[index].is_some());
                }
                for receiver in 0..4 {
                    for source in 0..4 {
                        if source != receiver {
                            fixture.drivers[receiver].process(DriverEvent::InboundVote {
                                from: format!("127.0.0.1:{}", 30_700 + source * 10 + receiver)
                                    .parse()
                                    .unwrap(),
                                vote: nil_precommits[source].clone().unwrap(),
                            });
                        }
                    }
                }
                for driver in &mut fixture.drivers {
                    driver.on_precommit_timeout().unwrap();
                }
                events.push(format!("h{height}:r{round}:bounded-empty-round"));
                assert_multiseed_chaos_safety(&fixture.drivers);
            };

            let proposal = if let Some((locked_hash, valid_round)) = reproposal_source {
                let (block, retained_round) = fixture.drivers[proposer]
                    .take_valid_block_for_reproposal()
                    .unwrap();
                assert_eq!(retained_round, valid_round);
                assert_eq!(block.header.block_hash(), locked_hash);
                let timestamp = block.header.timestamp;
                let last_qc = fixture.drivers[proposer].last_qc_bytes();
                fixture.drivers[proposer]
                    .engine
                    .repropose(
                        &block,
                        recovery_round,
                        Some(valid_round),
                        &election,
                        timestamp,
                        last_qc,
                    )
                    .unwrap()
            } else {
                let parent_qc = if height == 1 {
                    vec![]
                } else {
                    fixture.drivers[proposer].last_qc_bytes()
                };
                fixture.drivers[proposer]
                    .engine
                    .propose(
                        &election,
                        1_700_200_000
                            + seed * 10_000
                            + height * 100
                            + u64::from(recovery_round),
                        parent_qc,
                        None,
                    )
                    .unwrap()
            };
            let recovery_hash = proposal.block.header.block_hash();
            assert_eq!(proposal.block.header.height, height);
            assert_eq!(proposal.block.header.prev_hash, parent_tip);
            if height > 1 {
                let parent_qc = QuorumCertificateV1::decode_exact(
                    proposal.block.header.quorum_certificate.as_slice(),
                )
                .unwrap();
                assert_eq!((parent_qc.height, parent_qc.block_hash), (height - 1, parent_tip));
                let parent_snapshot = fixture.drivers[0]
                    .engine
                    .state
                    .snapshot_for_consensus_height(height - 1)
                    .unwrap();
                indra_core::types::qc::verify_qc_against_snapshot(
                    &parent_qc,
                    parent_snapshot,
                    TEST_CHAIN_ID,
                )
                .unwrap();
            }

            let mut order = [0usize, 1, 2, 3];
            order.rotate_left((multiseed_chaos_next(&mut schedule_state) as usize) % 4);
            if multiseed_chaos_next(&mut schedule_state) & 1 == 1 {
                order.reverse();
            }
            let vote_before_proposal = order[3];
            let emitted_proposal_step = 0u64;
            let mut delivered_step = 0u64;
            for receiver in order.iter().copied().filter(|index| *index != vote_before_proposal) {
                delivered_step += 1;
                let message_delivery_step = emitted_proposal_step + 1;
                assert!(message_delivery_step - emitted_proposal_step <= MAX_POST_GST_DELIVERY_STEPS);
                fixture.drivers[receiver].process(DriverEvent::InboundBlock {
                    from: Some(
                        format!("127.0.0.1:{}", 30_800 + proposer * 10 + receiver)
                            .parse()
                            .unwrap(),
                    ),
                    proposal: proposal.clone(),
                });
                assert!(fixture.drivers[receiver]
                    .pending_proposal(&recovery_hash)
                    .is_some());
                assert_multiseed_chaos_safety(&fixture.drivers);
            }
            events.push(format!(
                "h{height}:r{recovery_round}:recovery-proposal:{}:proposer={}",
                hex::encode(&recovery_hash.0[..6]),
                hex::encode(&ids[proposer].0[..6]),
            ));

            let mut prevotes: Vec<Option<VoteV1>> = vec![None; 4];
            for index in order.iter().copied().filter(|index| *index != vote_before_proposal) {
                let vote = fixture.drivers[index]
                    .on_propose_timeout()
                    .into_iter()
                    .find_map(|action| match action {
                        DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Prevote => {
                            Some(vote)
                        }
                        _ => None,
                    })
                    .unwrap();
                assert_eq!(
                    (vote.validator_id, vote.height, vote.round, vote.block_hash),
                    (ids[index], height, recovery_round, recovery_hash),
                );
                prevotes[index] = Some(vote);
            }

            let buffer_sources: Vec<_> = order
                .iter()
                .copied()
                .filter(|index| *index != vote_before_proposal)
                .take(2)
                .collect();
            for source in &buffer_sources {
                delivered_step += 1;
                let emitted_step = delivered_step - 1;
                assert!(delivered_step - emitted_step <= MAX_POST_GST_DELIVERY_STEPS);
                fixture.drivers[vote_before_proposal].process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 30_900 + source)
                        .parse()
                        .unwrap(),
                    vote: prevotes[*source].clone().unwrap(),
                });
            }
            assert!(fixture.drivers[vote_before_proposal]
                .buffered_votes
                .contains_key(&(height, recovery_round, recovery_hash)));
            delivered_step += 1;
            assert!(1 <= MAX_POST_GST_DELIVERY_STEPS);
            fixture.drivers[vote_before_proposal].process(DriverEvent::InboundBlock {
                from: Some(
                    format!("127.0.0.1:{}", 31_000 + proposer * 10 + vote_before_proposal)
                        .parse()
                        .unwrap(),
                ),
                proposal: proposal.clone(),
            });
            assert!(!fixture.drivers[vote_before_proposal]
                .buffered_votes
                .contains_key(&(height, recovery_round, recovery_hash)));
            let delayed_actions = fixture.drivers[vote_before_proposal].on_propose_timeout();
            let mut early_precommit = None;
            for action in delayed_actions {
                if let DriverAction::BroadcastVote(vote) = action {
                    if vote.step == VoteStep::Prevote {
                        prevotes[vote_before_proposal] = Some(vote);
                    } else if vote.step == VoteStep::Precommit {
                        early_precommit = Some(vote);
                    }
                }
            }
            assert!(prevotes.iter().all(Option::is_some));

            // Exact proposal and vote relays arrive through different peer
            // addresses. Metrics and collector identity prove that replay does
            // not gain stake or repeat expensive authenticated admission.
            let replay_receiver = (vote_before_proposal + 1) % 4;
            let proposal_metrics = fixture.drivers[replay_receiver].proposal_admission_metrics;
            for duplicate in 0..DUPLICATE_DELIVERIES {
                fixture.drivers[replay_receiver].process(DriverEvent::InboundBlock {
                    from: Some(
                        format!("127.0.0.1:{}", 31_100 + duplicate)
                            .parse()
                            .unwrap(),
                    ),
                    proposal: proposal.clone(),
                });
            }
            assert_eq!(
                fixture.drivers[replay_receiver].proposal_admission_metrics,
                proposal_metrics,
            );
            let replay_source = (replay_receiver + 1) % 4;
            let first_actions = fixture.drivers[replay_receiver].process(
                DriverEvent::InboundVote {
                    from: "127.0.0.1:31200".parse().unwrap(),
                    vote: prevotes[replay_source].clone().unwrap(),
                },
            );
            let vote_metrics = fixture.drivers[replay_receiver].vote_admission_metrics;
            for duplicate in 0..DUPLICATE_DELIVERIES {
                let actions = fixture.drivers[replay_receiver].process(
                    DriverEvent::InboundVote {
                        from: format!("127.0.0.1:{}", 31_201 + duplicate)
                            .parse()
                            .unwrap(),
                        vote: prevotes[replay_source].clone().unwrap(),
                    },
                );
                assert!(actions.iter().all(|action| {
                    !matches!(action, DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Precommit)
                }));
            }
            assert_eq!(fixture.drivers[replay_receiver].vote_admission_metrics, vote_metrics);
            let _ = first_actions;

            let mut precommits: Vec<Option<VoteV1>> = vec![None; 4];
            precommits[vote_before_proposal] = early_precommit;
            for receiver in 0..4 {
                let mut sources = [0usize, 1, 2, 3];
                sources.rotate_left((receiver + seed as usize + height as usize) % 4);
                for source in sources {
                    if source == receiver {
                        continue;
                    }
                    delivered_step += 1;
                    let emitted_step = delivered_step - 1;
                    assert!(delivered_step - emitted_step <= MAX_POST_GST_DELIVERY_STEPS);
                    let actions = fixture.drivers[receiver].process(DriverEvent::InboundVote {
                        from: format!("127.0.0.1:{}", 31_300 + source * 10 + receiver)
                            .parse()
                            .unwrap(),
                        vote: prevotes[source].clone().unwrap(),
                    });
                    if let Some(vote) = actions.into_iter().find_map(|action| match action {
                        DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Precommit => {
                            Some(vote)
                        }
                        _ => None,
                    }) {
                        assert!(precommits[receiver].replace(vote).is_none());
                    }
                    assert_multiseed_chaos_safety(&fixture.drivers);
                }
                assert_eq!(fixture.drivers[receiver].locked_value, Some(recovery_hash));
                assert!(precommits[receiver].is_some());
            }

            // One local and one remote precommit is exactly 2/4 and cannot
            // finalize. A second distinct remote identity crosses 3/4. No
            // duplicate relay may substitute for this third signer.
            for receiver in 0..4 {
                let second = (receiver + 1) % 4;
                delivered_step += 1;
                let emitted_step = delivered_step - 1;
                assert!(delivered_step - emitted_step <= MAX_POST_GST_DELIVERY_STEPS);
                fixture.drivers[receiver].process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 31_400 + second * 10 + receiver)
                        .parse()
                        .unwrap(),
                    vote: precommits[second].clone().unwrap(),
                });
                assert_eq!(fixture.drivers[receiver].engine.state.height, parent_height);
                assert_eq!(fixture.drivers[receiver].engine.state.tip_hash, parent_tip);
                assert!(!matches!(
                    fixture.drivers[receiver].vote_decision(
                        height,
                        recovery_round,
                        VoteStep::Precommit,
                    ),
                    Some(VoteDecision::QuorumReached { .. })
                ));
                assert_multiseed_chaos_safety(&fixture.drivers);
            }
            for receiver in 0..4 {
                let third = (receiver + 2) % 4;
                delivered_step += 1;
                let emitted_step = delivered_step - 1;
                assert!(delivered_step - emitted_step <= MAX_POST_GST_DELIVERY_STEPS);
                fixture.drivers[receiver].process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 31_500 + third * 10 + receiver)
                        .parse()
                        .unwrap(),
                    vote: precommits[third].clone().unwrap(),
                });
                assert_multiseed_chaos_safety(&fixture.drivers);
            }

            let canonical_roots = indra_state::compute_state_roots(&fixture.drivers[0].engine.state);
            let snapshot = fixture.drivers[0]
                .engine
                .state
                .snapshot_for_consensus_height(height)
                .unwrap()
                .clone();
            for driver in &fixture.drivers {
                assert_eq!(driver.engine.state.height, height);
                assert_eq!(driver.engine.state.tip_hash, recovery_hash);
                assert_eq!(driver.current_round(), 0);
                assert_eq!(driver.current_phase(), RoundPhase::Propose);
                assert_eq!(driver.last_qc_height(), Some(height));
                let roots = indra_state::compute_state_roots(&driver.engine.state);
                assert_eq!(roots.state_root, canonical_roots.state_root);
                assert_eq!(roots.validator_set_root, canonical_roots.validator_set_root);
                let qc = QuorumCertificateV1::decode_exact(&driver.last_qc_bytes()).unwrap();
                assert_eq!(
                    (qc.height, qc.round, qc.block_hash),
                    (height, recovery_round, recovery_hash),
                );
                indra_core::types::qc::verify_qc_against_snapshot(
                    &qc,
                    &snapshot,
                    TEST_CHAIN_ID,
                )
                .unwrap();
                assert!(matches!(driver.vote_safety.load(), VoteSafetyLoadResult::NoRecord));
            }
            committed_hashes.push(recovery_hash);
            historical_traffic.push((
                proposal.clone(),
                prevotes[0].clone().unwrap(),
                precommits[0].clone().unwrap(),
            ));
            events.push(format!(
                "h{height}:commit:{}:round={recovery_round}:steps={delivered_step}",
                hex::encode(&recovery_hash.0[..6]),
            ));

            // Across the eight seeds this covers restart after finality and a
            // two-validator staggered restart at different committed heights.
            let finality_restart_indexes: Vec<usize> = match (seed, height) {
                (2, 1) => vec![2],
                (6, 1) => vec![0],
                (6, 2) => vec![2],
                _ => Vec::new(),
            };
            for index in finality_restart_indexes {
                let qc_before = fixture.drivers[index].last_qc_bytes();
                restart_multiseed_chaos_driver(&mut fixture.drivers, index);
                restarted_after_finality = true;
                assert_eq!(fixture.drivers[index].engine.state.height, height);
                assert_eq!(fixture.drivers[index].engine.state.tip_hash, recovery_hash);
                assert_eq!(fixture.drivers[index].last_qc_bytes(), qc_before);
                assert_eq!(fixture.drivers[index].current_round(), 0);
                assert_eq!(fixture.drivers[index].current_phase(), RoundPhase::Propose);
                events.push(format!("h{height}:restart-after-finality:{index}"));
                assert_multiseed_chaos_safety(&fixture.drivers);
            }
        }

        assert_eq!(committed_hashes.len(), 3);
        let final_tip = committed_hashes[2];
        let final_roots = indra_state::compute_state_roots(&fixture.drivers[0].engine.state);
        for driver in &fixture.drivers {
            assert_eq!(driver.engine.state.height, 3);
            assert_eq!(driver.engine.state.tip_hash, final_tip);
            assert_eq!(driver.current_round(), 0);
            assert_eq!(driver.current_phase(), RoundPhase::Propose);
            assert_eq!(driver.last_qc_height(), Some(3));
            let roots = indra_state::compute_state_roots(&driver.engine.state);
            assert_eq!(roots.state_root, final_roots.state_root);
            assert_eq!(roots.validator_set_root, final_roots.validator_set_root);
            let qc = QuorumCertificateV1::decode_exact(&driver.last_qc_bytes()).unwrap();
            assert_eq!((qc.height, qc.block_hash), (3, final_tip));
            let snapshot = driver
                .engine
                .state
                .snapshot_for_consensus_height(3)
                .unwrap();
            indra_core::types::qc::verify_qc_against_snapshot(
                &qc,
                snapshot,
                TEST_CHAIN_ID,
            )
            .unwrap();
        }

        // A deterministic stale flood includes genuine proposals, prevotes,
        // and precommits from H1, H2, and old H3 rounds. It is shuffled only by
        // the seeded state machine and must leave the entire committed identity
        // and QC-formation count unchanged.
        let driver = &mut fixture.drivers[0];
        let roots_before = indra_state::compute_state_roots(&driver.engine.state);
        let before = (
            driver.engine.state.height,
            driver.engine.state.tip_hash,
            roots_before.state_root,
            roots_before.validator_set_root,
            driver.last_qc_bytes(),
            driver.last_qc_height(),
            driver.current_round(),
            driver.current_phase(),
            driver.vote_admission_metrics.qc_formations,
        );
        let mut stale_order: Vec<_> = (0..historical_traffic.len()).collect();
        if multiseed_chaos_next(&mut schedule_state) & 1 == 1 {
            stale_order.reverse();
        }
        if !stale_order.is_empty() {
            let shift = (multiseed_chaos_next(&mut schedule_state) as usize) % stale_order.len();
            stale_order.rotate_left(shift);
        }
        for replay in 0..DUPLICATE_DELIVERIES {
            for index in &stale_order {
                let (proposal, prevote, precommit) = &historical_traffic[*index];
                driver.process(DriverEvent::InboundBlock {
                    from: Some(
                        format!("127.0.0.1:{}", 31_600 + replay * 100 + index)
                            .parse()
                            .unwrap(),
                    ),
                    proposal: proposal.clone(),
                });
                driver.process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 31_700 + replay * 100 + index)
                        .parse()
                        .unwrap(),
                    vote: prevote.clone(),
                });
                driver.process(DriverEvent::InboundVote {
                    from: format!("127.0.0.1:{}", 31_800 + replay * 100 + index)
                        .parse()
                        .unwrap(),
                    vote: precommit.clone(),
                });
            }
        }
        let roots_after = indra_state::compute_state_roots(&driver.engine.state);
        let after = (
            driver.engine.state.height,
            driver.engine.state.tip_hash,
            roots_after.state_root,
            roots_after.validator_set_root,
            driver.last_qc_bytes(),
            driver.last_qc_height(),
            driver.current_round(),
            driver.current_phase(),
            driver.vote_admission_metrics.qc_formations,
        );
        assert_eq!(before, after);
        for hash in &committed_hashes {
            assert!(driver.pending_proposal(hash).is_none());
        }
        events.push(format!("stale-flood:{}:no-op", historical_traffic.len()));

        if seed == 0 {
            assert!(restarted_after_prevote);
        }
        if seed == 1 {
            assert!(restarted_after_lock);
        }
        if seed == 2 || seed == 6 {
            assert!(restarted_after_finality);
        }

        let dirs = fixture.dirs;
        drop(fixture.drivers);
        for dir in dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
        MultiSeedChaosDigest {
            seed,
            events,
            committed_hashes,
        }
    }

    #[test]
    fn audit_harness_four_validator_multiseed_chaos_converges() {
        let mut first_pass = Vec::new();
        for seed in 0u64..8 {
            first_pass.push(run_four_validator_multiseed_chaos(seed));
        }

        // Exact schedule replay for two separated seeds proves that both the
        // event ordering and all three committed identities are deterministic.
        for seed in [0u64, 7u64] {
            let repeated = run_four_validator_multiseed_chaos(seed);
            assert_eq!(repeated, first_pass[seed as usize]);
        }
    }

    #[test]
    fn audit_collection_bounds_valid_traffic_pressure_production_admission() {
        let mut fixture = shared_four_validator_fixture();
        for driver in &mut fixture.drivers {
            driver.sync.mark_caught_up(driver.height());
        }

        let remote_validator_id = Bytes32::from(fixture.materials[0].validator_id);
        let remote_signer = HybridKeypair::new(
            ClassicalKeypair::from_seed(&fixture.materials[0].seed),
            fixture.materials[0].pq.clone(),
        );
        let snapshot_root = fixture.drivers[3]
            .engine
            .state
            .snapshot_for_consensus_height(1)
            .unwrap()
            .snapshot_root;
        let chain_id = fixture.drivers[3].engine.state.chain_id.clone();
        let genesis_tip = fixture.drivers[3].engine.state.tip_hash;

        // One authenticated remote vote at each legal current round creates a
        // distinct round-advance-evidence key. The observer moves between
        // rounds only through its production nil-prevote/nil-precommit timeout
        // path. At every insertion boundary, verify that automatic admission
        // pruning—not an explicit test-side prune—keeps every collection at or
        // below its advertised stalled-height cap.
        let mut authenticated_round_insertions = 0usize;
        for expected_round in 0..=(MAX_STALLED_HEIGHT_ENTRIES as u32) {
            let observer = &mut fixture.drivers[3];
            assert_eq!(observer.current_round(), expected_round);
            assert_eq!(observer.current_phase(), RoundPhase::Propose);

            let remote_prevote = indra_consensus::vote::produce_vote(
                1,
                expected_round,
                VoteStep::Prevote,
                Bytes32::ZERO,
                remote_validator_id,
                snapshot_root,
                &chain_id,
                &remote_signer,
            )
            .unwrap();
            observer.process(DriverEvent::InboundVote {
                from: "127.0.0.1:29990".parse().unwrap(),
                vote: remote_prevote,
            });
            authenticated_round_insertions += 1;

            assert!(observer.vote_collectors.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(observer.pending_blocks.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(observer.buffered_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(observer.requested_proposals.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(observer.seen_round_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(observer.pending_precommit_quorum.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(
                observer.round_advance_evidence.len() <= MAX_STALLED_HEIGHT_ENTRIES,
                "authenticated admission left round_advance_evidence above its cap at round {}: {} > {}",
                expected_round,
                observer.round_advance_evidence.len(),
                MAX_STALLED_HEIGHT_ENTRIES,
            );

            let local_prevotes: Vec<_> = observer
                .on_propose_timeout()
                .into_iter()
                .filter_map(|action| match action {
                    DriverAction::BroadcastVote(vote) => Some(vote),
                    _ => None,
                })
                .collect();
            assert_eq!(local_prevotes.len(), 1);
            assert_eq!(
                (
                    local_prevotes[0].height,
                    local_prevotes[0].round,
                    local_prevotes[0].step,
                    local_prevotes[0].block_hash,
                ),
                (1, expected_round, VoteStep::Prevote, Bytes32::ZERO),
            );
            assert!(observer.vote_collectors.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(observer.seen_round_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES);

            let local_precommits: Vec<_> = observer
                .on_prevote_timeout()
                .into_iter()
                .filter_map(|action| match action {
                    DriverAction::BroadcastVote(vote) => Some(vote),
                    _ => None,
                })
                .collect();
            assert_eq!(local_precommits.len(), 1);
            assert_eq!(
                (
                    local_precommits[0].height,
                    local_precommits[0].round,
                    local_precommits[0].step,
                    local_precommits[0].block_hash,
                ),
                (1, expected_round, VoteStep::Precommit, Bytes32::ZERO),
            );
            assert!(observer.vote_collectors.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert!(observer.seen_round_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            assert_eq!(observer.engine.state.height, 0);
            assert_eq!(observer.engine.state.tip_hash, genesis_tip);
            assert_eq!(observer.last_qc_height(), None);

            if expected_round < MAX_STALLED_HEIGHT_ENTRIES as u32 {
                observer.on_precommit_timeout().unwrap();
            }
        }

        assert_eq!(
            authenticated_round_insertions,
            MAX_STALLED_HEIGHT_ENTRIES + 1,
        );

        let observer = &mut fixture.drivers[3];
        let pressure_round = observer.current_round();
        let minimum_retained_round = pressure_round.saturating_sub(MAX_ACCEPTED_ROUND_JUMP);
        let maximum_retained_round = pressure_round
            .checked_add(MAX_ACCEPTED_ROUND_JUMP)
            .unwrap_or(u32::MAX)
            .min(MAX_ROUNDS_PER_HEIGHT - 1);
        assert!(observer.round_advance_evidence.keys().all(|(height, round)| {
            *height == 1
                && *round >= minimum_retained_round
                && *round <= maximum_retained_round
        }));
        assert!(
            observer.round_advance_evidence.len()
                <= (MAX_ACCEPTED_ROUND_JUMP as usize * 2 + 1)
        );
        assert!(!observer.round_advance_evidence.contains_key(&(1, 0)));

        // Pruning stale minority evidence must retain a newly admissible
        // certificate. Three distinct, authenticated validator identities at
        // the next legal round cross strict 3/4 stake through the ordinary
        // inbound-vote path and advance the observer without direct mutation.
        let target_round = pressure_round + 1;
        assert!(target_round <= maximum_retained_round);
        for signer_index in 0..3 {
            let signer = HybridKeypair::new(
                ClassicalKeypair::from_seed(&fixture.materials[signer_index].seed),
                fixture.materials[signer_index].pq.clone(),
            );
            let vote = indra_consensus::vote::produce_vote(
                1,
                target_round,
                VoteStep::Prevote,
                Bytes32::ZERO,
                Bytes32::from(fixture.materials[signer_index].validator_id),
                snapshot_root,
                &chain_id,
                &signer,
            )
            .unwrap();
            observer.process(DriverEvent::InboundVote {
                from: format!("127.0.0.1:{}", 29991 + signer_index)
                    .parse()
                    .unwrap(),
                vote,
            });
            assert!(observer.round_advance_evidence.len() <= MAX_STALLED_HEIGHT_ENTRIES);
            if signer_index < 2 {
                assert_eq!(observer.current_round(), pressure_round);
            }
        }
        assert_eq!(observer.current_round(), target_round);
        assert_eq!(observer.current_phase(), RoundPhase::Propose);
        assert_eq!(observer.engine.state.height, 0);
        assert_eq!(observer.engine.state.tip_hash, genesis_tip);
        assert_eq!(observer.last_qc_height(), None);

        let dirs = fixture.dirs;
        drop(fixture.drivers);
        for dir in dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn audit_fixture_shared_genesis_rejects_non_authority_local_validator() {
        let (_driver, dir) = local_driver([0xA1; 32], "shared_non_authority");
        let c = test_validator_material([0xC3; 32]);
        let mut config = NodeConfig::local_test(dir.clone());
        config.genesis_path = Some(dir.join("genesis.toml").to_string_lossy().into());
        config.validator_seed = Some(c.seed); config.vrf_seed = Some(c.seed);
        config.pq_seed = Some(c.pq.secret_key_bytes()); config.pq_pk = Some(c.pq.public_key().0.to_vec());
        assert!(NodeEngine::init(config).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn audit_harness_two_distinct_validators_exchange_votes() {
        let mut fixture = shared_two_validator_fixture();
        let a_id = Bytes32::from(fixture.material_a.validator_id);
        let b_id = Bytes32::from(fixture.material_b.validator_id);
        assert_ne!(a_id, b_id);
        let h = fixture.driver_a.next_height();
        let r = fixture.driver_a.current_round();
        let va = fixture.driver_a.sign_and_record_local_vote(h, r, VoteStep::Prevote, Bytes32::ZERO)
            .into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a {Some(v)} else {None}).unwrap();
        assert_eq!(va.validator_id, a_id);
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(va);
        let va = queue.pop_front().unwrap();
        fixture.driver_b.process(DriverEvent::InboundVote { from: "127.0.0.1:11001".parse().unwrap(), vote: va });
        assert!(fixture.driver_b.collector_has_vote_from(h, r, VoteStep::Prevote, a_id));
        let vb = fixture.driver_b.sign_and_record_local_vote(h, r, VoteStep::Prevote, Bytes32::ZERO)
            .into_iter().find_map(|a| if let DriverAction::BroadcastVote(v)=a {Some(v)} else {None}).unwrap();
        assert_eq!(vb.validator_id, b_id);
        queue.push_back(vb);
        let vb = queue.pop_front().unwrap();
        fixture.driver_a.process(DriverEvent::InboundVote { from: "127.0.0.1:11002".parse().unwrap(), vote: vb });
        assert!(fixture.driver_a.collector_has_vote_from(h, r, VoteStep::Prevote, b_id));
        let c = test_validator_material([0xC3; 32]);
        let signer = HybridKeypair::new(ClassicalKeypair::from_seed(&c.seed), c.pq);
        let vc = indra_consensus::vote::produce_vote(h, r, VoteStep::Prevote, Bytes32::ZERO, Bytes32::from(c.validator_id), governing_snapshot_root(&fixture.driver_a, h), TEST_CHAIN_ID, &signer).unwrap();
        queue.push_back(vc);
        let vc = queue.pop_front().unwrap();
        let c_actions = fixture.driver_a.process(DriverEvent::InboundVote { from: "127.0.0.1:11003".parse().unwrap(), vote: vc });
        assert!(fixture.driver_a.collector_has_vote_from(h, r, VoteStep::Prevote, Bytes32::from(c.validator_id)));
        let _ = c_actions;
        let _ = std::fs::remove_dir_all(fixture.dir_a); let _ = std::fs::remove_dir_all(fixture.dir_b);
    }


    #[test]
    fn proposer_authority_uses_snapshot_weights_not_live_registry() {
        let (mut driver, dir) = local_driver([0xB1; 32], "snapshot_proposer_weight");
        let local_id = driver.engine.validator_id().unwrap();
        let snapshot = driver.engine.state.consensus_snapshots[0].clone();
        let frozen = snapshot
            .entry_with_position(&local_id)
            .unwrap()
            .1
            .consensus_weight_spark;

        driver
            .engine
            .state
            .validators
            .get_mut(&local_id)
            .unwrap()
            .stake_spark = frozen + 999;

        let election = driver.proposer_election_for_height(u64::MAX, 0).unwrap();
        let local_candidate = election
            .candidates
            .iter()
            .find(|candidate| candidate.validator_id == local_id)
            .unwrap();
        assert_eq!(local_candidate.stake, frozen);
        assert_ne!(
            local_candidate.stake,
            driver
                .engine
                .state
                .validators
                .get(&local_id)
                .unwrap()
                .stake_spark
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposer_vrf_vote_and_qc_authority_are_snapshot_identical() {
        let (driver, dir) = local_driver([0xB5; 32], "snapshot_cross_authority");
        let snapshot = driver
            .engine
            .state
            .build_genesis_consensus_snapshot()
            .unwrap();
        let vrf = vrf_authority_from_snapshot(
            TEST_CHAIN_ID.as_bytes(),
            301,
            2,
            indra_core::types::primitives::Bytes64([0x55; 64]),
            &snapshot,
        )
        .unwrap();
        let voters = NodeEngine::registered_voters_for_height(301, &snapshot);
        let qc = NodeEngine::qc_validators_for_height(301, &snapshot);

        assert_eq!(
            vrf.election.sortition_log,
            snapshot.sortition_log_interval().unwrap()
        );
        assert_eq!(vrf.election.candidates.len(), voters.len());
        assert_eq!(voters.len(), qc.len());
        for ((candidate, voter), validator) in vrf.election.candidates.iter().zip(&voters).zip(&qc)
        {
            assert_eq!(candidate.validator_id, voter.validator_id);
            assert_eq!(voter.validator_id, validator.validator_id);
            assert_eq!(candidate.stake, voter.stake);
            assert_eq!(voter.stake, validator.stake);
            assert_eq!(
                candidate.vrf_pubkey,
                snapshot.entries()[validator.position].vrf_pk
            );
        }
        assert_eq!(
            voters.iter().map(|voter| voter.stake).sum::<u64>(),
            snapshot.total_weight_spark
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn consensus_snapshot_capstone_multi_epoch_authority_lifecycle_is_consistent() {
        let mut fixture = shared_four_validator_fixture();
        let local_seed = [0x01; 32];
        let b_seed = [0x02; 32];
        let c_seed = [0x03; 32];
        let d_seed = [0x04; 32];
        let local = HybridKeypair::new(ClassicalKeypair::from_seed(&local_seed), PqKeypair::from_seed(&local_seed).unwrap());
        let b = HybridKeypair::new(ClassicalKeypair::from_seed(&b_seed), PqKeypair::from_seed(&b_seed).unwrap());
        let c = HybridKeypair::new(ClassicalKeypair::from_seed(&c_seed), PqKeypair::from_seed(&c_seed).unwrap());
        let d = HybridKeypair::new(ClassicalKeypair::from_seed(&d_seed), PqKeypair::from_seed(&d_seed).unwrap());
        let driver = &mut fixture.drivers[0];
        let local_id = validator_id_for(&local);
        let b_id = validator_id_for(&b);
        let c_id = validator_id_for(&c);
        for (id, stake) in [(local_id, 40), (b_id, 30), (c_id, 30)] {
            driver
                .engine
                .state
                .validators
                .get_mut(&id)
                .unwrap()
                .stake_spark = stake;
        }
        let genesis = driver
            .engine
            .state
            .build_genesis_consensus_snapshot()
            .unwrap();
        driver
            .engine
            .state
            .validators
            .get_mut(&c_id)
            .unwrap()
            .stake_spark = 60;
        let at_301 = driver
            .engine
            .state
            .build_consensus_snapshot(301, 300)
            .unwrap();
        driver
            .engine
            .state
            .validators
            .get_mut(&b_id)
            .unwrap()
            .status = ValidatorStatus::Registered;
        let d_id = validator_id_for(&d);
        driver
            .engine
            .state
            .validators
            .get_mut(&d_id)
            .unwrap()
            .stake_spark = 50;
        let at_601 = driver
            .engine
            .state
            .build_consensus_snapshot(601, 600)
            .unwrap();
        driver
            .engine
            .state
            .validators
            .get_mut(&local_id)
            .unwrap()
            .stake_spark = 80;
        driver
            .engine
            .state
            .validators
            .get_mut(&c_id)
            .unwrap()
            .status = ValidatorStatus::Registered;
        let at_901 = driver
            .engine
            .state
            .build_consensus_snapshot(901, 900)
            .unwrap();
        driver.engine.state.consensus_snapshots = vec![at_601.clone(), at_901.clone()];

        let signers = vec![
            (local_id, local_seed, local),
            (b_id, b_seed, b),
            (c_id, c_seed, c),
            (d_id, d_seed, d),
        ];
        let snapshots = [(1, genesis), (301, at_301), (601, at_601), (901, at_901)];
        let run = || {
            snapshots
                .iter()
                .map(|(height, snapshot)| {
                    let voters = NodeEngine::registered_voters_for_height(*height, snapshot);
                    let validators = NodeEngine::qc_validators_for_height(*height, snapshot);
                    let authority = vrf_authority_from_snapshot(
                        TEST_CHAIN_ID.as_bytes(),
                        *height,
                        0,
                        Bytes64([(*height % 251) as u8; 64]),
                        snapshot,
                    )
                    .unwrap();
                    assert_eq!(voters.len(), validators.len());
                    assert_eq!(validators.len(), authority.election.candidates.len());
                    for ((voter, validator), candidate) in voters
                        .iter()
                        .zip(&validators)
                        .zip(&authority.election.candidates)
                    {
                        assert_eq!(voter.validator_id, validator.validator_id);
                        assert_eq!(validator.validator_id, candidate.validator_id);
                        assert_eq!(voter.stake, validator.stake);
                        assert_eq!(validator.stake, candidate.stake);
                    }
                    let block_hash = Bytes32::from([(*height % 239) as u8; 32]);
                    let votes = signers
                        .iter()
                        .filter(|(id, _, _)| snapshot.entry_with_position(id).is_some())
                        .map(|(id, _, signer)| {
                            indra_consensus::vote::produce_vote(
                                *height,
                                0,
                                VoteStep::Precommit,
                                block_hash,
                                *id,
                                snapshot.snapshot_root,
                                TEST_CHAIN_ID,
                                signer,
                            )
                            .unwrap()
                        })
                        .collect::<Vec<_>>();
                    let qc = indra_consensus::qc::build_qc(
                        *height,
                        0,
                        block_hash,
                        TEST_CHAIN_ID,
                        snapshot.snapshot_root,
                        &validators,
                        votes.iter().collect(),
                    )
                    .unwrap();
                    NodeEngine::verify_qc_with_snapshot(&qc, snapshot, TEST_CHAIN_ID).unwrap();
                    let sortition = signers
                        .iter()
                        .filter(|(id, _, _)| snapshot.entry_with_position(id).is_some())
                        .map(|(id, seed, _)| {
                            let result = indra_consensus::proposer::compute_proposer_vrf(
                                *id,
                                &VrfKeypair::from_seed(seed),
                                &authority.election,
                            )
                            .unwrap();
                            (result.vrf_output.0, result.eligible, result.priority)
                        })
                        .collect::<Vec<_>>();
                    (snapshot.snapshot_root, sortition, qc.encode_to_vec())
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            run(),
            run(),
            "live and replay transcripts must be identical"
        );
        assert_eq!(
            snapshots
                .iter()
                .map(|(_, snapshot)| snapshot.activation_height)
                .collect::<Vec<_>>(),
            vec![1, 301, 601, 901]
        );
        assert_eq!(
            driver
                .engine
                .state
                .consensus_snapshots
                .iter()
                .map(|snapshot| snapshot.activation_height)
                .collect::<Vec<_>>(),
            vec![601, 901]
        );
        drop(fixture.drivers);
        for dir in fixture.dirs { let _ = std::fs::remove_dir_all(dir); }
    }

    #[test]
    fn governed_proposer_and_vrf_quorum_fail_closed_without_snapshot() {
        let (mut driver, dir) = local_driver([0xB7; 32], "missing_vrf_snapshot");
        driver.engine.state.consensus_snapshots.clear();
        assert!(matches!(
            driver.proposer_election_for_height(u64::MAX, 0),
            Err(NodeError::ConsensusSnapshotLookup(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn competing_proposals_same_value_hash_cannot_both_reach_quorum() {
        let mut fixture = shared_four_validator_fixture();
        let mut driver = fixture.drivers.remove(0);
        let a = HybridKeypair::new(ClassicalKeypair::from_seed(&[0x01; 32]), PqKeypair::from_seed(&[0x01; 32]).unwrap());
        let b = HybridKeypair::new(ClassicalKeypair::from_seed(&[0x02; 32]), PqKeypair::from_seed(&[0x02; 32]).unwrap());
        let c = HybridKeypair::new(ClassicalKeypair::from_seed(&[0x03; 32]), PqKeypair::from_seed(&[0x03; 32]).unwrap());
        let d = HybridKeypair::new(ClassicalKeypair::from_seed(&[0x04; 32]), PqKeypair::from_seed(&[0x04; 32]).unwrap());
        driver.refresh_registered_voters();

        let mut block_a = make_block(&driver.engine.state);
        block_a.header.proposer_round = 0;
        block_a.header.polc_round = None;
        let mut block_b = block_a.clone();
        block_b.header.proposer_round = 1;
        block_b.header.polc_round = Some(0);

        assert_eq!(block_a.header.value_hash, block_b.header.value_hash);
        let hash_a = block_a.header.block_hash();
        let hash_b = block_b.header.block_hash();
        assert_ne!(hash_a, hash_b);

        let voters = driver.registered_voters.clone();
        let mut collector = VoteCollector::new(
            1,
            0,
            VoteStep::Prevote,
            TEST_CHAIN_ID.to_string(),
            governing_snapshot_root(&driver, 1),
            voters,
        );
        let signer_ids = [
            indra_core::types::crypto::hybrid_identity_id(
                &a.public_key().classical.0,
                &a.public_key().pq.0,
            ),
            indra_core::types::crypto::hybrid_identity_id(
                &b.public_key().classical.0,
                &b.public_key().pq.0,
            ),
            indra_core::types::crypto::hybrid_identity_id(
                &c.public_key().classical.0,
                &c.public_key().pq.0,
            ),
            indra_core::types::crypto::hybrid_identity_id(
                &d.public_key().classical.0,
                &d.public_key().pq.0,
            ),
        ];
        let signers = [&a, &b, &c, &d];

        for idx in 0..2 {
            let vote = indra_consensus::vote::produce_vote(
                1,
                0,
                VoteStep::Prevote,
                hash_a,
                signer_ids[idx],
                governing_snapshot_root(&driver, 1),
                TEST_CHAIN_ID,
                signers[idx],
            )
            .unwrap();
            assert!(matches!(
                collector.add_vote(vote).unwrap(),
                indra_consensus::vote::VoteDecision::Waiting
            ));
        }
        for idx in 2..4 {
            let vote = indra_consensus::vote::produce_vote(
                1,
                0,
                VoteStep::Prevote,
                hash_b,
                signer_ids[idx],
                governing_snapshot_root(&driver, 1),
                TEST_CHAIN_ID,
                signers[idx],
            )
            .unwrap();
            assert!(matches!(
                collector.add_vote(vote).unwrap(),
                indra_consensus::vote::VoteDecision::Waiting
            ));
        }

        let equivocation = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Prevote,
            hash_a,
            signer_ids[2],
            governing_snapshot_root(&driver, 1),
            TEST_CHAIN_ID,
            signers[2],
        )
        .unwrap();
        assert!(
            collector.add_vote(equivocation).is_err(),
            "a validator cannot move from one full hash to another to make both quorums"
        );

        drop(driver);
        for dir in fixture.dirs { let _ = std::fs::remove_dir_all(dir); }
    }

    #[test]
    fn vote_before_block_requests_proposal_then_commits() {
        let (mut driver, dir) = local_driver([0x42u8; 32], "votes_before_block");
        let _local = install_active_validator(&mut driver, [0x42u8; 32], "local");
        let remote_a = install_active_validator(&mut driver, [0x43u8; 32], "remote-a");
        let remote_b = install_active_validator(&mut driver, [0x44u8; 32], "remote-b");
        driver.refresh_registered_voters();
        let block = make_strict_block(&driver, [0x42u8; 32], 0, vec![]);
        let round = block.header.proposer_round;
        driver.current_round = round;
        let block_hash = block.header.block_hash();

        let remote_a_id = indra_core::types::crypto::hybrid_identity_id(
            &remote_a.public_key().classical.0,
            &remote_a.public_key().pq.0,
        );
        let remote_b_id = indra_core::types::crypto::hybrid_identity_id(
            &remote_b.public_key().classical.0,
            &remote_b.public_key().pq.0,
        );

        let prevote_a = indra_consensus::vote::produce_vote(
            1,
            round,
            VoteStep::Prevote,
            block_hash,
            remote_a_id,
            governing_snapshot_root(&driver, 1),
            TEST_CHAIN_ID,
            &remote_a,
        )
        .unwrap();
        let prevote_b = indra_consensus::vote::produce_vote(
            1,
            round,
            VoteStep::Prevote,
            block_hash,
            remote_b_id,
            governing_snapshot_root(&driver, 1),
            TEST_CHAIN_ID,
            &remote_b,
        )
        .unwrap();
        let precommit_a = indra_consensus::vote::produce_vote(
            1,
            round,
            VoteStep::Precommit,
            block_hash,
            remote_a_id,
            governing_snapshot_root(&driver, 1),
            TEST_CHAIN_ID,
            &remote_a,
        )
        .unwrap();
        let precommit_b = indra_consensus::vote::produce_vote(
            1,
            round,
            VoteStep::Precommit,
            block_hash,
            remote_b_id,
            governing_snapshot_root(&driver, 1),
            TEST_CHAIN_ID,
            &remote_b,
        )
        .unwrap();

        let peer_a: SocketAddr = "127.0.0.1:9101".parse().unwrap();
        let peer_b: SocketAddr = "127.0.0.1:9102".parse().unwrap();
        let actions_a = driver.process(DriverEvent::InboundVote {
            from: peer_a,
            vote: prevote_a,
        });
        let actions_b = driver.process(DriverEvent::InboundVote {
            from: peer_b,
            vote: prevote_b,
        });
        assert!(actions_a
            .iter()
            .any(|a| matches!(a, DriverAction::RequestProposal { .. })));
        assert!(actions_b.is_empty());

        let mut actions = driver.process(DriverEvent::InboundBlock {
            from: Some(peer_a),
            proposal: block,
        });
        actions.extend(driver.on_propose_timeout());
        actions.extend(driver.process(DriverEvent::InboundVote {
            from: peer_a,
            vote: precommit_a,
        }));
        actions.extend(driver.process(DriverEvent::InboundVote {
            from: peer_b,
            vote: precommit_b,
        }));

        assert_eq!(driver.height(), 1);
        assert!(actions.iter().any(|a| matches!(
            a,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Precommit && vote.block_hash == block_hash
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn propose_timeout_prevotes_staged_block_instead_of_nil() {
        let mut fixture = shared_four_validator_fixture();
        let mut driver = fixture.drivers.remove(0);
        let local_id = driver.engine.validator_id().unwrap();
        let other_ids: Vec<_> = driver
            .engine
            .state
            .validators
            .all_validators()
            .map(|validator| validator.validator_id)
            .filter(|id| *id != local_id)
            .collect();
        for id in other_ids {
            driver.engine.state.validators.get_mut(&id).unwrap().status = ValidatorStatus::Registered;
        }
        driver.refresh_registered_voters();

        let block = make_strict_block(&driver, [0x01u8; 32], 0, vec![]);
        let block_hash = block.header.block_hash();
        let mut actions = driver.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9201".parse().unwrap()),
            proposal: block,
        });
        actions.extend(driver.on_propose_timeout());

        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == block_hash
        )));
        drop(driver);
        for dir in fixture.dirs { let _ = std::fs::remove_dir_all(dir); }
    }

    #[test]
    fn accepted_proposal_replay_skips_authoritative_admission_across_peer_paths() {
        let seed = [0x49u8; 32];
        let (mut driver, dir) = local_driver(seed, "accepted_proposal_replay_fast_path");
        let _local = install_active_validator(&mut driver, seed, "local");
        driver.refresh_registered_voters();

        let proposal = make_strict_block(&driver, seed, 0, vec![]);
        let hash = proposal.header.block_hash();
        let phase_before = driver.current_phase();
        let first = driver.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9202".parse().unwrap()),
            proposal: proposal.clone(),
        });
        assert!(first
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastBlock(_))));
        assert_eq!(
            driver.proposal_admission_metrics,
            ProposalAdmissionMetrics {
                proposal_verifications: 1,
                qc_verifications: 0,
                detached_projections: 1,
            }
        );
        let pending_before = driver.pending_blocks.len();
        let metrics_before = driver.proposal_admission_metrics;

        // A different authenticated transport address models another relay or
        // a reconnected peer. Driver-authoritative state is connection-agnostic.
        let replay = driver.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9203".parse().unwrap()),
            proposal,
        });

        assert!(replay
            .iter()
            .all(|action| matches!(action, DriverAction::None)));
        assert_eq!(driver.proposal_admission_metrics, metrics_before);
        assert_eq!(driver.pending_blocks.len(), pending_before);
        assert!(driver.pending_blocks.contains_key(&hash));
        assert_eq!(driver.current_phase(), phase_before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_proposal_cannot_poison_accepted_replay_state() {
        let seed = [0x4Au8; 32];
        let (mut driver, dir) = local_driver(seed, "invalid_proposal_no_replay_poison");
        let _local = install_active_validator(&mut driver, seed, "local");
        driver.refresh_registered_voters();

        let valid = make_strict_block(&driver, seed, 0, vec![]);
        let hash = valid.header.block_hash();
        let mut invalid = valid.clone();
        invalid.proposer_authorization.classical_sig =
            VariableBytes::from_slice(&[0xA5; indra_crypto::CLASSICAL_SIG_BYTES]).unwrap();

        let rejected = driver.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9204".parse().unwrap()),
            proposal: invalid,
        });
        assert!(rejected
            .iter()
            .all(|action| matches!(action, DriverAction::None)));
        assert!(!driver.pending_blocks.contains_key(&hash));
        assert_eq!(driver.proposal_admission_metrics.proposal_verifications, 1);
        assert_eq!(driver.proposal_admission_metrics.detached_projections, 0);

        let accepted = driver.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9205".parse().unwrap()),
            proposal: valid,
        });
        assert!(accepted
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastBlock(_))));
        assert!(driver.pending_blocks.contains_key(&hash));
        assert_eq!(driver.proposal_admission_metrics.proposal_verifications, 2);
        assert_eq!(driver.proposal_admission_metrics.detached_projections, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn accepted_height_two_proposal_replay_skips_embedded_qc_verification() {
        let seed = [0x4Cu8; 32];
        let (mut driver, dir) = local_driver(seed, "height_two_proposal_replay_fast_path");
        let _local = install_active_validator(&mut driver, seed, "local");
        driver.refresh_registered_voters();

        let first_height = make_strict_block(&driver, seed, 0, vec![]);
        let _ = process_single_validator_proposal(&mut driver, first_height);
        assert_eq!(driver.height(), 1);

        let proposal = make_strict_block(&driver, seed, 0, driver.last_qc_bytes().to_vec());
        let before = driver.proposal_admission_metrics;
        let accepted = driver.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9206".parse().unwrap()),
            proposal: proposal.clone(),
        });
        assert!(accepted
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastBlock(_))));
        assert_eq!(
            driver.proposal_admission_metrics.proposal_verifications,
            before.proposal_verifications + 1
        );
        assert_eq!(
            driver.proposal_admission_metrics.qc_verifications,
            before.qc_verifications + 1
        );
        assert_eq!(
            driver.proposal_admission_metrics.detached_projections,
            before.detached_projections + 1
        );
        let after_first = driver.proposal_admission_metrics;

        let replay = driver.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9207".parse().unwrap()),
            proposal,
        });
        assert!(replay
            .iter()
            .all(|action| matches!(action, DriverAction::None)));
        assert_eq!(driver.proposal_admission_metrics, after_first);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_round_timeouts_do_not_advance_election_seed() {
        let (mut driver, dir) = local_driver([0x48; 32], "empty_round_seed_stable");
        let _local = install_active_validator(&mut driver, [0x48; 32], "local");
        driver.refresh_registered_voters();
        let seed = driver.engine.state.election_seed;
        let height = driver.height();
        let _ = driver.on_propose_timeout();
        let _ = driver.on_precommit_timeout();
        assert_eq!(driver.height(), height);
        assert_eq!(driver.engine.state.election_seed, seed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposal_selection_switches_to_better_priority_only_before_prevote() {
        let mut fixture = shared_four_validator_fixture();
        let (left, _) = fixture.drivers.split_at_mut(1);
        let driver = &mut left[0];
        let a = HybridKeypair::new(ClassicalKeypair::from_seed(&[0x01; 32]), PqKeypair::from_seed(&[0x01; 32]).unwrap());
        let b = HybridKeypair::new(ClassicalKeypair::from_seed(&[0x02; 32]), PqKeypair::from_seed(&[0x02; 32]).unwrap());
        driver.refresh_registered_voters();
        let a_id = validator_id_for(&a);
        let b_id = validator_id_for(&b);
        let a_vrf = VrfKeypair::from_seed(&[0x01; 32]);
        let b_vrf = VrfKeypair::from_seed(&[0x02; 32]);
        let round = (0..MAX_ROUNDS_PER_HEIGHT)
            .find(|round| {
                let election = election_for_round(&driver, 1, *round);
                indra_consensus::proposer::compute_proposer_vrf(a_id, &a_vrf, &election)
                    .is_ok_and(|r| r.eligible)
                    && indra_consensus::proposer::compute_proposer_vrf(b_id, &b_vrf, &election)
                        .is_ok_and(|r| r.eligible)
            })
            .expect("two deterministic candidates must share an eligible test round");
        driver.current_round = round;
        let a_proposal = make_strict_block(driver, [0x01; 32], round, vec![]);
        let b_proposal = make_strict_block(driver, [0x02; 32], round, vec![]);
        assert_eq!(a_proposal.header.proposer_round, round);
        assert_eq!(b_proposal.header.proposer_round, round);
        let (better, worse) =
            if a_proposal.header.proposer_priority < b_proposal.header.proposer_priority {
                (a_proposal, b_proposal)
            } else {
                (b_proposal, a_proposal)
            };
        let better_hash = better.header.block_hash();
        let worse_hash = worse.header.block_hash();

        let first = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: worse.clone(),
        });
        let switched = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: better,
        });
        assert!(!first.iter().chain(&switched).any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Prevote
        )));
        let timeout = driver.on_propose_timeout();
        assert!(timeout.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == better_hash
        )));

        let after_prevote = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: worse,
        });
        assert!(!after_prevote.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == worse_hash
        )));
        drop(fixture);
    }

    #[test]
    fn proposal_requires_quorum_evidence_before_round_advancement() {
        let (mut driver, dir) = local_driver([0x4Fu8; 32], "proposal_round_advance");
        let signer = install_active_validator(&mut driver, [0x4Fu8; 32], "validator");
        driver.refresh_registered_voters();

        let target_round = (1..=8)
            .find(|round| {
                driver
                    .engine
                    .is_proposer(&election_for_round(&driver, 1, *round))
            })
            .expect("single-validator fixture must be eligible within the round-jump cap");
        let block = make_strict_block(&driver, [0x4Fu8; 32], target_round, vec![]);
        let block_hash = block.header.block_hash();
        let mut actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: block,
        });
        actions.extend(driver.on_propose_timeout());

        assert_eq!(driver.current_round(), 0);
        assert!(!actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.round == target_round && vote.step == VoteStep::Prevote && vote.block_hash == block_hash
        )));

        let vote = indra_consensus::vote::produce_vote(
            1,
            target_round,
            VoteStep::Prevote,
            block_hash,
            validator_id_for(&signer),
            governing_snapshot_root(&driver, 1),
            TEST_CHAIN_ID,
            &signer,
        )
        .unwrap();
        let actions = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9202".parse().unwrap(),
            vote,
        });
        // With the single-validator test snapshot, the certified advance also
        // lets the staged proposal immediately reach vote quorum and commit.
        assert_eq!(driver.height(), 1);
        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.round == target_round && vote.step == VoteStep::Prevote && vote.block_hash == block_hash
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposal_does_not_retreat_round() {
        let (mut driver, dir) = local_driver([0x50u8; 32], "proposal_round_no_retreat");
        let _local = install_active_validator(&mut driver, [0x50u8; 32], "local");
        driver.refresh_registered_voters();
        driver.current_round = 10;

        let block = make_strict_block(&driver, [0x50u8; 32], 3, vec![]);
        let _actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: block,
        });

        assert_eq!(driver.current_round(), 10);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposal_round_jump_cannot_bypass_vote_safety_without_evidence() {
        let (mut driver, dir) = local_driver([0x51u8; 32], "proposal_round_vote_safety");
        let _local = install_active_validator(&mut driver, [0x51u8; 32], "local");
        driver.refresh_registered_voters();
        driver.vote_safety.record(1, 5, 0, None).unwrap();

        let block = make_strict_block(&driver, [0x51u8; 32], 5, vec![]);
        let actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: block,
        });

        assert_eq!(driver.current_round(), 0);
        assert!(!actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote) if vote.round == 5
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prevote_timeout_sends_nil_precommit() {
        let (mut driver, dir) = local_driver([0x46u8; 32], "prevote_timeout_nil");
        let _local = install_active_validator(&mut driver, [0x46u8; 32], "local");
        driver.refresh_registered_voters();
        driver.current_phase = RoundPhase::Prevote;

        let actions = driver.on_prevote_timeout();
        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Precommit && vote.block_hash == Bytes32::ZERO
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn precommit_timeout_advances_round() {
        let (mut driver, dir) = local_driver([0x47u8; 32], "precommit_timeout_round");
        let _local = install_active_validator(&mut driver, [0x47u8; 32], "local");
        driver.refresh_registered_voters();
        driver.current_phase = RoundPhase::Precommit;
        driver.current_round = 3;

        driver.on_precommit_timeout().unwrap();
        assert_eq!(driver.current_round(), 4);
        assert_eq!(driver.current_phase(), RoundPhase::Propose);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn final_round_timeout_fails_closed_without_state_mutation() {
        let (mut driver, dir) = local_driver([0x48u8; 32], "round_limit");
        driver.current_round = MAX_ROUNDS_PER_HEIGHT - 2;
        driver.current_phase = RoundPhase::Precommit;
        driver.on_precommit_timeout().unwrap();
        assert_eq!(driver.current_round(), MAX_ROUNDS_PER_HEIGHT - 1);
        assert_eq!(driver.current_phase(), RoundPhase::Propose);

        driver.current_phase = RoundPhase::Precommit;
        let before = (
            driver.current_round,
            driver.current_phase,
            driver.pending_blocks.len(),
            driver.vote_collectors.len(),
            driver.locked_round,
            driver.valid_round,
        );
        let error = driver.on_precommit_timeout().unwrap_err();
        assert!(matches!(error, NodeError::RoundLimitExceeded { .. }));
        assert_eq!(
            before,
            (
                driver.current_round,
                driver.current_phase,
                driver.pending_blocks.len(),
                driver.vote_collectors.len(),
                driver.locked_round,
                driver.valid_round,
            )
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn certified_round_jump_accepts_new_bound_and_rejects_exclusive_bound() {
        let mut fixture = shared_four_validator_fixture();
        let driver = &mut fixture.drivers[0];
        driver.sync.mark_caught_up(driver.height());
        driver.refresh_registered_voters();
        let target_round = MAX_ROUNDS_PER_HEIGHT - 1;
        driver.current_round = target_round - MAX_ACCEPTED_ROUND_JUMP;
        let snapshot_root = governing_snapshot_root(driver, 1);
        for voter in driver.registered_voters.iter().take(3) {
            driver
                .round_advance_evidence
                .entry((1, target_round))
                .or_default()
                .insert(
                    voter.validator_id,
                    dummy_vote(1, target_round, VoteStep::Prevote, Bytes32::ZERO, snapshot_root),
                );
        }

        let _ = driver.maybe_advance_to_certified_round(1, target_round);
        assert_eq!(driver.current_round(), target_round);

        driver.current_round = target_round - 1;
        let actions = driver.maybe_advance_to_certified_round(1, MAX_ROUNDS_PER_HEIGHT);
        assert!(actions.is_empty());
        assert_eq!(driver.current_round(), target_round - 1);

        let dirs = fixture.dirs.clone();
        drop(fixture.drivers);
        for dir in dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn invalid_high_round_vote_is_rejected_before_any_consensus_mutation() {
        let (mut driver, dir) = local_driver([0x49u8; 32], "high_round_vote");
        let signer = install_active_validator(&mut driver, [0x49u8; 32], "local");
        driver.refresh_registered_voters();
        let mut vote = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Prevote,
            Bytes32::ZERO,
            validator_id_for(&signer),
            governing_snapshot_root(&driver, 1),
            TEST_CHAIN_ID,
            &signer,
        )
        .unwrap();
        vote.round = MAX_ROUNDS_PER_HEIGHT;
        let before = (
            driver.seen_round_votes.len(),
            driver.round_advance_evidence.len(),
            driver.vote_collectors.len(),
            driver.locked_round,
            driver.valid_round,
        );
        let actions = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9499".parse().unwrap(),
            vote,
        });
        assert!(actions.is_empty());
        assert_eq!(
            before,
            (
                driver.seen_round_votes.len(),
                driver.round_advance_evidence.len(),
                driver.vote_collectors.len(),
                driver.locked_round,
                driver.valid_round,
            )
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn process_status_cannot_advance_round_without_quorum_evidence() {
        let (mut driver, dir) = local_driver([0x4Au8; 32], "status_round_advance");
        let peer: SocketAddr = "127.0.0.1:9301".parse().unwrap();

        driver.process(DriverEvent::PeerStatus {
            from: peer,
            validator_id: Bytes32::ZERO,
            height: 1,
            tip_hash: driver.engine.state.tip_hash,
            round: 8,
        });

        assert_eq!(driver.current_round(), 0);
        assert_eq!(driver.current_phase(), RoundPhase::Propose);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legitimate_hybrid_signed_quorum_advances_round_and_preserves_liveness() {
        let (mut driver, dir) = local_driver([0x93u8; 32], "round_evidence_quorum");
        let signers: Vec<HybridKeypair> = (0u8..4)
            .map(|i| {
                let seed = [0xA0u8.saturating_add(i); 32];
                HybridKeypair::new(
                    ClassicalKeypair::from_seed(&seed),
                    PqKeypair::from_seed(&seed).unwrap(),
                )
            })
            .collect();
        driver.set_voters(
            signers
                .iter()
                .map(|signer| {
                    let public = signer.public_key();
                    RegisteredVoter {
                        validator_id: validator_id_for(signer),
                        classical_pk: public.classical.0,
                        pq_pk: public.pq.0.to_vec(),
                        stake: 1,
                    }
                })
                .collect(),
        );

        for (index, signer) in signers.iter().enumerate() {
            let vote = indra_consensus::vote::produce_vote(
                1,
                4,
                if index == 1 {
                    VoteStep::Precommit
                } else {
                    VoteStep::Prevote
                },
                Bytes32::ZERO,
                validator_id_for(signer),
                governing_snapshot_root(&driver, 1),
                TEST_CHAIN_ID,
                signer,
            )
            .unwrap();
            driver.process(DriverEvent::InboundVote {
                from: format!("127.0.0.1:{}", 9500 + index).parse().unwrap(),
                vote,
            });
            if index < 2 {
                assert_eq!(driver.current_round(), 0, "<=2/3 must not advance");
            } else {
                assert_eq!(driver.current_round(), 4, "strict >2/3 must advance");
                break;
            }
        }
        assert_eq!(driver.current_phase(), RoundPhase::Propose);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_status_large_round_claim_is_informational_only() {
        let (mut driver, dir) = local_driver([0x8Au8; 32], "status_round_cap");
        driver.current_round = 5;
        let peer: SocketAddr = "127.0.0.1:9401".parse().unwrap();

        driver.process(DriverEvent::PeerStatus {
            from: peer,
            validator_id: Bytes32::ZERO,
            height: 1,
            tip_hash: driver.engine.state.tip_hash,
            round: 1_358,
        });

        assert_eq!(driver.current_round(), 5);
        assert_eq!(driver.current_phase(), RoundPhase::Propose);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_status_normal_round_claim_is_informational_only() {
        let (mut driver, dir) = local_driver([0x8Bu8; 32], "status_round_normal");
        driver.current_round = 5;
        let peer: SocketAddr = "127.0.0.1:9402".parse().unwrap();

        driver.process(DriverEvent::PeerStatus {
            from: peer,
            validator_id: Bytes32::ZERO,
            height: 1,
            tip_hash: driver.engine.state.tip_hash,
            round: 6,
        });

        assert_eq!(driver.current_round(), 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn peer_status_repeated_messages_cannot_force_round_advance() {
        let (mut driver, dir) = local_driver([0x8Cu8; 32], "status_round_repeated");
        driver.current_round = 5;
        let peer: SocketAddr = "127.0.0.1:9403".parse().unwrap();

        for _ in 0..100 {
            driver.sync.mark_caught_up(driver.height());
            driver.process(DriverEvent::PeerStatus {
                from: peer,
                validator_id: Bytes32::ZERO,
                height: 1,
                tip_hash: driver.engine.state.tip_hash,
                round: 29,
            });
        }

        assert_eq!(driver.current_round(), 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn process_status_does_not_retreat_round() {
        let (mut driver, dir) = local_driver([0x4Bu8; 32], "status_round_no_retreat");
        driver.current_round = 10;
        let peer: SocketAddr = "127.0.0.1:9302".parse().unwrap();

        driver.process(DriverEvent::PeerStatus {
            from: peer,
            validator_id: Bytes32::ZERO,
            height: 1,
            tip_hash: driver.engine.state.tip_hash,
            round: 3,
        });

        assert_eq!(driver.current_round(), 10);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn process_status_ignores_round_if_not_caught_up() {
        let (mut driver, dir) = local_driver([0x4Cu8; 32], "status_round_syncing");
        driver.sync = SyncState::follower(driver.engine.height());
        let peer: SocketAddr = "127.0.0.1:9303".parse().unwrap();

        driver.process(DriverEvent::PeerStatus {
            from: peer,
            validator_id: Bytes32::ZERO,
            height: 1,
            tip_hash: driver.engine.state.tip_hash,
            round: 8,
        });

        assert_eq!(driver.current_round(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn buffered_votes_does_not_grow_unbounded_while_stalled() {
        let (mut driver, dir) = local_driver([0x90u8; 32], "bounded_buffered_votes");
        driver.current_round = 128;
        let peer: SocketAddr = "127.0.0.1:9501".parse().unwrap();
        let snapshot_root = governing_snapshot_root(&driver, 1);

        for i in 0..(MAX_STALLED_HEIGHT_ENTRIES + 100) {
            let hash = test_hash(i);
            driver
                .buffered_votes
                .entry((1, i as u32, hash))
                .or_default()
                .push((
                    peer,
                    dummy_vote(1, i as u32, VoteStep::Prevote, hash, snapshot_root),
                ));
        }
        driver.prune_buffered_votes();

        assert!(driver.buffered_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vote_collectors_evicts_oldest_when_at_capacity() {
        let (mut driver, dir) = local_driver([0x91u8; 32], "bounded_vote_collectors");
        driver.current_round = 128;

        for i in 0..(MAX_STALLED_HEIGHT_ENTRIES + 100) {
            driver.vote_collectors.insert(
                (1, i as u32, VoteStep::Prevote),
                VoteCollector::new(
                    1,
                    i as u32,
                    VoteStep::Prevote,
                    TEST_CHAIN_ID.to_string(),
                    governing_snapshot_root(&driver, 1),
                    driver.registered_voters.clone(),
                ),
            );
        }
        driver.prune_vote_collectors();

        assert!(driver.vote_collectors.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn requested_proposals_does_not_grow_unbounded() {
        let (mut driver, dir) = local_driver([0x92u8; 32], "bounded_requested");
        driver.current_round = 128;

        for i in 0..(MAX_STALLED_HEIGHT_ENTRIES + 100) {
            driver
                .requested_proposals
                .insert((1, i as u32, test_hash(i)));
        }
        driver.prune_requested_proposals();

        assert!(driver.requested_proposals.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn seen_round_votes_does_not_grow_unbounded() {
        let (mut driver, dir) = local_driver([0x93u8; 32], "bounded_seen_votes");
        driver.current_round = 128;

        for i in 0..(MAX_STALLED_HEIGHT_ENTRIES + 100) {
            driver.seen_round_votes.insert(
                (test_hash(i), 1, i as u32, VoteStep::Prevote),
                AcceptedVoteIdentity {
                    block_hash: test_hash(i + 1_000),
                    snapshot_root: Bytes32::ZERO,
                },
            );
        }
        driver.prune_seen_round_votes();

        assert!(driver.seen_round_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_blocks_does_not_grow_unbounded() {
        let (mut driver, dir) = local_driver([0x94u8; 32], "bounded_pending_blocks");
        driver.current_round = 128;

        for i in 0..(MAX_STALLED_HEIGHT_ENTRIES + 100) {
            let mut block = make_block(&driver.engine.state);
            block.header.proposer_round = i as u32;
            block.header.timestamp = block.header.timestamp.saturating_add(i as u64);
            driver
                .pending_blocks
                .insert(block.header.block_hash(), block);
        }
        driver.prune_pending_blocks();

        assert!(driver.pending_blocks.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn future_and_wrong_parent_proposals_are_dropped_before_consensus_mutation() {
        let seed = [0x95u8; 32];
        let (mut driver, dir) = local_driver(seed, "strict_future_admission");
        let _local = install_active_validator(&mut driver, seed, "local");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());

        let current = make_strict_block(&driver, seed, 0, vec![]);
        let mut future = current.clone();
        future.block.header.height = driver.next_height() + 1;
        reauthorize_test_proposal(&mut future, seed, driver.engine.state.chain_id.as_bytes());

        let mut wrong_parent = current;
        wrong_parent.block.header.prev_hash = Bytes32::from([0xDD; 32]);
        reauthorize_test_proposal(
            &mut wrong_parent,
            seed,
            driver.engine.state.chain_id.as_bytes(),
        );

        // These mutations represent every expensive validation family in the
        // ordinary path. Because the parent state is unavailable/wrong, none
        // may obtain verified-container status before those checks are possible.
        let mut cases = vec![
            ("future-valid-envelope", future.clone()),
            ("wrong-parent", wrong_parent),
        ];
        let mut invalid_signature = future.clone();
        invalid_signature.proposer_authorization.classical_sig =
            VariableBytes::from_slice(&[0xA5; 64]).unwrap();
        cases.push(("invalid-signature", invalid_signature));
        let mut invalid_vrf = future.clone();
        invalid_vrf.block.header.proposer_vrf_proof =
            VariableBytes::from_slice(&[0x5A; 80]).unwrap();
        cases.push(("invalid-vrf-or-ineligible", invalid_vrf));
        let mut invalid_qc = future.clone();
        invalid_qc.block.header.quorum_certificate = VariableBytes::from_slice(&[0xFF]).unwrap();
        cases.push(("invalid-qc", invalid_qc));
        let mut wrong_snapshot_context = future.clone();
        wrong_snapshot_context.block.header.election_seed = Bytes64::from([0x44; 64]);
        cases.push(("wrong-snapshot-context", wrong_snapshot_context));
        let mut wrong_value = future.clone();
        wrong_value.block.header.value_hash = Bytes32::from([0x11; 32]);
        cases.push(("wrong-value-hash", wrong_value));
        let mut invalid_transaction = future.clone();
        invalid_transaction.block.transactions.push(
            indra_core::types::transaction::TransactionV1 {
                version: ProtocolVersion::CURRENT,
                signature_module_id: 0,
                inputs: vec![],
                outputs: vec![],
                fee_amount: 0,
                signature: indra_core::types::crypto::HybridSignature {
                    classical_sig: VariableBytes::from_slice(&[]).unwrap(),
                    pq_sig: VariableBytes::from_slice(&[]).unwrap(),
                },
            },
        );
        cases.push(("invalid-transaction-transition", invalid_transaction));
        let mut invalid_monetary = future.clone();
        invalid_monetary.block.header.base_fee = u64::MAX;
        cases.push(("invalid-monetary-transition", invalid_monetary));
        let mut wrong_state = future.clone();
        wrong_state.block.header.state_root = Bytes32::from([0x22; 32]);
        cases.push(("wrong-state-or-transition", wrong_state));
        let mut wrong_validators = future;
        wrong_validators.block.header.validator_set_root = Bytes32::from([0x33; 32]);
        cases.push(("wrong-validator-root", wrong_validators));

        for (name, proposal) in cases {
            let before = (
                driver.pending_blocks.len(),
                driver.vote_collectors.len(),
                driver.locked_round,
                driver.locked_value,
                driver.valid_round,
                driver.valid_value,
                driver.current_round,
                driver.vote_safety.load(),
            );
            let actions = driver.process(DriverEvent::InboundBlock {
                from: None,
                proposal,
            });
            assert!(
                actions
                    .iter()
                    .all(|action| matches!(action, DriverAction::None)),
                "{name}"
            );
            assert_eq!(
                before,
                (
                    driver.pending_blocks.len(),
                    driver.vote_collectors.len(),
                    driver.locked_round,
                    driver.locked_value,
                    driver.valid_round,
                    driver.valid_value,
                    driver.current_round,
                    driver.vote_safety.load(),
                ),
                "{name} mutated consensus state"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pending_precommit_quorum_does_not_grow_unbounded() {
        let (mut driver, dir) = local_driver([0x96u8; 32], "bounded_pending_quorum");
        driver.current_round = 128;

        for i in 0..(MAX_STALLED_HEIGHT_ENTRIES + 100) {
            driver
                .pending_precommit_quorum
                .insert((1, i as u32, test_hash(i)));
        }
        driver.prune_pending_precommit_quorum();

        assert!(driver.pending_precommit_quorum.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn bounded_collections_do_not_break_normal_consensus_operation() {
        let mut fixture = shared_four_validator_fixture();
        let mut driver = fixture.drivers.remove(0);
        let local_id = driver.engine.validator_id().unwrap();
        let other_ids: Vec<_> = driver
            .engine
            .state
            .validators
            .all_validators()
            .map(|validator| validator.validator_id)
            .filter(|id| *id != local_id)
            .collect();
        for id in other_ids {
            driver.engine.state.validators.get_mut(&id).unwrap().status = ValidatorStatus::Registered;
        }
        driver.refresh_registered_voters();

        let block = make_strict_block(&driver, [0x01u8; 32], 0, vec![]);
        let block_hash = block.header.block_hash();
        driver.current_round = block.header.proposer_round;
        let mut actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: block,
        });
        actions.extend(driver.on_propose_timeout());
        let remote_signers = [
            HybridKeypair::new(ClassicalKeypair::from_seed(&[0x02; 32]), PqKeypair::from_seed(&[0x02; 32]).unwrap()),
            HybridKeypair::new(ClassicalKeypair::from_seed(&[0x03; 32]), PqKeypair::from_seed(&[0x03; 32]).unwrap()),
            HybridKeypair::new(ClassicalKeypair::from_seed(&[0x04; 32]), PqKeypair::from_seed(&[0x04; 32]).unwrap()),
        ];
        for (index, signer) in remote_signers.iter().enumerate() {
            let vote = indra_consensus::vote::produce_vote(
                1,
                driver.current_round,
                VoteStep::Prevote,
                block_hash,
                validator_id_for(signer),
                governing_snapshot_root(&driver, 1),
                TEST_CHAIN_ID,
                signer,
            ).unwrap();
            actions.extend(driver.process(DriverEvent::InboundVote {
                from: SocketAddr::from(([127, 0, 0, 1], 9800 + index as u16)),
                vote,
            }));
        }
        for (index, signer) in remote_signers.iter().take(2).enumerate() {
            let vote = indra_consensus::vote::produce_vote(
                1,
                driver.current_round,
                VoteStep::Precommit,
                block_hash,
                validator_id_for(signer),
                governing_snapshot_root(&driver, 1),
                TEST_CHAIN_ID,
                signer,
            ).unwrap();
            actions.extend(driver.process(DriverEvent::InboundVote {
                from: SocketAddr::from(([127, 0, 0, 1], 9810 + index as u16)),
                vote,
            }));
        }
        assert_eq!(driver.height(), 1);
        assert!(actions
            .iter()
            .any(|action| matches!(action, DriverAction::BroadcastBlock(_))));
        assert!(driver.vote_collectors.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        assert!(driver.pending_blocks.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        assert!(driver.buffered_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        assert!(driver.requested_proposals.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        assert!(driver.seen_round_votes.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        assert!(driver.pending_precommit_quorum.len() <= MAX_STALLED_HEIGHT_ENTRIES);
        drop(driver);
        for dir in fixture.dirs { let _ = std::fs::remove_dir_all(dir); }
    }

    #[test]
    fn apply_vote_safety_skips_past_voted_rounds() {
        let (mut driver, dir) = local_driver([0x4Du8; 32], "vote_safety_skip");
        driver.engine.state.height = 4;
        driver.vote_safety.record(5, 7, 0, None).unwrap();

        driver.apply_vote_safety();

        assert_eq!(driver.current_round(), 8);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn restart_after_vote_in_final_round_fails_closed() {
        let (mut driver, dir) = local_driver([0x4Cu8; 32], "final_round_restart");
        driver
            .vote_safety
            .record(1, MAX_ROUNDS_PER_HEIGHT - 1, 1, None)
            .unwrap();
        let before = driver.current_round();
        driver.apply_vote_safety();
        assert_eq!(driver.current_round(), before);
        assert!(driver
            .vote_safety_unavailable
            .as_deref()
            .is_some_and(|reason| reason.contains("no safe round")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_vote_safety_ignores_old_height() {
        let (mut driver, dir) = local_driver([0x4Eu8; 32], "vote_safety_old_height");
        driver.engine.state.height = 5;
        driver.vote_safety.record(3, 10, 0, None).unwrap();

        driver.apply_vote_safety();

        assert_eq!(driver.current_round(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_vote_safety_record_prevents_voting() {
        let (mut driver, dir) = local_driver([0x71u8; 32], "vote_safety_corrupt_blocks");
        std::fs::write(driver.engine.config.vote_safety_path(), [0xAA, 0xBB]).unwrap();
        driver.apply_vote_safety();
        let actions = driver.sign_and_record_local_vote(1, 0, VoteStep::Prevote, Bytes32::ZERO);
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, DriverAction::BroadcastVote(_))),
            "corrupt vote_safety.dat must fail closed and block vote broadcast"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_vote_safety_record_allows_voting_on_fresh_start() {
        let (mut driver, dir) = local_driver([0x72u8; 32], "vote_safety_missing_allows");
        let _ = std::fs::remove_file(driver.engine.config.vote_safety_path());
        driver.apply_vote_safety();
        let actions = driver.sign_and_record_local_vote(1, 0, VoteStep::Prevote, Bytes32::ZERO);
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, DriverAction::BroadcastVote(_))),
            "missing vote_safety.dat on a fresh start should allow voting"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vote_safety_write_failure_prevents_vote_broadcast() {
        let (mut driver, dir) = local_driver([0x73u8; 32], "vote_safety_write_fail");
        let safety_path = driver.engine.config.vote_safety_path();
        let _ = std::fs::remove_file(&safety_path);
        std::fs::create_dir_all(&safety_path).unwrap();
        let actions = driver.sign_and_record_local_vote(1, 0, VoteStep::Prevote, Bytes32::ZERO);
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, DriverAction::BroadcastVote(_))),
            "vote safety persistence failure must block vote broadcast"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn valid_vote_safety_record_constrains_future_rounds() {
        let (mut driver, dir) = local_driver([0x74u8; 32], "vote_safety_valid_constrains");
        driver.vote_safety.record(1, 2, 0, None).unwrap();
        driver.apply_vote_safety();
        assert_eq!(driver.current_round(), 3);
        let actions = driver.sign_and_record_local_vote(1, 3, VoteStep::Prevote, Bytes32::ZERO);
        assert!(
            actions
                .iter()
                .any(|action| matches!(action, DriverAction::BroadcastVote(_))),
            "higher round after persisted vote-safety record should remain allowed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn crash_restart_restores_lock_and_rejects_conflicting_no_polc_prevote() {
        let seed = [0x79u8; 32];
        let (mut driver, dir) = local_driver(seed, "restart_restores_lock");
        let local = install_active_validator(&mut driver, seed, "local");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());

        // Step 1-2: A received a genuine strict-two-thirds prevote PoLC and the
        // validator persisted its resulting lock before its non-nil precommit.
        let block_a = make_strict_block(&driver, seed, 0, vec![]);
        let hash_a = block_a.header.block_hash();
        let value_a = block_a.header.value_hash;
        let prevote_a = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Prevote,
            hash_a,
            validator_id_for(&local),
            governing_snapshot_root(&driver, 1),
            TEST_CHAIN_ID,
            &local,
        )
        .unwrap();
        let durable_lock = PersistedConsensusLock {
            height: 1,
            round: 0,
            block_hash: hash_a,
            value_hash: value_a,
            proposal: block_a,
            polc_votes: vec![prevote_a],
        };
        driver
            .vote_safety
            .record(1, 0, 1, Some(&durable_lock))
            .unwrap();

        // Step 3-4: crash and reconstruct from durable state. The lock and its
        // independently verified PoLC must be restored, not merely round-skip.
        let config = driver.engine.config.clone();
        drop(driver);
        let engine = NodeEngine::init(config).unwrap();
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let mut restarted = ConsensusDriver::new(engine, vote_safety);
        restarted.sync.mark_caught_up(restarted.height());
        assert_eq!(restarted.locked_round, Some(0));
        assert_eq!(restarted.locked_value, Some(hash_a));
        assert_eq!(restarted.current_round(), 1);

        // Step 5: a conflicting round-1 proposal without a later PoLC must get
        // a nil prevote. Before T7-01 the restarted driver was unlocked and
        // legitimately prevoted this conflicting full block hash.
        let mut block_b = make_block(&restarted.engine.state);
        block_b.header.proposer_round = 1;
        block_b.header.polc_round = None;
        block_b.header.timestamp = block_b.header.timestamp.saturating_add(1);
        block_b.header.value_hash = block_b.compute_value_hash(restarted.engine.state.total_supply);
        let hash_b = block_b.header.block_hash();
        assert_ne!(hash_b, hash_a);
        restarted.pending_blocks.insert(hash_b, block_b);
        restarted.current_phase = RoundPhase::Propose;
        let actions = restarted.maybe_prevote_current_round_proposal();
        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == Bytes32::ZERO
        )));
        assert!(!actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote) if vote.block_hash == hash_b
        )));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn restart_rejects_persisted_lock_with_invalid_proposer_authorization() {
        let seed = [0x7Eu8; 32];
        let (mut driver, dir) = local_driver(seed, "restart_rejects_bad_lock_envelope");
        let local = install_active_validator(&mut driver, seed, "local");
        driver.refresh_registered_voters();

        let mut proposal = make_strict_block(&driver, seed, 0, vec![]);
        let block_hash = proposal.header.block_hash();
        let value_hash = proposal.header.value_hash;
        let prevote = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Prevote,
            block_hash,
            validator_id_for(&local),
            governing_snapshot_root(&driver, 1),
            TEST_CHAIN_ID,
            &local,
        )
        .unwrap();
        let mut bad_pq = proposal.proposer_authorization.pq_sig.as_slice().to_vec();
        bad_pq[0] ^= 0x01;
        proposal.proposer_authorization.pq_sig = VariableBytes::from_slice(&bad_pq).unwrap();
        let durable_lock = PersistedConsensusLock {
            height: 1,
            round: 0,
            block_hash,
            value_hash,
            proposal,
            polc_votes: vec![prevote],
        };
        driver
            .vote_safety
            .record(1, 0, 1, Some(&durable_lock))
            .unwrap();

        let config = driver.engine.config.clone();
        drop(driver);
        let engine = NodeEngine::init(config).unwrap();
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let restarted = ConsensusDriver::new(engine, vote_safety);
        assert!(restarted.locked_round.is_none());
        assert!(restarted.locked_value.is_none());
        assert!(restarted
            .vote_safety_unavailable
            .as_deref()
            .is_some_and(|reason| reason.contains("persisted lock proposal failed verification")));

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn persisted_lock_above_round_cap_is_rejected_before_restore_mutation() {
        let seed = [0x7Fu8; 32];
        let (mut driver, dir) = local_driver(seed, "restart_rejects_high_lock_round");
        let local = install_active_validator(&mut driver, seed, "local");
        driver.refresh_registered_voters();
        let proposal = make_strict_block(&driver, seed, 0, vec![]);
        let block_hash = proposal.header.block_hash();
        let prevote = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Prevote,
            block_hash,
            validator_id_for(&local),
            governing_snapshot_root(&driver, 1),
            TEST_CHAIN_ID,
            &local,
        )
        .unwrap();
        let lock = PersistedConsensusLock {
            height: 1,
            round: MAX_ROUNDS_PER_HEIGHT,
            block_hash,
            value_hash: proposal.header.value_hash,
            proposal,
            polc_votes: vec![prevote],
        };
        assert!(driver.vote_safety.record(1, 0, 1, Some(&lock)).is_err());
        let before = (driver.locked_round, driver.valid_round, driver.locked_value);
        assert!(driver.verify_and_restore_consensus_lock(lock).is_err());
        assert_eq!(
            before,
            (driver.locked_round, driver.valid_round, driver.locked_value)
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn lock_polc_is_durable_before_precommit_broadcast_is_returned() {
        let mut fixture = shared_four_validator_fixture();
        let mut driver = fixture.drivers.remove(0);
        let remote_a = HybridKeypair::new(ClassicalKeypair::from_seed(&[0x02; 32]), PqKeypair::from_seed(&[0x02; 32]).unwrap());
        let remote_b = HybridKeypair::new(ClassicalKeypair::from_seed(&[0x03; 32]), PqKeypair::from_seed(&[0x03; 32]).unwrap());
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());

        let block = make_strict_block(&driver, [0x01u8; 32], 0, vec![]);
        let round = block.header.proposer_round;
        driver.current_round = round;
        let hash = block.header.block_hash();
        let _ = process_single_validator_proposal(&mut driver, block);
        for (port, signer) in [(9711, &remote_a), (9712, &remote_b)] {
            let vote = indra_consensus::vote::produce_vote(
                1,
                round,
                VoteStep::Prevote,
                hash,
                validator_id_for(signer),
                governing_snapshot_root(&driver, 1),
                TEST_CHAIN_ID,
                signer,
            )
            .unwrap();
            let actions = driver.process(DriverEvent::InboundVote {
                from: SocketAddr::from(([127, 0, 0, 1], port)),
                vote,
            });
            if actions.iter().any(|action| {
                matches!(
                    action,
                    DriverAction::BroadcastVote(vote)
                        if vote.step == VoteStep::Precommit && vote.block_hash == hash
                )
            }) {
                let VoteSafetyLoadResult::Record(record) = driver.vote_safety.load() else {
                    panic!("precommit broadcast requires a durable safety record")
                };
                let lock = record
                    .consensus_lock
                    .expect("precommit broadcast requires a durable lock");
                assert_eq!(lock.block_hash, hash);
                assert!(lock.polc_votes.len() >= 3);
                drop(driver);
                for dir in fixture.dirs { let _ = std::fs::remove_dir_all(dir); }
                return;
            }
        }
        panic!("prevote quorum did not produce the expected precommit");
    }

    #[test]
    fn accepted_vote_replay_skips_snapshot_and_hybrid_work_across_peer_paths() {
        let (mut driver, dir) = local_driver([0x40u8; 32], "accepted_vote_replay_fast_path");
        let remote = install_active_validator(&mut driver, [0x41u8; 32], "remote");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());
        let vote = indra_consensus::vote::produce_vote(
            driver.next_height(),
            0,
            VoteStep::Prevote,
            Bytes32::ZERO,
            validator_id_for(&remote),
            governing_snapshot_root(&driver, driver.next_height()),
            TEST_CHAIN_ID,
            &remote,
        )
        .unwrap();
        let phase_before = driver.current_phase();

        let first = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9291".parse().unwrap(),
            vote: vote.clone(),
        });
        assert!(!first
            .iter()
            .any(|action| matches!(action, DriverAction::DisconnectInvalidConsensusPeer { .. })));
        assert_eq!(
            driver.vote_admission_metrics,
            VoteAdmissionMetrics {
                snapshot_lookups: 1,
                hybrid_authority_calls: 1,
                successful_ed25519_verifications: 1,
                successful_mldsa_verifications: 1,
                collector_insertions: 1,
                qc_formations: 0,
            }
        );
        let metrics_after_first = driver.vote_admission_metrics;
        let seen_after_first = driver.seen_round_votes.len();

        // A new authenticated address models another relay or a replacement
        // connection. The driver state is consensus-scoped, not connection-scoped.
        let replay = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9292".parse().unwrap(),
            vote,
        });
        assert!(replay.is_empty());
        assert_eq!(driver.vote_admission_metrics, metrics_after_first);
        assert_eq!(driver.seen_round_votes.len(), seen_after_first);
        assert_eq!(driver.current_phase(), phase_before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cryptographically_invalid_vote_cannot_poison_replay_state() {
        let (mut driver, dir) = local_driver([0x42u8; 32], "invalid_vote_no_replay_poison");
        let remote = install_active_validator(&mut driver, [0x43u8; 32], "remote");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());
        let valid = indra_consensus::vote::produce_vote(
            driver.next_height(),
            0,
            VoteStep::Prevote,
            Bytes32::ZERO,
            validator_id_for(&remote),
            governing_snapshot_root(&driver, driver.next_height()),
            TEST_CHAIN_ID,
            &remote,
        )
        .unwrap();
        let slot = (valid.validator_id, valid.height, valid.round, valid.step);
        let mut invalid = valid.clone();
        let mut bad_pq = invalid.signature.pq_sig.as_slice().to_vec();
        bad_pq[0] ^= 0x80;
        invalid.signature.pq_sig = VariableBytes::from_slice(&bad_pq).unwrap();

        let rejected = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9293".parse().unwrap(),
            vote: invalid,
        });
        assert!(rejected
            .iter()
            .any(|action| matches!(action, DriverAction::DisconnectInvalidConsensusPeer { .. })));
        assert!(!driver.seen_round_votes.contains_key(&slot));
        assert_eq!(driver.vote_admission_metrics.collector_insertions, 0);
        assert_eq!(
            driver.vote_admission_metrics.successful_mldsa_verifications,
            0
        );

        let accepted = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9294".parse().unwrap(),
            vote: valid,
        });
        assert!(!accepted
            .iter()
            .any(|action| matches!(action, DriverAction::DisconnectInvalidConsensusPeer { .. })));
        assert!(driver.seen_round_votes.contains_key(&slot));
        assert_eq!(driver.vote_admission_metrics.hybrid_authority_calls, 2);
        assert_eq!(driver.vote_admission_metrics.collector_insertions, 1);
        assert_eq!(
            driver
                .vote_admission_metrics
                .successful_ed25519_verifications,
            1
        );
        assert_eq!(
            driver.vote_admission_metrics.successful_mldsa_verifications,
            1
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_snapshot_vote_is_not_collapsed_into_exact_replay() {
        let (mut driver, dir) = local_driver([0x44u8; 32], "wrong_snapshot_not_replay");
        let remote = install_active_validator(&mut driver, [0x45u8; 32], "remote");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());
        let remote_id = validator_id_for(&remote);
        let accepted = indra_consensus::vote::produce_vote(
            driver.next_height(),
            0,
            VoteStep::Prevote,
            Bytes32::ZERO,
            remote_id,
            governing_snapshot_root(&driver, driver.next_height()),
            TEST_CHAIN_ID,
            &remote,
        )
        .unwrap();
        let _ = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9295".parse().unwrap(),
            vote: accepted,
        });
        let before = driver.vote_admission_metrics;
        let wrong_root = Bytes32::from([0xA6; 32]);
        let wrong = indra_consensus::vote::produce_vote(
            driver.next_height(),
            0,
            VoteStep::Prevote,
            Bytes32::ZERO,
            remote_id,
            wrong_root,
            TEST_CHAIN_ID,
            &remote,
        )
        .unwrap();

        let rejected = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9296".parse().unwrap(),
            vote: wrong,
        });
        assert!(rejected
            .iter()
            .any(|action| matches!(action, DriverAction::DisconnectInvalidConsensusPeer { .. })));
        assert_eq!(
            driver.vote_admission_metrics.snapshot_lookups,
            before.snapshot_lookups + 1
        );
        assert_eq!(
            driver.vote_admission_metrics.hybrid_authority_calls,
            before.hybrid_authority_calls + 1
        );
        assert_eq!(
            driver
                .vote_admission_metrics
                .successful_ed25519_verifications,
            before.successful_ed25519_verifications
        );
        assert_eq!(driver.vote_admission_metrics.collector_insertions, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vote_replay_identity_is_round_step_and_height_scoped() {
        let (mut driver, dir) = local_driver([0x46u8; 32], "vote_replay_dimensions");
        let remote = install_active_validator(&mut driver, [0x47u8; 32], "remote");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());
        let height = driver.next_height();
        let root = governing_snapshot_root(&driver, height);
        let remote_id = validator_id_for(&remote);
        let votes = [
            indra_consensus::vote::produce_vote(
                height,
                0,
                VoteStep::Prevote,
                Bytes32::ZERO,
                remote_id,
                root,
                TEST_CHAIN_ID,
                &remote,
            )
            .unwrap(),
            indra_consensus::vote::produce_vote(
                height,
                0,
                VoteStep::Precommit,
                Bytes32::ZERO,
                remote_id,
                root,
                TEST_CHAIN_ID,
                &remote,
            )
            .unwrap(),
            indra_consensus::vote::produce_vote(
                height,
                1,
                VoteStep::Prevote,
                Bytes32::ZERO,
                remote_id,
                root,
                TEST_CHAIN_ID,
                &remote,
            )
            .unwrap(),
        ];
        for (index, vote) in votes.iter().cloned().enumerate() {
            let actions = driver.process(DriverEvent::InboundVote {
                from: SocketAddr::from(([127, 0, 0, 1], 9300 + index as u16)),
                vote,
            });
            assert!(!actions.iter().any(|action| matches!(
                action,
                DriverAction::DisconnectInvalidConsensusPeer { .. }
            )));
        }
        assert_eq!(driver.vote_admission_metrics.snapshot_lookups, 3);
        assert_eq!(driver.vote_admission_metrics.hybrid_authority_calls, 3);
        assert_eq!(driver.seen_round_votes.len(), 3);

        let before = driver.vote_admission_metrics;
        let seen_before = driver.seen_round_votes.len();
        driver.engine.state.height = height;
        let stale = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9303".parse().unwrap(),
            vote: votes[0].clone(),
        });
        assert!(stale.is_empty());
        assert_eq!(driver.vote_admission_metrics, before);
        assert_eq!(driver.seen_round_votes.len(), seen_before);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vote_replay_state_is_not_persisted_across_restart() {
        let seed = [0x48u8; 32];
        let (mut driver, dir) = local_driver(seed, "vote_replay_restart_scope");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());
        let signer = HybridKeypair::new(
            ClassicalKeypair::from_seed(&seed),
            PqKeypair::from_seed(&seed).unwrap(),
        );
        let vote = indra_consensus::vote::produce_vote(
            driver.next_height(),
            0,
            VoteStep::Prevote,
            Bytes32::ZERO,
            validator_id_for(&signer),
            governing_snapshot_root(&driver, driver.next_height()),
            TEST_CHAIN_ID,
            &signer,
        )
        .unwrap();
        let _ = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9304".parse().unwrap(),
            vote: vote.clone(),
        });
        assert_eq!(driver.seen_round_votes.len(), 1);

        let config = driver.engine.config.clone();
        drop(driver);
        let engine = NodeEngine::init(config).unwrap();
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let mut restarted = ConsensusDriver::new(engine, vote_safety);
        restarted.sync.mark_caught_up(restarted.height());
        assert!(restarted.seen_round_votes.is_empty());
        let _ = restarted.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9305".parse().unwrap(),
            vote,
        });
        assert_eq!(restarted.vote_admission_metrics.snapshot_lookups, 1);
        assert_eq!(restarted.vote_admission_metrics.hybrid_authority_calls, 1);
        assert_eq!(restarted.vote_admission_metrics.collector_insertions, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn driver_detects_double_precommit() {
        let (mut driver, dir) = local_driver([0x48u8; 32], "double_precommit");
        let remote = install_active_validator(&mut driver, [0x49u8; 32], "remote");
        driver.refresh_registered_voters();

        let remote_id = indra_core::types::crypto::hybrid_identity_id(
            &remote.public_key().classical.0,
            &remote.public_key().pq.0,
        );
        let vote_a = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Precommit,
            Bytes32::from([0xAAu8; 32]),
            remote_id,
            governing_snapshot_root(&driver, 1),
            TEST_CHAIN_ID,
            &remote,
        )
        .unwrap();
        let vote_b = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Precommit,
            Bytes32::from([0xBBu8; 32]),
            remote_id,
            governing_snapshot_root(&driver, 1),
            TEST_CHAIN_ID,
            &remote,
        )
        .unwrap();

        let peer: SocketAddr = "127.0.0.1:9301".parse().unwrap();
        let _ = driver.process(DriverEvent::InboundVote {
            from: peer,
            vote: vote_a,
        });
        let actions = driver.process(DriverEvent::InboundVote {
            from: peer,
            vote: vote_b,
        });

        assert!(actions
            .iter()
            .any(|a| matches!(a, DriverAction::SlashDetected(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn conflicting_vote_orderings_bypass_exact_replay_fast_path() {
        for (index, reverse) in [false, true].into_iter().enumerate() {
            let seed = [0x50u8 + index as u8; 32];
            let suffix = format!("equivocation_order_{index}");
            let (mut driver, dir) = local_driver(seed, &suffix);
            let remote =
                install_active_validator(&mut driver, [0x52u8 + index as u8; 32], "remote");
            driver.refresh_registered_voters();
            driver.sync.mark_caught_up(driver.height());
            let remote_id = validator_id_for(&remote);
            let make_vote = |hash| {
                indra_consensus::vote::produce_vote(
                    driver.next_height(),
                    0,
                    VoteStep::Precommit,
                    hash,
                    remote_id,
                    governing_snapshot_root(&driver, driver.next_height()),
                    TEST_CHAIN_ID,
                    &remote,
                )
                .unwrap()
            };
            let a = make_vote(Bytes32::from([0xAA; 32]));
            let b = make_vote(Bytes32::from([0xBB; 32]));
            let (first, second) = if reverse { (b, a) } else { (a, b) };
            let _ = driver.process(DriverEvent::InboundVote {
                from: "127.0.0.1:9297".parse().unwrap(),
                vote: first,
            });
            let evidence = driver.process(DriverEvent::InboundVote {
                from: "127.0.0.1:9298".parse().unwrap(),
                vote: second,
            });

            assert!(evidence
                .iter()
                .any(|action| matches!(action, DriverAction::SlashDetected(_))));
            assert_eq!(driver.vote_admission_metrics.snapshot_lookups, 2);
            assert_eq!(driver.vote_admission_metrics.hybrid_authority_calls, 2);
            assert_eq!(
                driver
                    .vote_admission_metrics
                    .successful_ed25519_verifications,
                2
            );
            assert_eq!(
                driver.vote_admission_metrics.successful_mldsa_verifications,
                2
            );
            assert_eq!(driver.vote_admission_metrics.collector_insertions, 0);
            let _ = std::fs::remove_dir_all(&dir);
        }
    }

    #[test]
    fn forged_vote_cannot_poison_real_validators_round_slot() {
        let (mut driver, dir) = local_driver([0x4Bu8; 32], "forged_vote_slot");
        let real = install_active_validator(&mut driver, [0x4Cu8; 32], "real");
        let attacker = install_active_validator(&mut driver, [0x4Du8; 32], "attacker");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());
        let real_id = indra_core::types::crypto::hybrid_identity_id(
            &real.public_key().classical.0,
            &real.public_key().pq.0,
        );
        let slot = (real_id, driver.next_height(), 0, VoteStep::Prevote);
        let forged = indra_consensus::vote::produce_vote(
            driver.next_height(),
            0,
            VoteStep::Prevote,
            Bytes32::ZERO,
            real_id,
            governing_snapshot_root(&driver, driver.next_height()),
            TEST_CHAIN_ID,
            &attacker,
        )
        .unwrap();
        let forged_actions = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9302".parse().unwrap(),
            vote: forged,
        });
        assert!(forged_actions
            .iter()
            .any(|action| matches!(action, DriverAction::DisconnectInvalidConsensusPeer { .. })));
        assert!(!driver.seen_round_votes.contains_key(&slot));

        let legitimate = indra_consensus::vote::produce_vote(
            driver.next_height(),
            0,
            VoteStep::Prevote,
            Bytes32::ZERO,
            real_id,
            governing_snapshot_root(&driver, driver.next_height()),
            TEST_CHAIN_ID,
            &real,
        )
        .unwrap();
        let legitimate_actions = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9303".parse().unwrap(),
            vote: legitimate,
        });
        assert!(!legitimate_actions
            .iter()
            .any(|action| matches!(action, DriverAction::DisconnectInvalidConsensusPeer { .. })));
        assert_eq!(
            driver.seen_round_votes.get(&slot),
            Some(&AcceptedVoteIdentity {
                block_hash: Bytes32::ZERO,
                snapshot_root: governing_snapshot_root(&driver, driver.next_height()),
            })
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn implausible_future_vote_is_rejected_before_slot_reservation() {
        let (mut driver, dir) = local_driver([0x4Eu8; 32], "future_vote_bound");
        let remote = install_active_validator(&mut driver, [0x4Fu8; 32], "remote");
        driver.refresh_registered_voters();
        let remote_id = indra_core::types::crypto::hybrid_identity_id(
            &remote.public_key().classical.0,
            &remote.public_key().pq.0,
        );
        let vote = indra_consensus::vote::produce_vote(
            driver.next_height().saturating_add(100),
            driver
                .current_round
                .saturating_add(MAX_ACCEPTED_ROUND_JUMP + 1),
            VoteStep::Prevote,
            Bytes32::ZERO,
            remote_id,
            governing_snapshot_root(&driver, driver.next_height()),
            TEST_CHAIN_ID,
            &remote,
        )
        .unwrap();
        let _ = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9304".parse().unwrap(),
            vote,
        });
        assert!(driver.seen_round_votes.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn forged_conflicting_votes_do_not_reach_slash_detector() {
        let (mut driver, dir) = local_driver([0x50u8; 32], "forged_vote_slash");
        let real = install_active_validator(&mut driver, [0x51u8; 32], "real");
        let attacker = install_active_validator(&mut driver, [0x52u8; 32], "attacker");
        driver.refresh_registered_voters();
        let real_id = indra_core::types::crypto::hybrid_identity_id(
            &real.public_key().classical.0,
            &real.public_key().pq.0,
        );
        for hash in [Bytes32::from([0xAA; 32]), Bytes32::from([0xBB; 32])] {
            let forged = indra_consensus::vote::produce_vote(
                driver.next_height(),
                0,
                VoteStep::Precommit,
                hash,
                real_id,
                governing_snapshot_root(&driver, driver.next_height()),
                TEST_CHAIN_ID,
                &attacker,
            )
            .unwrap();
            let actions = driver.process(DriverEvent::InboundVote {
                from: "127.0.0.1:9305".parse().unwrap(),
                vote: forged,
            });
            assert!(!actions
                .iter()
                .any(|action| matches!(action, DriverAction::SlashDetected(_))));
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn polc_round_exposes_valid_round_for_reproposal() {
        let (mut driver, dir) = local_driver([0x4Au8; 32], "valid_round");
        let _local = install_active_validator(&mut driver, [0x4Au8; 32], "local");
        driver.refresh_registered_voters();

        driver.valid_round = Some(2);
        driver.valid_value = Some(Bytes32::from([0x11u8; 32]));

        assert_eq!(driver.proposal_polc_round(1), Some(2));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn last_qc_persisted_after_commit() {
        let (mut driver, dir) = local_driver([0x61u8; 32], "persist_qc");
        let _local = install_active_validator(&mut driver, [0x61u8; 32], "local");
        driver.refresh_registered_voters();

        let block = make_strict_block(&driver, [0x61u8; 32], 0, vec![]);
        let _ = process_single_validator_proposal(&mut driver, block);

        let qc_path = driver.engine.config.state_dir().join("last_qc.bin");
        assert!(qc_path.exists(), "expected last_qc.bin to be created");
        let bytes = std::fs::read(qc_path).unwrap();
        assert!(!bytes.is_empty(), "persisted QC must be non-empty");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn last_qc_is_stale_detects_height_mismatch() {
        let (mut driver, dir) = local_driver([0xA1u8; 32], "last_qc_stale");
        let local = install_active_validator(&mut driver, [0xA1u8; 32], "local");
        driver.refresh_registered_voters();
        driver.engine.state.height = 5;
        driver.last_qc_bytes =
            single_validator_qc_bytes(&driver, &local, 3, Bytes32::from([0x33u8; 32]));

        assert!(driver.last_qc_is_stale());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn last_qc_is_stale_false_when_height_matches() {
        let (mut driver, dir) = local_driver([0xA2u8; 32], "last_qc_fresh");
        let local = install_active_validator(&mut driver, [0xA2u8; 32], "local");
        driver.refresh_registered_voters();
        driver.engine.state.height = 5;
        driver.last_qc_bytes =
            single_validator_qc_bytes(&driver, &local, 5, Bytes32::from([0x55u8; 32]));

        assert!(!driver.last_qc_is_stale());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sync_path_promotes_last_qc_bytes() {
        let (mut source, source_dir) = local_driver([0xA3u8; 32], "sync_promote_source");
        let _source_local = install_active_validator(&mut source, [0xA3u8; 32], "local");
        source.refresh_registered_voters();

        let block1 = make_strict_block(&source, [0xA3u8; 32], 0, vec![]);
        let _ = process_single_validator_proposal(&mut source, block1.clone());
        let qc_for_height_1 = source.last_qc_bytes();
        assert!(!qc_for_height_1.is_empty());
        let block2 = make_strict_block(&source, [0xA3u8; 32], 0, qc_for_height_1.clone());

        let (mut driver, dir) = local_driver([0xA3u8; 32], "sync_promote_importer");
        let local = install_active_validator(&mut driver, [0xA3u8; 32], "local");
        driver.refresh_registered_voters();

        driver.engine.commit_proposal(&block1).unwrap();
        driver.promote_block_header_qc(&block1, "sync").unwrap();
        driver.engine.commit_proposal(&block2).unwrap();
        driver.promote_block_header_qc(&block2, "sync").unwrap();
        driver.refresh_registered_voters();
        driver.sync_mut().on_block_imported(block2.header.height);
        driver.reset_round();

        assert_eq!(driver.height(), 2);
        assert_eq!(driver.last_qc_bytes(), qc_for_height_1);
        assert_eq!(driver.last_qc_height(), Some(1));
        assert!(driver.last_qc_is_stale());
        assert!(matches!(
            driver.request_qc_if_needed().as_slice(),
            [DriverAction::RequestQC { height }] if *height == 2
        ));

        drop(local);
        let _ = std::fs::remove_dir_all(&source_dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sync_then_consensus_transition_recovers_after_qc_response() {
        let (mut source, source_dir) = local_driver([0xB5u8; 32], "sync_transition_source");
        let source_local = install_active_validator(&mut source, [0xB5u8; 32], "local");
        source.refresh_registered_voters();

        let block1 = make_strict_block(&source, [0xB5u8; 32], 0, vec![]);
        let _ = process_single_validator_proposal(&mut source, block1.clone());
        let qc_for_height_1 = source.last_qc_bytes();
        let block2 = make_strict_block(&source, [0xB5u8; 32], 0, qc_for_height_1.clone());

        let (mut driver, dir) = local_driver([0xB5u8; 32], "sync_transition_importer");
        let local = install_active_validator(&mut driver, [0xB5u8; 32], "local");
        driver.refresh_registered_voters();

        for block in [&block1, &block2] {
            driver.engine.commit_proposal(block).unwrap();
            driver.promote_block_header_qc(block, "sync").unwrap();
            driver.sync_mut().on_block_imported(block.header.height);
            driver.reset_round();
        }
        driver.on_sync_caught_up();

        assert_eq!(driver.height(), 2);
        assert_eq!(driver.last_qc_height(), Some(1));
        assert!(driver.last_qc_is_stale());
        assert!(matches!(
            driver.request_qc_if_needed().as_slice(),
            [DriverAction::RequestQC { height }] if *height == 2
        ));

        let source_validator_id = validator_id_for(&source_local);
        let qc_vote = indra_consensus::vote::produce_vote(
            2,
            block2.header.proposer_round,
            VoteStep::Precommit,
            block2.header.block_hash(),
            source_validator_id,
            governing_snapshot_root(&driver, 2),
            TEST_CHAIN_ID,
            &source_local,
        )
        .unwrap();
        let qc = indra_consensus::build_qc(
            2,
            block2.header.proposer_round,
            block2.header.block_hash(),
            TEST_CHAIN_ID,
            governing_snapshot_root(&driver, 2),
            &driver.engine.qc_validators(),
            vec![&qc_vote],
        )
        .unwrap();
        let qc_bytes = qc.encode_to_vec();

        let _ = driver.process(DriverEvent::QcResponse {
            from: "127.0.0.1:9510".parse().unwrap(),
            height: 2,
            qc_bytes: qc_bytes.clone(),
        });

        assert_eq!(driver.last_qc_height(), Some(2));
        assert_eq!(driver.last_qc_bytes(), qc_bytes);
        assert!(
            !driver.last_qc_is_stale(),
            "current-tip QC response must clear sync-recovery staleness"
        );
        assert!(
            driver.request_qc_if_needed().is_empty(),
            "driver must stop requesting QC after current-tip QC recovery"
        );
        let local_vrf = VrfKeypair::from_seed(&[0xB5; 32]);
        let election = (0..4_096)
            .map(|round| driver.proposer_election_for_height(3, round).unwrap())
            .find(|election| {
                indra_consensus::proposer::compute_proposer_vrf(
                    validator_id_for(&source_local),
                    &local_vrf,
                    election,
                )
                .is_ok_and(|result| result.eligible)
            })
            .expect("local validator must become eligible within the bounded round search");
        let proposal_result =
            driver
                .engine
                .propose(&election, 1_700_000_003, driver.last_qc_bytes(), None);
        assert!(
            proposal_result.is_ok(),
            "recovered current-tip QC should allow height-3 proposal construction: {proposal_result:?}"
        );

        drop(local);
        let _ = std::fs::remove_dir_all(&source_dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_recovers_pending_current_tip_qc_after_commit_boundary() {
        let (mut source, source_dir) = local_driver([0xC1u8; 32], "pending_qc_source");
        let _source_local = install_active_validator(&mut source, [0xC1u8; 32], "local");
        source.refresh_registered_voters();

        let block1 = make_strict_block(&source, [0xC1u8; 32], 0, vec![]);
        let _ = process_single_validator_proposal(&mut source, block1.clone());
        let qc_for_height_1 = source.last_qc_bytes();
        assert!(!qc_for_height_1.is_empty());

        let (mut driver, dir) = local_driver([0xC1u8; 32], "pending_qc_restart");
        let local = install_active_validator(&mut driver, [0xC1u8; 32], "local");
        driver.refresh_registered_voters();

        driver.engine.commit_proposal(&block1).unwrap();
        driver
            .set_last_qc_bytes_if_newer(1, qc_for_height_1.clone())
            .unwrap();
        assert_eq!(driver.height(), 1);
        assert_eq!(driver.last_qc_height(), Some(1));

        let block2 = make_strict_block(&driver, [0xC1u8; 32], 0, driver.last_qc_bytes());
        let validator_id = validator_id_for(&local);
        let qc_vote = indra_consensus::vote::produce_vote(
            2,
            block2.header.proposer_round,
            VoteStep::Precommit,
            block2.header.block_hash(),
            validator_id,
            governing_snapshot_root(&driver, 2),
            TEST_CHAIN_ID,
            &local,
        )
        .unwrap();
        let qc_for_height_2 = indra_consensus::build_qc(
            2,
            block2.header.proposer_round,
            block2.header.block_hash(),
            TEST_CHAIN_ID,
            governing_snapshot_root(&driver, 2),
            &driver.engine.qc_validators(),
            vec![&qc_vote],
        )
        .unwrap()
        .encode_to_vec();

        // Simulate the old crash boundary exactly: the current-tip QC has been
        // durably staged, the block/state commit reaches height 2, but the
        // process stops before `last_qc.bin` is promoted from height 1 to 2.
        indra_storage::save_pending_last_qc(&driver.engine.config.state_dir(), &qc_for_height_2)
            .unwrap();
        driver.engine.commit_proposal(&block2).unwrap();
        assert_eq!(driver.height(), 2);
        assert_eq!(driver.last_qc_height(), Some(1));
        assert_eq!(
            ConsensusDriver::decode_qc_height(
                &indra_storage::load_last_qc(&driver.engine.config.state_dir())
                    .unwrap()
                    .unwrap()
            ),
            Some(1)
        );
        assert_eq!(
            ConsensusDriver::decode_qc_height(
                &indra_storage::load_pending_last_qc(&driver.engine.config.state_dir())
                    .unwrap()
                    .unwrap()
            ),
            Some(2)
        );

        let config = driver.engine.config.clone();
        drop(local);
        drop(driver);

        let engine = NodeEngine::init(config).unwrap();
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let restarted = ConsensusDriver::new(engine, vote_safety);
        assert_eq!(restarted.height(), 2);
        assert_eq!(restarted.last_qc_height(), Some(2));
        assert_eq!(restarted.last_qc_bytes(), qc_for_height_2);
        assert!(!restarted.last_qc_is_stale());
        assert!(restarted.request_qc_if_needed().is_empty());
        assert_eq!(
            ConsensusDriver::decode_qc_height(
                &indra_storage::load_last_qc(&restarted.engine.config.state_dir())
                    .unwrap()
                    .unwrap()
            ),
            Some(2)
        );
        assert!(
            indra_storage::load_pending_last_qc(&restarted.engine.config.state_dir())
                .unwrap()
                .is_none()
        );

        let _ = std::fs::remove_dir_all(&source_dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sync_batch_partial_failure_does_not_promote_orphaned_qc() {
        let (mut source, source_dir) = local_driver([0xB6u8; 32], "sync_partial_source");
        let _source_local = install_active_validator(&mut source, [0xB6u8; 32], "local");
        source.refresh_registered_voters();

        let block1 = make_strict_block(&source, [0xB6u8; 32], 0, vec![]);
        let _ = process_single_validator_proposal(&mut source, block1.clone());
        let qc_for_height_1 = source.last_qc_bytes();
        let block2 = make_strict_block(&source, [0xB6u8; 32], 0, qc_for_height_1.clone());
        let _ = process_single_validator_proposal(&mut source, block2.clone());
        let qc_for_height_2 = source.last_qc_bytes();
        let mut bad_block3 = make_strict_block(&source, [0xB6u8; 32], 0, qc_for_height_2);
        bad_block3.header.prev_hash = Bytes32::from([0xEEu8; 32]);
        reauthorize_test_proposal(&mut bad_block3, [0xB6u8; 32], TEST_CHAIN_ID.as_bytes());

        let (mut driver, dir) = local_driver([0xB6u8; 32], "sync_partial_importer");
        install_active_validator(&mut driver, [0xB6u8; 32], "local");
        driver.refresh_registered_voters();

        for block in [&block1, &block2] {
            driver.engine.commit_proposal(block).unwrap();
            driver.promote_block_header_qc(block, "sync").unwrap();
        }
        assert!(driver.engine.commit_proposal(&bad_block3).is_err());

        assert_eq!(driver.height(), 2);
        assert_eq!(driver.last_qc_height(), Some(1));
        assert_eq!(driver.last_qc_bytes(), qc_for_height_1);

        let _ = std::fs::remove_dir_all(&source_dir);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn set_last_qc_bytes_if_newer_height_ordering() {
        let (mut driver, dir) = local_driver([0xB7u8; 32], "last_qc_ordering");
        let local = install_active_validator(&mut driver, [0xB7u8; 32], "local");
        driver.refresh_registered_voters();

        let qc_height_3 =
            single_validator_qc_bytes(&driver, &local, 3, Bytes32::from([0x33u8; 32]));
        let qc_height_5_a =
            single_validator_qc_bytes(&driver, &local, 5, Bytes32::from([0x55u8; 32]));
        let qc_height_5_b =
            single_validator_qc_bytes(&driver, &local, 5, Bytes32::from([0x56u8; 32]));

        driver
            .set_last_qc_bytes_if_newer(5, qc_height_5_a.clone())
            .unwrap();
        assert_eq!(driver.last_qc_height(), Some(5));
        assert_eq!(driver.last_qc_bytes(), qc_height_5_a);

        driver.set_last_qc_bytes_if_newer(3, qc_height_3).unwrap();
        assert_eq!(driver.last_qc_height(), Some(5));
        assert_eq!(driver.last_qc_bytes(), qc_height_5_a);

        driver
            .set_last_qc_bytes_if_newer(5, qc_height_5_a.clone())
            .unwrap();
        assert_eq!(driver.last_qc_bytes(), qc_height_5_a);

        assert!(driver.set_last_qc_bytes_if_newer(5, qc_height_5_b).is_err());
        assert_eq!(driver.last_qc_height(), Some(5));
        assert_eq!(driver.last_qc_bytes(), qc_height_5_a);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn equivalent_qc_different_signer_subset_no_conflict() {
        let (mut driver, dir) = local_driver([0xB8u8; 32], "equivalent_qc_subset");
        let a = install_active_validator(&mut driver, [0xB8u8; 32], "a");
        let b = install_active_validator(&mut driver, [0xB9u8; 32], "b");
        let c = install_active_validator(&mut driver, [0xBAu8; 32], "c");
        let d = install_active_validator(&mut driver, [0xBBu8; 32], "d");
        driver.refresh_registered_voters();

        let block_hash = Bytes32::from([0x88u8; 32]);
        let qc_abc = qc_bytes_from_signers(&driver, &[&a, &b, &c], 5, 0, block_hash);
        let qc_abd = qc_bytes_from_signers(&driver, &[&a, &b, &d], 5, 0, block_hash);
        assert_ne!(
            qc_abc, qc_abd,
            "test setup must produce distinct QC bytes from different valid signer subsets"
        );

        driver
            .set_last_qc_bytes_if_newer(5, qc_abc.clone())
            .unwrap();
        driver.set_last_qc_bytes_if_newer(5, qc_abd).unwrap();

        assert_eq!(
            driver.last_qc_bytes(),
            qc_abc,
            "benign equivalent QCs should not replace the cached bytes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_qc_matching_metadata_still_rejected() {
        let (mut driver, dir) = local_driver([0xBCu8; 32], "invalid_equivalent_qc");
        let a = install_active_validator(&mut driver, [0xBCu8; 32], "a");
        let b = install_active_validator(&mut driver, [0xBDu8; 32], "b");
        let c = install_active_validator(&mut driver, [0xBEu8; 32], "c");
        let d = install_active_validator(&mut driver, [0xBFu8; 32], "d");
        driver.refresh_registered_voters();

        let block_hash = Bytes32::from([0x8Au8; 32]);
        let qc_abc = qc_bytes_from_signers(&driver, &[&a, &b, &c], 6, 0, block_hash);
        let mut invalid_qc = qc_bytes_from_signers(&driver, &[&a, &b, &d], 6, 0, block_hash);
        let last = invalid_qc.len() - 1;
        invalid_qc[last] ^= 0x01;

        driver
            .set_last_qc_bytes_if_newer(6, qc_abc.clone())
            .unwrap();
        let err = driver
            .set_last_qc_bytes_if_newer(6, invalid_qc)
            .unwrap_err();

        assert!(
            matches!(err, NodeError::BlockInvalid { .. }),
            "invalid same-content QC must be rejected, not treated as benign equivalent"
        );
        assert_eq!(driver.last_qc_bytes(), qc_abc);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn genuinely_conflicting_content_still_hard_errors() {
        let (mut driver, dir) = local_driver([0xC0u8; 32], "genuine_qc_conflict");
        let a = install_active_validator(&mut driver, [0xC0u8; 32], "a");
        let b = install_active_validator(&mut driver, [0xC1u8; 32], "b");
        let c = install_active_validator(&mut driver, [0xC2u8; 32], "c");
        let d = install_active_validator(&mut driver, [0xC3u8; 32], "d");
        driver.refresh_registered_voters();

        let qc_a = qc_bytes_from_signers(&driver, &[&a, &b, &c], 7, 0, Bytes32::from([0x8Du8; 32]));
        let qc_b = qc_bytes_from_signers(&driver, &[&a, &b, &d], 7, 0, Bytes32::from([0x8Eu8; 32]));

        driver.set_last_qc_bytes_if_newer(7, qc_a.clone()).unwrap();
        assert!(driver.set_last_qc_bytes_if_newer(7, qc_b).is_err());
        assert_eq!(driver.last_qc_bytes(), qc_a);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn proposal_with_wrong_qc_height_rejected_at_intake_not_just_finalization() {
        let (mut driver, dir) = local_driver([0xA4u8; 32], "proposal_wrong_qc_intake");
        let _local = install_active_validator(&mut driver, [0xA4u8; 32], "local");
        driver.refresh_registered_voters();

        let block1 = make_strict_block(&driver, [0xA4u8; 32], 0, vec![]);
        let _ = process_single_validator_proposal(&mut driver, block1);
        let qc_for_height_1 = driver.last_qc_bytes();

        let block2 = make_strict_block(&driver, [0xA4u8; 32], 0, qc_for_height_1.clone());
        let _ = process_single_validator_proposal(&mut driver, block2);
        assert_eq!(driver.height(), 2);

        let mut malformed_block3 =
            make_strict_block(&driver, [0xA4u8; 32], 0, driver.last_qc_bytes());
        malformed_block3.header.quorum_certificate =
            VariableBytes::from_slice(&qc_for_height_1).unwrap();
        reauthorize_test_proposal(
            &mut malformed_block3,
            [0xA4; 32],
            driver.engine.state.chain_id.as_bytes(),
        );
        let malformed_hash = malformed_block3.header.block_hash();
        let actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: malformed_block3,
        });

        assert!(actions
            .iter()
            .all(|action| matches!(action, DriverAction::None)));
        assert!(driver.pending_block(&malformed_hash).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn driver_restart_with_stale_persisted_qc_does_not_restore_it() {
        let seed = [0xA5u8; 32];
        let stale_qc_bytes = {
            let (mut source_driver, source_dir) = local_driver(seed, "restart_stale_qc_source");
            let local = install_active_validator(&mut source_driver, seed, "local");
            source_driver.refresh_registered_voters();
            source_driver.engine.state.height = 3;
            let bytes =
                single_validator_qc_bytes(&source_driver, &local, 3, Bytes32::from([0xA5u8; 32]));
            let _ = std::fs::remove_dir_all(&source_dir);
            bytes
        };

        let (mut pristine, dir) = local_driver(seed, "restart_stale_qc");
        let config = pristine.engine.config.clone();
        pristine.engine.write_chain_manifest().unwrap();
        drop(pristine);
        indra_storage::save_last_qc(&config.state_dir(), &stale_qc_bytes).unwrap();

        let mut engine = NodeEngine::init(config).unwrap();
        engine.state.height = 5;
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let restarted = ConsensusDriver::new(engine, vote_safety);

        assert!(restarted.last_qc_bytes().is_empty());
        assert!(restarted.last_qc_is_stale());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn normal_consensus_unaffected_by_staleness_checks() {
        let (mut driver, dir) = local_driver([0xA6u8; 32], "normal_qc_fresh");
        let _local = install_active_validator(&mut driver, [0xA6u8; 32], "local");
        driver.refresh_registered_voters();

        let seed_at_height_one = driver.engine.state.election_seed;
        let block1 = make_strict_block(&driver, [0xA6u8; 32], 0, vec![]);
        let _ = process_single_validator_proposal(&mut driver, block1.clone());
        assert_eq!(driver.height(), 1);
        assert_ne!(driver.engine.state.election_seed, seed_at_height_one);
        let seed_at_height_two = driver.engine.state.election_seed;
        let _ = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: block1,
        });
        assert_eq!(driver.engine.state.election_seed, seed_at_height_two);
        assert!(!driver.last_qc_is_stale());

        let block2 = make_strict_block(&driver, [0xA6u8; 32], 0, driver.last_qc_bytes());
        let _ = process_single_validator_proposal(&mut driver, block2);
        assert_eq!(driver.height(), 2);
        assert!(!driver.last_qc_is_stale());
        assert!(driver.request_qc_if_needed().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn last_qc_restored_on_restart() {
        let dir = temp_dir("restore_qc");
        let seed = [0x62u8; 32];
        {
            let (mut driver, _) = local_driver_at_dir(seed, dir.clone());
            let _local = install_active_validator(&mut driver, seed, "local");
            driver.refresh_registered_voters();
            let block = make_strict_block(&driver, seed, 0, vec![]);
            let _ = process_single_validator_proposal(&mut driver, block);
            assert!(!driver.last_qc_bytes().is_empty());
        }

        let mut config = NodeConfig::local_test(dir.clone());
        let pq = PqKeypair::from_seed(&seed).unwrap();
        config.genesis_path = Some(dir.join("genesis.toml").to_string_lossy().to_string());
        config.validator_seed = Some(seed);
        config.vrf_seed = Some(seed);
        config.pq_pk = Some(pq.public_key().0.to_vec());
        config.pq_seed = Some(pq.secret_key_bytes());
        let engine = NodeEngine::init(config).unwrap();
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let restarted = ConsensusDriver::new(engine, vote_safety);
        assert!(
            !restarted.last_qc_bytes().is_empty(),
            "restarted driver should restore persisted QC"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn startup_discards_structurally_valid_qc_with_forged_signatures() {
        let seed = [0x68u8; 32];
        let (mut driver, dir) = local_driver(seed, "restore_forged_qc");
        let _local = install_active_validator(&mut driver, seed, "local");
        driver.refresh_registered_voters();
        let block = make_strict_block(&driver, seed, 0, vec![]);
        let _ = process_single_validator_proposal(&mut driver, block);
        let mut qc = QuorumCertificateV1::decode_exact(&driver.last_qc_bytes()).unwrap();
        let mut forged_signature = qc.pq_signatures[0].pq_sig.as_slice().to_vec();
        forged_signature[0] ^= 0x80;
        qc.pq_signatures[0].pq_sig = VariableBytes::from_slice(&forged_signature).unwrap();
        let forged = qc.encode_to_vec();
        indra_storage::save_last_qc(&driver.engine.config.state_dir(), &forged).unwrap();
        indra_storage::save_pending_last_qc(&driver.engine.config.state_dir(), &forged).unwrap();
        let config = driver.engine.config.clone();
        drop(driver);

        let engine = NodeEngine::init(config).unwrap();
        let state_dir = engine.config.state_dir();
        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let restarted = ConsensusDriver::new(engine, vote_safety);
        assert!(restarted.last_qc_bytes().is_empty());
        assert!(indra_storage::load_last_qc(&state_dir).unwrap().is_none());
        assert!(indra_storage::load_pending_last_qc(&state_dir)
            .unwrap()
            .is_none());
        assert!(!restarted.request_qc_if_needed().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn node_can_enter_proposer_path_without_qc() {
        let (mut driver, dir) = local_driver([0x63u8; 32], "no_qc_no_propose");
        driver.engine.state.height = 2;
        driver.engine.state.tip_hash = Bytes32::from([0x11; 32]);
        assert!(
            driver.can_propose(),
            "proposal gating should be enforced during block construction, not before proposer selection"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_qc_file_does_not_panic() {
        let (mut driver, dir) = local_driver([0x64u8; 32], "missing_qc");
        driver.engine.state.height = 2;
        driver.engine.state.tip_hash = Bytes32::from([0x22; 32]);
        let engine = driver.engine;

        let vote_safety = VoteSafetyStore::open(engine.config.vote_safety_path());
        let restarted = ConsensusDriver::new(engine, vote_safety);
        assert!(restarted.last_qc_bytes().is_empty());
        assert!(restarted.can_propose());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn handle_qc_response_accepts_valid_qc() {
        let (mut driver, dir) = local_driver([0x65u8; 32], "qc_response_valid");
        let local = install_active_validator(&mut driver, [0x65u8; 32], "local");
        driver.engine.state.height = 7;
        driver.engine.state.tip_hash = Bytes32::from([0x31; 32]);
        driver.refresh_registered_voters();

        let validator_id = indra_core::types::crypto::hybrid_identity_id(
            &local.public_key().classical.0,
            &local.public_key().pq.0,
        );
        let value_hash = Bytes32::from([0x44u8; 32]);
        let vote = indra_consensus::vote::produce_vote(
            7,
            0,
            VoteStep::Precommit,
            value_hash,
            validator_id,
            governing_snapshot_root(&driver, 7),
            TEST_CHAIN_ID,
            &local,
        )
        .unwrap();
        let validators = driver.engine.qc_validators();
        let qc = indra_consensus::build_qc(
            7,
            0,
            value_hash,
            TEST_CHAIN_ID,
            governing_snapshot_root(&driver, 7),
            &validators,
            vec![&vote],
        )
        .unwrap();
        let qc_bytes = qc.encode_to_vec();

        let _ = driver.process(DriverEvent::QcResponse {
            from: "127.0.0.1:9501".parse().unwrap(),
            height: 7,
            qc_bytes: qc_bytes.clone(),
        });

        assert_eq!(driver.last_qc_bytes(), qc_bytes);
        assert!(driver
            .engine
            .config
            .state_dir()
            .join("last_qc.bin")
            .exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn handle_qc_response_rejects_invalid_qc() {
        let (mut driver, dir) = local_driver([0x66u8; 32], "qc_response_invalid");
        let local = install_active_validator(&mut driver, [0x66u8; 32], "local");
        driver.engine.state.height = 7;
        driver.refresh_registered_voters();

        let validator_id = indra_core::types::crypto::hybrid_identity_id(
            &local.public_key().classical.0,
            &local.public_key().pq.0,
        );
        let value_hash = Bytes32::from([0x45u8; 32]);
        let vote = indra_consensus::vote::produce_vote(
            7,
            0,
            VoteStep::Precommit,
            value_hash,
            validator_id,
            governing_snapshot_root(&driver, 7),
            TEST_CHAIN_ID,
            &local,
        )
        .unwrap();
        let validators = driver.engine.qc_validators();
        let qc = indra_consensus::build_qc(
            7,
            0,
            value_hash,
            TEST_CHAIN_ID,
            governing_snapshot_root(&driver, 7),
            &validators,
            vec![&vote],
        )
        .unwrap();
        let mut qc_bytes = qc.encode_to_vec();
        let last = qc_bytes.len() - 1;
        qc_bytes[last] ^= 0x01;

        let actions = driver.process(DriverEvent::QcResponse {
            from: "127.0.0.1:9502".parse().unwrap(),
            height: 7,
            qc_bytes,
        });

        assert!(driver.last_qc_bytes().is_empty());
        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::ScorePeer {
                event: indra_network::peer::ScoreEvent::InvalidMessage,
                ..
            }
        )));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn handle_qc_response_rejects_trailing_bytes_before_verification() {
        let (mut driver, dir) = local_driver([0x68u8; 32], "qc_response_trailing");
        let local = install_active_validator(&mut driver, [0x68u8; 32], "local");
        driver.engine.state.height = 7;
        driver.refresh_registered_voters();
        let validator_id = indra_core::types::crypto::hybrid_identity_id(
            &local.public_key().classical.0,
            &local.public_key().pq.0,
        );
        let value_hash = Bytes32::from([0x46u8; 32]);
        let vote = indra_consensus::vote::produce_vote(
            7,
            0,
            VoteStep::Precommit,
            value_hash,
            validator_id,
            governing_snapshot_root(&driver, 7),
            TEST_CHAIN_ID,
            &local,
        )
        .unwrap();
        let validators = driver.engine.qc_validators();
        let mut qc_bytes = indra_consensus::build_qc(
            7,
            0,
            value_hash,
            TEST_CHAIN_ID,
            governing_snapshot_root(&driver, 7),
            &validators,
            vec![&vote],
        )
        .unwrap()
        .encode_to_vec();
        qc_bytes.push(0xA5);

        let actions = driver.process(DriverEvent::QcResponse {
            from: "127.0.0.1:9503".parse().unwrap(),
            height: 7,
            qc_bytes,
        });
        assert!(driver.last_qc_bytes().is_empty());
        assert!(actions.iter().any(|action| matches!(
            action,
            DriverAction::ScorePeer {
                event: indra_network::peer::ScoreEvent::InvalidMessage,
                ..
            }
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn handle_qc_response_ignores_wrong_height() {
        let (mut driver, dir) = local_driver([0x67u8; 32], "qc_response_height");
        driver.engine.state.height = 100;
        let _ = driver.process(DriverEvent::QcResponse {
            from: "127.0.0.1:9503".parse().unwrap(),
            height: 50,
            qc_bytes: vec![1, 2, 3],
        });
        assert!(driver.last_qc_bytes().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn qc_request_not_sent_when_qc_present() {
        let (mut driver, dir) = local_driver([0x68u8; 32], "qc_request_present");
        let local = install_active_validator(&mut driver, [0x68u8; 32], "local");
        driver.refresh_registered_voters();
        driver.engine.state.height = 9;
        driver.last_qc_bytes =
            single_validator_qc_bytes(&driver, &local, 9, Bytes32::from([0x68u8; 32]));
        assert!(driver.request_qc_if_needed().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn qc_request_served_when_height_matches() {
        let (mut driver, dir) = local_driver([0x69u8; 32], "qc_request_served");
        let local = install_active_validator(&mut driver, [0x69u8; 32], "local");
        driver.refresh_registered_voters();
        let from: SocketAddr = "127.0.0.1:9504".parse().unwrap();
        driver.engine.state.height = 12;
        let expected_qc_bytes =
            single_validator_qc_bytes(&driver, &local, 12, Bytes32::from([0x69u8; 32]));
        driver.last_qc_bytes = expected_qc_bytes.clone();

        let actions = driver.process(DriverEvent::QcRequest { from, height: 12 });

        assert!(matches!(
            actions.as_slice(),
            [DriverAction::SendQCResponse { to, height, qc_bytes }]
                if *to == from && *height == 12 && qc_bytes == &expected_qc_bytes
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn qc_request_served_from_block_header_when_one_ahead() {
        let (mut driver, dir) = local_driver([0x6Au8; 32], "qc_request_one_ahead");
        let _local = install_active_validator(&mut driver, [0x6Au8; 32], "local");
        driver.refresh_registered_voters();

        let block1 = make_strict_block(&driver, [0x6Au8; 32], 0, vec![]);
        let _ = process_single_validator_proposal(&mut driver, block1);
        let qc_for_height_1 = driver.last_qc_bytes();
        assert!(!qc_for_height_1.is_empty());

        let mut block2 = make_strict_block(&driver, [0x6Au8; 32], 0, qc_for_height_1.clone());
        block2.header.quorum_certificate =
            indra_core::VariableBytes::from_slice(&qc_for_height_1).unwrap();
        let _ = process_single_validator_proposal(&mut driver, block2);

        let from: SocketAddr = "127.0.0.1:9505".parse().unwrap();
        let actions = driver.process(DriverEvent::QcRequest { from, height: 1 });

        assert!(matches!(
            actions.as_slice(),
            [DriverAction::SendQCResponse { to, height, qc_bytes }]
                if *to == from && *height == 1 && *qc_bytes == qc_for_height_1
        ));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reproposal_is_voted_with_its_own_block_hash() {
        let mut fixture = shared_four_validator_fixture();
        let mut driver = fixture.drivers.remove(0);
        let local = HybridKeypair::new(ClassicalKeypair::from_seed(&[0x01; 32]), PqKeypair::from_seed(&[0x01; 32]).unwrap());
        let remote_a = HybridKeypair::new(ClassicalKeypair::from_seed(&[0x02; 32]), PqKeypair::from_seed(&[0x02; 32]).unwrap());
        let remote_b = HybridKeypair::new(ClassicalKeypair::from_seed(&[0x03; 32]), PqKeypair::from_seed(&[0x03; 32]).unwrap());
        driver.refresh_registered_voters();

        let block = make_strict_block(&driver, [0x01u8; 32], 0, vec![]);
        let value_hash = block.header.value_hash;
        let original_hash = block.header.block_hash();
        let height = block.header.height;
        let original_round = block.header.proposer_round;
        driver.current_round = original_round;
        let mut actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: block,
        });
        actions.extend(driver.on_propose_timeout());
        assert!(actions.iter().any(
            |a| matches!(a, DriverAction::BroadcastVote(vote) if vote.step == VoteStep::Prevote)
        ));

        let remote_a_id = indra_core::types::crypto::hybrid_identity_id(
            &remote_a.public_key().classical.0,
            &remote_a.public_key().pq.0,
        );
        let remote_b_id = indra_core::types::crypto::hybrid_identity_id(
            &remote_b.public_key().classical.0,
            &remote_b.public_key().pq.0,
        );
        let prevote_a = indra_consensus::vote::produce_vote(
            height,
            original_round,
            VoteStep::Prevote,
            original_hash,
            remote_a_id,
            governing_snapshot_root(&driver, height),
            TEST_CHAIN_ID,
            &remote_a,
        )
        .unwrap();
        let prevote_b = indra_consensus::vote::produce_vote(
            height,
            original_round,
            VoteStep::Prevote,
            original_hash,
            remote_b_id,
            governing_snapshot_root(&driver, height),
            TEST_CHAIN_ID,
            &remote_b,
        )
        .unwrap();

        let _ = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9701".parse().unwrap(),
            vote: prevote_a,
        });
        let _ = driver.process(DriverEvent::InboundVote {
            from: "127.0.0.1:9702".parse().unwrap(),
            vote: prevote_b,
        });

        assert_eq!(driver.valid_round, Some(original_round));
        assert_eq!(driver.valid_value, Some(original_hash));
        let (valid_block, valid_round) = driver
            .take_valid_block_for_reproposal()
            .expect("valid block should be stored for reproposal");
        assert_eq!(valid_round, original_round);
        assert_eq!(valid_block.header.value_hash, value_hash);

        let local_vrf = VrfKeypair::from_seed(&[0x01; 32]);
        let election = (original_round + 1..MAX_ROUNDS_PER_HEIGHT)
            .map(|round| election_for_round(&driver, height, round))
            .find(|election| {
                indra_consensus::proposer::compute_proposer_vrf(
                    validator_id_for(&local),
                    &local_vrf,
                    election,
                )
                .is_ok_and(|result| result.eligible)
            })
            .expect("local proposer must become eligible for a later test round");
        let reproposal_round = election.round;

        let reproposed = driver
            .engine
            .repropose(
                &valid_block,
                reproposal_round,
                Some(valid_round),
                &election,
                valid_block.header.timestamp,
                driver.last_qc_bytes(),
            )
            .expect("reproposal should succeed");

        assert_eq!(reproposed.header.value_hash, value_hash);
        assert_eq!(reproposed.header.proposer_round, reproposal_round);
        assert_eq!(reproposed.header.polc_round, Some(original_round));

        driver.current_round = reproposal_round;
        driver.current_phase = RoundPhase::Propose;
        let reproposed_hash = reproposed.header.block_hash();
        driver.pending_blocks.insert(reproposed_hash, reproposed);
        let reproposal_actions = driver.maybe_prevote_current_round_proposal();
        assert!(reproposal_actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == reproposed_hash
        )));

        drop(driver);
        for dir in fixture.dirs { let _ = std::fs::remove_dir_all(dir); }
    }

    #[test]
    fn repropose_preserves_value_hash() {
        let (mut driver, dir) = local_driver([0x77u8; 32], "repropose_value_hash");
        let local = install_active_validator(&mut driver, [0x77u8; 32], "local");
        driver.refresh_registered_voters();

        let height = driver.engine.state.height + 1;
        let election_round_zero = election_for_round(&driver, height, 0);
        let proposal = driver
            .engine
            .propose(
                &election_round_zero,
                1_700_000_001,
                driver.last_qc_bytes(),
                None,
            )
            .expect("initial proposal should succeed");

        let local_validator_id = indra_core::types::crypto::hybrid_identity_id(
            &local.public_key().classical.0,
            &local.public_key().pq.0,
        );
        assert!(
            indra_consensus::proposer::compute_proposer_vrf(
                local_validator_id,
                &VrfKeypair::from_seed(&[0x77; 32]),
                &election_round_zero,
            )
            .unwrap()
            .eligible
        );
        let local_vrf = VrfKeypair::from_seed(&[0x77; 32]);
        let election_round_one = (1..4_096)
            .map(|round| election_for_round(&driver, height, round))
            .find(|election| {
                indra_consensus::proposer::compute_proposer_vrf(
                    local_validator_id,
                    &local_vrf,
                    election,
                )
                .is_ok_and(|result| result.eligible)
            })
            .expect("local proposer must become eligible for a later test round");

        let reproposed = driver
            .engine
            .repropose(
                &proposal,
                election_round_one.round,
                Some(0),
                &election_round_one,
                proposal.header.timestamp,
                driver.last_qc_bytes(),
            )
            .expect("reproposal should succeed");

        assert!(verify_live_proposal(&driver, &reproposed).is_ok());
        assert_eq!(
            proposal.header.value_entropy,
            reproposed.header.value_entropy
        );
        assert_eq!(proposal.header.value_hash, reproposed.header.value_hash);
        assert_ne!(proposal.header.block_hash(), reproposed.header.block_hash());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn vrf007_substituted_entropy_is_rejected_before_vote_or_lock_mutation() {
        let seed = [0x7Au8; 32];
        let (mut driver, dir) = local_driver(seed, "vrf007_admission_order");
        let local = install_active_validator(&mut driver, seed, "local");
        driver.refresh_registered_voters();
        driver.sync.mark_caught_up(driver.height());

        let height = driver.next_height();
        let round_zero = election_for_round(&driver, height, 0);
        let original = driver
            .engine
            .propose(&round_zero, 1_700_000_001, driver.last_qc_bytes(), None)
            .unwrap();
        let local_id = validator_id_for(&local);
        let local_vrf = VrfKeypair::from_seed(&seed);
        let later = (1..4_096)
            .map(|round| election_for_round(&driver, height, round))
            .find(|election| {
                indra_consensus::proposer::compute_proposer_vrf(local_id, &local_vrf, election)
                    .is_ok_and(|claim| claim.eligible)
            })
            .expect("test validator becomes eligible in a later round");
        let mut substituted = driver
            .engine
            .repropose(
                &original,
                later.round,
                Some(0),
                &later,
                original.header.timestamp,
                driver.last_qc_bytes(),
            )
            .unwrap();

        // Reproduce VRF-007 exactly: install another genuine eligible entropy
        // proof but retain the old stable value identity and post-state roots.
        substituted.block.header.value_entropy = indra_core::types::block::ProposalEntropyV1 {
            origin_proposer_id: substituted.header.proposer_id,
            origin_round: substituted.header.proposer_round,
            vrf_output: substituted.header.proposer_vrf_output.clone(),
            vrf_proof: substituted.header.proposer_vrf_proof.clone(),
        };
        reauthorize_test_proposal(
            &mut substituted,
            seed,
            driver.engine.state.chain_id.as_bytes(),
        );
        assert_ne!(
            original.header.value_entropy,
            substituted.header.value_entropy
        );
        assert_eq!(original.header.value_hash, substituted.header.value_hash);
        assert!(verify_live_proposal(&driver, &substituted).is_ok());
        assert_ne!(
            substituted.header.value_hash,
            substituted.compute_value_hash(driver.engine.state.total_supply),
            "the substituted entropy has a different canonical stable identity"
        );

        driver.current_round = later.round;
        driver.current_phase = RoundPhase::Propose;
        let pending_before = driver.pending_blocks.len();
        let collectors_before = driver.vote_collectors.len();
        let lock_before = (
            driver.locked_round,
            driver.locked_value,
            driver.locked_value_hash,
        );
        let actions = driver.process(DriverEvent::InboundBlock {
            from: None,
            proposal: substituted,
        });

        assert!(actions
            .iter()
            .all(|action| matches!(action, DriverAction::None)));
        assert_eq!(driver.pending_blocks.len(), pending_before);
        assert_eq!(driver.vote_collectors.len(), collectors_before);
        assert_eq!(
            (
                driver.locked_round,
                driver.locked_value,
                driver.locked_value_hash
            ),
            lock_before
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn repropose_matches_clone_based_reference() {
        let (mut driver, dir) = local_driver([0x78u8; 32], "repropose_clone_reference");
        let _local = install_active_validator(&mut driver, [0x78u8; 32], "local");
        driver.refresh_registered_voters();

        let height = driver.engine.state.height + 1;
        let election_round_zero = election_for_round(&driver, height, 0);
        let proposal = driver
            .engine
            .propose(
                &election_round_zero,
                1_700_000_001,
                driver.last_qc_bytes(),
                None,
            )
            .expect("initial proposal should succeed");

        let reproposal_round = (1..4_096)
            .find(|round| {
                driver
                    .engine
                    .is_proposer(&election_for_round(&driver, height, *round))
            })
            .expect("test proposer must become eligible within bounded round search");
        let election_round_one = election_for_round(&driver, height, reproposal_round);
        let pre_state = driver.engine.state.clone();
        let reproposed = driver
            .engine
            .repropose(
                &proposal,
                reproposal_round,
                Some(0),
                &election_round_one,
                proposal.header.timestamp,
                driver.last_qc_bytes(),
            )
            .expect("reproposal should succeed");

        let mut clone_reference = pre_state.clone();
        let snapshot = clone_reference
            .snapshot_for_consensus_height(height)
            .unwrap();
        let verified = indra_core::types::proposal::verify_proposal(
            &reproposed,
            clone_reference.chain_id.as_bytes(),
            &clone_reference.election_seed,
            snapshot,
        )
        .unwrap();
        apply_block(&mut clone_reference, &verified, 0).unwrap();
        assert_eq!(
            reproposed.header.value_hash,
            reproposed.compute_value_hash(clone_reference.total_supply)
        );
        assert_eq!(proposal.header.value_hash, reproposed.header.value_hash);
        assert_eq!(reproposed.header.proposer_round, reproposal_round);
        assert_eq!(reproposed.header.polc_round, Some(0));
        assert_eq!(
            driver.engine.state, pre_state,
            "reproposal projection must roll back and leave real engine state untouched"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reproposal_converges_after_disruption() {
        let mut fixture = shared_four_validator_fixture();
        let fixture_dirs = fixture.dirs.clone();
        let (left, right) = fixture.drivers.split_at_mut(1);
        let driver_a = &mut left[0];
        let driver_b = &mut right[0];
        let a = HybridKeypair::new(ClassicalKeypair::from_seed(&[0x01; 32]), PqKeypair::from_seed(&[0x01; 32]).unwrap());
        let b = HybridKeypair::new(ClassicalKeypair::from_seed(&[0x02; 32]), PqKeypair::from_seed(&[0x02; 32]).unwrap());
        let c = HybridKeypair::new(ClassicalKeypair::from_seed(&[0x03; 32]), PqKeypair::from_seed(&[0x03; 32]).unwrap());
        let d = HybridKeypair::new(ClassicalKeypair::from_seed(&[0x04; 32]), PqKeypair::from_seed(&[0x04; 32]).unwrap());
        driver_a.refresh_registered_voters();
        driver_b.refresh_registered_voters();

        let a_id = indra_core::types::crypto::hybrid_identity_id(
            &a.public_key().classical.0,
            &a.public_key().pq.0,
        );
        let b_id = indra_core::types::crypto::hybrid_identity_id(
            &b.public_key().classical.0,
            &b.public_key().pq.0,
        );
        let c_id = indra_core::types::crypto::hybrid_identity_id(
            &c.public_key().classical.0,
            &c.public_key().pq.0,
        );
        let d_id = indra_core::types::crypto::hybrid_identity_id(
            &d.public_key().classical.0,
            &d.public_key().pq.0,
        );

        let a_vrf = VrfKeypair::from_seed(&[0x01; 32]);
        let election_round_zero = (0..MAX_ROUNDS_PER_HEIGHT)
            .map(|round| election_for_round(&driver_a, 1, round))
            .find(|election| {
                indra_consensus::proposer::compute_proposer_vrf(a_id, &a_vrf, election)
                    .is_ok_and(|result| result.eligible)
            })
            .expect("A must become eligible in the bounded test search");
        let original_round = election_round_zero.round;
        let block_x = driver_a
            .engine
            .propose(
                &election_round_zero,
                1_700_000_100,
                driver_a.last_qc_bytes(),
                None,
            )
            .expect("A should propose its eligible round");
        let value_hash = block_x.header.value_hash;
        let block_x_hash = block_x.header.block_hash();

        driver_b.current_round = original_round;
        let mut stage_actions = driver_b.process(DriverEvent::InboundBlock {
            from: Some("127.0.0.1:9801".parse().unwrap()),
            proposal: block_x.clone(),
        });
        stage_actions.extend(driver_b.on_propose_timeout());
        assert!(stage_actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == block_x_hash
        )));

        for (peer, validator_id, signer) in [
            ("127.0.0.1:9802", a_id, &a),
            ("127.0.0.1:9803", c_id, &c),
            ("127.0.0.1:9804", d_id, &d),
        ] {
            let vote = indra_consensus::vote::produce_vote(
                1,
                original_round,
                VoteStep::Prevote,
                block_x_hash,
                validator_id,
                governing_snapshot_root(&driver_b, 1),
                TEST_CHAIN_ID,
                signer,
            )
            .unwrap();
            let _ = driver_b.process(DriverEvent::InboundVote {
                from: peer.parse().unwrap(),
                vote,
            });
        }

        assert_eq!(driver_b.valid_round, Some(original_round));
        assert_eq!(driver_b.valid_value, Some(block_x_hash));
        assert_eq!(
            driver_b
                .take_valid_block_for_reproposal()
                .expect("valid block should be preserved")
                .0
                .header
                .value_hash,
            value_hash
        );

        driver_b.on_precommit_timeout().unwrap();
        let b_vrf = VrfKeypair::from_seed(&[0x02; 32]);
        let election_round_one = (original_round + 1..MAX_ROUNDS_PER_HEIGHT)
            .map(|round| election_for_round(&driver_b, 1, round))
            .find(|election| {
                indra_consensus::proposer::compute_proposer_vrf(b_id, &b_vrf, election)
                    .is_ok_and(|result| result.eligible)
            })
            .expect("B must become eligible in a later bounded test round");
        let reproposal_round = election_round_one.round;
        driver_b.current_round = reproposal_round;
        driver_b.current_phase = RoundPhase::Propose;
        let (valid_block, valid_round) = driver_b
            .take_valid_block_for_reproposal()
            .expect("round 1 proposer should still have valid block");
        let block_y = driver_b
            .engine
            .repropose(
                &valid_block,
                reproposal_round,
                Some(valid_round),
                &election_round_one,
                valid_block.header.timestamp,
                driver_b.last_qc_bytes(),
            )
            .expect("B should repropose valid value at round 1");
        assert_eq!(block_y.header.value_hash, value_hash);
        let block_y_hash = block_y.header.block_hash();
        assert_ne!(block_y_hash, block_x_hash);

        let mut reproposal_actions = driver_b.process(DriverEvent::InboundBlock {
            from: None,
            proposal: block_y.clone(),
        });
        reproposal_actions.extend(driver_b.on_propose_timeout());
        assert!(reproposal_actions.iter().any(|action| matches!(
            action,
            DriverAction::BroadcastVote(vote)
                if vote.step == VoteStep::Prevote && vote.block_hash == block_y_hash
        )));

        for (peer, validator_id, signer) in [
            ("127.0.0.1:9811", a_id, &a),
            ("127.0.0.1:9812", c_id, &c),
            ("127.0.0.1:9813", d_id, &d),
        ] {
            let vote = indra_consensus::vote::produce_vote(
                1,
                reproposal_round,
                VoteStep::Prevote,
                block_y_hash,
                validator_id,
                governing_snapshot_root(&driver_b, 1),
                TEST_CHAIN_ID,
                signer,
            )
            .unwrap();
            let _ = driver_b.process(DriverEvent::InboundVote {
                from: peer.parse().unwrap(),
                vote,
            });
        }

        for (peer, validator_id, signer) in [
            ("127.0.0.1:9821", a_id, &a),
            ("127.0.0.1:9822", c_id, &c),
            ("127.0.0.1:9823", d_id, &d),
        ] {
            let vote = indra_consensus::vote::produce_vote(
                1,
                reproposal_round,
                VoteStep::Precommit,
                block_y_hash,
                validator_id,
                governing_snapshot_root(&driver_b, 1),
                TEST_CHAIN_ID,
                signer,
            )
            .unwrap();
            let _ = driver_b.process(DriverEvent::InboundVote {
                from: peer.parse().unwrap(),
                vote,
            });
        }

        assert_eq!(driver_b.height(), 1, "reproposal should commit the block");

        drop(fixture);
        for dir in fixture_dirs {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn node_syncs_before_joining_consensus() {
        let (mut driver, dir) = local_driver([0x6Bu8; 32], "sync_before_consensus");
        let _local = install_active_validator(&mut driver, [0x6Bu8; 32], "local");
        driver.refresh_registered_voters();

        let peer: SocketAddr = "127.0.0.1:9601".parse().unwrap();
        let voter = driver.registered_voters[0].clone();
        let local_height = driver.height();
        driver.sync.peer_connected(voter.validator_id);
        let _ = driver.sync.observe_status(
            voter.validator_id,
            peer,
            10,
            Bytes32::ZERO,
            voter.stake,
            voter.stake,
            local_height,
            Instant::now(),
        );
        assert!(!driver.sync.is_caught_up());

        let block = make_block(&driver.engine.state);
        let hash = block.header.block_hash();
        driver.pending_blocks.insert(hash, block);

        let actions = driver.maybe_prevote_current_round_proposal();
        assert!(actions.is_empty(), "syncing nodes must not join consensus");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn consensus_gate_blocks_votes_during_sync() {
        let (mut driver, dir) = local_driver([0x6Cu8; 32], "sync_vote_gate");
        let _local = install_active_validator(&mut driver, [0x6Cu8; 32], "local");
        let remote = install_active_validator(&mut driver, [0x6Du8; 32], "remote");
        driver.refresh_registered_voters();

        let peer: SocketAddr = "127.0.0.1:9602".parse().unwrap();
        let voter = driver.registered_voters[0].clone();
        let local_height = driver.height();
        driver.sync.peer_connected(voter.validator_id);
        let _ = driver.sync.observe_status(
            voter.validator_id,
            peer,
            10,
            Bytes32::ZERO,
            voter.stake,
            voter.stake,
            local_height,
            Instant::now(),
        );
        assert!(!driver.sync.is_caught_up());

        let remote_id = indra_core::types::crypto::hybrid_identity_id(
            &remote.public_key().classical.0,
            &remote.public_key().pq.0,
        );
        let vote = indra_consensus::vote::produce_vote(
            1,
            0,
            VoteStep::Prevote,
            Bytes32::from([0xABu8; 32]),
            remote_id,
            governing_snapshot_root(&driver, 1),
            TEST_CHAIN_ID,
            &remote,
        )
        .unwrap();

        let actions = driver.process(DriverEvent::InboundVote { from: peer, vote });
        assert!(
            !actions
                .iter()
                .any(|action| matches!(action, DriverAction::BroadcastVote(_))),
            "syncing nodes must not emit votes"
        );
        let collector = driver
            .vote_collectors
            .get(&(1, 0, VoteStep::Prevote))
            .expect("vote should be recorded while syncing");
        assert_eq!(collector.vote_count(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }
