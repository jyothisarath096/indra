//! Quorum Certificate construction and verification.

use indra_core::types::qc::SIGNER_BITFIELD_BYTES;
use std::collections::{BTreeMap, HashMap, HashSet};

use indra_core::types::{
    crypto::PQVoteSig,
    primitives::{
        Bytes32, MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES, MAX_VALIDATORS, VariableBytes,
        has_strict_two_thirds_quorum, muldiv, strict_two_thirds_minimum, validate_consensus_round,
    },
    qc::{ClassicalVoteSig, QuorumCertificateV1},
    vote::{VoteStep, VoteV1},
};
use indra_crypto::hybrid::{
    ClassicalPublicKey, ClassicalSignature, PqPublicKey, PqSignature, verify_classical, verify_pq,
};

use crate::{
    error::{ConsensusError, ConsensusResult},
    vote::vote_signing_bytes,
};

/// A registered validator for QC construction and verification.
#[derive(Debug, Clone)]
pub struct QcValidator {
    /// Validator identity.
    pub validator_id: Bytes32,
    /// Position in the epoch's sorted validator list (0-indexed).
    pub position: usize,
    /// ML-DSA-87 public key bytes.
    pub pq_pk: Vec<u8>,
    /// Ed25519 public key bytes.
    pub classical_pk: [u8; 32],
    /// Stake in Spark.
    pub stake: u64,
}

/// A QC builder — accumulates votes and builds the QC when quorum is reached.
pub struct QcBuilder {
    height: u64,
    round: u32,
    block_hash: Bytes32,
    chain_id: String,
    snapshot_root: Bytes32,
    validators: Vec<QcValidator>,
    total_stake: u64,
    votes: BTreeMap<Bytes32, VoteV1>,
}

impl QcBuilder {
    /// Create a new QC builder.
    pub fn new(
        height: u64,
        round: u32,
        block_hash: Bytes32,
        chain_id: String,
        snapshot_root: Bytes32,
        validators: Vec<QcValidator>,
    ) -> Self {
        let total_stake = validators
            .iter()
            .map(|v| v.stake)
            .fold(0u64, |a, b| a.saturating_add(b));
        Self {
            height,
            round,
            block_hash,
            chain_id,
            snapshot_root,
            validators,
            total_stake,
            votes: BTreeMap::new(),
        }
    }

    /// Add a precommit vote to the builder.
    pub fn add_precommit(&mut self, vote: VoteV1) {
        if vote.height == self.height
            && vote.round == self.round
            && vote.block_hash == self.block_hash
            && vote.snapshot_root == self.snapshot_root
        {
            self.votes.insert(vote.validator_id, vote);
        }
    }

    /// Current stake fraction in basis points.
    pub fn current_stake_bps(&self) -> u64 {
        if self.total_stake == 0 {
            return 0;
        }
        let voted: u64 = self
            .votes
            .keys()
            .filter_map(|id| self.validators.iter().find(|v| v.validator_id == *id))
            .map(|v| v.stake)
            .fold(0u64, |a, b| a.saturating_add(b));
        muldiv(voted, 10_000, self.total_stake)
    }

    /// Build the QC if quorum has been reached.
    pub fn build(&self) -> ConsensusResult<QuorumCertificateV1> {
        validate_round(self.round)?;
        let stake_bps = self.current_stake_bps();
        let voted_stake = self
            .votes
            .keys()
            .filter_map(|id| self.validators.iter().find(|v| v.validator_id == *id))
            .fold(0u64, |total, validator| {
                total.saturating_add(validator.stake)
            });
        if !has_strict_two_thirds_quorum(voted_stake, self.total_stake) {
            return Err(ConsensusError::QuorumNotReached {
                have_bps: stake_bps,
            });
        }
        build_qc_from_votes(
            self.height,
            self.round,
            self.block_hash,
            &self.chain_id,
            self.snapshot_root,
            &self.validators,
            self.votes.values().collect(),
        )
    }
}

/// Build a QC from a set of precommit votes.
pub fn build_qc(
    height: u64,
    round: u32,
    block_hash: Bytes32,
    chain_id: &str,
    snapshot_root: Bytes32,
    validators: &[QcValidator],
    votes: Vec<&VoteV1>,
) -> ConsensusResult<QuorumCertificateV1> {
    build_qc_from_votes(
        height,
        round,
        block_hash,
        chain_id,
        snapshot_root,
        validators,
        votes,
    )
}

fn build_qc_from_votes(
    height: u64,
    round: u32,
    block_hash: Bytes32,
    _chain_id: &str,
    snapshot_root: Bytes32,
    validators: &[QcValidator],
    votes: Vec<&VoteV1>,
) -> ConsensusResult<QuorumCertificateV1> {
    validate_round(round)?;
    let by_id: HashMap<Bytes32, &QcValidator> =
        validators.iter().map(|v| (v.validator_id, v)).collect();

    let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
    let mut pq_sigs = Vec::new();
    let mut classical_sigs = Vec::new();
    for vote in &votes {
        if vote.snapshot_root != snapshot_root {
            return Err(ConsensusError::CryptoError {
                detail: "mixed or incorrect snapshot roots in QC votes".to_string(),
            });
        }
        let Some(validator) = by_id.get(&vote.validator_id) else {
            continue;
        };

        let pos = validator.position;
        if pos < MAX_VALIDATORS {
            let byte_index = pos / 8;
            if let Some(byte) = signer_bitfield.get_mut(byte_index) {
                *byte |= 1 << (pos % 8);
            }
        }

        pq_sigs.push(PQVoteSig {
            validator_id: vote.validator_id,
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(vote.signature.pq_sig.as_slice())
                .map_err(|_| ConsensusError::CryptoError {
                    detail: "PQ sig too large".to_string(),
                })?,
        });
        classical_sigs.push(ClassicalVoteSig {
            validator_id: vote.validator_id,
            classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(
                vote.signature.classical_sig.as_slice(),
            )
            .map_err(|_| ConsensusError::CryptoError {
                detail: "classical sig too large".to_string(),
            })?,
        });
    }

    if pq_sigs.is_empty() {
        return Err(ConsensusError::QuorumNotReached { have_bps: 0 });
    }

    Ok(QuorumCertificateV1 {
        height,
        round,
        block_hash,
        snapshot_root,
        signer_bitfield,
        pq_signatures: pq_sigs,
        classical_signatures: classical_sigs,
    })
}

fn signer_validators<'a>(
    qc: &QuorumCertificateV1,
    validators: &'a [QcValidator],
) -> ConsensusResult<Vec<&'a QcValidator>> {
    let by_position: HashMap<usize, &QcValidator> = validators
        .iter()
        .map(|validator| (validator.position, validator))
        .collect();
    let mut signers = Vec::new();

    for (byte_idx, &byte) in qc.signer_bitfield.iter().enumerate() {
        for bit_idx in 0..8 {
            let pos = byte_idx * 8 + bit_idx;
            if pos >= MAX_VALIDATORS {
                break;
            }
            if (byte >> bit_idx) & 1 == 1 {
                let validator = by_position
                    .get(&pos)
                    .copied()
                    .ok_or(ConsensusError::QcVerificationFailed)?;
                signers.push(validator);
            }
        }
    }

    Ok(signers)
}

/// Verify a QC using hybrid Ed25519 + ML-DSA-87 signatures when active.
/// # Why two disagreeing valid QCs for the same (height, round) cannot both exist
///
/// A QC is accepted only if `signed_stake * 3 > total_stake * 2`, using
/// `u128` cross-products. The signing set therefore represents strictly more
/// than 2/3 of total stake without any integer-rounding exception.
///
/// Suppose two disagreeing QCs, A and B, both satisfy this bound for the
/// same (height, round). Two subsets of a fixed total stake, each
/// exceeding 2/3, cannot be disjoint: their intersection is strictly more
/// than 1/3 of total stake.
///
/// Under the standard BFT assumption that Byzantine stake is strictly
/// below 1/3 of total, that intersection cannot consist entirely of
/// Byzantine validators — at least one HONEST validator's signature must
/// appear in both A and B.
///
/// Each per-signer signature is verified here over the exact (height,
/// round, block_hash, validator_id, chain_id)
/// tuple it signs. For A and B to disagree while both containing that
/// honest validator's valid signature, the honest validator would have
/// had to sign two different values for the same (height, round) — which
/// honest vote-casting logic never does (an honest validator signs at
/// most one value per height/round/step). This verification relies on
/// that invariant holding for the honest fraction of the validator set;
/// it is a local property of honest signing behavior, not something this
/// function itself observes or enforces for a remote signer.
///
/// This is reinforced by independent defense-in-depth at the driver
/// layer: `ConsensusDriver`'s QC-caching logic explicitly rejects a
/// second QC arriving for an already-cached height if its round,
/// or block_hash disagrees with what's cached
/// (see driver.rs, "conflicting last_qc_bytes").
pub fn verify_qc(
    qc: &QuorumCertificateV1,
    validators: &[QcValidator],
    total_stake: u64,
    chain_id: &str,
) -> ConsensusResult<()> {
    validate_round(qc.round)?;
    let signers = signer_validators(qc, validators)?;
    let signed_stake = signers
        .iter()
        .fold(0u64, |acc, validator| acc.saturating_add(validator.stake));
    if !has_strict_two_thirds_quorum(signed_stake, total_stake) {
        return Err(ConsensusError::InsufficientStake {
            have: signed_stake,
            need: strict_two_thirds_minimum(total_stake),
        });
    }

    let mut seen = HashSet::new();
    let mut pq_by_validator = HashMap::new();
    for signature in &qc.pq_signatures {
        if !seen.insert(signature.validator_id) {
            return Err(ConsensusError::DuplicateSignature);
        }
        pq_by_validator.insert(signature.validator_id, signature);
    }

    if qc.pq_signatures.len() != signers.len() {
        return Err(ConsensusError::SignatureCountMismatch {
            expected: signers.len(),
            got: qc.pq_signatures.len(),
        });
    }

    let mut classical_by_validator = HashMap::new();
    if qc.classical_signatures.len() != signers.len() {
        return Err(ConsensusError::SignatureCountMismatch {
            expected: signers.len(),
            got: qc.classical_signatures.len(),
        });
    }
    let mut seen_classical = HashSet::new();
    for signature in &qc.classical_signatures {
        if !seen_classical.insert(signature.validator_id) {
            return Err(ConsensusError::DuplicateSignature);
        }
        classical_by_validator.insert(signature.validator_id, signature);
    }

    for validator in signers {
        let pq_sig = pq_by_validator
            .get(&validator.validator_id)
            .copied()
            .ok_or(ConsensusError::MissingSignature {
                validator_id: validator.validator_id,
            })?;
        let signing_bytes = vote_signing_bytes(
            qc.height,
            qc.round,
            VoteStep::Precommit,
            &qc.block_hash,
            &validator.validator_id,
            &qc.snapshot_root,
            chain_id,
        )?;
        let pq_sig_bytes: [u8; indra_crypto::PQ_SIG_BYTES] =
            pq_sig.pq_sig.as_slice().try_into().map_err(|_| {
                ConsensusError::InvalidPQSignature {
                    validator_id: validator.validator_id,
                }
            })?;
        let pq_pk_bytes: [u8; indra_crypto::PQ_PK_BYTES] =
            validator.pq_pk.as_slice().try_into().map_err(|_| {
                ConsensusError::InvalidPQSignature {
                    validator_id: validator.validator_id,
                }
            })?;
        verify_pq(
            &signing_bytes,
            &PqSignature(pq_sig_bytes),
            &PqPublicKey(pq_pk_bytes),
        )
        .map_err(|_| ConsensusError::InvalidPQSignature {
            validator_id: validator.validator_id,
        })?;

        let classical_sig = classical_by_validator
            .get(&validator.validator_id)
            .copied()
            .ok_or(ConsensusError::MissingSignature {
                validator_id: validator.validator_id,
            })?;
        let classical_sig_bytes: [u8; indra_crypto::CLASSICAL_SIG_BYTES] = classical_sig
            .classical_sig
            .as_slice()
            .try_into()
            .map_err(|_| ConsensusError::CryptoError {
                detail: format!(
                    "invalid QC classical signature for validator {}",
                    validator.validator_id
                ),
            })?;
        verify_classical(
            &signing_bytes,
            &ClassicalSignature(classical_sig_bytes),
            &ClassicalPublicKey(validator.classical_pk),
        )
        .map_err(|_| ConsensusError::CryptoError {
            detail: format!(
                "invalid QC classical signature for validator {}",
                validator.validator_id
            ),
        })?;
    }

    Ok(())
}

fn validate_round(round: u32) -> ConsensusResult<()> {
    validate_consensus_round(round)
        .map(|_| ())
        .map_err(|error| ConsensusError::InvalidRound {
            detail: error.to_string(),
        })
}

/// Verify a QC with full hybrid signature enforcement.
///
/// Both ML-DSA-87 (PQ) and
/// Ed25519 (classical) signatures are required for every signer.
/// Delegates to `verify_qc`, which enforces the hybrid requirement.
pub fn verify_qc_strict(
    qc: &QuorumCertificateV1,
    validators: &[QcValidator],
    total_stake: u64,
    chain_id: &str,
) -> ConsensusResult<()> {
    verify_qc(qc, validators, total_stake, chain_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vote::produce_vote;
    use indra_core::types::primitives::TEST_CHAIN_ID;
    use indra_core::types::{
        block::VrfSuiteV1,
        consensus_snapshot::{ConsensusSnapshot, ConsensusSnapshotEntry},
        primitives::MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
        qc::verify_qc_against_snapshot,
    };
    use indra_crypto::VrfKeypair;
    use indra_crypto::hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair};

    const TEST_SNAPSHOT_ROOT: Bytes32 = Bytes32([0x5A; 32]);

    fn make_validator(seed: u8, position: usize, stake: u64) -> (QcValidator, HybridKeypair) {
        let classical = ClassicalKeypair::from_seed(&[seed; 32]);
        let pq = PqKeypair::generate();
        let hybrid_kp = HybridKeypair::new(classical, pq);
        let pk = hybrid_kp.public_key();
        let id = indra_core::types::crypto::hybrid_identity_id(&pk.classical.0, &pk.pq.0);
        let v = QcValidator {
            validator_id: id,
            position,
            pq_pk: pk.pq.0.to_vec(),
            classical_pk: pk.classical.0,
            stake,
        };
        (v, hybrid_kp)
    }

    #[test]
    fn qc_is_cryptographically_bound_to_one_snapshot_root() {
        let (validator, signer) = make_validator(0x61, 0, 1);
        let public = signer.public_key();
        let vrf_pk = VrfKeypair::from_seed(&[0x62; 32]).public_key();
        let entry = |weight| {
            ConsensusSnapshotEntry::new(
                validator.validator_id,
                weight,
                public.classical.0,
                public.pq.0,
                vrf_pk,
                VrfSuiteV1::EcvrfEdwards25519Sha512Ell2,
                0,
            )
            .unwrap()
        };
        let snapshot_a = ConsensusSnapshot::new(
            1,
            0,
            vec![entry(1)],
            MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
        )
        .unwrap();
        let snapshot_b = ConsensusSnapshot::new(
            1,
            0,
            vec![entry(2)],
            MAINNET_ACTIVE_SLOT_COEFFICIENT_NUMERATOR,
        )
        .unwrap();
        assert_ne!(snapshot_a.snapshot_root, snapshot_b.snapshot_root);

        let block_hash = Bytes32::from([0x63; 32]);
        let vote = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            validator.validator_id,
            snapshot_a.snapshot_root,
            TEST_CHAIN_ID,
            &signer,
        )
        .unwrap();
        let qc = build_qc(
            1,
            0,
            block_hash,
            TEST_CHAIN_ID,
            snapshot_a.snapshot_root,
            &[validator],
            vec![&vote],
        )
        .unwrap();

        assert!(verify_qc_against_snapshot(&qc, &snapshot_a, TEST_CHAIN_ID).is_ok());
        assert!(verify_qc_against_snapshot(&qc, &snapshot_b, TEST_CHAIN_ID).is_err());
    }

    #[test]
    fn qc_builder_rejects_mixed_snapshot_votes_before_quorum() {
        let (a, a_key) = make_validator(0x64, 0, 5);
        let (b, b_key) = make_validator(0x65, 1, 5);
        let block_hash = Bytes32::from([0x66; 32]);
        let root_a = Bytes32::from([0xA1; 32]);
        let root_b = Bytes32::from([0xB2; 32]);
        let vote_a = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            a.validator_id,
            root_a,
            TEST_CHAIN_ID,
            &a_key,
        )
        .unwrap();
        let vote_b = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            b.validator_id,
            root_b,
            TEST_CHAIN_ID,
            &b_key,
        )
        .unwrap();
        assert!(
            build_qc(
                1,
                0,
                block_hash,
                TEST_CHAIN_ID,
                root_a,
                &[a, b],
                vec![&vote_a, &vote_b],
            )
            .is_err()
        );
    }

    #[test]
    fn build_qc_single_validator() {
        let (v, kp) = make_validator(0x01, 0, 10_000);
        let block_hash = Bytes32::from([0xAAu8; 32]);
        let vote = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            v.validator_id,
            TEST_SNAPSHOT_ROOT,
            TEST_CHAIN_ID,
            &kp,
        )
        .unwrap();
        let qc = build_qc(
            1,
            0,
            block_hash,
            TEST_CHAIN_ID,
            TEST_SNAPSHOT_ROOT,
            std::slice::from_ref(&v),
            vec![&vote],
        )
        .unwrap();
        assert_eq!(qc.height, 1);
        assert_eq!(qc.block_hash, block_hash);
        assert_eq!(qc.signer_count(), 1);
    }

    #[test]
    fn qc_construction_rejects_round_limit_and_above() {
        let (validator, keypair) = make_validator(0x72, 0, 10_000);
        let vote = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            TEST_SNAPSHOT_ROOT,
            validator.validator_id,
            TEST_SNAPSHOT_ROOT,
            TEST_CHAIN_ID,
            &keypair,
        )
        .unwrap();
        for round in [
            indra_core::types::primitives::MAX_ROUNDS_PER_HEIGHT,
            indra_core::types::primitives::MAX_ROUNDS_PER_HEIGHT + 1,
            u32::MAX,
        ] {
            let error = build_qc(
                1,
                round,
                TEST_SNAPSHOT_ROOT,
                TEST_CHAIN_ID,
                TEST_SNAPSHOT_ROOT,
                std::slice::from_ref(&validator),
                vec![&vote],
            )
            .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "invalid consensus round: invalid consensus round {round}; maximum legal round is {}",
                    indra_core::types::primitives::MAX_ROUNDS_PER_HEIGHT - 1
                )
            );
        }
    }

    #[test]
    fn qc_bitfield_set_correctly() {
        let (v, kp) = make_validator(0x02, 5, 10_000);
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let vote = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            v.validator_id,
            TEST_SNAPSHOT_ROOT,
            TEST_CHAIN_ID,
            &kp,
        )
        .unwrap();
        let qc = build_qc(
            1,
            0,
            block_hash,
            TEST_CHAIN_ID,
            TEST_SNAPSHOT_ROOT,
            std::slice::from_ref(&v),
            vec![&vote],
        )
        .unwrap();
        assert!(qc.is_signer(5));
        assert!(!qc.is_signer(0));
    }

    #[test]
    fn verify_qc_passes_with_quorum() {
        let (v, kp) = make_validator(0x03, 0, 10_000);
        let block_hash = Bytes32::from([0xCCu8; 32]);
        let vote = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            v.validator_id,
            TEST_SNAPSHOT_ROOT,
            TEST_CHAIN_ID,
            &kp,
        )
        .unwrap();
        let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
        signer_bitfield[0] = 0b0000_0001;
        let qc = QuorumCertificateV1 {
            height: 1,
            round: 0,
            block_hash,
            snapshot_root: TEST_SNAPSHOT_ROOT,
            signer_bitfield,
            pq_signatures: vec![PQVoteSig {
                validator_id: v.validator_id,
                pq_sig: VariableBytes::from_slice(vote.signature.pq_sig.as_slice()).unwrap(),
            }],
            classical_signatures: vec![ClassicalVoteSig {
                validator_id: v.validator_id,
                classical_sig: VariableBytes::from_slice(vote.signature.classical_sig.as_slice())
                    .unwrap(),
            }],
        };
        assert!(verify_qc(&qc, std::slice::from_ref(&v), 10_000, TEST_CHAIN_ID).is_ok());
        assert!(verify_qc_strict(&qc, &[v], 10_000, TEST_CHAIN_ID).is_ok());
    }

    #[test]
    fn verify_qc_requires_both_classical_and_pq_when_hybrid_active() {
        let (v, kp) = make_validator(0x13, 0, 10_000);
        let block_hash = Bytes32::from([0x13u8; 32]);
        let vote = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            v.validator_id,
            TEST_SNAPSHOT_ROOT,
            TEST_CHAIN_ID,
            &kp,
        )
        .unwrap();
        let mut qc = build_qc(
            1,
            0,
            block_hash,
            TEST_CHAIN_ID,
            TEST_SNAPSHOT_ROOT,
            std::slice::from_ref(&v),
            vec![&vote],
        )
        .unwrap();
        qc.classical_signatures.clear();

        assert_eq!(
            verify_qc(&qc, &[v], 10_000, TEST_CHAIN_ID),
            Err(ConsensusError::SignatureCountMismatch {
                expected: 1,
                got: 0,
            })
        );
    }

    #[test]
    fn verify_qc_accepts_valid_hybrid_qc() {
        let (v, kp) = make_validator(0x14, 0, 10_000);
        let block_hash = Bytes32::from([0x14u8; 32]);
        let vote = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            v.validator_id,
            TEST_SNAPSHOT_ROOT,
            TEST_CHAIN_ID,
            &kp,
        )
        .unwrap();
        let qc = build_qc(
            1,
            0,
            block_hash,
            TEST_CHAIN_ID,
            TEST_SNAPSHOT_ROOT,
            std::slice::from_ref(&v),
            vec![&vote],
        )
        .unwrap();

        assert!(verify_qc(&qc, &[v], 10_000, TEST_CHAIN_ID).is_ok());
    }

    #[test]
    fn verify_qc_rejects_classical_forgery() {
        let (v, kp) = make_validator(0x15, 0, 10_000);
        let block_hash = Bytes32::from([0x15u8; 32]);
        let vote = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            v.validator_id,
            TEST_SNAPSHOT_ROOT,
            TEST_CHAIN_ID,
            &kp,
        )
        .unwrap();
        let mut qc = build_qc(
            1,
            0,
            block_hash,
            TEST_CHAIN_ID,
            TEST_SNAPSHOT_ROOT,
            std::slice::from_ref(&v),
            vec![&vote],
        )
        .unwrap();
        qc.classical_signatures[0].classical_sig =
            VariableBytes::from_slice(&[0x42u8; 64]).unwrap();

        assert!(matches!(
            verify_qc(&qc, &[v], 10_000, TEST_CHAIN_ID),
            Err(ConsensusError::CryptoError { .. })
        ));
    }

    #[test]
    fn verify_qc_rejects_insufficient_stake() {
        let (v1, kp1) = make_validator(0x01, 0, 3_000);
        let (v2, _) = make_validator(0x02, 1, 7_000);
        let block_hash = Bytes32::from([0xDDu8; 32]);
        let vote = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            v1.validator_id,
            TEST_SNAPSHOT_ROOT,
            TEST_CHAIN_ID,
            &kp1,
        )
        .unwrap();
        let qc = build_qc(
            1,
            0,
            block_hash,
            TEST_CHAIN_ID,
            TEST_SNAPSHOT_ROOT,
            &[v1.clone(), v2.clone()],
            vec![&vote],
        )
        .unwrap();
        assert!(matches!(
            verify_qc(&qc, &[v1, v2], 10_000, TEST_CHAIN_ID),
            Err(ConsensusError::InsufficientStake { .. })
        ));
    }

    #[test]
    fn verify_qc_rejects_invalid_pq_signature() {
        let (v, _) = make_validator(0x0A, 0, 10_000);
        let block_hash = Bytes32::from([0xABu8; 32]);
        let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
        signer_bitfield[0] = 0b0000_0001;
        let qc = QuorumCertificateV1 {
            height: 1,
            round: 0,
            block_hash,
            snapshot_root: TEST_SNAPSHOT_ROOT,
            signer_bitfield,
            pq_signatures: vec![PQVoteSig {
                validator_id: v.validator_id,
                pq_sig: VariableBytes::from_slice(&[0x42u8; 32]).unwrap(),
            }],
            classical_signatures: vec![ClassicalVoteSig {
                validator_id: v.validator_id,
                classical_sig: VariableBytes::from_slice(&[0x42u8; 64]).unwrap(),
            }],
        };
        assert!(matches!(
            verify_qc(&qc, &[v], 10_000, TEST_CHAIN_ID),
            Err(ConsensusError::InvalidPQSignature { .. })
        ));
    }

    #[test]
    fn verify_qc_rejects_missing_pq_signature() {
        let (v, _) = make_validator(0x0B, 0, 10_000);
        let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
        signer_bitfield[0] = 0b0000_0001;
        let qc = QuorumCertificateV1 {
            height: 1,
            round: 0,
            block_hash: Bytes32::from([0x11u8; 32]),
            snapshot_root: TEST_SNAPSHOT_ROOT,
            signer_bitfield,
            pq_signatures: vec![],
            classical_signatures: vec![],
        };
        assert_eq!(
            verify_qc(&qc, &[v], 10_000, TEST_CHAIN_ID),
            Err(ConsensusError::SignatureCountMismatch {
                expected: 1,
                got: 0
            })
        );
    }

    #[test]
    fn verify_qc_rejects_duplicate_pq_signatures() {
        let (v, kp) = make_validator(0x0C, 0, 10_000);
        let block_hash = Bytes32::from([0x12u8; 32]);
        let vote = produce_vote(
            1,
            0,
            VoteStep::Precommit,
            block_hash,
            v.validator_id,
            TEST_SNAPSHOT_ROOT,
            TEST_CHAIN_ID,
            &kp,
        )
        .unwrap();
        let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
        signer_bitfield[0] = 0b0000_0001;
        let sig = VariableBytes::from_slice(vote.signature.pq_sig.as_slice()).unwrap();
        let qc = QuorumCertificateV1 {
            height: 1,
            round: 0,
            block_hash,
            snapshot_root: TEST_SNAPSHOT_ROOT,
            signer_bitfield,
            pq_signatures: vec![
                PQVoteSig {
                    validator_id: v.validator_id,
                    pq_sig: sig.clone(),
                },
                PQVoteSig {
                    validator_id: v.validator_id,
                    pq_sig: sig,
                },
            ],
            classical_signatures: vec![
                ClassicalVoteSig {
                    validator_id: v.validator_id,
                    classical_sig: VariableBytes::from_slice(
                        vote.signature.classical_sig.as_slice(),
                    )
                    .unwrap(),
                },
                ClassicalVoteSig {
                    validator_id: v.validator_id,
                    classical_sig: VariableBytes::from_slice(
                        vote.signature.classical_sig.as_slice(),
                    )
                    .unwrap(),
                },
            ],
        };
        assert_eq!(
            verify_qc(&qc, &[v], 10_000, TEST_CHAIN_ID),
            Err(ConsensusError::DuplicateSignature)
        );
    }

    #[test]
    fn strict_consensus_quorum_is_above_two_thirds() {
        assert!(!has_strict_two_thirds_quorum(2, 3));
        assert!(has_strict_two_thirds_quorum(3, 4));
    }

    #[test]
    fn floor_rounded_conflicting_qc_exploit_is_rejected() {
        let (byzantine, byzantine_key) = make_validator(0x71, 0, 3_333);
        let (honest_a, honest_a_key) = make_validator(0x72, 1, 3_334);
        let (honest_b, honest_b_key) = make_validator(0x73, 2, 3_334);
        let validators = vec![byzantine.clone(), honest_a.clone(), honest_b.clone()];
        let total_stake = 10_001;
        let height = 91;
        let round = 7;
        let hash_a = Bytes32::from([0xA1; 32]);
        let hash_b = Bytes32::from([0xB2; 32]);

        let byzantine_a = produce_vote(
            height,
            round,
            VoteStep::Precommit,
            hash_a,
            byzantine.validator_id,
            TEST_SNAPSHOT_ROOT,
            TEST_CHAIN_ID,
            &byzantine_key,
        )
        .unwrap();
        let honest_a_vote = produce_vote(
            height,
            round,
            VoteStep::Precommit,
            hash_a,
            honest_a.validator_id,
            TEST_SNAPSHOT_ROOT,
            TEST_CHAIN_ID,
            &honest_a_key,
        )
        .unwrap();
        let byzantine_b = produce_vote(
            height,
            round,
            VoteStep::Precommit,
            hash_b,
            byzantine.validator_id,
            TEST_SNAPSHOT_ROOT,
            TEST_CHAIN_ID,
            &byzantine_key,
        )
        .unwrap();
        let honest_b_vote = produce_vote(
            height,
            round,
            VoteStep::Precommit,
            hash_b,
            honest_b.validator_id,
            TEST_SNAPSHOT_ROOT,
            TEST_CHAIN_ID,
            &honest_b_key,
        )
        .unwrap();

        let qc_a = build_qc(
            height,
            round,
            hash_a,
            TEST_CHAIN_ID,
            TEST_SNAPSHOT_ROOT,
            &validators,
            vec![&byzantine_a, &honest_a_vote],
        )
        .unwrap();
        let qc_b = build_qc(
            height,
            round,
            hash_b,
            TEST_CHAIN_ID,
            TEST_SNAPSHOT_ROOT,
            &validators,
            vec![&byzantine_b, &honest_b_vote],
        )
        .unwrap();

        assert!(3_333u128 * 3 < total_stake as u128);
        assert!(!has_strict_two_thirds_quorum(6_667, total_stake));
        assert!(matches!(
            verify_qc(&qc_a, &validators, total_stake, TEST_CHAIN_ID),
            Err(ConsensusError::InsufficientStake { .. })
        ));
        assert!(matches!(
            verify_qc(&qc_b, &validators, total_stake, TEST_CHAIN_ID),
            Err(ConsensusError::InsufficientStake { .. })
        ));
    }

    #[test]
    fn exact_quorum_property_forces_more_than_one_third_intersection() {
        for total_stake in 1u64..=100_000 {
            let minimum = strict_two_thirds_minimum(total_stake);
            assert!(has_strict_two_thirds_quorum(minimum, total_stake));
            assert!(!has_strict_two_thirds_quorum(
                minimum.saturating_sub(1),
                total_stake
            ));

            // Two minimum-size quorums have the smallest possible overlap when
            // each otherwise contains disjoint stake. Their overlap must still
            // be strictly greater than one third of the total.
            let minimum_overlap = (minimum as u128) * 2 - total_stake as u128;
            assert!(
                minimum_overlap * 3 > total_stake as u128,
                "total={total_stake} minimum={minimum} overlap={minimum_overlap}"
            );
        }
    }

    #[test]
    fn conflicting_qcs_require_more_than_one_third_double_signing_weight() {
        let validator_count = 4usize;
        let stake_per_validator = 2_500u64;
        let total_stake = stake_per_validator * validator_count as u64;
        // Any two signer sets which each satisfy the strict >2/3 quorum
        // overlap in strictly more than 1/3 of total stake. With four equal
        // validators, every quorum has three signers and two conflicting
        // quorums share two signers (50% stake). Those shared validators
        // would have to sign both block hashes. This equal-weight example did
        // not exercise integer rounding, so the uneven-stake regression above
        // is also required.
        let first = [true, true, true, false];
        let second = [true, true, false, true];
        let signed_stake = |set: &[bool; 4]| {
            set.iter().filter(|signed| **signed).count() as u64 * stake_per_validator
        };
        let overlap_stake = first
            .iter()
            .zip(second.iter())
            .filter(|(left, right)| **left && **right)
            .count() as u64
            * stake_per_validator;

        assert!(has_strict_two_thirds_quorum(
            signed_stake(&first),
            total_stake
        ));
        assert!(has_strict_two_thirds_quorum(
            signed_stake(&second),
            total_stake
        ));
        assert!(overlap_stake > total_stake / 3);
        assert_eq!(overlap_stake, 5_000);
    }
}
