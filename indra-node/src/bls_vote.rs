//! Proper BLS vote signing — replaces the Phase 4 placeholder.
//!
//! In Phase 4, vote signatures used Ed25519 bytes passed off as BLS
//! (causing the "malformed signature for BLS12-381: got 64 bytes" error
//! in QC aggregation). This module provides:
//!
//! - `BlsVoteSigner`: wraps a BLS keypair and signs vote messages
//! - `sign_vote_bls`: produce a 96-byte BLS signature over a vote message
//! - `build_bls_qc`: aggregate BLS vote signatures into a real QC
//!
//! ## What changes
//!
//! Validators now maintain TWO signing keypairs:
//! - Hybrid (Ed25519 + Dilithium2): for transaction signatures and prevotes
//! - BLS12-381: for precommit aggregation into QCs
//!
//! The QC contains:
//! - One 96-byte BLS aggregate signature (all precommit classical components)
//! - N individual Dilithium2 signatures (one per signer)

use indra_core::types::qc::SIGNER_BITFIELD_BYTES;
use indra_core::{
    codec::Encode,
    types::{
        primitives::{
            Bytes32, VariableBytes,
            MAX_BLS_AGG_SIG_BYTES, MAX_PQ_SIG_BYTES, MAX_VALIDATORS,
            CONSENSUS_QUORUM_BPS,
        },
        qc::QuorumCertificateV1,
        crypto::PQVoteSig,
        vote::{VoteStep, VoteV1},
    },
};
use indra_crypto::{
    bls::{BlsKeypair, BlsPublicKey, BlsSignature, aggregate_signatures, verify_aggregate},
    hash::domains::VOTE_SIGN,
    CryptoError,
};

use crate::error::{NodeError, NodeResult};

/// A validator's BLS signing key for QC aggregation.
pub struct BlsVoteSigner {
    keypair: BlsKeypair,
    /// The validator's public key (48 bytes).
    pub public_key: BlsPublicKey,
}

impl BlsVoteSigner {
    /// Create from a 32-byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> NodeResult<Self> {
        let keypair = BlsKeypair::from_seed(seed)?;
        let public_key = keypair.public_key();
        Ok(Self { keypair, public_key })
    }

    /// Sign a vote message with BLS.
    pub fn sign_vote(&self, msg: &[u8]) -> BlsSignature {
        self.keypair.sign(msg)
    }
}

/// Compute the BLS signing message for a vote.
///
/// BLS signs: VOTE_SIGN || height || round || step || block_hash
///
/// The aggregate signature must cover the same message for every signer, so
/// validator identity is intentionally excluded here.
pub fn bls_vote_message(
    height: u64,
    round: u32,
    step: VoteStep,
    block_hash: &Bytes32,
    _validator_id: &Bytes32,
) -> Vec<u8> {
    let mut buf = VOTE_SIGN.to_vec();
    height.encode(&mut buf);
    round.encode(&mut buf);
    step.encode(&mut buf);
    block_hash.encode(&mut buf);
    buf
}

/// A precommit vote with an accompanying BLS signature.
pub struct PrecommitWithBls {
    /// The vote (carries the hybrid signature).
    pub vote: VoteV1,
    /// The BLS signature over the vote message.
    pub bls_sig: BlsSignature,
}

/// Build a QC from precommit votes that each carry a real BLS signature.
///
/// This replaces the Phase 4 placeholder that used zeroed bytes.
pub fn build_bls_qc(
    height: u64,
    round: u32,
    block_hash: Bytes32,
    precommits: &[PrecommitWithBls],
    validator_positions: &[(Bytes32, usize, u64)], // (validator_id, position, stake)
    total_stake: u64,
) -> NodeResult<QuorumCertificateV1> {
    let mut signer_bitfield = [0u8; SIGNER_BITFIELD_BYTES];
    let mut bls_sigs: Vec<BlsSignature> = Vec::new();
    let mut bls_msgs: Vec<Vec<u8>> = Vec::new();
    let mut pq_sigs: Vec<PQVoteSig> = Vec::new();
    let mut signed_stake: u64 = 0;

    for pc in precommits {
        // Look up position and stake
        let pos_stake = validator_positions.iter()
            .find(|(id, _, _)| *id == pc.vote.validator_id);

        let (position, stake) = match pos_stake {
            Some((_, pos, stake)) => (*pos, *stake),
            None => continue,
        };

        if position < MAX_VALIDATORS {
            signer_bitfield[position / 8] |= 1 << (position % 8);
        }

        let msg = bls_vote_message(
            height, round, VoteStep::Precommit,
            &block_hash, &pc.vote.validator_id,
        );
        bls_sigs.push(pc.bls_sig.clone());
        bls_msgs.push(msg);

        let pq_sig = PQVoteSig {
            validator_id: pc.vote.validator_id,
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(
                pc.vote.signature.pq_sig.as_slice()
            ).map_err(|_| NodeError::Crypto(CryptoError::MalformedSignature {
                scheme: "Dilithium2",
                actual: pc.vote.signature.pq_sig.len(),
            }))?,
        };
        pq_sigs.push(pq_sig);
        signed_stake = signed_stake.saturating_add(stake);
    }

    // Check quorum
    let stake_bps = if total_stake > 0 {
        signed_stake.saturating_mul(10_000) / total_stake
    } else {
        0
    };
    if (stake_bps as u32) < CONSENSUS_QUORUM_BPS {
        return Err(NodeError::BlockInvalid {
            height,
            reason: format!("quorum not reached: {stake_bps} bps < {CONSENSUS_QUORUM_BPS} bps"),
        });
    }

    // Aggregate BLS signatures
    let agg = aggregate_signatures(&bls_sigs)?;

    let bls_agg_sig = VariableBytes::<MAX_BLS_AGG_SIG_BYTES>::from_slice(&agg.0)
        .map_err(|_| NodeError::Crypto(CryptoError::MalformedSignature {
            scheme: "BLS12-381 aggregate",
            actual: agg.0.len(),
        }))?;

    Ok(QuorumCertificateV1 {
        height,
        round,
        block_hash,
        bls_agg_sig,
        signer_bitfield,
        pq_signatures: pq_sigs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        VariableBytes,
        types::{
            crypto::HybridSignature,
            primitives::{MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES},
        },
    };
    use indra_crypto::hybrid::{ClassicalKeypair, HybridKeypair, PqKeypair};
    use indra_consensus::vote::produce_vote;

    fn make_precommit(
        seed: u8,
        height: u64,
        block_hash: Bytes32,
    ) -> (PrecommitWithBls, BlsVoteSigner, Bytes32) {
        let classical = ClassicalKeypair::from_seed(&[seed; 32]);
        let pq = PqKeypair::generate();
        let hybrid_kp = HybridKeypair::new(classical, pq);
        let pk = hybrid_kp.public_key();
        let validator_id = Bytes32::from(indra_crypto::sha256(&pk.classical.0));

        let bls_signer = BlsVoteSigner::from_seed(&[seed; 32]).unwrap();
        let vote = produce_vote(
            height, 0, VoteStep::Precommit,
            block_hash, validator_id, &hybrid_kp,
        ).unwrap();

        let bls_msg = bls_vote_message(height, 0, VoteStep::Precommit, &block_hash, &validator_id);
        let bls_sig = bls_signer.sign_vote(&bls_msg);

        (PrecommitWithBls { vote, bls_sig }, bls_signer, validator_id)
    }

    #[test]
    fn bls_qc_with_real_signatures() {
        let block_hash = Bytes32::from([0xAAu8; 32]);
        let (pc1, s1, id1) = make_precommit(0x01, 1, block_hash);
        let (pc2, s2, id2) = make_precommit(0x02, 1, block_hash);

        let positions = vec![
            (id1, 0usize, 5_000u64),
            (id2, 1usize, 5_000u64),
        ];

        let qc = build_bls_qc(1, 0, block_hash, &[pc1, pc2], &positions, 10_000).unwrap();
        assert_eq!(qc.signer_count(), 2);
        assert!(qc.is_signer(0));
        assert!(qc.is_signer(1));
        // BLS agg sig should be 96 bytes (real BLS, not a placeholder)
        assert_eq!(qc.bls_agg_sig.as_slice().len(), 96);
    }

    #[test]
    fn bls_vote_message_is_deterministic() {
        let block_hash = Bytes32::from([0xBBu8; 32]);
        let validator_id = Bytes32::from([0x01u8; 32]);
        let m1 = bls_vote_message(1, 0, VoteStep::Precommit, &block_hash, &validator_id);
        let m2 = bls_vote_message(1, 0, VoteStep::Precommit, &block_hash, &validator_id);
        assert_eq!(m1, m2);
    }

    #[test]
    fn below_quorum_fails() {
        let block_hash = Bytes32::from([0xCCu8; 32]);
        let (pc1, _, id1) = make_precommit(0x01, 1, block_hash);

        // Only 1 of 10: 10% < consensus threshold
        let positions = vec![(id1, 0usize, 1_000u64)];
        let result = build_bls_qc(1, 0, block_hash, &[pc1], &positions, 10_000);
        assert!(result.is_err());
    }
}
