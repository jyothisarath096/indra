//! Canonical proposer verification capability.
use crate::{
    codec::Encode,
    error::{IndraError, IndraResult},
    sortition::{evaluate, priority},
    types::{
        block::{transaction_set_root, BlockProposalVNext, VrfSuiteV1},
        consensus_snapshot::ConsensusSnapshot,
        primitives::{validate_consensus_round, Bytes32, Bytes64},
    },
};
use indra_crypto::{
    verify_hybrid, vrf_verify, ClassicalPublicKey, HybridPublicKey, PqPublicKey, VrfOutput,
    VrfProof,
};
use sha2::{Digest, Sha512};

/// Evidence that authorization, eligibility, and priority were independently verified.
#[derive(Debug)]
pub struct VerifiedProposal<'a> {
    proposal: &'a BlockProposalVNext,
}
impl<'a> VerifiedProposal<'a> {
    /// Borrow the verified envelope.
    pub fn proposal(&self) -> &'a BlockProposalVNext {
        self.proposal
    }
    /// Borrow the verified unsigned block.
    pub fn block(&self) -> &'a crate::types::block::BlockVNext {
        &self.proposal.block
    }
}

/// Build the complete domain-separated VRF input.
pub fn proposer_vrf_alpha(
    chain_id: &[u8],
    seed: &Bytes64,
    height: u64,
    round: u32,
    snapshot_root: &Bytes32,
    proposer_id: &Bytes32,
) -> IndraResult<Vec<u8>> {
    validate_consensus_round(round)?;
    let n = u16::try_from(chain_id.len()).map_err(|_| IndraError::LengthExceeded {
        field: "chain_id",
        max: u16::MAX as usize,
        actual: chain_id.len(),
    })?;
    let mut out = b"INDRA-PROPOSER-SORTITION-v2".to_vec();
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(chain_id);
    seed.encode(&mut out);
    height.encode(&mut out);
    round.encode(&mut out);
    snapshot_root.encode(&mut out);
    proposer_id.encode(&mut out);
    Ok(out)
}

/// Derive the seed for the height following one finalized proposal.
pub fn next_election_seed(
    chain_id: &[u8],
    prior: &Bytes64,
    block: &crate::types::block::BlockVNext,
    snapshot_root: &Bytes32,
) -> IndraResult<Bytes64> {
    let n = u16::try_from(chain_id.len()).map_err(|_| IndraError::LengthExceeded {
        field: "chain_id",
        max: u16::MAX as usize,
        actual: chain_id.len(),
    })?;
    let h = &block.header;
    let mut material = b"INDRA-ELECTION-SEED-v2".to_vec();
    material.extend_from_slice(&n.to_be_bytes());
    material.extend_from_slice(chain_id);
    prior.encode(&mut material);
    h.height.encode(&mut material);
    h.value_entropy.origin_round.encode(&mut material);
    h.value_entropy.origin_proposer_id.encode(&mut material);
    material.extend_from_slice(h.value_entropy.vrf_output.as_slice());
    snapshot_root.encode(&mut material);
    let digest = Sha512::digest(&material);
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest);
    Ok(Bytes64(out))
}

/// Verify the complete proposal trust boundary and issue a non-forgeable capability.
pub fn verify_proposal<'a>(
    proposal: &'a BlockProposalVNext,
    chain_id: &[u8],
    expected_seed: &Bytes64,
    snapshot: &ConsensusSnapshot,
) -> IndraResult<VerifiedProposal<'a>> {
    let h = &proposal.block.header;
    if h.mempool_set_root != transaction_set_root(&proposal.block.transactions) {
        return Err(IndraError::InvalidSortition(
            "proposal transaction-set root mismatch".into(),
        ));
    }
    if h.election_seed != *expected_seed {
        return Err(IndraError::InvalidSortition(
            "proposal election seed differs from committed state".into(),
        ));
    }
    if h.vrf_suite != VrfSuiteV1::EcvrfEdwards25519Sha512Ell2 {
        return Err(IndraError::VrfProofInvalid);
    }
    let (_, entry) = snapshot
        .entry_with_position(&h.proposer_id)
        .ok_or_else(|| {
            IndraError::InvalidSortition("proposer is absent from governing snapshot".into())
        })?;
    if entry.vrf_suite != h.vrf_suite {
        return Err(IndraError::VrfProofInvalid);
    }
    let pk = HybridPublicKey {
        classical: ClassicalPublicKey(entry.classical_vote_pk),
        pq: PqPublicKey(entry.pq_vote_pk),
    };
    let sig = proposal
        .proposer_authorization
        .to_crypto_sig()
        .map_err(|_| IndraError::SignatureInvalid {
            scheme: "hybrid proposer authorization",
        })?;
    let signing = proposal.signing_bytes(chain_id)?;
    verify_hybrid(&signing, &sig, &pk).map_err(|_| IndraError::SignatureInvalid {
        scheme: "hybrid proposer authorization",
    })?;
    let alpha = proposer_vrf_alpha(
        chain_id,
        expected_seed,
        h.height,
        h.proposer_round,
        &snapshot.snapshot_root,
        &h.proposer_id,
    )?;
    let output: [u8; 64] = h
        .proposer_vrf_output
        .as_slice()
        .try_into()
        .map_err(|_| IndraError::VrfProofInvalid)?;
    let proof = h.proposer_vrf_proof.as_slice().to_vec();
    vrf_verify(&entry.vrf_pk, &alpha, &VrfOutput(output), &VrfProof(proof))
        .map_err(|_| IndraError::VrfProofInvalid)?;
    let log = snapshot.sortition_log_interval()?;
    let result = evaluate(
        &log,
        entry.consensus_weight_spark,
        snapshot.total_weight_spark,
        &output,
    )?;
    if !result.eligible {
        return Err(IndraError::InvalidSortition(
            "proposer is not eligible".into(),
        ));
    }
    if h.proposer_priority != Bytes64(priority(&output, &h.proposer_id.0)) {
        return Err(IndraError::InvalidSortition(
            "proposer priority mismatch".into(),
        ));
    }

    let (_, entropy_entry) = snapshot
        .entry_with_position(&h.value_entropy.origin_proposer_id)
        .ok_or_else(|| {
            IndraError::InvalidSortition(
                "value-entropy origin is absent from governing snapshot".into(),
            )
        })?;
    let entropy_alpha = proposer_vrf_alpha(
        chain_id,
        expected_seed,
        h.height,
        h.value_entropy.origin_round,
        &snapshot.snapshot_root,
        &h.value_entropy.origin_proposer_id,
    )?;
    let entropy_output: [u8; 64] = h
        .value_entropy
        .vrf_output
        .as_slice()
        .try_into()
        .map_err(|_| IndraError::VrfProofInvalid)?;
    vrf_verify(
        &entropy_entry.vrf_pk,
        &entropy_alpha,
        &VrfOutput(entropy_output),
        &VrfProof(h.value_entropy.vrf_proof.as_slice().to_vec()),
    )
    .map_err(|_| IndraError::VrfProofInvalid)?;
    let entropy_result = evaluate(
        &log,
        entropy_entry.consensus_weight_spark,
        snapshot.total_weight_spark,
        &entropy_output,
    )?;
    if !entropy_result.eligible {
        return Err(IndraError::InvalidSortition(
            "value-entropy origin was not eligible".into(),
        ));
    }
    validate_consensus_round(h.proposer_round)?;
    validate_consensus_round(h.value_entropy.origin_round)?;
    if let Some(polc_round) = h.polc_round {
        validate_consensus_round(polc_round)?;
    }
    if h.polc_round.is_none()
        && (h.value_entropy.origin_proposer_id != h.proposer_id
            || h.value_entropy.origin_round != h.proposer_round
            || h.value_entropy.vrf_output.as_slice() != h.proposer_vrf_output.as_slice()
            || h.value_entropy.vrf_proof.as_slice() != h.proposer_vrf_proof.as_slice())
    {
        return Err(IndraError::InvalidSortition(
            "first proposal does not bind entropy to its current-round VRF proof".into(),
        ));
    }
    Ok(VerifiedProposal { proposal })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vrf_alpha_binds_every_seed_bit_and_every_context() {
        let chain = b"indra-test";
        let seed = Bytes64([0; 64]);
        let root = Bytes32::from([3; 32]);
        let proposer = Bytes32::from([4; 32]);
        let baseline = proposer_vrf_alpha(chain, &seed, 7, 9, &root, &proposer).unwrap();
        for bit in 0..512 {
            let mut changed = seed;
            changed.0[bit / 8] ^= 1 << (bit % 8);
            assert_ne!(
                proposer_vrf_alpha(chain, &changed, 7, 9, &root, &proposer).unwrap(),
                baseline
            );
        }
        assert_ne!(
            proposer_vrf_alpha(b"other", &seed, 7, 9, &root, &proposer).unwrap(),
            baseline
        );
        assert_ne!(
            proposer_vrf_alpha(chain, &seed, 8, 9, &root, &proposer).unwrap(),
            baseline
        );
        assert_ne!(
            proposer_vrf_alpha(chain, &seed, 7, 10, &root, &proposer).unwrap(),
            baseline
        );
        assert_ne!(
            proposer_vrf_alpha(chain, &seed, 7, 9, &Bytes32::from([5; 32]), &proposer).unwrap(),
            baseline
        );
        assert_ne!(
            proposer_vrf_alpha(chain, &seed, 7, 9, &root, &Bytes32::from([6; 32])).unwrap(),
            baseline
        );
    }
}
