//! Commit-reveal VRF proposer election messages and result hash.

use crate::{
    codec::{ByteReader, Decode, Encode},
    error::IndraResult,
    ssz::sha256,
    types::{
        crypto::HybridSignature,
        primitives::{
            reveal_set_commitment_active, Bytes32, VariableBytes, MAX_ACTIVE_VALIDATORS,
            MAX_VRF_PROOF_BYTES,
        },
    },
};

/// Broadcast during the commit phase of a consensus round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfCommit {
    /// Hash of the chain ID, preventing cross-chain replay.
    pub chain_id_hash: Bytes32,
    /// Block height being elected.
    pub height: u64,
    /// Consensus round being elected.
    pub round: u32,
    /// Validator identity.
    pub validator_id: Bytes32,
    /// Registered VRF public key.
    pub vrf_pubkey: [u8; 32],
    /// Commitment to the validator's VRF output and proof.
    pub commit_hash: Bytes32,
    /// Hybrid signature over all fields above.
    pub signature: HybridSignature,
}

impl VrfCommit {
    /// Canonical bytes signed by the validator.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut data = b"INDRA-VRF-COMMIT-SIGN-v1".to_vec();
        self.chain_id_hash.encode(&mut data);
        self.height.encode(&mut data);
        self.round.encode(&mut data);
        self.validator_id.encode(&mut data);
        data.extend_from_slice(&self.vrf_pubkey);
        self.commit_hash.encode(&mut data);
        data
    }
}

impl Encode for VrfCommit {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.chain_id_hash.encode(buf);
        self.height.encode(buf);
        self.round.encode(buf);
        self.validator_id.encode(buf);
        buf.extend_from_slice(&self.vrf_pubkey);
        self.commit_hash.encode(buf);
        self.signature.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        32 + 8 + 4 + 32 + 32 + 32 + self.signature.encoded_len()
    }
}

impl Decode for VrfCommit {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            chain_id_hash: Bytes32::decode(r)?,
            height: u64::decode(r)?,
            round: u32::decode(r)?,
            validator_id: Bytes32::decode(r)?,
            vrf_pubkey: r.read_bytes32()?,
            commit_hash: Bytes32::decode(r)?,
            signature: HybridSignature::decode(r)?,
        })
    }
}

/// Broadcast during the reveal phase of a consensus round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfReveal {
    /// Hash of the chain ID, preventing cross-chain replay.
    pub chain_id_hash: Bytes32,
    /// Block height being elected.
    pub height: u64,
    /// Consensus round being elected.
    pub round: u32,
    /// Validator identity.
    pub validator_id: Bytes32,
    /// Registered VRF public key.
    pub vrf_pubkey: [u8; 32],
    /// Revealed VRF output.
    pub vrf_output: Bytes32,
    /// Revealed VRF proof.
    pub vrf_proof: VariableBytes<MAX_VRF_PROOF_BYTES>,
    /// Prior commitment hash for this validator and slot.
    pub commit_hash: Bytes32,
    /// Hybrid signature over all fields above.
    pub signature: HybridSignature,
}

/// Durable block-body evidence for one VRF reveal that contributed to a
/// commit-reveal election result.
///
/// Retention follows normal block-body retention. Pruned validators retain
/// this evidence for their configured block window; archive nodes retain it
/// for full history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VrfRevealEvidence {
    /// Validator identity.
    pub validator_id: Bytes32,
    /// Revealed VRF output.
    pub vrf_output: Bytes32,
    /// Revealed VRF proof.
    pub vrf_proof: VariableBytes<MAX_VRF_PROOF_BYTES>,
}

impl Encode for VrfRevealEvidence {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.validator_id.encode(buf);
        self.vrf_output.encode(buf);
        self.vrf_proof.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        32 + 32 + self.vrf_proof.encoded_len()
    }
}

impl Decode for VrfRevealEvidence {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            validator_id: Bytes32::decode(r)?,
            vrf_output: Bytes32::decode(r)?,
            vrf_proof: VariableBytes::decode(r)?,
        })
    }
}

impl VrfReveal {
    /// Canonical bytes signed by the validator.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut data = b"INDRA-VRF-REVEAL-SIGN-v1".to_vec();
        self.chain_id_hash.encode(&mut data);
        self.height.encode(&mut data);
        self.round.encode(&mut data);
        self.validator_id.encode(&mut data);
        data.extend_from_slice(&self.vrf_pubkey);
        self.vrf_output.encode(&mut data);
        self.vrf_proof.encode(&mut data);
        self.commit_hash.encode(&mut data);
        data
    }
}

impl Encode for VrfReveal {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.chain_id_hash.encode(buf);
        self.height.encode(buf);
        self.round.encode(buf);
        self.validator_id.encode(buf);
        buf.extend_from_slice(&self.vrf_pubkey);
        self.vrf_output.encode(buf);
        self.vrf_proof.encode(buf);
        self.commit_hash.encode(buf);
        self.signature.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        32 + 8 + 4 + 32 + 32 + 32 + self.vrf_proof.encoded_len() + 32 + self.signature.encoded_len()
    }
}

impl Decode for VrfReveal {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            chain_id_hash: Bytes32::decode(r)?,
            height: u64::decode(r)?,
            round: u32::decode(r)?,
            validator_id: Bytes32::decode(r)?,
            vrf_pubkey: r.read_bytes32()?,
            vrf_output: Bytes32::decode(r)?,
            vrf_proof: VariableBytes::decode(r)?,
            commit_hash: Bytes32::decode(r)?,
            signature: HybridSignature::decode(r)?,
        })
    }
}

/// Deterministic election result attested by precommit votes and block headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VrfElectionResult {
    /// Block height being elected.
    pub height: u64,
    /// Consensus round being elected.
    pub round: u32,
    /// Elected validator identity.
    pub elected_validator_id: Bytes32,
    /// VRF output used for the winning election score.
    pub elected_vrf_output: Bytes32,
    /// Whether the round used the public deterministic fallback.
    pub fallback_used: bool,
    /// Merkle root over the full sorted reveal evidence set.
    ///
    /// This is included in the election result hash only when
    /// reveal_set_commitment_active(height) is true, preserving pre-fork
    /// election hashes before the activation boundary.
    pub reveal_set_commitment: Bytes32,
}

impl VrfElectionResult {
    /// Hash committed in block headers and precommit votes.
    pub fn hash(&self) -> Bytes32 {
        let mut data = b"INDRA-ELECTION-v1".to_vec();
        self.height.encode(&mut data);
        self.round.encode(&mut data);
        self.elected_validator_id.encode(&mut data);
        self.elected_vrf_output.encode(&mut data);
        (self.fallback_used as u8).encode(&mut data);
        if reveal_set_commitment_active(self.height) {
            self.reveal_set_commitment.encode(&mut data);
        }
        Bytes32::from(sha256(&data))
    }
}

/// Canonical Merkle root over sorted `(validator_id, vrf_output, vrf_proof)`
/// reveal tuples.
///
/// Leaves are sorted by validator_id. Each leaf and internal node is domain
/// separated. The empty-set root is a domain-separated hash, not all-zero.
pub fn compute_reveal_set_commitment(reveals: &[VrfRevealEvidence]) -> Bytes32 {
    let mut sorted = reveals.to_vec();
    sorted.sort_by_key(|reveal| reveal.validator_id.0);

    let mut leaves: Vec<Bytes32> = sorted
        .iter()
        .map(|reveal| {
            let mut data = b"INDRA-VRF-REVEAL-LEAF-v1".to_vec();
            reveal.encode(&mut data);
            Bytes32::from(sha256(&data))
        })
        .collect();

    if leaves.is_empty() {
        return Bytes32::from(sha256(b"INDRA-VRF-REVEAL-SET-EMPTY-v1"));
    }

    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        for pair in leaves.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            let mut data = b"INDRA-VRF-REVEAL-NODE-v1".to_vec();
            left.encode(&mut data);
            right.encode(&mut data);
            next.push(Bytes32::from(sha256(&data)));
        }
        leaves = next;
    }

    leaves[0]
}

/// Build canonical block-body reveal evidence from full signed reveal gossip.
pub fn reveal_evidence_from_reveals<I>(reveals: I) -> Vec<VrfRevealEvidence>
where
    I: IntoIterator<Item = VrfReveal>,
{
    let mut evidence: Vec<_> = reveals
        .into_iter()
        .map(|reveal| VrfRevealEvidence {
            validator_id: reveal.validator_id,
            vrf_output: reveal.vrf_output,
            vrf_proof: reveal.vrf_proof,
        })
        .collect();
    evidence.sort_by_key(|reveal| reveal.validator_id.0);
    evidence.truncate(MAX_ACTIVE_VALIDATORS);
    evidence
}

/// Compute the hidden commitment for a validator's VRF reveal.
pub fn compute_vrf_commit_hash(
    chain_id_hash: &Bytes32,
    height: u64,
    round: u32,
    validator_id: &Bytes32,
    vrf_pubkey: &[u8; 32],
    vrf_input: &[u8; 32],
    vrf_output: &Bytes32,
    vrf_proof: &[u8],
) -> Bytes32 {
    let mut data = b"INDRA-VRF-COMMIT-v1".to_vec();
    chain_id_hash.encode(&mut data);
    height.encode(&mut data);
    round.encode(&mut data);
    validator_id.encode(&mut data);
    data.extend_from_slice(vrf_pubkey);
    data.extend_from_slice(vrf_input);
    vrf_output.encode(&mut data);
    data.extend_from_slice(&sha256(vrf_proof));
    Bytes32::from(sha256(&data))
}

/// Hash a chain ID into the fixed-width field carried by VRF election messages.
pub fn chain_id_hash(chain_id: &str) -> Bytes32 {
    let mut data = b"INDRA-CHAIN-ID-v1".to_vec();
    let bytes = chain_id.as_bytes();
    let len = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    len.encode(&mut data);
    data.extend_from_slice(bytes);
    Bytes32::from(sha256(&data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::primitives::{MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES};

    fn dummy_sig() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(&[0xAA; 64])
                .expect("dummy classical sig length"),
            pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&[0xBB; 4627])
                .expect("dummy pq sig length"),
        }
    }

    #[test]
    fn vrf_commit_round_trip() {
        let commit = VrfCommit {
            chain_id_hash: Bytes32::from([1; 32]),
            height: 7,
            round: 2,
            validator_id: Bytes32::from([2; 32]),
            vrf_pubkey: [3; 32],
            commit_hash: Bytes32::from([4; 32]),
            signature: dummy_sig(),
        };
        assert_eq!(
            commit,
            VrfCommit::decode_exact(&commit.encode_to_vec()).unwrap()
        );
    }

    #[test]
    fn vrf_reveal_round_trip() {
        let reveal = VrfReveal {
            chain_id_hash: Bytes32::from([1; 32]),
            height: 7,
            round: 2,
            validator_id: Bytes32::from([2; 32]),
            vrf_pubkey: [3; 32],
            vrf_output: Bytes32::from([4; 32]),
            vrf_proof: VariableBytes::from_slice(&[5; 80]).unwrap(),
            commit_hash: Bytes32::from([6; 32]),
            signature: dummy_sig(),
        };
        assert_eq!(
            reveal,
            VrfReveal::decode_exact(&reveal.encode_to_vec()).unwrap()
        );
    }

    #[test]
    fn election_result_hash_is_domain_separated() {
        let a = VrfElectionResult {
            height: 1,
            round: 0,
            elected_validator_id: Bytes32::from([1; 32]),
            elected_vrf_output: Bytes32::from([2; 32]),
            fallback_used: false,
            reveal_set_commitment: Bytes32::ZERO,
        };
        let b = VrfElectionResult {
            fallback_used: true,
            ..a
        };
        assert_ne!(a.hash(), b.hash());
    }

    #[test]
    fn reveal_set_commitment_included_in_election_hash() {
        let a = VrfElectionResult {
            height: u64::MAX,
            round: 0,
            elected_validator_id: Bytes32::from([1; 32]),
            elected_vrf_output: Bytes32::from([2; 32]),
            fallback_used: false,
            reveal_set_commitment: Bytes32::from([0xAA; 32]),
        };
        let b = VrfElectionResult {
            reveal_set_commitment: Bytes32::from([0xBB; 32]),
            ..a.clone()
        };

        assert_ne!(
            a.hash(),
            b.hash(),
            "post-activation election hash must commit to reveal-set commitment"
        );
    }
}
