//! Canonical slash-evidence membership roots and proofs.

use crate::{
    codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::{
        consensus_snapshot::{ConsensusSnapshot, ConsensusSnapshotEntry},
        primitives::{Bytes32, MAX_ACTIVE_VALIDATORS},
    },
};
use indra_crypto::sha256;

/// Version of the ordered slash-membership Merkle construction.
pub const SLASH_MEMBERSHIP_ROOT_FORMAT_VERSION_V1: u8 = 1;
/// Maximum sibling hashes for at most 200 active validators.
pub const MAX_SLASH_MEMBERSHIP_PROOF_DEPTH: usize = 8;
/// Maximum retained roots for the inclusive 500-epoch evidence window.
pub const MAX_SLASH_MEMBERSHIP_ROOT_RECORDS: usize = 502;

const D_LEAF: &[u8] = b"INDRA-SLASH-MEMBER-LEAF-v1";
const D_EMPTY: &[u8] = b"INDRA-SLASH-MEMBER-EMPTY-v1";
const D_NODE: &[u8] = b"INDRA-SLASH-MEMBER-NODE-v1";
const D_ROOT: &[u8] = b"INDRA-SLASH-MEMBERSHIP-ROOT-v1";

/// Minimal canonical commitment retained for one consensus-authority interval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlashMembershipRootRecord {
    /// First height governed by this membership root.
    pub activation_height: u64,
    /// Ordered-tree membership commitment.
    pub membership_root: Bytes32,
}

impl Encode for SlashMembershipRootRecord {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.activation_height.encode(buf);
        self.membership_root.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        40
    }
}

impl Decode for SlashMembershipRootRecord {
    fn decode(reader: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            activation_height: u64::decode(reader)?,
            membership_root: Bytes32::decode(reader)?,
        })
    }
}

/// Version 1 membership proof for one complete consensus-snapshot entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashMembershipProofV1 {
    /// Root construction version; must be one.
    pub root_format_version: u8,
    /// Activation height of the proven snapshot.
    pub activation_height: u64,
    /// Number of real members before power-of-two padding.
    pub member_count: u32,
    /// Complete proven consensus entry.
    pub entry: ConsensusSnapshotEntry,
    /// Canonical zero-based entry position.
    pub position: u32,
    /// Siblings ordered from leaf level upward.
    pub sibling_hashes: Vec<Bytes32>,
}

impl SlashMembershipProofV1 {
    /// Validate canonical structural invariants independent of a selected root.
    pub fn validate_structure(&self) -> IndraResult<()> {
        if self.root_format_version != SLASH_MEMBERSHIP_ROOT_FORMAT_VERSION_V1 {
            return invalid("unsupported root format version");
        }
        if self.activation_height == 0 {
            return invalid("activation height is zero");
        }
        let count = usize::try_from(self.member_count)
            .map_err(|_| invalid_error("member count does not fit usize"))?;
        if count == 0 || count > MAX_ACTIVE_VALIDATORS {
            return invalid("member count is outside active-set bounds");
        }
        if usize::try_from(self.position).map_or(true, |position| position >= count) {
            return invalid("position is outside the real member set");
        }
        if self.sibling_hashes.len() != proof_depth(count)? {
            return invalid("sibling count does not equal canonical tree depth");
        }
        self.entry.validate()?;
        Ok(())
    }

    /// Verify this proof against the selected canonical root record.
    pub fn verify(&self, record: &SlashMembershipRootRecord) -> IndraResult<()> {
        self.validate_structure()?;
        if self.activation_height != record.activation_height {
            return invalid("proof activation height does not match root record");
        }
        let source_boundary_height = self
            .activation_height
            .checked_sub(1)
            .ok_or_else(|| invalid_error("activation height underflow"))?;
        let mut accumulator = real_leaf(self.activation_height, self.position, &self.entry);
        for (level, sibling) in self.sibling_hashes.iter().enumerate() {
            let level_u8 =
                u8::try_from(level).map_err(|_| invalid_error("proof level does not fit u8"))?;
            accumulator = if (self.position >> level) & 1 == 0 {
                node(level_u8, accumulator, *sibling)
            } else {
                node(level_u8, *sibling, accumulator)
            };
        }
        let root = final_root(
            self.activation_height,
            source_boundary_height,
            self.member_count,
            accumulator,
        );
        if root != record.membership_root {
            return invalid("membership proof root mismatch");
        }
        Ok(())
    }
}

impl Encode for SlashMembershipProofV1 {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.root_format_version.encode(buf);
        self.activation_height.encode(buf);
        self.member_count.encode(buf);
        self.entry.encode(buf);
        self.position.encode(buf);
        encode_list(&self.sibling_hashes, buf);
    }

    fn encoded_len(&self) -> usize {
        1 + 8 + 4 + self.entry.encoded_len() + 4 + list_encoded_len(&self.sibling_hashes)
    }
}

impl Decode for SlashMembershipProofV1 {
    fn decode(reader: &mut ByteReader<'_>) -> IndraResult<Self> {
        let proof = Self {
            root_format_version: u8::decode(reader)?,
            activation_height: u64::decode(reader)?,
            member_count: u32::decode(reader)?,
            entry: ConsensusSnapshotEntry::decode(reader)?,
            position: u32::decode(reader)?,
            sibling_hashes: decode_list(
                reader,
                MAX_SLASH_MEMBERSHIP_PROOF_DEPTH,
                "slash_membership_proof.sibling_hashes",
            )?,
        };
        proof.validate_structure()?;
        Ok(proof)
    }
}

/// Compute the Version 1 membership root of a fully validated snapshot.
pub fn compute_slash_membership_root(snapshot: &ConsensusSnapshot) -> IndraResult<Bytes32> {
    validate_snapshot_for_membership(snapshot)?;
    let leaves = tree_leaves(snapshot)?;
    let tree_root = reduce_tree(leaves)?;
    let member_count = u32::try_from(snapshot.entries().len())
        .map_err(|_| invalid_error("snapshot member count does not fit u32"))?;
    Ok(final_root(
        snapshot.activation_height,
        snapshot.source_boundary_height,
        member_count,
        tree_root,
    ))
}

/// Construct the unique canonical proof for one snapshot position.
pub fn build_slash_membership_proof(
    snapshot: &ConsensusSnapshot,
    position: usize,
) -> IndraResult<SlashMembershipProofV1> {
    validate_snapshot_for_membership(snapshot)?;
    let entry = snapshot
        .entries()
        .get(position)
        .ok_or_else(|| invalid_error("proof position is outside snapshot"))?
        .clone();
    let mut level_nodes = tree_leaves(snapshot)?;
    let mut index = position;
    let mut siblings = Vec::with_capacity(proof_depth(snapshot.entries().len())?);
    let mut level = 0u8;
    while level_nodes.len() > 1 {
        let sibling_index = index ^ 1;
        siblings.push(
            *level_nodes
                .get(sibling_index)
                .ok_or_else(|| invalid_error("missing canonical sibling"))?,
        );
        level_nodes = level_nodes
            .chunks_exact(2)
            .map(|pair| node(level, pair[0], pair[1]))
            .collect();
        index /= 2;
        level = level
            .checked_add(1)
            .ok_or_else(|| invalid_error("tree level overflow"))?;
    }
    let proof = SlashMembershipProofV1 {
        root_format_version: SLASH_MEMBERSHIP_ROOT_FORMAT_VERSION_V1,
        activation_height: snapshot.activation_height,
        member_count: u32::try_from(snapshot.entries().len())
            .map_err(|_| invalid_error("snapshot member count does not fit u32"))?,
        entry,
        position: u32::try_from(position)
            .map_err(|_| invalid_error("proof position does not fit u32"))?,
        sibling_hashes: siblings,
    };
    proof.validate_structure()?;
    Ok(proof)
}

fn validate_snapshot_for_membership(snapshot: &ConsensusSnapshot) -> IndraResult<()> {
    snapshot.validate()?;
    if snapshot.activation_height == 0
        || snapshot.source_boundary_height.checked_add(1) != Some(snapshot.activation_height)
    {
        return invalid("snapshot activation is not source boundary plus one");
    }
    Ok(())
}

fn tree_leaves(snapshot: &ConsensusSnapshot) -> IndraResult<Vec<Bytes32>> {
    let count = snapshot.entries().len();
    let padded = count
        .checked_next_power_of_two()
        .ok_or_else(|| invalid_error("padded member count overflow"))?;
    let mut leaves = Vec::with_capacity(padded);
    for (position, entry) in snapshot.entries().iter().enumerate() {
        let position = u32::try_from(position)
            .map_err(|_| invalid_error("entry position does not fit u32"))?;
        leaves.push(real_leaf(snapshot.activation_height, position, entry));
    }
    for position in count..padded {
        leaves.push(empty_leaf(
            snapshot.activation_height,
            u32::try_from(position)
                .map_err(|_| invalid_error("padding position does not fit u32"))?,
        ));
    }
    Ok(leaves)
}

fn reduce_tree(mut nodes: Vec<Bytes32>) -> IndraResult<Bytes32> {
    let mut level = 0u8;
    while nodes.len() > 1 {
        nodes = nodes
            .chunks_exact(2)
            .map(|pair| node(level, pair[0], pair[1]))
            .collect();
        level = level
            .checked_add(1)
            .ok_or_else(|| invalid_error("tree level overflow"))?;
    }
    nodes
        .first()
        .copied()
        .ok_or_else(|| invalid_error("membership tree is empty"))
}

fn proof_depth(count: usize) -> IndraResult<usize> {
    if count == 0 || count > MAX_ACTIVE_VALIDATORS {
        return invalid("member count is outside active-set bounds");
    }
    let padded = count
        .checked_next_power_of_two()
        .ok_or_else(|| invalid_error("padded member count overflow"))?;
    Ok(padded.trailing_zeros() as usize)
}

fn real_leaf(activation_height: u64, position: u32, entry: &ConsensusSnapshotEntry) -> Bytes32 {
    let mut bytes = Vec::with_capacity(D_LEAF.len() + 1 + 8 + 4 + entry.encoded_len());
    bytes.extend_from_slice(D_LEAF);
    SLASH_MEMBERSHIP_ROOT_FORMAT_VERSION_V1.encode(&mut bytes);
    activation_height.encode(&mut bytes);
    position.encode(&mut bytes);
    entry.encode(&mut bytes);
    Bytes32::from(sha256(&bytes))
}

fn empty_leaf(activation_height: u64, position: u32) -> Bytes32 {
    let mut bytes = Vec::with_capacity(D_EMPTY.len() + 1 + 8 + 4);
    bytes.extend_from_slice(D_EMPTY);
    SLASH_MEMBERSHIP_ROOT_FORMAT_VERSION_V1.encode(&mut bytes);
    activation_height.encode(&mut bytes);
    position.encode(&mut bytes);
    Bytes32::from(sha256(&bytes))
}

fn node(level: u8, left: Bytes32, right: Bytes32) -> Bytes32 {
    let mut bytes = Vec::with_capacity(D_NODE.len() + 1 + 1 + 64);
    bytes.extend_from_slice(D_NODE);
    SLASH_MEMBERSHIP_ROOT_FORMAT_VERSION_V1.encode(&mut bytes);
    level.encode(&mut bytes);
    left.encode(&mut bytes);
    right.encode(&mut bytes);
    Bytes32::from(sha256(&bytes))
}

fn final_root(
    activation_height: u64,
    source_boundary_height: u64,
    member_count: u32,
    tree_root: Bytes32,
) -> Bytes32 {
    let mut bytes = Vec::with_capacity(D_ROOT.len() + 1 + 8 + 8 + 4 + 32);
    bytes.extend_from_slice(D_ROOT);
    SLASH_MEMBERSHIP_ROOT_FORMAT_VERSION_V1.encode(&mut bytes);
    activation_height.encode(&mut bytes);
    source_boundary_height.encode(&mut bytes);
    member_count.encode(&mut bytes);
    tree_root.encode(&mut bytes);
    Bytes32::from(sha256(&bytes))
}

fn invalid<T>(reason: impl Into<String>) -> IndraResult<T> {
    Err(invalid_error(reason))
}

fn invalid_error(reason: impl Into<String>) -> IndraError {
    IndraError::InvalidSlashMembershipProof(reason.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_crypto::{ClassicalKeypair, HybridKeypair, PqKeypair, VrfKeypair};

    fn entry(id: u8) -> ConsensusSnapshotEntry {
        let classical = ClassicalKeypair::from_seed(&[id; 32]);
        let pq = PqKeypair::from_seed(&[id.wrapping_add(1); 32]).unwrap();
        let public = HybridKeypair::new(classical, pq).public_key();
        let vrf = VrfKeypair::from_seed(&[id.wrapping_add(2); 32]);
        ConsensusSnapshotEntry::new(
            Bytes32::from([id; 32]),
            u64::from(id) + 1,
            public.classical.0,
            public.pq.0,
            vrf.public_key(),
        )
        .unwrap()
    }

    fn snapshot(count: u8) -> ConsensusSnapshot {
        ConsensusSnapshot::new(301, 300, (1..=count).map(entry).collect()).unwrap()
    }

    #[test]
    fn membership_proofs_round_trip_and_verify_for_real_and_padded_trees() {
        for count in [1u8, 4, 20, 50, 100, 200] {
            let snapshot = snapshot(count);
            let root = SlashMembershipRootRecord {
                activation_height: 301,
                membership_root: compute_slash_membership_root(&snapshot).unwrap(),
            };
            for position in [0usize, usize::from(count) - 1] {
                let proof = build_slash_membership_proof(&snapshot, position).unwrap();
                proof.verify(&root).unwrap();
                let decoded = SlashMembershipProofV1::decode_exact(&proof.encode_to_vec()).unwrap();
                assert_eq!(decoded, proof);
                assert_eq!(
                    proof.sibling_hashes.len(),
                    proof_depth(usize::from(count)).unwrap()
                );
            }
        }
    }

    #[test]
    fn one_member_root_matches_independent_domain_separated_oracle() {
        let snapshot = snapshot(1);
        let entry = &snapshot.entries()[0];

        let mut leaf_preimage = Vec::new();
        leaf_preimage.extend_from_slice(b"INDRA-SLASH-MEMBER-LEAF-v1");
        leaf_preimage.push(1);
        leaf_preimage.extend_from_slice(&301u64.to_le_bytes());
        leaf_preimage.extend_from_slice(&0u32.to_le_bytes());
        entry.encode(&mut leaf_preimage);
        let tree_root = sha256(&leaf_preimage);

        let mut root_preimage = Vec::new();
        root_preimage.extend_from_slice(b"INDRA-SLASH-MEMBERSHIP-ROOT-v1");
        root_preimage.push(1);
        root_preimage.extend_from_slice(&301u64.to_le_bytes());
        root_preimage.extend_from_slice(&300u64.to_le_bytes());
        root_preimage.extend_from_slice(&1u32.to_le_bytes());
        root_preimage.extend_from_slice(&tree_root);

        assert_eq!(
            compute_slash_membership_root(&snapshot).unwrap(),
            Bytes32::from(sha256(&root_preimage))
        );
    }

    #[test]
    fn membership_proof_fails_closed_on_every_bound_field() {
        let snapshot = snapshot(4);
        let record = SlashMembershipRootRecord {
            activation_height: 301,
            membership_root: compute_slash_membership_root(&snapshot).unwrap(),
        };
        let proof = build_slash_membership_proof(&snapshot, 2).unwrap();

        let mut wrong_activation = proof.clone();
        wrong_activation.activation_height = 601;
        assert!(wrong_activation.verify(&record).is_err());

        let mut wrong_position = proof.clone();
        wrong_position.position = 1;
        assert!(wrong_position.verify(&record).is_err());

        let mut wrong_count = proof.clone();
        wrong_count.member_count = 3;
        assert!(wrong_count.verify(&record).is_err());

        let mut wrong_entry = proof.clone();
        wrong_entry.entry.consensus_weight_spark += 1;
        assert!(wrong_entry.verify(&record).is_err());

        let mut wrong_sibling = proof.clone();
        wrong_sibling.sibling_hashes[0] = Bytes32::from([0xFF; 32]);
        assert!(wrong_sibling.verify(&record).is_err());

        let mut short = proof;
        short.sibling_hashes.pop();
        assert!(short.verify(&record).is_err());
    }

    #[test]
    fn root_record_has_exact_forty_byte_encoding() {
        let record = SlashMembershipRootRecord {
            activation_height: 301,
            membership_root: Bytes32::from([7; 32]),
        };
        assert_eq!(record.encoded_len(), 40);
        assert_eq!(record.encode_to_vec().len(), 40);
        assert_eq!(
            SlashMembershipRootRecord::decode_exact(&record.encode_to_vec()).unwrap(),
            record
        );
    }
}
