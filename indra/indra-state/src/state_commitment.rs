//! Incremental authenticated commitment for validator/delegation/staking state.
//!
//! `StateCommitmentV2` is deliberately a derived cache over canonical
//! `ChainState` maps, not an independently persisted source of truth. Snapshot
//! decode and startup may rebuild it from canonical state. That keeps consensus
//! replay deterministic and avoids the "stored-but-not-canonical" drift class;
//! the tradeoff is a one-time O(total state) rebuild at startup instead of an
//! O(total state) rebuild on every block.
//!
//! Explicit scope boundary: this commitment fixes the per-block
//! validator/delegation/staking root rebuild. It does not fix the current
//! full-state `clone()` used for block projection, the linear
//! `DelegationMap` Vec lookup under a single validator, or the inherently
//! O(touched delegators) reward distribution pass.

use indra_core::{
    codec::Encode,
    types::{
        consensus_snapshot::ConsensusSnapshot,
        crypto::HybridPubKey,
        primitives::Bytes32,
        reward_economic_snapshot::RewardEconomicSnapshot,
        slash_membership::SlashMembershipRootRecord,
        stake_position::{StakePositionV1, UnbondingTrancheV1},
    },
};
use indra_crypto::sha256;

use crate::{
    persistent::PersistentAuthTree,
    validator::{
        DelegationReturnEvent, DelegatorEntry, EvictedValidatorTombstoneV1, StakeBondEntry,
        ValidatorEntry,
    },
    ChainState,
};

const KEY_DOMAIN: &[u8] = b"INDRA-state-v2-key:";

const DOMAIN_VALIDATOR: u8 = 0x01;
const DOMAIN_DELEGATOR: u8 = 0x02;
const DOMAIN_STAKING_NONCE: u8 = 0x03;
const DOMAIN_STAKED_BOND: u8 = 0x04;
const DOMAIN_SLASH_HASH: u8 = 0x05;
const DOMAIN_DELEGATION_RETURN_EVENT: u8 = 0x06;
const DOMAIN_DELEGATOR_IDENTITY: u8 = 0x07;
const DOMAIN_RETIRED_COLD_COMPONENT: u8 = 0x09;
const DOMAIN_CONSENSUS_SNAPSHOT: u8 = 0x0A;
const DOMAIN_REWARD_ECONOMIC_SNAPSHOT: u8 = 0x0B;
const DOMAIN_SLASH_MEMBERSHIP_ROOT: u8 = 0x0C;
const DOMAIN_EVICTED_VALIDATOR_TOMBSTONE: u8 = 0x0D;
/// Reserved canonical leaf domain for genesis-native staking positions.
pub const DOMAIN_STAKE_POSITION: u8 = 0x0E;
/// Reserved canonical leaf domain for exact-height unbonding tranches.
pub const DOMAIN_UNBONDING_TRANCHE: u8 = 0x0F;

/// Value-hash domain for a canonical staking-position leaf.
pub const STAKE_POSITION_LEAF_DOMAIN_V1: &[u8] = b"INDRA-STAKE-POSITION-LEAF-v1";
/// Value-hash domain for a canonical unbonding-tranche leaf.
pub const UNBONDING_TRANCHE_LEAF_DOMAIN_V1: &[u8] = b"INDRA-UNBONDING-TRANCHE-LEAF-v1";

/// Incremental sparse-Merkle commitment to validator/delegation/staking state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateCommitmentV2 {
    tree: PersistentAuthTree,
}

impl StateCommitmentV2 {
    /// Build a V2 commitment deterministically from canonical chain state.
    pub fn from_state(state: &ChainState, height: u64) -> Self {
        let mut leaves = Vec::new();
        for validator in state.validators.all_validators() {
            leaves.push((
                validator_key(&validator.validator_id),
                validator_value_hash(validator, height),
            ));
        }
        for (validator_id, delegators) in state.delegations.all_delegators() {
            for delegator in delegators {
                leaves.push((
                    delegator_key(validator_id, &delegator.delegator_id),
                    delegator_value_hash(delegator),
                ));
            }
        }
        for (signer_id, nonce) in &state.staking_nonces {
            leaves.push((
                staking_nonce_key(signer_id),
                staking_nonce_value_hash(signer_id, *nonce),
            ));
        }
        for (utxo_id, bond) in &state.staked_bonds {
            leaves.push((staked_bond_key(utxo_id), staked_bond_value_hash(bond)));
        }
        for position in state.stake_positions.values() {
            leaves.push(stake_position_commitment_leaf(position));
        }
        for tranche in state.unbonding_tranches.values() {
            leaves.push(unbonding_tranche_commitment_leaf(tranche));
        }
        for hash in &state.applied_slash_hashes {
            leaves.push((slash_hash_key(hash), slash_hash_value_hash(hash)));
        }
        for (delegator_id, pubkey) in &state.delegator_identities {
            leaves.push((
                delegator_identity_key(delegator_id),
                delegator_identity_value_hash(delegator_id, pubkey),
            ));
        }
        for component in &state.retired_cold_classical_components {
            leaves.push((
                retired_cold_component_key(0, component),
                retired_cold_component_value_hash(0, component),
            ));
        }
        for component in &state.retired_cold_pq_components {
            leaves.push((
                retired_cold_component_key(1, component),
                retired_cold_component_value_hash(1, component),
            ));
        }
        {
            for event in &state.delegation_return_events {
                leaves.push((
                    delegation_return_event_key(event),
                    delegation_return_event_value_hash(event),
                ));
            }
        }
        for snapshot in &state.consensus_snapshots {
            leaves.push((
                consensus_snapshot_key(snapshot.activation_height),
                consensus_snapshot_value_hash(snapshot),
            ));
        }
        if let Some(snapshot) = &state.reward_economic_snapshot {
            leaves.push((
                reward_economic_snapshot_key(snapshot.activation_height),
                reward_economic_snapshot_value_hash(snapshot),
            ));
        }
        for record in &state.slash_membership_roots {
            leaves.push((
                slash_membership_root_key(record.activation_height),
                slash_membership_root_value_hash(record),
            ));
        }
        for tombstone in state.evicted_validator_tombstones.values() {
            leaves.push((
                evicted_validator_tombstone_key(&tombstone.validator_id),
                evicted_validator_tombstone_value_hash(tombstone),
            ));
        }
        Self {
            tree: PersistentAuthTree::from_pairs(leaves)
                .expect("StateCommitmentV2 keys are domain-separated and unique"),
        }
    }

    /// Current commitment root.
    pub fn root(&self) -> Bytes32 {
        Bytes32::from(self.tree.root())
    }

    /// Insert or replace a validator leaf.
    pub fn put_validator(&mut self, validator: &ValidatorEntry, height: u64) {
        self.tree.insert(
            validator_key(&validator.validator_id),
            validator_value_hash(validator, height),
        );
    }

    /// Delete a validator leaf.
    pub fn delete_validator(&mut self, validator_id: &Bytes32) {
        self.tree.delete(validator_key(validator_id));
    }

    /// Insert or replace a delegator leaf.
    pub fn put_delegator(&mut self, validator_id: &Bytes32, delegator: &DelegatorEntry) {
        self.tree.insert(
            delegator_key(validator_id, &delegator.delegator_id),
            delegator_value_hash(delegator),
        );
    }

    /// Delete a delegator leaf.
    pub fn delete_delegator(&mut self, validator_id: &Bytes32, delegator_id: &Bytes32) {
        self.tree.delete(delegator_key(validator_id, delegator_id));
    }

    /// Insert or replace a staking nonce leaf.
    pub fn put_staking_nonce(&mut self, signer_id: &Bytes32, nonce: u64) {
        self.tree.insert(
            staking_nonce_key(signer_id),
            staking_nonce_value_hash(signer_id, nonce),
        );
    }

    /// Delete a staking nonce leaf.
    pub fn delete_staking_nonce(&mut self, signer_id: &Bytes32) {
        self.tree.delete(staking_nonce_key(signer_id));
    }

    /// Insert or replace a staked-bond leaf.
    pub fn put_staked_bond(&mut self, utxo_id: &Bytes32, bond: &StakeBondEntry) {
        self.tree
            .insert(staked_bond_key(utxo_id), staked_bond_value_hash(bond));
    }

    /// Delete a staked-bond leaf.
    pub fn delete_staked_bond(&mut self, utxo_id: &Bytes32) {
        self.tree.delete(staked_bond_key(utxo_id));
    }

    /// Insert or replace a canonical stake-position leaf.
    pub fn put_stake_position(&mut self, position: &StakePositionV1) {
        let (key, value) = stake_position_commitment_leaf(position);
        self.tree.insert(key, value);
    }

    /// Delete a canonical stake-position leaf.
    pub fn delete_stake_position(&mut self, position_id: &Bytes32) {
        self.tree
            .delete(derive_key(DOMAIN_STAKE_POSITION, &position_id.0));
    }

    /// Insert or replace a canonical unbonding-tranche leaf.
    pub fn put_unbonding_tranche(&mut self, tranche: &UnbondingTrancheV1) {
        let (key, value) = unbonding_tranche_commitment_leaf(tranche);
        self.tree.insert(key, value);
    }

    /// Delete a canonical unbonding-tranche leaf.
    pub fn delete_unbonding_tranche(&mut self, tranche_id: &Bytes32) {
        self.tree
            .delete(derive_key(DOMAIN_UNBONDING_TRANCHE, &tranche_id.0));
    }

    /// Insert a slash-evidence hash leaf.
    pub fn put_slash_hash(&mut self, hash: &Bytes32) {
        self.tree
            .insert(slash_hash_key(hash), slash_hash_value_hash(hash));
    }

    /// Insert a delegation-return event leaf.
    pub fn put_delegation_return_event(&mut self, event: &DelegationReturnEvent) {
        self.tree.insert(
            delegation_return_event_key(event),
            delegation_return_event_value_hash(event),
        );
    }

    /// Delete a delegation-return event leaf.
    pub fn delete_delegation_return_event(&mut self, event: &DelegationReturnEvent) {
        self.tree.delete(delegation_return_event_key(event));
    }

    /// Insert or replace a delegator identity-registry leaf.
    pub fn put_delegator_identity(&mut self, delegator_id: &Bytes32, pubkey: &HybridPubKey) {
        self.tree.insert(
            delegator_identity_key(delegator_id),
            delegator_identity_value_hash(delegator_id, pubkey),
        );
    }

    /// Permanently commit one retired cold public-key component.
    pub fn put_retired_cold_component(&mut self, kind: u8, component: &[u8]) {
        self.tree.insert(
            retired_cold_component_key(kind, component),
            retired_cold_component_value_hash(kind, component),
        );
    }

    /// Insert or replace an evicted-validator tombstone leaf.
    pub fn put_evicted_validator_tombstone(&mut self, tombstone: &EvictedValidatorTombstoneV1) {
        self.tree.insert(
            evicted_validator_tombstone_key(&tombstone.validator_id),
            evicted_validator_tombstone_value_hash(tombstone),
        );
    }

    /// Delete an evicted-validator tombstone leaf.
    pub fn delete_evicted_validator_tombstone(&mut self, validator_id: &Bytes32) {
        self.tree
            .delete(evicted_validator_tombstone_key(validator_id));
    }
}

pub(crate) fn validator_key(validator_id: &Bytes32) -> [u8; 32] {
    derive_key(DOMAIN_VALIDATOR, &validator_id.0)
}

pub(crate) fn delegator_key(validator_id: &Bytes32, delegator_id: &Bytes32) -> [u8; 32] {
    let mut raw = Vec::with_capacity(64);
    raw.extend_from_slice(&validator_id.0);
    raw.extend_from_slice(&delegator_id.0);
    derive_key(DOMAIN_DELEGATOR, &raw)
}

fn staking_nonce_key(signer_id: &Bytes32) -> [u8; 32] {
    derive_key(DOMAIN_STAKING_NONCE, &signer_id.0)
}

fn staked_bond_key(utxo_id: &Bytes32) -> [u8; 32] {
    derive_key(DOMAIN_STAKED_BOND, &utxo_id.0)
}

fn slash_hash_key(hash: &Bytes32) -> [u8; 32] {
    derive_key(DOMAIN_SLASH_HASH, &hash.0)
}

fn delegation_return_event_key(event: &DelegationReturnEvent) -> [u8; 32] {
    let mut raw = Vec::with_capacity(72);
    raw.extend_from_slice(&event.delegator_id.0);
    raw.extend_from_slice(&event.bond_utxo_id.0);
    raw.extend_from_slice(&event.returned_height.to_le_bytes());
    derive_key(DOMAIN_DELEGATION_RETURN_EVENT, &raw)
}

pub(crate) fn delegator_identity_key(delegator_id: &Bytes32) -> [u8; 32] {
    derive_key(DOMAIN_DELEGATOR_IDENTITY, &delegator_id.0)
}

fn retired_cold_component_key(kind: u8, component: &[u8]) -> [u8; 32] {
    let mut raw = Vec::with_capacity(1 + component.len());
    raw.push(kind);
    raw.extend_from_slice(component);
    derive_key(DOMAIN_RETIRED_COLD_COMPONENT, &raw)
}

fn consensus_snapshot_key(activation_height: u64) -> [u8; 32] {
    derive_key(DOMAIN_CONSENSUS_SNAPSHOT, &activation_height.to_le_bytes())
}

fn consensus_snapshot_value_hash(snapshot: &ConsensusSnapshot) -> [u8; 32] {
    sha256(&snapshot.encode_to_vec())
}

fn reward_economic_snapshot_key(activation_height: u64) -> [u8; 32] {
    derive_key(
        DOMAIN_REWARD_ECONOMIC_SNAPSHOT,
        &activation_height.to_le_bytes(),
    )
}

fn reward_economic_snapshot_value_hash(snapshot: &RewardEconomicSnapshot) -> [u8; 32] {
    sha256(&snapshot.encode_to_vec())
}

fn slash_membership_root_key(activation_height: u64) -> [u8; 32] {
    derive_key(
        DOMAIN_SLASH_MEMBERSHIP_ROOT,
        &activation_height.to_le_bytes(),
    )
}

fn slash_membership_root_value_hash(record: &SlashMembershipRootRecord) -> [u8; 32] {
    sha256(&record.encode_to_vec())
}

fn evicted_validator_tombstone_key(validator_id: &Bytes32) -> [u8; 32] {
    derive_key(DOMAIN_EVICTED_VALIDATOR_TOMBSTONE, &validator_id.0)
}

fn evicted_validator_tombstone_value_hash(tombstone: &EvictedValidatorTombstoneV1) -> [u8; 32] {
    let mut value = b"INDRA-EVICTED-VALIDATOR-TOMBSTONE-v1".to_vec();
    tombstone.encode(&mut value);
    sha256(&value)
}

fn retired_cold_component_value_hash(kind: u8, component: &[u8]) -> [u8; 32] {
    let mut value = Vec::with_capacity(1 + component.len());
    value.push(kind);
    value.extend_from_slice(component);
    sha256(&value)
}

fn derive_key(domain: u8, raw_key: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(KEY_DOMAIN.len() + 1 + raw_key.len());
    data.extend_from_slice(KEY_DOMAIN);
    data.push(domain);
    data.extend_from_slice(raw_key);
    sha256(&data)
}

/// Pure canonical leaf construction; Stage 1 deliberately does not insert it
/// into `StateCommitmentV2` or `ChainState`.
pub fn stake_position_commitment_leaf(position: &StakePositionV1) -> ([u8; 32], [u8; 32]) {
    let mut value =
        Vec::with_capacity(STAKE_POSITION_LEAF_DOMAIN_V1.len() + position.encoded_len());
    value.extend_from_slice(STAKE_POSITION_LEAF_DOMAIN_V1);
    position.encode(&mut value);
    (
        derive_key(DOMAIN_STAKE_POSITION, &position.position_id.0),
        sha256(&value),
    )
}

/// Pure canonical leaf construction; Stage 1 deliberately does not insert it
/// into `StateCommitmentV2` or `ChainState`.
pub fn unbonding_tranche_commitment_leaf(tranche: &UnbondingTrancheV1) -> ([u8; 32], [u8; 32]) {
    let mut value =
        Vec::with_capacity(UNBONDING_TRANCHE_LEAF_DOMAIN_V1.len() + tranche.encoded_len());
    value.extend_from_slice(UNBONDING_TRANCHE_LEAF_DOMAIN_V1);
    tranche.encode(&mut value);
    (
        derive_key(DOMAIN_UNBONDING_TRANCHE, &tranche.tranche_id.0),
        sha256(&value),
    )
}

pub(crate) fn validator_value_hash(validator: &ValidatorEntry, _height: u64) -> [u8; 32] {
    let include_network_addr = true;
    let mut value = Vec::new();
    value.extend_from_slice(&validator.validator_id.0);
    value.extend_from_slice(&validator.stake_spark.to_le_bytes());
    value.extend_from_slice(&validator.pending_rewards.to_le_bytes());
    value.extend_from_slice(&validator.registered_epoch.to_le_bytes());
    value.extend_from_slice(&validator.last_active_epoch.to_le_bytes());
    value.extend_from_slice(&validator.rewards_last_epoch.to_le_bytes());
    value.extend_from_slice(&validator.self_report_count.to_le_bytes());
    value.extend_from_slice(&validator.commission_bps.to_le_bytes());
    value.extend_from_slice(&validator.min_delegation_spark.to_le_bytes());
    value.push(u8::from(validator.auto_delegate_to.is_some()));
    if let Some(target_id) = validator.auto_delegate_to {
        value.extend_from_slice(&target_id.0);
    }
    match validator.status {
        crate::validator::ValidatorStatus::Registered => value.push(0),
        crate::validator::ValidatorStatus::Active => value.push(1),
        crate::validator::ValidatorStatus::Unbonding {
            unbonding_end_epoch,
        } => {
            value.push(2);
            value.extend_from_slice(&unbonding_end_epoch.to_le_bytes());
        }
        crate::validator::ValidatorStatus::Slashed => value.push(3),
        crate::validator::ValidatorStatus::Exited => value.push(4),
    }
    if let Some(pk) = validator.hybrid_classical_pk {
        value.extend_from_slice(&pk);
    }
    if let Some(pk) = &validator.hybrid_pq_pk {
        value.extend_from_slice(pk);
    }
    if let Some(vrf_pk) = validator.vrf_pk {
        value.extend_from_slice(&vrf_pk);
    }
    if include_network_addr {
        value.push(u8::from(validator.network_addr.is_some()));
        if let Some(addr) = &validator.network_addr {
            value.extend_from_slice(&(addr.len() as u16).to_le_bytes());
            value.extend_from_slice(addr.as_bytes());
        }
        value.push(u8::from(
            validator.network_addr_last_updated_epoch.is_some(),
        ));
        if let Some(epoch) = validator.network_addr_last_updated_epoch {
            value.extend_from_slice(&epoch.to_le_bytes());
        }
    }
    validator.append_cold_key_commitment(&mut value);
    sha256(&value)
}

pub(crate) fn delegator_value_hash(delegator: &DelegatorEntry) -> [u8; 32] {
    let mut value = Vec::new();
    value.extend_from_slice(&delegator.delegator_id.0);
    value.extend_from_slice(&delegator.staked_spark.to_le_bytes());
    value.extend_from_slice(&delegator.pending_rewards.to_le_bytes());
    value.extend_from_slice(&delegator.rewards_last_epoch.to_le_bytes());
    value.extend_from_slice(&delegator.unbonding_end_epoch.unwrap_or(0).to_le_bytes());
    value.push(u8::from(delegator.unbonding_end_epoch.is_some()));
    sha256(&value)
}

fn staking_nonce_value_hash(signer_id: &Bytes32, nonce: u64) -> [u8; 32] {
    let mut value = Vec::with_capacity(40);
    value.extend_from_slice(&signer_id.0);
    value.extend_from_slice(&nonce.to_le_bytes());
    sha256(&value)
}

fn staked_bond_value_hash(bond: &StakeBondEntry) -> [u8; 32] {
    let mut value = Vec::new();
    bond.encode(&mut value);
    sha256(&value)
}

fn slash_hash_value_hash(hash: &Bytes32) -> [u8; 32] {
    sha256(&hash.0)
}

fn delegation_return_event_value_hash(event: &DelegationReturnEvent) -> [u8; 32] {
    let mut value = Vec::new();
    event.encode(&mut value);
    sha256(&value)
}

pub(crate) fn delegator_identity_value_hash(
    delegator_id: &Bytes32,
    pubkey: &HybridPubKey,
) -> [u8; 32] {
    let mut value = Vec::with_capacity(32 + pubkey.encoded_len());
    value.extend_from_slice(&delegator_id.0);
    pubkey.encode(&mut value);
    sha256(&value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        codec::{Decode, Encode},
        types::{
            consensus_snapshot::{ConsensusSnapshot, ConsensusSnapshotEntry},
            crypto::{CommitmentV1, HybridPubKey},
            primitives::UNBONDING_PERIOD_EPOCHS,
            reward_economic_snapshot::{RewardEconomicSnapshot, RewardEconomicValidatorEntry},
            transaction::OutputV1,
        },
        VariableBytes,
    };
    use std::time::Instant;

    use crate::smt::CompressedAuthTree;

    fn id(byte: u8) -> Bytes32 {
        Bytes32::from([byte; 32])
    }

    fn validator(byte: u8) -> ValidatorEntry {
        let classical = indra_crypto::ClassicalKeypair::from_seed(&[byte; 32]);
        let pq = indra_crypto::PqKeypair::from_seed(&[byte.wrapping_add(1); 32]).unwrap();
        let public = indra_crypto::HybridKeypair::new(classical, pq).public_key();
        ValidatorEntry {
            validator_id: id(byte),
            name: format!("validator-{byte}"),
            hybrid_classical_pk: Some(public.classical.0),
            hybrid_pq_pk: Some(public.pq.0.to_vec()),
            vrf_pk: Some(
                indra_crypto::VrfKeypair::from_seed(&[byte.wrapping_add(2); 32]).public_key(),
            ),
            stake_spark: 1_000_000 + byte as u64,
            status: crate::validator::ValidatorStatus::Active,
            registered_epoch: 1,
            last_active_epoch: 1,
            pending_rewards: 0,
            rewards_last_epoch: 1,
            self_report_count: 0,
            commission_bps: 1_000,
            pending_commission_bps: None,
            pending_commission_effective_epoch: None,
            min_delegation_spark: 1,
            auto_delegate_to: None,
            network_addr: None,
            network_addr_last_updated_epoch: None,
            cold_hybrid_classical_pk: Some(public.classical.0),
            cold_hybrid_pq_pk: Some(public.pq.0),
            cold_key_version: 1,
            cold_nonce: 0,
        }
    }

    fn consensus_snapshot(
        activation_height: u64,
        source_boundary_height: u64,
        weight: u64,
    ) -> ConsensusSnapshot {
        let classical = indra_crypto::ClassicalKeypair::from_seed(&[0xA1; 32]);
        let pq = indra_crypto::PqKeypair::from_seed(&[0xA2; 32]).unwrap();
        let public = indra_crypto::HybridKeypair::new(classical, pq).public_key();
        let vrf = indra_crypto::VrfKeypair::from_seed(&[0xA3; 32]);
        ConsensusSnapshot::new(
            activation_height,
            source_boundary_height,
            vec![ConsensusSnapshotEntry::new(
                id(0xA0),
                weight,
                public.classical.0,
                public.pq.0,
                vrf.public_key(),
            )
            .unwrap()],
        )
        .unwrap()
    }

    #[test]
    fn consensus_snapshot_leaf_is_content_sensitive_and_domain_separated() {
        let height = u64::MAX;
        let mut state = ChainState::new_genesis();
        state.height = height;
        state.consensus_snapshots = vec![
            consensus_snapshot(1, 0, 1_000_000_000),
            consensus_snapshot(301, 300, 2_000_000_000),
        ];
        let baseline = StateCommitmentV2::from_state(&state, height).root();

        let mut changed_previous = state.clone();
        changed_previous.consensus_snapshots[0] = consensus_snapshot(1, 0, 1_000_000_001);
        assert_ne!(
            StateCommitmentV2::from_state(&changed_previous, height).root(),
            baseline
        );
        let mut changed_current = state.clone();
        changed_current.consensus_snapshots[1] = consensus_snapshot(301, 300, 2_000_000_001);
        assert_ne!(
            StateCommitmentV2::from_state(&changed_current, height).root(),
            baseline
        );

        let mut unrelated = state.clone();
        unrelated.epoch_fees_burned = 99;
        unrelated.epoch_slashed_spark = 88;
        unrelated.epoch_slash_event_count = 7;
        assert_eq!(
            StateCommitmentV2::from_state(&unrelated, height).root(),
            baseline
        );

        assert_ne!(
            consensus_snapshot_key(1),
            validator_key(&id(1)),
            "snapshot and validator leaf domains must not collide"
        );
    }

    #[test]
    fn reward_economic_snapshot_leaf_is_content_sensitive_and_domain_separated() {
        let height = u64::MAX;
        let mut state = ChainState::new_genesis();
        state.height = height;
        state.reward_economic_snapshot = Some(
            RewardEconomicSnapshot::new(
                301,
                300,
                2_000,
                vec![RewardEconomicValidatorEntry::new(id(0xA0), 1_000, vec![], 2_000).unwrap()],
            )
            .unwrap(),
        );
        let baseline = StateCommitmentV2::from_state(&state, height).root();

        let mut changed = state.clone();
        changed.reward_economic_snapshot = Some(
            RewardEconomicSnapshot::new(
                301,
                300,
                2_000,
                vec![RewardEconomicValidatorEntry::new(id(0xA0), 1_001, vec![], 2_000).unwrap()],
            )
            .unwrap(),
        );
        assert_ne!(
            StateCommitmentV2::from_state(&changed, height).root(),
            baseline
        );

        let mut unrelated = state.clone();
        unrelated.epoch_fees_burned = 99;
        assert_eq!(
            StateCommitmentV2::from_state(&unrelated, height).root(),
            baseline
        );
        assert_ne!(
            reward_economic_snapshot_key(301),
            consensus_snapshot_key(301)
        );
    }

    #[test]
    fn slash_membership_root_leaf_is_content_sensitive_and_domain_separated() {
        let height = u64::MAX;
        let mut state = ChainState::new_genesis();
        state.height = height;
        state.slash_membership_roots = vec![SlashMembershipRootRecord {
            activation_height: height,
            membership_root: id(0xC1),
        }];
        let baseline = StateCommitmentV2::from_state(&state, height).root();

        let mut changed = state.clone();
        changed.slash_membership_roots[0].membership_root = id(0xC2);
        assert_ne!(
            StateCommitmentV2::from_state(&changed, height).root(),
            baseline
        );

        let mut unrelated = state.clone();
        unrelated.epoch_fees_burned = 99;
        assert_eq!(
            StateCommitmentV2::from_state(&unrelated, height).root(),
            baseline
        );
        assert_ne!(
            slash_membership_root_key(height),
            reward_economic_snapshot_key(height)
        );
        assert_ne!(
            slash_membership_root_key(height),
            consensus_snapshot_key(height)
        );
    }

    fn output(owner: u8, value: u64) -> OutputV1 {
        OutputV1 {
            value_spark: value,
            commitment: CommitmentV1 {
                compressed_point: id(owner),
            },
            owner_pubkey: HybridPubKey {
                classical_pk: id(owner),
                pq_pk: VariableBytes::from_slice(&[owner; 32]).unwrap_or_default(),
            },
            range_proof: VariableBytes::from_slice(&[]).unwrap_or_default(),
            lock_height: 0,
        }
    }

    fn bond(utxo_id: Bytes32, validator_id: Bytes32, delegator_id: Bytes32) -> StakeBondEntry {
        StakeBondEntry {
            utxo_id,
            validator_id,
            delegator_id,
            amount_spark: 7_000,
            bonded_epoch: 3,
            unbonding_end_epoch: None,
            unbonding_start_height: None,
            custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(delegator_id),
            original_output: output(0xAA, 7_000).into(),
        }
    }

    fn pubkey(byte: u8) -> HybridPubKey {
        HybridPubKey {
            classical_pk: id(byte),
            pq_pk: VariableBytes::from_slice(&[byte.wrapping_add(1); 2_592]).unwrap_or_default(),
        }
    }

    fn legacy_state_commitment_v2_root(state: &ChainState, height: u64) -> Bytes32 {
        let mut leaves = Vec::new();
        for validator in state.validators.all_validators() {
            leaves.push((
                validator_key(&validator.validator_id),
                validator_value_hash(validator, height),
            ));
        }
        for (validator_id, delegators) in state.delegations.all_delegators() {
            for delegator in delegators {
                leaves.push((
                    delegator_key(validator_id, &delegator.delegator_id),
                    delegator_value_hash(delegator),
                ));
            }
        }
        for (signer_id, nonce) in &state.staking_nonces {
            leaves.push((
                staking_nonce_key(signer_id),
                staking_nonce_value_hash(signer_id, *nonce),
            ));
        }
        for (utxo_id, bond) in &state.staked_bonds {
            leaves.push((staked_bond_key(utxo_id), staked_bond_value_hash(bond)));
        }
        for hash in &state.applied_slash_hashes {
            leaves.push((slash_hash_key(hash), slash_hash_value_hash(hash)));
        }
        for (delegator_id, pubkey) in &state.delegator_identities {
            leaves.push((
                delegator_identity_key(delegator_id),
                delegator_identity_value_hash(delegator_id, pubkey),
            ));
        }
        {
            for event in &state.delegation_return_events {
                leaves.push((
                    delegation_return_event_key(event),
                    delegation_return_event_value_hash(event),
                ));
            }
        }
        for snapshot in &state.consensus_snapshots {
            leaves.push((
                consensus_snapshot_key(snapshot.activation_height),
                consensus_snapshot_value_hash(snapshot),
            ));
        }
        if let Some(snapshot) = &state.reward_economic_snapshot {
            leaves.push((
                reward_economic_snapshot_key(snapshot.activation_height),
                reward_economic_snapshot_value_hash(snapshot),
            ));
        }
        for record in &state.slash_membership_roots {
            leaves.push((
                slash_membership_root_key(record.activation_height),
                slash_membership_root_value_hash(record),
            ));
        }
        for tombstone in state.evicted_validator_tombstones.values() {
            leaves.push((
                evicted_validator_tombstone_key(&tombstone.validator_id),
                evicted_validator_tombstone_value_hash(tombstone),
            ));
        }
        Bytes32::from(
            CompressedAuthTree::from_pairs(leaves)
                .expect("legacy oracle keys are domain-separated and unique")
                .root(),
        )
    }

    fn pre_identity_state_commitment_v2_root(state: &ChainState, height: u64) -> Bytes32 {
        let mut leaves = Vec::new();
        for validator in state.validators.all_validators() {
            leaves.push((
                validator_key(&validator.validator_id),
                validator_value_hash(validator, height),
            ));
        }
        for (validator_id, delegators) in state.delegations.all_delegators() {
            for delegator in delegators {
                leaves.push((
                    delegator_key(validator_id, &delegator.delegator_id),
                    delegator_value_hash(delegator),
                ));
            }
        }
        for (signer_id, nonce) in &state.staking_nonces {
            leaves.push((
                staking_nonce_key(signer_id),
                staking_nonce_value_hash(signer_id, *nonce),
            ));
        }
        for (utxo_id, bond) in &state.staked_bonds {
            leaves.push((staked_bond_key(utxo_id), staked_bond_value_hash(bond)));
        }
        for hash in &state.applied_slash_hashes {
            leaves.push((slash_hash_key(hash), slash_hash_value_hash(hash)));
        }
        {
            for event in &state.delegation_return_events {
                leaves.push((
                    delegation_return_event_key(event),
                    delegation_return_event_value_hash(event),
                ));
            }
        }
        Bytes32::from(
            CompressedAuthTree::from_pairs(leaves)
                .expect("pre-identity oracle keys are domain-separated and unique")
                .root(),
        )
    }

    fn independent_delegator_identity_key(delegator_id: &Bytes32) -> [u8; 32] {
        let mut data = Vec::with_capacity(KEY_DOMAIN.len() + 1 + 32);
        data.extend_from_slice(KEY_DOMAIN);
        data.push(0x07);
        data.extend_from_slice(&delegator_id.0);
        sha256(&data)
    }

    fn independent_delegator_identity_value_hash(
        delegator_id: &Bytes32,
        pubkey: &HybridPubKey,
    ) -> [u8; 32] {
        let mut encoded_pubkey = Vec::new();
        pubkey.encode(&mut encoded_pubkey);
        let mut value = Vec::with_capacity(32 + encoded_pubkey.len());
        value.extend_from_slice(&delegator_id.0);
        value.extend_from_slice(&encoded_pubkey);
        sha256(&value)
    }

    fn synthetic_delegation_state(size: usize, height: u64) -> ChainState {
        let validator = validator(0x99);
        let validator_id = validator.validator_id;
        let mut state = ChainState::new_genesis();
        state.validators.upsert(validator).unwrap();
        for index in 0..size {
            let mut bytes = [0u8; 32];
            bytes[0] = 0xD0;
            bytes[8..16].copy_from_slice(&(index as u64).to_be_bytes());
            state.delegations.push_delegator_for_test(
                validator_id,
                DelegatorEntry {
                    delegator_id: Bytes32::from(bytes),
                    staked_spark: 1_000,
                    pending_rewards: (index % 17) as u64,
                    rewards_last_epoch: (index % 11) as u64,
                    unbonding_end_epoch: (index % 97 == 0).then_some(100 + index as u64),
                },
            );
        }
        state.finalize_genesis().unwrap();
        state.height = height;
        state
    }

    fn synthetic_commitment_leaves(size: usize, height: u64) -> Vec<([u8; 32], [u8; 32])> {
        let validator = validator(0x99);
        let validator_id = validator.validator_id;
        let mut leaves = Vec::with_capacity(size.saturating_add(1));
        leaves.push((
            validator_key(&validator_id),
            validator_value_hash(&validator, height),
        ));
        for index in 0..size {
            let mut bytes = [0u8; 32];
            bytes[0] = 0xD0;
            bytes[8..16].copy_from_slice(&(index as u64).to_be_bytes());
            let delegator = DelegatorEntry {
                delegator_id: Bytes32::from(bytes),
                staked_spark: 1_000,
                pending_rewards: (index % 17) as u64,
                rewards_last_epoch: (index % 11) as u64,
                unbonding_end_epoch: (index % 97 == 0).then_some(100 + index as u64),
            };
            leaves.push((
                delegator_key(&validator_id, &delegator.delegator_id),
                delegator_value_hash(&delegator),
            ));
        }
        leaves
    }

    #[test]
    fn validator_leaf_commits_cold_state_but_not_uncommitted_display_name() {
        let base = validator(0x73);
        let height = 0;
        let base_hash = validator_value_hash(&base, height);

        let mut display_only = base.clone();
        display_only.name = "uncommitted display metadata".to_string();
        assert_eq!(validator_value_hash(&display_only, height), base_hash);

        let mut cold = base;
        cold.cold_hybrid_classical_pk = Some([0x81; 32]);
        cold.cold_hybrid_pq_pk = Some([0x82; indra_crypto::PQ_PK_BYTES]);
        cold.cold_key_version = 1;
        assert_ne!(validator_value_hash(&cold, height), base_hash);

        cold.cold_nonce = 1;
        assert_ne!(
            validator_value_hash(&cold, height),
            validator_value_hash(&display_only, height)
        );
    }

    #[test]
    fn delegator_identity_leaf_hashing_matches_documented_oracle_formula() {
        for byte in [0x01u8, 0x7F, 0xA5, 0xFE] {
            let delegator_id = id(byte);
            let pubkey = pubkey(byte.wrapping_add(3));
            assert_eq!(
                delegator_identity_key(&delegator_id),
                independent_delegator_identity_key(&delegator_id)
            );
            assert_eq!(
                delegator_identity_value_hash(&delegator_id, &pubkey),
                independent_delegator_identity_value_hash(&delegator_id, &pubkey)
            );
        }
    }

    #[test]
    fn delegator_identity_incremental_updates_match_full_rebuild() {
        let height = u64::MAX;
        let mut state = ChainState::new_genesis();
        let mut incremental = StateCommitmentV2::from_state(&state, height);

        for index in 0..64u8 {
            let delegator_id = id(index);
            let identity = pubkey(index.wrapping_add(0x40));
            state
                .delegator_identities
                .insert(delegator_id, identity.clone());
            incremental.put_delegator_identity(&delegator_id, &identity);
        }

        assert_eq!(
            incremental.root(),
            StateCommitmentV2::from_state(&state, height).root()
        );
        assert_eq!(
            incremental.root(),
            legacy_state_commitment_v2_root(&state, height)
        );
    }

    #[test]
    fn delegator_identity_leaves_are_root_sensitive_and_domain_separated() {
        let height = u64::MAX;
        let mut state = ChainState::new_genesis();
        state.rebuild_state_commitment_v2(height);
        let empty_root = state.state_commitment_v2_root(height);

        let delegator_id = id(0x31);
        let identity = pubkey(0x41);
        state
            .delegator_identities
            .insert(delegator_id, identity.clone());
        state
            .state_commitment_v2
            .as_mut()
            .unwrap()
            .put_delegator_identity(&delegator_id, &identity);
        let inserted_root = state.state_commitment_v2_root(height);
        assert_ne!(empty_root, inserted_root);

        let updated_identity = pubkey(0x42);
        state
            .delegator_identities
            .insert(delegator_id, updated_identity.clone());
        state
            .state_commitment_v2
            .as_mut()
            .unwrap()
            .put_delegator_identity(&delegator_id, &updated_identity);
        assert_ne!(inserted_root, state.state_commitment_v2_root(height));

        let identity_key = delegator_identity_key(&delegator_id);
        assert_ne!(identity_key, validator_key(&delegator_id));
        assert_ne!(identity_key, staking_nonce_key(&delegator_id));
        assert_ne!(identity_key, staked_bond_key(&delegator_id));
        assert_ne!(identity_key, slash_hash_key(&delegator_id));
    }

    #[test]
    fn state_txn_rollback_rebuilds_identity_commitment_from_canonical_registry() {
        let height = u64::MAX;
        let mut state = ChainState::new_genesis();
        let existing_id = id(0x50);
        let existing_identity = pubkey(0x51);
        state
            .delegator_identities
            .insert(existing_id, existing_identity.clone());
        state.rebuild_state_commitment_v2(height);
        let baseline_root = state.state_commitment_v2_root(height);

        {
            let mut txn = crate::txn::StateTxn::begin(&mut state, height);
            txn.ensure_state_commitment_v2().unwrap();
            txn.snapshot_delegator_identity_scope();
            let transient_id = id(0x60);
            let transient_identity = pubkey(0x61);
            txn.state_mut()
                .delegator_identities
                .insert(transient_id, transient_identity.clone());
            txn.state_mut()
                .state_commitment_v2
                .as_mut()
                .unwrap()
                .put_delegator_identity(&transient_id, &transient_identity);
            assert_ne!(txn.state().state_commitment_v2_root(height), baseline_root);
        }

        assert_eq!(state.delegator_identities.len(), 1);
        assert_eq!(
            state.delegator_identities.get(&existing_id),
            Some(&existing_identity)
        );
        assert_eq!(state.state_commitment_v2_root(height), baseline_root);
        state.rebuild_state_commitment_v2(height);
        assert_eq!(state.state_commitment_v2_root(height), baseline_root);
    }

    #[test]
    fn empty_delegator_identity_registry_preserves_pre_stage2_root() {
        let height = u64::MAX;
        let mut state = ChainState::new_genesis();
        let validator = validator(0x70);
        state.validators.upsert(validator.clone()).unwrap();
        state.staking_nonces.insert(id(0x71), 12);
        let bond_id = id(0x72);
        state
            .staked_bonds
            .insert(bond_id, bond(bond_id, validator.validator_id, id(0x73)));
        assert!(state.delegator_identities.is_empty());

        let pre_stage2_root = pre_identity_state_commitment_v2_root(&state, height);
        let post_stage2_root = StateCommitmentV2::from_state(&state, height).root();
        assert_eq!(post_stage2_root, pre_stage2_root);
    }

    #[test]
    fn state_commitment_v2_domain_bytes_do_not_collide() {
        let domains = [
            ("validator", DOMAIN_VALIDATOR),
            ("delegator", DOMAIN_DELEGATOR),
            ("staking_nonce", DOMAIN_STAKING_NONCE),
            ("staked_bond", DOMAIN_STAKED_BOND),
            ("slash_hash", DOMAIN_SLASH_HASH),
            ("delegation_return_event", DOMAIN_DELEGATION_RETURN_EVENT),
            ("delegator_identity", DOMAIN_DELEGATOR_IDENTITY),
            ("retired_cold_component", DOMAIN_RETIRED_COLD_COMPONENT),
            ("consensus_snapshot", DOMAIN_CONSENSUS_SNAPSHOT),
            ("reward_economic_snapshot", DOMAIN_REWARD_ECONOMIC_SNAPSHOT),
            ("slash_membership_root", DOMAIN_SLASH_MEMBERSHIP_ROOT),
            (
                "evicted_validator_tombstone",
                DOMAIN_EVICTED_VALIDATOR_TOMBSTONE,
            ),
            ("stake_position", DOMAIN_STAKE_POSITION),
            ("unbonding_tranche", DOMAIN_UNBONDING_TRANCHE),
        ];
        let mut seen = std::collections::BTreeMap::new();
        for (name, domain) in domains {
            assert_eq!(
                seen.insert(domain, name),
                None,
                "StateCommitmentV2 domain byte collision at 0x{domain:02x}"
            );
        }
        assert_eq!(DOMAIN_CONSENSUS_SNAPSHOT, 0x0A);
        assert_eq!(DOMAIN_REWARD_ECONOMIC_SNAPSHOT, 0x0B);
        assert_eq!(DOMAIN_SLASH_MEMBERSHIP_ROOT, 0x0C);
        assert_eq!(DOMAIN_EVICTED_VALIDATOR_TOMBSTONE, 0x0D);
        assert_eq!(DOMAIN_STAKE_POSITION, 0x0E);
        assert_eq!(DOMAIN_UNBONDING_TRANCHE, 0x0F);
    }

    #[test]
    fn position_and_tranche_leaf_primitives_are_sensitive_and_cross_domain_separated() {
        use indra_core::types::stake_position::{
            ActiveStakeAggregateV1, PositionCustodyV1, StakePositionV1, UnbondingTimingV1,
            UnbondingTrancheV1,
        };
        let custody = PositionCustodyV1::DelegatorIdentity {
            delegator_id: id(2),
        };
        let position = StakePositionV1::new(
            id(1),
            id(2),
            custody,
            Some(ActiveStakeAggregateV1::new(1_000, 10, 20).unwrap()),
            7,
            3,
        )
        .unwrap();
        let timing = UnbondingTimingV1::height_precise(301).unwrap();
        let tranche = UnbondingTrancheV1::new(
            position.position_id,
            400,
            indra_crypto::commit(400, &[9; 32]),
            timing,
            custody,
            id(3),
            0,
        )
        .unwrap();
        let position_leaf = stake_position_commitment_leaf(&position);
        let tranche_leaf = unbonding_tranche_commitment_leaf(&tranche);
        assert_ne!(position_leaf.0, tranche_leaf.0);
        assert_ne!(position_leaf.1, tranche_leaf.1);

        let changed_position = StakePositionV1::new(
            id(1),
            id(2),
            custody,
            Some(ActiveStakeAggregateV1::new(1_001, 10, 20).unwrap()),
            7,
            3,
        )
        .unwrap();
        assert_ne!(
            stake_position_commitment_leaf(&changed_position),
            position_leaf
        );
        let changed_tranche = UnbondingTrancheV1::new(
            position.position_id,
            401,
            indra_crypto::commit(401, &[9; 32]),
            timing,
            custody,
            id(3),
            0,
        )
        .unwrap();
        assert_ne!(
            unbonding_tranche_commitment_leaf(&changed_tranche),
            tranche_leaf
        );

        // Even identical raw IDs cannot collide across the allocated key domains.
        assert_ne!(
            derive_key(DOMAIN_STAKE_POSITION, &position.position_id.0),
            derive_key(DOMAIN_UNBONDING_TRANCHE, &position.position_id.0)
        );
    }

    #[test]
    fn evicted_validator_tombstone_incremental_commitment_matches_rebuild() {
        let height = u64::MAX;
        let mut state = ChainState::new_genesis();
        state.height = height;
        let baseline = StateCommitmentV2::from_state(&state, height).root();
        let validator_id = id(0xED);
        let tombstone = EvictedValidatorTombstoneV1 {
            validator_id,
            eviction_height: height - 1,
            eviction_epoch: crate::epoch::epoch_for_height(height - 1),
            last_classical_vote_pk: [0x01; 32],
            last_pq_vote_pk: [0x02; indra_crypto::PQ_PK_BYTES],
            last_vrf_pk: [0x03; 32],
            cold_custody: None,
            retained_bonds: Vec::new(),
        };
        state
            .evicted_validator_tombstones
            .insert(validator_id, tombstone.clone());
        let rebuilt = StateCommitmentV2::from_state(&state, height).root();
        assert_ne!(rebuilt, baseline);

        let mut incremental = StateCommitmentV2::from_state(&ChainState::new_genesis(), height);
        incremental.put_evicted_validator_tombstone(&tombstone);
        assert_eq!(incremental.root(), rebuilt);
        incremental.delete_evicted_validator_tombstone(&validator_id);
        assert_eq!(incremental.root(), baseline);
    }

    #[test]
    fn state_commitment_v2_incremental_matches_rebuild_after_each_category() {
        let height = u64::MAX;
        let mut state = ChainState::new_genesis();
        state.rebuild_state_commitment_v2(height);
        assert_eq!(
            state.state_commitment_v2_root(height),
            legacy_state_commitment_v2_root(&state, height)
        );

        let validator = validator(0x11);
        state.validators.upsert(validator.clone()).unwrap();
        state
            .state_commitment_v2
            .as_mut()
            .unwrap()
            .put_validator(&validator, height);
        assert_eq!(
            state.state_commitment_v2_root(height),
            StateCommitmentV2::from_state(&state, height).root()
        );
        assert_eq!(
            state.state_commitment_v2_root(height),
            legacy_state_commitment_v2_root(&state, height)
        );

        let delegator = DelegatorEntry {
            delegator_id: id(0x22),
            staked_spark: 500,
            pending_rewards: 9,
            rewards_last_epoch: 2,
            unbonding_end_epoch: None,
        };
        state
            .delegations
            .add_delegation(validator.validator_id, delegator.delegator_id, 500, 2)
            .unwrap();
        if let Some(entry) = state
            .delegations
            .get_delegators(&validator.validator_id)
            .first()
        {
            state
                .state_commitment_v2
                .as_mut()
                .unwrap()
                .put_delegator(&validator.validator_id, entry);
        }
        assert_eq!(
            state.state_commitment_v2_root(height),
            StateCommitmentV2::from_state(&state, height).root()
        );
        assert_eq!(
            state.state_commitment_v2_root(height),
            legacy_state_commitment_v2_root(&state, height)
        );

        state.staking_nonces.insert(id(0x33), 4);
        state
            .state_commitment_v2
            .as_mut()
            .unwrap()
            .put_staking_nonce(&id(0x33), 4);
        assert_eq!(
            state.state_commitment_v2_root(height),
            StateCommitmentV2::from_state(&state, height).root()
        );
        assert_eq!(
            state.state_commitment_v2_root(height),
            legacy_state_commitment_v2_root(&state, height)
        );

        let bond_id = id(0x44);
        let bond = bond(bond_id, validator.validator_id, delegator.delegator_id);
        state.staked_bonds.insert(bond_id, bond.clone());
        state
            .state_commitment_v2
            .as_mut()
            .unwrap()
            .put_staked_bond(&bond_id, &bond);
        assert_eq!(
            state.state_commitment_v2_root(height),
            StateCommitmentV2::from_state(&state, height).root()
        );
        assert_eq!(
            state.state_commitment_v2_root(height),
            legacy_state_commitment_v2_root(&state, height)
        );

        let slash_hash = id(0x55);
        state.applied_slash_hashes.insert(slash_hash);
        state
            .state_commitment_v2
            .as_mut()
            .unwrap()
            .put_slash_hash(&slash_hash);
        assert_eq!(
            state.state_commitment_v2_root(height),
            StateCommitmentV2::from_state(&state, height).root()
        );
        assert_eq!(
            state.state_commitment_v2_root(height),
            legacy_state_commitment_v2_root(&state, height)
        );

        let event = DelegationReturnEvent {
            delegator_id: delegator.delegator_id,
            validator_id: validator.validator_id,
            bond_utxo_id: bond_id,
            amount_spark: 100,
            reason: crate::validator::DelegationReturnReason::ValidatorEvicted,
            returned_epoch: 9,
            returned_height: height,
            refund_utxo_id: id(0x66),
        };
        state.push_delegation_return_event(event);
        assert_eq!(
            state.state_commitment_v2_root(height),
            StateCommitmentV2::from_state(&state, height).root()
        );
        assert_eq!(
            state.state_commitment_v2_root(height),
            legacy_state_commitment_v2_root(&state, height)
        );

        let identity_id = id(0x77);
        let identity_pubkey = pubkey(0x78);
        state
            .delegator_identities
            .insert(identity_id, identity_pubkey.clone());
        state
            .state_commitment_v2
            .as_mut()
            .unwrap()
            .put_delegator_identity(&identity_id, &identity_pubkey);
        assert_eq!(
            state.state_commitment_v2_root(height),
            StateCommitmentV2::from_state(&state, height).root()
        );
        assert_eq!(
            state.state_commitment_v2_root(height),
            legacy_state_commitment_v2_root(&state, height)
        );

        state
            .state_commitment_v2
            .as_mut()
            .unwrap()
            .delete_delegator(&validator.validator_id, &delegator.delegator_id);
        state
            .delegations
            .remove_virtual_delegation(&validator.validator_id, &delegator.delegator_id);
        assert_eq!(
            state.state_commitment_v2_root(height),
            StateCommitmentV2::from_state(&state, height).root()
        );
        assert_eq!(
            state.state_commitment_v2_root(height),
            legacy_state_commitment_v2_root(&state, height)
        );
    }

    #[test]
    fn height_precise_bond_incremental_root_matches_rebuild_before_and_after_unstake() {
        let height = 100;
        let bond_id = id(0xE4);
        let mut precise = bond(bond_id, id(0xE5), id(0xE5));
        precise.unbonding_start_height = None;
        let mut state = ChainState::new_genesis();
        state.staked_bonds.insert(bond_id, precise.clone());
        state.rebuild_state_commitment_v2(height);
        assert_eq!(
            state.state_commitment_v2_root(height),
            StateCommitmentV2::from_state(&state, height).root()
        );

        precise
            .begin_unbonding(height, UNBONDING_PERIOD_EPOCHS)
            .unwrap();
        state.staked_bonds.insert(bond_id, precise.clone());
        state
            .state_commitment_v2
            .as_mut()
            .unwrap()
            .put_staked_bond(&bond_id, &precise);
        assert_eq!(
            state.state_commitment_v2_root(height),
            StateCommitmentV2::from_state(&state, height).root()
        );
    }

    #[test]
    fn state_commitment_v2_persistent_tree_matches_legacy_oracle_roots() {
        for size in [0usize, 1, 17, 257] {
            let height = u64::MAX;
            let mut state = synthetic_delegation_state(size, height);
            state.rebuild_state_commitment_v2(height);
            assert_eq!(
                state.state_commitment_v2_root(height),
                legacy_state_commitment_v2_root(&state, height),
                "persistent StateCommitmentV2 root diverged from legacy compressed oracle at size {size}"
            );
        }
    }

    #[test]
    fn state_commitment_v2_rebuild_after_decode_is_deterministic() {
        let height = u64::MAX;
        let mut state = ChainState::new_genesis();
        let validator = validator(0x77);
        state.validators.upsert(validator).unwrap();
        state.finalize_genesis().unwrap();
        state.rebuild_state_commitment_v2(height);
        let root_before = state.state_commitment_v2_root(height);

        let encoded = state.encode_to_vec();
        let mut reader = indra_core::codec::ByteReader::new(&encoded);
        let decoded = ChainState::decode(&mut reader).unwrap();
        assert!(decoded.state_commitment_v2.is_none());
        assert_eq!(decoded.state_commitment_v2_root(height), root_before);
    }

    #[test]
    #[ignore = "synthetic StateCommitmentV2 scale benchmark; run explicitly with --ignored --nocapture"]
    fn state_commitment_v2_synthetic_benchmark() {
        let sizes = std::env::var("INDRA_STATE_COMMITMENT_BENCH_SIZES")
            .unwrap_or_else(|_| "100000".to_string())
            .split(',')
            .filter_map(|part| part.trim().parse::<usize>().ok())
            .collect::<Vec<_>>();
        let height = u64::MAX;

        eprintln!(
            "[state-commitment-v2-bench] old full-root baselines from Step 0: 100k≈107ms, 1M≈1.03s, 5M≈5.19s"
        );

        for size in sizes {
            let mut state = synthetic_delegation_state(size, height);
            let validator_id = state
                .validators
                .all_validators()
                .next()
                .unwrap()
                .validator_id;

            let init_start = Instant::now();
            state.rebuild_state_commitment_v2(height);
            let init = init_start.elapsed();
            assert_eq!(
                state.state_commitment_v2_root(height),
                legacy_state_commitment_v2_root(&state, height)
            );

            let first_delegator_id = state
                .delegations
                .get_delegators(&validator_id)
                .first()
                .unwrap()
                .delegator_id;
            let updated = state
                .delegations
                .update_delegator(&validator_id, &first_delegator_id, |entry| {
                    entry.pending_rewards = entry.pending_rewards.saturating_add(1);
                    entry.clone()
                })
                .unwrap();
            let update_start = Instant::now();
            state
                .state_commitment_v2
                .as_mut()
                .unwrap()
                .put_delegator(&validator_id, &updated);
            let update = update_start.elapsed();

            let root_start = Instant::now();
            let mut root = Bytes32::ZERO;
            for _ in 0..1_000 {
                root = state.state_commitment_v2_root(height);
            }
            let root_reads = root_start.elapsed();

            eprintln!(
                "[state-commitment-v2-bench] delegators={size} init={:?} single_update={:?} root_read_avg={:?} root={}",
                init,
                update,
                root_reads / 1_000,
                hex::encode(root.0)
            );
        }
    }

    #[test]
    #[ignore = "release-mode StateCommitmentV2 tree-clone benchmark; run with --release --ignored --nocapture"]
    fn state_commitment_v2_persistent_tree_clone_benchmark() {
        let sizes = std::env::var("INDRA_STATE_COMMITMENT_V2_CLONE_BENCH_SIZES")
            .unwrap_or_else(|_| "100000,1000000,10000000".to_string())
            .split(',')
            .filter_map(|part| part.trim().parse::<usize>().ok())
            .collect::<Vec<_>>();
        let height = u64::MAX;

        for size in sizes {
            let legacy_build_start = Instant::now();
            let legacy_tree =
                CompressedAuthTree::from_pairs(synthetic_commitment_leaves(size, height)).unwrap();
            let legacy_build = legacy_build_start.elapsed();

            let persistent_build_start = Instant::now();
            let persistent_commitment = StateCommitmentV2 {
                tree: PersistentAuthTree::from_pairs(synthetic_commitment_leaves(size, height))
                    .unwrap(),
            };
            let persistent_build = persistent_build_start.elapsed();
            let persistent_root = persistent_commitment.root();
            assert_eq!(Bytes32::from(legacy_tree.root()), persistent_root);

            let legacy_clone_start = Instant::now();
            let legacy_clone = legacy_tree.clone();
            let legacy_clone_elapsed = legacy_clone_start.elapsed();
            assert_eq!(Bytes32::from(legacy_clone.root()), persistent_root);

            let persistent_clone_start = Instant::now();
            let persistent_clone = persistent_commitment.clone();
            let persistent_clone_elapsed = persistent_clone_start.elapsed();
            assert_eq!(persistent_clone.root(), persistent_root);

            println!(
                "stage2d_state_commitment_v2_clone delegators={size} legacy_build={legacy_build:?} persistent_build={persistent_build:?} legacy_compressed_tree_clone={legacy_clone_elapsed:?} persistent_auth_tree_clone={persistent_clone_elapsed:?}"
            );
        }
    }
}
