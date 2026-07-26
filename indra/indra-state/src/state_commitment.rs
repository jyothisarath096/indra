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
        crypto::HybridPubKey,
        primitives::{registered_validator_cap_active, validator_network_address_active, Bytes32},
    },
};
use indra_crypto::{sha256, PaymentPubKeyV1};

use crate::{
    persistent::PersistentAuthTree,
    validator::{DelegationReturnEvent, DelegatorEntry, StakeBondEntry, ValidatorEntry},
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
const DOMAIN_PAYMENT_IDENTITY: u8 = 0x08;

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
        for hash in &state.applied_slash_hashes {
            leaves.push((slash_hash_key(hash), slash_hash_value_hash(hash)));
        }
        for (delegator_id, pubkey) in &state.delegator_identities {
            leaves.push((
                delegator_identity_key(delegator_id),
                delegator_identity_value_hash(delegator_id, pubkey),
            ));
        }
        for (owner_id, pubkey) in &state.payment_identities {
            leaves.push((
                payment_identity_key(owner_id),
                payment_identity_value_hash(owner_id, pubkey),
            ));
        }
        if registered_validator_cap_active(height) {
            for event in &state.delegation_return_events {
                leaves.push((
                    delegation_return_event_key(event),
                    delegation_return_event_value_hash(event),
                ));
            }
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

    /// Insert or replace a payment identity-registry leaf.
    pub fn put_payment_identity(&mut self, owner_id: &Bytes32, pubkey: &PaymentPubKeyV1) {
        self.tree.insert(
            payment_identity_key(owner_id),
            payment_identity_value_hash(owner_id, pubkey),
        );
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

pub(crate) fn payment_identity_key(owner_id: &Bytes32) -> [u8; 32] {
    derive_key(DOMAIN_PAYMENT_IDENTITY, &owner_id.0)
}

fn derive_key(domain: u8, raw_key: &[u8]) -> [u8; 32] {
    let mut data = Vec::with_capacity(KEY_DOMAIN.len() + 1 + raw_key.len());
    data.extend_from_slice(KEY_DOMAIN);
    data.push(domain);
    data.extend_from_slice(raw_key);
    sha256(&data)
}

pub(crate) fn validator_value_hash(validator: &ValidatorEntry, height: u64) -> [u8; 32] {
    let include_network_addr = validator_network_address_active(height);
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

pub(crate) fn payment_identity_value_hash(
    owner_id: &Bytes32,
    pubkey: &PaymentPubKeyV1,
) -> [u8; 32] {
    let encoded_pubkey = pubkey.encode();
    let mut value = Vec::with_capacity(32 + encoded_pubkey.len());
    value.extend_from_slice(&owner_id.0);
    value.extend_from_slice(&encoded_pubkey);
    sha256(&value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::{
        codec::{Decode, Encode},
        types::{
            crypto::{CommitmentV1, HybridPubKey},
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
        ValidatorEntry {
            validator_id: id(byte),
            name: format!("validator-{byte}"),
            hybrid_classical_pk: Some([byte; 32]),
            hybrid_pq_pk: Some(vec![byte; 32]),
            vrf_pk: Some([byte.wrapping_add(1); 32]),
            stake_spark: 1_000_000 + byte as u64,
            status: crate::validator::ValidatorStatus::Registered,
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
            cold_hybrid_classical_pk: None,
            cold_hybrid_pq_pk: None,
            cold_key_version: 0,
            cold_key_status: crate::validator::ColdKeyStatus::Unenrolled,
            cold_nonce: 0,
        }
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
        for (owner_id, pubkey) in &state.payment_identities {
            leaves.push((
                payment_identity_key(owner_id),
                payment_identity_value_hash(owner_id, pubkey),
            ));
        }
        if registered_validator_cap_active(height) {
            for event in &state.delegation_return_events {
                leaves.push((
                    delegation_return_event_key(event),
                    delegation_return_event_value_hash(event),
                ));
            }
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
        if registered_validator_cap_active(height) {
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

    fn payment_pubkey(index: usize) -> PaymentPubKeyV1 {
        let mut x25519_sk = [0u8; 32];
        x25519_sk[0] = 0xA5;
        x25519_sk[8..16].copy_from_slice(&(index as u64).to_be_bytes());
        let mut ml_kem_1024_seed = [0u8; 64];
        ml_kem_1024_seed[0] = 0x5A;
        ml_kem_1024_seed[8..16].copy_from_slice(&(index as u64).to_be_bytes());
        indra_crypto::PaymentKeypairV1 {
            version: indra_crypto::PAYMENT_VERSION_V1,
            x25519_sk,
            ml_kem_1024_seed,
        }
        .public_key()
    }

    fn independent_payment_identity_key(owner_id: &Bytes32) -> [u8; 32] {
        let mut data = Vec::with_capacity(KEY_DOMAIN.len() + 1 + 32);
        data.extend_from_slice(KEY_DOMAIN);
        data.push(0x08);
        data.extend_from_slice(&owner_id.0);
        sha256(&data)
    }

    fn independent_payment_identity_value_hash(
        owner_id: &Bytes32,
        pubkey: &PaymentPubKeyV1,
    ) -> [u8; 32] {
        let encoded_pubkey = pubkey.encode();
        let mut value = Vec::with_capacity(32 + encoded_pubkey.len());
        value.extend_from_slice(&owner_id.0);
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
        cold.cold_key_status = crate::validator::ColdKeyStatus::Active;
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
    fn payment_identity_leaf_hashing_matches_documented_oracle_formula() {
        for byte in [0x01u8, 0x7F, 0xA5, 0xFE] {
            let owner_id = id(byte);
            let pubkey = payment_pubkey(byte as usize);
            assert_eq!(
                payment_identity_key(&owner_id),
                independent_payment_identity_key(&owner_id)
            );
            assert_eq!(
                payment_identity_value_hash(&owner_id, &pubkey),
                independent_payment_identity_value_hash(&owner_id, &pubkey)
            );
        }
    }

    #[test]
    fn payment_identity_incremental_updates_match_full_rebuild() {
        let height = u64::MAX;
        let mut state = ChainState::new_genesis();
        let mut incremental = StateCommitmentV2::from_state(&state, height);

        for index in 0..64usize {
            let owner_id = id(index as u8);
            let identity = payment_pubkey(index);
            state.payment_identities.insert(owner_id, identity.clone());
            incremental.put_payment_identity(&owner_id, &identity);
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
    fn payment_identity_leaves_are_root_sensitive_and_domain_separated() {
        let height = u64::MAX;
        let mut state = ChainState::new_genesis();
        state.rebuild_state_commitment_v2(height);
        let empty_root = state.state_commitment_v2_root(height);

        let owner_id = id(0x31);
        let identity = payment_pubkey(0x41);
        state.payment_identities.insert(owner_id, identity.clone());
        state
            .state_commitment_v2
            .as_mut()
            .unwrap()
            .put_payment_identity(&owner_id, &identity);
        let inserted_root = state.state_commitment_v2_root(height);
        assert_ne!(empty_root, inserted_root);

        let updated_identity = payment_pubkey(0x42);
        state
            .payment_identities
            .insert(owner_id, updated_identity.clone());
        state
            .state_commitment_v2
            .as_mut()
            .unwrap()
            .put_payment_identity(&owner_id, &updated_identity);
        assert_ne!(inserted_root, state.state_commitment_v2_root(height));

        let identity_key = payment_identity_key(&owner_id);
        assert_ne!(identity_key, validator_key(&owner_id));
        assert_ne!(identity_key, delegator_key(&owner_id, &owner_id));
        assert_ne!(identity_key, staking_nonce_key(&owner_id));
        assert_ne!(identity_key, staked_bond_key(&owner_id));
        assert_ne!(identity_key, slash_hash_key(&owner_id));
        assert_ne!(identity_key, delegator_identity_key(&owner_id));
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
    fn state_txn_rollback_rebuilds_payment_commitment_from_canonical_registry() {
        let height = u64::MAX;
        let mut state = ChainState::new_genesis();
        let existing_id = id(0x50);
        let existing_identity = payment_pubkey(0x51);
        state
            .payment_identities
            .insert(existing_id, existing_identity.clone());
        state.rebuild_state_commitment_v2(height);
        let baseline_root = state.state_commitment_v2_root(height);

        {
            let mut txn = crate::txn::StateTxn::begin(&mut state, height);
            txn.ensure_state_commitment_v2().unwrap();
            txn.snapshot_payment_identity_scope();
            let transient_id = id(0x60);
            let transient_identity = payment_pubkey(0x61);
            txn.state_mut()
                .payment_identities
                .insert(transient_id, transient_identity.clone());
            txn.state_mut()
                .state_commitment_v2
                .as_mut()
                .unwrap()
                .put_payment_identity(&transient_id, &transient_identity);
            assert_ne!(txn.state().state_commitment_v2_root(height), baseline_root);
        }

        assert_eq!(state.payment_identities.len(), 1);
        assert_eq!(
            state.payment_identities.get(&existing_id),
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
    fn empty_payment_identity_registry_preserves_pre_payment_root_with_unrelated_mutations() {
        let height = u64::MAX;
        let mut state = ChainState::new_genesis();
        let validator = validator(0x70);
        state.validators.upsert(validator.clone()).unwrap();
        state.staking_nonces.insert(id(0x71), 12);
        state.delegator_identities.insert(id(0x72), pubkey(0x73));
        assert!(state.payment_identities.is_empty());

        let pre_payment_root = legacy_state_commitment_v2_root(&state, height);
        let post_payment_structure_root = StateCommitmentV2::from_state(&state, height).root();
        assert_eq!(post_payment_structure_root, pre_payment_root);

        state.delegator_identities.insert(id(0x74), pubkey(0x75));
        assert_eq!(
            StateCommitmentV2::from_state(&state, height).root(),
            legacy_state_commitment_v2_root(&state, height)
        );
        assert!(state.payment_identities.is_empty());
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
            ("payment_identity", DOMAIN_PAYMENT_IDENTITY),
        ];
        let mut seen = std::collections::BTreeMap::new();
        for (name, domain) in domains {
            assert_eq!(
                seen.insert(domain, name),
                None,
                "StateCommitmentV2 domain byte collision at 0x{domain:02x}"
            );
        }
        assert_eq!(DOMAIN_PAYMENT_IDENTITY, 0x08);
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

        let payment_id = id(0x88);
        let payment_pubkey = payment_pubkey(0x89);
        state
            .payment_identities
            .insert(payment_id, payment_pubkey.clone());
        state
            .state_commitment_v2
            .as_mut()
            .unwrap()
            .put_payment_identity(&payment_id, &payment_pubkey);
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
