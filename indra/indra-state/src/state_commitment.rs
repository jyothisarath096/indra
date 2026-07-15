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
    types::primitives::{
        registered_validator_cap_active, validator_network_address_active, Bytes32,
    },
};
use indra_crypto::sha256;

use crate::{
    smt::SparseMerkleTree,
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

/// Incremental sparse-Merkle commitment to validator/delegation/staking state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StateCommitmentV2 {
    tree: SparseMerkleTree,
}

impl StateCommitmentV2 {
    /// Build a V2 commitment deterministically from canonical chain state.
    pub fn from_state(state: &ChainState, height: u64) -> Self {
        let mut commitment = Self::default();
        for validator in state.validators.all_validators() {
            commitment.put_validator(validator, height);
        }
        for (validator_id, delegators) in state.delegations.all_delegators() {
            for delegator in delegators {
                commitment.put_delegator(validator_id, delegator);
            }
        }
        for (signer_id, nonce) in &state.staking_nonces {
            commitment.put_staking_nonce(signer_id, *nonce);
        }
        for (utxo_id, bond) in &state.staked_bonds {
            commitment.put_staked_bond(utxo_id, bond);
        }
        for hash in &state.applied_slash_hashes {
            commitment.put_slash_hash(hash);
        }
        if registered_validator_cap_active(height) {
            for event in &state.delegation_return_events {
                commitment.put_delegation_return_event(event);
            }
        }
        commitment
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
            original_output: output(0xAA, 7_000),
        }
    }

    #[test]
    fn state_commitment_v2_incremental_matches_rebuild_after_each_category() {
        let height = u64::MAX;
        let mut state = ChainState::new_genesis();
        state.rebuild_state_commitment_v2(height);

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
        use std::time::Instant;

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
                        pending_rewards: 0,
                        rewards_last_epoch: 0,
                        unbonding_end_epoch: None,
                    },
                );
            }

            let init_start = Instant::now();
            state.rebuild_state_commitment_v2(height);
            let init = init_start.elapsed();

            let updated = {
                let entry = state
                    .delegations
                    .get_delegators_mut(&validator_id)
                    .and_then(|entries| entries.first_mut())
                    .unwrap();
                entry.pending_rewards = entry.pending_rewards.saturating_add(1);
                entry.clone()
            };
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
}
