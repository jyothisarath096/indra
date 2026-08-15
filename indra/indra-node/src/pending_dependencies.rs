//! Rebuildable reverse dependency indexes for pending operations.

use std::collections::{BTreeMap, BTreeSet};

use indra_core::{
    codec::Encode,
    types::{
        governance::{GovernanceOpV2, GovernancePayload},
        stake_position::{derive_position_id, PositionCustodyV1},
        staking::{StakingOp, StakingOpBody},
    },
    Bytes32,
};
use indra_state::ChainState;

/// A canonical state dependency that can invalidate pending work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum DependencyKey {
    Utxo(Bytes32),
    BaseFee,
    NextHeight,
    StakingNonce(Bytes32),
    GovernanceNonce(Bytes32),
    Validator(Bytes32),
    ValidatorRegistry,
    ValidatorKey(Bytes32),
    RetiredColdComponent(Bytes32),
    DelegatorIdentity(Bytes32),
    StakePosition(Bytes32),
    ValidatorPositionCapacity(Bytes32),
    GlobalPositionCapacity,
    PositionTrancheCapacity(Bytes32),
    ValidatorTrancheCapacity(Bytes32),
    GlobalTrancheCapacity,
    PendingPositionSlot(Bytes32),
    PendingGlobalPositionSlot,
    PendingTrancheSlot(Bytes32),
    PendingValidatorTrancheSlot(Bytes32),
    PendingGlobalTrancheSlot,
    PendingValidatorFinalExitSlot(Bytes32),
    PendingGlobalFinalExitSlot,
    Tombstone(Bytes32),
    TombstoneRegistry,
    Proposal(Bytes32),
    ActiveProposalCount,
    ProposerProposalCount(Bytes32),
    GovernanceActionTarget(Bytes32),
    GovernanceParam(u8),
    SlashAuthorityAtHeight(u64),
    EpochDeadline(u64, u8),
}

/// A bidirectional, atomically maintained pending-entry dependency index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct DependencyIndex {
    by_key: BTreeMap<DependencyKey, BTreeSet<Bytes32>>,
    by_entry: BTreeMap<Bytes32, BTreeSet<DependencyKey>>,
}

impl DependencyIndex {
    pub(crate) fn len(&self) -> usize {
        self.by_entry.len()
    }

    pub(crate) fn contains_key(&self, key: DependencyKey) -> bool {
        self.by_key.get(&key).is_some_and(|ids| !ids.is_empty())
    }
    pub(crate) fn insert(&mut self, id: Bytes32, footprint: BTreeSet<DependencyKey>) {
        self.remove(&id);
        for key in &footprint {
            self.by_key.entry(*key).or_default().insert(id);
        }
        self.by_entry.insert(id, footprint);
    }

    pub(crate) fn remove(&mut self, id: &Bytes32) {
        let Some(keys) = self.by_entry.remove(id) else {
            return;
        };
        for key in keys {
            if let Some(ids) = self.by_key.get_mut(&key) {
                ids.remove(id);
                if ids.is_empty() {
                    self.by_key.remove(&key);
                }
            }
        }
    }

    pub(crate) fn affected(
        &self,
        keys: impl IntoIterator<Item = DependencyKey>,
    ) -> BTreeSet<Bytes32> {
        keys.into_iter()
            .filter_map(|key| self.by_key.get(&key))
            .flat_map(|ids| ids.iter().copied())
            .collect()
    }

    pub(crate) fn assert_reconstructed(
        &self,
        entries: impl IntoIterator<Item = (Bytes32, BTreeSet<DependencyKey>)>,
    ) {
        #[cfg(not(debug_assertions))]
        let _ = entries;
        #[cfg(debug_assertions)]
        {
            let mut rebuilt = Self::default();
            for (id, footprint) in entries {
                rebuilt.insert(id, footprint);
            }
            debug_assert_eq!(self, &rebuilt);
        }
    }
}

fn component_key(tag: u8, bytes: &[u8]) -> Bytes32 {
    let mut material = Vec::with_capacity(bytes.len() + 1);
    material.push(tag);
    material.extend_from_slice(bytes);
    Bytes32::from(indra_crypto::sha256(&material))
}

fn all_governance_params(keys: &mut BTreeSet<DependencyKey>) {
    keys.extend((0..10).map(DependencyKey::GovernanceParam));
}

pub(crate) fn staking_footprint(
    state: &ChainState,
    op: &StakingOp,
    current_epoch: u64,
) -> BTreeSet<DependencyKey> {
    let signer = op.signer_id();
    let mut keys = BTreeSet::from([
        DependencyKey::StakingNonce(signer),
        DependencyKey::Validator(signer),
        DependencyKey::DelegatorIdentity(signer),
        DependencyKey::EpochDeadline(current_epoch.saturating_add(1), 0),
    ]);
    match &op.body {
        StakingOpBody::Delegate {
            validator_id,
            deposit_utxo_id,
            ..
        } => {
            let position = derive_position_id(
                *validator_id,
                signer,
                PositionCustodyV1::DelegatorIdentity {
                    delegator_id: signer,
                },
            );
            keys.extend([
                DependencyKey::Utxo(*deposit_utxo_id),
                DependencyKey::Validator(*validator_id),
                DependencyKey::GovernanceParam(1),
                DependencyKey::StakePosition(position),
                DependencyKey::ValidatorPositionCapacity(*validator_id),
                DependencyKey::GlobalPositionCapacity,
                DependencyKey::PositionTrancheCapacity(position),
                DependencyKey::ValidatorTrancheCapacity(*validator_id),
                DependencyKey::GlobalTrancheCapacity,
            ]);
            if state.stake_positions.get(&position).is_none() {
                keys.extend([
                    DependencyKey::PendingPositionSlot(*validator_id),
                    DependencyKey::PendingGlobalPositionSlot,
                    DependencyKey::PendingValidatorFinalExitSlot(*validator_id),
                    DependencyKey::PendingGlobalFinalExitSlot,
                ]);
            }
        }
        StakingOpBody::SelfStake {
            deposit_utxo_id,
            validator_pubkey,
            ..
        } => {
            let validator = validator_pubkey.identity_id();
            let position = derive_position_id(
                validator,
                validator,
                PositionCustodyV1::ValidatorColdIdentity {
                    validator_id: validator,
                },
            );
            keys.extend([
                DependencyKey::Utxo(*deposit_utxo_id),
                DependencyKey::Validator(validator),
                DependencyKey::DelegatorIdentity(validator),
                DependencyKey::StakePosition(position),
                DependencyKey::ValidatorPositionCapacity(validator),
                DependencyKey::GlobalPositionCapacity,
                DependencyKey::PositionTrancheCapacity(position),
                DependencyKey::ValidatorTrancheCapacity(validator),
                DependencyKey::GlobalTrancheCapacity,
            ]);
            if state.stake_positions.get(&position).is_none() {
                keys.extend([
                    DependencyKey::PendingPositionSlot(validator),
                    DependencyKey::PendingGlobalPositionSlot,
                    DependencyKey::PendingValidatorFinalExitSlot(validator),
                    DependencyKey::PendingGlobalFinalExitSlot,
                ]);
            }
        }
        StakingOpBody::ExitStakePosition {
            position_id,
            amount_spark,
            ..
        } => {
            keys.extend([
                DependencyKey::StakePosition(*position_id),
                DependencyKey::PositionTrancheCapacity(*position_id),
                DependencyKey::GlobalTrancheCapacity,
                DependencyKey::NextHeight,
            ]);
            if let Some(position) = state.stake_positions.get(position_id) {
                keys.extend([
                    DependencyKey::Validator(position.validator_id),
                    DependencyKey::ValidatorTrancheCapacity(position.validator_id),
                    DependencyKey::PendingTrancheSlot(*position_id),
                    DependencyKey::PendingValidatorTrancheSlot(position.validator_id),
                    DependencyKey::PendingGlobalTrancheSlot,
                ]);
                if position
                    .active
                    .is_some_and(|active| active.principal_spark != *amount_spark)
                {
                    keys.extend([
                        DependencyKey::PendingValidatorFinalExitSlot(position.validator_id),
                        DependencyKey::PendingGlobalFinalExitSlot,
                    ]);
                }
            }
        }
        StakingOpBody::ClaimRewards { validator_id, .. } => {
            let custody = if *validator_id == signer {
                PositionCustodyV1::ValidatorColdIdentity {
                    validator_id: signer,
                }
            } else {
                PositionCustodyV1::DelegatorIdentity {
                    delegator_id: signer,
                }
            };
            keys.extend([
                DependencyKey::Validator(*validator_id),
                DependencyKey::StakePosition(derive_position_id(*validator_id, signer, custody)),
                DependencyKey::NextHeight,
            ]);
        }
        StakingOpBody::RegisterValidator {
            validator_pubkey,
            vrf_pk,
            deposit_utxo_id,
            cold_pubkey,
            ..
        } => {
            let validator = validator_pubkey.identity_id();
            keys.extend([
                DependencyKey::GovernanceParam(6),
                DependencyKey::Validator(validator),
                DependencyKey::Tombstone(validator),
                DependencyKey::TombstoneRegistry,
                DependencyKey::ValidatorRegistry,
                DependencyKey::Utxo(*deposit_utxo_id),
                DependencyKey::GlobalPositionCapacity,
                DependencyKey::GlobalTrancheCapacity,
                DependencyKey::ValidatorKey(component_key(0, &validator_pubkey.classical_pk.0)),
                DependencyKey::ValidatorKey(component_key(1, validator_pubkey.pq_pk.as_slice())),
                DependencyKey::ValidatorKey(component_key(4, vrf_pk)),
                DependencyKey::RetiredColdComponent(component_key(
                    0,
                    &validator_pubkey.classical_pk.0,
                )),
                DependencyKey::RetiredColdComponent(component_key(
                    1,
                    validator_pubkey.pq_pk.as_slice(),
                )),
            ]);
            let position = derive_position_id(
                validator,
                validator,
                PositionCustodyV1::ValidatorColdIdentity {
                    validator_id: validator,
                },
            );
            if state.stake_positions.get(&position).is_none() {
                keys.extend([
                    DependencyKey::StakePosition(position),
                    DependencyKey::ValidatorPositionCapacity(validator),
                    DependencyKey::PendingPositionSlot(validator),
                    DependencyKey::PendingGlobalPositionSlot,
                    DependencyKey::PendingValidatorFinalExitSlot(validator),
                    DependencyKey::PendingGlobalFinalExitSlot,
                ]);
            }
            keys.extend([
                DependencyKey::ValidatorKey(component_key(2, &cold_pubkey.classical_pk.0)),
                DependencyKey::ValidatorKey(component_key(3, cold_pubkey.pq_pk.as_slice())),
                DependencyKey::RetiredColdComponent(component_key(2, &cold_pubkey.classical_pk.0)),
                DependencyKey::RetiredColdComponent(component_key(3, cold_pubkey.pq_pk.as_slice())),
            ]);
        }
        StakingOpBody::RotateValidatorColdKey {
            validator_id,
            new_cold_pubkey,
            ..
        } => {
            keys.extend([
                DependencyKey::Validator(*validator_id),
                DependencyKey::ValidatorRegistry,
                DependencyKey::ValidatorKey(component_key(2, &new_cold_pubkey.classical_pk.0)),
                DependencyKey::ValidatorKey(component_key(3, new_cold_pubkey.pq_pk.as_slice())),
                DependencyKey::RetiredColdComponent(component_key(
                    2,
                    &new_cold_pubkey.classical_pk.0,
                )),
                DependencyKey::RetiredColdComponent(component_key(
                    3,
                    new_cold_pubkey.pq_pk.as_slice(),
                )),
            ]);
        }
        StakingOpBody::SetCommission { validator_id, .. } => {
            keys.extend([
                DependencyKey::Validator(*validator_id),
                DependencyKey::GovernanceParam(6),
            ]);
        }
        StakingOpBody::SetAutoDelegate {
            validator_id,
            target_validator_id,
            ..
        } => {
            keys.insert(DependencyKey::Validator(*validator_id));
            if *target_validator_id != Bytes32::ZERO {
                keys.insert(DependencyKey::Validator(*target_validator_id));
            }
        }
        StakingOpBody::UpdateNetworkAddress { validator_id, .. } => {
            keys.extend([
                DependencyKey::Validator(*validator_id),
                DependencyKey::EpochDeadline(current_epoch.saturating_add(1), 1),
            ]);
        }
        StakingOpBody::RegisterVrfKey {
            validator_id,
            activation_epoch_id,
            ..
        } => {
            keys.extend([
                DependencyKey::Validator(*validator_id),
                DependencyKey::EpochDeadline(*activation_epoch_id, 2),
            ]);
        }
    }
    keys
}

pub(crate) fn governance_footprint(
    op: &GovernanceOpV2,
    current_epoch: u64,
) -> BTreeSet<DependencyKey> {
    let mut keys = BTreeSet::from([
        DependencyKey::GovernanceNonce(op.signer_id),
        DependencyKey::Validator(op.signer_id),
        DependencyKey::DelegatorIdentity(op.signer_id),
        DependencyKey::EpochDeadline(current_epoch.saturating_add(1), 2),
    ]);
    match &op.payload {
        GovernancePayload::Propose {
            action,
            deposit_utxo_id,
            ..
        } => {
            keys.extend([
                DependencyKey::Utxo(*deposit_utxo_id),
                DependencyKey::ActiveProposalCount,
                DependencyKey::ProposerProposalCount(op.signer_id),
                DependencyKey::GovernanceActionTarget(component_key(5, &action.encode_to_vec())),
                DependencyKey::NextHeight,
            ]);
            all_governance_params(&mut keys);
        }
        GovernancePayload::Commit { proposal_id, .. }
        | GovernancePayload::Reveal { proposal_id, .. }
        | GovernancePayload::Cancel { proposal_id, .. } => {
            keys.insert(DependencyKey::Proposal(*proposal_id));
        }
        GovernancePayload::Redelegate {
            proposal_id,
            from_validator,
            to_validator,
            ..
        } => {
            keys.extend([
                DependencyKey::Proposal(*proposal_id),
                DependencyKey::Validator(*from_validator),
                DependencyKey::Validator(*to_validator),
                DependencyKey::StakePosition(derive_position_id(
                    *from_validator,
                    op.signer_id,
                    PositionCustodyV1::DelegatorIdentity {
                        delegator_id: op.signer_id,
                    },
                )),
            ]);
        }
        GovernancePayload::Execute { proposal_id } => {
            keys.extend([
                DependencyKey::Proposal(*proposal_id),
                DependencyKey::NextHeight,
            ]);
            all_governance_params(&mut keys);
        }
    }
    keys
}

pub(crate) fn slash_footprint(
    state: &ChainState,
    evidence: &indra_core::types::slashing::SlashEvidenceV2,
    current_epoch: u64,
) -> BTreeSet<DependencyKey> {
    let mut keys = BTreeSet::from([
        DependencyKey::SlashAuthorityAtHeight(evidence.vote_1.height),
        DependencyKey::Validator(evidence.validator_id),
        DependencyKey::Tombstone(evidence.validator_id),
        DependencyKey::ValidatorPositionCapacity(evidence.validator_id),
        DependencyKey::ValidatorTrancheCapacity(evidence.validator_id),
        DependencyKey::GlobalTrancheCapacity,
        DependencyKey::GovernanceParam(4),
        DependencyKey::EpochDeadline(current_epoch.saturating_add(1), 3),
    ]);
    for (position_id, position) in state.stake_positions.iter() {
        if position.validator_id == evidence.validator_id {
            keys.extend([
                DependencyKey::StakePosition(*position_id),
                DependencyKey::PositionTrancheCapacity(*position_id),
            ]);
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::{
        crypto::{ColdHybridPubKey, HybridSignature},
        governance::{GovernableAction, GovernanceActionType},
        stake_position::{ActiveStakeAggregateV1, StakePositionV1},
        staking::ColdStakingAuthorization,
    };
    use indra_core::VariableBytes;

    fn signature() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0; 4627]).unwrap(),
        }
    }

    fn pubkey(seed: u8) -> indra_core::HybridPubKey {
        indra_core::HybridPubKey {
            classical_pk: Bytes32::from([seed; 32]),
            pq_pk: VariableBytes::from_slice(&[seed; 2592]).unwrap(),
        }
    }

    fn staking(body: StakingOpBody) -> StakingOp {
        StakingOp {
            body,
            nonce: 1,
            signature: signature(),
        }
    }

    fn governance(signer_id: Bytes32, payload: GovernancePayload) -> GovernanceOpV2 {
        GovernanceOpV2 {
            action_type: payload.action_type(),
            signer_id,
            nonce: 1,
            payload,
            signature: signature(),
        }
    }

    #[test]
    fn reverse_index_survives_deterministic_insert_replace_evict_sequence() {
        let mut index = DependencyIndex::default();
        let a = Bytes32::from([1; 32]);
        let b = Bytes32::from([2; 32]);
        let u = Bytes32::from([3; 32]);
        let v = Bytes32::from([4; 32]);

        index.insert(
            a,
            BTreeSet::from([DependencyKey::Utxo(u), DependencyKey::BaseFee]),
        );
        index.insert(
            b,
            BTreeSet::from([DependencyKey::Utxo(u), DependencyKey::Validator(v)]),
        );
        assert_eq!(
            index.affected([DependencyKey::Utxo(u)]),
            BTreeSet::from([a, b])
        );

        index.insert(a, BTreeSet::from([DependencyKey::Utxo(v)]));
        assert_eq!(
            index.affected([DependencyKey::Utxo(u)]),
            BTreeSet::from([b])
        );
        assert_eq!(
            index.affected([DependencyKey::Utxo(v)]),
            BTreeSet::from([a])
        );

        index.remove(&b);
        index.assert_reconstructed([(a, BTreeSet::from([DependencyKey::Utxo(v)]))]);
    }

    #[test]
    fn every_staking_and_governance_variant_has_its_required_dependency_families() {
        let mut state = ChainState::new_genesis();
        let signer = Bytes32::from([0x11; 32]);
        let validator = Bytes32::from([0x22; 32]);
        let position = StakePositionV1::new(
            validator,
            signer,
            PositionCustodyV1::DelegatorIdentity {
                delegator_id: signer,
            },
            Some(ActiveStakeAggregateV1::new(1_000_000, 0, 0).unwrap()),
            1,
            0,
        )
        .unwrap();
        let position_id = position.position_id;
        state.stake_positions.insert(position_id, position);
        let deposit = Bytes32::from([0x33; 32]);
        let cold = ColdHybridPubKey {
            classical_pk: Bytes32::from([0x44; 32]),
            pq_pk: VariableBytes::from_slice(&[0x44; 2592]).unwrap(),
        };
        let cold_auth = Some(ColdStakingAuthorization {
            cold_key_version: 1,
            cold_nonce: 1,
        });

        let staking_cases = [
            staking(StakingOpBody::Delegate {
                validator_id: validator,
                deposit_utxo_id: deposit,
                delegator_pubkey: pubkey(0x11),
            }),
            staking(StakingOpBody::SelfStake {
                deposit_utxo_id: deposit,
                validator_pubkey: pubkey(0x12),
                cold_authorization: cold_auth,
            }),
            staking(StakingOpBody::ExitStakePosition {
                position_id,
                amount_spark: 500_000,
                custody: PositionCustodyV1::DelegatorIdentity {
                    delegator_id: signer,
                },
                cold_authorization: None,
            }),
            staking(StakingOpBody::ClaimRewards {
                validator_id: validator,
                delegator_pubkey: pubkey(0x11),
                cold_authorization: None,
            }),
            staking(StakingOpBody::RegisterValidator {
                commission_bps: 1_000,
                deposit_utxo_id: deposit,
                validator_pubkey: pubkey(0x13),
                vrf_pk: [0x55; 32],
                cold_pubkey: cold.clone(),
                cold_signature: signature(),
            }),
            staking(StakingOpBody::RotateValidatorColdKey {
                validator_id: validator,
                current_cold_key_version: 1,
                new_cold_key_version: 2,
                current_cold_nonce: 1,
                new_cold_pubkey: cold,
                new_cold_signature: None,
            }),
            staking(StakingOpBody::SetCommission {
                validator_id: validator,
                new_commission_bps: 1_000,
                cold_authorization: cold_auth,
            }),
            staking(StakingOpBody::SetAutoDelegate {
                validator_id: signer,
                target_validator_id: validator,
                cold_authorization: cold_auth,
            }),
            staking(StakingOpBody::UpdateNetworkAddress {
                validator_id: signer,
                network_addr: Some("127.0.0.1:9000".into()),
            }),
        ];
        let footprints: Vec<_> = staking_cases
            .iter()
            .map(|op| staking_footprint(&state, op, 7))
            .collect();
        assert!(footprints[0].contains(&DependencyKey::Utxo(deposit)));
        assert!(footprints[0].contains(&DependencyKey::GlobalPositionCapacity));
        assert!(footprints[1]
            .iter()
            .any(|key| matches!(key, DependencyKey::StakePosition(_))));
        assert!(footprints[2].contains(&DependencyKey::PendingTrancheSlot(position_id)));
        assert!(footprints[2].contains(&DependencyKey::PendingGlobalFinalExitSlot));
        assert!(footprints[3].contains(&DependencyKey::NextHeight));
        assert!(footprints[4].contains(&DependencyKey::ValidatorRegistry));
        assert!(footprints[4].contains(&DependencyKey::TombstoneRegistry));
        assert!(footprints[4]
            .iter()
            .any(|key| matches!(key, DependencyKey::ValidatorKey(_))));
        assert!(footprints[5].contains(&DependencyKey::ValidatorRegistry));
        assert!(footprints[5]
            .iter()
            .any(|key| matches!(key, DependencyKey::RetiredColdComponent(_))));
        assert!(footprints[6].contains(&DependencyKey::GovernanceParam(6)));
        assert!(footprints[7].contains(&DependencyKey::Validator(validator)));
        assert!(footprints[8].contains(&DependencyKey::EpochDeadline(8, 1)));
        assert!(footprints.iter().all(|keys| keys
            .iter()
            .any(|key| matches!(key, DependencyKey::StakingNonce(_)))));

        let proposal = Bytes32::from([0x66; 32]);
        let governance_cases = [
            governance(
                signer,
                GovernancePayload::Propose {
                    action: GovernableAction::SetMinDelegationSpark { value: 1 },
                    deposit_utxo_id: deposit,
                    proposer_pubkey: pubkey(0x11),
                    title: VariableBytes::from_slice(b"t").unwrap(),
                    description: VariableBytes::from_slice(b"d").unwrap(),
                    cold_authorization: None,
                },
            ),
            governance(
                signer,
                GovernancePayload::Commit {
                    proposal_id: proposal,
                    commit_hash: Bytes32::from([0x77; 32]),
                    cold_authorization: None,
                },
            ),
            governance(
                signer,
                GovernancePayload::Reveal {
                    proposal_id: proposal,
                    vote: 1,
                    nonce: Bytes32::from([0x88; 32]),
                    cold_authorization: None,
                },
            ),
            governance(
                signer,
                GovernancePayload::Redelegate {
                    proposal_id: proposal,
                    from_validator: validator,
                    to_validator: Bytes32::from([0x99; 32]),
                    amount_spark: 1,
                },
            ),
            governance(
                signer,
                GovernancePayload::Execute {
                    proposal_id: proposal,
                },
            ),
            governance(
                signer,
                GovernancePayload::Cancel {
                    proposal_id: proposal,
                    cold_authorization: None,
                },
            ),
        ];
        assert_eq!(
            governance_cases
                .iter()
                .map(|op| op.action_type)
                .collect::<Vec<_>>(),
            vec![
                GovernanceActionType::ProposeChange,
                GovernanceActionType::CommitVote,
                GovernanceActionType::RevealVote,
                GovernanceActionType::GovernanceRedelegate,
                GovernanceActionType::ExecuteProposal,
                GovernanceActionType::CancelProposal,
            ]
        );
        let footprints: Vec<_> = governance_cases
            .iter()
            .map(|op| governance_footprint(op, 7))
            .collect();
        assert!(footprints[0].contains(&DependencyKey::ActiveProposalCount));
        assert_eq!(
            footprints[0]
                .iter()
                .filter(|key| matches!(key, DependencyKey::GovernanceParam(_)))
                .count(),
            10
        );
        assert!(footprints[1].contains(&DependencyKey::Proposal(proposal)));
        assert!(footprints[2].contains(&DependencyKey::Proposal(proposal)));
        assert!(footprints[3].contains(&DependencyKey::Validator(validator)));
        assert!(footprints[3]
            .iter()
            .any(|key| matches!(key, DependencyKey::StakePosition(_))));
        assert!(footprints[4].contains(&DependencyKey::NextHeight));
        assert_eq!(
            footprints[4]
                .iter()
                .filter(|key| matches!(key, DependencyKey::GovernanceParam(_)))
                .count(),
            10
        );
        assert!(footprints[5].contains(&DependencyKey::Proposal(proposal)));
        assert!(footprints.iter().all(|keys| keys
            .iter()
            .any(|key| matches!(key, DependencyKey::GovernanceNonce(_)))));
    }
}
