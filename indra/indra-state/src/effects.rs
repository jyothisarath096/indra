//! Canonical state effects published only by committed state transactions.

use std::collections::BTreeSet;

use indra_core::Bytes32;

/// Key-level mutation journal for one successfully committed block/state transaction.
///
/// This is node-local metadata, not consensus-encoded state. Conservative global
/// flags are intentional: they let pending-pool invalidation remain correct when
/// an operation depends on collection-wide capacity or uniqueness.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CanonicalStateEffects {
    /// Canonical height changed.
    pub height_changed: bool,
    /// Canonical tip hash changed.
    pub tip_hash_changed: bool,
    /// Canonical UTXOs consumed by the committed transition.
    pub spent_utxos: BTreeSet<Bytes32>,
    /// Whether the resident UTXO namespace changed in any way.
    pub utxo_set_changed: bool,
    /// Whether the transaction fee floor changed.
    pub base_fee_changed: bool,
    /// Supply/reward accounting scalars changed.
    pub economic_accounting_changed: bool,
    /// Signers whose canonical staking nonce changed.
    pub staking_nonces_changed: BTreeSet<Bytes32>,
    /// Signers whose canonical governance nonce changed.
    pub governance_nonces_changed: BTreeSet<Bytes32>,
    /// Validators whose canonical entry changed.
    pub validators_changed: BTreeSet<Bytes32>,
    /// Whether any collection-wide validator-registry property changed.
    pub validator_registry_changed: bool,
    /// Validators whose hot or cold authority material changed.
    pub validator_keys_changed: BTreeSet<Bytes32>,
    /// Delegator identities inserted or changed.
    pub delegator_identities_changed: BTreeSet<Bytes32>,
    /// Canonical staking positions inserted, changed, or deleted.
    pub stake_positions_changed: BTreeSet<Bytes32>,
    /// Whether a global position/tranche capacity counter changed.
    pub global_position_tranche_capacity_changed: bool,
    /// Validators whose position counts changed.
    pub validator_position_capacity_changed: BTreeSet<Bytes32>,
    /// Positions whose tranche counts changed.
    pub position_tranche_capacity_changed_for: BTreeSet<Bytes32>,
    /// Validators whose tranche counts changed.
    pub validator_tranche_capacity_changed: BTreeSet<Bytes32>,
    /// Evicted-validator tombstones inserted, changed, or deleted.
    pub tombstones_changed: BTreeSet<Bytes32>,
    /// Whether either permanently-retired cold-component set changed.
    pub retired_cold_components_changed: bool,
    /// Governance proposals inserted, changed, or deleted.
    pub proposals_changed: BTreeSet<Bytes32>,
    /// Whether any governable parameter changed.
    pub governance_params_changed: bool,
    /// Whether any canonical governance state changed.
    pub governance_state_changed: bool,
    /// Slash evidence hashes newly recorded as applied.
    pub applied_slash_hashes: BTreeSet<Bytes32>,
    /// Whether retained historical slash authority changed.
    pub slash_membership_history_changed: bool,
    /// Consensus-authority snapshots rotated.
    pub consensus_snapshots_changed: bool,
    /// Epoch reward-economic snapshot changed.
    pub reward_economic_snapshot_changed: bool,
    /// A derived position-to-tranche index changed with its canonical maps.
    pub position_tranche_index_changed: bool,
    /// The derived state-commitment cache changed.
    pub state_commitment_cache_changed: bool,
    /// Transient epoch summary counters changed.
    pub epoch_summary_changed: bool,
    /// Whether the transition crossed an epoch boundary.
    pub epoch_changed: bool,
    /// Slash transitions that actually committed with this state transaction.
    pub slash_events: Vec<CommittedSlashEvent>,
}

#[cfg(test)]
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum CanonicalStateField {
    ChainId,
    Height,
    TipHash,
    BaseFee,
    TotalSupply,
    TreasuryBalance,
    BurnBuffer,
    FeeRewardPool,
    Utxos,
    Validators,
    ConsensusSnapshots,
    RewardEconomicSnapshot,
    SlashMembershipRoots,
    EvictedValidatorTombstones,
    StakePositions,
    UnbondingTranches,
    PositionTrancheIndex,
    StakingNonces,
    DelegatorIdentities,
    RetiredColdClassicalComponents,
    RetiredColdPqComponents,
    AppliedSlashHashes,
    Governance,
    StateCommitmentV2,
    EpochFeesBurned,
    EpochSlashedSpark,
    EpochSlashEventCount,
}

/// Structured details for one canonical slash transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedSlashEvent {
    /// Slashed validator identity.
    pub validator_id: Bytes32,
    /// Applied slash rate in basis points.
    pub slash_bps: u32,
    /// Supply burned by the transition.
    pub burned: u64,
    /// Self principal removed from positions and tranches.
    pub self_principal_slashed: u64,
    /// Reporter reward minted as a UTXO, if any.
    pub reporter_reward: u64,
}

/// The result of one successfully committed authoritative block transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedBlockOutcome {
    /// Epoch record emitted when the block crossed an epoch boundary.
    pub epoch_record: Option<indra_core::EpochRecord>,
    /// Validity-relevant canonical state changes made by the block.
    pub effects: CanonicalStateEffects,
}

impl CanonicalStateEffects {
    /// True when the committed transition changed no validity dependency.
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn covers_field(&self, field: CanonicalStateField) -> bool {
        use CanonicalStateField as F;
        match field {
            F::ChainId => false,
            F::Height => self.height_changed,
            F::TipHash => self.tip_hash_changed,
            F::BaseFee => self.base_fee_changed,
            F::TotalSupply | F::TreasuryBalance | F::BurnBuffer | F::FeeRewardPool => {
                self.economic_accounting_changed
            }
            F::Utxos => self.utxo_set_changed,
            F::Validators => self.validator_registry_changed || !self.validators_changed.is_empty(),
            F::ConsensusSnapshots => self.consensus_snapshots_changed,
            F::RewardEconomicSnapshot => self.reward_economic_snapshot_changed,
            F::SlashMembershipRoots => self.slash_membership_history_changed,
            F::EvictedValidatorTombstones => !self.tombstones_changed.is_empty(),
            F::StakePositions => !self.stake_positions_changed.is_empty(),
            F::UnbondingTranches => {
                self.global_position_tranche_capacity_changed
                    || !self.position_tranche_capacity_changed_for.is_empty()
            }
            F::PositionTrancheIndex => self.position_tranche_index_changed,
            F::StakingNonces => !self.staking_nonces_changed.is_empty(),
            F::DelegatorIdentities => !self.delegator_identities_changed.is_empty(),
            F::RetiredColdClassicalComponents | F::RetiredColdPqComponents => {
                self.retired_cold_components_changed
            }
            F::AppliedSlashHashes => !self.applied_slash_hashes.is_empty(),
            F::Governance => self.governance_state_changed,
            F::StateCommitmentV2 => self.state_commitment_cache_changed,
            F::EpochFeesBurned | F::EpochSlashedSpark | F::EpochSlashEventCount => {
                self.epoch_summary_changed
            }
        }
    }
}
