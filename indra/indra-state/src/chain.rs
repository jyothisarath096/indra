//! ChainState — the complete state of the INDRA chain at a point in time.
//!
//! This is everything a node needs to validate the next block.
//! It is the input and output of `apply_block`.

use indra_core::codec::{decode_list, encode_list, list_encoded_len, ByteReader, Decode, Encode};
use indra_core::error::{IndraError, IndraResult};
use indra_core::types::consensus_snapshot::{ConsensusSnapshot, ConsensusSnapshotEntry};
use indra_core::types::crypto::HybridPubKey;
use indra_core::types::reward_economic_snapshot::{
    RewardEconomicDelegatorEntry, RewardEconomicSnapshot, RewardEconomicValidatorEntry,
};
use indra_core::types::slash_membership::{
    compute_slash_membership_root, SlashMembershipRootRecord, MAX_SLASH_MEMBERSHIP_ROOT_RECORDS,
};

use indra_core::types::primitives::{
    Bytes32, VariableBytes, DEFAULT_CHAIN_ID, EPOCH_DURATION_BLOCKS, GENESIS_SUPPLY_SPARK,
    INITIAL_BASE_FEE_SPARK_PER_KB, MAX_CHAIN_ID_BYTES, MAX_STAKE_POSITIONS_PER_VALIDATOR,
    MAX_STAKE_POSITIONS_TOTAL, MAX_TRANCHES_PER_POSITION, MAX_TRANCHES_PER_VALIDATOR,
    MAX_TRANCHES_TOTAL,
};
use indra_core::types::stake_position::{
    ActiveStakeAggregateV1, PositionCustodyV1, StakePositionV1, UnbondingTrancheV1,
};
use std::collections::BTreeMap;

use crate::{
    governance::GovernanceState,
    persistent::{PersistentOrdMap, PersistentOrdSet},
    state_commitment::StateCommitmentV2,
    utxo::UtxoSet,
    validator::{EvictedValidatorTombstoneV2, ValidatorSet},
};

/// Defensive snapshot decode ceiling for staking nonce entries.
///
/// Staking nonces are keyed by staking signer identity: validator identities
/// for validator-owned ops and delegator identities for delegation-owned ops.
/// This guard must therefore cover the largest current validator/delegator
/// identity set the protocol can retain, not only validators.
pub const MAX_STAKING_NONCES_DECODE: usize = indra_core::types::primitives::MAX_VALIDATORS
    .saturating_add(
        indra_core::types::primitives::MAX_VALIDATORS
            .saturating_mul(crate::validator::MAX_DELEGATORS_PER_VALIDATOR),
    );

/// Defensive decode ceiling for permanently-retired classical cold components.
pub const MAX_RETIRED_COLD_CLASSICAL_COMPONENTS_DECODE: usize =
    indra_core::types::primitives::MAX_VALIDATORS.saturating_mul(2);
/// Defensive decode ceiling for permanently-retired PQ cold components.
pub const MAX_RETIRED_COLD_PQ_COMPONENTS_DECODE: usize =
    indra_core::types::primitives::MAX_VALIDATORS.saturating_mul(2);

/// The complete chain state at a given block height.
///
/// Two `ChainState` values are equivalent if and only if they represent
/// the same chain history. The `state_root` field (once implemented in
/// Phase 5) will be a cryptographic commitment to this entire structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainState {
    /// Chain identifier loaded from genesis and included in consensus-visible state.
    pub chain_id: String,

    /// Height of the most recently applied block (0 = genesis, before block 1).
    pub height: u64,

    /// Hash of the most recently applied block header.
    /// All-zero at genesis (no block has been applied yet).
    pub tip_hash: Bytes32,

    /// Current base fee in Spark/KB.
    /// Set to INITIAL_BASE_FEE at genesis, updated after each block.
    pub base_fee: u64,

    /// Total supply of Spark in existence (minted - burned).
    pub total_supply: u64,

    /// Accumulated block reward dust from proportional distribution rounding.
    ///
    /// This balance has no spend path and is effectively locked. Reporter slash
    /// rewards are not routed here; they are paid directly to the reporting
    /// block proposer as spendable UTXOs. Future cleanup: burn reward dust
    /// directly and remove treasury accounting entirely.
    pub treasury_balance: u64,

    /// Burn buffer balance in Spark (pending governance-directed burns).
    pub burn_buffer: u64,

    /// Accumulated validator fee rewards awaiting epoch distribution.
    pub fee_reward_pool: u64,

    /// All unspent transaction outputs.
    pub utxos: UtxoSet,

    /// Current validator set.
    pub validators: ValidatorSet,

    /// Canonical ascending-by-activation pair of versioned consensus snapshots.
    ///
    /// Once active, this contains the snapshot authoritative for the next
    /// consensus height and its immediately preceding snapshot when one exists.
    /// The bounded ordered vector supports Stage 3's greatest-activation-height
    /// lookup without introducing a separately mutable index.
    pub consensus_snapshots: Vec<ConsensusSnapshot>,

    /// Epoch-start commission/delegation basis paired with consensus authority.
    pub reward_economic_snapshot: Option<RewardEconomicSnapshot>,

    /// Canonical rolling commitments used for historical slash membership.
    pub slash_membership_roots: Vec<SlashMembershipRootRecord>,

    /// Bounded historical/custody records for post-v8 registry evictions.
    pub evicted_validator_tombstones: PersistentOrdMap<Bytes32, EvictedValidatorTombstoneV2>,

    /// Canonical active/reward staking positions.
    pub stake_positions: PersistentOrdMap<Bytes32, StakePositionV1>,

    /// Canonical immutable exact-height unbonding tranches.
    pub unbonding_tranches: PersistentOrdMap<Bytes32, UnbondingTrancheV1>,

    /// Rebuildable non-canonical position-to-tranche lookup index.
    pub(crate) position_tranche_index: BTreeMap<Bytes32, Vec<Bytes32>>,

    /// Monotonic nonces for staking op replay protection.
    pub staking_nonces: PersistentOrdMap<Bytes32, u64>,

    /// Canonical full public key for each post-activation delegator identity.
    pub delegator_identities: PersistentOrdMap<Bytes32, HybridPubKey>,

    /// Permanently retired cold Ed25519 public-key components.
    pub retired_cold_classical_components: PersistentOrdSet<[u8; 32]>,

    /// Permanently retired cold ML-DSA-87 public-key components.
    pub retired_cold_pq_components: PersistentOrdSet<[u8; indra_crypto::PQ_PK_BYTES]>,

    /// Hashes of applied slash evidence — prevents double-slash.
    /// Key: SHA-256(encode(SlashEvidenceV1))
    pub applied_slash_hashes: PersistentOrdSet<Bytes32>,

    /// On-chain governance state.
    pub governance: GovernanceState,

    /// Derived, non-authoritative StateCommitmentV2 cache.
    ///
    /// This is intentionally not encoded in snapshots. Canonical maps above
    /// remain the only persisted consensus state; the cache is rebuilt from
    /// them on decode/startup or before the first post-activation mutation.
    /// This task does not solve three separate scale costs: full-state clone
    /// during projected block application, linear per-validator delegation Vec
    /// lookup, or the O(touched delegators) reward distribution pass.
    pub state_commitment_v2: Option<StateCommitmentV2>,

    /// Transient fee burns accumulated for the current epoch summary.
    /// Not encoded and not included in consensus state roots.
    pub epoch_fees_burned: u64,

    /// Transient slash total accumulated for the current epoch summary.
    /// Not encoded and not included in consensus state roots.
    pub epoch_slashed_spark: u64,

    /// Transient slash event count accumulated for the current epoch summary.
    /// Not encoded and not included in consensus state roots.
    pub epoch_slash_event_count: u32,
}

#[cfg(test)]
#[allow(dead_code)]
impl ChainState {
    /// Return every top-level state field whose value differs.
    ///
    /// The exhaustive destructuring is deliberate: adding a field to
    /// `ChainState` without extending this detector is a compile error.
    pub(crate) fn changed_fields(
        before: &Self,
        after: &Self,
    ) -> std::collections::BTreeSet<crate::effects::CanonicalStateField> {
        use crate::effects::CanonicalStateField as F;
        let ChainState {
            chain_id: _,
            height: _,
            tip_hash: _,
            base_fee: _,
            total_supply: _,
            treasury_balance: _,
            burn_buffer: _,
            fee_reward_pool: _,
            utxos: _,
            validators: _,
            consensus_snapshots: _,
            reward_economic_snapshot: _,
            slash_membership_roots: _,
            evicted_validator_tombstones: _,
            stake_positions: _,
            unbonding_tranches: _,
            position_tranche_index: _,
            staking_nonces: _,
            delegator_identities: _,
            retired_cold_classical_components: _,
            retired_cold_pq_components: _,
            applied_slash_hashes: _,
            governance: _,
            state_commitment_v2: _,
            epoch_fees_burned: _,
            epoch_slashed_spark: _,
            epoch_slash_event_count: _,
        } = before;
        let mut changed = std::collections::BTreeSet::new();
        macro_rules! changed {
            ($field:ident, $variant:expr) => {
                if before.$field != after.$field {
                    changed.insert($variant);
                }
            };
        }
        changed!(chain_id, F::ChainId);
        changed!(height, F::Height);
        changed!(tip_hash, F::TipHash);
        changed!(base_fee, F::BaseFee);
        changed!(total_supply, F::TotalSupply);
        changed!(treasury_balance, F::TreasuryBalance);
        changed!(burn_buffer, F::BurnBuffer);
        changed!(fee_reward_pool, F::FeeRewardPool);
        changed!(utxos, F::Utxos);
        changed!(validators, F::Validators);
        changed!(consensus_snapshots, F::ConsensusSnapshots);
        changed!(reward_economic_snapshot, F::RewardEconomicSnapshot);
        changed!(slash_membership_roots, F::SlashMembershipRoots);
        changed!(evicted_validator_tombstones, F::EvictedValidatorTombstones);
        changed!(stake_positions, F::StakePositions);
        changed!(unbonding_tranches, F::UnbondingTranches);
        changed!(position_tranche_index, F::PositionTrancheIndex);
        changed!(staking_nonces, F::StakingNonces);
        changed!(delegator_identities, F::DelegatorIdentities);
        changed!(
            retired_cold_classical_components,
            F::RetiredColdClassicalComponents
        );
        changed!(retired_cold_pq_components, F::RetiredColdPqComponents);
        changed!(applied_slash_hashes, F::AppliedSlashHashes);
        changed!(governance, F::Governance);
        changed!(state_commitment_v2, F::StateCommitmentV2);
        changed!(epoch_fees_burned, F::EpochFeesBurned);
        changed!(epoch_slashed_spark, F::EpochSlashedSpark);
        changed!(epoch_slash_event_count, F::EpochSlashEventCount);
        changed
    }
}

impl Encode for ChainState {
    fn encode(&self, buf: &mut Vec<u8>) {
        // Included: transaction signing and state-root computation depend on the configured chain.
        VariableBytes::<MAX_CHAIN_ID_BYTES>::from_slice(self.chain_id.as_bytes())
            .unwrap_or_default()
            .encode(buf);
        // Included: the applied height determines the next valid block height.
        self.height.encode(buf);
        // Included: the next block must chain to the exact committed tip hash.
        self.tip_hash.encode(buf);
        // Included: fee validation for the next block depends on the current base fee.
        self.base_fee.encode(buf);
        // Included: block value hashing and supply accounting depend on total supply.
        self.total_supply.encode(buf);
        // Included: treasury accounting is part of consensus state and affects rewards.
        self.treasury_balance.encode(buf);
        // Included: burn-buffer accounting is consensus-visible and must survive restart.
        self.burn_buffer.encode(buf);
        // Included: pending fee rewards affect future epoch distribution.
        self.fee_reward_pool.encode(buf);
        // Included: the full UTXO set is required to validate spends after restart.
        self.utxos.encode(buf);
        // Included: validator metadata is needed for proposer election and signature/QC verification.
        self.validators.encode(buf);
        encode_nonce_map(&self.staking_nonces, buf);
        encode_hash_set(&self.applied_slash_hashes, buf);
        self.governance.encode(buf);
        encode_delegator_identity_registry(&self.delegator_identities, buf);
        encode_retired_cold_components(
            &self.retired_cold_classical_components,
            &self.retired_cold_pq_components,
            buf,
        );
        encode_list(&self.consensus_snapshots, buf);
        self.reward_economic_snapshot.is_some().encode(buf);
        if let Some(snapshot) = &self.reward_economic_snapshot {
            snapshot.encode(buf);
        }
        encode_list(&self.slash_membership_roots, buf);
        encode_stake_positions(&self.stake_positions, buf);
        encode_unbonding_tranches(&self.unbonding_tranches, buf);
        encode_tombstones(&self.evicted_validator_tombstones, buf);
        // Omitted: transient epoch summary counters and nested SMT caches are intentionally
        // reconstructed/reset by decoders from the serialized canonical entries.
    }

    fn encoded_len(&self) -> usize {
        VariableBytes::<MAX_CHAIN_ID_BYTES>::from_slice(self.chain_id.as_bytes())
            .unwrap_or_default()
            .encoded_len()
            + self.height.encoded_len()
            + self.tip_hash.encoded_len()
            + self.base_fee.encoded_len()
            + self.total_supply.encoded_len()
            + self.treasury_balance.encoded_len()
            + self.burn_buffer.encoded_len()
            + self.fee_reward_pool.encoded_len()
            + self.utxos.encoded_len()
            + self.validators.encoded_len()
            + nonce_map_encoded_len(&self.staking_nonces)
            + hash_set_encoded_len(&self.applied_slash_hashes)
            + self.governance.encoded_len()
            + delegator_identity_registry_encoded_len(&self.delegator_identities)
            + retired_cold_components_encoded_len(
                &self.retired_cold_classical_components,
                &self.retired_cold_pq_components,
            )
            + list_encoded_len(&self.consensus_snapshots)
            + 1
            + self
                .reward_economic_snapshot
                .as_ref()
                .map(Encode::encoded_len)
                .unwrap_or(0)
            + list_encoded_len(&self.slash_membership_roots)
            + tombstones_encoded_len(&self.evicted_validator_tombstones)
            + stake_positions_encoded_len(&self.stake_positions)
            + unbonding_tranches_encoded_len(&self.unbonding_tranches)
    }
}

impl Decode for ChainState {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let chain_id_bytes = VariableBytes::<MAX_CHAIN_ID_BYTES>::decode(r)?;
        let chain_id = String::from_utf8(chain_id_bytes.as_slice().to_vec())
            .unwrap_or_else(|_| DEFAULT_CHAIN_ID.to_string());
        let height = u64::decode(r)?;
        let tip_hash = Bytes32::decode(r)?;
        let base_fee = u64::decode(r)?;
        let total_supply = u64::decode(r)?;
        let treasury_balance = u64::decode(r)?;
        let burn_buffer = u64::decode(r)?;
        let fee_reward_pool = u64::decode(r)?;
        let utxos = UtxoSet::decode_at_height(r, height)?;
        let validators = ValidatorSet::decode(r)?;
        let staking_nonces = decode_nonce_map(r)?;
        let applied_slash_hashes = decode_hash_set(r, "snapshot.applied_slash_hashes")?;
        let governance = GovernanceState::decode(r)?;
        let delegator_identities = if r.remaining() > 0 {
            decode_delegator_identity_registry(r)?
        } else {
            PersistentOrdMap::new()
        };
        let (retired_cold_classical_components, retired_cold_pq_components) = if r.remaining() > 0 {
            decode_retired_cold_components(r)?
        } else {
            (PersistentOrdSet::new(), PersistentOrdSet::new())
        };
        let consensus_snapshots = {
            let snapshots = decode_list(r, 2, "chain_state.consensus_snapshots")?;
            validate_consensus_snapshot_collection(&snapshots, height)?;
            snapshots
        };
        let reward_economic_snapshot = if bool::decode(r)? {
            Some(RewardEconomicSnapshot::decode(r)?)
        } else {
            None
        };
        validate_reward_economic_pairing(&consensus_snapshots, reward_economic_snapshot.as_ref())?;
        let slash_membership_roots = decode_list(
            r,
            MAX_SLASH_MEMBERSHIP_ROOT_RECORDS,
            "chain_state.slash_membership_roots",
        )?;
        validate_slash_membership_root_history(&slash_membership_roots, height)?;
        for snapshot in &consensus_snapshots {
            let record = slash_membership_roots
                .iter()
                .find(|record| record.activation_height == snapshot.activation_height)
                .ok_or_else(|| {
                    IndraError::InvalidSlashMembershipProof(
                        "retained full snapshot has no matching membership root".to_string(),
                    )
                })?;
            if compute_slash_membership_root(snapshot)? != record.membership_root {
                return Err(IndraError::InvalidSlashMembershipProof(
                    "retained full snapshot membership root mismatch".to_string(),
                ));
            }
        }
        let stake_positions = decode_stake_positions(r)?;
        let unbonding_tranches = decode_unbonding_tranches(r)?;
        let evicted_validator_tombstones = decode_tombstones(
            r,
            &stake_positions,
            &unbonding_tranches,
            &validators,
            height,
        )?;
        let position_tranche_index = validate_and_build_position_tranche_index(
            &chain_id,
            &stake_positions,
            &unbonding_tranches,
        )?;
        Ok(Self {
            chain_id,
            height,
            tip_hash,
            base_fee,
            total_supply,
            treasury_balance,
            burn_buffer,
            fee_reward_pool,
            utxos,
            validators,
            consensus_snapshots,
            reward_economic_snapshot,
            slash_membership_roots,
            evicted_validator_tombstones,
            stake_positions,
            unbonding_tranches,
            position_tranche_index,
            staking_nonces,
            delegator_identities,
            retired_cold_classical_components,
            retired_cold_pq_components,
            applied_slash_hashes,
            governance,
            state_commitment_v2: None,
            epoch_fees_burned: 0,
            epoch_slashed_spark: 0,
            epoch_slash_event_count: 0,
        })
    }
}

impl ChainState {
    /// Sum active delegated principal from authoritative staking positions.
    pub fn total_active_delegated_stake(&self) -> u64 {
        self.stake_positions
            .values()
            .filter(|position| position.validator_id != position.principal_owner_id)
            .filter_map(|position| position.active)
            .fold(0u64, |sum, active| {
                sum.saturating_add(active.principal_spark)
            })
    }

    /// Create the genesis state (before any block has been applied).
    ///
    /// This is the canonical starting point for every INDRA node.
    pub fn new_genesis() -> Self {
        Self {
            chain_id: DEFAULT_CHAIN_ID.to_string(),
            height: 0,
            tip_hash: Bytes32::ZERO,
            base_fee: INITIAL_BASE_FEE_SPARK_PER_KB,
            total_supply: GENESIS_SUPPLY_SPARK,
            treasury_balance: 0,
            burn_buffer: 0,
            fee_reward_pool: 0,
            utxos: UtxoSet::new(),
            validators: ValidatorSet::new(),
            consensus_snapshots: Vec::new(),
            reward_economic_snapshot: None,
            slash_membership_roots: Vec::new(),
            evicted_validator_tombstones: PersistentOrdMap::new(),
            stake_positions: PersistentOrdMap::new(),
            unbonding_tranches: PersistentOrdMap::new(),
            position_tranche_index: BTreeMap::new(),
            staking_nonces: PersistentOrdMap::new(),
            delegator_identities: PersistentOrdMap::new(),
            retired_cold_classical_components: PersistentOrdSet::new(),
            retired_cold_pq_components: PersistentOrdSet::new(),
            applied_slash_hashes: PersistentOrdSet::new(),
            governance: GovernanceState::new(),
            state_commitment_v2: None,
            epoch_fees_burned: 0,
            epoch_slashed_spark: 0,
            epoch_slash_event_count: 0,
        }
    }

    /// Ensure the derived StateCommitmentV2 cache exists at `height`.
    pub fn ensure_state_commitment_v2(&mut self, height: u64) {
        if self.state_commitment_v2.is_none() {
            self.state_commitment_v2 = Some(StateCommitmentV2::from_state(self, height));
        }
    }

    /// Rebuild the derived StateCommitmentV2 cache from canonical state.
    pub fn rebuild_state_commitment_v2(&mut self, height: u64) {
        self.state_commitment_v2 = Some(StateCommitmentV2::from_state(self, height));
    }

    /// Rebuild and validate the non-canonical position-to-tranche index.
    pub fn rebuild_position_tranche_index(&mut self) -> IndraResult<()> {
        self.position_tranche_index = validate_and_build_position_tranche_index(
            &self.chain_id,
            &self.stake_positions,
            &self.unbonding_tranches,
        )?;
        Ok(())
    }

    /// Canonically ordered tranche identifiers belonging to `position_id`.
    pub fn tranche_ids_for_position(&self, position_id: &Bytes32) -> &[Bytes32] {
        self.position_tranche_index
            .get(position_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Return the StateCommitmentV2 root, rebuilding from canonical state if
    /// this decoded/restarted state does not yet have a warm cache.
    pub fn state_commitment_v2_root(&self, height: u64) -> Bytes32 {
        self.state_commitment_v2
            .as_ref()
            .map(StateCommitmentV2::root)
            .unwrap_or_else(|| StateCommitmentV2::from_state(self, height).root())
    }

    /// Resolve the one authoritative snapshot for a governed consensus height.
    ///
    /// This is exactly the retained snapshot with the greatest activation
    /// height not greater than `height`.
    pub fn snapshot_for_consensus_height(
        &self,
        height: u64,
    ) -> Result<&ConsensusSnapshot, crate::error::ConsensusSnapshotLookupError> {
        validate_retained_consensus_snapshots_for_lookup(&self.consensus_snapshots)?;
        self.consensus_snapshots
            .iter()
            .rev()
            .find(|snapshot| snapshot.activation_height <= height)
            .ok_or(crate::error::ConsensusSnapshotLookupError::NoSnapshotForHeight { height })
    }

    /// Build the immutable snapshot selected by the current final registry state.
    pub fn build_consensus_snapshot(
        &self,
        activation_height: u64,
        source_boundary_height: u64,
    ) -> crate::error::StateResult<ConsensusSnapshot> {
        if activation_height != source_boundary_height.saturating_add(1) {
            return Err(crate::error::StateError::InvalidConsensusSnapshot(
                "activation height must equal source boundary height plus one".to_string(),
            ));
        }
        let mut entries = Vec::new();
        for validator in self.validators.active_validators() {
            let classical_vote_pk = validator.hybrid_classical_pk.ok_or_else(|| {
                crate::error::StateError::InvalidConsensusSnapshot(format!(
                    "active validator {} has no Ed25519 vote key",
                    validator.validator_id
                ))
            })?;
            let pq_bytes = validator.hybrid_pq_pk.as_ref().ok_or_else(|| {
                crate::error::StateError::InvalidConsensusSnapshot(format!(
                    "active validator {} has no ML-DSA-87 vote key",
                    validator.validator_id
                ))
            })?;
            let pq_vote_pk: [u8; indra_crypto::PQ_PK_BYTES] =
                pq_bytes.as_slice().try_into().map_err(|_| {
                    crate::error::StateError::InvalidConsensusSnapshot(format!(
                        "active validator {} has malformed ML-DSA-87 vote key",
                        validator.validator_id
                    ))
                })?;
            let vrf_pk = validator.vrf_pk.ok_or_else(|| {
                crate::error::StateError::InvalidConsensusSnapshot(format!(
                    "active validator {} has no VRF key",
                    validator.validator_id
                ))
            })?;
            entries.push(
                ConsensusSnapshotEntry::new(
                    validator.validator_id,
                    validator.stake_spark,
                    classical_vote_pk,
                    pq_vote_pk,
                    vrf_pk,
                )
                .map_err(|error| {
                    crate::error::StateError::InvalidConsensusSnapshot(error.to_string())
                })?,
            );
        }
        entries.sort_by_key(|entry| entry.validator_id.0);
        ConsensusSnapshot::new(activation_height, source_boundary_height, entries)
            .map_err(|error| crate::error::StateError::InvalidConsensusSnapshot(error.to_string()))
    }

    /// Build the Section 3.3 snapshot for a chain whose snapshot gate is height 1.
    pub fn build_genesis_consensus_snapshot(&self) -> crate::error::StateResult<ConsensusSnapshot> {
        self.build_consensus_snapshot(1, 0)
    }

    /// Build the frozen epoch-start economic authority from active positions.
    pub fn build_reward_economic_snapshot(
        &self,
        consensus_snapshot: &ConsensusSnapshot,
    ) -> crate::error::StateResult<RewardEconomicSnapshot> {
        let mut principals: BTreeMap<Bytes32, BTreeMap<Bytes32, (u64, u64)>> = BTreeMap::new();
        for member in consensus_snapshot.entries() {
            principals.insert(member.validator_id, BTreeMap::new());
        }
        for position in self.stake_positions.values() {
            let Some(active) = position.active else {
                continue;
            };
            if position.principal_owner_id == position.validator_id {
                continue;
            }
            if let Some(owners) = principals.get_mut(&position.validator_id) {
                let (bonded, _) = owners.entry(position.principal_owner_id).or_default();
                *bonded = bonded.checked_add(active.principal_spark).ok_or_else(|| {
                    crate::error::StateError::InvalidRewardEconomicSnapshot(
                        "delegated principal overflow".into(),
                    )
                })?;
            }
        }
        for source in self.validators.all_validators().filter(|v| {
            matches!(v.status, crate::validator::ValidatorStatus::Registered)
                && v.auto_delegate_to.is_some()
        }) {
            let Some(position) = self.stake_positions.values().find(|p| {
                p.validator_id == source.validator_id && p.principal_owner_id == source.validator_id
            }) else {
                continue;
            };
            let Some(active) = position.active else {
                continue;
            };
            if let Some(owners) = principals.get_mut(&source.auto_delegate_to.expect("filtered")) {
                let (_, auto) = owners.entry(source.validator_id).or_default();
                *auto = auto.checked_add(active.principal_spark).ok_or_else(|| {
                    crate::error::StateError::InvalidRewardEconomicSnapshot(
                        "auto-delegated principal overflow".into(),
                    )
                })?;
            }
        }
        let bound = self.governance.params.max_commission_bps;
        let mut validators = Vec::with_capacity(consensus_snapshot.entries().len());
        for member in consensus_snapshot.entries() {
            let validator = self.validators.get(&member.validator_id).ok_or_else(|| {
                crate::error::StateError::InvalidRewardEconomicSnapshot(
                    "snapshot validator missing".into(),
                )
            })?;
            let owners = principals
                .remove(&member.validator_id)
                .unwrap_or_default()
                .into_iter()
                .map(|(id, (bonded, auto))| {
                    RewardEconomicDelegatorEntry::new(id, bonded, auto).map_err(|e| {
                        crate::error::StateError::InvalidRewardEconomicSnapshot(e.to_string())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            validators.push(
                RewardEconomicValidatorEntry::new(
                    member.validator_id,
                    validator.commission_bps,
                    owners,
                    bound,
                )
                .map_err(|e| {
                    crate::error::StateError::InvalidRewardEconomicSnapshot(e.to_string())
                })?,
            );
        }
        RewardEconomicSnapshot::new(
            consensus_snapshot.activation_height,
            consensus_snapshot.source_boundary_height,
            bound,
            validators,
        )
        .map_err(|e| crate::error::StateError::InvalidRewardEconomicSnapshot(e.to_string()))
    }

    /// Resolve exactly paired consensus and reward authority for `height`.
    pub fn reward_economic_snapshot_for_height(
        &self,
        height: u64,
    ) -> crate::error::StateResult<(&ConsensusSnapshot, &RewardEconomicSnapshot)> {
        let consensus = self
            .snapshot_for_consensus_height(height)
            .map_err(|error| {
                crate::error::StateError::InvalidRewardEconomicSnapshot(error.to_string())
            })?;
        let economic = self.reward_economic_snapshot.as_ref().ok_or_else(|| {
            crate::error::StateError::InvalidRewardEconomicSnapshot(
                "missing reward economic snapshot".to_string(),
            )
        })?;
        validate_reward_economic_membership(consensus, economic).map_err(|error| {
            crate::error::StateError::InvalidRewardEconomicSnapshot(error.to_string())
        })?;
        Ok((consensus, economic))
    }

    /// Finalize genesis authority after the validator set has been populated.
    pub fn finalize_genesis(&mut self) -> crate::error::StateResult<()> {
        if self.height != 0 || !self.consensus_snapshots.is_empty() {
            return Err(crate::error::StateError::InvalidConsensusSnapshot(
                "genesis snapshot initialization requires pristine height-zero snapshot state"
                    .to_string(),
            ));
        }
        if !self.unbonding_tranches.is_empty() {
            return Err(crate::error::StateError::InvalidRewardEconomicSnapshot(
                "genesis cannot contain unbonding tranches".into(),
            ));
        }
        self.stake_positions = PersistentOrdMap::new();
        let active: Vec<(Bytes32, u64)> = self
            .validators
            .active_validators()
            .map(|validator| (validator.validator_id, validator.stake_spark))
            .collect();
        for (validator_id, principal_spark) in active {
            let position = StakePositionV1::new(
                validator_id,
                validator_id,
                PositionCustodyV1::ValidatorColdIdentity { validator_id },
                Some(
                    ActiveStakeAggregateV1::new(principal_spark, 0, 0).map_err(|error| {
                        crate::error::StateError::InvalidRewardEconomicSnapshot(error.to_string())
                    })?,
                ),
                0,
                0,
            )
            .map_err(|error| {
                crate::error::StateError::InvalidRewardEconomicSnapshot(error.to_string())
            })?;
            // Genesis finalization is the authority for the self-position. Test
            // builders may deliberately amend the height-zero validator set and
            // finalize again; replace the same deterministic position atomically.
            self.stake_positions.insert(position.position_id, position);
        }
        self.rebuild_position_tranche_index().map_err(|error| {
            crate::error::StateError::InvalidRewardEconomicSnapshot(error.to_string())
        })?;
        let snapshot = self.build_genesis_consensus_snapshot()?;
        let economic = self.build_reward_economic_snapshot(&snapshot)?;
        let membership = SlashMembershipRootRecord {
            activation_height: snapshot.activation_height,
            membership_root: compute_slash_membership_root(&snapshot).map_err(|error| {
                crate::error::StateError::InvalidConsensusSnapshot(error.to_string())
            })?,
        };
        self.install_consensus_snapshot(snapshot)?;
        self.reward_economic_snapshot = Some(economic);
        self.append_slash_membership_root(membership)?;
        self.rebuild_state_commitment_v2(1);
        Ok(())
    }

    /// Create, rotate, and deterministically prune after a settled boundary.
    pub(crate) fn create_consensus_snapshot_after_boundary(
        &mut self,
        boundary_height: u64,
    ) -> crate::error::StateResult<()> {
        if boundary_height == 0
            || boundary_height % EPOCH_DURATION_BLOCKS != 0
            || self.height != boundary_height
        {
            return Err(crate::error::StateError::InvalidConsensusSnapshot(
                "snapshot creation requires the fully applied epoch-boundary state".to_string(),
            ));
        }
        self.rotate_consensus_snapshot_after_boundary(boundary_height)
    }

    pub(crate) fn rotate_consensus_snapshot_after_boundary(
        &mut self,
        boundary_height: u64,
    ) -> crate::error::StateResult<()> {
        let activation_height = boundary_height.checked_add(1).ok_or_else(|| {
            crate::error::StateError::InvalidConsensusSnapshot(
                "snapshot activation height overflow".to_string(),
            )
        })?;
        let snapshot = self.build_consensus_snapshot(activation_height, boundary_height)?;
        let economic = self.build_reward_economic_snapshot(&snapshot)?;
        let membership_record = SlashMembershipRootRecord {
            activation_height,
            membership_root: compute_slash_membership_root(&snapshot).map_err(|error| {
                crate::error::StateError::InvalidConsensusSnapshot(error.to_string())
            })?,
        };
        self.install_consensus_snapshot(snapshot)?;
        self.reward_economic_snapshot = Some(economic);
        self.append_slash_membership_root(membership_record)?;
        self.prune_slash_membership_roots(boundary_height)?;
        Ok(())
    }

    fn append_slash_membership_root(
        &mut self,
        record: SlashMembershipRootRecord,
    ) -> crate::error::StateResult<()> {
        if self
            .slash_membership_roots
            .last()
            .is_some_and(|last| last.activation_height >= record.activation_height)
        {
            return Err(crate::error::StateError::InvalidConsensusSnapshot(
                "slash membership roots are duplicate or not strictly ordered".to_string(),
            ));
        }
        self.slash_membership_roots.push(record);
        Ok(())
    }

    fn prune_slash_membership_roots(
        &mut self,
        current_height: u64,
    ) -> crate::error::StateResult<()> {
        let current_epoch = crate::epoch::epoch_for_height(current_height);
        while self.slash_membership_roots.len() > 1 {
            let successor_activation = self
                .slash_membership_roots
                .get(1)
                .ok_or_else(|| crate::error::StateError::InvariantViolation {
                    message: "slash root successor disappeared during pruning",
                })?
                .activation_height;
            let last_governed_height = successor_activation.checked_sub(1).ok_or_else(|| {
                crate::error::StateError::InvariantViolation {
                    message: "slash root successor activation underflow",
                }
            })?;
            let last_epoch = crate::epoch::epoch_for_height(last_governed_height);
            if current_epoch
                <= last_epoch
                    .saturating_add(indra_core::types::primitives::SLASH_EVIDENCE_WINDOW_EPOCHS)
            {
                break;
            }
            self.slash_membership_roots.remove(0);
        }
        if self.slash_membership_roots.len() > MAX_SLASH_MEMBERSHIP_ROOT_RECORDS {
            return Err(crate::error::StateError::InvalidConsensusSnapshot(
                "slash membership root history exceeds 502 nonexpired records".to_string(),
            ));
        }
        Ok(())
    }

    /// Resolve the unique retained root authoritative for `height`.
    pub fn slash_membership_root_for_height(
        &self,
        height: u64,
    ) -> crate::error::StateResult<&SlashMembershipRootRecord> {
        validate_slash_membership_root_history(&self.slash_membership_roots, self.height).map_err(
            |error| crate::error::StateError::InvalidConsensusSnapshot(error.to_string()),
        )?;
        self.slash_membership_roots
            .iter()
            .rev()
            .find(|record| record.activation_height <= height)
            .ok_or_else(|| {
                crate::error::StateError::InvalidConsensusSnapshot(format!(
                    "no slash membership root governs height {height}",
                ))
            })
    }

    fn install_consensus_snapshot(
        &mut self,
        snapshot: ConsensusSnapshot,
    ) -> crate::error::StateResult<()> {
        snapshot.validate().map_err(|error| {
            crate::error::StateError::InvalidConsensusSnapshot(error.to_string())
        })?;
        if self
            .consensus_snapshots
            .iter()
            .any(|existing| existing.activation_height == snapshot.activation_height)
        {
            return Err(crate::error::StateError::InvalidConsensusSnapshot(
                "duplicate consensus snapshot activation height".to_string(),
            ));
        }
        self.consensus_snapshots.push(snapshot);
        self.consensus_snapshots
            .sort_by_key(|snapshot| snapshot.activation_height);
        let excess = self.consensus_snapshots.len().saturating_sub(2);
        if excess > 0 {
            self.consensus_snapshots.drain(0..excess);
        }
        Ok(())
    }

    /// Current epoch number (0-indexed).
    pub fn current_epoch(&self) -> u64 {
        crate::epoch::epoch_for_height(self.height)
    }

    /// True if the chain has had at least one block applied.
    pub fn has_blocks(&self) -> bool {
        self.height > 0
    }
}

fn validate_reward_economic_membership(
    consensus: &ConsensusSnapshot,
    economic: &RewardEconomicSnapshot,
) -> IndraResult<()> {
    economic.validate()?;
    if consensus.activation_height != economic.activation_height
        || consensus.source_boundary_height != economic.source_boundary_height
        || consensus.entries().len() != economic.validators().len()
        || consensus
            .entries()
            .iter()
            .zip(economic.validators())
            .any(|(consensus, economic)| consensus.validator_id != economic.validator_id)
    {
        return Err(IndraError::InvalidRewardEconomicSnapshot(
            "economic snapshot is not exactly paired with consensus membership".to_string(),
        ));
    }
    Ok(())
}

fn encode_tombstones(
    tombstones: &PersistentOrdMap<Bytes32, EvictedValidatorTombstoneV2>,
    buf: &mut Vec<u8>,
) {
    2u8.encode(buf);
    (tombstones.len() as u32).encode(buf);
    for tombstone in tombstones.values() {
        tombstone.encode(buf);
    }
}

fn tombstones_encoded_len(
    tombstones: &PersistentOrdMap<Bytes32, EvictedValidatorTombstoneV2>,
) -> usize {
    1 + 4 + tombstones.values().map(Encode::encoded_len).sum::<usize>()
}

fn decode_tombstones(
    reader: &mut ByteReader<'_>,
    stake_positions: &PersistentOrdMap<Bytes32, StakePositionV1>,
    unbonding_tranches: &PersistentOrdMap<Bytes32, UnbondingTrancheV1>,
    validators: &ValidatorSet,
    state_height: u64,
) -> IndraResult<PersistentOrdMap<Bytes32, EvictedValidatorTombstoneV2>> {
    let version = u8::decode(reader)?;
    if version != 2 {
        return Err(IndraError::UnsupportedVersion {
            version: version.into(),
        });
    }
    let tombstones: Vec<EvictedValidatorTombstoneV2> = decode_list(
        reader,
        indra_core::types::primitives::MAX_VALIDATORS,
        "chain_state.evicted_validator_tombstones",
    )?;
    let mut result = PersistentOrdMap::new();
    let mut previous_validator_id = None;
    let mut seen_positions = PersistentOrdSet::new();
    let mut seen_tranches = PersistentOrdSet::new();
    for tombstone in tombstones {
        if previous_validator_id.is_some_and(|previous| previous >= tombstone.validator_id) {
            return Err(IndraError::InvalidSlashMembershipProof(
                "tombstones are not strictly ordered by validator ID".to_string(),
            ));
        }
        if validators.get(&tombstone.validator_id).is_some() {
            return Err(IndraError::InvalidSlashMembershipProof(
                "tombstoned validator remains in the live registry".to_string(),
            ));
        }
        if tombstone.eviction_height > state_height
            || tombstone.eviction_epoch != crate::epoch::epoch_for_height(tombstone.eviction_height)
        {
            return Err(IndraError::InvalidSlashMembershipProof(
                "malformed evicted-validator tombstone".to_string(),
            ));
        }
        indra_crypto::validate_classical_public_key(&indra_crypto::ClassicalPublicKey(
            tombstone.last_classical_vote_pk,
        ))
        .map_err(|error| {
            IndraError::InvalidSlashMembershipProof(format!(
                "malformed tombstone classical vote key: {error}"
            ))
        })?;
        indra_crypto::validate_pq_public_key(&indra_crypto::PqPublicKey(tombstone.last_pq_vote_pk))
            .map_err(|error| {
                IndraError::InvalidSlashMembershipProof(format!(
                    "malformed tombstone PQ vote key: {error}"
                ))
            })?;
        indra_crypto::validate_vrf_public_key(&tombstone.last_vrf_pk).map_err(|error| {
            IndraError::InvalidSlashMembershipProof(format!("malformed tombstone VRF key: {error}"))
        })?;
        if let Some(cold) = &tombstone.cold_custody {
            indra_crypto::validate_classical_public_key(&indra_crypto::ClassicalPublicKey(
                cold.classical_pk,
            ))
            .map_err(|error| {
                IndraError::InvalidSlashMembershipProof(format!(
                    "malformed tombstone cold classical key: {error}"
                ))
            })?;
            indra_crypto::validate_pq_public_key(&indra_crypto::PqPublicKey(cold.pq_pk)).map_err(
                |error| {
                    IndraError::InvalidSlashMembershipProof(format!(
                        "malformed tombstone cold PQ key: {error}"
                    ))
                },
            )?;
        }
        let mut requires_cold_custody = false;
        for position_id in &tombstone.retained_position_ids {
            if !seen_positions.insert(*position_id) {
                return Err(IndraError::InvalidSlashMembershipProof(
                    "position is retained by multiple tombstones".to_string(),
                ));
            }
            let position = stake_positions.get(position_id).ok_or_else(|| {
                IndraError::InvalidSlashMembershipProof(
                    "tombstone references a missing position".to_string(),
                )
            })?;
            if position.validator_id != tombstone.validator_id {
                return Err(IndraError::InvalidSlashMembershipProof(
                    "tombstone position owner mismatch".to_string(),
                ));
            }
            requires_cold_custody |= matches!(
                position.custody,
                indra_core::types::stake_position::PositionCustodyV1::ValidatorColdIdentity { validator_id: id }
                    if id == tombstone.validator_id
            );
        }
        for tranche_id in &tombstone.retained_tranche_ids {
            if !seen_tranches.insert(*tranche_id) {
                return Err(IndraError::InvalidSlashMembershipProof(
                    "tranche is retained by multiple tombstones".to_string(),
                ));
            }
            let tranche = unbonding_tranches.get(tranche_id).ok_or_else(|| {
                IndraError::InvalidSlashMembershipProof(
                    "tombstone references a missing tranche".to_string(),
                )
            })?;
            if !tombstone
                .retained_position_ids
                .contains(&tranche.position_id)
            {
                return Err(IndraError::InvalidSlashMembershipProof(
                    "tombstone tranche points outside retained positions".to_string(),
                ));
            }
        }
        if requires_cold_custody && tombstone.cold_custody.is_none() {
            return Err(IndraError::InvalidSlashMembershipProof(
                "cold-owned tombstone bond has no retained cold custody key".to_string(),
            ));
        }
        previous_validator_id = Some(tombstone.validator_id);
        result.insert(tombstone.validator_id, tombstone);
    }
    for position in stake_positions.values() {
        if result.contains_key(&position.validator_id)
            && !seen_positions.contains(&position.position_id)
        {
            return Err(IndraError::InvalidSlashMembershipProof(
                "evicted-validator position is missing its unique tombstone reference".to_string(),
            ));
        }
    }
    Ok(result)
}

fn validate_reward_economic_pairing(
    consensus_snapshots: &[ConsensusSnapshot],
    economic: Option<&RewardEconomicSnapshot>,
) -> IndraResult<()> {
    let economic = economic.ok_or_else(|| {
        IndraError::InvalidRewardEconomicSnapshot(
            "post-gate state is missing its reward economic snapshot".to_string(),
        )
    })?;
    let consensus = consensus_snapshots
        .iter()
        .find(|snapshot| snapshot.activation_height == economic.activation_height)
        .ok_or_else(|| {
            IndraError::InvalidRewardEconomicSnapshot(
                "no retained consensus snapshot has the economic activation height".to_string(),
            )
        })?;
    validate_reward_economic_membership(consensus, economic)
}

fn validate_slash_membership_root_history(
    roots: &[SlashMembershipRootRecord],
    state_height: u64,
) -> IndraResult<()> {
    use indra_core::types::primitives::SLASH_EVIDENCE_WINDOW_EPOCHS;
    if roots.is_empty() {
        return Err(IndraError::InvalidSlashMembershipProof(
            "post-gate state is missing slash membership root history".to_string(),
        ));
    }
    if roots.len() > MAX_SLASH_MEMBERSHIP_ROOT_RECORDS {
        return Err(IndraError::LengthExceeded {
            field: "chain_state.slash_membership_roots",
            max: MAX_SLASH_MEMBERSHIP_ROOT_RECORDS,
            actual: roots.len(),
        });
    }
    for (index, root) in roots.iter().enumerate() {
        if root.activation_height == 0 {
            return Err(IndraError::InvalidSlashMembershipProof(
                "root activation height must be nonzero".to_string(),
            ));
        }
        if index > 0
            && roots
                .get(index - 1)
                .is_some_and(|previous| previous.activation_height >= root.activation_height)
        {
            return Err(IndraError::InvalidSlashMembershipProof(
                "root activations are duplicate or not strictly ascending".to_string(),
            ));
        }
    }
    for pair in roots.windows(2) {
        let previous = pair.first().ok_or_else(|| {
            IndraError::InvalidSlashMembershipProof("root-history pair is empty".to_string())
        })?;
        let successor = pair.get(1).ok_or_else(|| {
            IndraError::InvalidSlashMembershipProof("root-history successor is missing".to_string())
        })?;
        let last_height = successor.activation_height.checked_sub(1).ok_or_else(|| {
            IndraError::InvalidSlashMembershipProof("successor activation underflow".to_string())
        })?;
        let expiry_epoch = crate::epoch::epoch_for_height(last_height)
            .saturating_add(SLASH_EVIDENCE_WINDOW_EPOCHS);
        if crate::epoch::epoch_for_height(state_height) > expiry_epoch
            && previous.activation_height != roots.last().map_or(0, |root| root.activation_height)
        {
            return Err(IndraError::InvalidSlashMembershipProof(
                "expired slash membership root was not pruned".to_string(),
            ));
        }
    }
    Ok(())
}

fn validate_consensus_snapshot_collection(
    snapshots: &[ConsensusSnapshot],
    state_height: u64,
) -> IndraResult<()> {
    if snapshots.is_empty() {
        return Err(IndraError::InvalidConsensusSnapshot(
            "post-gate ChainState has no consensus snapshot".to_string(),
        ));
    }
    if snapshots.len() > 2 {
        return Err(IndraError::LengthExceeded {
            field: "chain_state.consensus_snapshots",
            max: 2,
            actual: snapshots.len(),
        });
    }
    for (index, snapshot) in snapshots.iter().enumerate() {
        snapshot.validate()?;
        if index > 0 && snapshots[index - 1].activation_height >= snapshot.activation_height {
            return Err(IndraError::InvalidConsensusSnapshot(
                "snapshot activation heights are not strictly ascending".to_string(),
            ));
        }
    }
    let next_height = state_height.saturating_add(1);
    if snapshots
        .last()
        .map(|snapshot| snapshot.activation_height > next_height)
        .unwrap_or(true)
    {
        return Err(IndraError::InvalidConsensusSnapshot(
            "latest snapshot activates after the next consensus height".to_string(),
        ));
    }
    Ok(())
}

fn validate_retained_consensus_snapshots_for_lookup(
    snapshots: &[ConsensusSnapshot],
) -> Result<(), crate::error::ConsensusSnapshotLookupError> {
    use crate::error::ConsensusSnapshotLookupError;

    if snapshots.is_empty() {
        return Err(ConsensusSnapshotLookupError::InvalidRetainedState {
            reason: "snapshot collection is empty".to_string(),
        });
    }
    if snapshots.len() > 2 {
        return Err(ConsensusSnapshotLookupError::InvalidRetainedState {
            reason: "snapshot collection exceeds the two-snapshot retention bound".to_string(),
        });
    }
    for (index, snapshot) in snapshots.iter().enumerate() {
        snapshot.validate().map_err(|error| {
            ConsensusSnapshotLookupError::InvalidRetainedState {
                reason: error.to_string(),
            }
        })?;
        let expected_activation =
            snapshot
                .source_boundary_height
                .checked_add(1)
                .ok_or_else(|| ConsensusSnapshotLookupError::InvalidRetainedState {
                    reason: "snapshot source-boundary height overflows activation".to_string(),
                })?;
        if snapshot.activation_height != expected_activation {
            return Err(ConsensusSnapshotLookupError::InvalidRetainedState {
                reason: "activation height is not source boundary height plus one".to_string(),
            });
        }
        if index > 0 && snapshots[index - 1].activation_height >= snapshot.activation_height {
            return Err(ConsensusSnapshotLookupError::InvalidRetainedState {
                reason: "activation heights are duplicate or not strictly ascending".to_string(),
            });
        }
    }
    Ok(())
}

fn encode_hash_set(hashes: &PersistentOrdSet<Bytes32>, buf: &mut Vec<u8>) {
    (hashes.len() as u32).encode(buf);
    for hash in hashes {
        hash.encode(buf);
    }
}

fn hash_set_encoded_len(hashes: &PersistentOrdSet<Bytes32>) -> usize {
    4 + hashes.len() * 32
}

fn decode_hash_set(
    r: &mut ByteReader<'_>,
    field: &'static str,
) -> IndraResult<PersistentOrdSet<Bytes32>> {
    use indra_core::error::IndraError;
    use indra_core::types::primitives::MAX_SLASHES_PER_BLOCK;

    let count = u32::decode(r)? as usize;
    let max = MAX_SLASHES_PER_BLOCK.saturating_mul(10_000);
    if count > max {
        return Err(IndraError::LengthExceeded {
            field,
            max,
            actual: count,
        });
    }
    let mut hashes = PersistentOrdSet::new();
    for _ in 0..count {
        let hash = Bytes32::decode(r)?;
        if !hashes.insert(hash) {
            return Err(IndraError::DuplicateEntries { field });
        }
    }
    Ok(hashes)
}

fn encode_stake_positions(
    positions: &PersistentOrdMap<Bytes32, StakePositionV1>,
    buf: &mut Vec<u8>,
) {
    (positions.len() as u32).encode(buf);
    for (position_id, position) in positions {
        position_id.encode(buf);
        position.encode(buf);
    }
}

fn stake_positions_encoded_len(positions: &PersistentOrdMap<Bytes32, StakePositionV1>) -> usize {
    4 + positions
        .iter()
        .map(|(position_id, position)| position_id.encoded_len() + position.encoded_len())
        .sum::<usize>()
}

fn decode_stake_positions(
    reader: &mut ByteReader<'_>,
) -> IndraResult<PersistentOrdMap<Bytes32, StakePositionV1>> {
    let count = u32::decode(reader)? as usize;
    if count > MAX_STAKE_POSITIONS_TOTAL {
        return Err(IndraError::LengthExceeded {
            field: "chain_state.stake_positions",
            max: MAX_STAKE_POSITIONS_TOTAL,
            actual: count,
        });
    }
    let mut positions = PersistentOrdMap::new();
    for _ in 0..count {
        let key = Bytes32::decode(reader)?;
        let position = StakePositionV1::decode(reader)?;
        if key != position.position_id {
            return Err(IndraError::InvalidStakePosition(
                "stake-position map key does not match canonical position ID".to_string(),
            ));
        }
        if positions.insert(key, position).is_some() {
            return Err(IndraError::DuplicateEntries {
                field: "chain_state.stake_positions",
            });
        }
    }
    Ok(positions)
}

fn encode_unbonding_tranches(
    tranches: &PersistentOrdMap<Bytes32, UnbondingTrancheV1>,
    buf: &mut Vec<u8>,
) {
    (tranches.len() as u32).encode(buf);
    for (tranche_id, tranche) in tranches {
        tranche_id.encode(buf);
        tranche.encode(buf);
    }
}

fn unbonding_tranches_encoded_len(
    tranches: &PersistentOrdMap<Bytes32, UnbondingTrancheV1>,
) -> usize {
    4 + tranches
        .iter()
        .map(|(tranche_id, tranche)| tranche_id.encoded_len() + tranche.encoded_len())
        .sum::<usize>()
}

fn decode_unbonding_tranches(
    reader: &mut ByteReader<'_>,
) -> IndraResult<PersistentOrdMap<Bytes32, UnbondingTrancheV1>> {
    let count = u32::decode(reader)? as usize;
    if count > MAX_TRANCHES_TOTAL {
        return Err(IndraError::LengthExceeded {
            field: "chain_state.unbonding_tranches",
            max: MAX_TRANCHES_TOTAL,
            actual: count,
        });
    }
    let mut tranches = PersistentOrdMap::new();
    for _ in 0..count {
        let key = Bytes32::decode(reader)?;
        let tranche = UnbondingTrancheV1::decode(reader)?;
        if key != tranche.tranche_id {
            return Err(IndraError::InvalidStakePosition(
                "unbonding-tranche map key does not match canonical tranche ID".to_string(),
            ));
        }
        if tranches.insert(key, tranche).is_some() {
            return Err(IndraError::DuplicateEntries {
                field: "chain_state.unbonding_tranches",
            });
        }
    }
    Ok(tranches)
}

fn validate_and_build_position_tranche_index(
    _chain_id: &str,
    positions: &PersistentOrdMap<Bytes32, StakePositionV1>,
    tranches: &PersistentOrdMap<Bytes32, UnbondingTrancheV1>,
) -> IndraResult<BTreeMap<Bytes32, Vec<Bytes32>>> {
    if positions.len() > MAX_STAKE_POSITIONS_TOTAL || tranches.len() > MAX_TRANCHES_TOTAL {
        return Err(IndraError::InvalidStakePosition(
            "global staking-position capacity exceeded".to_string(),
        ));
    }

    let mut positions_per_validator = BTreeMap::<Bytes32, usize>::new();
    let mut active_positions_per_validator = BTreeMap::<Bytes32, usize>::new();
    let mut active_positions = 0usize;
    for (position_id, position) in positions {
        position.validate()?;
        if position_id != &position.position_id {
            return Err(IndraError::InvalidStakePosition(
                "stake-position map key mismatch".to_string(),
            ));
        }
        let count = positions_per_validator
            .entry(position.validator_id)
            .or_default();
        *count += 1;
        if *count > MAX_STAKE_POSITIONS_PER_VALIDATOR {
            return Err(IndraError::InvalidStakePosition(
                "per-validator stake-position capacity exceeded".to_string(),
            ));
        }
        if position.active.is_some() {
            active_positions += 1;
            *active_positions_per_validator
                .entry(position.validator_id)
                .or_default() += 1;
        }
    }

    let mut index = BTreeMap::<Bytes32, Vec<Bytes32>>::new();
    let mut tranches_per_validator = BTreeMap::<Bytes32, usize>::new();
    for (tranche_id, tranche) in tranches {
        tranche.validate()?;
        if tranche_id != &tranche.tranche_id {
            return Err(IndraError::InvalidStakePosition(
                "unbonding-tranche map key mismatch".to_string(),
            ));
        }
        let position = positions.get(&tranche.position_id).ok_or_else(|| {
            IndraError::InvalidStakePosition(
                "unbonding tranche references a missing position".to_string(),
            )
        })?;
        if tranche.custody != position.custody {
            return Err(IndraError::InvalidStakePosition(
                "unbonding tranche custody differs from its position".to_string(),
            ));
        }
        let ids = index.entry(tranche.position_id).or_default();
        ids.push(*tranche_id);
        if ids.len() > MAX_TRANCHES_PER_POSITION {
            return Err(IndraError::InvalidStakePosition(
                "per-position tranche capacity exceeded".to_string(),
            ));
        }
        let validator_count = tranches_per_validator
            .entry(position.validator_id)
            .or_default();
        *validator_count += 1;
        if *validator_count > MAX_TRANCHES_PER_VALIDATOR {
            return Err(IndraError::InvalidStakePosition(
                "per-validator tranche capacity exceeded".to_string(),
            ));
        }
    }

    if tranches.len().saturating_add(active_positions) > MAX_TRANCHES_TOTAL {
        return Err(IndraError::InvalidStakePosition(
            "global final-exit tranche reservation exceeded".to_string(),
        ));
    }
    for (validator_id, active_count) in active_positions_per_validator {
        let tranche_count = tranches_per_validator
            .get(&validator_id)
            .copied()
            .unwrap_or(0);
        if tranche_count.saturating_add(active_count) > MAX_TRANCHES_PER_VALIDATOR {
            return Err(IndraError::InvalidStakePosition(
                "per-validator final-exit tranche reservation exceeded".to_string(),
            ));
        }
    }
    for (position_id, position) in positions {
        let tranche_count = index.get(position_id).map_or(0, Vec::len);
        let has_tranches = tranche_count != 0;
        if position.active.is_some() && tranche_count.saturating_add(1) > MAX_TRANCHES_PER_POSITION
        {
            return Err(IndraError::InvalidStakePosition(
                "per-position final-exit tranche reservation exceeded".to_string(),
            ));
        }
        if position.active.is_none() && position.pending_rewards_spark == 0 && !has_tranches {
            return Err(IndraError::InvalidStakePosition(
                "empty stake position must not remain canonical".to_string(),
            ));
        }
    }
    Ok(index)
}

fn encode_nonce_map(nonces: &PersistentOrdMap<Bytes32, u64>, buf: &mut Vec<u8>) {
    (nonces.len() as u32).encode(buf);
    for (signer_id, nonce) in nonces {
        signer_id.encode(buf);
        nonce.encode(buf);
    }
}

fn nonce_map_encoded_len(nonces: &PersistentOrdMap<Bytes32, u64>) -> usize {
    4 + nonces.len() * (32 + 8)
}

fn decode_nonce_map(r: &mut ByteReader<'_>) -> IndraResult<PersistentOrdMap<Bytes32, u64>> {
    let count = u32::decode(r)? as usize;
    validate_nonce_map_count(count)?;
    let mut nonces = PersistentOrdMap::new();
    for _ in 0..count {
        let signer_id = Bytes32::decode(r)?;
        let nonce = u64::decode(r)?;
        if nonces.insert(signer_id, nonce).is_some() {
            return Err(IndraError::DuplicateEntries {
                field: "snapshot.staking_nonces",
            });
        }
    }
    Ok(nonces)
}

fn validate_nonce_map_count(count: usize) -> IndraResult<()> {
    if count > MAX_STAKING_NONCES_DECODE {
        return Err(IndraError::LengthExceeded {
            field: "snapshot.staking_nonces",
            max: MAX_STAKING_NONCES_DECODE,
            actual: count,
        });
    }
    Ok(())
}

fn encode_delegator_identity_registry(
    identities: &PersistentOrdMap<Bytes32, HybridPubKey>,
    buf: &mut Vec<u8>,
) {
    (identities.len() as u32).encode(buf);
    for (delegator_id, pubkey) in identities {
        delegator_id.encode(buf);
        pubkey.encode(buf);
    }
}

fn delegator_identity_registry_encoded_len(
    identities: &PersistentOrdMap<Bytes32, HybridPubKey>,
) -> usize {
    4 + identities
        .iter()
        .map(|(delegator_id, pubkey)| delegator_id.encoded_len() + pubkey.encoded_len())
        .sum::<usize>()
}

fn decode_delegator_identity_registry(
    r: &mut ByteReader<'_>,
) -> IndraResult<PersistentOrdMap<Bytes32, HybridPubKey>> {
    let count = u32::decode(r)? as usize;
    validate_delegator_identity_count(count)?;
    let mut identities = PersistentOrdMap::new();
    for _ in 0..count {
        let delegator_id = Bytes32::decode(r)?;
        let pubkey = HybridPubKey::decode(r)?;
        if identities.insert(delegator_id, pubkey).is_some() {
            return Err(IndraError::DuplicateEntries {
                field: "snapshot.delegator_identities",
            });
        }
    }
    Ok(identities)
}

fn validate_delegator_identity_count(count: usize) -> IndraResult<()> {
    if count > MAX_STAKING_NONCES_DECODE {
        return Err(IndraError::LengthExceeded {
            field: "snapshot.delegator_identities",
            max: MAX_STAKING_NONCES_DECODE,
            actual: count,
        });
    }
    Ok(())
}

fn encode_retired_cold_components(
    classical: &PersistentOrdSet<[u8; 32]>,
    pq: &PersistentOrdSet<[u8; indra_crypto::PQ_PK_BYTES]>,
    buf: &mut Vec<u8>,
) {
    (classical.len() as u32).encode(buf);
    for component in classical {
        buf.extend_from_slice(component);
    }
    (pq.len() as u32).encode(buf);
    for component in pq {
        buf.extend_from_slice(component);
    }
}

fn retired_cold_components_encoded_len(
    classical: &PersistentOrdSet<[u8; 32]>,
    pq: &PersistentOrdSet<[u8; indra_crypto::PQ_PK_BYTES]>,
) -> usize {
    8 + classical.len() * 32 + pq.len() * indra_crypto::PQ_PK_BYTES
}

fn decode_retired_cold_components(
    r: &mut ByteReader<'_>,
) -> IndraResult<(
    PersistentOrdSet<[u8; 32]>,
    PersistentOrdSet<[u8; indra_crypto::PQ_PK_BYTES]>,
)> {
    let classical_count = u32::decode(r)? as usize;
    if classical_count > MAX_RETIRED_COLD_CLASSICAL_COMPONENTS_DECODE {
        return Err(IndraError::LengthExceeded {
            field: "snapshot.retired_cold_classical_components",
            max: MAX_RETIRED_COLD_CLASSICAL_COMPONENTS_DECODE,
            actual: classical_count,
        });
    }
    let mut classical = PersistentOrdSet::new();
    for _ in 0..classical_count {
        let component = r.read_bytes32()?;
        if !classical.insert(component) {
            return Err(IndraError::DuplicateEntries {
                field: "snapshot.retired_cold_classical_components",
            });
        }
    }
    let pq_count = u32::decode(r)? as usize;
    if pq_count > MAX_RETIRED_COLD_PQ_COMPONENTS_DECODE {
        return Err(IndraError::LengthExceeded {
            field: "snapshot.retired_cold_pq_components",
            max: MAX_RETIRED_COLD_PQ_COMPONENTS_DECODE,
            actual: pq_count,
        });
    }
    let mut pq = PersistentOrdSet::new();
    for _ in 0..pq_count {
        let bytes = r.read_bytes(indra_crypto::PQ_PK_BYTES)?;
        let mut component = [0u8; indra_crypto::PQ_PK_BYTES];
        component.copy_from_slice(bytes);
        if !pq.insert(component) {
            return Err(IndraError::DuplicateEntries {
                field: "snapshot.retired_cold_pq_components",
            });
        }
    }
    Ok((classical, pq))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_cold_component_decode_caps_fail_before_allocation() {
        let mut classical = Vec::new();
        ((MAX_RETIRED_COLD_CLASSICAL_COMPONENTS_DECODE + 1) as u32).encode(&mut classical);
        assert!(matches!(
            decode_retired_cold_components(&mut ByteReader::new(&classical)),
            Err(IndraError::LengthExceeded {
                field: "snapshot.retired_cold_classical_components",
                ..
            })
        ));

        let mut pq = Vec::new();
        0u32.encode(&mut pq);
        ((MAX_RETIRED_COLD_PQ_COMPONENTS_DECODE + 1) as u32).encode(&mut pq);
        assert!(matches!(
            decode_retired_cold_components(&mut ByteReader::new(&pq)),
            Err(IndraError::LengthExceeded {
                field: "snapshot.retired_cold_pq_components",
                ..
            })
        ));
    }
    use crate::ValidatorEntry;
    use std::collections::{BTreeMap, HashSet};

    use indra_core::{
        codec::Encode,
        error::IndraError,
        types::{
            crypto::HybridPubKey,
            primitives::{
                VariableBytes, GENESIS_SUPPLY_SPARK, INITIAL_BASE_FEE_SPARK_PER_KB, MAX_VALIDATORS,
            },
        },
    };

    fn snapshot_validator(id_byte: u8, key_seed: u8, stake: u64) -> ValidatorEntry {
        let classical = indra_crypto::ClassicalKeypair::from_seed(&[key_seed; 32]);
        let pq = indra_crypto::PqKeypair::from_seed(&[key_seed.wrapping_add(1); 32]).unwrap();
        let public = indra_crypto::HybridKeypair::new(classical, pq).public_key();
        let vrf = indra_crypto::VrfKeypair::from_seed(&[key_seed.wrapping_add(2); 32]);
        ValidatorEntry {
            validator_id: Bytes32::from([id_byte; 32]),
            name: format!("snapshot-validator-{id_byte}"),
            hybrid_classical_pk: Some(public.classical.0),
            hybrid_pq_pk: Some(public.pq.0.to_vec()),
            vrf_pk: Some(vrf.public_key()),
            stake_spark: stake,
            status: crate::validator::ValidatorStatus::Active,
            registered_epoch: 0,
            last_active_epoch: 0,
            pending_rewards: 0,
            rewards_last_epoch: 0,
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
            cold_nonce: 0,
        }
    }

    fn snapshot_state() -> ChainState {
        let mut state = ChainState::new_genesis();
        state
            .validators
            .upsert(snapshot_validator(1, 11, 2_000_000_000))
            .unwrap();
        state
            .validators
            .upsert(snapshot_validator(2, 21, 3_000_000_000))
            .unwrap();
        state.finalize_genesis().unwrap();
        state
    }

    #[test]
    fn genesis_state_is_correct() {
        let state = ChainState::new_genesis();
        assert_eq!(state.height, 0);
        assert_eq!(state.chain_id, DEFAULT_CHAIN_ID);
        assert_eq!(state.tip_hash, Bytes32::ZERO);
        assert_eq!(state.base_fee, INITIAL_BASE_FEE_SPARK_PER_KB);
        assert_eq!(state.total_supply, GENESIS_SUPPLY_SPARK);
        assert_eq!(state.treasury_balance, 0);
        assert_eq!(state.fee_reward_pool, 0);
        assert!(state.utxos.is_empty());
        assert!(state.validators.is_empty());
        assert!(state.consensus_snapshots.is_empty());
    }

    #[test]
    fn consensus_snapshot_storage_round_trips_with_exact_two_retained() {
        let mut state = snapshot_state();
        state.rotate_consensus_snapshot_after_boundary(300).unwrap();
        state
            .validators
            .get_mut(&Bytes32::from([1; 32]))
            .unwrap()
            .stake_spark += 1;
        state.rotate_consensus_snapshot_after_boundary(600).unwrap();
        state.rotate_consensus_snapshot_after_boundary(900).unwrap();
        state.height = u64::MAX;
        let bootstrap = state
            .build_consensus_snapshot(u64::MAX, u64::MAX - 1)
            .unwrap();
        let bootstrap_economic = state.build_reward_economic_snapshot(&bootstrap).unwrap();
        state.consensus_snapshots = vec![state.consensus_snapshots[1].clone(), bootstrap.clone()];
        state.reward_economic_snapshot = Some(bootstrap_economic);
        state.slash_membership_roots = state
            .consensus_snapshots
            .iter()
            .map(|snapshot| SlashMembershipRootRecord {
                activation_height: snapshot.activation_height,
                membership_root: compute_slash_membership_root(snapshot).unwrap(),
            })
            .collect();
        let tombstone_keys = bootstrap.entries()[0].clone();
        let tombstone_id = Bytes32::from([0xE7; 32]);
        state.evicted_validator_tombstones.insert(
            tombstone_id,
            crate::validator::EvictedValidatorTombstoneV2 {
                validator_id: tombstone_id,
                eviction_height: u64::MAX - 1,
                eviction_epoch: crate::epoch::epoch_for_height(u64::MAX - 1),
                last_classical_vote_pk: tombstone_keys.classical_vote_pk,
                last_pq_vote_pk: tombstone_keys.pq_vote_pk,
                last_vrf_pk: tombstone_keys.vrf_pk,
                cold_custody: None,
                // Empty is a valid later lifecycle state after all originally
                // retained positions and tranches have matured or been slashed.
                retained_position_ids: Vec::new(),
                retained_tranche_ids: Vec::new(),
            },
        );
        state.rebuild_state_commitment_v2(u64::MAX);

        assert_eq!(state.consensus_snapshots.len(), 2);
        assert_eq!(state.consensus_snapshots[0].activation_height, 901);
        assert_eq!(state.consensus_snapshots[1].activation_height, u64::MAX);
        assert_eq!(
            state
                .reward_economic_snapshot
                .as_ref()
                .unwrap()
                .activation_height,
            u64::MAX
        );

        let bytes = state.encode_to_vec();
        assert_eq!(bytes.len(), state.encoded_len());
        let decoded = ChainState::decode_exact(&bytes).unwrap();
        assert_eq!(decoded.consensus_snapshots, state.consensus_snapshots);
        assert_eq!(
            decoded.evicted_validator_tombstones,
            state.evicted_validator_tombstones
        );
        assert_eq!(
            decoded.reward_economic_snapshot,
            state.reward_economic_snapshot
        );
        assert_eq!(decoded.encode_to_vec(), bytes);
        assert_eq!(
            decoded.state_commitment_v2_root(u64::MAX),
            state.state_commitment_v2_root(u64::MAX)
        );
    }

    #[test]
    fn slash_membership_history_keeps_502_until_last_governed_window_expires() {
        let mut state = ChainState::new_genesis();
        state.slash_membership_roots = (0u64..502)
            .map(|index| SlashMembershipRootRecord {
                activation_height: 301 + index * EPOCH_DURATION_BLOCKS,
                membership_root: Bytes32::from([(index % 251) as u8; 32]),
            })
            .collect();

        state.prune_slash_membership_roots(150_600).unwrap();
        assert_eq!(crate::epoch::epoch_for_height(150_600), 502);
        assert_eq!(state.slash_membership_roots.len(), 502);
        assert_eq!(state.slash_membership_roots[0].activation_height, 301);

        state.prune_slash_membership_roots(150_900).unwrap();
        assert_eq!(crate::epoch::epoch_for_height(150_900), 503);
        assert_eq!(state.slash_membership_roots.len(), 501);
        assert_eq!(state.slash_membership_roots[0].activation_height, 601);
    }

    #[test]
    fn snapshot_lookup_uses_exact_greatest_activation_not_greater_than_height() {
        let mut state = snapshot_state();
        state.rotate_consensus_snapshot_after_boundary(600).unwrap();
        state.rotate_consensus_snapshot_after_boundary(900).unwrap();

        for height in [601, 700, 900] {
            assert_eq!(
                state
                    .snapshot_for_consensus_height(height)
                    .unwrap()
                    .activation_height,
                601
            );
        }
        for height in [901, 1_000, u64::MAX] {
            assert_eq!(
                state
                    .snapshot_for_consensus_height(height)
                    .unwrap()
                    .activation_height,
                901
            );
        }
    }

    #[test]
    fn snapshot_lookup_boundary_qc_300_uses_old_and_301_uses_new() {
        let mut state = snapshot_state();
        state
            .consensus_snapshots
            .push(state.build_genesis_consensus_snapshot().unwrap());
        state.rotate_consensus_snapshot_after_boundary(300).unwrap();

        assert_eq!(
            state
                .snapshot_for_consensus_height(300)
                .unwrap()
                .activation_height,
            1
        );
        assert_eq!(
            state
                .snapshot_for_consensus_height(301)
                .unwrap()
                .activation_height,
            301
        );
    }

    #[test]
    fn snapshot_lookup_fails_closed_for_invalid_or_uncovered_state() {
        use crate::error::ConsensusSnapshotLookupError;

        let mut duplicate = snapshot_state();
        duplicate
            .rotate_consensus_snapshot_after_boundary(600)
            .unwrap();
        duplicate
            .consensus_snapshots
            .push(duplicate.consensus_snapshots[0].clone());
        assert!(matches!(
            duplicate.snapshot_for_consensus_height(601),
            Err(ConsensusSnapshotLookupError::InvalidRetainedState { .. })
        ));

        let mut uncovered = snapshot_state();
        uncovered
            .rotate_consensus_snapshot_after_boundary(900)
            .unwrap();
        uncovered
            .consensus_snapshots
            .retain(|snapshot| snapshot.activation_height == 901);
        assert_eq!(
            uncovered.snapshot_for_consensus_height(601),
            Err(ConsensusSnapshotLookupError::NoSnapshotForHeight { height: 601 })
        );

        let mut empty = snapshot_state();
        empty.consensus_snapshots.clear();
        assert!(matches!(
            empty.snapshot_for_consensus_height(601),
            Err(ConsensusSnapshotLookupError::InvalidRetainedState { .. })
        ));
    }

    #[test]
    fn snapshot_lookup_api_returns_definitive_result_without_fallback_value() {
        fn compile_time_api_shape(
            state: &ChainState,
            height: u64,
        ) -> Result<&ConsensusSnapshot, crate::error::ConsensusSnapshotLookupError> {
            state.snapshot_for_consensus_height(height)
        }

        let state = snapshot_state();
        let result = compile_time_api_shape(&state, 0);
        assert!(result.is_err());
        assert!(state.validators.active_count() > 0);
        // A populated live validator registry neither changes the error nor
        // appears anywhere in the lookup return type.
    }

    #[test]
    fn genesis_consensus_snapshot_uses_active_genesis_set_at_height_one() {
        let state = snapshot_state();
        let snapshot = state.build_genesis_consensus_snapshot().unwrap();
        assert_eq!(snapshot.activation_height, 1);
        assert_eq!(snapshot.source_boundary_height, 0);
        assert_eq!(snapshot.entries().len(), 2);
        assert_eq!(snapshot.entries()[0].validator_id, Bytes32::from([1; 32]));
        assert_eq!(snapshot.entries()[1].validator_id, Bytes32::from([2; 32]));
        assert_eq!(snapshot.total_weight_spark, 5_000_000_000);
    }

    #[test]
    fn consensus_snapshot_pruning_is_deterministic_across_boundaries() {
        fn execute() -> ChainState {
            let mut state = snapshot_state();
            for boundary in [300, 600, 900, 1_200] {
                state
                    .rotate_consensus_snapshot_after_boundary(boundary)
                    .unwrap();
            }
            state
        }

        let first = execute();
        let second = execute();
        assert_eq!(first.consensus_snapshots, second.consensus_snapshots);
        assert_eq!(
            first
                .consensus_snapshots
                .iter()
                .map(|snapshot| snapshot.activation_height)
                .collect::<Vec<_>>(),
            vec![901, 1_201]
        );
    }

    #[test]
    fn full_consensus_snapshot_replay_matches_independent_reference() {
        let mut reference = snapshot_state();
        reference
            .validators
            .upsert(snapshot_validator(3, 31, 3_000_000_000))
            .unwrap();
        reference
            .validators
            .get_mut(&Bytes32::from([1; 32]))
            .unwrap()
            .stake_spark = 4_000_000_000;
        reference
            .rotate_consensus_snapshot_after_boundary(300)
            .unwrap();

        // Scenario A as a legitimate historical operation: C gains stake after
        // the old authority was fixed. The snapshot governing that interval
        // must remain byte-for-byte unchanged.
        let first_root = reference.consensus_snapshots[0].snapshot_root;
        reference
            .validators
            .get_mut(&Bytes32::from([3; 32]))
            .unwrap()
            .stake_spark = 14_000_000_000;
        assert_eq!(reference.consensus_snapshots[0].snapshot_root, first_root);

        // Change membership before the next boundary.
        reference
            .validators
            .get_mut(&Bytes32::from([2; 32]))
            .unwrap()
            .status = crate::validator::ValidatorStatus::Registered;
        reference
            .validators
            .upsert(snapshot_validator(4, 41, 5_000_000_000))
            .unwrap();
        reference
            .rotate_consensus_snapshot_after_boundary(600)
            .unwrap();

        // Scenario B as a legitimate historical operation: A inflates stake
        // within the interval, but cannot rewrite the already-active snapshot.
        let second_root = reference.consensus_snapshots[1].snapshot_root;
        reference
            .validators
            .get_mut(&Bytes32::from([1; 32]))
            .unwrap()
            .stake_spark = 20_000_000_000;
        assert_eq!(reference.consensus_snapshots[1].snapshot_root, second_root);
        reference
            .validators
            .get_mut(&Bytes32::from([3; 32]))
            .unwrap()
            .status = crate::validator::ValidatorStatus::Registered;
        reference
            .rotate_consensus_snapshot_after_boundary(900)
            .unwrap();
        reference.height = u64::MAX;
        reference.tip_hash = Bytes32::from([0xF0; 32]);
        reference.rebuild_state_commitment_v2(reference.height);

        // Independently replay the same historical event transcript from
        // genesis rather than cloning the reference state.
        let mut replayed = snapshot_state();
        replayed
            .validators
            .upsert(snapshot_validator(3, 31, 3_000_000_000))
            .unwrap();
        enum Event {
            Stake(u8, u64),
            Status(u8, crate::validator::ValidatorStatus),
            Add(ValidatorEntry),
            Boundary(u64),
        }
        let events = vec![
            Event::Stake(1, 4_000_000_000),
            Event::Boundary(300),
            Event::Stake(3, 14_000_000_000),
            Event::Status(2, crate::validator::ValidatorStatus::Registered),
            Event::Add(snapshot_validator(4, 41, 5_000_000_000)),
            Event::Boundary(600),
            Event::Stake(1, 20_000_000_000),
            Event::Status(3, crate::validator::ValidatorStatus::Registered),
            Event::Boundary(900),
        ];
        for event in events {
            match event {
                Event::Stake(id, stake) => {
                    replayed
                        .validators
                        .get_mut(&Bytes32::from([id; 32]))
                        .unwrap()
                        .stake_spark = stake;
                }
                Event::Status(id, status) => {
                    replayed
                        .validators
                        .get_mut(&Bytes32::from([id; 32]))
                        .unwrap()
                        .status = status;
                }
                Event::Add(validator) => replayed.validators.upsert(validator).unwrap(),
                Event::Boundary(height) => {
                    replayed
                        .rotate_consensus_snapshot_after_boundary(height)
                        .unwrap();
                }
            }
        }
        replayed.height = u64::MAX;
        replayed.tip_hash = Bytes32::from([0xF0; 32]);
        replayed.rebuild_state_commitment_v2(replayed.height);

        assert_eq!(reference.consensus_snapshots.len(), 2);
        assert_eq!(reference.consensus_snapshots, replayed.consensus_snapshots);
        assert_eq!(
            reference.reward_economic_snapshot,
            replayed.reward_economic_snapshot
        );
        assert_eq!(reference.encode_to_vec(), replayed.encode_to_vec());
        assert_eq!(
            crate::compute_state_root(&reference),
            crate::compute_state_root(&replayed)
        );
        assert_eq!(reference, replayed);
    }

    #[test]
    fn genesis_has_no_blocks() {
        assert!(!ChainState::new_genesis().has_blocks());
    }

    #[test]
    fn genesis_epoch_is_zero() {
        assert_eq!(ChainState::new_genesis().current_epoch(), 0);
    }

    fn test_hybrid_pubkey(byte: u8) -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::from([byte; 32]),
            pq_pk: VariableBytes::from_slice(&vec![byte.wrapping_add(1); 2_592]).unwrap(),
        }
    }

    fn encode_nonce_map_btree(nonces: &BTreeMap<Bytes32, u64>, buf: &mut Vec<u8>) {
        (nonces.len() as u32).encode(buf);
        for (signer_id, nonce) in nonces {
            signer_id.encode(buf);
            nonce.encode(buf);
        }
    }

    fn encode_hash_set_hashset(hashes: &HashSet<Bytes32>, buf: &mut Vec<u8>) {
        let mut entries: Vec<_> = hashes.iter().copied().collect();
        entries.sort_by_key(|hash| hash.0);
        (entries.len() as u32).encode(buf);
        for hash in entries {
            hash.encode(buf);
        }
    }

    #[test]
    fn staking_nonce_decode_cap_is_derived_from_staking_signer_capacity() {
        let old_placeholder_cap = MAX_VALIDATORS.saturating_mul(100);
        assert!(
            MAX_STAKING_NONCES_DECODE > old_placeholder_cap,
            "corrected cap must accept signer nonce counts above the old validator-only placeholder"
        );
        assert_eq!(
            MAX_STAKING_NONCES_DECODE,
            MAX_VALIDATORS.saturating_add(
                MAX_VALIDATORS.saturating_mul(crate::validator::MAX_DELEGATORS_PER_VALIDATOR)
            )
        );
        assert!(validate_nonce_map_count(old_placeholder_cap + 1).is_ok());
    }

    #[test]
    fn staking_nonce_decode_no_longer_rejects_count_above_old_placeholder_cap() {
        let old_placeholder_cap = MAX_VALIDATORS.saturating_mul(100);
        let mut bytes = Vec::new();
        ((old_placeholder_cap + 1) as u32).encode(&mut bytes);

        let err = decode_nonce_map(&mut ByteReader::new(&bytes)).unwrap_err();
        assert!(
            matches!(err, IndraError::UnexpectedEof { .. }),
            "count above old placeholder cap should pass the staking_nonces cap guard and fail only because this synthetic stream has no entries; got {err:?}"
        );
    }

    #[test]
    fn staking_nonce_decode_rejects_count_above_corrected_cap_cleanly() {
        let mut bytes = Vec::new();
        ((MAX_STAKING_NONCES_DECODE + 1) as u32).encode(&mut bytes);

        let err = decode_nonce_map(&mut ByteReader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            IndraError::LengthExceeded {
                field: "snapshot.staking_nonces",
                max: MAX_STAKING_NONCES_DECODE,
                actual
            } if actual == MAX_STAKING_NONCES_DECODE + 1
        ));
    }

    #[test]
    fn staking_nonce_encode_decode_round_trip_uses_same_cap_path() {
        let mut nonces = PersistentOrdMap::new();
        nonces.insert(Bytes32::from([0xA1; 32]), 7);
        nonces.insert(Bytes32::from([0xD1; 32]), 11);

        let mut bytes = Vec::new();
        encode_nonce_map(&nonces, &mut bytes);
        let decoded = decode_nonce_map(&mut ByteReader::new(&bytes)).unwrap();
        assert_eq!(decoded, nonces);
    }

    #[test]
    fn staking_nonce_persistent_encoding_matches_legacy_btree_encoding() {
        let legacy = BTreeMap::from([
            (Bytes32::from([0xD1; 32]), 11),
            (Bytes32::from([0xA1; 32]), 7),
            (Bytes32::from([0xB1; 32]), 9),
        ]);
        let mut persistent = PersistentOrdMap::new();
        for (key, value) in [
            (Bytes32::from([0xD1; 32]), 11),
            (Bytes32::from([0xA1; 32]), 7),
            (Bytes32::from([0xB1; 32]), 9),
        ] {
            persistent.insert(key, value);
        }

        let mut legacy_bytes = Vec::new();
        encode_nonce_map_btree(&legacy, &mut legacy_bytes);
        let mut persistent_bytes = Vec::new();
        encode_nonce_map(&persistent, &mut persistent_bytes);
        assert_eq!(persistent_bytes, legacy_bytes);
    }

    #[test]
    fn staking_nonce_persistent_encoding_is_insertion_order_independent() {
        let mut forward = PersistentOrdMap::new();
        let mut reverse = PersistentOrdMap::new();
        for byte in [0x01, 0x02, 0x03, 0x04] {
            forward.insert(Bytes32::from([byte; 32]), byte as u64);
        }
        for byte in [0x04, 0x03, 0x02, 0x01] {
            reverse.insert(Bytes32::from([byte; 32]), byte as u64);
        }

        let mut forward_bytes = Vec::new();
        encode_nonce_map(&forward, &mut forward_bytes);
        let mut reverse_bytes = Vec::new();
        encode_nonce_map(&reverse, &mut reverse_bytes);
        assert_eq!(forward_bytes, reverse_bytes);
    }

    #[test]
    fn delegator_identity_registry_insert_lookup_contains() {
        let mut registry = PersistentOrdMap::new();
        let delegator_id = Bytes32::from([0xD1; 32]);
        let pubkey = test_hybrid_pubkey(0x11);

        assert!(registry.is_empty());
        assert!(!registry.contains_key(&delegator_id));
        assert_eq!(registry.insert(delegator_id, pubkey.clone()), None);
        assert_eq!(registry.len(), 1);
        assert!(registry.contains_key(&delegator_id));
        assert_eq!(registry.get(&delegator_id), Some(&pubkey));

        let replacement = test_hybrid_pubkey(0x22);
        assert_eq!(
            registry.insert(delegator_id, replacement.clone()),
            Some(pubkey)
        );
        assert_eq!(registry.get(&delegator_id), Some(&replacement));
    }

    #[test]
    fn delegator_identity_registry_round_trips_empty_small_and_realistic_scale() {
        for size in [0usize, 3, 2_000] {
            let mut registry = PersistentOrdMap::new();
            for index in 0..size {
                let mut id = [0u8; 32];
                id[0] = 0xD0;
                id[8..16].copy_from_slice(&(index as u64).to_be_bytes());
                registry.insert(Bytes32::from(id), test_hybrid_pubkey(index as u8));
            }

            let mut bytes = Vec::new();
            encode_delegator_identity_registry(&registry, &mut bytes);
            assert_eq!(
                bytes.len(),
                delegator_identity_registry_encoded_len(&registry)
            );
            let decoded = decode_delegator_identity_registry(&mut ByteReader::new(&bytes)).unwrap();
            assert_eq!(decoded, registry);
        }
    }

    #[test]
    fn delegator_identity_registry_encoding_is_insertion_order_independent() {
        let mut forward = PersistentOrdMap::new();
        let mut reverse = PersistentOrdMap::new();
        for byte in [0x01, 0x02, 0x03, 0x04] {
            forward.insert(Bytes32::from([byte; 32]), test_hybrid_pubkey(byte));
        }
        for byte in [0x04, 0x03, 0x02, 0x01] {
            reverse.insert(Bytes32::from([byte; 32]), test_hybrid_pubkey(byte));
        }

        let mut forward_bytes = Vec::new();
        encode_delegator_identity_registry(&forward, &mut forward_bytes);
        let mut reverse_bytes = Vec::new();
        encode_delegator_identity_registry(&reverse, &mut reverse_bytes);
        assert_eq!(forward_bytes, reverse_bytes);
        assert_eq!(
            forward
                .iter()
                .map(|(delegator_id, _)| delegator_id.0[0])
                .collect::<Vec<_>>(),
            vec![0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn delegator_identity_registry_decode_rejects_duplicate_ids() {
        let delegator_id = Bytes32::from([0xD1; 32]);
        let mut bytes = Vec::new();
        2u32.encode(&mut bytes);
        delegator_id.encode(&mut bytes);
        test_hybrid_pubkey(0x11).encode(&mut bytes);
        delegator_id.encode(&mut bytes);
        test_hybrid_pubkey(0x22).encode(&mut bytes);

        let err = decode_delegator_identity_registry(&mut ByteReader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            IndraError::DuplicateEntries {
                field: "snapshot.delegator_identities"
            }
        ));
    }

    #[test]
    fn applied_slash_hash_persistent_encoding_matches_legacy_hashset_encoding() {
        let mut legacy = HashSet::new();
        let mut persistent = PersistentOrdSet::new();
        for byte in [0x03, 0x01, 0x02, 0x04] {
            let hash = Bytes32::from([byte; 32]);
            legacy.insert(hash);
            persistent.insert(hash);
        }

        let mut legacy_bytes = Vec::new();
        encode_hash_set_hashset(&legacy, &mut legacy_bytes);
        let mut persistent_bytes = Vec::new();
        encode_hash_set(&persistent, &mut persistent_bytes);
        assert_eq!(persistent_bytes, legacy_bytes);

        let decoded = decode_hash_set(
            &mut ByteReader::new(&persistent_bytes),
            "snapshot.applied_slash_hashes",
        )
        .unwrap();
        assert_eq!(decoded, persistent);
    }

    #[test]
    fn applied_slash_hash_persistent_encoding_is_insertion_order_independent() {
        let mut forward = PersistentOrdSet::new();
        let mut reverse = PersistentOrdSet::new();
        for byte in [0x01, 0x02, 0x03, 0x04] {
            forward.insert(Bytes32::from([byte; 32]));
        }
        for byte in [0x04, 0x03, 0x02, 0x01] {
            reverse.insert(Bytes32::from([byte; 32]));
        }

        let mut forward_bytes = Vec::new();
        encode_hash_set(&forward, &mut forward_bytes);
        let mut reverse_bytes = Vec::new();
        encode_hash_set(&reverse, &mut reverse_bytes);
        assert_eq!(forward_bytes, reverse_bytes);
    }
}
