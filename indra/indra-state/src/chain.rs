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
use indra_crypto::PaymentPubKeyV1;

use indra_core::types::primitives::hard_forks::CONSENSUS_SNAPSHOT_HEIGHT;
use indra_core::types::primitives::{
    consensus_snapshot_active, state_commitment_v2_active, Bytes32, VariableBytes,
    DEFAULT_CHAIN_ID, EPOCH_DURATION_BLOCKS, GENESIS_SUPPLY_SPARK, INITIAL_BASE_FEE_SPARK_PER_KB,
    MAX_CHAIN_ID_BYTES, MAX_DELEGATION_RETURN_EVENTS,
};

use crate::{
    governance::GovernanceState,
    nullifier::NullifierSet,
    persistent::{PersistentOrdMap, PersistentOrdSet},
    state_commitment::StateCommitmentV2,
    utxo::UtxoSet,
    validator::{
        decode_delegation_return_events, delegation_return_events_encoded_len,
        encode_delegation_return_events, DelegationMap, DelegationReturnEvent, StakeBondEntry,
        ValidatorSet,
    },
};

/// Defensive snapshot decode ceiling for staked-bond entries.
///
/// This must not be lower than the validator/delegator state that the protocol
/// itself can accept: every retained delegator position may have at least one
/// corresponding bonded UTXO. The guard remains finite so corrupted snapshots
/// cannot request unbounded decode work.
pub const MAX_STAKED_BONDS_DECODE: usize = indra_core::types::primitives::MAX_VALIDATORS
    .saturating_mul(crate::validator::MAX_DELEGATORS_PER_VALIDATOR);

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

    /// All spent nullifiers (double-spend guard).
    pub nullifiers: NullifierSet,

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

    /// Delegation map: validator_id → delegator entries.
    pub delegations: DelegationMap,

    /// Stake bonds: UTXOs locked as delegation stake.
    pub staked_bonds: PersistentOrdMap<Bytes32, StakeBondEntry>,

    /// Monotonic nonces for staking op replay protection.
    pub staking_nonces: PersistentOrdMap<Bytes32, u64>,

    /// Canonical full public key for each post-activation delegator identity.
    pub delegator_identities: PersistentOrdMap<Bytes32, HybridPubKey>,

    /// Canonical payment key-exchange public key for each payment owner identity.
    pub payment_identities: PersistentOrdMap<Bytes32, PaymentPubKeyV1>,

    /// Permanently retired cold Ed25519 public-key components.
    pub retired_cold_classical_components: PersistentOrdSet<[u8; 32]>,

    /// Permanently retired cold ML-DSA-87 public-key components.
    pub retired_cold_pq_components: PersistentOrdSet<[u8; indra_crypto::PQ_PK_BYTES]>,

    /// Hashes of applied slash evidence — prevents double-slash.
    /// Key: SHA-256(encode(SlashEvidenceV1))
    pub applied_slash_hashes: PersistentOrdSet<Bytes32>,

    /// On-chain governance state.
    pub governance: GovernanceState,

    /// Bounded rolling log of automatic delegation principal returns.
    ///
    /// This is consensus-visible after the registered-validator-cap activation
    /// so delegators can discover forced returns caused by validator eviction.
    pub delegation_return_events: Vec<DelegationReturnEvent>,

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
        // Included: nullifiers are the double-spend guard and cannot be reconstructed from summaries.
        self.nullifiers.encode(buf);
        // Included: validator metadata is needed for proposer election and signature/QC verification.
        self.validators.encode(buf);
        // Included: delegations affect validator power and epoch transitions.
        self.delegations.encode(buf);
        // Included: stake bonds lock UTXOs and drive delegation/unbonding state.
        encode_bond_map(&self.staked_bonds, buf);
        encode_nonce_map(&self.staking_nonces, buf);
        encode_hash_set(&self.applied_slash_hashes, buf);
        self.governance.encode(buf);
        encode_delegation_return_events(&self.delegation_return_events, buf);
        let retired_present = !self.retired_cold_classical_components.is_empty()
            || !self.retired_cold_pq_components.is_empty();
        let snapshot_present = consensus_snapshot_active(self.height);
        if !self.delegator_identities.is_empty()
            || !self.payment_identities.is_empty()
            || retired_present
            || snapshot_present
        {
            encode_delegator_identity_registry(&self.delegator_identities, buf);
        }
        if !self.payment_identities.is_empty() || retired_present || snapshot_present {
            encode_payment_identity_registry(&self.payment_identities, buf);
        }
        if retired_present || snapshot_present {
            encode_retired_cold_components(
                &self.retired_cold_classical_components,
                &self.retired_cold_pq_components,
                buf,
            );
        }
        if consensus_snapshot_active(self.height) {
            encode_list(&self.consensus_snapshots, buf);
            self.reward_economic_snapshot.is_some().encode(buf);
            if let Some(snapshot) = &self.reward_economic_snapshot {
                snapshot.encode(buf);
            }
        }
        if indra_core::types::primitives::slash_membership_proof_active(self.height) {
            encode_list(&self.slash_membership_roots, buf);
        }
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
            + self.nullifiers.encoded_len()
            + self.validators.encoded_len()
            + self.delegations.encoded_len()
            + bond_map_encoded_len(&self.staked_bonds)
            + nonce_map_encoded_len(&self.staking_nonces)
            + hash_set_encoded_len(&self.applied_slash_hashes)
            + self.governance.encoded_len()
            + delegation_return_events_encoded_len(&self.delegation_return_events)
            + if self.delegator_identities.is_empty()
                && self.payment_identities.is_empty()
                && self.retired_cold_classical_components.is_empty()
                && self.retired_cold_pq_components.is_empty()
                && !consensus_snapshot_active(self.height)
            {
                0
            } else {
                delegator_identity_registry_encoded_len(&self.delegator_identities)
            }
            + if self.payment_identities.is_empty()
                && self.retired_cold_classical_components.is_empty()
                && self.retired_cold_pq_components.is_empty()
                && !consensus_snapshot_active(self.height)
            {
                0
            } else {
                payment_identity_registry_encoded_len(&self.payment_identities)
            }
            + if consensus_snapshot_active(self.height) {
                8 + self.retired_cold_classical_components.len() * 32
                    + self.retired_cold_pq_components.len() * indra_crypto::PQ_PK_BYTES
            } else {
                retired_cold_components_encoded_len(
                    &self.retired_cold_classical_components,
                    &self.retired_cold_pq_components,
                )
            }
            + if consensus_snapshot_active(self.height) {
                list_encoded_len(&self.consensus_snapshots)
                    + 1
                    + self
                        .reward_economic_snapshot
                        .as_ref()
                        .map(Encode::encoded_len)
                        .unwrap_or(0)
            } else {
                0
            }
            + if indra_core::types::primitives::slash_membership_proof_active(self.height) {
                list_encoded_len(&self.slash_membership_roots)
            } else {
                0
            }
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
        let nullifiers = NullifierSet::decode_at_height(r, height)?;
        let validators = ValidatorSet::decode(r)?;
        let delegations = DelegationMap::decode(r)?;
        let staked_bonds = decode_bond_map(r)?;
        let staking_nonces = decode_nonce_map(r)?;
        let applied_slash_hashes = decode_hash_set(r, "snapshot.applied_slash_hashes")?;
        let governance = GovernanceState::decode(r)?;
        let delegation_return_events = if r.remaining() > 0 {
            decode_delegation_return_events(r)?
        } else {
            Vec::new()
        };
        let delegator_identities = if r.remaining() > 0 {
            decode_delegator_identity_registry(r)?
        } else {
            PersistentOrdMap::new()
        };
        let payment_identities = if r.remaining() > 0 {
            decode_payment_identity_registry(r)?
        } else {
            PersistentOrdMap::new()
        };
        let (retired_cold_classical_components, retired_cold_pq_components) = if r.remaining() > 0 {
            decode_retired_cold_components(r)?
        } else {
            (PersistentOrdSet::new(), PersistentOrdSet::new())
        };
        let consensus_snapshots = if consensus_snapshot_active(height) {
            let snapshots = decode_list(r, 2, "chain_state.consensus_snapshots")?;
            validate_consensus_snapshot_collection(&snapshots, height)?;
            snapshots
        } else {
            Vec::new()
        };
        let reward_economic_snapshot = if consensus_snapshot_active(height) {
            if bool::decode(r)? {
                Some(RewardEconomicSnapshot::decode(r)?)
            } else {
                None
            }
        } else {
            None
        };
        validate_reward_economic_pairing(
            &consensus_snapshots,
            reward_economic_snapshot.as_ref(),
            height,
        )?;
        let slash_membership_roots =
            if indra_core::types::primitives::slash_membership_proof_active(height) {
                let roots = decode_list(
                    r,
                    MAX_SLASH_MEMBERSHIP_ROOT_RECORDS,
                    "chain_state.slash_membership_roots",
                )?;
                validate_slash_membership_root_history(&roots, height)?;
                for snapshot in &consensus_snapshots {
                    if snapshot.activation_height
                        >= indra_core::types::primitives::hard_forks::SLASH_MEMBERSHIP_PROOF_HEIGHT
                    {
                        let record = roots
                            .iter()
                            .find(|record| record.activation_height == snapshot.activation_height)
                            .ok_or_else(|| {
                                IndraError::InvalidSlashMembershipProof(
                                    "retained full snapshot has no matching membership root"
                                        .to_string(),
                                )
                            })?;
                        if compute_slash_membership_root(snapshot)? != record.membership_root {
                            return Err(IndraError::InvalidSlashMembershipProof(
                                "retained full snapshot membership root mismatch".to_string(),
                            ));
                        }
                    }
                }
                roots
            } else {
                Vec::new()
            };
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
            nullifiers,
            validators,
            consensus_snapshots,
            reward_economic_snapshot,
            slash_membership_roots,
            delegations,
            staked_bonds,
            staking_nonces,
            delegator_identities,
            payment_identities,
            retired_cold_classical_components,
            retired_cold_pq_components,
            applied_slash_hashes,
            governance,
            delegation_return_events,
            state_commitment_v2: None,
            epoch_fees_burned: 0,
            epoch_slashed_spark: 0,
            epoch_slash_event_count: 0,
        })
    }
}

impl ChainState {
    /// Sum active delegated principal from authoritative bond records.
    pub fn total_active_delegated_bond_stake(&self) -> u64 {
        self.staked_bonds
            .values()
            .filter(|bond| {
                bond.validator_id != bond.delegator_id && bond.unbonding_end_epoch.is_none()
            })
            .fold(0u64, |sum, bond| sum.saturating_add(bond.amount_spark))
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
            nullifiers: NullifierSet::new(),
            validators: ValidatorSet::new(),
            consensus_snapshots: Vec::new(),
            reward_economic_snapshot: None,
            slash_membership_roots: Vec::new(),
            delegations: DelegationMap::new(),
            staked_bonds: PersistentOrdMap::new(),
            staking_nonces: PersistentOrdMap::new(),
            delegator_identities: PersistentOrdMap::new(),
            payment_identities: PersistentOrdMap::new(),
            retired_cold_classical_components: PersistentOrdSet::new(),
            retired_cold_pq_components: PersistentOrdSet::new(),
            applied_slash_hashes: PersistentOrdSet::new(),
            governance: GovernanceState::new(),
            delegation_return_events: Vec::new(),
            state_commitment_v2: None,
            epoch_fees_burned: 0,
            epoch_slashed_spark: 0,
            epoch_slash_event_count: 0,
        }
    }

    /// Decode a legacy unversioned snapshot payload at the supplied schema version.
    pub fn decode_legacy_snapshot(r: &mut ByteReader<'_>, schema_version: u8) -> IndraResult<Self> {
        let chain_id_bytes = VariableBytes::<MAX_CHAIN_ID_BYTES>::decode(r)?;
        let chain_id = String::from_utf8(chain_id_bytes.as_slice().to_vec())
            .unwrap_or_else(|_| DEFAULT_CHAIN_ID.to_string());
        let height = u64::decode(r)?;
        Ok(Self {
            chain_id,
            height,
            tip_hash: Bytes32::decode(r)?,
            base_fee: u64::decode(r)?,
            total_supply: u64::decode(r)?,
            treasury_balance: u64::decode(r)?,
            burn_buffer: u64::decode(r)?,
            fee_reward_pool: u64::decode(r)?,
            utxos: UtxoSet::decode_legacy_at_height(r, height)?,
            nullifiers: NullifierSet::decode_at_height(r, height)?,
            validators: ValidatorSet::decode_legacy(r, schema_version)?,
            consensus_snapshots: Vec::new(),
            reward_economic_snapshot: None,
            slash_membership_roots: Vec::new(),
            delegations: DelegationMap::decode_legacy(r)?,
            staked_bonds: decode_bond_map_legacy(r)?,
            staking_nonces: decode_nonce_map(r)?,
            delegator_identities: PersistentOrdMap::new(),
            payment_identities: PersistentOrdMap::new(),
            retired_cold_classical_components: PersistentOrdSet::new(),
            retired_cold_pq_components: PersistentOrdSet::new(),
            applied_slash_hashes: if r.remaining() > 0 {
                decode_hash_set(r, "snapshot.applied_slash_hashes")?
            } else {
                PersistentOrdSet::new()
            },
            governance: GovernanceState::new(),
            delegation_return_events: Vec::new(),
            state_commitment_v2: None,
            epoch_fees_burned: 0,
            epoch_slashed_spark: 0,
            epoch_slash_event_count: 0,
        })
    }

    /// Decode a schema-v2 versioned snapshot payload that predates governance.
    pub fn decode_schema_v2_snapshot(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        let chain_id_bytes = VariableBytes::<MAX_CHAIN_ID_BYTES>::decode(r)?;
        let chain_id = String::from_utf8(chain_id_bytes.as_slice().to_vec())
            .unwrap_or_else(|_| DEFAULT_CHAIN_ID.to_string());
        let height = u64::decode(r)?;
        Ok(Self {
            chain_id,
            height,
            tip_hash: Bytes32::decode(r)?,
            base_fee: u64::decode(r)?,
            total_supply: u64::decode(r)?,
            treasury_balance: u64::decode(r)?,
            burn_buffer: u64::decode(r)?,
            fee_reward_pool: u64::decode(r)?,
            utxos: UtxoSet::decode_at_height(r, height)?,
            nullifiers: NullifierSet::decode_at_height(r, height)?,
            validators: ValidatorSet::decode(r)?,
            consensus_snapshots: Vec::new(),
            reward_economic_snapshot: None,
            slash_membership_roots: Vec::new(),
            delegations: DelegationMap::decode(r)?,
            staked_bonds: decode_bond_map(r)?,
            staking_nonces: decode_nonce_map(r)?,
            delegator_identities: PersistentOrdMap::new(),
            payment_identities: PersistentOrdMap::new(),
            retired_cold_classical_components: PersistentOrdSet::new(),
            retired_cold_pq_components: PersistentOrdSet::new(),
            applied_slash_hashes: decode_hash_set(r, "snapshot.applied_slash_hashes")?,
            governance: GovernanceState::new(),
            delegation_return_events: Vec::new(),
            state_commitment_v2: None,
            epoch_fees_burned: 0,
            epoch_slashed_spark: 0,
            epoch_slash_event_count: 0,
        })
    }

    /// Ensure the derived StateCommitmentV2 cache exists when the V2 root rule
    /// is active at `height`.
    pub fn ensure_state_commitment_v2(&mut self, height: u64) {
        let crossing_snapshot_gate =
            consensus_snapshot_active(height) && !consensus_snapshot_active(self.height);
        if state_commitment_v2_active(height)
            && (self.state_commitment_v2.is_none() || crossing_snapshot_gate)
        {
            self.state_commitment_v2 = Some(StateCommitmentV2::from_state(self, height));
        }
    }

    /// Rebuild the derived StateCommitmentV2 cache from canonical state.
    pub fn rebuild_state_commitment_v2(&mut self, height: u64) {
        self.state_commitment_v2 = Some(StateCommitmentV2::from_state(self, height));
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
    /// height not greater than `height`. Pre-gate callers receive an explicit
    /// error and must remain on the separate legacy consensus path.
    pub fn snapshot_for_consensus_height(
        &self,
        height: u64,
    ) -> Result<&ConsensusSnapshot, crate::error::ConsensusSnapshotLookupError> {
        self.snapshot_for_consensus_height_at_gate(height, CONSENSUS_SNAPSHOT_HEIGHT)
    }

    fn snapshot_for_consensus_height_at_gate(
        &self,
        height: u64,
        gate_height: u64,
    ) -> Result<&ConsensusSnapshot, crate::error::ConsensusSnapshotLookupError> {
        use crate::error::ConsensusSnapshotLookupError;

        if height < gate_height {
            return Err(ConsensusSnapshotLookupError::PreGateHeight {
                height,
                gate_height,
            });
        }
        validate_retained_consensus_snapshots_for_lookup(&self.consensus_snapshots)?;
        self.consensus_snapshots
            .iter()
            .rev()
            .find(|snapshot| snapshot.activation_height <= height)
            .ok_or(ConsensusSnapshotLookupError::NoSnapshotForHeight { height })
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

    /// Build the epoch-start reward basis paired exactly with `consensus_snapshot`.
    pub fn build_reward_economic_snapshot(
        &self,
        consensus_snapshot: &ConsensusSnapshot,
    ) -> crate::error::StateResult<RewardEconomicSnapshot> {
        use std::collections::BTreeMap;

        let mut principals: BTreeMap<Bytes32, BTreeMap<Bytes32, (u64, u64)>> = BTreeMap::new();
        for member in consensus_snapshot.entries() {
            principals.insert(member.validator_id, BTreeMap::new());
        }

        // Real delegation is derived only from authoritative active bond records.
        for bond in self.staked_bonds.values().filter(|bond| {
            bond.validator_id != bond.delegator_id && bond.unbonding_end_epoch.is_none()
        }) {
            if let Some(delegators) = principals.get_mut(&bond.validator_id) {
                let (bonded, _) = delegators.entry(bond.delegator_id).or_default();
                *bonded = bonded.checked_add(bond.amount_spark).ok_or_else(|| {
                    crate::error::StateError::InvalidRewardEconomicSnapshot(
                        "bonded delegator principal overflows u64".to_string(),
                    )
                })?;
            }
        }

        // Virtual auto-delegation is frozen separately because it is credited
        // to ValidatorEntry.pending_rewards, never DelegatorEntry.pending_rewards.
        for source in self.validators.all_validators().filter(|validator| {
            matches!(
                validator.status,
                crate::validator::ValidatorStatus::Registered
            ) && validator.auto_delegate_to.is_some()
                && validator.stake_spark > 0
        }) {
            let target_id = source.auto_delegate_to.expect("filter checked target");
            if let Some(delegators) = principals.get_mut(&target_id) {
                let (_, auto) = delegators.entry(source.validator_id).or_default();
                *auto = auto.checked_add(source.stake_spark).ok_or_else(|| {
                    crate::error::StateError::InvalidRewardEconomicSnapshot(
                        "auto-delegated principal overflows u64".to_string(),
                    )
                })?;
            }
        }

        let frozen_bound = self.governance.params.max_commission_bps;
        let mut validators = Vec::with_capacity(consensus_snapshot.entries().len());
        for member in consensus_snapshot.entries() {
            let validator = self.validators.get(&member.validator_id).ok_or_else(|| {
                crate::error::StateError::InvalidRewardEconomicSnapshot(format!(
                    "consensus member {} missing from validator registry",
                    member.validator_id
                ))
            })?;
            let delegators = principals
                .remove(&member.validator_id)
                .unwrap_or_default()
                .into_iter()
                .map(|(delegator_id, (bonded, auto))| {
                    RewardEconomicDelegatorEntry::new(delegator_id, bonded, auto).map_err(|error| {
                        crate::error::StateError::InvalidRewardEconomicSnapshot(error.to_string())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            validators.push(
                RewardEconomicValidatorEntry::new(
                    member.validator_id,
                    validator.commission_bps,
                    delegators,
                    frozen_bound,
                )
                .map_err(|error| {
                    crate::error::StateError::InvalidRewardEconomicSnapshot(error.to_string())
                })?,
            );
        }
        RewardEconomicSnapshot::new(
            consensus_snapshot.activation_height,
            consensus_snapshot.source_boundary_height,
            frozen_bound,
            validators,
        )
        .map_err(|error| crate::error::StateError::InvalidRewardEconomicSnapshot(error.to_string()))
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

    /// Install the genesis snapshot when the global gate is configured at height 1.
    pub fn initialize_genesis_consensus_snapshot(&mut self) -> crate::error::StateResult<()> {
        if !consensus_snapshot_active(1) {
            return Ok(());
        }
        if self.height != 0 || !self.consensus_snapshots.is_empty() {
            return Err(crate::error::StateError::InvalidConsensusSnapshot(
                "genesis snapshot initialization requires pristine height-zero snapshot state"
                    .to_string(),
            ));
        }
        let snapshot = self.build_genesis_consensus_snapshot()?;
        let economic = self.build_reward_economic_snapshot(&snapshot)?;
        self.install_consensus_snapshot(snapshot)?;
        self.reward_economic_snapshot = Some(economic);
        if state_commitment_v2_active(1) {
            self.rebuild_state_commitment_v2(1);
        }
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
        let activation_height = boundary_height.checked_add(1).ok_or_else(|| {
            crate::error::StateError::InvalidConsensusSnapshot(
                "snapshot activation height overflow".to_string(),
            )
        })?;
        if !consensus_snapshot_active(activation_height) {
            return Ok(());
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
        let membership_record = if activation_height
            > indra_core::types::primitives::hard_forks::SLASH_MEMBERSHIP_PROOF_HEIGHT
        {
            Some(SlashMembershipRootRecord {
                activation_height,
                membership_root: compute_slash_membership_root(&snapshot).map_err(|error| {
                    crate::error::StateError::InvalidConsensusSnapshot(error.to_string())
                })?,
            })
        } else {
            None
        };
        self.install_consensus_snapshot(snapshot)?;
        self.reward_economic_snapshot = Some(economic);
        if let Some(record) = membership_record {
            self.append_slash_membership_root(record)?;
            self.prune_slash_membership_roots(boundary_height)?;
        }
        Ok(())
    }

    /// Insert the bootstrap root into block `G` post-state.
    pub(crate) fn bootstrap_slash_membership_root(
        &mut self,
        height: u64,
    ) -> crate::error::StateResult<()> {
        use indra_core::types::primitives::hard_forks::SLASH_MEMBERSHIP_PROOF_HEIGHT;
        if height != SLASH_MEMBERSHIP_PROOF_HEIGHT {
            return Ok(());
        }
        if !self.slash_membership_roots.is_empty() {
            return Err(crate::error::StateError::InvalidConsensusSnapshot(
                "slash membership bootstrap requires empty root history".to_string(),
            ));
        }
        let snapshot = self
            .consensus_snapshots
            .iter()
            .find(|snapshot| snapshot.activation_height == height)
            .ok_or_else(|| {
                crate::error::StateError::InvalidConsensusSnapshot(
                    "slash membership bootstrap snapshot is missing".to_string(),
                )
            })?;
        let record = SlashMembershipRootRecord {
            activation_height: height,
            membership_root: compute_slash_membership_root(snapshot).map_err(|error| {
                crate::error::StateError::InvalidConsensusSnapshot(error.to_string())
            })?,
        };
        self.append_slash_membership_root(record)
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

    /// Append a delegation-return event and prune the oldest entries if the
    /// fixed global retention bound is exceeded.
    pub fn push_delegation_return_event(&mut self, event: DelegationReturnEvent) {
        if let Some(commitment) = self.state_commitment_v2.as_mut() {
            commitment.put_delegation_return_event(&event);
        }
        self.delegation_return_events.push(event);
        let excess = self
            .delegation_return_events
            .len()
            .saturating_sub(MAX_DELEGATION_RETURN_EVENTS);
        if excess > 0 {
            let removed: Vec<_> = self.delegation_return_events.drain(0..excess).collect();
            if let Some(commitment) = self.state_commitment_v2.as_mut() {
                for event in &removed {
                    commitment.delete_delegation_return_event(event);
                }
            }
        }
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

fn validate_reward_economic_pairing(
    consensus_snapshots: &[ConsensusSnapshot],
    economic: Option<&RewardEconomicSnapshot>,
    height: u64,
) -> IndraResult<()> {
    if !consensus_snapshot_active(height) {
        return Ok(());
    }
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
    use indra_core::types::primitives::{
        hard_forks::SLASH_MEMBERSHIP_PROOF_HEIGHT, slash_membership_proof_active,
        SLASH_EVIDENCE_WINDOW_EPOCHS,
    };
    if !slash_membership_proof_active(state_height) {
        if !roots.is_empty() {
            return Err(IndraError::InvalidSlashMembershipProof(
                "pre-gate state contains slash membership roots".to_string(),
            ));
        }
        return Ok(());
    }
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
        if root.activation_height < SLASH_MEMBERSHIP_PROOF_HEIGHT {
            return Err(IndraError::InvalidSlashMembershipProof(
                "root activation precedes slash membership gate".to_string(),
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

fn encode_bond_map(bonds: &PersistentOrdMap<Bytes32, StakeBondEntry>, buf: &mut Vec<u8>) {
    (bonds.len() as u32).encode(buf);
    for (utxo_id, bond) in bonds {
        utxo_id.encode(buf);
        bond.encode(buf);
    }
}

fn bond_map_encoded_len(bonds: &PersistentOrdMap<Bytes32, StakeBondEntry>) -> usize {
    4 + bonds
        .iter()
        .map(|(utxo_id, bond)| utxo_id.encoded_len() + bond.encoded_len())
        .sum::<usize>()
}

fn decode_bond_map(
    r: &mut ByteReader<'_>,
) -> IndraResult<PersistentOrdMap<Bytes32, StakeBondEntry>> {
    let count = u32::decode(r)? as usize;
    validate_bond_map_count(count)?;
    let mut bonds = PersistentOrdMap::new();
    for _ in 0..count {
        let key = Bytes32::decode(r)?;
        let bond = StakeBondEntry::decode(r)?;
        if key != bond.utxo_id {
            return Err(IndraError::InvariantViolation {
                message: "stake bond map key must match bond utxo_id",
            });
        }
        if bonds.insert(key, bond).is_some() {
            return Err(IndraError::DuplicateEntries {
                field: "snapshot.staked_bonds",
            });
        }
    }
    Ok(bonds)
}

fn decode_bond_map_legacy(
    r: &mut ByteReader<'_>,
) -> IndraResult<PersistentOrdMap<Bytes32, StakeBondEntry>> {
    let count = u32::decode(r)? as usize;
    validate_bond_map_count(count)?;
    let mut bonds = PersistentOrdMap::new();
    for _ in 0..count {
        let key = Bytes32::decode(r)?;
        let bond = StakeBondEntry::decode_legacy(r)?;
        if key != bond.utxo_id {
            return Err(IndraError::InvariantViolation {
                message: "stake bond map key must match bond utxo_id",
            });
        }
        if bonds.insert(key, bond).is_some() {
            return Err(IndraError::DuplicateEntries {
                field: "snapshot.staked_bonds",
            });
        }
    }
    Ok(bonds)
}

fn validate_bond_map_count(count: usize) -> IndraResult<()> {
    use indra_core::error::IndraError;

    if count > MAX_STAKED_BONDS_DECODE {
        return Err(IndraError::LengthExceeded {
            field: "snapshot.staked_bonds",
            max: MAX_STAKED_BONDS_DECODE,
            actual: count,
        });
    }
    Ok(())
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

fn encode_payment_identity_registry(
    identities: &PersistentOrdMap<Bytes32, PaymentPubKeyV1>,
    buf: &mut Vec<u8>,
) {
    (identities.len() as u32).encode(buf);
    for (owner_id, pubkey) in identities {
        owner_id.encode(buf);
        buf.extend_from_slice(&pubkey.encode());
    }
}

fn payment_identity_registry_encoded_len(
    identities: &PersistentOrdMap<Bytes32, PaymentPubKeyV1>,
) -> usize {
    4 + identities
        .iter()
        .map(|(owner_id, pubkey)| owner_id.encoded_len() + pubkey.encode().len())
        .sum::<usize>()
}

fn decode_payment_identity_registry(
    r: &mut ByteReader<'_>,
) -> IndraResult<PersistentOrdMap<Bytes32, PaymentPubKeyV1>> {
    let count = u32::decode(r)? as usize;
    validate_payment_identity_count(count)?;
    let mut identities = PersistentOrdMap::new();
    for _ in 0..count {
        let owner_id = Bytes32::decode(r)?;
        let pubkey_bytes = r.read_bytes(indra_crypto::PAYMENT_PUBKEY_V1_ENCODED_LEN)?;
        let pubkey =
            PaymentPubKeyV1::decode(pubkey_bytes).map_err(|_| IndraError::InvariantViolation {
                message: "snapshot.payment_identities contains malformed payment public key",
            })?;
        if identities.insert(owner_id, pubkey).is_some() {
            return Err(IndraError::DuplicateEntries {
                field: "snapshot.payment_identities",
            });
        }
    }
    Ok(identities)
}

fn validate_payment_identity_count(count: usize) -> IndraResult<()> {
    if count > MAX_STAKING_NONCES_DECODE {
        return Err(IndraError::LengthExceeded {
            field: "snapshot.payment_identities",
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
    if classical.is_empty() && pq.is_empty() {
        0
    } else {
        8 + classical.len() * 32 + pq.len() * indra_crypto::PQ_PK_BYTES
    }
}

fn decode_retired_cold_components(
    r: &mut ByteReader<'_>,
) -> IndraResult<(
    PersistentOrdSet<[u8; 32]>,
    PersistentOrdSet<[u8; indra_crypto::PQ_PK_BYTES]>,
)> {
    let classical_count = u32::decode(r)? as usize;
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
            transaction::OutputV1,
        },
        CommitmentV1,
    };
    use indra_crypto::{PaymentKeypairV1, PAYMENT_VERSION_V1};

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
            cold_key_status: crate::validator::ColdKeyStatus::Unenrolled,
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
        assert!(state.nullifiers.is_empty());
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
        state.slash_membership_roots = vec![SlashMembershipRootRecord {
            activation_height: u64::MAX,
            membership_root: compute_slash_membership_root(&bootstrap).unwrap(),
        }];

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
            decoded.reward_economic_snapshot,
            state.reward_economic_snapshot
        );
        assert_eq!(decoded, state);
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
                    .snapshot_for_consensus_height_at_gate(height, 601)
                    .unwrap()
                    .activation_height,
                601
            );
        }
        for height in [901, 1_000, u64::MAX] {
            assert_eq!(
                state
                    .snapshot_for_consensus_height_at_gate(height, 601)
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
                .snapshot_for_consensus_height_at_gate(300, 1)
                .unwrap()
                .activation_height,
            1
        );
        assert_eq!(
            state
                .snapshot_for_consensus_height_at_gate(301, 1)
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
            duplicate.snapshot_for_consensus_height_at_gate(601, 601),
            Err(ConsensusSnapshotLookupError::InvalidRetainedState { .. })
        ));

        let mut uncovered = snapshot_state();
        uncovered
            .rotate_consensus_snapshot_after_boundary(900)
            .unwrap();
        assert_eq!(
            uncovered.snapshot_for_consensus_height_at_gate(601, 601),
            Err(ConsensusSnapshotLookupError::NoSnapshotForHeight { height: 601 })
        );

        let empty = snapshot_state();
        assert!(matches!(
            empty.snapshot_for_consensus_height_at_gate(601, 601),
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
    fn snapshot_lookup_explicitly_rejects_pre_gate_heights() {
        use crate::error::ConsensusSnapshotLookupError;

        let mut state = snapshot_state();
        state.rotate_consensus_snapshot_after_boundary(600).unwrap();
        assert_eq!(
            state.snapshot_for_consensus_height_at_gate(600, 601),
            Err(ConsensusSnapshotLookupError::PreGateHeight {
                height: 600,
                gate_height: 601,
            })
        );
        assert_eq!(
            state.snapshot_for_consensus_height(0),
            Err(ConsensusSnapshotLookupError::PreGateHeight {
                height: 0,
                gate_height: CONSENSUS_SNAPSHOT_HEIGHT,
            })
        );
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
    fn pre_gate_chain_state_bytes_and_roots_ignore_snapshot_field() {
        let baseline = snapshot_state();
        let mut with_staged_snapshot = baseline.clone();
        with_staged_snapshot
            .consensus_snapshots
            .push(baseline.build_genesis_consensus_snapshot().unwrap());
        with_staged_snapshot.reward_economic_snapshot = Some(
            baseline
                .build_reward_economic_snapshot(&with_staged_snapshot.consensus_snapshots[0])
                .unwrap(),
        );
        with_staged_snapshot.slash_membership_roots = vec![SlashMembershipRootRecord {
            activation_height: u64::MAX,
            membership_root: Bytes32::from([0xCC; 32]),
        }];

        assert!(!consensus_snapshot_active(baseline.height));
        assert_eq!(
            baseline.encode_to_vec(),
            with_staged_snapshot.encode_to_vec()
        );
        assert_eq!(
            crate::state_root::compute_state_root(&baseline),
            crate::state_root::compute_state_root(&with_staged_snapshot)
        );
        assert!(ChainState::decode_exact(&baseline.encode_to_vec())
            .unwrap()
            .consensus_snapshots
            .is_empty());
        assert!(ChainState::decode_exact(&baseline.encode_to_vec())
            .unwrap()
            .reward_economic_snapshot
            .is_none());
        assert!(ChainState::decode_exact(&baseline.encode_to_vec())
            .unwrap()
            .slash_membership_roots
            .is_empty());
    }

    #[test]
    fn genesis_has_no_blocks() {
        assert!(!ChainState::new_genesis().has_blocks());
    }

    #[test]
    fn genesis_epoch_is_zero() {
        assert_eq!(ChainState::new_genesis().current_epoch(), 0);
    }

    fn test_output(byte: u8) -> OutputV1 {
        OutputV1 {
            value_spark: 1_000_000,
            commitment: CommitmentV1 {
                compressed_point: Bytes32::from([byte; 32]),
            },
            owner_pubkey: HybridPubKey {
                classical_pk: Bytes32::from([byte; 32]),
                pq_pk: VariableBytes::from_slice(&[byte; 32]).unwrap(),
            },
            range_proof: VariableBytes::from_slice(&[byte; 32]).unwrap(),
            lock_height: 0,
        }
    }

    fn test_hybrid_pubkey(byte: u8) -> HybridPubKey {
        HybridPubKey {
            classical_pk: Bytes32::from([byte; 32]),
            pq_pk: VariableBytes::from_slice(&vec![byte.wrapping_add(1); 2_592]).unwrap(),
        }
    }

    fn test_payment_pubkey(index: usize) -> PaymentPubKeyV1 {
        let mut x25519_sk = [0u8; 32];
        x25519_sk[0] = 0xA5;
        x25519_sk[8..16].copy_from_slice(&(index as u64).to_be_bytes());
        let mut ml_kem_1024_seed = [0u8; 64];
        ml_kem_1024_seed[0] = 0x5A;
        ml_kem_1024_seed[8..16].copy_from_slice(&(index as u64).to_be_bytes());
        PaymentKeypairV1 {
            version: PAYMENT_VERSION_V1,
            x25519_sk,
            ml_kem_1024_seed,
        }
        .public_key()
    }

    fn test_bond(byte: u8) -> StakeBondEntry {
        StakeBondEntry {
            utxo_id: Bytes32::from([byte; 32]),
            validator_id: Bytes32::from([0xA0 | byte; 32]),
            delegator_id: Bytes32::from([0xD0 | byte; 32]),
            amount_spark: 1_000_000,
            bonded_epoch: 7,
            unbonding_end_epoch: None,
            unbonding_precision: crate::validator::StakeBondUnbondingPrecision::LegacyEpochOnly,
            custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                Bytes32::from([0xD0 | byte; 32]),
            ),
            original_output: test_output(byte).into(),
        }
    }

    fn encode_bond_map_btree(bonds: &BTreeMap<Bytes32, StakeBondEntry>, buf: &mut Vec<u8>) {
        (bonds.len() as u32).encode(buf);
        for (utxo_id, bond) in bonds {
            utxo_id.encode(buf);
            bond.encode(buf);
        }
    }

    fn encode_nonce_map_btree(nonces: &BTreeMap<Bytes32, u64>, buf: &mut Vec<u8>) {
        (nonces.len() as u32).encode(buf);
        for (signer_id, nonce) in nonces {
            signer_id.encode(buf);
            nonce.encode(buf);
        }
    }

    fn encode_chain_state_without_delegator_identities(state: &ChainState) -> Vec<u8> {
        let mut buf = Vec::new();
        VariableBytes::<MAX_CHAIN_ID_BYTES>::from_slice(state.chain_id.as_bytes())
            .unwrap_or_default()
            .encode(&mut buf);
        state.height.encode(&mut buf);
        state.tip_hash.encode(&mut buf);
        state.base_fee.encode(&mut buf);
        state.total_supply.encode(&mut buf);
        state.treasury_balance.encode(&mut buf);
        state.burn_buffer.encode(&mut buf);
        state.fee_reward_pool.encode(&mut buf);
        state.utxos.encode(&mut buf);
        state.nullifiers.encode(&mut buf);
        state.validators.encode(&mut buf);
        state.delegations.encode(&mut buf);
        encode_bond_map(&state.staked_bonds, &mut buf);
        encode_nonce_map(&state.staking_nonces, &mut buf);
        encode_hash_set(&state.applied_slash_hashes, &mut buf);
        state.governance.encode(&mut buf);
        encode_delegation_return_events(&state.delegation_return_events, &mut buf);
        buf
    }

    fn encode_chain_state_without_identity_tails(state: &ChainState) -> Vec<u8> {
        encode_chain_state_without_delegator_identities(state)
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
    fn staked_bond_decode_cap_is_derived_from_validator_delegator_caps() {
        let old_placeholder_cap = MAX_VALIDATORS.saturating_mul(1_000);
        assert!(
            MAX_STAKED_BONDS_DECODE > old_placeholder_cap,
            "corrected cap must accept states above the old placeholder ceiling"
        );
        assert_eq!(
            MAX_STAKED_BONDS_DECODE,
            MAX_VALIDATORS.saturating_mul(crate::validator::MAX_DELEGATORS_PER_VALIDATOR)
        );
        assert!(validate_bond_map_count(old_placeholder_cap + 1).is_ok());
    }

    #[test]
    fn staked_bond_decode_no_longer_rejects_count_above_old_placeholder_cap() {
        let old_placeholder_cap = MAX_VALIDATORS.saturating_mul(1_000);
        let mut bytes = Vec::new();
        ((old_placeholder_cap + 1) as u32).encode(&mut bytes);

        let err = decode_bond_map(&mut ByteReader::new(&bytes)).unwrap_err();
        assert!(
            matches!(err, IndraError::UnexpectedEof { .. }),
            "count above old placeholder cap should pass the staked_bonds cap guard and fail only because this synthetic stream has no entries; got {err:?}"
        );
    }

    #[test]
    fn staked_bond_decode_rejects_count_above_corrected_cap_cleanly() {
        let mut bytes = Vec::new();
        ((MAX_STAKED_BONDS_DECODE + 1) as u32).encode(&mut bytes);

        let err = decode_bond_map(&mut ByteReader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            IndraError::LengthExceeded {
                field: "snapshot.staked_bonds",
                max: MAX_STAKED_BONDS_DECODE,
                actual
            } if actual == MAX_STAKED_BONDS_DECODE + 1
        ));
    }

    #[test]
    fn staked_bond_encode_decode_round_trip_uses_same_cap_path() {
        let mut bonds = PersistentOrdMap::new();
        let bond_a = test_bond(0x01);
        let bond_b = test_bond(0x02);
        bonds.insert(bond_a.utxo_id, bond_a);
        bonds.insert(bond_b.utxo_id, bond_b);

        let mut bytes = Vec::new();
        encode_bond_map(&bonds, &mut bytes);
        let decoded = decode_bond_map(&mut ByteReader::new(&bytes)).unwrap();
        assert_eq!(decoded, bonds);
    }

    #[test]
    fn mixed_legacy_and_height_precise_bond_map_checkpoint_round_trip_is_deterministic() {
        let mut state = ChainState::new_genesis();
        let legacy = StakeBondEntry::new_for_test_with_compact_activation(
            Bytes32::from([0x21; 32]),
            Bytes32::from([0xA1; 32]),
            Bytes32::from([0xD1; 32]),
            1_000_000,
            7,
            test_output(0x21),
            9,
            10,
        );
        let compact = StakeBondEntry::new_for_test_with_compact_activation(
            Bytes32::from([0x22; 32]),
            Bytes32::from([0xA2; 32]),
            Bytes32::from([0xD2; 32]),
            1_000_000,
            8,
            test_output(0x22),
            10,
            10,
        );
        let fully_compact = StakeBondEntry::new_for_test_with_compact_and_pubkey_activation(
            Bytes32::from([0x23; 32]),
            Bytes32::from([0xA3; 32]),
            Bytes32::from([0xD3; 32]),
            1_000_000,
            9,
            test_output(0x23),
            20,
            10,
            20,
        );
        let mut height_precise = StakeBondEntry::new_for_test_with_all_activations(
            Bytes32::from([0x24; 32]),
            Bytes32::from([0xA4; 32]),
            Bytes32::from([0xD4; 32]),
            1_000_000,
            10,
            test_output(0x24),
            100,
            10,
            20,
            100,
        );
        height_precise
            .begin_unbonding(100, indra_core::types::primitives::UNBONDING_PERIOD_EPOCHS)
            .unwrap();
        assert!(legacy.original_output.range_proof.is_some());
        assert!(legacy.original_output.owner_pubkey.is_some());
        assert!(compact.original_output.range_proof.is_none());
        assert!(compact.original_output.owner_pubkey.is_some());
        assert!(fully_compact.original_output.range_proof.is_none());
        assert!(fully_compact.original_output.owner_pubkey.is_none());
        state.staked_bonds.insert(legacy.utxo_id, legacy);
        state.staked_bonds.insert(compact.utxo_id, compact);
        state
            .staked_bonds
            .insert(fully_compact.utxo_id, fully_compact);
        state
            .staked_bonds
            .insert(height_precise.utxo_id, height_precise);

        let encoded = state.encode_to_vec();
        let decoded = ChainState::decode(&mut ByteReader::new(&encoded)).unwrap();
        let independently_decoded = ChainState::decode(&mut ByteReader::new(&encoded)).unwrap();
        assert_eq!(decoded, state);
        assert_eq!(independently_decoded.encode_to_vec(), encoded);
        assert_eq!(
            crate::state_root::compute_state_root(&decoded),
            crate::state_root::compute_state_root(&state)
        );
        assert_eq!(
            crate::state_commitment::StateCommitmentV2::from_state(&decoded, u64::MAX).root(),
            crate::state_commitment::StateCommitmentV2::from_state(&state, u64::MAX).root()
        );
    }

    #[test]
    fn independent_bond_replays_across_height_precision_gate_are_byte_identical() {
        fn replay() -> ChainState {
            const TEST_GATE: u64 = 100;
            let mut state = ChainState::new_genesis();
            let legacy = StakeBondEntry::new_for_test_with_all_activations(
                Bytes32::from([0x31; 32]),
                Bytes32::from([0xA1; 32]),
                Bytes32::from([0xD1; 32]),
                1_000_000,
                0,
                test_output(0x31),
                TEST_GATE - 1,
                u64::MAX,
                u64::MAX,
                TEST_GATE,
            );
            let mut precise = StakeBondEntry::new_for_test_with_all_activations(
                Bytes32::from([0x32; 32]),
                Bytes32::from([0xA2; 32]),
                Bytes32::from([0xD2; 32]),
                1_000_000,
                0,
                test_output(0x32),
                TEST_GATE,
                u64::MAX,
                u64::MAX,
                TEST_GATE,
            );
            precise
                .begin_unbonding(
                    TEST_GATE + 1,
                    indra_core::types::primitives::UNBONDING_PERIOD_EPOCHS,
                )
                .unwrap();
            state.staked_bonds.insert(legacy.utxo_id, legacy);
            state.staked_bonds.insert(precise.utxo_id, precise);
            state.height = TEST_GATE + 1;
            state.rebuild_state_commitment_v2(state.height);
            state
        }

        let first = replay();
        let second = replay();
        assert_eq!(first.encode_to_vec(), second.encode_to_vec());
        assert_eq!(
            crate::state_root::compute_state_root(&first),
            crate::state_root::compute_state_root(&second)
        );
        assert_eq!(
            first.state_commitment_v2_root(first.height),
            second.state_commitment_v2_root(second.height)
        );
    }

    #[test]
    fn staked_bond_persistent_encoding_matches_legacy_btree_encoding() {
        let mut legacy = BTreeMap::new();
        let mut persistent = PersistentOrdMap::new();
        for byte in [0x03, 0x01, 0x02] {
            let bond = test_bond(byte);
            legacy.insert(bond.utxo_id, bond.clone());
            persistent.insert(bond.utxo_id, bond);
        }

        let mut legacy_bytes = Vec::new();
        encode_bond_map_btree(&legacy, &mut legacy_bytes);
        let mut persistent_bytes = Vec::new();
        encode_bond_map(&persistent, &mut persistent_bytes);
        assert_eq!(persistent_bytes, legacy_bytes);

        let mut state = ChainState::new_genesis();
        state.staked_bonds = persistent;
        let encoded = state.encode_to_vec();
        let decoded = ChainState::decode(&mut ByteReader::new(&encoded)).unwrap();
        assert_eq!(decoded, state);
    }

    #[test]
    fn staked_bond_persistent_encoding_is_insertion_order_independent() {
        let mut forward = PersistentOrdMap::new();
        let mut reverse = PersistentOrdMap::new();
        for byte in [0x01, 0x02, 0x03, 0x04] {
            let bond = test_bond(byte);
            forward.insert(bond.utxo_id, bond);
        }
        for byte in [0x04, 0x03, 0x02, 0x01] {
            let bond = test_bond(byte);
            reverse.insert(bond.utxo_id, bond);
        }

        let mut forward_bytes = Vec::new();
        encode_bond_map(&forward, &mut forward_bytes);
        let mut reverse_bytes = Vec::new();
        encode_bond_map(&reverse, &mut reverse_bytes);
        assert_eq!(forward_bytes, reverse_bytes);
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
    fn payment_identity_registry_round_trips_empty_small_and_realistic_scale() {
        for size in [0usize, 3, 2_000] {
            let mut registry = PersistentOrdMap::new();
            for index in 0..size {
                let mut id = [0u8; 32];
                id[0] = 0xC0;
                id[8..16].copy_from_slice(&(index as u64).to_be_bytes());
                registry.insert(Bytes32::from(id), test_payment_pubkey(index));
            }

            let mut bytes = Vec::new();
            encode_payment_identity_registry(&registry, &mut bytes);
            assert_eq!(
                bytes.len(),
                payment_identity_registry_encoded_len(&registry)
            );
            let decoded = decode_payment_identity_registry(&mut ByteReader::new(&bytes)).unwrap();
            assert_eq!(decoded, registry);
        }
    }

    #[test]
    fn payment_identity_registry_encoding_is_insertion_order_independent() {
        let mut forward = PersistentOrdMap::new();
        let mut reverse = PersistentOrdMap::new();
        for index in [1usize, 2, 3, 4] {
            forward.insert(Bytes32::from([index as u8; 32]), test_payment_pubkey(index));
        }
        for index in [4usize, 3, 2, 1] {
            reverse.insert(Bytes32::from([index as u8; 32]), test_payment_pubkey(index));
        }

        let mut forward_bytes = Vec::new();
        encode_payment_identity_registry(&forward, &mut forward_bytes);
        let mut reverse_bytes = Vec::new();
        encode_payment_identity_registry(&reverse, &mut reverse_bytes);
        assert_eq!(forward_bytes, reverse_bytes);
        assert_eq!(
            forward
                .iter()
                .map(|(owner_id, _)| owner_id.0[0])
                .collect::<Vec<_>>(),
            vec![0x01, 0x02, 0x03, 0x04]
        );
    }

    #[test]
    fn payment_identity_registry_decode_rejects_duplicate_ids() {
        let owner_id = Bytes32::from([0xC1; 32]);
        let mut bytes = Vec::new();
        2u32.encode(&mut bytes);
        owner_id.encode(&mut bytes);
        bytes.extend_from_slice(&test_payment_pubkey(1).encode());
        owner_id.encode(&mut bytes);
        bytes.extend_from_slice(&test_payment_pubkey(2).encode());

        let err = decode_payment_identity_registry(&mut ByteReader::new(&bytes)).unwrap_err();
        assert!(matches!(
            err,
            IndraError::DuplicateEntries {
                field: "snapshot.payment_identities"
            }
        ));
    }

    #[test]
    fn empty_delegator_identity_registry_preserves_chain_state_encoding() {
        let mut state = ChainState::new_genesis();
        state.height = 42;
        state.staking_nonces.insert(Bytes32::from([0x44; 32]), 7);
        state.applied_slash_hashes.insert(Bytes32::from([0x55; 32]));

        let old_bytes = encode_chain_state_without_delegator_identities(&state);
        let new_bytes = state.encode_to_vec();
        assert!(state.delegator_identities.is_empty());
        assert_eq!(new_bytes, old_bytes);
        assert_eq!(new_bytes.len(), state.encoded_len());

        let decoded = ChainState::decode_exact(&old_bytes).unwrap();
        assert_eq!(decoded, state);
        assert!(decoded.delegator_identities.is_empty());
    }

    #[test]
    fn empty_payment_identity_registry_preserves_chain_state_encoding() {
        let mut state = ChainState::new_genesis();
        state.height = 42;
        state.staking_nonces.insert(Bytes32::from([0x44; 32]), 7);
        state.applied_slash_hashes.insert(Bytes32::from([0x55; 32]));

        let old_bytes = encode_chain_state_without_identity_tails(&state);
        let new_bytes = state.encode_to_vec();
        assert!(state.delegator_identities.is_empty());
        assert!(state.payment_identities.is_empty());
        assert_eq!(new_bytes, old_bytes);
        assert_eq!(new_bytes.len(), state.encoded_len());

        let decoded = ChainState::decode_exact(&old_bytes).unwrap();
        assert_eq!(decoded, state);
        assert!(decoded.delegator_identities.is_empty());
        assert!(decoded.payment_identities.is_empty());
    }

    #[test]
    fn chain_state_round_trips_optional_payment_identity_registry_tail() {
        let mut state = ChainState::new_genesis();
        state
            .payment_identities
            .insert(Bytes32::from([0xC2; 32]), test_payment_pubkey(2));
        state
            .payment_identities
            .insert(Bytes32::from([0xC1; 32]), test_payment_pubkey(1));

        let without_identity_tails = encode_chain_state_without_identity_tails(&state);
        let encoded = state.encode_to_vec();
        assert!(encoded.len() > without_identity_tails.len());
        assert!(encoded.starts_with(&without_identity_tails));
        assert_eq!(encoded.len(), state.encoded_len());

        let decoded = ChainState::decode_exact(&encoded).unwrap();
        assert_eq!(decoded, state);
        assert!(decoded.delegator_identities.is_empty());
        assert_eq!(decoded.payment_identities.len(), 2);
    }

    #[test]
    fn chain_state_round_trips_optional_delegator_identity_registry_tail() {
        let mut state = ChainState::new_genesis();
        state
            .delegator_identities
            .insert(Bytes32::from([0xD2; 32]), test_hybrid_pubkey(0x12));
        state
            .delegator_identities
            .insert(Bytes32::from([0xD1; 32]), test_hybrid_pubkey(0x11));

        let without_registry = encode_chain_state_without_delegator_identities(&state);
        let encoded = state.encode_to_vec();
        assert!(encoded.len() > without_registry.len());
        assert!(encoded.starts_with(&without_registry));
        assert_eq!(encoded.len(), state.encoded_len());

        let decoded = ChainState::decode_exact(&encoded).unwrap();
        assert_eq!(decoded, state);
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

    #[test]
    fn chain_state_migrated_clone_matches_deep_materialized_oracle() {
        let mut state = ChainState::new_genesis();
        state.height = indra_core::types::primitives::hard_forks::STATE_COMMITMENT_V2_HEIGHT;
        state.utxos.insert(test_output(0x11), 1, 0, 0).unwrap();
        state.nullifiers.insert(Bytes32::from([0x22; 32]));
        state
            .staked_bonds
            .insert(Bytes32::from([0x33; 32]), test_bond(0x33));
        state.staking_nonces.insert(Bytes32::from([0x44; 32]), 7);
        state.applied_slash_hashes.insert(Bytes32::from([0x55; 32]));
        state.push_delegation_return_event(DelegationReturnEvent {
            delegator_id: Bytes32::from([0x66; 32]),
            validator_id: Bytes32::from([0x77; 32]),
            bond_utxo_id: Bytes32::from([0x88; 32]),
            amount_spark: 123,
            reason: crate::validator::DelegationReturnReason::ValidatorEvicted,
            returned_epoch: 9,
            returned_height: state.height,
            refund_utxo_id: Bytes32::from([0x99; 32]),
        });
        state.rebuild_state_commitment_v2(state.height);

        let migrated_clone = state.clone();
        let deep_materialized = ChainState::decode_exact(&state.encode_to_vec()).unwrap();

        assert_eq!(
            migrated_clone.encode_to_vec(),
            deep_materialized.encode_to_vec()
        );
        assert_eq!(
            crate::state_root::compute_state_roots(&migrated_clone),
            crate::state_root::compute_state_roots(&deep_materialized)
        );
        assert_eq!(migrated_clone, state);
    }

    #[test]
    #[ignore = "release-mode fix #6 capstone whole-ChainState clone benchmark; run with --release --ignored --nocapture"]
    fn fix6_capstone_whole_chain_state_clone_benchmark() {
        use std::{hint::black_box, time::Instant};

        fn id_from_index(domain: u8, index: usize) -> Bytes32 {
            let mut bytes = [0u8; 32];
            bytes[0] = domain;
            bytes[8..16].copy_from_slice(&(index as u64).to_be_bytes());
            Bytes32::from(bytes)
        }

        fn heavy_output(index: usize) -> OutputV1 {
            let byte = (index as u8).wrapping_add(1);
            OutputV1 {
                value_spark: 1_000,
                commitment: CommitmentV1 {
                    compressed_point: id_from_index(0xC0, index),
                },
                owner_pubkey: HybridPubKey {
                    classical_pk: id_from_index(0xA0, index),
                    pq_pk: VariableBytes::from_slice(&vec![byte.wrapping_add(2); 2_592]).unwrap(),
                },
                range_proof: VariableBytes::from_slice(&vec![byte.wrapping_add(3); 674]).unwrap(),
                lock_height: 0,
            }
        }

        fn heavy_bond(
            index: usize,
            validator_id: Bytes32,
            delegator_id: Bytes32,
        ) -> StakeBondEntry {
            let utxo_id = id_from_index(0xB0, index);
            StakeBondEntry {
                utxo_id,
                validator_id,
                delegator_id,
                amount_spark: 1_000,
                bonded_epoch: 0,
                unbonding_end_epoch: None,
                unbonding_precision: crate::validator::StakeBondUnbondingPrecision::LegacyEpochOnly,
                custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                    delegator_id,
                ),
                original_output: heavy_output(index).into(),
            }
        }

        fn populate_state(size: usize, heavy_bond_count: usize) -> ChainState {
            let mut state = ChainState::new_genesis();
            state.height = indra_core::types::primitives::hard_forks::STATE_COMMITMENT_V2_HEIGHT;
            let validator_count = size.clamp(1, 10_000);
            for index in 0..size {
                let validator_id = id_from_index(0x70, index % validator_count);
                let delegator_id = id_from_index(0xD0, index);
                state
                    .delegations
                    .add_delegation(validator_id, delegator_id, 1_000, 0)
                    .unwrap();
                state.staking_nonces.insert(delegator_id, index as u64);
                if index < heavy_bond_count {
                    let bond = heavy_bond(index, validator_id, delegator_id);
                    state.staked_bonds.insert(bond.utxo_id, bond);
                }
            }
            for index in 0..size.min(30_000) {
                state
                    .applied_slash_hashes
                    .insert(id_from_index(0xE0, index));
            }
            for index in 0..size.min(MAX_DELEGATION_RETURN_EVENTS) {
                state.push_delegation_return_event(DelegationReturnEvent {
                    delegator_id: id_from_index(0xD0, index),
                    validator_id: id_from_index(0x70, index % validator_count),
                    bond_utxo_id: id_from_index(0xB0, index),
                    amount_spark: 1_000,
                    reason: crate::validator::DelegationReturnReason::ValidatorEvicted,
                    returned_epoch: index as u64 / 100,
                    returned_height: state.height,
                    refund_utxo_id: id_from_index(0xF0, index),
                });
            }
            state.rebuild_state_commitment_v2(state.height);
            state
        }

        let sizes = std::env::var("INDRA_FIX6_CAPSTONE_CLONE_BENCH_SIZES")
            .unwrap_or_else(|_| "100000,1000000".to_string())
            .split(',')
            .map(|part| part.trim().parse::<usize>().unwrap())
            .collect::<Vec<_>>();
        let heavy_bond_limit = std::env::var("INDRA_FIX6_CAPSTONE_HEAVY_BOND_LIMIT")
            .ok()
            .and_then(|raw| raw.parse::<usize>().ok())
            .unwrap_or(1_000_000);

        eprintln!(
            "[fix6-capstone] original Step 0: normal import/commit ≈7 clone-equivalents and ≈11.6-11.9s at 1M delegators before the clone-cost arc"
        );

        for size in sizes {
            let heavy_bonds = size.min(heavy_bond_limit);
            let setup_start = Instant::now();
            let state = populate_state(size, heavy_bonds);
            let setup = setup_start.elapsed();

            let whole_clone_start = Instant::now();
            let whole_clone = state.clone();
            let whole_clone_elapsed = whole_clone_start.elapsed();
            black_box(&whole_clone);

            let slash_hash_clone_start = Instant::now();
            let slash_hash_clone = state.applied_slash_hashes.clone();
            let slash_hash_clone_elapsed = slash_hash_clone_start.elapsed();
            black_box(&slash_hash_clone);

            let event_clone_start = Instant::now();
            let event_clone = state.delegation_return_events.clone();
            let event_clone_elapsed = event_clone_start.elapsed();
            black_box(&event_clone);

            println!(
                "fix6_capstone_chainstate_clone delegators={size} heavy_bonds={heavy_bonds} setup={setup:?} whole_chainstate_clone={whole_clone_elapsed:?} applied_slash_hashes_clone={slash_hash_clone_elapsed:?} delegation_return_events_clone={event_clone_elapsed:?}"
            );
        }
    }

    #[test]
    #[ignore = "release-mode Stage 2a field-clone benchmark; run explicitly with --release --ignored --nocapture"]
    fn stage2a_persistent_bonds_and_nonces_clone_benchmark() {
        use std::{hint::black_box, time::Instant};

        fn id_from_index(index: usize) -> Bytes32 {
            let mut bytes = [0u8; 32];
            for (dst, src) in bytes
                .iter_mut()
                .zip((index as u64).to_le_bytes().into_iter())
            {
                *dst = src;
            }
            Bytes32::from(bytes)
        }

        fn heavy_output(index: usize) -> OutputV1 {
            let byte = (index as u8).wrapping_add(1);
            OutputV1 {
                value_spark: 1_000,
                commitment: CommitmentV1 {
                    compressed_point: Bytes32::from([byte; 32]),
                },
                owner_pubkey: HybridPubKey {
                    classical_pk: Bytes32::from([byte.wrapping_add(1); 32]),
                    pq_pk: VariableBytes::from_slice(&vec![byte.wrapping_add(2); 2_592]).unwrap(),
                },
                range_proof: VariableBytes::from_slice(&vec![byte.wrapping_add(3); 674]).unwrap(),
                lock_height: 0,
            }
        }

        fn heavy_bond(index: usize) -> StakeBondEntry {
            let utxo_id = id_from_index(index);
            StakeBondEntry {
                utxo_id,
                validator_id: Bytes32::from([0x55; 32]),
                delegator_id: id_from_index(index + 1_000_000),
                amount_spark: 1_000,
                bonded_epoch: 0,
                unbonding_end_epoch: None,
                unbonding_precision: crate::validator::StakeBondUnbondingPrecision::LegacyEpochOnly,
                custody_owner: crate::validator::StakeBondCustodyOwner::DelegatorIdentity(
                    id_from_index(index + 1_000_000),
                ),
                original_output: heavy_output(index).into(),
            }
        }

        fn legacy_bonds(size: usize) -> BTreeMap<Bytes32, StakeBondEntry> {
            let mut map = BTreeMap::new();
            for index in 0..size {
                let bond = heavy_bond(index);
                map.insert(bond.utxo_id, bond);
            }
            map
        }

        fn persistent_bonds(size: usize) -> PersistentOrdMap<Bytes32, StakeBondEntry> {
            let mut map = PersistentOrdMap::new();
            for index in 0..size {
                let bond = heavy_bond(index);
                map.insert(bond.utxo_id, bond);
            }
            map
        }

        fn legacy_nonces(size: usize) -> BTreeMap<Bytes32, u64> {
            let mut map = BTreeMap::new();
            for index in 0..size {
                map.insert(id_from_index(index), index as u64);
            }
            map
        }

        fn persistent_nonces(size: usize) -> PersistentOrdMap<Bytes32, u64> {
            let mut map = PersistentOrdMap::new();
            for index in 0..size {
                map.insert(id_from_index(index), index as u64);
            }
            map
        }

        // This is intentionally ignored and release-only: debug timings for
        // million-entry heavy bond maps are dominated by instrumentation and are
        // not meaningful for validator deployment decisions.
        for size in [100_000usize, 1_000_000usize] {
            let legacy = legacy_bonds(size);
            let start = Instant::now();
            let legacy_clone = legacy.clone();
            black_box(&legacy_clone);
            let legacy_bond_clone = start.elapsed();
            drop(legacy_clone);
            drop(legacy);

            let persistent = persistent_bonds(size);
            let start = Instant::now();
            let persistent_clone = persistent.clone();
            black_box(&persistent_clone);
            let persistent_bond_clone = start.elapsed();
            drop(persistent_clone);
            drop(persistent);

            let legacy = legacy_nonces(size);
            let start = Instant::now();
            let legacy_clone = legacy.clone();
            black_box(&legacy_clone);
            let legacy_nonce_clone = start.elapsed();
            drop(legacy_clone);
            drop(legacy);

            let persistent = persistent_nonces(size);
            let start = Instant::now();
            let persistent_clone = persistent.clone();
            black_box(&persistent_clone);
            let persistent_nonce_clone = start.elapsed();
            drop(persistent_clone);
            drop(persistent);

            println!(
                "stage2a_persistent_bonds_and_nonces_clone size={size} legacy_bonds_clone={legacy_bond_clone:?} persistent_bonds_clone={persistent_bond_clone:?} legacy_nonces_clone={legacy_nonce_clone:?} persistent_nonces_clone={persistent_nonce_clone:?}"
            );

            assert!(
                persistent_bond_clone < legacy_bond_clone,
                "persistent staked_bonds clone should be cheaper than legacy BTreeMap clone at size {size}"
            );
            assert!(
                persistent_nonce_clone < legacy_nonce_clone,
                "persistent staking_nonces clone should be cheaper than legacy BTreeMap clone at size {size}"
            );
        }
    }
}
