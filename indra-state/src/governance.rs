//! On-chain governance state.

use std::collections::HashMap;

use indra_core::{
    codec::{ByteReader, Decode, Encode},
    error::{IndraError, IndraResult},
    types::{
        crypto::HybridPubKey,
        governance::{GovernableAction, ProposalTier},
        primitives::{
            Bytes32, DUST_LIMIT_SPARK, GOVERNANCE_DELAY_EPOCHS, MAX_COMMISSION_BPS,
            SLASH_DOUBLE_PRECOMMIT_BPS, SLASH_LIVENESS_BPS, SLASH_LIVENESS_THRESHOLD_EPOCHS,
            SLASH_SURROUND_VOTE_BPS, SPARK_PER_INDRA,
        },
    },
};

/// Maximum active proposals globally.
pub const MAX_ACTIVE_GOVERNANCE_PROPOSALS: usize = 3;
/// Maximum active proposals per proposer.
pub const MAX_ACTIVE_GOVERNANCE_PROPOSALS_PER_PROPOSER: usize = 1;
/// Proposal cooldown per proposer.
pub const GOVERNANCE_PROPOSAL_COOLDOWN_EPOCHS: u64 = 10;
/// Deliberation duration.
pub const GOVERNANCE_DELIBERATION_EPOCHS: u64 = 30;
/// Standard proposal commit duration.
pub const GOVERNANCE_STANDARD_COMMIT_EPOCHS: u64 = 20;
/// Critical proposal commit duration.
pub const GOVERNANCE_CRITICAL_COMMIT_EPOCHS: u64 = 30;
/// Reveal duration.
pub const GOVERNANCE_REVEAL_EPOCHS: u64 = 10;
/// Deposit return support threshold.
pub const GOVERNANCE_DEPOSIT_RETURN_SUPPORT_BPS: u32 = 1_000;

/// Runtime-governable protocol parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernableParams {
    /// Liveness threshold.
    pub slash_liveness_threshold_epochs: u64,
    /// Global delegation floor.
    pub min_delegation_spark: u64,
    /// Proposal deposit.
    pub proposal_deposit_spark: u64,
    /// Liveness slash bps.
    pub slash_liveness_bps: u32,
    /// Double precommit slash bps.
    pub slash_double_precommit_bps: u32,
    /// Surround vote slash bps.
    pub slash_surround_vote_bps: u32,
    /// Maximum commission bps.
    pub max_commission_bps: u32,
    /// Governance delay.
    pub governance_delay_epochs: u64,
    /// Standard quorum bps.
    pub governance_quorum_bps: u32,
    /// Critical quorum bps.
    pub governance_critical_quorum_bps: u32,
}

impl GovernableParams {
    /// Mainnet defaults.
    pub fn default_mainnet() -> Self {
        Self {
            slash_liveness_threshold_epochs: SLASH_LIVENESS_THRESHOLD_EPOCHS,
            min_delegation_spark: DUST_LIMIT_SPARK,
            proposal_deposit_spark: 1_000 * SPARK_PER_INDRA,
            slash_liveness_bps: SLASH_LIVENESS_BPS,
            slash_double_precommit_bps: SLASH_DOUBLE_PRECOMMIT_BPS,
            slash_surround_vote_bps: SLASH_SURROUND_VOTE_BPS,
            max_commission_bps: MAX_COMMISSION_BPS,
            governance_delay_epochs: GOVERNANCE_DELAY_EPOCHS,
            governance_quorum_bps: 5_000,
            governance_critical_quorum_bps: 6_700,
        }
    }

    /// Validate action bounds and monotonic constraints.
    pub fn validate_action(&self, action: &GovernableAction) -> Result<(), String> {
        match action {
            GovernableAction::SetSlashLivenessThresholdEpochs { value } => {
                if *value < 1 {
                    return Err("floor is 1".into());
                }
                if *value > 10 {
                    return Err("ceiling is 10".into());
                }
            }
            GovernableAction::SetMinDelegationSpark { value } => {
                if *value < DUST_LIMIT_SPARK {
                    return Err(format!("floor is {DUST_LIMIT_SPARK} Spark (DUST_LIMIT)"));
                }
            }
            GovernableAction::SetProposalDepositSpark { value } => {
                if *value < 100 * SPARK_PER_INDRA {
                    return Err("floor is 100 INDRA".into());
                }
                if *value > 10_000 * SPARK_PER_INDRA {
                    return Err("ceiling is 10,000 INDRA".into());
                }
            }
            GovernableAction::SetSlashLivenessBps { value } => {
                if *value < 1 {
                    return Err("floor is 1 BPS (cannot be 0)".into());
                }
                if *value > 1_000 {
                    return Err("ceiling is 1000 BPS".into());
                }
            }
            GovernableAction::SetSlashDoublePrecommitBps { value } => {
                if *value < 100 {
                    return Err("floor is 100 BPS".into());
                }
                if *value > 5_000 {
                    return Err("ceiling is 5000 BPS".into());
                }
            }
            GovernableAction::SetSlashSurroundVoteBps { value } => {
                if *value < self.slash_double_precommit_bps {
                    return Err("must be >= slash_double_precommit_bps".into());
                }
                if *value > 5_000 {
                    return Err("ceiling is 5000 BPS".into());
                }
            }
            GovernableAction::SetMaxCommissionBps { value } => {
                if *value >= self.max_commission_bps {
                    return Err(format!(
                        "max_commission_bps can only decrease (current: {})",
                        self.max_commission_bps
                    ));
                }
                if *value < 500 {
                    return Err("floor is 500 BPS (5%)".into());
                }
            }
            GovernableAction::SetGovernanceDelayEpochs { value } => {
                if *value <= self.governance_delay_epochs {
                    return Err(format!(
                        "governance_delay_epochs can only increase (current: {})",
                        self.governance_delay_epochs
                    ));
                }
                if *value < 10 {
                    return Err("floor is 10 epochs".into());
                }
                if *value > 1_000 {
                    return Err("ceiling is 1000 epochs".into());
                }
            }
            GovernableAction::SetGovernanceQuorumBps { value } => {
                if *value <= self.governance_quorum_bps {
                    return Err(format!(
                        "governance_quorum_bps can only increase (current: {})",
                        self.governance_quorum_bps
                    ));
                }
                if *value < 4_000 {
                    return Err("floor is 4000 BPS (40%)".into());
                }
                if *value > 9_000 {
                    return Err("ceiling is 9000 BPS (90%)".into());
                }
            }
            GovernableAction::SetGovernanceCriticalQuorumBps { value } => {
                if *value <= self.governance_critical_quorum_bps {
                    return Err(format!(
                        "governance_critical_quorum_bps can only increase (current: {})",
                        self.governance_critical_quorum_bps
                    ));
                }
                if *value < 5_000 {
                    return Err("floor is 5000 BPS (50%)".into());
                }
                if *value > 9_500 {
                    return Err("ceiling is 9500 BPS (95%)".into());
                }
            }
        }
        Ok(())
    }

    /// Apply an approved action.
    pub fn apply_action(&mut self, action: &GovernableAction) {
        match action {
            GovernableAction::SetSlashLivenessThresholdEpochs { value } => {
                self.slash_liveness_threshold_epochs = *value;
            }
            GovernableAction::SetMinDelegationSpark { value } => {
                self.min_delegation_spark = *value;
            }
            GovernableAction::SetProposalDepositSpark { value } => {
                self.proposal_deposit_spark = *value;
            }
            GovernableAction::SetSlashLivenessBps { value } => {
                self.slash_liveness_bps = *value;
            }
            GovernableAction::SetSlashDoublePrecommitBps { value } => {
                self.slash_double_precommit_bps = *value;
            }
            GovernableAction::SetSlashSurroundVoteBps { value } => {
                self.slash_surround_vote_bps = *value;
            }
            GovernableAction::SetMaxCommissionBps { value } => {
                self.max_commission_bps = *value;
            }
            GovernableAction::SetGovernanceDelayEpochs { value } => {
                self.governance_delay_epochs = *value;
            }
            GovernableAction::SetGovernanceQuorumBps { value } => {
                self.governance_quorum_bps = *value;
            }
            GovernableAction::SetGovernanceCriticalQuorumBps { value } => {
                self.governance_critical_quorum_bps = *value;
            }
        }
    }
}

impl Default for GovernableParams {
    fn default() -> Self {
        Self::default_mainnet()
    }
}

impl Encode for GovernableParams {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.slash_liveness_threshold_epochs.encode(buf);
        self.min_delegation_spark.encode(buf);
        self.proposal_deposit_spark.encode(buf);
        self.slash_liveness_bps.encode(buf);
        self.slash_double_precommit_bps.encode(buf);
        self.slash_surround_vote_bps.encode(buf);
        self.max_commission_bps.encode(buf);
        self.governance_delay_epochs.encode(buf);
        self.governance_quorum_bps.encode(buf);
        self.governance_critical_quorum_bps.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        3 * 8 + 4 * 4 + 8 + 2 * 4
    }
}

impl Decode for GovernableParams {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            slash_liveness_threshold_epochs: u64::decode(r)?,
            min_delegation_spark: u64::decode(r)?,
            proposal_deposit_spark: u64::decode(r)?,
            slash_liveness_bps: u32::decode(r)?,
            slash_double_precommit_bps: u32::decode(r)?,
            slash_surround_vote_bps: u32::decode(r)?,
            max_commission_bps: u32::decode(r)?,
            governance_delay_epochs: u64::decode(r)?,
            governance_quorum_bps: u32::decode(r)?,
            governance_critical_quorum_bps: u32::decode(r)?,
        })
    }
}

/// Phase of an active proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProposalPhase {
    /// Deliberation.
    Deliberation = 0,
    /// Commit.
    Commit = 1,
    /// Reveal.
    Reveal = 2,
    /// Tally.
    Tally = 3,
    /// Execution delay.
    ExecDelay = 4,
    /// Executed.
    Executed = 5,
    /// Failed.
    Failed = 6,
    /// Expired.
    Expired = 7,
    /// Cancelled.
    Cancelled = 8,
}

impl Encode for ProposalPhase {
    fn encode(&self, buf: &mut Vec<u8>) {
        (*self as u8).encode(buf);
    }

    fn encoded_len(&self) -> usize {
        1
    }
}

impl Decode for ProposalPhase {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        match u8::decode(r)? {
            0 => Ok(Self::Deliberation),
            1 => Ok(Self::Commit),
            2 => Ok(Self::Reveal),
            3 => Ok(Self::Tally),
            4 => Ok(Self::ExecDelay),
            5 => Ok(Self::Executed),
            6 => Ok(Self::Failed),
            7 => Ok(Self::Expired),
            8 => Ok(Self::Cancelled),
            b => Err(IndraError::InvalidBool { byte: b }),
        }
    }
}

/// Compact governance stake snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GovernanceSnapshot {
    /// Per-validator weights.
    pub weights: HashMap<Bytes32, u64>,
    /// Total stake denominator.
    pub total_stake: u64,
}

impl GovernanceSnapshot {
    /// Return whether yes stake meets quorum.
    pub fn quorum_met(&self, yes_stake: u64, quorum_bps: u32) -> bool {
        if self.total_stake == 0 {
            return false;
        }
        let required = (self.total_stake as u128).saturating_mul(quorum_bps as u128) / 10_000;
        (yes_stake as u128) > required
    }

    /// Return yes support in bps.
    pub fn support_bps(&self, yes_stake: u64) -> u32 {
        if self.total_stake == 0 {
            return 0;
        }
        ((yes_stake as u128 * 10_000) / self.total_stake as u128) as u32
    }
}

impl Encode for GovernanceSnapshot {
    fn encode(&self, buf: &mut Vec<u8>) {
        encode_u64_map(&self.weights, buf);
        self.total_stake.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        4 + self.weights.len() * 40 + 8
    }
}

impl Decode for GovernanceSnapshot {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            weights: decode_u64_map(r, "governance.snapshot.weights")?,
            total_stake: u64::decode(r)?,
        })
    }
}

/// Vote commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteCommit {
    /// Validator id.
    pub validator_id: Bytes32,
    /// Commitment hash.
    pub commit_hash: Bytes32,
    /// Epoch committed.
    pub committed_epoch: u64,
}

impl Encode for VoteCommit {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.validator_id.encode(buf);
        self.commit_hash.encode(buf);
        self.committed_epoch.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        72
    }
}

impl Decode for VoteCommit {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            validator_id: Bytes32::decode(r)?,
            commit_hash: Bytes32::decode(r)?,
            committed_epoch: u64::decode(r)?,
        })
    }
}

/// Revealed vote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VoteReveal {
    /// Validator id.
    pub validator_id: Bytes32,
    /// true = yes.
    pub vote: bool,
    /// Epoch revealed.
    pub revealed_epoch: u64,
}

impl Encode for VoteReveal {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.validator_id.encode(buf);
        self.vote.encode(buf);
        self.revealed_epoch.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        41
    }
}

impl Decode for VoteReveal {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            validator_id: Bytes32::decode(r)?,
            vote: bool::decode(r)?,
            revealed_epoch: u64::decode(r)?,
        })
    }
}

/// Governance redelegation overlay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceRedelegation {
    /// Delegator id.
    pub delegator_id: Bytes32,
    /// Source validator.
    pub from_validator: Bytes32,
    /// Target validator.
    pub to_validator: Bytes32,
    /// Amount shifted.
    pub amount_spark: u64,
}

impl Encode for GovernanceRedelegation {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.delegator_id.encode(buf);
        self.from_validator.encode(buf);
        self.to_validator.encode(buf);
        self.amount_spark.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        104
    }
}

impl Decode for GovernanceRedelegation {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            delegator_id: Bytes32::decode(r)?,
            from_validator: Bytes32::decode(r)?,
            to_validator: Bytes32::decode(r)?,
            amount_spark: u64::decode(r)?,
        })
    }
}

/// Queued parameter execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedExecution {
    /// Proposal id.
    pub proposal_id: Bytes32,
    /// Action to apply.
    pub action: GovernableAction,
    /// Earliest executable epoch.
    pub executable_epoch: u64,
    /// Whether executed.
    pub executed: bool,
}

impl Encode for QueuedExecution {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.proposal_id.encode(buf);
        self.action.encode(buf);
        self.executable_epoch.encode(buf);
        self.executed.encode(buf);
    }

    fn encoded_len(&self) -> usize {
        32 + self.action.encoded_len() + 8 + 1
    }
}

impl Decode for QueuedExecution {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            proposal_id: Bytes32::decode(r)?,
            action: GovernableAction::decode(r)?,
            executable_epoch: u64::decode(r)?,
            executed: bool::decode(r)?,
        })
    }
}

/// A full governance proposal record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalRecord {
    /// Proposal id.
    pub proposal_id: Bytes32,
    /// Proposer id.
    pub proposer_id: Bytes32,
    /// Proposer public key for refunds.
    pub proposer_pubkey: HybridPubKey,
    /// Tier.
    pub tier: ProposalTier,
    /// Action.
    pub action: GovernableAction,
    /// Title.
    pub title: String,
    /// Description.
    pub description: String,
    /// Deposit value.
    pub deposit_spark: u64,
    /// Whether deposit burned.
    pub deposit_burned: bool,
    /// Proposal epoch.
    pub proposed_epoch: u64,
    /// Commit start.
    pub commit_start_epoch: u64,
    /// Reveal start.
    pub reveal_start_epoch: u64,
    /// Tally epoch.
    pub tally_epoch: u64,
    /// Delay at proposal time.
    pub exec_delay_epochs: u64,
    /// Earliest execution epoch.
    pub executable_after_epoch: u64,
    /// Current phase.
    pub phase: ProposalPhase,
    /// Snapshot 1.
    pub snapshot1: Option<GovernanceSnapshot>,
    /// Commits.
    pub commits: HashMap<Bytes32, VoteCommit>,
    /// Reveals.
    pub reveals: HashMap<Bytes32, VoteReveal>,
    /// Redelegations.
    pub redelegations: Vec<GovernanceRedelegation>,
    /// Delegators already redelegated.
    pub redelegated_delegators: HashMap<Bytes32, ()>,
    /// Snapshot 2.
    pub snapshot2: Option<GovernanceSnapshot>,
    /// Yes stake.
    pub yes_stake: u64,
    /// No stake.
    pub no_stake: u64,
    /// Abstain stake.
    pub abstain_stake: u64,
    /// Pass/fail.
    pub passed: Option<bool>,
}

impl Encode for ProposalRecord {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.proposal_id.encode(buf);
        self.proposer_id.encode(buf);
        self.proposer_pubkey.encode(buf);
        self.tier.encode(buf);
        self.action.encode(buf);
        encode_string(&self.title, buf);
        encode_string(&self.description, buf);
        self.deposit_spark.encode(buf);
        self.deposit_burned.encode(buf);
        self.proposed_epoch.encode(buf);
        self.commit_start_epoch.encode(buf);
        self.reveal_start_epoch.encode(buf);
        self.tally_epoch.encode(buf);
        self.exec_delay_epochs.encode(buf);
        self.executable_after_epoch.encode(buf);
        self.phase.encode(buf);
        encode_option(&self.snapshot1, buf);
        encode_commit_map(&self.commits, buf);
        encode_reveal_map(&self.reveals, buf);
        encode_vec(&self.redelegations, buf);
        encode_set_map(&self.redelegated_delegators, buf);
        encode_option(&self.snapshot2, buf);
        self.yes_stake.encode(buf);
        self.no_stake.encode(buf);
        self.abstain_stake.encode(buf);
        self.passed.is_some().encode(buf);
        if let Some(passed) = self.passed {
            passed.encode(buf);
        }
    }

    fn encoded_len(&self) -> usize {
        32 + 32
            + self.proposer_pubkey.encoded_len()
            + self.tier.encoded_len()
            + self.action.encoded_len()
            + 2
            + self.title.len()
            + 2
            + self.description.len()
            + 8
            + 1
            + 6 * 8
            + self.phase.encoded_len()
            + option_len(&self.snapshot1)
            + commit_map_len(&self.commits)
            + reveal_map_len(&self.reveals)
            + vec_len(&self.redelegations)
            + set_map_len(&self.redelegated_delegators)
            + option_len(&self.snapshot2)
            + 3 * 8
            + 1
            + self.passed.map(|_| 1).unwrap_or(0)
    }
}

impl Decode for ProposalRecord {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            proposal_id: Bytes32::decode(r)?,
            proposer_id: Bytes32::decode(r)?,
            proposer_pubkey: HybridPubKey::decode(r)?,
            tier: ProposalTier::decode(r)?,
            action: GovernableAction::decode(r)?,
            title: decode_string(r)?,
            description: decode_string(r)?,
            deposit_spark: u64::decode(r)?,
            deposit_burned: bool::decode(r)?,
            proposed_epoch: u64::decode(r)?,
            commit_start_epoch: u64::decode(r)?,
            reveal_start_epoch: u64::decode(r)?,
            tally_epoch: u64::decode(r)?,
            exec_delay_epochs: u64::decode(r)?,
            executable_after_epoch: u64::decode(r)?,
            phase: ProposalPhase::decode(r)?,
            snapshot1: decode_option(r)?,
            commits: decode_commit_map(r)?,
            reveals: decode_reveal_map(r)?,
            redelegations: decode_vec(r, "governance.redelegations")?,
            redelegated_delegators: decode_set_map(r)?,
            snapshot2: decode_option(r)?,
            yes_stake: u64::decode(r)?,
            no_stake: u64::decode(r)?,
            abstain_stake: u64::decode(r)?,
            passed: if bool::decode(r)? {
                Some(bool::decode(r)?)
            } else {
                None
            },
        })
    }
}

/// Complete governance state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceState {
    /// Current params.
    pub params: GovernableParams,
    /// Proposals by id.
    pub proposals: HashMap<Bytes32, ProposalRecord>,
    /// Queued executions.
    pub queued_executions: Vec<QueuedExecution>,
    /// Governance nonces.
    pub gov_nonces: HashMap<Bytes32, u64>,
    /// Last proposal epoch by proposer.
    pub last_proposal_epoch: HashMap<Bytes32, u64>,
}

impl GovernanceState {
    /// New default governance state.
    pub fn new() -> Self {
        Self {
            params: GovernableParams::default_mainnet(),
            proposals: HashMap::new(),
            queued_executions: Vec::new(),
            gov_nonces: HashMap::new(),
            last_proposal_epoch: HashMap::new(),
        }
    }

    /// Count active proposals globally.
    pub fn active_proposal_count(&self) -> usize {
        self.proposals
            .values()
            .filter(|p| is_active_phase(p.phase))
            .count()
    }

    /// Count active proposals for proposer.
    pub fn active_proposals_by(&self, proposer: &Bytes32) -> usize {
        self.proposals
            .values()
            .filter(|p| &p.proposer_id == proposer && is_active_phase(p.phase))
            .count()
    }
}

impl Default for GovernanceState {
    fn default() -> Self {
        Self::new()
    }
}

impl Encode for GovernanceState {
    fn encode(&self, buf: &mut Vec<u8>) {
        self.params.encode(buf);
        encode_proposal_map(&self.proposals, buf);
        encode_vec(&self.queued_executions, buf);
        encode_u64_map(&self.gov_nonces, buf);
        encode_u64_map(&self.last_proposal_epoch, buf);
    }

    fn encoded_len(&self) -> usize {
        self.params.encoded_len()
            + proposal_map_len(&self.proposals)
            + vec_len(&self.queued_executions)
            + 4
            + self.gov_nonces.len() * 40
            + 4
            + self.last_proposal_epoch.len() * 40
    }
}

impl Decode for GovernanceState {
    fn decode(r: &mut ByteReader<'_>) -> IndraResult<Self> {
        Ok(Self {
            params: GovernableParams::decode(r)?,
            proposals: decode_proposal_map(r)?,
            queued_executions: decode_vec(r, "governance.queued_executions")?,
            gov_nonces: decode_u64_map(r, "governance.gov_nonces")?,
            last_proposal_epoch: decode_u64_map(r, "governance.last_proposal_epoch")?,
        })
    }
}

fn is_active_phase(phase: ProposalPhase) -> bool {
    matches!(
        phase,
        ProposalPhase::Deliberation
            | ProposalPhase::Commit
            | ProposalPhase::Reveal
            | ProposalPhase::Tally
            | ProposalPhase::ExecDelay
    )
}

fn encode_string(value: &str, buf: &mut Vec<u8>) {
    let bytes = value.as_bytes();
    (bytes.len() as u16).encode(buf);
    buf.extend_from_slice(bytes);
}

fn decode_string(r: &mut ByteReader<'_>) -> IndraResult<String> {
    let len = u16::decode(r)? as usize;
    let bytes = r.read_bytes(len)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| IndraError::InvariantViolation {
        message: "invalid UTF-8 governance string",
    })
}

fn encode_option<T: Encode>(value: &Option<T>, buf: &mut Vec<u8>) {
    value.is_some().encode(buf);
    if let Some(value) = value {
        value.encode(buf);
    }
}

fn decode_option<T: Decode>(r: &mut ByteReader<'_>) -> IndraResult<Option<T>> {
    Ok(if bool::decode(r)? {
        Some(T::decode(r)?)
    } else {
        None
    })
}

fn option_len<T: Encode>(value: &Option<T>) -> usize {
    1 + value.as_ref().map(|v| v.encoded_len()).unwrap_or(0)
}

fn encode_vec<T: Encode>(values: &[T], buf: &mut Vec<u8>) {
    (values.len() as u32).encode(buf);
    for value in values {
        value.encode(buf);
    }
}

fn decode_vec<T: Decode>(r: &mut ByteReader<'_>, field: &'static str) -> IndraResult<Vec<T>> {
    let count = u32::decode(r)? as usize;
    if count > 10_000 {
        return Err(IndraError::LengthExceeded {
            field,
            max: 10_000,
            actual: count,
        });
    }
    let mut values = Vec::with_capacity(count);
    for _ in 0..count {
        values.push(T::decode(r)?);
    }
    Ok(values)
}

fn vec_len<T: Encode>(values: &[T]) -> usize {
    4 + values.iter().map(Encode::encoded_len).sum::<usize>()
}

fn encode_u64_map(map: &HashMap<Bytes32, u64>, buf: &mut Vec<u8>) {
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by_key(|(key, _)| key.0);
    (entries.len() as u32).encode(buf);
    for (key, value) in entries {
        key.encode(buf);
        value.encode(buf);
    }
}

fn decode_u64_map(
    r: &mut ByteReader<'_>,
    field: &'static str,
) -> IndraResult<HashMap<Bytes32, u64>> {
    let count = u32::decode(r)? as usize;
    if count > 10_000 {
        return Err(IndraError::LengthExceeded {
            field,
            max: 10_000,
            actual: count,
        });
    }
    let mut map = HashMap::with_capacity(count);
    for _ in 0..count {
        let key = Bytes32::decode(r)?;
        let value = u64::decode(r)?;
        if map.insert(key, value).is_some() {
            return Err(IndraError::DuplicateEntries { field });
        }
    }
    Ok(map)
}

fn encode_set_map(map: &HashMap<Bytes32, ()>, buf: &mut Vec<u8>) {
    let mut entries: Vec<_> = map.keys().copied().collect();
    entries.sort_by_key(|key| key.0);
    (entries.len() as u32).encode(buf);
    for key in entries {
        key.encode(buf);
    }
}

fn decode_set_map(r: &mut ByteReader<'_>) -> IndraResult<HashMap<Bytes32, ()>> {
    let count = u32::decode(r)? as usize;
    let mut map = HashMap::with_capacity(count);
    for _ in 0..count {
        let key = Bytes32::decode(r)?;
        if map.insert(key, ()).is_some() {
            return Err(IndraError::DuplicateEntries {
                field: "governance.redelegated_delegators",
            });
        }
    }
    Ok(map)
}

fn set_map_len(map: &HashMap<Bytes32, ()>) -> usize {
    4 + map.len() * 32
}

fn encode_commit_map(map: &HashMap<Bytes32, VoteCommit>, buf: &mut Vec<u8>) {
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by_key(|(key, _)| key.0);
    (entries.len() as u32).encode(buf);
    for (key, value) in entries {
        key.encode(buf);
        value.encode(buf);
    }
}

fn decode_commit_map(r: &mut ByteReader<'_>) -> IndraResult<HashMap<Bytes32, VoteCommit>> {
    let count = u32::decode(r)? as usize;
    let mut map = HashMap::with_capacity(count);
    for _ in 0..count {
        let key = Bytes32::decode(r)?;
        let value = VoteCommit::decode(r)?;
        if key != value.validator_id {
            return Err(IndraError::InvariantViolation {
                message: "governance commit key must match validator_id",
            });
        }
        if map.insert(key, value).is_some() {
            return Err(IndraError::DuplicateEntries {
                field: "governance.commits",
            });
        }
    }
    Ok(map)
}

fn commit_map_len(map: &HashMap<Bytes32, VoteCommit>) -> usize {
    4 + map.len() * (32 + 72)
}

fn encode_reveal_map(map: &HashMap<Bytes32, VoteReveal>, buf: &mut Vec<u8>) {
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by_key(|(key, _)| key.0);
    (entries.len() as u32).encode(buf);
    for (key, value) in entries {
        key.encode(buf);
        value.encode(buf);
    }
}

fn decode_reveal_map(r: &mut ByteReader<'_>) -> IndraResult<HashMap<Bytes32, VoteReveal>> {
    let count = u32::decode(r)? as usize;
    let mut map = HashMap::with_capacity(count);
    for _ in 0..count {
        let key = Bytes32::decode(r)?;
        let value = VoteReveal::decode(r)?;
        if key != value.validator_id {
            return Err(IndraError::InvariantViolation {
                message: "governance reveal key must match validator_id",
            });
        }
        if map.insert(key, value).is_some() {
            return Err(IndraError::DuplicateEntries {
                field: "governance.reveals",
            });
        }
    }
    Ok(map)
}

fn reveal_map_len(map: &HashMap<Bytes32, VoteReveal>) -> usize {
    4 + map.len() * (32 + 41)
}

fn encode_proposal_map(map: &HashMap<Bytes32, ProposalRecord>, buf: &mut Vec<u8>) {
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by_key(|(key, _)| key.0);
    (entries.len() as u32).encode(buf);
    for (key, value) in entries {
        key.encode(buf);
        value.encode(buf);
    }
}

fn decode_proposal_map(r: &mut ByteReader<'_>) -> IndraResult<HashMap<Bytes32, ProposalRecord>> {
    let count = u32::decode(r)? as usize;
    let mut map = HashMap::with_capacity(count);
    for _ in 0..count {
        let key = Bytes32::decode(r)?;
        let value = ProposalRecord::decode(r)?;
        if key != value.proposal_id {
            return Err(IndraError::InvariantViolation {
                message: "governance proposal key must match proposal_id",
            });
        }
        if map.insert(key, value).is_some() {
            return Err(IndraError::DuplicateEntries {
                field: "governance.proposals",
            });
        }
    }
    Ok(map)
}

fn proposal_map_len(map: &HashMap<Bytes32, ProposalRecord>) -> usize {
    4 + map
        .iter()
        .map(|(_, proposal)| 32 + proposal.encoded_len())
        .sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governable_params_default_values_match_constants() {
        let params = GovernableParams::default_mainnet();
        assert_eq!(params.slash_liveness_bps, SLASH_LIVENESS_BPS);
        assert_eq!(
            params.slash_liveness_threshold_epochs,
            SLASH_LIVENESS_THRESHOLD_EPOCHS
        );
        assert_eq!(params.proposal_deposit_spark, 1_000 * SPARK_PER_INDRA);
    }

    #[test]
    fn validate_action_rejects_liveness_bps_zero() {
        let params = GovernableParams::default_mainnet();
        assert!(params
            .validate_action(&GovernableAction::SetSlashLivenessBps { value: 0 })
            .is_err());
    }

    #[test]
    fn apply_action_updates_params_correctly() {
        let mut params = GovernableParams::default_mainnet();
        params.apply_action(&GovernableAction::SetSlashLivenessBps { value: 25 });
        assert_eq!(params.slash_liveness_bps, 25);
    }

    #[test]
    fn governance_snapshot_quorum_met() {
        let snapshot = GovernanceSnapshot {
            weights: HashMap::new(),
            total_stake: 100,
        };
        assert!(snapshot.quorum_met(51, 5_000));
        assert!(!snapshot.quorum_met(50, 5_000));
    }

    #[test]
    fn governance_state_active_proposal_count() {
        let mut state = GovernanceState::new();
        let id = Bytes32::from([1u8; 32]);
        state.proposals.insert(
            id,
            ProposalRecord {
                proposal_id: id,
                proposer_id: Bytes32::from([2u8; 32]),
                proposer_pubkey: HybridPubKey {
                    classical_pk: Bytes32::from([2u8; 32]),
                    pq_pk: indra_core::VariableBytes::from_slice(&[0u8; 2592]).unwrap(),
                },
                tier: ProposalTier::Standard,
                action: GovernableAction::SetSlashLivenessThresholdEpochs { value: 4 },
                title: "t".to_string(),
                description: "d".to_string(),
                deposit_spark: 1,
                deposit_burned: false,
                proposed_epoch: 0,
                commit_start_epoch: 1,
                reveal_start_epoch: 2,
                tally_epoch: 3,
                exec_delay_epochs: 4,
                executable_after_epoch: 7,
                phase: ProposalPhase::Deliberation,
                snapshot1: None,
                commits: HashMap::new(),
                reveals: HashMap::new(),
                redelegations: Vec::new(),
                redelegated_delegators: HashMap::new(),
                snapshot2: None,
                yes_stake: 0,
                no_stake: 0,
                abstain_stake: 0,
                passed: None,
            },
        );
        assert_eq!(state.active_proposal_count(), 1);
    }
}
