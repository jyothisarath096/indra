//! Per-peer token bucket rate limiting for the INDRA async transport.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use crate::message::Message;

const SCALE: u64 = 1_000;

/// Token bucket with fixed-point integer arithmetic.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    tokens: u64,
    capacity: u64,
    refill_per_ms: u64,
    last_refill: Instant,
    unit_scale: u64,
}

impl TokenBucket {
    /// Create a message-count bucket.
    pub fn new(refill_per_sec: u64, burst: u64) -> Self {
        Self {
            tokens: burst.saturating_mul(SCALE),
            capacity: burst.saturating_mul(SCALE),
            refill_per_ms: refill_per_sec.saturating_mul(SCALE) / 1000,
            last_refill: Instant::now(),
            unit_scale: SCALE,
        }
    }

    /// Create a byte bucket.
    pub fn new_bytes(refill_per_sec: u64, burst: u64) -> Self {
        Self {
            tokens: burst,
            capacity: burst,
            refill_per_ms: refill_per_sec / 1000,
            last_refill: Instant::now(),
            unit_scale: 1,
        }
    }

    fn refill(&mut self) {
        let elapsed_ms = self.last_refill.elapsed().as_millis() as u64;
        if elapsed_ms == 0 {
            return;
        }
        self.tokens = self
            .tokens
            .saturating_add(elapsed_ms.saturating_mul(self.refill_per_ms))
            .min(self.capacity);
        self.last_refill = Instant::now();
    }

    /// Try to consume `amount` tokens.
    pub fn try_consume(&mut self, amount: u64) -> bool {
        self.refill();
        let cost = amount.saturating_mul(self.unit_scale);
        if self.tokens >= cost {
            self.tokens -= cost;
            true
        } else {
            false
        }
    }

    /// Try to consume `bytes` bytes from a byte bucket.
    pub fn try_consume_bytes(&mut self, bytes: u64) -> bool {
        self.try_consume(bytes)
    }
}

/// Message class for rate limiting decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MessageClass {
    /// Consensus votes.
    Vote,
    /// Proposals and full blocks.
    BlockOrProposal,
    /// Status announcements.
    Status,
    /// Peer discovery gossip.
    PeerList,
    /// Block/QC/proposal requests.
    BlockRequest,
    /// Transactions.
    Tx,
    /// Staking operations.
    StakingOp,
    /// Governance operations.
    GovernanceOp,
    /// Ping and pong keepalives.
    PingPong,
    /// Block sync responses.
    BlockResponse,
    /// QC sync responses.
    QCResponse,
    /// Commit-reveal VRF election gossip.
    VrfElection,
}

impl MessageClass {
    /// Classify a protocol message.
    pub fn from_message(msg: &Message) -> Self {
        match msg {
            Message::Vote(_) => Self::Vote,
            Message::Block(_) => Self::BlockOrProposal,
            Message::Status { .. } => Self::Status,
            Message::PeerList(_) => Self::PeerList,
            Message::RequestBlocks { .. }
            | Message::RequestProposal { .. }
            | Message::RequestQC { .. }
            | Message::RequestVrfReveals { .. } => Self::BlockRequest,
            Message::Tx(_) => Self::Tx,
            Message::StakingOp(_) => Self::StakingOp,
            Message::GovernanceOp(_) => Self::GovernanceOp,
            Message::Ping(_) | Message::Pong(_) => Self::PingPong,
            Message::BlockResponse { .. } => Self::BlockResponse,
            Message::QCResponse { .. } | Message::VrfRevealsResponse { .. } => Self::QCResponse,
            Message::VrfCommit(_) | Message::VrfReveal(_) => Self::VrfElection,
        }
    }

    /// True for consensus messages whose legitimate volume is bounded by
    /// protocol slots rather than wall-clock message rate.
    ///
    /// These messages must not trigger punitive count-bucket penalties:
    /// the consensus driver already enforces one vote/commit/reveal per
    /// validator slot, and banning authenticated validators for duplicate
    /// gossip can fragment BFT liveness.
    pub fn is_consensus_slot_message(self) -> bool {
        matches!(self, Self::Vote | Self::VrfElection)
    }

    /// True for messages that authenticated validator peers must be able to
    /// send during consensus, sync, and recovery without punitive count-bucket
    /// ban risk. These classes may still be subject to byte-budget protection.
    pub fn is_protocol_necessary_for_validators(self) -> bool {
        matches!(
            self,
            Self::Vote
                | Self::VrfElection
                | Self::Status
                | Self::BlockRequest
                | Self::BlockResponse
                | Self::QCResponse
        )
    }

    /// True when a per-peer byte bucket applies.
    pub fn needs_per_peer_byte_limit(msg: &Message) -> bool {
        matches!(
            msg,
            Message::Block(_)
                | Message::BlockResponse { .. }
                | Message::VrfRevealsResponse { .. }
                | Message::Tx(_)
                | Message::StakingOp(_)
                | Message::GovernanceOp(_)
        )
    }

    /// True when a global byte bucket applies.
    pub fn needs_global_byte_limit(msg: &Message) -> bool {
        matches!(
            msg,
            Message::Block(_) | Message::BlockResponse { .. } | Message::VrfRevealsResponse { .. }
        )
    }
}

/// Escalating strike counter with simple time-based decay.
#[derive(Debug, Clone)]
pub struct StrikeCounter {
    count: u32,
    last_violation: Option<Instant>,
}

impl StrikeCounter {
    /// Create an empty strike counter.
    pub fn new() -> Self {
        Self {
            count: 0,
            last_violation: None,
        }
    }

    /// Record a violation and return the score penalty.
    pub fn record(&mut self) -> i32 {
        if self
            .last_violation
            .map(|t| t.elapsed() > Duration::from_secs(60))
            .unwrap_or(false)
        {
            self.count = self.count.saturating_sub(self.count / 2 + 1);
        }
        self.count = self.count.saturating_add(1);
        self.last_violation = Some(Instant::now());
        match self.count {
            1 => 2,
            2..=5 => 5,
            _ => 10,
        }
    }
}

/// Per-peer rate limiter.
#[derive(Debug, Clone)]
pub struct PeerRateLimiter {
    count_buckets: HashMap<MessageClass, TokenBucket>,
    per_peer_byte_bucket: TokenBucket,
    strikes: StrikeCounter,
    authenticated_validator: bool,
}

/// Why a message exceeded the rate limiter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitReason {
    /// Message count bucket for the class was exhausted.
    Count,
    /// Per-peer byte bucket was exhausted.
    Byte,
}

/// A rate-limit violation with enough context for peer-manager policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitViolation {
    /// Message class that exceeded a limiter.
    pub class: MessageClass,
    /// Score penalty suggested by the strike escalation schedule.
    pub penalty: i32,
    /// Which limiter was exhausted.
    pub reason: RateLimitReason,
}

impl PeerRateLimiter {
    /// Construct the default transport rate limiter.
    pub fn new() -> Self {
        Self::new_for_authenticated_validator()
    }

    /// Construct a rate limiter for a cryptographically authenticated validator
    /// transport connection.
    pub fn new_for_authenticated_validator() -> Self {
        Self::with_authentication(true)
    }

    /// Construct a rate limiter for unauthenticated/observer-like callers.
    #[cfg(test)]
    pub fn new_for_unauthenticated() -> Self {
        Self::with_authentication(false)
    }

    fn with_authentication(authenticated_validator: bool) -> Self {
        let mut count_buckets = HashMap::new();
        count_buckets.insert(MessageClass::Vote, TokenBucket::new(20, 80));
        count_buckets.insert(MessageClass::BlockOrProposal, TokenBucket::new(5, 10));
        count_buckets.insert(MessageClass::Status, TokenBucket::new(2, 4));
        count_buckets.insert(MessageClass::PeerList, TokenBucket::new(2, 4));
        count_buckets.insert(MessageClass::BlockRequest, TokenBucket::new(5, 10));
        count_buckets.insert(MessageClass::Tx, TokenBucket::new(50, 200));
        count_buckets.insert(MessageClass::StakingOp, TokenBucket::new(10, 50));
        count_buckets.insert(MessageClass::GovernanceOp, TokenBucket::new(5, 20));
        count_buckets.insert(MessageClass::PingPong, TokenBucket::new(2, 4));
        // Sync catch-up can legitimately receive several BlockResponse
        // messages back-to-back after pipelined RequestBlocks. Keep the
        // message-count bucket permissive enough for honest bursts and rely
        // on the byte buckets below as the primary abuse guard for large
        // payloads.
        count_buckets.insert(MessageClass::BlockResponse, TokenBucket::new(20, 64));
        count_buckets.insert(MessageClass::QCResponse, TokenBucket::new(5, 10));
        count_buckets.insert(MessageClass::VrfElection, TokenBucket::new(8, 16));

        Self {
            count_buckets,
            per_peer_byte_bucket: TokenBucket::new_bytes(33_554_432, 67_108_864),
            strikes: StrikeCounter::new(),
            authenticated_validator,
        }
    }

    /// Check whether a message should be accepted.
    ///
    /// Returns `Some(violation)` when rate limited, `None` when allowed.
    pub fn check(&mut self, msg: &Message, msg_size: usize) -> Option<RateLimitViolation> {
        let class = MessageClass::from_message(msg);
        let bypass_count_bucket =
            self.authenticated_validator && class.is_protocol_necessary_for_validators();
        let count_ok = if bypass_count_bucket {
            true
        } else {
            self.count_buckets
                .get_mut(&class)
                .map(|bucket| bucket.try_consume(1))
                .unwrap_or(true)
        };

        let byte_ok = if MessageClass::needs_per_peer_byte_limit(msg) {
            self.per_peer_byte_bucket.try_consume_bytes(msg_size as u64)
        } else {
            true
        };

        if !byte_ok {
            return Some(RateLimitViolation {
                class,
                penalty: self.strikes.record(),
                reason: RateLimitReason::Byte,
            });
        }
        if !count_ok {
            return Some(RateLimitViolation {
                class,
                penalty: self.strikes.record(),
                reason: RateLimitReason::Count,
            });
        }
        None
    }
}

/// Global large-payload limiter owned by the peer-manager actor.
#[derive(Debug, Clone)]
pub struct GlobalRateLimiter {
    large_payload_bucket: TokenBucket,
}

impl GlobalRateLimiter {
    /// Construct the default global limiter.
    pub fn new() -> Self {
        Self {
            large_payload_bucket: TokenBucket::new_bytes(134_217_728, 268_435_456),
        }
    }

    /// Check a large payload against the shared byte budget.
    pub fn check_large_payload(&mut self, msg_size: usize) -> bool {
        self.large_payload_bucket.try_consume_bytes(msg_size as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;
    use indra_core::types::{
        crypto::HybridSignature,
        governance::{GovernanceActionType, GovernanceOpV2, GovernancePayload},
        primitives::{Bytes32, VariableBytes},
        staking::{StakingOp, StakingOpBody},
        vote::{VoteStep, VoteV1},
        vrf_election::{VrfCommit, VrfReveal},
    };

    fn dummy_signature() -> HybridSignature {
        HybridSignature {
            classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
            pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
        }
    }

    fn dummy_vote() -> Message {
        Message::Vote(VoteV1 {
            height: 1,
            round: 0,
            step: VoteStep::Prevote,
            block_hash: Bytes32::ZERO,
            validator_id: Bytes32::ZERO,
            election_result_hash: None,
            signature: dummy_signature(),
        })
    }

    fn dummy_vrf_commit() -> Message {
        Message::VrfCommit(VrfCommit {
            chain_id_hash: Bytes32::from([0x01; 32]),
            height: 1,
            round: 0,
            validator_id: Bytes32::from([0x02; 32]),
            vrf_pubkey: [0x03; 32],
            commit_hash: Bytes32::from([0x04; 32]),
            signature: dummy_signature(),
        })
    }

    fn dummy_vrf_reveal() -> Message {
        Message::VrfReveal(VrfReveal {
            chain_id_hash: Bytes32::from([0x01; 32]),
            height: 1,
            round: 0,
            validator_id: Bytes32::from([0x02; 32]),
            vrf_pubkey: [0x03; 32],
            vrf_output: Bytes32::from([0x04; 32]),
            vrf_proof: VariableBytes::from_slice(&[0x05; 80]).unwrap(),
            commit_hash: Bytes32::from([0x06; 32]),
            signature: dummy_signature(),
        })
    }

    fn dummy_staking_op() -> Message {
        Message::StakingOp(StakingOp {
            body: StakingOpBody::ClaimRewards {
                validator_id: Bytes32::from([0x21; 32]),
                delegator_pubkey: indra_core::types::crypto::HybridPubKey {
                    classical_pk: Bytes32::from([0x22; 32]),
                    pq_pk: VariableBytes::from_slice(&[0x23; 32]).unwrap(),
                },
                cold_authorization: None,
            },
            nonce: 1,
            signature: dummy_signature(),
        })
    }

    fn dummy_governance_op() -> Message {
        Message::GovernanceOp(GovernanceOpV2 {
            action_type: GovernanceActionType::CommitVote,
            signer_id: Bytes32::from([0x31; 32]),
            nonce: 1,
            payload: GovernancePayload::Commit {
                proposal_id: Bytes32::from([0x32; 32]),
                commit_hash: Bytes32::from([0x33; 32]),
            },
            signature: dummy_signature(),
        })
    }

    #[test]
    fn test_bucket_starts_full() {
        let mut bucket = TokenBucket::new(20, 80);
        assert!(bucket.try_consume(80));
    }

    #[test]
    fn test_bucket_depletes() {
        let mut bucket = TokenBucket::new(1, 2);
        assert!(bucket.try_consume(1));
        assert!(bucket.try_consume(1));
        assert!(!bucket.try_consume(1));
    }

    #[test]
    fn test_bucket_refills() {
        let mut bucket = TokenBucket::new(20, 20);
        assert!(bucket.try_consume(20));
        assert!(!bucket.try_consume(1));
        bucket.last_refill = Instant::now() - Duration::from_millis(100);
        assert!(bucket.try_consume(1));
    }

    #[test]
    fn test_byte_bucket_single_large_message() {
        let mut bucket = TokenBucket::new_bytes(1024, 2048);
        assert!(!bucket.try_consume_bytes(4096));
    }

    #[test]
    fn test_strike_escalation() {
        let mut strikes = StrikeCounter::new();
        assert_eq!(strikes.record(), 2);
        assert_eq!(strikes.record(), 5);
        assert_eq!(strikes.record(), 5);
        assert_eq!(strikes.record(), 5);
        assert_eq!(strikes.record(), 5);
        assert_eq!(strikes.record(), 10);
    }

    #[test]
    fn test_strike_decay() {
        let mut strikes = StrikeCounter::new();
        let _ = strikes.record();
        let _ = strikes.record();
        strikes.last_violation = Some(Instant::now() - Duration::from_secs(61));
        assert_eq!(strikes.record(), 2);
    }

    #[test]
    fn test_legitimate_vote_rate_never_limited() {
        let mut limiter = PeerRateLimiter::new();
        let msg = dummy_vote();
        for _ in 0..10 {
            assert_eq!(limiter.check(&msg, 512), None);
            if let Some(bucket) = limiter.count_buckets.get_mut(&MessageClass::Vote) {
                bucket.last_refill = Instant::now() - Duration::from_secs(3);
            }
        }
    }

    #[test]
    fn staking_and_governance_ops_have_tight_rate_limits() {
        let mut limiter = PeerRateLimiter::new();
        let staking = dummy_staking_op();
        let governance = dummy_governance_op();

        for _ in 0..50 {
            assert_eq!(limiter.check(&staking, 512), None);
        }
        assert!(matches!(
            limiter.check(&staking, 512),
            Some(RateLimitViolation {
                class: MessageClass::StakingOp,
                ..
            })
        ));

        let mut limiter = PeerRateLimiter::new();
        for _ in 0..20 {
            assert_eq!(limiter.check(&governance, 512), None);
        }
        assert!(matches!(
            limiter.check(&governance, 512),
            Some(RateLimitViolation {
                class: MessageClass::GovernanceOp,
                ..
            })
        ));
    }

    #[test]
    fn vote_duplicate_does_not_penalize_authenticated_validator() {
        let mut limiter = PeerRateLimiter::new();
        let msg = dummy_vote();
        for _ in 0..100 {
            assert_eq!(limiter.check(&msg, 512), None);
        }
    }

    #[test]
    fn vrf_commit_duplicate_does_not_penalize_authenticated_validator() {
        let mut limiter = PeerRateLimiter::new();
        let msg = dummy_vrf_commit();
        for _ in 0..100 {
            assert_eq!(limiter.check(&msg, 512), None);
        }
    }

    #[test]
    fn vrf_reveal_duplicate_does_not_penalize_authenticated_validator() {
        let mut limiter = PeerRateLimiter::new();
        let msg = dummy_vrf_reveal();
        for _ in 0..100 {
            assert_eq!(limiter.check(&msg, 512), None);
        }
    }

    #[test]
    fn non_consensus_flood_still_triggers_rate_limit() {
        let mut limiter = PeerRateLimiter::new();
        let msg = Message::Ping(1);
        let mut limited = false;
        for _ in 0..10 {
            if limiter.check(&msg, 512).is_some() {
                limited = true;
                break;
            }
        }
        assert!(limited);
    }

    #[test]
    fn authenticated_validator_status_burst_does_not_trigger_penalty() {
        let mut limiter = PeerRateLimiter::new_for_authenticated_validator();
        let msg = Message::Status {
            height: 42,
            tip_hash: Bytes32::from([0x42; 32]),
            round: 7,
        };
        for _ in 0..100 {
            assert_eq!(limiter.check(&msg, 256), None);
        }
    }

    #[test]
    fn authenticated_validator_block_request_burst_does_not_ban() {
        let mut limiter = PeerRateLimiter::new_for_authenticated_validator();
        let msg = Message::RequestBlocks {
            from_height: 1,
            to_height: 50,
        };
        for _ in 0..100 {
            assert_eq!(limiter.check(&msg, 256), None);
        }
    }

    #[test]
    fn unauthenticated_peer_status_flood_still_rate_limited() {
        let mut limiter = PeerRateLimiter::new_for_unauthenticated();
        let msg = Message::Status {
            height: 42,
            tip_hash: Bytes32::from([0x42; 32]),
            round: 7,
        };
        let mut limited = false;
        for _ in 0..10 {
            if let Some(violation) = limiter.check(&msg, 256) {
                assert_eq!(violation.class, MessageClass::Status);
                assert_eq!(violation.reason, RateLimitReason::Count);
                limited = true;
                break;
            }
        }
        assert!(limited);
    }

    #[test]
    fn authenticated_validator_protocol_messages_still_hit_byte_limits() {
        let mut limiter = PeerRateLimiter::new_for_authenticated_validator();
        let msg = Message::BlockResponse {
            blocks: Vec::new(),
            lowest_available: None,
            highest_available: None,
        };
        let violation = limiter
            .check(&msg, 128 * 1024 * 1024)
            .expect("large response should exhaust per-peer byte bucket");
        assert_eq!(violation.class, MessageClass::BlockResponse);
        assert_eq!(violation.reason, RateLimitReason::Byte);
    }

    #[test]
    fn test_global_rate_limiter() {
        let mut limiter = GlobalRateLimiter::new();
        assert!(limiter.check_large_payload(64 * 1024 * 1024));
        assert!(limiter.check_large_payload(64 * 1024 * 1024));
        assert!(!limiter.check_large_payload(200 * 1024 * 1024));
    }

    #[test]
    fn test_all_classes_at_legitimate_rates() {
        let mut limiter = PeerRateLimiter::new();
        let messages = vec![
            Message::Status {
                height: 1,
                tip_hash: Bytes32::ZERO,
                round: 0,
            },
            Message::RequestQC { height: 1 },
            Message::Ping(1),
            Message::QCResponse {
                height: 1,
                qc_bytes: vec![1, 2, 3],
            },
        ];
        for msg in messages {
            assert_eq!(limiter.check(&msg, 256), None);
        }
    }

    #[test]
    fn legitimate_sync_burst_does_not_trigger_rate_limit_penalty() {
        let mut limiter = PeerRateLimiter::new();
        let msg = Message::BlockResponse {
            blocks: Vec::new(),
            lowest_available: None,
            highest_available: None,
        };

        for _ in 0..50 {
            assert_eq!(
                limiter.check(&msg, 1024),
                None,
                "honest catch-up BlockResponse bursts should not be penalized"
            );
        }
    }

    #[test]
    fn unsolicited_block_response_flood_still_rate_limited() {
        let mut limiter = PeerRateLimiter::new_for_unauthenticated();
        let msg = Message::BlockResponse {
            blocks: Vec::new(),
            lowest_available: None,
            highest_available: None,
        };

        let mut limited = false;
        for _ in 0..100 {
            if limiter.check(&msg, 1024).is_some() {
                limited = true;
                break;
            }
        }

        assert!(
            limited,
            "unsolicited BlockResponse floods must still exhaust the count bucket"
        );
    }
}
