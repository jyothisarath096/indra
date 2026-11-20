//! Per-peer token bucket rate limiting for the INDRA async transport.

use std::{
    collections::HashMap,
    sync::{atomic::{AtomicU64, Ordering}, Arc},
    time::Instant,
};

#[cfg(test)]
use std::time::Duration;

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
}

impl MessageClass {
    /// Stable class order used by metrics and bounded internal arrays.
    pub const ALL: [Self; 11] = [
        Self::Vote,
        Self::BlockOrProposal,
        Self::Status,
        Self::PeerList,
        Self::BlockRequest,
        Self::Tx,
        Self::StakingOp,
        Self::GovernanceOp,
        Self::PingPong,
        Self::BlockResponse,
        Self::QCResponse,
    ];

    /// Stable Prometheus label for this message class.
    pub const fn metric_name(self) -> &'static str {
        match self {
            Self::Vote => "vote",
            Self::BlockOrProposal => "block_or_proposal",
            Self::Status => "status",
            Self::PeerList => "peer_list",
            Self::BlockRequest => "block_request",
            Self::Tx => "tx",
            Self::StakingOp => "staking_op",
            Self::GovernanceOp => "governance_op",
            Self::PingPong => "ping_pong",
            Self::BlockResponse => "block_response",
            Self::QCResponse => "qc_response",
        }
    }

    /// Classify a protocol message.
    pub fn from_message(msg: &Message) -> Self {
        match msg {
            Message::Vote(_) => Self::Vote,
            Message::Block(_) => Self::BlockOrProposal,
            Message::Status { .. } => Self::Status,
            Message::PeerList(_) => Self::PeerList,
            Message::RequestBlocks { .. }
            | Message::RequestProposal { .. }
            | Message::RequestQC { .. } => Self::BlockRequest,
            Message::Tx(_) | Message::TxStem(_) => Self::Tx,
            Message::StakingOp(_) => Self::StakingOp,
            Message::GovernanceOp(_) => Self::GovernanceOp,
            Message::Ping(_) | Message::Pong(_) => Self::PingPong,
            Message::BlockResponse { .. } => Self::BlockResponse,
            Message::QCResponse { .. } => Self::QCResponse,
        }
    }

    /// True for messages that authenticated validator peers must be able to
    /// send during consensus, sync, and recovery without punitive count-bucket
    /// ban risk. These classes may still be subject to byte-budget protection.
    pub fn is_protocol_necessary_for_validators(self) -> bool {
        matches!(
            self,
            Self::Vote | Self::Status | Self::BlockRequest | Self::BlockResponse | Self::QCResponse
        )
    }

    /// True when a per-peer byte bucket applies.
    pub fn needs_per_peer_byte_limit(msg: &Message) -> bool {
        matches!(
            msg,
            Message::Block(_)
                | Message::BlockResponse { .. }
                | Message::QCResponse { .. }
                | Message::Vote(_)
                | Message::Tx(_)
                | Message::TxStem(_)
                | Message::StakingOp(_)
                | Message::GovernanceOp(_)
        )
    }

    /// True when a global byte bucket applies.
    pub fn needs_global_byte_limit(msg: &Message) -> bool {
        matches!(msg, Message::Block(_) | Message::BlockResponse { .. })
    }
}

/// Process-wide counters for bounded, non-punitive rate-limit drops.
#[derive(Debug)]
pub struct RateLimitMetrics {
    drops_by_class: [Arc<AtomicU64>; 11],
    disconnects_total: Arc<AtomicU64>,
}

impl RateLimitMetrics {
    fn counter_for(&self, class: MessageClass) -> &AtomicU64 {
        let [vote, block_or_proposal, status, peer_list, block_request, tx, staking_op,
            governance_op, ping_pong, block_response, qc_response] = &self.drops_by_class;
        match class {
            MessageClass::Vote => vote,
            MessageClass::BlockOrProposal => block_or_proposal,
            MessageClass::Status => status,
            MessageClass::PeerList => peer_list,
            MessageClass::BlockRequest => block_request,
            MessageClass::Tx => tx,
            MessageClass::StakingOp => staking_op,
            MessageClass::GovernanceOp => governance_op,
            MessageClass::PingPong => ping_pong,
            MessageClass::BlockResponse => block_response,
            MessageClass::QCResponse => qc_response,
        }
    }

    /// Create empty network rate-limit counters.
    pub fn new() -> Self {
        Self {
            drops_by_class: std::array::from_fn(|_| Arc::new(AtomicU64::new(0))),
            disconnects_total: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Record one dropped message by its stable class.
    pub fn record_drop(&self, class: MessageClass) {
        self.counter_for(class).fetch_add(1, Ordering::Relaxed);
    }

    /// Record one sustained-flood disconnect.
    pub fn record_disconnect(&self) {
        self.disconnects_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Read a class counter for metrics rendering.
    pub fn drops_for(&self, class: MessageClass) -> u64 {
        self.counter_for(class).load(Ordering::Relaxed)
    }

    /// Read the sustained-flood disconnect counter.
    pub fn disconnects(&self) -> u64 {
        self.disconnects_total.load(Ordering::Relaxed)
    }
}

impl Default for RateLimitMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-peer rate limiter.
#[derive(Debug, Clone)]
pub struct PeerRateLimiter {
    count_buckets: HashMap<MessageClass, TokenBucket>,
    per_peer_byte_bucket: TokenBucket,
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
        Self::with_default_buckets()
    }

    /// Construct a rate limiter for unauthenticated/observer-like callers.
    #[cfg(test)]
    pub fn new_for_unauthenticated() -> Self {
        Self::with_default_buckets()
    }

    /// Construct the authenticated-validator limiter with a non-refilling
    /// vote bucket so peer-manager burst-boundary tests do not depend on wall
    /// clock time while awaiting actor delivery.
    #[cfg(test)]
    pub(crate) fn new_for_test_with_frozen_vote_bucket() -> Self {
        let mut limiter = Self::with_default_buckets();
        limiter
            .count_buckets
            .insert(MessageClass::Vote, TokenBucket::new(0, 80));
        limiter
    }

    fn with_default_buckets() -> Self {
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

        Self {
            count_buckets,
            per_peer_byte_bucket: TokenBucket::new_bytes(33_554_432, 67_108_864),
        }
    }

    /// Check whether a message should be accepted.
    ///
    /// Returns `Some(violation)` when rate limited, `None` when allowed.
    pub fn check(&mut self, msg: &Message, msg_size: usize) -> Option<RateLimitViolation> {
        let class = MessageClass::from_message(msg);
        let count_ok = self
            .count_buckets
            .get_mut(&class)
            .map(|bucket| bucket.try_consume(1))
            .unwrap_or(true);

        let byte_ok = if MessageClass::needs_per_peer_byte_limit(msg) {
            self.per_peer_byte_bucket.try_consume_bytes(msg_size as u64)
        } else {
            true
        };

        if !byte_ok {
            return Some(RateLimitViolation {
                class,
                reason: RateLimitReason::Byte,
            });
        }
        if !count_ok {
            return Some(RateLimitViolation {
                class,
                reason: RateLimitReason::Count,
            });
        }
        None
    }
}

impl Default for PeerRateLimiter {
    fn default() -> Self {
        Self::new()
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

impl Default for GlobalRateLimiter {
    fn default() -> Self {
        Self::new()
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
        transaction::{InputV1, OutputV1, TransactionV1},
        vote::{VoteStep, VoteV1},
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
            snapshot_root: Bytes32::ZERO,
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
                cold_authorization: None,
            },
            signature: dummy_signature(),
        })
    }

    fn dummy_transaction() -> TransactionV1 {
        TransactionV1 {
            version: indra_core::ProtocolVersion(
                indra_core::types::primitives::TRANSACTION_PROTOCOL_VERSION,
            ),
            signature_module_id: 1,
            inputs: vec![InputV1 {
                utxo_id: Bytes32::from([0x41; 32]),
            }],
            outputs: vec![OutputV1 {
                value_spark: 2,
                owner_pubkey: indra_core::types::crypto::HybridPubKey {
                    classical_pk: Bytes32::from([0x42; 32]),
                    pq_pk: VariableBytes::from_slice(&[0x43; 32]).unwrap(),
                },
                lock_height: 0,
            }],
            fee_amount: 1,
            signature: dummy_signature(),
        }
    }

    #[test]
    fn tx_stem_and_fluff_share_the_transaction_rate_limit_bucket() {
        let tx = dummy_transaction();
        assert_eq!(
            MessageClass::from_message(&Message::Tx(tx.clone())),
            MessageClass::Tx
        );
        assert_eq!(
            MessageClass::from_message(&Message::TxStem(tx.clone())),
            MessageClass::Tx
        );
        assert_eq!(
            MessageClass::needs_per_peer_byte_limit(&Message::Tx(tx.clone())),
            MessageClass::needs_per_peer_byte_limit(&Message::TxStem(tx))
        );
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
    fn vote_bucket_first_full_token_refills_after_fifty_milliseconds() {
        let mut before_boundary = TokenBucket::new(20, 80);
        assert!(before_boundary.try_consume(80));
        before_boundary.last_refill = Instant::now() - Duration::from_millis(49);
        assert!(!before_boundary.try_consume(1));

        let mut at_boundary = TokenBucket::new(20, 80);
        assert!(at_boundary.try_consume(80));
        at_boundary.last_refill = Instant::now() - Duration::from_millis(50);
        assert!(at_boundary.try_consume(1));
    }

    #[test]
    fn test_byte_bucket_single_large_message() {
        let mut bucket = TokenBucket::new_bytes(1024, 2048);
        assert!(!bucket.try_consume_bytes(4096));
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
    fn authenticated_vote_flood_is_finitely_limited() {
        let mut limiter = PeerRateLimiter::new();
        let msg = dummy_vote();
        for _ in 0..80 {
            assert_eq!(limiter.check(&msg, 512), None);
        }
        assert!(limiter.check(&msg, 512).is_some());
    }

    #[test]
    fn authenticated_qc_response_flood_is_finitely_limited() {
        let mut limiter = PeerRateLimiter::new_for_authenticated_validator();
        let msg = Message::QCResponse {
            height: 1,
            qc_bytes: vec![0u8; 1_000_000],
        };
        for _ in 0..10 {
            assert_eq!(limiter.check(&msg, 1_000_000), None);
        }
        assert!(limiter.check(&msg, 1_000_000).is_some());
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
    fn authenticated_validator_status_burst_is_finitely_limited() {
        let mut limiter = PeerRateLimiter::new_for_authenticated_validator();
        let msg = Message::Status {
            height: 42,
            tip_hash: Bytes32::from([0x42; 32]),
            round: 7,
        };
        for _ in 0..4 {
            assert_eq!(limiter.check(&msg, 256), None);
        }
        assert!(limiter.check(&msg, 256).is_some());
    }

    #[test]
    fn authenticated_validator_block_request_burst_is_finitely_limited() {
        let mut limiter = PeerRateLimiter::new_for_authenticated_validator();
        let msg = Message::RequestBlocks {
            from_height: 1,
            to_height: 50,
        };
        for _ in 0..10 {
            assert_eq!(limiter.check(&msg, 256), None);
        }
        assert!(limiter.check(&msg, 256).is_some());
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
    fn normal_full_consensus_round_is_well_below_authenticated_limits() {
        let mut limiter = PeerRateLimiter::new_for_authenticated_validator();
        let messages = [
            dummy_vote(),
            dummy_vote(),
            Message::QCResponse {
                height: 1,
                qc_bytes: vec![0u8; 1_000_000],
            },
        ];
        for msg in messages {
            let size = msg.encode_wire().unwrap().len();
            assert_eq!(limiter.check(&msg, size), None);
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
