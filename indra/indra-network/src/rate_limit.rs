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
    /// Status announcements and peer lists.
    Status,
    /// Block/QC/proposal requests.
    BlockRequest,
    /// Transactions.
    Tx,
    /// Ping and pong keepalives.
    PingPong,
    /// Block sync responses.
    BlockResponse,
    /// QC sync responses.
    QCResponse,
}

impl MessageClass {
    /// Classify a protocol message.
    pub fn from_message(msg: &Message) -> Self {
        match msg {
            Message::Vote(_) => Self::Vote,
            Message::Block(_) => Self::BlockOrProposal,
            Message::Status { .. } | Message::PeerList(_) => Self::Status,
            Message::RequestBlocks { .. }
            | Message::RequestProposal { .. }
            | Message::RequestQC { .. } => Self::BlockRequest,
            Message::Tx(_) => Self::Tx,
            Message::Ping(_) | Message::Pong(_) => Self::PingPong,
            Message::BlockResponse { .. } => Self::BlockResponse,
            Message::QCResponse { .. } => Self::QCResponse,
        }
    }

    /// True when a per-peer byte bucket applies.
    pub fn needs_per_peer_byte_limit(msg: &Message) -> bool {
        matches!(
            msg,
            Message::Block(_) | Message::BlockResponse { .. } | Message::Tx(_)
        )
    }

    /// True when a global byte bucket applies.
    pub fn needs_global_byte_limit(msg: &Message) -> bool {
        matches!(msg, Message::Block(_) | Message::BlockResponse { .. })
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
}

impl PeerRateLimiter {
    /// Construct the default transport rate limiter.
    pub fn new() -> Self {
        let mut count_buckets = HashMap::new();
        count_buckets.insert(MessageClass::Vote, TokenBucket::new(20, 80));
        count_buckets.insert(MessageClass::BlockOrProposal, TokenBucket::new(5, 10));
        count_buckets.insert(MessageClass::Status, TokenBucket::new(2, 4));
        count_buckets.insert(MessageClass::BlockRequest, TokenBucket::new(5, 10));
        count_buckets.insert(MessageClass::Tx, TokenBucket::new(50, 200));
        count_buckets.insert(MessageClass::PingPong, TokenBucket::new(2, 4));
        count_buckets.insert(MessageClass::BlockResponse, TokenBucket::new(2, 4));
        count_buckets.insert(MessageClass::QCResponse, TokenBucket::new(5, 10));

        Self {
            count_buckets,
            per_peer_byte_bucket: TokenBucket::new_bytes(33_554_432, 67_108_864),
            strikes: StrikeCounter::new(),
        }
    }

    /// Check whether a message should be accepted.
    ///
    /// Returns `Some(penalty)` when rate limited, `None` when allowed.
    pub fn check(&mut self, msg: &Message, msg_size: usize) -> Option<i32> {
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

        if count_ok && byte_ok {
            None
        } else {
            Some(self.strikes.record())
        }
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
        primitives::{Bytes32, VariableBytes},
        vote::{VoteStep, VoteV1},
    };

    fn dummy_vote() -> Message {
        Message::Vote(VoteV1 {
            height: 1,
            round: 0,
            step: VoteStep::Prevote,
            block_hash: Bytes32::ZERO,
            validator_id: Bytes32::ZERO,
            signature: HybridSignature {
                classical_sig: VariableBytes::from_slice(&[0u8; 64]).unwrap(),
                pq_sig: VariableBytes::from_slice(&[0u8; 4627]).unwrap(),
            },
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
    fn test_attack_vote_rate_triggers_limit() {
        let mut limiter = PeerRateLimiter::new();
        let msg = dummy_vote();
        let mut limited = false;
        for _ in 0..100 {
            if limiter.check(&msg, 512).is_some() {
                limited = true;
                break;
            }
        }
        assert!(limited);
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
}
