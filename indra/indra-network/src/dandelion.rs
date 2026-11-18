//! Dandelion++-style transaction stem state for the authenticated validator mesh.
//!
//! Transaction stem relay reduces other validators' confidence in the RPC-entry
//! validator. At four validators the protection remains weak: a one-validator
//! coalition identifies approximately half of honest entry validators under the
//! modeled first-spy attack. Allowing any authenticated connection as the small-N
//! relay removes the frequent zero-outbound fallback, but does not enlarge the
//! validator anonymity set or hide the submitting wallet from its RPC validator.
//! Material anonymity-set benefits still require a larger validator set.

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

use indra_core::{
    codec::Encode,
    ssz::sha256,
    types::{
        primitives::{Bytes32, MIN_ROUND_TIME_MS, TARGET_OUTBOUND_PEERS},
        transaction::TransactionV1,
    },
};
use rand::{rngs::OsRng, Rng, RngCore};

// Settled by audit_evidence/22_gossip_origin_privacy/SIMULATION_RESULTS_V2.md.
pub(crate) const STEM_FLUFF_PROBABILITY: f64 = 0.20;
pub(crate) const EMBARGO_BASE: Duration = Duration::from_millis(3 * MIN_ROUND_TIME_MS);
// Truncate only the extreme e^-10 tail so attacker-controlled state has a
// provable lifetime. The ordinary timer remains independently exponential.
pub(crate) const MAX_EMBARGO: Duration = Duration::from_millis(30 * MIN_ROUND_TIME_MS);
pub(crate) const STATE_TTL: Duration = Duration::from_secs(10 * 60);
pub(crate) const STATE_CAPACITY: usize = 16_384;
pub(crate) const RELAY_RETRY_WINDOW: Duration = Duration::from_secs(3);
pub(crate) const EPOCH_DURATION: Duration = Duration::from_secs(10 * 60);
pub(crate) const SWEEP_INTERVAL: Duration = Duration::from_millis(100);

const SMALL_MESH_MAX_VALIDATORS: usize = TARGET_OUTBOUND_PEERS + 1;

#[derive(Debug, Clone)]
pub(crate) struct RelayPeer {
    pub(crate) validator_id: Bytes32,
    pub(crate) is_outbound: bool,
}

#[derive(Debug, Clone)]
pub(crate) enum Action {
    Stem {
        tx_id: Bytes32,
        to: Bytes32,
        tx: TransactionV1,
    },
    Fluff {
        tx: TransactionV1,
        except: Option<Bytes32>,
        reason: FluffReason,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FluffReason {
    CoinFlip,
    Loop,
    Embargo,
    NoRelay,
    Capacity,
}

#[derive(Debug, Clone)]
enum Phase {
    Pending {
        tx: TransactionV1,
        embargo_at: Instant,
        retry_until: Instant,
        awaiting_relay: bool,
        exclude: Option<Bytes32>,
    },
    Fluffed,
}

#[derive(Debug, Clone)]
struct Entry {
    phase: Phase,
    expires_at: Instant,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Metrics {
    pub(crate) stemmed: u64,
    pub(crate) fluffed_coin: u64,
    pub(crate) fluffed_loop: u64,
    pub(crate) fluffed_embargo: u64,
    pub(crate) fluffed_no_relay: u64,
    pub(crate) fluffed_capacity: u64,
    pub(crate) observed_fluff: u64,
}

pub(crate) struct State {
    entries: HashMap<Bytes32, Entry>,
    order: VecDeque<Bytes32>,
    epoch_relay: Option<Bytes32>,
    epoch_ends_at: Instant,
    metrics: Metrics,
    rng: OsRng,
}

impl State {
    pub(crate) fn new(now: Instant) -> Self {
        debug_assert!(STATE_TTL > MAX_EMBARGO + RELAY_RETRY_WINDOW);
        Self {
            entries: HashMap::with_capacity(STATE_CAPACITY),
            order: VecDeque::with_capacity(STATE_CAPACITY),
            epoch_relay: None,
            epoch_ends_at: now,
            metrics: Metrics::default(),
            rng: OsRng,
        }
    }

    pub(crate) fn start_local(
        &mut self,
        tx: TransactionV1,
        now: Instant,
        peers: &[RelayPeer],
        active_validator_count: usize,
    ) -> Vec<Action> {
        self.start_pending(tx, None, false, now, peers, active_validator_count)
    }

    pub(crate) fn accept_stem(
        &mut self,
        from: Bytes32,
        tx: TransactionV1,
        now: Instant,
        peers: &[RelayPeer],
        active_validator_count: usize,
    ) -> Vec<Action> {
        let tx_id = transaction_id(&tx);
        if self.entries.contains_key(&tx_id) {
            self.mark_fluffed(tx_id, now);
            self.metrics.fluffed_loop = self.metrics.fluffed_loop.saturating_add(1);
            return vec![Action::Fluff {
                tx,
                except: Some(from),
                reason: FluffReason::Loop,
            }];
        }
        let fluff = self.rng.gen_bool(STEM_FLUFF_PROBABILITY);
        self.start_pending(tx, Some(from), fluff, now, peers, active_validator_count)
    }

    pub(crate) fn observe_fluff(&mut self, tx_id: Bytes32, now: Instant) -> Vec<Action> {
        if self
            .entries
            .get(&tx_id)
            .is_some_and(|entry| matches!(entry.phase, Phase::Pending { .. }))
        {
            self.metrics.observed_fluff = self.metrics.observed_fluff.saturating_add(1);
            self.mark_fluffed(tx_id, now);
            Vec::new()
        } else {
            let actions = self.make_room(now);
            self.insert(tx_id, Phase::Fluffed, now);
            actions
        }
    }

    pub(crate) fn stem_send_failed(&mut self, tx_id: Bytes32, now: Instant) {
        if let Some(Entry {
            phase:
                Phase::Pending {
                    awaiting_relay,
                    retry_until,
                    ..
                },
            ..
        }) = self.entries.get_mut(&tx_id)
        {
            *awaiting_relay = true;
            *retry_until = now + RELAY_RETRY_WINDOW;
        }
    }

    pub(crate) fn tick(
        &mut self,
        now: Instant,
        peers: &[RelayPeer],
        active_validator_count: usize,
    ) -> Vec<Action> {
        self.expire_fluffed(now);
        let pending = self
            .entries
            .iter()
            .filter_map(|(id, entry)| match &entry.phase {
                Phase::Pending {
                    tx,
                    embargo_at,
                    retry_until,
                    awaiting_relay,
                    exclude,
                } => Some((
                    *id,
                    tx.clone(),
                    *embargo_at,
                    *retry_until,
                    *awaiting_relay,
                    *exclude,
                )),
                Phase::Fluffed => None,
            })
            .collect::<Vec<_>>();
        let mut actions = Vec::new();
        for (tx_id, tx, embargo_at, retry_until, awaiting, exclude) in pending {
            if awaiting {
                if let Some(to) = self.choose_relay(now, peers, active_validator_count, exclude) {
                    if let Some(Entry {
                        phase: Phase::Pending { awaiting_relay, .. },
                        ..
                    }) = self.entries.get_mut(&tx_id)
                    {
                        *awaiting_relay = false;
                    }
                    self.metrics.stemmed = self.metrics.stemmed.saturating_add(1);
                    actions.push(Action::Stem { tx_id, to, tx });
                } else if now >= retry_until {
                    self.mark_fluffed(tx_id, now);
                    self.metrics.fluffed_no_relay = self.metrics.fluffed_no_relay.saturating_add(1);
                    actions.push(Action::Fluff {
                        tx,
                        except: None,
                        reason: FluffReason::NoRelay,
                    });
                }
            } else if now >= embargo_at {
                self.mark_fluffed(tx_id, now);
                self.metrics.fluffed_embargo = self.metrics.fluffed_embargo.saturating_add(1);
                actions.push(Action::Fluff {
                    tx,
                    except: None,
                    reason: FluffReason::Embargo,
                });
            }
        }
        actions
    }

    #[cfg(test)]
    pub(crate) fn metrics(&self) -> Metrics {
        self.metrics
    }

    fn start_pending(
        &mut self,
        tx: TransactionV1,
        exclude: Option<Bytes32>,
        fluff_now: bool,
        now: Instant,
        peers: &[RelayPeer],
        active_validator_count: usize,
    ) -> Vec<Action> {
        let tx_id = transaction_id(&tx);
        if self.entries.contains_key(&tx_id) {
            return Vec::new();
        }
        let mut actions = self.make_room(now);
        if fluff_now {
            self.insert(tx_id, Phase::Fluffed, now);
            self.metrics.fluffed_coin = self.metrics.fluffed_coin.saturating_add(1);
            actions.push(Action::Fluff {
                tx,
                except: exclude,
                reason: FluffReason::CoinFlip,
            });
            return actions;
        }
        let embargo_at = now + self.sample_embargo();
        let relay = self.choose_relay(now, peers, active_validator_count, exclude);
        self.insert(
            tx_id,
            Phase::Pending {
                tx: tx.clone(),
                embargo_at,
                retry_until: now + RELAY_RETRY_WINDOW,
                awaiting_relay: relay.is_none(),
                exclude,
            },
            now,
        );
        if let Some(to) = relay {
            self.metrics.stemmed = self.metrics.stemmed.saturating_add(1);
            actions.push(Action::Stem { tx_id, to, tx });
        }
        actions
    }

    fn sample_embargo(&mut self) -> Duration {
        let uniform = (self.rng.next_u64() as f64 + 1.0) / (u64::MAX as f64 + 1.0);
        Duration::from_secs_f64(
            (-uniform.ln() * EMBARGO_BASE.as_secs_f64()).min(MAX_EMBARGO.as_secs_f64()),
        )
    }

    fn choose_relay(
        &mut self,
        now: Instant,
        peers: &[RelayPeer],
        active_count: usize,
        exclude: Option<Bytes32>,
    ) -> Option<Bytes32> {
        let eligible = peers
            .iter()
            .filter(|peer| {
                (active_count <= SMALL_MESH_MAX_VALIDATORS || peer.is_outbound)
                    && Some(peer.validator_id) != exclude
            })
            .map(|peer| peer.validator_id)
            .collect::<Vec<_>>();
        if eligible.is_empty() {
            return None;
        }
        if now >= self.epoch_ends_at
            || self.epoch_relay.is_none()
            || !eligible.contains(&self.epoch_relay.unwrap_or(Bytes32::from([0; 32])))
        {
            self.epoch_relay = eligible.get(self.rng.gen_range(0..eligible.len())).copied();
            self.epoch_ends_at = now + EPOCH_DURATION;
        }
        self.epoch_relay
            .filter(|relay| Some(*relay) != exclude)
            .or_else(|| eligible.get(self.rng.gen_range(0..eligible.len())).copied())
    }

    fn insert(&mut self, tx_id: Bytes32, phase: Phase, now: Instant) {
        self.entries.insert(
            tx_id,
            Entry {
                phase,
                expires_at: now + STATE_TTL,
            },
        );
        self.order.push_back(tx_id);
    }

    fn mark_fluffed(&mut self, tx_id: Bytes32, now: Instant) {
        if let Some(entry) = self.entries.get_mut(&tx_id) {
            entry.phase = Phase::Fluffed;
            entry.expires_at = now + STATE_TTL;
        }
    }

    fn make_room(&mut self, now: Instant) -> Vec<Action> {
        self.expire_fluffed(now);
        let mut actions = Vec::new();
        while self.entries.len() >= STATE_CAPACITY {
            let Some(old) = self.order.pop_front() else {
                break;
            };
            if let Some(entry) = self.entries.remove(&old) {
                if let Phase::Pending { tx, .. } = entry.phase {
                    self.metrics.fluffed_capacity = self.metrics.fluffed_capacity.saturating_add(1);
                    actions.push(Action::Fluff {
                        tx,
                        except: None,
                        reason: FluffReason::Capacity,
                    });
                }
            }
        }
        actions
    }

    fn expire_fluffed(&mut self, now: Instant) {
        while let Some(id) = self.order.front().copied() {
            let expired = self.entries.get(&id).is_none_or(|entry| {
                matches!(entry.phase, Phase::Fluffed) && entry.expires_at <= now
            });
            if !expired {
                break;
            }
            self.order.pop_front();
            if self.entries.get(&id).is_some_and(|entry| {
                matches!(entry.phase, Phase::Fluffed) && entry.expires_at <= now
            }) {
                self.entries.remove(&id);
            }
        }
    }
}

pub(crate) fn transaction_id(tx: &TransactionV1) -> Bytes32 {
    Bytes32::from(sha256(&tx.encode_to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use indra_core::types::{
        crypto::{HybridPubKey, HybridSignature},
        primitives::{
            Bytes32, ProtocolVersion, VariableBytes, MAX_CLASSICAL_SIG_BYTES, MAX_PQ_SIG_BYTES,
            TRANSACTION_PROTOCOL_VERSION,
        },
        transaction::{InputV1, OutputV1},
    };

    fn tx(tag: u8) -> TransactionV1 {
        TransactionV1 {
            version: ProtocolVersion(TRANSACTION_PROTOCOL_VERSION),
            signature_module_id: 1,
            inputs: vec![InputV1 {
                utxo_id: Bytes32::from([tag; 32]),
            }],
            outputs: vec![OutputV1 {
                value_spark: 10,
                owner_pubkey: HybridPubKey {
                    classical_pk: Bytes32::from([tag.wrapping_add(1); 32]),
                    pq_pk: VariableBytes::from_slice(&[tag; 32]).unwrap(),
                },
                lock_height: 0,
            }],
            fee_amount: 1,
            signature: HybridSignature {
                classical_sig: VariableBytes::<MAX_CLASSICAL_SIG_BYTES>::from_slice(&[tag; 64])
                    .unwrap(),
                pq_sig: VariableBytes::<MAX_PQ_SIG_BYTES>::from_slice(&[tag; 64]).unwrap(),
            },
        }
    }

    fn peer(tag: u8, is_outbound: bool) -> RelayPeer {
        RelayPeer {
            validator_id: Bytes32::from([tag; 32]),
            is_outbound,
        }
    }

    #[test]
    fn local_origin_stems_when_relay_exists() {
        let now = Instant::now();
        let mut state = State::new(now);
        let actions = state.start_local(tx(1), now, &[peer(2, true)], 20);
        assert!(
            matches!(actions.as_slice(), [Action::Stem { to, .. }] if *to == Bytes32::from([2; 32]))
        );
    }

    #[test]
    fn start_pending_duplicate_is_a_noop() {
        let now = Instant::now();
        let mut state = State::new(now);
        let transaction = tx(2);
        let peers = [peer(3, true)];
        assert!(matches!(
            state
                .start_local(transaction.clone(), now, &peers, 20)
                .as_slice(),
            [Action::Stem { .. }]
        ));
        let entries_before = state.entries.len();
        let order_before = state.order.len();
        let metrics_before = state.metrics();

        let actions = state.start_pending(transaction, None, false, now, &peers, 20);

        assert!(actions.is_empty());
        assert_eq!(state.entries.len(), entries_before);
        assert_eq!(state.order.len(), order_before);
        assert_eq!(state.metrics(), metrics_before);
    }

    #[test]
    fn inbound_stem_never_reflects_to_sender_and_loop_fluffs() {
        let now = Instant::now();
        let mut state = State::new(now);
        let transaction = tx(3);
        let sender = Bytes32::from([4; 32]);
        let _ = state.start_local(transaction.clone(), now, &[peer(5, true)], 20);
        let actions = state.accept_stem(
            sender,
            transaction,
            now,
            &[peer(4, true), peer(5, true)],
            20,
        );
        assert!(
            matches!(actions.as_slice(), [Action::Fluff { except: Some(except), reason: FluffReason::Loop, .. }] if *except == sender)
        );
    }

    #[test]
    fn excluded_epoch_relay_uses_a_different_peer() {
        let now = Instant::now();
        let excluded = Bytes32::from([12; 32]);
        let alternate = Bytes32::from([13; 32]);
        let mut state = State::new(now);
        state.epoch_relay = Some(excluded);
        state.epoch_ends_at = now + EPOCH_DURATION;

        let selected =
            state.choose_relay(now, &[peer(12, true), peer(13, true)], 20, Some(excluded));

        assert_eq!(selected, Some(alternate));
        assert_ne!(selected, Some(excluded));
    }

    #[test]
    fn embargo_and_no_relay_fallback_make_progress() {
        let now = Instant::now();
        let mut embargoed = State::new(now);
        let _ = embargoed.start_local(tx(6), now, &[peer(7, true)], 20);
        let actions = embargoed.tick(now + MAX_EMBARGO, &[peer(7, true)], 20);
        assert!(actions.iter().any(|action| matches!(
            action,
            Action::Fluff {
                reason: FluffReason::Embargo,
                ..
            }
        )));

        let mut disconnected = State::new(now);
        assert!(disconnected.start_local(tx(8), now, &[], 4).is_empty());
        let actions = disconnected.tick(now + RELAY_RETRY_WINDOW, &[], 4);
        assert!(matches!(
            actions.as_slice(),
            [Action::Fluff {
                reason: FluffReason::NoRelay,
                ..
            }]
        ));
    }

    #[test]
    fn policy_b_switches_after_nine() {
        let now = Instant::now();
        let inbound = [peer(9, false)];
        let mut small = State::new(now);
        assert!(matches!(
            small.start_local(tx(10), now, &inbound, 9).as_slice(),
            [Action::Stem { .. }]
        ));
        assert_eq!(small.metrics().stemmed, 1);

        let mut large = State::new(now);
        assert!(large.start_local(tx(11), now, &inbound, 10).is_empty());
    }

    #[test]
    fn epoch_rotation_during_tick_relays_awaiting_transaction() {
        let now = Instant::now();
        let relay = Bytes32::from([14; 32]);
        let mut state = State::new(now);
        let transaction = tx(15);
        let tx_id = transaction_id(&transaction);
        assert!(state.start_local(transaction, now, &[], 20).is_empty());
        assert!(matches!(
            state.entries.get(&tx_id).map(|entry| &entry.phase),
            Some(Phase::Pending {
                awaiting_relay: true,
                ..
            })
        ));
        state.epoch_relay = Some(Bytes32::from([16; 32]));
        state.epoch_ends_at = now;

        let actions = state.tick(now, &[peer(14, true)], 20);

        assert!(matches!(
            actions.as_slice(),
            [Action::Stem { tx_id: action_id, to, .. }]
                if *action_id == tx_id && *to == relay
        ));
        assert!(matches!(
            state.entries.get(&tx_id).map(|entry| &entry.phase),
            Some(Phase::Pending {
                awaiting_relay: false,
                ..
            })
        ));
    }

    #[test]
    fn state_bound_and_ttl_outlive_maximum_embargo() {
        assert!(STATE_TTL > MAX_EMBARGO + RELAY_RETRY_WINDOW);
        let now = Instant::now();
        let mut state = State::new(now);
        for index in 0..=STATE_CAPACITY {
            let mut id = [0u8; 32];
            id[..8].copy_from_slice(&(index as u64).to_le_bytes());
            let _ = state.make_room(now);
            state.insert(Bytes32::from(id), Phase::Fluffed, now);
        }
        assert!(state.entries.len() <= STATE_CAPACITY);
    }
}
