//! Shared bounded policy primitives for authenticated peer management.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    fs::{self, OpenOptions},
    hash::Hash,
    io::{self, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use indra_core::types::primitives::Bytes32;

const BAN_STORE_MAGIC: &[u8; 8] = b"INDBAN01";
const BAN_STORE_VERSION: u16 = 1;

/// Canonical address group used for eclipse-resistant peer diversity.
/// IPv4 addresses are grouped by /16 and IPv6 addresses by /32.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NetworkGroup {
    /// First 16 bits of an IPv4 address.
    V4([u8; 2]),
    /// First 32 bits of an IPv6 address.
    V6([u8; 4]),
}

impl NetworkGroup {
    /// Derive the canonical network group for an IP address.
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                Self::V4([octets[0], octets[1]])
            }
            IpAddr::V6(ip) => {
                let octets = ip.octets();
                Self::V6([octets[0], octets[1], octets[2], octets[3]])
            }
        }
    }
}

#[derive(Debug, Clone)]
struct TimedEntry<K> {
    key: K,
    expires_at: Instant,
}

/// Capacity- and TTL-bounded set with average O(1) membership checks.
pub struct BoundedTtlSet<K> {
    order: VecDeque<TimedEntry<K>>,
    keys: HashSet<K>,
    capacity: usize,
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct TimedMapEntry<K> {
    key: K,
    generation: u64,
    expires_at: Instant,
}

/// Capacity- and idle-TTL-bounded map for attacker-controlled identity state.
///
/// Access refreshes the idle deadline. Capacity eviction is deterministic:
/// the least-recently-touched live entry is removed first.
#[derive(Debug)]
pub struct BoundedTtlMap<K, V> {
    order: VecDeque<TimedMapEntry<K>>,
    values: HashMap<K, (V, u64, Instant)>,
    capacity: usize,
    ttl: Duration,
    next_generation: u64,
    evictions: u64,
}

impl<K: Clone + Eq + Hash, V> BoundedTtlMap<K, V> {
    /// Create an empty bounded map.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            order: VecDeque::with_capacity(capacity),
            values: HashMap::with_capacity(capacity),
            capacity,
            ttl,
            next_generation: 0,
            evictions: 0,
        }
    }

    /// Get an entry, inserting it when absent, and refresh its idle TTL.
    pub fn get_or_insert_with_at(
        &mut self,
        key: K,
        now: Instant,
        make: impl FnOnce() -> V,
    ) -> Option<&mut V> {
        self.expire_at(now);
        if self.capacity == 0 {
            return None;
        }
        if !self.values.contains_key(&key) {
            while self.values.len() >= self.capacity {
                if !self.evict_oldest_live() {
                    return None;
                }
                self.evictions = self.evictions.saturating_add(1);
            }
            self.next_generation = self.next_generation.wrapping_add(1);
            let generation = self.next_generation;
            let expires_at = now + self.ttl;
            self.values
                .insert(key.clone(), (make(), generation, expires_at));
            self.order.push_back(TimedMapEntry {
                key: key.clone(),
                generation,
                expires_at,
            });
        } else {
            self.next_generation = self.next_generation.wrapping_add(1);
            let generation = self.next_generation;
            let expires_at = now + self.ttl;
            if let Some((_, stored_generation, stored_expiry)) = self.values.get_mut(&key) {
                *stored_generation = generation;
                *stored_expiry = expires_at;
            }
            self.order.push_back(TimedMapEntry {
                key: key.clone(),
                generation,
                expires_at,
            });
        }
        self.compact_order_if_needed();
        self.values.get_mut(&key).map(|(value, _, _)| value)
    }

    /// Remove expired entries.
    pub fn expire_at(&mut self, now: Instant) {
        while self
            .order
            .front()
            .is_some_and(|entry| entry.expires_at <= now)
        {
            let entry = self.order.pop_front().expect("front exists");
            if self
                .values
                .get(&entry.key)
                .is_some_and(|(_, generation, expiry)| {
                    *generation == entry.generation && *expiry <= now
                })
            {
                self.values.remove(&entry.key);
                self.evictions = self.evictions.saturating_add(1);
            }
        }
    }

    fn compact_order_if_needed(&mut self) {
        if self.order.len() <= self.capacity.saturating_mul(2).max(1) {
            return;
        }
        let mut live = self
            .values
            .iter()
            .map(|(key, (_, generation, expires_at))| TimedMapEntry {
                key: key.clone(),
                generation: *generation,
                expires_at: *expires_at,
            })
            .collect::<Vec<_>>();
        live.sort_by_key(|entry| entry.generation);
        self.order = live.into();
    }

    fn evict_oldest_live(&mut self) -> bool {
        while let Some(entry) = self.order.pop_front() {
            if self
                .values
                .get(&entry.key)
                .is_some_and(|(_, generation, _)| *generation == entry.generation)
            {
                self.values.remove(&entry.key);
                return true;
            }
        }
        false
    }

    /// Number of live entries.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Return true when there are no live entries.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Number of capacity or idle-TTL evictions since construction.
    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    #[cfg(test)]
    fn bookkeeping_len(&self) -> usize {
        self.order.len()
    }
}

impl<K: Clone + Eq + Hash> BoundedTtlSet<K> {
    /// Create an empty set.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            order: VecDeque::with_capacity(capacity),
            keys: HashSet::with_capacity(capacity),
            capacity,
            ttl,
        }
    }

    /// Return whether a live entry exists, removing expired entries first.
    pub fn contains_at(&mut self, key: &K, now: Instant) -> bool {
        self.expire_at(now);
        self.keys.contains(key)
    }

    /// Insert a key at a caller-supplied time. Returns true only for a new key.
    pub fn insert_at(&mut self, key: K, now: Instant) -> bool {
        self.expire_at(now);
        if self.keys.contains(&key) || self.capacity == 0 {
            return false;
        }
        while self.order.len() >= self.capacity {
            if let Some(old) = self.order.pop_front() {
                self.keys.remove(&old.key);
            }
        }
        self.keys.insert(key.clone());
        self.order.push_back(TimedEntry {
            key,
            expires_at: now + self.ttl,
        });
        true
    }

    /// Remove expired entries at a caller-supplied time.
    pub fn expire_at(&mut self, now: Instant) {
        while self
            .order
            .front()
            .is_some_and(|entry| entry.expires_at <= now)
        {
            if let Some(expired) = self.order.pop_front() {
                self.keys.remove(&expired.key);
            }
        }
    }

    /// Number of live cached keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when no live keys are retained.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

#[derive(Debug, Clone, Copy)]
struct CooldownEntry {
    retry_at: Instant,
    next_delay: Duration,
}

/// Typed exponential cooldown tracker shared by inbound and outbound policy.
pub struct CooldownTracker<K> {
    entries: HashMap<K, CooldownEntry>,
    minimum: Duration,
    maximum: Duration,
}

#[derive(Debug, Clone)]
struct BoundedCooldownValue {
    cooldown: CooldownEntry,
    generation: u64,
    retention_deadline: Instant,
}

#[derive(Debug, Clone)]
struct BoundedCooldownOrderEntry<K> {
    key: K,
    generation: u64,
    retention_deadline: Instant,
}

/// Capacity- and idle-retention-bounded cooldown state for attacker-controlled
/// identities.
///
/// Lookups do not refresh failure recency. Only a recorded failure advances the
/// exponential cooldown and the retention deadline. Capacity eviction is
/// deterministic: expired history is reclaimed first, then the
/// least-recently-failed live identity is removed.
pub struct BoundedCooldownTracker<K> {
    values: HashMap<K, BoundedCooldownValue>,
    order: VecDeque<BoundedCooldownOrderEntry<K>>,
    capacity: usize,
    minimum: Duration,
    maximum: Duration,
    retention_ttl: Duration,
    next_generation: u64,
    evictions: u64,
}

impl<K: Clone + Eq + Hash> BoundedCooldownTracker<K> {
    /// Construct a bounded tracker with an explicit idle-retention policy.
    pub fn new(
        capacity: usize,
        minimum: Duration,
        maximum: Duration,
        retention_ttl: Duration,
    ) -> Self {
        Self {
            values: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
            minimum,
            maximum,
            retention_ttl,
            next_generation: 0,
            evictions: 0,
        }
    }

    /// Record a failure and return the cooldown applied to this attempt.
    pub fn record_failure_at(&mut self, key: K, now: Instant) -> Duration {
        self.prune_expired(now);
        let current = self
            .values
            .get(&key)
            .map(|value| value.cooldown.next_delay)
            .unwrap_or(self.minimum);

        if !self.values.contains_key(&key) {
            while self.values.len() >= self.capacity {
                if !self.evict_oldest_live() {
                    break;
                }
                self.evictions = self.evictions.saturating_add(1);
            }
            if self.capacity == 0 {
                return current;
            }
        }

        let generation = self.allocate_generation();
        let retention_deadline = now + self.retention_ttl;
        self.values.insert(
            key.clone(),
            BoundedCooldownValue {
                cooldown: CooldownEntry {
                    retry_at: now + current,
                    next_delay: (current * 2).min(self.maximum),
                },
                generation,
                retention_deadline,
            },
        );
        self.order.push_back(BoundedCooldownOrderEntry {
            key,
            generation,
            retention_deadline,
        });
        self.compact_order_if_needed();
        current
    }

    /// Return whether `key` is still inside its active retry cooldown.
    ///
    /// This operation may reclaim idle-expired metadata but never refreshes
    /// recency, generation, or retention.
    pub fn blocked_at(&mut self, key: &K, now: Instant) -> bool {
        self.prune_expired(now);
        self.values
            .get(key)
            .is_some_and(|value| now < value.cooldown.retry_at)
    }

    /// Reset exactly one identity after successful authentication.
    pub fn reset(&mut self, key: &K) {
        self.values.remove(key);
        self.compact_order_if_needed();
    }

    /// Reclaim failure metadata whose idle-retention deadline has elapsed.
    pub fn prune_expired(&mut self, now: Instant) {
        while self
            .order
            .front()
            .is_some_and(|entry| entry.retention_deadline <= now)
        {
            let entry = self.order.pop_front().expect("front exists");
            if self.values.get(&entry.key).is_some_and(|value| {
                value.generation == entry.generation && value.retention_deadline <= now
            }) {
                self.values.remove(&entry.key);
            }
        }
        self.compact_order_if_needed();
    }

    fn allocate_generation(&mut self) -> u64 {
        if self.next_generation == u64::MAX {
            self.reindex_generations();
        }
        self.next_generation += 1;
        self.next_generation
    }

    fn reindex_generations(&mut self) {
        let mut live = Vec::with_capacity(self.values.len());
        for entry in &self.order {
            if self
                .values
                .get(&entry.key)
                .is_some_and(|value| value.generation == entry.generation)
            {
                live.push((entry.key.clone(), entry.retention_deadline));
            }
        }
        self.order.clear();
        for (index, (key, retention_deadline)) in live.into_iter().enumerate() {
            let generation = (index as u64) + 1;
            if let Some(value) = self.values.get_mut(&key) {
                value.generation = generation;
            }
            self.order.push_back(BoundedCooldownOrderEntry {
                key,
                generation,
                retention_deadline,
            });
        }
        self.next_generation = self.values.len() as u64;
    }

    fn evict_oldest_live(&mut self) -> bool {
        while let Some(entry) = self.order.pop_front() {
            if self
                .values
                .get(&entry.key)
                .is_some_and(|value| value.generation == entry.generation)
            {
                self.values.remove(&entry.key);
                return true;
            }
        }
        false
    }

    fn compact_order_if_needed(&mut self) {
        if self.order.len() <= self.capacity.saturating_mul(2) {
            return;
        }
        let mut live = self
            .values
            .iter()
            .map(|(key, value)| BoundedCooldownOrderEntry {
                key: key.clone(),
                generation: value.generation,
                retention_deadline: value.retention_deadline,
            })
            .collect::<Vec<_>>();
        live.sort_by_key(|entry| entry.generation);
        self.order = live.into();
    }

    /// Number of live cooldown identities.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether no retained cooldown metadata remains.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Configured live-identity hard cap.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of deterministic capacity evictions.
    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    /// Number of bounded ordering records retained.
    pub fn bookkeeping_len(&self) -> usize {
        self.order.len()
    }
}

impl<K: Eq + Hash> CooldownTracker<K> {
    /// Create a tracker with inclusive minimum and maximum delays.
    pub fn new(minimum: Duration, maximum: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            minimum,
            maximum,
        }
    }

    /// Record a failure and return the delay applied to this attempt.
    pub fn record_failure_at(&mut self, key: K, now: Instant) -> Duration {
        let current = self
            .entries
            .get(&key)
            .map(|entry| entry.next_delay)
            .unwrap_or(self.minimum);
        let next = (current * 2).min(self.maximum);
        self.entries.insert(
            key,
            CooldownEntry {
                retry_at: now + current,
                next_delay: next,
            },
        );
        current
    }

    /// True while a key remains inside its cooldown window.
    pub fn blocked_at(&self, key: &K, now: Instant) -> bool {
        self.entries
            .get(key)
            .is_some_and(|entry| now < entry.retry_at)
    }

    /// Reset a key after a sustained successful connection.
    pub fn reset(&mut self, key: &K) {
        self.entries.remove(key);
    }
}

/// Restart-persistent, validator-identity-keyed ban records.
pub struct BanStore {
    path: PathBuf,
    expires_by_validator: HashMap<Bytes32, u64>,
}

impl BanStore {
    /// Load a store, treating a missing file as an empty store.
    pub fn load(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let expires_by_validator = match fs::read(&path) {
            Ok(bytes) => decode_bans(&bytes)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => HashMap::new(),
            Err(error) => return Err(error),
        };
        Ok(Self {
            path,
            expires_by_validator,
        })
    }

    /// Create an empty in-memory store backed by the supplied path.
    pub fn empty(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            expires_by_validator: HashMap::new(),
        }
    }

    /// Current Unix time in seconds.
    pub fn unix_now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// True when an identity has an unexpired ban.
    pub fn is_banned_at(&self, validator_id: &Bytes32, unix_now: u64) -> bool {
        self.expires_by_validator
            .get(validator_id)
            .is_some_and(|expiry| *expiry > unix_now)
    }

    /// Persist a ban ending at the supplied Unix timestamp.
    pub fn ban_until(&mut self, validator_id: Bytes32, expiry: u64) -> io::Result<()> {
        self.expires_by_validator.insert(validator_id, expiry);
        self.save()
    }

    /// Remove only expired bans and persist when anything changed.
    pub fn cleanup_expired_at(&mut self, unix_now: u64) -> io::Result<usize> {
        let before = self.expires_by_validator.len();
        self.expires_by_validator
            .retain(|_, expiry| *expiry > unix_now);
        let removed = before - self.expires_by_validator.len();
        if removed > 0 {
            self.save()?;
        }
        Ok(removed)
    }

    fn save(&self) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = self.path.with_extension("tmp");
        let bytes = encode_bans(&self.expires_by_validator);
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, &self.path)?;
        if let Some(parent) = self.path.parent() {
            sync_directory(parent)?;
        }
        Ok(())
    }
}

fn encode_bans(bans: &HashMap<Bytes32, u64>) -> Vec<u8> {
    let mut entries: Vec<_> = bans.iter().collect();
    entries.sort_by_key(|(validator_id, _)| validator_id.0);
    let mut bytes = Vec::with_capacity(14 + entries.len() * 40);
    bytes.extend_from_slice(BAN_STORE_MAGIC);
    bytes.extend_from_slice(&BAN_STORE_VERSION.to_le_bytes());
    bytes.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (validator_id, expiry) in entries {
        bytes.extend_from_slice(&validator_id.0);
        bytes.extend_from_slice(&expiry.to_le_bytes());
    }
    bytes
}

fn decode_bans(bytes: &[u8]) -> io::Result<HashMap<Bytes32, u64>> {
    if bytes.len() < 14 || &bytes[..8] != BAN_STORE_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ban store header",
        ));
    }
    let version = u16::from_le_bytes([bytes[8], bytes[9]]);
    if version != BAN_STORE_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported ban store version",
        ));
    }
    let count = u32::from_le_bytes(
        bytes[10..14]
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ban store count"))?,
    ) as usize;
    if bytes.len() != 14usize.saturating_add(count.saturating_mul(40)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid ban store length",
        ));
    }
    let mut bans = HashMap::with_capacity(count);
    for chunk in bytes[14..].chunks_exact(40) {
        let mut id = [0u8; 32];
        id.copy_from_slice(&chunk[..32]);
        let expiry = u64::from_le_bytes(
            chunk[32..40]
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ban expiry"))?,
        );
        if bans.insert(Bytes32::from(id), expiry).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "duplicate ban identity",
            ));
        }
    }
    Ok(bans)
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> io::Result<()> {
    OpenOptions::new().read(true).open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn network_groups_use_ipv4_16_and_ipv6_32() {
        assert_eq!(
            NetworkGroup::from_ip(Ipv4Addr::new(203, 0, 113, 9).into()),
            NetworkGroup::V4([203, 0])
        );
        assert_eq!(
            NetworkGroup::from_ip("2001:db8:abcd::1".parse::<Ipv6Addr>().unwrap().into()),
            NetworkGroup::V6([0x20, 0x01, 0x0d, 0xb8])
        );
    }

    #[test]
    fn ttl_set_is_bounded_and_expires() {
        let start = Instant::now();
        let mut set = BoundedTtlSet::new(2, Duration::from_secs(10));
        assert!(set.insert_at(1u8, start));
        assert!(set.insert_at(2u8, start));
        assert!(set.insert_at(3u8, start));
        assert!(!set.contains_at(&1, start));
        assert!(set.contains_at(&3, start));
        assert!(!set.contains_at(&3, start + Duration::from_secs(10)));
    }

    #[test]
    fn ttl_map_refreshes_idle_ttl_and_evicts_oldest_deterministically() {
        let start = Instant::now();
        let mut map = BoundedTtlMap::new(2, Duration::from_secs(10));
        *map.get_or_insert_with_at(1u8, start, || 10).unwrap() += 1;
        map.get_or_insert_with_at(2u8, start + Duration::from_secs(1), || 20);
        assert_eq!(map.len(), 2);

        // Touch key 1, making key 2 the deterministic least-recently-used entry.
        assert_eq!(
            *map.get_or_insert_with_at(1u8, start + Duration::from_secs(2), || 0)
                .unwrap(),
            11
        );
        map.get_or_insert_with_at(3u8, start + Duration::from_secs(3), || 30);
        assert_eq!(map.evictions(), 1);
        assert_eq!(
            *map.get_or_insert_with_at(1u8, start + Duration::from_secs(3), || 0)
                .unwrap(),
            11
        );
        // Key 2 was evicted, so it is reconstructed with the supplied value.
        assert_eq!(
            *map.get_or_insert_with_at(2u8, start + Duration::from_secs(3), || 99)
                .unwrap(),
            99
        );
        assert_eq!(map.evictions(), 2);

        map.expire_at(start + Duration::from_secs(14));
        assert!(map.is_empty());
    }

    #[test]
    fn ttl_map_refresh_bookkeeping_remains_capacity_bounded() {
        let start = Instant::now();
        let mut map = BoundedTtlMap::new(2, Duration::from_secs(60));
        for tick in 0..10_000 {
            map.get_or_insert_with_at(1u8, start + Duration::from_millis(tick), || 1);
        }
        assert_eq!(map.len(), 1);
        assert!(map.bookkeeping_len() <= 4);
    }

    #[test]
    fn cooldown_doubles_and_resets() {
        let start = Instant::now();
        let mut tracker = CooldownTracker::new(Duration::from_secs(2), Duration::from_secs(60));
        assert_eq!(
            tracker.record_failure_at("peer", start),
            Duration::from_secs(2)
        );
        assert!(tracker.blocked_at(&"peer", start + Duration::from_secs(1)));
        assert_eq!(
            tracker.record_failure_at("peer", start + Duration::from_secs(2)),
            Duration::from_secs(4)
        );
        tracker.reset(&"peer");
        assert!(!tracker.blocked_at(&"peer", start));
    }

    fn bounded_cooldown(capacity: usize) -> BoundedCooldownTracker<u32> {
        BoundedCooldownTracker::new(
            capacity,
            Duration::from_secs(2),
            Duration::from_secs(60),
            Duration::from_secs(60),
        )
    }

    #[test]
    fn bounded_cooldown_enforces_capacity_and_oldest_failure_eviction() {
        let start = Instant::now();
        let mut tracker = bounded_cooldown(4_096);
        for key in 0..4_096 {
            tracker.record_failure_at(key, start);
        }
        assert_eq!(tracker.len(), 4_096);
        assert_eq!(tracker.capacity(), 4_096);

        tracker.record_failure_at(4_096, start + Duration::from_millis(1));
        assert_eq!(tracker.len(), 4_096);
        assert_eq!(tracker.evictions(), 1);
        assert!(!tracker.blocked_at(&0, start + Duration::from_millis(1)));
        assert!(tracker.blocked_at(&4_096, start + Duration::from_millis(1)));
    }

    #[test]
    fn bounded_cooldown_stays_bounded_under_original_attack_scale() {
        let start = Instant::now();
        let mut tracker = bounded_cooldown(4_096);
        let mut maximum_live = 0;
        let mut maximum_bookkeeping = 0;
        for key in 0..200_000 {
            tracker.record_failure_at(key, start);
            maximum_live = maximum_live.max(tracker.len());
            maximum_bookkeeping = maximum_bookkeeping.max(tracker.bookkeeping_len());
        }
        assert_eq!(maximum_live, 4_096);
        assert!(maximum_bookkeeping <= 8_192);
        assert_eq!(tracker.len(), 4_096);
        assert!(tracker.bookkeeping_len() <= 8_192);
    }

    #[test]
    fn bounded_cooldown_escalates_and_separates_retry_from_retention() {
        let start = Instant::now();
        let mut tracker = bounded_cooldown(8);
        let expected = [2, 4, 8, 16, 32, 60, 60];
        for (index, seconds) in expected.into_iter().enumerate() {
            assert_eq!(
                tracker.record_failure_at(1, start + Duration::from_millis(index as u64)),
                Duration::from_secs(seconds)
            );
        }

        let mut retry_tracker = bounded_cooldown(8);
        assert_eq!(
            retry_tracker.record_failure_at(2, start),
            Duration::from_secs(2)
        );
        assert!(!retry_tracker.blocked_at(&2, start + Duration::from_secs(2)));
        assert_eq!(retry_tracker.len(), 1, "failure history remains retained");
        assert_eq!(
            retry_tracker.record_failure_at(2, start + Duration::from_secs(59)),
            Duration::from_secs(4),
            "retained history continues exponential backoff"
        );
    }

    #[test]
    fn bounded_cooldown_reclaims_idle_metadata_at_retention_deadline() {
        let start = Instant::now();
        let mut tracker = bounded_cooldown(8);
        tracker.record_failure_at(1, start);
        assert_eq!(tracker.len(), 1);
        tracker.prune_expired(start + Duration::from_secs(59));
        assert_eq!(tracker.len(), 1);
        tracker.prune_expired(start + Duration::from_secs(60));
        assert_eq!(tracker.len(), 0);
        assert_eq!(
            tracker.record_failure_at(1, start + Duration::from_secs(60)),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn bounded_cooldown_reset_is_exact_and_stale_records_are_safe() {
        let start = Instant::now();
        let mut tracker = bounded_cooldown(3);
        tracker.record_failure_at(1, start);
        tracker.record_failure_at(2, start + Duration::from_secs(1));
        tracker.record_failure_at(1, start + Duration::from_secs(10));
        tracker.reset(&2);
        assert_eq!(tracker.len(), 1);
        assert!(tracker.blocked_at(&1, start + Duration::from_secs(10)));
        assert!(!tracker.blocked_at(&2, start + Duration::from_secs(10)));

        tracker.prune_expired(start + Duration::from_secs(60));
        assert_eq!(tracker.len(), 1, "stale generation must not remove refresh");
        tracker.prune_expired(start + Duration::from_secs(70));
        assert_eq!(tracker.len(), 0);
    }

    #[test]
    fn bounded_cooldown_refresh_changes_deterministic_eviction_order() {
        let start = Instant::now();
        let mut tracker = bounded_cooldown(2);
        tracker.record_failure_at(1, start);
        tracker.record_failure_at(2, start + Duration::from_millis(1));
        tracker.record_failure_at(1, start + Duration::from_millis(2));
        tracker.record_failure_at(3, start + Duration::from_millis(3));
        assert!(tracker.blocked_at(&1, start + Duration::from_millis(3)));
        assert!(!tracker.blocked_at(&2, start + Duration::from_millis(3)));
        assert!(tracker.blocked_at(&3, start + Duration::from_millis(3)));
        assert_eq!(tracker.evictions(), 1);
    }

    #[test]
    fn bounded_cooldown_generation_wrap_reindexes_safely() {
        let start = Instant::now();
        let mut tracker = bounded_cooldown(3);
        tracker.record_failure_at(1, start);
        tracker.record_failure_at(2, start + Duration::from_millis(1));
        tracker.next_generation = u64::MAX;
        tracker.record_failure_at(1, start + Duration::from_millis(2));
        tracker.record_failure_at(3, start + Duration::from_millis(3));
        tracker.record_failure_at(4, start + Duration::from_millis(4));
        assert!(tracker.blocked_at(&1, start + Duration::from_millis(4)));
        assert!(!tracker.blocked_at(&2, start + Duration::from_millis(4)));
        assert!(tracker.blocked_at(&3, start + Duration::from_millis(4)));
        assert!(tracker.blocked_at(&4, start + Duration::from_millis(4)));
        assert_eq!(tracker.len(), 3);
        assert!(tracker.bookkeeping_len() <= 6);
    }

    #[test]
    fn bounded_cooldown_concurrent_mutex_updates_never_exceed_bounds() {
        use std::sync::{Arc, Mutex};

        for round in 0..100u32 {
            let tracker = Arc::new(Mutex::new(bounded_cooldown(4_096)));
            let mut threads = Vec::new();
            for worker in 0..8u32 {
                let tracker = Arc::clone(&tracker);
                threads.push(std::thread::spawn(move || {
                    let now = Instant::now();
                    for offset in 0..128u32 {
                        let key = round * 10_000 + worker * 128 + offset;
                        let mut guard = tracker.lock().unwrap();
                        guard.record_failure_at(key, now);
                        assert!(guard.len() <= 4_096);
                        assert!(guard.bookkeeping_len() <= 8_192);
                    }
                }));
            }
            for thread in threads {
                thread.join().unwrap();
            }
            let guard = tracker.lock().unwrap();
            assert!(guard.len() <= 4_096);
            assert!(guard.bookkeeping_len() <= 8_192);
        }
    }

    #[test]
    fn persistent_ban_survives_reload_and_new_socket_port() {
        let path = std::env::temp_dir().join(format!(
            "indra-ban-store-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        let validator = Bytes32::from([7u8; 32]);
        let mut store = BanStore::empty(&path);
        store.ban_until(validator, 2_000).unwrap();
        let reloaded = BanStore::load(&path).unwrap();
        assert!(reloaded.is_banned_at(&validator, 1_000));
        let _ = fs::remove_file(path);
    }

    #[test]
    fn cleanup_removes_only_expired_identity_bans() {
        let path = std::env::temp_dir().join(format!(
            "indra-ban-cleanup-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        let active = Bytes32::from([1u8; 32]);
        let expired = Bytes32::from([2u8; 32]);
        let mut store = BanStore::empty(&path);
        store.expires_by_validator.insert(active, 200);
        store.expires_by_validator.insert(expired, 100);
        assert_eq!(store.cleanup_expired_at(150).unwrap(), 1);
        assert!(store.is_banned_at(&active, 150));
        assert!(!store.is_banned_at(&expired, 150));
        let _ = fs::remove_file(path);
    }

    fn rand_suffix() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    }
}
