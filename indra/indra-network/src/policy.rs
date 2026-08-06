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
