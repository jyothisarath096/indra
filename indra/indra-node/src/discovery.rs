//! Peer discovery — DNS seeding, peer exchange, and peer table persistence.

use std::{
    collections::{BTreeMap, HashSet},
    io,
    net::{SocketAddr, ToSocketAddrs},
};

use indra_core::types::primitives::{DNS_SEED_HOSTS, MAX_PEER_LIST_SIZE};
use indra_network::PeerListEntry;

/// Encode the default DNS seed list into the existing config string field.
pub fn default_dns_seed_hosts_config() -> String {
    DNS_SEED_HOSTS.join(",")
}

fn parse_dns_seed_hosts(hosts: &str) -> Vec<String> {
    hosts
        .split(',')
        .map(str::trim)
        .filter(|host| !host.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn resolve_dns_seed_hosts_with<F>(hosts: &[String], port: u16, mut resolver: F) -> Vec<SocketAddr>
where
    F: FnMut(&str) -> io::Result<Vec<SocketAddr>>,
{
    let mut addrs = HashSet::new();
    for host in hosts {
        let addr_str = format!("{host}:{port}");
        match resolver(&addr_str) {
            Ok(resolved) => {
                if !resolved.is_empty() {
                    eprintln!(
                        "[discovery] DNS seed {} resolved to {} addresses",
                        host,
                        resolved.len()
                    );
                }
                addrs.extend(resolved);
            }
            Err(e) => {
                eprintln!(
                    "[discovery] DNS seed {} resolution failed: {} — using bootstrap peers only",
                    host, e
                );
            }
        }
    }

    let mut resolved: Vec<SocketAddr> = addrs.into_iter().collect();
    resolved.sort();
    resolved
}

/// Resolve DNS seed hostname to a list of socket addresses.
///
/// Returns an empty vec on failure. Discovery is best-effort and must not
/// prevent node startup.
///
/// `hosts` may contain one hostname or a comma-separated host list. DNS seeds
/// supplement configured bootstrap peers but never replace them; a node with
/// configured bootstrap peers can function if DNS resolution returns nothing.
///
/// TODO(mainnet): add DNSSEC or signed seed validation. A poisoned DNS response
/// can cause dial churn, but cannot eclipse consensus because the validator
/// transport rejects unknown validator identities.
pub fn resolve_dns_seeds(hosts: &str, port: u16) -> Vec<SocketAddr> {
    let hosts = parse_dns_seed_hosts(hosts);
    resolve_dns_seed_hosts_with(&hosts, port, |addr_str| {
        addr_str
            .to_socket_addrs()
            .map(|iter| iter.collect::<Vec<SocketAddr>>())
    })
}

/// Resolve the default DNS seed hostnames.
pub fn resolve_default_dns_seeds(port: u16) -> Vec<SocketAddr> {
    resolve_dns_seeds(&default_dns_seed_hosts_config(), port)
}

/// Resolve a single peer address string to a socket address.
pub fn resolve_peer_addr(addr_str: &str) -> Option<SocketAddr> {
    if let Ok(addr) = addr_str.parse::<SocketAddr>() {
        return Some(addr);
    }
    addr_str.to_socket_addrs().ok()?.next()
}

/// Persist known peers to disk as a JSON array of `"ip:port"` strings.
pub fn save_peers(path: &str, peers: &[SocketAddr]) {
    let mut strings: Vec<String> = peers.iter().map(|addr| addr.to_string()).collect();
    strings.sort();
    strings.dedup();
    let json = serde_json::to_string_pretty(&strings).unwrap_or_default();
    if let Err(e) = std::fs::write(path, &json) {
        eprintln!("[discovery] failed to save peers to {}: {}", path, e);
    }
}

/// Load known peers from disk.
pub fn load_peers(path: &str) -> Vec<SocketAddr> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(_) => return vec![],
    };
    let strings: Vec<String> = serde_json::from_str(&content).unwrap_or_default();
    strings
        .iter()
        .filter_map(|addr| addr.parse::<SocketAddr>().ok())
        .collect()
}

/// Sanitize persisted peers loaded from disk before they enter discovery.
///
/// Persisted `peers.json` predates connection-direction tracking, so a bare
/// `ip:port` cannot prove whether it was a legitimate listening address or an
/// accepted inbound socket source with an ephemeral port. Multiple ports for
/// the same IP are therefore treated as an anomaly and collapsed to a single
/// deterministic candidate, preferring the configured P2P listening port when
/// present.
pub fn sanitize_loaded_peers(
    peers: impl IntoIterator<Item = SocketAddr>,
    preferred_port: Option<u16>,
) -> Vec<SocketAddr> {
    let mut by_ip = BTreeMap::new();
    for peer in peers {
        by_ip.entry(peer.ip()).or_insert_with(Vec::new).push(peer);
    }

    let mut sanitized = Vec::new();
    for (_ip, mut candidates) in by_ip {
        candidates.sort_by_key(|addr| {
            (
                preferred_port
                    .map(|port| addr.port() != port)
                    .unwrap_or(false),
                addr.port(),
                addr.to_string(),
            )
        });
        if let Some(peer) = candidates.into_iter().next() {
            sanitized.push(peer);
        }
    }
    sanitized.sort();
    sanitized.dedup();
    sanitized
}

/// Build a deterministic PeerList payload from candidate addresses.
pub fn peer_list_payload(
    candidates: impl IntoIterator<Item = SocketAddr>,
    own_addr: Option<SocketAddr>,
    banned: &HashSet<SocketAddr>,
) -> Vec<PeerListEntry> {
    let mut seen = HashSet::new();
    let mut peers = Vec::new();
    for addr in candidates {
        if Some(addr) == own_addr || banned.contains(&addr) || !seen.insert(addr) {
            continue;
        }
        peers.push(PeerListEntry::address_only(addr.to_string()));
        if peers.len() >= MAX_PEER_LIST_SIZE {
            break;
        }
    }
    peers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_resolve_returns_empty_on_failure() {
        assert!(resolve_dns_seeds("invalid.invalid.indraprotocol.test", 30303).is_empty());
    }

    #[test]
    fn multiple_dns_seeds_are_queried() {
        let hosts = vec!["seed-a.example".to_string(), "seed-b.example".to_string()];
        let resolved = resolve_dns_seed_hosts_with(&hosts, 30303, |addr_str| match addr_str {
            "seed-a.example:30303" => Ok(vec!["203.0.113.10:30303".parse().unwrap()]),
            "seed-b.example:30303" => Ok(vec![
                "203.0.113.11:30303".parse().unwrap(),
                "203.0.113.10:30303".parse().unwrap(),
            ]),
            _ => Err(io::Error::new(io::ErrorKind::NotFound, "unexpected seed")),
        });

        assert_eq!(
            resolved,
            vec![
                "203.0.113.10:30303".parse().unwrap(),
                "203.0.113.11:30303".parse().unwrap()
            ]
        );
    }

    #[test]
    fn dns_failure_does_not_prevent_bootstrap_peer_connection() {
        let bootstrap_peers = vec!["198.51.100.10:30303".to_string()];
        let dns_peers =
            resolve_dns_seed_hosts_with(&["bad-seed.example".to_string()], 30303, |_| {
                Err(io::Error::new(io::ErrorKind::NotFound, "dns unavailable"))
            });
        let mut dial_candidates = bootstrap_peers.clone();
        dial_candidates.extend(dns_peers.into_iter().map(|addr| addr.to_string()));

        assert_eq!(dial_candidates, bootstrap_peers);
    }

    #[test]
    fn save_and_load_peers_round_trip() {
        let path = std::env::temp_dir().join(format!(
            "indra_peers_{}_round_trip.json",
            std::process::id()
        ));
        let peers = vec![
            "127.0.0.1:30303".parse().unwrap(),
            "127.0.0.2:30303".parse().unwrap(),
        ];
        save_peers(path.to_str().unwrap(), &peers);
        let loaded = load_peers(path.to_str().unwrap());
        assert_eq!(loaded, peers);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_peers_missing_file_returns_empty() {
        let path =
            std::env::temp_dir().join(format!("indra_missing_peers_{}.json", std::process::id()));
        assert!(load_peers(path.to_str().unwrap()).is_empty());
    }

    #[test]
    fn sanitize_loaded_peers_collapses_multiple_ports_per_ip() {
        let peers = vec![
            "203.0.113.10:52154".parse().unwrap(),
            "203.0.113.10:30303".parse().unwrap(),
            "203.0.113.10:49844".parse().unwrap(),
            "198.51.100.22:45240".parse().unwrap(),
            "198.51.100.22:30303".parse().unwrap(),
        ];

        let sanitized = sanitize_loaded_peers(peers, Some(30303));

        assert_eq!(
            sanitized,
            vec![
                "198.51.100.22:30303".parse().unwrap(),
                "203.0.113.10:30303".parse().unwrap(),
            ]
        );
    }

    #[test]
    fn sanitize_loaded_peers_leaves_single_port_per_ip_unchanged() {
        let peers = vec![
            "203.0.113.10:30303".parse().unwrap(),
            "198.51.100.22:30303".parse().unwrap(),
            "192.0.2.44:30303".parse().unwrap(),
        ];

        let mut expected = peers;
        expected.sort();
        let sanitized = sanitize_loaded_peers(expected.clone(), Some(30303));

        assert_eq!(sanitized, expected);
    }

    #[test]
    fn peer_list_deduplicates() {
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();
        let payload = peer_list_payload([addr, addr], None, &HashSet::new());
        assert_eq!(
            payload,
            vec![PeerListEntry::address_only("127.0.0.1:30303")]
        );
    }

    #[test]
    fn peer_list_respects_max_size() {
        let peers = (0..40).map(|i| SocketAddr::from(([127, 0, 0, 1], 30_000 + i)));
        let payload = peer_list_payload(peers, None, &HashSet::new());
        assert_eq!(payload.len(), MAX_PEER_LIST_SIZE);
    }

    #[test]
    fn peer_discovery_skips_banned_peers() {
        let banned_addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();
        let good_addr: SocketAddr = "127.0.0.2:30303".parse().unwrap();
        let banned = HashSet::from([banned_addr]);
        let payload = peer_list_payload([banned_addr, good_addr], None, &banned);
        assert_eq!(
            payload,
            vec![PeerListEntry::address_only("127.0.0.2:30303")]
        );
    }
}
