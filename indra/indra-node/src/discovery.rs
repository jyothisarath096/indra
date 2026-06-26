//! Peer discovery — DNS seeding, peer exchange, and peer table persistence.

use std::{
    collections::HashSet,
    net::{SocketAddr, ToSocketAddrs},
};

use indra_core::types::primitives::{DNS_SEED_HOST, MAX_PEER_LIST_SIZE};

/// Resolve DNS seed hostname to a list of socket addresses.
///
/// Returns an empty vec on failure. Discovery is best-effort and must not
/// prevent node startup.
pub fn resolve_dns_seeds(host: &str, port: u16) -> Vec<SocketAddr> {
    let addr_str = format!("{host}:{port}");
    match addr_str.to_socket_addrs() {
        Ok(addrs) => {
            let resolved: Vec<SocketAddr> = addrs.collect();
            if !resolved.is_empty() {
                eprintln!(
                    "[discovery] DNS seed {} resolved to {} addresses",
                    host,
                    resolved.len()
                );
            }
            resolved
        }
        Err(e) => {
            eprintln!(
                "[discovery] DNS seed {} resolution failed: {} — using bootstrap peers only",
                host, e
            );
            vec![]
        }
    }
}

/// Resolve the default DNS seed hostname.
pub fn resolve_default_dns_seeds(port: u16) -> Vec<SocketAddr> {
    resolve_dns_seeds(DNS_SEED_HOST, port)
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

/// Build a deterministic PeerList payload from candidate addresses.
pub fn peer_list_payload(
    candidates: impl IntoIterator<Item = SocketAddr>,
    own_addr: Option<SocketAddr>,
    banned: &HashSet<SocketAddr>,
) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut peers = Vec::new();
    for addr in candidates {
        if Some(addr) == own_addr || banned.contains(&addr) || !seen.insert(addr) {
            continue;
        }
        peers.push(addr.to_string());
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
    fn peer_list_deduplicates() {
        let addr: SocketAddr = "127.0.0.1:30303".parse().unwrap();
        let payload = peer_list_payload([addr, addr], None, &HashSet::new());
        assert_eq!(payload, vec!["127.0.0.1:30303"]);
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
        assert_eq!(payload, vec!["127.0.0.2:30303"]);
    }
}
