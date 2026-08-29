use std::{collections::HashMap, net::IpAddr, time::Instant};

use indra_network::policy::BoundedCooldownTracker;

fn main() {
    const UNIQUE_AUTHENTICATED_ADDRESSES: u128 = 200_000;
    let validator_id = [0x42; 32];
    let prefix = u128::from_be_bytes([
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ]);
    let now = Instant::now();
    let mut trackers = HashMap::<[u8; 32], BoundedCooldownTracker<IpAddr>>::new();
    let tracker = trackers.entry(validator_id).or_insert_with(|| {
        BoundedCooldownTracker::new(
            16,
            std::time::Duration::from_secs(2),
            std::time::Duration::from_secs(60),
            std::time::Duration::from_secs(60),
        )
    });

    for suffix in 1..=UNIQUE_AUTHENTICATED_ADDRESSES {
        tracker.record_failure_at(IpAddr::V6((prefix | suffix).into()), now);
    }
    assert_eq!(tracker.len(), 16);
    assert!(tracker.bookkeeping_len() <= 32);

    let retained = (1..=UNIQUE_AUTHENTICATED_ADDRESSES)
        .filter(|suffix| {
            tracker.blocked_at(&IpAddr::V6((prefix | *suffix).into()), now)
        })
        .count();
    assert_eq!(retained, 16);

    let current = IpAddr::V6((prefix | UNIQUE_AUTHENTICATED_ADDRESSES).into());
    tracker.reset(&current);
    let retained_after_exact_reset = (1..UNIQUE_AUTHENTICATED_ADDRESSES)
        .filter(|suffix| {
            tracker.blocked_at(&IpAddr::V6((prefix | *suffix).into()), now)
        })
        .count();
    assert_eq!(retained_after_exact_reset, 15);

    println!(
        "REMEDIATED: validator_id=42..42 unique_authenticated_source_ips={} retained_before_reset={} retained_after_exact_current_key_reset={} per_validator_cap=16 bookkeeping_cap=32",
        UNIQUE_AUTHENTICATED_ADDRESSES,
        retained,
        retained_after_exact_reset,
    );
}
