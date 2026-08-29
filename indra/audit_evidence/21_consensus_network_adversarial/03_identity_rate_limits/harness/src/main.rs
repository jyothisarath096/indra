use std::{net::IpAddr, time::Instant};

use indra_network::policy::BoundedCooldownTracker;

fn distinct_ipv6(index: u128) -> IpAddr {
    IpAddr::V6(index.into())
}

fn main() {
    const FIRST_WAVE: u128 = 100_000;
    const SECOND_WAVE: u128 = 100_000;

    let now = Instant::now();
    let mut tracker = BoundedCooldownTracker::new(
        4_096,
        std::time::Duration::from_secs(2),
        std::time::Duration::from_secs(60),
        std::time::Duration::from_secs(60),
    );

    let mut maximum_live = 0;
    let mut maximum_bookkeeping = 0;
    for index in 1..=FIRST_WAVE {
        tracker.record_failure_at(distinct_ipv6(index), now);
        maximum_live = maximum_live.max(tracker.len());
        maximum_bookkeeping = maximum_bookkeeping.max(tracker.bookkeeping_len());
    }
    assert_eq!(tracker.len(), 4_096);

    for index in (FIRST_WAVE + 1)..=(FIRST_WAVE + SECOND_WAVE) {
        tracker.record_failure_at(distinct_ipv6(index), now);
        maximum_live = maximum_live.max(tracker.len());
        maximum_bookkeeping = maximum_bookkeeping.max(tracker.bookkeeping_len());
    }
    assert_eq!(tracker.len(), 4_096);
    assert!(maximum_live <= 4_096);
    assert!(maximum_bookkeeping <= 8_192);

    println!(
        "REMEDIATED: unique_keys={} live={} maximum_live={} bookkeeping={} maximum_bookkeeping={} hard_cap=4096 bookkeeping_cap=8192",
        FIRST_WAVE + SECOND_WAVE,
        tracker.len(),
        maximum_live,
        tracker.bookkeeping_len(),
        maximum_bookkeeping,
    );
}
