use indra_network::BoundedCooldownTracker;
use std::{
    collections::HashMap,
    net::IpAddr,
    time::{Duration, Instant},
};

fn main() {
    const N: usize = 200;
    let now = Instant::now();
    let mut by_validator: HashMap<[u8; 32], BoundedCooldownTracker<IpAddr>> = HashMap::new();
    for id in 0..N as u8 {
        let mut tracker = BoundedCooldownTracker::new(
            16,
            Duration::from_secs(2),
            Duration::from_secs(60),
            Duration::from_secs(60),
        );
        tracker.record_failure_at("192.0.2.1".parse().unwrap(), now);
        by_validator.insert([id; 32], tracker);
    }
    let before = by_validator.len();
    let expired = now + Duration::from_secs(61);
    let retained = by_validator
        .values_mut()
        .map(|t| {
            let _ = t.blocked_at(&"192.0.2.1".parse().unwrap(), expired);
            t.len()
        })
        .sum::<usize>();
    let new_id = [0xEE; 32];
    let inserted = if by_validator.len() >= N {
        let expired_ids = by_validator
            .iter_mut()
            .filter_map(|(id, tracker)| {
                tracker.prune_expired(expired);
                tracker.is_empty().then_some(*id)
            })
            .collect::<Vec<_>>();
        for id in expired_ids {
            by_validator.remove(&id);
        }
        false
    } else {
        by_validator.insert(
            new_id,
            BoundedCooldownTracker::new(
                16,
                Duration::from_secs(2),
                Duration::from_secs(60),
                Duration::from_secs(60),
            ),
        );
        true
    };
    let inserted = if !by_validator.contains_key(&new_id) {
        by_validator.insert(
            new_id,
            BoundedCooldownTracker::new(
                16,
                Duration::from_secs(2),
                Duration::from_secs(60),
                Duration::from_secs(60),
            ),
        );
        true
    } else {
        inserted
    };
    println!("ROTATION: historical_namespaces={before} expired_live_entries={retained} new_validator_tracker_inserted={inserted} namespaces_after={}", by_validator.len());
    assert_eq!(before, N);
    assert_eq!(retained, 0);
    assert!(inserted);
    for id in 0..(N - 1) as u8 {
        let mut rotated = [0u8; 32];
        rotated[0] = 0x80;
        rotated[1] = id;
        by_validator.entry(rotated).or_insert_with(|| {
            BoundedCooldownTracker::new(
                16,
                Duration::from_secs(2),
                Duration::from_secs(60),
                Duration::from_secs(60),
            )
        });
    }
    assert_eq!(by_validator.len(), N);
}
