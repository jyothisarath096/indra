# CRITICAL STOP — restart double-sign candidate

## Reproducer

Production test setup: `indra-node/src/driver.rs` private `local_driver` with
seed `[0xA8; 32]` and suffix `audit_fixture_reopen_conflict`.

1. Construct `(driver, dir) = local_driver(seed, suffix)`.
2. Call `driver.sign_and_record_local_vote(u64::MAX, 0, VoteStep::Prevote,
   Bytes32::ZERO)`. Production logs `produced Prevote ... hash=00000000` and
   persists the safety record.
3. Clone only `driver.engine.config`, drop the driver and all handles.
4. Reconstruct `NodeEngine::init(config)`, reopen `VoteSafetyStore::open` at
   the same path, and construct `ConsensusDriver::new(engine, vote_safety)`.
5. Call the production private signing path with the same H/R/S but target
   `Bytes32::from([0x01; 32])`.

## Actual result

The reopened production driver produced and broadcast a second `Prevote` for
the conflicting target (`hash=01010101`). The assertion that no
`DriverAction::BroadcastVote` was returned failed.

## Expected result

The authoritative VoteSafetyStore record should prevent a conflicting vote at
the same height, round, and step after restart.

## Impact and reachability

Production-reachable through the existing restart reconstruction path. This is
a consensus safety candidate: crash/restart may permit honest double-signing.
No remediation was attempted. Further work is stopped pending independent
review.

## Ordinary-height confirmation

The same behavior reproduces at ordinary legal height 1 in
`audit_restart_conflicting_vote_reproducer_ordinary_height` in
`indra-node/src/driver.rs`. The first vote is persisted at `(1,0,Prevote,
ZERO)`, the driver is reconstructed from the same `NodeEngine` configuration
and safety file, and a second vote at `(1,0,Prevote,[1;32])` returns
`DriverAction::BroadcastVote`.

`VoteSafetyRecord` stores only height, round, step, and optional lock; it does
not store the voted block hash. `VoteSafetyStore::record` enforces structural
round/lock bounds and atomic persistence, not same-slot target identity. On
restart `apply_vote_safety` advances the in-memory round to 1, but
`sign_and_record_local_vote` accepts the caller-supplied round 0 and overwrites
the record before signing. This is the exact production root cause. No fix was
attempted.
