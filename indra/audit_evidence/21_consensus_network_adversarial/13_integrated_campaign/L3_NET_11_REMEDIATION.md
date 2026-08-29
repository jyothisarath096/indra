# L3-NET-11 Remediation

Implemented the smallest durable safety fix: `VoteSafetyStore::record` now
loads the existing record and rejects any requested signing slot that is not
strictly later in `(height, round, step)` ordering. This preserves
persist-before-sign semantics and conservatively consumes a slot after a crash.
No target/hash format migration was added.

The ordinary-height restart regression now proves a conflicting vote at
`(1,0,Prevote)` is not broadcast after reopen. A storage regression proves a
second same-slot record is rejected while a later precommit slot is accepted.

Production files changed:

- `indra-storage/src/vote_safety.rs`
- `indra-node/src/driver.rs` (test expectation only)

Focused tests passed:

`cargo test -p indra-storage --lib same_signing_slot_is_rejected_on_second_record`

`cargo test -p indra-node --lib audit_restart_conflicting_vote_reproducer_ordinary_height`

L3-NET-11 remains OPEN PENDING INDEPENDENT REVIEW. No broader harness campaign
was resumed.

Correction: the driver signing boundary now independently requires requested
height to equal `next_height()` and requested round to equal `current_round`
before durable persistence or signing. The focused evidence is recorded in
`L3_NET_11_REMEDIATION_FOCUSED.diff`.
