# Crash / Restart / Round-Exhaustion Recovery Audit

## Final disposition

**PASS WITH NON-CRITICAL FINDINGS**. No conflicting signature, durable height
regression, divergent commit, or stale volatile-state resurrection was
reproduced. No production code was modified.

## Startup and persistence

Startup restores the chain database, consensus safety records, authority/snapshot
context, and validator keys before authenticated networking and consensus event
processing. Volatile sockets, event queues, outstanding/provisional sync state,
replay caches, cooldowns, and timers are reconstructed/reset. BanStore is the
intentional restart-persistent exception and is validated strictly on load.

The driver records votes before returning/broadcasting them; restart tests show
the persisted safety record prevents conflicting votes. Durable chain/state
transaction boundaries and recovery tests preserve height, tip, and roots.

## Crash boundaries

Existing deterministic restart tests cover crash after vote persistence before
send, locked-state restoration, conflicting proposal rejection, durable commit
recovery, partial sync/projection rollback, stale QC handling, and restart with
invalid persisted QC. Volatile sync requests and provisional QC bindings do not
survive restart and therefore cannot authorize a stale socket response.

## Round 1023

`on_precommit_timeout` advances through legal rounds and returns
`RoundLimitExceeded` at the final legal round without mutation or wraparound.
The node event loop logs the error and continues processing; automatic promotion
to a later height is not established by this audit. If the network remains at
the same unfinalized height, operator/recovery intervention may be required.
When peers are at a later finalized height, normal status-driven sync can be
re-entered from durable state. This is a bounded operational liveness concern,
not a reproduced safety failure; reaching round 1023 requires prolonged failure
of the synchrony/proposer assumptions.

## Network and authority recovery

After restart, peers reauthenticate against current authority state; stale
credentials do not resurrect. Honest configured/bootstrap roots remain available
under the eclipse deployment assumption. Restart clears transient replay,
cooldown, connection, and sync-source state while preserving durable chain and
anti-double-sign state.

## Validation

Existing driver and sync tests cover final-round fail-closed behavior, restart
vote safety, lock restoration, durable commit boundaries, projection rollback,
and sync recovery. `cargo test -p indra-node --lib`, `cargo test -p
indra-consensus`, `cargo fmt --all -- --check`, and `git diff --check` passed in
the preceding audit runs. No production files were changed.

## Residual risk

The final-round terminal condition has no demonstrated automatic same-height
round reset. A later focused task should specify operator or sync recovery
semantics and add a multi-node round-1023-to-later-height harness.
