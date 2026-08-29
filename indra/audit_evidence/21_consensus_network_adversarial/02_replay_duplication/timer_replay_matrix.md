# Timer replay matrix

The production loop owns one `phase_started_at` value. It changes only when the
observed `(height, round, phase)` changes, when consensus is paused/resumed for
peer or sync state, or after the phase timeout handler actually fires. An
inbound event returning no driver state transition does not recreate or reset a
timer.

| Schedule | Replayed object | Driver result | Timer result |
|---|---|---|---|
| Propose phase, just before deadline | already-staged proposal | full revalidation, then `None` | original propose deadline remains |
| Propose phase, repeated status | same/future status 100 times | sync claim replacement; no round transition | original deadline remains |
| Prevote phase, just before deadline | already-seen prevote | cross-path replay may reverify, then no actions | original prevote deadline remains |
| Precommit phase, just before deadline | already-seen precommit | cross-path replay may reverify, then no actions | original precommit deadline remains |
| Any phase | stale/finalized proposal or vote | rejected before crypto | unchanged |
| Any phase | round >= 1024 | rejected at decode/driver guard | unchanged |
| Timeout delivered twice | same timeout method | first call changes phase/round; stale second call is phase-guarded | no concurrent timer and no second transition |
| Reconnect | same canonical object | network connection-local vote cache resets, actor/driver state remains | unchanged unless normal peer-count pause/resume policy applies |

Deterministic evidence includes
`peer_status_repeated_messages_cannot_force_round_advance` and the phase guards
in `on_propose_timeout`, `on_prevote_timeout`, and `on_precommit_timeout`.
No replay schedule was found that suppresses a deadline indefinitely.
