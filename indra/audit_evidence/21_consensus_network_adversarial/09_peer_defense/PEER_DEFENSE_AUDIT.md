# Peer Scoring / Banning / Disconnect Audit

## Final disposition

**PASS WITH NON-CRITICAL FINDINGS**. No false-ban, stale-event penalty, ban
evasion, or unbounded persistent defensive-state issue was reproduced. No
production code was modified.

## Attribution and lifecycle

Peer-manager scoring is actor-serialized. Validator-scoped score changes use the
authenticated transport validator and resolve the currently mapped socket before
updating the peer table or disconnecting. Socket-scoped table penalties use the
address that supplied the event. A relay's invalid payload is attributed to the
transport peer unless cryptographic consensus processing independently proves an
originator; arbitrary claimed signer IDs do not redirect peer scoring.

The connection lifecycle exact-address check prevents stale disconnects from
removing a replacement. Existing stale-disconnect tests pass. A single invalid
object does not produce a parser plus duplicate plus consensus penalty in the
same path unless separate evidence/events are generated; relay verification is
not itself scored as authoritative consensus failure.

## Thresholds and saturation

Scores start at 100 and clamp to [0,200]. InvalidMessage is -10, Timeout -5,
DuplicateVote -20, and EquivocatingBlock -50; score <=0 enters a one-hour ban
(ten minutes for sustained rate-limit bans). Integer arithmetic is clamped, so
underflow/overflow is not possible. Recovery events are +1/+5 and cannot exceed
200. Existing boundary tests cover banning at zero, recovery, and active-ban
retention.

## BanStore

BanStore is validator-identity keyed, restart persistent, atomically written via
temporary file + rename, and strictly length/version/duplicate checked on load.
Expired bans are removed and persisted by `cleanup_expired_at`; reconnect from a
new socket/port is rejected before peer registration while the identity ban is
active. Historical IDs can occupy entries until expiry, but each ban has a
finite duration and no attacker-controlled address dimension was found.

Malformed or truncated stores fail closed (peer manager disables authenticated
networking rather than accepting corrupt state). Duplicate records are rejected.

## Findings and residual risks

No security finding met the HIGH/CRITICAL thresholds. A low hardening concern is
that scores_by_validator and BanStore are not separately capped beyond finite
ban expiry; protocol/governance authority bounds and one-hour expiry limit
practical growth. Another low concern is that peer-table metrics and validator
score state are maintained in separate structures, so operational snapshots can
briefly differ during event processing; no consensus or admission impact was
reproduced.

## Validation

`cargo test -p indra-network --lib` passed, including peer score, ban persistence,
active-ban reconnect, rate-limit ban, and stale-disconnect tests. `cargo test -p
indra-node --lib` passed. `cargo fmt --all -- --check` and `git diff --check`
passed. No remediation was attempted.
