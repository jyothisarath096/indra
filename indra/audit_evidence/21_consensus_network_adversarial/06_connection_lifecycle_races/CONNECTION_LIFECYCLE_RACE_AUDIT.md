# Connection Lifecycle Races & Stale Events Audit

## Final disposition

**PASS**. No HIGH, MEDIUM, or LOW production-reachable lifecycle race was
reproduced in the deterministic production tests and source-trace permutations.
No production code was changed.

## Lifecycle model

`PeerManagerActor` is the authoritative owner of `peers_by_validator` and
`validator_by_addr`. Registration is serialized through its control channel.
When a validator already has a peer, `tie_break_keep_new` deterministically
chooses one connection. Replacing a peer calls `drop_peer` with the old socket;
that function checks the currently stored socket before removal and emits a
disconnect only for the current peer. A stale `(validator, addr)` disconnect is
therefore ignored when the replacement is active.

The node bridge maintains address/validator sets under mutexes. Its event order
is the peer-manager event-channel order: replacement emits old disconnect before
new connected, and read tasks are aborted when replaced. No stale event was
observed to remove the replacement or clear its validator-scoped limiter.

## Required answers

- Two connections for one validator may exist transiently at the transport
  layer, but only one remains logically active.
- Winner is deterministic according to `tie_break_keep_new` and initiator role.
- Stale disconnect cannot remove the replacement because of exact socket check.
- Queued stale messages carry the old socket and validator; the old task is
  aborted on replacement; no lifecycle mutation was reproduced.
- Penalties are socket-addressed through peer-table APIs; replacement is not
  disconnected by a stale address event.
- Validator rate limits are keyed by validator and survive replacement.
- Reconnect does not mint a new validator limiter bucket.
- L3-NET-10 provisional/QC checks retain exact validator + socket + height
  binding across replacement.
- Address and validator maps remain consistent in tested permutations.
- Authority refresh does not resurrect stale authorization; current admission
  uses current authenticated identity and authority state.
- There is no explicit generation counter; exact socket identity plus serialized
  actor ownership supplies the required protection for current paths.

## Deterministic cases and residual assumptions

Existing tests `test_stale_disconnect_preserves_replacement` and sync response
binding tests cover the primary stale-disconnect and source-replacement paths.
The actor channel serializes producer events, so barrier permutations reduce to
the listed event orders rather than timing races. A future transport that can
reuse a socket identity without peer-manager address correlation should add a
generation token; current Tokio stream tasks use captured address and are
aborted on replacement.

Validation: `cargo test -p indra-network --lib` and `cargo test -p indra-node
--lib` passed; `cargo fmt --all -- --check` and `git diff --check` passed.
