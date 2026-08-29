# Stale Credentials & Authority-Transition Audit

## Final disposition

**PASS** for this subphase. No HIGH/CRITICAL stale-credential defect was reproduced. No production code was modified.

## Authority-transition call graph

`ConsensusDriver` commits a height transition in `indra-node/src/bin/node.rs`; when the observed height increases, the message loop calls `refresh_handshake_and_relay_config` (around line 3224). That calls `build_handshake_config`, which uses `engine.state.height + 1` and `engine.network_authority_for_height` (around lines 1082–1099). The returned snapshot authority populates `HandshakeConfig.known_validators` and `relay_validator_keys`. Success atomically replaces the shared config and calls `NetworkBridge::update_relay_validator_keys`, which sends `NetworkCommand::UpdateRelayValidatorKeys` to the peer-manager actor. Lookup failure clears both remote-authority vectors and updates relay keys to empty (fail-closed).

New handshakes perform `lookup_validator_pk` against the current `known_validators`, then verify the authenticated transcript. Existing sockets are not automatically disconnected on authority refresh. Their inbound relay path is nevertheless checked against current `relay_keys`; consensus delivery performs snapshot/validator authorization in `ConsensusDriver` (`verify_vote_authority` and proposal authorization).

## Matrix results

| Case | Result |
|---|---|
| Removed validator, new connection | Rejected by current handshake config (`UnknownValidator`). |
| Removed validator, existing connection | Socket remains transport-authenticated; current relay key removal prevents consensus relay; driver performs current snapshot authorization before mutation. |
| K1 → K2, new K1 | Rejected after config refresh. |
| K1 → K2, new K2 | Accepted when K2 is in current authority. |
| Existing K1 across rotation | Not forcibly disconnected; transport A remains, but relay verification uses refreshed keys and consensus authorization remains snapshot-scoped. |
| Old K1 + new K2 overlap | Peer manager keeps one deterministic connection per validator; stale disconnect is ignored for the replacement. Existing tests `tie_break_with_same_validator_resolves_deterministically` and `test_stale_disconnect_preserves_replacement` passed. |
| Remove → re-add K1 | Current authority controls admission; no stale map inheritance observed. |
| Remove → re-add K2 | Current authority controls admission; no stale map inheritance observed. |
| Refresh failure, new connection | Cleared `known_validators` causes fail-closed authentication. |
| Refresh failure, existing connection | Existing transport remains until disconnect, but relay validator keys are empty and consensus checks remain authoritative. |

## Explicit answers

- Removed validator establishing a new connection: **No**, once refreshed config is active.
- Old credential after rotation: **No** for a new connection; existing transport is not proactively disconnected.
- Existing stale connections disconnected: **No automatic disconnect observed**.
- Existing removed validator relaying consensus: **No successful relay authorization with removed current keys; driver still receives transport messages and rejects unauthorized consensus objects before mutation**.
- Current authority enforcement: handshake lookup, peer-manager relay signature lookup, and consensus snapshot authorization.
- Refresh failure: **fail closed** for new authentication and relay authorization.
- Stale K1 interfering with K2: deterministic validator tie-break prevents stale disconnect from removing the replacement.
- Stale authorization lifetime: existing transport authentication lasts until socket closure; consensus/relay authorization is bounded by the refreshed current authority.

## Validation

Passed deterministic handshake tests: unknown validator, invalid signature, successful handshake, timeout, chain/genesis mismatch. Passed peer-manager tests covering duplicate-connection tie-break, stale disconnect preservation, relay verification, and current relay-key updates. Existing node snapshot-authority tests passed, including `snapshot_network_authority_drives_handshake_relay_and_discovery` and `removed_snapshot_member_remains_authorized_but_has_no_discovery_address`.

The latter test confirms an important protocol distinction: a validator removed from the live registry can remain authorized for a historical/future consensus snapshot selected by `network_authority_for_height`; this is snapshot semantics, not stale handshake authorization.

No L3-NET-10 finding was created. Relay-origin attribution, request-family limits, outbound/sync cardinality, and generic connection-race auditing remain outside this subphase.
