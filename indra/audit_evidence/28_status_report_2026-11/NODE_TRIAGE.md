# `indra-node` production panic triage

Scope: read-only investigation from `/Users/bonkai/Desktop/indra/project_indra/indra`. No repository source, manifest, lock file, or commit was changed. The only temporary source edit was in `/tmp/indra_node_triage/indra/indra-node/src/lib.rs`, solely to let the binary clippy run proceed; that worktree was removed after the run.

## 1. Exact library diagnostic list

Run by Codex:

```text
cargo clippy -p indra-node --lib --no-deps 2>&1 | tee audit_evidence/28_status_report_2026-11/logs/node_triage_clippy_lib.log
```

The command exited non-zero. Exact denied diagnostics, in source order:

```text
indra-node/src/driver.rs:716:9  used `expect()` on a `Result` value
indra-node/src/driver.rs:731:9  used `expect()` on a `Result` value
indra-node/src/driver.rs:945:21 used `expect()` on a `Result` value
indra-node/src/driver.rs:1232:31 used `expect()` on an `Option` value
indra-node/src/driver.rs:1748:9  used `expect()` on a `Result` value
indra-node/src/driver.rs:2050:13 used `expect()` on a `Result` value
indra-node/src/driver.rs:2148:17 used `expect()` on a `Result` value
indra-node/src/engine.rs:723:32 used `expect()` on an `Option` value
indra-node/src/engine.rs:986:24 used `expect()` on a `Result` value
indra-node/src/hardened_read_rpc.rs:206:34 used `unwrap()` on a `Result` value
indra-node/src/metrics.rs:391:27 used `expect()` on a `Result` value
indra-node/src/metrics.rs:393:17 used `expect()` on an `Option` value
error: could not compile `indra-node` (lib) due to 12 previous errors; 14 warnings emitted
```

The diagnostic text and final line above are copied from `audit_evidence/28_status_report_2026-11/logs/node_triage_clippy_lib.log`.

## 2. Site-by-site traces

Verdicts use exactly the requested vocabulary: A means the local invariant is established by code; B means a constructible panic remains; UNRESOLVED means the repository does not establish the required invariant from the inspected path.

### `driver.rs`

#### `reset_round` and catch-up reset (`driver.rs:713-733`)

```rust
713 /// External round-reset hook used after height advancement.
714 pub fn reset_round(&mut self) {
715     self.valid_proposal = None;
716     self.start_round(0).expect("round zero is always legal");
717     self.apply_vote_safety();
718 }
719
720 /// Re-enter consensus cleanly after block download catchup.
721 pub fn on_sync_caught_up(&mut self) {
722     self.sync.mark_caught_up(self.engine.state.height);
723     self.refresh_registered_voters();
724     self.pending_blocks.clear();
725     self.buffered_votes.clear();
726     self.requested_proposals.clear();
727     self.pending_precommit_quorum.clear();
728     self.vote_collectors.clear();
729     self.round_advance_evidence.clear();
730     self.seen_round_votes.clear();
731     self.start_round(0).expect("round zero is always legal");
732     self.apply_vote_safety();
733 }
```

`start_round` is `driver.rs:760-768`: it calls `validate_consensus_round(round)`, then sets `current_round` and `current_phase`. Round zero is accepted by the round validator, so this is verdict **A**, subject to the stated invariant that the validator continues to accept zero. The exact production fix would be to make the hook return `NodeResult<()>` and propagate the `validate_consensus_round` error, or to handle it explicitly at the caller; replacing the assertion with an ignored result would hide the error. A regression test should invoke both hooks after constructing a driver and assert `Ok(())`/round zero, plus a focused test of the error path if `start_round` is made fallible.

The consensus thread is spawned at `indra-node/src/bin/node.rs:3336-3339` with `std::thread::spawn` and the returned `JoinHandle` is not stored. A panic unwinds that thread; the process does not exit because no supervisor observes the handle. The validator process therefore remains alive but its consensus task is silent and its configured slot remains present.

#### persisted vote-safety round (`driver.rs:932-946`)

```rust
932 let message = format!(
933     "persisted vote at final legal round {} leaves no safe round at height {}",
934     record.round, record.height
935 );
936 eprintln!("[vote_safety] CRITICAL: {message}");
937 self.vote_safety_unavailable = Some(message);
938 return;
939 }
940 eprintln!(
941     "[vote_safety] restarted: skipping to round {} (already voted at height={} round={} step={})",
942     safe_round, record.height, record.round, record.step
943 );
944 self.start_round(safe_round)
945     .expect("safe persisted round was validated above");
946 }
```

The preceding code computes `safe_round` only after the final-legal-round case is rejected; the value is also checked by the round validator before the call. On the inspected path this is verdict **A**: `safe_round` is intended to be a legal round by construction. The exact fix is the same typed propagation/explicit error handling as above, with a test loading a valid persisted safety record and a corrupt/out-of-range record. The same consensus-thread supervision finding applies (`node.rs:3336-3339`).

#### `polc_round` option (`driver.rs:1218-1244`)

```rust
1218 let Some(block) = self.pending_block_for_slot(height, self.current_round) else {
1219     return vec![];
1220 };
1221 let hash = block.header.block_hash();
1222 let value_hash = block.header.value_hash;
1223 let vote_hash = if block.header.polc_round.is_none() {
1224     // Rule 2
1225     if self.locked_round.is_none() || self.locked_value == Some(hash) {
1226         hash
1227     } else {
1228         Bytes32::ZERO
1229     }
1230 } else {
1231     // Rule 3
1232     let valid_round = block.header.polc_round.expect("checked Some above");
1233     if valid_round < self.current_round
1234         && self.has_quorum_for_value_hash(
1235             height,
1236             valid_round,
1237             VoteStep::Prevote,
1238             value_hash,
1239         )
1240         && (self.locked_round.is_none()
1241             || self.locked_value_hash == Some(value_hash)
1242             || self
1243                 .locked_round
1244                 .is_some_and(|locked_round| locked_round <= valid_round))
```

The `else` is entered immediately after `is_none()` returned false, so `polc_round` is `Some`; this is verdict **A**. The exact non-panicking rewrite is `if let Some(valid_round) = block.header.polc_round { ... } else { ... }`, with a test covering both `None` and `Some` proposals. This runs in the consensus thread described above.

#### quorum-certified round advance (`driver.rs:1735-1752`)

```rust
1735     .iter()
1736     .try_fold(0u64, |total, voter| total.checked_add(voter.stake))
1737 else {
1738     return Vec::new();
1739 };
1740 if !has_strict_two_thirds_quorum(signed_stake, total_stake) {
1741     return Vec::new();
1742 }
1743
1744 eprintln!(
1745     "[consensus] quorum-certified round advance: {} → {} at height={} (stake={}/{})",
1746     self.current_round, target_round, height, signed_stake, total_stake
1747 );
1748 self.start_round(target_round)
1749     .expect("certified target round was validated before mutation");
1750 self.apply_vote_safety();
1751 self.prune_stalled_collections();
1752 self.maybe_prevote_current_round_proposal()
```

The local code establishes quorum and checked stake addition, but the excerpt does not itself prove that `target_round` was passed through `validate_consensus_round` on every caller path. This is **UNRESOLVED** until all assignments/callers of `target_round` are audited. The exact fix is to make `start_round` return `NodeResult<()>` and propagate/convert the error at this function, with a test sending the largest legal round and an out-of-range round-advance event. It runs in the unsupervised consensus thread (`node.rs:3336-3339`), so a panic silently stops consensus.

#### QC snapshot lookup (`driver.rs:2039-2061`)

```rust
2039 let quorum_vote_values = self.precommit_votes_for_block(collector, block_hash);
2040 let quorum_votes: Vec<&VoteV1> = quorum_vote_values.iter().collect();
2041 #[cfg(test)]
2042 {
2043     self.vote_admission_metrics.qc_formations += 1;
2044 }
2045 let qc = match build_qc(
2046     height,
2047     round,
2048     block_hash,
2049     &self.engine.state.chain_id,
2050     self.engine
2051         .state
2052         .snapshot_for_consensus_height(height)
2053         .expect("governing snapshot already resolved")
2054         .snapshot_root,
2055     &qc_validators,
2056     quorum_votes,
2057 ) {
2058     Ok(qc) => qc,
2059     Err(ConsensusError::CryptoError { detail }) => {
2060         eprintln!(
2061             "[commit] failed to build QC for {} at height={} round={}: CryptoError: {}",
```

`height` and the vote set come from consensus state, while `snapshot_for_consensus_height` reads the state snapshot map. The excerpt does not prove that a snapshot always exists for every QC formation height; the call is fallible and its error is not inspected. Verdict **UNRESOLVED**. The exact fix is to bind the lookup with `let snapshot = ...?` and map the state error to the node's commit/action error, or return a typed “governing snapshot unavailable” action without constructing a QC. A test should remove/withhold the requested snapshot and assert the node returns an error/action rather than panics. The panic occurs on the unsupervised consensus thread.

#### post-commit reset (`driver.rs:2138-2160`)

```rust
2138 self.locked_value_hash = None;
2139 self.locked_polc_votes.clear();
2140 self.valid_round = None;
2141 self.valid_value = None;
2142 self.valid_proposal = None;
2143 if let Err(error) = self.vote_safety.clear() {
2144     eprintln!(
2145         "[vote_safety] WARNING: failed to clear committed-height safety record: {error}"
2146     );
2147 }
2148 self.start_round(0).expect("round zero is always legal");
2149
2150 self.vote_collectors
2151     .retain(|(vote_height, _, _), _| *vote_height > height);
2152 self.round_advance_evidence
2153     .retain(|(vote_height, _), _| *vote_height > height);
2154 self.pending_blocks
2155     .retain(|_, pending| pending.block.header.height > height);
2156 self.buffered_votes
2157     .retain(|(vote_height, _, _), _| *vote_height > height);
2158 self.seen_round_votes
2159     .retain(|(_, vote_height, _, _)| *vote_height > height);
2160 self.pending_precommit_quorum
```

This is **A** for the same local round-zero invariant as `reset_round`; the exact fix is typed propagation rather than `expect`. The unsupervised consensus-thread consequence is the same.

### `engine.rs`

#### exit dependency position (`engine.rs:718-746`)

```rust
718 let exit_position = footprint.iter().find_map(|key| match key {
719     DependencyKey::PendingTrancheSlot(id) => Some(*id),
720     _ => None,
721 });
722 if let Some(position_id) = exit_position {
723     let validator_id = self
724         .state
725         .stake_positions
726         .get(&position_id)
727         .expect("verified exit footprint has a canonical position")
728         .validator_id;
729     let reserved_position = self
730         .staking_dependency_index
731         .affected([DependencyKey::PendingTrancheSlot(position_id)])
732         .len();
733     let reserved_validator = self
734         .staking_dependency_index
735         .affected([DependencyKey::PendingValidatorTrancheSlot(validator_id)])
736         .len();
737     let reserved_global = self
738         .staking_dependency_index
739         .affected([DependencyKey::PendingGlobalTrancheSlot])
740         .len();
741     let used_position = self.state.tranche_ids_for_position(&position_id).len();
742     let used_validator = self
743         .state
744         .unbonding_tranches
745         .values()
746         .filter(|tranche| {
```

The value originates in `staking_footprint`/the pending dependency index, not directly from a peer or RPC byte in this function. The inspected excerpt does not establish that every `PendingTrancheSlot` in the index necessarily has a live `stake_positions` entry after all exit/eviction mutations. Verdict **UNRESOLVED**. The exact fix is `get(...).ok_or(NodeError::InvalidStakingOp(...))?` (or the project’s existing typed invariant error), plus a test that deletes the position while retaining the dependency key and asserts a rejected candidate rather than panic. This is called from block-candidate/mempool handling; the enclosing request/task supervision was not proven to exit the process, so the exact process-level outcome is **UNRESOLVED** rather than assumed.

#### reporter PQ key conversion (`engine.rs:974-996`)

```rust
974 /// ordering remains the mempool's age/fee/tx-id policy.
975 fn select_block_contents(&mut self) -> SelectedBlockContents {
976     self.ensure_pending_indexes();
977     let height = self.state.height.saturating_add(1);
978     let current_epoch = epoch_for_height(height);
979     let mut scratch = self.state.clone();
980     let transaction_dust_limit =
981         indra_core::types::primitives::transaction_dust_limit_spark(self.state.utxos.len());
982     let reporter_pubkey = self.hybrid_keypair.as_ref().map(|keypair| {
983         let public = keypair.public_key();
984         HybridPubKey {
985             classical_pk: Bytes32::from(public.classical.0),
986             pq_pk: VariableBytes::from_slice(&public.pq.0)
987                 .expect("ML-DSA-87 public key fits protocol bound"),
988         }
989     });
990
991     let transaction_candidates: Vec<_> = self
992         .mempool
993         .select_for_block(usize::MAX, self.state.height)
994         .into_iter()
995         .map(|entry| (entry.tx_id, entry.tx.clone()))
996         .collect();
```

`public.pq.0` comes from the fixed-size PQ public key in the locally configured hybrid keypair. The protocol-bound conversion is therefore verdict **A** if the fixed ML-DSA-87 length remains below `VariableBytes`'s bound; the exact invariant is enforced by the key type and the conversion itself. The exact fix is to use a fallible `map`/`transpose` and return the existing block-selection error if that bound changes. A test should construct the configured keypair and assert the conversion succeeds, plus a boundary test for the variable-byte bound. This is a producer path; its caller/task supervision was not established in the inspected excerpt.

### `hardened_read_rpc.rs`

#### per-IP mutex (`hardened_read_rpc.rs:194-218`)

```rust
194         });
195         eprintln!("[observer-rpc] listening on {addr} (hardened read-only)");
196         for stream in listener.incoming() {
197             let Ok(stream) = stream else { continue };
198             let Some(ip) = stream.peer_addr().ok().map(|peer| peer.ip()) else {
199                 continue;
200             };
201             if total.fetch_add(1, Ordering::AcqRel) >= CONNECTION_CAP {
202                 total.fetch_sub(1, Ordering::AcqRel);
203                 continue;
204             }
205             {
206                 let mut counts = per_ip_connections.lock().unwrap();
207                 if !reserve_ip_connection(&mut counts, ip, PER_IP_CONNECTION_CAP) {
208                     total.fetch_sub(1, Ordering::AcqRel);
209                     continue;
210                 }
211             }
212             metrics
213                 .rpc_active_connections
214                 .fetch_add(1, Ordering::Relaxed);
215             let publisher = publisher.clone();
216             let storage = storage.clone();
217             let total = Arc::clone(&total);
218             let per_ip_connections = Arc::clone(&per_ip_connections);
```

The mutex is created inside the observer RPC thread at `hardened_read_rpc.rs:182-184`; the only holder in this excerpt performs bounded map bookkeeping. A poisoned mutex is possible only if another holder panics while holding it; no such holder is established from the inspected source. Verdict **UNRESOLVED**: the `unwrap` is constructible if the mutex is poisoned, but the repository does not establish that poisoning cannot occur. The exact fix is `lock().map_err(|_| ObserverError::LockPoisoned)?` with the listener logging/releasing the connection, plus a test that poisons the mutex and asserts a controlled rejection. The listener itself is spawned without a stored handle at `hardened_read_rpc.rs:174`; its panic kills only the observer RPC thread and does not exit the node.

### `metrics.rs`

#### next reward computation (`metrics.rs:380-404`)

```rust
380 let validator_id_hex = engine
381     .validator_id()
382     .map(|id| hex::encode(&id.0[..4]))
383     .unwrap_or_else(|| "none".to_string());
384 Self {
385     height: s.height,
386     epoch: s.current_epoch(),
387     era: era_for_height(s.height),
388     base_fee: s.base_fee,
389     total_supply: s.total_supply,
390     total_staked,
391     block_reward: indra_state::monetary::block_reward_for_budget(
392         s.monetary_ledger.reward_budget_spark,
393         s.height
394             .checked_add(1)
395             .expect("validated chain height must admit a successor"),
396     )
397     .expect("validated monetary schedule must produce the next reward"),
398     round,
399     connected_validator_peers,
400     observer_connections: observer_count.load(Ordering::Relaxed),
401     mempool_size: engine.mempool.len(),
402     staking_mempool_size: engine.staking_mempool.len(),
403     pending_slashes: engine.pending_slashes.len(),
404     sync_caught_up,
```

The height comes from `ChainState`; the budget and schedule come from the monetary ledger. The excerpt does not prove that a persisted or externally reconstructed state can never have `u64::MAX`, nor that `block_reward_for_budget` always has a next reward for every valid ledger state. Verdict **UNRESOLVED**. The exact fix is to use `checked_add(1).ok_or(MetricsError::HeightOverflow)?` and map the monetary `None`/error to `MetricsError::RewardUnavailable`; tests should cover max height and exhausted/invalid reward budget. Metrics listeners are unsupervised threads (`metrics.rs:234-272` and `metrics.rs:285-315`), so a panic kills only the metrics listener/connection thread, not the node process.

## 3. Clock, channel, and mutex edge cases

The 12 denied sites above do not directly call `SystemTime`, `Instant`, `duration_since`, `send`, or `recv`; no backward-clock behavior is therefore attributable to one of these exact sites. The consensus loop does store a `SystemTime` at `node.rs:3342`, but that is outside the denied library sites and was not used to classify any of them.

For channels, the inspected node network code explicitly breaks when `event_tx.send(event).is_err()` at `node.rs:1376-1378`; a dropped receiver ends that event-dispatch task, not the process. `qc_verification.rs:72-75` creates a bounded channel and an unsupervised worker; a dropped sender/receiver is handled by the worker loop's channel result, but no restart supervisor is shown. Mutex `unwrap()` sites can panic on poisoning; the sources inspected do not show a panic while holding the short per-IP bookkeeping guards, so poisoning remains a conditional/unresolved case rather than a demonstrated live path.

## 4. Binary findings after the throwaway allow

The library errors prevented the normal binary lint from being reached. In the temporary worktree `/tmp/indra_node_triage`, the only temporary edit was a second crate-level allow in `indra-node/src/lib.rs`; the exact command was:

```text
CARGO_TARGET_DIR=/tmp/indra_node_triage_target cargo clippy -p indra-node --bins --no-deps 2>&1 | tee /tmp/indra_node_triage_clippy_bins2.log
```

It exited non-zero. The observer binary produced 1 denied finding:

```text
indra-node/src/bin/observer.rs:428:18 used `unwrap()` on a `Result` value
```

The node binary produced 141 denied findings: 129 `unwrap()` on `Result`, 3 `expect()` on `Result`, 5 `expect()` on `Option`, and 4 `panic!` findings. Complete line lists, copied from the raw diagnostic log, are:

```text
unwrap(Result): 558, 562, 583, 680, 803, 819, 951, 952, 956, 960, 964, 968, 973, 974, 981, 982, 986, 990, 992, 1000, 1005, 1161, 1162, 1168, 1172, 1206, 1268, 1304, 1325, 1338, 1351, 1356, 1370, 1371, 1372, 1409, 1447, 1454, 1467, 1522, 1523, 1576, 1577, 1587, 1609, 1615, 1632, 1633, 1638, 1647, 1671, 1672, 1678, 1685, 1686, 1688, 1693, 1700, 1713, 1730, 1737, 1743, 1744, 1745, 1760, 1766, 1767, 1768, 1782, 1783, 1802, 1803, 1895, 1899, 2036, 2053, 2433, 2455, 2457, 2523, 2544, 2557, 2575, 2588, 2606, 2623, 2633, 2694, 2874, 2876, 2878, 2899, 2925, 2951, 2969, 2994, 3009, 3036, 3252, 3280, 3297, 3298, 3309, 3312, 3351, 3362, 3369, 3429, 3460, 3513, 3620, 3636, 3651, 3666, 3670, 3704, 3720, 3796, 3823, 3838, 3840, 3842, 3851, 3852, 3879, 3937, 4036, 4054, 4062, 4099, 4511, 4570, 5277
expect(Result): 1261, 1821, 1843
expect(Option): 2634, 2704, 2736, 3036, 3552
panic!: 2433, 2455, 2457, 4409
```

The raw log says `error: could not compile indra-node (bin "node") due to 141 previous errors; 16 warnings emitted`. These findings span startup/configuration, peer/network runtime, consensus runtime, RPC runtime, and helper code; they are not startup-only. The `#[cfg(test)] mod tests` begins at `node.rs:5734`, so findings above that line are production binary code; the clippy list contains no denied binary findings after that test-module boundary.

Correction to the copied line-list transcription above: parsing every `error:` diagnostic in `/tmp/indra_node_triage_clippy_bins2.log` gives the authoritative counts and complete lists below. The raw log, not the compact transcription above, is the evidence source.

```text
node unwrap(Result), 129: 558, 562, 583, 680, 803, 819, 951, 952, 956, 960, 964, 968, 973, 974, 981, 982, 986, 990, 992, 1000, 1005, 1161, 1162, 1168, 1172, 1206, 1268, 1304, 1325, 1338, 1351, 1356, 1370, 1371, 1372, 1409, 1447, 1454, 1467, 1522, 1523, 1576, 1577, 1587, 1609, 1615, 1632, 1633, 1638, 1647, 1671, 1672, 1678, 1685, 1686, 1688, 1693, 1700, 1713, 1730, 1737, 1743, 1744, 1745, 1760, 1766, 1767, 1768, 1782, 1783, 1802, 1803, 1895, 1899, 2036, 2053, 2523, 2544, 2557, 2575, 2588, 2606, 2623, 2633, 2694, 2874, 2876, 2878, 2899, 2925, 2951, 2969, 2994, 3009, 3252, 3280, 3297, 3298, 3309, 3312, 3351, 3362, 3369, 3429, 3460, 3513, 3620, 3636, 3651, 3666, 3670, 3704, 3720, 3796, 3823, 3838, 3840, 3842, 3851, 3852, 3879, 3937, 4036, 4054, 4062, 4099, 4511, 4570, 5277
node expect(Result), 3: 1261, 1821, 1843
node expect(Option), 5: 2634, 2704, 2736, 3036, 3552
node panic!, 4: 2433, 2455, 2457, 4409
observer unwrap(Result), 1: observer.rs:428
```

This binary run is a triage inventory, not a proof that every listed panic is reachable from an external input. Each site still needs the same source-level constructor/input trace before being classified A or B. The source build was not changed to make these findings pass.

## 5. Spawn and supervision inventory

| Component | Spawn sites | Observation |
|---|---|---|
| Consensus driver | `indra-node/src/bin/node.rs:3336-3339` | `std::thread::spawn`; handle not stored or joined. A panic leaves the process alive with a silent validator task. |
| P2P runtime/event bridge | `node.rs:1244-1264`, `1281`, `1383`, `1445`, `1484`, `1728` | Threads/tasks are spawned without a supervisor handle. Listener bind/accept failures are logged/returned; per-connection failures are local. |
| Observer runtime | `node.rs:1842`, `1860`, `1873` | Runtime and poller/connection tasks are spawned; no process-exit supervisor is shown. |
| Block-store writer | `node.rs:1946` | `tokio::spawn` returns `writer_task`, but no join/await was found in the inspected caller path; a task panic is not shown to terminate the process. |
| Authenticated network event loop | `node.rs:2519` | `std::thread::spawn`; loop exits when the channel closes, with no restart supervisor shown. |
| Full RPC server | `node.rs:4490`, per connection `4544` | Listener and connection threads are unsupervised. The per-IP `lock().unwrap()` is a separate potential poison panic at `node.rs:4511`. |
| Hardened read-only RPC | `indra-node/src/hardened_read_rpc.rs:174`, per connection `226` | Unsupervised listener/connection threads. |
| Metrics | `indra-node/src/metrics.rs:234`, `253`, `285`, `303` | Unsupervised listener/connection threads. |
| Network QC verifier | `indra-node/src/qc_verification.rs:72-75` | Dedicated worker is spawned without a stored `JoinHandle`; caller receives a channel result, but worker restart is not shown. |

No repository systemd unit was found. `rg` found only the generic deployment-document reference `docs/DNS_SEED_PUBLISHING_AUTOMATION.md:81`; therefore the actual `Restart=` policy is **not established from the repository** and is server-side deployment state.

## 6. Recovery and limits noticed

`NodeEngine::init` loads a snapshot, checks its genesis fingerprint, verifies the retained tip, and replays from `snapshot.height + 1` (`indra-node/src/engine.rs:501-522`). With no snapshot it replays from genesis (`engine.rs:523-532`). `rebuild_state_from_height` anchors height-one replay to the stored genesis block hash (`engine.rs:1739-1750`) and verifies each stored proposal/state root during replay (`engine.rs:1752-1764`). The tests `restart_from_snapshot_produces_same_state_as_continuous` (`engine.rs:4146-4200`) and `startup_fails_on_snapshot_replay_gap` (`engine.rs:4276-4336`) exercise these recovery properties.

Not established: a complete reachability proof for the `engine.rs:723` dependency-index expectation, the `driver.rs:2053` snapshot lookup, the metrics reward schedule, every binary finding, and a deployed systemd restart policy. No source fix was applied.

