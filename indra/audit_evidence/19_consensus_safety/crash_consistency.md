# Crash consistency and vote uniqueness

## Exact order

1. Check authority and in-memory collector duplication (`indra-node/src/driver.rs:1294-1323`).
2. Serialize the current verified lock, if any (`:1331-1338`).
3. Write format-3 safety state to a same-directory temporary file, flush and
   `fsync`, atomic rename, then parent-directory `fsync`
   (`indra-storage/src/vote_safety.rs:84-127`; `indra-storage/src/atomic.rs:9-28`).
4. Resolve the canonical snapshot root and produce the hybrid vote
   (`indra-node/src/engine.rs:1557-1584`).
5. Add the complete vote locally; only then return broadcast
   (`indra-node/src/driver.rs:1349-1374,1797-1831`).

Persistence is **before signing** and **before broadcast**.

| Crash point | Durable/restart result | Result |
|---|---|---|
| before persistence | no signature requested; slot may be retried | safe |
| during temp write / before rename | old record remains or load fails closed | safe |
| after rename before signing | restart advances to `round+1` | safe, conservative lost vote |
| before Ed25519 | same as above | safe |
| between Ed25519 and ML-DSA | no complete signature returned; restart skips round | safe |
| after both, before collector/broadcast | record durable; restart skips round | safe |
| before/after broadcast | record durable | safe |
| after quorum, before lock persistence | non-nil precommit cannot be signed/broadcast | safe |
| after lock persistence | restart re-verifies proposal, root-bound PoLC and quorum | safe |
| commit before safety-file clear | old record height is behind new `next_height` | safe |

The record stores the latest slot rather than its hash. Restart never re-enters
that round (`indra-node/src/driver.rs:896-918`), so it cannot sign B after a
possibly broadcast A. Round 1023 disables voting rather than resetting (`:897-910`).

Format 3 rejects wrong version/step/round, malformed option framing,
empty/oversized or wrong-round PoLCs, non-exact embedded encodings and trailing
bytes (`indra-storage/src/vote_safety.rs:200-260`). CRC-valid content is still
untrusted: driver restoration checks next height, all block identities,
canonical proposer authority, every root-bound PoLC vote and strict quorum before
assigning lock fields (`indra-node/src/driver.rs:813-866`). Failure sets
`vote_safety_unavailable` and blocks voting (`:869-928`).

Classification: **PASS**.
