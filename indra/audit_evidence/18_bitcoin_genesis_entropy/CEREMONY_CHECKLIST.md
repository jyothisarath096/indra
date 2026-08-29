# Bitcoin genesis-entropy commit/reveal checklist

## Phase A — before the target exists

- Each validator runs `indra-genesis commit-validator`, publishes only the
  version-1 commitment artifact, and retains the reveal artifact privately.
- The coordinator supplies all public commitment artifacts to
  `indra-genesis precommit` with at least two independently operated Bitcoin
  Core clients. Both nodes must report the same tip.
- Require `target_height >= current_tip + 144`; equality is valid. The command
  rejects an already-mined target and any shorter lead.
- Publish the complete precommit artifact and hash through at least two
  independent public witness channels. The local timestamp is informational.
- Confirm the artifact exposes commitments but no raw validator keys or nonce.

## Phase B/C — validator opening and authority freeze, before target

- Publish every validator reveal while the committed target remains in the
  future. Run `freeze-authority` against two agreeing Bitcoin Core nodes; it
  fails unless both report `tip < target`.
- Confirm each reveal opens its committed hash and that the opened set exactly
  equals the precommitted set. No replacement member, key, stake, suite, or
  activation value is permitted.
- Publish the fully opened authority artifact and hash through at least two
  independent witness channels before the target. The recorded tip and local
  timestamp are informational; external witnesses establish chronology.

## Phase D/E — target, confirmations, and deterministic finalization

- Only after the frozen authority is witnessed, record the exact committed
  target header from two independent Bitcoin Core nodes.
- Wait until the target has at least 100 observed confirmations. The descriptor
  must declare exactly 100; 99 and 101 are invalid protocol values.
- Run `indra-genesis finalize` with the original precommit, frozen authority,
  and at least two independently operated Bitcoin Core clients. It accepts no
  validator reveal. Both nodes must agree on network genesis, target hash/header,
  target height, active-chain membership, and tip.
- Run `indra-genesis verify-bitcoin-entropy` again from independent operators.
- Publish the final manifest, ceremony artifacts, RPC evidence, genesis block
  hash/fingerprint, snapshot root, and election seed.

## Reorg/no-fallback rule

- If the target is displaced before launch, keep the committed height, use the
  new active-chain block there, and restart the 100-confirmation wait. Validator
  commitments remain unchanged.
- Never select another height, lower depth, use current tip, cached stale data,
  local randomness, or a single-node override. If RPC is unavailable, wait.

## Abort conditions

- Missing publication through two independent witness channels before target.
- Any precommit hash/canonical-byte mismatch or reveal-opening mismatch.
- Missing, duplicate, or replacement validator reveal.
- Frozen authority was not completed and externally witnessed before target.
- Any attempt to observe a target for an incomplete ceremony and selectively
  publish/restart only when its randomness is favorable.
- Independent Bitcoin nodes disagree.
- Declared depth is not exactly 100 or observed depth is below 100.
- Any attempt to invoke the removed one-shot `indra-genesis build` workflow.
