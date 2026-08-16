# INDRA Privacy Status

This document states the current privacy boundary plainly. It is deliberately
conservative: it describes what the current code actually protects, and what it
does not yet protect.

## What is protected today

Public RPC does not provide unauthenticated owner-indexed scans or joined
protocol-output provenance. Raw blocks and transactions remain public and can
still be downloaded and scanned by any caller.

The old unauthenticated address-indexed RPC methods have been replaced by:

- `indra_getScanChallenge(payment_address)`
- `indra_explainUtxoProvenanceAuthorized(payment_address, proof, utxo_id)`
- optional authenticated provenance parameters on `indra_getCanonicalBlocks`

The authorized methods use canonical chain-bound `PaymentAddressV1`, a random
two-minute challenge, and a dual-verified hybrid signature. A challenge is
consumed after its first successful verification. Joined provenance is filtered
by exact full-hybrid-public-key equality; no classical-only lookup identity or
authorization path remains.

This is RPC-layer hardening only. It prevents the node from performing extra
owner-specific joins for an unauthorized caller; it cannot prevent that caller
from independently analyzing public block data. The proof is not a view key.

## What is not protected today

OutputV1 still stores owner public-key data and value metadata in raw chain
state. Anyone running a full node, operating an archive, or reading raw blocks
directly can still inspect that data without using public RPC at all.

INDRA is therefore a transparent-amount, pseudonymous ledger. Ownership uses
full hybrid public keys and monetary validity uses checked-`u64` conservation
plus dust rules. Values and owners remain linkable in raw chain data, so amount
correlation can deanonymize transaction flows even when users avoid key reuse.

The previous broad “optional view keys” wording was inaccurate. This document
corrects that claim; it does not remove a privacy guarantee that was actually
implemented.

## Planned future work

Genuine node-level transaction privacy requires a protocol upgrade, currently
referred to as `OutputV2`, with:

- stealth destinations instead of raw recipient public keys;
- encrypted recipient notes;
- real view keys for selective disclosure; and
- wallet scanning that can identify owned outputs without exposing spend
  capability.

That design remains explicitly deferred. It must use a reviewed,
post-quantum-appropriate stealth-spend construction before implementation,
because real user funds and privacy would depend on it.

Until that review is complete, INDRA should not claim full view-key,
stealth-address, or node-level transaction privacy.
