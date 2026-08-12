# INDRA Privacy Status

This document states the current privacy boundary plainly. It is deliberately
conservative: it describes what the current code actually protects, and what it
does not yet protect.

## What is protected today

Casual remote surveillance through public RPC endpoints is closed for legacy
OutputV1 wallet scans.

The old unauthenticated address-indexed RPC methods have been replaced by:

- `indra_getLegacyScanChallenge(address)`

The authorized methods require a dual-verified hybrid signature and an exact
full-hybrid-public-key match to the requested UTXO owner before returning
address-specific UTXO or balance data. The legacy 32-byte address remains a
lookup label only; its classical-key hash is not an authorization boundary.
A public RPC endpoint can still serve general chain data, but it should
not let arbitrary callers enumerate a specific owner's holdings by address.

This is RPC-layer hardening only. The proof is not a view key and does not grant
read-only third-party visibility without spend-key possession.

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
