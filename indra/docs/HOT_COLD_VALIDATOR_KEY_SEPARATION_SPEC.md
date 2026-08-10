# INDRA Validator Hot/Cold Key Separation Specification

## Status

This is the canonical genesis-native authority model. Every validator is
created with distinct hot and cold roles. There is no enrollment interval,
legacy hot-authorized validator state, bond conversion, or compatibility
fallback.

## Roles

### Hot identity

The hot hybrid key derives `validator_id` and signs live consensus traffic and
the outer staking/governance envelope where required. The VRF key participates
in proposer election. Hot compromise must not grant custody of validator
principal.

### Cold identity

The cold identity is a complete independent Ed25519 + ML-DSA-87 hybrid pair.
It authorizes validator asset-custody and governance operations designated as
cold. Both components are mandatory; classical-only, PQ-only, component-mixed,
or default-key authorization is invalid.

Cold keystores use the authenticated encrypted `indra-cold-keystore` format.
Offline Shamir ceremonies split both independent cold seeds. Recovery produces
an encrypted temporary cold keystore, never a plaintext protocol format.

## Registration

`RegisterValidator` binds:

- the hot-derived validator ID and hot public identity;
- the VRF public key;
- the initial full cold hybrid public key and version;
- commission and network-visible validator metadata;
- the bond UTXO and its custody proof; and
- the chain/signature domains.

The hot and cold signatures prove their respective roles. The registration
bond's logical principal remains `validator_id`, while its source UTXO must be
owned by the registering cold key. Registration is atomic.

## Authority matrix

- Consensus votes, proposals, VRF messages, and QCs: hot/VRF authority.
- Validator self stake, self exit, reward/commission/auto-delegation actions,
  validator governance actions, and cold-key rotation: current cold authority
  plus any required outer envelope.
- Delegation and delegator exits: registered delegator identity.
- Ordinary payment transactions: the payment/output ownership key.
- Slashing: protocol evidence verified against the historical consensus
  authority committed for the infraction.

The canonical staking/governance tag table expresses these roles directly.
There are no historical tag aliases or alternative wire encodings.

## Custody and state

Validator-owned stake uses
`PositionCustodyV1::ValidatorColdIdentity { validator_id }`. Logical owner and
custody owner are deliberately different concepts: the position belongs to the
validator identity, while the source asset must be controlled by its current
cold hybrid key. Delegated positions use
`PositionCustodyV1::DelegatorIdentity` for both logical and custody identity.

Rewards, snapshots, governance weight, exits, slashing, tranche refunds,
tombstones, and RPC classification continue to key validator positions by
`validator_id`; rotation changes custody authority, not logical ownership or
position identifiers.

## Rotation

`RotateValidatorColdKey` requires authorization from the current cold pair and
proof of possession of the proposed full new pair. Versions advance exactly by
one and use the cold-role nonce namespace. The registry rejects reuse or
cross-role/component collisions. After commit, every later cold operation
resolves only the new current key; retired components remain recorded under
bounded canonical collections for anti-reuse checks.

Rotation cannot alter the hot validator identity, VRF identity, existing
position IDs, or historical signature verification.

## Loss and compromise

There is no online fallback from cold authority to the hot key. Loss of the
cold recovery material can make cold-authorized assets unavailable; this is an
intentional custody property. Operators must maintain verified offline shares
and exercise recovery procedures before funding a validator.

On suspected compromise, rotate while the current cold key remains available.
The protocol does not accept an emergency classical-only or hot-key override.

## Required invariants

1. Hot and cold secrets are independently generated.
2. Every hybrid authorization verifies both complete matching components.
3. Every validator asset deposit checks current cold custody separately from
   logical validator ownership.
4. Nonces and key versions advance monotonically and atomically.
5. Rotation updates every authority dependency and preserves historical
   verification material required by consensus.
6. No decoder, tag, state branch, CLI, or FFI path exposes a compatibility
   fallback to raw/private or old hot-authorized behavior.
