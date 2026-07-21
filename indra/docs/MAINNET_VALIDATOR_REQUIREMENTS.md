# Mainnet Validator Requirements

Status: pre-mainnet operational requirement. This document records validator
operator requirements that are protocol-relevant but not encoded directly in
chain state.

## Network bandwidth

Mainnet validators must have at least **250 Mbps sustained uplink** capacity.
**1 Gbps sustained uplink is preferred**.

This is a sustained-capacity requirement, not merely an advertised burst port
speed. Operators should provision enough headroom that consensus traffic is not
regularly contending with backups, monitoring exports, unrelated workloads, or
provider throttling.

### Rationale

Scale-validation Phase 2 measured block delivery over the N=200 partial-mesh
consensus relay topology with byte-level transfer time included. The binding
case was a worst-case bootstrap-as-proposer block carrying:

- a full-size 200-signer hybrid QC;
- 200 reveal-set evidence entries;
- origin broadcast over the bootstrap node's high connection degree;
- relay-hop fanout using the block relay multiplier.

Under that scenario, sustained uplink below roughly 75 Mbps has no meaningful
margin against the 8s propose timeout:

| Sustained uplink | Worst-case quorum delivery time |
| ---: | ---: |
| 70 Mbps | ~8.51s — fails the 8s propose timeout |
| 75 Mbps | ~7.95s — barely passes, effectively no margin |
| 100 Mbps | ~6.00s |
| 250 Mbps | ~2.50s — comfortable margin |
| 1 Gbps | ~0.74s — preferred operating headroom |

Therefore INDRA should treat **250 Mbps sustained uplink** as the minimum
mainnet validator requirement, with **1 Gbps preferred** for healthy operational
margin.

### Methodology reference

This requirement comes from Scale-Validation Phase 2, which extended the
existing N=200 relay/topology simulations from
[`PARTIAL_MESH_CONSENSUS_RELAY_DESIGN.md`](PARTIAL_MESH_CONSENSUS_RELAY_DESIGN.md)
and the Phase 1 timing work in
[`VRF_TIMING_WINDOWS_SCALE_VALIDATION.md`](VRF_TIMING_WINDOWS_SCALE_VALIDATION.md).

The Phase 2 model specifically filled the gap left by arithmetic-only bandwidth
estimates: it simulated elapsed delivery time as network latency plus actual
byte transfer time for each store-and-forward relay hop.

## Network address advertisement

Mainnet validators are expected to publish a current P2P dial address in their
on-chain validator entry once the validator-network-address protocol upgrade is
activated.

The on-chain `network_addr` field is the source of truth for dynamic validator
discovery. DNS seeds, static bootstrap peers, peer exchange, and persisted peer
tables remain useful distribution/cache layers, but they must not be treated as
independent authorities for "who is active and how do I reach them."

Operationally, DNS seed records should be generated from the current active
validator set by querying `indra_getValidatorSet` and publishing active
validators' non-null `network_addr` values. The DNS publishing script/service is
out of scope for the protocol field itself. The operational publisher is
documented in
[`DNS_SEED_PUBLISHING_AUTOMATION.md`](DNS_SEED_PUBLISHING_AUTOMATION.md), and
the intended relationship is:

1. chain state records validator identity, active status, and `network_addr`;
2. `indra_getValidatorSet` exposes those fields;
3. DNS seed infrastructure caches that chain-derived active-address set;
4. PEX and persisted peer tables continue to accelerate discovery after first
   contact.

For the initial version, `network_addr` is intentionally strict IP:port syntax
only. Hostnames are rejected so the authoritative discovery field does not
reintroduce a live DNS dependency or hostname-hijack surface.

## Mainnet genesis hard-fork height reset checklist

Before mainnet launch, reset every testnet-specific hard-fork activation height
to an explicit mainnet-genesis value. These constants are single global values
in source code; they are **not automatically network-aware** and do **not**
derive from `chain_id`. Reusing a height chosen for this already-running testnet
would activate a rule at an arbitrary, meaningless point in mainnet history.

For rules intended to exist from mainnet genesis, set the activation height to
`0` before building the mainnet genesis/release. For rules intentionally deferred
past mainnet genesis, record the release hash, planned activation height, and
operator rollout plan before launch.

Current hardcoded hard-fork/activation-height constants that must be reviewed:

- `STAKING_COMMITMENT_PROOF_HEIGHT`
- `OVERFLOW_FIX_HEIGHT`
- `VRF_VERIFIED_OUTPUT_HEIGHT`
- `HYBRID_QC_HEIGHT`
- `VOTE_CHAIN_ID_HEIGHT`
- `PUBLIC_PROPOSER_ELECTION_HEIGHT`
- `VRF_COMMIT_REVEAL_ELECTION_HEIGHT`
- `REVEAL_SET_COMMITMENT_HEIGHT`
- `VALIDATOR_NETWORK_ADDRESS_HEIGHT`
- `REGISTERED_VALIDATOR_CAP_HEIGHT`
- `GOVERNANCE_PROPOSAL_PRUNING_HEIGHT`
- `STATE_COMMITMENT_V2_HEIGHT`
- `COMPRESSED_AUTH_TREE_HEIGHT`
- `COMPACT_STAKE_BOND_HEIGHT`
- `DELEGATOR_IDENTITY_REGISTRY_HEIGHT`

This checklist is intentionally broader than currently-live testnet features.
Any future constant following the same hardcoded height-gate pattern must be
added here before merge, otherwise mainnet readiness review can miss it.
