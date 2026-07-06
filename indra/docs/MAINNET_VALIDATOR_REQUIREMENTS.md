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
