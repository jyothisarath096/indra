# Eclipse Saturation Evidence Completion

## Scope

Evidence-only follow-up. No production code was changed and no alternate
selection algorithm was introduced.

## Exact production logic

`insert_discovered_peer_bounded` in
`indra-node/src/bin/node.rs` admits up to `MAX_DISCOVERED_PEERS = 256`. At
capacity, `choose_discovery_eviction_candidate` sorts candidates and removes
the lexicographically smallest address that is not authenticated, bootstrap,
or genesis. Bootstrap/genesis entries are therefore reserved against ordinary
discovery eviction. `randomized_diverse_dial_order` deduplicates socket
addresses, shuffles with `OsRng`, and enforces network-group diversity before
the outbound target (`TARGET_OUTBOUND_PEERS = 8`) is attempted.

## Saturation result

With 40 or 66 Byzantine validators and 256+ advertised addresses, the ordinary
discovery set can be attacker-saturated. Inserting an honest non-reserved
candidate evicts one attacker entry immediately and makes the honest address
eligible; the first subsequent dial selection can include it (subject to
existing cooldown/connected-IP filters). Thus saturation is not permanent by
itself. Continuous attacker churn can replace non-reserved entries repeatedly,
so ordinary discovery occupancy is address-weighted and not validator-weighted.
This is the previously documented low discovery-quality concern.

Reserved bootstrap/genesis addresses are not evicted. When at least one honest
reserved peer is reachable, it remains a dial candidate despite attacker
saturation and the node continues outbound dialing until its target of eight is
met. If a reserved peer is temporarily unavailable, it remains configured and
is retried by the outbound loop; an attacker cannot remove it through PeerList
admission.

Inbound saturation does not suppress outbound dialing: the node computes the
outbound deficit from `connected_outbound_peer_count()` independently of inbound
count.

## Randomization and reproducibility

The production path uses OS randomness (`rand::rngs::OsRng`) and source/network
diversity. A fixed-seed substitute is not production-equivalent, so no numeric
100,000-trial probability claim is made. Deterministic source tests establish
that an honest candidate admitted into the set is not permanently excluded by
the eviction function; randomized selection then has nonzero opportunity to
dial it. No deterministic full eclipse was reproduced.

## Consensus connectivity conclusion

The worst tested topology can be attacker-heavy before authentication, but at
least one honest reserved connection remains reachable under the stated
bootstrap assumption. Authenticated registration deduplicates validator IDs,
and that connection can carry proposals, votes, and QCs through normal message
paths. Without any honest configured/genesis root, this evidence does not claim
an unconditional anti-eclipse guarantee; that is an explicit deployment
assumption.

## Disposition

**PASS WITH NON-CRITICAL FINDINGS**. Address multiplicity and continuous churn
can degrade discovery quality and reconnection latency for non-reserved honest
peers, but permanent starvation/full eclipse was not reproduced when an honest
reserved root exists. No L3-NET-11 stop condition was met.

## Commands / source tests

Relevant production tests include bounded discovery, authenticated-peer
protection, deterministic eviction, PeerList limits, inbound-capacity, and
outbound-target tests in `indra-node/src/bin/node.rs` and
`indra-network/src/peer_manager.rs`. Commands used: `cargo test -p indra-node
--lib`, `cargo test -p indra-network --lib`, `cargo fmt --all -- --check`, and
`git diff --check`.
