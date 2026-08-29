# Gossip origin-correlation privacy audit and design recommendation

**Scope:** audit and design only; no production-code change  
**Repository snapshot:** `20448f3d2fd68181481947da13dbd5d17b503e35`  
**Audit date:** 2026-08-30

## Executive result

INDRA does not currently obscure the validator through which a transaction enters
the validator gossip network. A transaction accepted through
`indra_sendTransaction` is sent immediately to every connected validator. Every
one-hop peer can therefore identify the RPC-entry validator as the peer that sent
the transaction first (subject to ordinary races and incomplete observation).
Inbound recipients validate it and flood it to every connected validator except
the sender. This is source-like flood propagation, not Dandelion-style stem
propagation.

The P2P threat model is narrower than Bitcoin's, Grin's, or Monero's. Port 30303
is an authenticated **active-validator-only** mesh. A non-validator/full-node
observer uses the separate port 30304 protocol and cannot inject or relay
transactions. The repository contains no implemented path, configuration, or
committed near-term design that admits a non-validator or light client into
`peers_by_validator`. Signed transactions enter through a validator's full RPC
submission endpoint, or are received from another already-authenticated
validator.

The realistic gossip-layer property is therefore:

> Make it harder for other validators, and for connection observers that cannot
> observe every stem hop, to identify which validator was the transaction's RPC
> entry point.

It cannot hide the submitting wallet's IP, timing, or identity from the validator
whose RPC service the wallet uses. That requires client-to-RPC transport privacy
(Tor/I2P, a privacy proxy, or another submission network). Nor can a gossip
scheme defeat a global passive observer that sees the wallet-to-RPC connection
and all validator links, or a sufficiently colluding validator set.

**Recommendation for human approval:** implement a deliberately small
Dandelion++-inspired v1 for `Message::Tx` only: one epoch-stable outbound stem
relay; 10-minute epochs; per-transaction probabilistic stem/fluff forwarding with
provisional fluff probability `q = 0.20`; diffusion on fluff; loop detection and
a randomized embargo fail-safe. Reuse authenticated validator identity,
`ManagedPeer::is_outbound`, bounded TTL caches, and deterministic epoch/key
selection idioms. Do not apply it to `Vote` or `Block`; their latency and liveness
requirements differ and their cryptographic authors are already explicit. Defer
staking/governance operations until their lower-volume anonymity set and product
semantics are decided.

This recommendation is not an implementation authorization. Section 9 lists the
parameters and product choices that require a human decision.

## 1. Evidence standard and terminology

All repository citations below are `file:line` references in the audited commit.
“Local” means created or accepted by this node's RPC/consensus path. “Inbound”
means received over an authenticated validator connection. “Broadcast” means a
`NetworkCommand::Broadcast` to every current entry of `peers_by_validator`;
“broadcast except” excludes one authenticated validator
(`indra-network/src/net_types.rs:61-79`,
`indra-network/src/peer_manager.rs:714-749`).

The wire enum defines the requested five classes as `Block`, `Vote`, `Tx`,
`StakingOp`, and `GovernanceOp` (`indra-network/src/message.rs:132-144`).

## 2. Current message-propagation map

### 2.1 `Message::Tx`

#### Locally submitted transaction

1. The full RPC handler decodes the transaction and calls
   `engine.add_transaction` (`indra-node/src/bin/node.rs:5378-5404`).
2. On acceptance it inserts the transaction ID into the transaction TTL cache
   and directly calls `gossip.broadcast(&Message::Tx(tx))`
   (`indra-node/src/bin/node.rs:5405-5418`).
3. `Broadcast` enumerates all connected validator identities and enqueues a copy
   to each (`indra-network/src/peer_manager.rs:714-749`).

This path does **not** use `broadcast_locally_accepted_op`; that helper handles
only staking/governance keys. The direct RPC call is the precise divergence the
design must remove or route through a transaction-origin policy.

#### Transaction received from a validator

1. The peer manager applies the authenticated-validator rate limiter, then calls
   `relay_if_eligible` before delivering the message to the node
   (`indra-network/src/peer_manager.rs:895-949`). `relay_if_eligible` recognizes
   only `Block` and `Vote`, so it is a no-op for `Tx`
   (`indra-network/src/peer_manager.rs:309-315`,
   `indra-network/src/peer_manager.rs:647-650`).
2. The node hashes the encoded transaction and drops it if already in its
   transaction TTL cache (`indra-node/src/bin/node.rs:2736-2746`).
3. It calls `engine.add_transaction`; on success it records the ID, gives any
   applicable admission score, and broadcasts to all validator peers except the
   authenticated sender (`indra-node/src/bin/node.rs:2747-2768`).

Thus a local transaction immediately floods all neighbors. Each first recipient
then floods all of its neighbors except the sender. Dedup prevents repeated
admission, but does not conceal the first sender.

### 2.2 `Message::StakingOp`

#### Locally submitted operation

The RPC path decodes and admits the operation, then calls
`broadcast_locally_accepted_op` (`indra-node/src/bin/node.rs:5271-5288`). The
helper hashes/marks the operation in the shared operation cache and broadcasts to
all validator peers (`indra-node/src/bin/node.rs:612-635`).

#### Operation received from a validator

The node derives the same relay key, drops a seen item, validates/adopts it, and
on success calls `rebroadcast_inbound_accepted_op`
(`indra-node/src/bin/node.rs:2672-2696`). That helper marks the cache and
broadcasts to every peer except the authenticated sender
(`indra-node/src/bin/node.rs:637-651`).

The local/inbound divergence is therefore “all peers” versus “all peers except
origin,” after a common dedup-key insertion.

### 2.3 `Message::GovernanceOp`

The shape is identical to staking. Local RPC admission calls
`broadcast_locally_accepted_op` (`indra-node/src/bin/node.rs:5316-5350`). Inbound
processing drops a seen operation, admits it, then calls
`rebroadcast_inbound_accepted_op` (`indra-node/src/bin/node.rs:2704-2728`). The
helpers' behavior is at `indra-node/src/bin/node.rs:612-651`.

### 2.4 `Message::Vote` and `Message::Block`

#### Locally produced consensus message

`DriverAction::BroadcastBlock` and `BroadcastVote` convert directly to
`Message::Block` and `Message::Vote`
(`indra-node/src/net_driver.rs:49-55`). `process_driver_actions` passes either
message to `broadcast_driver_message`, whose implementation is a full
`gossip.broadcast` (`indra-node/src/bin/node.rs:3816-3818`,
`indra-node/src/bin/node.rs:3891-3899`). Therefore a locally produced vote or
block goes to every connected validator.

#### Consensus message received from a validator

Before node/driver delivery, the peer manager recognizes only `Block` and `Vote`
as relay classes, cryptographically verifies a first-seen message, selects a
bounded subset of peers excluding the sender/already-forwarded targets, and
enqueues it (`indra-network/src/peer_manager.rs:309-330`,
`indra-network/src/peer_manager.rs:551-580`,
`indra-network/src/peer_manager.rs:608-711`). The verified message is then also
delivered to the node/consensus driver
(`indra-network/src/peer_manager.rs:895-949`); network-to-driver mapping is at
`indra-node/src/net_driver.rs:13-27`.

This is the reverse of transaction/op propagation in one important respect:
locally generated consensus messages flood, while inbound consensus messages use
bounded relay fanout. It is not Dandelion: there is no stem marker, epoch-stable
single relay, probabilistic fluff transition, or embargo timer.

## 3. Actual topology: validator gossip versus observers and RPC

### 3.1 `peers_by_validator` is validator-only in current code

The validator transport cannot be joined merely by speaking the wire format:

* A node cannot construct its validator handshake configuration without a local
  validator ID and PQ keypair (`indra-node/src/bin/node.rs:1082-1095`).
* The allowed remote identities/keys are derived from the height-specific network
  authority set (`indra-node/src/bin/node.rs:1097-1127`).
* Both initiator and responder reject an identity absent from `known_validators`
  before completing authentication, and verify its PQ signature
  (`indra-network/src/handshake.rs:317-366`,
  `indra-network/src/handshake.rs:375-418`).
* Only a successful handshake is registered in `peers_by_validator`; the map is
  keyed by authenticated validator ID and retains one logical connection per ID
  (`indra-network/src/peer_manager.rs:954-1026`,
  `indra-network/src/peer_manager.rs:1102-1123`).

The P2P listener sends successful validator handshakes to that peer manager
(`indra-node/src/bin/node.rs:1367-1440`). README labels port 30303 “validator
gossip” (`README.md:137-141`).

### 3.2 Full-node/observer connections are a separate, non-relaying protocol

Port 30304 has its own listener and observer handshake
(`indra-node/src/bin/node.rs:1814-1855`,
`indra-node/src/bin/node.rs:1900-1905`). It serves status/block-range requests
and pushes blocks. If an observer sends `Tx`, `StakingOp`, or `GovernanceOp`, the
match arm does nothing; consensus control messages cause disconnect
(`indra-node/src/bin/node.rs:1931-1991`). Observer connections are never inserted
into `peers_by_validator` and never participate in relay.

### 3.3 Transaction ingress conclusion and roadmap boundary

The submission methods exist on the full RPC listener, while the optional public
listener is read-only (`README.md:248-255`, `README.md:313-319`). Deployment
guidance says the full listener exposes signed submissions and should normally be
bound locally (`docs/RPC_PUBLIC_DEPLOYMENT_GUIDANCE.md:63-70`). Consequently,
from code in this snapshot, a wallet transaction first enters one validator via
that validator's full RPC path; after that, only authenticated validators carry
it.

Repository-wide searches found no roadmap file and no proposed full/light-client
admission path into `peers_by_validator`. The closest network design explicitly
left `Tx` relay as a separate open design question
(`docs/PARTIAL_MESH_CONSENSUS_RELAY_DESIGN.md:428-439`). This proves absence from
the audited repository, not a promise about unrecorded future plans. A human
roadmap owner must confirm that the validator-only boundary is intended to
remain stable before implementation.

## 4. Existing relay, dedup, rate-limit, and direction mechanisms

| Mechanism | Actual role | Origin-obscuring effect |
|---|---|---|
| Transaction/operation `BoundedTtlSet` caches | 16,384-entry caches, 10-minute TTL; local and accepted inbound items are marked before flood (`indra-node/src/bin/node.rs:66-69`, `indra-node/src/bin/node.rs:590-610`, `indra-node/src/bin/node.rs:2736-2768`). | Prevents repeated processing/loops. It does not obscure the first hop; indeed the first peer remains observable. Useful reusable storage idiom for stem/fluff state. |
| `RelaySeenCache` | For `Vote`/`Block` only, stores message key → validators already forwarded to, bounded at 16,384 and 10 minutes (`indra-network/src/peer_manager.rs:48-49`, `indra-network/src/peer_manager.rs:159-164`, `indra-network/src/peer_manager.rs:201-253`). | Incidental partial obscuring after hop one: not every peer necessarily hears directly from the signer. No protection for `Tx`, staking, or governance. Since local consensus messages flood, direct peers still know the signer-origin link—and signatures identify the author regardless. |
| `derive_consensus_relay_fanout` | Computes `clamp(ceil(2 ln N)+2, 4, 16)`; block fanout is higher and capped at 24 (`indra-network/src/peer_manager.rs:52-57`, `indra-network/src/peer_manager.rs:333-355`). Target order is message-key-derived, score-prioritized, excludes sender/already-forwarded nodes (`indra-network/src/peer_manager.rs:608-645`). | Lowers the number of inbound-relay observers and produces multi-hop arrival, so it incidentally weakens naive timing inference for votes/blocks. Selection is deterministic for a message/key and not an anonymity protocol. It is irrelevant to current `Tx` flooding. |
| `ConsensusDuplicateFilter` | Per-connection bounded TTL suppression of duplicate votes before actor delivery (`indra-network/src/peer_manager.rs:175-192`; use at `indra-network/src/peer_manager.rs:1034-1066`). | Loop/bandwidth protection only; no deliberate origin hiding. |
| Per-validator/global rate limits | Classifies every requested message type; Tx bucket 50/s burst 200, staking 10/s burst 50, governance 5/s burst 20; large payloads also use byte budgets (`indra-network/src/rate_limit.rs:75-150`, `indra-network/src/rate_limit.rs:215-285`). | Abuse resistance, not anonymity. A stem design must remain behind these admission limits and must not let retries bypass them. |
| `BoundedCooldownTracker` | Bounded exponential retry history used for inbound/outbound connection failures (`indra-network/src/policy.rs:300-376`; connection use at `indra-node/src/bin/node.rs:1301-1341`). | No message-origin protection. Its bounded/TTL/backoff style is reusable for relay failure handling, but the current tracker is connection policy, not a transaction embargo. |
| `ManagedPeer::is_outbound` | Records whether this node initiated the authenticated connection (`indra-network/src/peer_manager.rs:82-89`, `indra-network/src/peer_manager.rs:1026-1112`); exposed event semantics are explicit (`indra-network/src/net_types.rs:35-55`). It is currently used for connection counts/cooldowns (`indra-network/src/peer_manager.rs:1160-1169`, `indra-node/src/bin/node.rs:1301-1341`). | No current message privacy. It is the natural v1 input for choosing Dandelion++ stem relays: prefer locally initiated connections, avoiding an attacker gaining relay selection merely by opening many inbound sockets. In INDRA, validator authentication and one-connection-per-ID already limit Sybil multiplicity. |

## 5. What observers can and cannot see today

### 5.1 Another validator in the mesh

A connected validator sees the authenticated identity and socket address of its
direct peer (`indra-network/src/net_types.rs:23-46`). If validator A accepts a
transaction over RPC, A immediately sends the identical `Message::Tx` to every
connected validator. Each direct neighbor can truthfully say “A was my first
network sender for this transaction.” In a fully connected mesh, all other
validators see A directly, making A the unique common first sender absent races.
In a partial mesh, A's neighbors learn this directly and downstream validators
can use first-spy/timing inference, but cannot prove that A created the transaction
rather than receiving it from some peer not visible to them.

The message does not contain a gossip-origin field. What leaks is the correlation
between transaction identity, earliest arrival time, and authenticated transport
peer. The RPC client's IP is not carried in gossip. Only A observes the client's
RPC transport endpoint (or its proxy).

Staking/governance operations have the same flood-from-entry shape. Votes and
blocks differ: the locally producing validator floods them, while later peers
relay to bounded subsets. Their signed payloads also identify the voting
validator/proposer, so concealing cryptographic authorship is neither achieved
nor a sensible goal.

### 5.2 Non-validator network-level observer

The answer depends on vantage point:

* An ordinary observer-port client sees pushed blocks/status and block responses,
  not transaction gossip; it cannot join `peers_by_validator` (Section 3).
* A passive observer of one validator link can see endpoints and packet timing/
  sizes, but application frames on validator transport use negotiated encrypted
  directional keys (`indra-network/src/handshake.rs:317-374`). It may correlate
  simultaneous bursts, but cannot identify a `Tx` from plaintext solely from
  this code's transport.
* An observer that can identify transaction-shaped encrypted frames across many
  links sees the current entry validator fan out nearly simultaneously to all its
  peers. This traffic-analysis pattern strongly correlates that validator with
  network entry.
* An observer that sees the wallet-to-RPC flow and the validator mesh can correlate
  both layers. No gossip-only change can prevent that global correlation.

Accordingly, “flood-from-origin leaks the wallet's IP to every validator” would
be false. It leaks the likely **RPC-entry validator** to direct validators and to
sufficiently capable traffic observers; the entry validator separately knows
the RPC client endpoint.

## 6. Other systems: primary-source review

### 6.1 Dandelion and Dandelion++

The original Dandelion paper proposes a transaction's two-stage propagation:
an anonymity/stem phase over a line-like graph followed by ordinary
diffusion/fluff. Its objective is to prevent observers from linking transaction
origins to IP addresses while retaining low overhead [Venkatakrishnan, Fanti &
Viswanath, *Dandelion: Redesigning the Bitcoin Network for Anonymity*, 2017](https://arxiv.org/abs/1701.04439).

Dandelion++ removes fragile assumptions of the first design and analyzes an
adversary that controls a fraction of nodes, observes its incident traffic, and
may deviate from the protocol. Nodes periodically build an anonymity graph from
outbound connections; during each epoch they use stable relay mappings. An
originated transaction enters stem. At each stem relay it either continues along
one selected edge or transitions with probability `q` to diffusion. A randomized
fail-safe timer causes a prior stem node to diffuse a transaction if a malicious
successor black-holes it. The paper analyzes graph construction, intersection
attacks, graph learning, black holes, and first-spy estimation, and evaluates
**precision** (fraction of an adversary's source assignments that are correct)
and **recall** (fraction of honest sources correctly identified), rather than
claiming sender indistinguishability against every observer. It recommends the
fluff/path parameter `q <= 0.2` and proposes a 4-regular anonymity graph as a
robust operating point [Fanti et al., *Dandelion++: Lightweight Cryptocurrency
Networking with Formal Anonymity Guarantees*, SIGMETRICS 2018, §§3–5 and 7](https://arxiv.org/abs/1805.11060).

The formal guarantees assume a large open cryptocurrency P2P graph with many
honest nodes and adversarial nodes distributed through it. INDRA's authenticated,
bounded (maximum mature active set 200) validator mesh removes public Sybil
admission but also sharply reduces the anonymity set. The mechanism transfers;
the paper's numerical anonymity results do not transfer without an INDRA-specific
topology/adversary simulation.

### 6.2 Production adaptation: Grin's simplified Dandelion++

Grin's own implementation document is unusually explicit about deviations. It
uses individually tracked 10-minute epochs, selects one random connected outbound
relay per epoch, chooses stem mode with 90% probability (`q = 0.10` fluff), keeps
a stempool, uses a 180-second embargo, checks it every 10 seconds, and aggregates
transactions before fluffing. Locally generated transactions always begin in
stem. Duplicate stem receipt/loops cause fluff
[Grin, *Dandelion++ in Grin: Privacy-Preserving Transaction Aggregation and
Propagation*, “Current implementation”](https://github.com/mimblewimble/grin/blob/master/doc/dandelion/dandelion.md).

Grin simplified the paper's graph: it uses a single outbound relay and a
2-regular construction rather than the proposed 4-regular graph. It also uses an
identical default embargo across nodes rather than the paper's randomized timer;
Grin documents that this makes the origin most likely to time out first during a
black-hole attack. Grin's extra aggregation delay is specific to Mimblewimble's
transaction aggregation/linkability objective, not a generally required part of
Dandelion++ [same Grin primary document, “Known limitations” and “Objectives”](https://github.com/mimblewimble/grin/blob/master/doc/dandelion/dandelion.md).

This is a better engineering analogue for a small v1 than copying the ideal
4-regular construction, but Grin still operates in a large open full-node network.
INDRA should copy neither Grin's fixed embargo (known origin leak) nor its
Mimblewimble aggregation delay.

### 6.3 Erlay: related bandwidth work, not the privacy design

Erlay combines fast low-fanout transaction flooding with periodic set
reconciliation across remaining links. Its primary result is reducing Bitcoin
transaction-relay bandwidth and making bandwidth grow slowly as connectivity
increases; the paper reports origin-inference hardening as a secondary effect of
lower fanout. It was designed around Bitcoin's large open network, typically
eight outbound connections, and reconciliation between mempool peers
[Naumenko et al., *Erlay: Efficient Transaction Relay for Bitcoin*, CCS 2019,
§§1, 4–6](https://arxiv.org/abs/1905.10518).

Erlay is a **false lead for the present privacy objective**. Low fanout can reduce
the number of first-hop spies, but it lacks a separate anonymity phase and does
not supply Dandelion++'s formal origin-anonymity model. Set reconciliation might
be valuable later if INDRA's transaction bandwidth becomes material, especially
as validator connectivity rises. With at most 200 authenticated validators and
no measured bandwidth problem in this audit, adding reconciliation would be a
larger protocol change that does not directly close the stated leak.

## 7. Gap analysis

Current INDRA has strong authenticated membership, per-identity rate limits,
bounded dedup, and multi-hop consensus relay. It lacks every transaction-specific
origin-privacy primitive:

* no stem/fluff wire state;
* no epoch-stable relay selection;
* no distinction between a locally entered and relayed transaction at the
  network-policy layer;
* no probabilistic transition to diffusion;
* no black-hole/loop fail-safe;
* no privacy metrics or simulation tied to validator-set size and adversarial
  fraction.

The validator-only topology changes both benefit and ceiling. Authentication
prevents cheap public Sybils, and `is_outbound` prevents an inbound connection
attacker from forcing itself into every relay choice. Conversely, at four
validators a one-hop or five-hop stem cannot create a large anonymity set; at 20,
50, 100, or 200 it may hide the entry among a useful subset only if enough
validators are honest and the connection graph has alternate paths.

Achievable: reduce other validators' confidence that the first validator they
heard from was the RPC entry, and remove the conspicuous all-neighbor burst from
the entry validator.

Not achievable here: hide the wallet endpoint from its RPC validator; defeat a
global passive observer; hide transaction contents after diffusion/on-chain;
hide vote/proposal authors; or promise paper-level anonymity without validating
INDRA's small, authenticated topology.

## 8. Recommended INDRA design (proposal, not decided configuration)

### 8.1 v1 state and flow

For accepted `Message::Tx` only:

1. Maintain a bounded transaction relay record keyed by canonical transaction ID:
   phase (`Stem`/`Fluff`), first sender if inbound, expiry, and peers forwarded to.
   Extend/reuse the `BoundedTtlSet`/`RelaySeenCache` bounded-TTL idiom rather than
   introducing unbounded per-transaction state.
2. At each relay epoch, derive/select one eligible `ManagedPeer` with
   `is_outbound == true`. Selection must be unpredictable to remote peers (local
   CSPRNG or keyed epoch derivation), stable throughout the epoch, and exclude
   self/banned/unavailable peers. Validator identity—not socket address—is the
   unit of choice.
3. A locally RPC-accepted transaction always starts in stem and is sent only to
   the current stem relay. This replaces the direct full broadcast at
   `node.rs:5410` conceptually; no code change belongs in this audit.
4. On a first, valid inbound stem transaction, choose independently for that
   transaction: with probability `q`, fluff and broadcast to every connected
   validator except the sender; otherwise forward to the epoch relay. Do not send
   it back to the sender. Per-transaction choice avoids an entire epoch's traffic
   becoming linkable to a node-wide stem/fluff mode.
5. On receiving the same transaction as fluff, mark it fluffed and cancel the
   embargo. On a stem loop/duplicate from a different path, fluff it to guarantee
   progress. Existing validation and rate limiting remain before forwarding.
6. Every node that stems the transaction installs a randomized embargo. If it has
   not observed fluff by expiry, it fluffs the transaction. This is essential
   against a malicious/failed next relay.
7. Add phase-aware counters and latency histograms without logging transaction ID
   plus peer address at ordinary log levels. Measure stem hops indirectly in
   tests/simulation, not by adding a globally traceable hop count to the wire.

A phase signal is required so recipients distinguish stem from diffusion. The
implementation design must decide whether that is a new message envelope/version
or a separate transaction relay command. It must not alter the signed transaction
or consensus transaction ID.

### 8.2 Proposed parameters and rationale

| Parameter | Proposed v1 value | Basis and deviation | Decision status |
|---|---:|---|---|
| Relay count | 1 outbound validator per epoch | Matches the practical Grin simplification. It minimizes first-hop exposure and directly uses `is_outbound`. Unlike the paper's 4-regular graph, INDRA may have too few peers for four independent privacy edges. | **Human approval required.** Simulate 1 versus 2 on actual target topology. |
| Relay epoch | 10 minutes, plus random startup/rotation jitter | Matches Grin's production default and the existing 10-minute relay/dedup TTL idiom. Long enough to resist per-transaction graph probing; short enough to rotate a compromised/failed choice. Jitter prevents synchronized network-wide rotation. | **Human approval required.** Confirm operational churn and link lifetime. |
| Fluff probability `q` | 0.20 provisional (80% continue stem) | At the upper edge of the Dandelion++ recommendation `q <= 0.2`, giving expected geometric stem length `1/q = 5` hops. This intentionally deviates from Grin's `q=0.10`/10 hops because INDRA's sets can be 4–20 during early deployment and extra hops increase loops/latency without creating new identities. | **Human approval required.** Validator-set-size simulation is gating evidence. |
| Local origin behavior | Always stem | Required by Dandelion++ and Grin; locally fluffing a fraction creates an immediately identifiable origin subset. | Recommended invariant. |
| Embargo distribution | Independent exponential/randomized deadline at every stem node; **no fixed common timeout** | Follows the Dandelion++ fail-safe principle and avoids Grin's documented fixed-timer weakness. | Distribution approved in principle; base value unresolved. |
| Embargo base | No final number in this audit; evaluate 30 s, 60 s, 120 s | The paper relates the base timeout to desired hop survival, hop delay, and failure probability. INDRA has no cited measured stem-hop latency here. Choosing one value now would be arbitrary. 30/60/120 s are experiment points, not defaults. | **Product/performance decision after measurement.** |
| Cache TTL/capacity | Start evaluation from existing 10 min / 16,384, but retain stem state at least through maximum embargo | Reuses existing bounds. Epoch duration alone is not sufficient if an embargo can outlive it. | Engineering validation required; not yet approved. |
| No eligible outbound peer | Either immediate fluff, or allow a deterministically selected authenticated inbound peer | Immediate fluff preserves latency but reveals the entry; inbound fallback preserves some privacy but weakens the outbound-selection defense. | **Human threat-model decision.** Recommended safe default is immediate fluff with a metric. |

Epoch selection and probabilistic fluff should use domain-separated randomness so
an observing validator cannot predict another node's future relay/mode from
public transaction IDs or validator IDs. “Similar to existing relay-fanout
patterns” means reuse bounded state, validator-key addressing, active-set refresh,
and epoch rotation; it must not reuse current public message-hash target ordering,
which is predictable (`indra-network/src/peer_manager.rs:627-639`).

### 8.3 Why consensus relay should remain separate

`Vote` and `Block` are latency-critical and signed by an explicit validator. The
current bounded fanout already provides scalable multi-hop diffusion on inbound
receipt, while local full broadcast prioritizes liveness. Adding a probabilistic
stem delay would not hide the payload author and could harm QC/proposal latency.
Keep `derive_consensus_relay_fanout` and `RelaySeenCache` behavior separate from
transaction origin privacy.

## 9. v1 scope, deferrals, and required human decisions

### v1 recommendation

* `Message::Tx` only.
* Validator gossip only; no observer-port change.
* No transaction aggregation.
* No change to transaction validation, IDs, consensus rules, or RPC authentication.
* Preserve immediate diffusion as an explicit failure fallback.

Transactions have the clearest wallet-to-validator ingress and the largest
expected traffic/anonymity set. Confining v1 permits latency/privacy measurement
without changing time-sensitive consensus propagation or low-frequency control
operations.

### Deferred

* `StakingOp` and `GovernanceOp`: structurally similar flood leak, but likely
  sparse and identity-linked by their signed semantics. Stem propagation may add
  latency with little anonymity set; decide after Tx evidence.
* `Vote` and `Block`: explicitly out of scope for the reasons in §8.3.
* Erlay/set reconciliation: defer until bandwidth measurements justify it.
* Client-to-validator privacy: separate Tor/I2P/proxy/RPC endpoint design.
* Multi-relay/4-regular anonymity graph: reconsider only if validator degree and
  set size support it.

### Decisions required before implementation

1. What validator-set sizes are launch, one-year, and mature operating targets?
   Report privacy results separately for 4, 20, 50, 100, and 200 validators.
2. What adversarial model should acceptance tests use: fraction of identities,
   fraction of stake, colluding infrastructure operators, passive AS observer,
   or some combination?
3. Must the design protect only against other validators, or also against a
   partial network observer capable of encrypted-flow fingerprinting?
4. Approve or reject the proposed one-relay, 10-minute, `q=0.20` profile after
   simulation. In particular, is expected five-hop latency acceptable?
5. What p50/p95 added submission-to-all-validators latency is acceptable?
6. Which embargo experiment point meets the black-hole success target without
   unacceptable confirmation latency? Define the target probability explicitly.
7. On zero outbound peers, should privacy yield to immediate propagation, or may
   an authenticated inbound peer be used?
8. Should staking/governance entry-validator privacy be a later requirement even
   though payload signers and low volume constrain their anonymity set?
9. Is validator-only gossip a stable roadmap invariant? If non-validator relay
   admission is planned, this threat model and topology design must be redone.
10. What telemetry is permissible? Origin-privacy diagnostics can themselves
    become correlation logs.

## 10. Acceptance evidence required for a later implementation task

Before enabling v1, produce an INDRA-specific simulator/model over real degree
distributions and the set sizes above. At minimum report first-spy precision and
recall, fraction fluffed by embargo, loop rate, propagation coverage, and p50/p95/
p99 latency for `q` in `{0.10, 0.15, 0.20}`, relay count in `{1,2}`, and embargo
experiment points `{30,60,120}` seconds. Include colluding-validator placement on
inbound/outbound edges and partial/global passive observers.

Tests must prove: local origin never directly floods while a valid stem relay is
available; inbound stem never returns to sender; fluff reaches all connected
peers subject to queues; duplicate/loop causes safe progress; black-hole timeout
works; epoch rotation does not lose transactions; active-set/connection churn is
safe; cache bounds hold; rate limits cannot be bypassed by phase changes; and the
zero-outbound fallback matches the approved product policy.

## 11. Final assessment

INDRA has a real origin-correlation gap, but its scope must be stated narrowly.
Today, transaction flooding identifies the likely RPC-entry validator. A
Dandelion++-inspired stem phase can make that inference materially harder inside
the validator mesh. It cannot make the wallet anonymous to its chosen RPC
validator, and the small authenticated mesh prevents importing anonymity numbers
from large open networks.

Proceed only after the human decisions and topology-specific simulation above.
The smallest coherent v1 is transaction-only, one epoch-stable outbound relay,
probabilistic fluff, and a randomized fail-safe—built from INDRA's existing
validator identity, direction, bounded-cache, and rotation idioms.
