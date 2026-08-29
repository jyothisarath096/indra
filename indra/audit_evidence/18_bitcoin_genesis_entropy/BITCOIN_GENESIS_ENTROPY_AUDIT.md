# INDRA Layer 2 Phase 9 — Bitcoin genesis entropy audit

Date: 2026-08-18  
Base revision: `b6404ccacc508d92a022f50ad1af3da4d4e31a02` plus the pre-existing
uncommitted audit worktree; production code was not changed by this phase.  
Result: **one ceremony-integrity finding**. The cryptographic binding after a
descriptor is fixed is sound, but the assembly workflow does not establish that
the descriptor was published before the selected Bitcoin block existed.

## Executive classification

| Area | Class | Conclusion |
|---|---|---|
| Precommitment integrity | **FINDING** | The spec requires a public pre-block commitment, but the CLI accepts height and header together and records no prior commitment. An operator can construct several otherwise-valid manifests from already-mined heights, then publish the preferred one. |
| Target-block uniqueness | **PASS, conditional** | Given a fixed descriptor and a Bitcoin node's active chain, `getblockhash(height)` selects one block; the exact 80-byte header is checked. |
| No-fallback behavior | **PASS in code; operational policy only for disappearance/reorg** | Build/verify fails on RPC, header, network or depth failure. No alternate source/current-tip/RNG/cached-block fallback was found. The prescribed wait/restart behavior exists in the spec, not an automated state machine. |
| Confirmation-depth enforcement | **PASS with qualification** | The protocol enforces a floor `>=100`, then enforces the descriptor's declared value. It does **not** require exactly 100; mainnet may select a larger depth without a protocol version change. |
| Reorg resistance structure | **PASS, conditional** | Active-most-work membership and depth are delegated to the configured fully validating Bitcoin Core node; the header/fingerprint binding is local and deterministic. Economic sufficiency is separate. |
| Miner grinding resistance | **OPEN** | Grinding is bounded exponentially in desired bits, but 1–2 bit selection costs only 1 or 3 expected discarded valid blocks for a miner who controls the target-height race. Economic acceptability needs current external inputs. |
| Ceremony preannouncement | **FINDING** | No minimum future-height distance, timestamped commitment artifact, or CLI workflow enforces the required ordering. |
| Current economic sufficiency | **OPEN** | Current hash rate, reward, pool concentration, rental liquidity, bribery cost, and value at risk are intentionally absent. |

The critical-stop condition is met in a precise operational sense: absent an
external public precommitment, the current tool permits post-observation source
selection. This report preserves that finding and proposes no remediation.

## 1. Exact production ceremony and transcripts

### Manifest and canonical descriptor

`GenesisSettings` requires chain ID, the fixed mainnet active-slot numerator,
one `BitcoinPowEntropySourceV1`, and the source header
([`indra-node/src/genesis.rs:42`](../../indra-node/src/genesis.rs#L42)). The
descriptor fields and exact canonical byte sequence are
([`indra-node/src/genesis.rs:73`](../../indra-node/src/genesis.rs#L73),
[`indra-node/src/genesis.rs:93`](../../indra-node/src/genesis.rs#L93)):

```text
offset  width  field
0       1      scheme = 1
1       32     network_genesis_hash (raw digest order)
33      8      announced_height, u64 little-endian
41      1      header_codec = 1 (Bitcoin 80-byte header)
42      1      extraction_algorithm = 1 (double SHA-256)
43      4      minimum_confirmations, u32 little-endian, >=100
47      1      reorg_policy = 1 (same-height/restart)
```

All enum values are exact; depth below 100 is rejected. Text hex must be
lowercase canonical hex ([`indra-node/src/genesis.rs:378`](../../indra-node/src/genesis.rs#L378)).
Manifest validation invokes seed derivation, so descriptor validation is not
optional ([`indra-node/src/genesis.rs:214`](../../indra-node/src/genesis.rs#L214)).

### Entropy and identity derivations

Exact transcripts from [`indra-node/src/genesis.rs:118`](../../indra-node/src/genesis.rs#L118):

```text
descriptor = the 48 bytes above
header     = exactly 80 consensus-serialized Bitcoin header bytes

entropy_record_hash = SHA256(
  ASCII("INDRA-GENESIS-ENTROPY-RECORD-v1") || descriptor || header)

source_id = SHA256(
  ASCII("INDRA-EXTERNAL-ENTROPY-SOURCE-ID-v1") || descriptor)

external_entropy_value = SHA256(SHA256(header))   // raw digest order

election_seed[0] = SHA512(
  ASCII("INDRA-GENESIS-ELECTION-SEED-v1") ||
  UTF8(chain_id) || source_id[32] || external_entropy_value[32])
```

The source/header record hash and seed enter chain state at load
([`indra-node/src/genesis.rs:570`](../../indra-node/src/genesis.rs#L570)). The
genesis fingerprint then binds a length-prefixed chain ID, state root, snapshot
root, monetary ledger encoding, election seed and entropy-record hash
([`indra-node/src/genesis.rs:395`](../../indra-node/src/genesis.rs#L395)). The
height-zero header uses that fingerprint as `value_hash` and includes the seed
([`indra-node/src/genesis.rs:414`](../../indra-node/src/genesis.rs#L414)). The P2P
preface transmits chain ID plus fingerprint and rejects disagreement before the
authenticated transport exchange ([`indra-network/src/handshake.rs:81`](../../indra-network/src/handshake.rs#L81),
[`indra-network/src/handshake.rs:109`](../../indra-network/src/handshake.rs#L109)).

Thus changing the network, height, codec, extraction, depth, policy or header
changes the entropy record and fingerprint. It cannot silently preserve public
INDRA chain identity.

### Tool flow

`indra-genesis build` requires the source network hash, height, header, depth and
Bitcoin CLI path at the same invocation
([`indra-cli/src/bin/genesis.rs:79`](../../indra-cli/src/bin/genesis.rs#L79)). It:

1. asks Bitcoin Core for the active-chain hash at the supplied height;
2. asks for that block's raw header and requires exact equality;
3. locally double-hashes the 80 bytes and checks the displayed hash;
4. checks `getblockhash 0` against the raw network genesis digest;
5. calculates confirmations as `tip-height+1` and enforces the descriptor value;
6. only then writes a new manifest, refusing overwrite.

The checks are at [`indra-cli/src/bin/genesis.rs:180`](../../indra-cli/src/bin/genesis.rs#L180).
`verify-bitcoin-entropy` repeats them for an existing manifest
([`indra-cli/src/bin/genesis.rs:224`](../../indra-cli/src/bin/genesis.rs#L224)).
Bitcoin Core defines `getblockhash` as the hash in the best chain at a supplied
height; this matches the implementation's reliance on the configured node
([Bitcoin Core RPC documentation](https://bitcoincore.org/en/doc/26.0.0/rpc/blockchain/getblockhash/)).

### Timeline: fact versus intended ceremony

| Time | Intended fixed facts | Newly known | Remaining operator choice |
|---|---|---|---|
| Before target exists | Public descriptor and chain ID; validator VRF keys not yet finalized | No target header | Select a genuinely future height and depth; publish commitment |
| Target mined | Descriptor remains fixed | Exact canonical block/header and raw digest | No block/source choice; wait |
| Confirmations accumulate | Same descriptor/header candidate | Active-chain survival and tip | No depth reduction; abort/restart at same height if reorg |
| Genesis assembly | All above fixed | Final roots/fingerprint | Assemble only that record, finalize validator material |
| After launch | Fingerprint immutable | Later reorgs/incidents | No genesis rewrite |

The code enforces the right-hand binding **after assembly**, but does not enforce
the first row. The specification explicitly requires the commitment before VRF
key finalization and prohibits post-observation changes
([`docs/PROPOSER_AUTHORIZATION_VRF_DESIGN_SPEC.md:645`](../../docs/PROPOSER_AUTHORIZATION_VRF_DESIGN_SPEC.md#L645),
[`docs/PROPOSER_AUTHORIZATION_VRF_DESIGN_SPEC.md:658`](../../docs/PROPOSER_AUTHORIZATION_VRF_DESIGN_SPEC.md#L658)).

## 2. Precommitment attack surface

| Operator action after observing blocks | With a witnessed descriptor commitment | Current CLI by itself |
|---|---|---|
| Change announced height / choose another block | **IMPOSSIBLE AFTER COMMITMENT** without a detectable new descriptor | **POSSIBLE** before publishing the final manifest |
| Change Bitcoin network | **POSSIBLE BUT DETECTABLE**; network genesis/source ID/fingerprint change | **POSSIBLE** before publication |
| Change header codec or extraction algorithm | **IMPOSSIBLE AFTER COMMITMENT**; only enum 1 validates | Not selectable to another supported value |
| Reduce depth below 100 | **IMPOSSIBLE**; validation rejects | **IMPOSSIBLE** |
| Change 100 to a larger depth | **POSSIBLE BUT DETECTABLE**; descriptor/fingerprint change | **POSSIBLE** before publication |
| Change reorg policy | **IMPOSSIBLE AFTER COMMITMENT**; only enum 1 validates | Not selectable to another supported value |
| Regenerate genesis around another source | **POSSIBLE BUT DETECTABLE**; creates another fingerprint/chain | **POSSIBLE** before anyone anchors which fingerprint is authoritative |

**Smallest preserved reproducer (source-level):** choose two already-mined heights
`H1,H2`; obtain each active-chain header and sufficient confirmations; invoke the
documented build command twice with otherwise identical inputs. Both pass
`verify_bitcoin_entropy`; their descriptor/source ID/seed/fingerprint differ. The
operator can inspect both seeds and publish one. The CLI has no precommitment
input, timestamp check, minimum lead distance, or record linking either build to
an earlier publication. No live Bitcoin endpoint was needed to establish this
reachability; the required CLI dataflow is explicit at lines 88–140 above.

This is detectable **after** a public descriptor exists, not preventable by the
eventual genesis fingerprint alone. Detection is meaningful only if auditors
possess the earlier commitment.

## 3. Failure and no-fallback matrix

| Event | Actual behavior |
|---|---|
| Target block delayed | Build cannot supply a matching active-chain header. Spec says wait; no alternate-height code exists. |
| Bitcoin RPC unavailable/operator disappears | command fails; no manifest written. No automatic replacement operator/source exists. |
| Reorg before 100/declaration depth | Existing header stops matching `getblockhash(height)` and verification fails. Spec requires the new block at the same height and restarts depth. |
| Reorg after depth but before launch | Reverification detects changed active-chain header. Spec mandates abort/rebuild at same height. |
| Reorg after launch | INDRA fingerprint remains immutable; operational incident only. Consensus does not follow Bitcoin. |
| Malformed/wrong header | canonical hex/80-byte/local double-hash/exact RPC-header checks fail. |
| Wrong network | `getblockhash 0` raw digest check fails. |

No code path was found for current tip, another height, local RNG, reduced depth,
or cached stale header. Reorg handling is fail-closed but manual: there is no
persisted ceremony state machine automatically proving that operators followed
the same-height restart rule.

## 4. Confirmation rule and trusted PoW object

The protocol law is **a configurable committed depth with a hard floor of 100**,
not exact equality. `minimum_confirmations=101` is valid and changes descriptor,
seed and fingerprint; `99` is invalid. Mainnet can therefore choose a larger
depth at ceremony time without a new protocol version, but cannot silently lower
it after publication.

INDRA stores and commits the raw 80-byte header. That includes version, previous
block hash, Merkle root, timestamp, compact target and nonce. It also derives and
commits the raw double-SHA-256 block-header hash. It does **not** store the full
block, transactions, an ancestry proof, a chainwork value, or a sequence of
headers. Locally it validates byte length, header hash and configured network
genesis. Proof-of-work validity, ancestry and active-most-work-chain membership
are delegated to the configured Bitcoin Core node via `getblockhash`; the tool
does not call `getblockchaininfo`, inspect chainwork, or independently validate
the target encoded in `bits`. This is consistent with the spec's declared
operational gate ([spec lines 647–652](../../docs/PROPOSER_AUTHORIZATION_VRF_DESIGN_SPEC.md#L647)),
but requires trustworthy independent full nodes at ceremony time.

## 5. Reorg model

Let `q` be attacker hash fraction, `p=1-q`, and `z` the block deficit. In the
ideal independent equal-difficulty random-walk model, eventual catch-up is:

```text
P_catch(z,q) = (q/p)^z, q < 1/2
             = 1,       q >= 1/2.
```

The Bitcoin-paper Poisson approximation additionally accounts for attacker
blocks privately found while honest miners accumulate `z` confirmations:

```text
lambda = z*q/p
P = 1 - sum(k=0..z) Poisson(lambda,k) * (1 - min(1,(q/p)^(z-k))).
```

Both are generated exactly/high-precision by `symbolic_attack_model.py` for
depths 1, 6, 20, 50 and 100. With equal per-block work, replacing a branch of `z`
blocks requires at least `z+1` attacker blocks to have strictly more accumulated
work. Expected time to find those blocks at fixed difficulty is
`(z+1)*tau/q`, where `tau` is the baseline whole-network expected block interval;
mean-time statements do not bound lucky tails.

Limitations: Bitcoin selects accumulated work, not block count; difficulty can
vary; propagation, selfish mining, timestamp rules, pool behavior and stopping
strategies violate the simple random-walk assumptions; the Poisson expression is
not an economic-cost proof. One hundred confirmations is a structural floor, not
deterministic finality. Bitcoin's own whitepaper describes the exponential decay
with confirmations ([Bitcoin whitepaper](https://bitcoin.org/bitcoin.pdf)).

## 6. Target-block miner grinding

The entropy is the entire header hash, so changing nonce, timestamp, coinbase or
extranonce (through the Merkle root), transaction set/order, or permitted version
bits supplies new header candidates. These are normal mining degrees of freedom;
they do not give free selection among **valid published blocks**. To select `b`
desired predicate bits, a miner must reject valid blocks that fail the predicate.

Under independent uniform hashes:

```text
favorable probability per valid block = 2^-b
expected valid finds                  = 2^b
expected discarded valid blocks       = 2^b - 1
```

| desired bits | expected finds | expected discarded valid blocks |
|---:|---:|---:|
| 1 | 2 | 1 |
| 2 | 4 | 3 |
| 4 | 16 | 15 |
| 8 | 256 | 255 |

If the attacker has hash fraction `q` and honest miners publish any valid block,
the attacker's favorable-block process has rate `q/2^b`; the probability it wins
the target-height race is:

```text
q / (2^b*(1-q) + q).
```

This selection is exponentially costly, so no unexpectedly cheap multi-bit
mechanism was found. Nevertheless, one-bit bias is not cryptographically
negligible: it costs one expected foregone block conditional on the attacker
being able to keep competing. Whether even that is rational requires the current
block reward, fees, q, bribery market and INDRA value at risk. Pool bribery,
rented hash, pool coordination and Bitcoin consensus exploits are external
capability/economic assumptions, not repository facts.

Private mining/reorg attacks change Bitcoin canonical history and INDRA entropy
if successful before launch. Target-miner withholding changes which Bitcoin block
becomes canonical and therefore both histories. After INDRA launch, a Bitcoin
reorg changes Bitcoin history only; INDRA genesis is fixed.

## 7. Ceremony timing and independent verification

No code or normative document specifies a minimum number of Bitcoin blocks or a
minimum wall-clock interval between descriptor publication and target height.
The spec only says “future” and “before validator VRF keys are finalized.” This is
a **FINDING**, because a just-in-time or post-hoc publication defeats public
observability and makes source selection indistinguishable from compliance.

The concrete independent procedure is in `CEREMONY_CHECKLIST.md`. At minimum an
auditor must verify the Bitcoin network genesis, target height/header/hash,
active-chain membership, confirmation count, tip/chainwork, descriptor and
entropy derivations, and final INDRA fingerprint. Multiple independently operated
fully validating nodes are required by the design; trusting a single hosted RPC
is a weaker operational assumption.

## 8. External-data boundary

`external_inputs.json` lists every unavailable current input. In particular,
this audit makes no present-day dollar-cost claim. `attack_model_results.csv`
contains only explicit symbolic/model inputs and reproducible calculated values.
Accordingly, **current economic sufficiency remains OPEN**.

## 9. Reproduction and validation

```bash
python3 audit_evidence/18_bitcoin_genesis_entropy/symbolic_attack_model.py
cargo test --workspace --no-run
git diff --check
```

The model writes 30 reorg rows and 20 target-grinding rows. Decimal precision is
100 digits; no external data or Monte Carlo randomness is used.
