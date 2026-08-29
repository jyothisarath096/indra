# Domain-separation matrix

All tags were compared literally. Every off-diagonal entry is byte-distinct.

| Domain | Sortition | Seed | Entropy commit | Proposal auth | VRF PoP | Snapshot | Genesis record | Genesis seed | Genesis fingerprint | Staking |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `INDRA-PROPOSER-SORTITION-v2` | self | distinct | distinct | distinct | distinct | distinct | distinct | distinct | distinct | distinct |
| `INDRA-ELECTION-SEED-v2` | distinct | self | distinct | distinct | distinct | distinct | distinct | distinct | distinct | distinct |
| `INDRA-PROPOSAL-ENTROPY-COMMIT-v1` | distinct | distinct | self | distinct | distinct | distinct | distinct | distinct | distinct | distinct |
| `INDRA-PROPOSAL-AUTH-v1` | distinct | distinct | distinct | self | distinct | distinct | distinct | distinct | distinct | distinct |
| `INDRA-VRF-KEY-POSSESSION-v1` | distinct | distinct | distinct | distinct | self | distinct | distinct | distinct | distinct | distinct |
| `INDRA-CONSENSUS-SNAPSHOT-v1` | distinct | distinct | distinct | distinct | distinct | self | distinct | distinct | distinct | distinct |
| `INDRA-GENESIS-ENTROPY-RECORD-v1` | distinct | distinct | distinct | distinct | distinct | distinct | self | distinct | distinct | distinct |
| `INDRA-GENESIS-ELECTION-SEED-v1` | distinct | distinct | distinct | distinct | distinct | distinct | distinct | self | distinct | distinct |
| `INDRA-GENESIS-FINGERPRINT-v1` | distinct | distinct | distinct | distinct | distinct | distinct | distinct | distinct | self | distinct |
| `INDRA_STAKING_V2` | distinct | distinct | distinct | distinct | distinct | distinct | distinct | distinct | distinct | self |

Also distinct:

```text
INDRA-EXTERNAL-ENTROPY-SOURCE-ID-v1
INDRA-validator-hot-auth-v1
INDRA-validator-cold-auth-v1
INDRA-register-validator-payload-v1
INDRA-register-validator-dual-authorization-v1
INDRA-rotate-validator-cold-key-payload-v1
INDRA-rotate-validator-cold-key-dual-authorization-v1
```

The sole deliberate reuse is `INDRA-VRF-KEY-POSSESSION-v1` across initial,
genesis, and rotated VRF-key registration. These invoke one semantic proof
protocol and identical grammar. Activation epoch 0 denotes initial registration;
a required future snapshot epoch denotes rotation. The PoP grants no state
authorization: a separately domain-separated, operation-tagged, hybrid-signed
staking envelope authorizes the mutation.
