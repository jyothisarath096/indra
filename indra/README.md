# INDRA Protocol

**Quantum-safe digital money. Earned, not issued.**

INDRA is a post-quantum Layer 1 blockchain written in Rust. It implements
ML-DSA-87 + Ed25519 hybrid signatures, hybrid X25519 + ML-KEM-1024
encrypted transport, confidential transactions via Pedersen commitments
and Bulletproof range proofs, BFT consensus with 6-second absolute
finality, and on-chain five-phase commit-reveal governance.

One billion INDRA. No new coins ever. No foundation. No pre-mine.

→ **[indraprotocol.com](https://indraprotocol.com)**
→ **[Whitepaper](docs/WHITEPAPER.md)**
→ **[Testnet RPC](https://rpc.indraprotocol.com)**

---

## Key properties

```
Hard cap:         1,000,000,000 INDRA (immutable)
Decimals:         8 (1 INDRA = 100,000,000 Spark)
Block time:       6 seconds
Finality:         Instant (BFT — no forks possible)
Tx signatures:    Ed25519 + ML-DSA-87 (NIST FIPS 204, level 5)
QC signatures:    ML-DSA-87 only (fully post-quantum)
Transport:        X25519 + ML-KEM-1024 + ChaCha20-Poly1305 + ML-DSA-87
Transactions:     Confidential (Pedersen commitments + Bulletproofs)
Era 1 reward:     11.892 INDRA/block (Year 1–4)
Fee split:        50% burned / 50% to validators
Consensus:        Proof of Stake (Tendermint-style BFT)
Governance:       Five-phase commit-reveal, two-snapshot, on-chain
Language:         Rust
```

---

## Repository structure

```
indra/
├── indra-core/           Types, codec, primitives, protocol constants
├── indra-crypto/         ML-DSA-87, Ed25519, ML-KEM-1024, VRF, Pedersen
├── indra-bulletproofs/   Range proof implementation
├── indra-state/          State machine, UTXO set, epoch logic, governance
├── indra-consensus/      BFT consensus, mempool, proposer election
├── indra-network/        P2P networking, gossip, observer protocol
├── indra-storage/        Block store, state snapshots, epoch history, migration
├── indra-node/           Node binary, engine, RPC dispatch
├── indra-rpc/            JSON-RPC 2.0 server and handlers
├── indra-cli/            CLI tools (stake, governance, keygen, send, wallet-scan)
├── indra-ffi/            C FFI bridge for iOS/Android wallets
└── indra-bench/          Benchmarks
```

---

## Prerequisites

```bash
# Rust stable 1.75+
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustc --version
cargo --version
```

---

## Build

```bash
git clone https://github.com/jyothisarath096/indra
cd indra
cargo build --release
```

---

## Test

```bash
# Full test suite (662 tests, zero failures)
cargo test --workspace --exclude indra-ffi

# Single crate
cargo test -p indra-state
cargo test -p indra-consensus

# Lint
cargo clippy --workspace -- -D warnings
```

---

## Running a validator node

### 1. Generate keys

```bash
cargo run -p indra-cli --bin indra-keygen --release -- \
  --name yourname \
  --output ~/.indra/data/keys.json
```

Your `keys.json` contains your validator identity, ML-DSA-87 and Ed25519
public keys, ML-DSA-87 secret key, and Ed25519 seed. Keep it secure.

### 2. Generate config

```bash
cargo run -p indra-node --bin node --release -- --init
```

This interactively generates `~/.indra/data/config.toml`.

### 3. Start the node

```bash
cargo run -p indra-node --bin node --release -- \
  --config ~/.indra/data/config.toml
```

The node starts:
- P2P on port 30303 (validator gossip)
- Observer on port 30304 (public sync)
- JSON-RPC on port 8545
- Prometheus metrics on port 9615

### 4. Check node status

```bash
curl -s http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"indra_getChainInfo","params":[],"id":1}'
```

---

## Staking operations

```bash
# Register as a validator
indra-stake register --keys ~/.indra/data/keys.json --commission 1000

# Self-stake a UTXO
indra-stake self-stake --keys ~/.indra/data/keys.json --utxo <utxo_id>

# Delegate to a validator
indra-stake delegate --keys ~/.indra/data/keys.json \
  --validator <validator_id> --utxo <utxo_id>

# Claim rewards
indra-stake claim-rewards --keys ~/.indra/data/keys.json

# Set auto-delegation target (for validators outside the active set)
indra-stake auto-delegate --keys ~/.indra/data/keys.json \
  --target <validator_id>

# View all subcommands
indra-stake --help
```

---

## Governance

```bash
# Submit a governance proposal
indra-governance propose \
  --action SetSlashLivenessBps --value 8 \
  --title "Reduce liveness penalty" \
  --description "Reduce from 10 BPS to 8 BPS to be less punitive" \
  --deposit-utxo <utxo_id> \
  --keys ~/.indra/data/keys.json

# Commit a hidden vote (Phase 2)
indra-governance commit \
  --proposal <proposal_id> --vote yes \
  --keys ~/.indra/data/keys.json
# Nonce saved to ~/.indra/gov_nonces/<proposal_id>.json

# Reveal your vote (Phase 3)
indra-governance reveal \
  --proposal <proposal_id> \
  --keys ~/.indra/data/keys.json

# Redelegate vote weight (Phase 3 only, delegators only)
indra-governance redelegate \
  --proposal <proposal_id> \
  --from <validator_id> --to <validator_id> \
  --amount 100000000000 \
  --keys ~/.indra/data/keys.json

# Execute a passed proposal (after delay)
indra-governance execute \
  --proposal <proposal_id> \
  --keys ~/.indra/data/keys.json

# List proposals and governance parameters
indra-governance list
indra-governance params

# View all subcommands
indra-governance --help
```

---

## Sending transactions

```bash
# Scan for UTXOs
indra-wallet-scan \
  --keys ~/.indra/data/keys.json \
  --wallet ~/.indra/wallet.json \
  --node http://127.0.0.1:8545

# Send INDRA
indra-send \
  --keys ~/.indra/data/keys.json \
  --wallet ~/.indra/wallet.json \
  --to <recipient_classical_pk_hex> \
  --amount 1.0 \
  --node http://127.0.0.1:8545
```

---

## JSON-RPC reference

All endpoints accept JSON-RPC 2.0 POST to `http://node:8545`.

**Chain**
| Method | Description |
|--------|-------------|
| `indra_getChainInfo` | Height, epoch, era, supply, validators, fees |
| `indra_getBlock` | Full block by height |
| `indra_getTip` | Current tip hash and height |
| `indra_getMempoolSize` | Pending transaction count |
| `indra_getPeers` | Connected peers |

**Validators**
| Method | Description |
|--------|-------------|
| `indra_getValidatorSet` | All active validators |
| `indra_getValidator` | Single validator by ID |
| `indra_getValidatorSelfStake` | Self-stake bonds |
| `indra_getValidatorDelegators` | All delegators to a validator |
| `indra_getValidatorAutoDelegate` | Auto-delegation target |

**Delegation**
| Method | Description |
|--------|-------------|
| `indra_getDelegatorPositions` | All positions across all validators |
| `indra_getDelegatorRewards` | Pending rewards across all validators |
| `indra_getDelegations` | Delegations to a specific validator |

**Epoch history**
| Method | Description |
|--------|-------------|
| `indra_getEpochRecord` | Full record for one epoch |
| `indra_getEpochHistory` | Paginated epoch summaries |
| `indra_getLatestEpoch` | Most recently completed epoch |

**Governance**
| Method | Description |
|--------|-------------|
| `indra_getGovernanceParams` | Current governable parameters |
| `indra_getProposals` | All active and recent proposals |
| `indra_getProposal` | Full proposal detail by ID |
| `indra_getProposalVotes` | Per-validator vote breakdown |
| `indra_getGovernanceNonce` | Replay-protection nonce |
| `indra_submitGovernanceOp` | Submit a governance operation |

**Schema**
| Method | Description |
|--------|-------------|
| `indra_getSchemaInfo` | Schema version and migration history |

**Wallet**
| Method | Description |
|--------|-------------|
| `indra_getBalance` | UTXO balance for an address |
| `indra_getUtxos` | UTXOs for an address |
| `indra_sendTransaction` | Submit a signed transaction |
| `indra_submitStakingOp` | Submit a staking operation |
| `indra_getStakingNonce` | Replay-protection nonce for staking |

---

## Token economics

```
Total supply:      1,000,000,000 INDRA (hard cap, immutable)
Pre-mine:          None. 0% to founders, team, or foundation.
Distribution:      100% earned via block rewards over ~100 years

Era 1 (Yr 1–4):   11.892 INDRA/block   ~250,000,000 INDRA total
Era 2 (Yr 4–8):    5.946 INDRA/block   ~125,000,000 INDRA total
Era 3 (Yr 8–16):   2.973 INDRA/block   ~125,000,000 INDRA total
Era 4+:            Halves every 8 years

Fee split:         50% burned / 50% to validators (proportional to stake)
Supply direction:  Decreasing over time (fee burn)
```

---

## Post-quantum security

| Component | Scheme | Quantum-safe |
|-----------|--------|--------------|
| Transaction signatures | Ed25519 + ML-DSA-87 | Yes (hybrid) |
| QC finality proofs | ML-DSA-87 only | Yes |
| Validator transport | X25519 + ML-KEM-1024 | Yes (hybrid) |
| Block hashing | SHA-256 | Partial (Grover) |
| Amount hiding | Ristretto255 / Pedersen | No (acknowledged) |

Transaction ownership and consensus finality are fully post-quantum.
Amount confidentiality uses classical cryptography — documented in the
[whitepaper](docs/WHITEPAPER.md) Section 7.3.

---

## Governance

INDRA uses five-phase commit-reveal on-chain governance:

```
Phase 1  Deliberation   30 epochs   Proposal published, community discusses
Phase 2  Commit         20 epochs   Validators submit hidden vote hash
Phase 3  Reveal         10 epochs   Votes revealed, delegators can redelegate
Phase 4  Tally           1 epoch    Automatic count with two-snapshot weights
Phase 5  Exec delay    100 epochs   Queued parameter change, auto-executes
```

Monetary parameters (hard cap, era rewards) and safety parameters
(consensus quorum) are permanently immutable regardless of governance.

See [whitepaper Section 6](docs/WHITEPAPER.md) for full governance specification.

---

## Testnet

```
Chain ID:    indra-testnet-1
RPC:         https://rpc.indraprotocol.com
P2P:         116.203.185.28:30303
Observer:    116.203.185.28:30304
Explorer:    https://indraprotocol.com/#explorer
Schema:      v3
```

Genesis validators:

| Name | Validator ID |
|------|-------------|
| buddhi | `8b06a9b0e9e883828ad7f9492060247b068c1530098d409a6f12b81eca4cf490` |
| bonkai | `7cf530e0d358a41cc86cb0026c33f4f796af0947dbd2e1c694586559d9918839` |
| siddhi | `3e202b95d9b98b695580272b102c5c040ada5d9a4330eb03aa8971a02c29b4a7` |
| kushal | `458c74da954351ddd15cf906f5cd1bf7cc9fd994f9b026c8ce788b8aa8120d29` |

---

## iOS wallet

Native iOS wallet at [github.com/jyothisarath096/indra-ios](https://github.com/jyothisarath096/indra-ios).
Built with SwiftUI. Uses `indra-ffi` via XCFramework for ML-DSA-87 key
generation and signing. Keys stored in iOS Keychain.

---

## Security

Found a vulnerability? Do not open a public issue.
Email: security@indraprotocol.com

A professional third-party security audit is planned before mainnet.
The audit report will be published in full.

---

## Contributing

1. Open an issue before large changes
2. Follow existing code style (`cargo clippy --workspace`)
3. Add tests for new functionality
4. All tests must pass: `cargo test --workspace --exclude indra-ffi`

---

## Licence

Apache 2.0 — see [LICENSE](LICENSE)

---

Website: [indraprotocol.com](https://indraprotocol.com)
Whitepaper: [docs/WHITEPAPER.md](docs/WHITEPAPER.md)
GitHub: [github.com/jyothisarath096/indra](https://github.com/jyothisarath096/indra)
