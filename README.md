
# INDRA Protocol

**Quantum-safe digital money. Earned, not issued.**

INDRA is a post-quantum Layer 1 blockchain written in Rust. It implements
Dilithium2 + Ed25519 hybrid signatures, confidential transactions via
Pedersen commitments and Bulletproof range proofs, and BFT consensus
with 6-second absolute finality.

One billion INDRA. No new coins ever. Governed by consensus, not administrators.

---

## Key properties

Hard cap:         1,000,000,000 INDRA (immutable)

Decimals:         8 (1 INDRA = 100,000,000 Spark)

Block time:       6 seconds

Finality:         Instant (BFT — no forks possible)

Signatures:       Ed25519 + Dilithium2 (NIST FIPS 204)

Transactions:     Confidential (Pedersen commitments + Bulletproofs)

Block reward:     ~11.29 INDRA/block (Era 1, Year 1-4)

Fee split:        50% burned / 50% to validators

Consensus:        Proof of Stake (Tendermint-style BFT)

Language:         Rust


---

## Repository structure

indra/
├── indra-core/          # Types, codec, primitives, protocol constants

├── indra-crypto/        # Ed25519, Dilithium2, BLS, VRF, Pedersen

├── indra-bulletproofs/  # Range proof implementation (dalek 4.x)

├── indra-state/         # State transitions, UTXO set, epoch logic

├── indra-consensus/     # BFT consensus, mempool, proposer election

├── indra-network/       # P2P networking, gossip protocol

├── indra-storage/       # Block store, WAL, state snapshots

├── indra-node/          # Node binary, engine, RPC handler

├── indra-rpc/           # JSON-RPC server

├── indra-cli/           # CLI tools (keygen, send, wallet-scan)

├── indra-ffi/           # C FFI bridge for iOS/Android wallets

└── indra-bench/         # Benchmarks


---

## Prerequisites

```bash
# Rust (stable, 1.75+)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Verify
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
# Full test suite (35 suites, should be zero failures)
cargo test

# Specific crate
cargo test -p indra-state
cargo test -p indra-crypto
cargo test -p indra-consensus

# Lint
cargo clippy -- -D warnings
```

---

## Running a validator node

### 1. Generate keys

```bash
cargo run -p indra-cli --bin indra-keygen -- \
  --passphrase "your-secure-passphrase" \
  --output keys.json
```

Your `keys.json` contains:
- `validator_id` — your on-chain identity (SHA-256 of Ed25519 public key)
- `hybrid_classical_pk` — Ed25519 public key
- `hybrid_pq_pk` — Dilithium2 public key  
- `pq_sk` — Dilithium2 secret key (keep secret)
- `hybrid_seed` — Ed25519 seed (keep secret)

### 2. Start the node

```bash
cargo run -p indra-node --bin node --release -- \
  --keys keys.json \
  --genesis genesis.toml \
  --data-dir ~/.indra-data \
  --p2p-addr 0.0.0.0:30303
```

The node starts:
- P2P listener on port 30303
- JSON-RPC on port 8545

### 3. Check node status

```bash
curl -s -X POST http://127.0.0.1:8545 \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"indra_getChainInfo","params":[],"id":1}'
```

---

## Sending a transaction

### 1. Scan for your UTXOs

```bash
cargo run -p indra-cli --bin indra-wallet-scan -- \
  --keys keys.json \
  --wallet wallet.json \
  --node http://127.0.0.1:8545
```

### 2. Send INDRA

```bash
cargo run -p indra-cli --bin indra-send -- \
  --keys keys.json \
  --wallet wallet.json \
  --to <recipient_classical_pk_hex> \
  --amount 1.0 \
  --fee 0.001 \
  --node http://127.0.0.1:8545
```

---

## RPC endpoints

All endpoints accept JSON-RPC 2.0 POST requests to `http://node:8545`.

| Method | Description |
|--------|-------------|
| `indra_getChainInfo` | Height, epoch, supply, fee, validators |
| `indra_getHeight` | Current block height |
| `indra_getTip` | Latest block hash |
| `indra_getValidatorSet` | Active validators with stake and commission |
| `indra_getMempoolSize` | Pending transaction count |
| `indra_getUtxos` | UTXOs owned by a public key |
| `indra_getBalance` | UTXO count for a public key |
| `indra_sendTransaction` | Submit a signed transaction |

---

## Economics (v7.1)

Total supply:      1,000,000,000 INDRA (hard cap, immutable)
Distribution:      95% earned via block rewards (~100 years)
5% operational bootstrap (Foundation, 6-year vest)
Block rewards:
Era 1 (Yr 1-4):  ~11.29 INDRA/block
Era 2 (Yr 4-8):  ~5.64 INDRA/block
Era 3 (Yr 8-16): ~2.82 INDRA/block
Era 4+:          Halves every 8 years
Fee split:         50% burned / 50% to validators
Supply:            Decreases over time (fee burn)
Governance:        INDRA Improvement Proposals (IIPs) via GitHub
No on-chain governance token voting


Full economics: see [WHITEPAPER.md] or check indraprotocol.com

---

## Post-quantum security

INDRA transaction ownership and consensus finality are fully post-quantum.
Transaction signatures use an Ed25519 + Dilithium2 hybrid, while Quorum
Certificates use Dilithium2-only verification. Amount confidentiality still
uses classical cryptography and is documented as such.

| Component | Scheme | Quantum-safe |
|-----------|--------|--------------|
| Transaction signatures | Ed25519 + Dilithium2 | Yes (hybrid) |
| QC finality proofs | Dilithium2 | Yes |
| Block hashing | SHA-256 | Partial |
| Amount hiding | Ristretto255 / Pedersen | No (known) |


---

## iOS wallet

A native iOS wallet is available at:
https://github.com/jyothisarath096/indra-ios

Built with SwiftUI. Uses the `indra-ffi` crate via XCFramework for
all cryptographic operations. Keys stored in iOS Keychain.

---

## Contributing

INDRA welcomes contributions. Please:

1. Open an issue before large changes
2. Follow existing code style (run `cargo clippy` before submitting)
3. Add tests for new functionality
4. All tests must pass: `cargo test`

Protocol changes require an INDRA Improvement Proposal (IIP).
See `IIPs/` directory (coming soon) for the process.

---

## Security

Found a vulnerability? Please do not open a public issue.
Email: security@indraprotocol.com (coming soon)

A bug bounty program will be announced with the public testnet launch.

---

## Licence

Apache 2.0 — see [LICENSE](LICENSE)

---

## Foundation

INDRA Protocol Foundation
Ecosystem maintenance, audits, and infrastructure.
Does not control monetary policy or protocol parameters.

Website: indraprotocol.com (coming soon)
GitHub:  github.com/jyothisarath096/indra
