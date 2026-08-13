# INDRA Protocol

**Quantum-safe digital money. Earned, not issued.**

INDRA is a post-quantum Layer 1 blockchain written in Rust. It implements
ML-DSA-87 + Ed25519 hybrid signatures, hybrid X25519 + ML-KEM-1024
encrypted transport, transparent checked-`u64` transaction amounts,
BFT consensus with 6-second absolute
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
Transactions:     Transparent amounts and pseudonymous hybrid-key ownership
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
├── indra-crypto/         ML-DSA-87, Ed25519, ML-KEM-1024, VRF
├── indra-state/          State machine, UTXO set, epoch logic, governance
├── indra-consensus/      BFT consensus, mempool, proposer election
├── indra-network/        P2P networking, gossip, observer protocol
├── indra-storage/        Block store, state snapshots, and epoch history
├── indra-node/           Node binary, engine, RPC dispatch
├── indra-rpc/            JSON-RPC 2.0 server and handlers
├── indra-cli/            CLI tools (stake, governance, keygen, send, wallet-scan)
├── indra-keystore/       Canonical encrypted keys.json parsing and creation
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
# Full workspace suite, excluding the optional FFI crate
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
public keys. New key generation writes an encrypted keystore by default and
prompts for a password; private seeds and signing keys are encrypted with
Argon2id + ChaCha20-Poly1305.

For unattended validator startup, store the keystore password in a separate
mode-0600 file and reference it from `[keys].password_file` in `config.toml`,
or pass `--keys-password-file` to the node. Plaintext keystores are not
accepted.

### 2. Generate config

```bash
cargo run -p indra-node --bin node --release -- --init
```

This interactively generates `~/.indra/data/config.toml`.

### 3. Start the node

```bash
cargo run -p indra-node --bin node --release -- \
  --config ~/.indra/data/config.toml \
  --keys-password-file ~/.indra/data/keys.pass
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
indra-stake register --keys ~/.indra/data/keys.json \
  --commission 1000 --utxo <utxo_id>

# Self-stake a UTXO
indra-stake self-stake --keys ~/.indra/data/keys.json --utxo <utxo_id>

# Delegate to a validator
indra-stake delegate --keys ~/.indra/data/keys.json \
  --validator <validator_id> --utxo <utxo_id>

# Claim rewards
indra-stake claim-rewards --keys ~/.indra/data/keys.json \
  --validator <validator_id>

# Set auto-delegation target (for validators outside the active set)
indra-stake auto-delegate --keys ~/.indra/data/keys.json \
  --validator <your_validator_id> --target <target_validator_id>

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
  --proposal-id <proposal_id> --vote yes \
  --keys ~/.indra/data/keys.json --wait
# Vote nonce is generated automatically and saved beside keys.json by default.

# Reveal your vote (Phase 3)
indra-governance reveal \
  --proposal-id <proposal_id> --vote yes \
  --keys ~/.indra/data/keys.json --wait

# Redelegate vote weight (Phase 3 only, delegators only)
indra-governance redelegate \
  --proposal-id <proposal_id> \
  --from-validator <validator_id> --to-validator <validator_id> \
  --amount-spark 100000000000 \
  --keys ~/.indra/data/keys.json

# Execute a passed proposal (after delay)
indra-governance execute \
  --proposal-id <proposal_id> \
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

The full local listener accepts JSON-RPC 2.0 POST to `http://node:8545`.
The optional `rpc_public` listener is structurally read-only, has stricter
public-endpoint limits, and should be exposed through a reverse proxy/CDN/WAF
for real internet traffic. Normal transaction, staking, and governance
submissions remain authenticated by their signed payloads; operator-only
diagnostics require `X-Admin-Token` on the full listener.

**Chain**
| Method | Description |
|--------|-------------|
| `indra_getChainInfo` | Height, epoch, era, supply, validators, fees |
| `indra_getBlock` | Full block by height |
| `indra_getTip` | Current tip hash and height |
| `indra_getMempoolSize` | Pending transaction count |
| `indra_getPeers` | Summary-only connected peer information |
| `indra_getRpcPolicy` | Listener mode and admin-token policy, without revealing token value |

**Validators**
| Method | Description |
|--------|-------------|
| `indra_getValidatorSet` | All active validators |
| `indra_getValidator` | Single validator by ID |
| `indra_getValidatorSelfStake` | Validator self-position summary |
| `indra_getValidatorStakePositions` | Paginated stake positions targeting a validator |
| `indra_getValidatorAutoDelegate` | Auto-delegation target |

**Stake positions and tranches**
| Method | Description |
|--------|-------------|
| `indra_getStakePositions` | Paginated positions, optionally filtered by owner and validator |
| `indra_getStakePosition` | Exact position lookup by ID |
| `indra_getUnbondingTranches` | Paginated tranches, optionally filtered by position, owner, and validator |
| `indra_getUnbondingTranche` | Exact tranche lookup by ID |
| `indra_getOwnerStakePositions` | Paginated positions controlled by one owner |
| `indra_getDelegatorRewards` | Pending rewards across all validators |

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

`indra_getProposals.total_count` is the count retained in current node state,
not a lifetime proposal count. A proposal `NotFound` response means either that
the proposal never existed or that it has been pruned; ordinary nodes cannot
distinguish those cases.

**Admin/operator**
| Method | Description |
|--------|-------------|
| `indra_getPeerTopology` | Admin-only full peer topology |

**Wallet**
| Method | Description |
|--------|-------------|
| `indra_getLegacyScanChallenge` | Ownership challenge for protocol-output provenance |
| `indra_sendTransaction` | Submit a signed transaction |
| `indra_submitStakingOp` | Submit a staking operation |
| `indra_getStakingNonce` | Replay-protection nonce for staking |

Tranche-refund provenance is committed inside the refund UTXO and remains
available for exactly that UTXO's unspent lifetime. Canonical block-range wallet
scanning recovers the deterministic refund opening without a fixed retention
window.

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
| Value conservation | Checked `u64` public arithmetic | Exact arithmetic invariant |

Transaction ownership requires exact full-hybrid-key custody and dual
Ed25519 + ML-DSA-87 verification; consensus finality uses ML-DSA-87. These
authorization paths retain post-quantum security through their PQ components.
Current OutputV1 owner/value metadata is public to raw-chain observers and
amount correlation can deanonymize flows. See the
[whitepaper](docs/WHITEPAPER.md) Section 4 and [privacy status](docs/PRIVACY_STATUS.md).

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
The governance threshold is intentionally conservative: YES stake must
strictly exceed the configured fraction of total Snapshot 1 stake. This is
not a participation-quorum-plus-majority model.

Ordinary nodes retain all active proposals plus the 1,024 most recent terminal
proposals in consensus state. Older terminal proposal history is an archive
node or indexer responsibility.

See [whitepaper Section 6](docs/WHITEPAPER.md) for full governance specification.

---

## Testnet

```
Chain ID:    indra-testnet-1
RPC:         https://rpc.indraprotocol.com
P2P:         116.203.185.28:30303
Observer:    116.203.185.28:30304
Explorer:    https://indraprotocol.com/#explorer
Schema:      v4
```

Genesis validators:

| Name | Validator ID |
|------|-------------|
| buddhi | `a8c62f6a12e9b662a70efb09356854b6997e173735b80c621a4059cd9e55f019` |
| bonkai | `bab8ecad302c48f16859af6313c48e1c41f074e1cfb249a5d88b85d75dba9476` |
| siddhi | `8cb883e7cbec5b7d697f1a5254eab885d2ae39c0c71ceea48e5948a949d4ceb3` |
| kushal | `0fd6df9dc13dcf8a49b09d8534bc5ebdc24d8bba296f43a643f91f3b2258089b` |

Discovery uses DNS seed A records with DNSSEC validation support, plus INDRA's
signed DNS discovery format: an ML-DSA-87-signed node list whose public
verification key is configured independently of DNS. Plain A-record discovery
remains a fallback during rollout.

---

## iOS wallet

Native iOS wallet at [github.com/jyothisarath096/indra-ios](https://github.com/jyothisarath096/indra-ios).
Built with SwiftUI. Uses `indra-ffi` via XCFramework. Production FFI builds use
128-bit high-entropy, session-scoped key capabilities (`IndraKeyHandle`) and
public metadata structs so raw private keys do not cross the FFI boundary. The
opaque-handle API is the only supported signing surface. Session teardown is a
blocking revocation boundary: admitted signers abort before publishing output.
Transaction results are also Rust-owned opaque capabilities and are copied out
through bounded accessors before one checked destroy call.
Long-term persistence remains the consuming app's platform secure storage
(iOS Keychain today; Android Keystore for a future Android app).

The Topic 5 lifecycle redesign is a breaking mobile ABI. Existing iOS/macOS
consumers must create a session, pass it with every key/result operation, treat
key and result handles as 16-byte opaque values, and replace direct Rust-buffer
freeing with the result copy/destroy API. No legacy sequential-handle or raw
result-buffer entry points remain.

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
