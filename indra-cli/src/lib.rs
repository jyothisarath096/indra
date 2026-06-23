//! # indra-cli
//!
//! Command-line tools for the INDRA v2 protocol.
//!
//! ## Commands
//!
//! ### `keygen`
//! Generate a complete validator keypair set:
//! - Ed25519 + ML-DSA-87 hybrid keypair (for signing transactions and votes)
//! - Legacy BLS12-381 keypair metadata (retained for backward compatibility)
//! - VRF keypair (for proposer election)
//!
//! Output: a `keys.json` file with hex-encoded public and private keys.
//! The private keys are stored as seeds (32 bytes each).
//!
//! ### `genesis`
//! Build a `genesis.toml` from a list of validator public keys and stake amounts.
//! Used by the testnet coordinator to produce the agreed-upon genesis block.
//!
//! ### `send-tx`
//! Build and submit a transaction to a running node via JSON-RPC.
//!
//! ### `stake`
//! Build and submit validator and delegation staking operations.
//!
//! ### `query`
//! Query chain state from a running node:
//! - `query height`
//! - `query chain-info`
//! - `query validator <id>`
//! - `query mempool-size`

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]

pub mod error;
pub mod genesis_cmd;
pub mod keygen;
pub mod query;
pub mod staking;
pub mod tx_builder;
pub mod wallet;

pub use error::{CliError, CliResult};
pub use genesis_cmd::{build_genesis_config, GenesisConfig, GenesisEntry};
pub use keygen::{
    generate_from_new_mnemonic, generate_from_passphrase, generate_keypairs, recover_from_mnemonic,
    KeysFile, ValidatorKeys,
};
pub use query::{rpc_call, QueryResult};
pub use staking::{
    build_claim_rewards_op, build_delegate_op, build_register_validator_op,
    build_set_auto_delegate_op, build_set_commission_op, build_undelegate_op, fetch_chain_id,
    fetch_staking_nonce, reconstruct_keypair, submit_staking_op,
};
pub use tx_builder::{build_transaction, BuiltStakingOp, BuiltTransaction, TxParams};
pub use wallet::{PendingChange, Wallet, WalletEntry};
