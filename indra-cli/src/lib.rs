//! # indra-cli
//!
//! Command-line tools for the INDRA v2 protocol.
//!
//! ## Commands
//!
//! ### `keygen`
//! Generate a complete validator keypair set:
//! - Ed25519 + Dilithium2 hybrid keypair (for signing transactions and votes)
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
pub mod keygen;
pub mod genesis_cmd;
pub mod query;
pub mod wallet;
pub mod tx_builder;

pub use error::{CliError, CliResult};
pub use keygen::{generate_keypairs, generate_from_passphrase, ValidatorKeys, KeysFile};
pub use genesis_cmd::{GenesisEntry, build_genesis_config, GenesisConfig};
pub use query::{rpc_call, QueryResult};
pub use wallet::{Wallet, WalletEntry};
pub use tx_builder::{build_transaction, TxParams, BuiltTransaction};
